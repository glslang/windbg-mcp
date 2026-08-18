//! The supervisor↔worker wire protocol.
//!
//! A debug session lives in its own child process (see [`crate::worker`]), so the work a tool
//! wants done has to survive being *serialized* — which is the one real constraint this
//! architecture imposes. The old in-process design marshalled a closure onto the engine thread;
//! a closure cannot cross a process boundary, so the closures became the variants of
//! [`EngineOp`].
//!
//! One line of JSON per message in each direction, on a **channel of the protocol's own**: a pair
//! of anonymous pipes the supervisor creates and the worker inherits, requests down one and
//! messages up the other. The worker's standard handles carry none of it.
//!
//! That is a correctness property, not tidiness. The channel used to be the worker's stdin and
//! stdout, which is the same stdout any code in that process can write to — DbgEng's own output
//! is captured through `IDebugOutputCallbacks` and never lands there, but an extension DLL that
//! prints to the console directly does. A stray *unterminated* line then swallowed the message
//! written after it, and the supervisor drops what it cannot parse: the reply is lost, and since
//! only a `Done` removes a waiter, the caller times out and its session stays busy — and so
//! unreclaimable — for the life of the server. One stray `printf` cost a session permanently.
//!
//! An anonymous pipe has no name to open and is reachable only through an inherited handle, so
//! nothing outside this pair of processes can write on it, and inside the worker nothing but
//! `worker::emit` holds it. "Stray output cannot corrupt a reply" is therefore a
//! property of the plumbing rather than a convention about who prints where — which is what lets
//! the framing stay line-delimited and cheap.

use serde::{Deserialize, Serialize};

use crate::batch::BatchOp;
use crate::kdconn::Connection;
use crate::walk::WalkOp;

/// One unit of debugger work, as it crosses the process boundary.
///
/// The variants are deliberately **tool-shaped, not DbgEng-shaped**. Several tools are more than
/// one engine call — `reachable_from_dispatch` disassembles a whole call graph, `run_to_address`
/// resolves an expression and then runs — and splitting those into per-primitive round trips
/// would let another call for the same session interleave between the parts, so the walk could
/// see a target that moved underneath it. One op is one indivisible job on the worker's engine
/// thread, which is exactly the guarantee the single queued closure used to provide.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EngineOp {
    // ---- openers: the first op sent to a freshly spawned worker ----
    OpenDump {
        path: String,
    },
    OpenTrace {
        path: String,
    },
    AttachKernelLocal,
    /// The one op carrying a **secret**. [`Connection`] serializes as the bare string it always
    /// was — this channel is a pair of anonymous pipes, and nothing outside these two processes
    /// can read it — but renders redacted everywhere else, so the `Debug` this enum derives
    /// cannot become the leak. See [`crate::kdconn`].
    AttachKernel {
        connection: Connection,
    },
    AttachProcess {
        pid: u32,
    },
    Launch {
        command_line: String,
    },

    // ---- ordinary work ----
    /// A raw command, run to completion (`IDebugControl::Execute`).
    Command {
        command: String,
    },
    /// A raw command bounded by win-kexp's watchdog, which Ctrl+Breaks the engine before the
    /// caller gives up rather than letting a runaway command pin the session.
    ///
    /// What crosses the boundary is **the caller's remaining patience**, not the watchdog
    /// deadline: how much of the tool call's budget was left when the supervisor wrote this
    /// request. The watchdog deadline is derived from it in the worker, because only the worker
    /// knows the other half — how long the request then sat in *its* queue behind a command
    /// already running. Deriving it on the supervisor's side (where a request is written the
    /// moment it is submitted, and waits on the far side of the pipe) would credit that wait to
    /// nobody, and a command that queued for most of the budget would then run a full budget
    /// *after* its caller had already given up. Filled in by the supervisor's pump; the value
    /// callers construct is ignored.
    BoundedCommand {
        command: String,
        patience_ms: u32,
    },
    /// A command plus the `WaitForEvent` pump that actually moves the target (`g`, `p`, `t`,
    /// and their TTD reverses).
    CommandAndWait {
        command: String,
        timeout_ms: u32,
    },
    /// The target's registers, as text (`r`) *and* as values.
    ///
    /// `all` is the caller's choice between the integer registers — which is what `r` prints, and
    /// what almost every question is about — and the whole bank including x87, vector and
    /// subregister views, which on x64 is several hundred entries and would otherwise ride along
    /// with every single call.
    Registers {
        all: bool,
    },
    /// The loaded modules, as text (`lm`) *and* as values.
    ///
    /// `filter` is a module-name pattern, already validated as an operand by the supervisor and
    /// normalised in the worker — where it has to be, because the same normalised pattern must
    /// reach `lm m` and the typed listing or the two channels would answer different questions.
    Modules {
        #[serde(default)]
        filter: Option<String>,
    },
    /// The current thread's call stack, as values and as the listing rendered from them.
    ///
    /// One op rather than `k` as a [`Self::Command`] because the answer this tool exists to give
    /// is each frame's `module` + `rva`, and that is two engine questions per frame — where the
    /// instruction is, and which image holds it — that only the worker can ask. It is the same
    /// walk [`Self::CrashTriage`] does, through the same helper, so the frames of the two tools
    /// are the same records rather than two renderings that agree by inspection.
    ///
    /// **Unbounded, as the `k` it replaces was.** These are direct engine calls rather than a
    /// command, so no watchdog can cut them short and resolving a frame's symbol can block on a
    /// symbol server — which is exactly what `EngineOp::Command { command: "k" }` did before.
    /// Carrying a `patience_ms` would imply a bound that does not exist.
    Backtrace {
        /// How many frames to walk. Bounded by the supervisor before it gets here.
        frames: u32,
    },
    /// A run of instructions, as values and as the listing rendered from them.
    ///
    /// One op rather than `u` for [`Self::Backtrace`]'s reason: the answer is each instruction's
    /// `module` + `rva`, which is the engine's own walk plus a containment test the worker has to
    /// make. `address` is still an *expression* — a symbol, `module+0x1c`, a register — because
    /// that is what a caller has, and only the worker can ask the debugger to evaluate it.
    ///
    /// Unbounded, as the `u` it replaces was: direct engine calls rather than a command, so there
    /// is no watchdog to carry a patience for.
    Disassemble {
        /// The expression to start at, or `None` for the current instruction pointer.
        #[serde(default)]
        address: Option<String>,
        /// How many instructions to render. Bounded by the supervisor before it gets here.
        count: u32,
    },
    /// Set a breakpoint (`bp <expression>`) and report what the session now holds.
    ///
    /// A command rather than a typed `AddBreakpoint` because `bp`'s syntax is the point: a
    /// condition, a command string to run on each hit, `/1` for one-shot. What the typed side
    /// adds is the *answer* — a successful `bp` prints nothing at all, so "did that work, and
    /// what is it now?" was previously only answerable with a second `bl`.
    SetBreakpoint {
        expression: String,
    },
    ReadMemory {
        address: String,
        size: u32,
    },
    /// A structure traversal: a list of addresses, an array, or a pointer chain, with named
    /// fields read out of every node ([`crate::walk`]).
    ///
    /// One indivisible job for the usual reason and one of its own. The usual one: it is up to a
    /// thousand reads, and letting another call for the same session interleave would let the
    /// table describe a target that moved between its rows. Its own: the walk is a **long run of
    /// reads with no command behind it**, so win-kexp's watchdog — which bounds an `Execute` —
    /// has nothing to bound. The only thing that keeps it inside its caller's wait is the
    /// deadline it checks between nodes, and that arithmetic needs the queue wait only the worker
    /// can see.
    ///
    /// `patience_ms` lives inside [`WalkOp`], filled in and derived exactly as
    /// [`Self::BoundedCommand`]'s is.
    Walk(WalkOp),
    SymbolPath {
        path: String,
        append: bool,
        reload: String,
    },
    RunToAddress {
        address: String,
        timeout_ms: u32,
    },
    Reachability(ReachabilityOp),
    /// A pool query. Like [`Self::Reachability`] this is one indivisible job: a query may have
    /// to walk every pool page, and letting another call for the same session interleave would
    /// let the walk describe a target that moved underneath it.
    ///
    /// `patience_ms` is the caller's remaining patience, filled in and derived exactly as
    /// [`Self::BoundedCommand`]'s is, and for the same reason: a walk that outlives its caller is a
    /// walk nobody is waiting for holding a session nobody can use. Without it the walk takes
    /// win-kexp's `DEFAULT_WALK_BUDGET`, which knows nothing about this server's deadline and is
    /// wrong in both directions — too long for a host configured with a short
    /// `WINDBG_MCP_CALL_TIMEOUT_SECS`, and needlessly short for the default one, where it stops
    /// with minutes still to spend and hands back a partial snapshot.
    Pool {
        query: PoolOp,
        patience_ms: u32,
    },
    /// A user-mode Segment Heap query, with the same queue-aware deadline and interrupt
    /// semantics as [`Self::Pool`].
    Heap {
        query: HeapOp,
        patience_ms: u32,
    },
    /// Everything a bug check is, in one job: the code and its four parameters, the crashing
    /// stack with each frame attributed to a module, the process — and, when `analyze` is set,
    /// `!analyze -v`'s own conclusions beside them ([`crate::triage`]).
    ///
    /// Indivisible for the usual reason and one more. The usual one: it is half a dozen engine
    /// calls, and a stack walk whose module attribution came from a target that moved in between
    /// would report frames against the wrong load bases — which is the single field this tool
    /// exists to get right. The extra one: `analyze` is a *command*, so the caller's patience has
    /// to be spent across the gathering and the analysis together, and only one side of the pipe
    /// can do that arithmetic.
    ///
    /// `patience_ms` is the caller's remaining patience, filled in exactly as
    /// [`Self::BoundedCommand`]'s is. It bounds the `!analyze` only — the typed reads are bounded
    /// by the dump, not by a watchdog — so a triage that runs out of clock still answers with
    /// everything the engine gave it and an analysis that says why it is missing.
    CrashTriage {
        /// How many stack frames to walk. Bounded by the supervisor before it gets here.
        frames: u32,
        /// Whether to run `!analyze -v` at all.
        analyze: bool,
        patience_ms: u32,
    },
    /// A whole transaction: ordered steps, their assertions, and the rollback block that runs
    /// whatever happens to them ([`crate::batch`]).
    ///
    /// The most emphatic case for one op being one indivisible job. The point of a batch is that
    /// the caller's timeout cannot land between a mutation and its undo — which is only true
    /// because the sequence crosses the boundary once, as a value, and the worker owns the
    /// deadline. Splitting it into per-step round trips would put the client back in the middle
    /// of it, which is the design this replaces.
    Batch(BatchOp),
    /// Ctrl+Break whatever this worker's engine is running, and answer without going near the
    /// engine thread.
    ///
    /// **The second op the reader acts on where it reads it**, and here it is the entire point
    /// rather than an ordering detail: an interrupt queued behind the operation it is meant to stop
    /// would be read after that operation ended, which is a request that can never do anything.
    /// So this one is answered by the reader outright and never queued at all.
    ///
    /// It carries no job id, because the id that matters is not the caller's to know. A tool call
    /// names a *session*, and which job that session is running is decided inside the worker
    /// between the request being written and it being read — so the binding is made where the
    /// answer is: the reader reads the running job and raises the interrupt under one lock, and the
    /// engine thread clears that job under the same lock and drains anything still pending before
    /// it starts the next one. An interrupt therefore reaches the job that was running when it
    /// arrived, or nothing at all; it can never land on the one after it.
    ///
    /// What it cannot do is bounded by `SetInterrupt` itself: a live-kernel wait whose target has
    /// never connected does not poll, so an `attach_kernel` parked on a dead link is unreachable
    /// this way and only [`Self::EndSession`] ends it.
    Interrupt,
    /// Release the target. The supervisor tears the worker down afterwards — under
    /// process-per-session a worker outlives its target for no reason.
    ///
    /// **The one op that acts before it is dequeued.** Every other variant is nothing until the
    /// engine thread reaches it, but a [`Self::Batch`] can be running when this arrives, and this
    /// would then queue behind every step it has left — so the grace would expire mid-transaction
    /// and the worker be terminated with the target still patched. The worker's *request reader*
    /// therefore acts on this one where it reads it: it tells any running batch to stop at its
    /// next step and roll back ([`WorkerMessage::RollingBack`], which says how long that leaves),
    /// and only then queues the op for the engine thread, which reaches it with the transaction
    /// already unwound. The reader can do that because it is never blocked by the engine — it
    /// drains this channel into an in-process queue and nothing more.
    ///
    /// Carrying the signal on *this* op rather than on one of its own is what keeps it honest: a
    /// request the session's gate refuses never reaches the worker, so nothing can tell a batch to
    /// stop except a teardown that is really happening — and every request that does reach the
    /// worker is followed by the supervisor terminating it, so the flag it sets cannot outlive the
    /// session it belongs to.
    ///
    /// It does not interrupt a step already inside DbgEng; the batch stops at the next step
    /// boundary. Interrupting the engine itself is a different mechanism (`SetInterrupt`, bound to
    /// job identity) and is not this.
    EndSession,
}

impl EngineOp {
    /// The `patience_ms` this op carries, for the supervisor's pump to fill in as it writes the
    /// request — or `None` for an op that derives no deadline from its caller's.
    ///
    /// Named here, next to the variants, rather than as a `match` inside [`crate::engine::pump`],
    /// because the failure it prevents is silent: a variant that grows a `patience_ms` and is not
    /// added to that `match` compiles, ships, and takes whatever the field's default happens to
    /// be. That is exactly what [`Self::Pool`] did — it carried none at all and quietly took
    /// win-kexp's default walk budget instead of this server's deadline.
    pub fn patience_slot(&mut self) -> Option<&mut u32> {
        match self {
            Self::BoundedCommand { patience_ms, .. }
            | Self::Pool { patience_ms, .. }
            | Self::Heap { patience_ms, .. }
            | Self::CrashTriage { patience_ms, .. }
            | Self::Walk(WalkOp { patience_ms, .. })
            | Self::Batch(BatchOp { patience_ms, .. }) => Some(patience_ms),
            _ => None,
        }
    }

    /// Whether this op creates the worker's target, and so reports the `Committed`/`Opened`
    /// milestones below.
    pub fn is_opener(&self) -> bool {
        matches!(
            self,
            Self::OpenDump { .. }
                | Self::OpenTrace { .. }
                | Self::AttachKernelLocal
                | Self::AttachKernel { .. }
                | Self::AttachProcess { .. }
                | Self::Launch { .. }
        )
    }
}

/// `reachable_from_dispatch`'s arguments, after the supervisor has applied its defaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReachabilityOp {
    pub from: String,
    pub address: Option<String>,
    pub module: Option<String>,
    pub rva: Option<String>,
    pub max_functions: usize,
    pub max_depth: usize,
    pub recipe: bool,
}

/// The pool tools' arguments, after the supervisor has applied its defaults.
///
/// One variant per question rather than one op with optional fields: the three answers have
/// different shapes, and a caller that asked for a census should not be able to get a chunk
/// lookup back because a field defaulted.
///
/// `refresh` forces a fresh walk of the pool. It is off by default because walking every pool
/// page is expensive enough that repeating it per query would make the tools unusable — the
/// snapshot is cached per session and invalidated when the debugger reports the session
/// changed. Pass it after resuming the target, when the cached view is a photograph of a
/// target that has since moved.
///
/// **Built through the constructors below, never by hand.** Two callers now ask these questions —
/// the pool tools and a [`crate::batch`] step — and the defaults are part of the *answer's* shape
/// rather than of one tool's argument parsing. Spelling them out at each call site is how the two
/// come to disagree about what `limit` means.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PoolOp {
    /// Every *allocated* chunk carrying `tag`.
    FindTag {
        tag: String,
        /// `Some(true)` paged only, `Some(false)` nonpaged only, `None` both.
        paged: Option<bool>,
        refresh: bool,
        limit: usize,
    },
    /// The chunk containing `address`, with its immediate neighbours.
    Chunk { address: String, refresh: bool },
    /// Per-tag totals across the whole snapshot, heaviest consumer first.
    Census { refresh: bool, limit: usize },
    /// The walk's own diagnostics, verbatim, optionally narrowed to a substring.
    ///
    /// A real walk emits tens of thousands of these across a hundred-plus categories, so
    /// the summaries the other tools print necessarily truncate. When a specific heap or
    /// address is under suspicion, the one line that explains it is reliably *not* in the
    /// truncated head — hence a filter rather than a bigger cap.
    Diagnostics {
        filter: Option<String>,
        refresh: bool,
        limit: usize,
    },
}

/// Most rows or lines an allocator answer will render in one response.
///
/// The worker builds the whole reply as a single `String` before it crosses the pipe, so an
/// unbounded `limit` is a request to allocate a snapshot-sized buffer — hundreds of thousands
/// of chunks, or ~19k diagnostic lines on an idle machine. Clamping costs a caller nothing
/// they can act on; a worker killed mid-session costs them the session.
pub const MAX_ROWS: u32 = 2000;

fn clamp_rows(limit: Option<u32>, default: u32) -> usize {
    limit.unwrap_or(default).min(MAX_ROWS) as usize
}

impl PoolOp {
    /// Rows each question prints when the caller names no `limit`.
    const FIND_TAG_ROWS: u32 = 64;
    const CENSUS_ROWS: u32 = 40;
    const DIAGNOSTIC_LINES: u32 = 60;

    /// Every allocated chunk carrying `tag`.
    pub fn find_tag(
        tag: String,
        paged: Option<bool>,
        refresh: Option<bool>,
        limit: Option<u32>,
    ) -> Self {
        Self::FindTag {
            tag,
            paged,
            refresh: refresh.unwrap_or(false),
            limit: clamp_rows(limit, Self::FIND_TAG_ROWS),
        }
    }

    /// The chunk containing `address`, with its immediate neighbours.
    pub fn chunk(address: String, refresh: Option<bool>) -> Self {
        Self::Chunk {
            address,
            refresh: refresh.unwrap_or(false),
        }
    }

    /// Per-tag totals across the whole snapshot.
    pub fn census(refresh: Option<bool>, limit: Option<u32>) -> Self {
        Self::Census {
            refresh: refresh.unwrap_or(false),
            limit: clamp_rows(limit, Self::CENSUS_ROWS),
        }
    }

    /// The walk's own diagnostics, optionally narrowed.
    pub fn diagnostics(filter: Option<String>, refresh: Option<bool>, limit: Option<u32>) -> Self {
        Self::Diagnostics {
            filter,
            refresh: refresh.unwrap_or(false),
            limit: clamp_rows(limit, Self::DIAGNOSTIC_LINES),
        }
    }

    /// Whether this query **must** walk, rather than possibly being served from the session's
    /// cached snapshot.
    ///
    /// The distinction matters only when there is no time to walk in: a query that can be answered
    /// from the cache costs nothing and should be, while one that has to walk and cannot finish
    /// produces a truncated snapshot that win-kexp discards rather than caches — so it is work for
    /// nobody, twice over. The worker refuses that one instead of doing it.
    pub fn refreshes(&self) -> bool {
        match self {
            Self::FindTag { refresh, .. }
            | Self::Chunk { refresh, .. }
            | Self::Census { refresh, .. }
            | Self::Diagnostics { refresh, .. } => *refresh,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum HeapBackendFilter {
    Lfh,
    Vs,
    Segment,
    Large,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum HeapStateFilter {
    Allocated,
    ReusableFree,
    CachedFree,
    Unreadable,
}

/// The five user Segment Heap tools after defaults and output caps are applied.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HeapOp {
    List {
        refresh: bool,
    },
    Allocations {
        heap: Option<String>,
        backend: Option<HeapBackendFilter>,
        state: HeapStateFilter,
        min_capacity: Option<u64>,
        max_capacity: Option<u64>,
        refresh: bool,
        limit: usize,
    },
    Chunk {
        address: String,
        refresh: bool,
    },
    Census {
        heap: Option<String>,
        refresh: bool,
        limit: usize,
    },
    Diagnostics {
        heap: Option<String>,
        filter: Option<String>,
        refresh: bool,
        limit: usize,
    },
}

impl HeapOp {
    const ALLOCATION_ROWS: u32 = 64;
    const CENSUS_ROWS: u32 = 40;
    const DIAGNOSTIC_ROWS: u32 = 60;

    pub fn list(refresh: Option<bool>) -> Self {
        Self::List {
            refresh: refresh.unwrap_or(false),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn allocations(
        heap: Option<String>,
        backend: Option<HeapBackendFilter>,
        state: Option<HeapStateFilter>,
        min_capacity: Option<u64>,
        max_capacity: Option<u64>,
        refresh: Option<bool>,
        limit: Option<u32>,
    ) -> Self {
        Self::Allocations {
            heap,
            backend,
            state: state.unwrap_or(HeapStateFilter::Allocated),
            min_capacity,
            max_capacity,
            refresh: refresh.unwrap_or(false),
            limit: clamp_rows(limit, Self::ALLOCATION_ROWS),
        }
    }

    pub fn chunk(address: String, refresh: Option<bool>) -> Self {
        Self::Chunk {
            address,
            refresh: refresh.unwrap_or(false),
        }
    }

    pub fn census(heap: Option<String>, refresh: Option<bool>, limit: Option<u32>) -> Self {
        Self::Census {
            heap,
            refresh: refresh.unwrap_or(false),
            limit: clamp_rows(limit, Self::CENSUS_ROWS),
        }
    }

    pub fn diagnostics(
        heap: Option<String>,
        filter: Option<String>,
        refresh: Option<bool>,
        limit: Option<u32>,
    ) -> Self {
        Self::Diagnostics {
            heap,
            filter,
            refresh: refresh.unwrap_or(false),
            limit: clamp_rows(limit, Self::DIAGNOSTIC_ROWS),
        }
    }

    pub fn refreshes(&self) -> bool {
        match self {
            Self::List { refresh }
            | Self::Allocations { refresh, .. }
            | Self::Chunk { refresh, .. }
            | Self::Census { refresh, .. }
            | Self::Diagnostics { refresh, .. } => *refresh,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every op that *carries* a caller's patience must hand it out, and no other op may claim to.
    ///
    /// Checked against the serialized form rather than against a second list, because that is the
    /// one thing a hand-written `match` cannot get out of step with: the field is either in the
    /// JSON this op crosses the pipe as, or it is not. `Pool` is the reason — it reached the worker
    /// with no patience at all, and the walk took win-kexp's 120s default however long its caller
    /// was actually willing to wait ([#75](https://github.com/glslang/windbg-mcp/issues/75)).
    #[test]
    fn an_op_that_carries_a_deadline_hands_it_to_the_pump() {
        let mut ops = vec![
            EngineOp::Command {
                command: "lm".into(),
            },
            EngineOp::BoundedCommand {
                command: "s -b 0 L?0x1000 41".into(),
                patience_ms: 0,
            },
            EngineOp::Registers { all: false },
            EngineOp::Pool {
                query: PoolOp::census(None, None),
                patience_ms: 0,
            },
            EngineOp::Heap {
                query: HeapOp::list(None),
                patience_ms: 0,
            },
            EngineOp::CrashTriage {
                frames: 16,
                analyze: true,
                patience_ms: 0,
            },
            EngineOp::Walk(
                WalkOp::new(Some(vec!["0x1000".into()]), None, None, None, None, None)
                    .expect("a one-address walk"),
            ),
            EngineOp::Batch(BatchOp {
                budget_ms: 1_000,
                patience_ms: 0,
                steps: Vec::new(),
                always: Vec::new(),
            }),
            EngineOp::Interrupt,
            EngineOp::EndSession,
        ];
        for op in &mut ops {
            let carries = serde_json::to_string(&op)
                .expect("every op is plain data")
                .contains("patience_ms");
            let handed = op.patience_slot().is_some();
            assert_eq!(
                carries, handed,
                "{op:?} carries patience_ms={carries} but hands it out={handed}; the supervisor \
                 fills in exactly what this returns, so the two disagreeing is a deadline that is \
                 never set"
            );
        }
    }

    /// And what it hands out is the field the worker then reads, not a copy of it.
    #[test]
    fn the_slot_the_pump_writes_is_the_one_that_crosses_the_pipe() {
        let mut op = EngineOp::Pool {
            query: PoolOp::find_tag("Tgsm".into(), None, None, None),
            patience_ms: 0,
        };
        *op.patience_slot().expect("a pool query carries one") = 42_000;
        let EngineOp::Pool { patience_ms, .. } = op else {
            unreachable!("still a pool query")
        };
        assert_eq!(patience_ms, 42_000);
    }

    #[test]
    fn heap_defaults_and_row_caps_are_applied_before_crossing_the_worker_pipe() {
        let HeapOp::Allocations { state, limit, .. } =
            HeapOp::allocations(None, None, None, None, None, None, Some(u32::MAX))
        else {
            unreachable!()
        };
        assert!(matches!(state, HeapStateFilter::Allocated));
        assert_eq!(limit, MAX_ROWS as usize);

        let HeapOp::Census { limit, .. } = HeapOp::census(None, None, None) else {
            unreachable!()
        };
        assert_eq!(limit, 40);
        let HeapOp::Diagnostics { limit, .. } = HeapOp::diagnostics(None, None, None, None) else {
            unreachable!()
        };
        assert_eq!(limit, 60);
    }
}

/// A request down the worker's stdin. `id` is echoed on every message the op produces.
#[derive(Debug, Serialize, Deserialize)]
pub struct WorkerRequest {
    pub id: u64,
    pub op: EngineOp,
}

/// A message up the worker's stdout.
#[derive(Debug, Serialize, Deserialize)]
pub enum WorkerMessage {
    /// The engine was created; the worker will accept requests. Sent once, before anything
    /// else, so the supervisor never registers a session behind a worker that cannot debug.
    Ready,
    /// The engine could not be created and this worker is exiting. Distinct from a failed
    /// operation: no argument the caller can change makes the next attempt work.
    Fatal { message: String },
    /// The opener's target was **created or claimed** — the dump is loaded, the process is
    /// spawned, the KD connection is taken. Everything after this point can fail without the
    /// target ceasing to exist, which is the difference between "open again" and "do not open
    /// again, you would start a second one".
    Committed { id: u64 },
    /// The opener's wait returned: the target is loaded and stopped. Only the follow-up
    /// diagnostic (`lm`, `vertarget`, …) is left, so a failure from here on costs nothing but
    /// that report. This is also what moves a kernel attach out of the state it can park in
    /// forever.
    Opened { id: u64 },
    /// An [`EngineOp::EndSession`] found a batch in flight and told it to stop; it will be done —
    /// stopped, rolled back and reported — within `within_ms`. `id` is that request's, like every
    /// other message here.
    ///
    /// A milestone rather than part of the reply, for the same reason [`Self::Committed`] is: it
    /// says something the supervisor has to act on while the op it belongs to is still running.
    /// The teardown is already waiting on that op's `Done` when this arrives, and extends its wait
    /// by what this says — for that one session and no other. Absent, the ordinary short grace
    /// stands.
    ///
    /// The figure is a **field, not a sentence in the reply**, because the supervisor computes a
    /// deadline from it, and it is the worker's to compute: only that process knows what budget the
    /// batch is running under and how much of it is spent. It covers the step in flight as well as
    /// the rollback, since the signal cannot reach a step already inside DbgEng — a grace sized for
    /// the rollback alone would expire mid-step, which is the whole failure being fixed, arriving a
    /// little later.
    RollingBack { id: u64, within_ms: u32 },
    /// The op finished. `Err` is a failure with the engine's own text, and — where the worker
    /// knows better than "the debugger said no" — what kind of failure it was.
    Done {
        id: u64,
        result: Result<Output, Failed>,
    },
    /// One of this worker's own `tracing` records, mirrored so the supervisor owns every record
    /// either process made — see [`crate::logbridge`] for why that is worth a message.
    ///
    /// The only variant that belongs to **no request**, which is what it is: a worker logs from
    /// its engine thread, from its request reader, and from paths that run after every request is
    /// answered. It is intercepted where the channel is read and never reaches the routing that
    /// the rest of these go through, because there is no `id` to route it by.
    ///
    /// The worker still writes the same record to its inherited stderr. This copy is not that one
    /// arriving by another road: it is the one that can be read from the *client's* machine.
    Log {
        /// Milliseconds since the Unix epoch, stamped in the worker — where it happened, which is
        /// not where it is filed.
        at_ms: u64,
        level: crate::logbridge::Level,
        /// The `tracing` target, kept rather than assumed: a worker's records are not all
        /// `windbg_mcp::worker`, and the one from a dependency is the one worth seeing whole.
        target: String,
        message: String,
        /// Records this worker had to drop before this one, its queue having filled. Zero on
        /// every ordinary message — a gap in a log has to be reported, or a reader takes it for a
        /// stretch where nothing happened.
        #[serde(default)]
        dropped: u32,
    },
}

/// A failed op, as it crosses the pipe.
///
/// The message was once the whole of it, and a supervisor reading only a message has to call
/// every failure a debugger failure. Two are emphatically not: a walk stopped because somebody
/// asked it to stop, and a query that was **never run** because too little of the caller's budget
/// was left to run it in. Both used to arrive looking like a target that had misbehaved, which is
/// the opposite of what each one means.
#[derive(Debug, Serialize, Deserialize)]
pub struct Failed {
    pub message: String,
    /// `None` means the ordinary case: the debugger ran it and it failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<crate::structured::ErrorCategory>,
}

impl Failed {
    /// A failure of a kind the worker can name.
    pub fn categorised(
        category: crate::structured::ErrorCategory,
        message: impl Into<String>,
    ) -> Self {
        Self {
            message: message.into(),
            category: Some(category),
        }
    }
}

/// The ordinary case, so a bare `Err(message)?` keeps reading as it did.
///
/// Spelled out for the two string types rather than blanket over `ToString`, which cannot be
/// written: it would overlap the reflexive `From<Failed> for Failed`.
impl From<String> for Failed {
    fn from(message: String) -> Self {
        Self {
            message,
            category: None,
        }
    }
}

impl From<&str> for Failed {
    fn from(message: &str) -> Self {
        Self::from(message.to_string())
    }
}

/// What an op produced: the text every client has always received, plus the typed answer for
/// the tools that have one.
///
/// Two channels rather than one, because they answer to different readers and neither is a
/// projection of the other. The text is a rendering — aligned columns, caveats, advice on what
/// to do next — and a program reading it is parsing prose that exists to be reworded. `data` is
/// the same answer as values, and it is built **here**, on the side of the pipe where the engine's
/// own types are still in hand ([`crate::structured`]). Sending only the text and re-deriving
/// values on the supervisor's side would be the mistake
/// [#77](https://github.com/glslang/windbg-mcp/issues/77) was: a figure recovered from a
/// rendering measures the rendering.
///
/// `data` is already the *whole* structured result — `{"status": "ok", …}` — rather than a bare
/// payload, so the supervisor forwards it untouched and never has to know which tool asked.
#[derive(Debug, Serialize, Deserialize)]
pub struct Output {
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    /// An opener's typed facts about the target it just opened, and nothing else's.
    ///
    /// Its own field rather than [`Self::data`] because an opener is the one op whose typed answer
    /// **cannot be finished here**: it is keyed by a session handle the supervisor mints, and this
    /// process does not know it. So the worker sends the half it does know — as a value, on the
    /// side of the pipe where the engine's own types are in hand — and the supervisor folds it
    /// into [`crate::structured::OpenedSession`]. Re-deriving it over there from the report text
    /// would be [#77](https://github.com/glslang/windbg-mcp/issues/77) again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<crate::structured::TargetSummary>,
}

impl Output {
    /// A reply with text only — every op that has no typed shape yet.
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            data: None,
            summary: None,
        }
    }

    /// A reply carrying both, from a payload that is serialized here so no caller can forget
    /// the `status` discriminator that makes an outcome one shape.
    pub fn typed<T: Serialize>(text: impl Into<String>, payload: T) -> Self {
        let data = serde_json::to_value(crate::structured::Outcome::Ok(payload));
        Self {
            text: text.into(),
            // A payload that will not serialize is a bug in a `structured` type, not a debugger
            // failure, and it must not cost the caller the text they asked for.
            data: match data {
                Ok(value) => Some(value),
                Err(error) => {
                    tracing::error!("structured payload did not serialize: {error}");
                    None
                }
            },
            summary: None,
        }
    }

    /// An opener's reply: the report, and the facts behind it for the supervisor to fold in.
    pub fn opened(text: impl Into<String>, summary: crate::structured::TargetSummary) -> Self {
        Self {
            text: text.into(),
            data: None,
            summary: Some(summary),
        }
    }
}

impl From<String> for Output {
    fn from(text: String) -> Self {
        Self::text(text)
    }
}
