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
    Registers,
    ReadMemory {
        address: String,
        size: u32,
    },
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

impl PoolOp {
    /// Most rows or lines a pool answer will render in one response.
    ///
    /// The worker builds the whole reply as a single `String` before it crosses the pipe, so an
    /// unbounded `limit` is a request to allocate a snapshot-sized buffer — hundreds of thousands
    /// of chunks, or ~19k diagnostic lines on an idle machine. Clamping costs a caller nothing
    /// they can act on; a worker killed mid-session costs them the session.
    pub const MAX_ROWS: u32 = 2000;

    /// Rows each question prints when the caller names no `limit`.
    const FIND_TAG_ROWS: u32 = 64;
    const CENSUS_ROWS: u32 = 40;
    const DIAGNOSTIC_LINES: u32 = 60;

    fn rows(limit: Option<u32>, default: u32) -> usize {
        limit.unwrap_or(default).min(Self::MAX_ROWS) as usize
    }

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
            limit: Self::rows(limit, Self::FIND_TAG_ROWS),
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
            limit: Self::rows(limit, Self::CENSUS_ROWS),
        }
    }

    /// The walk's own diagnostics, optionally narrowed.
    pub fn diagnostics(filter: Option<String>, refresh: Option<bool>, limit: Option<u32>) -> Self {
        Self::Diagnostics {
            filter,
            refresh: refresh.unwrap_or(false),
            limit: Self::rows(limit, Self::DIAGNOSTIC_LINES),
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
            EngineOp::Registers,
            EngineOp::Pool {
                query: PoolOp::census(None, None),
                patience_ms: 0,
            },
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
    /// The op finished. `Err` is a debugger-level failure with the engine's own text.
    Done {
        id: u64,
        result: Result<String, String>,
    },
}
