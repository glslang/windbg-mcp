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
    Pool(PoolOp),
    /// A whole transaction: ordered steps, their assertions, and the rollback block that runs
    /// whatever happens to them ([`crate::batch`]).
    ///
    /// The most emphatic case for one op being one indivisible job. The point of a batch is that
    /// the caller's timeout cannot land between a mutation and its undo — which is only true
    /// because the sequence crosses the boundary once, as a value, and the worker owns the
    /// deadline. Splitting it into per-step round trips would put the client back in the middle
    /// of it, which is the design this replaces.
    Batch(BatchOp),
    /// Abandon a running [`Self::Batch`]: stop before the next step and go straight to its
    /// `always` block. Sent by a teardown — a client disconnect, or `end_session` — so the
    /// rollback runs before the worker is asked to let the target go.
    ///
    /// **The one op the worker does not run on its engine thread.** Every other variant here is a
    /// job for that thread, and this one exists precisely because that thread is busy: it is
    /// inside the batch being abandoned. So the worker's *request reader* handles it where it
    /// reads it, which it can, because the reader is never blocked by the engine — it drains this
    /// channel into an in-process queue and nothing more.
    ///
    /// It does not interrupt a step already inside DbgEng; the batch stops at the next step
    /// boundary, and the worker says how long that leaves it ([`WorkerMessage::RollingBack`]) so
    /// the teardown can wait for the step as well as the rollback. Interrupting the engine itself
    /// is a different mechanism (`SetInterrupt`, bound to job identity) and is not this.
    AbandonBatch,
    /// Release the target. The supervisor tears the worker down afterwards — under
    /// process-per-session a worker outlives its target for no reason.
    EndSession,
}

impl EngineOp {
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
    /// An [`EngineOp::AbandonBatch`] found a batch in flight, and it will be done — stopped,
    /// rolled back and reported — within `within_ms`. `id` is the abandon request's, like every
    /// other message here.
    ///
    /// A milestone rather than part of the reply, for the same reason [`Self::Committed`] is: it
    /// says something the supervisor has to act on *before* the `Done` it precedes. The two travel
    /// the same ordered channel and are processed in order, so by the time the abandon call
    /// returns, the session already knows how long to hold its grace open — for that one session
    /// and no other. Absent, the ordinary short grace stands.
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
