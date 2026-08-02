//! The supervisor↔worker wire protocol.
//!
//! A debug session lives in its own child process (see [`crate::worker`]), so the work a tool
//! wants done has to survive being *serialized* — which is the one real constraint this
//! architecture imposes. The old in-process design marshalled a closure onto the engine thread;
//! a closure cannot cross a process boundary, so the closures became the variants of
//! [`EngineOp`].
//!
//! One line of JSON per message in each direction: requests down the worker's stdin, messages
//! up its stdout. Line-delimited rather than length-prefixed so that a stray write to the
//! worker's stdout — DbgEng output is captured through `IDebugOutputCallbacks`, but nothing
//! *guarantees* every extension behaves — corrupts one line the supervisor can log and skip,
//! rather than desynchronizing the stream permanently.

use serde::{Deserialize, Serialize};

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
    AttachKernel {
        connection: String,
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
    /// The op finished. `Err` is a debugger-level failure with the engine's own text.
    Done {
        id: u64,
        result: Result<String, String>,
    },
}
