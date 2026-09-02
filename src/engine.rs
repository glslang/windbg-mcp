//! The supervisor: session registry and worker-process supervision.
//!
//! dbgeng.dll holds **one debuggee session per process**. That is not a binding limitation — it
//! is why `.opendump` *replaces* the target rather than opening a second one. So a server that
//! wants more than one session at a time, or that wants to be able to *abandon* one, needs more
//! than one process. Each open target here gets its own [`crate::worker`] child process, and
//! this module routes tool calls to them.
//!
//! Two things fall out of that, and they are the point:
//!
//! * **A session that cannot be unwound costs a process, not the server.** A live-kernel attach
//!   whose target never dials in blocks in `WaitForEvent(INFINITE)` with no cancellation path
//!   (dbgscope's `SetInterrupt` watchdog cannot reach a wait that is still establishing the
//!   link). Confined to its own process, that is one worker the supervisor can kill —
//!   `end_session` does exactly that — instead of the one engine thread every tool queued on.
//! * **`session_id` routes rather than merely detects.** The old handle existed to notice that
//!   the single target had been *replaced* underneath a caller. Here it names a worker, so an
//!   `open_dump` cannot disturb a kernel attach at all, and an `end_session` for session A can
//!   no longer be ordered against an open of B — there is nothing shared to order.
//!
//! What has *not* changed is the per-session ordering guarantee. Each session has one queue with
//! one consumer ([`pump`]), and a job's gate runs there, immediately before the request is
//! written — the same slot the engine thread used to provide, for the same reason.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::io::{BufRead, PipeReader, PipeWriter, Write};
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, ChildStdout, Command};
use tokio::sync::{mpsc, oneshot};
use windows_sys::Win32::Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation};
use windows_sys::Win32::System::Console::GetConsoleProcessList;

use crate::kdconn;
use crate::proto::{EngineOp, Output, SymbolPathSetting, WorkerMessage, WorkerRequest};
use crate::worker::{MESSAGES_FLAG, REQUESTS_FLAG, TARGET_FLAG, WORKER_FLAG};

/// How many sessions may be open at once.
///
/// Each is a process holding a dump, a trace, or a live target, so this is a real resource
/// bound, not a policy. Four is enough for the workflows that motivated concurrency at all
/// (triage a crash dump while a kernel attach is live; compare two traces) and small enough that
/// a client leaking sessions notices.
pub const MAX_SESSIONS: usize = 4;

/// How many *closed* sessions to remember **per client**, so `session_status` can still answer
/// for a handle after its target is gone. Live sessions are never evicted, whatever this says.
///
/// Per client rather than per server, because a shared bound is a shared fate: one client opening
/// and closing sessions would age out another client's history, and the answer that client then
/// gets for its own handle is "unknown" — which reads as "never existed" and advises opening
/// again. The clients are the configured credentials, a set fixed at startup, so this is still a
/// bound and not a hole.
const CLOSED_HISTORY: usize = 8;

/// How long to wait for a freshly spawned worker to report [`WorkerMessage::Ready`]. This covers
/// process creation and `DebugCreate`, nothing else — a worker that is slower than this is not
/// going to become usable.
pub(crate) const WORKER_READY_TIMEOUT: Duration = Duration::from_secs(30);

/// How long `end_session` gives the worker to release its target cleanly before the process is
/// killed instead.
///
/// It is a bound on *politeness*, not on the teardown: the session ends either way. Long enough
/// that a live target with real teardown work (a detach that has to resume threads) finishes
/// gracefully, short enough that recovering a parked attach is not a wait.
const END_SESSION_TIMEOUT: Duration = Duration::from_secs(20);

/// What a session says while an explicit `end_session` is in flight.
///
/// This is written by [`pump`] when it forwards the teardown, not when the call is submitted:
/// work already ahead of the teardown keeps its place, while anything behind it is refused. The
/// final disposition replaces this once [`Sessions::end`] knows whether the target was released or
/// the worker had to be terminated.
const END_SESSION_CLOSING: &str = "end_session is releasing its target";

/// What a `launch` session's end says about its debuggee.
///
/// Deliberately not "was terminated with it", which would be a causal claim this side cannot make:
/// a launched process that had already run to completion reaches the same teardown, and that
/// sentence would attribute its exit to it. What is true either way is that it is not still
/// running, which is the half a caller acts on — and which of the two happened was reported when
/// it happened, by the resume that saw the target go.
const LAUNCH_ENDED: &str = " The process this session launched did not outlive it.";

/// How long to wait for a worker to acknowledge an interrupt.
///
/// Not a bound on the operation being interrupted: that one ends when the engine next polls, and it
/// reports to its own caller on its own clock. This bounds only the round trip to the worker's
/// *request reader*, which does no debugging and is by construction never blocked behind the engine
/// — so it is short, and a wait that reaches it means the worker has stopped reading altogether.
const INTERRUPT_TIMEOUT: Duration = Duration::from_secs(5);

/// The same grace, but at shutdown, where it competes with the client's expectation that closing
/// stdin ends the process promptly.
///
/// Releasing rather than killing is not tidiness here. A live kernel left detached *while halted*
/// stays frozen — one CPU stopped, the rest spinning — so a worker killed instead of released
/// leaves the target machine stopped and its KD stub wedged until someone reboots it. That is a
/// far worse outcome than an extra few seconds on the way out, and a client disconnect is exactly
/// when nobody is watching.
///
/// Shorter than [`END_SESSION_TIMEOUT`] because a session that cannot let go within a few seconds
/// is one that never will, and sessions are released concurrently, so this is the whole cost
/// rather than the cost per session.
pub(crate) const SHUTDOWN_RELEASE_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a teardown commits to before looking at the worker's promise again.
///
/// A promise can be **revised downwards**: a batch that finishes early retracts its bound to what
/// the release still needs. A wait that committed to the whole of it in one `timeout` could not see
/// that — the retraction would update a value nobody reads again, and a disconnect would sit out the
/// rest of a batch budget with no transaction left to protect. So no single wait is longer than
/// this, and the promise is re-read between them.
///
/// A second is chosen against what it competes with: the shortest grace it can follow is five
/// seconds, and the thing being waited for takes seconds at least, so a re-read this often is
/// invisible — while the wakeups it costs, on a path that runs once per session teardown, are not
/// worth avoiding with machinery that would have to be woken from a thread with no runtime of its
/// own.
const UNWIND_RECHECK: Duration = Duration::from_secs(1);

/// How long to wait before looking again, given what the worker last promised and how much of the
/// teardown's total patience is left.
fn unwind_slice(within: Duration, left: Duration) -> Duration {
    within.min(left).min(UNWIND_RECHECK)
}

/// The last wait a teardown owes once the transaction it was waiting on has ended: the ordinary
/// grace, measured from the moment the release could first have started.
///
/// `ended` is the last instant the worker named — the moment its batch finished, when it retracted,
/// or the bound it promised and did not beat. Measuring from *there* rather than from now is what
/// keeps the total honest: the grace this teardown already spent ran concurrently with a
/// transaction the release was queued behind, so it bought the release nothing, but it should not
/// buy it a second full helping either.
///
/// `None` when there was no transaction — an ordinary teardown is not lengthened by a mechanism it
/// never used — and none when that grace is already spent or the teardown's own patience is, so the
/// total stays bounded by what [`Sessions::call_as`] started with.
fn release_handoff(
    ended: Option<Instant>,
    now: Instant,
    base: Duration,
    left: Duration,
) -> Option<Duration> {
    let owed = (ended? + base).saturating_duration_since(now).min(left);
    (!owed.is_zero()).then_some(owed)
}

/// `CREATE_NEW_PROCESS_GROUP`, which every worker is spawned with.
///
/// An interactive Ctrl+C is delivered to *every* process attached to the console, and a child
/// inherits its parent's process group — so without this a worker takes the default console
/// handler and terminates on the spot, before its request channel closes and before it can
/// release its target. That is precisely the halted kernel this design exists to avoid, arriving
/// by the one route where the supervisor cannot help: its own default handler ends it, so it never
/// reaches [`Sessions::shutdown`].
///
/// With the flag, Ctrl+C is disabled for the worker's group. The supervisor still dies, its handles
/// still close, and the worker meets the EOF path that knows how to let go.
const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;

/// `CREATE_NO_WINDOW`, passed only to a child this process has no console to hand down.
///
/// A console-subsystem child spawned with neither this flag nor `CREATE_NEW_CONSOLE` inherits its
/// parent's console — and where the parent has **none**, Windows gives the child a brand-new,
/// *visible* one instead, titled with the exe's path and taking the foreground as it appears. A
/// GUI MCP client has no console to pass on, so on the hosts this server is actually used from,
/// every worker spawn opened a window; at the rate a model opens and ends sessions that is a
/// desktop nobody can work at ([#273](https://github.com/glslang/windbg-mcp/issues/273)).
///
/// **It is conditional because the flag does not suppress a console — it suppresses the window,
/// by giving the child a console of its own**, and a worker's stderr is *inherited*
/// ([`spawn_worker`]). A console handle handed to a process attached to a different console is
/// re-bound to that one: measured on this bench, such a child's `WriteFile` reports success —
/// bytes written, no error — and the text lands in its own invisible console instead of in the
/// terminal, while a child that inherits the console writes where the operator is looking.
/// Applied unconditionally this would therefore delete every worker log line from a terminal-run
/// server, silently, and make [`crate::logbridge`]'s "they are still on the server's stderr"
/// untrue.
///
/// So it goes on exactly where it changes something. With no console there is nothing to inherit
/// and nothing for stderr to lose — it is a pipe or a file, which is inherited unchanged
/// (measured) — and with one, the worker shares it and opens no window anyway.
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// [`CREATE_NO_WINDOW`] when this process has no console, and no flag at all when it has one.
///
/// Shared with [`crate::ttd::record_launch`], the other process this server creates: a recorder
/// window is the same window, and the recorded target inherits whatever console the recorder was
/// given.
pub(crate) fn without_a_console_window() -> u32 {
    if attached_to_a_console() {
        0
    } else {
        CREATE_NO_WINDOW
    }
}

/// Whether this process is attached to a console at all.
///
/// **Not `GetConsoleWindow() != NULL`**, which is the usual spelling of this question and is
/// wrong here: a console with no window is an ordinary thing — a ConPTY (Windows Terminal, and
/// this repo's own test harness) has none, and neither has a console created by
/// [`CREATE_NO_WINDOW`] one level up — so that call answers "no console" for a process holding a
/// live console handle, which is the one case where passing the flag on costs something.
/// `GetConsoleProcessList` counts the processes sharing this process's console and fails with
/// `ERROR_INVALID_HANDLE` when there is no console; both halves measured on this bench.
fn attached_to_a_console() -> bool {
    // The count, not the identifiers: a buffer too small for all of them is not a failure — the
    // call answers how many there are and stores none — so one element is enough to ask with.
    let mut one = [0u32; 1];
    // SAFETY: a valid, writable one-element buffer, described to the call as one element.
    unsafe { GetConsoleProcessList(one.as_mut_ptr(), 1) != 0 }
}

/// Counter behind [`mint_session_id`]. Only needs to be unique within this process.
static SESSION_SEQ: AtomicU64 = AtomicU64::new(1);

/// Mints a fresh session handle. Unique per process, which is all the routing needs: the handle
/// exists to name a worker, not to authenticate.
fn mint_session_id() -> String {
    let n = SESSION_SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    format!("sess-{nanos:x}-{n}")
}

/// Why an engine call failed, split by who can act on the failure.
///
/// The MCP tool spec draws exactly this line: failures the model can see and self-correct from
/// belong in the tool *result* (`isError: true`), while failures of the server machinery belong
/// in a JSON-RPC error. Keeping the two apart here lets [`crate::server`] render each one the
/// right way instead of collapsing every debugger hiccup into an opaque protocol error the model
/// never really sees.
///
/// `Clone` because an asynchronous run's outcome is filed on its session and read by every
/// `wait_for_stop` that asks, rather than delivered to one waiter and gone. Every variant is a
/// message.
#[derive(Debug, Clone)]
pub enum EngineError {
    /// The debugger ran the operation and it failed — an unresolvable symbol, an unreadable
    /// address, a command error, a target that never stopped. Actionable: the model can adjust
    /// its arguments and retry.
    Debugger(String),
    /// The call outlived its budget. Reported to the model exactly like [`Self::Debugger`], but
    /// kept separate because it means something the caller must know: the job was abandoned by
    /// the *waiter*, not by the worker, so it may still be running and may still succeed.
    /// Anything whose retry has side effects has to say so.
    Timeout(String),
    /// The handle named a session this server will not run the call against — it was ended, its
    /// target was replaced out from under it, or it never existed. Not an engine failure at all:
    /// the refusal is the feature.
    Stale(String),
    /// The worker holding this session is gone — it crashed, or it was terminated to reclaim it.
    /// The session is unrecoverable, but the server is not: opening again gets a fresh worker.
    Lost(String),
    /// The work was stopped on request. Not a failure of the target, and reported as one for as
    /// long as the worker could only send a message: somebody asked for this.
    Interrupted(String),
    /// The work was never started — too little of the caller's budget was left to do it and
    /// report back. Distinct from [`Self::Timeout`] in the way that matters: nothing ran, so
    /// nothing changed, and a retry is unambiguous.
    NotRun(String),
    /// The **worker** refused the call on its arguments, before the debugger saw them — an
    /// address that will not parse, say. The same class of mistake this server rejects on its own
    /// side, and it has to read the same way from both: a caller told "the debugger failed" for a
    /// malformed argument goes looking at the target.
    InvalidArgument(String),
    /// The session has a run in flight — `continue_async` set the target going and it has not
    /// stopped — so this call was refused rather than queued behind it.
    ///
    /// Its own variant rather than a [`Self::Debugger`] failure because nothing about the call was
    /// wrong and changing it would not help: the answer is to wait for the stop, break the target
    /// in, or end the session. Folded into `Debugger` it would read as "the debugger said no", and
    /// a caller acting on that goes looking at the target — which is the one thing it must not do
    /// while the target is moving.
    ///
    /// It is a refusal rather than a queue for the same reason. A read queued behind the run would
    /// be answered whenever the target next stopped, which may be an hour, and the caller would
    /// have no way to tell that from a debugger that had hung.
    TargetRunning(String),
}

// Note what is *not* here any more: an "engine is unusable" variant. Under process-per-session
// every one of these failures is scoped to one session and every one of them has a next move —
// fix the arguments, name a different session, or open again — so all of them belong in the tool
// result where the model can read them. The only failure that is genuinely the server's rather
// than a session's is "no worker process could be started at all", which only an opener can hit;
// it is `OpenError::Unavailable`, and it is the one thing this server reports as a JSON-RPC error.

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Debugger(m)
            | Self::Timeout(m)
            | Self::Stale(m)
            | Self::Lost(m)
            | Self::Interrupted(m)
            | Self::NotRun(m)
            | Self::InvalidArgument(m)
            | Self::TargetRunning(m) => f.write_str(m),
        }
    }
}

/// Lifts a worker's failure into this side's error type, keeping the kind the worker named.
///
/// The default is [`EngineError::Debugger`], because for almost every op that is what a failure
/// is. The exceptions are the kinds the worker can tell apart and the supervisor cannot: an
/// operation that was interrupted, one that was never started for want of budget, one refused on
/// its arguments before the debugger ever saw them, and a session whose **target went away** —
/// which only the worker's engine can see, and which the supervisor's own handle bookkeeping has
/// no way to learn.
///
/// Every named category gets a variant rather than being folded into the default. Folding is how
/// a category becomes decorative: the worker went to the trouble of saying "this was the caller's
/// mistake, not the target's", and a `_` arm here quietly restates it as the target's. That is
/// not hypothetical — the target-gone refusal arrived here as `debugger` for exactly as long as
/// this arm was missing, telling callers to change what they asked when nothing they could ask
/// would work.
fn engine_error(failed: crate::proto::Failed) -> EngineError {
    use crate::structured::ErrorCategory;
    match failed.category {
        Some(ErrorCategory::Interrupted) => EngineError::Interrupted(failed.message),
        Some(ErrorCategory::NotRun) => EngineError::NotRun(failed.message),
        Some(ErrorCategory::InvalidArgument) => EngineError::InvalidArgument(failed.message),
        Some(ErrorCategory::StaleSession) => EngineError::Stale(failed.message),
        _ => EngineError::Debugger(failed.message),
    }
}

/// How much of the caller's budget is left, from the moment this is called until the tool call
/// gives up. Sent to the worker so it can size the watchdog on a bounded command — see
/// [`EngineOp::BoundedCommand`] for why the worker rather than here.
fn remaining_patience_ms(call_timeout: Duration, submitted: Instant) -> u32 {
    call_timeout
        .saturating_sub(submitted.elapsed())
        .as_millis()
        .min(u32::MAX as u128) as u32
}

// ---- session state -------------------------------------------------------

/// What kind of target a session holds, for reporting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionKind {
    Dump,
    Trace,
    KernelLocal,
    Kernel,
    Process,
    Launch,
}

impl SessionKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Dump => "crash dump",
            Self::Trace => "TTD trace",
            Self::KernelLocal => "local kernel",
            Self::Kernel => "kernel target",
            Self::Process => "attached process",
            Self::Launch => "launched process",
        }
    }

    /// Whether an open of this kind can wait forever. Only a live kernel does: it needs
    /// `WaitForEvent(INFINITE)` and nothing can interrupt a wait that has not yet connected.
    pub fn waits_indefinitely(self) -> bool {
        matches!(self, Self::Kernel | Self::KernelLocal)
    }
}

/// How far a session's opener got, tracked **independently of the session state**.
///
/// The state cannot answer this on its own, because it encodes two different things: how the open
/// is progressing *and* whether the handle still names what it was issued for. A command queued
/// behind the open retires the handle, and that retirement — correctly — outranks the opener's
/// own transitions. But it also erases the difference between "nothing was created" and "the
/// target exists", and those need opposite recovery advice: re-open, versus do not re-open or you
/// will start a second one.
///
/// Monotonic, and only ever advanced by the worker's milestones.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
enum OpenPhase {
    /// Nothing has been created or claimed. A failure here leaves a clean slate.
    Started = 0,
    /// The target exists. Re-running the open would attach a second time, or start a second
    /// process.
    Committed = 1,
    /// The target is loaded and stopped; only the follow-up diagnostic was left.
    Opened = 2,
}

impl OpenPhase {
    fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Started,
            1 => Self::Committed,
            _ => Self::Opened,
        }
    }

    /// Whether the target exists — the question the recovery advice turns on.
    fn committed(self) -> bool {
        self >= Self::Committed
    }
}

/// Where a session is in its life.
///
/// The three opening states are the distinction issue #61 could not draw: a `Pending` open looked
/// identical whether the link was five seconds from coming up or would never come up, and those
/// need opposite advice. [`Self::Attaching`] is reached only once the target has been *claimed*,
/// so a session sitting in it is one whose transport is up or never will be — and how long it has
/// sat there is the signal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionState {
    /// The opener is running and has not created or claimed anything yet. Opening again is the
    /// correct recovery from a failure here.
    Opening,
    /// The target has been created or claimed, and the opener is waiting for it to stop. The
    /// target exists from here on, so re-running the open would attach a second time or start a
    /// second process.
    Attaching,
    /// The open completed. Ready for work.
    Open,
    /// The open failed without creating anything. This handle will never be usable.
    Failed(String),
    /// The worker still holds a target, but a raw command replaced it, so this handle no longer
    /// names what it was issued for. Calls that *supply* the handle are refused; calls that
    /// supply none still reach the worker, exactly as they did before handles existed.
    Retired(String),
    /// The session is over: ended, reclaimed, or its worker died.
    Closed(String),
}

impl SessionState {
    /// May a call that names this session by handle run against it?
    fn accepts_handle(&self) -> bool {
        matches!(self, Self::Opening | Self::Attaching | Self::Open)
    }

    /// May a call that named no session be routed here? Broader than [`Self::accepts_handle`] by
    /// exactly one state: a retired handle is refused, but the worker behind it is still the
    /// server's current target and a caller who asked for no guarantee still gets it.
    fn accepts_default(&self) -> bool {
        self.accepts_handle() || matches!(self, Self::Retired(_))
    }

    /// May a call that names this session by handle **release** it?
    ///
    /// Broader than [`Self::accepts_handle`] by the same one state, and for a reason that is not
    /// the same reason: retirement says the handle no longer names the *target* it was issued
    /// for, and a teardown does not touch the target — it releases the **session**, which the
    /// handle still names exactly.
    ///
    /// Refusing it was `FOLLOWUPS.md` item 55, found by the session fuzz. Two things did not line
    /// up. A raw `execute` that retires a handle appends "`end_session` releases it" and
    /// `end_session` with that handle was then refused, so the server contradicted its own
    /// instruction one call later. And the recovery the refusal named — omit `session_id` — routes
    /// to whichever session is *current*, so with anything newer open the retired one could not be
    /// released by its owner at all: it held one of the four slots and a live engine process until
    /// everything newer had gone, or a disconnect, or a lease expiry.
    ///
    /// Its own predicate rather than a second caller of [`Self::accepts_default`], whose set is
    /// the same today. They answer different questions — "where does an unaddressed call go" and
    /// "may this handle end its session" — and a state that ever wants one without the other
    /// should be a change here rather than a surprise there.
    fn accepts_teardown(&self) -> bool {
        self.accepts_handle() || matches!(self, Self::Retired(_))
    }

    /// Whether the session still owns a worker process.
    pub fn is_live(&self) -> bool {
        !matches!(self, Self::Failed(_) | Self::Closed(_))
    }

    /// The state's name on its own, for a transcript that records a transition as a value.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Opening => "opening",
            Self::Attaching => "attaching",
            Self::Open => "open",
            Self::Failed(_) => "failed",
            Self::Retired(_) => "retired",
            Self::Closed(_) => "closed",
        }
    }

    /// Why it is in this state, for the three that carry a reason.
    pub fn detail(&self) -> Option<&str> {
        match self {
            Self::Opening | Self::Attaching | Self::Open => None,
            Self::Failed(why) | Self::Retired(why) | Self::Closed(why) => Some(why),
        }
    }
}

/// One session: a worker process, its queue, and the outstanding calls against it.
#[derive(Debug)]
pub struct Session {
    pub id: String,
    pub kind: SessionKind,
    /// What was opened — the path, connection string, pid, or command line. Reported so a
    /// caller looking at several sessions can tell them apart.
    pub what: String,
    pub pid: u32,
    created: Instant,
    state: Mutex<(SessionState, Instant)>,
    tx: mpsc::UnboundedSender<Job>,
    next_id: AtomicU64,
    /// Calls submitted and not yet answered. Non-empty means the worker owes a reply — including
    /// for a call whose caller already gave up, which is precisely when a session must not be
    /// reclaimed as idle.
    waiters: Waiters,
    /// Whether `open` has finished with this session and told its caller about it. Until then it
    /// is not reclaimable however idle it looks — see [`Session::busy`].
    delivered: AtomicBool,
    /// Which client opened this session.
    ///
    /// The registry is one map for the whole server — handles are minted from it, the cap is
    /// shared, and `end_session` ends what it is handed — so two clients on one listener could see
    /// and end each other's targets. The listener's tenancy gate stood in for a boundary by serving
    /// one client at a time, and `2026-07-28` removed the identifier that gate was keyed on
    /// ([#162](https://github.com/glslang/windbg-mcp/issues/162)). Recording the owner makes the
    /// separation a property of the registry rather than of how many clients are let in — which is
    /// what let the gate be retired entirely.
    ///
    /// Always [`crate::client::Client::LOCAL`] under stdio, so the rules below are uniform rather
    /// than conditional.
    pub owner: crate::client::Client,
    /// When a call was last submitted against this session.
    ///
    /// The transport's disconnect is what normally releases a target, and under the revision of
    /// MCP this server now speaks over HTTP there is no disconnect to have: sessions were removed
    /// from the protocol (SEP-2567), so a client that vanishes is indistinguishable from one that
    /// is thinking, for ever. This is the only signal left that nobody is coming back
    /// ([#162](https://github.com/glslang/windbg-mcp/issues/162)).
    last_used: Mutex<Instant>,
    /// How far the opener got, as [`OpenPhase`]. Separate from the state on purpose.
    phase: AtomicU8,
    /// Whether *some* teardown got a successful `EndSession` out of this worker.
    ///
    /// Exists because two teardowns can race for one session — a reclamation releasing in the
    /// background and a disconnect arriving mid-flight — and only the winner is told it worked.
    /// The loser is failed out of its wait with [`EngineError::Lost`], which is indistinguishable
    /// from the worker having crashed. This is what tells those two apart, and the difference is
    /// "the target was let go" versus "a live kernel may be sitting halted".
    released: AtomicBool,
    /// How long this session's worker said a transaction it was told to unwind still needs, or
    /// `None` while it has said nothing. Set from [`WorkerMessage::RollingBack`] and read by the
    /// teardown whose own request provoked it; see [`Sessions::release`].
    ///
    /// **Written by [`read_messages`]'s thread**, where the bytes arrive, rather than by [`reader`]
    /// where every other message is handled. That is what the teardown's decision rests on: it
    /// reads this once, when its grace expires, and killing a worker that is mid-rollback because
    /// the runtime had not yet got round to dispatching the message would be the exact outcome the
    /// message exists to prevent. Recorded on arrival, "the worker said so in time" means what it
    /// says — it cannot turn on how busy this process was.
    ///
    /// Held as the **instant the batch must be done by**, not as the interval the worker named. The
    /// interval was measured when the milestone was sent and only ever shrinks after it, so reading
    /// it later as though it were still owed would hand a teardown the whole of a batch budget that
    /// had already been spent. A worker that finishes early retracts it by naming zero.
    unwinding: Arc<Mutex<Option<Instant>>>,
    /// The asynchronous run this session has outstanding, if any — see [`Execution`].
    ///
    /// One slot rather than a map, because a session has one engine thread and DbgEng moves a
    /// target only from inside `WaitForEvent`: a second run would have to wait for the first, so
    /// two handles could never both be live. Refusing the second is the same fact said out loud.
    execution: Mutex<Option<Execution>>,
    /// Serialises "may this call run?" against "put it in the queue", for this session.
    ///
    /// Both submitters read the execution slot and then send on [`Self::tx`], and between those
    /// two steps they are not holding anything: an ordinary call could pass
    /// [`Sessions::refuse_while_running`] with the slot empty, be descheduled, and enqueue
    /// *behind* a `Resume` that claimed the slot in the meantime. It would then wait out the
    /// whole run inside `WaitForEvent` instead of being told the target was running — and if the
    /// run outlasted its call timeout, its caller would see a timeout while a command that may
    /// mutate the target still ran when the target stopped. That is exactly the outcome the
    /// refusal exists to prevent, arriving through the gap in the middle of it.
    ///
    /// A lock of its own rather than the slot's, because the enqueue also takes the registry lock
    /// and [`Sessions::snapshot`] takes the registry lock and then the slot's — nesting the slot
    /// outside the registry here would close the loop. This one is only ever taken first, so it
    /// orders the two submitters against each other and nothing else.
    submit_gate: Mutex<()>,
    /// Bumped whenever [`Self::execution`] changes, so waiters wake without polling.
    ///
    /// A `watch` rather than a `Notify` for the one property that matters here: a receiver taken
    /// *before* the slot is read cannot miss a change made after that read. With a notify the
    /// waiter would have to register, then check, then await, and getting that order wrong loses
    /// a wakeup for the whole of a caller's timeout — a `wait_for_stop` reporting "still running"
    /// about a target that stopped a minute ago.
    execution_changed: tokio::sync::watch::Sender<u64>,
    child: Mutex<Option<Child>>,
    /// Where this session's life is recorded, when anything is. Held here rather than reached for
    /// through [`Sessions`] because the transitions worth recording happen in [`Self::update_state`],
    /// which the registry does not call and cannot see — a worker dying moves a session from a
    /// task that holds nothing but the session itself.
    rec: crate::record::Recorder,
}

/// A call that has been submitted and not yet answered: where its answer goes, and where the
/// milestones on the way to it go.
///
/// The two travel together because they have the same lifetime and the same lock. A milestone is
/// only worth reporting while somebody is still waiting for the result, and removing the waiter —
/// which is how a call stops counting as outstanding — takes the only reporter reachable by that
/// job id with it. Keeping them in separate maps would be two removals to keep in step, and the one
/// that got forgotten would report progress against a call already answered.
#[derive(Debug)]
struct Waiting {
    done: oneshot::Sender<Result<Output, EngineError>>,
    /// Where this call reports what it is doing, when its client asked to be told
    /// ([`crate::progress`]). `None` for the overwhelming majority: no `progressToken`, or no
    /// client at all — the shutdown sweep and reclamation call through here too.
    ///
    /// Read from the task-local on the **caller's** task, in [`Sessions::call_as`], because that is
    /// the only place both facts are in hand. The milestones themselves arrive in [`reader`], which
    /// belongs to the session rather than to any one call and can only find this by job id.
    progress: Option<crate::progress::Reporter>,
    /// Where this job's [`WorkerMessage::Resumed`] milestone goes — the one call that returns on
    /// a milestone rather than on its own result.
    ///
    /// `None` for every other call, and taken when it fires: the milestone is sent once per run,
    /// and a second one would mean a worker reporting a target it had already reported.
    ///
    /// Beside [`Self::progress`] rather than in a map of its own, for that field's reason: it has
    /// the same lifetime and the same lock, and removing the waiter must take it too — a
    /// `continue_async` still waiting when its job is answered has to be woken by the answer, not
    /// left holding a milestone that will never come.
    resumed: Option<oneshot::Sender<()>>,
    /// Whether this job's transaction has already been reported as unwound.
    ///
    /// The worker's two `RollingBack` messages are emitted by *different threads* — the promise by
    /// its request reader, the retraction by its engine thread — so a teardown landing exactly as a
    /// batch exits can put them on the wire in either order. [`read_messages`] already defends the
    /// session's deadline against that by keeping the earlier instant; this is the same defence for
    /// the words a client reads, which would otherwise go "has been rolled back" and then back to
    /// "rolling it back".
    unwound: bool,
}

type Waiters = Arc<Mutex<HashMap<u64, Waiting>>>;

/// A run started by `continue_async` and not yet replaced: the handle a caller holds, the job it
/// is, and — once the worker has answered — the stop it ended at.
///
/// **Installed when the job is submitted, not when the target starts moving**, which is the
/// property everything else here rests on. A session whose slot says nothing is running is one
/// where every tool reads a target that is standing still; if the slot were filled only once the
/// worker's milestone arrived, the window in between would be a target that may already be moving
/// and a supervisor that would let reads through to it.
///
/// **And it is not cleared when the run stops** — only replaced by the next one. The stop has to
/// survive the call that was waiting for it giving up, or a `continue_async` whose caller
/// disconnects mid-run leaves an answer nobody can ever read; and it has to survive being read, or
/// two `wait_for_stop` calls disagree about what happened.
#[derive(Debug)]
struct Execution {
    /// The handle, minted here and unique across this server — see [`mint_execution_id`].
    handle: String,
    /// The debugger command that set the target going, echoed back on every report about it.
    command: String,
    /// The worker job whose reply is this run's stop.
    job: u64,
    started: Instant,
    /// When the worker reported the target actually moving, or `None` while the run is still
    /// **queued** behind another operation on the engine thread.
    ///
    /// The slot is claimed before the job is even submitted, deliberately — a slot filled only
    /// once the worker answered would leave a window where the target may be moving and this side
    /// would let a read through. The cost of that is that `started` is when the *caller asked*,
    /// which is not when the target went. For a run that goes straight onto an idle engine those
    /// are the same instant; for one queued behind a `pool_census` they are minutes apart, and
    /// every figure derived from `started` is then wrong in the same direction: `running_for_ms`
    /// counts time the target stood still, and `breaks_in_ms` counts down a bound the worker has
    /// not started — reporting no bound left for a run that has just begun a full-length one.
    ///
    /// So the phase is recorded rather than inferred. [`Self::running`] deliberately does **not**
    /// read it: a queued run is one whose target may be moving by the time a read arrives, and
    /// that has always been the conservative answer.
    moving_since: Option<Instant>,
    /// How long the target actually ran, fixed when the stop is filed — `None` while it is still
    /// moving.
    ///
    /// Recorded rather than derived, because the clock it comes from goes on running after the
    /// run is over: a stop read an hour later would report an hour-long run, and `session_status` would
    /// show a finished run getting steadily longer. The stop is deliberately kept until another
    /// run replaces it, so "how long ago it was filed" and "how long it ran" are different
    /// questions and only the second is this one.
    ran_for: Option<Duration>,
    /// What the worker was told to bound its pump by, so a report can say when a run that is
    /// going nowhere will end itself.
    bound: Duration,
    /// The stop, once the worker answered — `None` while the target is moving.
    ///
    /// `Arc` because several `wait_for_stop` calls read one answer, and the two things it holds
    /// are both several strings; cloning per reader would copy a debugger's whole output each
    /// time somebody asked whether the run had finished.
    stopped: Option<Arc<Result<Output, EngineError>>>,
}

impl Execution {
    fn running(&self) -> bool {
        self.stopped.is_none()
    }

    /// Whether the target has started moving — the [`WorkerMessage::Resumed`] milestone.
    ///
    /// Named rather than spelled out at each use, for the reason this branch keeps rediscovering:
    /// a meaning written twice is one that drifts once. It is not the negation of anything here —
    /// a run can be `!moving() && running()` (claimed, still queued) and `moving() && !running()`
    /// (went, and has stopped).
    fn moving(&self) -> bool {
        self.moving_since.is_some()
    }

    /// How long the target ran: frozen once it stopped, counting while it has not, and zero while
    /// the run is still queued and the target has not moved at all.
    fn ran_for(&self) -> Duration {
        self.ran_for.unwrap_or_else(|| self.going_for())
    }

    /// How long the target has been moving, from the milestone rather than from the claim — zero
    /// for a run still waiting its turn on the engine thread. See [`Self::moving_since`].
    fn going_for(&self) -> Duration {
        self.moving_since
            .map_or(Duration::ZERO, |since| since.elapsed())
    }

    /// How much longer the worker will let the target run before breaking it in — `None` once it
    /// has stopped, and `None` again once the bound has passed with no stop reported, since a
    /// figure that has run out is not time anybody has left.
    fn breaks_in(&self) -> Option<Duration> {
        // Measured from the milestone, because that is when the *worker* starts its own bound: a
        // run queued behind a long operation would otherwise have its whole budget counted down
        // before the engine thread reached it, and report no bound left at the moment it began a
        // full-length run.
        self.running()
            .then(|| self.bound.saturating_sub(self.going_for()))
            .filter(|left| !left.is_zero())
    }

    fn info(&self) -> crate::structured::ExecutionInfo {
        crate::structured::ExecutionInfo {
            execution: self.handle.clone(),
            command: self.command.clone(),
            running_for_ms: ms(self.ran_for()),
            stopped: !self.running(),
            breaks_in_ms: self.breaks_in().map(ms),
        }
    }
}

/// The run that refused a claim, and how long it has been in the state it is in.
///
/// `waited` is measured from the milestone when `moving` and from the claim when it is not — see
/// [`Session::claim_execution`], where the two are told apart — so the refusal can say which of
/// the two it is quoting rather than calling a queue wait a run.
#[derive(Debug)]
struct Held {
    handle: String,
    waited: Duration,
    moving: bool,
}

/// One run, read out from under its session's lock so a caller can `await` on what it says.
struct FoundExecution {
    /// The worker job this run is, so a break can be bound to it rather than to whatever the
    /// engine thread happens to be doing when the request lands.
    job: u64,
    running: bool,
    stopped: Option<Arc<Result<Output, EngineError>>>,
    running_for: Duration,
    breaks_in: Option<Duration>,
}

/// A duration in whole milliseconds, saturating rather than wrapping.
fn ms(d: Duration) -> u64 {
    d.as_millis().min(u128::from(u64::MAX)) as u64
}

/// What a caller is told when the handle it presented is not the run its session is holding.
///
/// One answer for three cases — never issued here, issued by another session, or replaced by a
/// later run — and deliberately so: from the caller's side they are one fact, that this handle
/// names nothing to wait for, and each has the same next move. `session_status` is what
/// distinguishes them, and it is in every surface.
fn unknown_execution(session: &str, handle: &str) -> String {
    format!(
        "`{handle}` is not a run session `{session}` is holding. Either it was never issued here, \
         or another run has since replaced it — a session holds one at a time, and starting a new \
         one retires the last. `session_status` reports the run this session has, if it has one."
    )
}

/// A handle for one asynchronous run, unique across this server rather than within its session.
///
/// Within the session would be enough for the lookup — every tool that takes one takes a
/// `session_id` beside it — and is exactly why it is not done that way: `session_id` is optional
/// everywhere here, so an `exec-1` presented without one would be matched against whichever
/// session is current, which on a server holding four is a coin toss between "not yours" and a
/// **different run of the same name**. Unique handles make the second impossible.
fn mint_execution_id() -> String {
    let n = EXECUTION_SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    format!("exec-{nanos:x}-{n}")
}

static EXECUTION_SEQ: AtomicU64 = AtomicU64::new(1);

impl Session {
    fn state(&self) -> SessionState {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .0
            .clone()
    }

    /// Moves a live session to `next` and restamps it. Refuses to change a session that has
    /// already stopped owning a worker, so a milestone arriving from a worker being torn down
    /// cannot undo or relabel the teardown.
    fn set_state(&self, next: SessionState) {
        self.update_state(|state| state.is_live().then_some(next));
    }

    /// Replaces the dispatch-time reason for an explicit `end_session` with its final outcome.
    ///
    /// Conditional on the placeholder so another teardown that won the race keeps its own reason.
    fn finish_end(&self, reason: String) {
        self.update_state(|state| match state {
            SessionState::Closed(why) if why == END_SESSION_CLOSING => {
                Some(SessionState::Closed(reason))
            }
            _ => None,
        });
    }

    /// Recomputes the state *from itself*, under a single lock acquisition, and reports where it
    /// ended up. `next` returns `None` to leave it alone. Settled states cannot move, with one
    /// narrow exception: a `Closed` state may be refined to another `Closed` state so an
    /// `end_session` marked closed at dispatch can later record how its teardown finished.
    ///
    /// The atomicity is the whole point, and check-then-set through two acquisitions is not good
    /// enough: `pump` retires a session from another task the instant it forwards a
    /// target-changing command, so a transition that decided on a state it no longer holds would
    /// overwrite that retirement — and the handle would go on certifying a target the queued
    /// command is about to replace. Every conditional transition goes through here for that
    /// reason, not for tidiness.
    fn update_state(
        &self,
        next: impl FnOnce(&SessionState) -> Option<SessionState>,
    ) -> SessionState {
        // Whether this *changed* anything, which is a different question from whether a transition
        // was taken: a transition to the state the session is already in restamps it — that is
        // what `in_state_for` measures and nothing here may quietly stop doing — while there is
        // nothing about it worth a line in a transcript. Every conditional transition comes
        // through here and most of them decline, so recording each call would fill a file with a
        // session repeatedly not moving.
        let (settled, moved) = {
            let mut slot = self.state.lock().unwrap_or_else(|e| e.into_inner());
            let proposed = next(&slot.0);
            let allowed = slot.0.is_live()
                || matches!(
                    (&slot.0, &proposed),
                    (SessionState::Closed(_), Some(SessionState::Closed(_)))
                );
            if !allowed {
                return slot.0.clone();
            }
            let moved = match proposed {
                Some(next) => {
                    let moved = next != slot.0;
                    *slot = (next, Instant::now());
                    moved
                }
                None => false,
            };
            (slot.0.clone(), moved)
        };
        if moved {
            // Outside the lock: writing a record touches a disk, and nothing that does belongs
            // inside the mutex every state read in this process contends on.
            let limit = self.rec.field_limit();
            self.rec.write(crate::record::Event::SessionState {
                session: self.id.clone(),
                state: settled.name().to_string(),
                detail: settled
                    .detail()
                    .map(|d| crate::record::Capped::of(&crate::kdconn::scrub(d), limit)),
            });
        }
        settled
    }

    /// How far the opener got. See [`OpenPhase`] for why this is not read off the state.
    fn phase(&self) -> OpenPhase {
        OpenPhase::from_u8(self.phase.load(Ordering::Acquire))
    }

    /// Advances the opener's phase. Monotonic, so a milestone can never walk it backwards.
    fn reach(&self, phase: OpenPhase) {
        self.phase.fetch_max(phase as u8, Ordering::AcqRel);
    }

    /// How long the session has been in its current state.
    fn in_state_for(&self) -> Duration {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .1
            .elapsed()
    }

    /// Whether the worker owes a reply, is still opening, or has not been handed to its caller
    /// yet. An idle session is one that can be reclaimed to make room without abandoning work in
    /// flight.
    ///
    /// That last clause covers a window nothing else does. A session goes idle the moment its
    /// opener's waiter is removed — before `open` has returned the handle — so with two opens
    /// admitted at the limit, the later one's reconciliation could reclaim the earlier one and
    /// its caller would be handed a `session_id` that was already `Closed`. Undelivered means
    /// in flight as far as anyone outside is concerned.
    /// Whether nobody has asked this session for anything in `after`, so it can be let go.
    ///
    /// **`busy` first, and it is not a formality.** A live kernel attach parked in
    /// `WaitForEvent(INFINITE)` submits one call and then waits — possibly for hours, legitimately,
    /// until its target dials in. It has a waiter outstanding the whole time, so `busy()` covers
    /// it; reading the clock alone would release the one session whose whole job is to wait.
    fn idle_for(&self, after: Duration) -> bool {
        !self.busy()
            && self
                .last_used
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .elapsed()
                >= after
    }

    fn busy(&self) -> bool {
        !self.delivered.load(Ordering::Acquire)
            || !self
                .waiters
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty()
            // A target that is moving is work in flight, whatever the waiter map says — and for
            // most of a run it says so too, since the resume's own job is outstanding. The gap is
            // at the end: `reader` removes the waiter when the reply lands, and the task that
            // files the stop runs after it. In between, a session whose run had outlasted the
            // reclamation window would look both idle and stale, and could be closed by a
            // concurrent open — filing the stop on a session nothing can resolve any more, so the
            // caller waiting on that handle never learns what happened. Reading the slot closes
            // that window exactly: it is still `running()` until `finish_execution` says
            // otherwise, and that is the same call that restamps `last_used`.
            || self.running_execution().is_some()
            || matches!(
                self.state(),
                SessionState::Opening | SessionState::Attaching
            )
    }

    /// How much longer the worker's transaction may still need, from *now* — `None` when it has
    /// said nothing, and `None` again once the time it named has run out or it has said it is done.
    ///
    /// Read by the teardown that provoked it, after its own grace has run out — see
    /// [`Sessions::release`]. Nothing else consults it, and a session that never ran a batch never
    /// sets it, so an ordinary teardown neither reads nor pays for anything here.
    /// The last moment this session's worker named for its transaction — when it ended, or the
    /// bound it promised — or `None` if it never reported one. [`Self::unwinding_for`] is this read
    /// as time remaining; the raw instant is what a release's own grace is measured from.
    fn unwound_at(&self) -> Option<Instant> {
        *self.unwinding.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn unwinding_for(&self) -> Option<Duration> {
        let by = (*self.unwinding.lock().unwrap_or_else(|e| e.into_inner()))?;
        let left = by.saturating_duration_since(Instant::now());
        (!left.is_zero()).then_some(left)
    }

    /// Answers every outstanding call with `why`. Used when the worker dies or is killed: those
    /// callers are waiting on a reply that is never coming.
    fn fail_outstanding(&self, why: &str) {
        let waiters: Vec<_> = self
            .waiters
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain()
            .map(|(_, waiting)| waiting.done)
            .collect();
        for tx in waiters {
            let _ = tx.send(Err(EngineError::Lost(why.to_string())));
        }
    }

    /// This session's outstanding run, as a report — `None` when it has never had one.
    fn execution_info(&self) -> Option<crate::structured::ExecutionInfo> {
        self.execution
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(Execution::info)
    }

    /// The run that is **still going**, or `None` — which covers both "never started one" and
    /// "started one and it stopped". Those two are the same answer to the only question anyone
    /// asks this: may work reach the target?
    fn running_execution(&self) -> Option<(String, Duration)> {
        self.execution
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .filter(|execution| execution.running())
            .map(|execution| (execution.handle.clone(), execution.ran_for()))
    }

    /// Installs a run, replacing whatever the slot held. Refuses while one is still going.
    ///
    /// The check and the install are one lock acquisition, which is the whole of what stops two
    /// `continue_async` calls arriving together from both minting a handle: check-then-install
    /// through two acquisitions leaves a window in which each sees the slot free.
    fn claim_execution(&self, execution: Execution) -> Result<(), Held> {
        let mut slot = self.execution.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(running) = slot.as_ref().filter(|e| e.running()) {
            return Err(Held {
                handle: running.handle.clone(),
                // Two clocks and the refusal names which one it is quoting. A run that is moving
                // has been *resumed*, and how long ago is the milestone's business. One still
                // queued has not been resumed at all — quoting `ran_for` there would say `0ms`
                // about a call made ten minutes ago, and quoting the claim would call a queue
                // wait a run. So: since the target went, or since the caller asked, and the
                // sentence says which.
                waited: if running.moving() {
                    running.ran_for()
                } else {
                    running.started.elapsed()
                },
                moving: running.moving(),
            });
        }
        *slot = Some(execution);
        drop(slot);
        self.execution_moved();
        Ok(())
    }

    /// Files a run's outcome against the job that produced it.
    ///
    /// Keyed by **job**, not by handle, because the writer is a task that outlived its caller and
    /// the slot may by then hold a later run: a reply filed by handle alone could land a stop from
    /// the run before last on the one in flight. A job id is minted once per session and never
    /// reused, so a mismatch here is exactly "this answer is about a run nobody is holding any
    /// more" and is dropped.
    fn finish_execution(&self, job: u64, result: Result<Output, EngineError>) {
        {
            let mut slot = self.execution.lock().unwrap_or_else(|e| e.into_inner());
            let Some(execution) = slot.as_mut().filter(|e| e.job == job) else {
                return;
            };
            execution.ran_for = Some(execution.going_for());
            // The idle clock starts now, not when the run was submitted. `last_used` is stamped
            // on submission everywhere else, which is right for a call that answers in seconds
            // and wrong for one that can run for an hour: a session whose run outlasted the
            // reclamation window would be idle the instant it stopped, and could be taken before
            // its caller had read the stop it was waiting for.
            //
            // **Stamped before the stop is published, and under the slot's lock**, which is what
            // makes that true of every observer rather than of most of them. Publishing first
            // left a window with the two facts disagreeing: `busy()` reads the slot, so a run
            // marked stopped is no longer busy, while `last_used` still held the submission
            // stamp — and for a run that outlasted the window, that pair is exactly "idle and
            // stale". A sweep landing there releases the session and the stop is filed where its
            // caller can no longer resolve it, which is the failure the restamp exists to
            // prevent, surviving in the gap between two statements. Stamping inside the lock
            // closes it: `stopped` cannot be seen without acquiring this lock, and by the time it
            // can be, the new stamp is already in place.
            *self.last_used.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
            execution.stopped = Some(Arc::new(result));
        }
        self.execution_moved();
    }

    /// The run this handle names, if the slot still holds it.
    ///
    /// A copy rather than a guard, because every caller goes on to `await` and holding a
    /// `std::sync::Mutex` across an await point is how a session's slot comes to be locked by a
    /// task that has been parked.
    fn execution_by(&self, handle: &str) -> Option<FoundExecution> {
        let slot = self.execution.lock().unwrap_or_else(|e| e.into_inner());
        let execution = slot.as_ref().filter(|e| e.handle == handle)?;
        Some(FoundExecution {
            job: execution.job,
            running: execution.running(),
            stopped: execution.stopped.clone(),
            running_for: execution.ran_for(),
            breaks_in: execution.breaks_in(),
        })
    }

    /// Records that `job`'s target is actually moving — the [`WorkerMessage::Resumed`] milestone.
    ///
    /// Keyed by job for [`Self::finish_execution`]'s reason: the slot may by then hold a later
    /// run, and stamping that one would date it from a milestone that was not its own.
    fn execution_moving(&self, job: u64) {
        if let Some(execution) = self
            .execution
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_mut()
            .filter(|e| e.job == job)
        {
            // Only the first, so a worker that reported twice cannot restart the clock on a run
            // that has been going for an hour.
            execution.moving_since.get_or_insert_with(Instant::now);
        }
    }

    /// Wakes everything waiting on the slot. Sent rather than compared, so a run replaced by one
    /// that happens to look the same still wakes its waiters.
    fn execution_moved(&self) {
        self.execution_changed.send_modify(|seq| *seq += 1);
    }

    /// Kills the worker process. Idempotent.
    fn kill(&self) {
        let child = self.child.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(mut child) = child {
            // `start_kill` is enough: tokio's process driver reaps the child once it is dropped,
            // and waiting here would block the caller on a process that is already condemned.
            let _ = child.start_kill();
        }
    }
}

/// A queued call, waiting for its turn on the session's worker.
struct Job {
    id: u64,
    op: EngineOp,
    startup_symbol_path: Option<SymbolPathSetting>,
    submitted: Instant,
    gate: Gate,
}

/// On whose behalf a call runs, which is what decides whether the session may still accept it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum On {
    /// A caller who supplied `session_id`. They get the guarantee: refused unless the session
    /// still stands behind the handle it issued.
    Handle,
    /// A caller who supplied none, and so accepts whatever the current session holds — the
    /// behaviour from before handles existed.
    Default,
    /// A caller who supplied `session_id` and is **releasing** the session rather than working
    /// on its target. Admitted where [`Self::Handle`] is, plus a retired handle: retirement is
    /// about the target the handle no longer names, and a teardown does not touch the target.
    /// See [`SessionState::accepts_teardown`] and `FOLLOWUPS.md` item 55.
    Teardown,
    /// The supervisor's own teardown. There is no handle to honour and no caller to protect, so
    /// it runs against a session already marked closed. Reclamation needs this: it has to mark
    /// its victim before releasing it, or two opens racing at the session limit both pick the
    /// same one and only one of them frees anything.
    Supervisor,
}

/// What has to hold at the moment a call reaches the front of its session's queue.
///
/// This runs in [`pump`], immediately before the request is written and after everything queued
/// ahead of it — the slot the engine thread used to occupy, kept for the same reason. Checking on
/// the caller side instead would be a time-of-check/time-of-use bug: an `execute { ".opendump
/// other.dmp" }` already queued ahead can retire the handle between a caller's check and its
/// call, so the call would run against a target it never opened.
#[derive(Clone)]
struct Gate {
    on: On,
    /// Set when the call itself can replace the target, so the handle is retired *before* the
    /// command runs. A `.detach` that reports an error may still have detached, and a handle
    /// that outlives its target is the failure this ordering exists to prevent.
    retires: Option<String>,
    /// Set for an explicit teardown, so the session stops accepting work at this call's exact
    /// place in the queue. Everything ahead still runs; everything behind is refused as stale.
    closes: Option<String>,
}

impl Gate {
    /// Whether the session in `state` may still run this call.
    fn admits(&self, state: &SessionState) -> bool {
        match self.on {
            On::Handle => state.accepts_handle(),
            On::Default => state.accepts_default(),
            On::Teardown => state.accepts_teardown(),
            On::Supervisor => true,
        }
    }
}

/// How a caller's wait answers a worker that says it needs longer.
///
/// Only a teardown accepts more time, and only because it is the only wait a worker can ask to
/// extend: [`WorkerMessage::RollingBack`] is sent when an [`EngineOp::EndSession`] finds a
/// transaction to unwind. Every other call keeps the budget it was given.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Wait {
    Fixed,
    UntilUnwound,
}

/// A call to run against a session.
pub struct Call {
    op: EngineOp,
    startup_symbol_path: Option<SymbolPathSetting>,
    gate: Gate,
}

impl Call {
    /// A call the caller did not attach a handle to.
    pub fn new(op: EngineOp) -> Self {
        Self {
            op,
            startup_symbol_path: None,
            gate: Gate {
                on: On::Default,
                retires: None,
                closes: None,
            },
        }
    }

    /// Records whether the caller supplied `session_id`; see [`On`].
    pub fn named(mut self, named: bool) -> Self {
        self.gate.on = if named { On::Handle } else { On::Default };
        self
    }

    /// The same, for a call that **releases** the session rather than working on its target, so a
    /// retired handle is still good enough to end what it names. See [`On::Teardown`].
    fn releasing(mut self, named: bool) -> Self {
        self.gate.on = if named { On::Teardown } else { On::Default };
        self
    }

    /// Marks this call as one that can replace or release the target, retiring the handle before
    /// it runs.
    pub fn retiring(mut self, why: impl Into<String>) -> Self {
        self.gate.retires = Some(why.into());
        self
    }

    /// Carries supervisor-held starting state on an opener's first worker request.
    fn starting_with_symbols(mut self, setting: Option<SymbolPathSetting>) -> Self {
        debug_assert!(self.op.is_opener(), "startup symbols belong on an opener");
        self.startup_symbol_path = setting;
        self
    }

    /// Marks this call as the point where its session stops accepting work.
    fn closing(mut self, why: impl Into<String>) -> Self {
        self.gate.closes = Some(why.into());
        self
    }

    /// The supervisor's own teardown; see [`On::Supervisor`].
    fn supervisor(op: EngineOp) -> Self {
        Self {
            op,
            startup_symbol_path: None,
            gate: Gate {
                on: On::Supervisor,
                retires: None,
                closes: None,
            },
        }
    }
}

// ---- what `session_status` reads ------------------------------------------

/// A session as reported by `session_status`, taken without touching any worker.
#[derive(Clone, Debug)]
pub struct SessionSnapshot {
    pub id: String,
    pub kind: SessionKind,
    pub what: String,
    pub pid: u32,
    pub state: SessionState,
    /// How long the session has been in `state`.
    pub in_state_for: Duration,
    pub age: Duration,
    /// Whether a call that names no session is routed here.
    pub current: bool,
    /// The asynchronous run this session is holding, if it has ever had one.
    pub execution: Option<crate::structured::ExecutionInfo>,
}

// ---- outcomes of an open --------------------------------------------------

pub struct OpenReport {
    pub id: String,
    pub report: String,
    /// The target's own facts, as the worker read them off the engine. Defaulted — every field
    /// absent — only for a reply that carried none, which the openers do not produce.
    pub summary: crate::structured::TargetSummary,
}

/// How an open failed. The variants exist because they need different recovery advice, and
/// getting that wrong costs a second attach or a second process.
pub enum OpenError {
    /// No worker could be started, so no session exists and none could.
    Unavailable(String),
    /// Refused without opening anything: every session slot is taken by work in flight, or the
    /// connection is going away. The message says which.
    NoRoom(String),
    /// The open failed before anything was created or claimed. The slate is clean and opening
    /// again is the correct recovery.
    Clean(String),
    /// The target was created or claimed and something after it failed. The handle names a
    /// session that exists, so it is handed back rather than lost.
    PostCommit {
        id: String,
        message: String,
        /// The target opened and only the follow-up diagnostic failed — the session is fine.
        report_only: bool,
    },
    /// The wait was abandoned. The open may still be running and may still land.
    Timeout { id: String, message: String },
}

/// A slot taken for an open that has not registered its session yet.
///
/// Exists so the capacity check can see opens that are still in flight, and releases the slot on
/// drop — so an open that fails on the way (no worker, a bad path) gives it back rather than
/// holding it for the life of the process.
struct Slot {
    registry: Arc<Mutex<Registry>>,
    /// Whose open this is, so releasing the slot decrements the right client's count.
    owner: crate::client::Client,
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut registry = self.registry.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = registry.opening.get_mut(&self.owner) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                registry.opening.remove(&self.owner);
            }
        }
    }
}

/// How a worker took being told to let go of its target.
#[derive(Debug)]
enum Release {
    /// It released the target and said so — the whole reply, because what became of the target is
    /// the worker's answer and is on the reply beside the text (`Output::target_left_running`).
    Released(Box<Output>),
    /// It never answered inside the grace it was given — which is [`END_SESSION_TIMEOUT`] or
    /// [`SHUTDOWN_RELEASE_TIMEOUT`], plus any extension the worker asked for to unwind a
    /// transaction — and was killed. The case this whole design is for.
    Parked { waited: Duration },
    /// It had already exited.
    AlreadyGone,
    /// The engine reported an error releasing the target. The worker was killed anyway.
    Refused(String),
    /// The handle did not name a session that would accept the call. Nothing was torn down.
    Stale(String),
}

// ---- the registry ---------------------------------------------------------

#[derive(Default)]
struct Registry {
    /// Every session this server has held, oldest first: the live ones plus a bounded tail of
    /// closed ones, kept so a caller can still ask what became of a handle.
    all: VecDeque<Arc<Session>>,
    /// Opens that have taken a slot but have not registered a session yet.
    ///
    /// Without this the capacity check is blind to opens already in flight, and two of them can
    /// each look at the same four live sessions, each conclude there is room, and each spawn —
    /// so the bound is only enforced against sessions that finished opening.
    opening: HashMap<crate::client::Client, usize>,
    /// Set once the client has disconnected. Refuses new opens, so the set of workers to release
    /// stops growing while shutdown is walking it.
    closing: bool,
    /// Credentials that have been **revoked**, whose sessions must stop growing for the same
    /// reason `closing` exists — see [`Sessions::revoke`].
    revoked: std::collections::HashSet<crate::client::Client>,
    /// The symbol-path mutation each client explicitly asked future workers to start with.
    ///
    /// This is client state for the same reason sessions are: a listener credential is an
    /// isolation boundary, and one caller's host paths must not change another caller's opens.
    symbol_paths: HashMap<crate::client::Client, SymbolPathSetting>,
}

impl Registry {
    /// The session a call that names none is routed to: the newest that still accepts one.
    ///
    /// Computed rather than stored, so ending the newest session falls back to the one before it
    /// instead of leaving the server with no default while a perfectly good target is loaded.
    fn current(&self, owner: &crate::client::Client) -> Option<Arc<Session>> {
        self.all
            .iter()
            .rev()
            .find(|s| s.state().accepts_default() && &s.owner == owner)
            .cloned()
    }

    fn find(&self, id: &str) -> Option<Arc<Session>> {
        self.all.iter().find(|s| s.id == id).cloned()
    }

    fn live(&self) -> Vec<Arc<Session>> {
        self.all
            .iter()
            .filter(|s| s.state().is_live())
            .cloned()
            .collect()
    }

    /// The live sessions belonging to one client.
    ///
    /// Every question a *caller* asks is this one rather than [`Self::live`]: which session is
    /// current, whether there is room to open another, what `session_status` lists. `live` stays
    /// the server's own view, for the sweeps and the shutdown that are about workers rather than
    /// about who owns them.
    fn live_for(&self, owner: &crate::client::Client) -> Vec<Arc<Session>> {
        self.all
            .iter()
            .filter(|s| s.state().is_live() && &s.owner == owner)
            .cloned()
            .collect()
    }

    /// Sessions that still have a worker process, whatever their state says.
    ///
    /// Not the same set as [`Self::live`], and shutdown needs this one. A session claimed for
    /// reclamation is marked `Closed` immediately but its worker is released in the background, so
    /// between those two points it is not live and still owns a process — and a client
    /// disconnecting in that window would drop the runtime and cancel that release, leaving the
    /// worker to fall back on noticing its own request channel close: a bounded best effort,
    /// where an orderly `EndSession` was there for the asking.
    fn owning_workers(&self) -> Vec<Arc<Session>> {
        self.all
            .iter()
            .filter(|s| s.child.lock().unwrap_or_else(|e| e.into_inner()).is_some())
            .cloned()
            .collect()
    }

    /// Drops the oldest settled sessions once a client's history bound is exceeded. Live sessions
    /// are never evicted — forgetting one would report its handle as unknown, and the advice that
    /// follows from "unknown" is "open again", which for an attach or a launch means a second
    /// target.
    ///
    /// **The bound is per owner**, walked client by client, so what ages a client's history out is
    /// that client's own churn. A single deque bounded once would have let a busy client evict a
    /// quiet one's record of a session that failed an hour ago, which is exactly the answer
    /// `session_status` exists to keep.
    ///
    /// Nor is one that still owns a worker, whatever its state says. A session claimed for
    /// reclamation is `Closed` at once and released in the background, and evicting it in that
    /// window would take it out of [`Self::owning_workers`] — so a disconnect would no longer find
    /// it, the release would be cancelled with the runtime, and the worker would be left to let go
    /// on its own rather than being asked properly, which is the weaker of the two guarantees a
    /// halted kernel can be given.
    fn trim(&mut self) {
        let mut owners: Vec<crate::client::Client> = Vec::new();
        for session in &self.all {
            if !owners.contains(&session.owner) {
                owners.push(session.owner.clone());
            }
        }
        for owner in owners {
            while self.all.iter().filter(|s| s.owner == owner).count()
                > CLOSED_HISTORY + MAX_SESSIONS
            {
                let evictable = self.all.iter().position(|s| {
                    s.owner == owner
                        && !s.state().is_live()
                        && s.child.lock().unwrap_or_else(|e| e.into_inner()).is_none()
                });
                let Some(oldest_settled) = evictable else {
                    break;
                };
                self.all.remove(oldest_settled);
            }
        }
    }
}

/// The session registry: what [`crate::server`] holds instead of an engine handle.
#[derive(Clone)]
pub struct Sessions {
    inner: Arc<Mutex<Registry>>,
    call_timeout: Duration,
    rec: crate::record::Recorder,
}

impl Sessions {
    /// Creates an empty registry. No process is started until something is opened, so a server
    /// that is only ever asked for `tools/list` never loads DbgEng at all.
    ///
    /// Recording is off unless [`Self::recording`] turns it on, which is what every test here
    /// relies on: a registry is built in a dozen of them and none of them is about transcripts.
    pub fn new(call_timeout: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Registry::default())),
            call_timeout,
            rec: crate::record::Recorder::disabled(),
        }
    }

    /// Records this registry's sessions into `rec`. Called once, by `main`, with whatever the
    /// environment asked for.
    pub fn recording(mut self, rec: crate::record::Recorder) -> Self {
        self.rec = rec;
        self
    }

    /// The transcript this server is writing, so the tool surface can record against the same one.
    /// How long a tool call waits for an engine reply before giving up.
    ///
    /// Read by `wait_for_stop`, which has to cap its own wait below it: a wait that ran the whole
    /// budget would have the call expire rather than answering, and "the call expired" and "the
    /// target never stopped" are indistinguishable to the caller.
    pub fn call_timeout(&self) -> Duration {
        self.call_timeout
    }

    pub fn recorder(&self) -> crate::record::Recorder {
        self.rec.clone()
    }

    /// Sets or clears the calling client's starting symbol path for workers opened later.
    ///
    /// The tool calls this only after the same mutation succeeded in its current session, so a
    /// path DbgEng refused can never become startup state. Existing workers are deliberately not
    /// visited: this is a starting point, not shared engine state.
    pub fn set_startup_symbol_path(&self, setting: Option<SymbolPathSetting>) {
        let owner = crate::client::current();
        let mut registry = self.registry();
        match setting {
            Some(setting) => {
                registry.symbol_paths.insert(owner, setting);
            }
            None => {
                registry.symbol_paths.remove(&owner);
            }
        }
    }

    /// Snapshots the calling client's starting symbol path for one open.
    fn startup_symbol_path(&self) -> Option<SymbolPathSetting> {
        let owner = crate::client::current();
        self.registry().symbol_paths.get(&owner).cloned()
    }

    fn registry(&self) -> std::sync::MutexGuard<'_, Registry> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Routes a call to the session the caller named, or to the current one.
    ///
    /// This is where a stale handle is refused. It is *not* the whole check — the session can
    /// still be retired between here and the worker — which is why [`Gate`] repeats it at the
    /// front of the queue.
    ///
    /// It is also where the transcript learns **which** session a call reached
    /// ([`crate::record::routed_to`]), and it is here rather than at the call sites because the
    /// caller's argument is not the answer: a call naming no session still acts on the current
    /// one. Two tools resolve by hand instead of going through `run_call` — `interrupt` and
    /// `end_session` — and recording at the funnel is what stops them, and the next one like
    /// them, from being missed.
    pub fn resolve(&self, supplied: Option<&str>) -> Result<Arc<Session>, EngineError> {
        self.resolve_admitting(supplied, SessionState::accepts_handle)
    }

    /// [`Self::resolve`] for a call that **releases** the session rather than working on its
    /// target, so a retired handle still resolves.
    ///
    /// Both halves have to agree: this is the caller-side check, and [`Call::releasing`] is the
    /// same widening at the front of the queue. Widening one alone would trade the refusal here
    /// for the same refusal a moment later, from a place with no caller to explain it to.
    pub fn resolve_for_teardown(
        &self,
        supplied: Option<&str>,
    ) -> Result<Arc<Session>, EngineError> {
        self.resolve_admitting(supplied, SessionState::accepts_teardown)
    }

    fn resolve_admitting(
        &self,
        supplied: Option<&str>,
        admits: fn(&SessionState) -> bool,
    ) -> Result<Arc<Session>, EngineError> {
        let registry = self.registry();
        let caller = crate::client::current();
        let Some(want) = supplied else {
            let current = registry.current(&caller).ok_or_else(|| {
                EngineError::Stale(
                    "no debug session is open. Start one with open_dump / open_trace / \
                     attach_process / attach_kernel / attach_kernel_local / launch."
                        .to_string(),
                )
            })?;
            crate::record::routed_to(&current.id);
            return Ok(current);
        };
        match registry.find(want) {
            // **Another client's handle is not "refused", it is unknown.** Saying "that session
            // belongs to someone else" would confirm the handle exists and leak that a second
            // client is here, and there is nothing this caller could do with the answer. The
            // message below is the one a handle this server never issued gets, which is exactly
            // what this handle is from where the caller stands.
            Some(session) if session.owner != caller => {
                Err(EngineError::Stale(unknown_handle(want)))
            }
            Some(session) if admits(&session.state()) => {
                crate::record::routed_to(&session.id);
                Ok(session)
            }
            Some(session) => Err(EngineError::Stale(stale_handle(want, &session.state()))),
            None => Err(EngineError::Stale(unknown_handle(want))),
        }
    }

    /// Every session id the calling client owns, live or settled.
    ///
    /// For `server_log`, which reads one ring for the whole server: a record naming a session is
    /// only this caller's to read if the session is. Settled ones are included deliberately —
    /// the run-up to a session's *failure* is exactly what a caller asks the log for, and it is
    /// their own failure to read.
    pub fn visible_session_ids(&self) -> Vec<String> {
        let caller = crate::client::current();
        self.registry()
            .all
            .iter()
            .filter(|s| s.owner == caller)
            .map(|s| s.id.clone())
            .collect()
    }

    /// How many live sessions one client holds, **named rather than inferred**.
    ///
    /// Every other question about "the caller's sessions" reads the identity from the task-local
    /// [`crate::client::current`], because it is asked from inside a tool call, where that is
    /// exactly who is asking. This one is asked by the listener *after* the call has finished and
    /// its scope has ended, so the ambient answer there is the default `local` — which for a named
    /// client is either nobody's sessions or somebody else's. So the owner is a parameter: the
    /// caller of this method is the only thing that still knows.
    pub fn live_count_for(&self, owner: &crate::client::Client) -> usize {
        self.registry().live_for(owner).len()
    }

    /// A credential is gone: refuse it any *new* session from here.
    ///
    /// The counterpart of `closing`, for one client rather than the server, and it exists for the
    /// window a revocation has and a lease expiry does not. An expiry only fires after the client
    /// has been silent for a whole grace, and the grace is longer than the longest a call can keep
    /// it quiet — so no request of that credential's can still be in flight when its sessions are
    /// released. A revocation has no such quiet period: the token stops being accepted the moment
    /// the set is swapped, but a call that got past authentication a moment earlier is still
    /// running, and an opener may be seconds from registering.
    ///
    /// So the release cannot be a single pass over a snapshot. This closes the gate first, under
    /// the registry lock, and the release then walks a set that cannot grow — the same shape
    /// `closing` gives shutdown. The in-flight call fails, which is the right answer: its
    /// credential was revoked while it ran.
    ///
    /// **Never lifted**, and it used to need lifting. A [`crate::client::Client`] is an incarnation
    /// rather than a name ([#190](https://github.com/glslang/windbg-mcp/issues/190)), so a client
    /// configured under the same name afterwards is simply not this one and is not gated by this
    /// mark — which deleted the question of *when* to take it off, and with it two findings that
    /// lived there. What it leaves behind is a name and a `u64` per revocation, for the life of the
    /// process.
    pub fn revoke(&self, owner: &crate::client::Client) {
        let mut registry = self.registry();
        registry.revoked.insert(owner.clone());
        registry.symbol_paths.remove(owner);
    }

    pub fn snapshot(&self) -> Vec<SessionSnapshot> {
        let registry = self.registry();
        // A caller is shown its own sessions and told which of *those* is current. Another client's
        // are not listed: the handles would be unusable, and reporting them would say how many
        // clients this server has and what they are debugging.
        let caller = crate::client::current();
        let current = registry.current(&caller).map(|s| s.id.clone());
        registry
            .all
            .iter()
            .filter(|s| s.owner == caller)
            .rev()
            .map(|s| SessionSnapshot {
                id: s.id.clone(),
                kind: s.kind,
                what: s.what.clone(),
                pid: s.pid,
                state: s.state(),
                in_state_for: s.in_state_for(),
                age: s.created.elapsed(),
                current: current.as_deref() == Some(s.id.as_str()),
                execution: s.execution_info(),
            })
            .collect()
    }

    /// Runs `call` against `session`, awaiting the result with the configured timeout.
    pub async fn call(&self, session: &Arc<Session>, call: Call) -> Result<Output, EngineError> {
        self.call_within(session, call, self.call_timeout).await
    }

    async fn call_within(
        &self,
        session: &Arc<Session>,
        call: Call,
        budget: Duration,
    ) -> Result<Output, EngineError> {
        let id = session.next_id.fetch_add(1, Ordering::Relaxed);
        self.call_as(session, call, budget, id, Wait::Fixed).await
    }

    /// Registers a waiter for `id` and queues the job, without waiting for the answer.
    ///
    /// Split out of [`Self::call_as`] because there are now two kinds of caller: one that waits
    /// for its own reply, and `continue_async`, whose reply is a stop that arrives long after the
    /// call is over and is filed on the session instead. Both need the registration to happen the
    /// same way and in the same order, and a second copy of it is how the two come to disagree
    /// about when a session counts as busy.
    ///
    /// `resumed` is where [`WorkerMessage::Resumed`] is reported, for the one caller that returns
    /// on it.
    fn submit(
        &self,
        session: &Arc<Session>,
        call: Call,
        id: u64,
        resumed: Option<oneshot::Sender<()>>,
    ) -> Result<oneshot::Receiver<Result<Output, EngineError>>, EngineError> {
        let _gate = session
            .submit_gate
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        self.submit_gated(session, call, id, resumed)
    }

    /// [`Self::submit`] with [`Session::submit_gate`] already held, for the one caller that has to
    /// hold it across a decision of its own — [`Self::start_execution`], whose claim on the
    /// execution slot and whose enqueue must not have another submission between them.
    fn submit_gated(
        &self,
        session: &Arc<Session>,
        call: Call,
        id: u64,
        resumed: Option<oneshot::Sender<()>>,
    ) -> Result<oneshot::Receiver<Result<Output, EngineError>>, EngineError> {
        // Refused rather than queued while the target is moving — see
        // [`Sessions::refuse_while_running`]. Under the gate above, so the answer cannot go stale
        // between here and the enqueue below.
        if let Some(refusal) = self.refuse_while_running(session, &call.op) {
            return Err(refusal);
        }
        let (tx, rx) = oneshot::channel();
        // Registered before the job is queued, so the session counts as busy from the moment the
        // call is submitted rather than from the moment it is written to the worker.
        //
        // Under the *registry* lock, which is not this map's lock and is not about this map: it is
        // what `claim_overage_victim` holds while it decides a session is idle and closes it.
        // Without taking it here, a call could become in-flight in the gap between that decision
        // and the close, and reclamation would then end a session the caller had just started
        // using. Held only across the insert; the send below is outside it.
        //
        // The reporter is read here for a reason of its own: this is the caller's task, and so the
        // last point at which the client's request is still reachable. Everything past it —
        // `pump`'s thread, the worker's reader — belongs to the session rather than to this call.
        {
            let _reclamation = self.registry();
            // Touched on submission rather than on completion: a call that is still running keeps
            // the session `busy()` anyway, and the question this answers is when someone last
            // *wanted* it.
            *session.last_used.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
            session
                .waiters
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(
                    id,
                    Waiting {
                        done: tx,
                        progress: crate::progress::current(),
                        resumed,
                        unwound: false,
                    },
                );
        }
        let queued = session.tx.send(Job {
            id,
            op: call.op,
            startup_symbol_path: call.startup_symbol_path,
            submitted: Instant::now(),
            gate: call.gate,
        });
        if queued.is_err() {
            session
                .waiters
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&id);
            return Err(EngineError::Lost(worker_gone(&session.id)));
        }
        Ok(rx)
    }

    /// Refuses a call that would read or drive a target an asynchronous run has moving — or
    /// `None` for one that may go through.
    ///
    /// **A refusal rather than a queue**, which is the whole of the choice. The session's engine
    /// thread is inside `WaitForEvent` for the length of the run, so anything queued behind it is
    /// answered whenever the target next stops: minutes, or the bound the run was started with,
    /// and from the caller's side indistinguishable from a debugger that has hung. Worse, the
    /// answer when it came would describe a target at a position nobody asked about.
    ///
    /// Three ops go through, each for its own reason. [`EngineOp::Interrupt`] is what stops the
    /// run — it is answered by the worker's request reader ahead of the queue, so it does not wait
    /// for the engine thread at all. [`EngineOp::EndSession`] is the other way out, and a teardown
    /// refused because the target is running is a session nothing can release. And
    /// [`EngineOp::Resume`] is refused a second way, by the slot itself
    /// ([`Session::claim_execution`]), which reports the handle already holding it rather than the
    /// generic sentence here.
    fn refuse_while_running(&self, session: &Arc<Session>, op: &EngineOp) -> Option<EngineError> {
        if matches!(
            op,
            EngineOp::Interrupt { .. } | EngineOp::EndSession | EngineOp::Resume { .. }
        ) {
            return None;
        }
        let (handle, running_for) = session.running_execution()?;
        Some(EngineError::TargetRunning(format!(
            "The target on session `{}` is running: it was resumed {} ago and has not stopped. \
             Nothing can be read from a target while it moves, so this call was refused rather \
             than queued behind the run — queued, it would have been answered whenever the target \
             next stopped, about wherever it happened to be. The run is `{handle}`: wait for its \
             stop, break the target in, or end the session.",
            session.id,
            crate::server::fmt_duration(running_for),
        )))
    }

    /// [`Self::call_within`] with the job id chosen by the caller, which only the opener does —
    /// see [`OPENER_JOB`] — and with how this wait answers a worker that asks for more time.
    async fn call_as(
        &self,
        session: &Arc<Session>,
        call: Call,
        budget: Duration,
        id: u64,
        wait: Wait,
    ) -> Result<Output, EngineError> {
        // Borrowed rather than consumed, so an expired budget can be extended below without losing
        // the reply that may still be coming.
        let mut rx = self.submit(session, call, id, None)?;
        // The sender is dropped only when the worker's reader gives up on it, which it does by
        // answering first — so `Err` here is the residual case, not the normal one.
        let settled = |reply: Result<Result<Output, EngineError>, oneshot::error::RecvError>| {
            reply.unwrap_or_else(|_| Err(EngineError::Lost(worker_gone(&session.id))))
        };
        if let Ok(reply) = tokio::time::timeout(budget, &mut rx).await {
            return settled(reply);
        }
        // The budget is spent. A teardown keeps waiting only while the worker keeps saying it is
        // unwinding a transaction — and it asks again every time it looks, because the answer
        // moves in both directions: the batch may finish early and hand the rest back, or run on
        // to the bound it promised. Committing to one extension read at this instant would honour
        // neither.
        if wait == Wait::UntilUnwound {
            let mut left = self.call_timeout;
            while let Some(within) = session.unwinding_for().filter(|_| !left.is_zero()) {
                let slice = unwind_slice(within, left);
                if let Ok(reply) = tokio::time::timeout(slice, &mut rx).await {
                    return settled(reply);
                }
                left -= slice;
            }
            // The transaction is over — it either said so or ran out the bound it promised — and
            // the release has not started until this moment, because it was queued behind it. So
            // it gets the grace it would have had if there had been no transaction at all, rather
            // than whatever the batch happened to leave over.
            //
            // A guarantee, where the worker's own retraction is only an optimisation: that message
            // is emitted as the batch ends, so a batch that runs to its bound emits it at the very
            // instant this loop stops looking. Resting on it arriving first would be resting on
            // pipe scheduling, and losing costs a worker killed as its release begins.
            if let Some(handoff) =
                release_handoff(session.unwound_at(), Instant::now(), budget, left)
                && let Ok(reply) = tokio::time::timeout(handoff, &mut rx).await
            {
                return settled(reply);
            }
        }
        // A timeout is an operational outcome, not broken plumbing: the target may simply still be
        // running. Note the job itself is *not* cancelled — only this wait for it.
        //
        // Its own record, and not merely a failed `tool_result`: the two say different things. The
        // result says this caller gave up; this says the *job* is still out there, which is the
        // fact that makes a later reply, or a session that will not go idle, make sense.
        self.rec.write(crate::record::Event::CallTimeout {
            session: session.id.clone(),
            budget_ms: budget.as_millis().min(u128::from(u64::MAX)) as u64,
        });
        Err(EngineError::Timeout(format!(
            "engine call timed out (the target may still be running). The session `{}` is still \
             holding this call; `session_status` reports it, and `end_session` ends it outright — \
             including by terminating the worker process if it will not unwind.",
            session.id
        )))
    }

    /// Opens a target in a fresh worker process.
    pub async fn open(
        &self,
        kind: SessionKind,
        what: String,
        op: EngineOp,
    ) -> Result<OpenReport, OpenError> {
        debug_assert!(op.is_opener(), "open() needs an opener op");
        // A default belongs to the moment an open starts. One changed while this worker is being
        // selected or spawned affects the next open, not a request already in flight.
        let startup_symbol_path = self.startup_symbol_path();
        // Take a slot before doing anything expensive, but do **not** reclaim anything yet — see
        // `take_slot` and `reconcile_capacity` for why those are separate.
        let slot = self.take_slot().map_err(OpenError::NoRoom)?;

        let id = mint_session_id();
        // Read before the worker exists, because the architecture of the target decides which
        // process that worker's engine lives in — see `worker::TARGET_FLAG`.
        let opening = op.opening();
        let session = match self.spawn(&id, kind, what, opening.as_ref()).await {
            Ok(session) => session,
            // The slot goes back and no existing session was touched: a worker that would not
            // start must not cost the caller a target they already had.
            Err(why) => return Err(OpenError::Unavailable(why)),
        };
        if let Err(why) = self.admit(&session) {
            // Refused *before* the opener was written, so this worker is `Ready` and holds
            // nothing at all — no dump, no trace, no attach. There is no target to release and so
            // nothing for its channel closing to accomplish; killing it is the whole teardown.
            //
            // And nothing is recorded, because nothing happened to a target: no session was
            // registered, so there is none to end either. The caller is told why in the result.
            // Recording an open here — as this did, from inside `spawn` — would put a session in
            // the transcript that never existed, with no end to match it, and a disconnect racing
            // a handshake is enough to produce one *after* the shutdown record.
            session.kill();
            return Err(OpenError::NoRoom(why));
        }
        // Admitted, so this session exists and is routable. Recorded now rather than when the
        // *opener* returns: a target that then fails to open still had a process started against
        // it, and a transcript that only knew about the ones that worked would be missing exactly
        // the sessions somebody is reading it to understand.
        self.rec.write(crate::record::Event::SessionOpen {
            session: session.id.clone(),
            kind: kind.label().to_string(),
            // Already masked where it is a connection: an attach resolves its label in
            // `kdconn::select` before a worker is ever spawned. Scrubbed anyway, and capped,
            // because a `launch` target is a command line somebody wrote.
            target: crate::record::Capped::of(
                &crate::kdconn::scrub(&session.what),
                self.rec.field_limit(),
            ),
            engine_pid: session.pid,
        });
        // Released only now: from here the session is counted in `all` instead, and holding both
        // would count this open twice.
        drop(slot);

        // The supervisor's own milestone, and the only one an opener has before the worker's.
        // Bringing a worker up takes as long as `WORKER_READY_TIMEOUT` allows, and until this the
        // client has been told nothing at all — so a client watching progress reads a server that
        // looks idle for the one part of an open the *supervisor* is responsible for. Reported here
        // rather than from `spawn`, so it says a worker that was also admitted and registered:
        // `admit` can still refuse one, and a session that was never routable is not an open that
        // is under way. See [`crate::progress`] for why this one can be reported directly while the
        // worker's have to travel with the waiter.
        crate::progress::report(crate::progress::Step::Spawned { pid: session.pid });

        // On the reserved job id, so `reader` can still recognise this open if the caller's
        // timeout means nobody is left to settle it.
        let out = self
            .call_as(
                &session,
                Call::new(op).starting_with_symbols(startup_symbol_path),
                self.call_timeout,
                OPENER_JOB,
                Wait::Fixed,
            )
            .await;
        let outcome = match out {
            Ok(report) => {
                // Defensive: a worker that answered without reporting `Opened` still produced a
                // usable target, and leaving the session mid-open would make every later call
                // read as "still attaching".
                //
                // Promoted *only* from the opening states, never from `Retired`. A
                // target-changing `execute` can be queued behind an open — through an unnamed
                // call, or a handle read from `session_status` — and `pump` retires the session
                // when it forwards that command. Normalising to `Open` here would undo that
                // while the command is still on its way to the worker, and the handle would go
                // on certifying a target it no longer names.
                promote_opened(&session);
                // Only now, with a target that is genuinely open, is an existing session
                // reclaimed to pay for it — and not on this caller's clock: reclaiming waits on
                // *other* sessions' workers, each up to `END_SESSION_TIMEOUT`, and serially when
                // the overage is more than one. The caller is owed the handle for a target that
                // is already open.
                self.reconcile_capacity(&session);
                Ok(OpenReport {
                    id,
                    report: report.text,
                    summary: report.summary.unwrap_or_default(),
                })
            }
            Err(EngineError::Timeout(message)) => Err(OpenError::Timeout { id, message }),
            Err(e) => {
                let message = e.to_string();
                let state = session.state();
                // Which side of the seam the failure fell on is the **phase**, never the state.
                // The state also carries handle validity, so a command queued behind the open can
                // retire it and erase the distinction — and answering "your session exists" for
                // an open that created nothing strands the caller exactly as badly as the advice
                // this seam replaced.
                if !session.phase().committed() {
                    // Whether this still owes a slot is what `settle_uncommitted` reports, not
                    // what `state` said a moment ago: a session that has just been failed and
                    // killed owns nothing, and reconciling on its behalf would evict somebody
                    // else's idle target to pay for a session that no longer exists.
                    if settle_uncommitted(&session, &message) {
                        // Retired: a queued command owns that worker now, so it keeps its slot
                        // and has to pay for it.
                        self.reconcile_capacity(&session);
                    }
                    Err(OpenError::Clean(message))
                } else if !state.is_live() {
                    // The worker died after committing. Whatever it had claimed went with the
                    // process, so there is no session to hand back and no reason to warn against
                    // opening again — that is now the only way forward.
                    Err(OpenError::Clean(message))
                } else {
                    // The target exists and the wait failed; or it opened and only the diagnostic
                    // failed. Either way the session stays: making the caller re-open to get a
                    // handle is how they end up with two processes.
                    let report_only = session.phase() == OpenPhase::Opened;
                    // Same rule as the success path: `Retired` outranks this normalisation.
                    promote_opened(&session);
                    // It failed, but it left a live session behind, so it still has to pay for
                    // its slot. Skipping this is how the limit stops being one: the sessions
                    // retained this way are idle, so they go on satisfying the capacity check for
                    // the *next* open, and the count climbs.
                    self.reconcile_capacity(&session);
                    Err(OpenError::PostCommit {
                        id,
                        message,
                        report_only,
                    })
                }
            }
        };
        // The caller is about to be told about this session, whatever the outcome. Until that
        // moment it is not reclaimable however idle it looks — otherwise a concurrent open's
        // reconciliation can close it in the gap, and this returns a handle that is already dead.
        session.delivered.store(true, Ordering::Release);
        outcome
    }

    /// Ctrl+Breaks whatever a session's engine is running, leaving the session and its target
    /// alone.
    ///
    /// The graceful counterpart to [`Self::end`], and the reason both exist: `end_session` also
    /// ends a runaway command, but by throwing away the target it was running against. Here the
    /// operation returns to *its own* caller — with whatever it had reached — and the session is
    /// ready for the next call.
    ///
    /// Its own short budget rather than the call timeout, because this waits on nothing that can
    /// run long. The worker answers from its request reader, which is never blocked by the engine
    /// (that is what makes an interrupt deliverable at all), so anything slower than this is a
    /// worker that has stopped reading rather than one that is thinking.
    ///
    /// `bound` is the job the break is for, or `None` for "whatever this session is running".
    /// Only [`Self::break_in`] names one — see [`EngineOp::Interrupt`] for why the two callers
    /// differ.
    pub async fn interrupt(
        &self,
        session: &Arc<Session>,
        named: bool,
        bound: Option<u64>,
    ) -> Result<Output, EngineError> {
        let call = Call::new(EngineOp::Interrupt { job: bound }).named(named);
        let outcome = self.call_within(session, call, INTERRUPT_TIMEOUT).await;
        // Recorded from this side because an interrupt is a *cause*: whatever the interrupted call
        // reports next — a short result, a batch that says `INTERRUPTED`, a walk that stopped —
        // reads as an unexplained truncation without the record that somebody asked for it.
        self.rec.write(crate::record::Event::Interrupt {
            session: session.id.clone(),
            // The worker's own answer, and specifically the *narrow* half of it: did this
            // request raise the break. Most of what this op can do is `Ok` and sends nothing —
            // nothing was running, the job named had already finished, a batch was sealed for its
            // rollback, or a break was already pending — and this event exists to explain a later
            // truncated result, which a request that sent nothing does not.
            delivered: outcome
                .as_ref()
                .is_ok_and(|out| out.raised.is_some_and(crate::proto::Interrupted::delivered)),
            // Scrubbed and capped like every other debugger-supplied string that reaches the
            // transcript — this one is the engine's own words about what it stopped, and it is
            // the one path that was not going through the rule the module documents.
            detail: Some(crate::record::Capped::of(
                &crate::kdconn::scrub(&match &outcome {
                    Ok(out) => out.text.clone(),
                    Err(e) => e.to_string(),
                }),
                self.rec.field_limit(),
            )),
        });
        outcome
    }

    /// Sets the target running and hands back a handle for the run, without waiting for it to
    /// stop.
    ///
    /// **The wait this replaces is the caller's, not the worker's.** The engine thread still sits
    /// in `WaitForEvent` for the whole run — DbgEng moves a target from nowhere else — and it is
    /// still bounded, by `bound`, in the process that owns it. What changes is that the *tool
    /// call* returns as soon as the target is moving, so the caller can go and do the thing the
    /// run is waiting for: start a process on the guest, send an IOCTL, trip the code the
    /// breakpoint is on.
    ///
    /// So there is no hidden wait anywhere. The run is recorded on the session before the job is
    /// even queued, `session_status` reports it, `bound` says when the debugger will end it
    /// itself, and the reply is filed against the handle by a task that does not care whether this
    /// caller is still here.
    ///
    /// Returns when the worker says the target is moving, when the run turns out to have finished
    /// without ever moving it, or when this call's own budget runs out — which leaves the run in
    /// place rather than abandoning it, because by then it may well be running.
    pub async fn start_execution(
        &self,
        session: &Arc<Session>,
        named: bool,
        command: String,
        bound: Duration,
    ) -> Result<crate::structured::ExecutionStarted, EngineError> {
        let handle = mint_execution_id();
        let job = session.next_id.fetch_add(1, Ordering::Relaxed);
        // Held across both the claim and the enqueue below, which is what makes them one decision
        // as far as every other submitter is concerned: a call that takes this gate either sees a
        // free slot and is queued *ahead* of the resume, or sees the claim and is refused. See
        // [`Session::submit_gate`].
        let gate = session
            .submit_gate
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Claimed before anything is submitted, so a session with a run in flight is one whose
        // slot already says so — there is no window where the target may be moving and this side
        // would let a read through. The claim is also the "one at a time" check.
        session
            .claim_execution(Execution {
                handle: handle.clone(),
                command: command.clone(),
                job,
                started: Instant::now(),
                moving_since: None,
                ran_for: None,
                bound,
                stopped: None,
            })
            .map_err(|held| {
                let Held {
                    handle: other,
                    waited,
                    moving,
                } = held;
                let since = crate::server::fmt_duration(waited);
                let state = if moving {
                    format!("resumed {since} ago and not yet stopped")
                } else {
                    format!(
                        "claimed {since} ago and still waiting its turn behind another call on \
                         this session's engine"
                    )
                };
                EngineError::TargetRunning(format!(
                    "Session `{}` already has a run in flight: `{other}`, {state}. A session has \
                     one engine thread and a target moves only while that thread is pumping it, \
                     so a second run could not start until the first ended — this refusal is that \
                     fact, said at the point it can still be acted on. Wait for `{other}` to \
                     stop, break the target in, or end the session.",
                    session.id,
                ))
            })?;
        // Taken before the job is submitted so no change to the slot can be missed — including one
        // made by the filing task below before this function gets as far as waiting.
        let mut changed = session.execution_changed.subscribe();
        let (resumed_tx, mut resumed_rx) = oneshot::channel();
        let call = Call::new(EngineOp::Resume {
            command: command.clone(),
            timeout_ms: bound.as_millis().min(u128::from(u32::MAX)) as u32,
        })
        .named(named);
        let reply = match self.submit_gated(session, call, job, Some(resumed_tx)) {
            Ok(reply) => reply,
            Err(why) => {
                // Nothing was queued, so nothing will ever answer this job — and a slot left
                // saying "running" would refuse every later call on a session where nothing is.
                drop(gate);
                session.finish_execution(job, Err(why.clone()));
                return Err(why);
            }
        };
        // Everything below waits, and a lock held across an await is a lock held by a parked task.
        drop(gate);
        // Files the stop whenever it comes, whoever is still listening. Spawned before this
        // function waits for anything, because the case it exists for is this caller not being
        // here: a `continue_async` whose client disconnects mid-run must still leave the session
        // in a state where the next caller can see what happened.
        let filing = Arc::clone(session);
        tokio::spawn(async move {
            let result = reply
                .await
                .unwrap_or_else(|_| Err(EngineError::Lost(worker_gone(&filing.id))));
            filing.finish_execution(job, result);
        });

        // `moved` is what the milestone said; `running` is asked of the slot as the answer is
        // written, because a run can be over by then — a `g` onto a breakpoint one instruction
        // away does it routinely. Reporting the milestone as both would tell a caller to go and
        // do the thing the run is waiting for while the session is already stopped and taking
        // ordinary reads.
        let started = |moved: bool, found: &FoundExecution| crate::structured::ExecutionStarted {
            session_id: session.id.clone(),
            execution: handle.clone(),
            command: command.clone(),
            running: moved && found.running,
            moved,
            breaks_in_ms: found.breaks_in.map(ms),
        };
        let settled = tokio::time::timeout(self.call_timeout, async {
            loop {
                // **The milestone first, always.** A run can start and stop before this loop gets a
                // turn — a `g` onto a breakpoint one instruction away — and then both facts are
                // waiting here. Reading the stop first would answer "the target never started
                // moving" about a target that moved and stopped, which is the one sentence here
                // that is simply false. `try_recv` leaves the receiver usable when there is
                // nothing yet, and a value survives the sender being dropped, so a milestone sent
                // before the reply is never missed. Taken before the slot is read, and acted on
                // after: the ordering is what matters, not where the value is used.
                let moved = resumed_rx.try_recv().is_ok();
                // The slot has held this handle since before the job was submitted, so the only
                // way it stops resolving is another run replacing it — which a *stopped* run
                // permits, and this run may have stopped in the moment before this loop got a
                // turn. Reported rather than worked around, and both alternatives were worse: a
                // record built from a handle nothing resolves would say the stop is there to be
                // read when `wait_for_stop` can no longer find it, and carrying on round the loop
                // would wait for a change to a slot this run no longer owns until the call's whole
                // budget ran out.
                let Some(found) = session.execution_by(&handle) else {
                    return Err(EngineError::Stale(format!(
                        "The run on session `{}` was started and is `{handle}`, but another run \
                         has already replaced it — a session holds one at a time. Whatever this \
                         one reached cannot be read any more. Runs on a session are one at a \
                         time by construction, so start the next only once the last has been \
                         collected.",
                        session.id
                    )));
                };
                if moved {
                    return Ok(started(true, &found));
                }
                // Then the reply, which by now can only belong to a run that never moved the
                // target: the command completed by itself, or it was refused. A refusal is this
                // call's failure — reported rather than dressed up as a run that finished early,
                // which is what a `continue_async` on a session whose target has gone would
                // otherwise come back as.
                if let Some(stopped) = &found.stopped {
                    return match stopped.as_ref() {
                        Err(why) => Err(why.clone()),
                        Ok(_) => Ok(started(false, &found)),
                    };
                }
                // **One wait, for both signals.** The milestone does not arrive on this channel
                // — it arrives on `resumed_rx`, read at the top — so `reader` bumps the slot when
                // it lands. Waiting on the milestone's own channel *as well* would be a second
                // road to the same place, and waiting on this one *alone* without that bump is
                // what shipped in the first draft: `continue_async` slept until the run ended,
                // which CI caught as a call that took exactly as long as its target ran.
                //
                // `Err` is the sender dropped, which cannot happen while this holds the session —
                // answered rather than unwrapped all the same, and the loop's own two checks are
                // what answer it.
                //
                // Cancellation-safe: `watch::Receiver::changed` is documented to be, so losing the
                // race costs nothing on the next turn.
                if changed.changed().await.is_err() {
                    return Ok(started(false, &found));
                }
            }
        })
        .await;
        settled.unwrap_or_else(|_| {
            // The run stays on the session. This is the wait that gave up, and the job it was
            // waiting on is still out there — the same rule every other call here follows, with
            // one thing more to say, because a run nobody is holding a handle to would be a target
            // that could be moving with no way to find out.
            Err(EngineError::Timeout(format!(
                "The resume on session `{}` was submitted and had not reported the target moving \
                 before this call's budget ran out; it is `{handle}`. The run was not abandoned — \
                 `session_status` reports it, including whether the target is moving and when the \
                 debugger will break it in.",
                session.id
            )))
        })
    }

    /// Waits for an asynchronous run to stop, for at most `wait`.
    ///
    /// **Nothing here touches the engine**, which is what makes a timeout free of consequences:
    /// the run is bounded in the worker by what `continue_async` was asked for, and this waits on
    /// a channel the filing task writes. A wait that runs out has cancelled nothing, consumed
    /// nothing and left nothing behind — the target is still running, the handle is still good,
    /// and waiting again carries on.
    ///
    /// The stop is **read, not taken**: several waits can watch one run, a caller that gave up can
    /// come back for the answer, and two calls asking about one run must not disagree.
    pub async fn wait_for_stop(
        &self,
        session: &Arc<Session>,
        handle: &str,
        wait: Duration,
    ) -> Result<crate::structured::StopWait, EngineError> {
        let mut changed = session.execution_changed.subscribe();
        // **One deadline, taken once.** The loop can be woken by a change to the slot that is not
        // a stop — the `Resumed` milestone bumps it, which is what a caller waiting on a handle it
        // got from `session_status` will see — and re-arming `wait` on each turn would give each
        // of those wakeups the whole budget again. This wait is deliberately capped below the call
        // timeout (`STOP_WAIT_MARGIN`) so the call answers rather than expiring; a budget that can
        // be spent twice is that cap not holding.
        let deadline = tokio::time::Instant::now() + wait;
        // Set when the deadline passes, so the loop takes exactly one more turn — long enough to
        // re-read the slot through the checks below, and no longer.
        let mut ran_out = false;
        let report = |found: FoundExecution| crate::structured::StopWait {
            session_id: session.id.clone(),
            execution: handle.to_string(),
            running_for_ms: ms(found.running_for),
            stop: None,
            breaks_in_ms: found.breaks_in.map(ms),
        };
        loop {
            let Some(found) = session.execution_by(handle) else {
                return Err(EngineError::Stale(unknown_execution(&session.id, handle)));
            };
            if let Some(stopped) = &found.stopped {
                return match stopped.as_ref() {
                    // The run itself failed. Reported as this call's failure, keeping the kind the
                    // worker named — a caller asking what happened to a run gets the same answer
                    // the synchronous tool would have given it.
                    Err(why) => Err(why.clone()),
                    Ok(out) => Ok(crate::structured::StopWait {
                        // The worker's own value, folded into a record keyed by a handle it has
                        // never heard of. See `proto::Output::stop`.
                        stop: out.stop.as_deref().cloned(),
                        ..report(found)
                    }),
                };
            }
            // The budget is spent, and the checks above have just re-read the slot — which is
            // the point of answering here rather than where the timeout fired. The run may have
            // stopped while this was waiting out the last of it, and reporting a target as still
            // moving because a figure was a second stale is the one wrong answer this tool can
            // give.
            if ran_out {
                return Ok(report(found));
            }
            if tokio::time::timeout_at(deadline, changed.changed())
                .await
                .is_err()
            {
                ran_out = true;
            }
        }
    }

    /// Asks the engine to break an asynchronous run in, and answers without waiting for it to.
    ///
    /// The stop is not reported here on purpose: `SetInterrupt` lodges a request and returns, so
    /// the target stops at the engine's next poll — which is the run *ending*, and belongs where
    /// every other ending of that run is reported. Answering with a stop here would mean inventing
    /// one from a request that had only just been made.
    pub async fn break_in(
        &self,
        session: &Arc<Session>,
        handle: &str,
        named: bool,
    ) -> Result<crate::structured::BreakInRequested, EngineError> {
        let Some(found) = session.execution_by(handle) else {
            return Err(EngineError::Stale(unknown_execution(&session.id, handle)));
        };
        if !found.running {
            // Not an error: a run that stopped by itself while the caller was deciding to break it
            // is the ordinary race, and the thing they wanted has happened.
            return Ok(crate::structured::BreakInRequested {
                session_id: session.id.clone(),
                execution: handle.to_string(),
                requested: false,
                detail: format!(
                    "`{handle}` had already stopped, so nothing was sent. Read where it stopped \
                     rather than breaking it in."
                ),
            });
        }
        // **Bound to this run's job**, so it cannot be rebound. Between the check above and this
        // request being read, the run may have stopped and the worker started the next thing —
        // a command that was queued, or the run after this one — and an unbound break would land
        // on that instead, reported to *its* caller as an interruption nobody asked for.
        //
        // The failure is propagated rather than folded into `requested: false`, which used to
        // make a worker that could not be reached read exactly like the benign race below. They
        // are opposite facts: one says the target has already stopped, the other that nothing
        // knows whether it will.
        let out = self.interrupt(session, named, Some(found.job)).await?;
        Ok(crate::structured::BreakInRequested {
            session_id: session.id.clone(),
            execution: handle.to_string(),
            // The worker's answer, and the *wide* half of it: is this run going to stop. A break
            // already pending counts, and so does a queued run barred from starting — the caller
            // asked for the target not to keep going, and in both cases it will not. See
            // [`crate::proto::Interrupted`].
            requested: out.raised.is_some_and(crate::proto::Interrupted::stopping),
            detail: out.text,
        })
    }

    /// Ends a session: asks the worker to release its target, then terminates it.
    ///
    /// The kill is not a fallback for tidiness — it is the recovery path. A worker parked in a
    /// kernel attach that will never connect cannot answer, cannot be interrupted, and would
    /// otherwise hold its session forever; killing it is the only thing that ends that wait, and
    /// under process-per-session it costs nothing else.
    pub async fn end(&self, session: &Arc<Session>, named: bool) -> Result<Output, EngineError> {
        let call = Call::new(EngineOp::EndSession)
            .releasing(named)
            .closing(END_SESSION_CLOSING);
        let outcome = self.release(session, call, END_SESSION_TIMEOUT).await;
        // Read before the rendering, from the outcome rather than from the message it produces:
        // "did the worker let go, or was it killed still holding the target?" is the question a
        // caller has to act on, and it was previously only answerable by reading which paragraph
        // came back.
        let ended = crate::structured::SessionEnded {
            session_id: session.id.clone(),
            released: matches!(outcome, Release::Released(_)),
            worker_terminated: !matches!(outcome, Release::AlreadyGone | Release::Stale(_)),
            waited_ms: match &outcome {
                Release::Parked { waited } => {
                    Some(waited.as_millis().min(u128::from(u64::MAX)) as u64)
                }
                _ => None,
            },
            // The worker's answer where there was one, and this side's where only this side can
            // give one. A clean release reports what the engine actually did; a session that was
            // *terminated* holding its target reports `false` whatever it held, because
            // terminating a debugger is not a detach and the kernel takes the debuggee. And a
            // clean release of a session that had no live process to keep is `false` for a
            // `launch` — the one thing the worker cannot say, since the engine can tell an
            // attached live process from anything else but not a launch from a dump.
            target_left_running: match &outcome {
                Release::Released(out) => out
                    .target_left_running
                    .or((session.kind == SessionKind::Launch).then_some(false)),
                Release::Parked { .. } | Release::Refused(_) => {
                    matches!(session.kind, SessionKind::Process | SessionKind::Launch)
                        .then_some(false)
                }
                Release::AlreadyGone | Release::Stale(_) => None,
            },
        };
        let (reason, message) = match outcome {
            // A refused handle is the mechanism working, not a session to tear down.
            Release::Stale(why) => return Err(EngineError::Stale(why)),
            Release::Released(out) => (
                "ended by end_session".to_string(),
                format!(
                    "{}\n\nSession `{}` is closed and its engine worker process (pid {}) has \
                     been shut down.{}",
                    out.text,
                    session.id,
                    session.pid,
                    // The other half of what the worker says about an attached process, and it is
                    // here rather than there because **only this side knows**: the worker asks the
                    // engine, which can tell an attached live process from anything else but not a
                    // launch from a dump. `SessionKind` is the supervisor's, and this is the one
                    // place it meets a rendered result.
                    match session.kind {
                        SessionKind::Launch => LAUNCH_ENDED,
                        _ => "",
                    }
                ),
            ),
            Release::Parked { waited } => (
                format!("terminated by end_session after {waited:?} without unwinding"),
                format!(
                    "Session `{}` did not release its target within {waited:?}, so \
                     its engine worker process (pid {}) was terminated.\n\nThat is the expected \
                     outcome for a session parked in a wait DbgEng cannot be interrupted out of — \
                     a live-kernel attach whose target never connected is the usual one. The \
                     session is gone and the server is unaffected; no other session was touched.",
                    session.id, session.pid
                ),
            ),
            Release::AlreadyGone => (
                "the worker process was already gone".to_string(),
                format!(
                    "Session `{}` was already gone — its engine worker process had exited. The \
                     session is closed.",
                    session.id
                ),
            ),
            // The engine refused to release the target. Under process-per-session the worker has
            // no other purpose, so it still goes; reporting both is more use than leaving a
            // session the caller believes they ended.
            //
            // What it must not do is call that clean. Terminating a debugger is not a detach —
            // DbgEng resumes and detaches a live kernel as part of releasing it, and detaches a
            // process this server attached to, which is the step that just failed — so the one
            // caller who most needs to check their target was previously told there was nothing
            // to check.
            Release::Refused(why) => (
                format!("ended after an error: {why}"),
                format!(
                    "The debugger reported an error releasing the target:\n  {why}\n\nSession \
                     `{}` is closed and its engine worker process (pid {}) has been terminated. \
                     Terminating the debugger does not resume and detach for it, so a live kernel \
                     target may be left halted and a process this session attached to may have \
                     been killed rather than detached — check the target before treating this as \
                     a clean end. For a dump or a trace there is nothing left to clean up.",
                    session.id, session.pid
                ),
            ),
        };
        session.finish_end(reason);
        Ok(Output::typed(message, ended))
    }

    /// Asks a worker to release its target and then terminates it, without deciding *why* the
    /// session is closing — `end_session` and reclamation share the teardown but not the reason,
    /// and the reason is what the caller reads afterwards.
    ///
    /// The wait is the one that can be extended. A `debug_batch` is one indivisible job, so this
    /// `EndSession` queues *behind* it — but the worker's reader acts on the request as it reads
    /// it, telling that batch to stop at its next step and roll back, and answering with how long
    /// that leaves ([`WorkerMessage::RollingBack`]). So a grace that expires mid-transaction is
    /// extended by what the worker asked for, instead of killing a worker with the target still
    /// patched. A session with nothing to unwind never asks, and costs exactly `grace`.
    ///
    /// **Why the signal rides on this op rather than one of its own.** Telling a batch to stop is a
    /// sticky, one-way change to worker state, so it must not be possible for a teardown that does
    /// not happen. Sent separately it would be: the two requests are gated independently, and a
    /// target-changing call landing between them retires the session, so the release is refused
    /// while the abandon has already aborted somebody's transaction and left a flag no later batch
    /// could get past. Carried on the release, the property is structural — the gate below refuses
    /// before the request reaches the worker at all (the only path that returns without killing
    /// it), and every request that *does* reach it is followed by [`Session::kill`] a few lines
    /// down. Nothing can tell a batch to stop except a teardown that then ends the session.
    async fn release(&self, session: &Arc<Session>, call: Call, grace: Duration) -> Release {
        let waited = Instant::now();
        let id = session.next_id.fetch_add(1, Ordering::Relaxed);
        let out = match self
            .call_as(session, call, grace, id, Wait::UntilUnwound)
            .await
        {
            Err(EngineError::Stale(why)) => return Release::Stale(why),
            other => other,
        };
        let waited = waited.elapsed();
        // Recorded **before** `fail_outstanding`, and the order is the whole point: that call is
        // what turns another teardown's wait on this same session into `Lost`, so the flag has to
        // be visible by the time anyone is failed out of it. Reordering these two lines silently
        // restores a warning that says a target may be halted when it was just released.
        if out.is_ok() {
            session.released.store(true, Ordering::SeqCst);
        }
        session.fail_outstanding(&format!("session `{}` was ended", session.id));
        session.kill();
        let outcome = match out {
            Ok(out) => Release::Released(Box::new(out)),
            // Carries what it actually waited, because that is no longer one constant: a session
            // unwinding a transaction is given the extra time it asked for, and a report naming
            // the base grace would understate what was allowed before the worker was terminated.
            Err(EngineError::Timeout(_)) => Release::Parked { waited },
            Err(EngineError::Lost(_)) => Release::AlreadyGone,
            Err(e) => Release::Refused(e.to_string()),
        };
        // Recorded **here**, at the one place every teardown passes, rather than by each caller.
        // There are three — `end_session`, the shutdown sweep, and the reclamation that pays for
        // a new session at the limit — and the first two rounds of review each found one that had
        // been forgotten. A caller cannot forget this one.
        //
        // `released` is the session's flag, not this attempt's outcome, and the difference shows
        // when two teardowns race for one session: only the winner is told it worked, and the
        // loser's failure is not news about the *target*. The question a transcript is read for is
        // "was it let go?", which the flag answers and this attempt's result does not.
        //
        // A stale handle never reaches here — it returns above — so no teardown that tore nothing
        // down is recorded as one.
        session.rec.write(crate::record::Event::SessionEnd {
            session: session.id.clone(),
            released: session.released.load(Ordering::SeqCst),
            worker_terminated: !matches!(outcome, Release::AlreadyGone),
            waited_ms: match &outcome {
                Release::Parked { waited } => {
                    Some(waited.as_millis().min(u128::from(u64::MAX)) as u64)
                }
                _ => None,
            },
        });
        outcome
    }

    /// Ends every session, then terminates any worker that did not let go. Called when the client
    /// disconnects, so a debugger process — or a debuggee — never outlives the connection.
    ///
    /// A disconnect is treated as `end_session` on everything, which is both the simplest rule to
    /// explain and the only safe one: see [`SHUTDOWN_RELEASE_TIMEOUT`] for what killing a live
    /// kernel outright costs. Sessions are released concurrently because they are independent
    /// processes and the client is waiting.
    pub async fn shutdown(&self) {
        self.release_every_worker(Teardown::Shutdown).await
    }

    /// Releases every session the way [`Self::shutdown`] does, but **leaves the registry open**.
    ///
    /// For the listener ([`crate::listen`]), where a client going away is not the server going
    /// away: the lease on the sessions it opened expires, those targets are let go, and the next
    /// client opens its own. Closing the gate here would turn one client's disconnect into a
    /// server that can never debug anything again.
    ///
    /// The caller owns the race this leaves open. Nothing stops a session registering behind the
    /// snapshot, so the listener marks that client's lease `releasing` under the same lock that
    /// read its deadline, and refuses its requests until this returns — otherwise a client
    /// connecting exactly as its grace expires could have the session it just opened released
    /// underneath it.
    pub async fn release_leased(&self, owner: &crate::client::Client) {
        self.release_workers_of(Teardown::Lease, Some(owner)).await
    }

    /// Releases every session nobody has used for `after`, and says how many.
    ///
    /// The transport-independent half of what a disconnect used to do. `release_leased` releases
    /// *a client's* sessions when its lease runs out, which needs a client to identify; this asks
    /// only whether anyone is still using a target, which is answerable with no notion of a client
    /// at all — and so keeps working on a stateless transport where there is nothing to identify
    /// ([#162](https://github.com/glslang/windbg-mcp/issues/162)).
    ///
    /// **Claimed under the registry lock, released outside it**, exactly as
    /// [`Self::claim_overage_victim`] does and for a sharper version of the same reason. Deciding a
    /// session is idle and then ending it are two moments, and [`Self::call_as`] takes that same
    /// lock to register a waiter: without the claim, a call arriving in the gap would be routed to
    /// a session this sweep is about to tear down, and a caller would lose an operation it had
    /// just started — against a live kernel, mid-command. Closing the state under the lock is what
    /// makes the gap unreachable: [`Sessions::resolve`] refuses a `Closed` session, so a call is on
    /// one side of the claim or the other.
    pub async fn release_idle(&self, after: Duration) -> usize {
        let claimed = {
            let registry = self.registry();
            let stale: Vec<Arc<Session>> = registry
                .live()
                .iter()
                .filter(|session| session.idle_for(after))
                .cloned()
                .collect();
            for session in &stale {
                session.set_state(SessionState::Closed(format!(
                    "released after {}s with nobody using it — this server holds no target for a \
                     client that has stopped asking, because on a stateless transport there is no \
                     disconnect to notice",
                    after.as_secs()
                )));
            }
            stale
        };
        for session in &claimed {
            tracing::info!(
                "releasing session {} — nobody has used it for {}s",
                session.id,
                after.as_secs()
            );
            // The supervisor's own teardown rather than a caller's call, so it runs past the gate
            // the claim just closed — and orderly, because a live kernel that is merely killed is
            // left halted.
            self.release(
                &session.clone(),
                Call::supervisor(EngineOp::EndSession),
                END_SESSION_TIMEOUT,
            )
            .await;
        }
        claimed.len()
    }

    async fn release_every_worker(&self, teardown: Teardown) {
        self.release_workers_of(teardown, None).await
    }

    /// Releases every worker, or only those belonging to one client.
    ///
    /// `None` is the whole server going away, which is shutdown's question. `Some` is one client's
    /// lease running out, which since [#162] is emphatically not the same set: another client's
    /// sessions sit in the same registry and must survive a teardown that has nothing to do with
    /// them.
    ///
    /// [#162]: https://github.com/glslang/windbg-mcp/issues/162
    async fn release_workers_of(&self, teardown: Teardown, owner: Option<&crate::client::Client>) {
        // Closing the gate and taking the snapshot under **one** lock acquisition is what makes
        // one pass enough. [`Self::admit`] re-checks `closing` under this same lock after its
        // worker's handshake, so every open is on one side or the other of this moment: either it
        // registered first and is in `owners`, or it registers never and is refused. The set
        // cannot grow behind this snapshot, which is what earlier versions used a timed drain to
        // approximate.
        //
        // That guarantee is bought by `closing` and so belongs to shutdown alone; a lease release
        // does not get it, which is why the listener has to shut that client out for the duration
        // (see [`Self::release_leased`]).
        //
        // Every session that still *owns a worker*, not every live one. A session claimed for
        // reclamation is already `Closed` while its release runs in the background, and a
        // disconnect in that window would otherwise drop the runtime and cancel that release,
        // leaving the worker to notice its own request channel close — a five-second best-effort
        // where an orderly release was available. Releasing one twice is harmless; missing one is
        // not.
        let owners = {
            let mut registry = self.registry();
            registry.closing |= teardown.closes_registry();
            let owning = registry.owning_workers();
            match owner {
                Some(owner) => owning.into_iter().filter(|s| &s.owner == owner).collect(),
                None => owning,
            }
        };
        // Recorded before the releases rather than after them, and even when there are none: this
        // is the record that says the transcript ends here on purpose. Without it a file that
        // stops mid-session is indistinguishable from one whose server was killed.
        self.rec.write(teardown.record(owners.len()));
        if owners.is_empty() {
            return;
        }
        let label = teardown.label();
        tracing::info!("{label}: releasing {} session(s)", owners.len());
        let mut releasing = Vec::with_capacity(owners.len());
        for session in owners {
            let sessions = self.clone();
            releasing.push(tokio::spawn(async move {
                // Marked first so nothing new is routed to a session on its way out; the release
                // runs as the supervisor's own teardown and so passes the gate that closes. A
                // session already closed keeps the reason it closed for.
                session.set_state(SessionState::Closed(teardown.state_reason().to_string()));
                let outcome = sessions
                    .release(
                        &session,
                        Call::supervisor(EngineOp::EndSession),
                        SHUTDOWN_RELEASE_TIMEOUT,
                    )
                    .await;
                let note = shutdown_note(&outcome, session.released.load(Ordering::SeqCst));
                // `end_session` renders this for its caller. Shutdown has no caller — the client
                // has already gone — so the log is the only place it can land, and it is exactly
                // where an operator looks after finding a guest that did not come back.
                match note {
                    ShutdownNote::Released => {
                        tracing::info!("{label}: session {} released its target", session.id)
                    }
                    ShutdownNote::ReleasedElsewhere => tracing::info!(
                        "{label}: session {}'s target was released by a teardown already in flight",
                        session.id
                    ),
                    ShutdownNote::Refused(why) => tracing::warn!(
                        "{label}: session {} reported an error releasing its target ({why}); \
                         its worker (pid {}) was terminated anyway — and terminating a debugger \
                         does not resume and detach for it, so a live kernel target may be left \
                         halted",
                        session.id,
                        session.pid
                    ),
                    ShutdownNote::Unreleased(what) => tracing::warn!(
                        "{label}: session {} (pid {}) {what}, and no teardown reported \
                         releasing its target — so a live kernel target may be left halted",
                        session.id,
                        session.pid
                    ),
                    ShutdownNote::Settled(why) => tracing::info!(
                        "{label}: session {} was already settled ({why})",
                        session.id
                    ),
                }
            }));
        }
        for task in releasing {
            // A panic in here is not a correctness gap — the worker still has its own EOF teardown
            // to fall back on — but it is the difference between a target released and a target
            // released by the five-second best effort, and an operator should not have to infer
            // that from a frozen guest.
            if let Err(e) = task.await {
                tracing::error!("{label}: a session's release task failed: {e}");
            }
        }
    }

    /// Takes a slot for a new session, or refuses the open.
    ///
    /// Deliberately **decides** without **doing**: at the limit it only checks that some session
    /// *could* be reclaimed, and leaves the reclaiming to [`Self::reconcile_capacity`] once the
    /// replacement is real. Evicting here instead would mean a mistyped path, or a worker that
    /// would not start, destroys a perfectly good target the caller still wanted — a failed open
    /// must cost nothing but the attempt.
    ///
    /// Reclaimable means *idle*. A session with a call in flight — including one whose caller has
    /// already given up waiting, and including a parked attach — is never taken, because ending it
    /// silently is how a caller loses a target they are still using. When nothing is reclaimable
    /// the open is refused with the list, which is a better answer than picking a victim.
    fn take_slot(&self) -> Result<Slot, String> {
        let mut registry = self.registry();
        if registry.closing {
            return Err(shutting_down());
        }
        // **This client's sessions, not the server's.** The cap is what stops one caller filling
        // the machine with engine processes; applying it across clients would let a busy one deny
        // a quiet one, which is the shared-registry harm this separation exists to end.
        let caller = crate::client::current();
        let live = registry.live_for(&caller);
        let in_flight_for_caller = registry.opening.get(&caller).copied().unwrap_or(0);
        // How many sessions would have to be reclaimed to be back at the limit once this open,
        // and every open already in flight, has landed — against how many *can* be. Counting the
        // opens in flight is what stops two of them spending the same idle session: the first
        // needs one reclaimable, the second needs two.
        let needed = (live.len() + in_flight_for_caller + 1).saturating_sub(MAX_SESSIONS);
        let reclaimable = live.iter().filter(|s| !s.busy()).count();
        if needed > reclaimable {
            let listed: Vec<String> = live
                .iter()
                .map(|s| {
                    let busy = if s.busy() { " — busy" } else { " — idle" };
                    format!("  {} — {} ({}){busy}", s.id, s.kind.label(), s.what)
                })
                .collect();
            let in_flight = match in_flight_for_caller {
                0 => String::new(),
                n => format!(
                    " ({n} more open{} already in flight)",
                    if n == 1 { "" } else { "s" }
                ),
            };
            return Err(format!(
                "this server holds {} debug sessions{in_flight} and none of them can be reclaimed \
                 — a session with a call in flight is never ended to make room, and that includes \
                 an attach still waiting for its target. So there is no room to open another:\n{}\
                 \n\nEnd one with `end_session {{ \"session_id\": \"…\" }}` — it terminates that \
                 session's engine worker process even if the session is parked and cannot unwind \
                 on its own.",
                live.len(),
                listed.join("\n")
            ));
        }
        *registry.opening.entry(caller.clone()).or_default() += 1;
        Ok(Slot {
            registry: Arc::clone(&self.inner),
            owner: caller,
        })
    }

    /// Reclaims idle sessions until the server is back within [`MAX_SESSIONS`], now that
    /// `keeping` has actually opened and is worth paying for.
    ///
    /// Runs from **every** path that leaves a live session behind — a landed open, and an open
    /// that failed after committing but kept its target. Only reconciling on success is how the
    /// limit stops being one: a session retained by a post-commit failure is *idle*, so it goes
    /// on satisfying [`Self::take_slot`] for the next open, and the count climbs.
    ///
    /// Reclaims as many as it takes rather than one per call, because an overage can outlive the
    /// open that caused it: if every candidate was busy at the time, that debt is still owed once
    /// they go idle, and taking one victim per open would just carry it forever.
    ///
    /// `keeping` is excluded because it is idle the instant it opens, and with every other
    /// session busy it would otherwise be the one reclaimed — an open that closes itself.
    ///
    /// **Claims synchronously, releases in the background**, and the split is load-bearing in both
    /// directions. Claiming is a lock and a state write, so doing it on the caller's thread costs
    /// nothing and means the *next* `take_slot` sees the victims already gone — deferring it would
    /// let a concurrent open count them as reclaimable a second time, admit itself on capacity
    /// that was already spent, and end up reclaimed by the first open's own reconciliation.
    /// Releasing, by contrast, waits on another session's worker for up to
    /// [`END_SESSION_TIMEOUT`] each and serially when more than one is owed, and nobody opening a
    /// target should wait for unrelated sessions to finish ending.
    fn reconcile_capacity(&self, keeping: &Arc<Session>) {
        let mut victims = Vec::new();
        while let Some(victim) = self.claim_overage_victim(keeping) {
            tracing::info!(
                "reclaimed idle session {} (at the {MAX_SESSIONS}-session limit)",
                victim.id
            );
            victims.push(victim);
        }
        let over = self.registry().live_for(&keeping.owner).len();
        if over > MAX_SESSIONS {
            // The honest outcome when nothing is reclaimable: the alternatives are ending
            // someone's live target or discarding one that already opened. It does not compound —
            // `take_slot` refuses the next open — and the debt is settled by a later call here
            // once something goes idle.
            tracing::warn!(
                "{over} sessions are open, over the {MAX_SESSIONS} limit: nothing was idle \
                 enough to reclaim when `{}` opened",
                keeping.id
            );
        }
        if victims.is_empty() {
            return;
        }
        let sessions = self.clone();
        tokio::spawn(async move {
            for victim in victims {
                // Released the same way `end_session` releases one, so a live debuggee is let go
                // cleanly rather than dying with its debugger. As the supervisor's own teardown
                // rather than a caller's call, it runs past the gate the claim already closed.
                sessions
                    .release(
                        &victim,
                        Call::supervisor(EngineOp::EndSession),
                        END_SESSION_TIMEOUT,
                    )
                    .await;
            }
        });
    }

    /// Marks and hands back the oldest idle session while the registry is over the cap.
    ///
    /// Separate from [`Self::reconcile_capacity`] so the registry lock is never held across the
    /// release that follows. The marking happens *under* the lock, so a second open racing this
    /// one cannot see the same session as live-and-idle, pick it too, and free nothing.
    fn claim_overage_victim(&self, keeping: &Arc<Session>) -> Option<Arc<Session>> {
        let registry = self.registry();
        // **The owner's own sessions.** Reclaiming another client's idle target to make room for
        // this one is precisely the harm a shared registry did: it ends a session its owner still
        // holds a handle to, for a reason that has nothing to do with them.
        let live = registry.live_for(&keeping.owner);
        if live.len() <= MAX_SESSIONS {
            return None;
        }
        let idle = live.iter().find(|s| s.id != keeping.id && !s.busy())?;
        idle.set_state(SessionState::Closed(format!(
            "reclaimed to make room for a new session — this server holds at most \
             {MAX_SESSIONS} at once, and this was the oldest idle one"
        )));
        Some(Arc::clone(idle))
    }

    /// Registers a worker that has just come up — or refuses it, because the connection it was
    /// opened for is gone.
    ///
    /// This is a *second* reading of the same gate [`Self::take_slot`] checked, and the gap
    /// between them is the point: an open spends a whole worker handshake there, up to
    /// [`WORKER_READY_TIMEOUT`], and the client can disconnect in the middle of it. By then
    /// [`Self::shutdown`] has walked the registry and will not walk it again, so registering here
    /// would hand a target to a worker nobody is left to release — and for a live kernel attach
    /// that commits before the process goes, a target left halted.
    ///
    /// Refusing is what makes shutdown's single pass sound. Both take the registry lock, so an
    /// open is on one side or the other of the moment `closing` is set: it either registers first
    /// and is found by the snapshot, or is refused here. There is no interleaving in which a
    /// worker holding a target goes unseen.
    fn admit(&self, session: &Arc<Session>) -> Result<(), String> {
        let mut registry = self.registry();
        if registry.closing {
            return Err(shutting_down());
        }
        // **The credential was revoked while this open was in flight.** Refused here rather than
        // released afterwards, because "afterwards" has no end: an opener that authenticated a
        // moment before the revocation can be seconds from registering — an `attach_kernel` is —
        // so a one-pass release cannot see it, and the session it registers behind that pass is
        // owned by a client nothing can authenticate as and nothing will ever come back for. See
        // [`Self::revoke`].
        if registry.revoked.contains(&session.owner) {
            return Err(revoked(&session.owner));
        }
        registry.all.push_back(Arc::clone(session));
        registry.trim();
        Ok(())
    }

    /// Starts a worker process and waits for it to report that its engine came up.
    ///
    /// **More than one image may be tried**, because a 32-bit user dump wants a 32-bit worker and
    /// this build may not be one — see [`worker_images`]. A candidate that will not come up says
    /// nothing about the next, so the list is walked in order and only the last one's failure is
    /// the caller's. Falling back is not silent: the worker that does come up reads the same dump
    /// header the supervisor did and reports the limitation itself, so a session opened by the
    /// wrong-architecture worker says so in its summary.
    async fn spawn(
        &self,
        id: &str,
        kind: SessionKind,
        what: String,
        target: Option<&crate::target::Opening>,
    ) -> Result<Arc<Session>, String> {
        let images = worker_images(target)?;
        let mut started = None;
        let mut rest = images.iter().peekable();
        while let Some(exe) = rest.next() {
            match start_worker(id, exe, target).await {
                Ok(worker) => {
                    started = Some(worker);
                    break;
                }
                // The last image's failure is the caller's; every earlier one is a fallback, and
                // saying which image is being fallen back *to* is what makes the pair legible in a
                // log where the two are otherwise the same file name.
                Err(why) => match rest.peek() {
                    Some(next) => tracing::warn!(
                        "session {id}: {} could not come up ({why}); falling back to {}",
                        exe.display(),
                        next.display()
                    ),
                    None => return Err(why),
                },
            }
        }
        let StartedWorker {
            child,
            requests,
            messages,
            unwinding,
            pid,
            // Unreachable: `worker_images` never answers with an empty list, and the loop above
            // either breaks with a worker or returns the last image's error. Answered rather than
            // unwrapped because a panic here would take the supervisor down with it.
        } = started.ok_or("no engine worker image to start")?;
        tracing::info!("session {id}: engine worker pid {pid} ready");

        let (tx, rx) = mpsc::unbounded_channel();
        let waiters: Waiters = Arc::new(Mutex::new(HashMap::new()));
        let session = Arc::new(Session {
            id: id.to_string(),
            kind,
            what,
            pid,
            created: Instant::now(),
            owner: crate::client::current(),
            last_used: Mutex::new(Instant::now()),
            state: Mutex::new((SessionState::Opening, Instant::now())),
            tx,
            // Job ids start *past* the opener's, which is reserved — see [`OPENER_JOB`].
            next_id: AtomicU64::new(OPENER_JOB + 1),
            waiters: Arc::clone(&waiters),
            delivered: AtomicBool::new(false),
            phase: AtomicU8::new(OpenPhase::Started as u8),
            released: AtomicBool::new(false),
            unwinding,
            execution: Mutex::new(None),
            submit_gate: Mutex::new(()),
            execution_changed: tokio::sync::watch::Sender::new(0),
            child: Mutex::new(Some(child)),
            rec: self.rec.clone(),
        });
        // Both halves hold a `Weak`, so a session dropped from the registry takes its worker's
        // plumbing with it rather than keeping the Arc alive forever.
        let pumping = std::thread::Builder::new()
            .name(format!("reqs-{id}"))
            // A pump parks on its queue, and a session keeps its queue for as long as the registry
            // remembers it — a dozen at the outside — so keep the stack small. The loop serializes
            // one request and writes it; there is no deep call graph to leave room for.
            .stack_size(256 * 1024)
            .spawn({
                let session = Arc::downgrade(&session);
                let waiters = Arc::clone(&waiters);
                let call_timeout = self.call_timeout;
                move || pump(session, rx, requests, waiters, call_timeout)
            });
        if let Err(e) = pumping {
            // Nothing has been submitted yet, so this worker holds no target either. Killing it
            // also frees the reader thread, whose pipe closes with the process.
            session.kill();
            return Err(format!(
                "could not start a writer for an engine worker's requests: {e}"
            ));
        }
        tokio::spawn(reader(
            Arc::downgrade(&session),
            messages,
            waiters,
            self.clone(),
        ));
        Ok(session)
    }
}

/// The message for a handle whose session will not accept it.
fn stale_handle(want: &str, state: &SessionState) -> String {
    match state {
        SessionState::Failed(why) => format!(
            "session `{want}` never opened:\n  {why}\n\nOpening again is how you get a target — \
             but read the reason first, since some failures leave one behind."
        ),
        // The recovery named here is the one that always works: `end_session` accepts a retired
        // handle, because the handle still names the session even though it no longer names a
        // target (`SessionState::accepts_teardown`). Omitting `session_id` is mentioned second
        // and **qualified**, which was the other half of `FOLLOWUPS.md` item 55: it routes to
        // whichever session is current, so with anything newer open it reaches a different one —
        // advice that reads as a way back to this target and is a way to act on another.
        SessionState::Retired(why) => format!(
            "session handle `{want}` has been retired: {why}. The worker still holds a target, \
             but it is not the one this handle names, so the guarantee the handle buys no longer \
             applies. Open again for a handle that means something, or `end_session \
             {{ \"session_id\": \"{want}\" }}` to release this worker — that still takes this \
             handle. Omitting `session_id` reaches the worker only while this is still your \
             current session, so it is not a way back to it once you have opened another."
        ),
        SessionState::Closed(why) => format!(
            "session `{want}` is closed: {why}. Open a target again with open_dump / open_trace \
             / attach_process / attach_kernel / attach_kernel_local / launch."
        ),
        // The accepting states never reach here.
        _ => format!("session `{want}` is not accepting calls"),
    }
}

/// The job id **reserved** for a session's opener.
///
/// It is reserved rather than inferred. Inferring it from "the opener is the first call, and ids
/// start at 1" looks safe — `open` registers the session and submits the opener with no `await`
/// between — but it is not: a session is routable the moment it is registered (`Opening` and
/// `Attaching` both accept calls), so a tool call on another runtime thread can slip in and take
/// id 1 first. The opener would then get id 2, [`reader`] would stop recognising it, and the
/// settling that keeps a timed-out open from stranding its session would silently never run.
///
/// So `next_id` starts *past* this value and only [`Sessions::open`] ever uses it.
const OPENER_JOB: u64 = 1;

/// Moves a session that is still opening to [`SessionState::Open`], and leaves every other state
/// alone.
///
/// The states it refuses to touch are the point. `Retired` in particular must survive: a
/// target-changing command queued behind the open retires the session as `pump` forwards it, and
/// an opener finishing afterwards must not undo that — the handle would then certify a target the
/// queued command is about to replace.
fn promote_opened(session: &Session) {
    session.update_state(|state| {
        matches!(state, SessionState::Opening | SessionState::Attaching)
            .then_some(SessionState::Open)
    });
}

/// What a caller is told about a handle this server will not route.
///
/// One message for two cases — a handle that was never issued, and one belonging to another client
/// — because from where the caller stands they are the same fact, and distinguishing them would
/// confirm the existence of a session it may not touch.
fn unknown_handle(want: &str) -> String {
    format!(
        "unknown session handle `{want}`: this server is not holding it. Either it was never \
         issued here, or it closed a while ago and has aged out of the session history. A session \
         still in flight is never forgotten, so opening again is safe."
    )
}

/// Settles a session whose opener failed **without creating anything**, and ends its worker
/// unless something else has claimed it. Returns whether the session survived — which is to say,
/// whether it still owns a worker and therefore still owes its slot.
///
/// The exception is the whole reason this is a function rather than two lines: a target-changing
/// command queued behind the open retires the handle *and* takes the worker over, and that worker
/// may be about to hold a target of its own. Killing it because this open failed would discard
/// something the caller explicitly asked for. So a retired session keeps its worker and its
/// (retired) handle; only the open's own caller is told the slate is clean, which it is.
fn settle_uncommitted(session: &Session, why: &str) -> bool {
    if matches!(session.state(), SessionState::Retired(_)) {
        return true;
    }
    session.set_state(SessionState::Failed(why.to_string()));
    session.kill();
    false
}

/// Settles a session from its opener's result when nobody is left to do it — the caller's timeout
/// fired, so [`Sessions::open`] never saw the reply.
///
/// Returns whether the session was left **live**: its worker still holds a target, so it still
/// owes its slot and capacity has to be reconciled against it.
fn settle_open(session: &Session, result: &Result<Output, EngineError>) -> bool {
    // The same discriminator `open` uses, and for the same reason: the *phase* says whether a
    // target was created, while the state may since have been retired by a command queued behind
    // the open.
    if let Err(e) = result
        && !session.phase().committed()
    {
        // Nothing was created, so the handle will never be usable — unless something else has
        // taken the worker over, which `settle_uncommitted` is the arbiter of, and which is also
        // what decides whether a slot is still owed.
        return settle_uncommitted(session, &e.to_string());
    }
    // Decided and applied under one lock, for the reason `update_state` gives: `pump` can retire
    // this session from another task, and that must outrank a decision taken a moment earlier.
    let settled = session.update_state(|state| {
        // The target exists, so the session stays usable whichever way the open ended — that is
        // the whole point of committing before the wait. Retired and already-settled states are
        // left exactly as they are.
        matches!(state, SessionState::Opening | SessionState::Attaching)
            .then_some(SessionState::Open)
    });
    settled.is_live()
}

/// Why every session is being released at once.
///
/// The two occasions differ in one structural way and several cosmetic ones. The structural one:
/// **shutdown closes the registry and a lease expiry does not**, because the server is still
/// serving and the next client will want to open sessions of its own. The rest is saying which
/// happened — an operator reading a log after finding a guest that did not come back is owed the
/// difference between "the server stopped" and "your client went away and stayed away", since only
/// one of those is about them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Teardown {
    /// The server itself is going away.
    Shutdown,
    /// A client's lease on the sessions it opened ran out. See [`crate::listen`].
    Lease,
}

impl Teardown {
    /// Whether the registry is finished with, or merely between clients.
    fn closes_registry(self) -> bool {
        matches!(self, Self::Shutdown)
    }

    /// The log prefix every line of this teardown carries.
    fn label(self) -> &'static str {
        match self {
            Self::Shutdown => "shutting down",
            Self::Lease => "lease expired",
        }
    }

    /// What a session released this way says when something asks why it closed.
    fn state_reason(self) -> &'static str {
        match self {
            Self::Shutdown => "the server is shutting down",
            Self::Lease => "the client's lease on this session expired",
        }
    }

    /// The transcript record. Two variants rather than one with a reason, so a reader filtering a
    /// transcript for "the server stopped" does not have to also parse why.
    fn record(self, sessions: usize) -> crate::record::Event {
        match self {
            Self::Shutdown => crate::record::Event::Shutdown { sessions },
            Self::Lease => crate::record::Event::LeaseExpired { sessions },
        }
    }
}

/// What a session's teardown should be reported as at shutdown.
///
/// Separate from [`Release`] because a release attempt reports *its own* fate, and that is not the
/// same question as what became of the target. Two teardowns can be racing for one session — a
/// reclamation releasing in the background and a disconnect collecting it mid-flight — and only
/// the winner is told it worked. The loser sees a timeout, a `Lost`, or a debugger error, none of
/// which mean the target is still attached.
#[derive(Debug, PartialEq, Eq)]
enum ShutdownNote<'a> {
    /// This attempt released the target.
    Released,
    /// Another teardown released it first; this attempt's failure is a consequence, not news.
    ReleasedElsewhere,
    /// The engine answered and refused. The worker went anyway — which for a live kernel leaves
    /// the target no better off than [`Self::Unreleased`], since terminating a debugger does not
    /// resume and detach for it. Kept separate because the engine's reason is the lead here.
    Refused(&'a str),
    /// Nothing reported releasing the target, so it may still be attached. The string says what
    /// this attempt saw, since the two ways of getting here need different investigation.
    Unreleased(&'static str),
    /// There was nothing to tear down.
    Settled(&'a str),
}

/// Reads one session's teardown, given what its own attempt returned and whether *any* teardown
/// got a successful `EndSession` out of that worker.
///
/// The rule is one line: a success anywhere outranks this attempt's failure. Every non-success
/// outcome says only that *we* did not get a confirmation — `Parked` that our clock ran out,
/// `AlreadyGone` that another teardown failed us out of our wait, `Refused` that the engine had
/// nothing left to release and said so — and each of those is exactly what winning teardown
/// leaves behind.
///
/// What this cannot do is close the race, only stop misreading it: `released` is set a moment
/// before the losing waiter is failed, so a teardown that succeeds *while* this is being read
/// still logs as unreleased. Fixing that means shutdown waiting on another teardown's clock
/// rather than its own, which is a trade the five-second grace exists to refuse. A warning that
/// is occasionally early is the acceptable end of that; one that fires when nothing is wrong is
/// not, because the next real one gets ignored.
fn shutdown_note(outcome: &Release, released: bool) -> ShutdownNote<'_> {
    match outcome {
        Release::Released(_) => ShutdownNote::Released,
        Release::Stale(why) => ShutdownNote::Settled(why),
        _ if released => ShutdownNote::ReleasedElsewhere,
        Release::Parked { .. } => ShutdownNote::Unreleased(
            "did not let go within the grace and its worker was terminated",
        ),
        Release::AlreadyGone => {
            ShutdownNote::Unreleased("had no worker left to ask — it crashed, or was terminated")
        }
        Release::Refused(why) => ShutdownNote::Refused(why),
    }
}

/// Why an open is refused once the client has disconnected.
///
/// Shared by the two gates that refuse it — before a worker is spawned, and again after it comes
/// up — so the answer cannot drift depending on which one the caller raced.
/// What an opener is told when the credential it authenticated with was revoked while it ran.
///
/// Names the cause rather than reporting a generic refusal, because the caller's own token is
/// about to stop working for a *different* reason (a `401` on its next request) and one message
/// that explains both saves an operator guessing which of the two they are looking at.
fn revoked(owner: &crate::client::Client) -> String {
    format!(
        "the credential for client `{owner}` was revoked while this was opening, so the session \
         was not registered — nothing was left running. Whoever administers this listener removed \
         or rotated that client; the next request with the old token is refused outright."
    )
}

fn shutting_down() -> String {
    "this server is shutting down — the client disconnected, and every session is being released. \
     Nothing more can be opened on this connection."
        .to_string()
}

fn worker_gone(id: &str) -> String {
    format!(
        "the engine worker process holding session `{id}` is gone — it exited, crashed, or was \
         terminated. That session's target is lost; the server is unaffected, so opening again \
         starts a fresh one."
    )
}

/// Locates the executable to spawn workers from.
///
/// The supervisor re-executes *itself*, so worker and server can never drift apart in version or
/// in protocol. The override exists for tests, which run from a harness binary rather than from
/// the server.
///
/// **One target type does not take this image**, and [`worker_images`] is where that is decided:
/// a 32-bit user dump needs a 32-bit engine, which needs a 32-bit *process*, which cannot be this
/// one. The invariant above is then kept by construction rather than by identity — both images
/// come out of one build of one crate — and checked at the handshake, which is what
/// [`WorkerMessage::Ready`] carries a build identity for.
fn worker_exe() -> Result<PathBuf, String> {
    if let Some(path) = std::env::var_os("WINDBG_MCP_WORKER_EXE") {
        return Ok(PathBuf::from(path));
    }
    std::env::current_exe()
        .map_err(|e| format!("cannot locate this executable to spawn an engine worker: {e}"))
}

/// The worker images to try for a target, in order. Never empty.
///
/// **Only a 32-bit user-mode target gets more than one entry.** An extension DLL is loaded into
/// the debugger's own process, so its architecture is the *host's*: a 64-bit process cannot load
/// the 32-bit `sos.dll` at all, and the 64-bit one refuses a 32-bit CLR because the data access
/// DLL behind it is paired to the target as well as the host. No in-process arrangement reads a
/// 32-bit .NET target ([#234](https://github.com/glslang/windbg-mcp/issues/234)), so the engine
/// has to move — and since a process's architecture is fixed when its image loads, moving the
/// engine means moving the *process*.
///
/// **The decision has to precede the engine, which is why it is made here.**
/// `IDebugControl::GetEffectiveProcessorType` would answer authoritatively, but only inside a
/// session that already exists in a process whose architecture is by then the thing being chosen.
/// So [`crate::target`] answers it without one — from a dump's own header, or from
/// `IsWow64Process2` for a live process — and the supervisor, which has no engine and never will,
/// is the one place that answer can change which process is started.
///
/// **The fallback is deliberate**: a 32-bit target opens perfectly well in this build, and native
/// analysis of it works. Only SOS is lost. So a missing or unstartable 32-bit worker degrades to
/// this one rather than failing the open, and the worker that ends up with the target asks the
/// same question again and reports the limitation itself.
fn worker_images(target: Option<&crate::target::Opening>) -> Result<Vec<PathBuf>, String> {
    let default = worker_exe()?;
    // An explicit override means *this* image and no other. It is how the tests point a server at
    // a worker that is not the harness binary they run from, and second-guessing it would make
    // that unpredictable.
    if std::env::var_os("WINDBG_MCP_WORKER_EXE").is_some() {
        return Ok(vec![default]);
    }
    // A 32-bit build has nowhere better to put the engine than where it already is.
    if std::env::consts::ARCH == "x86" {
        return Ok(vec![default]);
    }
    let Some(target) = target else {
        return Ok(vec![default]);
    };
    match target.arch() {
        Ok(Some(crate::target::Arch::X86)) => {}
        // Not an error worth failing an open over, in either arm: the engine opens the target next
        // and will say far more about it than a header parse or an `IsWow64Process2` can.
        Ok(_) => return Ok(vec![default]),
        // **Warned, not `debug`ged**, because this is the one arm where the answer may be wrong
        // rather than merely uninteresting: the arms above *know* the target does not want
        // another image, and this one failed to find out. The session still opens — falling back
        // is the whole design — but it may quietly be the session a 32-bit target should not have
        // got, and this is the only place that will ever say so. It is the same level, and for
        // the same reason, as the "could not come up; falling back to" line in `spawn`.
        Err(why) => {
            tracing::warn!(
                "could not read the architecture of {} ({why}); using this build's worker, which \
                 is the wrong one if that target is 32-bit",
                target.describe()
            );
            return Ok(vec![default]);
        }
    }
    match x86_worker_image(&default) {
        Some(x86) => Ok(vec![x86, default]),
        None => Ok(vec![default]),
    }
}

/// The 32-bit worker beside this one, if this host has a usable one.
///
/// **An `x86\` subdirectory, not this directory**, and that is the loader's rule rather than a
/// tidiness choice: an executable's own directory is searched first, so a 32-bit `dbgeng.dll`
/// dropped beside the 64-bit one this server loads would be found by the wrong process. Putting
/// the 32-bit worker *inside* `x86\` turns that same rule into the mechanism — it loads the
/// engine sitting next to it, with no code here to make it happen. It is also the layout a
/// debugger package already ships (`amd64\`, `x86\`) and the one `setup.md` prescribes.
///
/// **Both halves are checked, because the engine is bound by the loader before `main` runs.** An
/// image with no `dbgeng.dll` beside it does not fail to open a dump; it fails to *start*, as a
/// loader error with no Rust in it. Probing for the pair here keeps that out of the fallback path.
fn x86_worker_image(default: &Path) -> Option<PathBuf> {
    let dir = default.parent()?.join("x86");
    if !dir.join("dbgeng.dll").is_file() {
        return None;
    }
    // This build's own file name first, then the released one. They are the same in a release
    // layout; they differ while the running image has been renamed out of the way for a rebuild,
    // and a stale 32-bit worker is worse than none.
    let named = default.file_name().map(|name| dir.join(name));
    named
        .into_iter()
        .chain(std::iter::once(dir.join("windbg-mcp.exe")))
        .find(|image| image.is_file())
}

/// A worker process that has come up and said so.
struct StartedWorker {
    child: Child,
    requests: PipeWriter,
    messages: mpsc::UnboundedReceiver<WorkerMessage>,
    /// Created before the thread that records into it, and handed to the session: see
    /// [`Session::unwinding`] for why it is written there rather than in [`reader`].
    unwinding: Arc<Mutex<Option<Instant>>>,
    pid: u32,
}

/// Starts one worker image and waits out its handshake.
///
/// Every failure path kills the child before returning, because nothing has been asked of it yet:
/// it holds no target, so killing it is the whole teardown. That is also what makes this safe to
/// call again with the next image.
async fn start_worker(
    id: &str,
    exe: &Path,
    target: Option<&crate::target::Opening>,
) -> Result<StartedWorker, String> {
    let (mut child, channel) = spawn_worker(exe, target)
        .map_err(|e| format!("could not start an engine worker ({}): {e}", exe.display()))?;

    let stdout = child.stdout.take().ok_or("engine worker has no stdout")?;
    let pid = child.id().unwrap_or(0);
    // Drained from the start, before the handshake: a worker that prints during startup must
    // not be able to block on a full pipe on its way to `Ready`.
    tokio::spawn(log_stray_output(id.to_string(), stdout));
    let unwinding: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));
    let mut messages = match read_messages(id.to_string(), channel.messages, Arc::clone(&unwinding))
    {
        Ok(messages) => messages,
        Err(e) => {
            let _ = child.start_kill();
            return Err(format!(
                "could not start a reader for an engine worker's messages: {e}"
            ));
        }
    };

    // Nothing is registered until the worker says its engine exists. A session that cannot
    // debug is worse than no session: it would accept calls and fail every one.
    let ready = match tokio::time::timeout(WORKER_READY_TIMEOUT, messages.recv()).await {
        // **The one thing a second worker image can get wrong that nothing else would catch.**
        // A stale `x86\\windbg-mcp.exe` deserializes this protocol well enough to look healthy and
        // then differs somewhere that surfaces as a debugger error hours later, so the mismatch is
        // refused here — where the caller still has a working fallback to be given instead.
        Ok(Some(WorkerMessage::Ready { build })) if build == crate::BUILD_VERSION => Ok(()),
        Ok(Some(WorkerMessage::Ready { build })) => Err(format!(
            "the engine worker at {} is build {build}, and this server is build {}; both images \
             come from one build of one crate, so replace the mismatched one",
            exe.display(),
            crate::BUILD_VERSION
        )),
        Ok(Some(WorkerMessage::Fatal { message })) => Err(message),
        Ok(Some(other)) => Err(format!("engine worker said {other:?} before it was ready")),
        Ok(None) => Err("the engine worker exited before it was ready".to_string()),
        Err(_) => Err(format!(
            "the engine worker did not come up within {WORKER_READY_TIMEOUT:?}"
        )),
    };
    if let Err(why) = ready {
        let _ = child.start_kill();
        return Err(why);
    }
    Ok(StartedWorker {
        child,
        requests: channel.requests,
        messages,
        unwinding,
        pid,
    })
}

/// The supervisor's ends of one worker's protocol channel.
///
/// Two anonymous pipes rather than the worker's standard handles, because those are shared with
/// everything else loaded into that process — see [`crate::proto`] for what a stray `printf` used
/// to cost. Anonymous, so there is no name for anything outside this pair of processes to open:
/// the only way to reach either pipe is the handle the child inherited.
struct Channel {
    /// Requests down to the worker.
    requests: PipeWriter,
    /// Messages up from it.
    messages: PipeReader,
}

/// Serializes **every** process this server creates, so an inheritable handle reaches only the
/// child it was made for. Held by [`spawn_worker`], by the TTD recorder ([`crate::ttd`]), and by
/// the stand-in children the tests below spawn — every `spawn()` in this process, without
/// exception, because that is what the guarantee is made of.
///
/// A handle marked inheritable is inherited by **every** process created while it is marked, and
/// `CreateProcess` cannot narrow that without a full `STARTUPINFOEX` handle list. So the hazard is
/// not "two opens racing" but "anything at all starting during the marking window". Two overlapping
/// opens would cross-inherit each other's channel ends; a `record_trace` landing there would hand
/// them to `TTD.exe`, which then outlives the whole recording. Either way the damage is the same
/// and it is concrete: a process holding a worker's *message write end* keeps that pipe from ever
/// reporting EOF, so the supervisor never learns that worker exited — [`reader`]'s tail does not
/// run, the calls it owed replies to wait for ever, and the session can never be reclaimed.
///
/// std holds a lock of its own across the same window for the stdio handles it prepares, which is
/// the same reasoning applied to the same hazard; this one covers the handles std knows nothing
/// about. **A new process created anywhere in this crate has to take it** — `spawn`, and equally
/// `output` and `status`, which spawn and wait in one call. See [`spawn_guard`].
static SPAWN_LOCK: Mutex<()> = Mutex::new(());

/// Claims [`SPAWN_LOCK`] for the caller's own process creation. Hold it across that and no longer.
///
/// Every process creation in this server goes through here, including ones that have nothing to do
/// with debug sessions: the flag is a property of the *process*, not of the spawn that set it, so a
/// child started for any reason during the window inherits whatever is marked.
///
/// "And no longer" is a rule about the **creation**, which `Command::output` and `Command::status`
/// fuse with the wait — so a caller using either holds this across the child's whole run, and that
/// is only acceptable for a child that exits in milliseconds (`service::icacls` is the one). For
/// anything longer, `spawn` under the guard and wait after it: every other process creation in
/// this server queues behind this lock.
pub(crate) fn spawn_guard() -> std::sync::MutexGuard<'static, ()> {
    SPAWN_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Marks a handle inheritable, so the child gets a copy of it.
fn inheritable(handle: &impl AsRawHandle) -> std::io::Result<()> {
    // SAFETY: the handle is borrowed from an owner that outlives the call, and this only changes
    // a flag on it.
    let ok = unsafe {
        SetHandleInformation(
            handle.as_raw_handle(),
            HANDLE_FLAG_INHERIT,
            HANDLE_FLAG_INHERIT,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Starts a worker process with a protocol channel of its own.
///
/// Marking, spawning and closing all happen under [`SPAWN_LOCK`], which is the whole of what
/// keeps this channel private: a handle is inheritable from the moment it is marked until it is
/// closed, and every process created in between gets a copy. The supervisor's copies of the
/// child's ends go at the end of that window for a second reason too — one left open on the
/// request side would mean the worker never sees the EOF that tells it the supervisor is gone,
/// and one left open on the message side would mean the supervisor never sees the EOF that tells
/// it the worker exited.
fn spawn_worker(
    exe: &Path,
    target: Option<&crate::target::Opening>,
) -> std::io::Result<(Child, Channel)> {
    let (their_requests, our_requests) = std::io::pipe()?;
    let (our_messages, their_messages) = std::io::pipe()?;

    let _one_spawn_at_a_time = spawn_guard();
    inheritable(&their_requests)?;
    inheritable(&their_messages)?;
    let mut command = Command::new(exe);
    // Configured KDNET connections stay in the supervisor. A worker is told the *one* connection
    // it is opening, down its private pipe, and has no use for the rest — while a `launch`ed
    // debuggee inherits this environment in turn, and a debuggee is exactly the untrusted program
    // that must not be handed every kernel key on the host.
    for name in kdconn::env_names() {
        command.env_remove(name);
    }
    // The listener's bearer token, for exactly the same reason and with a sharper edge. A worker
    // never authenticates anything, so it has no use for the token — but a `launch`ed debuggee
    // inheriting it could dial the listener on loopback, wait for the holder to go quiet, and take
    // over the very sessions being used to debug it. The credential does not cross this boundary.
    crate::client::strip_credentials(&mut command);
    // The target this worker is for, when its architecture can be read before an engine exists.
    // It travels on the command line rather than down the channel because the worker has to act
    // on it *before* the channel carries its first op: the engine must exist by `Ready`, and
    // which process it exists in is what this decides (`worker::TARGET_FLAG`). A dump path and a
    // pid are not secrets; the connection strings that are never come this way.
    if let Some(target) = target {
        command.arg(format!("{TARGET_FLAG}{}", target.flag_value()));
    }
    let child = command
        .arg(WORKER_FLAG)
        .arg(format!(
            "{REQUESTS_FLAG}{}",
            their_requests.as_raw_handle() as usize
        ))
        .arg(format!(
            "{MESSAGES_FLAG}{}",
            their_messages.as_raw_handle() as usize
        ))
        // Emphatically **not** inherited: this server's stdin is the MCP transport, and a worker
        // holding it could consume the client's requests. Nothing of ours is read from it either
        // — the protocol has its own channel — so there is nothing for it to be.
        .stdin(Stdio::null())
        // Piped and drained into the log (`log_stray_output`). This is where an extension DLL
        // that prints to the console lands, and it is now only a log: nothing of the protocol
        // comes this way.
        .stdout(Stdio::piped())
        // Worker logs join the server's own, which is where an MCP client looks for them.
        .stderr(Stdio::inherit())
        // Deliberately **not** `kill_on_drop`, and the absence is load-bearing. Dropping the
        // request channel — or the whole process exiting — closes the worker's end of it, and a
        // worker reads that EOF as "the supervisor is gone" and asks its engine to release the
        // target before it exits, bounded (`worker::run`). Terminating on drop pre-empts exactly
        // that: a worker this server never got round to releasing would die by `TerminateProcess`
        // with its target still attached, which for a live kernel means a machine left halted. So
        // EOF is the teardown, on every route out — clean shutdown, Ctrl+C, or a crash — and
        // [`Session::kill`] is the deliberate one, used only once a release has been asked for
        // and refused, or on a worker known to hold nothing.
        //
        // Which is why the worker also gets its own process group: see
        // [`CREATE_NEW_PROCESS_GROUP`]. EOF cannot be the teardown if a console Ctrl+C ends the
        // worker before its channel ever closes.
        //
        // And [`without_a_console_window`], which is nothing at all when this process has a
        // console to hand down — the two flags are independent, and the Ctrl+C guarantee rests on
        // the group rather than on a side effect of the other, which is documented as ignored for
        // a child that is not a console application.
        .creation_flags(CREATE_NEW_PROCESS_GROUP | without_a_console_window())
        .spawn()?;
    // Explicitly, and before the lock is released rather than at the end of the function: the
    // child has its copies, and these are the ones that would otherwise stay inheritable — and
    // hold both pipes open — for as long as this scope lasted.
    drop(their_requests);
    drop(their_messages);
    drop(_one_spawn_at_a_time);

    Ok((
        child,
        Channel {
            requests: our_requests,
            messages: our_messages,
        },
    ))
}

/// Reads one worker's messages off the channel, on a thread of its own.
///
/// A thread rather than a task because an anonymous pipe cannot be read asynchronously on Windows
/// — it is not an overlapped handle, so there is nothing to register with the runtime's poller.
/// Detached rather than joined, for the same reason `kill_on_drop` is not set: this thread is
/// parked in a read that ends when the worker exits, and the supervisor must never wait on that.
///
/// Parsing happens here so the task side only ever sees well-formed messages. A line that does
/// not parse is a bug in this program now, not a stray `printf` from an extension — those go to
/// the worker's stdout, which no longer carries protocol.
fn read_messages(
    id: String,
    pipe: PipeReader,
    unwinding: Arc<Mutex<Option<Instant>>>,
) -> std::io::Result<mpsc::UnboundedReceiver<WorkerMessage>> {
    let (tx, rx) = mpsc::unbounded_channel();
    std::thread::Builder::new()
        .name(format!("msgs-{id}"))
        .spawn(move || {
            for line in std::io::BufReader::new(pipe).lines() {
                let Ok(line) = line else { break };
                if line.trim().is_empty() {
                    continue;
                }
                match serde_json::from_str::<WorkerMessage>(&line) {
                    // Not protocol, and belonging to no request: one of that worker's own log
                    // records, mirrored so the supervisor holds every record either process made
                    // (`crate::logbridge`). Filed here rather than forwarded, because everything
                    // past this point is routed by request id and this has none — and because
                    // *here* is where the session id is known, which is the one thing the worker
                    // could not stamp it with.
                    Ok(WorkerMessage::Log {
                        at_ms,
                        level,
                        target,
                        message,
                        dropped,
                    }) => {
                        crate::logbridge::from_worker(&id, at_ms, level, &target, message, dropped);
                    }
                    Ok(message) => {
                        // Recorded here, before the message is handed on, because a teardown reads
                        // it against a deadline — see [`Session::unwinding`]. Everything this
                        // message is *reported* as still happens in `reader`.
                        // Turned into a deadline here, at the one moment the interval the worker
                        // named is current. A later zero retracts it — that is a worker saying its
                        // transaction is done and only the release is left.
                        //
                        // Kept **only if it is earlier**, which is what makes the order these
                        // arrive in stop mattering. A worker's promise never grows: the bound is
                        // fixed when the batch is claimed, and the one other thing it can say is
                        // the moment that batch ended. But the two are emitted from different
                        // threads — the promise by the worker's request reader, the retraction by
                        // its engine thread — so a teardown landing exactly as a batch exits can
                        // put them on the wire in either order. Taking the earlier means a stale
                        // promise cannot undo a retraction that beat it here.
                        if let WorkerMessage::RollingBack { within_ms, .. } = &message {
                            let named =
                                Instant::now() + Duration::from_millis(u64::from(*within_ms));
                            let mut slot = unwinding.lock().unwrap_or_else(|e| e.into_inner());
                            *slot = Some(slot.map_or(named, |had| had.min(named)));
                        }
                        // Nobody is left to route it to. Stopping here is what **closes the read
                        // end** — this thread owns it — and that is load-bearing rather than
                        // incidental: a worker's next write then fails immediately instead of
                        // blocking in `write_all` on a pipe nothing is emptying.
                        //
                        // The distinction decides whether a teardown can hang. Every message a
                        // worker sends goes through one lock (`worker::emit`), so a write that
                        // blocked here would hold that lock against the release its EOF is about
                        // to ask for — the one bounded by `ABRUPT_EXIT_RELEASE` — and for a live
                        // kernel that is a target left halted because the supervisor stopped
                        // listening. It cannot: an absent consumer is a *closed* pipe, not a full
                        // one. Pinned by `the_channel_fails_a_worker_fast_when_nobody_is_left`,
                        // because "the reader stops" and "the reader stalls" are one line apart
                        // here and only one of them is safe.
                        if tx.send(message).is_err() {
                            break;
                        }
                    }
                    // **Reported, not merely dropped, because on this channel it can only be a
                    // build mismatch.** The pipe is anonymous and inherited, and inside the worker
                    // nothing but `worker::emit` holds it (see [`crate::proto`]) — so unlike the
                    // shared stdout this channel replaced, an unreadable line here is not stray
                    // output that will be followed by good messages. It is a peer whose
                    // `WorkerMessage` is not this build's.
                    //
                    // That became reachable when a session could be served by a *second image*
                    // (`worker_images`): an `x86\\windbg-mcp.exe` left behind by a partial upgrade
                    // is old enough to disagree about the wire and new enough to keep running.
                    // Dropped, the handshake then waits out the whole of `WORKER_READY_TIMEOUT`
                    // before the caller gets its fallback; synthesised as a `Fatal`, the wait ends
                    // at the first unreadable line and the caller is told why.
                    //
                    // **Reported rather than closing the channel**, which would be the shorter
                    // fix: [`reader`]'s tail reads a closed channel as the worker's *death* and
                    // records the session as having lost its engine, which for a worker that is
                    // merely unintelligible is a claim about a process that is still running.
                    // Past the handshake `reader` ignores a `Fatal`, so this costs a log line and
                    // changes nothing else.
                    Err(e) => {
                        let why = format!(
                            "cannot read this engine worker's messages ({e}) — it is almost \
                             certainly a different build of this server from the one that started \
                             it: {}",
                            clipped(&line)
                        );
                        tracing::error!("session {id}: {why}");
                        if tx.send(WorkerMessage::Fatal { message: why }).is_err() {
                            break;
                        }
                    }
                }
            }
        })?;
    Ok(rx)
}

/// How much of a line from a worker to put in the log before clipping it. Generous enough for a
/// real diagnostic, small enough that a runaway extension cannot bury the log in one line.
const LOGGED_LINE_LIMIT: usize = 2048;

/// One line as it should appear in the log: clipped, and honest about what was clipped.
fn clipped(line: &str) -> String {
    let mut out: String = line.chars().take(LOGGED_LINE_LIMIT).collect();
    if out.len() < line.len() {
        out.push_str(&format!("… ({} bytes in all)", line.len()));
    }
    out
}

/// Drains a worker's stdout into the log.
///
/// Nothing of ours writes there — the protocol has its own channel — so anything that arrives was
/// printed by something else inside that process: an extension DLL writing to the console is the
/// case that motivated all of this. Logged rather than discarded because it is the only place
/// that output can now be seen, and drained rather than left because an unread pipe fills at a
/// few dozen KiB and the *next* write blocks the engine thread inside DbgEng.
async fn log_stray_output(id: String, stdout: ChildStdout) {
    let mut stdout = BufReader::new(stdout);
    let mut line = Vec::new();
    while let Some(dropped) = next_capped_line(&mut stdout, &mut line).await {
        // A lossy decode, not `lines()`. Whatever prints here is not ours and owes us no encoding
        // — an extension writing in the console's code page is not UTF-8 — and a decode error
        // must not be able to end this loop. Stopping the drain is the one outcome that matters:
        // the pipe would fill, and the next write would block the engine thread inside DbgEng,
        // which is a session lost to output nobody even wanted.
        let text = String::from_utf8_lossy(&line);
        let text = text.trim_end_matches(['\r', '\n']);
        if text.trim().is_empty() && dropped == 0 {
            continue;
        }
        let dropped = if dropped > 0 {
            format!(" [+{dropped} further bytes on this line, discarded]")
        } else {
            String::new()
        };
        tracing::info!(
            "session {id}: its engine worker wrote to stdout: {}{dropped}",
            clipped(text)
        );
    }
}

/// Reads the next line into `line`, keeping at most [`LOGGED_LINE_LIMIT`] bytes of it and
/// reporting how many were thrown away. `None` at EOF or on a broken pipe.
///
/// The cap is the point, and it is not about the log. Draining a worker's stdout moves the cost of
/// runaway output off the worker — where a full pipe blocked the engine thread — and onto the
/// supervisor, which is only an improvement if what arrives is bounded: reading to a newline that
/// never comes would let one session's noisy extension grow this buffer until the whole server
/// runs out of memory, and take every other session with it. [`clipped`] bounds what is *logged*,
/// which is a different thing and too late.
async fn next_capped_line<R: tokio::io::AsyncBufRead + Unpin>(
    stdout: &mut R,
    line: &mut Vec<u8>,
) -> Option<usize> {
    line.clear();
    let mut dropped = 0usize;
    loop {
        // `fill_buf`/`consume` rather than `read_until`, because this has to decide what to keep
        // *before* it is buffered.
        let (consumed, complete) = {
            let chunk = stdout.fill_buf().await.ok()?;
            if chunk.is_empty() {
                // EOF. A last line with no terminator is still a line worth logging.
                return (!line.is_empty() || dropped > 0).then_some(dropped);
            }
            let (upto, complete) = match chunk.iter().position(|&b| b == b'\n') {
                Some(at) => (at + 1, true),
                None => (chunk.len(), false),
            };
            let room = LOGGED_LINE_LIMIT.saturating_sub(line.len());
            let kept = upto.min(room);
            line.extend_from_slice(&chunk[..kept]);
            dropped += upto - kept;
            (upto, complete)
        };
        stdout.consume(consumed);
        if complete {
            return Some(dropped);
        }
    }
}

/// Feeds one session's queue to its worker, one job at a time.
///
/// This is the session's single serialization point, and the only place a [`Gate`] runs. Jobs are
/// written as they arrive rather than one-per-reply on purpose: a job whose caller has given up
/// is still running in the worker, and blocking the queue behind it would stop `end_session` from
/// ever reaching the worker at all.
///
/// Runs on a thread rather than as a task, because the request channel is an anonymous pipe and
/// those cannot be written asynchronously on Windows. A blocking write on a runtime thread is the
/// one thing that could not be allowed here: the whole design is about a stuck session costing a
/// process, not the server.
fn pump(
    session: Weak<Session>,
    mut rx: mpsc::UnboundedReceiver<Job>,
    mut requests: PipeWriter,
    waiters: Waiters,
    call_timeout: Duration,
) {
    // No runtime on this thread, so this really blocks — which is what lets the write below do
    // the same without stalling anything else.
    while let Some(job) = rx.blocking_recv() {
        let Some(session) = session.upgrade() else {
            return;
        };
        let answer = |result: Result<Output, EngineError>| {
            let waiter = waiters
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&job.id);
            if let Some(waiter) = waiter {
                let _ = waiter.done.send(result);
            }
        };

        // The gate, at the front of the queue. See `Gate`.
        let state = session.state();
        if !job.gate.admits(&state) {
            answer(Err(EngineError::Stale(stale_handle(&session.id, &state))));
            continue;
        }
        if let Some(why) = &job.gate.retires {
            session.set_state(SessionState::Retired(why.clone()));
        }
        if let Some(why) = &job.gate.closes {
            session.set_state(SessionState::Closed(why.clone()));
        }

        let mut op = job.op;
        // For the ops whose own deadline is derived from the caller's: what is written here is how
        // much patience the caller had left when this job reached the front of the queue, and the
        // worker sizes its watchdog (or its walk, or its batch budget) from it. See
        // `EngineOp::BoundedCommand` for why the derivation itself belongs to the worker.
        if let Some(patience_ms) = op.patience_slot() {
            *patience_ms = remaining_patience_ms(call_timeout, job.submitted);
        }
        let request = WorkerRequest {
            id: job.id,
            op,
            startup_symbol_path: job.startup_symbol_path,
        };
        let Ok(mut line) = serde_json::to_string(&request) else {
            answer(Err(EngineError::Debugger(
                "could not encode this operation for the engine worker".to_string(),
            )));
            continue;
        };
        line.push('\n');
        if requests
            .write_all(line.as_bytes())
            .and_then(|()| requests.flush())
            .is_err()
        {
            // The worker is gone. The reader task sees the same thing and settles the session;
            // this job is simply the first to notice.
            answer(Err(EngineError::Lost(worker_gone(&session.id))));
            return;
        }
    }
}

/// Passes a milestone on to the caller waiting for `id`, if that caller asked to be told.
///
/// Looked up rather than removed: the call is still running, and this is a thing it is doing on the
/// way to its answer. Silent when there is no waiter (the caller's budget expired and the job is
/// still out there) or no reporter (the common case — see [`Waiting::progress`]).
fn tell(waiters: &Waiters, id: u64, step: crate::progress::Step) {
    let reporter = waiters
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&id)
        .and_then(|waiting| waiting.progress.clone());
    if let Some(reporter) = reporter {
        reporter.step(step);
    }
}

/// Reports a rollback milestone to the caller waiting for `id`, and refuses to walk one backwards.
///
/// Its own function rather than a [`tell`] call because it is the one milestone with *state*: the
/// worker sends `RollingBack` twice for a single transaction, and the second reading is terminal.
/// Both the flag and the reporter are read under one lock so the decision cannot straddle another
/// message; the send happens outside it, as everywhere else here.
///
/// See [`Waiting::unwound`] for why arrival order cannot be trusted.
fn tell_rollback(waiters: &Waiters, id: u64, within: Duration) {
    let telling = {
        let mut waiters = waiters.lock().unwrap_or_else(|e| e.into_inner());
        let Some(waiting) = waiters.get_mut(&id) else {
            return;
        };
        if within.is_zero() {
            // Terminal for this job: nothing arriving later can put the transaction back in
            // flight, because there is no longer one to be in flight.
            waiting.unwound = true;
        } else if waiting.unwound {
            return;
        }
        let step = if within.is_zero() {
            crate::progress::Step::Unwound
        } else {
            crate::progress::Step::Unwinding { within }
        };
        waiting.progress.clone().map(|reporter| (reporter, step))
    };
    if let Some((reporter, step)) = telling {
        reporter.step(step);
    }
}

/// Consumes one worker's messages: milestones move the session's state, results answer callers.
///
/// Fed by [`read_messages`]'s thread, so this side stays on the runtime — settling a session
/// touches the registry and the worker's process handle, which is where both belong.
async fn reader(
    session: Weak<Session>,
    mut messages: mpsc::UnboundedReceiver<WorkerMessage>,
    waiters: Waiters,
    sessions: Sessions,
) {
    while let Some(message) = messages.recv().await {
        let Some(session) = session.upgrade() else {
            return;
        };
        match message {
            // Each milestone records the opener's phase *and* moves the state. The phase is what
            // survives a retirement landing in between, and it is what the recovery advice reads.
            //
            // Both state moves are conditional transitions, so both go through `update_state`:
            // a check-then-set would let that retirement be overwritten.
            // Matched on the reserved opener id, so the contract that only an opener reports
            // milestones is enforced here rather than assumed to hold for ever.
            WorkerMessage::Committed { id } if id == OPENER_JOB => {
                session.reach(OpenPhase::Committed);
                session.update_state(|state| {
                    matches!(state, SessionState::Opening).then_some(SessionState::Attaching)
                });
                tell(&waiters, id, crate::progress::Step::Committed);
            }
            WorkerMessage::Opened { id } if id == OPENER_JOB => {
                session.reach(OpenPhase::Opened);
                promote_opened(&session);
                tell(&waiters, id, crate::progress::Step::Opened);
            }
            // Already recorded by the thread that read it — see [`Session::unwinding`] — so this
            // arm only reports it. Nothing here is on the teardown's critical path, which is the
            // whole reason the store is not here.
            WorkerMessage::RollingBack { id, within_ms } => {
                let within = Duration::from_millis(u64::from(within_ms));
                // **Zero is a retraction, not a shorter promise.** The worker sends this message
                // twice for one transaction: once when a teardown finds a batch to stop, naming
                // how long that leaves, and once from the batch's own guard naming zero to say the
                // transaction is over (`worker::RETRACTED`). Reading the second as another unwind
                // reports a transaction still in flight at the moment it stopped being one — and
                // says "up to 0.0s" doing it.
                if within.is_zero() {
                    tracing::info!(
                        "session {}: job {id}'s transaction is unwound; only the release is left",
                        session.id
                    );
                } else {
                    // The one milestone whose *number* the caller can act on: a teardown that
                    // looks stuck is a teardown waiting out a rollback, and this says how long.
                    tracing::info!(
                        "session {}: job {id} found a transaction in flight and told it to roll \
                         back; it needs up to {within:?}",
                        session.id
                    );
                }
                // Logged either way and *reported* conditionally, which is the right split: the log
                // is a faithful record of what arrived on the wire, and progress is a narration of
                // the call for a client — and a narration may not contradict itself.
                tell_rollback(&waiters, id, within);
            }
            // The target an `EngineOp::Resume` was given is moving. Reported to the call that
            // started it — which is waiting on exactly this and not on the result, since the
            // result is the stop and may be an hour away.
            WorkerMessage::Resumed { id } => {
                let told = waiters
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .get_mut(&id)
                    .and_then(|waiting| waiting.resumed.take());
                // **Everything this milestone says, before anything that wakes a reader of it.**
                // `start_execution` waits on the *slot* and reads the milestone's channel at the
                // top of its loop, so a bump published first can wake it on another runtime
                // thread while the channel is still empty — it would then find nothing, see the
                // run still going, consume the only notification and wait again, sleeping until
                // the run *ended*. That is the exact bug this branch shipped once already,
                // arriving the second time through a two-line ordering instead of a missing wake.
                // So: the phase on the slot, then the channel, then the wake.
                session.execution_moving(id);
                match told {
                    Some(tx) => {
                        let _ = tx.send(());
                    }
                    // The caller gave up before the target got going, or this is a second
                    // milestone for one job. Neither is worth failing anything over: the run is
                    // recorded on the session either way, and `session_status` reports it.
                    None => tracing::debug!(
                        "session {}: job {id} reported its target running with nobody waiting on \
                         the milestone",
                        session.id
                    ),
                }
                // Whether or not anyone was holding the channel: the wake is what
                // `Sessions::start_execution` is waiting on, and it waits on the *slot* rather
                // than on the milestone's channel — one wait, so the run failing and the run
                // starting arrive by the same road. Bumping only inside the arm above would leave
                // `continue_async` asleep until the run *ended*, which is the one thing the tool
                // exists not to do.
                session.execution_moved();
            }
            WorkerMessage::Committed { id } | WorkerMessage::Opened { id } => {
                tracing::warn!(
                    "session {}: job {id} reported an opener milestone",
                    session.id
                );
            }
            WorkerMessage::Done { id, result } => {
                let waiter = waiters
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&id);
                // Taken out of the map, so nothing can report a milestone for this job again: the
                // only reporter reachable by its id went with it. A call that has an answer is
                // done saying what it is doing.
                let Some(Waiting { done: waiter, .. }) = waiter else {
                    continue;
                };
                // A failed send means the receiver is gone: the caller's timeout fired and
                // nobody is left to act on this result. For an ordinary call that is fine —
                // removing the entry above is what mattered, and it is how the session stops
                // counting as busy. For the *opener* it is not: `open` settles the session's
                // state from its result, so with no one to run that, the session would sit in
                // `Opening` or `Attaching` for the life of the process — `session_status` would
                // keep reporting an open that finished long ago, and `busy()` would keep the
                // worker from ever being reclaimed.
                if let Err(unreceived) = waiter.send(result.map_err(engine_error))
                    && id == OPENER_JOB
                    && settle_open(&session, &unreceived)
                {
                    // It settled *live*, so it owes the slot it took — the same reconciliation
                    // `open` runs, which nobody is left here to run for it.
                    sessions.reconcile_capacity(&session);
                }
            }
            // `Ready` and `Fatal` belong to the spawn handshake, which has already happened.
            // `Log` never gets this far: it is filed by the reader thread that parsed it, which
            // is also where the session id it is tagged with lives.
            WorkerMessage::Ready { .. }
            | WorkerMessage::Fatal { .. }
            | WorkerMessage::Log { .. } => {}
        }
    }
    // The channel closed: the worker exited, for whatever reason. Nothing else can close it —
    // the worker's end of it is held by nobody but that process, and the reader thread runs until
    // it reads EOF — so this is the worker's death, not a message that failed to parse.
    let Some(session) = session.upgrade() else {
        return;
    };
    // Whether this death is *news*. A session already settled is one somebody ended — `release`
    // terminates the worker on purpose, so its pipe reaching EOF here is the last step of an
    // orderly teardown, not a loss. Recording it either way would put a red "lost its engine"
    // line after every successful `end_session`, describing a failure that did not happen.
    let unexpected = session.state().is_live();
    if unexpected {
        session.set_state(SessionState::Closed(
            "the engine worker process exited".to_string(),
        ));
        // Beside the state transition rather than instead of it: the transition says the session
        // is closed, and this says the calls it owed replies to are being answered with a failure
        // nobody asked for. A reader looking at a result that never arrived needs the second one.
        session.rec.write(crate::record::Event::WorkerLost {
            session: session.id.clone(),
            detail: crate::record::Capped::of(&worker_gone(&session.id), session.rec.field_limit()),
        });
    }
    session.fail_outstanding(&worker_gone(&session.id));
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- the worker's protocol channel --------------------------------------------

    /// The property the private channel exists for: a worker's stdout is not the protocol.
    ///
    /// `cmd.exe` is the stand-in, and a good one. Handed a worker's command line it makes nothing
    /// of it, prints its banner and a promptless line to stdout, reads EOF on the null stdin and
    /// exits — a process that writes to its standard handles, leaves the last line unterminated,
    /// and never says a word on the channel. That is the exact shape of the hazard: it used to be
    /// an extension's `printf` swallowing the reply written after it.
    ///
    /// What the supervisor has to conclude is "this worker said nothing, then exited", because
    /// that is what settles the session and fails its callers out ([`reader`]'s tail). Reading
    /// the banner as a message would be the old corruption; never reaching EOF would be the
    /// supervisor holding a copy of the child's end open, and either one leaves a session waiting
    /// for a reply that is not coming.
    #[tokio::test]
    async fn a_workers_stdout_is_not_its_protocol_channel() {
        use tokio::io::AsyncReadExt;

        let (mut child, channel) =
            spawn_worker(Path::new("cmd.exe"), None).expect("spawn a stand-in worker");
        let mut stdout = child.stdout.take().expect("a worker's stdout is piped");
        // **Bytes, not a `String`.** `cmd.exe` writes its banner in the code page of whatever
        // console it ended up attached to, which is the *host's* business and not this test's: on
        // a system whose OEM code page is GBK the banner is not UTF-8, and reading it as one fails
        // the test for a property it does not hold an opinion about. What is under test is whether
        // those bytes reached the protocol channel.
        let mut printed = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), stdout.read_to_end(&mut printed))
            .await
            .expect("the stand-in's stdout closed within 10s")
            .expect("read the stand-in's stdout");
        assert!(
            printed.iter().any(|b| !b.is_ascii_whitespace()),
            "the stand-in printed nothing to stdout, so this test would pass whatever the \
             channel did with it"
        );

        let mut messages = read_messages(
            "sess-stand-in".to_string(),
            channel.messages,
            Arc::new(Mutex::new(None)),
        )
        .expect("read messages");
        let heard = tokio::time::timeout(Duration::from_secs(10), messages.recv()).await;
        assert!(
            matches!(heard, Ok(None)),
            "expected silence and then EOF on the channel, got {heard:?} — either stdout reached \
             the protocol, or the channel never reported the worker's exit, which is what a \
             supervisor's own copy of the child's end left open looks like"
        );
        let _ = child.wait().await;
    }

    /// The processes attached to this process's console, or nothing when it has none.
    fn console_process_list() -> Vec<u32> {
        let mut buf = vec![0u32; 64];
        loop {
            // SAFETY: a valid, writable buffer, described to the call at its true length.
            let n = unsafe { GetConsoleProcessList(buf.as_mut_ptr(), buf.len() as u32) } as usize;
            if n == 0 {
                return Vec::new(); // No console: `ERROR_INVALID_HANDLE`.
            }
            if n <= buf.len() {
                buf.truncate(n);
                return buf;
            }
            // Too small — the call stored nothing and answered how many there are.
            buf = vec![0u32; n];
        }
    }

    /// A child spawned the way a worker is opens **no console window of its own**, and the half of
    /// that with teeth is the console branch.
    ///
    /// Passing `CREATE_NO_WINDOW` unconditionally also leaves no window anywhere, so a test that
    /// only looked for a window would wave through the simplification this conditional exists to
    /// refuse — and that simplification silently sends a worker's stderr to a console nobody is
    /// looking at ([`CREATE_NO_WINDOW`]). So where this process has a console, the assertion is
    /// that the child **joined it**, which is what keeps its log lines in the terminal.
    ///
    /// Spawned here rather than through [`spawn_worker`] for one reason only: a stand-in handed a
    /// worker's command line exits in milliseconds, and this has to read a list the child is still
    /// in. The shipped call site is asserted end to end by `mcp_smoke`, against a real session's
    /// engine pid.
    #[tokio::test]
    async fn a_worker_shares_this_processs_console_or_gets_a_windowless_one() {
        let flags = without_a_console_window();
        if console_process_list().is_empty() {
            assert_eq!(
                flags, CREATE_NO_WINDOW,
                "with no console to inherit, a worker would be given a brand-new visible one"
            );
            eprintln!(
                "SKIPPED: this process has no console, so there is no sharing to observe — the \
                 flag is asserted instead"
            );
            return;
        }

        assert_eq!(
            flags, 0,
            "a console this process can hand down is one the worker must inherit, so that its              stderr keeps reaching the terminal"
        );

        let mut child = {
            let _one_spawn_at_a_time = spawn_guard();
            Command::new("cmd")
                .args(["/c", "ping", "-n", "30", "127.0.0.1"])
                .stdout(Stdio::null())
                .kill_on_drop(true)
                .creation_flags(CREATE_NEW_PROCESS_GROUP | flags)
                .spawn()
                .expect("spawn a stand-in child")
        };
        let pid = child.id().expect("a freshly spawned child has a pid");

        // Polled: a child joins its console during its own startup, not when `CreateProcess`
        // returns, so the list can legitimately not name it yet.
        let deadline = Instant::now() + Duration::from_secs(10);
        let joined = loop {
            if console_process_list().contains(&pid) {
                break true;
            }
            if Instant::now() >= deadline {
                break false;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        let _ = child.kill().await;
        assert!(
            joined,
            "pid {pid} never appeared in this process's console ({:?}), so it opened a console of \
             its own — which off a console-bearing parent is a visible window, and takes the \
             worker's stderr with it",
            console_process_list()
        );
    }

    /// The rule [`SPAWN_LOCK`] rests on, checked against the source rather than asserted in a doc
    /// comment: **no process is created in this crate without [`spawn_guard`] held**.
    ///
    /// It is checked this way because the rule is the kind that decays silently and expensively.
    /// A handle is inheritable process-wide from the moment it is marked, so a spawn added
    /// anywhere — a new tool that shells out, another recorder — can hand a worker's channel end
    /// to a process that outlives it, and the pipe then never reports EOF: the session never
    /// settles, its callers never hear back, and nothing about the new code looks wrong. The
    /// first cut of this very change missed two existing spawn sites (`ttd::record`, the
    /// stand-ins below), which is the evidence that a comment is not enough.
    ///
    /// `.spawn()` with empty parentheses is a reliable marker for a *process* spawn here: a
    /// thread spawn always takes a closure, and `tokio::spawn` a future. The count is asserted
    /// too, so a refactor that stops matching fails loudly instead of quietly checking nothing.
    ///
    /// **`.spawn()` alone is not the whole of process creation, and the gap was live**: `Command`
    /// also has `output()` and `status()`, which spawn and wait in one call, and `service::icacls`
    /// used the first of those — so this test read "no unguarded spawns" over a source file that
    /// creates a process the marker could not see. Its own name was half of why that stayed
    /// invisible, and is why this is `every_process_created…` rather than `every_process_spawn…`:
    /// what the rule is about is a *process being created*, and `spawn` is only the spelling that
    /// says so.
    ///
    /// The two fused calls are matched **only in a function that also constructs a `Command`**,
    /// which `.spawn()` needs and they do. `.status()` is the reason: `response.status()` is an
    /// HTTP status in `listen::gate`, twice, and an unanchored marker would demand the spawn lock
    /// there. What the anchor costs is a fused call on a `Command` some *other* function built —
    /// nothing does that here, and a marker that is wrong about `listen.rs` on every run is worse
    /// than one that could miss a shape this crate has never had. `.spawn()` stays unanchored,
    /// since it is specific enough on its own and anchoring it would open exactly that hole in the
    /// half that is load-bearing today.
    ///
    /// Each half is counted separately and each is asserted, because a marker that matches nothing
    /// passes: the fused half rests on `icacls` being the one site, and if that call moves to
    /// `spawn` the assertion says so rather than quietly checking nothing.
    ///
    /// A raw `CreateProcessW` through `windows-sys` would be outside all of this. Nothing in this
    /// crate creates a process that way, and the rule for one that did is the same rule.
    #[test]
    fn every_process_created_in_this_crate_takes_the_spawn_lock() {
        // Assembled at run time rather than written as literals, because this function is *in* the
        // source it reads. Written out, the two lines below would each match themselves: the
        // matcher would count as a spawn site, and — the guard's name being on the line above it —
        // as a *guarded* one. The floor asserted at the end would then be satisfied by the checker
        // itself, which is the one line that cannot stop matching, and a real spawn site could drop
        // out of the marker with nothing to notice. Splitting them keeps the checker invisible to
        // itself, which is what leaves the floor counting only real spawns.
        let a_spawn = [".spawn", "()"].concat();
        let the_guard = ["spawn_", "guard()"].concat();
        // Split for the same reason, and one more: written out, `Command::new(` would make this
        // function count as one that builds a command, and the two fused markers below are matched
        // only inside such a function.
        let a_command = ["Command", "::new("].concat();
        let fused = [[".output", "()"].concat(), [".status", "()"].concat()];

        let mut spawns = 0;
        let mut fused_sites = 0;
        let mut unguarded = Vec::new();
        for file in rust_sources(&PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/src"))) {
            let text = std::fs::read_to_string(&file).expect("read a source file");
            // Reset at each function, so "guarded" means guarded *here* rather than anywhere
            // earlier in the file. Comments are skipped: prose about a `fn` is not one.
            let mut guarded = false;
            let mut builds_a_command = false;
            for (n, line) in text.lines().enumerate() {
                let code = line.trim_start();
                if code.starts_with("//") {
                    continue;
                }
                if code.starts_with("fn ") || code.contains(" fn ") {
                    guarded = false;
                    builds_a_command = false;
                }
                if code.contains(&the_guard) {
                    guarded = true;
                }
                if code.contains(&a_command) {
                    builds_a_command = true;
                }
                let spawns_here = code.contains(&a_spawn);
                let fused_here = builds_a_command && fused.iter().any(|f| code.contains(f));
                spawns += usize::from(spawns_here);
                fused_sites += usize::from(fused_here);
                if (spawns_here || fused_here) && !guarded {
                    unguarded.push(format!("{}:{}", file.display(), n + 1));
                }
            }
        }
        assert!(
            unguarded.is_empty(),
            // `engine::spawn_guard` without its parentheses, for the reason above: written in
            // full it would be one more line the checker sees as a guard.
            "these create a process without holding `engine::spawn_guard` in the same function, \
             so a child started there can inherit a worker's protocol channel and keep it from \
             ever reporting EOF: {unguarded:?}"
        );
        assert!(
            spawns >= 3,
            "expected to find the known process spawns (the worker, the TTD recorder, the test \
             stand-in) and found {spawns} — the marker no longer matches, so this test is checking \
             nothing"
        );
        assert!(
            fused_sites >= 1,
            "expected to find the spawn-and-wait in `service::icacls` and found none, so the half \
             of this marker that covers `output`/`status` is checking nothing — if that call is \
             now a `spawn`, this floor is what needs re-deriving"
        );
    }

    /// Every "`FOLLOWUPS.md` item N" citation in this repository names an item that exists, and
    /// `DONE.md`'s index covers every entry in it.
    ///
    /// **A citation is deliberately not retargeted when an item closes**, which is what this test
    /// exists to make safe. The string is spread over some twenty files — doc comments in eleven
    /// modules and in `tests/`, `CHANGELOG.md`, `DECISIONS.md`, every `docs/*.md`, `build.rs`,
    /// `ci.yml` and the eval tooling — so making the *file* half of a citation follow the entry
    /// would turn closing an item into a sweep of source comments, with nothing to catch the ones
    /// missed. "Item N" is the stable name; which of the two files holds it is what
    /// `FOLLOWUPS.md`'s header answers, above every entry, for whoever followed a citation there.
    /// So the invariant is not that a citation points at the right file — it is that the number it
    /// names still exists, in one of the two, and can be reached from the landing page.
    ///
    /// Lines are joined before scanning because a citation wraps: in a doc comment the file name
    /// sits on one line and `item 43` on the next. A range is expanded inclusively rather than
    /// read as two endpoints — `DECISIONS.md` cites `items 7–9`, and item 9 is named nowhere else,
    /// so the interior of a range is the half that can go missing unnoticed.
    ///
    /// The slug the index is checked against is GitHub's, for the ASCII headings this file has:
    /// lower-case, drop all but letters, digits, spaces, `-` and `_`, then spaces to hyphens.
    #[test]
    fn every_followups_citation_names_an_item_that_exists() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let open = items_in(&root.join("FOLLOWUPS.md"));
        let closed = items_in(&root.join("DONE.md"));
        assert!(
            !open.is_empty() && !closed.is_empty(),
            "neither file parsed as items"
        );

        let both: Vec<_> = open.intersection(&closed).collect();
        assert!(
            both.is_empty(),
            "these item numbers are in both FOLLOWUPS.md and DONE.md, so a citation resolves to \
             two different entries: {both:?}"
        );

        let mut dangling = Vec::new();
        let mut seen = 0;
        for file in repo_text(&root) {
            let Ok(text) = std::fs::read_to_string(&file) else {
                continue;
            };
            // A substring scan before any allocation: 71 of the hundred files this walks never
            // name the file at all, and normalising one to look is the expensive half.
            if !text.contains(CITED) {
                continue;
            }
            for n in cited_items(&text) {
                seen += 1;
                if !open.contains(&n) && !closed.contains(&n) {
                    dangling.push(format!("{}: item {n}", file.display()));
                }
            }
        }
        assert!(
            dangling.is_empty(),
            "these cite a follow-up that is in neither FOLLOWUPS.md nor DONE.md — an entry was \
             deleted or renumbered, and the citation cannot be followed: {dangling:?}"
        );
        assert!(
            seen >= 60,
            "found only {seen} citations, where this repository has of the order of a hundred — \
             the scanner no longer matches, so this test is checking nothing"
        );

        // The landing page: a reader who followed a citation to FOLLOWUPS.md is sent here, so the
        // index has to name everything the file holds, at an anchor that resolves.
        let done = std::fs::read_to_string(root.join("DONE.md")).expect("read DONE.md");
        let mut entries = std::collections::BTreeMap::new();
        let mut indexed = std::collections::BTreeMap::new();
        // A number listed twice is refused rather than overwritten, for the same reason as a
        // heading filed twice: the map would keep one of them and every check below would agree
        // with itself about an index that names an entry twice.
        let mut twice = Vec::new();
        for line in done.lines() {
            if let Some(title) = line.strip_prefix("## ")
                && let Some(n) = leading_item_number(title)
            {
                entries.insert(n, anchor_of(title));
            }
            if let Some(rest) = line.strip_prefix("- [Item ")
                && let Some((number, rest)) = rest.split_once("](#")
                && let Some((anchor, _)) = rest.split_once(')')
                && let Ok(n) = number.parse::<u32>()
                && indexed.insert(n, anchor.to_string()).is_some()
            {
                twice.push(n);
            }
        }
        assert!(
            twice.is_empty(),
            "DONE.md's index lists these item numbers more than once: {twice:?}"
        );
        assert_eq!(
            entries.keys().collect::<Vec<_>>(),
            indexed.keys().collect::<Vec<_>>(),
            "DONE.md's index and its entries disagree — an entry moved in without an index line, \
             or the other way round"
        );
        let broken: Vec<_> = indexed
            .iter()
            .filter(|(n, anchor)| entries.get(n) != Some(*anchor))
            .map(|(n, anchor)| format!("item {n} -> #{anchor}"))
            .collect();
        assert!(
            broken.is_empty(),
            "these index links do not match the heading they name, so they resolve to nothing: \
             {broken:?}"
        );
    }

    /// The item numbers a follow-up file holds, read off its `## N.` headings.
    ///
    /// A number filed twice in one file is refused here rather than folded into the set, because
    /// every check downstream is an identity check: two `## 47.` headings collapse to one entry
    /// that the overlap and citation tests both pass, while "item 47" has quietly stopped naming
    /// one thing. A bad merge is how that arrives.
    fn items_in(path: &PathBuf) -> std::collections::BTreeSet<u32> {
        let text = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let mut found = std::collections::BTreeSet::new();
        let mut twice = Vec::new();
        for n in text
            .lines()
            .filter_map(|line| line.strip_prefix("## ").and_then(leading_item_number))
        {
            if !found.insert(n) {
                twice.push(n);
            }
        }
        assert!(
            twice.is_empty(),
            "{} files these item numbers more than once, so a citation of one names two entries: \
             {twice:?}",
            path.display()
        );
        found
    }

    /// `12` from `12. [windbg-mcp] …`, and nothing from a heading that does not open with one.
    fn leading_item_number(title: &str) -> Option<u32> {
        let (number, _) = title.split_once('.')?;
        number.parse().ok()
    }

    /// The name a citation is written with, and therefore what is searched for.
    const CITED: &str = "FOLLOWUPS";

    /// Item numbers cited beside `FOLLOWUPS.md` in one file's text.
    fn cited_items(text: &str) -> Vec<u32> {
        let mut flat = String::new();
        for line in text.lines() {
            let mut line = line.trim_start();
            for sigil in ["///", "//!", "//", "#", "*", "-"] {
                if let Some(rest) = line.strip_prefix(sigil) {
                    line = rest.trim_start();
                    break;
                }
            }
            flat.push_str(line);
            flat.push(' ');
        }

        let mut found = Vec::new();
        // Matched as it is spelled, not case-folded: the citation names a file, and the only
        // lower-case spellings in this repository are identifiers (this test's own name among
        // them). It also keeps the offsets honest — a case-folded copy can differ in byte length
        // from the string being indexed, which is a panic waiting for the first heading with an
        // uppercase non-ASCII letter in it.
        for (at, _) in flat.match_indices(CITED) {
            // A window rather than the rest of the line: far enough to clear a markdown link back
            // to the file, short enough that the next sentence's "item" is not this citation's.
            let window: String = flat[at..]
                .chars()
                .take(60)
                .collect::<String>()
                .to_lowercase();
            // Every "item" in the window, not the first: `FOLLOWUPS item 10 records what moved
            // for items 7–9` is one sentence citing four entries, and `DECISIONS.md` writes
            // exactly that.
            for (from, _) in window.match_indices("item") {
                found.extend(numbers_from(&window[from + "item".len()..]));
            }
        }
        found
    }

    /// The numbers opening a citation's tail: `s 13–14,` is 13 and 14, `s 7–9` is 7, 8 and 9,
    /// ` 24's` is 24, and ` N` (the literal, in prose about the form) is none.
    ///
    /// Two things it refuses, both of which stand in a real sentence a few words from a citation.
    /// A digit run followed by a comma and another digit is a **thousands group** — `8,654 B`, in
    /// the eval write-ups — and reading it as two item numbers invents one that cannot exist. And
    /// an ASCII hyphen is not a separator, so a date (`2026-08-26`) after a number ends the run
    /// rather than continuing it; the ranges written here are en-dashes.
    fn numbers_from(tail: &str) -> Vec<u32> {
        /// The widest range ever written in these files is seven (`items 20–26`). Beyond that it
        /// is a misparse, and expanding one would bury a real failure under hundreds of numbers.
        const SPAN: u32 = 20;

        let mut found = Vec::new();
        // `item` or `items`, and then the numbers.
        let mut rest = tail.strip_prefix('s').unwrap_or(tail);
        loop {
            rest = rest.trim_start();
            rest = rest.strip_prefix(',').unwrap_or(rest).trim_start();
            rest = rest.strip_prefix("and ").unwrap_or(rest).trim_start();

            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            let Ok(n) = digits.parse::<u32>() else {
                return found;
            };
            rest = &rest[digits.len()..];
            if rest.starts_with(',') && rest[1..].starts_with(|c: char| c.is_ascii_digit()) {
                return found;
            }
            found.push(n);

            // A range is inclusive, and its interior is the half a citation can lose: `items
            // 16–18` cites 17, and nothing else in the file mentions it.
            if let Some(after) = rest.strip_prefix('\u{2013}') {
                let end: String = after.chars().take_while(char::is_ascii_digit).collect();
                let Ok(last) = end.parse::<u32>() else {
                    return found;
                };
                if last <= n || last - n > SPAN {
                    return found;
                }
                found.extend(n + 1..=last);
                rest = &after[end.len()..];
            }
        }
    }

    /// GitHub's heading slug, for ASCII headings.
    fn anchor_of(title: &str) -> String {
        title
            .chars()
            .flat_map(char::to_lowercase)
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '-' | '_'))
            .map(|c| if c == ' ' { '-' } else { c })
            .collect()
    }

    /// Every text file in the repository a citation could be written in — so one added to a new
    /// module, a new document or a new script is checked rather than silently skipped.
    fn repo_text(dir: &PathBuf) -> Vec<PathBuf> {
        const READ: [&str; 8] = ["md", "rs", "py", "json", "toml", "yml", "yaml", "ps1"];
        let mut found = Vec::new();
        let Ok(entries) = std::fs::read_dir(dir) else {
            return found;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if path.is_dir() {
                // `target` is enormous and holds copies of this crate's own source; a dotted
                // directory is tooling, except the workflows, which cite items too.
                if name == "target"
                    || name == "node_modules"
                    || (name.starts_with('.') && name != ".github")
                {
                    continue;
                }
                found.extend(repo_text(&path));
            } else if path
                .extension()
                .is_some_and(|e| READ.iter().any(|r| e == *r))
            {
                found.push(path);
            }
        }
        found
    }

    /// Every `.rs` file under a directory, recursively — so a spawn added in a new submodule is
    /// checked rather than silently skipped.
    fn rust_sources(dir: &PathBuf) -> Vec<PathBuf> {
        let mut found = Vec::new();
        for entry in std::fs::read_dir(dir).expect("read the source directory") {
            let path = entry.expect("read a directory entry").path();
            if path.is_dir() {
                found.extend(rust_sources(&path));
            } else if path.extension().is_some_and(|e| e == "rs") {
                found.push(path);
            }
        }
        found
    }

    /// Draining a worker's stdout moves runaway output off the worker, where a full pipe blocked
    /// the engine thread, and onto the supervisor — which is only an improvement if what arrives
    /// is bounded. So the cap is applied to what is *buffered*, not just to what is logged: a
    /// line with no newline in sight must not be able to grow this buffer until the server runs
    /// out of memory and takes every other session with it.
    ///
    /// Read through an 8-byte buffer, so the cap has to hold across many small chunks — a pipe
    /// hands over whatever has arrived, not whole lines.
    #[tokio::test]
    async fn a_line_from_a_worker_is_capped_before_it_is_buffered() {
        let mut input = b"short\n".to_vec();
        let overrun = LOGGED_LINE_LIMIT * 3;
        input.extend(std::iter::repeat_n(b'x', overrun));
        input.push(b'\n');
        input.extend_from_slice(b"a last line, unterminated");
        let mut stdout = BufReader::with_capacity(8, &input[..]);
        let mut line = Vec::new();

        assert_eq!(next_capped_line(&mut stdout, &mut line).await, Some(0));
        assert_eq!(line, b"short\n");

        let dropped = next_capped_line(&mut stdout, &mut line)
            .await
            .expect("the long line");
        assert_eq!(
            line.len(),
            LOGGED_LINE_LIMIT,
            "the buffer grew past the cap, so a worker printing without newlines is unbounded"
        );
        assert_eq!(
            dropped,
            overrun + 1 - LOGGED_LINE_LIMIT,
            "the discarded bytes are miscounted, so the log would understate what was dropped"
        );

        // EOF ends a line rather than losing it: an unterminated last line is still output.
        assert_eq!(next_capped_line(&mut stdout, &mut line).await, Some(0));
        assert_eq!(line, b"a last line, unterminated");
        assert_eq!(
            next_capped_line(&mut stdout, &mut line).await,
            None,
            "the drain must end at EOF"
        );
    }

    /// A worker line reaches the log clipped, and says how much was left out. An extension in a
    /// loop must not be able to bury the log under one line.
    #[test]
    fn a_long_line_from_a_worker_is_clipped_before_it_is_logged() {
        let short = "a stray printf";
        assert_eq!(clipped(short), short);

        let long = "x".repeat(LOGGED_LINE_LIMIT * 3);
        let clipped = clipped(&long);
        assert!(clipped.len() < long.len(), "a long line was logged whole");
        assert!(
            clipped.contains(&format!("{} bytes in all", long.len())),
            "the clipped line does not say how much there was: {clipped}"
        );
    }

    // ---- what the worker is told about the caller's deadline ----------------------

    /// A request written immediately carries the whole call budget: nothing has been spent yet,
    /// so the worker gets the full picture and subtracts its own queue wait from it.
    #[test]
    fn a_request_written_at_once_carries_the_whole_call_budget() {
        let sent = remaining_patience_ms(Duration::from_secs(300), Instant::now());
        assert!(
            (299_000..=300_000).contains(&sent),
            "expected ~300s of patience, got {sent}ms"
        );
    }

    /// Time already spent — in the supervisor's own queue, or waiting for a worker to spawn —
    /// is time the caller will not wait again, so it comes off before the request is written.
    #[test]
    fn time_already_spent_comes_off_the_patience_sent() {
        let submitted = Instant::now() - Duration::from_secs(100);
        let sent = remaining_patience_ms(Duration::from_secs(300), submitted);
        assert!(
            (199_000..=200_000).contains(&sent),
            "expected ~200s of patience left, got {sent}ms"
        );
    }

    /// A caller that has already given up leaves no patience rather than an underflowed one.
    /// The worker floors it into a real watchdog budget; what must not happen is a wrap into a
    /// huge number, which would arm the watchdog for weeks.
    #[test]
    fn an_exhausted_budget_saturates_at_zero() {
        let submitted = Instant::now() - Duration::from_secs(600);
        assert_eq!(
            remaining_patience_ms(Duration::from_secs(300), submitted),
            0
        );
    }

    // ---- session handles ----------------------------------------------------------

    #[test]
    fn minted_handles_are_unique() {
        let a = mint_session_id();
        let b = mint_session_id();
        assert_ne!(a, b);
        assert!(a.starts_with("sess-"));
    }

    /// The routing rules, stated as the states rather than as a table: a handle is honoured
    /// only while its session can still make good on it, and the one state that parts company
    /// with that is `Retired` — the worker is alive, so a caller who asked for no guarantee
    /// still reaches it.
    ///
    /// **And a teardown is honoured there too** (`FOLLOWUPS.md` item 55). Retirement says the
    /// handle no longer names the *target*; `end_session` does not touch the target, it releases
    /// the session, which the handle still names exactly. Refused, a caller with anything newer
    /// open could not release their own worker at all — omitting `session_id` reaches whichever
    /// session is current, which is then a different one.
    #[test]
    fn a_retired_handle_is_refused_but_can_still_be_defaulted_to_and_ended() {
        let retired = SessionState::Retired("a raw command replaced the target".to_string());
        assert!(!retired.accepts_handle());
        assert!(retired.accepts_default());
        assert!(retired.accepts_teardown());
        assert!(retired.is_live());
    }

    #[test]
    fn an_opening_session_accepts_calls_that_then_queue_behind_the_open() {
        for state in [
            SessionState::Opening,
            SessionState::Attaching,
            SessionState::Open,
        ] {
            assert!(state.accepts_handle(), "{state:?} should accept its handle");
            assert!(state.accepts_default());
            assert!(state.accepts_teardown(), "{state:?} should be endable");
        }
    }

    #[test]
    fn a_settled_session_accepts_nothing_and_owns_no_worker() {
        for state in [
            SessionState::Failed("boom".to_string()),
            SessionState::Closed("ended".to_string()),
        ] {
            assert!(!state.accepts_handle(), "{state:?}");
            assert!(!state.accepts_default(), "{state:?}");
            // A teardown is widened by exactly one state, not into "always". There is nothing
            // left to release here, and answering a second `end_session` with a release would
            // report work that did not happen.
            assert!(!state.accepts_teardown(), "{state:?}");
            assert!(!state.is_live(), "{state:?}");
        }
    }

    /// The gate at the front of the queue agrees with the caller-side resolve, on every state.
    ///
    /// Both have to widen together: widening one alone trades the refusal in `resolve` for the
    /// same refusal a moment later from [`Gate`], which has no caller to explain it to. This is
    /// the join that says they did.
    #[test]
    fn a_teardown_gate_admits_exactly_what_a_teardown_resolve_does() {
        let gate = Gate {
            on: On::Teardown,
            retires: None,
            closes: None,
        };
        for state in [
            SessionState::Opening,
            SessionState::Attaching,
            SessionState::Open,
            SessionState::Retired("`.opendump`".to_string()),
            SessionState::Failed("boom".to_string()),
            SessionState::Closed("ended".to_string()),
        ] {
            assert_eq!(
                gate.admits(&state),
                state.accepts_teardown(),
                "the queue-front gate and the caller-side check disagree about {state:?}"
            );
        }
    }

    /// A stale-handle message has to say which of the three ways it went stale, because the
    /// recovery differs: re-open, drop the handle, or read the failure first.
    #[test]
    fn a_stale_handle_explains_which_way_it_went_stale() {
        let failed = stale_handle("sess-1", &SessionState::Failed("no such file".to_string()));
        assert!(failed.contains("never opened"), "{failed}");
        assert!(failed.contains("no such file"), "{failed}");

        let retired = stale_handle("sess-1", &SessionState::Retired("`.opendump`".to_string()));
        assert!(retired.contains("retired"), "{retired}");
        // It names the recovery that always works, and names the handle in it — a retired handle
        // still ends its own session. It used to offer "Omit `session_id`" unqualified, which
        // routes to whichever session is current and is therefore a way to act on a *different*
        // one (`FOLLOWUPS.md` item 55).
        assert!(retired.contains("end_session"), "{retired}");
        assert!(retired.contains("sess-1"), "{retired}");
        assert!(
            retired.contains("only while this is still your current session"),
            "the fallback has to carry its condition, or it reads as a way back to this \
             target: {retired}"
        );

        let closed = stale_handle("sess-1", &SessionState::Closed("ended".to_string()));
        assert!(closed.contains("closed"), "{closed}");
        assert!(closed.contains("open_dump"), "{closed}");
    }

    // ---- one registry, several clients ---------------------------------------------

    /// The listener counts a reconnecting client's sessions **after** its identity scope has
    /// closed — the adoption line is written once the MCP call has been handled — so the count has
    /// to be asked for by name. Reading the ambient identity there answers about `local`, which for
    /// a named client is nobody, and the line then reports an adoption of nothing on exactly the
    /// reconnect it exists to describe.
    #[tokio::test]
    async fn a_clients_live_count_is_asked_for_by_name_not_inferred() {
        let ci = crate::client::Client::new("ci");
        let sessions = Sessions::new(Duration::from_secs(1));
        let theirs = crate::client::as_client(ci.clone(), async {
            (0..2)
                .map(|n| dormant(&format!("sess-ci-{n}"), SessionState::Open))
                .collect::<Vec<_>>()
        })
        .await;
        {
            let mut registry = sessions.registry();
            for session in theirs {
                registry.all.push_back(session);
            }
        }

        // No scope here, which is the listener's position after the call it just served.
        assert_eq!(
            sessions.live_count_for(&ci),
            2,
            "a client's sessions have to be countable from outside its own call"
        );
        assert_eq!(sessions.live_count_for(&crate::client::Client::local()), 0);
        assert!(
            sessions.snapshot().is_empty(),
            "the ambient answer here is `local`, which is the mistake the parameter exists to \
             make unavailable"
        );
    }

    /// The property the whole owner field exists for: a handle is only usable by the client that
    /// opened it, and to anyone else it is not "refused" but *unknown* — saying otherwise would
    /// confirm a session exists that the caller may not touch.
    #[tokio::test]
    async fn a_handle_is_not_usable_by_another_client() {
        let sessions = Sessions::new(Duration::from_secs(300));
        let opener = crate::client::Client::new("laptop");
        let session = crate::client::as_client(opener.clone(), async {
            let session = dormant("sess-laptop", SessionState::Open);
            sessions.registry().all.push_back(Arc::clone(&session));
            session
        })
        .await;
        assert_eq!(session.owner, opener);

        // Its own client routes to it, by handle and by default.
        crate::client::as_client(opener, async {
            assert!(sessions.resolve(Some("sess-laptop")).is_ok());
            assert_eq!(sessions.resolve(None).expect("current").id, "sess-laptop");
        })
        .await;

        crate::client::as_client(crate::client::Client::new("ci"), async {
            let by_handle = sessions
                .resolve(Some("sess-laptop"))
                .expect_err("another client's handle must not route");
            assert!(
                by_handle.to_string().contains("unknown session handle"),
                "the refusal must not confirm the session exists: {by_handle}"
            );
            let by_default = sessions
                .resolve(None)
                .expect_err("another client's session is not this one's current");
            assert!(
                by_default.to_string().contains("no debug session is open"),
                "{by_default}"
            );
        })
        .await;
    }

    /// A remembered symbol path is client state, not server state. Rotation keeps the same typed
    /// identity and therefore the setting; revocation removes it, and a later holder of the same
    /// visible name starts from nothing.
    #[tokio::test]
    async fn startup_symbol_paths_follow_client_identity_and_revocation() {
        let sessions = Sessions::new(Duration::from_secs(1));
        let original = crate::client::Client::incarnate("ci", 1);
        let replacement = crate::client::Client::incarnate("ci", 2);
        let other = crate::client::Client::incarnate("other", 3);
        let first = SymbolPathSetting {
            path: r"C:\symbols\first".to_string(),
            append: true,
        };
        let second = SymbolPathSetting {
            path: r"D:\symbols\second".to_string(),
            append: false,
        };

        crate::client::as_client(original.clone(), async {
            assert_eq!(sessions.startup_symbol_path(), None);
            sessions.set_startup_symbol_path(Some(first.clone()));
            assert_eq!(sessions.startup_symbol_path(), Some(first.clone()));
            // The latest explicit setting replaces the earlier starting mutation.
            sessions.set_startup_symbol_path(Some(second.clone()));
            assert_eq!(sessions.startup_symbol_path(), Some(second.clone()));
            sessions.set_startup_symbol_path(None);
            assert_eq!(sessions.startup_symbol_path(), None);
            sessions.set_startup_symbol_path(Some(second.clone()));
        })
        .await;

        crate::client::as_client(other, async {
            assert_eq!(
                sessions.startup_symbol_path(),
                None,
                "one client inherited another client's host path"
            );
        })
        .await;

        // A token rotation supplies this same identity, so it still sees the setting.
        crate::client::as_client(original.clone(), async {
            assert_eq!(sessions.startup_symbol_path(), Some(second));
        })
        .await;
        sessions.revoke(&original);
        crate::client::as_client(original, async {
            assert_eq!(sessions.startup_symbol_path(), None);
        })
        .await;
        crate::client::as_client(replacement, async {
            assert_eq!(
                sessions.startup_symbol_path(),
                None,
                "a name given back inherited the revoked incarnation's setting"
            );
        })
        .await;
    }

    /// And it is not listed either. Reporting another client's sessions would hand over handles it
    /// cannot use, and say how many clients this server has and what they are debugging.
    #[tokio::test]
    async fn session_status_shows_only_the_callers_own() {
        let sessions = Sessions::new(Duration::from_secs(300));
        for (client, id) in [("laptop", "sess-laptop"), ("ci", "sess-ci")] {
            crate::client::as_client(crate::client::Client::new(client), async {
                sessions
                    .registry()
                    .all
                    .push_back(dormant(id, SessionState::Open));
            })
            .await;
        }

        let listed = crate::client::as_client(crate::client::Client::new("laptop"), async {
            sessions
                .snapshot()
                .into_iter()
                .map(|s| s.id)
                .collect::<Vec<_>>()
        })
        .await;
        assert_eq!(listed, vec!["sess-laptop".to_string()]);
    }

    /// The cap is per client, so a caller that fills its own quota cannot deny another one — the
    /// shared-limit version of the same harm.
    #[tokio::test]
    async fn one_clients_sessions_do_not_fill_anothers_quota() {
        let sessions = Sessions::new(Duration::from_secs(300));
        crate::client::as_client(crate::client::Client::new("hog"), async {
            for n in 0..MAX_SESSIONS {
                sessions
                    .registry()
                    .all
                    .push_back(dormant(&format!("sess-hog-{n}"), SessionState::Attaching));
            }
            assert!(
                sessions.take_slot().is_err(),
                "the client at its own limit is refused"
            );
        })
        .await;

        crate::client::as_client(crate::client::Client::new("quiet"), async {
            assert!(
                sessions.take_slot().is_ok(),
                "a client with no sessions has room, whatever another client is holding"
            );
        })
        .await;
    }

    /// Opens in flight for the client these tests run as, which is the local one: the counter is
    /// per client now, so a bare total would answer a question the registry no longer asks.
    fn in_flight_opens(sessions: &Sessions) -> usize {
        sessions
            .registry()
            .opening
            .get(&crate::client::current())
            .copied()
            .unwrap_or(0)
    }

    // ---- asynchronous runs ---------------------------------------------------------
    //
    // A run's whole life above the engine: who may hold one, what a wait does when it runs out,
    // what a stop does to the session, and which calls are refused while a target moves. None of
    // it needs a debugger — the engine's part is one `settle` in the worker, and the smoke tier's
    // launch tests are where that is exercised.

    /// Builds a run in the state the tests below start from, and hands back its handle.
    fn resumed_on(session: &Arc<Session>, job: u64) -> String {
        let handle = mint_execution_id();
        session
            .claim_execution(Execution {
                handle: handle.clone(),
                command: "g".to_string(),
                job,
                started: Instant::now(),
                moving_since: Some(Instant::now()),
                ran_for: None,
                bound: Duration::from_secs(60),
                stopped: None,
            })
            .expect("a session with no run accepts one");
        handle
    }

    /// One run per session, and the refusal names the one already there.
    ///
    /// Not a policy so much as the shape of the thing: a session has one engine thread and DbgEng
    /// moves a target only from inside `WaitForEvent`, so a second run could not start until the
    /// first ended. Refusing says that at the point a caller can still act on it.
    #[test]
    fn a_session_holds_one_run_at_a_time() {
        let session = dormant("sess-1", SessionState::Open);
        let first = resumed_on(&session, 7);

        let held = session
            .claim_execution(Execution {
                handle: "exec-second".to_string(),
                command: "g".to_string(),
                job: 8,
                started: Instant::now(),
                moving_since: Some(Instant::now()),
                ran_for: None,
                bound: Duration::from_secs(60),
                stopped: None,
            })
            .expect_err("a second run started while the first was going");
        assert_eq!(
            held.handle, first,
            "the refusal has to name the run already there, or a caller cannot wait for it"
        );
        assert!(
            held.moving,
            "and say which clock it is quoting: this one is moving, so `waited` is time the \
             target has been going rather than time the caller has been waiting"
        );

        // Once it has stopped the slot is free again — and the new run *replaces* the old one
        // rather than being refused, which is what makes a handle age out rather than accumulate.
        session.finish_execution(7, Ok(Output::text("stopped")));
        let second = resumed_on(&session, 8);
        assert_ne!(second, first);
        assert!(
            session.execution_by(&first).is_none(),
            "the replaced handle must stop resolving, or two handles name one slot"
        );
    }

    /// A reply is filed against the job that produced it, never against whatever the slot holds.
    ///
    /// The writer is a task that outlives its caller, so by the time a stop arrives the session may
    /// be on a later run. Filing by handle alone would land the run-before-last's stop on the one
    /// in flight — reported as a target that had stopped when it is still moving, which is the one
    /// answer here that gets a caller to read a moving target.
    #[test]
    fn a_stop_is_filed_against_its_own_job() {
        let session = dormant("sess-1", SessionState::Open);
        let first = resumed_on(&session, 7);
        session.finish_execution(7, Ok(Output::text("first stop")));
        let second = resumed_on(&session, 8);

        session.finish_execution(7, Ok(Output::text("a stop from the run before last")));
        let found = session.execution_by(&second).expect("the current run");
        assert!(
            found.running,
            "a stale job's reply was filed against the run in flight"
        );
        assert!(session.execution_by(&first).is_none());
    }

    /// While a target is moving, everything that would read it is refused — and the three ops that
    /// are the way out are not.
    #[test]
    fn a_moving_target_refuses_the_calls_that_would_read_it() {
        let sessions = Sessions::new(Duration::from_secs(300));
        let session = dormant("sess-1", SessionState::Open);
        let handle = resumed_on(&session, 7);

        let refused = sessions
            .refuse_while_running(&session, &EngineOp::Registers { all: false })
            .expect("a read of a moving target was allowed through");
        assert!(matches!(refused, EngineError::TargetRunning(_)));
        let said = refused.to_string();
        assert!(
            said.contains(&handle),
            "the refusal has to name the run, or a caller cannot wait for it: {said}"
        );
        assert!(
            said.contains("refused rather than queued"),
            "a caller told only 'no' will retry; the point is that queueing was the alternative \
             and it is worse: {said}"
        );

        for op in [
            EngineOp::Interrupt { job: None },
            EngineOp::EndSession,
            EngineOp::Resume {
                command: "g".to_string(),
                timeout_ms: 1_000,
            },
        ] {
            assert!(
                sessions.refuse_while_running(&session, &op).is_none(),
                "{op:?} is a way out of a running target and must not be refused by it"
            );
        }

        // And the refusal lifts the moment the run stops, with nothing else having to happen.
        session.finish_execution(7, Ok(Output::text("stopped")));
        assert!(
            sessions
                .refuse_while_running(&session, &EngineOp::Registers { all: false })
                .is_none()
        );
    }

    /// A wait that runs out is not a failure, cancels nothing, and says the target is still going.
    ///
    /// The distinction the whole tool rests on: a caller that reads "this wait ran out" as "the
    /// debugger did not answer" ends a session that is working perfectly.
    #[tokio::test(start_paused = true)]
    async fn a_wait_that_runs_out_leaves_the_run_alone() {
        let sessions = Sessions::new(Duration::from_secs(300));
        let session = dormant("sess-1", SessionState::Open);
        let handle = resumed_on(&session, 7);

        let waited = sessions
            .wait_for_stop(&session, &handle, Duration::from_secs(5))
            .await
            .expect("running out is an answer, not an error");
        assert!(
            waited.stop.is_none(),
            "a wait that ran out must not report a stop"
        );
        assert!(
            waited.breaks_in_ms.is_some_and(|left| left > 0),
            "a running target has a bound left, and it is what tells a caller how long to keep \
             waiting"
        );
        assert!(
            session.execution_by(&handle).is_some_and(|f| f.running),
            "the wait consumed the run"
        );
    }

    /// A stop is read, not taken: the second reader gets the same answer as the first.
    #[tokio::test(start_paused = true)]
    async fn a_stop_can_be_read_more_than_once() {
        let sessions = Sessions::new(Duration::from_secs(300));
        let session = dormant("sess-1", SessionState::Open);
        let handle = resumed_on(&session, 7);
        session.finish_execution(
            7,
            Ok(Output::stopped(
                "stopped",
                crate::structured::StopReport {
                    command: "g".to_string(),
                    stopped_at: Some("0xdead".to_string()),
                    thread: Some(4242),
                    processor: None,
                    interrupted: false,
                    timed_out: false,
                    target_gone: false,
                    output: String::new(),
                },
            )),
        );

        for read in 0..2 {
            let waited = sessions
                .wait_for_stop(&session, &handle, Duration::from_secs(5))
                .await
                .expect("the stop is there");
            let stop = waited
                .stop
                .unwrap_or_else(|| panic!("read {read} found no stop"));
            assert_eq!(stop.stopped_at.as_deref(), Some("0xdead"), "read {read}");
            assert_eq!(stop.thread, Some(4242), "read {read}");
            assert!(
                waited.breaks_in_ms.is_none(),
                "a stopped run has no bound left"
            );
        }
    }

    /// A run that failed is reported as this call's failure, keeping the kind the worker named.
    #[tokio::test(start_paused = true)]
    async fn a_run_that_failed_fails_the_wait() {
        let sessions = Sessions::new(Duration::from_secs(300));
        let session = dormant("sess-1", SessionState::Open);
        let handle = resumed_on(&session, 7);
        session.finish_execution(7, Err(EngineError::Lost("the worker died".to_string())));

        let failed = sessions
            .wait_for_stop(&session, &handle, Duration::from_secs(5))
            .await
            .expect_err("a failed run has to fail its wait");
        assert!(matches!(failed, EngineError::Lost(_)));
    }

    /// A handle the session is not holding is refused, and the refusal says what to ask instead.
    #[tokio::test(start_paused = true)]
    async fn an_unknown_handle_is_refused_rather_than_waited_on() {
        let sessions = Sessions::new(Duration::from_secs(300));
        let session = dormant("sess-1", SessionState::Open);

        let refused = sessions
            .wait_for_stop(&session, "exec-nothing", Duration::from_secs(5))
            .await
            .expect_err("an unknown handle was waited on");
        assert!(matches!(refused, EngineError::Stale(_)));
        assert!(
            refused.to_string().contains("session_status"),
            "the one tool every surface has is what distinguishes the three ways a handle can be \
             unknown: {refused}"
        );

        let refused = sessions
            .break_in(&session, "exec-nothing", true)
            .await
            .expect_err("an unknown handle was broken in");
        assert!(matches!(refused, EngineError::Stale(_)));
    }

    /// Breaking in a run that has already stopped is the ordinary race, not a failure.
    #[tokio::test(start_paused = true)]
    async fn breaking_in_a_run_that_already_stopped_is_not_an_error() {
        let sessions = Sessions::new(Duration::from_secs(300));
        let session = dormant("sess-1", SessionState::Open);
        let handle = resumed_on(&session, 7);
        session.finish_execution(7, Ok(Output::text("stopped")));

        let asked = sessions
            .break_in(&session, &handle, true)
            .await
            .expect("a stopped run is a fine thing to have asked about");
        assert!(
            !asked.requested,
            "nothing should have been sent to an engine with nothing to break"
        );
        assert!(asked.detail.contains("already stopped"));
    }

    /// Plays the worker for one queued resume: takes the job, reports the milestone if asked, and
    /// answers with `reply`.
    ///
    /// Standing in for [`reader`] rather than running it, because what these tests are about is
    /// the order `start_execution` reads two facts in — and staging that needs the two to arrive
    /// together, which is exactly what a real worker does for a run that is over before its caller
    /// looks and exactly what a scheduler will not reproduce on demand.
    fn answer_one_resume(
        session: &Arc<Session>,
        mut jobs: mpsc::UnboundedReceiver<Job>,
        moved: bool,
        reply: Option<Result<Output, EngineError>>,
    ) {
        let session = Arc::clone(session);
        tokio::spawn(async move {
            let job = jobs.recv().await.expect("the resume reached the queue");
            if moved {
                let told = session
                    .waiters
                    .lock()
                    .unwrap()
                    .get_mut(&job.id)
                    .and_then(|waiting| waiting.resumed.take())
                    .expect("a resume registers somewhere to report the milestone");
                // The real `reader`'s order exactly, which is the point of a double: the phase
                // and the channel are published *before* the wake that announces them, or a
                // waiter can be woken on another thread and find neither.
                session.execution_moving(job.id);
                let _ = told.send(());
                session.execution_moved();
            }
            // `None` leaves the run going, which is the ordinary state of one — the reply is the
            // *stop*, and for a `g` on a live target it may be an hour away. A helper that always
            // answered could only ever stage runs that were already over.
            let Some(reply) = reply else { return };
            let done = session
                .waiters
                .lock()
                .unwrap()
                .remove(&job.id)
                .expect("the waiter is still registered")
                .done;
            let _ = done.send(reply);
        });
    }

    /// A run that started **and stopped** before its caller got a turn is still a run that moved
    /// the target.
    ///
    /// Both facts are waiting by then — the milestone and the reply — and reading the reply first
    /// answers "the target never started moving" about a target that moved and stopped. That is
    /// not a nuance: it is the difference between a `g` onto a nearby breakpoint reporting what it
    /// did and reporting that nothing happened.
    #[tokio::test(start_paused = true)]
    async fn a_run_that_stopped_before_its_caller_looked_still_says_it_moved() {
        let sessions = Sessions::new(Duration::from_secs(300));
        let (session, jobs) = queued("sess-1", SessionState::Open);
        answer_one_resume(
            &session,
            jobs,
            true,
            Some(Ok(Output::text("Breakpoint 0 hit"))),
        );

        let started = sessions
            .start_execution(&session, true, "g".to_string(), Duration::from_secs(60))
            .await
            .expect("a run that reached a breakpoint is not a failure");
        assert!(
            started.moved,
            "the milestone said the target moved, and the reply arriving first must not overwrite \
             that with `it never started`"
        );
        assert!(
            !started.running,
            "but it is not moving *now* — the stop is already filed. Saying otherwise tells the \
             caller to go and do the thing the run is waiting for while the session is stopped \
             and taking ordinary reads"
        );
    }

    /// **`continue_async` returns while the target is still moving.** The whole tool, as one
    /// assertion.
    ///
    /// Stated as a *budget* rather than as a wall-clock measurement because that is what went
    /// wrong: the first draft waited only on the execution slot, which nothing touches until the
    /// run **ends**, so the call blocked for exactly as long as the target ran and then answered
    /// `running: true` about a run that was over. Every other test here passed — including the one
    /// that sends the milestone and the reply together, which is satisfied either way. CI caught
    /// it, on a target that ran thirty seconds.
    ///
    /// `start_paused` makes the budget exact: no time passes unless something awaits a timer, so a
    /// call that returns has returned without waiting for one.
    #[tokio::test(start_paused = true)]
    async fn a_run_is_handed_back_while_the_target_is_still_moving() {
        let sessions = Sessions::new(Duration::from_secs(300));
        let (session, jobs) = queued("sess-1", SessionState::Open);
        // The milestone and **no reply**: the target is running and will go on running.
        answer_one_resume(&session, jobs, true, None);

        let started = tokio::time::Instant::now();
        let handed = sessions
            .start_execution(&session, true, "g".to_string(), Duration::from_secs(600))
            .await
            .expect("a target that is moving is not a failure");
        assert!(handed.running, "{handed:?}");
        assert!(
            handed.breaks_in_ms.is_some_and(|left| left > 0),
            "a run still going has a bound left; absent means this answered about a run that had \
             already ended: {handed:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "the call waited {:?} — it returns on the milestone, not on the stop",
            started.elapsed()
        );
    }

    /// A resume the worker **refused** fails the call, rather than being dressed up as a run that
    /// finished early.
    ///
    /// The refusal that reaches this is a real one: a session whose target has gone refuses every
    /// op, this one included. Reported as an `ExecutionStarted` it would be a success carrying a
    /// handle to a run that never existed, and the failure would only surface on a later wait.
    #[tokio::test(start_paused = true)]
    async fn a_resume_the_worker_refused_fails_the_call() {
        let sessions = Sessions::new(Duration::from_secs(300));
        let (session, jobs) = queued("sess-1", SessionState::Open);
        answer_one_resume(
            &session,
            jobs,
            false,
            Some(Err(EngineError::Stale(
                "this session has no target left".to_string(),
            ))),
        );

        let refused = sessions
            .start_execution(&session, true, "g".to_string(), Duration::from_secs(60))
            .await
            .expect_err("a refused resume reported a started run");
        assert!(
            matches!(refused, EngineError::Stale(_)),
            "the kind the worker named has to survive, or a caller retries what cannot work: \
             {refused}"
        );
    }

    /// A stop filed **while** a wait is in flight wakes it, rather than being found on the next
    /// poll.
    ///
    /// The property the `watch` is there for: a receiver taken before the slot is read cannot miss
    /// a change made after that read. Got wrong, the wait sits out its whole budget and reports
    /// "still running" about a target that stopped a moment after it started waiting.
    #[tokio::test(start_paused = true)]
    async fn a_stop_filed_during_a_wait_wakes_it() {
        let sessions = Sessions::new(Duration::from_secs(300));
        let session = dormant("sess-1", SessionState::Open);
        let handle = resumed_on(&session, 7);

        let filing = Arc::clone(&session);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(2)).await;
            filing.finish_execution(
                7,
                Ok(Output::stopped(
                    "Breakpoint 0 hit",
                    crate::structured::StopReport {
                        command: "g".to_string(),
                        stopped_at: Some("0xbeef".to_string()),
                        thread: None,
                        processor: None,
                        interrupted: false,
                        timed_out: false,
                        target_gone: false,
                        output: String::new(),
                    },
                )),
            );
        });

        let started = tokio::time::Instant::now();
        let waited = sessions
            .wait_for_stop(&session, &handle, Duration::from_secs(120))
            .await
            .expect("the run stopped");
        assert_eq!(
            waited
                .stop
                .expect("the wait found no stop")
                .stopped_at
                .as_deref(),
            Some("0xbeef")
        );
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "the wait sat out its budget instead of being woken, which is what a lost wakeup looks \
             like: {:?}",
            started.elapsed()
        );
    }

    /// A session holding a run is busy, and stops being idle from the moment the run *ends*.
    ///
    /// Three mechanisms, not one, and the middle one is the reason this test is longer than it
    /// looks. Busy is the *waiter* for as long as the resume's own job is outstanding. Then
    /// `reader` removes that waiter and the task that files the stop runs after it — so between
    /// the two the waiter map is empty while the target's stop has not been recorded anywhere,
    /// and a `last_used` stamped when a long run was submitted is by then stale. A session in
    /// that state could be closed by a concurrent open, and the stop would be filed where nobody
    /// could ever resolve it. Busy therefore also reads the *slot*, which still says the run is
    /// going. And the clock is `last_used`, stamped again when the stop is filed, without which a
    /// run that outlasted the reclamation window would leave the session reclaimable the instant
    /// it stopped.
    #[test]
    fn a_run_keeps_its_session_from_being_reclaimed() {
        let session = dormant("sess-1", SessionState::Open);
        let handle = resumed_on(&session, 7);
        session.waiters.lock().unwrap().insert(
            7,
            Waiting {
                done: oneshot::channel().0,
                progress: None,
                resumed: None,
                unwound: false,
            },
        );
        assert!(session.busy(), "a run in flight has a reply outstanding");

        session.waiters.lock().unwrap().remove(&7);
        // Aged past the reclamation window, which is what a long run does to the stamp taken when
        // it was *submitted* — the only stamp there was before the stop started taking one.
        *session.last_used.lock().unwrap() = Instant::now() - Duration::from_secs(3_600);
        // The window between `reader` taking the waiter and the filing task recording the stop.
        // The stamp is stale and nothing is outstanding, so the slot is the only thing left
        // saying this session is in use — and it has to be enough.
        assert!(
            session.busy(),
            "the reply has been taken but the stop is not filed yet; a session closed here files              its stop where no caller can resolve it"
        );
        assert!(
            !session.idle_for(Duration::from_secs(60)),
            "and so it is not idle either, however stale the submission stamp is"
        );
        session.finish_execution(7, Ok(Output::text("stopped")));
        assert!(!session.busy(), "a run that ended owes nothing");
        assert!(
            !session.idle_for(Duration::from_secs(60)),
            "the idle clock has to restart when the run ends, or a long run leaves its session \
             reclaimable the moment it stops — and the stop could be taken before its caller read \
             it"
        );
        assert!(
            session.execution_by(&handle).is_some(),
            "the stop outlives the run so a caller who was not waiting can still read it"
        );
    }

    /// And the two facts move together, which a sequential test cannot tell from them merely both
    /// being true at the end.
    ///
    /// `busy()` reads the slot and `idle_for` reads `last_used`, so "not busy" and "stale" are the
    /// pair that gets a session released. `finish_execution` produces both, and while it published
    /// the stop first and stamped the clock afterwards there was a window holding exactly that
    /// pair — small, but reachable by any sweep, and only on a run that had outlasted the
    /// reclamation window, which is the one case the restamp was added for.
    ///
    /// Staged by holding the clock's own lock, so the filing thread is stopped at the point of
    /// interest rather than raced past it. With the stamp inside the slot's lock, a thread blocked
    /// on the clock is *still holding the slot*, so the stop cannot be read at all. With it
    /// outside, the slot has been released and already says the run stopped — the bad pair,
    /// standing still to be looked at, and it stays that way for as long as the clock is held.
    ///
    /// The sampling bound is what makes a **failure** observable, not what makes a pass true: a
    /// pass is guaranteed by the lock, so no amount of scheduling luck manufactures one. A run
    /// starved of the CPU for the whole spell would report a false pass and never a false failure,
    /// which is the direction to be wrong in.
    #[test]
    fn a_filed_stop_is_never_visible_beside_a_stale_idle_clock() {
        let session = dormant("sess-1", SessionState::Open);
        let _handle = resumed_on(&session, 7);
        *session.last_used.lock().unwrap() = Instant::now() - Duration::from_secs(3_600);

        let clock = session.last_used.lock().unwrap();
        let (entered, has_entered) = std::sync::mpsc::channel();
        let filing = {
            let session = Arc::clone(&session);
            std::thread::spawn(move || {
                entered.send(()).expect("the test is still waiting");
                session.finish_execution(7, Ok(Output::text("stopped")));
            })
        };
        has_entered.recv().expect("the filing thread starts");

        let deadline = Instant::now() + Duration::from_millis(250);
        let mut published_without_the_clock = false;
        while Instant::now() < deadline {
            if let Ok(slot) = session.execution.try_lock()
                && slot.as_ref().is_some_and(|e| !e.running())
            {
                published_without_the_clock = true;
                break;
            }
            std::thread::yield_now();
        }
        assert!(
            !published_without_the_clock,
            "the stop was published while the idle clock still held the submission stamp: a sweep \
             reading the slot here finds a session that is neither busy nor recently used, \
             releases it, and the stop lands where its caller can no longer resolve it"
        );

        drop(clock);
        filing.join().expect("the filing thread files the stop");
        assert!(!session.busy(), "a run that ended owes nothing");
        assert!(
            !session.idle_for(Duration::from_secs(60)),
            "and once it has, the clock says so"
        );
    }

    /// How long the run *ran*, not how long ago it started.
    ///
    /// The stop is deliberately kept until another run replaces it, so a handle can be read
    /// minutes or hours after the target stopped. Derived from `started.elapsed()` the figure
    /// grows the whole time: a stop read twice reports two different run lengths, and
    /// `session_status` shows a finished run getting steadily longer.
    ///
    /// Staged by moving `started` backwards, which is what the passage of real time does to it,
    /// because the clock these instants are on is `std::time::Instant` — tokio's paused clock does
    /// not move it, and a test that advanced tokio's would assert nothing while appearing to.
    #[tokio::test]
    async fn a_finished_run_reports_how_long_it_ran() {
        let sessions = Sessions::new(Duration::from_secs(300));
        let session = dormant("sess-1", SessionState::Open);
        let handle = mint_execution_id();
        session
            .claim_execution(Execution {
                handle: handle.clone(),
                command: "g".to_string(),
                job: 7,
                // A run that has been going five seconds when it stops.
                started: Instant::now() - Duration::from_secs(5),
                moving_since: Some(Instant::now() - Duration::from_secs(5)),
                ran_for: None,
                bound: Duration::from_secs(60),
                stopped: None,
            })
            .expect("a session with no run accepts one");
        session.finish_execution(7, Ok(Output::text("stopped")));

        let took = session
            .execution_info()
            .expect("the slot still holds it")
            .running_for_ms;
        assert!(
            (5_000..6_000).contains(&took),
            "the run took five seconds: {took}ms"
        );

        // An hour goes by with the stop still sitting there, unread. Nothing about the run has
        // changed, so nothing about how long it took may change either.
        {
            let mut slot = session.execution.lock().unwrap();
            slot.as_mut().expect("the run is there").started -= Duration::from_secs(3_600);
        }
        assert_eq!(
            session
                .execution_info()
                .expect("the slot still holds it")
                .running_for_ms,
            took,
            "an hour later the run still took five seconds; a figure that keeps counting is \
             reporting how long ago it started"
        );
        assert_eq!(
            sessions
                .wait_for_stop(&session, &handle, Duration::from_secs(1))
                .await
                .expect("a stopped run answers at once")
                .running_for_ms,
            took,
            "`session_status` and the wait have to agree about one run"
        );
    }

    /// A wait woken by something that is not a stop keeps the deadline it was given.
    ///
    /// The slot is bumped by more than the stop — the `Resumed` milestone bumps it, which is what
    /// a caller waiting on a handle it got from `session_status` sees — and re-arming the full
    /// budget on each wakeup makes `timeout_ms` a per-wakeup allowance rather than a deadline.
    /// This wait is capped below the call timeout on purpose (`STOP_WAIT_MARGIN`) so the call
    /// answers instead of expiring, and a budget that can be spent twice is that cap not holding.
    #[tokio::test(start_paused = true)]
    async fn a_wait_woken_by_anything_else_still_ends_on_time() {
        let sessions = Sessions::new(Duration::from_secs(300));
        let session = dormant("sess-1", SessionState::Open);
        let handle = resumed_on(&session, 7);

        // Three wakeups that are not the stop, spread across the budget.
        let nudging = Arc::clone(&session);
        tokio::spawn(async move {
            for _ in 0..3 {
                tokio::time::sleep(Duration::from_secs(20)).await;
                nudging.execution_moved();
            }
        });

        let started = tokio::time::Instant::now();
        let waited = sessions
            .wait_for_stop(&session, &handle, Duration::from_secs(30))
            .await
            .expect("a wait that runs out is a poll, not a failure");
        assert!(
            waited.stop.is_none(),
            "nothing stopped, so there is no stop"
        );
        assert!(
            started.elapsed() < Duration::from_secs(45),
            "the wait was for 30s and took {:?}; a wakeup that is not a stop must not buy it \
             another whole budget",
            started.elapsed()
        );
    }

    /// A break is bound to the run it was asked about, and cannot be rebound.
    ///
    /// Between `break_in` reading the slot and the worker reading the request, the run may have
    /// stopped and the engine thread started the next thing — a queued command, or the run after
    /// this one. An unbound interrupt is bound by the *worker* to whatever is running then, so it
    /// would cut that short instead, reported to its caller as an interruption nobody asked for.
    #[tokio::test]
    async fn a_break_names_the_job_of_the_run_it_was_asked_about() {
        let sessions = Sessions::new(Duration::from_secs(300));
        let (session, mut jobs) = queued("sess-1", SessionState::Open);
        let handle = resumed_on(&session, 7);

        let answering = Arc::clone(&session);
        let sent = tokio::spawn(async move {
            let job = jobs.recv().await.expect("the break reached the queue");
            let done = answering
                .waiters
                .lock()
                .unwrap()
                .remove(&job.id)
                .expect("the waiter is registered")
                .done;
            let _ = done.send(Ok(Output::interrupted(
                "Interrupted.",
                crate::proto::Interrupted::Raised,
            )));
            job.op
        });

        let asked = sessions
            .break_in(&session, &handle, true)
            .await
            .expect("the worker answered");
        assert!(asked.requested, "the worker said a break is lodged");
        assert!(
            matches!(
                sent.await.expect("the fake worker ran"),
                EngineOp::Interrupt { job: Some(7) }
            ),
            "the break has to name the run's job, or the worker binds it to whatever it is doing"
        );
    }

    /// `requested` is the worker's answer, not "the request went through".
    ///
    /// Four of the five things an interrupt can do are `Ok` and raise nothing — nothing was
    /// running, the job named had moved on, a batch was sealed for its rollback. Reading `Ok` as
    /// delivery reports every one of those as a target about to stop.
    #[tokio::test]
    async fn a_break_that_reached_nothing_says_so() {
        let sessions = Sessions::new(Duration::from_secs(300));
        let (session, mut jobs) = queued("sess-1", SessionState::Open);
        let handle = resumed_on(&session, 7);

        let answering = Arc::clone(&session);
        tokio::spawn(async move {
            let job = jobs.recv().await.expect("the break reached the queue");
            let done = answering
                .waiters
                .lock()
                .unwrap()
                .remove(&job.id)
                .expect("the waiter is registered")
                .done;
            let _ = done.send(Ok(Output::interrupted(
                "Nothing was running on this session's engine.",
                crate::proto::Interrupted::NothingRunning,
            )));
        });

        let asked = sessions
            .break_in(&session, &handle, true)
            .await
            .expect("a request that reached nothing still reached the worker");
        assert!(
            !asked.requested,
            "the worker raised nothing, so nothing is going to stop"
        );
    }

    /// A break-in that could not reach its worker is a failure, not a benign race.
    ///
    /// `requested: false` has one meaning — the run had already stopped, so nothing needed
    /// sending. Folding a lost worker into it makes "the target is already stopped" and "nothing
    /// knows whether it ever will" the same answer.
    #[tokio::test]
    async fn a_break_in_that_cannot_reach_its_worker_fails() {
        let sessions = Sessions::new(Duration::from_secs(300));
        let (session, jobs) = queued("sess-1", SessionState::Open);
        let handle = resumed_on(&session, 7);
        // The worker is gone: the queue has no receiver, so nothing can ever answer.
        drop(jobs);

        let why = sessions
            .break_in(&session, &handle, true)
            .await
            .expect_err("a break nobody can deliver is not a break that was not needed");
        assert!(
            matches!(why, EngineError::Lost(_)),
            "the failure keeps its kind rather than becoming a quiet `requested: false`: {why:?}"
        );
    }

    /// A run whose slot is taken before its own call returns says so, rather than handing back a
    /// handle nothing resolves.
    ///
    /// A run that stops makes the slot replaceable — deliberately, since that is what lets a
    /// handle age out instead of accumulating — and it can stop before the `continue_async` that
    /// started it is scheduled again. A concurrent caller watching `session_status` can claim the
    /// slot in that window. Both of the other answers are worse than an error: a record built
    /// from the old handle would say the stop is recorded and waiting to be read when
    /// `wait_for_stop` can no longer find it, and carrying on round the loop would wait on a slot
    /// this run no longer owns until the whole call budget ran out.
    #[tokio::test(start_paused = true)]
    async fn a_run_whose_slot_was_taken_before_it_answered_says_so() {
        let sessions = Sessions::new(Duration::from_secs(300));
        let (session, mut jobs) = queued("sess-1", SessionState::Open);

        // The worker answers, and a concurrent caller takes the slot before the starter looks.
        let racing = Arc::clone(&session);
        tokio::spawn(async move {
            let job = jobs.recv().await.expect("the resume reached the queue");
            let done = racing
                .waiters
                .lock()
                .unwrap()
                .remove(&job.id)
                .expect("the waiter is registered")
                .done;
            let _ = done.send(Ok(Output::text("Breakpoint 0 hit")));
            racing.finish_execution(job.id, Ok(Output::text("Breakpoint 0 hit")));
            // Another `continue_async` gets there first.
            resumed_on(&racing, job.id + 1);
        });

        let why = sessions
            .start_execution(&session, true, "g".to_string(), Duration::from_secs(60))
            .await
            .expect_err("the handle this call was about is gone");
        assert!(
            matches!(why, EngineError::Stale(_)),
            "a handle nothing resolves is a stale handle, not a run that is still going: {why:?}"
        );
        assert!(
            why.to_string().contains("replaced"),
            "and the message has to say what happened to it: {why}"
        );
    }

    /// A run that is claimed but still queued has not run for any time, and has its whole bound.
    ///
    /// The slot is claimed before the job is submitted — deliberately, so no read can slip through
    /// to a target that may already be moving — which means `started` is when the *caller asked*,
    /// not when the target went. Behind a long `pool_census` those are minutes apart, and every
    /// figure taken from `started` is then wrong the same way: time the target stood still counted
    /// as running, and a bound counted down before the worker had begun it. A run queued longer
    /// than its own bound would report no bound left at the moment it started a full-length one.
    #[test]
    fn a_queued_run_has_not_started_counting() {
        let session = dormant("sess-1", SessionState::Open);
        let handle = mint_execution_id();
        session
            .claim_execution(Execution {
                handle: handle.clone(),
                command: "g".to_string(),
                job: 7,
                // Claimed two minutes ago and still waiting its turn: a bound this stale would
                // have run out twice over.
                started: Instant::now() - Duration::from_secs(120),
                moving_since: None,
                bound: Duration::from_secs(60),
                ran_for: None,
                stopped: None,
            })
            .expect("a session with no run accepts one");

        let queued = session.execution_info().expect("the slot holds it");
        assert_eq!(
            queued.running_for_ms, 0,
            "the target has not moved, so it has not run for two minutes or for anything else"
        );
        assert_eq!(
            queued.breaks_in_ms,
            Some(60_000),
            "the worker starts its bound when it starts pumping, so a run still in the queue has \
             all of it — reporting none left would say a run that is about to begin is about to \
             end"
        );
        assert!(
            !queued.stopped,
            "queued is not stopped: a read arriving now could find the target already moving, \
             which is why the slot is claimed this early in the first place"
        );

        // And from the milestone it counts.
        session.execution_moving(7);
        assert!(
            session
                .execution_info()
                .expect("the slot holds it")
                .breaks_in_ms
                .is_some_and(|left| left <= 60_000),
            "once it is moving the bound counts down"
        );
    }

    /// The duplicate-run refusal quotes the clock it names, and a queued run has a different one.
    ///
    /// `ran_for` is zero until the target moves, so a refusal built from it would tell a caller
    /// that a run claimed ten minutes ago was "resumed 0ms ago" — and one built from the claim
    /// would call a queue wait a run. The refusal says which it is quoting instead.
    #[test]
    fn the_duplicate_run_refusal_says_which_clock_it_is_quoting() {
        let session = dormant("sess-1", SessionState::Open);
        session
            .claim_execution(Execution {
                handle: "exec-queued".to_string(),
                command: "g".to_string(),
                job: 7,
                // Asked for ten minutes ago and still behind another call on the engine.
                started: Instant::now() - Duration::from_secs(600),
                moving_since: None,
                ran_for: None,
                bound: Duration::from_secs(60),
                stopped: None,
            })
            .expect("a session with no run accepts one");

        let held = session
            .claim_execution(Execution {
                handle: "exec-second".to_string(),
                command: "g".to_string(),
                job: 8,
                started: Instant::now(),
                moving_since: None,
                ran_for: None,
                bound: Duration::from_secs(60),
                stopped: None,
            })
            .expect_err("a queued run still holds the slot: it may be moving any moment");
        assert!(
            !held.moving,
            "the run it names has not been resumed, and the refusal must not say it has"
        );
        assert!(
            held.waited >= Duration::from_secs(600),
            "so the figure is how long the caller has been waiting, not the zero a run that has \
             not moved has been running: {:?}",
            held.waited
        );
    }

    /// A second milestone for one job does not restart its clock.
    #[test]
    fn a_repeated_milestone_does_not_restart_the_run() {
        let session = dormant("sess-1", SessionState::Open);
        let handle = resumed_on(&session, 7);
        let first = session
            .execution_by(&handle)
            .expect("it is there")
            .running_for;
        session.execution_moving(7);
        assert!(
            session
                .execution_by(&handle)
                .expect("it is there")
                .running_for
                >= first,
            "a run that has been going an hour is not one that just started because the worker \
             said `Resumed` twice"
        );
    }

    /// The two questions an interrupt's outcome answers do not partition the same way.
    ///
    /// `break_in` asks *is this run going to stop*, for which a break already lodged and a queued
    /// run barred from starting are both yes. The transcript asks *did this request raise the
    /// break*, because its `interrupt` event exists to explain a later truncated result and a
    /// request that sent nothing explains nothing. One `bool` made these the same, and whichever
    /// reader lost had a plausible wrong answer.
    #[test]
    fn an_interrupt_outcome_answers_two_different_questions() {
        use crate::proto::Interrupted;
        for (outcome, stopping, delivered) in [
            (Interrupted::Raised, true, true),
            (Interrupted::AlreadyPending, true, false),
            (Interrupted::Barred, true, false),
            (Interrupted::NothingRunning, false, false),
            (Interrupted::Sealed, false, false),
        ] {
            assert_eq!(outcome.stopping(), stopping, "{outcome:?}.stopping()");
            assert_eq!(outcome.delivered(), delivered, "{outcome:?}.delivered()");
        }
    }

    // ---- releasing what nobody is using -------------------------------------------

    /// The clock alone is not the question. A session with a call outstanding is in use however
    /// long ago that call was submitted — which is the parked kernel attach exactly: one call, then
    /// a wait for a target that may take hours to dial in.
    #[test]
    fn a_session_with_a_call_outstanding_is_never_idle() {
        let session = dormant("sess-waiting", SessionState::Open);
        // Backdate it well past any timeout, so only `busy()` can save it.
        *session.last_used.lock().unwrap() = Instant::now() - Duration::from_secs(3600);
        assert!(
            session.idle_for(Duration::from_secs(1)),
            "with nothing outstanding it is idle"
        );

        session.waiters.lock().unwrap().insert(
            1,
            Waiting {
                done: oneshot::channel().0,
                progress: None,
                resumed: None,
                unwound: false,
            },
        );
        assert!(
            !session.idle_for(Duration::from_secs(1)),
            "a call is outstanding: the session is in use, whatever the clock says"
        );
    }

    /// An opener that has not yet been handed back is not idle either, however long the spawn
    /// takes — the caller has not been told the handle yet, so nobody could have used it.
    #[test]
    fn a_session_not_yet_delivered_is_never_idle() {
        let session = dormant("sess-opening", SessionState::Open);
        session.delivered.store(false, Ordering::Release);
        *session.last_used.lock().unwrap() = Instant::now() - Duration::from_secs(3600);
        assert!(!session.idle_for(Duration::from_secs(1)));
    }

    /// And the ordinary case: used recently, so left alone.
    #[test]
    fn a_session_used_recently_is_left_alone() {
        let session = dormant("sess-busy", SessionState::Open);
        assert!(!session.idle_for(Duration::from_secs(60)));
    }

    // ---- the registry (no workers involved) ---------------------------------------

    /// A revoked credential cannot register a session, and a name given back can again.
    ///
    /// **The window this closes is the one a lease expiry does not have.** An expiry fires only
    /// after the client has been silent for longer than any call can keep it quiet, so nothing of
    /// that credential's can still be in flight. A revocation has no quiet period: the token stops
    /// being accepted the moment the set is swapped, but a call that got past authentication an
    /// instant earlier is still running, and an opener can be *seconds* from registering — an
    /// `attach_kernel` is. Without this gate the sweep is one pass over a snapshot, and a session
    /// admitted behind it belongs to a client nothing can authenticate as and nothing will ever
    /// come back for: a live kernel target held by nobody.
    ///
    /// **What lifts it is the name being configured again**, and nothing else. Hanging it on the
    /// teardown finishing lifts it on a timing coincidence: that release is one pass over a
    /// snapshot, so an opener which authenticated before the revocation but has not registered yet
    /// — an `attach_kernel` is seconds of worker spawn and link wait away from doing so — is
    /// invisible to it, and would then register a target owned by a credential nothing can
    /// authenticate as. A name revoked and never given back keeps its gate for the life of the
    /// process, which is the answer wanted rather than a leak to tidy.
    #[test]
    fn a_revoked_credential_cannot_register_a_session_until_the_sweep_lifts_it() {
        let sessions = Sessions::new(Duration::from_secs(300));
        let gone = crate::client::Client::new("ci");
        let mine = |id: &str| {
            let session = dormant(id, SessionState::Open);
            // `dormant` takes the ambient client, which in a test is `local`; these have to be
            // owned by the client being revoked for the gate to be about anything.
            Arc::new(Session {
                owner: gone.clone(),
                ..Arc::into_inner(session).expect("`dormant` hands back the only reference")
            })
        };

        assert!(
            sessions.admit(&mine("sess-before")).is_ok(),
            "nothing is revoked yet"
        );

        sessions.revoke(&gone);
        let refused = sessions
            .admit(&mine("sess-behind-the-sweep"))
            .expect_err("a revoked credential registered a session");
        assert!(
            refused.contains("revoked"),
            "the refusal has to say why, or it reads as a capacity problem: {refused}"
        );
        // Another client is untouched: a revocation is about one credential, not the registry.
        assert!(
            sessions
                .admit(&dormant("sess-someone-else", SessionState::Open))
                .is_ok(),
            "revoking one client refused another one's session"
        );

        // **A name given back is a different client, and is not gated by its predecessor's mark.**
        // Nothing lifts the mark — nothing has to, which is the whole of what an incarnation buys
        // here: the question of *when* to take a gate off is where two separate findings lived
        // ([#190](https://github.com/glslang/windbg-mcp/issues/190)).
        let again = crate::client::Client::incarnate("ci", 2);
        assert_ne!(again, gone, "a re-added name has to be a different client");
        assert_eq!(again.name(), gone.name(), "and has to still be called `ci`");
        let session = dormant("sess-after", SessionState::Open);
        assert!(
            sessions
                .admit(&Arc::new(Session {
                    owner: again,
                    ..Arc::into_inner(session).expect("`dormant` hands back the only reference")
                }))
                .is_ok(),
            "a client configured under a revoked name could not open a session"
        );
    }

    /// A `Session` with no worker behind it, for the routing tests. Its queue has no consumer,
    /// which is all these need: they never submit a call.
    fn dormant(id: &str, state: SessionState) -> Arc<Session> {
        dormant_recording(id, state, crate::record::Recorder::disabled())
    }

    /// [`dormant`] with a transcript, for the one test that is about what gets recorded.
    fn dormant_recording(
        id: &str,
        state: SessionState,
        rec: crate::record::Recorder,
    ) -> Arc<Session> {
        let (tx, _rx) = mpsc::unbounded_channel();
        // The phase a session in this state would really have reached. They are separate fields
        // for good reason, but a double whose phase contradicts its state would prove nothing.
        let phase = match state {
            SessionState::Opening => OpenPhase::Started,
            SessionState::Attaching => OpenPhase::Committed,
            _ => OpenPhase::Opened,
        };
        Arc::new(Session {
            id: id.to_string(),
            kind: SessionKind::Dump,
            what: "test".to_string(),
            pid: 0,
            created: Instant::now(),
            owner: crate::client::current(),
            last_used: Mutex::new(Instant::now()),
            state: Mutex::new((state, Instant::now())),
            tx,
            next_id: AtomicU64::new(1),
            waiters: Arc::new(Mutex::new(HashMap::new())),
            // Test doubles stand in for sessions their callers already hold.
            delivered: AtomicBool::new(true),
            phase: AtomicU8::new(phase as u8),
            released: AtomicBool::new(false),
            unwinding: Arc::new(Mutex::new(None)),
            execution: Mutex::new(None),
            submit_gate: Mutex::new(()),
            execution_changed: tokio::sync::watch::Sender::new(0),
            child: Mutex::new(None),
            rec,
        })
    }

    /// A routing double whose queue still has a consumer, for tests that drive [`pump`] itself.
    fn queued(id: &str, state: SessionState) -> (Arc<Session>, mpsc::UnboundedReceiver<Job>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let session =
            Arc::into_inner(dormant(id, state)).expect("`dormant` hands back the only reference");
        (Arc::new(Session { tx, ..session }), rx)
    }

    /// The starting path travels on the opener's request itself. Sending a standalone setup job
    /// would make the worker briefly routable between setup and open, and would let another call
    /// occupy that gap.
    #[test]
    fn an_opener_carries_its_starting_symbol_path_on_the_same_request() {
        let (session, rx) = queued("sess-1", SessionState::Opening);
        let waiters = Arc::clone(&session.waiters);
        let (requests, worker) = std::io::pipe().expect("a pipe to stand in for the worker's");
        let setting = SymbolPathSetting {
            path: r"C:\symbols\driver".to_string(),
            append: true,
        };
        let call = Call::new(EngineOp::OpenDump {
            path: r"C:\dumps\sample.dmp".to_string(),
        })
        .starting_with_symbols(Some(setting.clone()));
        session
            .tx
            .send(Job {
                id: OPENER_JOB,
                op: call.op,
                startup_symbol_path: call.startup_symbol_path,
                submitted: Instant::now(),
                gate: call.gate,
            })
            .expect("the pump's queue is open");

        let pumping = std::thread::spawn({
            let session = Arc::downgrade(&session);
            move || pump(session, rx, worker, waiters, Duration::from_secs(30))
        });
        let mut requests = std::io::BufReader::new(requests);
        let mut line = String::new();
        requests
            .read_line(&mut line)
            .expect("read the opener request");
        let request: WorkerRequest =
            serde_json::from_str(&line).expect("the worker request is JSON");
        assert!(request.op.is_opener());
        assert_eq!(request.startup_symbol_path, Some(setting));

        drop(session);
        pumping.join().expect("the pump stops with its session");
    }

    /// Closing is a queue operation, not a caller-side state change. Work already ahead of an
    /// `EndSession` must reach the worker, while work queued behind it must be refused even though
    /// it was submitted while the session still looked open.
    #[tokio::test]
    async fn end_session_closes_at_its_place_in_the_queue() {
        let (session, rx) = queued("sess-1", SessionState::Open);
        let waiters = Arc::clone(&session.waiters);
        let (requests, worker) = std::io::pipe().expect("a pipe to stand in for the worker's");

        let (done, answer) = oneshot::channel();
        session
            .waiters
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                3,
                Waiting {
                    done,
                    progress: None,
                    resumed: None,
                    unwound: false,
                },
            );

        // All three are submitted while the session is still open. Their order in this channel is
        // the order `pump` owns, independent of how the runtime happened to schedule their callers.
        {
            let enqueue = |id, call: Call| {
                session
                    .tx
                    .send(Job {
                        id,
                        op: call.op,
                        startup_symbol_path: call.startup_symbol_path,
                        submitted: Instant::now(),
                        gate: call.gate,
                    })
                    .expect("the pump's queue is open");
            };
            enqueue(
                1,
                Call::new(EngineOp::UnboundedCommand {
                    command: "before".to_string(),
                })
                .named(true),
            );
            enqueue(
                2,
                Call::new(EngineOp::EndSession)
                    .named(true)
                    .closing(END_SESSION_CLOSING),
            );
            enqueue(
                3,
                Call::new(EngineOp::UnboundedCommand {
                    command: "after".to_string(),
                })
                .named(true),
            );
        }

        let pumping = std::thread::spawn({
            let session = Arc::downgrade(&session);
            move || pump(session, rx, worker, waiters, Duration::from_secs(30))
        });
        let mut requests = std::io::BufReader::new(requests);
        let mut line = String::new();
        requests
            .read_line(&mut line)
            .expect("read the job ahead of the teardown");
        let before: WorkerRequest =
            serde_json::from_str(&line).expect("the first worker request is JSON");
        assert_eq!(before.id, 1);
        assert!(matches!(before.op, EngineOp::UnboundedCommand { .. }));

        line.clear();
        requests
            .read_line(&mut line)
            .expect("read the teardown request");
        let ending: WorkerRequest =
            serde_json::from_str(&line).expect("the second worker request is JSON");
        assert_eq!(ending.id, 2);
        assert!(matches!(ending.op, EngineOp::EndSession));
        assert_eq!(
            session.state(),
            SessionState::Closed(END_SESSION_CLOSING.to_string()),
            "the session must be closed before anything behind the teardown is considered"
        );

        let refused = tokio::time::timeout(Duration::from_secs(5), answer)
            .await
            .expect("the queued call behind the teardown was not answered")
            .expect("the pump dropped the queued call's answer");
        match refused {
            Err(EngineError::Stale(why)) => {
                assert!(why.contains("is closed"), "{why}");
                assert!(why.contains(END_SESSION_CLOSING), "{why}");
            }
            Err(other) => panic!("the queued call was not refused as stale: {other}"),
            Ok(_) => panic!("the queued call ran after EndSession"),
        }

        drop(session);
        pumping
            .join()
            .expect("the pump thread exits with its queue");
    }

    /// The dispatch mark is provisional, but it is still a settled state: only that exact mark may
    /// be refined with the teardown's outcome, and nothing may use the exception to resurrect or
    /// relabel a session another teardown already closed.
    #[test]
    fn an_explicit_end_refines_only_its_own_closed_state() {
        let session = dormant(
            "sess-1",
            SessionState::Closed(END_SESSION_CLOSING.to_string()),
        );
        session.finish_end("ended by end_session".to_string());
        assert_eq!(
            session.state(),
            SessionState::Closed("ended by end_session".to_string())
        );

        session.set_state(SessionState::Open);
        session.set_state(SessionState::Closed("a different close".to_string()));
        assert_eq!(
            session.state(),
            SessionState::Closed("ended by end_session".to_string()),
            "ordinary state writes must neither reopen nor relabel a settled session"
        );

        let shutdown = dormant(
            "sess-2",
            SessionState::Closed("the server is shutting down".to_string()),
        );
        shutdown.finish_end("ended by end_session".to_string());
        assert_eq!(
            shutdown.state(),
            SessionState::Closed("the server is shutting down".to_string()),
            "another teardown's reason won the race and must survive"
        );

        let failed = dormant("sess-3", SessionState::Failed("never opened".to_string()));
        failed.update_state(|_| Some(SessionState::Closed("not really".to_string())));
        assert_eq!(
            failed.state(),
            SessionState::Failed("never opened".to_string()),
            "the closed-to-closed exception must not settle a different terminal state"
        );
    }

    /// A transition that changes nothing still restamps the session — that is what `session_status`
    /// measures — but it must not put a line in the transcript.
    ///
    /// Both halves matter and they pull in opposite directions. Skipping the restamp would quietly
    /// change what `in_state_for` means, and with it the "this attach is overdue" advice built on
    /// it; recording every call would fill a file with a session repeatedly not moving, because
    /// most conditional transitions decline. `update_state` is the single funnel for all of them,
    /// so this is the one place either could go wrong.
    #[test]
    fn a_transition_that_changes_nothing_restamps_without_recording_it() {
        let path = std::env::temp_dir().join(format!(
            "windbg-mcp-engine-transitions-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let rec = crate::record::Recorder::to_file(&path, 0).expect("open a transcript");
        let session = dormant_recording("sess-1", SessionState::Opening, rec);

        session.set_state(SessionState::Attaching);
        // Let it age first. A reset is invisible from a stamp taken an instant ago — the two
        // readings would differ by the time the assertion itself took, and the test would pass
        // whether or not anything restamped.
        std::thread::sleep(Duration::from_millis(20));
        let aged = session.in_state_for();
        assert!(
            aged >= Duration::from_millis(20),
            "the baseline has to be a session that has visibly been sitting in this state"
        );
        // The same state again, which is what a milestone arriving twice would do.
        session.set_state(SessionState::Attaching);
        assert!(
            session.in_state_for() < aged,
            "a repeated transition has to restamp: `in_state_for` should have gone back down"
        );
        // And a transition that declines outright.
        session.update_state(|_| None);
        session.set_state(SessionState::Open);

        let states: Vec<String> = std::fs::read_to_string(&path)
            .expect("the transcript")
            .lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter(|r| r["event"] == "session_state")
            .filter_map(|r| r["state"].as_str().map(str::to_string))
            .collect();
        assert_eq!(
            states,
            ["attaching", "open"],
            "only the transitions that moved the session belong in the transcript"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// A long-lived child to stand in for a worker, where what is under test is which sessions own
    /// a process rather than what that process is.
    ///
    /// Under [`spawn_guard`] like every other spawn here, and for a reason these tests can hit:
    /// `cargo test` runs them as threads of one process, alongside
    /// [`a_workers_stdout_is_not_its_protocol_channel`], which marks a channel inheritable. A
    /// stand-in created inside that window would inherit the stand-in worker's message write end
    /// and hold it for its full 30 seconds — the pipe would never report EOF, and that test would
    /// fail waiting for it. The hazard is process-wide; so is the rule.
    fn stand_in_child() -> Child {
        let _one_spawn_at_a_time = spawn_guard();
        Command::new("cmd")
            .args(["/c", "ping", "-n", "30", "127.0.0.1"])
            .stdout(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn a stand-in child")
    }

    fn registry_of(sessions: &[Arc<Session>]) -> Sessions {
        let s = Sessions::new(Duration::from_secs(1));
        s.registry().all.extend(sessions.iter().cloned());
        s
    }

    #[test]
    fn an_unnamed_call_goes_to_the_newest_usable_session() {
        let older = dormant("sess-1", SessionState::Open);
        let newer = dormant("sess-2", SessionState::Open);
        let sessions = registry_of(&[older, newer]);
        assert_eq!(sessions.resolve(None).unwrap().id, "sess-2");
    }

    /// Ending the newest session must not leave the server with no default while another target
    /// is still loaded — the old design had exactly one session, so "ended" and "none" were the
    /// same thing; here they are not.
    #[test]
    fn ending_the_newest_session_falls_back_to_the_one_before_it() {
        let older = dormant("sess-1", SessionState::Open);
        let newer = dormant("sess-2", SessionState::Closed("ended".to_string()));
        let sessions = registry_of(&[older, newer]);
        assert_eq!(sessions.resolve(None).unwrap().id, "sess-1");
    }

    #[test]
    fn a_named_session_is_routed_to_regardless_of_which_is_current() {
        let mine = dormant("sess-1", SessionState::Open);
        let newer = dormant("sess-2", SessionState::Open);
        let sessions = registry_of(&[mine, newer]);
        assert_eq!(sessions.resolve(Some("sess-1")).unwrap().id, "sess-1");
    }

    /// The property process-per-session buys that the single-engine design could not: opening a
    /// second target does not disturb the first, so a handle stays good across someone else's
    /// open instead of being invalidated by it.
    #[test]
    fn a_handle_survives_another_callers_open() {
        let mine = dormant("sess-1", SessionState::Open);
        let sessions = registry_of(&[Arc::clone(&mine)]);
        assert!(sessions.resolve(Some("sess-1")).is_ok());

        sessions
            .registry()
            .all
            .push_back(dormant("sess-2", SessionState::Attaching));
        assert!(
            sessions.resolve(Some("sess-1")).is_ok(),
            "another session opening must not retire this one"
        );
    }

    #[test]
    fn an_unknown_handle_is_refused_rather_than_answered_by_the_current_session() {
        let sessions = registry_of(&[dormant("sess-1", SessionState::Open)]);
        let err = sessions.resolve(Some("sess-nope")).unwrap_err().to_string();
        assert!(err.contains("unknown session handle"), "{err}");
    }

    #[test]
    fn with_nothing_open_a_call_is_told_how_to_open_something() {
        let sessions = Sessions::new(Duration::from_secs(1));
        let err = sessions.resolve(None).unwrap_err().to_string();
        assert!(err.contains("no debug session is open"), "{err}");
        assert!(err.contains("open_dump"), "{err}");
    }

    /// Closed sessions age out; live ones never do. Forgetting a live session would report its
    /// handle as unknown, and "unknown" tells a caller to open again — which for an attach or a
    /// launch means a second target.
    #[test]
    fn closed_sessions_age_out_and_live_ones_do_not() {
        let sessions = Sessions::new(Duration::from_secs(1));
        {
            let mut registry = sessions.registry();
            registry
                .all
                .push_back(dormant("sess-live", SessionState::Attaching));
            for n in 0..(CLOSED_HISTORY + MAX_SESSIONS + 4) {
                registry.all.push_back(dormant(
                    &format!("sess-{n}"),
                    SessionState::Closed("x".into()),
                ));
            }
            registry.trim();
        }
        assert!(
            sessions.resolve(Some("sess-live")).is_ok(),
            "a live session must never be evicted"
        );
        assert!(
            sessions.registry().all.len() <= CLOSED_HISTORY + MAX_SESSIONS,
            "settled sessions should have been trimmed to the bound"
        );
    }

    /// History ages out on a client's *own* churn, not the server's. A shared bound would let a
    /// busy client evict a quiet one's settled sessions, and `session_status` would then answer
    /// "unknown" for a handle that client is still holding — the one answer that tells a caller to
    /// open again, which for an attach or a launch means a second target.
    #[tokio::test]
    async fn one_clients_history_is_not_evicted_by_anothers_churn() {
        let sessions = Sessions::new(Duration::from_secs(1));
        // Mine go in first, so they are the oldest in the deque and a single global bound would
        // reach them before it reached any of theirs.
        let mine = crate::client::as_client(crate::client::Client::new("laptop"), async {
            (0..2)
                .map(|n| dormant(&format!("mine-{n}"), SessionState::Closed("x".into())))
                .collect::<Vec<_>>()
        })
        .await;
        let theirs = crate::client::as_client(crate::client::Client::new("ci"), async {
            (0..(CLOSED_HISTORY + MAX_SESSIONS) * 3)
                .map(|n| dormant(&format!("theirs-{n}"), SessionState::Closed("x".into())))
                .collect::<Vec<_>>()
        })
        .await;
        {
            let mut registry = sessions.registry();
            for session in mine.into_iter().chain(theirs) {
                registry.all.push_back(session);
            }
            registry.trim();
        }
        let registry = sessions.registry();
        assert!(
            registry.all.iter().any(|s| s.id == "mine-0")
                && registry.all.iter().any(|s| s.id == "mine-1"),
            "another client's churn evicted this client's settled sessions, so its own history \
             aged out on someone else's activity"
        );
        assert_eq!(
            registry
                .all
                .iter()
                .filter(|s| s.owner == crate::client::Client::new("ci"))
                .count(),
            CLOSED_HISTORY + MAX_SESSIONS,
            "the busy client's own history should still be bounded"
        );
    }

    /// The bound is on *settled* sessions only: a server at the session limit with every session
    /// live keeps all of them, because there is nothing evictable.
    #[test]
    fn a_registry_of_only_live_sessions_is_never_trimmed() {
        let sessions = Sessions::new(Duration::from_secs(1));
        {
            let mut registry = sessions.registry();
            for n in 0..MAX_SESSIONS {
                registry
                    .all
                    .push_back(dormant(&format!("sess-{n}"), SessionState::Open));
            }
            registry.trim();
        }
        assert_eq!(sessions.registry().live().len(), MAX_SESSIONS);
    }

    /// A rollback promise that arrives *after* its own retraction is not reported.
    ///
    /// The two `RollingBack` messages come from different threads in the worker, so a teardown
    /// landing exactly as a batch exits can put them on the wire in either order — `read_messages`
    /// says so where it keeps the earlier deadline. Without the same defence here, the client is
    /// told the transaction is done and then told it is still unwinding, which is the one thing a
    /// narration of a call must never do.
    #[test]
    fn a_rollback_promise_that_arrives_after_its_retraction_is_not_reported() {
        let (reporter, mut reported) = crate::progress::Reporter::for_test();
        let waiters: Waiters = Arc::new(Mutex::new(HashMap::new()));
        let (tx, _caller) = oneshot::channel();
        waiters.lock().unwrap_or_else(|e| e.into_inner()).insert(
            7,
            Waiting {
                done: tx,
                progress: Some(reporter),
                resumed: None,
                unwound: false,
            },
        );

        // Out of order on purpose: the retraction first, then the promise it retracts.
        tell_rollback(&waiters, 7, Duration::ZERO);
        tell_rollback(&waiters, 7, Duration::from_secs(12));

        assert_eq!(
            reported.try_recv(),
            Ok(crate::progress::Step::Unwound),
            "the retraction is the milestone worth having"
        );
        assert!(
            reported.try_recv().is_err(),
            "a stale promise must not put the transaction back in flight"
        );
    }

    /// And in the ordinary order both are reported, because both are true in turn.
    #[test]
    fn a_rollback_reports_its_promise_and_then_its_retraction() {
        let (reporter, mut reported) = crate::progress::Reporter::for_test();
        let waiters: Waiters = Arc::new(Mutex::new(HashMap::new()));
        let (tx, _caller) = oneshot::channel();
        waiters.lock().unwrap_or_else(|e| e.into_inner()).insert(
            7,
            Waiting {
                done: tx,
                progress: Some(reporter),
                resumed: None,
                unwound: false,
            },
        );

        tell_rollback(&waiters, 7, Duration::from_secs(12));
        tell_rollback(&waiters, 7, Duration::ZERO);

        assert_eq!(
            reported.try_recv(),
            Ok(crate::progress::Step::Unwinding {
                within: Duration::from_secs(12)
            })
        );
        assert_eq!(reported.try_recv(), Ok(crate::progress::Step::Unwound));
    }

    /// A parked attach is *busy*, so it is never the session reclaimed to make room — and a
    /// caller who gave up waiting does not make it idle either, because the worker still owes a
    /// reply.
    #[tokio::test]
    async fn a_parked_session_is_never_reclaimed_to_make_room() {
        let parked = dormant("sess-parked", SessionState::Attaching);
        let idle = dormant("sess-idle", SessionState::Open);
        assert!(parked.busy(), "an attaching session is busy");
        assert!(!idle.busy(), "an open session with no calls is idle");

        // A call whose caller has given up leaves its waiter registered, which is what keeps the
        // session busy after the timeout.
        let (tx, _rx) = oneshot::channel();
        idle.waiters
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                1,
                Waiting {
                    done: tx,
                    progress: None,
                    resumed: None,
                    unwound: false,
                },
            );
        assert!(idle.busy(), "an abandoned call still owes a reply");
    }

    /// Fills the registry with `count` sessions in `state`.
    fn registry_full_of(state: SessionState) -> Sessions {
        let sessions = Sessions::new(Duration::from_secs(1));
        {
            let mut registry = sessions.registry();
            for n in 0..MAX_SESSIONS {
                registry
                    .all
                    .push_back(dormant(&format!("sess-{n}"), state.clone()));
            }
        }
        sessions
    }

    /// At the limit with nothing idle, an open is refused with the list rather than picking a
    /// victim — ending someone's live target silently is the one outcome worse than failing.
    #[test]
    fn opening_past_the_limit_with_no_idle_session_is_refused_with_the_list() {
        let sessions = registry_full_of(SessionState::Attaching);
        let err = sessions
            .take_slot()
            .err()
            .expect("no idle session means no room");
        assert!(err.contains("no room to open another"), "{err}");
        assert!(err.contains("sess-0"), "{err}");
        assert!(err.contains("end_session"), "{err}");
    }

    /// Below the limit nothing is reclaimed, however many settled sessions are remembered.
    #[tokio::test]
    async fn opening_below_the_limit_reclaims_nothing() {
        let live = dormant("sess-1", SessionState::Open);
        let sessions = registry_of(&[
            Arc::clone(&live),
            dormant("sess-0", SessionState::Closed("x".into())),
        ]);
        let slot = sessions.take_slot().expect("there is room");
        drop(slot);
        sessions.reconcile_capacity(&live);
        assert_eq!(live.state(), SessionState::Open, "it was not reclaimed");
    }

    /// **A failed open must cost nothing.** Taking a slot deliberately reclaims nothing, so a
    /// mistyped path or a worker that will not start cannot destroy a target the caller still
    /// had — the eviction is deferred until a replacement actually exists.
    #[test]
    fn a_slot_that_is_never_used_reclaims_nothing() {
        let sessions = registry_full_of(SessionState::Open);
        let before: Vec<_> = sessions.registry().live();
        let slot = sessions
            .take_slot()
            .expect("an idle session means there is room");
        assert!(
            before.iter().all(|s| s.state() == SessionState::Open),
            "no session may be touched before the replacement exists"
        );
        // The open failed on the way, so the slot goes back.
        drop(slot);
        assert_eq!(in_flight_opens(&sessions), 0);
        assert_eq!(sessions.registry().live().len(), MAX_SESSIONS);
    }

    /// Opens already in flight count against the limit. Without that the check only sees
    /// *finished* opens, so two concurrent ones look at the same sessions, both conclude there is
    /// room, and the bound is enforced against neither.
    #[test]
    fn an_open_in_flight_takes_a_slot_from_the_next_one() {
        let sessions = registry_full_of(SessionState::Open);
        // One idle session, so exactly one slot can be paid for.
        for session in sessions.registry().live().iter().skip(1) {
            session.set_state(SessionState::Attaching);
        }
        let _first = sessions
            .take_slot()
            .expect("the idle session pays for this one");
        assert_eq!(in_flight_opens(&sessions), 1);
        // Hmm — the same idle session cannot pay twice, but it is still idle, so the check has to
        // reason about the open already in flight rather than about the sessions alone.
        let second = sessions.take_slot();
        assert!(
            second.is_err(),
            "a second concurrent open must not spend the same slot"
        );
    }

    /// The session that just opened is never the one reclaimed to pay for itself, even when it is
    /// the only idle one — which it always is for a moment.
    #[tokio::test]
    async fn a_new_session_is_not_reclaimed_to_make_room_for_itself() {
        let sessions = Sessions::new(Duration::from_secs(1));
        let newest = dormant("sess-new", SessionState::Open);
        {
            let mut registry = sessions.registry();
            for n in 0..MAX_SESSIONS {
                registry
                    .all
                    .push_back(dormant(&format!("sess-busy-{n}"), SessionState::Attaching));
            }
            registry.all.push_back(Arc::clone(&newest));
        }
        sessions.reconcile_capacity(&newest);
        assert_eq!(
            newest.state(),
            SessionState::Open,
            "the new session reclaimed itself"
        );
        assert_eq!(
            sessions.registry().live().len(),
            MAX_SESSIONS + 1,
            "nothing was reclaimable, so the server sits one over the limit rather than \
             discarding a target that already opened"
        );
    }

    // ---- settling an opener whose caller stopped waiting --------------------------

    /// An opener that finishes after its caller gave up must still settle the session. Left in
    /// `Opening`/`Attaching` it would report an open that finished long ago, and `busy()` would
    /// keep the worker from ever being reclaimed.
    #[test]
    fn an_abandoned_opener_still_settles_the_session() {
        // Nothing was created, so the handle is dead and re-opening is the way forward.
        let clean = dormant("sess-1", SessionState::Opening);
        settle_open(&clean, &Err(EngineError::Debugger("no such file".into())));
        assert_eq!(clean.state(), SessionState::Failed("no such file".into()));
        assert!(!clean.busy(), "a settled session is reclaimable");

        // The target exists and the wait failed: the session stays usable, which is the whole
        // point of committing before the wait.
        let committed = dormant("sess-2", SessionState::Attaching);
        settle_open(
            &committed,
            &Err(EngineError::Debugger("never broke in".into())),
        );
        assert_eq!(committed.state(), SessionState::Open);

        let landed = dormant("sess-3", SessionState::Attaching);
        settle_open(&landed, &Ok(Output::text("vertarget")));
        assert_eq!(landed.state(), SessionState::Open);
    }

    /// A teardown that lost the race must not report a halted target.
    ///
    /// All three ways this attempt can fail are also what a *winning* concurrent teardown leaves
    /// behind: it fails our waiter out with `Lost`, or beats our clock, or leaves the engine with
    /// nothing to release and an error to say so. Warning on any of them would mean warning that
    /// a live kernel may be halted at the moment another teardown cleanly detached it.
    #[test]
    fn a_release_that_landed_elsewhere_outranks_this_attempt_failing() {
        for outcome in [
            Release::Parked {
                waited: END_SESSION_TIMEOUT,
            },
            Release::AlreadyGone,
            Release::Refused("the engine said no".to_string()),
        ] {
            assert_eq!(
                shutdown_note(&outcome, true),
                ShutdownNote::ReleasedElsewhere,
                "{outcome:?} with the target already released is not a halted-kernel warning"
            );
        }
    }

    fn parked() -> Release {
        Release::Parked {
            waited: SHUTDOWN_RELEASE_TIMEOUT,
        }
    }

    /// And with nothing else having released it, those same outcomes are the warning.
    #[test]
    fn nothing_having_released_the_target_is_what_deserves_the_warning() {
        assert!(matches!(
            shutdown_note(&parked(), false),
            ShutdownNote::Unreleased(_)
        ));
        assert!(matches!(
            shutdown_note(&Release::AlreadyGone, false),
            ShutdownNote::Unreleased(_)
        ));
        // The two say different things, because they need different investigation.
        assert_ne!(
            shutdown_note(&parked(), false),
            shutdown_note(&Release::AlreadyGone, false)
        );
        // A refusal is its own outcome: the engine answered, it just said no, and the reason is
        // the useful part.
        assert_eq!(
            shutdown_note(&Release::Refused("bad handle".to_string()), false),
            ShutdownNote::Refused("bad handle")
        );
    }

    /// The outcomes that are already unambiguous are not touched by the flag.
    #[test]
    fn a_release_this_attempt_made_reads_the_same_either_way() {
        let released = Release::Released(Box::new(Output::text("session ended")));
        // `true` is the normal case here: this very release is what set the flag.
        assert_eq!(shutdown_note(&released, true), ShutdownNote::Released);
        assert_eq!(shutdown_note(&released, false), ShutdownNote::Released);
        assert_eq!(
            shutdown_note(&Release::Stale("already closed".to_string()), false),
            ShutdownNote::Settled("already closed")
        );
    }

    /// A teardown never commits to more than one recheck at a time, however long the worker says
    /// it needs — because the answer can be revised *downwards*.
    ///
    /// A batch that finishes early retracts its bound to what the release still needs, and a wait
    /// that had already committed to the original figure could not see it: a disconnect would sit
    /// out the rest of a batch budget with no transaction left to protect. The cap is the other
    /// half — a teardown cannot be made to wait for ever by a number arriving over a pipe.
    #[test]
    fn a_teardown_never_commits_to_more_than_one_recheck() {
        let cap = Duration::from_secs(300);
        // Minutes promised, but only ever a recheck at a time.
        assert_eq!(unwind_slice(Duration::from_secs(110), cap), UNWIND_RECHECK);
        assert_eq!(
            unwind_slice(Duration::from_secs(86_400), cap),
            UNWIND_RECHECK
        );
        // Less than a recheck left to promise: wait exactly that, then look again.
        let sliver = UNWIND_RECHECK / 4;
        assert_eq!(unwind_slice(sliver, cap), sliver);
        // And the teardown's own patience bounds it, whatever the worker says.
        assert_eq!(unwind_slice(Duration::from_secs(110), sliver), sliver);
    }

    /// A release that could not start until the transaction ended gets the ordinary grace from
    /// *that* moment, rather than whatever the batch happened to leave over.
    ///
    /// The worker retracts its promise as the batch ends, which usually arrives first and makes
    /// this moot — but a batch that runs to the bound it advertised emits that retraction at the
    /// very instant the wait above stops looking for one. Resting on it winning that race would be
    /// resting on pipe scheduling, and losing means a worker killed as its release begins, which
    /// for a live kernel is the halted target this whole path exists to avoid.
    #[test]
    fn a_release_that_waited_for_a_transaction_still_gets_its_own_grace() {
        let base = SHUTDOWN_RELEASE_TIMEOUT;
        let plenty = Duration::from_secs(300);
        let now = Instant::now();

        // The transaction has just ended, so the release has its whole grace ahead of it.
        assert_eq!(release_handoff(Some(now), now, base, plenty), Some(base));

        // It ended a while ago and the release has been running since: it gets the rest, not
        // another helping. Measuring from *now* instead would hand a second grace to every
        // teardown that ever waited on a batch — which is what the retraction window used to do.
        let third = base / 3;
        assert_eq!(
            release_handoff(Some(now - third), now, base, plenty),
            Some(base - third)
        );
        assert_eq!(release_handoff(Some(now - base), now, base, plenty), None);

        // A teardown that never waited on a transaction is not lengthened by a mechanism it never
        // used: this is what keeps an ordinary disconnect costing what it always did.
        assert_eq!(release_handoff(None, now, base, plenty), None);

        // And the teardown's own patience still bounds the total.
        let sliver = base / 4;
        assert_eq!(release_handoff(Some(now), now, base, sliver), Some(sliver));
        assert_eq!(release_handoff(Some(now), now, base, Duration::ZERO), None);
    }

    /// A session that has said nothing about a transaction is never waited on for one — which is
    /// what keeps an ordinary teardown costing exactly what it always did. Only a worker that was
    /// told to unwind one ever answers, and only the teardown that told it consults this.
    #[test]
    fn a_session_with_nothing_to_unwind_asks_for_no_extension() {
        let idle = dormant("sess-idle", SessionState::Open);
        assert_eq!(idle.unwinding_for(), None);
    }

    /// What the worker promised is owed *until the moment it named*, and not a second longer.
    ///
    /// The interval it sends is measured when the teardown reaches it, and only ever shrinks after
    /// that. Read later as though it were still owed in full — which is what storing the interval
    /// rather than the deadline would do — a teardown whose release then hangs would wait out the
    /// remains of a batch budget that was spent long ago: minutes, with the defaults, for a
    /// transaction already unwound. The same reading is what makes a worker's retraction work: it
    /// names zero, and zero is instantly in the past.
    #[test]
    fn a_promise_that_has_run_out_buys_no_more_time() {
        let session = dormant("sess-1", SessionState::Open);
        let set = |deadline| *session.unwinding.lock().unwrap() = Some(deadline);

        set(Instant::now() + Duration::from_secs(30));
        let left = session
            .unwinding_for()
            .expect("a live promise is still owed");
        assert!(
            left > Duration::from_secs(25) && left <= Duration::from_secs(30),
            "owed the time remaining, not {left:?}"
        );

        // Spent, and so worth nothing — the batch's own deadline has passed.
        set(Instant::now()
            .checked_sub(Duration::from_secs(1))
            .unwrap_or_else(Instant::now));
        assert_eq!(session.unwinding_for(), None);

        // The boundary itself: a deadline of exactly now is spent, not owed.
        set(Instant::now());
        assert_eq!(session.unwinding_for(), None);
    }

    /// A rollback milestone is recorded by the thread that **reads** it, before it is handed on to
    /// be dispatched at all.
    ///
    /// That ordering is the whole guarantee. A teardown reads this once, when its grace expires,
    /// and then kills the worker; if the store happened where the message is *handled* instead, the
    /// read could miss a milestone that arrived seconds earlier but had not been dispatched — and
    /// the worker would be terminated mid-rollback for being unlucky with the runtime's scheduling.
    /// Receiving the message here is the synchronisation point: the value has to be visible to
    /// anyone who could observe the message at all.
    #[tokio::test]
    async fn a_rollback_milestone_is_recorded_where_it_arrives() {
        let (arriving, mut worker) = std::io::pipe().expect("a pipe to stand in for a worker's");
        let unwinding: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));
        let mut messages = read_messages("sess-x".to_string(), arriving, Arc::clone(&unwinding))
            .expect("start a reader");

        let line = serde_json::to_string(&WorkerMessage::RollingBack {
            id: 7,
            within_ms: 90_000,
        })
        .expect("encode a milestone");
        writeln!(worker, "{line}").expect("write it as a worker would");

        let dispatched = tokio::time::timeout(Duration::from_secs(10), messages.recv())
            .await
            .expect("the milestone reached the dispatcher within 10s");
        assert!(matches!(
            dispatched,
            Some(WorkerMessage::RollingBack { id: 7, .. })
        ));
        let by = unwinding.lock().unwrap().expect(
            "the milestone was dispatched without having been recorded, so a teardown \
                     reading it on a deadline could miss one that had already arrived",
        );
        let left = by.saturating_duration_since(Instant::now());
        assert!(
            left > Duration::from_secs(85) && left <= Duration::from_secs(90),
            "recorded as a deadline 90s out, not {left:?}"
        );

        // A retraction *replaces* it with the moment the batch ended, however long it said it
        // might need when it was told to stop. The last word wins, in both directions — and what
        // the release then gets is measured from that moment by `release_handoff`, not named here.
        let done = serde_json::to_string(&WorkerMessage::RollingBack {
            id: 7,
            within_ms: 0,
        })
        .expect("encode the retraction");
        writeln!(worker, "{done}").expect("write it as a worker would");
        tokio::time::timeout(Duration::from_secs(10), messages.recv())
            .await
            .expect("the retraction reached the dispatcher within 10s");
        let by = unwinding.lock().unwrap().expect("still recorded");
        assert!(
            by <= Instant::now(),
            "a finished transaction must not go on being waited out for the rest of its budget"
        );

        // And a promise that arrives *after* its own retraction cannot undo it. The two are
        // emitted from different threads inside the worker — the promise by its request reader,
        // the retraction by its engine thread — so a teardown landing exactly as a batch exits can
        // put them on the wire in either order. Only the earlier deadline counts, so the order
        // stops mattering.
        let stale = serde_json::to_string(&WorkerMessage::RollingBack {
            id: 7,
            within_ms: 90_000,
        })
        .expect("encode a stale promise");
        writeln!(worker, "{stale}").expect("write it as a worker would");
        tokio::time::timeout(Duration::from_secs(10), messages.recv())
            .await
            .expect("the stale promise reached the dispatcher within 10s");
        assert_eq!(
            *unwinding.lock().unwrap(),
            Some(by),
            "a promise overtaken by its own retraction would have a teardown wait out a batch \
             budget that is already spent"
        );
    }

    /// A log record is **filed** against its session rather than dispatched, and a worker whose
    /// consumer has gone is failed **fast** rather than blocked.
    ///
    /// The second is the one with teeth, and it is not about the log. Every message a worker sends
    /// goes through one lock (`worker::emit`), held across the write. If a departed consumer left a
    /// pipe that was merely *full*, a background writer could hold that lock indefinitely — and the
    /// release a worker's EOF asks for, bounded by [`ABRUPT_EXIT_RELEASE`], would never get a
    /// message out. For a live kernel that is a target left halted because the supervisor stopped
    /// listening.
    ///
    /// It cannot happen, and this is why: the reader thread owns the read end, so the moment it
    /// stops reading it *closes* it, and the worker's next write errors instead of waiting. That is
    /// one line of `read_messages` — `break` versus carrying on — and the safe answer is the
    /// unobvious one, which is what makes it worth pinning. Written as "more than any pipe can
    /// hold, with the consumer gone": against a reader that stalled instead of stopping, the writes
    /// would never return.
    #[test]
    fn the_channel_fails_a_worker_fast_when_nobody_is_left() {
        let (arriving, mut worker) = std::io::pipe().expect("a pipe to stand in for a worker's");
        // A session id nothing else uses: the ring this files into is process-wide, and the whole
        // test suite logs into it.
        let session = "sess-drain-to-eof";
        let messages = read_messages(
            session.to_string(),
            arriving,
            Arc::new(Mutex::new(None::<Instant>)),
        )
        .expect("start a reader");

        let log = serde_json::to_string(&WorkerMessage::Log {
            at_ms: 1_700_000_000_000,
            level: crate::logbridge::Level::Warn,
            target: "windbg_mcp::worker".to_string(),
            message: "worker: something worth reading".to_string(),
            dropped: 0,
        })
        .expect("encode a log record");
        writeln!(worker, "{log}").expect("write it as a worker would");

        let query = || crate::logbridge::Query {
            // The test reads the ring directly, as the supervisor does: no client, nothing to
            // narrow to.
            visible: None,
            session: Some(session.to_string()),
            level: crate::logbridge::Level::Trace,
            since: None,
            limit: 10,
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        let filed = loop {
            let tail = crate::logbridge::tail(&query());
            if let Some(entry) = tail.entries.first() {
                break entry.clone();
            }
            assert!(
                Instant::now() < deadline,
                "a worker's log record never reached the ring, so `server_log` would show nothing \
                 of what that worker said"
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(filed.message, "worker: something worth reading");
        assert_eq!(
            filed.session.as_deref(),
            Some(session),
            "filed against the session whose worker sent it — the one thing the worker could not \
             stamp it with"
        );

        // Nobody is left to route to.
        drop(messages);

        // Comfortably more than any pipe buffer, in lines a real worker could send. Written from a
        // thread of its own so a write that never returns fails this test rather than hanging it.
        let bulk = serde_json::to_string(&WorkerMessage::Fatal {
            message: "x".repeat(8192),
        })
        .expect("encode a message");
        let (wrote, written) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut sent = 0usize;
            let outcome = loop {
                if sent == 256 {
                    break Ok(sent);
                }
                if let Err(e) = writeln!(worker, "{bulk}") {
                    break Err((sent, e.kind()));
                }
                sent += 1;
            };
            let _ = wrote.send(outcome);
        });
        let outcome = written.recv_timeout(Duration::from_secs(20)).expect(
            "a worker writing to a channel nobody is routing blocked inside its write — which in a \
             real worker is `emit`, holding the lock its teardown needs to report a release",
        );
        // And it is an *error*, not 2MB into a void: the read end is gone, which is the property
        // that makes the block above impossible rather than merely unlikely.
        let (sent, kind) = match outcome {
            Err(refused) => refused,
            Ok(sent) => panic!(
                "all {sent} line(s) went through, so the reader was still draining a channel it \
                 had stopped routing — one step from the stall this test exists to rule out"
            ),
        };
        assert!(
            sent < 256,
            "the writer should have been refused before it finished, not after"
        );
        assert!(
            matches!(
                kind,
                std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionAborted
            ),
            "expected the closed read end to refuse the write, got {kind:?} after {sent} line(s)"
        );
    }

    /// The gap `admit` exists to close: a worker that finishes its handshake after the client has
    /// gone must never be registered.
    ///
    /// `take_slot` let this open through while the connection was alive, and it then spent a whole
    /// worker handshake — up to `WORKER_READY_TIMEOUT`, against a `SHUTDOWN_RELEASE_TIMEOUT` of
    /// five seconds — before reaching this point. Registering now would send it an opener, and for
    /// a kernel attach that commits, the process would exit with a target halted.
    #[tokio::test]
    async fn a_worker_that_comes_up_after_the_client_has_gone_is_not_registered() {
        let sessions = Sessions::new(Duration::from_secs(1));
        // Nothing to release, so this is the whole of shutdown: close the gate.
        sessions.shutdown().await;

        let late = dormant("sess-late", SessionState::Opening);
        let refused = sessions
            .admit(&late)
            .expect_err("a worker that came up after the disconnect must be refused");
        assert!(
            refused.contains("shutting down"),
            "the refusal has to say why: {refused}"
        );
        assert!(
            sessions.registry().all.is_empty(),
            "a refused worker must leave nothing behind for `owning_workers` to have missed"
        );
    }

    /// And the ordinary path still registers, which is what makes the refusal above a gate rather
    /// than a wall.
    #[tokio::test]
    async fn a_worker_that_comes_up_on_a_live_connection_is_registered() {
        let sessions = Sessions::new(Duration::from_secs(1));
        let session = dormant("sess-1", SessionState::Opening);
        sessions.admit(&session).expect("a live connection admits");
        assert_eq!(
            sessions
                .registry()
                .all
                .iter()
                .map(|s| s.id.as_str())
                .collect::<Vec<_>>(),
            vec!["sess-1"]
        );
    }

    /// Shutdown is keyed on owning a worker, not on being live.
    ///
    /// A session claimed for reclamation is `Closed` immediately while its release runs in the
    /// background. A disconnect landing in that window must still collect it: otherwise the
    /// runtime is dropped, the release is cancelled, and the worker is left to notice its request
    /// channel close and let go on its own — best effort, when the orderly `EndSession` a halted
    /// kernel wants was available.
    #[tokio::test]
    async fn shutdown_collects_a_session_whose_release_is_still_in_flight() {
        let sessions = Sessions::new(Duration::from_secs(1));
        let reclaimed = dormant("sess-reclaimed", SessionState::Open);
        // A stand-in for the worker: any child process will do, since what is under test is
        // which sessions the registry hands to shutdown, not what the process is.
        let child = stand_in_child();
        *reclaimed.child.lock().unwrap() = Some(child);
        // Claimed for reclamation: closed already, release still to come.
        reclaimed.set_state(SessionState::Closed("reclaimed".to_string()));
        sessions.registry().all.push_back(Arc::clone(&reclaimed));

        assert!(
            sessions.registry().live().is_empty(),
            "a claimed victim is not live, which is why keying shutdown on `live` missed it"
        );
        assert_eq!(
            sessions
                .registry()
                .owning_workers()
                .iter()
                .map(|s| s.id.as_str())
                .collect::<Vec<_>>(),
            vec!["sess-reclaimed"],
            "it still owns a worker, so shutdown has to collect it"
        );

        // And once the worker is gone there is nothing left to collect.
        reclaimed.kill();
        assert!(sessions.registry().owning_workers().is_empty());
    }

    /// History eviction must not forget a session whose worker is still being released.
    ///
    /// A reclaimed session is `Closed` at once and released in the background. Evicting it in that
    /// window takes it out of `owning_workers`, so a disconnect no longer finds it, the release is
    /// cancelled with the runtime, and the worker is left to let go on its own instead of being
    /// asked — the weaker guarantee, for the target that can least afford it.
    #[tokio::test]
    async fn history_eviction_keeps_a_session_that_still_owns_a_worker() {
        let sessions = Sessions::new(Duration::from_secs(1));
        let releasing = dormant(
            "sess-releasing",
            SessionState::Closed("reclaimed".to_string()),
        );
        let child = stand_in_child();
        *releasing.child.lock().unwrap() = Some(child);
        {
            let mut registry = sessions.registry();
            registry.all.push_back(Arc::clone(&releasing));
            // Far past the history bound, so trimming has every reason to take it.
            for n in 0..(CLOSED_HISTORY + MAX_SESSIONS) * 2 {
                registry.all.push_back(dormant(
                    &format!("sess-{n}"),
                    SessionState::Closed("x".into()),
                ));
            }
            registry.trim();
        }
        assert!(
            sessions
                .registry()
                .owning_workers()
                .iter()
                .any(|s| s.id == "sess-releasing"),
            "a session mid-release was evicted, so shutdown could no longer find its worker"
        );
        releasing.kill();
    }

    /// A retired handle must not be mistaken for a committed target.
    ///
    /// When a target-changing command is queued behind an opener that has not created anything
    /// yet, `pump` retires the session while the phase is still `Started`. `Retired` is live, so
    /// reading commitment off the state would call that a post-commit failure and tell the caller
    /// their session exists and not to re-open — for an open that created nothing. That is the
    /// exact false claim `post_commit_failure` documents as unreachable.
    ///
    /// The worker still goes untouched, though: the queued command has taken it over and may be
    /// about to give it a target of its own.
    #[test]
    fn a_retirement_is_not_mistaken_for_a_created_target() {
        let retired = dormant(
            "sess-1",
            SessionState::Retired("`.opendump` queued behind the open".to_string()),
        );
        // The state says live, the phase says nothing was created. The phase is the truth.
        retired
            .phase
            .store(OpenPhase::Started as u8, Ordering::Release);
        assert!(!retired.phase().committed());

        let live = settle_open(&retired, &Err(EngineError::Debugger("no target".into())));
        assert!(
            matches!(retired.state(), SessionState::Retired(_)),
            "the worker belongs to the queued command now, so it is not ours to fail or kill"
        );
        assert!(live, "it still holds a worker, so it still owes its slot");

        // Without a retirement in the way, the same failure ends the session and its worker.
        let plain = dormant("sess-2", SessionState::Opening);
        assert!(!settle_open(
            &plain,
            &Err(EngineError::Debugger("no such file".into()))
        ));
        assert_eq!(plain.state(), SessionState::Failed("no such file".into()));
    }

    /// Settling is idempotent and never resurrects: a session ended while its opener was still
    /// running stays ended.
    #[test]
    fn settling_never_reopens_a_session_that_is_already_over() {
        let closed = dormant("sess-1", SessionState::Closed("ended".into()));
        assert!(!settle_open(&closed, &Ok(Output::text("vertarget"))));
        assert_eq!(closed.state(), SessionState::Closed("ended".into()));
    }

    /// Whether a settled opener still owes its slot is exactly whether it left a live session —
    /// that is what tells the caller to reconcile capacity, and a wrong answer here either leaks
    /// a slot or reclaims a session nothing paid for.
    #[test]
    fn settling_reports_whether_the_session_survived() {
        let kept = dormant("sess-1", SessionState::Attaching);
        assert!(
            settle_open(&kept, &Err(EngineError::Debugger("never broke in".into()))),
            "the target exists, so the session lives and owes its slot"
        );
        let lost = dormant("sess-2", SessionState::Opening);
        assert!(
            !settle_open(&lost, &Err(EngineError::Debugger("no such file".into()))),
            "nothing was created, so there is no session to pay for"
        );
    }

    // ---- reconciling capacity -----------------------------------------------------

    /// An opener finishing must not undo a retirement that happened while it ran.
    ///
    /// A target-changing `execute` can be queued behind an open, and `pump` retires the session
    /// as it forwards that command — before the worker has run it, and possibly before the opener
    /// has even answered. Normalising the session back to `Open` afterwards would leave the handle
    /// certifying a target the queued command is about to replace, which is the one thing the
    /// handle is supposed to make impossible.
    #[test]
    fn an_opener_that_finishes_does_not_un_retire_its_session() {
        let retired = dormant(
            "sess-1",
            SessionState::Retired("`.opendump` queued behind the open".to_string()),
        );
        promote_opened(&retired);
        assert!(
            matches!(retired.state(), SessionState::Retired(_)),
            "retirement outranks the opener's normalisation, got {:?}",
            retired.state()
        );

        // The states it *is* for.
        for state in [SessionState::Opening, SessionState::Attaching] {
            let opening = dormant("sess-2", state.clone());
            promote_opened(&opening);
            assert_eq!(opening.state(), SessionState::Open, "from {state:?}");
        }

        // And it never resurrects a settled one.
        let closed = dormant("sess-3", SessionState::Closed("ended".to_string()));
        promote_opened(&closed);
        assert_eq!(closed.state(), SessionState::Closed("ended".to_string()));
    }

    /// Reclaims *until* the server is back at the limit, not once per call — and does the
    /// claiming **synchronously**, which is the half that keeps the accounting honest.
    ///
    /// An overage can outlive the open that caused it — if every candidate was busy at the time,
    /// the debt is still owed once they go idle. Taking one victim per open would carry it
    /// forever: six live sessions would become five on the next open, then six, then five.
    ///
    /// That the count is already correct when this returns is the point of claiming before
    /// spawning the releases: a concurrent open would otherwise still see the victims as live and
    /// idle, count them as capacity a second time, and admit itself on room that was already
    /// spent — only to be reclaimed by this reconciliation moments later, handing its caller a
    /// `session_id` that was stale on arrival.
    #[tokio::test]
    async fn reclaiming_clears_the_whole_overage_not_one_session_per_open() {
        let sessions = Sessions::new(Duration::from_secs(1));
        let keeping = dormant("sess-keep", SessionState::Open);
        {
            let mut registry = sessions.registry();
            for n in 0..MAX_SESSIONS + 2 {
                registry
                    .all
                    .push_back(dormant(&format!("sess-{n}"), SessionState::Open));
            }
            registry.all.push_back(Arc::clone(&keeping));
        }
        assert_eq!(sessions.registry().live().len(), MAX_SESSIONS + 3);

        sessions.reconcile_capacity(&keeping);

        assert_eq!(
            sessions.registry().live().len(),
            MAX_SESSIONS,
            "the whole overage should be cleared in one pass"
        );
        assert_eq!(
            keeping.state(),
            SessionState::Open,
            "the session being kept is never a victim"
        );
    }

    /// A session that has opened but whose caller has not been told about it yet must not be
    /// reclaimed, however idle it looks.
    ///
    /// It goes idle the moment its opener's waiter is removed, which is *before* `open` returns
    /// the handle. With two opens admitted at the limit, the later one's reconciliation would
    /// otherwise pick the earlier one — and that caller would be handed a `session_id` that was
    /// already `Closed`.
    #[tokio::test]
    async fn a_session_not_yet_handed_to_its_caller_is_never_reclaimed() {
        let sessions = Sessions::new(Duration::from_secs(1));
        let undelivered = dormant("sess-just-opened", SessionState::Open);
        undelivered.delivered.store(false, Ordering::Release);
        let keeping = dormant("sess-keep", SessionState::Open);
        {
            let mut registry = sessions.registry();
            for n in 0..MAX_SESSIONS - 1 {
                registry
                    .all
                    .push_back(dormant(&format!("sess-busy-{n}"), SessionState::Attaching));
            }
            registry.all.push_back(Arc::clone(&undelivered));
            registry.all.push_back(Arc::clone(&keeping));
        }
        assert!(
            undelivered.busy(),
            "an undelivered session counts as in flight"
        );

        sessions.reconcile_capacity(&keeping);

        assert_eq!(
            undelivered.state(),
            SessionState::Open,
            "the session whose caller is still waiting for its handle was reclaimed"
        );

        // Once its caller has it, it is an ordinary idle session and can pay for the next open.
        undelivered.delivered.store(true, Ordering::Release);
        assert!(!undelivered.busy());
        sessions.reconcile_capacity(&keeping);
        assert!(!undelivered.state().is_live(), "now it is reclaimable");
    }

    /// Busy sessions are still never taken, so an overage that cannot be paid for is left
    /// standing rather than settled by ending someone's live target.
    #[tokio::test]
    async fn reclaiming_leaves_an_overage_it_cannot_pay_for() {
        let sessions = Sessions::new(Duration::from_secs(1));
        let keeping = dormant("sess-keep", SessionState::Open);
        {
            let mut registry = sessions.registry();
            for n in 0..MAX_SESSIONS {
                registry
                    .all
                    .push_back(dormant(&format!("sess-busy-{n}"), SessionState::Attaching));
            }
            registry.all.push_back(Arc::clone(&keeping));
        }
        sessions.reconcile_capacity(&keeping);
        assert_eq!(
            sessions.registry().live().len(),
            MAX_SESSIONS + 1,
            "nothing was reclaimable, so the overage stands"
        );
    }

    /// The 32-bit worker is looked for **inside** `x86\`, and only when the engine it would load
    /// is there too.
    ///
    /// Both halves matter and only one of them is obvious. The subdirectory is the loader's own
    /// rule turned into the mechanism; the `dbgeng.dll` check is what keeps a half-populated
    /// `x86\` out of the spawn path, because an image with no engine beside it fails *before*
    /// `main` and there is no Rust left to report it.
    #[test]
    fn a_32_bit_worker_needs_its_engine_beside_it() {
        let dir = tempdir();
        let exe = dir.join("windbg-mcp.exe");
        std::fs::write(&exe, b"").expect("a stand-in server image");
        assert_eq!(x86_worker_image(&exe), None, "nothing is there yet");

        let x86 = dir.join("x86");
        std::fs::create_dir_all(&x86).expect("an x86 directory");
        let worker = x86.join("windbg-mcp.exe");
        std::fs::write(&worker, b"").expect("a stand-in 32-bit worker");
        assert_eq!(
            x86_worker_image(&exe),
            None,
            "a worker with no engine beside it would fail in the loader, not in this server"
        );

        std::fs::write(x86.join("dbgeng.dll"), b"").expect("a stand-in engine");
        assert_eq!(x86_worker_image(&exe), Some(worker));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A renamed running image still finds the released worker name.
    ///
    /// This is the `.stale` rebuild dance: the supervisor is executing `windbg-mcp.exe.stale`, so
    /// its own file name names nothing under `x86\`. Falling back to the released name is what
    /// keeps a 32-bit dump routed during it — and the order matters the other way round too, so a
    /// worker named after *this* build is preferred to one that merely shares the release's name.
    #[test]
    fn a_renamed_supervisor_still_finds_the_released_worker() {
        let dir = tempdir();
        let x86 = dir.join("x86");
        std::fs::create_dir_all(&x86).expect("an x86 directory");
        std::fs::write(x86.join("dbgeng.dll"), b"").expect("a stand-in engine");
        let released = x86.join("windbg-mcp.exe");
        std::fs::write(&released, b"").expect("a stand-in 32-bit worker");

        let stale = dir.join("windbg-mcp.exe.stale");
        assert_eq!(x86_worker_image(&stale), Some(released));

        let named = x86.join("windbg-mcp.exe.stale");
        std::fs::write(&named, b"").expect("a matching 32-bit worker");
        assert_eq!(
            x86_worker_image(&stale),
            Some(named),
            "a worker named after this build wins over one named after the release"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Only a 32-bit user-mode target is offered a second image, and the list is never empty.
    ///
    /// The negative half is the one worth pinning: a kernel dump is a different format entirely
    /// (`PAGEDU64`), has no CLR in it, and is read by this build's engine whatever architecture it
    /// was captured on — so routing one at a 32-bit worker would trade a working session for a
    /// broken one. The samples are checked in, which is what lets this assert against real files.
    ///
    /// The **live process** here is this test binary, which is this build's own architecture by
    /// construction: whatever that is, it is not a reason to start a second image. A process that
    /// *is* 32-bit is `a_wow64_process_is_read_as_x86` in `crate::target`, one layer down, and
    /// the tool-surface end of it is the 32-bit tier in `tests/mcp_smoke.rs`.
    #[test]
    fn only_a_32_bit_user_target_asks_for_another_image() {
        let samples = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/samples");
        for entry in std::fs::read_dir(&samples).expect("the sample directory is checked in") {
            let path = entry.expect("a readable directory entry").path();
            if path.extension().is_none_or(|e| e != "dmp") {
                continue;
            }
            let images = worker_images(Some(&crate::target::Opening::Dump(path.clone())))
                .expect("this executable can locate itself");
            assert_eq!(
                images.len(),
                1,
                "{} is a kernel dump and must stay on this build's worker",
                path.display()
            );
        }
        assert_eq!(
            worker_images(Some(&crate::target::Opening::Process(std::process::id())))
                .expect("this executable can locate itself")
                .len(),
            1,
            "this test binary is this build's own architecture, so it wants no second image"
        );
        assert_eq!(
            worker_images(None)
                .expect("this executable can locate itself")
                .len(),
            1,
            "a worker told nothing (a kernel attach, a trace, a launch) has one image, this one"
        );
    }

    /// A message this build cannot read ends the handshake at once, instead of being dropped and
    /// waited out.
    ///
    /// The input is the shape that made this reachable: a worker old enough to serialize `Ready`
    /// as the bare string — its unit form, before the variant carried a build identity. No release
    /// ever shipped an image that does that, so this exact line cannot arrive from one; what can,
    /// once a session may be served by a *second* image, is any stale `x86\windbg-mcp.exe` whose
    /// `WorkerMessage` is a version behind. Every one of those lands here, and dropping it costs
    /// the caller the whole of `WORKER_READY_TIMEOUT` in silence before the fallback.
    #[test]
    fn a_worker_this_build_cannot_read_is_reported_rather_than_ignored() {
        let (reader, mut writer) = std::io::pipe().expect("a pipe");
        let mut messages = read_messages("test".to_string(), reader, Arc::new(Mutex::new(None)))
            .expect("a reader thread");
        writeln!(writer, "\"Ready\"").expect("a line the supervisor cannot read");
        drop(writer);

        match messages.blocking_recv() {
            Some(WorkerMessage::Fatal { message }) => assert!(
                message.contains("different build"),
                "the reason has to name the cause, or an operator is left with a parse error: \
                 {message}"
            ),
            other => panic!("expected a Fatal naming the mismatch, got {other:?}"),
        }
    }

    /// A scratch directory of this test binary's own, removed by the test that made it.
    fn tempdir() -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "windbg-mcp-images-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        dir
    }
}
