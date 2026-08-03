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
//!   (win-kexp's `SetInterrupt` watchdog cannot reach a wait that is still establishing the
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
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::{mpsc, oneshot};

use crate::proto::{EngineOp, WorkerMessage, WorkerRequest};
use crate::worker::WORKER_FLAG;

/// How many sessions may be open at once.
///
/// Each is a process holding a dump, a trace, or a live target, so this is a real resource
/// bound, not a policy. Four is enough for the workflows that motivated concurrency at all
/// (triage a crash dump while a kernel attach is live; compare two traces) and small enough that
/// a client leaking sessions notices.
pub const MAX_SESSIONS: usize = 4;

/// How many *closed* sessions to remember, so `session_status` can still answer for a handle
/// after its target is gone. Live sessions are never evicted, whatever this says.
const CLOSED_HISTORY: usize = 8;

/// How long to wait for a freshly spawned worker to report [`WorkerMessage::Ready`]. This covers
/// process creation and `DebugCreate`, nothing else — a worker that is slower than this is not
/// going to become usable.
const WORKER_READY_TIMEOUT: Duration = Duration::from_secs(30);

/// How long `end_session` gives the worker to release its target cleanly before the process is
/// killed instead.
///
/// It is a bound on *politeness*, not on the teardown: the session ends either way. Long enough
/// that a live target with real teardown work (a detach that has to resume threads) finishes
/// gracefully, short enough that recovering a parked attach is not a wait.
const END_SESSION_TIMEOUT: Duration = Duration::from_secs(20);

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
const SHUTDOWN_RELEASE_TIMEOUT: Duration = Duration::from_secs(5);

/// `CREATE_NEW_PROCESS_GROUP`, which every worker is spawned with.
///
/// An interactive Ctrl+C is delivered to *every* process attached to the console, and a child
/// inherits its parent's process group — so without this a worker takes the default console
/// handler and terminates on the spot, before its stdin closes and before it can release its
/// target. That is precisely the halted kernel this design exists to avoid, arriving by the one
/// route where the supervisor cannot help: its own default handler ends it, so it never reaches
/// [`Sessions::shutdown`].
///
/// With the flag, Ctrl+C is disabled for the worker's group. The supervisor still dies, its handles
/// still close, and the worker meets the EOF path that knows how to let go.
const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;

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
#[derive(Debug)]
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
            Self::Debugger(m) | Self::Timeout(m) | Self::Stale(m) | Self::Lost(m) => f.write_str(m),
        }
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

    /// Whether the session still owns a worker process.
    pub fn is_live(&self) -> bool {
        !matches!(self, Self::Failed(_) | Self::Closed(_))
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
    /// How far the opener got, as [`OpenPhase`]. Separate from the state on purpose.
    phase: AtomicU8,
    child: Mutex<Option<Child>>,
}

type Waiters = Arc<Mutex<HashMap<u64, oneshot::Sender<Result<String, EngineError>>>>>;

impl Session {
    fn state(&self) -> SessionState {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .0
            .clone()
    }

    /// Moves the session to `next` and restamps it. Refuses to resurrect a session that has
    /// already stopped owning a worker, so a milestone arriving from a worker being torn down
    /// cannot undo the teardown.
    fn set_state(&self, next: SessionState) {
        self.update_state(|_| Some(next));
    }

    /// Recomputes the state *from itself*, under a single lock acquisition, and reports where it
    /// ended up. `next` returns `None` to leave it alone.
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
        let mut slot = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if !slot.0.is_live() {
            return slot.0.clone();
        }
        if let Some(next) = next(&slot.0) {
            *slot = (next, Instant::now());
        }
        slot.0.clone()
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
    fn busy(&self) -> bool {
        !self.delivered.load(Ordering::Acquire)
            || !self
                .waiters
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty()
            || matches!(
                self.state(),
                SessionState::Opening | SessionState::Attaching
            )
    }

    /// Answers every outstanding call with `why`. Used when the worker dies or is killed: those
    /// callers are waiting on a reply that is never coming.
    fn fail_outstanding(&self, why: &str) {
        let waiters: Vec<_> = self
            .waiters
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain()
            .map(|(_, tx)| tx)
            .collect();
        for tx in waiters {
            let _ = tx.send(Err(EngineError::Lost(why.to_string())));
        }
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
}

impl Gate {
    /// Whether the session in `state` may still run this call.
    fn admits(&self, state: &SessionState) -> bool {
        match self.on {
            On::Handle => state.accepts_handle(),
            On::Default => state.accepts_default(),
            On::Supervisor => true,
        }
    }
}

/// A call to run against a session.
pub struct Call {
    op: EngineOp,
    gate: Gate,
}

impl Call {
    /// A call the caller did not attach a handle to.
    pub fn new(op: EngineOp) -> Self {
        Self {
            op,
            gate: Gate {
                on: On::Default,
                retires: None,
            },
        }
    }

    /// Records whether the caller supplied `session_id`; see [`On`].
    pub fn named(mut self, named: bool) -> Self {
        self.gate.on = if named { On::Handle } else { On::Default };
        self
    }

    /// Marks this call as one that can replace or release the target, retiring the handle before
    /// it runs.
    pub fn retiring(mut self, why: impl Into<String>) -> Self {
        self.gate.retires = Some(why.into());
        self
    }

    /// The supervisor's own teardown; see [`On::Supervisor`].
    fn supervisor(op: EngineOp) -> Self {
        Self {
            op,
            gate: Gate {
                on: On::Supervisor,
                retires: None,
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
}

// ---- outcomes of an open --------------------------------------------------

pub struct OpenReport {
    pub id: String,
    pub report: String,
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
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut registry = self.registry.lock().unwrap_or_else(|e| e.into_inner());
        registry.opening = registry.opening.saturating_sub(1);
    }
}

/// How a worker took being told to let go of its target.
enum Release {
    /// It released the target and said so.
    Released(String),
    /// It never answered inside [`END_SESSION_TIMEOUT`] and was killed. The case this whole
    /// design is for.
    Parked,
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
    opening: usize,
    /// Set once the client has disconnected. Refuses new opens, so the set of workers to release
    /// stops growing while shutdown is walking it.
    closing: bool,
}

impl Registry {
    /// The session a call that names none is routed to: the newest that still accepts one.
    ///
    /// Computed rather than stored, so ending the newest session falls back to the one before it
    /// instead of leaving the server with no default while a perfectly good target is loaded.
    fn current(&self) -> Option<Arc<Session>> {
        self.all
            .iter()
            .rev()
            .find(|s| s.state().accepts_default())
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

    /// Sessions that still have a worker process, whatever their state says.
    ///
    /// Not the same set as [`Self::live`], and shutdown needs this one. A session claimed for
    /// reclamation is marked `Closed` immediately but its worker is released in the background, so
    /// between those two points it is not live and still owns a process — and a client
    /// disconnecting in that window would drop the runtime and cancel that release, leaving the
    /// worker to fall back on noticing its own stdin close: a bounded best effort, where an
    /// orderly `EndSession` was there for the asking.
    fn owning_workers(&self) -> Vec<Arc<Session>> {
        self.all
            .iter()
            .filter(|s| s.child.lock().unwrap_or_else(|e| e.into_inner()).is_some())
            .cloned()
            .collect()
    }

    /// Drops the oldest settled sessions once the history bound is exceeded. Live sessions are
    /// never evicted — forgetting one would report its handle as unknown, and the advice that
    /// follows from "unknown" is "open again", which for an attach or a launch means a second
    /// target.
    ///
    /// Nor is one that still owns a worker, whatever its state says. A session claimed for
    /// reclamation is `Closed` at once and released in the background, and evicting it in that
    /// window would take it out of [`Self::owning_workers`] — so a disconnect would no longer find
    /// it, the release would be cancelled with the runtime, and the worker would be left to let go
    /// on its own rather than being asked properly, which is the weaker of the two guarantees a
    /// halted kernel can be given.
    fn trim(&mut self) {
        while self.all.len() > CLOSED_HISTORY + MAX_SESSIONS {
            let evictable = self.all.iter().position(|s| {
                !s.state().is_live() && s.child.lock().unwrap_or_else(|e| e.into_inner()).is_none()
            });
            let Some(oldest_settled) = evictable else {
                return;
            };
            self.all.remove(oldest_settled);
        }
    }
}

/// The session registry: what [`crate::server`] holds instead of an engine handle.
#[derive(Clone)]
pub struct Sessions {
    inner: Arc<Mutex<Registry>>,
    call_timeout: Duration,
}

impl Sessions {
    /// Creates an empty registry. No process is started until something is opened, so a server
    /// that is only ever asked for `tools/list` never loads DbgEng at all.
    pub fn new(call_timeout: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Registry::default())),
            call_timeout,
        }
    }

    fn registry(&self) -> std::sync::MutexGuard<'_, Registry> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Routes a call to the session the caller named, or to the current one.
    ///
    /// This is where a stale handle is refused. It is *not* the whole check — the session can
    /// still be retired between here and the worker — which is why [`Gate`] repeats it at the
    /// front of the queue.
    pub fn resolve(&self, supplied: Option<&str>) -> Result<Arc<Session>, EngineError> {
        let registry = self.registry();
        let Some(want) = supplied else {
            return registry.current().ok_or_else(|| {
                EngineError::Stale(
                    "no debug session is open. Start one with open_dump / open_trace / \
                     attach_process / attach_kernel / attach_kernel_local / launch."
                        .to_string(),
                )
            });
        };
        match registry.find(want) {
            Some(session) if session.state().accepts_handle() => Ok(session),
            Some(session) => Err(EngineError::Stale(stale_handle(want, &session.state()))),
            None => Err(EngineError::Stale(format!(
                "unknown session handle `{want}`: this server is not holding it. Either it was \
                 never issued here, or it closed a while ago and has aged out of the session \
                 history. A session still in flight is never forgotten, so opening again is safe."
            ))),
        }
    }

    /// Every session, newest first, as `session_status` reports them.
    pub fn snapshot(&self) -> Vec<SessionSnapshot> {
        let registry = self.registry();
        let current = registry.current().map(|s| s.id.clone());
        registry
            .all
            .iter()
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
            })
            .collect()
    }

    /// Runs `call` against `session`, awaiting the result with the configured timeout.
    pub async fn call(&self, session: &Arc<Session>, call: Call) -> Result<String, EngineError> {
        self.call_within(session, call, self.call_timeout).await
    }

    async fn call_within(
        &self,
        session: &Arc<Session>,
        call: Call,
        budget: Duration,
    ) -> Result<String, EngineError> {
        let id = session.next_id.fetch_add(1, Ordering::Relaxed);
        self.call_as(session, call, budget, id).await
    }

    /// [`Self::call_within`] with the job id chosen by the caller, which only the opener does —
    /// see [`OPENER_JOB`].
    async fn call_as(
        &self,
        session: &Arc<Session>,
        call: Call,
        budget: Duration,
        id: u64,
    ) -> Result<String, EngineError> {
        let (tx, rx) = oneshot::channel();
        // Registered before the job is queued, so the session counts as busy from the moment the
        // call is submitted rather than from the moment it is written to the worker.
        //
        // Under the *registry* lock, which is not this map's lock and is not about this map: it is
        // what `claim_overage_victim` holds while it decides a session is idle and closes it.
        // Without taking it here, a call could become in-flight in the gap between that decision
        // and the close, and reclamation would then end a session the caller had just started
        // using. Held only across the insert; the send below is outside it.
        {
            let _reclamation = self.registry();
            session
                .waiters
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(id, tx);
        }
        let queued = session.tx.send(Job {
            id,
            op: call.op,
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
        match tokio::time::timeout(budget, rx).await {
            Ok(Ok(result)) => result,
            // The sender is dropped only when the worker's reader gives up on it, which it does
            // by answering first — so this is the residual case, not the normal one.
            Ok(Err(_)) => Err(EngineError::Lost(worker_gone(&session.id))),
            // A timeout is an operational outcome, not broken plumbing: the target may simply
            // still be running. Note the job itself is *not* cancelled — only this wait for it.
            Err(_) => Err(EngineError::Timeout(format!(
                "engine call timed out (the target may still be running). The session `{}` is \
                 still holding this call; `session_status` reports it, and `end_session` ends it \
                 outright — including by terminating the worker process if it will not unwind.",
                session.id
            ))),
        }
    }

    /// Opens a target in a fresh worker process.
    pub async fn open(
        &self,
        kind: SessionKind,
        what: String,
        op: EngineOp,
    ) -> Result<OpenReport, OpenError> {
        debug_assert!(op.is_opener(), "open() needs an opener op");
        // Take a slot before doing anything expensive, but do **not** reclaim anything yet — see
        // `take_slot` and `reconcile_capacity` for why those are separate.
        let slot = self.take_slot().map_err(OpenError::NoRoom)?;

        let id = mint_session_id();
        let session = match self.spawn(&id, kind, what).await {
            Ok(session) => session,
            // The slot goes back and no existing session was touched: a worker that would not
            // start must not cost the caller a target they already had.
            Err(why) => return Err(OpenError::Unavailable(why)),
        };
        if let Err(why) = self.admit(&session) {
            // Refused *before* the opener was written, so this worker is `Ready` and holds
            // nothing at all — no dump, no trace, no attach. There is no target to release and so
            // nothing for its stdin closing to accomplish; killing it is the whole teardown.
            session.kill();
            return Err(OpenError::NoRoom(why));
        }
        // Released only now: from here the session is counted in `all` instead, and holding both
        // would count this open twice.
        drop(slot);

        // On the reserved job id, so `reader` can still recognise this open if the caller's
        // timeout means nobody is left to settle it.
        let out = self
            .call_as(&session, Call::new(op), self.call_timeout, OPENER_JOB)
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
                Ok(OpenReport { id, report })
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

    /// Ends a session: asks the worker to release its target, then terminates it.
    ///
    /// The kill is not a fallback for tidiness — it is the recovery path. A worker parked in a
    /// kernel attach that will never connect cannot answer, cannot be interrupted, and would
    /// otherwise hold its session forever; killing it is the only thing that ends that wait, and
    /// under process-per-session it costs nothing else.
    pub async fn end(&self, session: &Arc<Session>, named: bool) -> Result<String, EngineError> {
        let call = Call::new(EngineOp::EndSession).named(named);
        let (reason, message) = match self.release(session, call, END_SESSION_TIMEOUT).await {
            // A refused handle is the mechanism working, not a session to tear down.
            Release::Stale(why) => return Err(EngineError::Stale(why)),
            Release::Released(text) => (
                "ended by end_session".to_string(),
                format!(
                    "{text}\n\nSession `{}` is closed and its engine worker process (pid {}) has \
                     been shut down.",
                    session.id, session.pid
                ),
            ),
            Release::Parked => (
                format!(
                    "terminated by end_session after {END_SESSION_TIMEOUT:?} without unwinding"
                ),
                format!(
                    "Session `{}` did not release its target within {END_SESSION_TIMEOUT:?}, so \
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
            Release::Refused(why) => (
                format!("ended after an error: {why}"),
                format!(
                    "The debugger reported an error releasing the target:\n  {why}\n\nSession \
                     `{}` is closed anyway and its engine worker process (pid {}) has been \
                     terminated, so nothing is left attached.",
                    session.id, session.pid
                ),
            ),
        };
        session.set_state(SessionState::Closed(reason));
        Ok(message)
    }

    /// Asks a worker to release its target and then terminates it, without deciding *why* the
    /// session is closing — `end_session` and reclamation share the teardown but not the reason,
    /// and the reason is what the caller reads afterwards.
    async fn release(&self, session: &Arc<Session>, call: Call, grace: Duration) -> Release {
        let out = match self.call_within(session, call, grace).await {
            Err(EngineError::Stale(why)) => return Release::Stale(why),
            other => other,
        };
        session.fail_outstanding(&format!("session `{}` was ended", session.id));
        session.kill();
        match out {
            Ok(text) => Release::Released(text),
            Err(EngineError::Timeout(_)) => Release::Parked,
            Err(EngineError::Lost(_)) => Release::AlreadyGone,
            Err(e) => Release::Refused(e.to_string()),
        }
    }

    /// Ends every session, then terminates any worker that did not let go. Called when the client
    /// disconnects, so a debugger process — or a debuggee — never outlives the connection.
    ///
    /// A disconnect is treated as `end_session` on everything, which is both the simplest rule to
    /// explain and the only safe one: see [`SHUTDOWN_RELEASE_TIMEOUT`] for what killing a live
    /// kernel outright costs. Sessions are released concurrently because they are independent
    /// processes and the client is waiting.
    pub async fn shutdown(&self) {
        // Closing the gate and taking the snapshot under **one** lock acquisition is what makes
        // one pass enough. [`Self::admit`] re-checks `closing` under this same lock after its
        // worker's handshake, so every open is on one side or the other of this moment: either it
        // registered first and is in `owners`, or it registers never and is refused. The set
        // cannot grow behind this snapshot, which is what earlier versions used a timed drain to
        // approximate.
        //
        // Every session that still *owns a worker*, not every live one. A session claimed for
        // reclamation is already `Closed` while its release runs in the background, and a
        // disconnect in that window would otherwise drop the runtime and cancel that release,
        // leaving the worker to notice its own stdin close — a five-second best-effort where an
        // orderly release was available. Releasing one twice is harmless; missing one is not.
        let owners = {
            let mut registry = self.registry();
            registry.closing = true;
            registry.owning_workers()
        };
        if owners.is_empty() {
            return;
        }
        tracing::info!("shutting down: releasing {} session(s)", owners.len());
        let mut releasing = Vec::with_capacity(owners.len());
        for session in owners {
            let sessions = self.clone();
            releasing.push(tokio::spawn(async move {
                // Marked first so nothing new is routed to a session on its way out; the release
                // runs as the supervisor's own teardown and so passes the gate that closes. A
                // session already closed keeps the reason it closed for.
                session.set_state(SessionState::Closed(
                    "the server is shutting down".to_string(),
                ));
                let outcome = sessions
                    .release(
                        &session,
                        Call::supervisor(EngineOp::EndSession),
                        SHUTDOWN_RELEASE_TIMEOUT,
                    )
                    .await;
                // `end_session` renders this for its caller. Shutdown has no caller — the client
                // has already gone — so the log is the only place it can land, and it is exactly
                // where an operator looks after finding a guest that did not come back.
                match outcome {
                    Release::Released(_) => {
                        tracing::info!("shutting down: session {} released its target", session.id)
                    }
                    Release::AlreadyGone => tracing::info!(
                        "shutting down: session {}'s worker had already exited",
                        session.id
                    ),
                    Release::Parked => tracing::warn!(
                        "shutting down: session {} did not let go within {SHUTDOWN_RELEASE_TIMEOUT:?} \
                         and its worker (pid {}) was terminated — a live kernel target may be left \
                         halted",
                        session.id,
                        session.pid
                    ),
                    Release::Refused(why) => tracing::warn!(
                        "shutting down: session {} reported an error releasing its target ({why}); \
                         its worker (pid {}) was terminated anyway",
                        session.id,
                        session.pid
                    ),
                    Release::Stale(why) => tracing::info!(
                        "shutting down: session {} was already settled ({why})",
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
                tracing::error!("shutting down: a session's release task failed: {e}");
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
        let live = registry.live();
        // How many sessions would have to be reclaimed to be back at the limit once this open,
        // and every open already in flight, has landed — against how many *can* be. Counting the
        // opens in flight is what stops two of them spending the same idle session: the first
        // needs one reclaimable, the second needs two.
        let needed = (live.len() + registry.opening + 1).saturating_sub(MAX_SESSIONS);
        let reclaimable = live.iter().filter(|s| !s.busy()).count();
        if needed > reclaimable {
            let listed: Vec<String> = live
                .iter()
                .map(|s| {
                    let busy = if s.busy() { " — busy" } else { " — idle" };
                    format!("  {} — {} ({}){busy}", s.id, s.kind.label(), s.what)
                })
                .collect();
            let in_flight = match registry.opening {
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
        registry.opening += 1;
        Ok(Slot {
            registry: Arc::clone(&self.inner),
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
        let over = self.registry().live().len();
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
        let live = registry.live();
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
        registry.all.push_back(Arc::clone(session));
        registry.trim();
        Ok(())
    }

    /// Starts a worker process and waits for it to report that its engine came up.
    async fn spawn(
        &self,
        id: &str,
        kind: SessionKind,
        what: String,
    ) -> Result<Arc<Session>, String> {
        let exe = worker_exe()?;
        let mut child = Command::new(&exe)
            .arg(WORKER_FLAG)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // Worker logs join the server's own, which is where an MCP client looks for them.
            .stderr(Stdio::inherit())
            // Deliberately **not** `kill_on_drop`, and the absence is load-bearing. Dropping this
            // handle — or the whole process exiting — closes the worker's stdin, and a worker
            // reads that EOF as "the supervisor is gone" and asks its engine to release the target
            // before it exits, bounded (`worker::run`). Terminating on drop pre-empts exactly
            // that: a worker this server never got round to releasing would die by
            // `TerminateProcess` with its target still attached, which for a live kernel means a
            // machine left halted. So EOF is the teardown, on every route out — clean shutdown,
            // Ctrl+C, or a crash — and [`Session::kill`] is the deliberate one, used only once a
            // release has been asked for and refused, or on a worker known to hold nothing.
            //
            // Which is why the worker also gets its own process group: see
            // [`CREATE_NEW_PROCESS_GROUP`]. EOF cannot be the teardown if a console Ctrl+C ends the
            // worker before its stdin ever closes.
            .creation_flags(CREATE_NEW_PROCESS_GROUP)
            .spawn()
            .map_err(|e| format!("could not start an engine worker ({}): {e}", exe.display()))?;

        let stdin = child.stdin.take().ok_or("engine worker has no stdin")?;
        let stdout = child.stdout.take().ok_or("engine worker has no stdout")?;
        let pid = child.id().unwrap_or(0);
        let mut lines = BufReader::new(stdout).lines();

        // Nothing is registered until the worker says its engine exists. A session that cannot
        // debug is worse than no session: it would accept calls and fail every one.
        match tokio::time::timeout(WORKER_READY_TIMEOUT, next_message(&mut lines)).await {
            Ok(Some(WorkerMessage::Ready)) => {}
            Ok(Some(WorkerMessage::Fatal { message })) => {
                let _ = child.start_kill();
                return Err(message);
            }
            Ok(Some(other)) => {
                let _ = child.start_kill();
                return Err(format!("engine worker said {other:?} before it was ready"));
            }
            Ok(None) => {
                let _ = child.start_kill();
                return Err("the engine worker exited before it was ready".to_string());
            }
            Err(_) => {
                let _ = child.start_kill();
                return Err(format!(
                    "the engine worker did not come up within {WORKER_READY_TIMEOUT:?}"
                ));
            }
        }
        tracing::info!("session {id}: engine worker pid {pid} ready");

        let (tx, rx) = mpsc::unbounded_channel();
        let waiters: Waiters = Arc::new(Mutex::new(HashMap::new()));
        let session = Arc::new(Session {
            id: id.to_string(),
            kind,
            what,
            pid,
            created: Instant::now(),
            state: Mutex::new((SessionState::Opening, Instant::now())),
            tx,
            // Job ids start *past* the opener's, which is reserved — see [`OPENER_JOB`].
            next_id: AtomicU64::new(OPENER_JOB + 1),
            waiters: Arc::clone(&waiters),
            delivered: AtomicBool::new(false),
            phase: AtomicU8::new(OpenPhase::Started as u8),
            child: Mutex::new(Some(child)),
        });

        // Both tasks hold a `Weak`, so a session dropped from the registry takes its worker's
        // plumbing with it rather than keeping the Arc alive forever.
        tokio::spawn(pump(
            Arc::downgrade(&session),
            rx,
            stdin,
            Arc::clone(&waiters),
            self.call_timeout,
        ));
        tokio::spawn(reader(
            Arc::downgrade(&session),
            lines,
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
        SessionState::Retired(why) => format!(
            "session handle `{want}` has been retired: {why}. The worker still holds a target, \
             but it is not the one this handle names, so the guarantee the handle buys no longer \
             applies. Omit `session_id` to operate on it anyway, or open again for a handle that \
             means something."
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
fn settle_open(session: &Session, result: &Result<String, EngineError>) -> bool {
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

/// Why an open is refused once the client has disconnected.
///
/// Shared by the two gates that refuse it — before a worker is spawned, and again after it comes
/// up — so the answer cannot drift depending on which one the caller raced.
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
fn worker_exe() -> Result<PathBuf, String> {
    if let Some(path) = std::env::var_os("WINDBG_MCP_WORKER_EXE") {
        return Ok(PathBuf::from(path));
    }
    std::env::current_exe()
        .map_err(|e| format!("cannot locate this executable to spawn an engine worker: {e}"))
}

/// Reads the next well-formed message, skipping anything else on the worker's stdout.
///
/// Skipping rather than failing is deliberate: DbgEng output reaches this server through
/// `IDebugOutputCallbacks`, but an extension that writes to the console directly would otherwise
/// desynchronize the stream permanently. A logged line costs nothing; a dead session costs a
/// target.
async fn next_message(lines: &mut Lines<BufReader<ChildStdout>>) -> Option<WorkerMessage> {
    loop {
        let line = lines.next_line().await.ok().flatten()?;
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<WorkerMessage>(&line) {
            Ok(message) => return Some(message),
            Err(_) => tracing::warn!("engine worker wrote a line that is not a message: {line}"),
        }
    }
}

/// Feeds one session's queue to its worker, one job at a time.
///
/// This is the session's single serialization point, and the only place a [`Gate`] runs. Jobs are
/// written as they arrive rather than one-per-reply on purpose: a job whose caller has given up
/// is still running in the worker, and blocking the queue behind it would stop `end_session` from
/// ever reaching the worker at all.
async fn pump(
    session: Weak<Session>,
    mut rx: mpsc::UnboundedReceiver<Job>,
    mut stdin: ChildStdin,
    waiters: Waiters,
    call_timeout: Duration,
) {
    while let Some(job) = rx.recv().await {
        let Some(session) = session.upgrade() else {
            return;
        };
        let answer = |result: Result<String, EngineError>| {
            let waiter = waiters
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&job.id);
            if let Some(waiter) = waiter {
                let _ = waiter.send(result);
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

        let mut op = job.op;
        if let EngineOp::BoundedCommand { patience_ms, .. } = &mut op {
            *patience_ms = remaining_patience_ms(call_timeout, job.submitted);
        }
        let request = WorkerRequest { id: job.id, op };
        let Ok(mut line) = serde_json::to_string(&request) else {
            answer(Err(EngineError::Debugger(
                "could not encode this operation for the engine worker".to_string(),
            )));
            continue;
        };
        line.push('\n');
        if stdin.write_all(line.as_bytes()).await.is_err() || stdin.flush().await.is_err() {
            // The worker is gone. The reader task sees the same thing and settles the session;
            // this job is simply the first to notice.
            answer(Err(EngineError::Lost(worker_gone(&session.id))));
            return;
        }
    }
}

/// Consumes one worker's messages: milestones move the session's state, results answer callers.
async fn reader(
    session: Weak<Session>,
    mut lines: Lines<BufReader<ChildStdout>>,
    waiters: Waiters,
    sessions: Sessions,
) {
    while let Some(message) = next_message(&mut lines).await {
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
            }
            WorkerMessage::Opened { id } if id == OPENER_JOB => {
                session.reach(OpenPhase::Opened);
                promote_opened(&session);
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
                let Some(waiter) = waiter else { continue };
                // A failed send means the receiver is gone: the caller's timeout fired and
                // nobody is left to act on this result. For an ordinary call that is fine —
                // removing the entry above is what mattered, and it is how the session stops
                // counting as busy. For the *opener* it is not: `open` settles the session's
                // state from its result, so with no one to run that, the session would sit in
                // `Opening` or `Attaching` for the life of the process — `session_status` would
                // keep reporting an open that finished long ago, and `busy()` would keep the
                // worker from ever being reclaimed.
                if let Err(unreceived) = waiter.send(result.map_err(EngineError::Debugger))
                    && id == OPENER_JOB
                    && settle_open(&session, &unreceived)
                {
                    // It settled *live*, so it owes the slot it took — the same reconciliation
                    // `open` runs, which nobody is left here to run for it.
                    sessions.reconcile_capacity(&session);
                }
            }
            // Both belong to the spawn handshake, which has already happened.
            WorkerMessage::Ready | WorkerMessage::Fatal { .. } => {}
        }
    }
    // stdout closed: the worker exited, for whatever reason.
    let Some(session) = session.upgrade() else {
        return;
    };
    if session.state().is_live() {
        session.set_state(SessionState::Closed(
            "the engine worker process exited".to_string(),
        ));
    }
    session.fail_outstanding(&worker_gone(&session.id));
}

#[cfg(test)]
mod tests {
    use super::*;

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
    #[test]
    fn a_retired_handle_is_refused_but_still_the_default_target() {
        let retired = SessionState::Retired("a raw command replaced the target".to_string());
        assert!(!retired.accepts_handle());
        assert!(retired.accepts_default());
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
            assert!(!state.is_live(), "{state:?}");
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
        assert!(retired.contains("Omit `session_id`"), "{retired}");

        let closed = stale_handle("sess-1", &SessionState::Closed("ended".to_string()));
        assert!(closed.contains("closed"), "{closed}");
        assert!(closed.contains("open_dump"), "{closed}");
    }

    // ---- the registry (no workers involved) ---------------------------------------

    /// A `Session` with no worker behind it, for the routing tests. Its queue has no consumer,
    /// which is all these need: they never submit a call.
    fn dormant(id: &str, state: SessionState) -> Arc<Session> {
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
            state: Mutex::new((state, Instant::now())),
            tx,
            next_id: AtomicU64::new(1),
            waiters: Arc::new(Mutex::new(HashMap::new())),
            // Test doubles stand in for sessions their callers already hold.
            delivered: AtomicBool::new(true),
            phase: AtomicU8::new(phase as u8),
            child: Mutex::new(None),
        })
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
            .insert(1, tx);
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
        assert_eq!(sessions.registry().opening, 0);
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
        assert_eq!(sessions.registry().opening, 1);
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
        settle_open(&landed, &Ok("vertarget".into()));
        assert_eq!(landed.state(), SessionState::Open);
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
    /// runtime is dropped, the release is cancelled, and the worker is left to notice its stdin
    /// close and let go on its own — best effort, when the orderly `EndSession` a halted kernel
    /// wants was available.
    #[tokio::test]
    async fn shutdown_collects_a_session_whose_release_is_still_in_flight() {
        let sessions = Sessions::new(Duration::from_secs(1));
        let reclaimed = dormant("sess-reclaimed", SessionState::Open);
        // A stand-in for the worker: any child process will do, since what is under test is
        // which sessions the registry hands to shutdown, not what the process is.
        let child = Command::new("cmd")
            .args(["/c", "ping", "-n", "30", "127.0.0.1"])
            .stdout(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn a stand-in child");
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
        let child = Command::new("cmd")
            .args(["/c", "ping", "-n", "30", "127.0.0.1"])
            .stdout(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn a stand-in child");
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
        assert!(!settle_open(&closed, &Ok("vertarget".into())));
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
}
