//! The engine worker process: one child process, one DbgEng session.
//!
//! dbgeng.dll holds **one debuggee session per process**, so a session is a process here rather
//! than a thread. The supervisor ([`crate::engine`]) spawns one of these per open target and
//! talks to it over a private pair of inherited pipes ([`crate::proto`]) — *not* over this
//! process's standard handles, which anything linked into it may write to.
//!
//! Inside the worker the old confinement rules still apply — DbgEng wants serialized,
//! single-threaded access, and `WaitForEvent` must run on the session-owning thread — so the
//! [`DebugEngine`] is created on, and never leaves, one dedicated thread. What changed is what
//! happens when that thread cannot be freed: a live-kernel attach whose target never dials in
//! blocks in `WaitForEvent(INFINITE)` with no cancellation path (win-kexp's `SetInterrupt`
//! watchdog cannot reach a wait that is still establishing the link). That used to park the
//! server's only engine thread; here it parks this process, which the supervisor can kill.
//!
//! Which is why the request reader lives on the *main* thread and exits the process outright on
//! EOF instead of joining the engine thread: at EOF the engine thread may be parked forever,
//! and waiting for it would recreate the very wedge this design removes.
//!
//! **The one call that crosses that line, and why it is not a hole in it.** `SetInterrupt` is the
//! single DbgEng entry point Microsoft documents as safe from any thread, and it is the only one
//! this process ever makes off the engine thread — from exactly one place, [`interrupt_running`],
//! on the request reader. Everything else about the engine stays where it always was: it is created
//! on the engine thread, never sent anywhere, and every other call is made there.
//!
//! The exception is not optional and not an optimisation. An interrupt exists to stop an operation
//! that is *running*, which means the engine thread is by definition busy; routed through that
//! thread it would be read only once there was nothing left to interrupt. So the alternative to
//! reaching the engine from outside is not a safer interrupt, it is no interrupt at all.
//!
//! It is also not new here — win-kexp's two watchdogs have always Ctrl+Broken the engine from a
//! thread of their own, on every bounded command and every go/step. What this adds is a caller who
//! can ask for the same thing, and the binding ([`Running`]) that decides *which job* the request
//! reaches. See `AGENTS.md` and the `DECISIONS.md` entry for the invariant and its boundary.

use std::io::{BufRead, BufReader, PipeReader, PipeWriter, Write};
use std::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use win_kexp::dbgeng::{DebugEngine, InterruptHandle, RunToOutcome};
use win_kexp::pool::query::{self, PoolPageFilter, PoolWalk};
use win_kexp::pool::{DiagnosticShape, PoolDiagnostics, PoolSpan, PoolState};
use windows_sys::Win32::Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation};

use crate::batch::{self, BatchOp, Debuggee};
use crate::proto::{EngineOp, PoolOp, ReachabilityOp, WorkerMessage, WorkerRequest};
use crate::server::{
    fmt_addr, format_recipe, format_report, hexdump, parse_eval, parse_lm_base, parse_u64,
    parse_windbg_addr, path_recipe, reachability,
};

/// The argument that turns this executable into a worker. Not a documented CLI: the supervisor
/// re-executes itself with it, and nothing else should.
pub const WORKER_FLAG: &str = "--engine-worker";

/// The flags carrying this worker's two ends of the protocol channel, as raw handle values:
/// requests to read, messages to write ([`crate::proto`]).
///
/// Even less of a CLI than [`WORKER_FLAG`]. A handle number means nothing outside the process
/// that inherited it, so these are only ever valid in the child the supervisor spawned with them.
pub const REQUESTS_FLAG: &str = "--requests-handle=";
pub const MESSAGES_FLAG: &str = "--messages-handle=";

/// Reads the two inherited handle values off the command line.
///
/// There is deliberately no fallback to stdin/stdout when they are missing. Falling back is the
/// exposure this channel exists to remove — a worker that quietly spoke the protocol over its
/// standard handles again would be back to sharing them with whatever an extension DLL prints.
fn channel_handles(args: &[String]) -> Result<(usize, usize), String> {
    let value = |flag: &str| {
        let raw = args
            .iter()
            .find_map(|arg| arg.strip_prefix(flag))
            .ok_or_else(|| format!("no `{flag}<handle>` on the command line"))?;
        match raw.parse::<usize>() {
            // A null handle is not a channel: it would fail every read or write, silently, for
            // the life of the process.
            Ok(0) | Err(_) => Err(format!("`{flag}{raw}` is not a usable handle value")),
            Ok(handle) => Ok(handle),
        }
    };
    Ok((value(REQUESTS_FLAG)?, value(MESSAGES_FLAG)?))
}

/// Clears `HANDLE_FLAG_INHERIT` on a handle this process inherited, so no child of *this* process
/// gets a copy in turn. The supervisor's side of the same flag is `engine::inheritable`.
fn stop_inheriting(handle: RawHandle) -> std::io::Result<()> {
    // SAFETY: the handle is owned by this process for the rest of its life, and this only changes
    // a flag on it.
    let ok = unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// How long to wait for a target to stop after open/attach/launch (ms).
///
/// Advisory for everything but a live kernel: `attach_kernel` needs `WaitForEvent(INFINITE)`
/// (a finite timeout returns `E_NOTIMPL` and never drives the KD link), so win-kexp's
/// `PendingTarget::wait` ignores this for that one case. That unbounded wait is the reason
/// sessions live in their own process.
const LOAD_WAIT_MS: u32 = 60_000;

/// Most bytes a single `read_memory` will fetch.
///
/// A guard against exhausting the worker, not a judgement about what is useful: the buffer costs
/// this much and the hexdump built from it costs roughly four times more, so an unbounded `size`
/// is an out-of-memory away from losing the session. 1 MiB is far past any real inspection —
/// which renders as some 65,000 lines of hex — while leaving no plausible caller short.
const MAX_READ_BYTES: usize = 1024 * 1024;

/// How much of the caller's remaining patience the watchdog keeps for itself: it Ctrl+Breaks the
/// engine this long before the caller's wait expires, so the interrupt has time to land, `Execute`
/// has time to unwind, and this worker is free again before the tool call reports its timeout.
const WATCHDOG_HEADROOM: Duration = Duration::from_secs(15);

/// The watchdog deadline for a command that waited `queued` in this worker's queue, given the
/// `patience` its caller had left when the supervisor sent it.
///
/// The caller's timeout starts at submission, but a command may sit behind another job for the
/// same session (a backgrounded `go`, a long `!ttdext.index`) before the engine reaches it.
/// Budgeting from what *remains* — not from the patience as sent — is what makes the interrupt
/// fire before the caller gives up regardless of queue wait.
///
/// Floored at [`WATCHDOG_HEADROOM`] rather than allowed to reach zero, because zero *disables*
/// win-kexp's watchdog: a command dequeued at or past the deadline would then be the one command
/// that runs unbounded, which is exactly the wedge case. The floor overruns the caller's timeout
/// by design — the caller has already given up by then, and freeing the worker 15s late still
/// beats never.
fn watchdog_budget_ms(patience: Duration, queued: Duration) -> u32 {
    patience
        .saturating_sub(queued)
        .saturating_sub(WATCHDOG_HEADROOM)
        .max(WATCHDOG_HEADROOM)
        .as_millis()
        .min(u32::MAX as u128) as u32
}

/// How long a pool walk may run: the same arithmetic as [`watchdog_budget_ms`] and the same
/// headroom, but **no floor** — `None` when the caller's clock has nothing left to give it.
///
/// The same question as the watchdog's, so deliberately the same answer rather than a second
/// constant that would drift from it. What differs is what running out of time *does*. There, zero
/// disables the bound outright, so a command dequeued past the deadline would be the one command
/// that runs unbounded, and a floor that overruns the caller by a headroom is the lesser evil. Here
/// zero merely stops the walk at its first check — so the floor buys nothing and costs the one thing
/// this budget exists to prevent, a walk still running after its caller gave up. That is #75 in
/// miniature: with `WINDBG_MCP_CALL_TIMEOUT_SECS=10`, a floored 15s walk outlives *every* call.
///
/// **And it really does buy nothing**, which is the part worth writing down, because the first cut
/// of this reasoned the other way: a walk cut short by its budget clears `complete`, and
/// win-kexp caches only complete snapshots — an incomplete one invalidates the entry instead. So a
/// floored walk for a caller who has gone does 15s of work that is then *discarded*, and the next
/// query walks from scratch anyway. There is no cache to warm.
fn walk_budget(patience: Duration, queued: Duration) -> Option<Duration> {
    let left = patience
        .saturating_sub(queued)
        .saturating_sub(WATCHDOG_HEADROOM);
    (!left.is_zero()).then_some(left)
}

/// How long the worker gives its engine to let go of the target when the supervisor disappears
/// without saying goodbye — a Ctrl+C, a crash, anything that is not a clean disconnect.
///
/// Short, because this is a process on its way out and the engine may be parked in a wait that
/// will never end. Long enough for an idle engine to resume and detach a live kernel, which is
/// the case that matters: exiting without it leaves the target machine halted.
const ABRUPT_EXIT_RELEASE: Duration = Duration::from_secs(5);

/// Whether the batch on this worker's engine thread has been told to stop, and — the part a
/// teardown actually needs — how long it can still be running.
///
/// The deadline *is* the "is one running" answer rather than a second flag beside it, so the two
/// can never disagree about a batch that started or finished in between.
struct BatchSignal {
    /// Set by a teardown, and never cleared. Sticky on purpose: after it a batch that has not
    /// started must not start, or the session's last act would be a fresh set of mutations run for
    /// a caller who is already gone.
    abandon: AtomicBool,
    /// The mutable half, under one lock so the deadline and the teardown that is waiting on it
    /// cannot be read out of step with each other.
    ///
    /// A `Mutex` rather than atomics because it carries an `Instant`, and because the lock is what
    /// orders it against [`Self::abandon`] — see there. Uncontended in practice: taken twice per
    /// batch and once per teardown.
    state: Mutex<SignalState>,
}

/// What [`BatchSignal`] knows about the batch on the engine thread and about who is waiting for it.
#[derive(Default)]
struct SignalState {
    /// When the running batch must be finished by, or `None` when none is running. This *is* the
    /// "is one running" answer rather than a second flag beside it, so the two can never disagree
    /// about a batch that started or finished in between.
    finish_by: Option<Instant>,
    /// The request id of the teardown that told the batch to stop, once one has. Kept so the
    /// promise made to that teardown can be *retracted* when the batch finishes — see
    /// [`BatchGuard::drop`].
    told_by: Option<u64>,
}

impl BatchSignal {
    const fn new() -> Self {
        Self {
            abandon: AtomicBool::new(false),
            state: Mutex::new(SignalState {
                finish_by: None,
                told_by: None,
            }),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, SignalState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Tells any batch to stop at its next step boundary, and reports **how long it may still
    /// need** — which is what a teardown sizes its grace from.
    ///
    /// That figure is the batch's own remaining budget, not the rollback's reserve, and the
    /// difference is the whole point: the signal cannot reach a step already inside DbgEng, so what
    /// the teardown waits out is the step in flight *and* the `always` block after it. A batch is
    /// finished inside its budget however it ends (`batch::run`), and that budget was already
    /// clamped to the caller's patience, so this is a bound the worker can actually keep rather
    /// than a guess that holds until a step runs long.
    ///
    /// **The one interleaving that must not happen** is a batch running while this reports nothing
    /// to wait for. It cannot: the store precedes this lock, and [`Self::enter`] locks before it
    /// loads. If this sees `None` because it got the lock first, its store is already visible to
    /// the load `enter` makes after taking the lock — so that batch refuses to start. Both sides
    /// seeing each other is fine, and costs a teardown a grace it did not need.
    fn abandon(&self, told_by: u64) -> Option<Duration> {
        self.abandon.store(true, Ordering::SeqCst);
        let mut state = self.state();
        state.told_by = Some(told_by);
        state
            .finish_by
            .map(|by| by.saturating_duration_since(Instant::now()))
    }

    fn abandoned(&self) -> bool {
        self.abandon.load(Ordering::SeqCst)
    }

    /// Ends the claim, and reports the teardown that is owed a **retraction** — the one told, back
    /// when it arrived, that this batch might need up to N.
    ///
    /// The retraction is not tidiness. That promise was measured when the teardown arrived, and a
    /// rollback usually finishes in a fraction of it. Left standing, a teardown whose *release*
    /// then hangs — a live kernel that will not detach, the case the short grace exists for —
    /// would wait out the rest of a batch budget that was spent long ago: minutes, for a
    /// transaction already safely unwound. A fresh promise of zero says the only thing still worth
    /// waiting for is the release itself.
    ///
    /// Owed once: whoever takes it here sends it, to the id and with the figure this returns.
    fn finish(&self) -> Option<(u64, u32)> {
        let mut state = self.state();
        state.finish_by = None;
        state.told_by.take().map(|id| (id, RETRACTED))
    }

    /// Claims the engine thread for a batch that will be done by `bound` — everything it may start
    /// plus everything that may still be finishing — for as long as the guard lives, or refuses
    /// when a teardown has already been through.
    ///
    /// Checking and publishing under the **one** lock acquisition is what keeps a refused batch
    /// from ever being visible: published first and withdrawn after, there is a window in which a
    /// second teardown reads a whole batch budget for a batch that will not run, and waits it out
    /// before killing a worker that is doing nothing.
    fn enter(&self, bound: Duration) -> Option<BatchGuard<'_>> {
        let mut state = self.state();
        // Under the lock, which is what pairs it with [`Self::abandon`]: that one stores before it
        // takes this lock, so a teardown that got here first is visible to this load, and a batch
        // that got here first is visible to that read. Never neither.
        if self.abandon.load(Ordering::SeqCst) {
            return None;
        }
        state.finish_by = Some(Instant::now() + bound);
        Some(BatchGuard { signal: self })
    }
}

/// Ends the batch's claim however it ends — including by unwinding, which `engine_thread`'s guard
/// catches one frame further out.
struct BatchGuard<'a> {
    signal: &'a BatchSignal,
}

impl Drop for BatchGuard<'_> {
    fn drop(&mut self) {
        // Outside the lock `finish` takes: `emit` takes one of its own, and nothing here should
        // hold two at once.
        if let Some((id, within_ms)) = self.signal.finish() {
            emit(&WorkerMessage::RollingBack { id, within_ms });
        }
    }
}

/// What a retraction says: **nothing more**, because the transaction is over.
///
/// A retraction names the moment the batch ended, and zero is how a deadline says "now". What the
/// release still needs is not the worker's to name — the supervisor grants it from this moment,
/// out of the same grace it would have given a session that never ran a batch at all. Naming a
/// release interval here as well, which is what this first was, adds one: the supervisor waits the
/// interval out and *then* starts the grace, so a disconnect took two of them after a batch ended
/// rather than one.
const RETRACTED: u32 = 0;

/// This process's one batch signal. Global for the same reason [`MESSAGES`] is: the reader thread
/// sets it, the engine thread reads it, and there is exactly one engine here to be talking about.
static BATCH: BatchSignal = BatchSignal::new();

/// Which job the engine thread is running, and whether an interrupt has been raised for it.
///
/// The two live under one lock because the property that matters is a relation between them: an
/// interrupt must reach *the job that was running when it arrived*, or nothing. `SetInterrupt`
/// addresses an engine rather than an operation, so raised a moment late it Ctrl+Breaks whatever
/// started next — a caller's `go` aborted by a cancel meant for the search before it, with nothing
/// in the record to say why.
///
/// Holding the lock across the raise is what closes that: the engine thread takes the same lock to
/// clear `job`, so an interrupt either finds the job still claimed (and the engine thread then
/// waits behind it) or finds `None` and does nothing. It is never held *across* a job — only around
/// its two ends — so the reader is not blocked by the work it may be about to interrupt.
struct Running {
    /// The request id the engine thread is executing, or `None` between jobs.
    job: Option<u64>,
    /// The job an interrupt was raised for, kept until that job ends so the engine thread knows to
    /// drain whatever the engine did not consume. An interrupt lodged just as a command finishes
    /// leaves a Ctrl+Break pending with nothing running, and the next job would wear it.
    interrupted: Option<u64>,
}

static RUNNING: Mutex<Running> = Mutex::new(Running {
    job: None,
    interrupted: None,
});

impl Running {
    /// Claims the engine thread for `id`.
    fn claim(&mut self, id: u64) {
        self.job = Some(id);
    }

    /// Records that an interrupt has been raised for the job running *now* — which is the binding
    /// itself, and why it takes no id: the only job an interrupt can ever reach is the one claimed
    /// at the moment it is raised, and this is called under the lock that makes that true.
    fn interrupt_raised(&mut self) {
        self.interrupted = self.job;
    }

    /// Whether an interrupt has been raised for `id` and not yet spent.
    ///
    /// A peek, where [`Self::release`] takes: a long-running job that can stop *itself* — a
    /// [`crate::batch`], between its steps — has to be able to see the request without consuming
    /// the record that its reply is owed an explanation.
    fn interrupt_pending(&self, id: u64) -> bool {
        self.interrupted == Some(id)
    }

    /// Ends `id`'s claim, reporting whether an interrupt was bound to it.
    ///
    /// Taken rather than read, so an interrupt is spent by the job it reached: the next job starts
    /// with nothing outstanding and cannot inherit a cut-short label — or a drain — that belongs
    /// to the one before it.
    fn release(&mut self, id: u64) -> bool {
        self.job = None;
        self.interrupted.take() == Some(id)
    }
}

fn running() -> std::sync::MutexGuard<'static, Running> {
    RUNNING.lock().unwrap_or_else(|e| e.into_inner())
}

/// The engine's interrupt handle, published by the engine thread once the engine exists.
///
/// A `OnceLock` rather than a field somewhere, because the two threads that need it are the only
/// two this process has: the engine thread creates the engine, and the request reader is the one
/// that ever asks for a break. Set before [`WorkerMessage::Ready`], so a supervisor that has been
/// told this worker is usable is never then told there is no handle.
static INTERRUPT: OnceLock<InterruptHandle> = OnceLock::new();

/// [`Running::claim`] on this process's one tracker.
fn claim(id: u64) {
    running().claim(id);
}

/// [`Running::interrupt_pending`] on this process's one tracker.
fn interrupt_pending(id: u64) -> bool {
    running().interrupt_pending(id)
}

/// [`Running::release`] on this process's one tracker.
///
/// `true` is the engine thread's cue to do two things before the next job: drain whatever
/// Ctrl+Break the engine did not consume, and tell the caller their result was cut short. Paired
/// with [`claim`] around the `catch_unwind` rather than inside it, so an op that panics still gives
/// the claim back.
fn release(id: u64) -> bool {
    running().release(id)
}

/// What the request reader hands to the engine thread.
enum Job {
    /// A request from the supervisor, stamped when it was read.
    Run(Instant, WorkerRequest),
    /// The supervisor is gone: release the target and acknowledge.
    Release(mpsc::Sender<()>),
}

/// Runs this process as an engine worker. Never returns.
pub fn run(args: &[String]) -> ! {
    let (requests, messages) = match channel_handles(args) {
        Ok(handles) => handles,
        Err(why) => {
            // Nothing can be *reported*: the channel a supervisor would be listening on is the
            // very thing that is missing. So this goes to stderr, and the exit is what the
            // supervisor reads — its end of the channel closes and it says the worker exited
            // before it was ready, which is exactly what happened.
            tracing::error!("worker: {why}; this executable is not meant to be run by hand");
            std::process::exit(2);
        }
    };
    // SAFETY: these are the two handles the supervisor created for this process and passed on the
    // command line, inherited by `CreateProcess` and owned by nothing else here — the supervisor
    // closed its copies as soon as the spawn returned (`engine::spawn_worker`). Wrapping them
    // takes that ownership; they close when this process does, which is what gives the supervisor
    // its EOF.
    let requests = unsafe { PipeReader::from_raw_handle(requests as RawHandle) };
    let messages = unsafe { PipeWriter::from_raw_handle(messages as RawHandle) };
    // The inheritable flag came with them and has done its job; carrying it further is how the
    // channel would escape this process. DbgEng creates children of its own — a launched debuggee,
    // whatever an extension shells out to — and one that inherited the message end would keep that
    // pipe from reporting EOF after this worker exits, which is exactly the signal the supervisor
    // settles a session on. Warned about rather than fatal: the channel itself still works, and
    // the risk only materializes if something is spawned here at all.
    for (what, handle) in [
        ("requests", requests.as_raw_handle()),
        ("messages", messages.as_raw_handle()),
    ] {
        if let Err(e) = stop_inheriting(handle) {
            tracing::warn!(
                "worker: could not stop the {what} channel being inherited ({e}); a process this \
                 debugger starts could hold it open past this worker's exit"
            );
        }
    }
    // Installed before the engine thread exists, so nothing can reach `emit` without a channel.
    let _ = MESSAGES.set(Mutex::new(messages));

    // Each request is stamped when it is *read*, so the engine thread can tell how long it then
    // waited its turn — the half of the watchdog budget only this process can measure.
    let (tx, rx) = mpsc::channel::<Job>();
    // Reported rather than panicked: the supervisor is waiting for `Ready` or `Fatal`, and a
    // panic here would give it neither — it would see only "the worker exited before it was
    // ready" and lose the reason.
    if let Err(e) = thread::Builder::new()
        .name("dbgeng".into())
        .spawn(move || engine_thread(rx))
    {
        emit(&WorkerMessage::Fatal {
            message: format!("could not start the engine thread: {e}"),
        });
        std::process::exit(1);
    }

    for line in BufReader::new(requests).lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<WorkerRequest>(&line) {
            Ok(request) => {
                // Acted on here, before it is queued, because the thread that will run it is the
                // one it is about: a batch on that thread has to be told to stop *now* if the
                // release behind it is not to wait out every step it has left. This loop is never
                // blocked by the engine — it reads a line and hands it on — which is the whole
                // reason the signal can arrive at all. See [`EngineOp::EndSession`].
                if matches!(request.op, EngineOp::EndSession) {
                    announce_teardown(request.id);
                }
                // The one request that is *answered* here rather than queued. Queueing it would
                // put it behind the operation it exists to stop, so it could only ever run once
                // there was nothing left to interrupt. See [`EngineOp::Interrupt`].
                if matches!(request.op, EngineOp::Interrupt) {
                    emit(&WorkerMessage::Done {
                        id: request.id,
                        result: interrupt_running(),
                    });
                    continue;
                }
                if tx.send(Job::Run(Instant::now(), request)).is_err() {
                    break; // the engine thread is gone; nothing can run any more
                }
            }
            // The line itself is never logged. An `AttachKernel` request carries the KD
            // connection string, key and all, and this worker's stderr is the supervisor's —
            // which is to say, the MCP client's log.
            Err(e) => tracing::error!(
                "worker: unreadable request ({e}); {} bytes, discarded",
                line.len()
            ),
        }
    }

    // The request channel closed: the supervisor ended this session, or died. Either way this
    // process has no reason to exist.
    //
    // This is the *only* thing that ends a worker the supervisor did not explicitly kill — it does
    // not set `kill_on_drop`, deliberately (`engine::Sessions::spawn`). So the path below has to
    // be unconditional, and is: whatever the engine thread is doing, and whether or not it ever
    // picks the release up, this process exits within `ABRUPT_EXIT_RELEASE`. Nothing upstream
    // needs a backstop for a worker that "does not exit on EOF", because there is no such worker.
    //
    // On the clean path the supervisor has already had this session release its target, so the
    // engine has nothing left to do. On the other one — Ctrl+C, a crash, anything that kills the
    // supervisor without it running its own shutdown — nobody has, and exiting here would leave a
    // live kernel *halted*, because DbgEng needs an explicit resume-and-detach. So ask for one,
    // bounded: an idle engine obliges in milliseconds, a parked one never will, and either way
    // this process is gone within `ABRUPT_EXIT_RELEASE` — or, when a batch is being unwound first,
    // within that plus what the batch itself has left to run.
    //
    // Ctrl+C only reaches this path because a worker is spawned into its own process group
    // (`engine::CREATE_NEW_PROCESS_GROUP`). Without that it would be delivered here too, and the
    // default console handler would end this process where it stands — no EOF, no release.
    //
    // Bounded and then abandoned, never joined: the engine thread may be blocked in DbgEng
    // forever, and this is precisely the case where that must not hold anything up.
    //
    // Logged because it is otherwise invisible: this is the teardown nobody asked for, and an
    // operator looking at a target that came back fine wants to see which path did it.
    tracing::info!("worker: supervisor is gone; releasing the target before exit");
    // Same signal, sent to ourselves. A batch still running would otherwise hold the release
    // behind every step it has left, on the one path where nobody is left to have asked for
    // anything — and this process is leaving either way, so the choice is between a rollback and
    // no rollback, not between finishing the batch and not.
    // No teardown request to answer here — the supervisor is gone — so the id is immaterial; what
    // matters is that the batch is told, and that this process waits for it.
    let grace = match BATCH.abandon(0) {
        Some(within) => {
            tracing::info!(
                "worker: a batch is running; giving it up to {within:?} to stop and roll back \
                 before exit"
            );
            ABRUPT_EXIT_RELEASE + within
        }
        None => ABRUPT_EXIT_RELEASE,
    };
    let (ack, released) = mpsc::channel();
    if tx.send(Job::Release(ack)).is_err() {
        // The engine thread died before this could be asked, so nothing was even attempted --
        // a different failure from the two below, and the only one where no release was tried
        // at all.
        tracing::error!(
            "worker: the engine thread is gone, so nothing was asked to release the target"
        );
    } else {
        // Whichever way this ends the process does, but *which* way is the difference between a
        // target let go and a target still attached to a debugger that no longer exists. Silence
        // here would leave that to be inferred from a guest that never came back.
        match released.recv_timeout(grace) {
            Ok(()) => {}
            Err(mpsc::RecvTimeoutError::Timeout) => tracing::warn!(
                "worker: the engine did not finish releasing within {grace:?} (parked in DbgEng, \
                 most likely); exiting anyway, so a live kernel target may be left halted"
            ),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                tracing::error!("worker: the engine thread is gone, so nothing released the target")
            }
        }
    }
    std::process::exit(0);
}

/// Owns the [`DebugEngine`] for the life of the process and runs one op at a time.
fn engine_thread(rx: mpsc::Receiver<Job>) {
    // `DebugEngine::new()` panics if the engine can't be created (dbgeng.dll not discoverable,
    // most likely). Report it and exit instead of accepting requests that can only fail: the
    // supervisor is waiting for exactly one of these two messages before it registers a
    // session, so it can report a dead engine as server machinery rather than as a debugger
    // error the model would pointlessly retry.
    let engine = match catch_unwind(AssertUnwindSafe(DebugEngine::new)) {
        Ok(engine) => engine,
        Err(_) => {
            emit(&WorkerMessage::Fatal {
                message: "failed to initialize DbgEng (is dbgeng.dll on the search path?)"
                    .to_string(),
            });
            std::process::exit(1);
        }
    };
    // Published before `Ready`, so the request reader can never be handed work it cannot interrupt.
    let _ = INTERRUPT.set(engine.interrupt_handle());
    emit(&WorkerMessage::Ready);

    while let Ok(job) = rx.recv() {
        let (arrived, request) = match job {
            Job::Run(arrived, request) => (arrived, request),
            // The supervisor is gone. Let go of the target before this process does, so a live
            // kernel is left running rather than halted, then acknowledge so the main thread can
            // stop waiting. Best-effort by nature: if the engine never reaches this, the main
            // thread times out and exits anyway.
            Job::Release(ack) => {
                // Reported here rather than handed back: the main thread's only move is to exit
                // either way, and this is where the reason still exists. So the ack means
                // "finished trying", not "succeeded" — what the main thread waits for is
                // permission to stop waiting.
                match catch_unwind(AssertUnwindSafe(|| engine.end_session())) {
                    Ok(Ok(_)) => tracing::info!("worker: target released"),
                    Ok(Err(e)) => tracing::error!(
                        "worker: the debugger refused to release the target ({}); a live kernel \
                         target may be left halted",
                        es(e)
                    ),
                    Err(_) => tracing::error!(
                        "worker: releasing the target panicked; a live kernel target may be left \
                         halted"
                    ),
                }
                let _ = ack.send(());
                continue;
            }
        };
        // Measured here, at the front of the queue: this is the wait only this process can see,
        // and the bounded path needs it to size the watchdog.
        let queued = arrived.elapsed();
        let id = request.id;
        // Claimed around the whole op, so an interrupt arriving while it runs names *this* job.
        // Outside the `catch_unwind` below, so a panicking op gives the claim back too.
        claim(id);
        // A panic inside a win-kexp method (several use `.expect`) must not kill the session —
        // surface it as an error for this one op. The engine survives, so this stays a
        // debugger-level failure the model can work around by trying something else.
        let result = catch_unwind(AssertUnwindSafe(|| {
            execute(&engine, id, request.op, queued)
        }))
        .unwrap_or_else(|_| Err("debugger operation panicked".to_string()));
        let result = if release(id) {
            // The engine may have consumed the Ctrl+Break, or the request may have been lodged as
            // the operation was already returning — in which case it is still pending with nothing
            // running, and the next job would be the one to stop. Draining is cheap and this is
            // the only moment it is unambiguous: this job's claim is gone and the next has not
            // been made, so nothing else can be raising one.
            let _ = engine.interrupted();
            cut_short(result)
        } else {
            result
        };
        // A `Done` is what removes the supervisor's waiter, so one that never arrives costs the
        // caller its session rather than its result: the call times out, the waiter stays, and
        // the session counts as busy — and so stays unreclaimable — for the life of the server.
        // The channel now makes corruption impossible, but delivery is still worth insisting on.
        if let Emit::Unencodable = emit(&WorkerMessage::Done { id, result }) {
            // The result could not be serialized, so send one that cannot fail to be: plain text
            // in the same shape. The caller loses the output, not the session.
            emit(&WorkerMessage::Done {
                id,
                result: Err(
                    "the debugger's result could not be encoded for the supervisor".to_string(),
                ),
            });
        }
        // `Unwritable` gets no retry, and needs none: the supervisor holds the only read end, so
        // a channel that will not take a write means it is gone — its request channel has closed
        // too, and the teardown at the end of `run` is already on its way. The supervisor fails
        // every outstanding call out when this process exits, which answers this caller.
    }
}

/// The channel this worker writes its messages on: its end of the pipe the supervisor is reading
/// ([`crate::proto`]). One per process and for the life of the process, installed by [`run`]
/// before anything exists that could emit.
///
/// Global for the same reason stdout was: `emit` is reached from the engine thread, from inside
/// an opener's milestones, and from the main thread's startup path, and threading a handle
/// through all of that would buy nothing — there is exactly one channel, and no code path may
/// choose a different one.
static MESSAGES: OnceLock<Mutex<PipeWriter>> = OnceLock::new();

/// What became of a message [`emit`] was asked to send.
enum Emit {
    Sent,
    /// It could not be serialized. Every variant is plain data, so this is a bug rather than a
    /// condition — but see the `Done` path in [`engine_thread`] for why it is still handled.
    Unencodable,
    /// It could not be written. The supervisor holds the only read end, so this means it is gone
    /// or going, and the request channel is at EOF or about to be.
    Unwritable,
}

/// Writes one message on the protocol channel.
///
/// The whole message is one `write_all` under one lock, and the channel is private to this pair
/// of processes, so a message always arrives as its own line. Nothing else here holds the handle,
/// and an anonymous pipe has no name for anything else to open — which is what makes framing a
/// matter of what this function does rather than of what nobody else happens to print.
fn emit(message: &WorkerMessage) -> Emit {
    let Ok(mut line) = serde_json::to_string(message) else {
        tracing::error!("worker: could not encode {message:?}");
        return Emit::Unencodable;
    };
    line.push('\n');
    let Some(channel) = MESSAGES.get() else {
        tracing::error!("worker: no protocol channel to write {message:?} on");
        return Emit::Unwritable;
    };
    let mut channel = channel.lock().unwrap_or_else(|e| e.into_inner());
    match channel
        .write_all(line.as_bytes())
        .and_then(|()| channel.flush())
    {
        Ok(()) => Emit::Sent,
        Err(e) => {
            tracing::error!("worker: could not write to the protocol channel ({e})");
            Emit::Unwritable
        }
    }
}

/// Tells any running batch that its session is going away, from the request reader — see
/// [`EngineOp::EndSession`] for why this happens here rather than on the engine thread.
///
/// The message it may send is a promise about time, so it goes out *before* the release is queued:
/// the supervisor is waiting on that release, and this is what tells it how long the wait is worth.
/// Sent only when there is a batch to stop, so an ordinary teardown says nothing and costs nothing.
fn announce_teardown(id: u64) {
    let Some(within) = BATCH.abandon(id) else {
        return;
    };
    tracing::info!("worker: session ending with a batch in flight; it has {within:?} to unwind");
    emit(&WorkerMessage::RollingBack {
        id,
        within_ms: within.as_millis().min(u128::from(u32::MAX)) as u32,
    });
}

/// Marks a result as one that was cut short by an interrupt somebody asked for.
///
/// Said on *this* reply because this is the caller who cannot otherwise find out. The one who asked
/// for the interrupt was answered when they asked; this one gets back a search that found nothing,
/// or a `go` that stopped somewhere unremarkable, and would read either as a fact about the target
/// rather than about a request made behind their back.
///
/// Appended rather than substituted, both ways round: the partial output is the point of
/// interrupting rather than ending the session, and a failure keeps its debugger text because
/// "this is why it stopped" is not the same claim as "this is what it would have said".
fn cut_short(result: Result<String, String>) -> Result<String, String> {
    const NOTE: &str = "[windbg-mcp] This operation was interrupted on request (Ctrl+Break) \
                        before it finished, so this is what it had reached, not a complete \
                        result. Nothing about the target failed. Re-run it — scoped more \
                        narrowly, if it was interrupted for taking too long.";
    match result {
        Ok(text) if text.is_empty() => Ok(NOTE.to_string()),
        Ok(text) if text.ends_with('\n') => Ok(format!("{text}\n{NOTE}")),
        Ok(text) => Ok(format!("{text}\n\n{NOTE}")),
        Err(text) => Err(format!("{text}\n\n{NOTE}")),
    }
}

/// Ctrl+Breaks the job the engine thread is running, from the request reader — see
/// [`EngineOp::Interrupt`] for why this happens here rather than on the engine thread.
///
/// The whole decision is made under [`RUNNING`]'s lock: which job is running, and the raise itself.
/// That is what binds the interrupt to a job rather than to a moment — the engine thread cannot
/// finish that job and start another in between, because clearing the claim needs the same lock.
///
/// Says which job it reached, in a reply the *interrupting* caller reads. That caller is not the
/// one running the operation, so "an operation was interrupted" and "there was nothing to
/// interrupt" are the two answers it needs, and they are indistinguishable from the outside.
fn interrupt_running() -> Result<String, String> {
    let mut running = running();
    let Some(job) = running.job else {
        return Ok(
            "Nothing was running on this session's engine, so nothing was interrupted. \
                   Whatever you meant to stop had already finished — its own reply says how it \
                   ended."
                .to_string(),
        );
    };
    // At most one break per job, and the reason is a `debug_batch`: its rollback runs as part of
    // the same job, so a second interrupt aimed at a batch that is already stopping would land on
    // a restore command instead — a cut-short `Execute` that still reports `Ok`, which is a
    // mutation left applied and reported as undone. The one thing this subsystem exists to prevent.
    //
    // Costs nothing anywhere else: a repeat only ever meant "that same operation, again", and it
    // is already stopping. A *later* job is a different id and is interrupted normally, which is
    // why this is not idempotence — see the tool's annotation.
    if running.interrupt_pending(job) {
        return Ok(format!(
            "Already interrupted. Ctrl+Break was raised on this session's engine for the \
             operation it is running (job {job}) and it is stopping; nothing further was sent. If \
             it does not end, it is one of the cases an interrupt cannot reach — a command that \
             never polls, or a live-kernel attach whose target has not connected — and \
             `end_session` is what ends those, at the cost of the target."
        ));
    }
    let Some(handle) = INTERRUPT.get() else {
        // Only reachable before the engine exists, and the supervisor is told `Ready` after that,
        // so no session can be routed here. Reported rather than unwrapped all the same.
        return Err(
            "this engine worker has no interrupt handle yet — its engine is still \
                    starting up"
                .to_string(),
        );
    };
    handle.interrupt().map_err(es)?;
    // Recorded only once the raise succeeded: a failed one has left nothing pending, and claiming
    // otherwise would have the engine thread drain an interrupt that was never lodged and label a
    // complete result as cut short.
    running.interrupt_raised();
    tracing::info!("worker: interrupt raised for job {job}");
    Ok(
        "Interrupted. Ctrl+Break was raised on this session's engine, so the operation it was \
         running stops at its next poll and returns whatever it had reached — to the call that \
         started it, not to this one. A command that never polls, and a live-kernel attach whose \
         target has not connected, cannot be reached this way; `end_session` is what ends those."
            .to_string(),
    )
}

/// Runs one op against this worker's engine. `queued` is how long it waited its turn here, which
/// only the bounded-command path cares about.
fn execute(e: &DebugEngine, id: u64, op: EngineOp, queued: Duration) -> Result<String, String> {
    match op {
        // ---- openers ----
        //
        // Each reads the same way: side effect, `commit`, wait, `opened`, report. That order is
        // the contract the milestones exist to express — see [`open`].
        EngineOp::OpenDump { path } => open(
            id,
            |commit| {
                // `open_dump` is the call that claims the target, so commit right after it: a
                // load wait that times out still leaves DbgEng holding the dump.
                e.open_dump(&path).map_err(es)?;
                commit();
                e.wait_for_event(LOAD_WAIT_MS).map_err(es)
            },
            || {
                // Load the WinDbg extension DLL so `!`-extension commands resolve — most
                // importantly `!ext.analyze -v`, the crash-dump triage workhorse. A bare engine
                // doesn't auto-load it, and even after `.load ext` the unqualified `!analyze`
                // won't resolve, so callers must use `!ext.analyze`. Best-effort: a minimal
                // engine without a bundled `winext\` directory simply won't have ext.dll, which
                // must not fail the open (live/dump state is still usable).
                let _ = e.execute_command(".load ext");
                e.execute_command("lm").map_err(es)
            },
        ),

        EngineOp::OpenTrace { path } => open(
            id,
            |commit| {
                // As in `OpenDump`: commit before the load wait, because a wait that times out
                // still leaves DbgEng holding the trace.
                e.open_trace(&path).map_err(es)?;
                commit();
                e.wait_for_event(LOAD_WAIT_MS).map_err(es)
            },
            || {
                // Check the index state *before* any data-model query: `!ttdext.index -status`
                // only reads the on-disk .idx (never builds), whereas a `dx` on an unindexed
                // trace can itself trigger the long in-memory index build. TtdExt reports a
                // healthy, ready index as exactly "Index file loaded."; per MS guidance treat
                // anything else (missing, out of date, corrupt, unloadable) as needing an index.
                // A blank result means the status query itself failed — don't warn then.
                let needs_index = {
                    let status = e
                        .execute_command("!ttdext.index -status")
                        .unwrap_or_default();
                    !status.trim().is_empty()
                        && !status.to_ascii_lowercase().contains("index file loaded")
                };
                // Confirm TTD replay is active and report the trace's position span. Lifetime
                // is cheap metadata (min/max position); the expensive indexing is triggered by
                // Calls/Memory/Events queries, which is what the note below warns about.
                let mut out = e
                    .execute_command("dx @$curprocess.TTD.Lifetime")
                    .map_err(es)?;
                if needs_index {
                    out.push_str(
                        "\nNote: this trace's index is not loaded (missing, out of date, or \
                         unusable). The first data-model query (ttd_calls/ttd_memory/ttd_events/dx) \
                         then builds an in-memory index and can run long — let it finish before \
                         issuing more queries. Run index_trace to (re)build a persistent .idx \
                         (fast queries and re-opens).",
                    );
                }
                Ok(out)
            },
        ),

        EngineOp::AttachKernelLocal => open(
            id,
            |commit| {
                // The engine has claimed the local kernel once `_begin` returns; the break-in
                // wait (INITIAL_BREAK + the INFINITE wait a live kernel requires) happens in
                // `wait`, after the target is ours.
                let pending = e.attach_local_kernel_begin().map_err(es)?;
                commit();
                pending.wait().map_err(es)
            },
            || kernel_report(e),
        ),

        EngineOp::AttachKernel { connection } => open(
            id,
            |commit| {
                // `_begin` takes the connection; the KD link is dialed and the break-in awaited
                // in `wait`. Committing between them is what stops a failed wait from looking
                // like "nothing happened" — re-dialing a live link is not a clean retry.
                //
                // This `wait` is the one that can never return: `SetInterrupt` cannot reach a
                // wait still establishing the link, so a guest that never dials in parks here
                // for good. It parks *this process*, which the supervisor can kill.
                // The one place the key is unwrapped, and the last: it goes straight into
                // DbgEng. Everything else that touches this value renders it redacted.
                let pending = e.attach_kernel_begin(connection.expose()).map_err(es)?;
                commit();
                pending.wait().map_err(es)
            },
            || kernel_report(e),
        ),

        EngineOp::AttachProcess { pid } => open(
            id,
            |commit| {
                // Attached once `_begin` returns; the break-in wait follows the commit, so a
                // wait that fails cannot read as "never attached" and get retried into a second
                // attach on the same PID.
                let pending = e.attach_process_begin(pid).map_err(es)?;
                commit();
                pending.wait().map_err(es)
            },
            || e.execute_command("r").map_err(es),
        ),

        EngineOp::Launch { command_line } => open(
            id,
            |commit| {
                // The commit point is *before* the process actually starts: CreateProcessWide is
                // deferred into the wait. That is still the right moment — once `_begin` returns
                // Ok the spawn is committed, so a retry from here means two processes.
                //
                // It is also not too early, which is the natural worry: only the *spawn* is
                // deferred, not validation. CreateProcessWide resolves and checks the image
                // synchronously, so the ways a launch fails with nothing created all land on
                // this `?`, before the commit — verified against a live engine for a missing
                // path (0x80070002), a directory (0x80070005), a non-PE file (0x800700C1) and
                // an empty command line (0x80070057). A failure from `wait` below therefore
                // means the process really was created, which is what makes the post-commit
                // message ("a session exists, do not open again") true rather than a guess.
                let pending = e.launch_process_begin(&command_line).map_err(es)?;
                commit();
                pending.wait().map_err(es)
            },
            || e.execute_command("r").map_err(es),
        ),

        // ---- ordinary work ----
        EngineOp::Command { command } => e.execute_command(&command).map_err(es),
        EngineOp::BoundedCommand {
            command,
            patience_ms,
        } => {
            let budget = watchdog_budget_ms(Duration::from_millis(u64::from(patience_ms)), queued);
            e.execute_command_bounded(&command, budget).map_err(es)
        }
        EngineOp::CommandAndWait {
            command,
            timeout_ms,
        } => e.execute_and_wait(&command, timeout_ms).map_err(es),
        EngineOp::Registers => e.registers().map_err(es),
        EngineOp::ReadMemory { address, size } => read_memory(e, &address, size),
        EngineOp::SymbolPath {
            path,
            append,
            reload,
        } => {
            if append {
                e.append_symbol_path(&path).map_err(es)?;
            } else {
                e.set_symbol_path(&path).map_err(es)?;
            }
            // Reload so the new path takes effect (default: all deferred modules).
            e.reload_symbols(&reload).map_err(es)?;
            // Echo the effective path so the caller can confirm what resolved.
            e.execute_command(".sympath").map_err(es)
        }
        EngineOp::RunToAddress {
            address,
            timeout_ms,
        } => run_to_address(e, &address, timeout_ms),
        EngineOp::Reachability(args) => reachable(e, args),
        // The caller's own deadline, on the same arithmetic as a bounded command's: a walk that
        // outlives its caller holds this session against nobody. Taking win-kexp's default instead
        // was wrong in both directions — see [`EngineOp::Pool`].
        EngineOp::Pool { query, patience_ms } => {
            let patience = Duration::from_millis(u64::from(patience_ms));
            match walk_budget(patience, queued) {
                Some(budget) => {
                    // Logged because a truncated walk otherwise says only *that* it was truncated,
                    // and the two explanations — this deadline, or a target the walk could not
                    // read — want opposite responses. It is also the only place the figure is
                    // observable, which is what `tests/mcp_smoke.rs` asserts against: the bug this
                    // fixed was that no figure crossed the pipe at all.
                    tracing::debug!("worker: pool walk budget {budget:?} (queued {queued:?})");
                    pool(e, query, budget)
                }
                // Nothing left to walk in. A query that *must* walk is refused rather than
                // attempted, because attempting it cannot produce an answer: the walk would be cut
                // short at its first check, and a truncated snapshot is discarded rather than
                // cached, so the work would be spent for nobody and the next query would walk from
                // scratch regardless.
                None if query.refreshes() => {
                    tracing::debug!(
                        "worker: no pool walk budget left (queued {queued:?}); refusing a query \
                         that must walk"
                    );
                    Err(format!(
                        "This pool query was not run: it reached the engine with {}s of its \
                         caller's timeout left, which is not enough to walk the pool and report \
                         back before that timeout expires. It asked for `refresh`, so it cannot \
                         be answered from the snapshot cached for this session either. Nothing \
                         was read and nothing changed. It waited {}s behind other work on this \
                         session; issue it when the session is idle, or raise the server's call \
                         timeout (WINDBG_MCP_CALL_TIMEOUT_SECS — a pool walk needs more than the \
                         {}s of headroom the reply itself reserves).",
                        patience.saturating_sub(queued).as_secs(),
                        queued.as_secs(),
                        WATCHDOG_HEADROOM.as_secs(),
                    ))
                }
                // Without `refresh` the session's cached snapshot may well answer this outright, and
                // a caller with no time left can certainly afford a cache read. Passed zero rather
                // than refused: if a walk *is* needed it stops at once and the answer says its
                // coverage was nil, which every rendering below already does.
                None => pool(e, query, Duration::ZERO),
            }
        }
        // `id` is passed because a batch is the one op that can stop *itself*: it checks between
        // steps whether an interrupt has been raised for the job it is running as.
        EngineOp::Batch(op) => run_batch(e, id, op, queued),
        // Answered by the request reader, which is the only way it could reach a busy engine at
        // all, so it is never queued and never arrives here. See [`EngineOp::Interrupt`].
        EngineOp::Interrupt => Err(
            "an interrupt reached the engine thread, which cannot act on \
                                    one; this is a bug in the worker's request reader"
                .to_string(),
        ),
        // Reaching here means any batch has already been told to stop and has finished unwinding —
        // the reader saw this request go past and said so, and this thread runs one job at a time.
        EngineOp::EndSession => e
            .end_session()
            .map(|_| "session ended".to_string())
            .map_err(es),
    }
}

/// Maps any error to a `String` for the wire.
fn es<E: ToString>(e: E) -> String {
    e.to_string()
}

/// Reads target memory and renders it as a hex dump.
///
/// Free function rather than an inline arm because a batch step reads memory the same way, and a
/// second copy of the bound below would be a second chance to get it wrong.
fn read_memory(e: &DebugEngine, address: &str, size: u32) -> Result<String, String> {
    let addr = parse_u64(address)?;
    // Bounded before the allocation, not after. `size` arrives from the caller as a bare `u32`,
    // and a large one costs that many bytes here plus a hexdump several times larger — enough to
    // take the worker down with an OOM, which costs the caller their whole session for a number a
    // model can produce by accident.
    if size as usize > MAX_READ_BYTES {
        return Err(format!(
            "`size` is {size} bytes; this tool reads at most {MAX_READ_BYTES}. Read the range you \
             need in pieces, or use `execute` with a `db`/`dd` command if you want the debugger's \
             own paging."
        ));
    }
    let bytes = e.read_memory(addr, size as usize).map_err(es)?;
    Ok(hexdump(addr, &bytes))
}

/// How long a batch may run, given what it asked for and what its caller has left.
///
/// The batch's whole value is that its rollback runs *before* the tool call reports anything, so
/// the budget has to end before the caller's patience does — [`WATCHDOG_HEADROOM`] again, for the
/// same reason and with the same arithmetic as [`watchdog_budget_ms`]: patience as sent, minus the
/// wait in this worker's queue, minus the headroom the reply needs.
///
/// The caller's `timeout_ms` can only make it *shorter*. A batch that asks for ten minutes inside
/// a five-minute call budget would otherwise be a batch whose rollback report is guaranteed to
/// arrive after nobody is listening — which is the failure this tool exists to remove, arriving
/// by way of the argument that was supposed to prevent it.
///
/// `None` when there is not enough left to be worth starting, and **this is where a batch parts
/// company with [`watchdog_budget_ms`]**. That one floors at [`WATCHDOG_HEADROOM`] rather than
/// reaching zero, because its command is already running and the job left is to free the worker:
/// bounding it 15s late beats never. A batch has not started. Handing it the same floor would run
/// *mutations* for a caller who has already been told the call timed out — a job sits in the queue
/// after its waiter has given up, so this is reachable by a long queue wait alone, and by any
/// `WINDBG_MCP_CALL_TIMEOUT_SECS` under the headroom — and would then roll them back with nobody
/// left to read whether that worked. Not starting is the only outcome that leaves the target as
/// the caller last saw it.
fn batch_budget(requested_ms: u32, patience: Duration, queued: Duration) -> Option<Duration> {
    // What is left after reserving the headroom the reply needs to land inside the caller's wait.
    let usable = patience
        .saturating_sub(queued)
        .saturating_sub(WATCHDOG_HEADROOM);
    // The same floor the caller's own `timeout_ms` has to clear: below it the reserve cannot seat
    // a step and a rollback, so there is no batch to run, only mutations to regret.
    if usable < Duration::from_millis(u64::from(batch::MIN_BATCH_MS)) {
        return None;
    }
    Some(usable.min(Duration::from_millis(u64::from(requested_ms))))
}

/// A [`Debuggee`] over this worker's engine: the seam that keeps [`crate::batch`] free of DbgEng.
struct BatchEngine<'a> {
    e: &'a DebugEngine,
    started: Instant,
    signal: &'a BatchSignal,
    /// The request id this batch is running as, so it can see an interrupt aimed at *it* — see
    /// [`Debuggee::interrupted`].
    job: u64,
}

impl Debuggee for BatchEngine<'_> {
    fn command(&mut self, command: &str, budget_ms: u32) -> Result<String, String> {
        // Bounded, always. A batch is the one place a runaway command would also strand a
        // rollback, so the step self-aborts rather than eating the reserve.
        self.e
            .execute_command_bounded(command, budget_ms)
            .map_err(es)
    }

    fn resume(&mut self, command: &str, timeout_ms: u32) -> Result<String, String> {
        self.e.execute_and_wait(command, timeout_ms).map_err(es)
    }

    fn run_to(&mut self, address: &str, timeout_ms: u32) -> Result<String, String> {
        run_to_address(self.e, address, timeout_ms)
    }

    fn read_memory(&mut self, address: &str, size: u32) -> Result<String, String> {
        read_memory(self.e, address, size)
    }

    fn pool(&mut self, query: &PoolOp, budget_ms: u32) -> Result<String, String> {
        // The step's own budget, handed to the walker. Bounded, always, for the same reason a
        // command step is: this is the one step that can spend minutes without a runaway anywhere
        // — a full pool walk is every committed page over the KD wire — and the reserve the
        // rollback lives on is what it would spend.
        pool(
            self.e,
            query.clone(),
            Duration::from_millis(u64::from(budget_ms)),
        )
    }

    fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    fn abandoned(&self) -> bool {
        self.signal.abandoned()
    }

    fn interrupted(&self) -> bool {
        interrupt_pending(self.job)
    }
}

/// Runs a batch and renders its report.
///
/// The report is the result either way — a failed transaction that did not say which step failed
/// and whether the rollback ran would be worse than no report at all. `Err` only chooses how
/// [`crate::server`] renders it: a tool-execution error the model can read and act on.
fn run_batch(e: &DebugEngine, job: u64, op: BatchOp, queued: Duration) -> Result<String, String> {
    let Some(budget) = batch_budget(
        op.budget_ms,
        Duration::from_millis(u64::from(op.patience_ms)),
        queued,
    ) else {
        // Answered rather than silently dropped: a `Done` is what releases the supervisor's waiter
        // and frees this session, so the reply is worth sending even though its caller has stopped
        // waiting for it. "Nothing ran" is the part that matters — it is what makes resubmitting
        // safe, which is not true of a batch abandoned partway.
        return Err(format!(
            "This batch was not started: it reached the engine with {}s of its caller's timeout \
             left, which is not enough to run it and report back before that timeout expires. \
             Nothing was run and nothing was changed — no step, no assertion, no rollback — so \
             the target is exactly as it was and resubmitting is safe. It waited {}s behind other \
             work on this session; issue it when the session is idle, or raise the server's call \
             timeout (WINDBG_MCP_CALL_TIMEOUT_SECS).",
            Duration::from_millis(u64::from(op.patience_ms))
                .saturating_sub(queued)
                .as_secs(),
            queued.as_secs(),
        ));
    };
    // Claimed only now, because the claim carries the deadline: a teardown that finds this batch
    // has to be told how long it may still run, and that is not known until the budget is. From
    // here an abandon signal either finds this batch or is found by it — never neither. See
    // [`BatchSignal::abandon`].
    //
    // What is advertised is the budget **plus what the executor is allowed to overrun it by**: the
    // budget bounds what a batch may start, and an operation started a moment before it still gets
    // a watchdog floor. Advertising the bare budget would have a teardown terminate this worker
    // while the last restore was still running — see [`batch::OVERRUN_ALLOWANCE`].
    let Some(_running) = BATCH.enter(budget + batch::OVERRUN_ALLOWANCE) else {
        // The same answer as an unaffordable budget above, and for the same reason: nothing ran, so
        // there is nothing to undo and resubmitting is safe. This is the queue-wait case — the
        // teardown that set the flag arrived while this batch was still behind other work.
        return Err(
            "This batch was not started: the session it names is being torn down (the client \
             disconnected, or the session was ended) and was already doing so when this batch \
             reached the engine. Nothing was run and nothing was changed — no step, no assertion, \
             no rollback — so the target is exactly as it was. Open a session again and resubmit \
             the whole batch."
                .to_string(),
        );
    };
    let mut engine = BatchEngine {
        e,
        started: Instant::now(),
        signal: &BATCH,
        job,
    };
    let report = batch::run(&mut engine, &op, budget);
    let rendered = batch::render(&report);
    // The one outcome whose report is written for nobody: a batch is abandoned by a teardown, so
    // the caller is already gone and the `Done` this becomes answers a waiter that is being failed
    // out anyway. The log is where it can still be read, and an operator looking at a target that
    // was patched wants to know the patch came off.
    if matches!(report.outcome, batch::BatchOutcome::Abandoned { .. }) {
        tracing::info!(
            "worker: batch abandoned mid-flight; rollback {}",
            if report.rollback_complete() {
                "complete"
            } else {
                "INCOMPLETE — the target may still be patched"
            }
        );
    }
    if report.committed() && report.rollback_complete() {
        Ok(rendered)
    } else {
        Err(rendered)
    }
}

/// Column header for the chunk tables below. Kept next to [`pool_row`] so the two cannot
/// drift out of alignment.
const POOL_COLUMNS: &str =
    "address               size  state          kind                    backend  tag   numa";

/// Renders one chunk as a fixed-width row.
///
/// The address column is `usable_address` — what the allocation call *returned*, and so the
/// value that appears in the target's own pointers. `header_address` is where the allocator's
/// bookkeeping starts and is rarely what a caller is holding.
fn pool_row(span: &PoolSpan) -> String {
    format!(
        "{:<18}  {:>5}  {:<13}  {:<22}  {:<7}  {:<4}  {}",
        fmt_addr(span.usable_address),
        format!("{:#x}", span.size),
        format!("{:?}", span.state),
        format!("{:?}", span.pool_kind),
        format!("{:?}", span.backend),
        span.display_tag,
        span.numa_node,
    )
}

/// Parses a pool address in any form a caller is likely to paste.
///
/// [`parse_windbg_addr`] is tried first because it accepts the backtick form that debugger
/// output actually prints; it requires >= 8 hex digits, so shorter `0x`-hex and decimal fall
/// through to [`parse_u64`]. A bare 8+ digit run is read as hex, matching WinDbg's own
/// convention rather than Rust's.
fn parse_pool_addr(text: &str) -> Result<u64, String> {
    parse_windbg_addr(text).map_or_else(|| parse_u64(text), Ok)
}

/// The walk's own diagnostic categories, commonest first.
///
/// The grouping is the walk's, not ours: it collapses floods as it goes and keeps a total per
/// category, so re-deriving categories here would count the *sample* it kept — off by two
/// orders of magnitude on a live target — and report that as a fact about the pool. Only the
/// ordering is a presentation choice, and it belongs on this side.
/// "1 category" / "24 categories" — the irregular plural shows up in every rendering here.
fn categories_phrase(count: usize) -> String {
    format!("{count} categor{}", if count == 1 { "y" } else { "ies" })
}

fn diagnostic_categories(diagnostics: &PoolDiagnostics) -> Vec<&DiagnosticShape> {
    let mut categories: Vec<&DiagnosticShape> = diagnostics.shapes().iter().collect();
    categories.sort_by(|left, right| {
        right
            .total
            .cmp(&left.total)
            .then_with(|| left.shape.cmp(&right.shape))
    });
    categories
}

/// The caveat an answer needs when the walk that produced it did not finish, or `None` when
/// it did — so a healthy answer stays quiet.
///
/// A *nonempty* result looks self-explanatory in a way an empty one does not, which is what
/// makes it the more dangerous of the two: "3 allocations, 0x138 bytes total" reads as the
/// whole set whether the walk covered the whole pool or a corner of it. Every list here is
/// drawn from what the walk indexed, so under partial coverage a count is a floor. Saying so
/// is the difference between "there are three of these" and "these are the three I could see".
fn coverage_caveat(report: &query::PoolSnapshotReport) -> Option<String> {
    if report.complete {
        return None;
    }
    Some(format!(
        "\n--- pool walk ---\ncoverage: INCOMPLETE - the walk reached {} chunk(s), but not \
         everything it set out to. What is listed above is therefore a floor, not a total: \
         there may be more the walk never saw.\n",
        report.total_chunks
    ))
}

/// Appends what the walk itself managed, so an empty answer explains itself.
///
/// Without this, an empty result is ambiguous in the worst way: "the pool holds no such
/// chunk" and "the walk reached almost none of the pool" render identically. The snapshot
/// is already cached by the time this runs, so the extra query costs nothing.
///
/// The diagnostics are *categorised* rather than listed: a real walk emits tens of
/// thousands, and the first forty of those are a sample of whichever heap happened to be
/// walked first, not of the problem. Counts per category say which failures actually
/// dominate; the verbatim tail keeps concrete addresses available.
fn append_walk_report(out: &mut String, e: &DebugEngine) {
    match query::snapshot_report(e, false) {
        Ok(report) => out.push_str(&render_walk_report(&report)),
        Err(error) => out.push_str(&format!("\n(could not summarise the walk: {error})\n")),
    }
}

/// The body of [`append_walk_report`], split out so the counts can be tested without an engine.
fn render_walk_report(report: &query::PoolSnapshotReport) -> String {
    // `complete` is not implied by an empty diagnostics list: a walk can end partway
    // through without saying anything. Report it explicitly, or a caller reads a truncated
    // snapshot as a healthy one.
    let mut out = format!(
        "\n--- pool walk ---\nchunks walked: {} ({} allocated), coverage: {}\n",
        report.total_chunks,
        report.allocated_chunks,
        if report.complete {
            "complete"
        } else {
            "INCOMPLETE - the walk did not reach everything it set out to"
        }
    );
    if report.diagnostics.is_empty() {
        out.push_str("the walk reported no diagnostics.\n");
        return out;
    }
    let categories = diagnostic_categories(&report.diagnostics);
    out.push_str(&format!(
        "{} diagnostic(s) in {}:\n",
        report.diagnostics.emitted(),
        categories_phrase(categories.len())
    ));
    for category in categories.iter().take(25) {
        out.push_str(&format!(
            "  {:>7}x  {}\n",
            category.total,
            category.shape.trim()
        ));
    }
    if categories.len() > 25 {
        out.push_str(&format!(
            "  ... {} more categories\n",
            categories.len() - 25
        ));
    }
    // The last few verbatim: heaps are walked in order, so the tail is where the most
    // recently discovered ones (special pool included) report. These are only the messages
    // the walk kept — a capped sample per category — so say so, or "last 12" reads as the
    // tail of everything rather than the tail of the sample.
    let examples = report.diagnostics.examples();
    let shown = examples.len().min(12);
    out.push_str(&format!(
        "\nlast {shown} of the {} kept verbatim (the rest are in the counts above):\n",
        examples.len()
    ));
    for line in examples.iter().skip(examples.len() - shown) {
        out.push_str("  ");
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// Answers one pool question, walking the pool if the cached snapshot will not do.
///
/// `within` is the caller's own deadline for a walk that actually happens, and is **required** —
/// win-kexp's `DEFAULT_WALK_BUDGET` is reachable from neither caller here, which is right, because
/// neither is a human at a prompt who could Ctrl+C a walk that ran long. A [`crate::batch`] step
/// passes its step budget; a pool *tool* call passes what is left of its caller's patience
/// ([`walk_budget`]). For a batch the deadline is load-bearing beyond the caller: it reserves part
/// of its budget for the rollback and advertises the whole of it to a teardown, so a walk running to
/// the *walker's* default could overrun both. A walk stopped by a budget still answers — every
/// rendering below carries how much of the pool the walk reached — so the cost of a short deadline
/// is coverage, not an error.
fn pool(e: &DebugEngine, args: PoolOp, within: Duration) -> Result<String, String> {
    let walk = |refresh: bool| PoolWalk::from(refresh).within(within);
    match args {
        PoolOp::FindTag {
            tag,
            paged,
            refresh,
            limit,
        } => {
            let filter = paged.map(|paged| {
                if paged {
                    PoolPageFilter::Paged
                } else {
                    PoolPageFilter::NonPaged
                }
            });
            let spans = query::find_tag(e, &tag, filter, walk(refresh)).map_err(es)?;
            let mut out = render_find_tag(&tag, filter, &spans, limit);
            // Both branches read the snapshot `find_tag` has just taken or reused — hence the bare
            // `false` below, which cannot start a walk of its own whatever budget this query had.
            if spans.is_empty() {
                append_walk_report(&mut out, e);
            } else if let Ok(report) = query::snapshot_report(e, false)
                && let Some(caveat) = coverage_caveat(&report)
            {
                out.push_str(&caveat);
            }
            Ok(out)
        }
        PoolOp::Chunk { address, refresh } => {
            let address = parse_pool_addr(&address)?;
            match query::chunk_at(e, address, walk(refresh)).map_err(es)? {
                Some(found) => Ok(render_chunk(address, &found)),
                // "Not in the snapshot" and "free" are different answers, and reporting this one
                // as free would manufacture a dangling pointer out of a gap in the walk.
                None => {
                    let mut out = format!(
                        "{} is not covered by the pool snapshot.\n\nThat is not the same as \
                         \"free\": a free hole inside a walked region comes back as a chunk in \
                         an explicitly free state (ReusableFree or CachedFree). An address \
                         outside every region is either not pool at all, or sits in a region \
                         this walk did not reach. If the target has run since the snapshot was \
                         taken, retry with refresh=true.",
                        fmt_addr(address)
                    );
                    append_walk_report(&mut out, e);
                    Ok(out)
                }
            }
        }
        PoolOp::Diagnostics {
            filter,
            refresh,
            limit,
        } => {
            let report = query::snapshot_report(e, walk(refresh)).map_err(es)?;
            Ok(render_diagnostics(&report, filter.as_deref(), limit))
        }
        // The census *is* the state of the walk, so it always carries the report.
        PoolOp::Census { refresh, limit } => {
            let census = query::tag_census(e, walk(refresh)).map_err(es)?;
            let mut out = render_census(&census, limit);
            append_walk_report(&mut out, e);
            Ok(out)
        }
    }
}

fn render_find_tag(
    tag: &str,
    filter: Option<PoolPageFilter>,
    spans: &[PoolSpan],
    limit: usize,
) -> String {
    let scope = match filter {
        Some(PoolPageFilter::Paged) => " in paged pool",
        Some(PoolPageFilter::NonPaged) => " in nonpaged pool",
        None => "",
    };
    if spans.is_empty() {
        return format!(
            "No allocated chunks carry tag `{tag}`{scope}.\n\nOnly *allocated* chunks are \
             indexed by tag: a freed chunk's tag is not reliably preserved by the allocator, so \
             this never reports freed memory. To ask about one address that may have been freed, \
             use `pool_chunk`. If the target has run since the snapshot was taken, retry with \
             refresh=true."
        );
    }
    let total: u64 = spans.iter().map(|span| span.size).sum();
    let mut out = format!(
        "tag `{tag}`{scope}: {} allocation(s), {total:#x} bytes total\n\n{POOL_COLUMNS}\n",
        spans.len()
    );
    for span in spans.iter().take(limit) {
        out.push_str(&pool_row(span));
        out.push('\n');
    }
    if spans.len() > limit {
        out.push_str(&format!(
            "\n... {} more not shown; raise `limit` to see them.\n",
            spans.len() - limit
        ));
    }
    out
}

fn render_chunk(address: u64, found: &query::PoolNeighbourhood) -> String {
    let chunk = &found.chunk;
    let mut out = format!(
        "{} is {:#x} byte(s) into a {:#x}-byte chunk tagged `{}` ({:?}).\n\n{POOL_COLUMNS}\n",
        fmt_addr(address),
        address.saturating_sub(chunk.usable_address),
        chunk.size,
        chunk.display_tag,
        chunk.state,
    );
    if let Some(previous) = &found.previous {
        out.push_str(&format!("{}   prev\n", pool_row(previous)));
    }
    out.push_str(&format!("{}   <== containing chunk\n", pool_row(chunk)));
    if let Some(next) = &found.next {
        out.push_str(&format!("{}   next\n", pool_row(next)));
    }
    if found.previous.is_none() && found.next.is_none() {
        out.push_str("\n(no neighbouring chunks in the same heap)\n");
    }
    match chunk.state {
        PoolState::Allocated => {}
        // Only these two mean the allocator actually released the chunk.
        PoolState::ReusableFree | PoolState::CachedFree => out.push_str(&format!(
            "\nThis chunk is {:?}, not Allocated: any pointer the target still holds to it is a \
             use-after-free.\n",
            chunk.state
        )),
        // `Unreadable` is a limit of the walk, not a fact about lifetime — a Verifier guard
        // page reads exactly this way. Calling it a use-after-free would turn "could not
        // read" into a verdict, which is the one mistake this tool must not make.
        PoolState::Unreadable => out.push_str(
            "\nThis span could not be read, so its state is unknown. That is a limit of the \
             walk, not evidence that the allocator freed it.\n",
        ),
    }
    if chunk.heap.special {
        out.push_str(
            "\nThis is Driver Verifier special pool: the allocation owns a whole page and is \
             butted against a guard page, so an overflow or a touch after free faults at once \
             instead of quietly corrupting a neighbour. A freed special-pool page is unmapped, \
             so its former contents cannot be read back.\n",
        );
    }
    out
}

/// Whether `text` contains `needle`, case-insensitively; every text matches no needle.
fn matches_filter(text: &str, needle: Option<&str>) -> bool {
    needle.is_none_or(|needle| text.to_ascii_lowercase().contains(needle))
}

/// Selects the messages the walk kept verbatim that match `filter`.
fn select_examples<'a>(diagnostics: &'a PoolDiagnostics, filter: Option<&str>) -> Vec<&'a String> {
    let needle = filter.map(str::to_ascii_lowercase);
    diagnostics
        .examples()
        .iter()
        .filter(|line| matches_filter(line, needle.as_deref()))
        .collect()
}

/// Selects the categories whose shape matches `filter`, commonest first.
fn select_categories<'a>(
    diagnostics: &'a PoolDiagnostics,
    filter: Option<&str>,
) -> Vec<&'a DiagnosticShape> {
    let needle = filter.map(str::to_ascii_lowercase);
    diagnostic_categories(diagnostics)
        .into_iter()
        .filter(|category| matches_filter(&category.shape, needle.as_deref()))
        .collect()
}

/// Splits `limit` rows between the two halves of a diagnostics listing.
///
/// `limit` bounds the whole reply — the worker builds it as one `String` before it crosses the
/// pipe — so the two sections share one budget rather than each taking it in full.
///
/// Spending it in print order would be simpler and is wrong: a flood of examples would take
/// the lot and drop the category counts entirely, which is the very number this listing exists
/// to report. So each half is offered half the budget and hands back what it does not need.
/// Every shape contributes at least one example, so the categories are never the more numerous
/// half — in practice this means "the categories in full, the examples take the rest", and the
/// even split only bites on a target with an unusual number of distinct complaints.
fn split_row_budget(limit: usize, examples: usize, categories: usize) -> (usize, usize) {
    let for_examples = examples.min((limit / 2).max(limit.saturating_sub(categories)));
    (for_examples, categories.min(limit - for_examples))
}

/// Lists the walk's complaints: the verbatim ones it kept, then what the counts say.
///
/// Both halves are needed and neither substitutes for the other. The walk keeps only a
/// handful of messages per category, so the verbatim list is where a concrete address can be
/// found and is *not* where volume can be read; the categories carry the real totals and have
/// had their addresses generalised away. Printing only the first would answer "how many of
/// these were there?" with the size of a sample.
///
/// That trade has a sharp edge, and it is the reason for the note in the examples branch: the
/// two halves are filtered independently and an address can only ever match the first, so a
/// filter that finds its heap gets no counts at all — and must be told that rather than
/// pointed at a volume the response does not contain.
fn render_diagnostics(
    report: &query::PoolSnapshotReport,
    filter: Option<&str>,
    limit: usize,
) -> String {
    let examples = select_examples(&report.diagnostics, filter);
    let categories = select_categories(&report.diagnostics, filter);
    let scope = match filter {
        Some(filter) => format!(" matching \"{filter}\""),
        None => String::new(),
    };
    if examples.is_empty() && categories.is_empty() {
        return format!(
            "No diagnostics{scope}.\n\nThe walk was {}. It emitted {} diagnostic(s) in total over {} \
             chunk(s) ({} allocated). If you expected a match, check the spelling — the \
             filter is a plain case-insensitive substring, not a pattern.",
            if report.complete {
                "complete"
            } else {
                "INCOMPLETE"
            },
            report.diagnostics.emitted(),
            report.total_chunks,
            report.allocated_chunks
        );
    }
    let mut out = format!(
        "The walk emitted {} diagnostic(s) in {}.\n\n",
        report.diagnostics.emitted(),
        categories_phrase(report.diagnostics.shapes().len())
    );
    let (example_rows, category_rows) = split_row_budget(limit, examples.len(), categories.len());
    if !examples.is_empty() {
        out.push_str(&format!(
            "{} of {} kept verbatim{scope} (the walk keeps only a few per category, so this is \
             a sample):\n\n",
            examples.len(),
            report.diagnostics.examples().len()
        ));
        for line in examples.iter().take(example_rows) {
            out.push_str("  ");
            out.push_str(line);
            out.push('\n');
        }
        if examples.len() > example_rows {
            out.push_str(&format!(
                "\n... {} more match; raise `limit` to see them.\n",
                examples.len() - example_rows
            ));
        }
        // A filter naming a concrete value is the documented case — "an address
        // (ffff8c8f0d300000)" — and it is exactly the one that cannot match a category, because
        // generalising those values away is what lets a category carry a count. Promising the
        // volume anyway would repeat #77's mistake in the header: pointing at a number that is
        // not there, and leaving a capped sample as the only figure on the page.
        if categories.is_empty() && filter.is_some() {
            out.push_str(&format!(
                "\nNo category matches{scope}, so there is no volume to report for it. A \
                 category is the message with its numbers generalised away, which is what lets \
                 it carry a count — so a filter naming a concrete value can only ever match the \
                 verbatim sample above. Filter on the wording instead, or drop the filter, to \
                 see how often this kind of complaint occurred.\n"
            ));
        }
    }
    if !categories.is_empty() {
        out.push_str(&format!(
            "\n{}{scope}, commonest first — the count is every message of that shape, not just \
             the ones kept verbatim:\n\n",
            categories_phrase(categories.len())
        ));
        for category in categories.iter().take(category_rows) {
            out.push_str(&format!(
                "  {:>7}x  {}\n",
                category.total,
                category.shape.trim()
            ));
        }
        if categories.len() > category_rows {
            out.push_str(&format!(
                "\n... {} more; raise `limit` to see them.\n",
                categories_phrase(categories.len() - category_rows)
            ));
        }
    }
    // "2 of 2 diagnostics" is an exact-looking claim about a walk that may have stopped before
    // whole heaps. The empty branch above already says which; a nonempty one owes the same.
    if let Some(caveat) = coverage_caveat(report) {
        out.push_str(&caveat);
    }
    out
}

fn render_census(census: &[query::PoolTagSummary], limit: usize) -> String {
    if census.is_empty() {
        return "The pool snapshot contains no allocated chunks.".to_string();
    }
    let mut out = format!(
        "{} distinct tag(s) allocated, heaviest first.\n\ntag      allocs        bytes  \
         nonpaged   paged\n",
        census.len()
    );
    for entry in census.iter().take(limit) {
        out.push_str(&format!(
            "{:<6}  {:>7}  {:>11}  {:>8}  {:>6}\n",
            entry.display_tag,
            entry.allocations,
            format!("{:#x}", entry.total_bytes),
            entry.nonpaged_allocations,
            entry.paged_allocations,
        ));
    }
    if census.len() > limit {
        out.push_str(&format!(
            "\n... {} more not shown; raise `limit` to see them.\n",
            census.len() - limit
        ));
    }
    out
}

/// Runs an opener as **transition, then report**, announcing the two milestones the supervisor
/// needs to tell the failure modes apart.
///
/// The split is where correctness lives. `transition` claims the target; `report` is the
/// diagnostic (`lm`, `vertarget`, `r`, the TTD lifetime query) whose output the caller reads. A
/// failure is one of three things, and they need different advice:
///
/// * before `commit` — nothing was created, and opening again is the correct recovery;
/// * after `commit` — the target exists and the *wait* failed, so opening again would attach a
///   second time or start a second process;
/// * after `Opened` — only the diagnostic failed; the session is fine.
///
/// The supervisor infers which from the milestones that arrived before the `Done`, so the error
/// text lives there, with the session handle it has to quote.
///
/// win-kexp's openers expose the first seam as `x_begin()` returning a `PendingTarget` guard,
/// which cannot exist unless the side effect succeeded — so `commit()` between the guard and its
/// `wait()` is enforced by the type rather than by convention (glslang/win-kexp#71).
fn open<T, R>(id: u64, transition: T, report: R) -> Result<String, String>
where
    T: FnOnce(&dyn Fn()) -> Result<(), String>,
    R: FnOnce() -> Result<String, String>,
{
    transition(&|| {
        emit(&WorkerMessage::Committed { id });
    })?;
    emit(&WorkerMessage::Opened { id });
    report()
}

/// The post-attach diagnostic shared by both kernel openers.
fn kernel_report(e: &DebugEngine) -> Result<String, String> {
    // The driver_object/device_object/irp_stack tools use kernel-extension commands
    // (!drvobj/!devobj/!irp) from kdexts.dll, which a bare engine does not auto-load.
    // Best-effort, like open_dump's `.load ext`; harmless if the extension isn't bundled
    // (those tools then report a clean "no export").
    let _ = e.execute_command(".load kdexts");
    e.execute_command("vertarget").map_err(es)
}

/// Resolve an address/offset expression the way `uf`/WinDbg read it: evaluate `? <expr>` first
/// (the MASM evaluator's default base is hex, so a bare `00401234` is 0x00401234 and
/// `module!Dispatch+0x123` resolves), then fall back to pure parsing (backtick / bare-hex, then
/// `0x`/decimal).
fn resolve(e: &DebugEngine, expr: &str) -> Option<u64> {
    e.execute_command(&format!("? {expr}"))
        .ok()
        .as_deref()
        .and_then(parse_eval)
        .or_else(|| parse_windbg_addr(expr))
        .or_else(|| parse_u64(expr).ok())
}

fn run_to_address(e: &DebugEngine, address: &str, wait: u32) -> Result<String, String> {
    let target =
        resolve(e, address).ok_or_else(|| format!("could not resolve address `{address}`"))?;
    let res = e.run_to_address(target, wait).map_err(es)?;
    let mut msg = match res.outcome {
        RunToOutcome::Hit => format!("VERDICT: HIT — execution reached {}\n", fmt_addr(target)),
        RunToOutcome::StoppedElsewhere { stopped_at } => format!(
            "VERDICT: STOPPED ELSEWHERE — stopped at {} before reaching {}\n  \
             (another breakpoint or exception fired first)\n",
            fmt_addr(stopped_at),
            fmt_addr(target)
        ),
        RunToOutcome::Timeout => format!(
            "VERDICT: TIMEOUT — did not reach {} within {wait} ms\n  \
             (the current input/state likely does not drive execution to this block)\n",
            fmt_addr(target)
        ),
    };
    if !res.output.trim().is_empty() {
        msg.push_str("---- debugger output ----\n");
        msg.push_str(&res.output);
    }
    Ok(msg)
}

fn reachable(e: &DebugEngine, args: ReachabilityOp) -> Result<String, String> {
    // Resolve the target VA: an absolute address, or module+RVA rebased against the module's
    // live base from `lm m <module>`. Both sides go through `resolve`, so a value pasted from
    // WinDbg — a `hi`lo` backtick address or a digit-only 32-bit address — reads consistently.
    let target = match (&args.address, &args.module, &args.rva) {
        // Reject conflicting target forms rather than silently ignoring one — analysing the
        // wrong target would give a misleading verdict.
        (Some(_), Some(_), _) | (Some(_), _, Some(_)) => {
            return Err("provide `address` OR `module`+`rva`, not both".to_string());
        }
        (Some(a), None, None) => {
            resolve(e, a).ok_or_else(|| format!("could not resolve target address `{a}`"))?
        }
        (None, Some(m), Some(r)) => {
            let rva = resolve(e, r).ok_or_else(|| format!("could not resolve rva `{r}`"))?;
            let lm = e.execute_command(&format!("lm m {m}")).map_err(es)?;
            let base = parse_lm_base(&lm)
                .ok_or_else(|| format!("module `{m}` not found (`lm m {m}` returned):\n{lm}"))?;
            base.checked_add(rva)
                .ok_or_else(|| "module base + rva overflowed u64".to_string())?
        }
        _ => return Err("provide `address`, or both `module` and `rva`".to_string()),
    };

    // Resolve `from` to a numeric VA so a mid-function start (a handler scoped past a switch)
    // is honored; `None` (unresolvable) starts at the entry.
    let seed_start = resolve(e, &args.from);

    // A real `uf` lists backtick addresses or at least a "module!Func:" label; error text
    // ("Couldn't resolve...", "no code") lacks both and prunes the branch. parse_uf then
    // discards any non-disassembly. Held in a `&mut` binding so the same disassembler drives
    // both the walk and the recipe.
    let mut uf = |arg: &str| match e.execute_command(&format!("uf {arg}")) {
        Ok(t) if t.contains('`') || t.contains(':') => Some(t),
        _ => None,
    };

    let rpt = reachability(
        &args.from,
        seed_start,
        target,
        args.max_functions,
        args.max_depth,
        &mut uf,
    );

    if rpt.from_entry.is_none() {
        return Err(format!(
            "could not disassemble `from` ({}): `uf` returned no function. Check the \
             symbol/address and that the module is loaded.",
            args.from
        ));
    }

    // On a REACHABLE verdict, re-walk the path functions to emit the directional recipe (which
    // branch each on-path `jcc` must take, and what it tests).
    let mut out = format_report(&rpt);
    if rpt.verdict_reachable && args.recipe {
        let recipes = path_recipe(&args.from, seed_start, &rpt, &mut uf);
        out.push_str(&format_recipe(&recipes));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- pool walk diagnostics ------------------------------------------------------

    fn report_with(complete: bool, diagnostics: &[&str]) -> query::PoolSnapshotReport {
        query::PoolSnapshotReport {
            total_chunks: 4211,
            allocated_chunks: 3007,
            complete,
            diagnostics: diagnostics.iter().map(|line| line.to_string()).collect(),
        }
    }

    /// A flood of one complaint plus one of another — a live walk in miniature. The flood is
    /// deliberately larger than the walk's verbatim cap, which is the whole difficulty.
    fn flooded_report() -> query::PoolSnapshotReport {
        let mut lines: Vec<String> = (0..500)
            .map(|node| format!("unreadable VS free tree node {node:#018x}: sparse"))
            .collect();
        lines.push("per-session paged heaps are not included".to_string());
        query::PoolSnapshotReport {
            total_chunks: 4211,
            allocated_chunks: 3007,
            complete: false,
            diagnostics: lines.into_iter().collect(),
        }
    }

    #[test]
    fn diagnostics_group_by_category_commonest_first() {
        let report = report_with(
            true,
            &[
                "unreadable VS free tree node 0xaaaaaaaaaaaaaaaa: sparse",
                "unreadable VS free tree node 0xbbbbbbbbbbbbbbbb: sparse",
                "unreadable VS free tree node 0xcccccccccccccccc: sparse",
                "per-session paged heaps are not included",
            ],
        );
        let categories = diagnostic_categories(&report.diagnostics);
        assert_eq!(categories.len(), 2);
        assert_eq!(categories[0].total, 3);
        assert!(
            categories[0]
                .shape
                .starts_with("unreadable VS free tree node")
        );
        assert_eq!(categories[1].total, 1);
    }

    /// The count in the header is the walk's, not the length of the sample the walk kept.
    ///
    /// Measured on a live 26100 kernel this read "71 diagnostic(s)" for a walk that made
    /// ~7,700 complaints, because the number came from counting the surviving lines. It
    /// describes the collapsing and reads as a fact about the pool (glslang/windbg-mcp#77).
    #[test]
    fn the_walk_report_counts_what_the_walk_emitted() {
        let report = flooded_report();
        let kept = report.diagnostics.examples().len();
        assert!(
            kept < 501,
            "the fixture must exercise the cap, or it proves nothing: {kept} kept"
        );

        let rendered = render_walk_report(&report);
        assert!(
            rendered.contains("501 diagnostic(s) in 2 categories"),
            "{rendered}"
        );
        assert!(
            !rendered.contains(&format!("{kept} diagnostic(s)")),
            "the sample size must not be presented as the walk's count: {rendered}"
        );
    }

    /// Every category's count is the true one, and no count is hidden behind a placeholder —
    /// the two remaining faults from the same cause. Before, the collapse summaries arrived
    /// as ordinary lines, so they were re-grouped into categories of their own and their
    /// counts blanked by this side's address-masking (`and 492 more` → `and <addr> more`).
    #[test]
    fn categories_are_findings_not_collapse_summaries() {
        let rendered = render_walk_report(&flooded_report());
        assert!(rendered.contains("500x"), "{rendered}");
        assert!(
            !rendered.contains("more like"),
            "a collapse summary must not appear as a category: {rendered}"
        );
        assert!(
            !rendered.contains("<addr>"),
            "nothing may mask a count: {rendered}"
        );
    }

    #[test]
    fn diagnostics_filter_is_a_case_insensitive_substring() {
        let report = report_with(
            true,
            &[
                "cannot fully discover heap 0xffff8c8f0d300000: read failed",
                "LFH slot 0xffffb28ac16fcf30+0xe0 would cross a page",
                "rejecting page segment 0xdeadbeef with invalid signature",
            ],
        );
        // The whole point: find the one line about a specific heap among the noise.
        let hits = select_examples(&report.diagnostics, Some("FFFF8C8F0D300000"));
        assert_eq!(hits.len(), 1);
        assert!(hits[0].starts_with("cannot fully discover heap"));

        assert_eq!(
            select_examples(&report.diagnostics, Some("cross a page")).len(),
            1
        );
        assert_eq!(select_examples(&report.diagnostics, None).len(), 3);
        assert!(select_examples(&report.diagnostics, Some("no such text")).is_empty());
    }

    /// A report with far more of both halves than any budget will print.
    ///
    /// The shapes are told apart by *wording*, not by a number: the walk generalises every
    /// number-bearing token, so `complaint 1` and `complaint 2` would be one shape and the
    /// fixture would quietly collapse to a single category.
    fn crowded_report() -> query::PoolSnapshotReport {
        let lines: Vec<String> = ('a'..='i')
            .flat_map(|first| ('a'..='j').map(move |second| format!("{first}{second}")))
            .flat_map(|kind| {
                (0..20).map(move |node| format!("cannot read {kind} at node {node:#018x}"))
            })
            .collect();
        query::PoolSnapshotReport {
            total_chunks: 4211,
            allocated_chunks: 3007,
            complete: true,
            diagnostics: lines.into_iter().collect(),
        }
    }

    /// Counts the rendered diagnostic rows — verbatim messages and category counts alike.
    fn rendered_rows(rendered: &str) -> usize {
        rendered
            .lines()
            .filter(|line| line.starts_with("  ") && !line.trim().is_empty())
            .count()
    }

    /// `limit` bounds the whole reply, not each section of it.
    ///
    /// The worker builds the reply as one `String` before it crosses the pipe, which is why
    /// `MAX_POOL_ROWS` exists at all — an unbounded listing is a request to allocate a
    /// snapshot-sized buffer, and a worker killed mid-session costs the caller the session.
    /// Two sections that each restart the budget quietly double the ceiling the clamp was
    /// chosen to enforce.
    #[test]
    fn the_row_limit_bounds_the_whole_listing() {
        let report = crowded_report();
        for limit in [1, 7, 60, 200] {
            let rendered = render_diagnostics(&report, None, limit);
            let rows = rendered_rows(&rendered);
            assert!(
                rows <= limit,
                "limit {limit} produced {rows} rows:\n{rendered}"
            );
        }

        // And it must still spend the budget rather than hoard it: a listing that prints two
        // rows under a limit of 60 satisfies the bound above and is useless.
        let rendered = render_diagnostics(&report, None, 60);
        assert_eq!(rendered_rows(&rendered), 60, "{rendered}");
    }

    /// Neither half may be squeezed out by the other. The categories carry the counts, so a
    /// flood of verbatim examples taking the whole budget would reintroduce #77 one level up:
    /// a listing whose only visible numbers describe the sample.
    #[test]
    fn both_halves_of_the_listing_get_a_share() {
        let (examples, categories) = split_row_budget(60, 900, 90);
        assert!(examples > 0 && categories > 0, "{examples}, {categories}");
        assert_eq!(examples + categories, 60);

        // The common shape: few categories, many examples. The categories fit whole and the
        // examples take everything left, rather than each half being held to half.
        assert_eq!(split_row_budget(60, 71, 24), (36, 24));

        // Nothing is truncated when both halves already fit.
        assert_eq!(split_row_budget(60, 5, 3), (5, 3));
    }

    /// Filtering by a concrete address — the tool's own documented example — can match a kept
    /// message but never a category, because generalising numbers away is exactly what lets a
    /// category carry a count. So this is the one shape of request that legitimately has no
    /// volume to report, and it must say so rather than promise one: a header pointing at
    /// counts that were never rendered leaves a capped sample as the only figure on the page,
    /// which is #77's mistake moved into the prose.
    #[test]
    fn an_address_filter_admits_it_has_no_volume_to_report() {
        let report = report_with(
            true,
            &[
                "cannot fully discover heap 0xffff8c8f0d300000: read failed",
                "LFH slot 0xffffb28ac16fcf30+0xe0 would cross a page",
            ],
        );
        let rendered = render_diagnostics(&report, Some("ffff8c8f0d300000"), 10);
        assert!(
            rendered.contains("cannot fully discover heap"),
            "{rendered}"
        );
        assert!(
            rendered.contains("No category matches"),
            "an example-only match must say the volume is missing: {rendered}"
        );
        // And it must point somewhere: "no counts" without a way to get them is a dead end.
        assert!(
            rendered.contains("Filter on the wording instead"),
            "{rendered}"
        );

        // The wording filter is the one that *can* answer it, and must not carry the note.
        let rendered = render_diagnostics(&report, Some("discover heap"), 10);
        assert!(rendered.contains("1 category"), "{rendered}");
        assert!(!rendered.contains("No category matches"), "{rendered}");

        // Nor may an unfiltered listing, which has every category by definition.
        let rendered = render_diagnostics(&report, None, 10);
        assert!(!rendered.contains("No category matches"), "{rendered}");
    }

    /// An address only ever appears in a kept message — the categories have had theirs
    /// generalised away — so a filter that finds one must still not leave the reader
    /// believing the sample is the volume.
    #[test]
    fn a_filtered_listing_reports_the_walk_not_the_sample() {
        let report = flooded_report();
        let rendered = render_diagnostics(&report, Some("free tree node"), 10);
        assert!(
            rendered.contains("501 diagnostic(s)"),
            "the walk's own count is missing: {rendered}"
        );
        assert!(
            rendered.contains("500x"),
            "the matching category owes its true total: {rendered}"
        );
    }

    fn report(complete: bool) -> query::PoolSnapshotReport {
        report_with(complete, &[])
    }

    /// A found-something answer carries its own count, and that count is only a total if the
    /// walk finished. Left unsaid, "3 allocations" from a walk that reached a fraction of the
    /// pool reads as "there are exactly 3".
    #[test]
    fn an_incomplete_walk_says_so_even_when_it_found_something() {
        let caveat = coverage_caveat(&report(false)).expect("an incomplete walk must be flagged");
        assert!(caveat.contains("INCOMPLETE"), "{caveat}");
        assert!(caveat.contains("4211"), "{caveat}");
        // Not merely "incomplete": the caller has to know which way the number is wrong.
        assert!(caveat.contains("floor"), "{caveat}");
    }

    /// The other half: a complete walk must not decorate every answer with a warning, or the
    /// warning stops meaning anything on the walk that matters.
    #[test]
    fn a_complete_walk_adds_no_caveat() {
        assert_eq!(coverage_caveat(&report(true)), None);
    }

    /// The filtered list has the same failure mode as a tag result: "1 of 2 diagnostic(s)" is
    /// an exact-looking claim, and a walk that stopped before whole heaps never produced the
    /// diagnostics those heaps would have emitted.
    #[test]
    fn filtered_diagnostics_carry_the_coverage_state() {
        let lines = [
            "cannot fully discover heap 0xffff8c8f0d300000: read failed",
            "LFH slot 0xffffb28ac16fcf30+0xe0 would cross a page",
        ];
        let rendered = render_diagnostics(&report_with(false, &lines), Some("heap"), 10);
        assert!(
            rendered.contains("cannot fully discover heap"),
            "{rendered}"
        );
        assert!(rendered.contains("INCOMPLETE"), "{rendered}");

        let rendered = render_diagnostics(&report_with(true, &lines), Some("heap"), 10);
        assert!(
            rendered.contains("cannot fully discover heap"),
            "{rendered}"
        );
        assert!(!rendered.contains("INCOMPLETE"), "{rendered}");
    }

    // ---- pool address parsing ------------------------------------------------------

    /// The form debugger output actually prints. Callers paste these straight from a
    /// `dq`/`!pool` line, backtick and all.
    #[test]
    fn pool_addr_accepts_the_backtick_form() {
        assert_eq!(
            parse_pool_addr("ffffc00f`6ec02f90"),
            Ok(0xffffc00f_6ec02f90)
        );
    }

    /// A bare run of 8+ hex digits is hex, matching WinDbg rather than Rust. `6ec02f90`
    /// is a plausible decimal string too, and reading it as decimal would silently point
    /// the query at unrelated memory.
    #[test]
    fn pool_addr_reads_a_bare_run_as_hex() {
        assert_eq!(parse_pool_addr("6ec02f90"), Ok(0x6ec02f90));
        assert_eq!(parse_pool_addr("00401000"), Ok(0x0040_1000));
    }

    /// Shorter tokens fall through to the decimal/`0x` parser, since the WinDbg form
    /// deliberately requires 8+ digits so it cannot swallow a mnemonic or short immediate.
    #[test]
    fn pool_addr_falls_through_to_prefixed_and_decimal() {
        assert_eq!(parse_pool_addr("0x1000"), Ok(0x1000));
        assert_eq!(parse_pool_addr("4096"), Ok(4096));
        // 0x-prefixed stays hex even when long enough to reach the WinDbg parser, because
        // the `x` is not a hex digit and that parser rejects it.
        assert_eq!(
            parse_pool_addr("0xffffc00f6ec02f90"),
            Ok(0xffffc00f_6ec02f90)
        );
    }

    #[test]
    fn pool_addr_rejects_nonsense() {
        assert!(parse_pool_addr("not-an-address").is_err());
        assert!(parse_pool_addr("").is_err());
    }

    // ---- the protocol channel this worker was handed -------------------------------

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|a| a.to_string()).collect()
    }

    /// The ordinary case: the supervisor's command line, read back as the two handles.
    #[test]
    fn the_channel_is_read_off_the_command_line() {
        let handles = channel_handles(&args(&[
            "windbg-mcp.exe",
            WORKER_FLAG,
            "--requests-handle=132",
            "--messages-handle=140",
        ]));
        assert_eq!(handles, Ok((132, 140)));
    }

    /// Every way the pair can be missing or unusable is refused, and none of them may fall back
    /// to a standard handle: a worker that quietly spoke the protocol over stdout again would be
    /// back to sharing it with whatever an extension prints, which is the whole exposure.
    #[test]
    fn a_worker_without_a_usable_channel_is_refused() {
        for line in [
            // Started by hand, with no channel at all.
            args(&["windbg-mcp.exe", WORKER_FLAG]),
            // Half a channel is no channel.
            args(&["windbg-mcp.exe", WORKER_FLAG, "--requests-handle=132"]),
            args(&["windbg-mcp.exe", WORKER_FLAG, "--messages-handle=140"]),
            // Present but unusable: a null handle fails every read and write, silently.
            args(&[
                "windbg-mcp.exe",
                WORKER_FLAG,
                "--requests-handle=0",
                "--messages-handle=140",
            ]),
            args(&[
                "windbg-mcp.exe",
                WORKER_FLAG,
                "--requests-handle=132",
                "--messages-handle=oops",
            ]),
        ] {
            assert!(
                channel_handles(&line).is_err(),
                "accepted a command line that carries no usable channel: {line:?}"
            );
        }
    }

    // The watchdog budget, as arithmetic. What it is *wired to* needs a real engine and a real
    // target, and lives in `tests/mcp_smoke.rs`'s bounded-command tier — the wiring now spans two
    // processes, so the shipped binary is the only place it exists whole.

    /// The everyday case: nothing queued ahead, so the watchdog fires one headroom before the
    /// caller's wait expires. This is the number that keeps a runaway command from outliving the
    /// tool call that started it.
    #[test]
    fn an_unqueued_command_is_bounded_one_headroom_short_of_the_callers_patience() {
        let patience = Duration::from_secs(300);
        assert_eq!(
            watchdog_budget_ms(patience, Duration::ZERO),
            (300 - 15) * 1000
        );
    }

    /// The property the queue-awareness exists for, stated as the invariant rather than as an
    /// arithmetic identity: **queue wait + watchdog budget must not exceed the caller's
    /// patience**, or the caller gives up while the command is still running — the wedge.
    ///
    /// Budgeting from the patience as sent (ignoring the wait) breaks this for every non-zero
    /// wait, which is why it is checked across a spread rather than at one point. That is not a
    /// hypothetical: it is the bug the first cut of the process split shipped, because the
    /// supervisor writes a request the moment it is submitted and the waiting then happens on
    /// the far side of the pipe, where only this process can see it.
    #[test]
    fn a_queued_command_still_aborts_before_its_caller_gives_up() {
        let patience = Duration::from_secs(300);
        for waited in [0, 1, 30, 100, 240, 269] {
            let waited = Duration::from_secs(waited);
            let budget = Duration::from_millis(watchdog_budget_ms(patience, waited) as u64);
            assert!(
                waited + budget <= patience,
                "a command dequeued after {waited:?} gets a {budget:?} budget — it would still \
                 be running at the {patience:?} mark, which is the wedge this bounds"
            );
        }
    }

    /// Past the point where any headroom is left, the budget floors instead of reaching zero —
    /// because zero *disables* win-kexp's watchdog, which would make a command dequeued near the
    /// deadline the one command that runs unbounded.
    ///
    /// The floor deliberately overruns the caller's timeout: by then the caller has already given
    /// up, and the remaining job is to free this worker for the *next* call.
    #[test]
    fn a_command_dequeued_past_the_deadline_is_still_bounded() {
        let patience = Duration::from_secs(300);
        for waited in [290, 300, 600, 86_400] {
            assert_eq!(
                watchdog_budget_ms(patience, Duration::from_secs(waited)),
                15_000,
                "a command dequeued after {waited}s must still arm the watchdog"
            );
        }
    }

    /// A caller whose patience was already exhausted when the request was written (the
    /// supervisor sends 0) must still arm the watchdog, not disable it.
    #[test]
    fn no_patience_left_still_arms_the_watchdog() {
        assert_eq!(watchdog_budget_ms(Duration::ZERO, Duration::ZERO), 15_000);
    }

    /// A patience beyond `u32::MAX` milliseconds (~49 days) must saturate, not wrap: a wrapped
    /// budget could land on 0 and silently disable the watchdog.
    #[test]
    fn an_absurd_patience_saturates_rather_than_wrapping() {
        assert_eq!(
            watchdog_budget_ms(Duration::from_secs(u32::MAX as u64), Duration::ZERO),
            u32::MAX
        );
    }

    // ---- the batch budget -------------------------------------------------

    /// A batch gets what it asked for when the caller can afford it.
    #[test]
    fn a_batch_that_fits_gets_the_deadline_it_asked_for() {
        assert_eq!(
            batch_budget(60_000, Duration::from_secs(300), Duration::ZERO),
            Some(Duration::from_secs(60))
        );
    }

    /// The property that makes the rollback report worth anything: **queue wait + batch budget
    /// must leave the caller a headroom**, so the `always` block has finished and the report has
    /// been written before the tool call gives up. A batch that asks for more than the call
    /// budget is the case that would otherwise break it.
    #[test]
    fn a_batch_never_outlives_the_call_that_started_it() {
        let patience = Duration::from_secs(300);
        // Waits short enough that the floor below is not in play; past it the budget deliberately
        // overruns, exactly as `watchdog_budget_ms`'s does.
        for asked in [60_000, 300_000, 900_000, u32::MAX] {
            for waited in [0, 30, 200, 270] {
                let waited = Duration::from_secs(waited);
                let budget = batch_budget(asked, patience, waited).expect("still worth running");
                assert!(
                    waited + budget <= patience,
                    "asking for {asked}ms after a {waited:?} queue wait yielded {budget:?}, which \
                     runs past the caller's {patience:?}"
                );
            }
        }
    }

    /// The one place a batch parts company with a bounded command: past the point where its
    /// caller can still be answered, it does **not** start.
    ///
    /// `watchdog_budget_ms` floors instead, and is right to — its command is already running and
    /// the job left is to free the worker. A batch has not started, so the same floor would apply
    /// mutations for a caller already told the call timed out, then roll them back with nobody
    /// left to read whether that worked.
    #[test]
    fn a_batch_whose_caller_has_given_up_is_not_started_at_all() {
        // Dequeued long after the caller's timeout.
        assert_eq!(
            batch_budget(120_000, Duration::from_secs(300), Duration::from_secs(400)),
            None
        );
        // And the case a short `WINDBG_MCP_CALL_TIMEOUT_SECS` produces, with no queue wait at all.
        assert_eq!(batch_budget(120_000, Duration::ZERO, Duration::ZERO), None);
        assert_eq!(
            batch_budget(120_000, WATCHDOG_HEADROOM, Duration::ZERO),
            None
        );

        // The boundary: enough left for the headroom plus the smallest batch there can be.
        let least = WATCHDOG_HEADROOM + Duration::from_millis(u64::from(batch::MIN_BATCH_MS));
        assert_eq!(
            batch_budget(120_000, least, Duration::ZERO),
            Some(Duration::from_millis(u64::from(batch::MIN_BATCH_MS)))
        );
        assert_eq!(
            batch_budget(120_000, least - Duration::from_millis(1), Duration::ZERO),
            None
        );
    }

    // ---- the abandon signal -----------------------------------------------
    //
    // Against a local `BatchSignal` rather than the process-wide `BATCH`, so these say nothing
    // about the order the test binary happens to run them in — and so that both sides of the race
    // below can be staged, which against the real one would mean disconnecting a client at an
    // exact instant.

    /// A budget long enough that the remaining-time assertions below are not measuring how fast
    /// this machine runs a test.
    const A_LONG_BATCH: Duration = Duration::from_secs(120);

    /// Stands in for the request id of the teardown doing the telling.
    const TEARDOWN: u64 = 42;

    /// The property the signal exists to hold: a batch never runs with a teardown believing there
    /// is nothing to wait for.
    ///
    /// Whichever way the race falls, at least one side sees the other — the batch refuses to start,
    /// or the signal reports it and says how long it may still take. The forbidden outcome is
    /// *both* missing, which is a worker terminated mid-transaction on the five-second grace.
    #[test]
    fn a_batch_and_the_signal_that_stops_it_cannot_both_miss() {
        // The signal arrives first: the batch must not start.
        let waiting = BatchSignal::new();
        assert_eq!(waiting.abandon(TEARDOWN), None, "nothing is running yet");
        assert!(
            waiting.enter(A_LONG_BATCH).is_none(),
            "a batch that reached the engine after the teardown must not run its mutations"
        );

        // The batch got there first: the signal must report it, so the grace is held open.
        let started = BatchSignal::new();
        let _running = started.enter(A_LONG_BATCH).expect("an ordinary batch runs");
        let within = started.abandon(TEARDOWN).expect(
            "a signal that found a batch running has to say so, or the teardown waits five \
             seconds and kills it mid-transaction",
        );
        assert!(started.abandoned(), "and the batch has to see it");
        // What it reports is what the batch has left, which is what covers the step in flight as
        // well as the rollback after it.
        assert!(
            within <= A_LONG_BATCH && within > A_LONG_BATCH - Duration::from_secs(5),
            "a batch just started should have nearly its whole budget left, not {within:?}"
        );
    }

    /// A batch already past its deadline asks for nothing, rather than reporting a negative
    /// remainder as a huge positive one.
    #[test]
    fn a_batch_that_is_out_of_time_asks_a_teardown_for_none() {
        let signal = BatchSignal::new();
        let _running = signal.enter(Duration::ZERO).expect("it may start");
        assert_eq!(
            signal.abandon(TEARDOWN),
            Some(Duration::ZERO),
            "its budget is spent, so the teardown owes it only the ordinary grace"
        );
    }

    /// A batch that finishes retracts what it was promised for, so a teardown stops waiting on a
    /// transaction that is already unwound.
    ///
    /// Without this the promise stands at the figure it had when the teardown arrived — and if the
    /// *release* behind it then hangs, which is exactly what the short grace exists to bound, the
    /// teardown waits out the rest of a batch budget that was spent long ago. Minutes, for a
    /// rollback that finished in seconds.
    #[test]
    fn a_finished_batch_retracts_the_promise_it_was_given() {
        // Nobody was told, so nobody is owed an answer.
        let untold = BatchSignal::new();
        drop(untold.enter(A_LONG_BATCH).expect("it may start"));
        assert_eq!(untold.finish(), None);

        let signal = BatchSignal::new();
        let guard = signal.enter(A_LONG_BATCH).expect("it may start");
        assert!(
            signal.abandon(TEARDOWN).is_some(),
            "the teardown is told this batch may need time"
        );
        let (told, within_ms) = signal
            .finish()
            .expect("so it is owed the news when that stops being true");
        assert_eq!(told, TEARDOWN);
        assert_eq!(signal.finish(), None, "and owed it once");
        drop(guard);

        // What it is told is "now": the batch is done, and the moment it ended is the only thing
        // the worker knows that the supervisor does not. How long the release then gets is the
        // supervisor's to decide, out of the grace it would have given any session — naming an
        // interval here as well would be added to that rather than replacing it.
        // Against `0`, not against `RETRACTED`: comparing the constant with itself would hold
        // whatever it was changed to, which is exactly how a retraction quietly became a second
        // helping of grace once before.
        assert_eq!(
            within_ms, 0,
            "a retraction names the moment the batch ended, not an interval — what the release \
             then gets is the supervisor's own grace, measured from that moment"
        );
    }

    /// Once the batch is over, a teardown gets the short grace again — the extra wait is for a
    /// transaction in flight, not for a session that has ever run one.
    #[test]
    fn a_finished_batch_leaves_nothing_for_a_teardown_to_wait_on() {
        let signal = BatchSignal::new();
        drop(signal.enter(A_LONG_BATCH).expect("it may start"));
        assert_eq!(
            signal.abandon(TEARDOWN),
            None,
            "the batch is done; there is nothing to unwind"
        );
        // Still sticky, though: this session is on its way out and must not start another.
        assert!(signal.enter(A_LONG_BATCH).is_none());
    }

    // ---- binding an interrupt to a job -------------------------------------
    //
    // Against a local `Running` rather than the process-wide `RUNNING`, for the reason above: these
    // stage both orderings of a race that against the real one would mean interrupting a real
    // engine at an exact instant. What is *wired* to it — that the reader raises under this lock
    // and the engine thread claims and releases under it — is `src/worker.rs`'s own code above and
    // the smoke tier's business; what is checked here is that the bookkeeping cannot misattribute.

    fn idle() -> Running {
        Running {
            job: None,
            interrupted: None,
        }
    }

    /// The everyday case: an interrupt raised while a job runs is reported to *that* job, so its
    /// caller is told their result was cut short and the engine's pending break is drained.
    #[test]
    fn an_interrupt_reaches_the_job_that_was_running() {
        let mut running = idle();
        running.claim(7);
        running.interrupt_raised();
        assert!(running.release(7));
    }

    /// The failure the binding exists to prevent, stated as the property: an interrupt is spent by
    /// the job it reached and can never be charged to the next one.
    ///
    /// `SetInterrupt` addresses an engine, not an operation. Without the pairing, a cancel landing
    /// as a search ends would leave a Ctrl+Break pending for whatever ran next — and the caller of
    /// *that* would be told their `go` had been interrupted on request, which nobody asked for.
    #[test]
    fn an_interrupt_is_spent_by_the_job_it_reached() {
        let mut running = idle();
        running.claim(7);
        running.interrupt_raised();
        assert!(running.release(7));

        running.claim(8);
        assert!(
            !running.release(8),
            "the next job inherited an interrupt meant for the one before it"
        );
    }

    /// The other side of the same race: an interrupt that arrives between jobs binds to nothing, so
    /// the job that starts next is not the one it stops.
    ///
    /// This is what the reader's early return reports as "nothing was running". The engine may
    /// still hold a pending break from it — that is what the drain after each job is for — but no
    /// caller is told their complete result was cut short.
    #[test]
    fn an_interrupt_between_jobs_binds_to_nothing() {
        let mut running = idle();
        running.interrupt_raised();
        assert_eq!(running.interrupted, None, "there was no job to bind it to");

        running.claim(9);
        assert!(
            !running.release(9),
            "a job that started after the interrupt must not answer for it"
        );
    }

    // ---- what an interrupted caller is told --------------------------------

    /// A cut-short result keeps what it reached and gains the reason — which is the whole point of
    /// interrupting rather than ending the session.
    #[test]
    fn a_cut_short_result_keeps_its_output_and_says_why() {
        let out = cut_short(Ok("0x1000  41 42 43\n".to_string())).expect("still a result");
        assert!(out.starts_with("0x1000  41 42 43"), "{out}");
        assert!(out.contains("interrupted on request"), "{out}");

        // And a failure keeps its debugger text: "this is why it stopped" is not a claim about
        // what it would otherwise have said.
        let err = cut_short(Err("Memory access error".to_string())).expect_err("still a failure");
        assert!(err.starts_with("Memory access error"), "{err}");
        assert!(err.contains("interrupted on request"), "{err}");
    }

    /// An operation interrupted before it printed anything still explains itself, rather than
    /// coming back as an empty success the caller would read as "found nothing".
    #[test]
    fn a_cut_short_result_with_no_output_is_still_an_explanation() {
        let out = cut_short(Ok(String::new())).expect("still a result");
        assert!(out.contains("interrupted on request"), "{out}");
        assert!(
            !out.starts_with('\n'),
            "no blank lead-in when there is nothing above it: {out:?}"
        );
    }

    // ---- the pool walk budget (#75) ----------------------------------------

    /// A pool walk is bounded by the *caller's* deadline, not by win-kexp's default.
    ///
    /// Both directions matter, which is why this checks a short call budget and the default one.
    /// Taking `DEFAULT_WALK_BUDGET` (120s) meant a host configured with a 60s call timeout got a
    /// walk that outlived its caller — the wedge, reintroduced from this side — while the 300s
    /// default stopped at 120s and handed back a partial snapshot with minutes left to spend.
    #[test]
    fn a_pool_walk_is_bounded_by_the_call_that_asked_for_it() {
        const WIN_KEXP_DEFAULT: Duration = Duration::from_secs(120);

        let short = Duration::from_secs(60);
        let budget = walk_budget(short, Duration::ZERO).expect("60s leaves time to walk in");
        assert!(
            budget < short,
            "a walk under a {short:?} call budget got {budget:?}; it would still be walking when \
             its caller gave up"
        );
        assert!(
            budget < WIN_KEXP_DEFAULT,
            "which is what taking the walker's own default did"
        );

        let generous = Duration::from_secs(300);
        assert!(
            walk_budget(generous, Duration::ZERO).expect("300s does too") > WIN_KEXP_DEFAULT,
            "a caller who can wait five minutes should not be handed a partial snapshot at two"
        );
    }

    /// The same invariant the bounded command holds, for the same reason: **queue wait + walk
    /// budget must not exceed the caller's patience**. A pool query can sit behind another job on
    /// its session, and a budget derived from the patience as sent would spend it all again.
    ///
    /// Checked down to patiences *below* the headroom, which is where the first cut of this failed:
    /// it borrowed the watchdog's floor, so every patience under 15s got a 15s walk. A 10s call
    /// budget yielded a walk allowed to run half again as long as the call — #75's own complaint,
    /// arriving at the small end.
    #[test]
    fn a_queued_pool_walk_still_stops_before_its_caller_gives_up() {
        for patience in [10, 15, 20, 60, 300] {
            let patience = Duration::from_secs(patience);
            for waited in [0, 1, 5, 30, 100, 240, 269, 400] {
                let waited = Duration::from_secs(waited);
                // No budget means no walk, which trivially cannot outlive anybody.
                let Some(budget) = walk_budget(patience, waited) else {
                    continue;
                };
                assert!(
                    waited + budget <= patience,
                    "a walk dequeued after {waited:?} of a {patience:?} budget got {budget:?} — it \
                     would still be walking after its caller gave up"
                );
            }
        }
    }

    /// A caller who cannot be answered gets **no walk at all**, rather than one floored to a
    /// headroom.
    ///
    /// Two ways in, and both are real: a server configured with a call timeout at or under the
    /// headroom, and a query dequeued after its caller has given up. Neither can be answered, and
    /// the work would not even leave a cache behind — win-kexp caches complete snapshots only, so a
    /// budget-truncated walk is discarded and the next query walks again regardless.
    #[test]
    fn a_pool_walk_with_no_time_left_is_not_run_at_all() {
        assert_eq!(
            walk_budget(Duration::from_secs(10), Duration::ZERO),
            None,
            "a 10s call budget is entirely reply headroom; there is no walk to be had"
        );
        assert_eq!(
            walk_budget(WATCHDOG_HEADROOM, Duration::ZERO),
            None,
            "and the headroom itself is the boundary, not the first affordable value"
        );
        assert_eq!(
            walk_budget(WATCHDOG_HEADROOM + Duration::from_millis(1), Duration::ZERO),
            Some(Duration::from_millis(1)),
            "one millisecond past it is a walk, however short"
        );
        // The queue-wait route to the same place: patience that was ample when the request was
        // written and is spent by the time the engine reaches it.
        assert_eq!(
            walk_budget(Duration::from_secs(300), Duration::from_secs(290)),
            None
        );
        assert_eq!(
            walk_budget(Duration::from_secs(300), Duration::from_secs(400)),
            None,
            "and a wait past the whole budget saturates rather than wrapping to a huge one"
        );
    }

    /// The refusal applies to a query that **must** walk. One that may be served from the cached
    /// snapshot is still worth trying, because a cache read costs nothing that a caller with no time
    /// left cannot afford.
    #[test]
    fn only_a_query_that_must_walk_is_refused_for_want_of_time() {
        assert!(PoolOp::census(Some(true), None).refreshes());
        assert!(PoolOp::find_tag("Tgsm".into(), None, Some(true), None).refreshes());
        assert!(PoolOp::chunk("0x1000".into(), Some(true)).refreshes());
        assert!(PoolOp::diagnostics(None, Some(true), None).refreshes());

        // The default, and the reason the distinction is worth making at all.
        assert!(!PoolOp::census(None, None).refreshes());
        assert!(!PoolOp::chunk("0x1000".into(), Some(false)).refreshes());
    }
}
