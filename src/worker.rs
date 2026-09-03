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
//! blocks in `WaitForEvent(INFINITE)` with no cancellation path (dbgscope's `SetInterrupt`
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
//! It is also not new here — dbgscope's two watchdogs have always Ctrl+Broken the engine from a
//! thread of their own, on every bounded command and every go/step. What this adds is a caller who
//! can ask for the same thing, and the binding ([`Running`]) that decides *which job* the request
//! reaches. See `AGENTS.md` and the `DECISIONS.md` entry for the invariant and its boundary.

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, PipeReader, PipeWriter, Write};
use std::num::NonZeroUsize;
use std::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use dbgscope::dbgeng::{
    BreakpointAt, BreakpointSpec, CommandRun, DebugEngine, InterruptHandle, Interruption,
    RunToOutcome, WaitOutcome,
};
use dbgscope::heap::{self as heap_query, HeapAllocation, HeapBackend, HeapState, HeapWalk};
use dbgscope::pool::query::{self, PoolPageFilter, PoolWalk};
use dbgscope::pool::{
    DiagnosticShape, PoolDiagnostics, PoolSpan, PoolState, display_is_ambiguous, parse_raw_tag,
    parse_tag, raw_tag_hex, tag_label,
};
use windows_sys::Win32::Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation};

use crate::batch::{self, BatchOp, Debuggee, Ran};
use crate::proto::{
    EngineOp, Failed, HeapBackendFilter, HeapOp, HeapStateFilter, Interrupted, MAX_MODULE_ROWS,
    Output, PoolOp, ReachabilityOp, SymbolPathSetting, WorkerMessage, WorkerRequest,
};
use crate::server::{
    EXEC_WAIT_MS, fmt_addr, format_recipe, format_report, hexdump, matches_module_pattern,
    module_pattern, parse_eval, parse_lm_base, parse_u64, parse_windbg_addr, path_recipe,
    reachability,
};
use crate::structured;
use crate::target::{Arch, Opening};
use crate::triage::{self, Analysis, AttributedFrame, Attribution};
use crate::walk;

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

/// The flag naming the target this worker was spawned for, when its architecture could be read
/// before an engine existed — a dump or a live process ([`crate::target::Opening`]).
///
/// It exists because **the engine has to be built before the opener arrives**. A 32-bit target
/// wants an engine in a 32-bit process, and that cannot be decided after the fact: `Ready` means
/// the engine exists, `INTERRUPT` is taken from it once into a `OnceLock`, and an engine swapped
/// mid-session would leave `interrupt` pointing at a dead one. So the supervisor forwards what it
/// already holds and this worker asks the same question again — see [`build_engine`].
///
/// A dump path is a caller's and a pid is a number, neither of them secret: the connection
/// strings that *are* travel down the protocol pipe instead
/// ([`crate::proto::EngineOp::AttachKernel`]), and never on a command line.
pub const TARGET_FLAG: &str = "--engine-target=";

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
/// (a finite timeout returns `E_NOTIMPL` and never drives the KD link), so dbgscope's
/// `PendingTarget::wait` ignores this for that one case. That unbounded wait is the reason
/// sessions live in their own process.
const LOAD_WAIT_MS: u32 = 60_000;

/// Whether the wait that *is* the load finished it, as an opener's `transition` reads it.
///
/// `open_dump` and `open_trace` defer the real work to the next `WaitForEvent`, so this wait is
/// not a wait *for* the load — it is the load. Only [`WaitOutcome::Stopped`] is one that finished:
/// the engine processed the target and stopped on it.
///
/// **[`WaitOutcome::Expired`] is the one this was silently passing**, and it could not have done
/// otherwise: until [dbgscope#136] a finite wait answered `Result<(), _>`, and `S_FALSE` — the
/// bound passing with the load still going — was flattened by the generated wrapper into the same
/// `Ok` a stop gets. So a dump too large, or a symbol path too cold, to finish inside
/// [`LOAD_WAIT_MS`] was reported as an open that worked, and whatever the caller did next failed
/// for a reason nothing connected to the open. The two comments at the call sites have said "a
/// load wait that times out still leaves DbgEng holding the dump" since they were written; that is
/// what `commit()` above the wait is for, and this is the other half of it finally arriving — the
/// caller is told the session holds the target, so `end_session` is the recovery and opening again
/// would claim a second one.
///
/// [`WaitOutcome::OnRequest`] is a host interrupting the load through `interrupt`. Not an error
/// about the target, but not a finished load either, and the same advice applies.
/// [`WaitOutcome::Deadline`] cannot arise — a finite bound arms no watchdog — so it shares that
/// arm rather than being given a message this cannot produce.
///
/// **The reachability of `Expired` here is argued, not measured.** dbgscope measured a finite
/// expiry on a *running* target (`S_FALSE` at 312 ms for a 300 ms bound); nothing has held a dump
/// load past sixty seconds on purpose. So this is unit-tested as a mapping, and what is not
/// claimed is how often the mapping fires.
///
/// [dbgscope#136]: https://github.com/glslang/dbgscope/issues/136
fn load_completed(outcome: WaitOutcome, target: &str) -> Result<(), String> {
    match outcome {
        WaitOutcome::Stopped { .. } => Ok(()),
        WaitOutcome::Expired => Err(format!(
            "the {target} had not finished loading after {LOAD_WAIT_MS} ms. The session holds it, \
             so end_session releases it; opening it again would claim a second target. A large \
             dump or a cold symbol path is the usual cause."
        )),
        WaitOutcome::OnRequest | WaitOutcome::Deadline => Err(format!(
            "loading the {target} was interrupted before it finished. The session holds it, so \
             end_session releases it; opening it again would claim a second target."
        )),
    }
}

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

/// How much of a `crash_triage`'s patience is kept back for the reads that follow its `!analyze`.
///
/// Those reads — the stack walk, the per-frame module lookups, the process name — are direct engine
/// calls rather than commands, so **no watchdog can cut them short**, and a frame whose symbol has
/// to be fetched from a symbol server can block for a long time inside one. Time nothing can bound
/// is time that has to be reserved instead, and this is the reservation.
///
/// [`WATCHDOG_HEADROOM`] again, deliberately: it is already this file's answer to "how long does
/// the part after the bounded work need?", and a second constant beside it would be a second
/// number to keep in step with the first for no reason. With the default 300s call timeout it
/// costs nothing; on a host configured much tighter it is what makes the triage skip its analysis
/// and *say so*, rather than run one that outlives the caller.
const TRIAGE_READ_RESERVE: Duration = WATCHDOG_HEADROOM;

/// The watchdog deadline for a command that waited `queued` in this worker's queue, given the
/// `patience` its caller had left when the supervisor sent it.
///
/// The caller's timeout starts at submission, but a command may sit behind another job for the
/// same session (a backgrounded `go`, a long `!ttdext.index`) before the engine reaches it.
/// Budgeting from what *remains* — not from the patience as sent — is what makes the interrupt
/// fire before the caller gives up regardless of queue wait.
///
/// Floored at [`WATCHDOG_HEADROOM`] rather than allowed to reach zero, because zero *disables*
/// dbgscope's watchdog: a command dequeued at or past the deadline would then be the one command
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
/// dbgscope caches only complete snapshots — an incomplete one invalidates the entry instead. So a
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
    /// The job pumping a target an [`EngineOp::Resume`] set running, or `None`.
    ///
    /// Read by the request reader when a teardown arrives, and it is the one operation a teardown
    /// must *break out of* rather than wait behind. Every other job ends on its own: a command
    /// has a watchdog, a walk checks a deadline, a batch is told to stop at its next step. This
    /// one ends when the **target** stops, which is a thing outside this process and may be
    /// hours away — so an `end_session` queued behind it would sit there, its grace would expire,
    /// and the worker would be killed still holding the target. Tracked here rather than as a
    /// flag beside this lock, so "which job is pumping" and "which job may be interrupted" are
    /// decided together and cannot name different jobs.
    pumping: Option<u64>,
    /// Jobs that were broken in before they reached the engine thread, and must not start.
    ///
    /// The other half of what [`Self::tearing_down`] does for a teardown, for one run rather than
    /// all of them. `break_in` names the job it is for, so a break arriving while that job is
    /// still queued behind another operation has no pump to interrupt — and doing nothing would
    /// let the run start afterwards and hold the target for up to the bound its caller named,
    /// which is the opposite of what they asked for.
    ///
    /// **A set, where the first version was one slot**, and the reasoning for the slot is worth
    /// keeping because it was the right answer to the wrong question. A session holds one run at
    /// a time, so only one queued resume ever *needs* barring — but that is about how many bars
    /// are wanted at once, not about how many requests can arrive. A `break_in` for a run that
    /// has since finished still reaches here (the supervisor sent it while its slot said the run
    /// was going), and it can be overtaken on the way: descheduled between reading the slot and
    /// the send, it lands *after* a later `break_in` has barred a genuinely queued run, and a
    /// single slot would overwrite that bar with a dead id. The queued run would then start.
    ///
    /// It grows by one `u64` per break that misses, and shrinks only in [`Self::claim_pump`],
    /// which is the one place an entry can ever be used. A bar for a job that has already run is
    /// therefore kept for the life of the worker — the alternative is knowing which jobs have
    /// run, which is the same set the other way up and no smaller.
    barred: BTreeSet<u64>,
    /// Whether this worker's session is ending, so no target of its may be set running again.
    ///
    /// Set by the request reader the moment a teardown is read — an [`EngineOp::EndSession`], or
    /// the EOF that says the supervisor has gone — and never cleared, because nothing that
    /// happens after it makes the session live again.
    ///
    /// **It is the other half of [`Self::pumping`], and the pair is what makes the window
    /// between them empty.** Breaking the pump only reaches a resume that has *already started*;
    /// a resume still sitting in the engine thread's queue — behind a long `pool_census`, or
    /// simply not yet dequeued — has nothing to break, so a teardown would find no pump, queue
    /// behind it, and then wait out the whole run it was too early to stop. The two facts are
    /// therefore read and written under the one lock, in opposite orders: the reader sets this
    /// and *then* reads `pumping`, [`resume`] claims `pumping` only after reading this. Whichever
    /// gets there first, the other sees it — so a run is either broken in or never started, and
    /// there is no third outcome where the teardown waits.
    tearing_down: bool,
    /// The job that has entered a phase no break may reach — a [`crate::batch`] running its
    /// `always` block.
    ///
    /// Cleanup is the one thing an interrupt must never touch. A restore cut short returns `Ok`
    /// with partial output like any other interrupted command, so `run_step` records it as a step
    /// that worked and the report says `rollback: COMPLETE` with the patch still applied — the
    /// exact loss the whole transaction machinery exists to prevent, arriving through the tool
    /// meant to be the gentle way out.
    uninterruptible: Option<u64>,
}

static RUNNING: Mutex<Running> = Mutex::new(Running {
    job: None,
    interrupted: None,
    pumping: None,
    barred: BTreeSet::new(),
    tearing_down: false,
    uninterruptible: None,
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

    /// Closes `id` to interrupts for the rest of its life. See [`Self::uninterruptible`].
    fn seal(&mut self, id: u64) {
        self.uninterruptible = Some(id);
    }

    /// Whether a break may still be raised for `id`.
    fn sealed(&self, id: u64) -> bool {
        self.uninterruptible == Some(id)
    }

    /// Records that `id` is pumping a target it set running, or that it has stopped doing so.
    fn pump(&mut self, id: Option<u64>) {
        self.pumping = id;
    }

    /// Claims the pump for `id`, or says why this resume may not set the target going.
    ///
    /// A refusal rather than a wait, either way: whatever stopped it — a teardown already read,
    /// or a `break_in` on this very run — arrived *before* the engine thread got here, so a run
    /// started now could only end by being broken in a moment later, having moved a target nobody
    /// asked to move.
    fn claim_pump(&mut self, id: u64) -> Result<(), PumpRefused> {
        if self.tearing_down {
            return Err(PumpRefused::TearingDown);
        }
        // Taken rather than read: this is the only place a bar can be used, and the job it names
        // is being refused right now and will never be dequeued again.
        if self.barred.remove(&id) {
            return Err(PumpRefused::BrokenIn);
        }
        self.pumping = Some(id);
        Ok(())
    }

    /// What a break named for `named` does when that is **not** the job on the engine thread —
    /// or `None` when it is, and the ordinary path applies.
    ///
    /// It bars it ([`Self::barred`]), without asking whether the job is still queued or has
    /// already finished, **because nothing here can tell**. The first draft did ask, by comparing
    /// ids: they are minted in order, so one above the running job looked like one that had not
    /// started. That is not sound. `Sessions::call_within` and `Sessions::start_execution` both
    /// allocate a job id *before* taking `Session::submit_gate`, so a task descheduled between
    /// the two is overtaken and enqueued behind a **larger** id — and the run that most needs
    /// barring is then read as one that has already ended, left to start when the queue drains
    /// and hold the target for the bound it named. Ordering the ids would work and is the wrong
    /// fix: it keeps the inference and props it up with an invariant three call sites have to
    /// maintain, where the next one to allocate an id elsewhere breaks it silently again.
    ///
    /// Barring unconditionally needs no invariant. Ids are minted once per session and never
    /// reused, so barring a job that has already run is a no-op that can never match anything
    /// later — provided the bars are kept apart, which is what [`Self::barred`] being a set is
    /// for.
    ///
    /// What it costs is the *report*: this can no longer say which of the two it was, and so it
    /// does not. That precision was invented rather than known.
    fn break_for_other(&mut self, named: u64) -> Option<Interrupted> {
        if self.job == Some(named) {
            return None;
        }
        self.barred.insert(named);
        Some(Interrupted::Barred)
    }

    /// Records that this session is ending, and reports the job pumping a resumed target if one
    /// had already started. See [`Self::tearing_down`].
    fn begin_teardown(&mut self) -> Option<u64> {
        self.tearing_down = true;
        self.pumping
    }

    /// Ends `id`'s claim, reporting whether an interrupt was bound to it.
    ///
    /// Taken rather than read, so an interrupt is spent by the job it reached: the next job starts
    /// with nothing outstanding and cannot inherit a cut-short label — or a drain — that belongs
    /// to the one before it.
    fn release(&mut self, id: u64) -> bool {
        self.job = None;
        self.pumping = None;
        self.uninterruptible = None;
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

/// [`Running::pump`] on this process's one tracker.
fn pumping(id: Option<u64>) {
    running().pump(id);
}

/// Why a resume was not allowed to set its target going. See [`Running::claim_pump`].
enum PumpRefused {
    /// The session is ending.
    TearingDown,
    /// `break_in` reached this run before it started.
    BrokenIn,
}

/// [`Running::claim_pump`] on this process's one tracker.
fn claim_pump(id: u64) -> Result<(), PumpRefused> {
    running().claim_pump(id)
}

/// Closes `id` to further interrupts and consumes anything already pending on the engine.
///
/// Both under the one lock, which is what makes it a boundary rather than a hope: a raise takes the
/// same lock, so every break is either lodged before this — and drained here, before the first
/// cleanup command runs — or refused after it. Called by a batch as it enters its `always` block.
fn seal_against_interrupts(e: &DebugEngine, id: u64) {
    let mut running = running();
    running.seal(id);
    // Under the lock deliberately: a break raised between the seal and the drain would survive
    // both and land on the first restore command.
    let _ = e.interrupted();
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
    start_log_writer();

    // Optional, and absent for every opener whose architecture cannot be read without an engine.
    // Unlike the two handles above, a missing one is not a fault: it means "nothing about this
    // worker's target was decided before it started", which is the common case. A value that does
    // not parse means the supervisor and this worker disagree about the encoding — a mismatch the
    // handshake's build check is what actually catches — so it is logged rather than fatal, and
    // this worker carries on as though it had been told nothing.
    let target = args
        .iter()
        .find_map(|arg| arg.strip_prefix(TARGET_FLAG))
        .and_then(|value| {
            Opening::parse(value).or_else(|| {
                tracing::warn!(
                    "worker: `{TARGET_FLAG}{value}` is not a target this build can read"
                );
                None
            })
        });

    // Each request is stamped when it is *read*, so the engine thread can tell how long it then
    // waited its turn — the half of the watchdog budget only this process can measure.
    let (tx, rx) = mpsc::channel::<Job>();
    // Reported rather than panicked: the supervisor is waiting for `Ready` or `Fatal`, and a
    // panic here would give it neither — it would see only "the worker exited before it was
    // ready" and lose the reason.
    if let Err(e) = thread::Builder::new()
        .name("dbgeng".into())
        .spawn(move || engine_thread(rx, target))
    {
        emit(&WorkerMessage::Fatal {
            message: format!("could not start the engine thread: {e}"),
        });
        crate::logbridge::flush(LOG_FLUSH);
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
                    stop_resuming();
                }
                // The one request that is *answered* here rather than queued. Queueing it would
                // put it behind the operation it exists to stop, so it could only ever run once
                // there was nothing left to interrupt. See [`EngineOp::Interrupt`].
                if let EngineOp::Interrupt { job } = request.op {
                    emit(&WorkerMessage::Done {
                        id: request.id,
                        result: interrupt_running(job)
                            .map(|(did, text)| Output::interrupted(text, did))
                            .map_err(Failed::from),
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
    // The same door the explicit teardown closes, and for a sharper version of its reason. A
    // resume pumping here has up to the bound its caller named — an hour — while the release
    // below waits `ABRUPT_EXIT_RELEASE`, so without this the wait expires against a worker that
    // is working perfectly and this process exits with the target never released: exactly the
    // halted live kernel the paragraph above exists to prevent, reached by the one path where
    // nobody is left to ask again.
    stop_resuming();
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
    // Everything above is the account of a teardown nobody asked for, and it is the account most
    // worth reading — so it goes up the channel before this process stops existing. Bounded, and
    // last: a flush that held the exit open would be a worse bug than a lost log line.
    crate::logbridge::flush(LOG_FLUSH);
    std::process::exit(0);
}

/// How long a worker will wait, on its way out, for its log records to reach the supervisor.
///
/// Small on purpose. The records are already on this process's stderr; what this buys is the
/// copy a client on another machine can read ([`crate::logbridge`]), and no diagnostic is worth
/// delaying the release of a debug target for.
const LOG_FLUSH: Duration = Duration::from_millis(250);

/// Starts the thread that mirrors this worker's `tracing` records up the protocol channel.
///
/// A thread of its own because the alternative is writing them from wherever they are logged —
/// which is mostly the engine thread, inside DbgEng, where a pipe that has filled would block the
/// debugger on a log line. Queued and dropped when full instead; the drops are counted and
/// reported rather than swallowed.
fn start_log_writer() {
    let started = thread::Builder::new().name("logs".into()).spawn(|| {
        crate::logbridge::run_worker_writer(|entry, dropped| {
            !matches!(
                emit(&WorkerMessage::Log {
                    at_ms: entry.at_ms,
                    level: entry.level,
                    target: entry.target,
                    message: entry.message,
                    dropped,
                }),
                Emit::Unwritable
            )
        });
    });
    if let Err(e) = started {
        // Not fatal, and not silent: the session works, and its records still reach this
        // process's stderr — they just stop reaching a client that is not on this machine.
        tracing::warn!(
            "worker: could not start the log writer ({e}); this session's log records will not \
             reach the client, only the server's own stderr"
        );
    }
}

/// What this session cannot do that a caller would otherwise assume it can, if anything.
///
/// Set once, by [`engine_thread`], before `Ready`. `None` is the ordinary case and says nothing.
static LIMITATION: OnceLock<Option<String>> = OnceLock::new();

/// What this session cannot do, if anything.
fn session_limitation() -> Option<String> {
    LIMITATION.get().cloned().flatten()
}

/// Builds this worker's engine, and works out what this session will not be able to do.
///
/// The engine is always created **here**: which process a target is opened in was decided by the
/// supervisor before this one existed ([`crate::engine::worker_images`]), because a process's
/// architecture is fixed when its image loads and so the choice cannot be made from inside the
/// process being chosen.
///
/// What is left for this end is the honest report. A 32-bit target opens perfectly well in a
/// 64-bit worker and native analysis of it works — only the .NET SOS extension is unreachable,
/// because an extension loads into the debugger's own process. So when this build is the wrong
/// architecture for the target it has been given, the session comes up and says so, rather than
/// failing or quietly producing one whose SOS commands all fail with something that names none of
/// this. It is the *same question* the supervisor asked, asked again here, which is why the two
/// cannot disagree.
fn build_engine(target: Option<&Opening>) -> Result<(DebugEngine, Option<String>), String> {
    // `DebugEngine::new()` panics if the engine cannot be created — dbgeng.dll not discoverable,
    // most likely.
    let engine = catch_unwind(AssertUnwindSafe(DebugEngine::new))
        .map_err(|_| "failed to initialize DbgEng (is dbgeng.dll on the search path?)")?;
    Ok((engine, limitation_for(target)))
}

/// Whether this worker is the wrong architecture for its target, said in a sentence a caller can
/// act on.
///
/// **Names no tool**, deliberately: this is built in the worker, which owns one session and has
/// never heard of the caller's surface (`FOLLOWUPS.md` item 43). It names a document instead,
/// which every caller can reach.
///
/// **Computed here rather than sent down the wire, on purpose.** The supervisor asked this same
/// question to choose an image; asking it again is two reads of one fact rather than a field the
/// two processes could come to disagree about, and it needs no new protocol to say what a session
/// is.
fn limitation_for(target: Option<&Opening>) -> Option<String> {
    // A 32-bit worker is the answer, not the problem.
    if std::env::consts::ARCH == "x86" {
        return None;
    }
    let target = target?;
    match target.arch() {
        Ok(Some(Arch::X86)) => Some(NO_X86_WORKER.to_string()),
        Ok(Some(arch)) => {
            tracing::debug!(
                "worker: {} is {}; this build can open it",
                target.describe(),
                arch.label()
            );
            None
        }
        Ok(None) => None,
        // Not worth a limitation: the engine opens the target next and will say far more about it
        // than a header parse or an `IsWow64Process2` can.
        Err(why) => {
            tracing::debug!(
                "worker: could not read the architecture of {} ({why}); assuming this build can \
                 open it",
                target.describe()
            );
            None
        }
    }
}

/// Told to a caller whose 32-bit target this build cannot give a 32-bit engine.
///
/// One sentence covers both ways of getting here — no 32-bit worker on the host, and one that
/// would not start — because from the caller's side they are the same fact and the same remedy.
/// Why the 32-bit worker did not start is a *server* fact, and is logged by the supervisor that
/// tried it.
const NO_X86_WORKER: &str = "This is a 32-bit target and this build of the server is not, so the \
                             .NET SOS extension cannot be loaded for it: an extension is loaded \
                             into the debugger's own process, and from here neither the 32-bit \
                             `sos.dll` (which will not load) nor the 64-bit one (which refuses a \
                             32-bit CLR) can work. Native analysis — stacks, modules, memory, \
                             disassembly — is unaffected. To make SOS available, put the 32-bit \
                             build of this server alongside a debugger package's `x86` engine \
                             payload in an `x86\\` directory beside this executable; the skill's \
                             `setup.md` has the copy block.";

/// Owns the [`DebugEngine`] for the life of the process and runs one op at a time.
fn engine_thread(rx: mpsc::Receiver<Job>, target: Option<Opening>) {
    // Reported and exited rather than accepted: the supervisor is waiting for exactly one of these
    // two messages before it registers a session, so a dead engine reads as server machinery
    // rather than as a debugger error the model would pointlessly retry.
    let (engine, limitation) = match build_engine(target.as_ref()) {
        Ok(built) => built,
        Err(message) => {
            emit(&WorkerMessage::Fatal {
                message: message.to_string(),
            });
            crate::logbridge::flush(LOG_FLUSH);
            std::process::exit(1);
        }
    };
    // Read later by [`open`]: what to tell the caller about what this session cannot do.
    let _ = LIMITATION.set(limitation);
    // Published before `Ready`, so the request reader can never be handed work it cannot interrupt.
    let _ = INTERRUPT.set(engine.interrupt_handle());
    emit(&WorkerMessage::Ready {
        build: crate::BUILD_VERSION.to_string(),
    });

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
                         target may be left halted, and a process this session attached to may \
                         have been killed rather than detached",
                        e
                    ),
                    Err(_) => tracing::error!(
                        "worker: releasing the target panicked; a live kernel target may be left \
                         halted, and a process this session attached to may have been killed \
                         rather than detached"
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
        // A panic inside a dbgscope method (several use `.expect`) must not kill the session —
        // surface it as an error for this one op. The engine survives, so this stays a
        // debugger-level failure the model can work around by trying something else.
        let result = catch_unwind(AssertUnwindSafe(|| {
            if let Some(setting) = request.startup_symbol_path {
                if !request.op.is_opener() {
                    return Err(Failed::from(
                        "startup symbol state was attached to a request that is not an opener",
                    ));
                }
                apply_symbol_path(&engine, &setting).map_err(Failed::from)?;
            }
            execute(&engine, id, request.op, queued)
        }))
        .unwrap_or_else(|_| Err(Failed::from("debugger operation panicked")));
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
                result: Err(Failed::from(
                    "the debugger's result could not be encoded for the supervisor",
                )),
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

/// Closes this worker to running a target, so a teardown queued behind a resume is reached —
/// from the request reader, beside [`announce_teardown`] and for the same reason.
///
/// **Two halves, and neither is sufficient alone.** It records that the session is ending
/// ([`Running::tearing_down`]), which refuses any [`EngineOp::Resume`] that has not started; and
/// it breaks the engine out of one that has. A resume can be in either state when a teardown
/// arrives — queued behind a long `pool_census`, or already pumping — and the halves are taken
/// under one lock in the order that leaves no window between them.
///
/// **The one job a teardown cannot simply wait for.** Every other operation on the engine thread
/// ends on a clock this process owns: a command has a watchdog, a walk checks a deadline, a batch
/// stops at its next step. A resume ends when the *target* stops, which may be the bound the
/// caller named — minutes, or an hour — and until then the `EndSession` behind it is not even
/// dequeued. Its grace would expire against a worker that is working perfectly, and the worker
/// would be killed still holding the target: a live kernel left halted, an attached process taken
/// down with the debug port.
///
/// Narrow on purpose. It raises a break **only** for a job that is pumping a resumed target, not
/// for whatever happens to be running: a teardown arriving behind a long `pool_census` still lets
/// that finish, which is the behaviour every release here has had. Widening it would change what
/// `end_session` does to every other operation, which is not what this is for.
///
/// It goes through [`interrupt_running`], so the seal a [`crate::batch`] takes for its `always`
/// block is honoured here too — a batch is never pumping, but the check costs nothing and the
/// alternative is a second road to `SetInterrupt` with its own idea of what may be broken.
fn stop_resuming() {
    // Two statements, so the guard is unmistakably dropped before `interrupt_running` below takes
    // the same lock. A `let ... else` over `running()` directly would leave that to the rule about
    // when a temporary in a `let` initializer dies — correct, and not a thing to have to be right
    // about when being wrong is a deadlock in a teardown.
    let pumping = running().begin_teardown();
    let Some(job) = pumping else { return };
    tracing::info!(
        "worker: session ending while job {job} pumps a resumed target; breaking in so the \
         teardown is reached"
    );
    // The reply is the caller's, not this path's — an interrupt that finds nothing to stop is a
    // normal answer, and the teardown behind it is what actually reports.
    if let Err(why) = interrupt_running(Some(job)) {
        tracing::warn!("worker: could not break the target in for the teardown ({why})");
    }
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
fn cut_short(result: Result<Output, Failed>) -> Result<Output, Failed> {
    // Says what happened and stops short of prescribing a re-run, for [`told`]'s reason and on
    // the other interruption path: this wraps *any* op, so it cannot see whether the one it is
    // wrapping changed the target. It used to end "Re-run it — scoped more narrowly", which is
    // right for the search it was written for and installs a second breakpoint when the op was a
    // `bp`.
    const NOTE: &str = "[windbg-mcp] This operation was interrupted on request (Ctrl+Break) \
                        before it finished, so this is what it had reached, not a complete \
                        result. Nothing about the target failed. Whatever it had already done \
                        stands: a query can be narrowed and run again, while an operation that \
                        changes the target may have done so before the break.";
    match result {
        // The note lands on the text and the typed payload is left as it was: the interruption is
        // a fact about this *call*, and rewriting an answer the engine did produce — a stop
        // position, a chunk listing — to say it did not would throw away the very thing that
        // makes interrupting better than ending the session.
        Ok(mut out) => {
            out.text = match std::mem::take(&mut out.text) {
                text if text.is_empty() => NOTE.to_string(),
                text if text.ends_with('\n') => format!("{text}\n{NOTE}"),
                text => format!("{text}\n\n{NOTE}"),
            };
            Ok(out)
        }
        // The category matters as much as the note: an interrupted operation reported as a
        // debugger failure tells its caller the target misbehaved, when what happened is that
        // somebody — quite possibly that same caller — asked for it to stop.
        Err(failed) => Err(Failed::categorised(
            structured::ErrorCategory::Interrupted,
            format!("{}\n\n{NOTE}", failed.message),
        )),
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
fn interrupt_running(bound: Option<u64>) -> Result<(Interrupted, String), String> {
    let mut running = running();
    // A break asked for on behalf of one particular job is **never rebound** to a different one.
    // The engine thread may have finished that job and started the next thing — a queued command,
    // or the run after this one — and a break raised now would cut *that* short, reported to its
    // caller as an interruption nobody asked for. The session-scoped `interrupt` tool passes
    // `None` and keeps the other meaning, because its caller named a session and gets whatever
    // that session is doing.
    //
    // Which leaves two ways for the named job not to be the running one, and they need opposite
    // answers. Ids are minted in order and the worker runs them in order, so one **above** the
    // running job has not started yet — and that is the case that must not be a no-op: doing
    // nothing would let it start once the queue drained and hold the target for the bound it
    // named, which is exactly what the break asked it not to do. So it is barred instead. One
    // *below* is over, and there is nothing to do about it.
    if let Some(named) = bound
        && let Some(outcome) = running.break_for_other(named)
    {
        return Ok((
            outcome,
            format!(
                "Job {named} is not what this session's engine is running, so nothing was sent — \
                 breaking in on work that was not asked about is the one thing naming the job \
                 prevents. It has been barred instead: if it is still queued behind other work it \
                 will not set the target going, and if it has already finished its own reply says \
                 how it ended."
            ),
        ));
    }
    let Some(job) = running.job else {
        return Ok((
            Interrupted::NothingRunning,
            "Nothing was running on this session's engine, so nothing was interrupted. \
             Whatever you meant to stop had already finished — its own reply says how it ended."
                .to_string(),
        ));
    };
    // A batch that has reached its `always` block is closed to breaks, whether or not one has been
    // raised for it before. Cleanup is the one thing an interrupt must not reach: a restore cut
    // short returns `Ok` with partial output like any other interrupted command, so it would be
    // recorded as a step that worked and reported as `rollback: COMPLETE` with the patch still
    // applied.
    if running.sealed(job) {
        return Ok((
            Interrupted::Sealed,
            format!(
                "Not interrupted. The operation on this session (job {job}) is a `debug_batch` \
                 that has finished its steps and is running its rollback, which is deliberately \
                 not interruptible — a restore stopped halfway would report success while leaving \
                 the target changed. It is bounded by the batch's own budget and will return \
                 shortly. If it does not, `end_session` ends the session outright, at the cost of \
                 the target."
            ),
        ));
    }
    // At most one break per job otherwise, for the same reason one step later: a batch told to stop
    // runs its rollback as part of this same job, so a second interrupt aimed at it would land on a
    // restore command.
    //
    // Costs nothing anywhere else: a repeat only ever meant "that same operation, again", and it
    // is already stopping.
    //
    // Note this is not what makes either tool idempotent or not, and the two answer differently.
    // A *later* job is a different id and is interrupted normally — which is why `interrupt`, whose
    // caller named a session, is `idempotentHint: false`: its retry addresses whatever is running
    // by then. `break_in` names a run, so its retry is pinned to this same job and can only arrive
    // here, or at a bar it has already set; it is `idempotentHint: true`. Both annotations are in
    // `server.rs` and carry the reasoning.
    if running.interrupt_pending(job) {
        // Nothing was sent, but a break **is** lodged for this job and the target is stopping,
        // which is what `break_in` is asking about — while the transcript is asking who raised it
        // and must not credit this request. That is the split `Interrupted` exists for.
        return Ok((
            Interrupted::AlreadyPending,
            format!(
                "Already interrupted. Ctrl+Break was raised on this session's engine for the \
             operation it is running (job {job}) and it is stopping; nothing further was sent. If \
             it does not end, it is one of the cases an interrupt cannot reach — a command that \
             never polls, or a live-kernel attach whose target has not connected — and \
             `end_session` is what ends those, at the cost of the target."
            ),
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
    let filed = handle.interrupt().map_err(es)?;
    // Recorded only once the raise succeeded: a failed one has left nothing pending, and claiming
    // otherwise would have the engine thread drain an interrupt that was never lodged and label a
    // complete result as cut short.
    running.interrupt_raised();
    // Logged, and deliberately not turned into a different answer for the caller.
    // `BreakRequest::NothingRunning` says the *engine* had no bounded operation to file the request
    // against — a typed getter, or a plain `execute_command`, neither of which is one — and not
    // that this session is idle: the job the caller named is running either way, and the break was
    // delivered either way, since `SetInterrupt` is engine-wide. What it does tell you, in a log
    // read after the fact, is whether the break had anything to be reported by, which is the
    // difference between an operation that will come back `cut_short` and one that will not.
    tracing::info!("worker: interrupt raised for job {job}, filed as {filed:?}");
    Ok((
        Interrupted::Raised,
        "Interrupted. Ctrl+Break was raised on this session's engine, so the operation it was \
         running stops at its next poll and returns whatever it had reached — to the call that \
         started it, not to this one. A command that never polls, and a live-kernel attach whose \
         target has not connected, cannot be reached this way; `end_session` is what ends those."
            .to_string(),
    ))
}

/// Refuses work on a session whose target has gone away — in one place, with one message.
///
/// dbgscope refuses *raw commands* itself, because text driven into an engine with no debuggee
/// faults the process. Without this, the typed tools would be the inconsistent half: `registers`,
/// `modules` and `backtrace` go through the engine's own interfaces, which answer `E_UNEXPECTED`
/// there — so a caller would get a different failure per tool for one fact about the session, and
/// none of them would say what it was.
///
/// Three groups are exempt, each for its own reason. The **openers** run on an engine that has no
/// target *yet*, which is the same state read from outside — and a worker is sent exactly one of
/// them, as its first op, so exempting them cannot let later work through.
/// [`EngineOp::EndSession`] is the answer to this refusal and must not be refused by it.
/// [`EngineOp::Interrupt`] never reaches here at all (it is answered ahead of the queue, so the
/// engine thread can be busy), and is named so that giving it a route later does not silently
/// acquire a gate.
///
/// An unreadable status is not a refusal — the same rule dbgscope's own guard follows. Refusing on
/// a guess costs a caller a session that was working, which is the worse of the two mistakes.
fn refuse_when_the_target_is_gone(e: &DebugEngine, op: &EngineOp) -> Option<Failed> {
    if matches!(
        op,
        EngineOp::OpenDump { .. }
            | EngineOp::OpenTrace { .. }
            | EngineOp::AttachKernelLocal
            | EngineOp::AttachKernel { .. }
            | EngineOp::AttachProcess { .. }
            | EngineOp::Launch { .. }
            | EngineOp::EndSession
            | EngineOp::Interrupt { .. }
    ) {
        return None;
    }
    match e.has_target() {
        // `StaleSession` rather than `Debugger`, because no change to what is asked will help and
        // the next move is the one that category already means: release this handle and open
        // again. The worker stays alive until `end_session` is called, exactly as a retired
        // session's does.
        Ok(false) => Some(Failed::categorised(
            structured::ErrorCategory::StaleSession,
            NO_TARGET_LEFT.to_string(),
        )),
        Ok(true) | Err(_) => None,
    }
}

/// Applies one symbol-path mutation through DbgEng's typed API.
///
/// Shared by the ordinary tool and an opener's supervisor-held starting state so the two cannot
/// drift into different interpretations of `append`.
fn apply_symbol_path(e: &DebugEngine, setting: &SymbolPathSetting) -> Result<(), String> {
    if setting.append {
        e.append_symbol_path(&setting.path).map_err(es)
    } else {
        e.set_symbol_path(&setting.path).map_err(es)
    }
}

/// Runs one op against this worker's engine. `queued` is how long it waited its turn here, which
/// only the bounded-command path cares about.
fn execute(e: &DebugEngine, id: u64, op: EngineOp, queued: Duration) -> Result<Output, Failed> {
    if let Some(refusal) = refuse_when_the_target_is_gone(e, &op) {
        return Err(refusal);
    }
    match op {
        // ---- openers ----
        //
        // Each reads the same way: side effect, `commit`, wait, `opened`, report. That order is
        // the contract the milestones exist to express — see [`open`].
        EngineOp::OpenDump { path } => open(
            e,
            id,
            |commit| {
                // **Already open**, when this session's engine lives in a host started with
                // `-z <dump>`: that host opened the target before this worker ever connected, and
                // opening it again on the same session is an error rather than a no-op.
                //
                // **Confirmed first, committed second** — the opposite order to the local path
                // below, and for the same reason it uses that one. There, `open_dump` *is* the
                // claim, so the commit follows it. Here the claim happened in another process
                // before this one connected, and publishing a pipe is not evidence of it: a host
                // can serve its transport and still fail to open the file behind it. Committing on
                // the strength of the transport alone would report `target: yes` for a session
                // holding nothing, which tells the caller to reclaim rather than retry — the one
                // thing that answer is for.
                // `open_dump` is the call that claims the target, so commit right after it: a
                // load wait that times out still leaves DbgEng holding the dump.
                e.open_dump(&path).map_err(es)?;
                commit();
                load_completed(e.wait_for_event(LOAD_WAIT_MS).map_err(es)?, "dump")
            },
            || {
                // Load the WinDbg extension DLL so `!`-extension commands resolve — most
                // importantly `!ext.analyze -v`, the crash-dump triage workhorse. A bare engine
                // doesn't auto-load it, and even after `.load ext` the unqualified `!analyze`
                // won't resolve, so callers must use `!ext.analyze`. Best-effort: a minimal
                // engine without a bundled `winext\` directory simply won't have ext.dll, which
                // must not fail the open (live/dump state is still usable).
                let _ = e.execute_command(".load ext");
                // `vertarget`, not `lm`: which build this dump is from, and — on a kernel dump —
                // where the kernel is loaded, in six lines rather than the couple of hundred the
                // module table took (#105). The bug check and the module count come from
                // `target_summary` below; the table itself is what `modules` is for.
                e.execute_command("vertarget").map_err(es)
            },
        ),

        EngineOp::OpenTrace { path } => open(
            e,
            id,
            |commit| {
                // As in `OpenDump`: commit before the load wait, because a wait that times out
                // still leaves DbgEng holding the trace.
                e.open_trace(&path).map_err(trace_open_failure)?;
                commit();
                load_completed(e.wait_for_event(LOAD_WAIT_MS).map_err(es)?, "trace")
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
            e,
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
            e,
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
            e,
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
            e,
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
        // Bounded with a zero deadline, which is `execute_command` plus one thing: the recovery
        // that keeps the output an *interrupted* command had already produced. Without it a break
        // makes `Execute` fail and the captured buffer goes with the error, so the caller of a long
        // `index_trace` gets a bare failure and a note promising partial output that is not there.
        //
        // Zero spawns no watchdog at all, which is now what `index_trace` alone asks for: a
        // `-force` rebuild broken in part-way can leave a trace with no usable index, so the abort
        // is worse than the wedge. It used to be what every cheap point query asked for too,
        // because arming a watchdog rounded a command up to a multiple of 200ms; it parks on a
        // condvar now and costs nothing until the bound is reached, so they all take
        // [`EngineOp::BoundedCommand`] instead (DECISIONS.md, 2026-08-02, revised 2026-08-31).
        EngineOp::UnboundedCommand { command } => raw_command(e, &command, 0)
            .map(|run| Output::text(told(run)))
            .map_err(failed),
        EngineOp::BoundedCommand {
            command,
            patience_ms,
        } => {
            let budget = watchdog_budget_ms(Duration::from_millis(u64::from(patience_ms)), queued);
            raw_command(e, &command, budget)
                .map(|run| Output::text(told(run)))
                .map_err(failed)
        }
        EngineOp::CommandAndWait {
            command,
            timeout_ms,
        } => resumed(e, &command, timeout_ms),
        EngineOp::Resume {
            command,
            timeout_ms,
        } => resume(e, id, &command, timeout_ms),
        EngineOp::Registers { all } => registers(e, all),
        EngineOp::Modules {
            filter,
            limit,
            refresh,
        } => modules(e, filter.as_deref(), limit, refresh),
        EngineOp::Backtrace { frames } => backtrace(e, frames as usize),
        EngineOp::Disassemble { address, count } => {
            disassemble(e, address.as_deref(), count as usize)
        }
        EngineOp::SetBreakpoint {
            expression,
            command,
            one_shot,
            pass_count,
            patience_ms,
        } => set_breakpoint(
            e,
            &expression,
            command.as_deref(),
            one_shot,
            pass_count,
            watchdog_budget_ms(Duration::from_millis(u64::from(patience_ms)), queued),
        ),
        EngineOp::ReadMemory { address, size } => read_memory(e, &address, size)
            .map(Output::text)
            .map_err(Failed::from),
        // The caller's own deadline, on the same arithmetic as a pool walk's and for the same
        // reason — with one difference that makes it matter more here. A pool walk is bounded by
        // dbgscope *as well*; this one has no command behind it, so between-node checking is the
        // only bound there is.
        EngineOp::Walk(op) => {
            let patience = Duration::from_millis(u64::from(op.patience_ms));
            match walk_budget(patience, queued) {
                Some(budget) => walk_memory(e, op, budget),
                // Refused rather than attempted, as a pool query that must walk is. A walk with no
                // time reads nothing and reports an empty table with `stopped: deadline`, which
                // looks exactly like a target whose every node is missing — the one reading a
                // caller must not take away from a call that never started.
                None => Err(Failed::categorised(
                    structured::ErrorCategory::NotRun,
                    format!(
                        "This walk was not run: it reached the engine with {}s of its caller's \
                         timeout left, which is not enough to read a node and report back before \
                         that timeout expires. Nothing was read and nothing changed. It waited \
                         {}s behind other work on this session; issue it when the session is \
                         idle, or raise the server's call timeout (WINDBG_MCP_CALL_TIMEOUT_SECS \
                         — the reply itself reserves {}s of headroom).",
                        patience.saturating_sub(queued).as_secs(),
                        queued.as_secs(),
                        WATCHDOG_HEADROOM.as_secs(),
                    ),
                )),
            }
        }
        EngineOp::SymbolPath { setting, reload } => {
            apply_symbol_path(e, &setting).map_err(Failed::from)?;
            // Reload so the new path takes effect (default: all deferred modules).
            e.reload_symbols(&reload).map_err(es)?;
            // Echo the effective path so the caller can confirm what resolved.
            e.execute_command(".sympath")
                .map(Output::text)
                .map_err(failed)
        }
        EngineOp::RunToAddress {
            address,
            timeout_ms,
        } => run_to_address(e, &address, timeout_ms),
        EngineOp::Reachability(args) => reachable(e, args).map(Output::text).map_err(Failed::from),
        EngineOp::CrashTriage {
            frames,
            analyze,
            patience_ms,
        } => crash_triage(
            e,
            frames as usize,
            analyze,
            Duration::from_millis(u64::from(patience_ms)),
            queued,
        ),
        // The caller's own deadline, on the same arithmetic as a bounded command's: a walk that
        // outlives its caller holds this session against nobody. Taking dbgscope's default instead
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
                    // Categorised, because "nothing ran" is the whole content of this answer and
                    // a caller that reads it as an ordinary debugger failure learns the opposite
                    // of what happened: nothing about the target is wrong, and nothing changed.
                    Err(Failed::categorised(
                        structured::ErrorCategory::NotRun,
                        format!(
                            "This pool query was not run: it reached the engine with {}s of its \
                             caller's timeout left, which is not enough to walk the pool and \
                             report back before that timeout expires. It asked for `refresh`, so \
                             it cannot be answered from the snapshot cached for this session \
                             either. Nothing was read and nothing changed. It waited {}s behind \
                             other work on this session; issue it when the session is idle, or \
                             raise the server's call timeout (WINDBG_MCP_CALL_TIMEOUT_SECS — a \
                             pool walk needs more than the {}s of headroom the reply itself \
                             reserves).",
                            patience.saturating_sub(queued).as_secs(),
                            queued.as_secs(),
                            WATCHDOG_HEADROOM.as_secs(),
                        ),
                    ))
                }
                // Without `refresh` the session's cached snapshot may well answer this outright, and
                // a caller with no time left can certainly afford a cache read. Passed zero rather
                // than refused: if a walk *is* needed it stops at once and the answer says its
                // coverage was nil, which every rendering below already does.
                None => pool(e, query, Duration::ZERO),
            }
        }
        EngineOp::Heap { query, patience_ms } => {
            let patience = Duration::from_millis(u64::from(patience_ms));
            match walk_budget(patience, queued) {
                Some(budget) => {
                    tracing::debug!("worker: heap walk budget {budget:?} (queued {queued:?})");
                    heap(e, query, budget)
                }
                None if query.refreshes() => Err(Failed::categorised(
                    structured::ErrorCategory::NotRun,
                    format!(
                        "This heap query was not run: it reached the engine with {}s of its \
                         caller's timeout left, which is not enough to walk the heap and report \
                         back before that timeout expires. It requested `refresh`, so no cached \
                         snapshot can answer it. Nothing was read and nothing changed. It waited \
                         {}s behind other work on this session; issue it when the session is idle, \
                         or raise WINDBG_MCP_CALL_TIMEOUT_SECS (an allocator walk reserves {}s of \
                         reply headroom).",
                        patience.saturating_sub(queued).as_secs(),
                        queued.as_secs(),
                        WATCHDOG_HEADROOM.as_secs()
                    ),
                )),
                None => heap(e, query, Duration::ZERO),
            }
        }
        // `id` is passed because a batch is the one op that can stop *itself*: it checks between
        // steps whether an interrupt has been raised for the job it is running as.
        EngineOp::Batch(op) => run_batch(e, id, op, queued).map_err(Failed::from),
        // Answered by the request reader, which is the only way it could reach a busy engine at
        // all, so it is never queued and never arrives here. See [`EngineOp::Interrupt`].
        EngineOp::Interrupt { .. } => Err(Failed::from(
            "an interrupt reached the engine thread, which cannot act on one; this is a bug in \
             the worker's request reader",
        )),
        // Reaching here means any batch has already been told to stop and has finished unwinding —
        // the reader saw this request go past and said so, and this thread runs one job at a time.
        EngineOp::EndSession => {
            // Read *before* the teardown, which is the only moment it is still true: ending a
            // session is what clears it. And it is worth saying at all because the two endings
            // are opposite and neither is visible from the caller's side — a process this server
            // attached to is detached and goes on running, where one it launched goes with the
            // session. Naming no tool, per `FOLLOWUPS.md` item 43: this is built in the worker,
            // which has never heard of the client's surface.
            let detaching = e.attached_to_a_live_process();
            let ended = e
                .end_session()
                .map(|_| {
                    // Both halves of the result, from one read of one fact. A structured-aware
                    // client forwards `structuredContent` and drops the text, so a disposition on
                    // the text alone is a disposition half the clients never see — the rule
                    // `docs/smoke-test.md` states for the ending in [#242], met here by the op
                    // that ends a session on purpose. `None` where there was no live process to
                    // keep, which the supervisor turns into `false` for a session that takes its
                    // target: only it knows a launch from a dump.
                    Output::released(
                        if detaching {
                            "Session ended. The process this session attached to was detached and \
                             left running."
                        } else {
                            "session ended"
                        },
                        detaching.then_some(true),
                    )
                })
                .map_err(failed);
            query::invalidate_allocator_caches();
            ended
        }
    }
}

/// Maps any error to a `String` for the wire.
fn es<E: ToString>(e: E) -> String {
    e.to_string()
}

/// Whether a TTD replay engine is bundled beside this executable.
///
/// DbgEng loads the replay engine — `TTDReplay*.dll`, `TtdExt.dll`, `TTDAnalyze.dll` — out of a
/// `ttd\` directory next to itself, and System32's `dbgeng.dll` ships none of them. So a host that
/// never bundled the WinDbg package cannot replay *any* trace, and the only way it says so is
/// `0x80070057` from `open_trace` — "the parameter is incorrect", which names neither the missing
/// directory nor the fix, and reads as a complaint about the path the caller passed.
///
/// Probed against **this executable's** directory rather than the loaded engine's, because that is
/// the layout `setup.md` prescribes and the only one this server can reason about without asking
/// the loader where `dbgeng.dll` came from: the bundle is copied next to `windbg-mcp.exe`, so the
/// engine and its `ttd\` are both there. It answers correctly for the case that actually happens
/// too — an engine taken from System32, where there is no `ttd\` anywhere on the host.
fn replay_engine_bundled() -> bool {
    // Say nothing rather than something wrong: an executable that cannot locate itself is no
    // evidence that the engine is unbundled.
    let Some(dir) = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.to_path_buf()))
    else {
        return true;
    };
    // Non-empty, not merely present. A `New-Item ttd` whose copy then failed leaves a directory
    // that satisfies `is_dir` and replays nothing, which is a plausible end state for a manual
    // bundling step.
    //
    // What this deliberately does *not* check is that the DLLs match this binary's architecture —
    // that needs a PE read per file, and the layout it would be reading is WinDbg's to change. A
    // wrong-architecture `ttd\` therefore still fails with the engine's own error, which is the
    // behaviour without this diagnostic at all rather than a regression from it; `setup.md` states
    // the rule where the copy is made, which is the only place it can be acted on.
    std::fs::read_dir(dir.join("ttd"))
        .map(|mut entries| entries.next().is_some())
        .unwrap_or(false)
}

/// `open_trace`'s failure, told against what this host can actually do.
fn trace_open_failure<E: ToString>(error: E) -> String {
    explain_trace_failure(error.to_string(), replay_engine_bundled())
}

/// The message half of [`trace_open_failure`], split from the probe so it can be tested without
/// standing up a directory layout around the test binary.
fn explain_trace_failure(message: String, bundled: bool) -> String {
    if bundled {
        return message;
    }
    format!(
        "{message}\n\nAlso worth knowing, whatever this error turns out to be: there is no `ttd\\` \
         directory beside this server's executable, so this host cannot replay *any* trace — \
         System32's `dbgeng.dll` ships no replay engine and rejects every `.run` with \
         `0x80070057`. If the path is right, that is the reason, and no change to it will help. \
         Copy `ttd\\` from the WinDbg package next to `windbg-mcp.exe`; the skill's `setup.md` \
         lists the whole engine bundle."
    )
}

/// Maps any error onto the wire as the ordinary case: the debugger ran it and it failed.
///
/// The two failures that are *not* that — interrupted, and never started — say so where they
/// happen, through [`Failed::categorised`]. Everything else reaching a caller as a debugger
/// failure is right: that is what it is.
fn failed<E: ToString>(e: E) -> Failed {
    Failed::from(e.to_string())
}

/// A command's text, with the deadline's explanation appended when there is one.
///
/// The note lives here rather than in dbgscope because it is prose for whoever reads the tool's
/// output, and a return value is the wrong place to put prose: the caller before this one had to
/// string-match for it. Only the deadline earns one — an interrupt *on request* is explained to
/// the caller by [`cut_short`], and to the one who asked by their own reply.
///
/// **It says what happened and stops short of prescribing a retry**, which is not fastidiousness:
/// every raw command in this server comes through here, and it cannot see which one. It used to
/// end "scope it and retry", written for the unbounded `s` search that the bounded path was
/// adopted for — advice that is right for a query and actively harmful for a mutation, since a
/// `bp` cut short may have installed its breakpoint already and re-running it installs a second.
/// The reach of that is wider than it looks: a `debug_batch` step is any command at all, and `dx`
/// can execute one. A caller that knows its own command is a query still gets the scoping hint;
/// nobody gets told to re-issue a mutation.
///
/// The one path that *can* say more is the one that knows what its mutation did — [`set_breakpoint`]
/// is handed the breakpoint by the engine, so it can say whether the location resolved and tailor
/// the advice to that, which is why it has [`told_cut_short_bp`] instead of this. That is the shape
/// to copy for any other mutating command that grows a typed op. (`ioctl_trace` used to be listed
/// here as a `bp` with a logging command string; it goes through that typed op now, so it gets the
/// better note rather than this one.)
fn told(run: CommandRun) -> String {
    let note = match run.cut_short {
        Some(Interruption::Deadline { after_ms }) => Some(format!(
            "[windbg-mcp] command interrupted after {after_ms} ms (Ctrl+Break) — it was taking \
             too long. Whatever it had already done stands: a query can be narrowed (e.g. a \
             bounded memory range) and run again, but a command that changes the target — `bp`, \
             `eb`, `r <reg>=` — may have taken effect before the break, so read the target rather \
             than re-issuing it."
        )),
        _ => None,
    };
    appended(run.output, note)
}

/// [`told`] for a command that was **moving the target**, where the same deadline means something
/// else entirely and `told`'s advice would be wrong.
///
/// There, a bound reached means the query was too broad and should be scoped. Here it means the
/// target had not stopped yet, so the debugger broke in — which is neither a failure nor a stop
/// the target reached, and a caller reading the position without knowing that reads it as one.
///
/// **Names no tool**, deliberately: this text is built in the worker, which owns one session and
/// has never heard of the caller's surface, so a pointer to `go` or `step_over` here would ship to
/// callers not served them (`FOLLOWUPS.md` item 43). The fact goes on the wire; a pointer, if one
/// is ever wanted, belongs where `self.surface` is.
fn told_moving(run: CommandRun) -> String {
    // Checked before `cut_short`, because the two cannot both be acted on and only one of them
    // is terminal: a target that is gone is not somewhere a caller can run it on from.
    if run.target_gone {
        return appended(run.output, Some(TARGET_GONE.to_string()));
    }
    let note = match run.cut_short {
        Some(Interruption::Deadline { after_ms }) => Some(format!(
            "[windbg-mcp] the target had not stopped after {after_ms} ms, so the debugger broke in \
             (Ctrl+Break). It is stopped where it happened to be, which is not a stop it reached \
             — run it on, or allow this call longer."
        )),
        _ => None,
    };
    appended(run.output, note)
}

/// What a caller is told when the target ended rather than stopped.
///
/// **Not a failure**, and the wording has to carry that: running a program to completion is what a
/// `go` is for, and the output above this line is what the run printed on its way there — the only
/// copy there will be. Before this, DbgEng's own `E_UNEXPECTED` was reported unchanged, so an
/// ordinary ending read as `Debug command failed: Catastrophic failure (0x8000FFFF)` and the output
/// went with it (`FOLLOWUPS.md` item 48).
///
/// It names `end_session` and nothing else. That is the one tool every surface serves
/// (`crate::toolset`'s `ALWAYS`), so a worker — which owns one session and has never heard of the
/// caller's surface — may point at it and at no other (`FOLLOWUPS.md` item 43).
const TARGET_GONE: &str = "[windbg-mcp] the target is gone: it ran to completion, or this command \
     released it. That is an ending rather than a failure, and the output above is what the run \
     captured on the way there. Nothing further will run against this session — `end_session` \
     releases it, and opening again gets a fresh one.";

/// The same fact told to a call that arrives *after* the ending, where there is no output above it
/// and no command of the caller's that caused it.
///
/// Split from [`TARGET_GONE`] rather than shared, because one sentence cannot be true of both: the
/// observing call did release the target and does have output to point at, and a later call did
/// neither. A single wording would have to drop the halves that make each one actionable.
const NO_TARGET_LEFT: &str = "This session has no target left: the process ran to completion, or a \
     command released it, so there is nothing here to run against. This is not a failure of the \
     call — `end_session` releases the session, and opening again gets a fresh target.";

/// `text` with `note` on a line of its own, when there is one.
fn appended(mut text: String, note: Option<String>) -> String {
    let Some(note) = note else { return text };
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(&note);
    text
}

/// Executes arbitrary debugger text, **settles anything it left running**, and conservatively
/// retires allocator snapshots afterward.
///
/// A raw command can resume the target or write allocator memory, and DbgEng does not expose a
/// reliable classification of those effects. Invalidate even when execution reports an error:
/// the command may have changed memory before its failing token was reached.
///
/// **The settle is what keeps this hatch from wedging its session** (issue #226). A plain
/// `Execute` of execution-control text — `g`, `p`, `t`, a `;` list ending in one, an alias, a
/// script that reaches one — sets the run state and returns *without moving the target*; until
/// something pumps it the session answers read-only commands normally and refuses every later
/// `g`/`p`/`t` with `0x80040205`, which reads as half alive. `settle` asks the **engine** whether
/// that happened rather than reading the command text, which is the only way to cover the routes
/// no name list can enumerate — and the reason this needs no list at all.
///
/// It runs on the error path too: a command that failed part-way may still have run an earlier
/// segment that resumed the target, and a wedged engine after a failed command is no better than
/// one after a successful command.
///
/// **A target can leave by either half, and each is reported.** The pump is where a program that
/// runs to completion ends (issue #242 — an exit racing the settle used to come back as a failure
/// with the pump's output discarded); the command itself is where `.detach`, `q` and `qd` end it,
/// leaving nothing for a pump to find. One note covers both, because from the caller's side there
/// is one fact: this session has no target left.
fn raw_command(e: &DebugEngine, command: &str, budget_ms: u32) -> Result<CommandRun, String> {
    let started = Instant::now();
    let result = e.execute_command_bounded(command, budget_ms).map_err(es);
    query::invalidate_allocator_snapshots();

    // Capped at the ordinary execution wait, and again at what is left of the caller's clock.
    //
    // [`EXEC_WAIT_MS`] because a raw `g` that reaches no stop should cost what `go` costs and not
    // what this caller's patience happens to be — which with the default call timeout is nearly
    // four minutes, so the hatch would block far longer than the typed tool doing the same thing.
    // The remaining budget because the two share one clock, and zero is a fine answer there rather
    // than a floor to defend: it breaks the target in at once, which is the guarantee that
    // actually matters — the session survives. In practice nearly the whole budget is still here,
    // since a command that leaves the target running returns from `Execute` almost immediately.
    //
    // An unbounded op (`budget_ms == 0`) has no clock to divide, so it takes the cap alone.
    let settle_ms = match budget_ms {
        0 => EXEC_WAIT_MS,
        budget => budget.saturating_sub(elapsed_ms(started)).min(EXEC_WAIT_MS),
    };
    // The command may have taken the target away *itself* — `.detach`, `q` and `qd` return with
    // the engine already holding nothing, so there is nothing left to pump and the settle below
    // would report the ending to nobody. Measured, and `.kill` is deliberately not in that group:
    // it leaves a target that still reads a stack and goes away on the next resume, which is why
    // this is read off the run rather than off the command's name.
    if result.as_ref().is_ok_and(|run| run.target_gone) {
        return result.map(|mut run| {
            run.output = appended(run.output, Some(TARGET_GONE.to_string()));
            run
        });
    }
    let settled = match e.settle(settle_ms) {
        Ok(settled) => settled,
        Err(why) => return settle_failed(e, result, &es(why)),
    };
    let Some(settled) = settled else {
        return result;
    };
    // Read before `settled` is consumed below.
    let forced = matches!(settled.cut_short, Some(Interruption::Deadline { .. }));
    tracing::debug!(
        "worker: `{command}` left the target running; pumped it to a stop within {settle_ms} ms"
    );

    // The pump's output, and then a sentence naming where the target ended up.
    //
    // The sentence is not decoration the way it would be on [`resumed`], which answers with a
    // typed `stopped_at` beside its text while this path has no structured half at all. And the
    // pump's output can be **empty**: measured, a `g` captures the module loads and the stop
    // banner, while a `t` or a `p` captures nothing, because DbgEng prints a step's new position
    // from the command's own completion rather than from the wait. Without the sentence, `execute`
    // with `t` would move the target and still answer with nothing but its own echo — which is
    // exactly the reading that made the bug this fixes look like a swallow.
    // `told_moving` has already said the target is gone, and `moved_note` must not then claim it
    // is "now stopped" somewhere: there is no position to read, and the sentence would describe a
    // session that no longer exists.
    let ending = settled.target_gone;
    let pumped = match ending {
        true => told_moving(settled),
        false => appended(told_moving(settled), Some(moved_note(e, forced))),
    };
    match result {
        Ok(mut run) => {
            run.output = appended(run.output, Some(pumped));
            // The pump's ending belongs to the run this returns, not only to its prose. The
            // command's own `target_gone` is false here — it was the *pump* that watched the
            // target leave — so without this a `debug_batch` `{"op": "command", "command": "g"}`
            // hands back an ordinary success and the batch runs on, which is the same defect
            // this fixes for a `resume` step, on the sibling path.
            run.target_gone |= ending;
            Ok(run)
        }
        // The command failed *and* left the target running. Both facts, in the one channel an
        // error has: dropping the second would report a session as untouched when it was pumped.
        Err(why) => Err(appended(why, Some(pumped))),
    }
}

/// Where a raw command left the target, for the note above.
///
/// The position is read *after* the pump rather than parsed out of its output, since a step prints
/// none. One that cannot be read is left out of the sentence rather than guessed at or reported as
/// zero — the same rule as [`resumed`]'s `stopped_at`, and the same reason.
///
/// `forced` only decides how much is claimed: [`told_moving`] has already said what a break at the
/// bound means, so this must not also call that position a stop the target reached.
fn moved_note(e: &DebugEngine, forced: bool) -> String {
    let at = match e.instruction_pointer() {
        Ok(ip) => format!(" at {}", fmt_addr(ip)),
        Err(_) => String::new(),
    };
    match forced {
        true => format!("[windbg-mcp] this command moved the target, which is now stopped{at}."),
        false => format!("[windbg-mcp] this command moved the target; it is now stopped{at}."),
    }
}

/// What a failed settle means for the session, decided from what the engine says afterwards.
#[derive(Debug, PartialEq)]
enum SettleVerdict {
    /// The engine is still running: the recovery itself failed, and execution control on this
    /// session will fail until the target stops.
    Damaged(String),
    /// Whatever failed, the engine is stopped and the session is fine.
    Fine,
    /// The engine could not be asked either, so nothing is claimed about it.
    Unknown(String),
}

/// [`DebugEngine::settle`] does two things behind one `Result`: it asks whether the engine was
/// left running, and, if it was, it pumps it to a stop. Treating every failure as the first —
/// logging it and handing back the command's own answer — is right for a status query that could
/// not be made and wrong for a pump that did not work, which leaves the session in exactly the
/// state the settle exists to prevent while telling the caller it succeeded.
///
/// So the engine is asked again, and the three answers are three different things. Split from
/// [`settle_failed`] because the engine is what makes it untestable and the decision is what is
/// worth testing.
fn settle_verdict(running: Result<bool, String>, why: &str) -> SettleVerdict {
    match running {
        Ok(true) => SettleVerdict::Damaged(format!(
            "The command ran, and it left the target running. Pumping it to a stop failed \
             ({why}), and the engine still reports it running, so execution control on this \
             session will fail until the target stops. The command's own output follows."
        )),
        Ok(false) => SettleVerdict::Fine,
        // Reported as not knowing rather than guessed at, which is this server's rule everywhere
        // else. A caller acting on a guess either abandons a working session or keeps a broken one.
        Err(unreadable) => SettleVerdict::Unknown(format!(
            "[windbg-mcp] this command may have left the target running: the debugger could not \
             be pumped ({why}) and could not be asked whether it is running ({unreadable}). If a \
             later call fails with 0x80040205, that is why."
        )),
    }
}

/// [`settle_verdict`] applied to what the command itself answered.
///
/// The output survives every branch, including the one that becomes an error: a caller whose
/// session is damaged still needs to see what the command printed, and this is the only copy.
fn settled_or(
    verdict: SettleVerdict,
    result: Result<CommandRun, String>,
) -> Result<CommandRun, String> {
    match verdict {
        SettleVerdict::Fine => result,
        SettleVerdict::Damaged(said) => Err(appended(said, output_of(result))),
        SettleVerdict::Unknown(note) => match result {
            Ok(mut run) => {
                run.output = appended(run.output, Some(note));
                Ok(run)
            }
            Err(command_failed) => Err(appended(command_failed, Some(note))),
        },
    }
}

/// Asks the engine what a failed settle left behind, and answers accordingly.
fn settle_failed(
    e: &DebugEngine,
    result: Result<CommandRun, String>,
    why: &str,
) -> Result<CommandRun, String> {
    let verdict = settle_verdict(e.is_running().map_err(es), why);
    match &verdict {
        SettleVerdict::Damaged(_) => tracing::warn!(
            "worker: the settle after a raw command failed and the target is still running: {why}"
        ),
        SettleVerdict::Fine => {
            tracing::warn!("worker: could not settle the target after a raw command: {why}")
        }
        SettleVerdict::Unknown(_) => tracing::warn!(
            "worker: the settle after a raw command failed and the run state is unreadable: {why}"
        ),
    }
    settled_or(verdict, result)
}

/// A command's text whichever way it ended, for a message that has to carry both.
fn output_of(result: Result<CommandRun, String>) -> Option<String> {
    Some(match result {
        Ok(run) => run.output,
        Err(why) => why,
    })
    .filter(|text| !text.trim().is_empty())
}

/// Milliseconds since `started`, saturating — the shape every budget subtraction here wants.
fn elapsed_ms(started: Instant) -> u32 {
    started.elapsed().as_millis().min(u128::from(u32::MAX)) as u32
}

/// Runs a command that moves the target, and reports where it ended up.
///
/// The text is exactly what it always was. What is added is the *position*, read typed from the
/// engine rather than left for a caller to find in the stop banner — which is a different shape
/// for a breakpoint, an exception and the end of a trace.
///
/// A position that cannot be read is reported as absent, never as zero: after a `g` that left the
/// target running, or on a module-load break with no thread context, there is no instruction
/// pointer to report and saying `0` would name the null page as the answer.
///
/// **A target that ends rather than stops is one of the answers here**, not an error
/// (`FOLLOWUPS.md` item 48). It carries no position, for the reason above, and the debugger text
/// it does carry is the only copy of what the run printed — which is why it must not travel as an
/// `Err`, whose one channel is a message.
fn resumed(e: &DebugEngine, command: &str, timeout_ms: u32) -> Result<Output, Failed> {
    let run = e.execute_and_wait(command, timeout_ms).map_err(failed)?;
    query::invalidate_allocator_snapshots();
    let (text, report) = stop_report(e, command, run);
    Ok(Output::typed(text, report))
}

/// [`resumed`] split at the moment the target starts moving, for [`EngineOp::Resume`]: the
/// milestone goes out as soon as the run state is set, and this op's own reply is the stop.
///
/// **`Execute` and the pump, rather than `execute_and_wait`**, because the whole point is the gap
/// between them: `Execute` sets the run state and returns without the target having moved, and
/// [`DebugEngine::settle`] is what pumps it. That is the same pair [`raw_command`] runs, so the
/// two halves of the output are stitched here the way they are there — a `g` prints its echo from
/// the command and its module loads and stop banner from the pump, while a `t` prints its new
/// position from the command and nothing at all from the pump.
///
/// **The engine thread stays here for the whole run**, which is not an implementation detail to
/// be optimised away later: DbgEng only moves a target from inside `WaitForEvent`, so a worker
/// that went back to its queue after the `Execute` would have set a target running that then sat
/// still. What crosses the pipe early is the milestone, not the thread.
///
/// A command that leaves the engine **not** running never sends the milestone and answers as an
/// ordinary completed run — there is no execution for a caller to hold a handle to. The
/// supervisor reads that as a `continue_async` that finished before it began, which is the honest
/// description of `g` on a target with nothing left to run.
fn resume(e: &DebugEngine, id: u64, command: &str, timeout_ms: u32) -> Result<Output, Failed> {
    // Claimed around the **whole** of this, `Execute` included, and that is not tidiness. A
    // teardown reads this flag to decide whether to break in ([`stop_resuming`]); one arriving in
    // the window between `Execute` returning and the flag being set would find nothing to break
    // and queue behind the entire run instead — its grace would expire, and the worker would be
    // killed still holding the target. Raising a break during the `Execute` costs nothing: it
    // returns immediately either way, and the pending break lands on the pump.
    //
    // Claimed rather than simply set, because the same lock answers the other half of that
    // window: a teardown read *before* this job was dequeued has already barred resuming, and the
    // claim fails. Between the two there is nowhere for a run to hide.
    //
    // Cleared here rather than at each exit, and again in [`Running::release`], which is what
    // covers a panic.
    if let Err(why) = claim_pump(id) {
        // Something reached this run before the engine thread did, and in both cases there was no
        // pump for it to interrupt — so the only way to honour it is here, by not starting.
        return Err(match why {
            // Refused as a stale session, which is what it is: the handle a caller holds is being
            // torn down.
            PumpRefused::TearingDown => Failed::categorised(
                crate::structured::ErrorCategory::StaleSession,
                "This session is ending, so its target was not resumed. The teardown was already \
                 read when this run reached the engine; nothing was set running, and the target \
                 is being released as it stood.",
            ),
            PumpRefused::BrokenIn => Failed::categorised(
                crate::structured::ErrorCategory::Interrupted,
                "This run was broken in before it started, so the target was never resumed. \
                 `break_in` arrived while this run was still queued behind another operation on \
                 the session's engine — there was no pump to interrupt, so it was barred from \
                 starting instead. Letting it run would have set the target going for up to the \
                 bound this run named, which is what the break asked it not to do.",
            ),
        });
    }
    let outcome = pump_a_resume(e, id, command, timeout_ms);
    pumping(None);
    outcome
}

/// [`resume`]'s body, with the claim above held around it.
fn pump_a_resume(
    e: &DebugEngine,
    id: u64,
    command: &str,
    timeout_ms: u32,
) -> Result<Output, Failed> {
    let echo = e.execute_command(command).map_err(failed)?;
    // As in `raw_command`, and for its reason: the command may have written allocator memory
    // before this process gets to say anything about what it did.
    query::invalidate_allocator_snapshots();
    // Asked of the engine rather than read off the command text, for [`raw_command`]'s reason:
    // an alias, a `;` list and `.if` all reach execution without saying so, and a name list that
    // decided this would be wrong in both directions.
    if !e.is_running().map_err(failed)? {
        return Ok(stopped(
            e,
            command,
            CommandRun {
                output: echo,
                cut_short: None,
                // The command itself can take the target away — `.detach`, `q`, `qd` — and there
                // is no pump here to notice, so this is the only place it can be read.
                target_gone: !e.has_target().unwrap_or(true),
            },
        ));
    }
    // The target is moving, so the reply to this op is now the *stop* and this milestone is what
    // lets the caller stop waiting. Sent only from here: a command that failed, or that left the
    // engine not running, has already returned above.
    emit(&WorkerMessage::Resumed { id });
    let settled = e.settle(timeout_ms);
    let ran = |output| CommandRun {
        output,
        cut_short: None,
        target_gone: false,
    };
    let pumped = match settled {
        Ok(Some(run)) => run,
        // Unreachable — the engine was running a line ago and this thread is the only one that
        // could have changed that — and answered rather than asserted, because the answer is
        // obvious: the run is over and the command's own text is all of it.
        Ok(None) => ran(String::new()),
        Err(why) => {
            let why = es(why);
            tracing::warn!("worker: pumping a resumed target failed ({why})");
            return match settle_failed(e, Ok(ran(echo)), &why) {
                Ok(run) => Ok(stopped(e, command, run)),
                Err(text) => Err(Failed::from(text)),
            };
        }
    };
    Ok(stopped(
        e,
        command,
        CommandRun {
            output: appended(echo, Some(pumped.output)),
            ..pumped
        },
    ))
}

/// [`stop_report`] as an [`EngineOp::Resume`] answers it: the value goes in the field the
/// supervisor folds into its own record rather than in `data`, which that path never reads. See
/// [`Output::stop`].
fn stopped(e: &DebugEngine, command: &str, run: CommandRun) -> Output {
    let (text, report) = stop_report(e, command, run);
    Output::stopped(text, report)
}

/// Where a run that moved the target ended up, as text and as values.
///
/// Shared by the synchronous and asynchronous paths so the two cannot describe one stop
/// differently — they are the same run, split at a different place, and a caller reading a
/// `StopReport` should not be able to tell which tool produced it.
///
/// Every one of the three positions is read *after* the run and reported as absent where the
/// engine will not answer, never as zero: a target that has **gone** answers none of them, and a
/// stop with no thread context answers neither of the last two. Saying `0` would name the null
/// page, thread 0 and processor 0 as the answer.
fn stop_report(
    e: &DebugEngine,
    command: &str,
    run: CommandRun,
) -> (String, structured::StopReport) {
    let stopped_at = e.instruction_pointer().ok().map(structured::addr);
    // Which thread the position above belongs to, and — on a kernel target — which processor it
    // is running on.
    //
    // `current_processor` distinguishes "no processor number applies" from "the mapping could not
    // be read", and this **deliberately collapses the two**, as it does for the two reads either
    // side of it. A stop report is read by a model, which cannot act on the difference — there is
    // no position either way, and a failed read's own words are in the run's output — so a third
    // state per position would be three shapes for one answer. The distinction is kept where a
    // caller can use it, which is the library.
    let thread = e.current_thread_system_id().ok();
    let processor = e.current_processor().ok().flatten();
    // Two different things, matched on the variant rather than on "was it cut short at all",
    // because a caller acts differently on each: `OnRequest` is somebody having asked, and
    // `Deadline` is this run's own bound passing with the target still going — so the
    // position above is where it happened to be, not a stop it reached. Rolling the two into one
    // flag is how "the target had not stopped" comes to be read as "it stopped here".
    let interrupted = matches!(run.cut_short, Some(Interruption::OnRequest));
    let timed_out = matches!(run.cut_short, Some(Interruption::Deadline { .. }));
    let target_gone = run.target_gone;
    let text = told_moving(run.clone());
    (
        text,
        structured::StopReport {
            command: command.to_string(),
            stopped_at,
            thread,
            processor,
            interrupted,
            timed_out,
            target_gone,
            output: run.output,
        },
    )
}

/// The register set, as `r` renders it and as values beside it.
///
/// Two reads of the same context rather than one parsed twice — and they cannot disagree, because
/// this is one indivisible job on the engine thread, so nothing can move the target between them.
///
/// `all` decides how much of the bank travels. The integer registers are what `r` prints and what
/// nearly every question is about; the x87/vector registers and the subregister views are several
/// hundred more entries, and including them unasked would put ~20x the payload on every call for
/// `rsp`.
fn registers(e: &DebugEngine, all: bool) -> Result<Output, Failed> {
    let text = e.registers().map_err(failed)?;
    let registers = e.register_values().map_err(failed)?;
    let selected: Vec<structured::RegisterInfo> = registers
        .iter()
        .filter(|register| all || plain_integer(register))
        .map(|register| structured::RegisterInfo {
            name: register.name.clone(),
            value: (&register.value).into(),
            subregister: register.subregister,
        })
        .collect();
    Ok(Output::typed(
        // DbgEng prints nothing for `r` when there is no live thread context (a module-load
        // break, or a bare `goto_position` to the very start of a trace). The explanation is the
        // supervisor's to add — it is advice about which tool to call next — so the text crosses
        // as the engine gave it.
        text,
        structured::RegisterSet {
            instruction_pointer: e.instruction_pointer().ok().map(structured::addr),
            registers: selected,
            all_registers: all,
        },
    ))
}

/// Whether a register belongs in the **default** answer: the integer registers a caller means by
/// "the registers", rather than the vector bank in disguise.
///
/// Two of the three rules are the obvious ones. `subregister` is the engine's own flag and drops
/// `eax` within `rax`; the value being `Int` drops the x87 and vector registers, which the engine
/// reports as bytes.
///
/// **The third is measured rather than obvious, and it is where the weight was.** DbgEng exposes a
/// vector register *twice*: `xmm0` as the 128-bit register, and `xmm0/0` … `xmm0/3` as four 32-bit
/// pseudo-registers — and those lanes are **not** flagged as subregisters, so they passed both
/// rules above. A default answer whose own argument documents it as "not the x87 and vector
/// registers" was carrying sixty-four of them: 64 of the 123 rows on this repo's x64 sample, and
/// 44% of the bytes of the largest typed answer this server gives after `modules`.
///
/// It is a test on the *name* because the description the engine hands back has nothing better to
/// offer, which is **measured rather than assumed** (`FOLLOWUPS.md` item 35): every field of
/// `DEBUG_REGISTER_DESCRIPTION` was read for both architectures, and `SubregMaster` is `0` for
/// every row whose flag is clear, while `Type` puts a view in the same bucket as a register that is
/// simply narrow — `xmm0/0` beside `efl`, `w0` beside `cpsr`. The `/` is DbgEng's own convention for
/// "a piece of a wider register" and appears in no register's real name, so the test is narrow — and
/// it decides only what the *default* carries, since `all` still returns everything the engine
/// knows.
fn plain_integer(register: &dbgscope::dbgeng::Register) -> bool {
    !register.subregister
        && matches!(register.value, dbgscope::dbgeng::RegisterValue::Int(_))
        && !register.name.contains('/')
}

/// A module row with the PDB identity the engine has for it, where it has one.
///
/// **One helper for the listing and the opener's summary**, because `TargetSummary::primary_module`
/// documents itself as exactly the row `modules` returns — and enriching only one of them made
/// that false, which is a promise breaking rather than a field missing.
///
/// **Asked only of the modules the engine has already resolved.** A listing is two hundred rows and
/// this is a call into the engine per row, so it is asked where the answer will not be empty. Both
/// PDB-backed states count: `pdb` is the ordinary one, and `dia` is the same PDB reached through
/// the Debug Interface Access API, which resolves an identity just as well.
///
/// A failure costs this one field. A listing must not fail over the provenance of the symbols it
/// is listing.
fn with_pdb_identity(
    e: &DebugEngine,
    module: &dbgscope::dbgeng::Module,
    mut info: structured::ModuleInfo,
) -> structured::ModuleInfo {
    use dbgscope::dbgeng::SymbolKind;
    if matches!(module.symbols, SymbolKind::Pdb | SymbolKind::Dia) {
        match e.module_pdb(module.base) {
            Ok(pdb) => info.pdb = pdb.map(structured::PdbInfo::from),
            Err(why) => {
                tracing::debug!("worker: no PDB identity for {}: {why}", info.listed_name());
            }
        }
    }
    info
}

/// The modules, as values and as a listing rendered **from those same values** — optionally
/// narrowed to the ones whose name matches a pattern.
///
/// **One list, both channels.** The records come from `IDebugSymbols3` (dbgscope's `modules()` and
/// `unloaded_modules()`); nothing here runs `lm`. That is the whole point of
/// [#120](https://github.com/glslang/windbg-mcp/issues/120): while the text was DbgEng's rendering
/// and the values were this process's match over the engine's list, one answer had two independent
/// implementations of one filter, and they disagreed about character sets, the `\` escape,
/// whitespace, case folding and the unloaded tail — five ways for a listing to show rows its own
/// count denies. Rendering here leaves one implementation, so the filter's syntax is this server's
/// to define rather than something that has to track `lm m`'s. `execute { "command": "lm" }` still
/// runs the engine's own listing for anyone who wants it verbatim.
///
/// **Both halves of the engine's list.** The modules that have since unloaded are a second list,
/// narrowed by the same pattern and rendered under their own heading: on this repo's sample a
/// filter of `nvhda` matches no loaded module and twenty-six unloaded ones, which is an answer
/// rather than the "nothing matched" it once read as.
///
/// **`limit` rows in all**, because the whole table is the largest answer this server gives and a
/// caller pays for all of it ([`crate::proto::DEFAULT_MODULE_ROWS`]). One budget across both
/// halves rather than one each — [`split_row_budget`] shares it, so a two-hundred-row loaded table
/// cannot squeeze out the unloaded rows and two halves cannot double the ceiling between them.
/// What the cap must not cost is the counts: the note and the values report what *matched*, so a
/// listing that stops short says so rather than reading as a smaller target.
///
/// **`refresh` runs before any of that**, and the ordering is the whole of it: a listing taken
/// from an inventory the engine has not resynchronised is a listing of what the *engine* knows
/// rather than of what the target has loaded ([`resynchronise`]).
fn modules(
    e: &DebugEngine,
    filter: Option<&str>,
    limit: usize,
    refresh: bool,
) -> Result<Output, Failed> {
    let pattern = filter.map(module_pattern);
    // Asked for first, and its failure does **not** end the call: a stale listing plus a field
    // saying the resynchronisation failed is strictly more than an error, since the rows may well
    // be the right ones and the caller can see for themselves. What must not happen is the
    // failure going unsaid, which is why [`refresh_note`] renders above the tables rather than
    // into the note under them — the caveat has to arrive before the conclusion it qualifies.
    let refreshed = refresh.then(|| resynchronise(e)).transpose()?;
    let loaded = e.modules().map_err(failed)?;
    // Unloaded modules are best-effort: not every Windows version tracks them, the ones that do
    // may have nothing to report, and a listing of what *is* loaded must not fail over what is
    // not. An error here costs the tail and nothing else.
    let unloaded = e
        .unloaded_modules()
        .inspect_err(|why| tracing::debug!("worker: unloaded modules could not be read: {why}"))
        .unwrap_or_default();
    // Filtered first and counted before either half is cut, because the counts are of the target
    // and the rows are a page of it — and the share is where the two halves meet, so that neither
    // can take the budget in full.
    let (matched, matched_unloaded) = (
        matching(&loaded, pattern.as_deref()),
        matching(&unloaded, pattern.as_deref()),
    );
    let (total, total_unloaded) = (matched.len(), matched_unloaded.len());
    let (for_loaded, for_unloaded) = split_row_budget(limit, total, total_unloaded);
    let list = structured::ModuleList {
        loaded: loaded.len(),
        filter: pattern,
        modules: identified(e, matched, for_loaded),
        matched: total,
        unloaded: identified(e, matched_unloaded, for_unloaded),
        unloaded_matched: total_unloaded,
        refresh: refreshed,
    };
    Ok(Output::typed(render_modules(&list), list))
}

/// Asks the engine to resynchronise its module inventory with the target, and reports what that
/// did.
///
/// **The defect this closes.** DbgEng's module list is the engine's, not the target's: it is built
/// from the module-load events the debugger *saw*, so a live kernel attach starts from whatever it
/// can read at connect time and a driver loaded before the debugger dialled in is simply not in
/// it. On the MessageManager regression target that was `nt` and nothing else, and a `modules`
/// call straight after the attach read as "the challenge driver is not loaded" while the driver
/// was open and serving IOCTLs ([#85]). Measured there on 2026-08-30, one attach: the engine held
/// **1** module, a filter on `MessageManager` matched **0**, and the same call with `refresh`
/// reported `before: 1` against **158** loaded and matched the driver — `deferred`, so it was
/// found without a byte of PDB being fetched. The synchronisation existed all along — it is what the
/// tier's `.reload /f` was doing as a side effect — and nothing said so, so finding a loaded image
/// meant guessing that a force symbol reload was the missing step.
///
/// **Unqualified and unforced**, which is the argument for a separate flag rather than a wider
/// `set_symbol_path`. `Reload("")` is the `.reload` a person types: it re-reads the target's
/// loaded-module list and leaves every module's symbols *deferred*, so the images it discovers
/// cost their names and nothing else. `/f` — what the symbol path's own reload takes — is a PDB
/// fetch per module, which on a live kernel over a symbol server is minutes and is not what a
/// caller asking whether a driver is loaded wanted to buy.
///
/// The one thing it does cost is that a reload *discards* the symbol information the engine had
/// and reloads it as needed, so a module that had symbols reports `deferred` afterwards until
/// something asks for one again (from the local cache, not the server). That cost is why this is
/// opt-in rather than something an opener does for you, and why the tool's own prose says to
/// refresh before loading symbols rather than after.
///
/// **And it is a live-target cost, which took two measurements to establish** (this bench,
/// 2026-08-30, with the engine's `symsrv.dll`/`msdia140.dll` bundled and a store configured —
/// without them the first attempt saw only `export` fallback and read the effect as smaller than
/// it is):
///
/// * a launched `cmd.exe`, five modules. After `.reload /f`, all five `pdb`. After a refresh,
///   `cmd`/`ucrtbase`/`KERNELBASE`/`KERNEL32` back to `deferred` and `ntdll` still `pdb` — real
///   PDB state discarded, and *most* modules rather than all of them.
/// * the checked-in kernel dump, 227 modules. `nt` is `pdb` and stays `pdb` across a refresh; the
///   other 226 are `deferred` either side. **Nothing is discarded at all.**
///
/// Which fits what the reload is: on a live target it re-reads the module list and the entries are
/// rebuilt, while a dump's list comes from its own header and there is nothing to re-read. So the
/// note beside the listing says *on a live target*, and a caller reading a dump is not warned
/// about a cost that target cannot pay.
///
/// **`before` is read here rather than derived**, because the count the caller needs is the one
/// from before the reload and there is no later moment that still has it. It is the engine's own
/// bookkeeping — `GetNumberModules` and the parameter block behind it — not a target read, so it
/// costs the same as the listing that follows and no round trip to the debuggee.
///
/// A `Failed` here is a pre-count that did not work, which is the same call the listing itself is
/// about to make: there is nothing to report a refresh against if the inventory cannot be read at
/// all, and letting it through would only move the identical failure two lines down.
///
/// [#85]: https://github.com/glslang/windbg-mcp/issues/85
fn resynchronise(e: &DebugEngine) -> Result<structured::ModuleRefresh, Failed> {
    let before = e.modules().map_err(failed)?.len();
    match e.reload_symbols("") {
        Ok(()) => Ok(structured::ModuleRefresh {
            synchronized: true,
            before,
            error: None,
        }),
        Err(why) => {
            // Logged as well as reported, because the reported half is a field on a result that
            // still looks like an answer, and the server's own record of a failing engine call
            // belongs in the log whether or not the caller reads the field.
            tracing::warn!("worker: the module inventory could not be resynchronised: {why}");
            Ok(structured::ModuleRefresh {
                synchronized: false,
                before,
                error: Some(why.to_string()),
            })
        }
    }
}

/// The records a pattern matched, each still paired with the engine's own — which is what the PDB
/// lookup needs, and the reason matching and cutting are two steps rather than one iterator.
///
/// Converted before it is matched, so the name a row is *matched* by is read from the same record,
/// by the same accessor, as the name it is *listed* by ([#120]).
///
/// [#120]: https://github.com/glslang/windbg-mcp/issues/120
fn matching<'a>(
    modules: &'a [dbgscope::dbgeng::Module],
    pattern: Option<&str>,
) -> Vec<(structured::ModuleInfo, &'a dbgscope::dbgeng::Module)> {
    modules
        .iter()
        .map(|module| (structured::ModuleInfo::from(module), module))
        .filter(|(info, _)| {
            pattern.is_none_or(|pattern| matches_module_pattern(pattern, info.listed_name()))
        })
        .collect()
}

/// The first `take` of those rows, with each one's PDB identity read.
///
/// Asked last, and only about the rows the answer carries: [`with_pdb_identity`] is an engine call
/// per row, so cutting first is the difference between one lookup per module the target has loaded
/// and one per row printed. The cap buys time here as well as context at the other end.
fn identified(
    e: &DebugEngine,
    matched: Vec<(structured::ModuleInfo, &dbgscope::dbgeng::Module)>,
    take: usize,
) -> Vec<structured::ModuleInfo> {
    matched
        .into_iter()
        .take(take)
        .map(|(info, module)| with_pdb_identity(e, module, info))
        .collect()
}

/// The listing a person reads, built from the records beside it.
///
/// Two tables at most — the loaded modules and the unloaded ones, each under a heading naming
/// which it is — and then one line about the listing as a whole. Neither table is printed when it
/// is empty: a filter that matched only unloaded images should not be preceded by an empty column
/// header, and one that matched nothing at all is the note alone.
fn render_modules(list: &structured::ModuleList) -> String {
    let mut out = String::new();
    if !list.modules.is_empty() {
        out.push_str(&fenced(&module_table(&list.modules, "module")));
    }
    if !list.unloaded.is_empty() {
        if !out.is_empty() {
            out.push('\n');
        }
        // Said above the rows rather than in the note below them, because it is what the two
        // address columns *mean* here and a reader meets them first.
        out.push_str(
            "Unloaded modules — `start` and `end` are where the image was, not where it is:\n\n",
        );
        out.push_str(&fenced(&module_table(&list.unloaded, "image")));
    }
    let note = listing_note(list);
    let listing = if out.is_empty() {
        note
    } else {
        format!("{out}\n{note}")
    };
    // Above everything, including the tables — a refresh that failed makes every count below it
    // untrustworthy, and a caveat printed under a table is read after the conclusion it was there
    // to prevent. Composed last rather than pushed first so the two tables keep deciding their own
    // spacing from whether *they* are empty.
    match refresh_note(list.refresh.as_ref(), list.loaded) {
        Some(said) => format!("{said}\n\n{listing}"),
        None => listing,
    }
}

/// The line above a listing that says what the call's `refresh` did — and nothing at all for the
/// calls that asked for none, which is every default one.
///
/// Three states, because they are three different things to do next. A resynchronisation that
/// **found something** is the case [#85] is about, and it names both counts: a caller who has just
/// been told the driver is not loaded needs to see that the inventory it was told that from had
/// one module in it. One that found **nothing new** is worth a line too — it is what turns "the
/// module is absent" from a guess into an answer, and without it a caller has no way to tell a
/// refresh that ran from one that was ignored. And one that **failed** is the only line that
/// carries advice, because it is the only one where the listing under it may be wrong.
///
/// [#85]: https://github.com/glslang/windbg-mcp/issues/85
fn refresh_note(refresh: Option<&structured::ModuleRefresh>, loaded: usize) -> Option<String> {
    let refresh = refresh?;
    // Keyed on `synchronized` rather than on the presence of `error`, so the sentence and the flag
    // beside it cannot say different things: `synchronized` is the field that *means* it, and the
    // reason is what a failure additionally carries.
    if refresh.synchronized {
        let found = if loaded > refresh.before {
            format!(
                "Inventory resynchronised with the target: {} module(s) before, {loaded} now.",
                refresh.before
            )
        } else {
            format!("Inventory resynchronised with the target; it already held all {loaded}.")
        };
        return Some(format!(
            "{found} On a live target it discards the symbol information the engine had loaded \
             (most modules come back `deferred`), so load symbols **after** refreshing rather \
             than before."
        ));
    }
    let warning = "**The inventory could not be resynchronised**, so the listing below is whatever \
                   the engine was already holding and may be missing modules the target has \
                   loaded — a module absent from it is not evidence it is absent from the target.";
    // The engine's own words, escaped like every other string that came from outside this server.
    // A failure with no reason is a state this worker does not produce, but the sentence above is
    // the load-bearing half and must not depend on one having survived the trip.
    Some(match &refresh.error {
        Some(why) => format!("{warning} The engine said: {}", renderable(why)),
        None => warning.to_string(),
    })
}

/// One table: a header, then a row per module.
///
/// The name column is sized from the rows it holds — every other column has a fixed width, since
/// the addresses are this module's one representation (`0x` and sixteen digits, always) and the
/// symbol state is a short word. Names are never truncated to fit: a listing whose text and values
/// disagree about a *name* is the disagreement this rendering exists to remove.
///
/// **The names are the target's, not this server's**, so they go through [`renderable`] like any
/// other untrusted string — and the width is measured on what is actually printed, so an escaped
/// name still lines its row up.
///
/// What the rows are printed *into* is the other half of that, and it is [`fenced`]'s: the
/// alignment below only means anything in a monospaced block, and so does the promise that a name
/// is shown as itself rather than as markup.
fn module_table(rows: &[structured::ModuleInfo], names: &str) -> String {
    let listed: Vec<_> = rows
        .iter()
        .map(|row| renderable(row.listed_name()))
        .collect();
    // At least as wide as the column's own header, which is also the answer for a table with no
    // rows in it — `format!`'s width counts characters, so this does too.
    let width = listed.iter().fold(names.chars().count(), |width, name| {
        width.max(name.chars().count())
    });
    let mut out = format!("{:<18}  {:<18}  {names:<width$}  symbols\n", "start", "end");
    for (row, name) in rows.iter().zip(&listed) {
        // Trimmed at the end: the last column is padded for nothing, and trailing spaces on every
        // line of a tool result are noise.
        out.push_str(
            format!(
                "{}  {}  {name:<width$}  {}",
                row.start, row.end, row.symbols
            )
            .trim_end(),
        );
        out.push('\n');
    }
    out
}

/// The one line under the rows: what this listing is, and what it is a part of.
///
/// **Counted from what matched, not from what was printed.** Both halves are cut to the call's
/// `limit`, so the row counts and the match counts are different numbers — and it is the match
/// counts that answer the question the note is here for. [`truncation_note`] then says what the
/// rows are, which is the only part of this the cap changed.
fn listing_note(list: &structured::ModuleList) -> String {
    let note = match &list.filter {
        Some(pattern) => narrowing_note(pattern, list.matched, list.loaded, list.unloaded_matched),
        // The whole table. `loaded` is still worth printing under it — it is the number a reader
        // would otherwise count — and the unloaded half is named as the separate thing it is.
        None if list.unloaded_matched == 0 => format!("{} module(s) loaded.", list.loaded),
        None => format!(
            "{} module(s) loaded, and {} that have since **unloaded** — {WHERE_UNLOADED}",
            list.loaded, list.unloaded_matched
        ),
    };
    match truncation_note(list) {
        Some(cut) => format!("{note} {cut}"),
        None => note,
    }
}

/// What the note adds when `limit` stopped a table short of what matched — and nothing at all when
/// it did not, which is every filtered listing anyone actually types.
///
/// Said per table even though the budget is shared, because a caller reads the two tables as two
/// answers: which half was cut is what tells them whether to raise `limit` or to narrow with
/// `filter`. It names `limit` rather than saying rows are missing, for the same reason
/// `backtrace`'s truncation line names `frames` — an answer that stops short has to name the
/// argument that undoes it.
///
/// **And it names the number**, which is the difference between one more call and two. The obvious
/// value to reach for is the count the note above just gave — `227 module(s) loaded` — and that one
/// is *guaranteed* to fall short, because the budget it goes into is shared with the unloaded half:
/// a local model measured driving this asked for `limit: 227`, was given 177 loaded rows and 50
/// unloaded ones, and had to ask a third time for the rest. Both halves are known here, so their
/// sum is known here, and a caller who wants all of it should have to read it rather than derive
/// it.
fn truncation_note(list: &structured::ModuleList) -> Option<String> {
    let cut = (
        list.modules.len() < list.matched,
        list.unloaded.len() < list.unloaded_matched,
    );
    let rows = match cut {
        (false, false) => return None,
        (true, false) => format!("the first {} loaded row(s)", list.modules.len()),
        (false, true) => format!("the first {} unloaded row(s)", list.unloaded.len()),
        (true, true) => format!(
            "the first {} loaded and {} unloaded row(s)",
            list.modules.len(),
            list.unloaded.len()
        ),
    };
    // What it would take to see everything that matched. Past the ceiling there is no such value,
    // and saying one would be worse than saying none: `filter` is the only way through from there.
    let all = list.matched + list.unloaded_matched;
    let rest = if all <= MAX_MODULE_ROWS as usize {
        format!(
            "`limit: {all}` returns all of them, or narrow with `filter` to ask about one driver"
        )
    } else {
        format!(
            "`limit` stops at {MAX_MODULE_ROWS}, short of the {all} that matched — narrow with \
             `filter` to ask about one driver"
        )
    };
    Some(format!("Showing {rows} — {rest}."))
}

/// Where the unloaded rows are, said wherever any of them are in the answer: above under their own
/// heading, and in a field of their own rather than among the loaded modules.
const WHERE_UNLOADED: &str = "listed above under `Unloaded modules` and carried as the `unloaded` \
                              values here, where the addresses say where an image was rather than \
                              where it is.";

/// What a narrowed listing says about the narrowing, under the rows.
///
/// Two things the rows above cannot say for themselves.
///
/// **A pattern that matched nothing** has no rows at all, so without this a filtered call is
/// indistinguishable from a target with no modules, or from a call that quietly failed. The
/// message also names the mistake callers actually make: the pattern matches the name symbols are
/// qualified by (`nt`), not the image file (`ntkrnlmp.exe`) — measured behaviour, since a dump
/// whose kernel image is `ntkrnlmp.exe` has no module of that name. And it names the other
/// mistake, which the refused-wildcard errors used to: `*` and `?` are the whole grammar here, so
/// a WinDbg pattern that leans on the rest of it (`nt[fd]*`) is matched literally and finds
/// nothing.
///
/// **Which half of the list matched.** A pattern can match only modules that have since unloaded —
/// `nvhda` on this repo's sample matches twenty-six of them and no loaded module — and that is an
/// answer rather than a miss, so it is reported as a count of what was found and not as a caveat
/// about what was not.
fn narrowing_note(pattern: &str, matched: usize, loaded: usize, unloaded: usize) -> String {
    let pattern = renderable(pattern);
    match (matched, unloaded) {
        // Nothing at all. The only branch that offers advice, because it is the only one where the
        // caller has nothing and may have asked the wrong question.
        (0, 0) => format!(
            "Nothing matches `{pattern}`; {loaded} module(s) are loaded. The pattern matches the \
             name symbols are qualified by — `nt`, not `ntkrnlmp.exe` — with `*` and `?` as the \
             only wildcards and every other character literal. Omit `filter` for the whole table, \
             or run execute {{ \"command\": \"lm m <pattern>\" }} for WinDbg's own wildcard grammar."
        ),
        // A find, not a miss: the driver is in this target's history rather than its present.
        (0, unloaded) => format!(
            "No *loaded* module matches `{pattern}`, but {unloaded} that have since **unloaded** \
             do — {WHERE_UNLOADED} {loaded} module(s) are loaded."
        ),
        (matched, 0) => format!("{matched} of {loaded} loaded module(s) match `{pattern}`."),
        (matched, unloaded) => format!(
            "{matched} of {loaded} loaded module(s) match `{pattern}`, and {unloaded} that have \
             since **unloaded** — {WHERE_UNLOADED}"
        ),
    }
}

/// A string from **outside this server**, made safe to put in the listing: anything that could
/// break out of the row or the span it is printed in is rendered as an escape rather than acted on.
///
/// Two such strings, and the reason is the same for both. The listing is line-oriented and its rows
/// begin with an address, so a string carrying a line break prints as *two* lines — and the second
/// can be shaped exactly like a row, putting a module in the text that the values beside it do not
/// have. That is the one property this rendering exists to hold, and it must not depend on what a
/// caller typed or on what the target calls itself:
///
/// * **the caller's `filter`**, quoted into the note. Until #120 it was command text and
///   `reject_command_breakers` refused line breaks along with `;`; the command went, and the
///   refusal with it, which is what left this open.
/// * **the module and image names**, which come from the target. Windows file names exclude the
///   characters below `0x20`, and nothing else: a driver may legally be named with a `U+2028`, and
///   a target being *analysed* is the last place to assume it is not — this server is pointed at
///   malware on purpose.
///
/// Escaped rather than refused, because "nothing matches this" is a perfectly good answer to a
/// pattern no module is named, and because a module named something hostile still has to be
/// listable. It also covers `\r` and an ANSI escape for the same money, where refusing line breaks
/// would let those through to a terminal.
///
/// [`renderable`] is not Markdown escaping and does not try to be — the backtick is in the set
/// because it is the delimiter this listing quotes with, so a string carrying one can hand what
/// follows it to a Markdown-rendering client as markup.
fn renderable(text: &str) -> std::borrow::Cow<'_, str> {
    if !text.contains(escapes_the_listing) {
        return std::borrow::Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            // `escape_debug` leaves a *printable* character alone, and a backtick is printable: it
            // is escaped here for what it does to the container, not for what it is.
            '`' => out.push_str("\\u{60}"),
            c if escapes_the_listing(c) => out.extend(c.escape_debug()),
            c => out.push(c),
        }
    }
    std::borrow::Cow::Owned(out)
}

/// Whether a character could put what follows it outside the row or the span it was printed in.
///
/// **Line breaks, in any renderer** — not only in [`str::lines`]. [`char::is_control`] is the
/// obvious test and is not enough: it is the `Cc` category, which holds `\n`, `\r`, `\u{b}`,
/// `\u{c}` and NEL, but *not* `U+2028 LINE SEPARATOR` or `U+2029 PARAGRAPH SEPARATOR` — which are
/// `Zl`/`Zp`, break a line in a Unicode-aware renderer, and are invisible to `lines()` and so to a
/// test written against it. Those two are the rest of Unicode's line-break set.
///
/// The controls that are *not* line breaks stay in for a second reason: an ESC in a listing is an
/// ANSI sequence a terminal acts on.
///
/// **And the backtick**, which is the listing's own quoting delimiter: a pattern containing one
/// closes the code span it was quoted into, and everything after it is markup to a client that
/// renders Markdown — `<br>` included, which is a line break this would otherwise never see.
fn escapes_the_listing(c: char) -> bool {
    c.is_control() || matches!(c, '\u{2028}' | '\u{2029}' | '`')
}

/// Puts a table in a fenced block, which is the container its rows are written for.
///
/// The columns are padded to line up, and that only means anything in a monospaced,
/// whitespace-preserving context. Printed bare, a Markdown-rendering client reflows the rows into
/// a paragraph and the alignment the padding paid for is gone — so the fence is what the table
/// always needed to render as a table at all.
///
/// It also settles what the rows may contain, which is the reason it went in. A name is the
/// target's to choose and was being printed with no container around it, so
/// `[ntdll.dll](https://elsewhere)` — a legal Windows file name — displayed as `ntdll.dll` with
/// the rest hidden: nothing broke out of the row, the row simply stated a different name than the
/// module had, while `structuredContent` carried the truth. Inside a fence every one of those
/// constructs is literal text, so there is no set of Markdown metacharacters to keep escaping and
/// keep up to date, and ordinary names stay exactly as the target spells them.
///
/// **The one way out of a fence is its own delimiter**, and [`renderable`] already escapes the
/// backtick for the note's code span. That guard is what holds this container shut too, which is
/// why it is not repeated here.
fn fenced(table: &str) -> String {
    format!("```\n{table}```\n")
}

/// Everything a bug check is, gathered as one indivisible job.
///
/// Six engine reads and (optionally) one command. They are one op because the frames and the
/// module bases they are turned into RVAs against have to describe the *same* target: interleave
/// another call for this session between the walk and the attribution and the offsets are
/// computed against bases that have moved, which is the one number this tool exists to get right.
///
/// **Only the bug check itself can fail this call.** A crash with no readable stack, no nameable
/// process or no `!analyze` is still a crash, and reporting "the process name could not be read"
/// as a failed triage would throw away the code, the parameters and everything else the dump did
/// give up. So each of those comes back as an absent field, and the report says so.
fn crash_triage(
    e: &DebugEngine,
    frames: usize,
    analyze: bool,
    patience: Duration,
    queued: Duration,
) -> Result<Output, Failed> {
    // Started before the first engine read, not before the `!analyze`. Everything below is on the
    // caller's clock, and the reads are not free — resolving a frame's symbol can pull a PDB over
    // the network — so an `!analyze` that measured only its own elapsed time would be handed a
    // budget the caller had mostly already spent.
    let started = Instant::now();
    let bug_check = match e.bug_check() {
        Ok(Some(bug_check)) => bug_check,
        // A kernel target that did not bug check. Both cases are named because they want opposite
        // responses: a live kernel simply has not crashed *yet*, and a dump that is not a crash
        // dump never will.
        Ok(None) => {
            return Err(Failed::categorised(
                structured::ErrorCategory::Debugger,
                "this target is not stopped at a bug check: the engine reports bug check code 0. \
                 A live kernel reads this way until it actually crashes — leave the session open, \
                 `go`, and triage it once it does. A dump reads this way when it is not a crash \
                 dump (a live-system or hand-written dump), and nothing will change that.",
            ));
        }
        // The engine has no bug check data to read at all, which on a user-mode target is not a
        // failure of this call so much as the wrong question — said plainly, because "reading the
        // target's bug check data failed: 0x80004005" is not.
        Err(why) => {
            let user_mode = matches!(e.is_kernel_target(), Ok(false));
            return Err(Failed::categorised(
                structured::ErrorCategory::Debugger,
                if user_mode {
                    // The pointer that used to end this sentence named `backtrace` and
                    // `execute`, both `inspect`, while `crash_triage` is `crash` — so on an
                    // eleven-tool surface it sent a caller to two tools it would be refused. The
                    // server appends it, where the surface is.
                    structured::USER_MODE_NO_BUG_CHECK.to_string()
                } else {
                    format!("the target's bug check data could not be read: {why}")
                },
            ));
        }
    };

    // **The scope is saved here and restored when this returns.** `!analyze -v` leaves the
    // session's scope at the target's *default*, discarding whatever the caller had selected —
    // measured on a `0x13A`, a `0xD1`, a `0x9F` and a user-mode AV (glslang/dbgscope#98). Nothing
    // is written to the debuggee, but a `.frame 3` or `.ecxr` a caller set before calling this is
    // gone afterwards, and that is a change to what every other tool on the session reads. The
    // guard is what lets this tool be annotated read-only; it restores on every path out,
    // including the interrupt return below.
    //
    // Best-effort by design: the bug check above already read through this engine, so a scope that
    // cannot be read here is not a state this can reach — and failing a triage over the bookkeeping
    // around it would trade the whole answer for tidiness.
    let _scope = e.scope_guard().inspect_err(|why| {
        tracing::debug!("worker: crash triage could not save the debugger scope: {why}");
    });

    // **`!analyze` runs before the reads, not after**, and the ordering is load-bearing — though
    // not for the reason it looks like. The analysis *does* go and look at the thread it blames:
    // on the `0x9F` sample its output says `Implicit thread is now …` partway through, naming a
    // thread that is not the one the dump opens on. But it puts that back before it returns, and
    // leaves the scope at the default. So running it first *normalises* a session a caller had
    // navigated (`.frame`, `.cxr`) back to the default before the stack is walked, which is what
    // makes two triages of one session agree.
    //
    // **That normalisation is a side effect of the analysis, so it holds exactly when the analysis
    // *completed*.** Two ways it does not. `run_analyze` declines to start when the patience is
    // already spent, and both spellings can fail to resolve on an engine with no `ext.dll` —
    // nothing has moved the scope, and the reads describe whatever the caller had selected, the
    // same as `analyze: false`. And a run the **deadline** cut short is not a cancellation
    // ([`Analysis::interrupted`] is false for it, deliberately), so the reads below still happen —
    // but the reset is something `!analyze` does partway through its own output, not at the end,
    // so a truncated run may or may not have reached it and this cannot tell which.
    //
    // Hence the qualification a caller is given is `ran` **and not** `truncated`, not `ran` alone.
    // Not fixed by resetting the scope here instead: that would make the tool normalise a session
    // it was not asked to normalise, and the claim would then be one no host with a working
    // `ext.dll` can test — the whole point of this comment is that the reset is the analysis's,
    // and where it does not happen there is nothing to demonstrate.
    //
    // With `analyze: false` nothing normalises anything, and the reads describe whichever scope
    // the session currently has — the same one `backtrace` would show. On a freshly opened crash
    // dump that *is* the crash context; on a session where a caller has moved it (`.thread`,
    // `~Ns`, `.cxr`) it is wherever they moved it, and this mode has no way to tell. Said plainly
    // in the tool's own documentation rather than papered over, because the alternative is a
    // report that labels an unrelated thread's stack as the crash.
    //
    // The ordering has one cost, and it is paid here rather than left to bite. The reads below are
    // *unbounded* — they are direct engine calls, not commands, so no watchdog can cut them short,
    // and resolving a frame's symbol can block on a symbol server. While they came first that was
    // harmless, because the analysis after them was bounded by whatever they had left. Now they
    // come last, so the analysis is handed a patience with [`TRIAGE_READ_RESERVE`] already taken
    // out of it: time this side of the pipe cannot bound, and therefore has to reserve.
    let analysis = if analyze {
        run_analyze(
            e,
            patience.saturating_sub(TRIAGE_READ_RESERVE),
            queued.saturating_add(started.elapsed()),
        )
    } else {
        Analysis::NotRequested
    };

    // **An interrupt stops here, before the reads rather than after them.** They are unbounded,
    // so starting them now would mean the caller who just asked this call to stop waits for a
    // stack walk that can block on a symbol server — which is the one thing `interrupt` exists to
    // prevent. What has already been read (the bug check, and whatever `!analyze` printed) still
    // comes back; the report says the walk was abandoned rather than empty, because "found
    // nothing" would be a claim about the crash and this is a claim about the call.
    //
    // Asked two ways, because one interrupt can arrive in two places. `Analysis::interrupted` sees
    // a break that landed *inside* the `!analyze`; the engine's own pending flag sees one that
    // landed anywhere else — between the analysis finishing and this line, or during a triage that
    // never ran an analysis at all (`analyze: false`), neither of which the analysis state can
    // know about. Deriving cancellation from the parsed output alone would make it depend on
    // exactly when the break landed, which is the one thing a caller cannot aim.
    if analysis.interrupted() || matches!(e.interrupted(), Ok(true)) {
        let report = triage::report(bug_check, &triage::Walk::Abandoned, None, analysis);
        return Ok(Output::typed(triage::render(&report), report));
    }

    // Best effort here, unlike `backtrace`: a triage that cannot walk the stack still has the bug
    // check, the parameters and whatever `!analyze` printed, and the report renders a missing walk
    // as "no faulting frame" with the reason — strictly more than a failed call would say.
    let (attributed, truncated) =
        walk_attributed(e, frames, "crash triage").unwrap_or_else(|why| {
            tracing::debug!("worker: crash triage could not walk the stack: {why}");
            (Vec::new(), false)
        });
    let process_name = e
        .current_process_name()
        .ok()
        .filter(|name| !name.trim().is_empty());

    let walk = triage::Walk::Done {
        frames: attributed,
        truncated,
    };
    let report = triage::report(bug_check, &walk, process_name, analysis);
    Ok(Output::typed(triage::render(&report), report))
}

/// The current thread's stack, each frame attributed to the module holding it, and whether the
/// stack went on past `frames`.
///
/// **One helper for both stack tools.** `crash_triage` and `backtrace` ask the engine the same two
/// questions per frame — where the instruction is, and which image holds it — and the answer to
/// the second is what becomes `module` + `rva`. Written twice they would agree until one of them
/// was fixed, and the claim this coordinate rests on is that a frame from either tool names the
/// same place.
///
/// **One frame more than the caller asked for**, so that "the stack went on" and "the stack was
/// exactly this long" are different observations rather than the same one. `GetStackTrace` says
/// how much of the buffer it filled, never how much it left, so a walk that came back exactly full
/// is ambiguous — and the ambiguity is not cosmetic: for a triage it decides whether a missing
/// `faulting_frame` is a fact about the crash or an artefact of the cap. The extra frame is
/// trimmed before anything sees it; it exists only to be counted.
///
/// `what` names the caller in the log lines, because an attribution that failed is a fact about
/// one frame of one call and the two tools are read in different places.
fn walk_attributed(
    e: &DebugEngine,
    frames: usize,
    what: &str,
) -> Result<(Vec<AttributedFrame>, bool), String> {
    let mut walked = e.stack_frames(frames.saturating_add(1)).map_err(es)?;
    let truncated = walked.len() > frames;
    walked.truncate(frames);
    let attributed = walked
        .into_iter()
        .map(|frame| AttributedFrame {
            // The three answers are kept apart rather than collapsed into "no module". A lookup
            // that *failed* says nothing about where the address is, and treating it as "in no
            // module" would let it be blamed as the culprit — pre-empting the real driver frame
            // below it on the strength of the engine having declined to answer.
            module: match e.module_at(frame.instruction_offset) {
                Ok(Some(module)) => Attribution::In(module),
                Ok(None) => Attribution::NoModule,
                Err(why) => {
                    tracing::debug!(
                        "worker: {what} could not attribute frame {}: {why}",
                        frame.index
                    );
                    Attribution::Unknown
                }
            },
            frame,
        })
        .collect();
    Ok((attributed, truncated))
}

/// The call stack, as values and as the listing rendered from them.
///
/// One op rather than `k` for the reason [`crate::proto::EngineOp::Backtrace`] gives: the answer
/// is each frame's `module` + `rva`, and nothing but the worker can ask the engine for it.
///
/// **The walk failing fails this call**, unlike in a triage. A triage that cannot walk still has a
/// bug check to report; here the stack *is* the answer, and an empty one would say "this thread has
/// no frames" — a claim about the target — when what happened was that a read failed.
fn backtrace(e: &DebugEngine, frames: usize) -> Result<Output, Failed> {
    let (attributed, frames_truncated) = walk_attributed(e, frames, "backtrace").map_err(failed)?;
    let trace = structured::StackTrace {
        frames: attributed.iter().map(triage::frame_info).collect(),
        frames_truncated,
    };
    Ok(Output::typed(render_backtrace(&trace, frames), trace))
}

/// The stack a person reads, built from the records beside it.
///
/// Each frame on one line through [`triage::describe`], so the listing here and the `STACK`
/// section of a triage are the same rendering rather than two that look alike.
fn render_backtrace(trace: &structured::StackTrace, asked: usize) -> String {
    // Not an error, and not necessarily an empty thread either: a target stopped with no thread
    // context — a module-load break, a bare `goto_position` to the very start of a trace — has a
    // position but no stack to walk, and `k` prints nothing at all for it. Saying which of the two
    // this is would be a guess; saying that the walk returned nothing is the fact.
    if trace.frames.is_empty() {
        return "No frames: the engine walked no stack from the current context. That is what a \
                target with no thread context selected looks like (a module-load break, or a \
                trace positioned before its first thread); `registers` says whether there is a \
                context at all."
            .to_string();
    }
    let mut listing = String::new();
    for frame in &trace.frames {
        // Escaped for the same reason a module name is ([#126]): a frame's `module` and `symbol`
        // are read out of the target, a module can legally be named with a backtick, and this line
        // is going inside a fence. Applied to the whole rendered line rather than to the fields,
        // so a form of the coordinate added later cannot escape by being added in the wrong place.
        //
        // [#126]: https://github.com/glslang/windbg-mcp/issues/126
        listing.push_str(&format!(
            "{:02} {}\n",
            frame.index,
            renderable(&triage::describe(frame))
        ));
    }
    let mut out = fenced(&listing);
    out.push_str(&format!(
        "\n{} frame{} from the current context. Each frame is `module+RVA` as well as its \
         symbol — the offset is computed from the load base, so it is the half that survives a \
         driver with no PDB and stays comparable across reboots.\n",
        trace.frames.len(),
        if trace.frames.len() == 1 { "" } else { "s" },
    ));
    if trace.frames_truncated {
        out.push_str(&format!(
            "The stack goes on past frame {}: this call asked for {asked}. Raise `frames` to see \
             the rest.\n",
            asked.saturating_sub(1),
        ));
    }
    out
}

/// DbgEng writes a 64-bit address as ``fffff801`3c677ef0`` — a backtick separating the halves —
/// and an instruction's operands are full of them: `bl nt!Foo (fffff801`3c677ef0)`.
///
/// Removed here for two reasons that happen to agree. This server spells an address one way
/// ([`structured::addr`]), and `docs/structured-results.md` says the debugger's form appears only
/// in raw text; and
/// that tick is the delimiter of the code span this text is printed in, so leaving it means every
/// operand carrying an address renders as `\u{60}` once [`renderable`] has made it safe.
///
/// **Only where it is an address.** Exactly eight hex digits either side, bounded by non-hex,
/// which is the form DbgEng emits and nothing else is. MSVC decorates real symbols with backticks
/// — `` `anonymous namespace'::Foo ``, `` `vftable' `` — and stripping those would corrupt a name;
/// they survive here and are escaped by `renderable` as any other backtick is.
fn plain_addresses(text: &str) -> String {
    let bytes = text.as_bytes();
    let hex = |index: usize| bytes[index].is_ascii_hexdigit();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        let separates_two_halves = bytes[at] == b'`'
            && at >= 8
            && at + 8 < bytes.len()
            && (at - 8..at).all(hex)
            && (at + 1..at + 9).all(hex)
            && (at == 8 || !hex(at - 9))
            && (at + 9 == bytes.len() || !hex(at + 9));
        if separates_two_halves {
            at += 1;
            continue;
        }
        out.push(bytes[at]);
        at += 1;
    }
    // Only ever drops one ASCII byte, so the boundaries of everything else are untouched.
    String::from_utf8_lossy(&out).into_owned()
}

/// A run of instructions, as values and as the listing rendered from them.
///
/// `address` is an expression rather than a number because that is what a caller has — a symbol,
/// `module+0x1c`, a register — and only the debugger can evaluate one. `None` disassembles at the
/// current instruction pointer, which is what a bare `u` does.
fn disassemble(e: &DebugEngine, address: Option<&str>, count: usize) -> Result<Output, Failed> {
    let start = match address {
        Some(expr) => {
            resolve(e, expr).ok_or_else(|| format!("could not resolve address `{expr}`"))?
        }
        // Not an error worth dressing up: a target with no register context has no current
        // instruction, and the engine says so better than a guess here would.
        None => e.instruction_pointer().map_err(failed)?,
    };
    let decoded = e.disassemble(start, count).map_err(failed)?;

    // **Asked once per image, not once per instruction.** A disassembly is a contiguous range, so
    // after the first lookup every following address is almost always inside the same module — and
    // a containment test is arithmetic where `module_at` is a call into the engine. Correctness
    // does not rest on the guess: an address outside the module in hand re-asks.
    let mut held: Option<dbgscope::dbgeng::Module> = None;
    let mut instructions = Vec::with_capacity(decoded.len());
    for instruction in &decoded {
        let inside = |module: &dbgscope::dbgeng::Module| {
            instruction.address >= module.base && instruction.address < module.end()
        };
        let mut attribution_failed = false;
        if !held.as_ref().is_some_and(inside) {
            held = match e.module_at(instruction.address) {
                Ok(module) => module,
                // Kept apart from `Ok(None)` for the reason a stack walk keeps them apart: one
                // says the address is outside every image, which is a finding, and the other says
                // the engine did not answer, which is not.
                Err(why) => {
                    tracing::debug!(
                        "worker: disassembly could not attribute {:#x}: {why}",
                        instruction.address
                    );
                    attribution_failed = true;
                    None
                }
            };
        }
        // An unloaded module has no name to qualify anything with, exactly as in a stack walk.
        let named = held.as_ref().filter(|module| !module.name.is_empty());
        instructions.push(structured::InstructionInfo {
            address: structured::addr(instruction.address),
            module: named.map(|module| module.name.clone()),
            // `saturating_sub`, as the stack walk's is: the base is the engine's and the address
            // is the walk's, and an underflow here would print a 16-exabyte offset rather than
            // fail — the sort of number nobody double-checks.
            rva: named
                .map(|module| triage::offset(instruction.address.saturating_sub(module.base))),
            attribution_failed,
            bytes: instruction.bytes.clone(),
            text: plain_addresses(&instruction.text),
        });
    }

    let disassembly = structured::Disassembly {
        start: structured::addr(start),
        instructions,
        stopped_early: decoded.len() < count,
    };
    Ok(Output::typed(render_disassembly(&disassembly), disassembly))
}

/// The listing a person reads, built from the records beside it.
///
/// Columns are the coordinate, the encoding and the instruction — the absolute address is in the
/// values and in the heading, because printing it on every row costs a screen's width to repeat
/// what the module base plus the offset already says.
fn render_disassembly(disassembly: &structured::Disassembly) -> String {
    if disassembly.instructions.is_empty() {
        return format!(
            "No instructions: the engine disassembled nothing at {}. That address is readable as \
             a number and not as code — unmapped, paged out, or past the end of what this target \
             holds.",
            disassembly.start
        );
    }
    let mut listing = String::new();
    for instruction in &disassembly.instructions {
        // The engine's rendering of bytes the *target* holds, going inside a fence: escaped for
        // the reason a module name is ([#126]), since an operand carries symbol names from the
        // image and an image can be named anything at all.
        //
        // [#126]: https://github.com/glslang/windbg-mcp/issues/126
        // `module+rva` — the form that can be pasted straight back into the debugger. An
        // instruction in no module keeps its address, which is all there is to say about it, and
        // one whose lookup failed says that rather than looking like the first.
        let coordinate = match (&instruction.module, &instruction.rva) {
            (Some(module), Some(rva)) => format!("{module}+{rva}"),
            _ if instruction.attribution_failed => {
                format!("{} (module lookup failed)", instruction.address)
            }
            _ => instruction.address.clone(),
        };
        listing.push_str(&format!(
            "{:<18} {:<20} {}\n",
            renderable(&coordinate),
            renderable(&instruction.bytes),
            renderable(&instruction.text),
        ));
    }
    let mut out = fenced(&listing);
    out.push_str(&format!(
        "\n{} instruction{} from {}{}. The first column is the offset into the image, which is \
         what an analysis server can be asked about; the second is the encoding, which is what \
         says whether it holds the same build.\n",
        disassembly.instructions.len(),
        if disassembly.instructions.len() == 1 {
            ""
        } else {
            "s"
        },
        disassembly.start,
        // Named from the instructions rather than carried separately, and escaped: a module name
        // is read out of the target, this sentence is outside the fence that protects the rows,
        // and a backtick in a name would close the code span and leave the rest as markup — the
        // defect `summary_text` already guards against for the same construct.
        match disassembly.instructions.first() {
            Some(first) => match first.module.as_deref() {
                Some(module) => format!(" in `{}`", renderable(module)),
                // The row for this instruction says the lookup failed; the sentence must not turn
                // the same absence into a finding about the target two lines below it.
                None if first.attribution_failed => {
                    " in a module the engine could not name".to_string()
                }
                None => " in no loaded module".to_string(),
            },
            None => String::new(),
        },
    ));
    if disassembly.stopped_early {
        out.push_str(
            "The engine stopped before the count asked for: what follows the last instruction \
             could not be disassembled, so this is where the code ends rather than where the call \
             ran out. Asking again with a larger count returns the same instructions.\n",
        );
    }
    out
}

/// Runs `!analyze -v`, whichever spelling this engine resolves.
/// Runs `!analyze -v`, whichever spelling this engine resolves.
///
/// The bundled minimal engine does not resolve the unqualified `!analyze` even after `.load ext`
/// — only the module-qualified `!ext.analyze` does — while a full WinDbg install resolves both.
/// So the plain form is tried first and the qualified one is the fallback, and which one worked
/// is reported rather than assumed.
///
/// **The deadline is checked before *every* attempt, not just the fallback.**
/// `watchdog_budget_ms` floors at [`WATCHDOG_HEADROOM`] — deliberately, because a command dequeued
/// past its deadline must still be bounded by *something* — so an attempt started with nothing left
/// still runs for a floor's worth, and two of them for two floors, all of it after the caller has
/// given up. Checking first is the arithmetic [`crate::batch`] does per step and for the same
/// reason. Note the reads *ahead* of this can exhaust the patience on their own, so the very first
/// attempt is as capable of being skipped as the second.
///
/// `before` is what the whole triage has already spent, not just what it queued for: resolving a
/// frame's symbol can pull a PDB over the network, and an `!analyze` handed the full patience
/// afterwards would run on past its caller either way.
///
/// **Why it did not run matters**, so the three ways of failing are kept apart: no time left, the
/// run cut short before it printed anything readable, and both spellings tried with neither
/// resolving. Reporting any of them as the last sends a caller looking for an `ext.dll` that is
/// sitting right where it should be.
fn run_analyze(e: &DebugEngine, patience: Duration, before: Duration) -> Analysis {
    let started = Instant::now();
    let mut last: Option<String> = None;
    let mut ran_out = false;
    // `Some(on_request)` once an attempt has been cut short with nothing readable to keep.
    let mut cut_short: Option<bool> = None;
    for command in ["!analyze -v", "!ext.analyze -v"] {
        let spent = before.saturating_add(started.elapsed());
        if !analysis_fits(patience, spent) {
            ran_out = true;
            break;
        }
        match e.execute_command_bounded(command, watchdog_budget_ms(patience, spent)) {
            // Cut short. The output is *not* discarded — `!analyze` prints its summary block
            // early, so a truncated run usually still carries the code and the arguments — but it
            // is reported as truncated, because otherwise a `pool_tag` that was merely never
            // reached is indistinguishable from one `!analyze` decided there was none.
            //
            // The *cause* travels with it. A deadline and a caller's `interrupt` both land here
            // and the advice differs: one says raise the timeout, the other is a caller who
            // already knows, having asked.
            // **Any cut-short ends the attempts, whether or not it left anything readable.**
            //
            // The fallback spelling exists for one failure and one only: an engine on which the
            // command does not *resolve*. A command that got far enough to be cut short plainly
            // resolved, so the other spelling has nothing to add — and trying it anyway is
            // actively wrong for both causes. After an `interrupt` it would restart, under a fresh
            // watchdog, the very work the caller just asked to stop. After a deadline it would run
            // for another floor's worth past a caller who has gone: the `spent >= patience` check
            // above does not catch that one, because a deadline fires with the reply's headroom
            // still nominally unspent.
            Ok(run) if run.cut_short.is_some() => {
                let on_request = matches!(run.cut_short, Some(Interruption::OnRequest));
                if looks_analysed(&run.output) {
                    return Analysis::Truncated {
                        command: command.to_string(),
                        output: run.output,
                        on_request,
                    };
                }
                // Cut short before it printed anything this can read. There is no partial
                // analysis to keep, so it is not `Truncated` — but it is still terminal, and the
                // reason a caller gets has to be the interruption rather than the missing
                // `ext.dll` the fallback path would otherwise blame.
                cut_short = Some(on_request);
                break;
            }
            // An engine without the extension answers with "No export analyze found" and an
            // otherwise empty result, which is a *successful* command that analysed nothing — so
            // emptiness, not the HRESULT, is what decides whether to try the other spelling.
            Ok(run) if looks_analysed(&run.output) => {
                return Analysis::Ran {
                    command: command.to_string(),
                    output: run.output,
                };
            }
            Ok(run) => {
                last = Some(format!(
                    "`{command}` returned no analysis: {}",
                    brief(&run.output)
                ))
            }
            Err(why) => last = Some(format!("`{command}` failed: {why}")),
        }
    }
    // An on-request break is *cancellation*, and it stays cancellation even when there was nothing
    // readable to keep: the triage has to abandon the reads after this either way, so what it gets
    // back has to say so rather than look like an ordinary unavailability.
    if cut_short == Some(true) {
        return Analysis::Interrupted(
            "`!analyze -v` was interrupted on this session before it printed anything worth \
             keeping, and was not retried — retrying would restart the very work the interrupt \
             asked to stop. Triage again without interrupting."
                .to_string(),
        );
    }
    let why = if cut_short.is_some() {
        "it hit this call's deadline before printing anything worth keeping. Raise \
         WINDBG_MCP_CALL_TIMEOUT_SECS, or issue the triage on an idle session."
            .to_string()
    } else if ran_out {
        format!(
            "this call had less than {}s of its timeout left{}, which is not enough to run an \
             `!analyze` *and* still have time to answer in: below that the watchdog is armed for \
             the whole of what remains, so a command that ran to its deadline would leave nothing \
             for the break to unwind in. Raise WINDBG_MCP_CALL_TIMEOUT_SECS (a triage also keeps \
             {}s back for the reads after the analysis, which no watchdog can cut short), issue \
             the triage on an idle session, or pass `analyze: false` to skip it deliberately.",
            (2 * WATCHDOG_HEADROOM).as_secs(),
            match &last {
                Some(first) => format!(" by the time the first attempt had been made and {first}"),
                None => String::new(),
            },
            WATCHDOG_HEADROOM.as_secs(),
        )
    } else {
        format!(
            "neither `!analyze -v` nor `!ext.analyze -v` resolved — the engine most likely has no \
             `winext\\ext.dll` beside it (see `docs/install.md`). Last attempt: {}",
            last.unwrap_or_else(|| "no output".to_string())
        )
    };
    Analysis::Unavailable(format!(
        "`!analyze -v` did not run, so the pool tag and failure bucket are missing; everything \
         else here is read from the engine and is unaffected. Reason: {why}"
    ))
}

/// Whether an `!analyze` attempt can still be bounded inside what is left of the caller's patience
/// **and leave the headroom the reply needs**.
///
/// Not "is any patience left", and not "does the watchdog fit" either. [`watchdog_budget_ms`]
/// subtracts [`WATCHDOG_HEADROOM`] precisely so that a command stopped at its deadline still has
/// time for the Ctrl+Break to unwind and the answer to travel — but it also *floors* at that same
/// figure, deliberately, because a command dequeued past its deadline must be bounded by
/// something. Below twice the headroom the floor wins, and the subtraction it overrides is exactly
/// the reserve the reply was relying on: with fifteen seconds left the watchdog is armed for
/// fifteen, so a command that runs to its deadline leaves nothing at all to answer in.
///
/// Twice the headroom is therefore the threshold — the point below which `watchdog_budget_ms` stops
/// keeping its own promise. The test below pins that as a *relationship* rather than as the
/// number, so it survives either constant being retuned.
fn analysis_fits(patience: Duration, spent: Duration) -> bool {
    patience.saturating_sub(spent) >= 2 * WATCHDOG_HEADROOM
}

/// Whether output is an analysis rather than the engine declining to run one.
///
/// `!analyze` on an engine with no extension DLL prints a one-line "No export analyze found" and
/// nothing else, so the test is for the summary block every real analysis has: the `Arguments:`
/// list, or one of the `KEY:  value` lines the fields are taken from.
fn looks_analysed(output: &str) -> bool {
    output.contains("Arguments:")
        || output.contains("BUGCHECK_CODE:")
        || output.contains("Bugcheck Analysis")
}

/// A one-line rendering of output that was not what was wanted, for a note about it.
fn brief(output: &str) -> String {
    let line = output
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("(no output)");
    line.chars().take(160).collect()
}

/// Sets a breakpoint and reports it, plus what the session holds afterwards.
///
/// **The id comes from the engine now, not from a diff.** This used to run `bp <expression>` and
/// subtract the breakpoint list either side of it, because a successful `bp` prints nothing at all
/// and there was no other way to learn what it had done. `set_breakpoint_bounded` hands back the
/// breakpoint it created, so the id, the address and whether it deferred are read off the object
/// itself. The diff went, and with it the whole degraded mode where the "before" read failed and
/// `added` was empty because it was *unknown* rather than empty — a distinction that needed two
/// fields and four paragraphs to explain and now cannot arise.
///
/// **`Replace`, deliberately, because that is what `bp` did.** The engine deduplicates nothing:
/// two typed sets at one address leave two breakpoints, both armed, and both *activate* on the one
/// stop — so each runs its command, and removing one by id leaves the address armed by the other.
/// `bp` resolves and then removes what is already there, printing `breakpoint N redefined`. Since
/// this tool's callers have always had that behaviour, keeping it is the change-free choice, and
/// [`structured::BreakpointSet::replaced`] is the line of debugger text turned into a value.
///
/// **The listing is still read, and is now unable to lie about the mutation.** It is an inspection
/// taken after the fact, best-effort: if it fails, `breakpoints` is empty and nothing else in the
/// result moves, because the breakpoint this call set is reported from the engine's own object
/// rather than by finding it in that list. The rule it used to need — an inspection that fails
/// after a mutation must not be reported as the mutation failing — is now a property of the shape
/// instead of a comment on a field.
///
/// **What survives unchanged is `cut_short`**, and the reason it is not an error. A break leaves
/// the breakpoint set and its location possibly unresolved, and an error is the shape a caller
/// retries — which here means a second breakpoint, since a deferred expression has no address to
/// deduplicate on. `render_breakpoints` is where that is explained to a human.
fn set_breakpoint(
    e: &DebugEngine,
    expression: &str,
    command: Option<&str>,
    one_shot: bool,
    pass_count: Option<u32>,
    budget_ms: u32,
) -> Result<Output, Failed> {
    let mut spec =
        BreakpointSpec::code(BreakpointAt::Expression(expression.to_string())).replacing_existing();
    if let Some(command) = command {
        spec = spec.with_command(command);
    }
    if one_shot {
        spec = spec.one_shot();
    }
    if let Some(passes) = pass_count {
        spec = spec.with_pass_count(passes);
    }
    // Bounded, and the bound is still real after the move off the text path: a symbolic location
    // is resolved eagerly, so `nt!Foo+0x10` on a module whose PDB is not local is a symbol-server
    // fetch with this session's engine held for all of it — 2445 ms measured for a cold
    // `KERNELBASE!CreateFileW`. `SetInterrupt` reaches that resolve, which is what makes this a
    // bound rather than a promise.
    let done = e.set_breakpoint_bounded(&spec, budget_ms).map_err(failed)?;
    // Best-effort and deliberately not a `?`: the breakpoint is set, and a session whose list
    // cannot be read must not have that reported as the set having failed.
    let breakpoints = e
        .breakpoints()
        .map(|held| held.iter().map(structured::BreakpointInfo::from).collect())
        .unwrap_or_default();
    let set = structured::BreakpointSet {
        breakpoint: structured::BreakpointInfo::from(&done.breakpoint),
        replaced: done.replaced,
        breakpoints,
        cut_short: done.cut_short.is_some(),
    };
    let mut text = told_cut_short_bp(done.cut_short);
    text.push_str(&render_breakpoints(&set));
    Ok(Output::typed(text, set))
}

/// [`told`] for a breakpoint, where the same deadline means the same thing and its advice does not.
///
/// `told` tells the caller to scope the query and retry, which is right for a search and wrong
/// twice over here: there is nothing to scope in a symbol, and setting a breakpoint is not
/// idempotent, so a retry is exactly the move that leaves two where the caller wanted one. What
/// replaces it is in [`render_breakpoints`], which can see whether the location resolved and so can
/// say whether a retry is safe rather than guessing. This keeps the fact and the timing.
///
/// **Only the deadline gets a note here, and that is not the same as ignoring an interrupt.**
/// `Interruption::OnRequest` is explained by [`cut_short`], which wraps *every* op's result when a
/// break was raised for it, so noting it again would say it twice. What the on-request case does
/// need from this side is the **flag** — [`set_breakpoint`] sets `cut_short` from
/// `Option::is_some`, not from the deadline alone, because the rendering has to know the resolve
/// did not finish whatever stopped it.
///
/// It takes the interruption rather than a `CommandRun` because there is no command any more:
/// there is no debugger text to append a note to, so the note is the whole of what this returns.
fn told_cut_short_bp(cut_short: Option<Interruption>) -> String {
    match cut_short {
        Some(Interruption::Deadline { after_ms }) => format!(
            "[windbg-mcp] resolving the breakpoint's location did not finish within {after_ms} ms, \
             so the debugger broke in (Ctrl+Break). A symbol whose module has to be fetched from a \
             symbol server is what takes this long; the module is left on export symbols and needs \
             reloading rather than another attempt at this call.\n"
        ),
        _ => String::new(),
    }
}

/// Renders what a `set_breakpoint` left the session holding, for the text channel.
///
/// The whole of the text channel now, rather than an appendix to the debugger's own output: there
/// is no command, so there is nothing the engine printed to keep.
fn render_breakpoints(set: &structured::BreakpointSet) -> String {
    // **One sentence about this call, and it is never conditional on the listing.** The four-way
    // match this replaces existed because an empty `added` meant four different things and only the
    // listing could separate them; the engine now names the breakpoint it created, so what this
    // call did is known before the listing is read and cannot be contradicted by it failing.
    let bp = &set.breakpoint;
    let mut out = format!(
        "\nBreakpoint {} set at {}{}.\n",
        bp.id,
        bp.address
            .as_deref()
            .or(bp.expression.as_deref())
            .unwrap_or("an unresolved location"),
        if bp.deferred {
            " — deferred, so it has no address until its module loads"
        } else {
            ""
        },
    );
    if !set.replaced.is_empty() {
        // The replacement is worth saying out loud rather than leaving in a field: a caller who
        // had a *logging* breakpoint at this address has just lost it, and would otherwise notice
        // only when the log stopped.
        out.push_str(&format!(
            "It replaced {} already at that address ({}), which is what `bp` does.\n",
            match set.replaced.len() {
                1 => "the breakpoint".to_string(),
                n => format!("the {n} breakpoints"),
            },
            set.replaced
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(", "),
        ));
    }
    if set.cut_short {
        // Says what is uncertain and what is not, because the two used to be one question. The
        // breakpoint is set — that is not in doubt any more — and only its *location* is.
        out.push_str(if bp.deferred {
            "\nResolving its location was interrupted, and it is **deferred**: it has no address \
             yet. Do **not** re-request it — the breakpoint above is set, and a second call would \
             set a second one, which for a deferred location the engine cannot deduplicate.\n"
        } else {
            "\nResolving its location was interrupted, but it did resolve — the address above is \
             where it will fire. Do **not** re-request it.\n"
        });
    }
    if set.breakpoints.is_empty() {
        // Distinguished from "the session holds none", which is impossible here: this call just
        // set one. So an empty listing is a failed inspection, and says so rather than rendering
        // as an empty table.
        out.push_str(
            "\nThe session's full breakpoint list could not be read, which says nothing about the \
             breakpoint above.\n",
        );
        return out;
    }
    out.push_str(&format!(
        "\nThe session now holds {} breakpoint(s) (this call's marked *):\n",
        set.breakpoints.len(),
    ));
    for breakpoint in &set.breakpoints {
        // Trimmed at the end, because the columns are padded for alignment and the last one on a
        // row is usually empty — trailing spaces on every line of a tool result are noise.
        let row = format!(
            "{} {:<3} {:<18} {:<9}{}{}",
            if breakpoint.id == set.breakpoint.id {
                "*"
            } else {
                " "
            },
            breakpoint.id,
            // A deferred breakpoint has no address *yet*; printing a zero would name the null
            // page as the place it will fire.
            breakpoint.address.as_deref().unwrap_or("(unresolved)"),
            if breakpoint.enabled {
                "enabled"
            } else {
                "disabled"
            },
            breakpoint
                .expression
                .as_deref()
                .map(|expression| format!("  {expression}"))
                .unwrap_or_default(),
            if breakpoint.deferred {
                "  (deferred)"
            } else {
                ""
            },
        );
        out.push_str(row.trim_end());
        out.push('\n');
    }
    out
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

/// Resolves the address a walk starts from, **inside the walk's own deadline**.
///
/// A number in any form the debugger prints costs nothing to recognise, so it is tried first, and
/// the commonest shapes — an address list, a table base pasted out of another tool — never reach
/// the engine at all. What is left is MASM — a symbol (`MessageManager!g_MessageTable`), an offset
/// from one, a `poi()` of a list head that is not itself a node — and `?` is the only thing that
/// reads those. One command for the whole walk, rather than one per node, which is the point of
/// resolving here rather than making every address an expression.
///
/// **Bounded, because this one command is the one part of a walk a watchdog can reach.** Resolving
/// a symbol can send the engine to a symbol server, and an unbounded `Execute` there outlives the
/// caller's whole timeout with the session held — the walk's between-node deadline cannot help,
/// since it is not polled until this returns. So the remaining budget is handed to dbgscope's
/// watchdog, and what it costs (up to one 200ms watchdog join) is paid only by a caller who passed
/// an expression rather than a number.
/// The watchdog budget for [`resolve_start`]'s one command: what the walk has left, in ms.
///
/// **Floored at 1 and never 0**, which is the whole reason this is a named function rather than a
/// cast at the call site. `execute_command_bounded(cmd, 0)` arms no watchdog at all, so a walk
/// whose budget rounds down to nothing would run its `?` — the one part of the call that can block
/// on a symbol server for minutes — as the single *unbounded* thing in it. That is the wedge the
/// bound exists to prevent, reachable by sub-millisecond arithmetic alone.
///
/// The same reasoning as [`watchdog_budget_ms`]'s floor and deliberately not the same number: that
/// one keeps a headroom because its command is already running and the job left is to free the
/// worker. Here there is nothing to be generous to — 1ms means the resolve is cut short at once,
/// which is the correct answer for a caller with no time, and it is reported as `NotRun` rather
/// than as a bad expression.
fn resolve_budget_ms(within: Duration) -> u32 {
    u32::try_from(within.as_millis()).unwrap_or(u32::MAX).max(1)
}

fn resolve_start(e: &DebugEngine, start: &str, within: Duration) -> Result<u64, Failed> {
    if let Ok(address) = parse_pool_addr(start) {
        return Ok(address);
    }
    let budget = resolve_budget_ms(within);
    let run = e
        .execute_command_bounded(&format!("? {start}"), budget)
        .map_err(|why| {
            Failed::categorised(
                structured::ErrorCategory::InvalidArgument,
                format!("`start` = `{start}` could not be evaluated: {why}"),
            )
        })?;
    // A resolve that was cut short is not a bad expression, and must not be reported as one: it
    // says nothing about whether the symbol exists. Both origins mean the same thing for the walk
    // — nothing was read — but they call for opposite responses, so they are categorised apart.
    if let Some(interruption) = run.cut_short {
        return Err(match interruption {
            Interruption::Deadline { after_ms } => Failed::categorised(
                structured::ErrorCategory::NotRun,
                format!(
                    "Resolving `start` = `{start}` was still running after {after_ms}ms, which \
                     was all the time this call had, so it was stopped and no node was walked. \
                     Resolving a symbol can send the debugger to a symbol server; pass the \
                     numeric address instead (`execute {{\"command\": \"? {start}\"}}` once, then \
                     walk from what it prints), or raise the server's call timeout \
                     (WINDBG_MCP_CALL_TIMEOUT_SECS)."
                ),
            ),
            Interruption::OnRequest => Failed::categorised(
                structured::ErrorCategory::Interrupted,
                format!(
                    "Resolving `start` = `{start}` was interrupted before the walk began, so \
                     nothing was read."
                ),
            ),
        });
    }
    // A `?` that *runs* but produces nothing an address can be read out of is the caller's
    // mistake, not the target's — a misspelt symbol is the usual one — so it is categorised as
    // such, and the debugger's own words go with it rather than a paraphrase.
    parse_eval(&run.output).ok_or_else(|| {
        Failed::categorised(
            structured::ErrorCategory::InvalidArgument,
            format!(
                "`start` = `{start}` did not evaluate to an address. The debugger said: {}",
                run.output.trim()
            ),
        )
    })
}

/// Walks a list, an array or a pointer chain, reading named fields out of every node.
///
/// The engine appears here twice and nowhere else in the walk: once to resolve the start, and once
/// as the closure that reads bytes. Everything about the traversal — the coalesced span read and
/// its per-field fallback, the loop detection, the table — is [`crate::walk`], which has no engine
/// and so can be tested against an address space with holes in exactly the places that matter.
///
/// **The deadline starts before the start expression is resolved**, and the resolve is bounded by
/// what is left of it ([`resolve_start`]) — `?` on a symbol can block on a symbol server, and a
/// budget that began after it would be a budget measured from an unknown point in the caller's
/// wait.
fn walk_memory(e: &DebugEngine, op: walk::WalkOp, within: Duration) -> Result<Output, Failed> {
    let deadline = Instant::now() + within;
    // What is left *now*, so the resolve cannot spend time the walk has already used and the walk
    // cannot be handed time the resolve already spent. One deadline, read twice.
    let left = || deadline.saturating_duration_since(Instant::now());
    let source = match op.source {
        walk::Source::List { addresses } => walk::Resolved::List(addresses),
        walk::Source::Array {
            start,
            stride,
            count,
        } => walk::Resolved::Array {
            start: resolve_start(e, &start, left())?,
            stride,
            count,
        },
        walk::Source::Chain {
            start,
            next_offset,
            count,
        } => walk::Resolved::Chain {
            start: resolve_start(e, &start, left())?,
            next_offset,
            count,
        },
    };

    // Kept for the one case the table cannot explain by itself: a walk where *nothing* read. Only
    // the first is kept — a thousand copies of "memory read failed" is the table with the answer
    // buried in it, which is the shape this tool exists to replace.
    let mut first_failure: Option<String> = None;
    let mut report = walk::run(
        &source,
        &op.fields,
        |address, size| match e.read_memory(address, size) {
            Ok(bytes) => Some(bytes),
            Err(why) => {
                first_failure.get_or_insert_with(|| why.to_string());
                None
            }
        },
        || {
            // The interrupt is asked about first. Both can be true at once — a caller who gives up
            // and a clock that ran out land in the same poll — and being told a call was cut short
            // by a deadline it *also* passed sends them to the timeout setting instead of to the
            // break they just asked for.
            if matches!(e.interrupted(), Ok(true)) {
                Some(walk::Halt::Interrupted)
            } else if Instant::now() >= deadline {
                Some(walk::Halt::Deadline)
            } else {
                None
            }
        },
    );
    if walk::read_nothing(&report) {
        report.note = first_failure;
    }
    Ok(Output::typed(walk::render(&report), report))
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

impl BatchEngine<'_> {
    /// Whether a break has been raised for this batch's job.
    ///
    /// Which, at the moment a call returns, means it was raised *during that call*: the executor
    /// checks between steps, so a break outstanding from an earlier one would have stopped the
    /// batch before this step began.
    ///
    /// This is the authority for the calls dbgscope cannot answer for. A command knows its own
    /// interruption — the engine clears and reads a flag around `Execute` — but a `run_to` verdict,
    /// a typed memory read and a pool walk have no such notion, and a walk in particular *is*
    /// interruptible: dbgscope's walker polls the same Ctrl+C flag and stops. Left unasked, they
    /// reported every result as whole.
    fn broken(&self) -> bool {
        interrupt_pending(self.job)
    }

    /// A command's result as the executor sees it: the text with any deadline note, and whether a
    /// break reached it — from the engine, which knows, or from this worker, which raised it.
    fn ran(&self, run: CommandRun) -> Ran {
        self.ran_told(run, told)
    }

    /// [`Self::ran`] for a step that was moving the target, which needs [`told_moving`]'s reading
    /// of a deadline rather than [`told`]'s. Only the prose differs; `interrupted` is the same
    /// question either way, and a *deadline* is deliberately not it — that is the step's own
    /// `timeout_ms` doing its job, which its output now says in as many words.
    fn ran_moving(&self, run: CommandRun) -> Ran {
        self.ran_told(run, told_moving)
    }

    fn ran_told(&self, run: CommandRun, note: fn(CommandRun) -> String) -> Ran {
        Ran {
            interrupted: matches!(run.cut_short, Some(Interruption::OnRequest)) || self.broken(),
            target_gone: run.target_gone,
            output: note(run),
        }
    }

    /// Whether the engine has lost its target, for the one step whose call does not say.
    ///
    /// `command` and `resume` are told on the value, by dbgscope. `run_to` drops its typed half by
    /// design — a batch's product is its own report — so it asks instead. `read_memory` and `pool`
    /// cannot end a target and answer `false` without asking: an engine round trip per step, on a
    /// path whose answer is fixed, is a cost with no reader.
    fn target_gone(&self) -> bool {
        !self.e.has_target().unwrap_or(true)
    }
}

impl Debuggee for BatchEngine<'_> {
    fn command(&mut self, command: &str, budget_ms: u32) -> Result<Ran, String> {
        // Bounded, always. A batch is the one place a runaway command would also strand a
        // rollback, so the step self-aborts rather than eating the reserve.
        raw_command(self.e, command, budget_ms).map(|run| self.ran(run))
    }

    fn resume(&mut self, command: &str, timeout_ms: u32) -> Result<Ran, String> {
        self.e
            .execute_and_wait(command, timeout_ms)
            .inspect(|_| query::invalidate_allocator_snapshots())
            .map(|run| self.ran_moving(run))
            .map_err(es)
    }

    fn running(&mut self) -> Option<bool> {
        self.e.is_running().ok()
    }

    fn has_target(&mut self) -> Option<bool> {
        self.e.has_target().ok()
    }

    fn run_to(&mut self, address: &str, timeout_ms: u32) -> Result<Ran, String> {
        // The typed half is dropped here, deliberately: a batch's product is its own report,
        // which renders every step into one narrative, and a step does not answer separately.
        let output = run_to_address(self.e, address, timeout_ms).map_err(|error| error.message)?;
        Ok(Ran {
            output: output.text,
            interrupted: self.broken(),
            target_gone: self.target_gone(),
        })
    }

    fn read_memory(&mut self, address: &str, size: u32) -> Result<Ran, String> {
        let output = read_memory(self.e, address, size)?;
        Ok(Ran {
            output,
            interrupted: self.broken(),
            target_gone: false,
        })
    }

    fn pool(&mut self, query: &PoolOp, budget_ms: u32) -> Result<Ran, String> {
        // The step's own budget, handed to the walker. Bounded, always, for the same reason a
        // command step is: this is the one step that can spend minutes without a runaway anywhere
        // — a full pool walk is every committed page over the KD wire — and the reserve the
        // rollback lives on is what it would spend.
        let output = pool(
            self.e,
            query.clone(),
            Duration::from_millis(u64::from(budget_ms)),
        )
        .map_err(|error| error.message)?;
        Ok(Ran {
            output: output.text,
            interrupted: self.broken(),
            target_gone: false,
        })
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

    fn rolling_back(&mut self) {
        seal_against_interrupts(self.e, self.job);
    }
}

/// Runs a batch and reports what happened, as the rendered report and as values.
///
/// The report is the result either way — a failed transaction that did not say which step failed
/// and whether the rollback ran would be worse than no report at all. So a batch that **ran**
/// answers `Ok` whatever it concluded, and its verdict is a field inside
/// [`crate::structured::BatchReportInfo`] rather than the choice of `Ok`/`Err`;
/// [`crate::server::batch_result`] is what turns that verdict into a tool-execution error, and the
/// two `Err`s here are the batch that never started at all.
///
/// It is built here rather than parsed from the rendering on the other side of the pipe for the
/// reason [#77](https://github.com/glslang/windbg-mcp/issues/77) gives, and it exists at all so a
/// transcript can record a transaction's outcome and rollback state as facts
/// ([#87](https://github.com/glslang/windbg-mcp/issues/87)).
fn run_batch(e: &DebugEngine, job: u64, op: BatchOp, queued: Duration) -> Result<Output, String> {
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
    Ok(Output::typed(
        rendered,
        crate::structured::BatchReportInfo::from(&report),
    ))
}

/// Column header for the chunk tables below. Kept next to [`pool_row`] so the two cannot
/// drift out of alignment — `tag_columns_line_up` is what enforces it.
const POOL_COLUMNS: &str =
    "address              size  state          kind                    backend  tag         numa";

/// Width of the tag column, in both tables.
///
/// Ten, not four, because [`tag_label`] falls back to the raw form — `0x` and eight hex digits —
/// and a tag that has to be shown as its bytes must not shove the rest of the row out of line.
const TAG_WIDTH: usize = 10;

/// Why a query for an ambiguous *rendering* found nothing, when it is worth saying.
///
/// Empty for the ordinary case — a plain tag that simply is not allocated, and a raw form, which
/// says exactly which four bytes it meant. It speaks only for the case that would otherwise
/// mislead: a rendering containing `.`, which searched for literal `.` bytes rather than for
/// whatever the table it was copied from was showing.
///
/// The raw form is recognised by `parse_raw_tag`, the same predicate the parser uses, and not by
/// its `0x` prefix. A prefix is not the form: `0x..` is four printable bytes and an ordinary
/// tag — an *ambiguous* one, which is exactly a case this owes an explanation, and which a
/// prefix test would wave through as raw.
fn pool_tag_rendering_hint(tag: &str) -> String {
    if parse_raw_tag(tag).is_some() {
        return String::new();
    }
    match parse_tag(tag) {
        Some(raw) if display_is_ambiguous(raw) => format!(
            "\n\n`{tag}` is a rendering rather than a tag: a table prints every unprintable byte \
             as `.`, and a literal `.` the same way, so this searched for the four bytes {} and \
             nothing else. If you copied it from a listing, query the `raw_tag` beside it.",
            raw_tag_hex(raw)
        ),
        _ => String::new(),
    }
}

/// Renders one chunk as a fixed-width row.
///
/// The address column is `usable_address` — what the allocation call *returned*, and so the
/// value that appears in the target's own pointers. `header_address` is where the allocator's
/// bookkeeping starts and is rarely what a caller is holding.
fn pool_row(span: &PoolSpan) -> String {
    format!(
        "{:<18}  {:>5}  {:<13}  {:<22}  {:<7}  {:<TAG_WIDTH$}  {}",
        fmt_addr(span.usable_address),
        format!("{:#x}", span.size),
        format!("{:?}", span.state),
        format!("{:?}", span.pool_kind),
        format!("{:?}", span.backend),
        tag_label(span.raw_tag),
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

/// Parses a user-heap address using WinDbg's hexadecimal default radix.
///
/// User-mode pointers can be much shorter than kernel pointers, so every nonempty bare hex run
/// is hexadecimal here. Prefixed and backtick-separated inputs keep the common parser's
/// validation and error text.
fn parse_heap_addr(text: &str) -> Result<u64, String> {
    let text = text.trim();
    if !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return u64::from_str_radix(text, 16).map_err(|_| format!("invalid address: {text:?}"));
    }
    parse_pool_addr(text)
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
    if let Some(matches) = report.stopped_after_matches {
        return Some(format!(
            "\n--- pool walk ---\ncoverage: MATCH LIMIT REACHED - stopped after {matches} \
             matching allocated chunk(s), having walked {} chunk(s). What is listed above is \
             intentionally partial; omit or raise `stop_after_matches` for more.\n",
            report.total_chunks
        ));
    }
    if report.coverage.complete() {
        return None;
    }
    Some(format!(
        "\n--- pool walk ---\ncoverage: INCOMPLETE - the walk reached {} chunk(s), but not \
         everything it set out to. What is listed above is therefore a floor, not a total: \
         there may be more the walk never saw.\n",
        report.total_chunks
    ))
}

/// What the walk itself managed, so an empty answer explains itself.
///
/// Without it, an empty result is ambiguous in the worst way: "the pool holds no such chunk" and
/// "the walk reached almost none of the pool" render identically. The report rendered here is the
/// one the query handed back *with* its answer, so this describes the walk that produced the list
/// above it rather than whichever walk a later question happened to provoke.
///
/// The diagnostics are *categorised* rather than listed: a real walk emits tens of thousands, and
/// the first forty of those are a sample of whichever heap happened to be walked first, not of the
/// problem. Counts per category say which failures actually dominate; the verbatim tail keeps
/// concrete addresses available.
fn render_walk_report(report: &query::PoolSnapshotReport) -> String {
    // `complete` is not implied by an empty diagnostics list: a walk can end partway
    // through without saying anything. Report it explicitly, or a caller reads a truncated
    // snapshot as a healthy one.
    let mut out = format!(
        "\n--- pool walk ---\nchunks walked: {} ({} allocated), coverage: {}\n",
        report.total_chunks,
        report.allocated_chunks,
        match report.stopped_after_matches {
            Some(_) => "match_limit_reached - the requested match threshold stopped the walk",
            None if report.coverage.complete() => "complete",
            None => "INCOMPLETE - the walk did not reach everything it set out to",
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
/// dbgscope's `DEFAULT_WALK_BUDGET` is reachable from neither caller here, which is right, because
/// neither is a human at a prompt who could Ctrl+C a walk that ran long. A [`crate::batch`] step
/// passes its step budget; a pool *tool* call passes what is left of its caller's patience
/// ([`walk_budget`]). For a batch the deadline is load-bearing beyond the caller: it reserves part
/// of its budget for the rollback and advertises the whole of it to a teardown, so a walk running to
/// the *walker's* default could overrun both. A walk stopped by a budget still answers — every
/// rendering below carries how much of the pool the walk reached — so the cost of a short deadline
/// is coverage, not an error.
fn pool(e: &DebugEngine, args: PoolOp, within: Duration) -> Result<Output, Failed> {
    // Every answer below carries `answer.walk` — the state of the walk it was *itself* drawn
    // from, handed back by the query. Asking separately would be a second call, and an incomplete
    // walk is deliberately not cached, so that call could walk again and report the coverage of a
    // different walk as this one's (dbgscope's `PoolAnswer`).
    let walk = |refresh: bool| PoolWalk::from(refresh).within(within);
    match args {
        PoolOp::FindTag {
            tag,
            paged,
            refresh,
            stop_after_matches,
            limit,
        } => {
            let filter = paged.map(|paged| {
                if paged {
                    PoolPageFilter::Paged
                } else {
                    PoolPageFilter::NonPaged
                }
            });
            let answer = query::find_tag(
                e,
                &tag,
                filter,
                stop_after_matches.and_then(|matches| NonZeroUsize::new(matches.get() as usize)),
                walk(refresh),
            )
            .map_err(pool_failure)?;
            let spans = &answer.found;
            let mut out = render_find_tag(&tag, filter, spans, limit);
            if spans.is_empty() {
                // An empty answer has to explain itself, or "the pool holds no such chunk" and
                // "the walk reached almost none of the pool" read identically.
                out.push_str(&render_walk_report(&answer.walk));
            } else if let Some(caveat) = coverage_caveat(&answer.walk) {
                out.push_str(&caveat);
            }
            Ok(Output::typed(
                out,
                structured::PoolTagMatches {
                    layout: (&answer.walk.layout).into(),
                    // The query succeeded, so the tag parsed; the fallback cannot be reached and
                    // echoing the caller's own text is the harmless answer if it ever were.
                    raw_tag: parse_tag(&tag).map_or_else(|| tag.clone(), raw_tag_hex),
                    tag,
                    scope: match filter {
                        None => structured::PoolScope::Both,
                        Some(PoolPageFilter::Paged) => structured::PoolScope::Paged,
                        Some(PoolPageFilter::NonPaged) => structured::PoolScope::NonPaged,
                    },
                    matches: spans.len(),
                    // Summed over every match, not over the listed ones: `limit` bounds the
                    // rows a reply carries and must never bound what it *says* is there.
                    total_bytes: spans.iter().map(|span| span.size).sum(),
                    chunks: spans
                        .iter()
                        .take(limit)
                        .map(structured::PoolChunkInfo::from)
                        .collect(),
                    walk: walk_info(&answer.walk),
                },
            ))
        }
        PoolOp::Chunk { address, refresh } => {
            // The caller's own mistake, and named as one: an unparseable address never reached
            // the debugger, so reporting it as a debugger failure would send them looking at the
            // target.
            let address = parse_pool_addr(&address).map_err(|why| {
                Failed::categorised(structured::ErrorCategory::InvalidArgument, why)
            })?;
            let answer = query::chunk_at(e, address, walk(refresh)).map_err(pool_failure)?;
            let found = &answer.found;
            let mut out = match found {
                Some(found) => render_chunk(address, found),
                // "Not in the snapshot" and "free" are different answers, and reporting this one
                // as free would manufacture a dangling pointer out of a gap in the walk.
                None => format!(
                    "{} is not covered by the pool snapshot.\n\nThat is not the same as \
                     \"free\": a free hole inside a walked region comes back as a chunk in \
                     an explicitly free state (ReusableFree or CachedFree). An address \
                     outside every region is either not pool at all, or sits in a region \
                     this walk did not reach. If the target has run since the snapshot was \
                     taken, retry with refresh=true.",
                    fmt_addr(address)
                ),
            };
            if found.is_none() {
                out.push_str(&render_walk_report(&answer.walk));
            }
            Ok(Output::typed(
                out,
                structured::PoolChunkAt {
                    layout: (&answer.walk.layout).into(),
                    address: structured::addr(address),
                    covered: found.is_some(),
                    offset: found
                        .as_ref()
                        .map(|found| address.saturating_sub(found.chunk.usable_address)),
                    chunk: found
                        .as_ref()
                        .map(|found| structured::PoolChunkInfo::from(&found.chunk)),
                    previous: found
                        .as_ref()
                        .and_then(|found| found.previous.as_ref())
                        .map(structured::PoolChunkInfo::from),
                    next: found
                        .as_ref()
                        .and_then(|found| found.next.as_ref())
                        .map(structured::PoolChunkInfo::from),
                    walk: walk_info(&answer.walk),
                },
            ))
        }
        PoolOp::Diagnostics {
            filter,
            refresh,
            limit,
        } => {
            let report = query::snapshot_report(e, walk(refresh)).map_err(pool_failure)?;
            let out = render_diagnostics(&report, filter.as_deref(), limit);
            let examples = select_examples(&report.diagnostics, filter.as_deref());
            let categories = select_categories(&report.diagnostics, filter.as_deref());
            let (example_rows, category_rows) =
                split_row_budget(limit, examples.len(), categories.len());
            Ok(Output::typed(
                out,
                structured::PoolDiagnosticsReport {
                    layout: (&report.layout).into(),
                    filter,
                    matched_categories: categories.len(),
                    matched_examples: examples.len(),
                    categories: categories
                        .iter()
                        .take(category_rows)
                        .map(|category| structured::DiagnosticCategory {
                            shape: category.shape.trim().to_string(),
                            // The walk's own total for this shape, not the number of messages
                            // that survived its sampling — see #77.
                            total: category.total,
                        })
                        .collect(),
                    examples: examples
                        .iter()
                        .take(example_rows)
                        .map(|line| (*line).clone())
                        .collect(),
                    walk: walk_info(&report),
                },
            ))
        }
        // The census *is* the state of the walk, so it always carries the report.
        PoolOp::Census { refresh, limit } => {
            let answer = query::tag_census(e, walk(refresh)).map_err(pool_failure)?;
            let census = &answer.found;
            let mut out = render_census(census, limit);
            out.push_str(&render_walk_report(&answer.walk));
            Ok(Output::typed(
                out,
                structured::PoolCensus {
                    layout: (&answer.walk.layout).into(),
                    distinct_tags: census.len(),
                    tags: census
                        .iter()
                        .take(limit)
                        .map(|entry| structured::PoolTagTotals {
                            tag: entry.display_tag.clone(),
                            raw_tag: raw_tag_hex(entry.raw_tag),
                            allocations: entry.allocations,
                            total_bytes: entry.total_bytes,
                            paged_allocations: entry.paged_allocations,
                            nonpaged_allocations: entry.nonpaged_allocations,
                        })
                        .collect(),
                    walk: walk_info(&answer.walk),
                },
            ))
        }
    }
}

fn heap_backend_name(backend: HeapBackend) -> structured::HeapBackendName {
    match backend {
        HeapBackend::Lfh => structured::HeapBackendName::Lfh,
        HeapBackend::Vs => structured::HeapBackendName::Vs,
        HeapBackend::Segment => structured::HeapBackendName::Segment,
        HeapBackend::Large => structured::HeapBackendName::Large,
    }
}

fn heap_state_name(state: HeapState) -> structured::HeapChunkState {
    match state {
        HeapState::Allocated => structured::HeapChunkState::Allocated,
        HeapState::ReusableFree => structured::HeapChunkState::ReusableFree,
        HeapState::CachedFree => structured::HeapChunkState::CachedFree,
        HeapState::Unreadable => structured::HeapChunkState::Unreadable,
    }
}

fn heap_failure(error: heap_query::HeapQueryError) -> Failed {
    match error {
        heap_query::HeapQueryError::Interrupted => {
            Failed::categorised(structured::ErrorCategory::Interrupted, error.to_string())
        }
        heap_query::HeapQueryError::InvalidPeb(_) => {
            Failed::categorised(structured::ErrorCategory::Debugger, error.to_string())
        }
        other => Failed::from(other.to_string()),
    }
}

fn heap_walk_text(walk: &heap_query::HeapWalkReport) -> String {
    let coverage = structured::AllocatorCoverage::from(walk.coverage);
    format!(
        "coverage={}; {} chunks ({} allocated); {} diagnostics; {} unreadable gaps; {} \
         refused headers",
        coverage.as_str(),
        walk.total_chunks,
        walk.allocated_chunks,
        walk.diagnostic_count,
        walk.unreadable_gaps,
        walk.refused_headers
    )
}

fn heap_root_matches(candidate: u64, selected: Option<u64>) -> bool {
    selected.is_none_or(|selected| candidate == selected)
}

fn heap_allocation_matches(
    allocation: &HeapAllocation,
    heap: Option<u64>,
    backend: Option<HeapBackend>,
    state: HeapState,
    min_capacity: Option<u64>,
    max_capacity: Option<u64>,
) -> bool {
    heap_root_matches(allocation.heap, heap)
        && backend.is_none_or(|backend| allocation.backend == backend)
        && allocation.state == state
        && min_capacity.is_none_or(|minimum| allocation.capacity >= minimum)
        && max_capacity.is_none_or(|maximum| allocation.capacity <= maximum)
}

fn query_heap_diagnostics<T, E>(
    heap: Option<u64>,
    all: impl FnOnce() -> Result<T, E>,
    scoped: impl FnOnce(u64) -> Result<T, E>,
) -> Result<T, E> {
    match heap {
        Some(heap) => scoped(heap),
        None => all(),
    }
}

struct HeapDiagnosticSelection<'a> {
    categories: Vec<&'a DiagnosticShape>,
    examples: Vec<&'a String>,
}

fn select_heap_diagnostics<'a>(
    report: &'a heap_query::HeapDiagnosticReport,
    filter: Option<&str>,
) -> HeapDiagnosticSelection<'a> {
    let needle = filter.map(str::to_ascii_lowercase);
    HeapDiagnosticSelection {
        categories: report
            .categories
            .iter()
            .filter(|category| matches_filter(&category.shape, needle.as_deref()))
            .collect(),
        examples: report
            .examples
            .iter()
            .filter(|example| matches_filter(example, needle.as_deref()))
            .collect(),
    }
}

fn heap_row(allocation: &HeapAllocation) -> String {
    format!(
        "{}  {:>8}  {:<13}  {:<7}  heap {}  class {:#x}",
        fmt_addr(allocation.user_address),
        format!("{:#x}", allocation.capacity),
        format!("{:?}", allocation.state),
        format!("{:?}", allocation.backend),
        fmt_addr(allocation.heap),
        allocation.size_class,
    )
}

/// Answers one user Segment Heap question under the caller-derived deadline.
fn heap(e: &DebugEngine, args: HeapOp, within: Duration) -> Result<Output, Failed> {
    let walk = |refresh: bool| HeapWalk::from(refresh).within(within);
    match args {
        HeapOp::List { refresh } => {
            let answer = heap_query::list(e, walk(refresh)).map_err(heap_failure)?;
            let mut text = format!(
                "{} PEB heap(s); {}\n\nindex  address             kind        supported\n",
                answer.found.len(),
                heap_walk_text(&answer.walk)
            );
            for root in &answer.found {
                text.push_str(&format!(
                    "{:>5}  {}  {:<11} {}{}\n",
                    root.index,
                    fmt_addr(root.address),
                    format!("{:?}", root.kind),
                    root.supported,
                    root.reason
                        .as_deref()
                        .map(|reason| format!(" — {reason}"))
                        .unwrap_or_default()
                ));
            }
            Ok(Output::typed(
                text,
                structured::HeapListResult {
                    layout: (&answer.layout).into(),
                    scope: (&answer.scope).into(),
                    walk: (&answer.walk).into(),
                    heaps: answer
                        .found
                        .iter()
                        .map(structured::HeapRootInfo::from)
                        .collect(),
                },
            ))
        }
        HeapOp::Allocations {
            heap,
            backend,
            state,
            min_capacity,
            max_capacity,
            refresh,
            limit,
        } => {
            if min_capacity
                .zip(max_capacity)
                .is_some_and(|(min, max)| min > max)
            {
                return Err(Failed::categorised(
                    structured::ErrorCategory::InvalidArgument,
                    "min_capacity cannot exceed max_capacity",
                ));
            }
            let heap = heap
                .as_deref()
                .map(parse_heap_addr)
                .transpose()
                .map_err(|error| {
                    Failed::categorised(structured::ErrorCategory::InvalidArgument, error)
                })?;
            let backend = backend.map(|backend| match backend {
                HeapBackendFilter::Lfh => HeapBackend::Lfh,
                HeapBackendFilter::Vs => HeapBackend::Vs,
                HeapBackendFilter::Segment => HeapBackend::Segment,
                HeapBackendFilter::Large => HeapBackend::Large,
            });
            let state = match state {
                HeapStateFilter::Allocated => HeapState::Allocated,
                HeapStateFilter::ReusableFree => HeapState::ReusableFree,
                HeapStateFilter::CachedFree => HeapState::CachedFree,
                HeapStateFilter::Unreadable => HeapState::Unreadable,
            };
            let answer = heap_query::allocations(e, walk(refresh)).map_err(heap_failure)?;
            let matches: Vec<_> = answer
                .found
                .iter()
                .filter(|allocation| {
                    heap_allocation_matches(
                        allocation,
                        heap,
                        backend,
                        state,
                        min_capacity,
                        max_capacity,
                    )
                })
                .collect();
            let mut text = format!(
                "{} matching allocation(s); {}\n\naddress             capacity  state          backend  heap/class\n",
                matches.len(),
                heap_walk_text(&answer.walk)
            );
            for allocation in matches.iter().take(limit) {
                text.push_str(&heap_row(allocation));
                text.push('\n');
            }
            Ok(Output::typed(
                text,
                structured::HeapAllocationsResult {
                    layout: (&answer.layout).into(),
                    scope: (&answer.scope).into(),
                    walk: (&answer.walk).into(),
                    matches: matches.len(),
                    allocations: matches
                        .into_iter()
                        .take(limit)
                        .map(structured::HeapAllocationInfo::from)
                        .collect(),
                },
            ))
        }
        HeapOp::Chunk { address, refresh } => {
            let address = parse_heap_addr(&address).map_err(|error| {
                Failed::categorised(structured::ErrorCategory::InvalidArgument, error)
            })?;
            let answer = heap_query::chunk_at(e, address, walk(refresh)).map_err(heap_failure)?;
            let text = match &answer.found {
                Some(found) => format!(
                    "{} is {:#x} from user address {}\n{}\n{}",
                    fmt_addr(address),
                    found.offset,
                    fmt_addr(found.allocation.user_address),
                    heap_row(&found.allocation),
                    heap_walk_text(&answer.walk)
                ),
                None => format!(
                    "{} is not covered by the Segment Heap snapshot. This is not evidence that \
                     it is free; inspect coverage and retry with refresh=true after execution.\n{}",
                    fmt_addr(address),
                    heap_walk_text(&answer.walk)
                ),
            };
            Ok(Output::typed(
                text,
                structured::HeapChunkResult {
                    layout: (&answer.layout).into(),
                    scope: (&answer.scope).into(),
                    walk: (&answer.walk).into(),
                    address: structured::addr(address),
                    covered: answer.found.is_some(),
                    offset: answer.found.as_ref().map(|found| found.offset),
                    allocation: answer
                        .found
                        .as_ref()
                        .map(|found| (&found.allocation).into()),
                    previous: answer
                        .found
                        .as_ref()
                        .and_then(|found| found.previous.as_ref())
                        .map(Into::into),
                    next: answer
                        .found
                        .as_ref()
                        .and_then(|found| found.next.as_ref())
                        .map(Into::into),
                },
            ))
        }
        HeapOp::Census {
            heap,
            refresh,
            limit,
        } => {
            let heap = heap
                .as_deref()
                .map(parse_heap_addr)
                .transpose()
                .map_err(|error| {
                    Failed::categorised(structured::ErrorCategory::InvalidArgument, error)
                })?;
            let answer = heap_query::census(e, walk(refresh)).map_err(heap_failure)?;
            let rows: Vec<_> = answer
                .found
                .iter()
                .filter(|row| heap_root_matches(row.heap, heap))
                .collect();
            let mut text = format!(
                "{} census group(s), heaviest first; {}\n\n",
                rows.len(),
                heap_walk_text(&answer.walk)
            );
            for row in rows.iter().take(limit) {
                text.push_str(&format!(
                    "heap {} {:?}/{:?} class {:#x}: {} chunks, {:#x} bytes\n",
                    fmt_addr(row.heap),
                    row.backend,
                    row.state,
                    row.size_class,
                    row.chunks,
                    row.total_capacity
                ));
            }
            Ok(Output::typed(
                text,
                structured::HeapCensusResult {
                    layout: (&answer.layout).into(),
                    scope: (&answer.scope).into(),
                    walk: (&answer.walk).into(),
                    groups: rows.len(),
                    rows: rows
                        .into_iter()
                        .take(limit)
                        .map(|row| structured::HeapCensusRowInfo {
                            heap: structured::addr(row.heap),
                            backend: heap_backend_name(row.backend),
                            state: heap_state_name(row.state),
                            size_class: row.size_class,
                            chunks: row.chunks,
                            total_capacity: row.total_capacity,
                        })
                        .collect(),
                },
            ))
        }
        HeapOp::Diagnostics {
            heap,
            filter,
            refresh,
            limit,
        } => {
            let heap = heap
                .as_deref()
                .map(parse_heap_addr)
                .transpose()
                .map_err(|error| {
                    Failed::categorised(structured::ErrorCategory::InvalidArgument, error)
                })?;
            // Scope before dbgscope aggregates diagnostic shapes: those shapes deliberately
            // generalise addresses, so filtering them for the heap address afterwards loses the
            // category totals and leaves only incidental examples.
            let answer = query_heap_diagnostics(
                heap,
                || heap_query::diagnostics(e, walk(refresh)),
                |heap| heap_query::diagnostics_for_heap(e, heap, walk(refresh)),
            )
            .map_err(heap_failure)?;
            let selected = select_heap_diagnostics(&answer.found, filter.as_deref());
            let categories = selected.categories;
            let examples = selected.examples;
            let (example_rows, category_rows) =
                split_row_budget(limit, examples.len(), categories.len());
            let mut text = format!(
                "{} matching categories, {} kept examples; {}\n",
                categories.len(),
                examples.len(),
                heap_walk_text(&answer.walk)
            );
            for category in categories.iter().take(category_rows) {
                text.push_str(&format!("{} × {}\n", category.total, category.shape));
            }
            for example in examples.iter().take(example_rows) {
                text.push_str("  ");
                text.push_str(example);
                text.push('\n');
            }
            Ok(Output::typed(
                text,
                structured::HeapDiagnosticsResult {
                    layout: (&answer.layout).into(),
                    scope: (&answer.scope).into(),
                    walk: (&answer.walk).into(),
                    heap: heap.map(structured::addr),
                    filter,
                    matched_categories: categories.len(),
                    matched_examples: examples.len(),
                    categories: categories
                        .into_iter()
                        .take(category_rows)
                        .map(|category| structured::DiagnosticCategory {
                            shape: category.shape.trim().to_string(),
                            total: category.total,
                        })
                        .collect(),
                    examples: examples.into_iter().take(example_rows).cloned().collect(),
                },
            ))
        }
    }
}

/// The walk state every pool answer carries.
///
/// Infallible, because the report is no longer something to go and ask for: it arrives with the
/// answer, from the same snapshot. There is no "could not read the walk" case left to render.
fn walk_info(report: &query::PoolSnapshotReport) -> structured::WalkInfo {
    structured::WalkInfo {
        coverage: if report.stopped_after_matches.is_some() {
            structured::AllocatorCoverage::MatchLimitReached
        } else {
            report.coverage.into()
        },
        stop_after_matches: report.stopped_after_matches,
        chunks_walked: report.total_chunks,
        allocated_chunks: report.allocated_chunks,
        diagnostics_emitted: report.diagnostics.emitted(),
        diagnostic_categories: report.diagnostics.shapes().len(),
        gaps: structured::WalkGaps::of(report),
    }
}

/// A pool query's failure, with the one kind of stop that is not a failure kept apart from it.
///
/// A walk that was interrupted did exactly what it was told; reporting it as a debugger failure
/// sends a caller looking for a broken target.
fn pool_failure(error: query::PoolQueryError) -> Failed {
    match error {
        query::PoolQueryError::Interrupted => {
            Failed::categorised(structured::ErrorCategory::Interrupted, error.to_string())
        }
        other => Failed::from(other.to_string()),
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
        // The one empty answer that is not about the pool at all: a rendering was handed back as
        // if it were a tag. `....` parses as four perfectly good ASCII bytes, so this found
        // nothing for a reason no amount of walk coverage explains, and saying so here is what
        // keeps it from reading as "the tag is not allocated".
        let rendering = pool_tag_rendering_hint(tag);
        return format!(
            "No allocated chunks carry tag `{tag}`{scope}.{rendering}\n\nOnly *allocated* chunks \
             are indexed by tag: a freed chunk's tag is not reliably preserved by the allocator, \
             so this never reports freed memory. To ask about one address that may have been \
             freed, use `pool_chunk`. If the target has run since the snapshot was taken, retry \
             with refresh=true."
        );
    }
    let total: u64 = spans.iter().map(|span| span.size).sum();
    // The same warning, and the case that needs it *more*. A rendering that finds nothing is at
    // least not an answer about something else; a rendering that finds the literal `.` bytes
    // reports another tag's chunks as though they were the ones the caller meant — the collision
    // this whole distinction exists to prevent, arriving as a confident result. It goes above the
    // table rather than after it, because it is a caveat on the rows, not a footnote to them.
    let rendering = pool_tag_rendering_hint(tag);
    let mut out = format!(
        "tag `{tag}`{scope}: {} allocation(s), {total:#x} bytes total{rendering}\n\n\
         {POOL_COLUMNS}\n",
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
        tag_label(chunk.raw_tag),
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

/// Splits `limit` rows between the two halves of a listing that has two.
///
/// `limit` bounds the whole reply rather than each section of it, for whichever reason the caller
/// of this has: the diagnostics listing because the worker builds the reply as one `String` before
/// it crosses the pipe, the module listing because the number is a bound on what the *caller* pays
/// for the answer. Either way, two sections that each took the budget in full would quietly double
/// the ceiling it was chosen to be.
///
/// Spending it in print order would be simpler and is wrong: whichever half prints first would take
/// the lot on a target that has a lot of it, and the other half is never the less interesting one —
/// it is the category counts in a diagnostics listing, and the images that have *unloaded* in a
/// module one, which is the half that can name a driver no longer there. So each half is offered
/// half the budget and hands back what it does not need, which in practice means "the smaller half
/// whole, the larger half takes the rest" and only splits evenly when both are over.
fn split_row_budget(limit: usize, first: usize, second: usize) -> (usize, usize) {
    let for_first = first.min((limit / 2).max(limit.saturating_sub(second)));
    (for_first, second.min(limit - for_first))
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
            if report.coverage.complete() {
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
        "{} distinct tag(s) allocated, heaviest first.\n\ntag          allocs        bytes  \
         nonpaged   paged\n",
        census.len()
    );
    for entry in census.iter().take(limit) {
        out.push_str(&format!(
            "{:<TAG_WIDTH$}  {:>7}  {:>11}  {:>8}  {:>6}\n",
            tag_label(entry.raw_tag),
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
/// dbgscope's openers expose the first seam as `x_begin()` returning a `PendingTarget` guard,
/// which cannot exist unless the side effect succeeded — so `commit()` between the guard and its
/// `wait()` is enforced by the type rather than by convention (glslang/dbgscope#71).
fn open<T, R>(e: &DebugEngine, id: u64, transition: T, report: R) -> Result<Output, Failed>
where
    T: FnOnce(&dyn Fn()) -> Result<(), String>,
    R: FnOnce() -> Result<String, String>,
{
    // **The limitation travels on the failures too.** Both `?`s below return before the summary is
    // built, and the supervisor turns a post-commit failure into an error that still carries a live
    // session handle — so without this, a caller who fell back to this process learns their open
    // went wrong and never learns SOS cannot work in the session they are left holding. That is the
    // loud fallback going quiet at exactly the moment it matters: a dump slow enough to fail the
    // wait is a large one, which is the shape most likely to be a 32-bit service dump.
    let with_limitation = |failed: Failed| match session_limitation() {
        Some(limitation) => failed.and_note(&limitation),
        None => failed,
    };
    transition(&|| {
        emit(&WorkerMessage::Committed { id });
    })
    .map_err(|why| with_limitation(Failed::from(why)))?;
    emit(&WorkerMessage::Opened { id });
    let diagnostic = report().map_err(Failed::from).map_err(with_limitation)?;
    // Read *after* the diagnostic, and only if it worked: the diagnostic is the answer, and a
    // summary is a few facts to read it by. The supervisor finishes the typed side, because it is
    // the only side that knows the handle it minted and the state it settled the session into.
    let mut summary = target_summary(e);
    // Both halves, or it is half a warning: a structured-aware client forwards `structuredContent`
    // and drops the text block, so a limitation stated only in the sentence is one the better
    // clients never see (`FOLLOWUPS.md` item 43).
    summary.limitation = session_limitation();
    let text = appended(
        summary_text(&diagnostic, &summary),
        summary.limitation.clone(),
    );
    Ok(Output::opened(text, summary))
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

/// The handful of facts every opener reports about the target it just opened
/// ([#105](https://github.com/glslang/windbg-mcp/issues/105)).
///
/// **Every read here is best-effort, and deliberately so.** The target is open by the time this
/// runs; failing the open over a summary field would throw away a session that exists, and each
/// of these has an ordinary reason to be unavailable — `bug_check` fails outright on a user-mode
/// target, and a kernel attach that has not synchronised its module list yet answers with one
/// module (#85). An absent field says "not available", and the fields that did read say what they
/// know.
///
/// Cheap, too, which is what makes it affordable on every open: three engine queries against the
/// engine's own bookkeeping — no symbol resolution, no command, and nothing that goes near a
/// symbol server.
fn target_summary(e: &DebugEngine) -> structured::TargetSummary {
    let kernel_mode = e
        .is_kernel_target()
        .inspect_err(|why| {
            tracing::debug!("worker: open summary could not read target type: {why}")
        })
        .ok();
    let modules = e
        .modules()
        .inspect_err(|why| tracing::debug!("worker: open summary could not list modules: {why}"))
        .ok();
    structured::TargetSummary {
        kernel_mode,
        modules_loaded: modules.as_ref().map(Vec::len),
        primary_module: modules
            .as_deref()
            .and_then(|modules| primary_module(modules, kernel_mode))
            .map(|module| {
                Box::new(with_pdb_identity(
                    e,
                    module,
                    structured::ModuleInfo::from(module),
                ))
            }),
        // `Ok(None)` is the target that did not bug check, and `Err` is the target that has no
        // bug check data to read at all (user mode). Both are simply "no bug check here".
        bug_check: e
            .bug_check()
            .ok()
            .flatten()
            .as_ref()
            .map(triage::bug_check_info),
        // Filled by [`open`], not here: this reads the *target*, and a limitation is a fact about
        // the engine that was built for it — known before the target existed.
        limitation: None,
    }
}

/// The image a target is *about*, out of everything the engine has loaded.
///
/// On a kernel target that is the kernel, which the engine always names `nt` whichever image the
/// build shipped (`ntkrnlmp.exe` and friends) — so it is matched by that name, and the name is what
/// every `nt!Symbol` in the session is qualified by. Anywhere else it is the first module in the
/// engine's list, which is load order, which is the process's own executable.
///
/// The kernel lookup falls back to the same first entry rather than to nothing: `nt` is first on
/// every kernel target seen, and a build that ordered it differently should cost a caller a
/// slightly odd answer, not an empty one.
fn primary_module(
    modules: &[dbgscope::dbgeng::Module],
    kernel_mode: Option<bool>,
) -> Option<&dbgscope::dbgeng::Module> {
    if kernel_mode == Some(true)
        && let Some(kernel) = modules
            .iter()
            .find(|module| module.name.eq_ignore_ascii_case("nt"))
    {
        return Some(kernel);
    }
    modules.first()
}

/// The opener's diagnostic with the summary rendered under it.
///
/// Three lines at most, and each is there because it answers a question its reader would otherwise
/// spend a whole tool call on: which bug check this dump is, and where the target's own image is
/// loaded.
///
/// **The pointers to the tools that read the rest are not here**, though they used to be: a worker
/// serves one session and knows nothing of the client's surface, so a sentence naming `modules`
/// reached an eleven-tool caller that cannot call it — the same defect items 40 and 41 removed from
/// the instructions and the descriptions, surviving in the one channel nobody had scanned. They are
/// appended by [`crate::server::WindbgServer::annotated_report`], from this same summary, and only
/// where the surface serves the tool named.
fn summary_text(diagnostic: &str, summary: &structured::TargetSummary) -> String {
    let mut lines: Vec<String> = Vec::new();
    if let Some(bug_check) = &summary.bug_check {
        lines.push(format!(
            "Bug check {}{}, parameters {}.",
            bug_check.code,
            bug_check
                .name
                .as_deref()
                .map(|name| format!(" {name}"))
                .unwrap_or_default(),
            bug_check.parameters.join(" "),
        ));
    }
    if let Some(loaded) = summary.modules_loaded {
        lines.push(match &summary.primary_module {
            // Quoted, and through the same guard the filter goes through. This name is the
            // target's and the sentence around it is prose, so bare it would reach a
            // Markdown-rendering client as markup — `[ntdll](https://elsewhere)` displaying as
            // `ntdll` and the opener naming a module that is not the one it opened. A code span
            // renders its contents literally, and `renderable` escapes the one character that
            // closes one. The table solves the same problem with a fence; a sentence cannot carry
            // a fence, so it carries the span instead.
            Some(module) => format!(
                "{loaded} module(s) loaded, `{}` at {}.",
                renderable(&module.name),
                module.start
            ),
            None => format!("{loaded} module(s) loaded."),
        });
    }
    let diagnostic = diagnostic.trim_end();
    match (diagnostic.is_empty(), lines.is_empty()) {
        (_, true) => diagnostic.to_string(),
        (true, false) => lines.join("\n"),
        (false, false) => format!("{diagnostic}\n\n{}", lines.join("\n")),
    }
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

fn run_to_address(e: &DebugEngine, address: &str, wait: u32) -> Result<Output, Failed> {
    let target =
        resolve(e, address).ok_or_else(|| format!("could not resolve address `{address}`"))?;
    let res = e.run_to_address(target, wait).map_err(failed)?;
    query::invalidate_allocator_snapshots();
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
        // Says nothing about reachability, and must not be read as a timeout: the run ended
        // because the target did, so `address` was never ruled out.
        RunToOutcome::TargetGone => format!(
            "VERDICT: TARGET GONE — the target ended before reaching {}\n  \
             (it ran to completion or was released; this says nothing about whether the address \
             is reachable)\n{TARGET_GONE}\n",
            fmt_addr(target)
        ),
    };
    if !res.output.trim().is_empty() {
        msg.push_str("---- debugger output ----\n");
        msg.push_str(&res.output);
    }
    // The verdict was a value in dbgscope and became a `VERDICT:` line here, which is what every
    // caller then matched on. It travels as a value again; the line stays for the reader.
    let (verdict, stopped_at) = match res.outcome {
        RunToOutcome::Hit => (structured::RunToVerdict::Hit, Some(target)),
        RunToOutcome::StoppedElsewhere { stopped_at } => {
            (structured::RunToVerdict::StoppedElsewhere, Some(stopped_at))
        }
        RunToOutcome::Timeout => (structured::RunToVerdict::Timeout, None),
        // No position: the engine has no target to read one from, and reporting the address asked
        // for would say execution got there.
        RunToOutcome::TargetGone => (structured::RunToVerdict::TargetGone, None),
    };
    Ok(Output::typed(
        msg,
        structured::RunToReport {
            verdict,
            target: structured::addr(target),
            stopped_at: stopped_at.map(structured::addr),
            timeout_ms: wait,
            output: res.output,
        },
    ))
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
    use dbgscope::pool::WalkStalls;

    use super::*;

    /// The other half of the coverage rule, and the half a check on the *op* cannot see: which
    /// `Execute` calls in this file run with no watchdog.
    ///
    /// `server::tests::only_index_trace_runs_a_command_unbounded` certifies that one **tool**
    /// constructs [`EngineOp::UnboundedCommand`]. That is true and is narrower than the rule
    /// reads, because a typed op can run a command too — and one did: `set_breakpoint` reached
    /// `execute_command("bp <caller's expression>")` while every op around it had moved onto the
    /// bounded path, so `bp nt!Foo+0x10` against a deferred module with a `srv*` path could hold
    /// this session's engine for a symbol-server fetch with nothing to cut it short. Raised by
    /// Codex on [#271](https://github.com/glslang/windbg-mcp/pull/271); the finding was right and
    /// this test is what stops the next one being found by review rather than by the build.
    ///
    /// **That op runs no command at all now** (dbgscope#126), which does not retire this test and
    /// is the reason worth keeping: reading why `set_breakpoint` ran a command led to finding that
    /// its stated reason — `bp`'s syntax — was unreachable through the tool, and the op became a
    /// typed setter. A count that only ever went up would have missed that; what this asserts is
    /// the *set*, so a site leaving it is as visible as one arriving.
    ///
    /// So the allowlist is enumerated rather than the exception, **by count and not by function**.
    /// `execute` is the whole `EngineOp` dispatcher, so "is `execute` on the list" is a question
    /// that stays answered however many commands are added to it; the number is what makes each
    /// one somebody's decision. Every unbounded `execute_command` left in this file is one of:
    ///
    /// - **`execute`, seven** — six in the opener arms (`.load ext`, `vertarget`,
    ///   `!ttdext.index -status`, `dx @$curprocess.TTD.Lifetime`, and `r` after an attach and
    ///   after a launch): fixed strings with no caller text in them, run once inside an open that
    ///   is already bounded by `LOAD_WAIT_MS` on its wait half, and each the *report* an opener
    ///   answers with rather than work a caller asked for. The seventh is **not** an opener and
    ///   the count is how you find it: `SymbolPath`'s `.sympath`, which echoes back the path just
    ///   applied. Same argument — a fixed string, reading state this call has already changed —
    ///   but it is an ordinary arm, so a reader who took "`execute`'s opener arms" at face value
    ///   would be six for seven.
    /// - **`kernel_report`** — `.load kdexts` and `vertarget`, the same, for a kernel attach.
    /// - **`pump_a_resume`** — the `Execute` that sets the run state. Bounded by the pump that
    ///   follows it rather than by a watchdog, which is the whole shape of `EngineOp::Resume`:
    ///   `Execute` returns without the target having moved.
    /// - **`resolve`** — `? <expr>`, which *is* caller text and is the one entry here that is a
    ///   deferral rather than a reason. It is a shared helper with three callers on three
    ///   different clocks (`disassemble`, `run_to_address`, `reachable`), two of which have no
    ///   patience to thread through it at all. `FOLLOWUPS.md` item 56.
    /// - **`reachable`** — `lm m` and `uf`, up to `max_functions` of them in one job. A
    ///   command-level bound is the wrong instrument: no individual `uf` is the problem.
    ///   `FOLLOWUPS.md` item 13.
    ///
    /// Read from the source for `record::tests::this_module_never_writes_to_stdout`'s reason: the
    /// property is about what is *written*, and no runtime test can prove the absence of a call
    /// nobody made today.
    #[test]
    fn every_unbounded_execute_in_this_worker_is_accounted_for() {
        // Only the half that ships; the tests below run no engine, and this one names the thing
        // it searches for.
        let code = include_str!("worker.rs")
            .split_once("\n#[cfg(test)]")
            .expect("this module has a test half")
            .0;

        // **Call sites, not functions.** Deduplicating by enclosing function would let a new
        // `execute_command` inside an arm of `execute` — which is the whole `EngineOp` dispatcher,
        // already allowlisted, and already holding seven — leave this list unchanged and the test
        // green. The count is what makes each one a decision somebody took.
        let mut sites: Vec<&str> = Vec::new();
        let mut enclosing = "<top level>";
        for line in code.lines() {
            // Every function in this file is at column 0; the closures inside them are not, and a
            // call from one is still that function's.
            if let Some(name) = line.strip_prefix("fn ").or(line.strip_prefix("pub fn ")) {
                enclosing = name.split(['(', '<']).next().unwrap_or(name);
            }
            // `execute_command_bounded` starts with the same text, so the open paren is what
            // tells the two apart — which is also why a zero budget is invisible here and is
            // `only_index_trace_runs_a_command_unbounded`'s half of the question.
            if line.contains("execute_command(") {
                sites.push(enclosing);
            }
        }
        let mut counted: Vec<(&str, usize)> = Vec::new();
        for site in sites {
            match counted.iter_mut().find(|(name, _)| *name == site) {
                Some((_, n)) => *n += 1,
                None => counted.push((site, 1)),
            }
        }
        counted.sort_unstable();
        assert_eq!(
            counted,
            [
                ("execute", 7),
                ("kernel_report", 2),
                ("pump_a_resume", 1),
                ("reachable", 2),
                ("resolve", 1),
            ],
            "an `Execute` with no watchdog is in a place this rule has not accounted for. Every              command a tool's op runs is bounded on the caller's clock (DECISIONS.md, 2026-08-02,              revised 2026-08-31); the sites above are the enumerated exceptions and the doc              comment says why each is one. Bound it, or add it here with its reason — including              when the count of an already-listed function goes up, which is a new unbounded              command inside a function that has some for other reasons."
        );
    }

    // ---- pool tags ------------------------------------------------------------------

    // What `tag_label` returns for a given tag is dbgscope's own test
    // (`test_raw_tag_round_trips_where_the_displayed_one_cannot`); the rule is defined there so
    // the extension's output and this server's cannot disagree. What is this crate's to prove is
    // that its two tables *use* it — `tag_columns_line_up` below.

    /// The empty answer that is about the question rather than about the pool.
    #[test]
    fn a_rendering_handed_back_as_a_tag_says_so() {
        let hint = pool_tag_rendering_hint("....");
        assert!(
            hint.contains("0x2e2e2e2e") && hint.contains("rendering"),
            "querying a rendering must say which bytes it really searched for: {hint}"
        );

        // The two cases that must stay quiet: a tag that simply is not allocated, and a raw form,
        // which already says exactly which bytes it meant.
        assert_eq!(pool_tag_rendering_hint("Tgsm"), "");
        assert_eq!(pool_tag_rendering_hint("0x000180ff"), "");

        // A `0x` prefix is not the raw form. `0x..` is four printable bytes — an ordinary,
        // *ambiguous* tag — so it is owed the same explanation as `....`, and testing the prefix
        // rather than the form would have silently skipped it.
        let prefixed = pool_tag_rendering_hint("0x..");
        assert!(
            prefixed.contains(&raw_tag_hex(u32::from_le_bytes(*b"0x.."))),
            "a four-byte tag that merely starts with `0x` is still a rendering: {prefixed}"
        );
    }

    /// The header and the rows are two literals that have to agree, and nothing else checks it.
    ///
    /// Widening the tag column for the raw form is exactly the edit that breaks this, so the
    /// invariant is pinned rather than eyeballed: every column of a rendered row must start
    /// where the header says it does.
    /// One allocated chunk carrying `raw_tag`, for the rendering tests below.
    fn tagged_chunk(raw_tag: u32) -> PoolSpan {
        PoolSpan {
            header_address: 0xffff_e20d_bc6a_f030,
            usable_address: 0xffff_e20d_bc6a_f040,
            size: 0x70,
            requested_size: None,
            raw_tag,
            display_tag: dbgscope::pool::tag_label(raw_tag),
            pool_kind: dbgscope::pool::PoolKind::NonPagedNx,
            numa_node: 0,
            heap: dbgscope::pool::HeapIdentity {
                pool_state: 0,
                heap: 0,
                special: false,
            },
            subsegment: None,
            backend: dbgscope::pool::PoolBackend::Vs,
            state: PoolState::Allocated,
            size_class: 0x70,
        }
    }

    /// The collision this distinction exists for, arriving as an *answer* rather than an empty.
    ///
    /// A caller copies `....` from a binary tag's row, and the snapshot also holds chunks whose
    /// tag really is four dots. Those match, so the empty branch never runs — and without the
    /// caveat the rows read as the binary tag's chunks. A confident answer about a different tag
    /// is worse than finding nothing, so the warning cannot be conditioned on emptiness.
    #[test]
    fn a_rendering_that_matches_a_different_tag_is_still_flagged() {
        let dots = u32::from_le_bytes(*b"....");
        let answered = render_find_tag("....", None, &[tagged_chunk(dots)], 64);
        assert!(
            answered.contains("0x2e2e2e2e") && answered.contains("rendering"),
            "rows for the literal dots must still say what was actually searched for: {answered}"
        );

        // An unambiguous tag keeps its answer clean — the caveat is for renderings, not for
        // every result.
        let plain = render_find_tag(
            "Tgsm",
            None,
            &[tagged_chunk(u32::from_le_bytes(*b"Tgsm"))],
            64,
        );
        assert!(
            !plain.contains("rendering"),
            "an unambiguous tag needs no caveat: {plain}"
        );
    }

    #[test]
    fn tag_columns_line_up() {
        let raw = u32::from_le_bytes([0x00, 0x01, 0x80, 0xff]);
        let span = tagged_chunk(raw);
        let row = pool_row(&span);
        let tag_at = POOL_COLUMNS.find("tag").expect("header names a tag column");
        assert_eq!(
            row[tag_at..tag_at + TAG_WIDTH].trim(),
            "0x000180ff",
            "the tag column must sit under its header:\n{POOL_COLUMNS}\n{row}"
        );
        let numa_at = POOL_COLUMNS
            .find("numa")
            .expect("header names a numa column");
        assert_eq!(
            row[numa_at..].trim(),
            "0",
            "widening the tag column must move every column after it:\n{POOL_COLUMNS}\n{row}"
        );

        // The census is a second table with its own header literal and the same tag column.
        let census = render_census(
            &[query::PoolTagSummary {
                display_tag: "....".into(),
                raw_tag: raw,
                allocations: 18633,
                total_bytes: 0x3f6_6cf0,
                paged_allocations: 13115,
                nonpaged_allocations: 5518,
            }],
            40,
        );
        let (header, entry) = census
            .lines()
            .skip_while(|line| !line.starts_with("tag"))
            .take(2)
            .collect::<Vec<_>>()
            .split_first()
            .map(|(head, rest)| (*head, rest[0]))
            .expect("the census renders a header and a row");
        let tag_at = header.find("tag").expect("header names a tag column");
        assert_eq!(
            entry[tag_at..tag_at + TAG_WIDTH].trim(),
            "0x000180ff",
            "an unprintable tag must be queryable from the census too:\n{header}\n{entry}"
        );
        // `rfind`, because "paged" also sits inside "nonpaged" two columns earlier.
        let paged_at = header.rfind("paged").expect("header names a paged column");
        assert_eq!(
            entry[paged_at..].trim(),
            "13115",
            "the census columns must line up under their header:\n{header}\n{entry}"
        );
    }

    // ---- pool walk diagnostics ------------------------------------------------------

    /// A report from a walk that met no unreadable page and refused no chunk, for the fixtures
    /// below to spread over their own fields. They exercise the diagnostic *rendering*; what
    /// the gap figures do with a walk that met either is `structured`'s question.
    fn quiet_walk() -> query::PoolSnapshotReport {
        query::PoolSnapshotReport {
            layout: Default::default(),
            total_chunks: 0,
            allocated_chunks: 0,
            coverage: coverage(true),
            stopped_after_matches: None,
            diagnostics: PoolDiagnostics::default(),
            stalls: WalkStalls::default(),
            refused_chunks: 0,
            unplaced_bytes: 0,
        }
    }

    /// The gap figures reach an answer through `walk_info`, which is a struct literal: a field
    /// wired to `None`, or to the wrong half of the report, compiles and silently drops what the
    /// walk measured. `structured` proves the mapping; this proves the assignment.
    #[test]
    fn walk_info_carries_what_the_walk_measured() {
        let mut report = quiet_walk();
        assert!(
            walk_info(&report).gaps.is_none(),
            "a walk that met none of it reports none"
        );

        report.stalls = WalkStalls {
            pages: 2,
            skipped_bytes: 0x2000,
            recovered_bytes: 0x8000,
        };
        report.refused_chunks = 7;
        let gaps = walk_info(&report)
            .gaps
            .expect("a walk that stalled has gaps to report");
        assert_eq!(
            (
                gaps.stalled_pages,
                gaps.skipped_bytes,
                gaps.recovered_bytes,
                gaps.refused_chunks
            ),
            (2, 0x2000, 0x8000, 7)
        );

        report.stopped_after_matches = Some(2);
        let intentional = walk_info(&report);
        assert_eq!(
            intentional.coverage,
            structured::AllocatorCoverage::MatchLimitReached
        );
        assert_eq!(intentional.stop_after_matches, Some(2));
    }

    fn report_with(complete: bool, diagnostics: &[&str]) -> query::PoolSnapshotReport {
        query::PoolSnapshotReport {
            total_chunks: 4211,
            allocated_chunks: 3007,
            coverage: coverage(complete),
            diagnostics: diagnostics.iter().map(|line| line.to_string()).collect(),
            ..quiet_walk()
        }
    }

    /// A walk that covered everything, or one that stopped short for a reason other than the
    /// clock. The deadline case is a value of its own and is exercised where it becomes an
    /// answer — in `structured`.
    fn coverage(complete: bool) -> query::WalkCoverage {
        if complete {
            query::WalkCoverage::Complete
        } else {
            query::WalkCoverage::Partial
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
            coverage: coverage(false),
            diagnostics: lines.into_iter().collect(),
            ..quiet_walk()
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
            coverage: coverage(true),
            diagnostics: lines.into_iter().collect(),
            ..quiet_walk()
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

    #[test]
    fn an_intentional_match_stop_names_the_condition_instead_of_a_failure() {
        let mut report = report(false);
        report.stopped_after_matches = Some(1);
        let caveat = coverage_caveat(&report).expect("an early stop must be explained");
        assert!(caveat.contains("MATCH LIMIT REACHED"), "{caveat}");
        assert!(caveat.contains("stopped after 1"), "{caveat}");
        assert!(!caveat.contains("INCOMPLETE"), "{caveat}");
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

    #[test]
    fn heap_addr_reads_a_short_bare_run_as_hex() {
        assert_eq!(parse_heap_addr("10000"), Ok(0x1_0000));
        assert_eq!(parse_heap_addr("ffff"), Ok(0xffff));
        assert_eq!(parse_heap_addr("0x10000"), Ok(0x1_0000));
    }

    fn heap_filter_fixture() -> HeapAllocation {
        HeapAllocation {
            heap: 0x10000,
            backend: HeapBackend::Vs,
            state: HeapState::Allocated,
            header_address: 0x20000,
            user_address: 0x20010,
            capacity: 0x80,
            requested_size: None,
            subsegment: Some(0x30000),
            size_class: 0x80,
        }
    }

    #[test]
    fn heap_filter_rejects_capacity_below_minimum() {
        let allocation = heap_filter_fixture();
        assert!(!heap_allocation_matches(
            &allocation,
            None,
            None,
            HeapState::Allocated,
            Some(0x81),
            None,
        ));
        assert!(heap_allocation_matches(
            &allocation,
            None,
            None,
            HeapState::Allocated,
            Some(0x80),
            None,
        ));
    }

    #[test]
    fn heap_filter_rejects_capacity_above_maximum() {
        let allocation = heap_filter_fixture();
        assert!(!heap_allocation_matches(
            &allocation,
            None,
            None,
            HeapState::Allocated,
            None,
            Some(0x7f),
        ));
        assert!(heap_allocation_matches(
            &allocation,
            None,
            None,
            HeapState::Allocated,
            None,
            Some(0x80),
        ));
    }

    #[test]
    fn heap_filter_requires_the_selected_allocator_identity() {
        let allocation = heap_filter_fixture();
        assert!(!heap_allocation_matches(
            &allocation,
            Some(0x20000),
            Some(HeapBackend::Vs),
            HeapState::Allocated,
            None,
            None,
        ));
        assert!(!heap_allocation_matches(
            &allocation,
            Some(0x10000),
            Some(HeapBackend::Lfh),
            HeapState::Allocated,
            None,
            None,
        ));
        assert!(heap_allocation_matches(
            &allocation,
            Some(0x10000),
            Some(HeapBackend::Vs),
            HeapState::Allocated,
            None,
            None,
        ));
    }

    #[test]
    fn heap_diagnostic_scope_and_filter_preserve_scoped_totals_and_examples() {
        let (routed_heap, report) = query_heap_diagnostics(
            Some(0x20000),
            || {
                Ok::<_, ()>((
                    None,
                    heap_query::HeapDiagnosticReport {
                        categories: Vec::new(),
                        examples: Vec::new(),
                    },
                ))
            },
            |heap| {
                Ok::<_, ()>((
                    Some(heap),
                    heap_query::HeapDiagnosticReport {
                        categories: vec![
                            DiagnosticShape {
                                shape: "unreadable VS free tree node <address>: sparse memory"
                                    .into(),
                                total: 17,
                            },
                            DiagnosticShape {
                                shape: "invalid LFH bitmap at <address>".into(),
                                total: 3,
                            },
                        ],
                        examples: vec![
                            "unreadable VS free tree node 0x20100: sparse memory".into(),
                            "invalid LFH bitmap at 0x20200".into(),
                        ],
                    },
                ))
            },
        )
        .unwrap();

        assert_eq!(routed_heap, Some(0x20000));
        let selected = select_heap_diagnostics(&report, Some("free TREE"));
        assert_eq!(selected.categories.len(), 1);
        assert_eq!(selected.categories[0].total, 17);
        assert_eq!(selected.examples.len(), 1);
        assert!(selected.examples[0].contains("0x20100"));

        let unfiltered = select_heap_diagnostics(&report, None);
        assert_eq!(unfiltered.categories.len(), 2);
        assert_eq!(unfiltered.examples.len(), 2);
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
    /// because zero *disables* dbgscope's watchdog, which would make a command dequeued near the
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

    /// And a walk's start resolution is armed too, whatever is left of the clock.
    ///
    /// A walk is a run of reads that no watchdog can bound — the between-node deadline is the only
    /// thing holding it — with exactly one exception: the `?` that resolves a symbolic `start`,
    /// which is a command, can block on a symbol server, and *can* be bounded. Zero would leave
    /// that one command unbounded inside a call whose every other part is bounded, so the floor is
    /// what makes the exception hold at every budget rather than at most of them.
    #[test]
    fn resolving_a_symbolic_start_is_bounded_at_every_budget() {
        assert_eq!(resolve_budget_ms(Duration::from_secs(30)), 30_000);
        // Sub-millisecond, which truncates to zero — and zero disarms the watchdog entirely.
        assert_ne!(resolve_budget_ms(Duration::from_micros(1)), 0);
        assert_ne!(resolve_budget_ms(Duration::ZERO), 0);
        // And a budget past what the API can carry saturates rather than wrapping to something
        // small, which would cut a healthy resolve short.
        assert_eq!(
            resolve_budget_ms(Duration::from_secs(u32::MAX as u64)),
            u32::MAX
        );
    }

    /// An `!analyze` is only started when its watchdog fits inside what is left **and still leaves
    /// the headroom the reply needs** — not merely when something is left.
    ///
    /// The property rather than the constant, in both directions. Whenever [`analysis_fits`] says
    /// yes, the budget [`watchdog_budget_ms`] then arms plus [`WATCHDOG_HEADROOM`] is within the
    /// patience remaining — so a command that runs all the way to its deadline still has time for
    /// the break to unwind and the answer to travel. Whenever it says no, that sum would have
    /// overrun — so the check is not refusing time it could have used. Both halves stay true if
    /// either constant is retuned, which is the point of testing them this way.
    #[test]
    fn an_analysis_only_starts_when_its_watchdog_and_the_reply_both_fit() {
        let patience = Duration::from_secs(300);
        for spent in (0..=300).map(Duration::from_secs) {
            let left = patience.saturating_sub(spent);
            let budget = Duration::from_millis(u64::from(watchdog_budget_ms(patience, spent)));
            let needed = budget + WATCHDOG_HEADROOM;
            if analysis_fits(patience, spent) {
                assert!(
                    needed <= left,
                    "with {left:?} left, a watchdog of {budget:?} plus the reply's headroom needs \
                     {needed:?} — `analysis_fits` must not have allowed it"
                );
            } else {
                assert!(
                    needed > left,
                    "with {left:?} left, {budget:?} plus headroom is {needed:?} and would have \
                     fitted; refusing to run is time thrown away"
                );
            }
        }
        // The boundary, spelled out: twice the headroom is enough, a millisecond less is not.
        assert!(analysis_fits(2 * WATCHDOG_HEADROOM, Duration::ZERO));
        assert!(!analysis_fits(
            2 * WATCHDOG_HEADROOM - Duration::from_millis(1),
            Duration::ZERO
        ));
        // The floor alone is *not* enough, which is the case this threshold exists for: the
        // watchdog would be armed for the whole of it and leave nothing to answer in.
        assert!(!analysis_fits(WATCHDOG_HEADROOM, Duration::ZERO));
        // A caller whose patience the supervisor could not fill in at all gets no analysis rather
        // than a floored one.
        assert!(!analysis_fits(Duration::ZERO, Duration::ZERO));
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
            barred: BTreeSet::new(),
            tearing_down: false,
            interrupted: None,
            pumping: None,
            uninterruptible: None,
        }
    }

    /// Which job is pumping a resumed target, which is what a teardown reads to decide whether to
    /// break in — and it is cleared however the job ends.
    ///
    /// The property, stated as the failure it prevents: a stale `pumping` would have the *next*
    /// `end_session` on this session Ctrl+Break whatever happened to be running, and a teardown
    /// arriving behind a long `pool_census` would cut it short for no reason. So the release
    /// clears it as well as the ordinary path, which is what covers a panicking op.
    #[test]
    fn the_pumping_job_is_cleared_however_it_ends() {
        let mut running = idle();
        running.claim(7);
        assert_eq!(
            running.pumping, None,
            "a job is not pumping until it says so"
        );
        running.pump(Some(7));
        assert_eq!(running.pumping, Some(7));
        // The ordinary path: the pump returned and everything after it is not a thing to break.
        running.pump(None);
        assert_eq!(running.pumping, None);

        // And the backstop, for an op that panicked between the two.
        running.pump(Some(7));
        running.release(7);
        assert_eq!(
            running.pumping, None,
            "a claim given back must take the pump with it, or a later teardown breaks in on a \
             job that is not running a target"
        );
    }

    /// A teardown reaches a resume in either of the two states it can be in, and there is no
    /// third.
    ///
    /// Breaking the pump only reaches a run that has *already started*. A resume still in the
    /// engine thread's queue — behind a long `pool_census`, or simply not yet dequeued — has
    /// nothing to break, so a teardown that only looked at `pumping` would find none, queue behind
    /// the resume, and then wait out the whole run it arrived too early to stop: the release grace
    /// would expire against a worker that was working perfectly, and the worker would be killed
    /// still holding the target. Both orderings are staged here because it is the *pair* that
    /// leaves no window, not either half.
    #[test]
    fn a_teardown_either_breaks_a_run_or_stops_it_starting() {
        // The resume got there first: there is a pump, and the teardown is told to break it.
        let mut running = idle();
        running.claim(7);
        assert!(
            running.claim_pump(7).is_ok(),
            "nothing is ending; the run may start"
        );
        assert_eq!(
            running.begin_teardown(),
            Some(7),
            "a teardown arriving on a pumping run has to be given the job to break"
        );

        // The teardown got there first: there is nothing to break, and the run never starts.
        let mut running = idle();
        assert_eq!(
            running.begin_teardown(),
            None,
            "nothing was pumping, so there is nothing to break — and that is not the end of it"
        );
        running.claim(8);
        assert!(
            matches!(running.claim_pump(8), Err(PumpRefused::TearingDown)),
            "a resume dequeued after the teardown was read must not set the target going: there \
             is no one left to break it in, and the release behind it would wait out the whole run"
        );
        assert_eq!(
            running.pumping, None,
            "and a refused claim leaves nothing for a later teardown to break either"
        );
    }

    /// A break for a run that is not the one on the engine bars it, rather than doing nothing.
    ///
    /// Naming the job stops the break being rebound to whatever the engine thread is doing
    /// instead — but refusing to rebind is only half an answer. The run may still be *in the
    /// queue*, and left alone it starts the moment the queue drains and holds the target for the
    /// bound it named, which may be an hour: the caller asked for the target to stop and got a
    /// target that had not started yet and then did.
    ///
    /// **Unconditionally**, in either id direction, because nothing here can tell a queued job
    /// from a finished one — a job id is allocated before `Session::submit_gate` is taken, so a
    /// task overtaken between the two is enqueued behind a larger id. Reading the smaller id as
    /// "already finished" would skip barring the very run that needs it. Barring one that has
    /// already run is a no-op, since ids are never reused.
    #[test]
    fn a_break_for_a_run_that_is_not_running_bars_it_either_way() {
        for (running_job, named) in [(4, 9), (9, 4)] {
            let mut running = idle();
            running.claim(running_job);
            assert_eq!(
                running.break_for_other(named),
                Some(Interrupted::Barred),
                "job {named} is not job {running_job}, and which of them is the larger says \
                 nothing about which reaches the engine thread first"
            );
            running.release(running_job);
            running.claim(named);
            assert!(
                matches!(running.claim_pump(named), Err(PumpRefused::BrokenIn)),
                "and when it is dequeued it must not set the target going: the break that could \
                 not reach it is honoured here or nowhere"
            );
        }

        // Between jobs is barred too, and is not an edge case: the resume may be next in the
        // queue, which is exactly when barring matters most.
        let mut running = idle();
        assert_eq!(running.break_for_other(1), Some(Interrupted::Barred));

        // **A bar for a dead job does not displace a live one.** A `break_in` for a run that has
        // since finished still arrives here — the supervisor sent it while its slot said the run
        // was going — and it can be overtaken on the way, landing after a later `break_in` has
        // barred a genuinely queued run. One slot would overwrite that bar with a dead id, and
        // the queued run would start after all.
        let mut running = idle();
        running.claim(20);
        running.break_for_other(9); // the live one: queued behind job 20
        running.break_for_other(3); // the stale one: job 3 is long gone
        running.release(20);
        running.claim(9);
        assert!(
            matches!(running.claim_pump(9), Err(PumpRefused::BrokenIn)),
            "the bar on the queued run has to survive a break that arrives late for a run that \
             had already ended"
        );

        // The job that *is* running takes the ordinary path instead — it has a pump to interrupt.
        let mut running = idle();
        running.claim(3);
        assert_eq!(running.break_for_other(3), None);
        assert!(
            running.claim_pump(3).is_ok(),
            "and nothing barred it, which is the whole point of naming the job on the request"
        );

        // A bar is spent by the job it refuses, which is the only place one can ever be used.
        let mut running = idle();
        running.break_for_other(5);
        running.claim(5);
        assert!(matches!(running.claim_pump(5), Err(PumpRefused::BrokenIn)));
        assert!(
            running.barred.is_empty(),
            "the job it named has been refused and can never be dequeued again, so keeping it \
             would only make the set grow for nothing"
        );
    }

    /// The bar stays up. A session that is ending does not stop ending because a job finished.
    #[test]
    fn a_teardown_bars_every_later_resume_not_just_the_next_one() {
        let mut running = idle();
        running.begin_teardown();
        running.claim(1);
        assert!(running.claim_pump(1).is_err());
        running.release(1);
        running.claim(2);
        assert!(
            running.claim_pump(2).is_err(),
            "releasing a job clears what that job held, not the fact that the session is ending"
        );
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

    /// A job that has sealed itself takes no break at all — not a second one, and **not a first**.
    ///
    /// The first is the case that matters and the one the seal exists for. A `debug_batch` reaches
    /// its `always` block on every path, including paths no interrupt was ever involved in, so an
    /// interrupt arriving for the first time while cleanup runs would land on a restore command.
    /// That returns `Ok` with partial output like any interrupted command, so it is recorded as a
    /// step that worked: `rollback: COMPLETE` with the target still changed.
    #[test]
    fn a_sealed_job_takes_no_interrupt_at_all() {
        let mut running = idle();
        running.claim(7);
        assert!(!running.sealed(7), "an ordinary job is interruptible");

        running.seal(7);
        assert!(running.sealed(7));
        // And the seal is the job's, not the process's: it goes when the job does, or the next
        // batch on this session could never be interrupted.
        assert!(!running.release(7), "no interrupt was ever raised for it");
        running.claim(8);
        assert!(!running.sealed(8), "the next job starts interruptible");
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

    // ---- what a set_breakpoint caller is told -------------------------------

    fn breakpoint(id: u32, address: Option<&str>) -> structured::BreakpointInfo {
        structured::BreakpointInfo {
            id,
            kind: structured::BreakpointKind::Code,
            address: address.map(str::to_string),
            expression: address.is_none().then(|| "nosuchmod!Sym".to_string()),
            command: None,
            watch: None,
            thread: None,
            enabled: true,
            deferred: address.is_none(),
            one_shot: false,
            pass_count: 1,
            passes_remaining: 1,
        }
    }

    fn breakpoint_set(
        set: structured::BreakpointInfo,
        breakpoints: Vec<structured::BreakpointInfo>,
    ) -> structured::BreakpointSet {
        structured::BreakpointSet {
            breakpoint: set,
            replaced: Vec::new(),
            breakpoints,
            cut_short: false,
        }
    }

    /// Setting a breakpoint printed **nothing**, so a text-only client saw an empty result and
    /// could not tell it from silence. The answer goes into the text as well as into the typed
    /// half, or the fix only reaches half the clients it was written for.
    #[test]
    fn a_breakpoint_that_was_set_says_so_in_the_text_too() {
        let out = render_breakpoints(&breakpoint_set(
            breakpoint(1, None),
            vec![
                breakpoint(0, Some("0x00007ffb6e6a0e10")),
                breakpoint(1, None),
            ],
        ));
        assert!(out.contains("Breakpoint 1 set"), "{out}");
        assert!(out.contains("deferred"), "{out}");
        assert!(out.contains("0x00007ffb6e6a0e10"), "{out}");
        // The one this call set is marked in the listing, so a caller reading the table can find
        // it without comparing ids by eye.
        assert!(
            out.lines().any(|line| line.starts_with("* 1")),
            "this call's breakpoint should be marked in the listing: {out}"
        );
    }

    /// A listing that failed must not read as a breakpoint that was not set.
    ///
    /// **This used to need saying and now cannot be got wrong**, which is the point of asserting
    /// it here rather than dropping the test with the fields it was written against. The listing
    /// was once the *only* source of what a call had done — the id came from diffing `bl` either
    /// side — so a failed read meant an unknown outcome and two fields (`listed`,
    /// `listing_error`) existed to say so. The engine now hands back the breakpoint it created,
    /// so the mutation and the inspection are different fields and a failure in one cannot reach
    /// the other.
    #[test]
    fn a_listing_that_failed_still_says_the_breakpoint_is_set() {
        let out = render_breakpoints(&breakpoint_set(
            breakpoint(3, Some("0x00007ffb6e6a0e10")),
            Vec::new(),
        ));
        assert!(out.contains("Breakpoint 3 set"), "{out}");
        assert!(out.contains("0x00007ffb6e6a0e10"), "{out}");
        assert!(
            out.contains("could not be read"),
            "the missing listing should be explained rather than rendered as an empty table: {out}"
        );
        // And it must not invite the recovery that sets a second breakpoint.
        assert!(
            !out.to_ascii_lowercase().contains("re-run"),
            "nothing here is unknown, so nothing should suggest running it again: {out}"
        );
    }

    /// A replacement is told to the caller, not left in a field.
    ///
    /// Setting a breakpoint where one already is *removes* it — that is what `bp` does, and what
    /// this tool has always done — and the caller most affected is the one whose old breakpoint
    /// carried a command: an `ioctl_trace` log that stops with nothing to say why. It was a
    /// `breakpoint N redefined` line in debugger text before and is a value now, so the rendering
    /// is what puts it back in front of a human.
    #[test]
    fn a_breakpoint_that_replaced_others_says_which() {
        let mut set = breakpoint_set(
            breakpoint(4, Some("0x00007ffb6e6a0e10")),
            vec![breakpoint(4, Some("0x00007ffb6e6a0e10"))],
        );
        set.replaced = vec![1, 2];
        let out = render_breakpoints(&set);
        assert!(out.contains("replaced"), "{out}");
        assert!(out.contains('1') && out.contains('2'), "{out}");
    }

    /// Cut short and **resolved**: the location got an address, so the only thing to say is not to
    /// ask again.
    ///
    /// A break leaves an `Ok` result carrying a breakpoint, so nothing about the shape says the
    /// resolve did not finish. What changed with the typed setter is that this is no longer
    /// ambiguous — the breakpoint is known set either way, and only its *location* was ever in
    /// question.
    #[test]
    fn an_interrupted_set_that_resolved_says_where_it_landed_and_not_to_retry() {
        let mut set = breakpoint_set(
            breakpoint(2, Some("0x00007ffb6e6a0e10")),
            vec![breakpoint(2, Some("0x00007ffb6e6a0e10"))],
        );
        set.cut_short = true;
        let out = render_breakpoints(&set);
        assert!(out.contains("interrupted"), "{out}");
        assert!(out.contains("it did resolve"), "{out}");
        assert!(
            out.contains("**not** re-request"),
            "a retry sets a second breakpoint: {out}"
        );
    }

    /// Cut short and **deferred**: the same interruption, and the advice has more force.
    ///
    /// The engine deduplicates a resolved location by address, so a retry there is merely wasteful;
    /// a deferred one has no address to key on, so a retry genuinely leaves two breakpoints. The
    /// two states must not share a sentence, and the deferred one is the one that has to warn.
    #[test]
    fn an_interrupted_set_that_deferred_warns_that_a_retry_would_duplicate() {
        let mut set = breakpoint_set(breakpoint(2, None), vec![breakpoint(2, None)]);
        set.cut_short = true;
        let out = render_breakpoints(&set);
        assert!(out.contains("interrupted"), "{out}");
        assert!(out.contains("deferred"), "{out}");
        assert!(
            out.contains("cannot deduplicate"),
            "the deferred case is the one where a retry really does duplicate: {out}"
        );
    }

    // ---- what an interrupted caller is told --------------------------------

    /// The note every bounded raw command gets, which is why it must not prescribe a retry.
    ///
    /// One function serves `execute`, `dx`, every `debug_batch` command step and the six typed
    /// tools that build a command — and it is handed a `CommandRun`, so it cannot see which. It
    /// used to end "scope it and retry", written for the unbounded `s` search the bounded path was
    /// adopted for. That is right for a query and harmful for a mutation: `ioctl_trace` builds a
    /// `bp` with a logging command string, and a `bp` cut short may have installed its breakpoint
    /// before the break, so re-issuing it installs a second. Raised on
    /// [#271](https://github.com/glslang/windbg-mcp/pull/271) against `ioctl_trace`, and true of
    /// `execute { "command": "bp …" }` for as long as the note has existed.
    #[test]
    fn the_deadline_note_does_not_tell_a_caller_to_re_issue_a_mutation() {
        let note = told(CommandRun {
            output: "partial output\n".to_string(),
            cut_short: Some(Interruption::Deadline { after_ms: 30_000 }),
            target_gone: false,
        });
        assert!(note.starts_with("partial output"), "{note}");
        assert!(note.contains("30000 ms"), "{note}");
        // The fact a caller has to act on: this may have already changed the target.
        assert!(note.contains("already done stands"), "{note}");
        assert!(
            note.contains("read the target rather than re-issuing"),
            "{note}"
        );
        // The scoping hint survives, because it is what a query actually wants.
        assert!(note.contains("narrowed"), "{note}");
        // Nothing here may read as "run it again". The old wording ended "and retry".
        assert!(
            !note.contains("and retry") && !note.contains("and run it again"),
            "an unconditional retry instruction is the one thing this note must not carry: {note}"
        );

        // A run that finished gains nothing at all.
        assert_eq!(
            told(CommandRun {
                output: "partial output\n".to_string(),
                cut_short: None,
                target_gone: false,
            }),
            "partial output\n"
        );
    }

    /// A cut-short result keeps what it reached and gains the reason — which is the whole point of
    /// interrupting rather than ending the session.
    #[test]
    fn a_cut_short_result_keeps_its_output_and_says_why() {
        let out = cut_short(Ok(Output::text("0x1000  41 42 43\n")))
            .expect("still a result")
            .text;
        assert!(out.starts_with("0x1000  41 42 43"), "{out}");
        assert!(out.contains("interrupted on request"), "{out}");

        // And a failure keeps its debugger text: "this is why it stopped" is not a claim about
        // what it would otherwise have said. It also stops calling itself a *debugger* failure,
        // which is the half a caller acts on rather than reads.
        let err = cut_short(Err(Failed::from("Memory access error"))).expect_err("still a failure");
        assert!(err.message.starts_with("Memory access error"), "{err:?}");
        assert!(err.message.contains("interrupted on request"), "{err:?}");
        assert_eq!(err.category, Some(structured::ErrorCategory::Interrupted));
    }

    /// An operation interrupted before it printed anything still explains itself, rather than
    /// coming back as an empty success the caller would read as "found nothing".
    #[test]
    fn a_cut_short_result_with_no_output_is_still_an_explanation() {
        let out = cut_short(Ok(Output::text(String::new())))
            .expect("still a result")
            .text;
        assert!(out.contains("interrupted on request"), "{out}");
        assert!(
            !out.starts_with('\n'),
            "no blank lead-in when there is nothing above it: {out:?}"
        );
    }

    // ---- rendering a module listing ----------------------------------------

    /// Every row the listing prints, read back out of the text as `(start, name)`.
    ///
    /// The rendering is this server's now, so a test can read it as records rather than matching
    /// substrings — which is the point of [#120] and also what keeps this from repeating the smoke
    /// tier's old mistake of matching the wrong token in a table `lm` had laid out.
    ///
    /// [#120]: https://github.com/glslang/windbg-mcp/issues/120
    fn listed_rows(text: &str) -> Vec<(String, String)> {
        text.lines()
            .filter(|line| line.starts_with("0x"))
            .map(|line| {
                let mut columns = line.split_whitespace();
                let start = columns.next().unwrap_or_default().to_string();
                let _end = columns.next();
                (start, columns.next().unwrap_or_default().to_string())
            })
            .collect()
    }

    /// A listing of three modules and one that has since unloaded, as the engine reports them.
    fn sample_list(filter: Option<&str>) -> structured::ModuleList {
        capped_sample_list(filter, usize::MAX)
    }

    /// The same listing, cut to `limit` rows the way [`modules`] cuts it — through the same
    /// [`split_row_budget`], so the fixture cannot describe a division the tool does not make. The
    /// rows are the head of what matched and the counts are of what matched, which is the pairing
    /// the note and the values both rest on.
    fn capped_sample_list(filter: Option<&str>, limit: usize) -> structured::ModuleList {
        let pdb = |name: &str, base| dbgscope::dbgeng::Module {
            symbols: dbgscope::dbgeng::SymbolKind::Pdb,
            ..module(name, base)
        };
        let loaded = [
            module("ntosext", 0xfffff803_1afe0000),
            module("Ntfs", 0xfffff803_1c770000),
            pdb("nt", 0xfffff803_89200000),
        ];
        let unloaded = [unloaded_module("nvhda64v.sys", 0xfffff803_3d680000)];
        let narrow = |modules: &[dbgscope::dbgeng::Module]| -> Vec<structured::ModuleInfo> {
            modules
                .iter()
                .map(structured::ModuleInfo::from)
                .filter(|module| {
                    filter.is_none_or(|filter| {
                        matches_module_pattern(&module_pattern(filter), module.listed_name())
                    })
                })
                .collect()
        };
        let (matched, matched_unloaded) = (narrow(&loaded), narrow(&unloaded));
        let (for_loaded, for_unloaded) =
            split_row_budget(limit, matched.len(), matched_unloaded.len());
        structured::ModuleList {
            loaded: loaded.len(),
            filter: filter.map(module_pattern),
            matched: matched.len(),
            unloaded_matched: matched_unloaded.len(),
            refresh: None,
            modules: matched.into_iter().take(for_loaded).collect(),
            unloaded: matched_unloaded.into_iter().take(for_unloaded).collect(),
        }
    }

    /// The claim [#120](https://github.com/glslang/windbg-mcp/issues/120) is about: the listing and
    /// the values name **exactly** the same modules.
    ///
    /// Not "every value appears in the text", which is what could be asserted while the text was
    /// `lm`'s and which cannot catch a row the text has and the values do not — the direction all
    /// five of the measured divergences ran in. Read as records and compared as a sequence, so an
    /// extra row, a missing row and a reordered one all fail.
    #[test]
    fn the_listing_names_exactly_the_modules_its_values_do() {
        // Every limit as well as every filter: a cap is a second way for the two halves to end up
        // describing different sets, and it cuts the rows and the values in one place precisely so
        // that it cannot. `0` is in the list because a caller may ask for the counts alone.
        for (filter, limit) in [None, Some("nt"), Some("nvhda"), Some("nosuchmodule")]
            .into_iter()
            .flat_map(|filter| [usize::MAX, 2, 1, 0].map(|limit| (filter, limit)))
        {
            let list = capped_sample_list(filter, limit);
            let expected: Vec<(String, String)> = list
                .modules
                .iter()
                .chain(&list.unloaded)
                .map(|module| (module.start.clone(), module.listed_name().to_string()))
                .collect();
            let text = render_modules(&list);
            assert_eq!(
                listed_rows(&text),
                expected,
                "the rows and the values disagree for `{filter:?}` at limit {limit}:\n{text}"
            );
        }
    }

    /// What the columns carry, and what they do not.
    #[test]
    fn a_rendered_listing_carries_the_addresses_and_the_symbol_state() {
        let text = render_modules(&sample_list(None));
        let mut lines = text.lines();
        assert_eq!(
            lines.next(),
            Some("```"),
            "the table opens its own fenced block — the columns are padded to line up, and that \
             only means anything in a monospaced one:\n{text}"
        );
        assert_eq!(
            lines
                .next()
                .map(|header| header.split_whitespace().collect::<Vec<_>>()),
            Some(vec!["start", "end", "module", "symbols"]),
            "the loaded half is a table with a header:\n{text}"
        );
        assert!(
            text.contains("0xfffff80389200000  0xfffff80389201000  nt       pdb"),
            "one address representation, and the symbol state as its own column:\n{text}"
        );
        assert!(
            text.lines()
                .all(|line| !line.contains("fffff803`") && !line.contains("`89200000")),
            "`lm`'s backtick addresses are not this rendering's:\n{text}"
        );
        assert!(
            text.lines().all(|line| !line.ends_with(' ')),
            "columns are padded for alignment, not for trailing space:\n{text}"
        );
        assert!(
            text.contains("3 module(s) loaded, and 1 that have since **unloaded**"),
            "an unfiltered listing says how big it is, in both halves:\n{text}"
        );
    }

    /// The unloaded half is rendered under its own heading, by the only name it has, and says what
    /// its addresses mean — a row whose `start` is where an image *was* is not a row in the table
    /// above.
    #[test]
    fn the_unloaded_half_is_rendered_as_the_different_thing_it_is() {
        let text = render_modules(&sample_list(Some("nvhda")));
        assert!(
            text.contains("Unloaded modules — `start` and `end` are where the image was"),
            "{text}"
        );
        assert!(
            text.contains("image") && !text.contains("  module  "),
            "its name column is the image's, since an unloaded module has no module name:\n{text}"
        );
        assert!(text.contains("nvhda64v.sys"), "{text}");
        assert!(
            text.contains("1 that have since **unloaded** do"),
            "matching only unloaded modules is a finding, not a miss:\n{text}"
        );

        // A filter that matched nothing at all is the note by itself — no headers over no rows.
        let text = render_modules(&sample_list(Some("nosuchmodule")));
        assert!(
            text.starts_with("Nothing matches `*nosuchmodule*`"),
            "{text}"
        );
        assert!(
            !text.contains("start ") && !text.contains("unloaded"),
            "nothing matched, so there is no table and nothing to say about either half:\n{text}"
        );
    }

    /// A name is never truncated to fit the column, and the column is never narrower than its own
    /// header.
    ///
    /// Truncation would be the one rendering bug that breaks the property above: a row naming a
    /// module the values do not.
    #[test]
    fn the_name_column_is_sized_from_the_names_it_holds() {
        let long = "api_ms_win_core_synch_l1_2_0";
        let list = structured::ModuleList {
            loaded: 2,
            matched: 2,
            filter: None,
            modules: [module(long, 0x1000), module("nt", 0x2000)]
                .iter()
                .map(structured::ModuleInfo::from)
                .collect(),
            unloaded: Vec::new(),
            unloaded_matched: 0,
            refresh: None,
        };
        let text = render_modules(&list);
        assert!(text.contains(long), "a long name is printed whole:\n{text}");
        // The short row's symbol column lines up under the long row's, which is what the width is
        // computed for.
        let column = |name: &str| {
            text.lines()
                .find(|line| line.contains(name))
                .and_then(|line| line.find("deferred"))
        };
        assert_eq!(column(long), column("  nt "), "{text}");
    }

    /// A filter is **quoted into** the listing, so it must not be able to add a line to it.
    ///
    /// The rows and the values agreeing is the property this rendering exists for, and it cannot
    /// be one a caller can undo: a filter carrying a newline followed by something shaped like a
    /// row would put a module in the text that the values beside it do not have. What used to make
    /// that impossible was `reject_command_breakers`, which refused line breaks because the filter
    /// was command text — and it went with the command.
    #[test]
    fn a_filter_cannot_smuggle_a_row_into_the_listing() {
        let listing = |filter: &str| {
            render_modules(&structured::ModuleList {
                loaded: 227,
                matched: 0,
                filter: Some(module_pattern(filter)),
                modules: Vec::new(),
                unloaded: Vec::new(),
                unloaded_matched: 0,
                refresh: None,
            })
        };

        let text = listing("zzz\n0xfffff80389200000  0xfffff8038a650000  smuggled  pdb");
        assert!(
            listed_rows(&text).is_empty(),
            "a filter must not be able to print a row:\n{text}"
        );
        assert_eq!(
            text.lines().count(),
            1,
            "the note is one line, whatever the pattern contains:\n{text}"
        );
        assert!(
            text.contains(r"\n") && text.contains("smuggled"),
            "the newline is shown rather than obeyed, and the pattern is still reported as \
             applied:\n{text}"
        );

        // A carriage return and an ANSI escape go the same way — neither is a line break to
        // `str::lines`, and both are things a terminal acts on.
        let text = listing("nt\r\u{1b}[2J");
        assert_eq!(text.lines().count(), 1, "{text}");
        assert!(
            !text.contains('\r') && !text.contains('\u{1b}'),
            "nothing a terminal acts on reaches it: {text:?}"
        );

        // **The line breaks `char::is_control` does not name.** `U+2028 LINE SEPARATOR` and
        // `U+2029 PARAGRAPH SEPARATOR` are `Zl`/`Zp`, not `Cc`, so the obvious guard lets them
        // through — and `str::lines` does not see them either, so a test written around it passes
        // while a Unicode-aware renderer puts the smuggled row on a line of its own. Asserted on
        // the characters themselves for that reason, not on a line count.
        for separator in ['\u{2028}', '\u{2029}'] {
            let text = listing(&format!(
                "zzz{separator}0xfffff80389200000  0xfffff8038a650000  smuggled  pdb"
            ));
            assert!(
                !text.contains(separator),
                "{separator:?} breaks a line in a renderer that knows Unicode: {text:?}"
            );
            assert!(
                text.contains(r"\u{202"),
                "…and is shown as an escape: {text}"
            );
            assert!(listed_rows(&text).is_empty(), "{text}");
        }

        // **The delimiter itself.** The pattern is quoted in a code span, so a backtick in it ends
        // the span — and everything after it is markup to a client that renders Markdown, `<br>`
        // included, which is a line break no character-level guard would ever see.
        let text = listing("zzz`<br>0xfffff80389200000  0xfffff8038a650000  smuggled  pdb");
        assert!(
            !text.contains("zzz`"),
            "a pattern must not be able to close the span it is quoted in:\n{text}"
        );
        assert!(
            text.contains(r"\u{60}"),
            "…and the backtick is shown: {text}"
        );
        assert!(listed_rows(&text).is_empty(), "{text}");

        // An ordinary pattern is quoted exactly as it was applied — this guard is invisible to
        // every filter anyone actually types.
        assert!(listing("nt[fd]*").contains("`nt[fd]*`"));
    }

    /// A **module name** is the target's to choose, so the same guard covers the rows.
    ///
    /// Windows file names exclude the characters below `0x20` and nothing else, so a driver may
    /// legally be called something carrying a `U+2028` — and a server pointed at malware on
    /// purpose is the last place to assume nobody will. Escaped, not refused: a module named
    /// something hostile still has to be listable, and its row still has to be its row.
    #[test]
    fn a_module_name_cannot_smuggle_a_row_either() {
        let hostile = "drv\u{2028}0xfffff80389200000  0xfffff8038a650000  nt";
        let list = structured::ModuleList {
            loaded: 2,
            matched: 2,
            filter: None,
            modules: [module(hostile, 0x1000), module("nt", 0x2000)]
                .iter()
                .map(structured::ModuleInfo::from)
                .collect(),
            unloaded: Vec::new(),
            unloaded_matched: 0,
            refresh: None,
        };
        let text = render_modules(&list);
        assert_eq!(
            listed_rows(&text).len(),
            2,
            "two records are two rows, whatever they are called:\n{text}"
        );
        assert!(
            !text.contains('\u{2028}'),
            "the separator is escaped rather than printed: {text:?}"
        );

        // The column is measured on what is printed, so the escaped row still lines up — the
        // width and the rendering cannot disagree about the same name.
        let column = |name: &str| {
            text.lines()
                .find(|line| line.contains(name))
                .and_then(|line| line.find("deferred"))
        };
        assert_eq!(column("drv"), column("  nt "), "{text}");
    }

    /// A row's *container*, which is a different question from what a row may contain.
    ///
    /// The escaping above answers "can a name break out of its row". This answers "can a name be
    /// *shown as something else while sitting in it*". `[ntdll.dll](https://elsewhere)` is a legal
    /// Windows file name, and printed with nothing around it a Markdown-rendering client displays
    /// it as `ntdll.dll` — so an analyst reads the wrong name for a module while
    /// `structuredContent` quietly carries the right one. The fence makes every such construct
    /// literal, and takes the whole class rather than a list of metacharacters to keep current.
    ///
    /// Reported by chatgpt-codex-connector on #126.
    #[test]
    fn a_module_name_cannot_be_displayed_as_a_different_one() {
        let hostile = "[ntdll.dll](https://elsewhere)";
        let list = structured::ModuleList {
            loaded: 2,
            matched: 2,
            filter: None,
            modules: [module(hostile, 0x1000), module("nt", 0x2000)]
                .iter()
                .map(structured::ModuleInfo::from)
                .collect(),
            unloaded: Vec::new(),
            unloaded_matched: 0,
            refresh: None,
        };
        let text = render_modules(&list);

        // Verbatim, not escaped: inside a fence the name needs no mangling to be shown as itself,
        // which is the advantage this has over escaping the metacharacters one at a time.
        assert!(
            text.contains(hostile),
            "the name renders exactly as the target spells it:\n{text}"
        );
        assert!(
            fenced_body(&text).is_some_and(|body| body.contains(hostile)),
            "and it is inside the fence, which is what makes that literal:\n{text}"
        );
        assert_eq!(
            listed_rows(&text).len(),
            2,
            "fencing the table must not cost a row:\n{text}"
        );
    }

    /// The fence is only a container while the target cannot close it, and the target names the
    /// rows. A backtick already goes through [`renderable`] for the note's code span — this is the
    /// same guard doing the other job, and the reason [`fenced`] does not repeat it.
    #[test]
    fn a_module_name_cannot_close_the_fence_it_is_printed_in() {
        let hostile = "a```\n```elsewhere";
        let list = structured::ModuleList {
            loaded: 1,
            matched: 1,
            filter: None,
            modules: [module(hostile, 0x1000)]
                .iter()
                .map(structured::ModuleInfo::from)
                .collect(),
            unloaded: Vec::new(),
            unloaded_matched: 0,
            refresh: None,
        };
        let text = render_modules(&list);

        assert_eq!(
            text.matches("```").count(),
            2,
            "exactly one fence opens and one closes it:\n{text}"
        );
        assert_eq!(
            listed_rows(&text).len(),
            1,
            "one record is one row, whatever it is called:\n{text}"
        );
        let body = fenced_body(&text).expect("the block opens and closes");
        assert!(
            !body.contains('`'),
            "no backtick reaches the block at all, so none of it can be a delimiter:\n{body}"
        );
        assert!(
            body.contains("\\u{60}"),
            "the name is still listed, with its backticks shown as escapes:\n{body}"
        );
    }

    /// The rows between the fence markers, or `None` if the block is not opened and closed.
    fn fenced_body(text: &str) -> Option<&str> {
        let (_, rest) = text.split_once("```\n")?;
        let (body, _) = rest.split_once("```")?;
        Some(body)
    }

    /// **The vector bank in disguise.** A default `registers` answer is documented as the integer
    /// registers, and `xmm0/0` is not one — but it is an `Int` the engine does not flag as a
    /// subregister, so it passed until this test existed. Sixty-four of them did, on the sample
    /// the budget table is measured against.
    #[test]
    fn a_default_register_set_is_the_integer_ones_and_not_the_vector_bank() {
        use dbgscope::dbgeng::{Register, RegisterValue as Engine};
        let reg = |name: &str, value, subregister| Register {
            name: name.to_string(),
            value,
            subregister,
        };

        assert!(plain_integer(&reg("rax", Engine::Int(0), false)));
        assert!(plain_integer(&reg("cr3", Engine::Int(0), false)));
        assert!(
            plain_integer(&reg("gdtr", Engine::Int(0), false)),
            "a kernel caller's control and descriptor registers are integer registers"
        );

        assert!(
            !plain_integer(&reg("eax", Engine::Int(0), true)),
            "a view of another register is the engine's own flag to report"
        );
        assert!(
            !plain_integer(&reg("xmm0", Engine::Bytes(vec![0; 16]), false)),
            "a vector register is not a number"
        );
        for slice in ["xmm0/0", "xmm15/3"] {
            assert!(
                !plain_integer(&reg(slice, Engine::Int(0), false)),
                "`{slice}` is a piece of a vector register, whatever the engine calls its value"
            );
        }

        // And `all` is unaffected: it is the caller asking for everything the engine knows, which
        // includes every row this test excludes.
        assert!(
            !plain_integer(&reg("xmm0/0", Engine::Int(0), false)),
            "the rule decides the default only"
        );
    }

    // ---- narrowing a module listing ----------------------------------------

    /// A filtered listing that found nothing prints no rows, so it has to say so itself —
    /// otherwise it is indistinguishable from a target with no modules at all, or from a call
    /// that quietly failed.
    #[test]
    fn a_filter_that_matches_nothing_says_so_rather_than_printing_nothing() {
        let note = narrowing_note("*nosuch*", 0, 227, 0);
        assert!(note.contains("*nosuch*"), "{note}");
        assert!(
            note.contains("227"),
            "the inventory is still a fact worth having: {note}"
        );
        assert!(
            note.contains("ntkrnlmp.exe"),
            "it must name the mistake a caller actually makes — filtering on the image: {note}"
        );

        // And a listing that did match says how much of the table it is showing.
        let note = narrowing_note("*nt*", 3, 227, 0);
        assert!(note.contains("3 of 227"), "{note}");
        // Nothing unloaded matched, so nothing is said about unloaded modules.
        assert!(!note.contains("unloaded"), "{note}");
        assert!(
            !note.contains("ntkrnlmp.exe"),
            "a listing that found what it was asked for is not corrected: {note}"
        );
    }

    /// **A pattern that matches only unloaded modules has found something.** `lm m nvhda*` on this
    /// repo's own sample matches no *loaded* module and twenty-six unloaded `nvhda64v.sys` rows, so
    /// a bare "no module matches" would be denying the listing the caller is looking at — and,
    /// since [`dbgscope::dbgeng::DebugEngine::unloaded_modules`], those rows are values here rather
    /// than text this can only apologise for. The note reports them as a count of what was found.
    #[test]
    fn a_pattern_that_matches_only_unloaded_modules_reports_them_as_matches() {
        let note = narrowing_note("*nvhda*", 0, 227, 26);
        assert!(
            note.contains("26 that have since **unloaded** do"),
            "{note}"
        );
        assert!(
            note.contains("`unloaded` values"),
            "the reader has to be told which field carries them: {note}"
        );
        assert!(
            !note.contains("ntkrnlmp.exe"),
            "twenty-six matches is a find; it must not read as a mistake to correct: {note}"
        );

        // A loaded match and an unloaded one are counted in their own halves.
        let note = narrowing_note("*nt*", 3, 227, 2);
        assert!(
            note.contains("3 of 227 loaded") && note.contains("2 that have since **unloaded**"),
            "{note}"
        );
    }

    /// **The cap does not touch the counts.** A listing cut to `limit` still says how many
    /// matched, and says separately how many rows it printed — the row count quietly becoming the
    /// match count would be #120's disagreement arrived at from the other side, with the text and
    /// the values agreeing with each other and both wrong about the target.
    #[test]
    fn a_listing_cut_by_its_limit_says_so_and_still_counts_what_matched() {
        // Three loaded and one unloaded in a budget of three: the unloaded row keeps its share,
        // and the loaded half takes the rest.
        let list = capped_sample_list(None, 3);
        assert_eq!(
            list.modules.len(),
            2,
            "the rows are the head of what matched"
        );
        assert_eq!(list.matched, 3, "and the count is still of what matched");
        assert_eq!(list.loaded, 3);
        assert_eq!(list.unloaded.len(), 1, "the other half kept its share");

        let text = render_modules(&list);
        assert_eq!(
            listed_rows(&text).len(),
            3,
            "two loaded rows and the unloaded one, which the budget had room for:\n{text}"
        );
        assert!(
            text.contains("3 module(s) loaded"),
            "the inventory is what it always was:\n{text}"
        );
        assert!(
            text.contains("Showing the first 2 loaded row(s)"),
            "and the listing says it is a part of it, naming the half it counted — the unloaded \
             row beside them is in the listing too:\n{text}"
        );
        assert!(
            text.contains("`limit: 4` returns all of them"),
            "…and names the value that would: three loaded rows and one unloaded, so four — not \
             the `3` a reader would take from the count above it:\n{text}"
        );

        // Nothing was cut, so nothing is said about a cut: the note a caller reads on every
        // ordinary filtered call is the one it always was.
        let whole = render_modules(&sample_list(Some("nt")));
        assert!(
            !whole.contains("limit"),
            "an uncut listing says nothing about the cap:\n{whole}"
        );
    }

    /// One budget across both halves, and **neither half may be squeezed out of it** — the same
    /// rule the diagnostics listing keeps, for the same reason: spending the budget in print order
    /// would let a two-hundred-row loaded table erase the unloaded rows, and "no loaded module
    /// matches, but twenty-six unloaded images do" is the whole reason that list is carried.
    #[test]
    fn one_budget_is_shared_between_the_halves_and_each_is_reported_on_its_own() {
        // The shape the rule exists for: far more loaded rows than budget, and a tail a listing
        // that simply printed until it ran out would never reach.
        assert_eq!(
            split_row_budget(64, 213, 26),
            (38, 26),
            "the smaller half whole, the larger half takes the rest — and 64 rows in all"
        );
        assert_eq!(
            split_row_budget(64, 213, 0),
            (64, 0),
            "a listing with nothing unloaded spends the whole budget on the rows it has"
        );

        let cut_tail = structured::ModuleList {
            loaded: 227,
            matched: 1,
            filter: Some(module_pattern("nvhda")),
            modules: [module("nvhda64v", 0x1000)]
                .iter()
                .map(structured::ModuleInfo::from)
                .collect(),
            unloaded: [unloaded_module("nvhda64v.sys", 0x2000)]
                .iter()
                .map(structured::ModuleInfo::from)
                .collect(),
            unloaded_matched: 26,
            refresh: None,
        };
        let text = render_modules(&cut_tail);
        assert!(
            text.contains("26 that have since **unloaded**"),
            "the unloaded count is of what matched, not of what fitted:\n{text}"
        );
        assert!(
            text.contains("Showing the first 1 unloaded row(s)"),
            "and only the half that was cut is reported as cut:\n{text}"
        );

        let both = structured::ModuleList {
            matched: 227,
            ..cut_tail
        };
        let text = render_modules(&both);
        assert!(
            text.contains("Showing the first 1 loaded and 1 unloaded row(s)"),
            "both halves cut is one sentence naming both:\n{text}"
        );
        assert!(
            text.contains("`limit: 253` returns all of them"),
            "and the value that returns everything is both halves' matches, not either one's:\n{text}"
        );
    }

    /// **The number a caller reaches for is the one that falls short**, which is why the note names
    /// the other one. `227 module(s) loaded` is what the line above says, so `limit: 227` is what
    /// gets asked for — and it buys 177 loaded rows and 50 unloaded ones, because the budget is
    /// shared. A local model driving this server did exactly that and had to ask a third time
    /// (`docs/local-model.md`).
    #[test]
    fn the_note_names_the_limit_that_returns_everything_not_the_one_that_falls_short() {
        let listing = |limit: usize| {
            let (for_loaded, for_unloaded) = split_row_budget(limit, 227, 50);
            structured::ModuleList {
                loaded: 227,
                matched: 227,
                unloaded_matched: 50,
                refresh: None,
                filter: None,
                modules: (0..for_loaded)
                    .map(|i| structured::ModuleInfo::from(&module("drv", 0x1000 + i as u64 * 0x10)))
                    .collect(),
                unloaded: (0..for_unloaded)
                    .map(|i| {
                        structured::ModuleInfo::from(&unloaded_module(
                            "gone.sys",
                            0x9000 + i as u64 * 0x10,
                        ))
                    })
                    .collect(),
            }
        };

        // The default page, and the guess it invites.
        let text = render_modules(&listing(64));
        assert!(text.contains("227 module(s) loaded"), "{text}");
        assert!(
            text.contains("`limit: 277` returns all of them"),
            "the whole listing is both halves, so the value is 227 + 50:\n{text}"
        );

        // The guess itself: still short, and still told what would not be.
        let text = render_modules(&listing(227));
        assert!(
            text.contains("Showing the first 177 loaded row(s)"),
            "the count from the line above does not buy the whole table — it buys 177 of the 227 \
             loaded rows, the other 50 of the budget having gone to the unloaded half:\n{text}"
        );
        assert!(text.contains("`limit: 277` returns all of them"), "{text}");

        // And that value does.
        let whole = listing(277);
        assert_eq!(whole.modules.len(), 227);
        assert_eq!(whole.unloaded.len(), 50);
        assert!(
            truncation_note(&whole).is_none(),
            "nothing was cut, so nothing is said about a cut"
        );
    }

    /// The three things a `refresh` can have done, said above the listing rather than under it.
    ///
    /// The ordering is the assertion that matters. A caller reads a `modules` answer top-down and
    /// draws its conclusion from the rows; a caveat about those rows printed beneath them arrives
    /// after the conclusion it was there to prevent — which is exactly how
    /// [#85](https://github.com/glslang/windbg-mcp/issues/85) was read as "the driver is not
    /// loaded" in the first place.
    #[test]
    fn a_refresh_says_what_it_did_before_the_listing_it_qualifies() {
        let listing = |refresh: Option<structured::ModuleRefresh>| {
            render_modules(&structured::ModuleList {
                loaded: 226,
                matched: 0,
                unloaded_matched: 0,
                filter: Some(module_pattern("MessageManager")),
                modules: Vec::new(),
                unloaded: Vec::new(),
                refresh,
            })
        };

        // Not asked for: not one word about it, on every default call.
        let quiet = listing(None);
        assert!(
            !quiet.to_lowercase().contains("resynchronis"),
            "a call that asked for no refresh must not be told about one:\n{quiet}"
        );

        // The case the flag exists for — the fresh-attach inventory, and what it grew to.
        let found = listing(Some(structured::ModuleRefresh {
            synchronized: true,
            before: 1,
            error: None,
        }));
        assert!(
            found.contains("1 module(s) before, 226 now"),
            "the refresh names both counts, which is the evidence it was worth asking for:\n{found}"
        );
        assert!(
            found.contains("deferred"),
            "and warns what it costs, which is the symbol state the engine had:\n{found}"
        );

        // Already current. Worth a line of its own: it is what turns "the module is absent" from
        // a guess into an answer, and a caller cannot otherwise tell it from a refresh that was
        // ignored.
        let current = listing(Some(structured::ModuleRefresh {
            synchronized: true,
            before: 226,
            error: None,
        }));
        assert!(
            current.contains("already held all 226"),
            "a refresh that found nothing new still says it ran:\n{current}"
        );

        // And the failure, which is the only one that may not be quietly believed. It has to be
        // above the note that says nothing matched, or it is advice arriving after the verdict.
        let failed = listing(Some(structured::ModuleRefresh {
            synchronized: false,
            before: 1,
            error: Some("Unable to read PsLoadedModuleList".into()),
        }));
        let (warning, verdict) = (
            failed.find("could not be resynchronised"),
            failed.find("Nothing matches"),
        );
        assert!(
            warning.is_some() && verdict.is_some() && warning < verdict,
            "the caveat has to arrive before the conclusion it qualifies:\n{failed}"
        );
        assert!(
            failed.contains("Unable to read PsLoadedModuleList"),
            "and it carries the engine's own reason:\n{failed}"
        );
        assert!(
            failed.contains("not evidence it is absent from the target"),
            "…and withdraws the only conclusion the listing would otherwise support:\n{failed}"
        );
    }

    /// The engine's failure text is a string from outside this server, and lands in the listing.
    ///
    /// Same rule and same escape as a module name and the caller's own filter: this rendering is
    /// line-oriented and its rows begin with an address, so a reason carrying a line break could
    /// otherwise print a row the values beside it do not have.
    #[test]
    fn a_refresh_failure_cannot_smuggle_a_row_into_the_listing() {
        let text = render_modules(&structured::ModuleList {
            loaded: 1,
            matched: 0,
            unloaded_matched: 0,
            filter: None,
            modules: Vec::new(),
            unloaded: Vec::new(),
            refresh: Some(structured::ModuleRefresh {
                synchronized: false,
                before: 1,
                error: Some(
                    "no\n0xfffff80389200000  0xfffff8038a650000  smuggled  pdb".to_string(),
                ),
            }),
        });
        assert!(
            listed_rows(&text).is_empty(),
            "an engine message must not be able to print a row:\n{text}"
        );
    }

    // ---- rendering a stack -------------------------------------------------

    /// A frame as the two stack tools carry it: an address, and the coordinate where the engine
    /// could place it.
    fn frame(
        index: u32,
        address: &str,
        placed: Option<(&str, &str)>,
        symbol: Option<&str>,
    ) -> structured::FrameInfo {
        structured::FrameInfo {
            index,
            address: address.to_string(),
            module: placed.map(|(module, _)| module.to_string()),
            rva: placed.map(|(_, rva)| rva.to_string()),
            symbol: symbol.map(str::to_string),
            displacement: symbol.map(|_| "0x1c".to_string()),
            attribution_failed: false,
        }
    }

    /// A walk that returned nothing is not an empty answer, and printing nothing would make it
    /// one — indistinguishable from a call that quietly failed. Same reasoning as the empty
    /// module listing above.
    #[test]
    fn a_stack_with_no_frames_says_so_rather_than_printing_nothing() {
        let text = render_backtrace(
            &structured::StackTrace {
                frames: Vec::new(),
                frames_truncated: false,
            },
            32,
        );
        assert!(
            text.contains("No frames") && text.contains("context"),
            "an empty walk has to explain itself: {text}"
        );
    }

    /// The case the whole coordinate exists for: a driver with no PDB resolves no symbol at all,
    /// and the frame is still named — by the offset into its image, which is what an analysis
    /// server can be asked about.
    #[test]
    fn a_frame_with_no_symbol_is_still_named_by_its_image() {
        let text = render_backtrace(
            &structured::StackTrace {
                frames: vec![frame(
                    0,
                    "0xfffff8031afe1654",
                    Some(("MessageManager", "0x1654")),
                    None,
                )],
                frames_truncated: false,
            },
            32,
        );
        assert!(
            text.contains("MessageManager+0x1654"),
            "an unsymbolised frame is `module+RVA` or it is nothing: {text}"
        );
    }

    /// An address in no module at all — a freed pool page, an unloaded driver — is a real finding
    /// rather than a gap, so the line is the address rather than an empty one.
    #[test]
    fn a_frame_in_no_module_prints_its_address() {
        let text = render_backtrace(
            &structured::StackTrace {
                frames: vec![frame(0, "0xffffa30712340000", None, None)],
                frames_truncated: false,
            },
            32,
        );
        assert!(
            text.contains("0xffffa30712340000"),
            "a frame the engine could place in no module still has an address: {text}"
        );
    }

    /// A lookup that **failed** and an address that is genuinely in no module both come back with
    /// no coordinate, and they are opposite facts — the second is a finding (freed pool, unloaded
    /// driver), the first is the engine declining to answer. The line has to say which.
    #[test]
    fn a_failed_attribution_does_not_read_as_an_address_in_no_module() {
        let one = |failed| {
            render_backtrace(
                &structured::StackTrace {
                    frames: vec![structured::FrameInfo {
                        attribution_failed: failed,
                        ..frame(0, "0xffffa30712340000", None, None)
                    }],
                    frames_truncated: false,
                },
                32,
            )
        };
        assert!(
            one(true).contains("lookup failed"),
            "a failed lookup has to say so: {}",
            one(true)
        );
        assert!(
            !one(false).contains("lookup failed"),
            "an address the engine placed in no module is not a failure: {}",
            one(false)
        );
    }

    /// A stack cut off by the cap and a stack that is simply this long are different answers, and
    /// the note is the only place the text says which. Without it a caller reads a truncated walk
    /// as the whole stack — the same mistake the triage cap is walked one frame past to avoid.
    #[test]
    fn a_stack_cut_off_by_the_cap_says_the_cap_is_why() {
        let one = |truncated| {
            render_backtrace(
                &structured::StackTrace {
                    frames: vec![frame(
                        0,
                        "0xfffff80389201234",
                        Some(("nt", "0x1234")),
                        Some("nt!KeBugCheckEx"),
                    )],
                    frames_truncated: truncated,
                },
                1,
            )
        };
        assert!(
            one(true).contains("goes on past") && one(true).contains("`frames`"),
            "a truncated stack has to name the argument that lifts the cap: {}",
            one(true)
        );
        assert!(
            !one(false).contains("goes on past"),
            "a stack that ended on its own must not be reported as capped: {}",
            one(false)
        );
    }

    /// A module or symbol is named by the target, so a frame's line is untrusted text going into a
    /// fence — the same threat [#126](https://github.com/glslang/windbg-mcp/issues/126) fixed for
    /// a module listing, at a call site that did not exist then.
    #[test]
    fn a_frame_name_cannot_close_the_fence_it_is_printed_in() {
        let hostile = "a```\n```elsewhere";
        let text = render_backtrace(
            &structured::StackTrace {
                frames: vec![frame(
                    0,
                    "0xfffff80389201234",
                    Some((hostile, "0x1234")),
                    None,
                )],
                frames_truncated: false,
            },
            32,
        );

        assert_eq!(
            text.matches("```").count(),
            2,
            "exactly one fence opens and one closes it:\n{text}"
        );
        let body = fenced_body(&text).expect("the block opens and closes");
        assert!(
            !body.contains('`'),
            "no backtick reaches the block at all, so none of it can be a delimiter:\n{body}"
        );
        assert_eq!(
            body.lines().count(),
            1,
            "one frame is one line, whatever it is called:\n{body}"
        );
    }

    /// The listing and the records are one answer, as they are for a module listing: every frame
    /// in the values appears in the text, in the walk's order.
    #[test]
    fn the_listing_prints_the_frames_the_records_carry() {
        let trace = structured::StackTrace {
            frames: vec![
                frame(
                    0,
                    "0xfffff80389201234",
                    Some(("nt", "0x1234")),
                    Some("nt!KeBugCheckEx"),
                ),
                frame(
                    1,
                    "0xfffff8031afe1654",
                    Some(("MessageManager", "0x1654")),
                    None,
                ),
                frame(2, "0xffffa30712340000", None, None),
            ],
            frames_truncated: false,
        };
        let text = render_backtrace(&trace, 32);
        let listed: Vec<&str> = text
            .lines()
            .filter(|line| line.len() > 3 && line[..2].chars().all(|c| c.is_ascii_digit()))
            .collect();
        assert_eq!(
            listed.len(),
            trace.frames.len(),
            "one line per frame: {text}"
        );
        assert!(listed[0].contains("nt!KeBugCheckEx"), "{text}");
        assert!(listed[1].contains("MessageManager+0x1654"), "{text}");
        assert!(listed[2].contains("0xffffa30712340000"), "{text}");
        assert!(
            text.contains("3 frames"),
            "the count is the reader's check: {text}"
        );
    }

    // ---- rendering a disassembly -------------------------------------------

    fn instruction(address: &str, rva: Option<&str>, text: &str) -> structured::InstructionInfo {
        structured::InstructionInfo {
            address: address.to_string(),
            module: rva.map(|_| "nt".to_string()),
            rva: rva.map(str::to_string),
            attribution_failed: false,
            bytes: "48895c2408".to_string(),
            text: text.to_string(),
        }
    }

    fn disassembly(
        instructions: Vec<structured::InstructionInfo>,
        stopped_early: bool,
    ) -> structured::Disassembly {
        structured::Disassembly {
            start: "0xfffff8013c65bca8".to_string(),
            instructions,
            stopped_early,
        }
    }

    /// The debugger's own address form is a backtick between two halves, and an operand is full of
    /// them. Left in, every such operand renders as an escape once the line is made safe for the
    /// fence it goes in — so the tick comes out where it is punctuation.
    #[test]
    fn an_address_in_an_operand_loses_the_debuggers_backtick() {
        assert_eq!(
            plain_addresses("bl nt!KiSaveProcessorControlState (fffff801`3c677ef0)"),
            "bl nt!KiSaveProcessorControlState (fffff8013c677ef0)"
        );
    }

    /// And nowhere else. MSVC decorates real symbols with backticks, and a blanket strip would
    /// quietly rename them — the same class of mistake as reading a module name as markup.
    #[test]
    fn a_backtick_that_is_part_of_a_symbol_is_left_alone() {
        for text in [
            "call `anonymous namespace'::Handler",
            "mov rax,qword ptr [nt!Foo::`vftable']",
            // Not eight digits either side, so not the address form.
            "add rax,dead`beef",
        ] {
            assert_eq!(plain_addresses(text), text, "{text}");
        }
    }

    /// The coordinate is the first column, because it is the column an analysis server is asked
    /// about; the absolute address is in the values and the heading.
    #[test]
    fn the_listing_leads_with_the_offset_into_the_image() {
        let text = render_disassembly(&disassembly(
            vec![instruction(
                "0xfffff8013c65bca8",
                Some("0x25bca8"),
                "add x0,x22,#0x40",
            )],
            false,
        ));
        let row = text
            .lines()
            .find(|line| line.contains("add x0"))
            .unwrap_or_else(|| panic!("no instruction row:\n{text}"));
        assert!(row.starts_with("nt+0x25bca8"), "{row}");
        assert!(
            text.contains("in `nt`"),
            "the range names its image once: {text}"
        );
    }

    /// Running out of code and running out of budget are different answers, and only one of them
    /// means "ask again for more".
    #[test]
    fn code_that_ends_early_says_it_ended_rather_than_that_it_was_cut() {
        let ended = render_disassembly(&disassembly(
            vec![instruction("0xfffff8013c65bca8", Some("0x25bca8"), "ret")],
            true,
        ));
        assert!(ended.contains("could not be disassembled"), "{ended}");
        assert!(
            ended.contains("same instructions"),
            "asking again has to be described as pointless, not offered: {ended}"
        );
    }

    /// Nothing at all is an answer about the address, not a failure of the call.
    #[test]
    fn an_address_that_disassembles_to_nothing_explains_itself() {
        let text = render_disassembly(&disassembly(Vec::new(), false));
        assert!(text.contains("No instructions"), "{text}");
        assert!(
            text.contains("0xfffff8013c65bca8"),
            "and names the address: {text}"
        );
    }

    /// A range can run off the end of one image into another, and each instruction says which it
    /// is in. The answer used to name the image once and let the rest inherit it, which was
    /// smaller and could not express the two rows below.
    #[test]
    fn each_instruction_names_the_image_it_is_actually_in() {
        let mut second = instruction("0xfffff8013c65bcac", Some("0x20"), "ret");
        second.module = Some("MessageManager".to_string());
        let text = render_disassembly(&disassembly(
            vec![
                instruction("0xfffff8013c65bca8", Some("0x25bca8"), "nop"),
                second,
            ],
            false,
        ));
        assert!(text.contains("nt+0x25bca8"), "{text}");
        assert!(text.contains("MessageManager+0x20"), "{text}");
    }

    /// An instruction in **no** module is the row the inheritance rule got wrong: it has nothing
    /// to inherit, and crediting it to the image around it is a claim about where code lives.
    #[test]
    fn an_instruction_in_no_module_is_not_credited_to_its_neighbours_image() {
        let loose = instruction("0xffffa30712340000", None, "nop");
        let text = render_disassembly(&disassembly(
            vec![
                instruction("0xfffff8013c65bca8", Some("0x25bca8"), "nop"),
                loose,
            ],
            false,
        ));
        let row = text
            .lines()
            .find(|line| line.contains("0xffffa30712340000"))
            .unwrap_or_else(|| panic!("no row for the unattributed instruction:\n{text}"));
        assert!(
            !row.contains("nt+"),
            "an address in no module is not an offset into the module beside it: {row}"
        );
    }

    /// And a lookup that failed says so rather than looking like the row above.
    #[test]
    fn an_instruction_whose_lookup_failed_says_so() {
        let mut failed = instruction("0xffffa30712340000", None, "nop");
        failed.attribution_failed = true;
        let text = render_disassembly(&disassembly(vec![failed], false));
        assert!(text.contains("lookup failed"), "{text}");
    }

    /// The row says the lookup failed; the sentence under it must not say the address is in no
    /// module. They are the two readings the flag exists to keep apart, and one answer cannot
    /// carry both.
    #[test]
    fn the_summary_does_not_call_a_failed_lookup_an_address_in_no_module() {
        let mut failed = instruction("0xffffa30712340000", None, "nop");
        failed.attribution_failed = true;
        let text = render_disassembly(&disassembly(vec![failed], false));
        assert!(
            !text.contains("in no loaded module"),
            "a lookup that did not answer is not a finding about the target:\n{text}"
        );
        assert!(text.contains("could not name"), "{text}");
    }

    /// The summary sentence is outside the fence that protects the rows, and it quotes a module
    /// The summary sentence is outside the fence that protects the rows, and it quotes a module
    /// name read out of the target — the same construct `summary_text` already escapes.
    #[test]
    fn a_module_name_cannot_escape_the_summary_sentence() {
        let mut hostile = instruction("0xfffff8013c65bca8", Some("0x25bca8"), "nop");
        hostile.module = Some("a`b".to_string());
        let text = render_disassembly(&disassembly(vec![hostile], false));
        let summary = text
            .rsplit("```")
            .next()
            .expect("the summary follows the fence");
        assert!(
            !summary.contains('`') || summary.matches('`').count() == 2,
            "the name must not add a backtick of its own to the sentence: {summary}"
        );
        assert!(
            summary.contains("\\u{60}"),
            "it is shown as an escape: {summary}"
        );
    }

    /// An operand carries symbol names out of the image, so the same fence threat as a module
    /// An operand carries symbol names out of the image, so the same fence threat as a module
    /// name's ([#126]) — at a third call site.
    ///
    /// [#126]: https://github.com/glslang/windbg-mcp/issues/126
    #[test]
    fn an_instruction_cannot_close_the_fence_it_is_printed_in() {
        let text = render_disassembly(&disassembly(
            vec![instruction(
                "0xfffff8013c65bca8",
                Some("0x25bca8"),
                "call a```\n```elsewhere",
            )],
            false,
        ));
        assert_eq!(
            text.matches("```").count(),
            2,
            "exactly one fence opens and one closes it:\n{text}"
        );
        let body = fenced_body(&text).expect("the block opens and closes");
        assert!(
            !body.contains('`'),
            "no backtick reaches the block:\n{body}"
        );
    }

    // ---- what an opener says about the target (#105) ------------------------

    fn module(name: &str, base: u64) -> dbgscope::dbgeng::Module {
        dbgscope::dbgeng::Module {
            base,
            size: 0x1000,
            name: name.to_string(),
            image_name: format!("{name}.sys"),
            loaded_image_name: String::new(),
            timestamp: 0,
            checksum: 0,
            symbols: dbgscope::dbgeng::SymbolKind::Deferred,
            user_mode: false,
            unloaded: false,
        }
    }

    /// An unloaded module as the engine really reports one: **no module name**, only the image's,
    /// which the kernel has truncated to twelve characters (glslang/dbgscope#101).
    fn unloaded_module(image: &str, base: u64) -> dbgscope::dbgeng::Module {
        dbgscope::dbgeng::Module {
            name: String::new(),
            image_name: image.to_string(),
            symbols: dbgscope::dbgeng::SymbolKind::None,
            unloaded: true,
            ..module("", base)
        }
    }

    /// A filter has to match an unloaded module by the only name it has — which is also the name
    /// the listing prints for it.
    ///
    /// Testing `name` alone would match nothing for every row in that half of the list, while the
    /// rows themselves showed the image name they were listed under.
    #[test]
    fn an_unloaded_module_is_matched_by_its_image_name() {
        let gone =
            structured::ModuleInfo::from(&unloaded_module("nvhda64v.sys", 0xfffff803_3d680000));
        assert_eq!(gone.listed_name(), "nvhda64v.sys");
        assert!(matches_module_pattern(
            &module_pattern("nvhda"),
            gone.listed_name()
        ));

        // A loaded module is still listed by its module name, not its image.
        assert_eq!(
            structured::ModuleInfo::from(&module("nt", 0x1000)).listed_name(),
            "nt"
        );
    }

    fn summary_of(modules: &[dbgscope::dbgeng::Module], kernel: bool) -> structured::TargetSummary {
        structured::TargetSummary {
            kernel_mode: Some(kernel),
            modules_loaded: Some(modules.len()),
            primary_module: primary_module(modules, Some(kernel))
                .map(|module| Box::new(structured::ModuleInfo::from(module))),
            bug_check: None,
            limitation: None,
        }
    }

    /// The kernel is the image a kernel target is about, wherever the engine happens to list it.
    ///
    /// Position is the tempting test — `nt` is first on every kernel target this has been run
    /// against — and it is the one that would quietly name a driver on the target where it is not.
    #[test]
    fn a_kernel_targets_primary_module_is_the_kernel_by_name() {
        let modules = [
            module("MessageManager", 0xfffff8000f000000),
            module("nt", 0xfffff80312000000),
        ];
        let picked = primary_module(&modules, Some(true)).expect("a kernel target has a kernel");
        assert_eq!(picked.name, "nt");

        // The same list read as user mode is load order, which is that process's own image.
        let picked =
            primary_module(&modules, Some(false)).expect("a user-mode target has an image");
        assert_eq!(picked.name, "MessageManager");

        // And a target with nothing loaded has no primary module rather than a made-up one.
        assert!(primary_module(&[], Some(true)).is_none());
    }

    /// The diagnostic is the answer; the summary is a couple of lines under it.
    ///
    /// The measurement that matters is the one in the issue: what an opener emits must be a
    /// summary rather than the whole module table `open_dump` used to print — 227 lines on this
    /// repo's own sample dump ([#105](https://github.com/glslang/windbg-mcp/issues/105)). So this
    /// asserts a *bound* on what the summary adds, not merely that it says something.
    #[test]
    fn an_open_summary_adds_a_couple_of_lines_to_the_diagnostic() {
        let modules: Vec<_> = (0..233)
            .map(|i| module(&format!("mod{i}"), 0x1000 * i))
            .collect();
        let diagnostic = "Windows 10 Kernel Version 26100 MP (4 procs) Free x64\n\
                          Kernel base = 0xfffff803`12000000 PsLoadedModuleList = 0xfffff803`12c33cf0";
        let mut summary = summary_of(&modules, true);
        summary.primary_module = primary_module(&[module("nt", 0xfffff80312000000)], Some(true))
            .map(|module| Box::new(structured::ModuleInfo::from(module)));

        let text = summary_text(diagnostic, &summary);
        assert!(
            text.starts_with(diagnostic),
            "the diagnostic is the answer and stays first:\n{text}"
        );
        assert!(
            text.lines().count() <= diagnostic.lines().count() + 3,
            "233 modules must not become 233 lines again:\n{text}"
        );
        assert!(text.contains("233 module(s) loaded"), "{text}");
        // Quoted, because the name is the target's: see `a_primary_module_cannot_rename_itself`.
        assert!(text.contains("`nt` at 0xfffff80312000000"), "{text}");
        // The pointer to `modules` is the *server's* to add, and only for a surface that serves
        // it: see `SUMMARY_NOTES`. What the worker owes is the count, which is the fact.
        assert!(
            !text.contains("`modules`"),
            "a worker knows no surface, so it names no tool: {text}"
        );
    }

    /// The summary names the target's own image, in a sentence, and the name is the target's.
    ///
    /// The rows solved this with a fence; a sentence cannot carry one, so it carries a code span
    /// instead — which renders its contents literally, and whose only delimiter [`renderable`]
    /// already escapes. Without it the opener's first line names a module that is not the one it
    /// opened: `[ntdll](https://elsewhere)` displays as `ntdll`, and this line is the one thing a
    /// reader takes from an open without calling anything else.
    #[test]
    fn a_primary_module_cannot_rename_itself_in_the_summary() {
        let hostile = "[ntdll](https://elsewhere)";
        let mut summary = summary_of(&[module(hostile, 0x1000)], true);
        summary.primary_module = primary_module(&[module(hostile, 0x1000)], Some(true))
            .map(|module| Box::new(structured::ModuleInfo::from(module)));

        let text = summary_text("", &summary);
        assert!(
            text.contains(&format!("`{hostile}`")),
            "the name is quoted whole, so the span is what renders and not a link:\n{text}"
        );

        // And the span cannot be closed from inside it, which is the only way out of one.
        let breaker = "nt`x`y";
        summary.primary_module = primary_module(&[module(breaker, 0x1000)], Some(true))
            .map(|module| Box::new(structured::ModuleInfo::from(module)));
        let text = summary_text("", &summary);
        assert_eq!(
            text.matches('`').count() % 2,
            0,
            "every span opened in the line is closed:\n{text}"
        );
        assert!(
            !text.contains("nt`x`y"),
            "the name's own backticks are escaped rather than printed:\n{text}"
        );
    }

    /// A dump that stopped on a bug check says which one, and where the rest of it is.
    #[test]
    fn a_bug_check_is_named_where_a_dump_is_opened() {
        let mut summary = summary_of(&[module("nt", 0xfffff80312000000)], true);
        summary.bug_check = Some(triage::bug_check_info(&dbgscope::dbgeng::BugCheck {
            code: 0x9f,
            parameters: [3, 0xffffe284ffe59060, 0, 0],
        }));

        let text = summary_text("Windows 10 Kernel Version 26100 MP", &summary);
        assert!(text.contains("0x9f DRIVER_POWER_STATE_FAILURE"), "{text}");
        assert!(
            text.contains("0xffffe284ffe59060"),
            "the parameters are the half a caller reads first: {text}"
        );
        assert!(
            !text.contains("crash_triage"),
            "the pointer to it is the server's, which alone knows the surface: {text}"
        );
    }

    /// Nothing read, nothing claimed. A summary whose every field is absent leaves the diagnostic
    /// exactly as the engine printed it — an open that worked must not grow a line saying the
    /// bookkeeping around it did not.
    #[test]
    fn a_summary_that_read_nothing_leaves_the_diagnostic_alone() {
        let diagnostic = "Windows 10 Kernel Version 26100 MP";
        assert_eq!(
            summary_text(diagnostic, &structured::TargetSummary::default()),
            diagnostic
        );
        // And a target that simply did not bug check says nothing about bug checks.
        let text = summary_text(diagnostic, &summary_of(&[module("nt", 0x1000)], true));
        assert!(!text.contains("Bug check"), "{text}");
    }

    // ---- the pool walk budget (#75) ----------------------------------------

    /// A pool walk is bounded by the *caller's* deadline, not by dbgscope's default.
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
    /// the work would not even leave a cache behind — dbgscope caches complete snapshots only, so a
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
        assert!(PoolOp::find_tag("Tgsm".into(), None, Some(true), None, None).refreshes());
        assert!(PoolOp::chunk("0x1000".into(), Some(true)).refreshes());
        assert!(PoolOp::diagnostics(None, Some(true), None).refreshes());

        // The default, and the reason the distinction is worth making at all.
        assert!(!PoolOp::census(None, None).refreshes());
        assert!(!PoolOp::chunk("0x1000".into(), Some(false)).refreshes());

        assert!(HeapOp::list(Some(true)).refreshes());
        assert!(HeapOp::chunk("0x1000".into(), Some(true)).refreshes());
        assert!(!HeapOp::census(None, None, None).refreshes());
        assert!(!HeapOp::diagnostics(None, None, Some(false), None).refreshes());
    }

    /// A host that *can* replay says only what the debugger said.
    ///
    /// The point of the split is that the note is evidence-bearing: appending it to every failed
    /// `open_trace` would make it noise, and would misdirect the one caller whose path really is
    /// wrong on a properly bundled host.
    #[test]
    fn a_bundled_host_reports_the_engines_own_failure_and_nothing_else() {
        let engine = "trace load failed: 0x80070057".to_string();
        assert_eq!(explain_trace_failure(engine.clone(), true), engine);
    }

    /// A host that cannot replay at all says so, and names the directory to copy.
    ///
    /// `0x80070057` is "the parameter is incorrect", which on this path is a lie of omission: the
    /// parameter is fine and the engine simply has no replay DLLs. A reader who takes the error at
    /// face value edits the one thing that was never wrong ([#132]).
    ///
    /// [#132]: https://github.com/glslang/windbg-mcp/issues/132
    #[test]
    fn a_host_with_no_replay_engine_says_so_rather_than_leaving_the_error_bare() {
        let explained = explain_trace_failure("trace load failed: 0x80070057".to_string(), false);

        assert!(
            explained.starts_with("trace load failed: 0x80070057"),
            "the engine's own words stay first; the note is added to them, not substituted for \
             them: {explained}"
        );
        assert!(
            explained.contains("ttd\\"),
            "it names the directory to copy: {explained}"
        );
    }

    /// A settle that failed is three different situations, and only one of them is an error.
    ///
    /// [`DebugEngine::settle`] asks whether the engine was left running *and* pumps it, behind one
    /// `Result`. Folding both into "log it and hand back the command's answer" reports
    /// `status: "ok"` on a session whose next execution-control call cannot work — which is the
    /// bug this whole settle exists to prevent, arriving through the recovery for it.
    #[test]
    fn a_failed_settle_is_read_from_what_the_engine_says_afterwards() {
        let damaged = settle_verdict(Ok(true), "the pump timed out");
        let SettleVerdict::Damaged(said) = &damaged else {
            panic!("an engine that is still running is a damaged session: {damaged:?}")
        };
        assert!(said.contains("the pump timed out"), "{said}");

        assert_eq!(
            settle_verdict(Ok(false), "the pump timed out"),
            SettleVerdict::Fine,
            "an engine that is stopped is a session that is fine, whatever failed on the way"
        );

        let unknown = settle_verdict(Err("no current process".to_string()), "the pump timed out");
        let SettleVerdict::Unknown(note) = &unknown else {
            panic!("an engine that cannot be asked is not a verdict: {unknown:?}")
        };
        // Both reasons, because either alone reads as the whole story.
        assert!(note.contains("the pump timed out"), "{note}");
        assert!(note.contains("no current process"), "{note}");
    }

    /// And the command's output survives all three, including the branch that becomes an error.
    ///
    /// The one copy of it is in the value being turned into a message, so a caller whose session is
    /// damaged would otherwise be told that and nothing about what they ran.
    #[test]
    fn a_settle_verdict_never_swallows_what_the_command_printed() {
        let ran = || {
            Ok(CommandRun {
                output: "0:000> the command said this".to_string(),
                cut_short: None,
                target_gone: false,
            })
        };

        let damaged = settled_or(SettleVerdict::Damaged("still running".into()), ran())
            .expect_err("a damaged session is an error");
        assert!(damaged.contains("still running"), "{damaged}");
        assert!(damaged.contains("the command said this"), "{damaged}");

        let fine = settled_or(SettleVerdict::Fine, ran()).expect("a fine session is not an error");
        assert_eq!(fine.output, "0:000> the command said this");

        let unknown = settled_or(SettleVerdict::Unknown("cannot say".into()), ran())
            .expect("not knowing is not the command failing");
        assert!(
            unknown.output.contains("the command said this"),
            "{unknown:?}"
        );
        assert!(unknown.output.contains("cannot say"), "{unknown:?}");

        // And when the command itself failed, both facts reach the caller through the one channel
        // an error has.
        let both = settled_or(
            SettleVerdict::Unknown("cannot say".into()),
            Err("the command failed".to_string()),
        )
        .expect_err("a failed command stays failed");
        assert!(both.contains("the command failed"), "{both}");
        assert!(both.contains("cannot say"), "{both}");
    }

    /// And it claims only what it can know.
    ///
    /// The probe answers "can this host replay at all", which is a fact about the *host* — it is
    /// no evidence about why this particular open failed. On a host with no `ttd\`, a genuinely
    /// mistyped path fails for its own reason and gets this note too, so a note that asserted the
    /// path was fine would be confidently wrong exactly when the caller most needs it right.
    #[test]
    fn the_note_does_not_pronounce_on_a_failure_it_cannot_see() {
        let explained =
            explain_trace_failure("trace load failed: file not found".to_string(), false);

        assert!(
            explained.contains("whatever this error turns out to be"),
            "it is explicit that it has not diagnosed this failure: {explained}"
        );
        assert!(
            explained.contains("If the path is right"),
            "and conditions the conclusion on the one thing it cannot check: {explained}"
        );
        assert!(
            !explained.contains("Nothing about the trace or the path needs changing"),
            "never the unconditional claim, which a mistyped path would falsify: {explained}"
        );
    }

    /// **A load wait that did not load is a failure**, which is what the wait answering a value
    /// rather than `Result<(), _>` bought (dbgscope#136).
    ///
    /// The gap this closes was structural rather than an oversight: `S_FALSE` and `S_OK` were one
    /// `Ok(())`, so an opener could not tell a dump that finished loading from one still loading
    /// at the bound, and reported both as an open that worked. The commit above the wait was
    /// already placed for this — the target exists, so the recovery is `end_session` and not
    /// another open — and the two comments saying so predate any code that could reach it.
    ///
    /// Asserted as a mapping, because that is the whole of what this host can check: holding a
    /// real dump load past sixty seconds is not something a test can arrange. So the `Expired` arm
    /// is unmeasured against a real engine, and says so where it is defined.
    #[test]
    fn a_load_that_did_not_finish_is_not_an_open_that_worked() {
        assert!(
            load_completed(WaitOutcome::Stopped { process: None }, "dump").is_ok(),
            "a load that stopped on its target is the one outcome that finished it"
        );

        let expired = load_completed(WaitOutcome::Expired, "dump")
            .expect_err("a bound that passed with the load still going is not a finished load");
        assert!(
            expired.contains("end_session"),
            "the advice names the recovery for a target the session already holds: {expired}"
        );
        assert!(
            expired.contains(&LOAD_WAIT_MS.to_string()),
            "and says what bound it was measured against, or the number is folklore: {expired}"
        );

        // Both breaks, because the reason is that the load did not finish and not which origin
        // stopped it -- and the `Deadline` arm is unreachable on a finite bound, so this is the
        // only place it is exercised at all.
        for broke_in in [WaitOutcome::OnRequest, WaitOutcome::Deadline] {
            let interrupted = load_completed(broke_in, "trace").unwrap_err();
            assert!(
                interrupted.contains("trace") && interrupted.contains("end_session"),
                "{broke_in:?} names the target it left half-open and the recovery: {interrupted}"
            );
        }
    }
}
