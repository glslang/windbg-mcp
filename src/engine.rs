//! The dedicated DbgEng worker thread.
//!
//! DbgEng requires single-threaded, serialized access (and `WaitForEvent` must run
//! on the session-owning thread). We therefore confine the [`DebugEngine`] to one
//! OS thread and marshal every operation onto it over a channel, returning results
//! to the async (rmcp/tokio) side via oneshot replies.

use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::thread;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, oneshot};
use win_kexp::dbgeng::DebugEngine;

/// What a job closure returns: `Ok(text)` or `Err(message)`. Jobs describe debugger work,
/// so a plain message is all they can meaningfully report.
type Reply = Result<String, String>;

/// What travels back over the reply channel. The worker classifies each outcome at the
/// point it knows the difference — an operation that failed versus an engine that was
/// never usable — because that distinction is unrecoverable once it reaches the caller.
type Classified = Result<String, EngineError>;

/// Why an engine call failed, split by who can act on the failure.
///
/// The MCP tool spec draws exactly this line: failures the model can see and
/// self-correct from belong in the tool *result* (`isError: true`), while failures
/// of the server machinery belong in a JSON-RPC error. Keeping the two apart here
/// lets [`crate::server`] render each one the right way instead of collapsing every
/// debugger hiccup into an opaque protocol error the model never really sees.
#[derive(Debug)]
pub enum EngineError {
    /// The debugger ran the operation and it failed — an unresolvable symbol, an
    /// unreadable address, a command error, a target that never stopped. Actionable:
    /// the model can adjust its arguments and retry.
    Debugger(String),
    /// The call outlived its budget. Reported to the model exactly like [`Self::Debugger`],
    /// but kept separate because it means something the caller must know: the job was
    /// abandoned by the *waiter*, not by the engine, so it may still be running and may
    /// still succeed. Anything whose retry has side effects has to say so.
    Timeout(String),
    /// The engine itself is unusable — the worker thread is gone or dropped the reply.
    /// Nothing the model can do about it.
    Unavailable(String),
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Debugger(m) | Self::Timeout(m) | Self::Unavailable(m) => f.write_str(m),
        }
    }
}

/// How much of the call budget the watchdog leaves for itself: it Ctrl+Breaks the engine this
/// long before the caller's wait expires, so the interrupt has time to land, `Execute` has time
/// to unwind, and the *engine thread* is free again before the tool call reports its timeout.
const WATCHDOG_HEADROOM: Duration = Duration::from_secs(15);

/// The watchdog deadline for a command that waited `queued_wait` in the engine queue, given the
/// caller's total `call_timeout`.
///
/// The outer timeout in [`EngineHandle::run`] starts counting at *submission*, but a command may
/// sit behind another job (e.g. a backgrounded `go`) before reaching the worker. Budgeting from
/// the time *remaining* — not the full `call_timeout` — is what makes the interrupt fire before
/// the caller gives up regardless of queue wait.
///
/// Floored at [`WATCHDOG_HEADROOM`] rather than allowed to reach zero, because zero *disables*
/// win-kexp's watchdog: a command dequeued at or past the deadline would then be the one command
/// that runs unbounded, which is exactly the wedge case. The floor overruns the caller's timeout
/// by design — the caller has already given up by then, and freeing the engine 15s late still
/// beats never.
fn watchdog_budget_ms(call_timeout: Duration, queued_wait: Duration) -> u32 {
    call_timeout
        .saturating_sub(queued_wait)
        .saturating_sub(WATCHDOG_HEADROOM)
        .max(WATCHDOG_HEADROOM)
        .as_millis()
        .min(u32::MAX as u128) as u32
}

/// A unit of work to run on the engine thread, plus where to send its result.
struct Job {
    run: Box<dyn FnOnce(&DebugEngine) -> Reply + Send>,
    reply: oneshot::Sender<Classified>,
}

/// Cloneable handle to the engine thread, shared across all tool calls.
#[derive(Clone)]
pub struct EngineHandle {
    tx: mpsc::UnboundedSender<Job>,
    call_timeout: Duration,
}

impl EngineHandle {
    /// Spawns the worker thread. The [`DebugEngine`] is created on, and never leaves,
    /// that thread.
    pub fn spawn(call_timeout: Duration) -> Self {
        let (tx, mut rx) = mpsc::unbounded_channel::<Job>();
        thread::Builder::new()
            .name("dbgeng".into())
            .spawn(move || {
                // `DebugEngine::new()` panics if the engine can't be created (e.g.
                // dbgeng.dll is not discoverable); convert that into failed calls
                // instead of tearing down the process.
                let engine = match catch_unwind(AssertUnwindSafe(DebugEngine::new)) {
                    Ok(engine) => engine,
                    Err(_) => {
                        // The engine never came up, and never will for this process. That is
                        // `Unavailable`, not a failed operation: no argument the model can
                        // change makes the next call work, so it must not come back as a
                        // retryable tool error.
                        while let Some(job) = rx.blocking_recv() {
                            let _ = job.reply.send(Err(EngineError::Unavailable(
                                "failed to initialize DbgEng (is dbgeng.dll on the search path?)"
                                    .to_string(),
                            )));
                        }
                        return;
                    }
                };
                while let Some(job) = rx.blocking_recv() {
                    // A panic inside a win-kexp method (several use `.expect`) must not
                    // kill the worker — surface it as an error for this one call. The engine
                    // survives, so this stays a debugger-level failure the model can work
                    // around by trying something else.
                    let result = catch_unwind(AssertUnwindSafe(|| (job.run)(&engine)))
                        .unwrap_or_else(|_| Err("debugger operation panicked".to_string()));
                    let _ = job.reply.send(result.map_err(EngineError::Debugger));
                }
            })
            .expect("failed to spawn dbgeng thread");
        Self { tx, call_timeout }
    }

    /// Runs `f` on the engine thread, awaiting the result with the configured timeout.
    pub async fn run<F>(&self, f: F) -> Result<String, EngineError>
    where
        F: FnOnce(&DebugEngine) -> Reply + Send + 'static,
    {
        let (rtx, rrx) = oneshot::channel();
        self.tx
            .send(Job {
                run: Box::new(f),
                reply: rtx,
            })
            .map_err(|_| EngineError::Unavailable("engine thread unavailable".to_string()))?;
        match tokio::time::timeout(self.call_timeout, rrx).await {
            // Already classified by the worker, which is the only place that can tell a
            // failed operation apart from an engine that never initialized.
            Ok(Ok(classified)) => classified,
            Ok(Err(_)) => Err(EngineError::Unavailable("engine dropped reply".to_string())),
            // A timeout is an operational outcome, not broken plumbing: the target may
            // simply still be running, and the model can wait, retry, or end the session.
            // Note the job itself is *not* cancelled — only this wait for it is.
            Err(_) => Err(EngineError::Timeout(
                "engine call timed out (the target may still be running)".to_string(),
            )),
        }
    }

    /// Runs a raw debugger command **bounded** by an engine-side watchdog. If the command
    /// runs longer than the call budget, win-kexp's `execute_command_bounded` Ctrl+Breaks the
    /// engine so it aborts and frees the thread — instead of a runaway command (most importantly
    /// an unbounded `s` memory search) pinning the single engine thread and wedging every later
    /// call.
    ///
    /// **Which tools use this** is a deliberate split, not an oversight — see `DECISIONS.md`
    /// (2026-08-02). Route a tool here when its cost scales with the *target's size* or with an
    /// *arbitrary caller-supplied expression*: `execute` and `dx` (open-ended hatches) and the
    /// `ttd_*` wrappers (whole-trace scans). Point queries against current target state — `k`,
    /// `lm`, `~`, `u`, `!drvobj`, `!devobj`, `!irp`, `bp` — keep [`Self::run`], because arming
    /// the watchdog rounds a command's duration up to a multiple of 200ms (measured; win-kexp
    /// joins a 200ms poll loop), so a 30ms query would become a 200ms one for a runaway case
    /// it does not have.
    ///
    /// `precheck` runs **on the engine thread**, immediately before the command and after any
    /// job queued ahead of it. Callers use it for gates that must not be evaluated while
    /// earlier work is still in flight — see [`crate::server`]'s session handles.
    pub async fn run_command<P>(&self, command: String, precheck: P) -> Result<String, EngineError>
    where
        P: FnOnce() -> Result<(), String> + Send + 'static,
    {
        let call_timeout = self.call_timeout;
        let submitted = Instant::now();
        self.run(move |e| {
            precheck()?;
            // `submitted.elapsed()`, evaluated here on the engine thread, is the queue wait —
            // see [`watchdog_budget_ms`] for why the budget is computed from what remains.
            let budget_ms = watchdog_budget_ms(call_timeout, submitted.elapsed());
            e.execute_command_bounded(&command, budget_ms)
                .map_err(|e| e.to_string())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- the watchdog budget (pure) -----------------------------------------------

    /// The everyday case: nothing queued ahead, so the watchdog fires one headroom before the
    /// caller's wait expires. This is the number that keeps a runaway command from outliving
    /// the tool call that started it.
    #[test]
    fn an_unqueued_command_is_bounded_one_headroom_short_of_the_call_timeout() {
        let timeout = Duration::from_secs(300);
        assert_eq!(
            watchdog_budget_ms(timeout, Duration::ZERO),
            (300 - 15) * 1000
        );
    }

    /// The property the queue-awareness exists for, stated as the invariant rather than as an
    /// arithmetic identity: **queue wait + watchdog budget must not exceed the caller's
    /// timeout**, or the caller gives up while the command is still running — the wedge.
    ///
    /// Budgeting from the full `call_timeout` (ignoring the wait) breaks this for every
    /// non-zero wait, which is why it is checked across a spread rather than at one point.
    #[test]
    fn a_queued_command_still_aborts_before_its_caller_gives_up() {
        let timeout = Duration::from_secs(300);
        for waited in [0, 1, 30, 100, 240, 269] {
            let waited = Duration::from_secs(waited);
            let budget = Duration::from_millis(watchdog_budget_ms(timeout, waited) as u64);
            assert!(
                waited + budget <= timeout,
                "a command dequeued after {waited:?} gets a {budget:?} budget — it would still \
                 be running at the {timeout:?} mark, which is the wedge this bounds"
            );
        }
    }

    /// Past the point where any headroom is left, the budget floors instead of reaching zero —
    /// because zero *disables* win-kexp's watchdog, which would make a command dequeued near
    /// the deadline the one command that runs unbounded.
    ///
    /// The floor deliberately overruns the caller's timeout: by then the caller has already
    /// given up, and the remaining job is to free the engine thread for the *next* call.
    #[test]
    fn a_command_dequeued_past_the_deadline_is_still_bounded() {
        let timeout = Duration::from_secs(300);
        for waited in [290, 300, 600, 86_400] {
            assert_eq!(
                watchdog_budget_ms(timeout, Duration::from_secs(waited)),
                15_000,
                "a command dequeued after {waited}s must still arm the watchdog"
            );
        }
    }

    /// A `call_timeout` beyond `u32::MAX` milliseconds (~49 days) must saturate, not wrap: a
    /// wrapped budget could land on 0 and silently disable the watchdog.
    #[test]
    fn an_absurd_call_timeout_saturates_rather_than_wrapping() {
        assert_eq!(
            watchdog_budget_ms(Duration::from_secs(u32::MAX as u64), Duration::ZERO),
            u32::MAX
        );
    }

    // ---- the interrupt path, against a real engine ---------------------------------
    //
    // These need DbgEng and a target, so they are `#[ignore]`d rather than gated by an env
    // var: they are the manual counterpart to win-kexp's own bounded-command tests, and CI
    // has no way to provide what they need.
    //
    // dbgeng holds **one debuggee session per process**, so they must not run in parallel
    // with each other:
    //
    //     cargo test --bin windbg-mcp -- --ignored --nocapture --test-threads=1 engine::tests
    //
    // win-kexp proves the primitive (`execute_command_bounded` aborts a runaway command, and
    // the next command survives it). What is unproven *here* — and is what these cover — is
    // this crate's wiring of it: that `run_command`'s budget actually reaches the watchdog,
    // that the abort beats the caller's timeout (including from behind a queued job), and
    // that the engine thread is free for the next call afterwards.

    /// The checked-in kernel crash dump, also used by `tests/mcp_smoke.rs`'s target tier.
    const SAMPLE_DUMP: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/samples/052126-34312-01.dmp"
    );

    /// A deliberately runaway command: a tight `.for` in the expression evaluator, which is
    /// genuinely CPU-bound and polls for Ctrl+Break exactly as a real runaway command does.
    ///
    /// A broad `s` memory search — the wedge that motivated all of this — is the wrong probe
    /// despite being the motivating case: it skips unmapped ranges, so even a whole-address-
    /// space search returns almost immediately on this dump. The `.for` also leaves its
    /// progress in `$t0`, which is what proves the interruption below.
    ///
    /// Sized to run for hours, so "did not finish" cannot mean "finished early on a fast host".
    const RUNAWAY_ITERATIONS: u64 = 0x4000_0000;

    fn runaway_command() -> String {
        format!(".for (r $t0 = 0; @$t0 < 0x{RUNAWAY_ITERATIONS:x}; r $t0 = @$t0 + 1) {{ }}")
    }

    /// Reads a user pseudo-register (`$t0`, `$t1`) as a number. Returns `None` if the engine
    /// printed something unexpected, so a caller can tell "unreadable" from "zero".
    fn pseudo_register(text: &str, name: &str) -> Option<u64> {
        text.split_whitespace()
            .find_map(|tok| tok.strip_prefix(&format!("{name}=")))
            .and_then(|v| u64::from_str_radix(&v.replace('`', ""), 16).ok())
    }

    /// Opens the sample dump on `engine`, or returns why it could not.
    ///
    /// `open_dump` only hands the file to DbgEng — the target is not loaded, and `Execute`
    /// blocks, until `wait_for_event` drives the load. Both halves therefore have to run in
    /// **one** job: an engine left between them is not a usable target for anything else.
    async fn open_sample_dump(engine: &EngineHandle) -> Result<(), String> {
        engine
            .run(|e| {
                // Empty symbol path, deliberately: these tests measure *timing*, and a symbol
                // server on the ambient `_NT_SYMBOL_PATH` would put an unbounded network fetch
                // inside the very budget under test. Nothing here needs symbols — the `.for`
                // probe runs in the expression evaluator.
                let _ = e.set_symbol_path("");
                e.open_dump(SAMPLE_DUMP).map_err(|e| e.to_string())?;
                e.wait_for_event(60_000).map_err(|e| e.to_string())?;
                Ok(String::new())
            })
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// Whether the engine still *executes* commands. Asserted on an effect rather than on
    /// returned text: `Execute` echoes the command into the output buffer before running it,
    /// so any substring check against the command itself passes on the echo alone — even for
    /// a command that was aborted before it did anything.
    async fn engine_still_executes(engine: &EngineHandle) -> bool {
        const SENTINEL: u64 = 0x5A5E;
        if engine
            .run(|e| {
                e.execute_command(&format!("r $t1 = 0x{SENTINEL:x}"))
                    .map_err(|e| e.to_string())
            })
            .await
            .is_err()
        {
            return false;
        }
        match engine
            .run(|e| e.execute_command("r $t1").map_err(|e| e.to_string()))
            .await
        {
            Ok(text) => pseudo_register(&text, "$t1") == Some(SENTINEL),
            Err(_) => false,
        }
    }

    /// The whole point of the bounded path, end to end at this crate's altitude: a command
    /// that would run for hours comes back to the caller *as a result* (not as a timeout),
    /// and the engine thread is free for the next call.
    #[tokio::test]
    #[ignore = "needs DbgEng and a target; run manually with --ignored --test-threads=1"]
    async fn a_runaway_command_self_aborts_and_leaves_the_engine_usable() {
        // 30s of call budget leaves the watchdog the 15s floor, which keeps the test short
        // while still exercising the real arithmetic rather than a special case.
        let engine = EngineHandle::spawn(Duration::from_secs(30));
        open_sample_dump(&engine).await.expect("open sample dump");

        let started = Instant::now();
        let out = engine
            .run_command(runaway_command(), || Ok(()))
            .await
            .expect("a bounded runaway command must return a result, not a timeout");
        let elapsed = started.elapsed();

        // Proof of interruption is the loop counter, not the clock and not the note: the note
        // is appended whenever the watchdog *attempted* an interrupt, so an interrupt the
        // engine ignored would still produce it.
        let t0 = engine
            .run(|e| e.execute_command("r $t0").map_err(|e| e.to_string()))
            .await
            .ok()
            .and_then(|text| pseudo_register(&text, "$t0"))
            .expect("could not read $t0 back");
        println!(
            "bounded command returned after {elapsed:?}, $t0 = {t0:#x} of {RUNAWAY_ITERATIONS:#x}"
        );
        assert!(t0 > 0, "the loop never started ($t0 = {t0:#x})");
        assert!(
            t0 < RUNAWAY_ITERATIONS,
            "the loop ran to completion ($t0 = {t0:#x}) — the watchdog did not cut it short, \
             so the rest of this test would prove nothing"
        );
        assert!(
            out.contains("interrupted after"),
            "no interruption note despite a loop that stopped short:\n{out}"
        );

        // The wedge itself. Before the bounded path this is where every later call timed out,
        // and the only recovery was restarting the server.
        assert!(
            engine_still_executes(&engine).await,
            "the engine thread was not freed by the abort — this is the wedge"
        );

        let _ = engine
            .run(|e| {
                e.end_session()
                    .map(|_| String::new())
                    .map_err(|e| e.to_string())
            })
            .await;
    }

    /// The queue-aware half of the budget, which is the part that has no equivalent in
    /// win-kexp: a bounded command that spent most of the call budget waiting its turn must
    /// still abort *before* its caller's timeout, not one full budget after it was dequeued.
    ///
    /// Budgeting from the full `call_timeout` instead of the remainder passes every assertion
    /// in the test above and fails here — the command would abort ~30s after the caller had
    /// already given up, with the engine pinned in between.
    // Multi-threaded runtime, because this test blocks on the "job started" signal below.
    // On the default current-thread runtime that block also starves the spawned task that
    // would send it, and the test deadlocks instead of failing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs DbgEng and a target; run manually with --ignored --test-threads=1"]
    async fn a_runaway_command_queued_behind_another_job_still_beats_its_caller() {
        const CALL_TIMEOUT: Duration = Duration::from_secs(60);
        const QUEUE_WAIT: Duration = Duration::from_secs(30);

        let engine = EngineHandle::spawn(CALL_TIMEOUT);
        open_sample_dump(&engine).await.expect("open sample dump");

        // Occupy the engine thread. The signal is sent from *inside* the job, so the runaway
        // command below is submitted while this one is provably already running — a plain
        // spawn would race and might queue the two the other way round.
        let (running_tx, running_rx) = std::sync::mpsc::channel();
        let blocker = tokio::spawn({
            let engine = engine.clone();
            async move {
                engine
                    .run(move |_| {
                        running_tx.send(()).expect("signal receiver alive");
                        thread::sleep(QUEUE_WAIT);
                        Ok(String::new())
                    })
                    .await
            }
        });
        running_rx.recv().expect("blocker job started");

        let started = Instant::now();
        let out = engine
            .run_command(runaway_command(), || Ok(()))
            .await
            .expect("a bounded runaway command must return a result, not a timeout");
        let elapsed = started.elapsed();

        println!(
            "queued {QUEUE_WAIT:?}, then returned after {elapsed:?} of a {CALL_TIMEOUT:?} budget"
        );
        assert!(
            out.contains("interrupted after"),
            "the queued command was not interrupted:\n{out}"
        );
        assert!(
            elapsed < CALL_TIMEOUT,
            "the abort landed after the caller's {CALL_TIMEOUT:?} timeout ({elapsed:?}) — the \
             watchdog budget did not account for the {QUEUE_WAIT:?} spent queued"
        );
        assert!(
            engine_still_executes(&engine).await,
            "the engine thread was not freed by the abort"
        );

        let _ = blocker.await;
        let _ = engine
            .run(|e| {
                e.end_session()
                    .map(|_| String::new())
                    .map_err(|e| e.to_string())
            })
            .await;
    }

    /// What the bounded path *costs* a command that was never going to run away — the evidence
    /// behind the coverage split in `DECISIONS.md` (2026-08-02), kept as a test so a win-kexp
    /// change to the watchdog can be re-measured rather than re-argued.
    ///
    /// The cost is not a constant overhead but a **quantization**, which is why this reports a
    /// distribution rather than a mean. win-kexp's watchdog thread checks its `done` flag, then
    /// sleeps 200ms; `Execute` returning sets the flag, but the join has to wait for the sleep
    /// to end. A command therefore takes `ceil(d / 200ms) * 200ms` — measured on the sample
    /// dump: `lm` at 0.2ms and a `.for` at 127ms both come back at ~200ms, and a 377ms `.for`
    /// at ~401ms.
    ///
    /// The one escape is a command that finishes before the watchdog thread's *first* check (a
    /// thread spawn away), which costs ~nothing. Only sub-millisecond commands are ever in that
    /// regime and they straddle it — the `lm` median flips between ~0.3ms and ~200ms run to run
    /// on the same host, so it is a race, not a guarantee.
    ///
    /// So the tax on a point query is best read as: anything that takes 1–200ms now takes
    /// 200ms. A 30ms `k` becomes 200ms.
    ///
    /// Prints rather than asserts. The cost belongs to win-kexp's watchdog, not to this crate,
    /// and a threshold pinned here would fail on an unrelated host difference.
    #[tokio::test]
    #[ignore = "needs DbgEng and a target; run manually with --ignored --test-threads=1"]
    async fn measure_what_the_bounded_path_costs_a_quick_command() {
        const ROUNDS: usize = 20;

        let engine = EngineHandle::spawn(Duration::from_secs(60));
        open_sample_dump(&engine).await.expect("open sample dump");

        /// min / median / max, because a mean hides the two modes entirely.
        fn spread(mut samples: Vec<Duration>) -> String {
            samples.sort();
            format!(
                "min {:?}, median {:?}, max {:?}",
                samples[0],
                samples[samples.len() / 2],
                samples[samples.len() - 1]
            )
        }

        // Two probes, either side of the regime boundary:
        //   `lm`  — the command the `modules` tool issues; sub-millisecond on a warm engine
        //           with no symbol path, so it lands near the boundary and straddles it.
        //   `.for`— a calibrated ~10ms command, standing in for any real query on a real
        //           target (symbols, a live stack walk), which is well past the boundary.
        let spin = |iterations: u64| {
            format!(".for (r $t0 = 0; @$t0 < 0x{iterations:x}; r $t0 = @$t0 + 1) {{ }}")
        };
        for (label, command) in [
            ("lm", "lm".to_string()),
            (".for (short)", spin(20_000)),
            (".for (long)", spin(60_000)),
        ] {
            let mut plain = Vec::with_capacity(ROUNDS);
            let mut bounded = Vec::with_capacity(ROUNDS);
            for _ in 0..ROUNDS {
                let cmd = command.clone();
                let t = Instant::now();
                engine
                    .run(move |e| e.execute_command(&cmd).map_err(|e| e.to_string()))
                    .await
                    .expect("unbounded command");
                plain.push(t.elapsed());

                let t = Instant::now();
                engine
                    .run_command(command.clone(), || Ok(()))
                    .await
                    .expect("bounded command");
                bounded.push(t.elapsed());
            }
            println!("`{label}` x{ROUNDS}");
            println!("   unbounded: {}", spread(plain));
            println!("   bounded:   {}", spread(bounded));
        }

        let _ = engine
            .run(|e| {
                e.end_session()
                    .map(|_| String::new())
                    .map_err(|e| e.to_string())
            })
            .await;
    }
}
