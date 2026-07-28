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
    /// The engine itself is unusable — the worker thread is gone or dropped the reply.
    /// Nothing the model can do about it.
    Unavailable(String),
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Debugger(m) | Self::Unavailable(m) => f.write_str(m),
        }
    }
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
            Err(_) => Err(EngineError::Debugger(
                "engine call timed out (the target may still be running)".to_string(),
            )),
        }
    }

    /// Runs a raw debugger command **bounded** by an engine-side watchdog. If the command
    /// runs longer than the call budget, win-kexp's `execute_command_bounded` Ctrl+Breaks the
    /// engine so it aborts and frees the thread — instead of a runaway command (most importantly
    /// an unbounded `s` memory search) pinning the single engine thread and wedging every later
    /// call. Use this for command-executing tools (`execute`, `dx`, the `ttd_*` wrappers); the
    /// quick, inherently-bounded operations can keep using [`Self::run`].
    ///
    /// `precheck` runs **on the engine thread**, immediately before the command and after any
    /// job queued ahead of it. Callers use it for gates that must not be evaluated while
    /// earlier work is still in flight — see [`crate::server`]'s session handles.
    pub async fn run_command<P>(&self, command: String, precheck: P) -> Result<String, EngineError>
    where
        P: FnOnce() -> Result<(), String> + Send + 'static,
    {
        // The outer timeout in `run` starts counting at *submission*, but this command may sit
        // in the engine queue behind another job (e.g. a backgrounded `go`) before reaching the
        // worker. Compute the watchdog budget from the time *remaining* until that timeout — not
        // the full `call_timeout` — so it Ctrl+Breaks ~15s before the caller gives up regardless
        // of queue wait. `submitted.elapsed()` (evaluated on the engine thread) is that wait.
        let call_timeout = self.call_timeout;
        let submitted = Instant::now();
        self.run(move |e| {
            precheck()?;
            // Floor the budget so a command dequeued near the deadline still arms the watchdog
            // (a 0 budget disables it) and thus still frees the engine promptly.
            let budget_ms = call_timeout
                .saturating_sub(submitted.elapsed())
                .saturating_sub(Duration::from_secs(15))
                .max(Duration::from_secs(15))
                .as_millis()
                .min(u32::MAX as u128) as u32;
            e.execute_command_bounded(&command, budget_ms)
                .map_err(|e| e.to_string())
        })
        .await
    }
}
