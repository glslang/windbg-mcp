//! The dedicated DbgEng worker thread.
//!
//! DbgEng requires single-threaded, serialized access (and `WaitForEvent` must run
//! on the session-owning thread). We therefore confine the [`DebugEngine`] to one
//! OS thread and marshal every operation onto it over a channel, returning results
//! to the async (rmcp/tokio) side via oneshot replies.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::thread;
use std::time::Duration;

use rmcp::ErrorData;
use tokio::sync::{mpsc, oneshot};
use win_kexp::dbgeng::DebugEngine;

/// Result of an engine operation: `Ok(text)` or `Err(message)`.
type Reply = Result<String, String>;

/// A unit of work to run on the engine thread, plus where to send its result.
struct Job {
    run: Box<dyn FnOnce(&DebugEngine) -> Reply + Send>,
    reply: oneshot::Sender<Reply>,
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
                        while let Some(job) = rx.blocking_recv() {
                            let _ = job.reply.send(Err(
                                "failed to initialize DbgEng (is dbgeng.dll on the search path?)"
                                    .to_string(),
                            ));
                        }
                        return;
                    }
                };
                while let Some(job) = rx.blocking_recv() {
                    // A panic inside a win-kexp method (several use `.expect`) must not
                    // kill the worker — surface it as an error for this one call.
                    let result = catch_unwind(AssertUnwindSafe(|| (job.run)(&engine)))
                        .unwrap_or_else(|_| Err("debugger operation panicked".to_string()));
                    let _ = job.reply.send(result);
                }
            })
            .expect("failed to spawn dbgeng thread");
        Self { tx, call_timeout }
    }

    /// Runs `f` on the engine thread, awaiting the result with the configured timeout.
    pub async fn run<F>(&self, f: F) -> Result<String, ErrorData>
    where
        F: FnOnce(&DebugEngine) -> Reply + Send + 'static,
    {
        let (rtx, rrx) = oneshot::channel();
        self.tx
            .send(Job {
                run: Box::new(f),
                reply: rtx,
            })
            .map_err(|_| ErrorData::internal_error("engine thread unavailable", None))?;
        match tokio::time::timeout(self.call_timeout, rrx).await {
            Ok(Ok(Ok(s))) => Ok(s),
            Ok(Ok(Err(e))) => Err(ErrorData::internal_error(e, None)),
            Ok(Err(_)) => Err(ErrorData::internal_error("engine dropped reply", None)),
            Err(_) => Err(ErrorData::internal_error(
                "engine call timed out (the target may still be running)",
                None,
            )),
        }
    }
}
