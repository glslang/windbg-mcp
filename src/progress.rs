//! What a long call says while it is still running: MCP progress notifications.
//!
//! A tool call here can take minutes. A kernel attach waits for its target to dial in, a pool walk
//! reads every page, `!analyze -v` goes to a symbol server — and every one of them used to be
//! silent from the request until the result. Under stdio that was survivable, because the operator
//! could watch the server's stderr scroll past. Over `--listen` it is not: those records are on the
//! *other* machine, and both ways of asking for them ([`crate::server`]'s `session_status` and
//! `server_log`) are **pull**, so a client has to guess when to ask about a call it cannot see.
//!
//! **The facts were already there.** A worker announces `Committed` and `Opened` as it opens a
//! target and `RollingBack` when a teardown finds a transaction to unwind
//! ([`crate::proto::WorkerMessage`]), and the supervisor knows when the engine worker process came
//! up. What was missing was a `progressToken` to hang them on and a route out to the client. This
//! module is that route, plus one fact of its own — the heartbeat below.
//!
//! ## Four properties worth keeping
//!
//! **Nothing is sent unless the client asked for it.** MCP makes progress opt-in per request: a
//! caller that wants it puts a `progressToken` in the call's `_meta`. Without one there is no
//! channel, no timer and no notification — the same shape as [`crate::record`], which costs a
//! server that is not recording nothing at all.
//!
//! **A milestone is learned where it cannot be reported.** `Committed` arrives on the task that
//! reads a worker's channel, which belongs to the session rather than to any one call — while the
//! peer and the token belong to the *call*, forty-odd tool bodies away. So the sink is read once
//! from a task-local on the caller's own task, in [`crate::engine::Sessions::call_as`], and left
//! beside that call's waiter for the reader to find by job id. It is dropped with the waiter, which
//! is what stops a milestone being reported against a call that has already been answered.
//!
//! **Reporting never holds up the work.** A notification is sent while the tool call is still being
//! polled, never instead of it: a client that has stopped reading its stream must not be able to
//! stall a debugger command. If the call finishes mid-send, the send is abandoned — the result is
//! already on its way, and nothing downstream needs the notification that would have preceded it.
//!
//! **`progress` counts seconds, and there is no `total`.** Elapsed time is the one measure every
//! call here shares, it increases strictly (which is what MCP asks of the field), and it is the
//! number a reader actually wants from a debugger. A denominator would have to be the call's
//! budget, and that is a different constant per tool — `END_SESSION_TIMEOUT` for a teardown,
//! `INTERRUPT_TIMEOUT` for an interrupt, the configured call timeout for the rest, none of which
//! covers the up-to-30s worker handshake an opener spends before its budget even starts. An absent
//! `total` says "unknown", which is true; a wrong one would say something false.

use std::future::Future;
use std::time::{Duration, Instant};

use rmcp::model::{ProgressNotificationParam, ProgressToken};
use rmcp::service::RequestContext;
use rmcp::{Peer, RoleServer};
use tokio::sync::mpsc;

use crate::server::fmt_duration;

/// How long a call may say nothing before it reports that it is nonetheless still running.
///
/// Not decoration. A client may treat progress as a liveness signal and extend its own request
/// timeout on each one (rmcp's own client does, as `reset_timeout_on_progress`), so the interval
/// has to sit well inside any timeout a client would plausibly apply to a single call. It also has
/// to be long enough that the default 300s budget produces a readable trace rather than a flood:
/// at ten seconds that is thirty lines for the longest call this server allows, and none at all for
/// the overwhelming majority, which answer in milliseconds.
const HEARTBEAT: Duration = Duration::from_secs(10);

/// Something a call did on its way to an answer.
///
/// Deliberately a closed set of *milestones* rather than a free-text channel. Each one is a
/// transition the supervisor already acts on — they decide what an open's failure means and how
/// long a teardown waits — so a step that stops being reported here is a step that stopped
/// happening, rather than a log line somebody forgot to write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// The engine worker process is up and has an engine; the opener is about to be sent to it.
    ///
    /// The supervisor's own, not a worker's: it is what the up-to-[`crate::engine::WORKER_READY_TIMEOUT`]
    /// handshake before an opener ends with, and without it the whole of that wait looks like a
    /// server doing nothing.
    Spawned { pid: u32 },
    /// The target was created or claimed — the dump handed over, the process spawned, the KD
    /// connection taken. From here a failure means "do not open again"; see
    /// [`crate::proto::WorkerMessage::Committed`].
    Committed,
    /// The opener's wait returned: the target is loaded and stopped, and only its report is left.
    Opened,
    /// A teardown found a transaction in flight and told it to stop and roll back, which it has
    /// this long to finish ([`crate::proto::WorkerMessage::RollingBack`]).
    Unwinding { within: Duration },
}

impl Step {
    /// What the client is told. Written in the same vocabulary `session_status` uses for the same
    /// states, so a caller that sees both does not have to learn two names for one thing.
    fn message(self) -> String {
        match self {
            Self::Spawned { pid } => {
                format!("engine worker started (pid {pid}); opening the target")
            }
            Self::Committed => {
                "the target has been created or claimed; waiting for it to break in".to_string()
            }
            Self::Opened => "the target is open; reading its report".to_string(),
            Self::Unwinding { within } => format!(
                "a transaction is in flight; rolling it back (up to {})",
                fmt_duration(within)
            ),
        }
    }
}

/// Where one call's milestones go while it runs.
///
/// Unbounded because the alternative is worse in the one case that matters: this is written from a
/// worker's message reader, and a bounded channel that filled would block that reader — which is
/// the thread whose progress a teardown's grace depends on. The bound is inherent instead, and
/// small: a call reports at most three of these, and the copy the engine holds is dropped when the
/// call is answered.
#[derive(Clone, Debug)]
pub struct Reporter(mpsc::UnboundedSender<Step>);

impl Reporter {
    /// Reports `step`. A step nobody reads — into a closed channel, or into an open one the relay
    /// has stopped selecting on because the answer arrived first — is a normal outcome, not an
    /// error: what supersedes a progress line is the result it would have preceded.
    pub fn step(&self, step: Step) {
        let _ = self.0.send(step);
    }
}

tokio::task_local! {
    /// Where the call running on this task reports what it is doing.
    ///
    /// A task-local for the mirror image of [`crate::record`]'s `ROUTED`: that one carries a fact
    /// *out* of a call that forty-odd tool bodies never mention, and this one carries a sink *in*.
    /// Threading it through would mean a parameter on every tool signature, on `run`, on `run_call`
    /// and on `opened`, naming something none of them uses — and the tools that would be forgotten
    /// are the ones added next.
    ///
    /// Set only when the client asked for progress, so `try_with` failing is the ordinary case.
    static REPORTING: Reporter;
}

/// The reporter for the call running on this task, if it has one.
///
/// Read once, by [`crate::engine::Sessions::call_as`], and stored beside the call's waiter — the
/// milestones themselves arrive on another task entirely, where this would answer `None`.
pub fn current() -> Option<Reporter> {
    REPORTING.try_with(Clone::clone).ok()
}

/// Reports a step for the call running on this task. Silent when there is none — outside a tool
/// call, or when the client asked for no progress.
pub fn report(step: Step) {
    let _ = REPORTING.try_with(|reporter| reporter.step(step));
}

/// A client's request to be told how a call is going, or the absence of one.
///
/// Built from the request before the tool router consumes it, so the whole of a tool call — the
/// routing, the worker handshake, the engine call — runs inside the scope.
pub struct Watch(Option<(Peer<RoleServer>, ProgressToken)>);

impl Watch {
    /// What this request asked for. `_meta.progressToken` is MCP's opt-in, and its absence is the
    /// common case.
    pub fn of(context: &RequestContext<RoleServer>) -> Self {
        Self(
            context
                .meta
                .get_progress_token()
                .map(|token| (context.peer.clone(), token)),
        )
    }

    /// Runs `work`, forwarding what it reports to the client as `notifications/progress`.
    pub async fn run<F: Future>(self, work: F) -> F::Output {
        let Some((peer, token)) = self.0 else {
            return work.await;
        };
        relay(work, HEARTBEAT, move |progress, message| {
            let param =
                ProgressNotificationParam::new(token.clone(), progress).with_message(message);
            let peer = peer.clone();
            async move {
                // Best-effort by construction: the client is being *told* something, and a
                // notification that could not be delivered must never turn a debugger call that
                // worked into one that failed. Logged at debug because the ordinary cause is a
                // client that has gone away, which every other path already reports.
                if let Err(e) = peer.notify_progress(param).await {
                    tracing::debug!("could not send a progress notification: {e}");
                }
            }
        })
        .await
    }
}

/// Drives `work`, turning the steps it reports — and the silences between them — into `notify`
/// calls carrying seconds elapsed and a message.
///
/// Free of rmcp on purpose: the policy (what is reported, when a silence becomes a heartbeat, that
/// a send never delays the work) is the part worth testing, and it tests against a `Vec` rather
/// than against a peer that would need a whole service behind it.
async fn relay<W, N, F>(work: W, beat: Duration, notify: N) -> W::Output
where
    W: Future,
    N: Fn(f64, String) -> F,
    F: Future<Output = ()>,
{
    let started = Instant::now();
    let (tx, mut rx) = mpsc::unbounded_channel();
    // Held here *as well as* inside the scope, so the channel cannot close while this loop is still
    // selecting on it. A `recv()` on a closed channel is instantly ready, and an arm that is
    // instantly ready inside a loop is a spin.
    let reporter = Reporter(tx);
    let mut work = std::pin::pin!(REPORTING.scope(reporter.clone(), work));
    let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + beat, beat);
    // The beat measures silence, not wall clock: a runtime that was busy elsewhere must not make up
    // the ticks it missed by sending several notifications at once.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        let message = tokio::select! {
            outcome = &mut work => return outcome,
            Some(step) = rx.recv() => step.message(),
            _ = ticker.tick() => format!("still running ({})", fmt_duration(started.elapsed())),
        };
        // Restarted after anything said, so the heartbeat is "nothing for `beat`" rather than a
        // metronome running beside the milestones.
        ticker.reset();
        let mut sending = std::pin::pin!(notify(started.elapsed().as_secs_f64(), message));
        tokio::select! {
            // The work is still polled while the notification goes out, and wins if it lands
            // first: an undelivered progress line costs nothing once the result exists, while a
            // client that has stopped reading its stream must never be able to stall the debugger.
            outcome = &mut work => return outcome,
            () = &mut sending => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    /// Collects what `relay` would have sent.
    type Sent = Arc<Mutex<Vec<(f64, String)>>>;

    fn collector() -> (Sent, impl Fn(f64, String) -> std::future::Ready<()>) {
        let sent: Sent = Arc::default();
        let into = Arc::clone(&sent);
        (sent, move |progress, message| {
            into.lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((progress, message));
            std::future::ready(())
        })
    }

    fn messages(sent: &Sent) -> Vec<String> {
        sent.lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|(_, message)| message.clone())
            .collect()
    }

    /// Lets the relay drain what has just been reported before the work returns.
    ///
    /// A step reported in the same instant the answer arrives may or may not be delivered — the
    /// result supersedes it, and `select!` picks between two ready branches at random — so a test
    /// that asserted on that race would be flaky about behaviour nobody depends on. Every test
    /// here ends its work with this so what it counts is the steady state.
    async fn settle() {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }

    /// The opener sequence, end to end: what the supervisor and its worker report becomes three
    /// notifications, in the order the target actually reached those states.
    #[tokio::test(start_paused = true)]
    async fn the_milestones_a_call_reports_become_notifications_in_order() {
        let (sent, notify) = collector();
        relay(
            async {
                report(Step::Spawned { pid: 4242 });
                // The reporter a worker's reader would be handed: the milestones after the first
                // arrive on another task, and reach the same channel through the waiter.
                let reader = current().expect("a call being watched has a reporter");
                tokio::task::spawn(async move {
                    reader.step(Step::Committed);
                    reader.step(Step::Opened);
                })
                .await
                .expect("the reader task");
                settle().await;
            },
            HEARTBEAT,
            notify,
        )
        .await;

        let said = messages(&sent);
        assert_eq!(said.len(), 3, "one notification per milestone: {said:?}");
        assert!(said[0].contains("pid 4242"), "{said:?}");
        assert!(said[1].contains("created or claimed"), "{said:?}");
        assert!(said[2].contains("target is open"), "{said:?}");
    }

    /// Progress is seconds elapsed, so it strictly increases and never claims a total it cannot
    /// know. Two milestones in the same instant would otherwise report the same number, which is
    /// the one thing MCP asks this field not to do.
    #[tokio::test(start_paused = true)]
    async fn progress_increases_and_names_no_total() {
        let (sent, notify) = collector();
        relay(
            async {
                report(Step::Committed);
                tokio::time::sleep(Duration::from_millis(250)).await;
                report(Step::Opened);
                settle().await;
            },
            HEARTBEAT,
            notify,
        )
        .await;

        let sent = sent.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert_eq!(sent.len(), 2, "{sent:?}");
        assert!(
            sent[1].0 > sent[0].0,
            "progress must increase between milestones: {sent:?}"
        );
    }

    /// A call with nothing to say still says it is running, which is the whole point for a kernel
    /// attach: `Committed` lands in the first second and the next real event may be minutes away.
    #[tokio::test(start_paused = true)]
    async fn a_silent_call_still_reports_that_it_is_running() {
        let (sent, notify) = collector();
        relay(
            tokio::time::sleep(HEARTBEAT * 3 + Duration::from_secs(1)),
            HEARTBEAT,
            notify,
        )
        .await;

        let said = messages(&sent);
        assert_eq!(said.len(), 3, "one beat per silent interval: {said:?}");
        assert!(
            said.iter().all(|m| m.starts_with("still running")),
            "{said:?}"
        );
    }

    /// And the beat measures silence rather than wall clock, so a call that is reporting normally
    /// does not also accumulate heartbeats behind it.
    #[tokio::test(start_paused = true)]
    async fn a_milestone_restarts_the_beat() {
        let (sent, notify) = collector();
        relay(
            async {
                for _ in 0..3 {
                    tokio::time::sleep(HEARTBEAT - Duration::from_secs(1)).await;
                    report(Step::Committed);
                }
                settle().await;
            },
            HEARTBEAT,
            notify,
        )
        .await;

        let said = messages(&sent);
        assert_eq!(
            said.len(),
            3,
            "three milestones and no beat between them: {said:?}"
        );
    }

    /// Nothing is reported after the result exists. The work winning the race is what makes a
    /// stalled client a client's own problem rather than the debugger's.
    #[tokio::test(start_paused = true)]
    async fn the_answer_ends_the_reporting() {
        let (sent, notify) = collector();
        let reporter: Arc<Mutex<Option<Reporter>>> = Arc::default();
        let escaped = Arc::clone(&reporter);
        relay(
            async move {
                *escaped.lock().unwrap_or_else(|e| e.into_inner()) = current();
            },
            HEARTBEAT,
            notify,
        )
        .await;

        // The waiter this belongs to would be gone by now; a clone that outlived it must not be
        // able to say anything more.
        let escaped = reporter
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .expect("the call had a reporter");
        escaped.step(Step::Opened);
        tokio::time::advance(HEARTBEAT * 2).await;
        assert!(
            messages(&sent).is_empty(),
            "a finished call reports nothing: {:?}",
            messages(&sent)
        );
    }

    /// Outside a watched call there is nowhere to report to, and that is the common case — a
    /// client that asked for no progress, the shutdown sweep, the reclamation that ends somebody
    /// else's session on a task of its own.
    #[tokio::test]
    async fn reporting_outside_a_watched_call_is_silent() {
        assert!(current().is_none(), "no reporter outside a scope");
        report(Step::Committed);
    }
}
