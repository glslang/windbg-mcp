//! Every log record either role produces, in one place a client can read.
//!
//! On stdio this was free, and nobody had to build it. A worker's stderr is the supervisor's
//! (`engine::spawn_worker` inherits it), the supervisor's is the MCP client's, and an operator
//! asking "why did that session die" finds both in the log file their client already keeps.
//! `--listen` takes that away: the server is on another machine, and its stderr goes to a console
//! on that machine. Nothing about HTTP requires that, so it is a regression against stdio rather
//! than a property of the transport, and it is put back here.
//!
//! What is put back is not the stream — it is a **bounded ring of the most recent records**, kept
//! by the supervisor and served by the `server_log` tool. That shape follows from where the
//! records have to arrive:
//!
//! - **A tool works on both transports.** Nothing here is listener-only, so stdio and HTTP report
//!   the same thing and there is one code path to be wrong.
//! - **It answers when the session cannot.** `server_log` is answered by the supervisor and never
//!   routed to a worker, exactly like `session_status` — which matters, because the case it exists
//!   for is a session that is wedged, and a tool that queued behind the wedge would be unavailable
//!   precisely when it is wanted.
//! - **It reaches a reader stderr never did.** Under stdio these records go to a file the *human*
//!   can open. The model driving the debugger has never been able to see them at all, and it is
//!   the one holding the session.
//!
//! Deliberately **not** MCP's `notifications/message`. The protocol's logging capability is what
//! this would otherwise be a few lines of, and it is on its way out: rmcp marks every type in it
//! `#[deprecated]` for removal (SEP-2577). This server's smoke test also asserts that the
//! `logging` capability is *not* advertised, on the grounds that advertising what you do not
//! implement routes real calls into `method_not_found` — so building on it would mean unpicking
//! that test in order to depend on an API the SDK has announced it is deleting.
//!
//! # How a record gets here
//!
//! Both roles install [`layer`] under the same [`EnvFilter`](tracing_subscriber::EnvFilter), so
//! what the ring holds is exactly what stderr shows, and `RUST_LOG` widens both together.
//!
//! In the **supervisor** the layer writes straight into the ring. In a **worker** it cannot: the
//! ring is in the other process. So the layer queues the record and a writer thread mirrors it up
//! the protocol channel as [`WorkerMessage::Log`](crate::proto::WorkerMessage::Log) — a fact
//! crossing the pipe as a value, which is the same rule everything else in this server follows.
//! The supervisor stamps it with the session id on arrival, which is the one thing the worker does
//! not know and the reader most wants.
//!
//! A worker keeps writing to its inherited stderr as well. That copy is not redundant: it is what
//! an operator standing at the server machine reads, it survives a channel that has already
//! failed, and — because it is unchanged — the stdio behaviour this module exists to preserve is
//! preserved by *not touching it*.

use std::cell::Cell;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tracing::field::{Field, Visit};
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;

/// Severity, as it crosses the pipe and as `server_log` reports it.
///
/// Ordered most severe first, so "at least this severe" is `entry.level <= wanted` — the
/// comparison the filter actually wants, rather than one spelled backwards at every use.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl Level {
    fn of(level: &tracing::Level) -> Self {
        match *level {
            tracing::Level::ERROR => Self::Error,
            tracing::Level::WARN => Self::Warn,
            tracing::Level::INFO => Self::Info,
            tracing::Level::DEBUG => Self::Debug,
            tracing::Level::TRACE => Self::Trace,
        }
    }

    /// The label a rendered line carries, padded so a column of them lines up.
    pub fn label(self) -> &'static str {
        match self {
            Self::Error => "ERROR",
            Self::Warn => "WARN ",
            Self::Info => "INFO ",
            Self::Debug => "DEBUG",
            Self::Trace => "TRACE",
        }
    }
}

/// One record, as the ring holds it.
#[derive(Debug, Clone)]
pub struct Entry {
    /// Assigned by the ring, in arrival order, and never reused within a run. This is what makes
    /// `since` paging exact and what makes an eviction visible as a gap.
    pub seq: u64,
    /// Milliseconds since the Unix epoch, stamped **where the record happened** — in the worker,
    /// for a worker's. So `at` and `seq` can disagree by the width of a pipe write, and each is
    /// right about a different question: `at` when it happened, `seq` the order it was filed.
    pub at_ms: u64,
    pub level: Level,
    /// The `tracing` target, which is what says which half of the server spoke:
    /// `windbg_mcp::worker` against `windbg_mcp::engine` and friends.
    pub target: String,
    /// The session this record is about, for one that came from a worker. `None` is the
    /// supervisor itself — the registry, the listener, the tool surface.
    pub session: Option<String>,
    pub message: String,
}

/// How many records the ring holds before the oldest is evicted.
///
/// Sized for the question it answers — "what happened around the failure I am looking at" — not
/// for keeping a session's history. A transcript (`WINDBG_MCP_TRANSCRIPT`) is what keeps history,
/// and it is a file rather than memory for exactly that reason.
pub const DEFAULT_CAPACITY: usize = 1000;

/// Overrides [`DEFAULT_CAPACITY`], in records. Read once, on first use.
const CAPACITY_ENV: &str = "WINDBG_MCP_LOG_BUFFER";

/// The most a single record contributes to the ring. A runaway line is clipped rather than
/// dropped: the point of the cap is that one record cannot cost unbounded memory, and the first
/// few kilobytes of a line is where its meaning is.
const MESSAGE_LIMIT: usize = 4096;

/// How many records a worker will hold when the supervisor is not draining fast enough.
///
/// Bounded and **dropped when full**, never blocked on. The queue is fed from the engine thread,
/// which spends its life inside DbgEng, and a log line that could block that thread would be a
/// worse bug than any it could report.
const WORKER_QUEUE: usize = 512;

struct Ring {
    entries: VecDeque<Entry>,
    next_seq: u64,
    capacity: usize,
}

impl Ring {
    fn new(capacity: usize) -> Self {
        Self {
            entries: VecDeque::with_capacity(capacity.min(DEFAULT_CAPACITY)),
            next_seq: 0,
            capacity,
        }
    }

    /// Files a record, evicting the oldest if the ring is full.
    fn file(
        &mut self,
        level: Level,
        at_ms: u64,
        target: String,
        session: Option<String>,
        message: String,
    ) {
        let seq = self.next_seq;
        self.next_seq += 1;
        if self.entries.len() == self.capacity {
            self.entries.pop_front();
        }
        self.entries.push_back(Entry {
            seq,
            at_ms,
            level,
            target,
            session,
            message: clip(message),
        });
    }

    fn tail(&self, query: &Query) -> Tail {
        let matches: Vec<&Entry> = self
            .entries
            .iter()
            .filter(|e| e.level <= query.level)
            .filter(|e| query.since.is_none_or(|since| e.seq >= since))
            .filter(|e| match &query.session {
                Some(wanted) => e.session.as_deref() == Some(wanted.as_str()),
                None => true,
            })
            .collect();
        let matched = matches.len();
        let from = matched.saturating_sub(query.limit);
        Tail {
            entries: matches[from..].iter().map(|e| (*e).clone()).collect(),
            matched,
            next_since: self.next_seq,
            held: self.entries.len(),
            capacity: self.capacity,
            oldest_seq: self.entries.front().map(|e| e.seq),
        }
    }
}

fn ring() -> &'static Mutex<Ring> {
    static RING: OnceLock<Mutex<Ring>> = OnceLock::new();
    RING.get_or_init(|| {
        let capacity = std::env::var(CAPACITY_ENV)
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|n| *n > 0)
            .unwrap_or(DEFAULT_CAPACITY);
        Mutex::new(Ring::new(capacity))
    })
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

fn clip(mut message: String) -> String {
    if message.len() <= MESSAGE_LIMIT {
        return message;
    }
    let full = message.len();
    // On a character boundary, because a message is text and a clip that split a code point would
    // be a record nothing could read back.
    let mut cut = MESSAGE_LIMIT;
    while cut > 0 && !message.is_char_boundary(cut) {
        cut -= 1;
    }
    message.truncate(cut);
    message.push_str(&format!("… ({full} bytes in all)"));
    message
}

/// Files a record in this process's ring.
fn file(level: Level, at_ms: u64, target: String, session: Option<String>, message: String) {
    ring()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .file(level, at_ms, target, session, message);
}

/// Files a record a worker produced, against the session that worker holds.
///
/// `dropped` is what that worker's queue had to throw away since its last record, and it is filed
/// as a record of its own rather than folded into this one's text. A gap in the log is a fact
/// about the log, and a reader who is not told about it reads a quiet stretch as nothing having
/// happened.
pub fn from_worker(
    session: &str,
    at_ms: u64,
    level: Level,
    target: &str,
    message: String,
    dropped: u32,
) {
    if dropped > 0 {
        file(
            Level::Warn,
            at_ms,
            target.to_string(),
            Some(session.to_string()),
            format!(
                "[windbg-mcp] {dropped} log record(s) from this session's engine worker were \
                 dropped before the next one — its queue filled faster than the supervisor drained \
                 it. They are still on the server's stderr."
            ),
        );
    }
    file(
        level,
        at_ms,
        target.to_string(),
        Some(session.to_string()),
        message,
    );
}

/// What a reader asked for.
pub struct Query {
    /// Only records about this session. A record the supervisor made about a session — spawning
    /// its worker, timing its call out — carries no session id, so this narrows to what the
    /// *worker* said.
    pub session: Option<String>,
    /// The least severe level to include.
    pub level: Level,
    /// Only records filed after this `seq`.
    pub since: Option<u64>,
    /// At most this many, taking the most recent.
    pub limit: usize,
}

/// What the ring answered with.
pub struct Tail {
    /// Oldest first, which is reading order.
    pub entries: Vec<Entry>,
    /// How many matched the query before `limit` clipped it.
    pub matched: usize,
    /// Pass this as `since` next time to get only what is new. It is the next seq the ring will
    /// issue, not the last one returned, so a query that matched nothing still advances.
    pub next_since: u64,
    /// How many records the ring is holding, and how many it can.
    pub held: usize,
    pub capacity: usize,
    /// The oldest seq still held. A `since` older than this means records were evicted between
    /// the two calls, which is the only way a reader can find out.
    pub oldest_seq: Option<u64>,
}

pub fn tail(query: &Query) -> Tail {
    ring().lock().unwrap_or_else(|e| e.into_inner()).tail(query)
}

// ---- the worker's side of the bridge ---------------------------------------

/// The worker's queue. Created by [`layer`] so a record made before the protocol channel exists
/// is held rather than lost, and drained by [`take_worker_queue`] once there is somewhere to send
/// it.
static TO_SUPERVISOR: OnceLock<SyncSender<Entry>> = OnceLock::new();
static PENDING: Mutex<Option<Receiver<Entry>>> = Mutex::new(None);
static DROPPED: AtomicU32 = AtomicU32::new(0);
/// Queued and written, so [`flush`] can tell whether the writer has caught up. Counters rather
/// than a channel depth, which `SyncSender` does not expose.
static QUEUED: AtomicU64 = AtomicU64::new(0);
static WRITTEN: AtomicU64 = AtomicU64::new(0);
static WRITER_GONE: AtomicBool = AtomicBool::new(false);

thread_local! {
    /// Set on the worker's log-writer thread. Without it, a failure *inside* the write — which is
    /// reported with `tracing::error!` — would queue a record for the same thread to write, and a
    /// broken channel would spin producing reports of itself.
    static MUTED: Cell<bool> = const { Cell::new(false) };
}

/// Mirrors this worker's queued records up the protocol channel, on the thread that calls this.
/// Returns when the channel will take no more, or when the queue's last sender goes — which,
/// the sender being process-wide, means never in practice: the worker exits under it.
///
/// `send` is given a record and however many were dropped before it, and says whether the channel
/// is still usable. It lives in [`crate::worker`] because the channel does; the accounting lives
/// here because [`flush`] depends on it.
pub fn run_worker_writer(mut send: impl FnMut(Entry, u32) -> bool) {
    MUTED.with(|muted| muted.set(true));
    let Some(queue) = PENDING.lock().unwrap_or_else(|e| e.into_inner()).take() else {
        return;
    };
    for entry in queue {
        // Read before the send, and reset: these are the records that were dropped to make room
        // for the ones already queued ahead of this one, so this is the earliest message that can
        // truthfully carry them.
        let dropped = DROPPED.swap(0, Ordering::Relaxed);
        let usable = send(entry, dropped);
        WRITTEN.fetch_add(1, Ordering::Relaxed);
        if !usable {
            break;
        }
    }
    WRITER_GONE.store(true, Ordering::Relaxed);
}

/// Waits, up to `within`, for the writer to have mirrored everything queued so far.
///
/// Called by a worker on its way out. Without it the records that matter most are the ones most
/// likely to be lost: the teardown path logs *why* a target was released, and then exits the
/// process — which is not something a background thread survives.
pub fn flush(within: std::time::Duration) {
    let deadline = std::time::Instant::now() + within;
    while WRITTEN.load(Ordering::Relaxed) < QUEUED.load(Ordering::Relaxed) {
        if WRITER_GONE.load(Ordering::Relaxed) || std::time::Instant::now() >= deadline {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

// ---- the layer -------------------------------------------------------------

/// Which side of the pipe this process is on.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Files into the ring directly.
    Supervisor,
    /// Queues for the writer thread, which mirrors up the protocol channel.
    Worker,
}

/// The `tracing` layer both roles install beside the stderr one.
pub struct Bridge {
    role: Role,
}

/// Builds the layer, and — in a worker — the queue behind it.
pub fn layer(role: Role) -> Bridge {
    if role == Role::Worker {
        let (tx, rx) = sync_channel(WORKER_QUEUE);
        if TO_SUPERVISOR.set(tx).is_ok() {
            *PENDING.lock().unwrap_or_else(|e| e.into_inner()) = Some(rx);
        }
    }
    Bridge { role }
}

impl<S> tracing_subscriber::Layer<S> for Bridge
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        if MUTED.with(Cell::get) {
            return;
        }
        let mut rendered = Rendered::default();
        event.record(&mut rendered);
        let metadata = event.metadata();
        let level = Level::of(metadata.level());
        match self.role {
            Role::Supervisor => file(
                level,
                now_ms(),
                metadata.target().to_string(),
                None,
                rendered.finish(),
            ),
            Role::Worker => {
                let entry = Entry {
                    seq: 0, // the supervisor's ring assigns it; this side has no sequence
                    at_ms: now_ms(),
                    level,
                    target: metadata.target().to_string(),
                    session: None, // likewise: a worker does not know its session id
                    message: clip(rendered.finish()),
                };
                let queued = match TO_SUPERVISOR.get() {
                    Some(queue) => queue.try_send(entry),
                    None => Err(TrySendError::Disconnected(entry)),
                };
                if queued.is_ok() {
                    QUEUED.fetch_add(1, Ordering::Relaxed);
                } else {
                    DROPPED.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
}

/// An event's fields as one line, the way the stderr layer would have written them.
#[derive(Default)]
struct Rendered {
    message: String,
    fields: String,
}

impl Rendered {
    fn finish(self) -> String {
        match (self.message.is_empty(), self.fields.is_empty()) {
            (_, true) => self.message,
            (true, false) => self.fields.trim_start().to_string(),
            (false, false) => format!("{}{}", self.message, self.fields),
        }
    }

    fn push(&mut self, field: &Field, value: String) {
        if field.name() == "message" {
            self.message = value;
        } else {
            self.fields.push_str(&format!(" {}={value}", field.name()));
        }
    }
}

impl Visit for Rendered {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.push(field, format!("{value:?}"));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.push(field, value.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A ring of its own, so nothing here depends on the process-wide one — these tests run in
    /// one process alongside everything else in this crate that logs. It is the *same* type with
    /// the same `file` and `tail`, so what is asserted below is the shipping code.
    fn ring_of(capacity: usize, records: &[(Level, Option<&str>, &str)]) -> Ring {
        let mut ring = Ring::new(capacity);
        for (level, session, message) in records {
            ring.file(
                *level,
                1_700_000_000_000,
                "windbg_mcp::test".to_string(),
                session.map(str::to_string),
                (*message).to_string(),
            );
        }
        ring
    }

    fn query() -> Query {
        Query {
            session: None,
            level: Level::Trace,
            since: None,
            limit: 100,
        }
    }

    /// Severity ordering is what the filter is built on, and it reads backwards from the
    /// declaration if it is ever reordered: "at least a warning" must include errors.
    #[test]
    fn severity_orders_most_severe_first() {
        assert!(Level::Error < Level::Warn);
        assert!(Level::Warn < Level::Info);
        assert!(Level::Info < Level::Debug);
        assert!(Level::Debug < Level::Trace);
        let wanted = Level::Warn;
        assert!(Level::Error <= wanted, "an error is at least a warning");
        assert!(!(Level::Info <= wanted), "info is not at least a warning");
    }

    /// The ring drops the oldest, and the drop is *visible*: seq numbers do not restart, so a
    /// reader holding an older `since` can see that records passed between the two calls.
    #[test]
    fn eviction_leaves_a_gap_a_reader_can_see() {
        let records: Vec<(Level, Option<&str>, String)> = (0..5)
            .map(|seq| (Level::Info, None, format!("record {seq}")))
            .collect();
        let ring = ring_of(
            3,
            &records
                .iter()
                .map(|(l, s, m)| (*l, *s, m.as_str()))
                .collect::<Vec<_>>(),
        );
        let tail = ring.tail(&query());
        assert_eq!(tail.held, 3, "the ring holds its capacity and no more");
        assert_eq!(
            tail.oldest_seq,
            Some(2),
            "0 and 1 were evicted, and the oldest seq says so"
        );
        assert_eq!(tail.next_since, 5);
        let seqs: Vec<u64> = tail.entries.iter().map(|e| e.seq).collect();
        assert_eq!(seqs, vec![2, 3, 4], "oldest first, which is reading order");
    }

    /// `since` is the paging contract: a second call with the returned `next_since` must return
    /// what arrived in between and nothing it has already seen.
    #[test]
    fn since_returns_only_what_is_new() {
        let mut ring = ring_of(10, &[(Level::Info, None, "before")]);
        let first = ring.tail(&query());
        assert_eq!(first.entries.len(), 1);
        assert_eq!(first.next_since, 1);

        ring.file(
            Level::Info,
            1_700_000_000_001,
            "windbg_mcp::test".to_string(),
            None,
            "after".to_string(),
        );
        let second = ring.tail(&Query {
            since: Some(first.next_since),
            ..query()
        });
        let messages: Vec<&str> = second.entries.iter().map(|e| e.message.as_str()).collect();
        assert_eq!(messages, vec!["after"], "only what is new: {messages:?}");
    }

    /// A query that matches nothing still has to advance, or a caller polling a quiet server
    /// re-reads the same tail forever.
    #[test]
    fn an_empty_page_still_advances() {
        let ring = ring_of(10, &[(Level::Info, None, "only")]);
        let tail = ring.tail(&Query {
            since: Some(1),
            ..query()
        });
        assert!(tail.entries.is_empty());
        assert_eq!(tail.next_since, 1);
    }

    /// The level filter is a floor on severity, not an equality test.
    #[test]
    fn the_level_filter_is_a_floor() {
        let ring = ring_of(
            10,
            &[
                (Level::Debug, None, "noise"),
                (Level::Warn, None, "worth reading"),
                (Level::Error, None, "worth reading"),
            ],
        );
        let tail = ring.tail(&Query {
            level: Level::Warn,
            ..query()
        });
        assert_eq!(tail.matched, 2, "warnings and errors, not the debug record");
        assert!(tail.entries.iter().all(|e| e.level <= Level::Warn));
    }

    /// Narrowing to a session keeps that worker's records and drops the other's. The
    /// supervisor's own records carry no session, so they are not "everyone's" — asking about one
    /// session means asking what that worker said.
    #[test]
    fn a_session_filter_keeps_only_that_workers_records() {
        let ring = ring_of(
            10,
            &[
                (Level::Info, None, "supervisor"),
                (Level::Info, Some("a"), "worker a"),
                (Level::Info, Some("b"), "worker b"),
            ],
        );
        let tail = ring.tail(&Query {
            session: Some("a".to_string()),
            ..query()
        });
        let messages: Vec<&str> = tail.entries.iter().map(|e| e.message.as_str()).collect();
        assert_eq!(messages, vec!["worker a"]);
    }

    /// A tail is the *most recent* n, not the first n — the failure being looked at is at the end.
    #[test]
    fn a_limit_takes_the_newest_and_says_how_many_it_left() {
        let records: Vec<String> = (0..5).map(|seq| format!("record {seq}")).collect();
        let ring = ring_of(
            10,
            &records
                .iter()
                .map(|m| (Level::Info, None, m.as_str()))
                .collect::<Vec<_>>(),
        );
        let tail = ring.tail(&Query {
            limit: 2,
            ..query()
        });
        let seqs: Vec<u64> = tail.entries.iter().map(|e| e.seq).collect();
        assert_eq!(seqs, vec![3, 4]);
        assert_eq!(tail.matched, 5, "the clip is reported, not hidden");
    }

    /// A record cannot cost unbounded memory, and clipping must not split a code point — the
    /// message is text, and half a character is a record nothing can read back.
    #[test]
    fn a_runaway_record_is_clipped_on_a_character_boundary() {
        let long = "é".repeat(MESSAGE_LIMIT);
        let clipped = clip(long.clone());
        assert!(clipped.len() < long.len(), "it was clipped");
        assert!(
            clipped.contains(&format!("({} bytes in all)", long.len())),
            "and says what it clipped: {}",
            &clipped[clipped.len().saturating_sub(40)..]
        );
        // The assertion that matters: `clip` returned a `String`, so a split code point would
        // have panicked in `truncate` — this pins that it did not, in the case that provokes it.
        assert!(clipped.chars().count() > 1);
    }

    /// A short record is left exactly alone. Worth pinning because the clip is on the hot path
    /// for every record the server ever writes.
    #[test]
    fn an_ordinary_record_is_untouched() {
        assert_eq!(clip("session 3: open".to_string()), "session 3: open");
    }

    /// A dropped run is filed as a record of its own, so a gap in a worker's log reads as a gap
    /// rather than as a quiet stretch where nothing happened.
    #[test]
    fn dropped_worker_records_are_reported_as_a_record() {
        // Against the process-wide ring, which is the one `from_worker` writes to. Filtered by a
        // session id nothing else uses, so it does not matter what else has logged.
        let session = "ring-test-dropped";
        from_worker(
            session,
            1_700_000_000_000,
            Level::Info,
            "windbg_mcp::worker",
            "worker: target released".to_string(),
            4,
        );
        let tail = tail(&Query {
            session: Some(session.to_string()),
            ..query()
        });
        assert_eq!(tail.entries.len(), 2, "the gap, then the record");
        assert_eq!(tail.entries[0].level, Level::Warn);
        assert!(
            tail.entries[0].message.contains("4 log record(s)"),
            "it names how many: {}",
            tail.entries[0].message
        );
        assert_eq!(tail.entries[1].message, "worker: target released");
        assert_eq!(tail.entries[1].session.as_deref(), Some(session));
    }

    /// An event's own fields are kept beside its message rather than thrown away — the stderr
    /// layer prints them, so a bridge that dropped them would be reporting less than the log.
    #[test]
    fn fields_are_kept_beside_the_message() {
        let both = Rendered {
            message: "session ended".to_string(),
            fields: " id=3".to_string(),
        };
        assert_eq!(both.finish(), "session ended id=3");

        let only_fields = Rendered {
            message: String::new(),
            fields: " id=3".to_string(),
        };
        assert_eq!(only_fields.finish(), "id=3");

        let only_message = Rendered {
            message: "session ended".to_string(),
            fields: String::new(),
        };
        assert_eq!(only_message.finish(), "session ended");
    }
}
