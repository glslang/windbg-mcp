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
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
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
    ///
    /// **Numbered across the whole server, not per client**, and that is a deliberate limit rather
    /// than an oversight: the counter is what makes a cursor stable under eviction, and the ring
    /// cannot number per client without knowing which client each session belongs to — a fact that
    /// lives in the registry and arrives here only as [`Query::visible`], one query at a time. So a
    /// client reading two of its own records a hundred apart can tell that *something* was filed in
    /// between. It learns a count and nothing else; the records themselves, their sessions and
    /// their text stay unreachable.
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
        // What this caller may read at all, before any filter they asked for. A record about
        // *someone else's* session is not theirs to read; the supervisor's own records carry no
        // session id and stay visible to everyone, being about this process rather than about any
        // client's target.
        //
        // Everything below is counted over *this* stream rather than over the ring, because a
        // number about records the caller cannot read is still a report of another client's
        // activity: a `held` that climbs while nothing of theirs is filed says another client is
        // busy, and an `oldest_seq` that moves says its records are being evicted. Neither leaks
        // content, and both are answers to a question the boundary says a client may not ask.
        let visible: Vec<&Entry> = self
            .entries
            .iter()
            .filter(|e| match (&query.visible, e.session.as_deref()) {
                (Some(mine), Some(about)) => mine.iter().any(|id| id == about),
                _ => true,
            })
            .collect();
        let matches: Vec<&Entry> = visible
            .iter()
            .copied()
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
            // One past the newest record this caller can see, rather than one past the newest the
            // ring has filed. It still advances past everything they could have been shown — which
            // is what the cursor promises — and a caller who can see nothing keeps the cursor they
            // came with rather than being handed a count of what happened elsewhere.
            next_since: visible
                .last()
                .map_or_else(|| query.since.unwrap_or(0), |e| e.seq + 1),
            held: visible.len(),
            capacity: self.capacity,
            oldest_seq: visible.first().map(|e| e.seq),
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
/// `dropped` is what that worker's queue threw away **immediately before this record**, and it is
/// filed as a record of its own rather than folded into this one's text. A gap in the log is a fact
/// about the log, and a reader who is not told about it reads a quiet stretch as nothing having
/// happened — which is also why the count travels with the record that follows the gap rather than
/// being read as the writer sends: see [`TO_SUPERVISOR`].
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
    /// The session ids the caller owns, when the caller is one of several clients.
    ///
    /// **The ring is one buffer for the whole server**, so without this a client could read what
    /// another client's worker said — its session ids, the target it opened, whatever the debugger
    /// printed on the way to a failure. That is the boundary
    /// ([#162](https://github.com/glslang/windbg-mcp/issues/162)) leaking through a different tool
    /// than the one it was written for.
    ///
    /// `None` means "everything", which is stdio and the supervisor's own use: one client by
    /// construction, so there is nothing to separate.
    pub visible: Option<Vec<String>>,
}

/// What the ring answered with — **as this caller sees it**. Every count here is over the records
/// [`Query::visible`] admits, so a client is told about the buffer it can read rather than about
/// the buffer the server keeps.
pub struct Tail {
    /// Oldest first, which is reading order.
    pub entries: Vec<Entry>,
    /// How many matched the query before `limit` clipped it.
    pub matched: usize,
    /// Pass this as `since` next time to get only what is new. It is one past the newest record
    /// this caller can see, not the last one returned, so a query that matched nothing still
    /// advances.
    pub next_since: u64,
    /// How many records the caller can read, and how many the ring can hold in all. The capacity
    /// is a configured constant and says nothing about anyone's activity, so it stays as it is.
    pub held: usize,
    pub capacity: usize,
    /// The oldest seq this caller can still see. A `since` older than this means records were
    /// evicted between the two calls, which is the only way a reader can find out.
    pub oldest_seq: Option<u64>,
}

pub fn tail(query: &Query) -> Tail {
    ring().lock().unwrap_or_else(|e| e.into_inner()).tail(query)
}

// ---- the worker's side of the bridge ---------------------------------------

/// The worker's queue. Created by [`layer`] so a record made before the protocol channel exists
/// is held rather than lost, and drained by [`run_worker_writer`] once there is somewhere to send
/// it.
///
/// Each record travels with **however many were dropped immediately before it**, rather than the
/// writer reading a counter as it sends. The difference is where the gap is reported: a full queue
/// holds up to [`WORKER_QUEUE`] records that were made *before* the drops, so a count picked up at
/// send time lands against the oldest of those — several hundred records early, which tells a
/// reader the loss happened somewhere it did not.
static TO_SUPERVISOR: OnceLock<SyncSender<(Entry, u32)>> = OnceLock::new();
static PENDING: Mutex<Option<Receiver<(Entry, u32)>>> = Mutex::new(None);
/// Records dropped since the last one that got through, waiting to be carried by the next.
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
    for (entry, dropped) in queue {
        let usable = send(entry, dropped);
        WRITTEN.fetch_add(1, Ordering::Relaxed);
        if !usable {
            break;
        }
    }
    WRITER_GONE.store(true, Ordering::Relaxed);
}

/// Serializes taking the drop count with the insertion that carries it.
///
/// Not for the counter's sake — the atomics are sound on their own — but for *where the gap is
/// reported*. Take and insert are two steps, so without this one thread can take a run of drops,
/// be descheduled, and have another thread enqueue the true first-record-after-the-gap carrying
/// zero; the marker then lands a record or two late. A lock is affordable precisely because
/// nothing under it can wait: an atomic swap, a **non-blocking** `try_send`, an atomic add. There
/// is no I/O in the critical section, and the log-writer thread never enters it (it is muted), so
/// it cannot be held against the thread that drains it.
static HANDOFF: Mutex<()> = Mutex::new(());

/// Queues one record, carrying however many were dropped since the last one that got through.
/// `false` when the queue would not take it, which is itself a drop.
///
/// The count is **taken** before the attempt and put back if it fails, rather than read and
/// subtracted afterwards: two threads reading the same count would each attach it, and the second
/// subtraction would wrap the counter past zero into a very large number of imaginary drops.
fn enqueue(queue: Option<&SyncSender<(Entry, u32)>>, entry: Entry) -> bool {
    let _in_order = HANDOFF.lock().unwrap_or_else(|e| e.into_inner());
    let carried = DROPPED.swap(0, Ordering::Relaxed);
    let queued = match queue {
        Some(queue) => queue.try_send((entry, carried)).is_ok(),
        None => false,
    };
    if queued {
        QUEUED.fetch_add(1, Ordering::Relaxed);
    } else {
        // This record, plus whatever it was going to carry for the ones before it.
        DROPPED.fetch_add(carried.saturating_add(1), Ordering::Relaxed);
    }
    queued
}

/// Takes whatever drops are outstanding, so the caller can report them itself.
///
/// Under [`HANDOFF`] like every other transfer of this count: without it, a record being enqueued
/// concurrently could carry a run this has already taken, and the same drops would be reported
/// twice.
fn take_unreported_drops() -> u32 {
    let _in_order = HANDOFF.lock().unwrap_or_else(|e| e.into_inner());
    DROPPED.swap(0, Ordering::Relaxed)
}

/// Waits, up to `within`, for the writer to have mirrored everything queued so far.
///
/// Called by a worker on its way out. Without it the records that matter most are the ones most
/// likely to be lost: the teardown path logs *why* a target was released, and then exits the
/// process — which is not something a background thread survives.
pub fn flush(within: std::time::Duration) {
    // A run of drops is carried by the *next* record to get through, and at exit there may not be
    // one — so this is that record. Taken first, so the count is in the text even if the queue will
    // not take this one either: stderr has it regardless, which is the fallback everywhere here.
    let unreported = take_unreported_drops();
    if unreported > 0 {
        tracing::warn!(
            "worker: {unreported} log record(s) were dropped and this process is exiting, so \
             nothing later can report them; its log queue had filled"
        );
    }
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
                enqueue(
                    TO_SUPERVISOR.get(),
                    Entry {
                        seq: 0, // the supervisor's ring assigns it; this side has no sequence
                        at_ms: now_ms(),
                        level,
                        target: metadata.target().to_string(),
                        session: None, // likewise: a worker does not know its session id
                        message: clip(rendered.finish()),
                    },
                );
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

    /// The drop counter is process-wide, and two tests below drive it. `cargo test` runs them on
    /// different threads, so they take turns here rather than reading each other's arithmetic.
    static COUNTER_TESTS: Mutex<()> = Mutex::new(());

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
            visible: None,
        }
    }

    /// One ring serves the whole server, so a client may only read the records of sessions it
    /// owns. The supervisor's own records carry no session id and stay visible to everyone: they
    /// are about this process rather than about anyone's target.
    #[test]
    fn a_client_reads_only_its_own_sessions_records() {
        let mut ring = Ring::new(100);
        ring.file(
            Level::Info,
            1,
            "windbg_mcp::worker".into(),
            Some("sess-mine".into()),
            "mine".into(),
        );
        ring.file(
            Level::Info,
            2,
            "windbg_mcp::worker".into(),
            Some("sess-theirs".into()),
            "theirs".into(),
        );
        ring.file(
            Level::Info,
            3,
            "windbg_mcp::engine".into(),
            None,
            "the supervisor's".into(),
        );

        let mine = ring.tail(&Query {
            visible: Some(vec!["sess-mine".to_string()]),
            ..query()
        });
        let messages: Vec<&str> = mine.entries.iter().map(|e| e.message.as_str()).collect();
        assert_eq!(
            messages,
            vec!["mine", "the supervisor's"],
            "another client's records are not this caller's to read: {messages:?}"
        );

        // And naming their session explicitly narrows to a set this caller is not in, so it comes
        // back empty — the same answer a handle this server never issued gets.
        let theirs = ring.tail(&Query {
            session: Some("sess-theirs".to_string()),
            visible: Some(vec!["sess-mine".to_string()]),
            ..query()
        });
        assert!(theirs.entries.is_empty(), "{:?}", theirs.entries);
    }

    /// The filter is only half the boundary. A caller who is told how full the buffer is, how far
    /// its cursor has moved and what its oldest record is can watch all three climb while nothing
    /// of theirs is filed — which is a report of another client's activity, arrived at without
    /// reading a single one of its records.
    #[test]
    fn the_buffers_own_numbers_do_not_report_another_clients_activity() {
        let mut ring = Ring::new(100);
        ring.file(
            Level::Info,
            1,
            "windbg_mcp::worker".into(),
            Some("sess-mine".into()),
            "mine".into(),
        );
        let mine = Query {
            visible: Some(vec!["sess-mine".to_string()]),
            ..query()
        };
        let before = ring.tail(&mine);
        assert_eq!(before.held, 1, "one record of this caller's is in the ring");

        // A busy neighbour, filing steadily and telling this caller nothing.
        for n in 0..7 {
            ring.file(
                Level::Info,
                2,
                "windbg_mcp::worker".into(),
                Some("sess-theirs".into()),
                format!("theirs {n}"),
            );
        }
        let after = ring.tail(&Query {
            since: Some(before.next_since),
            ..mine
        });

        assert!(
            after.entries.is_empty(),
            "nothing of this caller's was filed: {:?}",
            after.entries
        );
        assert_eq!(
            after.held, before.held,
            "the buffer looked seven records fuller, so a caller polling it can count another \
             client's records without reading one"
        );
        assert_eq!(
            after.next_since, before.next_since,
            "the cursor advanced past records this caller was never shown, which is the same \
             count arriving as a gap"
        );
        assert_eq!(
            after.oldest_seq, before.oldest_seq,
            "the oldest record moved, which reports eviction pressure this caller did not cause"
        );
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
        assert!(Level::Info > wanted, "info is not at least a warning");
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

    /// A dropped run is carried by the record that **follows** it, not by whichever record the
    /// writer happens to be sending when it notices.
    ///
    /// The distinction is where the gap is reported, and it is only visible when the queue is full:
    /// a full queue holds hundreds of records made *before* the drops, so a count picked up at send
    /// time is attached to the oldest of those and tells a reader the loss happened somewhere it did
    /// not. Driven through the real `enqueue` with a queue of two, which is the same code path with
    /// the arithmetic small enough to state.
    #[test]
    fn a_dropped_run_is_carried_by_the_record_that_follows_it() {
        let _mine = COUNTER_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        let (tx, rx) = sync_channel::<(Entry, u32)>(2);
        DROPPED.store(0, Ordering::Relaxed);
        let record = |message: &str| Entry {
            seq: 0,
            at_ms: 1_700_000_000_000,
            level: Level::Info,
            target: "windbg_mcp::test".to_string(),
            session: None,
            message: message.to_string(),
        };

        // Two fit.
        assert!(enqueue(Some(&tx), record("first")));
        assert!(enqueue(Some(&tx), record("second")));
        // Three do not, and each refusal is a drop.
        for lost in ["lost a", "lost b", "lost c"] {
            assert!(!enqueue(Some(&tx), record(lost)), "the queue was full");
        }
        assert_eq!(DROPPED.load(Ordering::Relaxed), 3);

        // Draining one makes room, and the next record through carries the run.
        let (first, before_first) = rx.recv().expect("the first record");
        assert_eq!(first.message, "first");
        assert_eq!(
            before_first, 0,
            "the record *ahead* of the gap must not be blamed for it — it was made before the \
             drops, and marking it moves the reported loss hundreds of records early"
        );
        assert!(enqueue(Some(&tx), record("after the gap")));
        assert_eq!(
            DROPPED.load(Ordering::Relaxed),
            0,
            "the run was handed over, not counted twice"
        );

        let (second, _) = rx.recv().expect("the second record");
        assert_eq!(second.message, "second");
        let (after, carried) = rx.recv().expect("the record after the gap");
        assert_eq!(after.message, "after the gap");
        assert_eq!(
            carried, 3,
            "the three that were lost, reported where they were lost"
        );
    }

    /// Under concurrency, every record is either delivered or counted — never both, and never
    /// neither.
    ///
    /// This is the invariant the drop count is *for*, and the one a race would break in the way
    /// that matters: a double-counted run reports a gap that did not happen, and a lost one reports
    /// silence where records went missing. Placement can only ever be best-effort — the drops are
    /// discovered by whoever is refused next — but conservation is exact, and it is what makes the
    /// number in the marker worth printing.
    ///
    /// Driven from several threads against a queue too small for them, which is the only state in
    /// which any of this arithmetic runs at all.
    #[test]
    fn no_record_is_lost_or_counted_twice_when_threads_log_at_once() {
        const THREADS: usize = 8;
        const EACH: usize = 250;
        // Small enough that most attempts are refused, which is the arithmetic under test.
        let _mine = COUNTER_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        let (tx, rx) = sync_channel::<(Entry, u32)>(4);
        DROPPED.store(0, Ordering::Relaxed);

        // Eight writers against four slots do not *guarantee* a refusal — when the drain keeps up,
        // every attempt is taken and the run asserts conservation over the one path it exists to
        // cover. That is a vacuous pass rather than a wrong one, and it was a flake at roughly one
        // run in twenty-five. So the drain is held until a record has actually been turned away.
        //
        // A rendezvous and not a nap: with nothing draining, a queue of four must refuse the fifth
        // `enqueue`, so the gate is opened by the very thing it waits for and cannot hang — where
        // a sleep would only make the refusal *likely*, and would trade the flake for a slower
        // test that still has one.
        let (refused_tx, refused_rx) = sync_channel::<()>(1);

        // Drains as the writers work, so slots keep freeing and the full/not-full boundary is
        // crossed constantly rather than once.
        let drained = std::thread::spawn(move || {
            // `Err` only if every writer finished without one refusal, which the gate above makes
            // impossible; either way the drain proceeds and the assertions below decide.
            let _ = refused_rx.recv();
            let mut received = 0u64;
            let mut reported = 0u64;
            while let Ok((_, carried)) = rx.recv() {
                received += 1;
                reported += u64::from(carried);
            }
            (received, reported)
        });

        let writers: Vec<_> = (0..THREADS)
            .map(|thread| {
                let tx = tx.clone();
                let refused = refused_tx.clone();
                std::thread::spawn(move || {
                    for n in 0..EACH {
                        let queued = enqueue(
                            Some(&tx),
                            Entry {
                                seq: 0,
                                at_ms: 1_700_000_000_000,
                                level: Level::Info,
                                target: "windbg_mcp::test".to_string(),
                                session: None,
                                message: format!("thread {thread} record {n}"),
                            },
                        );
                        if !queued {
                            // One slot and a non-blocking send, so the first refusal opens the
                            // gate and every later one costs nothing and blocks nobody.
                            let _ = refused.try_send(());
                        }
                    }
                })
            })
            .collect();
        for writer in writers {
            writer.join().expect("a writer finished");
        }
        // The last sender, so the drain ends.
        drop(tx);
        let (received, reported) = drained.join().expect("the drain finished");
        let outstanding = u64::from(take_unreported_drops());

        assert_eq!(
            received + reported + outstanding,
            (THREADS * EACH) as u64,
            "every record made must be delivered, reported as dropped, or still awaiting a report \
             — {received} delivered + {reported} reported + {outstanding} outstanding is not \
             {} made",
            THREADS * EACH
        );
        assert!(
            reported + outstanding > 0,
            "the drain was held until a record was turned away, so refusing nothing means that \
             gate has stopped working and this is asserting conservation over a path it never took"
        );
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
