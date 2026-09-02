//! The session transcript: an opt-in, server-side JSONL record of what this server was asked and
//! what it did.
//!
//! A debugger server is the only party that sees the whole of a session — the tool call, the
//! session it was routed to, the target's answer, the state the session moved to, the worker that
//! died — and until now it recorded none of it. What existed instead were artifacts with opposite
//! problems ([#87](https://github.com/glslang/windbg-mcp/issues/87)): a client's own log, which is
//! tens of megabytes of prompts with the debugger operations buried inside shell-command source,
//! and a hand-curated proof record, which is readable and is written afterwards from memory. The
//! recordings in `examples/` say as much on their face — *"timing is illustrative because live
//! recording was not enabled for the original run"*.
//!
//! # What it is not
//!
//! It is **not the log**. `tracing` reports on the server; this reports on the *session*, and the
//! two answer to different readers. A log line is prose for whoever is debugging this server; a
//! record here is a value, keyed by session and request, for a program that has to reconstruct
//! what happened — or for [`crate::cast`], which renders the same stream as a terminal recording.
//!
//! # Where the records come from
//!
//! Every one is written by the **supervisor**. That is not a limitation: a worker's facts reach
//! here as the typed half of its reply ([`crate::proto::Output::data`]), built on the side of the
//! pipe where the engine's own types are in hand. So a stop position, a batch's verdict and its
//! rollback state are recorded from [`crate::structured`] values — never re-read out of the
//! rendering, which would measure the rendering ([#77](https://github.com/glslang/windbg-mcp/issues/77)).
//!
//! A worker inherits [`TRANSCRIPT_ENV`] like any other variable and never acts on it: the role
//! check in [`crate::main`] runs before the server is built, so [`Recorder::from_env`] is only ever
//! reached by the supervisor. One server is therefore one writer, and within it the file lock in
//! [`Recorder::write`] is what makes the record order and the line order the same order.
//!
//! **Two servers can still share a path**, because the file is opened for append and nothing
//! stops an operator pointing both at it. Their lines then interleave, which is why every record
//! carries a [`Record::run`] and not just the `start` line: grouping by it is what keeps two
//! independently numbered sessions from being read as one.
//!
//! # Safety properties, and why each one is here
//!
//! * **Opt-in.** Nothing is written unless [`TRANSCRIPT_ENV`] names a path. A debugger's output is
//!   the contents of somebody's memory, and it is not this server's to spill into a file by
//!   default.
//! * **Never the MCP transport.** The process's standard output is JSON-RPC. This writes to its
//!   own file, opened here, and to nothing else — a test in this module holds that line by
//!   reading the source.
//! * **Redacted.** Every string that goes in passes [`kdconn::scrub`], which masks a secret this
//!   server has been handed **by value** — in any syntax, that being the guarantee — and scans for
//!   `key=`/`password=` as a best-effort net under it. An argument member *named* like a secret is
//!   masked whole. Profiles keep a key out of the request in the first place; this covers a caller
//!   who passed a raw `connection` anyway.
//! * **Bounded, and says so.** A rendering can be megabytes. Fields are capped at
//!   [`FIELD_LIMIT_ENV`] bytes and the record says how much was dropped, rather than being
//!   silently short — a transcript that quietly truncates is worse than one that does not exist,
//!   because it reads as complete. A whole record is bounded too
//!   ([`Recorder::over_ceiling`]), which is what holds the promise for a field somebody forgot.
//! * **Parseable after a crash.** One record is one `write_all` to a file opened for append, with
//!   no buffering in this process, so an abrupt exit leaves whole records behind it.

use std::fs::OpenOptions;
use std::future::Future;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::kdconn;
use crate::structured::{
    BatchReportInfo, BreakpointSet, ErrorCategory, Outcome, RunToReport, StopReport,
};

/// Names the file to record into. Absent — the ordinary case — and nothing is recorded at all.
pub const TRANSCRIPT_ENV: &str = "WINDBG_MCP_TRANSCRIPT";

/// Overrides [`DEFAULT_FIELD_LIMIT`], in bytes. `0` means no cap.
pub const FIELD_LIMIT_ENV: &str = "WINDBG_MCP_TRANSCRIPT_MAX_FIELD";

/// How much of one field is kept before it is truncated.
///
/// Chosen against what the fields actually hold. A typed answer is facts and is far under it; a
/// rendering is what runs long — a module table, a pool census, a batch of a thousand steps — and
/// 16 KiB is several screens of one. The whole point of the cap is that a transcript stays a
/// record of the session rather than becoming a second copy of every byte the debugger printed,
/// which is the failure the client's own log already demonstrates.
const DEFAULT_FIELD_LIMIT: usize = 16 * 1024;

/// The record format's version, carried on every line so a reader never has to guess.
pub const SCHEMA: u32 = 1;

/// Headroom over the field cap for a whole record: its envelope, and the several capped fields
/// one can carry. See [`Recorder::over_ceiling`].
const RECORD_OVERHEAD: usize = 4096;

// ---- the sink -------------------------------------------------------------

/// A transcript sink. Cheap to clone and to call when disabled, which is the common case.
#[derive(Clone)]
pub struct Recorder(Option<Arc<Sink>>);

/// Renders as where it is writing, and nothing else. A `Debug` that dumped the open file handle
/// and the counters would be noise in every `{:?}` of a [`crate::engine::Session`], which is the
/// only place this is ever printed.
impl std::fmt::Debug for Recorder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.path() {
            Some(path) => write!(f, "Recorder({})", path.display()),
            None => f.write_str("Recorder(off)"),
        }
    }
}

struct Sink {
    /// The open file. A `Mutex` rather than a channel because a record must be *on disk* before
    /// the call that produced it returns — a queue would lose the tail of a session precisely
    /// when the server is going down, which is when a transcript earns its keep.
    file: Mutex<std::fs::File>,
    path: PathBuf,
    /// Which run this is, on every record it writes. See [`Record::run`].
    run: u64,
    /// Where `mono_ms` is measured from: this server's start, not the wall clock, so a record's
    /// ordering survives a clock that steps.
    started: Instant,
    limit: usize,
    seq: AtomicU64,
    request: AtomicU64,
}

impl Recorder {
    /// A recorder that writes nothing — for every run that did not ask for one, and for tests
    /// that are not about recording.
    pub fn disabled() -> Self {
        Self(None)
    }

    /// Reads [`TRANSCRIPT_ENV`] and opens the file it names.
    ///
    /// A path that cannot be opened is **loud but not fatal**: an operator who asked for a
    /// transcript and silently got none is badly served, and a debug session refused because a log
    /// file would not open is served worse. So it reports the failure and runs without one.
    pub fn from_env() -> Self {
        let Some(path) = std::env::var_os(TRANSCRIPT_ENV).filter(|p| !p.is_empty()) else {
            return Self::disabled();
        };
        let limit = configured_field_limit();
        match Self::to_file(Path::new(&path), limit) {
            Ok(recorder) => {
                tracing::info!(
                    "recording a session transcript to {} (fields capped at {})",
                    Path::new(&path).display(),
                    match limit {
                        0 => "no limit".to_string(),
                        n => format!("{n} bytes"),
                    }
                );
                recorder
            }
            Err(e) => {
                tracing::error!(
                    "{TRANSCRIPT_ENV} names `{}`, which could not be opened for recording ({e}); \
                     this session is NOT being recorded",
                    Path::new(&path).display()
                );
                Self::disabled()
            }
        }
    }

    /// Opens `path` for append and writes the header record.
    ///
    /// Append rather than truncate: two servers pointed at one path, or a second run of the same
    /// one, must not silently erase what is already there. Which run wrote which line is then
    /// [`Record::run`]'s job — on every record, because two servers appending at once interleave
    /// theirs and a marker at the top of each run would only be able to describe a file whose
    /// runs do not overlap.
    pub fn to_file(path: &Path, limit: usize) -> std::io::Result<Self> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        let recorder = Self(Some(Arc::new(Sink {
            file: Mutex::new(file),
            path: path.to_path_buf(),
            run: mint_run_id(),
            started: Instant::now(),
            limit,
            seq: AtomicU64::new(0),
            request: AtomicU64::new(0),
        })));
        recorder.write(Event::Start {
            version: crate::BUILD_VERSION.to_string(),
            pid: std::process::id(),
            field_limit: limit,
            schema: SCHEMA,
        });
        Ok(recorder)
    }

    pub fn enabled(&self) -> bool {
        self.0.is_some()
    }

    /// Where records are going, for a caller that has to report it.
    pub fn path(&self) -> Option<&Path> {
        self.0.as_ref().map(|s| s.path.as_path())
    }

    /// Records `event`, stamped and numbered. Does nothing when disabled.
    ///
    /// **The lock is taken before the record is built, not after.** Numbering and stamping outside
    /// it would make `seq` and `mono_ms` an order of their own, different from the order the lines
    /// land in: two threads recording at once can be numbered one way and preempted into writing
    /// the other. A reader then has a file whose lines disagree with their own sequence numbers,
    /// and a cast rendered from it has times that go backwards — which a player refuses. Inside
    /// the lock, the two orders are the same order by construction.
    ///
    /// It costs serializing a small record while holding the lock. That is the right side to pay
    /// on: this contends only with other records, never with a debugger operation.
    pub fn write(&self, event: Event) {
        let Some(sink) = &self.0 else { return };
        let mut file = sink.file.lock().unwrap_or_else(|e| e.into_inner());
        let record_seq = sink.seq.fetch_add(1, Ordering::Relaxed);
        // Read before the event moves into the record, for the marker below.
        let kind = name_of(&event);
        let record = Record {
            v: SCHEMA,
            run: sink.run,
            seq: record_seq,
            at: rfc3339(SystemTime::now()),
            mono_ms: ms(sink.started.elapsed()),
            event,
        };
        // A record that will not serialize is a bug in an event type, not a debugger failure, and
        // it must not cost the caller anything. It is still worth saying loudly: a transcript
        // missing a line it should have is exactly the sort of thing this file is trusted about.
        let mut line = match serde_json::to_string(&record) {
            Ok(line) => line,
            Err(e) => {
                tracing::error!("a transcript record did not serialize: {e}");
                return;
            }
        };
        // The backstop under the per-field caps. Those are applied field by field, by hand, and
        // three rounds of review each found a field that had been missed — the derived batch
        // details, a session's target, a caller's handle. Every one of them was a *new* place to
        // remember, which is a losing shape. This bounds the record itself, so a field nobody
        // capped — including one added later — cannot put an unbounded line in the file. It
        // reports what it dropped rather than dropping it silently, and it is deliberately far
        // above what a well-capped record reaches, so it fires only when something slipped past.
        if let Some(bytes) = self.over_ceiling(&line) {
            tracing::warn!(
                "a transcript record of kind `{kind}` was {bytes} bytes, past the whole-record \
                 ceiling, and was replaced by a marker: a field of it is not being capped"
            );
            let marker = Record {
                v: SCHEMA,
                run: sink.run,
                seq: record_seq,
                at: record.at,
                mono_ms: record.mono_ms,
                event: Event::Oversized { of: kind, bytes },
            };
            match serde_json::to_string(&marker) {
                Ok(replacement) => line = replacement,
                Err(e) => {
                    tracing::error!("an oversized-record marker did not serialize: {e}");
                    return;
                }
            }
        }
        line.push('\n');
        // One `write_all` per record, on a file opened for append and with no buffer in front of
        // it: that is what leaves a parseable prefix behind an abrupt exit.
        if let Err(e) = file.write_all(line.as_bytes()) {
            tracing::error!("could not write a transcript record: {e}");
        }
    }

    /// How big a serialized record is, if that is past the whole-record ceiling.
    ///
    /// The ceiling is the field cap with room for the several capped fields a record can hold and
    /// its envelope — generous on purpose. It is not the bound the documentation promises, which
    /// is per field; it is the thing that makes that promise hold even where a field was missed.
    /// `None` when the cap is off, which is an operator asking for everything.
    fn over_ceiling(&self, line: &str) -> Option<usize> {
        match self.limit() {
            0 => None,
            limit => {
                let ceiling = limit.saturating_mul(8).saturating_add(RECORD_OVERHEAD);
                (line.len() > ceiling).then_some(line.len())
            }
        }
    }

    // ---- tool calls -------------------------------------------------------

    /// Records a tool request and returns the handle its result is recorded against.
    ///
    /// The handle carries the start instant, so the elapsed time on the result is measured across
    /// the call rather than recomputed from two wall-clock stamps that a clock step could reorder.
    pub fn tool_request(&self, tool: &str, args: Option<&Value>) -> InFlight {
        let Some(sink) = &self.0 else {
            return InFlight::untracked();
        };
        let request = sink.request.fetch_add(1, Ordering::Relaxed) + 1;
        // The session a call names is worth having on the *request*, not only on the result: a
        // call that never comes back is one this is the only record of.
        //
        // Scrubbed, like the argument object it is lifted out of. A handle this server issued is
        // `sess-…` and holds nothing — but this is whatever the *caller* sent, and the case the
        // backstop exists for is precisely a caller who put a connection string somewhere it does
        // not belong. `kdconn` already refuses that mistake in `profile` *without echoing it*; a
        // copy taken before the scrub would write it to a file instead. It survives to the result
        // too, because a handle that does not resolve is never replaced by a routed one.
        let session = args
            .and_then(|a| a.get("session_id"))
            .and_then(Value::as_str)
            .map(|id| Capped::of(&kdconn::scrub(id), self.limit()).text);
        self.write(Event::ToolRequest {
            request,
            tool: tool.to_string(),
            session: session.clone(),
            args: args.map(|a| self.payload(scrubbed(a))),
        });
        InFlight {
            request,
            tool: tool.to_string(),
            session,
            at: Instant::now(),
        }
    }

    /// Records a tool result, and whatever the typed half of it says happened.
    ///
    /// `data` is the same structured content the client receives. Reading the derived events out
    /// of it is a *typed* read — [`derived`] deserializes the payload each tool declares — not a
    /// scrape of the text beside it.
    pub fn tool_result(&self, call: InFlight, is_error: bool, text: &str, data: Option<&Value>) {
        if self.0.is_none() {
            return;
        }
        let scrubbed_data = data.map(scrubbed);
        self.write(Event::ToolResult {
            request: call.request,
            tool: call.tool.clone(),
            session: call.session.clone(),
            elapsed_ms: ms(call.at.elapsed()),
            verdict: if is_error {
                Verdict::Error
            } else {
                Verdict::Ok
            },
            category: scrubbed_data.as_ref().and_then(category_of),
            // Scrubbed *then* capped, and the order is load-bearing: cutting first can leave the
            // front of a secret behind, because the cut lands wherever the byte count says and a
            // `key=1.2` is a key partly disclosed. Scrubbing first costs a scan of a rendering
            // that may be megabytes, which is the right side to pay on.
            text: Capped::of(&kdconn::scrub(text), self.limit()),
            // Cloned only when the value is small enough to keep; the marker branch does not
            // clone at all. `derived` reads the same value below without taking a copy either.
            data: scrubbed_data.as_ref().map(|d| self.payload_of(d)),
        });
        if let Some(data) = &scrubbed_data {
            for event in derived(&call, data, self.limit()) {
                self.write(event);
            }
        }
    }

    // ---- fields -----------------------------------------------------------

    /// How many bytes of one field this transcript keeps. `0` is no cap.
    ///
    /// Public because the supervisor writes events of its own ([`crate::engine`]) and has to cap
    /// them to the same figure. A caller that picked its own would be a second answer to "how big
    /// may a record be", which is the sort of thing that stays right until someone reads the
    /// documentation and believes it.
    pub fn field_limit(&self) -> usize {
        self.0.as_ref().map_or(DEFAULT_FIELD_LIMIT, |s| s.limit)
    }

    fn limit(&self) -> usize {
        self.field_limit()
    }

    /// A JSON value as a capped field: itself, or a marker naming what was dropped.
    ///
    /// A value is kept whole or not at all, unlike text: half a JSON object is not a smaller JSON
    /// object, and a reader that had to cope with both would be parsing a shape this cannot
    /// promise. The marker is an object so it can never be mistaken for the payload.
    fn payload(&self, value: Value) -> Value {
        match self.dropped_bytes(&value) {
            Some(size) => serde_json::json!({ "transcript_dropped_bytes": size }),
            None => value,
        }
    }

    /// [`Self::payload`] for a value the caller still needs.
    fn payload_of(&self, value: &Value) -> Value {
        match self.dropped_bytes(value) {
            Some(size) => serde_json::json!({ "transcript_dropped_bytes": size }),
            None => value.clone(),
        }
    }

    /// How big `value` is, if that is over the cap. `None` means it fits.
    fn dropped_bytes(&self, value: &Value) -> Option<usize> {
        // A value that will not serialize is dropped rather than kept. Kept, it takes the whole
        // record down with it in [`Self::write`] — the same serialization fails there — and a
        // missing line is worse than a marker saying a payload could not be measured.
        let Ok(rendered) = serde_json::to_string(value) else {
            return Some(0);
        };
        match self.limit() {
            0 => None,
            limit => (rendered.len() > limit).then_some(rendered.len()),
        }
    }
}

/// A tool call in flight: what its result will be recorded against.
pub struct InFlight {
    request: u64,
    tool: String,
    session: Option<String>,
    at: Instant,
}

impl InFlight {
    /// The handle a disabled recorder hands back. Its request number is zero, which no recorded
    /// request ever is.
    fn untracked() -> Self {
        Self {
            request: 0,
            tool: String::new(),
            session: None,
            at: Instant::now(),
        }
    }

    /// Names the session this call was actually **routed** to, which is not always the one it
    /// named.
    ///
    /// A caller that omits `session_id` is not saying "no session" — it is accepting whatever the
    /// current one is ([`crate::engine::Sessions::resolve`]), which is the ordinary way this
    /// server is driven. Recording the argument alone would put `null` on every such call and on
    /// every event derived from it, so with more than one target open a transcript could not say
    /// which one was read or changed. The request record is already written by then, deliberately:
    /// it is stamped when the call *arrived*, and routing had not happened yet.
    pub fn routed_to(&mut self, session: Option<String>) {
        if let Some(session) = session {
            self.session = Some(session);
        }
    }
}

// ---- which session a call reached ------------------------------------------

tokio::task_local! {
    /// Where the tool call running on this task was routed.
    ///
    /// A task-local rather than a return value because the answer is discovered deep inside the
    /// call — [`crate::engine::Sessions::resolve`] picks the current session for anyone who named
    /// none — and is wanted by the recorder, forty-odd tool bodies further out. Threading it back
    /// would mean changing the signature of every one of them to carry a fact none of them uses.
    static ROUTED: Mutex<Option<String>>;
}

/// Runs `work` with somewhere to note the session it reaches, and hands back both.
pub async fn tracking_route<F: Future>(work: F) -> (F::Output, Option<String>) {
    ROUTED
        .scope(Mutex::new(None), async move {
            let outcome = work.await;
            let routed = ROUTED.with(|r| r.lock().unwrap_or_else(|e| e.into_inner()).clone());
            (outcome, routed)
        })
        .await
}

/// Notes that the work on this task reached `session`.
///
/// Called from **resolution** rather than from each tool, which is what makes it hard to forget:
/// a tool that resolves a session by any route is recorded, including the two that do it by hand
/// instead of going through `run_call`. Silent outside a scope, because the in-process tests call
/// tool bodies directly and a missing transcript is not a reason to fail a debug call.
pub fn routed_to(session: &str) {
    let _ = ROUTED.try_with(|routed| {
        *routed.lock().unwrap_or_else(|e| e.into_inner()) = Some(session.to_string());
    });
}

// ---- the records ----------------------------------------------------------

/// One line of the transcript: the envelope every event shares.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    /// The format version, on every line rather than only in the header — a reader that starts
    /// mid-file, or in the middle of a second run appended to the first, still knows what it has.
    pub v: u32,
    /// Which run of this server wrote the line, unique among the runs that could be sharing the
    /// file.
    ///
    /// On **every** record, not only on `start`, because two supervisors can be pointed at one
    /// path and this file is opened for append — which is a thing [`Recorder::to_file`] allows on
    /// purpose. Their records then interleave, and with the run named only once a reader would
    /// take everything after the later `start` as one run, mixing two sets of `seq`, `request` and
    /// session identifiers that were each numbered from scratch. Grouping by this field is what
    /// makes such a file readable rather than merely present.
    ///
    /// Defaulted for a transcript written before this field existed; all of its records then share
    /// run `0` and are segmented by their `start` records instead.
    #[serde(default)]
    pub run: u64,
    /// Position in this run, from zero. What orders records that share a millisecond.
    pub seq: u64,
    /// Wall clock, RFC 3339 in UTC. For a person, and for lining a transcript up against other
    /// evidence.
    pub at: String,
    /// Milliseconds since this run started. Monotonic, so this is what a renderer measures
    /// intervals with — a wall clock can step, and an asciicast whose times went backwards would
    /// not play.
    pub mono_ms: u64,
    #[serde(flatten)]
    pub event: Event,
}

/// Whether a tool call reported success.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Ok,
    Error,
}

/// A text field, and what was left out of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capped {
    pub text: String,
    /// Bytes dropped from the end. Absent when nothing was — which is the ordinary case, and
    /// keeping the key out of it is what makes a truncated field visible at a glance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dropped: Option<usize>,
}

impl Capped {
    /// `text` if it fits, else as much of it as does — cut at a character boundary, because a
    /// record has to be valid JSON and half a character is not a character.
    pub fn of(text: &str, limit: usize) -> Self {
        if limit == 0 || text.len() <= limit {
            return Self {
                text: text.to_string(),
                dropped: None,
            };
        }
        let mut end = limit;
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        Self {
            text: text[..end].to_string(),
            dropped: Some(text.len() - end),
        }
    }
}

/// What happened. One variant per thing worth recording, tagged on `event`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    /// The first record of a run. Its pid is what tells two runs apart in one appended-to file.
    Start {
        version: String,
        pid: u32,
        field_limit: usize,
        schema: u32,
    },
    /// A tool call arrived.
    ToolRequest {
        request: u64,
        tool: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        args: Option<Value>,
    },
    /// It answered.
    ToolResult {
        request: u64,
        tool: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session: Option<String>,
        elapsed_ms: u64,
        verdict: Verdict,
        /// The failure's kind, where the typed half named one. What a reader counts failures by
        /// without matching on wording.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        category: Option<ErrorCategory>,
        text: Capped,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        data: Option<Value>,
    },
    /// A session was opened, and a worker process is holding it.
    SessionOpen {
        session: String,
        kind: String,
        /// What was opened, already redacted where it is a connection — this is the session's own
        /// label, which is built masked (see [`kdconn::select`]).
        ///
        /// Capped like everything else: a `launch` target is a whole command line, and it is the
        /// caller's.
        target: Capped,
        engine_pid: u32,
    },
    /// A session moved. Every transition goes through one place in the supervisor, so this covers
    /// an open landing, a handle being retired, a failed open and a worker's death alike.
    SessionState {
        session: String,
        state: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<Capped>,
    },
    /// A session was released. `released` is the fact that matters: false means the worker was
    /// killed still holding its target, which for a live kernel means a machine left halted.
    SessionEnd {
        session: String,
        released: bool,
        worker_terminated: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        waited_ms: Option<u64>,
    },
    /// The engine process holding a session is gone, and the calls it owed replies to are being
    /// failed out.
    WorkerLost { session: String, detail: Capped },
    /// A wait was abandoned. The job itself was not cancelled — it may still be running — which is
    /// why this is its own event and not a failed result.
    CallTimeout { session: String, budget_ms: u64 },
    /// Someone Ctrl+Broke a session's engine.
    Interrupt {
        session: String,
        /// Whether the worker acknowledged it.
        delivered: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<Capped>,
    },
    /// A target was resumed and stopped again. Derived from the tool's own typed answer.
    ///
    /// The resume itself has no event of its own: the `tool_request` immediately before this *is*
    /// the resume, stamped at the instant the target was let go, and a second record saying the
    /// same thing at the same time would be a fact counted twice. What this adds is the half the
    /// request cannot know — where it ended up, and whether it got there on its own.
    Stop {
        request: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session: Option<String>,
        /// The debugger command that moved it.
        command: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stopped_at: Option<String>,
        /// Whether it was broken into on request rather than stopping on its own.
        interrupted: bool,
        /// Whether the call's own wait ran out with the target still going, so the debugger broke
        /// it in at the bound.
        ///
        /// Kept apart from `interrupted` for the reason the whole transcript exists:
        /// both mean the position is real and is *not* a stop the target reached, and they need
        /// opposite next moves — one had a cause outside the session, the other means the target
        /// wanted longer. Defaulted, so a transcript written before this field reads back.
        #[serde(default)]
        timed_out: bool,
        /// Whether the target **ended** rather than stopping — it ran to completion, or the
        /// command released it.
        ///
        /// The one stop that is terminal, and without it a transcript cannot tell it from an
        /// ordinary one: it carries no position, like a module-load break, and both flags above
        /// are false, like an ordinary stop. A reader would see a locationless stop followed by
        /// every later call being refused, with nothing joining the two. Defaulted, so a
        /// transcript written before this field reads back.
        #[serde(default)]
        target_gone: bool,
    },
    /// A `run_to_address` verdict.
    RunTo {
        request: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session: Option<String>,
        verdict: String,
        target: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stopped_at: Option<String>,
    },
    /// Something about the target changed. The event an operator reading a transcript after the
    /// fact is looking for: what did this session leave behind?
    Mutation {
        request: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session: Option<String>,
        /// What kind of change — `breakpoint`, or a batch step's own description.
        kind: String,
        detail: Capped,
        /// For a batch step: which block it was in and where. Capped like the rest, because the
        /// label inside it is the caller's own string.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        step: Option<Capped>,
    },
    /// An assertion inside a transactional batch did not hold. Its own record because it is the
    /// fact that decided the transaction, and a reader should not have to walk the step list to
    /// find it.
    Assertion {
        request: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session: Option<String>,
        step: Capped,
        detail: Capped,
    },
    /// How a transactional batch ended, and whether it put everything back.
    Batch {
        request: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session: Option<String>,
        outcome: String,
        /// The 1-based position it stopped at, absent when it committed. `at_step` rather than
        /// the payload's own `at`, because these events are flattened into a record whose `at` is
        /// the wall clock — two fields of that name would be one field, and JSON would not say
        /// which.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        at_step: Option<u32>,
        committed: bool,
        /// Whether the `always` block completed. The one an unattended run is read for.
        rollback_complete: bool,
        /// What the session holds now: `stopped`, `running`, `detached`, `uncertain`.
        after: String,
        elapsed_ms: u64,
    },
    /// The server is going down and every session is being let go.
    Shutdown { sessions: usize },
    /// A client stayed away past its grace, and the sessions it opened were let go — but the
    /// server is still running and will serve the next client.
    ///
    /// Distinct from [`Self::Shutdown`] rather than a reason on it, because the two answer
    /// different questions about a transcript that stops: one says the recording ended, the other
    /// says this client's work did while the file goes on.
    LeaseExpired { sessions: usize },
    /// A record that would have been past the whole-record ceiling, replaced by its size.
    ///
    /// Present so that a field which is not being capped shows up as a **fact in the transcript**
    /// rather than as an enormous line. Seeing one means this module has a bug, not that the
    /// session did something unusual — `of` names the event kind to look at.
    Oversized { of: String, bytes: usize },
}

// ---- deriving the typed events --------------------------------------------

/// The events a tool's typed answer implies, read as values.
///
/// Keyed on the tool name because the name is what says which type the payload is — the same
/// mapping `output_schema` declares in [`crate::server`]. A tool that is not here contributes its
/// `tool_result` and nothing more, which is the honest answer: this server cannot know what an
/// arbitrary `execute` command did to the target, and inventing a `mutation` event by matching on
/// command text would be a guess wearing a value's clothes.
fn derived(call: &InFlight, data: &Value, limit: usize) -> Vec<Event> {
    let request = call.request;
    let session = call.session.clone();
    match call.tool.as_str() {
        "go" | "step_over" | "step_into" | "step_back" | "step_over_back" | "reverse_go" => {
            let Some(stop) = typed::<StopReport>(data) else {
                return Vec::new();
            };
            vec![Event::Stop {
                request,
                session,
                command: stop.command,
                stopped_at: stop.stopped_at,
                interrupted: stop.interrupted,
                timed_out: stop.timed_out,
                target_gone: stop.target_gone,
            }]
        }
        "run_to_address" => {
            let Some(run) = typed::<RunToReport>(data) else {
                return Vec::new();
            };
            vec![Event::RunTo {
                request,
                session,
                verdict: name_of(&run.verdict),
                target: run.target,
                stopped_at: run.stopped_at,
            }]
        }
        "set_breakpoint" => {
            let Some(set) = typed::<BreakpointSet>(data) else {
                return Vec::new();
            };
            // Only what this call changed. The rest of the list is state, not a change, and a
            // transcript that recorded the whole list as a mutation would report the same
            // breakpoint again every time another one was set.
            //
            // **A replacement is a mutation too**, and the one a reader is most likely to be
            // hunting for: a breakpoint that stopped firing because a later call took its address.
            // It is recorded beside the set rather than folded into its sentence, so the ids the
            // transcript says went away are greppable.
            let mut events = vec![Event::Mutation {
                request,
                session: session.clone(),
                kind: "breakpoint".to_string(),
                detail: Capped::of(&breakpoint_detail(&set), limit),
                step: None,
            }];
            events.extend(set.replaced.iter().map(|id| Event::Mutation {
                request,
                session: session.clone(),
                kind: "breakpoint".to_string(),
                detail: Capped::of(
                    &format!(
                        "breakpoint {id} removed — replaced by breakpoint {} at the same address",
                        set.breakpoint.id
                    ),
                    limit,
                ),
                step: None,
            }));
            events
        }
        "debug_batch" => batch_events(request, session, data, limit),
        _ => Vec::new(),
    }
}

/// A batch's verdict, the assertion that decided it, and everything it changed.
///
/// Every field here is capped like any other, and the step label is the reason it has to be: it is
/// the *caller's* string, of whatever length they sent, and a batch of a thousand labelled steps
/// would otherwise produce a thousand unbounded lines beside a payload the cap had already
/// replaced with a marker.
fn batch_events(request: u64, session: Option<String>, data: &Value, limit: usize) -> Vec<Event> {
    let Some(report) = typed::<BatchReportInfo>(data) else {
        return Vec::new();
    };
    let mut events = Vec::new();
    for (block, steps) in [("steps", &report.steps), ("always", &report.always)] {
        for step in steps {
            let at = Capped::of(&format!("{block}[{}] {}", step.position, step.label), limit);
            // Recorded whether or not the step then succeeded: a command that errors may already
            // have written, which is exactly when a record of it matters.
            if let Some(changes) = &step.changes {
                events.push(Event::Mutation {
                    request,
                    session: session.clone(),
                    kind: "batch_step".to_string(),
                    detail: Capped::of(changes, limit),
                    step: Some(at.clone()),
                });
            }
            if step.result == crate::structured::StepResultName::Unmet {
                events.push(Event::Assertion {
                    request,
                    session: session.clone(),
                    step: at,
                    detail: Capped::of(step.detail.as_deref().unwrap_or_default(), limit),
                });
            }
        }
    }
    events.push(Event::Batch {
        request,
        session,
        outcome: name_of(&report.outcome),
        at_step: report.at,
        committed: report.committed,
        rollback_complete: report.rollback_complete,
        after: name_of(&report.after),
        elapsed_ms: report.elapsed_ms,
    });
    events
}

/// The payload of a successful outcome, or `None` for a failure or a shape that is not this one.
///
/// Both are ordinary. A tool that failed carries the error branch, and a client of a *future*
/// version may see a payload this build cannot read — neither is worth losing the `tool_result`
/// record over, so this returns nothing rather than reporting an error nobody can act on.
/// Deserialized from a borrow, not from a clone: a payload can be the whole of a pool census, and
/// the recorder already holds it.
fn typed<'a, T: Deserialize<'a>>(data: &'a Value) -> Option<T> {
    match Outcome::<T>::deserialize(data) {
        Ok(Outcome::Ok(payload)) => Some(payload),
        _ => None,
    }
}

/// The failure category a result's typed half names, when it names one.
fn category_of(data: &Value) -> Option<ErrorCategory> {
    match Outcome::<serde::de::IgnoredAny>::deserialize(data).ok()? {
        Outcome::Error(failure) => Some(failure.error.category),
        Outcome::Ok(_) => None,
    }
}

/// The serde name of an enum variant — `"stopped_elsewhere"`, `"committed"` — taken from its own
/// serialization rather than written out a second time here, so a renamed variant cannot leave a
/// stale spelling behind in the transcript.
fn name_of<T: Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(Value::String(name)) => name,
        // A tagged object: the discriminator is the name. The tags this crate uses, in the one
        // place that has to know all of them.
        Ok(Value::Object(map)) => ["event", "state", "kind", "status", "reason"]
            .iter()
            .find_map(|tag| map.get(*tag).and_then(Value::as_str))
            .unwrap_or("unknown")
            .to_string(),
        _ => "unknown".to_string(),
    }
}

/// How one added breakpoint reads in a transcript: where it will fire, and what it is.
fn breakpoint_detail(set: &BreakpointSet) -> String {
    // Read off the breakpoint the engine reported, not found by id in the listing. That search
    // used to have a miss to handle — "the session's list could not be read back" — and it is
    // gone: the mutation and the inspection are different fields now, so a failed listing cannot
    // reach this at all.
    let bp = &set.breakpoint;
    let at = bp
        .address
        .as_deref()
        .or(bp.expression.as_deref())
        .unwrap_or("an unresolved location");
    let deferred = if bp.deferred { ", deferred" } else { "" };
    let command = match &bp.command {
        Some(command) => format!(", running {command:?} on each hit"),
        None => String::new(),
    };
    format!("breakpoint {} at {at}{deferred}{command}", bp.id)
}

// ---- redaction ------------------------------------------------------------

/// Every string in a value, scrubbed — and any member *named* like a secret masked whole.
///
/// Two rules because there are two ways a secret arrives. A connection string is a string leaf
/// that happens to contain `key=…`, which [`kdconn::scrub`] finds. A member named `key` is a
/// secret by its name, whatever its value looks like — and no tool in this server has one today,
/// which is exactly why the rule belongs here rather than being left for the first one that does.
fn scrubbed(value: &Value) -> Value {
    match value {
        Value::String(s) => Value::String(kdconn::scrub(s)),
        Value::Array(items) => Value::Array(items.iter().map(scrubbed).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(name, value)| {
                    let value = match kdconn::is_secret_name(name) {
                        true => Value::String(kdconn::MASK.to_string()),
                        false => scrubbed(value),
                    };
                    (name.clone(), value)
                })
                .collect(),
        ),
        other => other.clone(),
    }
}

// ---- odds and ends --------------------------------------------------------

/// The cap this host's environment asks for, or [`DEFAULT_FIELD_LIMIT`].
fn configured_field_limit() -> usize {
    std::env::var(FIELD_LIMIT_ENV)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(DEFAULT_FIELD_LIMIT)
}

fn ms(d: Duration) -> u64 {
    d.as_millis().min(u128::from(u64::MAX)) as u64
}

/// An identifier for this run: distinct from any other run that could be appending to the same
/// file at the same time, and from the run before it in a file that reuses a pid.
///
/// The wall clock in nanoseconds, mixed with the pid. Neither alone is enough — two processes can
/// start in the same nanosecond about as easily as a pid is reused, which is to say rarely, and a
/// transcript is not the place to rely on rarely.
fn mint_run_id() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64);
    nanos ^ ((std::process::id() as u64) << 48)
}

/// A wall-clock instant as RFC 3339 in UTC, to the millisecond.
///
/// Written out rather than pulled in: the crate has no date dependency, this is the only place
/// that needs one, and the arithmetic below is the whole of it. Days are converted with the
/// civil-from-days algorithm, which is exact for every date a file's timestamp can hold.
pub fn rfc3339(at: SystemTime) -> String {
    let since = at.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
    let secs = since.as_secs();
    let (days, rem) = ((secs / 86_400) as i64, secs % 86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60,
        since.subsec_millis()
    )
}

/// A stamp this module wrote, read back as seconds since the epoch.
///
/// The inverse of [`rfc3339`], and it parses only the shape that function emits — this is for
/// reading *this* server's own transcripts ([`crate::cast`] needs a header timestamp), not for
/// accepting RFC 3339 in general, which has offsets and fractional widths nothing here produces.
/// `None` for anything else, so a hand-edited or truncated stamp is skipped rather than guessed at.
pub fn unix_seconds(at: &str) -> Option<u64> {
    let (date, rest) = at.split_once('T')?;
    let time = rest.strip_suffix('Z')?;
    let mut date = date.splitn(3, '-');
    let (y, m, d): (i64, u32, u32) = (
        date.next()?.parse().ok()?,
        date.next()?.parse().ok()?,
        date.next()?.parse().ok()?,
    );
    let mut clock = time.split(':');
    let (hh, mm): (u64, u64) = (clock.next()?.parse().ok()?, clock.next()?.parse().ok()?);
    let ss: u64 = clock.next()?.split('.').next()?.parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    let days = days_from_civil(y, m, d);
    u64::try_from(days.checked_mul(86_400)?)
        .ok()?
        .checked_add(hh * 3600 + mm * 60 + ss)
}

/// A civil date as days since 1970-01-01 — [`civil_from_days`] the other way round, and the same
/// era shift.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = y - i64::from(m <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = i64::from(if m > 2 { m - 3 } else { m + 9 });
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Days since 1970-01-01 as a civil date. Howard Hinnant's algorithm, shifted to an era starting
/// in March so a leap day is the last day of the year and needs no special case.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (y + i64::from(m <= 2), m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reads a transcript back the way a consumer has to: one JSON object per line.
    fn records(path: &Path) -> Vec<Record> {
        std::fs::read_to_string(path)
            .expect("the transcript exists")
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|line| {
                serde_json::from_str(line)
                    .unwrap_or_else(|e| panic!("a transcript line is not a record ({e}): {line}"))
            })
            .collect()
    }

    /// A recorder writing into a fresh file under the test's own temporary directory.
    fn recorder(name: &str) -> (Recorder, PathBuf) {
        let path = std::env::temp_dir()
            .join("windbg-mcp-transcript-tests")
            .join(format!("{name}-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let recorder = Recorder::to_file(&path, DEFAULT_FIELD_LIMIT).expect("open the transcript");
        (recorder, path)
    }

    fn event_names(records: &[Record]) -> Vec<String> {
        records.iter().map(|r| name_of(&r.event)).collect()
    }

    /// The acceptance criterion in one test: a short session's records read back as JSONL, in the
    /// order the calls were made, carrying what each one answered.
    #[test]
    fn a_session_reads_back_as_ordered_records() {
        let (rec, path) = recorder("ordered");
        let call = rec.tool_request("open_dump", Some(&serde_json::json!({ "path": "a.dmp" })));
        rec.tool_result(call, false, "loaded", None);
        let call = rec.tool_request("go", Some(&serde_json::json!({ "session_id": "sess-1" })));
        rec.tool_result(
            call,
            false,
            "Breakpoint 0 hit",
            Some(&serde_json::json!({
                "status": "ok",
                "command": "g",
                "stopped_at": "0xfffff8031ab10000",
                "interrupted": false,
                "output": "Breakpoint 0 hit",
            })),
        );

        let records = records(&path);
        assert_eq!(
            event_names(&records),
            [
                "start",
                "tool_request",
                "tool_result",
                "tool_request",
                "tool_result",
                "stop"
            ],
            "the request order, and the stop the second call produced"
        );
        // Sequence numbers order records that share a millisecond, which on a fast call is all of
        // them.
        let seqs: Vec<u64> = records.iter().map(|r| r.seq).collect();
        assert_eq!(seqs, (0..records.len() as u64).collect::<Vec<_>>());
        assert!(records.iter().all(|r| r.v == SCHEMA));
        // Monotonic time never goes backwards, which is what a renderer relies on.
        assert!(records.windows(2).all(|w| w[0].mono_ms <= w[1].mono_ms));

        let Event::ToolResult {
            request,
            tool,
            session,
            verdict,
            ..
        } = &records[4].event
        else {
            panic!("expected a tool result: {:?}", records[4].event)
        };
        assert_eq!((tool.as_str(), *verdict), ("go", Verdict::Ok));
        assert_eq!(session.as_deref(), Some("sess-1"));
        // The derived stop is keyed to the same request, which is what lets a reader join them.
        let Event::Stop {
            request: stop_request,
            stopped_at,
            interrupted,
            command,
            ..
        } = &records[5].event
        else {
            panic!("expected a stop: {:?}", records[5].event)
        };
        assert_eq!(stop_request, request);
        assert_eq!(command, "g");
        assert_eq!(stopped_at.as_deref(), Some("0xfffff8031ab10000"));
        assert!(!interrupted);
    }

    /// A stop the target did not reach is recorded as one, and the three reasons are kept apart.
    ///
    /// The transcript is values about the session, and this is the value most worth having: a
    /// `go` broken in at its own bound reports a real position that is **not** where the target
    /// was going. Copying `interrupted` alone recorded that as an ordinary stop, which is the
    /// same "a fact that exists in one channel and not another" this whole change is about.
    ///
    /// **`target_gone` is the third, and it went missing here the same way** (issue #242): a stop
    /// that ended the target carries no position — like a module-load break — with both other
    /// flags false, like an ordinary stop. A reader would see a locationless stop followed by
    /// every later call on that session being refused, with nothing joining the two.
    #[test]
    fn a_stop_records_which_of_the_three_reasons_it_did_not_reach() {
        let (rec, path) = recorder("stop-reasons");
        let cases = [
            (false, true, false),
            (true, false, false),
            (false, false, true),
            (false, false, false),
        ];
        for (interrupted, timed_out, target_gone) in cases {
            let call = rec.tool_request("go", Some(&serde_json::json!({ "session_id": "s" })));
            rec.tool_result(
                call,
                false,
                "stopped",
                Some(&serde_json::json!({
                    "status": "ok",
                    "command": "g",
                    "stopped_at": "0xfffff8031ab10000",
                    "interrupted": interrupted,
                    "timed_out": timed_out,
                    "target_gone": target_gone,
                    "output": "stopped",
                })),
            );
        }

        let stops: Vec<(bool, bool, bool)> = records(&path)
            .into_iter()
            .filter_map(|r| match r.event {
                Event::Stop {
                    interrupted,
                    timed_out,
                    target_gone,
                    ..
                } => Some((interrupted, timed_out, target_gone)),
                _ => None,
            })
            .collect();
        assert_eq!(
            stops, cases,
            "each stop must record its own reason, not the first one's"
        );
    }

    /// The security criterion: a raw `connection` reaches this server as a tool argument, and the
    /// key must not reach the file.
    #[test]
    fn a_live_attach_transcript_contains_no_key() {
        let (rec, path) = recorder("no-key");
        let call = rec.tool_request(
            "attach_kernel",
            Some(&serde_json::json!({ "connection": "net:port=50000,key=1.2.3.4" })),
        );
        // The engine's own answer names the target too, in prose this time.
        rec.tool_result(
            call,
            true,
            "could not attach over net:port=50000,key=1.2.3.4",
            None,
        );
        rec.write(Event::SessionOpen {
            session: "sess-1".to_string(),
            kind: "kernel target".to_string(),
            target: Capped::of("net:port=50000,key=<redacted>", 0),
            engine_pid: 4,
        });

        let raw = std::fs::read_to_string(&path).expect("the transcript exists");
        assert!(
            !raw.contains("1.2.3.4"),
            "the key reached the transcript:\n{raw}"
        );
        assert!(
            raw.contains("net:port=50000"),
            "the transport and port are not secrets and should still identify the target:\n{raw}"
        );
        // And it reads back as records, rather than the scrub having broken the JSON.
        assert_eq!(records(&path).len(), 4);
    }

    /// The `session_id` a record carries is the caller's string until it resolves, so it is
    /// scrubbed like the argument object it was lifted out of.
    ///
    /// A handle this server issued is `sess-…` and holds nothing. But the backstop exists for the
    /// caller who puts a connection string where it does not belong — `kdconn` already refuses
    /// exactly that mistake in `profile`, and refuses it *without echoing the value back*. A copy
    /// taken before the scrub would write to a file what that refusal was careful not to say. It
    /// reaches the result too: a handle that does not resolve is never replaced by a routed one.
    #[test]
    fn a_session_handle_carrying_a_secret_is_scrubbed_like_any_other_argument() {
        let (rec, path) = recorder("session-handle");
        let call = rec.tool_request(
            "registers",
            Some(&serde_json::json!({ "session_id": "net:port=50000,key=1.2.3.4" })),
        );
        // Unresolvable, so nothing overwrites what the caller sent — which is the case that
        // carries the value all the way through to the result.
        rec.tool_result(call, true, "unknown session handle", None);

        let raw = std::fs::read_to_string(&path).expect("the transcript exists");
        assert!(!raw.contains("1.2.3.4"), "the key reached the file:\n{raw}");
        let sessions: Vec<String> = records(&path)
            .iter()
            .filter_map(|r| match &r.event {
                Event::ToolRequest { session, .. } | Event::ToolResult { session, .. } => {
                    session.clone()
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            sessions, ["net:port=50000,key=<redacted>"; 2],
            "both the request and the result carry the masked form"
        );
    }

    /// A member *named* like a secret is masked whole, whatever it holds. No tool has one today,
    /// which is the point: the rule is here before the tool that needs it.
    #[test]
    fn an_argument_named_like_a_secret_is_masked_whole() {
        let (rec, path) = recorder("secret-name");
        let call = rec.tool_request(
            "execute",
            Some(&serde_json::json!({ "key": "0123456789", "command": "version" })),
        );
        rec.tool_result(call, false, "ok", None);
        let raw = std::fs::read_to_string(&path).expect("the transcript exists");
        assert!(!raw.contains("0123456789"), "{raw}");
        assert!(raw.contains("<redacted>"), "{raw}");
        assert!(raw.contains("version"), "the rest is untouched: {raw}");
    }

    /// A truncated field says so. A transcript that quietly shortened a rendering would read as
    /// complete, which is worse than not having one.
    #[test]
    fn an_oversized_field_is_cut_and_says_how_much_was_dropped() {
        let path = std::env::temp_dir()
            .join("windbg-mcp-transcript-tests")
            .join(format!("capped-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let rec = Recorder::to_file(&path, 64).expect("open the transcript");
        let call = rec.tool_request("modules", None);
        rec.tool_result(call, false, &"m".repeat(500), None);

        let records = records(&path);
        let Event::ToolResult { text, .. } = &records[2].event else {
            panic!("expected a tool result")
        };
        assert_eq!(text.text.len(), 64);
        assert_eq!(text.dropped, Some(500 - 64));
    }

    /// Cutting a capped field must not cut a character in half — the record has to stay valid
    /// JSON, and a lone surrogate of a UTF-8 sequence is not a string.
    #[test]
    fn a_field_is_cut_at_a_character_boundary() {
        // Three bytes each, so a 4-byte limit lands inside the second one.
        let capped = Capped::of("✓✓✓", 4);
        assert_eq!(capped.text, "✓");
        assert_eq!(capped.dropped, Some(6));
        assert_eq!(Capped::of("abc", 0).dropped, None, "0 means no limit");
        assert_eq!(Capped::of("abc", 3).dropped, None, "exactly at the limit");
    }

    /// An oversized *payload* is dropped whole rather than cut: half an object is not a smaller
    /// object, and the marker says how much there was.
    #[test]
    fn an_oversized_payload_is_replaced_by_a_marker() {
        let path = std::env::temp_dir()
            .join("windbg-mcp-transcript-tests")
            .join(format!("payload-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let rec = Recorder::to_file(&path, 64).expect("open the transcript");
        let call = rec.tool_request("pool_census", None);
        let big = serde_json::json!({ "status": "ok", "rows": vec!["x".repeat(200)] });
        rec.tool_result(call, false, "census", Some(&big));

        let records = records(&path);
        let Event::ToolResult { data, .. } = &records[2].event else {
            panic!("expected a tool result")
        };
        let data = data.as_ref().expect("a payload marker is still a payload");
        assert!(
            data["transcript_dropped_bytes"].as_u64().unwrap_or(0) > 64,
            "the marker says how much there was: {data}"
        );
    }

    /// The batch criterion: a transaction that failed records the assertion that decided it, what
    /// it had already changed, and whether the rollback finished — as fields, not as prose.
    #[test]
    fn a_failed_batch_records_its_assertion_and_its_rollback() {
        let (rec, path) = recorder("batch");
        let call = rec.tool_request("debug_batch", None);
        rec.tool_result(
            call,
            true,
            "BATCH: FAILED at step 2 of 3",
            Some(&serde_json::json!({
                "status": "ok",
                "outcome": "failed",
                "at": 2,
                "committed": false,
                "rollback_complete": true,
                "after": { "state": "stopped", "ip": "0xfffff8031ab10000" },
                "budget_ms": 60000,
                "elapsed_ms": 120,
                "steps": [
                    { "position": 1, "label": "patch", "action": "eb fffff803 90",
                      "result": "ok", "changes": "wrote 1 byte at fffff803", "cut_short": false },
                    { "position": 2, "label": "check", "action": "db fffff803 L1",
                      "result": "unmet", "detail": "expected `91`", "cut_short": false },
                    { "position": 3, "label": "never", "action": "version",
                      "result": "skipped", "detail": "a step before it failed", "cut_short": false }
                ],
                "always": [
                    { "position": 1, "label": "restore", "action": "eb fffff803 cc",
                      "result": "ok", "changes": "wrote 1 byte at fffff803", "cut_short": false }
                ]
            })),
        );

        let records = records(&path);
        assert_eq!(
            event_names(&records),
            [
                "start",
                "tool_request",
                "tool_result",
                // The step that changed something, then the assertion that stopped the batch,
                // then the rollback's own change, then the verdict.
                "mutation",
                "assertion",
                "mutation",
                "batch",
            ]
        );
        let Event::Assertion { step, detail, .. } = &records[4].event else {
            panic!("expected an assertion: {:?}", records[4].event)
        };
        assert_eq!(step.text, "steps[2] check");
        assert_eq!(detail.text, "expected `91`");
        let Event::Mutation { step, detail, .. } = &records[5].event else {
            panic!("expected the rollback's mutation")
        };
        assert_eq!(
            step.as_ref().map(|s| s.text.as_str()),
            Some("always[1] restore")
        );
        assert_eq!(detail.text, "wrote 1 byte at fffff803");
        let Event::Batch {
            outcome,
            at_step,
            committed,
            rollback_complete,
            after,
            ..
        } = &records[6].event
        else {
            panic!("expected the batch verdict")
        };
        assert_eq!((outcome.as_str(), *at_step), ("failed", Some(2)));
        assert!(!committed);
        assert!(rollback_complete, "the `always` block ran");
        assert_eq!(after, "stopped");
    }

    /// The cap covers the **derived** records too, and the step label is why it has to: that
    /// string is the caller's, of whatever length they sent, so a batch of long labels could
    /// otherwise produce unbounded lines beside a payload the cap had already replaced.
    #[test]
    fn a_derived_records_fields_are_capped_like_any_other() {
        let path = std::env::temp_dir()
            .join("windbg-mcp-transcript-tests")
            .join(format!("derived-cap-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let rec = Recorder::to_file(&path, 32).expect("open the transcript");
        let call = rec.tool_request("debug_batch", None);
        rec.tool_result(
            call,
            true,
            "BATCH: FAILED",
            Some(&serde_json::json!({
                "status": "ok",
                "outcome": "failed",
                "at": 1,
                "committed": false,
                "rollback_complete": true,
                "after": { "state": "stopped", "ip": "0x0" },
                "budget_ms": 1,
                "elapsed_ms": 1,
                "steps": [{
                    "position": 1,
                    "label": "L".repeat(400),
                    "action": "eb 0 90",
                    "result": "unmet",
                    "detail": "D".repeat(400),
                    "changes": "C".repeat(400),
                    "cut_short": false,
                }],
                "always": []
            })),
        );

        let records = records(&path);
        let capped: Vec<(&Capped, &Capped)> = records
            .iter()
            .filter_map(|r| match &r.event {
                Event::Mutation { detail, step, .. } => Some((step.as_ref()?, detail)),
                Event::Assertion { step, detail, .. } => Some((step, detail)),
                _ => None,
            })
            .collect();
        assert_eq!(
            capped.len(),
            2,
            "a mutation and the assertion: {records:#?}"
        );
        for (step, detail) in capped {
            for field in [step, detail] {
                assert!(field.text.len() <= 32, "over the cap: {field:?}");
                assert!(field.dropped.is_some(), "and it has to say so: {field:?}");
            }
        }
    }

    /// The whole-record ceiling: the backstop under the per-field caps.
    ///
    /// Three rounds of review each found a *different* field that had been missed — derived batch
    /// details, a session's target, a caller's handle — because capping was something each new
    /// field had to remember to do. This bounds the record itself, so the next missed field is a
    /// marker in the transcript instead of an unbounded line, and says which kind to go and look
    /// at. `tool` is the field used here because it is genuinely uncapped and genuinely the
    /// caller's: an MCP client chooses the name it asks for.
    #[test]
    fn a_record_no_field_cap_bounded_is_replaced_by_a_marker() {
        let path = std::env::temp_dir()
            .join("windbg-mcp-transcript-tests")
            .join(format!("ceiling-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let rec = Recorder::to_file(&path, 64).expect("open the transcript");
        let enormous = "t".repeat(64 * 8 + RECORD_OVERHEAD + 1);
        let call = rec.tool_request(&enormous, None);
        rec.tool_result(call, false, "", None);

        let records = records(&path);
        let Event::Oversized { of, bytes } = &records[1].event else {
            panic!(
                "expected the request to be replaced: {:?}",
                records[1].event
            )
        };
        assert_eq!(of, "tool_request");
        assert!(*bytes > 64 * 8, "the marker says how big it was: {bytes}");
        // The marker is a record like any other — numbered in sequence, so nothing is lost from
        // the ordering, and small.
        assert_eq!(records[1].seq, 1);
        let longest = std::fs::read_to_string(&path)
            .expect("the transcript")
            .lines()
            .map(str::len)
            .max()
            .unwrap_or(0);
        assert!(longest <= 64 * 8 + RECORD_OVERHEAD, "{longest} bytes");
    }

    /// A tool this module knows nothing about contributes its result and no derived events. The
    /// alternative — guessing at what an `execute` command did — would put a fact in the record
    /// that nothing measured.
    #[test]
    fn an_unrecognised_tool_derives_nothing() {
        let (rec, path) = recorder("underived");
        let call = rec.tool_request(
            "execute",
            Some(&serde_json::json!({ "command": "eb 0 90" })),
        );
        rec.tool_result(
            call,
            false,
            "",
            Some(&serde_json::json!({ "status": "ok" })),
        );
        assert_eq!(
            event_names(&records(&path)),
            ["start", "tool_request", "tool_result"]
        );
    }

    /// A failure carries its category, so a reader counts failures by kind rather than by wording.
    #[test]
    fn a_failure_records_the_category_it_was_given() {
        let (rec, path) = recorder("category");
        let call = rec.tool_request("registers", None);
        rec.tool_result(
            call,
            true,
            "no debug session is open",
            Some(&serde_json::json!({
                "status": "error",
                "error": { "category": "stale_session", "message": "no debug session is open" }
            })),
        );
        let records = records(&path);
        let Event::ToolResult {
            verdict, category, ..
        } = &records[2].event
        else {
            panic!("expected a tool result")
        };
        assert_eq!(*verdict, Verdict::Error);
        assert_eq!(*category, Some(ErrorCategory::StaleSession));
    }

    /// A disabled recorder is the ordinary case, and it must touch nothing at all.
    #[test]
    fn a_disabled_recorder_records_nothing() {
        let rec = Recorder::disabled();
        assert!(!rec.enabled());
        assert!(rec.path().is_none());
        let call = rec.tool_request("go", None);
        rec.tool_result(call, false, "text", None);
        rec.write(Event::Shutdown { sessions: 1 });
    }

    /// Appending rather than truncating: a second run must not erase the first. The `start`
    /// records are what separate them.
    #[test]
    fn a_second_run_appends_to_the_same_file() {
        let (first, path) = recorder("append");
        first.write(Event::Shutdown { sessions: 0 });
        drop(first);
        let second = Recorder::to_file(&path, DEFAULT_FIELD_LIMIT).expect("reopen");
        second.write(Event::Shutdown { sessions: 0 });

        let records = records(&path);
        assert_eq!(
            event_names(&records),
            ["start", "shutdown", "start", "shutdown"]
        );
        // Each run numbers its own records, which is why the pid on `start` is what tells them
        // apart rather than the sequence.
        assert_eq!(records[2].seq, 0);
    }

    /// stdout is the JSON-RPC transport. This module must never reach it — a single stray
    /// `println!` would corrupt the protocol for every client, and it would do it only on the
    /// runs where recording is on, which is the worst way to find out.
    ///
    /// Checked by reading the source, the way `engine`'s spawn-lock rule is: the property is about
    /// what is *written*, and no runtime test can prove the absence of a call nobody made today.
    #[test]
    fn this_module_never_writes_to_stdout() {
        // Only the half that ships. The tests below it do not run in a server, and one of them is
        // *named* after the thing being searched for.
        let source = include_str!("record.rs");
        let code = source
            .split_once("\n#[cfg(test)]")
            .expect("this module has a test half")
            .0;
        for forbidden in ["println!", "print!", "stdout"] {
            let uses = code
                .lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .filter(|l| l.contains(forbidden))
                .count();
            assert_eq!(
                uses, 0,
                "`{forbidden}` in the transcript writer would corrupt the MCP transport"
            );
        }
    }

    /// The wall clock is written out by hand, so it is worth checking against dates whose
    /// arithmetic differs: an epoch, a leap day, and a century that is not a leap year.
    #[test]
    fn wall_clock_stamps_are_rfc3339_in_utc() {
        let at = |secs: u64, millis: u32| {
            rfc3339(
                UNIX_EPOCH + Duration::from_secs(secs) + Duration::from_millis(u64::from(millis)),
            )
        };
        assert_eq!(at(0, 0), "1970-01-01T00:00:00.000Z");
        assert_eq!(at(1, 500), "1970-01-01T00:00:01.500Z");
        // 2000-02-29, the leap day of a century that *is* a leap year.
        assert_eq!(at(951_782_400, 0), "2000-02-29T00:00:00.000Z");
        // 2100-03-01: 2100 is not a leap year, so the day before it is the 28th.
        assert_eq!(at(4_107_542_400, 0), "2100-03-01T00:00:00.000Z");
        assert_eq!(at(1_755_324_000, 123), "2025-08-16T06:00:00.123Z");
    }

    /// A stamp has to survive being read back, because that is what gives an asciicast rendered
    /// from a transcript the time it was actually recorded at.
    #[test]
    fn a_stamp_reads_back_as_the_second_it_was_written_from() {
        for secs in [0, 1, 951_782_400, 1_755_324_000, 4_107_542_400] {
            let stamp = rfc3339(UNIX_EPOCH + Duration::from_secs(secs));
            assert_eq!(unix_seconds(&stamp), Some(secs), "round-tripping {stamp}");
        }
        // The milliseconds are dropped, deliberately — the header of an asciicast is whole
        // seconds — but nothing else about the stamp is.
        assert_eq!(
            unix_seconds(&rfc3339(UNIX_EPOCH + Duration::from_millis(1_500))),
            Some(1)
        );
    }

    /// Anything this module did not write is refused rather than guessed at.
    #[test]
    fn a_stamp_that_is_not_one_of_ours_is_refused() {
        for bad in [
            "",
            "2026-08-16",
            "2026-08-16T06:00:00",       // no zone
            "2026-08-16T06:00:00+01:00", // an offset, which `rfc3339` never emits
            "2026-13-16T06:00:00.000Z",  // month 13
            "2026-08-16T25:00:00.000Z",  // hour 25
            "not-a-date",
        ] {
            assert_eq!(unix_seconds(bad), None, "`{bad}` is not a stamp");
        }
    }
}
