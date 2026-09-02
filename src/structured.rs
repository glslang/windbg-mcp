//! The typed half of a tool result: what a program reads, beside the text a person reads.
//!
//! Every tool in this server has always answered with prose — a rendered pool table, a
//! `VERDICT: HIT` line, a `session_id:` line at the bottom of an opener's report. That is the
//! right answer for a model and for a human, and it is a bad API: the MessageManager batch
//! client and its regression test had to match on `allocation(s)`, on module-name substrings and
//! on the exact spelling of a session line, so a rewording here broke automation there without
//! any debugger behaviour changing at all ([#84](https://github.com/glslang/windbg-mcp/issues/84)).
//!
//! So the tools listed in that issue now emit **both**: the same text as before, plus MCP
//! `structuredContent` built from the types below, and an `outputSchema` in `tools/list`
//! describing it. The text is unchanged, deliberately — this adds a channel rather than
//! replacing one.
//!
//! **The doc comments below do not reach that schema**, and are not meant to: `schemars` inlines
//! every type into the `$defs` of every tool that can reach it, so one paragraph here was shipping
//! thirty-three times to a field no model is given and no validator reads. [`crate::schema`] takes
//! them out and says why. Write them for whoever edits this file;
//! `docs/structured-results.md` is where a caller reads the same facts.
//!
//! # Where the values come from
//!
//! Nothing here is parsed out of debugger output. Each type is built from a value: dbgscope's
//! `RunToOutcome`, `Register`, `Module`, `BreakpointInfo`, `PoolSpan` and `WalkCoverage` on the
//! worker side, and this server's own `SessionSnapshot`/`Release` on the supervisor side. That is
//! the rule the counts in [#77](https://github.com/glslang/windbg-mcp/issues/77) were fixed by,
//! pointed at results instead of at counts: a figure re-derived from a rendering measures the
//! rendering. Where a value did not exist upstream it was added there first — this is why
//! `dbgscope` grew `register_values`, `modules`, `breakpoints` and `WalkCoverage`.
//!
//! # One address representation
//!
//! Every address, and every register-sized value, is a **`0x`-prefixed, lowercase, 16-digit
//! zero-padded hex string** — `"0xfffff8031ab10000"`. One representation, everywhere, and a
//! string rather than a JSON number because a `u64` above 2^53 does not survive a JSON parser
//! that reads numbers as doubles, which is most of them. Zero-padded because clients sort and
//! group these, and `0x9f` sorting after `0xfffff803…` is a bug waiting in every consumer. The
//! debugger's own backtick form (`fffff803`1ab10000`) stays in the text and appears nowhere here.
//!
//! # Errors
//!
//! A failing tool still returns an MCP tool-execution error carrying the same text. It also
//! carries structured content — the `error` branch of [`Outcome`] — so a caller can branch on
//! [`ErrorCategory`] rather than on wording. Both branches are described by the one output
//! schema, which is why the discriminator exists: a client validating results against the schema
//! finds an error result conforms too.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::engine::{EngineError, SessionKind, SessionState};

/// Renders a value in this module's one address representation.
///
/// See the module docs: `0x`-prefixed, lowercase, zero-padded to 16 digits.
pub fn addr(value: u64) -> String {
    format!("{value:#018x}")
}

/// A tool's typed answer: the payload, or why there is none.
///
/// Internally tagged on `status`, so both branches are objects of the same schema and a client
/// switches on one field. The alternative — omitting structured content on failure — leaves the
/// one case a caller most needs to branch on (did this work?) answerable only by reading prose.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Outcome<T> {
    /// The tool did what was asked; the payload is the answer.
    Ok(T),
    /// It did not, and `error` says what kind of failure it was.
    Error(Failure),
}

impl<T> Outcome<T> {
    /// The error branch, naming the session the failure is about (where there is one).
    pub fn failed_in(
        category: ErrorCategory,
        message: impl Into<String>,
        session_id: Option<String>,
    ) -> Self {
        Self::Error(Failure {
            error: FailureDetail {
                category,
                message: message.into(),
                session_id,
            },
        })
    }
}

/// The `error` branch of [`Outcome`].
///
/// One level of nesting so the payload's own fields can never collide with the failure's: a
/// success and a failure are the same JSON object here, and a payload with a `message` field
/// would otherwise silently shadow this one.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Failure {
    pub error: FailureDetail,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct FailureDetail {
    /// What kind of failure this is. Stable across rewordings of `message`.
    pub category: ErrorCategory,
    /// The full human-readable failure, identical to the text content of the same result.
    pub message: String,
    /// The session the failure is about, where the failure has one — including the openers
    /// that fail *after* creating a target, where this handle is the only way to reach it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

/// `crash_triage`'s refusal on a user-mode session, without the pointer to what to read instead.
///
/// Shared so the server can recognise this exact message and append that pointer only where the
/// surface serves the tools it names ([`crate::server::WindbgServer`]'s `crash_triage`) — an
/// equality against one constant rather than a sniff at prose. The worker cannot append it
/// itself: it owns one session and has never heard of the client's surface, which is the same
/// reason an opener's summary crosses the pipe as facts. See `SUMMARY_NOTES`.
pub const USER_MODE_NO_BUG_CHECK: &str = "this is a user-mode session, which has no bug check: \
     `crash_triage` reads the kernel bug check data a crash dump or a bug-checked live kernel \
     carries.";

/// Why a tool call failed, as a value a caller can branch on.
///
/// Deliberately coarse. These are the distinctions that change what a caller *does* next, and
/// nothing finer: a category nobody can act on differently is a category that will drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCategory {
    /// The call was refused here, before it reached a debugger: a malformed number, an operand
    /// carrying a command separator, two arguments that cannot both be given. Fix the argument.
    InvalidArgument,
    /// The debugger ran it and it failed — an unresolvable symbol, an unreadable address, a
    /// target in the wrong state. Actionable, but by changing what is asked, not how.
    Debugger,
    /// The wait for this call's result expired. The job was abandoned by the *waiter*, not by
    /// the worker: it may still be running, and anything whose retry has side effects must
    /// treat it as possibly-done. `session_status` says what became of it.
    Timeout,
    /// The work was stopped on request — an `interrupt`, or a Ctrl+Break reaching the engine.
    /// Not a failure of the target: somebody asked for this.
    Interrupted,
    /// The work was never started, because too little of the call's budget was left to do it and
    /// report back. Nothing was read and nothing changed — which is what separates this from
    /// [`Self::Timeout`], where the job may well still be running. Retry on an idle session, or
    /// raise the server's call timeout.
    NotRun,
    /// The handle named no session this server will run the call against: it was ended, its
    /// target was replaced under it, **its target went away** — the process ran to completion, or
    /// a command released it — it never existed, or nothing is open at all. Release it and open
    /// again; no change to what was asked will help.
    StaleSession,
    /// The engine process holding this session is gone. The session is unrecoverable; opening
    /// again gets a fresh one.
    WorkerLost,
    /// No session slot was free, so nothing was opened. End a session and retry.
    Capacity,
    /// The session has a run in flight: `continue_async` set the target going and it has not
    /// stopped. Nothing about the call was wrong, and nothing read from a moving target would
    /// mean anything — wait for the stop, break the target in, or end the session.
    TargetRunning,
}

impl ErrorCategory {
    /// The category an engine-level failure falls into.
    ///
    /// A `match` rather than a string test, so a new [`EngineError`] variant is a compile error
    /// here instead of an `internal` that quietly swallows it.
    pub fn of(error: &EngineError) -> Self {
        match error {
            EngineError::Debugger(_) => Self::Debugger,
            EngineError::Timeout(_) => Self::Timeout,
            EngineError::Stale(_) => Self::StaleSession,
            EngineError::Lost(_) => Self::WorkerLost,
            EngineError::Interrupted(_) => Self::Interrupted,
            EngineError::NotRun(_) => Self::NotRun,
            EngineError::InvalidArgument(_) => Self::InvalidArgument,
            EngineError::TargetRunning(_) => Self::TargetRunning,
        }
    }
}

// ---- sessions -------------------------------------------------------------

/// What an opener produced.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum OpenOutcome {
    Ok(OpenedSession),
    Error(OpenFailure),
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct OpenedSession {
    /// The handle to pass as `session_id` on later calls. Previously recoverable only by
    /// finding the `session_id:` line in the report text.
    pub session_id: String,
    pub kind: SessionKindName,
    /// What was opened — a path, a pid, a redacted connection label. Never carries a debug key.
    pub target: String,
    /// The opener's own diagnostic (`vertarget`, `r`, the TTD lifetime query), verbatim, with
    /// [`Self::summary`] rendered under it.
    pub report: String,
    /// The same few facts as values.
    pub summary: TargetSummary,
}

/// What a caller reads off an open every single time: which build, where the kernel is, and —
/// for a crash dump — which bug check.
///
/// This is the *replacement* for the module table openers used to print. That table is 227 lines
/// on the kernel dump this repo ships, it arrived unprompted, and an agent opening five dumps in a
/// session paid for it five times to answer three questions this struct answers in four fields
/// ([#105](https://github.com/glslang/windbg-mcp/issues/105)). The inventory itself belongs to
/// `modules`, which is where it now stays until somebody asks.
///
/// **Every field is optional, and each is absent for its own reason** rather than because the open
/// failed: an open that produced a target hands back everything it could read about it. A
/// user-mode target has no bug check data at all, a freshly attached kernel may have nothing but
/// `nt` in the engine's inventory yet (#85), and a read that fails costs its own field and nothing
/// else.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct TargetSummary {
    /// Whether the engine calls this a kernel target. Absent only if the query itself failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel_mode: Option<bool>,
    /// How many modules the engine holds **at this moment**, which is what makes it worth
    /// carrying: a fresh kernel attach can report one. The table is `modules`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modules_loaded: Option<usize>,
    /// The image this target is *about*: the kernel (`nt`) on a kernel target, and on a user-mode
    /// one the first image the engine lists, which is the process's own executable. A base to
    /// compute `module+RVA` against without asking for the whole table first.
    ///
    /// One row of exactly what `modules` returns, rather than a name/base pair of its own, so a
    /// consumer reads one module shape everywhere. Boxed — which JSON never sees — because this
    /// summary travels inside two enums whose other variants are a fraction of its size.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_module: Option<Box<ModuleInfo>>,
    /// The bug check this target stopped on, when it stopped on one — read from the engine's
    /// `ReadBugCheckData`, not from `!analyze`. Absent for a user-mode target, a live kernel that
    /// has not crashed, and a kernel dump that is not a crash dump. `crash_triage` is the same
    /// code with the stack and the faulting driver beside it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bug_check: Option<BugCheckInfo>,
    /// Something this session **cannot** do that a caller would otherwise assume it can, and what
    /// to do about it. Absent when there is nothing to say, which is the ordinary case.
    ///
    /// Carried as a field rather than left in the summary's prose because a structured-aware
    /// client forwards `structuredContent` and drops the text block, so a limitation stated only
    /// in the sentence is one half the clients never see (`FOLLOWUPS.md` item 43). It names no
    /// tool, for the reason that item gives: this is built in the worker, which owns one session
    /// and has never heard of the caller's surface.
    ///
    /// The case that exists today is a 32-bit dump opened by an engine that is not 32-bit, where
    /// the .NET SOS extension cannot be loaded at all — an extension is loaded into the debugger's
    /// own process, so its architecture is the host's.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limitation: Option<String>,
}

/// A failed open, and the one thing a caller must know about it.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct OpenFailure {
    pub error: FailureDetail,
    /// Whether a target was created or claimed. This is the field that decides whether opening
    /// again is a recovery or a second attach: getting it wrong means two processes, or two
    /// dials at one KD link.
    pub target: TargetCreated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TargetCreated {
    /// Nothing was created or claimed. The slate is clean and opening again is correct.
    No,
    /// The target exists — the dump is loaded, the process is spawned, the connection is taken
    /// — and something after that failed. Do not open again; use the handle, or `end_session`.
    Yes,
    /// The wait was abandoned but the open was not: it is still running and may still land.
    /// `session_status` on the handle says which it became.
    Pending,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SessionKindName {
    Dump,
    Trace,
    Kernel,
    KernelLocal,
    Process,
    Launch,
}

impl From<SessionKind> for SessionKindName {
    fn from(kind: SessionKind) -> Self {
        match kind {
            SessionKind::Dump => Self::Dump,
            SessionKind::Trace => Self::Trace,
            SessionKind::Kernel => Self::Kernel,
            SessionKind::KernelLocal => Self::KernelLocal,
            SessionKind::Process => Self::Process,
            SessionKind::Launch => Self::Launch,
        }
    }
}

/// What `session_status` reports.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SessionsReport {
    /// The live sessions, or the single session asked about. Empty when nothing is open.
    pub sessions: Vec<SessionInfo>,
    /// How many sessions this server will hold at once.
    pub max_sessions: u32,
    /// The handle this call asked about, when it named one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asked: Option<String>,
    /// True when `asked` names no session this server is holding — never issued here, or closed
    /// long enough ago to have aged out of the history. `sessions` is then empty, which on its
    /// own is indistinguishable from "it closed".
    pub unknown_handle: bool,
}

/// What `server_log` reports: a page of the server's own log, and enough about the ring behind it
/// to tell "nothing happened" from "it scrolled past".
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct LogReport {
    /// Oldest first, which is reading order.
    pub records: Vec<LogRecord>,
    /// How many matched the filter before `limit` clipped it. Greater than `records.len()` means
    /// the oldest matches were left behind, not that they do not exist.
    pub matched: u32,
    /// Pass as `since` next time to get only what is new. It advances even when this page is
    /// empty, so polling a quiet server does not re-read the same tail.
    pub next_since: u64,
    /// How many records the buffer holds, and how many it can. Set the capacity with
    /// `WINDBG_MCP_LOG_BUFFER`.
    pub held: u32,
    pub capacity: u32,
    /// The oldest `seq` still buffered. A `since` older than this is the only way to find out
    /// that records were evicted between two calls.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oldest_seq: Option<u64>,
}

/// One log record.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct LogRecord {
    /// Filing order within this server run, gapless unless records were evicted.
    pub seq: u64,
    /// When it was logged, in the process that logged it — RFC 3339, UTC, to the millisecond.
    /// A worker's record is stamped in the worker, so `at` and `seq` can disagree by the width of
    /// a pipe write: `at` says when, `seq` says in what order it was filed.
    pub at: String,
    pub level: crate::logbridge::Level,
    /// The session a worker's record is about. Absent for the supervisor's own records — the
    /// session registry, the listener, the tool surface — which are *about* sessions without
    /// belonging to one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// The `tracing` target, which says which part of the server spoke.
    pub target: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SessionInfo {
    pub session_id: String,
    pub kind: SessionKindName,
    /// What this session holds, as it can safely be described: a kernel connection appears with
    /// its key redacted, exactly as in the text.
    pub target: String,
    /// The pid of the engine process that owns it — one process per session.
    pub engine_pid: u32,
    pub state: SessionStateInfo,
    /// How long it has been in that state.
    pub in_state_for_ms: u64,
    /// How long since it was opened.
    pub age_ms: u64,
    /// Whether a call that names no session is routed here.
    pub current: bool,
    /// Whether it will still accept work.
    pub live: bool,
    /// The run this session has outstanding, if any — started by `continue_async` and held until
    /// something starts another.
    ///
    /// Here rather than in a tool of its own, because "what is this session doing" is the question
    /// this report already answers and a second tool would be a second answer to it. While
    /// `stopped` is false the session refuses every tool that reads the target, which is otherwise
    /// only discoverable by being refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution: Option<ExecutionInfo>,
}

/// A session's state, with the one derived fact a caller cannot compute for itself.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SessionStateInfo {
    /// The open has started; nothing has been created or claimed yet.
    Opening,
    /// The target has been created or claimed and the debugger is waiting for it to break in.
    Attaching {
        /// Whether this wait has no timeout and cannot be interrupted — true for a live kernel
        /// attach, which parks until its target dials in or the session is reclaimed.
        waits_indefinitely: bool,
        /// Whether it has been waiting longer than a healthy open ever takes. The state alone
        /// cannot distinguish a KD link coming up from a guest that was never booted in debug
        /// mode; how long it has been waiting can, and the two need opposite responses.
        overdue: bool,
    },
    /// Open and ready for work.
    Open,
    /// The open failed and never created anything.
    Failed { why: String },
    /// The handle was retired: the engine process still holds a target, but not this one.
    Retired { why: String },
    /// Ended.
    Closed { why: String },
}

impl SessionStateInfo {
    /// Builds the state, given the two facts only the server knows.
    pub fn of(state: &SessionState, waits_indefinitely: bool, overdue: bool) -> Self {
        match state {
            SessionState::Opening => Self::Opening,
            SessionState::Attaching => Self::Attaching {
                waits_indefinitely,
                overdue,
            },
            SessionState::Open => Self::Open,
            SessionState::Failed(why) => Self::Failed { why: why.clone() },
            SessionState::Retired(why) => Self::Retired { why: why.clone() },
            SessionState::Closed(why) => Self::Closed { why: why.clone() },
        }
    }
}

/// What `end_session` did.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SessionEnded {
    pub session_id: String,
    /// Whether the worker let go of the target itself. False when it had to be killed holding
    /// it — the live-kernel attach that cannot be interrupted is the case this exists for.
    pub released: bool,
    /// Whether the engine process was terminated rather than exiting on its own.
    pub worker_terminated: bool,
    /// How long the worker was given to let go before it was terminated, when it was.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub waited_ms: Option<u64>,
    /// Whether the target process outlived the session, where the session had one.
    ///
    /// `true` for a process this server **attached** to: it was detached and left running.
    /// `false` for one this server **launched** — a launch does not outlive its session — and for
    /// either where the session had to be terminated still holding its target, since terminating
    /// a debugger is not a detach and the kernel takes the debuggee. Absent where the session
    /// never had a process to keep: a dump, a trace, or a kernel target.
    ///
    /// **It answers what the caller has to act on, not what caused it.** A launched process that
    /// had already run to completion reads `false` like one the teardown took, because both mean
    /// "nothing of yours is still running" — which is the question, and the only one this field is
    /// asked at a moment that can answer it. Which of the two happened was reported when it
    /// happened, by the resume that saw the target go (`StopReport::target_gone`).
    ///
    /// Here as well as in the text because a client that forwards `structuredContent` drops the
    /// text, and this is the one fact about a teardown that is not recoverable afterwards.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_left_running: Option<bool>,
}

// ---- execution ------------------------------------------------------------

/// What `run_to_address` established.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RunToReport {
    pub verdict: RunToVerdict,
    /// The address asked for, after resolution.
    pub target: String,
    /// Where the target actually stopped, when it stopped somewhere else.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stopped_at: Option<String>,
    /// The wait this verdict was reached under.
    pub timeout_ms: u32,
    /// The debugger text captured across the run.
    pub output: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RunToVerdict {
    /// Execution reached the address.
    Hit,
    /// Another breakpoint or an exception stopped it first. `stopped_at` says where.
    StoppedElsewhere,
    /// It did not stop within the wait — the current input/state does not drive execution here.
    Timeout,
    /// The target went away before it reached anything: it ran to completion, or the session was
    /// released. Terminal — this session has nothing left to run — and it says nothing about
    /// whether the address was reachable.
    TargetGone,
}

/// Where a target ended up after a command that moves it (`g`, `p`, `t`, and the TTD reverses).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct StopReport {
    /// The debugger command that was run.
    pub command: String,
    /// The instruction pointer after it, when the engine could be asked. Absent for a target
    /// that is running, gone, or has no thread context — which is not the same as zero.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stopped_at: Option<String>,
    /// The operating-system thread id [`Self::stopped_at`] belongs to. Absent where the engine
    /// would not answer — a target that has gone, or a stop with no thread context.
    ///
    /// Reported because a position on its own does not identify a stop: a `go` on a multi-threaded
    /// target stops wherever a breakpoint was hit, and "which thread" is half of what a caller
    /// then has to know to read the stack it walks next.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread: Option<u32>,
    /// Which of a kernel target's processors the stop is on. Never the same as processor 0.
    ///
    /// Absent covers two things, as [`Self::stopped_at`]'s and [`Self::thread`]'s do: no processor
    /// number **applies** — every user-mode target and every dump of one, which is not a failure —
    /// or the engine would not **answer**. They are one field here on purpose. The debugger tells
    /// them apart and a caller cannot act on the difference: there is no position to read either
    /// way, and what a failed read has to say is in [`Self::output`]. The library underneath does
    /// keep them apart, for callers that are not a tool result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub processor: Option<u32>,
    /// Whether the target was broken into **on request** rather than stopping on its own. The
    /// position is real either way, but it is where an `interrupt` landed rather than where the
    /// target was going, which is a different answer to "where did this stop?".
    pub interrupted: bool,
    /// Whether this call's own wait ran out with the target still going, so the debugger broke it
    /// in at the bound.
    ///
    /// The same "the position is real but it is not a stop the target reached" as
    /// [`Self::interrupted`], from the other cause — and kept apart from it because the next move
    /// differs: nobody asked for this one, and running on or allowing longer is what answers it.
    /// Defaulted so a record written before this field existed still reads.
    #[serde(default)]
    pub timed_out: bool,
    /// Whether the target **went away** rather than stopping: the process ran to completion, or
    /// the command released it. Terminal, and not a failure — running a program to its end is
    /// what a `go` is for.
    ///
    /// Its own field rather than an absent [`Self::stopped_at`], which a target with no thread
    /// context also produces, and rather than an error, which would discard [`Self::output`] —
    /// the only copy of what the run printed on its way there. When this is true the session has
    /// nothing left to run and every later call is refused; `end_session` releases it.
    ///
    /// Defaulted so a record written before this field existed still reads.
    #[serde(default)]
    pub target_gone: bool,
    /// The debugger's own output for the command.
    pub output: String,
}

// ---- asynchronous execution -----------------------------------------------

/// What `continue_async` produced: a handle for a target that is now running.
///
/// The handle exists because the run outlives the call that started it. Every other tool here
/// answers about a target that is stopped and will still be stopped when the answer arrives; this
/// one hands back a name for something in flight, and the name is what later calls address.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ExecutionStarted {
    pub session_id: String,
    /// The handle. Good until this run stops **and** something starts another one — a stop does
    /// not invalidate it, because the stop is exactly what it is then holding.
    pub execution: String,
    /// The debugger command that set the target going.
    pub command: String,
    /// Whether the target is moving **now**, as this answer is written.
    ///
    /// Almost always true, and both of the uncommon answers matter. A command can complete
    /// without ever leaving the engine running — `g` on a trace already at its end — and a run
    /// can start and finish before this call gets a turn, which a `g` onto a breakpoint one
    /// instruction away does routinely. Either way the run is over, its stop is already filed
    /// against the handle waiting to be read, and there is nothing to wait for and nothing to
    /// break in. [`Self::moved`] is what tells the two apart.
    pub running: bool,
    /// Whether the target ever started moving.
    ///
    /// A second field rather than a second meaning for [`Self::running`], because the two come
    /// apart exactly where it matters: `running: false, moved: true` is a run that did what it
    /// was asked and has already stopped, while `running: false, moved: false` is a command that
    /// never set the target going at all. Reported as one bool, a caller told "not running" would
    /// have to guess which, and the guess changes what they do next — collect a stop that says
    /// where the target got to, or work out why the command did nothing.
    pub moved: bool,
    /// How long the debugger will let the target run before breaking it in itself. Absent for a
    /// run that is no longer going.
    ///
    /// Not a suggestion and not this call's timeout: it is the bound the pump is armed with in
    /// the engine process, and it is what makes this a wait somebody can account for rather than
    /// one nobody is watching. A run that reaches it stops where it happens to be, which the stop
    /// reports as `timed_out`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub breaks_in_ms: Option<u64>,
}

/// What `wait_for_stop` produced.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct StopWait {
    pub session_id: String,
    pub execution: String,
    /// How long the target has run in all — since the run started, not since this wait did.
    /// Several waits can watch one run, and the run is what the number is about. It stops moving
    /// once the run does, so two reads of one stop agree.
    pub running_for_ms: u64,
    /// Where the run stopped, or **absent while it is still going**.
    ///
    /// One field rather than a flag beside it, because there is one fact: a wait that came back
    /// with no stop is a wait that ran out, not a run that did. The handle is still good and
    /// waiting again carries on from here — nothing was consumed and nothing was cancelled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop: Option<StopReport>,
    /// How much longer the debugger will let it run before breaking in itself. Absent once it has
    /// stopped, where there is nothing left to bound.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub breaks_in_ms: Option<u64>,
}

/// What `break_in` produced.
///
/// Deliberately not a stop. `SetInterrupt` lodges a request and returns; the target stops at the
/// engine's next poll, and *that* is the run ending — so it is reported where every other ending
/// of this run is reported, on the wait, rather than invented here from a request that had only
/// just been made.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct BreakInRequested {
    pub session_id: String,
    pub execution: String,
    /// Whether this run is not going to keep the target moving.
    ///
    /// Phrased for what it is actually good for rather than as "a break was sent", which is a
    /// narrower thing and is not always what happened. `true` covers a Ctrl+Break raised now, one
    /// already lodged and stopping the target, a run still queued and barred from ever starting,
    /// and a run that finished between the caller reading its handle and this arriving — which
    /// the debugger cannot tell from the queued case, and which needs no action either way.
    /// `detail` is the debugger's own account of which it was.
    ///
    /// `false` says the run had already stopped when this call looked, so nothing was sent. It is
    /// not a failure. A break that could not be *delivered* is an error rather than a `false`
    /// here.
    pub requested: bool,
    /// The debugger's own account of what it did.
    pub detail: String,
}

/// One session's outstanding run, as `session_status` reports it.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ExecutionInfo {
    pub execution: String,
    pub command: String,
    /// How long the target ran — counting while it is moving, and frozen at the stop once it has
    /// stopped. Not how long ago the run started: a stop is kept until another run replaces it,
    /// so a handle read an hour later would otherwise report an hour-long run.
    pub running_for_ms: u64,
    /// Whether the run has ended and its stop is waiting to be collected.
    ///
    /// The distinction the rest of the session's behaviour turns on: while this is `false` the
    /// target is moving and every tool that reads it is refused, and once it is `true` the
    /// session takes ordinary work again with the stop still there to be read.
    pub stopped: bool,
    /// How much longer the debugger will let it run before breaking in itself. Absent once it has
    /// stopped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub breaks_in_ms: Option<u64>,
}

// ---- registers, modules, breakpoints --------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RegisterSet {
    pub registers: Vec<RegisterInfo>,
    /// The instruction pointer, called out because it is the register most callers came for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instruction_pointer: Option<String>,
    /// Whether x87/vector registers and subregister views were included — see the tool's
    /// `include` argument. False means this is the integer set only.
    pub all_registers: bool,
}

/// One register: its name, and its value tagged by what kind of value it is.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RegisterInfo {
    /// The engine's own name for it (`rax`, `xmm0`, `efl`).
    pub name: String,
    #[serde(flatten)]
    pub value: RegisterValue,
    /// Whether this register is a view of another (`eax` within `rax`) rather than storage of
    /// its own. Only ever true when the whole set was asked for — and **absent from the JSON when
    /// false**, which is every row of a default answer.
    ///
    /// Skipped rather than written out because it was 25% of this answer while saying nothing: the
    /// same reason [`ModuleInfo::unloaded`] and [`PdbInfo::unmatched`] are skipped. A row without
    /// it is a register that is storage of its own.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub subregister: bool,
}

/// One register's value, tagged by what kind of value it is.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RegisterValue {
    /// An integer register, in this module's one address representation.
    Int { value: String },
    /// A floating-point register that a JSON number holds exactly.
    Float { value: f64 },
    /// A floating-point register holding a value JSON has **no literal for**: a NaN or an
    /// infinity, which a register legitimately holds and which `serde_json` renders as `null` —
    /// neither the value nor anything this schema allows, and not something that reads back.
    /// Its own kind rather than a `null` inside `float`, so the field a consumer reads is a
    /// number whenever it is present at all.
    NonFinite {
        value: NonFinite,
        /// The exact bits, as lowercase hex, little-endian. A register the engine reported as
        /// 32-bit was widened to 64 first — exact for every value except the payload of a NaN.
        bytes: String,
    },
    /// An x87 or vector register, as lowercase hex bytes in the engine's own order. Not
    /// narrowed to a number, because there is no number that holds it.
    Bytes { bytes: String },
    /// The engine holds no value for this register in this target — a minidump carrying no
    /// floating-point state answers this way. Distinct from zero.
    Unavailable,
}

/// Which value JSON could not express.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NonFinite {
    Nan,
    Infinity,
    NegativeInfinity,
}

impl From<&dbgscope::dbgeng::RegisterValue> for RegisterValue {
    fn from(value: &dbgscope::dbgeng::RegisterValue) -> Self {
        use dbgscope::dbgeng::RegisterValue as Engine;
        match value {
            Engine::Int(v) => Self::Int { value: addr(*v) },
            Engine::Float(v) if v.is_finite() => Self::Float { value: *v },
            Engine::Float(v) => Self::NonFinite {
                value: if v.is_nan() {
                    NonFinite::Nan
                } else if v.is_sign_positive() {
                    NonFinite::Infinity
                } else {
                    NonFinite::NegativeInfinity
                },
                bytes: v.to_le_bytes().iter().map(|b| format!("{b:02x}")).collect(),
            },
            Engine::Bytes(bytes) => Self::Bytes {
                bytes: bytes.iter().map(|b| format!("{b:02x}")).collect(),
            },
            Engine::Unavailable => Self::Unavailable,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ModuleList {
    /// The **loaded** modules this listing carries: those [`Self::filter`] matched, or every one —
    /// in either case as many as the call's `limit` left room for, with [`Self::matched`] saying
    /// how many there were.
    pub modules: Vec<ModuleInfo>,
    /// The modules that have **unloaded** — the engine's second list, narrowed by the same
    /// filter and rendered under its own heading in the text.
    ///
    /// Their own list rather than rows mixed into [`Self::modules`], because they answer a
    /// different question: `start`/`end` say where an image *was*, and the kernel keeps only a
    /// bounded, truncated record of it (`WpdUpFltr.sy`), so counting them among the loaded
    /// modules would overstate what is in the target now.
    ///
    /// Carried at all because the text beside these values lists them, and a listing whose two
    /// halves disagree is worse than either half alone: a filter of `nvhda` on this repo's own
    /// sample matches no loaded module and twenty-six unloaded ones, and the answer used to be
    /// "nothing matched" printed directly above twenty-six matching rows. They are also the only
    /// thing that can name a stack frame or pointer into a driver that is no longer there.
    ///
    /// **A module in this list has no [`ModuleInfo::name`]** — there is nothing left to qualify a
    /// symbol with — so it is matched, and rendered, by its image name.
    ///
    /// Sharing [`Self::modules`]' `limit` rather than having one of its own — two halves that each
    /// took the budget in full would double it — but with a share of it reserved: spending the
    /// budget in print order would let a two-hundred-row loaded table erase this list, and "no
    /// loaded module matches, but twenty-six unloaded images do" is the answer it exists to give.
    pub unloaded: Vec<ModuleInfo>,
    /// How many modules are loaded **in total** — which is the whole point of carrying it: a
    /// partial listing could otherwise be read as the inventory. Equal to [`Self::matched`] unless
    /// a filter narrowed the listing.
    pub loaded: usize,
    /// How many loaded modules the listing is a listing **of**: what [`Self::filter`] matched,
    /// before the call's `limit` cut it. Equal to [`Self::loaded`] when nothing was filtered.
    ///
    /// Carried always rather than only when it differs from `modules.len()`, because the question
    /// it answers — "is this the whole set?" — is one a caller has to be able to ask of every
    /// answer, and a length that is sometimes the total and sometimes a page of it cannot be read
    /// without knowing which. The two rules this server already keeps for a truncated answer are
    /// both here: the count comes from the same walk as the rows, and it is a value rather than
    /// something the text alone says.
    pub matched: usize,
    /// [`Self::matched`] for the unloaded half: how many of the images that have unloaded matched,
    /// before the same `limit` cut that table.
    pub unloaded_matched: usize,
    /// The pattern this listing was narrowed by, as it was actually applied rather than as it was
    /// typed: a `filter` with no wildcards is widened to `*filter*` (see the tool's argument), and
    /// this is what says so. Absent when nothing was filtered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>,
    /// What the call's `refresh` did to the engine's inventory before this listing was taken.
    ///
    /// **Absent means it was not asked for**, which is every default call — not "it was asked for
    /// and did nothing". The two have to be distinguishable because the question this listing
    /// answers most often is *is this driver loaded*, and a `matched: 0` means one thing when the
    /// inventory was resynchronised a moment ago and something much weaker when it was whatever
    /// the engine happened to be holding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh: Option<ModuleRefresh>,
}

/// What a `modules { "refresh": true }` did before the listing beside it was taken.
///
/// **Inventory, not symbols.** The engine is asked to resynchronise its module list with the
/// target (`IDebugSymbols::Reload` with no arguments, which is the `.reload` a person types).
/// That discovers images the engine has not heard of — the case this exists for is a live kernel
/// attach, where a driver loaded *before* the debugger connected is in the target and not in the
/// engine's list until something asks. It is deliberately not `.reload /f`: forcing a symbol load
/// would put a symbol-server round trip per module behind a call whose caller asked about module
/// *names*, and finding a loaded image should not cost a PDB download.
///
/// The price of that is on [`ModuleInfo::symbols`], and it is the one surprise here: **on a live
/// target** a resynchronisation discards what the engine had loaded and reloads it as needed, so
/// most rows that named a PDB before a refresh read `deferred` after one. Nothing was lost — the
/// PDB is re-read from the local cache the next time a symbol is asked for — but a caller that has
/// just run a force-reload and then refreshes has undone the state it paid for, so the order to do
/// them in is refresh first. A **dump** pays none of it: its module list comes from its own header
/// rather than from the target, so there is nothing to re-read and the symbol state survives
/// (measured either way — see `worker::resynchronise`).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ModuleRefresh {
    /// Whether the engine resynchronised. When this is `false` the listing beside it is whatever
    /// the engine was already holding, which may be stale — and is exactly the state that reads
    /// as "the driver is not loaded" when the driver is loaded.
    pub synchronized: bool,
    /// How many modules the engine listed **before** the resynchronisation, against
    /// [`ModuleList::loaded`] after it.
    ///
    /// Carried because it is the only evidence a caller has that the refresh was worth asking
    /// for, and because the number this tool exists for is the difference: a fresh kernel attach
    /// reporting `before: 1` against `loaded: 158` — measured on the CTF guest, 2026-08-30 — is
    /// the whole of [#85](https://github.com/glslang/windbg-mcp/issues/85) in two fields. On a
    /// target whose inventory was already current the two are equal, which is an answer rather
    /// than a wasted call.
    pub before: usize,
    /// Why the resynchronisation failed, in the engine's own words. Absent when it succeeded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ModuleInfo {
    /// The name this row is **listed and matched by**: its module name, or — for one that has
    /// unloaded — its image's.
    ///
    /// One definition for both, because a filter that matched on something other than what the
    /// listing prints is exactly the disagreement
    /// [#120](https://github.com/glslang/windbg-mcp/issues/120) removed. An unloaded module has no
    /// module name at all (glslang/dbgscope#101): there is nothing left to qualify a symbol with,
    /// so the image name is the only name it has.
    pub fn listed_name(&self) -> &str {
        if self.name.is_empty() {
            &self.image_name
        } else {
            &self.name
        }
    }
}

/// One loaded module.
///
/// Carries its own description because a flattened enum's would otherwise be hoisted onto the
/// struct: `symbols` is flattened in, and schemars merges its documentation with this object's.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ModuleInfo {
    /// The name symbols are qualified by — the `nt` in `nt!KeBugCheckEx`.
    pub name: String,
    /// The image's own name (`ntkrnlmp.exe`).
    pub image_name: String,
    /// Where the engine loaded the image from, where it has a path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loaded_image_name: Option<String>,
    pub start: String,
    /// One past the last byte, matching the `start end` pair `lm` prints.
    pub end: String,
    pub size: u64,
    #[serde(flatten)]
    pub symbols: SymbolState,
    pub user_mode: bool,
    /// The PE `TimeDateStamp`. With [`Self::size`] it is what a symbol server is keyed by, and
    /// what says whether an image somewhere else is *this* image — see
    /// [`docs/coordinates.md`](https://github.com/glslang/windbg-mcp/blob/main/docs/coordinates.md).
    pub timestamp: u32,
    pub checksum: u32,
    /// Which **PDB** the engine has for this module, when it has one.
    ///
    /// The image is identified by [`Self::timestamp`] + [`Self::size`]; its symbols are identified
    /// by a different pair, and this is it. Absent for a module whose `symbols` is anything but
    /// `pdb` — this reports what the engine *has*, and a deferred module has nothing until
    /// something makes it look. That is not "this module has no PDB".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pdb: Option<PdbInfo>,
    /// True for a module that has **unloaded** — the rows in [`ModuleList::unloaded`], where
    /// `start`/`end` are where the image *was*. Carried on the row as well as by which list it is
    /// in, from the engine's own flag, so a record that has been lifted out of that list still
    /// says so. Absent from the JSON when false, which is every ordinary module.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub unloaded: bool,
}

/// The identity of a module's PDB, in the form a symbol server is keyed by.
///
/// Here so that a client on another machine can fetch the **exact** symbols this engine resolved
/// without first fetching the image. The identity is recoverable from the image's own debug
/// directory, so this saves a download rather than enabling something otherwise impossible — and
/// it lets a caller check the PDB it already holds is the right one, which the image cannot do.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PdbInfo {
    /// The signature as a symbol server path spells it: 32 uppercase hex digits, no braces and no
    /// dashes. Not the form a GUID is usually printed in.
    pub guid: String,
    /// The age. Note it is appended to the GUID **in hex**, which [`Self::key`] has already done.
    pub age: u32,
    /// The path segment those two make — `<guid><age>`, the middle element of
    /// `<pdb>/<key>/<pdb>`. Carried already-built because assembling it is one line and getting it
    /// wrong (the age in decimal) produces a URL that 404s, which is a hard failure to read
    /// backwards.
    pub key: String,
    /// Whether the engine matched a PDB it then found does **not** belong to this image. Symbols
    /// read from it are another build's names, so this is a reason to distrust every symbol on
    /// this module rather than a detail. Absent from the JSON when false.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub unmatched: bool,
}

impl From<dbgscope::dbgeng::PdbIdentity> for PdbInfo {
    fn from(pdb: dbgscope::dbgeng::PdbIdentity) -> Self {
        Self {
            key: format!("{}{:X}", pdb.guid, pdb.age),
            guid: pdb.guid,
            age: pdb.age,
            unmatched: pdb.unmatched,
        }
    }
}

/// How much symbol information the engine has for a module.
///
/// Internally tagged on `symbols` and flattened into [`ModuleInfo`], so the field is **always a
/// string** — including for a symbol type this build does not name, which adds a sibling
/// `symbol_type_code` rather than turning `symbols` into an object. A field whose JSON type
/// depends on its value is one a consumer parses correctly right up until the first target that
/// reports something new.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "symbols", rename_all = "snake_case")]
pub enum SymbolState {
    None,
    /// Not loaded *yet* — the engine fetches them when something needs them. Emphatically not
    /// "this module has no symbols", which is the reading that makes `lm` output misleading.
    Deferred,
    Coff,
    CodeView,
    Pdb,
    /// Names from the export table only: enough for `module!Export`, nothing more.
    Export,
    Sym,
    Dia,
    /// A symbol type this build does not name. `symbol_type_code` is the engine's own value.
    Other {
        symbol_type_code: u32,
    },
}

impl From<dbgscope::dbgeng::SymbolKind> for SymbolState {
    fn from(kind: dbgscope::dbgeng::SymbolKind) -> Self {
        use dbgscope::dbgeng::SymbolKind as Engine;
        match kind {
            Engine::None => Self::None,
            Engine::Deferred => Self::Deferred,
            Engine::Coff => Self::Coff,
            Engine::CodeView => Self::CodeView,
            Engine::Pdb => Self::Pdb,
            Engine::Export => Self::Export,
            Engine::Sym => Self::Sym,
            Engine::Dia => Self::Dia,
            Engine::Other(code) => Self::Other {
                symbol_type_code: code,
            },
        }
    }
}

/// The word a listing prints for a symbol state, which is **the word the values carry** — the
/// serde tag, spelled once.
///
/// A rendering built from these values has to name them; writing that mapping out a second time is
/// how a text saying `codeview` ends up beside a value saying `code_view`. The test below walks
/// every variant through `serde_json` and asserts the two agree.
impl std::fmt::Display for SymbolState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => f.write_str("none"),
            Self::Deferred => f.write_str("deferred"),
            Self::Coff => f.write_str("coff"),
            Self::CodeView => f.write_str("code_view"),
            Self::Pdb => f.write_str("pdb"),
            Self::Export => f.write_str("export"),
            Self::Sym => f.write_str("sym"),
            Self::Dia => f.write_str("dia"),
            // The one variant carrying a value: the engine's own code, so an unnamed symbol type
            // is still identifiable from the text rather than reading as "something".
            Self::Other { symbol_type_code } => write!(f, "other ({symbol_type_code:#x})"),
        }
    }
}

impl From<&dbgscope::dbgeng::Module> for ModuleInfo {
    fn from(module: &dbgscope::dbgeng::Module) -> Self {
        Self {
            name: module.name.clone(),
            image_name: module.image_name.clone(),
            loaded_image_name: Some(module.loaded_image_name.clone())
                .filter(|name| !name.is_empty()),
            start: addr(module.base),
            end: addr(module.end()),
            size: u64::from(module.size),
            symbols: module.symbols.into(),
            user_mode: module.user_mode,
            timestamp: module.timestamp,
            checksum: module.checksum,
            // Filled in by the caller for the modules that have symbols: it is a second question
            // asked of the engine, and a conversion from a value it already holds cannot ask one.
            pdb: None,
            unloaded: module.unloaded,
        }
    }
}

/// What a `set_breakpoint` did, and what the session holds afterwards.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct BreakpointSet {
    /// The breakpoint this call set, as the **engine** reports it.
    ///
    /// The whole of what this call did, and known rather than inferred: the engine hands back the
    /// object it created, so its id, its address and whether it is deferred are read off it
    /// directly. Nothing here is a guess, and there is no case in which it is unavailable —
    /// a call that did not set a breakpoint is an error, not a result with this missing.
    ///
    /// **This replaced a before-and-after diff of `bl`**, which is worth knowing because the diff's
    /// empty case had four meanings and this has none: the command failed, or the expression
    /// already had a breakpoint, or the command was cut short, or the "before" listing failed and
    /// the answer was simply unknown. A caller had to be told how to tell those apart. Now the id
    /// is the answer.
    pub breakpoint: BreakpointInfo,
    /// Ids of breakpoints removed to make room, at the same resolved address.
    ///
    /// Normally empty. Non-empty means this location already had breakpoints and they have been
    /// replaced — which is what `bp` does, and what this tool has always done, but it was
    /// previously a `breakpoint N redefined` line in the debugger's text rather than a value.
    ///
    /// **Empty does not mean nothing was there**: a location that has not resolved has no address
    /// to compare, so a deferred breakpoint replaces nothing and duplicates instead. Read
    /// [`BreakpointInfo::deferred`] on [`Self::breakpoint`] before concluding the address was
    /// clear.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub replaced: Vec<u32>,
    /// Every breakpoint the session now holds, this call's included.
    ///
    /// An inspection taken after the fact, and **best-effort**: if it cannot be read this is empty,
    /// which says nothing about the breakpoint above — that one is reported by the engine as it is
    /// created. An inspection that fails after a mutation must not be reported as the mutation
    /// failing, and here it cannot be, because the two facts no longer share a field.
    #[serde(default)]
    pub breakpoints: Vec<BreakpointInfo>,
    /// Whether resolving the location was **cut short**: the engine was broken in before it
    /// finished, because the symbol outran this call's budget or because somebody called
    /// `interrupt`.
    ///
    /// One field for both, where a stop keeps them apart as `interrupted` and `timed_out`. There
    /// the next move differs — nobody asked for a deadline break, so running on answers it — and
    /// here it does not: either way the location may not have finished resolving.
    ///
    /// **The breakpoint exists either way**, which is why this is a field on a success rather than
    /// an error: an error is the shape a caller retries, and a retry here sets a second breakpoint.
    /// What it qualifies is only the *location* — read
    /// [`BreakpointInfo::deferred`] and [`BreakpointInfo::address`] on [`Self::breakpoint`] to see
    /// where it actually ended up. A break also abandons the symbol load it interrupted, so a
    /// module left on export symbols needs reloading rather than another attempt at this.
    ///
    /// Defaulted so a record written before this field existed still reads.
    #[serde(default)]
    pub cut_short: bool,
}

/// One breakpoint the session holds.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct BreakpointInfo {
    /// The id the debugger prints, and that `bc`/`bd`/`be` take.
    pub id: u32,
    #[serde(flatten)]
    pub kind: BreakpointKind,
    /// Where it will fire. Absent while it is deferred — its module is not loaded, so it has no
    /// address yet, which is not the same as an address of zero.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// The expression the engine is still holding it as, in practice only for a deferred one:
    /// a breakpoint that resolved when it was set keeps its address instead.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expression: Option<String>,
    /// The command string the debugger runs each time it fires (what `ioctl_trace` installs).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// For a data breakpoint, what it watches: the access, and how many bytes.
    ///
    /// Absent for a code breakpoint, which watches no region. Reported because the engine reports
    /// it — without it a data breakpoint says only that it *is* one, which cannot be checked
    /// against what was asked for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub watch: Option<DataWatch>,
    /// The thread it is restricted to, or absent for any thread.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread: Option<u32>,
    pub enabled: bool,
    pub deferred: bool,
    pub one_shot: bool,
    /// How many times it must be reached before it stops the target (1 = every time).
    pub pass_count: u32,
    /// How many of those passes are still to go.
    pub passes_remaining: u32,
}

/// What a breakpoint watches for.
///
/// Tagged and flattened for the reason [`SymbolState`] is: `kind` is always a string, and the one
/// case this build cannot name adds `kind_code` beside it instead of changing the field's type.
/// Not hypothetical — DbgEng also has time and inline breakpoint types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BreakpointKind {
    /// Execution reaching an address (`bp`).
    Code,
    /// Access to a range of memory (`ba`).
    Data,
    /// A type this build does not name. `kind_code` is the engine's own value.
    Other { kind_code: u32 },
}

/// What a data breakpoint watches, as the engine holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DataWatch {
    /// `read`, `write`, `read_write`, `execute`, `io` — or the engine's own bits for a combination
    /// this build does not name, which is reported rather than folded into a plausible neighbour.
    pub access: String,
    /// How many bytes are watched, starting at the breakpoint's address.
    pub size: u32,
}

impl From<dbgscope::dbgeng::DataWatch> for DataWatch {
    fn from(watch: dbgscope::dbgeng::DataWatch) -> Self {
        use dbgscope::dbgeng::DataAccess as Engine;
        Self {
            access: match watch.access {
                Engine::Read => "read".to_string(),
                Engine::Write => "write".to_string(),
                Engine::ReadWrite => "read_write".to_string(),
                Engine::Execute => "execute".to_string(),
                Engine::Io => "io".to_string(),
                Engine::Other(bits) => format!("{bits:#x}"),
            },
            size: watch.size,
        }
    }
}

impl From<&dbgscope::dbgeng::BreakpointInfo> for BreakpointInfo {
    fn from(bp: &dbgscope::dbgeng::BreakpointInfo) -> Self {
        use dbgscope::dbgeng::BreakpointKind as Engine;
        Self {
            id: bp.id,
            kind: match bp.kind {
                Engine::Code => BreakpointKind::Code,
                Engine::Data => BreakpointKind::Data,
                Engine::Other(code) => BreakpointKind::Other { kind_code: code },
            },
            address: bp.address.map(addr),
            expression: bp.expression.clone(),
            command: bp.command.clone(),
            watch: bp.data.map(DataWatch::from),
            thread: bp.thread,
            enabled: bp.enabled,
            deferred: bp.deferred,
            one_shot: bp.one_shot,
            pass_count: bp.pass_count,
            passes_remaining: bp.passes_remaining,
        }
    }
}

// ---- pool -----------------------------------------------------------------

/// The exact image and PDB-backed structural family used by an allocator walk.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AllocatorLayoutInfo {
    pub module: AllocatorModuleInfo,
    pub pdb: String,
    pub fingerprint: String,
    pub semantic_family: AllocatorSemanticFamily,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AllocatorModuleInfo {
    pub name: String,
    pub image_name: String,
    pub loaded_image_name: String,
    pub base: String,
    pub size: u32,
    pub timestamp: u32,
    pub checksum: u32,
    #[serde(flatten)]
    pub symbols: SymbolState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AllocatorSemanticFamily {
    InlineVs,
    AffinitySlotVs,
}

impl From<&dbgscope::allocator::LayoutProvenance> for AllocatorLayoutInfo {
    fn from(layout: &dbgscope::allocator::LayoutProvenance) -> Self {
        use dbgscope::allocator::VsSemanticFamily;
        Self {
            module: AllocatorModuleInfo {
                name: layout.module.name.clone(),
                image_name: layout.module.image_name.clone(),
                loaded_image_name: layout.module.loaded_image_name.clone(),
                base: addr(layout.module.base),
                size: layout.module.size,
                timestamp: layout.module.timestamp,
                checksum: layout.module.checksum,
                symbols: layout.module.symbols.into(),
            },
            pdb: layout.module.symbol_file.clone(),
            fingerprint: layout.fingerprint.clone(),
            semantic_family: match layout.semantic_family {
                VsSemanticFamily::Inline => AllocatorSemanticFamily::InlineVs,
                VsSemanticFamily::AffinitySlots => AllocatorSemanticFamily::AffinitySlotVs,
            },
        }
    }
}

/// How much of an allocator the walk behind an answer actually covered.
///
/// Every allocator answer carries this, because every one of them is drawn from a snapshot and a
/// count taken from a partial snapshot is a floor rather than a total. The ways of falling short
/// are separate values because they need different responses; a walk failing outright, or being
/// interrupted, is not a coverage state at all but the `error` branch of
/// [`Outcome`], with category [`ErrorCategory::Debugger`] or [`ErrorCategory::Interrupted`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[schemars(rename = "PoolCoverage")]
pub enum AllocatorCoverage {
    /// The walk covered everything it set out to. Counts here are totals.
    Complete,
    /// It stopped because its deadline — what was left of this call's budget — ran out. What it
    /// found was really there; what is missing is unknown rather than absent, and a longer
    /// budget (a larger `WINDBG_MCP_CALL_TIMEOUT_SECS`, or an idle session) reaches more.
    DeadlineTruncated,
    /// It ran to the end without covering all of it: unreadable regions, a region that stopped
    /// mid-chunk, a traversal cap. `pool_diagnostics` says which. Unlike `deadline_truncated`,
    /// more time changes nothing.
    Partial,
    /// The caller's `stop_after_matches` threshold was reached. This is an intentional partial
    /// answer rather than a deadline or decoder failure; `walk.stop_after_matches` names the
    /// threshold that fired.
    MatchLimitReached,
}

impl AllocatorCoverage {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::DeadlineTruncated => "deadline_truncated",
            Self::Partial => "partial",
            Self::MatchLimitReached => "match_limit_reached",
        }
    }
}

impl From<dbgscope::pool::query::WalkCoverage> for AllocatorCoverage {
    fn from(coverage: dbgscope::pool::query::WalkCoverage) -> Self {
        use dbgscope::pool::query::WalkCoverage as Engine;
        match coverage {
            Engine::Complete => Self::Complete,
            Engine::BudgetExpired => Self::DeadlineTruncated,
            Engine::Partial => Self::Partial,
        }
    }
}

/// The state of the walk an answer was drawn from.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct WalkInfo {
    pub coverage: AllocatorCoverage,
    /// The requested match threshold that intentionally stopped this walk. Absent when the
    /// threshold was not reached or a complete cached snapshot answered the query.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop_after_matches: Option<usize>,
    /// Chunks the walk indexed, allocated and free.
    pub chunks_walked: usize,
    pub allocated_chunks: usize,
    /// How many complaints the walk made — every one, not the capped sample it kept verbatim.
    pub diagnostics_emitted: usize,
    /// How many distinct kinds of complaint those fell into.
    pub diagnostic_categories: usize,
    /// What the walk could not read, in bytes and chunks, when there was anything. Absent on a
    /// walk that met none of it, which is the ordinary case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gaps: Option<WalkGaps>,
}

/// What a walk could not read, and what it read anyway by stepping over rather than giving up.
///
/// Sizes what `coverage` only names. `partial` says a walk fell short; these say by how much,
/// which is the difference between "a page was unreadable" and "a third of the pool was" — and
/// the diagnostics cannot answer it, because they collapse messages by shape and the counts
/// beside them count *occurrences of a shape*, not bytes or chunks.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WalkGaps {
    /// Pages the debugger's valid-region query could not advance over, stepped over one at a
    /// time rather than abandoning the rest of the region behind them.
    ///
    /// Narrower than it reads, and zero on a healthy walk. A query that reports finding *nothing*
    /// in the span it was asked about has answered for every byte through to the end of it, so
    /// that ends the region rather than being stepped over, and is not counted here. What remains
    /// is the query that reports a region and cannot size it — which has said nothing about what
    /// lies behind it, and is the case stepping exists for.
    pub stalled_pages: u64,
    /// Bytes those steps filed as unreadable.
    pub skipped_bytes: u64,
    /// Bytes of committed memory read *after* a stall, in the regions that stalled — coverage a
    /// walk that gave up at the first stall would have reported as nothing at all. Large next to
    /// `skipped_bytes` means the stalls were isolated pages in otherwise healthy regions.
    pub recovered_bytes: u64,
    /// Chunk headers a backend decoder refused.
    ///
    /// **Not a count of chunks lost.** A refusal resynchronises sixteen bytes along and tries
    /// again, so one lost sync bills a refusal per sixteen bytes until it recovers: a live
    /// 26100 walk reported 106,516 of these from 542 affected extents. Read it as the size of
    /// the disruption — the chunks reported from those extents were decoded at guessed offsets
    /// and are worth less than their count suggests — rather than as a population of bad
    /// chunks, which it overstates by orders of magnitude.
    pub refused_chunks: u64,
    /// Committed bytes of a variable-size subsegment the walk declined to decode, because it
    /// could not say where a chunk began in them.
    ///
    /// A chunk of that kind is only findable from the end of the one before it, and a walk that
    /// has lost that thread does not guess: guessing is what filled a snapshot with chunks
    /// decoded at arbitrary offsets. This is what declining costs — coverage, in bytes — so that
    /// a clean `refused_chunks` cannot be mistaken for a walk that read everything.
    pub unplaced_bytes: u64,
}

impl WalkGaps {
    /// `None` when the walk met none of this, so the ordinary answer does not carry five zeroes.
    pub(crate) fn of(report: &dbgscope::pool::query::PoolSnapshotReport) -> Option<Self> {
        Self::from_measurements(report.stalls, report.refused_chunks, report.unplaced_bytes)
    }

    pub(crate) fn of_heap(report: &dbgscope::heap::HeapWalkReport) -> Option<Self> {
        Self::from_measurements(report.stalls, report.refused_headers, report.unplaced_bytes)
    }

    fn from_measurements(
        stalls: dbgscope::pool::WalkStalls,
        refused_chunks: u64,
        unplaced_bytes: u64,
    ) -> Option<Self> {
        let gaps = Self {
            stalled_pages: stalls.pages,
            skipped_bytes: stalls.skipped_bytes,
            recovered_bytes: stalls.recovered_bytes,
            refused_chunks,
            unplaced_bytes,
        };
        (gaps != Self::default()).then_some(gaps)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PoolChunkInfo {
    /// What the allocation call returned, and so what the target's own pointers hold.
    pub address: String,
    /// Where the allocator's bookkeeping starts. Rarely what a caller is holding.
    pub header_address: String,
    pub size: u64,
    pub state: PoolChunkState,
    /// The tag as the debugger prints it — a label, not a key. See [`PoolTagTotals::tag`].
    pub tag: String,
    /// The same tag as its four bytes, in memory order: what `pool_find_tag` can be handed back.
    pub raw_tag: String,
    pub pool: PoolKindName,
    pub backend: PoolBackendName,
    pub numa_node: u16,
    /// Whether this chunk sits in Driver Verifier special pool — a whole page against a guard
    /// page, so an overflow or a touch after free faults at once.
    pub special_pool: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PoolChunkState {
    Allocated,
    /// Freed and available for reuse: a pointer the target still holds to it is dangling.
    ReusableFree,
    /// Freed into a cache: likewise dangling.
    CachedFree,
    /// The walk could not read the span. A limit of the walk, not a fact about lifetime — a
    /// Verifier guard page reads exactly this way.
    Unreadable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PoolKindName {
    NonPagedExecutable,
    NonPagedNx,
    Paged,
    PrototypePaged,
    SpecialNonPaged,
    SpecialNonPagedNx,
    SpecialPaged,
    SpecialPrototypePaged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PoolBackendName {
    Lfh,
    Vs,
    Segment,
    Large,
}

impl From<&dbgscope::pool::PoolSpan> for PoolChunkInfo {
    fn from(span: &dbgscope::pool::PoolSpan) -> Self {
        use dbgscope::pool::{PoolBackend, PoolKind, PoolState};
        Self {
            address: addr(span.usable_address),
            header_address: addr(span.header_address),
            size: span.size,
            state: match span.state {
                PoolState::Allocated => PoolChunkState::Allocated,
                PoolState::ReusableFree => PoolChunkState::ReusableFree,
                PoolState::CachedFree => PoolChunkState::CachedFree,
                PoolState::Unreadable => PoolChunkState::Unreadable,
            },
            tag: span.display_tag.clone(),
            raw_tag: dbgscope::pool::raw_tag_hex(span.raw_tag),
            pool: match span.pool_kind {
                PoolKind::NonPagedExecutable => PoolKindName::NonPagedExecutable,
                PoolKind::NonPagedNx => PoolKindName::NonPagedNx,
                PoolKind::Paged => PoolKindName::Paged,
                PoolKind::PrototypePaged => PoolKindName::PrototypePaged,
                PoolKind::SpecialNonPaged => PoolKindName::SpecialNonPaged,
                PoolKind::SpecialNonPagedNx => PoolKindName::SpecialNonPagedNx,
                PoolKind::SpecialPaged => PoolKindName::SpecialPaged,
                PoolKind::SpecialPrototypePaged => PoolKindName::SpecialPrototypePaged,
            },
            backend: match span.backend {
                PoolBackend::Lfh => PoolBackendName::Lfh,
                PoolBackend::Vs => PoolBackendName::Vs,
                PoolBackend::Segment => PoolBackendName::Segment,
                PoolBackend::Large => PoolBackendName::Large,
            },
            numa_node: span.numa_node,
            special_pool: span.heap.special,
        }
    }
}

/// What `pool_find_tag` found.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PoolTagMatches {
    pub layout: AllocatorLayoutInfo,
    /// The tag as the caller named it, in whichever form they used.
    pub tag: String,
    /// The four bytes that name actually resolved to, in memory order. Worth reading back when
    /// `tag` was a rendering: `....` resolves to literal `.` bytes, which is rarely what was
    /// meant, and this is where that shows.
    pub raw_tag: String,
    pub scope: PoolScope,
    /// How many allocated chunks carry the tag. A floor rather than a total unless
    /// `walk.coverage` is `complete`; when it is `match_limit_reached`, this is the threshold
    /// reached by the intentional early stop.
    pub matches: usize,
    /// Their total size in bytes, over every match the walk found — not only the ones listed.
    /// This is a floor unless `walk.coverage` is `complete`.
    pub total_bytes: u64,
    /// The matches themselves, capped by the call's rendering `limit`; `matches` is the full
    /// count from this walk.
    pub chunks: Vec<PoolChunkInfo>,
    pub walk: WalkInfo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PoolScope {
    Both,
    Paged,
    NonPaged,
}

/// What `pool_chunk` found at an address.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PoolChunkAt {
    pub layout: AllocatorLayoutInfo,
    /// The address asked about.
    pub address: String,
    /// Whether the snapshot covers this address at all. False is *not* "free": it means the
    /// address is not pool, or sits in a region this walk never reached — check `walk.coverage`
    /// before reading it as either.
    pub covered: bool,
    /// The chunk containing the address, when one covers it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chunk: Option<PoolChunkInfo>,
    /// How far into that chunk the address sits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous: Option<PoolChunkInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next: Option<PoolChunkInfo>,
    pub walk: WalkInfo,
}

/// What `pool_census` totalled.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PoolCensus {
    pub layout: AllocatorLayoutInfo,
    /// How many distinct tags are allocated. The listing below is capped by `limit`.
    pub distinct_tags: usize,
    pub tags: Vec<PoolTagTotals>,
    pub walk: WalkInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PoolTagTotals {
    /// The tag as the debugger prints it. A **label, not a key**: unprintable bytes render as
    /// `.` and so does a literal `.`, so several distinct tags can share one rendering — which
    /// is not hypothetical, since the heaviest two tags on a live kernel are routinely binary.
    /// Pass `raw_tag` to `pool_find_tag`, not this.
    pub tag: String,
    /// The same tag as its four bytes: `0x` and two hex digits each, in memory order. This is
    /// what identifies it, and what `pool_find_tag` accepts alongside the printed form.
    pub raw_tag: String,
    pub allocations: usize,
    pub total_bytes: u64,
    pub paged_allocations: usize,
    pub nonpaged_allocations: usize,
}

/// What `pool_diagnostics` selected.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PoolDiagnosticsReport {
    pub layout: AllocatorLayoutInfo,
    /// The substring the listing was narrowed to, when it was.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>,
    /// Categories matching the filter, commonest first, capped by `limit`.
    pub categories: Vec<DiagnosticCategory>,
    /// Verbatim messages matching the filter, capped by `limit`. A *sample*: the walk keeps
    /// only a few per category, so their number says nothing about volume — `categories` does.
    pub examples: Vec<String>,
    /// How many categories matched, before the cap.
    pub matched_categories: usize,
    /// How many kept messages matched, before the cap.
    pub matched_examples: usize,
    pub walk: WalkInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DiagnosticCategory {
    /// The message with its addresses and numbers generalised away — which is what lets it
    /// carry a count, and why a filter naming a concrete address never matches one.
    pub shape: String,
    /// Every message of this shape the walk emitted, not just the ones kept verbatim.
    pub total: usize,
}

// ---- user Segment Heap ----------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HeapKindName {
    Segment,
    Nt,
    Unknown,
    Unreadable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HeapBackendName {
    Lfh,
    Vs,
    Segment,
    Large,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HeapChunkState {
    Allocated,
    ReusableFree,
    CachedFree,
    Unreadable,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct HeapRootInfo {
    pub index: usize,
    pub address: String,
    pub kind: HeapKindName,
    pub supported: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl From<&dbgscope::heap::HeapRoot> for HeapRootInfo {
    fn from(root: &dbgscope::heap::HeapRoot) -> Self {
        use dbgscope::heap::HeapKind;
        Self {
            index: root.index,
            address: addr(root.address),
            kind: match root.kind {
                HeapKind::Segment => HeapKindName::Segment,
                HeapKind::Nt => HeapKindName::Nt,
                HeapKind::Unknown => HeapKindName::Unknown,
                HeapKind::Unreadable => HeapKindName::Unreadable,
            },
            supported: root.supported,
            reason: root.reason.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct HeapAllocationInfo {
    pub heap: String,
    pub backend: HeapBackendName,
    pub state: HeapChunkState,
    pub header_address: String,
    pub user_address: String,
    pub capacity: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subsegment: Option<String>,
    pub size_class: u32,
}

impl From<&dbgscope::heap::HeapAllocation> for HeapAllocationInfo {
    fn from(allocation: &dbgscope::heap::HeapAllocation) -> Self {
        use dbgscope::heap::{HeapBackend, HeapState};
        Self {
            heap: addr(allocation.heap),
            backend: match allocation.backend {
                HeapBackend::Lfh => HeapBackendName::Lfh,
                HeapBackend::Vs => HeapBackendName::Vs,
                HeapBackend::Segment => HeapBackendName::Segment,
                HeapBackend::Large => HeapBackendName::Large,
            },
            state: match allocation.state {
                HeapState::Allocated => HeapChunkState::Allocated,
                HeapState::ReusableFree => HeapChunkState::ReusableFree,
                HeapState::CachedFree => HeapChunkState::CachedFree,
                HeapState::Unreadable => HeapChunkState::Unreadable,
            },
            header_address: addr(allocation.header_address),
            user_address: addr(allocation.user_address),
            capacity: allocation.capacity,
            requested_size: allocation.requested_size,
            subsegment: allocation.subsegment.map(addr),
            size_class: allocation.size_class,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct HeapScopeInfo {
    pub segment_heaps_walked: Vec<String>,
    pub nt_heaps_skipped: Vec<String>,
    pub unknown_heaps_skipped: Vec<String>,
    pub unreadable_heaps_skipped: Vec<String>,
}

impl From<&dbgscope::heap::HeapScope> for HeapScopeInfo {
    fn from(scope: &dbgscope::heap::HeapScope) -> Self {
        Self {
            segment_heaps_walked: scope
                .segment_heaps_walked
                .iter()
                .copied()
                .map(addr)
                .collect(),
            nt_heaps_skipped: scope.nt_heaps_skipped.iter().copied().map(addr).collect(),
            unknown_heaps_skipped: scope
                .unknown_heaps_skipped
                .iter()
                .copied()
                .map(addr)
                .collect(),
            unreadable_heaps_skipped: scope
                .unreadable_heaps_skipped
                .iter()
                .copied()
                .map(addr)
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct HeapWalkInfo {
    pub coverage: AllocatorCoverage,
    pub chunks_walked: usize,
    pub allocated_chunks: usize,
    pub diagnostics_emitted: usize,
    pub unreadable_gaps: usize,
    /// What the walk could not read or decode, when there was anything. Healthy results omit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gaps: Option<WalkGaps>,
}

impl From<&dbgscope::heap::HeapWalkReport> for HeapWalkInfo {
    fn from(walk: &dbgscope::heap::HeapWalkReport) -> Self {
        Self {
            coverage: walk.coverage.into(),
            chunks_walked: walk.total_chunks,
            allocated_chunks: walk.allocated_chunks,
            diagnostics_emitted: walk.diagnostic_count,
            unreadable_gaps: walk.unreadable_gaps,
            gaps: WalkGaps::of_heap(walk),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct HeapListResult {
    pub layout: AllocatorLayoutInfo,
    pub scope: HeapScopeInfo,
    pub walk: HeapWalkInfo,
    pub heaps: Vec<HeapRootInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct HeapAllocationsResult {
    pub layout: AllocatorLayoutInfo,
    pub scope: HeapScopeInfo,
    pub walk: HeapWalkInfo,
    pub matches: usize,
    pub allocations: Vec<HeapAllocationInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct HeapChunkResult {
    pub layout: AllocatorLayoutInfo,
    pub scope: HeapScopeInfo,
    pub walk: HeapWalkInfo,
    pub address: String,
    /// Whether the Segment Heap snapshot covers this address at all. False is not "free": the
    /// address may not be user heap, or may sit in a region this walk never reached. Read
    /// `walk.coverage` before treating absence as evidence.
    pub covered: bool,
    /// Signed displacement from `allocation.user_address`; a header address is negative.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allocation: Option<HeapAllocationInfo>,
    /// The contiguous previous allocation in the same heap, backend, and subsegment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous: Option<HeapAllocationInfo>,
    /// The contiguous next allocation in the same heap, backend, and subsegment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next: Option<HeapAllocationInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct HeapCensusRowInfo {
    pub heap: String,
    pub backend: HeapBackendName,
    pub state: HeapChunkState,
    pub size_class: u32,
    pub chunks: usize,
    pub total_capacity: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct HeapCensusResult {
    pub layout: AllocatorLayoutInfo,
    pub scope: HeapScopeInfo,
    pub walk: HeapWalkInfo,
    pub groups: usize,
    pub rows: Vec<HeapCensusRowInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct HeapDiagnosticsResult {
    pub layout: AllocatorLayoutInfo,
    pub scope: HeapScopeInfo,
    pub walk: HeapWalkInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub heap: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>,
    pub matched_categories: usize,
    pub matched_examples: usize,
    pub categories: Vec<DiagnosticCategory>,
    pub examples: Vec<String>,
}

/// What `crash_triage` read off a bug check.
///
/// **Two provenances, kept apart on purpose.** Everything outside [`Self::analysis`] is read from
/// the engine as values — `ReadBugCheckData`, a stack walk, the module table, the current
/// process — and is as reliable as the dump. [`Self::analysis`] is `!analyze -v`'s own
/// conclusions, which are a heuristic: useful, occasionally wrong, and the reason the frames here
/// are attributed to modules independently rather than taken from it.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CrashTriage {
    pub bug_check: BugCheckInfo,
    /// The process the crashing context was in — `PROCESS_NAME`, read through the engine rather
    /// than off `!analyze`. Absent when the engine could not name it.
    ///
    /// On a kernel target this is the current `_EPROCESS`'s **audit name**, so it is the full
    /// image name (`mm_exploit_v5.exe`) rather than the 15-byte `ImageFileName` field, which cuts
    /// a name that long to `mm_exploit_v5.` — a string that looks like an answer and is not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
    /// The innermost frame that could be a kernel driver at all — in a driver bug, the driver.
    ///
    /// Ruled out: the kernel image and the HAL (which carry the bug check itself), the framework
    /// layers that sit on a stack on somebody else's behalf (KMDF, Driver Verifier), and any
    /// **user-mode** module, since a kernel stack that unwinds past the system call boundary keeps
    /// going into `ntdll` and the caller's own `.exe`, neither of which can be a driver. A frame in
    /// *no* module is not ruled out: a freed pool page or an unloaded driver looks exactly like
    /// that, and both are what a driver bug leaves behind.
    ///
    /// **A first guess, not a verdict.** The rule is positional, so a crash whose stack runs
    /// through a layer this build does not recognise as a layer names that layer instead of the
    /// driver behind it. What *is* reliable is each frame's `module` + `rva`, computed from the
    /// engine's load bases — so [`Self::frames`] is what settles a disagreement, and
    /// `analysis.module_name` is `!analyze`'s independent guess beside this one.
    ///
    /// `None` when no captured frame qualifies, which is a real answer (the bug is in the kernel's
    /// own path, or the stack did not reach the culprit) and not a failure;
    /// [`Self::faulting_frame_note`] says which.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub faulting_frame: Option<FrameInfo>,
    /// Why there is no [`Self::faulting_frame`], when there is none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub faulting_frame_note: Option<String>,
    /// The stack of **the context the session has selected**, innermost first, capped by the
    /// call's `frames` argument.
    ///
    /// On a freshly opened crash dump that context is the crash. It is the crash even on a session
    /// a caller had navigated away from **when the `!analyze -v` ran to completion**
    /// ([`AnalysisInfo::ran`] and not [`AnalysisInfo::truncated`]), because running it leaves the
    /// scope at the target's default — and the scope the caller chose is restored after the walk,
    /// so that normalisation costs them nothing. When it did not — `analyze: false`, no time left,
    /// an engine with no extensions, or a run the deadline cut short before it reached the reset
    /// it does partway through its own output — nothing normalises anything: a caller who has
    /// moved the context (`.thread`, `~Ns`, `.cxr` through `execute`) gets the stack they moved it
    /// to. Either way this is the same stack `backtrace` would print from that context, not a
    /// separately-discovered crash stack.
    pub frames: Vec<FrameInfo>,
    /// Whether the stack went on past the cap.
    ///
    /// Established by walking one frame further than was asked for and discarding it, so a stack
    /// that happens to be exactly `frames` long reports `false` — the distinction matters, because
    /// it decides whether an absent `faulting_frame` is a fact about the crash or an artefact of
    /// the cap. When `true`, raise `frames` and ask again.
    pub frames_truncated: bool,
    pub analysis: AnalysisInfo,
}

/// The bug check itself, exactly as the engine reports it.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct BugCheckInfo {
    /// The code, `0x`-prefixed and lowercase — `"0x9f"`, `"0x13a"`. Not zero-padded: this is a
    /// small enumerated value, not an address, and `0x9f` is how every bug check reference,
    /// the blue screen and `!analyze` all spell it.
    pub code: String,
    /// The bug check's name, where this build knows the code or `!analyze` printed it —
    /// `"DRIVER_POWER_STATE_FAILURE"`. Absent for a code neither could name; [`Self::code`] is
    /// still the answer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// `Arg1`..`Arg4`, always four, in the order the bug check screen prints them. Addresses by
    /// convention (padded, lowercase) because that is what most of them are; what each *means*
    /// is per-code, and `analysis.parameter_notes` carries `!analyze`'s explanation when it ran.
    pub parameters: Vec<String>,
}

/// One stack frame, named two ways.
///
/// `symbol` is what the debugger resolves; `module` + `rva` is what it can always compute. The
/// second is the point: a driver with no PDB has no `symbol` at all, and a bug check in one is
/// identified by the offset into its image — which is stable across reboots, unlike the load
/// address it was computed from.
///
/// One type for both stack tools: [`CrashTriage::frames`] and [`StackTrace::frames`] are the same
/// records from the same walk, so a frame from either joins the other — and anything else keyed by
/// `(module, rva)`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct FrameInfo {
    /// Position in the walk; 0 is where the target is stopped.
    pub index: u32,
    /// The instruction this frame is executing at.
    pub address: String,
    /// The module holding [`Self::address`], or absent if it is in none (unloaded driver, pool).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    /// The offset of [`Self::address`] from that module's load base — the `1654` in
    /// `MessageManager+0x1654`. `0x`-prefixed and lowercase, and *not* padded: an offset within
    /// an image is not an address, and this is the form that can be pasted after `module+`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rva: Option<String>,
    /// `module!Symbol` as the debugger resolves it, or absent when nothing resolves.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    /// How far past [`Self::symbol`] the instruction is, when there is a symbol. Unpadded, like
    /// [`Self::rva`], and for the same reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub displacement: Option<String>,
    /// True when the engine's "which module holds this address" lookup **failed**, rather than
    /// answering that no module does.
    ///
    /// Both leave [`Self::module`] and [`Self::rva`] absent, and they are opposite facts. "No
    /// loaded module holds this address" is a *positive finding*, and one a driver bug produces
    /// constantly — a freed pool page, an unloaded driver, a corrupted return address. "The lookup
    /// failed" is an absence of information, and reading it as the first would let one failed call
    /// be reported as evidence about the target. The distinction has always existed inside the
    /// walk, because picking a faulting frame needs it; without this field it stopped at the wire.
    ///
    /// Absent from the JSON when false, which is every frame of an ordinary walk.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub attribution_failed: bool,
}

/// The call stack of the context the session has selected, as values and as the listing rendered
/// from them.
///
/// **The coordinate, not the printout.** `k` renders a frame as `module!Symbol+0x1c`, which is
/// unusable the moment the symbol does not resolve — and on a driver with no PDB it never does.
/// Every frame here carries `module` + `rva` as well, computed from the load base the engine
/// reports, which is the form that survives an unsymbolised driver and stays comparable across
/// reboots and across machines. That is what lets a frame be joined to a function in a
/// disassembler without either side knowing the other exists.
///
/// **Rendered from these same values**, as [`ModuleList`] is, so the listing and the records
/// cannot disagree ([#120](https://github.com/glslang/windbg-mcp/issues/120)). The cost is that
/// this is *not* `k`'s output: the engine's own listing has `Child-SP` and `RetAddr` columns
/// these records do not carry, and it synthesises `[Inline Frame]` rows that a stack walk does
/// not return, so a stack with inlined callees has more lines in `k` than it has frames here.
/// `execute { "command": "k" }` is that listing verbatim for anyone who wants it.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct StackTrace {
    /// The frames, innermost first, capped by the call's `frames` argument.
    pub frames: Vec<FrameInfo>,
    /// Whether the stack went on past the cap.
    ///
    /// Established by walking one frame further than was asked for and discarding it, exactly as
    /// [`CrashTriage::frames_truncated`] is — so a stack that happens to be exactly `frames` long
    /// reports `false`. When `true`, raise `frames` and ask again.
    pub frames_truncated: bool,
}

/// A run of instructions, as values and as the listing rendered from them.
///
/// **The coordinate, on every instruction.** A disassembly is a contiguous range, so naming the
/// image once for the whole answer and letting each instruction inherit it is tempting, and it was
/// how this was first written. It is wrong: an instruction the engine places in **no** module has
/// nothing to inherit, and an absent field that means "look at the range" cannot also mean "there
/// is nothing to look at" — so a single unattributed instruction was silently credited to the
/// image around it. Each instruction therefore carries its own `module`, as a stack frame does,
/// and the pair is read off the instruction alone.
///
/// **Rendered from these same values**, so the listing and the records cannot disagree. It is
/// therefore not `u`'s output: no `module!Symbol+0x1c:` labels between instructions, since a stack
/// walk of labels is a second question this does not ask. `execute { "command": "u" }` is the
/// engine's own listing.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Disassembly {
    /// Where the disassembly began — the call's `address` after the debugger evaluated it, so a
    /// caller who passed `nt!KeBugCheckEx` learns what that resolved to.
    pub start: String,
    /// The instructions, in address order.
    pub instructions: Vec<InstructionInfo>,
    /// Whether the engine stopped before `count` instructions because it could not disassemble
    /// what came next.
    ///
    /// Not an error and not a truncation: disassembly runs forward into whatever follows, and
    /// what follows the end of a function may be unmapped, unreadable, or not code. `true` means
    /// the range simply ends here — asking again with a larger `count` returns the same
    /// instructions.
    pub stopped_early: bool,
}

/// One instruction of a [`Disassembly`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct InstructionInfo {
    /// Where it is.
    pub address: String,
    /// The image holding it, or absent if it is in none — code in a pool allocation, or a driver
    /// that has unloaded. Travels with [`Self::rva`]: either both are there or neither is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    /// Its offset from that module's load base — the half that survives a rebase, and the half an
    /// analysis server can be asked about. Absent exactly when [`Self::module`] is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rva: Option<String>,
    /// True when the engine's module lookup **failed** for this address, rather than answering
    /// that no module holds it. The same distinction, and the same reason for keeping it, as
    /// [`FrameInfo::attribution_failed`]: one is a finding about the target, the other is a call
    /// that did not answer, and both otherwise arrive as an absent coordinate.
    ///
    /// Absent from the JSON when false, which is every instruction of an ordinary disassembly.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub attribution_failed: bool,
    /// The encoding, **as the engine prints it** — `48895c2408` on x64, `d503237f` on ARM64,
    /// where that is the instruction word rather than the four bytes in memory order. It is a
    /// spelling to compare against another disassembly of the same architecture, not a byte string
    /// to match against a file: two images that disassemble differently are different builds
    /// whatever their names say, and that is the check this is for.
    pub bytes: String,
    /// The mnemonic and operands, the engine's own rendering with its column padding collapsed.
    pub text: String,
}

/// What `!analyze -v` concluded, kept separate from the values above because it is a heuristic.
///
/// Every field is `!analyze`'s own, extracted from its summary block. They are here because they
/// are the ones no API answers — most of all the pool tag, which `!analyze` recovers from the
/// header of the chunk a pool bug check is about.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AnalysisInfo {
    /// Whether `!analyze -v` ran and produced output. `false` is ordinary rather than a failure:
    /// the call may have asked for `analyze: false`, or the engine may have no extensions.
    pub ran: bool,
    /// Whether it was cut short by this call's deadline before it finished.
    ///
    /// The one qualification that changes how an *absent* field below reads: `!analyze` prints its
    /// summary block early, so a truncated run still carries real values — but a `pool_tag` that
    /// is missing may simply never have been reached, rather than `!analyze` having decided this
    /// bug check has none.
    pub truncated: bool,
    /// Which spelling produced it — `!analyze -v`, or `!ext.analyze -v` on an engine where the
    /// unqualified form does not resolve.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// The bug check's name off `!analyze`'s own header line. Beside `bug_check.name` rather than
    /// merged into it: that field prefers this build's table, and falls back to this one only for
    /// a code the table does not know.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bug_check_name: Option<String>,
    /// The pool tag `!analyze` blamed (`FREED_POOL_TAG`, or `POOL_TAG` where it names one).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pool_tag: Option<String>,
    /// `FAILURE_BUCKET_ID` — the bucket this crash would be grouped under.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_bucket_id: Option<String>,
    /// `MODULE_NAME`, `!analyze`'s guess at the culprit. Compare it with `faulting_frame`: for a
    /// driver without a PDB the two disagree often enough that the frame is the one to trust.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module_name: Option<String>,
    /// `IMAGE_NAME`, the image behind [`Self::module_name`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_name: Option<String>,
    /// `PROCESS_NAME` as `!analyze` printed it, beside the engine's own answer above.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
    /// `!analyze`'s explanation of each bug check parameter, in `Arg1`..`Arg4` order. Empty when
    /// it did not run or printed none.
    pub parameter_notes: Vec<String>,
    /// Why the analysis is missing or incomplete, when it is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

// ---- memory walks ---------------------------------------------------------

/// What `walk_memory` visited, what it read at each node, and why it stopped.
///
/// The shape exists because a walk's *holes* are its most valuable output. A MASM `.for` loop
/// through `execute` answers all-or-nothing — one unmapped dereference and the whole script is
/// `0x80040205` with no rows at all — and in pool work "some of these nodes are freed" is the
/// normal case ([#103](https://github.com/glslang/windbg-mcp/issues/103)). So a value that could
/// not be read is a `null` in its own field, a node where nothing could be read is counted, and
/// the walk carries on.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MemoryWalk {
    pub mode: WalkMode,
    /// The resolved address the walk started from. Absent for a list of addresses, which has no
    /// start — every entry is one address among many rather than the place a traversal began.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start: Option<String>,
    /// How many nodes the walk was asked for: `count`, or the length of the address list.
    pub requested: u32,
    /// How many it actually produced. Short of `requested` means it stopped early, and
    /// [`Self::stopped`] says why — which is never "an address would not read", for an array or
    /// a list.
    pub walked: u32,
    /// How many of those nodes yielded **no** readable value at all. A node with one unreadable
    /// field among several is not one of these; per-field `value: null` marks those.
    pub unreadable: u32,
    pub nodes: Vec<WalkNode>,
    pub stopped: WalkStop,
    /// Why *nothing* could be read, when nothing could: the debugger's own words for the first
    /// failed read.
    ///
    /// Present only when every node came back unreadable, which is the one case where this tool's
    /// answer is ambiguous. A list of freed objects legitimately reads that way — and so does a
    /// target that is not broken in, a session whose engine has let go, or a `start` pointing at
    /// nothing. Without the engine's message those are the same table.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// How a walk found its nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WalkMode {
    /// Addresses supplied outright.
    List,
    /// `start + i * stride`.
    Array,
    /// The pointer at `node + next_offset`, followed.
    Chain,
}

/// One node: where it was, what it held, and whether anything there could be read.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct WalkNode {
    /// Position in the walk, from 0.
    pub index: u32,
    pub address: String,
    /// The link this node held, for a chain — the address the walk went to next. `null` when the
    /// link could not be read, which for a chain is also where the walk ends, and always for a
    /// list or an array, which follow no link.
    ///
    /// **Always present, `null` included.** The two nullable fields on a walk are the ones a
    /// caller reads to find the holes, so an omitted key would make "this node's link is
    /// unreadable" and "this object came back malformed" the same observation — see
    /// [`WalkFieldValue::value`].
    pub next: Option<String>,
    pub fields: Vec<WalkFieldValue>,
    /// Whether *anything* at this node could be read. `false` is the interesting case in a
    /// use-after-free walk: the node's page is gone.
    pub readable: bool,
}

/// One field of one node.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct WalkFieldValue {
    /// The column name, as the request gave it or defaulted to the offset (`+0x18`).
    pub name: String,
    /// Where this value was read from: the node's address plus the field's offset.
    pub address: String,
    /// Bytes read: 1, 2, 4 or 8.
    pub size: u32,
    /// The value, zero-extended to 64 bits and rendered in this module's one address form
    /// whatever [`Self::size`] is — so a client never has to know a field's width to compare it.
    /// `null` means the debugger could not read those bytes.
    ///
    /// **Always present, `null` included** — the one place in this module where an absent key
    /// would be wrong rather than tidy. Everywhere else `null` is the boring case and omitting it
    /// saves noise; here it *is* the finding, and a client that has to tell a missing key from a
    /// null one is doing extra work to read the answer the tool exists to give. `MemoryWalk`'s own
    /// optional fields ([`MemoryWalk::start`], [`MemoryWalk::note`]) keep the usual treatment,
    /// because "there is no start" and "nothing needed explaining" really are absences.
    pub value: Option<String>,
}

/// Why a walk ended.
///
/// Seven reasons rather than a `complete` flag, because they call for opposite responses: a chain
/// that hit a null link is *finished*, one that hit the cap has more to walk and says where from,
/// one that hit an unreadable link has more that cannot be reached from here, and one the clock
/// stopped may have all of it still there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum WalkStop {
    /// Every node asked for was visited. Holes in an array or a list are reported per node and do
    /// not stop the walk, so this is the ordinary outcome for both.
    Complete,
    /// A chain reached the requested `count` with the list still going. `next` is the address to
    /// walk from to continue.
    Cap { next: String },
    /// A chain's next pointer is null: the list ends here.
    NullLink,
    /// A chain arrived at a node it had already visited. At the head that is the ordinary end of
    /// a circular `_LIST_ENTRY`; anywhere else it is a corrupted list, which is a finding.
    Loop { at: String },
    /// A chain's next pointer could not be read, so there is no address to continue from. Only a
    /// chain ends this way — an array's next address is arithmetic and a list's was supplied.
    UnreadableLink { at: String },
    /// The call's remaining time ran out. What is missing is unknown rather than absent.
    Deadline,
    /// `interrupt` was called on this session.
    Interrupted,
}

// ---- transactional batches ------------------------------------------------

/// What a `debug_batch` did, as values.
///
/// The last tool whose whole answer was a rendering. It is also the one with the most at stake in
/// being readable by a program: a batch is run precisely when something *mutates* the target, and
/// the two questions a caller has to act on afterwards — did this commit, and did the rollback put
/// everything back — were answerable only by matching on `BATCH: FAILED` and `rollback: INCOMPLETE`
/// in prose. A transcript recording that prose records the wording, not the verdict
/// ([#87](https://github.com/glslang/windbg-mcp/issues/87)).
///
/// One thing is deliberately **not** here: each step's debugger output. It is in the text half,
/// which is where a rendering belongs, and carrying a copy of every step's captured output would
/// make the typed answer the larger of the two channels while adding no fact this does not already
/// name. What each step *changed* is a fact, and that is [`BatchStepInfo::changes`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct BatchReportInfo {
    /// How the batch as a whole ended.
    pub outcome: BatchOutcomeName,
    /// The 1-based position the outcome is about: the step that failed, or the first one not
    /// attempted. Absent only for [`BatchOutcomeName::Committed`], where every step ran.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at: Option<u32>,
    /// Every step ran and every assertion held. The same fact as `outcome == committed`, named
    /// because it is the one a caller branches on.
    pub committed: bool,
    /// Whether every `always` step completed. **Read this even when `committed` is true**: a
    /// rollback that did not finish is a target left patched, and it is independent of how the
    /// steps themselves went.
    pub rollback_complete: bool,
    /// What the session holds now — the question the step list cannot answer.
    pub after: SessionAfterInfo,
    /// The budget the batch was given.
    pub budget_ms: u64,
    /// What it actually took.
    pub elapsed_ms: u64,
    /// The `steps` block, in order.
    pub steps: Vec<BatchStepInfo>,
    /// The `always` block, in order. Present whatever the outcome: it runs on every path, which
    /// is what a batch is for.
    pub always: Vec<BatchStepInfo>,
}

/// How a batch ended. Mirrors [`crate::batch::BatchOutcome`] without its position, which is
/// [`BatchReportInfo::at`] — one field for one fact, rather than a payload on four of five
/// variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BatchOutcomeName {
    /// Every step ran and every assertion held.
    Committed,
    /// A step failed, or an assertion did not hold.
    Failed,
    /// The deadline expired.
    TimedOut,
    /// The session was torn down under it — a disconnect, or `end_session`. Nothing was wrong
    /// with the steps, so resubmitting the whole batch is the right next move.
    Abandoned,
    /// `interrupt` was called on this batch's session. The session still holds its target, so
    /// this batch can be resubmitted as it stands.
    Interrupted,
    /// A step ended the target — it ran to completion, or the step released it — so the steps
    /// after it were not attempted. Nothing failed, but this session has nothing left to run
    /// against and its `always` block ran against a target that was not there: read `always` for
    /// what could not be undone, and open a new session.
    TargetGone,
}

/// One step, as the report tells it.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct BatchStepInfo {
    /// 1-based position within its own block.
    pub position: u32,
    /// The step's label, or the action if it was not given one.
    pub label: String,
    /// What actually ran, after interpolation — not what was written.
    pub action: String,
    pub result: StepResultName,
    /// Why, for every result but [`StepResultName::Ok`]: the debugger's refusal, the assertion
    /// that did not hold, or why the step was never attempted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// What this step changed, where the executor recognised a mutation. Recorded whether or not
    /// the step then succeeded — a command that errors may already have written.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub changes: Option<String>,
    /// A break landed while this step was running, so its output is what it had reached rather
    /// than what it would have produced.
    pub cut_short: bool,
    /// This step ended the target: it ran to completion, or the step released it. Terminal — the
    /// steps after it were not attempted, and nothing further will run on this session.
    ///
    /// Defaulted so a record written before this field existed still reads.
    #[serde(default)]
    pub target_gone: bool,
}

/// How one step ended. [`crate::batch::StepResult`] without its message, which is
/// [`BatchStepInfo::detail`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StepResultName {
    Ok,
    /// The debugger refused the operation.
    Failed,
    /// The action succeeded and an assertion on it did not hold.
    Unmet,
    /// Never attempted.
    Skipped,
}

/// What the session holds once the batch is done.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SessionAfterInfo {
    /// The engine answered with a current instruction pointer.
    Stopped { ip: String },
    /// The target was told to run and never reported a stop.
    Running { why: String },
    /// A step released or replaced the target.
    Detached { by: String },
    /// The target ran to completion. Kept apart from [`Self::Detached`], which is a debugger verb:
    /// a detached process is still running somewhere and can be attached to again, and on a live
    /// kernel that is the difference between a machine that is up and one that is not.
    Ended { by: String },
    /// The probe failed and nothing in the batch explains it. Reported as not knowing, never
    /// guessed at.
    Uncertain { why: String },
}

impl From<&crate::batch::BatchReport> for BatchReportInfo {
    fn from(report: &crate::batch::BatchReport) -> Self {
        use crate::batch::BatchOutcome;
        let (outcome, at) = match report.outcome {
            BatchOutcome::Committed => (BatchOutcomeName::Committed, None),
            BatchOutcome::Failed { at } => (BatchOutcomeName::Failed, Some(at as u32)),
            BatchOutcome::TimedOut { at } => (BatchOutcomeName::TimedOut, Some(at as u32)),
            BatchOutcome::Abandoned { at } => (BatchOutcomeName::Abandoned, Some(at as u32)),
            BatchOutcome::Interrupted { at } => (BatchOutcomeName::Interrupted, Some(at as u32)),
            BatchOutcome::TargetGone { at } => (BatchOutcomeName::TargetGone, Some(at as u32)),
        };
        Self {
            outcome,
            at,
            // From the report's own predicates, not from `outcome` re-tested here: they are what
            // the text is rendered from, so this cannot disagree with what a reader is told.
            committed: report.committed(),
            rollback_complete: report.rollback_complete(),
            after: (&report.after).into(),
            budget_ms: ms(report.budget),
            elapsed_ms: ms(report.elapsed),
            steps: report.steps.iter().map(BatchStepInfo::from).collect(),
            always: report.always.iter().map(BatchStepInfo::from).collect(),
        }
    }
}

impl From<&crate::batch::StepOutcome> for BatchStepInfo {
    fn from(step: &crate::batch::StepOutcome) -> Self {
        use crate::batch::StepResult;
        let (result, detail) = match &step.result {
            StepResult::Ok => (StepResultName::Ok, None),
            StepResult::Failed(why) => (StepResultName::Failed, Some(why.clone())),
            StepResult::Unmet(why) => (StepResultName::Unmet, Some(why.clone())),
            StepResult::Skipped(why) => (StepResultName::Skipped, Some(why.clone())),
        };
        Self {
            position: step.position as u32,
            label: step.label.clone(),
            action: step.rendered.clone(),
            result,
            detail,
            changes: step.changes.clone(),
            cut_short: step.cut_short,
            target_gone: step.target_gone,
        }
    }
}

impl From<&crate::batch::SessionAfter> for SessionAfterInfo {
    fn from(after: &crate::batch::SessionAfter) -> Self {
        use crate::batch::SessionAfter;
        match after {
            SessionAfter::Stopped { ip } => Self::Stopped { ip: ip.clone() },
            SessionAfter::Running { why } => Self::Running { why: why.clone() },
            SessionAfter::Detached { by } => Self::Detached { by: by.clone() },
            SessionAfter::Ended { by } => Self::Ended { by: by.clone() },
            SessionAfter::Uncertain { why } => Self::Uncertain { why: why.clone() },
        }
    }
}

/// A duration in whole milliseconds, saturating rather than wrapping.
fn ms(d: std::time::Duration) -> u64 {
    d.as_millis().min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One address representation, and it is the lossless one.
    ///
    /// The three properties a consumer relies on: it round-trips a full 64-bit value (a JSON
    /// number would not, above 2^53), it is fixed width so lexical order matches numeric order,
    /// and it never carries the debugger's backtick — that form is text, and text is the other
    /// channel.
    #[test]
    fn addresses_have_one_lossless_representation() {
        assert_eq!(addr(0), "0x0000000000000000");
        assert_eq!(addr(0x9f), "0x000000000000009f");
        assert_eq!(addr(u64::MAX), "0xffffffffffffffff");
        // A kernel pointer past 2^53, which is where a JSON number starts lying.
        assert_eq!(addr(0xffff_8000_dead_beef), "0xffff8000deadbeef");
        assert_eq!(
            u64::from_str_radix(addr(0xffff_8000_dead_beef).trim_start_matches("0x"), 16),
            Ok(0xffff_8000_dead_beef)
        );
        assert!(addr(0xfffff803_1ab10000) < addr(0xffffffff_00000000));
        assert!(!addr(0xfffff803_1ab10000).contains('`'));
    }

    /// Both branches of an outcome are objects carrying `status`, which is what lets one output
    /// schema describe a result whichever way it went.
    #[test]
    fn an_outcome_is_discriminated_on_status() {
        let ok = serde_json::to_value(Outcome::Ok(SessionEnded {
            session_id: "sess-1".into(),
            released: true,
            worker_terminated: false,
            waited_ms: None,
            target_left_running: Some(true),
        }))
        .expect("serializes");
        assert_eq!(ok["status"], "ok");
        assert_eq!(ok["session_id"], "sess-1");
        assert_eq!(ok["released"], true);
        // The teardown's one irrecoverable fact, on the half a structured-aware client keeps.
        assert_eq!(ok["target_left_running"], true);
        // Absent rather than null: a consumer reading `waited_ms` gets "no answer", not "0ms".
        assert!(ok.get("waited_ms").is_none());

        let failed: Outcome<SessionEnded> = Outcome::failed_in(
            ErrorCategory::StaleSession,
            "`sess-9` is not a handle this server is holding",
            Some("sess-9".into()),
        );
        let failed = serde_json::to_value(failed).expect("serializes");
        assert_eq!(failed["status"], "error");
        assert_eq!(failed["error"]["category"], "stale_session");
        assert_eq!(failed["error"]["session_id"], "sess-9");
    }

    /// The category is a value, and every engine failure maps to one — checked here rather than
    /// left to a `_` arm, because a new failure kind silently becoming "debugger" is exactly the
    /// drift this field exists to prevent.
    #[test]
    fn every_engine_failure_has_a_category() {
        let cases = [
            (
                EngineError::Debugger("no".into()),
                ErrorCategory::Debugger,
                "debugger",
            ),
            (
                EngineError::Timeout("no".into()),
                ErrorCategory::Timeout,
                "timeout",
            ),
            (
                EngineError::Stale("no".into()),
                ErrorCategory::StaleSession,
                "stale_session",
            ),
            (
                EngineError::Lost("no".into()),
                ErrorCategory::WorkerLost,
                "worker_lost",
            ),
            (
                EngineError::Interrupted("no".into()),
                ErrorCategory::Interrupted,
                "interrupted",
            ),
            (
                EngineError::NotRun("no".into()),
                ErrorCategory::NotRun,
                "not_run",
            ),
            (
                EngineError::InvalidArgument("no".into()),
                ErrorCategory::InvalidArgument,
                "invalid_argument",
            ),
        ];
        for (error, expected, wire) in cases {
            assert_eq!(ErrorCategory::of(&error), expected);
            assert_eq!(serde_json::to_value(expected).unwrap(), wire);
        }
    }

    /// A register's kind travels with its value, so a consumer never has to guess whether a
    /// string is a number or bytes.
    #[test]
    fn a_register_value_says_what_kind_of_value_it_is() {
        use dbgscope::dbgeng::RegisterValue as Engine;
        let int = RegisterValue::from(&Engine::Int(0xffff_8000_dead_beef));
        let json = serde_json::to_value(&int).unwrap();
        assert_eq!(json["kind"], "int");
        assert_eq!(json["value"], "0xffff8000deadbeef");

        let bytes = RegisterValue::from(&Engine::Bytes(vec![0x00, 0x1f, 0xff]));
        let json = serde_json::to_value(&bytes).unwrap();
        assert_eq!(json["kind"], "bytes");
        assert_eq!(json["bytes"], "001fff");

        let missing = RegisterValue::from(&Engine::Unavailable);
        assert_eq!(
            serde_json::to_value(&missing).unwrap(),
            serde_json::json!({ "kind": "unavailable" })
        );
    }

    /// A register holding a NaN or an infinity must not answer with `null`.
    ///
    /// JSON has no literal for either, and `serde_json` renders both as `null` — silently, so
    /// nothing on the server sees it happen. What reaches the client is then a `float` whose
    /// `value` is null: not the value, not valid against the schema this tool declares, and not
    /// something that deserializes back into the type it came from. A register legitimately holds
    /// these (uninitialised x87 state, an ARM64 `d0`), so they get a kind of their own with the
    /// exact bits beside the name.
    #[test]
    fn a_register_that_json_cannot_express_says_so_rather_than_saying_null() {
        use dbgscope::dbgeng::RegisterValue as Engine;
        let wire = |v: f64| serde_json::to_value(RegisterValue::from(&Engine::Float(v))).unwrap();

        let nan = wire(f64::NAN);
        assert_eq!(nan["kind"], "non_finite");
        assert_eq!(nan["value"], "nan");
        assert!(nan.get("value").is_some_and(|v| !v.is_null()));
        assert_eq!(wire(f64::INFINITY)["value"], "infinity");
        assert_eq!(wire(f64::NEG_INFINITY)["value"], "negative_infinity");
        // The bits are kept, so nothing about the register is lost in the retelling.
        assert_eq!(
            wire(f64::INFINITY)["bytes"],
            f64::INFINITY
                .to_le_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );

        // A finite float is untouched — it stays a number, which is the whole point of not
        // making every float a string.
        let finite = wire(1.5);
        assert_eq!(finite["kind"], "float");
        assert_eq!(finite["value"], 1.5);
    }

    /// The engine's three coverage states stay distinct across the seam: collapsing `deadline_truncated`
    /// into `partial` would tell a caller that waiting longer cannot help, when it is the one
    /// thing that would.
    #[test]
    fn pool_coverage_keeps_the_walks_own_reason() {
        use dbgscope::pool::query::WalkCoverage as Engine;
        for (engine, expected, wire) in [
            (Engine::Complete, AllocatorCoverage::Complete, "complete"),
            (
                Engine::BudgetExpired,
                AllocatorCoverage::DeadlineTruncated,
                "deadline_truncated",
            ),
            (Engine::Partial, AllocatorCoverage::Partial, "partial"),
        ] {
            assert_eq!(AllocatorCoverage::from(engine), expected);
            assert_eq!(expected.as_str(), wire);
            assert_eq!(serde_json::to_value(expected).unwrap(), wire);
        }
        let intentional = AllocatorCoverage::MatchLimitReached;
        assert_eq!(intentional.as_str(), "match_limit_reached");
        assert_eq!(
            serde_json::to_value(intentional).unwrap(),
            "match_limit_reached"
        );
    }

    #[test]
    fn allocator_layout_keeps_exact_image_pdb_and_structural_family() {
        let engine = dbgscope::allocator::LayoutProvenance {
            module: dbgscope::dbgeng::ModuleIdentity {
                name: "ntdll".into(),
                image_name: "ntdll.dll".into(),
                loaded_image_name: r"C:\Windows\System32\ntdll.dll".into(),
                symbol_file: r"C:\symbols\ntdll.pdb".into(),
                symbols: dbgscope::dbgeng::SymbolKind::Pdb,
                base: 0x7ffb_1234_0000,
                size: 0x234000,
                timestamp: 0x1234_5678,
                checksum: 0xabcdef,
            },
            fingerprint: "fnv1a64:0123456789abcdef".into(),
            semantic_family: dbgscope::allocator::VsSemanticFamily::AffinitySlots,
        };

        let wire = serde_json::to_value(AllocatorLayoutInfo::from(&engine)).unwrap();
        assert_eq!(wire["module"]["name"], "ntdll");
        assert_eq!(wire["pdb"], r"C:\symbols\ntdll.pdb");
        assert_eq!(wire["fingerprint"], "fnv1a64:0123456789abcdef");
        assert_eq!(wire["semantic_family"], "affinity_slot_vs");
        assert_eq!(wire["module"]["base"], "0x00007ffb12340000");
        assert_eq!(wire["module"]["symbols"], "pdb");
    }

    #[test]
    fn heap_requested_size_is_optional_rather_than_inferred_from_capacity() {
        let allocation = |requested_size| dbgscope::heap::HeapAllocation {
            heap: 0x10000,
            backend: dbgscope::heap::HeapBackend::Large,
            state: dbgscope::heap::HeapState::Allocated,
            header_address: 0x20000,
            user_address: 0x20000,
            capacity: 0x20000,
            requested_size,
            subsegment: None,
            size_class: 0x20000,
        };
        let unknown = serde_json::to_value(HeapAllocationInfo::from(&allocation(None))).unwrap();
        assert!(unknown.get("requested_size").is_none(), "{unknown}");
        let exact =
            serde_json::to_value(HeapAllocationInfo::from(&allocation(Some(0x1f234)))).unwrap();
        assert_eq!(exact["requested_size"], 0x1f234);
    }

    /// The gap figures answer the question `coverage` raises and cannot settle: `partial` says
    /// a walk fell short, and these say by how much. They have to come from the walk as numbers
    /// — the diagnostics cannot supply them, because they collapse messages by shape and the
    /// count beside a shape counts occurrences of *that shape*, not bytes or chunks.
    #[test]
    fn walk_gaps_carry_what_the_diagnostics_cannot() {
        let report = |stalls, refused_chunks| dbgscope::pool::query::PoolSnapshotReport {
            layout: Default::default(),
            total_chunks: 0,
            allocated_chunks: 0,
            coverage: dbgscope::pool::query::WalkCoverage::Partial,
            stopped_after_matches: None,
            diagnostics: dbgscope::pool::PoolDiagnostics::default(),
            stalls,
            refused_chunks,
            unplaced_bytes: 0,
        };

        // The ordinary walk meets none of this, and says so by saying nothing: five zeroes on
        // every pool answer would be noise on the answers that are fine.
        assert_eq!(
            WalkGaps::of(&report(dbgscope::pool::WalkStalls::default(), 0)),
            None
        );

        let gaps = WalkGaps::of(&report(
            dbgscope::pool::WalkStalls {
                pages: 3,
                skipped_bytes: 0x3000,
                recovered_bytes: 0x40000,
            },
            884,
        ))
        .expect("a walk that stalled has gaps to report");
        assert_eq!(gaps.stalled_pages, 3);
        assert_eq!(gaps.skipped_bytes, 0x3000);
        // The figure the whole measurement is for: committed memory read on the far side of a
        // stall, which a walk that abandoned the region at the first one reports as nothing.
        assert_eq!(gaps.recovered_bytes, 0x40000);
        assert_eq!(gaps.refused_chunks, 884);

        // Any one of them alone is still worth reporting — a walk can refuse chunks without
        // ever stalling, and reporting nothing there would hide the refusals entirely.
        assert!(WalkGaps::of(&report(dbgscope::pool::WalkStalls::default(), 1)).is_some());

        // The omission has to be asserted where it happens, on `WalkInfo`. `of` returning
        // `None` says nothing about whether the field then serialises as `"gaps": null`, which
        // would be a shape change on every healthy pool answer — the ones that are fine.
        let walk = |gaps| WalkInfo {
            coverage: AllocatorCoverage::Partial,
            stop_after_matches: None,
            chunks_walked: 0,
            allocated_chunks: 0,
            diagnostics_emitted: 0,
            diagnostic_categories: 0,
            gaps,
        };
        let quiet = serde_json::to_value(walk(None)).unwrap();
        assert!(quiet.get("gaps").is_none(), "{quiet}");
        let wire = serde_json::to_value(walk(Some(gaps))).unwrap();
        assert_eq!(wire["gaps"]["recovered_bytes"], 0x40000);
        assert_eq!(wire["gaps"]["refused_chunks"], 884);
    }

    #[test]
    fn heap_walk_gaps_use_the_shared_optional_shape() {
        let report = |stalls, refused_headers| dbgscope::heap::HeapWalkReport {
            coverage: dbgscope::pool::query::WalkCoverage::Complete,
            total_chunks: 0,
            allocated_chunks: 0,
            diagnostic_count: 0,
            unreadable_gaps: 0,
            refused_headers,
            stalls,
            unplaced_bytes: 0,
        };

        let quiet = serde_json::to_value(HeapWalkInfo::from(&report(
            dbgscope::pool::WalkStalls::default(),
            0,
        )))
        .unwrap();
        assert!(quiet.get("gaps").is_none(), "{quiet}");

        let wire = serde_json::to_value(HeapWalkInfo::from(&report(
            dbgscope::pool::WalkStalls {
                pages: 2,
                skipped_bytes: 0x2000,
                recovered_bytes: 0x8000,
            },
            17,
        )))
        .unwrap();
        assert_eq!(wire["gaps"]["stalled_pages"], 2);
        assert_eq!(wire["gaps"]["refused_chunks"], 17);
    }

    /// A field's JSON type must not depend on its value.
    ///
    /// `symbols` and `kind` each have a branch for a code this build does not name, and the
    /// obvious spelling makes those branches objects while every other is a string. A consumer
    /// then reads the field correctly until the first target that reports something new — which
    /// is the worst possible moment to change shape. Both are tagged and flattened instead, so
    /// the field stays a string and the unnamed code arrives beside it.
    /// The wire contract of a PDB identity, which is four separate chances to produce a URL that
    /// 404s: the GUID's spelling, the age in **hex** rather than decimal, the two concatenated in
    /// that order, and `unmatched` appearing only when it is true.
    ///
    /// Offline, and next to the type, because the smoke tier can only assert this against whatever
    /// PDB a host happens to have resolved — and an age of 1 hides the hex/decimal confusion
    /// completely, which is exactly the value a real `nt` reports.
    #[test]
    fn a_pdb_identity_is_spelled_the_way_a_symbol_server_path_is() {
        let identity = |age, unmatched| {
            serde_json::to_value(PdbInfo::from(dbgscope::dbgeng::PdbIdentity {
                guid: "FE3F58BDA39D2FC13C370618D1DBDF22".into(),
                age,
                unmatched,
                file: r"c:\symbols\ntkrnlmp.pdb".into(),
            }))
            .expect("serializes")
        };

        // Age 26 is 0x1A: decimal and hex differ, which age 1 cannot show.
        let twenty_six = identity(26, false);
        assert_eq!(twenty_six["guid"], "FE3F58BDA39D2FC13C370618D1DBDF22");
        assert_eq!(twenty_six["age"], 26);
        assert_eq!(
            twenty_six["key"], "FE3F58BDA39D2FC13C370618D1DBDF221A",
            "the key appends the age in hex, not decimal"
        );
        assert!(
            twenty_six.get("unmatched").is_none(),
            "the ordinary case carries no flag: {twenty_six}"
        );

        assert_eq!(
            identity(1, true)["unmatched"],
            true,
            "a PDB that does not belong to the image has to say so"
        );
        // The local path the engine loaded is not on the wire: it is a fact about the debugger's
        // filesystem, and this record is for a client somewhere else.
        assert!(identity(1, false).get("file").is_none());
    }

    #[test]
    fn a_named_state_is_a_string_whether_or_not_it_is_one_we_know() {
        let module = |symbols| {
            serde_json::to_value(ModuleInfo {
                name: "nt".into(),
                image_name: "ntkrnlmp.exe".into(),
                loaded_image_name: None,
                start: addr(0xfffff803_1ab10000),
                end: addr(0xfffff803_1ab1b000),
                size: 0xb000,
                symbols,
                user_mode: false,
                timestamp: 0,
                checksum: 0,
                pdb: None,
                unloaded: false,
            })
            .expect("serializes")
        };
        assert_eq!(module(SymbolState::Pdb)["symbols"], "pdb");
        assert_eq!(module(SymbolState::Deferred)["symbols"], "deferred");
        let unknown = module(SymbolState::Other {
            symbol_type_code: 9,
        });
        assert_eq!(unknown["symbols"], "other");
        assert_eq!(unknown["symbol_type_code"], 9);

        let breakpoint = |kind| {
            serde_json::to_value(BreakpointInfo {
                id: 0,
                kind,
                address: Some(addr(0x1000)),
                expression: None,
                command: None,
                watch: None,
                thread: None,
                enabled: true,
                deferred: false,
                one_shot: false,
                pass_count: 1,
                passes_remaining: 1,
            })
            .expect("serializes")
        };
        assert_eq!(breakpoint(BreakpointKind::Code)["kind"], "code");
        let inline = breakpoint(BreakpointKind::Other { kind_code: 3 });
        assert_eq!(inline["kind"], "other");
        assert_eq!(inline["kind_code"], 3);
    }

    /// A walk's two nullable fields are **present and null**, never absent.
    ///
    /// They are the ones a caller reads to find the holes, which is the whole point of the tool,
    /// so an omitted key would make "the debugger could not read this" and "this object came back
    /// malformed" the same observation — and leave every client writing missing-key handling to
    /// read the ordinary answer. The rest of the module keeps `skip_serializing_if`, where an
    /// absence really is one.
    #[test]
    fn an_unreadable_value_is_a_null_not_a_missing_key() {
        let node = WalkNode {
            index: 0,
            address: addr(0x1000),
            next: None,
            fields: vec![WalkFieldValue {
                name: "value".into(),
                address: addr(0x1000),
                size: 8,
                value: None,
            }],
            readable: false,
        };
        let wire = serde_json::to_value(&node).unwrap();
        assert!(
            wire.get("next").is_some_and(serde_json::Value::is_null),
            "{wire}"
        );
        assert!(
            wire["fields"][0]
                .get("value")
                .is_some_and(serde_json::Value::is_null),
            "{wire}"
        );

        // The walk's own optionals keep the usual treatment: "there is no start" and "nothing
        // needed explaining" are absences, not findings.
        let walk = MemoryWalk {
            mode: WalkMode::List,
            start: None,
            requested: 1,
            walked: 1,
            unreadable: 1,
            nodes: vec![node],
            stopped: WalkStop::Complete,
            note: None,
        };
        let wire = serde_json::to_value(&walk).unwrap();
        assert!(wire.get("start").is_none(), "{wire}");
        assert!(wire.get("note").is_none(), "{wire}");
    }

    /// The word a module listing prints for a symbol state is the word its value carries.
    ///
    /// `modules` renders its own text now ([#120](https://github.com/glslang/windbg-mcp/issues/120)),
    /// so this column is written here rather than read out of `lm` — and a hand-written mapping
    /// beside a derived one is how `code_view` becomes `codeview` in the half a person reads. Every
    /// variant is walked, so a state added later fails this rather than diverging quietly.
    #[test]
    fn a_symbol_state_is_spelled_the_same_in_both_channels() {
        for state in [
            SymbolState::None,
            SymbolState::Deferred,
            SymbolState::Coff,
            SymbolState::CodeView,
            SymbolState::Pdb,
            SymbolState::Export,
            SymbolState::Sym,
            SymbolState::Dia,
        ] {
            let wire = serde_json::to_value(state).unwrap();
            assert_eq!(
                wire["symbols"],
                serde_json::Value::from(state.to_string()),
                "the rendered word and the serialised tag are one spelling: {wire}"
            );
        }

        // The one variant a tag cannot carry alone: the code travels with the word, in this
        // module's hex, so an unnamed symbol type is still identifiable in the text.
        let other = SymbolState::Other {
            symbol_type_code: 0x2a,
        };
        assert_eq!(other.to_string(), "other (0x2a)");
        assert_eq!(
            serde_json::to_value(other).unwrap()["symbol_type_code"],
            0x2a
        );
    }

    /// A chunk's state is four named values, and the fourth is not a kind of free.
    ///
    /// `Unreadable` is a limit of the walk — a Verifier guard page reads exactly that way — so a
    /// consumer testing "is this a use-after-free?" must be able to see it as neither allocated
    /// nor freed. Collapsing it either way turns "could not read" into a verdict.
    #[test]
    fn a_chunk_state_names_the_unreadable_case_separately() {
        let wire = |state| serde_json::to_value(state).unwrap();
        assert_eq!(wire(PoolChunkState::Allocated), "allocated");
        assert_eq!(wire(PoolChunkState::ReusableFree), "reusable_free");
        assert_eq!(wire(PoolChunkState::CachedFree), "cached_free");
        assert_eq!(wire(PoolChunkState::Unreadable), "unreadable");
    }
}
