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
//! # Where the values come from
//!
//! Nothing here is parsed out of debugger output. Each type is built from a value: win-kexp's
//! `RunToOutcome`, `Register`, `Module`, `BreakpointInfo`, `PoolSpan` and `WalkCoverage` on the
//! worker side, and this server's own `SessionSnapshot`/`Release` on the supervisor side. That is
//! the rule the counts in [#77](https://github.com/glslang/windbg-mcp/issues/77) were fixed by,
//! pointed at results instead of at counts: a figure re-derived from a rendering measures the
//! rendering. Where a value did not exist upstream it was added there first — this is why
//! `win-kexp` grew `register_values`, `modules`, `breakpoints` and `WalkCoverage`.
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
    /// target was replaced under it, it never existed, or nothing is open at all.
    StaleSession,
    /// The engine process holding this session is gone. The session is unrecoverable; opening
    /// again gets a fresh one.
    WorkerLost,
    /// No session slot was free, so nothing was opened. End a session and retry.
    Capacity,
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
    /// The opener's own diagnostic (`lm`, `vertarget`, `r`, the TTD lifetime query), verbatim.
    pub report: String,
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
    /// Whether the target was broken into **on request** rather than stopping on its own. The
    /// position is real either way, but it is where an `interrupt` landed rather than where the
    /// target was going, which is a different answer to "where did this stop?".
    pub interrupted: bool,
    /// The debugger's own output for the command.
    pub output: String,
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

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RegisterInfo {
    /// The engine's own name for it (`rax`, `xmm0`, `efl`).
    pub name: String,
    #[serde(flatten)]
    pub value: RegisterValue,
    /// Whether this register is a view of another (`eax` within `rax`) rather than storage of
    /// its own. Only ever true when the whole set was asked for.
    pub subregister: bool,
}

/// One register's value, tagged by what kind of value it is.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RegisterValue {
    /// An integer register, in this module's one address representation.
    Int { value: String },
    /// A floating-point register that an `f64` holds exactly.
    Float { value: f64 },
    /// An x87 or vector register, as lowercase hex bytes in the engine's own order. Not
    /// narrowed to a number, because there is no number that holds it.
    Bytes { bytes: String },
    /// The engine holds no value for this register in this target — a minidump carrying no
    /// floating-point state answers this way. Distinct from zero.
    Unavailable,
}

impl From<&win_kexp::dbgeng::RegisterValue> for RegisterValue {
    fn from(value: &win_kexp::dbgeng::RegisterValue) -> Self {
        use win_kexp::dbgeng::RegisterValue as Engine;
        match value {
            Engine::Int(v) => Self::Int { value: addr(*v) },
            Engine::Float(v) => Self::Float { value: *v },
            Engine::Bytes(bytes) => Self::Bytes {
                bytes: bytes.iter().map(|b| format!("{b:02x}")).collect(),
            },
            Engine::Unavailable => Self::Unavailable,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ModuleList {
    pub modules: Vec<ModuleInfo>,
    /// How many modules are loaded. Equal to `modules.len()`; carried so a truncated listing
    /// could never be read as a total.
    pub loaded: usize,
}

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
    pub symbols: SymbolState,
    pub user_mode: bool,
    pub timestamp: u32,
    pub checksum: u32,
}

/// How much symbol information the engine has for a module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
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
    /// A symbol type this build does not name; `code` is the engine's own.
    Other {
        code: u32,
    },
}

impl From<win_kexp::dbgeng::SymbolKind> for SymbolState {
    fn from(kind: win_kexp::dbgeng::SymbolKind) -> Self {
        use win_kexp::dbgeng::SymbolKind as Engine;
        match kind {
            Engine::None => Self::None,
            Engine::Deferred => Self::Deferred,
            Engine::Coff => Self::Coff,
            Engine::CodeView => Self::CodeView,
            Engine::Pdb => Self::Pdb,
            Engine::Export => Self::Export,
            Engine::Sym => Self::Sym,
            Engine::Dia => Self::Dia,
            Engine::Other(code) => Self::Other { code },
        }
    }
}

impl From<&win_kexp::dbgeng::Module> for ModuleInfo {
    fn from(module: &win_kexp::dbgeng::Module) -> Self {
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
        }
    }
}

/// The breakpoints a session holds, after a `set_breakpoint`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct BreakpointSet {
    /// The ids this call added. Empty when the command set nothing — which `bp` reports by
    /// printing an error and is otherwise invisible, since a successful `bp` prints nothing.
    pub added: Vec<u32>,
    /// Every breakpoint the session now holds, added or not.
    pub breakpoints: Vec<BreakpointInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct BreakpointInfo {
    /// The id the debugger prints, and that `bc`/`bd`/`be` take.
    pub id: u32,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BreakpointKind {
    /// Execution reaching an address (`bp`).
    Code,
    /// Access to a range of memory (`ba`).
    Data,
    Other {
        code: u32,
    },
}

impl From<&win_kexp::dbgeng::BreakpointInfo> for BreakpointInfo {
    fn from(bp: &win_kexp::dbgeng::BreakpointInfo) -> Self {
        use win_kexp::dbgeng::BreakpointKind as Engine;
        Self {
            id: bp.id,
            kind: match bp.kind {
                Engine::Code => BreakpointKind::Code,
                Engine::Data => BreakpointKind::Data,
                Engine::Other(code) => BreakpointKind::Other { code },
            },
            address: bp.address.map(addr),
            expression: bp.expression.clone(),
            command: bp.command.clone(),
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

/// How much of the pool the walk behind an answer actually covered.
///
/// Every pool answer carries this, because every one of them is drawn from a snapshot and a
/// count taken from a partial snapshot is a floor rather than a total. The three ways of falling
/// short are separate values because they need different responses; a fourth — the walk failing
/// outright, or being interrupted — is not a coverage state at all but the `error` branch of
/// [`Outcome`], with category [`ErrorCategory::Debugger`] or [`ErrorCategory::Interrupted`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PoolCoverage {
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
}

impl From<win_kexp::pool::query::WalkCoverage> for PoolCoverage {
    fn from(coverage: win_kexp::pool::query::WalkCoverage) -> Self {
        use win_kexp::pool::query::WalkCoverage as Engine;
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
    pub coverage: PoolCoverage,
    /// Chunks the walk indexed, allocated and free.
    pub chunks_walked: usize,
    pub allocated_chunks: usize,
    /// How many complaints the walk made — every one, not the capped sample it kept verbatim.
    pub diagnostics_emitted: usize,
    /// How many distinct kinds of complaint those fell into.
    pub diagnostic_categories: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PoolChunkInfo {
    /// What the allocation call returned, and so what the target's own pointers hold.
    pub address: String,
    /// Where the allocator's bookkeeping starts. Rarely what a caller is holding.
    pub header_address: String,
    pub size: u64,
    pub state: PoolChunkState,
    pub tag: String,
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

impl From<&win_kexp::pool::PoolSpan> for PoolChunkInfo {
    fn from(span: &win_kexp::pool::PoolSpan) -> Self {
        use win_kexp::pool::{PoolBackend, PoolKind, PoolState};
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
    pub tag: String,
    pub scope: PoolScope,
    /// How many allocated chunks carry the tag. A floor rather than a total unless
    /// `walk.coverage` is `complete`.
    pub matches: usize,
    /// Their total size in bytes, over all matches — not only the ones listed.
    pub total_bytes: u64,
    /// The matches themselves, capped by the call's `limit`; `matches` is the full count.
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
    /// How many distinct tags are allocated. The listing below is capped by `limit`.
    pub distinct_tags: usize,
    pub tags: Vec<PoolTagTotals>,
    pub walk: WalkInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PoolTagTotals {
    pub tag: String,
    pub allocations: usize,
    pub total_bytes: u64,
    pub paged_allocations: usize,
    pub nonpaged_allocations: usize,
}

/// What `pool_diagnostics` selected.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PoolDiagnosticsReport {
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
        }))
        .expect("serializes");
        assert_eq!(ok["status"], "ok");
        assert_eq!(ok["session_id"], "sess-1");
        assert_eq!(ok["released"], true);
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
        use win_kexp::dbgeng::RegisterValue as Engine;
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

    /// The three coverage states stay distinct across the seam: collapsing `deadline_truncated`
    /// into `partial` would tell a caller that waiting longer cannot help, when it is the one
    /// thing that would.
    #[test]
    fn pool_coverage_keeps_the_walks_own_reason() {
        use win_kexp::pool::query::WalkCoverage as Engine;
        for (engine, expected, wire) in [
            (Engine::Complete, PoolCoverage::Complete, "complete"),
            (
                Engine::BudgetExpired,
                PoolCoverage::DeadlineTruncated,
                "deadline_truncated",
            ),
            (Engine::Partial, PoolCoverage::Partial, "partial"),
        ] {
            assert_eq!(PoolCoverage::from(engine), expected);
            assert_eq!(serde_json::to_value(expected).unwrap(), wire);
        }
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
