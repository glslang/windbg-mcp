//! The MCP server: a curated set of debugger tools plus a raw command passthrough.
//!
//! Every tool routes its work to a session's worker process via [`Sessions`] — the tool decides
//! *what* to run ([`EngineOp`]) and *which* session runs it, and [`crate::engine`] does the rest.
//! Most tools are thin wrappers over `execute_command` (the universal DbgEng escape hatch,
//! returning full text); session-management tools drive the typed `win-kexp` openers.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Duration;

use rmcp::ErrorData;
use rmcp::handler::server::tool::schema_for_output;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::batch;
use crate::engine::{
    Call, EngineError, MAX_SESSIONS, OpenError, OpenReport, SessionKind, SessionSnapshot,
    SessionState, Sessions,
};
use crate::kdconn;
use crate::proto::{
    EngineOp, HeapBackendFilter, HeapOp, HeapStateFilter, Output, PoolOp, ReachabilityOp,
};
use crate::structured::{self, ErrorCategory, Outcome, TargetCreated};
use crate::ttd;
use crate::walk;

/// How long to wait for an execution-control command (go/step/reverse) to reach its
/// next stop (ms).
pub(crate) const EXEC_WAIT_MS: u32 = 60_000;

/// How long an open may sit un-landed before `session_status` stops calling it normal.
///
/// A KDNET link that is coming up resyncs in ~25s; a guest that is not booted in debug mode
/// never dials at all, and the two look identical from here except for how long they have taken.
/// Past this the report says so, because the advice diverges completely — "wait" versus "this
/// will not return; `end_session` reclaims it".
const OPEN_TAKING_TOO_LONG: Duration = Duration::from_secs(120);

#[derive(Clone)]
pub struct WindbgServer {
    sessions: Sessions,
    /// The session transcript, if this run was asked for one. Taken from the registry rather than
    /// passed in separately, so the tool surface and the supervisor can never end up recording
    /// into two different files.
    rec: crate::record::Recorder,
}

fn text_result(s: String) -> Result<CallToolResult, ErrorData> {
    Ok(CallToolResult::success(vec![ContentBlock::text(s)]))
}

/// A tool-execution error: something the model should see in the result and can act on,
/// as opposed to a JSON-RPC protocol error it cannot.
fn tool_error(s: String) -> Result<CallToolResult, ErrorData> {
    Ok(CallToolResult::error(vec![ContentBlock::text(s)]))
}

/// A tool-execution error carrying a typed reason beside the text.
///
/// The text is what it always was. The structured half exists so a caller can branch on
/// [`ErrorCategory`] instead of on wording, and it conforms to the same `outputSchema` the
/// success branch does — see [`crate::structured`] for why both branches are one shape.
fn typed_error(
    category: ErrorCategory,
    message: String,
    session_id: Option<String>,
) -> Result<CallToolResult, ErrorData> {
    let structured: Outcome<()> = Outcome::failed_in(category, message.clone(), session_id);
    Ok(with_structured(
        CallToolResult::error(vec![ContentBlock::text(message)]),
        payload(structured),
    ))
}

/// Serializes a structured payload, saying so if it cannot.
///
/// A tool that declares an `outputSchema` and answers with text alone is a contract broken, and
/// silently: the client sees a schema-bearing tool return nothing to validate and has nothing to
/// go on. It cannot happen — these are plain data types — which is exactly why the one place it
/// could must not swallow it. [`Output::typed`] logs the same failure on the worker's side.
fn payload<T: serde::Serialize>(value: T) -> Option<serde_json::Value> {
    match serde_json::to_value(value) {
        Ok(value) => Some(value),
        Err(error) => {
            tracing::error!("structured payload did not serialize: {error}");
            None
        }
    }
}

/// Attaches structured content to a result, if there is any.
fn with_structured(mut result: CallToolResult, data: Option<serde_json::Value>) -> CallToolResult {
    result.structured_content = data;
    result
}

/// A success carrying both halves: the text a person reads, and the payload a program does.
///
/// For the tools the supervisor answers by itself — `session_status`, the openers, `end_session`
/// — where there is no worker to have built the typed half.
fn structured_result<T: serde::Serialize>(
    text: String,
    payload: T,
) -> Result<CallToolResult, ErrorData> {
    outcome_result(text, Outcome::Ok(payload))
}

/// [`structured_result`] for a payload that is already an outcome of its own — the openers,
/// whose success and failure branches carry different fields and so have their own enum.
fn outcome_result<T: serde::Serialize>(
    text: String,
    outcome: T,
) -> Result<CallToolResult, ErrorData> {
    Ok(with_structured(
        CallToolResult::success(vec![ContentBlock::text(text)]),
        payload(outcome),
    ))
}

/// The typed view of what `session_status` was asked and what it found.
///
/// `asked`/`unknown_handle` exist because an empty list is three different answers — nothing is
/// open, the handle you named is gone, the handle you named was never issued — and prose was the
/// only thing telling them apart.
fn sessions_report(
    sessions: &[&SessionSnapshot],
    asked: Option<&str>,
    unknown_handle: bool,
) -> structured::SessionsReport {
    structured::SessionsReport {
        sessions: sessions
            .iter()
            .map(|s| structured::SessionInfo {
                session_id: s.id.clone(),
                kind: s.kind.into(),
                target: s.what.clone(),
                engine_pid: s.pid,
                // The two derived facts a caller cannot compute: whether this wait can end on its
                // own, and whether it has already gone on longer than a healthy one ever does.
                // Both come from the same constants the text is written against.
                state: structured::SessionStateInfo::of(
                    &s.state,
                    s.kind.waits_indefinitely(),
                    s.in_state_for >= OPEN_TAKING_TOO_LONG,
                ),
                in_state_for_ms: ms(s.in_state_for),
                age_ms: ms(s.age),
                current: s.current,
                live: s.state.is_live(),
            })
            .collect(),
        max_sessions: MAX_SESSIONS as u32,
        asked: asked.map(str::to_string),
        unknown_handle,
    }
}

/// A duration in whole milliseconds, saturating rather than wrapping.
fn ms(d: Duration) -> u64 {
    d.as_millis().min(u128::from(u64::MAX)) as u64
}

/// How many records `server_log` returns when the caller does not say.
const DEFAULT_LOG_RECORDS: u32 = 50;

/// The most it will return in one call.
///
/// A page rather than the buffer. The buffer is a thousand records by design — enough to hold the
/// run-up to a failure — and the reader on the other end of a tool result has a context window.
const MAX_LOG_RECORDS: u32 = 500;

/// [`crate::logbridge::Tail`] as the typed half of a `server_log` result.
fn log_report(tail: &crate::logbridge::Tail) -> structured::LogReport {
    structured::LogReport {
        records: tail
            .entries
            .iter()
            .map(|e| structured::LogRecord {
                seq: e.seq,
                at: crate::record::rfc3339(std::time::UNIX_EPOCH + Duration::from_millis(e.at_ms)),
                level: e.level,
                session_id: e.session.clone(),
                target: e.target.clone(),
                message: e.message.clone(),
            })
            .collect(),
        matched: tail.matched.min(u32::MAX as usize) as u32,
        next_since: tail.next_since,
        held: tail.held.min(u32::MAX as usize) as u32,
        capacity: tail.capacity.min(u32::MAX as usize) as u32,
        oldest_seq: tail.oldest_seq,
    }
}

/// A `tracing` target as a line prefix: this crate's own shortened to the module, everything
/// else left whole.
///
/// Only the leading `windbg_mcp::` comes off, and the asymmetry is the point. Taking the *last*
/// segment of every target reads well until a dependency logs — `rmcp::handler::server` and this
/// crate's `server` then both render as `server`, which is worse than long, because the reader
/// cannot tell whose record they are looking at. The full target is kept in the typed half either
/// way.
fn short_target(target: &str) -> &str {
    target.strip_prefix("windbg_mcp::").unwrap_or(target)
}

/// One record as a line: when, how bad, who said it, and what it said.
fn describe_record(e: &crate::logbridge::Entry) -> String {
    let at = crate::record::rfc3339(std::time::UNIX_EPOCH + Duration::from_millis(e.at_ms));
    let source = match &e.session {
        Some(id) => format!("{}/{id}", short_target(&e.target)),
        None => short_target(&e.target).to_string(),
    };
    format!("{at} {} {source}: {}", e.level.label(), e.message)
}

/// A page of the log, with the facts about the *buffer* a reader cannot get from the records —
/// which is what separates "nothing happened" from "it scrolled past".
///
/// Free function so the wording tests without a debugger, like [`describe_session`].
fn describe_log(tail: &crate::logbridge::Tail, query: &crate::logbridge::Query) -> String {
    let level = query.level.label().trim().to_lowercase();
    let scope = match &query.session {
        Some(id) => format!(" about session {id}"),
        None => String::new(),
    };
    let mut out = String::new();
    if tail.entries.is_empty() {
        out.push_str(&format!("No log records{scope} at {level} or above.\n"));
        if query.session.is_some() {
            out.push_str(
                "Only what a session's own engine worker logged carries its session id — records \
                 the supervisor made *about* that session (spawning its worker, timing a call \
                 out, the worker dying) do not. Ask again without `session_id` to see those; that \
                 is also the only way to see an open that failed before there was a session.\n",
            );
        }
        if tail.held > 0 {
            out.push_str(&format!(
                "The buffer holds {} record(s) that this filter excluded.\n",
                tail.held
            ));
        }
    } else {
        out.push_str(&format!(
            "{} of {} record(s){scope} at {level} or above, oldest first:\n\n",
            tail.entries.len(),
            tail.matched
        ));
        for e in &tail.entries {
            out.push_str(&describe_record(e));
            out.push('\n');
        }
    }
    out.push_str(&format!(
        "\nBuffer: {} of {} record(s) held. Pass `since: {}` next time for only what is new.\n\
         This is the same stream as the server's stderr, so it holds nothing below the level the \
         server was started with — widen it with `RUST_LOG` (and restart) rather than with \
         `level` here.",
        tail.held, tail.capacity, tail.next_since
    ));
    // The one thing a caller paging through *must* be told, because their next page would
    // otherwise silently skip a stretch and read as a quiet one.
    if let (Some(since), Some(oldest)) = (query.since, tail.oldest_seq)
        && oldest > since
    {
        out.push_str(&format!(
            "\n[!] Records before seq {oldest} were evicted since your last call, so this page \
             starts later than the `since` you asked for. The buffer holds the most recent \
             {} records; ask sooner, or raise it with WINDBG_MCP_LOG_BUFFER.",
            tail.capacity
        ));
    }
    out
}

/// The session an open ended up with, for the outcomes that have one.
///
/// A `match` rather than a chain of `if let`s, so a new [`OpenError`] variant is a compile error
/// here rather than an outcome that quietly stops being recorded against its session.
fn opened_session(outcome: &Result<OpenReport, OpenError>) -> Option<&str> {
    match outcome {
        Ok(report) => Some(&report.id),
        Err(OpenError::PostCommit { id, .. }) | Err(OpenError::Timeout { id, .. }) => Some(id),
        // Nothing was created, so there is no session to name.
        Err(OpenError::Unavailable(_) | OpenError::NoRoom(_) | OpenError::Clean(_)) => None,
    }
}

/// A failed open, with the two things a caller has to act on as fields.
///
/// `session_id` because an open that failed *after* creating its target hands back the only
/// handle that reaches it — text that had to be scraped for a `session_id:` line before — and
/// `target` because "was anything created?" is what decides whether opening again is a recovery
/// or a second process.
fn open_failure(
    category: ErrorCategory,
    message: String,
    session_id: Option<String>,
    target: TargetCreated,
) -> Result<CallToolResult, ErrorData> {
    let structured = structured::OpenOutcome::Error(structured::OpenFailure {
        error: structured::FailureDetail {
            category,
            message: message.clone(),
            session_id,
        },
        target,
    });
    Ok(with_structured(
        CallToolResult::error(vec![ContentBlock::text(message)]),
        payload(structured),
    ))
}

/// Renders a session-scoped engine outcome using the MCP error model.
///
/// Everything that can go wrong here is feedback the model can act on — a failed debugger
/// operation (bad symbol, unreadable address, a target that never stopped), a refused handle, a
/// session whose worker is gone — so all of it comes back as a tool-execution error with the text
/// intact, never as a JSON-RPC error the model never really sees. The one failure that is the
/// *server's* rather than a session's is "no engine worker could be started", and only an opener
/// can hit it; [`WindbgServer::opened`] renders that one.
///
/// Both branches carry whatever typed answer exists: the worker's, on success ([`Output::data`]),
/// and the failure's category otherwise. A tool with no typed shape yet simply has none, and is
/// unchanged.
fn engine_result(r: Result<Output, EngineError>) -> Result<CallToolResult, ErrorData> {
    engine_result_for(None, r)
}

/// [`engine_result`] for a call that named a session, so a failure can say which one it was.
fn engine_result_for(
    session_id: Option<&str>,
    r: Result<Output, EngineError>,
) -> Result<CallToolResult, ErrorData> {
    match r {
        Ok(out) => Ok(with_structured(
            CallToolResult::success(vec![ContentBlock::text(out.text)]),
            out.data,
        )),
        Err(e) => typed_error(
            ErrorCategory::of(&e),
            e.to_string(),
            session_id.map(str::to_string),
        ),
    }
}

/// Renders a `debug_batch` outcome, where "did the tool fail?" and "did the engine call fail?" are
/// not the same question.
///
/// Every other tool answers one question, so [`engine_result`] can key `isError` on the engine's
/// `Ok`/`Err`. A batch answers two: the call succeeds whenever the transaction *ran*, and whether
/// that transaction committed — and whether its rollback finished — is the verdict inside the
/// report. The worker sends the report on both paths for exactly that reason (see
/// `worker::run_batch`), so the verdict is read back from the typed half here instead of being
/// encoded in the engine result and lost.
///
/// **Fails closed.** A report whose verdict cannot be read is rendered as an error. It cannot
/// happen — the payload is a plain data type, and [`Output::typed`] logs it if it ever does — but
/// the two ways of being wrong are not symmetric: a caller wrongly told "error" re-reads a report
/// that is right there in the text, while one wrongly told "success" walks away from a target that
/// may still be patched.
fn batch_result(
    session_id: Option<&str>,
    r: Result<Output, EngineError>,
) -> Result<CallToolResult, ErrorData> {
    let out = match r {
        Ok(out) => out,
        // The batch never ran: refused before it started, a stale handle, a worker that died. The
        // ordinary failure rendering, with its own category.
        Err(e) => {
            return typed_error(
                ErrorCategory::of(&e),
                e.to_string(),
                session_id.map(str::to_string),
            );
        }
    };
    let settled = out.data.as_ref().is_some_and(batch_settled);
    let content = vec![ContentBlock::text(out.text)];
    Ok(with_structured(
        if settled {
            CallToolResult::success(content)
        } else {
            CallToolResult::error(content)
        },
        out.data,
    ))
}

/// Whether a batch report says the transaction committed **and** its rollback finished — the two
/// facts that together mean nothing is owed. `false` for a payload that will not read back as a
/// report; see [`batch_result`] on failing closed.
fn batch_settled(data: &serde_json::Value) -> bool {
    match serde::Deserialize::deserialize(data) {
        Ok(Outcome::<structured::BatchReportInfo>::Ok(report)) => {
            report.committed && report.rollback_complete
        }
        Ok(Outcome::Error(_)) => false,
        Err(error) => {
            tracing::error!("a batch report did not read back as one: {error}");
            false
        }
    }
}

/// Wraps a pool question as an engine op.
///
/// `patience_ms` is filled in by the supervisor's pump when the job reaches the front of its
/// session's queue, so the zero here is never what the worker reads — see [`EngineOp::Pool`]. It
/// lives in one place rather than at each of the four call sites for the reason the `PoolOp`
/// constructors do: a tool that spelled it out and got it wrong would silently take a walk budget
/// of nothing.
fn pool_op(query: PoolOp) -> EngineOp {
    EngineOp::Pool {
        query,
        patience_ms: 0,
    }
}

fn heap_op(query: HeapOp) -> EngineOp {
    EngineOp::Heap {
        query,
        patience_ms: 0,
    }
}

/// Parses a decimal or `0x`-prefixed hex integer.
pub(crate) fn parse_u64(s: &str) -> Result<u64, String> {
    let t = s.trim();
    let parsed = if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(h, 16)
    } else {
        t.parse::<u64>()
    };
    parsed.map_err(|_| format!("invalid number: {s}"))
}

pub(crate) fn hexdump(base: u64, bytes: &[u8]) -> String {
    let mut out = String::new();
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let addr = base + (i * 16) as u64;
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if (0x20..0x7f).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        out.push_str(&format!("{addr:016x}  {:<47}  {ascii}\n", hex.join(" ")));
    }
    out
}

/// Decodes a 32-bit Windows IOCTL control code into its `CTL_CODE` fields and
/// renders a human-readable report. Pure (no debugger) so it is unit-testable and
/// works without a live session.
///
/// Layout: `DeviceType` = bits 16–31, `RequiredAccess` = bits 14–15,
/// `FunctionCode` = bits 2–13, `Method` = bits 0–1.
fn decode_ioctl_text(c: u32) -> String {
    let device_type = (c >> 16) & 0xFFFF;
    let access = (c >> 14) & 0x3;
    let function = (c >> 2) & 0xFFF;
    let method = c & 0x3;

    let method_name = match method {
        0 => "METHOD_BUFFERED",
        1 => "METHOD_IN_DIRECT",
        2 => "METHOD_OUT_DIRECT",
        _ => "METHOD_NEITHER",
    };
    let access_name = match access {
        0 => "FILE_ANY_ACCESS",
        1 => "FILE_READ_DATA",
        2 => "FILE_WRITE_DATA",
        _ => "FILE_READ_DATA | FILE_WRITE_DATA",
    };

    let mut out = String::new();
    out.push_str(&format!("IOCTL 0x{c:08x}\n"));
    out.push_str(&format!(
        "  CTL_CODE(0x{device_type:04x}, 0x{function:03x}, {method_name}, {access_name})\n"
    ));
    out.push_str(&format!("  DeviceType     0x{device_type:04x}\n"));
    out.push_str(&format!("  FunctionCode   0x{function:03x}\n"));
    out.push_str(&format!("  Method         {method} ({method_name})\n"));
    out.push_str(&format!("  RequiredAccess {access} ({access_name})\n"));

    // Surface the two fields that matter most for reachability / bug-class triage.
    if method == 3 {
        out.push_str(
            "  [!] METHOD_NEITHER: the driver receives raw user-mode pointers \
             (Type3InputBuffer / UserBuffer) — classic input-validation bug surface.\n",
        );
    }
    if access == 0 {
        out.push_str(
            "  [!] FILE_ANY_ACCESS: no access gate — the I/O manager delivers this IOCTL \
             on any handle, even one opened with minimal access.\n",
        );
    }
    out
}

// ---- IOCTL dispatch reachability (static call-graph walk) ----------------
//
// Answers "is the code block at <target> reachable from the IOCTL dispatch
// routine?" with a bounded breadth-first walk over the call graph, built from
// repeated `uf` (unassemble-function) disassembly parsed as text. The whole
// algorithm is engine-free — `reachability` takes a disassembler closure — so it
// unit-tests without a live debugger (like `decode_ioctl_text` above).

/// Parses a WinDbg address token into a `u64`. Accepts the `hi`lo` backtick form
/// ("fffff803`3e254750"), a plain hex run ("00401000"), and tokens wrapped or
/// trailed by parens/commas ("(fffff803`3e2547f0)"). Requires >= 8 hex digits so
/// it never mistakes a mnemonic, a short immediate, or a "module!Symbol:" label
/// for an address.
pub(crate) fn parse_windbg_addr(tok: &str) -> Option<u64> {
    let cleaned: String = tok
        .trim_matches(|c| c == '(' || c == ')' || c == ',')
        .chars()
        .filter(|&c| c != '`')
        .collect();
    if cleaned.len() < 8 || !cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(&cleaned, 16).ok()
}

/// The resolved target of a direct branch/call is the last parenthesized address
/// WinDbg prints on the line ("... (fffff803`3e2547f0)"). Register/memory-indirect
/// operands print no such address (or the *pointer's* address, which callers
/// exclude via the `[` guard in [`parse_uf`]) and are not followed.
fn branch_target(line: &str) -> Option<u64> {
    let open = line.rfind('(')?;
    let rest = &line[open..];
    let close = rest.find(')')?;
    parse_windbg_addr(&rest[..=close])
}

/// The control-flow behavior of one instruction, used to walk *within* a function.
/// Only *direct*, resolvable targets are carried; memory-indirect (`call qword ptr
/// [..]`) and register-indirect (`call rax`) operands become the `*Indirect` variants
/// with no target, so a REACHABLE verdict never rests on a guessed edge.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Flow {
    /// Falls through to the next instruction (the common case).
    Fallthrough,
    /// Direct `call`: schedules the target, then falls through.
    Call(u64),
    /// Indirect `call`: falls through (target unknown, not followed).
    CallIndirect,
    /// Unconditional direct `jmp`: control goes to the target only (no fall-through).
    Jmp(u64),
    /// Indirect `jmp` (function pointer / jump table): flow stops; target not followed.
    JmpIndirect,
    /// Conditional branch (je/jne/jz/jg/...): the target OR the next instruction.
    Branch(u64),
    /// `ret`/`iret`: flow stops.
    Return,
    /// A `noreturn` trap — `int 29h` (`__fastfail`/stack-cookie failure), `int 3`,
    /// `ud2`, `hlt`: execution stops, so the walk must not fall through it.
    Trap,
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct Insn {
    addr: u64,
    flow: Flow,
}

/// One function's `uf` disassembly as an ordered instruction list.
#[derive(Debug, Default, PartialEq)]
struct UfBlock {
    /// First instruction address (the function entry), if any lines parsed.
    entry: Option<u64>,
    /// Every instruction, in listing order, with its control-flow classification.
    insns: Vec<Insn>,
}

/// Classifies one `uf` instruction line into a [`Flow`]. A memory-operand (`[..]`)
/// line has no directly-resolvable target; otherwise the target is the parenthesized
/// address WinDbg prints ([`branch_target`]).
fn classify_flow(line: &str, mnem: &str) -> Flow {
    let target = if line.contains('[') {
        None
    } else {
        branch_target(line)
    };
    if mnem.starts_with("ret") || mnem.starts_with("iret") {
        Flow::Return
    } else if mnem == "jmp" {
        target.map_or(Flow::JmpIndirect, Flow::Jmp)
    } else if mnem.starts_with("call") {
        target.map_or(Flow::CallIndirect, Flow::Call)
    } else if mnem.starts_with('j') {
        // A conditional branch; a jcc without a resolvable rel target just falls through.
        target.map_or(Flow::Fallthrough, Flow::Branch)
    } else if mnem == "ud2" || mnem == "hlt" || mnem == "int" || mnem == "int3" || mnem == "int1" {
        // `noreturn` traps: `int 29h`/`int 3` (WinDbg emits mnemonic `int` + operand),
        // a single `int3` token, `ud2`, `hlt`. Execution stops here.
        Flow::Trap
    } else {
        Flow::Fallthrough
    }
}

/// Parses `uf <fn>` output. Each instruction line is `<addr> <bytes> <mnem> <ops>`;
/// label lines ("module!Foo:"), blanks, and jump-table data lines have no leading
/// address token and are skipped.
fn parse_uf(text: &str) -> UfBlock {
    let mut b = UfBlock::default();
    for line in text.lines() {
        let mut toks = line.split_whitespace();
        let Some(addr) = toks.next().and_then(parse_windbg_addr) else {
            continue;
        };
        let _bytes = toks.next(); // raw opcode-bytes column
        if b.entry.is_none() {
            b.entry = Some(addr);
        }
        let flow = match toks.next() {
            Some(mnem) => classify_flow(line, mnem),
            None => Flow::Fallthrough, // address with no mnemonic — treat as a bare line
        };
        b.insns.push(Insn { addr, flow });
    }
    b
}

/// Instructions reachable from `start` by walking *inside* one function — following
/// fall-through, direct conditional branches, and direct `jmp`s that stay in the
/// function — and stopping at `ret` or an unfollowed indirect/jump-table `jmp`. This
/// keeps a mid-function start (a handler scoped past a switch) from spuriously
/// treating sibling switch cases as reachable.
struct FnWalk {
    /// Instruction addresses reachable from `start` within the function.
    reachable: HashSet<u64>,
    /// Edges leaving the function, gathered only from reachable instructions:
    /// (site, target, "call"/"jmp").
    external: Vec<(u64, u64, &'static str)>,
}

/// Returns `None` if `start` is not an instruction boundary in `block` (the caller
/// then falls back to the function entry).
fn walk_function(block: &UfBlock, start: u64) -> Option<FnWalk> {
    let idx: HashMap<u64, usize> = block
        .insns
        .iter()
        .enumerate()
        .map(|(i, x)| (x.addr, i))
        .collect();
    let start_i = *idx.get(&start)?;
    let mut reachable: HashSet<u64> = HashSet::new();
    let mut external: Vec<(u64, u64, &'static str)> = Vec::new();
    let mut stack = vec![start_i];
    while let Some(i) = stack.pop() {
        let insn = block.insns[i];
        if !reachable.insert(insn.addr) {
            continue;
        }
        let next = (i + 1 < block.insns.len()).then_some(i + 1);
        match insn.flow {
            Flow::Return | Flow::JmpIndirect | Flow::Trap => {}
            Flow::Jmp(t) => match idx.get(&t) {
                Some(&j) => stack.push(j),
                None => external.push((insn.addr, t, "jmp")),
            },
            Flow::Branch(t) => {
                match idx.get(&t) {
                    Some(&j) => stack.push(j),
                    None => external.push((insn.addr, t, "jmp")),
                }
                if let Some(n) = next {
                    stack.push(n);
                }
            }
            Flow::Call(t) => {
                external.push((insn.addr, t, "call"));
                if let Some(n) = next {
                    stack.push(n);
                }
            }
            Flow::CallIndirect | Flow::Fallthrough => {
                if let Some(n) = next {
                    stack.push(n);
                }
            }
        }
    }
    Some(FnWalk {
        reachable,
        external,
    })
}

/// The first address token in `lm m <module>` output is the module's live start
/// (its base). Header lines ("Browse full module list", the "start end module"
/// legend) have no leading address and are skipped by the >= 8 hex-digit rule.
pub(crate) fn parse_lm_base(text: &str) -> Option<u64> {
    text.lines()
        .find_map(|l| l.split_whitespace().next().and_then(parse_windbg_addr))
}

// ---- what a module filter means -------------------------------------------
//
// One definition, in one place, and — since #120 — applied exactly **once**, by the worker, over
// the records it renders the listing from. While `modules` pasted `lm m`'s output there were two
// implementations of one pattern (this one and DbgEng's), which is why this section used to open
// with an allowlist refusing everything the two could disagree about. The grammar below is now
// this server's own, so it is documented rather than defended: `execute { "command": "lm m …" }`
// is where WinDbg's fuller wildcard grammar lives.

/// The wildcards a `modules` filter honours, which is exactly what [`matches_module_pattern`]
/// implements. Every other character is literal.
const MODULE_WILDCARDS: [char; 2] = ['*', '?'];

/// The pattern a `filter` argument really means.
///
/// A bare name matches **anywhere in** a module name, because that is what a caller asking for
/// `MessageManager` wants, and what every other `filter` in this server does (`pool_diagnostics`'
/// is a case-insensitive substring too). A filter that already carries a wildcard is somebody
/// writing a pattern deliberately and is left exactly as written — which is also how an
/// *anchored* match is asked for, since `nt` alone would otherwise be widened: `nt*` is names
/// beginning with `nt`, `nt` is names containing it.
pub(crate) fn module_pattern(filter: &str) -> String {
    let filter = filter.trim();
    if filter.contains(MODULE_WILDCARDS) {
        filter.to_string()
    } else {
        format!("*{filter}*")
    }
}

/// Whether a module name matches a `modules` filter: `*` for any run of characters, `?` for
/// exactly one, everything else literal, case-insensitively.
///
/// **This is the whole definition.** There is no DbgEng call that lists modules matching a pattern
/// — only `lm m`, which prints them — so a tool that answers with values has to match here; and
/// since the listing text is rendered from those same values ([#120]), here is the only place a
/// filter is applied. A pattern this does not implement is therefore not a disagreement between
/// two matchers but simply a literal, which is what it now documents.
///
/// **Case folds per character, by Unicode's lowercase mapping.** ASCII is the interesting part —
/// module names are ASCII — but `é`/`É` folding too costs one comparison and removes the caveat
/// that used to have to be explained (and enforced) to keep this in step with whatever fold
/// Windows applied on the other side. Per character, so a name whose case changes its *length*
/// (`ß`/`SS`) is not folded; `?` matches any single character, which is the way to reach one.
///
/// [#120]: https://github.com/glslang/windbg-mcp/issues/120
pub(crate) fn matches_module_pattern(pattern: &str, name: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let name: Vec<char> = name.chars().collect();
    // The standard greedy walk: remember the last `*` as the point to give ground at, so a pattern
    // that runs out of name backtracks to it instead of failing outright.
    let (mut p, mut n) = (0, 0);
    let (mut star, mut resume) = (None, 0);
    while n < name.len() {
        if p < pattern.len() && (pattern[p] == '?' || folds_to_same(pattern[p], name[n])) {
            p += 1;
            n += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some(p);
            resume = n;
            p += 1;
        } else if let Some(star) = star {
            resume += 1;
            n = resume;
            p = star + 1;
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|c| *c == '*')
}

/// Whether two characters are the same letter in different cases.
///
/// The equality test first: it is the answer for every character that is not a letter, and for the
/// overwhelmingly common case of a name and a pattern that already agree.
///
/// **Both directions, because one is not enough.** Lowercasing alone is the obvious test and it
/// misses the pairs that only converge upward: `Σ` lowercases to `σ`, while final sigma `ς`
/// lowercases to itself, so a filter of `Σ` would not have found a name containing `ς` — a promise
/// of case-insensitive matching that quietly is not. Uppercasing catches those (both map to `Σ`),
/// and lowercasing catches the ones that only converge downward (`ẞ`/`ß`).
///
/// This is Unicode's *simple* case mapping applied per character, not full case folding — Rust's
/// standard library has no folding API and this is not worth a dependency for names that are, in
/// practice, file names. Where the two differ it errs toward **matching**: dotless `ı` uppercases
/// to `I`, so a filter of `i` finds it, which full folding would not. For a listing filter that is
/// the right direction to be wrong in — the caller sees a row and the row names itself, rather than
/// missing one and concluding the module is not loaded. `?` matches any single character, which is
/// the way to sidestep the question entirely.
fn folds_to_same(a: char, b: char) -> bool {
    a == b || a.to_lowercase().eq(b.to_lowercase()) || a.to_uppercase().eq(b.to_uppercase())
}

/// Parses the value from WinDbg `?` (evaluate-expression) output, e.g.
/// "Evaluate expression: 18446735277667370832 = fffff803`3e254750" — the address
/// is the hex token after the `=`. Used to resolve a symbolic/backtick `from` (like
/// `mydriver!Dispatch+0x123`) to the numeric VA the intra-function walk starts at.
pub(crate) fn parse_eval(text: &str) -> Option<u64> {
    let rhs = text.split('=').nth(1)?;
    parse_windbg_addr(rhs.split_whitespace().next()?)
}

/// Outcome of a reachability walk. `verdict_reachable` is sound (a concrete static
/// path exists); a false verdict is best-effort within the explored bounds.
pub(crate) struct Report {
    pub(crate) verdict_reachable: bool,
    /// Resolved entry of the `from` function (None if `from` didn't disassemble).
    pub(crate) from_entry: Option<u64>,
    target: u64,
    /// Entry of the function containing `target`, when reachable.
    containing_fn: Option<u64>,
    /// Call path seed -> ... -> containing function: (site, "call"/"jmp", callee).
    path: Vec<(u64, &'static str, u64)>,
    funcs_explored: usize,
    max_depth_seen: usize,
    /// True if a function/depth bound was hit (so the caller can raise it and retry).
    bound_hit: bool,
    max_functions: usize,
    max_depth: usize,
}

/// Walks the call/branch graph from `from`, running `uf(arg)` for each discovered
/// function and an intra-function control-flow walk ([`walk_function`]) within each,
/// until `target` is found among the reachable instructions, the graph is exhausted,
/// or a bound is hit. `uf` returns the raw `uf <arg>` text or `None` (bad address /
/// forwarded export / disassembly failure) to prune that branch.
///
/// `seed_start` is the resolved numeric VA of `from` (the caller resolves symbols /
/// backtick / `module!sym+off` forms). When it points *inside* the seed function — a
/// handler scoped past a switch — the intra-function walk begins there, not at the
/// entry, so sibling switch cases aren't spuriously reachable. `None` (unresolvable)
/// falls back to the function entry.
pub(crate) fn reachability(
    from: &str,
    seed_start: Option<u64>,
    target: u64,
    max_functions: usize,
    max_depth: usize,
    mut uf: impl FnMut(&str) -> Option<String>,
) -> Report {
    let mut visited: HashSet<u64> = HashSet::new(); // walk start addresses already done
    let mut enqueued: HashSet<u64> = HashSet::new(); // target tokens scheduled
    // child token -> (caller token (None = seed), call site, kind).
    let mut parent: HashMap<u64, (Option<u64>, u64, &'static str)> = HashMap::new();
    let mut queue: VecDeque<(String, Option<u64>, usize)> = VecDeque::new();
    queue.push_back((from.to_string(), None, 0));

    let mut rpt = Report {
        verdict_reachable: false,
        from_entry: None,
        target,
        containing_fn: None,
        path: Vec::new(),
        funcs_explored: 0,
        max_depth_seen: 0,
        bound_hit: false,
        max_functions,
        max_depth,
    };

    while let Some((arg, token, depth)) = queue.pop_front() {
        if rpt.funcs_explored >= max_functions || depth > max_depth {
            rpt.bound_hit = true;
            continue;
        }
        let Some(text) = uf(&arg) else {
            continue; // disassembly failed — prune this branch
        };
        let block = parse_uf(&text);
        let Some(entry) = block.entry else {
            continue;
        };
        // Enter discovered functions at their call/jmp target (`token`); enter the
        // seed at its resolved address, or the entry if `from` was a symbol. Fall back
        // to the entry if the requested address isn't an instruction boundary.
        let desired = token.or(seed_start).unwrap_or(entry);
        let (start_used, walk) = match walk_function(&block, desired) {
            Some(w) => (desired, w),
            None => (
                entry,
                walk_function(&block, entry).expect("entry is always an instruction"),
            ),
        };
        if !visited.insert(start_used) {
            continue; // this (function, start) was already explored (dedupe cycles)
        }
        if token.is_none() {
            rpt.from_entry = Some(entry);
        }
        rpt.funcs_explored += 1;
        rpt.max_depth_seen = rpt.max_depth_seen.max(depth);

        if walk.reachable.contains(&target) {
            rpt.verdict_reachable = true;
            rpt.containing_fn = Some(entry);
            rpt.path = reconstruct(&parent, token);
            return rpt;
        }

        // Schedule edges that leave this function, gathered only from instructions
        // actually reachable from the start (so a mid-function start can't pull in
        // calls from unrelated switch cases).
        for (site, t, kind) in walk.external {
            if enqueued.insert(t) {
                parent.insert(t, (token, site, kind));
                queue.push_back((format!("0x{t:x}"), Some(t), depth + 1));
            }
        }
    }
    rpt
}

/// Rebuilds the call path from the seed to the function reached via `token`, by
/// walking the `parent` chain backward and reversing it.
fn reconstruct(
    parent: &HashMap<u64, (Option<u64>, u64, &'static str)>,
    token: Option<u64>,
) -> Vec<(u64, &'static str, u64)> {
    let mut hops = Vec::new();
    let mut cur = token;
    while let Some(t) = cur {
        let Some(&(caller, site, kind)) = parent.get(&t) else {
            break;
        };
        hops.push((site, kind, t));
        cur = caller;
    }
    hops.reverse();
    hops
}

/// Formats a WinDbg-style `hi`lo` address.
pub(crate) fn fmt_addr(a: u64) -> String {
    format!("{:08x}`{:08x}", a >> 32, a & 0xffff_ffff)
}

/// Renders a [`Report`] as the tool's text output.
pub(crate) fn format_report(r: &Report) -> String {
    let mut out = String::new();
    out.push_str("IOCTL dispatch reachability\n");
    match r.from_entry {
        Some(e) => out.push_str(&format!("  from   : entry {}\n", fmt_addr(e))),
        None => out.push_str("  from   : <unresolved>\n"),
    }
    out.push_str(&format!("  target : {}\n", fmt_addr(r.target)));
    if r.verdict_reachable {
        out.push_str("VERDICT: REACHABLE\n");
        if let Some(f) = r.containing_fn {
            out.push_str(&format!("  Containing function entry: {}\n", fmt_addr(f)));
        }
        if r.path.is_empty() {
            out.push_str("  Call path: target is inside the start function (0 hops)\n");
        } else {
            out.push_str(&format!("  Call path ({} hops):\n", r.path.len()));
            for (site, kind, callee) in &r.path {
                out.push_str(&format!(
                    "    {}  {:<4} -> {}\n",
                    fmt_addr(*site),
                    kind,
                    fmt_addr(*callee)
                ));
            }
        }
    } else {
        out.push_str("VERDICT: NOT REACHABLE (within bounds)\n");
        out.push_str(&format!(
            "  Bound hit: {}\n",
            if r.bound_hit {
                "yes — raise max_functions/max_depth and retry"
            } else {
                "no — the reachable call graph was fully explored"
            }
        ));
    }
    out.push_str(&format!(
        "  Functions explored: {} (bound {})   Max depth reached: {} (bound {})\n",
        r.funcs_explored, r.max_functions, r.max_depth_seen, r.max_depth
    ));
    out.push_str(
        "  Caveats: indirect/computed calls (call [ptr], call reg) and unresolved jump tables\n",
    );
    out.push_str(
        "           are NOT followed. REACHABLE is sound; NOT REACHABLE within bounds does not\n",
    );
    out.push_str(
        "           prove unreachability — raise max_functions/max_depth, or pass a specific\n",
    );
    out.push_str("           handler VA as `from` to scope past a jump-table switch dispatch.\n");
    out
}

// ---- Directional path recipe (which input keeps control on the path) ------
//
// A REACHABLE verdict proves a static path exists, but not *which way* each on-path
// conditional branch must go, nor *what* it tests. `path_recipe` walks the same `uf`
// disassembly a second time (engine-free, like the walk above) and, for every function
// on the reported call path, records the on-path branches with the direction required
// to stay on the path plus a best-effort decode of the compare feeding each one. It is
// heuristic: operands are text-parsed from `uf`, and the field mapping holds only when
// the memory base is the current IO_STACK_LOCATION pointer.

/// Which way an on-path conditional branch must go to keep control on the reconstructed
/// path to the goal. This is the concrete direction taken by the found path — a sound
/// *sufficient* condition. (An alternate successor may also reach the goal, but usually via
/// its own further conditions, so it is not reported as "don't care".)
#[derive(Debug, Clone, Copy, PartialEq)]
enum Direction {
    /// The branch must be taken (control goes to the `jcc` target).
    Taken,
    /// The branch must fall through (control goes to the next instruction).
    Fallthrough,
}

/// The IO_STACK_LOCATION field a predicate's memory operand likely reads, inferred from
/// its displacement — the offsets `ioctl_trace` encodes (`+0x18`/`+0x10`/`+0x08`).
#[derive(Debug, Clone, Copy, PartialEq)]
enum IoField {
    IoControlCode,
    InputBufferLength,
    OutputBufferLength,
}

impl IoField {
    fn name(self) -> &'static str {
        match self {
            IoField::IoControlCode => "IoControlCode",
            IoField::InputBufferLength => "InputBufferLength",
            IoField::OutputBufferLength => "OutputBufferLength",
        }
    }
}

/// A best-effort decode of the flag-setting instruction feeding an on-path branch.
#[derive(Debug, Clone, PartialEq)]
struct Predicate {
    /// Raw `uf` text of the compare (e.g. "cmp dword ptr [rdx+18h],222003h").
    raw: String,
    /// Heuristic mapping of the memory operand's displacement to an IO_STACK_LOCATION field.
    field: Option<IoField>,
    /// Immediate the compare tests against, when it has a trailing hex immediate.
    value: Option<u64>,
    /// Relation that holds in the required direction (e.g. "==", ">="), when derivable.
    relation: Option<&'static str>,
    /// True when the setter is bitwise (`test`/`and`): the condition is `(field & value)
    /// relation 0`, not `field relation value`. Distinguishes `test x,m; jne` — which means
    /// `(x & m) != 0` — from a `cmp`.
    mask: bool,
}

/// One on-path conditional branch and what it requires.
#[derive(Debug, Clone, PartialEq)]
struct BranchStep {
    /// Address of the `jcc`.
    site: u64,
    /// The `jcc` mnemonic (je/jne/jae/...), for rendering.
    jcc: String,
    /// Direction required to stay on the path to the goal.
    required: Direction,
    /// Decoded predicate (the flag-setting compare), when one was found.
    predicate: Option<Predicate>,
}

/// The recipe for one function on the call path: the branch decisions between where the
/// function is entered and where control leaves it toward the target.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SegmentRecipe {
    /// Entry (or mid-function start) the segment's walk begins at.
    start: u64,
    /// Address the segment routes to: the call/jmp site to the next hop, or the target.
    goal: u64,
    /// On-path conditional branches, in path order (includes `Either` steps).
    steps: Vec<BranchStep>,
}

/// Maps each instruction address to its mnemonic+operands text (address and raw-bytes
/// columns dropped). Mirrors [`parse_uf`]'s tokenization so the recipe can read operands
/// `parse_uf` discards.
fn uf_text_map(text: &str) -> HashMap<u64, String> {
    let mut m = HashMap::new();
    for line in text.lines() {
        let mut toks = line.split_whitespace();
        let Some(addr) = toks.next().and_then(parse_windbg_addr) else {
            continue;
        };
        let _bytes = toks.next(); // raw opcode-bytes column
        let rest: Vec<&str> = toks.collect();
        if !rest.is_empty() {
            m.insert(addr, rest.join(" "));
        }
    }
    m
}

/// Instructions that set flags a following `jcc` reads.
fn is_flag_setter(mnem: &str) -> bool {
    matches!(
        mnem,
        "cmp"
            | "test"
            | "sub"
            | "add"
            | "and"
            | "or"
            | "xor"
            | "inc"
            | "dec"
            | "neg"
            | "bt"
            | "cmpxchg"
            | "shl"
            | "shr"
            | "sar"
            | "sal"
    )
}

/// Parses a WinDbg immediate token: `0x22`, `222003h`, or a plain hex run containing a
/// digit (so a register mnemonic like `eax`/`rcx`/`ah` is rejected). `None` otherwise.
fn parse_imm(tok: &str) -> Option<u64> {
    let t = tok
        .trim()
        .trim_matches(|c| c == ',' || c == '(' || c == ')');
    let hex = if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        h
    } else if let Some(h) = t.strip_suffix('h').or_else(|| t.strip_suffix('H')) {
        h
    } else {
        t
    };
    if !hex.is_empty()
        && hex.chars().all(|c| c.is_ascii_hexdigit())
        && hex.chars().any(|c| c.is_ascii_digit())
    {
        u64::from_str_radix(hex, 16).ok()
    } else {
        None
    }
}

/// Heuristically maps the displacement in a memory operand (`[reg+18h]`) to an
/// IO_STACK_LOCATION field, using the offsets `ioctl_trace` encodes.
fn field_from_operands(raw: &str) -> Option<IoField> {
    let open = raw.find('[')?;
    let close = raw[open..].find(']')? + open;
    let inside = &raw[open + 1..close];
    let plus = inside.rfind('+')?;
    match parse_imm(&inside[plus + 1..])? {
        0x18 => Some(IoField::IoControlCode),
        0x10 => Some(IoField::InputBufferLength),
        0x08 => Some(IoField::OutputBufferLength),
        _ => None,
    }
}

/// The immediate a compare tests against — its last comma-separated operand.
fn predicate_value(raw: &str) -> Option<u64> {
    parse_imm(raw.rsplit(',').next()?)
}

/// The relation that holds when a `jcc` goes the given direction, for the common
/// signed/unsigned conditionals. `None` for branches we don't model.
fn branch_relation(jcc: &str, taken: bool) -> Option<&'static str> {
    let (t, f) = match jcc {
        "je" | "jz" => ("==", "!="),
        "jne" | "jnz" => ("!=", "=="),
        "jae" | "jnb" | "jnc" => (">=", "<"),
        "jb" | "jnae" | "jc" => ("<", ">="),
        "ja" | "jnbe" => (">", "<="),
        "jbe" | "jna" => ("<=", ">"),
        "jge" | "jnl" => (">=", "<"),
        "jl" | "jnge" => ("<", ">="),
        "jg" | "jnle" => (">", "<="),
        "jle" | "jng" => ("<=", ">"),
        _ => return None,
    };
    Some(if taken { t } else { f })
}

/// Finds one intra-function path from `start` to `goal`, returning the on-path
/// conditional-branch decisions `(branch addr, took_taken)` in path order, or `None` if
/// `goal` is not reachable within the function. Follows the same edges as
/// [`walk_function`]; a global visited-set bounds it and guarantees termination.
fn find_path(
    block: &UfBlock,
    idx: &HashMap<u64, usize>,
    start: u64,
    goal: u64,
) -> Option<Vec<(u64, bool)>> {
    fn dfs(
        block: &UfBlock,
        idx: &HashMap<u64, usize>,
        i: usize,
        goal: u64,
        visited: &mut HashSet<usize>,
        acc: &mut Vec<(u64, bool)>,
    ) -> bool {
        let insn = block.insns[i];
        if insn.addr == goal {
            return true;
        }
        if !visited.insert(i) {
            return false;
        }
        let next = (i + 1 < block.insns.len()).then_some(i + 1);
        match insn.flow {
            Flow::Return | Flow::JmpIndirect | Flow::Trap => false,
            Flow::Jmp(t) => match idx.get(&t) {
                Some(&j) => dfs(block, idx, j, goal, visited, acc),
                None => false,
            },
            Flow::Branch(t) => {
                if let Some(&j) = idx.get(&t) {
                    acc.push((insn.addr, true));
                    if dfs(block, idx, j, goal, visited, acc) {
                        return true;
                    }
                    acc.pop();
                }
                if let Some(n) = next {
                    acc.push((insn.addr, false));
                    if dfs(block, idx, n, goal, visited, acc) {
                        return true;
                    }
                    acc.pop();
                }
                false
            }
            Flow::Call(_) | Flow::CallIndirect | Flow::Fallthrough => match next {
                Some(n) => dfs(block, idx, n, goal, visited, acc),
                None => false,
            },
        }
    }
    let start_i = *idx.get(&start)?;
    let mut visited = HashSet::new();
    let mut acc = Vec::new();
    dfs(block, idx, start_i, goal, &mut visited, &mut acc).then_some(acc)
}

/// Classifies one on-path branch decision into a [`BranchStep`]: the concrete direction the
/// path took plus the decoded predicate feeding it.
fn branch_step(
    block: &UfBlock,
    idx: &HashMap<u64, usize>,
    textmap: &HashMap<u64, String>,
    site: u64,
    took_taken: bool,
) -> BranchStep {
    let bi = idx[&site];
    let required = if took_taken {
        Direction::Taken
    } else {
        Direction::Fallthrough
    };
    let jcc = textmap
        .get(&site)
        .and_then(|t| t.split_whitespace().next())
        .unwrap_or("jcc")
        .to_string();
    let predicate = decode_predicate(block, textmap, bi, &jcc, took_taken);
    BranchStep {
        site,
        jcc,
        required,
        predicate,
    }
}

/// Finds the nearest flag-setting instruction preceding the branch at index `bi` (within
/// a small window) and decodes it into a [`Predicate`]. A `cmp`/`sub` yields a comparison
/// (`field relation value`); a `test`/`and` yields a bitwise mask test (`(field & value)
/// relation 0`); other setters carry no relation (only the raw text is trustworthy).
fn decode_predicate(
    block: &UfBlock,
    textmap: &HashMap<u64, String>,
    bi: usize,
    jcc: &str,
    took_taken: bool,
) -> Option<Predicate> {
    for k in (bi.saturating_sub(6)..bi).rev() {
        let Some(raw) = textmap.get(&block.insns[k].addr) else {
            continue;
        };
        let Some(mnem) = raw.split_whitespace().next() else {
            continue;
        };
        if is_flag_setter(mnem) {
            let mask = matches!(mnem, "test" | "and");
            // Only subtractive (`cmp`/`sub`) and bitwise (`test`/`and`) setters map cleanly
            // to a `jcc` relation; for the rest, don't claim one (`raw` still shows the op).
            let relation = if mask || matches!(mnem, "cmp" | "sub") {
                branch_relation(jcc, took_taken)
            } else {
                None
            };
            return Some(Predicate {
                raw: raw.clone(),
                field: field_from_operands(raw),
                value: predicate_value(raw),
                relation,
                mask,
            });
        }
    }
    None
}

/// Builds the directional path recipe for a REACHABLE [`Report`]: one [`SegmentRecipe`]
/// per function on the call path, re-disassembling each with `uf` (a handful of calls) and
/// recording the on-path branch decisions. `from` disassembles the seed function (a symbol
/// still resolves); later functions enter their callee by address. `seed_start` scopes the
/// seed segment to a mid-function start when set.
pub(crate) fn path_recipe(
    from: &str,
    seed_start: Option<u64>,
    rpt: &Report,
    mut uf: impl FnMut(&str) -> Option<String>,
) -> Vec<SegmentRecipe> {
    let Some(from_entry) = rpt.from_entry else {
        return Vec::new();
    };
    // (uf arg, requested start, goal, goal_is_exit) per function on the path. `goal_is_exit`
    // is true when the goal is a hop *site* (control leaves the function there) rather than
    // the final target — used to capture a conditional exit branch (below).
    let mut segs: Vec<(String, u64, u64, bool)> = Vec::new();
    let from_start = seed_start.unwrap_or(from_entry);
    if rpt.path.is_empty() {
        segs.push((from.to_string(), from_start, rpt.target, false));
    } else {
        segs.push((from.to_string(), from_start, rpt.path[0].0, true));
        for (i, hop) in rpt.path.iter().enumerate() {
            let callee = hop.2;
            let (goal, is_exit) = rpt
                .path
                .get(i + 1)
                .map_or((rpt.target, false), |h| (h.0, true));
            segs.push((format!("0x{callee:x}"), callee, goal, is_exit));
        }
    }

    let mut recipes = Vec::new();
    for (arg, want_start, goal, goal_is_exit) in segs {
        let Some(text) = uf(&arg) else { continue };
        let block = parse_uf(&text);
        let idx: HashMap<u64, usize> = block
            .insns
            .iter()
            .enumerate()
            .map(|(i, x)| (x.addr, i))
            .collect();
        // Fall back to the function entry if the requested start isn't a boundary
        // (mirrors `reachability`'s handling of an unaligned seed).
        let start = if idx.contains_key(&want_start) {
            want_start
        } else {
            block.entry.unwrap_or(want_start)
        };
        let textmap = uf_text_map(&text);
        let mut steps: Vec<BranchStep> = find_path(&block, &idx, start, goal)
            .unwrap_or_default()
            .into_iter()
            .map(|(site, took)| branch_step(&block, &idx, &textmap, site, took))
            .collect();
        // When a function is left through a *conditional* branch to the next hop, the goal
        // is that branch and `find_path` stops before recording its decision. Add it:
        // reaching the callee means taking the branch. (A `call`/unconditional `jmp` exit
        // gates nothing, so only `Flow::Branch` needs a step.)
        if goal_is_exit
            && let Some(&gi) = idx.get(&goal)
            && matches!(block.insns[gi].flow, Flow::Branch(_))
        {
            let jcc = textmap
                .get(&goal)
                .and_then(|t| t.split_whitespace().next())
                .unwrap_or("jcc")
                .to_string();
            let predicate = decode_predicate(&block, &textmap, gi, &jcc, true);
            steps.push(BranchStep {
                site: goal,
                jcc,
                required: Direction::Taken,
                predicate,
            });
        }
        recipes.push(SegmentRecipe { start, goal, steps });
    }
    recipes
}

/// Renders the annotation for a decoded [`Predicate`]. A bitwise (`test`/`and`) setter is
/// rendered as a mask test `(field & value) relation 0`; a `cmp`/`sub` as `field relation
/// value`; a setter with no derivable relation carries only the field hint (`raw` still shows
/// the operation).
fn render_predicate(p: &Predicate) -> String {
    match (p.field, p.value, p.relation) {
        (Some(f), Some(v), Some(rel)) if p.mask => {
            format!("   (likely ({} & 0x{v:x}) {rel} 0)", f.name())
        }
        (Some(f), Some(v), Some(rel)) => format!("   (likely {} {rel} 0x{v:x})", f.name()),
        (Some(f), _, _) => format!("   (likely {})", f.name()),
        (None, Some(v), Some(rel)) if p.mask => format!("   (bits & 0x{v:x} {rel} 0)"),
        (None, Some(v), Some(rel)) => format!("   (tests {rel} 0x{v:x})"),
        _ => String::new(),
    }
}

/// Renders the path recipe, appended after [`format_report`] on a REACHABLE verdict.
pub(crate) fn format_recipe(recipes: &[SegmentRecipe]) -> String {
    let mut out = String::new();
    out.push_str("\nPath recipe (input that keeps control on the path to the target)\n");
    out.push_str(
        "  Note: the IOCTL dispatch switch is an indirect jump table the static walk does\n",
    );
    out.push_str(
        "        not follow — pass the handler VA as `from`. Its IoControlCode is implied\n",
    );
    out.push_str(
        "        by that choice, not by the branches below. Field mappings are heuristic.\n",
    );
    for (n, seg) in recipes.iter().enumerate() {
        out.push_str(&format!(
            "  Segment {}: {} -> {}\n",
            n + 1,
            fmt_addr(seg.start),
            fmt_addr(seg.goal)
        ));
        if seg.steps.is_empty() {
            out.push_str("    (no gating branches — straight-line to the goal)\n");
            continue;
        }
        for s in &seg.steps {
            let dir = match s.required {
                Direction::Taken => "take",
                Direction::Fallthrough => "fall through",
            };
            out.push_str(&format!(
                "    {}  {} — must {}",
                fmt_addr(s.site),
                s.jcc,
                dir
            ));
            if let Some(p) = &s.predicate {
                out.push_str(&format!("   ; {}", p.raw));
                out.push_str(&render_predicate(p));
            }
            out.push('\n');
        }
    }
    out
}

// ---- Tool parameter types ------------------------------------------------
//
// Every tool that touches the debug target carries an optional `session_id` (see the
// "Session handles" section below). The field is repeated per struct rather than
// flattened from a shared type so each tool's input schema stays a plain, self-contained
// object — flattening renders as a schema composition that clients handle unevenly.

/// Parameters for tools that take no arguments beyond the session handle.
#[derive(Deserialize, JsonSchema)]
pub struct SessionArgs {
    /// Session handle returned by open_dump/open_trace/attach_*/launch. Optional: omit it
    /// to act on whatever session is current, or pass it to have the call refuse to run if
    /// this server's debug target has been replaced since you opened it.
    #[serde(default)]
    pub session_id: Option<String>,
}

/// Parameters for `server_log`.
#[derive(Deserialize, JsonSchema)]
pub struct LogArgs {
    /// Only records about this session — what its engine worker logged. The supervisor's own
    /// records about that session (spawning its worker, timing a call out) carry no session id
    /// and are excluded, so omit this when tracing a session that failed to *open*.
    #[serde(default)]
    pub session_id: Option<String>,
    /// The least severe level to include; more severe records are always included. Defaults to
    /// `info`, which is what the server logs unless `RUST_LOG` says otherwise — asking for
    /// `debug` or `trace` on a server started without them returns nothing, because records
    /// below the filter are never made in the first place.
    #[serde(default)]
    pub level: Option<crate::logbridge::Level>,
    /// How many records to return, most recent last. Defaults to 50, capped at 500.
    #[serde(default)]
    pub limit: Option<u32>,
    /// Return only records filed after this point — pass back the `next_since` from the previous
    /// call to see what has happened since, without re-reading what you already have.
    #[serde(default)]
    pub since: Option<u64>,
}

/// Parameters for `modules`.
#[derive(Deserialize, JsonSchema)]
pub struct ModulesArgs {
    /// List only the modules whose name matches this pattern, instead of the whole table —
    /// `"MessageManager"` for one driver's load base. Matched against the name symbols are
    /// qualified by (`nt`, not `ntkrnlmp.exe`), case-insensitively; an unloaded module has no such
    /// name, so those are matched by their image (`nvhda64v.sys`). A plain name matches anywhere
    /// in a module name, so `"nt"` also finds `ntfs` and `WinNT`. `*` (any run of characters) and
    /// `?` (exactly one) are wildcards and a pattern using them is matched as written, so `"nt*"`
    /// is the names that *start* with `nt`, and `"*"` is every module. Those two are the whole
    /// grammar: **every other character is literal**, including the rest of WinDbg's wildcard
    /// syntax (`[fd]`, `#`, `+`, `\`), so `"nt[fd]*"` matches a module actually called that and
    /// otherwise nothing — run `execute { "command": "lm m <pattern>" }` for the engine's own
    /// matcher.
    #[serde(default)]
    pub filter: Option<String>,
    /// Session handle returned by open_dump/open_trace/attach_*/launch. Optional: omit it
    /// to act on whatever session is current, or pass it to have the call refuse to run if
    /// this server's debug target has been replaced since you opened it.
    #[serde(default)]
    pub session_id: Option<String>,
}

/// Parameters for `registers`.
#[derive(Deserialize, JsonSchema)]
pub struct RegistersArgs {
    /// Include every register the engine knows, not just the integer ones: x87 and vector
    /// registers, and subregister views such as `eax` within `rax`. Off by default because on
    /// x64 that is several hundred entries — the `r` text is unaffected either way.
    #[serde(default)]
    pub all: Option<bool>,
    /// Session handle returned by open_dump/open_trace/attach_*/launch. Optional: omit it
    /// to act on whatever session is current, or pass it to have the call refuse to run if
    /// this server's debug target has been replaced since you opened it.
    #[serde(default)]
    pub session_id: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct PathArgs {
    /// Filesystem path to the dump (.dmp) or TTD trace (.run) file.
    pub path: String,
}

/// `attach_kernel`'s target, named one of two ways. Exactly one is required, and that is checked
/// at runtime rather than in the schema — see [`crate::kdconn::select`] for why.
#[derive(Deserialize, JsonSchema)]
pub struct ConnectionArgs {
    /// Raw kernel debugging connection string, e.g. "net:port=50000,key=<w.x.y.z>". Pass exactly
    /// one of `connection` or `profile`. This puts the target's KDNET key in this request — and
    /// so into whatever transcript the client keeps — so prefer `profile` when the host has one
    /// configured. Never invent a key: ask the user for the string, or for a profile name.
    #[serde(default)]
    pub connection: Option<String>,
    /// Name of a kernel connection configured on this host, e.g. "ctf-vm", which this server
    /// resolves locally so the key never appears in this request. Pass exactly one of
    /// `connection` or `profile`. A wrong or absent name is answered with the names that do
    /// exist, so guessing costs one call rather than a leaked key.
    #[serde(default)]
    pub profile: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct PidArgs {
    /// Process ID to attach to.
    pub pid: u32,
}

#[derive(Deserialize, JsonSchema)]
pub struct CommandLineArgs {
    /// Full command line of the program to launch under the debugger.
    pub command_line: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct ExecuteArgs {
    /// Raw debugger command to run (e.g. "!analyze -v", "u rip", "dt nt!_EPROCESS").
    pub command: String,
    /// Session handle from open_dump/open_trace/attach_*/launch. Optional; pass it to
    /// refuse the call if this server's debug target has been replaced since you opened it.
    #[serde(default)]
    pub session_id: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct ReadMemoryArgs {
    /// Virtual address (decimal or 0x-hex).
    pub address: String,
    /// Number of bytes to read.
    pub size: u32,
    /// Session handle from open_dump/open_trace/attach_*/launch. Optional; pass it to
    /// refuse the call if this server's debug target has been replaced since you opened it.
    #[serde(default)]
    pub session_id: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct WalkMemoryArgs {
    /// Walk these addresses exactly, in this order. The bulk read: pass the pointers you already
    /// have and get a value for each, with the unreadable ones marked instead of ending the walk.
    /// Each is decimal, "0x"-hex, or the debugger's backtick form ("ffffc00f`6ec02f90"); a bare
    /// run of 8+ hex digits is read as hex. Mutually exclusive with `start`.
    #[serde(default)]
    pub addresses: Option<Vec<String>>,
    /// Where an array or a chain starts. An address, or any expression `?` evaluates — a symbol
    /// ("MessageManager!g_Table"), an offset from one, or "poi(<head>)" when the list head is a
    /// link rather than a node. Needs `stride` or `next_offset` beside it.
    #[serde(default)]
    pub start: Option<String>,
    /// Array mode: bytes from one element to the next. Negative walks downwards.
    #[serde(default)]
    pub stride: Option<i64>,
    /// Chain mode: byte offset within a node of the pointer to the next node (0 for a
    /// `_LIST_ENTRY.Flink` at the top of the structure).
    #[serde(default)]
    pub next_offset: Option<i64>,
    /// Most nodes to walk (default 64, max 1024). Not for `addresses`, which is its own count.
    #[serde(default)]
    pub count: Option<u32>,
    /// Values to read out of each node. Omit for one pointer at offset 0 — or, for a chain,
    /// nothing beyond the links it already reports.
    #[serde(default)]
    pub fields: Option<Vec<walk::FieldArg>>,
    /// Session handle from open_dump/open_trace/attach_*/launch. Optional; pass it to
    /// refuse the call if this server's debug target has been replaced since you opened it.
    #[serde(default)]
    pub session_id: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct DisassembleArgs {
    /// Address or symbol to disassemble at; uses the current instruction pointer if omitted.
    #[serde(default)]
    pub address: Option<String>,
    /// Session handle from open_dump/open_trace/attach_*/launch. Optional; pass it to
    /// refuse the call if this server's debug target has been replaced since you opened it.
    #[serde(default)]
    pub session_id: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct DxArgs {
    /// Data-model (LINQ) expression, e.g. "@$cursession.TTD.Calls(\"ntdll!*\")".
    pub expression: String,
    /// Session handle from open_dump/open_trace/attach_*/launch. Optional; pass it to
    /// refuse the call if this server's debug target has been replaced since you opened it.
    #[serde(default)]
    pub session_id: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct BreakpointArgs {
    /// Breakpoint location: symbol, address, or expression (e.g. "nt!NtCreateFile").
    pub expression: String,
    /// Session handle from open_dump/open_trace/attach_*/launch. Optional; pass it to
    /// refuse the call if this server's debug target has been replaced since you opened it.
    #[serde(default)]
    pub session_id: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct PositionArgs {
    /// TTD position to travel to, e.g. "12:0" or "0" for the start of the trace.
    pub position: String,
    /// Session handle from open_dump/open_trace/attach_*/launch. Optional; pass it to
    /// refuse the call if this server's debug target has been replaced since you opened it.
    #[serde(default)]
    pub session_id: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct RecordArgs {
    /// Directory to write the .run/.idx trace files into.
    pub out_dir: String,
    /// Program (with optional arguments) to launch and record.
    pub target: String,
    /// Extra environment variables for the recorded target, each as "KEY=VALUE".
    /// Useful when the target refuses to run without a specific environment (e.g. a Qt
    /// app that needs `QT_QPA_PLATFORM_PLUGIN_PATH`, or an anti-analysis env guard).
    #[serde(default)]
    pub env: Vec<String>,
    /// Working directory for the recorded target (defaults to TTD.exe's cwd). Set this
    /// when the target loads resources relative to its own directory.
    #[serde(default)]
    pub working_dir: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct TtdCallsArgs {
    /// Function symbol or wildcard pattern to find calls to, e.g.
    /// "kernelbase!CreateFileW" or "ntdll!Nt*".
    pub function: String,
    /// Session handle from open_dump/open_trace/attach_*/launch. Optional; pass it to
    /// refuse the call if this server's debug target has been replaced since you opened it.
    #[serde(default)]
    pub session_id: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct TtdMemoryArgs {
    /// Start virtual address of the range to watch (decimal or 0x-hex).
    pub address: String,
    /// Number of bytes in the range.
    pub size: u32,
    /// Optional access filter: any combination of r(ead), w(rite), e/c(execute).
    /// Omit to report every access.
    #[serde(default)]
    pub mode: Option<String>,
    /// Session handle from open_dump/open_trace/attach_*/launch. Optional; pass it to
    /// refuse the call if this server's debug target has been replaced since you opened it.
    #[serde(default)]
    pub session_id: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct DecodeIoctlArgs {
    /// 32-bit IOCTL control code (decimal or 0x-hex), e.g. "0x70000".
    pub code: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct SymbolPathArgs {
    /// Symbol search path to apply: a directory holding a module's PDB, a
    /// `srv*downstream*server` spec, or a `;`-separated list. Point it at the folder
    /// whose PDB matches the module's PDB GUID so `module!Symbol` names resolve. Must be
    /// reachable from THIS (debugger) host — symbols are not pulled from the target over
    /// the KD wire.
    pub path: String,
    /// Append to the existing path (default true) rather than replacing it. Appending
    /// keeps the OS/`nt` symbol server already configured.
    #[serde(default)]
    pub append: Option<bool>,
    /// Optional `.reload` argument applied after setting the path, e.g. "/f HEVD.sys" to
    /// force-load one module's symbols. Omit to reload all deferred modules.
    #[serde(default)]
    pub reload: Option<String>,
    /// Session handle from open_dump/open_trace/attach_*/launch. Optional; pass it to
    /// refuse the call if this server's debug target has been replaced since you opened it.
    #[serde(default)]
    pub session_id: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct PoolFindTagArgs {
    /// Pool tag to find: 1..4 ASCII bytes, e.g. "Tgsm". This is the tag as the debugger
    /// *displays* it — the tag bytes in memory order. A driver whose source passes the C
    /// literal 'msgT' therefore appears here as "Tgsm", not "msgT".
    pub tag: String,
    /// Restrict to one allocator: true = paged only, false = nonpaged only. Omit for both.
    #[serde(default)]
    pub paged: Option<bool>,
    /// Force a fresh walk instead of reusing this session's cached snapshot (default false).
    /// Walking every pool page is expensive, so a snapshot is cached and reused; pass this
    /// after letting the target run, when the cached view describes a target that has moved.
    #[serde(default)]
    pub refresh: Option<bool>,
    /// Maximum rows to print (default 64).
    #[serde(default)]
    pub limit: Option<u32>,
    /// Session handle from open_dump/open_trace/attach_*/launch. Optional; pass it to
    /// refuse the call if this server's debug target has been replaced since you opened it.
    #[serde(default)]
    pub session_id: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct PoolChunkArgs {
    /// Address to locate, in any form the debugger prints or accepts: a backtick address
    /// ("ffffc00f`6ec02f90"), a bare hex run, "0x"-hex, or decimal. A bare run of 8+ hex
    /// digits is read as hex, following WinDbg's convention.
    pub address: String,
    /// Force a fresh walk instead of reusing this session's cached snapshot (default false).
    #[serde(default)]
    pub refresh: Option<bool>,
    /// Session handle from open_dump/open_trace/attach_*/launch. Optional; pass it to
    /// refuse the call if this server's debug target has been replaced since you opened it.
    #[serde(default)]
    pub session_id: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct PoolCensusArgs {
    /// Force a fresh walk instead of reusing this session's cached snapshot (default false).
    #[serde(default)]
    pub refresh: Option<bool>,
    /// Maximum tags to print (default 40).
    #[serde(default)]
    pub limit: Option<u32>,
    /// Session handle from open_dump/open_trace/attach_*/launch. Optional; pass it to
    /// refuse the call if this server's debug target has been replaced since you opened it.
    #[serde(default)]
    pub session_id: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct PoolDiagnosticsArgs {
    /// Case-insensitive substring to narrow the diagnostics to, e.g. a heap address
    /// ("ffff8c8f0d300000") or a phrase ("cannot fully discover heap"). Omit for all.
    #[serde(default)]
    pub filter: Option<String>,
    /// Maximum lines to print (default 60).
    #[serde(default)]
    pub limit: Option<u32>,
    /// Force a fresh walk instead of reusing this session's cached snapshot (default false).
    #[serde(default)]
    pub refresh: Option<bool>,
    /// Session handle from open_dump/open_trace/attach_*/launch. Optional; pass it to
    /// refuse the call if this server's debug target has been replaced since you opened it.
    #[serde(default)]
    pub session_id: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct HeapListArgs {
    /// Force a fresh snapshot instead of reusing the one cached for this stopped target.
    #[serde(default)]
    pub refresh: Option<bool>,
    #[serde(default)]
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HeapBackendArg {
    Lfh,
    Vs,
    Segment,
    Large,
}

#[derive(Debug, Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HeapStateArg {
    Allocated,
    ReusableFree,
    CachedFree,
    Unreadable,
}

#[derive(Deserialize, JsonSchema)]
pub struct HeapAllocationsArgs {
    /// Optional Segment Heap root address.
    #[serde(default)]
    pub heap: Option<String>,
    #[serde(default)]
    pub backend: Option<HeapBackendArg>,
    /// Defaults to `allocated`.
    #[serde(default)]
    pub state: Option<HeapStateArg>,
    #[serde(default)]
    pub min_capacity: Option<u64>,
    #[serde(default)]
    pub max_capacity: Option<u64>,
    #[serde(default)]
    pub refresh: Option<bool>,
    /// Maximum rows to return (default 64, maximum 2000).
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(default)]
    pub session_id: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct HeapChunkArgs {
    /// Address anywhere in the allocator header or user capacity.
    pub address: String,
    #[serde(default)]
    pub refresh: Option<bool>,
    #[serde(default)]
    pub session_id: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct HeapCensusArgs {
    /// Optional Segment Heap root address.
    #[serde(default)]
    pub heap: Option<String>,
    #[serde(default)]
    pub refresh: Option<bool>,
    /// Maximum groups to return (default 40, maximum 2000).
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(default)]
    pub session_id: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct HeapDiagnosticsArgs {
    /// Optional Segment Heap root address.
    #[serde(default)]
    pub heap: Option<String>,
    /// Case-insensitive substring applied to diagnostic categories and kept examples.
    #[serde(default)]
    pub filter: Option<String>,
    #[serde(default)]
    pub refresh: Option<bool>,
    /// Maximum rows to return (default 60, maximum 2000).
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(default)]
    pub session_id: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct CrashTriageArgs {
    /// How many stack frames to walk (default 16, maximum 128). The default reaches past the
    /// kernel's own bug-check path to the driver frame on every crash seen so far; raise it for a
    /// deep stack where it does not.
    #[serde(default)]
    pub frames: Option<u32>,
    /// Run `!analyze -v` and report its conclusions beside the engine's values (default true).
    /// It is what supplies the pool tag, the failure bucket and the per-parameter explanations,
    /// and it is also the slow part — set false for a fast answer of code, parameters and frames.
    /// It is also what re-selects the faulting context on the bug checks that carry one, so with
    /// false the stack is whichever context the session currently has selected — the same one
    /// `backtrace` would print. On a freshly opened dump those are the same thing; on a session
    /// where the context has been moved (`.thread`, `~Ns`, `.cxr`) they are not.
    #[serde(default)]
    pub analyze: Option<bool>,
    /// Session handle from open_dump/open_trace/attach_*/launch. Optional; pass it to
    /// refuse the call if this server's debug target has been replaced since you opened it.
    #[serde(default)]
    pub session_id: Option<String>,
}

/// The most frames `crash_triage` will walk, and its default.
///
/// The cap is not about cost — a stack walk is cheap — but about the answer staying readable: a
/// triage is a summary, and a caller who wants the whole stack of a 200-frame recursion wants
/// `backtrace`. The default is deep enough to clear the kernel's bug-check preamble (`KeBugCheckEx`
/// over `KiBugCheckDispatch` over a fault handler over the allocator) and reach the driver.
const MAX_TRIAGE_FRAMES: u32 = 128;
const DEFAULT_TRIAGE_FRAMES: u32 = 16;

#[derive(Deserialize, JsonSchema)]
pub struct BacktraceArgs {
    /// How many frames to walk (default 32, maximum 256).
    #[serde(default)]
    pub frames: Option<u32>,
    /// Session handle from open_dump/open_trace/attach_*/launch. Optional; pass it to
    /// refuse the call if this server's debug target has been replaced since you opened it.
    #[serde(default)]
    pub session_id: Option<String>,
}

/// The most frames `backtrace` will walk, and its default.
///
/// Twice `crash_triage`'s, because this is the tool that answers "the whole stack" — a triage is a
/// summary, and its own cap comment points here for the 200-frame recursion. A cap at all is new:
/// `k` printed whatever the stack was. It is here because the frames are now *values*, and an
/// uncapped typed answer is an uncapped bill for whoever is reading it — the same reason every
/// other high-volume tool has one. `frames_truncated` is what keeps the cap honest, so a caller
/// who needs more knows to ask rather than reading a truncated stack as a short one.
const MAX_BACKTRACE_FRAMES: u32 = 256;
const DEFAULT_BACKTRACE_FRAMES: u32 = 32;

#[derive(Deserialize, JsonSchema)]
pub struct DriverObjectArgs {
    /// Driver object name, e.g. "mydriver" or "\\Driver\\mydriver".
    pub name: String,
    /// Session handle from open_dump/open_trace/attach_*/launch. Optional; pass it to
    /// refuse the call if this server's debug target has been replaced since you opened it.
    #[serde(default)]
    pub session_id: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct DeviceObjectArgs {
    /// Device object: a name (e.g. "\\Device\\MyDevice") or an address (0x-hex).
    pub device: String,
    /// Session handle from open_dump/open_trace/attach_*/launch. Optional; pass it to
    /// refuse the call if this server's debug target has been replaced since you opened it.
    #[serde(default)]
    pub session_id: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct IrpStackArgs {
    /// IRP address (decimal or 0x-hex). Defaults to `@rdx` — the PIRP passed to the
    /// dispatch routine on x64, valid only at the dispatch *entry*, before any step
    /// clobbers the register.
    #[serde(default)]
    pub irp: Option<String>,
    /// Session handle from open_dump/open_trace/attach_*/launch. Optional; pass it to
    /// refuse the call if this server's debug target has been replaced since you opened it.
    #[serde(default)]
    pub session_id: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct IoctlTraceArgs {
    /// Virtual address of the IRP_MJ_DEVICE_CONTROL dispatch routine, rebased to the
    /// live load base. Recover it via `driver_object` (MajorFunction[0x0e]).
    pub dispatch: String,
    /// Session handle from open_dump/open_trace/attach_*/launch. Optional; pass it to
    /// refuse the call if this server's debug target has been replaced since you opened it.
    #[serde(default)]
    pub session_id: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct ReachabilityArgs {
    /// Start of the search: the IRP_MJ_DEVICE_CONTROL dispatch routine — a symbol,
    /// address, or expression `uf` accepts (e.g. "mydriver!DispatchDeviceControl" or
    /// "fffff8033e254750"). Recover it via `driver_object` (MajorFunction[0x0e]). Pass
    /// a specific handler VA instead to scope the walk past a jump-table switch.
    pub from: String,
    /// Target code block as an absolute virtual address, in any WinDbg form — a bare
    /// value is hex (e.g. "fffff803`3e254750" or "00401234"), and "0x"-hex or a symbol
    /// also work. Provide this OR `module`+`rva`, not both.
    #[serde(default)]
    pub address: Option<String>,
    /// Module name for a module+RVA target, e.g. "mydriver". Its live base is read from
    /// `lm m <module>` and added to `rva`. Required (with `rva`) when `address` is omitted.
    #[serde(default)]
    pub module: Option<String>,
    /// Relative virtual address added to `module`'s live base, in WinDbg form (a bare
    /// value is hex; "0x"-hex also works).
    #[serde(default)]
    pub rva: Option<String>,
    /// Max distinct functions to disassemble before giving up (default 256). Bounds runtime.
    #[serde(default)]
    pub max_functions: Option<usize>,
    /// Max call-graph depth to explore from `from` (default 32).
    #[serde(default)]
    pub max_depth: Option<usize>,
    /// Emit a "Path recipe" on a REACHABLE verdict: the on-path branch directions and a
    /// best-effort decode of the compares that gate them (default true). Set false for
    /// the bare verdict + call path.
    #[serde(default)]
    pub recipe: Option<bool>,
    /// Session handle from open_dump/open_trace/attach_*/launch. Optional; pass it to
    /// refuse the call if this server's debug target has been replaced since you opened it.
    #[serde(default)]
    pub session_id: Option<String>,
}

/// Address to run the target to, for `run_to_address`.
#[derive(Deserialize, JsonSchema)]
pub struct RunToAddressArgs {
    /// Address, symbol, or expression to run until (any WinDbg form — a bare value is
    /// hex, "0x"-hex and symbols also work). Typically a block from `reachable_from_dispatch`.
    pub address: String,
    /// How long to wait for the target to reach `address` before reporting a timeout
    /// (milliseconds). Defaults to the standard execution wait.
    #[serde(default)]
    pub timeout_ms: Option<u32>,
    /// Session handle from open_dump/open_trace/attach_*/launch. Optional; pass it to
    /// refuse the call if this server's debug target has been replaced since you opened it.
    #[serde(default)]
    pub session_id: Option<String>,
}

/// A whole debugger transaction, for `debug_batch`.
///
/// The one argument struct in this server that refuses unknown fields, and it is not fussiness:
/// serde drops them silently, so `"aways"` for `always` would be accepted as a batch with **no
/// rollback block** — mutations applied, nothing restored, and a `COMMITTED` verdict saying so.
/// Every other tool's typo costs a wrong answer; this one's costs the target.
#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DebugBatchArgs {
    /// The steps to run, in order. Each is one flat object with an `op` field:
    /// `{"op": "command", "command": "bp nt!NtCreateFile"}` runs a raw command;
    /// `{"op": "resume", "command": "g"}` moves the target and waits for the next stop;
    /// `{"op": "run_to", "address": "hevd!Trigger"}` reports a HIT/STOPPED ELSEWHERE/TIMEOUT
    /// verdict; `{"op": "eval", "expr": "@rcx"}` reads a value; `{"op": "read_memory",
    /// "address": "0xfffff8000012c000", "size": 64}` hex-dumps memory — this one takes a *number*
    /// (decimal or `0x`-hex), not an expression, so for `@rsp` or `poi(...)` put an `eval` step in
    /// front of it and read the capture. Three more ask the kernel pool the same questions the
    /// `pool_*` tools do, because those are allocator walks rather than debugger commands and no
    /// `command` step can stand in for them: `{"op": "pool_chunk", "address": "{{obj}}"}`,
    /// `{"op": "pool_find_tag", "tag": "Tgsm", "paged": false}` and `{"op": "pool_census"}`, each
    /// taking `refresh` (re-walk rather than reuse this session's snapshot) and the last two a
    /// `limit`. Add `"expect"` to assert on the result and `"capture"`
    /// (on an `eval` step) to bind its value for later steps as `{{name}}`.
    /// The batch stops at the first step that fails or whose assertions do not hold.
    pub steps: Vec<batch::BatchStep>,
    /// Cleanup/rollback steps, same shape as `steps`. They run **on every path** — success, a
    /// debugger error, an assertion that did not hold, or the deadline expiring — inside the
    /// engine process, before this call returns. This is where an unpatch, a `bc *`, or a
    /// re-`go` belongs: a client cannot be relied on to send it after a call that timed out.
    /// Their failures are reported separately and never replace the batch's own outcome.
    #[serde(default)]
    pub always: Vec<batch::BatchStep>,
    /// Deadline for the whole batch in milliseconds (default 120000). Part of it is reserved for
    /// `always`, so a rollback still runs when the steps use the clock up. Clamped down to what
    /// is left of this call's budget — it can only make the batch shorter, never longer.
    #[serde(default)]
    pub timeout_ms: Option<u32>,
    /// Session handle from open_dump/open_trace/attach_*/launch. Optional; pass it to
    /// refuse the call if this server's debug target has been replaced since you opened it.
    #[serde(default)]
    pub session_id: Option<String>,
}

// ---- Session handles -----------------------------------------------------
//
// An MCP connection is explicitly *not* a session: clients may interleave unrelated requests
// over the same stdio process, so "the target the last open_* call attached to" is not a safe
// thing for a tool to assume. The session-creating tools therefore mint a handle, and every tool
// that touches a target accepts it.
//
// What the handle *does* changed with process-per-session. It used to be a tripwire: one engine,
// one target, and the handle existed so a call could notice that the target had been replaced
// underneath it. Now it **routes** — it names the worker process that holds that target — and the
// class of accident it guarded against mostly cannot happen any more, because opening a second
// target no longer disturbs the first. See [`crate::engine`].
//
// It is still optional, and omitting it still means "whatever session is current" (the newest one
// that will still accept work). What supplying it buys is unchanged: a call that names a session
// can never land on a target the caller did not open.
//
// Two seams remain, and both are inside one worker rather than across the server: `execute` and
// `dx` can replace a session's target from underneath its own handle. That retirement is ordered
// against the session's queue — see `engine::Gate` — for the same time-of-check/time-of-use
// reason the old design put the check on the engine thread.

/// Whether an operand may legitimately contain a double quote.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Quotes {
    /// Only `dx`, whose data-model expressions use quoted string literals as a matter of
    /// course (`@$cursession.TTD.Calls("ntdll!Nt*")`).
    Allowed,
    /// Everywhere else. A quote either escapes a string literal this server wrapped around
    /// the operand, or — for a `bp` location — opens a *breakpoint command string*, which
    /// WinDbg runs every time the breakpoint fires. `ioctl_trace` builds exactly that form
    /// deliberately, so `set_breakpoint { expression: "nt!Foo \".opendump other.dmp\"" }`
    /// would arm a target swap that happens later: outside any tool call, and outside
    /// anything that could retire the session handle. A quote has no legitimate meaning in
    /// an address, a symbol, a device name or a TTD position, so refusing it costs nothing.
    Rejected,
}

/// Rejects a caller-supplied operand that could end the command it is embedded in.
///
/// The typed tools build commands by interpolation — `u {address}`, `bp {expression}`,
/// `!drvobj {name} 7` — and DbgEng reads `;` as a command separator. So an operand of
/// `rip; .opendump C:\other.dmp` turns `disassemble` into a target swap: it runs a
/// session-control command from a tool that advertises `readOnlyHint: true`, and it does
/// it without going through the [`changes_debug_target`] check, leaving every outstanding
/// handle pointing at a target that is no longer loaded.
///
/// These parameters are documented as *operands*, never command lists, so refusing the
/// separator costs nothing real: `execute` exists for anything that genuinely needs to
/// chain, and it is annotated and handle-checked accordingly.
///
/// Quotes are refused everywhere except `dx` — see [`Quotes`] for why a quote is never a
/// legitimate part of an address, symbol, device name or breakpoint location.
pub(crate) fn reject_command_breakers(
    field: &str,
    value: &str,
    quotes: Quotes,
) -> Result<(), String> {
    let bad = value
        .chars()
        .find(|c| matches!(c, ';' | '\n' | '\r') || (quotes == Quotes::Rejected && *c == '"'));
    let Some(bad) = bad else {
        return Ok(());
    };
    let what = match bad {
        ';' => "a `;`",
        '"' => "a `\"`",
        _ => "a line break",
    };
    Err(format!(
        "`{field}` contains {what}, which would end the command this tool builds around it \
         and let the rest run as a separate command. This parameter takes a single operand. \
         Use `execute` if you meant to run a command list — it is annotated as destructive \
         and retires the session handle when a command replaces the target."
    ))
}

/// The failure message for a transition that fell *after* its commit: the target is open,
/// so the error has to carry the handle rather than swallow it.
///
/// Free function so it tests without an engine, as `OpenSideEffect::failure_caveat` did
/// before the openers were split (glslang/win-kexp#71). What it encodes is the distinction
/// that split bought — this text must be unreachable for a failure that created nothing,
/// because telling a caller "your session exists" when it does not strands them exactly as
/// badly as the advice it replaced.
fn post_commit_failure(err: &str, session_id: &str) -> String {
    format!(
        "{err}\n\nsession_id: {session_id}\nThis failure came *after* the target was opened, \
         so the handle above names a session that exists — what failed is the wait for it to \
         become ready. Do not open again to recover: for launch or attach, doing so would \
         start a second process or attach a second time. Inspect it (`execute \
         {{ \"command\": \"vertarget\" }}`) or `end_session` first."
    )
}

/// Renders a duration the way a person reads one: "8.4s", "3m12s", "1h05m".
///
/// Shared with [`crate::progress`], which is telling a client about the same waits `session_status`
/// describes here — a heartbeat that spelled its elapsed time differently would read as a second,
/// unrelated clock.
pub(crate) fn fmt_duration(d: Duration) -> String {
    let secs = d.as_secs();
    match secs {
        0..=59 => format!("{:.1}s", d.as_secs_f64()),
        60..=3599 => format!("{}m{:02}s", secs / 60, secs % 60),
        _ => format!("{}h{:02}m", secs / 3600, (secs % 3600) / 60),
    }
}

/// One session, as `session_status` reports it.
///
/// The interesting line is the one for an open that has not landed. `Attaching` means the target
/// has been *claimed* — the dump handed over, the connection taken — and the debugger is waiting
/// for it to break in. For a live kernel that wait is `WaitForEvent(INFINITE)` and nothing can
/// interrupt it, so the state itself cannot say whether the link is about to come up or the guest
/// was never booted in debug mode. **How long it has been waiting can**, which is why the
/// duration is not decoration here: past [`OPEN_TAKING_TOO_LONG`] the report stops calling it
/// normal and names the recovery, because the two cases need opposite responses.
///
/// Free function so the wording tests without a debugger.
fn describe_session(s: &SessionSnapshot) -> String {
    let current = if s.current { " (current)" } else { "" };
    let mut out = format!(
        "{}{current} — {}: {}  [engine pid {}, opened {} ago]\n",
        s.id,
        s.kind.label(),
        s.what,
        s.pid,
        fmt_duration(s.age)
    );
    let waited = fmt_duration(s.in_state_for);
    match &s.state {
        SessionState::Opening => {
            out.push_str(&format!(
                "  opening for {waited}. Nothing has been created or claimed yet, so a failure \
                 from here would leave a clean slate.\n"
            ));
        }
        SessionState::Attaching => {
            out.push_str(&format!(
                "  the target has been created or claimed, and the debugger has been waiting \
                 {waited} for it to break in. Do not re-run the open — that would attach to, or \
                 start, a second target.\n"
            ));
            if s.kind.waits_indefinitely() {
                if s.in_state_for >= OPEN_TAKING_TOO_LONG {
                    out.push_str(&format!(
                        "  [!] That is far longer than a healthy kernel attach takes (a KDNET \
                         link that is coming up resyncs in ~25s), and this wait has no timeout \
                         and cannot be interrupted — it will not return on its own. The usual \
                         causes are a guest that is powered off, not booted with debugging \
                         enabled, or pointed at a different host/port/key. Fix the target and it \
                         will still connect; otherwise reclaim the session with `end_session \
                         {{ \"session_id\": \"{}\" }}`, which terminates its engine process. \
                         Nothing else on this server is affected in the meantime.\n",
                        s.id
                    ));
                } else {
                    out.push_str(
                        "  A kernel attach waits for the target to dial in, so this is normal \
                         while the link comes up (~25s for a KDNET resync). Ask again shortly.\n",
                    );
                }
            }
        }
        SessionState::Open => out.push_str(&format!("  open for {waited}; ready for work.\n")),
        SessionState::Failed(why) => out.push_str(&format!(
            "  failed {waited} ago and never opened:\n    {why}\n  Nothing was created, so \
             opening again is the way forward.\n"
        )),
        SessionState::Retired(why) => out.push_str(&format!(
            "  the handle was retired {waited} ago: {why}. The engine process still holds a \
             target, but not the one this handle names — calls that pass `session_id` are \
             refused, calls that omit it still reach it.\n"
        )),
        SessionState::Closed(why) => out.push_str(&format!("  closed {waited} ago: {why}\n")),
    }
    out
}

/// Can this data-model expression run debugger commands?
///
/// `dx` evaluates arbitrary data-model expressions, and the data model exposes
/// `Debugger.Utility.Control.ExecuteCommand`, which runs any command string — `.opendump`
/// included. So `dx` is a second command hatch beside `execute`, and has to be treated as
/// one. Where [`changes_debug_target`] can read the command and decide, this cannot: the
/// command is a runtime string inside an expression. So the trigger is *reaching command
/// execution at all*, and the handle is retired without knowing what ran.
///
/// Best-effort for a stronger reason than [`changes_debug_target`]: the data model is
/// extensible, so no fixed list can enumerate every route to execution. `dx` and `execute`
/// are therefore both documented as surfaces where a handle is a strong hint, not a
/// guarantee — everywhere else in this server it is a guarantee.
fn dx_executes_commands(expression: &str) -> bool {
    expression.to_ascii_lowercase().contains("executecommand")
}

/// Does this raw `execute` command replace or release the debug target?
///
/// The typed tools announce their own transitions, but `execute` is an escape hatch: a
/// caller can `.opendump` a different file, or `.detach`, and every handle issued for the
/// old target is then meaningless. Matching the first token of each segment catches the
/// session-control commands by name.
///
/// Segments are split on `;` **and line breaks**, because DbgEng treats both as command
/// boundaries — [`reject_command_breakers`] refuses both in typed operands for exactly that
/// reason, and a scanner that honoured only `;` would let `r\n.opendump other.dmp` through
/// while seeing nothing but `r`.
///
/// This is deliberately **best-effort, biased toward retiring the handle**. Over-matching
/// costs a caller one re-open; under-matching would let a stale handle pass, which is the
/// failure this mechanism exists to prevent. It cannot be exhaustive — DbgEng has more ways
/// to reach the target than a name list can enumerate — so `execute` remains the one place
/// where a handle is a strong hint rather than a guarantee.
pub(crate) fn changes_debug_target(command: &str) -> bool {
    /// Session-control commands: open, attach to, release, or terminate a target.
    const RETIRES_SESSION: &[&str] = &[
        ".opendump",
        ".attach",
        ".detach",
        ".kill",
        ".restart",
        ".create",
        ".abandon",
        ".remote",
        "q",
        "qd",
        "qq",
    ];
    command.split([';', '\n', '\r']).any(|segment| {
        segment
            .split_whitespace()
            .next()
            .is_some_and(|first| RETIRES_SESSION.contains(&first.to_ascii_lowercase().as_str()))
    })
}

impl WindbgServer {
    /// Routes a call to the session the caller named — or to the current one — and runs it.
    ///
    /// Resolution happens here, on the async side, because under process-per-session it is a
    /// *routing* decision and routing cannot race: an open for another target creates its own
    /// worker and cannot be ordered against this call at all. What still has to be re-checked
    /// at the front of the session's own queue is whether the handle survived work queued ahead
    /// of it, and that is `engine::Gate`'s job.
    async fn run_call(&self, session_id: Option<&str>, call: Call) -> Result<Output, EngineError> {
        let session = self.sessions.resolve(session_id)?;
        self.sessions
            .call(&session, call.named(session_id.is_some()))
            .await
    }

    /// The common case: one op, no handle retirement.
    async fn run(&self, session_id: Option<&str>, op: EngineOp) -> Result<Output, EngineError> {
        self.run_call(session_id, Call::new(op)).await
    }

    /// Opens a target in a session of its own and renders the outcome.
    ///
    /// Every failure mode here needs different advice, and getting it wrong is expensive — "open
    /// again" after a launch that already spawned means two processes. [`OpenError`] carries
    /// which one happened; the worker's milestones are what let the supervisor tell them apart
    /// (see [`crate::proto::WorkerMessage`]).
    async fn opened(
        &self,
        kind: SessionKind,
        what: String,
        op: EngineOp,
    ) -> Result<CallToolResult, ErrorData> {
        // Kept for the typed answer, which describes what was asked for rather than re-deriving
        // it from the report the debugger printed.
        let target = what.clone();
        let outcome = self.sessions.open(kind, what, op).await;
        // An opener does not route to a session, it *mints* one — and the transcript wants the
        // same field filled in either way, so the call that created a target can be joined to the
        // events about it.
        //
        // From **every** outcome that carries an id, not only the successful one. The two that
        // fail with a handle are the ones a reader most needs joined up: `PostCommit` left a
        // target open, and `Timeout` left an open that may still land — both are recovery cases
        // where the next question is "what happened to that session?", and the answer is in the
        // events this field is what links to.
        if let Some(id) = opened_session(&outcome) {
            crate::record::routed_to(id);
        }
        match outcome {
            Ok(OpenReport {
                id,
                report,
                summary,
            }) => outcome_result(
                format!(
                    "{report}\n\nsession_id: {id}\nPass this as `session_id` on later calls \
                         to route them to this session and to fail loudly rather than act on a \
                         different target."
                ),
                structured::OpenOutcome::Ok(structured::OpenedSession {
                    session_id: id,
                    kind: kind.into(),
                    target,
                    report,
                    summary,
                }),
            ),
            // No worker, so no session — and no argument the model can change fixes that.
            Err(OpenError::Unavailable(m)) => Err(ErrorData::internal_error(m, None)),
            Err(OpenError::NoRoom(m)) => {
                open_failure(ErrorCategory::Capacity, m, None, TargetCreated::No)
            }
            Err(OpenError::Clean(m)) => {
                open_failure(ErrorCategory::Debugger, m, None, TargetCreated::No)
            }
            Err(OpenError::PostCommit {
                id,
                message,
                report_only,
            }) => open_failure(
                ErrorCategory::Debugger,
                if report_only {
                    format!(
                        "{message}\n\nsession_id: {id}\nThe target opened; only this follow-up \
                         report failed, so the handle above is valid and usable."
                    )
                } else {
                    post_commit_failure(&message, &id)
                },
                Some(id),
                // Both halves of this branch created a target; that is what "post commit" means,
                // and it is the fact that makes re-opening the wrong move.
                TargetCreated::Yes,
            ),
            // A timeout abandons the *wait*, not the job: this open may still be running and may
            // still land. The handle exists from the moment the session is registered, so it can
            // be named now — which is what makes recovery via `session_status` sound.
            // The `session_id:` line is the same one a successful open emits, deliberately: this
            // is the result a caller most needs to get a handle *out* of, and prose alone would
            // make it the one opener outcome they cannot parse the id from.
            Err(OpenError::Timeout { id, message }) => open_failure(
                ErrorCategory::Timeout,
                format!(
                    "{message}\n\nsession_id: {id}\nThe wait was abandoned, but this open was \
                     not: it is still running in the session above, and may still land. Ask \
                     `session_status {{ \"session_id\": \"{id}\" }}` — it reports whether the \
                     open is still going, how long it has been going, and whether that is longer \
                     than a healthy one takes. Do not re-run the open while it is still going, \
                     which would attach to, or start, a second target; `end_session \
                     {{ \"session_id\": \"{id}\" }}` ends it outright, terminating the worker \
                     process if it will not unwind."
                ),
                Some(id),
                TargetCreated::Pending,
            ),
        }
    }
}

// ---- Tools ---------------------------------------------------------------
//
// On `open_world_hint`: everything that touches a debug target is open-world, and only
// `decode_ioctl` (pure arithmetic on a control code), `session_status` and `server_log` (reads of
// this server's own state) are not. Two independent reasons put the rest over the line. A symbol server on the symbol
// path (the documented, recommended setup) means almost any command can make DbgEng
// download a PDB, and not only the obvious symbol-pattern queries: `r` symbolizes the
// current instruction, `k` symbolizes every frame, `bp module!Symbol` resolves a name.
// And a session opened over KDNET puts the *target itself* on the far side of a network
// link, so even `read_memory` fetching raw bytes, or `end_session` releasing the target,
// is remote traffic. That leaves `decode_ioctl`, `session_status` and `server_log`, the three
// that never reach the engine at all. Claiming otherwise would tell a client the tool cannot touch
// the network and let it skip whatever consent that decision gates.

#[rmcp::tool_router]
impl WindbgServer {
    pub fn new(sessions: Sessions) -> Self {
        Self {
            rec: sessions.recorder(),
            sessions,
        }
    }

    /// Open a crash dump (.dmp) or a Time Travel Debugging trace (.run) and wait for it to load.
    /// Opens a new session in its own engine process — sessions already open are left alone —
    /// and returns a `session_id` that routes later calls to it. End it with `end_session`.
    /// The result is a summary of the target — build, kernel/primary image base, module count and
    /// the bug check a crash dump stopped on — not its module table, which `modules` lists.
    #[rmcp::tool(
        annotations(
            title = "Open crash dump or TTD trace",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        ),
        output_schema = schema_for_output::<structured::OpenOutcome>()
    )]
    async fn open_dump(
        &self,
        Parameters(args): Parameters<PathArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.opened(
            SessionKind::Dump,
            args.path.clone(),
            EngineOp::OpenDump { path: args.path },
        )
        .await
    }

    /// Open a TTD trace (.run); alias of open_dump. Enables time-travel navigation and TTD queries.
    /// Opens a new session in its own engine process — sessions already open are left alone —
    /// and returns a `session_id` that routes later calls to it. End it with `end_session`.
    #[rmcp::tool(
        annotations(
            title = "Open TTD trace",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        ),
        output_schema = schema_for_output::<structured::OpenOutcome>()
    )]
    async fn open_trace(
        &self,
        Parameters(args): Parameters<PathArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.opened(
            SessionKind::Trace,
            args.path.clone(),
            EngineOp::OpenTrace { path: args.path },
        )
        .await
    }

    /// Attach to the local kernel (live local kernel debugging).
    /// Opens a new session in its own engine process — sessions already open are left alone —
    /// and returns a `session_id` that routes later calls to it. End it with `end_session`.
    #[rmcp::tool(
        annotations(
            title = "Attach to local kernel",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        ),
        output_schema = schema_for_output::<structured::OpenOutcome>()
    )]
    async fn attach_kernel_local(&self) -> Result<CallToolResult, ErrorData> {
        self.opened(
            SessionKind::KernelLocal,
            "local kernel".to_string(),
            EngineOp::AttachKernelLocal,
        )
        .await
    }

    /// Attach to a kernel target over a connection string (e.g. KDNET).
    /// Takes exactly one of `profile` (a connection configured on this host, which the server
    /// resolves locally — the target's debug key never enters this request) or `connection` (the
    /// raw string, key and all). Prefer `profile`; call it with neither to be told which profiles
    /// this host has.
    /// Opens a new session in its own engine process — sessions already open are left alone —
    /// and returns a `session_id` that routes later calls to it.
    /// A live kernel attach waits for the target to dial in, and that wait has no timeout and
    /// cannot be interrupted: if the guest is powered off, not booted with `/debug on`, or
    /// pointed at the wrong host/port/key, this call reports a timeout and the attach keeps
    /// waiting forever. That costs only this session — other sessions and the server are
    /// unaffected — and `session_status` says how long it has been waiting. Recover with
    /// `end_session`, which terminates the session's engine process; do NOT re-attach while it
    /// is still waiting.
    #[rmcp::tool(
        annotations(
            title = "Attach to kernel target",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        ),
        output_schema = schema_for_output::<structured::OpenOutcome>()
    )]
    async fn attach_kernel(
        &self,
        Parameters(args): Parameters<ConnectionArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        // Resolved here, in the supervisor, and *before* a worker exists: a selector the caller
        // has to fix should cost them a message, not a spawned process and a session to end. The
        // label that comes back is already redacted, so the session can describe itself in
        // `session_status` without holding the key anywhere but in the op below.
        let selected = match kdconn::select(args.connection, args.profile) {
            Ok(selected) => selected,
            // Typed like every other refusal from a tool that declares an output schema: the
            // result has to conform whichever way it went, and "fix the argument" is a category.
            Err(why) => {
                return open_failure(ErrorCategory::InvalidArgument, why, None, TargetCreated::No);
            }
        };
        self.opened(
            SessionKind::Kernel,
            selected.label,
            EngineOp::AttachKernel {
                connection: selected.connection,
            },
        )
        .await
    }

    /// Set or extend the symbol search path, then reload symbols, so `module!Symbol`
    /// names resolve. Use it when a driver's PDB isn't on the default path: ask the user
    /// for the folder holding the matching PDB (by GUID) and apply it here. The path must
    /// be reachable from THIS (debugger) host — symbols are not fetched from the target
    /// over the KD wire. Goes through the DbgEng API, so it avoids the `.sympath` command
    /// quirk of swallowing the rest of the command line.
    #[rmcp::tool(annotations(
        title = "Set symbol search path",
        read_only_hint = false,
        destructive_hint = false,
        idempotent_hint = false,
        open_world_hint = true
    ))]
    async fn set_symbol_path(
        &self,
        Parameters(args): Parameters<SymbolPathArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let out = self
            .run(
                args.session_id.as_deref(),
                EngineOp::SymbolPath {
                    path: args.path,
                    append: args.append.unwrap_or(true),
                    reload: args.reload.unwrap_or_default(),
                },
            )
            .await;
        engine_result(out)
    }

    /// Find every **allocated** kernel pool chunk carrying a tag, with its size, allocator
    /// and backend. Needs a broken-in x64 kernel target.
    /// This walks the pool's own descriptors rather than shelling out to `!poolused`, so the
    /// result is structured and consistent with `pool_chunk`/`pool_census`.
    /// Only allocated chunks are indexed by tag — a freed chunk's tag is not reliably
    /// preserved by the allocator, so this never reports freed memory. To ask whether one
    /// specific address has been freed, use `pool_chunk`.
    #[rmcp::tool(
        annotations(
            title = "Find pool chunks by tag",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        ),
        output_schema = schema_for_output::<Outcome<structured::PoolTagMatches>>()
    )]
    async fn pool_find_tag(
        &self,
        Parameters(args): Parameters<PoolFindTagArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let out = self
            .run(
                args.session_id.as_deref(),
                pool_op(PoolOp::find_tag(
                    args.tag,
                    args.paged,
                    args.refresh,
                    args.limit,
                )),
            )
            .await;
        engine_result_for(args.session_id.as_deref(), out)
    }

    /// Identify the pool chunk containing an address, **with its immediate neighbours**.
    /// Needs a broken-in x64 kernel target.
    /// This is the use-after-free question: it reports whether the chunk is still Allocated
    /// or has been freed, and what now borders it — which is what decides whether a pointer
    /// the target still holds is dangling, and what a reclaim would land next to.
    /// "Not in the snapshot" and "free" are reported differently: a free hole inside a walked
    /// region comes back as a chunk in an explicitly free state (`ReusableFree` or
    /// `CachedFree`), while an address outside every region is reported as uncovered — which
    /// means it is not pool *or* the walk never reached it, so check the coverage the result
    /// prints before reading it as "never was pool". A third state, `Unreadable`, is neither:
    /// the walk could not read the span (a Verifier guard page reads exactly this way), so it
    /// says nothing about whether the chunk is live.
    #[rmcp::tool(
        annotations(
            title = "Locate a pool chunk by address",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        ),
        output_schema = schema_for_output::<Outcome<structured::PoolChunkAt>>()
    )]
    async fn pool_chunk(
        &self,
        Parameters(args): Parameters<PoolChunkArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let out = self
            .run(
                args.session_id.as_deref(),
                pool_op(PoolOp::chunk(args.address, args.refresh)),
            )
            .await;
        engine_result_for(args.session_id.as_deref(), out)
    }

    /// The pool walk's own diagnostics, verbatim, optionally narrowed by substring.
    /// Needs a broken-in x64 kernel target.
    /// Use this when a chunk you can see with `!pool` does not appear in `pool_find_tag`
    /// or `pool_chunk`. A real walk emits tens of thousands of diagnostics across a
    /// hundred-plus categories, so the summaries the other tools print are necessarily
    /// truncated — and the one line explaining a specific heap is reliably not in the
    /// truncated head. Filter by a heap address or a phrase to get at it.
    /// `walk.gaps` on any pool answer sizes the three things a walk *records* running into —
    /// pages a region query stalled on, chunk headers a decoder refused, and committed bytes it
    /// declined to decode because it could not say where a chunk began in them — in bytes and
    /// chunks, which the diagnostics cannot, since a category's count counts occurrences of a
    /// message shape. It is not a total of everything a walk missed: one cut short by its
    /// deadline or a traversal cap carries no gaps at all. `walk.coverage` is still what says a
    /// walk fell short, and this tool is still what says why.
    #[rmcp::tool(
        annotations(
            title = "Filter pool walk diagnostics",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        ),
        output_schema = schema_for_output::<Outcome<structured::PoolDiagnosticsReport>>()
    )]
    async fn pool_diagnostics(
        &self,
        Parameters(args): Parameters<PoolDiagnosticsArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let out = self
            .run(
                args.session_id.as_deref(),
                pool_op(PoolOp::diagnostics(args.filter, args.refresh, args.limit)),
            )
            .await;
        engine_result_for(args.session_id.as_deref(), out)
    }

    /// Per-tag census of the kernel pool: allocation counts and bytes, heaviest first.
    /// Needs a broken-in x64 kernel target.
    /// The structured answer to what `!poolused` renders as text, taken from the same walk
    /// as `pool_find_tag` and `pool_chunk` so the three cannot disagree. Useful for spotting
    /// which tag a driver's allocations are landing under before querying it by name.
    #[rmcp::tool(
        annotations(
            title = "Census pool usage by tag",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        ),
        output_schema = schema_for_output::<Outcome<structured::PoolCensus>>()
    )]
    async fn pool_census(
        &self,
        Parameters(args): Parameters<PoolCensusArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let out = self
            .run(
                args.session_id.as_deref(),
                pool_op(PoolOp::census(args.refresh, args.limit)),
            )
            .await;
        engine_result_for(args.session_id.as_deref(), out)
    }

    /// List every heap root in the current process PEB. Segment Heaps are marked supported;
    /// classic NT heaps are listed but deliberately excluded from v1 coverage and should be
    /// inspected with `!heap`. Requires a stopped x64 live target or sufficiently complete dump
    /// and matching `ntdll` PDB type information.
    #[rmcp::tool(
        annotations(
            title = "List user-mode heaps",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        ),
        output_schema = schema_for_output::<Outcome<structured::HeapListResult>>()
    )]
    async fn heap_list(
        &self,
        Parameters(args): Parameters<HeapListArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let out = self
            .run(
                args.session_id.as_deref(),
                heap_op(HeapOp::list(args.refresh)),
            )
            .await;
        engine_result_for(args.session_id.as_deref(), out)
    }

    /// List user Segment Heap chunks, filtered by heap, backend, state, and capacity. Defaults
    /// to allocated chunks. Requires a stopped x64 live target or sufficiently complete dump and
    /// matching `ntdll` PDB type information.
    #[rmcp::tool(
        annotations(
            title = "List Segment Heap allocations",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        ),
        output_schema = schema_for_output::<Outcome<structured::HeapAllocationsResult>>()
    )]
    async fn heap_allocations(
        &self,
        Parameters(args): Parameters<HeapAllocationsArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        if args
            .min_capacity
            .zip(args.max_capacity)
            .is_some_and(|(minimum, maximum)| minimum > maximum)
        {
            return typed_error(
                ErrorCategory::InvalidArgument,
                "min_capacity cannot exceed max_capacity".into(),
                args.session_id,
            );
        }
        let backend = args.backend.map(|backend| match backend {
            HeapBackendArg::Lfh => HeapBackendFilter::Lfh,
            HeapBackendArg::Vs => HeapBackendFilter::Vs,
            HeapBackendArg::Segment => HeapBackendFilter::Segment,
            HeapBackendArg::Large => HeapBackendFilter::Large,
        });
        let state = args.state.map(|state| match state {
            HeapStateArg::Allocated => HeapStateFilter::Allocated,
            HeapStateArg::ReusableFree => HeapStateFilter::ReusableFree,
            HeapStateArg::CachedFree => HeapStateFilter::CachedFree,
            HeapStateArg::Unreadable => HeapStateFilter::Unreadable,
        });
        let out = self
            .run(
                args.session_id.as_deref(),
                heap_op(HeapOp::allocations(
                    args.heap,
                    backend,
                    state,
                    args.min_capacity,
                    args.max_capacity,
                    args.refresh,
                    args.limit,
                )),
            )
            .await;
        engine_result_for(args.session_id.as_deref(), out)
    }

    /// Locate the user allocation containing an address and return its contiguous neighbours
    /// from the same heap, backend, and subsegment. An uncovered address is not reported as free;
    /// inspect the returned coverage before treating absence as evidence. Requires a stopped x64
    /// live target or sufficiently complete dump and matching `ntdll` PDB type information.
    #[rmcp::tool(
        annotations(
            title = "Locate a Segment Heap chunk",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        ),
        output_schema = schema_for_output::<Outcome<structured::HeapChunkResult>>()
    )]
    async fn heap_chunk(
        &self,
        Parameters(args): Parameters<HeapChunkArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let out = self
            .run(
                args.session_id.as_deref(),
                heap_op(HeapOp::chunk(args.address, args.refresh)),
            )
            .await;
        engine_result_for(args.session_id.as_deref(), out)
    }

    /// Group Segment Heap chunks by heap, backend, state, and size class, heaviest first. Requires
    /// a stopped x64 live target or sufficiently complete dump and matching `ntdll` PDB type
    /// information.
    #[rmcp::tool(
        annotations(
            title = "Census Segment Heap usage",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        ),
        output_schema = schema_for_output::<Outcome<structured::HeapCensusResult>>()
    )]
    async fn heap_census(
        &self,
        Parameters(args): Parameters<HeapCensusArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let out = self
            .run(
                args.session_id.as_deref(),
                heap_op(HeapOp::census(args.heap, args.refresh, args.limit)),
            )
            .await;
        engine_result_for(args.session_id.as_deref(), out)
    }

    /// Inspect Segment Heap walk diagnostic categories and kept examples, optionally scoped to
    /// one heap root and narrowed by a case-insensitive substring. Requires a stopped x64 live
    /// target or sufficiently complete dump and matching `ntdll` PDB type information.
    #[rmcp::tool(
        annotations(
            title = "Filter Segment Heap diagnostics",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        ),
        output_schema = schema_for_output::<Outcome<structured::HeapDiagnosticsResult>>()
    )]
    async fn heap_diagnostics(
        &self,
        Parameters(args): Parameters<HeapDiagnosticsArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let out = self
            .run(
                args.session_id.as_deref(),
                heap_op(HeapOp::diagnostics(
                    args.heap,
                    args.filter,
                    args.refresh,
                    args.limit,
                )),
            )
            .await;
        engine_result_for(args.session_id.as_deref(), out)
    }

    /// Summarise a bug check: the code and its four parameters, the crashing process, the stack
    /// with every frame as `module+RVA`, and the faulting driver frame picked out of it — the
    /// handful of fields `!analyze -v` buries in ~150 lines.
    /// Works on a kernel crash dump and on a live kernel that has bug checked.
    /// The frames are attributed to modules from the engine's own load bases, so a driver with no
    /// PDB is still named `MessageManager+0x1654` — an offset that is comparable across reboots
    /// and does not depend on `!analyze`'s attribution, which for such a driver is often wrong.
    /// `!analyze`'s own conclusions (pool tag, failure bucket, blamed module) travel beside them
    /// under `analysis`, so the two can be compared; pass `analyze: false` to skip it.
    /// Reads the target and never writes to it, and leaves the session where it found it: the
    /// `!analyze -v` it runs by default would otherwise reset the selected scope, so the scope is
    /// saved and restored around the call.
    /// The stack it reports is the target's default context — the crash, on a crash dump —
    /// whenever the `!analyze` ran to completion, since running it is what resets the scope
    /// there. Otherwise it is whatever the session has selected, the same stack `backtrace`
    /// would show: with `analyze: false`, when the analysis could not run (no time left in the
    /// call, no `ext.dll` on the engine), and when it was cut short, since the reset happens
    /// partway through the analysis and a truncated one may not have reached it.
    /// `analysis.ran` and `analysis.truncated` are what tell those apart.
    #[rmcp::tool(
        annotations(
            title = "Triage a bug check",
            // **Read-only, and earned rather than assumed.** Nothing here writes to the debuggee,
            // but until glslang/win-kexp#98 this said `false` anyway, because `!analyze -v` moves
            // the session's selected scope and two identical `backtrace` calls either side of a
            // triage could therefore differ — a change to what every other tool reads.
            //
            // The measurement that settled it also corrected the reason. `!analyze` does not
            // *select* a faulting context and leave it, as this comment used to claim: it ends
            // with the scope at the target's **default**, discarding whatever the caller had
            // chosen. (Four targets: `0x13A`, `0xD1`, `0x9F`, and a user-mode AV.) The implicit
            // thread it really does move — visibly, on the `0x9F` — and really does put back.
            //
            // So the scope is what needed a guard, and `crash_triage` now takes one for the whole
            // call (`worker::crash_triage`): the analysis runs, the reads run at the default
            // context, and the caller's scope is restored on the way out, including on the
            // interrupt path. `ioctl_trace` keeps `false` for its own reasons — it is not this.
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        ),
        output_schema = schema_for_output::<Outcome<structured::CrashTriage>>()
    )]
    async fn crash_triage(
        &self,
        Parameters(args): Parameters<CrashTriageArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let out = self
            .run(
                args.session_id.as_deref(),
                EngineOp::CrashTriage {
                    frames: args
                        .frames
                        .unwrap_or(DEFAULT_TRIAGE_FRAMES)
                        .clamp(1, MAX_TRIAGE_FRAMES),
                    analyze: args.analyze.unwrap_or(true),
                    // Filled in by the supervisor's pump, like every other op that carries one.
                    patience_ms: 0,
                },
            )
            .await;
        engine_result_for(args.session_id.as_deref(), out)
    }

    /// Attach to an existing user-mode process by PID and break in.
    /// Opens a new session in its own engine process — sessions already open are left alone —
    /// and returns a `session_id` that routes later calls to it. End it with `end_session`.
    #[rmcp::tool(
        annotations(
            title = "Attach to process",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        ),
        output_schema = schema_for_output::<structured::OpenOutcome>()
    )]
    async fn attach_process(
        &self,
        Parameters(args): Parameters<PidArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.opened(
            SessionKind::Process,
            format!("pid {}", args.pid),
            EngineOp::AttachProcess { pid: args.pid },
        )
        .await
    }

    /// Launch a new user-mode process under the debugger, stopping at the initial breakpoint.
    /// Opens a new session in its own engine process — sessions already open are left alone —
    /// and returns a `session_id` that routes later calls to it. End it with `end_session`.
    #[rmcp::tool(
        annotations(
            title = "Launch process under debugger",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        ),
        output_schema = schema_for_output::<structured::OpenOutcome>()
    )]
    async fn launch(
        &self,
        Parameters(args): Parameters<CommandLineArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.opened(
            SessionKind::Launch,
            args.command_line.clone(),
            EngineOp::Launch {
                command_line: args.command_line,
            },
        )
        .await
    }

    /// List the debug sessions this server holds — what each one is, how long it has been in
    /// its current state, and which one a call that names no session is routed to. Pass a
    /// `session_id` to ask about one in particular.
    ///
    /// This is how you find out what happened to an open that reported a timeout. A per-call
    /// timeout abandons the *waiter*, not the job, so an open can still be running with no reply
    /// on its way — a live `attach_kernel` waits for its target indefinitely by design, and that
    /// wait cannot be interrupted. The state here separates the two cases that look identical
    /// from the outside: an open that is progressing normally, and one that has been waiting far
    /// longer than a healthy one ever takes and is not going to finish. They need opposite
    /// responses — wait, versus `end_session` to reclaim it — and re-running an attach or a
    /// launch on a guess connects or spawns a second time.
    ///
    /// Answers even while a session is parked: it reads this server's own bookkeeping and never
    /// queues on any session's engine.
    #[rmcp::tool(
        annotations(
            title = "List debug sessions",
            read_only_hint = true,
            open_world_hint = false
        ),
        output_schema = schema_for_output::<Outcome<structured::SessionsReport>>()
    )]
    async fn session_status(
        &self,
        Parameters(args): Parameters<SessionArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        // Deliberately never routed to a worker. The case this exists for is a session parked in
        // an attach, so asking that worker anything would make the tool unavailable exactly when
        // it is needed.
        let sessions = self.sessions.snapshot();

        let Some(asked) = args.session_id.as_deref() else {
            let live: Vec<&SessionSnapshot> =
                sessions.iter().filter(|s| s.state.is_live()).collect();
            let report = sessions_report(&live, None, false);
            if live.is_empty() {
                return structured_result(
                    "No debug session is open. Start one with open_dump / open_trace / \
                     attach_process / attach_kernel / attach_kernel_local / launch."
                        .to_string(),
                    report,
                );
            }
            let mut out = String::new();
            for s in &live {
                out.push_str(&describe_session(s));
                out.push('\n');
            }
            out.push_str(&format!(
                "\nEach session is its own engine process, so they do not interfere: work on one \
                 while another is busy or parked. Up to {MAX_SESSIONS} at a time. Pass \
                 `session_id` on a call to route it to a specific session; omit it and the \
                 session marked (current) is used.",
            ));
            return structured_result(out, report);
        };

        let Some(session) = sessions.iter().find(|s| s.id == asked) else {
            // Not an error: asking after a handle that has aged out is a fair question with a
            // definite answer. `unknown_handle` is how a caller tells that answer from "the
            // session exists, here it is", which an empty list on its own cannot.
            return structured_result(
                format!(
                    "`{asked}` is not a handle this server is holding. Either it was never issued \
                     here, or it closed a while ago and has aged out of the session history. A \
                     session that still exists is never forgotten, so opening again is safe."
                ),
                sessions_report(&[], Some(asked), true),
            );
        };
        structured_result(
            describe_session(session),
            sessions_report(&[session], Some(asked), false),
        )
    }

    /// Read this server's own log — the supervisor's records and every engine worker's, tagged
    /// with the session each one belongs to. This is the *server's* diagnostics, not the target's.
    ///
    /// Ask when something happened that a tool result cannot explain: a call that timed out, a
    /// session that failed to open, a worker that died, a target released by a path nobody asked
    /// for. The records name which of the two processes spoke and when.
    ///
    /// Answers even while a session is parked or wedged: it reads a buffer this server keeps and
    /// never queues on any session's engine. Only the most recent records are held (1000 by
    /// default) — `next_since` pages forward, and a `since` older than `oldest_seq` means records
    /// were evicted in between.
    ///
    /// The level filter cannot reach below what the server was started to log, which is `info`
    /// unless `RUST_LOG` says otherwise: records below that are never made, so asking for them
    /// returns nothing rather than more.
    #[rmcp::tool(
        annotations(
            title = "Read the server's log",
            read_only_hint = true,
            open_world_hint = false
        ),
        output_schema = schema_for_output::<Outcome<structured::LogReport>>()
    )]
    async fn server_log(
        &self,
        Parameters(args): Parameters<LogArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        // Never routed to a worker, for the same reason `session_status` is not: the case this
        // exists for is a session nothing can be asked of, and a tool that queued behind it would
        // be unavailable exactly when it is wanted.
        let query = crate::logbridge::Query {
            session: args.session_id.clone(),
            level: args.level.unwrap_or(crate::logbridge::Level::Info),
            since: args.since,
            limit: args
                .limit
                .unwrap_or(DEFAULT_LOG_RECORDS)
                .min(MAX_LOG_RECORDS) as usize,
        };
        let tail = crate::logbridge::tail(&query);
        structured_result(describe_log(&tail, &query), log_report(&tail))
    }

    /// Stop the operation a session is currently running, **keeping the session and its target**.
    /// The graceful way out of a call that is taking too long — a broad `s` search, a `go` that
    /// has not hit anything, a pool walk over a slow KD link.
    ///
    /// This is a Ctrl+Break, exactly as at a WinDbg prompt. The interrupted operation ends at the
    /// debugger's next poll and returns whatever it had reached *to the call that started it*, not
    /// to this one — so partial output is preserved, marked as cut short, and the session takes the
    /// next call immediately. This call answers as soon as the break is raised.
    ///
    /// Issue it while the other call is still outstanding; it does not queue behind it. With
    /// nothing running it reports exactly that and does nothing.
    ///
    /// **Not safe to retry blind.** Each call stops whatever is running *at the moment it arrives*,
    /// and this one returns as soon as the break is raised, while the operation it stopped runs on
    /// to its next poll. So a second call sent after the first has answered can land on the next
    /// operation instead of the one you meant. Read the reply — it says whether it reached anything
    /// — rather than repeating the call.
    ///
    /// Two things it cannot reach, both properties of the debugger rather than of this server: an
    /// operation that never polls for the break, and a live-kernel `attach_kernel` whose target has
    /// not connected yet (the documented case — see `session_status`). `end_session` is what ends
    /// those, at the cost of the target.
    ///
    /// A `debug_batch` interrupted this way stops at its next step and runs its `always` block, and
    /// its own result reports `BATCH: INTERRUPTED` with the rollback state — so no step after the
    /// interrupt is applied, and the session keeps its target (unlike `end_session`, which also
    /// stops a batch but takes the session with it). Its **rollback cannot be interrupted**: a
    /// restore cut short would report success while leaving the target changed, so a call aimed at
    /// a batch that is unwinding, or repeated while one is still stopping, says so and sends
    /// nothing. If a rollback will not end, `end_session` is the way out, at the cost of the
    /// target.
    // `idempotent_hint = false`, which is not the intuitive reading: raising the same Ctrl+Break
    // twice on the same operation plainly has no second effect. But the hint is about *repeating
    // the call*, and what a repeat addresses is whichever job is running when it arrives — which
    // after the first call has answered may well be the next one. So a client retrying this on a
    // timeout can stop an operation nobody asked it to. See the note above, and the smoke test that
    // has to loop until it reaches something, which is the same property from the other side.
    #[rmcp::tool(annotations(
        title = "Interrupt the running operation",
        read_only_hint = false,
        destructive_hint = false,
        idempotent_hint = false,
        open_world_hint = true
    ))]
    async fn interrupt(
        &self,
        Parameters(args): Parameters<SessionArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let session_id = args.session_id.as_deref();
        let session = match self.sessions.resolve(session_id) {
            Ok(session) => session,
            Err(e) => return engine_result(Err(e)),
        };
        engine_result(
            self.sessions
                .interrupt(&session, session_id.is_some())
                .await,
        )
    }

    /// End a debug session: release its target and shut down its engine process. Pass
    /// `session_id` to be sure you are ending your own session and not another one.
    ///
    /// This is also the recovery for a session that is stuck. If the session does not let go
    /// within a short grace period — a live-kernel attach whose target never dialed in cannot,
    /// since nothing can interrupt that wait — its engine process is terminated outright. The
    /// session ends either way, and no other session is affected.
    ///
    /// A `debug_batch` running on the session is told to stop at its next step and run its
    /// rollback before the target is released, and the batch's own call reports that; the grace
    /// covers the step in flight and the rollback after it.
    #[rmcp::tool(
        annotations(
            title = "End debug session",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = true,
            open_world_hint = true
        ),
        output_schema = schema_for_output::<Outcome<structured::SessionEnded>>()
    )]
    async fn end_session(
        &self,
        Parameters(args): Parameters<SessionArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let session_id = args.session_id.as_deref();
        let session = match self.sessions.resolve(session_id) {
            Ok(session) => session,
            Err(e) => return engine_result_for(session_id, Err(e)),
        };
        engine_result_for(
            session_id,
            self.sessions.end(&session, session_id.is_some()).await,
        )
    }

    /// Run a raw debugger command and return its full output. The universal escape hatch.
    /// A command that replaces or releases the target (`.opendump`, `.attach`, `.detach`, …)
    /// retires the current `session_id`; see [`changes_debug_target`].
    #[rmcp::tool(annotations(
        title = "Run raw debugger command",
        read_only_hint = false,
        destructive_hint = true,
        idempotent_hint = false,
        open_world_hint = true
    ))]
    async fn execute(
        &self,
        Parameters(args): Parameters<ExecuteArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        // Bounded: a runaway raw command (e.g. an unbounded `s` search) self-aborts instead of
        // pinning its session's engine and wedging every later call to it.
        let mut call = Call::new(EngineOp::BoundedCommand {
            command: args.command.clone(),
            patience_ms: 0,
        });
        if changes_debug_target(&args.command) {
            // Retired *before* the command runs, not after: a `.detach` that reports an error
            // may still have detached, and a handle that outlives its target is the failure
            // mode this whole mechanism exists to prevent.
            call = call.retiring("a raw `execute` command replaced or released the target");
        }
        engine_result(self.run_call(args.session_id.as_deref(), call).await)
    }

    /// Run an ordered sequence of debugger steps as one transaction, with assertions and a
    /// rollback block the engine process owns. Use this whenever a sequence *mutates* the
    /// target — a patched byte, an armed breakpoint, a resumed thread — and something has to be
    /// put back afterwards: the `always` block runs inside the worker on every path, including
    /// an assertion that does not hold and the deadline expiring, so cleanup cannot be lost to a
    /// call that times out. The result names every step that ran, the exact one that failed, what
    /// each changed, whether the rollback completed, and whether the target is left stopped,
    /// running, detached, or uncertain (the last when the debugger could not be asked — which is
    /// reported as not knowing, never guessed at). Tearing the session down while a batch runs —
    /// `end_session`, or a client disconnect — stops it at its next step and runs the rollback
    /// first, reported as `BATCH: ABANDONED`; the teardown waits for the step in flight as well as
    /// the rollback, but it cannot cut that step short, so a batch of long steps unwinds only once
    /// the current one ends. One edge remains: a step that overruns far enough to consume the
    /// reserved cleanup budget too leaves the rollback unrun, and the result says
    /// `rollback: INCOMPLETE`.
    /// The structured half carries all of that as values — `outcome`, the position it stopped at,
    /// `committed`, `rollback_complete`, what each step changed, and what the session holds now.
    /// Note the pairing: a batch that *ran* and did not commit answers with `status: "ok"` (the
    /// report is the answer) on a result flagged `isError`, because the transaction is what
    /// failed, not the call. `status: "error"` means the batch never ran at all.
    #[rmcp::tool(
        annotations(
            title = "Run a transactional debugger batch",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        ),
        output_schema = schema_for_output::<Outcome<structured::BatchReportInfo>>()
    )]
    async fn debug_batch(
        &self,
        Parameters(args): Parameters<DebugBatchArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        // Everything decidable without a debugger is decided here, before a single step runs.
        // The alternative is a batch that applies three mutations and then trips over a typo in
        // the fourth — survivable, because that is what `always` is for, but not something a
        // caller should have to survive.
        //
        // Typed, like every other refusal from a tool that declares an output schema: these are
        // precisely the documented "the batch never ran" cases, so they are the `status: "error"`
        // branch. Answering them with text alone would break the contract the schema states, and
        // break it on the two failures a caller is most likely to hit.
        let refused =
            |why: String| typed_error(ErrorCategory::InvalidArgument, why, args.session_id.clone());
        if let Err(why) = batch::validate(&args.steps, &args.always) {
            return refused(why);
        }
        let budget_ms = match batch::budget_ms(args.timeout_ms) {
            Ok(budget_ms) => budget_ms,
            Err(why) => return refused(why),
        };
        // Read before the steps move into the op, and before any of them runs: a `.detach` that
        // reports an error may still have detached, so the handle has to be retired ahead of the
        // batch rather than in light of what it reported.
        let retires = batch::retires_handle(&args.steps, &args.always);
        let mut call = Call::new(EngineOp::Batch(batch::BatchOp {
            budget_ms,
            // Filled in by the supervisor's pump when this job reaches the front of its session's
            // queue; see `EngineOp::Batch`.
            patience_ms: 0,
            steps: args.steps,
            always: args.always,
        }));
        if retires {
            call = call.retiring("a `debug_batch` step replaced or released the target");
        }
        let session_id = args.session_id.as_deref();
        batch_result(session_id, self.run_call(session_id, call).await)
    }

    /// Show the current register set, as `r` prints it and as typed values beside it.
    /// By default the structured half carries the **integer** registers (what `r` prints,
    /// plus any control registers the target has); pass `all: true` for the whole bank,
    /// including x87/vector registers and subregister views such as `eax` within `rax`.
    #[rmcp::tool(
        annotations(
            title = "Show registers",
            read_only_hint = true,
            open_world_hint = true
        ),
        output_schema = schema_for_output::<Outcome<structured::RegisterSet>>()
    )]
    async fn registers(
        &self,
        Parameters(args): Parameters<RegistersArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let out = self
            .run(
                args.session_id.as_deref(),
                EngineOp::Registers {
                    all: args.all.unwrap_or(false),
                },
            )
            .await;
        // DbgEng prints nothing for `r` when there is no live thread context (e.g. a
        // module-load break, or a bare goto_position to the very start of a trace). The
        // structured half says the same thing by carrying no registers, so this replaces only
        // the text — and only when the text is the empty one.
        let out = out.map(|mut out| {
            if out.text.trim().is_empty() {
                out.text = "(no thread register context at this position — e.g. a module-load \
                            break or the start of a trace. Travel to a settled position after a \
                            go/breakpoint, or read a specific register with execute \
                            { \"command\": \"r rip\" }.)"
                    .to_string();
            }
            out
        });
        engine_result_for(args.session_id.as_deref(), out)
    }

    /// Read process/kernel virtual memory and return a hex dump.
    #[rmcp::tool(annotations(
        title = "Read memory",
        read_only_hint = true,
        open_world_hint = true
    ))]
    async fn read_memory(
        &self,
        Parameters(args): Parameters<ReadMemoryArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let out = self
            .run(
                args.session_id.as_deref(),
                EngineOp::ReadMemory {
                    address: args.address,
                    size: args.size,
                },
            )
            .await;
        engine_result(out)
    }

    /// Walk a structure and read named fields out of every node — **without one unreadable
    /// address ending the walk**.
    /// This is the tool for a list, a handle table or a pointer array where some entries are
    /// freed: a MASM `.for` loop through `execute` aborts on the first unmapped dereference with
    /// `0x80040205` and no partial output, which loses exactly the node worth looking at. Here an
    /// unreadable value is `null` in its own field, an unreadable node is counted, and the walk
    /// carries on.
    /// Three ways to name the nodes, one of them required: `addresses` (an explicit list — the
    /// bulk read), `start` + `stride` (an array), or `start` + `next_offset` (a pointer chain).
    /// `fields` says what to read from each node; offsets may be negative, so a pool header at
    /// -16 is one argument.
    /// A chain is the exception to "a hole does not stop it": a node whose next pointer will not
    /// read has no address after it, so the walk stops and says which node. It also stops on a
    /// null link, on a loop (reporting where the list closed — at the head that is a healthy
    /// circular `_LIST_ENTRY`, anywhere else it is corruption), and at `count`, where it hands
    /// back the address to resume from.
    /// Two calls answer the usual question: walk the table for the object pointers, then walk
    /// those pointers as `addresses` for their fields.
    #[rmcp::tool(
        annotations(
            title = "Walk a structure in memory",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        ),
        output_schema = schema_for_output::<Outcome<structured::MemoryWalk>>()
    )]
    async fn walk_memory(
        &self,
        Parameters(args): Parameters<WalkMemoryArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        // `start` is interpolated into a `?`, so it is an operand like every other one this
        // server builds a command around.
        if let Some(start) = &args.start
            && let Err(e) = reject_command_breakers("start", start, Quotes::Rejected)
        {
            return typed_error(ErrorCategory::InvalidArgument, e, args.session_id);
        }
        let op = match walk::WalkOp::new(
            args.addresses,
            args.start,
            args.stride,
            args.next_offset,
            args.count,
            args.fields,
        ) {
            Ok(op) => op,
            // Refused here, before a session is chosen. Every one of these is a fact about the
            // request rather than about a target, so a caller learns about it now instead of
            // after queueing behind whatever that session is busy with.
            Err(why) => return typed_error(ErrorCategory::InvalidArgument, why, args.session_id),
        };
        let out = self
            .run(args.session_id.as_deref(), EngineOp::Walk(op))
            .await;
        engine_result_for(args.session_id.as_deref(), out)
    }

    /// Show the call stack of the current thread as typed frames. Each carries `module` + `rva` —
    /// the offset into the image, from its load base — beside the `module!Symbol` the debugger
    /// resolves: the symbol is missing on a driver with no PDB, the offset never is, and it stays
    /// comparable across reboots and joins a disassembler's function list. Same records as
    /// `crash_triage`'s `frames`. `frames_truncated` says when the stack went on past the cap.
    /// `execute { "command": "k" }` gives the engine's own listing instead, with `Child-SP` /
    /// `RetAddr` and the inline-frame rows a stack walk does not return.
    #[rmcp::tool(
        annotations(
            title = "Show call stack",
            read_only_hint = true,
            open_world_hint = true
        ),
        output_schema = schema_for_output::<Outcome<structured::StackTrace>>()
    )]
    async fn backtrace(
        &self,
        Parameters(args): Parameters<BacktraceArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let out = self
            .run(
                args.session_id.as_deref(),
                EngineOp::Backtrace {
                    frames: args
                        .frames
                        .unwrap_or(DEFAULT_BACKTRACE_FRAMES)
                        .clamp(1, MAX_BACKTRACE_FRAMES),
                },
            )
            .await;
        engine_result_for(args.session_id.as_deref(), out)
    }

    /// List modules, as typed values and as a listing rendered from those same values: each
    /// module's name, image name, start/end addresses and **symbol state** — `deferred` (not
    /// fetched yet) is not the same as `none` (this module has no symbols), which `lm` renders as
    /// an easily-missed parenthesis. Pass `filter` to ask about one driver rather than reading a
    /// table of two hundred; the answer still reports how many are loaded. The modules that have
    /// **unloaded** come back in their own `unloaded` list, narrowed by the same filter — that is
    /// what can name an address in a driver that is no longer there. For the engine's own listing
    /// verbatim, `execute { "command": "lm" }`.
    #[rmcp::tool(
        annotations(
            title = "List modules",
            read_only_hint = true,
            open_world_hint = true
        ),
        output_schema = schema_for_output::<Outcome<structured::ModuleList>>()
    )]
    async fn modules(
        &self,
        Parameters(args): Parameters<ModulesArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        // One refusal, where there used to be three. The other two were about a filter reaching
        // `lm m <pattern>` as command text — a `;` that would end the command, and the grammar
        // DbgEng would honour there but the values would not — and this tool builds no command
        // any more ([#120]). A `;` in a filter is now a character no module name contains, which
        // matches nothing and says so.
        //
        // [#120]: https://github.com/glslang/windbg-mcp/issues/120
        if let Some(filter) = &args.filter
            && filter.trim().is_empty()
        {
            // Refused rather than ignored: a blank filter is a caller who meant to narrow and
            // sent nothing to narrow by, and answering with the whole table would look like the
            // filter had been applied and matched everything.
            return typed_error(
                ErrorCategory::InvalidArgument,
                "`filter` is empty. Pass a module name (or a pattern using `*`/`?`) to narrow the \
                 listing, or omit `filter` for the whole table."
                    .to_string(),
                args.session_id,
            );
        }
        let out = self
            .run(
                args.session_id.as_deref(),
                EngineOp::Modules {
                    filter: args.filter,
                },
            )
            .await;
        engine_result_for(args.session_id.as_deref(), out)
    }

    /// List threads (`~`).
    #[rmcp::tool(annotations(
        title = "List threads",
        read_only_hint = true,
        open_world_hint = true
    ))]
    async fn threads(
        &self,
        Parameters(args): Parameters<SessionArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let out = self
            .run(
                args.session_id.as_deref(),
                EngineOp::Command {
                    command: "~".to_string(),
                },
            )
            .await;
        engine_result(out)
    }

    /// Disassemble at an address/symbol (or the current IP).
    #[rmcp::tool(annotations(
        title = "Disassemble",
        read_only_hint = true,
        open_world_hint = true
    ))]
    async fn disassemble(
        &self,
        Parameters(args): Parameters<DisassembleArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        if let Some(a) = &args.address
            && let Err(e) = reject_command_breakers("address", a, Quotes::Rejected)
        {
            return tool_error(e);
        }
        let cmd = match args.address {
            Some(a) => format!("u {a}"),
            None => "u".to_string(),
        };
        let out = self
            .run(
                args.session_id.as_deref(),
                EngineOp::Command { command: cmd },
            )
            .await;
        engine_result(out)
    }

    /// Evaluate a data-model (LINQ) expression with `dx` — ideal for TTD queries.
    /// The data model can also run debugger commands, so this is a second command hatch
    /// alongside `execute` and is annotated and handle-checked as one; see
    /// [`dx_executes_commands`].
    #[rmcp::tool(annotations(
        title = "Evaluate data-model expression",
        read_only_hint = false,
        // The data model reaches `Debugger.Utility.Control.ExecuteCommand`, so a `dx` can do
        // anything `execute` can — including replacing the target.
        destructive_hint = true,
        idempotent_hint = false,
        open_world_hint = true
    ))]
    async fn dx(&self, Parameters(args): Parameters<DxArgs>) -> Result<CallToolResult, ErrorData> {
        if let Err(e) = reject_command_breakers("expression", &args.expression, Quotes::Allowed) {
            return tool_error(e);
        }
        // Bounded: a data-model query that runs away (e.g. a heavy LINQ or index build on a
        // huge trace) self-aborts rather than pinning its session's engine.
        let mut call = Call::new(EngineOp::BoundedCommand {
            command: format!("dx {}", args.expression),
            patience_ms: 0,
        });
        if dx_executes_commands(&args.expression) {
            // We cannot see *which* command the data model is about to run, so the conservative
            // reading is the only sound one: assume it replaced the target. Retired before the
            // expression evaluates, for the reason `execute` does.
            call = call.retiring("a `dx` expression reached debugger command execution");
        }
        engine_result(self.run_call(args.session_id.as_deref(), call).await)
    }

    /// TTD: find every call to a function across the whole trace
    /// (`dx @$cursession.TTD.Calls(...)`). Each result carries the time, thread,
    /// parameters, and return value. Append LINQ in a follow-up `dx`/`execute` to
    /// filter (e.g. `.Where(c => c.ReturnValue != 0)`).
    #[rmcp::tool(annotations(
        title = "TTD: find calls to a function",
        read_only_hint = true,
        open_world_hint = true
    ))]
    async fn ttd_calls(
        &self,
        Parameters(args): Parameters<TtdCallsArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        if let Err(e) = reject_command_breakers("function", &args.function, Quotes::Rejected) {
            return tool_error(e);
        }
        let out = self
            .run(
                args.session_id.as_deref(),
                EngineOp::BoundedCommand {
                    command: format!("dx @$cursession.TTD.Calls(\"{}\")", args.function),
                    patience_ms: 0,
                },
            )
            .await;
        engine_result(out)
    }

    /// TTD: find every access to a memory range across the trace
    /// (`dx @$cursession.TTD.Memory(start, end, mode)`) — when and from where it was
    /// read, written, or executed.
    #[rmcp::tool(annotations(
        title = "TTD: find accesses to a memory range",
        read_only_hint = true,
        open_world_hint = true
    ))]
    async fn ttd_memory(
        &self,
        Parameters(args): Parameters<TtdMemoryArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        if let Some(mode) = &args.mode
            && let Err(e) = reject_command_breakers("mode", mode, Quotes::Rejected)
        {
            return tool_error(e);
        }
        // A bad address is the model's mistake to fix, so it comes back as a tool error
        // rather than a protocol error the model cannot act on.
        let start = match parse_u64(&args.address) {
            Ok(v) => v,
            Err(e) => return tool_error(e),
        };
        let end = start.saturating_add(args.size as u64);
        let cmd = match args.mode.as_deref() {
            Some(m) if !m.trim().is_empty() => format!(
                "dx @$cursession.TTD.Memory(0x{start:x}, 0x{end:x}, \"{}\")",
                m.trim()
            ),
            _ => format!("dx @$cursession.TTD.Memory(0x{start:x}, 0x{end:x})"),
        };
        let out = self
            .run(
                args.session_id.as_deref(),
                EngineOp::BoundedCommand {
                    command: cmd,
                    patience_ms: 0,
                },
            )
            .await;
        engine_result(out)
    }

    /// TTD: list trace events — module loads/unloads, thread create/exit, and
    /// exceptions (`dx @$curprocess.TTD.Events`). Events and Threads hang off
    /// `@$curprocess.TTD`; Calls and Memory hang off `@$cursession.TTD`.
    #[rmcp::tool(annotations(
        title = "TTD: list trace events",
        read_only_hint = true,
        open_world_hint = true
    ))]
    async fn ttd_events(
        &self,
        Parameters(args): Parameters<SessionArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let out = self
            .run(
                args.session_id.as_deref(),
                EngineOp::BoundedCommand {
                    command: "dx -r2 @$curprocess.TTD.Events".to_string(),
                    patience_ms: 0,
                },
            )
            .await;
        engine_result(out)
    }

    /// Set a breakpoint at a symbol, address, or expression (`bp`), and report every
    /// breakpoint the session then holds. A successful `bp` prints nothing at all, so the
    /// structured result is where "it was set, and here is its id" actually lives — along with
    /// whether it resolved to an address or is deferred until its module loads.
    #[rmcp::tool(
        annotations(
            title = "Set breakpoint",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = true
        ),
        output_schema = schema_for_output::<Outcome<structured::BreakpointSet>>()
    )]
    async fn set_breakpoint(
        &self,
        Parameters(args): Parameters<BreakpointArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        if let Err(e) = reject_command_breakers("expression", &args.expression, Quotes::Rejected) {
            return typed_error(ErrorCategory::InvalidArgument, e, args.session_id);
        }
        let out = self
            .run(
                args.session_id.as_deref(),
                EngineOp::SetBreakpoint {
                    expression: args.expression,
                },
            )
            .await;
        engine_result_for(args.session_id.as_deref(), out)
    }

    /// Continue execution (`g`). Runs to the next breakpoint, or the end of a TTD trace.
    #[rmcp::tool(
        annotations(
            title = "Continue execution",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        ),
        output_schema = schema_for_output::<Outcome<structured::StopReport>>()
    )]
    async fn go(
        &self,
        Parameters(args): Parameters<SessionArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let out = self
            .run(
                args.session_id.as_deref(),
                EngineOp::CommandAndWait {
                    command: "g".to_string(),
                    timeout_ms: EXEC_WAIT_MS,
                },
            )
            .await;
        engine_result_for(args.session_id.as_deref(), out)
    }

    /// Run the target until it reaches `address` (a one-shot `g <addr>` that doesn't
    /// disturb existing breakpoints) and report a structured verdict: HIT (reached it),
    /// STOPPED ELSEWHERE (another breakpoint/exception fired first), or TIMEOUT (not
    /// reached in time). Confirms *live* that the current input/state drives execution to
    /// a block — e.g. one from `reachable_from_dispatch`. Needs a real KDNET/VM kernel
    /// target (a local kernel can't set code breakpoints).
    #[rmcp::tool(
        annotations(
            title = "Run to address",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        ),
        output_schema = schema_for_output::<Outcome<structured::RunToReport>>()
    )]
    async fn run_to_address(
        &self,
        Parameters(args): Parameters<RunToAddressArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        if let Err(e) = reject_command_breakers("address", &args.address, Quotes::Rejected) {
            return typed_error(ErrorCategory::InvalidArgument, e, args.session_id);
        }
        let out = self
            .run(
                args.session_id.as_deref(),
                EngineOp::RunToAddress {
                    address: args.address,
                    timeout_ms: args.timeout_ms.unwrap_or(EXEC_WAIT_MS),
                },
            )
            .await;
        engine_result_for(args.session_id.as_deref(), out)
    }

    /// Step over one source/instruction step (`p`).
    #[rmcp::tool(
        annotations(
            title = "Step over",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        ),
        output_schema = schema_for_output::<Outcome<structured::StopReport>>()
    )]
    async fn step_over(
        &self,
        Parameters(args): Parameters<SessionArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let out = self
            .run(
                args.session_id.as_deref(),
                EngineOp::CommandAndWait {
                    command: "p".to_string(),
                    timeout_ms: EXEC_WAIT_MS,
                },
            )
            .await;
        engine_result_for(args.session_id.as_deref(), out)
    }

    /// Step into one instruction (`t`).
    #[rmcp::tool(
        annotations(
            title = "Step into",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        ),
        output_schema = schema_for_output::<Outcome<structured::StopReport>>()
    )]
    async fn step_into(
        &self,
        Parameters(args): Parameters<SessionArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let out = self
            .run(
                args.session_id.as_deref(),
                EngineOp::CommandAndWait {
                    command: "t".to_string(),
                    timeout_ms: EXEC_WAIT_MS,
                },
            )
            .await;
        engine_result_for(args.session_id.as_deref(), out)
    }

    /// Step backward one instruction in a TTD trace (`t-`). Reverse of step_into.
    // The reverse-navigation tools only work on a TTD trace, which is a recorded replay:
    // moving through it cannot destroy state, unlike stepping a live target.
    #[rmcp::tool(
        annotations(
            title = "Step back (TTD)",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = true
        ),
        output_schema = schema_for_output::<Outcome<structured::StopReport>>()
    )]
    async fn step_back(
        &self,
        Parameters(args): Parameters<SessionArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let out = self
            .run(
                args.session_id.as_deref(),
                EngineOp::CommandAndWait {
                    command: "t-".to_string(),
                    timeout_ms: EXEC_WAIT_MS,
                },
            )
            .await;
        engine_result_for(args.session_id.as_deref(), out)
    }

    /// Step over one call backward in a TTD trace (`p-`). Reverse of step_over.
    #[rmcp::tool(
        annotations(
            title = "Step over back (TTD)",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = true
        ),
        output_schema = schema_for_output::<Outcome<structured::StopReport>>()
    )]
    async fn step_over_back(
        &self,
        Parameters(args): Parameters<SessionArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let out = self
            .run(
                args.session_id.as_deref(),
                EngineOp::CommandAndWait {
                    command: "p-".to_string(),
                    timeout_ms: EXEC_WAIT_MS,
                },
            )
            .await;
        engine_result_for(args.session_id.as_deref(), out)
    }

    /// Reverse-continue: run the TTD trace backward until a breakpoint or its start (`g-`).
    #[rmcp::tool(
        annotations(
            title = "Reverse continue (TTD)",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = true
        ),
        output_schema = schema_for_output::<Outcome<structured::StopReport>>()
    )]
    async fn reverse_go(
        &self,
        Parameters(args): Parameters<SessionArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let out = self
            .run(
                args.session_id.as_deref(),
                EngineOp::CommandAndWait {
                    command: "g-".to_string(),
                    timeout_ms: EXEC_WAIT_MS,
                },
            )
            .await;
        engine_result_for(args.session_id.as_deref(), out)
    }

    /// Travel to a specific position in a TTD trace (`!tt <position>`).
    #[rmcp::tool(annotations(
        title = "Go to TTD position",
        read_only_hint = false,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true
    ))]
    async fn goto_position(
        &self,
        Parameters(args): Parameters<PositionArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        if let Err(e) = reject_command_breakers("position", &args.position, Quotes::Rejected) {
            return tool_error(e);
        }
        let cmd = format!("!tt {}", args.position);
        let out = self
            .run(
                args.session_id.as_deref(),
                EngineOp::Command { command: cmd },
            )
            .await;
        engine_result(out)
    }

    /// Build (or repair) the persistent index of the currently open TTD trace
    /// (`!ttdext.index -force`), writing an `.idx` next to the `.run` so later queries and
    /// re-opens are fast. `-force` is a fast no-op on an already-loaded index but deletes and
    /// rebuilds an unloadable/corrupt one — which plain `!ttdext.index` cannot repair, so this
    /// is the mode that actually fixes the "index not loaded" state `open_trace` warns about.
    /// (The bundled engine exposes these via `TtdExt.dll`; `!tt.index` fails with
    /// `LoadLibrary(tt)` because there is no `tt` extension.)
    /// On a large trace the build can outrun the per-call timeout: the call reports a timeout
    /// while the build keeps running, and later calls queue behind it until it finishes. That
    /// is deliberate — aborting a `-force` rebuild can leave no usable index at all. Wait and
    /// retry rather than re-issuing it.
    #[rmcp::tool(annotations(
        title = "Build TTD trace index",
        read_only_hint = false,
        // `-force` deletes and rebuilds an unloadable `.idx` — that is replacing an
        // on-disk artifact, whatever the intent behind it.
        destructive_hint = true,
        idempotent_hint = true,
        open_world_hint = true
    ))]
    async fn index_trace(
        &self,
        Parameters(args): Parameters<SessionArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        // Deliberately *not* on the bounded path, and the one O(trace) command that isn't —
        // see DECISIONS.md (2026-08-02). Indexing a large trace can legitimately outrun the
        // per-call timeout, but `-force` deletes an unloadable `.idx` before rebuilding it, so
        // a watchdog abort mid-rebuild can leave no usable index at all. Here the long run is
        // productive work rather than a runaway, and the engine frees itself when it finishes.
        let out = self
            .run(
                args.session_id.as_deref(),
                EngineOp::Command {
                    command: "!ttdext.index -force".to_string(),
                },
            )
            .await;
        engine_result(out)
    }

    /// Record a new TTD trace by launching a target under TTD.exe (requires elevation).
    /// Reports an error if the recorder fails to start (e.g. not running elevated).
    /// Optional `env` (KEY=VALUE entries) and `working_dir` are applied to the recorded
    /// target — use them when it needs a specific environment or cwd to run (e.g. a Qt
    /// app's `QT_QPA_PLATFORM_PLUGIN_PATH`, or an anti-analysis "run me from here" guard).
    /// Independent of the debug session, so it takes no `session_id`.
    #[rmcp::tool(annotations(
        title = "Record new TTD trace",
        read_only_hint = false,
        destructive_hint = true,
        idempotent_hint = false,
        open_world_hint = true
    ))]
    async fn record_trace(
        &self,
        Parameters(args): Parameters<RecordArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        // Locating TTD touches the filesystem and record_launch briefly blocks watching
        // the recorder, so run the whole thing on a blocking thread (not the engine
        // thread — recording is independent of the debug session).
        let res = tokio::task::spawn_blocking(move || {
            let ttd = ttd::find_ttd().ok_or_else(|| {
                "TTD.exe not found (install the Windows debugging tools / WinDbg)".to_string()
            })?;
            ttd::record_launch(
                &ttd,
                &args.out_dir,
                &args.target,
                &args.env,
                args.working_dir.as_deref(),
            )
        })
        .await
        .map_err(|e| ErrorData::internal_error(format!("record task panicked: {e}"), None))?;

        // A recorder that won't start (missing TTD.exe, not elevated, bad target) is
        // actionable feedback, so it belongs in the result rather than a protocol error.
        match res {
            Ok(msg) => text_result(msg),
            Err(e) => tool_error(e),
        }
    }

    /// Decode a 32-bit IOCTL control code into its CTL_CODE fields (DeviceType,
    /// FunctionCode, Method, RequiredAccess) and flag METHOD_NEITHER / FILE_ANY_ACCESS.
    /// Pure — needs no debug session, so it takes no `session_id`.
    #[rmcp::tool(annotations(
        title = "Decode IOCTL control code",
        read_only_hint = true,
        open_world_hint = false
    ))]
    async fn decode_ioctl(
        &self,
        Parameters(args): Parameters<DecodeIoctlArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        // Both rejections below are semantic input validation, not a malformed request:
        // the schema is satisfied either way, so they belong in the result where the
        // model can read them and correct the code it passed.
        let code = match parse_u64(&args.code) {
            Ok(v) => v,
            Err(e) => return tool_error(e),
        };
        // An IOCTL is a 32-bit value; reject anything wider rather than silently
        // truncating it to a different code.
        let Ok(code) = u32::try_from(code) else {
            return tool_error(format!("IOCTL must be a 32-bit value (got 0x{code:x})"));
        };
        text_result(decode_ioctl_text(code))
    }

    /// Dump a driver object's dispatch table and devices (`!drvobj <name> 7`).
    /// The MajorFunction table's index 0x0e is the IRP_MJ_DEVICE_CONTROL handler — the
    /// IOCTL dispatch routine. Root of the device-tree walk.
    #[rmcp::tool(annotations(
        title = "Inspect driver object",
        read_only_hint = true,
        open_world_hint = true
    ))]
    async fn driver_object(
        &self,
        Parameters(args): Parameters<DriverObjectArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        if let Err(e) = reject_command_breakers("name", &args.name, Quotes::Rejected) {
            return tool_error(e);
        }
        let cmd = format!("!drvobj {} 7", args.name);
        let out = self
            .run(
                args.session_id.as_deref(),
                EngineOp::Command { command: cmd },
            )
            .await;
        engine_result(out)
    }

    /// Inspect a device object (`!devobj <device>`): device type, characteristics
    /// (e.g. FILE_DEVICE_SECURE_OPEN), and the SecurityDescriptor pointer — the inputs to the
    /// *openable* gate. (`!sd <SecurityDescriptor>` decodes the DACL where that extension is
    /// available; it is not in the bundled engine.)
    #[rmcp::tool(annotations(
        title = "Inspect device object",
        read_only_hint = true,
        open_world_hint = true
    ))]
    async fn device_object(
        &self,
        Parameters(args): Parameters<DeviceObjectArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        if let Err(e) = reject_command_breakers("device", &args.device, Quotes::Rejected) {
            return tool_error(e);
        }
        let cmd = format!("!devobj {}", args.device);
        let out = self
            .run(
                args.session_id.as_deref(),
                EngineOp::Command { command: cmd },
            )
            .await;
        engine_result(out)
    }

    /// Dump the current IO_STACK_LOCATION of an IRP (`!irp <irp> 1`): major/minor,
    /// IoControlCode, input/output buffer lengths, and buffer pointers. Defaults the IRP
    /// to `@rdx` (the PIRP at the dispatch entry on x64) — valid only before stepping.
    #[rmcp::tool(annotations(
        title = "Dump IRP stack location",
        read_only_hint = true,
        open_world_hint = true
    ))]
    async fn irp_stack(
        &self,
        Parameters(args): Parameters<IrpStackArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        if let Some(irp) = &args.irp
            && let Err(e) = reject_command_breakers("irp", irp, Quotes::Rejected)
        {
            return tool_error(e);
        }
        let irp = args.irp.unwrap_or_else(|| "@rdx".to_string());
        let cmd = format!("!irp {irp} 1");
        let out = self
            .run(
                args.session_id.as_deref(),
                EngineOp::Command { command: cmd },
            )
            .await;
        engine_result(out)
    }

    /// Install a conditional logging breakpoint at the IOCTL dispatch routine that prints
    /// each IoControlCode + input/output lengths and continues (`gc`), so the IOCTL sweep
    /// needs no hand-assembled offsets. Reads the current IO_STACK_LOCATION via
    /// `poi(@rdx+0xb8)` (x64); confirm the offset with `dt nt!_IRP` / `dt nt!_IO_STACK_LOCATION`
    /// on the target. Requires a real KDNET/VM target — a local kernel cannot set code bp's.
    #[rmcp::tool(annotations(
        title = "Trace dispatched IOCTLs",
        read_only_hint = false,
        destructive_hint = false,
        idempotent_hint = false,
        open_world_hint = true
    ))]
    async fn ioctl_trace(
        &self,
        Parameters(args): Parameters<IoctlTraceArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        if let Err(e) = reject_command_breakers("dispatch", &args.dispatch, Quotes::Rejected) {
            return tool_error(e);
        }
        // IRP in @rdx at dispatch entry (x64). CurrentStackLocation = poi(Irp+0xb8).
        // Within IO_STACK_LOCATION: OutputBufferLength +0x08, InputBufferLength +0x10,
        // IoControlCode +0x18 (Parameters union begins at +0x08).
        let cmd = format!(
            "bp {} \".printf \\\"IOCTL %08x in=%x out=%x\\\\n\\\", \
             dwo(poi(@rdx+0xb8)+0x18), dwo(poi(@rdx+0xb8)+0x10), dwo(poi(@rdx+0xb8)+0x08); gc\"",
            args.dispatch
        );
        let out = self
            .run(
                args.session_id.as_deref(),
                EngineOp::Command { command: cmd },
            )
            .await;
        engine_result(out)
    }

    /// Static, best-effort control-flow reachability: is the code block at `address`
    /// (or `module`+`rva`) reachable from the IOCTL dispatch routine `from`? Runs a
    /// bounded breadth-first walk over the call graph via repeated `uf` disassembly,
    /// following direct calls and cross-function tail jumps. "REACHABLE" is sound (a
    /// concrete static path exists, and the call path is reported); "NOT REACHABLE"
    /// means only that the block was not found within the bounds — indirect calls
    /// through function pointers and unresolved compiler jump tables are NOT followed.
    #[rmcp::tool(annotations(
        title = "Test reachability from IOCTL dispatch",
        read_only_hint = true,
        open_world_hint = true
    ))]
    async fn reachable_from_dispatch(
        &self,
        Parameters(args): Parameters<ReachabilityArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        for (field, value) in [
            ("from", Some(&args.from)),
            ("address", args.address.as_ref()),
            ("module", args.module.as_ref()),
            ("rva", args.rva.as_ref()),
        ] {
            if let Some(value) = value
                && let Err(e) = reject_command_breakers(field, value, Quotes::Rejected)
            {
                return tool_error(e);
            }
        }
        let out = self
            .run(
                args.session_id.as_deref(),
                EngineOp::Reachability(ReachabilityOp {
                    from: args.from,
                    address: args.address,
                    module: args.module,
                    rva: args.rva,
                    max_functions: args.max_functions.unwrap_or(256),
                    max_depth: args.max_depth.unwrap_or(32),
                    recipe: args.recipe.unwrap_or(true),
                }),
            )
            .await;
        engine_result(out)
    }
}

// `name` is not cosmetic: without it the macro falls back to `Implementation::from_build_env()`,
// whose `env!` macros expand inside *rmcp*, so the server introduces itself to every client as
// "rmcp" version 3.0.0 — the SDK's identity, not this server's. Naming it here also fixes the
// version, because the macro's one-argument path pairs the name with an `env!("CARGO_PKG_VERSION")`
// that expands in this crate. Pass `name` only: the attribute takes a string literal, so
// `version = env!(...)` would not even parse, and spelling the version out by hand would just be a
// second place to forget to bump.
#[rmcp::tool_handler(
    name = "windbg-mcp",
    instructions = "Drive WinDbg/DbgEng for live user-mode, kernel, crash-dump, and Time Travel Debugging (TTD) analysis. \
Open a dump or .run trace, attach to a process or the kernel, inspect registers/memory/stacks/modules, and set breakpoints. \
Each open target is a separate session in its own engine process, so several can be open at once (up to 4) without \
disturbing each other; pass the `session_id` an opener returns on later calls to route them to that target, and \
`end_session` when done. An opener answers with a summary of the target — the build, the kernel or primary image and \
its base, how many modules are loaded, and a crash dump's bug check — rather than the module table; `modules` lists \
that table when you actually need it, and `crash_triage` reads a bug check with its stack. \
`session_status` lists what is open and what state each session is in — ask it when an open \
reports a timeout rather than re-running the open, which would attach or launch a second time. To stop a call that is \
taking too long without losing the target, call `interrupt` on its session while it is still outstanding: it Ctrl+Breaks \
the engine, the running call returns whatever it had reached, and the session is free for the next one. A live kernel \
attach is the exception — it waits for its target indefinitely and cannot be interrupted; if it has been waiting far \
longer than a healthy link takes, `end_session` reclaims that session (and only that session) by terminating its engine \
process. \
Navigate a TTD trace in both directions: go/step_over/step_into forward, and reverse_go/step_over_back/step_back backward, \
or jump with goto_position. Analyze a trace with the data-model tools ttd_calls (calls to a function), ttd_memory (accesses \
to an address range), and ttd_events (module/thread/exception events), or run any data-model query with dx. Record new traces \
with record_trace (needs elevation). For driver IOCTL work: decode_ioctl (decode a control code), driver_object \
and device_object (walk the driver/device tree and security), irp_stack (dump an IRP's IO_STACK_LOCATION), \
ioctl_trace (log every dispatched IOCTL), and reachable_from_dispatch (statically test, via a bounded \
uf-based call-graph walk, whether a code block — by address or module+RVA — is reachable from the IOCTL \
dispatch routine; REACHABLE is sound, NOT REACHABLE is best-effort, and a REACHABLE verdict includes a \
directional path recipe of the on-path branch conditions). Confirm a static verdict live with \
run_to_address (run to a block on a KDNET/VM kernel target and report HIT/STOPPED ELSEWHERE/TIMEOUT). \
When a sequence *mutates* the target — a patched byte, an armed breakpoint, a resumed thread — run it as \
one `debug_batch` rather than as separate calls: its `always` block runs inside the engine process on \
every path, including a failed assertion and an expired deadline, so cleanup cannot be lost to a call \
that times out or a client that disconnects, and the result names the exact failing step, what each step \
changed, whether the rollback completed, and whether the target is left stopped, running or gone. \
Use `execute` for any raw command not covered by a dedicated tool."
)]
impl rmcp::ServerHandler for WindbgServer {
    /// Every tool call, recorded on its way through.
    ///
    /// Written out rather than left to `#[rmcp::tool_handler]` — which supplies it only when the
    /// impl does not — because this is the one place *every* tool passes, whatever it is and
    /// whatever it answers. The alternative was a line in each of forty-odd tool bodies, which is
    /// forty-odd places to forget one, and the ones that would be forgotten are the ones added
    /// next. The rest of the handler is still the macro's.
    ///
    /// It records the call and its result, and nothing else: the events that say what the *target*
    /// did are derived from the typed half of the result by [`crate::record`], and the ones about
    /// sessions come from the supervisor, which is where sessions live.
    ///
    /// It is also where a call's **progress** is hung, for the same reason and with the same shape:
    /// one place every tool passes, rather than a line in each of forty-odd bodies. See
    /// [`crate::progress`].
    async fn call_tool(
        &self,
        request: rmcp::model::CallToolRequestParams,
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::CallToolResponse, ErrorData> {
        let tcc = rmcp::handler::server::tool::ToolCallContext::new(self, request, context);
        // Read before the router takes the context, and wrapped around the whole call rather than
        // around the engine work inside it: an opener spends up to `WORKER_READY_TIMEOUT` bringing
        // a worker up before there is any engine call to report on.
        let watch = crate::progress::Watch::of(&tcc.request_context);
        // Nothing at all when there is no transcript, which is the default: not the argument
        // clone, not the routing scope, and — the one that would actually cost something — not
        // `text_of`, which joins and copies every content block a tool produced. A module listing
        // or a pool census is megabytes, and paying for it on every call of a server that is not
        // recording is the kind of overhead nobody would ever see and everybody would pay.
        if !self.rec.enabled() {
            return watch.run(Self::tool_router().call(tcc)).await;
        }
        let args = tcc.arguments.clone().map(serde_json::Value::Object);
        let mut call = self.rec.tool_request(tcc.name(), args.as_ref());
        let (outcome, routed) =
            crate::record::tracking_route(watch.run(Self::tool_router().call(tcc))).await;
        // Where it actually went, which for a call that named no session is the only record of
        // which target it read or changed.
        call.routed_to(routed);
        match &outcome {
            Ok(rmcp::model::CallToolResponse::Complete(result)) => self.rec.tool_result(
                call,
                result.is_error.unwrap_or(false),
                &text_of(result),
                result.structured_content.as_ref(),
            ),
            // An MRTR round trip: the server is asking the *client* for something, and this call
            // has not produced a result. Deliberately recorded as nothing rather than as an empty
            // success — a `tool_result` says the call finished, and it has not. The request record
            // stands on its own, which is exactly what happened. (This server elicits nothing
            // today, so the arm is here to be correct rather than because it is reached.)
            Ok(_) => {}
            // A protocol error is a result: the rarest outcome here, since almost everything is
            // answered as a tool result on purpose, and so the one most worth naming rather than
            // leaving as a request with nothing after it.
            Err(e) => self.rec.tool_result(call, true, &e.message, None),
        }
        outcome
    }
}

/// The text a result carries, as one string — what a transcript records and what a renderer
/// prints. Non-text blocks (an image, a resource link) are named rather than dropped: a record
/// that silently omitted one would misreport what the caller was told.
fn text_of(result: &CallToolResult) -> String {
    result
        .content
        .iter()
        .map(|block| match block.as_text() {
            Some(text) => text.text.clone(),
            None => "<non-text content block>".to_string(),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- MCP protocol surface ------------------------------------------

    /// `tools/list` must not reorder between calls: clients cache the list, and a
    /// shuffled order also costs LLM prompt-cache hits. The SDK's router sorts by name
    /// today — this pins that so an SDK bump can't silently regress it.
    #[test]
    fn tool_list_is_deterministically_ordered() {
        let names: Vec<String> = WindbgServer::tool_router()
            .list_all()
            .into_iter()
            .map(|t| t.name.to_string())
            .collect();

        let mut expected = names.clone();
        expected.sort();
        assert_eq!(
            names, expected,
            "tools/list must be in a stable, sorted order"
        );

        // Guard against the list silently becoming empty if the macro wiring changes.
        assert!(names.contains(&"open_dump".to_string()));
    }

    /// Behaviour hints let a client tell "read a register" apart from "run arbitrary
    /// debugger commands" before prompting the user.
    #[test]
    fn every_tool_declares_annotations() {
        for tool in WindbgServer::tool_router().list_all() {
            let ann = tool
                .annotations
                .unwrap_or_else(|| panic!("tool `{}` declares no annotations", tool.name));
            assert!(
                ann.title.is_some(),
                "tool `{}` has no annotation title",
                tool.name
            );
        }
    }

    /// The tools that mutate a live target must not claim to be read-only, and the
    /// pure/inspection tools must not be flagged destructive.
    #[test]
    fn annotations_match_tool_behaviour() {
        let tools = WindbgServer::tool_router().list_all();
        let ann = |name: &str| {
            tools
                .iter()
                .find(|t| t.name == name)
                .unwrap_or_else(|| panic!("no tool `{name}`"))
                .annotations
                .clone()
                .unwrap()
        };

        for name in [
            "execute",
            "launch",
            "record_trace",
            "end_session",
            "go",
            "debug_batch",
        ] {
            assert_eq!(
                ann(name).read_only_hint,
                Some(false),
                "`{name}` changes the target and must not be marked read-only"
            );
            assert_eq!(ann(name).destructive_hint, Some(true), "`{name}`");
        }

        for name in [
            "read_memory",
            "walk_memory",
            "backtrace",
            "modules",
            "decode_ioctl",
        ] {
            assert_eq!(
                ann(name).read_only_hint,
                Some(true),
                "`{name}` only inspects and should be marked read-only"
            );
        }
    }

    /// Only a tool that structurally cannot reach the network may say so. Everything that
    /// touches a target can trigger a PDB download, and over KDNET the target itself is
    /// remote — leaving the three that never reach the engine at all.
    #[test]
    fn only_the_tools_that_cannot_reach_the_network_are_closed_world() {
        let closed: Vec<String> = WindbgServer::tool_router()
            .list_all()
            .into_iter()
            .filter(|t| {
                t.annotations
                    .as_ref()
                    .is_some_and(|a| a.open_world_hint == Some(false))
            })
            .map(|t| t.name.to_string())
            .collect();

        assert_eq!(closed, ["decode_ioctl", "server_log", "session_status"]);
    }

    /// Session-scoped tools take a handle; the two that are genuinely session-independent
    /// must not, or callers would think they were scoped when they are not.
    #[test]
    fn session_scoped_tools_accept_a_session_id() {
        let tools = WindbgServer::tool_router().list_all();
        let takes_session = |name: &str| {
            let tool = tools.iter().find(|t| t.name == name).unwrap();
            tool.input_schema
                .get("properties")
                .and_then(|p| p.get("session_id"))
                .is_some()
        };

        for name in [
            "read_memory",
            "execute",
            "go",
            "end_session",
            "modules",
            "debug_batch",
            // These two take one to ask *about*, not to be checked against.
            "session_status",
            "server_log",
        ] {
            assert!(takes_session(name), "`{name}` should accept session_id");
        }
        for name in ["decode_ioctl", "record_trace", "open_dump"] {
            assert!(
                !takes_session(name),
                "`{name}` should not accept session_id"
            );
        }

        // `session_status` must never *require* one: its whole purpose is answering for a
        // caller who did not receive a handle, and requiring the thing you are asking for
        // would defeat that.
        let required = tools
            .iter()
            .find(|t| t.name == "session_status")
            .unwrap()
            .input_schema
            .get("required")
            .cloned();
        let requires_nothing = required
            .as_ref()
            .is_none_or(|r| r.as_array().is_none_or(|r| r.is_empty()));
        assert!(
            requires_nothing,
            "`session_status` must not require any argument, got {required:?}"
        );
    }

    /// A `2026-07-28` client may skip the handshake entirely and open the connection with
    /// `server/discover`. Nothing in this crate implements that path — it falls out of the
    /// SDK's defaults — which is exactly why it is worth pinning: an SDK bump could take it
    /// away silently, and the failure mode is a whole class of client that cannot connect at
    /// all rather than a tool that misbehaves.
    ///
    /// Driven over a real duplex with hand-written JSON-RPC, because the claim is about the
    /// bytes on the wire: calling `discover()` directly would prove only that the default
    /// method exists, not that `serve` accepts it as the *opening* message.
    #[tokio::test]
    async fn discover_opens_a_session_without_initialize() {
        use std::time::Duration;

        use rmcp::ServiceExt;
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

        // Generous enough that a loaded CI runner never trips it, bounded so a regression
        // fails this test instead of hanging the suite.
        const STEP: Duration = Duration::from_secs(30);

        let (mut client_io, server_io) = tokio::io::duplex(64 * 1024);

        // Per-request metadata is what replaces the handshake, so a discover opener has to
        // carry the two keys 2026-07-28 makes mandatory; without them the SDK is entitled to
        // reject the request and demand `initialize`. Buffered before the server starts, so
        // the opening message is already waiting when `serve` reads.
        let discover = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "server/discover",
            "params": {
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                }
            }
        });
        client_io
            .write_all(format!("{discover}\n").as_bytes())
            .await
            .expect("write the discover request");

        // No session is ever opened, so no engine worker is spawned — discover is answered
        // from `get_info` alone, which is what lets this run on a machine with no debugger.
        let service = tokio::time::timeout(
            STEP,
            WindbgServer::new(Sessions::new(STEP)).serve(server_io),
        )
        .await
        .expect("serve must not block waiting for an `initialize` that never comes")
        .expect("`server/discover` must open a session on its own");

        let mut line = String::new();
        tokio::time::timeout(
            STEP,
            tokio::io::BufReader::new(&mut client_io).read_line(&mut line),
        )
        .await
        .expect("the discover response should arrive")
        .expect("read the discover response");

        let response: serde_json::Value = serde_json::from_str(&line)
            .unwrap_or_else(|e| panic!("malformed response {line:?}: {e}"));
        assert_eq!(
            response["error"],
            serde_json::Value::Null,
            "discover must not be answered with a JSON-RPC error: {line}"
        );
        let result = &response["result"];

        // SEP-2322: 2026-07-28 requires the discriminator, and a client that parses results
        // by it cannot read a response that omits it.
        assert_eq!(result["resultType"], "complete");

        // The point of the whole exercise: the revision that permits this opener is one the
        // server actually offers, alongside the handshake era it still serves.
        let versions = result["supportedVersions"]
            .as_array()
            .unwrap_or_else(|| panic!("discover must advertise supportedVersions: {line}"));
        for expected in ["2026-07-28", "2025-11-25"] {
            assert!(
                versions.iter().any(|v| v == expected),
                "discover must advertise `{expected}`, got {versions:?}"
            );
        }

        // A discover-first client learns the server only from this one response, so the tool
        // capability and the usage instructions have to reach it here — not only via
        // `initialize`, which such a client never sends.
        assert!(
            !result["capabilities"]["tools"].is_null(),
            "discover must advertise the tools capability: {line}"
        );
        let instructions = result["instructions"]
            .as_str()
            .unwrap_or_else(|| panic!("discover must carry the server instructions: {line}"));
        assert!(
            instructions.contains("WinDbg"),
            "instructions should be this server's, got {instructions:?}"
        );

        // The server has to introduce itself as itself. Left to the macro's default this reads
        // `rmcp` at the SDK's version, because `Implementation::from_build_env()` resolves its
        // `env!`s inside rmcp — so this asserts the `name` on `#[tool_handler]` is still there.
        let server_info = &result["_meta"]["io.modelcontextprotocol/serverInfo"];
        assert_eq!(
            server_info["name"], "windbg-mcp",
            "the server must not report the SDK's identity as its own: {line}"
        );
        assert_eq!(
            server_info["version"],
            env!("CARGO_PKG_VERSION"),
            "the reported version must track this crate, not the SDK: {line}"
        );

        service.cancel().await.expect("shut the service down");
    }

    // ---- What `session_status` says ------------------------------------
    //
    // The routing rules themselves live in `engine.rs`, with the registry that enforces them.
    // What is checked here is the reporting: an agent acts on this text, and for a session that
    // has not landed the right action flips entirely on how long it has been waiting.

    fn snapshot(kind: SessionKind, state: SessionState, waited: Duration) -> SessionSnapshot {
        SessionSnapshot {
            id: "sess-1".to_string(),
            kind,
            what: "net:port=50000,key=1.2.3.4".to_string(),
            pid: 4242,
            state,
            in_state_for: waited,
            age: waited,
            current: true,
        }
    }

    /// A kernel attach that is still settling is *normal*, and saying otherwise would send an
    /// agent off to reclaim a session that is about to come up.
    #[test]
    fn a_young_kernel_attach_is_reported_as_normal() {
        let out = describe_session(&snapshot(
            SessionKind::Kernel,
            SessionState::Attaching,
            Duration::from_secs(10),
        ));
        assert!(out.contains("waiting 10.0s"), "{out}");
        assert!(out.contains("normal"), "{out}");
        assert!(
            !out.contains("end_session"),
            "a healthy attach must not be advised to reclaim itself:\n{out}"
        );
        // The one thing that must be said whatever the age: the target exists.
        assert!(out.contains("Do not re-run the open"), "{out}");
    }

    /// The report issue #61 asked for. Past the point a healthy link takes, "pending" stops
    /// being an honest answer: this wait cannot be interrupted and will not return, and the
    /// caller needs to be told that *and* told the recovery — which now exists.
    #[test]
    fn a_long_parked_kernel_attach_is_reported_as_never_returning() {
        let out = describe_session(&snapshot(
            SessionKind::Kernel,
            SessionState::Attaching,
            Duration::from_secs(400),
        ));
        assert!(out.contains("6m40s"), "the wait must be quantified:\n{out}");
        assert!(
            out.contains("will not return on its own"),
            "the caller must not be left waiting on it:\n{out}"
        );
        assert!(
            out.contains("end_session") && out.contains("terminates its engine process"),
            "the recovery must be named, and it is a process kill:\n{out}"
        );
        assert!(
            out.contains("debug"),
            "the usual cause (a guest not booted in debug mode) should be named:\n{out}"
        );
    }

    /// The age advice is specific to a wait that cannot be interrupted. A dump load has a
    /// finite timeout, so telling its caller the same thing would be wrong.
    #[test]
    fn a_slow_dump_load_is_not_told_it_will_never_return() {
        let out = describe_session(&snapshot(
            SessionKind::Dump,
            SessionState::Attaching,
            Duration::from_secs(400),
        ));
        assert!(!out.contains("will not return on its own"), "{out}");
        assert!(!out.contains("KDNET"), "{out}");
    }

    /// A retired handle is the one state where "refused" and "unusable" part company, so the
    /// report has to say both halves or the caller writes the session off.
    #[test]
    fn a_retired_session_is_reported_as_reachable_without_the_handle() {
        let out = describe_session(&snapshot(
            SessionKind::Dump,
            SessionState::Retired("`.opendump` replaced the target".to_string()),
            Duration::from_secs(3),
        ));
        assert!(out.contains("retired"), "{out}");
        assert!(out.contains("`.opendump` replaced the target"), "{out}");
        assert!(out.contains("calls that omit it still reach it"), "{out}");
    }

    /// A failed open must say the slate is clean — that is what makes "open again" safe advice
    /// rather than the thing that starts a second process.
    #[test]
    fn a_failed_open_says_nothing_was_created() {
        let out = describe_session(&snapshot(
            SessionKind::Launch,
            SessionState::Failed("0x80070002".to_string()),
            Duration::from_secs(1),
        ));
        assert!(out.contains("0x80070002"), "{out}");
        assert!(out.contains("Nothing was created"), "{out}");
    }

    // ---- the server's own log ------------------------------------------

    fn log_entry(
        level: crate::logbridge::Level,
        session: Option<&str>,
        target: &str,
    ) -> crate::logbridge::Entry {
        crate::logbridge::Entry {
            seq: 7,
            at_ms: 1_770_000_000_000,
            level,
            target: target.to_string(),
            session: session.map(str::to_string),
            message: "a thing happened".to_string(),
        }
    }

    /// Only this crate's own targets are shortened. Taking the last segment of every target — the
    /// first cut here — rendered `rmcp::handler::server` and this crate's `server` identically,
    /// which loses the one thing the prefix is there to say.
    #[test]
    fn a_foreign_target_is_not_shortened_into_one_of_ours() {
        assert_eq!(short_target("windbg_mcp::worker"), "worker");
        assert_eq!(short_target("windbg_mcp::server"), "server");
        assert_eq!(
            short_target("rmcp::handler::server"),
            "rmcp::handler::server"
        );
        assert_ne!(
            short_target("rmcp::handler::server"),
            short_target("windbg_mcp::server"),
            "two different sources must not render as the same prefix"
        );
    }

    /// A record says which session it belongs to in the line itself, not only in the typed half —
    /// the text is what a person reads, and a worker's record is meaningless without it.
    #[test]
    fn a_workers_record_carries_its_session_in_the_line() {
        let line = describe_record(&log_entry(
            crate::logbridge::Level::Warn,
            Some("sess-abc-1"),
            "windbg_mcp::worker",
        ));
        assert!(line.contains("worker/sess-abc-1"), "{line}");
        assert!(line.contains("WARN"), "{line}");
        assert!(line.contains("a thing happened"), "{line}");
        // The supervisor's own records have no session, and must not invent one.
        let supervisor = describe_record(&log_entry(
            crate::logbridge::Level::Info,
            None,
            "windbg_mcp::engine",
        ));
        assert!(
            supervisor.contains("engine: a thing happened"),
            "{supervisor}"
        );
        assert!(!supervisor.contains('/'), "{supervisor}");
    }

    /// An empty page is the answer most likely to be misread, so it has to explain itself: why
    /// there is nothing, and what to ask instead.
    #[test]
    fn an_empty_page_says_why_it_is_empty() {
        let tail = crate::logbridge::Tail {
            entries: Vec::new(),
            matched: 0,
            next_since: 12,
            held: 12,
            capacity: 1000,
            oldest_seq: Some(0),
        };
        let query = crate::logbridge::Query {
            session: Some("sess-abc-1".to_string()),
            level: crate::logbridge::Level::Info,
            since: None,
            limit: 50,
        };
        let out = describe_log(&tail, &query);
        assert!(
            out.contains("No log records about session sess-abc-1"),
            "{out}"
        );
        assert!(
            out.contains("without `session_id`"),
            "an empty session page has to name the filter that would show the supervisor's own \
             records about that session: {out}"
        );
        assert!(
            out.contains("12 record(s) that this filter excluded"),
            "{out}"
        );
    }

    /// A caller paging with `since` has to be told when the buffer moved past them, or their next
    /// page silently skips a stretch and reads as a quiet one.
    #[test]
    fn a_page_that_missed_records_says_so() {
        let tail = crate::logbridge::Tail {
            entries: vec![log_entry(
                crate::logbridge::Level::Info,
                None,
                "windbg_mcp::engine",
            )],
            matched: 1,
            next_since: 400,
            held: 100,
            capacity: 100,
            oldest_seq: Some(300),
        };
        let caught_up = crate::logbridge::Query {
            session: None,
            level: crate::logbridge::Level::Info,
            since: Some(350),
            limit: 50,
        };
        assert!(
            !describe_log(&tail, &caught_up).contains("were evicted"),
            "a cursor the buffer still covers is not a gap"
        );
        let left_behind = crate::logbridge::Query {
            since: Some(2),
            ..caught_up
        };
        let out = describe_log(&tail, &left_behind);
        assert!(out.contains("before seq 300 were evicted"), "{out}");
        assert!(out.contains("WINDBG_MCP_LOG_BUFFER"), "{out}");
    }

    #[test]
    fn durations_are_rendered_at_human_scale() {
        assert_eq!(fmt_duration(Duration::from_millis(8400)), "8.4s");
        assert_eq!(fmt_duration(Duration::from_secs(192)), "3m12s");
        assert_eq!(fmt_duration(Duration::from_secs(3900)), "1h05m");
    }

    /// The typed tools interpolate their operands into commands, and DbgEng chains on `;`.
    /// Without this, `disassemble { address: "rip; .opendump other.dmp" }` runs a target
    /// swap from a tool advertising `readOnlyHint: true`, and does it without retiring
    /// anyone's session handle.
    #[test]
    fn operands_may_not_end_the_command_they_are_embedded_in() {
        for value in [
            "rip; .opendump C:\\other.dmp",
            "rip;.detach",
            "rip\n.detach",
            "rip\r\n.kill",
        ] {
            assert!(
                reject_command_breakers("address", value, Quotes::Rejected).is_err(),
                "`{value}` must be refused"
            );
        }
    }

    /// A quote is refused everywhere except `dx`, for two separate reasons.
    #[test]
    fn operands_may_not_carry_quotes_except_in_dx() {
        // Escaping the string literal this server wrapped around the operand.
        assert!(
            reject_command_breakers("function", "nt!*\") ; .detach //", Quotes::Rejected).is_err()
        );

        // Opening a `bp` command string, which WinDbg runs on every hit — a target swap
        // armed for later, outside any tool call and outside handle retirement.
        assert!(
            reject_command_breakers(
                "expression",
                "nt!NtCreateFile \".opendump C:\\\\other.dmp\"",
                Quotes::Rejected
            )
            .is_err()
        );

        // `dx` is the exception: quoted literals are ordinary data-model syntax.
        assert!(
            reject_command_breakers(
                "expression",
                "@$cursession.TTD.Calls(\"ntdll!Nt*\")",
                Quotes::Allowed
            )
            .is_ok()
        );
        // Even there, a separator still ends the command.
        assert!(
            reject_command_breakers("expression", "@$curprocess; .detach", Quotes::Allowed)
                .is_err()
        );
    }

    /// The rejection must not swallow the operand forms these tools exist to accept.
    #[test]
    fn ordinary_operands_are_accepted() {
        for value in [
            "rip",
            "nt!NtCreateFile",
            "fffff803`3e254750",
            "0x1000",
            "@$curprocess.TTD.Lifetime",
            "HEVD!DispatchDeviceControl+0x42",
            "\\Driver\\HEVD",
            "12:0",
        ] {
            assert!(
                reject_command_breakers("operand", value, Quotes::Rejected).is_ok(),
                "`{value}` must be accepted"
            );
        }
        assert!(
            reject_command_breakers("function", "kernelbase!CreateFileW", Quotes::Rejected).is_ok()
        );
        assert!(reject_command_breakers("function", "ntdll!Nt*", Quotes::Rejected).is_ok());
    }

    // ---- what a module filter means ----------------------------------------

    /// A `filter` typed as a name finds that name **anywhere**, which is what makes
    /// `{"filter": "MessageManager"}` answer "where is that driver loaded" rather than nothing.
    #[test]
    fn a_filter_without_wildcards_is_a_substring() {
        assert_eq!(module_pattern("MessageManager"), "*MessageManager*");
        assert_eq!(module_pattern("  nt  "), "*nt*");
        // …and one with wildcards is a pattern the caller wrote deliberately, left alone — which
        // is the only way to ask for an anchored match.
        assert_eq!(module_pattern("nt*"), "nt*");
        assert_eq!(module_pattern("*"), "*");
        assert_eq!(module_pattern("k?32"), "k?32");
    }

    /// The one match a `modules` listing performs — over the records both of its halves are built
    /// from.
    #[test]
    fn a_module_pattern_matches_names_by_wildcard_and_case() {
        // Case-insensitive, and `*` spans any run — including an empty one.
        assert!(matches_module_pattern("*nt*", "nt"));
        assert!(matches_module_pattern("*nt*", "ntfs"));
        assert!(matches_module_pattern("*NT*", "WinNT"));
        assert!(matches_module_pattern("*", "anything"));
        assert!(matches_module_pattern("nt", "NT"));

        // Anchored where the caller anchored it.
        assert!(matches_module_pattern("nt*", "ntoskrnl"));
        assert!(!matches_module_pattern("nt*", "WinNT"));
        assert!(!matches_module_pattern("nt", "ntfs"));

        // `?` is exactly one character, and a pattern that runs out of name does not match.
        assert!(matches_module_pattern("k?32", "k132"));
        assert!(!matches_module_pattern("k?32", "k32"));
        assert!(!matches_module_pattern("*manager", "MessageManagerX"));

        // The backtracking case: the first `*` has to give ground for the tail to land.
        assert!(matches_module_pattern("*a*b", "xaybzb"));
        assert!(!matches_module_pattern("*a*b", "xayb z"));
    }

    /// The grammar WinDbg has and this does not is **literal**, not refused.
    ///
    /// Each of these was measured against the sample dump back when the text came from `lm m`:
    /// `lm m nt[fd]*` and `lm m nt#f*` print `Ntfs`, `lm m ha+l` prints `hal`, and `lm m n\t*`
    /// prints `nt`, `Ntfs` and `ntosext` — the backslash escaping the `t`. Every one of them was
    /// refused, because honouring it in the text and not in the values would make one answer
    /// describe two sets of modules. With one matcher there is nothing to disagree with: the
    /// characters are matched as themselves, and a filter carrying them finds whatever is actually
    /// named that — on a real target, nothing.
    #[test]
    fn wildcards_this_server_does_not_implement_are_matched_literally() {
        for filter in ["nt[fd]*", "nt#f*", "ha+l", r"n\t*", "nt v", "nvhdaé"] {
            assert!(
                !matches_module_pattern(&module_pattern(filter), "Ntfs"),
                "`{filter}` is not a wildcard pattern here, so it must not match `Ntfs`"
            );
        }
        // Literal means literal in both directions: a module actually called `nt[fd]` matches the
        // filter that spells it, which is the property that makes "everything else is a character"
        // a rule rather than a hole.
        assert!(matches_module_pattern(&module_pattern("nt[fd]"), "nt[fd]"));
        assert!(matches_module_pattern(
            &module_pattern("nt v"),
            "my nt v drv"
        ));

        // The names real targets carry — punctuation and all — go through untouched.
        for (filter, name) in [
            ("nvhda64v.sys", "nvhda64v.sys"),
            ("RzDev_0228", "RzDev_0228"),
            (
                "api-ms-win-core-file-l1-1-0.dll",
                "api-ms-win-core-file-l1-1-0.dll",
            ),
            ("  nt  ", "nt"),
        ] {
            assert!(
                matches_module_pattern(&module_pattern(filter), name),
                "`{filter}` has to find `{name}`"
            );
        }
    }

    /// Case folds beyond ASCII, because with one matcher there is no second fold to stay in step
    /// with.
    ///
    /// This is what the ASCII-only refusal used to buy: DbgEng folded `é` by Windows' rules while
    /// this side compared it case-sensitively, so a filter could match in the listing text and
    /// miss in the values. Now the fold here is the only fold there is.
    #[test]
    fn a_filter_folds_case_outside_ascii_too() {
        assert!(matches_module_pattern(&module_pattern("nvhdaé"), "NVHDAÉ"));
        assert!(matches_module_pattern(&module_pattern("Ä"), "wä32"));
        assert!(matches_module_pattern(&module_pattern("日本語"), "日本語"));
        assert!(!matches_module_pattern(&module_pattern("nvhdaé"), "nvhdae"));

        // **The pairs that only converge upward.** Lowercasing alone is the obvious fold and it
        // misses these: `Σ` lowercases to `σ` while final sigma `ς` lowercases to itself, so a
        // filter of `Σ` would not have found a name spelled with `ς` — case-insensitive right up
        // until the first name that needed it. Both mappings are compared, in both directions.
        assert!(matches_module_pattern(&module_pattern("Σ"), "drvς"));
        assert!(matches_module_pattern(&module_pattern("ς"), "DRVΣ"));
        assert!(matches_module_pattern(&module_pattern("Σ"), "drvσ"));
        // …and the ones that only converge downward, which is why lowercasing stays.
        assert!(matches_module_pattern(&module_pattern("ẞ"), "straße"));

        // `?` still matches any single character, non-ASCII included — the escape hatch for a
        // name whose case does not fold per character at all.
        assert!(matches_module_pattern("nvhda?4v", "nvhdaé4v"));
    }

    /// `dx` reaches command execution through the data model, so it retires the handle too
    /// — conservatively, since the command it runs is a runtime string this server never
    /// sees. The ordinary TTD queries `dx` exists for must not trip it, or the handle would
    /// be useless for the workflow it was built for.
    #[test]
    fn dx_retires_the_handle_only_when_it_reaches_command_execution() {
        for expression in [
            "Debugger.Utility.Control.ExecuteCommand(\".opendump C:\\\\b.dmp\")",
            "@$curprocess.TTD.Events.Select(e => Debugger.Utility.Control.ExecuteCommand(\"g\"))",
            // Case is not an escape route.
            "Debugger.Utility.Control.executecommand(\".detach\")",
        ] {
            assert!(
                dx_executes_commands(expression),
                "`{expression}` must retire the handle"
            );
        }

        for expression in [
            "@$curprocess.TTD.Lifetime",
            "@$cursession.TTD.Calls(\"ntdll!Nt*\")",
            "@$cursession.TTD.Calls(\"kernelbase!CreateFileW\").Where(c => c.ReturnValue != 0)",
            "@$curprocess.TTD.Memory(0x1000, 0x2000, \"rw\")",
        ] {
            assert!(
                !dx_executes_commands(expression),
                "`{expression}` is an ordinary query and must keep the handle"
            );
        }
    }

    /// `execute` is the one path that can swap the target without going through a typed
    /// tool, so the session-control commands have to retire the handle — otherwise a
    /// `.detach` followed by `read_memory(session_id=A)` reads a target A never opened.
    #[test]
    fn session_control_commands_retire_the_handle() {
        for cmd in [
            ".detach",
            ".opendump c:\\crash.dmp",
            ".attach 0n4242",
            ".kill",
            ".restart",
            ".abandon",
            "qd",
            // Case and chaining must not be an escape route.
            ".DETACH",
            "db @rip; .detach",
            // DbgEng ends a command at a line break too, and `reject_command_breakers`
            // already refuses them in typed operands for that reason. `execute` accepts
            // them, so the scanner has to split on them.
            "r\n.opendump C:\\other.dmp",
            "r\r\n.detach",
        ] {
            assert!(
                changes_debug_target(cmd),
                "`{cmd}` should retire the handle"
            );
        }
    }

    /// Over-matching only costs a re-open, but it should still not fire on ordinary
    /// inspection commands, or the handle would be useless in practice.
    #[test]
    fn ordinary_commands_keep_the_handle() {
        for cmd in [
            "db @rip",
            "dt nt!_EPROCESS",
            "!ext.analyze -v",
            "u rip",
            "lm m HEVD",
            // Starts with a token that merely contains a listed command as a substring.
            ".sympath+ c:\\symbols\\qd",
            ".reload /f",
        ] {
            assert!(!changes_debug_target(cmd), "`{cmd}` should keep the handle");
        }
    }

    /// A failure that lands after the target is open must hand the handle back and say not
    /// to re-open. "Just open again" is how a caller ends up with two processes — before the
    /// openers were split (glslang/win-kexp#71) this server could not tell that case from a
    /// clean slate and had to hedge on every attach and launch; now it knows which it is.
    #[test]
    fn a_post_commit_failure_returns_the_handle_and_warns_against_reopening() {
        let msg = post_commit_failure("the target never broke in", "sess-1");
        assert!(
            msg.contains("the target never broke in"),
            "must keep the underlying error"
        );
        assert!(
            msg.contains("session_id: sess-1"),
            "must hand back the handle — re-opening is the only other way to get one"
        );
        assert!(
            msg.contains("second process") && msg.contains("attach a second time"),
            "must name the cost of re-running blindly, for launch and attach alike"
        );
        assert!(msg.contains("vertarget"), "must say how to inspect it");
    }

    // ---- Error reporting -----------------------------------------------

    /// Every session-scoped failure belongs in the result (`isError: true`) so the model can
    /// read it and correct itself: a bad symbol (fix the arguments), a timeout (wait, retry, or
    /// end the session), a refused handle (name a different session, or open one), a session
    /// whose worker is gone (open again). A JSON-RPC error would hide the text that says which.
    #[test]
    fn session_scoped_failures_are_tool_errors_not_protocol_errors() {
        for e in [
            EngineError::Debugger("no such symbol".into()),
            EngineError::Timeout("timed out".into()),
            EngineError::Stale("that session is closed".into()),
            EngineError::Lost("the worker exited".into()),
        ] {
            let rendered = e.to_string();
            let r = engine_result(Err(e)).expect("must not surface as a protocol error");
            assert_eq!(r.is_error, Some(true), "{rendered}");
            assert!(
                r.content
                    .iter()
                    .any(|b| b.as_text().is_some_and(|t| t.text == rendered)),
                "the explanation must survive: {rendered}"
            );
        }
    }

    /// A malformed batch must be refused *before* it reaches a session, and as a tool error the
    /// model can read. The check that proves it: this server has no session at all, so a batch
    /// that got past validation would come back complaining about that instead.
    #[tokio::test]
    async fn a_malformed_batch_is_refused_before_it_reaches_a_session() {
        let server = WindbgServer::new(Sessions::new(Duration::from_secs(1)));
        let result = server
            .debug_batch(Parameters(DebugBatchArgs {
                steps: vec![
                    serde_json::from_value(serde_json::json!({
                        "op": "command",
                        "command": "eb fffff800`00001000 {{never_bound}}"
                    }))
                    .unwrap(),
                ],
                always: Vec::new(),
                timeout_ms: None,
                session_id: None,
            }))
            .await
            .expect("a bad batch is a tool error, not a protocol error");
        assert_eq!(result.is_error, Some(true));
        let text = result
            .content
            .iter()
            .filter_map(|b| b.as_text().map(|t| t.text.clone()))
            .collect::<String>();
        assert!(text.contains("`{{never_bound}}` is not bound"), "{text}");
        assert!(
            !text.contains("session"),
            "validation must not have reached a session: {text}"
        );
        // Typed, because this tool declares an output schema and a refusal is a result like any
        // other. It is also the documented "the batch never ran" case, which is the *only* thing
        // `status: "error"` means here — a batch that ran answers `ok` and reports its verdict in
        // the payload — so a caller that cannot see this branch cannot tell "resubmit after fixing
        // the argument" from "go and look at what the target is holding".
        let data = result
            .structured_content
            .as_ref()
            .expect("a schema-bearing tool must answer with structured content");
        assert_eq!(data["status"], "error", "{data}");
        assert_eq!(data["error"]["category"], "invalid_argument", "{data}");
        assert_eq!(
            data["error"]["message"].as_str().unwrap_or_default(),
            text,
            "the typed message and the text are one failure, not two accounts of it"
        );
    }

    /// The typo that would be worst to ignore: `always` misspelt is a batch with **no rollback
    /// block**, which then applies its mutations and reports `COMMITTED` with nothing restored.
    /// Serde drops unknown fields by default, so this only fails because the struct says otherwise.
    #[test]
    fn a_misspelt_rollback_block_is_refused_rather_than_silently_dropped() {
        let args = serde_json::json!({
            "steps": [{ "op": "command", "command": "eb fffff800`00001000 90" }],
            "aways": [{ "op": "command", "command": "eb fffff800`00001000 41" }]
        });
        let refused = serde_json::from_value::<DebugBatchArgs>(args.clone())
            .err()
            .expect("an unknown field must be refused");
        assert!(
            refused.to_string().contains("aways"),
            "the refusal should name the field: {refused}"
        );

        // Spelt correctly it deserializes, and the rollback is there.
        let mut fixed = args.as_object().unwrap().clone();
        let always = fixed.remove("aways").unwrap();
        fixed.insert("always".to_string(), always);
        let parsed: DebugBatchArgs =
            serde_json::from_value(serde_json::Value::Object(fixed)).expect("valid");
        assert_eq!(parsed.always.len(), 1);
    }

    #[test]
    fn successful_output_is_not_flagged_as_an_error() {
        let r = engine_result(Ok(Output::text("rax=0000000000000000"))).unwrap();
        assert_eq!(r.is_error, Some(false));
    }

    /// A failure carries its category as a value beside the same text it always had.
    ///
    /// The point of the pair: the text is what the model reads and may be reworded at any time,
    /// while `category` is what a program branches on. A client that had to tell a stale handle
    /// from a debugger error by matching prose was one rewording away from breaking.
    #[test]
    fn a_failure_carries_its_category_beside_the_text() {
        let r = engine_result_for(
            Some("sess-7"),
            Err(EngineError::Stale("`sess-7` was retired".into())),
        )
        .unwrap();
        assert_eq!(r.is_error, Some(true));
        let structured = r.structured_content.expect("a failure is structured too");
        assert_eq!(structured["status"], "error");
        assert_eq!(structured["error"]["category"], "stale_session");
        assert_eq!(structured["error"]["session_id"], "sess-7");
        assert_eq!(structured["error"]["message"], "`sess-7` was retired");
        // And the text content is unchanged — the whole point of adding a channel rather than
        // replacing one.
        assert_eq!(
            r.content.first().and_then(|c| c.as_text()).map(|t| &t.text),
            Some(&"`sess-7` was retired".to_string())
        );
    }

    /// A failed open says whether a target exists, because that is what decides the next move.
    ///
    /// The most consequential field in this PR: `no` means opening again is the recovery, `yes`
    /// means it would attach a second time or start a second process, and `pending` means the
    /// open is still running. A future edit that returned the wrong one here would invert the
    /// advice while every other assertion stayed green — the text carries the same distinction,
    /// but only in prose, which is what this replaces.
    #[test]
    fn a_post_commit_open_failure_reports_that_a_target_exists() {
        let r = open_failure(
            ErrorCategory::Debugger,
            "the target never broke in".to_string(),
            Some("sess-3".to_string()),
            TargetCreated::Yes,
        )
        .unwrap();
        assert_eq!(r.is_error, Some(true));
        let structured = r
            .structured_content
            .expect("a failed open is structured too");
        assert_eq!(structured["status"], "error");
        assert_eq!(structured["target"], "yes");
        assert_eq!(structured["error"]["session_id"], "sess-3");

        // And the clean case says the opposite, which is the pair that matters: these two
        // failures read alike and want opposite responses.
        let clean = open_failure(
            ErrorCategory::Debugger,
            "the dump could not be opened".to_string(),
            None,
            TargetCreated::No,
        )
        .unwrap();
        let clean = clean.structured_content.expect("structured");
        assert_eq!(clean["target"], "no");
        assert!(clean["error"].get("session_id").is_none());
    }

    /// The typed half of a success is the worker's, forwarded rather than re-derived.
    #[test]
    fn a_success_forwards_the_workers_typed_answer() {
        let r = engine_result(Ok(Output::typed(
            "VERDICT: HIT",
            structured::RunToReport {
                verdict: structured::RunToVerdict::Hit,
                target: structured::addr(0xfffff803_1ab10000),
                stopped_at: Some(structured::addr(0xfffff803_1ab10000)),
                timeout_ms: 60_000,
                output: String::new(),
            },
        )))
        .unwrap();
        let structured = r.structured_content.expect("carried through");
        assert_eq!(structured["status"], "ok");
        assert_eq!(structured["verdict"], "hit");
        assert_eq!(structured["target"], "0xfffff8031ab10000");
    }

    #[test]
    fn parse_u64_decimal() {
        assert_eq!(parse_u64("4096"), Ok(4096));
        assert_eq!(parse_u64("0"), Ok(0));
    }

    #[test]
    fn parse_u64_hex_either_case_prefix() {
        assert_eq!(parse_u64("0x1000"), Ok(0x1000));
        assert_eq!(parse_u64("0X1000"), Ok(0x1000));
        assert_eq!(parse_u64("0xdeadbeef"), Ok(0xdead_beef));
    }

    #[test]
    fn parse_u64_trims_surrounding_whitespace() {
        assert_eq!(parse_u64("  4096  "), Ok(4096));
        assert_eq!(parse_u64("\t0x10\n"), Ok(0x10));
    }

    #[test]
    fn parse_u64_boundaries() {
        assert_eq!(parse_u64("18446744073709551615"), Ok(u64::MAX));
        assert_eq!(parse_u64("0xffffffffffffffff"), Ok(u64::MAX));
    }

    #[test]
    fn parse_u64_rejects_invalid() {
        for bad in ["xyz", "", "0xZZ", "0x", "-1", "12.3"] {
            let err = parse_u64(bad).unwrap_err();
            assert!(
                err.starts_with("invalid number:"),
                "unexpected error for {bad:?}: {err}"
            );
        }
    }

    #[test]
    fn hexdump_empty_is_empty() {
        assert_eq!(hexdump(0, &[]), "");
    }

    #[test]
    fn hexdump_short_row_pads_hex_column() {
        // Three bytes: the hex column is left-aligned to 47 chars, then the ASCII
        // column follows. Printable bytes pass through verbatim. Build the expected
        // padding with the same width constant rather than hand-counting spaces.
        let out = hexdump(0, b"abc");
        let expected = format!("0000000000000000  {:<47}  abc\n", "61 62 63");
        assert_eq!(out, expected);
    }

    #[test]
    fn hexdump_full_row_then_partial_advances_address() {
        let bytes: Vec<u8> = (0u8..18).collect();
        let out = hexdump(0x1000, &bytes);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("0000000000001000  "));
        // Second chunk starts 16 bytes (0x10) on.
        assert!(lines[1].starts_with("0000000000001010  "));
    }

    #[test]
    fn hexdump_renders_nonprintable_as_dot() {
        // 0x00 and 0x7f are non-printable; 'A' (0x41) is printable.
        let out = hexdump(0, &[0x00, 0x41, 0x7f]);
        assert!(out.ends_with(".A.\n"), "got: {out:?}");
    }

    #[test]
    fn decode_ioctl_disk_get_drive_geometry() {
        // IOCTL_DISK_GET_DRIVE_GEOMETRY = CTL_CODE(IOCTL_DISK_BASE=0x7, 0, BUFFERED, ANY).
        let out = decode_ioctl_text(0x70000);
        assert!(out.contains("DeviceType     0x0007"), "got: {out}");
        assert!(out.contains("FunctionCode   0x000"), "got: {out}");
        assert!(
            out.contains("Method         0 (METHOD_BUFFERED)"),
            "got: {out}"
        );
        assert!(
            out.contains("RequiredAccess 0 (FILE_ANY_ACCESS)"),
            "got: {out}"
        );
        // FILE_ANY_ACCESS is flagged; METHOD_NEITHER is not.
        assert!(out.contains("[!] FILE_ANY_ACCESS"), "got: {out}");
        assert!(!out.contains("[!] METHOD_NEITHER"), "got: {out}");
    }

    #[test]
    fn decode_ioctl_neither_write_flags_both_warnings() {
        // CTL_CODE(DeviceType=0x8000, Function=0x800, METHOD_NEITHER, FILE_WRITE_DATA).
        // Device type 0x8000 sets bit 31 — exercises a full 32-bit (unsigned) code.
        let code = (0x8000u32 << 16) | (2u32 << 14) | (0x800u32 << 2) | 3;
        let out = decode_ioctl_text(code);
        assert!(out.contains("DeviceType     0x8000"), "got: {out}");
        assert!(out.contains("FunctionCode   0x800"), "got: {out}");
        assert!(
            out.contains("Method         3 (METHOD_NEITHER)"),
            "got: {out}"
        );
        assert!(
            out.contains("RequiredAccess 2 (FILE_WRITE_DATA)"),
            "got: {out}"
        );
        assert!(out.contains("[!] METHOD_NEITHER"), "got: {out}");
        // FILE_WRITE_DATA is an access gate, so the ANY_ACCESS warning must be absent.
        assert!(!out.contains("[!] FILE_ANY_ACCESS"), "got: {out}");
    }

    // ---- reachability: parsing --------------------------------------------

    #[test]
    fn parse_windbg_addr_forms() {
        assert_eq!(
            parse_windbg_addr("fffff803`3e254750"),
            Some(0xfffff803_3e254750)
        );
        assert_eq!(
            parse_windbg_addr("(fffff803`3e2547f0)"),
            Some(0xfffff803_3e2547f0)
        );
        // Plain 32-bit (x86) hex, no backtick.
        assert_eq!(parse_windbg_addr("00401000"), Some(0x0040_1000));
        // Mnemonics, registers, labels, and short immediates are not addresses.
        assert_eq!(parse_windbg_addr("call"), None);
        assert_eq!(parse_windbg_addr("rax"), None);
        assert_eq!(parse_windbg_addr("mydriver!Foo:"), None);
        assert_eq!(parse_windbg_addr("28h"), None);
    }

    #[test]
    fn parse_uf_classifies_flow_and_skips_indirect() {
        // A function with a direct call, a conditional branch, a memory-indirect call
        // (which must classify as CallIndirect, not a resolved target), an unconditional
        // jmp, and a ret.
        let text = "\
mydriver!Dispatch:
fffff803`3e254750 4c8bdc          mov     r11,rsp
fffff803`3e254758 e893000000      call    mydriver!Helper (fffff803`3e2547f0)
fffff803`3e25475d 85c0            test    eax,eax
fffff803`3e25475f 0f8541000000    jne     mydriver!Dispatch+0x56 (fffff803`3e2547a6)
fffff803`3e254765 ff15aabbccdd    call    qword ptr [mydriver!Ptr (fffff803`3e260000)]
fffff803`3e25476b e9c0000000      jmp     mydriver!Tail (fffff803`3e254830)
fffff803`3e254770 c3              ret
";
        let b = parse_uf(text);
        assert_eq!(b.entry, Some(0xfffff803_3e254750));
        assert_eq!(b.insns.len(), 7); // 7 instruction lines; the label line is not one
        let flows: Vec<Flow> = b.insns.iter().map(|i| i.flow).collect();
        assert_eq!(
            flows,
            vec![
                Flow::Fallthrough,                 // mov
                Flow::Call(0xfffff803_3e2547f0),   // direct call
                Flow::Fallthrough,                 // test
                Flow::Branch(0xfffff803_3e2547a6), // jne
                Flow::CallIndirect,                // call qword ptr [..]
                Flow::Jmp(0xfffff803_3e254830),    // jmp
                Flow::Return,                      // ret
            ]
        );
    }

    #[test]
    fn parse_lm_base_reads_module_start() {
        let text = "\
Browse full module list
start             end                 module name
fffff803`3e250000 fffff803`3e270000   mydriver   (pdb symbols)
";
        assert_eq!(parse_lm_base(text), Some(0xfffff803_3e250000));
        assert_eq!(parse_lm_base("Unable to enumerate modules\n"), None);
    }

    #[test]
    fn parse_eval_reads_expression_value() {
        // `? mydriver!Dispatch+0x123` → the address is the hex after the `=`.
        assert_eq!(
            parse_eval("Evaluate expression: 18446735277667370832 = fffff803`3e254750"),
            Some(0xfffff803_3e254750)
        );
        assert_eq!(
            parse_eval("Evaluate expression: 4096 = 00000000`00001000"),
            Some(0x1000)
        );
        // A failed evaluation ("Couldn't resolve error ...") has no `=`/address.
        assert_eq!(parse_eval("Couldn't resolve error at 'bogus'"), None);
    }

    // ---- reachability: graph walk -----------------------------------------

    /// Builds a `uf` block whose entry is `entry`, with the given follow-on lines
    /// appended (each already a full `uf` instruction line).
    fn uf_fn(label: &str, entry: u64, body: &[&str]) -> String {
        let mut s = format!("{label}:\n{} 90              nop\n", fmt_addr(entry));
        for l in body {
            s.push_str(l);
            s.push('\n');
        }
        s
    }

    #[test]
    fn reachability_direct_call_chain() {
        let mut m: HashMap<String, String> = HashMap::new();
        m.insert(
            "start".to_string(),
            uf_fn(
                "A",
                0x1000,
                &[&format!(
                    "{} e8xx call A!B ({})",
                    fmt_addr(0x1004),
                    fmt_addr(0x2000)
                )],
            ),
        );
        m.insert(
            "0x2000".to_string(),
            uf_fn("B", 0x2000, &[&format!("{} c3 ret", fmt_addr(0x2008))]),
        );
        let r = reachability("start", None, 0x2008, 256, 32, |a| m.get(a).cloned());
        assert!(r.verdict_reachable);
        assert_eq!(r.from_entry, Some(0x1000));
        assert_eq!(r.containing_fn, Some(0x2000));
        assert_eq!(r.path, vec![(0x1004, "call", 0x2000)]);
    }

    #[test]
    fn reachability_follows_tail_jmp() {
        let mut m: HashMap<String, String> = HashMap::new();
        m.insert(
            "start".to_string(),
            uf_fn(
                "A",
                0x1000,
                &[&format!(
                    "{} e9xx jmp A!B ({})",
                    fmt_addr(0x1004),
                    fmt_addr(0x2000)
                )],
            ),
        );
        m.insert(
            "0x2000".to_string(),
            uf_fn("B", 0x2000, &[&format!("{} c3 ret", fmt_addr(0x2008))]),
        );
        let r = reachability("start", None, 0x2008, 256, 32, |a| m.get(a).cloned());
        assert!(r.verdict_reachable);
        assert_eq!(r.path, vec![(0x1004, "jmp", 0x2000)]);
    }

    #[test]
    fn reachability_target_in_seed_is_zero_hops() {
        let mut m: HashMap<String, String> = HashMap::new();
        m.insert(
            "start".to_string(),
            uf_fn("A", 0x1000, &[&format!("{} c3 ret", fmt_addr(0x1004))]),
        );
        let r = reachability("start", None, 0x1004, 256, 32, |a| m.get(a).cloned());
        assert!(r.verdict_reachable);
        assert_eq!(r.containing_fn, Some(0x1000));
        assert!(r.path.is_empty());
    }

    #[test]
    fn reachability_indirect_only_is_not_reached() {
        let mut m: HashMap<String, String> = HashMap::new();
        m.insert(
            "start".to_string(),
            uf_fn(
                "A",
                0x1000,
                &[&format!(
                    "{} ff15aa call qword ptr [A!Ptr ({})]",
                    fmt_addr(0x1004),
                    fmt_addr(0x9000)
                )],
            ),
        );
        // The target sits behind the indirect call, which is never followed.
        let r = reachability("start", None, 0x2008, 256, 32, |a| m.get(a).cloned());
        assert!(!r.verdict_reachable);
        assert!(!r.bound_hit); // graph exhausted, not a bound
    }

    #[test]
    fn reachability_cycle_terminates() {
        let mut m: HashMap<String, String> = HashMap::new();
        m.insert(
            "start".to_string(),
            uf_fn(
                "A",
                0x1000,
                &[&format!(
                    "{} e8xx call A!B ({})",
                    fmt_addr(0x1004),
                    fmt_addr(0x2000)
                )],
            ),
        );
        m.insert(
            "0x2000".to_string(),
            uf_fn(
                "B",
                0x2000,
                &[&format!(
                    "{} e8xx call B!A ({})",
                    fmt_addr(0x2004),
                    fmt_addr(0x1000)
                )],
            ),
        );
        // Target is absent — the A<->B cycle must not loop forever.
        let r = reachability("start", None, 0x7777, 256, 32, |a| m.get(a).cloned());
        assert!(!r.verdict_reachable);
        assert_eq!(r.funcs_explored, 2);
    }

    #[test]
    fn reachability_respects_function_bound() {
        let mut m: HashMap<String, String> = HashMap::new();
        m.insert(
            "start".to_string(),
            uf_fn(
                "A",
                0x1000,
                &[&format!(
                    "{} e8xx call A!B ({})",
                    fmt_addr(0x1004),
                    fmt_addr(0x2000)
                )],
            ),
        );
        m.insert(
            "0x2000".to_string(),
            uf_fn("B", 0x2000, &[&format!("{} c3 ret", fmt_addr(0x2004))]),
        );
        // Bound to a single function: B (which contains the target) is never explored.
        let r = reachability("start", None, 0x2004, 1, 32, |a| m.get(a).cloned());
        assert!(!r.verdict_reachable);
        assert!(r.bound_hit);
        assert_eq!(r.funcs_explored, 1);
    }

    #[test]
    fn reachability_scopes_from_mid_function_start() {
        // A single dispatch function: the entry does an indirect jump-table `jmp`
        // (which we don't follow), then two independent switch-case blocks. `uf` of
        // any address returns the whole function, so a mid-function `from` must NOT
        // treat the *other* case as reachable.
        let dispatch = format!(
            "Dispatch:\n\
             {} 90 nop\n\
             {} ff2500000000 jmp qword ptr [Dispatch!tbl ({})]\n\
             {} 90 nop\n\
             {} c3 ret\n\
             {} 90 nop\n\
             {} c3 ret\n",
            fmt_addr(0x1000), // entry
            fmt_addr(0x1004), // indirect jump-table switch
            fmt_addr(0x9000), // (table pointer address, not a code target)
            fmt_addr(0x1008), // case 1 block
            fmt_addr(0x100c), // case 1 body (target A)
            fmt_addr(0x1010), // case 2 block
            fmt_addr(0x1014), // case 2 body (target B)
        );
        // `uf` of any address in the function returns the whole function. `&mut uf`
        // implements FnMut, so the same disassembler can drive several walks.
        let mut uf = |a: &str| match a {
            "0x1008" | "0x1000" => Some(dispatch.clone()),
            _ => None,
        };

        // Starting inside case 1 (seed_start resolved to 0x1008), case 1's body IS reachable.
        assert!(reachability("0x1008", Some(0x1008), 0x100c, 256, 32, &mut uf).verdict_reachable);
        // ...but case 2's body is NOT reachable from case 1 (no intra-function path).
        assert!(!reachability("0x1008", Some(0x1008), 0x1014, 256, 32, &mut uf).verdict_reachable);
        // From the entry, the switch cases are unreachable — the jump table isn't followed.
        assert!(!reachability("0x1000", Some(0x1000), 0x1008, 256, 32, &mut uf).verdict_reachable);
    }

    #[test]
    fn parse_uf_classifies_traps() {
        // WinDbg emits `int 29h` / `int 3` as mnemonic `int` + operand; plus `ud2`/`hlt`.
        let text = "\
mydriver!Guard:
fffff803`3e254750 cd29            int     29h
fffff803`3e254752 0f0b            ud2
fffff803`3e254754 f4              hlt
fffff803`3e254755 cc              int     3
";
        let flows: Vec<Flow> = parse_uf(text).insns.iter().map(|i| i.flow).collect();
        assert_eq!(flows, vec![Flow::Trap, Flow::Trap, Flow::Trap, Flow::Trap]);
    }

    #[test]
    fn reachability_stops_at_trap() {
        // A function: entry, a call, then `int 29h` (fastfail, noreturn), then a block
        // that is reachable ONLY by falling through the trap. It must not be reachable.
        let func = format!(
            "Guard:\n\
             {} 90 nop\n\
             {} cd29 int 29h\n\
             {} 90 nop\n\
             {} c3 ret\n",
            fmt_addr(0x1000), // entry
            fmt_addr(0x1004), // int 29h — execution stops here
            fmt_addr(0x1006), // dead code, only reachable by falling through the trap
            fmt_addr(0x1007),
        );
        let mut uf = |a: &str| (a == "0x1000").then(|| func.clone());
        // The entry (before the trap) is reachable...
        assert!(reachability("0x1000", Some(0x1000), 0x1000, 256, 32, &mut uf).verdict_reachable);
        // ...but code after the trap is not (the walk stops at `int 29h`).
        assert!(!reachability("0x1000", Some(0x1000), 0x1006, 256, 32, &mut uf).verdict_reachable);
    }

    // ---- reachability: path recipe ----------------------------------------

    #[test]
    fn recipe_forced_direction_decodes_ioctl_predicate() {
        // Handler: `cmp [rdx+18h],222003h; jne bail`. The target block is the jne
        // fall-through, so the branch is forced to fall through, and the compare decodes
        // to `IoControlCode == 0x222003` (displacement +0x18, the IO_STACK_LOCATION offset).
        let mut m: HashMap<String, String> = HashMap::new();
        m.insert(
            "Handler".to_string(),
            uf_fn(
                "Handler",
                0x1000,
                &[
                    &format!("{} 813a cmp dword ptr [rdx+18h],222003h", fmt_addr(0x1004)),
                    &format!(
                        "{} 7506 jne Handler+0x10 ({})",
                        fmt_addr(0x1008),
                        fmt_addr(0x1010)
                    ),
                    &format!("{} 90 nop", fmt_addr(0x100c)), // target: jne fall-through
                    &format!("{} c3 ret", fmt_addr(0x100e)),
                    &format!("{} c3 ret", fmt_addr(0x1010)), // bail: jne taken
                ],
            ),
        );
        let rpt = reachability("Handler", Some(0x1000), 0x100c, 256, 32, |a| {
            m.get(a).cloned()
        });
        assert!(rpt.verdict_reachable);

        let recipes = path_recipe("Handler", Some(0x1000), &rpt, |a| m.get(a).cloned());
        assert_eq!(recipes.len(), 1);
        assert_eq!(recipes[0].start, 0x1000);
        assert_eq!(recipes[0].goal, 0x100c);
        assert_eq!(recipes[0].steps.len(), 1);
        let step = &recipes[0].steps[0];
        assert_eq!(step.site, 0x1008);
        assert_eq!(step.jcc, "jne");
        assert_eq!(step.required, Direction::Fallthrough);
        let p = step.predicate.as_ref().expect("predicate decoded");
        assert_eq!(p.field, Some(IoField::IoControlCode));
        assert_eq!(p.value, Some(0x222003));
        assert_eq!(p.relation, Some("==")); // jne, fall-through ⇒ equality holds

        let rendered = format_recipe(&recipes);
        assert!(rendered.contains("IoControlCode == 0x222003"), "{rendered}");
        assert!(rendered.contains("must fall through"), "{rendered}");
    }

    #[test]
    fn recipe_reports_concrete_direction_even_when_other_side_reaches() {
        // Both successors of the `je` can reach the goal, but the recipe reports the concrete
        // direction the path took (a sound sufficient condition) rather than "don't care" —
        // an alternate successor usually reaches the goal only via its own conditions.
        let mut m: HashMap<String, String> = HashMap::new();
        m.insert(
            "Merge".to_string(),
            uf_fn(
                "Merge",
                0x1000,
                &[
                    &format!("{} 85c0 test eax,eax", fmt_addr(0x1004)),
                    &format!(
                        "{} 7404 je Merge+0x10 ({})",
                        fmt_addr(0x1008),
                        fmt_addr(0x1010)
                    ),
                    &format!("{} 90 nop", fmt_addr(0x100c)), // fall-through, then into 0x1010
                    &format!("{} 90 nop", fmt_addr(0x1010)), // goal (also the je target)
                    &format!("{} c3 ret", fmt_addr(0x1012)),
                ],
            ),
        );
        let rpt = reachability("Merge", Some(0x1000), 0x1010, 256, 32, |a| {
            m.get(a).cloned()
        });
        assert!(rpt.verdict_reachable);

        let recipes = path_recipe("Merge", Some(0x1000), &rpt, |a| m.get(a).cloned());
        assert_eq!(recipes.len(), 1);
        assert_eq!(recipes[0].steps.len(), 1);
        assert_eq!(recipes[0].steps[0].required, Direction::Taken);
        assert!(format_recipe(&recipes).contains("must take"));
    }

    #[test]
    fn recipe_bit_test_predicate_renders_as_mask() {
        // `test [rdx+10h],20h; jne target` means `(InputBufferLength & 0x20) != 0`, not the
        // `cmp`-style `!= 0x20` — the recipe must render the bitwise mask form.
        let mut m: HashMap<String, String> = HashMap::new();
        m.insert(
            "Handler".to_string(),
            uf_fn(
                "Handler",
                0x1000,
                &[
                    &format!("{} f742 test dword ptr [rdx+10h],20h", fmt_addr(0x1004)),
                    &format!(
                        "{} 7504 jne Handler+0x10 ({})",
                        fmt_addr(0x1008),
                        fmt_addr(0x1010)
                    ),
                    &format!("{} c3 ret", fmt_addr(0x100c)),
                    &format!("{} 90 nop", fmt_addr(0x1010)), // target: jne taken
                    &format!("{} c3 ret", fmt_addr(0x1012)),
                ],
            ),
        );
        let rpt = reachability("Handler", Some(0x1000), 0x1010, 256, 32, |a| {
            m.get(a).cloned()
        });
        assert!(rpt.verdict_reachable);

        let recipes = path_recipe("Handler", Some(0x1000), &rpt, |a| m.get(a).cloned());
        let step = &recipes[0].steps[0];
        assert_eq!(step.required, Direction::Taken);
        let p = step.predicate.as_ref().expect("predicate decoded");
        assert!(p.mask);
        assert_eq!(p.field, Some(IoField::InputBufferLength));
        assert_eq!(p.value, Some(0x20));
        assert_eq!(p.relation, Some("!=")); // jne taken ⇒ bit set
        assert!(
            format_recipe(&recipes).contains("(InputBufferLength & 0x20) != 0"),
            "{}",
            format_recipe(&recipes)
        );
    }

    #[test]
    fn recipe_spans_call_path_with_one_segment_per_function() {
        // A (length gate) calls B (field gate) which contains the target. The recipe has
        // one segment per function, each routing to the next hop's site / the target.
        let mut m: HashMap<String, String> = HashMap::new();
        m.insert(
            "start".to_string(),
            uf_fn(
                "A",
                0x1000,
                &[
                    &format!("{} 817a10 cmp dword ptr [rdx+10h],20h", fmt_addr(0x1004)),
                    &format!("{} 7208 jb A+0x14 ({})", fmt_addr(0x1008), fmt_addr(0x1014)),
                    &format!("{} e8xx call A!B ({})", fmt_addr(0x100c), fmt_addr(0x2000)),
                    &format!("{} c3 ret", fmt_addr(0x1011)),
                    &format!("{} c3 ret", fmt_addr(0x1014)), // bail: jb taken
                ],
            ),
        );
        m.insert(
            "0x2000".to_string(),
            uf_fn(
                "B",
                0x2000,
                &[
                    &format!("{} 803808 cmp byte ptr [rax+8h],1", fmt_addr(0x2004)),
                    &format!(
                        "{} 7506 jne B+0x10 ({})",
                        fmt_addr(0x2008),
                        fmt_addr(0x2010)
                    ),
                    &format!("{} 90 nop", fmt_addr(0x200c)), // target: jne fall-through
                    &format!("{} c3 ret", fmt_addr(0x200e)),
                    &format!("{} c3 ret", fmt_addr(0x2010)),
                ],
            ),
        );
        let rpt = reachability("start", None, 0x200c, 256, 32, |a| m.get(a).cloned());
        assert!(rpt.verdict_reachable);
        assert_eq!(rpt.path, vec![(0x100c, "call", 0x2000)]);

        let recipes = path_recipe("start", None, &rpt, |a| m.get(a).cloned());
        assert_eq!(recipes.len(), 2);
        // Segment 1: A, routing from entry to the call site.
        assert_eq!(recipes[0].start, 0x1000);
        assert_eq!(recipes[0].goal, 0x100c);
        let a_pred = recipes[0].steps[0].predicate.as_ref().expect("A predicate");
        assert_eq!(a_pred.field, Some(IoField::InputBufferLength));
        assert_eq!(a_pred.value, Some(0x20));
        assert_eq!(recipes[0].steps[0].required, Direction::Fallthrough);
        // Segment 2: B, routing from entry to the target.
        assert_eq!(recipes[1].start, 0x2000);
        assert_eq!(recipes[1].goal, 0x200c);
        assert_eq!(recipes[1].steps[0].required, Direction::Fallthrough);
    }

    #[test]
    fn recipe_captures_conditional_branch_that_exits_the_function() {
        // A leaves to B via `jne B` — a conditional branch whose target is outside A's
        // block. The hop site is the branch itself, so the recipe must record "take this
        // branch" (taking it is what leaves A toward B), not stop short of it.
        let mut m: HashMap<String, String> = HashMap::new();
        m.insert(
            "start".to_string(),
            uf_fn(
                "A",
                0x1000,
                &[
                    &format!("{} 813a cmp dword ptr [rdx+18h],222003h", fmt_addr(0x1004)),
                    &format!("{} 7506 jne B ({})", fmt_addr(0x1008), fmt_addr(0x2000)), // exits A
                    &format!("{} c3 ret", fmt_addr(0x100c)),
                ],
            ),
        );
        m.insert(
            "0x2000".to_string(),
            uf_fn(
                "B",
                0x2000,
                &[
                    &format!("{} 90 nop", fmt_addr(0x2004)), // target
                    &format!("{} c3 ret", fmt_addr(0x2006)),
                ],
            ),
        );
        let rpt = reachability("start", None, 0x2004, 256, 32, |a| m.get(a).cloned());
        assert!(rpt.verdict_reachable);
        assert_eq!(rpt.path, vec![(0x1008, "jmp", 0x2000)]);

        let recipes = path_recipe("start", None, &rpt, |a| m.get(a).cloned());
        assert_eq!(recipes.len(), 2);
        // Segment 1 (A): the exit branch is captured as a required "take" with its predicate.
        assert_eq!(recipes[0].steps.len(), 1);
        let exit = &recipes[0].steps[0];
        assert_eq!(exit.site, 0x1008);
        assert_eq!(exit.jcc, "jne");
        assert_eq!(exit.required, Direction::Taken);
        let p = exit.predicate.as_ref().expect("exit predicate decoded");
        assert_eq!(p.field, Some(IoField::IoControlCode));
        assert_eq!(p.value, Some(0x222003));
        assert_eq!(p.relation, Some("!=")); // jne taken ⇒ inequality leaves toward B
    }
}
