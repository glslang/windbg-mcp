//! The MCP server: a curated set of debugger tools plus a raw command passthrough.
//!
//! Every tool marshals its work onto the engine thread via [`EngineHandle`]. Most
//! tools are thin wrappers over `execute_command` (the universal DbgEng escape
//! hatch, returning full text); session-management tools call the typed
//! `win-kexp` methods and then wait for the target to stop.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use rmcp::ErrorData;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content};
use schemars::JsonSchema;
use serde::Deserialize;

use win_kexp::dbgeng::{DebugEngine, RunToOutcome};

use crate::engine::{EngineError, EngineHandle};
use crate::ttd;

/// How long to wait for a target to stop after open/attach/launch (ms).
const LOAD_WAIT_MS: u32 = 60_000;
/// How long to wait for an execution-control command (go/step/reverse) to reach its
/// next stop (ms).
const EXEC_WAIT_MS: u32 = 60_000;

/// Counter behind [`mint_session_id`]. Only needs to be unique within this process.
static SESSION_SEQ: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
pub struct WindbgServer {
    engine: EngineHandle,
    /// Handle identifying the debug session the engine is currently attached to, or
    /// `None` when no target is open. See [`WindbgServer::check_session`] for why this
    /// exists rather than letting the connection stand in for the session.
    session: Arc<Mutex<Option<String>>>,
}

/// Maps any error to a `String` for the engine `Reply` channel.
fn es<E: ToString>(e: E) -> String {
    e.to_string()
}

fn text_result(s: String) -> Result<CallToolResult, ErrorData> {
    Ok(CallToolResult::success(vec![Content::text(s)]))
}

/// A tool-execution error: something the model should see in the result and can act on,
/// as opposed to a JSON-RPC protocol error it cannot.
fn tool_error(s: String) -> Result<CallToolResult, ErrorData> {
    Ok(CallToolResult::error(vec![Content::text(s)]))
}

/// Renders an engine outcome using the MCP error model.
///
/// A failed *debugger operation* (bad symbol, unreadable address, target that never
/// stopped) is feedback the model can act on, so it comes back as a tool-execution
/// error with the text intact. Only a broken engine — the one thing no amount of
/// retrying will fix — becomes a JSON-RPC protocol error.
fn engine_result(r: Result<String, EngineError>) -> Result<CallToolResult, ErrorData> {
    match r {
        Ok(out) => text_result(out),
        Err(EngineError::Debugger(m)) => tool_error(m),
        Err(EngineError::Unavailable(m)) => Err(ErrorData::internal_error(m, None)),
    }
}

/// Mints a fresh session handle. Unique per process, which is all the guard needs:
/// the handle exists to detect *replacement* of the target, not to authenticate.
fn mint_session_id() -> String {
    let n = SESSION_SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    format!("sess-{nanos:x}-{n}")
}

/// Parses a decimal or `0x`-prefixed hex integer.
fn parse_u64(s: &str) -> Result<u64, String> {
    let t = s.trim();
    let parsed = if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(h, 16)
    } else {
        t.parse::<u64>()
    };
    parsed.map_err(|_| format!("invalid number: {s}"))
}

fn hexdump(base: u64, bytes: &[u8]) -> String {
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
fn parse_windbg_addr(tok: &str) -> Option<u64> {
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
fn parse_lm_base(text: &str) -> Option<u64> {
    text.lines()
        .find_map(|l| l.split_whitespace().next().and_then(parse_windbg_addr))
}

/// Parses the value from WinDbg `?` (evaluate-expression) output, e.g.
/// "Evaluate expression: 18446735277667370832 = fffff803`3e254750" — the address
/// is the hex token after the `=`. Used to resolve a symbolic/backtick `from` (like
/// `mydriver!Dispatch+0x123`) to the numeric VA the intra-function walk starts at.
fn parse_eval(text: &str) -> Option<u64> {
    let rhs = text.split('=').nth(1)?;
    parse_windbg_addr(rhs.split_whitespace().next()?)
}

/// Outcome of a reachability walk. `verdict_reachable` is sound (a concrete static
/// path exists); a false verdict is best-effort within the explored bounds.
struct Report {
    verdict_reachable: bool,
    /// Resolved entry of the `from` function (None if `from` didn't disassemble).
    from_entry: Option<u64>,
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
fn reachability(
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
fn fmt_addr(a: u64) -> String {
    format!("{:08x}`{:08x}", a >> 32, a & 0xffff_ffff)
}

/// Renders a [`Report`] as the tool's text output.
fn format_report(r: &Report) -> String {
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
struct SegmentRecipe {
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
fn path_recipe(
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
fn format_recipe(recipes: &[SegmentRecipe]) -> String {
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

#[derive(Deserialize, JsonSchema)]
pub struct PathArgs {
    /// Filesystem path to the dump (.dmp) or TTD trace (.run) file.
    pub path: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct ConnectionArgs {
    /// Kernel debugging connection string, e.g. "net:port=50000,key=...".
    pub connection: String,
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

// ---- Session handles -----------------------------------------------------
//
// One process drives one DbgEng session, but an MCP connection is explicitly *not*
// a session: clients may interleave unrelated requests over the same stdio process,
// so "the target the last open_* call attached to" is not a safe thing for a tool to
// assume. Rather than silently operating on whatever target happens to be loaded,
// the session-creating tools mint a handle and every other tool accepts it and
// refuses to run when it no longer matches.
//
// The handle is optional so existing callers keep working; supplying it is what buys
// the guarantee that a call which does supply one can never land on a target it did
// not open.
//
// That guarantee only holds because both the check and the session transition happen
// **on the engine thread**, inside the same queued job as the debugger call itself.
// Checking on the async side instead would be a time-of-check/time-of-use bug: with
// session A current, an `open_dump` for B can already be in flight while `session`
// still reads A, so an `end_session(session_id=A)` would pass the check, queue behind
// the open, and then close B. The engine queue is the only serialisation point that
// orders against DbgEng access, so the gate has to live on it.

/// The session-handle policy, as a pure function so it unit-tests without an engine.
///
/// `supplied == None` means the caller opted out of the check and accepts whatever
/// session is current — the behaviour from before handles existed. A handle that does
/// not match is refused rather than silently honoured, because honouring it means
/// reading memory from, or setting breakpoints on, a target the caller never opened.
fn check_session_handle(current: Option<&str>, supplied: Option<&str>) -> Result<(), String> {
    let Some(want) = supplied else {
        return Ok(());
    };
    match current {
        Some(cur) if cur == want => Ok(()),
        Some(cur) => Err(format!(
            "stale session handle `{want}`: this server is now debugging session `{cur}`. \
             The debug target was replaced after you opened yours — this stdio process is \
             shared, not per-conversation. Re-open your target, or omit `session_id` to \
             operate on whatever session is current."
        )),
        None => Err(format!(
            "stale session handle `{want}`: this server has no debug session open — it was \
             ended, or never started. Re-open your target with open_dump / open_trace / \
             attach_process / attach_kernel / attach_kernel_local / launch."
        )),
    }
}

/// A poisoned lock only ever means a previous holder panicked mid-update; the value is a
/// plain `Option<String>` and cannot be left inconsistent, so recovering beats poisoning
/// every later tool call. The lock is never held across a debugger operation.
fn lock(session: &Mutex<Option<String>>) -> std::sync::MutexGuard<'_, Option<String>> {
    session.lock().unwrap_or_else(|e| e.into_inner())
}

/// Builds the deferred session check.
///
/// The returned closure reads the session *when it runs*, not when it is built — that is
/// the whole point, and it is why the gate must be handed to the engine thread rather than
/// evaluated by the caller. Free function so it tests without an engine.
fn session_gate_for(
    session: Arc<Mutex<Option<String>>>,
    supplied: Option<&str>,
) -> impl FnOnce() -> Result<(), String> + Send + 'static + use<> {
    let supplied = supplied.map(str::to_owned);
    move || check_session_handle(lock(&session).as_deref(), supplied.as_deref())
}

impl WindbgServer {
    /// Builds the session gate for a caller-supplied handle. The returned closure is run
    /// *by the engine thread*, immediately before the debugger operation it guards — see
    /// the module note above for why checking any earlier is unsound.
    fn session_gate(
        &self,
        supplied: Option<&str>,
    ) -> impl FnOnce() -> Result<(), String> + Send + 'static + use<> {
        session_gate_for(Arc::clone(&self.session), supplied)
    }

    /// Runs a session-opening operation and takes ownership of the session in the same
    /// queued job, so no other call can be ordered across the transition.
    async fn opened_result<F>(&self, f: F) -> Result<CallToolResult, ErrorData>
    where
        F: FnOnce(&DebugEngine) -> Result<String, String> + Send + 'static,
    {
        let id = mint_session_id();
        let session = Arc::clone(&self.session);
        let new_id = id.clone();
        let out = self
            .engine
            .run(move |e| {
                // The target is being replaced, so every handle issued so far is stale from
                // here on — including if the open fails partway and leaves the engine holding
                // neither the old target nor a usable new one.
                *lock(&session) = None;
                let out = f(e)?;
                *lock(&session) = Some(new_id);
                Ok(out)
            })
            .await;
        match out {
            Ok(out) => text_result(format!(
                "{out}\n\nsession_id: {id}\nPass this as `session_id` on later calls so they \
                 fail loudly instead of silently acting on a different target if this \
                 server's session is replaced."
            )),
            Err(e) => engine_result(Err(e)),
        }
    }
}

// ---- Tools ---------------------------------------------------------------

#[rmcp::tool_router]
impl WindbgServer {
    pub fn new(engine: EngineHandle) -> Self {
        Self {
            engine,
            session: Arc::new(Mutex::new(None)),
        }
    }

    /// Open a crash dump (.dmp) or a Time Travel Debugging trace (.run) and wait for it to load.
    /// Replaces any session already open, and returns a `session_id` for later calls.
    #[rmcp::tool(annotations(
        title = "Open crash dump or TTD trace",
        read_only_hint = false,
        destructive_hint = true,
        idempotent_hint = false,
        open_world_hint = true
    ))]
    async fn open_dump(
        &self,
        Parameters(args): Parameters<PathArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.opened_result(move |e| {
            e.open_dump(&args.path).map_err(es)?;
            e.wait_for_event(LOAD_WAIT_MS).map_err(es)?;
            // Load the WinDbg extension DLL so `!`-extension commands resolve — most
            // importantly `!ext.analyze -v`, the crash-dump triage workhorse. A bare
            // engine doesn't auto-load it, and even after `.load ext` the unqualified
            // `!analyze` won't resolve, so callers must use `!ext.analyze`. Best-effort:
            // a minimal engine without a bundled `winext\` directory simply won't have
            // ext.dll, which must not fail the open (live/dump state is still usable).
            let _ = e.execute_command(".load ext");
            e.execute_command("lm").map_err(es)
        })
        .await
    }

    /// Open a TTD trace (.run); alias of open_dump. Enables time-travel navigation and TTD queries.
    /// Replaces any session already open, and returns a `session_id` for later calls.
    #[rmcp::tool(annotations(
        title = "Open TTD trace",
        read_only_hint = false,
        destructive_hint = true,
        idempotent_hint = false,
        open_world_hint = true
    ))]
    async fn open_trace(
        &self,
        Parameters(args): Parameters<PathArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.opened_result(move |e| {
                e.open_trace(&args.path).map_err(es)?;
                e.wait_for_event(LOAD_WAIT_MS).map_err(es)?;
                // Check the index state *before* any data-model query: `!ttdext.index -status`
                // only reads the on-disk .idx (never builds), whereas a `dx` on an unindexed
                // trace can itself trigger the long in-memory index build. TtdExt reports a
                // healthy, ready index as exactly "Index file loaded."; per MS guidance treat
                // anything else (missing, out of date, corrupt, unloadable) as needing an index.
                // A blank result means the status query itself failed — don't warn then.
                let needs_index = {
                    let status = e
                        .execute_command("!ttdext.index -status")
                        .unwrap_or_default();
                    !status.trim().is_empty()
                        && !status.to_ascii_lowercase().contains("index file loaded")
                };
                // Confirm TTD replay is active and report the trace's position span. Lifetime
                // is cheap metadata (min/max position); the expensive indexing is triggered by
                // Calls/Memory/Events queries, which is what the note below warns about.
                let mut out = e
                    .execute_command("dx @$curprocess.TTD.Lifetime")
                    .map_err(es)?;
                if needs_index {
                    out.push_str(
                        "\nNote: this trace's index is not loaded (missing, out of date, or \
                         unusable). The first data-model query (ttd_calls/ttd_memory/ttd_events/dx) \
                         then builds an in-memory index and can run long — let it finish before \
                         issuing more queries. Run index_trace to (re)build a persistent .idx \
                         (fast queries and re-opens).",
                    );
                }
                Ok(out)
        })
        .await
    }

    /// Attach to the local kernel (live local kernel debugging).
    /// Replaces any session already open, and returns a `session_id` for later calls.
    #[rmcp::tool(annotations(
        title = "Attach to local kernel",
        read_only_hint = false,
        destructive_hint = true,
        idempotent_hint = false,
        open_world_hint = true
    ))]
    async fn attach_kernel_local(&self) -> Result<CallToolResult, ErrorData> {
        self.opened_result(move |e| {
            // attach_local_kernel breaks the target in internally (INITIAL_BREAK +
            // an INFINITE wait, as a live kernel requires).
            e.attach_local_kernel().map_err(es)?;
            // The driver_object/device_object/irp_stack tools use kernel-extension
            // commands (!drvobj/!devobj/!irp) from kdexts.dll, which a bare engine does
            // not auto-load. Best-effort, like open_dump's `.load ext`; harmless if the
            // extension isn't bundled (those tools then report a clean "no export").
            let _ = e.execute_command(".load kdexts");
            e.execute_command("vertarget").map_err(es)
        })
        .await
    }

    /// Attach to a kernel target over a connection string (e.g. KDNET).
    /// Replaces any session already open, and returns a `session_id` for later calls.
    #[rmcp::tool(annotations(
        title = "Attach to kernel target",
        read_only_hint = false,
        destructive_hint = true,
        idempotent_hint = false,
        open_world_hint = true
    ))]
    async fn attach_kernel(
        &self,
        Parameters(args): Parameters<ConnectionArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.opened_result(move |e| {
            // attach_kernel connects, requests an initial break, and waits (INFINITE,
            // as a live kernel requires) for the break-in — all internally.
            e.attach_kernel(&args.connection).map_err(es)?;
            // Load kdexts.dll so the driver_object/device_object/irp_stack tools'
            // !drvobj/!devobj/!irp commands resolve (see attach_kernel_local). Best-effort.
            let _ = e.execute_command(".load kdexts");
            e.execute_command("vertarget").map_err(es)
        })
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
        let gate = self.session_gate(args.session_id.as_deref());
        let append = args.append.unwrap_or(true);
        let out = self
            .engine
            .run(move |e| {
                gate()?;
                if append {
                    e.append_symbol_path(&args.path).map_err(es)?;
                } else {
                    e.set_symbol_path(&args.path).map_err(es)?;
                }
                // Reload so the new path takes effect (default: all deferred modules).
                e.reload_symbols(args.reload.as_deref().unwrap_or(""))
                    .map_err(es)?;
                // Echo the effective path so the caller can confirm what resolved.
                e.execute_command(".sympath").map_err(es)
            })
            .await;
        engine_result(out)
    }

    /// Attach to an existing user-mode process by PID and break in.
    /// Replaces any session already open, and returns a `session_id` for later calls.
    #[rmcp::tool(annotations(
        title = "Attach to process",
        read_only_hint = false,
        destructive_hint = true,
        idempotent_hint = false,
        open_world_hint = true
    ))]
    async fn attach_process(
        &self,
        Parameters(args): Parameters<PidArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let pid = args.pid;
        self.opened_result(move |e| {
            // attach_process waits for the break-in internally.
            e.attach_process(pid).map_err(es)?;
            e.execute_command("r").map_err(es)
        })
        .await
    }

    /// Launch a new user-mode process under the debugger, stopping at the initial breakpoint.
    /// Replaces any session already open, and returns a `session_id` for later calls.
    #[rmcp::tool(annotations(
        title = "Launch process under debugger",
        read_only_hint = false,
        destructive_hint = true,
        idempotent_hint = false,
        open_world_hint = true
    ))]
    async fn launch(
        &self,
        Parameters(args): Parameters<CommandLineArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.opened_result(move |e| {
            // launch_process waits for the initial break internally.
            e.launch_process(&args.command_line).map_err(es)?;
            e.execute_command("r").map_err(es)
        })
        .await
    }

    /// End the current debug session (detach/close the target) without exiting the server.
    /// Pass `session_id` to be sure you are ending your own session and not one another
    /// caller opened in the meantime.
    #[rmcp::tool(annotations(
        title = "End debug session",
        read_only_hint = false,
        destructive_hint = true,
        idempotent_hint = true,
        open_world_hint = false
    ))]
    async fn end_session(
        &self,
        Parameters(args): Parameters<SessionArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let gate = self.session_gate(args.session_id.as_deref());
        let session = Arc::clone(&self.session);
        let out = self
            .engine
            .run(move |e| {
                gate()?;
                let out = e
                    .end_session()
                    .map(|_| "session ended".to_string())
                    .map_err(es)?;
                // Cleared in the same job as the teardown, so a call queued behind this one
                // sees "no session open" rather than a handle that outlived its target.
                *lock(&session) = None;
                Ok(out)
            })
            .await;
        engine_result(out)
    }

    /// Run a raw debugger command and return its full output. The universal escape hatch.
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
        let gate = self.session_gate(args.session_id.as_deref());
        // Bounded: a runaway raw command (e.g. an unbounded `s` search) self-aborts instead
        // of pinning the engine thread and wedging every later call.
        let out = self.engine.run_command(args.command, gate).await;
        engine_result(out)
    }

    /// Show the current register set.
    #[rmcp::tool(annotations(
        title = "Show registers",
        read_only_hint = true,
        open_world_hint = false
    ))]
    async fn registers(
        &self,
        Parameters(args): Parameters<SessionArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let gate = self.session_gate(args.session_id.as_deref());
        let out = self
            .engine
            .run(move |e| {
                gate()?;
                e.registers().map_err(es)
            })
            .await;
        // DbgEng prints nothing for `r` when there is no live thread context (e.g. a
        // module-load break, or a bare goto_position to the very start of a trace).
        let out = out.map(|s| {
            if s.trim().is_empty() {
                "(no thread register context at this position — e.g. a module-load break or \
                 the start of a trace. Travel to a settled position after a go/breakpoint, or \
                 read a specific register with execute { \"command\": \"r rip\" }.)"
                    .to_string()
            } else {
                s
            }
        });
        engine_result(out)
    }

    /// Read process/kernel virtual memory and return a hex dump.
    #[rmcp::tool(annotations(
        title = "Read memory",
        read_only_hint = true,
        open_world_hint = false
    ))]
    async fn read_memory(
        &self,
        Parameters(args): Parameters<ReadMemoryArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let gate = self.session_gate(args.session_id.as_deref());
        let size = args.size;
        let out = self
            .engine
            .run(move |e| {
                gate()?;
                let addr = parse_u64(&args.address)?;
                let bytes = e.read_memory(addr, size as usize).map_err(es)?;
                Ok(hexdump(addr, &bytes))
            })
            .await;
        engine_result(out)
    }

    /// Show the call stack of the current thread (`k`).
    #[rmcp::tool(annotations(
        title = "Show call stack",
        read_only_hint = true,
        open_world_hint = false
    ))]
    async fn backtrace(
        &self,
        Parameters(args): Parameters<SessionArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let gate = self.session_gate(args.session_id.as_deref());
        let out = self
            .engine
            .run(move |e| {
                gate()?;
                e.execute_command("k").map_err(es)
            })
            .await;
        engine_result(out)
    }

    /// List loaded modules (`lm`).
    #[rmcp::tool(annotations(
        title = "List modules",
        read_only_hint = true,
        open_world_hint = false
    ))]
    async fn modules(
        &self,
        Parameters(args): Parameters<SessionArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let gate = self.session_gate(args.session_id.as_deref());
        let out = self
            .engine
            .run(move |e| {
                gate()?;
                e.execute_command("lm").map_err(es)
            })
            .await;
        engine_result(out)
    }

    /// List threads (`~`).
    #[rmcp::tool(annotations(
        title = "List threads",
        read_only_hint = true,
        open_world_hint = false
    ))]
    async fn threads(
        &self,
        Parameters(args): Parameters<SessionArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let gate = self.session_gate(args.session_id.as_deref());
        let out = self
            .engine
            .run(move |e| {
                gate()?;
                e.execute_command("~").map_err(es)
            })
            .await;
        engine_result(out)
    }

    /// Disassemble at an address/symbol (or the current IP).
    #[rmcp::tool(annotations(
        title = "Disassemble",
        read_only_hint = true,
        open_world_hint = false
    ))]
    async fn disassemble(
        &self,
        Parameters(args): Parameters<DisassembleArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let gate = self.session_gate(args.session_id.as_deref());
        let cmd = match args.address {
            Some(a) => format!("u {a}"),
            None => "u".to_string(),
        };
        let out = self
            .engine
            .run(move |e| {
                gate()?;
                e.execute_command(&cmd).map_err(es)
            })
            .await;
        engine_result(out)
    }

    /// Evaluate a data-model (LINQ) expression with `dx` — ideal for TTD queries.
    #[rmcp::tool(annotations(
        title = "Evaluate data-model expression",
        read_only_hint = false,
        destructive_hint = false,
        idempotent_hint = false,
        open_world_hint = false
    ))]
    async fn dx(&self, Parameters(args): Parameters<DxArgs>) -> Result<CallToolResult, ErrorData> {
        let gate = self.session_gate(args.session_id.as_deref());
        let cmd = format!("dx {}", args.expression);
        // Bounded: a data-model query that runs away (e.g. a heavy LINQ or index build on a
        // huge trace) self-aborts rather than pinning the engine thread.
        let out = self.engine.run_command(cmd, gate).await;
        engine_result(out)
    }

    /// TTD: find every call to a function across the whole trace
    /// (`dx @$cursession.TTD.Calls(...)`). Each result carries the time, thread,
    /// parameters, and return value. Append LINQ in a follow-up `dx`/`execute` to
    /// filter (e.g. `.Where(c => c.ReturnValue != 0)`).
    #[rmcp::tool(annotations(
        title = "TTD: find calls to a function",
        read_only_hint = true,
        open_world_hint = false
    ))]
    async fn ttd_calls(
        &self,
        Parameters(args): Parameters<TtdCallsArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let gate = self.session_gate(args.session_id.as_deref());
        let cmd = format!("dx @$cursession.TTD.Calls(\"{}\")", args.function);
        let out = self.engine.run_command(cmd, gate).await;
        engine_result(out)
    }

    /// TTD: find every access to a memory range across the trace
    /// (`dx @$cursession.TTD.Memory(start, end, mode)`) — when and from where it was
    /// read, written, or executed.
    #[rmcp::tool(annotations(
        title = "TTD: find accesses to a memory range",
        read_only_hint = true,
        open_world_hint = false
    ))]
    async fn ttd_memory(
        &self,
        Parameters(args): Parameters<TtdMemoryArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let gate = self.session_gate(args.session_id.as_deref());
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
        let out = self.engine.run_command(cmd, gate).await;
        engine_result(out)
    }

    /// TTD: list trace events — module loads/unloads, thread create/exit, and
    /// exceptions (`dx @$curprocess.TTD.Events`). Events and Threads hang off
    /// `@$curprocess.TTD`; Calls and Memory hang off `@$cursession.TTD`.
    #[rmcp::tool(annotations(
        title = "TTD: list trace events",
        read_only_hint = true,
        open_world_hint = false
    ))]
    async fn ttd_events(
        &self,
        Parameters(args): Parameters<SessionArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let gate = self.session_gate(args.session_id.as_deref());
        let out = self
            .engine
            .run_command("dx -r2 @$curprocess.TTD.Events".to_string(), gate)
            .await;
        engine_result(out)
    }

    /// Set a breakpoint at a symbol, address, or expression (`bp`).
    #[rmcp::tool(annotations(
        title = "Set breakpoint",
        read_only_hint = false,
        destructive_hint = false,
        idempotent_hint = false,
        open_world_hint = false
    ))]
    async fn set_breakpoint(
        &self,
        Parameters(args): Parameters<BreakpointArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let gate = self.session_gate(args.session_id.as_deref());
        let cmd = format!("bp {}", args.expression);
        let out = self
            .engine
            .run(move |e| {
                gate()?;
                e.execute_command(&cmd).map_err(es)
            })
            .await;
        engine_result(out)
    }

    /// Continue execution (`g`). Runs to the next breakpoint, or the end of a TTD trace.
    #[rmcp::tool(annotations(
        title = "Continue execution",
        read_only_hint = false,
        destructive_hint = true,
        idempotent_hint = false,
        open_world_hint = false
    ))]
    async fn go(
        &self,
        Parameters(args): Parameters<SessionArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let gate = self.session_gate(args.session_id.as_deref());
        let out = self
            .engine
            .run(move |e| {
                gate()?;
                e.execute_and_wait("g", EXEC_WAIT_MS).map_err(es)
            })
            .await;
        engine_result(out)
    }

    /// Run the target until it reaches `address` (a one-shot `g <addr>` that doesn't
    /// disturb existing breakpoints) and report a structured verdict: HIT (reached it),
    /// STOPPED ELSEWHERE (another breakpoint/exception fired first), or TIMEOUT (not
    /// reached in time). Confirms *live* that the current input/state drives execution to
    /// a block — e.g. one from `reachable_from_dispatch`. Needs a real KDNET/VM kernel
    /// target (a local kernel can't set code breakpoints).
    #[rmcp::tool(annotations(
        title = "Run to address",
        read_only_hint = false,
        destructive_hint = true,
        idempotent_hint = false,
        open_world_hint = false
    ))]
    async fn run_to_address(
        &self,
        Parameters(args): Parameters<RunToAddressArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let gate = self.session_gate(args.session_id.as_deref());
        let out = self
            .engine
            .run(move |e| {
                gate()?;
                // Resolve the target the same WinDbg-aware way as `reachable_from_dispatch`.
                let resolve = |expr: &str| -> Option<u64> {
                    e.execute_command(&format!("? {expr}"))
                        .ok()
                        .as_deref()
                        .and_then(parse_eval)
                        .or_else(|| parse_windbg_addr(expr))
                        .or_else(|| parse_u64(expr).ok())
                };
                let target = resolve(&args.address)
                    .ok_or_else(|| format!("could not resolve address `{}`", args.address))?;
                let wait = args.timeout_ms.unwrap_or(EXEC_WAIT_MS);

                let res = e.run_to_address(target, wait).map_err(es)?;
                let mut msg = match res.outcome {
                    RunToOutcome::Hit => {
                        format!("VERDICT: HIT — execution reached {}\n", fmt_addr(target))
                    }
                    RunToOutcome::StoppedElsewhere { stopped_at } => format!(
                        "VERDICT: STOPPED ELSEWHERE — stopped at {} before reaching {}\n  \
                         (another breakpoint or exception fired first)\n",
                        fmt_addr(stopped_at),
                        fmt_addr(target)
                    ),
                    RunToOutcome::Timeout => format!(
                        "VERDICT: TIMEOUT — did not reach {} within {wait} ms\n  \
                         (the current input/state likely does not drive execution to this block)\n",
                        fmt_addr(target)
                    ),
                };
                if !res.output.trim().is_empty() {
                    msg.push_str("---- debugger output ----\n");
                    msg.push_str(&res.output);
                }
                Ok(msg)
            })
            .await;
        engine_result(out)
    }

    /// Step over one source/instruction step (`p`).
    #[rmcp::tool(annotations(
        title = "Step over",
        read_only_hint = false,
        destructive_hint = true,
        idempotent_hint = false,
        open_world_hint = false
    ))]
    async fn step_over(
        &self,
        Parameters(args): Parameters<SessionArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let gate = self.session_gate(args.session_id.as_deref());
        let out = self
            .engine
            .run(move |e| {
                gate()?;
                e.execute_and_wait("p", EXEC_WAIT_MS).map_err(es)
            })
            .await;
        engine_result(out)
    }

    /// Step into one instruction (`t`).
    #[rmcp::tool(annotations(
        title = "Step into",
        read_only_hint = false,
        destructive_hint = true,
        idempotent_hint = false,
        open_world_hint = false
    ))]
    async fn step_into(
        &self,
        Parameters(args): Parameters<SessionArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let gate = self.session_gate(args.session_id.as_deref());
        let out = self
            .engine
            .run(move |e| {
                gate()?;
                e.execute_and_wait("t", EXEC_WAIT_MS).map_err(es)
            })
            .await;
        engine_result(out)
    }

    /// Step backward one instruction in a TTD trace (`t-`). Reverse of step_into.
    // The reverse-navigation tools only work on a TTD trace, which is a recorded replay:
    // moving through it cannot destroy state, unlike stepping a live target.
    #[rmcp::tool(annotations(
        title = "Step back (TTD)",
        read_only_hint = false,
        destructive_hint = false,
        idempotent_hint = false,
        open_world_hint = false
    ))]
    async fn step_back(
        &self,
        Parameters(args): Parameters<SessionArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let gate = self.session_gate(args.session_id.as_deref());
        let out = self
            .engine
            .run(move |e| {
                gate()?;
                e.execute_and_wait("t-", EXEC_WAIT_MS).map_err(es)
            })
            .await;
        engine_result(out)
    }

    /// Step over one call backward in a TTD trace (`p-`). Reverse of step_over.
    #[rmcp::tool(annotations(
        title = "Step over back (TTD)",
        read_only_hint = false,
        destructive_hint = false,
        idempotent_hint = false,
        open_world_hint = false
    ))]
    async fn step_over_back(
        &self,
        Parameters(args): Parameters<SessionArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let gate = self.session_gate(args.session_id.as_deref());
        let out = self
            .engine
            .run(move |e| {
                gate()?;
                e.execute_and_wait("p-", EXEC_WAIT_MS).map_err(es)
            })
            .await;
        engine_result(out)
    }

    /// Reverse-continue: run the TTD trace backward until a breakpoint or its start (`g-`).
    #[rmcp::tool(annotations(
        title = "Reverse continue (TTD)",
        read_only_hint = false,
        destructive_hint = false,
        idempotent_hint = false,
        open_world_hint = false
    ))]
    async fn reverse_go(
        &self,
        Parameters(args): Parameters<SessionArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let gate = self.session_gate(args.session_id.as_deref());
        let out = self
            .engine
            .run(move |e| {
                gate()?;
                e.execute_and_wait("g-", EXEC_WAIT_MS).map_err(es)
            })
            .await;
        engine_result(out)
    }

    /// Travel to a specific position in a TTD trace (`!tt <position>`).
    #[rmcp::tool(annotations(
        title = "Go to TTD position",
        read_only_hint = false,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = false
    ))]
    async fn goto_position(
        &self,
        Parameters(args): Parameters<PositionArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let gate = self.session_gate(args.session_id.as_deref());
        let cmd = format!("!tt {}", args.position);
        let out = self
            .engine
            .run(move |e| {
                gate()?;
                e.execute_command(&cmd).map_err(es)
            })
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
    #[rmcp::tool(annotations(
        title = "Build TTD trace index",
        read_only_hint = false,
        destructive_hint = false,
        idempotent_hint = true,
        open_world_hint = true
    ))]
    async fn index_trace(
        &self,
        Parameters(args): Parameters<SessionArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let gate = self.session_gate(args.session_id.as_deref());
        let out = self
            .engine
            .run(move |e| {
                gate()?;
                e.execute_command("!ttdext.index -force").map_err(es)
            })
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
        open_world_hint = false
    ))]
    async fn driver_object(
        &self,
        Parameters(args): Parameters<DriverObjectArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let gate = self.session_gate(args.session_id.as_deref());
        let cmd = format!("!drvobj {} 7", args.name);
        let out = self
            .engine
            .run(move |e| {
                gate()?;
                e.execute_command(&cmd).map_err(es)
            })
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
        open_world_hint = false
    ))]
    async fn device_object(
        &self,
        Parameters(args): Parameters<DeviceObjectArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let gate = self.session_gate(args.session_id.as_deref());
        let cmd = format!("!devobj {}", args.device);
        let out = self
            .engine
            .run(move |e| {
                gate()?;
                e.execute_command(&cmd).map_err(es)
            })
            .await;
        engine_result(out)
    }

    /// Dump the current IO_STACK_LOCATION of an IRP (`!irp <irp> 1`): major/minor,
    /// IoControlCode, input/output buffer lengths, and buffer pointers. Defaults the IRP
    /// to `@rdx` (the PIRP at the dispatch entry on x64) — valid only before stepping.
    #[rmcp::tool(annotations(
        title = "Dump IRP stack location",
        read_only_hint = true,
        open_world_hint = false
    ))]
    async fn irp_stack(
        &self,
        Parameters(args): Parameters<IrpStackArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let gate = self.session_gate(args.session_id.as_deref());
        let irp = args.irp.unwrap_or_else(|| "@rdx".to_string());
        let cmd = format!("!irp {irp} 1");
        let out = self
            .engine
            .run(move |e| {
                gate()?;
                e.execute_command(&cmd).map_err(es)
            })
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
        open_world_hint = false
    ))]
    async fn ioctl_trace(
        &self,
        Parameters(args): Parameters<IoctlTraceArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let gate = self.session_gate(args.session_id.as_deref());
        // IRP in @rdx at dispatch entry (x64). CurrentStackLocation = poi(Irp+0xb8).
        // Within IO_STACK_LOCATION: OutputBufferLength +0x08, InputBufferLength +0x10,
        // IoControlCode +0x18 (Parameters union begins at +0x08).
        let cmd = format!(
            "bp {} \".printf \\\"IOCTL %08x in=%x out=%x\\\\n\\\", \
             dwo(poi(@rdx+0xb8)+0x18), dwo(poi(@rdx+0xb8)+0x10), dwo(poi(@rdx+0xb8)+0x08); gc\"",
            args.dispatch
        );
        let out = self
            .engine
            .run(move |e| {
                gate()?;
                e.execute_command(&cmd).map_err(es)
            })
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
        open_world_hint = false
    ))]
    async fn reachable_from_dispatch(
        &self,
        Parameters(args): Parameters<ReachabilityArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let gate = self.session_gate(args.session_id.as_deref());
        let out = self
            .engine
            .run(move |e| {
                gate()?;
                // Resolve an address/offset expression the way `uf`/WinDbg read it:
                // evaluate `? <expr>` first (the MASM evaluator's default base is hex, so
                // a bare `00401234` is 0x00401234 and `module!Dispatch+0x123` resolves),
                // then fall back to pure parsing (backtick / bare-hex, then `0x`/decimal).
                // Applied to both the target VA and the `from` seed so a value pasted from
                // WinDbg — a `hi`lo` backtick address or a digit-only 32-bit address — is
                // read consistently on both sides.
                let resolve = |expr: &str| -> Option<u64> {
                    e.execute_command(&format!("? {expr}"))
                        .ok()
                        .as_deref()
                        .and_then(parse_eval)
                        .or_else(|| parse_windbg_addr(expr))
                        .or_else(|| parse_u64(expr).ok())
                };

                // Resolve the target VA: an absolute address, or module+RVA rebased
                // against the module's live base from `lm m <module>`.
                let target = match (&args.address, &args.module, &args.rva) {
                    // Reject conflicting target forms rather than silently ignoring one —
                    // analysing the wrong target would give a misleading verdict.
                    (Some(_), Some(_), _) | (Some(_), _, Some(_)) => {
                        return Err("provide `address` OR `module`+`rva`, not both".to_string());
                    }
                    (Some(a), None, None) => resolve(a)
                        .ok_or_else(|| format!("could not resolve target address `{a}`"))?,
                    (None, Some(m), Some(r)) => {
                        let rva =
                            resolve(r).ok_or_else(|| format!("could not resolve rva `{r}`"))?;
                        let lm = e.execute_command(&format!("lm m {m}")).map_err(es)?;
                        let base = parse_lm_base(&lm).ok_or_else(|| {
                            format!("module `{m}` not found (`lm m {m}` returned):\n{lm}")
                        })?;
                        base.checked_add(rva)
                            .ok_or_else(|| "module base + rva overflowed u64".to_string())?
                    }
                    _ => {
                        return Err("provide `address`, or both `module` and `rva`".to_string());
                    }
                };

                let max_functions = args.max_functions.unwrap_or(256);
                let max_depth = args.max_depth.unwrap_or(32);

                // Resolve `from` to a numeric VA so a mid-function start (a handler scoped
                // past a switch) is honored; `None` (unresolvable) starts at the entry.
                let seed_start = resolve(&args.from);

                // A real `uf` lists backtick addresses or at least a "module!Func:" label;
                // error text ("Couldn't resolve...", "no code") lacks both and prunes the
                // branch. parse_uf then discards any non-disassembly. Held in a `&mut`
                // binding so the same disassembler drives both the walk and the recipe.
                let mut uf = |arg: &str| match e.execute_command(&format!("uf {arg}")) {
                    Ok(t) if t.contains('`') || t.contains(':') => Some(t),
                    _ => None,
                };

                let rpt = reachability(
                    &args.from,
                    seed_start,
                    target,
                    max_functions,
                    max_depth,
                    &mut uf,
                );

                if rpt.from_entry.is_none() {
                    return Err(format!(
                        "could not disassemble `from` ({}): `uf` returned no function. \
                         Check the symbol/address and that the module is loaded.",
                        args.from
                    ));
                }

                // On a REACHABLE verdict, re-walk the path functions to emit the directional
                // recipe (which branch each on-path `jcc` must take, and what it tests).
                let mut out = format_report(&rpt);
                if rpt.verdict_reachable && args.recipe.unwrap_or(true) {
                    let recipes = path_recipe(&args.from, seed_start, &rpt, &mut uf);
                    out.push_str(&format_recipe(&recipes));
                }
                Ok(out)
            })
            .await;
        engine_result(out)
    }
}

#[rmcp::tool_handler(
    instructions = "Drive WinDbg/DbgEng for live user-mode, kernel, crash-dump, and Time Travel Debugging (TTD) analysis. \
Open a dump or .run trace, attach to a process or the kernel, inspect registers/memory/stacks/modules, and set breakpoints. \
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
Use `execute` for any raw command not covered by a dedicated tool."
)]
impl rmcp::ServerHandler for WindbgServer {}

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

        for name in ["execute", "launch", "record_trace", "end_session", "go"] {
            assert_eq!(
                ann(name).read_only_hint,
                Some(false),
                "`{name}` changes the target and must not be marked read-only"
            );
            assert_eq!(ann(name).destructive_hint, Some(true), "`{name}`");
        }

        for name in ["read_memory", "backtrace", "modules", "decode_ioctl"] {
            assert_eq!(
                ann(name).read_only_hint,
                Some(true),
                "`{name}` only inspects and should be marked read-only"
            );
        }
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

        for name in ["read_memory", "execute", "go", "end_session", "modules"] {
            assert!(takes_session(name), "`{name}` should accept session_id");
        }
        for name in ["decode_ioctl", "record_trace", "open_dump"] {
            assert!(
                !takes_session(name),
                "`{name}` should not accept session_id"
            );
        }
    }

    // ---- Session handles -----------------------------------------------

    #[test]
    fn omitted_handle_accepts_whatever_session_is_current() {
        assert!(check_session_handle(Some("sess-1"), None).is_ok());
        assert!(check_session_handle(None, None).is_ok());
    }

    #[test]
    fn matching_handle_is_accepted() {
        assert!(check_session_handle(Some("sess-1"), Some("sess-1")).is_ok());
    }

    #[test]
    fn handle_from_a_replaced_session_is_refused() {
        let err = check_session_handle(Some("sess-2"), Some("sess-1")).unwrap_err();
        assert!(err.contains("sess-1"), "{err}");
        assert!(err.contains("sess-2"), "{err}");
    }

    #[test]
    fn handle_is_refused_once_the_session_is_ended() {
        let err = check_session_handle(None, Some("sess-1")).unwrap_err();
        assert!(err.contains("no debug session open"), "{err}");
    }

    /// The gate must read the session at execution time. Building it and evaluating it at
    /// submission time — the obvious-looking caller-side check — leaves a window in which a
    /// concurrent `open_*` replaces the target between the check and the debugger call, so
    /// a call that passed validation still runs against the wrong session.
    #[test]
    fn the_gate_reads_the_session_when_it_runs_not_when_it_is_built() {
        let session = Arc::new(Mutex::new(Some("sess-A".to_string())));
        let gate = session_gate_for(Arc::clone(&session), Some("sess-A"));

        // A concurrent open lands after the gate was built but before it runs.
        *lock(&session) = Some("sess-B".to_string());

        let err = gate().unwrap_err();
        assert!(err.contains("sess-B"), "{err}");
    }

    #[test]
    fn the_gate_passes_when_the_session_is_unchanged_at_execution_time() {
        let session = Arc::new(Mutex::new(Some("sess-A".to_string())));
        let gate = session_gate_for(Arc::clone(&session), Some("sess-A"));
        assert!(gate().is_ok());
    }

    /// A target replaced while the caller held no handle is still their problem to opt into,
    /// so an absent handle keeps passing whatever the session did in the meantime.
    #[test]
    fn an_absent_handle_still_passes_after_a_replacement() {
        let session = Arc::new(Mutex::new(Some("sess-A".to_string())));
        let gate = session_gate_for(Arc::clone(&session), None);
        *lock(&session) = Some("sess-B".to_string());
        assert!(gate().is_ok());
    }

    #[test]
    fn minted_handles_are_unique() {
        let a = mint_session_id();
        let b = mint_session_id();
        assert_ne!(a, b);
    }

    // ---- Error reporting -----------------------------------------------

    /// A failed debugger operation belongs in the result (`isError: true`) so the model
    /// can read it and correct itself; only a dead engine is a protocol error.
    #[test]
    fn debugger_failures_are_tool_errors_not_protocol_errors() {
        let r = engine_result(Err(EngineError::Debugger("no such symbol".into())))
            .expect("debugger failure must not surface as a protocol error");
        assert_eq!(r.is_error, Some(true));

        let err = engine_result(Err(EngineError::Unavailable("engine gone".into())))
            .expect_err("a dead engine must surface as a protocol error");
        assert!(err.message.contains("engine gone"));
    }

    #[test]
    fn successful_output_is_not_flagged_as_an_error() {
        let r = engine_result(Ok("rax=0000000000000000".into())).unwrap();
        assert_eq!(r.is_error, Some(false));
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
