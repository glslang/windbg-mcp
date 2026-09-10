//! Static analysis of a driver's IOCTL dispatch: the call-graph walk behind
//! `reachable_from_dispatch`, and the directional path recipe built on it.
//!
//! Moved here from `src/server.rs` unchanged. It had grown to about six hundred lines inside an
//! eight-thousand-line module that is otherwise the MCP tool surface, and it is about to grow
//! again -- the driver tools port the Driver Buddy Revolutions analyses onto this same walk. The
//! move is its own commit so the rework that follows reads as a diff rather than as a relocation
//! with edits hidden inside it.
//!
//! # Engine-free
//!
//! [`reachability`] takes a disassembler closure and [`path_recipe`] the same, exactly as
//! [`crate::walk::run`] takes a reader, so the traversal, the predicate decoding and the rendering
//! all test against fake disassembly with no debugger. The worker supplies the one closure that
//! touches DbgEng.

use std::collections::{HashMap, HashSet, VecDeque};

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

#[cfg(test)]
mod tests {
    use super::*;

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
