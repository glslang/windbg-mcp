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

/// The control-flow classification a walk needs, and where it now comes from.
///
/// It used to be recovered here, from the `uf` line: a mnemonic table plus "the last
/// parenthesised address on the line is the target". Both halves have been retired into
/// [`dbgscope::dbgeng::Instruction`], which decodes the **encoding** instead — because the mnemonic
/// table was never finished (a software interrupt's vector, `xbegin`, `xabort`, `hlt` each arrived
/// as a separate defect) and because a symbol's own punctuation kept severing operands: a comma
/// inside `std::map<int,int>`, a parenthesis inside `operator()`, a bracket inside `operator[]`,
/// each one turning a direct call into an indirect one that this walk then dropped.
///
/// So the walk reads [`Instruction::flow`] and nothing textual. What is still read out of `uf` is
/// the one thing it uniquely knows and the encoding cannot say: **which addresses belong to this
/// function**, across the several unwind regions MSVC splits one into. That parse is now the
/// address column alone.
use dbgscope::dbgeng::{Flow, Instruction};

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
fn walk_function(block: &[Instruction], start: u64) -> Option<FnWalk> {
    let idx: HashMap<u64, usize> = block
        .iter()
        .enumerate()
        .map(|(i, x)| (x.address, i))
        .collect();
    let start_i = *idx.get(&start)?;
    let mut reachable: HashSet<u64> = HashSet::new();
    let mut external: Vec<(u64, u64, &'static str)> = Vec::new();
    let mut stack = vec![start_i];
    while let Some(i) = stack.pop() {
        let insn = &block[i];
        if !reachable.insert(insn.address) {
            continue;
        }
        let next = (i + 1 < block.len()).then_some(i + 1);
        // A destination inside this function's listing is an edge within it; one outside is an
        // edge leaving it. `None` is an indirect transfer and is never followed, which is what
        // keeps a REACHABLE verdict from ever resting on a guessed edge.
        let mut leave = |site: u64, to: Option<u64>, kind| {
            if let Some(t) = to {
                match idx.get(&t) {
                    Some(&j) => stack.push(j),
                    None => external.push((site, t, kind)),
                }
            }
        };
        match insn.flow {
            // `Unreadable` stops the walk for the same reason a `ret` does: there is no
            // instruction here, so there is nothing after it either.
            Flow::Return | Flow::Trap | Flow::Unreadable => {}
            Flow::Jmp(t) => {
                // An unconditional jump has no fall-through, so an *indirect* one ends the path.
                leave(insn.address, t, "jmp");
            }
            Flow::Branch(t) => {
                leave(insn.address, t, "jmp");
                if let Some(n) = next {
                    stack.push(n);
                }
            }
            Flow::Call(t) => {
                leave(insn.address, t, "call");
                if let Some(n) = next {
                    stack.push(n);
                }
            }
            // `Unknown` falls through with the rest: an instruction set this build does not
            // decode still has an instruction there, and stopping would drop the function's tail.
            Flow::Fallthrough | Flow::Unknown => {
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

/// The addresses a `uf` listing names, grouped into the runs the engine can disassemble in one
/// go: `(start, instruction count)`.
///
/// `uf` lists a function in flow order, in blocks separated by label lines, and consecutive
/// listed addresses are usually **contiguous** even across a label — measured on
/// `mountmgr!MountMgrDeviceControl`, where the whole 376-instruction routine is a handful of runs
/// rather than 376 of them. A real gap is where one unwind region ends and the next begins; on
/// that routine the largest is 319 bytes.
///
/// So a run breaks where the next address is not within one instruction's reach of the last, or
/// goes backwards. Sixteen bytes is the longest an x86 instruction can be, which makes the test
/// "could this plausibly be the next instruction" rather than a tuning knob.
pub(crate) fn listing_runs(addresses: &[u64]) -> Vec<(u64, usize)> {
    /// The longest an x86 instruction can be.
    const REACH: u64 = 16;

    let mut runs: Vec<(u64, usize)> = Vec::new();
    let mut previous: Option<u64> = None;
    for &address in addresses {
        let continues = previous.is_some_and(|p| address > p && address - p <= REACH);
        match runs.last_mut() {
            Some((_, len)) if continues => *len += 1,
            _ => runs.push((address, 1)),
        }
        previous = Some(address);
    }
    runs
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
fn instruction_text(block: &[Instruction]) -> HashMap<u64, String> {
    block
        .iter()
        .filter(|instruction| !instruction.text.is_empty())
        .map(|instruction| (instruction.address, instruction.text.clone()))
        .collect()
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
    block: &[Instruction],
    idx: &HashMap<u64, usize>,
    start: u64,
    goal: u64,
) -> Option<Vec<(u64, bool)>> {
    fn dfs(
        block: &[Instruction],
        idx: &HashMap<u64, usize>,
        i: usize,
        goal: u64,
        visited: &mut HashSet<usize>,
        acc: &mut Vec<(u64, bool)>,
    ) -> bool {
        let insn = &block[i];
        if insn.address == goal {
            return true;
        }
        if !visited.insert(i) {
            return false;
        }
        let next = (i + 1 < block.len()).then_some(i + 1);
        match insn.flow {
            Flow::Return | Flow::Trap | Flow::Unreadable => false,
            Flow::Jmp(t) => match t.and_then(|t| idx.get(&t)) {
                Some(&j) => dfs(block, idx, j, goal, visited, acc),
                None => false,
            },
            Flow::Branch(t) => {
                if let Some(&j) = t.and_then(|t| idx.get(&t)) {
                    acc.push((insn.address, true));
                    if dfs(block, idx, j, goal, visited, acc) {
                        return true;
                    }
                    acc.pop();
                }
                if let Some(n) = next {
                    acc.push((insn.address, false));
                    if dfs(block, idx, n, goal, visited, acc) {
                        return true;
                    }
                    acc.pop();
                }
                false
            }
            Flow::Call(_) | Flow::Fallthrough | Flow::Unknown => match next {
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
    block: &[Instruction],
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
    block: &[Instruction],
    textmap: &HashMap<u64, String>,
    bi: usize,
    jcc: &str,
    took_taken: bool,
) -> Option<Predicate> {
    for k in (bi.saturating_sub(6)..bi).rev() {
        let Some(raw) = textmap.get(&block[k].address) else {
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
    mut uf: impl FnMut(&str) -> Option<Vec<Instruction>>,
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
        let Some(block) = uf(&arg) else { continue };
        let idx: HashMap<u64, usize> = block
            .iter()
            .enumerate()
            .map(|(i, x)| (x.address, i))
            .collect();
        // Fall back to the function entry if the requested start isn't a boundary
        // (mirrors `reachability`'s handling of an unaligned seed).
        let start = if idx.contains_key(&want_start) {
            want_start
        } else {
            block.first().map_or(want_start, |i| i.address)
        };
        let textmap = instruction_text(&block);
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
            && matches!(block[gi].flow, Flow::Branch(_))
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
    mut uf: impl FnMut(&str) -> Option<Vec<Instruction>>,
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
        let Some(block) = uf(&arg) else {
            continue; // disassembly failed — prune this branch
        };
        let Some(entry) = block.first().map(|i| i.address) else {
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

    /// One instruction as the walk sees it: an address, the flow it carries, and the rendering
    /// the recipe reads its predicate out of.
    ///
    /// The flow is **stated** rather than encoded in a fake mnemonic, which is the point of the
    /// rework these fixtures came through: classifying control flow is no longer this module's
    /// job, so a test of the walk should not have to spell an instruction convincingly enough to
    /// be classified. It says what the instruction does and the walk is tested on that.
    fn insn(address: u64, flow: Flow, text: &str) -> Instruction {
        Instruction {
            address,
            bytes: String::new(),
            text: text.to_string(),
            mnemonic: text
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_string(),
            operands: Vec::new(),
            flow,
        }
    }

    /// A function: an entry `nop` at `entry`, then the given instructions in listing order.
    fn uf_fn(entry: u64, body: Vec<Instruction>) -> Vec<Instruction> {
        std::iter::once(insn(entry, Flow::Fallthrough, "nop"))
            .chain(body)
            .collect()
    }

    /// A disassembler over a fixed set of functions, keyed the way the walk asks for them.
    fn functions(entries: &[(&str, Vec<Instruction>)]) -> HashMap<String, Vec<Instruction>> {
        entries
            .iter()
            .map(|(k, v)| ((*k).to_string(), v.clone()))
            .collect()
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

    /// The runs a real `uf` listing groups into, and where its gaps actually are.
    ///
    /// The addresses are lifted verbatim from `uf mountmgr!MountMgrDeviceControl` on a 26100
    /// image, which is what makes this fixture worth more than a composed one: it shows that
    /// consecutive listed addresses stay contiguous **across a block label** — `…4793` is a
    /// two-byte `je` and `…4795` is the next line, under a new label — so a run is not a basic
    /// block and grouping by label would multiply the engine calls for nothing. And it shows what
    /// a real gap looks like: `…4d49` to `…4e88`, 319 bytes, where one unwind region ends.
    #[test]
    fn a_listing_groups_into_runs_at_its_real_gaps() {
        // The routine's opening block, running through two label boundaries.
        let contiguous: Vec<u64> = vec![
            0xfffff805_5ec04750,
            0xfffff805_5ec04755,
            0xfffff805_5ec0475a,
            0xfffff805_5ec0475b,
            0xfffff805_5ec0475d,
            0xfffff805_5ec0475f,
            0xfffff805_5ec04761,
            0xfffff805_5ec04763,
            0xfffff805_5ec04767,
            0xfffff805_5ec0476e,
            // label: MountMgrDeviceControl+0x45
            0xfffff805_5ec04795,
        ];
        assert_eq!(
            listing_runs(&contiguous[..10]),
            vec![(0xfffff805_5ec04750, 10)],
            "one contiguous block should be one run"
        );

        // `…476e` to `…4795` is 39 bytes — a gap, and the label between them is not what makes
        // it one. The pair either side of a label that *is* contiguous stays in one run.
        assert_eq!(
            listing_runs(&contiguous),
            vec![(0xfffff805_5ec04750, 10), (0xfffff805_5ec04795, 1)]
        );
        assert_eq!(
            listing_runs(&[0xfffff805_5ec04793, 0xfffff805_5ec04795]),
            vec![(0xfffff805_5ec04793, 2)],
            "a label between two contiguous addresses must not split the run"
        );

        // The routine's largest real gap: the end of one unwind region to the start of the next.
        assert_eq!(
            listing_runs(&[0xfffff805_5ec04d49, 0xfffff805_5ec04e88]),
            vec![(0xfffff805_5ec04d49, 1), (0xfffff805_5ec04e88, 1)]
        );

        // A backwards step is a new run too — nothing guarantees a listing is monotonic.
        assert_eq!(
            listing_runs(&[0x2000, 0x2004, 0x1000]),
            vec![(0x2000, 2), (0x1000, 1)]
        );
        assert!(listing_runs(&[]).is_empty());
    }

    /// Every flow variant, and what the walk does with it.
    ///
    /// This replaces the two tests that used to assert a mnemonic table's output. That
    /// classification now happens in `dbgscope`, from the encoding, so what is left to pin here
    /// is the half this module still owns: which edges a walk takes given a flow. The two
    /// variants worth the most are the new ones — `Unknown` continues, because an instruction set
    /// this build cannot decode still has an instruction there, and `Unreadable` stops, because
    /// it does not.
    #[test]
    fn the_walk_takes_the_edges_the_flow_carries() {
        let one = |flow: Flow| {
            let block = uf_fn(
                0x1000,
                vec![insn(0x1004, flow, "x"), insn(0x1008, Flow::Return, "ret")],
            );
            let walk = walk_function(&block, 0x1000).expect("entry is an instruction");
            (
                walk.reachable.contains(&0x1008),
                walk.external.iter().map(|e| (e.1, e.2)).collect::<Vec<_>>(),
            )
        };

        // Continues past the instruction, and leaves no edge.
        for flow in [Flow::Fallthrough, Flow::Unknown, Flow::Call(None)] {
            let (continues, external) = one(flow);
            assert!(
                continues,
                "{flow:?} should continue to the next instruction"
            );
            assert!(external.is_empty(), "{flow:?} left an edge: {external:?}");
        }

        // Stops, and leaves no edge.
        for flow in [Flow::Return, Flow::Trap, Flow::Unreadable, Flow::Jmp(None)] {
            let (continues, external) = one(flow);
            assert!(!continues, "{flow:?} should stop the walk");
            assert!(external.is_empty(), "{flow:?} left an edge: {external:?}");
        }

        // Leaves an edge. A call also continues; an unconditional jump does not.
        assert_eq!(
            one(Flow::Call(Some(0x2000))),
            (true, vec![(0x2000, "call")])
        );
        assert_eq!(one(Flow::Jmp(Some(0x2000))), (false, vec![(0x2000, "jmp")]));
        assert_eq!(
            one(Flow::Branch(Some(0x2000))),
            (true, vec![(0x2000, "jmp")])
        );
    }

    #[test]
    fn reachability_direct_call_chain() {
        let m = functions(&[
            (
                "start",
                uf_fn(
                    0x1000,
                    vec![insn(0x1004, Flow::Call(Some(0x2000)), "call A!B")],
                ),
            ),
            (
                "0x2000",
                uf_fn(0x2000, vec![insn(0x2008, Flow::Return, "ret")]),
            ),
        ]);
        let r = reachability("start", None, 0x2008, 256, 32, |a| m.get(a).cloned());
        assert!(r.verdict_reachable);
        assert_eq!(r.from_entry, Some(0x1000));
        assert_eq!(r.containing_fn, Some(0x2000));
        assert_eq!(r.path, vec![(0x1004, "call", 0x2000)]);
    }

    #[test]
    fn reachability_follows_tail_jmp() {
        let m = functions(&[
            (
                "start",
                uf_fn(
                    0x1000,
                    vec![insn(0x1004, Flow::Jmp(Some(0x2000)), "jmp A!B")],
                ),
            ),
            (
                "0x2000",
                uf_fn(0x2000, vec![insn(0x2008, Flow::Return, "ret")]),
            ),
        ]);
        let r = reachability("start", None, 0x2008, 256, 32, |a| m.get(a).cloned());
        assert!(r.verdict_reachable);
        assert_eq!(r.path, vec![(0x1004, "jmp", 0x2000)]);
    }

    #[test]
    fn reachability_target_in_seed_is_zero_hops() {
        let m = functions(&[(
            "start",
            uf_fn(0x1000, vec![insn(0x1004, Flow::Return, "ret")]),
        )]);
        let r = reachability("start", None, 0x1004, 256, 32, |a| m.get(a).cloned());
        assert!(r.verdict_reachable);
        assert_eq!(r.containing_fn, Some(0x1000));
        assert!(r.path.is_empty());
    }

    #[test]
    fn reachability_indirect_only_is_not_reached() {
        let m = functions(&[(
            "start",
            uf_fn(
                0x1000,
                vec![insn(0x1004, Flow::Call(None), "call qword ptr [A!Ptr]")],
            ),
        )]);
        // The target sits behind the indirect call, which is never followed.
        let r = reachability("start", None, 0x2008, 256, 32, |a| m.get(a).cloned());
        assert!(!r.verdict_reachable);
        assert!(!r.bound_hit); // graph exhausted, not a bound
    }

    #[test]
    fn reachability_cycle_terminates() {
        let m = functions(&[
            (
                "start",
                uf_fn(
                    0x1000,
                    vec![insn(0x1004, Flow::Call(Some(0x2000)), "call A!B")],
                ),
            ),
            (
                "0x2000",
                uf_fn(
                    0x2000,
                    vec![insn(0x2004, Flow::Call(Some(0x1000)), "call B!A")],
                ),
            ),
        ]);
        // Target is absent — the A<->B cycle must not loop forever.
        let r = reachability("start", None, 0x7777, 256, 32, |a| m.get(a).cloned());
        assert!(!r.verdict_reachable);
        assert_eq!(r.funcs_explored, 2);
    }

    #[test]
    fn reachability_respects_function_bound() {
        let m = functions(&[
            (
                "start",
                uf_fn(
                    0x1000,
                    vec![insn(0x1004, Flow::Call(Some(0x2000)), "call A!B")],
                ),
            ),
            (
                "0x2000",
                uf_fn(0x2000, vec![insn(0x2004, Flow::Return, "ret")]),
            ),
        ]);
        // Bound to a single function: B (which contains the target) is never explored.
        let r = reachability("start", None, 0x2004, 1, 32, |a| m.get(a).cloned());
        assert!(!r.verdict_reachable);
        assert!(r.bound_hit);
        assert_eq!(r.funcs_explored, 1);
    }

    #[test]
    fn reachability_scopes_from_mid_function_start() {
        // A single dispatch function: the entry does an indirect jump-table `jmp` (which is not
        // followed), then two independent switch-case blocks. Disassembling any address returns
        // the whole function, so a mid-function `from` must NOT treat the *other* case as
        // reachable.
        let dispatch = uf_fn(
            0x1000,
            vec![
                insn(0x1004, Flow::Jmp(None), "jmp qword ptr [Dispatch!tbl]"),
                insn(0x1008, Flow::Fallthrough, "nop"), // case 1 block
                insn(0x100c, Flow::Return, "ret"),      // case 1 body (target A)
                insn(0x1010, Flow::Fallthrough, "nop"), // case 2 block
                insn(0x1014, Flow::Return, "ret"),      // case 2 body (target B)
            ],
        );
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
    fn reachability_stops_at_trap() {
        // A function: entry, then a `noreturn` trap, then a block reachable ONLY by falling
        // through it. It must not be reachable.
        let guard = uf_fn(
            0x1000,
            vec![
                insn(0x1004, Flow::Trap, "int 29h"),    // execution stops here
                insn(0x1006, Flow::Fallthrough, "nop"), // dead code behind the trap
                insn(0x1007, Flow::Return, "ret"),
            ],
        );
        let mut uf = |a: &str| (a == "0x1000").then(|| guard.clone());
        // The entry (before the trap) is reachable...
        assert!(reachability("0x1000", Some(0x1000), 0x1000, 256, 32, &mut uf).verdict_reachable);
        // ...but code after the trap is not (the walk stops at the trap).
        assert!(!reachability("0x1000", Some(0x1000), 0x1006, 256, 32, &mut uf).verdict_reachable);
    }

    // ---- reachability: path recipe ----------------------------------------

    #[test]
    fn recipe_forced_direction_decodes_ioctl_predicate() {
        // Handler: `cmp [rdx+18h],222003h; jne bail`. The target block is the jne fall-through,
        // so the branch is forced to fall through, and the compare decodes to
        // `IoControlCode == 0x222003` (displacement +0x18, the IO_STACK_LOCATION offset).
        let m = functions(&[(
            "Handler",
            uf_fn(
                0x1000,
                vec![
                    insn(0x1004, Flow::Fallthrough, "cmp dword ptr [rdx+18h],222003h"),
                    insn(0x1008, Flow::Branch(Some(0x1010)), "jne Handler+0x10"),
                    insn(0x100c, Flow::Fallthrough, "nop"), // target: jne fall-through
                    insn(0x100e, Flow::Return, "ret"),
                    insn(0x1010, Flow::Return, "ret"), // bail: jne taken
                ],
            ),
        )]);
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
        // direction the path took (a sound sufficient condition) rather than "don't care" — an
        // alternate successor usually reaches the goal only via its own conditions.
        let m = functions(&[(
            "Merge",
            uf_fn(
                0x1000,
                vec![
                    insn(0x1004, Flow::Fallthrough, "test eax,eax"),
                    insn(0x1008, Flow::Branch(Some(0x1010)), "je Merge+0x10"),
                    insn(0x100c, Flow::Fallthrough, "nop"), // fall-through, then into 0x1010
                    insn(0x1010, Flow::Fallthrough, "nop"), // goal (also the je target)
                    insn(0x1012, Flow::Return, "ret"),
                ],
            ),
        )]);
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
        let m = functions(&[(
            "Handler",
            uf_fn(
                0x1000,
                vec![
                    insn(0x1004, Flow::Fallthrough, "test dword ptr [rdx+10h],20h"),
                    insn(0x1008, Flow::Branch(Some(0x1010)), "jne Handler+0x10"),
                    insn(0x100c, Flow::Return, "ret"),
                    insn(0x1010, Flow::Fallthrough, "nop"), // target: jne taken
                    insn(0x1012, Flow::Return, "ret"),
                ],
            ),
        )]);
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
        // A (length gate) calls B (field gate) which contains the target. The recipe has one
        // segment per function, each routing to the next hop's site / the target.
        let m = functions(&[
            (
                "start",
                uf_fn(
                    0x1000,
                    vec![
                        insn(0x1004, Flow::Fallthrough, "cmp dword ptr [rdx+10h],20h"),
                        insn(0x1008, Flow::Branch(Some(0x1014)), "jb A+0x14"),
                        insn(0x100c, Flow::Call(Some(0x2000)), "call A!B"),
                        insn(0x1011, Flow::Return, "ret"),
                        insn(0x1014, Flow::Return, "ret"), // bail: jb taken
                    ],
                ),
            ),
            (
                "0x2000",
                uf_fn(
                    0x2000,
                    vec![
                        insn(0x2004, Flow::Fallthrough, "cmp byte ptr [rax+8h],1"),
                        insn(0x2008, Flow::Branch(Some(0x2010)), "jne B+0x10"),
                        insn(0x200c, Flow::Fallthrough, "nop"), // target: jne fall-through
                        insn(0x200e, Flow::Return, "ret"),
                        insn(0x2010, Flow::Return, "ret"),
                    ],
                ),
            ),
        ]);
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
        // A leaves to B via `jne B` — a conditional branch whose target is outside A's block.
        // The hop site is the branch itself, so the recipe must record "take this branch"
        // (taking it is what leaves A toward B), not stop short of it.
        let m = functions(&[
            (
                "start",
                uf_fn(
                    0x1000,
                    vec![
                        insn(0x1004, Flow::Fallthrough, "cmp dword ptr [rdx+18h],222003h"),
                        insn(0x1008, Flow::Branch(Some(0x2000)), "jne B"), // exits A
                        insn(0x100c, Flow::Return, "ret"),
                    ],
                ),
            ),
            (
                "0x2000",
                uf_fn(
                    0x2000,
                    vec![
                        insn(0x2004, Flow::Fallthrough, "nop"), // target
                        insn(0x2006, Flow::Return, "ret"),
                    ],
                ),
            ),
        ]);
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
