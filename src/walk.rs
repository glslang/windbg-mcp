//! Walking memory node by node, where **an unreadable node is a row rather than an end**.
//!
//! The natural way to inspect a kernel list through this server used to be a MASM loop through
//! `execute`:
//!
//! ```text
//! r @$t0 = poi(<head>); .for (...) { r @$t9 = poi(@$t7+8); r @$ta = poi(@$t9) ... }
//! ```
//!
//! One node pointing at a freed chunk whose page has come back unmapped ends the whole script
//! with `An unexpected exception was raised (0x80040205)`: no rows, no iteration number, no
//! indication of how many nodes were classified before it. Driving the MessageManager
//! use-after-free that meant bisecting a 512-entry handle table by hand to find the one bad
//! pointer — which was, inevitably, the pointer the walk existed to find
//! ([#103](https://github.com/glslang/windbg-mcp/issues/103)).
//!
//! That is backwards for this server in particular. Its subject is pool and UAF analysis, where
//! "some of these nodes are freed" is the normal case and not an error, so a walk has to report
//! the holes rather than die on the first one. Every read here is its own `ReadVirtual`, and one
//! that fails marks a value unreadable and leaves the walk running.
//!
//! # Three ways to name the nodes, one way to read them
//!
//! * `addresses` — an explicit list. The bulk read: N pointers, N answers, no arithmetic.
//! * `start` + `stride` — an array. Element `i` is `start + i * stride`.
//! * `start` + `next_offset` — a chain. The next node is the pointer at `node + next_offset`.
//!
//! `fields` then says what to pull out of each node, and applies to all three. A caller with 512
//! handle-table slots reads the message pointer out of each in one call, and reads the refcount
//! out of those 512 pointers in a second — one round trip per *question* rather than per node,
//! and neither call has an iteration that can abort the rest.
//!
//! # Why a chain stops and an array does not
//!
//! An unreadable node in an array or a list costs that node's values and nothing else: the next
//! address is arithmetic, or was supplied. An unreadable node in a *chain* costs the walk, because
//! the address of everything after it lived in the bytes that would not read. So the two behave
//! differently on purpose, and the report says which happened
//! ([`structured::WalkStop::UnreadableLink`]).
//!
//! A chain also stops on a **loop**, which is not an error either: a list that points back into
//! itself is a finding, and every address visited is kept so the walk reports where it closed
//! instead of running to its cap.
//!
//! # Engine-free
//!
//! [`run`] takes a reader closure rather than a `DebugEngine`, exactly as
//! [`crate::server::reachability`] takes a disassembler: the traversal, the span coalescing, the
//! loop detection and the rendering are all testable against a fake address space, and the worker
//! supplies the one closure that touches DbgEng.

use std::collections::HashSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::structured::{self, addr};

/// Most nodes one walk will visit.
///
/// A guard against the worker, not a judgement about what is useful. The reply is built as a
/// single `String` before it crosses the pipe, and each node is a row plus a cell per field — so
/// an unbounded `count` is a request to allocate a table nobody asked for, in a process whose
/// death costs the caller their session. It is also the read budget: over KDNET every node is at
/// least one round trip on the wire.
pub const MAX_NODES: u32 = 1024;

/// Most fields one node may be asked for.
pub const MAX_FIELDS: usize = 16;

/// Longest a field's name may be.
///
/// The one argument here that is **amplified**, which is why it needs a bound of its own on top of
/// [`MAX_NODES`] and [`MAX_FIELDS`]. Every other input is spent once — an address is parsed to a
/// `u64` and dropped — but a name is cloned into each field of each node, rendered into the table,
/// and serialized again, so a single large one becomes up to 16,384 copies and can take the worker
/// out of memory. That costs the caller their session, which is exactly what the node and field
/// caps exist to prevent, arriving through the argument they do not cover.
///
/// 64 characters, because this is a **column header**. The generated default is `+0x18`; a name
/// wider than the value beneath it has already stopped helping anyone read the table.
pub const MAX_FIELD_NAME: usize = 64;

/// Nodes a walk visits when the caller names no `count`.
const DEFAULT_NODES: u32 = 64;

/// Sizes a field may have: the four widths the debugger's own `db`/`dw`/`dd`/`dq` read.
const FIELD_SIZES: [u32; 4] = [1, 2, 4, 8];

/// The widest run of bytes this will fetch in one read to satisfy several fields at once.
///
/// Fields of one structure sit close together, so a single read of the span they cover is one
/// round trip instead of one per field — over a KD link that is the difference between a walk that
/// answers and a walk that times out. Past this the span has stopped being "one structure" and
/// become a request to haul back memory nobody asked about, so the walk reads each field on its
/// own instead.
const MAX_SPAN: i64 = 4096;

/// Where a walk's nodes come from, as the tool's arguments name them.
///
/// The three are exclusive rather than combinable: each answers "what is the next address?", and a
/// request naming two would have to pick one silently.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Source {
    /// Addresses supplied outright, already parsed. Nothing is derived, so every entry is visited
    /// whether or not the one before it could be read.
    List { addresses: Vec<u64> },
    /// `start + i * stride`, `count` times. `stride` is signed so an array that runs downwards is
    /// an argument rather than a different tool.
    Array {
        start: String,
        stride: i64,
        count: u32,
    },
    /// `start`, then the pointer at `node + next_offset`, up to `count` nodes.
    Chain {
        start: String,
        next_offset: i64,
        count: u32,
    },
}

/// One value to read out of every node.
///
/// `offset` is signed because the interesting field is often *behind* the pointer a caller holds:
/// a pool chunk's header sits 0x10 bytes before the address the allocator returned, and asking for
/// it should not mean doing the subtraction per node and losing the table's alignment with the
/// pointers the target actually stores.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Field {
    pub name: String,
    pub offset: i64,
    pub size: u32,
}

/// A field as the tool takes it, before defaults.
///
/// Separate from [`Field`] so the wire form has no optional halves: a `size` still `None` on the
/// far side of the pipe is a decision the worker would have to make, and the worker is the one
/// place that cannot see the rest of the request to make it consistently.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct FieldArg {
    /// Column name for this value, at most 64 characters. Defaults to the offset, e.g. `+0x18`.
    #[serde(default)]
    pub name: Option<String>,
    /// Byte offset within the node. Negative reads *behind* it — a pool header is at -16.
    pub offset: i64,
    /// Bytes to read: 1, 2, 4 or 8. Defaults to 8 (a pointer).
    #[serde(default)]
    pub size: Option<u32>,
}

/// A memory walk, as it crosses the pipe.
///
/// `patience_ms` is filled in by the supervisor's pump like every other deadline-carrying op — the
/// value a caller constructs is ignored. A walk is a long run of reads with no *command* behind
/// it, so dbgscope's watchdog cannot cut it short; the deadline it checks between nodes is the
/// only thing keeping it from outliving the caller who asked for it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalkOp {
    pub source: Source,
    pub fields: Vec<Field>,
    pub patience_ms: u32,
}

impl WalkOp {
    /// Validates a request and fills in its defaults, or says what is wrong with it.
    ///
    /// **On the supervisor's side, before a worker is involved.** Everything checked here is a
    /// fact about the request rather than about the target — the wrong number of traversal
    /// arguments, a field width the debugger has no read for, a count past the cap — so answering
    /// it costs nobody a round trip, and a session busy with something else does not have to
    /// become idle before a caller learns they made a typo.
    pub fn new(
        addresses: Option<Vec<String>>,
        start: Option<String>,
        stride: Option<i64>,
        next_offset: Option<i64>,
        count: Option<u32>,
        fields: Option<Vec<FieldArg>>,
    ) -> Result<Self, String> {
        let source = Self::source(addresses, start, stride, next_offset, count)?;
        Ok(Self {
            fields: Self::fields(fields, &source)?,
            source,
            patience_ms: 0,
        })
    }

    fn source(
        addresses: Option<Vec<String>>,
        start: Option<String>,
        stride: Option<i64>,
        next_offset: Option<i64>,
        count: Option<u32>,
    ) -> Result<Source, String> {
        match count {
            // Refused rather than clamped. A clamp answers a different question than the one asked
            // and then labels the result complete — and "every node asked for was visited" is the
            // one sentence a caller reads to decide whether to look further, so it must never be
            // about a count this server quietly lowered. A chain that stops at its cap hands back
            // where to resume, which is the shape a caller with more to walk actually needs.
            Some(count) if count > MAX_NODES => {
                return Err(format!(
                    "`count` is {count}; this tool walks at most {MAX_NODES} nodes in one call. \
                     Walk in pieces — a chain that stops at its cap reports the address to resume \
                     from, and an array is arithmetic."
                ));
            }
            Some(0) => return Err("`count` is 0, so there is nothing to walk.".to_string()),
            _ => {}
        }
        let nodes = count.unwrap_or(DEFAULT_NODES);
        match (addresses, start, stride, next_offset) {
            (Some(addresses), None, None, None) => {
                if count.is_some() {
                    return Err(
                        "`addresses` and `count` say the same thing twice: the list is \
                                the count. Pass the addresses you want walked."
                            .to_string(),
                    );
                }
                if addresses.is_empty() {
                    return Err("`addresses` is empty, so there is nothing to walk.".to_string());
                }
                if addresses.len() > MAX_NODES as usize {
                    return Err(format!(
                        "`addresses` holds {} entries; this tool walks at most {MAX_NODES} nodes \
                         in one call.",
                        addresses.len()
                    ));
                }
                Ok(Source::List {
                    addresses: addresses
                        .iter()
                        .map(|a| parse_addr(a))
                        .collect::<Result<_, _>>()?,
                })
            }
            (Some(_), _, _, _) => Err("`addresses` supplies the nodes outright, so it cannot be \
                                       combined with `start`, `stride` or `next_offset`."
                .to_string()),
            (None, Some(start), Some(stride), None) => Ok(Source::Array {
                start,
                stride,
                count: nodes,
            }),
            (None, Some(start), None, Some(next_offset)) => Ok(Source::Chain {
                start,
                next_offset,
                count: nodes,
            }),
            (None, Some(_), Some(_), Some(_)) => Err(
                "`stride` and `next_offset` are two different walks: `stride` steps through an \
                 array, `next_offset` follows a pointer chain. Pass one."
                    .to_string(),
            ),
            (None, Some(_), None, None) => Err(
                "`start` needs a traversal beside it: `stride` to step through an array, or \
                 `next_offset` to follow a pointer chain."
                    .to_string(),
            ),
            (None, None, _, _) => Err(
                "no nodes to walk. Pass `addresses` (an explicit list), or `start` with `stride` \
                 (an array) or `next_offset` (a pointer chain)."
                    .to_string(),
            ),
        }
    }

    /// The fields to read from every node, defaulted by what the walk already reports.
    ///
    /// A list or an array with no fields named is the bulk-read case — "what is the pointer at
    /// each of these addresses?" — so it defaults to one qword at offset 0. A **chain** already
    /// reports the link it followed out of every node, so the same default there would print one
    /// column twice; it defaults to nothing instead, and a chain walked with no fields is a list
    /// of nodes and their links, which is exactly what a caller checking a list's shape asked for.
    fn fields(fields: Option<Vec<FieldArg>>, source: &Source) -> Result<Vec<Field>, String> {
        let fields = fields.unwrap_or_default();
        if fields.is_empty() {
            return Ok(match source {
                Source::Chain { .. } => Vec::new(),
                _ => vec![Field {
                    name: "value".to_string(),
                    offset: 0,
                    size: 8,
                }],
            });
        }
        if fields.len() > MAX_FIELDS {
            return Err(format!(
                "`fields` names {} values; this tool reads at most {MAX_FIELDS} per node.",
                fields.len()
            ));
        }
        fields
            .into_iter()
            .map(|field| {
                let size = field.size.unwrap_or(8);
                if !FIELD_SIZES.contains(&size) {
                    return Err(format!(
                        "field size {size} is not a width the debugger reads: pass 1, 2, 4 or 8."
                    ));
                }
                // Counted in `char`s rather than bytes, so the limit a caller is told is the one
                // they can see: a name of accented or CJK characters must not be refused at a
                // third of its apparent length.
                if let Some(name) = &field.name
                    && name.chars().count() > MAX_FIELD_NAME
                {
                    return Err(format!(
                        "a field name is {} characters; this tool allows {MAX_FIELD_NAME}. It is \
                         a column header, and it is copied into every node the walk returns.",
                        name.chars().count()
                    ));
                }
                Ok(Field {
                    name: field.name.unwrap_or_else(|| offset_name(field.offset)),
                    offset: field.offset,
                    size,
                })
            })
            .collect()
    }
}

/// The default column name for an unnamed field: its offset, as a caller would write it.
fn offset_name(offset: i64) -> String {
    if offset < 0 {
        format!("-0x{:x}", offset.unsigned_abs())
    } else {
        format!("+0x{offset:x}")
    }
}

/// Parses an address in any form a caller is likely to paste — the same rule `pool_chunk` uses, so
/// a chunk address copied out of one tool goes into this one.
fn parse_addr(text: &str) -> Result<u64, String> {
    crate::server::parse_windbg_addr(text).map_or_else(|| crate::server::parse_u64(text), Ok)
}

/// A [`Source`] with its `start` expression resolved to a number.
///
/// Separate from [`Source`] because resolving a symbolic start is an engine call and everything
/// after it is not: the walk below is handed numbers, which is what lets it be tested without one.
#[derive(Debug, Clone)]
pub enum Resolved {
    List(Vec<u64>),
    Array {
        start: u64,
        stride: i64,
        count: u32,
    },
    Chain {
        start: u64,
        next_offset: i64,
        count: u32,
    },
}

impl Resolved {
    /// The first node's address and how many nodes at most, or `None` when there are none to walk.
    fn head(&self) -> Option<(u64, u32)> {
        match self {
            Self::List(addresses) => addresses
                .first()
                .map(|first| (*first, addresses.len() as u32)),
            Self::Array { start, count, .. } | Self::Chain { start, count, .. } => {
                Some((*start, *count))
            }
        }
    }

    /// The address the caller named as the start, for the report — `None` for a list, whose first
    /// entry is one address among many rather than a place the walk began from.
    fn start(&self) -> Option<u64> {
        match self {
            Self::List(_) => None,
            Self::Array { start, .. } | Self::Chain { start, .. } => Some(*start),
        }
    }

    /// The link this walk follows out of each node, when it follows one.
    fn link(&self) -> Option<i64> {
        match self {
            Self::Chain { next_offset, .. } => Some(*next_offset),
            _ => None,
        }
    }

    fn mode(&self) -> structured::WalkMode {
        match self {
            Self::List(_) => structured::WalkMode::List,
            Self::Array { .. } => structured::WalkMode::Array,
            Self::Chain { .. } => structured::WalkMode::Chain,
        }
    }
}

/// Why a walk gave up before it ran out of nodes — the two reasons that are about the *call*
/// rather than about the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Halt {
    /// The caller's remaining patience ran out.
    Deadline,
    /// Someone called `interrupt` on this session.
    Interrupted,
}

/// Walks `source`, reading `fields` out of every node it reaches.
///
/// `read` fetches bytes and returns `None` for memory the debugger could not read — the whole
/// point of this module, and a plain `Option` because which of the several ways `ReadVirtual` says
/// no is not a distinction a caller can act on, while threading a thousand copies of one message
/// back would bury the table in it.
///
/// `halt` is polled **once per node, before its reads**, which is where a bound has to sit when
/// the loop's body is the expensive part: checking afterwards would let an interrupt arrive during
/// node 3 and still pay for node 4's round trips. What it stops is reported as the walk's outcome
/// rather than as a failure, and the nodes already read come back — a walk cut short is this tool
/// working, not this tool breaking.
///
/// **There is deliberately no poll after the last node**, which looks like a gap and is not. The
/// loop leaves four ways: the count was reached, the address list ran out, a chain ended on its own
/// terms, or `halt` fired — so the only path on which an interrupt *truncates* a walk is the one
/// that already observes it. A break landing during the final read changed nothing, and recording
/// it in [`structured::WalkStop`] would report a truncation that did not happen, telling a caller
/// the rest is unknown when there is no rest. The interrupt is a fact about the **call**, and
/// `worker::cut_short` says so in the prose, for every tool alike.
pub fn run(
    source: &Resolved,
    fields: &[Field],
    mut read: impl FnMut(u64, usize) -> Option<Vec<u8>>,
    mut halt: impl FnMut() -> Option<Halt>,
) -> structured::MemoryWalk {
    let (head, count) = source.head().unzip();
    let count = count.unwrap_or(0);
    let link = source.link();
    let mut nodes: Vec<structured::WalkNode> = Vec::new();
    // Every node visited, so a chain pointing back into itself is reported where it closes rather
    // than walked to its cap. The head is in here from the first iteration: a circular
    // `_LIST_ENTRY` returning to it is the ordinary end of a healthy list, not a special case.
    let mut visited: HashSet<u64> = HashSet::new();
    let mut unreadable = 0u32;
    let mut stopped = structured::WalkStop::Complete;
    let mut index = 0u32;
    let mut next_node = head;

    while index < count {
        let Some(at) = next_node else { break };
        if let Some(halted) = halt() {
            stopped = match halted {
                Halt::Deadline => structured::WalkStop::Deadline,
                Halt::Interrupted => structured::WalkStop::Interrupted,
            };
            break;
        }

        let node = read_node(at, index, fields, link, &mut read);
        if !node.readable {
            unreadable += 1;
        }
        let followed = node.next.clone();
        visited.insert(at);
        nodes.push(node);
        index += 1;

        next_node = match source {
            Resolved::List(addresses) => addresses.get(index as usize).copied(),
            Resolved::Array { stride, .. } => Some(at.wrapping_add_signed(*stride)),
            Resolved::Chain { .. } => {
                // `followed` is the link this node held, and the three ways a chain ends are all
                // statements about it. Each is a finding rather than a failure.
                let Some(next) = followed.as_deref().and_then(parse_addr_back) else {
                    stopped = structured::WalkStop::UnreadableLink { at: addr(at) };
                    break;
                };
                if next == 0 {
                    stopped = structured::WalkStop::NullLink;
                    break;
                }
                if visited.contains(&next) {
                    stopped = structured::WalkStop::Loop { at: addr(next) };
                    break;
                }
                Some(next)
            }
        };
    }

    // A chain that reached its cap has one more thing to say than "done": where it was up to. The
    // three ways it could have *ended* are ruled out above — the loop only leaves a link in hand
    // when it is readable, non-null and unvisited — so this is unambiguously "there is more", and
    // the address is what a caller walks from next.
    if matches!(stopped, structured::WalkStop::Complete)
        && matches!(source, Resolved::Chain { .. })
        && let Some(next) = next_node
    {
        stopped = structured::WalkStop::Cap { next: addr(next) };
    }

    structured::MemoryWalk {
        mode: source.mode(),
        start: source.start().map(addr),
        requested: count,
        walked: nodes.len() as u32,
        unreadable,
        nodes,
        stopped,
        // Filled in by the caller that owns the reader, which is the only side that has the
        // engine's words for a read that failed. See [`structured::MemoryWalk::note`].
        note: None,
    }
}

/// Whether a walk read nothing at all — the one outcome that needs the reader to explain itself.
///
/// A walk of freed objects legitimately comes back this way, and so does one against a target
/// that is not broken in. They are the same table, so the caller of [`run`] attaches the
/// debugger's own message when this holds.
pub fn read_nothing(walk: &structured::MemoryWalk) -> bool {
    walk.walked > 0 && walk.unreadable == walk.walked
}

/// Reads one node's fields, and the link out of it when there is one.
///
/// The fields are fetched in **one read of the span they cover**, where that span is narrow enough
/// to be a structure rather than a haul ([`MAX_SPAN`]) — one round trip per node instead of one
/// per field, which is what lets a 512-node walk finish over a KD link.
///
/// When that read fails the fields are read individually, and that is not merely a fallback: a
/// node straddling a page boundary with only its second page unmapped answers *most* of the
/// question, and a span read is all-or-nothing about it. Paying for per-field reads only where
/// there is actually a hole keeps the precise answer and the cheap one at once.
fn read_node(
    at: u64,
    index: u32,
    fields: &[Field],
    link: Option<i64>,
    read: &mut impl FnMut(u64, usize) -> Option<Vec<u8>>,
) -> structured::WalkNode {
    // The link is read with the fields rather than after them: it lives in the same structure and
    // usually in the same span, so folding it in is the difference between one read and two.
    let reads = fields
        .iter()
        .map(|f| (f.offset, f.size))
        .chain(link.map(|offset| (offset, 8)));
    let lo = reads.clone().map(|(offset, _)| offset).min();
    let hi = reads
        .clone()
        .map(|(offset, size)| offset.saturating_add(i64::from(size)))
        .max();
    // Only worth coalescing when there is more than one read to coalesce. With a single value the
    // span read *is* that value's read, so a failed one would be retried below against the same
    // bytes — and the single-value bulk read over a table full of holes is this tool's commonest
    // shape, which would then cost two round trips per hole instead of one.
    let coalesce = reads.count() > 1;
    let buffer = lo
        .zip(hi)
        .filter(|(lo, hi)| coalesce && hi.saturating_sub(*lo) <= MAX_SPAN)
        .and_then(|(lo, hi)| {
            read(at.wrapping_add_signed(lo), (hi - lo) as usize).map(|bytes| (lo, bytes))
        });

    // One closure for both routes, so which one served a field cannot change the value it gets.
    let mut value = |offset: i64, size: u32| -> Option<u64> {
        match &buffer {
            Some((lo, bytes)) => {
                let from = offset.abs_diff(*lo) as usize;
                bytes.get(from..from.checked_add(size as usize)?).map(le)
            }
            None => read(at.wrapping_add_signed(offset), size as usize)
                .as_deref()
                .map(le),
        }
    };

    let values: Vec<structured::WalkFieldValue> = fields
        .iter()
        .map(|field| structured::WalkFieldValue {
            name: field.name.clone(),
            address: addr(at.wrapping_add_signed(field.offset)),
            size: field.size,
            value: value(field.offset, field.size).map(addr),
        })
        .collect();
    let next = link.and_then(|offset| value(offset, 8)).map(addr);

    structured::WalkNode {
        index,
        address: addr(at),
        // "Nothing here could be read" is the claim worth making about a node, and it is not the
        // same as any one field failing: a structure whose last qword is unreadable because it
        // straddles a guard page still answers for the fields before it, and calling that node
        // unreadable would overstate the hole by the width of the structure.
        readable: values.iter().any(|v| v.value.is_some()) || next.is_some(),
        next,
        fields: values,
    }
}

/// Little-endian, whatever the width: `db`/`dw`/`dd`/`dq` read the same bytes the same way.
fn le(bytes: &[u8]) -> u64 {
    bytes.iter().enumerate().fold(0u64, |value, (i, byte)| {
        value | (u64::from(*byte) << (8 * i))
    })
}

/// Reads back an address this module wrote with [`addr`].
///
/// A chain's link crosses from [`read_node`] to the traversal as the same string the caller sees,
/// rather than as a second `u64` beside it, so the address a report prints and the address the
/// walk followed cannot disagree.
fn parse_addr_back(text: &str) -> Option<u64> {
    u64::from_str_radix(text.strip_prefix("0x")?, 16).ok()
}

// ---- rendering ------------------------------------------------------------

/// The walk as a table, for the reader who is not a program.
pub fn render(walk: &structured::MemoryWalk) -> String {
    let mut out = heading(walk);
    out.push_str("\n\n");

    // Column widths are the *value* widths, so an unreadable cell — `0x????????????????`, exactly
    // as wide as the value it stands in for — keeps the table a table precisely where the
    // interesting rows are.
    let index_width = walk.walked.max(1).to_string().len().max(3);
    let columns: Vec<(&str, usize)> = walk
        .nodes
        .first()
        .map(|node| {
            node.fields
                .iter()
                .map(|f| (f.name.as_str(), f.name.len().max(2 + 2 * f.size as usize)))
                .collect()
        })
        .unwrap_or_default();
    let chain = matches!(walk.mode, structured::WalkMode::Chain);

    let mut header = format!("  {:>index_width$}  {:<18}", "idx", "node");
    if chain {
        header.push_str(&format!("  {:<18}", "next"));
    }
    for (name, width) in &columns {
        header.push_str(&format!("  {name:<width$}"));
    }
    out.push_str(header.trim_end());
    out.push('\n');

    for node in &walk.nodes {
        let mut row = format!("  {:>index_width$}  {}", node.index, node.address);
        if chain {
            row.push_str(&format!("  {}", cell(node.next.as_deref(), 8)));
        }
        for (field, (_, width)) in node.fields.iter().zip(&columns) {
            row.push_str(&format!(
                "  {:<width$}",
                cell(field.value.as_deref(), field.size)
            ));
        }
        out.push_str(row.trim_end());
        out.push('\n');
    }

    out.push('\n');
    out.push_str(&summary(walk));
    out
}

/// The first line: what was walked, and how.
fn heading(walk: &structured::MemoryWalk) -> String {
    let start = walk.start.as_deref().unwrap_or("?");
    match walk.mode {
        structured::WalkMode::List => format!(
            "Memory walk: {} address{} supplied.",
            walk.requested,
            if walk.requested == 1 { "" } else { "es" }
        ),
        structured::WalkMode::Array => {
            format!("Memory walk: up to {} nodes from {start}.", walk.requested)
        }
        structured::WalkMode::Chain => format!(
            "Memory walk: up to {} nodes chained from {start}.",
            walk.requested
        ),
    }
}

/// One value in the table, or the debugger's own mark for memory it could not read.
///
/// `????` rather than a word, and exactly as wide as the value would have been: it is what `dd`
/// prints for an unmapped page, so it reads as "the debugger could not read this" to anyone who
/// has used the debugger, and it keeps the column aligned.
fn cell(value: Option<&str>, size: u32) -> String {
    let digits = 2 * size as usize;
    match value {
        // Trimmed to the field's own width: a byte read renders as `0x41`, not as a qword with
        // fourteen leading zeroes it never read. The structured half keeps one width for every
        // value; this half is for a person comparing a column.
        Some(value) => {
            let hex = value.trim_start_matches("0x");
            format!("0x{}", &hex[hex.len().saturating_sub(digits)..])
        }
        None => format!("0x{}", "?".repeat(digits)),
    }
}

/// The footer: how much was read, what could not be, and why it ended.
fn summary(walk: &structured::MemoryWalk) -> String {
    let mut out = format!(
        "{} node{} walked",
        walk.walked,
        if walk.walked == 1 { "" } else { "s" }
    );
    if walk.unreadable > 0 {
        out.push_str(&format!(
            ", {} of which the debugger could not read at all",
            walk.unreadable
        ));
    }
    out.push_str(".\n");
    out.push_str(&format!("Stopped: {}\n", stop_sentence(&walk.stopped)));
    if let Some(note) = &walk.note {
        out.push_str(&format!(
            "\nNothing here could be read at all. The debugger's reason for the first read: \
             {note}\nA list of freed objects really does look like this — but so does a target \
             that is not broken in, or a `start` that is not where you think it is. \
             `session_status` says which.\n"
        ));
    }
    // Keyed on the *cells* rather than on `unreadable`, because one hole in a node that otherwise
    // read fine puts a `????` in the table without making that node unreadable — and a legend for
    // a mark the reader can see is the whole job of a legend.
    let unread_cell = |node: &structured::WalkNode| {
        node.fields.iter().any(|field| field.value.is_none())
            || (matches!(walk.mode, structured::WalkMode::Chain) && node.next.is_none())
    };
    if walk.nodes.iter().any(unread_cell) {
        out.push_str(
            "\n`0x????` marks memory the debugger could not read — unmapped, paged out, or not \
             captured in this dump. Those nodes are reported rather than dropped: in a \
             use-after-free walk the pointer that will not read is usually the one worth looking \
             at. `pool_chunk` says whether such an address was pool, and whether it is still \
             allocated.\n",
        );
    }
    out
}

fn stop_sentence(stopped: &structured::WalkStop) -> String {
    match stopped {
        structured::WalkStop::Complete => {
            "every node asked for was visited; there is nothing left to walk.".to_string()
        }
        structured::WalkStop::Cap { next } => format!(
            "the requested count was reached and the chain continues at {next}. Walk again from \
             there for more."
        ),
        structured::WalkStop::NullLink => {
            "the next pointer is null — the chain ends here.".to_string()
        }
        structured::WalkStop::Loop { at } => format!(
            "the chain returned to {at}, a node it had already visited. Back at the head that is \
             the ordinary end of a circular _LIST_ENTRY; anywhere else it is a loop."
        ),
        structured::WalkStop::UnreadableLink { at } => format!(
            "the next pointer in the node at {at} could not be read, so there is no address to \
             continue from. The nodes above are what the chain reached; `pool_chunk` on that node \
             says whether it has been freed."
        ),
        structured::WalkStop::Deadline => "this call ran out of time. The nodes above were really \
                                           read; the rest are unknown rather than absent. Walk a \
                                           smaller `count`, issue it on an idle session, or raise \
                                           the server's call timeout \
                                           (WINDBG_MCP_CALL_TIMEOUT_SECS)."
            .to_string(),
        structured::WalkStop::Interrupted => {
            "interrupted. The nodes above were read before the break landed.".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake address space. A walk's whole contract is what it does with the holes in one, and
    /// nothing here needs a debugger to have holes.
    struct Memory {
        mapped: Vec<(u64, Vec<u8>)>,
        reads: usize,
    }

    impl Memory {
        fn new() -> Self {
            Self {
                mapped: Vec::new(),
                reads: 0,
            }
        }

        fn at(mut self, address: u64, bytes: &[u8]) -> Self {
            self.mapped.push((address, bytes.to_vec()));
            self
        }

        /// A node holding `next` at +0 and `value` at +8.
        fn node(self, address: u64, next: u64, value: u64) -> Self {
            let mut bytes = next.to_le_bytes().to_vec();
            bytes.extend_from_slice(&value.to_le_bytes());
            self.at(address, &bytes)
        }

        /// Every requested byte has to fall inside one mapping, which is what makes a read
        /// straddling a hole fail outright — as `ReadVirtual` does — rather than come back short.
        fn read(&mut self, address: u64, size: usize) -> Option<Vec<u8>> {
            self.reads += 1;
            let (base, bytes) = self.mapped.iter().find(|(base, bytes)| {
                address >= *base && address + size as u64 <= base + bytes.len() as u64
            })?;
            let from = (address - base) as usize;
            Some(bytes[from..from + size].to_vec())
        }
    }

    fn field(name: &str, offset: i64, size: u32) -> Field {
        Field {
            name: name.to_string(),
            offset,
            size,
        }
    }

    fn never_halts() -> Option<Halt> {
        None
    }

    /// The failure this module exists for: one unreadable node in the middle of a list is a row,
    /// and every node after it is still walked.
    #[test]
    fn an_unreadable_node_does_not_end_a_list_walk() {
        let mut memory = Memory::new()
            .at(0x1000, &0xaaaau64.to_le_bytes())
            .at(0x3000, &0xccccu64.to_le_bytes());
        let walk = run(
            &Resolved::List(vec![0x1000, 0x2000, 0x3000]),
            &[field("value", 0, 8)],
            |a, s| memory.read(a, s),
            never_halts,
        );

        assert_eq!(walk.walked, 3, "the hole must not shorten the walk");
        assert_eq!(walk.unreadable, 1);
        assert_eq!(walk.nodes[0].fields[0].value, Some(addr(0xaaaa)));
        assert_eq!(walk.nodes[1].fields[0].value, None);
        assert!(!walk.nodes[1].readable);
        assert_eq!(walk.nodes[2].fields[0].value, Some(addr(0xcccc)));
        assert_eq!(walk.stopped, structured::WalkStop::Complete);
    }

    /// The same for an array, whose next address is arithmetic and so cannot be lost to a hole.
    #[test]
    fn an_unreadable_element_does_not_end_an_array_walk() {
        let mut memory = Memory::new()
            .at(0x1000, &1u64.to_le_bytes())
            .at(0x1010, &3u64.to_le_bytes());
        let walk = run(
            &Resolved::Array {
                start: 0x1000,
                stride: 8,
                count: 3,
            },
            &[field("value", 0, 8)],
            |a, s| memory.read(a, s),
            never_halts,
        );

        assert_eq!(walk.walked, 3);
        assert_eq!(walk.unreadable, 1);
        assert_eq!(walk.nodes[1].address, addr(0x1008));
        assert_eq!(walk.nodes[2].fields[0].value, Some(addr(3)));
    }

    /// A chain *is* ended by an unreadable node, because the address of everything after it lived
    /// in the bytes that would not read — and the report says so rather than calling it the end of
    /// the list.
    #[test]
    fn an_unreadable_link_ends_a_chain_and_says_which_node() {
        let mut memory = Memory::new().node(0x1000, 0x2000, 0xaa);
        let walk = run(
            &Resolved::Chain {
                start: 0x1000,
                next_offset: 0,
                count: 8,
            },
            &[field("value", 8, 8)],
            |a, s| memory.read(a, s),
            never_halts,
        );

        assert_eq!(walk.walked, 2, "the unreadable node is still a row");
        assert_eq!(
            walk.stopped,
            structured::WalkStop::UnreadableLink { at: addr(0x2000) }
        );
    }

    #[test]
    fn a_chain_ends_on_a_null_link() {
        let mut memory = Memory::new().node(0x1000, 0x2000, 1).node(0x2000, 0, 2);
        let walk = run(
            &Resolved::Chain {
                start: 0x1000,
                next_offset: 0,
                count: 8,
            },
            &[],
            |a, s| memory.read(a, s),
            never_halts,
        );

        assert_eq!(walk.walked, 2);
        assert_eq!(walk.stopped, structured::WalkStop::NullLink);
    }

    /// A corrupted list pointing back into itself is a finding, not a hang: the walk reports where
    /// it closed instead of running to its cap.
    #[test]
    fn a_chain_that_loops_is_reported_where_it_closes() {
        let mut memory = Memory::new()
            .node(0x1000, 0x2000, 1)
            .node(0x2000, 0x3000, 2)
            .node(0x3000, 0x2000, 3);
        let walk = run(
            &Resolved::Chain {
                start: 0x1000,
                next_offset: 0,
                count: 64,
            },
            &[],
            |a, s| memory.read(a, s),
            never_halts,
        );

        assert_eq!(walk.walked, 3);
        assert_eq!(
            walk.stopped,
            structured::WalkStop::Loop { at: addr(0x2000) }
        );
    }

    /// A circular `_LIST_ENTRY` closing on its head is the same mechanism, and must not run to the
    /// cap either.
    #[test]
    fn a_circular_list_closes_on_its_head() {
        let mut memory = Memory::new()
            .node(0x1000, 0x2000, 1)
            .node(0x2000, 0x1000, 2);
        let walk = run(
            &Resolved::Chain {
                start: 0x1000,
                next_offset: 0,
                count: 64,
            },
            &[],
            |a, s| memory.read(a, s),
            never_halts,
        );

        assert_eq!(walk.walked, 2);
        assert_eq!(
            walk.stopped,
            structured::WalkStop::Loop { at: addr(0x1000) }
        );
    }

    /// Reaching the cap on a chain is not "done": it hands back where to resume, which is the
    /// difference between a walk a caller can continue and one they have to reconstruct.
    #[test]
    fn a_chain_at_its_cap_reports_where_to_resume() {
        let mut memory = Memory::new()
            .node(0x1000, 0x2000, 1)
            .node(0x2000, 0x3000, 2)
            .node(0x3000, 0x4000, 3);
        let walk = run(
            &Resolved::Chain {
                start: 0x1000,
                next_offset: 0,
                count: 2,
            },
            &[],
            |a, s| memory.read(a, s),
            never_halts,
        );

        assert_eq!(walk.walked, 2);
        assert_eq!(
            walk.stopped,
            structured::WalkStop::Cap { next: addr(0x3000) }
        );
    }

    /// A chain whose cap lands exactly on the last node reports the *end*, not the cap: the link
    /// is read as part of the node, so "there is more" is a fact rather than an assumption.
    #[test]
    fn a_chain_that_ends_at_its_cap_says_it_ended() {
        let mut memory = Memory::new().node(0x1000, 0x2000, 1).node(0x2000, 0, 2);
        let walk = run(
            &Resolved::Chain {
                start: 0x1000,
                next_offset: 0,
                count: 2,
            },
            &[],
            |a, s| memory.read(a, s),
            never_halts,
        );

        assert_eq!(walk.stopped, structured::WalkStop::NullLink);
    }

    /// Fields of one structure cost one read, not one read each — over a KD link that is the
    /// difference between a walk that answers and a walk that times out.
    #[test]
    fn fields_in_one_structure_are_fetched_in_one_read() {
        let mut bytes = vec![0u8; 0x40];
        bytes[0x10] = 0x41;
        bytes[0x20] = 0x42;
        let mut memory = Memory::new().at(0x1000, &bytes);
        let walk = run(
            &Resolved::List(vec![0x1000]),
            &[field("a", 0x10, 1), field("b", 0x20, 1)],
            |a, s| memory.read(a, s),
            never_halts,
        );

        assert_eq!(memory.reads, 1, "two fields, one round trip");
        assert_eq!(walk.nodes[0].fields[0].value, Some(addr(0x41)));
        assert_eq!(walk.nodes[0].fields[1].value, Some(addr(0x42)));
    }

    /// A hole in the commonest shape of all — one value per node — costs one read, not two.
    ///
    /// The per-field fallback exists because a coalesced read is all-or-nothing; with a single
    /// value there is nothing to coalesce, so retrying would re-read the bytes that just failed.
    /// Over a 512-entry table where a third of the objects are freed that is 170 wasted round
    /// trips on a KD link.
    #[test]
    fn a_single_value_costs_one_read_whether_or_not_it_is_there() {
        let mut memory = Memory::new().at(0x1000, &7u64.to_le_bytes());
        let walk = run(
            &Resolved::List(vec![0x1000, 0x2000]),
            &[field("value", 0, 8)],
            |a, s| memory.read(a, s),
            never_halts,
        );

        assert_eq!(walk.walked, 2);
        assert_eq!(memory.reads, 2, "one read for the hit and one for the hole");
    }

    /// And when that one read fails, the fields are read individually — so a structure with only
    /// its tail unmapped still answers for its head, instead of being written off whole.
    #[test]
    fn a_partly_mapped_node_answers_for_the_fields_that_are_mapped() {
        // +0 is mapped, +0x100 is not, so the span covering both fails and only the per-field
        // route can tell them apart.
        let mut memory = Memory::new().at(0x1000, &0x1234u64.to_le_bytes());
        let walk = run(
            &Resolved::List(vec![0x1000]),
            &[field("head", 0, 8), field("tail", 0x100, 8)],
            |a, s| memory.read(a, s),
            never_halts,
        );

        assert_eq!(walk.nodes[0].fields[0].value, Some(addr(0x1234)));
        assert_eq!(walk.nodes[0].fields[1].value, None);
        assert!(
            walk.nodes[0].readable,
            "a node with one readable field is not an unreadable node"
        );
        assert_eq!(walk.unreadable, 0);
    }

    /// A field behind the pointer a caller holds — a pool header at -0x10 — is one argument, not
    /// arithmetic the caller does per node and the table then cannot line up.
    #[test]
    fn a_negative_offset_reads_behind_the_node() {
        let mut memory = Memory::new().at(0x1000, &0xfeedu64.to_le_bytes());
        let walk = run(
            &Resolved::List(vec![0x1010]),
            &[field("header", -0x10, 8)],
            |a, s| memory.read(a, s),
            never_halts,
        );

        assert_eq!(walk.nodes[0].fields[0].address, addr(0x1000));
        assert_eq!(walk.nodes[0].fields[0].value, Some(addr(0xfeed)));
    }

    /// Widths narrower than a pointer read the bytes the debugger would, little-endian.
    #[test]
    fn narrow_fields_read_their_own_width() {
        let mut memory = Memory::new().at(0x1000, &[0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0]);
        let walk = run(
            &Resolved::List(vec![0x1000]),
            &[field("b", 0, 1), field("w", 0, 2), field("d", 0, 4)],
            |a, s| memory.read(a, s),
            never_halts,
        );

        let value = |i: usize| walk.nodes[0].fields[i].value.clone().unwrap();
        assert_eq!(value(0), addr(0x78));
        assert_eq!(value(1), addr(0x5678));
        assert_eq!(value(2), addr(0x1234_5678));
    }

    /// A halt is polled before a node's reads, not after: an interrupt landing during node 1 must
    /// not buy node 2's round trips.
    #[test]
    fn a_halt_stops_before_the_next_nodes_reads() {
        let mut memory = Memory::new()
            .at(0x1000, &1u64.to_le_bytes())
            .at(0x1008, &2u64.to_le_bytes())
            .at(0x1010, &3u64.to_le_bytes());
        let mut polls = 0;
        let walk = run(
            &Resolved::Array {
                start: 0x1000,
                stride: 8,
                count: 3,
            },
            &[field("value", 0, 8)],
            |a, s| memory.read(a, s),
            || {
                polls += 1;
                (polls > 2).then_some(Halt::Interrupted)
            },
        );

        assert_eq!(walk.walked, 2, "the third node's reads were never paid for");
        assert_eq!(memory.reads, 2);
        assert_eq!(walk.stopped, structured::WalkStop::Interrupted);
    }

    /// A walk that ran out of the caller's clock says so and hands back what it really read — the
    /// same distinction the pool walk draws between "not there" and "not reached".
    #[test]
    fn a_deadline_returns_what_was_read() {
        let mut memory = Memory::new().at(0x1000, &1u64.to_le_bytes());
        let mut polls = 0;
        let walk = run(
            &Resolved::Array {
                start: 0x1000,
                stride: 8,
                count: 64,
            },
            &[field("value", 0, 8)],
            |a, s| memory.read(a, s),
            || {
                polls += 1;
                (polls > 1).then_some(Halt::Deadline)
            },
        );

        assert_eq!(walk.walked, 1);
        assert_eq!(walk.stopped, structured::WalkStop::Deadline);
    }

    // ---- argument validation ------------------------------------------------

    #[test]
    fn a_list_and_a_traversal_are_not_combinable() {
        let err = WalkOp::new(
            Some(vec!["0x1000".into()]),
            Some("0x2000".into()),
            Some(8),
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(err.contains("cannot be combined"), "{err}");
    }

    #[test]
    fn a_list_carries_its_own_count() {
        let err =
            WalkOp::new(Some(vec!["0x1000".into()]), None, None, None, Some(4), None).unwrap_err();
        assert!(err.contains("the same thing twice"), "{err}");
    }

    #[test]
    fn a_stride_and_a_next_offset_are_two_different_walks() {
        let err =
            WalkOp::new(None, Some("0x1000".into()), Some(8), Some(0), None, None).unwrap_err();
        assert!(err.contains("Pass one"), "{err}");
    }

    #[test]
    fn a_start_with_no_traversal_is_refused() {
        let err = WalkOp::new(None, Some("0x1000".into()), None, None, None, None).unwrap_err();
        assert!(err.contains("needs a traversal"), "{err}");
    }

    #[test]
    fn nothing_at_all_is_refused() {
        let err = WalkOp::new(None, None, None, None, None, None).unwrap_err();
        assert!(err.contains("no nodes to walk"), "{err}");
    }

    /// Refused rather than clamped: a clamp would report "every node asked for was visited" about
    /// a count this server lowered behind the caller's back.
    #[test]
    fn a_count_past_the_cap_is_refused_not_clamped() {
        let err = WalkOp::new(
            None,
            Some("0x1000".into()),
            Some(8),
            None,
            Some(MAX_NODES + 1),
            None,
        )
        .unwrap_err();
        assert!(err.contains("at most"), "{err}");
    }

    #[test]
    fn a_field_size_the_debugger_cannot_read_is_refused() {
        let err = WalkOp::new(
            None,
            Some("0x1000".into()),
            Some(8),
            None,
            None,
            Some(vec![FieldArg {
                name: None,
                offset: 0,
                size: Some(3),
            }]),
        )
        .unwrap_err();
        assert!(err.contains("1, 2, 4 or 8"), "{err}");
    }

    /// A list or an array with no fields is the bulk-pointer read; a chain already prints its
    /// link, so defaulting it the same way would print one column twice.
    #[test]
    fn the_default_field_depends_on_what_the_walk_already_reports() {
        let array = WalkOp::new(None, Some("0x1000".into()), Some(8), None, None, None).unwrap();
        assert_eq!(array.fields.len(), 1);
        assert_eq!(array.fields[0].offset, 0);
        assert_eq!(array.fields[0].size, 8);

        let chain = WalkOp::new(None, Some("0x1000".into()), None, Some(0), None, None).unwrap();
        assert!(chain.fields.is_empty());
    }

    /// The one argument that is *amplified* — a name is copied into every field of every node —
    /// so the node and field caps do not bound it and it needs its own.
    #[test]
    fn a_field_name_is_bounded_because_it_is_copied_per_node() {
        let err = WalkOp::new(
            None,
            Some("0x1000".into()),
            Some(8),
            None,
            None,
            Some(vec![FieldArg {
                name: Some("n".repeat(MAX_FIELD_NAME + 1)),
                offset: 0,
                size: None,
            }]),
        )
        .unwrap_err();
        assert!(err.contains("column header"), "{err}");

        // And the bound is on characters a reader sees, not on the bytes they encode to: a name
        // of CJK characters must not be refused at a third of its apparent length.
        assert!(
            WalkOp::new(
                None,
                Some("0x1000".into()),
                Some(8),
                None,
                None,
                Some(vec![FieldArg {
                    name: Some("識".repeat(MAX_FIELD_NAME)),
                    offset: 0,
                    size: None,
                }]),
            )
            .is_ok()
        );
    }

    #[test]
    fn an_unnamed_field_is_named_for_its_offset() {
        let op = WalkOp::new(
            None,
            Some("0x1000".into()),
            Some(8),
            None,
            None,
            Some(vec![
                FieldArg {
                    name: None,
                    offset: 0x18,
                    size: Some(4),
                },
                FieldArg {
                    name: None,
                    offset: -0x10,
                    size: None,
                },
            ]),
        )
        .unwrap();
        assert_eq!(op.fields[0].name, "+0x18");
        assert_eq!(op.fields[1].name, "-0x10");
    }

    /// Addresses come in the forms the debugger prints, so a chunk address copied out of
    /// `pool_chunk` goes straight into this tool.
    #[test]
    fn addresses_accept_the_forms_the_debugger_prints() {
        let op = WalkOp::new(
            Some(vec![
                "ffffc00f`6ec02f90".into(),
                "0x1000".into(),
                "4096".into(),
            ]),
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        let Source::List { addresses } = op.source else {
            panic!("a list")
        };
        assert_eq!(addresses, [0xffffc00f_6ec02f90, 0x1000, 4096]);
    }

    // ---- rendering ----------------------------------------------------------

    /// An unreadable cell is as wide as the value it stands in for, so the column a caller is
    /// scanning stays a column exactly where the interesting rows are.
    #[test]
    fn an_unreadable_cell_keeps_the_column_aligned() {
        let mut memory = Memory::new().at(0x1000, &0xaaaau64.to_le_bytes());
        let walk = run(
            &Resolved::List(vec![0x1000, 0x2000]),
            &[field("value", 0, 8)],
            |a, s| memory.read(a, s),
            never_halts,
        );
        let text = render(&walk);

        let rows: Vec<&str> = text
            .lines()
            .filter(|l| l.contains(&addr(0x1000)) || l.contains(&addr(0x2000)))
            .collect();
        assert_eq!(rows.len(), 2, "{text}");
        assert_eq!(rows[0].len(), rows[1].len(), "{text}");
        assert!(rows[1].contains("0x????????????????"), "{text}");
    }

    /// The footer has to say what stopped the walk, or "2 nodes" reads the same whether the list
    /// ended, the cap was hit, or the call ran out of time.
    #[test]
    fn the_summary_names_what_stopped_the_walk() {
        let mut memory = Memory::new().node(0x1000, 0x2000, 1).node(0x2000, 0, 2);
        let walk = run(
            &Resolved::Chain {
                start: 0x1000,
                next_offset: 0,
                count: 8,
            },
            &[],
            |a, s| memory.read(a, s),
            never_halts,
        );
        let text = render(&walk);

        assert!(text.contains("2 nodes walked"), "{text}");
        assert!(text.contains("the chain ends here"), "{text}");
    }
}
