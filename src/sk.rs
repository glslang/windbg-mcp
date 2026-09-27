//! Secure Kernel landmarks out of a guest's **VTL1**, over a source seam.
//!
//! `FOLLOWUPS.md` item 103 gate **S1**. Gates H0–H4 of
//! [`docs/secure-kernel/secure-kernel-hypercall-feasibility.md`] reached a VBS guest's VTL1 from
//! the root partition and found `securekernel.exe`, its `KdDebuggerDataBlock` and its module
//! list; gate S0 then found a **second** byte source for the same pages — a Hyper-V saved state,
//! which needs no driver. This module is everything those two runs decoded, with the byte source
//! as a parameter: a guarded four-level page-table walk, PE identification against an on-disk
//! image, the debugger data block, and the loader list it points at.
//!
//! # The seam is not `read(gpa, len)` alone
//!
//! A decode cannot start from reads. It starts from the **VTL1 page-table root**, which H4 read
//! with `HvCallGetVpRegisters` against a live processor and S0 read out of a capture's saved
//! register state. So the root is part of the source contract ([`GuestShape::cr3`]) rather than
//! something derived here, and the measured reason is in the record: three captures of one guest
//! carry `0x1201000`, `0x1201000` and `0x107593000`. An implementation carrying the first forward
//! would have walked from the wrong root on the third and not been told.
//!
//! # What a failed read is allowed to look like, which is the whole design
//!
//! Three failure modes have each cost a run, and none of them is "no bytes came back":
//!
//! - **A refusal answers success.** `HvCallReadGpa` returns `HV_STATUS_SUCCESS` with a per-access
//!   `ReadIntercept` and zeros. A seam carrying bytes-or-nothing turns protected memory into
//!   plausible zeros, so [`ReadFailure`] carries *why* and [`ReadFailure::Refused`] is its own
//!   variant.
//! - **A consumer drops the reason.** The contract "return a reason" binds the producer only;
//!   four review rounds on S0's probe each found another `if reason { continue }` reporting a
//!   clean negative. So the count lives **inside** [`Reader::read`], where no consumer can bypass
//!   it, and each scan keeps its own count beside it for locality. A run that found nothing with a
//!   non-zero [`ReadStats::failed`] is a run whose negative has not been earned.
//! - **The source's transfer width leaks.** `HvCallReadGpa` moves at most 16 bytes, and judging a
//!   4096-byte page on its first sixteen is what made Secure Kernel's PML4 read as all-zero for
//!   most of a session. [`Reader::read`] chunks at [`RawSource::max_read`] and answers whole or
//!   not at all, so no decode below sees a source's width.
//!
//! # Unknown is not wrong
//!
//! Every field of [`GuestShape`] is optional, and [`walkable`] refuses on what a source *says* and
//! never on what it could not say. A provider that cannot return `EFER` must not read as a machine
//! that is not in long mode, and a refused VTL switch — which is the control arm's entire result —
//! must not read the same as a register that did not come back. They are separate variants of
//! [`NotWalkable`] for that reason.
//!
//! # Engine-free, and testable with no bench
//!
//! Nothing here loads DbgEng, opens a session or names a VM: it takes a [`RawSource`] and an
//! on-disk image. The fixtures below are **synthetic** — page tables and PE headers built to hit
//! the self-map, the large-page mask, a duplicate mapping and a stale list deliberately, which a
//! captured page does only by luck. Pages recorded off a real Secure Kernel are memory-dump
//! material and `AGENTS.md` keeps those out of the tree.

use std::collections::{BTreeMap, HashSet};

/// 4 KiB, the granularity everything here reads and translates at.
pub(crate) const PAGE: u64 = 0x1000;

/// Bits 12–51 of a paging entry: the frame it points at.
const PFN_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// Bit 0 of a paging entry.
const ENTRY_PRESENT: u64 = 1;

/// Bit 7 of a paging entry: page size, meaning "this is a leaf" below the PML4.
const ENTRY_LARGE: u64 = 0x80;

/// Hard ceiling on table reads in one descent.
///
/// Not a tuning knob: an unguarded walk of Secure Kernel's self-mapping PML4 took the bench down
/// twice during H4 and cost a reboot each time. Exceeding it is reported ([`WalkStats::complete`]),
/// never absorbed.
const MAX_TABLE_READS: u64 = 20_000;

/// Hard ceiling on collected leaves in one descent. Reported the same way.
const MAX_LEAVES: usize = 200_000;

/// A guest **physical** address.
///
/// A newtype rather than a `u64` because the two address spaces here are read by different
/// primitives — [`Reader::read`] takes physical, [`Space::read_span`] takes virtual — and the
/// failure from mixing them is not a compile error but a plausible-looking page of somebody
/// else's memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Gpa(pub(crate) u64);

/// A guest **virtual** address, in the space whose root [`walkable`] returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Gva(pub(crate) u64);

// Hex formatting on both, so a report never has to reach through the newtype to print an address —
// which is how a `Gva` gets printed where a `Gpa` was meant.
impl std::fmt::UpperHex for Gpa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::UpperHex::fmt(&self.0, f)
    }
}

impl std::fmt::UpperHex for Gva {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::UpperHex::fmt(&self.0, f)
    }
}

impl Gpa {
    /// This address with its offset-in-page cleared.
    fn page(self) -> Gpa {
        Gpa(self.0 & !(PAGE - 1))
    }

    fn offset(self, by: u64) -> Gpa {
        Gpa(self.0.wrapping_add(by))
    }
}

impl Gva {
    /// Bits 63:48 sign-extended from bit 47, which is what a 4-level x64 walk produces.
    ///
    /// Kept as an unsigned value. The probe's note applies here too for a different reason: a
    /// signed form prints correctly and then compares unequal against every pointer read out of
    /// the guest, which are unsigned words.
    fn canonical(self) -> Gva {
        if self.0 & (1 << 47) != 0 {
            Gva(self.0 | 0xFFFF_0000_0000_0000)
        } else {
            self
        }
    }

    fn page(self) -> Gva {
        Gva(self.0 & !(PAGE - 1))
    }

    fn offset_in_page(self) -> u64 {
        self.0 & (PAGE - 1)
    }

    fn offset(self, by: u64) -> Gva {
        Gva(self.0.wrapping_add(by))
    }
}

/// The paging mode a source reports for the processor its bytes were captured from.
///
/// The names are the SDK's `PAGING_MODE`, so a provider's number maps onto them without a table of
/// our own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PagingMode {
    Invalid,
    NonPaged,
    Bits32,
    Pae,
    Long,
    Armv8,
    /// A value this build does not know, kept as itself rather than folded into `Invalid` — an
    /// unrecognised mode is unknown, and unknown is not wrong.
    Other(i32),
}

impl PagingMode {
    pub(crate) fn from_raw(raw: i32) -> PagingMode {
        match raw {
            0 => PagingMode::Invalid,
            1 => PagingMode::NonPaged,
            2 => PagingMode::Bits32,
            3 => PagingMode::Pae,
            4 => PagingMode::Long,
            5 => PagingMode::Armv8,
            other => PagingMode::Other(other),
        }
    }
}

/// What a source can say about the processor state its bytes belong to.
///
/// **Every field is optional and a `None` means unread**, which is the distinction this struct
/// exists to keep: [`walkable`] refuses on what the source said and never on what it could not
/// say. [`GuestShape::switch_refused`] is separate from [`GuestShape::unreadable`] for the same
/// reason at one level up — "the source will not put this processor in VTL1" is the VBS-off
/// control's entire result, while "the switch worked and a register did not come back" says
/// nothing at all about whether the VTL is there.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct GuestShape {
    /// Why the source could not select this VTL, when it could not. `Some` here makes every field
    /// below meaningless — they describe whichever VTL the processor was left in.
    pub(crate) switch_refused: Option<String>,
    /// The source's own answer to whether the VTL it selected is actually enabled on this
    /// processor. `Some(false)` blocks the walk; `None` does not.
    pub(crate) vtl_enabled: Option<bool>,
    pub(crate) paging_mode: Option<PagingMode>,
    pub(crate) cr0: Option<u64>,
    /// The page-table root. The one field a walk cannot proceed without.
    pub(crate) cr3: Option<u64>,
    pub(crate) cr4: Option<u64>,
    pub(crate) efer: Option<u64>,
    /// Registers that were asked for and did not answer, with the source's reason, so a report
    /// says which question went unanswered rather than looking like a guest with nothing to say.
    pub(crate) unreadable: Vec<(&'static str, String)>,
}

impl GuestShape {
    /// Whether these control registers describe a long-mode processor, or `None` if they cannot
    /// say.
    ///
    /// The control that says a provider's register indexing is right rather than off by one — and
    /// it has to answer *unknown* rather than *false* when a register did not come back, or a
    /// source that cannot return `EFER` reads as a machine that is not in long mode.
    fn long_mode(&self) -> Option<bool> {
        let (cr0, cr4, efer) = (self.cr0?, self.cr4?, self.efer?);
        Some(
            cr0 & (1 << 31) != 0    // PG
                && cr0 & 1 != 0     // PE
                && cr4 & (1 << 5) != 0  // PAE
                && efer & (1 << 10) != 0, // LMA
        )
    }
}

/// Why a [`GuestShape`] is not one to walk from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NotWalkable {
    /// The source would not select the VTL at all. On a VBS-off guest this *is* the result.
    SwitchRefused(String),
    /// The source selected it and reports it is not enabled on this processor, so its register
    /// state describes nothing.
    VtlNotEnabled,
    /// No root came back. Carries what the source said about the registers it could not read, so
    /// this cannot be mistaken for the variant above.
    NoRoot {
        unreadable: Vec<(&'static str, String)>,
    },
    /// A mode this walk does not decode. Named rather than refused blankly: the descent hard-codes
    /// nine-bit indices and a 48-bit canonical form, so any other shape would be traversed with
    /// the wrong strides and yield missing or invented leaves rather than an error — the walk
    /// cannot tell it is reading the wrong tables.
    PagingMode(PagingMode),
    /// `CR4.LA57`: five-level paging, same reason as above.
    FiveLevel,
    /// `GetPagingMode` said one thing and the control registers say another. The registers win: a
    /// four-level walk of tables that are not four-level produces leaves rather than an error, and
    /// nothing downstream can tell.
    NotLongMode,
}

/// Whether this shape is one to walk from, and the root if it is.
pub(crate) fn walkable(shape: &GuestShape) -> Result<Gpa, NotWalkable> {
    if let Some(detail) = &shape.switch_refused {
        return Err(NotWalkable::SwitchRefused(detail.clone()));
    }
    if shape.vtl_enabled == Some(false) {
        return Err(NotWalkable::VtlNotEnabled);
    }
    let Some(cr3) = shape.cr3.filter(|cr3| *cr3 != 0) else {
        return Err(NotWalkable::NoRoot {
            unreadable: shape.unreadable.clone(),
        });
    };
    if let Some(mode) = shape.paging_mode
        && mode != PagingMode::Long
    {
        return Err(NotWalkable::PagingMode(mode));
    }
    if shape.cr4.is_some_and(|cr4| cr4 & (1 << 12) != 0) {
        return Err(NotWalkable::FiveLevel);
    }
    if shape.long_mode() == Some(false) {
        return Err(NotWalkable::NotLongMode);
    }
    Ok(Gpa(cr3).page())
}

/// Why a physical read did not answer.
///
/// The variants are the point. A source that collapses them produces silent zeros exactly where
/// the protected memory is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReadFailure {
    /// The source was told no, per access — `HvCallReadGpa`'s `ReadIntercept`, and whatever a
    /// later source calls the same thing. Bytes may well have been written into the buffer; they
    /// are not an answer.
    ///
    /// **Constructed by no source in this build**, and that is the point rather than an oversight: a
    /// capture has nothing to refuse with, and the route that does — the hypercall H4 measured,
    /// which answers `HV_STATUS_SUCCESS` with a per-access `ReadIntercept` and zeros — is not built
    /// here. The fixtures construct it, so the decode's behaviour on a refusal is pinned before the
    /// source that produces one exists. Mapping a provider `HRESULT` onto it to satisfy the
    /// compiler would be inventing a measurement.
    #[allow(
        dead_code,
        reason = "the live hypercall source is what constructs this; fixtures cover it"
    )]
    Refused { detail: String },
    /// A physical address this source does not cover at all.
    NotPresent,
    /// The source failed on its own terms: an `HRESULT`, a released handle.
    SourceError { detail: String },
    /// Fewer bytes than were asked for. A short read is a failed read, not a small answer.
    Short { got: usize, want: usize },
}

impl ReadFailure {
    /// Whether this failure is the source refusing, as against being unable.
    fn is_refusal(&self) -> bool {
        matches!(self, ReadFailure::Refused { .. })
    }
}

/// A byte source for one guest's physical memory, plus what it can say about the processor.
///
/// Implemented by [`crate::savedstate`] for a Hyper-V capture, and by the fixtures below. A
/// future driver-backed live source joins here and changes nothing above it.
pub(crate) trait RawSource {
    /// What the source knows about the processor state these bytes were captured from.
    ///
    /// Asked once and cheap: an implementation that has to talk to a provider does that when it
    /// opens, not here.
    fn shape(&self) -> GuestShape;

    /// The most this source will transfer in one call.
    ///
    /// 16 for the hypercall route, a page for a capture. [`Reader::read`] chunks at this width so
    /// the number never reaches a decode.
    fn max_read(&self) -> usize;

    /// Fill `out` from physical memory, or say why not. `out.len()` is at most
    /// [`RawSource::max_read`].
    fn read_chunk(&self, gpa: Gpa, out: &mut [u8]) -> Result<(), ReadFailure>;
}

/// Every physical read attempted through a [`Reader`], and how many did not answer.
///
/// Counted at the primitive rather than by each caller, because a per-caller contract in prose is
/// what four review rounds on S0's probe each found another way around.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ReadStats {
    pub(crate) attempted: u64,
    pub(crate) failed: u64,
    /// Of the failures, how many were the source refusing rather than being unable. On a VBS guest
    /// read through the hypercall this is the protected-page count; through a capture it is zero.
    pub(crate) refused: u64,
    pub(crate) bytes: u64,
}

/// A counted, width-normalising view of a [`RawSource`].
///
/// Decodes take `&Reader` and never a source, which is what makes [`ReadStats`] unbypassable: the
/// only way to get bytes is through the call that counts.
pub(crate) struct Reader<'a> {
    source: &'a dyn RawSource,
    stats: std::cell::Cell<ReadStats>,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(source: &'a dyn RawSource) -> Reader<'a> {
        Reader {
            source,
            stats: std::cell::Cell::new(ReadStats::default()),
        }
    }

    /// `len` bytes at `gpa`, whole or not at all.
    ///
    /// Chunked at the source's own width, and a failure in any chunk fails the read: a caller that
    /// asked for a page and got the first sixteen bytes would judge the page on them, which is the
    /// mistake this signature exists to make impossible.
    pub(crate) fn read(&self, gpa: Gpa, len: usize) -> Result<Vec<u8>, ReadFailure> {
        let mut stats = self.stats.get();
        stats.attempted += 1;
        let mut out = vec![0u8; len];
        let width = self.source.max_read().max(1);
        let mut done = 0usize;
        let mut failure = None;
        while done < len {
            let take = width.min(len - done);
            match self
                .source
                .read_chunk(gpa.offset(done as u64), &mut out[done..done + take])
            {
                Ok(()) => done += take,
                Err(e) => {
                    failure = Some(e);
                    break;
                }
            }
        }
        stats.bytes += done as u64;
        let outcome = match failure {
            None => Ok(out),
            Some(e) => {
                stats.failed += 1;
                if e.is_refusal() {
                    stats.refused += 1;
                }
                Err(e)
            }
        };
        self.stats.set(stats);
        outcome
    }

    /// Every read through this reader so far.
    pub(crate) fn stats(&self) -> ReadStats {
        self.stats.get()
    }

    /// What the source says about the processor these bytes belong to.
    pub(crate) fn shape(&self) -> GuestShape {
        self.source.shape()
    }
}

/// One mapping the walk found: a virtual range and the physical range it covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Leaf {
    pub(crate) va: Gva,
    pub(crate) gpa: Gpa,
    /// 4 KiB, 2 MiB or 1 GiB.
    pub(crate) size: u64,
}

/// Which budget a descent ran out of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Budget {
    TableReads(u64),
    Leaves(usize),
}

/// Why a descent is not the whole tree.
///
/// Two ways, kept apart because a reader checking one should not have to know about the other: a
/// budget is this walk's own limit, an unreadable table is a subtree the *source* did not answer
/// for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Incomplete {
    Budget(Budget),
    UnreadableTables(u64),
}

/// How a descent went, in counts.
///
/// No prose: a caller renders these. A figure recounted downstream measures the processing rather
/// than the walk.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct WalkStats {
    pub(crate) table_reads: u64,
    /// Tables whose entries were decoded. Higher than [`WalkStats::table_reads`] on a self-mapped
    /// tree, because one page serves at more than one level — 36 of them on the measured build,
    /// where 215 decodes came from 179 reads.
    pub(crate) tables_decoded: u64,
    /// Prefixes not expanded because the table was already expanded at this level.
    ///
    /// **Reported rather than silent, and deliberately not a failure.** Secure Kernel's tables are
    /// recursively self-mapped, so complete virtual enumeration is combinatorial by construction:
    /// H4 measured a path-based walk exhausting a 200,000-leaf budget over 509 distinct pages and
    /// identifying nothing, where this one costs 166 reads and finds the image. 6,773 prefixes go
    /// unexpanded on a real capture, so a `complete` that counted them would never be true.
    pub(crate) alias_prefixes_skipped: u64,
    /// Entries the processor would fault on rather than follow: reserved bits set on a large leaf,
    /// or the page-size bit in a PML4E. Skipped, and counted.
    pub(crate) malformed_entries: u64,
    pub(crate) unreadable_tables: u64,
    pub(crate) leaves: usize,
    pub(crate) incomplete: Option<Incomplete>,
}

impl WalkStats {
    /// Whether anything went wrong. Pruned aliases do not count — see
    /// [`WalkStats::alias_prefixes_skipped`].
    pub(crate) fn complete(&self) -> bool {
        self.incomplete.is_none()
    }
}

/// What one paging entry points at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntryKind {
    Table,
    Leaf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Decoded {
    kind: EntryKind,
    address: Gpa,
    /// The mapping's size, for a leaf.
    size: u64,
    malformed: bool,
}

/// One paging entry: where it points, whether that is a leaf, and whether it is legal.
///
/// **The address field is not `entry & PFN_MASK` for every entry**, and holding that in one place
/// is the point of this function. In a large-page PDPTE or PDE bit 12 is the **PAT** flag rather
/// than the low bit of the frame, and the frame is aligned to the mapping's own size — so masking
/// at 4 KiB granularity lands one page high on any large mapping with PAT set, and a scan of that
/// leaf then starts a page inside the mapping and runs a page past its end.
///
/// `malformed` means the processor would fault rather than follow: reserved bits between 13 and the
/// mapping's alignment on a large leaf, or the page-size bit set in a PML4E, where it has no
/// meaning.
fn decode_entry(entry: u64, level: u32) -> Option<Decoded> {
    if entry & ENTRY_PRESENT == 0 {
        return None;
    }
    let frame = Gpa(entry & PFN_MASK);
    if level == 0 {
        return Some(Decoded {
            kind: EntryKind::Table,
            address: frame,
            size: 0,
            malformed: entry & ENTRY_LARGE != 0,
        });
    }
    if level == 3 {
        return Some(Decoded {
            kind: EntryKind::Leaf,
            address: frame,
            size: PAGE,
            malformed: false,
        });
    }
    if entry & ENTRY_LARGE != 0 {
        let size = 1u64 << (39 - 9 * level);
        // Bit 12 is PAT and is legal; 13 up to the mapping's alignment are not.
        let reserved = frame.0 & (size - 1) & !0x1FFF;
        return Some(Decoded {
            kind: EntryKind::Leaf,
            address: Gpa(frame.0 & !(size - 1)),
            size,
            malformed: reserved != 0,
        });
    }
    Some(Decoded {
        kind: EntryKind::Table,
        address: frame,
        size: 0,
        malformed: false,
    })
}

/// A guarded four-level descent from `root`.
///
/// **Each table is expanded once per level, and the prefixes that would have re-expanded it are
/// counted rather than passed over in silence.** Three guards: an entry pointing at the table it
/// came from is skipped, each level keeps a visited set, and reads and leaves are budgeted so that
/// exhausting one sets [`WalkStats::incomplete`] rather than quietly returning a short answer.
///
/// Why a visited set rather than path-based cycle cutting, which drops fewer prefixes: it was
/// built and measured during S0 and does not work here. Secure Kernel's VTL1 tables are
/// recursively self-mapped, so one page is a PML4, a PDPT, a PD *and* a PT depending on the route
/// taken to it. Walking every prefix is ~512 paths per level, and the path-based walk exhausted a
/// 200,000-leaf budget over 509 distinct pages while identifying nothing. What this owes instead is
/// to say how much it left out, which [`WalkStats::alias_prefixes_skipped`] does.
pub(crate) fn walk(reader: &Reader<'_>, root: Gpa) -> (Vec<Leaf>, WalkStats) {
    walk_within(reader, root, Budgets::default())
}

/// What a descent will spend before it reports a partial answer.
///
/// Injectable for one reason: the rule worth pinning is that exhausting a budget *reports* rather
/// than quietly returning a short tree, and a fixture large enough to exhaust
/// [`MAX_TABLE_READS`] would be 80 MB of synthetic page tables. A shrunk budget runs the same code
/// path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Budgets {
    pub(crate) table_reads: u64,
    pub(crate) leaves: usize,
}

impl Default for Budgets {
    fn default() -> Budgets {
        Budgets {
            table_reads: MAX_TABLE_READS,
            leaves: MAX_LEAVES,
        }
    }
}

pub(crate) fn walk_within(
    reader: &Reader<'_>,
    root: Gpa,
    budgets: Budgets,
) -> (Vec<Leaf>, WalkStats) {
    let mut state = Descent {
        reader,
        budgets,
        leaves: Vec::new(),
        stats: WalkStats::default(),
        visited: [
            HashSet::new(),
            HashSet::new(),
            HashSet::new(),
            HashSet::new(),
        ],
        cache: BTreeMap::new(),
    };
    state.descend(root.page(), 0, Gva(0));
    let mut stats = state.stats;
    stats.leaves = state.leaves.len();
    if stats.incomplete.is_none() && stats.unreadable_tables > 0 {
        stats.incomplete = Some(Incomplete::UnreadableTables(stats.unreadable_tables));
    }
    (state.leaves, stats)
}

struct Descent<'a, 'b> {
    reader: &'a Reader<'b>,
    budgets: Budgets,
    leaves: Vec<Leaf>,
    stats: WalkStats,
    visited: [HashSet<Gpa>; 4],
    cache: BTreeMap<Gpa, Option<Vec<u64>>>,
}

impl Descent<'_, '_> {
    /// One table's 512 entries, read once however many levels reach it.
    fn table(&mut self, gpa: Gpa) -> Option<Vec<u64>> {
        if let Some(cached) = self.cache.get(&gpa) {
            return cached.clone();
        }
        if self.stats.table_reads >= self.budgets.table_reads {
            self.stats.incomplete = Some(Incomplete::Budget(Budget::TableReads(
                self.budgets.table_reads,
            )));
            return None;
        }
        let read = self.reader.read(gpa, PAGE as usize);
        self.stats.table_reads += 1;
        let entries = match read {
            Ok(page) => Some(
                page.as_chunks::<8>()
                    .0
                    .iter()
                    .map(|w| u64::from_le_bytes(*w))
                    .collect::<Vec<u64>>(),
            ),
            Err(_) => {
                // A table that could not be read is a subtree missing from this answer. Counted,
                // because "found no image" and "could not read part of the tree" are different
                // results and the leaf list does not distinguish them.
                self.stats.unreadable_tables += 1;
                None
            }
        };
        self.cache.insert(gpa, entries.clone());
        entries
    }

    fn descend(&mut self, table: Gpa, level: u32, va: Gva) {
        if self.stats.incomplete.is_some() {
            return;
        }
        if !self.visited[level as usize].insert(table) {
            self.stats.alias_prefixes_skipped += 1;
            return;
        }
        let Some(entries) = self.table(table) else {
            return;
        };
        self.stats.tables_decoded += 1;
        let shift = 39 - 9 * level;
        for (index, entry) in entries.iter().enumerate() {
            let Some(decoded) = decode_entry(*entry, level) else {
                continue;
            };
            if decoded.malformed {
                self.stats.malformed_entries += 1;
                continue;
            }
            let child = Gva(va.0 | ((index as u64) << shift));
            match decoded.kind {
                EntryKind::Leaf => {
                    if self.leaves.len() >= self.budgets.leaves {
                        self.stats.incomplete =
                            Some(Incomplete::Budget(Budget::Leaves(self.budgets.leaves)));
                        return;
                    }
                    self.leaves.push(Leaf {
                        va: child.canonical(),
                        gpa: decoded.address,
                        size: decoded.size,
                    });
                }
                EntryKind::Table => {
                    if decoded.address == table.page() {
                        // The self-map, and any other cycle of one. The per-level visited set would
                        // otherwise let it through once at each level beneath this one. A *leaf*
                        // landing on this page is ordinary data and is kept, above.
                        continue;
                    }
                    self.descend(decoded.address, level + 1, child);
                    if self.stats.incomplete.is_some() {
                        return;
                    }
                }
            }
        }
    }
}

/// What the root page itself says, judged on all 4096 bytes.
///
/// Secure Kernel maps nothing in the low canonical half, so its PML4's first entries are
/// legitimately zero — which is how a 16-byte window read the whole page as empty for most of a
/// session. Reported as counts so a run can be compared with another run of another build.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RootPage {
    pub(crate) present_entries: usize,
    pub(crate) nonzero_bytes: usize,
    /// Indexes whose entry points back at this very page. The measured builds self-map at 388 and
    /// at 309, which is the guard in [`walk`] having something to guard against.
    pub(crate) self_map_indexes: Vec<usize>,
    pub(crate) first_present_index: Option<usize>,
    pub(crate) upper_half_present: usize,
}

/// Read the root page and describe it, or say the read failed.
pub(crate) fn describe_root(reader: &Reader<'_>, root: Gpa) -> Result<RootPage, ReadFailure> {
    let page = reader.read(root, PAGE as usize)?;
    let entries: Vec<u64> = page
        .as_chunks::<8>()
        .0
        .iter()
        .map(|w| u64::from_le_bytes(*w))
        .collect();
    let present: Vec<usize> = entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| **entry & ENTRY_PRESENT != 0)
        .map(|(index, _)| index)
        .collect();
    Ok(RootPage {
        present_entries: present.len(),
        nonzero_bytes: page.iter().filter(|byte| **byte != 0).count(),
        self_map_indexes: present
            .iter()
            .copied()
            .filter(|index| entries[*index] & PFN_MASK == root.page().0)
            .collect(),
        first_present_index: present.first().copied(),
        upper_half_present: present.iter().filter(|index| **index >= 256).count(),
    })
}

/// The virtual address space a descent found, as a lookup.
pub(crate) struct AddressSpace {
    /// Leaf spans sorted by virtual start. A virtual address mapped by more than one leaf keeps
    /// the first the walk found; the count of the rest is in
    /// [`WalkStats::alias_prefixes_skipped`]'s neighbourhood rather than here.
    spans: Vec<Leaf>,
}

impl AddressSpace {
    pub(crate) fn new(mut leaves: Vec<Leaf>) -> AddressSpace {
        leaves.sort_by_key(|leaf| (leaf.va, leaf.size));
        leaves.dedup_by_key(|leaf| leaf.va);
        AddressSpace { spans: leaves }
    }

    /// The physical address `va` maps to, if this space maps it.
    pub(crate) fn translate(&self, va: Gva) -> Option<Gpa> {
        let at = self.spans.partition_point(|leaf| leaf.va <= va);
        let leaf = self.spans.get(at.checked_sub(1)?)?;
        let offset = va.0.checked_sub(leaf.va.0)?;
        (offset < leaf.size).then(|| leaf.gpa.offset(offset))
    }

    /// How many distinct 4 KiB frames the leaves cover.
    ///
    /// Merged spans rather than a set of frames: a set counts a 2 MiB leaf as one page while a
    /// frame count calls it 512, so the two figures would be in different units the first time a
    /// large mapping appeared — and materialising the frames of a single 1 GiB leaf is 262,144
    /// entries, which is the explosion the walk's budgets exist to prevent.
    pub(crate) fn distinct_pages(&self) -> u64 {
        let mut spans: Vec<(u64, u64)> = self
            .spans
            .iter()
            .map(|leaf| (leaf.gpa.0, leaf.gpa.0 + leaf.size))
            .collect();
        spans.sort_unstable();
        let mut total = 0u64;
        let mut current: Option<(u64, u64)> = None;
        for (start, end) in spans {
            match current {
                Some((cur_start, cur_end)) if start <= cur_end => {
                    current = Some((cur_start, cur_end.max(end)));
                }
                Some((cur_start, cur_end)) => {
                    total += cur_end - cur_start;
                    current = Some((start, end));
                }
                None => current = Some((start, end)),
            }
        }
        if let Some((start, end)) = current {
            total += end - start;
        }
        total / PAGE
    }
}

/// Why a virtual read did not answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VaFailure {
    /// The walk found no mapping for this page. Distinct from a read that failed: an address
    /// nothing maps and an address whose bytes were refused are different facts.
    Unmapped(Gva),
    Read {
        va: Gva,
        gpa: Gpa,
        failure: ReadFailure,
    },
}

/// Virtual reads over one address space.
pub(crate) struct Space<'a, 'b> {
    reader: &'a Reader<'b>,
    space: &'a AddressSpace,
}

impl<'a, 'b> Space<'a, 'b> {
    pub(crate) fn new(reader: &'a Reader<'b>, space: &'a AddressSpace) -> Space<'a, 'b> {
        Space { reader, space }
    }

    /// One whole page, by the virtual address of its start.
    pub(crate) fn page(&self, va: Gva) -> Result<Vec<u8>, VaFailure> {
        let page = va.page();
        let gpa = self
            .space
            .translate(page)
            .ok_or(VaFailure::Unmapped(page))?;
        self.reader
            .read(gpa, PAGE as usize)
            .map_err(|failure| VaFailure::Read {
                va: page,
                gpa,
                failure,
            })
    }

    /// `len` bytes from `va`, stitched across page boundaries.
    ///
    /// Whole or not at all, and the failure names the page that stopped it — a structure straddling
    /// a boundary is the ordinary case here, not the exception: the debugger data block sits
    /// wherever it sits.
    pub(crate) fn read_span(&self, va: Gva, len: usize) -> Result<Vec<u8>, VaFailure> {
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            let at = va.offset(out.len() as u64);
            let page = self.page(at)?;
            let from = at.offset_in_page() as usize;
            let take = (len - out.len()).min(PAGE as usize - from);
            out.extend_from_slice(&page[from..from + take]);
        }
        Ok(out)
    }
}

/// A PE64 image's identity: what says these bytes *are* that image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PeIdentity {
    pub(crate) machine: u16,
    pub(crate) sections: u16,
    pub(crate) timestamp: u32,
    pub(crate) size_of_image: u32,
    pub(crate) section_names: Vec<String>,
}

/// Sections, timestamp and `SizeOfImage` out of a PE64 header, or `None` if it is not one.
pub(crate) fn pe_identity(bytes: &[u8]) -> Option<PeIdentity> {
    if bytes.len() < 0x40 || &bytes[..2] != b"MZ" {
        return None;
    }
    let e_lfanew = u32::from_le_bytes(bytes[0x3C..0x40].try_into().ok()?) as usize;
    if e_lfanew.checked_add(0x108)? > bytes.len() {
        return None;
    }
    if &bytes[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return None;
    }
    let at = |offset: usize, len: usize| &bytes[e_lfanew + offset..e_lfanew + offset + len];
    let machine = u16::from_le_bytes(at(4, 2).try_into().ok()?);
    let sections = u16::from_le_bytes(at(6, 2).try_into().ok()?);
    let timestamp = u32::from_le_bytes(at(8, 4).try_into().ok()?);
    let optional_size = u16::from_le_bytes(at(20, 2).try_into().ok()?) as usize;
    // PE32+ only. A PE32 image in a 64-bit guest's VTL1 would have a different optional header
    // layout, so reading `SizeOfImage` at this offset would be reading some other field.
    if u16::from_le_bytes(at(24, 2).try_into().ok()?) != 0x20B {
        return None;
    }
    let size_of_image = u32::from_le_bytes(at(24 + 56, 4).try_into().ok()?);
    let table = e_lfanew + 24 + optional_size;
    let mut section_names = Vec::new();
    for index in 0..sections as usize {
        let start = table + index * 40;
        if start + 8 > bytes.len() {
            break;
        }
        let raw = &bytes[start..start + 8];
        let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
        section_names.push(raw[..end].iter().map(|b| *b as char).collect());
    }
    Some(PeIdentity {
        machine,
        sections,
        timestamp,
        size_of_image,
        section_names,
    })
}

/// The image on disk that a mapping is being identified against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DiskImage {
    pub(crate) path: String,
    pub(crate) file_size: u64,
    pub(crate) identity: PeIdentity,
}

impl DiskImage {
    pub(crate) fn open(path: &std::path::Path) -> Result<DiskImage, String> {
        let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let identity =
            pe_identity(&bytes).ok_or_else(|| format!("{} is not a PE64 image", path.display()))?;
        Ok(DiskImage {
            path: path.display().to_string(),
            file_size: bytes.len() as u64,
            identity,
        })
    }

    /// Whether a mapping's identity is this image's.
    ///
    /// Four fields agreeing say the bytes are the image. They do **not** say the address is the
    /// base it was loaded at — a second mapping of one image matches all four, and the 2026-09-25
    /// capture has exactly that, a duplicate `symcryptk.dll` the module list does not name. What
    /// settles the base is [`identify`].
    pub(crate) fn matches(&self, found: &PeIdentity) -> bool {
        self.identity.sections == found.sections
            && self.identity.timestamp == found.timestamp
            && self.identity.size_of_image == found.size_of_image
            && self.identity.section_names == found.section_names
    }
}

/// An image's mapped range, read into one buffer.
pub(crate) struct GatheredImage {
    pub(crate) base: Gva,
    pub(crate) bytes: Vec<u8>,
    /// Page offsets that could not be read, and why. Their bytes in [`GatheredImage::bytes`] are
    /// the poison below.
    pub(crate) missing: Vec<(u64, VaFailure)>,
}

/// What a page that could not be read is filled with.
///
/// **0xAA rather than zero.** A zero fill makes "this page was not in the capture" read as "this
/// page is zeros", which is the one distinction this whole gate turns on — H4 lost a session to it
/// once already, judging a poisoned buffer it had zeroed.
const POISON: u8 = 0xAA;

/// Read an image's mapped range into one contiguous buffer, poisoning what could not be read.
///
/// Contiguity is the other reason this exists: a structure straddling a page boundary is found
/// rather than skipped, which is what a per-page search of a debugger data block gets wrong.
pub(crate) fn gather_image(space: &Space<'_, '_>, base: Gva, size_of_image: u32) -> GatheredImage {
    let size = size_of_image as usize;
    let mut bytes = vec![POISON; size];
    let mut missing = Vec::new();
    let mut offset = 0u64;
    while (offset as usize) < size {
        let at = offset as usize;
        match space.page(base.offset(offset)) {
            Ok(page) => {
                let end = (at + PAGE as usize).min(size);
                bytes[at..end].copy_from_slice(&page[..end - at]);
            }
            Err(failure) => missing.push((offset, failure)),
        }
        offset += PAGE;
    }
    GatheredImage {
        base,
        bytes,
        missing,
    }
}

/// A mapping that carries a PE header, before anything has vouched for its base.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Candidate {
    pub(crate) va: Gva,
    pub(crate) gpa: Gpa,
    pub(crate) identity: PeIdentity,
    pub(crate) matches_disk: bool,
}

/// How a scan for PE headers went.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ScanStats {
    pub(crate) scanned: u64,
    /// Pages a read did not answer for. **A leaf that could not be read is not a leaf without an
    /// image**: dropping this lets a refused read arrive as "no PE header", and the scan then
    /// reports zero matching images with nothing capped — an incomplete scan wearing the shape of a
    /// negative result.
    pub(crate) unreadable: u64,
    pub(crate) capped: bool,
}

/// One page read per page-aligned base in the leaves, looking for a PE header at offset 0.
///
/// The window is the whole page rather than a sample: an image base is page-aligned and the header
/// sits at offset 0, so this reads the thing itself. A large-page leaf covers many page-aligned
/// bases and is **expanded** rather than sampled at its first page — an image inside one would
/// otherwise be invisible.
pub(crate) fn scan_for_images(
    reader: &Reader<'_>,
    leaves: &[Leaf],
    disk: &DiskImage,
) -> (Vec<Candidate>, ScanStats) {
    let mut found = Vec::new();
    let mut stats = ScanStats::default();
    for leaf in leaves {
        let mut offset = 0u64;
        while offset < leaf.size {
            if stats.scanned >= MAX_LEAVES as u64 {
                stats.capped = true;
                return (found, stats);
            }
            let gpa = leaf.gpa.offset(offset);
            stats.scanned += 1;
            let page = match reader.read(gpa, PAGE as usize) {
                Ok(page) => page,
                Err(_) => {
                    stats.unreadable += 1;
                    offset += PAGE;
                    continue;
                }
            };
            if page.starts_with(b"MZ")
                && let Some(identity) = pe_identity(&page)
            {
                found.push(Candidate {
                    va: leaf.va.offset(offset),
                    gpa,
                    matches_disk: disk.matches(&identity),
                    identity,
                });
            }
            offset += PAGE;
        }
    }
    (found, stats)
}

/// The `KDBG` tag's offset inside `_KDDEBUGGER_DATA64`, past the leading `LIST_ENTRY`.
const KDBG_OWNER_TAG: u64 = 0x10;

/// `KernBase`, `0x18` into the block — `0x8` past the tag.
const KDBG_KERN_BASE: u64 = 0x18;

/// `PsLoadedModuleList`, which is what `SkLoadedModuleList` is read out of.
const KDBG_PS_LOADED_MODULE_LIST: u64 = 0x48;

/// A `KDBG` owner tag found in an image, with what sits beside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KdbgHit {
    /// The block's own start — the tag's address less [`KDBG_OWNER_TAG`].
    pub(crate) va: Gva,
    pub(crate) image_offset: u64,
    /// **Reported, never matched.** A needle built from a remembered `0x3A8` is what made an earlier
    /// scan report zero occurrences with the block three pages away — and the measured live value
    /// is `0x3A0`, which disagrees with the same build's on-disk reading.
    pub(crate) size: u32,
    pub(crate) kern_base: u64,
    pub(crate) kern_base_matches: bool,
    pub(crate) ps_loaded_module_list: u64,
}

/// Every `KDBG` owner tag in an image buffer, in order.
///
/// The tag alone is the needle. Nothing about the block's size, its fields or its neighbours is
/// required to *find* it — those are read out afterwards and reported, so a build whose block moved
/// or grew is still found.
pub(crate) fn find_kdbg(image: &GatheredImage) -> Vec<KdbgHit> {
    let bytes = &image.bytes;
    let mut hits = Vec::new();
    let mut at = 0usize;
    while let Some(found) = bytes[at..].windows(4).position(|w| w == b"KDBG") {
        let tag = at + found;
        at = tag + 1;
        let Some(header) = (tag as u64).checked_sub(KDBG_OWNER_TAG) else {
            continue;
        };
        let end = header as usize + KDBG_PS_LOADED_MODULE_LIST as usize + 8;
        if end > bytes.len() {
            continue;
        }
        let word = |offset: u64| {
            let start = (header + offset) as usize;
            u64::from_le_bytes(
                bytes[start..start + 8]
                    .try_into()
                    .expect("bounds checked above"),
            )
        };
        let size = u32::from_le_bytes(
            bytes[tag + 4..tag + 8]
                .try_into()
                .expect("bounds checked above"),
        );
        let kern_base = word(KDBG_KERN_BASE);
        hits.push(KdbgHit {
            va: image.base.offset(header),
            image_offset: header,
            size,
            kern_base,
            kern_base_matches: kern_base == image.base.0,
            ps_loaded_module_list: word(KDBG_PS_LOADED_MODULE_LIST),
        });
    }
    hits
}

/// `KLDR_DATA_TABLE_ENTRY` fields this walk reads, by offset.
mod kldr {
    /// `InLoadOrderLinks.Flink` is the record's first field, so an entry address is its own
    /// forward link.
    pub(super) const FLINK: u64 = 0x00;
    pub(super) const BLINK: u64 = 0x08;
    pub(super) const DLL_BASE: u64 = 0x30;
    pub(super) const SIZE_OF_IMAGE: u64 = 0x40;
    /// `BaseDllName`, a `UNICODE_STRING`: `Length` here, `Buffer` at `+0x08`.
    pub(super) const BASE_DLL_NAME: u64 = 0x58;
    pub(super) const BASE_DLL_NAME_BUFFER: u64 = 0x60;
    /// How much of a record this walk reads.
    pub(super) const RECORD: usize = 0x70;
}

/// Why an entry's name is not a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NameFailure {
    /// A `Length` no module name has. Like every other field here it is read out of guest memory,
    /// so it is named rather than trusted.
    ImplausibleLength(u16),
    NullBuffer {
        length: u16,
    },
    Unreadable {
        buffer: Gva,
        failure: VaFailure,
    },
}

/// One loader entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ModuleEntry {
    pub(crate) va: Gva,
    /// `None` when the record itself could not be read — which is not the same as an entry whose
    /// *name* could not be read, below.
    pub(crate) record: Option<ModuleRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ModuleRecord {
    pub(crate) dll_base: u64,
    pub(crate) size_of_image: u32,
    /// `Ok("")` is an entry with no name, which the loader list legitimately has. An unreadable
    /// name is `Err`: returning `""` for both made "this entry has no name" and "I could not read
    /// its name" the same record, and an enumeration could then be reported complete while quietly
    /// omitting names.
    pub(crate) name: Result<String, NameFailure>,
}

/// Why an enumeration is not the whole list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ListIncomplete {
    EntryUnreadable(Gva),
    Limit(usize),
    NullForwardLink,
    /// The walk left the list somewhere that is neither the head nor null.
    LeftTheList(Gva),
}

/// Why a list does not vouch for the block that pointed at it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ListInvalid {
    HeadUnreadable {
        head: Gva,
        failure: VaFailure,
    },
    Empty,
    FirstEntryUnreadable(Gva),
    /// The first entry named somebody else. The block was read at the wrong alignment, or through a
    /// stale pointer, or through a coincidental tag — and in every one of those cases the list
    /// still yields plausible names and sizes, which is why this has to be checked rather than
    /// looked at.
    FirstBaseIsNot {
        found: u64,
        expected: u64,
    },
}

/// A walk of the loader list a debugger data block points at.
pub(crate) struct ModuleList {
    pub(crate) head: Gva,
    pub(crate) entries: Vec<ModuleEntry>,
    pub(crate) names_unreadable: u64,
    /// Whether the enumeration closed back on its head.
    pub(crate) incomplete: Option<ListIncomplete>,
    /// Whether the list vouches for the block.
    pub(crate) valid: Result<(), ListInvalid>,
}

impl ModuleList {
    pub(crate) fn complete(&self) -> bool {
        self.incomplete.is_none()
    }

    /// The names this walk read, in list order, skipping entries whose name it could not read.
    pub(crate) fn names(&self) -> Vec<&str> {
        self.entries
            .iter()
            .filter_map(|entry| entry.record.as_ref()?.name.as_deref().ok())
            .collect()
    }
}

/// `BaseDllName` out of a loader record: the name, or why there is none.
fn read_module_name(space: &Space<'_, '_>, record: &[u8]) -> Result<String, NameFailure> {
    let at = |offset: u64| offset as usize;
    let length = u16::from_le_bytes(
        record[at(kldr::BASE_DLL_NAME)..at(kldr::BASE_DLL_NAME) + 2]
            .try_into()
            .expect("record is read at KLDR::RECORD bytes"),
    );
    let buffer = Gva(u64::from_le_bytes(
        record[at(kldr::BASE_DLL_NAME_BUFFER)..at(kldr::BASE_DLL_NAME_BUFFER) + 8]
            .try_into()
            .expect("record is read at KLDR::RECORD bytes"),
    ));
    if length == 0 {
        return Ok(String::new());
    }
    if length > 512 {
        return Err(NameFailure::ImplausibleLength(length));
    }
    if buffer.0 == 0 {
        return Err(NameFailure::NullBuffer { length });
    }
    let raw = space
        .read_span(buffer, length as usize)
        .map_err(|failure| NameFailure::Unreadable { buffer, failure })?;
    Ok(String::from_utf16_lossy(
        &raw.as_chunks::<2>()
            .0
            .iter()
            .map(|w| u16::from_le_bytes(*w))
            .collect::<Vec<u16>>(),
    ))
}

/// Walk the `LIST_ENTRY` a debugger data block points at, as `KLDR_DATA_TABLE_ENTRY` records.
///
/// **Validation rather than discovery.** The first entry's `DllBase` has to equal the base the PE
/// walk established independently, or the list was read at the wrong alignment, through a stale
/// pointer, or through a coincidental `KDBG` hit — and all three still yield plausible names. The
/// result carries [`ModuleList::valid`], and a caller that gets `Err` moves to the next hit or the
/// next candidate rather than publishing the entries. That sentence is enforced by
/// [`identify`], which is the only caller that can accept a block.
///
/// **`valid` and `complete` are deliberately two answers.** `valid` is about the *block*: does this
/// list begin with an entry naming the image whose base the block already claims? Two independent
/// structures agreeing on one address is what makes the identification implausible as a
/// coincidence. `complete` is about the *enumeration*: did it close back on its head? Rejecting a
/// list that does not close would refuse a genuine block on any build with more than `limit` VTL1
/// modules, so a truncated enumeration confirms the block and says it is partial.
pub(crate) fn walk_module_list(
    space: &Space<'_, '_>,
    head: Gva,
    expected_base: u64,
    limit: usize,
) -> ModuleList {
    let first_link = match space.read_span(head, 0x10) {
        Ok(bytes) => Gva(u64::from_le_bytes(
            bytes[..8]
                .try_into()
                .expect("read_span answered 0x10 bytes"),
        )),
        Err(failure) => {
            return ModuleList {
                head,
                entries: Vec::new(),
                names_unreadable: 0,
                // Not `NullForwardLink`: nothing was enumerated at all, and a reason naming a
                // *link* would describe a walk that happened. The head is where it stopped.
                incomplete: Some(ListIncomplete::EntryUnreadable(head)),
                valid: Err(ListInvalid::HeadUnreadable { head, failure }),
            };
        }
    };
    let mut entries: Vec<ModuleEntry> = Vec::new();
    let mut names_unreadable = 0u64;
    let mut current = first_link;
    while current.0 != 0 && current != head && entries.len() < limit {
        let record = match space.read_span(current, kldr::RECORD) {
            Ok(record) => record,
            Err(_) => {
                entries.push(ModuleEntry {
                    va: current,
                    record: None,
                });
                break;
            }
        };
        let word = |offset: u64| {
            u64::from_le_bytes(
                record[offset as usize..offset as usize + 8]
                    .try_into()
                    .expect("record is KLDR::RECORD bytes"),
            )
        };
        let name = read_module_name(space, &record);
        if name.is_err() {
            names_unreadable += 1;
        }
        entries.push(ModuleEntry {
            va: current,
            record: Some(ModuleRecord {
                dll_base: word(kldr::DLL_BASE),
                size_of_image: u32::from_le_bytes(
                    record[kldr::SIZE_OF_IMAGE as usize..kldr::SIZE_OF_IMAGE as usize + 4]
                        .try_into()
                        .expect("record is KLDR::RECORD bytes"),
                ),
                name,
            }),
        });
        current = Gva(word(kldr::FLINK));
    }
    let closed = current == head;
    let incomplete = if closed {
        None
    } else if entries.last().is_some_and(|entry| entry.record.is_none()) {
        Some(ListIncomplete::EntryUnreadable(
            entries.last().expect("checked just above").va,
        ))
    } else if entries.len() >= limit {
        Some(ListIncomplete::Limit(limit))
    } else if current.0 == 0 {
        Some(ListIncomplete::NullForwardLink)
    } else {
        Some(ListIncomplete::LeftTheList(current))
    };
    let valid = match entries.first() {
        None => Err(ListInvalid::Empty),
        Some(ModuleEntry { va, record: None }) => Err(ListInvalid::FirstEntryUnreadable(*va)),
        Some(ModuleEntry {
            record: Some(record),
            ..
        }) => {
            if record.dll_base == expected_base {
                Ok(())
            } else {
                Err(ListInvalid::FirstBaseIsNot {
                    found: record.dll_base,
                    expected: expected_base,
                })
            }
        }
    };
    ModuleList {
        head,
        entries,
        names_unreadable,
        incomplete,
        valid,
    }
}

/// How many entries a module-list walk reads before it calls itself limited.
///
/// The measured build has six VTL1 modules, so this is room rather than a bound anyone has hit.
pub(crate) const MODULE_LIST_LIMIT: usize = 32;

/// Why one `KDBG` hit was not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HitRejected {
    /// The tag's neighbouring `KernBase` names a different image, so this is a coincidental tag or
    /// a misaligned read. Until this passes, the field at `+0x48` is whatever bytes happen to sit
    /// there.
    KernBaseIsNot { found: u64, expected: u64 },
    /// `KernBase` vouched for the block and the list it points at did not vouch back. **Necessary,
    /// not sufficient** is the whole reason this variant exists: the measured block has 26 of its
    /// 116 words non-zero, so a field meaning nothing is the ordinary case, and a list walked from
    /// a stale pointer yields plausible names rather than an error.
    ListInvalid(ListInvalid),
}

/// One candidate mapping examined.
pub(crate) struct Attempt {
    pub(crate) candidate: Candidate,
    pub(crate) image_pages_unreadable: usize,
    pub(crate) hits: Vec<KdbgHit>,
    /// Why each hit that was refused was refused, in the order they were tried. A run where every
    /// tag was found and every one was refused is the case these reasons exist for — and it is
    /// exactly the case S0's probe used to report as no tags at all.
    pub(crate) rejected: Vec<(Gva, HitRejected)>,
    pub(crate) accepted: bool,
}

/// An image whose base two independent structures agree on.
pub(crate) struct Identified {
    pub(crate) candidate: Candidate,
    pub(crate) image: GatheredImage,
    pub(crate) block: KdbgHit,
    pub(crate) modules: ModuleList,
}

/// Try each candidate until one is vouched for by a data block *and* the list that block points at.
///
/// **Per candidate, not per first match, and acceptance is two things agreeing.** `matches_disk`
/// says the bytes at a virtual address are the image; it does not say the address is the base the
/// image was loaded at, and a second mapping of one image matches every field. Which candidate the
/// walk reaches first is prefix order and means nothing — so stopping at the first reports "no
/// debugger data block" for an image whose block is under the next one.
///
/// The two agreeing are `KernBase` inside the block, and the first `DllBase` of the loader list the
/// block points at. Both are checked here rather than by a caller, because a rule enforced by
/// whoever remembers to call the helper is half a rule.
pub(crate) fn identify(
    space: &Space<'_, '_>,
    candidates: &[Candidate],
) -> (Option<Identified>, Vec<Attempt>) {
    let mut attempts = Vec::new();
    for candidate in candidates {
        let image = gather_image(space, candidate.va, candidate.identity.size_of_image);
        let hits = find_kdbg(&image);
        let mut rejected = Vec::new();
        let mut accepted = None;
        for hit in &hits {
            if !hit.kern_base_matches {
                rejected.push((
                    hit.va,
                    HitRejected::KernBaseIsNot {
                        found: hit.kern_base,
                        expected: candidate.va.0,
                    },
                ));
                continue;
            }
            let modules = walk_module_list(
                space,
                Gva(hit.ps_loaded_module_list),
                candidate.va.0,
                MODULE_LIST_LIMIT,
            );
            match &modules.valid {
                Ok(()) => {
                    accepted = Some((hit.clone(), modules));
                    break;
                }
                Err(invalid) => {
                    rejected.push((hit.va, HitRejected::ListInvalid(invalid.clone())));
                }
            }
        }
        attempts.push(Attempt {
            candidate: candidate.clone(),
            image_pages_unreadable: image.missing.len(),
            hits: hits.clone(),
            rejected,
            accepted: accepted.is_some(),
        });
        if let Some((block, modules)) = accepted {
            return (
                Some(Identified {
                    candidate: candidate.clone(),
                    image,
                    block,
                    modules,
                }),
                attempts,
            );
        }
    }
    (None, attempts)
}

/// The list head found structurally, without reading any debugger data block.
#[derive(Debug)]
pub(crate) struct CrossCheck {
    /// The loader entry whose `DllBase` is the identified base.
    pub(crate) entry: Gva,
    /// The head its `Blink` points at, which is the same address the block named if the two routes
    /// agree.
    pub(crate) head: Gva,
    pub(crate) pages_scanned: u64,
    pub(crate) pages_unreadable: u64,
}

/// How a structural search ended when it found nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CrossCheckMiss {
    pub(crate) pages_scanned: u64,
    pub(crate) pages_unreadable: u64,
    /// Whether the budget stopped it. **"Scanned everything and found nothing" and "ran out of
    /// budget" are different answers**, and a cross-check that reports the second as the first would
    /// contradict the block for no reason.
    pub(crate) capped: bool,
}

/// Pages the structural cross-check will read before giving up.
///
/// It needs a ceiling for the same reason the primary walk does, and the measured run hides that: it
/// found its entry after 1,249 pages, which is luck rather than a bound. A single 1 GiB leaf is
/// 262,144 pages on its own, and a walk can return many — so without this an optional cross-check
/// can outlast everything it is checking.
const MAX_CROSS_CHECK_PAGES: u64 = 200_000;

/// Find the loader list a second way: by its entry for the image, not by the block that names it.
///
/// Search for a word equal to the identified base with the image's `SizeOfImage` sixteen bytes
/// later — the `DllBase`/`SizeOfImage` pair of a `KLDR_DATA_TABLE_ENTRY` — then follow that entry's
/// `Blink` to the head. This is the route that found the head independently during H4, and **the
/// two agreeing is what made either believable**. Kept as the cross-check rather than the primary,
/// because `SkLoadedModuleList` is a bare `LIST_ENTRY` with no signature to search for: only the
/// block has one.
///
/// **Budgeted like every other scan here**, and the answer says which way it ended: `Err` carries
/// whether [`MAX_CROSS_CHECK_PAGES`] stopped it, because a search that ran out and a search that
/// looked everywhere are different statements about the block it is checking.
pub(crate) fn cross_check_module_list(
    space: &Space<'_, '_>,
    leaves: &[Leaf],
    base: u64,
    size_of_image: u32,
) -> Result<CrossCheck, CrossCheckMiss> {
    cross_check_within(space, leaves, base, size_of_image, MAX_CROSS_CHECK_PAGES)
}

/// [`cross_check_module_list`] with the budget as a parameter, for the same reason
/// [`walk_within`] exists: the rule worth pinning is that the budget *reports*, and a fixture big
/// enough to spend 200,000 pages is not a test anyone runs.
pub(crate) fn cross_check_within(
    space: &Space<'_, '_>,
    leaves: &[Leaf],
    base: u64,
    size_of_image: u32,
    budget: u64,
) -> Result<CrossCheck, CrossCheckMiss> {
    let mut pages_scanned = 0u64;
    let mut pages_unreadable = 0u64;
    for leaf in leaves {
        let mut offset = 0u64;
        while offset < leaf.size {
            if pages_scanned + pages_unreadable >= budget {
                return Err(CrossCheckMiss {
                    pages_scanned,
                    pages_unreadable,
                    capped: true,
                });
            }
            let va = leaf.va.offset(offset);
            offset += PAGE;
            let page = match space.page(va) {
                Ok(page) => page,
                Err(_) => {
                    pages_unreadable += 1;
                    continue;
                }
            };
            pages_scanned += 1;
            // The pair has to be whole inside this page: `DllBase` at `at`, `SizeOfImage` 0x10
            // later. A record straddling the boundary is missed, which is why this is a
            // cross-check and not the route anything rests on.
            for at in (0..PAGE as usize - 0x14).step_by(8) {
                let word = u64::from_le_bytes(
                    page[at..at + 8]
                        .try_into()
                        .expect("bounded by the loop above"),
                );
                if word != base {
                    continue;
                }
                let size = u32::from_le_bytes(
                    page[at + 0x10..at + 0x14]
                        .try_into()
                        .expect("bounded by the loop above"),
                );
                if size != size_of_image {
                    continue;
                }
                // The record starts 0x30 before its `DllBase`, which for a pair near the start of
                // a page is in the page before this one. `read_span` follows it there; subtracting
                // inside the page offset would underflow.
                let entry = Gva(va.0.wrapping_add(at as u64).wrapping_sub(kldr::DLL_BASE));
                let Ok(links) = space.read_span(entry.offset(kldr::BLINK), 8) else {
                    continue;
                };
                let head = Gva(u64::from_le_bytes(
                    links[..8].try_into().expect("read_span answered 8 bytes"),
                ));
                return Ok(CrossCheck {
                    entry,
                    head,
                    pages_scanned,
                    pages_unreadable,
                });
            }
        }
    }
    Err(CrossCheckMiss {
        pages_scanned,
        pages_unreadable,
        capped: false,
    })
}

/// Everything this gate decodes about one source, in the order the decodes depend on each other.
pub(crate) struct Landmarks {
    /// The root the source supplied, never a remembered one.
    pub(crate) root: Gpa,
    /// What that page itself holds, or why it could not be read — which is a different failure from
    /// a walk that found nothing.
    pub(crate) root_page: Result<RootPage, ReadFailure>,
    pub(crate) walk: WalkStats,
    /// The address space the walk found, kept so a caller can translate an address the decode did
    /// not happen to read — which is what the provider differential needs.
    pub(crate) space: AddressSpace,
    /// Distinct 4 KiB frames the mappings cover, which is a smaller number than the leaf count on
    /// a self-mapped tree: the measured capture has 11,326 leaves over 4,189 pages.
    pub(crate) mapped_pages: u64,
    pub(crate) scan: ScanStats,
    pub(crate) candidates: Vec<Candidate>,
    pub(crate) attempts: Vec<Attempt>,
    pub(crate) identified: Option<Identified>,
    /// Present only when asked for; the inner `Err` says the structural route found nothing and
    /// whether its budget is why.
    pub(crate) cross_check: Option<Result<CrossCheck, CrossCheckMiss>>,
    /// Every physical read the whole decode made. **A run that identified nothing with a non-zero
    /// [`ReadStats::failed`] is a run whose negative has not been earned** — which is the one thing
    /// a caller must not have to remember to check, so it travels with the result.
    pub(crate) reads: ReadStats,
}

/// Decode one source: gate the shape, walk, scan, identify, and optionally cross-check.
///
/// The order is the dependency order and not a preference: nothing can be read before the shape
/// says the tables are the shape this walk decodes, and nothing can be identified before a walk has
/// produced an address space to read an image out of.
pub(crate) fn locate(
    reader: &Reader<'_>,
    disk: &DiskImage,
    cross_check: bool,
) -> Result<Landmarks, NotWalkable> {
    let root = walkable(&reader.shape())?;
    let root_page = describe_root(reader, root);
    let (leaves, walk_stats) = walk(reader, root);
    let space = AddressSpace::new(leaves.clone());
    let mapped_pages = space.distinct_pages();
    let (candidates, scan) = scan_for_images(reader, &leaves, disk);
    // Only the mappings whose bytes *are* the image are worth gathering whole; the rest are other
    // images, and this gate is about one.
    let matching: Vec<Candidate> = candidates
        .iter()
        .filter(|c| c.matches_disk)
        .cloned()
        .collect();
    // Scoped so the virtual-read view's borrow of `space` ends before `space` is handed to the
    // caller: everything it produces is owned, so nothing outlives it.
    let (identified, attempts, cross_check) = {
        let reads = Space::new(reader, &space);
        let (identified, attempts) = identify(&reads, &matching);
        let cross = match (&identified, cross_check) {
            (Some(found), true) => Some(cross_check_module_list(
                &reads,
                &leaves,
                found.candidate.va.0,
                found.candidate.identity.size_of_image,
            )),
            _ => None,
        };
        (identified, attempts, cross)
    };
    Ok(Landmarks {
        root,
        root_page,
        walk: walk_stats,
        space,
        mapped_pages,
        scan,
        candidates,
        attempts,
        identified,
        cross_check,
        reads: reader.stats(),
    })
}

#[cfg(test)]
mod tests {
    //! Synthetic guests, built to hit each rule deliberately.
    //!
    //! **Nothing here is recorded off a real Secure Kernel.** Those pages are memory-dump material
    //! carrying whatever guest and host state happened to be in them, and `AGENTS.md` keeps dumps
    //! out of version control. A built fixture is better on the merits anyway: it can be made to
    //! straddle a page boundary, self-map, or carry a duplicate image on purpose, where a captured
    //! page does those things only by luck.
    //!
    //! The one thing a synthetic fixture cannot pin is whether these offsets are *Windows'*
    //! offsets — a fixture and a decoder sharing a constant are blind to it together. So the
    //! layouts below are written as literals with the structure named beside them, and the
    //! authority for them is the live differential in `docs/secure-kernel/`, not this file.

    use std::collections::{BTreeMap, HashMap, HashSet};

    use super::*;

    /// A physical address space built by hand, with per-page refusals.
    struct Fixture {
        pages: BTreeMap<u64, Vec<u8>>,
        /// Pages the source refuses, which is a different answer from a page it does not have.
        refused: HashSet<u64>,
        shape: GuestShape,
        width: usize,
        root: u64,
        next_free: u64,
        mapped: HashMap<u64, u64>,
    }

    impl Fixture {
        /// A long-mode guest with an empty PML4 at a physical address that is not zero — so that a
        /// root of zero stays distinguishable from a root that was read.
        fn new() -> Fixture {
            let mut fixture = Fixture {
                pages: BTreeMap::new(),
                refused: HashSet::new(),
                shape: GuestShape::default(),
                width: PAGE as usize,
                root: 0x1000,
                next_free: 0x2000,
                mapped: HashMap::new(),
            };
            fixture.pages.insert(0x1000, vec![0u8; PAGE as usize]);
            fixture.shape = GuestShape {
                vtl_enabled: Some(true),
                paging_mode: Some(PagingMode::Long),
                cr0: Some((1 << 31) | 1),
                cr3: Some(fixture.root),
                cr4: Some(1 << 5),
                efer: Some(1 << 10),
                ..GuestShape::default()
            };
            fixture
        }

        fn alloc(&mut self) -> u64 {
            let at = self.next_free;
            self.next_free += PAGE;
            self.pages.insert(at, vec![0u8; PAGE as usize]);
            at
        }

        fn entry(&self, table: u64, index: usize) -> u64 {
            let page = self.pages.get(&table).expect("table exists");
            u64::from_le_bytes(page[index * 8..index * 8 + 8].try_into().expect("8 bytes"))
        }

        fn set_entry(&mut self, table: u64, index: usize, value: u64) {
            let page = self.pages.get_mut(&table).expect("table exists");
            page[index * 8..index * 8 + 8].copy_from_slice(&value.to_le_bytes());
        }

        /// Map one 4 KiB page, allocating whatever tables the descent needs.
        fn map_page(&mut self, va: u64, gpa: u64) {
            let mut table = self.root;
            for level in 0..3u32 {
                let index = ((va >> (39 - 9 * level)) & 0x1FF) as usize;
                let existing = self.entry(table, index);
                table = if existing & ENTRY_PRESENT != 0 {
                    existing & PFN_MASK
                } else {
                    let next = self.alloc();
                    self.set_entry(table, index, next | ENTRY_PRESENT);
                    next
                };
            }
            let index = ((va >> 12) & 0x1FF) as usize;
            self.set_entry(table, index, (gpa & PFN_MASK) | ENTRY_PRESENT);
            self.mapped.insert(va & !(PAGE - 1), gpa & !(PAGE - 1));
        }

        fn map_range(&mut self, va: u64, gpa: u64, len: u64) {
            let mut offset = 0;
            while offset < len {
                self.pages
                    .entry(gpa + offset)
                    .or_insert_with(|| vec![0u8; PAGE as usize]);
                self.map_page(va + offset, gpa + offset);
                offset += PAGE;
            }
        }

        fn write(&mut self, gpa: u64, bytes: &[u8]) {
            let page = self
                .pages
                .entry(gpa & !(PAGE - 1))
                .or_insert_with(|| vec![0u8; PAGE as usize]);
            let at = (gpa & (PAGE - 1)) as usize;
            page[at..at + bytes.len()].copy_from_slice(bytes);
        }

        /// Write through the fixture's own mapping, so a test can place a structure at a virtual
        /// address without doing the translation by hand.
        fn write_va(&mut self, va: u64, bytes: &[u8]) {
            let mut done = 0usize;
            while done < bytes.len() {
                let at = va + done as u64;
                let gpa = *self.mapped.get(&(at & !(PAGE - 1))).expect("va is mapped");
                let offset = at & (PAGE - 1);
                let take = (bytes.len() - done).min((PAGE - offset) as usize);
                self.write(gpa + offset, &bytes[done..done + take]);
                done += take;
            }
        }

        /// A PE64 image at `va`, backed at `gpa`, with the header fields identification reads.
        fn image(&mut self, va: u64, gpa: u64, size: u32, timestamp: u32, sections: &[&str]) {
            self.map_range(va, gpa, size as u64);
            let mut header = vec![0u8; PAGE as usize];
            header[..2].copy_from_slice(b"MZ");
            let lfanew = 0x80usize;
            header[0x3C..0x40].copy_from_slice(&(lfanew as u32).to_le_bytes());
            header[lfanew..lfanew + 4].copy_from_slice(b"PE\0\0");
            header[lfanew + 4..lfanew + 6].copy_from_slice(&0x8664u16.to_le_bytes());
            header[lfanew + 6..lfanew + 8].copy_from_slice(&(sections.len() as u16).to_le_bytes());
            header[lfanew + 8..lfanew + 12].copy_from_slice(&timestamp.to_le_bytes());
            let optional = 0xF0u16;
            header[lfanew + 20..lfanew + 22].copy_from_slice(&optional.to_le_bytes());
            header[lfanew + 24..lfanew + 26].copy_from_slice(&0x20Bu16.to_le_bytes());
            header[lfanew + 24 + 56..lfanew + 24 + 60].copy_from_slice(&size.to_le_bytes());
            let table = lfanew + 24 + optional as usize;
            for (index, name) in sections.iter().enumerate() {
                let at = table + index * 40;
                header[at..at + name.len()].copy_from_slice(name.as_bytes());
            }
            self.write(gpa, &header);
        }

        /// A `_KDDEBUGGER_DATA64` at `image_offset` into the image based at `base`.
        fn kdbg(&mut self, base: u64, image_offset: u64, kern_base: u64, module_list: u64) {
            let at = base + image_offset;
            self.write_va(at + 0x10, b"KDBG");
            self.write_va(at + 0x14, &0x3A0u32.to_le_bytes());
            self.write_va(at + 0x18, &kern_base.to_le_bytes());
            self.write_va(at + 0x48, &module_list.to_le_bytes());
        }

        /// A `KLDR_DATA_TABLE_ENTRY` at `va`.
        fn kldr(&mut self, va: u64, flink: u64, blink: u64, dll_base: u64, size: u32, name: &str) {
            self.write_va(va + kldr::FLINK, &flink.to_le_bytes());
            self.write_va(va + kldr::BLINK, &blink.to_le_bytes());
            self.write_va(va + kldr::DLL_BASE, &dll_base.to_le_bytes());
            self.write_va(va + kldr::SIZE_OF_IMAGE, &size.to_le_bytes());
            let utf16: Vec<u8> = name
                .encode_utf16()
                .flat_map(|unit| unit.to_le_bytes())
                .collect();
            let buffer = va + 0x200;
            self.write_va(
                va + kldr::BASE_DLL_NAME,
                &(utf16.len() as u16).to_le_bytes(),
            );
            self.write_va(va + kldr::BASE_DLL_NAME_BUFFER, &buffer.to_le_bytes());
            self.write_va(buffer, &utf16);
        }
    }

    impl RawSource for Fixture {
        fn shape(&self) -> GuestShape {
            self.shape.clone()
        }

        fn max_read(&self) -> usize {
            self.width
        }

        fn read_chunk(&self, gpa: Gpa, out: &mut [u8]) -> Result<(), ReadFailure> {
            let page = gpa.0 & !(PAGE - 1);
            if self.refused.contains(&page) {
                // Bytes written beside a refusal are exactly what the hypercall does: zeros with
                // `HV_STATUS_SUCCESS` and a per-access `ReadIntercept`. Written here on purpose, so
                // a decode that ignored the error would see plausible zeros rather than nothing.
                out.fill(0);
                return Err(ReadFailure::Refused {
                    detail: "ReadIntercept".into(),
                });
            }
            let Some(bytes) = self.pages.get(&page) else {
                return Err(ReadFailure::NotPresent);
            };
            let at = (gpa.0 & (PAGE - 1)) as usize;
            out.copy_from_slice(&bytes[at..at + out.len()]);
            Ok(())
        }
    }

    /// The identity `Fixture::image` writes, as a disk image to compare against.
    fn disk(size: u32, timestamp: u32, sections: &[&str]) -> DiskImage {
        DiskImage {
            path: "synthetic".into(),
            file_size: size as u64,
            identity: PeIdentity {
                machine: 0x8664,
                sections: sections.len() as u16,
                timestamp,
                size_of_image: size,
                section_names: sections.iter().map(|s| (*s).to_string()).collect(),
            },
        }
    }

    #[test]
    fn a_refused_read_is_not_zeros_and_is_counted_at_the_source() {
        let mut fixture = Fixture::new();
        fixture.pages.insert(0x8000, vec![0x11; PAGE as usize]);
        fixture.refused.insert(0x8000);
        let reader = Reader::new(&fixture);
        let failure = reader
            .read(Gpa(0x8000), PAGE as usize)
            .expect_err("refused");
        assert_eq!(
            failure,
            ReadFailure::Refused {
                detail: "ReadIntercept".into()
            }
        );
        let stats = reader.stats();
        assert_eq!((stats.attempted, stats.failed, stats.refused), (1, 1, 1));
    }

    #[test]
    fn a_page_that_is_not_there_is_not_a_refusal() {
        let fixture = Fixture::new();
        let reader = Reader::new(&fixture);
        assert_eq!(reader.read(Gpa(0x900000), 8), Err(ReadFailure::NotPresent));
        // The count still moves — a failure is a failure — but not the refusal count, which is
        // what a VBS control arm reads.
        assert_eq!((reader.stats().failed, reader.stats().refused), (1, 0));
    }

    #[test]
    fn the_sources_transfer_width_does_not_reach_the_decode() {
        // 16 bytes is `HvCallReadGpa`'s width, and judging a page on its first sixteen is what made
        // Secure Kernel's PML4 read as all-zero for most of a session.
        let mut fixture = Fixture::new();
        fixture.width = 16;
        let mut page = vec![0u8; PAGE as usize];
        page[PAGE as usize - 1] = 0x5A;
        fixture.pages.insert(0x8000, page);
        let reader = Reader::new(&fixture);
        let read = reader.read(Gpa(0x8000), PAGE as usize).expect("whole page");
        assert_eq!(read.len(), PAGE as usize);
        assert_eq!(read[PAGE as usize - 1], 0x5A, "the last chunk was not read");
    }

    #[test]
    fn a_read_whose_second_page_is_refused_fails_rather_than_answering_short() {
        let mut fixture = Fixture::new();
        fixture.pages.insert(0x8000, vec![0x11; PAGE as usize]);
        fixture.pages.insert(0x9000, vec![0x22; PAGE as usize]);
        fixture.refused.insert(0x9000);
        let reader = Reader::new(&fixture);
        let failure = reader
            .read(Gpa(0x8000), 2 * PAGE as usize)
            .expect_err("second page refused");
        assert!(failure.is_refusal());
    }

    #[test]
    fn a_refused_switch_and_an_unreadable_register_are_different_answers() {
        // The whole point of keeping them apart: the first is a VBS-off guest, the second is a
        // provider that could not answer one question about a guest that may well have VTL1.
        let refused = GuestShape {
            switch_refused: Some("VM_SAVED_STATE_DUMP_E_VP_VTL_NOT_ENABLED".into()),
            ..GuestShape::default()
        };
        assert!(matches!(
            walkable(&refused),
            Err(NotWalkable::SwitchRefused(_))
        ));
        let no_register = GuestShape {
            unreadable: vec![("cr3", "hresult 0x80070057".into())],
            ..GuestShape::default()
        };
        match walkable(&no_register) {
            Err(NotWalkable::NoRoot { unreadable }) => {
                assert_eq!(unreadable.first().map(|(name, _)| *name), Some("cr3"));
            }
            other => panic!("expected NoRoot, got {other:?}"),
        }
    }

    #[test]
    fn an_unread_paging_mode_or_register_does_not_block_the_walk() {
        // Unknown is not wrong. A source that cannot answer `GetPagingMode` or `EFER` must not read
        // as a machine that is not in long mode.
        let shape = GuestShape {
            cr3: Some(0x1201000),
            ..GuestShape::default()
        };
        assert_eq!(walkable(&shape), Ok(Gpa(0x1201000)));
    }

    #[test]
    fn a_shape_this_walk_does_not_decode_is_refused_by_name() {
        let base = GuestShape {
            cr3: Some(0x1201000),
            ..GuestShape::default()
        };
        let other_mode = GuestShape {
            paging_mode: Some(PagingMode::Pae),
            ..base.clone()
        };
        assert_eq!(
            walkable(&other_mode),
            Err(NotWalkable::PagingMode(PagingMode::Pae))
        );
        let five_level = GuestShape {
            cr4: Some(1 << 12),
            ..base.clone()
        };
        assert_eq!(walkable(&five_level), Err(NotWalkable::FiveLevel));
        let not_long = GuestShape {
            cr0: Some(1),
            cr4: Some(1 << 5),
            efer: Some(0),
            ..base.clone()
        };
        assert_eq!(walkable(&not_long), Err(NotWalkable::NotLongMode));
        let vtl_off = GuestShape {
            vtl_enabled: Some(false),
            ..base
        };
        assert_eq!(walkable(&vtl_off), Err(NotWalkable::VtlNotEnabled));
    }

    #[test]
    fn a_self_mapping_root_terminates_and_says_what_it_skipped() {
        // Secure Kernel's PML4 self-maps at index 388 on the measured build. Unguarded, a descent
        // re-enters the table 512x per level; this took the bench down twice during H4.
        let mut fixture = Fixture::new();
        fixture.map_range(0xFFFF_F800_0000_0000, 0x40000, 2 * PAGE);
        let root = fixture.root;
        fixture.set_entry(root, 388, root | ENTRY_PRESENT);
        let reader = Reader::new(&fixture);
        let (leaves, stats) = walk(&reader, Gpa(root));
        assert!(stats.complete(), "{stats:?}");
        assert_eq!(leaves.len(), 2, "the two real pages, and nothing invented");
        // The self-map is cut where it is found rather than expanded at three levels, so the alias
        // counter stays at zero here: what it counts is a *table* reached twice at one level.
        assert_eq!(stats.alias_prefixes_skipped, 0);
    }

    /// A virtual address in PML4 slot 1, so that a test naming a slot means the slot it names.
    /// `0x1_0000_0000` is slot **0** — its index lives in the PDPT — and two tests here asserted
    /// against slot 4 and slot 8 on that arithmetic, passing over an empty entry each time.
    const SLOT: u64 = 1 << 39;

    #[test]
    fn the_root_page_is_judged_on_all_of_its_bytes() {
        // A 16-byte window is what read Secure Kernel's PML4 as all-zero: it maps nothing in the
        // low canonical half, so its first entries are legitimately zero.
        let mut fixture = Fixture::new();
        fixture.width = 16;
        fixture.map_range(0xFFFF_8000_0000_0000, 0x40000, PAGE);
        let root = fixture.root;
        fixture.set_entry(root, 388, root | ENTRY_PRESENT);
        let reader = Reader::new(&fixture);
        let described = describe_root(&reader, Gpa(root)).expect("the root page reads");
        assert_eq!(described.self_map_indexes, vec![388]);
        assert_eq!(described.present_entries, 2, "the mapping and the self-map");
        assert_eq!(described.first_present_index, Some(256));
        assert_eq!(described.upper_half_present, 2);
        assert!(described.nonzero_bytes > 0);
    }

    #[test]
    fn a_root_page_that_could_not_be_read_is_not_a_root_page_of_zeros() {
        let mut fixture = Fixture::new();
        fixture.refused.insert(fixture.root);
        let reader = Reader::new(&fixture);
        assert!(describe_root(&reader, Gpa(fixture.root)).is_err());
    }

    #[test]
    fn a_table_reached_twice_at_one_level_is_expanded_once_and_counted() {
        let mut fixture = Fixture::new();
        fixture.map_range(SLOT, 0x40000, PAGE);
        // Point a second PML4 slot at the same PDPT: one table, two prefixes.
        let root = fixture.root;
        let pdpt = fixture.entry(root, 1) & PFN_MASK;
        assert_ne!(pdpt, 0, "the fixture must have built a PDPT in slot 1");
        fixture.set_entry(root, 2, pdpt | ENTRY_PRESENT);
        let reader = Reader::new(&fixture);
        let (leaves, stats) = walk(&reader, Gpa(root));
        assert_eq!(leaves.len(), 1, "the second prefix is not expanded");
        assert_eq!(
            stats.alias_prefixes_skipped, 1,
            "and it is counted rather than silent"
        );
        assert!(
            stats.complete(),
            "pruning an alias is deliberate, not a failure"
        );
    }

    #[test]
    fn a_large_leaf_with_pat_set_is_not_masked_at_four_kibibytes() {
        // Bit 12 of a large PDE is PAT, not the low bit of the frame. Masking at 4 KiB lands one
        // page high, and a scan of that leaf then starts a page inside the mapping and runs a page
        // past its end.
        let two_mib = 1u64 << 21;
        let entry = (0x4000_0000u64) | (1 << 12) | ENTRY_LARGE | ENTRY_PRESENT;
        let decoded = decode_entry(entry, 2).expect("present");
        assert_eq!(decoded.kind, EntryKind::Leaf);
        assert_eq!(decoded.size, two_mib);
        assert_eq!(
            decoded.address,
            Gpa(0x4000_0000),
            "PAT must not reach the frame"
        );
        assert!(!decoded.malformed, "PAT is legal on a large leaf");
    }

    #[test]
    fn entries_the_processor_would_fault_on_are_skipped_and_counted() {
        // Reserved bits between 13 and the mapping's alignment.
        let malformed = (0x4000_0000u64 | (1 << 14)) | ENTRY_LARGE | ENTRY_PRESENT;
        assert!(decode_entry(malformed, 2).expect("present").malformed);
        // And the page-size bit in a PML4E, where it has no meaning.
        assert!(
            decode_entry(0x2000 | ENTRY_LARGE | ENTRY_PRESENT, 0)
                .expect("present")
                .malformed
        );

        let mut fixture = Fixture::new();
        fixture.map_range(0x1_0000_0000, 0x40000, PAGE);
        let root = fixture.root;
        fixture.set_entry(root, 6, 0x50000 | ENTRY_LARGE | ENTRY_PRESENT);
        let reader = Reader::new(&fixture);
        let (leaves, stats) = walk(&reader, Gpa(root));
        assert_eq!(leaves.len(), 1);
        assert_eq!(stats.malformed_entries, 1);
    }

    #[test]
    fn a_table_that_could_not_be_read_makes_the_walk_incomplete() {
        let mut fixture = Fixture::new();
        fixture.map_range(SLOT, 0x40000, PAGE);
        fixture.map_range(2 * SLOT, 0x50000, PAGE);
        let root = fixture.root;
        let pdpt = fixture.entry(root, 1) & PFN_MASK;
        assert_ne!(pdpt, 0, "the fixture must have built a PDPT in slot 1");
        fixture.refused.insert(pdpt);
        let reader = Reader::new(&fixture);
        let (leaves, stats) = walk(&reader, Gpa(root));
        assert_eq!(leaves.len(), 1, "the readable subtree is still an answer");
        assert_eq!(stats.unreadable_tables, 1);
        assert_eq!(stats.incomplete, Some(Incomplete::UnreadableTables(1)));
        assert!(!stats.complete());
    }

    #[test]
    fn exhausting_a_budget_reports_rather_than_truncating_silently() {
        let mut fixture = Fixture::new();
        for index in 0..8u64 {
            fixture.map_range(
                0x1_0000_0000 + index * (1 << 30),
                0x40000 + index * PAGE,
                PAGE,
            );
        }
        let reader = Reader::new(&fixture);
        let (_, stats) = walk_within(
            &reader,
            Gpa(fixture.root),
            Budgets {
                table_reads: 3,
                leaves: 1000,
            },
        );
        assert_eq!(
            stats.incomplete,
            Some(Incomplete::Budget(Budget::TableReads(3)))
        );
        assert!(!stats.complete());

        let reader = Reader::new(&fixture);
        let (leaves, stats) = walk_within(
            &reader,
            Gpa(fixture.root),
            Budgets {
                table_reads: 100,
                leaves: 2,
            },
        );
        assert_eq!(leaves.len(), 2);
        assert_eq!(
            stats.incomplete,
            Some(Incomplete::Budget(Budget::Leaves(2)))
        );
    }

    #[test]
    fn a_large_leaf_counts_as_the_pages_it_covers() {
        // A set of leaf GPAs would call a 2 MiB mapping one page, and a frame count would call it
        // 512 — two figures in different units the first time a large mapping appears.
        let space = AddressSpace::new(vec![
            Leaf {
                va: Gva(0x1000),
                gpa: Gpa(0x200000),
                size: 1 << 21,
            },
            Leaf {
                va: Gva(0x400000),
                gpa: Gpa(0x800000),
                size: PAGE,
            },
        ]);
        assert_eq!(space.distinct_pages(), 512 + 1);
    }

    #[test]
    fn a_page_that_could_not_be_read_is_poisoned_rather_than_zeroed() {
        let mut fixture = Fixture::new();
        fixture.image(0x2_0000_0000, 0x40000, 3 * PAGE as u32, 7, &[".text"]);
        let second = *fixture.mapped.get(&(0x2_0000_0000 + PAGE)).expect("mapped");
        fixture.refused.insert(second);
        let reader = Reader::new(&fixture);
        let (leaves, _) = walk(&reader, Gpa(fixture.root));
        let space = AddressSpace::new(leaves);
        let reads = Space::new(&reader, &space);
        let image = gather_image(&reads, Gva(0x2_0000_0000), 3 * PAGE as u32);
        assert_eq!(image.missing.len(), 1);
        assert_eq!(image.missing[0].0, PAGE);
        // The literal, deliberately, and **not** `POISON`: asserting against the constant the code
        // fills with compares it to itself, so changing the fill to zero moves both sides of the
        // assertion and the test passes on the bug it exists for. Mutation-verified.
        assert!(
            image.bytes[PAGE as usize..2 * PAGE as usize]
                .iter()
                .all(|b| *b == 0xAA),
            "a zero fill would make an unread page indistinguishable from a page of zeros"
        );
    }

    /// One image, two mappings, and the debugger data block under the second — which is the case
    /// that made "stop at the first match" report no block at all.
    fn duplicate_mapping_fixture() -> (Fixture, u64, u64) {
        let size = 4 * PAGE as u32;
        let (first, second) = (0x2_0000_0000u64, 0x3_0000_0000u64);
        let mut fixture = Fixture::new();
        // Deliberately mapped at two virtual addresses from two physical copies: the bytes are the
        // same image either way, which is exactly why `matches_disk` cannot settle the base.
        fixture.image(first, 0x40000, size, 7, &[".text"]);
        fixture.image(second, 0x60000, size, 7, &[".text"]);
        let list_head = second + 0x800;
        let entry = second + 0x900;
        fixture.kdbg(second, 0x100, second, list_head);
        fixture.write_va(list_head, &entry.to_le_bytes());
        fixture.write_va(list_head + 8, &entry.to_le_bytes());
        fixture.kldr(
            entry,
            list_head,
            list_head,
            second,
            size,
            "securekernel.exe",
        );
        (fixture, first, second)
    }

    #[test]
    fn identification_tries_every_candidate_and_accepts_the_one_two_structures_agree_on() {
        let (fixture, first, second) = duplicate_mapping_fixture();
        let reader = Reader::new(&fixture);
        let disk = disk(4 * PAGE as u32, 7, &[".text"]);
        let landmarks = locate(&reader, &disk, true).expect("walkable");
        let found = landmarks
            .identified
            .expect("the second mapping carries the block");
        assert_eq!(found.candidate.va, Gva(second));
        assert_eq!(found.block.kern_base, second);
        assert_eq!(found.modules.names(), vec!["securekernel.exe"]);
        assert!(found.modules.valid.is_ok());
        assert!(found.modules.complete(), "the list closes on its head");
        // Both mappings were examined, and the report says so rather than implying there was one.
        assert_eq!(landmarks.attempts.len(), 2);
        assert_eq!(landmarks.attempts[0].candidate.va, Gva(first));
        assert!(!landmarks.attempts[0].accepted);
        // And the structural route found the same head without reading the block.
        let cross = landmarks.cross_check.expect("the entry names the base");
        let cross = cross.expect("the structural route finds the entry");
        assert_eq!(cross.head, Gva(found.block.ps_loaded_module_list));
    }

    #[test]
    fn the_cross_check_says_whether_its_budget_stopped_it() {
        // The measured run found its entry after 1,249 pages, which is luck rather than a bound: a
        // single 1 GiB leaf is 262,144 pages, and a capture can return many.
        let mut fixture = Fixture::new();
        fixture.map_range(SLOT, 0x40000, 4 * PAGE);
        let reader = Reader::new(&fixture);
        let (leaves, _) = walk(&reader, Gpa(fixture.root));
        let space = AddressSpace::new(leaves.clone());
        let reads = Space::new(&reader, &space);

        // A base nothing names, with room to look everywhere: a miss that is a real search.
        let miss = cross_check_within(&reads, &leaves, 0xDEAD_0000, 0x1000, 100)
            .expect_err("nothing names that base");
        assert!(!miss.capped, "{miss:?}");
        assert_eq!(miss.pages_scanned, 4);

        // The same search with a budget below the work: refused, and it says so rather than
        // reporting the same clean miss.
        let capped = cross_check_within(&reads, &leaves, 0xDEAD_0000, 0x1000, 2)
            .expect_err("the budget stops it");
        assert!(
            capped.capped,
            "a budget that stops a search must not read as a search"
        );
        assert_eq!(capped.pages_scanned, 2);
    }

    #[test]
    fn a_kernbase_match_with_a_list_that_names_somebody_else_is_refused() {
        // `KernBase` is necessary and was once treated as sufficient. The measured block has 26 of
        // its 116 words non-zero, so a stale `PsLoadedModuleList` is the ordinary case, and a list
        // walked from one yields plausible names rather than an error.
        let size = 4 * PAGE as u32;
        let base = 0x2_0000_0000u64;
        let mut fixture = Fixture::new();
        fixture.image(base, 0x40000, size, 7, &[".text"]);
        let head = base + 0x800;
        let entry = base + 0x900;
        fixture.kdbg(base, 0x100, base, head);
        fixture.write_va(head, &entry.to_le_bytes());
        fixture.kldr(
            entry,
            head,
            head,
            0xDEAD_0000_0000,
            size,
            "somebody-else.sys",
        );
        let reader = Reader::new(&fixture);
        let landmarks = locate(&reader, &disk(size, 7, &[".text"]), false).expect("walkable");
        assert!(
            landmarks.identified.is_none(),
            "a block naming a foreign list is not an answer"
        );
        let rejected = &landmarks.attempts[0].rejected;
        assert!(matches!(
            rejected.first().map(|(_, why)| why),
            Some(HitRejected::ListInvalid(ListInvalid::FirstBaseIsNot { .. }))
        ));
        // The tag was found and refused, which is the case this record exists for — S0's probe used
        // to report exactly this as no tags at all.
        assert_eq!(landmarks.attempts[0].hits.len(), 1);
    }

    #[test]
    fn a_tag_straddling_a_page_boundary_is_found() {
        // A debugger data block sits wherever it sits. A per-page search cannot see a tag split
        // across the boundary, and would reject one whose fields continue into the page after.
        let size = 4 * PAGE as u32;
        let base = 0x2_0000_0000u64;
        let mut fixture = Fixture::new();
        fixture.image(base, 0x40000, size, 7, &[".text"]);
        let head = base + 0x1800;
        let entry = base + 0x1900;
        // The tag lands at image offset 0x1000 - 2: two bytes in one page, two in the next.
        let block = PAGE - 0x12;
        fixture.kdbg(base, block, base, head);
        fixture.write_va(head, &entry.to_le_bytes());
        fixture.kldr(entry, head, head, base, size, "securekernel.exe");
        let reader = Reader::new(&fixture);
        let landmarks = locate(&reader, &disk(size, 7, &[".text"]), false).expect("walkable");
        let found = landmarks
            .identified
            .expect("the tag straddles and is still found");
        assert_eq!(found.block.image_offset, block);
    }

    #[test]
    fn an_unreadable_name_is_not_a_module_without_a_name() {
        let size = 4 * PAGE as u32;
        let base = 0x2_0000_0000u64;
        let mut fixture = Fixture::new();
        fixture.image(base, 0x40000, size, 7, &[".text"]);
        let head = base + 0x800;
        let (first, second) = (base + 0x900, base + 0xA00);
        fixture.kdbg(base, 0x100, base, head);
        fixture.write_va(head, &first.to_le_bytes());
        fixture.kldr(first, second, head, base, size, "securekernel.exe");
        fixture.kldr(second, head, first, base + 0x10000, size, "skci.dll");
        // Point the second entry's name at an address nothing maps.
        fixture.write_va(
            second + kldr::BASE_DLL_NAME_BUFFER,
            &0xFFFF_0000_0000u64.to_le_bytes(),
        );
        let reader = Reader::new(&fixture);
        let landmarks = locate(&reader, &disk(size, 7, &[".text"]), false).expect("walkable");
        let modules = landmarks.identified.expect("identified").modules;
        assert_eq!(modules.names_unreadable, 1);
        assert_eq!(modules.entries.len(), 2);
        let name = &modules.entries[1]
            .record
            .as_ref()
            .expect("record read")
            .name;
        assert!(
            matches!(name, Err(NameFailure::Unreadable { .. })),
            "an empty string here would make this the same record as a module with no name"
        );
        // The enumeration still closed, so the list confirms the block and says nothing is missing.
        assert!(modules.valid.is_ok() && modules.complete());
    }

    #[test]
    fn a_list_that_does_not_close_still_confirms_the_block() {
        // Rejecting a list that does not close would refuse a genuine block on any build with more
        // modules than the limit — the round-2 defect from the other side.
        let size = 4 * PAGE as u32;
        let base = 0x2_0000_0000u64;
        let mut fixture = Fixture::new();
        fixture.image(base, 0x40000, size, 7, &[".text"]);
        let head = base + 0x800;
        let entry = base + 0x900;
        fixture.kdbg(base, 0x100, base, head);
        fixture.write_va(head, &entry.to_le_bytes());
        // A null forward link: the walk leaves the list without closing.
        fixture.kldr(entry, 0, head, base, size, "securekernel.exe");
        let reader = Reader::new(&fixture);
        let landmarks = locate(&reader, &disk(size, 7, &[".text"]), false).expect("walkable");
        let modules = landmarks
            .identified
            .expect("the block is still confirmed")
            .modules;
        assert!(modules.valid.is_ok(), "valid is about the block");
        assert_eq!(modules.incomplete, Some(ListIncomplete::NullForwardLink));
        assert!(!modules.complete(), "complete is about the enumeration");
    }

    #[test]
    fn a_scan_that_could_not_read_a_page_says_so_rather_than_reporting_no_image() {
        let mut fixture = Fixture::new();
        fixture.map_range(0x2_0000_0000, 0x40000, 2 * PAGE);
        fixture.refused.insert(0x40000);
        fixture.refused.insert(0x41000);
        let reader = Reader::new(&fixture);
        let (leaves, _) = walk(&reader, Gpa(fixture.root));
        let (found, stats) = scan_for_images(&reader, &leaves, &disk(PAGE as u32, 7, &[".text"]));
        assert!(found.is_empty());
        assert_eq!((stats.scanned, stats.unreadable), (2, 2));
        // And the reader's own count agrees, which is the number no scan can suppress.
        assert_eq!(reader.stats().refused, 2);
    }

    #[test]
    fn a_large_leaf_is_expanded_rather_than_sampled_at_its_first_page() {
        // An image inside a 2 MiB mapping would otherwise be invisible.
        let mut fixture = Fixture::new();
        let size = PAGE as u32;
        let base = 0x2_0000_0000u64;
        // Build the image's bytes at a physical address inside a large mapping, and map the whole
        // 2 MiB with one PDE.
        fixture.image(base, 0x200000 + 3 * PAGE, size, 7, &[".text"]);
        let root = fixture.root;
        let pdpt = fixture.entry(root, (base >> 39) as usize & 0x1FF) & PFN_MASK;
        let pd = fixture.entry(pdpt, (base >> 30) as usize & 0x1FF) & PFN_MASK;
        let index = (base >> 21) as usize & 0x1FF;
        fixture.set_entry(pd, index, 0x200000 | ENTRY_LARGE | ENTRY_PRESENT);
        for page in 0..4u64 {
            fixture
                .pages
                .entry(0x200000 + page * PAGE)
                .or_insert_with(|| vec![0u8; PAGE as usize]);
        }
        let reader = Reader::new(&fixture);
        let (leaves, _) = walk(&reader, Gpa(root));
        let large = leaves
            .iter()
            .find(|leaf| leaf.size == 1 << 21)
            .expect("a large leaf");
        let (found, stats) = scan_for_images(&reader, &[*large], &disk(size, 7, &[".text"]));
        assert_eq!(
            stats.scanned, 512,
            "every page-aligned base inside the mapping"
        );
        assert_eq!(found.len(), 1, "the image three pages in was found");
        assert_eq!(found[0].va, Gva(large.va.0 + 3 * PAGE));
    }

    #[test]
    fn the_block_size_is_reported_rather_than_matched() {
        // A needle built from a remembered 0x3A8 is what made an earlier scan report zero
        // occurrences with the block three pages away. The live value is 0x3A0.
        let size = 4 * PAGE as u32;
        let base = 0x2_0000_0000u64;
        let mut fixture = Fixture::new();
        fixture.image(base, 0x40000, size, 7, &[".text"]);
        let head = base + 0x800;
        let entry = base + 0x900;
        fixture.kdbg(base, 0x100, base, head);
        // A size no build has ever reported. It must not affect whether the block is found.
        fixture.write_va(base + 0x100 + 0x14, &0x1234u32.to_le_bytes());
        fixture.write_va(head, &entry.to_le_bytes());
        fixture.kldr(entry, head, head, base, size, "securekernel.exe");
        let reader = Reader::new(&fixture);
        let landmarks = locate(&reader, &disk(size, 7, &[".text"]), false).expect("walkable");
        assert_eq!(landmarks.identified.expect("found").block.size, 0x1234);
    }

    #[test]
    fn a_pe32_header_is_not_identified_as_a_pe64_image() {
        // `SizeOfImage` lives at a different offset in a PE32 optional header, so reading it there
        // would be reading some other field.
        let mut bytes = vec![0u8; PAGE as usize];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x80 + 24..0x80 + 26].copy_from_slice(&0x10Bu16.to_le_bytes());
        assert!(pe_identity(&bytes).is_none());
    }
}
