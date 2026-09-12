//! Which control codes a dispatch routine accepts, read off the driver's own code.
//!
//! The question `decode_ioctl` answers for one code, asked of a whole driver: given
//! `MajorFunction[IRP_MJ_DEVICE_CONTROL]`, which codes does it recognise, and where does each one
//! go. What comes back is a case per recognised code, with the site that recognised it and the
//! block it routes to, so a reader can go and look rather than take the list on trust.
//!
//! # How a code is recovered
//!
//! Two shapes, and the answer says which produced each case.
//!
//! - **A compare chain.** `cmp r13d, 6D0008h` / `je handler` is one case, and a driver with a
//!   handful of codes is usually nothing else. `sub eax, 6D0034h` is the same statement written
//!   as arithmetic, and is followed rather than skipped: the register is *rebased*, so every
//!   compare after it is against a code offset by what was subtracted, and a pass that ignored it
//!   would report the neighbouring codes wrongly rather than not at all.
//! - **A jump table.** A dense run of codes becomes a bounds check, an indexed load and an
//!   indirect jump, and the table is in the image. It is followed **only** when the base, the
//!   scale and a bounded entry count were all recovered, and only when the index is the code
//!   itself rather than the code **shifted**; anything else is recorded as an unresolved
//!   transfer, because a table read at a guessed address is a list of plausible addresses rather
//!   than an answer, and a shifted index is several codes reaching one slot with nothing here
//!   saying which of them the driver takes. A case recovered this way carries no **sizes**: the
//!   edge it arrived on is not in the graph, so nothing is believed about the registers a length
//!   check would be read through.
//!
//! # What decides the control code
//!
//! The code is `IO_STACK_LOCATION.Parameters.DeviceIoControl.IoControlCode`, which a dispatch
//! routine reaches as `[[Irp+0xb8]+0x18]`. This pass tracks that chain from the dispatch
//! routine's second argument, so `[rdx+0xb8]` into a register and `+0x18` off *that* register is
//! the control code and nothing else is. A driver whose chain this cannot follow — the pointer
//! came from a callee, the listing began mid-function — falls back to the bare `+0x18`
//! displacement, which is the heuristic `FOLLOWUPS.md` item 5 bounds, and [`Map::code_proved`]
//! says which of the two produced the answer. The distinction matters because `+0x18` off an
//! arbitrary register is an extremely ordinary thing for code to do.
//!
//! # How this is derived
//!
//! A **walk over the function's blocks**, not down its listing. `uf` prints a function's basic
//! blocks one after another, so reading the listing straight through carries register facts across
//! seams control flow never crosses -- a shared epilogue's `pop r13`, the block after a `ret` that
//! is entered from a branch elsewhere. [`crate::cfg`] recovers the blocks and the edges from the
//! flow the decoder already answers, and the facts here travel along those edges: what a block
//! knows is what **every** path into it agrees on, a bounds check holds on the path it admits and
//! not on the one it rejects, and a case block is read with the facts of the path that reaches it.
//!
//! That is a rewrite of an earlier straight-line pass ([#306](https://github.com/glslang/windbg-mcp/issues/306)),
//! and the reason for it is worth keeping: thirteen review findings across four rounds were all one
//! sentence -- the pass carried a fact across a boundary it had not earned -- and each fix was a
//! guard, with the guards becoming where the next finding landed. A graph answers them by
//! construction. The measure that it is the same analysis is `mountmgr`: the same control codes,
//! from the same two tables, with two more *sites* found because two blocks the straight-line pass
//! had lost the code register in are reached along an edge.
//!
//! # Engine-free
//!
//! Like [`crate::pe`], [`crate::hazards`] and [`crate::driver`], every entry point takes closures
//! rather than a `DebugEngine`: a decoded function, a reader for the image's own bytes, and a
//! halt poll. So every case below is unit-tested against a hand-built instruction list with no
//! debugger anywhere near it.

use std::collections::{BTreeMap, HashMap};

use dbgscope::dbgeng::{Condition, Effect, Flow, Instruction, Operand};

use crate::cfg;
use crate::walk::Halt;

/// Bounds. A malformed or hostile driver decides how much work this is, so every list the answer
/// carries has a cap, and [`Map::cap_hit`] says one was reached.
///
/// The **case** count stays exact past its cap, because how many codes a driver accepts is the
/// question the map answers. The other two lists are evidence rather than the answer, and a
/// truncated one supports the same reading as a full one -- entries in `unresolved` say the map is
/// a lower bound whether there are three of them or three thousand -- so they are bounded and not
/// counted.
///
/// The numbers are far past what a real driver produces — the largest dispatch routine measured
/// here recognises 28 codes — and are here to bound the absurd rather than to shape an answer.
pub(crate) const MAX_CASES: usize = 4096;
/// The most entries followed out of one jump table. A table is `entries * 4` bytes of reads, so
/// this is also what bounds the reading.
pub(crate) const MAX_TABLE_ENTRIES: usize = 4096;
/// The width of one entry in a switch table: a `DWORD` RVA, which is what makes the index's scale
/// 4 and what the reader decodes. Named once, because a guard and a read that disagree about it
/// would take a table apart at one width and put it back together at another.
pub(crate) const TABLE_ENTRY: u32 = 4;
/// The most jump tables and unresolved transfers one map carries. A block has one terminator, so
/// these are bounded by the routine's size -- which is the target's to decide, and a listing that
/// begins mid-code is indirect jumps all the way down.
pub(crate) const MAX_TABLES: usize = 256;
pub(crate) const MAX_UNRESOLVED: usize = 1024;

/// How a case was recovered, which is what says how much of it to trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Recovery {
    /// A compare against the control code, with a conditional branch reading its flags.
    Compare,
    /// An entry in a resolved jump table.
    JumpTable,
}

impl Recovery {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Compare => "compare",
            Self::JumpTable => "jump_table",
        }
    }
}

/// A size the dispatch code requires of a buffer, and whether it is the size or a floor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SizeCheck {
    /// The value compared against.
    pub(crate) value: u32,
    /// Where the compare is.
    pub(crate) at: u64,
    /// True when the path continues only if the length **equals** this — an exact size. False for
    /// a floor or a ceiling, which is evidence about the check rather than the buffer's size.
    pub(crate) exact: bool,
}

/// One control code the dispatch routine recognises.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Case {
    pub(crate) code: u32,
    pub(crate) recovered: Recovery,
    /// The instruction that recognises this code: the compare, or the indirect jump whose table
    /// holds it.
    pub(crate) site: u64,
    /// Where control goes when the code matches.
    pub(crate) lands: u64,
    /// The routine the case block reaches, when it reaches one directly — a `call` or a tail
    /// `jmp` to a fixed address within [`WINDOW`] instructions of the landing site. `None` means
    /// the work is inline, or is reached through a pointer, not that there is none.
    pub(crate) handler: Option<u64>,
    /// Whether the value this case tested was traced from the IRP rather than read off a bare
    /// `+0x18` displacement. Per case, because one routine can have both.
    pub(crate) proved: bool,
    /// Whether the block this code reaches **handles** it, as far as the code says.
    ///
    /// A compare and a branch say where control goes when a code matches; they do not say that
    /// the driver accepts it. `cmp code,N` / `je invalid_request` is the same shape as `je
    /// handler`, and reporting the first as an accepted code sends a reader to test a code the
    /// driver rejects. So this is `Some(false)` for a block that sets an NTSTATUS error and
    /// returns, `Some(true)` for one that reaches a routine, and `None` where neither is visible.
    pub(crate) accepted: Option<bool>,
    /// The input length the case requires, when the case block proves one.
    pub(crate) in_size: Option<SizeCheck>,
    /// The output length the case requires, when the case block proves one.
    pub(crate) out_size: Option<SizeCheck>,
}

/// One resolved jump table, kept as evidence for the cases it produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Table {
    /// The indirect `jmp` the table feeds.
    pub(crate) at: u64,
    /// Where the table is.
    pub(crate) table: u64,
    /// How many entries the bounds check admits.
    pub(crate) entries: usize,
    /// How many of those entries became cases. The difference is the slots that go to the
    /// switch's **default** -- a dense table covers every index in its range, and a compiler fills
    /// the ones it has no case for with the block the bounds check jumps to.
    pub(crate) followed: usize,
}

/// What a dispatch routine accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Map {
    /// Where the dispatch routine is.
    pub(crate) dispatch: u64,
    /// Whether the control code was reached through the IRP's stack location (`[[Irp+0xb8]+0x18]`)
    /// rather than through the bare `+0x18` displacement.
    ///
    /// **An empty case list means different things on either side of this.** Proved, it says the
    /// routine reads the control code and compares it against nothing this pass could follow.
    /// Unproved, it may equally mean the routine never read a control code at all, and the map is
    /// then about some other `+0x18`.
    pub(crate) code_proved: bool,
    /// The recognised codes, in the order the routine recognises them, up to [`MAX_CASES`].
    pub(crate) cases: Vec<Case>,
    /// How many were found, exact however many are listed.
    pub(crate) case_count: usize,
    /// The jump tables that were followed, up to [`MAX_TABLES`].
    pub(crate) tables: Vec<Table>,
    /// Indirect transfers that were **not** followed, by address: an unresolved switch, a call
    /// through a pointer. Each one is a place a code could be recognised and was not, which is
    /// what stops a short case list reading as a complete one. Up to [`MAX_UNRESOLVED`], past
    /// which [`Map::cap_hit`] carries the same warning the list does.
    pub(crate) unresolved: Vec<u64>,
    /// Why the walk stopped early, when it did.
    pub(crate) halted: Option<Halt>,
    /// True when a bound above ended something early.
    pub(crate) cap_hit: bool,
    /// How many of [`Self::case_count`] tested a value that was not traced to the IRP.
    ///
    /// Exact past the cap, as the count is: a figure taken from the cases that were **kept** reads
    /// `0 of 4096` under a warning that fired because the four thousand and ninety-seventh was the
    /// unproved one.
    pub(crate) unproved: usize,
    /// True when the block walk ran out of sweeps before the facts stopped moving.
    ///
    /// Everything that depends on a fact is **discarded** in that state rather than reported, so
    /// this is the difference between a routine with no recognisable codes and one this could not
    /// settle an answer about.
    pub(crate) unsettled: bool,
    /// Instructions examined.
    pub(crate) examined: usize,
    /// How many instructions in the routine could **not** be read or decoded.
    ///
    /// Each one is a place a compare or a dispatch jump may be, so a map with any of these is
    /// incomplete in a way no other field says: the walk did not stop, no bound was hit, and
    /// nothing was left unresolved -- there was simply nothing there to read. On a dump missing a
    /// code page that is the difference between a short answer and a wrong one.
    pub(crate) blind: usize,
}

/// What this pass believes a register holds.
///
/// Deliberately tiny: the three facts a control-code recovery needs, and nothing else. Anything
/// not modelled **clears** the register rather than being ignored, because a stale belief about a
/// register is how a compare against something else is reported as a control code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Value {
    /// The IRP, which a dispatch routine is handed in `rdx`.
    Irp,
    /// The IRP's current stack location.
    StackLocation,
    /// `(code - offset) >> shift`, where `code` is the control code. Both are what the dispatch
    /// arithmetic has done to it so far, so a compare against this register is a statement about
    /// the code itself.
    ///
    /// `proved` travels **with the value**, not beside it, and that is the point: a routine that
    /// compares some other structure's `+0x18` field and later reads the real control code has
    /// one of each, and a flag on the routine would let the first borrow the second's credibility.
    /// Copy propagation carries it, so a case says how the value it tested was obtained.
    Code {
        offset: i64,
        shift: u32,
        proved: bool,
    },
    /// `Parameters.DeviceIoControl.InputBufferLength`.
    InputLength,
    /// `Parameters.DeviceIoControl.OutputBufferLength`.
    OutputLength,
    /// A constant address, from a RIP-relative `lea` — what a jump table is indexed against.
    Address(u64),
}

/// Where the fields this reads live, which is a question about the target's **bitness** rather
/// than a constant.
///
/// Both structures are laid out around a pointer, so every offset moves between x86 and x64:
/// `Tail.Overlay.CurrentStackLocation` is at `+0xb8` in a 64-bit IRP and `+0x60` in a 32-bit one,
/// and the control code is `+0x18` into the stack location against `+0x0c`. Reading a 32-bit
/// driver with the 64-bit numbers finds no control code at all and reports every unrelated
/// `+0x18` access as one, which is the shape of wrong answer this module is arranged against — so
/// the layout is selected by the target rather than assumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Layout {
    /// `Irp->Tail.Overlay.CurrentStackLocation`.
    current_stack_location: i64,
    /// `IO_STACK_LOCATION.Parameters.DeviceIoControl.IoControlCode`.
    control_code: i64,
    input_length: i64,
    output_length: i64,
    /// Where a dispatch routine's return value goes, which is what makes a status a **refusal**
    /// rather than a constant somebody loaded.
    return_register: &'static str,
    /// How wide a pointer is on this target, which is what a load of the IRP's stack location has
    /// to be to have loaded one.
    pointer: u32,
    /// `Irp->IoStatus.Status`, which with the return register is where a refusal puts its status.
    status_field: i64,
    /// The registers a `call` may return over, spelled as **this target's** decoder spells a full
    /// register.
    ///
    /// Per layout rather than one list, because the spellings do not overlap: `eax` is part of
    /// `rax` on x64 and is the whole register on x86, so an x64 list applied to a 32-bit target
    /// forgets nothing at all -- and a routine that loads the code into `eax`, calls a helper and
    /// compares the helper's **return value** would have that compare reported as a case the
    /// driver accepts.
    volatile: &'static [&'static str],
    /// The register a dispatch routine's `Irp` argument arrives in, when the calling convention
    /// puts it in one.
    ///
    /// `None` on x86, where both arguments are on the stack: the chain from the IRP cannot be
    /// followed there, so a code comes from the bare displacement and every case says
    /// `proved: false`. A real limitation, reported rather than silent.
    irp_register: Option<&'static str>,
}

impl Layout {
    pub(crate) const X64: Self = Self {
        current_stack_location: 0xb8,
        control_code: 0x18,
        input_length: 0x10,
        output_length: 0x08,
        return_register: "rax",
        pointer: 8,
        status_field: 0x30,
        volatile: &["rax", "rcx", "rdx", "r8", "r9", "r10", "r11"],
        irp_register: Some("rdx"),
    };
    pub(crate) const X86: Self = Self {
        current_stack_location: 0x60,
        control_code: 0x0c,
        input_length: 0x08,
        output_length: 0x04,
        return_register: "eax",
        pointer: 4,
        status_field: 0x18,
        volatile: &["eax", "ecx", "edx"],
        irp_register: None,
    };
}

/// What the walk knows on one path into a block.
///
/// **Facts travel along edges, not down the listing.** That is the whole difference between this
/// and the pass it replaces: `uf` prints a function's blocks in sequence, so carrying a register's
/// meaning from one instruction to the next carries it across seams control flow never crosses —
/// a shared epilogue's `pop r13`, the block after a `ret` that is entered from a branch elsewhere.
/// Every such carry was a guard, and the guards were where the next defect landed (#306).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Facts {
    /// What each register holds, by the full-width register the decoder names.
    registers: BTreeMap<String, Value>,
    /// An index bound that holds **on this path**: `cmp eax,50h` / `ja default` leaves it on the
    /// fall-through edge and not on the branch's, which is what makes a jump table's length a
    /// fact about the path that reaches it rather than about the listing near it.
    bound: Option<Bound>,
}

impl Facts {
    /// What two paths into one block agree on.
    ///
    /// A fact that is not on every edge is not a fact at the join: a register holding the control
    /// code on one path and something else on another holds neither here. Dropping it is what
    /// makes the answer sound; keeping it is what a straight-line pass does by accident.
    fn join(&mut self, other: &Facts) -> bool {
        let mut changed = false;
        self.registers.retain(|register, value| {
            let agrees = other.registers.get(register) == Some(value);
            changed |= !agrees;
            agrees
        });
        if self.bound != other.bound {
            changed |= self.bound.is_some();
            self.bound = None;
        }
        changed
    }
}

/// The width of every field this module reads: `IoControlCode` and the two lengths are `ULONG`s,
/// so a value narrower than this is part of one rather than one.
const FIELD_WIDTH: u32 = 4;

/// How many times the block walk may sweep the function before the facts stop moving.
///
/// A forward analysis in reverse post-order converges in about one sweep per loop nesting level,
/// and a dispatch routine has one or two. This is far past that, and is here so a shape nobody
/// anticipated ends the walk with [`Map::cap_hit`] set rather than spinning.
const MAX_SWEEPS: usize = 32;

/// Recovers the control codes a dispatch routine accepts.
///
/// `block` is the routine's instructions in listing order — what `uf` produces, and what
/// [`crate::driver::in_listing_order`] guarantees has a barrier wherever one could not be read.
/// `read` serves the image's own bytes for a jump table, and answers `None` for an address that
/// will not read, which ends that table rather than the map. `in_image` says whether an address is
/// code in this driver, which is what a table recognised by accident fails.
pub(crate) fn map(
    dispatch: u64,
    block: &[Instruction],
    layout: Layout,
    read: impl FnMut(u64, usize) -> Option<Vec<u8>>,
    in_image: impl Fn(u64) -> bool,
    halt: impl FnMut() -> Option<Halt>,
) -> Map {
    map_within(dispatch, block, layout, read, in_image, halt, MAX_SWEEPS)
}

/// The same with the sweep budget named, which is how the state **at** that bound is asserted: a
/// routine that exhausts [`MAX_SWEEPS`] is one no fixture here can write down, and the rule about
/// what is reported when the facts never settle should not go untested for that reason.
#[allow(clippy::too_many_arguments)]
fn map_within(
    dispatch: u64,
    block: &[Instruction],
    layout: Layout,
    mut read: impl FnMut(u64, usize) -> Option<Vec<u8>>,
    in_image: impl Fn(u64) -> bool,
    mut halt: impl FnMut() -> Option<Halt>,
    sweeps: usize,
) -> Map {
    let graph = cfg::graph(block);
    let index_of: HashMap<u64, usize> = block
        .iter()
        .enumerate()
        .map(|(index, instruction)| (instruction.address, index))
        .collect();

    let mut halted = None;
    let mut cap_hit = false;

    // The facts on the way **into** each block, which is what the sweeps below settle.
    let mut entry: Vec<Option<Facts>> = vec![None; graph.blocks.len()];
    if !graph.blocks.is_empty() {
        let mut initial = Facts::default();
        // The second argument of a dispatch routine, where the calling convention passes it in a
        // register at all. Believed at the entry block and nowhere else: a block reached from
        // somewhere gets what that path left, which is what a prologue's `mov rbx,rdx` means.
        if let Some(register) = layout.irp_register {
            initial.registers.insert(register.to_string(), Value::Irp);
        }
        entry[0] = Some(initial);
    }

    let order = graph.walk_order();
    let mut unsettled = false;
    for sweep in 0.. {
        if sweep >= sweeps {
            unsettled = true;
            break;
        }
        // Polled per sweep rather than per instruction: a sweep is the unit of work here, and a
        // routine large enough for the clock to matter has many blocks rather than one long one.
        if let Some(why) = halt() {
            halted = Some(why);
            break;
        }
        let mut moved = false;
        for &index in &order {
            let Some(facts) = entry[index].clone() else {
                continue;
            };
            let run = simulate(
                index, &graph, block, &index_of, facts, layout, None, &in_image,
            );
            for (successor, facts) in run.to {
                match &mut entry[successor] {
                    Some(existing) => moved |= existing.join(&facts),
                    slot @ None => {
                        *slot = Some(facts);
                        moved = true;
                    }
                }
            }
        }
        if !moved {
            break;
        }
    }

    // **Facts that have not settled are stronger than the truth, not shorter.** A block's facts
    // start as whatever the first path into it left and are narrowed by every path after, so a
    // sweep budget that runs out leaves beliefs a later edge would have taken away -- a register
    // still holding the control code, a bounds check still standing. Recorded, those are cases and
    // tables no execution produces, which is worse than a short list because nothing about a
    // fabricated case says it is one. So the beliefs go, and what is left is what needed none of
    // them: the transfers that were not followed, and the instructions that would not read.
    //
    // A **halt** needs no equivalent: the recording pass below refuses to start on one, so a walk
    // the clock ended reports nothing at all rather than reporting from where it got to.
    if unsettled {
        entry.iter_mut().for_each(|slot| *slot = None);
    }

    // The recording pass, over facts that have stopped moving. Separate from the sweeps above
    // because a case found twice is a case reported twice, and the sweeps are how many times a
    // block is walked.
    let mut cases: Vec<Case> = Vec::new();
    let mut case_count = 0usize;
    let mut unproved = 0usize;
    let mut tables: Vec<Table> = Vec::new();
    let mut unresolved: Vec<u64> = Vec::new();
    let mut traced = false;
    let mut blind = 0usize;
    let mut examined = 0usize;
    let mut reader = ReadOnce {
        read: &mut read,
        served: 0,
    };
    for &index in &order {
        // Polled per block here as well as per sweep above: the sweeps settle the facts and this
        // is the walk that reads them, so a halt landing between the two would otherwise record
        // the whole routine after the caller had gone.
        if halted.is_some() {
            break;
        }
        if let Some(why) = halt() {
            halted = Some(why);
            break;
        }
        let Some(facts) = entry[index].clone() else {
            // A block no path reaches is still walked for what it *contains* -- a case block
            // selected only by a table is reached by nothing this graph knows -- but with nothing
            // believed about any register, which is the honest state to read it in.
            let run = simulate(
                index,
                &graph,
                block,
                &index_of,
                Facts::default(),
                layout,
                Some(&mut reader),
                &in_image,
            );
            record(
                run,
                &mut cases,
                &mut case_count,
                &mut unproved,
                &mut cap_hit,
                &mut tables,
                &mut unresolved,
                &mut traced,
                &mut blind,
                &mut examined,
            );
            continue;
        };
        let run = simulate(
            index,
            &graph,
            block,
            &index_of,
            facts,
            layout,
            Some(&mut reader),
            &in_image,
        );
        record(
            run,
            &mut cases,
            &mut case_count,
            &mut unproved,
            &mut cap_hit,
            &mut tables,
            &mut unresolved,
            &mut traced,
            &mut blind,
            &mut examined,
        );
    }

    if halted.is_none() {
        // Polled once more after the walk: a halt landing during the last sweep would otherwise
        // leave a map that reads as a routine fully walked.
        halted = halt();
    }

    // What each case's landing block says about it: the routine it reaches, whether the block
    // handles the code or refuses it, and the length checks it makes. Read from the **block** and
    // the facts on the way into it, so a window is never needed and a register's meaning is the
    // one this path gave it.
    //
    // **Asked once per block rather than once per case**: several codes share a landing --
    // `mountmgr` has one that six reach -- and following that block's tail jumps again for each of
    // them is work the target chose the size of.
    //
    // The second half of that key is the jump-table rule above: whether a store is to the IRP's
    // status field is a question about a register, so a case read with nothing believed gets a
    // different answer from one read with the block's own.
    let refusals: std::cell::RefCell<HashMap<(usize, bool), bool>> =
        std::cell::RefCell::new(HashMap::new());
    let refuses_at = |from: usize, blind: bool| {
        let known = refusals.borrow().get(&(from, blind)).copied();
        if let Some(known) = known {
            return known;
        }
        let answer = match graph.holding(from) {
            Some(at) => refuses_in(at, from, &graph, block, layout, &entry, blind),
            None => false,
        };
        refusals.borrow_mut().insert((from, blind), answer);
        answer
    };
    for case in &mut cases {
        // Polled here as well as in the two passes above: this loop is bounded by the case list,
        // which the target decides the length of, and a caller that has gone should not be waited
        // out by work whose answer nobody will read.
        if halted.is_some() {
            break;
        }
        if let Some(why) = halt() {
            halted = Some(why);
            break;
        }
        // **Read from where it lands, not from where its block begins.** A landing is a block's
        // first instruction only when some *edge* goes there, and a jump table's does not -- so
        // two entries into one shared tail both sit inside a block that starts above them, and
        // reading the block whole gives each of them instructions the other's path executes:
        // another case's handler, or a refusal neither reaches.
        let Some(&from) = index_of.get(&case.lands) else {
            continue;
        };
        let Some(at) = graph.holding(from) else {
            continue;
        };
        // **A jump-table case arrives along an edge this graph does not have.** Its blocks and
        // edges are what the *encoding* says, and an indirect `jmp` says nothing about where it
        // goes -- the table said that, and the table was read after the facts had stopped moving.
        // So what is on the way into a landing block is what its **direct** predecessors left,
        // which for a case the table selected is somebody else's path: `mountmgr` has a landing
        // reached by five table entries *and* by a `cmp`, and that compare's path would lend its
        // registers to all five -- a length checked through one of them published as the required
        // size of codes whose path clobbered it. Read with nothing believed instead, which is what
        // this pass already does for a block no edge reaches at all. It costs a table case its
        // sizes; getting them back means feeding the resolved edges into the sweeps and settling
        // the facts again, which is a different change from this one and would move what every
        // block downstream of such a landing believes.
        let facts = match case.recovered {
            Recovery::JumpTable => Facts::default(),
            Recovery::Compare => entry[at].clone().unwrap_or_default(),
        };
        let instructions = &block[from..graph.blocks[at].end];
        case.handler = handler_in(instructions);
        let blind = case.recovered == Recovery::JumpTable;
        let refuses = refuses_at(from, blind);
        case.accepted = match (
            refuses,
            case.handler,
            error_status(instructions, layout, &facts),
        ) {
            (true, _, _) => Some(false),
            (false, Some(_), false) => Some(true),
            _ => None,
        };
        if case.accepted == Some(false) {
            // A rejection has no handler to report: what it reaches is whatever completes the
            // request, and naming that as this code's handler is a name a reader would look up.
            case.handler = None;
        }
        let (input, output) = sizes_in(instructions, &facts, layout, &|address| {
            index_of
                .get(&address)
                .is_some_and(|&from| refuses_at(from, false))
        });
        case.in_size = input;
        case.out_size = output;
    }

    Map {
        dispatch,
        // **Every reported case, not any one load.** A routine that compares some other structure's
        // `+0x18` field and later reads the real control code would otherwise have the first case
        // borrow the second's credibility -- and the first is exactly the one a reader needs
        // warning about. With no cases at all this says whether the code was read, which is what
        // makes an empty answer readable.
        code_proved: traced && unproved == 0,
        unproved,
        cases,
        case_count,
        tables,
        unresolved,
        halted,
        cap_hit,
        unsettled,
        examined,
        blind,
    }
}

/// The image reader, with a count of what it was asked for.
///
/// Handed to one pass rather than to every sweep: a table is read when the answer is recorded, so
/// the number of reads is the number of tables and not the number of times the walk swept.
struct ReadOnce<'a> {
    read: &'a mut dyn FnMut(u64, usize) -> Option<Vec<u8>>,
    served: usize,
}

/// What walking one block produced.
struct Run {
    /// The facts on each edge out of this block.
    to: Vec<(usize, Facts)>,
    /// `(code, lands, site, proved)` for each case this block's terminator recognises.
    cases: Vec<(u64, u64, u64, bool)>,
    /// A jump table this block's terminator was resolved through.
    table: Option<Resolved>,
    /// An indirect transfer this block ends in that was **not** resolved.
    unresolved: Option<u64>,
    /// Whether a control code was traced from the IRP anywhere in this block.
    traced: bool,
    blind: usize,
    examined: usize,
}

/// Folds one block's findings into the answer.
#[allow(clippy::too_many_arguments)]
fn record(
    run: Run,
    cases: &mut Vec<Case>,
    case_count: &mut usize,
    unproved: &mut usize,
    cap_hit: &mut bool,
    tables: &mut Vec<Table>,
    unresolved: &mut Vec<u64>,
    traced: &mut bool,
    blind: &mut usize,
    examined: &mut usize,
) {
    *traced |= run.traced;
    *blind += run.blind;
    *examined += run.examined;
    for (code, lands, site, proved) in run.cases {
        push_case(
            cases,
            case_count,
            unproved,
            cap_hit,
            code,
            Recovery::Compare,
            site,
            lands,
            proved,
        );
    }
    if let Some(resolved) = run.table {
        for (code, lands) in resolved.cases {
            push_case(
                cases,
                case_count,
                unproved,
                cap_hit,
                code,
                Recovery::JumpTable,
                resolved.table.at,
                lands,
                resolved.proved,
            );
        }
        if tables.len() < MAX_TABLES {
            tables.push(resolved.table);
        } else {
            *cap_hit = true;
        }
    }
    if let Some(at) = run.unresolved {
        if unresolved.len() < MAX_UNRESOLVED {
            unresolved.push(at);
        } else {
            *cap_hit = true;
        }
    }
}

/// Walks one block: what its instructions do to the facts, and what its terminator recognises.
///
/// `reader` is `Some` only on the pass that records, so a table is read once however many times the
/// walk sweeps.
#[allow(clippy::too_many_arguments)]
fn simulate(
    index: usize,
    graph: &cfg::Graph,
    listing: &[Instruction],
    index_of: &HashMap<u64, usize>,
    entry: Facts,
    layout: Layout,
    reader: Option<&mut ReadOnce<'_>>,
    in_image: &impl Fn(u64) -> bool,
) -> Run {
    let block = &graph.blocks[index];
    // What the block was entered with, kept for the one thing that needs a register's value at a
    // **position** rather than at the end: a jump table, whose base and image base are read where
    // the code reads them. Only a block that ends in an indirect jump can want it.
    let arrived = graph
        .blocks
        .get(index)
        .and_then(|block| listing.get(block.end.saturating_sub(1)))
        .is_some_and(|last| matches!(last.flow, Flow::Jmp(None)))
        .then(|| entry.clone());
    let mut facts = entry;
    let mut compared: Option<Compared> = None;
    let mut traced = false;
    let mut blind = 0usize;
    let mut cases = Vec::new();
    let mut table = None;
    let mut unresolved = None;

    let instructions = &listing[block.start..block.end];
    let terminator = instructions.len().saturating_sub(1);
    for (position, instruction) in instructions.iter().enumerate() {
        if matches!(instruction.flow, Flow::Unreadable | Flow::Unknown) {
            blind += 1;
        }
        if position == terminator {
            break;
        }
        let next = update(&mut facts, instruction, layout, &mut traced);
        // **A compare survives anything that does not write the flags.** A compiler puts the
        // setup for the case block between the compare and its branch -- `cmp r13d,N` /
        // `mov rbx,rcx` / `je handler` -- and dropping the pending compare there loses the case
        // with nothing saying so: no unresolved transfer, no blind instruction, no stop. Which
        // instructions write flags is the decoder's answer rather than a list of arithmetic
        // mnemonics, so this is the whole rule.
        //
        // **A call is the exception**, and the decoder cannot say otherwise: a callee is free to
        // leave the flags as it likes, so a branch after one is not reading the compare before
        // it. Attributing it to that compare fabricates a case out of two unrelated
        // instructions.
        if matches!(instruction.flow, Flow::Call(_)) {
            compared = None;
        } else if instruction.writes_flags {
            compared = next;
        }
    }

    let last = instructions.last();
    // The terminator reads the flags the block left and decides where control goes.
    if let Some(last) = last {
        match last.flow {
            Flow::Branch(target) => {
                if let (Some(was), Some(condition)) = (compared.as_ref(), last.condition) {
                    match (condition, was.code) {
                        (Condition::Equal, Some(code)) => {
                            if let Some(target) = target {
                                cases.push((code, target, was.at, was.proved));
                            }
                        }
                        (Condition::NotEqual, Some(code)) => {
                            // The branch is the *rejection*, so the case is what follows.
                            if let Some(next) = listing.get(block.end) {
                                cases.push((code, next.address, was.at, was.proved));
                            }
                        }
                        _ => {}
                    }
                }
            }
            Flow::Jmp(None) | Flow::Call(None) if matches!(last.flow, Flow::Jmp(None)) => {
                // Everything **before** the jump: the jump reads the register the chain is walked
                // back from, and taking it for a definition of that register ends the walk at its
                // own first step.
                match arrived.as_ref().and_then(|arrived| {
                    follow_table(
                        &instructions[..terminator],
                        last,
                        arrived,
                        layout,
                        reader,
                        in_image,
                    )
                }) {
                    Some(resolved) => table = Some(resolved),
                    None => unresolved = Some(last.address),
                }
            }
            _ => {
                // A call at the end of a block is ordinary: the block continues after it, and the
                // callee is not this function's edge. Its effect on the registers is the one thing
                // that matters here.
                compared = update(&mut facts, last, layout, &mut traced);
            }
        }
    }

    // The facts on each edge. A bounds check narrows only the path where the index is in range,
    // which is what makes a table's length a fact about the path rather than about the listing.
    let mut to = Vec::new();
    let fall_through = listing
        .get(block.end)
        .and_then(|next| index_of.get(&next.address))
        .and_then(|&at| graph.holding(at));
    let mut carried = facts.clone();
    carried.bound = None;
    if let (Some(last), Some(was)) = (last, compared.as_ref())
        && let (Flow::Branch(target), Some(condition)) = (last.flow, last.condition)
        && matches!(
            condition,
            Condition::UnsignedAbove | Condition::UnsignedAboveOrEqual
        )
        && let (Some((register, offset, shift)), Some(limit)) = (was.index.clone(), was.bound)
        // **A bound is about the register's value from here on, so the register has to still hold
        // what was compared.** The pending compare deliberately outlives a flag-neutral
        // instruction between the `cmp` and its branch -- that is where a compiler puts the case's
        // setup -- but `cmp eax,2` / `mov eax,ecx` / `ja default` leaves a bound describing a value
        // `eax` no longer has, and a table indexed by `eax` is then read to a limit nothing
        // checked. The *case* built from the same compare needs no such thing: a comparison that
        // already happened is what the branch reads, whatever the register holds by then.
        && facts.registers.get(&register)
            == Some(&Value::Code {
                offset,
                shift,
                proved: was.proved,
            })
        && let Some(limit) = match condition {
            Condition::UnsignedAbove => Some(limit),
            _ => limit.checked_sub(1),
        }
    {
        let mut bounded = carried.clone();
        bounded.bound = Some(Bound {
            register,
            offset,
            shift,
            limit,
            // An index past the bound goes where this branch goes, and so does every slot of the
            // table the compiler had no case for.
            default: target,
            proved: was.proved,
        });
        if let Some(fall_through) = fall_through {
            to.push((fall_through, bounded));
        }
        if let Some(taken) = target
            .and_then(|target| index_of.get(&target))
            .and_then(|&at| graph.holding(at))
        {
            to.push((taken, carried.clone()));
        }
    } else {
        // **A bound survives a branch that is about something else.** It is a claim about one
        // register's value, and every way that value can change already takes it away: a write
        // that is not the table pattern, a call over a volatile register, a join with a path that
        // never had it. Clearing it here as well would mean a bounds check only ever reaches the
        // block immediately after it, so a compiler that puts an unrelated test in between leaves
        // a switch unresolved -- an answer reported as a lower bound for no reason in the code.
        for &successor in &graph.blocks[index].successors {
            to.push((successor, facts.clone()));
        }
    }

    Run {
        to,
        cases,
        table,
        unresolved,
        traced,
        blind,
        examined: instructions.len(),
    }
}

/// Records a case, keeping the count exact once the list stops growing.
#[allow(clippy::too_many_arguments)]
fn push_case(
    cases: &mut Vec<Case>,
    count: &mut usize,
    unproved: &mut usize,
    cap_hit: &mut bool,
    code: u64,
    recovered: Recovery,
    site: u64,
    lands: u64,
    proved: bool,
) {
    // A control code is a `ULONG`. A compare against a wider immediate is a compare against
    // something else, whatever register it used.
    let Ok(code) = u32::try_from(code) else {
        return;
    };
    *count += 1;
    // **Every case found, not every case kept.** `code_proved` is about the whole routine and
    // `case_count` stays exact past the cap, so reading provenance off the retained prefix would
    // report a map as wholly traced while counting a case that came from the bare displacement --
    // and counted rather than flagged, because the answer says *how many* and a figure taken from
    // the retained list contradicts the flag it is printed under.
    if !proved {
        *unproved += 1;
    }
    if cases.len() >= MAX_CASES {
        *cap_hit = true;
        return;
    }
    cases.push(Case {
        code,
        recovered,
        site,
        lands,
        proved,
        accepted: None,
        handler: None,
        in_size: None,
        out_size: None,
    });
}

/// The full-width register an operand names, which is the decoder's answer rather than a table's.
fn register_full(operand: &Operand) -> Option<String> {
    match operand {
        Operand::Register(register) => Some(register.full.clone()),
        _ => None,
    }
}

/// The immediate an operand carries, if it carries one.
fn immediate_of(operand: &Operand) -> Option<u64> {
    match operand {
        Operand::Immediate(value) => Some(*value),
        _ => None,
    }
}

/// The state one compare leaves for the branch that reads it.
#[derive(Debug, Clone)]
struct Compared {
    /// The control code the compare is about, when it is about one.
    code: Option<u64>,
    /// Whether the value compared was traced from the IRP rather than taken from a displacement.
    proved: bool,
    /// The register compared and what it held, for a bounds check feeding a jump table.
    index: Option<(String, i64, u32)>,
    /// The bound, when the compare was against an immediate.
    bound: Option<u64>,
    /// Where the compare is.
    at: u64,
}

/// A bounds check that holds on the path carrying it: `cmp index,N` / `ja default`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Bound {
    /// The register checked, by its full-width name.
    register: String,
    /// What it held: `(code - offset) >> shift`. A non-zero shift is what [`follow_table`]
    /// refuses on: the bits it discarded are what would say which code reached a slot.
    offset: i64,
    shift: u32,
    /// The largest index the check admits.
    limit: u64,
    /// Where an index past it goes — the switch's **default**, which is also what every unused
    /// slot of its table holds.
    default: Option<u64>,
    /// Whether the index came from a control code traced to the IRP.
    proved: bool,
}

/// Applies one instruction to the facts, and reports the compare it leaves behind.
fn update(
    facts: &mut Facts,
    instruction: &Instruction,
    layout: Layout,
    traced: &mut bool,
) -> Option<Compared> {
    // A compare writes no register and is the only thing a branch reads.
    if instruction.effect == Effect::Compare {
        return compare(facts, instruction, layout, traced);
    }
    // A call returns over the volatile registers, so a belief about one does not survive it --
    // including a bound whose index is one of them.
    if matches!(instruction.flow, Flow::Call(_)) {
        for volatile in layout.volatile {
            facts.registers.remove(*volatile);
        }
        if facts
            .bound
            .as_ref()
            .is_some_and(|bound| layout.volatile.contains(&bound.register.as_str()))
        {
            facts.bound = None;
        }
    }
    // Neither of these writes a register, and `test` is the other thing that writes only flags.
    if matches!(instruction.effect, Effect::Test | Effect::Push) {
        return None;
    }
    // **An instruction this pass does not model may write more than its first operand.**
    // `xchg eax,r13d` writes both, and clearing only the first leaves a tracked control code in a
    // register that now holds the old `eax` -- reported, when a later `cmp r13d,N` reads it, as a
    // code the driver accepts. Nothing here knows which registers an unmodelled instruction
    // writes, so every register it **names** stops being believed: the conservative reading, and
    // the one that cannot invent a case.
    //
    // It does not reach an **implicit** destination -- `mul ecx` writes `eax` and `edx` and names
    // neither -- and closing that means the decoder saying which registers an instruction writes,
    // which is [glslang/dbgscope#155](https://github.com/glslang/dbgscope/issues/155). A mnemonic
    // table here is the thing this module stopped keeping.
    if instruction.effect == Effect::Other {
        for operand in &instruction.operands {
            let Operand::Register(register) = operand else {
                continue;
            };
            set(facts, &register.full, None);
            if facts
                .bound
                .as_ref()
                .is_some_and(|bound| bound.register == register.full)
            {
                facts.bound = None;
            }
        }
        return None;
    }
    let operands = &instruction.operands;
    let Some(Operand::Register(written)) = operands.first() else {
        // Writes memory, or nothing this models. A store through a register does not change what
        // the register holds, so the facts stand.
        return None;
    };
    let destination = written.full.clone();
    // **A partial write leaves something that is not the value.** `sub ax,2003h` changes sixteen
    // bits of a `ULONG` and leaves the rest of the old code above them, so what the register holds
    // afterwards is neither the code nor the code minus an immediate -- and the `je` after it is a
    // statement about those sixteen bits. Read as the whole value it becomes an exact case for a
    // code nothing compared, and as a bounds check it sizes a table from a number the index may
    // exceed. Every arm below would have to ask this, so it is asked once, here.
    if written.width < FIELD_WIDTH {
        set(facts, &destination, None);
        if facts
            .bound
            .as_ref()
            .is_some_and(|bound| bound.register == destination)
        {
            facts.bound = None;
        }
        return None;
    }
    let held = facts.registers.get(&destination).cloned();
    // The bound goes with the register it was about, unless this is the load that carries it.
    if facts.bound.as_ref().is_some_and(|bound| {
        bound.register == destination && !keeps_a_bound(instruction, &bound.register)
    }) {
        facts.bound = None;
    }

    match instruction.effect {
        Effect::Move | Effect::LoadAddress => {
            // `lea eax,[r13-6DC004h]` is a `sub` that leaves the flags alone, and a compiler emits
            // it exactly where a switch is rebased before its bounds check. Read as an address it
            // is nothing, so without this the table that follows has no index.
            let rebased = match (instruction.effect, operands.get(1)) {
                (Effect::LoadAddress, Some(Operand::Memory(memory))) if memory.index.is_none() => {
                    match memory
                        .base
                        .as_ref()
                        .and_then(|base| facts.registers.get(&base.full))
                    {
                        Some(Value::Code {
                            offset,
                            shift,
                            proved,
                        }) => offset
                            .checked_sub(memory.displacement)
                            .map(|offset| Value::Code {
                                offset,
                                shift: *shift,
                                proved: *proved,
                            }),
                        _ => None,
                    }
                }
                _ => None,
            };
            // **And it is stored only in a register wide enough to hold it.** The guard above is
            // the `ULONG` width, because that is all a destination alone can be asked; what a
            // *pointer* needs is the target's, and `lea eax,[rip+table]` writes four bytes of one
            // -- the decoder still reports the whole address it computed, so the table would be
            // read at an address execution never formed. Asked here rather than in each arm, since
            // it is the value that knows what it needs.
            let value = rebased
                .or_else(|| source_value(facts, instruction, layout, traced))
                .filter(|value| written.width >= value.carried_by(layout));
            set(facts, &destination, value);
        }
        // `sub eax, 6D0034h` rebases the code: the register now holds `code - (offset + K)`, and
        // the `je` that follows is a case for that value rather than for zero.
        Effect::Subtract => match (held, operands.get(1).and_then(immediate_of)) {
            (
                Some(Value::Code {
                    offset,
                    shift,
                    proved,
                }),
                Some(immediate),
            ) => {
                let Some(offset) = offset.checked_add(immediate as i64) else {
                    set(facts, &destination, None);
                    return None;
                };
                set(
                    facts,
                    &destination,
                    Some(Value::Code {
                        offset,
                        shift,
                        proved,
                    }),
                );
                return Some(Compared {
                    code: (shift == 0).then_some(offset as u64),
                    proved,
                    index: Some((destination, offset, shift)),
                    bound: Some(0),
                    at: instruction.address,
                });
            }
            _ => set(facts, &destination, None),
        },
        Effect::Add => match (held, operands.get(1).and_then(immediate_of)) {
            (
                Some(Value::Code {
                    offset,
                    shift,
                    proved,
                }),
                Some(immediate),
            ) => {
                let value = offset
                    .checked_sub(immediate as i64)
                    .map(|offset| Value::Code {
                        offset,
                        shift,
                        proved,
                    });
                set(facts, &destination, value);
            }
            // An `add` of anything else -- a table entry to its base, most often -- leaves a value
            // this does not model.
            _ => set(facts, &destination, None),
        },
        Effect::ShiftRight => match (held, operands.get(1).and_then(immediate_of)) {
            (
                Some(Value::Code {
                    offset,
                    shift,
                    proved,
                }),
                Some(by),
            ) => {
                let value = shift.checked_add(by as u32).map(|shift| Value::Code {
                    offset,
                    shift,
                    proved,
                });
                set(facts, &destination, value);
            }
            _ => set(facts, &destination, None),
        },
        _ => set(facts, &destination, None),
    }
    None
}

/// Whether an instruction leaves a bounds check still describing the register it covered.
///
/// **A bound is about a register's *value*, and a write to that register ends it.** `cmp eax,2` /
/// `ja default` followed by `xor eax,eax` says nothing about what a table indexed by `eax` then
/// selects, and reading it as a bound reports every entry of that table as a code the driver
/// accepts when execution can reach only one.
///
/// One write is exempt, and only while it **reads** the bounded register: MSVC's dense switch
/// loads a **byte map** through the index and leaves the case number in the same register, and
/// the dword table read after it is indexed by that -- so this one write carries the bound
/// forward rather than ending it. Anything else -- an arithmetic adjustment, a copy from
/// elsewhere, a zeroing, a load indexed by something else -- takes it away.
///
/// **The dword table's own load used to be exempt too, and is not.** It does not need to be: the
/// bound is read at that load, before it executes, so what it leaves in the index is nobody's
/// question. Exempt, it carried a bound over `mov rax,qword ptr [foo+rax*4]` -- a scale-4 load
/// that is not a table entry -- and the switch after that was resolved to the slots a check on
/// some earlier value admitted.
///
/// **The `add` that folds an image base into a loaded entry used to be exempt too, and is not.**
/// It happens *after* the load, so the bound it would have to survive is one nothing reads by
/// then: [`follow_table`] asks for the bound that stood **at the load**, which is the only place
/// the index means anything. Exempting it here instead let `cmp eax,2` / `ja default` /
/// `add eax,ecx` / `movsxd rdx,[table+rax*4]` index the table by something unbounded and report
/// its slots as the codes the check admitted.
fn keeps_a_bound(instruction: &Instruction, register: &str) -> bool {
    match instruction.operands.get(1) {
        // A byte per index, read **through** the bounded register and **zero-extended**: the
        // first of the two tables a switch is made of, leaving the case number where the index
        // was. A case number is an index into the second table and cannot be negative, so MSVC
        // emits `movzx` -- and a sign-extending load is not this stage. Accepting one kept a
        // bound that [`follow_table`] then read as though the dword table were indexed by the
        // original values, pairing every code with the wrong target.
        Some(Operand::Memory(memory)) if instruction.effect == Effect::Move => {
            let through = memory
                .index
                .as_ref()
                .is_some_and(|index| index.full == register);
            through && memory.scale == 1 && memory.size.unwrap_or(1) == 1
        }
        _ => false,
    }
}

/// What a `mov`-shaped instruction's source is worth.
fn source_value(
    facts: &Facts,
    instruction: &Instruction,
    layout: Layout,
    traced: &mut bool,
) -> Option<Value> {
    match instruction.operands.get(1)? {
        // **A copy carries the value only if it carries all of it.** `movzx ecx,ax` and a plain
        // `mov cx,ax` both leave two bytes of a `ULONG` behind, and a compare against that is a
        // statement about part of a field reported as one about the field -- a control code whose
        // device type nobody read. The question is the source register's **width**, which the
        // decoder answers because it decoded the register.
        Operand::Register(register) => match instruction.effect {
            Effect::Move | Effect::MoveSigned => facts
                .registers
                .get(&register.full)
                .filter(|value| register.width >= value.carried_by(layout))
                .cloned(),
            _ => None,
        },
        Operand::Memory(memory) => {
            // `lea` takes the address rather than what is at it, which is how a jump table's base
            // reaches a register.
            if instruction.effect == Effect::LoadAddress {
                return memory.address.map(Value::Address);
            }
            // **A field is at a displacement, not at a displacement plus whatever is in a
            // register.** `mov eax,[rbx+rcx*4+18h]` is an array element off a structure this walk
            // happens to know, and reading it as `IoControlCode` publishes an array's contents as
            // proved control codes. Every pattern below names a fixed field, so none of them
            // admits an index.
            if memory.index.is_some() {
                return None;
            }
            let base = memory.base.as_ref().map(|base| base.full.clone());
            let held = base.as_ref().and_then(|base| facts.registers.get(base));
            // **A partial read of a `ULONG` is not the field.** Reported as one it invents the
            // bits nobody read -- a device type out of two bytes of a control code.
            let dword = memory.size == Some(FIELD_WIDTH);
            match (held, memory.displacement) {
                // And a **pointer** has a width of its own: `movzx eax,byte ptr [rdx+0b8h]` reads
                // one byte of the stack location's address, so whatever is in `eax` afterwards is
                // not that pointer -- and a `+0x18` off it would be reported as a control code
                // traced from the IRP.
                (Some(Value::Irp), d)
                    if d == layout.current_stack_location
                        && memory.size == Some(layout.pointer) =>
                {
                    Some(Value::StackLocation)
                }
                (Some(Value::StackLocation), d) if d == layout.control_code && dword => {
                    *traced = true;
                    Some(Value::Code {
                        offset: 0,
                        shift: 0,
                        proved: true,
                    })
                }
                (Some(Value::StackLocation), d) if d == layout.input_length && dword => {
                    Some(Value::InputLength)
                }
                (Some(Value::StackLocation), d) if d == layout.output_length && dword => {
                    Some(Value::OutputLength)
                }
                // The fallback the module doc describes: the control code's displacement off a
                // register whose chain was not followed. Believed, because a listing that starts
                // mid-function or a driver that fetches the stack location in a helper would
                // otherwise answer nothing -- and every case says `proved: false`, which is where
                // that doubt is carried.
                (None, d) if d == layout.control_code && dword && base.is_some() => {
                    Some(Value::Code {
                        offset: 0,
                        shift: 0,
                        proved: false,
                    })
                }
                _ => None,
            }
        }
        _ => None,
    }
}

/// Reads a `cmp`, which is where a case and a bounds check both begin.
fn compare(
    facts: &Facts,
    instruction: &Instruction,
    layout: Layout,
    traced: &mut bool,
) -> Option<Compared> {
    let left = instruction.operands.first()?;
    let bound = instruction.operands.get(1).and_then(immediate_of);

    // `cmp dword ptr [rdx+18h], 222003h` -- the code compared where it lives, with no register in
    // between, which is what a compiler emits for a small switch.
    if let Operand::Memory(_) = left {
        let mut probe = instruction.clone();
        probe.operands = vec![Operand::Immediate(0), left.clone()];
        probe.effect = Effect::Move;
        if let Some(Value::Code {
            offset,
            shift,
            proved,
        }) = source_value(facts, &probe, layout, traced)
            && shift == 0
        {
            return Some(Compared {
                code: bound.map(|value| value.wrapping_add(offset as u64)),
                proved,
                index: None,
                bound,
                at: instruction.address,
            });
        }
        return None;
    }

    // **A narrow compare tests part of the value, and that is not the value.** `cmp r13w,2003h`
    // constrains sixteen bits of a `ULONG` and matches every code sharing them, so reporting it as
    // one exact control code invents the bits it never read -- and as a bounds check it would size
    // a table from a number the index may exceed.
    let Operand::Register(operand) = left else {
        return None;
    };
    if operand.width < FIELD_WIDTH {
        return None;
    }
    let register = operand.full.clone();
    match facts.registers.get(&register)? {
        Value::Code {
            offset,
            shift,
            proved,
        } => Some(Compared {
            // A shifted register is an index into a table, not a code: the low bits the shift
            // dropped are not this compare's to claim. The compare is still reported, because it
            // is the bounds check a jump table needs.
            code: match shift {
                0 => bound.map(|value| value.wrapping_add(*offset as u64)),
                _ => None,
            },
            proved: *proved,
            index: Some((register.clone(), *offset, *shift)),
            bound,
            at: instruction.address,
        }),
        _ => None,
    }
}

impl Value {
    /// How wide a register has to be to still be holding this.
    ///
    /// **Not one answer, because these are not one kind of thing.** The fields are `ULONG`s, and
    /// four bytes of one is the field. A **pointer** is the target's width: `mov ecx,edx` passes a
    /// four-byte test and zero-extends the low half of a kernel address, so what is in `rcx`
    /// afterwards is not the IRP -- and a `+0x18` off it would be published as a control code
    /// traced from one, or a truncated table base would resolve a table at an address execution
    /// never used.
    fn carried_by(self, layout: Layout) -> u32 {
        match self {
            Value::Irp | Value::StackLocation | Value::Address(_) => layout.pointer,
            Value::Code { .. } | Value::InputLength | Value::OutputLength => FIELD_WIDTH,
        }
    }
}

/// Sets or clears one register's value.
fn set(facts: &mut Facts, register: &str, value: Option<Value>) {
    match value {
        Some(value) => {
            facts.registers.insert(register.to_string(), value);
        }
        None => {
            facts.registers.remove(register);
        }
    }
}

/// A table that resolved: the table itself, the `(code, target)` pairs it holds, and whether the
/// index it is read by came from a control code traced to the IRP.
struct Resolved {
    table: Table,
    cases: Vec<(u64, u64)>,
    proved: bool,
}

/// Follows an indirect jump's table, when every part of it was recovered from **this block**.
///
/// Three things have to hold, and each is a way a table is otherwise invented: the load has to
/// define the register the jump reads, the index has to be one a bounds check on this path covered,
/// and every entry has to be code in this image.
///
/// **Every register is read where the code reads it**, and the block's facts at its *jump* answer
/// for none of them. A block is free to reuse a register after the load -- `movsxd rcx,[rbx+rax*4]`
/// / `lea rbx,[rip+another]` / `add rcx,rdx` / `jmp rcx` indexed through the old `rbx` and would be
/// read against the new one, giving a table nobody addressed -- and the **bound** is the same
/// question pointed the other way, since what the block does to the index *after* the load is about
/// the target rather than about the index. So `arrived` is what the block was entered with, and the
/// instructions before a position are replayed onto it to answer for that position.
#[allow(clippy::too_many_arguments)]
fn follow_table(
    instructions: &[Instruction],
    jump: &Instruction,
    arrived: &Facts,
    layout: Layout,
    reader: Option<&mut ReadOnce<'_>>,
    in_image: &impl Fn(u64) -> bool,
) -> Option<Resolved> {
    let reader = reader?;
    let facts_at = |position: usize| {
        let mut replay = arrived.clone();
        let mut traced = false;
        for instruction in instructions.iter().take(position) {
            update(&mut replay, instruction, layout, &mut traced);
        }
        replay
    };

    // **The 32-bit form jumps through the table itself**: `jmp dword ptr [table+eax*4]`, with no
    // register in between and the entry a whole address rather than an offset from the image.
    let ((load, memory, at_load), added) = match jump.operands.first() {
        Some(Operand::Memory(memory))
            if u32::from(memory.scale) == TABLE_ENTRY
                && memory.size == Some(TABLE_ENTRY)
                && memory.index.is_some() =>
        {
            ((jump, memory, instructions.len()), None)
        }
        Some(Operand::Register(register)) => {
            let mut wanted = register.full.clone();
            let mut found = None;
            let mut added: Option<(String, usize)> = None;
            for (position, instruction) in instructions.iter().enumerate().rev() {
                // **A call ends the chain, whatever it names.** A callee returns over the volatile
                // registers, so `mov rax,[table+index*4]` / `call helper` / `jmp rax` jumps to
                // whatever the helper returned -- and the call names no destination operand, so a
                // walk that asks only "what defines this register" steps straight over it and
                // resolves the jump from a load execution overwrote. That reports a table's worth
                // of codes for a jump that goes somewhere else, and takes the jump out of
                // `unresolved` where it belongs.
                if matches!(instruction.flow, Flow::Call(_)) {
                    return None;
                }
                // **An instruction this pass does not model ends the chain if it names the
                // register at all.** `xchg edx,eax` writes `eax` as its *second* operand, so a
                // walk that looks only at the first steps over it and resolves the jump from a
                // load execution overwrote -- the same fault the forward walk had, from the other
                // direction. What an unmodelled instruction did to a register it names is not
                // something this knows, and the answer to that is to stop.
                if instruction.effect == Effect::Other
                    && instruction.operands.iter().any(|operand| {
                        matches!(operand, Operand::Register(register) if register.full == wanted)
                    })
                {
                    return None;
                }
                // **Only an instruction that *defines* the register continues the chain.** A
                // `cmp rcx,[base+rax*4+table]` reads it and writes nothing but the flags, and
                // reading that as the load turns an unrelated array into a table.
                if matches!(
                    instruction.effect,
                    Effect::Compare | Effect::Test | Effect::Push
                ) {
                    continue;
                }
                let Some(Operand::Register(written)) = instruction.operands.first() else {
                    continue;
                };
                if written.full != wanted {
                    continue;
                }
                match instruction.operands.get(1) {
                    // **And it reads a `DWORD`.** The entries are decoded four bytes at a time
                    // whatever the load's width was, so a `mov rax,qword ptr [base+index*4]`
                    // taken for this pattern is read as two halves of one entry and a pair of
                    // addresses nobody computed -- published as codes if they happen to land
                    // inside the image.
                    Some(Operand::Memory(memory))
                        if u32::from(memory.scale) == TABLE_ENTRY
                            && memory.size == Some(TABLE_ENTRY)
                            && memory.index.is_some()
                            && matches!(instruction.effect, Effect::Move | Effect::MoveSigned) =>
                    {
                        found = Some((instruction, memory, position));
                        break;
                    }
                    // `add rcx,rdx` folds the image base into the entry: the value being followed
                    // is still the one in `rcx`. **Which register was added is recorded**, because
                    // that -- and not the load's base -- is what execution adds to every entry.
                    // **Folded at the target's width.** `add eax,ecx` keeps four bytes of an
                    // address the jump then reads eight of, so what the entries are measured from
                    // is not what this computed.
                    Some(Operand::Register(source))
                        if instruction.effect == Effect::Add
                            && written.width >= layout.pointer
                            && source.width >= layout.pointer =>
                    {
                        // **One fold, and not several.** `add rcx,rdx` / `add rcx,r8` makes the
                        // target the sum of the entry and *both*, and keeping one of them
                        // reconstructs addresses nobody computed -- published as cases wherever
                        // they happen to be executable. A compiler emits one; anything else is a
                        // shape this does not follow.
                        if added.is_some() {
                            return None;
                        }
                        added = Some((source.full.clone(), position));
                        continue;
                    }
                    // **And copied at it.** Everything from the `add` to the jump is an *address*,
                    // so `mov edx,ecx` zero-extends the low half of one: the jump goes somewhere
                    // this walk did not compute, and the table's targets are published for it. The
                    // **load** is the exception and is matched above: a table entry really is four
                    // bytes, and `mov eax,[table+rax*4]` really does zero-extend it on purpose.
                    Some(Operand::Register(source))
                        if instruction.effect == Effect::Move
                            && written.width >= layout.pointer
                            && source.width >= layout.pointer =>
                    {
                        wanted = source.full.clone();
                    }
                    _ => return None,
                }
            }
            (found?, added)
        }
        _ => return None,
    };

    // **The bound that matters is the one standing at the load.** That is the only instruction
    // the index means anything to: what a block does to the register afterwards -- folding an
    // image base into the entry it just read, most of all -- is about the *target* and not about
    // the index, while what it does before is exactly what takes the check away.
    let bound = facts_at(at_load).bound.clone()?;
    let index = memory.index.as_ref()?.full.clone();
    if index != bound.register {
        return None;
    }
    // **A shifted index does not say which code reached a slot.** `shr eax,2` throws away two
    // bits, so slot zero is reached by four codes and not one -- and whether the driver accepts
    // all four turns on a check this walk does not follow (`test al,3` / `jne default`). Naming
    // one of them reports three codes as absent that may be accepted, and naming all four reports
    // three as accepted that may be refused. Neither is worth saying, so the jump goes back
    // unresolved and the map says a switch here was not followed. Lifting this means proving the
    // discarded bits, not picking one of the two wrong answers.
    if bound.shift != 0 {
        return None;
    }
    let entries = usize::try_from(bound.limit.checked_add(1)?).ok()?;
    if entries == 0 || entries > MAX_TABLE_ENTRIES {
        return None;
    }

    let table = match memory.base.as_ref() {
        Some(base) => match facts_at(at_load).registers.get(&base.full) {
            Some(Value::Address(address)) => *address,
            _ => return None,
        },
        // An absolute table with no base register at all -- the 32-bit shape.
        None => 0,
    }
    .checked_add_signed(memory.displacement)?;
    let entry_base = match &added {
        Some((register, at_add)) => match facts_at(*at_add).registers.get(register) {
            Some(Value::Address(address)) => Some(*address),
            _ => return None,
        },
        None => None,
    };

    // **MSVC's dense switch has two tables**: a byte per index saying which case it is, then a
    // dword per case holding its RVA. It reuses one register for both, so the dword load's index
    // carries the bounded register's name and none of its meaning unless the byte map is read too.
    // **Before the dword load, because that is the stage it feeds.** Searching the whole block
    // takes a later, unrelated byte load for the first stage -- the target was already in hand by
    // then -- and remaps every code through arbitrary bytes.
    let byte_map = instructions[..at_load.min(instructions.len())]
        .iter()
        .enumerate()
        .rev()
        .find_map(|(position, instruction)| {
            if instruction.effect != Effect::Move {
                return None;
            }
            let written = instruction.operands.first().and_then(register_full)?;
            if written != index {
                return None;
            }
            let Some(Operand::Memory(memory)) = instruction.operands.get(1) else {
                return None;
            };
            (memory.scale == 1 && memory.size.unwrap_or(1) == 1).then_some((memory, position))
        });

    let cases: Vec<usize> = match byte_map {
        Some((map, at_map)) => {
            let at = match map.base.as_ref() {
                Some(base) => match facts_at(at_map).registers.get(&base.full) {
                    Some(Value::Address(address)) => *address,
                    _ => return None,
                },
                None => 0,
            }
            .checked_add_signed(map.displacement)?;
            reader.served += 1;
            let map = (reader.read)(at, entries)?;
            // **A short read is not the map.** A partial dump, or a read that runs into a page
            // that was never captured, comes back with a prefix rather than nothing -- and taking
            // it resolves the table from the indices that did read, leaves the rest absent from
            // `cases`, and still takes the jump out of `unresolved` while `entries` advertises the
            // full bound. An incomplete answer reading as a complete one is the one thing this
            // module refuses to produce, so the table goes back unresolved instead.
            if map.len() != entries {
                return None;
            }
            map.into_iter().map(usize::from).collect()
        }
        None => (0..entries).collect(),
    };
    let dwords = cases.iter().copied().max()?.checked_add(1)?;
    if dwords > MAX_TABLE_ENTRIES {
        return None;
    }
    reader.served += 1;
    let bytes = (reader.read)(table, dwords.checked_mul(TABLE_ENTRY as usize)?)?;
    let rvas = bytes.as_chunks::<4>().0;

    let mut found = Vec::new();
    for (position, case) in cases.iter().enumerate() {
        let entry = u32::from_le_bytes(*rvas.get(*case)?);
        let target = match entry_base {
            // **A sign-extending load makes the entry a signed displacement.** `movsxd rax,dword
            // ptr [table+index*4]` is how a compiler writes a table whose cases sit *before* the
            // base it is measured from, and zero-extending one of those adds four gigabytes --
            // which lands outside the image, so the whole table is refused and its cases are
            // silently lost. Which of the two it is comes from the decoder's own classification
            // of the load rather than from its spelling.
            Some(base) if load.effect == Effect::MoveSigned => {
                base.wrapping_add_signed(i64::from(entry as i32))
            }
            Some(base) => base.wrapping_add(u64::from(entry)),
            None => u64::from(entry),
        };
        // **A slot that goes to the default is not a case.** A dense table covers every index in
        // its range, and a compiler fills the ones it has no case for with the block the bounds
        // check jumps to -- so `mountmgr`'s two 81-entry tables hold 13 codes each.
        if bound.default == Some(target) {
            continue;
        }
        // **Every entry has to be code in this image, or the table is not this table.** A shape
        // that matches by accident reads whatever is at the address it computed and turns it into
        // control codes; one entry outside the image says the bytes are not a jump table.
        if !in_image(target) {
            return None;
        }
        let code = (position as u64).wrapping_add(bound.offset as u64);
        found.push((code, target));
    }
    Some(Resolved {
        table: Table {
            at: jump.address,
            table,
            entries,
            followed: found.len(),
        },
        cases: found,
        proved: bound.proved,
    })
}

/// Whether a block sets an NTSTATUS **error** somewhere that returns it.
///
/// The severity field is the signal rather than a list of codes: the top two bits set is the
/// definition of an error status, so `STATUS_INVALID_DEVICE_REQUEST`, `STATUS_INVALID_PARAMETER`
/// and `STATUS_BUFFER_TOO_SMALL` all answer without being named.
///
/// **Where it goes is the other half, and taking the value alone is how a log line becomes a
/// rejection.** `mov ecx,0C000000Dh` before a tracing call is an *argument*; the same constant in
/// the return register, or stored into the IRP's status field, is the routine refusing the
/// request. So only those two destinations count, and a later write of the return register with
/// anything else takes the finding back -- a block that loads a status and then returns something
/// derived from a call is not refusing here.
fn error_status(instructions: &[Instruction], layout: Layout, arrived: &Facts) -> bool {
    let mut facts = arrived.clone();
    let mut traced = false;
    let mut status = Status::default();
    for instruction in instructions {
        status = status_after(status, instruction, layout, &facts);
        update(&mut facts, instruction, layout, &mut traced);
    }
    status.refusing()
}

/// What one instruction does to the status a block has established so far.
///
/// A fold rather than a rescan, because [`failure_block`] needs the answer **at every position**
/// and asking [`error_status`] for each prefix makes one refusal check cost the square of the
/// block's length -- which a malformed routine chooses.
fn status_after(
    status: Status,
    instruction: &Instruction,
    layout: Layout,
    facts: &Facts,
) -> Status {
    // Which of the two places a dispatch routine's status lives does this write?
    let writes_status = match instruction.operands.first() {
        // The return register, by the full-width name the decoder gives it.
        Some(Operand::Register(register)) if register.full == layout.return_register => Some(false),
        // Or `Irp->IoStatus.Status`, which is the other place a refusal writes one -- and **that
        // field**, not any store. A case that puts an error-looking constant in a stack local or a
        // diagnostic structure and then returns would otherwise be read as refusing the request:
        // the case comes back rejected and its handler is taken away, which is a wrong answer
        // about a code the driver accepts. So the destination has to be a dword at that
        // displacement off a register this walk watched the IRP reach.
        Some(Operand::Memory(memory))
            if memory.index.is_none()
                && memory.size == Some(FIELD_WIDTH)
                && memory.displacement == layout.status_field
                && memory
                    .base
                    .as_ref()
                    .is_some_and(|base| facts.registers.get(&base.full) == Some(&Value::Irp)) =>
        {
            Some(true)
        }
        _ => None,
    };
    let Some(into_the_irp) = writes_status else {
        return status;
    };
    // **Every write to it replaces what is there, and only one shape puts a refusal there.**
    // `mov eax,0C0000010h` / `xor eax,eax` / `ret` returns success, and reading the load alone
    // reports that case as one the driver refuses. So anything that is not a move of a literal
    // takes the finding back rather than leaving it standing.
    //
    // A **call** is the exception and is deliberately not one of these: it writes the return
    // register implicitly and names nothing, and the ordinary rejection calls a completion routine
    // on its way out -- so treating that as a write would stop this recognising the shape it
    // exists for. What that costs is a routine which loads a status, calls something that replaces
    // it, and returns without reloading; compilers reload.
    let refusal = instruction.effect == Effect::Move
        && match instruction.operands.get(1).and_then(immediate_of) {
            Some(value) => u32::try_from(value).is_ok_and(|value| value >> 30 == 0b11),
            // The destination was written with something that is not a literal status: whatever
            // is there now is no longer the refusal that was loaded.
            None => false,
        };
    match into_the_irp {
        true => Status {
            irp: refusal,
            ..status
        },
        false => Status {
            returned: refusal,
            ..status
        },
    }
}

/// Where a dispatch routine's status stands, which is **two** places and not one.
///
/// A refusal can put an error in either, and they are independent: a block that stores one into
/// `Irp->IoStatus.Status`, completes the request and then returns success has refused the code, and
/// folding the two into one flag has the `xor eax,eax` take the IRP's error away with it. The case
/// then reads as accepted, with the completion routine reported as its handler.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Status {
    /// An error literal in the return register, as it stands.
    returned: bool,
    /// An error literal in `Irp->IoStatus.Status`.
    irp: bool,
}

impl Status {
    /// Whether either of them is a refusal.
    fn refusing(self) -> bool {
        self.returned || self.irp
    }
}

/// Whether a block **refuses** the request: it sets an NTSTATUS error where the routine returns
/// it, and returns.
///
/// **The completion call is part of the shape rather than the end of it.** The ordinary rejection
/// stores the status into the IRP and calls a completion routine before returning, so a scan that
/// stopped at the first call would see a block that calls something and report the completion
/// routine as this code's handler.
///
/// It says nothing when it says nothing. A failure that jumps to a shared tail answers `false`
/// here, and [`refuses_in`] is what follows that jump.
fn failure_block(
    instructions: &[Instruction],
    layout: Layout,
    arrived: &Facts,
    incoming: Status,
) -> (bool, Status) {
    // **Read where the store is, not where the block starts.** Whether a destination is
    // `Irp->IoStatus.Status` is a question about a register, and a block is free to reuse one: a
    // `rbx` that arrives holding the IRP and is reassigned to a diagnostic object before the store
    // would otherwise have that store read as a refusal, taking a handler away from a code the
    // driver accepts. Same rule, and same replay, as a jump table's base.
    let mut facts = arrived.clone();
    let mut traced = false;
    let mut status = incoming;
    for instruction in instructions {
        // What the block has established **so far**, which is what says whether the call it is
        // about to make is a completion on the way out or a block doing something else. Asked
        // before the instruction is applied, because a store reads its base as it stands.
        status = status_after(status, instruction, layout, &facts);
        update(&mut facts, instruction, layout, &mut traced);
        match instruction.flow {
            Flow::Return => return (status.refusing(), status),
            // A completion call after the status is part of the rejection; one before it is a
            // block doing something else.
            Flow::Call(_) if status.refusing() => {}
            // **An unconditional tail jump carries the status it established.**
            // `mov eax,0C0000010h` / `jmp common_ret` is one rejection written across two blocks,
            // and starting the next one from nothing loses it -- the shared return block is then
            // reported as this case's handler. Whether that jump is followed at all is
            // [`refuses_in`]'s question; this says what goes with it.
            Flow::Jmp(Some(_)) => return (false, status),
            Flow::Call(_) | Flow::Branch(_) | Flow::Jmp(_) => return (false, Status::default()),
            Flow::Unreadable | Flow::Unknown => return (false, Status::default()),
            Flow::Fallthrough | Flow::Trap => {}
        }
    }
    (false, Status::default())
}

/// Whether the block at `index` **refuses** the request, following the tail jumps a shared
/// epilogue is reached through.
///
/// A case block that is one `jmp shared_error_tail` is the ordinary way to share an
/// invalid-request epilogue, and reading it as a handler presents the error tail as this code's
/// routine. The graph already has that edge, so following it is a lookup rather than a guess --
/// bounded to a few hops, since a chain longer than that is not an epilogue.
fn refuses_in(
    index: usize,
    from: usize,
    graph: &cfg::Graph,
    listing: &[Instruction],
    layout: Layout,
    entry: &[Option<Facts>],
    blind: bool,
) -> bool {
    let mut at = index;
    let mut start = from;
    let mut status = Status::default();
    for hop in 0..3 {
        let block = &graph.blocks[at];
        // The first block is read from the landing, which a jump table's need not be the start
        // of; a tail jump is an edge, so every block after this one is entered at its own.
        let instructions = &listing[start.max(block.start)..block.end];
        // The **first** block is the one a case landed in, and a case the table selected landed
        // there along an edge this graph does not have -- so it is read with nothing believed,
        // exactly as its sizes are. Every hop after that is a tail jump the graph *does* carry, so
        // those blocks are read with what reached them.
        let facts = match blind && hop == 0 {
            true => Facts::default(),
            false => entry.get(at).cloned().flatten().unwrap_or_default(),
        };
        let (refuses, carried) = failure_block(instructions, layout, &facts, status);
        if refuses {
            return true;
        }
        status = carried;
        // Only an unconditional tail jump is followed: a block that decides something is deciding
        // it, and whatever it reaches is not simply this block's answer.
        let tail = instructions
            .last()
            .is_some_and(|last| matches!(last.flow, Flow::Jmp(Some(_))));
        match (tail, block.successors.as_slice()) {
            (true, [next]) => {
                at = *next;
                start = graph.blocks[at].start;
            }
            _ => return false,
        }
    }
    false
}

/// The routine a case block reaches directly, when it reaches one.
fn handler_in(instructions: &[Instruction]) -> Option<u64> {
    for instruction in instructions {
        match instruction.flow {
            Flow::Call(Some(target)) | Flow::Jmp(Some(target)) => return Some(target),
            // A branch means the block is doing its own work before it decides, and whatever it
            // calls after that is not this case's handler.
            Flow::Branch(_) | Flow::Return | Flow::Unreadable | Flow::Unknown => return None,
            _ => {}
        }
    }
    None
}

/// The buffer-length checks a case block makes against a literal.
///
/// Four things have to hold before a compare here is a statement about a buffer, and each is a way
/// an answer would otherwise be invented.
///
/// **The value must be a length.** Either the field read where it lives — a `ULONG` at the stack
/// location's displacement, off a register this path put it in — or a register the walk watched it
/// loaded into, which is what a compiler emits when it tests the same length twice.
///
/// **The field is a `ULONG`**, so a narrower compare constrains part of one and is not its size.
///
/// **The block is the case's own.** A block is where a case's instructions end, so nothing here
/// can inherit the next case's compare.
///
/// **Exact means the path continues on equality *and* the other edge refuses.** `jne` says
/// equality falls through; only the branch target being a refusal says the fall-through is the
/// accepted path. `cmp length,20h` / `jne handler` has the success on the other edge, and
/// `cmp length,0` / `je failure` rejects zero rather than requiring it.
fn sizes_in(
    instructions: &[Instruction],
    entry: &Facts,
    layout: Layout,
    refuses: &impl Fn(u64) -> bool,
) -> (Option<SizeCheck>, Option<SizeCheck>) {
    let mut facts = entry.clone();
    let mut traced = false;
    let mut input = None;
    let mut output = None;
    let mut pending: Option<(Value, u32, u64)> = None;
    for instruction in instructions {
        if instruction.effect == Effect::Compare {
            pending = None;
            let length = match instruction.operands.first() {
                // The field where it lives.
                // At the field's width, off a base this walk watched the stack location reach,
                // and **at a displacement** -- `cmp [rbx+rcx*4+10h],20h` is an array element
                // beside the field, and reported as `InputBufferLength` it publishes an exact
                // size the driver never required.
                Some(Operand::Memory(memory))
                    if memory.size == Some(FIELD_WIDTH)
                        && memory.index.is_none()
                        && memory.base.as_ref().is_some_and(|base| {
                            facts.registers.get(&base.full) == Some(&Value::StackLocation)
                        }) =>
                {
                    match memory.displacement {
                        d if d == layout.input_length => Some(Value::InputLength),
                        d if d == layout.output_length => Some(Value::OutputLength),
                        _ => None,
                    }
                }
                // Or a register the walk watched it loaded into: `mov ecx,[sp+10h]` /
                // `cmp ecx,20h` is the same check with the field in hand, and it is what a
                // compiler emits when the length is tested more than once. At the field's own
                // width, for the reason a control code is: `cmp cx,20h` accepts every length whose
                // low sixteen bits are 32, and publishing that as an exact size of 32 is a
                // requirement the driver does not have.
                Some(Operand::Register(register)) if register.width >= FIELD_WIDTH => {
                    match facts.registers.get(&register.full) {
                        Some(value @ (Value::InputLength | Value::OutputLength)) => Some(*value),
                        _ => None,
                    }
                }
                _ => None,
            };
            if let Some(length) = length
                && let Some(value) = instruction.operands.get(1).and_then(immediate_of)
                && let Ok(value) = u32::try_from(value)
            {
                pending = Some((length, value, instruction.address));
            }
            continue;
        }
        if let Flow::Branch(target) = instruction.flow {
            if let Some((length, value, at)) = pending.take() {
                let exact = instruction.condition == Some(Condition::NotEqual)
                    && target.is_some_and(refuses);
                let check = SizeCheck { value, at, exact };
                match length {
                    Value::InputLength => input = input.or(Some(check)),
                    Value::OutputLength => output = output.or(Some(check)),
                    _ => {}
                }
            }
            continue;
        }
        // Everything else updates the facts, which is what retires a base the block overwrites.
        // The pending compare survives anything that writes no flags, for the reason the block
        // walk's does -- and not a call, for the reason it does not there either.
        update(&mut facts, instruction, layout, &mut traced);
        if instruction.writes_flags || matches!(instruction.flow, Flow::Call(_)) {
            pending = None;
        }
    }
    (input, output)
}

/// A control code taken apart: device type, function, method and required access.
///
/// The same four fields `decode_ioctl` reports for one code, from the same bit layout, as values
/// rather than as a rendering: `DeviceType` is bits 16-31, `RequiredAccess` 14-15, `FunctionCode`
/// 2-13 and `Method` 0-1.
pub(crate) fn decoded(code: u32) -> (u32, u32, &'static str, &'static str) {
    let device_type = (code >> 16) & 0xffff;
    let function = (code >> 2) & 0xfff;
    let method = match code & 0x3 {
        0 => "buffered",
        1 => "in_direct",
        2 => "out_direct",
        _ => "neither",
    };
    let access = match (code >> 14) & 0x3 {
        0 => "any",
        1 => "read",
        2 => "write",
        _ => "read_write",
    };
    (device_type, function, method, access)
}

/// The map as the typed result, with every address turned into a coordinate by `locate`.
pub(crate) fn structured_report(
    found: &Map,
    mut locate: impl FnMut(u64) -> crate::structured::CodeLocation,
) -> crate::structured::IoctlMap {
    use crate::structured;
    let rva_of = |location: &structured::CodeLocation| location.rva.clone();
    structured::IoctlMap {
        // Filled in by the caller, which is the only side that holds the attributor these
        // coordinates came from.
        images: Vec::new(),
        dispatch: locate(found.dispatch),
        code_proved: found.code_proved,
        cases: found
            .cases
            .iter()
            .map(|case| {
                let (device_type, function, method, access) = decoded(case.code);
                let lands = locate(case.lands);
                let handler = case.handler.map(&mut locate);
                let mut evidence = Vec::new();
                for (field, check) in [("input", case.in_size), ("output", case.out_size)] {
                    if let Some(check) = check {
                        evidence.push(structured::LengthCheck {
                            field: field.to_string(),
                            value: check.value,
                            exact: check.exact,
                            at: locate(check.at),
                        });
                    }
                }
                structured::IoctlCase {
                    code: format!("{:#010x}", case.code),
                    device_type,
                    function,
                    method: method.to_string(),
                    required_access: access.to_string(),
                    dispatch_rva: handler.as_ref().and_then(rva_of),
                    case_rva: rva_of(&lands),
                    // Only a proven exact check is a size. The floors are in `evidence` above,
                    // which is where the shared shape puts them and why these are two fields
                    // rather than one with a flag.
                    in_size: case
                        .in_size
                        .filter(|check| check.exact)
                        .map(|check| check.value),
                    out_size: case
                        .out_size
                        .filter(|check| check.exact)
                        .map(|check| check.value),
                    recovered: case.recovered.name().to_string(),
                    proved: case.proved,
                    accepted: case.accepted,
                    at: locate(case.site),
                    evidence,
                }
            })
            .collect(),
        case_count: found.case_count,
        tables: found
            .tables
            .iter()
            .map(|table| structured::JumpTable {
                at: locate(table.at),
                table: structured::addr(table.table),
                entries: table.entries,
                followed: table.followed,
            })
            .collect(),
        unresolved: found.unresolved.iter().map(|at| locate(*at)).collect(),
        stopped: found.halted.map(|halt| match halt {
            Halt::Deadline => crate::structured::WalkHalt::Deadline,
            Halt::Interrupted => crate::structured::WalkHalt::Interrupted,
        }),
        cap_hit: found.cap_hit,
        unproved: found.unproved,
        unsettled: found.unsettled,
        blind: found.blind,
    }
}

/// The map as the tool's text, which is what a reader without a structured client sees.
pub(crate) fn render(report: &crate::structured::IoctlMap) -> String {
    let mut out = String::new();
    let where_ =
        |location: &crate::structured::CodeLocation| match (&location.module, &location.rva) {
            (Some(module), Some(rva)) => format!("{module}+{rva}"),
            _ => location.address.clone(),
        };
    out.push_str(&format!("IOCTL map of {}\n", where_(&report.dispatch)));
    if !report.code_proved {
        out.push_str(&format!(
            "  [!] {} of {} case(s) tested a value taken from a displacement this could not trace \
             back to the IRP, so those compares may be about another structure\n",
            report.unproved, report.case_count
        ));
    }
    if report.cases.is_empty() {
        out.push_str("  No control codes recovered\n");
    } else {
        let listed = if report.case_count > report.cases.len() {
            format!(", first {} listed", report.cases.len())
        } else {
            String::new()
        };
        out.push_str(&format!("  {} code(s){listed}:\n", report.case_count));
        for case in &report.cases {
            out.push_str(&format!(
                "    {}  device 0x{:04x} function 0x{:03x} {} {}  -> {}{}\n",
                case.code,
                case.device_type,
                case.function,
                case.method,
                case.required_access,
                case.dispatch_rva
                    .clone()
                    .or_else(|| case.case_rva.clone())
                    .unwrap_or_else(|| where_(&case.at)),
                // Said where the code says it, and silent where it does not: a block that returns
                // an error status is a code the driver refuses, and one that reaches a routine is
                // a code it handles. Neither is what the compare and the branch alone say.
                match case.accepted {
                    Some(false) => "  [rejected]",
                    Some(true) => "",
                    None => "  [?]",
                },
            ));
            for check in &case.evidence {
                out.push_str(&format!(
                    "        {} length {} {}\n",
                    check.field,
                    if check.exact { "==" } else { "checked against" },
                    check.value
                ));
            }
        }
    }
    for table in &report.tables {
        out.push_str(&format!(
            "  Jump table at {} ({} of {} entries followed) for the switch at {}\n",
            table.table,
            table.followed,
            table.entries,
            where_(&table.at)
        ));
    }
    if !report.unresolved.is_empty() {
        out.push_str(&format!(
            "  [!] {} indirect transfer(s) not followed, so this is a lower bound rather than \
             the set: {}\n",
            report.unresolved.len(),
            report
                .unresolved
                .iter()
                .map(where_)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if let Some(stopped) = &report.stopped {
        out.push_str(&format!(
            "  [!] stopped early ({}), so codes after that point were never read\n",
            match stopped {
                crate::structured::WalkHalt::Deadline => "the call's clock ran out",
                crate::structured::WalkHalt::Interrupted => "interrupted",
            }
        ));
    }
    if report.cap_hit {
        out.push_str("  [!] a bound ended a list early; the counts stay exact\n");
    }
    if report.unsettled {
        out.push_str(
            "  [!] what each block knows never stopped changing, so everything resting on a fact \
             -- every jump table, and every code traced to the IRP -- was discarded rather than \
             reported. Anything listed is what a block said on its own, off a bare displacement, \
             and is unproved. This is a routine no answer was settled about rather than one with \
             no control codes\n",
        );
    }
    if report.blind > 0 {
        out.push_str(&format!(
            "  [!] {} instruction(s) could not be read or decoded, so a compare or a dispatch \
             jump may be in what was missed\n",
            report.blind
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use dbgscope::dbgeng::{MemoryOperand, RegisterOperand};

    const DISPATCH: u64 = 0xfffff803_3e254750;

    /// One instruction as the **decoder** reports it.
    ///
    /// The effect and the condition are spelled out from the mnemonic here because that is where
    /// they come from on a real target — iced answers them, and this module reads the fields
    /// rather than the spelling. A fixture stating them is stating data, like an instruction's
    /// bytes; deriving them from whatever the code under test uses would be the fixture agreeing
    /// with itself.
    fn insn(address: u64, mnemonic: &str, operands: Vec<Operand>, flow: Flow) -> Instruction {
        let effect = match mnemonic {
            "mov" | "movzx" => Effect::Move,
            "movsx" | "movsxd" => Effect::MoveSigned,
            "lea" => Effect::LoadAddress,
            "cmp" => Effect::Compare,
            "test" => Effect::Test,
            "add" => Effect::Add,
            "sub" => Effect::Subtract,
            "shl" | "sal" => Effect::ShiftLeft,
            "shr" | "sar" => Effect::ShiftRight,
            "and" => Effect::BitAnd,
            "or" => Effect::BitOr,
            "xor" => Effect::BitXor,
            "push" => Effect::Push,
            "pop" => Effect::Pop,
            // Every transfer of control, and everything else: `Flow` is what says where control
            // goes, and this says what the operands were done to.
            _ => Effect::Other,
        };
        let condition = match mnemonic {
            "je" | "jz" => Some(Condition::Equal),
            "jne" | "jnz" => Some(Condition::NotEqual),
            "ja" | "jnbe" => Some(Condition::UnsignedAbove),
            "jae" | "jnb" | "jnc" => Some(Condition::UnsignedAboveOrEqual),
            "jb" | "jnae" | "jc" => Some(Condition::UnsignedBelow),
            "jbe" | "jna" => Some(Condition::UnsignedBelowOrEqual),
            "jg" | "jnle" => Some(Condition::SignedGreater),
            "jge" | "jnl" => Some(Condition::SignedGreaterOrEqual),
            "jl" | "jnge" => Some(Condition::SignedLess),
            "jle" | "jng" => Some(Condition::SignedLessOrEqual),
            _ => None,
        };
        Instruction {
            address,
            bytes: String::new(),
            text: String::new(),
            mnemonic: mnemonic.to_string(),
            operands,
            flow,
            privileged: false,
            effect,
            condition,
            writes_flags: matches!(
                effect,
                Effect::Compare
                    | Effect::Test
                    | Effect::Add
                    | Effect::Subtract
                    | Effect::ShiftLeft
                    | Effect::ShiftRight
                    | Effect::BitAnd
                    | Effect::BitOr
                    | Effect::BitXor
            ),
        }
    }

    /// A register as the decoder names it: the printed spelling, and the full-width register it is
    /// part of.
    ///
    /// Spelled out for the same reason the effects above are — on a target it is the decoder's
    /// answer, and it is per bitness, so a fixture that computed it would be sharing whatever the
    /// code under test uses to decide.
    fn named(name: &str) -> RegisterOperand {
        // The width belongs to the spelling, and it is the field a test about a partial read is
        // about: `ax` is two bytes of the same register `eax` gives four of.
        // A numbered register's suffix says its width, and the legacy names say theirs by being
        // themselves. Spelled out because on a target it is the decoder's answer -- and because a
        // test about a **partial** read is about nothing at all if the narrow spelling is not in
        // the family map: the lookup misses, no fact is found, and the assertion passes for a
        // reason that has nothing to do with the width.
        let numbered = name.strip_prefix('r').and_then(|rest| {
            let (digits, suffix) = rest.split_at(rest.len().saturating_sub(1));
            match (
                digits.chars().all(|c| c.is_ascii_digit()) && !digits.is_empty(),
                suffix,
            ) {
                (true, "d") => Some((format!("r{digits}"), 4)),
                (true, "w") => Some((format!("r{digits}"), 2)),
                (true, "b") => Some((format!("r{digits}"), 1)),
                _ => match rest.chars().all(|c| c.is_ascii_digit()) && !rest.is_empty() {
                    true => Some((name.to_string(), 8)),
                    false => None,
                },
            }
        });
        if let Some((full, width)) = numbered {
            return RegisterOperand {
                name: name.to_string(),
                full,
                width,
            };
        }
        let width = match name {
            "al" | "ah" | "bl" | "cl" | "dl" | "sil" | "dil" => 1,
            "ax" | "bx" | "cx" | "dx" | "si" | "di" => 2,
            name if name.starts_with('e') => 4,
            _ => 8,
        };
        let full = match name {
            "rax" | "eax" | "ax" | "al" | "ah" => "rax",
            "rbx" | "ebx" | "bx" | "bl" => "rbx",
            "rcx" | "ecx" | "cx" | "cl" => "rcx",
            "rdx" | "edx" | "dx" | "dl" => "rdx",
            "rsi" | "esi" | "si" | "sil" => "rsi",
            "rdi" | "edi" | "di" | "dil" => "rdi",
            "rbp" | "ebp" => "rbp",
            "rsp" | "esp" => "rsp",
            "rip" | "eip" => "rip",
            other => other,
        };
        RegisterOperand {
            name: name.to_string(),
            full: full.to_string(),
            width,
        }
    }

    fn reg(name: &str) -> Operand {
        Operand::Register(named(name))
    }

    /// A register as the decoder names it **on a 32-bit target**, where a 32-bit spelling is the
    /// whole register: there is no `rax` there, so the full-width name is the name.
    fn named32(name: &str) -> RegisterOperand {
        RegisterOperand {
            name: name.to_string(),
            full: name.to_string(),
            // Every 32-bit spelling these fixtures use is the whole register on that target.
            width: 4,
        }
    }

    fn reg32(name: &str) -> Operand {
        Operand::Register(named32(name))
    }

    /// `[base+displacement]` on a 32-bit target.
    fn mem32(base: &str, displacement: i64) -> Operand {
        Operand::Memory(MemoryOperand {
            size: Some(4),
            segment: None,
            base: Some(named32(base)),
            index: None,
            scale: 1,
            displacement,
            address: None,
        })
    }

    /// `[index*4+displacement]` on a 32-bit target -- the form a switch jumps straight through.
    fn indexed32(index: &str, displacement: i64) -> Operand {
        Operand::Memory(MemoryOperand {
            size: Some(4),
            segment: None,
            base: None,
            index: Some(named32(index)),
            scale: 4,
            displacement,
            address: None,
        })
    }

    fn imm(value: u64) -> Operand {
        Operand::Immediate(value)
    }

    /// `[base+displacement]`, a dword read — the width every field this module reads has.
    fn mem(base: &str, displacement: i64) -> Operand {
        sized(base, displacement, Some(4))
    }

    /// `[base+displacement]` read at a **pointer's** width, which is what a load of the IRP's
    /// stack location is: `mov rax,[rdx+0b8h]` moves eight bytes on this target. Spelled apart
    /// from `mem` because the two widths are the distinction several tests here are about, and a
    /// fixture that gave every load four bytes would make the pointer check unreachable.
    fn pointer(base: &str, displacement: i64) -> Operand {
        sized(base, displacement, Some(8))
    }

    /// The same at a width a caller picks, for the tests about what a partial read is worth.
    fn sized(base: &str, displacement: i64, size: Option<u32>) -> Operand {
        Operand::Memory(MemoryOperand {
            size,
            segment: None,
            base: Some(named(base)),
            index: None,
            scale: 1,
            displacement,
            address: None,
        })
    }

    /// `[base+index*4+displacement]` -- a jump table's load.
    fn indexed(
        base: Option<&str>,
        index: &str,
        displacement: i64,
        address: Option<u64>,
    ) -> Operand {
        Operand::Memory(MemoryOperand {
            size: Some(4),
            segment: None,
            base: base.map(named),
            index: Some(named(index)),
            scale: 4,
            displacement,
            address,
        })
    }

    /// `[base+index*4+displacement]` read at a width the caller picks, for the tests about what a
    /// load that is not a `DWORD` is worth.
    fn indexed_sized(
        base: Option<&str>,
        index: &str,
        displacement: i64,
        size: Option<u32>,
    ) -> Operand {
        Operand::Memory(MemoryOperand {
            size,
            segment: None,
            base: base.map(named),
            index: Some(named(index)),
            scale: 4,
            displacement,
            address: None,
        })
    }

    /// A RIP-relative `lea`'s operand: an address and nothing at run time contributing to it.
    fn at_address(address: u64) -> Operand {
        Operand::Memory(MemoryOperand {
            size: None,
            segment: None,
            base: Some(named("rip")),
            index: None,
            scale: 1,
            displacement: 0,
            address: Some(address),
        })
    }

    /// The prologue every dispatch routine has: the stack location out of the IRP, the control
    /// code out of the stack location.
    fn prologue(at: u64) -> Vec<Instruction> {
        vec![
            insn(
                at,
                "mov",
                vec![reg("rax"), pointer("rdx", 0xb8)],
                Flow::Fallthrough,
            ),
            insn(
                at + 4,
                "mov",
                vec![reg("r13d"), mem("rax", 0x18)],
                Flow::Fallthrough,
            ),
        ]
    }

    fn never() -> Option<Halt> {
        None
    }

    fn unreadable(_: u64, _: usize) -> Option<Vec<u8>> {
        None
    }

    /// The image the fixtures live in. A jump-table entry outside it is what says the bytes were
    /// not a jump table, so the guard is a real range here rather than a closure that says yes.
    const IMAGE_BASE: u64 = 0xfffff803_3e250000;
    const IMAGE_SIZE: u64 = 0x0010_0000;

    fn in_image(address: u64) -> bool {
        (IMAGE_BASE..IMAGE_BASE + IMAGE_SIZE).contains(&address)
    }

    /// A compare chain is the ordinary shape, and each `cmp`/`je` pair is one case.
    #[test]
    fn a_compare_chain_recovers_a_case_per_code() {
        let mut block = prologue(DISPATCH);
        block.extend([
            insn(
                DISPATCH + 8,
                "cmp",
                vec![reg("r13d"), imm(0x6d0008)],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0xe, "je", Vec::new(), Flow::Branch(Some(0x900))),
            insn(
                DISPATCH + 0x14,
                "cmp",
                vec![reg("r13d"), imm(0x6d4020)],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x1a, "je", Vec::new(), Flow::Branch(Some(0x980))),
            insn(DISPATCH + 0x20, "ret", Vec::new(), Flow::Return),
        ]);

        let found = map(DISPATCH, &block, Layout::X64, unreadable, in_image, never);

        assert!(found.code_proved, "the chain from the IRP was followed");
        assert_eq!(
            found
                .cases
                .iter()
                .map(|case| (case.code, case.lands, case.recovered))
                .collect::<Vec<_>>(),
            vec![
                (0x6d0008, 0x900, Recovery::Compare),
                (0x6d4020, 0x980, Recovery::Compare),
            ],
            "{:?}",
            found.cases
        );
        assert_eq!(found.case_count, 2);
    }

    /// `sub eax, 6D0034h` is a compare written as arithmetic, and the codes after it are offset
    /// by what it subtracted.
    ///
    /// Taken from `mountmgr`, where this exact instruction sits in the middle of the chain: a pass
    /// that ignored the `sub` would read the `cmp eax,4` two instructions later as the control
    /// code `0x4`, which is not a code the driver accepts and is not a code at all.
    #[test]
    fn a_rebased_register_is_read_against_what_was_subtracted() {
        let mut block = prologue(DISPATCH);
        block.extend([
            insn(
                DISPATCH + 8,
                "mov",
                vec![reg("eax"), reg("r13d")],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xb,
                "sub",
                vec![reg("eax"), imm(0x6d0034)],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x11, "je", Vec::new(), Flow::Branch(Some(0xa00))),
            insn(
                DISPATCH + 0x17,
                "cmp",
                vec![reg("eax"), imm(4)],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x1a, "je", Vec::new(), Flow::Branch(Some(0xa80))),
            insn(DISPATCH + 0x20, "ret", Vec::new(), Flow::Return),
        ]);

        let found = map(DISPATCH, &block, Layout::X64, unreadable, in_image, never);

        assert_eq!(
            found
                .cases
                .iter()
                .map(|case| (case.code, case.lands))
                .collect::<Vec<_>>(),
            vec![(0x6d0034, 0xa00), (0x6d0038, 0xa80)],
            "the `sub` rebases the register and the `cmp` after it is relative: {:?}",
            found.cases
        );
    }

    /// The compare chain continues past a shared epilogue, because the facts travel along the
    /// **edge** rather than down the listing.
    ///
    /// `uf` prints a function's blocks in sequence, and a compiler puts a shared epilogue in the
    /// middle of a compare chain: `mountmgr` has `pop r13` there, restoring the caller's register,
    /// with the rest of its codes compared in blocks printed after it. A pass reading the listing
    /// straight through loses the control code at that `pop` and reported two of that driver's
    /// seven compare-chain codes.
    ///
    /// The fixture is that shape: the second compare's block is reached by the branch **before**
    /// the epilogue, and the epilogue is printed between them. Nothing but the edge connects the
    /// two, which is what makes this about the edge.
    #[test]
    fn the_chain_continues_past_an_epilogue() {
        let mut block = prologue(DISPATCH);
        block.extend([
            insn(
                DISPATCH + 8,
                "cmp",
                vec![reg("r13d"), imm(0x222003)],
                Flow::Fallthrough,
            ),
            // Not this code: on to the block after the epilogue.
            insn(
                DISPATCH + 0xe,
                "jne",
                Vec::new(),
                Flow::Branch(Some(DISPATCH + 0x20)),
            ),
            // This code: the case block, which falls through to the epilogue.
            insn(
                DISPATCH + 0x14,
                "call",
                vec![Operand::Target(0x5000)],
                Flow::Call(Some(0x5000)),
            ),
            // The shared epilogue, restoring the caller's register on the way out.
            insn(DISPATCH + 0x19, "pop", vec![reg("r13")], Flow::Fallthrough),
            insn(DISPATCH + 0x1b, "ret", Vec::new(), Flow::Return),
            // And the rest of the chain, printed after it and reached from before it.
            insn(
                DISPATCH + 0x20,
                "cmp",
                vec![reg("r13d"), imm(0x222007)],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x26, "je", Vec::new(), Flow::Branch(Some(0x980))),
            insn(DISPATCH + 0x2c, "ret", Vec::new(), Flow::Return),
        ]);

        let found = map(DISPATCH, &block, Layout::X64, unreadable, in_image, never);

        let mut codes: Vec<u32> = found.cases.iter().map(|case| case.code).collect();
        codes.sort_unstable();
        assert_eq!(
            codes,
            vec![0x222003, 0x222007],
            "the compare after the epilogue is still about the control code: {:?}",
            found.cases
        );
    }

    /// A `call` between the load and the compare leaves the register holding whatever the callee
    /// returned, and a compare against that is not a control code.
    ///
    /// The case that makes this visible needs the code in a **volatile** register: in a preserved
    /// one the value really does survive the call, so a pass that forgot nothing would agree with
    /// one that forgets the right registers, and the test would pass on the wrong rule.
    ///
    /// And it needs asserting on **both** targets, because the spellings do not overlap: `eax` is
    /// part of `rax` on x64 and is the whole register on x86, so one target's list applied to the
    /// other forgets nothing whatever. The x86 half is the same routine written for the target
    /// where both arguments arrive on the stack.
    #[test]
    fn a_call_forgets_the_registers_it_may_return_over() {
        let mut block = prologue(DISPATCH);
        block.extend([
            insn(
                DISPATCH + 8,
                "mov",
                vec![reg("eax"), reg("r13d")],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xb,
                "call",
                vec![Operand::Target(0xdead)],
                Flow::Call(Some(0xdead)),
            ),
            insn(
                DISPATCH + 0x10,
                "cmp",
                vec![reg("eax"), imm(0x6d0008)],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x16, "je", Vec::new(), Flow::Branch(Some(0xb00))),
            // The same compare on the callee-saved register the code was read into still counts.
            insn(
                DISPATCH + 0x1c,
                "cmp",
                vec![reg("r13d"), imm(0x6d4020)],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x22, "je", Vec::new(), Flow::Branch(Some(0xb80))),
            insn(DISPATCH + 0x28, "ret", Vec::new(), Flow::Return),
        ]);

        let found = map(DISPATCH, &block, Layout::X64, unreadable, in_image, never);

        assert_eq!(
            found.cases.iter().map(|case| case.code).collect::<Vec<_>>(),
            vec![0x6d4020],
            "`eax` did not survive the call and `r13d` did: {:?}",
            found.cases
        );

        let block32 = vec![
            insn(
                DISPATCH,
                "mov",
                vec![reg32("esi"), mem32("ebp", 0x0c)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 3,
                "mov",
                vec![reg32("edi"), mem32("esi", 0x60)],
                Flow::Fallthrough,
            ),
            // The code into a volatile register, and into a preserved one beside it.
            insn(
                DISPATCH + 6,
                "mov",
                vec![reg32("eax"), mem32("edi", 0x0c)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 9,
                "mov",
                vec![reg32("ebx"), mem32("edi", 0x0c)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xc,
                "call",
                vec![Operand::Target(0xdead)],
                Flow::Call(Some(0xdead)),
            ),
            insn(
                DISPATCH + 0x11,
                "cmp",
                vec![reg32("eax"), imm(0x6d0008)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x17,
                "je",
                Vec::new(),
                Flow::Branch(Some(DISPATCH + 0x30)),
            ),
            insn(
                DISPATCH + 0x1d,
                "cmp",
                vec![reg32("ebx"), imm(0x6d4020)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x23,
                "je",
                Vec::new(),
                Flow::Branch(Some(DISPATCH + 0x40)),
            ),
            insn(DISPATCH + 0x29, "ret", Vec::new(), Flow::Return),
        ];

        let found32 = map(DISPATCH, &block32, Layout::X86, unreadable, in_image, never);

        assert_eq!(
            found32
                .cases
                .iter()
                .map(|case| case.code)
                .collect::<Vec<_>>(),
            vec![0x6d4020],
            "on a 32-bit target the register a call returns over is `eax`, not `rax`: {:?}",
            found32.cases
        );
    }

    /// The evidence lists are bounded as the case list is, and `cap_hit` says one was reached.
    ///
    /// A block has one terminator, so how many jump tables and unresolved transfers a routine has
    /// is the *target's* to decide -- a listing that begins mid-code is indirect jumps all the way
    /// down. Uncapped, `MAX_CASES` bounds the answer and neither of these bounds the payload
    /// carrying it. The cases a table produced are still reported past the cap, because they are
    /// the answer and the table record is evidence for it.
    #[test]
    fn the_table_and_unresolved_lists_are_bounded_too() {
        // One unit: rebase, bound, and a one-entry table jumped through. The bounds check's own
        // branch goes to the *next* unit, which is what keeps every one of them reachable -- a
        // block nothing reaches believes nothing, and a table with no bound is not followed.
        const TABLES: usize = MAX_TABLES + 1;
        const UNIT: u64 = 0x40;
        const FIRST: u64 = DISPATCH + 0x100;
        const TABLE: i64 = 0x20000;
        let unit = |index: usize| {
            let at = FIRST + (index as u64) * UNIT;
            let next = at + UNIT;
            vec![
                insn(at, "mov", vec![reg("eax"), reg("r13d")], Flow::Fallthrough),
                insn(
                    at + 8,
                    "sub",
                    vec![reg("eax"), imm(0x6dc000 + index as u64 * 4)],
                    Flow::Fallthrough,
                ),
                insn(
                    at + 0x10,
                    "cmp",
                    vec![reg("eax"), imm(0)],
                    Flow::Fallthrough,
                ),
                insn(at + 0x18, "ja", Vec::new(), Flow::Branch(Some(next))),
                insn(
                    at + 0x20,
                    "lea",
                    vec![reg("rcx"), at_address(IMAGE_BASE)],
                    Flow::Fallthrough,
                ),
                insn(
                    at + 0x28,
                    "mov",
                    vec![
                        reg("eax"),
                        indexed(Some("rcx"), "rax", TABLE + (index as i64) * 4, None),
                    ],
                    Flow::Fallthrough,
                ),
                insn(
                    at + 0x30,
                    "add",
                    vec![reg("rax"), reg("rcx")],
                    Flow::Fallthrough,
                ),
                insn(at + 0x38, "jmp", vec![reg("rax")], Flow::Jmp(None)),
            ]
        };
        let mut block = prologue(DISPATCH);
        block.push(insn(
            DISPATCH + 8,
            "jmp",
            Vec::new(),
            Flow::Jmp(Some(FIRST)),
        ));
        for index in 0..TABLES {
            block.extend(unit(index));
        }
        // Every table holds one entry, and it lands somewhere in this image that is not the
        // bounds check's own target.
        let read = |at: u64, len: usize| {
            let first = IMAGE_BASE.wrapping_add(TABLE as u64);
            (at >= first && at < first + (TABLES as u64) * 4 && len == 4)
                .then(|| 0x3000u32.to_le_bytes().to_vec())
        };

        let found = map(DISPATCH, &block, Layout::X64, read, in_image, never);

        assert_eq!(found.tables.len(), MAX_TABLES, "the table list stops");
        assert_eq!(
            found.cases.len(),
            TABLES,
            "and the cases the last table produced are still the answer: {}",
            found.cases.len()
        );
        assert!(found.cap_hit, "which the answer says");

        // The other list, on a routine that is nothing but indirect jumps.
        let jumps: Vec<Instruction> = (0..MAX_UNRESOLVED + 8)
            .map(|index| {
                insn(
                    DISPATCH + (index as u64) * 4,
                    "jmp",
                    vec![reg("rax")],
                    Flow::Jmp(None),
                )
            })
            .collect();

        let found = map(DISPATCH, &jumps, Layout::X64, unreadable, in_image, never);

        assert_eq!(
            found.unresolved.len(),
            MAX_UNRESOLVED,
            "the unresolved list stops"
        );
        assert!(found.cap_hit, "which the answer says");
    }

    /// A bounded jump table becomes one case per entry, read out of the image -- and a **shifted**
    /// index is refused rather than guessed at.
    ///
    /// `shr eax,2` throws two bits away, so each slot of the table after it is reached by four
    /// codes rather than one, and which of them the driver accepts turns on a check this walk does
    /// not follow (`test al,3` / `jne default`). Naming one code per slot reports three as absent
    /// that may be accepted; naming all four reports three as accepted that may be refused. So the
    /// jump goes back unresolved, and the map says a switch here was not followed. The two halves
    /// of the fixture differ only by that one instruction, which is what makes this about the
    /// shift -- and the refusal happens before the table is read, which the reader's count is what
    /// says.
    #[test]
    fn a_bounded_jump_table_becomes_a_case_per_entry() {
        const IMAGE: u64 = 0xfffff803_3e250000;
        const TABLE: i64 = 0x9000;
        let block = |shifted: bool| {
            let mut block = prologue(DISPATCH);
            block.extend([
                insn(
                    DISPATCH + 8,
                    "mov",
                    vec![reg("eax"), reg("r13d")],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0xb,
                    "sub",
                    vec![reg("eax"), imm(0x6dc004)],
                    Flow::Fallthrough,
                ),
            ]);
            if shifted {
                block.push(insn(
                    DISPATCH + 0x11,
                    "shr",
                    vec![reg("eax"), imm(2)],
                    Flow::Fallthrough,
                ));
            }
            block.extend([
                insn(
                    DISPATCH + 0x14,
                    "cmp",
                    vec![reg("eax"), imm(2)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x17,
                    "ja",
                    Vec::new(),
                    Flow::Branch(Some(0xfa11)),
                ),
                insn(
                    DISPATCH + 0x1d,
                    "lea",
                    vec![reg("rcx"), at_address(IMAGE)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x24,
                    "mov",
                    vec![reg("eax"), indexed(Some("rcx"), "rax", TABLE, None)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x2b,
                    "add",
                    vec![reg("rax"), reg("rcx")],
                    Flow::Fallthrough,
                ),
                insn(DISPATCH + 0x2e, "jmp", vec![reg("rax")], Flow::Jmp(None)),
            ]);
            block
        };
        let table_at = IMAGE.wrapping_add(TABLE as u64);
        let served = std::cell::Cell::new(0usize);
        let read = |at: u64, len: usize| {
            served.set(served.get() + 1);
            (at == table_at && len == 12).then(|| {
                [0x1000u32, 0x1100, 0x1200]
                    .iter()
                    .flat_map(|rva| rva.to_le_bytes())
                    .collect()
            })
        };

        let found = map(DISPATCH, &block(false), Layout::X64, &read, in_image, never);

        assert_eq!(
            found
                .cases
                .iter()
                .map(|case| (case.code, case.lands, case.recovered))
                .collect::<Vec<_>>(),
            vec![
                (0x6dc004, IMAGE + 0x1000, Recovery::JumpTable),
                (0x6dc005, IMAGE + 0x1100, Recovery::JumpTable),
                (0x6dc006, IMAGE + 0x1200, Recovery::JumpTable),
            ],
            "one code per slot, counting from what was subtracted: {:?}",
            found.cases
        );
        assert_eq!(
            found.tables,
            vec![Table {
                at: DISPATCH + 0x2e,
                table: table_at,
                entries: 3,
                followed: 3,
            }]
        );
        assert!(found.unresolved.is_empty(), "{:?}", found.unresolved);

        served.set(0);
        let shifted = map(DISPATCH, &block(true), Layout::X64, &read, in_image, never);

        assert!(
            shifted.cases.is_empty(),
            "four codes reach each slot and this walk cannot say which: {:?}",
            shifted.cases
        );
        assert!(shifted.tables.is_empty(), "{:?}", shifted.tables);
        assert_eq!(shifted.unresolved, vec![DISPATCH + 0x2e]);
        assert_eq!(served.get(), 0, "the table was not read at all");
    }

    /// MSVC's dense switch has **two** tables, and reading it as one is how a map invents codes.
    ///
    /// A byte per index says which case that index is, and a dword per case holds its RVA --
    /// `movzx eax,byte ptr [rdx+rax+5B90h]` then `mov ecx,dword ptr [rdx+rax*4+5B80h]`, which is
    /// `mountmgr` verbatim. The register is reused for both, so the dword load's index carries the
    /// bounded register's *name* and none of its meaning: a pass matching on the name read that
    /// driver's 81-entry byte map as 81 dword entries and reported 160 control codes it does not
    /// accept. Two indices here select the same case, which is the thing a one-table reading
    /// cannot produce.
    ///
    /// It also pins the `lea eax,[r13-6DC004h]` rebase -- a `sub` that leaves the flags alone,
    /// which is what a compiler emits right before a bounds check.
    #[test]
    fn a_two_table_switch_is_read_through_its_byte_map() {
        const MAP: i64 = 0x5b90;
        const TABLE: i64 = 0x5b80;
        let mut block = prologue(DISPATCH);
        block.extend([
            insn(
                DISPATCH + 8,
                "lea",
                vec![
                    reg("eax"),
                    Operand::Memory(MemoryOperand {
                        size: None,
                        segment: None,
                        base: Some(named("r13")),
                        index: None,
                        scale: 1,
                        displacement: -0x6dc004,
                        address: None,
                    }),
                ],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xf,
                "cmp",
                vec![reg("eax"), imm(4)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x12,
                "ja",
                Vec::new(),
                Flow::Branch(Some(0xfa11)),
            ),
            insn(
                DISPATCH + 0x18,
                "lea",
                vec![reg("rdx"), at_address(IMAGE_BASE)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x1f,
                "movzx",
                vec![
                    reg("eax"),
                    Operand::Memory(MemoryOperand {
                        size: Some(1),
                        segment: None,
                        base: Some(named("rdx")),
                        index: Some(named("rax")),
                        scale: 1,
                        displacement: MAP,
                        address: None,
                    }),
                ],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x27,
                "mov",
                vec![reg("ecx"), indexed(Some("rdx"), "rax", TABLE, None)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x2e,
                "add",
                vec![reg("rcx"), reg("rdx")],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x31, "jmp", vec![reg("rcx")], Flow::Jmp(None)),
        ]);
        let map_at = IMAGE_BASE.wrapping_add(MAP as u64);
        let table_at = IMAGE_BASE.wrapping_add(TABLE as u64);
        let read = |at: u64, len: usize| match (at, len) {
            // Five indices, three cases: 0, 1, 0, 2, 1.
            (a, 5) if a == map_at => Some(vec![0u8, 1, 0, 2, 1]),
            (a, 12) if a == table_at => Some(
                [0x1000u32, 0x2000, 0x3000]
                    .iter()
                    .flat_map(|rva| rva.to_le_bytes())
                    .collect(),
            ),
            _ => None,
        };

        let found = map(DISPATCH, &block, Layout::X64, read, in_image, never);

        assert_eq!(
            found
                .cases
                .iter()
                .map(|case| (case.code, case.lands))
                .collect::<Vec<_>>(),
            vec![
                (0x6dc004, IMAGE_BASE + 0x1000),
                (0x6dc005, IMAGE_BASE + 0x2000),
                (0x6dc006, IMAGE_BASE + 0x1000),
                (0x6dc007, IMAGE_BASE + 0x3000),
                (0x6dc008, IMAGE_BASE + 0x2000),
            ],
            "two indices select one case, which one table cannot do: {:?}",
            found.cases
        );
        assert_eq!(found.tables.len(), 1, "{:?}", found.tables);
        assert!(found.unresolved.is_empty(), "{:?}", found.unresolved);
    }

    /// One entry outside the image refuses the **whole** table.
    ///
    /// The patterns are recognised from a handful of instructions, so a shape that matches by
    /// accident computes an address and reads whatever is there -- string data, a relocation, the
    /// next function -- and every dword of it becomes a control code the driver is reported as
    /// accepting. An entry that is not code in this image says the bytes are not a jump table, and
    /// the answer is then the unresolved jump rather than a partly-filtered table: half a
    /// misidentified table is not half an answer.
    #[test]
    fn a_table_entry_outside_the_image_refuses_the_table() {
        const TABLE: i64 = 0x9000;
        let mut block = prologue(DISPATCH);
        block.extend([
            insn(
                DISPATCH + 8,
                "mov",
                vec![reg("eax"), reg("r13d")],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xb,
                "cmp",
                vec![reg("eax"), imm(2)],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0xe, "ja", Vec::new(), Flow::Branch(Some(0xfa11))),
            insn(
                DISPATCH + 0x14,
                "lea",
                vec![reg("rcx"), at_address(IMAGE_BASE)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x1b,
                "mov",
                vec![reg("eax"), indexed(Some("rcx"), "rax", TABLE, None)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x22,
                "add",
                vec![reg("rax"), reg("rcx")],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x25, "jmp", vec![reg("rax")], Flow::Jmp(None)),
        ]);
        let table_at = IMAGE_BASE.wrapping_add(TABLE as u64);
        let read = |at: u64, len: usize| {
            (at == table_at && len == 12).then(|| {
                // The third entry lands past the end of the image.
                [0x1000u32, 0x2000, (IMAGE_SIZE + 0x1000) as u32]
                    .iter()
                    .flat_map(|rva| rva.to_le_bytes())
                    .collect()
            })
        };

        let found = map(DISPATCH, &block, Layout::X64, read, in_image, never);

        assert!(
            found.cases.is_empty(),
            "not two of three: {:?}",
            found.cases
        );
        assert!(found.tables.is_empty(), "{:?}", found.tables);
        assert_eq!(found.unresolved, vec![DISPATCH + 0x25]);
    }

    /// A slot that goes to the switch's **default** is not a case.
    ///
    /// A dense table covers every index between its bounds, and a compiler fills the ones it has
    /// no case for with the block the bounds check jumps to -- `mountmgr`'s two 81-entry tables
    /// hold 21 codes and 60 rejections each. Reporting those makes an answer look four times
    /// richer than it is and be wrong about three quarters of it: a code the driver rejects,
    /// reported as one it accepts, is exactly what a reader would go and test.
    ///
    /// The default is read off the **bounds check's own branch target**, not inferred from entries
    /// repeating, so a switch whose cases genuinely share a handler keeps both.
    #[test]
    fn a_slot_that_goes_to_the_default_is_not_a_case() {
        const TABLE: i64 = 0x9000;
        const DEFAULT: u64 = IMAGE_BASE + 0x500;
        let mut block = prologue(DISPATCH);
        block.extend([
            insn(
                DISPATCH + 8,
                "mov",
                vec![reg("eax"), reg("r13d")],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xb,
                "sub",
                vec![reg("eax"), imm(0x222000)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x11,
                "cmp",
                vec![reg("eax"), imm(3)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x14,
                "ja",
                Vec::new(),
                Flow::Branch(Some(DEFAULT)),
            ),
            insn(
                DISPATCH + 0x1a,
                "lea",
                vec![reg("rcx"), at_address(IMAGE_BASE)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x21,
                "mov",
                vec![reg("eax"), indexed(Some("rcx"), "rax", TABLE, None)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x28,
                "add",
                vec![reg("rax"), reg("rcx")],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x2b, "jmp", vec![reg("rax")], Flow::Jmp(None)),
        ]);
        let table_at = IMAGE_BASE.wrapping_add(TABLE as u64);
        let read = |at: u64, len: usize| {
            (at == table_at && len == 16).then(|| {
                // Four slots; the second and third are the default the `ja` jumps to, and the
                // first and last are cases. Two of them, so "every slot but one" cannot pass.
                [0x1000u32, 0x500, 0x500, 0x2000]
                    .iter()
                    .flat_map(|rva| rva.to_le_bytes())
                    .collect()
            })
        };

        let found = map(DISPATCH, &block, Layout::X64, read, in_image, never);

        assert_eq!(
            found
                .cases
                .iter()
                .map(|case| (case.code, case.lands))
                .collect::<Vec<_>>(),
            vec![
                (0x222000, IMAGE_BASE + 0x1000),
                (0x222003, IMAGE_BASE + 0x2000),
            ],
            "the two default slots are rejections, not codes: {:?}",
            found.cases
        );
        assert_eq!(
            found.tables,
            vec![Table {
                at: DISPATCH + 0x2b,
                table: table_at,
                entries: 4,
                followed: 2,
            }],
            "the table is four entries long and two of them are cases"
        );
    }

    /// The table load has to **feed the jump**, which is dataflow and not proximity.
    ///
    /// Here the bounded index is used for an ordinary array read a few instructions before a jump
    /// through a register loaded from somewhere else entirely. Taking the nearest scale-4 indexed
    /// load reads that array as the switch table: every dword of it that happens to resolve inside
    /// the image becomes a control code, and the real jump stops being listed as unresolved, so
    /// nothing says the switch was missed. The reader is counted for the same reason the
    /// no-bounds-check test counts it -- what is asserted is that nothing was read at a guessed
    /// address, not merely that the answer came out empty.
    #[test]
    fn a_load_that_does_not_feed_the_jump_is_not_the_table() {
        const TABLE: i64 = 0x9000;
        let mut block = prologue(DISPATCH);
        block.extend([
            insn(
                DISPATCH + 8,
                "mov",
                vec![reg("eax"), reg("r13d")],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xb,
                "sub",
                vec![reg("eax"), imm(0x222000)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x11,
                "cmp",
                vec![reg("eax"), imm(3)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x14,
                "ja",
                Vec::new(),
                Flow::Branch(Some(0xfa11)),
            ),
            insn(
                DISPATCH + 0x1a,
                "lea",
                vec![reg("rcx"), at_address(IMAGE_BASE)],
                Flow::Fallthrough,
            ),
            // An array indexed by the bounded register, into a register the jump never reads.
            insn(
                DISPATCH + 0x21,
                "mov",
                vec![reg("edx"), indexed(Some("rcx"), "rax", TABLE, None)],
                Flow::Fallthrough,
            ),
            // And the jump's own register, from the stack.
            insn(
                DISPATCH + 0x28,
                "mov",
                vec![reg("rbx"), mem("rsp", 0x30)],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x2d, "jmp", vec![reg("rbx")], Flow::Jmp(None)),
        ]);
        let served = std::cell::Cell::new(0usize);
        let read = |_: u64, len: usize| {
            served.set(served.get() + 1);
            Some(vec![0u8; len])
        };

        let found = map(DISPATCH, &block, Layout::X64, read, in_image, never);

        assert!(found.cases.is_empty(), "{:?}", found.cases);
        assert!(found.tables.is_empty(), "{:?}", found.tables);
        assert_eq!(found.unresolved, vec![DISPATCH + 0x2d]);
        assert_eq!(served.get(), 0, "nothing was read");
    }

    /// A 32-bit switch jumps **through** its table, and its entries are whole addresses.
    ///
    /// `jmp dword ptr [eax*4+410000h]` has no register in between and no image base to add, so a
    /// resolver that only knew the 64-bit form left every dense switch on exactly the targets
    /// `Layout::X86` exists to serve unresolved, while reporting the compare chain around it as if
    /// that were the whole answer.
    #[test]
    fn a_32_bit_switch_jumps_through_its_table() {
        const TABLE: i64 = 0x0041_0000;
        const CODE_BASE: u64 = 0x0040_0000;
        let in_image32 = |address: u64| (CODE_BASE..CODE_BASE + 0x2_0000).contains(&address);
        let block = vec![
            insn(
                DISPATCH,
                "mov",
                vec![reg32("esi"), mem32("ebp", 0x0c)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 3,
                "mov",
                vec![reg32("edi"), mem32("esi", 0x60)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 6,
                "mov",
                vec![reg32("eax"), mem32("edi", 0x0c)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 9,
                "sub",
                vec![reg32("eax"), imm(0x222000)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xf,
                "cmp",
                vec![reg32("eax"), imm(2)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x12,
                "ja",
                Vec::new(),
                Flow::Branch(Some(0xfa11)),
            ),
            insn(
                DISPATCH + 0x18,
                "jmp",
                vec![indexed32("eax", TABLE)],
                Flow::Jmp(None),
            ),
        ];
        let read = |at: u64, len: usize| {
            (at == TABLE as u64 && len == 12).then(|| {
                [
                    (CODE_BASE + 0x1000) as u32,
                    (CODE_BASE + 0x1100) as u32,
                    (CODE_BASE + 0x1200) as u32,
                ]
                .iter()
                .flat_map(|address| address.to_le_bytes())
                .collect()
            })
        };

        let found = map(DISPATCH, &block, Layout::X86, read, in_image32, never);

        assert_eq!(
            found
                .cases
                .iter()
                .map(|case| (case.code, case.lands))
                .collect::<Vec<_>>(),
            vec![
                (0x222000, CODE_BASE + 0x1000),
                (0x222001, CODE_BASE + 0x1100),
                (0x222002, CODE_BASE + 0x1200),
            ],
            "the entries are addresses, not offsets from anything: {:?}",
            found.cases
        );
        assert!(found.unresolved.is_empty(), "{:?}", found.unresolved);
    }

    /// An instruction that reads the jump's register is not the load that **defines** it.
    ///
    /// `cmp rcx,[rdx+rax*4+9000h]` has `rcx` as its first operand and writes nothing but the
    /// flags. Treating it as the table load turns an unrelated array into a switch table whenever
    /// its dwords resolve inside the image — and takes the real jump off the unresolved list, so
    /// nothing says the switch was missed. The reader is counted, because what is asserted is that
    /// nothing was read at an address arrived at this way.
    ///
    /// Two checks refuse this independently — the skip for instructions that write only flags, and
    /// the load arm requiring an instruction whose job is to load — so this pins the property and
    /// neither line. Removing both is what makes it fail.
    #[test]
    fn an_instruction_that_only_reads_the_register_is_not_the_load() {
        const TABLE: i64 = 0x9000;
        let mut block = prologue(DISPATCH);
        block.extend([
            insn(
                DISPATCH + 8,
                "mov",
                vec![reg("eax"), reg("r13d")],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xb,
                "sub",
                vec![reg("eax"), imm(0x222000)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x11,
                "cmp",
                vec![reg("eax"), imm(2)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x14,
                "ja",
                Vec::new(),
                Flow::Branch(Some(0xfa11)),
            ),
            insn(
                DISPATCH + 0x1a,
                "lea",
                vec![reg("rdx"), at_address(IMAGE_BASE)],
                Flow::Fallthrough,
            ),
            // Reads `rcx` and the array; defines neither.
            insn(
                DISPATCH + 0x21,
                "cmp",
                vec![reg("rcx"), indexed(Some("rdx"), "rax", TABLE, None)],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x28, "jmp", vec![reg("rcx")], Flow::Jmp(None)),
        ]);
        let served = std::cell::Cell::new(0usize);
        let read = |_: u64, len: usize| {
            served.set(served.get() + 1);
            Some(vec![0u8; len])
        };

        let found = map(DISPATCH, &block, Layout::X64, read, in_image, never);

        assert!(found.cases.is_empty(), "{:?}", found.cases);
        assert_eq!(found.unresolved, vec![DISPATCH + 0x28]);
        assert_eq!(served.get(), 0, "nothing was read");
    }

    /// A block that puts an error status in the **IRP** and completes the request is refusing it.
    ///
    /// That is the ordinary rejection: `mov dword ptr [rbx+30h],0C0000010h` into
    /// `Irp->IoStatus.Status`, a call to the completion routine, and out -- so a call alone is
    /// never read as acceptance, and the routine it calls is not reported as this code's handler.
    ///
    /// **That field, though, and not any store.** A case that puts an error-looking constant in a
    /// stack local or a diagnostic structure and then returns would otherwise come back rejected
    /// with its handler taken away, which is a wrong answer about a code the driver accepts. The
    /// three halves here differ only in where the constant goes: the status field off a register
    /// this walk watched the IRP reach, the `Information` beside it, and a stack slot at the same
    /// displacement off something else.
    #[test]
    fn a_block_that_completes_with_an_error_status_is_a_rejection() {
        let stored = |destination: Operand| {
            let mut block = prologue(DISPATCH);
            block.extend([
                // The IRP into a register the case block still has it in, which is what a
                // dispatch routine's prologue does.
                insn(
                    DISPATCH + 8,
                    "mov",
                    vec![reg("rbx"), reg("rdx")],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0xb,
                    "cmp",
                    vec![reg("r13d"), imm(0x222003)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x11,
                    "je",
                    Vec::new(),
                    Flow::Branch(Some(DISPATCH + 0x40)),
                ),
                insn(DISPATCH + 0x17, "ret", Vec::new(), Flow::Return),
                insn(
                    DISPATCH + 0x40,
                    "mov",
                    vec![destination, imm(0xc000_0010)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x47,
                    "call",
                    vec![Operand::Target(0x7000)],
                    Flow::Call(Some(0x7000)),
                ),
                insn(DISPATCH + 0x4c, "ret", Vec::new(), Flow::Return),
            ]);
            let found = map(DISPATCH, &block, Layout::X64, unreadable, in_image, never);
            assert_eq!(found.cases.len(), 1, "{:?}", found.cases);
            (found.cases[0].accepted, found.cases[0].handler)
        };

        assert_eq!(
            stored(mem("rbx", 0x30)),
            (Some(false), None),
            "the status into the IRP and a completion call is a rejection, and the routine it              completes through is not this code's handler"
        );
        assert_eq!(
            stored(mem("rbx", 0x38)),
            (Some(true), Some(0x7000)),
            "`Information` is not `Status`, so this is a case that reaches a routine"
        );
        assert_eq!(
            stored(mem("rsp", 0x30)),
            (Some(true), Some(0x7000)),
            "and neither is a stack slot at the same displacement off something else"
        );
    }

    /// A **partial** read of the control code is not the control code.
    ///
    /// `movzx eax,word ptr [rax+18h]` inspects the function and method bits and nothing above
    /// them, so a compare after it is a statement about part of the value. Reported as a whole
    /// code it invents a device type out of two bytes nobody read — `0x2003` becomes device
    /// `0x0000`, which is a code no driver has. The same fixture at four bytes wide is the control code:
    /// the only difference between the two is the width, which is what makes this about the width.
    #[test]
    fn a_partial_read_of_the_control_code_is_not_a_case() {
        let block = |width: u32| {
            vec![
                insn(
                    DISPATCH,
                    "mov",
                    vec![reg("rax"), pointer("rdx", 0xb8)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 4,
                    "movzx",
                    vec![
                        reg("eax"),
                        Operand::Memory(MemoryOperand {
                            size: Some(width),
                            segment: None,
                            base: Some(named("rax")),
                            index: None,
                            scale: 1,
                            displacement: 0x18,
                            address: None,
                        }),
                    ],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 8,
                    "cmp",
                    vec![reg("eax"), imm(0x2003)],
                    Flow::Fallthrough,
                ),
                insn(DISPATCH + 0xe, "je", Vec::new(), Flow::Branch(Some(0x900))),
                insn(DISPATCH + 0x14, "ret", Vec::new(), Flow::Return),
            ]
        };

        let partial = map(
            DISPATCH,
            &block(2),
            Layout::X64,
            unreadable,
            in_image,
            never,
        );
        assert!(
            partial.cases.is_empty(),
            "two bytes of a ULONG are not a control code: {:?}",
            partial.cases
        );
        assert!(!partial.code_proved);

        let whole = map(
            DISPATCH,
            &block(4),
            Layout::X64,
            unreadable,
            in_image,
            never,
        );
        assert_eq!(
            whole.cases.iter().map(|case| case.code).collect::<Vec<_>>(),
            vec![0x2003],
            "and four bytes are: {:?}",
            whole.cases
        );
        assert!(whole.code_proved);
    }

    /// A **partial** read of the IRP's stack location does not carry it.
    ///
    /// `movzx eax,byte ptr [rdx+0b8h]` reads one byte of a pointer, so what is in `eax` afterwards
    /// is not the stack location -- and a `+0x18` off it is not the control code reached through
    /// it. The case is still recovered, from the bare displacement the module doc describes, and
    /// that is the whole difference: it says `proved: false`, which is where the doubt is carried.
    /// Believed as a traced chain instead, a code nobody proved is published as one that was.
    #[test]
    fn a_partial_read_of_the_stack_location_is_not_the_stack_location() {
        let block = |width: u32| {
            vec![
                insn(
                    DISPATCH,
                    "mov",
                    vec![reg("rax"), sized("rdx", 0xb8, Some(width))],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 4,
                    "mov",
                    vec![reg("r13d"), mem("rax", 0x18)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 8,
                    "cmp",
                    vec![reg("r13d"), imm(0x222003)],
                    Flow::Fallthrough,
                ),
                insn(DISPATCH + 0xe, "je", Vec::new(), Flow::Branch(Some(0x900))),
                insn(DISPATCH + 0x14, "ret", Vec::new(), Flow::Return),
            ]
        };

        let partial = map(
            DISPATCH,
            &block(1),
            Layout::X64,
            unreadable,
            in_image,
            never,
        );
        assert_eq!(
            partial
                .cases
                .iter()
                .map(|case| (case.code, case.proved))
                .collect::<Vec<_>>(),
            vec![(0x222003, false)],
            "one byte of a pointer is not the pointer: {:?}",
            partial.cases
        );
        assert!(!partial.code_proved);

        let whole = map(
            DISPATCH,
            &block(8),
            Layout::X64,
            unreadable,
            in_image,
            never,
        );
        assert_eq!(
            whole
                .cases
                .iter()
                .map(|case| (case.code, case.proved))
                .collect::<Vec<_>>(),
            vec![(0x222003, true)],
            "and the whole pointer is: {:?}",
            whole.cases
        );
        assert!(whole.code_proved);
    }

    /// A table's entries are offsets from the register the code **adds**, not from the one the
    /// load happened to index against.
    ///
    /// They are the same register in a compiler's own switch, so a resolver reading the memory
    /// operand's base agrees with every real one and disagrees silently with anything else. The
    /// fixture separates them: the load indexes against `rdx` and the `add` folds in `rcx`, which
    /// holds a different image address. Read against `rdx` the entries resolve to addresses that
    /// are still inside the image, so nothing downstream catches it -- the answer is simply wrong
    /// about where every case goes.
    #[test]
    fn a_table_entry_is_an_offset_from_the_register_that_is_added() {
        const TABLE: i64 = 0x9000;
        const OTHER: u64 = IMAGE_BASE + 0x4000;
        let mut block = prologue(DISPATCH);
        block.extend([
            insn(
                DISPATCH + 8,
                "mov",
                vec![reg("eax"), reg("r13d")],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xb,
                "sub",
                vec![reg("eax"), imm(0x222000)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x11,
                "cmp",
                vec![reg("eax"), imm(1)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x14,
                "ja",
                Vec::new(),
                Flow::Branch(Some(0xfa11)),
            ),
            insn(
                DISPATCH + 0x1a,
                "lea",
                vec![reg("rdx"), at_address(IMAGE_BASE)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x21,
                "lea",
                vec![reg("rcx"), at_address(OTHER)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x28,
                "mov",
                vec![reg("eax"), indexed(Some("rdx"), "rax", TABLE, None)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x2f,
                "add",
                vec![reg("rax"), reg("rcx")],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x32, "jmp", vec![reg("rax")], Flow::Jmp(None)),
        ]);
        let table_at = IMAGE_BASE.wrapping_add(TABLE as u64);
        let read = |at: u64, len: usize| {
            (at == table_at && len == 8).then(|| {
                [0x1000u32, 0x2000]
                    .iter()
                    .flat_map(|rva| rva.to_le_bytes())
                    .collect()
            })
        };

        let found = map(DISPATCH, &block, Layout::X64, read, in_image, never);

        assert_eq!(
            found
                .cases
                .iter()
                .map(|case| (case.code, case.lands))
                .collect::<Vec<_>>(),
            vec![(0x222000, OTHER + 0x1000), (0x222001, OTHER + 0x2000)],
            "against `rcx`, which is what the `add` uses: {:?}",
            found.cases
        );
    }

    /// A stack-location register stops counting once the case block writes to it.
    ///
    /// The set is read at the top of the dispatch chain, and a case is free to put something else
    /// in `rax` before comparing `[rax+10h]` -- a field of another structure entirely, which a
    /// `jne` to a failure block would otherwise promote to an exact input length. The second case
    /// in the fixture does not overwrite it, so the assertion is about the write and not about
    /// the fixture.
    #[test]
    fn a_clobbered_base_is_no_longer_the_stack_location() {
        let mut block = prologue(DISPATCH);
        block.extend([
            insn(
                DISPATCH + 8,
                "cmp",
                vec![reg("r13d"), imm(0x222003)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xe,
                "je",
                Vec::new(),
                Flow::Branch(Some(DISPATCH + 0x40)),
            ),
            insn(
                DISPATCH + 0x14,
                "cmp",
                vec![reg("r13d"), imm(0x222007)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x1a,
                "je",
                Vec::new(),
                Flow::Branch(Some(DISPATCH + 0x60)),
            ),
            insn(DISPATCH + 0x20, "ret", Vec::new(), Flow::Return),
            // `rax` held the stack location at the top of the routine; this case puts something
            // else in it first.
            insn(
                DISPATCH + 0x40,
                "mov",
                vec![reg("rax"), mem("rbx", 0x8)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x44,
                "cmp",
                vec![mem("rax", 0x10), imm(0x20)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x4b,
                "jne",
                Vec::new(),
                Flow::Branch(Some(DISPATCH + 0x80)),
            ),
            insn(DISPATCH + 0x51, "ret", Vec::new(), Flow::Return),
            // And one that compares the same field without touching the register.
            insn(
                DISPATCH + 0x60,
                "cmp",
                vec![mem("rax", 0x10), imm(0x40)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x67,
                "jne",
                Vec::new(),
                Flow::Branch(Some(DISPATCH + 0x80)),
            ),
            insn(DISPATCH + 0x6d, "ret", Vec::new(), Flow::Return),
            // The failure tail both branch to.
            insn(
                DISPATCH + 0x80,
                "mov",
                vec![reg("eax"), imm(0xc000_000d)],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x85, "ret", Vec::new(), Flow::Return),
        ]);

        let found = map(DISPATCH, &block, Layout::X64, unreadable, in_image, never);

        assert_eq!(
            found
                .cases
                .iter()
                .map(|case| (case.code, case.in_size.map(|size| size.value)))
                .collect::<Vec<_>>(),
            vec![(0x222003, None), (0x222007, Some(0x40))],
            "the overwritten base is not the stack location any more: {:?}",
            found.cases
        );
    }

    /// A fact that is not on **every** path into a block is not a fact there.
    ///
    /// One path leaves the control code in `r13d` and the other overwrites it, so at the block
    /// they both reach the register holds neither — and a compare there is a compare against
    /// something unknown. A walk that kept whichever value it saw last would report it as a
    /// control code, which is the straight-line reading of a listing that has two ways in.
    ///
    /// The second half of the fixture is the same block reached from one path only, so what is
    /// asserted is the join rather than the compare: the same instructions, one edge fewer, do
    /// produce a case.
    #[test]
    fn a_fact_on_one_path_is_not_a_fact_at_the_join() {
        let joined = |overwrite: bool| {
            let mut block = prologue(DISPATCH);
            block.extend([
                insn(
                    DISPATCH + 8,
                    "test",
                    vec![reg("al"), reg("al")],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0xa,
                    "je",
                    Vec::new(),
                    Flow::Branch(Some(DISPATCH + 0x20)),
                ),
                // The other path through: it puts something else in the register, or does not.
                insn(
                    DISPATCH + 0x10,
                    if overwrite { "mov" } else { "nop" },
                    if overwrite {
                        vec![reg("r13d"), mem("rbx", 0x40)]
                    } else {
                        Vec::new()
                    },
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x16,
                    "jmp",
                    Vec::new(),
                    Flow::Jmp(Some(DISPATCH + 0x20)),
                ),
                // Reached from both.
                insn(
                    DISPATCH + 0x20,
                    "cmp",
                    vec![reg("r13d"), imm(0x222003)],
                    Flow::Fallthrough,
                ),
                insn(DISPATCH + 0x26, "je", Vec::new(), Flow::Branch(Some(0x900))),
                insn(DISPATCH + 0x2c, "ret", Vec::new(), Flow::Return),
            ]);
            map(DISPATCH, &block, Layout::X64, unreadable, in_image, never)
        };

        assert!(
            joined(true).cases.is_empty(),
            "one path overwrote the register: {:?}",
            joined(true).cases
        );
        assert_eq!(
            joined(false)
                .cases
                .iter()
                .map(|case| case.code)
                .collect::<Vec<_>>(),
            vec![0x222003],
            "and with both paths agreeing it is the control code: {:?}",
            joined(false).cases
        );
    }

    /// A bounds check holds on the path it **admits**, and not on the one it rejects.
    ///
    /// `cmp index,N` / `ja default` says nothing about the index on the branch it takes — that is
    /// the path where the index is out of range. A walk that carried the bound to both successors
    /// would let a table be read at the default's block, which is the one place the index is known
    /// *not* to be in range.
    #[test]
    fn a_bound_rides_the_edge_it_admits() {
        const TABLE: i64 = 0x9000;
        let mut block = prologue(DISPATCH);
        block.extend([
            insn(
                DISPATCH + 8,
                "mov",
                vec![reg("eax"), reg("r13d")],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xb,
                "sub",
                vec![reg("eax"), imm(0x222000)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x11,
                "cmp",
                vec![reg("eax"), imm(1)],
                Flow::Fallthrough,
            ),
            // Out of range: to the block below, which has a table-shaped tail of its own.
            insn(
                DISPATCH + 0x14,
                "ja",
                Vec::new(),
                Flow::Branch(Some(DISPATCH + 0x30)),
            ),
            insn(DISPATCH + 0x1a, "ret", Vec::new(), Flow::Return),
            // The default's block: the same instructions a resolved switch has, on the one path
            // where the index is known to be out of range.
            insn(
                DISPATCH + 0x30,
                "lea",
                vec![reg("rcx"), at_address(IMAGE_BASE)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x37,
                "mov",
                vec![reg("eax"), indexed(Some("rcx"), "rax", TABLE, None)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x3e,
                "add",
                vec![reg("rax"), reg("rcx")],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x41, "jmp", vec![reg("rax")], Flow::Jmp(None)),
        ]);
        let served = std::cell::Cell::new(0usize);
        let read = |_: u64, len: usize| {
            served.set(served.get() + 1);
            Some(vec![0u8; len])
        };

        let found = map(DISPATCH, &block, Layout::X64, read, in_image, never);

        assert!(found.cases.is_empty(), "{:?}", found.cases);
        assert_eq!(found.unresolved, vec![DISPATCH + 0x41]);
        assert_eq!(served.get(), 0, "nothing was read on the rejected path");
    }

    /// A compare survives anything that writes no flags.
    ///
    /// A compiler puts the case block's setup between the compare and its branch — `cmp r13d,N` /
    /// `mov rbx,rcx` / `je handler` — and the branch still reads the compare's flags. Dropping the
    /// pending compare there loses the case with nothing saying so: no unresolved transfer, no
    /// blind instruction, no stop, just a map one code shorter than the driver.
    ///
    /// Which instructions write flags is the **decoder's** answer, so the second half of the
    /// fixture puts an `add` in the same place: that one does replace the compare, and the case
    /// goes with it.
    #[test]
    fn a_compare_survives_an_instruction_that_writes_no_flags() {
        let between = |mnemonic: &str| {
            let mut block = prologue(DISPATCH);
            block.extend([
                insn(
                    DISPATCH + 8,
                    "cmp",
                    vec![reg("r13d"), imm(0x222003)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0xe,
                    mnemonic,
                    vec![reg("rbx"), reg("rcx")],
                    Flow::Fallthrough,
                ),
                insn(DISPATCH + 0x11, "je", Vec::new(), Flow::Branch(Some(0x900))),
                insn(DISPATCH + 0x17, "ret", Vec::new(), Flow::Return),
            ]);
            map(DISPATCH, &block, Layout::X64, unreadable, in_image, never)
        };

        assert_eq!(
            between("mov")
                .cases
                .iter()
                .map(|case| case.code)
                .collect::<Vec<_>>(),
            vec![0x222003],
            "a copy leaves the flags alone: {:?}",
            between("mov").cases
        );
        assert!(
            between("add").cases.is_empty(),
            "and an `add` is what the branch would then be reading: {:?}",
            between("add").cases
        );
    }

    /// An error status in an **argument** is not a refusal.
    ///
    /// `mov ecx,0C000000Dh` before a logging call is a constant on its way into a callee; the same
    /// value in the return register is the routine refusing the request. Taking the value alone
    /// marks the case rejected and takes its handler away, so a code the driver serves is reported
    /// as one it refuses and the routine that serves it is not named.
    #[test]
    fn an_error_status_in_an_argument_is_not_a_refusal() {
        let case_block = |destination: &str| {
            let mut block = prologue(DISPATCH);
            block.extend([
                insn(
                    DISPATCH + 8,
                    "cmp",
                    vec![reg("r13d"), imm(0x222003)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0xe,
                    "je",
                    Vec::new(),
                    Flow::Branch(Some(DISPATCH + 0x40)),
                ),
                insn(DISPATCH + 0x14, "ret", Vec::new(), Flow::Return),
                insn(
                    DISPATCH + 0x40,
                    "mov",
                    vec![reg(destination), imm(0xc000_000d)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x45,
                    "call",
                    vec![Operand::Target(0x7000)],
                    Flow::Call(Some(0x7000)),
                ),
                insn(DISPATCH + 0x4a, "ret", Vec::new(), Flow::Return),
            ]);
            map(DISPATCH, &block, Layout::X64, unreadable, in_image, never)
        };

        let argument = case_block("ecx");
        assert_eq!(argument.cases.len(), 1, "{:?}", argument.cases);
        assert_eq!(
            (argument.cases[0].accepted, argument.cases[0].handler),
            (Some(true), Some(0x7000)),
            "a constant on its way into a callee: {:?}",
            argument.cases[0]
        );

        let returned = case_block("eax");
        assert_eq!(
            (returned.cases[0].accepted, returned.cases[0].handler),
            (Some(false), None),
            "and the same value where the routine returns from: {:?}",
            returned.cases[0]
        );
    }

    /// A length check may be made against the field once it is **in a register** -- at the
    /// field's own width.
    ///
    /// `mov ecx,[sp+10h]` / `cmp ecx,20h` is the same check as comparing the field where it lives,
    /// and it is what a compiler emits when the length is tested more than once. Reading only the
    /// memory form drops it, and a case that does require an exact size then reports none.
    ///
    /// `cmp cx,20h` is not that check: it accepts every length whose low sixteen bits are 32 --
    /// 0x10020 among them -- so publishing an exact size of 32 states a requirement the driver
    /// does not have, and a caller sizing a buffer from it is refused by the driver it was
    /// obeying. The two halves differ only in the spelling of the register, which is what makes
    /// this about the width.
    #[test]
    fn a_length_check_may_be_made_against_the_loaded_field() {
        let block = |compared: &str| {
            let mut block = prologue(DISPATCH);
            block.extend([
                insn(
                    DISPATCH + 8,
                    "cmp",
                    vec![reg("r13d"), imm(0x222003)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0xe,
                    "je",
                    Vec::new(),
                    Flow::Branch(Some(DISPATCH + 0x40)),
                ),
                insn(DISPATCH + 0x14, "ret", Vec::new(), Flow::Return),
                // The field into a register, then the compare against it.
                insn(
                    DISPATCH + 0x40,
                    "mov",
                    vec![reg("ecx"), mem("rax", 0x10)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x43,
                    "cmp",
                    vec![reg(compared), imm(0x20)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x46,
                    "jne",
                    Vec::new(),
                    Flow::Branch(Some(DISPATCH + 0x60)),
                ),
                insn(
                    DISPATCH + 0x4c,
                    "call",
                    vec![Operand::Target(0x5000)],
                    Flow::Call(Some(0x5000)),
                ),
                insn(DISPATCH + 0x51, "ret", Vec::new(), Flow::Return),
                // The refusal the check's other edge reaches.
                insn(
                    DISPATCH + 0x60,
                    "mov",
                    vec![reg("eax"), imm(0xc000_0023)],
                    Flow::Fallthrough,
                ),
                insn(DISPATCH + 0x65, "ret", Vec::new(), Flow::Return),
            ]);
            block
        };

        let found = map(
            DISPATCH,
            &block("ecx"),
            Layout::X64,
            unreadable,
            in_image,
            never,
        );

        assert_eq!(found.cases.len(), 1, "{:?}", found.cases);
        assert_eq!(
            found.cases[0].in_size.map(|size| (size.value, size.exact)),
            Some((0x20, true)),
            "{:?}",
            found.cases[0]
        );

        let narrow = map(
            DISPATCH,
            &block("cx"),
            Layout::X64,
            unreadable,
            in_image,
            never,
        );

        assert_eq!(narrow.cases.len(), 1, "{:?}", narrow.cases);
        assert_eq!(
            narrow.cases[0].in_size, None,
            "two bytes of a ULONG are not the length: {:?}",
            narrow.cases[0]
        );
    }

    /// A landing block shared by a compare and a table lends its facts to the compare **only**.
    ///
    /// `mountmgr` has one: a block five table entries and one `cmp` all reach. The graph has the
    /// compare's edge and not the table's -- an indirect `jmp` says nothing about where it goes,
    /// and the table that does say was read after the facts had stopped moving -- so what is on
    /// the way into that block is the compare path's registers. Here that path still holds the IO
    /// stack location in `rax` while the switch path overwrites `rax` with the jump target, so a
    /// `cmp [rax+10h],20h` in the shared block is a length check on one path and an unknown
    /// register's field on the other. Read for both, it publishes an exact input size for codes
    /// whose own path proves nothing about it -- and a caller sizing a buffer from it is refused
    /// by the driver it was obeying.
    #[test]
    fn a_table_case_does_not_inherit_the_facts_of_a_compare_that_shares_its_landing() {
        const TABLE: i64 = 0x9000;
        const SHARED: u64 = DISPATCH + 0x80;
        const OTHER: u64 = DISPATCH + 0xa0;
        const REFUSE: u64 = DISPATCH + 0xc0;
        let mut block = prologue(DISPATCH);
        block.extend([
            insn(
                DISPATCH + 8,
                "cmp",
                vec![reg("r13d"), imm(0x222003)],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0xe, "je", Vec::new(), Flow::Branch(Some(SHARED))),
            // The switch, which takes `rax` for the jump target and so knows nothing about the
            // stack location by the time it arrives.
            insn(
                DISPATCH + 0x14,
                "mov",
                vec![reg("eax"), reg("r13d")],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x17,
                "sub",
                vec![reg("eax"), imm(0x6dc004)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x1d,
                "cmp",
                vec![reg("eax"), imm(1)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x20,
                "ja",
                Vec::new(),
                Flow::Branch(Some(0xfa11)),
            ),
            insn(
                DISPATCH + 0x26,
                "lea",
                vec![reg("rcx"), at_address(IMAGE_BASE)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x2d,
                "mov",
                vec![reg("eax"), indexed(Some("rcx"), "rax", TABLE, None)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x34,
                "add",
                vec![reg("rax"), reg("rcx")],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x37, "jmp", vec![reg("rax")], Flow::Jmp(None)),
            // The shared landing: the compare's case and the table's first entry both arrive.
            insn(
                SHARED,
                "cmp",
                vec![mem("rax", 0x10), imm(0x20)],
                Flow::Fallthrough,
            ),
            insn(SHARED + 6, "jne", Vec::new(), Flow::Branch(Some(REFUSE))),
            insn(
                SHARED + 0xc,
                "call",
                vec![Operand::Target(0x5000)],
                Flow::Call(Some(0x5000)),
            ),
            insn(SHARED + 0x11, "ret", Vec::new(), Flow::Return),
            // The table's second entry, so the table is a table rather than one slot.
            insn(
                OTHER,
                "call",
                vec![Operand::Target(0x6000)],
                Flow::Call(Some(0x6000)),
            ),
            insn(OTHER + 5, "ret", Vec::new(), Flow::Return),
            // What the length check's other edge reaches, which is what makes it exact.
            insn(
                REFUSE,
                "mov",
                vec![reg("eax"), imm(0xc000_0023)],
                Flow::Fallthrough,
            ),
            insn(REFUSE + 5, "ret", Vec::new(), Flow::Return),
        ]);
        let table_at = IMAGE_BASE.wrapping_add(TABLE as u64);
        let read = |at: u64, len: usize| {
            (at == table_at && len == 8).then(|| {
                [SHARED - IMAGE_BASE, OTHER - IMAGE_BASE]
                    .iter()
                    .flat_map(|rva| (*rva as u32).to_le_bytes())
                    .collect()
            })
        };

        let found = map(DISPATCH, &block, Layout::X64, read, in_image, never);

        assert_eq!(
            found
                .cases
                .iter()
                .map(|case| (
                    case.code,
                    case.recovered,
                    case.lands,
                    case.in_size.map(|size| (size.value, size.exact))
                ))
                .collect::<Vec<_>>(),
            vec![
                (0x222003, Recovery::Compare, SHARED, Some((0x20, true))),
                (0x6dc004, Recovery::JumpTable, SHARED, None),
                (0x6dc005, Recovery::JumpTable, OTHER, None),
            ],
            "the compare proved the length and the table entry beside it proved nothing: {:?}",
            found.cases
        );
    }

    /// A **partial** write leaves a register holding something that is neither value.
    ///
    /// `sub ax,2003h` changes sixteen bits of a `ULONG` and leaves the old code above them, so the
    /// `je` after it is a statement about those sixteen bits and not about a control code. Applied
    /// to the whole tracked value it becomes an exact case for a code nothing compared -- and the
    /// same arithmetic at the register's full width is the rebase a compiler really emits, which
    /// is what makes this about the width rather than about the `sub`.
    #[test]
    fn a_partial_write_does_not_carry_the_control_code() {
        let rebased = |spelling: &str| {
            let mut block = prologue(DISPATCH);
            block.extend([
                insn(
                    DISPATCH + 8,
                    "mov",
                    vec![reg("eax"), reg("r13d")],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0xb,
                    "sub",
                    vec![reg(spelling), imm(0x2003)],
                    Flow::Fallthrough,
                ),
                insn(DISPATCH + 0x11, "je", Vec::new(), Flow::Branch(Some(0x900))),
                insn(DISPATCH + 0x17, "ret", Vec::new(), Flow::Return),
            ]);
            map(DISPATCH, &block, Layout::X64, unreadable, in_image, never)
        };

        assert!(
            rebased("ax").cases.is_empty(),
            "sixteen bits of a rebased code are not a code: {:?}",
            rebased("ax").cases
        );
        assert_eq!(
            rebased("eax")
                .cases
                .iter()
                .map(|case| case.code)
                .collect::<Vec<_>>(),
            vec![0x2003],
            "and the whole width of it is: {:?}",
            rebased("eax").cases
        );
    }

    /// A **call** between a table's load and its jump ends the chain.
    ///
    /// A callee returns over the volatile registers, so `mov ebx,[table+index*4]` / `call helper`
    /// / `jmp rbx` goes wherever the helper returned -- and a call names no destination operand,
    /// so a walk asking only "what defines this register" steps over it and resolves the jump from
    /// a load execution overwrote, reporting a table's worth of codes for a jump that goes
    /// somewhere else.
    ///
    /// The index is `rbx` rather than `rax` deliberately: a volatile index has its **bound** taken
    /// away by the call already, so the table would be refused for a reason that has nothing to do
    /// with the chain and this test would pass without the rule it is for.
    #[test]
    fn a_call_between_the_load_and_the_jump_ends_the_chain() {
        const TABLE: i64 = 0x9000;
        let with_call = |called: bool| {
            let mut block = prologue(DISPATCH);
            block.extend([
                insn(
                    DISPATCH + 8,
                    "mov",
                    vec![reg("ebx"), reg("r13d")],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0xb,
                    "sub",
                    vec![reg("ebx"), imm(0x6dc004)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x11,
                    "cmp",
                    vec![reg("ebx"), imm(1)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x14,
                    "ja",
                    Vec::new(),
                    Flow::Branch(Some(0xfa11)),
                ),
                insn(
                    DISPATCH + 0x1a,
                    "lea",
                    vec![reg("rcx"), at_address(IMAGE_BASE)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x21,
                    "mov",
                    vec![reg("ebx"), indexed(Some("rcx"), "rbx", TABLE, None)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x28,
                    "add",
                    vec![reg("rbx"), reg("rcx")],
                    Flow::Fallthrough,
                ),
            ]);
            if called {
                block.push(insn(
                    DISPATCH + 0x2b,
                    "call",
                    vec![Operand::Target(0x5000)],
                    Flow::Call(Some(0x5000)),
                ));
            }
            block.push(insn(
                DISPATCH + 0x30,
                "jmp",
                vec![reg("rbx")],
                Flow::Jmp(None),
            ));
            block
        };
        let table_at = IMAGE_BASE.wrapping_add(TABLE as u64);
        let served = std::cell::Cell::new(0usize);
        let read = |at: u64, len: usize| {
            served.set(served.get() + 1);
            (at == table_at && len == 8).then(|| {
                [0x1000u32, 0x1100]
                    .iter()
                    .flat_map(|rva| rva.to_le_bytes())
                    .collect()
            })
        };

        let straight = map(
            DISPATCH,
            &with_call(false),
            Layout::X64,
            &read,
            in_image,
            never,
        );
        assert_eq!(
            straight.cases.len(),
            2,
            "without the call the table is this driver's switch: {:?}",
            straight.cases
        );

        served.set(0);
        let across = map(
            DISPATCH,
            &with_call(true),
            Layout::X64,
            &read,
            in_image,
            never,
        );

        assert!(
            across.cases.is_empty(),
            "the jump goes wherever the callee returned: {:?}",
            across.cases
        );
        assert_eq!(across.unresolved, vec![DISPATCH + 0x30]);
        assert_eq!(served.get(), 0, "and the table was not read");
    }

    /// A table's entries are **dwords**, and a load of something else is not that load.
    ///
    /// The reader decodes four bytes per slot whatever the load's width was, so a
    /// `mov rax,qword ptr [base+index*4]` taken for this pattern is read as two halves of one
    /// entry and a pair of addresses nobody computed -- published as codes wherever they happen to
    /// land inside the image. Only the width differs between the two halves here.
    #[test]
    fn a_table_load_that_is_not_a_dword_is_not_a_table() {
        const TABLE: i64 = 0x9000;
        let loaded = |size: Option<u32>| {
            let mut block = prologue(DISPATCH);
            block.extend([
                insn(
                    DISPATCH + 8,
                    "mov",
                    vec![reg("eax"), reg("r13d")],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0xb,
                    "sub",
                    vec![reg("eax"), imm(0x6dc004)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x11,
                    "cmp",
                    vec![reg("eax"), imm(1)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x14,
                    "ja",
                    Vec::new(),
                    Flow::Branch(Some(0xfa11)),
                ),
                insn(
                    DISPATCH + 0x1a,
                    "lea",
                    vec![reg("rcx"), at_address(IMAGE_BASE)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x21,
                    "mov",
                    vec![reg("rax"), indexed_sized(Some("rcx"), "rax", TABLE, size)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x28,
                    "add",
                    vec![reg("rax"), reg("rcx")],
                    Flow::Fallthrough,
                ),
                insn(DISPATCH + 0x2b, "jmp", vec![reg("rax")], Flow::Jmp(None)),
            ]);
            block
        };
        let table_at = IMAGE_BASE.wrapping_add(TABLE as u64);
        let served = std::cell::Cell::new(0usize);
        let read = |at: u64, len: usize| {
            served.set(served.get() + 1);
            (at == table_at && len == 8).then(|| {
                [0x1000u32, 0x1100]
                    .iter()
                    .flat_map(|rva| rva.to_le_bytes())
                    .collect()
            })
        };

        let dword = map(
            DISPATCH,
            &loaded(Some(4)),
            Layout::X64,
            &read,
            in_image,
            never,
        );
        assert_eq!(
            dword.cases.len(),
            2,
            "a dword table is a table: {:?}",
            dword.cases
        );

        served.set(0);
        let qword = map(
            DISPATCH,
            &loaded(Some(8)),
            Layout::X64,
            &read,
            in_image,
            never,
        );

        assert!(
            qword.cases.is_empty(),
            "eight bytes a slot is not the table this would read: {:?}",
            qword.cases
        );
        assert_eq!(qword.unresolved, vec![DISPATCH + 0x2b]);
        assert_eq!(served.get(), 0, "and nothing was read");
    }

    /// A table's base is the register's value **at the load**, not at the jump.
    ///
    /// A block is free to reuse a register after indexing through it, and a compiler does:
    /// `movsxd rcx,[rbx+rax*4]` / `lea rbx,[rip+another]` / `add rcx,rdx` / `jmp rcx` indexed
    /// through the old `rbx`. Read at the jump instead, the walk addresses whichever table the
    /// register points at by then and publishes its entries as this switch's codes. The fixture
    /// serves **both** tables, so reading the wrong one produces the wrong answer rather than no
    /// answer -- which is the shape the mistake really has.
    #[test]
    fn a_tables_base_is_what_the_load_indexed_through() {
        const TABLE: i64 = 0x9000;
        const MOVED: u64 = 0x30000;
        let mut block = prologue(DISPATCH);
        block.extend([
            insn(
                DISPATCH + 8,
                "mov",
                vec![reg("eax"), reg("r13d")],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xb,
                "sub",
                vec![reg("eax"), imm(0x6dc004)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x11,
                "cmp",
                vec![reg("eax"), imm(1)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x14,
                "ja",
                Vec::new(),
                Flow::Branch(Some(0xfa11)),
            ),
            insn(
                DISPATCH + 0x1a,
                "lea",
                vec![reg("rcx"), at_address(IMAGE_BASE)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x21,
                "lea",
                vec![reg("rdx"), at_address(IMAGE_BASE)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x28,
                "mov",
                vec![reg("eax"), indexed(Some("rcx"), "rax", TABLE, None)],
                Flow::Fallthrough,
            ),
            // The base register, reused for something else before the jump.
            insn(
                DISPATCH + 0x2f,
                "lea",
                vec![reg("rcx"), at_address(IMAGE_BASE + MOVED)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x36,
                "add",
                vec![reg("rax"), reg("rdx")],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x39, "jmp", vec![reg("rax")], Flow::Jmp(None)),
        ]);
        let indexed_through = IMAGE_BASE.wrapping_add(TABLE as u64);
        let pointed_at = indexed_through.wrapping_add(MOVED);
        let read = |at: u64, len: usize| {
            if len != 8 {
                return None;
            }
            let entries: [u32; 2] = if at == indexed_through {
                [0x1000, 0x1100]
            } else if at == pointed_at {
                [0x2000, 0x2100]
            } else {
                return None;
            };
            Some(
                entries
                    .iter()
                    .flat_map(|rva| rva.to_le_bytes())
                    .collect::<Vec<u8>>(),
            )
        };

        let found = map(DISPATCH, &block, Layout::X64, read, in_image, never);

        assert_eq!(
            found
                .cases
                .iter()
                .map(|case| (case.code, case.lands))
                .collect::<Vec<_>>(),
            vec![
                (0x6dc004, IMAGE_BASE + 0x1000),
                (0x6dc005, IMAGE_BASE + 0x1100)
            ],
            "the table the load indexed through, not the one the register points at by the jump: \
             {:?}",
            found.cases
        );
    }

    /// Facts that never settled are **discarded**, not reported.
    ///
    /// A block's facts start as whatever the first path into it left and are narrowed by every
    /// path after, so a sweep budget that runs out leaves beliefs a later edge would have taken
    /// away -- a register still holding the control code, a bounds check still standing. Reported,
    /// those are cases no execution produces, and nothing about a fabricated case says it is one.
    /// So the beliefs go and the answer says it never settled.
    ///
    /// What is asserted is a **jump table**, because a table needs a bound that reached the switch
    /// block along an edge -- exactly the kind of belief this is about. A code read off the bare
    /// `+0x18` displacement survives, and should: that is a statement the block makes on its own,
    /// which is why it comes back `proved: false` in both halves.
    ///
    /// The budget is named rather than reached: a routine that exhausts the real one is not
    /// something a fixture can write down, and the rule should not go untested for that.
    #[test]
    fn facts_that_never_settled_are_not_reported() {
        const TABLE: i64 = 0x9000;
        let mut block = prologue(DISPATCH);
        block.extend([
            insn(
                DISPATCH + 8,
                "mov",
                vec![reg("eax"), reg("r13d")],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xb,
                "sub",
                vec![reg("eax"), imm(0x6dc004)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x11,
                "cmp",
                vec![reg("eax"), imm(1)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x14,
                "ja",
                Vec::new(),
                Flow::Branch(Some(0xfa11)),
            ),
            insn(
                DISPATCH + 0x1a,
                "lea",
                vec![reg("rcx"), at_address(IMAGE_BASE)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x21,
                "mov",
                vec![reg("eax"), indexed(Some("rcx"), "rax", TABLE, None)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x28,
                "add",
                vec![reg("rax"), reg("rcx")],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x2b, "jmp", vec![reg("rax")], Flow::Jmp(None)),
        ]);
        let table_at = IMAGE_BASE.wrapping_add(TABLE as u64);
        let read = |at: u64, len: usize| {
            (at == table_at && len == 8).then(|| {
                [0x1000u32, 0x1100]
                    .iter()
                    .flat_map(|rva| rva.to_le_bytes())
                    .collect()
            })
        };

        let settled = map(DISPATCH, &block, Layout::X64, &read, in_image, never);
        assert_eq!(
            settled.cases.len(),
            2,
            "with the facts settled the switch is this driver's: {:?}",
            settled.cases
        );
        assert!(!settled.unsettled && settled.unresolved.is_empty());

        let short = map_within(DISPATCH, &block, Layout::X64, &read, in_image, never, 1);

        assert!(short.unsettled, "the walk says the facts never settled");
        assert!(
            short.cases.is_empty() && short.tables.is_empty(),
            "and the bound that reached the switch is gone with them: {:?}",
            short.cases
        );
        assert_eq!(
            short.unresolved,
            vec![DISPATCH + 0x2b],
            "so the jump is one that was not followed"
        );
    }

    /// The per-case pass has a clock of its own.
    ///
    /// It is bounded by the **case list**, whose length the target decides, and for each case it
    /// walks a block and a short chain of tail jumps. A caller that has gone can otherwise be
    /// waited out by work nobody will read, after the two bounded passes have both finished.
    ///
    /// The poll count is measured first, and the halt is armed on the last one. With the poll in
    /// place that is the last case's, so every earlier case is enriched and the last is not. With
    /// it gone the walk makes fewer polls, the same arming lands back in the recording pass, and
    /// the last case comes back enriched like the rest.
    #[test]
    fn the_per_case_pass_polls_the_clock() {
        let mut block = prologue(DISPATCH);
        block.extend([
            insn(
                DISPATCH + 8,
                "cmp",
                vec![reg("r13d"), imm(0x222003)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xe,
                "je",
                Vec::new(),
                Flow::Branch(Some(DISPATCH + 0x40)),
            ),
            insn(
                DISPATCH + 0x14,
                "cmp",
                vec![reg("r13d"), imm(0x222007)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x1a,
                "je",
                Vec::new(),
                Flow::Branch(Some(DISPATCH + 0x50)),
            ),
            insn(
                DISPATCH + 0x20,
                "cmp",
                vec![reg("r13d"), imm(0x22200b)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x26,
                "je",
                Vec::new(),
                Flow::Branch(Some(DISPATCH + 0x60)),
            ),
            insn(DISPATCH + 0x2c, "ret", Vec::new(), Flow::Return),
        ]);
        for (at, handler) in [
            (DISPATCH + 0x40, 0x7000u64),
            (DISPATCH + 0x50, 0x7100),
            (DISPATCH + 0x60, 0x7200),
        ] {
            block.push(insn(
                at,
                "call",
                vec![Operand::Target(handler)],
                Flow::Call(Some(handler)),
            ));
            block.push(insn(at + 5, "ret", Vec::new(), Flow::Return));
        }

        let polls = std::cell::Cell::new(0usize);
        let counted = map(DISPATCH, &block, Layout::X64, unreadable, in_image, || {
            polls.set(polls.get() + 1);
            None
        });
        assert_eq!(counted.cases.len(), 3, "{:?}", counted.cases);
        assert!(
            counted.cases.iter().all(|case| case.handler.is_some()),
            "every case here reaches a routine: {:?}",
            counted.cases
        );
        let total = polls.get();

        polls.set(0);
        let found = map(DISPATCH, &block, Layout::X64, unreadable, in_image, || {
            polls.set(polls.get() + 1);
            (polls.get() >= total).then_some(Halt::Deadline)
        });

        assert_eq!(found.halted, Some(Halt::Deadline));
        assert_eq!(
            found.cases.len(),
            3,
            "the recording pass finished, so every case is here: {:?}",
            found.cases
        );
        assert_eq!(
            found
                .cases
                .iter()
                .map(|case| case.handler.is_some())
                .collect::<Vec<_>>(),
            vec![true, true, false],
            "and the clock stopped the per-case pass at the last of them: {:?}",
            found.cases
        );
    }

    /// A bound is about the register's value **from here on**, so the register has to still hold
    /// what was compared.
    ///
    /// The pending compare deliberately outlives a flag-neutral instruction between the `cmp` and
    /// its branch, because that is where a compiler puts the case's setup. `cmp eax,1` /
    /// `mov eax,ecx` / `ja default` uses that to leave a bound describing a value `eax` no longer
    /// has, and the table indexed by `eax` is then read to a limit nothing checked. One
    /// instruction is the whole difference between the two halves here.
    ///
    /// The *case* built from such a compare is untouched, and should be: a comparison that already
    /// happened is what the branch reads, whatever the register holds by then.
    #[test]
    fn a_bound_needs_the_register_to_still_hold_what_was_compared() {
        const TABLE: i64 = 0x9000;
        let overwritten = |moved: bool| {
            let mut block = prologue(DISPATCH);
            block.extend([
                insn(
                    DISPATCH + 8,
                    "mov",
                    vec![reg("eax"), reg("r13d")],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0xb,
                    "sub",
                    vec![reg("eax"), imm(0x6dc004)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x11,
                    "cmp",
                    vec![reg("eax"), imm(1)],
                    Flow::Fallthrough,
                ),
            ]);
            if moved {
                // Writes no flags, so the compare still stands -- and `eax` is somebody else's.
                block.push(insn(
                    DISPATCH + 0x14,
                    "mov",
                    vec![reg("eax"), reg("ecx")],
                    Flow::Fallthrough,
                ));
            }
            block.extend([
                insn(
                    DISPATCH + 0x16,
                    "ja",
                    Vec::new(),
                    Flow::Branch(Some(0xfa11)),
                ),
                insn(
                    DISPATCH + 0x1c,
                    "lea",
                    vec![reg("rcx"), at_address(IMAGE_BASE)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x23,
                    "mov",
                    vec![reg("eax"), indexed(Some("rcx"), "rax", TABLE, None)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x2a,
                    "add",
                    vec![reg("rax"), reg("rcx")],
                    Flow::Fallthrough,
                ),
                insn(DISPATCH + 0x2d, "jmp", vec![reg("rax")], Flow::Jmp(None)),
            ]);
            block
        };
        let table_at = IMAGE_BASE.wrapping_add(TABLE as u64);
        let served = std::cell::Cell::new(0usize);
        let read = |at: u64, len: usize| {
            served.set(served.get() + 1);
            (at == table_at && len == 8).then(|| {
                [0x1000u32, 0x1100]
                    .iter()
                    .flat_map(|rva| rva.to_le_bytes())
                    .collect()
            })
        };

        let kept = map(
            DISPATCH,
            &overwritten(false),
            Layout::X64,
            &read,
            in_image,
            never,
        );
        assert_eq!(
            kept.cases.len(),
            2,
            "the register still holds the index, so this is the switch: {:?}",
            kept.cases
        );

        served.set(0);
        let lost = map(
            DISPATCH,
            &overwritten(true),
            Layout::X64,
            &read,
            in_image,
            never,
        );

        assert!(
            lost.cases.is_empty(),
            "the bound is about a value `eax` no longer has: {:?}",
            lost.cases
        );
        assert_eq!(lost.unresolved, vec![DISPATCH + 0x2d]);
        assert_eq!(served.get(), 0, "and the table was not read");
    }

    /// An **indexed** access is not a fixed structure field.
    ///
    /// `mov r13d,[rax+rcx*4+18h]` is an array element off a structure this walk happens to know,
    /// and reading it as `IoControlCode` publishes that array's contents as proved control codes.
    /// Every pattern the chain recognises names a field at a displacement, so none of them admits
    /// an index -- and the same access without one is the control code, which is what makes this
    /// about the index.
    #[test]
    fn an_indexed_access_is_not_a_structure_field() {
        let read_with = |index: Option<&str>| {
            let mut block = vec![insn(
                DISPATCH,
                "mov",
                vec![reg("rax"), pointer("rdx", 0xb8)],
                Flow::Fallthrough,
            )];
            let source = match index {
                Some(index) => Operand::Memory(MemoryOperand {
                    size: Some(4),
                    segment: None,
                    base: Some(named("rax")),
                    index: Some(named(index)),
                    scale: 4,
                    displacement: 0x18,
                    address: None,
                }),
                None => mem("rax", 0x18),
            };
            block.extend([
                insn(
                    DISPATCH + 4,
                    "mov",
                    vec![reg("r13d"), source],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 8,
                    "cmp",
                    vec![reg("r13d"), imm(0x222003)],
                    Flow::Fallthrough,
                ),
                insn(DISPATCH + 0xe, "je", Vec::new(), Flow::Branch(Some(0x900))),
                insn(DISPATCH + 0x14, "ret", Vec::new(), Flow::Return),
            ]);
            map(DISPATCH, &block, Layout::X64, unreadable, in_image, never)
        };

        let element = read_with(Some("rcx"));
        assert!(
            element.cases.is_empty() && !element.code_proved,
            "an array element off the stack location is not the control code: {:?}",
            element.cases
        );

        let field = read_with(None);
        assert_eq!(
            field
                .cases
                .iter()
                .map(|case| (case.code, case.proved))
                .collect::<Vec<_>>(),
            vec![(0x222003, true)],
            "and the field itself is: {:?}",
            field.cases
        );
    }

    /// A status store is read against the register **at the store**.
    ///
    /// Whether a destination is `Irp->IoStatus.Status` is a question about a register, and a block
    /// is free to reuse one: a `rbx` that arrives holding the IRP and is reassigned before the
    /// store would otherwise have that store read as a refusal, taking the handler away from a
    /// code the driver accepts. One instruction is the whole difference between the two halves.
    #[test]
    fn a_status_store_is_read_against_the_register_at_the_store() {
        let reassigned = |moved: bool| {
            let mut block = prologue(DISPATCH);
            block.extend([
                insn(
                    DISPATCH + 8,
                    "mov",
                    vec![reg("rbx"), reg("rdx")],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0xb,
                    "cmp",
                    vec![reg("r13d"), imm(0x222003)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x11,
                    "je",
                    Vec::new(),
                    Flow::Branch(Some(DISPATCH + 0x40)),
                ),
                insn(DISPATCH + 0x17, "ret", Vec::new(), Flow::Return),
            ]);
            let mut at = DISPATCH + 0x40;
            if moved {
                // Whatever `rsi` is, it is not the IRP.
                block.push(insn(
                    at,
                    "mov",
                    vec![reg("rbx"), reg("rsi")],
                    Flow::Fallthrough,
                ));
                at += 3;
            }
            block.extend([
                insn(
                    at,
                    "mov",
                    vec![mem("rbx", 0x30), imm(0xc000_0010)],
                    Flow::Fallthrough,
                ),
                insn(
                    at + 7,
                    "call",
                    vec![Operand::Target(0x7000)],
                    Flow::Call(Some(0x7000)),
                ),
                insn(at + 0xc, "ret", Vec::new(), Flow::Return),
            ]);
            let found = map(DISPATCH, &block, Layout::X64, unreadable, in_image, never);
            assert_eq!(found.cases.len(), 1, "{:?}", found.cases);
            (found.cases[0].accepted, found.cases[0].handler)
        };

        assert_eq!(
            reassigned(false),
            (Some(false), None),
            "the IRP is still in the register the status goes through"
        );
        assert_eq!(
            reassigned(true),
            (Some(true), Some(0x7000)),
            "and here it is not, so this is a case that reaches a routine"
        );
    }

    /// A bound outlives a branch that is about something else.
    ///
    /// It is a claim about one register's value, and every way that value can change already takes
    /// it away. Cleared at every block boundary as well, a bounds check reaches only the block
    /// immediately after it -- so a compiler that puts an unrelated test between the check and the
    /// switch leaves that switch unresolved, and the map says it is a lower bound for no reason
    /// that is in the driver.
    #[test]
    fn a_bound_outlives_a_branch_that_does_not_touch_its_index() {
        const TABLE: i64 = 0x9000;
        let mut block = prologue(DISPATCH);
        block.extend([
            insn(
                DISPATCH + 8,
                "mov",
                vec![reg("eax"), reg("r13d")],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xb,
                "sub",
                vec![reg("eax"), imm(0x6dc004)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x11,
                "cmp",
                vec![reg("eax"), imm(1)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x14,
                "ja",
                Vec::new(),
                Flow::Branch(Some(0xfa11)),
            ),
            // A block in between that decides something else entirely.
            insn(
                DISPATCH + 0x1a,
                "test",
                vec![reg("ecx"), reg("ecx")],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x1c,
                "je",
                Vec::new(),
                Flow::Branch(Some(DISPATCH + 0x60)),
            ),
            // The switch, still indexed by the register the bounds check covered.
            insn(
                DISPATCH + 0x22,
                "lea",
                vec![reg("rcx"), at_address(IMAGE_BASE)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x29,
                "mov",
                vec![reg("eax"), indexed(Some("rcx"), "rax", TABLE, None)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x30,
                "add",
                vec![reg("rax"), reg("rcx")],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x33, "jmp", vec![reg("rax")], Flow::Jmp(None)),
            insn(DISPATCH + 0x60, "ret", Vec::new(), Flow::Return),
        ]);
        let table_at = IMAGE_BASE.wrapping_add(TABLE as u64);
        let read = |at: u64, len: usize| {
            (at == table_at && len == 8).then(|| {
                [0x1000u32, 0x1100]
                    .iter()
                    .flat_map(|rva| rva.to_le_bytes())
                    .collect()
            })
        };

        let found = map(DISPATCH, &block, Layout::X64, read, in_image, never);

        assert_eq!(
            found
                .cases
                .iter()
                .map(|case| (case.code, case.lands))
                .collect::<Vec<_>>(),
            vec![
                (0x6dc004, IMAGE_BASE + 0x1000),
                (0x6dc005, IMAGE_BASE + 0x1100)
            ],
            "the test in between says nothing about the index: {:?}",
            found.cases
        );
        assert!(found.unresolved.is_empty(), "{:?}", found.unresolved);
    }

    /// A **pointer** is carried only by a register wide enough to hold one.
    ///
    /// `mov ecx,edx` passes any four-byte test and zero-extends the low half of a kernel address,
    /// so what is in `rcx` afterwards is not the IRP -- and a `+0xb8` off it is not the stack
    /// location, nor a `+0x18` off *that* the control code. The case is still recovered from the
    /// bare displacement, as it is for any chain this cannot follow, and says `proved: false`;
    /// the same copy at the target's pointer width is the chain, which is what makes this about
    /// the width.
    ///
    /// The `ULONG` rule stays at four bytes, because that is how wide those fields are. One
    /// threshold for both is what let a truncated pointer through.
    #[test]
    fn a_pointer_is_carried_only_at_a_pointers_width() {
        let copied = |spelling: (&str, &str)| {
            let block = vec![
                insn(
                    DISPATCH,
                    "mov",
                    vec![reg(spelling.0), reg(spelling.1)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 3,
                    "mov",
                    vec![reg("rax"), pointer("rcx", 0xb8)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 7,
                    "mov",
                    vec![reg("r13d"), mem("rax", 0x18)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0xb,
                    "cmp",
                    vec![reg("r13d"), imm(0x222003)],
                    Flow::Fallthrough,
                ),
                insn(DISPATCH + 0x11, "je", Vec::new(), Flow::Branch(Some(0x900))),
                insn(DISPATCH + 0x17, "ret", Vec::new(), Flow::Return),
            ];
            let found = map(DISPATCH, &block, Layout::X64, unreadable, in_image, never);
            (
                found
                    .cases
                    .iter()
                    .map(|case| (case.code, case.proved))
                    .collect::<Vec<_>>(),
                found.code_proved,
            )
        };

        assert_eq!(
            copied(("ecx", "edx")),
            (vec![(0x222003, false)], false),
            "half a pointer is not the IRP, so nothing off it was traced from one"
        );
        assert_eq!(
            copied(("rcx", "rdx")),
            (vec![(0x222003, true)], true),
            "and the whole of one is"
        );
    }

    /// An instruction this pass does not model may write more than its first operand.
    ///
    /// `xchg eax,r13d` writes both. Clearing only the first leaves a tracked control code in a
    /// register that now holds the old `eax`, and the `cmp r13d,N` after it is then reported as a
    /// code the driver accepts. Nothing here knows which registers an unmodelled instruction
    /// writes, so every register it **names** stops being believed.
    ///
    /// It does not reach an implicit destination -- `mul ecx` writes `eax` and `edx` and names
    /// neither -- which needs the decoder to say what an instruction writes
    /// (`glslang/dbgscope#155`), and is why this test is about the half that can be closed here.
    #[test]
    fn an_unmodelled_instruction_stops_every_register_it_names_being_believed() {
        let exchanged = |swapped: bool| {
            let mut block = prologue(DISPATCH);
            if swapped {
                block.push(insn(
                    DISPATCH + 8,
                    "xchg",
                    vec![reg("eax"), reg("r13d")],
                    Flow::Fallthrough,
                ));
            }
            block.extend([
                insn(
                    DISPATCH + 0xb,
                    "cmp",
                    vec![reg("r13d"), imm(0x222003)],
                    Flow::Fallthrough,
                ),
                insn(DISPATCH + 0x11, "je", Vec::new(), Flow::Branch(Some(0x900))),
                insn(DISPATCH + 0x17, "ret", Vec::new(), Flow::Return),
            ]);
            map(DISPATCH, &block, Layout::X64, unreadable, in_image, never)
        };

        assert_eq!(
            exchanged(false)
                .cases
                .iter()
                .map(|case| case.code)
                .collect::<Vec<_>>(),
            vec![0x222003],
            "the register still holds the code"
        );
        assert!(
            exchanged(true).cases.is_empty(),
            "and here it holds whatever was in `eax`: {:?}",
            exchanged(true).cases
        );
    }

    /// A status is only what the return register holds **when the block returns**.
    ///
    /// `mov eax,0C0000010h` / `xor eax,eax` / `ret` returns success. Reading the load alone reports
    /// that case as one the driver refuses and takes its handler away, which is a wrong answer
    /// about a code it accepts. One instruction is the whole difference between the two halves.
    #[test]
    fn a_status_overwritten_before_the_return_is_not_a_refusal() {
        let zeroed = |cleared: bool| {
            let mut block = prologue(DISPATCH);
            block.extend([
                insn(
                    DISPATCH + 8,
                    "cmp",
                    vec![reg("r13d"), imm(0x222003)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0xe,
                    "je",
                    Vec::new(),
                    Flow::Branch(Some(DISPATCH + 0x40)),
                ),
                insn(DISPATCH + 0x14, "ret", Vec::new(), Flow::Return),
                insn(
                    DISPATCH + 0x40,
                    "mov",
                    vec![reg("eax"), imm(0xc000_0010)],
                    Flow::Fallthrough,
                ),
            ]);
            let mut at = DISPATCH + 0x45;
            if cleared {
                block.push(insn(
                    at,
                    "xor",
                    vec![reg("eax"), reg("eax")],
                    Flow::Fallthrough,
                ));
                at += 2;
            }
            block.push(insn(at, "ret", Vec::new(), Flow::Return));
            let found = map(DISPATCH, &block, Layout::X64, unreadable, in_image, never);
            assert_eq!(found.cases.len(), 1, "{:?}", found.cases);
            found.cases[0].accepted
        };

        assert_eq!(zeroed(false), Some(false), "the status is what it returns");
        assert_eq!(
            zeroed(true),
            None,
            "and here it returns success, whatever it loaded first"
        );
    }

    /// A rejection written across two blocks is still a rejection.
    ///
    /// `mov eax,0C0000010h` / `jmp common_ret` is the ordinary way to share an epilogue, and
    /// starting the block it jumps to from nothing loses the status -- the shared return block is
    /// then reported as this case's **handler**, which is a routine a reader would go and look up.
    /// The tail jump is already followed; what this is about is what goes with it.
    #[test]
    fn a_status_carries_across_the_tail_jump_that_follows_it() {
        const TAIL: u64 = DISPATCH + 0x60;
        let mut block = prologue(DISPATCH);
        block.extend([
            insn(
                DISPATCH + 8,
                "cmp",
                vec![reg("r13d"), imm(0x222003)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xe,
                "je",
                Vec::new(),
                Flow::Branch(Some(DISPATCH + 0x40)),
            ),
            insn(DISPATCH + 0x14, "ret", Vec::new(), Flow::Return),
            // The case block: a status, and out to the shared epilogue.
            insn(
                DISPATCH + 0x40,
                "mov",
                vec![reg("eax"), imm(0xc000_0010)],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x45, "jmp", Vec::new(), Flow::Jmp(Some(TAIL))),
            // The epilogue, which is not this code's handler.
            insn(TAIL, "ret", Vec::new(), Flow::Return),
        ]);

        let found = map(DISPATCH, &block, Layout::X64, unreadable, in_image, never);

        assert_eq!(found.cases.len(), 1, "{:?}", found.cases);
        assert_eq!(
            (found.cases[0].accepted, found.cases[0].handler),
            (Some(false), None),
            "the status the first block set is what the second one returns: {:?}",
            found.cases[0]
        );
    }

    /// A length check is against the **field**, not an element beside it.
    ///
    /// `cmp dword ptr [rbx+rcx*4+10h],20h` off a base this walk watched the stack location reach
    /// is an array element, and reported as `InputBufferLength` it publishes a size the driver
    /// never required -- a caller sizing a buffer from it is refused by the driver it was obeying.
    /// The same compare without an index is the field.
    #[test]
    fn a_length_check_is_against_the_field_and_not_an_element_beside_it() {
        let checked = |index: Option<&str>| {
            let mut block = prologue(DISPATCH);
            let length = match index {
                Some(index) => Operand::Memory(MemoryOperand {
                    size: Some(4),
                    segment: None,
                    base: Some(named("rax")),
                    index: Some(named(index)),
                    scale: 4,
                    displacement: 0x10,
                    address: None,
                }),
                None => mem("rax", 0x10),
            };
            block.extend([
                insn(
                    DISPATCH + 8,
                    "cmp",
                    vec![reg("r13d"), imm(0x222003)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0xe,
                    "je",
                    Vec::new(),
                    Flow::Branch(Some(DISPATCH + 0x40)),
                ),
                insn(DISPATCH + 0x14, "ret", Vec::new(), Flow::Return),
                insn(
                    DISPATCH + 0x40,
                    "cmp",
                    vec![length, imm(0x20)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x48,
                    "jne",
                    Vec::new(),
                    Flow::Branch(Some(DISPATCH + 0x60)),
                ),
                insn(
                    DISPATCH + 0x4e,
                    "call",
                    vec![Operand::Target(0x5000)],
                    Flow::Call(Some(0x5000)),
                ),
                insn(DISPATCH + 0x53, "ret", Vec::new(), Flow::Return),
                // The refusal the check's other edge reaches, which is what makes it exact.
                insn(
                    DISPATCH + 0x60,
                    "mov",
                    vec![reg("eax"), imm(0xc000_0023)],
                    Flow::Fallthrough,
                ),
                insn(DISPATCH + 0x65, "ret", Vec::new(), Flow::Return),
            ]);
            let found = map(DISPATCH, &block, Layout::X64, unreadable, in_image, never);
            assert_eq!(found.cases.len(), 1, "{:?}", found.cases);
            found.cases[0].in_size.map(|size| (size.value, size.exact))
        };

        assert_eq!(
            checked(None),
            Some((0x20, true)),
            "the field itself is the length"
        );
        assert_eq!(
            checked(Some("rcx")),
            None,
            "and an element beside it is not"
        );
    }

    /// A **short** read of the byte map is not the byte map.
    ///
    /// A partial dump, or a read that runs into a page the capture left out, comes back with a
    /// prefix rather than with nothing. Taking it resolves the table from the indices that did
    /// read, leaves the rest absent from `cases`, and still takes the jump out of `unresolved`
    /// while the table record advertises the full bound -- an incomplete answer reading as a
    /// complete one. The two halves differ only in how many bytes the reader hands back.
    #[test]
    fn a_short_byte_map_read_leaves_the_jump_unresolved() {
        const MAP: i64 = 0x5b90;
        const TABLE: i64 = 0x5b80;
        let mut block = prologue(DISPATCH);
        block.extend([
            insn(
                DISPATCH + 8,
                "mov",
                vec![reg("eax"), reg("r13d")],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xb,
                "sub",
                vec![reg("eax"), imm(0x6dc004)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x11,
                "cmp",
                vec![reg("eax"), imm(2)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x14,
                "ja",
                Vec::new(),
                Flow::Branch(Some(0xfa11)),
            ),
            insn(
                DISPATCH + 0x1a,
                "lea",
                vec![reg("rcx"), at_address(IMAGE_BASE)],
                Flow::Fallthrough,
            ),
            // The byte map: one byte an index, saying which case that index is.
            insn(
                DISPATCH + 0x21,
                "movzx",
                vec![
                    reg("eax"),
                    Operand::Memory(MemoryOperand {
                        size: Some(1),
                        segment: None,
                        base: Some(named("rcx")),
                        index: Some(named("rax")),
                        scale: 1,
                        displacement: MAP,
                        address: None,
                    }),
                ],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x28,
                "mov",
                vec![reg("eax"), indexed(Some("rcx"), "rax", TABLE, None)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x2f,
                "add",
                vec![reg("rax"), reg("rcx")],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x32, "jmp", vec![reg("rax")], Flow::Jmp(None)),
        ]);
        let map_at = IMAGE_BASE.wrapping_add(MAP as u64);
        let table_at = IMAGE_BASE.wrapping_add(TABLE as u64);
        let served = |bytes: usize| {
            move |at: u64, len: usize| -> Option<Vec<u8>> {
                if at == map_at {
                    // Three indices, and a reader that hands back as many bytes as it has.
                    return Some(vec![0u8, 1, 2][..bytes.min(len)].to_vec());
                }
                // Served at whatever length is asked for, so that a refusal here is the map's
                // length and not the table read failing to find the one it expected.
                (at == table_at).then(|| {
                    [0x1000u32, 0x1100, 0x1200]
                        .iter()
                        .flat_map(|rva| rva.to_le_bytes())
                        .take(len)
                        .collect()
                })
            }
        };

        let whole = map(DISPATCH, &block, Layout::X64, served(3), in_image, never);
        assert_eq!(
            whole.cases.len(),
            3,
            "the whole map is this driver's switch: {:?}",
            whole.cases
        );

        let short = map(DISPATCH, &block, Layout::X64, served(2), in_image, never);

        assert!(
            short.cases.is_empty(),
            "a prefix of the map is not two thirds of an answer: {:?}",
            short.cases
        );
        assert!(short.tables.is_empty(), "{:?}", short.tables);
        assert_eq!(short.unresolved, vec![DISPATCH + 0x32]);
    }

    /// The chain walk stops at any write to the register it is following.
    ///
    /// `mov eax,[table+ecx*4]` / `xchg edx,eax` / `jmp rax` jumps to the old `edx`, and `xchg`
    /// writes `eax` as its **second** operand -- so a walk that looks only at the first steps over
    /// it and resolves the jump from a load execution overwrote. It is the same fault the forward
    /// walk had, from the other direction, and the same answer: what an unmodelled instruction did
    /// to a register it names is not something this knows.
    #[test]
    fn the_chain_walk_stops_at_any_write_to_the_register_it_wants() {
        const TABLE: i64 = 0x9000;
        let exchanged = |swapped: bool| {
            let mut block = prologue(DISPATCH);
            block.extend([
                insn(
                    DISPATCH + 8,
                    "mov",
                    vec![reg("eax"), reg("r13d")],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0xb,
                    "sub",
                    vec![reg("eax"), imm(0x6dc004)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x11,
                    "cmp",
                    vec![reg("eax"), imm(1)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x14,
                    "ja",
                    Vec::new(),
                    Flow::Branch(Some(0xfa11)),
                ),
                insn(
                    DISPATCH + 0x1a,
                    "lea",
                    vec![reg("rcx"), at_address(IMAGE_BASE)],
                    Flow::Fallthrough,
                ),
                // Into a register that is **not** the bounded index: an `xchg` naming the index
                // would have the forward walk take the bound away, and this test would pass on
                // that rule rather than on the one it is for.
                insn(
                    DISPATCH + 0x21,
                    "mov",
                    vec![reg("edx"), indexed(Some("rcx"), "rax", TABLE, None)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x28,
                    "add",
                    vec![reg("rdx"), reg("rcx")],
                    Flow::Fallthrough,
                ),
            ]);
            if swapped {
                // The wanted register as the **second** operand, which is the whole point.
                block.push(insn(
                    DISPATCH + 0x2b,
                    "xchg",
                    vec![reg("rsi"), reg("rdx")],
                    Flow::Fallthrough,
                ));
            }
            block.push(insn(
                DISPATCH + 0x30,
                "jmp",
                vec![reg("rdx")],
                Flow::Jmp(None),
            ));
            block
        };
        let table_at = IMAGE_BASE.wrapping_add(TABLE as u64);
        let served = std::cell::Cell::new(0usize);
        let read = |at: u64, len: usize| {
            served.set(served.get() + 1);
            (at == table_at && len == 8).then(|| {
                [0x1000u32, 0x1100]
                    .iter()
                    .flat_map(|rva| rva.to_le_bytes())
                    .collect()
            })
        };

        let straight = map(
            DISPATCH,
            &exchanged(false),
            Layout::X64,
            &read,
            in_image,
            never,
        );
        assert_eq!(straight.cases.len(), 2, "{:?}", straight.cases);

        served.set(0);
        let across = map(
            DISPATCH,
            &exchanged(true),
            Layout::X64,
            &read,
            in_image,
            never,
        );

        assert!(
            across.cases.is_empty(),
            "the jump goes to whatever `rsi` held: {:?}",
            across.cases
        );
        assert_eq!(across.unresolved, vec![DISPATCH + 0x30]);
        assert_eq!(served.get(), 0, "and the table was not read");
    }

    /// From the `add` to the jump the chain carries an **address**, so it is copied whole.
    ///
    /// `mov edx,ecx` zero-extends the low half of one, and the jump then goes somewhere this walk
    /// did not compute -- with the table's targets published for it. The **load** is the exception
    /// and stays: a table entry really is four bytes, and `mov eax,[table+rax*4]` really does
    /// zero-extend it on purpose, which is `mountmgr` verbatim. So only the copy after the fold
    /// has a width to answer for, and the two halves here differ in nothing else.
    #[test]
    fn a_jump_target_is_copied_at_a_pointers_width() {
        const TABLE: i64 = 0x9000;
        let copied = |spelling: (&str, &str)| {
            let mut block = prologue(DISPATCH);
            block.extend([
                insn(
                    DISPATCH + 8,
                    "mov",
                    vec![reg("eax"), reg("r13d")],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0xb,
                    "sub",
                    vec![reg("eax"), imm(0x6dc004)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x11,
                    "cmp",
                    vec![reg("eax"), imm(1)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x14,
                    "ja",
                    Vec::new(),
                    Flow::Branch(Some(0xfa11)),
                ),
                insn(
                    DISPATCH + 0x1a,
                    "lea",
                    vec![reg("rcx"), at_address(IMAGE_BASE)],
                    Flow::Fallthrough,
                ),
                // The entry, four bytes wide, zero-extended on purpose.
                insn(
                    DISPATCH + 0x21,
                    "mov",
                    vec![reg("eax"), indexed(Some("rcx"), "rax", TABLE, None)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x28,
                    "add",
                    vec![reg("rax"), reg("rcx")],
                    Flow::Fallthrough,
                ),
                // And the copy, which is of a whole address or of half of one.
                insn(
                    DISPATCH + 0x2b,
                    "mov",
                    vec![reg(spelling.0), reg(spelling.1)],
                    Flow::Fallthrough,
                ),
                insn(DISPATCH + 0x2e, "jmp", vec![reg("rdx")], Flow::Jmp(None)),
            ]);
            block
        };
        let table_at = IMAGE_BASE.wrapping_add(TABLE as u64);
        let served = std::cell::Cell::new(0usize);
        let read = |at: u64, len: usize| {
            served.set(served.get() + 1);
            (at == table_at).then(|| {
                [0x1000u32, 0x1100]
                    .iter()
                    .flat_map(|rva| rva.to_le_bytes())
                    .take(len)
                    .collect()
            })
        };

        let whole = map(
            DISPATCH,
            &copied(("rdx", "rax")),
            Layout::X64,
            &read,
            in_image,
            never,
        );
        assert_eq!(
            whole.cases.len(),
            2,
            "a whole address is the one the jump reads: {:?}",
            whole.cases
        );

        served.set(0);
        let half = map(
            DISPATCH,
            &copied(("edx", "eax")),
            Layout::X64,
            &read,
            in_image,
            never,
        );

        assert!(
            half.cases.is_empty(),
            "and half of one is not: {:?}",
            half.cases
        );
        assert_eq!(half.unresolved, vec![DISPATCH + 0x2e]);
        assert_eq!(served.get(), 0, "and the table was not read");
    }

    /// The two places a status lives are two facts.
    ///
    /// A block that stores an error into `Irp->IoStatus.Status`, completes the request and then
    /// returns success has **refused** the code: the completed IRP carries the error whatever the
    /// dispatch routine returned. Folded into one flag, the `xor eax,eax` takes the IRP's error
    /// away with it -- the case reads as accepted and the completion routine is reported as its
    /// handler, which is a routine a reader would go and look up.
    ///
    /// The other direction still has to hold, and is what the first half asserts: an error loaded
    /// into the return register and overwritten before the `ret` is not a refusal, because nothing
    /// else was told about it.
    #[test]
    fn the_return_register_and_the_irps_status_are_separate() {
        let refused = |into_the_irp: bool| {
            let mut block = prologue(DISPATCH);
            block.extend([
                insn(
                    DISPATCH + 8,
                    "mov",
                    vec![reg("rbx"), reg("rdx")],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0xb,
                    "cmp",
                    vec![reg("r13d"), imm(0x222003)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x11,
                    "je",
                    Vec::new(),
                    Flow::Branch(Some(DISPATCH + 0x40)),
                ),
                insn(DISPATCH + 0x17, "ret", Vec::new(), Flow::Return),
                // The status, into one place or the other.
                insn(
                    DISPATCH + 0x40,
                    "mov",
                    vec![
                        match into_the_irp {
                            true => mem("rbx", 0x30),
                            false => reg("eax"),
                        },
                        imm(0xc000_0010),
                    ],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x47,
                    "call",
                    vec![Operand::Target(0x7000)],
                    Flow::Call(Some(0x7000)),
                ),
                // And the return register cleared on the way out, either way.
                insn(
                    DISPATCH + 0x4c,
                    "xor",
                    vec![reg("eax"), reg("eax")],
                    Flow::Fallthrough,
                ),
                insn(DISPATCH + 0x4e, "ret", Vec::new(), Flow::Return),
            ]);
            let found = map(DISPATCH, &block, Layout::X64, unreadable, in_image, never);
            assert_eq!(found.cases.len(), 1, "{:?}", found.cases);
            (found.cases[0].accepted, found.cases[0].handler)
        };

        assert_eq!(
            refused(true),
            (Some(false), None),
            "the completed IRP carries the error whatever the routine returned"
        );
        assert_eq!(
            refused(false),
            (Some(true), Some(0x7000)),
            "and a status loaded into the return register and cleared before the `ret` told \
             nothing else about it"
        );
    }

    /// A table's base is an **address**, so a narrow `lea` does not establish one.
    ///
    /// `lea eax,[rip+table]` writes four bytes of a kernel address and the decoder still reports
    /// the whole one it computed, so the table would be read where execution never pointed -- and
    /// its entries published as this switch's codes. The same `lea` at the target's width is the
    /// base, which is what makes this about the width.
    #[test]
    fn a_narrow_lea_does_not_establish_a_table_base() {
        const TABLE: i64 = 0x9000;
        let based = |spelling: &str| {
            let mut block = prologue(DISPATCH);
            block.extend([
                insn(
                    DISPATCH + 8,
                    "mov",
                    vec![reg("eax"), reg("r13d")],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0xb,
                    "sub",
                    vec![reg("eax"), imm(0x6dc004)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x11,
                    "cmp",
                    vec![reg("eax"), imm(1)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x14,
                    "ja",
                    Vec::new(),
                    Flow::Branch(Some(0xfa11)),
                ),
                insn(
                    DISPATCH + 0x1a,
                    "lea",
                    vec![reg(spelling), at_address(IMAGE_BASE)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x21,
                    "mov",
                    vec![reg("eax"), indexed(Some("rcx"), "rax", TABLE, None)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x28,
                    "add",
                    vec![reg("rax"), reg("rcx")],
                    Flow::Fallthrough,
                ),
                insn(DISPATCH + 0x2b, "jmp", vec![reg("rax")], Flow::Jmp(None)),
            ]);
            block
        };
        let table_at = IMAGE_BASE.wrapping_add(TABLE as u64);
        let served = std::cell::Cell::new(0usize);
        let read = |at: u64, len: usize| {
            served.set(served.get() + 1);
            (at == table_at).then(|| {
                [0x1000u32, 0x1100]
                    .iter()
                    .flat_map(|rva| rva.to_le_bytes())
                    .take(len)
                    .collect()
            })
        };

        let whole = map(DISPATCH, &based("rcx"), Layout::X64, &read, in_image, never);
        assert_eq!(whole.cases.len(), 2, "{:?}", whole.cases);

        served.set(0);
        let narrow = map(DISPATCH, &based("ecx"), Layout::X64, &read, in_image, never);

        assert!(
            narrow.cases.is_empty(),
            "four bytes of an address is not where the table is: {:?}",
            narrow.cases
        );
        assert_eq!(narrow.unresolved, vec![DISPATCH + 0x2b]);
        assert_eq!(served.get(), 0, "and nothing was read");
    }

    /// The bound that matters is the one standing **at the load**.
    ///
    /// `cmp eax,1` / `ja default` / `add eax,ecx` / `mov eax,[table+rax*4]` indexes the table by
    /// something the check never covered, and reporting its slots gives the codes the check
    /// admitted for entries execution reaches by another number entirely. The same `add` *after*
    /// the load is the image base being folded into the entry, which is the shape every compiled
    /// switch has -- so this is about where the write is, not about the `add`.
    #[test]
    fn a_write_to_the_index_before_the_load_ends_the_bound() {
        const TABLE: i64 = 0x9000;
        let adjusted = |before: bool| {
            let mut block = prologue(DISPATCH);
            block.extend([
                insn(
                    DISPATCH + 8,
                    "mov",
                    vec![reg("eax"), reg("r13d")],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0xb,
                    "sub",
                    vec![reg("eax"), imm(0x6dc004)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x11,
                    "cmp",
                    vec![reg("eax"), imm(1)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x14,
                    "ja",
                    Vec::new(),
                    Flow::Branch(Some(0xfa11)),
                ),
                insn(
                    DISPATCH + 0x1a,
                    "lea",
                    vec![reg("rcx"), at_address(IMAGE_BASE)],
                    Flow::Fallthrough,
                ),
            ]);
            if before {
                block.push(insn(
                    DISPATCH + 0x21,
                    "add",
                    vec![reg("eax"), reg("esi")],
                    Flow::Fallthrough,
                ));
            }
            block.extend([
                insn(
                    DISPATCH + 0x24,
                    "mov",
                    vec![reg("eax"), indexed(Some("rcx"), "rax", TABLE, None)],
                    Flow::Fallthrough,
                ),
                // The fold every compiled switch has, which is the same `add` on the other side.
                insn(
                    DISPATCH + 0x2b,
                    "add",
                    vec![reg("rax"), reg("rcx")],
                    Flow::Fallthrough,
                ),
                insn(DISPATCH + 0x2e, "jmp", vec![reg("rax")], Flow::Jmp(None)),
            ]);
            block
        };
        let table_at = IMAGE_BASE.wrapping_add(TABLE as u64);
        let served = std::cell::Cell::new(0usize);
        let read = |at: u64, len: usize| {
            served.set(served.get() + 1);
            (at == table_at).then(|| {
                [0x1000u32, 0x1100]
                    .iter()
                    .flat_map(|rva| rva.to_le_bytes())
                    .take(len)
                    .collect()
            })
        };

        let after = map(
            DISPATCH,
            &adjusted(false),
            Layout::X64,
            &read,
            in_image,
            never,
        );
        assert_eq!(
            after.cases.len(),
            2,
            "the fold after the load is the switch: {:?}",
            after.cases
        );

        served.set(0);
        let ahead = map(
            DISPATCH,
            &adjusted(true),
            Layout::X64,
            &read,
            in_image,
            never,
        );

        assert!(
            ahead.cases.is_empty(),
            "the index is not the number the check covered: {:?}",
            ahead.cases
        );
        assert_eq!(ahead.unresolved, vec![DISPATCH + 0x2e]);
        assert_eq!(served.get(), 0, "and the table was not read");
    }

    /// One fold, and not several.
    ///
    /// `add rcx,rdx` / `add rcx,r8` makes the target the sum of the entry and **both**, and
    /// keeping one of them reconstructs addresses nobody computed -- published as cases wherever
    /// they happen to be executable, with the jump reported as followed.
    #[test]
    fn a_target_folded_twice_is_not_followed() {
        const TABLE: i64 = 0x9000;
        let folded = |twice: bool| {
            let mut block = prologue(DISPATCH);
            block.extend([
                insn(
                    DISPATCH + 8,
                    "mov",
                    vec![reg("eax"), reg("r13d")],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0xb,
                    "sub",
                    vec![reg("eax"), imm(0x6dc004)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x11,
                    "cmp",
                    vec![reg("eax"), imm(1)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x14,
                    "ja",
                    Vec::new(),
                    Flow::Branch(Some(0xfa11)),
                ),
                insn(
                    DISPATCH + 0x1a,
                    "lea",
                    vec![reg("rcx"), at_address(IMAGE_BASE)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x21,
                    "mov",
                    vec![reg("eax"), indexed(Some("rcx"), "rax", TABLE, None)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x28,
                    "add",
                    vec![reg("rax"), reg("rcx")],
                    Flow::Fallthrough,
                ),
            ]);
            if twice {
                block.push(insn(
                    DISPATCH + 0x2b,
                    "add",
                    vec![reg("rax"), reg("rsi")],
                    Flow::Fallthrough,
                ));
            }
            block.push(insn(
                DISPATCH + 0x2e,
                "jmp",
                vec![reg("rax")],
                Flow::Jmp(None),
            ));
            block
        };
        let table_at = IMAGE_BASE.wrapping_add(TABLE as u64);
        let read = |at: u64, len: usize| {
            (at == table_at).then(|| {
                [0x1000u32, 0x1100]
                    .iter()
                    .flat_map(|rva| rva.to_le_bytes())
                    .take(len)
                    .collect()
            })
        };

        assert_eq!(
            map(
                DISPATCH,
                &folded(false),
                Layout::X64,
                &read,
                in_image,
                never
            )
            .cases
            .len(),
            2,
            "one fold is the switch"
        );
        let twice = map(DISPATCH, &folded(true), Layout::X64, &read, in_image, never);
        assert!(
            twice.cases.is_empty(),
            "and two is a target this did not compute: {:?}",
            twice.cases
        );
        assert_eq!(twice.unresolved, vec![DISPATCH + 0x2e]);
    }

    /// A byte map is looked for **before** the load it feeds.
    ///
    /// It is the first stage of a two-table switch, so a byte load *after* the dword table read is
    /// something else entirely -- the target was already in hand by then. Taken for the map it
    /// remaps every code through arbitrary bytes. The fixture's reader answers at the map's
    /// address as readily as at the table's, so what says the later load was ignored is that the
    /// map was never asked for.
    #[test]
    fn a_byte_map_after_the_load_is_not_the_map() {
        const MAP: i64 = 0x5b90;
        const TABLE: i64 = 0x5b80;
        let mut block = prologue(DISPATCH);
        block.extend([
            insn(
                DISPATCH + 8,
                "mov",
                vec![reg("eax"), reg("r13d")],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xb,
                "sub",
                vec![reg("eax"), imm(0x6dc004)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x11,
                "cmp",
                vec![reg("eax"), imm(1)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x14,
                "ja",
                Vec::new(),
                Flow::Branch(Some(0xfa11)),
            ),
            insn(
                DISPATCH + 0x1a,
                "lea",
                vec![reg("rcx"), at_address(IMAGE_BASE)],
                Flow::Fallthrough,
            ),
            // The dword table, read into the register the jump reads.
            insn(
                DISPATCH + 0x21,
                "mov",
                vec![reg("edx"), indexed(Some("rcx"), "rax", TABLE, None)],
                Flow::Fallthrough,
            ),
            // A byte load into the index, *after* the target was in hand: not the first stage of
            // anything.
            insn(
                DISPATCH + 0x28,
                "movzx",
                vec![
                    reg("eax"),
                    Operand::Memory(MemoryOperand {
                        size: Some(1),
                        segment: None,
                        base: Some(named("rcx")),
                        index: Some(named("rax")),
                        scale: 1,
                        displacement: MAP,
                        address: None,
                    }),
                ],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x2f,
                "add",
                vec![reg("rdx"), reg("rcx")],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x32, "jmp", vec![reg("rdx")], Flow::Jmp(None)),
        ]);
        let map_at = IMAGE_BASE.wrapping_add(MAP as u64);
        let table_at = IMAGE_BASE.wrapping_add(TABLE as u64);
        let asked: std::cell::RefCell<Vec<u64>> = std::cell::RefCell::new(Vec::new());
        let read = |at: u64, len: usize| {
            asked.borrow_mut().push(at);
            if at == map_at {
                // Both slots remapped onto the second entry, which is what taking this for the
                // map would show.
                return Some(vec![1u8, 1][..len.min(2)].to_vec());
            }
            (at == table_at).then(|| {
                [0x1000u32, 0x1100]
                    .iter()
                    .flat_map(|rva| rva.to_le_bytes())
                    .take(len)
                    .collect()
            })
        };

        let found = map(DISPATCH, &block, Layout::X64, read, in_image, never);

        assert_eq!(
            found
                .cases
                .iter()
                .map(|case| (case.code, case.lands))
                .collect::<Vec<_>>(),
            vec![
                (0x6dc004, IMAGE_BASE + 0x1000),
                (0x6dc005, IMAGE_BASE + 0x1100)
            ],
            "one slot per index, not both through a byte the switch never read: {:?}",
            found.cases
        );
        assert_eq!(
            asked.borrow().as_slice(),
            &[table_at],
            "and the map was never asked for"
        );
    }

    /// A case is read from **where it lands**, not from where its block begins.
    ///
    /// A landing is a block's first instruction only when some *edge* goes there, and a jump
    /// table's does not -- so two entries into one shared tail both sit inside a block that starts
    /// above them. Read whole, each gets instructions the other's path executes: the fixture's
    /// first entry lands on a `call` that is its handler, and the second lands *past* it, so
    /// reading from the block's start hands the second case the first one's routine.
    #[test]
    fn a_case_is_read_from_where_it_lands() {
        const TABLE: i64 = 0x9000;
        const FIRST: u64 = DISPATCH + 0x40;
        const SECOND: u64 = DISPATCH + 0x4a;
        let mut block = prologue(DISPATCH);
        block.extend([
            insn(
                DISPATCH + 8,
                "mov",
                vec![reg("eax"), reg("r13d")],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xb,
                "sub",
                vec![reg("eax"), imm(0x6dc004)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x11,
                "cmp",
                vec![reg("eax"), imm(1)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x14,
                "ja",
                Vec::new(),
                Flow::Branch(Some(0xfa11)),
            ),
            insn(
                DISPATCH + 0x1a,
                "lea",
                vec![reg("rcx"), at_address(IMAGE_BASE)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x21,
                "mov",
                vec![reg("eax"), indexed(Some("rcx"), "rax", TABLE, None)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x28,
                "add",
                vec![reg("rax"), reg("rcx")],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x2b, "jmp", vec![reg("rax")], Flow::Jmp(None)),
            // One tail, entered at two points. Nothing branches to either, so the graph has one
            // block starting at the first.
            insn(
                FIRST,
                "call",
                vec![Operand::Target(0x7000)],
                Flow::Call(Some(0x7000)),
            ),
            insn(
                SECOND,
                "call",
                vec![Operand::Target(0x7100)],
                Flow::Call(Some(0x7100)),
            ),
            insn(SECOND + 5, "ret", Vec::new(), Flow::Return),
        ]);
        let table_at = IMAGE_BASE.wrapping_add(TABLE as u64);
        let read = |at: u64, len: usize| {
            (at == table_at).then(|| {
                [(FIRST - IMAGE_BASE) as u32, (SECOND - IMAGE_BASE) as u32]
                    .iter()
                    .flat_map(|rva| rva.to_le_bytes())
                    .take(len)
                    .collect()
            })
        };

        let found = map(DISPATCH, &block, Layout::X64, read, in_image, never);

        assert_eq!(
            found
                .cases
                .iter()
                .map(|case| (case.code, case.lands, case.handler))
                .collect::<Vec<_>>(),
            vec![
                (0x6dc004, FIRST, Some(0x7000)),
                (0x6dc005, SECOND, Some(0x7100)),
            ],
            "each entry reaches the routine at its own landing: {:?}",
            found.cases
        );
    }

    /// The dword table's own load does not carry a bound, because it does not need to.
    ///
    /// The bound is read **at** that load, before it executes, so what it leaves in the index is
    /// nobody's question -- and exempting it carried a bound over
    /// `mov rax,qword ptr [foo+rax*4]`, a scale-4 load that is not a table entry. The switch after
    /// that was then resolved to the slots a check on some earlier value admitted. The byte map,
    /// which really does feed the load that follows it, still carries one; the `a_two_table_switch`
    /// fixture is what says so.
    #[test]
    fn a_scale_four_load_that_is_not_an_entry_ends_the_bound() {
        const TABLE: i64 = 0x9000;
        let through = |wide: bool| {
            let mut block = prologue(DISPATCH);
            block.extend([
                insn(
                    DISPATCH + 8,
                    "mov",
                    vec![reg("eax"), reg("r13d")],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0xb,
                    "sub",
                    vec![reg("eax"), imm(0x6dc004)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x11,
                    "cmp",
                    vec![reg("eax"), imm(1)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x14,
                    "ja",
                    Vec::new(),
                    Flow::Branch(Some(0xfa11)),
                ),
                insn(
                    DISPATCH + 0x1a,
                    "lea",
                    vec![reg("rcx"), at_address(IMAGE_BASE)],
                    Flow::Fallthrough,
                ),
            ]);
            if wide {
                // Eight bytes a slot: whatever this is, it is not the table's entries, and what
                // it leaves in the index is not the number the check covered.
                block.push(insn(
                    DISPATCH + 0x21,
                    "mov",
                    vec![
                        reg("rax"),
                        indexed_sized(Some("rcx"), "rax", 0x8000, Some(8)),
                    ],
                    Flow::Fallthrough,
                ));
            }
            block.extend([
                insn(
                    DISPATCH + 0x28,
                    "mov",
                    vec![reg("edx"), indexed(Some("rcx"), "rax", TABLE, None)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x2f,
                    "add",
                    vec![reg("rdx"), reg("rcx")],
                    Flow::Fallthrough,
                ),
                insn(DISPATCH + 0x32, "jmp", vec![reg("rdx")], Flow::Jmp(None)),
            ]);
            block
        };
        let table_at = IMAGE_BASE.wrapping_add(TABLE as u64);
        let served = std::cell::Cell::new(0usize);
        let read = |at: u64, len: usize| {
            served.set(served.get() + 1);
            (at == table_at).then(|| {
                [0x1000u32, 0x1100]
                    .iter()
                    .flat_map(|rva| rva.to_le_bytes())
                    .take(len)
                    .collect()
            })
        };

        let straight = map(
            DISPATCH,
            &through(false),
            Layout::X64,
            &read,
            in_image,
            never,
        );
        assert_eq!(straight.cases.len(), 2, "{:?}", straight.cases);

        served.set(0);
        let indirect = map(
            DISPATCH,
            &through(true),
            Layout::X64,
            &read,
            in_image,
            never,
        );

        assert!(
            indirect.cases.is_empty(),
            "the index is whatever eight bytes of somebody's array said: {:?}",
            indirect.cases
        );
        assert_eq!(indirect.unresolved, vec![DISPATCH + 0x32]);
        assert_eq!(served.get(), 0, "and the table was not read");
    }

    /// A byte map is **zero-extended**, and a sign-extending load is not that stage.
    ///
    /// A case number is an index into the second table and cannot be negative, so MSVC emits
    /// `movzx`. Accepting a `movsx` kept the bound while [`follow_table`] declined to read the map
    /// through it -- so the dword table was read as though it were indexed by the original values,
    /// pairing every code with the target of a different case. The two halves differ in the
    /// mnemonic and in nothing else.
    #[test]
    fn a_sign_extending_byte_map_is_not_the_map() {
        const MAP: i64 = 0x5b90;
        const TABLE: i64 = 0x5b80;
        let extended = |mnemonic: &str| {
            let mut block = prologue(DISPATCH);
            block.extend([
                insn(
                    DISPATCH + 8,
                    "mov",
                    vec![reg("eax"), reg("r13d")],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0xb,
                    "sub",
                    vec![reg("eax"), imm(0x6dc004)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x11,
                    "cmp",
                    vec![reg("eax"), imm(1)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x14,
                    "ja",
                    Vec::new(),
                    Flow::Branch(Some(0xfa11)),
                ),
                insn(
                    DISPATCH + 0x1a,
                    "lea",
                    vec![reg("rcx"), at_address(IMAGE_BASE)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x21,
                    mnemonic,
                    vec![
                        reg("eax"),
                        Operand::Memory(MemoryOperand {
                            size: Some(1),
                            segment: None,
                            base: Some(named("rcx")),
                            index: Some(named("rax")),
                            scale: 1,
                            displacement: MAP,
                            address: None,
                        }),
                    ],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x28,
                    "mov",
                    vec![reg("edx"), indexed(Some("rcx"), "rax", TABLE, None)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x2f,
                    "add",
                    vec![reg("rdx"), reg("rcx")],
                    Flow::Fallthrough,
                ),
                insn(DISPATCH + 0x32, "jmp", vec![reg("rdx")], Flow::Jmp(None)),
            ]);
            block
        };
        let map_at = IMAGE_BASE.wrapping_add(MAP as u64);
        let table_at = IMAGE_BASE.wrapping_add(TABLE as u64);
        let read = |at: u64, len: usize| {
            if at == map_at {
                // Both indices are the *second* case, which is what reading the map is for.
                return Some(vec![1u8, 1][..len.min(2)].to_vec());
            }
            (at == table_at).then(|| {
                [0x1000u32, 0x1100]
                    .iter()
                    .flat_map(|rva| rva.to_le_bytes())
                    .take(len)
                    .collect()
            })
        };

        let zeroed = map(
            DISPATCH,
            &extended("movzx"),
            Layout::X64,
            &read,
            in_image,
            never,
        );
        assert_eq!(
            zeroed
                .cases
                .iter()
                .map(|case| (case.code, case.lands))
                .collect::<Vec<_>>(),
            vec![
                (0x6dc004, IMAGE_BASE + 0x1100),
                (0x6dc005, IMAGE_BASE + 0x1100)
            ],
            "both indices select the case the map names: {:?}",
            zeroed.cases
        );

        let signed = map(
            DISPATCH,
            &extended("movsx"),
            Layout::X64,
            &read,
            in_image,
            never,
        );

        assert!(
            signed.cases.is_empty(),
            "a signed load is not the stage this reads, and the index is no longer the bounded \
             one: {:?}",
            signed.cases
        );
        assert_eq!(signed.unresolved, vec![DISPATCH + 0x32]);
    }

    /// The unsettled warning says what was discarded, and what was not.
    ///
    /// Clearing the facts takes away everything that rested on one -- every table, every code
    /// traced to the IRP -- and leaves what a block says on its own: a compare against a bare
    /// `+0x18` displacement, which is unproved and is still reported. A note claiming *every* case
    /// was discarded, printed above a list of cases, is a result contradicting itself.
    #[test]
    fn the_unsettled_warning_does_not_contradict_the_list_under_it() {
        let mut block = prologue(DISPATCH);
        block.extend([
            insn(
                DISPATCH + 8,
                "cmp",
                vec![reg("r13d"), imm(0x222003)],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0xe, "je", Vec::new(), Flow::Branch(Some(0x900))),
            insn(DISPATCH + 0x14, "ret", Vec::new(), Flow::Return),
        ]);

        let found = map_within(
            DISPATCH,
            &block,
            Layout::X64,
            unreadable,
            in_image,
            never,
            0,
        );

        assert!(found.unsettled);
        assert_eq!(
            found
                .cases
                .iter()
                .map(|case| (case.code, case.proved))
                .collect::<Vec<_>>(),
            vec![(0x222003, false)],
            "a bare displacement is something the block said on its own: {:?}",
            found.cases
        );

        let rendered = render(&structured_report(&found, |address| {
            crate::structured::CodeLocation {
                address: format!("{address:#018x}"),
                module: None,
                rva: None,
                attribution_failed: false,
            }
        }));

        assert!(
            rendered.contains("everything resting on a fact"),
            "the note says what went: {rendered}"
        );
        assert!(
            !rendered.contains("every case and table was"),
            "and not that everything did, above a list of what did not: {rendered}"
        );
    }

    /// A bound is about a register's **value**, so a write that is not part of the table pattern
    /// ends it.
    ///
    /// `cmp eax,2` / `ja default` followed by `xor eax,eax` says nothing about what a table
    /// indexed by `eax` then selects: execution can reach only entry zero, and reading the bound
    /// as still standing reports all three as codes the driver accepts. The fixture's reader would
    /// serve the table happily, so what is asserted is that nothing was read rather than that the
    /// answer came out empty.
    #[test]
    fn a_write_that_is_not_the_table_pattern_ends_the_bound() {
        const TABLE: i64 = 0x9000;
        let mut block = prologue(DISPATCH);
        block.extend([
            insn(
                DISPATCH + 8,
                "mov",
                vec![reg("eax"), reg("r13d")],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xb,
                "sub",
                vec![reg("eax"), imm(0x222000)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x11,
                "cmp",
                vec![reg("eax"), imm(2)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x14,
                "ja",
                Vec::new(),
                Flow::Branch(Some(0xfa11)),
            ),
            // Nothing to do with the index any more.
            insn(
                DISPATCH + 0x1a,
                "xor",
                vec![reg("eax"), reg("eax")],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x1c,
                "lea",
                vec![reg("rcx"), at_address(IMAGE_BASE)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x23,
                "mov",
                vec![reg("eax"), indexed(Some("rcx"), "rax", TABLE, None)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x2a,
                "add",
                vec![reg("rax"), reg("rcx")],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x2d, "jmp", vec![reg("rax")], Flow::Jmp(None)),
        ]);
        let served = std::cell::Cell::new(0usize);
        let read = |_: u64, len: usize| {
            served.set(served.get() + 1);
            Some(vec![0u8; len])
        };

        let found = map(DISPATCH, &block, Layout::X64, read, in_image, never);

        assert!(found.cases.is_empty(), "{:?}", found.cases);
        assert_eq!(found.unresolved, vec![DISPATCH + 0x2d]);
        assert_eq!(served.get(), 0, "nothing was read");
    }

    /// A **call** ends a pending compare, whatever the decoder says about flags.
    ///
    /// A callee is free to leave the flags as it likes, so the branch after one is not reading the
    /// compare before it. Attributing it to that compare builds a case out of two unrelated
    /// instructions -- and `call` writes no flags of its own, so the rule that lets a `mov` through
    /// would let this through too.
    #[test]
    fn a_call_ends_a_pending_compare() {
        let mut block = prologue(DISPATCH);
        block.extend([
            insn(
                DISPATCH + 8,
                "cmp",
                vec![reg("r13d"), imm(0x222003)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xe,
                "call",
                vec![Operand::Target(0x5000)],
                Flow::Call(Some(0x5000)),
            ),
            insn(DISPATCH + 0x13, "je", Vec::new(), Flow::Branch(Some(0x900))),
            insn(DISPATCH + 0x19, "ret", Vec::new(), Flow::Return),
        ]);

        let found = map(DISPATCH, &block, Layout::X64, unreadable, in_image, never);

        assert!(
            found.cases.is_empty(),
            "the branch is not reading the compare before the call: {:?}",
            found.cases
        );
    }

    /// On a 32-bit target the return register is `eax`, and a refusal that returns one is read as
    /// a refusal.
    ///
    /// The full-width register a decoder names depends on the target -- `eax` is part of `rax` on
    /// x64 and is itself the whole register on x86 -- so a rejection written in `eax` is invisible
    /// to a layout carrying the other name. With a direct call in the same block it is worse than
    /// invisible: the block reads as handled and the call is published as the handler.
    #[test]
    fn a_32_bit_refusal_returns_in_the_register_that_target_returns_in() {
        let block = vec![
            insn(
                DISPATCH,
                "mov",
                vec![reg32("esi"), mem32("ebp", 0x0c)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 3,
                "mov",
                vec![reg32("edi"), mem32("esi", 0x60)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 6,
                "mov",
                vec![reg32("ebx"), mem32("edi", 0x0c)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 9,
                "cmp",
                vec![reg32("ebx"), imm(0x222003)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xf,
                "je",
                Vec::new(),
                Flow::Branch(Some(DISPATCH + 0x20)),
            ),
            insn(DISPATCH + 0x15, "ret", Vec::new(), Flow::Return),
            // The refusal: a status in the return register, a completion call, and out.
            insn(
                DISPATCH + 0x20,
                "mov",
                vec![reg32("eax"), imm(0xc000_0010)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x25,
                "call",
                vec![Operand::Target(0x7000)],
                Flow::Call(Some(0x7000)),
            ),
            insn(DISPATCH + 0x2a, "ret", Vec::new(), Flow::Return),
        ];

        let found = map(DISPATCH, &block, Layout::X86, unreadable, in_image, never);

        assert_eq!(found.cases.len(), 1, "{:?}", found.cases);
        assert_eq!(
            (found.cases[0].accepted, found.cases[0].handler),
            (Some(false), None),
            "the completion routine is not this code's handler: {:?}",
            found.cases[0]
        );
    }

    /// A **narrow** compare tests part of the control code, and part of it is not it.
    ///
    /// `cmp r13w,2003h` constrains sixteen bits of a `ULONG` and matches every code that shares
    /// them, so reporting it as one exact code invents the bits nobody read — a device type out of
    /// thin air. The same fixture at the register's full width is the control code, which is what
    /// makes this about the width rather than about the compare.
    ///
    /// The copy is the other half of the same question: `movzx ecx,ax` carries two bytes of the
    /// value, and a compare against `ecx` afterwards is a statement about those two.
    #[test]
    fn a_narrow_compare_or_copy_does_not_carry_the_control_code() {
        let compared = |spelling: &str| {
            let mut block = prologue(DISPATCH);
            block.extend([
                insn(
                    DISPATCH + 8,
                    "cmp",
                    vec![reg(spelling), imm(0x2003)],
                    Flow::Fallthrough,
                ),
                insn(DISPATCH + 0xe, "je", Vec::new(), Flow::Branch(Some(0x900))),
                insn(DISPATCH + 0x14, "ret", Vec::new(), Flow::Return),
            ]);
            map(DISPATCH, &block, Layout::X64, unreadable, in_image, never)
        };

        assert!(
            compared("r13w").cases.is_empty(),
            "two bytes of a ULONG are not a control code: {:?}",
            compared("r13w").cases
        );
        assert_eq!(
            compared("r13d")
                .cases
                .iter()
                .map(|case| case.code)
                .collect::<Vec<_>>(),
            vec![0x2003],
            "and four bytes are: {:?}",
            compared("r13d").cases
        );

        let copied = |mnemonic: &str, source: &str| {
            let mut block = prologue(DISPATCH);
            block.extend([
                // The code into `rax` first, so the narrow read below is a read of *it* rather
                // than of a register holding nothing.
                insn(
                    DISPATCH + 8,
                    "mov",
                    vec![reg("eax"), reg("r13d")],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0xb,
                    mnemonic,
                    vec![reg("ecx"), reg(source)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0xe,
                    "cmp",
                    vec![reg("ecx"), imm(0x222003)],
                    Flow::Fallthrough,
                ),
                insn(DISPATCH + 0x14, "je", Vec::new(), Flow::Branch(Some(0x900))),
                insn(DISPATCH + 0x1a, "ret", Vec::new(), Flow::Return),
            ]);
            map(DISPATCH, &block, Layout::X64, unreadable, in_image, never)
        };

        assert!(
            copied("movzx", "ax").cases.is_empty(),
            "a copy of two bytes carries two bytes: {:?}",
            copied("movzx", "ax").cases
        );
        assert_eq!(
            copied("mov", "eax")
                .cases
                .iter()
                .map(|case| case.code)
                .collect::<Vec<_>>(),
            vec![0x222003],
            "and a copy of the whole value carries it: {:?}",
            copied("mov", "eax").cases
        );
    }

    /// A **sign-extending** load makes a table entry a signed displacement.
    ///
    /// `movsxd rax,dword ptr [table+index*4]` is how a compiler writes a table whose cases sit
    /// *before* the base they are measured from. Zero-extending one of those adds about four
    /// gigabytes, which lands outside the image — so the table is refused as not being one and
    /// every case in it is lost, with the jump reported unresolved. The fixture's first entry is
    /// negative for exactly that reason.
    #[test]
    fn a_sign_extending_load_reads_its_entries_as_signed() {
        const TABLE: i64 = 0x9000;
        const BASE: u64 = IMAGE_BASE + 0x8000;
        let mut block = prologue(DISPATCH);
        block.extend([
            insn(
                DISPATCH + 8,
                "mov",
                vec![reg("eax"), reg("r13d")],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xb,
                "sub",
                vec![reg("eax"), imm(0x222000)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x11,
                "cmp",
                vec![reg("eax"), imm(1)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x14,
                "ja",
                Vec::new(),
                Flow::Branch(Some(0xfa11)),
            ),
            insn(
                DISPATCH + 0x1a,
                "lea",
                vec![reg("rcx"), at_address(BASE)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x21,
                "movsxd",
                vec![reg("rax"), indexed(Some("rcx"), "rax", TABLE, None)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x28,
                "add",
                vec![reg("rax"), reg("rcx")],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x2b, "jmp", vec![reg("rax")], Flow::Jmp(None)),
        ]);
        let table_at = BASE.wrapping_add(TABLE as u64);
        let read = |at: u64, len: usize| {
            (at == table_at && len == 8).then(|| {
                // One case before the base and one after it.
                [(-0x1000i32) as u32, 0x1000u32]
                    .iter()
                    .flat_map(|entry| entry.to_le_bytes())
                    .collect()
            })
        };

        let found = map(DISPATCH, &block, Layout::X64, read, in_image, never);

        assert_eq!(
            found
                .cases
                .iter()
                .map(|case| (case.code, case.lands))
                .collect::<Vec<_>>(),
            vec![(0x222000, BASE - 0x1000), (0x222001, BASE + 0x1000)],
            "the negative entry is a displacement backwards: {:?}",
            found.cases
        );
        assert!(found.unresolved.is_empty(), "{:?}", found.unresolved);
    }

    /// An indirect jump with no bounds check is **recorded**, not dropped.
    ///
    /// Which is the whole difference between a short answer and a wrong one: a driver whose switch
    /// this cannot resolve must not read as a driver that accepts the two codes before it.
    #[test]
    fn an_unresolved_transfer_is_recorded_rather_than_dropped() {
        let mut block = prologue(DISPATCH);
        block.extend([
            insn(
                DISPATCH + 8,
                "cmp",
                vec![reg("r13d"), imm(0x6d0008)],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0xe, "je", Vec::new(), Flow::Branch(Some(0x900))),
            insn(
                DISPATCH + 0x14,
                "jmp",
                vec![mem("rbx", 0x40)],
                Flow::Jmp(None),
            ),
        ]);

        let found = map(DISPATCH, &block, Layout::X64, unreadable, in_image, never);

        assert_eq!(found.cases.len(), 1, "{:?}", found.cases);
        assert_eq!(
            found.unresolved,
            vec![DISPATCH + 0x14],
            "the switch this could not follow is in the answer"
        );
        assert!(found.tables.is_empty());
    }

    /// A table whose bytes will not read produces no cases and leaves the jump unresolved, rather
    /// than a table of whatever the reader returned.
    #[test]
    fn a_table_that_will_not_read_leaves_the_jump_unresolved() {
        const IMAGE: u64 = 0xfffff803_3e250000;
        let mut block = prologue(DISPATCH);
        block.extend([
            insn(
                DISPATCH + 8,
                "mov",
                vec![reg("eax"), reg("r13d")],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xb,
                "cmp",
                vec![reg("eax"), imm(1)],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0xe, "ja", Vec::new(), Flow::Branch(Some(0xfa11))),
            insn(
                DISPATCH + 0x14,
                "lea",
                vec![reg("rcx"), at_address(IMAGE)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x1b,
                "mov",
                vec![reg("eax"), indexed(Some("rcx"), "rax", 0x9000, None)],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x22, "jmp", vec![reg("rax")], Flow::Jmp(None)),
        ]);

        let found = map(DISPATCH, &block, Layout::X64, unreadable, in_image, never);

        assert!(found.cases.is_empty(), "{:?}", found.cases);
        assert_eq!(found.unresolved, vec![DISPATCH + 0x22]);
    }

    /// A table with no bounds check is **not** followed, however readable its bytes are.
    ///
    /// The fixture is the resolved one minus the `cmp`/`ja`, with a reader that would happily
    /// serve a table: so a pass that guessed a length would produce cases here, and the assertion
    /// that there are none is about the guess rather than about the read. A length invented by
    /// the analyser is a list of addresses that happen to follow the table, reported as codes the
    /// driver accepts.
    #[test]
    fn a_table_with_no_bounds_check_is_not_followed() {
        const IMAGE: u64 = 0xfffff803_3e250000;
        const TABLE: i64 = 0x9000;
        let mut block = prologue(DISPATCH);
        block.extend([
            insn(
                DISPATCH + 8,
                "mov",
                vec![reg("eax"), reg("r13d")],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xb,
                "sub",
                vec![reg("eax"), imm(0x6dc004)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x11,
                "shr",
                vec![reg("eax"), imm(2)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x1d,
                "lea",
                vec![reg("rcx"), at_address(IMAGE)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x24,
                "mov",
                vec![reg("eax"), indexed(Some("rcx"), "rax", TABLE, None)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x2b,
                "add",
                vec![reg("rax"), reg("rcx")],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x2e, "jmp", vec![reg("rax")], Flow::Jmp(None)),
        ]);
        let served = std::cell::Cell::new(0usize);
        let read = |_: u64, len: usize| {
            served.set(served.get() + 1);
            Some(vec![0u8; len])
        };

        let found = map(DISPATCH, &block, Layout::X64, read, in_image, never);

        assert!(found.cases.is_empty(), "{:?}", found.cases);
        assert!(found.tables.is_empty(), "{:?}", found.tables);
        assert_eq!(found.unresolved, vec![DISPATCH + 0x2e]);
        assert_eq!(
            served.get(),
            0,
            "nothing was read: a table with no length is not read at a guessed one"
        );
    }

    /// A `+0x18` this could not trace to the IRP still answers, and says that it could not.
    #[test]
    fn a_code_not_traced_to_the_irp_is_answered_and_flagged() {
        let block = vec![
            insn(
                DISPATCH,
                "mov",
                vec![reg("r13d"), mem("rbx", 0x18)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 4,
                "cmp",
                vec![reg("r13d"), imm(0x222003)],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0xa, "je", Vec::new(), Flow::Branch(Some(0xc00))),
            insn(DISPATCH + 0x10, "ret", Vec::new(), Flow::Return),
        ];

        let found = map(DISPATCH, &block, Layout::X64, unreadable, in_image, never);

        assert_eq!(found.cases.len(), 1, "{:?}", found.cases);
        assert_eq!(found.cases[0].code, 0x222003);
        assert!(
            !found.code_proved,
            "the chain was not followed and the answer says so"
        );
    }

    /// An **exact** size needs two things: equality must be what the case continues on, and the
    /// other edge must be the one that fails.
    ///
    /// Three cases, each of which a weaker rule reports wrongly. The first branches away on
    /// inequality to a block that sets `STATUS_INVALID_PARAMETER` and returns, so 0x20 is
    /// required. The second makes the same compare and branches to a **handler**: the driver
    /// accepts the unequal length and reporting 0x20 as its size is a requirement it does not
    /// have. The third is a floor, which says nothing about the size of a buffer at all.
    ///
    /// All three are reported as evidence; only the first is a size.
    #[test]
    fn an_exact_size_needs_the_failing_edge_as_well_as_the_condition() {
        let mut block = prologue(DISPATCH);
        block.extend([
            insn(
                DISPATCH + 8,
                "cmp",
                vec![reg("r13d"), imm(0x222003)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xe,
                "je",
                Vec::new(),
                Flow::Branch(Some(DISPATCH + 0x40)),
            ),
            insn(
                DISPATCH + 0x14,
                "cmp",
                vec![reg("r13d"), imm(0x222007)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x1a,
                "je",
                Vec::new(),
                Flow::Branch(Some(DISPATCH + 0x60)),
            ),
            insn(
                DISPATCH + 0x20,
                "cmp",
                vec![reg("r13d"), imm(0x22200b)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x26,
                "je",
                Vec::new(),
                Flow::Branch(Some(DISPATCH + 0x90)),
            ),
            insn(DISPATCH + 0x2c, "ret", Vec::new(), Flow::Return),
            // Exactly 0x20 input bytes, or the path leaves for the failure tail.
            insn(
                DISPATCH + 0x40,
                "cmp",
                vec![mem("rax", 0x10), imm(0x20)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x47,
                "jne",
                Vec::new(),
                Flow::Branch(Some(DISPATCH + 0xb0)),
            ),
            insn(
                DISPATCH + 0x4d,
                "call",
                vec![Operand::Target(0x5000)],
                Flow::Call(Some(0x5000)),
            ),
            insn(DISPATCH + 0x52, "ret", Vec::new(), Flow::Return),
            // The same compare, branching to a handler: the unequal length is what is handled.
            insn(
                DISPATCH + 0x60,
                "cmp",
                vec![mem("rax", 0x10), imm(0x20)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x67,
                "jne",
                Vec::new(),
                Flow::Branch(Some(DISPATCH + 0xd0)),
            ),
            insn(DISPATCH + 0x6d, "ret", Vec::new(), Flow::Return),
            // A floor.
            insn(
                DISPATCH + 0x90,
                "cmp",
                vec![mem("rax", 0x10), imm(0x20)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x97,
                "jb",
                Vec::new(),
                Flow::Branch(Some(DISPATCH + 0xb0)),
            ),
            insn(DISPATCH + 0x9d, "ret", Vec::new(), Flow::Return),
            // The failure tail: `STATUS_INVALID_PARAMETER`, then a return.
            insn(
                DISPATCH + 0xb0,
                "mov",
                vec![reg("eax"), imm(0xc000_000d)],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0xb5, "ret", Vec::new(), Flow::Return),
            // And a handler, which is not a failure however it is reached.
            insn(
                DISPATCH + 0xd0,
                "call",
                vec![Operand::Target(0x6000)],
                Flow::Call(Some(0x6000)),
            ),
            insn(DISPATCH + 0xd5, "ret", Vec::new(), Flow::Return),
        ]);

        let found = map(DISPATCH, &block, Layout::X64, unreadable, in_image, never);

        assert_eq!(
            found
                .cases
                .iter()
                .map(|case| (case.code, case.in_size.map(|size| (size.value, size.exact))))
                .collect::<Vec<_>>(),
            vec![
                (0x222003, Some((0x20, true))),
                (0x222007, Some((0x20, false))),
                (0x22200b, Some((0x20, false))),
            ],
            "only the check whose other edge fails is a size: {:?}",
            found.cases
        );
    }

    /// A case whose block sets an NTSTATUS error and returns is one the driver **rejects**.
    ///
    /// `cmp code,N` / `je invalid_request` and `je handler` are the same instructions, so a case
    /// list that reports both as accepted sends a reader to test a code the driver refuses. The
    /// evidence is the block itself: an error status returned, against a block that reaches a
    /// routine.
    #[test]
    fn a_case_that_returns_an_error_status_is_reported_as_rejected() {
        let mut block = prologue(DISPATCH);
        block.extend([
            insn(
                DISPATCH + 8,
                "cmp",
                vec![reg("r13d"), imm(0x222003)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xe,
                "je",
                Vec::new(),
                Flow::Branch(Some(DISPATCH + 0x40)),
            ),
            insn(
                DISPATCH + 0x14,
                "cmp",
                vec![reg("r13d"), imm(0x222007)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x1a,
                "je",
                Vec::new(),
                Flow::Branch(Some(DISPATCH + 0x60)),
            ),
            insn(DISPATCH + 0x20, "ret", Vec::new(), Flow::Return),
            // Rejected: `STATUS_INVALID_DEVICE_REQUEST`, then a return.
            insn(
                DISPATCH + 0x40,
                "mov",
                vec![reg("eax"), imm(0xc000_0010)],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x45, "ret", Vec::new(), Flow::Return),
            // Handled.
            insn(
                DISPATCH + 0x60,
                "call",
                vec![Operand::Target(0x5000)],
                Flow::Call(Some(0x5000)),
            ),
            insn(DISPATCH + 0x65, "ret", Vec::new(), Flow::Return),
        ]);

        let found = map(DISPATCH, &block, Layout::X64, unreadable, in_image, never);

        assert_eq!(
            found
                .cases
                .iter()
                .map(|case| (case.code, case.accepted))
                .collect::<Vec<_>>(),
            vec![(0x222003, Some(false)), (0x222007, Some(true))],
            "{:?}",
            found.cases
        );
    }

    /// A 32-bit driver's fields are at 32-bit offsets, and the layout is picked by the target.
    ///
    /// The same instructions read with the x64 numbers find no control code at all: `+0x60` is not
    /// `+0xb8` and `+0x0c` is not `+0x18`. Both directions are asserted here, because a layout
    /// that is merely *different* would pass a test that only checked the right one — what makes
    /// this a real answer is that the wrong layout finds nothing rather than something else.
    ///
    /// Nothing is proved on x86: both arguments arrive on the stack, so the chain from the IRP
    /// cannot be followed and the code comes from the bare displacement.
    #[test]
    fn a_32_bit_driver_is_read_with_32_bit_offsets() {
        let block = vec![
            // `mov esi,[ebp+0Ch]` -- the Irp, off the frame. Nothing here can know that, which is
            // the point: what follows is recognised by displacement alone.
            insn(
                DISPATCH,
                "mov",
                vec![reg32("esi"), mem32("ebp", 0x0c)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 3,
                "mov",
                vec![reg32("edi"), mem32("esi", 0x60)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 6,
                "mov",
                vec![reg32("ebx"), mem32("edi", 0x0c)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 9,
                "cmp",
                vec![reg32("ebx"), imm(0x222003)],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0xf, "je", Vec::new(), Flow::Branch(Some(0x900))),
            insn(DISPATCH + 0x15, "ret", Vec::new(), Flow::Return),
        ];

        let found = map(DISPATCH, &block, Layout::X86, unreadable, in_image, never);

        assert_eq!(
            found
                .cases
                .iter()
                .map(|case| (case.code, case.proved))
                .collect::<Vec<_>>(),
            vec![(0x222003, false)],
            "{:?}",
            found.cases
        );
        assert!(!found.code_proved, "the IRP is on the stack on x86");

        let wrong = map(DISPATCH, &block, Layout::X64, unreadable, in_image, never);

        assert!(
            wrong.cases.is_empty(),
            "the 64-bit offsets find nothing here: {:?}",
            wrong.cases
        );
    }

    /// `jae default` admits one fewer index than `ja default`, and that is one table entry.
    ///
    /// The exclusive form leaves `0..N` on the path where the inclusive one leaves `0..=N`, so
    /// reading `limit + 1` entries either way takes one dword past the end of the table — which
    /// becomes a control code the driver is reported as accepting whenever that dword happens to
    /// resolve inside the image, as the fixture's fourth entry deliberately does.
    #[test]
    fn an_exclusive_bound_reads_one_entry_fewer() {
        const TABLE: i64 = 0x9000;
        let table_at = IMAGE_BASE.wrapping_add(TABLE as u64);
        let read = |at: u64, len: usize| {
            (at == table_at).then(|| {
                [0x1000u32, 0x2000, 0x3000, 0x4000]
                    .iter()
                    .flat_map(|rva| rva.to_le_bytes())
                    .take(len)
                    .collect()
            })
        };
        let switch = |jcc: &str| {
            let mut block = prologue(DISPATCH);
            block.extend([
                insn(
                    DISPATCH + 8,
                    "mov",
                    vec![reg("eax"), reg("r13d")],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0xb,
                    "sub",
                    vec![reg("eax"), imm(0x222000)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x11,
                    "cmp",
                    vec![reg("eax"), imm(3)],
                    Flow::Fallthrough,
                ),
                insn(DISPATCH + 0x14, jcc, Vec::new(), Flow::Branch(Some(0xfa11))),
                insn(
                    DISPATCH + 0x1a,
                    "lea",
                    vec![reg("rcx"), at_address(IMAGE_BASE)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x21,
                    "mov",
                    vec![reg("eax"), indexed(Some("rcx"), "rax", TABLE, None)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x28,
                    "add",
                    vec![reg("rax"), reg("rcx")],
                    Flow::Fallthrough,
                ),
                insn(DISPATCH + 0x2b, "jmp", vec![reg("rax")], Flow::Jmp(None)),
            ]);
            block
        };

        let inclusive = map(DISPATCH, &switch("ja"), Layout::X64, read, in_image, never);
        let exclusive = map(DISPATCH, &switch("jae"), Layout::X64, read, in_image, never);
        let signed = map(DISPATCH, &switch("jg"), Layout::X64, read, in_image, never);

        assert_eq!(inclusive.cases.len(), 4, "0..=3: {:?}", inclusive.cases);
        assert_eq!(exclusive.cases.len(), 3, "0..3: {:?}", exclusive.cases);
        assert!(
            signed.cases.is_empty() && signed.unresolved == vec![DISPATCH + 0x2b],
            "a signed compare proves nothing about an unsigned index: {signed:?}"
        );
    }

    /// An instruction that could not be read is **counted**, not merely stepped over.
    ///
    /// It may be the compare that recognises a code, so a case list short by one would otherwise
    /// read as a complete one: the walk did not stop, no bound was hit, and nothing was left
    /// unresolved. On a dump missing a code page that is the whole difference.
    #[test]
    fn an_instruction_that_would_not_read_is_counted() {
        let mut block = prologue(DISPATCH);
        block.extend([
            insn(
                DISPATCH + 8,
                "cmp",
                vec![reg("r13d"), imm(0x222003)],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0xe, "je", Vec::new(), Flow::Branch(Some(0x900))),
            // The barrier `crate::driver::in_listing_order` leaves where an address did not
            // decode.
            insn(DISPATCH + 0x14, "", Vec::new(), Flow::Unreadable),
            insn(
                DISPATCH + 0x15,
                "cmp",
                vec![reg("r13d"), imm(0x222007)],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x1b, "je", Vec::new(), Flow::Branch(Some(0x980))),
            insn(DISPATCH + 0x21, "ret", Vec::new(), Flow::Return),
        ]);

        let found = map(DISPATCH, &block, Layout::X64, unreadable, in_image, never);

        assert_eq!(found.blind, 1, "the barrier is a hole in the answer");
        assert!(
            found.halted.is_none() && !found.cap_hit && found.unresolved.is_empty(),
            "and nothing else says so: {found:?}"
        );
    }

    /// Provenance belongs to the **value**, so one routine can hold a proved case and a guessed
    /// one.
    ///
    /// A dispatch routine that compares some other structure's `+0x18` field before reading the
    /// real control code is the case a flag on the *routine* gets wrong: the guessed case borrows
    /// the traced one's credibility, and it is exactly the case a reader needs warning about.
    #[test]
    fn provenance_belongs_to_the_value_rather_than_the_routine() {
        let block = vec![
            // Some other structure's `+0x18`, which nothing traced to an IRP.
            insn(
                DISPATCH,
                "mov",
                vec![reg("r12d"), mem("rbx", 0x18)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 4,
                "cmp",
                vec![reg("r12d"), imm(0x111111)],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0xa, "je", Vec::new(), Flow::Branch(Some(0x800))),
            // And the real chain, after it.
            insn(
                DISPATCH + 0x10,
                "mov",
                vec![reg("rax"), pointer("rdx", 0xb8)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x14,
                "mov",
                vec![reg("r13d"), mem("rax", 0x18)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x18,
                "cmp",
                vec![reg("r13d"), imm(0x222003)],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x1e, "je", Vec::new(), Flow::Branch(Some(0x900))),
            insn(DISPATCH + 0x24, "ret", Vec::new(), Flow::Return),
        ];

        let found = map(DISPATCH, &block, Layout::X64, unreadable, in_image, never);

        assert_eq!(
            found
                .cases
                .iter()
                .map(|case| (case.code, case.proved))
                .collect::<Vec<_>>(),
            vec![(0x111111, false), (0x222003, true)],
            "{:?}",
            found.cases
        );
        assert!(
            !found.code_proved,
            "the aggregate is every case, not the one that was traced"
        );
    }

    /// A length check is about a buffer only if its base holds the IO_STACK_LOCATION, its compare
    /// is inside the case's own region, and the path continues on equality.
    ///
    /// Three ways to invent a size, and each needs its own construction: `cmp [rsp+10h],20h` is a
    /// stack slot rather than a length; a case that returns before checking anything would
    /// otherwise inherit the next case's compare, since `uf` prints regions in sequence; and
    /// `cmp length,0` / `je failure` *rejects* zero, so reading equality as the accepted edge
    /// reports a case requiring a zero-length buffer.
    #[test]
    fn a_length_check_needs_the_right_base_the_right_region_and_the_right_edge() {
        let mut block = prologue(DISPATCH);
        block.extend([
            insn(
                DISPATCH + 8,
                "cmp",
                vec![reg("r13d"), imm(0x222003)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xe,
                "je",
                Vec::new(),
                Flow::Branch(Some(DISPATCH + 0x40)),
            ),
            insn(
                DISPATCH + 0x14,
                "cmp",
                vec![reg("r13d"), imm(0x222007)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x1a,
                "je",
                Vec::new(),
                Flow::Branch(Some(DISPATCH + 0x60)),
            ),
            insn(
                DISPATCH + 0x20,
                "cmp",
                vec![reg("r13d"), imm(0x22200b)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x26,
                "je",
                Vec::new(),
                Flow::Branch(Some(DISPATCH + 0x80)),
            ),
            insn(DISPATCH + 0x2c, "ret", Vec::new(), Flow::Return),
            // The first case compares a **stack slot** at the same displacement.
            insn(
                DISPATCH + 0x40,
                "cmp",
                vec![mem("rsp", 0x10), imm(0x20)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x47,
                "jne",
                Vec::new(),
                Flow::Branch(Some(0xfa11)),
            ),
            insn(DISPATCH + 0x4d, "ret", Vec::new(), Flow::Return),
            // The second returns before checking anything, and the third's check follows it in
            // the listing.
            insn(DISPATCH + 0x60, "ret", Vec::new(), Flow::Return),
            insn(
                DISPATCH + 0x80,
                "cmp",
                vec![mem("rax", 0x10), imm(0x40)],
                Flow::Fallthrough,
            ),
            // Equality **leaves** the case, so this is a rejection rather than a size.
            insn(
                DISPATCH + 0x87,
                "je",
                Vec::new(),
                Flow::Branch(Some(0xfa11)),
            ),
            insn(DISPATCH + 0x8d, "ret", Vec::new(), Flow::Return),
        ]);

        let found = map(DISPATCH, &block, Layout::X64, unreadable, in_image, never);

        assert_eq!(
            found
                .cases
                .iter()
                .map(|case| (case.code, case.in_size.map(|size| (size.value, size.exact))))
                .collect::<Vec<_>>(),
            vec![
                (0x222003, None),
                (0x222007, None),
                (0x22200b, Some((0x40, false))),
            ],
            "a stack slot, an inherited check, and a rejection: {:?}",
            found.cases
        );
    }

    /// The handler is the first direct transfer out of the case block, and a block that decides
    /// something first has none to report.
    #[test]
    fn the_handler_is_the_first_direct_transfer_from_the_landing_site() {
        let mut block = prologue(DISPATCH);
        block.extend([
            insn(
                DISPATCH + 8,
                "cmp",
                vec![reg("r13d"), imm(0x222003)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xe,
                "je",
                Vec::new(),
                Flow::Branch(Some(DISPATCH + 0x40)),
            ),
            insn(
                DISPATCH + 0x14,
                "cmp",
                vec![reg("r13d"), imm(0x222007)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x1a,
                "je",
                Vec::new(),
                Flow::Branch(Some(DISPATCH + 0x60)),
            ),
            insn(DISPATCH + 0x20, "ret", Vec::new(), Flow::Return),
            insn(
                DISPATCH + 0x40,
                "mov",
                vec![reg("rcx"), reg("rdx")],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x43,
                "call",
                vec![Operand::Target(0x5000)],
                Flow::Call(Some(0x5000)),
            ),
            insn(DISPATCH + 0x48, "ret", Vec::new(), Flow::Return),
            insn(
                DISPATCH + 0x60,
                "test",
                vec![reg("rax"), reg("rax")],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x63,
                "je",
                Vec::new(),
                Flow::Branch(Some(0xfa11)),
            ),
            insn(
                DISPATCH + 0x69,
                "call",
                vec![Operand::Target(0x6000)],
                Flow::Call(Some(0x6000)),
            ),
        ]);

        let found = map(DISPATCH, &block, Layout::X64, unreadable, in_image, never);

        assert_eq!(
            found
                .cases
                .iter()
                .map(|case| (case.code, case.handler))
                .collect::<Vec<_>>(),
            vec![(0x222003, Some(0x5000)), (0x222007, None)],
            "a block that branches before it calls has no single handler: {:?}",
            found.cases
        );
    }

    /// The case list is bounded and the count stays exact past the bound.
    #[test]
    fn the_case_list_is_bounded_and_the_count_stays_exact() {
        let mut block = prologue(DISPATCH);
        let mut at = DISPATCH + 8;
        for index in 0..(MAX_CASES + 16) {
            block.push(insn(
                at,
                "cmp",
                vec![reg("r13d"), imm(0x222000 + index as u64)],
                Flow::Fallthrough,
            ));
            block.push(insn(
                at + 6,
                "je",
                Vec::new(),
                Flow::Branch(Some(0x900 + index as u64)),
            ));
            at += 12;
        }

        let found = map(DISPATCH, &block, Layout::X64, unreadable, in_image, never);

        assert_eq!(found.cases.len(), MAX_CASES, "the list stops");
        assert_eq!(
            found.case_count,
            MAX_CASES + 16,
            "and the count does not: {}",
            found.case_count
        );
        assert!(found.cap_hit);
        assert!(
            found.code_proved,
            "every one of these came through the IRP's stack location"
        );

        // **And neither does the provenance.** `code_proved` is about the whole routine, so a case
        // the cap dropped counts: read off the retained prefix it would report a map as wholly
        // traced while `case_count` includes one that came from a bare `+0x18` off a register
        // nothing followed -- which is exactly the case a reader needs warning about.
        block.extend([
            insn(
                at,
                "mov",
                vec![reg("r12d"), mem("rsi", 0x18)],
                Flow::Fallthrough,
            ),
            insn(
                at + 4,
                "cmp",
                vec![reg("r12d"), imm(0x333000)],
                Flow::Fallthrough,
            ),
            insn(at + 0xa, "je", Vec::new(), Flow::Branch(Some(0x8000))),
            insn(at + 0x10, "ret", Vec::new(), Flow::Return),
        ]);

        let mixed = map(DISPATCH, &block, Layout::X64, unreadable, in_image, never);

        assert_eq!(mixed.cases.len(), MAX_CASES);
        assert_eq!(mixed.case_count, MAX_CASES + 17);
        assert!(
            mixed.cases.iter().all(|case| case.proved),
            "the list this kept is all traced"
        );
        assert!(
            !mixed.code_proved,
            "and the one it dropped is not, which is what this says"
        );
        assert_eq!(
            mixed.unproved, 1,
            "and the figure printed under that warning counts it: read off the cases that were \
             kept it is zero, under a warning that fired because of the one that was not"
        );
    }

    /// A halted walk says so rather than answering as one that finished.
    #[test]
    fn a_halted_walk_says_so() {
        let mut block = prologue(DISPATCH);
        let mut at = DISPATCH + 8;
        for index in 0..1024u64 {
            block.push(insn(
                at,
                "cmp",
                vec![reg("r13d"), imm(0x222000 + index)],
                Flow::Fallthrough,
            ));
            block.push(insn(at + 6, "je", Vec::new(), Flow::Branch(Some(0x900))));
            at += 12;
        }
        let mut polls = 0;
        let halt = || {
            polls += 1;
            (polls > 1).then_some(Halt::Deadline)
        };

        let found = map(DISPATCH, &block, Layout::X64, unreadable, in_image, halt);

        assert_eq!(found.halted, Some(Halt::Deadline));
        assert!(
            found.examined < block.len(),
            "the walk stopped where the halt landed: {} of {}",
            found.examined,
            block.len()
        );
    }
}
