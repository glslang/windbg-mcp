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
//! flow the decoder already answers, and the facts here travel along those edges: a bounds check
//! holds on the path it admits and not on the one it rejects, and a case block is read with the
//! facts of the path that reaches it. What a block **knows** is what every path into it agrees on;
//! what a block's branches can **decide** is whatever any path into it left them -- a comparison
//! and a lost code are claims about the path that made them, so they are unioned where a register's
//! value is intersected.
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
//! Like [`dbgscope::pe`], [`crate::hazards`] and [`crate::driver`], every entry point takes closures
//! rather than a `DebugEngine`: a decoded function, a reader for the image's own bytes, and a
//! halt poll. So every case below is unit-tested against a hand-built instruction list with no
//! debugger anywhere near it.

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};

use dbgscope::dbgeng::{Condition, Effect, Flow, Instruction, MemoryOperand, Operand};

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
/// The most entries followed out of one jump table. An entry is at most [`TABLE_ENTRY`] bytes, so
/// this is also what bounds the reading.
pub(crate) const MAX_TABLE_ENTRIES: usize = 4096;
/// The **widest** entry in a switch table: a `DWORD`, which is the only width x86 emits and the
/// only one that can hold a whole address. A64 sizes the entry to the routine instead, so
/// [`entry_width`] is what a load is actually read at and this is the ceiling.
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
    /// The status standing where this case was recognised, for a case the graph has no edge to.
    /// Empty for a compare case, whose landing block's own facts carry it.
    pub(crate) status: Status,
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
    /// Where the control code stopped being followable, by address.
    ///
    /// An instruction that carried it into something this pass does not model, with a branch
    /// reading the flags it wrote -- so the test after it is about the code and could not be
    /// attributed to one. **The other way a case list is a lower bound**, and until HEVD it was
    /// the invisible one: that driver steps its chain with `sub ecx,eax`, so the walk followed the
    /// first code and silently lost twenty-four, reporting four with `unresolved` empty and
    /// nothing else set. Bounded like [`Self::unresolved`], and by the same cap.
    pub(crate) untracked: Vec<u64>,
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
    /// A literal a `mov` put in a register, which is how a status reaches the IRP: MSVC writes
    /// `mov ecx,0C0000010h` / `mov [rbx+30h],ecx` as readily as it writes the constant into the
    /// field, and the second of those says nothing about a refusal on its own.
    Literal(u32),
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
    /// Whether this target spells a constant it cannot encode as a **PC-relative literal load**,
    /// which is what makes such a load readable as an immediate rather than as a memory access.
    ///
    /// **An architectural gate and not a shape test, because the shape is ambiguous.** A64 has no
    /// instruction that can materialise an arbitrary 32-bit constant, so a compiler emits either
    /// `movz`/`movk` or `ldr w20,<pool>` -- and the literal form has *no base register*, because
    /// nothing at run time contributes to its address. A global on A64 does not look like that: it
    /// is `adrp x8,<page>` plus `ldr w8,[x8,#off]`, which has one. So on A64 the no-base form is
    /// the pool and reading it is reading the immediate the encoding could not hold.
    ///
    /// On x86 and x64 the identical operand -- no base, no index, an absolute `address` -- is a
    /// **global read**: `mov eax,[00401000h]`, or a RIP-relative load of the driver's own mutable
    /// data. Folding those would publish whatever the driver last wrote there as a constant it
    /// compares control codes against, which is the class of wrong answer this module is arranged
    /// against. Hence a flag per target rather than one rule for all three.
    literal_pool: bool,
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
        literal_pool: false,
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
        literal_pool: false,
        status_field: 0x18,
        volatile: &["eax", "ecx", "edx"],
        irp_register: None,
    };
    /// **The same structures as [`Self::X64`] and none of the same registers.** Both are 64-bit
    /// targets, so every offset here is that layout's -- the IRP is laid out around a pointer and
    /// nothing about it is x86's. What does not carry over is every register name, and that is the
    /// reason this exists rather than ARM64 sharing the x64 constant: a layout is a statement
    /// about the *target*, and an x64 one applied to an ARM64 driver seeds the IRP into a register
    /// that target has never heard of, so no chain is ever traced and every case falls back to the
    /// bare displacement.
    ///
    /// The `volatile` list is the one that would fail quietly rather than emptily. Spelled in
    /// x86's registers it matches nothing an A64 decoder ever names, so a `call` would invalidate
    /// **nothing** -- and a literal surviving a call is a compare after it reported as a control
    /// code the driver accepts. That is the failure this field's own documentation describes, and
    /// it is the one an architecture falling through to a neighbour's layout arrives at.
    ///
    /// Windows on ARM64 makes `x0`-`x17` volatile and reserves `x18` as the platform register, so
    /// `x18` is deliberately **not** here; `x19`-`x28` are callee-saved. The link register is
    /// clobbered by every call and the decoder spells it `lr`, which is the spelling this list has
    /// to use -- these are matched against `RegisterOperand::full`.
    pub(crate) const ARM64: Self = Self {
        current_stack_location: 0xb8,
        control_code: 0x18,
        input_length: 0x10,
        output_length: 0x08,
        return_register: "x0",
        pointer: 8,
        literal_pool: true,
        status_field: 0x30,
        volatile: &[
            "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13",
            "x14", "x15", "x16", "x17", "lr",
        ],
        // AAPCS64's second argument, which is where a dispatch routine's `Irp` arrives.
        irp_register: Some("x1"),
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
    /// A compare whose flags are still live, for a branch in a **later** block to read.
    ///
    /// `cmp r13d,N` / `ja default` / `je handler` is one compare feeding two conditional branches
    /// -- the three-way test a compiler emits for a binary-search dispatch. A conditional branch
    /// ends a block, so the `cmp` and the `je` are in different ones, and without this the second
    /// began with no pending compare and dropped the case silently: no unresolved transfer, no
    /// blind instruction, nothing in the answer saying a code had gone. Measured on `mountmgr`,
    /// where it cost `0x6dc000` outright and one of `0x6d4020`'s two sites.
    ///
    /// **Which edges carry it is the whole rule**, and [`equality_survives`] is that rule: an
    /// edge carries the compare exactly where an equality against it is still possible. Past
    /// `ja K` *taken* the code is above `K`, so a case built there would be invented; past `je K`
    /// not taken it is not `K`; and past `jne K` not taken the case is already recorded by the
    /// branch itself. A terminator that asks no question -- a fall-through, a call, an
    /// unconditional jump -- rules nothing out and so carries it everywhere it goes.
    ///
    /// **A set, because it is a fact about the path that left it rather than about this block.**
    /// A register's value has to hold *here*, so a join keeps only what every path agrees on. A
    /// comparison says what a branch below decides **on the path that made it**, and an execution
    /// taking that path reaches the case whatever the others did -- so the paths are unioned, not
    /// intersected. Intersecting cost `cmp code,K` / `jb other` / `je handler` its case outright
    /// whenever anything else reached that `je`, with no `untracked` either, because nothing had
    /// been lost. Bounded by the number of comparison sites that reach the block, each appearing
    /// once: a flag-writing instruction replaces the whole set with the one it leaves, so within a
    /// block there is never more than one.
    pending: Vec<Compared>,
    /// An instruction that took the control code somewhere unmodelled, whose flags are still live.
    ///
    /// Carried for the reason [`Self::pending`] is, and it is the same gap: `and ecx,mask` / `ja
    /// next` / `je handler` puts the loss in one block and the branch that makes it matter in the
    /// next, and a loss that stops at a block boundary is a short case list with nothing saying so.
    ///
    /// **It survives on both edges**, where a compare does not. `equality_survives` can rule an
    /// edge out because a comparison's flags are known; nothing is known about what an unmodelled
    /// operation did, so neither edge of a branch reading it has ruled anything out.
    lost: Option<u64>,
    /// Where a refusal's status stands, which is a fact about the path like the rest of these.
    ///
    /// **It used to be computed inside whichever block was being read for a refusal**, which made
    /// it the one thing here that did not cross an edge: a routine that stores the error into the
    /// IRP *before* deciding -- `mov [rbx+30h],0C0000010h` / `cmp code,N` / `je complete` -- had
    /// the store in one block and the completion in another, and the second was read as though the
    /// first had not happened. Every way of carrying it across one edge at a time was another
    /// round of this; carried as a fact, it crosses all of them and joins at merges the way a
    /// register's value does -- kept only where every path into a block agrees, which is the same
    /// conservatism, from the same place.
    status: Status,
}

impl Facts {
    /// What two paths into one block leave it holding.
    ///
    /// **Two kinds of fact, joined in opposite directions**, and reading them as one kind is the
    /// mistake this has now been on both sides of. A register's value, a bounds check and a
    /// refusal's status must hold *here*, so a fact that is not on every edge is not a fact at the
    /// join -- a register holding the control code on one path and something else on another holds
    /// neither. A live comparison and a lost code are claims about the **path that made them**: an
    /// execution taking that path reaches what they decide whatever the other edges did, so they
    /// are unioned. Intersecting those dropped real cases with nothing in the answer saying so,
    /// which is the failure the whole of this walk is arranged against.
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
        // **A compare is not the same kind of fact as a register's value, which is what the
        // rule above gets right and this one got wrong by copying it.** A register has to hold
        // its value *here*, so a join keeps what every path agrees on. A comparison says what the
        // branch below decides **on the path that made it** -- and an execution taking that path
        // reaches the case whatever the other edges did. So they are unioned. Intersecting them
        // dropped a real case with nothing saying so: no `untracked`, because nothing was lost.
        // Sorted by where the comparison is, so the order does not depend on which edge the walk
        // took first.
        for was in &other.pending {
            if !self.pending.contains(was) {
                self.pending.push(was.clone());
                changed = true;
            }
        }
        self.pending.sort_by_key(|was| (was.at, was.code));
        // The same rule, for the same reason. A loss asserts *doubt*, and doubt on any path in is
        // doubt here: a branch below is code-dependent on that path whatever the others did. The
        // lower address is kept when both have one, so the answer does not depend on which edge
        // the walk took first.
        let joined = match (self.lost, other.lost) {
            (Some(ours), Some(theirs)) => Some(ours.min(theirs)),
            (ours, theirs) => ours.or(theirs),
        };
        changed |= joined != self.lost;
        self.lost = joined;
        // A status only where **every** path into the block has one, for the reason a register's
        // value is: a refusal one path establishes is not one the block makes.
        let status = Status {
            returned: self.status.returned && other.status.returned,
            irp: self.status.irp && other.status.irp,
        };
        changed |= status != self.status;
        self.status = status;
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
/// Where every jump table in this listing sends control, as `(jump site, targets)`.
///
/// **`FOLLOWUPS.md` item 83.** `ioctl_map` resolves A64 switch tables and
/// [`crate::driver::reachability`] does not, so since windbg-mcp#345 the two tools disagree about
/// the same driver: the map names a handler that the reachability walk calls NOT REACHABLE, and the
/// tool's advice is to pass the handler's address by hand to scope past the switch.
///
/// **The same walk answers both, which is the point rather than an economy.** The alternative was
/// extracting [`follow_table`]'s table read out of the fact tracking it is built around, and two
/// resolvers would then have to agree about a table's base, its bound, its entry width, its byte
/// map and its fold -- six things this module has been wrong about once each, and a second copy is
/// six more chances. Running [`map`] instead costs the control-code analysis nobody asked for here,
/// and buys the property that matters: a target this returns is a target `ioctl_map` publishes, so
/// the two tools cannot disagree.
///
/// Every bound comes with it -- the sweep budget, `halt`, `MAX_TABLES`, `MAX_TABLE_ENTRIES`, and
/// the refusal to resolve a table whose base, scale or bound was not recovered. A table this
/// declines contributes **no** targets, which leaves the reachability walk ending at that jump
/// exactly as it does today: its REACHABLE verdict stays sound because every edge here is one the
/// resolver proved, and its NOT REACHABLE stays best-effort, which is already the contract.
///
/// Grouped by site because a listing may hold more than one table, and a reachability walk must not
/// take the targets of one jump for another's -- an edge that does not exist would make a REACHABLE
/// verdict unsound, which is the one direction that walk may not be wrong in.
///
/// **A halted map yields no targets, and says so.** [`map`] can stop during case enrichment and
/// return a retained *prefix* of its cases with [`Map::halted`] set. Those edges are individually
/// sound -- the resolver proved each one -- but handing them over silently lets the walk reach its
/// goal through them and answer a clean `REACHABLE`, with nothing recording that the analysis
/// behind that verdict was cut short. A verdict is about the graph that was explored, so the halt
/// travels with the answer and the caller reports it; the targets are dropped rather than used,
/// because a prefix is not the table.
pub(crate) fn jump_targets(
    entry: u64,
    block: &[Instruction],
    layout: Layout,
    read: impl FnMut(u64, usize) -> Option<Vec<u8>>,
    in_image: impl Fn(u64) -> bool,
    is_constant: impl Fn(u64) -> bool,
    halt: impl FnMut() -> Option<Halt>,
) -> (Vec<(u64, Vec<u64>)>, Option<Halt>) {
    let found = map(entry, block, layout, read, in_image, is_constant, halt);
    if let Some(why) = found.halted {
        return (Vec::new(), Some(why));
    }
    let mut by_site: Vec<(u64, Vec<u64>)> = Vec::new();
    for case in found
        .cases
        .iter()
        .filter(|case| case.recovered == Recovery::JumpTable)
    {
        match by_site.iter_mut().find(|(site, _)| *site == case.site) {
            Some((_, targets)) => targets.push(case.lands),
            None => by_site.push((case.site, vec![case.lands])),
        }
    }
    // A switch's slots routinely share a landing -- several codes handled by one block -- and an
    // edge repeated is an edge walked twice for nothing.
    for (_, targets) in &mut by_site {
        targets.sort_unstable();
        targets.dedup();
    }
    (by_site, None)
}

/// How many literal-pool entries one routine may have read for it.
///
/// Each is an engine round trip, which over KD is tens of milliseconds -- so this is a bound on the
/// *cost* rather than on the shape, and a routine past it simply has its later literals unresolved.
/// That degrades to the behaviour before they were read at all: the compare against an unknown
/// value reports the site in [`Map::untracked`] instead of naming a code, which already says the
/// map is a lower bound. Far past any real dispatch routine, which holds a handful.
const MAX_POOL_READS: usize = 256;

/// The address a PC-relative literal load reads, where this target spells constants that way.
///
/// **One predicate, two callers**, deliberately: [`with_pool_immediates`] collects the addresses
/// and the rewrite it performs is read back by [`source_value`]'s ordinary immediate arm, so there
/// is no second description of the form to fall out of step with the first. That is the failure
/// this module has most often had -- two places agreeing about a shape until one of them is edited.
///
/// Four things are required and each excludes a real instruction that is not this:
/// - `layout.literal_pool`, which is the architectural gate its own documentation explains;
/// - [`Effect::Move`] and not [`Effect::MoveSigned`], so `ldrsw` is left alone: it sign-extends to
///   64 bits, and a status or a control code with its top bit set is then not the `ULONG` the
///   compare is about;
/// - no base and no index register, which on A64 is what tells a pool entry from a global;
/// - [`FIELD_WIDTH`], because every value this module folds is a `ULONG`. An eight-byte literal is
///   a pointer or a doubleword constant, and neither is a control code or a status.
fn pool_load(layout: Layout, instruction: &Instruction) -> Option<u64> {
    if !layout.literal_pool || instruction.effect != Effect::Move {
        return None;
    }
    let Some(Operand::Memory(memory)) = instruction.operands.get(1) else {
        return None;
    };
    (memory.base.is_none() && memory.index.is_none() && memory.size == Some(FIELD_WIDTH))
        .then_some(memory.address)?
}

/// The listing with every readable literal pool entry put back as the immediate it stands for.
///
/// **A rewrite before the walk rather than a reader inside it**, and the reason is that the walk
/// runs twice. The sweeps settle each block's facts and a later pass records from them, and the two
/// must agree about every value: a literal visible only to the recording pass would produce a case
/// the sweeps had not admitted, which is precisely the class of defect this module's history is
/// made of. Resolving first makes the two passes read the same instruction, and makes each address
/// cost **one** read however many times the block is swept.
///
/// It is also why nothing downstream needed changing. `ldr w8,<pool>` becomes `mov`-of-immediate
/// in every respect the walk asks about, so [`source_value`] folds it, [`scalar_of`] resolves a
/// compare against it, and [`status_after`] reads it as a refusal -- each through the arm it
/// already had for an immediate. The claim being made is not that a memory access is an immediate
/// in general; it is that **this** load is how A64 writes one the encoding could not hold.
///
/// `reads` and `writes` are left exactly as the decoder set them. A literal load names no base or
/// index, so it read no register to begin with, and the destination it writes is unchanged -- which
/// is what keeps [`note_loss`] answering as before. (It never saw one of these anyway: a loss is
/// recorded only for an instruction that writes flags, and a load writes none.)
///
/// Borrowed where nothing matched, so the x64 and x86 paths clone no listing and are bit-for-bit
/// the walk they were before this existed.
fn with_pool_immediates<'a>(
    block: &'a [Instruction],
    layout: Layout,
    read: &mut impl FnMut(u64, usize) -> Option<Vec<u8>>,
    is_constant: &impl Fn(u64) -> bool,
    halt: &mut impl FnMut() -> Option<Halt>,
) -> (Cow<'a, [Instruction]>, Option<Halt>) {
    if !layout.literal_pool {
        return (Cow::Borrowed(block), None);
    }
    // **Attempted, not resolved.** Keyed on every address asked about rather than on the ones that
    // answered, because a dump missing the page a pool sits on, or one malformed literal repeated
    // through a routine, would otherwise retry it per instruction and spend the whole read budget
    // on an address that will never read -- leaving the readable literals after it unfolded, so
    // recoverable codes disappear for want of a slot.
    let mut asked: HashMap<u64, Option<u32>> = HashMap::new();
    let mut reads = 0usize;
    let mut stopped = None;
    for instruction in block {
        let Some(address) = pool_load(layout, instruction) else {
            continue;
        };
        if asked.contains_key(&address) {
            continue;
        }
        // **The one thing the operand's shape does not prove.** A base-less `ldr` is a PC-relative
        // access and nothing more; it can legally address writable module storage, and folding that
        // would publish whatever the driver last wrote there as a control code or a refusal status
        // -- the false positive the per-target gate exists to avoid, arriving by another door.
        //
        // So the question is **storage class**: readable image memory the driver cannot write. That
        // is `.text` and `.rdata` and not `.data`, and it is deliberately *not* `in_image`, which
        // answers "is this address **code**" for a jump-table entry. Gating on that was the first
        // attempt and was wrong in the other direction: it argued from the encoding's ±1 MB reach
        // that a compiler must put the pool among the functions reading it, which confuses distance
        // with permissions -- `.rdata` ordinarily sits within a megabyte of `.text`, so a
        // legitimate pool there was refused without being read and the code it held stayed lost.
        // Widening `in_image` instead is not available: a jump-table entry landing in `.rdata` is
        // data published as a case, which is the failure that predicate exists for.
        if !is_constant(address) {
            asked.insert(address, None);
            continue;
        }
        if reads >= MAX_POOL_READS {
            break;
        }
        // Polled **between reads**, not once before them. Each is an engine round trip -- tens of
        // milliseconds over KD -- so a routine with many literals could otherwise spend seconds on
        // them after its caller had gone, before `map_within` reached its own first poll.
        //
        // **And the reason it is returned rather than merely obeyed: the poll consumes it.**
        // `DebugEngine::interrupted` is `GetInterrupt`, which clears the pending flag -- the worker
        // calls it elsewhere precisely to drain one. So a break seen here is a break `map_within`'s
        // own polls will never see, and breaking the loop without carrying the reason out left
        // `Map::halted` and the structured `stopped` field unset: an answer cut short by a Ctrl+Break
        // reported as a complete one. Raised on review of #351, against the poll added one commit
        // earlier for the other half of this.
        if let Some(why) = halt() {
            stopped = Some(why);
            break;
        }
        reads += 1;
        // The caller's reader is what bounds this to the module: it refuses an address outside the
        // module holding the routine, so a pool address computed from a malformed displacement
        // reads nothing rather than reaching another module's memory.
        let value = read(address, FIELD_WIDTH as usize)
            .and_then(|bytes| <[u8; 4]>::try_from(bytes.as_slice()).ok())
            .map(u32::from_le_bytes);
        asked.insert(address, value);
    }
    if asked.values().all(Option::is_none) {
        return (Cow::Borrowed(block), stopped);
    }
    let mut out = block.to_vec();
    for instruction in &mut out {
        let Some(address) = pool_load(layout, instruction) else {
            continue;
        };
        if let Some(Some(value)) = asked.get(&address)
            && let Some(operand) = instruction.operands.get_mut(1)
        {
            *operand = Operand::Immediate(u64::from(*value));
        }
    }
    (Cow::Owned(out), stopped)
}

pub(crate) fn map(
    dispatch: u64,
    block: &[Instruction],
    layout: Layout,
    read: impl FnMut(u64, usize) -> Option<Vec<u8>>,
    in_image: impl Fn(u64) -> bool,
    is_constant: impl Fn(u64) -> bool,
    halt: impl FnMut() -> Option<Halt>,
) -> Map {
    map_within(
        dispatch,
        block,
        layout,
        read,
        in_image,
        is_constant,
        halt,
        MAX_SWEEPS,
    )
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
    is_constant: impl Fn(u64) -> bool,
    mut halt: impl FnMut() -> Option<Halt>,
    sweeps: usize,
) -> Map {
    // **Before the graph, because every pass below reads this listing.** A64 spells a constant it
    // cannot encode as a PC-relative load, and resolving those here is what lets the sweeps and the
    // recording pass agree about the value -- see [`with_pool_immediates`]. Borrowed unchanged on a
    // target that has no literal pool, so nothing about x64 or x86 moves.
    let (listing, pool_halt) =
        with_pool_immediates(block, layout, &mut read, &is_constant, &mut halt);
    let block: &[Instruction] = &listing;
    let graph = cfg::graph(block);
    let index_of: HashMap<u64, usize> = block
        .iter()
        .enumerate()
        .map(|(index, instruction)| (instruction.address, index))
        .collect();

    // Seeded from the pool phase, because its poll **consumed** the break it saw and no later one
    // can find it. Everything below reads this the way it reads its own polls: the sweeps stop and
    // the recording pass refuses to start, so a halted walk reports nothing rather than reporting
    // from where it got to.
    let mut halted = pool_halt;
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
        // Already stopped, by this loop's own poll on an earlier sweep or by the pool phase before
        // it. Checked as well as polled, because the poll is consuming: a break the pool phase drained
        // is one `halt()` will answer `None` for, and a sweep budget spent after it is work done for
        // a caller who has gone.
        if halted.is_some() {
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
    let mut untracked: Vec<u64> = Vec::new();
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
                &mut untracked,
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
            &mut untracked,
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
    let refusals: std::cell::RefCell<HashMap<(usize, Option<Status>), bool>> =
        std::cell::RefCell::new(HashMap::new());
    let refuses_at = |from: usize, blind: Option<Status>| {
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
    // **Every field on a case that is listed is an answer.** `handler`, `accepted` and the sizes
    // are absent when the block gave no evidence for them, so a case this loop never reached would
    // say the same thing about a block nobody read -- indistinguishable, and the more misleading
    // of the two because the codes around it *were* read. So a stop here ends the list where it
    // ends the work, exactly as a bound does, and `case_count` stays exact over both.
    let mut enriched = 0usize;
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
        enriched += 1;
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
            // Nothing believed about any **register**, for the reason above -- but the status is
            // not a register, and where it stood at the jump is on the path to this landing.
            Recovery::JumpTable => Facts {
                status: case.status,
                ..Facts::default()
            },
            Recovery::Compare => entry[at].clone().unwrap_or_default(),
        };
        let instructions = &block[from..graph.blocks[at].end];
        case.handler = handler_in(instructions);
        let blind = match case.recovered {
            Recovery::JumpTable => Some(case.status),
            Recovery::Compare => None,
        };
        let refuses = refuses_at(from, blind);
        case.accepted = match (
            refuses,
            case.handler,
            // A jump target this listing does not hold is a routine of its own, and the block
            // reaching it returns whatever that routine does.
            error_status(instructions, layout, &facts, &|target| {
                !index_of.contains_key(&target)
            }),
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
                .is_some_and(|&from| refuses_at(from, None))
        });
        case.in_size = input;
        case.out_size = output;
    }
    cases.truncate(enriched);

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
        untracked,
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
    /// Whether that transfer was left unresolved by a **bound** rather than by a shape this walk
    /// does not read. Without it the answer says no bound ended anything early while a table
    /// larger than [`MAX_TABLE_ENTRIES`] is exactly why the switch is in `unresolved`.
    capped: bool,
    /// Whether a control code was traced from the IRP anywhere in this block.
    traced: bool,
    /// Instructions that carried the control code into something this pass cannot model, with a
    /// branch reading their flags. See [`lost_the_code`].
    untracked: Vec<u64>,
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
    untracked: &mut Vec<u64>,
    traced: &mut bool,
    blind: &mut usize,
    examined: &mut usize,
) {
    *traced |= run.traced;
    *cap_hit |= run.capped;
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
            Status::default(),
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
                resolved.status,
            );
        }
        if tables.len() < MAX_TABLES {
            tables.push(resolved.table);
        } else {
            *cap_hit = true;
        }
    }
    // Bounded by the same cap and for the same reason: a routine that loses the code in a
    // thousand places is one nobody reads a list of, and `cap_hit` carries the warning the list
    // would have.
    for at in run.untracked {
        if untracked.len() < MAX_UNRESOLVED {
            untracked.push(at);
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

/// The edges a pending compare survives on: `(taken, fall-through)`.
///
/// **Derived from the flags an equality leaves, not from a list of families.** `cmp a,b` with
/// `a == b` computes zero, and zero fixes every flag a conditional branch reads:
///
/// | flag | value | why |
/// |---|---|---|
/// | `ZF` | 1 | the result is zero |
/// | `CF` | 0 | equal values do not borrow |
/// | `OF` | 0 | nor overflow |
/// | `SF` | 0 | zero is not negative |
/// | `PF` | 1 | the low byte is `0x00`, an even number of set bits |
///
/// So equality is possible on an edge exactly when that edge's flag requirement agrees with this
/// row, and every condition the decoder has gets an answer rather than a shrug. Two of them were
/// wrong when this was a list: `jo`/`jp` and their negations were given both edges on the grounds
/// that they "say nothing about equality", when `OF=0` and `PF=1` say precisely which edge each of
/// them admits.
///
/// Getting an edge wrong costs both ways. A compare not carried where equality is possible loses a
/// case; one carried where equality is impossible **invents** one -- a `je` there can never be
/// taken, so the case is reported and never reached, which is worse because nothing about it says
/// so.
fn equality_survives(condition: Condition, flags: Equality) -> (bool, bool) {
    match condition {
        // The branch *is* the case, and the other edge knows the equality is false. Both are
        // already recorded where the terminator is read, so neither edge carries it on.
        Condition::Equal | Condition::NotEqual => (false, false),
        // `ZF=1` rules these out wherever they branch, whatever else the flags hold: `ja` and `jg`
        // both need `ZF=0`, and `js` needs the `SF=1` a zero does not leave.
        Condition::UnsignedAbove | Condition::SignedGreater | Condition::Negative => (false, true),
        // And `ZF=1` alone takes these, for the mirrored reason.
        Condition::UnsignedBelowOrEqual | Condition::SignedLessOrEqual | Condition::NotNegative => {
            (true, false)
        }
        // `PF=1`, always: the low byte of a zero has an even number of set bits.
        Condition::Parity => (true, false),
        Condition::NotParity => (false, true),
        // Carry, which a subtraction clears and an addition reaching zero sets.
        Condition::UnsignedBelow => (flags.carry, !flags.carry),
        Condition::UnsignedAboveOrEqual => (!flags.carry, flags.carry),
        // Overflow, which only an `add` of the sign bit alone sets -- and `jge`/`jl` read it
        // against the `SF=0` a zero leaves, so they follow it exactly.
        Condition::Overflow | Condition::SignedLess => (flags.overflow, !flags.overflow),
        Condition::NotOverflow | Condition::SignedGreaterOrEqual => {
            (!flags.overflow, flags.overflow)
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
    // **The compare this block was entered with**, taken rather than copied: it belongs to the
    // edge that arrived, and what leaves is decided per outgoing edge below.
    let mut compared: Vec<Compared> = std::mem::take(&mut facts.pending);
    let mut lost: Option<u64> = facts.lost.take();
    let mut traced = false;
    let mut untracked = Vec::new();
    // The loss the last flag-writing instruction left, carried exactly as `compared` is: whether
    // it matters is decided by what reads those flags, which is the terminator's business.
    let mut just_lost: Option<u64> = None;
    let mut blind = 0usize;
    let mut cases = Vec::new();
    let mut table = None;
    let mut unresolved = None;
    let mut capped = false;

    let instructions = &listing[block.start..block.end];
    let terminator = instructions.len().saturating_sub(1);
    for (position, instruction) in instructions.iter().enumerate() {
        if matches!(instruction.flow, Flow::Unreadable | Flow::Unknown) {
            blind += 1;
        }
        if position == terminator {
            break;
        }
        let next = update(&mut facts, instruction, layout, &mut traced, &mut just_lost);
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
            compared.clear();
            lost = None;
        } else if instruction.writes_flags {
            // A flag write replaces the whole set with the one comparison it leaves: every live
            // compare was about the flags this just overwrote.
            compared = next.into_iter().collect();
            lost = just_lost.take();
        }
    }

    let last = instructions.last();
    // The terminator reads the flags the block left and decides where control goes.
    if let Some(last) = last {
        match last.flow {
            Flow::Branch(target) => {
                // **A branch reading flags an unmodelled instruction wrote.** The compare is gone,
                // so there is a test on the control code here that cannot be named -- which is the
                // case the list would otherwise be short of with nothing saying so. Committed here
                // rather than where the value was lost, because an instruction nothing branches on
                // costs the answer nothing.
                // `compared` is deliberately not consulted: a flag-writing instruction
                // either leaves a compare or loses the code, never both, so `lost` being set
                // already means there is no compare here. Asserting it as well was dead.
                if let Some(at) = lost
                    && matches!(last.condition, Some(Condition::Equal | Condition::NotEqual))
                {
                    untracked.push(at);
                }
                // **A64 folds the compare into the branch**, and then there is exactly one
                // reading rather than one per live compare: the comparison is this instruction's
                // own, so no earlier path contributed one. Where the branch reads *flags*, every
                // live compare is still a reading -- two paths meeting at one `je` make two cases
                // at two `case_rva`s, which is the "a case per site" rule the rest of this module
                // keeps.
                let folded = folded_compare(&facts, last, layout, &mut traced);
                let readings: Vec<(Compared, Condition)> = match folded {
                    Some((was, condition)) => vec![(was, condition)],
                    None => match last.condition {
                        Some(condition) => compared
                            .iter()
                            .cloned()
                            .map(|was| (was, condition))
                            .collect(),
                        None => Vec::new(),
                    },
                };
                // **A conditional branch this could not read at all**, over a register holding the
                // control code. On A64 that is `tbz`/`tbnz` -- one bit of a `ULONG`, which is not
                // a value and so not a case -- and anything else that grows here lands in the same
                // arm rather than quietly shortening the list. `Flow::Branch` with no condition is
                // the compare-and-branch family and nothing else; an unconditional `b` is
                // `Flow::Jmp`, so this cannot fire on x86, where every conditional branch carries
                // one.
                if readings.is_empty()
                    && last.condition.is_none()
                    && branches_on_the_code(&facts, last)
                {
                    untracked.push(last.address);
                }
                for (was, condition) in &readings {
                    match (*condition, was.code) {
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
                        // **A test on the control code that could not be attributed to one.**
                        // `index` says the register held the code; `code` is `None` because the
                        // value it was compared against was not resolvable. That is a case this
                        // walk cannot name, and saying nothing about it is what let a map of four
                        // codes out of twenty-eight report itself complete.
                        (Condition::Equal | Condition::NotEqual, None) if was.index.is_some() => {
                            untracked.push(was.at);
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
                        &mut capped,
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
                //
                // **And so is the rest of the loop's rule.** A block ends where the next address
                // is a branch target, which is a fact about the compiler's labels rather than
                // about the instruction -- so the same `cmp`, `and` or `call` is stepped by the
                // loop above in one routine and by this arm in the next. A transition written in
                // only one of them is a rule that holds until a label lands one instruction
                // later, and it was written in only one, three ways over: a compare here left no
                // pending compare for the `je` below, a loss here left no `untracked`, and a loss
                // from earlier in the block outlived a call that had overwritten the flags it was
                // about. The first two are short case lists with nothing saying so; the third is
                // an `untracked` entry for a branch reading a callee's flags.
                let next = update(&mut facts, last, layout, &mut traced, &mut just_lost);
                if matches!(last.flow, Flow::Call(_)) {
                    compared.clear();
                    lost = None;
                } else if last.writes_flags {
                    compared = next.into_iter().collect();
                    lost = just_lost.take();
                }
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
    carried.pending = Vec::new();
    carried.lost = None;
    // **A compare outlives the branch that reads it, on whichever edges that branch has not ruled
    // equality out on.** See [`equality_survives`]: `ja` leaves it live where it falls through and
    // `jbe` where it branches, and getting that backwards loses a case on one edge and invents one
    // on the other.
    let (onward_taken, onward_fallen) = match (
        last.map(|last| last.flow),
        last.and_then(|last| last.condition),
    ) {
        (Some(Flow::Branch(_)), Some(condition)) => {
            // **Asked of each compare separately**, because the flags an equality would leave are
            // that comparison's own fact: one reached by a `sub` and one by an `add` answer `jae`
            // differently, and a set decided by whichever arrived first would be right about one
            // of them by luck.
            let mut taken = Vec::new();
            let mut fallen = Vec::new();
            for was in &compared {
                let (on_taken, on_fallen) = equality_survives(condition, was.equality);
                if on_taken {
                    taken.push(was.clone());
                }
                if on_fallen {
                    fallen.push(was.clone());
                }
            }
            (taken, fallen)
        }
        // **A terminator that decides no equality rules nothing out**, so the compare goes down
        // every edge the block has. `equality_survives` answers per edge precisely because a
        // condition is what lets one edge know the equality is false; a fall-through, a call or an
        // unconditional jump asks nothing and so takes nothing away. Answering `(None, None)` here
        // dropped the compare at every block boundary a compiler's label happened to fall on.
        _ => (compared.clone(), compared.clone()),
    };
    // **The compare that makes a bounds check, asked of each in turn.** A bound is a claim
    // about one register, so the compare that supplies it is the one whose index that register
    // still holds -- not whichever of them the join happened to put first.
    let bounding = match (
        last.map(|last| last.flow),
        last.and_then(|last| last.condition),
    ) {
        (Some(Flow::Branch(target)), Some(condition))
            if matches!(
                condition,
                Condition::UnsignedAbove | Condition::UnsignedAboveOrEqual
            ) =>
        {
            compared.iter().find_map(|was| {
                let (register, offset, shift) = was.index.clone()?;
                let limit = was.bound?;
                // **A bound is about the register's value from here on, so the register has to
                // still hold what was compared.** The pending compare deliberately outlives a
                // flag-neutral instruction between the `cmp` and its branch -- that is where a
                // compiler puts the case's setup -- but `cmp eax,2` / `mov eax,ecx` / `ja default`
                // leaves a bound describing a value `eax` no longer has, and a table indexed by
                // `eax` is then read to a limit nothing checked. The *case* built from the same
                // compare needs no such thing: a comparison that already happened is what the
                // branch reads, whatever the register holds by then.
                if facts.registers.get(&register)
                    != Some(&Value::Code {
                        offset,
                        shift,
                        proved: was.proved,
                    })
                {
                    return None;
                }
                let limit = match condition {
                    Condition::UnsignedAbove => limit,
                    _ => limit.checked_sub(1)?,
                };
                Some(Bound {
                    register,
                    offset,
                    shift,
                    limit,
                    // An index past the bound goes where this branch goes, and so does every slot
                    // of the table the compiler had no case for.
                    default: target,
                    proved: was.proved,
                })
            })
        }
        _ => None,
    };
    if let Some(bound) = bounding {
        let target = bound.default;
        let mut bounded = carried.clone();
        bounded.bound = Some(bound);
        if let Some(fall_through) = fall_through {
            bounded.pending = onward_fallen.clone();
            bounded.lost = lost;
            to.push((fall_through, bounded));
        }
        if let Some(taken) = target
            .and_then(|target| index_of.get(&target))
            .and_then(|&at| graph.holding(at))
        {
            let mut edge = carried.clone();
            edge.pending = onward_taken.clone();
            edge.lost = lost;
            to.push((taken, edge));
        }
    } else {
        // **A bound survives a branch that is about something else.** It is a claim about one
        // register's value, and every way that value can change already takes it away: a write
        // that is not the table pattern, a call over a volatile register, a join with a path that
        // never had it. Clearing it here as well would mean a bounds check only ever reaches the
        // block immediately after it, so a compiler that puts an unrelated test in between leaves
        // a switch unresolved -- an answer reported as a lower bound for no reason in the code.
        // The taken edge is the branch's own target; every other successor of a block that
        // does not branch carries nothing, which is what `equality_survives` answers `(false,
        // false)` for.
        let taken = match last.map(|last| last.flow) {
            Some(Flow::Branch(Some(target))) => {
                index_of.get(&target).and_then(|&at| graph.holding(at))
            }
            _ => None,
        };
        for &successor in &graph.blocks[index].successors {
            let mut edge = facts.clone();
            edge.pending = match (Some(successor) == fall_through, Some(successor) == taken) {
                (true, _) => onward_fallen.clone(),
                (_, true) => onward_taken.clone(),
                // An unconditional jump's destination is neither: the instruction after the block
                // is not a successor of one. The two values are the same wherever this is reached,
                // since only a conditional branch tells its edges apart.
                _ => onward_taken.clone(),
            };
            // No edge of a branch reading an unmodelled result has ruled anything out, so the loss
            // goes down both of them.
            edge.lost = lost;
            to.push((successor, edge));
        }
    }

    Run {
        to,
        cases,
        table,
        unresolved,
        capped,
        traced,
        untracked,
        blind,
        examined: instructions.len(),
    }
}

/// Whether a branch reading the flags this instruction wrote would be reading the control code.
///
/// **Two ways it can be, and the second is the general one.** A register that *carried* the code
/// and no longer does -- asked against the snapshot taken before the instruction ran, so it sees a
/// register written implicitly (`mul ecx`) and one clipped by a narrow write (`sub cx,1`) as
/// readily as the named destination. And an instruction that **reads** the code, because flags are
/// computed from it without it moving anywhere: `and eax,ecx` with the mask in `eax` leaves `ecx`
/// holding the code, and the `je` below is about a bit of it.
///
/// The second subsumes every shape the first was widened for one at a time -- a `test` of a
/// register holding the code, a `test` of the field itself, an `or`, a `mul`, a `bt` -- because it
/// is one question over what the decoder decoded rather than a clause per mnemonic. That
/// distinction is the whole point: a clause answers for the shapes somebody thought of, and
/// answers *nothing* for the rest, which is a case list that is short with nothing saying so.
///
/// Flag-writing only, which is what keeps it from being noise. The question is not "was a value
/// forgotten" -- copies lose values all the time and nothing branches on them -- but "is a branch
/// about to read flags this pass cannot attribute to a code". And it is recorded as **pending**
/// rather than as a finding: what makes it matter is decided by what reads those flags, so an
/// `and ecx,3` no branch ever looks at costs the answer nothing.
///
/// **And "reads" is the decoder's answer rather than the operand list's**, which is the same
/// distinction one level down: an operand list names the reads an instruction was *written* with,
/// so `mul ecx` reads `eax` and names it nowhere, `cmpxchg` reads `rax`, the string instructions
/// read `rsi`/`rdi`/`rcx`, and `cmp dword ptr [rcx+8],5` names `rcx` only inside a memory operand.
/// `Instruction::reads` is the gap `Instruction::writes` closed on the other side, so the register
/// half asks that. The memory half stays a probe over the operands, because a memory operand is
/// not a register on either list and only this pass's own view of memory can say what is in the
/// slot it names.
fn note_loss(
    facts: &Facts,
    carried: &[String],
    instruction: &Instruction,
    lost: &mut Option<u64>,
    layout: Layout,
    traced: &mut bool,
) {
    if !instruction.writes_flags {
        return;
    }
    let gone = carried
        .iter()
        .any(|register| !matches!(facts.registers.get(register), Some(Value::Code { .. })));
    // Asked of the **snapshot**, not of the facts as they stand: by the time this runs the
    // instruction has been applied, and a destination that consumed the code no longer says it
    // ever held one.
    //
    // **A register read to form an address is a read, and it is counted.** `cmp [rcx+8],5` with
    // the code in `rcx` compares a loaded value rather than the code, so this is conservative
    // rather than exact -- and conservative in the direction the whole pass is: what it costs is
    // a branch reported as reading flags nobody can attribute, and what the alternative costs is a
    // control code published because the instruction that consumed it went unmodelled.
    let read = instruction
        .reads
        .iter()
        .any(|register| carried.contains(&register.full))
        || instruction.operands.iter().any(|operand| {
            // **Where `source_value` looks is operand one**, so the operand this cares about
            // has to be put there; `compare` builds the same probe for the same reason.
            // Passing the instruction whole resolves whatever is in that position instead,
            // which is a clause that can never match.
            let mut probe = instruction.clone();
            probe.operands = vec![Operand::Immediate(0), operand.clone()];
            probe.effect = Effect::Move;
            matches!(
                source_value(facts, &probe, layout, traced),
                Some(Value::Code { .. })
            )
        });
    *lost = (gone || read).then_some(instruction.address);
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
    status: Status,
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
        status,
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

/// The literal a `movk` leaves in the register it names, given what that register already held.
///
/// **Two readers need this and must not disagree**, which is why it is a function. [`update`] uses
/// it to keep following a compare chain; [`status_after`] uses it because an A64 `NTSTATUS` is two
/// instructions -- `mov w0,#0xD` / `movk w0,#0xC000,lsl #0x10` is `STATUS_INVALID_DEVICE_REQUEST`
/// -- and that second instruction runs through here *before* `update` sees it. Without it the
/// `movk` reads as a write of something unmodelled, the status is cleared, and a handler that
/// returns an ordinary multi-instruction status is reported as **accepting** the request. Raised
/// on windbg-mcp#343.
///
/// The decoder hands the immediate already shifted, so which halfword it lands in is read back out
/// of it; a zero immediate is ambiguous between the halfwords and keeps no answer at all.
fn movk_literal(held: Option<&Value>, operand: Option<&Operand>) -> Option<u32> {
    let immediate = match operand {
        Some(Operand::Immediate(value)) if *value != 0 => *value,
        _ => return None,
    };
    let Some(Value::Literal(literal)) = held else {
        return None;
    };
    let mask = 0xffff_u64 << ((immediate.trailing_zeros() / 16) * 16);
    // The immediate has to sit inside the halfword it starts in.
    match immediate & !mask == 0 {
        true => u32::try_from((u64::from(*literal) & !mask) | immediate).ok(),
        false => None,
    }
}

/// One step of the dispatch arithmetic, in the width the value actually has.
///
/// A control code is a `ULONG`: the machine computes `code - offset` modulo 2^32, so the offset
/// this pass carries has to move the same way. Widened to `i64` and added, a step of `0xfffffffc`
/// -- which is how a register carries `-4` -- leaves an offset past `u32::MAX`, and `push_case`
/// drops a code that does not fit one **silently**, with nothing in the answer saying a case went.
/// The immediate path had the same hole; carrying the step in a register is what made it
/// reachable.
fn stepped(offset: i64, by: u64, forward: bool, width: u32) -> i64 {
    // **At the destination's width, not at the field's.** A control code is a `ULONG` and the
    // ordinary chain steps a 32-bit register, but `sub rcx,rax` executes modulo 2^64 -- and a model
    // that wraps at 32 can bring an offset back to zero where the machine does not, so a following
    // `je` reports code `0`, a case no execution reaches. Sixty-four-bit arithmetic on a code is
    // not a shape this follows usefully; what matters is that it does not invent one.
    match width {
        FIELD_WIDTH => i64::from(match forward {
            true => (offset as u32).wrapping_add(by as u32),
            false => (offset as u32).wrapping_sub(by as u32),
        }),
        _ => match forward {
            true => (offset as u64).wrapping_add(by) as i64,
            false => (offset as u64).wrapping_sub(by) as i64,
        },
    }
}

/// The constant an operand stands for: an immediate, or a register this pass watched a literal
/// move into.
///
/// **The second is what a stepped chain needs.** HEVD's dispatch is `sub ecx,222003h` / `je` /
/// `sub ecx,eax` / `je` / ... twenty-four more times, with `eax` holding 4 -- so a pass reading
/// only immediates follows the first step and loses every one after it. Measured on the live
/// driver: 4 codes of the 28 its own header defines.
///
/// The width guard is the one the copy rule already applies: a literal in `al` says nothing about
/// what `sub ecx,eax` did to a `ULONG`.
fn scalar_of(facts: &Facts, operand: Option<&Operand>) -> Option<u64> {
    match operand? {
        Operand::Immediate(value) => Some(*value),
        Operand::Register(register) if register.width >= FIELD_WIDTH => {
            match facts.registers.get(&register.full) {
                Some(Value::Literal(value)) => Some(u64::from(*value)),
                _ => None,
            }
        }
        _ => None,
    }
}

/// The flags an **equality** against a comparison would leave.
///
/// Zero is zero however it is reached, so `ZF=1`, `SF=0` and `PF=1` hold whatever produced it. The
/// other two depend on how:
///
/// | reached by | `CF` | `OF` |
/// |---|---|---|
/// | `cmp`/`sub`, or an `add` of nothing | 0 | 0 |
/// | `add K` | 1 -- the operands summed to 2^32 | 1 only when `K` is the sign bit alone, where both are `INT_MIN` |
///
/// **Carried with the comparison rather than assumed by whoever reads it**, which is the
/// arrangement `proved` has with [`Value::Code`] and for the same reason: how a value was arrived
/// at is a fact about that value. Modelled as one flag first, and that was wrong twice over --
/// carry alone leaves `jno`, `jge` and `jl` reading a state nobody recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Equality {
    carry: bool,
    overflow: bool,
}

impl Equality {
    /// What a `cmp` or a `sub` leaves: equal values neither borrow nor overflow.
    const SUBTRACTIVE: Self = Self {
        carry: false,
        overflow: false,
    };

    /// What an `add` of `by` leaves, at a destination `width` bytes wide.
    fn after_add(by: u64, width: u32) -> Self {
        match by {
            0 => Self::SUBTRACTIVE,
            _ => Self {
                carry: true,
                // Signed overflow needs both operands negative and the result not, which for a sum
                // of exactly 2^n happens only when each is the sign bit alone.
                overflow: by == 1u64 << (width * 8 - 1),
            },
        }
    }
}

/// The state one compare leaves for the branch that reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Compared {
    /// The flags an equality here would leave. See [`Equality`].
    equality: Equality,
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
    lost: &mut Option<u64>,
) -> Option<Compared> {
    // **Which registers carry the control code as this begins**, snapshotted because the loss
    // check cannot be asked afterwards from one operand. An instruction writes registers it does
    // not name (`xadd`, `mul`), a narrow write returns before any arm runs, and by the time the
    // arms have finished the evidence is gone. Asked here, where nothing has happened yet, it
    // covers all of them with one question.
    let carried_the_code: Vec<String> = facts
        .registers
        .iter()
        .filter(|(_, value)| matches!(value, Value::Code { .. }))
        .map(|(register, _)| register.clone())
        .collect();
    // Where the status stands after this instruction, asked **before** it is applied because a
    // store reads its base as it stands. A compare writes neither a register nor a status, so this
    // is above the early return for one and the answer is the same either way.
    facts.status = status_after(facts.status, instruction, layout, facts);
    // A compare writes no register and is the only thing a branch reads.
    if instruction.effect == Effect::Compare {
        return compare(facts, instruction, layout, traced);
    }
    // A call returns over the volatile registers, so a belief about one does not survive it --
    // including a bound whose index is one of them, and including a **status** sitting in the
    // return register. That one used to be exempt, on the grounds that the ordinary rejection
    // calls a completion routine on its way out; what the exemption actually bought was
    // `mov eax,0C0000010h` / `call handler` / `ret` read as a refusal, when what that returns is
    // whatever the handler did. A driver that means to return the status reloads it after the
    // call, which is a thing this can see. `Irp->IoStatus.Status` is untouched by a call and is
    // where the ordinary rejection puts its status anyway.
    if matches!(instruction.flow, Flow::Call(_)) {
        facts.status.returned = false;
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
    // **Everything this instruction writes stops being believed**, and the decoder says what that
    // is. `xchg eax,r13d` writes both operands; `mul ecx` writes `eax` and `edx` and names
    // neither. A pass inferring it from the first operand keeps believing in a register the
    // instruction overwrote, and a control code that survives that way is reported as a code the
    // driver accepts.
    //
    // This used to be as much of the answer as could be had here -- every register an unmodelled
    // instruction *named* -- which reached the first of those and could not reach the second
    // without the mnemonic table this module stopped keeping. `Instruction::writes`
    // ([glslang/dbgscope#155](https://github.com/glslang/dbgscope/issues/155)) is that answer from
    // the decoder, so it is also **narrower**: a register an instruction only reads is left alone.
    //
    // The destination is skipped because the arms below are about to say what it holds, and the
    // bound that goes with it is the one write this has an exemption for -- the byte map's.
    let destination = instruction.operands.first().and_then(register_full);
    for written in &instruction.writes {
        if destination.as_deref() == Some(written.full.as_str()) {
            continue;
        }
        set(facts, &written.full, None);
        if facts
            .bound
            .as_ref()
            .is_some_and(|bound| bound.register == written.full)
        {
            facts.bound = None;
        }
    }
    // Neither of these writes a register this pass tracks, and `test` is the other thing that
    // writes only flags.
    //
    // **A `test` of the control code is still a branch about it**, though: `test ecx,3` / `je`
    // takes a path this cannot name a code for, and returning here left neither a case nor a sign
    // of one. Recorded as a pending loss, which the branch that reads these flags commits.
    if matches!(instruction.effect, Effect::Test | Effect::Push) {
        // **A `test` of the control code is still a branch about it**: `test ecx,3` / `je` takes a
        // path this cannot name a code for, and returning here left neither a case nor a sign of
        // one. It needs no clause of its own, though -- `note_loss` asks the general question, and
        // a `test` is a flag write whose operands read the code. A `push` writes no flags and is
        // answered by the same call returning at once.
        note_loss(facts, &carried_the_code, instruction, lost, layout, traced);
        return None;
    }
    let operands = &instruction.operands;
    let Some(Operand::Register(written)) = operands.first() else {
        // Writes memory, or nothing this models. A store through a register does not change what
        // the register holds, so the facts stand -- but the `writes` loop above may have cleared
        // one that did.
        note_loss(facts, &carried_the_code, instruction, lost, layout, traced);
        return None;
    };
    // **And operand zero is the destination only where the instruction writes it**, which is not
    // the same question and is only visibly not the same on A64. x86 names its destination first
    // and a store puts *memory* there, so the `else` above catches it; A64 names a store's
    // **source** first, so `str w9,[x8,#0x30]` arrives here with a register in hand and would be
    // modelled as a load *into* `w9` -- reading the memory operand for what `w9` now holds, when
    // what the instruction did was leave `w9` alone. The comment above says exactly that ("a store
    // through a register does not change what the register holds"), and it stopped being true the
    // moment an ARM64 target could reach this code.
    //
    // Asked of `Instruction::writes` rather than of the mnemonic, which is the same answer the
    // loop above uses and for the same reason (dbgscope#155). It also corrects a case that was
    // already wrong on x86: `mul ecx` names `ecx` first and writes `rax` and `rdx`, so `ecx` was
    // being cleared by the fallback arm below -- conservative, but a control code lost for an
    // instruction that never touched it.
    if !instruction
        .writes
        .iter()
        .any(|register| register.full == written.full)
    {
        note_loss(facts, &carried_the_code, instruction, lost, layout, traced);
        return None;
    }
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
        // A code clipped to sixteen bits is a code this can no longer follow, and the `je` after
        // it is a statement about those bits -- which is a loss like any other.
        note_loss(facts, &carried_the_code, instruction, lost, layout, traced);
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
        Effect::Subtract => match (
            arithmetic_source(facts, operands, held),
            scalar_of(facts, arithmetic_amount(operands)),
        ) {
            (
                Some(Value::Code {
                    offset,
                    shift,
                    proved,
                }),
                Some(immediate),
            ) => {
                let offset = stepped(offset, immediate, true, written.width);
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
                    // A `sub` reaching zero borrowed nothing and overflowed nothing.
                    equality: Equality::SUBTRACTIVE,
                    code: (shift == 0).then_some(offset as u64),
                    proved,
                    index: Some((destination, offset, shift)),
                    bound: Some(0),
                    at: instruction.address,
                });
            }
            _ => set(facts, &destination, None),
        },
        Effect::Add => match (
            arithmetic_source(facts, operands, held),
            scalar_of(facts, arithmetic_amount(operands)),
        ) {
            (
                Some(Value::Code {
                    offset,
                    shift,
                    proved,
                }),
                Some(immediate),
            ) => {
                // **And it leaves a comparison, exactly as the `sub` does.** `add ecx,K` /
                // `je` is a subtraction of a negative written the other way round, and returning
                // nothing here lost the case **silently**: `simulate` cleared the pending compare,
                // and the loss went unrecorded because the register still held a code.
                let offset = stepped(offset, immediate, false, written.width);
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
                    // **An `add` reaching zero carried out of the field**, and overflowed
                    // as well when what was added was the sign bit alone -- the one case where
                    // both operands are `INT_MIN` and the sum is not negative.
                    equality: Equality::after_add(immediate, written.width),
                    code: (shift == 0).then_some(offset as u64),
                    proved,
                    index: Some((destination, offset, shift)),
                    bound: Some(0),
                    at: instruction.address,
                });
            }
            // An `add` of anything else -- a table entry to its base, most often -- leaves a value
            // this does not model.
            _ => set(facts, &destination, None),
        },
        Effect::ShiftRight => match (
            arithmetic_source(facts, operands, held),
            arithmetic_amount(operands).and_then(immediate_of),
        ) {
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
        // **A halfword insert, which is the only way A64 states a constant wider than sixteen
        // bits.** `mov w9,#8` / `movk w9,#0x6D,lsl #0x10` is how a compiler writes `0x6D0008`, and
        // a control code is almost always wider than a `movz` can hold -- so without this every
        // ARM64 compare chain is against a register this pass lost at the *second* instruction,
        // and the map reports a driver that accepts no codes. Measured on this bench's ARM64
        // kernel: 855 `movk`, 58 of them immediately before a compare, and the idiom is always
        // this pair (`mov x0,#0xD` / `movk x0,#0xC000,lsl #0x10` builds `0xC000000D`).
        //
        // **This is the only mnemonic the production path reads**, and the module keeps no table
        // for a reason worth restating rather than quietly breaking. A table deciding *membership*
        // over an open set -- which instructions are privileged, which are calls -- is wrong by
        // construction, because the one it omits is a silent wrong answer. This is not that: it is
        // a single instruction whose semantics [`Effect`] has no vocabulary for, since it neither
        // moves a value nor computes one but replaces sixteen bits and keeps the rest. And the
        // cost of *not* recognising it is a case this loses rather than one it invents, which is
        // the direction that decides how much a reading like this may guess.
        //
        // The decoder hands the immediate already shifted into place, so which halfword it lands
        // in is read back out of it. Where the immediate is zero that is ambiguous -- a `movk` of
        // zero clears a halfword, and every halfword's zero looks alike -- so that keeps the
        // conservative answer below rather than guessing which one to clear.
        Effect::Other if instruction.mnemonic == "movk" => {
            set(
                facts,
                &destination,
                movk_literal(held.as_ref(), operands.get(1)).map(Value::Literal),
            );
        }
        _ => set(facts, &destination, None),
    }
    // **Asked after every arm, because every arm can be the one that drops it.** A `sub` against a
    // register nobody watched, a multiply, an `and` -- whatever it was, the branch about to read
    // these flags is a test on the control code that this cannot attribute, and a map that says
    // nothing about it reads as the whole set.
    note_loss(facts, &carried_the_code, instruction, lost, layout, traced);
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
        // A constant, which is worth keeping for one reason: a refusal's status reaches
        // `Irp->IoStatus.Status` through a register as often as it is written straight into it.
        Operand::Immediate(value) if instruction.effect == Effect::Move => {
            u32::try_from(*value).ok().map(Value::Literal)
        }
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
/// The value an arithmetic instruction operates **on**, which is not always what it writes to.
///
/// x86 is two-operand and destructive: `sub ecx,6D0034h` reads `ecx` and writes `ecx`, so the
/// destination's own value is the source and one lookup answers both. A64 is three-operand --
/// `sub w9,w8,w10` reads `w8` -- and taking the destination there reads the register this
/// instruction is about to overwrite.
///
/// **The common spelling has them the same register**, which is exactly why this stayed invisible:
/// `sub w9,w9,w10` gives the right answer by accident, and it was a chain written that way which
/// first showed the amount being read from the wrong operand. Raised on windbg-mcp#343.
fn arithmetic_source(facts: &Facts, operands: &[Operand], held: Option<Value>) -> Option<Value> {
    match operands.len() >= 3 {
        true => operands
            .get(operands.len() - 2)
            .and_then(register_full)
            .and_then(|register| facts.registers.get(&register).cloned()),
        false => held,
    }
}

/// And the amount it operates **by**, which is the last operand on both shapes.
///
/// Two-operand `sub ecx,eax` and three-operand `sub w9,w8,w10` agree about that, and a shift or
/// extension folded into an A64 operand never reaches here -- the decoder reports those as
/// [`Operand::Other`] and drops the effect, so `add x8,x9,x10,lsl #3` is not an `Add` at all.
fn arithmetic_amount(operands: &[Operand]) -> Option<&Operand> {
    match operands.len() >= 2 {
        true => operands.last(),
        false => None,
    }
}

/// The compare a branch carries **inside itself**, which is how A64 writes a dispatch chain.
///
/// x86 always leaves a comparison in the flags and then reads them, so [`compare`] runs over an
/// earlier instruction and the branch consults what it left. A64 has both forms, and the folded
/// one is the common one: `cbz w9,handler` is `cmp w9,#0` and `b.eq` in a single instruction that
/// writes no flags at all. Nothing in the loop over a block's body sees it, because it *is* the
/// terminator -- so a `sub w9,w9,w10` / `cbz w9,handler` chain, which is exactly the rebased shape
/// this module cites HEVD's `sub ecx,222003h` / `je` for, recovered **no cases and no unresolved
/// transfers**: a map that said `code_proved` and listed nothing, which reads as a driver that
/// accepts no control codes. Measured on windbg-mcp#343 before this existed.
///
/// `tbz`/`tbnz` are deliberately **not** here. They test one bit, which is a statement about part
/// of a `ULONG` rather than a value -- the same thing `test ecx,3` / `je` is on x86, and it gets
/// the same answer: not a case, and a loss recorded so the map reads as a lower bound.
fn folded_compare(
    facts: &Facts,
    instruction: &Instruction,
    layout: Layout,
    traced: &mut bool,
) -> Option<(Compared, Condition)> {
    let condition = match instruction.mnemonic.as_str() {
        // Branch if the register is zero, which after a rebasing `sub` is "equal to the code".
        "cbz" => Condition::Equal,
        "cbnz" => Condition::NotEqual,
        _ => return None,
    };
    let register = instruction.operands.first()?;
    if !matches!(register, Operand::Register(_)) {
        return None;
    }
    // Asked of [`compare`] through a probe rather than rebuilt, so the width guard, the shifted-
    // index rule and the `Value::Code` arithmetic are the ones every other compare gets.
    let mut probe = instruction.clone();
    probe.operands = vec![register.clone(), Operand::Immediate(0)];
    probe.effect = Effect::Compare;
    Some((compare(facts, &probe, layout, traced)?, condition))
}

/// Whether a branch this walk could not read is branching **on the control code**.
///
/// The question a silent short list needs asked: `tbz w9,#3,handler` where `w9` holds the code is
/// a decision about the request that this cannot name, and saying nothing about it is what lets a
/// map report fewer codes than the driver accepts with nothing marking the gap.
fn branches_on_the_code(facts: &Facts, instruction: &Instruction) -> bool {
    instruction.operands.iter().any(|operand| match operand {
        Operand::Register(register) => matches!(
            facts.registers.get(&register.full),
            Some(Value::Code { .. })
        ),
        _ => false,
    })
}

fn compare(
    facts: &Facts,
    instruction: &Instruction,
    layout: Layout,
    traced: &mut bool,
) -> Option<Compared> {
    let left = instruction.operands.first()?;
    // The constant, whether it is written here or carried in a register: a stepped chain
    // ends each group with `cmp ecx,eax`, and reading only immediates loses that code.
    let bound = scalar_of(facts, instruction.operands.get(1));

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
                equality: Equality::SUBTRACTIVE,
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
            // A `cmp`: equal values borrow nothing and overflow nothing.
            equality: Equality::SUBTRACTIVE,
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
            Value::Code { .. } | Value::InputLength | Value::OutputLength | Value::Literal(_) => {
                FIELD_WIDTH
            }
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
    /// Where a refusal's status stood **at the jump**, which is on the path to every landing the
    /// table selects.
    ///
    /// A case the table selected is read with nothing believed about any register, because the
    /// edge it arrived on is not in the graph -- but the status is not a register, and it *is* on
    /// that path. Dropped with the rest, a routine that stores an error into the IRP before
    /// switching has every case it routes to read as accepted, with whatever they call reported as
    /// the handler.
    status: Status,
}

/// The image base a compiler folds into every table entry, and where the fold stands.
struct Fold {
    /// The register holding the base. Recorded because that -- and not the load's base -- is what
    /// execution adds to each entry; a compiler is free to use one register for both and A64's
    /// `mountmgr` does, but it is also free not to.
    register: String,
    /// Where in the block the fold is, so the base is read where the code reads it.
    at: usize,
    /// What one unit of an entry is worth in bytes. x86 stores a whole displacement and this is
    /// 1; A64 stores an **instruction** count and folds the `lsl #2` into the same `add`.
    scale: u64,
}

/// The base a fold adds and what it multiplies the entry by, from either shape of `add`.
///
/// x86 is two-operand and destructive -- `add rcx,rdx` -- and the entry is a whole displacement.
/// A64 is three-operand and folds the scaling into the same instruction: `add x8,x9,x8,lsl #2`,
/// where the table holds an **instruction** count, so the address is four times it. Reading that
/// as x86's shape puts the target a quarter of the way from the base to where control actually
/// goes -- which lands inside the image often enough to be published as a case rather than
/// refused, so the scale is not a detail that fails safe.
///
/// **The shift sits on the last register operand, and that is what says which of the two is the
/// entry**: the other one is the base, and the *destination* has nothing to do with it. A64 is
/// not destructive, so `add x10,x9,x8,lsl #2` / `br x10` is as ordinary as the aliasing
/// `add x8,x9,x8,lsl #2` `mountmgr` happens to use, and requiring the entry to be the destination
/// refuses it -- raised on review of windbg-mcp#345. So this answers with the register the walk
/// should go on following rather than assuming it already has it.
///
/// A modifier this does not read -- `lsr`, `asr`, an extension -- refuses the table rather than
/// dropping it, dropping one being how an address nobody computed gets published.
fn folded_base(
    instruction: &Instruction,
    wanted: &str,
    layout: Layout,
) -> Option<(String, u64, String)> {
    let operands = &instruction.operands;
    let Some(Operand::Register(written)) = operands.first() else {
        return None;
    };
    // **Folded at the target's width.** `add eax,ecx` keeps four bytes of an address the jump
    // then reads eight of, so what the entries are measured from is not what this computed.
    if written.width < layout.pointer {
        return None;
    }
    // x86: `add rcx,rdx`, the destination being one of the two addends.
    if operands.len() == 2 {
        let Some(Operand::Register(source)) = operands.get(1) else {
            return None;
        };
        let plain = instruction.effect == Effect::Add && source.width >= layout.pointer;
        return plain.then(|| (source.full.clone(), 1, wanted.to_string()));
    }
    // A64: `add xD,xA,xB`, with the shift -- when there is one -- on `xB`.
    let shift = match operands.len() {
        3 => 0,
        4 => left_shift(operands.get(3)?)?,
        _ => return None,
    };
    // **A shifted add is not an `Add`.** The decoder reports a folded modifier as
    // [`Operand::Other`] and drops the effect with it, so the mnemonic is what is left to go on
    // and an `add` is the only one whose sum is an address.
    if instruction.effect != Effect::Add && instruction.mnemonic != "add" {
        return None;
    }
    let (Some(Operand::Register(first)), Some(Operand::Register(second))) =
        (operands.get(1), operands.get(2))
    else {
        return None;
    };
    if first.width < layout.pointer || second.width < layout.pointer {
        return None;
    }
    // **A shift settles it outright**, whatever the destination is: the operand carrying it is
    // the entry and the other is the base.
    if operands.len() == 4 {
        return Some((
            first.full.clone(),
            1u64.checked_shl(shift)?,
            second.full.clone(),
        ));
    }
    // Unshifted, the sum is the same either way round and nothing in the instruction says which
    // side is the table's. What is left to go on is which one the walk arrived following.
    match (first.full == wanted, second.full == wanted) {
        (false, true) => Some((first.full.clone(), 1, second.full.clone())),
        (true, false) => Some((second.full.clone(), 1, first.full.clone())),
        // Neither is the register being followed, or both are: `add x8,x8,x8` is a doubling and
        // not a fold, and reading it as one measures the entries from themselves.
        _ => None,
    }
}

/// The `lsl #n` an operand carries, as the number of bits.
///
/// [`Operand::Other`] is the decoder's text hatch for a modifier the typed operands cannot
/// express, and a left shift is the one a jump table's fold uses. Everything else answers `None`,
/// which refuses the table: a `lsr #2` read as no shift at all computes an address four times
/// further from the base than execution went.
fn left_shift(operand: &Operand) -> Option<u32> {
    let Operand::Other(modifier) = operand else {
        return None;
    };
    let amount = modifier.trim().strip_prefix("lsl #")?;
    let amount = match amount.strip_prefix("0x") {
        Some(hex) => u32::from_str_radix(hex, 16).ok()?,
        None => amount.parse().ok()?,
    };
    // Past a pointer's width the sum is not an address computation, whatever it is.
    (amount < 64).then_some(amount)
}

/// The width of one entry, where a load is indexing a table by whole entries.
///
/// **The index steps one entry at a time, so the scale *is* the width.** A load whose scale and
/// size disagree is walking some other array, and reading it as a table takes it apart at one
/// width and puts it back together at another.
///
/// x86 emits a `DWORD` table and nothing else. A64 sizes the entry to the routine -- `mountmgr`'s
/// dispatch has a `ldrsw` table of four-byte entries and a `ldrsb` one of single signed bytes,
/// both feeding a `br` in the same function -- which is why this is a range rather than the
/// constant it used to be. Widths this does not admit refuse the table.
fn entry_width(memory: &MemoryOperand) -> Option<u32> {
    let width = memory.size?;
    (matches!(width, 1 | 2 | 4) && u32::from(memory.scale) == width).then_some(width)
}

/// One table entry, as the number the fold adds to the base.
///
/// **A sign-extending load makes the entry a signed displacement.** `movsxd rax,dword ptr
/// [table+index*4]` is how a compiler writes a table whose cases sit *before* the base it is
/// measured from, and zero-extending one of those adds four gigabytes -- which lands outside the
/// image, so the whole table is refused and its cases are silently lost. A64's byte tables are
/// signed for the same reason at a width where the error is far smaller and therefore far worse:
/// an unsigned `0xa2` is 162 entries forward where the signed one is 94 back, and 162 forward is
/// still inside the function. Which of the two it is comes from the decoder's own classification
/// of the load rather than from its spelling.
///
/// **And the extension stops at the register the load writes**, which is a second question and
/// was answered wrong: `ldrsb w8,[...]` sign-extends to *32* bits, and writing `w8` zero-extends
/// `x8`, so a fold reading `x8` gets `0x00000000fffffffe` where extending straight to 64 bits
/// gives `-2`. On a table scaled by four that is `base + 0x3fffffff8` against `base - 8` -- and
/// since only the reconstructed target is checked against the image, the wrong one is *inside* it
/// and gets published as a control code the driver accepts, while the right one is far outside
/// and refuses the table. Raised on review of windbg-mcp#345. `destination` is that register's
/// width in bytes, absent where the load has no register destination at all, which is the 32-bit
/// form that jumps through the table itself.
fn entry_value(raw: &[u8], effect: Effect, destination: Option<u32>) -> Option<i64> {
    let bits = u32::try_from(raw.len().checked_mul(8)?).ok()?;
    if bits == 0 || bits > 64 {
        return None;
    }
    let mut extended = [0u8; 8];
    extended.get_mut(..raw.len())?.copy_from_slice(raw);
    let value = u64::from_le_bytes(extended);
    let value = match effect == Effect::MoveSigned && bits < 64 {
        true => ((value << (64 - bits)) as i64) >> (64 - bits),
        false => i64::try_from(value).ok()?,
    };
    let kept = match destination {
        Some(width) if width < 8 => width.checked_mul(8)?,
        _ => return Some(value),
    };
    if kept < bits {
        // The load reads more than it can write, which is not a shape this reads.
        return None;
    }
    Some((value as u64 & (u64::MAX >> (64 - kept))) as i64)
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
    capped: &mut bool,
) -> Option<Resolved> {
    let reader = reader?;
    let facts_at = |position: usize| {
        let mut replay = arrived.clone();
        let mut traced = false;
        for instruction in instructions.iter().take(position) {
            // A replay to recover a table's base, not a walk that reports: what it loses about the
            // control code is recorded by the pass that walks these same instructions.
            update(&mut replay, instruction, layout, &mut traced, &mut None);
        }
        replay
    };

    // **The 32-bit form jumps through the table itself**: `jmp dword ptr [table+eax*4]`, with no
    // register in between and the entry a whole address rather than an offset from the image. Held
    // to a `DWORD` and not to [`entry_width`]'s range: there is no fold here, so the entry *is*
    // the address, and one byte of an address is not one.
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
            let mut added: Option<Fold> = None;
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
                // **Only an instruction that *writes* the register continues the chain**, and the
                // decoder says which do. A `cmp rcx,[base+rax*4+table]` reads it and writes
                // nothing but the flags, so reading that as the load would turn an unrelated array
                // into a table; `xchg edx,eax` writes `eax` as its *second* operand, so a walk
                // looking only at the first would step over it and resolve the jump from a load
                // execution had overwritten.
                if !instruction
                    .writes
                    .iter()
                    .any(|register| register.full == wanted)
                {
                    continue;
                }
                // It writes it. Either it is one of the shapes below, or this walk cannot say what
                // is in the register and stops -- including the case where the write is not the
                // first operand at all, which is what an `xchg` is.
                let Some(Operand::Register(written)) = instruction.operands.first() else {
                    return None;
                };
                if written.full != wanted {
                    return None;
                }
                match instruction.operands.get(1) {
                    // **And it reads one whole entry**, which is what [`entry_width`] settles: a
                    // `mov rax,qword ptr [base+index*4]` taken for this pattern is read as two
                    // halves of one entry and a pair of addresses nobody computed -- published as
                    // codes if they happen to land inside the image.
                    Some(Operand::Memory(memory))
                        if entry_width(memory).is_some()
                            && memory.index.is_some()
                            && matches!(instruction.effect, Effect::Move | Effect::MoveSigned) =>
                    {
                        found = Some((instruction, memory, position));
                        break;
                    }
                    Some(Operand::Register(source)) => {
                        // `add rcx,rdx` folds the image base into the entry: the value being
                        // followed is still the one in `rcx`. **Which register was added is
                        // recorded**, because that -- and not the load's base -- is what execution
                        // adds to every entry, and so is what one entry is *worth*, which A64
                        // folds into the same instruction.
                        if let Some((base, scale, entry)) =
                            folded_base(instruction, &wanted, layout)
                        {
                            // **One fold, and not several.** `add rcx,rdx` / `add rcx,r8` makes
                            // the target the sum of the entry and *both*, and keeping one of them
                            // reconstructs addresses nobody computed -- published as cases
                            // wherever they happen to be executable. A compiler emits one;
                            // anything else is a shape this does not follow.
                            if added.is_some() {
                                return None;
                            }
                            added = Some(Fold {
                                register: base,
                                at: position,
                                scale,
                            });
                            // **And the walk goes on following the entry**, which the fold named
                            // and which need not be what it wrote into.
                            wanted = entry;
                            continue;
                        }
                        // **And copied at the target's width.** Everything from the `add` to the
                        // jump is an *address*, so `mov edx,ecx` zero-extends the low half of one:
                        // the jump goes somewhere this walk did not compute, and the table's
                        // targets are published for it. The **load** is the exception and is
                        // matched above: a table entry really is narrower than an address, and
                        // `mov eax,[table+rax*4]` really does zero-extend it on purpose.
                        if instruction.effect != Effect::Move
                            || written.width < layout.pointer
                            || source.width < layout.pointer
                        {
                            return None;
                        }
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
        *capped |= entries > MAX_TABLE_ENTRIES;
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
    let (entry_base, entry_scale) = match &added {
        Some(fold) => match facts_at(fold.at).registers.get(&fold.register) {
            Some(Value::Address(address)) => (Some(*address), i64::try_from(fold.scale).ok()?),
            _ => return None,
        },
        // An absolute table with no fold at all -- the 32-bit shape, where the entry is already
        // the address and multiplying it by anything is not what execution did.
        None => (None, 1),
    };
    // What the entries are read at, which the load settled and the guard above admitted, and how
    // far the register it writes carries the result.
    let width = entry_width(memory)? as usize;
    let destination = match load.operands.first() {
        Some(Operand::Register(register)) => Some(register.width),
        _ => None,
    };

    // **MSVC's dense switch has two tables**: a byte per index saying which case it is, then a
    // dword per case holding its RVA. It reuses one register for both, so the dword load's index
    // carries the bounded register's name and none of its meaning unless the byte map is read too.
    // **Before the dword load, because that is the stage it feeds.** Searching the whole block
    // takes a later, unrelated byte load for the first stage -- the target was already in hand by
    // then -- and remaps every code through arbitrary bytes.
    let stages: Vec<_> = instructions[..at_load.min(instructions.len())]
        .iter()
        .enumerate()
        .rev()
        .filter_map(|(position, instruction)| {
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
        })
        .collect();
    // **One stage, and not several.** Two byte maps in a row make the case number
    // `second[first[code]]`, and reading only the nearest pairs every code with the entry some
    // other index selects -- published wherever that entry happens to be executable, with the jump
    // reported as followed. Composing them is readable in principle and is a second table's worth
    // of reads for a shape no compiler emits; one is the switch, more is not this.
    if stages.len() > 1 {
        return None;
    }
    let byte_map = stages.into_iter().next();

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
    let slots = cases.iter().copied().max()?.checked_add(1)?;
    if slots > MAX_TABLE_ENTRIES {
        *capped = true;
        return None;
    }
    reader.served += 1;
    let bytes = (reader.read)(table, slots.checked_mul(width)?)?;

    let mut found = Vec::new();
    for (position, case) in cases.iter().enumerate() {
        let slot = case.checked_mul(width)?;
        let entry = entry_value(
            bytes.get(slot..slot.checked_add(width)?)?,
            load.effect,
            destination,
        )?;
        let target = match entry_base {
            Some(base) => base.wrapping_add_signed(entry.checked_mul(entry_scale)?),
            None => u64::try_from(entry).ok()?,
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
        status: facts_at(instructions.len()).status,
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
fn error_status(
    instructions: &[Instruction],
    layout: Layout,
    arrived: &Facts,
    leaves: &impl Fn(u64) -> bool,
) -> bool {
    let mut facts = arrived.clone();
    let mut traced = false;
    for instruction in instructions {
        update(&mut facts, instruction, layout, &mut traced, &mut None);
        // **A tail jump out of the routine hands the request on exactly as a call does**, and what
        // the routine returns is then the callee's. A dispatcher that loads a default error before
        // its compare chain and reaches a case through `jmp handler` accepts that code, and
        // reading the status the case arrived with as its answer reports it undecided instead. A
        // jump that stays *inside* the routine is one path continuing -- `jmp common_ret` is how a
        // rejection is written across two blocks -- and that one carries, which is
        // [`refuses_in`]'s question. `Irp->IoStatus.Status` survives both, for the reason it
        // survives a call: a callee is free to leave it alone.
        if let Flow::Jmp(Some(target)) = instruction.flow
            && leaves(target)
        {
            facts.status.returned = false;
        }
    }
    facts.status.refusing()
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
    // **Only an instruction that *writes* its first operand replaces what is there.**
    // `test eax,eax` and `cmp [rbx+30h],0` name the destination and change nothing, so reading
    // them as writes takes back a refusal the block still has -- and the case then reads as
    // accepted, with whatever it called reported as its handler. An instruction this pass does not
    // model stays in: it may write what it names, and clearing a status is the direction that
    // cannot invent one.
    if matches!(
        instruction.effect,
        Effect::Compare | Effect::Test | Effect::Push
    ) {
        return status;
    }
    // Which of the two places a dispatch routine's status lives does this write?
    //
    // **The return register is the decoder's answer and not the first operand's.** `mul ecx`
    // writes `rax` and names it nowhere; `xchg r13d,eax` writes it as its *second* operand. A rule
    // reading only the destination keeps a status in a register the instruction overwrote, and the
    // block then reads as refusing a code the driver accepts, with its handler taken away. A
    // status **is** a register fact, so it dies where the register does -- the rule [`update`]
    // applies to every other fact it keeps.
    let returns = instruction
        .writes
        .iter()
        .any(|written| written.full == layout.return_register);
    // Or `Irp->IoStatus.Status`, which is the other place a refusal writes one -- and **that
    // field**, not any store. A case that puts an error-looking constant in a stack local or a
    // diagnostic structure and then returns would otherwise be read as refusing the request: the
    // case comes back rejected and its handler is taken away, which is a wrong answer about a code
    // the driver accepts. So the destination has to be a dword at that displacement off a register
    // this walk watched the IRP reach.
    //
    // **By operand role rather than by position**, which is what a second architecture costs here:
    // x86 writes `mov [rbx+30h],ecx` with the memory first and A64 writes `str w9,[x8,#30h]` with
    // it second, so a first-operand rule sees no store at all on ARM64. A handler that refuses
    // through `Irp->IoStatus.Status` -- which is the shape a rejection takes once a completion
    // call has clobbered the return register -- was then reported as **accepting** the code.
    // Raised on windbg-mcp#343.
    //
    // A load off the same field has the same two operands the other way round, and the decoder is
    // what tells them apart: a load writes the register it names and a store writes none of them.
    let addressed = instruction
        .operands
        .iter()
        .find_map(|operand| match operand {
            Operand::Memory(memory) => Some(memory),
            _ => None,
        });
    let writes_a_named_register = instruction.operands.iter().any(|operand| match operand {
        Operand::Register(register) => instruction
            .writes
            .iter()
            .any(|written| written.full == register.full),
        _ => false,
    });
    let stores = !writes_a_named_register
        && addressed.is_some_and(|memory| {
            memory.index.is_none()
                && memory.size == Some(FIELD_WIDTH)
                && memory.displacement == layout.status_field
                && memory
                    .base
                    .as_ref()
                    .is_some_and(|base| facts.registers.get(&base.full) == Some(&Value::Irp))
        });
    if !returns && !stores {
        return status;
    }
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
    // **The literal, wherever it came from.** Written straight into the destination, or carried
    // there in a register: `mov ecx,0C0000010h` / `mov [rbx+30h],ecx` is the same refusal as the
    // one-instruction form, and reading only the immediate takes it for a store of something
    // unknown -- which clears the field's status and loses the rejection.
    // The source is operand one where the destination is a register, and the operand that is
    // *not* the memory where the destination is memory -- again because the two architectures put
    // it on opposite sides.
    let source = match stores {
        true => instruction
            .operands
            .iter()
            .find(|operand| !matches!(operand, Operand::Memory(_))),
        false => instruction.operands.get(1),
    };
    let written = match source {
        Some(Operand::Immediate(value)) => u32::try_from(*value).ok(),
        Some(Operand::Register(register)) => match facts.registers.get(&register.full) {
            Some(Value::Literal(value)) if register.width >= FIELD_WIDTH => Some(*value),
            _ => None,
        },
        _ => None,
    };
    // **A64 states a status in two instructions**, and the second is not a `Move`. This runs
    // before [`update`] does, so the combined literal is asked for here from the same helper
    // rather than waited for -- without it `movk` reads as a write of something unmodelled and
    // takes the refusal back, which reports an ordinary rejection as an accepted code.
    let inserted = match instruction.mnemonic == "movk" {
        true => movk_literal(
            facts.registers.get(layout.return_register),
            instruction.operands.get(1),
        ),
        false => None,
    };
    let refusal = match inserted {
        Some(value) => value >> 30 == 0b11,
        None => {
            instruction.effect == Effect::Move
                && match written {
                    Some(value) => value >> 30 == 0b11,
                    // The destination was written with something that is not a literal status:
                    // whatever is there now is no longer the refusal that was loaded.
                    None => false,
                }
        }
    };
    // **What is in the return register now**, which this pass can say only for a write it
    // modelled: a destination it recognised, taking something the arms above could read. An
    // implicit write names nothing for them, so what it left is neither a refusal nor the status
    // that was there -- and *gone* is the answer that cannot invent one.
    let modelled = matches!(
        instruction.operands.first(),
        Some(Operand::Register(register)) if register.full == layout.return_register
    );
    Status {
        returned: match (returns, modelled) {
            (false, _) => status.returned,
            (true, true) => refusal,
            (true, false) => false,
        },
        irp: match stores {
            true => refusal,
            false => status.irp,
        },
    }
}

/// What reading one block for a refusal produced.
#[derive(Default)]
struct Ending {
    /// Whether that block returned, refusing.
    refuses: bool,
    /// The registers it left, for the block a tail jump carries them to: a case's own path can put
    /// the IRP somewhere before jumping to a shared error block, and that block's *joined* facts
    /// are what every predecessor agreed on -- which for a fact only this path carries is nothing.
    /// The status rides in these, being one of them.
    facts: Facts,
}

/// Where a dispatch routine's status stands, which is **two** places and not one.
///
/// A refusal can put an error in either, and they are independent: a block that stores one into
/// `Irp->IoStatus.Status`, completes the request and then returns success has refused the code, and
/// folding the two into one flag has the `xor eax,eax` take the IRP's error away with it. The case
/// then reads as accepted, with the completion routine reported as its handler.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub(crate) struct Status {
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
) -> Ending {
    // **Read where the store is, not where the block starts.** Whether a destination is
    // `Irp->IoStatus.Status` is a question about a register, and a block is free to reuse one: a
    // `rbx` that arrives holding the IRP and is reassigned to a diagnostic object before the store
    // would otherwise have that store read as a refusal, taking a handler away from a code the
    // driver accepts. Same rule, and same replay, as a jump table's base.
    //
    // **The status starts where this walk starts, and not where the block's facts do.** A refusal
    // is a verdict, and a status the block *arrived* with does not support one: a dispatch routine
    // that puts `STATUS_INVALID_DEVICE_REQUEST` in the IRP before it decides anything and lets
    // each case overwrite it is an ordinary shape, and reading that as every case refusing takes
    // the handler away from every code the driver accepts. What the arrived status still does is
    // stop this claiming **acceptance**: `error_status` reads the case's own facts, which do carry
    // it, so such a case comes back undecided rather than wrong in either direction. A status
    // carried over an unconditional **tail jump** is different and is passed in here: that is one
    // path continuing, not a fact established before the routine chose.
    let mut facts = Facts {
        status: incoming,
        ..arrived.clone()
    };
    let mut traced = false;
    for instruction in instructions {
        // What the block has established **so far**, which is what says whether the call it is
        // about to make is a completion on the way out or a block doing something else. Kept by
        // `update` with everything else, so what arrived on the edge is already in it.
        update(&mut facts, instruction, layout, &mut traced, &mut None);
        let status = facts.status;
        match instruction.flow {
            Flow::Return => {
                return Ending {
                    refuses: status.refusing(),
                    facts,
                };
            }
            // **A call is walked through rather than stopped at.** It used to end the block
            // unless a status was already established, which is a heuristic standing in for what
            // the status itself now answers: the call clears the one in the return register and
            // leaves the one in the IRP, so the `ret` below decides on what is actually there. It
            // also finds the shape that heuristic missed -- a status **reloaded** after the call,
            // which is how a driver returns one it completed with.
            Flow::Call(_) => {}
            // **An unconditional tail jump carries the status it established.**
            // `mov eax,0C0000010h` / `jmp common_ret` is one rejection written across two blocks,
            // and starting the next one from nothing loses it -- the shared return block is then
            // reported as this case's handler. Whether that jump is followed at all is
            // [`refuses_in`]'s question; this says what goes with it.
            Flow::Jmp(Some(_)) => {
                return Ending {
                    refuses: false,
                    facts,
                };
            }
            Flow::Branch(_) | Flow::Jmp(_) => return Ending::default(),
            Flow::Unreadable | Flow::Unknown => return Ending::default(),
            Flow::Fallthrough | Flow::Trap => {}
        }
    }
    Ending::default()
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
    blind: Option<Status>,
) -> bool {
    let mut at = index;
    let mut start = from;
    // The status this walk has established so far, which starts at nothing: see `failure_block`.
    let mut status = Status::default();
    // What the block before this one left, once there has been one. **Carried rather than looked
    // up**: a tail edge is one path into a shared block, and that block's entry facts are what
    // *every* path into it agreed on -- so a case that copies the IRP into a register before
    // jumping to a shared error block has that provenance joined away by a predecessor which did
    // not, and the store the error goes through stops being one to `Irp->IoStatus.Status`. The
    // refusal is then missed and the tail is reported as this code's handler.
    let mut carried: Option<Facts> = None;
    for hop in 0..3 {
        let block = &graph.blocks[at];
        // The first block is read from the landing, which a jump table's need not be the start
        // of; a tail jump is an edge, so every block after this one is entered at its own.
        let instructions = &listing[start.max(block.start)..block.end];
        // The **first** block is the one a case landed in, and a case the table selected landed
        // there along an edge this graph does not have -- so it is read with nothing believed,
        // exactly as its sizes are. Every hop after that is a tail jump the graph *does* carry, so
        // those blocks are read with what reached them.
        let facts = match (&carried, blind.filter(|_| hop == 0)) {
            (Some(carried), _) => carried.clone(),
            // Nothing believed about any register, and the status that stood at the jump.
            (None, Some(status)) => Facts {
                status,
                ..Facts::default()
            },
            (None, None) => entry.get(at).cloned().flatten().unwrap_or_default(),
        };
        let ending = failure_block(instructions, layout, &facts, status);
        if ending.refuses {
            return true;
        }
        status = ending.facts.status;
        carried = Some(ending.facts);
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
        update(&mut facts, instruction, layout, &mut traced, &mut None);
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
        untracked: found.untracked.iter().map(|at| locate(*at)).collect(),
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
            // The module name is the target's -- see `structured::renderable`. The RVA
            // beside it is this crate's own formatting.
            (Some(module), Some(rva)) => {
                format!("{}+{rva}", crate::structured::renderable(module))
            }
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
    if !report.untracked.is_empty() {
        out.push_str(&format!(
            "  [!] the control code stopped being followable at {} place(s), so a compare \
             after each was a test on it that could not be attributed -- the case list is a \
             lower bound rather than the set: {}\n",
            report.untracked.len(),
            report
                .untracked
                .iter()
                .map(where_)
                .collect::<Vec<_>>()
                .join(", ")
        ));
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
    //! The oracle that is **not** this pass lives beside these, at
    //! `src/ioctl/tests/differential.rs`: it runs the same routines on a small concrete
    //! interpreter and checks every case this module reports against where execution actually
    //! went. A child of *this* module rather than of `ioctl`, because what it needs is the fixture
    //! vocabulary below -- and an ordinary `mod` rather than a `#[path]` to somewhere else, which
    //! is the shape that resolves on every platform: a relative path out of a module directory
    //! that does not exist is canonicalised by Windows and walked component by component by POSIX,
    //! so the first spelling of this built here and would not have built on Linux.
    mod differential;

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
            // A64's load and store are both moves; which way is decided by where the memory
            // operand is, not by the effect. `movk` is deliberately absent -- it falls to
            // `Effect::Other` below, which is what the decoder answers for it.
            "ldr" | "str" => Effect::Move,
            // A64's narrow loads, and the two spellings that matter to a jump table: the signed
            // ones are what let a table entry point *backwards* from the base it is measured
            // from, which `mountmgr`'s own byte table does.
            "ldrb" | "ldrh" => Effect::Move,
            "ldrsb" | "ldrsh" | "ldrsw" => Effect::MoveSigned,
            // `adr`/`adrp` are A64's `lea`: the address, not what is at it.
            "adr" | "adrp" => Effect::LoadAddress,
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
        // **A folded modifier costs the effect**, which is a fact about the decoder and so belongs
        // in the fixture rather than in the code under test. Measured against dbgscope on the
        // words `mountmgr`'s own ARM64 dispatch routine uses: `add x8,x9,x10` answers
        // `Effect::Add`, and `add x8,x9,x8,lsl #2` answers `Effect::Other` with the `lsl` carried
        // as an `Operand::Other`. A fixture that kept `Add` here would exercise a path no target
        // ever takes, and the rule it is meant to pin would go untested.
        let effect = match operands
            .iter()
            .any(|operand| matches!(operand, Operand::Other(_)))
        {
            true => Effect::Other,
            false => effect,
        };
        let condition = match mnemonic {
            "je" | "jz" | "b.eq" => Some(Condition::Equal),
            "jne" | "jnz" | "b.ne" => Some(Condition::NotEqual),
            // `b.hi` is A64's `ja`, and it is the branch a switch's bounds check leaves on.
            "ja" | "jnbe" | "b.hi" => Some(Condition::UnsignedAbove),
            "jae" | "jnb" | "jnc" => Some(Condition::UnsignedAboveOrEqual),
            "jb" | "jnae" | "jc" => Some(Condition::UnsignedBelow),
            "jbe" | "jna" => Some(Condition::UnsignedBelowOrEqual),
            "jg" | "jnle" => Some(Condition::SignedGreater),
            "jge" | "jnl" => Some(Condition::SignedGreaterOrEqual),
            "jl" | "jnge" => Some(Condition::SignedLess),
            "jle" | "jng" => Some(Condition::SignedLessOrEqual),
            // The flag-only branches, which the walk now has an answer for: an equality
            // leaves `SF=0`, `OF=0` and `PF=1`, so each of these admits it on one edge.
            // Absent here, a fixture using one silently became an unconditional branch
            // with no condition at all -- which is a fixture agreeing with any rule.
            "js" => Some(Condition::Negative),
            "jns" => Some(Condition::NotNegative),
            "jo" => Some(Condition::Overflow),
            "jno" => Some(Condition::NotOverflow),
            "jp" | "jpe" => Some(Condition::Parity),
            "jnp" | "jpo" => Some(Condition::NotParity),
            _ => None,
        };
        // **Which registers the instruction writes**, as the decoder would answer: the first
        // operand when it has one, both of an `xchg`, and none at all for the two that write only
        // flags. Spelled out here rather than derived from the effect the walk branches on,
        // because a fixture sharing that decision with the code under test agrees with it about a
        // wrong one -- and the real answers for these shapes are pinned in dbgscope's own test,
        // which is where this has to stay consistent with.
        let writes: Vec<RegisterOperand> = match (mnemonic, effect) {
            // `push rax` reads `rax` and writes `rsp`, which nothing here tracks.
            (_, Effect::Compare | Effect::Test | Effect::Push) => Vec::new(),
            // **A64's compare-and-branch reads a register and writes none**, which the first-
            // operand rule below would get backwards -- and a fixture saying `cbz w9` writes `w9`
            // would clear the very fact the branch is about, so the test would pass for having
            // nothing left to find rather than for the rule under test.
            ("cbz" | "cbnz" | "tbz" | "tbnz", _) => Vec::new(),
            // **A64's indirect branch writes nothing**, the register being where it reads its
            // destination from. The first-operand rule below would say `br x8` writes `x8`.
            ("br" | "blr", _) => Vec::new(),
            // **The implicit destination**, which is the shape a first-operand rule cannot reach:
            // `mul ecx` reads `ecx` and writes `rax` and `rdx`, naming neither. dbgscope's own
            // test pins that against the decoder, which is what this has to stay true to.
            ("mul" | "div", _) => vec![named("rax"), named("rdx")],
            // **A64 names a store's source first and writes no register at all**, which is the
            // fact the fixture has to state rather than derive: a rule taking operand zero would
            // say `str w9,[x8,#0x30]` writes `w9`, and a test built on that agrees with the
            // defect it is meant to catch. Without a writeback there is nothing in `writes`, and
            // that is what dbgscope answers.
            ("str", _) => Vec::new(),
            ("xchg", _) => operands
                .iter()
                .filter_map(|operand| match operand {
                    Operand::Register(register) => Some(register.clone()),
                    _ => None,
                })
                .collect(),
            _ => match operands.first() {
                Some(Operand::Register(register)) => vec![register.clone()],
                _ => Vec::new(),
            },
        };
        // **Which registers the instruction reads**, as the decoder would answer -- and it is not
        // the operand list, which is the whole reason `Instruction::reads` exists. Three
        // departures, each measured against iced rather than reasoned about: a copy reads its
        // source and **not** its destination; `mul`/`div` read the accumulator and name it
        // nowhere, as `push`/`pop`/`ret` read the stack pointer; and a memory operand reads the
        // registers that form its address wherever it appears, destination included -- writing to
        // `[rcx+8]` reads `rcx`.
        //
        // Spelled out here for the reason `writes` is above: a fixture deriving this from the
        // effect the walk branches on agrees with the code under test about a wrong answer.
        let reads: Vec<RegisterOperand> = {
            let mut reads: Vec<RegisterOperand> = match mnemonic {
                "mul" | "div" => vec![named("rax")],
                "push" | "pop" | "ret" => vec![named("rsp")],
                _ => Vec::new(),
            };
            // A destination that is only written: the copies, and `pop`. Everything else here
            // either reads its first operand as well (the arithmetic, the compares, `xchg`,
            // `cmovcc`) or has no register destination at all.
            let written_only = matches!(
                effect,
                Effect::Move | Effect::MoveSigned | Effect::LoadAddress | Effect::Pop
            );
            for (index, operand) in operands.iter().enumerate() {
                let addressed_only = index == 0 && written_only;
                let named: Vec<RegisterOperand> = match operand {
                    Operand::Register(register) if !addressed_only => vec![register.clone()],
                    Operand::Memory(memory) => memory
                        .base
                        .iter()
                        .chain(memory.index.iter())
                        .cloned()
                        .collect(),
                    _ => Vec::new(),
                };
                for register in named {
                    if !reads.iter().any(|seen| seen.name == register.name) {
                        reads.push(register);
                    }
                }
            }
            reads
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
            writes,
            reads,
            // **A multiply writes the flags too**, and it is filed here under `Other` -- so a
            // fixture deriving this from the effect alone says the opposite of what the decoder
            // says (`rflags_written()`, which for `mul` is the carry and the overflow). A test
            // putting one between a compare and its branch would then be pinning a rule the real
            // answer does not reach.
            writes_flags: matches!(mnemonic, "mul" | "div")
                || matches!(
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
        // **A64's two spellings of one register**, which is the same relationship `rax`/`eax` has
        // and the same field a partial-read test is about: `x9` is the whole of it and `w9` is its
        // low four bytes, which the decoder reports as `full: "x9"` either way. No x86 register is
        // spelled this way, so this catches nothing it should not.
        if let Some(digits) = name.strip_prefix('w').or_else(|| name.strip_prefix('x'))
            && !digits.is_empty()
            && digits.chars().all(|c| c.is_ascii_digit())
        {
            return RegisterOperand {
                name: name.to_string(),
                full: format!("x{digits}"),
                width: match name.starts_with('w') {
                    true => 4,
                    false => 8,
                },
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

    /// A64's table load: `[base, index, lsl #n]`, where the index steps one **entry** at a time,
    /// so the scale and the width are the same number. `size` is what the load reads -- 1 for the
    /// `ldrsb` table `mountmgr` has, 4 for its `ldrsw` one.
    fn table_load(base: &str, index: &str, size: u32) -> Operand {
        Operand::Memory(MemoryOperand {
            size: Some(size),
            segment: None,
            base: Some(named(base)),
            index: Some(named(index)),
            scale: u8::try_from(size).expect("an entry is 1, 2 or 4 bytes"),
            displacement: 0,
            address: None,
        })
    }

    /// An `adr`'s operand: the address it computed, with no register contributing to it. The
    /// decoder reports no base for one, which is where this differs from x86's `lea [rip+n]`.
    fn adr_to(address: u64) -> Operand {
        Operand::Memory(MemoryOperand {
            size: None,
            segment: None,
            base: None,
            index: None,
            scale: 1,
            displacement: 0,
            address: Some(address),
        })
    }

    /// The `lsl #n` an A64 instruction folds into an operand, as the decoder hands it over: text,
    /// in the hatch the typed operands do not cover.
    fn lsl(bits: u32) -> Operand {
        Operand::Other(format!("lsl #{bits:#x}"))
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

    /// Readable image memory the driver cannot write -- `.text` and `.rdata` -- which is what a
    /// literal pool has to sit in.
    ///
    /// Deliberately **wider** than [`in_image`] and asked for a different reason: that one answers
    /// "is this address code in this driver", for a jump-table entry, and a pool is data. The
    /// fixtures have no section table, so this is the whole fixture image plus a writable window
    /// carved out of it -- enough to state both halves of the rule.
    fn constant_data(address: u64) -> bool {
        (IMAGE_BASE..IMAGE_BASE + IMAGE_SIZE).contains(&address) && !WRITABLE.contains(&address)
    }

    /// A `.data`-like window inside the fixture image: readable, and writable, so nothing in it is a
    /// constant however it is addressed.
    const WRITABLE: std::ops::Range<u64> = (IMAGE_BASE + 0x9_0000)..(IMAGE_BASE + 0xa_0000);

    fn in_image(address: u64) -> bool {
        (IMAGE_BASE..IMAGE_BASE + IMAGE_SIZE).contains(&address)
    }

    /// An ARM64 dispatch routine, whose control code is materialised across two instructions.
    ///
    /// **A64 cannot state a control code in a compare.** Its immediates are twelve bits, so any
    /// code above `0xfff` is built with `movz`/`movk` into a register and compared register to
    /// register -- which is why dbgscope#170 named "the immediate a compare holds" as the thing
    /// this map was waiting on. Without the `movk` arm the pass loses the register at the second
    /// instruction and reports a driver that accepts nothing.
    ///
    /// The prologue is the same chain as x64's under different names: the `Irp` arrives in `x1`
    /// per AAPCS64, and the structure offsets are shared because both targets are 64-bit.
    #[test]
    fn an_arm64_chain_recovers_a_code_built_from_two_halves() {
        let block = vec![
            insn(
                DISPATCH,
                "ldr",
                vec![reg("x8"), pointer("x1", 0xb8)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 4,
                "ldr",
                vec![reg("w9"), mem("x8", 0x18)],
                Flow::Fallthrough,
            ),
            // `mov w10,#8` / `movk w10,#0x6D,lsl #0x10` -- the decoder folds each shift into the
            // value, so the second immediate arrives as `0x6D0000` rather than as `0x6D` and a
            // shift.
            insn(
                DISPATCH + 8,
                "mov",
                vec![reg("w10"), imm(8)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xc,
                "movk",
                vec![reg("w10"), imm(0x6d_0000)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x10,
                "cmp",
                vec![reg("w9"), reg("w10")],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x14,
                "b.eq",
                Vec::new(),
                Flow::Branch(Some(0x900)),
            ),
            insn(DISPATCH + 0x18, "ret", Vec::new(), Flow::Return),
        ];

        let found = map(
            DISPATCH,
            &block,
            Layout::ARM64,
            unreadable,
            in_image,
            constant_data,
            never,
        );

        assert!(found.code_proved, "the chain from the IRP was followed");
        assert_eq!(
            found
                .cases
                .iter()
                .map(|case| (case.code, case.lands, case.recovered))
                .collect::<Vec<_>>(),
            vec![(0x6d_0008, 0x900, Recovery::Compare)],
            "{:?}",
            found.cases
        );
    }

    /// A PC-relative literal load, as dbgscope decodes one: no base, no index, and the address the
    /// encoding names.
    ///
    /// Its own test pins that shape -- `ldr x5,nt!HalpStubVmTarget+0x34` answers `base: None` with
    /// the resolved address, "nothing at run time contributes to it" -- so this fixture is that
    /// answer rather than a guess at it.
    fn literal(at: u64, from: u64) -> Operand {
        Operand::Memory(MemoryOperand {
            size: Some(4),
            segment: None,
            base: None,
            index: None,
            scale: 1,
            displacement: at.wrapping_sub(from) as i64,
            address: Some(at),
        })
    }

    /// The ARM64 chain the narrow-form tests share: the code out of the IRP, a load whose form is
    /// under test, and a compare of the two. Only the middle instruction differs between them, so
    /// it is the argument and the rest is fixed -- a fixture that varied elsewhere would let a test
    /// pass for the wrong reason.
    fn literal_compare(mnemonic: &str, operands: Vec<Operand>) -> Vec<Instruction> {
        vec![
            insn(
                DISPATCH,
                "ldr",
                vec![reg("x8"), pointer("x1", 0xb8)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 4,
                "ldr",
                vec![reg("w9"), mem("x8", 0x18)],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 8, mnemonic, operands, Flow::Fallthrough),
            insn(
                DISPATCH + 0xc,
                "cmp",
                vec![reg("w9"), reg("w10")],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x10,
                "b.eq",
                Vec::new(),
                Flow::Branch(Some(0x900)),
            ),
            insn(DISPATCH + 0x14, "ret", Vec::new(), Flow::Return),
        ]
    }

    /// A reader serving one four-byte pool entry, and counting what it was asked.
    fn pool_reader(
        at: u64,
        value: u32,
        served: &std::cell::Cell<usize>,
    ) -> impl FnMut(u64, usize) -> Option<Vec<u8>> + '_ {
        move |address, len| {
            served.set(served.get() + 1);
            (address == at && len == 4).then(|| value.to_le_bytes().to_vec())
        }
    }

    /// **A control code in a literal pool is a case**, which is the half of `FOLLOWUPS.md` item 82
    /// that reaches the codes rather than the evidence.
    ///
    /// HEVD's ARM64 dispatch compares against `ldr w9,HEVD+0x87824`, whose pool entry is a control
    /// code. Before the pool was read, `scalar_of` saw a memory operand where it wanted a value and
    /// the compare resolved to nothing -- the site landed in `untracked` and the code was never
    /// named. The assertion is the code itself, not the warning.
    #[test]
    fn an_arm64_literal_pool_entry_is_recovered_as_a_case() {
        const POOL: u64 = IMAGE_BASE + 0x8_7824;
        let block = vec![
            insn(
                DISPATCH,
                "ldr",
                vec![reg("x8"), pointer("x1", 0xb8)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 4,
                "ldr",
                vec![reg("w9"), mem("x8", 0x18)],
                Flow::Fallthrough,
            ),
            // The constant no A64 instruction can hold, so the compiler put it in `.text` and reads
            // it back through the program counter.
            insn(
                DISPATCH + 8,
                "ldr",
                vec![reg("w10"), literal(POOL, DISPATCH + 8)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xc,
                "cmp",
                vec![reg("w9"), reg("w10")],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x10,
                "b.eq",
                Vec::new(),
                Flow::Branch(Some(0x900)),
            ),
            insn(DISPATCH + 0x14, "ret", Vec::new(), Flow::Return),
        ];

        let served = std::cell::Cell::new(0usize);
        let found = map(
            DISPATCH,
            &block,
            Layout::ARM64,
            pool_reader(POOL, 0x0022_203b, &served),
            in_image,
            constant_data,
            never,
        );

        assert!(found.code_proved, "the chain from the IRP was followed");
        assert_eq!(
            found
                .cases
                .iter()
                .map(|case| (case.code, case.lands, case.recovered))
                .collect::<Vec<_>>(),
            vec![(0x0022_203b, 0x900, Recovery::Compare)],
            "{:?}",
            found.cases
        );
        // **Once, not once per sweep.** The whole reason the pool is resolved before the walk is
        // that the walk runs many times over, and a read inside it would cost an engine round trip
        // per sweep -- see `with_pool_immediates`.
        assert_eq!(served.get(), 1, "the pool entry was read exactly once");
    }

    /// **And a status in a literal pool is a refusal**, which is the other half of item 82.
    ///
    /// `rdyboost!SmdDispatchDeviceControl+0x1b8` is `ldr w20,<pool>` / `b <epilogue>` with
    /// `0xc000000d` (`STATUS_INVALID_PARAMETER`) in the pool. `status_after` already reads a
    /// `Value::Literal` out of the register a routine returns through; what it could not do was see
    /// one arrive from memory, so `error_status` found a memory operand where it wanted a constant
    /// and the block was not a refusal. Item 82's measurement is the consequence: 235 codes
    /// recovered across seven drivers and **not one** reporting `accepted: false`.
    ///
    /// So the assertion is `accepted: Some(false)` on the case whose landing block loads the pool
    /// status -- the case is a rejection rather than a code the driver takes.
    #[test]
    fn an_arm64_literal_pool_status_is_read_as_a_refusal() {
        const POOL: u64 = IMAGE_BASE + 0x4_0100;
        const REFUSES: u64 = DISPATCH + 0x18;
        let block = vec![
            insn(
                DISPATCH,
                "ldr",
                vec![reg("x8"), pointer("x1", 0xb8)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 4,
                "ldr",
                vec![reg("w9"), mem("x8", 0x18)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 8,
                "cmp",
                vec![reg("w9"), imm(0x222_003)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xc,
                "b.eq",
                Vec::new(),
                Flow::Branch(Some(REFUSES)),
            ),
            // The accepting path, so the routine is not one block carrying two meanings.
            insn(
                DISPATCH + 0x10,
                "mov",
                vec![reg("w0"), imm(0)],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x14, "ret", Vec::new(), Flow::Return),
            // Where the recognised code lands: the status this driver refuses it with is in the
            // pool, and `w0` is where an ARM64 routine returns one.
            insn(
                REFUSES,
                "ldr",
                vec![reg("w0"), literal(POOL, REFUSES)],
                Flow::Fallthrough,
            ),
            insn(REFUSES + 4, "ret", Vec::new(), Flow::Return),
        ];

        let served = std::cell::Cell::new(0usize);
        let found = map(
            DISPATCH,
            &block,
            Layout::ARM64,
            pool_reader(POOL, 0xc000_000d, &served),
            in_image,
            constant_data,
            never,
        );

        assert_eq!(
            found
                .cases
                .iter()
                .map(|case| (case.code, case.accepted))
                .collect::<Vec<_>>(),
            vec![(0x222_003, Some(false))],
            "the pool status makes this case a refusal: {:?}",
            found.cases
        );
    }

    /// **The same operand shape on x64 is a global, and folding it would invent constants.**
    ///
    /// `mov eax,[00401000h]` has no base, no index and an absolute address -- byte for byte the
    /// form an A64 literal load takes. On x64 it reads the driver's own mutable data, so a compare
    /// after it is a statement about whatever was last written there rather than about a constant.
    /// That is why `Layout::literal_pool` is a per-target flag and not a shape test, and this is
    /// the assertion that keeps it one: no case, and the reader is never even asked.
    #[test]
    fn an_x64_absolute_load_is_not_a_literal_pool() {
        const GLOBAL: u64 = IMAGE_BASE + 0x2_0000;
        let block = vec![
            insn(
                DISPATCH,
                "mov",
                vec![reg("rbx"), pointer("rdx", 0xb8)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 4,
                "mov",
                vec![reg("r13d"), mem("rbx", 0x18)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 8,
                "mov",
                vec![reg("eax"), literal(GLOBAL, DISPATCH + 8)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xc,
                "cmp",
                vec![reg("r13d"), reg("eax")],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x10, "je", Vec::new(), Flow::Branch(Some(0x900))),
            insn(DISPATCH + 0x14, "ret", Vec::new(), Flow::Return),
        ];

        let served = std::cell::Cell::new(0usize);
        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            pool_reader(GLOBAL, 0x0022_203b, &served),
            in_image,
            constant_data,
            never,
        );

        assert!(
            found.cases.is_empty(),
            "a global is not a constant: {:?}",
            found.cases
        );
        assert_eq!(
            served.get(),
            0,
            "an x64 target has no literal pool, so nothing should have been read for one"
        );
    }

    /// **A pool entry the reader declines is left as the load it was**, which is the degradation
    /// item 82's bound relies on: the compare resolves to nothing, the site is reported, and no
    /// code is invented from bytes nobody could read.
    ///
    /// The reader here refuses everything, which is what one does for an address outside the module
    /// holding the routine.
    #[test]
    fn an_unreadable_arm64_pool_entry_names_no_code() {
        const POOL: u64 = IMAGE_BASE + 0x8_7824;
        let block = vec![
            insn(
                DISPATCH,
                "ldr",
                vec![reg("x8"), pointer("x1", 0xb8)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 4,
                "ldr",
                vec![reg("w9"), mem("x8", 0x18)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 8,
                "ldr",
                vec![reg("w10"), literal(POOL, DISPATCH + 8)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xc,
                "cmp",
                vec![reg("w9"), reg("w10")],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x10,
                "b.eq",
                Vec::new(),
                Flow::Branch(Some(0x900)),
            ),
            insn(DISPATCH + 0x14, "ret", Vec::new(), Flow::Return),
        ];

        let found = map(
            DISPATCH,
            &block,
            Layout::ARM64,
            unreadable,
            in_image,
            constant_data,
            never,
        );

        assert!(
            found.cases.is_empty(),
            "nothing was read, so nothing may be named: {:?}",
            found.cases
        );
        // **The compare's address, not the branch's.** `Compared::at` is where the comparison is,
        // and the equality arm that files an unnameable case pushes that -- so this pins the site a
        // reader is sent to as well as the fact that one is reported.
        assert_eq!(
            found.untracked,
            vec![DISPATCH + 0xc],
            "the compare against a value that would not resolve is reported instead"
        );
    }

    /// **`ldrsw` is not the literal form this folds**, and the reason is the value rather than the
    /// shape: a sign-extending load of `0xc000000d` leaves `0xffffffffc000000d`, which is not the
    /// `ULONG` the compare is about. [`pool_load`] requires [`Effect::Move`] for that, and the
    /// assertion is that the reader is never asked.
    #[test]
    fn a_sign_extending_arm64_literal_is_not_folded() {
        const POOL: u64 = IMAGE_BASE + 0x8_7824;
        let served = std::cell::Cell::new(0usize);
        let found = map(
            DISPATCH,
            &literal_compare("ldrsw", vec![reg("w10"), literal(POOL, DISPATCH + 8)]),
            Layout::ARM64,
            pool_reader(POOL, 0x0022_203b, &served),
            in_image,
            constant_data,
            never,
        );

        assert_eq!(served.get(), 0, "a signed load is not this form");
        assert!(found.cases.is_empty(), "{:?}", found.cases);
    }

    /// **And an eight-byte literal is not one either**: it is a pointer or a doubleword constant,
    /// and neither is a control code or a status. [`FIELD_WIDTH`] is what excludes it, which is the
    /// same rule every other value this module folds has to pass.
    #[test]
    fn a_wide_arm64_literal_is_not_folded() {
        const POOL: u64 = IMAGE_BASE + 0x8_7824;
        let wide = Operand::Memory(MemoryOperand {
            size: Some(8),
            segment: None,
            base: None,
            index: None,
            scale: 1,
            displacement: 0x20,
            address: Some(POOL),
        });
        let served = std::cell::Cell::new(0usize);
        let found = map(
            DISPATCH,
            &literal_compare("ldr", vec![reg("x10"), wide]),
            Layout::ARM64,
            pool_reader(POOL, 0x0022_203b, &served),
            in_image,
            constant_data,
            never,
        );

        assert_eq!(served.get(), 0, "a doubleword literal is not this form");
        assert!(found.cases.is_empty(), "{:?}", found.cases);
    }

    /// **A pool in read-only data is folded, even though it is not code.**
    ///
    /// The finding this pins: the first gate was `in_image`, the predicate that answers whether an
    /// address is **code** in this driver, and a legitimate `.rdata` pool was therefore refused
    /// without being read -- so the control code it held stayed lost, which is the whole of what
    /// item 82 was for. The argument for that gate was the literal load's ±1 MB reach, and it
    /// confuses distance with permissions: `.rdata` ordinarily sits well within a megabyte of
    /// `.text`.
    ///
    /// So the two predicates are made to **disagree** here, which is the only way to state the rule:
    /// `in_image` excludes the pool address and `constant_data` admits it. A test where both cover
    /// the whole fixture image cannot tell which one the fold consults.
    #[test]
    fn an_arm64_literal_pool_in_read_only_data_is_folded() {
        // Past the window `only_text` admits, so "not code" -- and inside the image and outside
        // `WRITABLE`, so "constant". That is `.rdata`.
        const POOL: u64 = IMAGE_BASE + 0x8_7824;
        fn only_text(address: u64) -> bool {
            (IMAGE_BASE..IMAGE_BASE + 0x8_0000).contains(&address)
        }
        assert!(
            !only_text(POOL) && constant_data(POOL),
            "the fixture has to make the two predicates disagree, or it tests nothing"
        );

        let served = std::cell::Cell::new(0usize);
        let found = map(
            DISPATCH,
            &literal_compare("ldr", vec![reg("w10"), literal(POOL, DISPATCH + 8)]),
            Layout::ARM64,
            pool_reader(POOL, 0x0022_203b, &served),
            only_text,
            constant_data,
            never,
        );

        assert_eq!(served.get(), 1, "the pool was read");
        assert_eq!(
            found.cases.iter().map(|case| case.code).collect::<Vec<_>>(),
            vec![0x0022_203b],
            "and the code it held is a case: {:?}",
            found.cases
        );
    }

    /// **And a literal in writable storage is not folded**, which is the other half of the same rule
    /// and the reason the gate exists at all.
    ///
    /// A base-less `ldr` proves only that the address is PC-relative; it can legally name module
    /// memory the driver writes. Folded, whatever was last written there becomes a control code the
    /// driver is reported to accept -- a value invented from runtime state, which is the class of
    /// wrong answer this module is arranged against. Raised on review of #351.
    #[test]
    fn an_arm64_literal_in_writable_storage_is_not_folded() {
        const MUTABLE: u64 = IMAGE_BASE + 0x9_0100;
        assert!(
            WRITABLE.contains(&MUTABLE) && !constant_data(MUTABLE),
            "the fixture's writable window has to contain this"
        );

        let served = std::cell::Cell::new(0usize);
        let found = map(
            DISPATCH,
            &literal_compare("ldr", vec![reg("w10"), literal(MUTABLE, DISPATCH + 8)]),
            Layout::ARM64,
            pool_reader(MUTABLE, 0x0022_203b, &served),
            in_image,
            constant_data,
            never,
        );

        assert_eq!(
            served.get(),
            0,
            "writable storage must not even be read for a constant"
        );
        assert!(
            found.cases.is_empty(),
            "and nothing may be named from it: {:?}",
            found.cases
        );
    }

    /// **An address that would not read is asked once, not once per instruction.**
    ///
    /// The dedup map keys on every address *attempted* rather than on the ones that answered. Keyed
    /// on successes, a missing dump page or one malformed literal repeated through a routine would
    /// retry it per instruction and spend the whole read budget on an address that will never read
    /// -- leaving the readable literals after it unfolded, so recoverable codes disappear for want
    /// of a slot. Raised on review of #351.
    #[test]
    fn an_unreadable_arm64_pool_address_is_attempted_once() {
        const POOL: u64 = IMAGE_BASE + 0x8_7824;
        let served = std::cell::Cell::new(0usize);
        let read = |address: u64, _len: usize| -> Option<Vec<u8>> {
            served.set(served.get() + 1);
            let _ = address;
            None
        };
        // The same pool address loaded three times over, which is what a routine comparing against
        // one constant in three places looks like.
        let mut block = literal_compare("ldr", vec![reg("w10"), literal(POOL, DISPATCH + 8)]);
        block.push(insn(
            DISPATCH + 0x18,
            "ldr",
            vec![reg("w11"), literal(POOL, DISPATCH + 0x18)],
            Flow::Fallthrough,
        ));
        block.push(insn(
            DISPATCH + 0x1c,
            "ldr",
            vec![reg("w12"), literal(POOL, DISPATCH + 0x1c)],
            Flow::Fallthrough,
        ));
        block.push(insn(DISPATCH + 0x20, "ret", Vec::new(), Flow::Return));

        let found = map(
            DISPATCH,
            &block,
            Layout::ARM64,
            read,
            in_image,
            constant_data,
            never,
        );

        assert_eq!(
            served.get(),
            1,
            "three loads of one unreadable address are one attempt"
        );
        assert!(found.cases.is_empty(), "{:?}", found.cases);
    }

    /// **A64 names a store's source first, and a store is not a load.**
    ///
    /// x86 puts memory in operand zero for a store, so the walk's "operand zero is the
    /// destination" rule catches it by shape. A64 puts the *register* there, so `str w11,[x8,#18h]`
    /// arrives with a register in hand and would be modelled as a load **into** `w11` -- reading
    /// the control code out of the memory operand and handing it to whatever compares `w11` next.
    /// That invents a case out of an instruction that stored to the field, which is the direction
    /// of wrongness this module is arranged against.
    ///
    /// The fix reads `Instruction::writes`, so the assertion is that comparing the stored-from
    /// register recovers **no** case at all.
    #[test]
    fn an_arm64_store_does_not_load_the_register_it_names() {
        let block = vec![
            insn(
                DISPATCH,
                "ldr",
                vec![reg("x8"), pointer("x1", 0xb8)],
                Flow::Fallthrough,
            ),
            // A store *to* the control-code offset through the traced pointer: the worst case,
            // since every displacement the walk recognises is in play.
            insn(
                DISPATCH + 4,
                "str",
                vec![reg("w11"), mem("x8", 0x18)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 8,
                "cmp",
                vec![reg("w11"), imm(5)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xc,
                "b.eq",
                Vec::new(),
                Flow::Branch(Some(0x900)),
            ),
            insn(DISPATCH + 0x10, "ret", Vec::new(), Flow::Return),
        ];

        let found = map(
            DISPATCH,
            &block,
            Layout::ARM64,
            unreadable,
            in_image,
            constant_data,
            never,
        );

        assert!(
            found.cases.is_empty(),
            "a store put nothing in w11, so the compare after it is about nothing: {:?}",
            found.cases
        );
        assert_eq!(found.case_count, 0);
    }

    /// **A64 folds the compare into the branch, and a dispatch chain written that way is read.**
    ///
    /// `sub w9,w9,w10` / `cbz w9,handler` is the ARM64 spelling of the `sub ecx,222003h` / `je`
    /// chain this module cites HEVD for, and it is the shape a rebased switch takes on that
    /// target. Before `folded_compare` it recovered **nothing**: no cases, and no `unresolved`
    /// either, so the map reported `code_proved` with an empty list -- a driver that accepts no
    /// control codes, which is the answer this whole module is arranged against. Measured on
    /// windbg-mcp#343.
    ///
    /// The second half is the one that keeps the list honest. `tbz` tests a single bit, which is a
    /// statement about part of a `ULONG` and not a value, so it is **not** a case -- exactly what
    /// `test ecx,3` / `je` gets on x86. What it must not be is silent, and `untracked` is where it
    /// goes so a short map reads as a lower bound.
    #[test]
    fn an_arm64_compare_and_branch_is_both_halves() {
        let chain = |terminator: Instruction| {
            let mut block = vec![
                insn(
                    DISPATCH,
                    "ldr",
                    vec![reg("x8"), pointer("x1", 0xb8)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 4,
                    "ldr",
                    vec![reg("w9"), mem("x8", 0x18)],
                    Flow::Fallthrough,
                ),
                // The code is materialised and subtracted, which is what rebases the register.
                insn(
                    DISPATCH + 8,
                    "mov",
                    vec![reg("w10"), imm(0x2003)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0xc,
                    "movk",
                    vec![reg("w10"), imm(0x22_0000)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x10,
                    "sub",
                    vec![reg("w9"), reg("w9"), reg("w10")],
                    Flow::Fallthrough,
                ),
            ];
            block.push(terminator);
            block.push(insn(DISPATCH + 0x18, "ret", Vec::new(), Flow::Return));
            map(
                DISPATCH,
                &block,
                Layout::ARM64,
                unreadable,
                in_image,
                constant_data,
                never,
            )
        };

        // `cbz w9,handler` -- the register is zero exactly when the code was `0x222003`.
        let zero = chain(insn(
            DISPATCH + 0x14,
            "cbz",
            vec![reg("w9")],
            Flow::Branch(Some(0x900)),
        ));
        assert_eq!(
            zero.cases
                .iter()
                .map(|case| (case.code, case.lands, case.recovered))
                .collect::<Vec<_>>(),
            vec![(0x222003, 0x900, Recovery::Compare)],
            "{:?}",
            zero.cases
        );
        assert!(zero.code_proved);
        assert!(zero.untracked.is_empty(), "{:?}", zero.untracked);

        // `cbnz w9,other` -- the branch is the rejection, so the case is the fall-through.
        let not_zero = chain(insn(
            DISPATCH + 0x14,
            "cbnz",
            vec![reg("w9")],
            Flow::Branch(Some(0x900)),
        ));
        assert_eq!(
            not_zero
                .cases
                .iter()
                .map(|case| (case.code, case.lands))
                .collect::<Vec<_>>(),
            vec![(0x222003, DISPATCH + 0x18)],
            "the case is what follows a branch that rejects: {:?}",
            not_zero.cases
        );

        // **A bit test is not a value.** `tbz w9,#3,handler` decides something about the code that
        // this cannot name, so there is no case -- and an entry in `untracked`, without which the
        // map would be short by one with nothing saying so.
        let bit = chain(insn(
            DISPATCH + 0x14,
            "tbz",
            vec![reg("w9"), imm(3)],
            Flow::Branch(Some(0x900)),
        ));
        assert!(
            bit.cases.is_empty(),
            "one bit of a ULONG is not a control code: {:?}",
            bit.cases
        );
        assert_eq!(
            bit.untracked,
            vec![DISPATCH + 0x14],
            "and the branch it could not read is recorded: {bit:?}"
        );

        // **A three-register `sub`, which is the form that pins where the source is read from.**
        // Every chain above writes `sub w9,w9,w10`, where the destination *is* the source -- so
        // taking either gives the same answer and the rule goes untested. Mutation said so: with
        // `arithmetic_source` forced back to the destination, all of the above still passed.
        // `sub w9,w8,w10` is the same statement with the code left in `w8`, and there the two
        // readings differ: the destination holds nothing yet, so a walk reading it loses the chain.
        let separate = vec![
            insn(
                DISPATCH,
                "ldr",
                vec![reg("x8"), pointer("x1", 0xb8)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 4,
                "ldr",
                vec![reg("w8"), mem("x8", 0x18)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 8,
                "mov",
                vec![reg("w10"), imm(0x2003)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xc,
                "movk",
                vec![reg("w10"), imm(0x22_0000)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x10,
                "sub",
                vec![reg("w9"), reg("w8"), reg("w10")],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x14,
                "cbz",
                vec![reg("w9")],
                Flow::Branch(Some(0x900)),
            ),
            insn(DISPATCH + 0x18, "ret", Vec::new(), Flow::Return),
        ];
        let found = map(
            DISPATCH,
            &separate,
            Layout::ARM64,
            unreadable,
            in_image,
            constant_data,
            never,
        );
        assert_eq!(
            found
                .cases
                .iter()
                .map(|case| (case.code, case.lands))
                .collect::<Vec<_>>(),
            vec![(0x222003, 0x900)],
            "the source is operand one on a three-register `sub`: {:?}",
            found.cases
        );
    }

    /// **An ARM64 rejection is read, through either place it can be written.**
    ///
    /// Both were invisible when this branch first enabled the map on ARM64, and both fail in the
    /// direction that matters: a refused code reported as **accepted**, with whatever it called
    /// named as its handler.
    ///
    /// - The status itself takes two instructions. `mov w0,#0x10` / `movk w0,#0xC000,lsl #0x10` is
    ///   `0xC0000010`, and `status_after` runs before the walk folds those together -- so the
    ///   `movk` read as an unmodelled write and took the refusal back.
    /// - A store to `Irp->IoStatus.Status` names its **source** first on A64, so a rule reading
    ///   operand zero for the memory saw no store at all. That is the shape a rejection takes once
    ///   a completion call has clobbered the return register, which is the ordinary case.
    ///
    /// Raised on windbg-mcp#343.
    #[test]
    fn an_arm64_rejection_is_read_from_its_status_and_from_its_store() {
        let refusal = |through_the_irp: bool| {
            let mut block = vec![
                insn(
                    DISPATCH,
                    "ldr",
                    vec![reg("x8"), pointer("x1", 0xb8)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 4,
                    "ldr",
                    vec![reg("w9"), mem("x8", 0x18)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 8,
                    "mov",
                    vec![reg("w10"), imm(0x2003)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0xc,
                    "movk",
                    vec![reg("w10"), imm(0x22_0000)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x10,
                    "cmp",
                    vec![reg("w9"), reg("w10")],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x14,
                    "b.eq",
                    Vec::new(),
                    Flow::Branch(Some(DISPATCH + 0x40)),
                ),
                insn(DISPATCH + 0x18, "ret", Vec::new(), Flow::Return),
            ];
            // The handler. `w11` for the store so that the return register is untouched and the
            // two paths are actually separate -- built in `w0`, this would pass on `returned`
            // whatever the store did.
            let status = match through_the_irp {
                true => "w11",
                false => "w0",
            };
            block.extend([
                insn(
                    DISPATCH + 0x40,
                    "mov",
                    vec![reg(status), imm(0x10)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x44,
                    "movk",
                    vec![reg(status), imm(0xc000_0000)],
                    Flow::Fallthrough,
                ),
            ]);
            if through_the_irp {
                block.push(insn(
                    DISPATCH + 0x48,
                    "str",
                    vec![reg("w11"), mem("x1", 0x30)],
                    Flow::Fallthrough,
                ));
            }
            block.push(insn(DISPATCH + 0x4c, "ret", Vec::new(), Flow::Return));

            let found = map(
                DISPATCH,
                &block,
                Layout::ARM64,
                unreadable,
                in_image,
                constant_data,
                never,
            );
            assert_eq!(found.cases.len(), 1, "{:?}", found.cases);
            assert_eq!(found.cases[0].code, 0x222003, "{:?}", found.cases);
            found.cases[0].accepted
        };

        assert_eq!(
            refusal(false),
            Some(false),
            "a status built by `mov`/`movk` and returned is a refusal"
        );
        assert_eq!(
            refusal(true),
            Some(false),
            "and so is one stored into `Irp->IoStatus.Status`, whose source A64 names first"
        );
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

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            unreadable,
            in_image,
            constant_data,
            never,
        );

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

    /// **One compare, two conditional branches** -- the three-way test a compiler emits for a
    /// binary-search dispatch, and the shape that cost a code.
    ///
    /// `cmp r13d,N` / `ja default` / `je handler`. The `ja` ends a block, so the `cmp` is in one
    /// block and the `je` is the terminator of the next with no compare of its own. The equality
    /// was dropped with nothing in the answer saying so: no unresolved transfer, no blind
    /// instruction, no stop -- just a code the driver accepts and the map does not list.
    ///
    /// Taken from `mountmgr` at RVA `0x149dc`, where it cost `0x6dc000`
    /// (`IOCTL_MOUNTMGR_CREATE_POINT`) outright and one of `0x6d4020`'s two sites. Found by
    /// Ghidra's decompiler and by Driver Buddy Revolutions independently; **not** by this module's
    /// own differential interpreter nor by the dump-tier oracle, both of which are derived from my
    /// own reading of that driver and encode the same miss.
    #[test]
    fn a_compare_read_by_a_second_branch_is_still_the_same_compare() {
        let mut block = prologue(DISPATCH);
        block.extend([
            insn(
                DISPATCH + 8,
                "cmp",
                vec![reg("r13d"), imm(0x6dc000)],
                Flow::Fallthrough,
            ),
            // Ends this block, and does not write the flags.
            insn(
                DISPATCH + 0xe,
                "ja",
                Vec::new(),
                Flow::Branch(Some(DISPATCH + 0x100)),
            ),
            // A block of its own, whose terminator reads the compare above it.
            insn(DISPATCH + 0x14, "je", Vec::new(), Flow::Branch(Some(0x900))),
            insn(DISPATCH + 0x1a, "ret", Vec::new(), Flow::Return),
            insn(DISPATCH + 0x100, "ret", Vec::new(), Flow::Return),
        ]);

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            unreadable,
            in_image,
            constant_data,
            never,
        );

        assert_eq!(
            found
                .cases
                .iter()
                .map(|case| (case.code, case.lands, case.recovered))
                .collect::<Vec<_>>(),
            vec![(0x6dc000, 0x900, Recovery::Compare)],
            "the second branch reads the compare the first one left: {:?}",
            found.cases
        );
        assert!(
            found.code_proved,
            "and it is the IRP's code, not a displacement"
        );
    }

    /// **And the edges it does not cross**, which is the other half of that rule and the half that
    /// invents cases if it is wrong.
    ///
    /// Past `ja K` **taken** the code is above `K`, so an equality against that same compare
    /// cannot hold; past `je K` not taken it is not `K`. A pending compare carried onto either
    /// edge would report a case no execution reaches -- and a fabricated case is worse than a
    /// missing one, because nothing about it says it is fabricated.
    #[test]
    fn a_compare_does_not_reach_an_edge_its_own_branch_ruled_out() {
        // The `ja`'s **taken** target ends in a `je` against the same flags.
        let mut above = prologue(DISPATCH);
        above.extend([
            insn(
                DISPATCH + 8,
                "cmp",
                vec![reg("r13d"), imm(0x6dc000)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xe,
                "ja",
                Vec::new(),
                Flow::Branch(Some(DISPATCH + 0x100)),
            ),
            insn(DISPATCH + 0x14, "ret", Vec::new(), Flow::Return),
            insn(
                DISPATCH + 0x100,
                "je",
                Vec::new(),
                Flow::Branch(Some(0x900)),
            ),
            insn(DISPATCH + 0x106, "ret", Vec::new(), Flow::Return),
        ]);
        let found = map(
            DISPATCH,
            &above,
            Layout::X64,
            unreadable,
            in_image,
            constant_data,
            never,
        );
        assert!(
            found.cases.is_empty(),
            "a code the branch just ruled out is not a case: {:?}",
            found.cases
        );

        // The same, through the **other** edge arm. `ja` leaves a bound and takes the arm that
        // builds a bounded fall-through; `jb` does not, and falls to the arm that pushes every
        // successor. Both have a taken edge, and neither may carry the compare across it.
        let mut below = prologue(DISPATCH);
        below.extend([
            insn(
                DISPATCH + 8,
                "cmp",
                vec![reg("r13d"), imm(0x6dc000)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xe,
                "jb",
                Vec::new(),
                Flow::Branch(Some(DISPATCH + 0x100)),
            ),
            insn(DISPATCH + 0x14, "ret", Vec::new(), Flow::Return),
            insn(
                DISPATCH + 0x100,
                "je",
                Vec::new(),
                Flow::Branch(Some(0x900)),
            ),
            insn(DISPATCH + 0x106, "ret", Vec::new(), Flow::Return),
        ]);
        let found = map(
            DISPATCH,
            &below,
            Layout::X64,
            unreadable,
            in_image,
            constant_data,
            never,
        );
        assert!(
            found.cases.is_empty(),
            "below the compare, an equality against it cannot hold either: {:?}",
            found.cases
        );

        // And the fall-through of a `je`, where equality is known false.
        let mut equal = prologue(DISPATCH);
        equal.extend([
            insn(
                DISPATCH + 8,
                "cmp",
                vec![reg("r13d"), imm(0x6dc000)],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0xe, "je", Vec::new(), Flow::Branch(Some(0x900))),
            insn(DISPATCH + 0x14, "je", Vec::new(), Flow::Branch(Some(0x980))),
            insn(DISPATCH + 0x1a, "ret", Vec::new(), Flow::Return),
        ]);
        let found = map(
            DISPATCH,
            &equal,
            Layout::X64,
            unreadable,
            in_image,
            constant_data,
            never,
        );
        assert_eq!(
            found
                .cases
                .iter()
                .map(|case| (case.code, case.lands))
                .collect::<Vec<_>>(),
            vec![(0x6dc000, 0x900)],
            "the first `je` is the case; the second is unreachable and is not a second one: {:?}",
            found.cases
        );
    }

    /// **An inclusive branch leaves equality possible where it *branches*, not where it falls.**
    ///
    /// `cmp code,K` / `jbe handler_side` admits `code == K` on the taken edge and forbids it on the
    /// fall-through, where `code > K`. `ja` is the mirror, which is the shape the other tests here
    /// are built from -- so a rule with the two backwards agrees with those fixtures exactly as
    /// well as the right one does, and only an inclusive condition can tell them apart.
    ///
    /// Both halves are asserted, because the two failures are opposite: the wrong edge **loses** a
    /// case where equality holds, and **invents** one where it cannot.
    #[test]
    fn an_inclusive_branch_carries_its_compare_to_the_edge_it_branches_to() {
        // `jbe` taken: `code <= K`, so the `je` there is a real case.
        let mut taken = prologue(DISPATCH);
        taken.extend([
            insn(
                DISPATCH + 8,
                "cmp",
                vec![reg("r13d"), imm(0x6dc000)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xe,
                "jbe",
                Vec::new(),
                Flow::Branch(Some(DISPATCH + 0x100)),
            ),
            insn(DISPATCH + 0x14, "ret", Vec::new(), Flow::Return),
            insn(
                DISPATCH + 0x100,
                "je",
                Vec::new(),
                Flow::Branch(Some(0x900)),
            ),
            insn(DISPATCH + 0x106, "ret", Vec::new(), Flow::Return),
        ]);
        let found = map(
            DISPATCH,
            &taken,
            Layout::X64,
            unreadable,
            in_image,
            constant_data,
            never,
        );
        assert_eq!(
            found
                .cases
                .iter()
                .map(|case| (case.code, case.lands))
                .collect::<Vec<_>>(),
            vec![(0x6dc000, 0x900)],
            "below-or-equal includes equal, so the compare is still live where it branched: {:?}",
            found.cases
        );

        // And the fall-through of the same branch is `code > K`, where it cannot be.
        let mut fallen = prologue(DISPATCH);
        fallen.extend([
            insn(
                DISPATCH + 8,
                "cmp",
                vec![reg("r13d"), imm(0x6dc000)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xe,
                "jbe",
                Vec::new(),
                Flow::Branch(Some(DISPATCH + 0x100)),
            ),
            insn(DISPATCH + 0x14, "je", Vec::new(), Flow::Branch(Some(0x900))),
            insn(DISPATCH + 0x1a, "ret", Vec::new(), Flow::Return),
            insn(DISPATCH + 0x100, "ret", Vec::new(), Flow::Return),
        ]);
        let found = map(
            DISPATCH,
            &fallen,
            Layout::X64,
            unreadable,
            in_image,
            constant_data,
            never,
        );
        assert!(
            found.cases.is_empty(),
            "above the compare, an equality against it cannot hold: {:?}",
            found.cases
        );
    }

    /// **An `add` reaching zero carried; a `cmp` reaching zero did not.**
    ///
    /// `equality_survives` is derived from the flags an equality leaves, and I derived them from a
    /// *subtraction*. For `add ecx,K` to be zero the operands must sum to exactly 2^32, so `CF=1`
    /// where a `cmp` leaves `CF=0` -- and `jae`/`jb` read carry alone, so their feasible edge
    /// flips. `add ...; jae t; je h` put the case at `t`, where it cannot be, and lost the one on
    /// the fall-through, where it is.
    ///
    /// The carry travels with the comparison rather than being assumed by whoever reads it, which
    /// is why a rule derived from one instruction's flags stopped being wrong about another's.
    #[test]
    fn an_add_that_wrapped_to_zero_carried_and_a_compare_did_not() {
        let chain = |mnemonic: &str, step: u64| {
            let mut block = prologue(DISPATCH);
            block.extend([
                insn(
                    DISPATCH + 8,
                    "mov",
                    vec![reg("ecx"), reg("r13d")],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0xb,
                    mnemonic,
                    vec![reg("ecx"), imm(step)],
                    Flow::Fallthrough,
                ),
                // Reads the carry alone, so which edge the equality is on turns on it.
                insn(
                    DISPATCH + 0x11,
                    "jae",
                    Vec::new(),
                    Flow::Branch(Some(DISPATCH + 0x100)),
                ),
                insn(DISPATCH + 0x17, "je", Vec::new(), Flow::Branch(Some(0x900))),
                insn(DISPATCH + 0x1d, "ret", Vec::new(), Flow::Return),
                insn(
                    DISPATCH + 0x100,
                    "je",
                    Vec::new(),
                    Flow::Branch(Some(0x980)),
                ),
                insn(DISPATCH + 0x106, "ret", Vec::new(), Flow::Return),
            ]);
            map(
                DISPATCH,
                &block,
                Layout::X64,
                unreadable,
                in_image,
                constant_data,
                never,
            )
        };

        // A subtraction leaves `CF=0`, so `jae` is taken and the case is at its target.
        assert_eq!(
            chain("sub", 0x6dc004)
                .cases
                .iter()
                .map(|case| (case.code, case.lands))
                .collect::<Vec<_>>(),
            vec![(0x6dc004, 0x980)],
            "equal values borrow nothing, so the branch reading `CF=0` is taken"
        );

        // An addition that reached zero left `CF=1`, so `jae` is **not** taken and the case is on
        // the fall-through.
        assert_eq!(
            chain("add", 0x6dc004)
                .cases
                .iter()
                .map(|case| (case.code, case.lands))
                .collect::<Vec<_>>(),
            // `0 - 0x6dc004` in the field's width, which is the code the `je` there tests.
            vec![(0xff92_3ffc, 0x900)],
            "an add reaching zero carried out of the field, so that branch is not taken"
        );
    }

    /// **An `add` of the sign bit alone overflows as well as carrying.**
    ///
    /// `0x80000000 + 0x80000000` is zero with `CF=1` **and** `OF=1`: both operands are `INT_MIN`
    /// and the sum is not negative, which is the one addition where that happens. `jno`, `jge` and
    /// `jl` read overflow, so they flip too -- and modelling the carry alone left them reading a
    /// state nobody had recorded, which is what "carry the flags" was supposed to have fixed the
    /// round before.
    #[test]
    fn an_add_of_the_sign_bit_overflows_as_well_as_carrying() {
        let after = |step: u64, mnemonic: &str| {
            let mut block = prologue(DISPATCH);
            block.extend([
                insn(
                    DISPATCH + 8,
                    "mov",
                    vec![reg("ecx"), reg("r13d")],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0xb,
                    "add",
                    vec![reg("ecx"), imm(step)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x11,
                    mnemonic,
                    Vec::new(),
                    Flow::Branch(Some(DISPATCH + 0x100)),
                ),
                insn(DISPATCH + 0x17, "je", Vec::new(), Flow::Branch(Some(0x900))),
                insn(DISPATCH + 0x1d, "ret", Vec::new(), Flow::Return),
                insn(
                    DISPATCH + 0x100,
                    "je",
                    Vec::new(),
                    Flow::Branch(Some(0x980)),
                ),
                insn(DISPATCH + 0x106, "ret", Vec::new(), Flow::Return),
            ]);
            map(
                DISPATCH,
                &block,
                Layout::X64,
                unreadable,
                in_image,
                constant_data,
                never,
            )
            .cases
            .iter()
            .map(|case| case.lands)
            .collect::<Vec<_>>()
        };

        // `jno` after an ordinary `add`: no overflow, so it is taken and the case is at its target.
        assert_eq!(
            after(4, "jno"),
            vec![0x980],
            "an add of four does not overflow, so the branch reading `OF=0` is taken"
        );
        // And after an `add` of the sign bit: overflow, so it is not, and the case falls through.
        assert_eq!(
            after(0x8000_0000, "jno"),
            vec![0x900],
            "two `INT_MIN`s summing to zero overflowed, so that branch is not taken"
        );
    }

    /// **Parity and overflow are decidable too, and were the two arms that had it wrong.**
    ///
    /// `cmp a,b` with `a == b` computes zero, which fixes `OF=0` and `PF=1` -- the low byte `0x00`
    /// has an even number of set bits. So `jp` admits equality where it **branches** and `jo`
    /// excludes it there, exactly as the inclusive and strict relational forms do. They were given
    /// both edges on the grounds that they say nothing about equality, which is what a rule written
    /// as a list of families rather than derived from the flags lets you believe.
    ///
    /// Neither shape occurs in a dispatch chain, which is the point: an edge nobody reaches is
    /// where a fabricated case would sit unnoticed.
    #[test]
    fn parity_and_overflow_admit_equality_on_opposite_edges() {
        let chain = |mnemonic: &str| {
            let mut block = prologue(DISPATCH);
            block.extend([
                insn(
                    DISPATCH + 8,
                    "cmp",
                    vec![reg("r13d"), imm(0x6dc000)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0xe,
                    mnemonic,
                    Vec::new(),
                    Flow::Branch(Some(DISPATCH + 0x100)),
                ),
                insn(DISPATCH + 0x14, "ret", Vec::new(), Flow::Return),
                insn(
                    DISPATCH + 0x100,
                    "je",
                    Vec::new(),
                    Flow::Branch(Some(0x900)),
                ),
                insn(DISPATCH + 0x106, "ret", Vec::new(), Flow::Return),
            ]);
            map(
                DISPATCH,
                &block,
                Layout::X64,
                unreadable,
                in_image,
                constant_data,
                never,
            )
        };

        assert_eq!(
            chain("jp")
                .cases
                .iter()
                .map(|case| case.code)
                .collect::<Vec<_>>(),
            vec![0x6dc000],
            "an equality sets the parity flag, so the branch it takes can still be equal"
        );
        assert!(
            chain("jo").cases.is_empty(),
            "and clears overflow, so the branch it takes cannot be: {:?}",
            chain("jo").cases
        );
    }

    /// **A compare one path into the block left is a case that path reaches.**
    ///
    /// This asserted the opposite until 2026-09-14, on the argument that a comparison is a fact
    /// like a register's value and so belongs to the block only where every path agrees. They are
    /// not the same kind of fact. A register has to hold its value *here*; a comparison says what
    /// the branch below decides **on the path that made it**, and an execution taking that path
    /// reaches the case whatever the other edges did.
    ///
    /// Read against this fixture the old claim -- "a case no execution reaches" -- is plainly
    /// false: falling through `jb 6DC000h` means the code is **not** below it, the `je` below
    /// still reads that same comparison, and an IRP carrying `0x6dc000` takes it. The other path
    /// in compares something else and contributes nothing, which is the point: it takes nothing
    /// away either.
    #[test]
    fn a_compare_one_path_left_is_a_case_that_path_reaches() {
        let mut block = prologue(DISPATCH);
        block.extend([
            insn(
                DISPATCH + 8,
                "cmp",
                vec![reg("r13d"), imm(0x6dc000)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xe,
                "jb",
                Vec::new(),
                Flow::Branch(Some(DISPATCH + 0x20)),
            ),
            // Reached by falling through with the compare live, and again from below with
            // a comparison of its own.
            insn(DISPATCH + 0x14, "je", Vec::new(), Flow::Branch(Some(0x900))),
            insn(DISPATCH + 0x1a, "ret", Vec::new(), Flow::Return),
            // The other path in: its own flags, then back to the `je`.
            insn(
                DISPATCH + 0x20,
                "cmp",
                vec![reg("rax"), imm(1)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x24,
                "jmp",
                Vec::new(),
                Flow::Jmp(Some(DISPATCH + 0x14)),
            ),
        ]);

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            unreadable,
            in_image,
            constant_data,
            never,
        );
        assert_eq!(
            found
                .cases
                .iter()
                .map(|case| (case.code, case.lands, case.site))
                .collect::<Vec<_>>(),
            vec![(0x6dc000, 0x900, DISPATCH + 8)],
            "the fall-through path reaches this case, and the other path says nothing about it"
        );
    }

    /// **Two paths meeting at one branch are two cases, at their own two sites.**
    ///
    /// Which is what makes the live compares a **set** rather than "whichever of the two the join
    /// saw first": `jbe` carries its comparison on the edge it **branches** to, so a block can be
    /// entered by two edges each holding a different one. Keeping one would report a real case and
    /// drop a real case, and nothing in the answer would say which.
    ///
    /// The second code is above the first deliberately. Falling through `jbe 6DC000h` means the
    /// code is greater than `0x6dc000`, so a compare against `0x6dc004` there is a case an
    /// execution reaches; one against a lower value would be a fixture asserting a path that
    /// cannot happen, and this walk does not track ranges to notice.
    #[test]
    fn two_paths_meeting_at_one_branch_are_two_cases() {
        let mut block = prologue(DISPATCH);
        block.extend([
            insn(
                DISPATCH + 8,
                "cmp",
                vec![reg("r13d"), imm(0x6dc000)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xe,
                "jbe",
                Vec::new(),
                Flow::Branch(Some(DISPATCH + 0x30)),
            ),
            insn(
                DISPATCH + 0x14,
                "cmp",
                vec![reg("r13d"), imm(0x6dc004)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x1a,
                "jmp",
                Vec::new(),
                Flow::Jmp(Some(DISPATCH + 0x30)),
            ),
            insn(DISPATCH + 0x30, "je", Vec::new(), Flow::Branch(Some(0x900))),
            insn(DISPATCH + 0x36, "ret", Vec::new(), Flow::Return),
        ]);

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            unreadable,
            in_image,
            constant_data,
            never,
        );
        assert_eq!(
            found
                .cases
                .iter()
                .map(|case| (case.code, case.lands, case.site))
                .collect::<Vec<_>>(),
            vec![
                (0x6dc000, 0x900, DISPATCH + 8),
                (0x6dc004, 0x900, DISPATCH + 0x14),
            ],
            "{:?}",
            found.cases
        );
    }

    /// **Each live compare answers `equality_survives` with its own flags.**
    ///
    /// Which only has consequences once there can be two: a `sub` reaching zero leaves `CF=0` and
    /// an `add` reaching zero leaves `CF=1`, so one and the same `jb` below them admits the
    /// equality on opposite edges. Asking once -- with whichever comparison the join happened to
    /// put first -- would send both the same way and be right about one of them by luck.
    #[test]
    fn each_compare_answers_the_branch_with_its_own_flags() {
        let mut block = prologue(DISPATCH);
        block.extend([
            insn(
                DISPATCH + 8,
                "mov",
                vec![reg("ecx"), reg("r13d")],
                Flow::Fallthrough,
            ),
            // A flag write of its own, so neither arm starts with the other's comparison.
            insn(
                DISPATCH + 0xb,
                "test",
                vec![reg("rax"), reg("rax")],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x11,
                "je",
                Vec::new(),
                Flow::Branch(Some(DISPATCH + 0x30)),
            ),
            // The subtractive arm.
            insn(
                DISPATCH + 0x17,
                "sub",
                vec![reg("ecx"), imm(0x6dc000)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x1d,
                "jmp",
                Vec::new(),
                Flow::Jmp(Some(DISPATCH + 0x50)),
            ),
            // And the one that carries.
            insn(
                DISPATCH + 0x30,
                "add",
                vec![reg("ecx"), imm(0x6dc000)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x36,
                "jmp",
                Vec::new(),
                Flow::Jmp(Some(DISPATCH + 0x50)),
            ),
            // Both meet here, and this branch reads the carry.
            insn(
                DISPATCH + 0x50,
                "jb",
                Vec::new(),
                Flow::Branch(Some(DISPATCH + 0x60)),
            ),
            insn(DISPATCH + 0x56, "je", Vec::new(), Flow::Branch(Some(0x900))),
            insn(DISPATCH + 0x5c, "ret", Vec::new(), Flow::Return),
            insn(DISPATCH + 0x60, "je", Vec::new(), Flow::Branch(Some(0x980))),
            insn(DISPATCH + 0x66, "ret", Vec::new(), Flow::Return),
        ]);

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            unreadable,
            in_image,
            constant_data,
            never,
        );
        let mut recovered: Vec<_> = found
            .cases
            .iter()
            .map(|case| (case.site, case.code, case.lands))
            .collect();
        // Keyed by where the comparison is rather than by the order the walk reached them, so the
        // assertion is about which edge each one took and not about the sweep order.
        recovered.sort();
        assert_eq!(
            recovered,
            vec![
                // `sub` leaves `CF=0`, so `jb` is **not** taken on the equality: the case is on
                // the fall-through.
                (DISPATCH + 0x17, 0x6dc000, 0x900),
                // `add` leaves `CF=1`, so the same `jb` **is** taken on it. The code is the value
                // that makes `ecx + 6DC000h` zero, which is `2^32 - 6DC000h`.
                (DISPATCH + 0x30, 0xff92_4000, 0x980),
            ],
            "{:?}",
            found.cases
        );
    }

    /// **A chain that steps by a register is still a chain.**
    ///
    /// HEVD's dispatch is `sub ecx,222003h` / `je` / `sub ecx,eax` / `je` / ... with `eax` holding
    /// 4, and each group ends `cmp ecx,eax` / `jne default`. Reading only immediates followed the
    /// first code and lost the rest: **4 of the 28** its own header defines, measured on the live
    /// driver.
    #[test]
    fn a_chain_that_steps_by_a_register_is_followed_like_one_that_steps_by_an_immediate() {
        let mut block = prologue(DISPATCH);
        block.extend([
            // The step, put in a register once and used throughout -- which is why a pass that
            // reads only immediates sees one `sub` it understands and two it does not.
            insn(
                DISPATCH + 8,
                "mov",
                vec![reg("eax"), imm(4)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xd,
                "mov",
                vec![reg("ecx"), reg("r13d")],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x10,
                "sub",
                vec![reg("ecx"), imm(0x222003)],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x16, "je", Vec::new(), Flow::Branch(Some(0x900))),
            insn(
                DISPATCH + 0x1c,
                "sub",
                vec![reg("ecx"), reg("eax")],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x1e, "je", Vec::new(), Flow::Branch(Some(0x980))),
            insn(
                DISPATCH + 0x24,
                "sub",
                vec![reg("ecx"), reg("eax")],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x26, "je", Vec::new(), Flow::Branch(Some(0xa00))),
            // The group's last code is a compare rather than a subtract, against the same
            // register -- which is the other half of the same shape.
            insn(
                DISPATCH + 0x2c,
                "cmp",
                vec![reg("ecx"), reg("eax")],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x2e, "je", Vec::new(), Flow::Branch(Some(0xa80))),
            insn(DISPATCH + 0x34, "ret", Vec::new(), Flow::Return),
        ]);

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            unreadable,
            in_image,
            constant_data,
            never,
        );

        assert_eq!(
            found
                .cases
                .iter()
                .map(|case| (case.code, case.lands))
                .collect::<Vec<_>>(),
            vec![
                (0x222003, 0x900),
                (0x222007, 0x980),
                (0x22200b, 0xa00),
                (0x22200f, 0xa80),
            ],
            "each step is four, whether four is written down or carried in `eax`: {:?}",
            found.cases
        );
        assert!(
            found.untracked.is_empty(),
            "and nothing was lost, so nothing says it was: {:?}",
            found.untracked
        );
    }

    /// **`add` is a subtraction written the other way round, and leaves a case like one.**
    ///
    /// `add ecx,K` / `je` rebased the value and returned no comparison fact, so `simulate` cleared
    /// the pending compare -- and the loss went unrecorded too, because the register still held a
    /// code and nothing had destroyed it. No case, no `untracked`, nothing in the answer at all.
    /// A compiler writes a subtraction of a negative this way, so it is an ordinary dispatch shape
    /// rather than an adversarial one.
    #[test]
    fn an_add_leaves_a_case_the_way_a_subtract_does() {
        let mut block = prologue(DISPATCH);
        block.extend([
            insn(
                DISPATCH + 8,
                "mov",
                vec![reg("ecx"), reg("r13d")],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xb,
                "sub",
                vec![reg("ecx"), imm(0x6dc004)],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x11, "je", Vec::new(), Flow::Branch(Some(0x900))),
            // `add ecx,4` walks the chain **back**: the register now holds `code - 0x6dc000`.
            insn(
                DISPATCH + 0x17,
                "add",
                vec![reg("ecx"), imm(4)],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x1a, "je", Vec::new(), Flow::Branch(Some(0x980))),
            insn(DISPATCH + 0x20, "ret", Vec::new(), Flow::Return),
        ]);

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            unreadable,
            in_image,
            constant_data,
            never,
        );

        assert_eq!(
            found
                .cases
                .iter()
                .map(|case| (case.code, case.lands))
                .collect::<Vec<_>>(),
            vec![(0x6dc004, 0x900), (0x6dc000, 0x980)],
            "the `add` moves the chain back four and its `je` is a case for the code there: {:?}",
            found.cases
        );
    }

    /// **A loss crosses a block boundary, because the branch that makes it matter may not be
    /// in the block that made it.**
    ///
    /// `and ecx,mask` / `ja next` / `next: je handler`. The `ja` is not an equality, so it commits
    /// nothing; the loss lived only in the block that made it, and the `je` in the next block
    /// found neither a compare nor a loss. The map read as complete. That is the gap
    /// `Facts::pending` was added to close, one field along -- and a loss survives on **both**
    /// edges where a compare does not, because nothing is known about what the operation did and
    /// so no edge has ruled anything out.
    #[test]
    fn a_loss_reaches_the_branch_that_reads_it_in_a_later_block() {
        let mut block = prologue(DISPATCH);
        block.extend([
            insn(
                DISPATCH + 8,
                "mov",
                vec![reg("ecx"), reg("r13d")],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xb,
                "and",
                vec![reg("ecx"), imm(0xffff)],
                Flow::Fallthrough,
            ),
            // Reads the flags and decides nothing this can name, so it ends the block without
            // committing anything.
            insn(
                DISPATCH + 0x11,
                "ja",
                Vec::new(),
                Flow::Branch(Some(DISPATCH + 0x100)),
            ),
            insn(DISPATCH + 0x17, "je", Vec::new(), Flow::Branch(Some(0x900))),
            insn(DISPATCH + 0x1d, "ret", Vec::new(), Flow::Return),
            insn(DISPATCH + 0x100, "ret", Vec::new(), Flow::Return),
        ]);

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            unreadable,
            in_image,
            constant_data,
            never,
        );

        assert!(found.cases.is_empty(), "{:?}", found.cases);
        assert_eq!(
            found.untracked,
            vec![DISPATCH + 0xb],
            "the `je` two blocks on is still reading the `and`'s flags, and still cannot name a \
             code for the path it takes"
        );
    }

    /// **A register the instruction writes without naming it loses the code too.**
    ///
    /// The check asked one question of the **first operand**, at the end, after the instruction's
    /// other writes had been cleared and after the narrow-write return. So `xadd eax,ecx` with the
    /// code in `ecx`, and `sub cx,1` with it in `rcx`, both lost it in silence. It is a snapshot
    /// now -- which registers carried the code before anything ran, against what they hold after.
    #[test]
    fn a_code_lost_through_a_register_the_operand_does_not_name_is_still_lost() {
        // `sub cx,1`: a narrow write over a register holding the code, which returns before any
        // arm and used to return before the check as well.
        let mut narrow = prologue(DISPATCH);
        narrow.extend([
            insn(
                DISPATCH + 8,
                "mov",
                vec![reg("rcx"), reg("r13")],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xb,
                "sub",
                vec![reg("cx"), imm(1)],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0xf, "je", Vec::new(), Flow::Branch(Some(0x900))),
            insn(DISPATCH + 0x15, "ret", Vec::new(), Flow::Return),
        ]);
        let found = map(
            DISPATCH,
            &narrow,
            Layout::X64,
            unreadable,
            in_image,
            constant_data,
            never,
        );
        assert!(
            found.cases.is_empty(),
            "sixteen bits of a `ULONG` is not the code: {:?}",
            found.cases
        );
        assert_eq!(
            found.untracked,
            vec![DISPATCH + 0xb],
            "and the `je` reading it is a path with no code this can name"
        );
    }

    /// **A loss survives a join that any path into the block made, which is the opposite of the
    /// rule the pending compare is under.**
    ///
    /// `pending` asserts a **fact** -- this comparison is live -- so every path has to agree on it,
    /// and one that disagrees takes it away. A loss asserts **doubt**, and doubt on any path in is
    /// doubt here: the branch below is code-dependent on that path whatever the others did.
    ///
    /// This test asserted the opposite until 2026-09-14, on reasoning that does not survive being
    /// read back -- "a loss no path into the block made" describes a thing that did not happen,
    /// because the loss *was* made on one of them. Two arms losing the code at different
    /// instructions then cleared it entirely, and the map read as complete.
    #[test]
    fn a_loss_any_path_made_is_a_loss_the_join_keeps() {
        let mut block = prologue(DISPATCH);
        block.extend([
            insn(
                DISPATCH + 8,
                "mov",
                vec![reg("ecx"), reg("r13d")],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xb,
                "and",
                vec![reg("ecx"), imm(0xffff)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x11,
                "jb",
                Vec::new(),
                Flow::Branch(Some(DISPATCH + 0x30)),
            ),
            // Reached by falling through with the loss live, and again from below with a path
            // that never held the code.
            insn(DISPATCH + 0x17, "je", Vec::new(), Flow::Branch(Some(0x900))),
            insn(DISPATCH + 0x1d, "ret", Vec::new(), Flow::Return),
            insn(
                DISPATCH + 0x30,
                "cmp",
                vec![reg("rax"), imm(1)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x34,
                "jmp",
                Vec::new(),
                Flow::Jmp(Some(DISPATCH + 0x17)),
            ),
        ]);

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            unreadable,
            in_image,
            constant_data,
            never,
        );
        assert_eq!(
            found.untracked,
            vec![DISPATCH + 0xb],
            "one path into that `je` cannot name a code for it, which makes the case list a lower \
             bound whatever the other path did"
        );
        assert!(found.cases.is_empty(), "{:?}", found.cases);
    }

    /// **A compare that ends a block still reaches the branch in the next one.**
    #[test]
    fn a_compare_that_ends_a_block_reaches_the_branch_below_it() {
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
            insn(
                DISPATCH + 0x20,
                "jmp",
                Vec::new(),
                Flow::Jmp(Some(DISPATCH + 0xe)),
            ),
        ]);

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            unreadable,
            in_image,
            constant_data,
            never,
        );
        assert_eq!(
            found.cases.iter().map(|case| case.code).collect::<Vec<_>>(),
            vec![0x222003],
            "{:?}",
            found.cases
        );
    }

    /// **A compare survives an unconditional jump to the branch that reads it.**
    #[test]
    fn a_compare_reaches_the_branch_an_unconditional_jump_leads_to() {
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
                "jmp",
                Vec::new(),
                Flow::Jmp(Some(DISPATCH + 0x20)),
            ),
            insn(DISPATCH + 0x14, "ret", Vec::new(), Flow::Return),
            insn(DISPATCH + 0x20, "je", Vec::new(), Flow::Branch(Some(0x900))),
            insn(DISPATCH + 0x26, "ret", Vec::new(), Flow::Return),
        ]);

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            unreadable,
            in_image,
            constant_data,
            never,
        );
        assert_eq!(
            found
                .cases
                .iter()
                .map(|case| (case.code, case.lands))
                .collect::<Vec<_>>(),
            vec![(0x222003, 0x900)],
            "{:?}",
            found.cases
        );
    }

    /// **A loss that ends a block still reaches the branch in the next one.**
    #[test]
    fn a_loss_that_ends_a_block_reaches_the_branch_below_it() {
        let mut block = prologue(DISPATCH);
        block.extend([
            insn(
                DISPATCH + 8,
                "mov",
                vec![reg("ecx"), reg("r13d")],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xb,
                "and",
                vec![reg("ecx"), imm(0xffff)],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x11, "je", Vec::new(), Flow::Branch(Some(0x900))),
            insn(DISPATCH + 0x17, "ret", Vec::new(), Flow::Return),
            insn(
                DISPATCH + 0x20,
                "jmp",
                Vec::new(),
                Flow::Jmp(Some(DISPATCH + 0x11)),
            ),
        ]);

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            unreadable,
            in_image,
            constant_data,
            never,
        );
        assert_eq!(found.untracked, vec![DISPATCH + 0xb], "{:?}", found.cases);
    }

    /// **A call that ends a block takes the loss with it, as one inside a block does.**
    #[test]
    fn a_call_that_ends_a_block_takes_the_loss_with_it() {
        let mut block = prologue(DISPATCH);
        block.extend([
            insn(
                DISPATCH + 8,
                "mov",
                vec![reg("ecx"), reg("r13d")],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xb,
                "and",
                vec![reg("ecx"), imm(0xffff)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x11,
                "call",
                Vec::new(),
                Flow::Call(Some(DISPATCH + 0x800)),
            ),
            insn(DISPATCH + 0x17, "je", Vec::new(), Flow::Branch(Some(0x900))),
            insn(DISPATCH + 0x1d, "ret", Vec::new(), Flow::Return),
            insn(
                DISPATCH + 0x30,
                "jmp",
                Vec::new(),
                Flow::Jmp(Some(DISPATCH + 0x17)),
            ),
        ]);

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            unreadable,
            in_image,
            constant_data,
            never,
        );
        assert!(found.untracked.is_empty(), "{:?}", found.untracked);
    }

    /// **Flags computed from the code, with the code still where it was.**
    #[test]
    fn a_flag_write_that_reads_the_code_without_taking_it_is_still_a_loss() {
        let about = |mnemonic: &str| {
            let mut block = prologue(DISPATCH);
            block.extend([
                insn(
                    DISPATCH + 8,
                    "mov",
                    vec![reg("ecx"), reg("r13d")],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0xb,
                    "mov",
                    vec![reg("eax"), imm(3)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x11,
                    mnemonic,
                    vec![reg("eax"), reg("ecx")],
                    Flow::Fallthrough,
                ),
                insn(DISPATCH + 0x17, "je", Vec::new(), Flow::Branch(Some(0x900))),
                insn(DISPATCH + 0x1d, "ret", Vec::new(), Flow::Return),
            ]);
            map(
                DISPATCH,
                &block,
                Layout::X64,
                unreadable,
                in_image,
                constant_data,
                never,
            )
        };
        let about_with_the_code_first = |mnemonic: &str| {
            let mut block = prologue(DISPATCH);
            block.extend([
                insn(
                    DISPATCH + 8,
                    "mov",
                    vec![reg("ecx"), reg("r13d")],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0xb,
                    "mov",
                    vec![reg("eax"), imm(3)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x11,
                    mnemonic,
                    vec![reg("ecx"), reg("eax")],
                    Flow::Fallthrough,
                ),
                insn(DISPATCH + 0x17, "je", Vec::new(), Flow::Branch(Some(0x900))),
                insn(DISPATCH + 0x1d, "ret", Vec::new(), Flow::Return),
            ]);
            map(
                DISPATCH,
                &block,
                Layout::X64,
                unreadable,
                in_image,
                constant_data,
                never,
            )
        };

        assert_eq!(
            about("and").untracked,
            vec![DISPATCH + 0x11],
            "the mask is the destination and the code is the source, so nothing stopped carrying it"
        );
        assert_eq!(
            about("test").untracked,
            vec![DISPATCH + 0x11],
            "and a `test` reads both its operands, not only the first"
        );
        // **The shape the deleted clause covered.** Generalising a rule has to keep what the
        // special case bought, and the only way to know is to assert it here rather than trust
        // that a wider question contains a narrower one.
        assert_eq!(
            about_with_the_code_first("test").untracked,
            vec![DISPATCH + 0x11],
            "the code in operand zero is what the clause this replaced asked about"
        );
    }

    /// **A register an instruction reads without naming is still a register it reads.**
    ///
    /// The operand list names the reads an instruction was *written* with, and that is not every
    /// read: a memory operand reads the registers that form its address, `mul` reads the
    /// accumulator, `cmpxchg` reads `rax`. Asked of the operand list, `test dword ptr [rcx+8],3`
    /// with the code in `rcx` reads nothing at all -- `register_full` answers `None` for a memory
    /// operand, the probe beside it asks about the *slot* rather than the base, and `test` writes
    /// no register so nothing had stopped carrying the code either. Three clauses, and a branch on
    /// flags this pass cannot attribute went unrecorded.
    ///
    /// **Measured rather than assumed, and the measurement moved the argument.** Over every
    /// flag-writing instruction iced decodes in 64-bit mode, the registers `reads` names that
    /// neither the operand list nor `writes` do are -- for every mnemonic a compiler emits -- the
    /// registers that form a memory address. `mul`, `cmpxchg` and the string instructions read
    /// registers they do not name, but they **write** them too, so the loss was already caught by
    /// the carried-and-gone half. So this is the shape that discriminates, and it is the one
    /// asserted.
    ///
    /// That it is conservative is deliberate: the flags here are computed from a *load* at an
    /// address derived from the code rather than from the code. But a pass that believes a control
    /// code is being dereferenced has lost the value, whichever of the two is wrong -- and the
    /// direction to be wrong in is the one that stops claiming.
    #[test]
    fn a_register_read_only_to_address_memory_is_still_a_read_of_the_code() {
        let mut block = prologue(DISPATCH);
        block.extend([
            insn(
                DISPATCH + 8,
                "mov",
                vec![reg("ecx"), reg("r13d")],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xb,
                "test",
                vec![mem("rcx", 8), imm(3)],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x11, "je", Vec::new(), Flow::Branch(Some(0x900))),
            insn(DISPATCH + 0x17, "ret", Vec::new(), Flow::Return),
        ]);

        // The premise, asserted rather than described: the decoder says this instruction reads the
        // register the code is in, and its operand list names no register at all. A fixture that
        // stopped being true of one of those would leave the assertion below passing for a reason
        // that is not this rule.
        let flag_write = &block[3];
        assert_eq!(
            flag_write
                .reads
                .iter()
                .map(|register| register.full.as_str())
                .collect::<Vec<_>>(),
            vec!["rcx"],
            "{flag_write:?}"
        );
        assert!(
            flag_write
                .operands
                .iter()
                .all(|operand| !matches!(operand, dbgscope::dbgeng::Operand::Register(_))),
            "the operand list names no register, which is the whole point: {flag_write:?}"
        );

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            unreadable,
            in_image,
            constant_data,
            never,
        );
        assert_eq!(
            found.untracked,
            vec![DISPATCH + 0xb],
            "the branch reads flags computed through the code, and the map says so rather than \
             answering with an empty case list: {:?}",
            found.cases
        );
    }

    /// **A `test` of the control code is a branch about it, and cannot be named.**
    ///
    /// `test ecx,3` / `je` takes a path whose codes this walk cannot enumerate -- and `update`
    /// returned early for a test, so it produced neither a case nor a record. Silence, which is
    /// the one thing the map is not allowed to answer with when it is short.
    #[test]
    fn a_test_of_the_control_code_is_a_branch_this_cannot_name() {
        let mut block = prologue(DISPATCH);
        block.extend([
            insn(
                DISPATCH + 8,
                "mov",
                vec![reg("ecx"), reg("r13d")],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xb,
                "test",
                vec![reg("ecx"), imm(3)],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0xe, "je", Vec::new(), Flow::Branch(Some(0x900))),
            insn(DISPATCH + 0x14, "ret", Vec::new(), Flow::Return),
        ]);

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            unreadable,
            in_image,
            constant_data,
            never,
        );

        assert!(
            found.cases.is_empty(),
            "a mask test names no single code, so it invents none: {:?}",
            found.cases
        );
        assert_eq!(
            found.untracked,
            vec![DISPATCH + 0xb],
            "but the branch reading it is a path the case list does not account for"
        );

        // **The field itself, not a register holding it.** A driver that writes
        // `test dword ptr [stack_location+18h],3` is testing the control code directly, and a
        // check that looks only at registers reads it as a test of something else.
        let mut direct = vec![
            insn(
                DISPATCH,
                "mov",
                vec![reg("rax"), pointer("rdx", 0xb8)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 4,
                "test",
                vec![mem("rax", 0x18), imm(3)],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 8, "je", Vec::new(), Flow::Branch(Some(0x900))),
            insn(DISPATCH + 0xe, "ret", Vec::new(), Flow::Return),
        ];
        direct.dedup_by_key(|one| one.address);
        let found = map(
            DISPATCH,
            &direct,
            Layout::X64,
            unreadable,
            in_image,
            constant_data,
            never,
        );
        assert_eq!(
            found.untracked,
            vec![DISPATCH + 4],
            "a test of the stack location's control-code field is a test of the code"
        );

        // And a `test` of something else is not about the control code at all.
        let mut other = prologue(DISPATCH);
        other.extend([
            insn(
                DISPATCH + 8,
                "test",
                vec![reg("eax"), reg("eax")],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0xa, "je", Vec::new(), Flow::Branch(Some(0x900))),
            insn(DISPATCH + 0x10, "ret", Vec::new(), Flow::Return),
        ]);
        let found = map(
            DISPATCH,
            &other,
            Layout::X64,
            unreadable,
            in_image,
            constant_data,
            never,
        );
        assert!(
            found.untracked.is_empty(),
            "every dispatch routine tests something; only the code's own tests are short lists: \
             {:?}",
            found.untracked
        );
    }

    /// **A step a register carries is a `ULONG`, and wraps like one.**
    ///
    /// `mov eax,0FFFFFFFCh` is how a compiler puts `-4` in a register, and `sub ecx,eax` then
    /// steps the chain *backwards*. Widened to `i64` the offset becomes 4,297,203,711, which is
    /// past `u32::MAX` -- and `push_case` drops a code that does not fit one **silently**, so the
    /// case disappears with nothing in the answer saying it did. The machine computes this modulo
    /// 2^32 and so must this.
    ///
    /// A fixture stepping by `4` cannot see it: wrapping and widening agree on every positive
    /// step, which is why the mutation for this rule came back MISSED against the chain test.
    #[test]
    fn a_step_a_register_carries_wraps_at_the_field_width() {
        let mut block = prologue(DISPATCH);
        block.extend([
            insn(
                DISPATCH + 8,
                "mov",
                vec![reg("eax"), imm(0xffff_fffc)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xd,
                "mov",
                vec![reg("ecx"), reg("r13d")],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x10,
                "sub",
                vec![reg("ecx"), imm(0x222003)],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x16, "je", Vec::new(), Flow::Branch(Some(0x900))),
            insn(
                DISPATCH + 0x1c,
                "sub",
                vec![reg("ecx"), reg("eax")],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x1e, "je", Vec::new(), Flow::Branch(Some(0x980))),
            insn(DISPATCH + 0x24, "ret", Vec::new(), Flow::Return),
        ]);

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            unreadable,
            in_image,
            constant_data,
            never,
        );

        assert_eq!(
            found
                .cases
                .iter()
                .map(|case| (case.code, case.lands))
                .collect::<Vec<_>>(),
            vec![(0x222003, 0x900), (0x221fff, 0x980)],
            "subtracting `-4` steps back by four, and the second code is below the first: {:?}",
            found.cases
        );
        assert!(
            found.untracked.is_empty(),
            "nothing was lost, so nothing claims it was: {:?}",
            found.untracked
        );
    }

    /// **A literal is only the step if the operand carries all of it.**
    ///
    /// `mov eax,104h` / `sub ecx,al` subtracts **four**, not 0x104: the byte register is the low
    /// eighth of the value this pass watched arrive. Reading the register's full contents would
    /// rebase the chain by 0x104 and report a case for a code nothing compared -- the same rule
    /// the copy path already applies, which a fixture stepping by `eax` cannot see because `eax`
    /// is the whole field.
    #[test]
    fn a_narrow_operand_does_not_carry_the_whole_literal() {
        let mut block = prologue(DISPATCH);
        block.extend([
            insn(
                DISPATCH + 8,
                "mov",
                vec![reg("eax"), imm(0x104)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xd,
                "mov",
                vec![reg("ecx"), reg("r13d")],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x10,
                "sub",
                vec![reg("ecx"), imm(0x222003)],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x16, "je", Vec::new(), Flow::Branch(Some(0x900))),
            insn(
                DISPATCH + 0x1c,
                "sub",
                vec![reg("ecx"), reg("al")],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x1e, "je", Vec::new(), Flow::Branch(Some(0x980))),
            insn(DISPATCH + 0x24, "ret", Vec::new(), Flow::Return),
        ]);

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            unreadable,
            in_image,
            constant_data,
            never,
        );

        assert_eq!(
            found.cases.iter().map(|case| case.code).collect::<Vec<_>>(),
            vec![0x222003],
            "the first step is written down; the second is a byte of a register and is not \
             followed: {:?}",
            found.cases
        );
        // **And the one it did not follow says so**, which is the other half: a chain abandoned
        // here is a case list that is a lower bound.
        assert_eq!(
            found.untracked,
            vec![DISPATCH + 0x1c],
            "the instruction that took the code somewhere unfollowable is named"
        );
    }

    /// **An instruction nothing branches on loses nothing.**
    ///
    /// `untracked` was appended the moment a flag-writing instruction destroyed a tracked code,
    /// whether or not anything read those flags -- so `and ecx,3` followed by a use with no branch
    /// marked an otherwise complete map `partial` and claimed a missing case. The conservative
    /// direction, and still wrong: this is the one signal whose value is that it is quiet, and a
    /// map that is `partial` for nothing teaches a reader to ignore it.
    ///
    /// The loss is pending state now, committed only where a branch consumes the flags.
    #[test]
    fn a_value_lost_with_no_branch_reading_it_is_not_a_missing_case() {
        let mut block = prologue(DISPATCH);
        block.extend([
            insn(
                DISPATCH + 8,
                "mov",
                vec![reg("ecx"), reg("r13d")],
                Flow::Fallthrough,
            ),
            // Writes flags and takes the code somewhere this does not model -- and nothing reads
            // the flags, so nothing was lost that anybody was going to use.
            insn(
                DISPATCH + 0xb,
                "and",
                vec![reg("ecx"), imm(3)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xe,
                "mov",
                vec![mem("rsp", 0x20), reg("ecx")],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x12, "ret", Vec::new(), Flow::Return),
        ]);

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            unreadable,
            in_image,
            constant_data,
            never,
        );

        assert!(
            found.untracked.is_empty(),
            "no branch read those flags, so no case went missing here: {:?}",
            found.untracked
        );
        assert!(found.cases.is_empty(), "{:?}", found.cases);
    }

    /// **A test on the control code this pass cannot attribute is in the answer.**
    ///
    /// The half that makes a short list readable. Until HEVD, `unresolved` fired only for an
    /// indirect *jump*, so a chain the walk could not follow produced neither cases nor any sign
    /// of them: the live driver reported 4 codes of 28 with `unresolved` empty, nothing stopped,
    /// nothing capped and `code_proved: true`, which `driver_surface` then called a complete
    /// section. Nothing about four codes said they were four of twenty-eight.
    ///
    /// Constructed, because after the fix both measured drivers report this empty -- correctly,
    /// which is exactly why only a fixture can show it fires.
    #[test]
    fn a_test_on_the_code_that_cannot_be_attributed_is_reported() {
        let mut block = prologue(DISPATCH);
        block.extend([
            insn(
                DISPATCH + 8,
                "mov",
                vec![reg("ecx"), reg("r13d")],
                Flow::Fallthrough,
            ),
            // `eax` holds nothing this pass watched arrive, so the compare is about the control
            // code against a value it cannot name.
            insn(
                DISPATCH + 0xb,
                "cmp",
                vec![reg("ecx"), reg("eax")],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0xd, "je", Vec::new(), Flow::Branch(Some(0x900))),
            insn(DISPATCH + 0x13, "ret", Vec::new(), Flow::Return),
        ]);

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            unreadable,
            in_image,
            constant_data,
            never,
        );

        assert!(
            found.cases.is_empty(),
            "it cannot name the code, so it invents no case: {:?}",
            found.cases
        );
        assert_eq!(
            found.untracked,
            vec![DISPATCH + 0xb],
            "but it says where it stopped being able to, which is what stops a short list \
             reading as a complete one"
        );
        assert!(
            found.unresolved.is_empty(),
            "and not in `unresolved`, which is the indirect transfers: different fact, different \
             remedy: {:?}",
            found.unresolved
        );
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

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            unreadable,
            in_image,
            constant_data,
            never,
        );

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

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            unreadable,
            in_image,
            constant_data,
            never,
        );

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

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            unreadable,
            in_image,
            constant_data,
            never,
        );

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

        let found32 = map(
            DISPATCH,
            &block32,
            Layout::X86,
            unreadable,
            in_image,
            constant_data,
            never,
        );

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

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            read,
            in_image,
            constant_data,
            never,
        );

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

        let found = map(
            DISPATCH,
            &jumps,
            Layout::X64,
            unreadable,
            in_image,
            constant_data,
            never,
        );

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

        let found = map(
            DISPATCH,
            &block(false),
            Layout::X64,
            &read,
            in_image,
            constant_data,
            never,
        );

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
        let shifted = map(
            DISPATCH,
            &block(true),
            Layout::X64,
            &read,
            in_image,
            constant_data,
            never,
        );

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

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            read,
            in_image,
            constant_data,
            never,
        );

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

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            read,
            in_image,
            constant_data,
            never,
        );

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

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            read,
            in_image,
            constant_data,
            never,
        );

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

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            read,
            in_image,
            constant_data,
            never,
        );

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

        let found = map(
            DISPATCH,
            &block,
            Layout::X86,
            read,
            in_image32,
            constant_data,
            never,
        );

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

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            read,
            in_image,
            constant_data,
            never,
        );

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
            let found = map(
                DISPATCH,
                &block,
                Layout::X64,
                unreadable,
                in_image,
                constant_data,
                never,
            );
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
            constant_data,
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
            constant_data,
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
            constant_data,
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
            constant_data,
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

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            read,
            in_image,
            constant_data,
            never,
        );

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

    /// A64 writes a switch as a table of **offsets**, scaled by the `add` that folds the base in.
    ///
    /// Every part of this differs from the x86 shape the reader was written for. The fold is
    /// three-operand (`add x8,x9,x8,lsl #2`), so the register being followed is not the
    /// destination's own previous value; it carries an `lsl #2`, because the table holds an
    /// *instruction* count rather than a displacement; and the decoder drops `Effect::Add` when
    /// it folds a modifier in, so the arm that recognised x86's `add rcx,rdx` does not fire at
    /// all. Measured on the ARM64 `mountmgr` of a live 26100 kernel: three indirect jumps of this
    /// shape, all three reported `unresolved` and none of their codes recovered.
    ///
    /// The fixture's entries are chosen so that **dropping the scale still lands in the image**,
    /// which is what a table matched by accident relies on and what makes the scale a rule rather
    /// than something `in_image` would catch: read unscaled, all four slots resolve, none of them
    /// matches the default, and the map reports four cases at addresses nothing computed.
    #[test]
    fn an_a64_switch_scales_its_entries_by_the_shift_the_fold_carries() {
        const TABLE: u64 = IMAGE_BASE + 0x9000;
        const ENTRIES: u64 = IMAGE_BASE + 0x4000;
        const DEFAULT: u64 = ENTRIES + 0x400;
        let block = vec![
            insn(
                DISPATCH,
                "ldr",
                vec![reg("x8"), pointer("x1", 0xb8)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 4,
                "ldr",
                vec![reg("w9"), mem("x8", 0x18)],
                Flow::Fallthrough,
            ),
            // `sub w10,w9,#0x6DC,lsl #0xC` -- the decoder folds the shift into the immediate, so
            // it arrives whole. Then the second rebase onto the switch's first case.
            insn(
                DISPATCH + 8,
                "sub",
                vec![reg("w10"), reg("w9"), imm(0x6dc000)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xc,
                "sub",
                vec![reg("w10"), reg("w10"), imm(0x40)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x10,
                "cmp",
                vec![reg("w10"), imm(3)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x14,
                "b.hi",
                Vec::new(),
                Flow::Branch(Some(DEFAULT)),
            ),
            insn(
                DISPATCH + 0x18,
                "adr",
                vec![reg("x9"), adr_to(TABLE)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x1c,
                "ldrsw",
                vec![reg("x8"), table_load("x9", "w10", 4)],
                Flow::Fallthrough,
            ),
            // The same register, reloaded with the base the entries are measured from -- which is
            // why the fold's base is read where the fold stands and not where the load does.
            insn(
                DISPATCH + 0x20,
                "adr",
                vec![reg("x9"), adr_to(ENTRIES)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x24,
                "add",
                vec![reg("x8"), reg("x9"), reg("x8"), lsl(2)],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x28, "br", vec![reg("x8")], Flow::Jmp(None)),
        ];
        // Slots 1 and 2 hold the default once scaled; slot 3 points backwards, which is what the
        // sign-extending load is for.
        let read = |at: u64, len: usize| {
            (at == TABLE && len == 16).then(|| {
                [0x40i32, 0x100, 0x100, -0x10]
                    .iter()
                    .flat_map(|entry| entry.to_le_bytes())
                    .collect()
            })
        };

        let found = map(
            DISPATCH,
            &block,
            Layout::ARM64,
            read,
            in_image,
            constant_data,
            never,
        );

        assert_eq!(
            found
                .cases
                .iter()
                .map(|case| (case.code, case.lands))
                .collect::<Vec<_>>(),
            vec![
                (0x6dc040, ENTRIES + 0x100),
                (0x6dc043, ENTRIES.wrapping_sub(0x40)),
            ],
            "each entry is four times what the table holds, and the two that land on the \
             bounds check's own target are the switch's default: {:?}",
            found.cases
        );
        assert!(
            found.unresolved.is_empty(),
            "the jump was followed, so it is not also a loss: {:?}",
            found.unresolved
        );
    }

    /// And it sizes the entry to the routine, so a table can be one **signed byte** per case.
    ///
    /// The reader took the entry width from a constant, `TABLE_ENTRY`, because x86 emits a
    /// `DWORD` table and nothing else. A64 picks the narrowest width that reaches every case, and
    /// the same `mountmgr!MountMgrDeviceControl` has both: a `ldrsw` table of four-byte entries
    /// and a `ldrsb` one of single bytes, feeding two different `br`s.
    ///
    /// Two readings are wrong here and both stay inside the image, which is the point of the
    /// fixture. Read four bytes at a time, slot zero is `0x97a2a211` and the table is refused
    /// outright -- a silent loss of every case. Read a byte at a time but **unsigned**, `0xa2` is
    /// 162 entries forward where it is 94 back, and the map reports four cases at addresses
    /// nobody computed instead of the two the driver has. The signedness is the decoder's
    /// classification of the load rather than the width of the read.
    #[test]
    fn an_a64_switch_reads_a_byte_table_a_byte_at_a_time() {
        // `mountmgr` uses one register for both, which is a thing a compiler is free to do and a
        // reader that assumed two would miss.
        const TABLE: u64 = IMAGE_BASE + 0x9000;
        const DEFAULT: u64 = TABLE.wrapping_sub(0x178);
        let block = vec![
            insn(
                DISPATCH,
                "ldr",
                vec![reg("x8"), pointer("x1", 0xb8)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 4,
                "ldr",
                vec![reg("w9"), mem("x8", 0x18)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 8,
                "sub",
                vec![reg("w10"), reg("w9"), imm(0x6dc044)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xc,
                "cmp",
                vec![reg("w10"), imm(3)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x10,
                "b.hi",
                Vec::new(),
                Flow::Branch(Some(DEFAULT)),
            ),
            insn(
                DISPATCH + 0x14,
                "adr",
                vec![reg("x9"), adr_to(TABLE)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x18,
                "ldrsb",
                vec![reg("x8"), table_load("x9", "w10", 1)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x1c,
                "add",
                vec![reg("x8"), reg("x9"), reg("x8"), lsl(2)],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x20, "br", vec![reg("x8")], Flow::Jmp(None)),
        ];
        let read =
            |at: u64, len: usize| (at == TABLE && len == 4).then(|| vec![0x11, 0xa2, 0xa2, 0x97]);

        let found = map(
            DISPATCH,
            &block,
            Layout::ARM64,
            read,
            in_image,
            constant_data,
            never,
        );

        assert_eq!(
            found
                .cases
                .iter()
                .map(|case| (case.code, case.lands))
                .collect::<Vec<_>>(),
            vec![
                (0x6dc044, TABLE + 0x44),
                (0x6dc047, TABLE.wrapping_sub(0x1a4)),
            ],
            "a signed byte, times four, from the same register the table is at: {:?}",
            found.cases
        );
    }

    /// The answer a pure compare chain produces carries every key its own schema requires.
    ///
    /// The general rule is pinned in `structured.rs`, over the source, because a skipped field is
    /// absent and no single value proves some other value would not have skipped it. This is the
    /// shape that actually tripped it, kept as the regression: a routine with no jump table,
    /// nothing unresolved and a case with no length checks skips `tables`, `unresolved` and
    /// `evidence` at once -- all three required -- so a validating client threw away a correct
    /// map of HEVD's 29 control codes and reported a schema error instead.
    #[test]
    fn a_map_with_no_tables_answers_its_own_output_schema() {
        let block = vec![
            insn(
                DISPATCH,
                "ldr",
                vec![reg("x8"), pointer("x1", 0xb8)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 4,
                "ldr",
                vec![reg("w9"), mem("x8", 0x18)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 8,
                "mov",
                vec![reg("w10"), imm(0x2003)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xc,
                "movk",
                vec![reg("w10"), imm(0x22_0000)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x10,
                "cmp",
                vec![reg("w9"), reg("w10")],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x14,
                "b.eq",
                Vec::new(),
                Flow::Branch(Some(IMAGE_BASE + 0x900)),
            ),
            insn(DISPATCH + 0x18, "ret", Vec::new(), Flow::Return),
        ];

        let found = map(
            DISPATCH,
            &block,
            Layout::ARM64,
            unreadable,
            in_image,
            constant_data,
            never,
        );
        let report = structured_report(&found, |address| crate::structured::CodeLocation {
            address: crate::structured::addr(address),
            module: None,
            rva: None,
            attribution_failed: false,
        });
        assert_eq!(
            report.cases.len(),
            1,
            "the fixture has to produce the shape under test: {:?}",
            report.cases
        );
        assert!(
            report.tables.is_empty() && report.unresolved.is_empty(),
            "and it has to be the empty-list shape, or this asserts nothing"
        );

        let written = serde_json::to_value(&report).expect("a map serialises");
        let missing = |schema: serde_json::Value, value: &serde_json::Value| -> Vec<String> {
            schema["required"]
                .as_array()
                .map(Vec::as_slice)
                .unwrap_or_default()
                .iter()
                .filter_map(|key| key.as_str())
                .filter(|key| value.get(key).is_none())
                .map(str::to_string)
                .collect()
        };
        let map_schema = serde_json::to_value(schemars::schema_for!(crate::structured::IoctlMap))
            .expect("a schema serialises");
        assert!(
            missing(map_schema, &written).is_empty(),
            "the map itself: {written}"
        );
        let case_schema = serde_json::to_value(schemars::schema_for!(crate::structured::IoctlCase))
            .expect("a schema serialises");
        assert!(
            missing(case_schema, &written["cases"][0]).is_empty(),
            "a case with no length checks: {}",
            written["cases"][0]
        );
    }

    /// The shift names the entry; the destination it is written into has nothing to say.
    ///
    /// A64 is not destructive, so `add x10,x9,x8,lsl #2` / `br x10` is as ordinary as the
    /// aliasing form `mountmgr` happens to emit, and the first draft of this reader required the
    /// entry to be the `add`'s own destination -- which refuses it, leaving a switch this change
    /// claims to read in `unresolved`. Raised on review; the remedy is to follow the register the
    /// **shift** identifies rather than the one that was written.
    ///
    /// The fixture puts the table's base in the register the destination *would* alias, so a
    /// reader that guessed from the destination does not merely refuse: `x9` holds an address and
    /// `x8` holds the entry, and swapping them measures the table from itself.
    #[test]
    fn an_a64_fold_names_its_entry_by_the_shift_not_by_the_destination() {
        const TABLE: u64 = IMAGE_BASE + 0x9000;
        const ENTRIES: u64 = IMAGE_BASE + 0x4000;
        const DEFAULT: u64 = ENTRIES + 0x400;
        let block = vec![
            insn(
                DISPATCH,
                "ldr",
                vec![reg("x8"), pointer("x1", 0xb8)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 4,
                "ldr",
                vec![reg("w9"), mem("x8", 0x18)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 8,
                "sub",
                vec![reg("w11"), reg("w9"), imm(0x6dc040)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xc,
                "cmp",
                vec![reg("w11"), imm(1)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x10,
                "b.hi",
                Vec::new(),
                Flow::Branch(Some(DEFAULT)),
            ),
            insn(
                DISPATCH + 0x14,
                "adr",
                vec![reg("x9"), adr_to(TABLE)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x18,
                "ldrsw",
                vec![reg("x8"), table_load("x9", "w11", 4)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x1c,
                "adr",
                vec![reg("x9"), adr_to(ENTRIES)],
                Flow::Fallthrough,
            ),
            // Neither source is the destination, which is the whole point.
            insn(
                DISPATCH + 0x20,
                "add",
                vec![reg("x10"), reg("x9"), reg("x8"), lsl(2)],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x24, "br", vec![reg("x10")], Flow::Jmp(None)),
        ];
        let read = |at: u64, len: usize| {
            (at == TABLE && len == 8).then(|| {
                [0x40i32, 0x80]
                    .iter()
                    .flat_map(|entry| entry.to_le_bytes())
                    .collect()
            })
        };

        let found = map(
            DISPATCH,
            &block,
            Layout::ARM64,
            read,
            in_image,
            constant_data,
            never,
        );

        assert_eq!(
            found
                .cases
                .iter()
                .map(|case| (case.code, case.lands))
                .collect::<Vec<_>>(),
            vec![(0x6dc040, ENTRIES + 0x100), (0x6dc041, ENTRIES + 0x200)],
            "the shifted operand is the entry however the sum is stored: {:?}",
            found.cases
        );
    }

    /// A signed load extends only as far as the register it writes.
    ///
    /// `ldrsb w8,[...]` sign-extends to **32** bits, and writing `w8` zero-extends `x8` -- so a
    /// fold reading `x8` gets `0x00000000fffffffe` where extending the byte straight to 64 bits
    /// gives `-2`. Scaled by four that is `base + 0x3fffffff8` against `base - 8`.
    ///
    /// **Only the reconstructed target is checked against the image**, which is what makes this
    /// the dangerous direction rather than a missed case: the wrong answer is a few bytes inside
    /// the function and is published as a control code the driver accepts, while the right one is
    /// sixteen gigabytes away and refuses the table. So the fixture asserts the *refusal*, and
    /// the entry is chosen so the 64-bit reading lands on a real instruction boundary inside the
    /// routine. Raised on review of windbg-mcp#345.
    #[test]
    fn a_signed_load_is_extended_only_as_far_as_the_register_it_writes() {
        const TABLE: u64 = IMAGE_BASE + 0x9000;
        let block = vec![
            insn(
                DISPATCH,
                "ldr",
                vec![reg("x8"), pointer("x1", 0xb8)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 4,
                "ldr",
                vec![reg("w9"), mem("x8", 0x18)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 8,
                "sub",
                vec![reg("w11"), reg("w9"), imm(0x6dc040)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xc,
                "cmp",
                vec![reg("w11"), imm(0)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x10,
                "b.hi",
                Vec::new(),
                Flow::Branch(Some(TABLE + 0x400)),
            ),
            insn(
                DISPATCH + 0x14,
                "adr",
                vec![reg("x9"), adr_to(TABLE)],
                Flow::Fallthrough,
            ),
            // **A 32-bit destination**, which is the one thing this differs from the byte-table
            // test in.
            insn(
                DISPATCH + 0x18,
                "ldrsb",
                vec![reg("w8"), table_load("x9", "w11", 1)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0x1c,
                "add",
                vec![reg("x8"), reg("x9"), reg("x8"), lsl(2)],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x20, "br", vec![reg("x8")], Flow::Jmp(None)),
        ];
        // 0xfe: -2 extended to 64 bits, and 0xfffffffe extended only as far as `w8` goes.
        let read = |at: u64, len: usize| (at == TABLE && len == 1).then(|| vec![0xfeu8]);

        let found = map(
            DISPATCH,
            &block,
            Layout::ARM64,
            read,
            in_image,
            constant_data,
            never,
        );

        assert!(
            found.cases.is_empty(),
            "`base - 8` is inside the image and is not where this jump goes: {:?}",
            found.cases
        );
        assert_eq!(
            found.unresolved,
            vec![DISPATCH + 0x20],
            "and a table that was refused leaves its jump recorded as a loss"
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

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            unreadable,
            in_image,
            constant_data,
            never,
        );

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
            map(
                DISPATCH,
                &block,
                Layout::X64,
                unreadable,
                in_image,
                constant_data,
                never,
            )
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

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            read,
            in_image,
            constant_data,
            never,
        );

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
            map(
                DISPATCH,
                &block,
                Layout::X64,
                unreadable,
                in_image,
                constant_data,
                never,
            )
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
                // **Reloaded after the call**, which is what a driver that means to return the
                // status does: the call it makes on its way out returns its own.
                insn(
                    DISPATCH + 0x4a,
                    "mov",
                    vec![reg(destination), imm(0xc000_000d)],
                    Flow::Fallthrough,
                ),
                insn(DISPATCH + 0x4f, "ret", Vec::new(), Flow::Return),
            ]);
            map(
                DISPATCH,
                &block,
                Layout::X64,
                unreadable,
                in_image,
                constant_data,
                never,
            )
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
            constant_data,
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
            constant_data,
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

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            read,
            in_image,
            constant_data,
            never,
        );

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
            map(
                DISPATCH,
                &block,
                Layout::X64,
                unreadable,
                in_image,
                constant_data,
                never,
            )
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
            constant_data,
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
            constant_data,
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
            constant_data,
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
            constant_data,
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

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            read,
            in_image,
            constant_data,
            never,
        );

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

        let settled = map(
            DISPATCH,
            &block,
            Layout::X64,
            &read,
            in_image,
            constant_data,
            never,
        );
        assert_eq!(
            settled.cases.len(),
            2,
            "with the facts settled the switch is this driver's: {:?}",
            settled.cases
        );
        assert!(!settled.unsettled && settled.unresolved.is_empty());

        let short = map_within(
            DISPATCH,
            &block,
            Layout::X64,
            &read,
            in_image,
            constant_data,
            never,
            1,
        );

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
        let counted = map(
            DISPATCH,
            &block,
            Layout::X64,
            unreadable,
            in_image,
            constant_data,
            || {
                polls.set(polls.get() + 1);
                None
            },
        );
        assert_eq!(counted.cases.len(), 3, "{:?}", counted.cases);
        assert!(
            counted.cases.iter().all(|case| case.handler.is_some()),
            "every case here reaches a routine: {:?}",
            counted.cases
        );
        let total = polls.get();

        polls.set(0);
        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            unreadable,
            in_image,
            constant_data,
            || {
                polls.set(polls.get() + 1);
                (polls.get() >= total).then_some(Halt::Deadline)
            },
        );

        assert_eq!(found.halted, Some(Halt::Deadline));
        assert_eq!(
            found.case_count, 3,
            "the recording pass finished, so the count is every case it found"
        );
        // **And the list ends where the work did.** A case this pass never reached would come back
        // with no handler, no acceptance and no sizes -- which is what a case whose block gave no
        // evidence says, and there would be nothing to tell the two apart. So the clock ends the
        // list as a bound does, and the count stays exact over the difference.
        assert_eq!(
            found
                .cases
                .iter()
                .map(|case| (case.code, case.handler))
                .collect::<Vec<_>>(),
            vec![(0x222003, Some(0x7000)), (0x222007, Some(0x7100))],
            "every case listed is one this finished reading: {:?}",
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
            constant_data,
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
            constant_data,
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
            map(
                DISPATCH,
                &block,
                Layout::X64,
                unreadable,
                in_image,
                constant_data,
                never,
            )
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
            let found = map(
                DISPATCH,
                &block,
                Layout::X64,
                unreadable,
                in_image,
                constant_data,
                never,
            );
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

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            read,
            in_image,
            constant_data,
            never,
        );

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
            let found = map(
                DISPATCH,
                &block,
                Layout::X64,
                unreadable,
                in_image,
                constant_data,
                never,
            );
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
            map(
                DISPATCH,
                &block,
                Layout::X64,
                unreadable,
                in_image,
                constant_data,
                never,
            )
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
            let found = map(
                DISPATCH,
                &block,
                Layout::X64,
                unreadable,
                in_image,
                constant_data,
                never,
            );
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

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            unreadable,
            in_image,
            constant_data,
            never,
        );

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
            let found = map(
                DISPATCH,
                &block,
                Layout::X64,
                unreadable,
                in_image,
                constant_data,
                never,
            );
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

        let whole = map(
            DISPATCH,
            &block,
            Layout::X64,
            served(3),
            in_image,
            constant_data,
            never,
        );
        assert_eq!(
            whole.cases.len(),
            3,
            "the whole map is this driver's switch: {:?}",
            whole.cases
        );

        let short = map(
            DISPATCH,
            &block,
            Layout::X64,
            served(2),
            in_image,
            constant_data,
            never,
        );

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
            constant_data,
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
            constant_data,
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
            constant_data,
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
            constant_data,
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
            let found = map(
                DISPATCH,
                &block,
                Layout::X64,
                unreadable,
                in_image,
                constant_data,
                never,
            );
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

        let whole = map(
            DISPATCH,
            &based("rcx"),
            Layout::X64,
            &read,
            in_image,
            constant_data,
            never,
        );
        assert_eq!(whole.cases.len(), 2, "{:?}", whole.cases);

        served.set(0);
        let narrow = map(
            DISPATCH,
            &based("ecx"),
            Layout::X64,
            &read,
            in_image,
            constant_data,
            never,
        );

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
            constant_data,
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
            constant_data,
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
                constant_data,
                never
            )
            .cases
            .len(),
            2,
            "one fold is the switch"
        );
        let twice = map(
            DISPATCH,
            &folded(true),
            Layout::X64,
            &read,
            in_image,
            constant_data,
            never,
        );
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

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            read,
            in_image,
            constant_data,
            never,
        );

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

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            read,
            in_image,
            constant_data,
            never,
        );

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
            constant_data,
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
            constant_data,
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
            constant_data,
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
            constant_data,
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
            constant_data,
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

    /// The facts a rejection's own path carries go with it over the tail jump.
    ///
    /// A shared error block's *entry* facts are what every path into it agreed on, so a case that
    /// copies the IRP into a register before jumping there has that provenance joined away by a
    /// predecessor which did not -- and the store the error goes through stops being one to
    /// `Irp->IoStatus.Status`. The refusal is missed, and the shared block is reported as this
    /// code's handler.
    ///
    /// The fixture's second predecessor is what makes the join do anything: with one path in, the
    /// entry facts *are* this path's and the test would pass without carrying them.
    #[test]
    fn a_rejections_own_facts_go_with_it_over_the_tail_jump() {
        const CASE: u64 = DISPATCH + 0x40;
        const OTHER: u64 = DISPATCH + 0x60;
        const SHARED: u64 = DISPATCH + 0x80;
        let mut block = prologue(DISPATCH);
        block.extend([
            insn(
                DISPATCH + 8,
                "cmp",
                vec![reg("r13d"), imm(0x222003)],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0xe, "je", Vec::new(), Flow::Branch(Some(CASE))),
            insn(
                DISPATCH + 0x14,
                "cmp",
                vec![reg("r13d"), imm(0x222007)],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x1a, "je", Vec::new(), Flow::Branch(Some(OTHER))),
            insn(DISPATCH + 0x20, "ret", Vec::new(), Flow::Return),
            // The case: the IRP into `rbx`, then out to the shared epilogue.
            insn(CASE, "mov", vec![reg("rbx"), reg("rdx")], Flow::Fallthrough),
            insn(CASE + 3, "jmp", Vec::new(), Flow::Jmp(Some(SHARED))),
            // The other predecessor, which reaches the same block with `rbx` holding something
            // else -- so the join keeps nothing about it.
            insn(
                OTHER,
                "mov",
                vec![reg("rbx"), reg("rsi")],
                Flow::Fallthrough,
            ),
            insn(OTHER + 3, "jmp", Vec::new(), Flow::Jmp(Some(SHARED))),
            // The shared epilogue: the status into the IRP, a completion call, and out.
            insn(
                SHARED,
                "mov",
                vec![mem("rbx", 0x30), imm(0xc000_0010)],
                Flow::Fallthrough,
            ),
            insn(
                SHARED + 7,
                "call",
                vec![Operand::Target(0x7000)],
                Flow::Call(Some(0x7000)),
            ),
            insn(SHARED + 0xc, "ret", Vec::new(), Flow::Return),
        ]);

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            unreadable,
            in_image,
            constant_data,
            never,
        );

        let case = found
            .cases
            .iter()
            .find(|case| case.code == 0x222003)
            .unwrap_or_else(|| panic!("the first code is a case: {:?}", found.cases));
        assert_eq!(
            (case.accepted, case.handler),
            (Some(false), None),
            "this path put the IRP where the status goes, whatever the other one did: {case:?}"
        );
    }

    /// Only an instruction that **writes** the return register replaces the status in it.
    ///
    /// `test eax,eax` and `cmp [rbx+30h],0` name the destination and change nothing, so reading
    /// them as writes takes back a refusal the block still has -- and the case then reads as
    /// accepted with whatever it called reported as its handler. Both halves here load the status
    /// and then *read* it, which is what a driver does before branching on what it just decided.
    #[test]
    fn reading_the_status_back_does_not_replace_it() {
        let followed_by = |mnemonic: &str, operands: Vec<Operand>| {
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
                insn(
                    DISPATCH + 0x40,
                    "mov",
                    vec![reg("eax"), imm(0xc000_0010)],
                    Flow::Fallthrough,
                ),
                insn(DISPATCH + 0x45, mnemonic, operands, Flow::Fallthrough),
                insn(DISPATCH + 0x4b, "ret", Vec::new(), Flow::Return),
            ]);
            let found = map(
                DISPATCH,
                &block,
                Layout::X64,
                unreadable,
                in_image,
                constant_data,
                never,
            );
            assert_eq!(found.cases.len(), 1, "{:?}", found.cases);
            found.cases[0].accepted
        };

        assert_eq!(
            followed_by("test", vec![reg("eax"), reg("eax")]),
            Some(false),
            "a `test` reads the status and leaves it where it is"
        );
        assert_eq!(
            followed_by("cmp", vec![mem("rbx", 0x30), imm(0)]),
            Some(false),
            "and so does a compare against the field it was stored in"
        );
        assert_eq!(
            followed_by("xor", vec![reg("eax"), reg("eax")]),
            None,
            "while something that writes it really does replace it"
        );
    }

    /// A table refused for its **size** is a bound that ended something, and the answer says so.
    ///
    /// `cap_hit` is what tells a reader that a list stopped where this module's bounds are rather
    /// than where the driver's code is. A bounds check admitting more entries than
    /// [`MAX_TABLE_ENTRIES`] leaves the jump in `unresolved` for exactly that reason, and saying
    /// no bound was reached sends the reader looking at the driver for an answer that is here.
    #[test]
    fn a_table_larger_than_the_cap_says_a_bound_stopped_it() {
        const TABLE: i64 = 0x9000;
        let admitting = |limit: u64| {
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
                    vec![reg("eax"), imm(limit)],
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
            block
        };
        let table_at = IMAGE_BASE.wrapping_add(TABLE as u64);
        let read = |at: u64, len: usize| {
            (at == table_at).then(|| {
                std::iter::repeat(0x1000u32)
                    .flat_map(|rva| rva.to_le_bytes())
                    .take(len)
                    .collect()
            })
        };

        let within = map(
            DISPATCH,
            &admitting(1),
            Layout::X64,
            &read,
            in_image,
            constant_data,
            never,
        );
        assert_eq!(within.cases.len(), 2, "{:?}", within.cases);
        assert!(!within.cap_hit, "nothing here reached a bound");

        let past = map(
            DISPATCH,
            &admitting(MAX_TABLE_ENTRIES as u64),
            Layout::X64,
            &read,
            in_image,
            constant_data,
            never,
        );

        assert!(past.cases.is_empty(), "{:?}", past.cases);
        assert_eq!(past.unresolved, vec![DISPATCH + 0x2b]);
        assert!(
            past.cap_hit,
            "and this jump is unresolved because of a bound in here, not one in the driver"
        );
    }

    /// One byte-map stage, and not several.
    ///
    /// Two maps in a row make the case number `second[first[code]]`, and reading only the nearest
    /// pairs every code with the entry some other index selects -- published wherever that entry
    /// happens to be executable, with the jump reported as followed. One stage is the switch MSVC
    /// emits; two is a shape this does not read.
    #[test]
    fn two_byte_map_stages_are_not_followed() {
        const FIRST: i64 = 0x5b90;
        const SECOND: i64 = 0x5c90;
        const TABLE: i64 = 0x5b80;
        let staged = |twice: bool| {
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
                    "movzx",
                    vec![
                        reg("eax"),
                        Operand::Memory(MemoryOperand {
                            size: Some(1),
                            segment: None,
                            base: Some(named("rcx")),
                            index: Some(named("rax")),
                            scale: 1,
                            displacement: FIRST,
                            address: None,
                        }),
                    ],
                    Flow::Fallthrough,
                ),
            ]);
            if twice {
                block.push(insn(
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
                            displacement: SECOND,
                            address: None,
                        }),
                    ],
                    Flow::Fallthrough,
                ));
            }
            block.extend([
                insn(
                    DISPATCH + 0x2f,
                    "mov",
                    vec![reg("edx"), indexed(Some("rcx"), "rax", TABLE, None)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x36,
                    "add",
                    vec![reg("rdx"), reg("rcx")],
                    Flow::Fallthrough,
                ),
                insn(DISPATCH + 0x39, "jmp", vec![reg("rdx")], Flow::Jmp(None)),
            ]);
            block
        };
        let table_at = IMAGE_BASE.wrapping_add(TABLE as u64);
        let read = |at: u64, len: usize| -> Option<Vec<u8>> {
            if at == IMAGE_BASE.wrapping_add(FIRST as u64)
                || at == IMAGE_BASE.wrapping_add(SECOND as u64)
            {
                return Some(vec![0u8, 1][..len.min(2)].to_vec());
            }
            (at == table_at).then(|| {
                [0x1000u32, 0x1100]
                    .iter()
                    .flat_map(|rva| rva.to_le_bytes())
                    .take(len)
                    .collect()
            })
        };

        let once = map(
            DISPATCH,
            &staged(false),
            Layout::X64,
            &read,
            in_image,
            constant_data,
            never,
        );
        assert_eq!(
            once.cases.len(),
            2,
            "one stage is the switch: {:?}",
            once.cases
        );

        let twice = map(
            DISPATCH,
            &staged(true),
            Layout::X64,
            &read,
            in_image,
            constant_data,
            never,
        );

        assert!(
            twice.cases.is_empty(),
            "a code's case number is what both maps say, not what the second does: {:?}",
            twice.cases
        );
        assert_eq!(twice.unresolved, vec![DISPATCH + 0x39]);
    }

    /// A status reaches the IRP through a register as readily as it is written into it.
    ///
    /// `mov ecx,0C0000010h` / `mov [rbx+30h],ecx` is the same refusal as the one-instruction form,
    /// and reading only the immediate takes the store for one of something unknown -- which clears
    /// the field and loses the rejection, so the completion call is reported as an accepted case's
    /// handler. The routine returns **success** here, which is what makes the IRP's copy the only
    /// evidence there is.
    #[test]
    fn a_status_carried_in_a_register_still_reaches_the_irp() {
        let through = |register: bool| {
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
            let source = match register {
                true => {
                    block.push(insn(
                        at,
                        "mov",
                        vec![reg("ecx"), imm(0xc000_0010)],
                        Flow::Fallthrough,
                    ));
                    at += 5;
                    reg("ecx")
                }
                false => imm(0xc000_0010),
            };
            block.extend([
                insn(at, "mov", vec![mem("rbx", 0x30), source], Flow::Fallthrough),
                insn(
                    at + 7,
                    "call",
                    vec![Operand::Target(0x7000)],
                    Flow::Call(Some(0x7000)),
                ),
                // The dispatch routine returns success; the completed IRP carries the error.
                insn(
                    at + 0xc,
                    "xor",
                    vec![reg("eax"), reg("eax")],
                    Flow::Fallthrough,
                ),
                insn(at + 0xe, "ret", Vec::new(), Flow::Return),
            ]);
            let found = map(
                DISPATCH,
                &block,
                Layout::X64,
                unreadable,
                in_image,
                constant_data,
                never,
            );
            assert_eq!(found.cases.len(), 1, "{:?}", found.cases);
            (found.cases[0].accepted, found.cases[0].handler)
        };

        assert_eq!(
            through(false),
            (Some(false), None),
            "the constant written straight into the field is a refusal"
        );
        assert_eq!(
            through(true),
            (Some(false), None),
            "and so is the same constant carried there in a register"
        );
    }

    /// A status established **before** the branch leaves the case that branch selects undecided.
    ///
    /// `mov [rbx+30h],0C0000010h` / `cmp code,N` / `je complete` puts the store in one block and
    /// the completion in another. Reading the second alone sees a block that calls something and
    /// returns success, and answers **accepted** with the completion routine as its handler --
    /// while the IRP it completed carries an error.
    ///
    /// It is not a refusal either, and that is the half this test exists to pin. Storing a default
    /// failure into the IRP before deciding and letting each case overwrite it is an ordinary
    /// shape, so a verdict of "refused" here takes the handler away from every code the driver
    /// accepts. The status crosses the edge as **evidence**: enough to stop this claiming
    /// acceptance, not enough to claim the opposite.
    ///
    /// And it **joins** the way a register's value does, which is the third half: a path that
    /// reaches the same compare without passing the store leaves the block knowing nothing at all,
    /// and the case is accepted again.
    #[test]
    fn a_status_set_before_the_branch_leaves_the_case_it_selects_undecided() {
        const JOIN: u64 = DISPATCH + 0x1a;
        const COMPLETE: u64 = DISPATCH + 0x40;
        let refusing = |stored: bool, skipping: bool| {
            let mut block = prologue(DISPATCH);
            block.push(insn(
                DISPATCH + 8,
                "mov",
                vec![reg("rbx"), reg("rdx")],
                Flow::Fallthrough,
            ));
            if skipping {
                // A way to the compare that never passes the store.
                block.extend([
                    insn(
                        DISPATCH + 0xb,
                        "test",
                        vec![reg("ecx"), reg("ecx")],
                        Flow::Fallthrough,
                    ),
                    insn(DISPATCH + 0xd, "je", Vec::new(), Flow::Branch(Some(JOIN))),
                ]);
            }
            if stored {
                block.push(insn(
                    DISPATCH + 0x13,
                    "mov",
                    vec![mem("rbx", 0x30), imm(0xc000_0010)],
                    Flow::Fallthrough,
                ));
            }
            block.extend([
                insn(
                    JOIN,
                    "cmp",
                    vec![reg("r13d"), imm(0x222003)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x20,
                    "je",
                    Vec::new(),
                    Flow::Branch(Some(COMPLETE)),
                ),
                insn(DISPATCH + 0x26, "ret", Vec::new(), Flow::Return),
                // The completion: a call, success in the return register, and out.
                insn(
                    COMPLETE,
                    "call",
                    vec![Operand::Target(0x7000)],
                    Flow::Call(Some(0x7000)),
                ),
                insn(
                    COMPLETE + 5,
                    "xor",
                    vec![reg("eax"), reg("eax")],
                    Flow::Fallthrough,
                ),
                insn(COMPLETE + 7, "ret", Vec::new(), Flow::Return),
            ]);
            let found = map(
                DISPATCH,
                &block,
                Layout::X64,
                unreadable,
                in_image,
                constant_data,
                never,
            );
            let case = found
                .cases
                .iter()
                .find(|case| case.code == 0x222003)
                .unwrap_or_else(|| panic!("the code is a case: {:?}", found.cases));
            (case.accepted, case.handler)
        };

        assert_eq!(
            refusing(true, false),
            (None, Some(0x7000)),
            "the IRP this completes carries the error the block before it stored, which is not              enough to call the case refused and is too much to call it accepted"
        );
        assert_eq!(
            refusing(false, false),
            (Some(true), Some(0x7000)),
            "and with nothing stored it is a case that reaches a routine"
        );
        assert_eq!(
            refusing(true, true),
            (Some(true), Some(0x7000)),
            "a status one path sets is not one the block makes: the other way in never passed              the store, so what they agree on is nothing"
        );
    }

    /// A status in the **return register** does not survive a call, and one in the IRP does.
    ///
    /// `mov eax,0C0000010h` / `call handler` / `ret` returns whatever the handler returned, so
    /// reading it as a refusal reports a code the driver accepts as one it refuses, with the
    /// routine it reaches taken away. The same status in `Irp->IoStatus.Status` is untouched by a
    /// call, which is where the ordinary rejection puts it and why this distinction costs nothing
    /// real -- and a driver that means to return one **reloads** it after the call, which is the
    /// third half here.
    ///
    /// The status arrives from the block before in every variant, so this is also the rule that
    /// makes carrying it across an edge safe.
    #[test]
    fn a_status_in_the_return_register_does_not_survive_a_call() {
        #[derive(Clone, Copy)]
        enum Put {
            Returned,
            Irp,
            Reloaded,
        }
        let refusing = |put: Put| {
            let mut block = prologue(DISPATCH);
            block.extend([
                insn(
                    DISPATCH + 8,
                    "mov",
                    vec![reg("rbx"), reg("rdx")],
                    Flow::Fallthrough,
                ),
                // The status, before the routine decides anything.
                insn(
                    DISPATCH + 0xb,
                    "mov",
                    vec![
                        match put {
                            Put::Irp => mem("rbx", 0x30),
                            _ => reg("eax"),
                        },
                        imm(0xc000_0010),
                    ],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x12,
                    "cmp",
                    vec![reg("r13d"), imm(0x222003)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x18,
                    "je",
                    Vec::new(),
                    Flow::Branch(Some(DISPATCH + 0x40)),
                ),
                insn(DISPATCH + 0x1e, "ret", Vec::new(), Flow::Return),
                // The case: a call, and out.
                insn(
                    DISPATCH + 0x40,
                    "call",
                    vec![Operand::Target(0x7000)],
                    Flow::Call(Some(0x7000)),
                ),
            ]);
            if matches!(put, Put::Reloaded) {
                block.push(insn(
                    DISPATCH + 0x45,
                    "mov",
                    vec![reg("eax"), imm(0xc000_0010)],
                    Flow::Fallthrough,
                ));
            }
            block.push(insn(DISPATCH + 0x4a, "ret", Vec::new(), Flow::Return));
            let found = map(
                DISPATCH,
                &block,
                Layout::X64,
                unreadable,
                in_image,
                constant_data,
                never,
            );
            assert_eq!(found.cases.len(), 1, "{:?}", found.cases);
            (found.cases[0].accepted, found.cases[0].handler)
        };

        assert_eq!(
            refusing(Put::Returned),
            (Some(true), Some(0x7000)),
            "the call returned its own status over the one loaded before it"
        );
        assert_eq!(
            refusing(Put::Irp),
            (None, Some(0x7000)),
            "a call writes no field of the IRP, so that status still stands -- as evidence, since              it was established before this case was chosen rather than by it"
        );
        assert_eq!(
            refusing(Put::Reloaded),
            (Some(false), None),
            "as does one put back after the call, which is how a driver returns what it completed \
             with"
        );
    }

    /// A status in the return register dies where the **register** does, and the decoder is what
    /// says when that is.
    ///
    /// `mul ecx` writes `rax` and names it nowhere; `xchg r13d,eax` writes it as its *second*
    /// operand. Reading the destination alone leaves the status standing in a register the
    /// instruction overwrote, and a block that goes on to return something computed is then read
    /// as refusing the code -- which takes the handler off a case the driver accepts. The same
    /// write set the registers are forgotten by answers this, because a status is one of them.
    #[test]
    fn a_status_in_the_return_register_dies_with_the_register() {
        #[derive(Clone, Copy)]
        enum Clobber {
            /// Nothing touches it, so the load is what the routine returns.
            None,
            /// Named, but as the second operand rather than the destination.
            Named,
            /// Written and named nowhere at all.
            Implicit,
        }
        let refusing = |clobber: Clobber| {
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
                // The case handles the code, and then decides what to return.
                insn(
                    DISPATCH + 0x40,
                    "call",
                    vec![Operand::Target(0x7000)],
                    Flow::Call(Some(0x7000)),
                ),
                insn(
                    DISPATCH + 0x45,
                    "mov",
                    vec![reg("eax"), imm(0xc000_0010)],
                    Flow::Fallthrough,
                ),
            ]);
            match clobber {
                Clobber::None => {}
                Clobber::Named => block.push(insn(
                    DISPATCH + 0x4a,
                    "xchg",
                    vec![reg("r13d"), reg("eax")],
                    Flow::Fallthrough,
                )),
                Clobber::Implicit => block.push(insn(
                    DISPATCH + 0x4a,
                    "mul",
                    vec![reg("ecx")],
                    Flow::Fallthrough,
                )),
            }
            block.push(insn(DISPATCH + 0x4d, "ret", Vec::new(), Flow::Return));
            let found = map(
                DISPATCH,
                &block,
                Layout::X64,
                unreadable,
                in_image,
                constant_data,
                never,
            );
            assert_eq!(found.cases.len(), 1, "{:?}", found.cases);
            (found.cases[0].accepted, found.cases[0].handler)
        };

        assert_eq!(
            refusing(Clobber::None),
            (Some(false), None),
            "the status it loaded after the call is the one it returns"
        );
        assert_eq!(
            refusing(Clobber::Named),
            (Some(true), Some(0x7000)),
            "an exchange returns the other register, and names this one second"
        );
        assert_eq!(
            refusing(Clobber::Implicit),
            (Some(true), Some(0x7000)),
            "and a multiply returns its product, naming neither register it wrote"
        );
    }

    /// A status in the return register does not survive a tail jump **out of the routine**, and
    /// does survive one that stays inside it.
    ///
    /// They are not the same instruction doing the same thing. `jmp handler` ends this routine and
    /// the callee supplies its return value, exactly as a call does -- so a dispatcher that loads
    /// a default error before its compare chain and reaches a case that way accepts the code, and
    /// reading the arrived status as its answer reports it undecided. `jmp common_ret` is one path
    /// continuing, and the rejection written across those two blocks is lost if the status does
    /// not go with it.
    #[test]
    fn a_status_does_not_survive_a_tail_jump_out_of_the_routine() {
        const CASE: u64 = DISPATCH + 0x40;
        const SHARED: u64 = DISPATCH + 0x50;
        let refusing = |inside: bool| {
            let mut block = prologue(DISPATCH);
            block.extend([
                // The default the routine returns for anything it does not recognise, loaded
                // before it has recognised anything.
                insn(
                    DISPATCH + 8,
                    "mov",
                    vec![reg("eax"), imm(0xc000_0010)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0xe,
                    "cmp",
                    vec![reg("r13d"), imm(0x222003)],
                    Flow::Fallthrough,
                ),
                insn(DISPATCH + 0x14, "je", Vec::new(), Flow::Branch(Some(CASE))),
                insn(DISPATCH + 0x1a, "ret", Vec::new(), Flow::Return),
                // The case, which is one jump.
                insn(
                    CASE,
                    "jmp",
                    vec![Operand::Target(match inside {
                        true => SHARED,
                        false => 0x7000,
                    })],
                    Flow::Jmp(Some(match inside {
                        true => SHARED,
                        false => 0x7000,
                    })),
                ),
                insn(SHARED, "ret", Vec::new(), Flow::Return),
            ]);
            let found = map(
                DISPATCH,
                &block,
                Layout::X64,
                unreadable,
                in_image,
                constant_data,
                never,
            );
            assert_eq!(found.cases.len(), 1, "{:?}", found.cases);
            (found.cases[0].accepted, found.cases[0].handler)
        };

        assert_eq!(
            refusing(false),
            (Some(true), Some(0x7000)),
            "the routine it jumps to returns what it likes, so the default is not the answer"
        );
        assert_eq!(
            refusing(true),
            (None, Some(SHARED)),
            "and a jump that lands in this listing carries what the case established"
        );
    }

    /// A table case is read with nothing believed about any **register**, and with the status that
    /// stood at its jump.
    ///
    /// The two are not the same kind of thing. A register's value is about the path the graph has
    /// no edge for, so it is dropped; the status is about the path that *reaches* the jump, and
    /// every landing the table selects is on it. Dropped with the registers, a routine that stores
    /// an error into the IRP before switching has every code it routes to read as accepted, with
    /// whatever they call reported as the handler.
    #[test]
    fn a_table_case_carries_the_status_that_stood_at_its_jump() {
        const TABLE: i64 = 0x9000;
        const FIRST: u64 = DISPATCH + 0x40;
        const SECOND: u64 = DISPATCH + 0x50;
        const DECIDES: u64 = DISPATCH + 0x60;
        let refusing = |stored: bool| {
            let mut block = prologue(DISPATCH);
            block.push(insn(
                DISPATCH + 8,
                "mov",
                vec![reg("rbx"), reg("rdx")],
                Flow::Fallthrough,
            ));
            if stored {
                block.push(insn(
                    DISPATCH + 0xb,
                    "mov",
                    vec![mem("rbx", 0x30), imm(0xc000_0010)],
                    Flow::Fallthrough,
                ));
            }
            block.extend([
                insn(
                    DISPATCH + 0x12,
                    "mov",
                    vec![reg("eax"), reg("r13d")],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x15,
                    "sub",
                    vec![reg("eax"), imm(0x6dc004)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x1b,
                    "cmp",
                    vec![reg("eax"), imm(1)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x1e,
                    "ja",
                    Vec::new(),
                    Flow::Branch(Some(0xfa11)),
                ),
                insn(
                    DISPATCH + 0x24,
                    "lea",
                    vec![reg("rcx"), at_address(IMAGE_BASE)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x2b,
                    "mov",
                    vec![reg("eax"), indexed(Some("rcx"), "rax", TABLE, None)],
                    Flow::Fallthrough,
                ),
                insn(
                    DISPATCH + 0x32,
                    "add",
                    vec![reg("rax"), reg("rcx")],
                    Flow::Fallthrough,
                ),
                insn(DISPATCH + 0x35, "jmp", vec![reg("rax")], Flow::Jmp(None)),
                // Two landings, each of which completes the request and returns.
                insn(
                    FIRST,
                    "call",
                    vec![Operand::Target(0x7000)],
                    Flow::Call(Some(0x7000)),
                ),
                insn(FIRST + 5, "ret", Vec::new(), Flow::Return),
                insn(
                    SECOND,
                    "call",
                    vec![Operand::Target(0x7100)],
                    Flow::Call(Some(0x7100)),
                ),
                // This one does **not** return: it leaves for a block that decides something, so
                // the refusal walk answers nothing about it and what is left to read is the
                // status the block itself has. That is the other place a table case's status is
                // used, and it is a different answer -- undecided rather than refused.
                insn(SECOND + 5, "jmp", Vec::new(), Flow::Jmp(Some(DECIDES))),
                insn(DECIDES, "cmp", vec![reg("r13d"), imm(1)], Flow::Fallthrough),
                insn(
                    DECIDES + 6,
                    "je",
                    Vec::new(),
                    Flow::Branch(Some(DISPATCH + 0xf00)),
                ),
                insn(DECIDES + 12, "ret", Vec::new(), Flow::Return),
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
            let found = map(
                DISPATCH,
                &block,
                Layout::X64,
                read,
                in_image,
                constant_data,
                never,
            );
            assert_eq!(found.cases.len(), 2, "{:?}", found.cases);
            found
                .cases
                .iter()
                .map(|case| (case.accepted, case.handler))
                .collect::<Vec<_>>()
        };

        assert_eq!(
            refusing(true),
            vec![(None, Some(0x7000)), (None, Some(0x7100))],
            "both codes complete an IRP carrying the error stored before the switch, which stops              this calling either accepted -- one reached through the block's own return and the              other through a block that decides something, which is the two places a case reads a              status"
        );
        assert_eq!(
            refusing(false),
            vec![(Some(true), Some(0x7000)), (Some(true), Some(0x7100))],
            "and with nothing stored they are cases that reach routines"
        );
    }

    /// An **implicit** destination is a write like any other.
    ///
    /// `mul ecx` reads `ecx` and writes `rax` and `rdx`, naming neither. A pass inferring what an
    /// instruction wrote from its first operand keeps believing in a register that no longer holds
    /// what it did, and a control code surviving that way is reported as a code the driver
    /// accepts. Nothing in this module could reach that shape until the decoder began answering
    /// which registers an instruction writes; the rule it replaced could only take the registers
    /// an instruction **named**.
    #[test]
    fn an_implicit_destination_is_a_write_like_any_other() {
        let multiplied = |between: bool| {
            let mut block = prologue(DISPATCH);
            block.extend([insn(
                DISPATCH + 8,
                "mov",
                vec![reg("eax"), reg("r13d")],
                Flow::Fallthrough,
            )]);
            if between {
                block.push(insn(
                    DISPATCH + 0xb,
                    "mul",
                    vec![reg("ecx")],
                    Flow::Fallthrough,
                ));
            }
            block.extend([
                insn(
                    DISPATCH + 0xd,
                    "cmp",
                    vec![reg("eax"), imm(0x222003)],
                    Flow::Fallthrough,
                ),
                insn(DISPATCH + 0x13, "je", Vec::new(), Flow::Branch(Some(0x900))),
                insn(DISPATCH + 0x19, "ret", Vec::new(), Flow::Return),
            ]);
            map(
                DISPATCH,
                &block,
                Layout::X64,
                unreadable,
                in_image,
                constant_data,
                never,
            )
        };

        assert_eq!(
            multiplied(false)
                .cases
                .iter()
                .map(|case| case.code)
                .collect::<Vec<_>>(),
            vec![0x222003],
            "the register still holds the code"
        );
        assert!(
            multiplied(true).cases.is_empty(),
            "and here a multiply put its own result there, naming neither register it wrote: {:?}",
            multiplied(true).cases
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

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            read,
            in_image,
            constant_data,
            never,
        );

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

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            unreadable,
            in_image,
            constant_data,
            never,
        );

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
            // The refusal: a completion call, the status into the return register, and out. The
            // status goes in **after** the call, because the call returns its own -- which is the
            // order a driver writes and the reason a status in that register does not survive one.
            insn(
                DISPATCH + 0x20,
                "call",
                vec![Operand::Target(0x7000)],
                Flow::Call(Some(0x7000)),
            ),
            insn(
                DISPATCH + 0x25,
                "mov",
                vec![reg32("eax"), imm(0xc000_0010)],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x2a, "ret", Vec::new(), Flow::Return),
        ];

        let found = map(
            DISPATCH,
            &block,
            Layout::X86,
            unreadable,
            in_image,
            constant_data,
            never,
        );

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
            map(
                DISPATCH,
                &block,
                Layout::X64,
                unreadable,
                in_image,
                constant_data,
                never,
            )
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
            map(
                DISPATCH,
                &block,
                Layout::X64,
                unreadable,
                in_image,
                constant_data,
                never,
            )
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

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            read,
            in_image,
            constant_data,
            never,
        );

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

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            unreadable,
            in_image,
            constant_data,
            never,
        );

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

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            unreadable,
            in_image,
            constant_data,
            never,
        );

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

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            read,
            in_image,
            constant_data,
            never,
        );

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

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            unreadable,
            in_image,
            constant_data,
            never,
        );

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

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            unreadable,
            in_image,
            constant_data,
            never,
        );

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

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            unreadable,
            in_image,
            constant_data,
            never,
        );

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

        let found = map(
            DISPATCH,
            &block,
            Layout::X86,
            unreadable,
            in_image,
            constant_data,
            never,
        );

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

        let wrong = map(
            DISPATCH,
            &block,
            Layout::X64,
            unreadable,
            in_image,
            constant_data,
            never,
        );

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

        let inclusive = map(
            DISPATCH,
            &switch("ja"),
            Layout::X64,
            read,
            in_image,
            constant_data,
            never,
        );
        let exclusive = map(
            DISPATCH,
            &switch("jae"),
            Layout::X64,
            read,
            in_image,
            constant_data,
            never,
        );
        let signed = map(
            DISPATCH,
            &switch("jg"),
            Layout::X64,
            read,
            in_image,
            constant_data,
            never,
        );

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

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            unreadable,
            in_image,
            constant_data,
            never,
        );

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

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            unreadable,
            in_image,
            constant_data,
            never,
        );

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

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            unreadable,
            in_image,
            constant_data,
            never,
        );

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

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            unreadable,
            in_image,
            constant_data,
            never,
        );

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

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            unreadable,
            in_image,
            constant_data,
            never,
        );

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

        let mixed = map(
            DISPATCH,
            &block,
            Layout::X64,
            unreadable,
            in_image,
            constant_data,
            never,
        );

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

        let found = map(
            DISPATCH,
            &block,
            Layout::X64,
            unreadable,
            in_image,
            constant_data,
            halt,
        );

        assert_eq!(found.halted, Some(Halt::Deadline));
        assert!(
            found.examined < block.len(),
            "the walk stopped where the halt landed: {} of {}",
            found.examined,
            block.len()
        );
    }
}
