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
//!   scale and a bounded entry count were all recovered; anything else is recorded as an
//!   unresolved transfer, because a table read at a guessed address is a list of plausible
//!   addresses rather than an answer.
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
//! # How this is derived, and what that costs
//!
//! A **linear pass** over the listing: register facts carried instruction to instruction, restored
//! at a region boundary, with a window looked backwards from an indirect jump and forwards from a
//! case's landing site. It answers `mountmgr` exactly as a hand decode did — and every guard below
//! about a fact not carrying across a boundary is there because a review round found the pass
//! carrying one. A block-structured walk answers those structurally rather than one guard at a
//! time, which is
//! [#306](https://github.com/glslang/windbg-mcp/issues/306); this module's entry point is what that
//! would keep, and these tests are what would check it.
//!
//! # Engine-free
//!
//! Like [`crate::pe`], [`crate::hazards`] and [`crate::driver`], every entry point takes closures
//! rather than a `DebugEngine`: a decoded function, a reader for the image's own bytes, and a
//! halt poll. So every case below is unit-tested against a hand-built instruction list with no
//! debugger anywhere near it.

use std::collections::HashMap;

use dbgscope::dbgeng::{Flow, Instruction, Operand};

use crate::walk::Halt;

/// Bounds. A malformed or hostile driver decides how much work this is, so every list the answer
/// carries has a cap and a count beside it that stays exact.
///
/// The numbers are far past what a real driver produces — the largest dispatch routine measured
/// here recognises 28 codes — and are here to bound the absurd rather than to shape an answer.
pub(crate) const MAX_CASES: usize = 4096;
/// The most entries followed out of one jump table. A table is `entries * 4` bytes of reads, so
/// this is also what bounds the reading.
pub(crate) const MAX_TABLE_ENTRIES: usize = 4096;
/// The most instructions examined in one dispatch routine.
pub(crate) const MAX_INSTRUCTIONS: usize = 64 * 1024;
/// How often the halt poll runs while walking the listing.
const POLL_EVERY: usize = 256;
/// How far back from an indirect `jmp` the table pattern is looked for, and how far forward from a
/// case's landing site a handler and a size check are.
const WINDOW: usize = 24;

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
    /// The jump tables that were followed.
    pub(crate) tables: Vec<Table>,
    /// Indirect transfers that were **not** followed, by address: an unresolved switch, a call
    /// through a pointer. Each one is a place a code could be recognised and was not, which is
    /// what stops a short case list reading as a complete one.
    pub(crate) unresolved: Vec<u64>,
    /// Why the walk stopped early, when it did.
    pub(crate) halted: Option<Halt>,
    /// True when a bound above ended something early.
    pub(crate) cap_hit: bool,
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
        irp_register: Some("rdx"),
    };
    pub(crate) const X86: Self = Self {
        current_stack_location: 0x60,
        control_code: 0x0c,
        input_length: 0x08,
        output_length: 0x04,
        irp_register: None,
    };
}

/// The 64-bit register a name belongs to, so `eax`, `ax` and `al` are one register and `r13d` is
/// `r13`.
///
/// A dispatch routine reads the control code as a **dword** and compares the same register as a
/// qword two instructions later; tracking the spellings separately would lose the value at the
/// first width change.
fn family(name: &str) -> Option<&'static str> {
    const WIDE: [&str; 16] = [
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12",
        "r13", "r14", "r15",
    ];
    let name = name.trim();
    for wide in WIDE {
        if name == wide {
            return Some(wide);
        }
    }
    // eax/ax/al/ah -> rax, and the same shape for the other three legacy names.
    const LEGACY: [(&str, [&str; 4]); 8] = [
        ("rax", ["eax", "ax", "al", "ah"]),
        ("rcx", ["ecx", "cx", "cl", "ch"]),
        ("rdx", ["edx", "dx", "dl", "dh"]),
        ("rbx", ["ebx", "bx", "bl", "bh"]),
        ("rsp", ["esp", "sp", "spl", ""]),
        ("rbp", ["ebp", "bp", "bpl", ""]),
        ("rsi", ["esi", "si", "sil", ""]),
        ("rdi", ["edi", "di", "dil", ""]),
    ];
    for (wide, narrow) in LEGACY {
        if narrow.contains(&name) {
            return Some(wide);
        }
    }
    // r8d/r8w/r8b and friends.
    for wide in WIDE {
        if let Some(rest) = name.strip_prefix(wide)
            && matches!(rest, "d" | "w" | "b")
        {
            return Some(wide);
        }
    }
    None
}

/// The registers a `call` may return over, which is what makes a belief about one stale.
const VOLATILE: [&str; 7] = ["rax", "rcx", "rdx", "r8", "r9", "r10", "r11"];

/// The register an operand names, if it names one.
fn register_of(operand: &Operand) -> Option<&'static str> {
    match operand {
        Operand::Register(name) => family(name),
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

/// What the flags a conditional branch reads say about the compare that set them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Relation {
    /// Equality: the branch is taken when the compared values are the same.
    Equal,
    /// Inequality: taken when they differ.
    NotEqual,
    /// **Unsigned** above: `cmp index,N` / `ja default` leaves `0..=N` on the path, so a table
    /// behind it has `N + 1` entries.
    Above,
    /// **Unsigned** above-or-equal: `jae default` leaves `0..N`, so a table behind it has `N`.
    ///
    /// Kept apart from [`Self::Above`] because the difference is one table entry, and one entry
    /// past the end of a table is a dword of whatever follows it -- which becomes a control code
    /// the driver is reported as accepting whenever it happens to resolve inside the image.
    AboveOrEqual,
    /// Anything else, which is modelled as "some order" and never as a case or a bound. The
    /// **signed** comparisons are deliberately here: `jg` proves nothing about an unsigned index,
    /// and a table is indexed as unsigned.
    Order,
}

fn relation_of(mnemonic: &str) -> Option<Relation> {
    Some(match mnemonic {
        "je" | "jz" => Relation::Equal,
        "jne" | "jnz" => Relation::NotEqual,
        "ja" | "jnbe" => Relation::Above,
        "jae" | "jnb" | "jnc" => Relation::AboveOrEqual,
        "jb" | "jnae" | "jc" | "jbe" | "jna" | "jg" | "jnle" | "jge" | "jnl" | "jl" | "jnge"
        | "jle" | "jng" => Relation::Order,
        _ => return None,
    })
}

/// A bounds check the walk has passed: `cmp index, N` / `ja default`, which is the only thing
/// that gives a jump table a length.
///
/// Kept as a short history rather than read off the register state at the jump, because the
/// pattern in between **overwrites the index register** with the table entry it loads: by the time
/// the indirect jump arrives, the register that was the index holds an address, and the fact that
/// it was bounded lives nowhere else.
#[derive(Debug, Clone, Copy)]
struct Bound {
    /// Where in the listing the check was, so a stale one can be dropped.
    at_index: usize,
    /// The compare's address, which is what says whether anything wrote the index *since* it.
    at: u64,
    /// The register checked.
    register: &'static str,
    /// What it held: `(code - offset) >> shift`.
    offset: i64,
    shift: u32,
    /// The largest index the check admits.
    limit: u64,
    /// Whether the index came from a control code traced to the IRP.
    proved: bool,
    /// Where the check sends an index past that -- the switch's **default**, which is also what
    /// every unused slot of its table holds.
    default: Option<u64>,
}

/// The state one compare leaves for the branch that reads it.
#[derive(Debug, Clone, Copy)]
struct Compared {
    /// The control code the compare is about, when it is about one.
    code: Option<u64>,
    /// Whether the value compared was traced from the IRP rather than taken from a bare
    /// displacement.
    proved: bool,
    /// The register compared and what it held, for a bounds check feeding a jump table.
    index: Option<(&'static str, i64, u32)>,
    /// The bound, when the compare was against an immediate.
    bound: Option<u64>,
    /// Where the compare is.
    at: u64,
}

/// Recovers the control codes a dispatch routine accepts.
///
/// `block` is the routine's instructions in listing order — what `uf` produces, and what
/// [`crate::driver::in_listing_order`] guarantees has a barrier wherever one could not be read.
/// `read` serves the image's own bytes for a jump table, and answers `None` for an address that
/// will not read, which ends that table rather than the map.
pub(crate) fn map(
    dispatch: u64,
    block: &[Instruction],
    layout: Layout,
    mut read: impl FnMut(u64, usize) -> Option<Vec<u8>>,
    in_image: impl Fn(u64) -> bool,
    mut halt: impl FnMut() -> Option<Halt>,
) -> Map {
    let mut state: HashMap<&'static str, Value> = HashMap::new();
    // The second argument of a dispatch routine. Believed from the first instruction, and
    // overwritten the moment anything writes to it, which is what a prologue's `mov rbx,rdx`
    // does — the belief travels rather than being pinned to the register.
    if let Some(register) = layout.irp_register {
        state.insert(register, Value::Irp);
    }

    let mut cases: Vec<Case> = Vec::new();
    let mut case_count = 0usize;
    let mut tables: Vec<Table> = Vec::new();
    let mut unresolved: Vec<u64> = Vec::new();
    let mut halted = None;
    let mut cap_hit = false;
    let mut traced = false;
    let mut examined = 0usize;
    let mut blind = 0usize;
    let mut compared: Option<Compared> = None;
    let mut bounds: Vec<Bound> = Vec::new();
    // The state as it stood when the control code was first in a register, kept to be restored at
    // a region boundary. See `ended` below for why.
    let mut entry_state: Option<HashMap<&'static str, Value>> = None;
    let mut ended = false;

    for (i, instruction) in block.iter().enumerate() {
        if i >= MAX_INSTRUCTIONS {
            cap_hit = true;
            break;
        }
        if i % POLL_EVERY == 0
            && let Some(why) = halt()
        {
            halted = Some(why);
            break;
        }
        examined += 1;

        // **A listing is a rendering of a graph, and belief does not flow across a region
        // boundary.** `uf` prints a function's blocks one after another, so the instruction after
        // a `ret` or an unconditional `jmp` is not reached from the one before it -- it is
        // reached from a branch somewhere else, with whatever that path left in the registers. A
        // straight-line pass that carried state across those seams read `mountmgr`'s shared
        // epilogue, saw its `pop r13` restore the caller's register, and lost the control code
        // for the whole rest of the routine: two of its codes were recovered and five were not.
        //
        // So a region boundary restores the state to what it was when the control code was first
        // loaded, which is the state every one of those blocks is in fact entered with. It is an
        // assumption rather than a proof -- a block entered with that register holding something
        // else would be read wrongly -- and it is the same assumption a person reading the
        // listing makes, for the same reason: the compare chain is one routine's, and its blocks
        // are its own.
        if ended {
            state = entry_state.clone().unwrap_or_default();
            compared = None;
            bounds.clear();
        }
        ended = matches!(
            instruction.flow,
            Flow::Return | Flow::Trap | Flow::Jmp(_) | Flow::Unreadable
        );
        // An instruction that could not be read, or whose encoding this build does not decode, is
        // counted rather than merely stepped over: the compare that recognises a code may be
        // exactly there, and a case list short by one reads like a complete one.
        if matches!(instruction.flow, Flow::Unreadable | Flow::Unknown) {
            blind += 1;
        }

        // A branch reading the flags of the compare before it is where a case is made, so it is
        // handled before the state update that clears `compared`.
        if let Flow::Branch(target) = instruction.flow {
            if let (Some(was), Some(relation)) = (compared, relation_of(&instruction.mnemonic)) {
                match (relation, was.code) {
                    // `cmp code, N` / `je handler` -- the case is at the branch target. A branch
                    // whose destination the encoding does not give is a case whose landing site is
                    // unknown, and a case has to say where it goes to be worth reporting.
                    (Relation::Equal, Some(code)) => {
                        if let Some(target) = target {
                            push_case(
                                &mut cases,
                                &mut case_count,
                                &mut cap_hit,
                                code,
                                Recovery::Compare,
                                was.at,
                                target,
                                was.proved,
                            );
                        }
                    }
                    // `cmp code, N` / `jne next` -- the case is what follows, since the branch is
                    // the *rejection*. Recorded at the next instruction's address rather than at
                    // the branch's, so the landing site is code that runs for this case.
                    (Relation::NotEqual, Some(code)) => {
                        if let Some(next) = block.get(i + 1) {
                            push_case(
                                &mut cases,
                                &mut case_count,
                                &mut cap_hit,
                                code,
                                Recovery::Compare,
                                was.at,
                                next.address,
                                was.proved,
                            );
                        }
                    }
                    // `cmp index, N` / `ja default` is the bounds check a jump table needs, and
                    // the one thing that survives the load overwriting the index register. The
                    // exclusive form admits one fewer index, which is one table entry.
                    (relation @ (Relation::Above | Relation::AboveOrEqual), _) => {
                        if let (Some((register, offset, shift)), Some(limit)) =
                            (was.index, was.bound)
                            && let Some(limit) = match relation {
                                Relation::Above => Some(limit),
                                _ => limit.checked_sub(1),
                            }
                        {
                            bounds.push(Bound {
                                at_index: i,
                                at: was.at,
                                register,
                                offset,
                                shift,
                                limit,
                                proved: was.proved,
                                // The branch's own target: an index past the bound goes to the
                                // switch's default, and so does every slot of the table the
                                // compiler had no case for.
                                default: target,
                            });
                        }
                    }
                    _ => {}
                }
            }
            compared = None;
            clobber(&mut state, instruction);
            continue;
        }

        // An indirect **jump** is either a jump table this can follow or a hole in the answer. An
        // indirect *call* is neither: a driver reaches its imports through the IAT, so a dispatch
        // routine is full of them and not one of them decides on a control code. Listing those as
        // places a code might be recognised made `mountmgr` report seventeen, every one an import
        // thunk -- noise that makes the list nobody can act on out of the one field that says the
        // answer is a lower bound.
        if matches!(instruction.flow, Flow::Jmp(None)) {
            let start = i.saturating_sub(WINDOW);
            bounds.retain(|bound| bound.at_index >= start);
            match follow_table(
                &block[start..i],
                instruction,
                instruction.address,
                &bounds,
                &state,
                &mut read,
                &in_image,
            ) {
                Some(resolved) => {
                    for (code, lands) in resolved.cases {
                        push_case(
                            &mut cases,
                            &mut case_count,
                            &mut cap_hit,
                            code,
                            Recovery::JumpTable,
                            instruction.address,
                            lands,
                            resolved.proved,
                        );
                    }
                    tables.push(resolved.table);
                }
                None => unresolved.push(instruction.address),
            }
            compared = None;
            clobber(&mut state, instruction);
            continue;
        }

        compared = update(&mut state, instruction, layout, &mut traced);
        // The first moment the control code is in a register is the state every block of the
        // dispatch chain is entered with, so it is what a region boundary restores.
        if entry_state.is_none()
            && state.values().any(|value| {
                matches!(
                    value,
                    Value::Code {
                        offset: 0,
                        shift: 0,
                        ..
                    }
                )
            })
        {
            entry_state = Some(state.clone());
        }
        // A **direct** call reaches here rather than the arms above, and it returns over the
        // volatile registers exactly as an indirect one does. Forgetting them only on the
        // indirect path would leave a compare against whatever a callee returned reported as a
        // control code, which is the shape of wrong answer this pass exists to avoid.
        clobber(&mut state, instruction);
    }

    if halted.is_none() {
        // Polled once more after the loop: a halt landing during the last window would otherwise
        // leave a map that reads as a routine fully walked.
        halted = halt();
    }

    // The handler and the size proofs are read off the block the case lands in, which is why they
    // are a second pass: a case made at a compare near the top of a routine lands hundreds of
    // instructions further down.
    let index: HashMap<u64, usize> = block
        .iter()
        .enumerate()
        .map(|(i, instruction)| (instruction.address, i))
        .collect();
    // The registers the IRP's stack location was watched into, which is what a length check's
    // base has to be one of. Taken from the state at the top of the dispatch chain, for the same
    // reason that state is what a region boundary restores: it is what every case block is
    // entered with. A case that re-derives the pointer into some other register is one whose
    // length checks are not reported, which is the direction to be wrong in.
    let stack_registers: Vec<&'static str> = entry_state
        .unwrap_or_default()
        .iter()
        .filter(|(_, value)| matches!(value, Value::StackLocation))
        .map(|(register, _)| *register)
        .collect();
    // Whether the block at an address sets an NTSTATUS error and returns, which is the only thing
    // in this routine that says which side of a branch the driver treats as success.
    let fails = |at: u64| {
        index.get(&at).is_some_and(|&at| {
            let end = (at + WINDOW).min(block.len());
            failure_block(&block[at..end])
        })
    };
    for case in &mut cases {
        if let Some(&at) = index.get(&case.lands) {
            let end = (at + WINDOW).min(block.len());
            let window = &block[at..end];
            case.handler = handler_in(window);
            // Rejected if the landing block fails, handled if it reaches a routine, and unknown
            // otherwise -- which is an ordinary outcome and is why this is not a `bool`.
            // **A call is not an acceptance**, which is the trap this three-way answer exists
            // for: the ordinary rejection calls a completion routine too, and reading that as the
            // handler publishes the completion routine as this code's. So `true` needs a routine
            // reached *and* no error status anywhere in the block -- the absence of a visible
            // rejection rather than proof of handling, which is what its documentation says.
            case.accepted = match (failure_block(window), case.handler, error_status(window)) {
                (true, _, _) => Some(false),
                (false, Some(_), false) => Some(true),
                _ => None,
            };
            // And a rejection has no handler to report: what it reaches is the completion routine
            // that refuses the request, and naming that as this code's handler is a name a reader
            // would go and look up.
            if case.accepted == Some(false) {
                case.handler = None;
            }
            let (input, output) = sizes_in(window, layout, &stack_registers, &fails);
            case.in_size = input;
            case.out_size = output;
        }
    }

    Map {
        dispatch,
        // **Every reported case, not any one load.** A routine that compares some other
        // structure's `+0x18` field and later reads the real control code would otherwise have the
        // first case borrow the second's credibility -- and the first is exactly the one a reader
        // needs warning about. With no cases at all this says whether the code was read, which is
        // what makes an empty answer readable.
        code_proved: traced && cases.iter().all(|case| case.proved),
        cases,
        case_count,
        tables,
        unresolved,
        halted,
        cap_hit,
        examined,
        blind,
    }
}

/// Records a case, keeping the count exact once the list stops growing.
#[allow(clippy::too_many_arguments)]
fn push_case(
    cases: &mut Vec<Case>,
    count: &mut usize,
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

/// Applies one instruction to the register state, and reports the compare it leaves behind.
fn update(
    state: &mut HashMap<&'static str, Value>,
    instruction: &Instruction,
    layout: Layout,
    traced: &mut bool,
) -> Option<Compared> {
    let operands = &instruction.operands;
    let mnemonic = instruction.mnemonic.as_str();

    // A compare writes no register and is the only thing a branch reads.
    if mnemonic == "cmp" {
        return compare(state, instruction, layout, traced);
    }
    // `test reg,reg` after a `sub` is the same statement about zero, but every other `test` is a
    // mask; neither makes a case, and both end the compare before them.
    if matches!(mnemonic, "test" | "push" | "nop" | "int" | "ret") {
        return None;
    }

    let Some(destination) = operands.first().and_then(register_of) else {
        // Writes memory, or nothing this models. A store through a register does not change what
        // the register holds, so the state stands.
        return None;
    };

    match mnemonic {
        "mov" | "movzx" | "movsxd" | "movsx" | "lea" => {
            // `lea eax,[r13-6DC004h]` is `sub` without touching the flags, and a compiler uses it
            // exactly where a switch is rebased before a bounds check. Read as an address it is
            // nothing -- there is no absolute in it -- so without this arm the jump table that
            // follows has no index and the whole dense run of codes is lost.
            let rebased = match (mnemonic, operands.get(1)) {
                ("lea", Some(Operand::Memory(memory))) if memory.index.is_none() => {
                    match memory
                        .base
                        .as_deref()
                        .and_then(family)
                        .and_then(|base| state.get(base))
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
            let value =
                rebased.or_else(|| source_value(state, operands.get(1), mnemonic, layout, traced));
            set(state, destination, value);
            None
        }
        "sub" => match (state.get(destination).copied(), operands.get(1)) {
            // `sub eax, 6D0034h` rebases the code: the register now holds `code - (offset + K)`,
            // and the `je` that follows is a case for that value rather than for zero.
            (
                Some(Value::Code {
                    offset,
                    shift,
                    proved,
                }),
                Some(operand),
            ) => {
                let immediate = immediate_of(operand)?;
                let offset = offset.checked_add(immediate as i64)?;
                set(
                    state,
                    destination,
                    Some(Value::Code {
                        offset,
                        shift,
                        proved,
                    }),
                );
                Some(Compared {
                    code: (shift == 0).then_some(offset as u64),
                    index: Some((destination, offset, shift)),
                    bound: Some(0),
                    at: instruction.address,
                    proved,
                })
            }
            _ => {
                set(state, destination, None);
                None
            }
        },
        "add" => {
            match (state.get(destination).copied(), operands.get(1)) {
                (
                    Some(Value::Code {
                        offset,
                        shift,
                        proved,
                    }),
                    Some(operand),
                ) => {
                    let immediate = immediate_of(operand)?;
                    let offset = offset.checked_sub(immediate as i64)?;
                    set(
                        state,
                        destination,
                        Some(Value::Code {
                            offset,
                            shift,
                            proved,
                        }),
                    );
                }
                // An `add` of anything else -- a table entry to its base, most often -- leaves a
                // value this does not model.
                _ => set(state, destination, None),
            }
            None
        }
        "shr" | "sar" => {
            match (state.get(destination).copied(), operands.get(1)) {
                (
                    Some(Value::Code {
                        offset,
                        shift,
                        proved,
                    }),
                    Some(operand),
                ) => {
                    let by = immediate_of(operand)? as u32;
                    set(
                        state,
                        destination,
                        shift.checked_add(by).map(|shift| Value::Code {
                            offset,
                            shift,
                            proved,
                        }),
                    );
                }
                _ => set(state, destination, None),
            }
            None
        }
        _ => {
            set(state, destination, None);
            None
        }
    }
}

/// What a `mov`-shaped instruction's source is worth.
fn source_value(
    state: &HashMap<&'static str, Value>,
    source: Option<&Operand>,
    mnemonic: &str,
    layout: Layout,
    traced: &mut bool,
) -> Option<Value> {
    match source? {
        Operand::Register(name) => state.get(family(name)?).copied(),
        Operand::Memory(memory) => {
            // `lea` takes the address rather than what is at it, which is how a jump table's base
            // reaches a register.
            if mnemonic == "lea" {
                return memory.address.map(Value::Address);
            }
            let base = memory.base.as_deref().and_then(family);
            let held = base.and_then(|base| state.get(base).copied());
            // **A partial read of the control code is not the control code.** `movzx eax,word ptr
            // [rdx+18h]` inspects the function and method bits and nothing above them, so a
            // compare after it is a statement about part of the value; reported as a whole code it
            // invents a device type out of the two bytes nobody read. A `ULONG` field is read four
            // bytes at a time, and anything else at that displacement is refused rather than
            // widened. The same for the two lengths, which are `ULONG`s too.
            let dword = memory.size == Some(4);
            match (held, memory.displacement) {
                (Some(Value::Irp), d) if d == layout.current_stack_location => {
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
                // The fallback the module doc describes: a `+0x18` off a register whose chain was
                // not followed. Believed, because a listing that starts mid-function or a driver
                // that fetches the stack location in a helper would otherwise answer nothing --
                // and `code_proved` stays false, which is where that doubt is carried.
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
    state: &HashMap<&'static str, Value>,
    instruction: &Instruction,
    layout: Layout,
    traced: &mut bool,
) -> Option<Compared> {
    let left = instruction.operands.first()?;
    let right = instruction.operands.get(1);
    let bound = right.and_then(immediate_of);

    // `cmp dword ptr [rdx+18h], 222003h` -- the code compared where it lives, with no register in
    // between, which is what a compiler emits for a small switch.
    if let Operand::Memory(_) = left
        && let Some(Value::Code {
            offset,
            shift,
            proved,
        }) = source_value(state, Some(left), "mov", layout, traced)
        && shift == 0
    {
        return Some(Compared {
            code: bound.map(|value| value.wrapping_add(offset as u64)),
            index: None,
            bound,
            at: instruction.address,
            proved,
        });
    }

    let register = register_of(left)?;
    match state.get(register).copied()? {
        Value::Code {
            offset,
            shift,
            proved,
        } => Some(Compared {
            // A shifted register is an index into a table, not a code: the low bits the shift
            // dropped are not this compare's to claim. The compare is still reported, because it
            // is exactly the bounds check a jump table needs — dropping it here would lose the
            // table's length, which is the one thing that makes a table followable.
            code: match shift {
                0 => bound.map(|value| value.wrapping_add(offset as u64)),
                _ => None,
            },
            index: Some((register, offset, shift)),
            bound,
            at: instruction.address,
            proved,
        }),
        _ => None,
    }
}

/// Forgets what a call or a branch may have changed.
fn clobber(state: &mut HashMap<&'static str, Value>, instruction: &Instruction) {
    if matches!(instruction.flow, Flow::Call(_)) {
        for volatile in VOLATILE {
            state.remove(volatile);
        }
    }
}

/// Sets or clears one register's value.
fn set(state: &mut HashMap<&'static str, Value>, register: &'static str, value: Option<Value>) {
    match value {
        Some(value) => {
            state.insert(register, value);
        }
        None => {
            state.remove(register);
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

/// Follows an indirect jump's table, when every part of it was recovered.
///
/// Returns the table and the `(code, target)` pairs it holds, or `None` for a transfer that is
/// not a table this can resolve — which the caller records as unresolved rather than dropping.
fn follow_table(
    window: &[Instruction],
    jump: &Instruction,
    at: u64,
    bounds: &[Bound],
    state: &HashMap<&'static str, Value>,
    read: &mut impl FnMut(u64, usize) -> Option<Vec<u8>>,
    in_image: &impl Fn(u64) -> bool,
) -> Option<Resolved> {
    // **The load has to feed *this* jump**, which is a question about dataflow and not about
    // proximity. Taking the last scale-4 indexed load in the window instead reads an unrelated
    // array indexed by the same bounded register -- ordinary code, a few instructions before a
    // jump through some other register -- as the switch table, and every dword of that array that
    // happens to resolve inside the image becomes a control code. Worse, the real jump is then not
    // listed as unresolved, so nothing says the switch was missed.
    //
    // So the chain is walked backwards from the jump's own register: `jmp rcx` <- `add rcx,rdx`
    // (an accumulation, so the chain continues through `rcx`) <- `mov ecx,[rdx+rax*4+5B80h]`,
    // which is the load. Anything else writing the register on the way ends it.
    // **The 32-bit form jumps through the table itself**: `jmp dword ptr [table+eax*4]`, with no
    // register in between and the entry an absolute address rather than an offset from the image.
    // Refusing every memory-operand jump left dense switches on exactly the targets `Layout::X86`
    // exists to serve permanently unresolved.
    let ((dword_load, dword_memory), added) = match jump.operands.first() {
        Some(Operand::Memory(memory)) if memory.scale == 4 && memory.index.is_some() => {
            ((jump, memory), None)
        }
        Some(Operand::Register(register)) => {
            let mut wanted = family(register)?;
            let mut found = None;
            let mut added: Option<&'static str> = None;
            for instruction in window.iter().rev() {
                // **Only an instruction that *defines* the register continues the chain.** A
                // `cmp rcx,[base+rax*4+table]` has the register as its first operand and writes
                // nothing but the flags, and reading that as the load turns an unrelated array
                // into a table whenever its dwords resolve inside the image -- while also taking
                // the real jump off the unresolved list, so nothing says the switch was missed.
                if matches!(instruction.mnemonic.as_str(), "cmp" | "test" | "push") {
                    continue;
                }
                let Some(written) = instruction.operands.first().and_then(register_of) else {
                    continue;
                };
                if written != wanted {
                    continue;
                }
                match instruction.operands.get(1) {
                    // The indexed load this whole function is about, and only from an instruction
                    // whose job is to load.
                    Some(Operand::Memory(memory))
                        if memory.scale == 4
                            && memory.index.is_some()
                            && matches!(
                                instruction.mnemonic.as_str(),
                                "mov" | "movzx" | "movsx" | "movsxd"
                            ) =>
                    {
                        found = Some((instruction, memory));
                        break;
                    }
                    // `add rcx,rdx` folds the image base into the entry: the value being followed
                    // is still the one in `rcx`, so the chain continues through the same register.
                    // **Which register was added is recorded**, because that — and not the memory
                    // operand's base — is what execution adds to every entry.
                    Some(Operand::Register(source)) if instruction.mnemonic == "add" => {
                        added = Some(family(source)?);
                        continue;
                    }
                    // A copy: follow the register it came from.
                    Some(Operand::Register(source)) if instruction.mnemonic == "mov" => {
                        wanted = family(source)?;
                    }
                    // Anything else -- an immediate, a different memory shape, an instruction this
                    // does not model -- ends the chain, and with it the claim that this is a table.
                    _ => return None,
                }
            }
            (found?, added)
        }
        _ => return None,
    };
    let table_index = dword_memory.index.as_deref().and_then(family)?;
    // **What an entry means depends on which form this is.** A 64-bit switch holds offsets from
    // the image base the compiler loaded into a register, which is why the same register appears
    // in the load and in the `add` after it. A 32-bit one jumps straight through the table and its
    // entries are whole addresses, so adding anything to them lands nowhere.
    let table = match dword_memory.base.as_deref().and_then(family) {
        Some(base) => match state.get(base).copied() {
            Some(Value::Address(address)) => address,
            _ => return None,
        },
        // An absolute table with no base register at all — the 32-bit shape.
        None => 0,
    }
    .checked_add_signed(dword_memory.displacement)?;
    // **What an entry means is decided by what the code adds to it.** A 64-bit switch folds the
    // image base in with an `add`, so its entries are offsets from *that register's* value; a
    // 32-bit one adds nothing and its entries are whole addresses. Taking the memory operand's
    // base instead agrees with a compiler's own switch, where they are the same register, and
    // disagrees silently with anything else — producing addresses that can still land inside the
    // image and so pass every check after this one.
    let entry_base = match added {
        Some(register) => match state.get(register).copied() {
            Some(Value::Address(address)) => Some(address),
            _ => return None,
        },
        None => None,
    };

    // **Which register the bounds check covered decides the shape, and getting this wrong is how a
    // table reads as eighty-one entries of whatever follows it.** MSVC's dense switch has *two*
    // tables: a byte per index saying which case it is, then a dword per case holding its RVA. It
    // reuses one register for both -- `movzx eax,byte ptr [rdx+rax+5B90h]` overwrites the index
    // with the case number -- so the dword load's index register carries the same *name* as the
    // bounded one and none of its meaning. Matching on the name alone read `mountmgr`'s
    // eighty-one-entry byte map as eighty-one dword entries, and reported a hundred and sixty
    // control codes the driver does not accept.
    //
    // So the byte load is looked for first, and the bound has to belong to *its* index.
    let byte_map = window.iter().rev().find_map(|instruction| {
        let written = instruction.operands.first().and_then(register_of)?;
        if written != table_index {
            return None;
        }
        let Some(Operand::Memory(memory)) = instruction.operands.get(1) else {
            return None;
        };
        // A byte per index, so scale 1 and a size of one byte where the decoder reports it.
        (memory.scale == 1 && memory.size.unwrap_or(1) == 1).then_some(memory)
    });

    let (bound, map) = match byte_map {
        Some(memory) => {
            let index = memory.index.as_deref().and_then(family)?;
            let bound = *bounds.iter().rev().find(|bound| bound.register == index)?;
            let entries = usize::try_from(bound.limit.checked_add(1)?).ok()?;
            if entries == 0 || entries > MAX_TABLE_ENTRIES {
                return None;
            }
            let map_at = table_base(memory, state)?.checked_add_signed(memory.displacement)?;
            (bound, Some((map_at, entries)))
        }
        None => {
            // The one-table shape: the dword table is indexed by the bounded register itself.
            let bound = *bounds
                .iter()
                .rev()
                .find(|bound| bound.register == table_index)?;
            // And nothing may have written that register **between the check and the load**, or
            // the name is all that matches. The byte map above is one such writer; this rules out
            // the rest. Bounded by the compare's own address rather than by a count of
            // instructions, because the window is a slice and the check may be anywhere in it.
            // The 32-bit form's "load" is the jump itself, which is past the window rather than
            // in it: everything here precedes it either way.
            let position = window
                .iter()
                .position(|instruction| instruction.address == dword_load.address)
                .unwrap_or(window.len());
            let overwritten = window[..position].iter().any(|instruction| {
                instruction.address > bound.at
                    && instruction.operands.first().and_then(register_of) == Some(table_index)
            });
            if overwritten {
                return None;
            }
            (bound, None)
        }
    };

    let entries = usize::try_from(bound.limit.checked_add(1)?).ok()?;
    if entries == 0 || entries > MAX_TABLE_ENTRIES {
        return None;
    }

    // The case each index selects: itself in the one-table shape, the byte map's value in the
    // two-table one.
    let cases: Vec<usize> = match map {
        Some((map_at, map_entries)) => read(map_at, map_entries)?
            .into_iter()
            .map(usize::from)
            .collect(),
        None => (0..entries).collect(),
    };
    let dwords = cases.iter().copied().max()?.checked_add(1)?;
    if dwords > MAX_TABLE_ENTRIES {
        return None;
    }
    let bytes = read(table, dwords.checked_mul(4)?)?;
    let rvas = bytes.as_chunks::<4>().0;

    let mut found = Vec::new();
    for (index, case) in cases.iter().enumerate() {
        let entry = u32::from_le_bytes(*rvas.get(*case)?);
        let target = match entry_base {
            Some(base) => base.wrapping_add(u64::from(entry)),
            None => u64::from(entry),
        };
        // **A slot that goes to the default is not a case.** A dense table covers every index
        // between its bounds, and a compiler fills the ones it has no case for with the same block
        // the bounds check jumps to -- so `mountmgr`'s two 81-entry tables hold 21 codes and 60
        // rejections each. Reporting those as codes the driver accepts is the same error as
        // reporting the byte map as addresses, one level up: the answer looks four times richer
        // and is wrong about three quarters of it. The default is the bounds check's own branch
        // target, so this is read off the code rather than inferred from the entries repeating.
        if bound.default == Some(target) {
            continue;
        }
        // **Every entry has to be code in this image, or the table is not this table.** The
        // patterns above are recognised from a handful of instructions, and a shape that matches
        // by accident reads whatever follows the address it computed -- string data, a relocation,
        // the next function's bytes -- and turns it into control codes the driver is reported as
        // accepting. One entry outside the image says the bytes are not a jump table, so the whole
        // table is refused and the jump is recorded as unresolved, which is the honest answer.
        if !in_image(target) {
            return None;
        }
        let code = ((index as u64) << bound.shift).wrapping_add(bound.offset as u64);
        found.push((code, target));
    }
    Some(Resolved {
        table: Table {
            at,
            table,
            entries,
            followed: found.len(),
        },
        cases: found,
        proved: bound.proved,
    })
}

/// The address a table's base register holds, or the absolute one an operand carries.
fn table_base(
    memory: &dbgscope::dbgeng::MemoryOperand,
    state: &HashMap<&'static str, Value>,
) -> Option<u64> {
    match memory.base.as_deref().and_then(family) {
        Some(base) => match state.get(base).copied() {
            Some(Value::Address(address)) => Some(address),
            _ => None,
        },
        // An absolute table with no base register at all -- the 32-bit shape.
        None => memory.address,
    }
}

/// Whether an NTSTATUS **error** value is set anywhere in a block before it leaves.
///
/// The severity field is the signal, not a list of codes: the top two bits set is the definition of
/// an error status, so `STATUS_INVALID_DEVICE_REQUEST`, `STATUS_INVALID_PARAMETER` and
/// `STATUS_BUFFER_TOO_SMALL` all answer without being named. Where it goes does not matter -- a
/// register on the way to a `ret`, or a store into the IRP before a completion call -- because
/// what is being asked is whether this block is refusing the request.
fn error_status(window: &[Instruction]) -> bool {
    for instruction in window {
        if instruction.mnemonic == "mov"
            && let Some(value) = instruction.operands.get(1).and_then(immediate_of)
            && let Ok(value) = u32::try_from(value)
            && value >> 30 == 0b11
        {
            return true;
        }
        // A branch means the block has not finished deciding, and a return means it has.
        if matches!(
            instruction.flow,
            Flow::Branch(_) | Flow::Jmp(_) | Flow::Return | Flow::Unreadable | Flow::Unknown
        ) {
            return false;
        }
    }
    false
}

/// Whether a block is a **failure path**: it sets an NTSTATUS error and returns, with or without
/// completing the IRP on the way out.
///
/// This is the one piece of evidence that says which side of a branch the driver treats as success,
/// and without it neither a case nor a size means what it reads like. `cmp code,N` /
/// `je invalid_request` and `cmp code,N` / `je handler` are the same instructions with opposite
/// meanings; so are `cmp length,20h` / `jne fail` and `cmp length,20h` / `jne handler`.
///
/// **The call is part of the shape rather than the end of it.** The ordinary rejection stores the
/// status into the IRP and calls a completion routine before returning, so a scan that stopped at
/// the first call would see a block that calls something and report the completion routine as this
/// code's handler.
///
/// It says nothing when it says nothing. A failure that jumps to a shared tail answers `false`
/// here, and every caller treats that as "could not tell" rather than as "this is the success
/// path".
fn failure_block(window: &[Instruction]) -> bool {
    let mut status = false;
    for instruction in window {
        if instruction.mnemonic == "mov"
            && let Some(value) = instruction.operands.get(1).and_then(immediate_of)
            && let Ok(value) = u32::try_from(value)
            && value >> 30 == 0b11
        {
            status = true;
        }
        match instruction.flow {
            Flow::Return => return status,
            // A completion call after the status is part of the rejection; one before it is a
            // block doing something else.
            Flow::Call(_) if status => {}
            Flow::Call(_) | Flow::Branch(_) | Flow::Jmp(_) => return false,
            Flow::Unreadable | Flow::Unknown => return false,
            Flow::Fallthrough | Flow::Trap => {}
        }
    }
    false
}

/// The routine a case block reaches directly, when it reaches one.
fn handler_in(window: &[Instruction]) -> Option<u64> {
    for instruction in window {
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
/// Three things have to hold before a compare here is a statement about a buffer at all, and each
/// of them is a way an answer would otherwise be invented.
///
/// **The base must hold the IO_STACK_LOCATION.** A displacement is not a type: `cmp [rsp+10h],20h`
/// is a stack slot, and `[rbx+10h]` is whatever `rbx` is. Only a register this walk watched the
/// stack location reach counts, which is why the set is passed in rather than re-derived here.
///
/// **The region ends at a terminator.** `uf` prints a function's blocks in sequence, so a case
/// that returns before checking anything would otherwise inherit the next sibling case's compare
/// and publish it as its own requirement.
///
/// **Exact means the path continues on equality**, which is `jne` -- the branch leaves on
/// inequality and the case block falls through. `cmp length,0` / `je failure` is the opposite: the
/// continuing path is *not* equal, and reading it as an exact size reports a case that requires a
/// zero-length buffer. So a `je` yields evidence and never a size.
fn sizes_in(
    window: &[Instruction],
    layout: Layout,
    stack_registers: &[&'static str],
    fails: &impl Fn(u64) -> bool,
) -> (Option<SizeCheck>, Option<SizeCheck>) {
    let mut input = None;
    let mut output = None;
    let mut pending: Option<(i64, u32, u64)> = None;
    // **The snapshot is where the case starts, not what it keeps.** The registers holding the IO
    // stack location are read at the top of the dispatch chain, and a case block is free to
    // overwrite one before it compares anything -- `mov rax,<some other pointer>` then
    // `cmp [rax+10h],20h` is a field of some other structure, and a `jne` to a failure block would
    // promote it to an exact input length. So a register stops counting the moment this block
    // writes to it. A block that re-derives the pointer into the same register loses it too, which
    // is the conservative direction: a length check not reported against one invented.
    let mut live: Vec<&'static str> = stack_registers.to_vec();
    for instruction in window {
        // The case's own region ends here, and what follows belongs to the next one.
        if matches!(
            instruction.flow,
            Flow::Return | Flow::Trap | Flow::Jmp(_) | Flow::Unreadable
        ) {
            break;
        }
        // Anything that writes a register retires it, and a compare writes none.
        if !matches!(instruction.mnemonic.as_str(), "cmp" | "test" | "push")
            && let Some(written) = instruction.operands.first().and_then(register_of)
        {
            live.retain(|register| *register != written);
        }
        if instruction.mnemonic == "cmp" {
            pending = None;
            if let Some(Operand::Memory(memory)) = instruction.operands.first()
                && let Some(base) = memory.base.as_deref().and_then(family)
                && live.contains(&base)
                && let Some(value) = instruction.operands.get(1).and_then(immediate_of)
                && let Ok(value) = u32::try_from(value)
            {
                pending = Some((memory.displacement, value, instruction.address));
            }
            continue;
        }
        if let Flow::Branch(target) = instruction.flow {
            if let Some((displacement, value, at)) = pending.take() {
                // **Exact needs both halves.** The mnemonic says equality continues by falling
                // through; it does not say the fall-through is the path that handles the code.
                // `cmp length,20h` / `jne handler` is the same instruction pair with the success
                // on the other edge, and reporting 0x20 there is a requirement the driver does not
                // have. So the branch has to be the one that *leaves*: its target sets an NTSTATUS
                // error and returns. Without that evidence the check is still reported, as
                // evidence rather than as a size.
                let exact = matches!(instruction.mnemonic.as_str(), "jne" | "jnz")
                    && target.is_some_and(fails);
                let check = SizeCheck { value, at, exact };
                match displacement {
                    d if d == layout.input_length => input = input.or(Some(check)),
                    d if d == layout.output_length => output = output.or(Some(check)),
                    _ => {}
                }
            }
            continue;
        }
        // Anything between a compare and its branch invalidates the pairing rather than being
        // assumed harmless.
        if !instruction.operands.is_empty() {
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
            report.cases.iter().filter(|case| !case.proved).count(),
            report.cases.len()
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
    use dbgscope::dbgeng::MemoryOperand;

    const DISPATCH: u64 = 0xfffff803_3e254750;

    /// One instruction, built from what the decoder would report rather than from a rendering:
    /// these tests are about the fields, and a fixture that spelled instructions in text would be
    /// testing a parser this module does not have.
    fn insn(address: u64, mnemonic: &str, operands: Vec<Operand>, flow: Flow) -> Instruction {
        Instruction {
            address,
            bytes: String::new(),
            text: String::new(),
            mnemonic: mnemonic.to_string(),
            operands,
            flow,
            privileged: false,
        }
    }

    fn reg(name: &str) -> Operand {
        Operand::Register(name.to_string())
    }

    fn imm(value: u64) -> Operand {
        Operand::Immediate(value)
    }

    /// `[base+displacement]`.
    fn mem(base: &str, displacement: i64) -> Operand {
        Operand::Memory(MemoryOperand {
            size: Some(4),
            segment: None,
            base: Some(base.to_string()),
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
            base: base.map(str::to_string),
            index: Some(index.to_string()),
            scale: 4,
            displacement,
            address,
        })
    }

    /// A RIP-relative `lea`'s operand: an address and nothing at run time contributing to it.
    fn at_address(address: u64) -> Operand {
        Operand::Memory(MemoryOperand {
            size: None,
            segment: None,
            base: Some("rip".to_string()),
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
                vec![reg("rax"), mem("rdx", 0xb8)],
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

    /// A listing is a rendering of a **graph**, and the blocks after an epilogue are entered with
    /// the control code still in its register.
    ///
    /// `uf` prints a function's blocks one after another, so a straight-line pass carries state
    /// across seams that control flow never crosses. `mountmgr` has a shared epilogue in the middle
    /// of its compare chain -- `pop r13` restoring the caller's register, then `ret` -- and reading
    /// that as the instruction before the next compare loses the control code for the whole rest of
    /// the routine: two of its seven codes were recovered and five were not, which is the failure
    /// this fixture is that driver's shape of.
    ///
    /// The rule is an assumption rather than a proof, and the test says which: the state is
    /// restored to what it was when the code was first loaded, because that is what every block of
    /// one dispatch chain is entered with.
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
            insn(DISPATCH + 0xe, "je", Vec::new(), Flow::Branch(Some(0x900))),
            // The shared epilogue, in the middle of the chain exactly as a compiler emits it.
            insn(DISPATCH + 0x14, "pop", vec![reg("r13")], Flow::Fallthrough),
            insn(DISPATCH + 0x16, "ret", Vec::new(), Flow::Return),
            // A block reached from a branch somewhere else, with the code still in `r13d`.
            insn(
                DISPATCH + 0x17,
                "cmp",
                vec![reg("r13d"), imm(0x222007)],
                Flow::Fallthrough,
            ),
            insn(DISPATCH + 0x1d, "je", Vec::new(), Flow::Branch(Some(0x980))),
            insn(DISPATCH + 0x23, "ret", Vec::new(), Flow::Return),
        ]);

        let found = map(DISPATCH, &block, Layout::X64, unreadable, in_image, never);

        assert_eq!(
            found.cases.iter().map(|case| case.code).collect::<Vec<_>>(),
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
    }

    /// A bounded jump table becomes one case per entry, read out of the image.
    #[test]
    fn a_bounded_jump_table_becomes_a_case_per_entry() {
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
        let table_at = IMAGE.wrapping_add(TABLE as u64);
        let read = |at: u64, len: usize| {
            (at == table_at && len == 12).then(|| {
                [0x1000u32, 0x1100, 0x1200]
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
                .map(|case| (case.code, case.lands, case.recovered))
                .collect::<Vec<_>>(),
            vec![
                (0x6dc004, IMAGE + 0x1000, Recovery::JumpTable),
                (0x6dc008, IMAGE + 0x1100, Recovery::JumpTable),
                (0x6dc00c, IMAGE + 0x1200, Recovery::JumpTable),
            ],
            "the shift is the stride between codes: {:?}",
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
                        base: Some("r13".to_string()),
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
                        base: Some("rdx".to_string()),
                        index: Some("rax".to_string()),
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
                vec![reg("esi"), mem("ebp", 0x0c)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 3,
                "mov",
                vec![reg("edi"), mem("esi", 0x60)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 6,
                "mov",
                vec![reg("eax"), mem("edi", 0x0c)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 9,
                "sub",
                vec![reg("eax"), imm(0x222000)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 0xf,
                "cmp",
                vec![reg("eax"), imm(2)],
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
                vec![indexed(None, "eax", TABLE, None)],
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

    /// A block that completes the IRP with an error status is a **rejection**, call and all.
    ///
    /// This is the ordinary shape of one: the status goes into the IRP, a completion routine is
    /// called, and the routine returns. A scan that stopped at the first call would see a block
    /// that calls something, report `accepted: true`, and publish the completion routine as this
    /// code's handler — which is a reader sent to test a code the driver refuses and a name that
    /// is not the handler's.
    #[test]
    fn a_block_that_completes_with_an_error_status_is_a_rejection() {
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
            // `mov dword ptr [rbx+30h],0C0000010h` -- the status into the IRP.
            insn(
                DISPATCH + 0x40,
                "mov",
                vec![mem("rbx", 0x30), imm(0xc000_0010)],
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
        assert_eq!(found.cases[0].accepted, Some(false), "{:?}", found.cases[0]);
        assert_eq!(
            found.cases[0].handler, None,
            "the completion routine is not this code's handler: {:?}",
            found.cases[0]
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
                    vec![reg("rax"), mem("rdx", 0xb8)],
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
                            base: Some("rax".to_string()),
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
                vec![reg("esi"), mem("ebp", 0x0c)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 3,
                "mov",
                vec![reg("edi"), mem("esi", 0x60)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 6,
                "mov",
                vec![reg("ebx"), mem("edi", 0x0c)],
                Flow::Fallthrough,
            ),
            insn(
                DISPATCH + 9,
                "cmp",
                vec![reg("ebx"), imm(0x222003)],
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
                vec![reg("rax"), mem("rdx", 0xb8)],
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
