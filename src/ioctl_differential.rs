//! An oracle for the IOCTL walk that is not the IOCTL walk.
//!
//! Every rule in [`super::super`] is pinned by a fixture somebody wrote after knowing the answer,
//! which is the one thing such a test cannot do: find a shape nobody thought of. Thirty-nine
//! review findings on the pull request that built that module were all of that kind, every one of
//! them a program state the walk mishandled, and the supply of those is the instruction set rather
//! than anyone's imagination.
//!
//! So this **executes** the routines instead. A small concrete interpreter runs the same
//! instruction list with a control code in the IRP and reports where control actually went; the
//! walk's answer is then checked against it. The property is one-directional, and deliberately:
//!
//! > **Every case the map reports must be one execution produces.**
//!
//! The other direction is not a defect. The map is documented as a lower bound -- a switch it
//! could not follow is reported unresolved rather than guessed at -- so a code the interpreter
//! routes somewhere the map never mentions is the module working as described. What must never
//! happen is the map naming a code, or a destination, that the machine does not agree with.
//!
//! **The interpreter shares no code with the walk**, which is the whole of its value. It reads the
//! same [`Instruction`] values, and everything it does with them -- flags, memory, control flow --
//! is written out again here. A helper reused from the pass under test would agree with that pass
//! about a mistake, which is what these tests exist to stop.

use std::collections::HashMap;

use super::*;

/// Where the fixture's IRP lives, and the stack location it points at.
/// **A kernel address, with bits above the low thirty-two.** A pointer copied four bytes at a
/// time keeps all of an address that fits in four, so an IRP down there would make a narrow copy
/// of one indistinguishable from a whole one and the rule about that untestable.
const IRP: u64 = 0xffff_8000_9000_0000;
const STACK_LOCATION: u64 = 0xffff_8000_9001_0000;

/// A register file and a memory, executing one routine.
///
/// Registers are keyed by the **full-width** name, as the walk's facts are, because that is what a
/// machine has: writing `eax` and reading `rax` is one register on this target. What differs from
/// the walk is that the value is a number rather than a description of one.
struct Machine {
    registers: HashMap<String, u64>,
    /// Dword-addressed memory, which is every width this fixture vocabulary reads except the
    /// pointer at `Irp+0xb8` -- that one is kept whole in [`Self::pointers`].
    memory: HashMap<u64, u32>,
    pointers: HashMap<u64, u64>,
    /// The last compare, as its two values, which is what a conditional branch reads.
    compared: Option<(u64, u64)>,
    /// Instructions executed, so a routine that loops cannot run for ever.
    steps: usize,
}

/// Where a run ended.
#[derive(Debug, PartialEq, Eq)]
enum Ran {
    /// Control reached this address and the run was stopped there, because it is a landing the
    /// map named.
    Reached(u64),
    /// The routine returned.
    Returned,
    /// It ran off the listing, jumped somewhere not in it, or ran too long.
    Lost,
}

impl Machine {
    fn new(code: u32) -> Self {
        let mut memory = HashMap::new();
        memory.insert(STACK_LOCATION + 0x18, code);
        let mut pointers = HashMap::new();
        pointers.insert(IRP + 0xb8, STACK_LOCATION);
        let mut registers = HashMap::new();
        registers.insert("rdx".to_string(), IRP);
        Self {
            registers,
            memory,
            pointers,
            compared: None,
            steps: 0,
        }
    }

    /// Puts the switch table where the routine will read it.
    ///
    /// The walk is handed these bytes through its reader; the machine has to find them in its own
    /// memory, because it really does execute the load.
    fn load_table(&mut self, at: u64, entries: &[u32]) {
        for (index, entry) in entries.iter().enumerate() {
            self.memory.insert(at + (index as u64) * 4, *entry);
        }
    }

    fn get(&self, register: &str) -> u64 {
        self.registers.get(register).copied().unwrap_or(0)
    }

    /// Writes a register at the width the operand names, which is what makes a narrow write
    /// different from a whole one: four bytes zero-extend on this target and two do not.
    fn put(&mut self, register: &RegisterOperand, value: u64) {
        let was = self.get(&register.full);
        let now = match register.width {
            1 => (was & !0xff) | (value & 0xff),
            2 => (was & !0xffff) | (value & 0xffff),
            4 => value & 0xffff_ffff,
            _ => value,
        };
        self.registers.insert(register.full.clone(), now);
    }

    /// The address a memory operand names.
    fn address_of(&self, memory: &MemoryOperand) -> u64 {
        if let Some(address) = memory.address {
            return address;
        }
        let base = memory
            .base
            .as_ref()
            .map(|base| self.get(&base.full))
            .unwrap_or(0);
        let index = memory
            .index
            .as_ref()
            .map(|index| self.get(&index.full))
            .unwrap_or(0);
        base.wrapping_add(index.wrapping_mul(u64::from(memory.scale)))
            .wrapping_add_signed(memory.displacement)
    }

    /// What an operand is worth as a source.
    fn read(&self, operand: &Operand) -> u64 {
        match operand {
            Operand::Register(register) => {
                let whole = self.get(&register.full);
                match register.width {
                    1 => whole & 0xff,
                    2 => whole & 0xffff,
                    4 => whole & 0xffff_ffff,
                    _ => whole,
                }
            }
            Operand::Immediate(value) => *value,
            Operand::Memory(memory) => {
                let at = self.address_of(memory);
                match memory.size {
                    Some(8) => self.pointers.get(&at).copied().unwrap_or(0),
                    Some(1) => u64::from(self.memory.get(&at).copied().unwrap_or(0) & 0xff),
                    _ => u64::from(self.memory.get(&at).copied().unwrap_or(0)),
                }
            }
            Operand::Target(address) => *address,
            _ => 0,
        }
    }

    /// Whether a condition holds against the last compare.
    fn holds(&self, condition: Condition) -> bool {
        let Some((left, right)) = self.compared else {
            return false;
        };
        match condition {
            Condition::Equal => left == right,
            Condition::NotEqual => left != right,
            Condition::UnsignedAbove => left > right,
            Condition::UnsignedAboveOrEqual => left >= right,
            Condition::UnsignedBelow => left < right,
            Condition::UnsignedBelowOrEqual => left <= right,
            _ => false,
        }
    }

    /// Applies one instruction to the machine, reporting nothing: control flow is the caller's.
    fn step(&mut self, instruction: &Instruction) {
        let operands = &instruction.operands;
        let source = operands.get(1).map(|operand| self.read(operand));
        match instruction.effect {
            Effect::Compare => {
                if let (Some(left), Some(right)) = (operands.first(), operands.get(1)) {
                    self.compared = Some((self.read(left), self.read(right)));
                }
                return;
            }
            Effect::Test => {
                if let (Some(left), Some(right)) = (operands.first(), operands.get(1)) {
                    let both = self.read(left) & self.read(right);
                    self.compared = Some((both, 0));
                }
                return;
            }
            _ => {}
        }
        let Some(destination) = operands.first() else {
            return;
        };
        let value = match (instruction.effect, source) {
            (Effect::Move, Some(source)) => source,
            (Effect::MoveSigned, Some(source)) => match operands.get(1) {
                // A dword read sign-extends, which is what makes a table of negative
                // displacements work at all.
                Some(Operand::Memory(memory)) if memory.size == Some(4) => {
                    (source as u32) as i32 as i64 as u64
                }
                _ => source,
            },
            (Effect::LoadAddress, _) => match operands.get(1) {
                Some(Operand::Memory(memory)) => self.address_of(memory),
                _ => return,
            },
            (Effect::Add, Some(source)) => self.read(destination).wrapping_add(source),
            (Effect::Subtract, Some(source)) => self.read(destination).wrapping_sub(source),
            (Effect::ShiftRight, Some(source)) => self.read(destination) >> (source & 63),
            (Effect::ShiftLeft, Some(source)) => self.read(destination) << (source & 63),
            (Effect::BitXor, Some(source)) => self.read(destination) ^ source,
            (Effect::BitAnd, Some(source)) => self.read(destination) & source,
            (Effect::BitOr, Some(source)) => self.read(destination) | source,
            // `xchg`, and everything else this vocabulary contains that the walk does not model.
            (Effect::Other, Some(source)) if instruction.mnemonic == "xchg" => {
                let left = self.read(destination);
                if let Some(Operand::Register(register)) = operands.get(1) {
                    self.put(&register.clone(), left);
                }
                source
            }
            _ => return,
        };
        // Arithmetic sets the flags, and a branch after one reads them. Written out rather than
        // taken from the decoder's `writes_flags`, so that a wrong answer there cannot be
        // agreed with here.
        if matches!(
            instruction.effect,
            Effect::Add | Effect::Subtract | Effect::ShiftRight | Effect::ShiftLeft
        ) {
            self.compared = Some((value, 0));
        }
        match destination {
            Operand::Register(register) => self.put(&register.clone(), value),
            Operand::Memory(memory) => {
                let at = self.address_of(memory);
                match memory.size {
                    Some(8) => {
                        self.pointers.insert(at, value);
                    }
                    _ => {
                        self.memory.insert(at, value as u32);
                    }
                }
            }
            _ => {}
        }
    }

    /// Runs the routine from its first instruction, stopping at any address in `landings`.
    fn run(&mut self, listing: &[Instruction], landings: &[u64]) -> Ran {
        let index: HashMap<u64, usize> = listing
            .iter()
            .enumerate()
            .map(|(at, instruction)| (instruction.address, at))
            .collect();
        let mut at = 0usize;
        loop {
            self.steps += 1;
            if self.steps > 4096 {
                return Ran::Lost;
            }
            let Some(instruction) = listing.get(at) else {
                return Ran::Lost;
            };
            if self.steps > 1 && landings.contains(&instruction.address) {
                return Ran::Reached(instruction.address);
            }
            let next = match instruction.flow {
                Flow::Return => return Ran::Returned,
                Flow::Branch(target) => {
                    match instruction.condition.is_some_and(|c| self.holds(c)) {
                        true => target,
                        false => listing.get(at + 1).map(|next| next.address),
                    }
                }
                Flow::Jmp(Some(target)) => Some(target),
                Flow::Jmp(None) => match instruction.operands.first() {
                    Some(operand) => Some(self.read(operand)),
                    None => return Ran::Lost,
                },
                _ => {
                    self.step(instruction);
                    // **A call returns over the volatile registers**, which is what the walk's own
                    // rule about them is for. Modelled rather than ignored, or the two agree by
                    // both doing nothing and the rule is untested.
                    if matches!(instruction.flow, Flow::Call(_)) {
                        for volatile in ["rax", "rcx", "rdx", "r8", "r9", "r10", "r11"] {
                            self.registers
                                .insert(volatile.to_string(), 0xdead_0000_0000_dead);
                        }
                        // And it leaves the **flags** as it likes, which is why a branch after one
                        // is not reading the compare before it. This machine is one legal callee
                        // among many, and the walk has to be right for every one -- so the one
                        // that clobbers is the one to model.
                        self.compared = None;
                    }
                    listing.get(at + 1).map(|next| next.address)
                }
            };
            let Some(next) = next else {
                return Ran::Lost;
            };
            if landings.contains(&next) {
                return Ran::Reached(next);
            }
            let Some(next) = index.get(&next) else {
                return Ran::Lost;
            };
            at = *next;
        }
    }
}

/// A seeded generator, so a failure names a number that reproduces it.
struct Seed(u64);

impl Seed {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound.max(1)
    }

    fn chance(&mut self, in_: u64) -> bool {
        self.below(in_) == 0
    }
}

/// One generated routine: its listing, the table it reads, and the codes it really handles.
struct Routine {
    listing: Vec<Instruction>,
    table_at: u64,
    entries: Vec<u32>,
    landings: Vec<u64>,
}

/// Instructions that do something the walk has to keep up with, dropped between the parts of a
/// dispatch routine.
///
/// Each is a shape a review finding on #305 was about: a partial write, an exchange writing its
/// second operand, an implicit destination, a call over the volatile registers, a narrow copy.
fn noise(seed: &mut Seed, at: u64) -> Vec<Instruction> {
    let which = seed.below(8);
    let one = |mnemonic: &str, operands: Vec<Operand>, flow: Flow| {
        vec![insn(at, mnemonic, operands, flow)]
    };
    match which {
        0 => one("xchg", vec![reg("rax"), reg("r13")], Flow::Fallthrough),
        1 => one("mov", vec![reg("r13w"), reg("ax")], Flow::Fallthrough),
        2 => one("xor", vec![reg("ecx"), reg("ecx")], Flow::Fallthrough),
        3 => one(
            "call",
            vec![Operand::Target(0x5000)],
            Flow::Call(Some(0x5000)),
        ),
        4 => one("mov", vec![reg("ecx"), reg("r13d")], Flow::Fallthrough),
        5 => one("add", vec![reg("r8d"), imm(1)], Flow::Fallthrough),
        6 => one(
            "sub",
            vec![reg("r13w"), imm(1 + seed.below(8))],
            Flow::Fallthrough,
        ),
        _ => Vec::new(),
    }
}

/// Builds a dispatch routine: a prologue, a compare chain, and sometimes a switch.
/// The prologue: the stack location out of the IRP and the control code out of that, sometimes
/// through a copy of the IRP first -- whole, or **four bytes of one**, which is a pointer a
/// register no longer holds.
fn opening(seed: &mut Seed) -> Vec<Instruction> {
    let through = match seed.below(3) {
        0 => ("rbx", "rdx"),
        1 => ("ebx", "edx"),
        _ => return prologue(DISPATCH),
    };
    vec![
        insn(
            DISPATCH,
            "mov",
            vec![reg(through.0), reg(through.1)],
            Flow::Fallthrough,
        ),
        insn(
            DISPATCH + 1,
            "mov",
            vec![reg("rax"), pointer("rbx", 0xb8)],
            Flow::Fallthrough,
        ),
        insn(
            DISPATCH + 4,
            "mov",
            vec![reg("r13d"), mem("rax", 0x18)],
            Flow::Fallthrough,
        ),
    ]
}

fn routine(seed: &mut Seed) -> Routine {
    // The chain's codes and the switch's, which do **not** overlap. A compiler emits one or the
    // other for a given code, and the property here is end to end: executing the routine with a
    // code has to reach the landing the map named for it. Two sites recognising one code makes
    // that ill-posed rather than false -- the map reports a case per **site**, which is its
    // documented answer, and the chain would simply catch the code before the switch saw it.
    const BASE: u64 = 0x6d0000;
    const SWITCHED: u64 = 0x6dc000;
    let mut listing = opening(seed);
    let mut at = DISPATCH + 8;
    let mut landings = Vec::new();
    let mut land = DISPATCH + 0x800;

    // Noise between the load and the first compare, which is where a value has to survive.
    for _ in 0..seed.below(3) {
        listing.extend(noise(seed, at));
        at += 8;
    }

    // A compare chain. Sometimes rebased first, which is the `sub eax,K` form.
    let rebase = seed.chance(3);
    // Distinct, because a code two sites recognise is a case per **site** -- the map's documented
    // answer -- while execution takes the first of them, and the end-to-end property here cannot
    // be stated about a routine like that.
    let mut already: Vec<u64> = Vec::new();
    let mut compared = "r13d";
    if rebase {
        listing.push(insn(
            at,
            "mov",
            vec![reg("eax"), reg("r13d")],
            Flow::Fallthrough,
        ));
        at += 8;
        listing.push(insn(
            at,
            "sub",
            vec![reg("eax"), imm(BASE)],
            Flow::Fallthrough,
        ));
        at += 8;
        compared = "eax";
    }
    for _ in 0..seed.below(4) {
        // Spread across the low sixteen bits rather than counting from zero: narrow arithmetic on
        // a code differs from the whole-width kind only when it **borrows**, and a code ending in
        // small digits never does.
        // Biased to the boundary a quarter of the time: narrow arithmetic on a code differs from
        // the whole-width kind only when it **borrows**, which needs the low sixteen bits within a
        // few of `0xffff`, and a uniform draw reaches that about once in eight thousand.
        let offset = match seed.chance(4) {
            true => 0xfff0 + seed.below(0x10),
            false => seed.below(0x2_0000),
        };
        let code = match rebase {
            true => offset,
            false => BASE + offset,
        };
        if already.contains(&code) {
            continue;
        }
        already.push(code);
        listing.push(insn(
            at,
            "cmp",
            vec![reg(compared), imm(code)],
            Flow::Fallthrough,
        ));
        at += 8;
        // Noise between the compare and its branch, which a compiler really does emit.
        if seed.chance(3) {
            listing.extend(noise(seed, at));
            at += 8;
        }
        listing.push(insn(at, "je", Vec::new(), Flow::Branch(Some(land))));
        at += 8;
        landings.push(land);
        land += 0x20;
    }

    // And sometimes a switch, bounded, through a table in the image.
    let mut table_at = 0;
    let mut entries = Vec::new();
    if seed.chance(2) {
        let limit = 1 + seed.below(3);
        table_at = IMAGE_BASE + 0x9000;
        listing.extend([
            insn(at, "mov", vec![reg("eax"), reg("r13d")], Flow::Fallthrough),
            insn(
                at + 8,
                "sub",
                vec![reg("eax"), imm(SWITCHED)],
                Flow::Fallthrough,
            ),
            insn(
                at + 16,
                "cmp",
                vec![reg("eax"), imm(limit)],
                Flow::Fallthrough,
            ),
            insn(
                at + 24,
                "ja",
                Vec::new(),
                Flow::Branch(Some(DISPATCH + 0xf00)),
            ),
        ]);
        at += 32;
        if seed.chance(3) {
            listing.extend(noise(seed, at));
            at += 8;
        }
        listing.extend([
            insn(
                at,
                "lea",
                vec![reg("rcx"), at_address(IMAGE_BASE)],
                Flow::Fallthrough,
            ),
            insn(
                at + 8,
                "mov",
                vec![reg("eax"), indexed(Some("rcx"), "rax", 0x9000, None)],
                Flow::Fallthrough,
            ),
            insn(
                at + 16,
                "add",
                vec![reg("rax"), reg("rcx")],
                Flow::Fallthrough,
            ),
            insn(at + 24, "jmp", vec![reg("rax")], Flow::Jmp(None)),
        ]);
        at += 32;
        for index in 0..=limit {
            let rva = (land - IMAGE_BASE) as u32;
            entries.push(rva);
            landings.push(land);
            land += 0x20;
            let _ = index;
        }
    }

    listing.push(insn(at, "ret", Vec::new(), Flow::Return));
    // Every landing is a block that calls something and returns, so the walk has a handler to
    // find and the machine has somewhere to stop.
    for landing in &landings {
        listing.push(insn(
            *landing,
            "call",
            vec![Operand::Target(0x7000)],
            Flow::Call(Some(0x7000)),
        ));
        listing.push(insn(landing + 8, "ret", Vec::new(), Flow::Return));
    }
    listing.push(insn(
        DISPATCH + 0xf00,
        "mov",
        vec![reg("eax"), imm(0xc000_0010)],
        Flow::Fallthrough,
    ));
    listing.push(insn(DISPATCH + 0xf08, "ret", Vec::new(), Flow::Return));
    listing.sort_by_key(|instruction| instruction.address);

    Routine {
        listing,
        table_at,
        entries,
        landings,
    }
}

/// **Every case the map reports is one execution produces.**
///
/// The map is a lower bound by construction -- a transfer it could not follow is reported rather
/// than guessed at -- so a code the machine routes somewhere the map never mentions is the module
/// working as described, and is not asserted. What is asserted is the direction every one of the
/// review findings on #305 was about: a case named for a code that does not reach it, or reaches
/// somewhere else.
///
/// **What it catches, measured by breaking the rules one at a time** (2026-09-12). Each of these is
/// a rule a review round on #305 added, and with it removed this test fails:
///
/// * a partial write leaves something that is not the value (`sub r13w,N`),
/// * an instruction this pass does not model may write more than its first operand (`xchg`),
/// * a call returns over the volatile registers,
/// * a call leaves the flags as it likes, so a branch after one is not reading the compare before.
///
/// Two more were tried and are **not** reached from here, for reasons worth knowing rather than
/// fixing by contorting the generator. Removing the copy-width rule in `source_value` changes
/// nothing, because the destination-width filter in `update` refuses the same thing one step later
/// -- for a register-to-register move the two widths are equal, so the guards overlap by
/// construction. And removing the pointer-width check on the stack-location load needs a **narrow
/// read** of `[Irp+0xb8]`, which this vocabulary does not emit. Both are covered by fixtures.
#[test]
fn every_case_the_map_reports_is_one_the_machine_produces() {
    let mut checked = 0usize;
    let mut tables = 0usize;
    for seed in 0..512u64 {
        let mut seed_state = Seed(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let built = routine(&mut seed_state);
        let entries = built.entries.clone();
        let table_at = built.table_at;
        let read = |at: u64, len: usize| {
            (table_at != 0 && at == table_at).then(|| {
                entries
                    .iter()
                    .flat_map(|rva| rva.to_le_bytes())
                    .take(len)
                    .collect()
            })
        };

        let found = map(DISPATCH, &built.listing, Layout::X64, read, in_image, never);

        tables += found.tables.len();
        for case in &found.cases {
            // **Only a proved case is a claim about this routine.** An unproved one was read off a
            // bare `+0x18` displacement off a register whose chain this could not follow, and the
            // module says in as many words that such a map may be about another structure
            // entirely -- so holding it to what execution does here would be asserting something
            // it declines to say.
            if !case.proved {
                continue;
            }
            checked += 1;
            let mut machine = Machine::new(case.code);
            machine.load_table(built.table_at, &built.entries);
            let ran = machine.run(&built.listing, &built.landings);
            assert_eq!(
                ran,
                Ran::Reached(case.lands),
                "seed {seed}: the map says code {:#x} reaches {:#x}, and running the routine with \
                 that code does not.\nlisting:\n{}",
                case.code,
                case.lands,
                built
                    .listing
                    .iter()
                    .map(|i| format!("  {:#x} {} {:?}", i.address, i.mnemonic, i.flow))
                    .collect::<Vec<_>>()
                    .join("\n")
            );
        }
    }
    // **A green run has to mean something was run.** These routines are generated, so a change to
    // the vocabulary or the seeds could quietly stop producing cases and leave this test passing
    // over nothing. Measured at 884 cases over 135 resolved tables on 512 seeds (2026-09-12); the
    // floors are well under that and are here to catch a collapse rather than to pin a number.
    assert!(
        checked > 500 && tables > 50,
        "the generator stopped producing routines worth checking: {checked} cases, {tables} tables"
    );
}
