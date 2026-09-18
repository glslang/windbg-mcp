//! What a driver's code can *do*, read off the image rather than off its behaviour.
//!
//! Two questions, and both are answered from facts rather than from heuristics. **Which sensitive
//! APIs does it import, and where is each called from** — named through the import table, so a
//! stripped third-party driver answers as well as one with a PDB. And **which privileged
//! instructions does it contain** — `rdmsr`, `out`, `mov cr3`, the ones a driver is the only thing
//! that can execute, taken from the **decoder's** own answer rather than from a list of mnemonics
//! somebody remembered, which is a list that always omits `cli`.
//!
//! # What this is not
//!
//! It is not a taint analysis and does not claim to be. There is no decompiler here, so "this
//! driver copies a user buffer without probing it" is not a question this can answer; what it can
//! say is that the driver imports `memcpy` and `ProbeForRead`, and where each is called. A reader
//! draws the conclusion, with the call sites to check it against.
//!
//! Three consequences a caller has to hold on to:
//!
//! - **An import is not a call.** A driver importing `MmMapIoSpace` may never reach it, and this
//!   reports the call sites it found rather than asserting reachability. Ask
//!   `reachable_from_dispatch` about a specific one.
//! - **An absent import excludes nothing.** A driver can resolve an export at run time through
//!   `MmGetSystemRoutineAddress`, which leaves no import-table entry — so this is evidence of
//!   what a driver *does* hold, never of what it cannot do.
//! - **The list is a judgement, and it is versioned.** What counts as sensitive is a curated
//!   opinion, so the result carries the version of the list it was scanned with, and a result
//!   quoted somewhere can be checked against the list it came from.
//!
//! # Engine-free
//!
//! Like [`dbgscope::pe`] and [`crate::driver`], every entry point takes closures rather than a
//! `DebugEngine`: one to decode a range of instructions, one to ask whether to stop. The worker
//! supplies the two that touch DbgEng; the tests supply fixtures.

use std::collections::{BTreeMap, HashMap};

use dbgscope::dbgeng::{Effect, Flow, Instruction, InstructionSet, Operand};

use crate::walk::Halt;
use dbgscope::pe;

/// The version of the sink list a scan was taken with.
///
/// **Carried in every result**, because what counts as a sensitive API is a curated opinion rather
/// than a fact about Windows: a result quoted in a report six months from now can be checked
/// against the list that produced it. Bump it whenever [`SINKS`] changes at all — an addition
/// changes what a scan finds as surely as a removal does.
pub const SINK_LIST_VERSION: &str = "2";

/// Why an import is worth reporting.
///
/// The category is the useful half. "This driver imports `MmMapIoSpace`" means little on its own;
/// "it can map physical memory" is what a reader acts on, and it is what makes two drivers
/// comparable without knowing either API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SinkKind {
    /// Moves bytes between buffers. The other end of an IOCTL's user buffer, when there is one.
    BufferCopy,
    /// Validates a user-mode pointer before it is touched. Its **presence** near a copy is the
    /// evidence that the copy was considered; its absence is not proof of anything.
    UserPointerGuard,
    /// Allocates, which is where an attacker-controlled size lands.
    Allocation,
    /// Checked arithmetic, the guard for the size that reaches an allocation.
    ArithmeticGuard,
    /// Reaches physical memory or maps it somewhere a user can see.
    PhysicalMemory,
    /// Reaches another process, its handles or its token.
    ProcessAccess,
    /// Reaches the file system or the registry with the driver's own authority.
    Persistence,
    /// Asks whether the caller is allowed to do this. Its absence in a driver that does any of the
    /// above is the classic finding; its presence is not a guarantee it is asked at the right time.
    AccessCheck,
}

impl SinkKind {
    /// A short label for a rendering, and the `snake_case` a typed result carries.
    pub fn name(self) -> &'static str {
        match self {
            Self::BufferCopy => "buffer_copy",
            Self::UserPointerGuard => "user_pointer_guard",
            Self::Allocation => "allocation",
            Self::ArithmeticGuard => "arithmetic_guard",
            Self::PhysicalMemory => "physical_memory",
            Self::ProcessAccess => "process_access",
            Self::Persistence => "persistence",
            Self::AccessCheck => "access_check",
        }
    }
}

/// The curated list: an exported name, and why it is here.
///
/// **Matched exactly**, not by prefix or substring. A prefix rule would fold `ExAllocatePool2`
/// into `ExAllocatePool` — which is wanted — and `MmProbeAndLockProcessPages` into
/// `MmProbeAndLockPages`, which is a different API with a different argument, and reporting one as
/// the other is a wrong answer rather than a broad one. Every variant that matters is listed.
///
/// Kept small on purpose. Every entry is one a driver-security reviewer would look for by hand,
/// and a list long enough to bury those is a list nobody reads.
pub const SINKS: &[(&str, SinkKind)] = &[
    // Copies. `memcpy` and `RtlCopyMemory` are the same routine to the linker, and both spellings
    // appear in real import tables.
    ("memcpy", SinkKind::BufferCopy),
    ("memmove", SinkKind::BufferCopy),
    ("RtlCopyMemory", SinkKind::BufferCopy),
    ("RtlMoveMemory", SinkKind::BufferCopy),
    ("RtlCopyMemoryNonTemporal", SinkKind::BufferCopy),
    ("MmCopyMemory", SinkKind::BufferCopy),
    ("MmCopyVirtualMemory", SinkKind::BufferCopy),
    // The guards for a user pointer.
    ("ProbeForRead", SinkKind::UserPointerGuard),
    ("ProbeForWrite", SinkKind::UserPointerGuard),
    ("MmProbeAndLockPages", SinkKind::UserPointerGuard),
    // Allocation, where a controlled size lands.
    ("ExAllocatePool", SinkKind::Allocation),
    ("ExAllocatePool2", SinkKind::Allocation),
    ("ExAllocatePool3", SinkKind::Allocation),
    ("ExAllocatePoolWithTag", SinkKind::Allocation),
    ("ExAllocatePoolWithQuotaTag", SinkKind::Allocation),
    ("MmAllocateContiguousMemory", SinkKind::Allocation),
    ("MmAllocateNonCachedMemory", SinkKind::Allocation),
    // The arithmetic that is supposed to guard it.
    ("RtlULongAdd", SinkKind::ArithmeticGuard),
    ("RtlULongMult", SinkKind::ArithmeticGuard),
    ("RtlULongLongMult", SinkKind::ArithmeticGuard),
    ("RtlSizeTAdd", SinkKind::ArithmeticGuard),
    ("RtlSizeTMult", SinkKind::ArithmeticGuard),
    // Physical memory, and the mappings that hand it out.
    ("MmMapIoSpace", SinkKind::PhysicalMemory),
    ("MmMapIoSpaceEx", SinkKind::PhysicalMemory),
    ("MmGetPhysicalAddress", SinkKind::PhysicalMemory),
    ("MmMapLockedPages", SinkKind::PhysicalMemory),
    ("MmMapLockedPagesSpecifyCache", SinkKind::PhysicalMemory),
    ("ZwMapViewOfSection", SinkKind::PhysicalMemory),
    ("ZwOpenSection", SinkKind::PhysicalMemory),
    // Another process, its handles, its token.
    ("PsLookupProcessByProcessId", SinkKind::ProcessAccess),
    ("ObReferenceObjectByHandle", SinkKind::ProcessAccess),
    ("ObOpenObjectByPointer", SinkKind::ProcessAccess),
    ("ZwOpenProcess", SinkKind::ProcessAccess),
    ("ZwOpenProcessToken", SinkKind::ProcessAccess),
    ("ZwDuplicateObject", SinkKind::ProcessAccess),
    ("KeStackAttachProcess", SinkKind::ProcessAccess),
    ("PsSetCreateProcessNotifyRoutine", SinkKind::ProcessAccess),
    // The file system and the registry, reached with the driver's authority.
    ("ZwCreateFile", SinkKind::Persistence),
    ("ZwWriteFile", SinkKind::Persistence),
    ("ZwDeleteFile", SinkKind::Persistence),
    ("ZwSetValueKey", SinkKind::Persistence),
    ("ZwCreateKey", SinkKind::Persistence),
    ("IoCreateSymbolicLink", SinkKind::Persistence),
    // **The numbered variant, which is what a current driver actually imports.** `mountmgr`
    // on 26100 uses `IoCreateSymbolicLink2` and nothing else, so a list holding only the
    // original reported that driver as creating no symbolic link at all -- found by running
    // Driver Buddy Revolutions over the same image and reading its import table directly.
    // The allocators already carry their numbered forms; this one had been missed.
    ("IoCreateSymbolicLink2", SinkKind::Persistence),
    // Asking whether any of it is allowed.
    ("SeAccessCheck", SinkKind::AccessCheck),
    ("SePrivilegeCheck", SinkKind::AccessCheck),
    ("SeSinglePrivilegeCheck", SinkKind::AccessCheck),
    ("ZwQueryInformationToken", SinkKind::AccessCheck),
];

/// Whether an imported name is on the list, and why.
fn sink_kind(name: &str) -> Option<SinkKind> {
    SINKS
        .iter()
        .find(|(sink, _)| *sink == name)
        .map(|(_, kind)| *kind)
}

/// What a privileged instruction does, which is what a reader wants rather than its mnemonic.
///
/// **A family, not the membership test.** Whether an instruction belongs in the report at all is
/// the decoder's answer; this only says which family it lands in. [`Self::Other`] is what makes
/// that split safe: an instruction no family names is reported under its own mnemonic rather than
/// dropped, which is the failure a hand-written list has by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PrivilegeKind {
    /// Reads or writes a model-specific register.
    ModelSpecificRegister,
    /// Reads or writes an I/O port.
    PortIo,
    /// Reads or writes a control or debug register.
    ControlRegister,
    /// Touches a descriptor table — the GDT, IDT, LDT or task register.
    DescriptorTable,
    /// Halts, invalidates caches, or otherwise reaches into the machine's state.
    MachineState,
    /// Sets or clears the interrupt flag.
    InterruptFlag,
    /// A hardware-virtualisation operation — the VMX and SVM families.
    Virtualization,
    /// Privileged, and in none of the families above. The mnemonic beside it is the answer.
    Other,
}

impl PrivilegeKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::ModelSpecificRegister => "model_specific_register",
            Self::PortIo => "port_io",
            Self::ControlRegister => "control_register",
            Self::DescriptorTable => "descriptor_table",
            Self::MachineState => "machine_state",
            Self::InterruptFlag => "interrupt_flag",
            Self::Virtualization => "virtualization",
            Self::Other => "other",
        }
    }
}

/// The instruction's privilege: **the decoder's answer**, with the family read off its mnemonic
/// and operands.
///
/// Membership used to be the table below, and a table is wrong by construction — a driver holding
/// `cli`, `clts`, `lmsw` or a VMX operation was reported as containing no privileged instructions,
/// which is the one answer this must never arrive at through omission. `dbgscope` now carries
/// `privileged` beside the flow, generated from the instruction set rather than remembered, so
/// nothing here decides *whether*.
///
/// What the table still decides is *which family*, and it carries a few instructions the decoder
/// calls **unprivileged** on purpose: `sgdt`, `sidt`, `sldt` and `str` read the descriptor tables
/// from user mode, and a driver doing that is worth seeing. So the answer is the union of the two,
/// and a mnemonic missing from the table now costs a family name — [`PrivilegeKind::Other`] —
/// rather than a finding.
///
/// `mov cr3, rax` and `mov rax, rbx` share a mnemonic, so the control-register case is decided by
/// an operand being a control or debug register — which is a field here, not a substring of a
/// printed line.
fn privilege_kind(instruction: &Instruction, set: InstructionSet) -> Option<PrivilegeKind> {
    let control_register = || {
        instruction.operands.iter().any(|operand| match operand {
            Operand::Register(register) => {
                let name = register.name.as_str();
                (name.starts_with("cr") || name.starts_with("dr"))
                    && name[2..].chars().all(|c| c.is_ascii_digit())
                    && name.len() > 2
            }
            _ => false,
        })
    };
    // `DAIF`, by each of the three ways it is written: the two processor-state fields, and the
    // system register itself -- `s3_3_c4_c2_1`, which is `op0` 3, `op1` 3, `CRn` 4, `CRm` 2,
    // `op2` 1. The neighbouring `..._0` is `NZCV` and is EL0's own, so the last field is the whole
    // distinction and matching it loosely would call every flag restore an interrupt mask.
    let interrupt_mask = || {
        instruction.operands.iter().any(|operand| match operand {
            Operand::Other(name) => {
                matches!(name.as_str(), "daifset" | "daifclr" | "s3_3_c4_c2_1")
            }
            _ => false,
        })
    };
    // **A family table is one architecture's vocabulary, and the namespaces collide.** x86's
    // `str` stores the task register and belongs to the descriptor tables; A64's `str` stores a
    // register and is among the commonest instructions in any image. Matched on the name alone, a
    // scan of an ARM64 `nt` reported **every store** as a descriptor-table access: 897 in the
    // listed sample and 59,450 privileged instructions in all, which is a disassembly rather than
    // a hazard report.
    //
    // Found by the debugger tier against a real ARM64 image, and nothing built from x86 fixtures
    // could have shown it -- the two namespaces are *mostly* disjoint, which is the worst way for
    // them to be, since it is one collision rather than a wholesale mismatch that would have been
    // obvious. So the table is now chosen by the target rather than searched across all of them.
    //
    // An architecture with no table here keeps `Other` for anything the decoder calls privileged,
    // which is what makes the split safe: it loses family names and loses no findings.
    let family = match set {
        InstructionSet::Arm64 => arm64_family(instruction, interrupt_mask),
        InstructionSet::X86 | InstructionSet::Amd64 => x86_family(instruction, control_register),
        InstructionSet::Other(_) => None,
    };
    match (family, instruction.privileged) {
        (Some(kind), _) => Some(kind),
        (None, true) => Some(PrivilegeKind::Other),
        (None, false) => None,
    }
}

/// The x86 and x64 families, by mnemonic and -- where a mnemonic does not settle it -- by operand.
fn x86_family(
    instruction: &Instruction,
    control_register: impl Fn() -> bool,
) -> Option<PrivilegeKind> {
    match instruction.mnemonic.as_str() {
        "rdmsr" | "wrmsr" => Some(PrivilegeKind::ModelSpecificRegister),
        "in" | "out" | "insb" | "insw" | "insd" | "outsb" | "outsw" | "outsd" => {
            Some(PrivilegeKind::PortIo)
        }
        "mov" if control_register() => Some(PrivilegeKind::ControlRegister),
        // Both write CR0 without naming it in an operand.
        "clts" | "lmsw" => Some(PrivilegeKind::ControlRegister),
        "lgdt" | "lidt" | "lldt" | "ltr" | "sgdt" | "sidt" | "sldt" | "str" => {
            Some(PrivilegeKind::DescriptorTable)
        }
        "hlt" | "invd" | "wbinvd" | "invlpg" | "invpcid" | "swapgs" | "xsetbv" | "rdpmc" => {
            Some(PrivilegeKind::MachineState)
        }
        "cli" | "sti" => Some(PrivilegeKind::InterruptFlag),
        "vmlaunch" | "vmresume" | "vmxon" | "vmxoff" | "vmread" | "vmwrite" | "vmptrld"
        | "vmptrst" | "vmclear" | "invept" | "invvpid" | "vmrun" | "vmload" | "vmsave" | "clgi"
        | "stgi" | "skinit" => Some(PrivilegeKind::Virtualization),
        _ => None,
    }
}

/// The A64 families.
///
/// Deliberately short. Every member is `privileged` from the decoder already, so this decides only
/// the family *name* -- without it they were reported correctly and namelessly under
/// [`PrivilegeKind::Other`], which is the state ARM64 was in the day dbgscope#170 landed. Adding a
/// name is worth doing; inventing one is not, which is why the system-register space past the
/// interrupt masks is deliberately absent.
fn arm64_family(
    instruction: &Instruction,
    interrupt_mask: impl Fn() -> bool,
) -> Option<PrivilegeKind> {
    match instruction.mnemonic.as_str() {
        // Cache, TLB and address-translation maintenance: the same family as `invd`/`wbinvd`/
        // `invlpg`, and where an ARM64 driver's machine-state work lives.
        "dc" | "ic" | "tlbi" | "at" => Some(PrivilegeKind::MachineState),
        // `msr daifset,#2` masks interrupts and `msr daifclr,#2` unmasks them, which is `cli` and
        // `sti` under another spelling; `DAIF` reached as a *register* is the same gate, and
        // dbgscope spells a system register by its encoding rather than by name. The rest of that
        // space lands in `Other` **with its register still in the operands**, which is a better
        // answer than a family invented for it.
        "msr" | "mrs" if interrupt_mask() => Some(PrivilegeKind::InterruptFlag),
        _ => None,
    }
}

/// One sensitive import the driver holds, and where it is called from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sink {
    pub library: String,
    pub name: String,
    pub kind: SinkKind,
    /// The IAT slots calls to it go through — the coordinates a call site is matched by.
    ///
    /// **A list, and almost always of one.** A linker emits an import once per library, so a real
    /// image has exactly one slot here; more than one means the import table repeats a name, which
    /// a crafted image can do and a real one does not. Bounded like everything else the answer
    /// carries, with [`Self::slot_count`] exact beside it.
    pub slots: Vec<u64>,
    /// How many slots carry this name in this library, exact however many are listed.
    pub slot_count: usize,
    /// The call sites found, in address order, **up to [`MAX_CALL_SITES_PER_SINK`]**. A sample
    /// rather than the list when [`Self::call_site_count`] is larger.
    ///
    /// **Empty is not "never called"**: an indirect call through a stored pointer, or a call in
    /// code this scan did not reach, leaves nothing here.
    pub call_sites: Vec<u64>,
    /// How many call sites the scan found, which is exact however many are listed above.
    ///
    /// The count is the fact and the list is a sample, which is the split `modules` makes between
    /// `matched` and its rows. Capping the list without carrying the count would report a driver
    /// that calls an allocator six hundred times as one that calls it two hundred and fifty-six.
    pub call_site_count: usize,
}

/// One privileged instruction, and what it reaches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Privileged {
    pub address: u64,
    pub kind: PrivilegeKind,
    /// The mnemonic, for a reader who wants to know which of the family it was.
    pub mnemonic: String,
}

/// One executable range this scan covered, so a caller can see what it did *not*.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scanned {
    pub section: String,
    pub start: u64,
    /// Bytes decoded. Less than the section's size means the scan stopped inside it — the byte cap
    /// or a halt — and the report says which.
    pub bytes: u64,
}

/// What a scan found, and how much of the image it looked at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scan {
    pub sinks: Vec<Sink>,
    /// The privileged instructions found, in address order, up to [`MAX_PRIVILEGED`].
    pub privileged: Vec<Privileged>,
    /// How many were found, which is exact however many are listed above.
    pub privileged_count: usize,
    pub scanned: Vec<Scanned>,
    /// Executable ranges that were **not** decoded, and therefore say nothing: bytes that would
    /// not read, and any part of a section whose declared span ran past the image.
    ///
    /// Separate from [`Self::halted`] and [`Self::cap_hit`] because it is a different fact with a
    /// different remedy — the scan ran to the end and part of the code was simply not there. Left
    /// silent, a dump missing one page reports a driver with no privileged instructions and
    /// nothing anywhere says a page was missing.
    pub unreadable: Vec<Scanned>,
    /// Imports this driver holds that are **not** on the list, counted rather than listed: the
    /// number is what says whether a short `sinks` means a small driver or a narrow list.
    pub other_imports: usize,
    /// Libraries whose imports could not be named at all, carried through from the import table.
    pub unnamed_libraries: Vec<String>,
    /// Why the scan stopped early, when it did.
    pub halted: Option<Halt>,
    /// True when the byte cap stopped it rather than the code running out.
    pub cap_hit: bool,
}

/// **Every list this answer carries is bounded, and every count beside it is exact.**
///
/// Stated once because it was arrived at three times: a byte cap that bounds the *work* bounds
/// nothing about the *answer*, and each list found its own way to be enormous — four million
/// privileged instructions inside the byte cap, six hundred call sites through one slot, half a
/// million sink records from an import table that repeats a name. The rule that ends the class is
/// that a list is capped and a count is not, so a bounded answer always says how much of one it is.
///
/// The sinks themselves need no number: keyed by library and name they are bounded by the curated
/// list, which is the difference between a limit and an arbitrary one.
///
/// **A per-group cap is not a bound**, which is the correction this rule needed after it was first
/// written. The call sites were capped per sink, and sixty-four libraries times forty-seven names
/// is three thousand sinks — so the product of two limits was three quarters of a million
/// locations, every one of them attributed and serialized. Where a list is per-group the groups
/// share a total, and the per-group cap is then only there to stop one group taking all of it.
///
/// The most call sites listed for one sink, and the most privileged instructions listed at all.
///
/// **The byte cap bounds the work; these bound the answer, and the two are different budgets.**
/// Four megabytes of one-byte `hlt` is within the byte cap and would be four million findings —
/// each one attributed through an engine call and serialized into the reply, which is a worker
/// that stalls or dies while analysing an untrusted driver. Both are far past what a real driver
/// produces (`mountmgr`: eighty-four call sites in total, no privileged instructions), so what
/// they prevent is the absurd rather than the large. The exact counts travel beside the lists, so
/// a capped answer says how much it is a sample of.
pub const MAX_CALL_SITES_PER_SINK: usize = 256;
/// The total across every sink. See [`MAX_CALL_SITES_PER_SINK`]: the per-sink cap keeps one name
/// from taking the whole budget, and this is what actually bounds the answer.
pub const MAX_CALL_SITES_TOTAL: usize = 4096;
/// See [`MAX_CALL_SITES_PER_SINK`].
pub const MAX_PRIVILEGED: usize = 1024;
/// See [`MAX_CALL_SITES_PER_SINK`]. One in every real image; more means a repeated name.
pub const MAX_SLOTS_PER_SINK: usize = 16;
/// See [`MAX_CALL_SITES_PER_SINK`]. Both lists are bounded by the byte cap and the section count
/// already; this keeps a pathological section table from turning that into thousands of rows.
pub const MAX_RANGES: usize = 256;

/// The most code one scan will decode, in bytes.
///
/// A driver's executable sections are tens to hundreds of kilobytes; this is well past that and is
/// there to bound the absurd — a caller pointing this at `nt`, whose `.text` is megabytes. It is a
/// **cap that reports itself** rather than a refusal, because a partial scan of a huge image still
/// names the sinks it found, and `cap_hit` says the rest was not looked at.
pub const MAX_SCAN_BYTES: u64 = 4 * 1024 * 1024;

/// How much is decoded between two halt polls.
///
/// The decode is one call per window, so this is also the largest read a scan makes at once. Small
/// enough that a cancelled scan stops promptly, large enough that a 100 KB section is a handful of
/// calls rather than hundreds.
const WINDOW: u64 = 64 * 1024;

/// Scans an image's executable sections for sensitive calls and privileged instructions.
///
/// `decode` takes an address and a length and answers the instructions in it, or `None` where the
/// bytes could not be read — which is a fact about the image rather than an error, and leaves that
/// window out of [`Scan::scanned`]. `halt` is polled between windows.
///
/// **Windows overlap by nothing and that is deliberate.** A window boundary can fall inside an
/// instruction, so the last instruction of a window may be decoded from a truncated tail and the
/// next window starts mid-instruction. Both are handled by decoding from the *instruction after*
/// the last complete one rather than from a fixed offset, which is what `next` below carries.
pub fn scan(
    image: &pe::Image,
    imports: &[pe::Import],
    set: InstructionSet,
    mut decode: impl FnMut(u64, usize) -> Option<Vec<Instruction>>,
    mut halt: impl FnMut() -> Option<Halt>,
) -> Scan {
    let by_slot = pe::imports_by_slot(imports);
    // **Keyed by library and name, not by slot**, which is what bounds this list by construction:
    // a crafted table repeating one sensitive name across half a million slots is one sink with a
    // slot count, where keying by slot made it half a million records to allocate, attribute and
    // serialize. A real image has one slot per name per library, so the two keyings agree on
    // everything anyone actually scans.
    let mut sinks: BTreeMap<(String, String), Sink> = BTreeMap::new();
    let mut other_imports = 0usize;
    for import in imports {
        match (&import.name, sink_kind(&import.name.to_string())) {
            (pe::ImportName::Named(name), Some(kind)) => {
                let sink = sinks
                    .entry((import.library.clone(), name.clone()))
                    .or_insert_with(|| Sink {
                        library: import.library.clone(),
                        name: name.clone(),
                        kind,
                        slots: Vec::new(),
                        slot_count: 0,
                        call_sites: Vec::new(),
                        call_site_count: 0,
                    });
                sink.slot_count += 1;
                if sink.slots.len() < MAX_SLOTS_PER_SINK {
                    sink.slots.push(import.slot);
                }
            }
            _ => other_imports += 1,
        }
    }

    let mut privileged = Vec::new();
    let mut privileged_count = 0usize;
    let mut listed_call_sites = 0usize;
    let mut scanned = Vec::new();
    let mut unreadable: Vec<Scanned> = Vec::new();
    let mut budget = MAX_SCAN_BYTES;
    let mut halted = None;
    let mut cap_hit = false;

    // **Sorted, and each range clamped past the last**, so every byte is decoded at most once. A
    // malformed header can declare two executable sections covering the same addresses, and
    // scanning both counts every call site and every privileged instruction in the overlap twice
    // — which would make `call_site_count` and `privileged_count`, documented as exact, quietly
    // inflated. Clamping rather than refusing, because the bytes are real and scanning them once
    // is the right answer; what is dropped is the second visit, not the code.
    let mut code: Vec<&pe::Section> = image.code_sections().collect();
    code.sort_by_key(|section| section.rva);
    let mut past = 0u64;

    'sections: for section in code {
        // **The whole span, not just its start.** `checked_va(rva, 0)` asks only whether the
        // section begins inside the image, and a header claiming a `virtual_size` that runs past
        // `SizeOfImage` would then have this decode straight out of the module and into whatever
        // is mapped next — on a live target, the next driver — reporting its calls and its
        // privileged instructions as this one's. A span that does not fit is **clamped to the
        // image and recorded as a gap**, rather than skipped: what is genuinely inside is still
        // worth scanning, and what was cut has to be visible for the same reason every other
        // shortfall here does.
        let Ok(start) = image.checked_va(section.rva, 0) else {
            // A section that begins **outside** the image is recorded, not skipped. Skipped, its
            // whole declared range vanished from both lists and the report read as a complete
            // clean scan of an image whose headers do not hold together. There is no address to
            // record it at -- that is the point of it -- so it is reported at the image's end,
            // which is the last address this scan can speak for.
            unreadable.push(Scanned {
                section: section.name.clone(),
                start: image.base.saturating_add(u64::from(image.size_of_image)),
                bytes: u64::from(section.virtual_size),
            });
            continue;
        };
        let declared = u64::from(section.virtual_size);
        let end = match image.checked_va(section.rva, section.virtual_size as usize) {
            Ok(_) => start.saturating_add(declared),
            Err(_) => {
                let inside = u64::from(image.size_of_image.saturating_sub(section.rva));
                unreadable.push(Scanned {
                    section: section.name.clone(),
                    start: start.saturating_add(inside),
                    bytes: declared.saturating_sub(inside),
                });
                start.saturating_add(inside)
            }
        };

        // The overlap with everything already scanned is skipped rather than decoded again.
        let mut at = start.max(past);
        past = past.max(end);
        // One entry per **contiguous** decoded run rather than one per section. A section with a
        // hole in it used to come back as a single range starting where the section starts and
        // counting only the bytes that read — a shape that cannot say where the hole was, and
        // whose `start` is wrong for everything after it.
        let mut run: Option<(u64, u64)> = None;
        // The addresses this section's code has been watched computing, for the calls that reach
        // an import through a register rather than through a memory operand. Per section, so a
        // register's meaning never crosses from one section's code into another's.
        let mut formed = Formed::default();
        let close = |run: &mut Option<(u64, u64)>, scanned: &mut Vec<Scanned>| {
            if let Some((from, bytes)) = run.take()
                && bytes > 0
            {
                scanned.push(Scanned {
                    section: section.name.clone(),
                    start: from,
                    bytes,
                });
            }
        };
        while at < end {
            if let Some(why) = halt() {
                halted = Some(why);
                close(&mut run, &mut scanned);
                break 'sections;
            }
            if budget == 0 {
                cap_hit = true;
                close(&mut run, &mut scanned);
                break 'sections;
            }
            // The two range lists are bounded like everything else the answer carries. A section
            // table that is plausible produces a handful of entries; one that is not can produce a
            // row per window per section, and a bounded answer is still an answer where thousands
            // of rows is a reply nobody reads.
            if scanned.len() + unreadable.len() >= MAX_RANGES {
                cap_hit = true;
                close(&mut run, &mut scanned);
                break 'sections;
            }
            let want = WINDOW.min(end - at).min(budget);
            let Some(block) = decode(at, want as usize) else {
                // A window that would not read is skipped rather than ending the scan — a driver
                // whose `.text` is partly absent still answers for the rest of it — but it is
                // **recorded**. Left silent, a dump missing one page reports a driver with no
                // privileged instructions, and nothing anywhere says a page was missing.
                close(&mut run, &mut scanned);
                unreadable.push(Scanned {
                    section: section.name.clone(),
                    start: at,
                    bytes: want,
                });
                at = at.saturating_add(want);
                budget = budget.saturating_sub(want);
                continue;
            };
            // **An empty answer is not an answer**, and neither is one that advances nothing.
            // The decoder can succeed and return nothing — bytes that are there and decode to no
            // instruction — and a zero-length instruction would loop for ever, so both end the
            // section. What each has to do first is say what it is leaving: without that, a window
            // that decoded to nothing ends a section silently and the rest of it is missing from
            // both lists, which is the same silence an unreadable window used to keep.
            if block.is_empty() {
                close(&mut run, &mut scanned);
                unreadable.push(Scanned {
                    section: section.name.clone(),
                    start: at,
                    bytes: end.saturating_sub(at),
                });
                break;
            }
            for instruction in &block {
                // The slot the call names, or -- where the architecture cannot name one -- the
                // slot this watched being computed into the register it calls through.
                let slot = called_slot(instruction).or_else(|| formed.slot_of(instruction));
                if let Some(import) = by_slot.get(&slot.unwrap_or(0))
                    && let Some(sink) =
                        sinks.get_mut(&(import.library.clone(), import.name.to_string()))
                {
                    // Counted always, listed up to the cap: the count is the fact and the list is
                    // a sample of it.
                    sink.call_site_count += 1;
                    if sink.call_sites.len() < MAX_CALL_SITES_PER_SINK
                        && listed_call_sites < MAX_CALL_SITES_TOTAL
                    {
                        sink.call_sites.push(instruction.address);
                        listed_call_sites += 1;
                    }
                }
                if let Some(kind) = privilege_kind(instruction, set) {
                    privileged_count += 1;
                    if privileged.len() < MAX_PRIVILEGED {
                        privileged.push(Privileged {
                            address: instruction.address,
                            kind,
                            mnemonic: instruction.mnemonic.clone(),
                        });
                    }
                }
                // **After the reads above, not before**: the call is the last step of the sequence
                // this watches, and applying it first would clear the register the call reaches
                // the slot through.
                formed.apply(instruction);
            }
            // Resume after the last instruction that decoded whole, not at a fixed stride: a
            // window's tail is usually a partial instruction, and restarting at `at + want` would
            // decode the next window from the middle of one.
            let last = block.last().expect("the block is not empty");
            let next = last.address.saturating_add(instruction_len(last));
            let consumed = next.saturating_sub(at);
            if consumed == 0 {
                close(&mut run, &mut scanned);
                unreadable.push(Scanned {
                    section: section.name.clone(),
                    start: at,
                    bytes: end.saturating_sub(at),
                });
                break;
            }
            let taken = consumed.min(want);
            match &mut run {
                Some((_, bytes)) => *bytes += taken,
                None => run = Some((at, taken)),
            }
            budget = budget.saturating_sub(taken);
            at = next;
        }
        close(&mut run, &mut scanned);
    }

    Scan {
        sinks: sinks.into_values().collect(),
        privileged,
        privileged_count,
        scanned,
        unreadable,
        other_imports,
        unnamed_libraries: Vec::new(),
        halted,
        cap_hit,
    }
}

/// The IAT slot an instruction transfers control through, when it transfers through one.
///
/// An import call is `call qword ptr [rip+disp]`, which the decoder resolves to an absolute
/// address on the operand — so this is a field read rather than a rendering matched, and no
/// symbol's spelling is involved. A call to a register, or to a computed address, resolves to
/// nothing and is not one of these.
///
/// **A tail `jmp` through the slot counts**, because it reaches the import exactly as a `call`
/// does and a driver whose `memcpy` is tail-called would otherwise report no use of it at all —
/// an under-report of the kind this module's own doc comment warns readers about. A `mov` that
/// loads the slot does **not**: it takes the pointer's value, which is a different fact about the
/// driver and belongs in a different field if anyone ever wants it.
fn called_slot(instruction: &Instruction) -> Option<u64> {
    if !matches!(instruction.flow, Flow::Call(None) | Flow::Jmp(None)) {
        return None;
    }
    instruction
        .operands
        .iter()
        .find_map(|operand| match operand {
            Operand::Memory(memory) => memory.address,
            _ => None,
        })
}

/// An import slot whose address the code **computed** rather than named, watched across the
/// instructions that compute it.
///
/// [`called_slot`] reads the slot straight off the call, which works because x64 states it there:
/// `call qword ptr [rip+1234h]` is one instruction carrying one memory operand carrying the
/// address. **A64 has no pc-relative memory operand at all**, so the identical call is three
/// instructions -- `adrp x8,page` / `ldr x8,[x8,#off]` / `blr x8` -- and a scan reading only the
/// call finds a register and no address.
///
/// Every sensitive call in an ARM64 driver has that shape, so without this the scan reports a
/// driver that calls none of them. That is precisely the answer this module's own documentation
/// warns readers about, and the refusal these tools used to give on ARM64 existed to avoid it; the
/// refusal went when dbgscope started answering A64 operands, so the answer had to arrive with it.
///
/// **It cannot invent a call site**, which is what makes carrying state here safe. The address it
/// computes is reported only where the import table already holds that exact slot, so a sequence
/// it misreads names no import and falls out. Nothing about it is ARM64-specific either:
/// `lea rax,[rip+X]` / `mov rax,[rax+8]` / `call rax` is the same three steps and the same answer,
/// and x64 compilers do emit it.
///
/// What it does not reach is a pair split across the decode window, the maps starting empty on
/// each one. A missed call site, never an invented one, and the same direction as every other
/// shortfall here.
#[derive(Debug, Default)]
struct Formed {
    /// A register holding an address the code computed: `adrp`'s page, or a `lea`'s target.
    address: HashMap<String, u64>,
    /// A register holding what was loaded *through* a slot, against that slot's own address.
    loaded_from: HashMap<String, u64>,
}

impl Formed {
    /// The slot an indirect call through a register reaches, where this watched it being formed.
    fn slot_of(&self, instruction: &Instruction) -> Option<u64> {
        if !matches!(instruction.flow, Flow::Call(None) | Flow::Jmp(None)) {
            return None;
        }
        match instruction.operands.first() {
            Some(Operand::Register(register)) => self.loaded_from.get(&register.full).copied(),
            _ => None,
        }
    }

    /// Applies one instruction.
    fn apply(&mut self, instruction: &Instruction) {
        // **Read before anything is cleared**, because the second step of the pair reads the
        // register it overwrites: `ldr x8,[x8,#off]` is the ordinary spelling, and clearing `x8`
        // first would lose the page that makes the slot.
        let formed = self.forms(instruction);
        // Everything the instruction writes stops being believed -- the same rule the IOCTL walk
        // applies, from the same field, and for the same reason: a register the decoder says was
        // written holds neither the address it held nor the slot it was loaded through.
        for written in &instruction.writes {
            self.address.remove(&written.full);
            self.loaded_from.remove(&written.full);
        }
        match formed {
            Some((register, Held::Address(address))) => {
                self.address.insert(register, address);
            }
            Some((register, Held::Slot(slot))) => {
                self.loaded_from.insert(register, slot);
            }
            None => {}
        }
    }

    /// What this instruction leaves in the register it writes, of the two things worth keeping.
    fn forms(&self, instruction: &Instruction) -> Option<(String, Held)> {
        let Some(Operand::Register(destination)) = instruction.operands.first() else {
            return None;
        };
        // Operand zero is the destination only where the decoder says it is written -- an A64
        // store names its source there, and reading that as a destination is how a `str` through a
        // formed address would be recorded as forming one.
        if !instruction
            .writes
            .iter()
            .any(|register| register.full == destination.full)
        {
            return None;
        }
        let Some(Operand::Memory(memory)) = instruction.operands.get(1) else {
            return None;
        };
        match instruction.effect {
            // `adrp x8,page`, and `lea rax,[rip+X]`: the address itself.
            Effect::LoadAddress => memory
                .address
                .map(|address| (destination.full.clone(), Held::Address(address))),
            // A load off one of those, which is the slot the pointer came through. An **indexed**
            // load is an array element rather than a named slot, and is not one.
            Effect::Move if memory.index.is_none() => {
                let base = memory.base.as_ref()?;
                let page = self.address.get(&base.full)?;
                let slot = page.wrapping_add_signed(memory.displacement);
                Some((destination.full.clone(), Held::Slot(slot)))
            }
            _ => None,
        }
    }
}

/// The two things [`Formed`] keeps about a register.
enum Held {
    /// An address the code computed into it.
    Address(u64),
    /// The slot a pointer in it was loaded through.
    Slot(u64),
}

/// The encoded length of an instruction, from the bytes the decoder reported.
///
/// The engine prints the encoding as hex pairs, so the length is half the digits. Zero for an
/// instruction that carried none, which is what stops a scan rather than looping on it.
fn instruction_len(instruction: &Instruction) -> u64 {
    (instruction.bytes.len() / 2) as u64
}

/// The scan as values, with every address turned into a coordinate by `locate`.
///
/// A closure for the same reason every other pass here takes one: attributing an address is an
/// engine call and this file has never seen an engine. The worker supplies one that caches per
/// module; a test supplies one that invents them.
pub fn structured_report(
    module: &str,
    base: u64,
    scan: &Scan,
    mut locate: impl FnMut(u64) -> crate::structured::CodeLocation,
) -> crate::structured::DriverHazards {
    use crate::structured;
    structured::DriverHazards {
        module: module.to_string(),
        base: structured::addr(base),
        sink_list_version: SINK_LIST_VERSION.to_string(),
        sinks: scan
            .sinks
            .iter()
            .map(|sink| structured::ImportedSink {
                library: sink.library.clone(),
                name: sink.name.clone(),
                kind: sink.kind.name().to_string(),
                slots: sink.slots.iter().map(|at| structured::addr(*at)).collect(),
                slot_count: sink.slot_count,
                call_sites: sink.call_sites.iter().map(|at| locate(*at)).collect(),
                call_site_count: sink.call_site_count,
            })
            .collect(),
        privileged: scan
            .privileged
            .iter()
            .map(|found| structured::PrivilegedInstruction {
                at: locate(found.address),
                kind: found.kind.name().to_string(),
                mnemonic: found.mnemonic.clone(),
            })
            .collect(),
        privileged_count: scan.privileged_count,
        scanned: scan.scanned.iter().map(scanned_range).collect(),
        unreadable: scan.unreadable.iter().map(scanned_range).collect(),
        other_imports: scan.other_imports,
        unnamed_libraries: scan.unnamed_libraries.clone(),
        stopped: scan.halted.map(|halt| match halt {
            Halt::Deadline => structured::WalkHalt::Deadline,
            Halt::Interrupted => structured::WalkHalt::Interrupted,
        }),
        cap_hit: scan.cap_hit,
    }
}

/// One covered or missing range, as the typed result carries it.
fn scanned_range(range: &Scanned) -> crate::structured::ScannedRange {
    crate::structured::ScannedRange {
        section: range.section.clone(),
        start: crate::structured::addr(range.start),
        bytes: range.bytes,
    }
}

/// The listing a person reads, rendered **from the values beside it**.
///
/// Unlike the reachability report, whose text predates its typed half and is pinned verbatim by
/// walkthroughs, this tool's two halves arrive together — so the text is derived from the record
/// rather than built in parallel with it, which is one fewer place for the two to disagree about
/// a count.
pub fn render(report: &crate::structured::DriverHazards) -> String {
    // **The module name and every library and import name below come out of the image**, which
    // on this tool's subject is a file somebody built to be analysed. `src/pe.rs` exists to
    // distrust those bytes as *structure*; this is the same distrust applied to them as *text*.
    let mut out = format!(
        "Driver hazards: {} at {}\n  sink list v{}\n",
        crate::structured::renderable(&report.module),
        report.base,
        report.sink_list_version
    );

    // Said above the findings rather than below them, because it changes what an empty list means:
    // a caveat has to arrive before the conclusion it qualifies.
    //
    // **Code that would not read gets its own line**, separate from a halt and from the cap,
    // because it is a different fact with a different remedy: the scan ran to the end and part of
    // the driver was simply not there. Without it, a dump missing one page prints "Privileged
    // instructions: none" and nothing anywhere says a page was missing.
    if !report.unreadable.is_empty() {
        let bytes: u64 = report.unreadable.iter().map(|range| range.bytes).sum();
        out.push_str(&format!(
            "  INCOMPLETE: {bytes} bytes of this driver's code could not be read, so what is\n           \
             below is what was found rather than what is there. On a dump the image is what\n           \
             supplies those bytes.\n"
        ));
    }
    if report.stopped.is_some() || report.cap_hit {
        let why = match (report.stopped, report.cap_hit) {
            (Some(crate::structured::WalkHalt::Deadline), _) => "the call ran out of time",
            (Some(crate::structured::WalkHalt::Interrupted), _) => "interrupted",
            _ => "the scan's byte cap was reached",
        };
        out.push_str(&format!(
            "  INCOMPLETE: {why} — part of this driver's code was not decoded, so what is\n           \
             below is what was found rather than what is there.\n"
        ));
    }

    if report.sinks.is_empty() {
        out.push_str("  Sensitive imports: none on the list\n");
    } else {
        out.push_str(&format!("  Sensitive imports ({}):\n", report.sinks.len()));
        for sink in &report.sinks {
            // The **count**, with the listed sample noted when it is one. Printing the list's
            // length would report a driver that calls an allocator six hundred times as one that
            // calls it two hundred and fifty-six.
            let listed = if sink.call_site_count > sink.call_sites.len() {
                format!(" (first {} listed)", sink.call_sites.len())
            } else {
                String::new()
            };
            out.push_str(&format!(
                "    {:<32} {:<20} {} call site(s){listed}\n",
                crate::structured::renderable(&sink.name),
                sink.kind,
                sink.call_site_count
            ));
        }
    }

    if report.privileged.is_empty() {
        out.push_str("  Privileged instructions: none\n");
    } else {
        let listed = if report.privileged_count > report.privileged.len() {
            format!(", first {} listed", report.privileged.len())
        } else {
            String::new()
        };
        out.push_str(&format!(
            "  Privileged instructions ({}{listed}):\n",
            report.privileged_count
        ));
        for found in &report.privileged {
            let rva = found.at.rva.as_deref().unwrap_or("?");
            out.push_str(&format!(
                "    {:<16} {:<24} {}\n",
                crate::structured::renderable(&found.mnemonic),
                found.kind,
                rva
            ));
        }
    }

    let scanned: u64 = report.scanned.iter().map(|range| range.bytes).sum();
    let missed: u64 = report.unreadable.iter().map(|range| range.bytes).sum();
    out.push_str(&format!(
        "  Scanned {scanned} bytes in {} run(s), {missed} not read; {} other import(s) not on \
         the list\n",
        report.scanned.len(),
        report.other_imports
    ));
    if !report.unnamed_libraries.is_empty() {
        out.push_str(&format!(
            "  Not nameable (bound imports): {}\n",
            report
                .unnamed_libraries
                .iter()
                .map(|one| crate::structured::renderable(one))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    // **Names no tool**, which is `FOLLOWUPS.md` item 43's rule and applies here for its sharper
    // reason: this is built in the worker, which owns one session and has never heard of the
    // client's surface, so a sentence pointing at another tool would be sent to a caller who may
    // not be served it. The fact is worth saying and the pointer is not this file's to make.
    out.push_str(
        "  Evidence, not a verdict: an import is not a call, an absent import excludes nothing\n",
    );
    out.push_str(
        "           (a driver can resolve an export at run time), and a call site is not a\n",
    );
    out.push_str(
        "           reachable one — whether the dispatch routine reaches it is a separate\n",
    );
    out.push_str("           question.\n");
    out
}

#[cfg(test)]
mod tests {

    /// A register operand as the decoder reports one: the printed name, and the full-width
    /// register it is part of.
    ///
    /// The pairs are spelled out rather than derived, because a fixture that computed them would
    /// be sharing whatever the code under test uses to decide — and the answer is the decoder's on
    /// a real target, so here it is data like an instruction's bytes.
    /// `privilege_kind` for an x64 target, which is what every fixture here but one is.
    fn privilege_kind_x86(instruction: &Instruction) -> Option<PrivilegeKind> {
        privilege_kind(instruction, InstructionSet::Amd64)
    }

    /// And for an ARM64 one, so a call site says which vocabulary it is asking about.
    fn privilege_kind_arm64(instruction: &Instruction) -> Option<PrivilegeKind> {
        privilege_kind(instruction, InstructionSet::Arm64)
    }

    fn register(name: &str) -> RegisterOperand {
        let full = match name {
            "rax" | "eax" | "ax" | "al" | "ah" => "rax",
            "rbx" | "ebx" | "bx" | "bl" => "rbx",
            "rcx" | "ecx" | "cx" | "cl" => "rcx",
            "rdx" | "edx" | "dx" | "dl" => "rdx",
            "rsi" | "esi" | "si" => "rsi",
            "rdi" | "edi" | "di" => "rdi",
            "rbp" | "ebp" => "rbp",
            "rsp" | "esp" => "rsp",
            "r13" | "r13d" => "r13",
            "r12" | "r12d" => "r12",
            "rip" | "eip" => "rip",
            // A control register, a segment, anything else: itself, and a fixture naming one this
            // does not know has to say so rather than get a plausible answer.
            other => other,
        };
        RegisterOperand {
            name: name.to_string(),
            full: full.to_string(),
            // The scan reads operands for what they *are* -- a control register, a port -- and
            // never for how much of a value they carry, so any width answers here.
            width: 8,
        }
    }

    use super::*;
    use dbgscope::dbgeng::{Effect, MemoryOperand, RegisterOperand};

    const BASE: u64 = 0xffff_f800_0000_0000;

    /// An image with one executable section and one that is not.
    fn image() -> pe::Image {
        pe::Image {
            base: BASE,
            bitness: pe::Bitness::Bits64,
            machine: 0x8664,
            size_of_image: 0x4000,
            section_alignment: 0x1000,
            sections: vec![
                pe::Section {
                    name: ".text".to_string(),
                    rva: 0x1000,
                    virtual_size: 0x100,
                    characteristics: 0x6000_0020,
                },
                pe::Section {
                    name: ".data".to_string(),
                    rva: 0x3000,
                    virtual_size: 0x100,
                    characteristics: 0xc000_0040,
                },
            ],
            export_directory: (0, 0),
            import_directory: (0x2000, 40),
        }
    }

    fn import(name: &str, slot: u64) -> pe::Import {
        pe::Import {
            library: "ntoskrnl.exe".to_string(),
            name: pe::ImportName::Named(name.to_string()),
            slot,
        }
    }

    /// One instruction, with the two fields this module reads: the encoded length, and whatever
    /// the operands say. `bytes` is hex pairs, as the engine prints them.
    fn insn(
        address: u64,
        bytes: &str,
        mnemonic: &str,
        flow: Flow,
        operands: Vec<Operand>,
    ) -> Instruction {
        Instruction {
            address,
            bytes: bytes.to_string(),
            text: String::new(),
            mnemonic: mnemonic.to_string(),
            operands,
            flow,
            privileged: false,
            // The scan reads the flow, the operands and the mnemonic, and `Formed` reads the
            // effect and the writes as well -- so a fixture about a **formed** slot has to supply
            // those two rather than take these defaults. `forming` below is that fixture.
            effect: Effect::Other,
            condition: None,
            writes_flags: false,
            // are not, and neither is either register set an instruction touches.
            writes: Vec::new(),
            reads: Vec::new(),
        }
    }

    /// The same, for an instruction the **decoder** reports as needing privilege.
    ///
    /// Separate rather than a sixth parameter on `insn`, because that is the point of the field:
    /// a fixture answers for the decoder here, so every test that means "the decoder said so" has
    /// to say it, and every test that does not gets the honest `false`.
    fn privileged_insn(
        address: u64,
        bytes: &str,
        mnemonic: &str,
        flow: Flow,
        operands: Vec<Operand>,
    ) -> Instruction {
        Instruction {
            privileged: true,
            ..insn(address, bytes, mnemonic, flow, operands)
        }
    }

    /// An instruction that computes something into the register it names first.
    ///
    /// [`Formed`] reads the effect and `Instruction::writes`, neither of which the plain fixture
    /// supplies -- and the second is the one that matters, since it is what tells a store from a
    /// load on a target that spells both with the register first. So a test about A64's three-step
    /// import call has to state both, as the decoder would.
    fn forming(
        address: u64,
        mnemonic: &str,
        effect: Effect,
        operands: Vec<Operand>,
    ) -> Instruction {
        let writes = match operands.first() {
            Some(Operand::Register(register)) => vec![register.clone()],
            _ => Vec::new(),
        };
        Instruction {
            effect,
            writes,
            ..insn(address, "00000000", mnemonic, Flow::Fallthrough, operands)
        }
    }

    /// A `call qword ptr [rip+disp]` whose operand resolves to `slot`.
    fn call_slot(address: u64, slot: u64) -> Instruction {
        insn(
            address,
            "ff1500000000",
            "call",
            Flow::Call(None),
            vec![Operand::Memory(MemoryOperand {
                size: Some(8),
                segment: None,
                base: Some(register("rip")),
                index: None,
                scale: 1,
                displacement: 0,
                address: Some(slot),
            })],
        )
    }

    fn never() -> Option<Halt> {
        None
    }

    /// A call site is matched to an import by the **slot it goes through**, never by a name.
    ///
    /// That is the whole reason this works on a stripped driver: `call qword ptr [drv+0x9018]`
    /// carries no symbol, and the import table says what lives at that address without the slot
    /// ever being read. An import that is not on the curated list is counted rather than reported,
    /// so a short list of sinks can be told from a driver that imports almost nothing.
    #[test]
    fn a_call_site_is_matched_by_its_slot() {
        let image = image();
        let imports = [
            import("ProbeForRead", BASE + 0x3000),
            import("memcpy", BASE + 0x3008),
            import("KeQueryPerformanceCounter", BASE + 0x3010),
            // A near-miss on the list, and the reason the match is exact: this is a different API
            // with a different argument, and reporting it as `MmProbeAndLockPages` would be a
            // wrong answer rather than a broad one. It also *starts with* a listed name, which is
            // what a prefix rule would fold in: a driver taking a priority hint reported as one
            // calling the plain allocator.
            import("ExAllocatePoolWithTagPriority", BASE + 0x3018),
        ];
        let block = vec![
            call_slot(BASE + 0x1000, BASE + 0x3008),
            call_slot(BASE + 0x1006, BASE + 0x3000),
            // An import nobody asked about, and an indirect call through a register: neither is a
            // sink call site, and the second resolves to no slot at all.
            call_slot(BASE + 0x100c, BASE + 0x3010),
            insn(
                BASE + 0x1012,
                "ffd0",
                "call",
                Flow::Call(None),
                vec![Operand::Register(register("rax"))],
            ),
            // Loading the slot is not calling through it: the driver takes the pointer's value,
            // which is a different fact and must not be reported as a call site.
            insn(
                BASE + 0x1014,
                "488b0500000000",
                "mov",
                Flow::Fallthrough,
                vec![
                    Operand::Register(register("rax")),
                    Operand::Memory(MemoryOperand {
                        size: Some(8),
                        segment: None,
                        base: Some(register("rip")),
                        index: None,
                        scale: 1,
                        displacement: 0,
                        address: Some(BASE + 0x3000),
                    }),
                ],
            ),
            // A tail jump through the slot *does* reach the import, and counts.
            insn(
                BASE + 0x101b,
                "ff2500000000",
                "jmp",
                Flow::Jmp(None),
                vec![Operand::Memory(MemoryOperand {
                    size: Some(8),
                    segment: None,
                    base: Some(register("rip")),
                    index: None,
                    scale: 1,
                    displacement: 0,
                    address: Some(BASE + 0x3008),
                })],
            ),
            insn(BASE + 0x1021, "c3", "ret", Flow::Return, Vec::new()),
        ];

        let found = scan(
            &image,
            &imports,
            InstructionSet::Amd64,
            |at, _| (at == BASE + 0x1000).then(|| block.clone()),
            never,
        );

        assert_eq!(found.sinks.len(), 2, "{:?}", found.sinks);
        let probe = &found.sinks[0];
        assert_eq!(probe.name, "ProbeForRead");
        assert_eq!(probe.kind, SinkKind::UserPointerGuard);
        assert_eq!(
            probe.call_sites,
            vec![BASE + 0x1006],
            "the `mov` that loads the same slot is not a call site"
        );
        let copy = &found.sinks[1];
        assert_eq!(copy.name, "memcpy");
        assert_eq!(copy.kind, SinkKind::BufferCopy);
        assert_eq!(
            copy.call_sites,
            vec![BASE + 0x1000, BASE + 0x101b],
            "the tail jump reaches the import as surely as the call does"
        );
        assert_eq!(
            found.other_imports, 2,
            "the two imports that are not sinks are counted, not dropped"
        );
        assert!(
            found
                .sinks
                .iter()
                .all(|s| s.name != "ExAllocatePoolWithTagPriority"),
            "a name that merely starts with a listed one is not that name: {:?}",
            found.sinks
        );
        assert_eq!(found.halted, None);
        assert!(!found.cap_hit);
        // The section that is not executable is never decoded.
        assert_eq!(found.scanned.len(), 1, "{:?}", found.scanned);
        assert_eq!(found.scanned[0].section, ".text");
    }

    /// An ARM64 import call, whose slot address is computed across three instructions.
    ///
    /// **A64 has no pc-relative memory operand**, so the call x64 writes as
    /// `call qword ptr [rip+disp]` is `adrp` / `ldr` / `blr` there, and a scan reading only the
    /// call finds a register and no address. Every sensitive call in an ARM64 driver is that
    /// shape, so without [`Formed`] this reports a driver that calls none of them -- the answer
    /// that looks exactly like a clean driver, which is what these tools refused ARM64 outright to
    /// avoid until dbgscope#170 made the refusal wrong.
    ///
    /// The two negative halves matter as much as the positive one: a slot **loaded** but never
    /// called is not a call site, and a call through a register nothing formed resolves to nothing
    /// at all rather than to whatever was last in the map.
    #[test]
    fn an_arm64_import_call_is_matched_through_the_slot_it_forms() {
        let image = image();
        let imports = [
            import("memcpy", BASE + 0x3008),
            import("ProbeForRead", BASE + 0x3000),
        ];
        let block = vec![
            // `adrp x8,BASE+3000h` / `ldr x8,[x8,#8]` / `blr x8` -- one call of `memcpy`.
            forming(
                BASE + 0x1000,
                "adrp",
                Effect::LoadAddress,
                vec![
                    Operand::Register(register("x8")),
                    Operand::Memory(MemoryOperand {
                        size: None,
                        segment: None,
                        base: None,
                        index: None,
                        scale: 0,
                        displacement: 0,
                        address: Some(BASE + 0x3000),
                    }),
                ],
            ),
            forming(
                BASE + 0x1004,
                "ldr",
                Effect::Move,
                vec![
                    Operand::Register(register("x8")),
                    Operand::Memory(MemoryOperand {
                        size: Some(8),
                        segment: None,
                        base: Some(register("x8")),
                        index: None,
                        scale: 1,
                        displacement: 8,
                        address: None,
                    }),
                ],
            ),
            insn(
                BASE + 0x1008,
                "00000000",
                "blr",
                Flow::Call(None),
                vec![Operand::Register(register("x8"))],
            ),
            // **A slot formed and never called is not a call site.** `ProbeForRead`'s pointer is
            // loaded into `x9` and nothing calls through it, exactly as the x64 test's `mov` of a
            // slot is not one.
            forming(
                BASE + 0x100c,
                "adrp",
                Effect::LoadAddress,
                vec![
                    Operand::Register(register("x9")),
                    Operand::Memory(MemoryOperand {
                        size: None,
                        segment: None,
                        base: None,
                        index: None,
                        scale: 0,
                        displacement: 0,
                        address: Some(BASE + 0x3000),
                    }),
                ],
            ),
            forming(
                BASE + 0x1010,
                "ldr",
                Effect::Move,
                vec![
                    Operand::Register(register("x9")),
                    Operand::Memory(MemoryOperand {
                        size: Some(8),
                        segment: None,
                        base: Some(register("x9")),
                        index: None,
                        scale: 1,
                        displacement: 0,
                        address: None,
                    }),
                ],
            ),
            // **A call through a register nothing formed reaches nothing.** `x10` was never
            // written here, so the map holds no slot for it and this must not borrow one.
            insn(
                BASE + 0x1014,
                "00000000",
                "blr",
                Flow::Call(None),
                vec![Operand::Register(register("x10"))],
            ),
        ];

        let found = scan(
            &image,
            &imports,
            InstructionSet::Arm64,
            |at, _| (at == BASE + 0x1000).then(|| block.clone()),
            never,
        );

        let copy = found
            .sinks
            .iter()
            .find(|sink| sink.name == "memcpy")
            .unwrap_or_else(|| panic!("{:?}", found.sinks));
        assert_eq!(
            copy.call_sites,
            vec![BASE + 0x1008],
            "the `blr` reaches the import through the slot adrp/ldr formed"
        );
        assert_eq!(copy.call_site_count, 1);
        let probe = found.sinks.iter().find(|sink| sink.name == "ProbeForRead");
        assert!(
            probe.is_none_or(|sink| sink.call_sites.is_empty()),
            "a slot loaded and never called through is not a call site: {probe:?}"
        );
    }

    /// A64's privileged instructions land in families rather than all in [`PrivilegeKind::Other`].
    ///
    /// Membership is the decoder's answer and always was, so these were reported correctly and
    /// namelessly the moment dbgscope#170 made `privileged` true on ARM64 -- which is what
    /// `Other` is for and why enabling these tools on ARM64 was safe before this. What the table
    /// adds is the family, for the two groups where it is unambiguous.
    ///
    /// The system-register space is deliberately **not** family-named beyond the interrupt masks:
    /// it is far too wide to map honestly onto x86's families, and `Other` carries the register in
    /// the operands, which is a better answer than an invented name.
    #[test]
    fn an_arm64_privileged_instruction_lands_in_a_family() {
        let other = |mnemonic: &str, operands: Vec<Operand>| {
            privileged_insn(
                BASE + 0x1000,
                "00000000",
                mnemonic,
                Flow::Fallthrough,
                operands,
            )
        };
        // Cache, TLB and address-translation maintenance: the same family as `invd`/`invlpg`.
        for mnemonic in ["dc", "ic", "tlbi", "at"] {
            assert_eq!(
                privilege_kind_arm64(&other(mnemonic, Vec::new())),
                Some(PrivilegeKind::MachineState),
                "{mnemonic}"
            );
        }
        // `msr daifset,#2` is `cli` under another spelling, and `DAIF` reached as a register is
        // the same gate: `s3_3_c4_c2_1`.
        for name in ["daifset", "daifclr", "s3_3_c4_c2_1"] {
            assert_eq!(
                privilege_kind_arm64(&other("msr", vec![Operand::Other(name.to_string())])),
                Some(PrivilegeKind::InterruptFlag),
                "{name}"
            );
        }
        // **`NZCV` is one `op2` away and is EL0's own**, so a looser match would call every flag
        // restore an interrupt mask. It is not privileged at all, so it is not reported.
        assert_eq!(
            privilege_kind_arm64(&insn(
                BASE + 0x1000,
                "00000000",
                "msr",
                Flow::Fallthrough,
                vec![Operand::Other("s3_3_c4_c2_0".to_string())],
            )),
            None,
        );
        // Everything else privileged keeps its mnemonic under `Other` rather than being dropped.
        assert_eq!(
            privilege_kind_arm64(&other("eret", Vec::new())),
            Some(PrivilegeKind::Other),
        );
        // **The collision that made these tables architecture-specific.** x86's `str` stores the
        // task register and belongs to the descriptor tables; A64's stores a register and is among
        // the commonest instructions there is. Read in one namespace, a scan of an ARM64 `nt`
        // called **every store** a descriptor-table access -- 59,450 privileged instructions,
        // which is a disassembly rather than a hazard report. Found by the debugger tier against a
        // real image, and asserted in **both** directions here: the x86 reading has to survive,
        // since that one is right.
        let store = insn(
            BASE + 0x1000,
            "00000000",
            "str",
            Flow::Fallthrough,
            Vec::new(),
        );
        assert_eq!(
            privilege_kind_arm64(&store),
            None,
            "an A64 store is not a descriptor-table access"
        );
        assert_eq!(
            privilege_kind_x86(&store),
            Some(PrivilegeKind::DescriptorTable),
            "and an x86 `str` still is"
        );
    }

    /// A privileged instruction is decided by its **operands**, not by its mnemonic.
    ///
    /// `mov cr3, rax` and `mov rax, rbx` are the same mnemonic, and the difference between a
    /// driver that reprograms paging and one that copies a register is entirely in the operand. A
    /// rule written against a rendering would have to find `cr3` in a string, where a symbol or a
    /// variable named `cr3` reads the same.
    #[test]
    fn a_privileged_instruction_is_decided_by_its_operands() {
        let image = image();
        let block = vec![
            privileged_insn(
                BASE + 0x1000,
                "0f20d8",
                "mov",
                Flow::Fallthrough,
                vec![
                    Operand::Register(register("rax")),
                    Operand::Register(register("cr3")),
                ],
            ),
            insn(
                BASE + 0x1003,
                "4889d8",
                "mov",
                Flow::Fallthrough,
                vec![
                    Operand::Register(register("rax")),
                    Operand::Register(register("rbx")),
                ],
            ),
            privileged_insn(
                BASE + 0x1006,
                "0f32",
                "rdmsr",
                Flow::Fallthrough,
                Vec::new(),
            ),
            privileged_insn(
                BASE + 0x1008,
                "ee",
                "out",
                Flow::Fallthrough,
                vec![
                    Operand::Register(register("dx")),
                    Operand::Register(register("al")),
                ],
            ),
            privileged_insn(
                BASE + 0x1009,
                "0f01f8",
                "swapgs",
                Flow::Fallthrough,
                Vec::new(),
            ),
            insn(BASE + 0x100c, "c3", "ret", Flow::Return, Vec::new()),
        ];
        let found = scan(
            &image,
            &[],
            InstructionSet::Amd64,
            |at, _| (at == BASE + 0x1000).then(|| block.clone()),
            never,
        );

        let kinds: Vec<(u64, PrivilegeKind)> = found
            .privileged
            .iter()
            .map(|p| (p.address, p.kind))
            .collect();
        assert_eq!(
            kinds,
            vec![
                (BASE + 0x1000, PrivilegeKind::ControlRegister),
                (BASE + 0x1006, PrivilegeKind::ModelSpecificRegister),
                (BASE + 0x1008, PrivilegeKind::PortIo),
                (BASE + 0x1009, PrivilegeKind::MachineState),
            ],
            "the plain `mov` is not privileged and everything else is: {:?}",
            found.privileged
        );
    }

    /// Whether an instruction is privileged is the **decoder's** answer; the table only names the
    /// family.
    ///
    /// The two directions that a table-as-membership gets wrong are both here, and each needs an
    /// instruction the other rule cannot reach. `sysret` is privileged and in **no** family, so it
    /// can arrive only through the decoder and only as [`PrivilegeKind::Other`] — a list of
    /// mnemonics reports a driver holding it as holding none, which is what this change is about,
    /// and the fallback family is what stops the decoder's extra findings being dropped for want
    /// of a name. `sgdt` is the reverse: the decoder calls it unprivileged, correctly, and it is in
    /// the report anyway because a driver reading the GDT is worth seeing.
    #[test]
    fn privilege_is_the_decoders_answer_and_the_table_only_names_the_family() {
        let image = image();
        let block = vec![
            // Privileged, named by no family: the decoder is the only thing that can find it.
            privileged_insn(BASE + 0x1000, "0f07", "sysret", Flow::Return, Vec::new()),
            privileged_insn(BASE + 0x1002, "fa", "cli", Flow::Fallthrough, Vec::new()),
            privileged_insn(
                BASE + 0x1003,
                "0f01c2",
                "vmlaunch",
                Flow::Fallthrough,
                Vec::new(),
            ),
            // Unprivileged, and reported: the table's own half of the union.
            insn(
                BASE + 0x1006,
                "0f0100",
                "sgdt",
                Flow::Fallthrough,
                vec![Operand::Memory(MemoryOperand {
                    size: None,
                    segment: None,
                    base: Some(register("rax")),
                    index: None,
                    scale: 1,
                    displacement: 0,
                    address: None,
                })],
            ),
            insn(BASE + 0x1009, "90", "nop", Flow::Fallthrough, Vec::new()),
            insn(BASE + 0x100a, "c3", "ret", Flow::Return, Vec::new()),
        ];
        let found = scan(
            &image,
            &[],
            InstructionSet::Amd64,
            |at, _| (at == BASE + 0x1000).then(|| block.clone()),
            never,
        );

        let kinds: Vec<(&str, PrivilegeKind)> = found
            .privileged
            .iter()
            .map(|p| (p.mnemonic.as_str(), p.kind))
            .collect();
        assert_eq!(
            kinds,
            vec![
                ("sysret", PrivilegeKind::Other),
                ("cli", PrivilegeKind::InterruptFlag),
                ("vmlaunch", PrivilegeKind::Virtualization),
                ("sgdt", PrivilegeKind::DescriptorTable),
            ],
            "the decoder's set and the table's, and `nop` in neither: {:?}",
            found.privileged
        );
    }

    /// The scan resumes after the last instruction that decoded **whole**.
    ///
    /// A window boundary falls wherever the arithmetic puts it, which is usually inside an
    /// instruction. Resuming at a fixed stride would start the next window in the middle of one
    /// and decode rubbish from there — every byte after it shifted, so a `call` through an import
    /// slot stops looking like one. Resuming at the end of the last complete instruction is what
    /// makes the windows an implementation detail rather than a source of wrong answers.
    #[test]
    fn the_scan_resumes_after_the_last_whole_instruction() {
        let image = image();
        let mut asked: Vec<u64> = Vec::new();
        let found = scan(
            &image,
            &[],
            InstructionSet::Amd64,
            |at, _| {
                asked.push(at);
                // The first window ends on a three-byte instruction, so the next must begin one
                // byte past its end rather than at a stride.
                if at == BASE + 0x1000 {
                    return Some(vec![
                        insn(BASE + 0x1000, "90", "nop", Flow::Fallthrough, Vec::new()),
                        insn(
                            BASE + 0x1001,
                            "0f1f00",
                            "nop",
                            Flow::Fallthrough,
                            Vec::new(),
                        ),
                    ]);
                }
                None
            },
            never,
        );
        assert_eq!(
            asked.first().copied(),
            Some(BASE + 0x1000),
            "the first window starts at the section: {asked:x?}"
        );
        assert_eq!(
            asked.get(1).copied(),
            Some(BASE + 0x1004),
            "the second starts after the three-byte instruction, not at a stride: {asked:x?}"
        );
        assert_eq!(found.scanned[0].bytes, 4, "{:?}", found.scanned);
    }

    /// A decode that answers **nothing** ends the section and says what it is leaving.
    ///
    /// The engine can succeed and return no instructions — bytes that are there and decode to
    /// none — and a zero-length instruction would loop for ever, so both end the section. Ending
    /// it silently was the defect: the rest of the section was missing from `scanned` and from
    /// `unreadable` alike, so a report could say "Privileged instructions: none" with most of a
    /// driver never looked at and nothing anywhere saying so.
    #[test]
    fn a_decode_that_answers_nothing_records_what_it_leaves() {
        let image = image();

        // An empty but successful decode.
        let empty = scan(
            &image,
            &[],
            InstructionSet::Amd64,
            |_, _| Some(Vec::new()),
            never,
        );
        assert!(empty.scanned.is_empty(), "{:?}", empty.scanned);
        assert_eq!(empty.unreadable.len(), 1, "{:?}", empty.unreadable);
        assert_eq!(empty.unreadable[0].start, BASE + 0x1000);
        assert_eq!(
            empty.unreadable[0].bytes, 0x100,
            "the whole section is left"
        );

        // And an instruction that advances nothing, which cannot be walked past.
        let stuck = scan(
            &image,
            &[],
            InstructionSet::Amd64,
            |at, _| Some(vec![insn(at, "", "nop", Flow::Fallthrough, Vec::new())]),
            never,
        );
        assert_eq!(stuck.unreadable.len(), 1, "{:?}", stuck.unreadable);
        assert_eq!(stuck.unreadable[0].bytes, 0x100);
    }

    /// A window that will not read is skipped, **and recorded**; the scan goes on.
    ///
    /// Silence here is the expensive kind. A dump missing one page of a driver's `.text` would
    /// otherwise produce an ordinary-looking report saying "Privileged instructions: none" -- a
    /// positive claim about code nobody decoded. And the ranges that *were* covered are reported
    /// one per contiguous run rather than one per section, because a single entry starting where
    /// the section starts cannot say where the hole was and is wrong about everything after it.
    #[test]
    fn an_unreadable_window_is_recorded_rather_than_skipped_in_silence() {
        let image = image();
        let found = scan(&image, &[], InstructionSet::Amd64, |_, _| None, never);
        assert!(
            found.scanned.is_empty(),
            "nothing was covered, and nothing claims to have been: {:?}",
            found.scanned
        );
        assert_eq!(
            found.unreadable.len(),
            1,
            "the whole section could not be read, and says so: {:?}",
            found.unreadable
        );
        assert_eq!(found.unreadable[0].start, BASE + 0x1000);
        assert_eq!(found.unreadable[0].bytes, 0x100);
        assert_eq!(found.halted, None, "an unreadable page is not a halt");
        assert!(!found.cap_hit);

        // And a hole *between* readable runs leaves two ranges with the right starts. The section
        // has to span three windows for that, since an unreadable window covers whatever is left
        // of a shorter one -- which is why the fixture above could only ever show a single gap.
        let mut wide = image;
        wide.size_of_image = 0x40000;
        wide.sections[0].virtual_size = 0x30000;
        // Each readable window is consumed whole, so the scan advances a window at a time rather
        // than a byte at a time.
        let filler = |at: u64, want: usize| {
            vec![insn(
                at,
                &"90".repeat(want),
                "nop",
                Flow::Fallthrough,
                Vec::new(),
            )]
        };
        let hole = scan(
            &wide,
            &[],
            InstructionSet::Amd64,
            |at, want| (at != BASE + 0x11000).then(|| filler(at, want)),
            never,
        );
        assert_eq!(hole.scanned.len(), 2, "{:?}", hole.scanned);
        assert_eq!(hole.scanned[0].start, BASE + 0x1000);
        assert_eq!(hole.unreadable.len(), 1, "{:?}", hole.unreadable);
        assert_eq!(hole.unreadable[0].start, BASE + 0x11000);
        assert_eq!(
            hole.scanned[1].start,
            hole.unreadable[0].start + hole.unreadable[0].bytes,
            "the run after the hole starts after it, not at the section: {:?}",
            hole.scanned
        );
    }

    /// A section whose declared span runs past the image is **clamped and recorded**, never
    /// followed out of the module.
    ///
    /// `checked_va(rva, 0)` asks only whether a section begins inside the image. A header claiming
    /// a `virtual_size` that overruns it would then have the scan decode straight into whatever is
    /// mapped next -- on a live target, the next driver -- and report its calls and its privileged
    /// instructions as this one's. That is the failure `Image::checked_va` exists to prevent, and
    /// the zero-length door is how it was walked around.
    #[test]
    fn a_section_that_overruns_the_image_is_clamped_and_says_so() {
        let mut image = image();
        // The image is 0x4000; this section claims to run to 0x11000.
        image.sections[0].virtual_size = 0x10000;

        let mut asked: Vec<u64> = Vec::new();
        let found = scan(
            &image,
            &[],
            InstructionSet::Amd64,
            |at, len| {
                asked.push(at + len as u64);
                None
            },
            never,
        );
        let furthest = asked.iter().copied().max().unwrap_or_default();
        assert!(
            furthest <= BASE + u64::from(image.size_of_image),
            "the scan read to {furthest:#x}, past the image's own end: {asked:x?}"
        );
        assert!(
            found
                .unreadable
                .iter()
                .any(|range| range.start == BASE + u64::from(image.size_of_image)),
            "the part cut off is recorded rather than silently dropped: {:?}",
            found.unreadable
        );
    }

    /// The findings are capped, and the **counts stay exact**.
    ///
    /// The byte cap bounds the work and not the answer, which are different budgets: four
    /// megabytes of one-byte `hlt` is inside it and would be four million findings, each attributed
    /// through an engine call and serialized into the reply. What that costs is a worker that
    /// stalls or dies while analysing an untrusted driver — so the lists are bounded and the counts
    /// are not, because a capped list reported as a count would turn a driver that calls an
    /// allocator six hundred times into one that calls it two hundred and fifty-six.
    #[test]
    fn the_findings_are_capped_and_the_counts_stay_exact() {
        let mut image = image();
        image.size_of_image = 0x40000;
        image.sections[0].virtual_size = 0x30000;
        let imports = [import("memcpy", BASE + 0x3008)];

        // One window's worth of alternating call-and-`hlt`, repeated: far more of each than the
        // caps allow, and the fixture consumes whole windows so the scan advances.
        let found = scan(
            &image,
            &imports,
            InstructionSet::Amd64,
            |at, want| {
                let mut block = Vec::new();
                let mut address = at;
                while address + 1 < at + want as u64 {
                    block.push(call_slot(address, BASE + 0x3008));
                    block.push(insn(address + 1, "f4", "hlt", Flow::Trap, Vec::new()));
                    address += 2;
                }
                Some(block)
            },
            never,
        );

        let sink = &found.sinks[0];
        assert_eq!(
            sink.call_sites.len(),
            MAX_CALL_SITES_PER_SINK,
            "the list stops at the cap"
        );
        assert!(
            sink.call_site_count > MAX_CALL_SITES_PER_SINK,
            "and the count does not: {}",
            sink.call_site_count
        );
        assert_eq!(found.privileged.len(), MAX_PRIVILEGED, "the list stops");
        assert!(
            found.privileged_count > MAX_PRIVILEGED,
            "and the count does not: {}",
            found.privileged_count
        );
        assert_eq!(
            sink.call_site_count, found.privileged_count,
            "the fixture emits one of each per pair, so the two counts agree — which is what says              both are counting rather than both being capped"
        );
    }

    /// Overlapping executable sections are decoded **once**, so the counts stay exact.
    ///
    /// A malformed header can declare two sections covering the same addresses. Scanned per
    /// section, every call site and every privileged instruction in the overlap is counted twice —
    /// and those counts are documented as exact, which is precisely the kind of claim that is worth
    /// nothing once it is quietly wrong. The bytes are real, so the second visit is what is
    /// dropped rather than the code.
    #[test]
    fn overlapping_executable_sections_are_decoded_once() {
        let mut image = image();
        // A second executable section covering the first, declared after it.
        image.sections.push(pe::Section {
            name: ".text2".to_string(),
            rva: 0x1000,
            virtual_size: 0x100,
            characteristics: 0x6000_0020,
        });
        let imports = [import("memcpy", BASE + 0x3008)];
        let block = vec![
            call_slot(BASE + 0x1000, BASE + 0x3008),
            insn(BASE + 0x1006, "f4", "hlt", Flow::Trap, Vec::new()),
            insn(BASE + 0x1007, "c3", "ret", Flow::Return, Vec::new()),
        ];

        let run = |image: &pe::Image| {
            let mut decoded_from: Vec<u64> = Vec::new();
            let found = scan(
                image,
                &imports,
                InstructionSet::Amd64,
                |at, _| {
                    decoded_from.push(at);
                    (at == BASE + 0x1000).then(|| block.clone())
                },
                never,
            );
            (found, decoded_from)
        };

        let (found, overlapped) = run(&image);
        assert_eq!(
            found.sinks[0].call_site_count, 1,
            "the overlapping range is not counted twice: {:?}",
            found.sinks
        );
        assert_eq!(found.privileged_count, 1, "{:?}", found.privileged);

        // And it costs nothing to decode either: the same image without the duplicate section asks
        // the decoder exactly the same questions. Compared rather than asserted as a literal,
        // because a section is scanned in windows and the number of them is not the point.
        let mut single = image.clone();
        single.sections.pop();
        let (_, plain) = run(&single);
        assert_eq!(
            overlapped, plain,
            "the overlap is skipped, not decoded again: {overlapped:x?}"
        );
    }

    /// The call sites are bounded **in total**, not only per sink.
    ///
    /// A per-group cap is not a bound, which is what this one needed pointing out: sixty-four
    /// libraries times forty-seven curated names is three thousand sinks, so two limits multiplied
    /// out to three quarters of a million locations — every one attributed through an engine call
    /// and serialized. The per-sink cap is still there to stop one name taking the whole budget;
    /// the total is what bounds the answer.
    #[test]
    fn the_call_sites_are_bounded_across_every_sink_together() {
        let mut image = image();
        image.size_of_image = 0x40000;
        image.sections[0].virtual_size = 0x30000;

        // Enough distinct sinks that the per-sink cap alone would allow far more than the total:
        // each gets its own slot, and the scan calls every one of them in turn.
        let names = [
            "memcpy",
            "memmove",
            "RtlCopyMemory",
            "RtlMoveMemory",
            "ProbeForRead",
            "ProbeForWrite",
            "ExAllocatePool2",
            "ExAllocatePool3",
            "MmMapIoSpace",
            "MmMapIoSpaceEx",
            "ZwCreateFile",
            "ZwWriteFile",
            "ZwOpenProcess",
            "ZwOpenProcessToken",
            "SeAccessCheck",
            "SePrivilegeCheck",
            "RtlULongAdd",
            "RtlULongMult",
            "MmGetPhysicalAddress",
            "ObReferenceObjectByHandle",
        ];
        assert!(
            names.len() * MAX_CALL_SITES_PER_SINK > MAX_CALL_SITES_TOTAL,
            "the fixture must be able to cross the total without any one sink crossing its own cap"
        );
        let imports: Vec<pe::Import> = names
            .iter()
            .enumerate()
            .map(|(index, name)| import(name, BASE + 0x3000 + (index as u64 * 8)))
            .collect();

        let found = scan(
            &image,
            &imports,
            InstructionSet::Amd64,
            |at, want| {
                let mut block = Vec::new();
                let mut address = at;
                let mut which = 0usize;
                while address + 6 <= at + want as u64 {
                    block.push(call_slot(
                        address,
                        BASE + 0x3000 + ((which % names.len()) as u64 * 8),
                    ));
                    address += 6;
                    which += 1;
                }
                Some(block)
            },
            never,
        );

        let listed: usize = found.sinks.iter().map(|sink| sink.call_sites.len()).sum();
        let counted: usize = found.sinks.iter().map(|sink| sink.call_site_count).sum();
        assert_eq!(
            listed, MAX_CALL_SITES_TOTAL,
            "the answer is bounded across the sinks together"
        );
        assert!(
            counted > MAX_CALL_SITES_TOTAL,
            "and the counts are not: {counted}"
        );
        assert!(
            found
                .sinks
                .iter()
                .all(|sink| sink.call_sites.len() < MAX_CALL_SITES_PER_SINK),
            "no single sink reached its own cap, so only the total can have stopped this"
        );
    }

    /// An import table that repeats a name is **one** sink, not one per slot.
    ///
    /// This is what bounds the sink list by construction rather than by a number. Keyed by slot, a
    /// crafted table naming `memcpy` in every one of its thousands of entries became thousands of
    /// records to allocate, attribute and serialize — the third way this answer found to be
    /// enormous inside a byte cap that bounds only the work. Keyed by library and name it is one
    /// record with a slot count, and a real image, which imports a name once per library, is
    /// unaffected either way.
    #[test]
    fn an_import_table_that_repeats_a_name_is_one_sink() {
        let image = image();
        let imports: Vec<pe::Import> = (0..MAX_SLOTS_PER_SINK * 4)
            .map(|index| import("memcpy", BASE + 0x3000 + (index as u64 * 8)))
            .collect();

        let found = scan(&image, &imports, InstructionSet::Amd64, |_, _| None, never);
        assert_eq!(
            found.sinks.len(),
            1,
            "one name, one sink: {:?}",
            found.sinks
        );
        let sink = &found.sinks[0];
        assert_eq!(sink.slot_count, imports.len(), "the count is exact");
        assert_eq!(
            sink.slots.len(),
            MAX_SLOTS_PER_SINK,
            "and the list is bounded"
        );
        assert_eq!(
            found.other_imports, 0,
            "every one of them is the same sink, not an unlisted import"
        );

        // The same name from a *different* library is a different import and stays separate.
        let mut two = imports.clone();
        two.push(pe::Import {
            library: "hal.dll".to_string(),
            name: pe::ImportName::Named("memcpy".to_string()),
            slot: BASE + 0x3900,
        });
        let found = scan(&image, &two, InstructionSet::Amd64, |_, _| None, never);
        assert_eq!(found.sinks.len(), 2, "{:?}", found.sinks);
    }

    /// A section beginning **outside** the image is recorded, not skipped.
    ///
    /// Skipped, its whole declared range vanished from both lists and the report read as a
    /// complete clean scan of an image whose headers do not hold together — the same silence the
    /// unreadable windows above were leaving, reached through the other half of the bounds check.
    #[test]
    fn a_section_beginning_outside_the_image_is_recorded() {
        let mut image = image();
        image.sections[0].rva = 0x9000;

        let found = scan(
            &image,
            &[],
            InstructionSet::Amd64,
            |_, _| panic!("nothing outside the image is read"),
            never,
        );
        assert!(found.scanned.is_empty(), "{:?}", found.scanned);
        assert_eq!(
            found.unreadable.len(),
            1,
            "the section is unavailable, and says so: {:?}",
            found.unreadable
        );
        assert_eq!(found.unreadable[0].section, ".text");
        assert_eq!(found.unreadable[0].bytes, 0x100);
    }

    /// A halt stops the scan and is reported, rather than leaving a partial answer that reads like
    /// a whole one.
    #[test]
    fn a_halt_stops_the_scan_and_says_so() {
        let image = image();
        let mut polls = 0;
        let found = scan(
            &image,
            &[],
            InstructionSet::Amd64,
            |at, _| Some(vec![insn(at, "90", "nop", Flow::Fallthrough, Vec::new())]),
            || {
                polls += 1;
                (polls > 1).then_some(Halt::Interrupted)
            },
        );
        assert_eq!(found.halted, Some(Halt::Interrupted));
    }
}
