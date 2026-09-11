//! What a driver's code can *do*, read off the image rather than off its behaviour.
//!
//! Two questions, and both are answered from facts rather than from heuristics. **Which sensitive
//! APIs does it import, and where is each called from** — named through the import table, so a
//! stripped third-party driver answers as well as one with a PDB. And **which privileged
//! instructions does it contain** — `rdmsr`, `out`, `mov cr3`, the ones a driver is the only thing
//! that can execute, decoded from the encoding rather than matched in a rendering.
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
//! Like [`crate::pe`] and [`crate::driver`], every entry point takes closures rather than a
//! `DebugEngine`: one to decode a range of instructions, one to ask whether to stop. The worker
//! supplies the two that touch DbgEng; the tests supply fixtures.

use std::collections::BTreeMap;

use dbgscope::dbgeng::{Flow, Instruction, Operand};

use crate::pe;
use crate::walk::Halt;

/// The version of the sink list a scan was taken with.
///
/// **Carried in every result**, because what counts as a sensitive API is a curated opinion rather
/// than a fact about Windows: a result quoted in a report six months from now can be checked
/// against the list that produced it. Bump it whenever [`SINKS`] changes at all — an addition
/// changes what a scan finds as surely as a removal does.
pub const SINK_LIST_VERSION: &str = "1";

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
}

impl PrivilegeKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::ModelSpecificRegister => "model_specific_register",
            Self::PortIo => "port_io",
            Self::ControlRegister => "control_register",
            Self::DescriptorTable => "descriptor_table",
            Self::MachineState => "machine_state",
        }
    }
}

/// The instruction's privilege, from its **mnemonic and operands** rather than its rendering.
///
/// `mov cr3, rax` and `mov rax, rbx` share a mnemonic, so the control-register case is decided by
/// an operand being a control or debug register — which is a field here, not a substring of a
/// printed line.
fn privilege_kind(instruction: &Instruction) -> Option<PrivilegeKind> {
    let control_register = || {
        instruction.operands.iter().any(|operand| match operand {
            Operand::Register(name) => {
                let name = name.as_str();
                (name.starts_with("cr") || name.starts_with("dr"))
                    && name[2..].chars().all(|c| c.is_ascii_digit())
                    && name.len() > 2
            }
            _ => false,
        })
    };
    match instruction.mnemonic.as_str() {
        "rdmsr" | "wrmsr" => Some(PrivilegeKind::ModelSpecificRegister),
        "in" | "out" | "insb" | "insw" | "insd" | "outsb" | "outsw" | "outsd" => {
            Some(PrivilegeKind::PortIo)
        }
        "mov" if control_register() => Some(PrivilegeKind::ControlRegister),
        "lgdt" | "lidt" | "lldt" | "ltr" | "sgdt" | "sidt" => Some(PrivilegeKind::DescriptorTable),
        "hlt" | "invd" | "wbinvd" | "invlpg" | "swapgs" | "xsetbv" | "rdpmc" => {
            Some(PrivilegeKind::MachineState)
        }
        _ => None,
    }
}

/// One sensitive import the driver holds, and where it is called from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sink {
    pub library: String,
    pub name: String,
    pub kind: SinkKind,
    /// The IAT slot a call to it goes through — the coordinate a call site is matched by.
    pub slot: u64,
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
/// See [`MAX_CALL_SITES_PER_SINK`].
pub const MAX_PRIVILEGED: usize = 1024;

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
    mut decode: impl FnMut(u64, usize) -> Option<Vec<Instruction>>,
    mut halt: impl FnMut() -> Option<Halt>,
) -> Scan {
    let by_slot = pe::imports_by_slot(imports);
    let mut sinks: BTreeMap<u64, Sink> = BTreeMap::new();
    let mut other_imports = 0usize;
    for import in imports {
        match (&import.name, sink_kind(&import.name.to_string())) {
            (pe::ImportName::Named(name), Some(kind)) => {
                sinks.insert(
                    import.slot,
                    Sink {
                        library: import.library.clone(),
                        name: name.clone(),
                        kind,
                        slot: import.slot,
                        call_sites: Vec::new(),
                        call_site_count: 0,
                    },
                );
            }
            _ => other_imports += 1,
        }
    }

    let mut privileged = Vec::new();
    let mut privileged_count = 0usize;
    let mut scanned = Vec::new();
    let mut unreadable: Vec<Scanned> = Vec::new();
    let mut budget = MAX_SCAN_BYTES;
    let mut halted = None;
    let mut cap_hit = false;

    'sections: for section in image.code_sections() {
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

        let mut at = start;
        // One entry per **contiguous** decoded run rather than one per section. A section with a
        // hole in it used to come back as a single range starting where the section starts and
        // counting only the bytes that read — a shape that cannot say where the hole was, and
        // whose `start` is wrong for everything after it.
        let mut run: Option<(u64, u64)> = None;
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
            if block.is_empty() {
                close(&mut run, &mut scanned);
                break;
            }
            for instruction in &block {
                if let Some(import) = by_slot.get(&called_slot(instruction).unwrap_or(0))
                    && let Some(sink) = sinks.get_mut(&import.slot)
                {
                    // Counted always, listed up to the cap: the count is the fact and the list is
                    // a sample of it.
                    sink.call_site_count += 1;
                    if sink.call_sites.len() < MAX_CALL_SITES_PER_SINK {
                        sink.call_sites.push(instruction.address);
                    }
                }
                if let Some(kind) = privilege_kind(instruction) {
                    privileged_count += 1;
                    if privileged.len() < MAX_PRIVILEGED {
                        privileged.push(Privileged {
                            address: instruction.address,
                            kind,
                            mnemonic: instruction.mnemonic.clone(),
                        });
                    }
                }
            }
            // Resume after the last instruction that decoded whole, not at a fixed stride: a
            // window's tail is usually a partial instruction, and restarting at `at + want` would
            // decode the next window from the middle of one.
            let last = block.last().expect("the block is not empty");
            let next = last.address.saturating_add(instruction_len(last));
            let consumed = next.saturating_sub(at);
            if consumed == 0 {
                close(&mut run, &mut scanned);
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
                slot: structured::addr(sink.slot),
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
    let mut out = format!(
        "Driver hazards: {} at {}\n  sink list v{}\n",
        report.module, report.base, report.sink_list_version
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
                sink.name, sink.kind, sink.call_site_count
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
                found.mnemonic, found.kind, rva
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
            report.unnamed_libraries.join(", ")
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
    use super::*;
    use dbgscope::dbgeng::MemoryOperand;

    const BASE: u64 = 0xffff_f800_0000_0000;

    /// An image with one executable section and one that is not.
    fn image() -> pe::Image {
        pe::Image {
            base: BASE,
            bitness: pe::Bitness::Bits64,
            machine: 0x8664,
            size_of_image: 0x4000,
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
                base: Some("rip".to_string()),
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
                vec![Operand::Register("rax".to_string())],
            ),
            // Loading the slot is not calling through it: the driver takes the pointer's value,
            // which is a different fact and must not be reported as a call site.
            insn(
                BASE + 0x1014,
                "488b0500000000",
                "mov",
                Flow::Fallthrough,
                vec![
                    Operand::Register("rax".to_string()),
                    Operand::Memory(MemoryOperand {
                        size: Some(8),
                        segment: None,
                        base: Some("rip".to_string()),
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
                    base: Some("rip".to_string()),
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
            insn(
                BASE + 0x1000,
                "0f20d8",
                "mov",
                Flow::Fallthrough,
                vec![
                    Operand::Register("rax".to_string()),
                    Operand::Register("cr3".to_string()),
                ],
            ),
            insn(
                BASE + 0x1003,
                "4889d8",
                "mov",
                Flow::Fallthrough,
                vec![
                    Operand::Register("rax".to_string()),
                    Operand::Register("rbx".to_string()),
                ],
            ),
            insn(
                BASE + 0x1006,
                "0f32",
                "rdmsr",
                Flow::Fallthrough,
                Vec::new(),
            ),
            insn(
                BASE + 0x1008,
                "ee",
                "out",
                Flow::Fallthrough,
                vec![
                    Operand::Register("dx".to_string()),
                    Operand::Register("al".to_string()),
                ],
            ),
            insn(
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
        let found = scan(&image, &[], |_, _| None, never);
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
            |at, _| Some(vec![insn(at, "90", "nop", Flow::Fallthrough, Vec::new())]),
            || {
                polls += 1;
                (polls > 1).then_some(Halt::Interrupted)
            },
        );
        assert_eq!(found.halted, Some(Halt::Interrupted));
    }
}
