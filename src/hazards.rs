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

use dbgscope::dbgeng::{Effect, Flow, Instruction, InstructionSet, Operand, Privilege};

use crate::codewalk;
// Re-exported rather than aliased at every use: this module's public result still carries
// these ranges, and a caller of `scan` should not have to know which module owns the type.
pub use crate::codewalk::Scanned;
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

/// The family's name on the wire and in the rendering.
///
/// **An exhaustive match over dbgscope's own families**, so a family it adds fails this build
/// rather than reaching a client unnamed. The names are this server's rather than the type's, which
/// is why they are spelled here and not derived from it: a rename in the library is not a change to
/// what a client was told to expect.
pub fn privilege_name(kind: Privilege) -> &'static str {
    match kind {
        Privilege::PortIo => "port_io",
        Privilege::ModelSpecificRegister => "model_specific_register",
        Privilege::ControlRegister => "control_register",
        Privilege::DescriptorTable => "descriptor_table",
        Privilege::InterruptFlag => "interrupt_flag",
        Privilege::CacheOrTlb => "cache_or_tlb",
        Privilege::Virtualization => "virtualization",
        Privilege::Other => "other",
    }
}

/// Whether an instruction is reported, and under which family: **the decoder's answer**, plus one
/// judgement of this module's own.
///
/// Both halves of the decoder's answer used to be tables here, and a table is wrong by
/// construction. Membership went first ([dbgscope#151]): a driver holding `cli`, `clts`, `lmsw` or
/// a VMX operation was reported as holding no privileged instruction, which is the one answer this
/// must never reach through omission. The family went with [dbgscope#153], for the same reason one
/// level down -- a privileged instruction the table did not name lost its family -- and for one of
/// its own: a family table is one architecture's vocabulary, and the namespaces collide. x86's `str`
/// stores the task register, and A64's stores a register to memory; read in one namespace, a scan
/// of an ARM64 `nt` called **every store** a descriptor-table access, 59,450 privileged
/// instructions in all. [`Instruction::privilege`] is answered from the encoding on each
/// architecture, so neither question is asked here any more.
///
/// **What is left is a judgement, and it is x86's alone.** `sgdt`, `sidt`, `sldt` and `str` read the
/// descriptor tables, need no privilege -- the decoder says so, correctly, and gives them no family
/// -- and are reported anyway, because a driver reading the GDT from wherever it runs is worth
/// seeing. That is a choice about what a hazard report shows, which is why it lives here rather
/// than in the decoder. It is asked of x86 and x64 only, which is the collision above: on A64 the
/// same spelling is a store.
///
/// [dbgscope#151]: https://github.com/glslang/dbgscope/pull/151
/// [dbgscope#153]: https://github.com/glslang/dbgscope/issues/153
fn privilege_kind(instruction: &Instruction, set: InstructionSet) -> Option<Privilege> {
    instruction.privilege.or_else(|| match set {
        InstructionSet::X86 | InstructionSet::Amd64 => matches!(
            instruction.mnemonic.as_str(),
            "sgdt" | "sidt" | "sldt" | "str"
        )
        .then_some(Privilege::DescriptorTable),
        InstructionSet::Arm64 | InstructionSet::Other(_) => None,
    })
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

/// Whether the image's own unwind table has an entry covering a finding's address.
///
/// **The answer to [#303](https://github.com/glslang/windbg-mcp/issues/303), and the reason it is
/// a field rather than a filter.** An executable section is not all instructions: a compiler puts
/// jump tables, `TraceLogging` metadata, import descriptors, string literals and alignment padding
/// in `.text`, and a linear decode spells those bytes as code and reports what they happen to say.
/// Four of the one-byte x86 port-I/O opcodes are ASCII letters — `6c`–`6f` are `l`, `m`, `n`, `o` —
/// so a string in `.text` reads as `insb`/`outsd` all day.
///
/// What tells the two apart with no symbols and no guesswork is the image's **unwind table**: the
/// `RUNTIME_FUNCTION` records in `.pdata`, which the x64 and ARM64 ABIs oblige a compiler to emit
/// for the code it generates, and which a stripped third-party driver carries exactly as a Microsoft
/// one does. It is read-only, so it is in a dump for the same reason the code is.
///
/// **Measured, and it splits the two populations almost perfectly.** Over the 2,994 findings one
/// scan of `docs/samples/081226-2187-01.dmp` listed: of the 1,434 that are `ins`/`outs` —
/// the opcodes a string literal spells — **1,405 have no entry** covering them, while of the other
/// 1,560, **1,453 are inside one**. By module, the concentration is the point: `tpm` 623 of 638
/// uncovered, `DTrace` 879 of 880, and `nt` **0 of 5,535**. Cross-checked against the engine's own
/// `.fnent` over every one of those findings — the two classifications agree on all 34 modules
/// that have any, with no mismatch.
///
/// **Three outcomes rather than a `bool`**, for the reason `dbgscope`'s own `FunctionExtent` gives:
/// collapsing them lets a reader take "not answered" for "not code".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Standing {
    /// An unwind entry covers this address: the compiler emitted a function here.
    ///
    /// **Not a guarantee the byte is an instruction.** A jump table embedded inside a function's
    /// own region is covered by its entry, so this narrows the question rather than settling it.
    /// It is the default because it is the expected answer for real code, and what the wire omits.
    #[default]
    InFunction,
    /// No unwind entry covers it, which has three readings and this cannot choose between them:
    /// data in an executable section (the case that motivates the field), code nobody emitted an
    /// unwind record for, or an unwind table that could not be read.
    ///
    /// So it is a **qualification and not a verdict**: these findings are listed and counted, and
    /// nothing here calls them fabricated. The second reading is not hypothetical, which is what
    /// settled it — measured on `docs/samples/082126-7015-01.dmp`, 240 of ARM64 `nt`'s 1,373
    /// findings have no entry, and the first of them is `nt!HalpStartupStub`, hand-written
    /// assembly whose `mrs x1,DAIF` and `msr daifset,#1` are exactly what this tool is for. A
    /// filter would have dropped them.
    NoUnwindEntry,
    /// The question was not answered at all, so the finding is neither placed in a function nor
    /// out of one. x86 lands here — 32-bit Windows has no unwind table, so there is nothing to ask
    /// — as does a target whose entry layout this build does not decode, and an engine that failed
    /// the query.
    ///
    /// **x86 therefore keeps the whole of issue #303**, and this says so rather than implying a
    /// coverage it has not got: measured on `docs/samples/cppthrow-fastfail-x86.dmp`, the 32-bit
    /// `ntdll` reports 10,623 privileged instructions, every one of them counted in
    /// [`Scan::unverified_privileged`] and none in the other two. Nothing was filtered and nothing
    /// was claimed, which is the same answer that image got before this field existed.
    Unverified,
}

impl Standing {
    /// A short label for a rendering, and the `snake_case` a typed result carries.
    pub fn name(self) -> &'static str {
        match self {
            Self::InFunction => "in_function",
            Self::NoUnwindEntry => "no_unwind_entry",
            Self::Unverified => "unverified",
        }
    }
}

/// One privileged instruction, and what it reaches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Privileged {
    pub address: u64,
    pub kind: Privilege,
    /// The mnemonic, for a reader who wants to know which of the family it was.
    pub mnemonic: String,
    /// What the image's unwind table says about this address. See [`Standing`].
    pub standing: Standing,
}

/// What a scan found, and how much of the image it looked at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scan {
    pub sinks: Vec<Sink>,
    /// The privileged instructions found, in address order.
    ///
    /// **Two budgets on one list**, [`MAX_PRIVILEGED`] and [`MAX_UNCOVERED_PRIVILEGED`], so that
    /// the findings an unwind entry covers and the ones it does not cannot push each other out of
    /// it: a module like the sample dump's `DTrace`, whose 880 findings are 879 bytes of data an
    /// unwind entry does not cover, would otherwise spend a single budget on noise and list none
    /// of the code. [`Standing::Unverified`] shares the first budget, because it is the standing
    /// of a finding that is **not** known to be data — on x86 it is every finding, and a budget of
    /// its own would have to be the full one anyway.
    pub privileged: Vec<Privileged>,
    /// How many were found, which is exact however many are listed above.
    ///
    /// The sum of the three counts below, which is the same arithmetic [`crate::structured::Xrefs`]
    /// states between `site_count` and its three kinds.
    pub privileged_count: usize,
    /// How many are in a region the image's unwind table covers — [`Standing::InFunction`].
    pub in_function_privileged: usize,
    /// How many are in bytes **no unwind entry covers** — [`Standing::NoUnwindEntry`].
    ///
    /// What says how much of [`Self::privileged_count`] is a linear decode's reading of data
    /// rather than of code.
    pub uncovered_privileged: usize,
    /// How many the unwind table could not be asked about at all — [`Standing::Unverified`].
    ///
    /// **A count of its own rather than folded into [`Self::in_function_privileged`]**, which is
    /// where it was until review on #468 found what that costs. Folded, a finding whose query
    /// failed was counted among the ones *known* to be code, and past the shared list budget its
    /// row was dropped as well — so a renderer looking for the standing among the listed rows found
    /// none and said nothing. An unanswered question counted as an answer, which is the one shape
    /// this module's doc comment says the result must never take.
    ///
    /// It is counted for every finding, so it is exact even where the shared budget left no row to
    /// show for it, and that is the case it exists for.
    pub unverified_privileged: usize,
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
    ///
    /// Every one of them was **asked** the question. An import that could not be asked is in
    /// [`Self::ordinal_imports`] instead.
    pub other_imports: usize,
    /// Imports named by **ordinal**, which the curated list cannot be asked about at all.
    ///
    /// This image carries the ordinal and no name for it, so there is nothing here to match
    /// against a name-keyed list. **Nor need a name exist anywhere**: an export declared `NONAME`
    /// is in no export-name table, so for those the question is unanswerable rather than answered
    /// in another image. Counted apart from
    /// [`Self::other_imports`] because folding the two made a driver importing a sensitive export
    /// by ordinal report as "Sensitive imports: none on the list" with that import counted among
    /// the ones that had been checked -- a question never asked, rendered as an answer.
    ///
    /// Resolving the ordinal is not attempted, and would not always succeed if it were: it needs
    /// the exporting module loaded and readable in this session, and then a name to find. This
    /// count is exact either way, and `docs/limitations.md` carries the boundary.
    pub ordinal_imports: usize,
    /// Which framework this image binds to, where one of its imports said so.
    ///
    /// Read from the same import table the sinks are, so it costs nothing and is exact whenever the
    /// table was read at all. It is **not** qualified by `unnamed_libraries`: an answer here is
    /// positive evidence, and its absence is reported as nothing rather than as a negative, so a
    /// bound import table that hid the tell costs a qualification rather than producing a wrong one.
    pub framework: Option<crate::framework::Framework>,
    /// Libraries whose imports could not be named at all, carried through from the import table.
    pub unnamed_libraries: Vec<String>,
    /// Where the imports were named from; the caller that read them sets it.
    pub imports_named_from: crate::structured::ImportsNamedFrom,
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
/// See [`MAX_CALL_SITES_PER_SINK`]. The budget for findings an unwind entry covers, and for the
/// ones no unwind table could be asked about.
pub const MAX_PRIVILEGED: usize = 1024;
/// The budget [`Standing::NoUnwindEntry`] findings have **of their own**, on the same list.
///
/// **A second budget rather than a share of the first**, because the two populations are not
/// competing for a reader's attention — a reader wants the code findings, and enough of the
/// uncovered ones to check the qualification against. Measured on `docs/samples/081226-2187-01.dmp`:
/// `DTrace` finds 880 privileged instructions of which 879 are uncovered, so one budget spent in
/// address order lists the data and drops the one real finding. Small, because a sample is all
/// these are for: the count beside them is the fact.
pub const MAX_UNCOVERED_PRIVILEGED: usize = 128;
/// See [`MAX_CALL_SITES_PER_SINK`]. One in every real image; more means a repeated name.
pub const MAX_SLOTS_PER_SINK: usize = 16;

/// Scans an image's executable sections for sensitive calls and privileged instructions.
///
/// `decode` takes an address and a length and answers the instructions in it, or `None` where the
/// bytes could not be read — which is a fact about the image rather than an error, and leaves that
/// window out of [`Scan::scanned`]. `halt` is polled between windows. Both are handed to
/// [`codewalk::walk_code`], which owns the section walk, the window boundaries and the two
/// budgets; what stays here is the per-instruction reading.
///
/// `standing` answers what the image's unwind table says about one address, and is asked **once
/// per privileged finding** — including the ones past a list budget, since the three counts
/// [`Scan::privileged_count`] is the sum of are counts and a count is exact. See [`Standing`] for what it
/// buys and why a caller that cannot answer returns [`Standing::Unverified`] rather than guessing.
/// It is a closure for the reason the other two are: the worker's reaches an engine, and a test's
/// is a fixture.
pub fn scan(
    image: &pe::Image,
    imports: &[pe::Import],
    set: InstructionSet,
    decode: impl FnMut(u64, usize) -> Option<Vec<Instruction>>,
    halt: impl FnMut() -> Option<Halt>,
    mut standing: impl FnMut(u64) -> Standing,
) -> Scan {
    let by_slot = pe::imports_by_slot(imports);
    // **Keyed by library and name, not by slot**, which is what bounds this list by construction:
    // a crafted table repeating one sensitive name across half a million slots is one sink with a
    // slot count, where keying by slot made it half a million records to allocate, attribute and
    // serialize. A real image has one slot per name per library, so the two keyings agree on
    // everything anyone actually scans.
    let mut sinks: BTreeMap<(String, String), Sink> = BTreeMap::new();
    let mut other_imports = 0usize;
    let mut ordinal_imports = 0usize;
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
            // **Not `other_imports`**, which would say this import was checked against the list
            // and is not on it. An ordinal carries no name in this image, so it was never
            // checked, and the two cases must not look alike -- the one that matters is a
            // sensitive export imported by ordinal, which is exactly where the fold said
            // "none on the list".
            (pe::ImportName::Ordinal(_), _) => ordinal_imports += 1,
            _ => other_imports += 1,
        }
    }

    let mut privileged = Vec::new();
    let mut privileged_count = 0usize;
    // One exact count per standing, which is what keeps an unanswered query from being counted as
    // an answer -- see `Scan::unverified_privileged`. Three counters matched exhaustively rather
    // than an array indexed by the discriminant, so a fourth standing is a compile error here
    // rather than a count nothing takes.
    let mut in_function_privileged = 0usize;
    let mut uncovered_privileged = 0usize;
    let mut unverified_privileged = 0usize;
    // The two list budgets, counted apart. One list, so it stays in address order; two counters,
    // so the uncovered findings cannot spend the covered ones' budget or be spent by them.
    let mut listed_covered = 0usize;
    let mut listed_uncovered = 0usize;
    let mut listed_call_sites = 0usize;
    // The addresses this code has been watched computing, for the calls that reach an import
    // through a register rather than through a memory operand. Cleared at every discontinuity the
    // walk reports, so a register's meaning never crosses a section boundary or an unreadable page.
    let mut formed = Formed::default();

    let covered = codewalk::walk_code(image, decode, halt, |step| {
        let instruction = match step {
            // Nothing a register held survives a break: what is on the far side of an unreadable
            // page, or at the start of the next section, is not the next instruction of anything.
            codewalk::Step::Break => return formed.clear(),
            codewalk::Step::At(instruction, _) => instruction,
        };
        // The slot the call names, or -- where the architecture cannot name one -- the slot this
        // watched being computed into the register it calls through.
        let slot = called_slot(instruction).or_else(|| formed.slot_of(instruction));
        if let Some(import) = by_slot.get(&slot.unwrap_or(0))
            && let Some(sink) = sinks.get_mut(&(import.library.clone(), import.name.to_string()))
        {
            // Counted always, listed up to the cap: the count is the fact and the list is a
            // sample of it.
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
            // **Asked for every finding, not for every listed one.** The per-standing counts are
            // counts, and a count that stopped being taken at a list's cap would report a module
            // whose findings are all data as one whose first thousand are.
            let standing = standing(instruction.address);
            match standing {
                Standing::InFunction => in_function_privileged += 1,
                Standing::NoUnwindEntry => uncovered_privileged += 1,
                Standing::Unverified => unverified_privileged += 1,
            }
            let (listed, cap) = if standing == Standing::NoUnwindEntry {
                (&mut listed_uncovered, MAX_UNCOVERED_PRIVILEGED)
            } else {
                (&mut listed_covered, MAX_PRIVILEGED)
            };
            if *listed < cap {
                *listed += 1;
                privileged.push(Privileged {
                    address: instruction.address,
                    kind,
                    mnemonic: instruction.mnemonic.clone(),
                    standing,
                });
            }
        }
        // **After the reads above, not before**: the call is the last step of the sequence this
        // watches, and applying it first would clear the register the call reaches the slot
        // through.
        formed.apply(instruction);
        // And nothing survives a terminator. The sequence is three adjacent instructions, so this
        // costs almost nothing and is what keeps a slot from being attributed to a `blr` on an
        // unrelated path.
        if !matches!(instruction.flow, Flow::Fallthrough) {
            formed.clear();
        }
    });

    Scan {
        sinks: sinks.into_values().collect(),
        privileged,
        privileged_count,
        in_function_privileged,
        uncovered_privileged,
        unverified_privileged,
        scanned: covered.scanned,
        unreadable: covered.unreadable,
        other_imports,
        ordinal_imports,
        // Over the whole table, not over the sinks: the bind routine is not a sink and never will
        // be -- it is how a driver *loads*, not something it does to a caller's buffer.
        framework: crate::framework::client_of(imports),
        unnamed_libraries: Vec::new(),
        imports_named_from: crate::structured::ImportsNamedFrom::ImportDirectory,
        halted: covered.halted,
        cap_hit: covered.cap_hit,
    }
}

/// Imports named from the exports their import-address-table slots are bound to, and how many
/// slots named nothing.
///
/// For a driver whose import directory the loader freed; see
/// [`crate::structured::ImportsNamedFrom`] for why naming the bound address names the import.
/// `exported_at` answers, for a bound address, the library the exporting module gives itself and
/// the names that module exports at that address -- read from its **export table**, not from
/// symbols, because a symbol at an exported address need not be the export's name. A slot whose
/// address no module exports is counted, never guessed.
///
/// **Where several names share the address, the one on the sink list is taken where there is one.**
/// The slot is one import and only one of those names was imported, but they are one function: a
/// call through the slot reaches the same code whichever name it was linked against, so a
/// sensitive alias is the right name for it rather than an arbitrary one that hides it.
///
/// Engine-free, so it is tested off a target: the worker reads the exports and hands them in.
pub fn imports_from_bound_slots(
    slots: &[pe::IatSlot],
    mut exported_at: impl FnMut(u64) -> Option<(String, Vec<String>)>,
) -> (Vec<pe::Import>, usize) {
    let mut imports = Vec::new();
    let mut unnamed = 0;
    for slot in slots {
        let named = exported_at(slot.value).and_then(|(library, names)| {
            let name = names
                .iter()
                .find(|name| sink_kind(name).is_some())
                .or_else(|| names.first())?
                .clone();
            Some((library, name))
        });
        match named {
            Some((library, name)) => imports.push(pe::Import {
                library,
                name: pe::ImportName::Named(name),
                slot: slot.slot,
            }),
            None => unnamed += 1,
        }
    }
    (imports, unnamed)
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
/// **It cannot invent an address, which is not the same as not inventing a call site**, and the
/// first draft of this claimed the second on the strength of the first. Matching an exact IAT slot
/// stops a *misread* sequence naming an import; it does nothing about a correctly read slot being
/// attributed to a `blr` that never held it. State that outlives the straight-line run which
/// formed it does exactly that -- one path forms an import pointer in `x8`, an unrelated one later
/// in the section executes `blr x8`, and the second is reported as calling the first's import.
/// Raised on windbg-mcp#343 by both reviewers.
///
/// So the state is carried **only along contiguous fallthrough**. Anything else -- a return, a
/// branch taken or not, a direct call clobbering the caller-saved registers, a window that would
/// not decode -- drops all of it. That is nearly free in practice: `adrp` / `ldr` / `blr` is three
/// adjacent instructions in every image, which is the whole sequence this exists to read.
///
/// Nothing about it is ARM64-specific either: `lea rax,[rip+X]` / `mov rax,[rax+8]` / `call rax`
/// is the same three steps and the same answer, and x64 compilers do emit it.
///
/// What it does not reach is a pair split across a decode window, the maps starting empty on each
/// one. A missed call site, never an invented one, which is the direction every shortfall here
/// goes.
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

    /// Everything this has watched, forgotten.
    ///
    /// Called wherever straight-line execution stops being a fact: a terminator of any kind, and a
    /// window that would not decode. A register's meaning does not survive the instruction that
    /// jumped away from it.
    fn clear(&mut self) {
        self.address.clear();
        self.loaded_from.clear();
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
                kind: privilege_name(found.kind).to_string(),
                mnemonic: found.mnemonic.clone(),
                standing: found.standing.name().to_string(),
            })
            .collect(),
        privileged_count: scan.privileged_count,
        in_function_privileged: scan.in_function_privileged,
        uncovered_privileged: scan.uncovered_privileged,
        unverified_privileged: scan.unverified_privileged,
        scanned: scan.scanned.iter().map(codewalk::range_report).collect(),
        unreadable: scan.unreadable.iter().map(codewalk::range_report).collect(),
        other_imports: scan.other_imports,
        ordinal_imports: scan.ordinal_imports,
        // The import tell, and only it: this end has read no driver object and no dispatch table, so
        // it must not claim the second tell, and `Table::Unread` is what says so in the note.
        // `driver_surface` is where the two are composed, and it passes a different `Table` --
        // having read one -- which is why that end cannot reuse this answer.
        framework: scan.framework.map(|framework| {
            crate::framework::client_report(framework, true, crate::framework::Table::Unread)
        }),
        unnamed_libraries: scan.unnamed_libraries.clone(),
        imports_named_from: scan.imports_named_from.clone(),
        stopped: scan.halted.map(|halt| match halt {
            Halt::Deadline => structured::WalkHalt::Deadline,
            Halt::Interrupted => structured::WalkHalt::Interrupted,
        }),
        cap_hit: scan.cap_hit,
    }
}

/// One of this rendering's long lines, folded to the width and continuation indent every other
/// sentence in this file is hand-wrapped to.
///
/// **A helper rather than more `\n           \` in a literal**, because the three group headings
/// below are built from a count and a clause and so cannot be wrapped by hand at all — the width
/// of the count moves the break. Breaks on whitespace only, so an over-long word runs past the
/// margin rather than being cut; nothing here produces one, and truncating a mnemonic would be the
/// worse failure.
fn wrapped(line: &str) -> String {
    // The two columns every other line of this rendering uses: where a label starts, and where a
    // continuation of it aligns. `line` carries neither, because `split_whitespace` below would
    // eat the first and nothing would restore it -- which it did, until `tm`'s rendering came back
    // with its headings flush against the margin and every assertion still green.
    const WIDTH: usize = 96;
    const LABEL: &str = "  ";
    const INDENT: &str = "           ";
    let mut out = String::from(LABEL);
    let mut at = LABEL.len();
    for word in line.split_whitespace() {
        if at == LABEL.len() {
            out.push_str(word);
        } else if at + 1 + word.chars().count() > WIDTH {
            out.push('\n');
            out.push_str(INDENT);
            out.push_str(word);
            at = INDENT.len();
        } else {
            out.push(' ');
            out.push_str(word);
            at += 1;
        }
        at += word.chars().count();
    }
    out.push('\n');
    out
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

    // What this image is, before what it holds: a reader of a framework driver's hazards is usually
    // on their way to its dispatch routine, and that is in another image.
    //
    // **The word, not the note**, which is the one place in this change that prints less than it
    // knows. Two reasons, and the second is the one that decided it: this renderer is embedded whole
    // inside `surface::render`, which prints the note at the top of the same answer, so the long form
    // here is a second copy of one fact in one reply -- and what a framework costs a *hazard* scan is
    // nothing, since the imports and the privileged instructions are this image's either way. The
    // note travels in `framework.note` for the readers that are served values rather than text.
    if let Some(framework) = &report.framework {
        out.push_str(&format!("  framework {}\n", framework.framework));
    }

    // Said above the findings rather than below them, because it changes what an empty list means:
    // a caveat has to arrive before the conclusion it qualifies.
    //
    // **Code that would not read gets its own line**, separate from a halt and from the cap,
    // because it is a different fact with a different remedy: the scan ran to the end and part of
    // the driver was simply not there. Without it, a dump missing one page prints "Privileged
    // instructions: none" and nothing anywhere says a page was missing.
    //
    // **Two remedies, because the line now reaches a live kernel.** Until a freed import directory
    // stopped refusing the scan outright, a live HEVD never got this far; now it does, with five of
    // its six `PAGE` pages absent, and the dump remedy alone told that reader to look for an image
    // the target already has. Measured: one IOCTL down HEVD's dispatch brought one page in.
    if !report.unreadable.is_empty() {
        let bytes: u64 = report.unreadable.iter().map(|range| range.bytes).sum();
        out.push_str(&format!(
            "  INCOMPLETE: {bytes} bytes of this driver's code could not be read, so what is\n           \
             below is what was found rather than what is there. On a dump the image is what\n           \
             supplies those bytes; on a live kernel a pageable section is resident only in the\n           \
             pages its last run touched, so running the driver brings more of it in, and a\n           \
             discardable one is gone.\n"
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
        // Qualified only here, where the sentence inverts: "none on the list" over an import the
        // list was never shown is a negative this answer has not earned.
        //
        // **Either channel, not just the new one.** A bound library's names were never read and an
        // ordinal has no name here to read, and `shortfall` has treated the two alike from the
        // start -- so qualifying one and not the other is worse than qualifying neither, which is
        // what this was: a reader would learn that an unqualified negative means every import was
        // shown, and a bound import table would then be the case that quietly breaks the lesson.
        // **Asked of `shortfall`, which owns the import-side rule**, rather than a second copy of
        // it here: the copy named two channels and the address table's unnamed slots are a third.
        let unasked = if matches!(
            report.shortfall(),
            Some(crate::structured::Shortfall::Imports | crate::structured::Shortfall::Both)
        ) {
            " (of the imports it was shown)"
        } else {
            ""
        };
        out.push_str(&format!("  Sensitive imports: none on the list{unasked}\n"));
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

    // **One group per standing, each headed with its own exact count**, which is the whole of what
    // a text reader gets from issue #303: the groups read identically as rows -- a real `tdcall` and
    // a `jo` that is the fifth byte of a `TraceLogging` blob -- and the only thing that tells them
    // apart is the heading they sit under.
    //
    // **Headed from the counts rather than from the rows**, which is what review on #468 corrected.
    // A single sentence appended when *any* listed row was unplaced said "none of the above is
    // known to be code" over a list whose other rows were confirmed, and it went missing entirely
    // when the shared list budget left no unplaced row to find. A count is exact whether or not a
    // row survived, so it is what decides whether a heading prints and what it says.
    let groups = [
        (
            Standing::InFunction,
            report.in_function_privileged,
            "Privileged instructions",
            "",
        ),
        (
            Standing::NoUnwindEntry,
            report.uncovered_privileged,
            "In bytes no unwind entry covers",
            " — an executable section is not all instructions, and a linear decode spells a jump \
             table, a string or TraceLogging metadata as whatever those bytes happen to say. But \
             code nobody emitted an unwind record for lands here too — hand-written assembly \
             does — so these are listed rather than dropped. Disassemble one before quoting it",
        ),
        (
            Standing::Unverified,
            report.unverified_privileged,
            "Not placed against an unwind table",
            " — this target's unwind entries are not decoded here (x86 has none at all), or the \
             query for them failed, so these are neither known to be code nor known to be data a \
             linear decode read as code",
        ),
    ];
    if report.privileged_count == 0 {
        out.push_str("  Privileged instructions: none\n");
    } else {
        for (standing, count, heading, why) in groups {
            if count == 0 {
                continue;
            }
            let rows: Vec<_> = report
                .privileged
                .iter()
                .filter(|found| found.standing == standing.name())
                .collect();
            // The count is the fact and the rows are a sample of it, so the two are printed apart
            // -- and a group whose rows all fell to a budget still prints its count.
            let listed = match count.saturating_sub(rows.len()) {
                0 => String::new(),
                _ if rows.is_empty() => ", none listed".to_string(),
                _ => format!(", first {} listed", rows.len()),
            };
            out.push_str(&wrapped(&format!("{heading} ({count}{listed}){why}:")));
            for found in rows {
                out.push_str(&format!(
                    "    {:<16} {:<24} {}\n",
                    crate::structured::renderable(&found.mnemonic),
                    found.kind,
                    found.at.rva.as_deref().unwrap_or("?")
                ));
            }
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
    // Beside the bound libraries because it is the same fact in the other channel -- an import
    // this answer could not name, and therefore a sink it may be missing. **One place for the
    // pair**: split across the rendering, the placement would say the two were different kinds of
    // thing. What the ordinal line cannot do here is qualify the sentence above it, so the one
    // sentence whose meaning inverts carries its own qualification where it is printed.
    if report.ordinal_imports > 0 {
        out.push_str(&format!(
            "  Not nameable (imported by ordinal): {} import(s) — this image carries the ordinal\n           \
             and no name, and the exporting image need not associate one with it either (an export\n           \
             declared NONAME has none at all). So the list was never shown them, and the sinks\n           \
             above are a lower bound.\n",
            report.ordinal_imports
        ));
    }
    if let crate::structured::ImportsNamedFrom::ImportAddressTable {
        discarded_section,
        unnamed_slots,
    } = &report.imports_named_from
    {
        out.push_str(&format!(
            "  Imports named from the import address table: the import directory is in `{}`,\n           \
             which the loader discarded, so each is the export its slot is bound to.\n",
            crate::structured::renderable(discarded_section)
        ));
        if *unnamed_slots > 0 {
            out.push_str(&format!(
                "  Not nameable (bound to no export): {unnamed_slots} slot(s), so the sinks above are a\n           \
                 lower bound.\n"
            ));
        }
    }
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
    fn privilege_kind_x86(instruction: &Instruction) -> Option<Privilege> {
        privilege_kind(instruction, InstructionSet::Amd64)
    }

    /// And for an ARM64 one, so a call site says which vocabulary it is asking about.
    fn privilege_kind_arm64(instruction: &Instruction) -> Option<Privilege> {
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
            iat_directory: (0, 0),
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
            privilege: None,
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

    /// The same, for an instruction the **decoder** reports as needing privilege, and the family
    /// it reports with it.
    ///
    /// Separate rather than a sixth parameter on `insn`, because that is the point of the field:
    /// a fixture answers for the decoder here, so every test that means "the decoder said so" has
    /// to say it, and every test that does not gets the honest `false`. And **both fields or
    /// neither**: dbgscope builds `privileged` and `privilege` from one value, so a fixture that
    /// could set one without the other would be standing in for a decoder that does not exist.
    fn privileged_insn(
        family: Privilege,
        address: u64,
        bytes: &str,
        mnemonic: &str,
        flow: Flow,
        operands: Vec<Operand>,
    ) -> Instruction {
        Instruction {
            privileged: true,
            privilege: Some(family),
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

    /// The `standing` fixture for a test that is not about the unwind table: every address is in a
    /// function, which is what a real image's own code answers.
    ///
    /// **Named rather than defaulted**, for the same reason `privileged_insn` is separate from
    /// `insn`: a fixture answers here for something the engine answers on a target, so a call site
    /// says which answer it is standing in for. The two tests that *are* about the table supply
    /// `unplaced` and `no_entry_at` instead.
    fn in_functions(_: u64) -> Standing {
        Standing::InFunction
    }

    /// The fixture for a target whose unwind entries this build does not decode -- x86, which has
    /// no unwind table at all -- and for an engine whose query failed.
    fn unplaced(_: u64) -> Standing {
        Standing::Unverified
    }

    /// The `locate` a test supplies: coordinates invented, because attributing an address is an
    /// engine call and this file has never seen an engine.
    fn invented(address: u64) -> crate::structured::CodeLocation {
        crate::structured::CodeLocation {
            address: crate::structured::addr(address),
            module: Some("vid".to_string()),
            rva: Some("0x0".to_string()),
            attribution_failed: false,
        }
    }

    /// **An import named by ordinal was never shown the list, and is not an import that is not on
    /// it.** The two must not look alike in either half of the answer.
    ///
    /// An ordinal import is a slot this image names with a number and no name, so a name-keyed
    /// list cannot be asked about it at all -- and the name need not exist anywhere, an export
    /// declared `NONAME` being in no export-name table. Counted into `other_imports` -- which
    /// is where it went -- a driver importing a sensitive export by ordinal came back as
    /// "Sensitive imports: none on the list" with that import counted among the ones that had
    /// been checked, and with `shortfall` reporting a scan short of nothing. A question never
    /// asked, rendered as an answer, which is the worst shape this tool's answer can take.
    ///
    /// **Mutation-verified against the fold**: delete the `Ordinal` arm from `scan`'s match and
    /// the ordinal falls into the catch-all. Measured -- the first assertion fails outright,
    /// `ordinal_imports` coming back 0 against 1. A panic stops there, which is why the fold is
    /// asserted in both halves and in the text rather than in one place: under that mutation
    /// `other_imports` is 2, the import-side shortfall is gone (`Both` becomes `Code`, and the
    /// code-read view `None`), and the rendered text loses the ordinal line and carries an
    /// unqualified "none on the list".
    #[test]
    fn an_ordinal_import_is_counted_apart_from_the_imports_that_were_checked() {
        let image = image();
        let by_ordinal = pe::Import {
            library: "ntoskrnl.exe".to_string(),
            name: pe::ImportName::Ordinal(0x2a),
            slot: BASE + 0x3000,
        };
        let found = scan(
            &image,
            &[
                by_ordinal,
                import("KeQueryPerformanceCounter", BASE + 0x3008),
            ],
            InstructionSet::Amd64,
            |_, _| None,
            never,
            in_functions,
        );
        assert_eq!(found.ordinal_imports, 1);
        assert_eq!(
            found.other_imports, 1,
            "the named import is the only one the list was shown"
        );
        assert!(
            found.sinks.is_empty(),
            "neither is a sensitive API: {:?}",
            found.sinks
        );

        let report = structured_report("vid", BASE, &found, invented);
        assert_eq!(report.ordinal_imports, 1);
        assert_eq!(report.other_imports, 1);
        // **Both**, because this test's decoder reads nothing: the code side is short by
        // construction here and says so. What is being asserted is the *import* side, so it is
        // asked again with the code side made whole -- there an ordinal alone is the whole
        // shortfall, which is what a bound library is on its own.
        assert_eq!(report.shortfall(), Some(crate::structured::Shortfall::Both));
        let code_read = crate::structured::DriverHazards {
            unreadable: Vec::new(),
            ..report.clone()
        };
        assert_eq!(
            code_read.shortfall(),
            Some(crate::structured::Shortfall::Imports),
            "an import the list was never shown makes `sinks` a lower bound for the same reason a \
             bound library does, and the typed answer has to say so"
        );

        let text = render(&report);
        assert!(
            text.contains("Not nameable (imported by ordinal): 1 import(s)"),
            "{text}"
        );
        assert!(
            text.contains("none on the list (of the imports it was shown)"),
            "the one line whose meaning inverts is the one that is qualified: {text}"
        );

        // And an image with no ordinal import pays nothing for any of it: the line is absent and
        // the negative is unqualified, which is what keeps the qualification meaningful.
        let named = scan(
            &image,
            &[import("KeQueryPerformanceCounter", BASE + 0x3008)],
            InstructionSet::Amd64,
            |_, _| None,
            never,
            in_functions,
        );
        assert_eq!(named.ordinal_imports, 0);
        let plain = render(&structured_report("vid", BASE, &named, invented));
        assert!(!plain.contains("by ordinal"), "{plain}");
        assert!(
            plain.contains("Sensitive imports: none on the list\n"),
            "{plain}"
        );

        // **And the qualification belongs to the channel, not to this change.** A bound library is
        // the same fact -- names that were never read -- and `shortfall` has always treated it as
        // one, so a negative qualified for an ordinal and bare for a bound import would teach a
        // reader that a bare one means every import was shown. Review on #461 found that
        // asymmetry; it was introduced here, since before this nothing was qualified at all.
        let mut bound = named.clone();
        bound.unnamed_libraries = vec!["FLTMGR.SYS".to_string()];
        let bound = render(&structured_report("vid", BASE, &bound, invented));
        assert!(
            bound.contains("none on the list (of the imports it was shown)"),
            "a bound library earns the same qualification an ordinal does: {bound}"
        );
        assert!(!bound.contains("by ordinal"), "{bound}");
    }

    /// Imports are named from the exports their address-table slots are bound to: by the export
    /// table, choosing a sensitive alias where an address has one, and counting anything else
    /// rather than guessing.
    #[test]
    fn imports_are_named_from_the_exports_their_slots_are_bound_to() {
        let slot = |index: u64, value| pe::IatSlot {
            slot: BASE + 0x3000 + index * 8,
            value,
        };
        let slots = [
            slot(0, 0xa000),
            // Not an address the module exports: part-way into a function, or not a function.
            slot(1, 0xa108),
            // In no module at all.
            slot(2, 0xb000),
            // Two names at one address, one of them a sink: the sink is the name.
            slot(3, 0xc000),
            // Two names, neither a sink: the first the table lists.
            slot(4, 0xd000),
        ];
        let exported_at = |address: u64| {
            let names: &[&str] = match address {
                0xa000 => &["ExAllocatePoolWithTag"],
                0xc000 => &["AnAliasOfTheAllocator", "ExAllocatePool2"],
                0xd000 => &["RtlInitUnicodeString", "AnotherName"],
                _ => return None,
            };
            Some((
                "ntoskrnl.exe".to_string(),
                names.iter().map(|name| name.to_string()).collect(),
            ))
        };
        let (imports, unnamed) = imports_from_bound_slots(&slots, exported_at);
        let named = |index: u64, name: &str| pe::Import {
            library: "ntoskrnl.exe".to_string(),
            name: pe::ImportName::Named(name.to_string()),
            slot: BASE + 0x3000 + index * 8,
        };
        assert_eq!(
            imports,
            vec![
                named(0, "ExAllocatePoolWithTag"),
                named(3, "ExAllocatePool2"),
                named(4, "RtlInitUnicodeString"),
            ]
        );
        assert_eq!(unnamed, 2, "every slot that named nothing is counted");
    }

    /// A scan whose imports came from the address table says so, and a slot that named nothing
    /// qualifies its negative exactly as an ordinal or a bound library does.
    #[test]
    fn imports_named_from_the_address_table_are_rendered_as_such() {
        let image = image();
        let mut named = scan(
            &image,
            &[import("KeQueryPerformanceCounter", BASE + 0x3008)],
            InstructionSet::Amd64,
            |_, _| None,
            never,
            in_functions,
        );
        named.imports_named_from = crate::structured::ImportsNamedFrom::ImportAddressTable {
            discarded_section: "INIT".to_string(),
            unnamed_slots: 0,
        };
        let whole = render(&structured_report("vid", BASE, &named, invented));
        assert!(
            whole.contains("Imports named from the import address table")
                && whole.contains("`INIT`"),
            "{whole}"
        );
        assert!(
            whole.contains("Sensitive imports: none on the list\n"),
            "every slot named is a whole table, so the negative stands unqualified: {whole}"
        );
        assert!(!whole.contains("bound to no export"), "{whole}");

        named.imports_named_from = crate::structured::ImportsNamedFrom::ImportAddressTable {
            discarded_section: "INIT".to_string(),
            unnamed_slots: 2,
        };
        let short = render(&structured_report("vid", BASE, &named, invented));
        assert!(
            short.contains("Not nameable (bound to no export): 2 slot(s)")
                && short.contains("none on the list (of the imports it was shown)"),
            "a slot that named nothing qualifies the negative: {short}"
        );
    }

    /// A call site is matched to an import by the **slot it goes through**, never by a name.
    ///
    /// That is the whole reason this works on a stripped driver: `call qword ptr [drv+0x9018]`
    /// carries no symbol, and the import table says what lives at that address without the slot
    /// ever being read. An import that is not on the curated list is counted rather than reported,
    /// so a short list of sinks can be told from a driver that imports almost nothing.
    /// The framework tell rides the import table the sinks are built from, so it answers on exactly
    /// the scans that answer at all -- and it is **not** a sink, which is the mistake available here:
    /// `WdfVersionBind` is how a driver loads, not something it does to a caller's buffer, so it
    /// must not show up in `sinks` or move `other_imports` into looking like a finding.
    #[test]
    fn the_bind_import_is_the_framework_tell_and_not_a_sink() {
        let image = image();
        let bind = pe::Import {
            library: "WDFLDR.SYS".to_string(),
            name: pe::ImportName::Named("WdfVersionBind".to_string()),
            slot: BASE + 0x3000,
        };
        let found = scan(
            &image,
            &[bind.clone(), import("memcpy", BASE + 0x3008)],
            InstructionSet::Amd64,
            |_, _| None,
            never,
            in_functions,
        );
        assert_eq!(found.framework, Some(crate::framework::Framework::Kmdf));
        assert_eq!(
            found.sinks.len(),
            1,
            "the bind routine is not a sensitive API: {:?}",
            found.sinks
        );
        assert_eq!(
            found.other_imports, 1,
            "it is counted as the ordinary import it is"
        );

        // And it travels into the typed answer as the one tell this end can have seen. The dispatch
        // tell needs a driver object, which a hazard scan has never read.
        let report = structured_report("vid", BASE, &found, |address| {
            crate::structured::CodeLocation {
                address: crate::structured::addr(address),
                module: Some("vid".to_string()),
                rva: Some("0x0".to_string()),
                attribution_failed: false,
            }
        });
        let framework = report
            .framework
            .expect("the scan said so, so the report does");
        assert_eq!(framework.framework, "kmdf");
        assert_eq!(
            framework.tells,
            vec![crate::structured::FrameworkTell::BindImport]
        );
        assert_eq!(framework.dispatch_image, None);
        // A WDM driver's scan carries no such field at all, which is what keeps the absence from
        // being a claim.
        let wdm = scan(
            &image,
            &[import("memcpy", BASE + 0x3008)],
            InstructionSet::Amd64,
            |_, _| None,
            never,
            in_functions,
        );
        assert_eq!(wdm.framework, None);

        // **And the rendered half says it too.** A structured-aware client is served
        // `structuredContent` instead of the text, so a field on one half reaches none of the
        // clients served the other -- the rule review on #437 found broken in
        // `reachable_from_dispatch`, pinned here as well so it is pinned at every site that has one.
        // This renderer prints the **word** rather than the note, deliberately: it is embedded whole
        // inside `surface::render`, which prints the note at the top of the same answer.
        let locate = |address: u64| crate::structured::CodeLocation {
            address: crate::structured::addr(address),
            module: Some("vid".to_string()),
            rva: Some("0x0".to_string()),
            attribution_failed: false,
        };
        let text = render(&structured_report("vid", BASE, &found, locate));
        assert!(text.contains("framework kmdf"), "{text}");
        assert!(
            !render(&structured_report("vid", BASE, &wdm, locate)).contains("framework"),
            "and a WDM driver's rendering gains nothing"
        );
    }

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
            in_functions,
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
            // **And nothing survives a terminator**, which is the half the first draft got wrong.
            // `x8` still holds `memcpy`'s slot as far as the maps are concerned; a `ret` ends the
            // straight-line run that formed it, so the `blr` after it is a different path's and
            // must not be credited with the import. Matching a real IAT slot is what makes this
            // dangerous rather than harmless -- the address is genuine, the attribution is not.
            insn(BASE + 0x1018, "00000000", "ret", Flow::Return, Vec::new()),
            insn(
                BASE + 0x101c,
                "00000000",
                "blr",
                Flow::Call(None),
                vec![Operand::Register(register("x8"))],
            ),
        ];

        let found = scan(
            &image,
            &imports,
            InstructionSet::Arm64,
            |at, _| (at == BASE + 0x1000).then(|| block.clone()),
            never,
            in_functions,
        );

        let copy = found
            .sinks
            .iter()
            .find(|sink| sink.name == "memcpy")
            .unwrap_or_else(|| panic!("{:?}", found.sinks));
        assert_eq!(
            copy.call_sites,
            vec![BASE + 0x1008],
            "the `blr` reaches the import through the slot adrp/ldr formed, and the one past the \
             `ret` does not: {copy:?}"
        );
        assert_eq!(
            copy.call_site_count, 1,
            "exactly one, so the stale-state call is not merely unlisted: {copy:?}"
        );
        let probe = found.sinks.iter().find(|sink| sink.name == "ProbeForRead");
        assert!(
            probe.is_none_or(|sink| sink.call_sites.is_empty()),
            "a slot loaded and never called through is not a call site: {probe:?}"
        );
    }

    /// The family is the decoder's, on every architecture, and this module adds exactly one thing
    /// to it: x86's descriptor-table reads, which need no privilege and are reported anyway.
    ///
    /// The fixture states what the decoder would -- `privileged` and the family together, as
    /// dbgscope builds them -- so what is under test is the passing-through and the one judgement.
    /// The classification itself is dbgscope's, and is tested there against encodings.
    #[test]
    fn the_family_is_the_decoders_and_only_the_descriptor_reads_are_added() {
        let unprivileged = |mnemonic: &str| {
            insn(
                BASE + 0x1000,
                "00000000",
                mnemonic,
                Flow::Fallthrough,
                Vec::new(),
            )
        };
        // Whatever the decoder names passes through, on both architectures and unchanged -- which
        // is what deleting the two per-architecture tables has to preserve. `other` among them,
        // since a privileged instruction nobody named is the one a table would have dropped.
        for family in [
            Privilege::PortIo,
            Privilege::ModelSpecificRegister,
            Privilege::ControlRegister,
            Privilege::DescriptorTable,
            Privilege::InterruptFlag,
            Privilege::CacheOrTlb,
            Privilege::Virtualization,
            Privilege::Other,
        ] {
            let one = privileged_insn(
                family,
                BASE + 0x1000,
                "00000000",
                "op",
                Flow::Fallthrough,
                Vec::new(),
            );
            assert_eq!(privilege_kind_x86(&one), Some(family), "{family:?}");
            assert_eq!(privilege_kind_arm64(&one), Some(family), "{family:?}");
        }
        // The judgement: the four descriptor-table reads, which the decoder calls unprivileged and
        // gives no family, are reported under the one they read.
        for mnemonic in ["sgdt", "sidt", "sldt", "str"] {
            assert_eq!(
                privilege_kind_x86(&unprivileged(mnemonic)),
                Some(Privilege::DescriptorTable),
                "{mnemonic}"
            );
        }
        // **And only on x86, which is the collision that made the old tables per-architecture.**
        // A64's `str` stores a register and is among the commonest instructions there is; read in
        // x86's namespace, a scan of an ARM64 `nt` called every store a descriptor-table access --
        // 59,450 privileged instructions. Found by the debugger tier against a real image.
        assert_eq!(
            privilege_kind_arm64(&unprivileged("str")),
            None,
            "an A64 store is not a descriptor-table access"
        );
        // Nothing else unprivileged is reported, including the one the old x86 table carried
        // beyond those four: `rdpmc`, which was never named as a deliberate addition and needs no
        // privilege by the decoder's reading.
        for mnemonic in ["rdpmc", "rdtsc", "mov", "nop"] {
            assert_eq!(
                privilege_kind_x86(&unprivileged(mnemonic)),
                None,
                "{mnemonic}"
            );
        }
    }

    /// Every family has its own wire name, so a client can tell any two apart.
    ///
    /// [`privilege_name`] is an exhaustive match, which makes a family dbgscope adds a build
    /// failure rather than an unnamed value; this is the other half, that no two of them collide.
    #[test]
    fn every_family_has_a_distinct_wire_name() {
        let families = [
            Privilege::PortIo,
            Privilege::ModelSpecificRegister,
            Privilege::ControlRegister,
            Privilege::DescriptorTable,
            Privilege::InterruptFlag,
            Privilege::CacheOrTlb,
            Privilege::Virtualization,
            Privilege::Other,
        ];
        let names: std::collections::BTreeSet<&str> = families
            .iter()
            .map(|family| privilege_name(*family))
            .collect();
        assert_eq!(names.len(), families.len(), "{names:?}");
    }

    /// The scan reports what the decoder says about an instruction, not what its mnemonic
    /// suggests.
    ///
    /// `mov cr3, rax` and `mov rax, rbx` are the same mnemonic, and the difference between a
    /// driver that reprograms paging and one that copies a register is entirely in the operand.
    /// That difference is the decoder's to find -- it reads `cr3` as a register it decoded, where a
    /// rule written against a rendering would find it in a string -- so what this pins is that the
    /// scan carries the decoder's answer through: the privileged `mov` under its family, the plain
    /// one not at all, and `swapgs` under `other`, which is where the decoder puts it.
    #[test]
    fn the_scan_reports_what_the_decoder_says_and_not_what_a_mnemonic_suggests() {
        let image = image();
        let block = vec![
            privileged_insn(
                Privilege::ControlRegister,
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
                Privilege::ModelSpecificRegister,
                BASE + 0x1006,
                "0f32",
                "rdmsr",
                Flow::Fallthrough,
                Vec::new(),
            ),
            privileged_insn(
                Privilege::PortIo,
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
                Privilege::Other,
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
            in_functions,
        );

        let kinds: Vec<(u64, Privilege)> = found
            .privileged
            .iter()
            .map(|p| (p.address, p.kind))
            .collect();
        assert_eq!(
            kinds,
            vec![
                (BASE + 0x1000, Privilege::ControlRegister),
                (BASE + 0x1006, Privilege::ModelSpecificRegister),
                (BASE + 0x1008, Privilege::PortIo),
                (BASE + 0x1009, Privilege::Other),
            ],
            "the plain `mov` is not privileged and everything else is: {:?}",
            found.privileged
        );
    }

    /// The report is the decoder's set, plus x86's descriptor-table reads.
    ///
    /// The two directions a list of mnemonics gets wrong are both here, and each needs an
    /// instruction the other rule cannot reach. `sysret` is privileged and in **no** named family,
    /// so it can arrive only through the decoder, as [`Privilege::Other`] -- a list reports a driver
    /// holding it as holding none. `sgdt` is the reverse: the decoder calls it unprivileged,
    /// correctly, and it is in the report anyway because a driver reading the GDT is worth seeing,
    /// which is the one judgement [`privilege_kind`] adds.
    #[test]
    fn the_report_is_the_decoders_set_plus_the_descriptor_table_reads() {
        let image = image();
        let block = vec![
            // Privileged, named by no family: the decoder is the only thing that can find it.
            privileged_insn(
                Privilege::Other,
                BASE + 0x1000,
                "0f07",
                "sysret",
                Flow::Return,
                Vec::new(),
            ),
            privileged_insn(
                Privilege::InterruptFlag,
                BASE + 0x1002,
                "fa",
                "cli",
                Flow::Fallthrough,
                Vec::new(),
            ),
            privileged_insn(
                Privilege::Virtualization,
                BASE + 0x1003,
                "0f01c2",
                "vmlaunch",
                Flow::Fallthrough,
                Vec::new(),
            ),
            // Unprivileged, and reported: the one judgement this module adds to the decoder.
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
            in_functions,
        );

        let kinds: Vec<(&str, Privilege)> = found
            .privileged
            .iter()
            .map(|p| (p.mnemonic.as_str(), p.kind))
            .collect();
        assert_eq!(
            kinds,
            vec![
                ("sysret", Privilege::Other),
                ("cli", Privilege::InterruptFlag),
                ("vmlaunch", Privilege::Virtualization),
                ("sgdt", Privilege::DescriptorTable),
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
            in_functions,
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
            in_functions,
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
            in_functions,
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
        let found = scan(
            &image,
            &[],
            InstructionSet::Amd64,
            |_, _| None,
            never,
            in_functions,
        );
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
            in_functions,
        );
        assert_eq!(hole.scanned.len(), 2, "{:?}", hole.scanned);
        assert_eq!(hole.scanned[0].start, BASE + 0x1000);
        assert_eq!(hole.unreadable.len(), 1, "{:?}", hole.unreadable);
        assert_eq!(hole.unreadable[0].start, BASE + 0x11000);
        assert_eq!(
            hole.unreadable[0].bytes, 0x1000,
            "a window that would not read is retried a page at a time, so only the page that \
             failed is lost: {:?}",
            hole.unreadable
        );
        assert_eq!(
            hole.scanned[1].start,
            hole.unreadable[0].start + hole.unreadable[0].bytes,
            "the run after the hole starts after it, not at the section: {:?}",
            hole.scanned
        );
    }

    /// A section with one absent page loses that page and no more, though the whole section is
    /// one window.
    ///
    /// HEVD's shape on a live kernel: its handlers are a 22 KiB pageable section, resident in the
    /// pages its last run touched. A read fails if **any** byte of it is absent, which is how the
    /// engine answers -- so one window over the section failed as a whole, and every call site in
    /// the driver was reported unread. This decoder fails a read that touches the absent page, as
    /// the engine does, rather than only a read that starts on it.
    #[test]
    fn a_section_with_one_absent_page_loses_only_that_page() {
        let mut image = image();
        image.size_of_image = 0x10000;
        image.sections[0].virtual_size = 0x5672;
        let absent = BASE + 0x3000..BASE + 0x4000;
        let filler = |at: u64, want: usize| {
            vec![insn(
                at,
                &"90".repeat(want),
                "nop",
                Flow::Fallthrough,
                Vec::new(),
            )]
        };
        let found = scan(
            &image,
            &[],
            InstructionSet::Amd64,
            |at, want| {
                let touches = at < absent.end && at + want as u64 > absent.start;
                (!touches).then(|| filler(at, want))
            },
            never,
            in_functions,
        );
        assert_eq!(found.unreadable.len(), 1, "{:?}", found.unreadable);
        assert_eq!(found.unreadable[0].start, absent.start);
        assert_eq!(found.unreadable[0].bytes, 0x1000, "{:?}", found.unreadable);
        assert_eq!(found.scanned.len(), 2, "{:?}", found.scanned);
        assert_eq!(found.scanned[0].start, BASE + 0x1000);
        assert_eq!(found.scanned[1].start, absent.end);
        assert_eq!(
            found.scanned.iter().map(|run| run.bytes).sum::<u64>(),
            0x5672 - 0x1000,
            "every resident byte is decoded: {:?}",
            found.scanned
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
            in_functions,
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
                    block.push(privileged_insn(
                        Privilege::Other,
                        address + 1,
                        "f4",
                        "hlt",
                        Flow::Trap,
                        Vec::new(),
                    ));
                    address += 2;
                }
                Some(block)
            },
            never,
            in_functions,
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

    /// **An executable section is not all instructions, and the answer says which is which**
    /// (issue [#303](https://github.com/glslang/windbg-mcp/issues/303)).
    ///
    /// A linear decode of `.text` walks the jump tables, string literals and `TraceLogging`
    /// metadata a compiler puts there and reports what those bytes happen to spell -- and four of
    /// x86's one-byte port-I/O opcodes are ASCII letters, so a string reads as `insb`/`outsd`. The
    /// two read identically as rows: measured on `docs/samples/081226-2187-01.dmp`,
    /// `kdstub+0x7fed` is a real `tdcall` inside `HcTdxVmcall` and `tpm+0x43fbd` is the fifth byte
    /// of `tpm!TraceLoggingMetadata`, and only the image's own unwind table tells them apart --
    /// `.fnent` answers `BeginAddress = 0x7fe0` for the first and *"No function entry"* for the
    /// second.
    ///
    /// So the standing travels on every row, the count of the uncovered ones travels beside the
    /// total, and the rendering puts them under **two headings**. Each of the three is asserted
    /// here, because each is a channel a reader may be served alone: a structured client reads the
    /// rows, a budget-conscious one reads the counts, and a text client reads the headings.
    #[test]
    fn a_finding_no_unwind_entry_covers_is_counted_apart_and_rendered_apart() {
        let image = image();
        let block = vec![
            privileged_insn(
                Privilege::ModelSpecificRegister,
                BASE + 0x1000,
                "0f32",
                "rdmsr",
                Flow::Fallthrough,
                Vec::new(),
            ),
            // The two one-byte opcodes that are `n` and `o` in a string literal.
            privileged_insn(
                Privilege::PortIo,
                BASE + 0x1002,
                "6e",
                "outsb",
                Flow::Fallthrough,
                Vec::new(),
            ),
            privileged_insn(
                Privilege::PortIo,
                BASE + 0x1003,
                "6f",
                "outsd",
                Flow::Fallthrough,
                Vec::new(),
            ),
            privileged_insn(
                Privilege::ModelSpecificRegister,
                BASE + 0x1004,
                "0f30",
                "wrmsr",
                Flow::Fallthrough,
                Vec::new(),
            ),
            insn(BASE + 0x1006, "c3", "ret", Flow::Return, Vec::new()),
        ];
        // The two in the middle are the ones no entry covers, exactly as the sample dump answers
        // for them.
        let covers = |at: u64| match at {
            a if a == BASE + 0x1002 || a == BASE + 0x1003 => Standing::NoUnwindEntry,
            _ => Standing::InFunction,
        };
        let found = scan(
            &image,
            &[],
            InstructionSet::Amd64,
            |at, _| (at == BASE + 0x1000).then(|| block.clone()),
            never,
            covers,
        );

        assert_eq!(
            found.privileged_count, 4,
            "the total is every privileged instruction decoded, as it always was: {:?}",
            found.privileged
        );
        assert_eq!(
            (
                found.in_function_privileged,
                found.uncovered_privileged,
                found.unverified_privileged
            ),
            (2, 2, 0),
            "and the three counts split it by standing, summing to the total: {:?}",
            found.privileged
        );
        assert_eq!(
            found
                .privileged
                .iter()
                .map(|found| (found.mnemonic.as_str(), found.standing))
                .collect::<Vec<_>>(),
            vec![
                ("rdmsr", Standing::InFunction),
                ("outsb", Standing::NoUnwindEntry),
                ("outsd", Standing::NoUnwindEntry),
                ("wrmsr", Standing::InFunction),
            ],
            "the list stays in address order and every row carries its own standing"
        );

        let report = structured_report("vid", BASE, &found, invented);
        assert_eq!(report.in_function_privileged, 2);
        assert_eq!(report.uncovered_privileged, 2);
        assert_eq!(report.unverified_privileged, 0);
        assert_eq!(
            report.in_function_privileged
                + report.uncovered_privileged
                + report.unverified_privileged,
            report.privileged_count,
            "the three are a partition of the total, which is what lets a reader trust a              subtraction between any two of them"
        );
        assert_eq!(
            report
                .privileged
                .iter()
                .map(|found| found.standing.as_str())
                .collect::<Vec<_>>(),
            vec![
                "in_function",
                "no_unwind_entry",
                "no_unwind_entry",
                "in_function"
            ],
        );
        // **Omitted from the wire when it is `in_function`**, which is the expected answer for
        // code: a thousand repetitions of the uninteresting value is bytes a reader pays for and
        // skips. Asserted on the serialized form, because that is the only place the omission
        // exists -- the field is `in_function` either way once a client has parsed it.
        let wire = serde_json::to_string(&report).expect("the report serializes");
        assert_eq!(
            wire.matches(r#""standing":"no_unwind_entry""#).count(),
            2,
            "the interesting standing is spelled out: {wire}"
        );
        // **The field, not the value**, which the first draft of this got wrong: `in_function`
        // appears in the serialized form either way, because `in_function_privileged` is a field
        // name -- so the loose match passed on a coincidence and would have gone on passing with
        // the omission backed out. Measured by backing it out.
        assert!(
            !wire.contains(r#""standing":"in_function""#),
            "and the expected one is left out of every row: {wire}"
        );

        let text = render(&report);
        assert!(
            text.contains("\n  Privileged instructions (2):\n"),
            "the heading counts the findings in code rather than every finding -- it said 4 while \
             the two groups were one: {text}"
        );
        assert!(
            text.contains("\n  In bytes no unwind entry covers (2)"),
            "and the others get a heading of their own: {text}"
        );
        // The rows land under the right heading, which is the whole of what a text reader gets
        // here. Compared by position rather than by presence: both groups are printed, so a
        // rendering that put all four under the first heading contains every mnemonic too.
        let split = text
            .find("In bytes no unwind entry covers")
            .expect("the second heading is there");
        let (code, data) = text.split_at(split);
        assert!(
            code.contains("rdmsr") && code.contains("wrmsr"),
            "the real findings are above it: {code}"
        );
        assert!(
            !code.contains("outsb") && !code.contains("outsd"),
            "and the data is not: {code}"
        );
        assert!(
            data.contains("outsb") && data.contains("outsd"),
            "the data is below it: {data}"
        );
        assert!(
            !text.contains("Not placed against an unwind table"),
            "the table answered, so nothing says it could not: {text}"
        );

        // And where **nothing** is in a covered region -- the sample dump's `tm`, whose one finding
        // is a `sldt` inside `tm!TmpTransactionManagerMapping` -- the first heading is absent
        // rather than printed over a count of zero. A group prints when its count does.
        let all_data = scan(
            &image,
            &[],
            InstructionSet::Amd64,
            |at, _| (at == BASE + 0x1000).then(|| block.clone()),
            never,
            |_| Standing::NoUnwindEntry,
        );
        let text = render(&structured_report("vid", BASE, &all_data, invented));
        assert!(
            !text.contains("\n  Privileged instructions ("),
            "no finding is in code, so that heading is not printed at all: {text}"
        );
        assert!(
            text.contains("\n  In bytes no unwind entry covers (4)"),
            "and all four are under the data heading: {text}"
        );
    }

    /// **A group's heading is printed from its count, not from the rows that survived the budget.**
    ///
    /// The case review on #468 found: [`Standing::Unverified`] shares [`MAX_PRIVILEGED`] with
    /// [`Standing::InFunction`], so a scan that places a thousand findings and *then* has one query
    /// fail has no unplaced row left to list. Driven from the rows, the qualification went missing
    /// entirely and the unplaced finding was counted among the ones known to be code. The count is
    /// taken for every finding, so it is what the heading reads -- and it says `none listed` rather
    /// than implying a sample it does not have.
    ///
    /// **Mutation-verified**: counting the `Unverified` finding into `in_function_privileged` fails
    /// the first assertion (0 against 1), and printing a heading only where a row survived fails
    /// the last. Both measured.
    #[test]
    fn a_standing_with_no_row_left_still_has_a_heading_and_a_count() {
        let mut image = image();
        image.size_of_image = 0x40000;
        image.sections[0].virtual_size = 0x30000;
        // Enough findings to fill the shared budget, and one query failing well past it.
        let unplaced = BASE + 0x1000 + 0x20000;
        let found = scan(
            &image,
            &[],
            InstructionSet::Amd64,
            |at, want| {
                Some(
                    (at..at + want as u64)
                        .map(|address| {
                            privileged_insn(
                                Privilege::InterruptFlag,
                                address,
                                "fa",
                                "cli",
                                Flow::Fallthrough,
                                Vec::new(),
                            )
                        })
                        .collect(),
                )
            },
            never,
            |at| {
                if at == unplaced {
                    Standing::Unverified
                } else {
                    Standing::InFunction
                }
            },
        );

        assert_eq!(
            found.unverified_privileged, 1,
            "the one unanswered query is counted whether or not a row survived"
        );
        assert_eq!(
            found.in_function_privileged,
            found.privileged_count - 1,
            "and it is not counted among the findings this placed in code"
        );
        assert!(
            !found
                .privileged
                .iter()
                .any(|found| found.standing == Standing::Unverified),
            "the shared budget was full long before it, so no row of it is listed: {}",
            found.privileged.len()
        );

        let text = render(&structured_report("vid", BASE, &found, invented));
        assert!(
            text.contains("\n  Not placed against an unwind table (1, none listed)"),
            "the heading is printed from the count, and says it has no sample: {}",
            text.lines()
                .filter(|line| line.contains("Not placed") || line.contains("Privileged"))
                .collect::<Vec<_>>()
                .join(" / ")
        );
    }

    /// **A finding the unwind table cannot be asked about is not called data.**
    ///
    /// x86 has no unwind table at all, so there is nothing to ask, and a target whose entry layout
    /// this build does not decode -- or an engine whose query failed -- is the same answer. Every
    /// one of those keeps the ordinary list budget and is counted into neither side of the split:
    /// a query that did not answer must not make a real `out` look like a byte of a string.
    ///
    /// **Mutation-verified**: fold `Standing::Unverified` into the `NoUnwindEntry` arm of `scan`
    /// and this fails on `uncovered_privileged`, coming back 2 against 0; fold it the other way in
    /// `render`'s `partition` and the two findings move under the data heading with the
    /// *"Not placed"* sentence still printed beneath them.
    #[test]
    fn a_finding_the_unwind_table_cannot_be_asked_about_is_not_called_data() {
        let image = image();
        let block = vec![
            privileged_insn(
                Privilege::PortIo,
                BASE + 0x1000,
                "ee",
                "out",
                Flow::Fallthrough,
                Vec::new(),
            ),
            privileged_insn(
                Privilege::InterruptFlag,
                BASE + 0x1001,
                "fa",
                "cli",
                Flow::Fallthrough,
                Vec::new(),
            ),
            insn(BASE + 0x1002, "c3", "ret", Flow::Return, Vec::new()),
        ];
        let found = scan(
            &image,
            &[],
            InstructionSet::X86,
            |at, _| (at == BASE + 0x1000).then(|| block.clone()),
            never,
            unplaced,
        );

        assert_eq!(found.privileged_count, 2);
        assert_eq!(
            (
                found.in_function_privileged,
                found.uncovered_privileged,
                found.unverified_privileged
            ),
            (0, 0, 2),
            "nothing was placed in a function or out of one, because nothing was placed: {:?}",
            found.privileged
        );
        assert!(
            found
                .privileged
                .iter()
                .all(|found| found.standing == Standing::Unverified),
            "{:?}",
            found.privileged
        );

        let text = render(&structured_report("vid", BASE, &found, invented));
        assert!(
            text.contains("\n  Not placed against an unwind table (2")
                && text.contains("out")
                && text.contains("cli"),
            "both are reported, under the heading that says the question was not answered: {text}"
        );
        assert!(
            !text.contains("In bytes no unwind entry covers"),
            "and neither is under the data heading, which is the one that would read as a verdict:              {text}"
        );
        assert!(
            !text.contains("\n  Privileged instructions ("),
            "nor under the heading for findings this placed in code: {text}"
        );
    }

    /// **Neither population can spend the other's list budget.**
    ///
    /// One budget in address order is spent by whatever comes first, and what comes first in a
    /// module like the sample dump's `DTrace` -- 880 privileged findings of which 879 are bytes no
    /// entry covers -- is the data. So the one real finding at the end would be counted and never
    /// listed, which is the shape this answer must not take: a reader cannot check a finding that
    /// is only a number.
    ///
    /// **Mutation-verified**: give the two one shared counter in `scan` and the covered finding
    /// disappears from the list while `privileged_count` still names it.
    #[test]
    fn neither_population_can_spend_the_others_list_budget() {
        let mut image = image();
        image.size_of_image = 0x40000;
        image.sections[0].virtual_size = 0x30000;
        // `DTrace`'s shape: a long run of bytes no entry covers, and one real finding past them.
        let real = BASE + 0x1000 + 0x20000;
        let found = scan(
            &image,
            &[],
            InstructionSet::Amd64,
            |at, want| {
                Some(
                    (at..at + want as u64)
                        .map(|address| {
                            privileged_insn(
                                Privilege::InterruptFlag,
                                address,
                                "fa",
                                "cli",
                                Flow::Fallthrough,
                                Vec::new(),
                            )
                        })
                        .collect(),
                )
            },
            never,
            |at| {
                if at == real {
                    Standing::InFunction
                } else {
                    Standing::NoUnwindEntry
                }
            },
        );

        assert!(
            found.uncovered_privileged > MAX_UNCOVERED_PRIVILEGED,
            "the fixture finds far more than the sample's budget: {}",
            found.uncovered_privileged
        );
        let (covered, uncovered): (Vec<_>, Vec<_>) = found
            .privileged
            .iter()
            .partition(|found| found.standing != Standing::NoUnwindEntry);
        assert_eq!(
            uncovered.len(),
            MAX_UNCOVERED_PRIVILEGED,
            "the data is sampled rather than listed"
        );
        assert_eq!(
            covered
                .iter()
                .map(|found| found.address)
                .collect::<Vec<_>>(),
            vec![real],
            "and the one real finding is listed, 0x20000 bytes of noise after the cap was reached"
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
            privileged_insn(
                Privilege::Other,
                BASE + 0x1006,
                "f4",
                "hlt",
                Flow::Trap,
                Vec::new(),
            ),
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
                in_functions,
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
            in_functions,
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

        let found = scan(
            &image,
            &imports,
            InstructionSet::Amd64,
            |_, _| None,
            never,
            in_functions,
        );
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
        let found = scan(
            &image,
            &two,
            InstructionSet::Amd64,
            |_, _| None,
            never,
            in_functions,
        );
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
            in_functions,
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
            in_functions,
        );
        assert_eq!(found.halted, Some(Halt::Interrupted));
    }
}
