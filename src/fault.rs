//! Turning a user-mode fault into the two or three facts a triage actually reads.
//!
//! The kernel counterpart is [`crate::triage`], and the split between them is the same one the
//! engine makes: a bug check is read by `ReadBugCheckData`, and a user-mode fault is an *event*
//! with an exception record. Nothing here overlaps that module — a kernel crash dump has no stored
//! event at all, measured, so neither is a fallback for the other.
//!
//! # What this exists for
//!
//! `docs/explorer-crash-walkthrough.md` §9. Three consecutive faults in one evening, and in all
//! three the fact that mattered — the `HRESULT` thrown through `winrt::check_hresult` — came out of
//! `execute`: `.exr`, `.ecxr`, `s -d`, `dd`, `!error`. The typed surface got to the frame and
//! stopped there. This is the routine that was performed by hand.
//!
//! # Everything here is pure
//!
//! No engine, no session: [`decode_status`] is arithmetic over a `u32` plus a call to the host's
//! message tables, and every walk takes a `Read` closure. That is not tidiness — it is what lets
//! the whole of the risky part be tested against synthetic memory, which matters because the
//! interesting inputs are corrupt dumps and nobody has a corpus of those.
//!
//! # Three provenances, kept apart
//!
//! This module reports facts of three quite different strengths, and a caller that cannot tell them
//! apart will trust the weakest as much as the strongest.
//!
//! **Read from the record.** The exception code, its flags, the faulting address, the parameter
//! count. These are the dump.
//!
//! **Decoded from documented structure.** The MSVC C++ EH graph — `ThrowInfo` to
//! `CatchableTypeArray` to `CatchableType` to `TypeDescriptor` — whose layout is fixed by the
//! compiler and whose every offset is confirmed against real MSVC output (see the unit tests, and
//! `docs/explorer-crash-walkthrough.md`). A type name from this route is as good as the memory it
//! was read from.
//!
//! **Recognised by convention.** The `0xAABBCCDD` sentinel that locates a `winrt::hresult_error`'s
//! `m_code`, and WIL's use of a fail-fast's second and third parameters. Neither is in any header
//! this can consult; both are patterns read off real crashes. They are reported as such
//! ([`Confidence`]) rather than presented beside the other two, because a number at an assumed
//! offset is not evidence — a number that *decodes to a plausible message* is, and that is why
//! [`decode_status`] runs on whatever comes out.
//!
//! # The two routes to a thrown HRESULT, and why both are needed
//!
//! The type-name route needs the throwing module's `.rdata`, because `ThrowInfo` and everything it
//! points at live in the image. **A `MiniDumpNormal` does not contain that.** Measured: the walk
//! succeeds on a WER minidump while the executable is still on disk at its recorded path, and the
//! same read comes back `????????` once the image is moved aside — the debugger had been reading
//! the image, not the dump.
//!
//! So on a dump from another machine, or one whose binaries have moved, the sentinel scan of the
//! *thrown object* — which is on the stack, and therefore in the dump — is the only route that
//! works. Neither is a superset of the other, and [`thrown_error`] tries both.
//!
//! **That second route is only as good as the range it is given**, which is why the caller anchors
//! its scan on the innermost frame rather than on the walk. The same missing image costs x64 its
//! unwind data, so the outer frames of such a dump are not trustworthy either — see
//! `worker::exception_triage`, where getting that wrong meant the fallback found nothing on
//! exactly the dumps it exists for.

/// Reads `len` bytes of the target at `address`, or `None` if that memory is not readable.
///
/// The whole engine dependency of this module, as one closure. A short read is `None` rather than a
/// truncated buffer: every caller below is reading a fixed-size structure, and half of one is not a
/// structure.
pub type Read<'a> = dyn Fn(u64, usize) -> Option<Vec<u8>> + 'a;

/// How much weight a convention-located field can bear. See the module docs.
///
/// **Only ever attached to the sentinel-located `HRESULT`**, because that is the one value here
/// whose provenance varies. The record's fields and the EH graph's are read from the dump and from
/// a layout the compiler fixes; they need no qualifier, and giving them one would suggest the
/// question is open where it is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    /// Two independent routes agree: the EH graph named the thrown type an `hresult_error`, *and*
    /// the sentinel scan of the object found a code.
    ///
    /// This is the cross-check the walkthrough argued for — "a number that decodes to a plausible
    /// message is evidence; a number at an assumed offset is not" — with the type name supplying
    /// the half that says the offset was not assumed but expected.
    Corroborated,
    /// One route: the sentinel matched, and nothing said what the thrown type was. The ordinary
    /// case on a minidump without the throwing module's image, and still the answer — it is just
    /// an answer resting on a pattern no header states.
    Convention,
}

// ---------------------------------------------------------------------------
// Status codes: the `!error` half
// ---------------------------------------------------------------------------

/// A 32-bit status value, decoded every way it can be read.
///
/// **Deliberately does not pick one reading.** A bare dword is ambiguous by construction:
/// `0xc0000005` is an `NTSTATUS`, `0x80070005` is an `HRESULT` wrapping the Win32 error `5`, and
/// nothing in the value says which space the caller took it from. `!error` guesses; this reports
/// what each reading yields and lets the caller — who knows where the number came from — choose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusDecode {
    /// The value, as given.
    pub value: u32,
    /// Whether the value **read as an `HRESULT`** is a failure.
    ///
    /// Bit 31 alone, because that is the whole of an `HRESULT`'s severity — it is a one-bit field
    /// there, not the two-bit one [`Self::ntstatus_severity`] reads. Conflating them is easy and
    /// wrong in a way that looks right: `0x80670015` is a *failed* `HRESULT`, and its top two bits
    /// are `10`, which as an `NTSTATUS` is a **warning**.
    pub hresult_failed: bool,
    /// The severity of the value **read as an `NTSTATUS`**, which is a two-bit field.
    pub ntstatus_severity: Severity,
    /// The facility field — bits 16..27, where the two layouts do agree.
    pub facility: u32,
    /// The low 16 bits.
    pub code: u16,
    /// Whether the customer bit (bit 29) is set, which marks a value that is **not** Microsoft's
    /// and therefore not in any message table worth consulting.
    pub customer_defined: bool,
    /// The well-known name, where this is one of the COM codes whose message text is unhelpful.
    /// `E_UNEXPECTED` for `0x8000ffff`, whose system message is the famously uninformative
    /// "Catastrophic failure".
    pub symbolic: Option<&'static str>,
    /// What the host's system message table says, reading the value as an `HRESULT` or Win32 error.
    pub system_message: Option<String>,
    /// What `ntdll`'s message table says, reading the value as an `NTSTATUS`.
    pub ntstatus_message: Option<String>,
    /// Which namespace the caller knows this value came from, where it knows.
    pub reading: Reading,
}

/// What the caller knows about which namespace a value belongs to.
///
/// **The two overlap, so this is not a formatting preference — it is the difference between the
/// right sentence and a plausible wrong one.** An exception record's code is an `NTSTATUS` by
/// construction; a value typed into `decode_error_reporting` could be anything, and there the tool
/// reports every reading rather than choosing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Reading {
    /// A bare value: report all readings, lead with the `HRESULT` one.
    #[default]
    Unknown,
    /// Known to be an `NTSTATUS` — an exception code, a bug check, a status returned by a syscall.
    NtStatus,
}

impl StatusDecode {
    /// The single most useful sentence about this value, for a rendering that has room for one.
    ///
    /// Prefers the symbolic name where there is one, because `E_UNEXPECTED` tells a reader more
    /// than "Catastrophic failure" does; then the system message; then `ntdll`'s.
    ///
    /// **Unless the caller knows the value is an `NTSTATUS`, in which case `ntdll`'s table leads
    /// and the `HRESULT` name is suppressed entirely.** The two namespaces overlap, and where they
    /// do the system table answers with the wrong one: `0x80000003` is `STATUS_BREAKPOINT`, and
    /// `FormatMessage` reads it as `E_INVALIDARG` and returns "One or more arguments are invalid".
    /// A debugger that prints that for every breakpoint is worse than one that prints nothing.
    /// Both readings stay on the wire either way — this only decides which one leads.
    pub fn best_effort(&self) -> Option<String> {
        if self.reading == Reading::NtStatus {
            return self
                .ntstatus_message
                .clone()
                .or_else(|| self.system_message.clone());
        }
        match (
            self.symbolic,
            self.system_message.as_deref(),
            self.ntstatus_message.as_deref(),
        ) {
            (Some(name), Some(message), _) => Some(format!("{name} — {message}")),
            (Some(name), None, _) => Some(name.to_string()),
            (None, Some(message), _) => Some(message.to_string()),
            (None, None, Some(message)) => Some(message.to_string()),
            (None, None, None) => None,
        }
    }
}

/// An `NTSTATUS`'s two-bit severity.
///
/// **Not an `HRESULT`'s.** An `HRESULT` has a one-bit severity in the same position — see
/// [`StatusDecode::hresult_failed`] — so applying this enum to one reports a failed `HRESULT` as a
/// "warning" whenever its facility's top bit is clear, which is most of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Success,
    Informational,
    Warning,
    Error,
}

impl Severity {
    fn of(value: u32) -> Self {
        match value >> 30 {
            0 => Self::Success,
            1 => Self::Informational,
            2 => Self::Warning,
            _ => Self::Error,
        }
    }

    /// The spelling used in headers and in `!error` output.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Informational => "informational",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }
}

/// The COM status codes whose system message text is actively unhelpful.
///
/// **Not a general `HRESULT` table, and must not become one.** The host's message tables already
/// answer for tens of thousands of codes — including the two this walkthrough turned on,
/// `0x80670015` ("The StateRepository cache is not initialized.") and `0x80073d54` ("The process
/// has no package identity."), neither of which is a code anybody would think to hardcode. What
/// they do *not* carry is the name a C++ programmer recognises, and for this handful the name is
/// the more useful half: `E_UNEXPECTED` locates the throw where "Catastrophic failure" does not.
///
/// **And a name here outranks both message tables**, because [`StatusDecode::best_effort`] prefers
/// it — so a wrong entry is not a cosmetic slip, it is the headline.
///
/// This table used to carry `0x80000001`–`0x80000009` as `E_NOTIMPL` … `E_ACCESSDENIED`.
/// `winerror.h` really does define those names at those values — **inside the `#else` of
/// `#if defined(_WIN32) && !defined(_MAC)`** (10.0.26100.0, `shared/winerror.h` lines 30418/30500),
/// so they are the non-Win32 branch and dead on every platform this server runs on. The live branch
/// puts `E_INVALIDARG` at `0x80070057` and `E_NOTIMPL` at `0x80004001`.
///
/// What made it a bug rather than a curiosity is that all nine collide with a defined `NTSTATUS`,
/// and two of them are the likeliest codes in the whole range for a *debugger*: `0x80000003` is
/// `STATUS_BREAKPOINT` and `0x80000004` is `STATUS_SINGLE_STEP`. Every breakpoint this tool decoded
/// announced itself as `E_INVALIDARG`. Separately, `0x8000000e` was labelled
/// `E_STRING_NOT_NULL_TERMINATED`, which is `0x80000017`; `0x8000000e` is `E_ILLEGAL_METHOD_CALL`.
///
/// Checked against this machine's SDK rather than from memory — which is how the error got in —
/// and `test_no_well_known_name_shadows_a_code_this_module_classifies` keeps the collision out.
const WELL_KNOWN: &[(u32, &str)] = &[
    (0x8000_000b, "E_BOUNDS"),
    (0x8000_000c, "E_CHANGED_STATE"),
    (0x8000_000e, "E_ILLEGAL_METHOD_CALL"),
    (0x8000_0017, "E_STRING_NOT_NULL_TERMINATED"),
    (0x8000_4001, "E_NOTIMPL"),
    (0x8000_4002, "E_NOINTERFACE"),
    (0x8000_4003, "E_POINTER"),
    (0x8000_4004, "E_ABORT"),
    (0x8000_4005, "E_FAIL"),
    (0x8000_ffff, "E_UNEXPECTED"),
    (0x8007_0005, "E_ACCESSDENIED"),
    (0x8007_000e, "E_OUTOFMEMORY"),
    (0x8007_0057, "E_INVALIDARG"),
    (0x8007_0006, "E_HANDLE"),
    (0x0000_0000, "S_OK"),
    (0x0000_0001, "S_FALSE"),
];

/// Decodes a status value structurally, and asks the host what it means.
///
/// The structural half is arithmetic and cannot be wrong. The message half comes from **this
/// machine's** message tables, not the target's, which is the one caveat worth carrying into a
/// result: a dump from a build that names an error differently will be described in this host's
/// words. In practice these strings are stable across builds, and the alternative — `!error` in the
/// engine — reads the same tables from the same machine.
pub fn decode_status_as(value: u32, reading: Reading) -> StatusDecode {
    let customer_defined = value & 0x2000_0000 != 0;
    StatusDecode {
        value,
        hresult_failed: value & 0x8000_0000 != 0,
        ntstatus_severity: Severity::of(value),
        facility: (value >> 16) & 0x0fff,
        code: value as u16,
        customer_defined,
        // **No `HRESULT` name for a value the caller has told us is a status.** The table is
        // right about `0x8000ffff` as an `HRESULT` and would be wrong about it as an `NTSTATUS`,
        // and there is no way to be right about both from the number alone.
        symbolic: (reading == Reading::Unknown)
            .then(|| {
                WELL_KNOWN
                    .iter()
                    .find(|(known, _)| *known == value)
                    .map(|(_, name)| *name)
            })
            .flatten(),
        // A customer-defined value is in nobody's table, and asking would return either nothing or
        // — worse — an unrelated Microsoft string that happens to share the number.
        system_message: (!customer_defined)
            .then(|| message::from_system(value))
            .flatten(),
        ntstatus_message: (!customer_defined)
            .then(|| message::from_ntdll(value))
            .flatten(),
        reading,
    }
}

/// A value of unknown provenance, which is what `decode_error_reporting` is given.
pub fn decode_status(value: u32) -> StatusDecode {
    decode_status_as(value, Reading::Unknown)
}

/// The host's message tables. The only impure code in this module, and it touches no debuggee.
mod message {
    use windows_sys::Win32::Foundation::HMODULE;
    use windows_sys::Win32::System::Diagnostics::Debug::{
        FORMAT_MESSAGE_FROM_HMODULE, FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_IGNORE_INSERTS,
        FormatMessageW,
    };
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;

    /// Long enough for every message in these tables; a longer one is truncated rather than
    /// retried, because a status description that runs past two kilobytes is not a description.
    const BUFFER: usize = 2048;

    /// What the system message table says — which is where `HRESULT`s and Win32 errors live.
    ///
    /// This is the call that answers for the codes the explorer walkthrough turned on, verbatim:
    /// `0x80670015` gives "The StateRepository cache is not initialized." and `0x80073d54` "The
    /// process has no package identity.", which is what `!error` printed for each.
    pub fn from_system(value: u32) -> Option<String> {
        format(FORMAT_MESSAGE_FROM_SYSTEM, std::ptr::null_mut(), value)
    }

    /// What `ntdll`'s message table says — which is where `NTSTATUS` values live.
    ///
    /// Separate from [`from_system`] because the system table does not carry them: `0xc0000409`
    /// resolves here and nowhere else. Worth reading with care rather than trust, mind — the text
    /// it gives for that very code is "an overrun of a stack-based buffer", which on a modern
    /// build is exactly the wrong conclusion. [`super::fail_fast_subcode`] is what actually
    /// informs there, which is why a fail-fast's decode carries both.
    pub fn from_ntdll(value: u32) -> Option<String> {
        // `GetModuleHandle` rather than `LoadLibrary`: ntdll is mapped into every process that
        // exists, so this is a lookup and never a load, and there is no handle to release.
        let ntdll = unsafe { GetModuleHandleW(windows_sys::w!("ntdll.dll")) };
        if ntdll.is_null() {
            return None;
        }
        format(FORMAT_MESSAGE_FROM_HMODULE, ntdll, value)
    }

    fn format(flags: u32, source: HMODULE, value: u32) -> Option<String> {
        let mut buffer = [0u16; BUFFER];
        // `IGNORE_INSERTS` because these messages carry `%1`-style placeholders this has no
        // arguments for — `0xc0000005`'s is "The instruction at 0x%p referenced memory at 0x%p" —
        // and without it `FormatMessage` fails outright rather than leaving them in place. Left in
        // place they are still readable; failed they are nothing.
        let written = unsafe {
            FormatMessageW(
                flags | FORMAT_MESSAGE_IGNORE_INSERTS,
                source.cast(),
                value,
                // Neutral language: let the loader pick, rather than pinning a locale this
                // machine may not have installed and getting nothing.
                0,
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                std::ptr::null(),
            )
        };
        if written == 0 {
            return None;
        }
        let text = String::from_utf16_lossy(&buffer[..written as usize]);
        // These strings are line-terminated for console printing, and some carry an interior
        // newline where the table author wrapped them. Collapsed, because this is a field.
        let collapsed = text.split_whitespace().collect::<Vec<_>>().join(" ");
        (!collapsed.is_empty()).then_some(collapsed)
    }
}

// ---------------------------------------------------------------------------
// Classifying the record
// ---------------------------------------------------------------------------

/// `STATUS_STACK_BUFFER_OVERRUN`, which on any build since Windows 8 almost never means one.
///
/// It is the code `__fastfail` raises, and reading it as a stack buffer overrun sends an
/// investigation looking for corruption that is not there — gotcha one in the walkthrough, and the
/// reason [`FaultKind::FailFast`] exists rather than letting the name speak.
pub const STATUS_STACK_BUFFER_OVERRUN: u32 = 0xc000_0409;

/// The MSVC C++ exception code: `0xe0000000 | 'msc'`.
pub const STATUS_CPP_EH_EXCEPTION: u32 = 0xe06d_7363;

/// `STATUS_ACCESS_VIOLATION`.
pub const STATUS_ACCESS_VIOLATION: u32 = 0xc000_0005;

/// `STATUS_BREAKPOINT` — an `int3`, and what an initial break arrives as.
pub const STATUS_BREAKPOINT: u32 = 0x8000_0003;

/// The `0x19930520` magic MSVC puts in a throw's first parameter.
///
/// It is a date, and it is also the EH ABI version, so a future toolset could move it. Matching it
/// exactly is deliberate: a record that does not carry it is not a throw this code understands, and
/// guessing at the remaining parameters would be worse than declining.
const CPP_EH_MAGIC: u64 = 0x1993_0520;

/// What kind of fault a record describes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FaultKind {
    /// A deliberate process kill. **Not a corruption bug**, whatever the code's name says.
    FailFast {
        /// The subcode, which is what says *why* — `7` is `FAST_FAIL_FATAL_APP_EXIT`, i.e. the
        /// CRT's `abort`, i.e. an unhandled C++ exception.
        subcode: Option<u64>,
        /// The subcode's name, where this build knows it.
        subcode_name: Option<&'static str>,
        /// WIL's extra parameters, on a three-parameter record. See [`WilFailure`].
        wil: Option<WilFailure>,
    },
    /// A C++ `throw` that reached `RaiseException`.
    CppThrow(CppThrow),
    /// A memory access the target was not allowed to make.
    AccessViolation {
        /// What was attempted: read, write, or execute from a no-execute page.
        operation: &'static str,
        /// The address that could not be accessed.
        address: u64,
    },
    /// An `int3`. On a live target this is usually the debugger's own initial break.
    Breakpoint,
    /// Anything else. [`decode_status`] on the code is what describes it.
    Other,
}

/// The three parameters a WIL fail-fast carries, where the CRT's carries one.
///
/// **Read off real records, not out of a header** — the walkthrough's second fault is the sample:
/// `NumberParameters: 3`, `Parameter[1]: ffffffff8000ffff`, `Parameter[2]: 000000000000028f`, and
/// `ub` from the fail-fast showed WIL being handed `"pcshell\shell\explorer\tray.cpp"`, making
/// `0x28f` line 655 of it. That is a convention of one library's `ReportFailure_Hr` and not a
/// property of fail-fasts, so it is reported as [`Confidence::Convention`] and only ever *beside*
/// the raw parameters, never instead of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WilFailure {
    /// The `HRESULT`, taken from parameter 1 and truncated from its sign extension —
    /// `0xffffffff8000ffff` is `0x8000ffff`.
    pub hresult: u32,
    /// Parameter 2, which WIL sets to the line number of the failing check.
    pub line: u64,
}

/// The target's pointer width, which is the axis the MSVC C++ EH ABI actually varies on.
///
/// **Named for the width rather than for x86.** `_WIN64` is what makes the EH descriptors hold
/// RVAs instead of pointers and widens `EXCEPTION_RECORD`, so ARM64 lays them out exactly like x64
/// and 32-bit ARM exactly like x86. A rule keyed on "is it x86" would be right twice and wrong
/// twice.
///
/// Every difference below is **measured** rather than read off a header, by building one throw
/// twice and having it print its own record and walk its own graph:
///
/// | | 32-bit | 64-bit |
/// |---|---|---|
/// | parameters a throw raises | 3 | 4 (the last is the image base) |
/// | `ThrowInfo`'s links | absolute pointers | RVAs from that base |
/// | `TypeDescriptor::name` | `+8` | `+16` |
/// | `EXCEPTION_RECORD` size | 80 | 152 |
///
/// The pointer-versus-RVA row needs no branch: a 32-bit target reports **no** image base, so
/// taking it as zero makes `base + field` the identity and the same arithmetic serves both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bitness {
    /// x86 and 32-bit ARM.
    Bits32,
    /// x64 and ARM64.
    Bits64,
}

impl Bitness {
    /// How many parameters a C++ throw raises. The fourth is the image base, which a 32-bit target
    /// has no use for because its descriptors hold absolute pointers.
    const fn cpp_throw_parameters(self) -> usize {
        match self {
            Self::Bits32 => 3,
            Self::Bits64 => 4,
        }
    }

    /// `TypeDescriptor::name`, which follows a vtable pointer and a spare pointer — so it moves
    /// with the pointer width, and is the one EH offset that does.
    const fn type_descriptor_name(self) -> usize {
        match self {
            Self::Bits32 => eh::TYPE_DESCRIPTOR_NAME_32,
            Self::Bits64 => eh::TYPE_DESCRIPTOR_NAME_64,
        }
    }

    /// The `EXCEPTION_RECORD` layout as the *target's* compiler lays it out on its own stack.
    const fn record(self) -> record::Layout {
        match self {
            Self::Bits32 => record::BITS32,
            Self::Bits64 => record::BITS64,
        }
    }
}

/// A C++ throw's parameters, named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CppThrow {
    /// Where the thrown object is. On the stack of the throwing frame, so it is in any dump that
    /// captured thread stacks — which is what makes the sentinel route work where the type route
    /// cannot.
    pub object: u64,
    /// The `ThrowInfo`, which describes the thrown *type*. In the throwing module's `.rdata`.
    pub throw_info: u64,
    /// The image base every RVA inside `ThrowInfo` is relative to — and **zero on a 32-bit
    /// target**, which raises no such parameter because those links are absolute pointers already.
    pub image_base: u64,
    /// The width those links were laid out at.
    pub bitness: Bitness,
}

/// The two subcodes for which `0xc0000409`'s name is the literal truth.
///
/// **The dismissal this module's summary leads with is wrong for exactly these.** `0xc0000409` is
/// `STATUS_STACK_BUFFER_OVERRUN` and almost never one — except when the subcode says a `/GS` cookie
/// check failed, which is the compiler reporting that the guard value between a local buffer and
/// the return address was overwritten. There, stack corruption is not a misreading of the code's
/// name; it is the finding, and telling a reader otherwise sends them away from the defect.
const GS_COOKIE_SUBCODES: &[u64] = &[
    0, // FAST_FAIL_LEGACY_GS_VIOLATION
    2, // FAST_FAIL_STACK_COOKIE_CHECK_FAILURE
];

/// `FAST_FAIL_FATAL_APP_EXIT`, the subcode the CRT's `abort` raises.
///
/// Named because two decisions turn on it and they must not drift apart: the sentence
/// [`summary_of`] writes, and whether `exception_triage` goes looking for a buried throw at all.
pub const FAST_FAIL_FATAL_APP_EXIT: u64 = 7;

/// The `__fastfail` subcodes worth naming.
///
/// Not the whole list — there are around eighty and most never occur — but every one this bench has
/// seen, plus the neighbours a reader is likely to hit. An unknown subcode reports its number,
/// which is the honest answer and still greppable.
const FAIL_FAST_SUBCODES: &[(u64, &str)] = &[
    (0, "FAST_FAIL_LEGACY_GS_VIOLATION"),
    (1, "FAST_FAIL_VTGUARD_CHECK_FAILURE"),
    (2, "FAST_FAIL_STACK_COOKIE_CHECK_FAILURE"),
    (3, "FAST_FAIL_CORRUPT_LIST_ENTRY"),
    (4, "FAST_FAIL_INCORRECT_STACK"),
    (5, "FAST_FAIL_INVALID_ARG"),
    (6, "FAST_FAIL_GS_COOKIE_INIT"),
    (FAST_FAIL_FATAL_APP_EXIT, "FAST_FAIL_FATAL_APP_EXIT"),
    (8, "FAST_FAIL_RANGE_CHECK_FAILURE"),
    (9, "FAST_FAIL_UNSAFE_REGISTRY_ACCESS"),
    (10, "FAST_FAIL_GUARD_ICALL_CHECK_FAILURE"),
    (11, "FAST_FAIL_GUARD_WRITE_CHECK_FAILURE"),
    (12, "FAST_FAIL_INVALID_FIBER_SWITCH"),
    (13, "FAST_FAIL_INVALID_SET_OF_CONTEXT"),
    (18, "FAST_FAIL_INVALID_IMAGE_BASE"),
    (23, "FAST_FAIL_INVALID_BUFFER_ACCESS"),
    (24, "FAST_FAIL_INVALID_BALANCED_TREE"),
    (27, "FAST_FAIL_INVALID_JUMP_BUFFER"),
    (29, "FAST_FAIL_INVALID_FAST_FAIL_CODE"),
    (37, "FAST_FAIL_INVALID_CONTROL_STACK"),
];

/// The name of a `__fastfail` subcode, where this build knows it.
pub fn fail_fast_subcode(subcode: u64) -> Option<&'static str> {
    FAIL_FAST_SUBCODES
        .iter()
        .find(|(known, _)| *known == subcode)
        .map(|(_, name)| *name)
}

/// What a record says about itself, before any memory is read.
///
/// **The parameter count is read first, and it is what decides the shape** — the walkthrough's own
/// rule, from having got two different fail-fasts in one evening whose `HRESULT` was retrieved two
/// entirely different ways. A one-parameter `0xc0000409` hides its cause in a thrown object; a
/// three-parameter one has it right there in parameter 1.
pub fn classify(code: u32, parameters: &[u64], bitness: Bitness) -> FaultKind {
    match code {
        STATUS_STACK_BUFFER_OVERRUN => {
            // **Absent, not zero.** `unwrap_or_default` here named a parameterless record
            // `FAST_FAIL_LEGACY_GS_VIOLATION`, which is subcode 0 — a diagnosis invented out of a
            // field the record does not have. Every real `__fastfail` supplies one; a record that
            // does not is truncated or synthetic, and the honest answer is that it does not say.
            let subcode = parameters.first().copied();
            FaultKind::FailFast {
                subcode,
                subcode_name: subcode.and_then(fail_fast_subcode),
                // **Exactly three, not "at least three".** WIL writes the subcode, the HRESULT and
                // the line and stops, so three *is* the discriminator; a record with two would be
                // some third thing whose second parameter this has no reason to read as an
                // HRESULT, and so would a record with four. Reading a fourth-parameter record as
                // WIL's would put two arbitrary numbers on the wire under the names `hresult` and
                // `line`, which is worse than saying nothing.
                wil: (parameters.len() == 3).then(|| WilFailure {
                    // Truncating rather than casting through `i64`: the parameter is a
                    // sign-extended 32-bit HRESULT, so the low half *is* the value.
                    hresult: parameters[1] as u32,
                    line: parameters[2],
                }),
            }
        }
        // Every field below is at a fixed index, so the count is checked before any of them is
        // read. A throw with fewer parameters is not a throw this understands — and how many is
        // "fewer" is the target's, not this build's: a 32-bit throw raises three, having no image
        // base to report.
        STATUS_CPP_EH_EXCEPTION
            if parameters.len() >= bitness.cpp_throw_parameters()
                && parameters[0] == CPP_EH_MAGIC =>
        {
            FaultKind::CppThrow(CppThrow {
                object: parameters[1],
                throw_info: parameters[2],
                image_base: parameters.get(3).copied().unwrap_or_default(),
                bitness,
            })
        }
        STATUS_ACCESS_VIOLATION if parameters.len() >= 2 => FaultKind::AccessViolation {
            operation: match parameters[0] {
                0 => "read",
                1 => "write",
                8 => "execute",
                _ => "unknown",
            },
            address: parameters[1],
        },
        STATUS_BREAKPOINT => FaultKind::Breakpoint,
        _ => FaultKind::Other,
    }
}

// ---------------------------------------------------------------------------
// The MSVC C++ EH graph
// ---------------------------------------------------------------------------

/// Offsets into MSVC's EH structures.
///
/// Fixed by the compiler rather than chosen here, and every one of them confirmed against real
/// `cl.exe` output — see `test_the_eh_graph_matches_real_msvc_output`, whose fixture is a
/// transcription of an actual `throw`'s structures.
mod eh {
    /// `ThrowInfo::pCatchableTypeArray`, an RVA.
    pub const THROW_INFO_CATCHABLE_ARRAY: usize = 12;
    /// `ThrowInfo` is four `int`s.
    pub const THROW_INFO_SIZE: usize = 16;
    /// `CatchableTypeArray::nCatchableTypes`, then the RVAs.
    pub const ARRAY_COUNT: usize = 0;
    pub const ARRAY_FIRST_RVA: usize = 4;
    /// `CatchableType::pType`, an RVA to the `TypeDescriptor`.
    pub const CATCHABLE_TYPE_DESCRIPTOR: usize = 4;
    /// `CatchableType::sizeOrOffset` — how big the thrown object is.
    pub const CATCHABLE_SIZE: usize = 20;
    /// `CatchableType` is 28 bytes: two `int`s, a three-`int` `PMD`, then two more `int`s.
    pub const CATCHABLE_TYPE_SIZE: usize = 28;
    /// `TypeDescriptor::name`, the mangled name, after the vtable pointer and a spare — **the
    /// only offset here that moves with the pointer width**, since those two are pointers and
    /// every other field in the graph is a fixed-width `int` either way. Reading a 32-bit
    /// descriptor at the 64-bit offset does not fail, it returns the name eight bytes in:
    /// `.?AUhresult_error@@` reads as `ult_error@@`, which is why this is a table and not a guess.
    pub const TYPE_DESCRIPTOR_NAME_64: usize = 16;
    /// `TypeDescriptor::name` on a 32-bit target.
    pub const TYPE_DESCRIPTOR_NAME_32: usize = 8;
    /// A sanity bound on the catchable-type list. A legitimate hierarchy is a handful deep; a
    /// count past this is a corrupt read, and walking it would be a read loop driven by dump data.
    pub const MAX_CATCHABLE_TYPES: u32 = 64;
    /// A sanity bound on a mangled type name, which is generous — templates get long.
    pub const MAX_NAME: usize = 1024;
}

/// What could be established about a thrown C++ object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThrownError {
    /// Where the object is.
    pub object: u64,
    /// The demangled type, where the name decoded — `winrt::hresult_error`.
    pub type_name: Option<String>,
    /// The mangled name exactly as the `TypeDescriptor` carries it, always reported when the walk
    /// reached one. It is the ground truth behind [`Self::type_name`], and the answer when
    /// demangling declines.
    pub mangled_name: Option<String>,
    /// The object's size in bytes, from `CatchableType::sizeOrOffset`.
    pub size: Option<u32>,
    /// The `HRESULT` the object carries, if one was found and how.
    pub hresult: Option<(u32, Confidence)>,
    /// Why the type could not be named, when it could not. The commonest reason by far is a
    /// minidump without the throwing module's image — see the module docs.
    pub type_note: Option<String>,
}

/// Reads a `u32` at `address`.
fn u32_at(read: &Read<'_>, address: u64) -> Option<u32> {
    let bytes = read(address, 4)?;
    Some(u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?))
}

/// Walks the EH graph and the object, and reports what each route managed.
///
/// Neither route is required to succeed. A dump with the image but a thrown type that is not an
/// `hresult_error` yields a name and no code; a dump without the image but with the stack yields a
/// code and no name; a healthy one yields both, and then they corroborate each other.
pub fn thrown_error(read: &Read<'_>, throw: &CppThrow) -> ThrownError {
    let mut out = ThrownError {
        object: throw.object,
        type_name: None,
        mangled_name: None,
        size: None,
        hresult: None,
        type_note: None,
    };

    match describe_type(read, throw) {
        Some((mangled, size)) => {
            out.type_name = demangle(&mangled);
            out.mangled_name = Some(mangled);
            out.size = size;
        }
        None => {
            out.type_note = Some(
                "the thrown type could not be read: `ThrowInfo` and the descriptors it points at \
                 live in the throwing module's image, which a minidump does not capture — the \
                 debugger reads them from the binary on disk, so this is what a dump from another \
                 machine, or one whose binaries have moved, looks like. The HRESULT below, where \
                 there is one, came from the thrown object on the stack instead."
                    .to_string(),
            );
        }
    }

    // **Corroborated exactly when the other route independently expected this shape.** The type
    // name comes from the compiler's descriptors and the code from a sentinel in the object; when
    // the first says `hresult_error` and the second matches, the offset was expected rather than
    // assumed. Matched on the *mangled* name, which is always present when the graph was read —
    // demangling can decline, and a name this file will not decode is not a weaker fact.
    //
    // **And a name that was read and is not one is contrary evidence, not merely absent evidence.**
    // The sentinel is four bytes with no header behind it, so `0xAABBCCDD` occurs inside objects
    // that are nothing to do with `winrt`; the reason to believe it is that the type said to expect
    // it. When the graph answered `std::runtime_error`, a hit is a coincidence in some member's
    // value, and reporting the next dword as the exception's failure code invents one. So the
    // sentinel runs when the type agrees, or when there is no type to disagree.
    let named_hresult_error = out
        .mangled_name
        .as_deref()
        .map(|name| name.contains("hresult_error"));
    out.hresult = match named_hresult_error {
        Some(false) => None,
        expected => hresult_in(read, throw.object, out.size).map(|hr| {
            (
                hr,
                if expected == Some(true) {
                    Confidence::Corroborated
                } else {
                    Confidence::Convention
                },
            )
        }),
    };
    if out.hresult.is_none() && named_hresult_error == Some(false) {
        out.type_note = Some(format!(
            "the thrown type was read and is not a `winrt::hresult_error`, so the `0xAABBCCDD` \
             sentinel was not looked for: in a type that does not carry one, those four bytes \
             would be some member's value and the dword after it is not an HRESULT. The object is \
             at {:#018x} and its type is above.",
            out.object
        ));
    }
    out
}

/// The mangled type name and object size, from the EH graph. `None` if any link is unreadable.
fn describe_type(read: &Read<'_>, throw: &CppThrow) -> Option<(String, Option<u32>)> {
    let info = read(throw.throw_info, eh::THROW_INFO_SIZE)?;
    let array_rva = u32::from_le_bytes(
        info.get(eh::THROW_INFO_CATCHABLE_ARRAY..eh::THROW_INFO_CATCHABLE_ARRAY + 4)?
            .try_into()
            .ok()?,
    );
    if array_rva == 0 {
        return None;
    }
    let array = throw.image_base.checked_add(array_rva as u64)?;
    let count = u32_at(read, array.checked_add(eh::ARRAY_COUNT as u64)?)?;
    if count == 0 || count > eh::MAX_CATCHABLE_TYPES {
        return None;
    }
    // **The first entry, and only the first.** The array is the thrown type followed by everything
    // it can be caught as — its bases, and `void*` — most-derived first. The rest are how a
    // `catch` matches, not what was thrown.
    let first_rva = u32_at(read, array.checked_add(eh::ARRAY_FIRST_RVA as u64)?)?;
    let catchable = throw.image_base.checked_add(first_rva as u64)?;
    let entry = read(catchable, eh::CATCHABLE_TYPE_SIZE)?;
    let descriptor_rva = u32::from_le_bytes(
        entry
            .get(eh::CATCHABLE_TYPE_DESCRIPTOR..eh::CATCHABLE_TYPE_DESCRIPTOR + 4)?
            .try_into()
            .ok()?,
    );
    let size = u32::from_le_bytes(
        entry
            .get(eh::CATCHABLE_SIZE..eh::CATCHABLE_SIZE + 4)?
            .try_into()
            .ok()?,
    );
    let descriptor = throw.image_base.checked_add(descriptor_rva as u64)?;
    let name = read_c_string(
        read,
        descriptor.checked_add(throw.bitness.type_descriptor_name() as u64)?,
    )?;
    Some((name, (size != 0).then_some(size)))
}

/// Reads up to `want` bytes, shrinking until the target will answer.
///
/// **A fixed-size read fails at the end of a mapped region**, and the end of a mapped region is
/// exactly where the last member of a structure tends to sit. Asking for 32 bytes of a name with
/// 26 left in the section is a read that refuses, and the caller then reports "no type" for a type
/// that is right there. Halving is cheap — at most six attempts — and the alternative is
/// byte-at-a-time reads through a debug engine for every string.
fn read_upto(read: &Read<'_>, address: u64, want: usize) -> Option<Vec<u8>> {
    let mut len = want;
    while len > 0 {
        if let Some(bytes) = read(address, len) {
            return Some(bytes);
        }
        len /= 2;
    }
    None
}

/// Reads a NUL-terminated ASCII string, in chunks, up to [`eh::MAX_NAME`].
///
/// Chunked because the length is not known in advance, and each chunk is read through
/// [`read_upto`] for the reason given there.
fn read_c_string(read: &Read<'_>, address: u64) -> Option<String> {
    let mut out = Vec::new();
    let mut at = address;
    while out.len() < eh::MAX_NAME {
        let chunk = read_upto(read, at, 32)?;
        if chunk.is_empty() {
            break;
        }
        match chunk.iter().position(|byte| *byte == 0) {
            Some(end) => {
                out.extend_from_slice(&chunk[..end]);
                // An empty name is not a name; a `TypeDescriptor` always has one.
                return (!out.is_empty()).then(|| String::from_utf8_lossy(&out).into_owned());
            }
            None => {
                out.extend_from_slice(&chunk);
                at = at.checked_add(chunk.len() as u64)?;
            }
        }
    }
    None
}

/// The `0xAABBCCDD` sentinel a `winrt::hresult_error` carries immediately before its `m_code`.
///
/// See the module docs on provenance: this is a pattern, not a documented layout. It is worth using
/// anyway because it is *checkable* — the dword after it has to decode to a plausible status, and
/// [`decode_status`] is what says whether it does — and because on a minidump without the throwing
/// image it is the only route to the code at all.
const HRESULT_ERROR_SENTINEL: u32 = 0xaabb_ccdd;

/// How far into a thrown object to look for the sentinel, when the object's size is unknown.
///
/// Small on purpose. The sentinel is a four-byte pattern, so a long scan is a long chance of
/// finding one that means nothing — and every `hresult_error` seen carries it within the first few
/// words, because it precedes the first data member.
const SENTINEL_SCAN_BYTES: usize = 64;

/// The `HRESULT` inside a thrown object, located by the sentinel.
///
/// Bounded by the object's own size where the EH graph supplied one, which is the better bound: it
/// stops the scan running off the end of the object into whatever the stack holds next.
fn hresult_in(read: &Read<'_>, object: u64, size: Option<u32>) -> Option<u32> {
    if object == 0 {
        return None;
    }
    // The sentinel and the dword after it both have to fit, so an object smaller than eight bytes
    // cannot be one of these whatever it holds.
    let span = size
        .map_or(SENTINEL_SCAN_BYTES, |size| size as usize)
        .min(SENTINEL_SCAN_BYTES);
    if span < 8 {
        return None;
    }
    // **A window per step rather than one read of the whole span.** The object is on the stack and
    // the span is a bound rather than a measurement, so a single read of 64 bytes refuses whenever
    // the object sits within 64 bytes of the end of what the dump captured — which for the
    // innermost frame's locals is normal. Aligned steps, because these are `int` members of a C++
    // object and not a byte pattern being hunted.
    for offset in (0..=span - 8).step_by(4) {
        let Some(window) = read(object.checked_add(offset as u64)?, 8) else {
            // Unreadable here means unreadable from here on, for the same region.
            break;
        };
        let word = u32::from_le_bytes(window.get(..4)?.try_into().ok()?);
        if word == HRESULT_ERROR_SENTINEL {
            let candidate = u32::from_le_bytes(window.get(4..8)?.try_into().ok()?);
            // **Checked, because the sentinel alone was never the reason to believe it.** Four
            // bytes with no header behind them occur, and the claim made about a hit has always
            // been that the number *after* it decodes — so that has to be tested rather than
            // asserted in prose. A `winrt::hresult_error` exists to carry a failure, so bit 31 is
            // set in every one of them; a success code or an arbitrary member value there means
            // this object is not one and the four bytes were a coincidence.
            //
            // Bit 31 only, not "resolves to a message": a failed HRESULT from a component whose
            // table this host does not have is still a real HRESULT, and `StatusInfo` already
            // reports whether it resolved. Rejecting those would trade a rare false positive for a
            // common false negative.
            if decode_status(candidate).hresult_failed {
                return Some(candidate);
            }
        }
    }
    None
}

/// Turns MSVC's mangled type name into something readable, or declines.
///
/// **Declining is the common case and not a failure.** This handles the shape a thrown exception
/// type actually has — `.?AVhresult_error@winrt@@` for a class, `.?AU...` for a struct, with the
/// namespace list written outermost-last — and nothing else. Templates, back-references and the
/// rest of the MSVC mangling grammar are a decoder this does not need to be: [`ThrownError`] always
/// carries the mangled name, so a caller that meets one of those still has the ground truth and can
/// paste it into a demangler that does.
fn demangle(mangled: &str) -> Option<String> {
    // `.` then `?A` then one character for the aggregate kind.
    let rest = mangled.strip_prefix(".?A")?;
    let mut chars = rest.chars();
    match chars.next()? {
        'V' | 'U' | 'W' | 'T' => {}
        _ => return None,
    }
    let names = chars.as_str().strip_suffix("@@")?;
    // Anything from the rest of the grammar means this is not the simple shape.
    if names.is_empty() || names.contains('?') || names.contains('$') {
        return None;
    }
    let parts: Vec<&str> = names.split('@').collect();
    if parts.iter().any(|part| part.is_empty()) {
        return None;
    }
    Some(parts.into_iter().rev().collect::<Vec<_>>().join("::"))
}

// ---------------------------------------------------------------------------
// Finding a throw the fail-fast buried
// ---------------------------------------------------------------------------

/// How many candidate records [`find_cpp_records`] will report.
///
/// A stack holds one throw's record in the ordinary case and a handful where an exception was
/// rethrown. A scan finding dozens has found a byte pattern, not records, and reporting them all
/// would bury the real one.
const MAX_RECORDS: usize = 8;

/// How much stack to scan in one read.
const SCAN_CHUNK: usize = 4096;

/// Candidate `EXCEPTION_RECORD`s for a C++ throw, found on a stack range.
///
/// **This is the §5 route, and it exists because the fail-fast is not the throw.** When a C++
/// exception goes unhandled, the record the *debugger* sees is `abort`'s `0xc0000409` — the throw
/// happened earlier and its record is a local of a frame between the throw site and
/// `RaiseException`. There is no engine call that returns it; searching the stack for the code is
/// what the walkthrough did by hand.
///
/// Every hit is a **candidate**: `0xe06d7363` is four bytes, and four bytes occur. What promotes
/// one to a record is that the fields behind it are self-consistent, which [`record_at`] checks.
pub fn find_cpp_records(
    read: &Read<'_>,
    stack_low: u64,
    stack_high: u64,
    bitness: Bitness,
) -> Vec<u64> {
    let mut found = Vec::new();
    let needle = STATUS_CPP_EH_EXCEPTION.to_le_bytes();
    let mut at = stack_low;
    while at < stack_high && found.len() < MAX_RECORDS {
        let want = SCAN_CHUNK.min((stack_high - at) as usize);
        // **Shrunk before it is skipped**, and the order matters. A debug engine refuses a read
        // that runs past what the dump captured rather than returning the readable prefix, so a
        // fixed 4 KB chunk fails at every region boundary — and skipping a whole chunk on that
        // failure steps over up to 4 KB of perfectly readable stack. Measured: on the fail-fast
        // dump this walk was written for, the throw's record sits in such a chunk, and the scan
        // found nothing at all until this shrank instead of skipping.
        let Some(chunk) = read_upto(read, at, want) else {
            // Genuinely unreadable even one byte at a time — an unmapped page in the middle of a
            // stack range, which is ordinary in a minidump. Step over it rather than giving up on
            // the range.
            at = at.saturating_add(SCAN_CHUNK as u64);
            continue;
        };
        if chunk.is_empty() {
            break;
        }
        // Stepping by 4: an `EXCEPTION_RECORD` starts with a `DWORD` and is at least
        // `DWORD`-aligned wherever a compiler put it.
        for offset in (0..chunk.len().saturating_sub(3)).step_by(4) {
            if chunk[offset..offset + 4] == needle {
                let candidate = at + offset as u64;
                if record_at(read, candidate, bitness).is_some() {
                    found.push(candidate);
                    if found.len() >= MAX_RECORDS {
                        break;
                    }
                }
            }
        }
        at = at.saturating_add(chunk.len() as u64);
    }
    found
}

/// Offsets into an `EXCEPTION_RECORD` as the compiler lays it out on the target's own stack.
///
/// **Not `EXCEPTION_RECORD64`**, which is the engine's flattened form: this is the native
/// structure, with a real pointer for the nested record and the address. Getting this wrong by one
/// slot is the mistake the walkthrough records making, which is why the parameters are reached from
/// the *count* rather than by assuming four.
///
/// **And "native" means the target's, not this build's.** Three pointer-sized members precede the
/// count, so the whole tail moves: reading a 32-bit target's stack with the 64-bit table finds the
/// count eight bytes late and every parameter at twice its stride, which does not fail — it
/// silently matches nothing, so the scan comes back empty on a target it should have answered.
/// Both rows are measured, by having a throw print `sizeof` and the two offsets under each build.
mod record {
    /// One target's layout.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Layout {
        /// `NumberParameters`, after `ExceptionCode`, `ExceptionFlags`, `ExceptionRecord` and
        /// `ExceptionAddress` — two `DWORD`s and two pointers.
        pub number_parameters: usize,
        /// `ExceptionInformation[0]`, which the `ULONG_PTR` array's alignment can pad up to.
        pub first_parameter: usize,
        /// Each parameter is a `ULONG_PTR`.
        pub parameter_width: usize,
        /// `sizeof(EXCEPTION_RECORD)`.
        pub size: usize,
    }

    /// The array is `EXCEPTION_MAXIMUM_PARAMETERS` long whatever the width.
    pub const MAX_PARAMETERS: u32 = 15;

    /// Measured: `sizeof` 152, count at 24, parameters at 32.
    pub const BITS64: Layout = Layout {
        number_parameters: 24,
        first_parameter: 32,
        parameter_width: 8,
        size: 32 + MAX_PARAMETERS as usize * 8,
    };

    /// Measured: `sizeof` 80, count at 16, parameters at 20 — no padding before the array, because
    /// a `ULONG_PTR` needs none at 4 bytes.
    pub const BITS32: Layout = Layout {
        number_parameters: 16,
        first_parameter: 20,
        parameter_width: 4,
        size: 20 + MAX_PARAMETERS as usize * 4,
    };
}

/// Reads a C++ throw's `EXCEPTION_RECORD` at `address`, if what is there is one.
///
/// The self-consistency check is what makes a stack scan usable: a record must declare a plausible
/// parameter count and carry the EH magic in its first parameter. Four bytes of `0xe06d7363` that
/// are something else fail both.
pub fn record_at(read: &Read<'_>, address: u64, bitness: Bitness) -> Option<CppThrow> {
    let layout = bitness.record();
    let bytes = read(address, layout.size)?;
    let code = u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?);
    if code != STATUS_CPP_EH_EXCEPTION {
        return None;
    }
    let count = u32::from_le_bytes(
        bytes
            .get(layout.number_parameters..layout.number_parameters + 4)?
            .try_into()
            .ok()?,
    );
    // The floor is the target's own: three on a 32-bit throw, which carries no image base.
    let least = bitness.cpp_throw_parameters() as u32;
    if !(least..=record::MAX_PARAMETERS).contains(&count) {
        return None;
    }
    let parameter = |index: usize| -> Option<u64> {
        let at = layout.first_parameter + index * layout.parameter_width;
        let slot = bytes.get(at..at + layout.parameter_width)?;
        Some(match layout.parameter_width {
            4 => u64::from(u32::from_le_bytes(slot.try_into().ok()?)),
            _ => u64::from_le_bytes(slot.try_into().ok()?),
        })
    };
    if parameter(0)? != CPP_EH_MAGIC {
        return None;
    }
    Some(CppThrow {
        object: parameter(1)?,
        throw_info: parameter(2)?,
        // Absent by construction where the count says three, and the zero is then exactly right:
        // the graph's links are absolute on such a target.
        image_base: if count > 3 { parameter(3)? } else { 0 },
        bitness,
    })
}

// ---------------------------------------------------------------------------
// Building the caller's answer
// ---------------------------------------------------------------------------

/// Where a message came from, said once rather than implied.
///
/// The tables are the **host's**, not the target's, so a dump written on a build that words an
/// error differently is described in this machine's words. Worth stating: everything else in an
/// `exception_triage` is a read of the dump, and a sentence that quietly is not would be the one
/// field a caller could not place.
const MESSAGE_PROVENANCE: &str = "the message text is from this host's message tables, not the target's — the codes and the \
     structure beside it are read from the dump";

/// [`StatusDecode`] as the wire type.
pub fn status_info(decode: &StatusDecode) -> crate::structured::StatusInfo {
    let has_message = decode.system_message.is_some() || decode.ntstatus_message.is_some();
    crate::structured::StatusInfo {
        value: format!("{:#010x}", decode.value),
        best_effort: decode.best_effort(),
        symbolic: decode.symbolic.map(str::to_string),
        system_message: decode.system_message.clone(),
        ntstatus_message: decode.ntstatus_message.clone(),
        hresult_failed: decode.hresult_failed,
        ntstatus_severity: decode.ntstatus_severity.as_str().to_string(),
        facility: decode.facility,
        code: u32::from(decode.code),
        customer_defined: decode.customer_defined,
        message_provenance: has_message.then(|| MESSAGE_PROVENANCE.to_string()),
    }
}

/// The one sentence a fault gets, where the code alone would mislead.
///
/// **[`ThrowEvidence`] is what separates a cause from a possibility.** An earlier draft said
/// subcode 7 "means a C++ exception nobody caught", and that is one of its causes rather than its
/// meaning: `abort` is also reached by calling it, by `assert`, by the CRT's invalid-parameter
/// handler, and by `terminate` for reasons that never involved a throw — a `noexcept` function that
/// throws, a joinable `std::thread` destroyed.
///
/// The draft after that named the throw whenever the scan found a record, which is better and still
/// wrong: a found record may be a *handled* exception's, left on the stack by an earlier
/// `try`/`catch`. The draft after *that* tried to corroborate against the stack, which was evidence
/// about the wrong thing — see [`ThrowEvidence`]. A scan earns no claim about cause at all.
fn summary_of(kind: &FaultKind, evidence: ThrowEvidence) -> Option<String> {
    match kind {
        FaultKind::FailFast {
            subcode,
            subcode_name,
            ..
        } => {
            let named = match (subcode, subcode_name) {
                (Some(subcode), Some(name)) => format!("{name} (subcode {subcode:#x})"),
                (Some(subcode), None) => format!("subcode {subcode:#x}"),
                // The record carried no parameters at all, so there is no subcode to name.
                (None, _) => "no subcode: this record carries no parameters".to_string(),
            };
            let abort = if *subcode == Some(FAST_FAIL_FATAL_APP_EXIT) {
                match evidence {
                    ThrowEvidence::Reported | ThrowEvidence::Scanned => {
                        " Subcode 7 is the CRT's abort(): an uncaught C++ exception ends here, but \
                         so does a direct abort(), a failed assert and every other terminate(). A \
                         C++ throw record was found on this stack — THROWN below — and such a \
                         record outlives the frames that held it, so confirm the throw site is on \
                         the stack above before calling it the cause."
                    }
                    ThrowEvidence::None => {
                        " Subcode 7 is the CRT's abort(): an uncaught C++ exception ends here, but \
                         so does a direct abort(), a failed assert and every other terminate() — \
                         and no throw record was found on this stack, so the record does not say \
                         which."
                    }
                }
            } else {
                ""
            };
            // **The lead sentence is conditional, because for two subcodes it would be false.**
            let lead = if subcode.is_some_and(|s| GS_COOKIE_SUBCODES.contains(&s)) {
                "a __fastfail, and one of the two whose code name is the literal truth: a /GS \
                 stack cookie check failed, which means the guard value between a local buffer \
                 and the return address was overwritten. Stack corruption is the finding here, \
                 not a misreading of the code's name"
            } else {
                "a __fastfail — a deliberate process exit, not a stack buffer overrun, whatever \
                 the code's name and the system's message text for it say"
            };
            Some(format!("{lead}. {named} is what says why.{abort}"))
        }
        FaultKind::CppThrow(_) => Some(
            "a C++ throw that reached RaiseException. The thrown object is what carries the \
             failure; the exception code says only that a throw happened."
                .to_string(),
        ),
        FaultKind::AccessViolation { operation, address } => Some(format!(
            "an access violation: the target tried to {operation} {address:#x}."
        )),
        FaultKind::Breakpoint => Some(
            "a breakpoint (int3). On a live target this is usually the debugger's own initial \
             break rather than a fault."
                .to_string(),
        ),
        FaultKind::Other => None,
    }
}

/// Where a throw record came from, and therefore how much it is worth.
///
/// **A record that parses is not a cause, and no amount of scanning makes it one.**
/// `find_cpp_records` promotes a candidate on self-consistency alone, and a C++
/// `EXCEPTION_RECORD` outlives the frames that held it: after a `try`/`catch` the handler unwinds
/// past the record but nothing erases it, so a later `abort()` — called directly, or through a
/// failed `assert`, or through the invalid-parameter handler — running deeper than the old throw
/// site finds one above its stack pointer that parses perfectly.
///
/// **Geometry cannot separate the two**: in both cases the record sits above the current stack
/// pointer inside a live caller's frame. An earlier attempt corroborated it against the *stack* —
/// `KiUserExceptionDispatcher` and friends being present — and that was wrong twice over. It is
/// evidence about the stack rather than about the candidate, so with a genuine unhandled throw
/// following an earlier caught one it would promote whichever record the scan happened to return
/// first; and it depends on symbols, so it answered differently on a host with none, which is
/// exactly the dump-from-another-machine this tool exists for.
///
/// So there is no upgrade. A scanned record is reported as scanned, with the caveat, always. What
/// *is* trustworthy is [`Self::Reported`]: the debugger stopped on the throw itself, and the record
/// is the event rather than something found lying on the stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThrowEvidence {
    /// No record was found, or none was looked for.
    None,
    /// Found by scanning the stack. It may predate this fault.
    Scanned,
    /// The debugger stopped on this throw; it is the reported event.
    Reported,
}

/// Where to start the buried-throw scan, given the walked frames' stack pointers in order.
///
/// **Frame 0, not the lowest.** The two agree on a healthy walk, and the whole reason the scan is
/// anchored here is the *unhealthy* one: frame 0's stack pointer is read from the recorded context
/// rather than produced by unwinding, so it is as good as the dump whatever the frames behind it
/// did. Taking the minimum hands that guarantee back to the unwinder — a frame it could not
/// establish reports a stack pointer of its own, and one bogus low value moves the whole fixed
/// span to the wrong place. A bogus **zero** is worse than that: it is indistinguishable from
/// having no anchor, and the scan is skipped entirely on a dump that has a throw in it.
///
/// Measured on the checked-in x64 fixture with its image moved aside — the case where the outer
/// frames really are garbage — the two agree: the engine still reports increasing stack pointers
/// there. So this is not a bug reproduced on a fixture; it is a guarantee that was being taken from
/// the one frame that has it and given to thirteen that do not.
pub fn scan_anchor(stack_offsets: impl IntoIterator<Item = u64>) -> Option<u64> {
    stack_offsets.into_iter().next().filter(|at| *at != 0)
}

/// Whether a scanned candidate's thrown object is somewhere a thrown object can be.
///
/// **The one correlation that is about the candidate rather than about the stack**, and it is
/// cheap: `_CxxThrowException` copies the thrown object into its caller's frame, so a live throw's
/// object is *on the stack*, inside the region being scanned. A record whose `object` points
/// somewhere else is not a throw that belongs to this thread's current stack at all.
///
/// Measured on `docs/samples/stale-throw-abort.dmp`, where the scan's first candidate reports an
/// `object` of `0x7ff632c172d6` — which is a *code* address in the faulting image, and in fact the
/// return address the walk shows for `staleabort!deep`. Four bytes of `0xe06d7363` on the stack
/// with a plausible count behind them, and nothing more.
///
/// Necessary rather than sufficient: a genuinely stale record from a caught exception has its
/// object on the stack too. That is why it filters rather than corroborates, and why a record that
/// survives it is still only [`ThrowEvidence::Scanned`].
pub fn object_is_on_the_scanned_stack(throw: &CppThrow, low: u64, high: u64) -> bool {
    (low..high).contains(&throw.object)
}

/// Whether this fault is the shape that can have a C++ throw buried under it.
///
/// **The gate on the stack scan, and it is about the fault rather than about the absence of a
/// throw in the record.** Scanning whenever the record carries no throw means scanning on every
/// access violation and every breakpoint — and a C++ `EXCEPTION_RECORD` left behind by an
/// exception the program *caught* stays perfectly legible on the stack long after its frames have
/// gone. An unrelated fault deeper than an old throw site would find one and report it as the
/// thrown object: a specific, plausible, wrong root cause, which is worse than the silence it
/// replaces.
///
/// So the answer is yes for exactly the shape the scan was written for — `abort`'s fail-fast,
/// carrying none of WIL's fields. A WIL fail-fast puts its `HRESULT` in parameter 1, so there is
/// nothing buried to go looking for, and a fail-fast with any other subcode was not reached
/// through `terminate` at all.
pub fn may_bury_a_throw(kind: &FaultKind, parameters: &[u64]) -> bool {
    // **The count is checked here rather than inferred from `wil`,** which is the mistake this
    // replaces: `wil` is `None` for *anything* that is not exactly three parameters, so a
    // subcode-7 record with two or four also passed. The shape the scan exists for is the CRT's,
    // and that is one parameter — the walkthrough's own rule, and the same count the classifier
    // uses to tell the CRT's fail-fast from WIL's.
    parameters.len() == 1
        && matches!(
            kind,
            FaultKind::FailFast {
                subcode: Some(FAST_FAIL_FATAL_APP_EXIT),
                wil: None,
                ..
            }
        )
}

/// The kind, as the one stable word a caller branches on.
fn kind_word(kind: &FaultKind) -> &'static str {
    match kind {
        FaultKind::FailFast { .. } => "fail_fast",
        FaultKind::CppThrow(_) => "cpp_throw",
        FaultKind::AccessViolation { .. } => "access_violation",
        FaultKind::Breakpoint => "breakpoint",
        FaultKind::Other => "other",
    }
}

/// The word [`crate::structured::ThrownErrorInfo::provenance`] carries.
fn provenance_word(evidence: ThrowEvidence) -> Option<&'static str> {
    match evidence {
        ThrowEvidence::None => None,
        ThrowEvidence::Reported => Some("reported"),
        ThrowEvidence::Scanned => Some("scanned"),
    }
}

/// [`ThrownError`] as the wire type.
pub fn thrown_info(
    thrown: &ThrownError,
    evidence: ThrowEvidence,
) -> crate::structured::ThrownErrorInfo {
    crate::structured::ThrownErrorInfo {
        object: format!("{:#018x}", thrown.object),
        type_name: thrown.type_name.clone(),
        mangled_name: thrown.mangled_name.clone(),
        size: thrown.size,
        hresult: thrown
            .hresult
            .map(|(code, _)| status_info(&decode_status(code))),
        hresult_confidence: thrown.hresult.map(|(_, confidence)| {
            match confidence {
                Confidence::Corroborated => "corroborated",
                Confidence::Convention => "convention",
            }
            .to_string()
        }),
        type_note: thrown.type_note.clone(),
        provenance: provenance_word(evidence).map(str::to_string),
    }
}

/// The exception record as the wire type, with its code decoded.
pub fn exception_info(
    record: &dbgscope::dbgeng::ExceptionRecord,
    first_chance: bool,
) -> crate::structured::ExceptionInfo {
    crate::structured::ExceptionInfo {
        code: format!("{:#010x}", record.code),
        // An exception code *is* an `NTSTATUS`, so it is decoded as one rather than guessed at.
        decoded: status_info(&decode_status_as(record.code, Reading::NtStatus)),
        address: format!("{:#018x}", record.address),
        flags: format!("{:#x}", record.flags),
        noncontinuable: record.noncontinuable(),
        first_chance,
        parameters: record
            .parameters
            .iter()
            .map(|value| format!("{value:#018x}"))
            .collect(),
        nested_record: record.nested.map(|at| format!("{at:#018x}")),
    }
}

/// Assembles the caller's answer from the pieces each half established.
#[allow(clippy::too_many_arguments)]
pub fn report(
    record: &dbgscope::dbgeng::ExceptionRecord,
    first_chance: bool,
    kind: &FaultKind,
    thrown: Option<&ThrownError>,
    evidence: ThrowEvidence,
    frames: Vec<crate::structured::FrameInfo>,
    frames_truncated: bool,
    frames_from_stored_context: bool,
    process_name: Option<String>,
) -> crate::structured::ExceptionTriage {
    crate::structured::ExceptionTriage {
        exception: exception_info(record, first_chance),
        kind: kind_word(kind).to_string(),
        summary: summary_of(kind, evidence),
        thrown: thrown.map(|thrown| thrown_info(thrown, evidence)),
        failure: match kind {
            FaultKind::FailFast { wil: Some(wil), .. } => Some(crate::structured::WilFailureInfo {
                hresult: status_info(&decode_status(wil.hresult)),
                line: wil.line,
            }),
            _ => None,
        },
        frames,
        frames_truncated,
        frames_from_stored_context,
        process_name,
    }
}

/// The text half of the answer, rendered from the same values so the two cannot disagree.
pub fn render(triage: &crate::structured::ExceptionTriage) -> String {
    let mut text = String::new();
    text.push_str(&format!(
        "EXCEPTION: {} at {}\n",
        triage.exception.code, triage.exception.address
    ));
    if let Some(best) = &triage.exception.decoded.best_effort {
        text.push_str(&format!("  {best}\n"));
    }
    text.push_str(&format!(
        "  {}, {}\n",
        if triage.exception.first_chance {
            "first chance"
        } else {
            "second chance — nothing in the target handled it"
        },
        if triage.exception.noncontinuable {
            "noncontinuable"
        } else {
            "continuable"
        }
    ));
    for (index, value) in triage.exception.parameters.iter().enumerate() {
        text.push_str(&format!("  Parameter[{index}]: {value}\n"));
    }
    if let Some(summary) = &triage.summary {
        text.push_str(&format!("WHAT THIS IS: {summary}\n"));
    }

    if let Some(failure) = &triage.failure {
        text.push_str(&format!(
            "FAILED WITH: {}{}  (line {})\n",
            failure.hresult.value,
            failure
                .hresult
                .best_effort
                .as_ref()
                .map(|best| format!(" — {best}"))
                .unwrap_or_default(),
            failure.line
        ));
    }

    if let Some(thrown) = &triage.thrown {
        let named = thrown
            .type_name
            .as_deref()
            .or(thrown.mangled_name.as_deref())
            .unwrap_or("<type unread>");
        text.push_str(&format!("THROWN: {named} at {}\n", thrown.object));
        if let Some(hresult) = &thrown.hresult {
            text.push_str(&format!(
                "  carries {}{}\n",
                hresult.value,
                hresult
                    .best_effort
                    .as_ref()
                    .map(|best| format!(" — {best}"))
                    .unwrap_or_default()
            ));
            text.push_str(
                "  found by the winrt::hresult_error sentinel, which no header states — the \
                 value after it is checked to be a failed HRESULT, so it is believable because of \
                 what it is rather than where it sat.\n",
            );
        }
        if thrown.provenance.as_deref() == Some("scanned") {
            text.push_str(
                "  CAUTION: found by scanning the stack rather than reported by the debugger. \
                 Such a record outlives the frames that held it, so this may be from an exception \
                 the program caught earlier rather than the cause of this fault.\n",
            );
        }
        if let Some(note) = &thrown.type_note {
            text.push_str(&format!("  {note}\n"));
        }
    }

    if let Some(process) = &triage.process_name {
        text.push_str(&format!("PROCESS: {process}\n"));
    }
    text.push_str(&format!(
        "\nSTACK ({} frames, {}):\n",
        triage.frames.len(),
        if triage.frames_from_stored_context {
            "from the stored crash context"
        } else {
            "from the selected thread — this target stores no event, so it is not promised to be \
             the crash"
        }
    ));
    for frame in &triage.frames {
        text.push_str(&format!(
            "  {:02} {}\n",
            frame.index,
            crate::triage::describe(frame)
        ));
    }
    if triage.frames_truncated {
        text.push_str("  ... (stack continues; raise `frames`)\n");
    }
    text
}

/// A memory image for tests: address to bytes, read as one flat space.
///
/// Public to the crate because the tool's own tests build fixtures with it too, and a second
/// implementation of "fake memory" is a second thing to get wrong.
#[cfg(test)]
pub struct FakeMemory {
    regions: std::collections::BTreeMap<u64, Vec<u8>>,
}

#[cfg(test)]
impl FakeMemory {
    pub fn new() -> Self {
        Self {
            regions: std::collections::BTreeMap::new(),
        }
    }

    pub fn put(&mut self, address: u64, bytes: impl Into<Vec<u8>>) -> &mut Self {
        self.regions.insert(address, bytes.into());
        self
    }

    /// Reads across the region that contains `address`, and refuses a read that would run past its
    /// end — the same way an unmapped page refuses one.
    pub fn read(&self, address: u64, len: usize) -> Option<Vec<u8>> {
        let (start, bytes) = self
            .regions
            .range(..=address)
            .next_back()
            .filter(|(start, bytes)| address < **start + bytes.len() as u64)?;
        let offset = (address - start) as usize;
        bytes.get(offset..offset + len).map(<[u8]>::to_vec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a `ThrowInfo`/`CatchableTypeArray`/`CatchableType`/`TypeDescriptor` graph.
    ///
    /// `bitness` moves one thing — where the descriptor's name starts — because that is the only
    /// offset in the graph that is not a fixed-width `int` on both. On a 32-bit target `base` is
    /// zero and the "RVAs" written here are then the absolute addresses, which is exactly how the
    /// real thing works.
    fn eh_graph(memory: &mut FakeMemory, base: u64, mangled: &str, size: u32, bitness: Bitness) {
        // ThrowInfo at base+0x1000, pointing at the array by RVA.
        let mut info = vec![0u8; eh::THROW_INFO_SIZE];
        info[eh::THROW_INFO_CATCHABLE_ARRAY..eh::THROW_INFO_CATCHABLE_ARRAY + 4]
            .copy_from_slice(&0x2000u32.to_le_bytes());
        memory.put(base + 0x1000, info);

        // The array: one entry, pointing at the catchable type by RVA.
        let mut array = vec![0u8; 8];
        array[eh::ARRAY_COUNT..eh::ARRAY_COUNT + 4].copy_from_slice(&1u32.to_le_bytes());
        array[eh::ARRAY_FIRST_RVA..eh::ARRAY_FIRST_RVA + 4]
            .copy_from_slice(&0x3000u32.to_le_bytes());
        memory.put(base + 0x2000, array);

        // The catchable type: descriptor RVA and the object's size.
        let mut catchable = vec![0u8; eh::CATCHABLE_TYPE_SIZE];
        catchable[eh::CATCHABLE_TYPE_DESCRIPTOR..eh::CATCHABLE_TYPE_DESCRIPTOR + 4]
            .copy_from_slice(&0x4000u32.to_le_bytes());
        catchable[eh::CATCHABLE_SIZE..eh::CATCHABLE_SIZE + 4].copy_from_slice(&size.to_le_bytes());
        memory.put(base + 0x3000, catchable);

        // The descriptor: vtable, spare, then the name.
        let mut descriptor = vec![0u8; bitness.type_descriptor_name()];
        descriptor.extend_from_slice(mangled.as_bytes());
        descriptor.push(0);
        memory.put(base + 0x4000, descriptor);
    }

    /// An `EXCEPTION_RECORD` for a C++ throw, laid out at the target's width.
    ///
    /// One builder for both, so a test cannot accidentally assert 64-bit offsets against a 32-bit
    /// claim: the offsets come from the same table the code under test uses, and what each test
    /// supplies is the parameter list a target of that width would really raise.
    fn cpp_record(bitness: Bitness, parameters: &[u64]) -> Vec<u8> {
        let layout = bitness.record();
        let mut bytes = vec![0u8; layout.size];
        bytes[..4].copy_from_slice(&STATUS_CPP_EH_EXCEPTION.to_le_bytes());
        let count = parameters.len() as u32;
        bytes[layout.number_parameters..layout.number_parameters + 4]
            .copy_from_slice(&count.to_le_bytes());
        for (index, value) in parameters.iter().enumerate() {
            let at = layout.first_parameter + index * layout.parameter_width;
            match layout.parameter_width {
                4 => bytes[at..at + 4].copy_from_slice(&(*value as u32).to_le_bytes()),
                _ => bytes[at..at + 8].copy_from_slice(&value.to_le_bytes()),
            }
        }
        bytes
    }

    /// A `winrt::hresult_error`-shaped object: sentinel then code, behind a vtable slot.
    fn hresult_object(code: u32) -> Vec<u8> {
        let mut object = vec![0u8; 8];
        object.extend_from_slice(&HRESULT_ERROR_SENTINEL.to_le_bytes());
        object.extend_from_slice(&code.to_le_bytes());
        object
    }

    /// **The offsets are MSVC's, transcribed from a real throw.**
    ///
    /// The fixture below reproduces the graph read out of an actual `cl.exe` 14.50 x64 binary in
    /// `docs/explorer-crash-walkthrough.md`'s idiom: `ThrowInfo+12` gave the array RVA, the array
    /// held `count=1` and one RVA, `CatchableType+4` gave the descriptor RVA and `+20` the size
    /// `0x10`, and `TypeDescriptor+16` was `.?AUhresult_error@@`. A test over synthetic memory can
    /// only ever check that this code reads the layout it was told to; what makes the layout right
    /// is that measurement, and this comment is where it is recorded.
    #[test]
    fn test_the_eh_graph_yields_the_thrown_type_and_size() {
        let base = 0x7ff6_a1d9_0000;
        let object_at = 0x0000_008d_e693_fd60;
        let mut memory = FakeMemory::new();
        eh_graph(
            &mut memory,
            base,
            ".?AVhresult_error@winrt@@",
            0x10,
            Bitness::Bits64,
        );
        memory.put(object_at, hresult_object(0x8067_0015));
        let read = |address, len| memory.read(address, len);

        let throw = CppThrow {
            object: object_at,
            throw_info: base + 0x1000,
            image_base: base,
            bitness: Bitness::Bits64,
        };
        let thrown = thrown_error(&read, &throw);
        assert_eq!(thrown.type_name.as_deref(), Some("winrt::hresult_error"));
        assert_eq!(
            thrown.mangled_name.as_deref(),
            Some(".?AVhresult_error@winrt@@")
        );
        assert_eq!(thrown.size, Some(0x10));
        // **Corroborated, not merely conventional**: the graph named the type an
        // `hresult_error` and the sentinel then matched, which is the cross-check that makes the
        // offset expected rather than assumed. The test below is the same object with no image to
        // name it, and reads `Convention` — the pair is the assertion.
        assert_eq!(
            thrown.hresult,
            Some((0x8067_0015, Confidence::Corroborated))
        );
        assert!(
            thrown.type_note.is_none(),
            "a walk that succeeded still explained why it had not"
        );
    }

    /// **The image is missing, which is what a minidump from another machine looks like.**
    ///
    /// Measured, not imagined: the same WER minidump reads the graph fine while the executable is
    /// on disk and answers `????????` once it is moved aside, because the debugger had been reading
    /// the image rather than the dump. So the sentinel route has to carry the answer alone, and the
    /// result has to say why the type is missing rather than leaving a caller to wonder.
    #[test]
    fn test_a_dump_without_the_image_still_yields_the_hresult() {
        let object_at = 0x0000_008d_e693_fd60;
        let mut memory = FakeMemory::new();
        // The stack is captured; nothing of the module is.
        memory.put(object_at, hresult_object(0x8007_3d54));
        let read = |address, len| memory.read(address, len);

        let thrown = thrown_error(
            &read,
            &CppThrow {
                object: object_at,
                throw_info: 0x7ff6_a1e2_aa00,
                image_base: 0x7ff6_a1d9_0000,
                bitness: Bitness::Bits64,
            },
        );
        assert_eq!(thrown.type_name, None);
        assert_eq!(thrown.mangled_name, None);
        assert_eq!(
            thrown.hresult,
            Some((0x8007_3d54, Confidence::Convention)),
            "with no type name to expect the shape, the sentinel stands alone and must say so"
        );
        let note = thrown
            .type_note
            .expect("no note explained the missing type");
        assert!(
            note.contains("minidump"),
            "the note did not name the reason a caller will actually hit: {note}"
        );
    }

    /// **The whole pipeline, over bytes transcribed from a real dump rather than invented.**
    ///
    /// The fixtures above are built by this file's own helpers, which means they can only ever
    /// check that the reader agrees with the writer — if my model of MSVC's layout were wrong,
    /// both halves would be wrong together and every test would pass. This one is immune to that:
    /// every byte below was read out of an actual WER minidump of an actual `cl.exe` 14.50 x64
    /// `throw`, through this server's own `execute`, and transcribed. Addresses are that dump's.
    ///
    /// It is the answer to "a fixture that flattens a real distinction hides the bugs its test is
    /// for": if a single offset in `mod eh` is wrong, this fails and the synthetic tests do not.
    #[test]
    fn test_the_pipeline_decodes_bytes_transcribed_from_a_real_dump() {
        let base = 0x7ff6_a1d9_0000_u64;
        let mut memory = FakeMemory::new();

        // `dd 0x8de693fc00 L10` — the throw's EXCEPTION_RECORD, found by scanning the stack for
        // `e06d7363` because the *last* event was `abort`'s fail-fast, not this.
        //   e06d7363 00000081 00000000 00000000
        //   98f7187a 00007ffc 00000004 00000000
        //   19930520 00000000 e693fd60 0000008d
        //   a1e2aa00 00007ff6 a1d90000 00007ff6
        let throw_record = 0x0000_008d_e693_fc00_u64;
        let mut record_bytes = Vec::new();
        for word in [
            0xe06d_7363_u32,
            0x0000_0081,
            0x0000_0000,
            0x0000_0000,
            0x98f7_187a,
            0x0000_7ffc,
            0x0000_0004,
            0x0000_0000,
            0x1993_0520,
            0x0000_0000,
            0xe693_fd60,
            0x0000_008d,
            0xa1e2_aa00,
            0x0000_7ff6,
            0xa1d9_0000,
            0x0000_7ff6,
        ] {
            record_bytes.extend_from_slice(&word.to_le_bytes());
        }
        // The record declares four parameters and the reader reads fifteen slots' worth, so the
        // tail past the four real ones is whatever the stack held. Zeroed here.
        record_bytes.resize(Bitness::Bits64.record().size, 0);
        memory.put(throw_record, record_bytes);

        // `dd 0x8de693fd60 L4` — the thrown object: 00000000 00000000 aabbccdd 80670015
        memory.put(
            0x0000_008d_e693_fd60_u64,
            [0u8; 8]
                .into_iter()
                .chain(0xaabb_ccddu32.to_le_bytes())
                .chain(0x8067_0015u32.to_le_bytes())
                .collect::<Vec<u8>>(),
        );

        // `dd 0x7ff6a1e2aa00 L4` — ThrowInfo: 00000000 00000000 00000000 0009aa20
        memory.put(
            base + 0x9_aa00,
            [0u8; 12]
                .into_iter()
                .chain(0x0009_aa20u32.to_le_bytes())
                .collect::<Vec<u8>>(),
        );
        // `dd base+0x9aa20 L4` — CatchableTypeArray: 00000001 0009aa30 ...
        memory.put(
            base + 0x9_aa20,
            1u32.to_le_bytes()
                .into_iter()
                .chain(0x0009_aa30u32.to_le_bytes())
                .collect::<Vec<u8>>(),
        );
        // `dd base+0x9aa30 L7` — CatchableType:
        //   00000000 0009be28 00000000 ffffffff 00000000 00000010 00000000
        let mut catchable = Vec::new();
        for word in [
            0x0000_0000u32,
            0x0009_be28,
            0x0000_0000,
            0xffff_ffff,
            0x0000_0000,
            0x0000_0010,
            0x0000_0000,
        ] {
            catchable.extend_from_slice(&word.to_le_bytes());
        }
        memory.put(base + 0x9_aa30, catchable);
        // `da base+0x9be28+0x10` — TypeDescriptor's name: ".?AUhresult_error@@"
        let mut descriptor = vec![0u8; Bitness::Bits64.type_descriptor_name()];
        descriptor.extend_from_slice(b".?AUhresult_error@@\0");
        memory.put(base + 0x9_be28, descriptor);

        let read = |address, len| memory.read(address, len);

        // The record parses, and its parameters are the four the walkthrough names.
        let throw =
            record_at(&read, throw_record, Bitness::Bits64).expect("the real record did not parse");
        assert_eq!(throw.object, 0x0000_008d_e693_fd60);
        assert_eq!(throw.throw_info, base + 0x9_aa00);
        assert_eq!(
            throw.image_base, base,
            "parameter 3 is the image base, and the RVAs below are relative to it"
        );

        // And the whole graph resolves, both routes agreeing.
        let thrown = thrown_error(&read, &throw);
        assert_eq!(thrown.mangled_name.as_deref(), Some(".?AUhresult_error@@"));
        assert_eq!(thrown.type_name.as_deref(), Some("hresult_error"));
        assert_eq!(thrown.size, Some(0x10));
        assert_eq!(
            thrown.hresult,
            Some((0x8067_0015, Confidence::Corroborated)),
            "the graph named the type, so the sentinel hit is corroborated"
        );

        // The code decodes to the sentence that redirected the whole investigation — which is what
        // makes a number found at a convention-located offset believable.
        let status = decode_status(0x8067_0015);
        assert!(
            status
                .system_message
                .as_deref()
                .is_some_and(|m| m.contains("StateRepository")),
            "the HRESULT decoded from real bytes did not resolve to a message: {status:?}"
        );
    }

    /// The two shapes of `0xc0000409`, told apart by the parameter count and nothing else.
    ///
    /// The walkthrough's own rule, from getting both in one evening: one parameter is the CRT's
    /// `abort`, whose cause is in a thrown object, and three is WIL's, whose cause is right there.
    #[test]
    fn test_the_parameter_count_decides_which_fail_fast_this_is() {
        let crt = classify(STATUS_STACK_BUFFER_OVERRUN, &[7], Bitness::Bits64);
        assert_eq!(
            crt,
            FaultKind::FailFast {
                subcode: Some(7),
                subcode_name: Some("FAST_FAIL_FATAL_APP_EXIT"),
                wil: None,
            },
            "a one-parameter fail-fast was read as carrying WIL's extras"
        );

        // **Four parameters is not WIL's shape either**, and the direction matters: reading a
        // record that merely has *at least* three as WIL's puts two arbitrary stack values on the
        // wire named `hresult` and `line`, which a reader has no way to distrust. Three is the
        // discriminator, so it is asserted from both sides.
        let four = classify(
            STATUS_STACK_BUFFER_OVERRUN,
            &[7, 0xffff_ffff_8000_ffff, 0x28f, 0x1234],
            Bitness::Bits64,
        );
        assert_eq!(
            four,
            FaultKind::FailFast {
                subcode: Some(7),
                subcode_name: Some("FAST_FAIL_FATAL_APP_EXIT"),
                wil: None,
            },
            "a four-parameter fail-fast was read as WIL's, inventing an HRESULT and a line"
        );

        // The walkthrough's second fault, verbatim.
        let wil = classify(
            STATUS_STACK_BUFFER_OVERRUN,
            &[7, 0xffff_ffff_8000_ffff, 0x28f],
            Bitness::Bits64,
        );
        let FaultKind::FailFast { wil: Some(wil), .. } = wil else {
            panic!("a three-parameter fail-fast was not read as WIL's");
        };
        assert_eq!(
            wil.hresult, 0x8000_ffff,
            "the sign extension was not trimmed, so the HRESULT is not one"
        );
        assert_eq!(wil.line, 0x28f);
        assert_eq!(
            decode_status(wil.hresult).symbolic,
            Some("E_UNEXPECTED"),
            "the HRESULT the walkthrough read as E_UNEXPECTED decodes as something else"
        );
    }

    /// **The layout numbers, as literals, because every other test here would agree with a wrong
    /// table.**
    ///
    /// `eh_graph` and `cpp_record` build their fixtures through the same `Bitness` methods that
    /// [`record_at`] and [`describe_type`] read them back through, so changing a constant moves the
    /// fixture with the parser and every one of those tests stays green. They check that the code
    /// reads the layout it was told to; only this one checks *which* layout it was told.
    ///
    /// The numbers are measured, by building one program twice and having it print `sizeof`, the
    /// two offsets, and the name it finds at each candidate — `docs/samples/cppthrow.cpp`'s shape
    /// under `cl /EHa` for x86 and x64. Reading the 32-bit descriptor at the 64-bit offset does not
    /// fail; it returns `ult_error@@` where `.?AUhresult_error@@` was, which is a silent wrong
    /// answer and exactly why it is nailed down here.
    #[test]
    fn test_the_layout_table_is_the_measured_one() {
        // sizeof(EXCEPTION_RECORD): 152 and 80.
        assert_eq!(Bitness::Bits64.record().size, 152);
        assert_eq!(Bitness::Bits32.record().size, 80);
        // offsetof(NumberParameters): four `DWORD`/pointer members precede it.
        assert_eq!(Bitness::Bits64.record().number_parameters, 24);
        assert_eq!(Bitness::Bits32.record().number_parameters, 16);
        // offsetof(ExceptionInformation).
        assert_eq!(Bitness::Bits64.record().first_parameter, 32);
        assert_eq!(Bitness::Bits32.record().first_parameter, 20);
        assert_eq!(Bitness::Bits64.record().parameter_width, 8);
        assert_eq!(Bitness::Bits32.record().parameter_width, 4);
        // TypeDescriptor::name, past a vtable pointer and a spare.
        assert_eq!(Bitness::Bits64.type_descriptor_name(), 16);
        assert_eq!(Bitness::Bits32.type_descriptor_name(), 8);
        // What a throw raises, which is the whole of the x86 difference in `classify`.
        assert_eq!(Bitness::Bits64.cpp_throw_parameters(), 4);
        assert_eq!(Bitness::Bits32.cpp_throw_parameters(), 3);
    }

    /// **A 32-bit record on a 32-bit stack, read end to end.**
    ///
    /// The pair to the 64-bit scan test above, and not a copy of it: the record is half the size,
    /// its count sits eight bytes earlier, its parameters are four bytes apart and there are three
    /// of them, and the graph it points at holds absolute addresses rather than RVAs. Every one of
    /// those is a way the 64-bit reader silently finds nothing rather than failing, which is what
    /// it did on the real 32-bit dump before this.
    #[test]
    fn test_a_32_bit_throw_is_found_and_walked_on_a_32_bit_stack() {
        let stack = 0x00af_e000_u64;
        let base = 0; // A 32-bit graph's links are absolute, so there is no base to add.
        let object_at = stack + 0x800;
        let mut memory = FakeMemory::new();
        // The graph, hung off address 0 the way `image_base` of zero makes the arithmetic work.
        eh_graph(
            &mut memory,
            base,
            ".?AUhresult_error@@",
            0x10,
            Bitness::Bits32,
        );

        let mut page = vec![0u8; 0x1000];
        let record_offset = 0x400;
        let rec = cpp_record(Bitness::Bits32, &[CPP_EH_MAGIC, object_at, base + 0x1000]);
        assert_eq!(rec.len(), 80, "the fixture is not a 32-bit record");
        page[record_offset..record_offset + rec.len()].copy_from_slice(&rec);
        page[0x800..0x810].copy_from_slice(&hresult_object(0x8067_0015));
        memory.put(stack, page);
        let read = |address, len| memory.read(address, len);

        let hits = find_cpp_records(&read, stack, stack + 0x1000, Bitness::Bits32);
        assert_eq!(
            hits,
            vec![stack + record_offset as u64],
            "the 32-bit record was not found on a 32-bit stack"
        );
        let throw = record_at(&read, hits[0], Bitness::Bits32).expect("the record did not parse");
        assert_eq!(throw.image_base, 0, "a 32-bit throw declares no image base");
        let thrown = thrown_error(&read, &throw);
        assert_eq!(thrown.type_name.as_deref(), Some("hresult_error"));
        assert_eq!(
            thrown.hresult,
            Some((0x8067_0015, Confidence::Corroborated)),
            "the 32-bit graph named the type, so the sentinel hit is corroborated"
        );

        // **And the 64-bit reader finds nothing here**, which is the half that says the two
        // layouts are really different rather than the wide one being a superset.
        assert!(
            find_cpp_records(&read, stack, stack + 0x1000, Bitness::Bits64).is_empty(),
            "the 64-bit reader accepted a 32-bit record, so this test proves nothing"
        );
    }

    /// **The buried-throw scan runs on one fault shape, and the list of what it declines is the
    /// test.**
    ///
    /// The scan reads raw stack looking for a C++ `EXCEPTION_RECORD`, and such a record outlives
    /// the frames that held it — an exception the program caught leaves one behind that is still
    /// perfectly legible. Running the scan on any fault that merely lacks a throw in its own record
    /// means an access violation deeper than an old throw site reports that stale object as its
    /// cause: specific, plausible and wrong.
    #[test]
    fn test_only_an_abort_fail_fast_goes_looking_for_a_buried_throw() {
        let gate = |parameters: &[u64]| {
            let kind = classify(STATUS_STACK_BUFFER_OVERRUN, parameters, Bitness::Bits64);
            may_bury_a_throw(&kind, parameters)
        };

        // The shape it exists for: the CRT's `abort`, one parameter, cause not in its own record.
        assert!(gate(&[FAST_FAIL_FATAL_APP_EXIT]));

        // **Every other count is refused, and the count is checked rather than inferred.** Reading
        // it off `wil` — which is `None` for anything that is not exactly three — let two- and
        // four-parameter subcode-7 records through, since neither is WIL's either.
        assert!(
            !gate(&[FAST_FAIL_FATAL_APP_EXIT, 0x1234]),
            "a two-parameter fail-fast is not the CRT's one-parameter abort"
        );
        assert!(
            !gate(&[FAST_FAIL_FATAL_APP_EXIT, 0xffff_ffff_8000_ffff, 0x28f]),
            "a WIL fail-fast has its cause in the record and must not be hunted for another"
        );
        assert!(
            !gate(&[FAST_FAIL_FATAL_APP_EXIT, 1, 2, 3]),
            "a four-parameter fail-fast is some third thing, not the CRT's"
        );

        // Another subcode is another mechanism entirely — a stack cookie, a corrupt list entry —
        // and none of them arrives through `terminate`.
        assert!(!gate(&[2]));

        // And the faults that motivated the gate: these all lack a throw in the record, which is
        // the property the first version keyed on.
        let av = classify(STATUS_ACCESS_VIOLATION, &[1, 0xdead_beef], Bitness::Bits64);
        assert!(!may_bury_a_throw(&av, &[1, 0xdead_beef]));
        let bp = classify(STATUS_BREAKPOINT, &[], Bitness::Bits64);
        assert!(!may_bury_a_throw(&bp, &[]));

        // A real throw needs no scan; the record is the throw.
        let throw = classify(
            STATUS_CPP_EH_EXCEPTION,
            &[CPP_EH_MAGIC, 1, 2, 3],
            Bitness::Bits64,
        );
        assert!(!may_bury_a_throw(&throw, &[CPP_EH_MAGIC, 1, 2, 3]));
    }

    /// **For two subcodes the code's name is the literal truth, and the summary must not dismiss
    /// it.**
    ///
    /// `0xc0000409` is `STATUS_STACK_BUFFER_OVERRUN` and almost never one — except when the subcode
    /// says a `/GS` cookie check failed, which is the compiler reporting that the guard between a
    /// local buffer and the return address was overwritten. Leading with "not a stack buffer
    /// overrun" there sends a reader away from the actual defect.
    #[test]
    fn test_a_gs_cookie_failure_is_not_told_it_is_not_stack_corruption() {
        for subcode in [0u64, 2] {
            let kind = classify(STATUS_STACK_BUFFER_OVERRUN, &[subcode], Bitness::Bits64);
            let text = summary_of(&kind, ThrowEvidence::None).expect("a fail-fast gets a summary");
            assert!(
                !text.contains("not a stack buffer overrun"),
                "subcode {subcode} is a /GS cookie failure and was told it was not corruption: \
                 {text}"
            );
            assert!(
                text.contains("Stack corruption is the finding"),
                "a /GS cookie failure has to say what it is: {text}"
            );
        }

        // And every other subcode keeps the dismissal, which is the reason the tool exists.
        let abort = classify(
            STATUS_STACK_BUFFER_OVERRUN,
            &[FAST_FAIL_FATAL_APP_EXIT],
            Bitness::Bits64,
        );
        let text = summary_of(&abort, ThrowEvidence::None).expect("a fail-fast gets a summary");
        assert!(text.contains("not a stack buffer overrun"), "{text}");
    }

    /// **The dword after the sentinel is checked, because "it decodes" was only ever prose.**
    ///
    /// The sentinel is four bytes with no header behind it, so it occurs by chance. The claim made
    /// about a hit has always been that the number after it decodes — which was asserted in a
    /// sentence and tested nowhere. A `winrt::hresult_error` exists to carry a failure, so bit 31
    /// is set in every one of them.
    #[test]
    fn test_a_sentinel_hit_that_is_not_a_failed_hresult_is_declined() {
        let object_at = 0x1000;
        let sentinel_object = |code: u32| {
            let mut bytes = vec![0u8; 8];
            bytes.extend_from_slice(&HRESULT_ERROR_SENTINEL.to_le_bytes());
            bytes.extend_from_slice(&code.to_le_bytes());
            bytes
        };

        // A real one.
        let mut memory = FakeMemory::new();
        memory.put(object_at, sentinel_object(0x8067_0015));
        let read = |address, len| memory.read(address, len);
        assert_eq!(hresult_in(&read, object_at, Some(16)), Some(0x8067_0015));

        // `S_OK` after the sentinel: an object that is not one of these, and four coincidental
        // bytes. Reporting `0` as the exception's failure code would be worse than nothing.
        let mut memory = FakeMemory::new();
        memory.put(object_at, sentinel_object(0));
        let read = |address, len| memory.read(address, len);
        assert_eq!(
            hresult_in(&read, object_at, Some(16)),
            None,
            "a success code was reported as a thrown error's HRESULT"
        );

        // An arbitrary small member value, likewise.
        let mut memory = FakeMemory::new();
        memory.put(object_at, sentinel_object(42));
        let read = |address, len| memory.read(address, len);
        assert_eq!(hresult_in(&read, object_at, Some(16)), None);

        // A failed HRESULT this host has no message for is still a real one, and is kept — the
        // check is structural, so an unknown component's code is not thrown away.
        let mut memory = FakeMemory::new();
        memory.put(object_at, sentinel_object(0x8bad_f00d));
        let read = |address, len| memory.read(address, len);
        assert_eq!(hresult_in(&read, object_at, Some(16)), Some(0x8bad_f00d));
    }

    /// **The summary reports what the record says and stops there.**
    ///
    /// An earlier version said subcode 7 "means a C++ exception nobody caught". That is one of its
    /// causes, not its meaning: `abort` is also reached by calling it, by a failed `assert`, by the
    /// CRT's invalid-parameter handler, and by `terminate` for reasons with no throw in them at all
    /// — a `noexcept` function that throws, a joinable `std::thread` destroyed. Nothing in the
    /// record distinguishes those, so the claim was free.
    #[test]
    fn test_the_abort_summary_claims_a_throw_only_when_one_was_found() {
        let abort = classify(
            STATUS_STACK_BUFFER_OVERRUN,
            &[FAST_FAIL_FATAL_APP_EXIT],
            Bitness::Bits64,
        );

        let alone =
            summary_of(&abort, ThrowEvidence::None).expect("a fail-fast always gets a summary");
        assert!(
            alone.contains("FAST_FAIL_FATAL_APP_EXIT"),
            "the subcode is what says why, and has to be named: {alone}"
        );
        assert!(
            !alone.contains("nobody caught"),
            "the summary asserted an uncaught exception with no throw record to show for it: \
             {alone}"
        );
        assert!(
            alone.contains("so does a direct abort()"),
            "a summary that cannot tell the causes apart has to say so: {alone}"
        );

        // **A record that parses does not become the cause, and there is no third state where it
        // does.** An `abort()` called directly after the program caught an exception earlier finds
        // that exception's record, still valid, above its stack pointer - and no property of the
        // *stack* distinguishes that from a genuine unhandled throw, which is why an earlier
        // attempt to corroborate one was withdrawn.
        for evidence in [ThrowEvidence::Scanned, ThrowEvidence::Reported] {
            let text = summary_of(&abort, evidence).expect("a fail-fast always gets a summary");
            assert!(
                !text.contains("nobody caught"),
                "a found record was reported as the cause ({evidence:?}): {text}"
            );
            assert!(
                text.contains("confirm the throw site"),
                "a found record has to say what would settle it ({evidence:?}): {text}"
            );
        }

        // And another subcode gets neither sentence, rather than the abort story with a different
        // number in it.
        let cookie = classify(STATUS_STACK_BUFFER_OVERRUN, &[2], Bitness::Bits64);
        let text =
            summary_of(&cookie, ThrowEvidence::None).expect("a fail-fast always gets a summary");
        assert!(!text.contains("abort()"), "{text}");
        assert!(
            text.contains("FAST_FAIL_STACK_COOKIE_CHECK_FAILURE"),
            "{text}"
        );
    }

    /// **A candidate is checked against what it points at, which is about the record rather than
    /// about the stack.**
    ///
    /// `_CxxThrowException` copies the thrown object into its caller's frame, so a live throw's
    /// object is on the stack inside the range being scanned. Measured on the checked-in
    /// stale-abort dump, whose first candidate reports an `object` of `0x7ff632c172d6` - a code
    /// address in the faulting image, and in fact the return address the walk shows for
    /// `staleabort!deep`. Four bytes of `0xe06d7363` with a plausible count behind them, nothing
    /// more.
    ///
    /// The predecessor of this check corroborated against the *stack* - looking for
    /// `KiUserExceptionDispatcher` and friends - and was wrong twice: it said nothing about which
    /// candidate was chosen, and it depended on symbols, so it answered differently on a host
    /// without them. That is the dump-from-another-machine this tool is for.
    #[test]
    fn test_a_candidates_object_has_to_be_on_the_stack_that_was_scanned() {
        let low = 0x0000_008d_e693_e000_u64;
        let high = low + 0x1_0000;
        let throw = |object| CppThrow {
            object,
            throw_info: 0,
            image_base: 0,
            bitness: Bitness::Bits64,
        };

        assert!(object_is_on_the_scanned_stack(
            &throw(low + 0x800),
            low,
            high
        ));
        assert!(object_is_on_the_scanned_stack(&throw(low), low, high));

        // The measured false positive: an address in the image, not on the stack.
        assert!(
            !object_is_on_the_scanned_stack(&throw(0x7ff6_32c1_72d6), low, high),
            "a record pointing into the image was accepted as a throw on this stack"
        );
        // And the ends are checked, since a record found at the very top of the range would
        // otherwise reach past what was read.
        assert!(!object_is_on_the_scanned_stack(&throw(high), low, high));
        assert!(!object_is_on_the_scanned_stack(&throw(low - 1), low, high));
        assert!(!object_is_on_the_scanned_stack(&throw(0), low, high));
    }

    /// **No name in this table may shadow a code this module itself classifies as a fault.**
    ///
    /// The table used to carry the non-Win32 `E_*` values, where `0x80000003` is `E_INVALIDARG` —
    /// and `0x80000003` is `STATUS_BREAKPOINT`, a constant defined twenty lines away in this same
    /// file. Since `best_effort` prefers the symbolic name, every breakpoint decoded as
    /// `E_INVALIDARG`. This is the assertion that the two namespaces stay apart, written against
    /// the codes this module actually meets rather than against all of `ntstatus.h`.
    #[test]
    fn test_no_well_known_name_shadows_a_code_this_module_classifies() {
        for code in [
            STATUS_BREAKPOINT,
            STATUS_ACCESS_VIOLATION,
            STATUS_STACK_BUFFER_OVERRUN,
            STATUS_CPP_EH_EXCEPTION,
            0x8000_0004, // STATUS_SINGLE_STEP
            0x8000_0001, // STATUS_GUARD_PAGE_VIOLATION
            0x8000_0002, // STATUS_DATATYPE_MISALIGNMENT
        ] {
            assert!(
                !WELL_KNOWN.iter().any(|(known, _)| *known == code),
                "{code:#010x} is an NTSTATUS this module decodes, and the HRESULT table claims it"
            );
        }

        // **The breakpoint a debugger meets constantly must decode as one**, and removing the
        // bogus name was only half of it: `FormatMessage` reads `0x80000003` as `E_INVALIDARG` and
        // answers "One or more arguments are invalid", so the *message* was wrong even once the
        // name was gone. An exception code is an `NTSTATUS`, and saying so is what fixes it.
        let as_code = decode_status_as(STATUS_BREAKPOINT, Reading::NtStatus);
        assert_eq!(as_code.symbolic, None, "a status was given an HRESULT name");
        assert!(
            as_code
                .best_effort()
                .unwrap_or_default()
                .to_ascii_lowercase()
                .contains("breakpoint"),
            "a breakpoint did not describe itself as one: {as_code:?}"
        );

        // Asked about the bare number, the tool still reports **both** readings rather than
        // choosing for the caller - that is `decode_error_reporting`'s whole design, and the
        // ambiguity is real: this value is a legitimate `E_INVALIDARG` in the non-Win32 headers.
        let bare = decode_status(STATUS_BREAKPOINT);
        assert!(bare.system_message.is_some(), "{bare:?}");
        assert!(
            bare.ntstatus_message
                .as_deref()
                .unwrap_or_default()
                .to_ascii_lowercase()
                .contains("breakpoint"),
            "the status reading has to survive even when it does not lead: {bare:?}"
        );
    }

    /// The names that remain are the SDK's, checked rather than recalled.
    ///
    /// Spot-checked against `shared/winerror.h` 10.0.26100.0 — the `#if defined(_WIN32)` branch,
    /// which is the live one here. The whole table was compared against that header when the
    /// non-Win32 values were removed; these are the entries whose being wrong would be worst.
    #[test]
    fn test_every_well_known_name_is_the_sdks_win32_value() {
        for (code, name) in [
            (0x8000_4001u32, "E_NOTIMPL"),
            (0x8000_4002, "E_NOINTERFACE"),
            (0x8000_4003, "E_POINTER"),
            (0x8000_4004, "E_ABORT"),
            (0x8000_4005, "E_FAIL"),
            (0x8007_0005, "E_ACCESSDENIED"),
            (0x8007_0006, "E_HANDLE"),
            (0x8007_000e, "E_OUTOFMEMORY"),
            (0x8007_0057, "E_INVALIDARG"),
            (0x8000_ffff, "E_UNEXPECTED"),
            (0x8000_000e, "E_ILLEGAL_METHOD_CALL"),
            (0x8000_0017, "E_STRING_NOT_NULL_TERMINATED"),
        ] {
            assert_eq!(
                decode_status(code).symbolic,
                Some(name),
                "{code:#010x} is not the name this build gives it"
            );
        }
    }

    /// **The record a caller actually receives says "breakpoint", and that is a separate claim
    /// from `decode_status_as` being able to.**
    ///
    /// Written because mutation testing found the gap: reverting `exception_info` to decode the
    /// code as a bare value left every test green, since they all called the decoder directly.
    /// The rule that matters is the one at the *call site* — an exception code is an `NTSTATUS` —
    /// so it is asserted through [`exception_info`], on the value that made this a bug.
    #[test]
    fn test_a_breakpoints_exception_record_reads_as_a_breakpoint() {
        let record = dbgscope::dbgeng::ExceptionRecord {
            code: STATUS_BREAKPOINT,
            flags: 0,
            address: 0x7ff8_1234_5678,
            parameters: vec![0],
            nested: None,
        };
        let info = exception_info(&record, true);
        let best = info.decoded.best_effort.unwrap_or_default();
        assert!(
            best.to_ascii_lowercase().contains("breakpoint"),
            "the exception a debugger meets most did not describe itself: {best}"
        );
        assert!(
            !best.contains("arguments are invalid"),
            "the system table's HRESULT reading led for a value that is an NTSTATUS: {best}"
        );
        assert!(
            info.decoded.symbolic.is_none(),
            "an exception code was given an HRESULT name: {:?}",
            info.decoded.symbolic
        );
    }

    /// **A record with no parameters has no subcode, and inventing one names a bug check.**
    ///
    /// `unwrap_or_default` made an absent subcode zero, and zero is
    /// `FAST_FAIL_LEGACY_GS_VIOLATION` — so a truncated or synthetic `0xc0000409` was reported as a
    /// specific security check having failed. Every real `__fastfail` supplies a subcode; a record
    /// that does not is saying nothing, and the report has to say nothing back.
    #[test]
    fn test_a_fail_fast_with_no_parameters_invents_no_subcode() {
        let bare = classify(STATUS_STACK_BUFFER_OVERRUN, &[], Bitness::Bits64);
        assert_eq!(
            bare,
            FaultKind::FailFast {
                subcode: None,
                subcode_name: None,
                wil: None,
            },
            "a parameterless fail-fast was given a subcode it does not carry"
        );

        let text = summary_of(&bare, ThrowEvidence::None).expect("a fail-fast gets a summary");
        assert!(
            !text.contains("LEGACY_GS_VIOLATION"),
            "an absent subcode was named as a specific check: {text}"
        );
        assert!(
            text.contains("no subcode"),
            "a summary that has no subcode to report has to say so: {text}"
        );

        // Subcode zero really *is* that check when the record says zero, which is the other half.
        let zero = classify(STATUS_STACK_BUFFER_OVERRUN, &[0], Bitness::Bits64);
        assert_eq!(
            zero,
            FaultKind::FailFast {
                subcode: Some(0),
                subcode_name: Some("FAST_FAIL_LEGACY_GS_VIOLATION"),
                wil: None,
            },
        );
    }

    /// **A type that was read and is not an `hresult_error` is contrary evidence.**
    ///
    /// The sentinel is four bytes with nothing behind it, so `0xAABBCCDD` occurs inside objects
    /// that have nothing to do with `winrt`. What makes a hit believable is the type saying to
    /// expect one. When the graph answered a different type, a hit is a coincidence in some
    /// member's value — and reporting the dword after it as the exception's failure code invents
    /// one out of an unrelated object.
    #[test]
    fn test_a_readable_type_that_is_not_an_hresult_error_suppresses_the_sentinel() {
        let base = 0x7ff6_a1d9_0000;
        let object_at = 0x0000_008d_e693_fd60;
        let mut memory = FakeMemory::new();
        // A type that is definitely not one of these, and an object that happens to carry the
        // sentinel bytes at the offset a `winrt::hresult_error` would.
        eh_graph(
            &mut memory,
            base,
            ".?AVruntime_error@std@@",
            0x10,
            Bitness::Bits64,
        );
        memory.put(object_at, hresult_object(0x8007_0005));
        let read = |address, len| memory.read(address, len);

        let thrown = thrown_error(
            &read,
            &CppThrow {
                object: object_at,
                throw_info: base + 0x1000,
                image_base: base,
                bitness: Bitness::Bits64,
            },
        );
        assert_eq!(
            thrown.type_name.as_deref(),
            Some("std::runtime_error"),
            "the fixture is not exercising the case: the type has to be readable"
        );
        assert_eq!(
            thrown.hresult, None,
            "a coincidental sentinel in an unrelated type was reported as an HRESULT: {thrown:?}"
        );
        assert!(
            thrown
                .type_note
                .as_deref()
                .unwrap_or_default()
                .contains("not a `winrt::hresult_error`"),
            "declining to read an HRESULT has to say why: {thrown:?}"
        );

        // And the same object under a type that *does* expect it still reports, corroborated —
        // which is what says this suppresses on the type rather than on the bytes.
        let mut memory = FakeMemory::new();
        eh_graph(
            &mut memory,
            base,
            ".?AVhresult_error@winrt@@",
            0x10,
            Bitness::Bits64,
        );
        memory.put(object_at, hresult_object(0x8007_0005));
        let read = |address, len| memory.read(address, len);
        let thrown = thrown_error(
            &read,
            &CppThrow {
                object: object_at,
                throw_info: base + 0x1000,
                image_base: base,
                bitness: Bitness::Bits64,
            },
        );
        assert_eq!(
            thrown.hresult,
            Some((0x8007_0005, Confidence::Corroborated)),
            "{thrown:?}"
        );
    }

    /// **The scan is anchored on frame 0, whose stack pointer is the recorded context's.**
    ///
    /// The minimum over all frames is the same thing on a healthy walk and gives the guarantee away
    /// on an unhealthy one, which is the only walk this matters for: one frame the unwinder could
    /// not establish moves the fixed span somewhere else, and a bogus zero reads as "no anchor" and
    /// skips the scan on a dump that does have a throw in it.
    #[test]
    fn test_the_scan_is_anchored_on_the_recorded_context_not_the_lowest_frame() {
        let real = 0x0000_008d_e693_fd60_u64;

        // The healthy walk: increasing, and the two rules agree.
        assert_eq!(scan_anchor([real, real + 8, real + 16]), Some(real));

        // A later frame the unwinder invented, lower than frame 0. Frame 0 still wins.
        assert_eq!(scan_anchor([real, real - 0x4000, real + 8]), Some(real));

        // And the case that silently disabled the scan: a bogus zero further down the walk.
        assert_eq!(
            scan_anchor([real, 0, real + 8]),
            Some(real),
            "one frame with no stack pointer turned off the scan for the whole dump"
        );

        // Frame 0 itself having none is the real "no anchor", and is the only one.
        assert_eq!(scan_anchor([0, real]), None);
        assert_eq!(scan_anchor(std::iter::empty()), None);
    }

    /// A throw is recognised by its magic, not by its code alone.
    #[test]
    fn test_a_throw_without_the_eh_magic_is_not_decoded() {
        assert!(matches!(
            classify(
                STATUS_CPP_EH_EXCEPTION,
                &[CPP_EH_MAGIC, 1, 2, 3],
                Bitness::Bits64
            ),
            FaultKind::CppThrow(_)
        ));
        assert_eq!(
            classify(
                STATUS_CPP_EH_EXCEPTION,
                &[0xdead_beef, 1, 2, 3],
                Bitness::Bits64
            ),
            FaultKind::Other,
            "a record with the right code and the wrong magic was decoded as a throw"
        );
        assert_eq!(
            classify(
                STATUS_CPP_EH_EXCEPTION,
                &[CPP_EH_MAGIC, 1, 2],
                Bitness::Bits64
            ),
            FaultKind::Other,
            "a three-parameter throw was decoded from fields a 64-bit one does not have"
        );
    }

    /// **A 32-bit throw raises three parameters, and three is all of them.**
    ///
    /// Measured rather than reasoned about: the same `throw` built both ways, each printing its own
    /// record. The 64-bit one carries an image base its descriptors' RVAs are relative to; the
    /// 32-bit one has no such parameter because its descriptors hold absolute pointers.
    ///
    /// So the count is a fact about the *target*, and a build-wide `>= 4` classified every 32-bit
    /// C++ throw as `Other` — an entire supported target class, since a 32-bit user minidump is
    /// routed at the 32-bit worker on purpose.
    #[test]
    fn test_a_32_bit_throw_carries_no_image_base() {
        let throw = classify(
            STATUS_CPP_EH_EXCEPTION,
            &[CPP_EH_MAGIC, 0x00af_fe3c, 0x004d_82f0],
            Bitness::Bits32,
        );
        assert_eq!(
            throw,
            FaultKind::CppThrow(CppThrow {
                object: 0x00af_fe3c,
                throw_info: 0x004d_82f0,
                image_base: 0,
                bitness: Bitness::Bits32,
            }),
            "a 32-bit throw was not decoded from the three parameters it really raises"
        );

        // And the zero is not a shrug: it is what makes `base + field` the identity, so the same
        // arithmetic reads absolute links on 32-bit and RVAs on 64-bit.
        let FaultKind::CppThrow(throw) = throw else {
            unreachable!("asserted above")
        };
        assert_eq!(throw.image_base, 0);

        // The 64-bit rule is unchanged and still refuses three, which is the half of this pair
        // that stops the fix from becoming "accept anything".
        assert_eq!(
            classify(
                STATUS_CPP_EH_EXCEPTION,
                &[CPP_EH_MAGIC, 0x00af_fe3c, 0x004d_82f0],
                Bitness::Bits64
            ),
            FaultKind::Other,
        );
    }

    /// A stack scan reports records, not every four bytes that look like one.
    #[test]
    fn test_the_stack_scan_rejects_a_pattern_that_is_not_a_record() {
        let stack = 0x0000_008d_e693_e000;
        let base = 0x7ff6_a1d9_0000;
        let object_at = stack + 0x800;
        let mut memory = FakeMemory::new();
        eh_graph(
            &mut memory,
            base,
            ".?AVhresult_error@winrt@@",
            0x10,
            Bitness::Bits64,
        );

        let mut page = vec![0u8; 0x1000];
        // A bare copy of the code with nothing behind it — the false positive a scan must drop.
        page[0x100..0x104].copy_from_slice(&STATUS_CPP_EH_EXCEPTION.to_le_bytes());
        // And a real record.
        let record_at_offset = 0x400;
        let rec = cpp_record(
            Bitness::Bits64,
            &[CPP_EH_MAGIC, object_at, base + 0x1000, base],
        );
        page[record_at_offset..record_at_offset + rec.len()].copy_from_slice(&rec);
        page[0x800..0x810].copy_from_slice(&hresult_object(0x8067_0015));
        memory.put(stack, page);
        let read = |address, len| memory.read(address, len);

        let hits = find_cpp_records(&read, stack, stack + 0x1000, Bitness::Bits64);
        assert_eq!(
            hits,
            vec![stack + record_at_offset as u64],
            "the scan did not report exactly the one self-consistent record"
        );

        // And the record it found leads all the way to the answer.
        let throw =
            record_at(&read, hits[0], Bitness::Bits64).expect("the reported record did not parse");
        let thrown = thrown_error(&read, &throw);
        assert_eq!(thrown.type_name.as_deref(), Some("winrt::hresult_error"));
        assert_eq!(
            thrown.hresult,
            Some((0x8067_0015, Confidence::Corroborated)),
            "the graph named the type, so the sentinel hit is corroborated"
        );
    }

    /// **The scan shrinks its read rather than skipping the chunk that refused it.**
    ///
    /// A debug engine refuses a read running past what the dump captured rather than returning
    /// the readable prefix, so a fixed 4 KB chunk fails at every region boundary — and the first
    /// version skipped a whole chunk on that failure, stepping over up to 4 KB of perfectly
    /// readable stack. It found nothing at all on the real fail-fast dump this tool was written
    /// for, while every synthetic test passed: they all gave the scan a region at least as large
    /// as its chunk, so the read never refused. The construction that exposes it is a region
    /// **smaller** than the chunk, with the record inside it.
    #[test]
    fn test_the_scan_shrinks_its_read_rather_than_skipping_the_chunk() {
        let stack = 0x0000_008d_e693_e000;
        let base = 0x7ff6_a1d9_0000;
        let object_at = stack + 0x100;
        let mut memory = FakeMemory::new();
        eh_graph(
            &mut memory,
            base,
            ".?AVhresult_error@winrt@@",
            0x10,
            Bitness::Bits64,
        );

        // Half a chunk of readable stack, and the record inside it. A 4 KB read of this refuses.
        let mut page = vec![0u8; SCAN_CHUNK / 2];
        page[0x100..0x110].copy_from_slice(&hresult_object(0x8067_0015));
        let record_offset = 0x200;
        let rec = cpp_record(
            Bitness::Bits64,
            &[CPP_EH_MAGIC, object_at, base + 0x1000, base],
        );
        page[record_offset..record_offset + rec.len()].copy_from_slice(&rec);
        memory.put(stack, page);
        let read = |address, len| memory.read(address, len);

        // The range asked about is a whole chunk, of which only half is readable.
        assert!(
            read(stack, SCAN_CHUNK).is_none(),
            "the fixture is not exercising the case: a full-chunk read has to refuse here"
        );
        assert_eq!(
            find_cpp_records(&read, stack, stack + SCAN_CHUNK as u64, Bitness::Bits64),
            vec![stack + record_offset as u64],
            "the scan skipped the chunk its read refused, and stepped over the record in it"
        );
    }

    /// The host's message tables answer for the codes this was written for.
    ///
    /// **The point of this test is that the two exotic ones resolve**: `0x80670015` and
    /// `0x80073d54` are not in any table this crate ships, and if `FormatMessage` did not answer
    /// for them the whole design — a pure decoder rather than a scrape of `!error` — would be
    /// wrong. Asserted on a substring rather than the whole sentence, since the wording is the
    /// host's and could be localised.
    #[test]
    fn test_the_host_names_the_codes_this_was_written_for() {
        // **The two severities disagree here, and that is the point.** `0x80670015` is a failed
        // `HRESULT` — bit 31 — while its top *two* bits are `10`, which as an `NTSTATUS` reads as
        // a warning. A single `severity` field would have to be one of these and would be wrong
        // about the other; this asserts both so that collapsing them fails here.
        let repository = decode_status(0x8067_0015);
        assert!(repository.hresult_failed);
        assert_eq!(repository.ntstatus_severity, Severity::Warning);
        assert!(
            repository
                .system_message
                .as_deref()
                .is_some_and(|m| m.contains("StateRepository")),
            "0x80670015 did not resolve: {:?}",
            repository.system_message
        );

        let identity = decode_status(0x8007_3d54);
        assert!(
            identity
                .system_message
                .as_deref()
                .is_some_and(|m| m.contains("package identity")),
            "0x80073d54 did not resolve: {:?}",
            identity.system_message
        );

        // An NTSTATUS resolves from ntdll and not from the system table, which is why both are
        // read. And its text is the misleading one, which is why a fail-fast carries the subcode
        // name beside it rather than relying on this.
        let fail_fast = decode_status(STATUS_STACK_BUFFER_OVERRUN);
        assert!(
            fail_fast.ntstatus_message.is_some(),
            "0xc0000409 resolved in neither table"
        );
        assert_eq!(fail_fast.system_message, None);
        assert_eq!(fail_fast_subcode(7), Some("FAST_FAIL_FATAL_APP_EXIT"));

        // The symbolic name is preferred in the one-line rendering, because it says more.
        assert_eq!(
            decode_status(0x8000_ffff).best_effort().as_deref(),
            Some("E_UNEXPECTED — Catastrophic failure")
        );
    }

    /// A customer-defined value is in nobody's table and is not looked up.
    #[test]
    fn test_a_customer_defined_code_is_not_given_someone_elses_message() {
        let mine = decode_status(0xa000_0001);
        assert!(mine.customer_defined);
        assert_eq!(mine.system_message, None);
        assert_eq!(mine.ntstatus_message, None);
        assert_eq!(mine.best_effort(), None);
    }

    /// Demangling handles the shape thrown types have, and declines everything else.
    #[test]
    fn test_demangling_declines_rather_than_guesses() {
        assert_eq!(
            demangle(".?AVhresult_error@winrt@@").as_deref(),
            Some("winrt::hresult_error")
        );
        assert_eq!(
            demangle(".?AUhresult_error@@").as_deref(),
            Some("hresult_error")
        );
        assert_eq!(
            demangle(".?AVruntime_error@std@@").as_deref(),
            Some("std::runtime_error")
        );
        // A template: the grammar this does not implement, declined rather than mangled further.
        assert_eq!(demangle(".?AV?$vector@HV?$allocator@H@std@@@std@@"), None);
        assert_eq!(demangle("not a mangled name"), None);
        assert_eq!(demangle(".?AV@@"), None);
    }

    /// A corrupt graph is declined at each link rather than followed.
    #[test]
    fn test_a_corrupt_graph_is_declined_at_every_link() {
        let base = 0x7ff6_a1d9_0000;
        let read_nothing = |_: u64, _: usize| None;
        let throw = CppThrow {
            object: 0,
            throw_info: base + 0x1000,
            image_base: base,
            bitness: Bitness::Bits64,
        };
        assert_eq!(describe_type(&read_nothing, &throw), None);

        // A count past the sanity bound is a corrupt read, not a deep hierarchy.
        let mut memory = FakeMemory::new();
        eh_graph(&mut memory, base, ".?AVx@@", 8, Bitness::Bits64);
        let mut array = vec![0u8; 8];
        array[..4].copy_from_slice(&(eh::MAX_CATCHABLE_TYPES + 1).to_le_bytes());
        array[4..8].copy_from_slice(&0x3000u32.to_le_bytes());
        memory.put(base + 0x2000, array);
        let read = |address, len| memory.read(address, len);
        assert_eq!(
            describe_type(&read, &throw),
            None,
            "an implausible catchable-type count was walked anyway"
        );

        // A zero array RVA is "no type information", not offset zero of the image.
        let mut memory = FakeMemory::new();
        eh_graph(&mut memory, base, ".?AVx@@", 8, Bitness::Bits64);
        memory.put(base + 0x1000, vec![0u8; eh::THROW_INFO_SIZE]);
        let read = |address, len| memory.read(address, len);
        assert_eq!(describe_type(&read, &throw), None);
    }

    /// The sentinel scan stays inside the object when the object's size is known.
    #[test]
    fn test_the_sentinel_scan_is_bounded_by_the_object() {
        let object_at = 0x1000;
        let mut memory = FakeMemory::new();
        // Eight bytes of object, and a sentinel just past it in whatever the stack holds next.
        let mut bytes = vec![0u8; 8];
        bytes.extend_from_slice(&HRESULT_ERROR_SENTINEL.to_le_bytes());
        bytes.extend_from_slice(&0xdead_beefu32.to_le_bytes());
        memory.put(object_at, bytes);
        let read = |address, len| memory.read(address, len);

        assert_eq!(
            hresult_in(&read, object_at, Some(8)),
            None,
            "the scan read past the end of the object and found the neighbour's bytes"
        );
        // With no size to bound it, the same bytes are in range — which is why the EH graph's size
        // is used when there is one.
        assert_eq!(hresult_in(&read, object_at, None), Some(0xdead_beef));
    }
}
