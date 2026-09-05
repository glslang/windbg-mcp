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

/// Reads `len` bytes of the target at `address`, or `None` if that memory is not readable.
///
/// The whole engine dependency of this module, as one closure. A short read is `None` rather than a
/// truncated buffer: every caller below is reading a fixed-size structure, and half of one is not a
/// structure.
pub type Read<'a> = dyn Fn(u64, usize) -> Option<Vec<u8>> + 'a;

/// How much weight a decoded field can bear. See the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    /// Read straight out of the exception record, or decoded from a structure whose layout the
    /// compiler fixes.
    Documented,
    /// Recognised by a pattern that no header states — a sentinel, or a convention a library
    /// happens to follow. Corroborated where possible, and reported as a guess either way.
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
}

impl StatusDecode {
    /// The single most useful sentence about this value, for a rendering that has room for one.
    ///
    /// Prefers the symbolic name where there is one, because `E_UNEXPECTED` tells a reader more
    /// than "Catastrophic failure" does; then the system message; then `ntdll`'s.
    pub fn best_effort(&self) -> Option<String> {
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
const WELL_KNOWN: &[(u32, &str)] = &[
    (0x8000_0001, "E_NOTIMPL"),
    (0x8000_0002, "E_OUTOFMEMORY"),
    (0x8000_0003, "E_INVALIDARG"),
    (0x8000_0004, "E_NOINTERFACE"),
    (0x8000_0005, "E_POINTER"),
    (0x8000_0006, "E_HANDLE"),
    (0x8000_0007, "E_ABORT"),
    (0x8000_0008, "E_FAIL"),
    (0x8000_0009, "E_ACCESSDENIED"),
    (0x8000_000b, "E_BOUNDS"),
    (0x8000_000c, "E_CHANGED_STATE"),
    (0x8000_000e, "E_STRING_NOT_NULL_TERMINATED"),
    (0x8000_4001, "E_NOTIMPL"),
    (0x8000_4002, "E_NOINTERFACE"),
    (0x8000_4003, "E_POINTER"),
    (0x8000_4004, "E_ABORT"),
    (0x8000_4005, "E_FAIL"),
    (0x8000_ffff, "E_UNEXPECTED"),
    (0x8007_0005, "E_ACCESSDENIED"),
    (0x8007_000e, "E_OUTOFMEMORY"),
    (0x8007_0057, "E_INVALIDARG"),
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
pub fn decode_status(value: u32) -> StatusDecode {
    let customer_defined = value & 0x2000_0000 != 0;
    StatusDecode {
        value,
        hresult_failed: value & 0x8000_0000 != 0,
        ntstatus_severity: Severity::of(value),
        facility: (value >> 16) & 0x0fff,
        code: value as u16,
        customer_defined,
        symbolic: WELL_KNOWN
            .iter()
            .find(|(known, _)| *known == value)
            .map(|(_, name)| *name),
        // A customer-defined value is in nobody's table, and asking would return either nothing or
        // — worse — an unrelated Microsoft string that happens to share the number.
        system_message: (!customer_defined)
            .then(|| message::from_system(value))
            .flatten(),
        ntstatus_message: (!customer_defined)
            .then(|| message::from_ntdll(value))
            .flatten(),
    }
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
        subcode: u64,
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

/// A C++ throw's four parameters, named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CppThrow {
    /// Where the thrown object is. On the stack of the throwing frame, so it is in any dump that
    /// captured thread stacks — which is what makes the sentinel route work where the type route
    /// cannot.
    pub object: u64,
    /// The `ThrowInfo`, which describes the thrown *type*. In the throwing module's `.rdata`.
    pub throw_info: u64,
    /// The image base every RVA inside `ThrowInfo` is relative to.
    pub image_base: u64,
}

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
    (7, "FAST_FAIL_FATAL_APP_EXIT"),
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
pub fn classify(code: u32, parameters: &[u64]) -> FaultKind {
    match code {
        STATUS_STACK_BUFFER_OVERRUN => {
            let subcode = parameters.first().copied().unwrap_or_default();
            FaultKind::FailFast {
                subcode,
                subcode_name: fail_fast_subcode(subcode),
                // Three parameters, not "at least two": WIL writes both, and a record with two
                // would be some third thing whose second parameter this has no reason to read as
                // an HRESULT.
                wil: (parameters.len() >= 3).then(|| WilFailure {
                    // Truncating rather than casting through `i64`: the parameter is a
                    // sign-extended 32-bit HRESULT, so the low half *is* the value.
                    hresult: parameters[1] as u32,
                    line: parameters[2],
                }),
            }
        }
        // Every field below is at a fixed index, so the count is checked before any of them is
        // read. A throw with fewer parameters is not a throw this understands.
        STATUS_CPP_EH_EXCEPTION if parameters.len() >= 4 && parameters[0] == CPP_EH_MAGIC => {
            FaultKind::CppThrow(CppThrow {
                object: parameters[1],
                throw_info: parameters[2],
                image_base: parameters[3],
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
    /// `TypeDescriptor::name`, past the vtable pointer and the spare, both pointer-sized.
    pub const TYPE_DESCRIPTOR_NAME: usize = 16;
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

    out.hresult = hresult_in(read, throw.object, out.size).map(|hr| (hr, Confidence::Convention));
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
        descriptor.checked_add(eh::TYPE_DESCRIPTOR_NAME as u64)?,
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
            return Some(u32::from_le_bytes(window.get(4..8)?.try_into().ok()?));
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
pub fn find_cpp_records(read: &Read<'_>, stack_low: u64, stack_high: u64) -> Vec<u64> {
    let mut found = Vec::new();
    let needle = STATUS_CPP_EH_EXCEPTION.to_le_bytes();
    let mut at = stack_low;
    while at < stack_high && found.len() < MAX_RECORDS {
        let want = SCAN_CHUNK.min((stack_high - at) as usize);
        let Some(chunk) = read(at, want) else {
            // An unreadable page in the middle of a stack range is ordinary in a minidump; step
            // over it rather than giving up on the range.
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
                if record_at(read, candidate).is_some() {
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

/// Offsets into a 64-bit `EXCEPTION_RECORD` as the compiler lays it out on the stack.
///
/// **Not `EXCEPTION_RECORD64`**, which is the engine's flattened form: this is the native
/// structure, with a real pointer for the nested record and the address. Getting this wrong by one
/// slot is the mistake the walkthrough records making, which is why the parameters are reached from
/// the *count* rather than by assuming four.
mod record {
    pub const FLAGS: usize = 4;
    pub const ADDRESS: usize = 16;
    pub const NUMBER_PARAMETERS: usize = 24;
    pub const FIRST_PARAMETER: usize = 32;
    pub const MAX_PARAMETERS: u32 = 15;
    pub const SIZE: usize = FIRST_PARAMETER + MAX_PARAMETERS as usize * 8;
}

/// Reads a C++ throw's `EXCEPTION_RECORD` at `address`, if what is there is one.
///
/// The self-consistency check is what makes a stack scan usable: a record must declare a plausible
/// parameter count and carry the EH magic in its first parameter. Four bytes of `0xe06d7363` that
/// are something else fail both.
pub fn record_at(read: &Read<'_>, address: u64) -> Option<CppThrow> {
    let bytes = read(address, record::SIZE)?;
    let code = u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?);
    if code != STATUS_CPP_EH_EXCEPTION {
        return None;
    }
    let count = u32::from_le_bytes(
        bytes
            .get(record::NUMBER_PARAMETERS..record::NUMBER_PARAMETERS + 4)?
            .try_into()
            .ok()?,
    );
    if !(4..=record::MAX_PARAMETERS).contains(&count) {
        return None;
    }
    let parameter = |index: usize| -> Option<u64> {
        let at = record::FIRST_PARAMETER + index * 8;
        Some(u64::from_le_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
    };
    if parameter(0)? != CPP_EH_MAGIC {
        return None;
    }
    Some(CppThrow {
        object: parameter(1)?,
        throw_info: parameter(2)?,
        image_base: parameter(3)?,
    })
}

/// The flags and faulting address of a record found by scanning, for a caller that wants to render
/// what it found rather than only follow it.
pub fn record_details(read: &Read<'_>, address: u64) -> Option<(u32, u64)> {
    let bytes = read(address, record::SIZE)?;
    let flags = u32::from_le_bytes(
        bytes
            .get(record::FLAGS..record::FLAGS + 4)?
            .try_into()
            .ok()?,
    );
    let at = u64::from_le_bytes(
        bytes
            .get(record::ADDRESS..record::ADDRESS + 8)?
            .try_into()
            .ok()?,
    );
    Some((flags, at))
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
    fn eh_graph(memory: &mut FakeMemory, base: u64, mangled: &str, size: u32) {
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
        let mut descriptor = vec![0u8; eh::TYPE_DESCRIPTOR_NAME];
        descriptor.extend_from_slice(mangled.as_bytes());
        descriptor.push(0);
        memory.put(base + 0x4000, descriptor);
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
        eh_graph(&mut memory, base, ".?AVhresult_error@winrt@@", 0x10);
        memory.put(object_at, hresult_object(0x8067_0015));
        let read = |address, len| memory.read(address, len);

        let throw = CppThrow {
            object: object_at,
            throw_info: base + 0x1000,
            image_base: base,
        };
        let thrown = thrown_error(&read, &throw);
        assert_eq!(thrown.type_name.as_deref(), Some("winrt::hresult_error"));
        assert_eq!(
            thrown.mangled_name.as_deref(),
            Some(".?AVhresult_error@winrt@@")
        );
        assert_eq!(thrown.size, Some(0x10));
        assert_eq!(thrown.hresult, Some((0x8067_0015, Confidence::Convention)));
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
            },
        );
        assert_eq!(thrown.type_name, None);
        assert_eq!(thrown.mangled_name, None);
        assert_eq!(thrown.hresult, Some((0x8007_3d54, Confidence::Convention)));
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
        record_bytes.resize(record::SIZE, 0);
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
        let mut descriptor = vec![0u8; eh::TYPE_DESCRIPTOR_NAME];
        descriptor.extend_from_slice(b".?AUhresult_error@@\0");
        memory.put(base + 0x9_be28, descriptor);

        let read = |address, len| memory.read(address, len);

        // The record parses, and its parameters are the four the walkthrough names.
        let throw = record_at(&read, throw_record).expect("the real record did not parse");
        assert_eq!(throw.object, 0x0000_008d_e693_fd60);
        assert_eq!(throw.throw_info, base + 0x9_aa00);
        assert_eq!(
            throw.image_base, base,
            "parameter 3 is the image base, and the RVAs below are relative to it"
        );
        assert_eq!(
            record_details(&read, throw_record),
            Some((0x81, 0x0000_7ffc_98f7_187a)),
            "the flags and the raising address did not read back — the record layout is off by a \
             slot, which is the mistake this offset set exists to prevent"
        );

        // And the whole graph resolves, both routes agreeing.
        let thrown = thrown_error(&read, &throw);
        assert_eq!(thrown.mangled_name.as_deref(), Some(".?AUhresult_error@@"));
        assert_eq!(thrown.type_name.as_deref(), Some("hresult_error"));
        assert_eq!(thrown.size, Some(0x10));
        assert_eq!(thrown.hresult.map(|(hr, _)| hr), Some(0x8067_0015));

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
        let crt = classify(STATUS_STACK_BUFFER_OVERRUN, &[7]);
        assert_eq!(
            crt,
            FaultKind::FailFast {
                subcode: 7,
                subcode_name: Some("FAST_FAIL_FATAL_APP_EXIT"),
                wil: None,
            },
            "a one-parameter fail-fast was read as carrying WIL's extras"
        );

        // The walkthrough's second fault, verbatim.
        let wil = classify(
            STATUS_STACK_BUFFER_OVERRUN,
            &[7, 0xffff_ffff_8000_ffff, 0x28f],
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

    /// A throw is recognised by its magic, not by its code alone.
    #[test]
    fn test_a_throw_without_the_eh_magic_is_not_decoded() {
        assert!(matches!(
            classify(STATUS_CPP_EH_EXCEPTION, &[CPP_EH_MAGIC, 1, 2, 3]),
            FaultKind::CppThrow(_)
        ));
        assert_eq!(
            classify(STATUS_CPP_EH_EXCEPTION, &[0xdead_beef, 1, 2, 3]),
            FaultKind::Other,
            "a record with the right code and the wrong magic was decoded as a throw"
        );
        assert_eq!(
            classify(STATUS_CPP_EH_EXCEPTION, &[CPP_EH_MAGIC, 1, 2]),
            FaultKind::Other,
            "a three-parameter throw was decoded from fields it does not have"
        );
    }

    /// A stack scan reports records, not every four bytes that look like one.
    #[test]
    fn test_the_stack_scan_rejects_a_pattern_that_is_not_a_record() {
        let stack = 0x0000_008d_e693_e000;
        let base = 0x7ff6_a1d9_0000;
        let object_at = stack + 0x800;
        let mut memory = FakeMemory::new();
        eh_graph(&mut memory, base, ".?AVhresult_error@winrt@@", 0x10);

        let mut page = vec![0u8; 0x1000];
        // A bare copy of the code with nothing behind it — the false positive a scan must drop.
        page[0x100..0x104].copy_from_slice(&STATUS_CPP_EH_EXCEPTION.to_le_bytes());
        // And a real record.
        let record_at_offset = 0x400;
        let mut rec = vec![0u8; record::SIZE];
        rec[..4].copy_from_slice(&STATUS_CPP_EH_EXCEPTION.to_le_bytes());
        rec[record::FLAGS..record::FLAGS + 4].copy_from_slice(&0x81u32.to_le_bytes());
        rec[record::ADDRESS..record::ADDRESS + 8]
            .copy_from_slice(&0x7ffc_98f7_187au64.to_le_bytes());
        rec[record::NUMBER_PARAMETERS..record::NUMBER_PARAMETERS + 4]
            .copy_from_slice(&4u32.to_le_bytes());
        for (index, value) in [CPP_EH_MAGIC, object_at, base + 0x1000, base]
            .into_iter()
            .enumerate()
        {
            let at = record::FIRST_PARAMETER + index * 8;
            rec[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }
        page[record_at_offset..record_at_offset + rec.len()].copy_from_slice(&rec);
        page[0x800..0x810].copy_from_slice(&hresult_object(0x8067_0015));
        memory.put(stack, page);
        let read = |address, len| memory.read(address, len);

        let hits = find_cpp_records(&read, stack, stack + 0x1000);
        assert_eq!(
            hits,
            vec![stack + record_at_offset as u64],
            "the scan did not report exactly the one self-consistent record"
        );

        // And the record it found leads all the way to the answer.
        let throw = record_at(&read, hits[0]).expect("the reported record did not parse");
        let thrown = thrown_error(&read, &throw);
        assert_eq!(thrown.type_name.as_deref(), Some("winrt::hresult_error"));
        assert_eq!(thrown.hresult.map(|(hr, _)| hr), Some(0x8067_0015));
        assert_eq!(
            record_details(&read, hits[0]),
            Some((0x81, 0x7ffc_98f7_187a))
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
        };
        assert_eq!(describe_type(&read_nothing, &throw), None);

        // A count past the sanity bound is a corrupt read, not a deep hierarchy.
        let mut memory = FakeMemory::new();
        eh_graph(&mut memory, base, ".?AVx@@", 8);
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
        eh_graph(&mut memory, base, ".?AVx@@", 8);
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
