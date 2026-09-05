//! Which architecture a target is, answered **before any engine opens it**.
//!
//! One question, asked for one reason: **a 32-bit user-mode target has to be opened by a 32-bit
//! engine if its managed extensions are ever going to load**. An extension DLL is loaded into the
//! debugger's own process, so a 64-bit host cannot load a 32-bit `sos.dll` at all — and the
//! 64-bit one refuses a 32-bit CLR, because the data access DLL behind it is paired to the
//! *target* as well as the host. There is no in-process arrangement that works, so the engine has
//! to move, and that decision has to be made **before** a target is opened rather than after.
//!
//! Hence this module rather than an engine call. `IDebugControl::GetEffectiveProcessorType`
//! would answer the same question authoritatively, but only once a session already exists in a
//! process whose architecture is by then fixed — which is exactly the thing being decided.
//!
//! Two kinds of target can be asked without an engine, and they are asked in different ways:
//!
//! * a **dump**, by parsing its own header ([`read`]) — a few hundred bytes of a file that may be
//!   hundreds of megabytes;
//! * a **live process**, by asking the kernel ([`process_arch`]), which is `IsWow64Process2` and
//!   needs no more right over the process than any tool that lists it.
//!
//! [`Opening`] is the pair of them, and is what the supervisor hands a worker it is about to
//! spawn — the one value that decides which image starts.
//!
//! Dumps deliberately answer for **user minidumps only** (`MDMP`). A kernel crash dump is a
//! different format (`PAGEDU64`), and it is not a case this routing is about: a kernel target has
//! no CLR in it and the x64 engine reads x86 and ARM64 kernel dumps alike. Anything unrecognised
//! is [`DumpTarget::Other`], which means "say nothing, let the engine decide" and never "this is
//! not openable".

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::System::SystemInformation::{
    IMAGE_FILE_MACHINE, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64,
    IMAGE_FILE_MACHINE_ARMNT, IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_UNKNOWN,
};
use windows_sys::Win32::System::Threading::{
    IsWow64Process2, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// `MDMP`, little-endian — the signature of a user-mode minidump.
const MINIDUMP_SIGNATURE: u32 = 0x504D_444D;

/// `MINIDUMP_STREAM_TYPE::SystemInfoStream`.
const SYSTEM_INFO_STREAM: u32 = 7;

/// One `MINIDUMP_DIRECTORY`: a stream type and a location descriptor (size, RVA).
const DIRECTORY_ENTRY_LEN: usize = 12;

/// A ceiling on the stream directory, so a corrupt or hostile header cannot make this allocate
/// against a `NumberOfStreams` it invented. Real dumps carry a couple of dozen streams; the cap is
/// far above anything a writer produces and far below anything worth worrying about.
const MAX_STREAMS: u32 = 4096;

/// The processor architectures this routing distinguishes, as `MINIDUMP_SYSTEM_INFO` records
/// them. The values are `PROCESSOR_ARCHITECTURE_*` from `winnt.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    /// `PROCESSOR_ARCHITECTURE_INTEL` — 32-bit x86, the case this module exists for.
    X86,
    /// `PROCESSOR_ARCHITECTURE_AMD64`.
    X64,
    /// `PROCESSOR_ARCHITECTURE_ARM64`.
    Arm64,
    /// `PROCESSOR_ARCHITECTURE_ARM` — 32-bit ARM.
    Arm,
    /// Something this build has no name for. Carried rather than discarded so a log line can say
    /// what was actually in the file.
    Other(u16),
}

impl Arch {
    fn of(value: u16) -> Self {
        match value {
            0 => Self::X86,
            5 => Self::Arm,
            9 => Self::X64,
            12 => Self::Arm64,
            other => Self::Other(other),
        }
    }

    /// The same answer from an `IMAGE_FILE_MACHINE`, which is how a *live* process reports it —
    /// and, measured, how the debug engine's `GetActualProcessorType` reports it too.
    ///
    /// A separate mapping rather than a shared one, because these are two different enumerations
    /// that happen to describe the same set: a minidump's `ProcessorArchitecture` numbers x64 as
    /// 9, and a PE machine type numbers it 0x8664. Folding them into one table is how a value
    /// from the wrong namespace comes to be read as a plausible architecture.
    ///
    /// So which table the engine's answer belongs to was **checked rather than assumed**: opening
    /// the two checked-in user-mode fixtures reports `0x14c` and `0x8664`, which are PE machine
    /// values — `0` and `9` are what the other namespace would have given.
    pub(crate) fn of_machine(value: IMAGE_FILE_MACHINE) -> Option<Self> {
        match value {
            IMAGE_FILE_MACHINE_I386 => Some(Self::X86),
            IMAGE_FILE_MACHINE_AMD64 => Some(Self::X64),
            IMAGE_FILE_MACHINE_ARM64 => Some(Self::Arm64),
            IMAGE_FILE_MACHINE_ARMNT => Some(Self::Arm),
            _ => None,
        }
    }

    /// The name this architecture goes by in a debugger package's directory layout and in
    /// `.effmach` — so a message naming one names something the reader can act on.
    pub fn label(self) -> String {
        match self {
            Self::X86 => "x86".to_string(),
            Self::X64 => "x64".to_string(),
            Self::Arm64 => "arm64".to_string(),
            Self::Arm => "arm".to_string(),
            Self::Other(value) => format!("unknown (PROCESSOR_ARCHITECTURE {value})"),
        }
    }
}

/// What the file turned out to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DumpTarget {
    /// A user-mode minidump, carrying the architecture of the process it captured.
    UserMinidump(Arch),
    /// Anything else — a kernel dump, a TTD trace, a file this does not recognise. Says nothing
    /// about whether the engine can open it.
    Other,
}

/// What a worker is being started for, as far as choosing its *architecture* goes.
///
/// The supervisor builds one of these from the opener it is about to send, before it spawns
/// anything, and hands the same value to the worker on its command line
/// ([`crate::worker::TARGET_FLAG`]). Two consumers, one value: [`crate::engine::worker_images`]
/// picks the image from it, and [`crate::worker::limitation_for`] reports — from the *worker* —
/// what a session on the wrong-architecture image cannot do.
///
/// **Only the openers that can be asked without an engine are here.** A kernel attach, a TTD
/// trace and a `launch` are all absent, and each for its own reason: a kernel target has no CLR
/// and the x64 engine reads every kernel dump alike; replaying a trace is a capability of the
/// engine bundle rather than a question about the target; and a `launch`ed program does not exist
/// yet, so there is nothing to ask. Every one of them takes this build's own image, which is what
/// `None` means at each call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Opening {
    /// A dump file, whose architecture is in its own header.
    Dump(PathBuf),
    /// A live process, whose architecture is `IsWow64Process2`.
    Process(u32),
}

impl Opening {
    /// The architecture of this target, or `None` where nothing here can say.
    ///
    /// `None` and `Err` mean the same thing to every caller — *this routing has nothing to
    /// contribute* — and are kept apart only so the `Err` can be logged: a dump whose header does
    /// not parse and a process that has already exited are worth a line, where a kernel dump is
    /// the ordinary case and is not.
    pub fn arch(&self) -> io::Result<Option<Arch>> {
        match self {
            Self::Dump(path) => Ok(match read(path)? {
                DumpTarget::UserMinidump(arch) => Some(arch),
                DumpTarget::Other => None,
            }),
            Self::Process(pid) => process_arch(*pid),
        }
    }

    /// How this crosses the command line to a worker, and back.
    ///
    /// **Tagged rather than bare**, and both shapes are, which is worth the eight characters: a
    /// bare value would have to be told apart by guessing — is `1234` a pid or a file called
    /// `1234`? — and the guess would be made in the one process that cannot ask anyone. The two
    /// halves are inverses and are tested as a pair.
    pub fn flag_value(&self) -> String {
        match self {
            Self::Dump(path) => format!("dump:{}", path.display()),
            Self::Process(pid) => format!("process:{pid}"),
        }
    }

    /// Reads back what [`Self::flag_value`] wrote. `None` for anything else, which a worker
    /// treats as "I was told nothing usable" rather than as a fault — the handshake's build
    /// check is what catches a supervisor and a worker that disagree about this encoding.
    pub fn parse(value: &str) -> Option<Self> {
        if let Some(path) = value.strip_prefix("dump:") {
            return Some(Self::Dump(PathBuf::from(path)));
        }
        value
            .strip_prefix("process:")
            .and_then(|pid| pid.parse().ok())
            .map(Self::Process)
    }

    /// What this target is, for a log line.
    pub fn describe(&self) -> String {
        match self {
            Self::Dump(path) => path.display().to_string(),
            Self::Process(pid) => format!("process {pid}"),
        }
    }
}

/// The architecture a **live process** is running as, which is `IsWow64Process2` and nothing else.
///
/// The two out-parameters answer different questions and only one of them is about this process:
/// `ProcessMachine` is the machine of the WoW64 *guest*, and is `IMAGE_FILE_MACHINE_UNKNOWN` when
/// the process is not one — in which case the process is running natively and the answer is the
/// machine of the host. Reading `NativeMachine` alone would report an ARM64 host's every process
/// as ARM64, x86 ones included, which is exactly the case this routing exists for.
///
/// `PROCESS_QUERY_LIMITED_INFORMATION` deliberately, not `QUERY_INFORMATION`: it is the right
/// that lets a caller ask what a process *is* without being able to read it, so asking this
/// question needs no more privilege than the caller already had to have to name the pid. The
/// attach that follows is what needs debug rights, and it is DbgEng that asks for them.
///
/// `Ok(None)` is a machine this build has no name for — logged, and then treated exactly like
/// every other target this routing has nothing to say about. It is deliberately **not**
/// [`Arch::Other`], which carries a minidump's `ProcessorArchitecture`: putting a PE machine type
/// in it would render as `unknown (PROCESSOR_ARCHITECTURE 34404)`, naming the wrong enumeration.
pub fn process_arch(pid: u32) -> io::Result<Option<Arch>> {
    // SAFETY: a plain Win32 call with a scalar argument. The handle it returns is null on
    // failure — checked below — and is closed on both paths out.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return Err(io::Error::last_os_error());
    }
    let mut guest: IMAGE_FILE_MACHINE = IMAGE_FILE_MACHINE_UNKNOWN;
    let mut native: IMAGE_FILE_MACHINE = IMAGE_FILE_MACHINE_UNKNOWN;
    // SAFETY: `process` is a live handle this function owns, and both out-parameters are
    // initialised locals of exactly the type the signature names.
    let ok = unsafe { IsWow64Process2(process, &mut guest, &mut native) };
    let failure = (ok == 0).then(io::Error::last_os_error);
    // SAFETY: closing a handle this function opened and nothing else holds.
    unsafe {
        CloseHandle(process);
    }
    if let Some(e) = failure {
        return Err(e);
    }
    let machine = if guest == IMAGE_FILE_MACHINE_UNKNOWN {
        native
    } else {
        guest
    };
    let arch = Arch::of_machine(machine);
    if arch.is_none() {
        tracing::debug!(
            "process {pid} runs as IMAGE_FILE_MACHINE {machine:#x}, which this build has no name for"
        );
    }
    Ok(arch)
}

/// Reads what `path` is, touching only its header rather than its contents.
///
/// A full-memory dump is tens or hundreds of megabytes and this reads a few hundred bytes of it:
/// the header, the stream directory, and the first field of one stream.
///
/// **Every error here means "this routing has nothing to say"**, not "this dump is bad". A file
/// that cannot be read, or whose directory does not lead anywhere, is reported as an error so the
/// caller can log it — and the caller's answer to an error is to open the dump the ordinary way
/// and let the engine produce the real diagnosis, which it is far better placed to do.
pub fn read(path: &Path) -> io::Result<DumpTarget> {
    let mut file = File::open(path)?;

    // MINIDUMP_HEADER is 32 bytes; the four fields this needs are in the first 16.
    let mut header = [0u8; 16];
    if let Err(e) = file.read_exact(&mut header) {
        // A file shorter than a minidump header is simply not one.
        return if e.kind() == io::ErrorKind::UnexpectedEof {
            Ok(DumpTarget::Other)
        } else {
            Err(e)
        };
    }
    if u32_at(&header, 0) != MINIDUMP_SIGNATURE {
        return Ok(DumpTarget::Other);
    }

    let streams = u32_at(&header, 8).min(MAX_STREAMS);
    let directory_rva = u32_at(&header, 12);

    let mut directory = vec![0u8; streams as usize * DIRECTORY_ENTRY_LEN];
    file.seek(SeekFrom::Start(u64::from(directory_rva)))?;
    file.read_exact(&mut directory)?;

    // The system-info stream holds `ProcessorArchitecture` as its very first field.
    let system_info_rva = directory
        .as_chunks::<DIRECTORY_ENTRY_LEN>()
        .0
        .iter()
        .find(|entry| u32_at(*entry, 0) == SYSTEM_INFO_STREAM)
        .map(|entry| u32_at(entry, 8))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "minidump has no system-info stream, so it does not say which architecture it \
                 captured",
            )
        })?;

    let mut architecture = [0u8; 2];
    file.seek(SeekFrom::Start(u64::from(system_info_rva)))?;
    file.read_exact(&mut architecture)?;

    Ok(DumpTarget::UserMinidump(Arch::of(u16::from_le_bytes(
        architecture,
    ))))
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The command-line encoding is an inverse pair, and a Windows path is what most nearly
    /// breaks it: it carries the `:` that separates a tag from its value, and it carries spaces.
    #[test]
    fn a_target_survives_the_command_line_and_comes_back_the_same() {
        for opening in [
            Opening::Dump(PathBuf::from(r"C:\dumps\a 32-bit dump.dmp")),
            Opening::Dump(PathBuf::from(r"\\server\share\x86.dmp")),
            Opening::Process(4),
            Opening::Process(u32::MAX),
        ] {
            assert_eq!(
                Opening::parse(&opening.flag_value()),
                Some(opening.clone()),
                "{} did not survive the round trip",
                opening.flag_value()
            );
        }
    }

    /// Anything else is "I was told nothing usable", never a guess.
    ///
    /// The bare path is the shape that matters: it is what this flag carried before a live
    /// process could be named on it, so a supervisor and a worker one release apart must not
    /// silently agree about it.
    #[test]
    fn an_untagged_or_malformed_target_names_nothing() {
        for value in [
            r"C:\dumps\x86.dmp",
            "1234",
            "",
            "process:",
            "process:-1",
            "process:12x",
            "Dump:C:/x.dmp",
        ] {
            assert_eq!(Opening::parse(value), None, "`{value}` should name nothing");
        }
    }

    /// **The two enumerations are not one table**, which is what `Arch::of_machine` exists to keep
    /// true: 9 is x64 to a minidump and nothing at all as a PE machine type, and 332 is the other
    /// way round. Reading a value in the wrong namespace is how a target gets a plausible and
    /// wrong architecture.
    #[test]
    fn a_pe_machine_type_and_a_processor_architecture_are_read_apart() {
        assert_eq!(Arch::of(9), Arch::X64);
        assert_eq!(Arch::of_machine(9), None);
        assert_eq!(Arch::of_machine(0x8664), Some(Arch::X64));
        assert_eq!(Arch::of(332), Arch::Other(332));
        assert_eq!(Arch::of_machine(332), Some(Arch::X86));
        assert_eq!(Arch::of_machine(IMAGE_FILE_MACHINE_UNKNOWN), None);
    }

    /// A live process reads as the architecture it is running as — checked against the one
    /// process whose answer is known without asking anything: this one.
    ///
    /// It is the whole of `IsWow64Process2`'s contract in one assertion. Reading `NativeMachine`
    /// alone would pass here on x64 and x86 alike and fail only on the 32-bit worker this routing
    /// exists to start, which is the reason to pin it rather than assume it.
    #[test]
    fn this_process_reads_as_this_builds_own_architecture() {
        let expected = match std::env::consts::ARCH {
            "x86" => Arch::X86,
            "x86_64" => Arch::X64,
            "aarch64" => Arch::Arm64,
            other => panic!("this build runs on {other}, which this test has no answer for"),
        };
        assert_eq!(
            process_arch(std::process::id()).expect("this process can be asked about itself"),
            Some(expected)
        );
    }

    /// **A WoW64 process reads as x86 whatever the host is**, which is the answer the whole
    /// second worker image hangs off.
    ///
    /// `SysWOW64\cmd.exe` is the fixture because every host that can run a 32-bit target has one
    /// — including an ARM64 one, where x86 runs under emulation and `NativeMachine` would say
    /// `ARM64`. A host with no `SysWOW64` cannot run the target this is about, so it stands down.
    #[test]
    fn a_wow64_process_is_read_as_x86() {
        let Some(cmd) = wow64_cmd() else {
            eprintln!("SKIPPED: this host has no SysWOW64\\cmd.exe, so it runs no 32-bit process");
            return;
        };
        // Long enough that nothing here races its exit, and killed the moment the answer is in.
        // Under `engine::spawn_guard` like every other process this crate starts: a handle is
        // inheritable process-wide from the moment it is marked, so a child started during a
        // worker's spawn window would inherit that worker's protocol channel and keep it from
        // ever reporting EOF.
        let _one_spawn_at_a_time = crate::engine::spawn_guard();
        let mut child = std::process::Command::new(cmd)
            .args(["/c", "ping", "-n", "30", "127.0.0.1"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn a 32-bit process");
        let arch = process_arch(child.id());
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(
            arch.expect("a live process can be asked about itself"),
            Some(Arch::X86)
        );
    }

    /// A process that cannot be opened is an `Err`, not a wrong answer — which every caller then
    /// treats as "this routing has nothing to say" and logs.
    ///
    /// Pid 0 is the idle process: it always exists, and `OpenProcess` always refuses it, so this
    /// needs no race with a process going away underneath it.
    #[test]
    fn a_process_that_cannot_be_opened_is_an_error() {
        assert!(process_arch(0).is_err());
    }

    fn wow64_cmd() -> Option<PathBuf> {
        let cmd = PathBuf::from(std::env::var_os("WINDIR")?)
            .join("SysWOW64")
            .join("cmd.exe");
        cmd.is_file().then_some(cmd)
    }

    /// Builds a minimal but *structurally real* minidump: a header, a one-entry stream directory,
    /// and a system-info stream. Written rather than checked in because the file this routing
    /// cares about is a full-memory dump — 58 MB for a trivial managed process, five times this
    /// whole repository — and a header is all that is being parsed.
    fn minidump(architecture: u16) -> Vec<u8> {
        let mut bytes = vec![0u8; 32];
        bytes[0..4].copy_from_slice(&MINIDUMP_SIGNATURE.to_le_bytes());
        bytes[8..12].copy_from_slice(&1u32.to_le_bytes()); // NumberOfStreams
        bytes[12..16].copy_from_slice(&32u32.to_le_bytes()); // StreamDirectoryRva

        // One directory entry at RVA 32, pointing at a system-info stream at RVA 44.
        bytes.extend_from_slice(&SYSTEM_INFO_STREAM.to_le_bytes());
        bytes.extend_from_slice(&56u32.to_le_bytes()); // DataSize
        bytes.extend_from_slice(&44u32.to_le_bytes()); // Rva
        bytes.extend_from_slice(&architecture.to_le_bytes());
        bytes.resize(44 + 56, 0);
        bytes
    }

    fn read_bytes(bytes: &[u8]) -> io::Result<DumpTarget> {
        let dir = std::env::temp_dir().join(format!(
            "windbg-mcp-dump-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        let path = dir.join("probe.dmp");
        std::fs::write(&path, bytes).expect("write the probe dump");
        let read = read(&path);
        let _ = std::fs::remove_file(&path);
        read
    }

    #[test]
    fn an_x86_minidump_is_recognised() {
        assert_eq!(
            read_bytes(&minidump(0)).expect("a well-formed minidump reads"),
            DumpTarget::UserMinidump(Arch::X86)
        );
    }

    #[test]
    fn the_other_architectures_are_recognised() {
        for (value, expected) in [(9u16, Arch::X64), (12, Arch::Arm64), (5, Arch::Arm)] {
            assert_eq!(
                read_bytes(&minidump(value)).expect("a well-formed minidump reads"),
                DumpTarget::UserMinidump(expected),
                "PROCESSOR_ARCHITECTURE {value}"
            );
        }
    }

    /// An architecture this build has no name for is carried rather than guessed at, so whatever
    /// logs it can say what was in the file.
    #[test]
    fn an_unknown_architecture_keeps_its_value() {
        assert_eq!(
            read_bytes(&minidump(0x4242)).expect("a well-formed minidump reads"),
            DumpTarget::UserMinidump(Arch::Other(0x4242))
        );
    }

    /// **A kernel crash dump is not a minidump**, and must not be routed as one. This is the file
    /// every checked-in sample in `docs/samples` actually is.
    #[test]
    fn a_kernel_dump_is_not_a_user_minidump() {
        let mut bytes = b"PAGEDU64".to_vec();
        bytes.resize(4096, 0);
        assert_eq!(
            read_bytes(&bytes).expect("a kernel dump reads as something else"),
            DumpTarget::Other
        );
    }

    /// Short files and unrecognised ones are *not* errors: they mean this routing has nothing to
    /// say, and the engine will produce a far better diagnosis than a header parser can.
    #[test]
    fn a_file_too_short_to_be_a_minidump_is_not_an_error() {
        assert_eq!(
            read_bytes(b"MD").expect("a short file reads as something else"),
            DumpTarget::Other
        );
        assert_eq!(
            read_bytes(b"").expect("an empty file reads as something else"),
            DumpTarget::Other
        );
    }

    /// A directory that does not lead anywhere is an error rather than a silent `Other`, because
    /// the signature already said this *is* a minidump — so failing to read it is a fact worth a
    /// log line, not a file to shrug at.
    #[test]
    fn a_minidump_whose_directory_runs_off_the_end_is_an_error() {
        let mut bytes = minidump(0);
        bytes[12..16].copy_from_slice(&0xFFFF_0000u32.to_le_bytes());
        assert!(read_bytes(&bytes).is_err());
    }

    /// A `NumberOfStreams` far larger than any writer produces is capped rather than allocated
    /// against — and then fails to read, which is the honest outcome.
    #[test]
    fn an_implausible_stream_count_does_not_allocate_against_it() {
        let mut bytes = minidump(0);
        bytes[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(read_bytes(&bytes).is_err());
    }

    /// The one checked-in **user-mode** dump, named because it is the exception to the rule below.
    ///
    /// `cppthrow-fastfail.dmp` is `exception_triage`'s fixture — a C++ throw nothing caught, so the
    /// CRT fail-fasted. It is a `MiniDumpWriteDump` capture of an x64 process, which is exactly the
    /// shape this parser routes on, so it is asserted rather than skipped.
    const USER_MODE_SAMPLES: &[(&str, Arch)] = &[
        ("cppthrow-fastfail.dmp", Arch::X64),
        ("cppthrow-fastfail-x86.dmp", Arch::X86),
        ("stale-throw-abort.dmp", Arch::X64),
    ];

    /// The synthesised headers above are this parser's own idea of the format, so they cannot
    /// show it reads a file somebody else wrote. **These are real dumps**, checked in and opened
    /// by the smoke tier.
    ///
    /// Every kernel crash dump must come back `Other`, so a kernel target is never routed at a
    /// 32-bit worker that could not open it. Each user-mode sample must come back with **its own**
    /// architecture — these are the only files here that exercise this parser against real
    /// minidumps somebody else's code wrote, since the synthesised cases above are this module's
    /// own idea of the format.
    ///
    /// **The x86 one is the case the whole module exists for**, and it is real rather than
    /// synthesised: a 32-bit user minidump is what has to reach the 32-bit worker, because the x64
    /// engine cannot open it.
    ///
    /// **Every half is named, rather than the loop accepting whatever it finds.** The rule this
    /// started as was "every sample is a kernel dump", and the tempting way to admit a user-mode
    /// one is to relax the assertion; that would leave a kernel dump misread as a user minidump
    /// passing silently, which is the routing bug the whole module exists to prevent.
    #[test]
    fn the_checked_in_samples_route_to_the_worker_their_target_needs() {
        let samples = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/samples");
        let (mut kernel, mut seen) = (0, Vec::new());
        for entry in std::fs::read_dir(&samples).expect("the sample directory is checked in") {
            let path = entry.expect("a readable directory entry").path();
            if path.extension().is_none_or(|e| e != "dmp") {
                continue;
            }
            let read = read(&path).expect("a checked-in sample reads");
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            match USER_MODE_SAMPLES.iter().find(|(sample, _)| *sample == name) {
                Some((_, arch)) => {
                    seen.push(name.to_string());
                    assert_eq!(
                        read,
                        DumpTarget::UserMinidump(*arch),
                        "{} did not route at the worker its own architecture needs",
                        path.display()
                    );
                }
                None => {
                    kernel += 1;
                    assert_eq!(read, DumpTarget::Other, "{}", path.display());
                }
            }
        }
        // Or the loop above asserted nothing at all, which is the way a table-driven test rots.
        assert!(
            kernel >= 4,
            "expected the checked-in kernel samples, saw {kernel}"
        );
        seen.sort();
        let mut want: Vec<String> = USER_MODE_SAMPLES
            .iter()
            .map(|(sample, _)| (*sample).to_string())
            .collect();
        want.sort();
        assert_eq!(
            seen, want,
            "a named user-mode sample is missing from docs/samples"
        );
    }

    /// The parser against a **real 32-bit user minidump** — the file this whole routing exists
    /// for, and the one shape no checked-in sample has.
    ///
    /// Gated because such a dump is a full-memory capture (58 MB for a trivial managed process),
    /// which is five times this repository and is not worth checking in to read 44 bytes of.
    /// Point the variable at one to run it:
    /// `$env:WINDBG_MCP_X86_DUMP = "C:\path\to\x86.dmp"`.
    ///
    /// **Skipping is no longer a gap**, which it was for as long as this was the only test that
    /// could read one: the 32-bit tier in `tests/mcp_smoke.rs` compiles a 32-bit program and has
    /// it dump itself, so a real capture reaches this parser on every run of that tier. What is
    /// left here is a cheaper way to point the parser at a dump somebody else wrote.
    #[test]
    fn a_real_x86_user_minidump_reads_as_x86() {
        let Some(path) = std::env::var_os("WINDBG_MCP_X86_DUMP") else {
            eprintln!("SKIPPED: set WINDBG_MCP_X86_DUMP to a 32-bit user dump to run this");
            return;
        };
        assert_eq!(
            read(Path::new(&path)).expect("the dump reads"),
            DumpTarget::UserMinidump(Arch::X86)
        );
    }

    #[test]
    fn a_minidump_with_no_system_info_stream_is_an_error() {
        let mut bytes = minidump(0);
        // Retype the one stream to something that is not system-info.
        bytes[32..36].copy_from_slice(&3u32.to_le_bytes());
        assert!(read_bytes(&bytes).is_err());
    }
}
