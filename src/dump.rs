//! What a dump file says about itself, read from its own header before any engine opens it.
//!
//! One question, asked for one reason: **a 32-bit user-mode dump has to be opened by a 32-bit
//! engine if its managed extensions are ever going to load**. An extension DLL is loaded into the
//! debugger's own process, so a 64-bit host cannot load a 32-bit `sos.dll` at all — and the
//! 64-bit one refuses a 32-bit CLR, because the data access DLL behind it is paired to the
//! *target* as well as the host. There is no in-process arrangement that works, so the engine has
//! to move, and that decision has to be made **before** a target is opened rather than after.
//!
//! Hence a header read rather than an engine call. `IDebugControl::GetEffectiveProcessorType`
//! would answer the same question authoritatively, but only once a session already exists in a
//! process whose architecture is by then fixed — which is exactly the thing being decided.
//!
//! This deliberately answers for **user minidumps only** (`MDMP`). A kernel crash dump is a
//! different format (`PAGEDU64`), and it is not a case this routing is about: a kernel target has
//! no CLR in it and the x64 engine reads x86 and ARM64 kernel dumps alike. Anything unrecognised
//! is [`DumpTarget::Other`], which means "say nothing, let the engine decide" and never "this is
//! not openable".

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

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
        .chunks_exact(DIRECTORY_ENTRY_LEN)
        .find(|entry| u32_at(entry, 0) == SYSTEM_INFO_STREAM)
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

    /// The synthesised headers above are this parser's own idea of the format, so they cannot
    /// show it reads a file somebody else wrote. **These are real dumps**, checked in and opened
    /// by the smoke tier: every one is a kernel crash dump, and each must come back `Other` so a
    /// kernel target is never routed at a 32-bit worker that could not open it.
    #[test]
    fn the_checked_in_samples_are_all_kernel_dumps() {
        let samples = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/samples");
        let mut seen = 0;
        for entry in std::fs::read_dir(&samples).expect("the sample directory is checked in") {
            let path = entry.expect("a readable directory entry").path();
            if path.extension().is_none_or(|e| e != "dmp") {
                continue;
            }
            seen += 1;
            assert_eq!(
                read(&path).expect("a checked-in sample reads"),
                DumpTarget::Other,
                "{}",
                path.display()
            );
        }
        // Or the loop above asserted nothing at all, which is the way a table-driven test rots.
        assert!(
            seen >= 4,
            "expected the checked-in kernel samples, saw {seen}"
        );
    }

    /// The parser against a **real 32-bit user minidump** — the file this whole routing exists
    /// for, and the one shape no checked-in sample has.
    ///
    /// Gated because such a dump is a full-memory capture (58 MB for a trivial managed process),
    /// which is five times this repository and is not worth checking in to read 44 bytes of.
    /// Point the variable at one to run it:
    /// `$env:WINDBG_MCP_X86_DUMP = "C:\path\to\x86.dmp"`.
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
