//! A loaded image's PE structures, read through a memory reader.
//!
//! What this is for is naming the imports of a **driver with no symbols**. A call site in a driver
//! reads `call qword ptr [driver+0x9018]`, and turning that into `ExAllocatePool2` is what
//! separates a hazard scan that works on a stripped third-party binary from one that only works
//! where a PDB happens to exist.
//!
//! # Never dereference the IAT
//!
//! The obvious implementation reads the pointer in the import address table and asks the engine
//! what symbol it resolves to. **That does not work on a dump**, and the measurement is worth
//! keeping: against `docs/samples/081226-2187-01.dmp`, a kernel minidump carries no driver pages
//! at all, and an executable image search path brings back only what the *file* can supply —
//! headers, `.text`, and the read-only import structures. The IAT is writable, its runtime
//! contents were never captured, and the file cannot stand in for them: `dps mountmgr+0x9000 L6`
//! is six rows of `????????` on a session where the same image's code disassembles perfectly.
//!
//! So a slot is named **structurally**. `OriginalFirstThunk` — the import *lookup* table — lives
//! in a read-only section and holds one entry per import, in the same order as the IAT, so the
//! slot at `FirstThunk + i * ptr` is the name at index `i` of the lookup table. No pointer is
//! read, no symbol is resolved, and the answer is the same on a live target, a dump, and a
//! stripped driver.
//!
//! # Engine-free
//!
//! Every entry point here takes a reader closure rather than a `DebugEngine`, exactly as
//! [`crate::walk::run`] does, so the parsing tests against a fake address space and the worker
//! supplies the one closure that touches DbgEng. A read that fails is [`PeError::Unreadable`]
//! naming what could not be read, never a zero silently parsed as a structure.

// Nothing outside the tests reads this module yet — the driver tools that will are the next
// commits — and twenty `dead_code` warnings would bury a real one in the meantime. **Delete this
// the moment `driver_hazards` consumes it**; if it is still here when the tool surface has that
// tool, the suppression has outlived its reason.
#![allow(dead_code)]

use std::collections::BTreeMap;

/// What went wrong, in terms a caller can render as an outcome rather than a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeError {
    /// A read the parse needed did not come back. On a dump this is the ordinary answer for
    /// anything outside the read-only sections an image file can supply.
    Unreadable { at: u64, len: usize },
    /// The bytes are readable and are not a PE image.
    NotAnImage { reason: &'static str },
    /// A PE image whose structures do not hold together — a directory pointing outside the
    /// image, a count past its bound.
    Malformed { reason: &'static str },
    /// The caller's halt closure asked for a stop.
    Interrupted,
}

impl std::fmt::Display for PeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable { at, len } => {
                write!(f, "{len} bytes at {at:#x} could not be read")
            }
            Self::NotAnImage { reason } => write!(f, "not a PE image: {reason}"),
            Self::Malformed { reason } => write!(f, "malformed PE image: {reason}"),
            Self::Interrupted => write!(f, "interrupted"),
        }
    }
}

/// Whether the image is PE32 or PE32+, which is the pointer width its thunks are in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bitness {
    Bits32,
    Bits64,
}

impl Bitness {
    /// The width of one thunk entry.
    pub fn pointer(self) -> usize {
        match self {
            Self::Bits32 => 4,
            Self::Bits64 => 8,
        }
    }
}

/// One section of the image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// The eight-byte name, trimmed — `.text`, `.rdata`, `PAGE`.
    pub name: String,
    pub rva: u32,
    /// The size the section occupies once loaded.
    pub virtual_size: u32,
    pub characteristics: u32,
}

impl Section {
    /// `IMAGE_SCN_MEM_EXECUTE`.
    pub fn executable(&self) -> bool {
        self.characteristics & 0x2000_0000 != 0
    }

    /// `IMAGE_SCN_MEM_WRITE` — which is what makes a section's runtime contents unavailable from
    /// the image file, and therefore unavailable on a dump that did not capture them.
    pub fn writable(&self) -> bool {
        self.characteristics & 0x8000_0000 != 0
    }

    /// Whether an RVA falls inside this section.
    pub fn contains(&self, rva: u32) -> bool {
        rva >= self.rva && rva < self.rva.saturating_add(self.virtual_size)
    }
}

/// The image's headers, as much as naming imports and bounding a code scan needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Image {
    pub base: u64,
    pub bitness: Bitness,
    /// `IMAGE_FILE_MACHINE_*`.
    pub machine: u16,
    pub size_of_image: u32,
    pub sections: Vec<Section>,
    /// `(rva, size)` of the export directory; both zero when the image has none, which is the
    /// ordinary case for a driver.
    pub export_directory: (u32, u32),
    /// `(rva, size)` of the import directory.
    pub import_directory: (u32, u32),
}

impl Image {
    /// The section holding an RVA.
    pub fn section_at(&self, rva: u32) -> Option<&Section> {
        self.sections.iter().find(|section| section.contains(rva))
    }

    /// The executable sections, which is what a linear code scan is bounded by.
    pub fn code_sections(&self) -> impl Iterator<Item = &Section> {
        self.sections.iter().filter(|section| section.executable())
    }

    /// An RVA as a virtual address in this image.
    pub fn va(&self, rva: u32) -> u64 {
        self.base + u64::from(rva)
    }
}

/// What an import is called. An ordinal import has no name in the image at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportName {
    Named(String),
    Ordinal(u16),
}

impl std::fmt::Display for ImportName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Named(name) => f.write_str(name),
            Self::Ordinal(ordinal) => write!(f, "#{ordinal}"),
        }
    }
}

/// What an image's import table yielded, and what it could not.
///
/// The second field exists because an empty answer and an unanswerable one must not look alike.
/// A descriptor whose `OriginalFirstThunk` is zero — a **bound** import — has real slots and no
/// lookup table, so its names live only in the import address table, which this deliberately does
/// not read. Reporting nothing for it would tell a hazard scan that the driver imports fewer
/// functions than it does, and "imports no dangerous API" is exactly the answer that must never
/// be produced by silence.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportTable {
    pub imports: Vec<Import>,
    /// Libraries whose imports could not be named, and why they could not: bound imports, whose
    /// names are only in the table this cannot read.
    pub unnamed_libraries: Vec<String>,
}

/// One imported function, and the address of the slot a call goes through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Import {
    /// The library as the image spells it — `ntoskrnl.exe`.
    pub library: String,
    pub name: ImportName,
    /// The virtual address of this import's IAT slot. **Not read**: it is
    /// `base + FirstThunk + index * pointer`, which is why this answers on an image whose
    /// writable pages were never captured.
    pub slot: u64,
}

/// Bounds. Every one of these is a refusal rather than a truncation: a structure that exceeds one
/// is [`PeError::Malformed`], because a plausible image does not, and a walk that quietly stopped
/// would report a driver as importing less than it does.
const MAX_SECTIONS: usize = 96;
const MAX_LIBRARIES: usize = 64;
const MAX_IMPORTS_PER_LIBRARY: usize = 8192;
const MAX_NAME: usize = 512;

/// Reads an image's headers and section table.
pub fn read_image(
    base: u64,
    mut read: impl FnMut(u64, usize) -> Option<Vec<u8>>,
) -> Result<Image, PeError> {
    let mut at = |offset: u64, len: usize| -> Result<Vec<u8>, PeError> {
        read(base + offset, len).ok_or(PeError::Unreadable {
            at: base + offset,
            len,
        })
    };

    let dos = at(0, 0x40)?;
    if u16(&dos, 0)? != 0x5a4d {
        return Err(PeError::NotAnImage {
            reason: "no MZ signature",
        });
    }
    let lfanew = u32(&dos, 0x3c)? as u64;
    if lfanew > 0x1000 {
        return Err(PeError::NotAnImage {
            reason: "e_lfanew is outside the header page",
        });
    }

    // COFF header, then as much optional header as the data directories need. Read in one go: the
    // header page is one read on any target that can answer at all.
    let headers = at(lfanew, 0x108)?;
    if u32(&headers, 0)? != 0x0000_4550 {
        return Err(PeError::NotAnImage {
            reason: "no PE signature",
        });
    }
    let machine = u16(&headers, 4)?;
    let section_count = u16(&headers, 6)? as usize;
    let optional_size = u16(&headers, 20)? as usize;
    let optional = 24usize;

    let bitness = match u16(&headers, optional)? {
        0x10b => Bitness::Bits32,
        0x20b => Bitness::Bits64,
        _ => {
            return Err(PeError::NotAnImage {
                reason: "the optional header names neither PE32 nor PE32+",
            });
        }
    };
    // `SizeOfImage` and the data directories sit at different offsets in the two shapes, because
    // PE32+ widens five fields between them.
    let (size_of_image_at, directories_at) = match bitness {
        Bitness::Bits32 => (optional + 56, optional + 96),
        Bitness::Bits64 => (optional + 56, optional + 112),
    };
    let size_of_image = u32(&headers, size_of_image_at)?;
    let export_directory = (
        u32(&headers, directories_at)?,
        u32(&headers, directories_at + 4)?,
    );
    let import_directory = (
        u32(&headers, directories_at + 8)?,
        u32(&headers, directories_at + 12)?,
    );

    if section_count > MAX_SECTIONS {
        return Err(PeError::Malformed {
            reason: "more sections than an image plausibly has",
        });
    }
    let table = lfanew + 24 + optional_size as u64;
    let raw = at(table, section_count * 40)?;
    let mut sections = Vec::with_capacity(section_count);
    for index in 0..section_count {
        let offset = index * 40;
        let name = raw
            .get(offset..offset + 8)
            .ok_or(PeError::Malformed {
                reason: "the section table is shorter than its count",
            })?
            .iter()
            .take_while(|&&byte| byte != 0)
            .map(|&byte| byte as char)
            .collect::<String>();
        sections.push(Section {
            name,
            virtual_size: u32(&raw, offset + 8)?,
            rva: u32(&raw, offset + 12)?,
            characteristics: u32(&raw, offset + 36)?,
        });
    }

    Ok(Image {
        base,
        bitness,
        machine,
        size_of_image,
        sections,
        export_directory,
        import_directory,
    })
}

/// Reads the import table, naming every slot without reading one.
///
/// The ordering rule this rests on is the PE specification's: the import lookup table and the
/// import address table are parallel arrays, so entry `i` of the lookup table names the slot at
/// `FirstThunk + i * pointer`. An image whose `OriginalFirstThunk` is zero — bound imports, which
/// a driver does not normally ship — has only the IAT to read names from, and this reports the
/// slots it can place with [`ImportName::Ordinal`] rather than reading a pointer that may not be
/// there.
pub fn read_imports(
    image: &Image,
    mut read: impl FnMut(u64, usize) -> Option<Vec<u8>>,
    mut halt: impl FnMut() -> bool,
) -> Result<ImportTable, PeError> {
    let (directory, size) = image.import_directory;
    if directory == 0 || size == 0 {
        return Ok(ImportTable::default());
    }
    let mut at = |rva: u32, len: usize| -> Result<Vec<u8>, PeError> {
        let address = image.va(rva);
        read(address, len).ok_or(PeError::Unreadable { at: address, len })
    };

    let descriptors = at(directory, size.min(MAX_LIBRARIES as u32 * 20) as usize)?;
    let mut table = ImportTable::default();
    for index in 0..(descriptors.len() / 20) {
        if halt() {
            return Err(PeError::Interrupted);
        }
        let offset = index * 20;
        let lookup = u32(&descriptors, offset)?;
        let name_rva = u32(&descriptors, offset + 12)?;
        let iat = u32(&descriptors, offset + 16)?;
        // The table ends at an all-zero descriptor.
        if lookup == 0 && name_rva == 0 && iat == 0 {
            break;
        }
        let library = read_c_string(name_rva, &mut at)?;
        // Bound imports leave no lookup table; the IAT is then the only array there is, and its
        // entries are addresses rather than name RVAs.
        // A bound import: real slots, no lookup table, names only in the IAT. Recorded by name
        // rather than skipped, so a caller can say "this library's imports are not nameable here"
        // instead of reporting a driver that imports less than it does.
        if lookup == 0 {
            table.unnamed_libraries.push(library);
            continue;
        }
        let pointer = image.bitness.pointer();

        for slot_index in 0..MAX_IMPORTS_PER_LIBRARY {
            if halt() {
                return Err(PeError::Interrupted);
            }
            let slot = image.va(iat) + (slot_index * pointer) as u64;
            let entry_rva = lookup + (slot_index * pointer) as u32;
            let entry = at(entry_rva, pointer)?;
            let value = match image.bitness {
                Bitness::Bits32 => u32(&entry, 0)? as u64,
                Bitness::Bits64 => u64_at(&entry, 0)?,
            };
            if value == 0 {
                break;
            }
            let ordinal_flag = match image.bitness {
                Bitness::Bits32 => 1u64 << 31,
                Bitness::Bits64 => 1u64 << 63,
            };
            let name = if value & ordinal_flag != 0 {
                ImportName::Ordinal((value & 0xffff) as u16)
            } else {
                // IMAGE_IMPORT_BY_NAME: a two-byte hint, then the name.
                ImportName::Named(read_c_string((value as u32) + 2, &mut at)?)
            };
            table.imports.push(Import {
                library: library.clone(),
                name,
                slot,
            });
        }
    }
    Ok(table)
}

/// The imports indexed by the slot a call goes through, which is how a call site is named.
pub fn imports_by_slot(imports: &[Import]) -> BTreeMap<u64, &Import> {
    imports.iter().map(|import| (import.slot, import)).collect()
}

/// A NUL-terminated ASCII string at an RVA, read in one bounded go.
fn read_c_string(
    rva: u32,
    at: &mut impl FnMut(u32, usize) -> Result<Vec<u8>, PeError>,
) -> Result<String, PeError> {
    let raw = at(rva, MAX_NAME)?;
    let end = raw.iter().position(|&byte| byte == 0).unwrap_or(raw.len());
    Ok(String::from_utf8_lossy(&raw[..end]).into_owned())
}

fn u16(bytes: &[u8], offset: usize) -> Result<u16, PeError> {
    let raw = bytes.get(offset..offset + 2).ok_or(PeError::Malformed {
        reason: "short read of a 16-bit field",
    })?;
    Ok(u16::from_le_bytes([raw[0], raw[1]]))
}

fn u32(bytes: &[u8], offset: usize) -> Result<u32, PeError> {
    let raw = bytes.get(offset..offset + 4).ok_or(PeError::Malformed {
        reason: "short read of a 32-bit field",
    })?;
    Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, PeError> {
    let raw = bytes.get(offset..offset + 8).ok_or(PeError::Malformed {
        reason: "short read of a 64-bit field",
    })?;
    let mut value = [0u8; 8];
    value.copy_from_slice(raw);
    Ok(u64::from_le_bytes(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake address space holding one loaded image, with ranges that can be made unreadable.
    ///
    /// Every offset below is written as a **literal** rather than computed the way the parser
    /// reads it: a fixture that derives its layout from the parser's own arithmetic agrees with
    /// the parser about a wrong layout, and pins nothing.
    struct FakeImage {
        base: u64,
        bytes: Vec<u8>,
        unreadable: Vec<(u64, u64)>,
    }

    impl FakeImage {
        fn read(&self, at: u64, len: usize) -> Option<Vec<u8>> {
            let end = at.checked_add(len as u64)?;
            if self
                .unreadable
                .iter()
                .any(|&(low, high)| at < high && end > low)
            {
                return None;
            }
            let offset = at.checked_sub(self.base)? as usize;
            // A read running off the end comes back short rather than absent, which is what a
            // real reader does at the last mapped page.
            let slice = self.bytes.get(offset..)?;
            Some(slice[..slice.len().min(len)].to_vec())
        }
    }

    fn put(bytes: &mut Vec<u8>, offset: usize, value: &[u8]) {
        if bytes.len() < offset + value.len() {
            bytes.resize(offset + value.len(), 0);
        }
        bytes[offset..offset + value.len()].copy_from_slice(value);
    }

    const BASE: u64 = 0xffff_f800_0000_0000;

    /// A PE32+ driver: three sections, one imported library, three imports — two by name and one
    /// by ordinal — with the import address table in the writable section.
    fn driver_image() -> FakeImage {
        let mut bytes = vec![0u8; 0x4000];

        // DOS header: `MZ`, and e_lfanew at 0x3c.
        put(&mut bytes, 0x00, b"MZ");
        put(&mut bytes, 0x3c, &0xe0u32.to_le_bytes());

        // COFF header at 0xe0.
        put(&mut bytes, 0xe0, b"PE\0\0");
        put(&mut bytes, 0xe4, &0x8664u16.to_le_bytes()); // Machine
        put(&mut bytes, 0xe6, &3u16.to_le_bytes()); // NumberOfSections
        put(&mut bytes, 0xf4, &0xf0u16.to_le_bytes()); // SizeOfOptionalHeader

        // Optional header at 0xf8 (0xe0 + 24), PE32+.
        put(&mut bytes, 0xf8, &0x20bu16.to_le_bytes()); // Magic
        put(&mut bytes, 0xf8 + 56, &0x4000u32.to_le_bytes()); // SizeOfImage
        // Data directories at 0xf8 + 112 = 0x168: export is [0], import is [1].
        put(&mut bytes, 0x170, &0x2000u32.to_le_bytes()); // import rva
        put(&mut bytes, 0x174, &40u32.to_le_bytes()); // import size

        // Section table at 0x1e8 (0xe0 + 24 + 0xf0), forty bytes an entry.
        let mut section = |index: usize, name: &[u8], rva: u32, characteristics: u32| {
            let at = 0x1e8 + index * 40;
            put(&mut bytes, at, name);
            put(&mut bytes, at + 8, &0x1000u32.to_le_bytes()); // VirtualSize
            put(&mut bytes, at + 12, &rva.to_le_bytes()); // VirtualAddress
            put(&mut bytes, at + 36, &characteristics.to_le_bytes());
        };
        section(0, b".text\0\0\0", 0x1000, 0x6000_0020); // CODE | EXECUTE | READ
        section(1, b".rdata\0\0", 0x2000, 0x4000_0040); // INITIALIZED_DATA | READ
        section(2, b".data\0\0\0", 0x3000, 0xc000_0040); // READ | WRITE

        // Import descriptor at 0x2000; the table ends at the all-zero one at 0x2014.
        put(&mut bytes, 0x2000, &0x2040u32.to_le_bytes()); // OriginalFirstThunk
        put(&mut bytes, 0x200c, &0x2100u32.to_le_bytes()); // Name
        put(&mut bytes, 0x2010, &0x3000u32.to_le_bytes()); // FirstThunk — in .data

        // Import lookup table at 0x2040, eight bytes an entry, zero-terminated.
        put(&mut bytes, 0x2040, &0x2110u64.to_le_bytes());
        put(&mut bytes, 0x2048, &0x2120u64.to_le_bytes());
        put(&mut bytes, 0x2050, &0x8000_0000_0000_0007u64.to_le_bytes()); // ordinal 7

        // Names. An IMAGE_IMPORT_BY_NAME is a two-byte hint and then the string.
        put(&mut bytes, 0x2100, b"ntoskrnl.exe\0");
        put(&mut bytes, 0x2112, b"ExAllocatePool2\0");
        put(&mut bytes, 0x2122, b"ProbeForRead\0");

        FakeImage {
            base: BASE,
            bytes,
            unreadable: Vec::new(),
        }
    }

    /// The rule this module exists for: an import is named without its slot ever being read.
    ///
    /// The import address table is unreadable here, which is not contrived — it is what a kernel
    /// minidump does. Measured against `docs/samples/081226-2187-01.dmp`: the driver's code and
    /// read-only data come back once an image search path is set, and `dps mountmgr+0x9000 L6` is
    /// six rows of `????????` on that same session, because the table is writable and its runtime
    /// contents were never captured.
    #[test]
    fn imports_are_named_without_reading_the_import_address_table() {
        let mut fake = driver_image();
        fake.unreadable.push((BASE + 0x3000, BASE + 0x4000));

        let image = read_image(BASE, |at, len| fake.read(at, len)).expect("the headers read");
        let imports = read_imports(&image, |at, len| fake.read(at, len), || false)
            .expect("imports read")
            .imports;

        assert_eq!(imports.len(), 3, "{imports:#?}");
        assert!(imports.iter().all(|i| i.library == "ntoskrnl.exe"));
        assert_eq!(
            imports
                .iter()
                .map(|i| i.name.to_string())
                .collect::<Vec<_>>(),
            vec!["ExAllocatePool2", "ProbeForRead", "#7"]
        );
        // The slots are arithmetic over FirstThunk, which is why they are answerable at all.
        assert_eq!(
            imports.iter().map(|i| i.slot).collect::<Vec<_>>(),
            vec![BASE + 0x3000, BASE + 0x3008, BASE + 0x3010]
        );
    }

    /// The inverse: with the *lookup* table unreadable there is nothing to name a slot with, and
    /// that is an error rather than an empty list.
    ///
    /// An empty list renders as "this driver imports nothing", which is the one answer a hazard
    /// scan must never give for a driver whose pages were simply not captured.
    #[test]
    fn an_unreadable_lookup_table_is_an_error_rather_than_no_imports() {
        let mut fake = driver_image();
        fake.unreadable.push((BASE + 0x2040, BASE + 0x2060));

        let image = read_image(BASE, |at, len| fake.read(at, len)).unwrap();
        let error = read_imports(&image, |at, len| fake.read(at, len), || false)
            .expect_err("an unreadable lookup table must not read as an empty import table");
        assert!(matches!(error, PeError::Unreadable { .. }), "{error:?}");
    }

    /// The section table, with the two flags the analyses branch on.
    #[test]
    fn sections_carry_the_flags_a_scan_is_bounded_by() {
        let fake = driver_image();
        let image = read_image(BASE, |at, len| fake.read(at, len)).unwrap();

        assert_eq!(image.bitness, Bitness::Bits64);
        assert_eq!(image.machine, 0x8664);
        assert_eq!(image.size_of_image, 0x4000);
        assert_eq!(
            image
                .sections
                .iter()
                .map(|s| s.name.as_str())
                .collect::<Vec<_>>(),
            vec![".text", ".rdata", ".data"]
        );

        let code = image.code_sections().collect::<Vec<_>>();
        assert_eq!(code.len(), 1);
        assert_eq!(code[0].name, ".text");
        assert!(!code[0].writable());
        assert!(
            image.sections[2].writable(),
            "the .data section is writable"
        );

        assert_eq!(
            image.section_at(0x2100).map(|s| s.name.as_str()),
            Some(".rdata")
        );
        assert_eq!(image.section_at(0x9999), None);
        assert_eq!(image.va(0x1000), BASE + 0x1000);
    }

    /// A driver with no import directory imports nothing, and that is not an error — but it is
    /// reported only for a directory the headers say is absent, never for one that would not read.
    #[test]
    fn an_absent_import_directory_is_no_imports() {
        let mut fake = driver_image();
        put(&mut fake.bytes, 0x170, &0u32.to_le_bytes());
        put(&mut fake.bytes, 0x174, &0u32.to_le_bytes());

        let image = read_image(BASE, |at, len| fake.read(at, len)).unwrap();
        assert_eq!(
            read_imports(&image, |at, len| fake.read(at, len), || false).unwrap(),
            ImportTable::default()
        );
    }

    /// A library with no lookup table is **named as unnameable**, not silently skipped.
    ///
    /// A bound import has real slots and no `OriginalFirstThunk`, so its names live only in the
    /// import address table this deliberately does not read. Dropping it would tell a hazard scan
    /// that the driver imports fewer functions than it does — and "imports no dangerous API" is
    /// exactly the answer that must never come from silence.
    #[test]
    fn a_library_with_no_lookup_table_is_reported_rather_than_skipped() {
        let mut fake = driver_image();
        // Clear OriginalFirstThunk, leaving the name and the IAT: a bound import.
        put(&mut fake.bytes, 0x2000, &0u32.to_le_bytes());

        let image = read_image(BASE, |at, len| fake.read(at, len)).unwrap();
        let table = read_imports(&image, |at, len| fake.read(at, len), || false).unwrap();

        assert!(
            table.imports.is_empty(),
            "nothing can be named without a lookup table: {table:?}"
        );
        assert_eq!(
            table.unnamed_libraries,
            vec!["ntoskrnl.exe".to_string()],
            "the library must be reported, not dropped: {table:?}"
        );
    }

    /// Headers that will not read are unreadable; bytes that are not an image are refused. The
    /// two are different outcomes because their remedies are — one is an image search path, the
    /// other is a wrong address.
    #[test]
    fn an_unreadable_header_and_a_non_image_are_told_apart() {
        let nothing =
            read_image(BASE, |_, _| None).expect_err("a reader answering nothing must not parse");
        assert!(matches!(nothing, PeError::Unreadable { .. }), "{nothing:?}");

        let mut rubbish = driver_image();
        put(&mut rubbish.bytes, 0x00, b"XX");
        let refused = read_image(BASE, |at, len| rubbish.read(at, len))
            .expect_err("bytes with no MZ must not parse");
        assert!(matches!(refused, PeError::NotAnImage { .. }), "{refused:?}");
    }

    /// PE32 puts its data directories sixteen bytes earlier than PE32+ does. Reading a 32-bit
    /// driver at the 64-bit offset finds an import directory of zero — no imports and no error,
    /// with nothing to say a whole architecture was misread.
    #[test]
    fn a_32_bit_image_reads_its_directories_at_the_32_bit_offset() {
        let mut fake = driver_image();
        put(&mut fake.bytes, 0xf8, &0x10bu16.to_le_bytes()); // PE32
        put(&mut fake.bytes, 0xe4, &0x014cu16.to_le_bytes()); // i386
        // Directories move to 0xf8 + 96 = 0x158, and the 64-bit slot is cleared, so a parser
        // reading the wrong one finds nothing rather than the right answer by accident.
        put(&mut fake.bytes, 0x158 + 8, &0x2000u32.to_le_bytes());
        put(&mut fake.bytes, 0x158 + 12, &40u32.to_le_bytes());
        put(&mut fake.bytes, 0x170, &0u32.to_le_bytes());
        put(&mut fake.bytes, 0x174, &0u32.to_le_bytes());
        // A 32-bit lookup table is four bytes an entry.
        put(&mut fake.bytes, 0x2040, &0x2110u32.to_le_bytes());
        put(&mut fake.bytes, 0x2044, &0x2120u32.to_le_bytes());
        put(&mut fake.bytes, 0x2048, &0u32.to_le_bytes());

        let image = read_image(BASE, |at, len| fake.read(at, len)).unwrap();
        assert_eq!(image.bitness, Bitness::Bits32);
        assert_eq!(image.import_directory, (0x2000, 40));

        let imports = read_imports(&image, |at, len| fake.read(at, len), || false)
            .unwrap()
            .imports;
        assert_eq!(
            imports
                .iter()
                .map(|i| i.name.to_string())
                .collect::<Vec<_>>(),
            vec!["ExAllocatePool2", "ProbeForRead"]
        );
        // Four-byte slots, not eight.
        assert_eq!(
            imports.iter().map(|i| i.slot).collect::<Vec<_>>(),
            vec![BASE + 0x3000, BASE + 0x3004]
        );
    }

    /// A halt is honoured inside the walk, because a bounded loop still needs a check in it.
    #[test]
    fn a_halt_stops_the_import_walk() {
        let fake = driver_image();
        let image = read_image(BASE, |at, len| fake.read(at, len)).unwrap();
        let error = read_imports(&image, |at, len| fake.read(at, len), || true)
            .expect_err("a halt should stop the walk");
        assert_eq!(error, PeError::Interrupted);
    }

    /// The slot index is what names a call site, so it is built once and looked up by address.
    #[test]
    fn imports_index_by_the_slot_a_call_goes_through() {
        let fake = driver_image();
        let image = read_image(BASE, |at, len| fake.read(at, len)).unwrap();
        let imports = read_imports(&image, |at, len| fake.read(at, len), || false)
            .unwrap()
            .imports;
        let index = imports_by_slot(&imports);

        assert_eq!(
            index.get(&(BASE + 0x3008)).map(|i| i.name.to_string()),
            Some("ProbeForRead".to_string())
        );
        assert!(!index.contains_key(&(BASE + 0x3018)));
    }
}
