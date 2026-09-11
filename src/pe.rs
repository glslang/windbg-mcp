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
//! keeping: against `docs/samples/081226-2187-01.dmp`, `db mountmgr+0x9000` is rows of `????????`
//! on a session where every other RVA probed across the same image reads and the code
//! disassembles perfectly. The IAT is writable, its runtime contents were never captured, and no
//! image file can stand in for them — whatever supplies the code, that page is gone.
//!
//! Which is the durable half of it. Whether a driver's *code* reads on a dump varies with what the
//! engine can obtain, and is not predicted by the dump's type: the same minidump reads mountmgr's
//! whole image with no executable image path set at all. So the rule below is not a workaround for
//! a cold session — it is the only way a slot is ever named, on a live target as much as on a dump.
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
//!
//! # This belongs in dbgscope, and not yet
//!
//! Reading an image out of a target is a primitive, and dbgscope is where the target-memory
//! abstractions live — so this is tracked to move there
//! ([dbgscope#150](https://github.com/glslang/dbgscope/issues/150)). Not now: its only consumer
//! today is its own tests, and a shape lifted before a real consumer has exercised it is the wrong
//! shape frozen. The moment is once `driver_hazards` is naming call sites from it. The issue lists
//! the properties a lift must keep — the reader closure, the halt, the two error kinds, and
//! refusing rather than truncating — which are the same properties that ruled out a third-party
//! parser: `goblin`, `object` and `pelite` all want a contiguous slice, and a loaded image in a
//! dump has holes in it.

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
    /// The executable sections, which is what a linear code scan is bounded by.
    pub fn code_sections(&self) -> impl Iterator<Item = &Section> {
        self.sections.iter().filter(|section| section.executable())
    }

    /// An RVA as a virtual address in this image, **checked against the image's own bounds**.
    ///
    /// The one door. An RVA past `SizeOfImage` added to the base lands in whatever is mapped next
    /// — on a live target, the next module — and every use of that address is then about some
    /// other image with nothing to say so. Whether the address is *read* or merely *reported* does
    /// not change that: an import slot this crate never dereferences is still an address a caller
    /// will attribute to this image, so it comes through here too. `len` is what will be reached
    /// from it, and zero asks only whether the start is inside.
    pub fn checked_va(&self, rva: u32, len: usize) -> Result<u64, PeError> {
        let end = u64::from(rva)
            .checked_add(len as u64)
            .ok_or(PeError::Malformed {
                reason: "an image offset and length overflowed",
            })?;
        if rva >= self.size_of_image || end > u64::from(self.size_of_image) {
            return Err(PeError::Malformed {
                reason: "an image offset points outside the image",
            });
        }
        self.base
            .checked_add(u64::from(rva))
            .ok_or(PeError::Malformed {
                reason: "an image address overflowed",
            })
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
/// And the **total**, which the two above do not bound: multiplied out they permit half a million
/// imports, each an owned name and an owned library string, which is hundreds of megabytes held
/// before any consumer sees a single one. A plausible driver imports a few hundred; the largest
/// system components a few thousand. This is far past both and bounds the absurd.
const MAX_IMPORTS_TOTAL: usize = 16 * 1024;
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
    // `SizeOfImage`, the directory count and the directories themselves sit at different offsets
    // in the two shapes, because PE32+ widens five fields between them.
    let (size_of_image_at, count_at, directories_at) = match bitness {
        Bitness::Bits32 => (optional + 56, optional + 92, optional + 96),
        Bitness::Bits64 => (optional + 56, optional + 108, optional + 112),
    };
    // The optional header must be long enough to hold the fields read out of it, and
    // `NumberOfRvaAndSizes` is the last of them in both shapes — so a header ending before it is
    // not an optional header, and is refused rather than read. Its declared length is also where
    // the **section table** begins, which is what makes a read past it a read of something else
    // entirely rather than of a zero: a garbage directory count would otherwise be a section
    // header's name.
    let optional_end = optional + optional_size;
    if optional_end < count_at + 4 {
        return Err(PeError::NotAnImage {
            reason: "the optional header is too short to hold its own fields",
        });
    }
    let size_of_image = u32(&headers, size_of_image_at)?;

    // **The data directories are declared, not assumed.** `NumberOfRvaAndSizes` says how many the
    // image carries and `SizeOfOptionalHeader` says how much room there is for them; an entry is
    // present only when both cover it. Read unconditionally, an undeclared entry is read out of
    // the section table that begins immediately after the optional header — so a section header's
    // `VirtualSize` and `VirtualAddress` become an import directory's RVA and size, and a valid
    // image with no import directory is reported as importing whatever they spell. The smaller of
    // the two bounds wins rather than their disagreement being an error: a header with no room for
    // an entry does not contain one, whatever it declares, and that reading needs no guess.
    let declared = u32(&headers, count_at)? as usize;
    let directory = |index: usize| -> Result<(u32, u32), PeError> {
        let entry = directories_at + index * 8;
        if index >= declared || entry + 8 > optional_end {
            return Ok((0, 0));
        }
        Ok((u32(&headers, entry)?, u32(&headers, entry + 4)?))
    };
    let export_directory = directory(0)?;
    let import_directory = directory(1)?;

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
    // Absent means **both** are zero. One of the two alone is a directory whose coordinates
    // disagree, and reading that as "no imports" is the silent wrong answer this module keeps
    // being asked not to give: a nonzero RVA with a zero size hides a real descriptor table, and a
    // hazard scan over it reports no dangerous imports.
    match (directory, size) {
        (0, 0) => return Ok(ImportTable::default()),
        (0, _) | (_, 0) => {
            return Err(PeError::Malformed {
                reason: "the import directory has a size without an address, or the reverse",
            });
        }
        _ => {}
    }
    // Every read is bounded by the image, and the arithmetic is checked.
    //
    // Without this, an RVA past `SizeOfImage` is added to the base and handed to the reader — and
    // on a live target the memory just past a driver is *the next module*, which reads perfectly
    // well. A malformed or adversarial image would then have its "imports" answered out of a
    // neighbour's bytes, with nothing in the result to say so. A start outside the image is
    // refused; a length that would run past its end is clipped to it, because a name near the end
    // is legitimately shorter than the bounded read asks for, and a structure that comes back
    // short fails its own field parse.
    let mut at = |rva: u32, len: usize| -> Result<Vec<u8>, PeError> {
        // Clipped to the image rather than refused for overrunning it: a name near the end is
        // legitimately shorter than the bounded read asks for, and a fixed-size structure that
        // comes back short fails its own field parse. The *start* is still bounded.
        let room = image.size_of_image.saturating_sub(rva) as usize;
        let len = len.min(room);
        let address = image.checked_va(rva, len)?;
        read(address, len).ok_or(PeError::Unreadable { at: address, len })
    };

    // Refused rather than truncated, which is this module's stated rule and was not followed
    // here: reading the first `MAX_LIBRARIES` and returning `Ok` drops the rest in silence, and a
    // hazard scan reading that concludes a dangerous import is absent when it is merely past the
    // cut. A plausible image does not have this many.
    //
    // The `+ 1` is the **terminator**, which is a descriptor and is not a library. Without it the
    // limit is off by one against its own sentence: an image importing exactly `MAX_LIBRARIES`
    // libraries carries `MAX_LIBRARIES + 1` descriptors and would be refused for having one more
    // library than it has.
    if size as usize / 20 > MAX_LIBRARIES + 1 {
        return Err(PeError::Malformed {
            reason: "the import directory names more libraries than an image plausibly has",
        });
    }
    let descriptors = at(directory, size as usize)?;
    let mut table = ImportTable::default();
    // **A slot belongs to one import.** It holds one function pointer, so two names claiming it is
    // a structure that does not hold together — and continuing would make every call through it an
    // arbitrary choice between the two, reported as a fact. Refused here rather than resolved
    // downstream, because a consumer indexing by slot can only silently keep the last one.
    let mut claimed: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut terminated = false;
    for index in 0..(descriptors.len() / 20) {
        if halt() {
            return Err(PeError::Interrupted);
        }
        let offset = index * 20;
        let lookup = u32(&descriptors, offset)?;
        let name_rva = u32(&descriptors, offset + 12)?;
        let iat = u32(&descriptors, offset + 16)?;
        // The table ends at an **all-zero** descriptor, which is all five fields and not the
        // three that happen to be read above: a descriptor with a stamp or a forwarder chain left
        // over would otherwise end the table early and drop every library after it.
        let stamp = u32(&descriptors, offset + 4)?;
        let forwarder = u32(&descriptors, offset + 8)?;
        if lookup == 0 && name_rva == 0 && iat == 0 && stamp == 0 && forwarder == 0 {
            terminated = true;
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

        let mut library_terminated = false;
        for slot_index in 0..MAX_IMPORTS_PER_LIBRARY {
            if halt() {
                return Err(PeError::Interrupted);
            }
            // Never dereferenced, and still bounded: a caller attributes this address to *this*
            // image, so a `FirstThunk` outside it would have an indirect call into a neighbour
            // reported as this driver's import.
            let slot_rva = u32::try_from(iat as usize + slot_index * pointer).map_err(|_| {
                PeError::Malformed {
                    reason: "an import address table entry lies outside a 32-bit image offset",
                }
            })?;
            let slot = image.checked_va(slot_rva, pointer)?;
            let entry_rva = lookup + (slot_index * pointer) as u32;
            let entry = at(entry_rva, pointer)?;
            let value = match image.bitness {
                Bitness::Bits32 => u32(&entry, 0)? as u64,
                Bitness::Bits64 => u64_at(&entry, 0)?,
            };
            if value == 0 {
                library_terminated = true;
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
            // Checked as the table grows rather than after it, which is the whole point: a limit
            // enforced on a finished list is a limit enforced after the memory was spent.
            if !claimed.insert(slot) {
                return Err(PeError::Malformed {
                    reason: "two imports claim the same import address table slot",
                });
            }
            if table.imports.len() >= MAX_IMPORTS_TOTAL {
                return Err(PeError::Malformed {
                    reason: "the image imports more functions in total than a plausible one does",
                });
            }
            table.imports.push(Import {
                library: library.clone(),
                name,
                slot,
            });
        }
        // Running out of entries is not the same as reaching the end of them. Stopping here and
        // returning `Ok` drops every later import of this library in silence, which is how a
        // hazard scan comes to report that a dangerous API is absent when it is merely past the
        // cut — the same defect as the directory bound above, one level down.
        if !library_terminated {
            return Err(PeError::Malformed {
                reason: "a library imports more functions than an image plausibly does",
            });
        }
    }
    // A directory that ran out before its null descriptor is one whose size does not describe it,
    // and the libraries past the end are exactly the ones a truncating read would have dropped.
    if !terminated {
        return Err(PeError::Malformed {
            reason: "the import directory ends without a null descriptor",
        });
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
    // No terminator inside the bound means this is not a name that fits the bound — and taking
    // the buffer as one turns a hazardous import into a *different*, unmatched string, which a
    // sink list then fails to recognise. The truncation would be invisible in the result.
    let Some(end) = raw.iter().position(|&byte| byte == 0) else {
        return Err(PeError::Malformed {
            reason: "an import or library name runs past the length a name may have",
        });
    };
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
        // NumberOfRvaAndSizes at 0xf8 + 108 = 0x164. Sixteen is what every real image writes, and
        // a directory is only read when this says it is there.
        put(&mut bytes, 0x164, &16u32.to_le_bytes());
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
        assert!(
            !code.iter().any(|s| s.name == ".data"),
            "a writable section is not code and is never decoded: {code:?}"
        );
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

    /// A slot belongs to **one** import, and two claiming it is refused.
    ///
    /// A slot holds one function pointer, so two names claiming it is a structure that does not
    /// hold together — and an index keyed by slot can only silently keep the last one, which makes
    /// every call through that address an arbitrary choice between the two, reported as a fact.
    /// The other name then reports no call sites at all, which reads as an import the driver never
    /// uses.
    #[test]
    fn two_imports_claiming_one_slot_are_refused() {
        let mut fake = driver_image();
        // A second library whose `FirstThunk` is the first one's, so their slots collide.
        put(&mut fake.bytes, 0x2014, &0x2060u32.to_le_bytes()); // OriginalFirstThunk
        put(&mut fake.bytes, 0x2014 + 12, &0x2100u32.to_le_bytes()); // Name
        put(&mut fake.bytes, 0x2014 + 16, &0x3000u32.to_le_bytes()); // FirstThunk: the same
        put(&mut fake.bytes, 0x2028, &[0u8; 20]); // terminator moves along
        put(&mut fake.bytes, 0x174, &60u32.to_le_bytes()); // three descriptor slots
        // Its lookup table names one import and ends.
        put(&mut fake.bytes, 0x2060, &0x2120u64.to_le_bytes());
        put(&mut fake.bytes, 0x2068, &0u64.to_le_bytes());

        let image = read_image(BASE, |at, len| fake.read(at, len)).unwrap();
        let read = read_imports(&image, |at, len| fake.read(at, len), || false);
        assert!(
            matches!(read, Err(PeError::Malformed { .. })),
            "a slot claimed twice is refused rather than resolved to whichever came last: {read:?}"
        );
    }

    /// The **total** is bounded too, which neither of the other two limits does.
    ///
    /// Sixty-four libraries of eight thousand imports each is within both of them and is half a
    /// million owned names and library strings — hundreds of megabytes held before a consumer sees
    /// one, on an image nobody chose to trust. The bound is checked as the table grows rather than
    /// after it, because a limit enforced on a finished list is a limit enforced after the memory
    /// was already spent.
    #[test]
    fn the_total_number_of_imports_is_bounded_as_the_table_grows() {
        // **Three libraries**, each just inside the per-library limit and summing past the total.
        // One library cannot test this: a table long enough to cross the total runs into
        // `MAX_IMPORTS_PER_LIBRARY` first, so the first draft of this fixture was green against a
        // build with no total bound at all -- passing on the neighbouring rule.
        let per_library = MAX_IMPORTS_PER_LIBRARY - 1;
        assert!(
            per_library * 3 > MAX_IMPORTS_TOTAL,
            "the fixture must be able to cross the total without crossing the per-library limit"
        );
        let mut fake = driver_image();
        fake.bytes.resize(0x80000, 0);
        put(&mut fake.bytes, 0xf8 + 56, &0x80000u32.to_le_bytes()); // SizeOfImage
        put(&mut fake.bytes, 0x174, &80u32.to_le_bytes()); // import directory size: four slots
        for library in 0..3usize {
            let descriptor = 0x2000 + library * 20;
            let lookup = 0x10000 + library * 0x20000;
            put(&mut fake.bytes, descriptor, &(lookup as u32).to_le_bytes());
            put(&mut fake.bytes, descriptor + 12, &0x2100u32.to_le_bytes());
            put(
                &mut fake.bytes,
                descriptor + 16,
                &((0x60000 + library * 0x8000) as u32).to_le_bytes(),
            );
            for index in 0..per_library {
                put(
                    &mut fake.bytes,
                    lookup + index * 8,
                    &0x2110u64.to_le_bytes(),
                );
            }
            put(
                &mut fake.bytes,
                lookup + per_library * 8,
                &0u64.to_le_bytes(),
            );
        }
        put(&mut fake.bytes, 0x2000 + 3 * 20, &[0u8; 20]);

        let image = read_image(BASE, |at, len| fake.read(at, len)).unwrap();
        let read = read_imports(&image, |at, len| fake.read(at, len), || false);
        assert!(
            matches!(read, Err(PeError::Malformed { .. })),
            "a table this large is refused rather than built: {read:?}"
        );
    }

    /// The library limit counts libraries, and the terminator is not one.
    ///
    /// An import directory holding `MAX_LIBRARIES` libraries has `MAX_LIBRARIES + 1` descriptors,
    /// the all-zero one that ends the array being a descriptor and not a library. A bound compared
    /// against the raw slot count is therefore off by one against the sentence it enforces, and
    /// refuses the very image the limit was written to permit — reported as malformed, which is
    /// the answer that stops a hazard scan rather than shortening it.
    #[test]
    fn the_library_limit_leaves_room_for_the_descriptor_that_ends_the_array() {
        /// Builds an image whose import directory holds `libraries` real descriptors plus the
        /// terminator, every one of them naming the same library and the same single import.
        fn image_importing(libraries: usize) -> FakeImage {
            let mut fake = driver_image();
            let size = (libraries + 1) * 20;
            put(&mut fake.bytes, 0x170, &0x2000u32.to_le_bytes());
            put(&mut fake.bytes, 0x174, &(size as u32).to_le_bytes());
            for index in 0..libraries {
                let at = 0x2000 + index * 20;
                put(&mut fake.bytes, at, &0x2600u32.to_le_bytes()); // OriginalFirstThunk
                put(&mut fake.bytes, at + 12, &0x2700u32.to_le_bytes()); // Name
                let iat = 0x3000 + (index as u32) * 8;
                put(&mut fake.bytes, at + 16, &iat.to_le_bytes()); // FirstThunk
            }
            // The terminator, and the one lookup table and name every descriptor shares.
            put(&mut fake.bytes, 0x2000 + libraries * 20, &[0u8; 20]);
            put(&mut fake.bytes, 0x2600, &0x2710u64.to_le_bytes());
            put(&mut fake.bytes, 0x2608, &0u64.to_le_bytes());
            put(&mut fake.bytes, 0x2700, b"lib.sys\0");
            put(&mut fake.bytes, 0x2712, b"Func\0");
            fake
        }

        let fake = image_importing(MAX_LIBRARIES);
        let image = read_image(BASE, |at, len| fake.read(at, len)).unwrap();
        let table = read_imports(&image, |at, len| fake.read(at, len), || false)
            .expect("an image with exactly the permitted number of libraries is not malformed");
        assert_eq!(table.imports.len(), MAX_LIBRARIES);

        // One more library is one more than the limit, and is refused as it always was.
        let fake = image_importing(MAX_LIBRARIES + 1);
        let image = read_image(BASE, |at, len| fake.read(at, len)).unwrap();
        assert!(matches!(
            read_imports(&image, |at, len| fake.read(at, len), || false),
            Err(PeError::Malformed { .. })
        ));
    }

    /// An image that declares no data directories has none, and the section table is not one.
    ///
    /// `NumberOfRvaAndSizes` and `SizeOfOptionalHeader` both bound where the directories stop, and
    /// what sits immediately after the optional header is the **section table** — so reading a
    /// directory index unconditionally does not read a zero, it reads a section header. Here the
    /// bytes that would be taken for the import directory are `.text`'s `VirtualSize` and
    /// `VirtualAddress`, which spell a 4 KB directory naming 204 libraries: a perfectly valid
    /// driver reported as malformed. Turn those two fields into a plausible descriptor table
    /// instead and it is reported as importing functions it does not import.
    #[test]
    fn an_image_declaring_no_data_directories_has_none() {
        let mut fake = driver_image();
        // A PE32+ optional header carrying the standard fields and no directories at all: 112
        // bytes, which puts the section table exactly where directory [0] used to be.
        put(&mut fake.bytes, 0xf4, &112u16.to_le_bytes()); // SizeOfOptionalHeader
        put(&mut fake.bytes, 0x164, &0u32.to_le_bytes()); // NumberOfRvaAndSizes
        // The section table moves with it, to 0xe0 + 24 + 112 = 0x168.
        let section = |bytes: &mut Vec<u8>, index: usize, name: &[u8], rva: u32| {
            let at = 0x168 + index * 40;
            put(bytes, at, name);
            put(bytes, at + 8, &0x1000u32.to_le_bytes()); // VirtualSize
            put(bytes, at + 12, &rva.to_le_bytes()); // VirtualAddress
            put(bytes, at + 36, &0x6000_0020u32.to_le_bytes());
        };
        section(&mut fake.bytes, 0, b".text\0\0\0", 0x1000);
        section(&mut fake.bytes, 1, b".rdata\0\0", 0x2000);
        section(&mut fake.bytes, 2, b".data\0\0\0", 0x3000);

        let image = read_image(BASE, |at, len| fake.read(at, len)).unwrap();
        assert_eq!(
            image.import_directory,
            (0, 0),
            "the first section header is not a data directory"
        );
        assert_eq!(image.export_directory, (0, 0));
        assert_eq!(image.sections.len(), 3, "and the sections still read");
        assert_eq!(
            read_imports(&image, |at, len| fake.read(at, len), || false).unwrap(),
            ImportTable::default(),
            "a valid image with no import directory imports nothing, and is not malformed"
        );

        // The two bounds are independent, and this is the case where they disagree: a header
        // declaring sixteen directories in a space with room for none. The count is not the last
        // word — the room is — so the entry is still absent rather than read out of the section
        // table behind it.
        put(&mut fake.bytes, 0x164, &16u32.to_le_bytes());
        let image = read_image(BASE, |at, len| fake.read(at, len)).unwrap();
        assert_eq!(
            image.import_directory,
            (0, 0),
            "a directory the header has no room for is not there, whatever it declares"
        );

        // And a header ending before `NumberOfRvaAndSizes` is not an optional header at all. Read
        // anyway, the count itself would come out of the section table — here the four bytes of
        // `.text`'s name — so this is refused rather than parsed around.
        put(&mut fake.bytes, 0xf4, &108u16.to_le_bytes());
        assert!(
            matches!(
                read_image(BASE, |at, len| fake.read(at, len)),
                Err(PeError::NotAnImage { .. })
            ),
            "an optional header too short to hold its own fields is not one"
        );
    }

    /// Absent is **both** coordinates zero. One without the other is a contradiction, and the
    /// tempting reading of it — "close enough to absent" — is the silent wrong answer: a nonzero
    /// RVA with a zero size hides a real descriptor table, and a hazard scan over the result
    /// reports a driver that imports nothing dangerous because it read nothing at all.
    #[test]
    fn an_import_directory_with_one_coordinate_missing_is_refused() {
        for (rva, size, what) in [
            (0x2000u32, 0u32, "an address with no size"),
            (0, 40, "a size with no address"),
        ] {
            let mut fake = driver_image();
            put(&mut fake.bytes, 0x170, &rva.to_le_bytes());
            put(&mut fake.bytes, 0x174, &size.to_le_bytes());

            let image = read_image(BASE, |at, len| fake.read(at, len)).unwrap();
            let read = read_imports(&image, |at, len| fake.read(at, len), || false);
            assert!(
                matches!(read, Err(PeError::Malformed { .. })),
                "{what} is not an absent directory: {read:?}"
            );
        }
    }

    /// A slot this crate never dereferences is still bounded by the image.
    ///
    /// The import address table is the one address here that is *reported* rather than read, and
    /// that is exactly why the bound is easy to leave off it. It does not help: a caller matching
    /// an indirect call against these slots attributes them to this image, so a `FirstThunk`
    /// running past the end would name a neighbouring module's memory as this driver's import.
    /// The read side cannot catch it, because there is no read.
    #[test]
    fn an_import_slot_past_the_end_of_the_image_is_refused_though_it_is_never_read() {
        let mut fake = driver_image();
        // Eight bytes short of the end: the first slot fits exactly, the second does not.
        put(&mut fake.bytes, 0x2010, &0x3ff8u32.to_le_bytes());
        // And nothing in that range reads, which is what says the refusal came from the bound.
        fake.unreadable.push((BASE + 0x3ff8, BASE + 0x4008));

        let image = read_image(BASE, |at, len| fake.read(at, len)).unwrap();
        assert_eq!(image.size_of_image, 0x4000);
        let read = read_imports(&image, |at, len| fake.read(at, len), || false);
        assert!(
            matches!(read, Err(PeError::Malformed { .. })),
            "a slot past the image must not be handed back as this image's: {read:?}"
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

    /// An import directory that overruns its bound is refused, not truncated.
    ///
    /// Reading the first `MAX_LIBRARIES` and returning `Ok` drops the rest in silence, and a
    /// hazard scan reading that concludes a dangerous import is absent when it is merely past the
    /// cut. Same for a directory whose size runs out before its null descriptor: the libraries
    /// past the end are exactly the ones a truncating read would have lost.
    #[test]
    fn an_import_directory_that_overruns_its_bound_is_refused() {
        // A size claiming far more descriptors than an image plausibly has.
        let mut oversized = driver_image();
        put(&mut oversized.bytes, 0x174, &(20u32 * 4096).to_le_bytes());
        let image = read_image(BASE, |at, len| oversized.read(at, len)).unwrap();
        assert!(
            matches!(
                read_imports(&image, |at, len| oversized.read(at, len), || false),
                Err(PeError::Malformed { .. })
            ),
            "an oversized directory must not read as a short one"
        );

        // A size that stops before the null descriptor: exactly one descriptor, no terminator.
        let mut unterminated = driver_image();
        put(&mut unterminated.bytes, 0x174, &20u32.to_le_bytes());
        let image = read_image(BASE, |at, len| unterminated.read(at, len)).unwrap();
        assert!(
            matches!(
                read_imports(&image, |at, len| unterminated.read(at, len), || false),
                Err(PeError::Malformed { .. })
            ),
            "a directory with no terminator inside its size must not read as complete"
        );
    }

    /// A per-library list that runs out of entries, and a name that runs out of bytes, are both
    /// refused rather than shortened.
    ///
    /// Same rule as the directory bound, one level down, and the same consequence for a hazard
    /// scan: an import list cut at its cap omits every later function in silence, and a name taken
    /// without its terminator becomes a *different* string that a sink list will not match. Either
    /// way the answer is "that API is not imported" and the truncation leaves no trace.
    #[test]
    fn a_list_or_a_name_that_overruns_its_bound_is_refused() {
        // A lookup table with no zero terminator inside the per-library cap. Filled with a valid
        // ordinal entry so every entry decodes and only the missing terminator is at issue.
        let mut endless = driver_image();
        let ordinal = 0x8000_0000_0000_0007u64.to_le_bytes();
        for slot in 0..(MAX_IMPORTS_PER_LIBRARY + 1) {
            put(&mut endless.bytes, 0x2040 + slot * 8, &ordinal);
        }
        let image = read_image(BASE, |at, len| endless.read(at, len)).unwrap();
        assert!(
            matches!(
                read_imports(&image, |at, len| endless.read(at, len), || false),
                Err(PeError::Malformed { .. })
            ),
            "an import list that fills its cap must not read as a complete one"
        );

        // A name with no NUL for the whole bounded read.
        let mut endless_name = driver_image();
        for offset in 0..(MAX_NAME + 8) {
            put(&mut endless_name.bytes, 0x2112 + offset, b"A");
        }
        let image = read_image(BASE, |at, len| endless_name.read(at, len)).unwrap();
        assert!(
            matches!(
                read_imports(&image, |at, len| endless_name.read(at, len), || false),
                Err(PeError::Malformed { .. })
            ),
            "a name with no terminator must not be accepted truncated"
        );
    }

    /// An import table that points outside the image is refused, not answered from a neighbour.
    ///
    /// On a live target the memory just past a driver is *the next module*, which reads perfectly
    /// well — so an RVA past `SizeOfImage` added blindly to the base gives a read that succeeds
    /// and describes something else entirely. The image's "imports" would then be another
    /// module's bytes, with nothing in the answer to say so.
    #[test]
    fn an_import_table_pointing_outside_the_image_is_refused() {
        // The lookup table moved past the end of the image, into what would be the next module.
        let mut outside = driver_image();
        put(&mut outside.bytes, 0x2000, &0x9000u32.to_le_bytes());
        let image = read_image(BASE, |at, len| outside.read(at, len)).unwrap();
        assert_eq!(image.size_of_image, 0x4000);
        assert!(
            matches!(
                read_imports(&image, |at, len| outside.read(at, len), || false),
                Err(PeError::Malformed { .. })
            ),
            "an RVA past the image must not be read from whatever is mapped there"
        );
    }

    /// The table ends at an **all-zero** descriptor, which is five fields and not three.
    ///
    /// A descriptor with a leftover stamp or forwarder chain, and zeroes elsewhere, would end the
    /// table early — dropping every library after it in the silence this module keeps promising
    /// not to.
    #[test]
    fn a_descriptor_is_a_terminator_only_when_every_field_is_zero() {
        let mut stamped = driver_image();
        // The terminator at 0x2014 keeps a nonzero TimeDateStamp, and a second real library
        // follows it, so ending early is visible as a missing import rather than as an error.
        put(&mut stamped.bytes, 0x2014 + 4, &1u32.to_le_bytes());

        let image = read_image(BASE, |at, len| stamped.read(at, len)).unwrap();
        let read = read_imports(&image, |at, len| stamped.read(at, len), || false);
        assert!(
            matches!(read, Err(PeError::Malformed { .. })),
            "a descriptor that is not all-zero must not end the table: {read:?}"
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
        // NumberOfRvaAndSizes moves with them, to 0xf8 + 92 = 0x154; the 64-bit slot is cleared
        // for the same reason the directories below are.
        put(&mut fake.bytes, 0x154, &16u32.to_le_bytes());
        put(&mut fake.bytes, 0x164, &0u32.to_le_bytes());
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
