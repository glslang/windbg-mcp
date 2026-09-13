//! What a driver presents to the rest of the system, read off its `_DRIVER_OBJECT`.
//!
//! `driver_object` prints `!drvobj <name> 7`, which is the debugger's own rendering of these. This
//! reads them as values, for the reason [`crate::device`] reads a device object as fields: the
//! answer to "what can reach this driver" is assembled out of several of them, and a renderer's
//! column widths are a bad place to assemble it from.
//!
//! # What a driver object is the root of
//!
//! Three things hang off it, and every one is a question one of this server's other driver tools
//! already answers about a *part*:
//!
//! * **`MajorFunction[28]`** -- the dispatch table. Index `0x0e` is the IOCTL handler, which is
//!   what `ioctl_map` takes, and until now a caller had to read it out of `!drvobj`'s rendering by
//!   eye.
//! * **`DeviceObject` -> `NextDevice` -> ...** -- every device this driver created, named or not.
//!   Each one's gate is what `device_security` answers about, one device at a time.
//! * **`DriverStart`/`DriverSize`** -- the image, which is what `driver_hazards` scans.
//!
//! So the composite is not a new analysis. It is the three that exist, joined at the one structure
//! that says they are about the same driver, with the joins made from the target's own fields
//! rather than from a caller matching a module name to a device path by hand.
//!
//! # Engine-free
//!
//! Like [`crate::device`], [`crate::sd`], [`crate::pe`] and [`crate::hazards`], everything here
//! takes a `read(addr, len)` closure rather than a `DebugEngine`, so a driver object is tested
//! against literal bytes with no debugger anywhere near it. The worker supplies the one closure
//! that touches DbgEng, and resolves the layout from the target's own type information.
//!
//! # Where the numbers come from
//!
//! Every offset is the **target's own**, handed in as a [`Layout`] -- nothing here is a constant a
//! build could move. The two numbers that are *not* offsets were settled differently, and the
//! difference is worth stating because it is the same split [`crate::device`] makes:
//!
//! * [`IRP_MJ_DEVICE_CONTROL`] is a **published** `wdm.h` constant, used as published. The index
//!   of a major function is part of the driver ABI; a build cannot move it without breaking every
//!   driver ever compiled.
//! * **How many major functions there are** is *not* taken as published, even though `wdm.h` says
//!   `IRP_MJ_MAXIMUM_FUNCTION + 1` and has said 28 for decades. It is derived from the target --
//!   the array runs from its own offset to the end of the structure -- because the cost of being
//!   wrong is reading past the object and reporting whatever follows it as a dispatch routine,
//!   and the target is already telling us. See [`Layout::majors`].

use crate::walk::Halt;

/// Why a driver object could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DriverError {
    /// The target would not serve these bytes. Names what could not be read rather than parsing a
    /// zero as a field -- which on a kernel minidump is the ordinary answer for anything in pool.
    Unreadable { at: u64, len: usize },
    /// The [`Layout`] does not describe a driver object.
    Malformed { reason: &'static str },
}

impl std::fmt::Display for DriverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable { at, len } => {
                write!(f, "{len} bytes at {at:#018x} could not be read")
            }
            Self::Malformed { reason } => write!(f, "{reason}"),
        }
    }
}

/// `IRP_MJ_DEVICE_CONTROL` -- the major function an IOCTL arrives on, and the one `ioctl_map`
/// takes the dispatch routine of.
///
/// Published in `wdm.h` and used as published, for the reason the module docs give: a major
/// function's index is driver ABI. This is the same judgement [`crate::device::FILE_DEVICE_SECURE_OPEN`]
/// records, and the opposite of the one [`crate::device::DO_EXCLUSIVE`] needed.
pub(crate) const IRP_MJ_DEVICE_CONTROL: usize = 0x0e;

/// The largest structure this will ask the target for, so a wrong [`Layout::size`] cannot turn
/// into a read in the gigabytes.
const MAX_DRIVER: usize = 0x1000;

/// The most major functions a dispatch table can hold. `wdm.h` says 28 and has for decades; this
/// is a bound on a number derived from the target, not a second opinion about the ABI.
const MAX_MAJORS: usize = 64;

/// The most bytes an object name is read as. `_UNICODE_STRING::Length` is the driver's own and a
/// malformed one would otherwise be a read of up to 64 KiB.
const MAX_NAME_BYTES: usize = 512;

/// The most devices a chain is followed for.
///
/// A bound rather than a budget: the chain is a linked list in memory the driver writes, so a
/// corrupted or hostile `NextDevice` makes it circular, and a circular list is walked until
/// something stops it. This is that something, beside the visited-set below -- **both**, because
/// they fail on different shapes. The set catches a cycle that closes; the cap catches a chain
/// that never repeats an address because each link points one byte on from the last.
pub(crate) const MAX_DEVICES: usize = 256;

/// Where a `_DRIVER_OBJECT`'s fields live, from the target's own type information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Layout {
    /// A pointer's width on this target.
    pub(crate) pointer: usize,
    /// `sizeof(_DRIVER_OBJECT)`, which is how much of it is read in one go.
    pub(crate) size: u32,
    /// `_DRIVER_OBJECT::DeviceObject` -- the head of the device chain.
    pub(crate) device_object: u32,
    /// `::Flags`.
    pub(crate) flags: u32,
    /// `::DriverStart` and `::DriverSize` -- the image this driver object was built for.
    pub(crate) driver_start: u32,
    pub(crate) driver_size: u32,
    /// `::DriverName`, a `_UNICODE_STRING`.
    pub(crate) driver_name: u32,
    /// `::DriverInit`, `::DriverStartIo`, `::DriverUnload` and `::FastIoDispatch`.
    pub(crate) driver_init: u32,
    pub(crate) driver_start_io: u32,
    pub(crate) driver_unload: u32,
    pub(crate) fast_io: u32,
    /// `::MajorFunction`, the dispatch table's first entry.
    pub(crate) major_function: u32,
    /// `_UNICODE_STRING::Length` and `::Buffer`, for [`Self::driver_name`].
    pub(crate) unicode_length: u32,
    pub(crate) unicode_buffer: u32,
}

impl Layout {
    /// How many major functions the dispatch table holds on **this** target.
    ///
    /// Derived rather than published, which the module docs give the reason for: the array is the
    /// last member of the structure, so it runs from its own offset to the end. A build that grew
    /// the table would be read correctly here and would be read past the end of by a constant.
    fn majors(&self) -> usize {
        (self.size as usize)
            .saturating_sub(self.major_function as usize)
            .checked_div(self.pointer)
            .unwrap_or_default()
    }

    /// Whether this describes a driver object, or merely has the right field names.
    ///
    /// **Checked once, here, rather than defended at each read** -- the rule
    /// [`crate::device::Layout::check`] states and borrows from dbgscope's namespace walk, which
    /// took five review rounds learning it one field at a time. Every offset below is an index
    /// into the bytes this reads, and `Layout` is the caller's to fill in.
    fn check(&self) -> Result<(), DriverError> {
        let bad = |reason| Err(DriverError::Malformed { reason });
        if !matches!(self.pointer, 4 | 8) {
            return bad("a pointer on this target is neither four bytes nor eight");
        }
        if self.size as usize > MAX_DRIVER {
            return bad("a driver object is not as large as this says");
        }
        let size = self.size as usize;
        let dwords = [self.flags, self.driver_size];
        if dwords
            .iter()
            .any(|offset| (*offset as usize).saturating_add(4) > size)
        {
            return bad("a field sits outside the driver object");
        }
        let pointers = [
            self.device_object,
            self.driver_start,
            self.driver_init,
            self.driver_start_io,
            self.driver_unload,
            self.fast_io,
        ];
        if pointers
            .iter()
            .any(|offset| (*offset as usize).saturating_add(self.pointer) > size)
        {
            return bad("a pointer field sits outside the driver object");
        }
        // A `_UNICODE_STRING` is read out of the same bytes: its length, then its buffer pointer.
        let name = self.driver_name as usize;
        let length = name.saturating_add(self.unicode_length as usize);
        let buffer = name.saturating_add(self.unicode_buffer as usize);
        if length.saturating_add(2) > size || buffer.saturating_add(self.pointer) > size {
            return bad("the driver name sits outside the driver object");
        }
        // **The dispatch table has to be inside the object and has to have entries.** A zero here
        // is the shape that matters: `majors()` divides the space left by a pointer, so an offset
        // at or past the end gives an empty table, and an empty table reports a driver that
        // handles no IRP at all -- which is a fact-shaped answer to a question that was not asked.
        let majors = self.majors();
        if majors == 0 {
            return bad("the dispatch table sits at or past the end of the driver object");
        }
        if majors > MAX_MAJORS {
            return bad("a dispatch table does not hold as many major functions as this says");
        }
        Ok(())
    }
}

/// What one driver object says about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Driver {
    /// `DriverName` -- `\Driver\mountmgr`. `None` where the field is empty or its buffer would not
    /// read, which is **not** the same as a driver with no name and is reported as neither.
    pub(crate) name: Option<String>,
    /// `DriverStart` and `DriverSize`: the image this driver object was built for.
    ///
    /// The join to [`crate::hazards`] and to the module inventory. It is the driver object's own
    /// answer about which image is its, rather than a name matched by hand.
    pub(crate) image_base: u64,
    pub(crate) image_size: u32,
    /// `Flags`, whole.
    pub(crate) flags: u32,
    /// `DriverInit`, `DriverStartIo`, `DriverUnload` and `FastIoDispatch`. Zero where absent,
    /// which for `DriverUnload` is the ordinary state of a driver that cannot be unloaded.
    pub(crate) init: u64,
    pub(crate) start_io: u64,
    pub(crate) unload: u64,
    pub(crate) fast_io: u64,
    /// The head of the device chain, or zero for a driver that created none.
    pub(crate) device_object: u64,
    /// `MajorFunction`, whole and in order, so index `0x0e` is the IOCTL handler.
    pub(crate) major_function: Vec<u64>,
}

impl Driver {
    /// The IOCTL dispatch routine, which is what `ioctl_map` takes.
    ///
    /// `None` for a table too short to hold the index, which [`Layout::check`] makes unreachable
    /// on a real target and which is still answered rather than indexed blindly: the bound and the
    /// read are in different functions, and a panic here would be a whole session.
    pub(crate) fn device_control(&self) -> Option<u64> {
        self.major_function.get(IRP_MJ_DEVICE_CONTROL).copied()
    }

    /// Whether an address is inside this driver's own image.
    ///
    /// What it is for is telling a driver's own dispatch routine from the kernel's stub and from
    /// another driver's: a `MajorFunction` entry pointing outside the image is either
    /// `nt!IopInvalidDeviceRequest` or a filter forwarding into the driver below it, and neither
    /// is code this driver's image can be scanned for.
    ///
    /// **Answers `false` for a driver object whose image extent did not read**, rather than
    /// treating a zero base as an image starting at zero -- which would put every kernel address
    /// outside it and every null pointer inside.
    pub(crate) fn owns(&self, address: u64) -> bool {
        self.image_base != 0
            && self.image_size != 0
            && address >= self.image_base
            && address < self.image_base.saturating_add(u64::from(self.image_size))
    }
}

/// Reads a driver object's fields.
///
/// `read` serves target memory and answers `None` for an address that will not read, which becomes
/// [`DriverError::Unreadable`] naming what could not be read.
///
/// **The name's buffer is the one read allowed to fail quietly.** It is in pool, at an address the
/// object itself supplies, and a driver object whose every other field read is worth reporting
/// with its name missing -- the alternative is refusing to describe a driver because its name is
/// paged out.
pub(crate) fn read_driver(
    at: u64,
    layout: Layout,
    mut read: impl FnMut(u64, usize) -> Option<Vec<u8>>,
) -> Result<Driver, DriverError> {
    layout.check()?;
    let len = layout.size as usize;
    let bytes = match read(at, len) {
        Some(bytes) if bytes.len() >= len => bytes,
        _ => return Err(DriverError::Unreadable { at, len }),
    };
    let word = |offset: u32| -> u16 {
        let at = offset as usize;
        u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap_or_default())
    };
    let dword = |offset: u32| -> u32 {
        let at = offset as usize;
        u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap_or_default())
    };
    let pointer = |offset: u32| -> u64 {
        let at = offset as usize;
        match layout.pointer {
            4 => u64::from(u32::from_le_bytes(
                bytes[at..at + 4].try_into().unwrap_or_default(),
            )),
            _ => u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap_or_default()),
        }
    };

    // The dispatch table, whole. Bounded by `check`, which put `majors()` inside the object and
    // under `MAX_MAJORS` before any of this indexed anything.
    let majors = layout.majors();
    let major_function = (0..majors)
        .map(|index| {
            let offset = layout.major_function as usize + index * layout.pointer;
            match layout.pointer {
                4 => u64::from(u32::from_le_bytes(
                    bytes[offset..offset + 4].try_into().unwrap_or_default(),
                )),
                _ => u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap_or_default()),
            }
        })
        .collect();

    // The name, out of the `_UNICODE_STRING` already read, with its buffer fetched from pool.
    let length = usize::from(word(layout.driver_name + layout.unicode_length));
    let buffer = pointer(layout.driver_name + layout.unicode_buffer);
    let name = match (length, buffer) {
        (0, _) | (_, 0) => None,
        (length, buffer) => {
            // **Clamped rather than refused.** `Length` is the driver object's own number, so a
            // corrupted one asks for a read of up to 64 KiB; taking the first `MAX_NAME_BYTES` of
            // a name that claims to be longer is the same answer a shorter name would give, and
            // refusing would lose every other field of a driver over its name.
            let length = length.min(MAX_NAME_BYTES);
            read(buffer, length)
                .filter(|raw| raw.len() >= length)
                .map(|raw| utf16(&raw[..length]))
        }
    };

    Ok(Driver {
        name,
        image_base: pointer(layout.driver_start),
        image_size: dword(layout.driver_size),
        flags: dword(layout.flags),
        init: pointer(layout.driver_init),
        start_io: pointer(layout.driver_start_io),
        unload: pointer(layout.driver_unload),
        fast_io: pointer(layout.fast_io),
        device_object: pointer(layout.device_object),
        major_function,
    })
}

/// UTF-16LE as the target holds it, rendered with replacements rather than refused.
///
/// A kernel object name is a counted run of UTF-16 units, so an unpaired surrogate is a legal name
/// and illegal text. dbgscope's namespace makes the same choice and says why: a name that cannot
/// be reproduced exactly is still worth showing, as long as nothing treats the rendering as an
/// identity. Nothing here does -- a driver is addressed by its object address, never by this.
fn utf16(raw: &[u8]) -> String {
    let units: Vec<u16> = raw
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();
    String::from_utf16_lossy(&units)
}

/// Every device on a driver's chain, in the order the driver object holds them.
///
/// The walk is `DeviceObject` then `NextDevice` until the chain ends, and **an unreadable device
/// ends it** -- which is the one thing here that is a judgement rather than a mechanism. A device
/// that will not read has no `NextDevice` to follow, so there is nothing to carry on from; what
/// this does is report how far it got rather than how far it claimed to get. The caller learns the
/// chain was cut short from [`Chain::stopped`], never from a count that silently got smaller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Chain {
    /// The device object addresses, head first.
    pub(crate) devices: Vec<u64>,
    /// Why the walk stopped before the chain ended, when it did.
    pub(crate) stopped: Option<ChainHalt>,
}

/// Why a device chain was not followed to its end.
///
/// **Four reasons rather than a flag**, because they send a reader somewhere different: two are
/// about this call, one is about the target's memory, and one says the chain is not a chain. A
/// single "incomplete" would put a corrupted list and a busy debugger in the same bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChainHalt {
    /// The caller's clock ran out, or the call was interrupted.
    Walk(Halt),
    /// A device on the chain would not read, so nothing could be followed from it.
    Unreadable,
    /// The chain came back to a device already visited: it is a ring, not a list.
    Cycle,
    /// [`MAX_DEVICES`] links were followed and the chain had not ended.
    Capped,
}

/// Follows a driver's device chain.
///
/// `next_of` reads one device and answers its `NextDevice`, or `None` where the device would not
/// read. `halt` is polled **per device**, not once before the walk: a chain of two hundred devices
/// over a kernel debugging wire is hundreds of reads, and a bounded loop still needs a check
/// inside it.
pub(crate) fn device_chain(
    head: u64,
    mut next_of: impl FnMut(u64) -> Option<u64>,
    halt: impl Fn() -> Option<Halt>,
) -> Chain {
    let mut devices = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut at = head;
    let mut stopped = None;
    while at != 0 {
        if let Some(why) = halt() {
            stopped = Some(ChainHalt::Walk(why));
            break;
        }
        if devices.len() >= MAX_DEVICES {
            stopped = Some(ChainHalt::Capped);
            break;
        }
        // **Recorded before it is followed**, so a device that will not read is still reported as
        // being on the chain. It is a device this driver created; what is missing is what it says
        // about itself, and dropping it would report a shorter chain rather than a hole in one.
        if !seen.insert(at) {
            stopped = Some(ChainHalt::Cycle);
            break;
        }
        devices.push(at);
        match next_of(at) {
            Some(next) => at = next,
            None => {
                stopped = Some(ChainHalt::Unreadable);
                break;
            }
        }
    }
    Chain { devices, stopped }
}

/// The major functions, as `wdm.h` names them, index `0x00` through `IRP_MJ_MAXIMUM_FUNCTION`.
///
/// **Published and used as published**, the judgement [`IRP_MJ_DEVICE_CONTROL`] records. These are
/// labels for a reader, never something this indexes *by*: how many entries a table has is read
/// off the target, and a table longer than this list is reported with the extra entries numbered
/// rather than dropped. The two cannot fall out of step and hide it, because the length that
/// matters comes from somewhere else entirely.
const MAJOR_NAMES: [&str; 28] = [
    "IRP_MJ_CREATE",
    "IRP_MJ_CREATE_NAMED_PIPE",
    "IRP_MJ_CLOSE",
    "IRP_MJ_READ",
    "IRP_MJ_WRITE",
    "IRP_MJ_QUERY_INFORMATION",
    "IRP_MJ_SET_INFORMATION",
    "IRP_MJ_QUERY_EA",
    "IRP_MJ_SET_EA",
    "IRP_MJ_FLUSH_BUFFERS",
    "IRP_MJ_QUERY_VOLUME_INFORMATION",
    "IRP_MJ_SET_VOLUME_INFORMATION",
    "IRP_MJ_DIRECTORY_CONTROL",
    "IRP_MJ_FILE_SYSTEM_CONTROL",
    "IRP_MJ_DEVICE_CONTROL",
    "IRP_MJ_INTERNAL_DEVICE_CONTROL",
    "IRP_MJ_SHUTDOWN",
    "IRP_MJ_LOCK_CONTROL",
    "IRP_MJ_CLEANUP",
    "IRP_MJ_CREATE_MAILSLOT",
    "IRP_MJ_QUERY_SECURITY",
    "IRP_MJ_SET_SECURITY",
    "IRP_MJ_POWER",
    "IRP_MJ_SYSTEM_CONTROL",
    "IRP_MJ_DEVICE_CHANGE",
    "IRP_MJ_QUERY_QUOTA",
    "IRP_MJ_SET_QUOTA",
    "IRP_MJ_PNP",
];

/// One major function as `0x0e IRP_MJ_DEVICE_CONTROL`.
///
/// An index past [`MAJOR_NAMES`] is numbered and **not** named, rather than being dropped or
/// given a neighbour's name: a build with a longer table is a thing to notice, and a made-up label
/// on the entry that would say so is the one answer worse than no label.
fn major_label(index: usize) -> String {
    match MAJOR_NAMES.get(index) {
        Some(name) => format!("{index:#04x} {name}"),
        None => format!("{index:#04x}"),
    }
}

/// The dispatch table as a report, grouped by the routine each major function reaches.
///
/// `locate` turns an address into a coordinate; in the worker it is the module attributor, and in
/// a test it is whatever the test wants, which is what keeps this engine-free.
///
/// **Every entry is accounted for, including the null ones.** The I/O manager fills an unhandled
/// major with its own stub rather than leaving it empty, so a null entry is a driver object that
/// has been written to -- exactly the thing not to quietly drop.
pub(crate) fn dispatch_section(
    driver: &Driver,
    mut locate: impl FnMut(u64) -> crate::structured::CodeLocation,
) -> crate::structured::DispatchSection {
    // Grouped in the order each handler is **first** reached, so the table reads top-down the way
    // the driver object holds it. A map keyed by address would order by hash, which for a report
    // whose whole value is its shape is no order at all.
    let mut groups: Vec<(u64, Vec<usize>)> = Vec::new();
    for (index, &handler) in driver.major_function.iter().enumerate() {
        match groups.iter_mut().find(|(at, _)| *at == handler) {
            Some((_, majors)) => majors.push(index),
            None => groups.push((handler, vec![index])),
        }
    }
    let handlers = groups
        .into_iter()
        .map(|(at, majors)| crate::structured::DispatchHandler {
            location: locate(at),
            majors: majors.into_iter().map(major_label).collect(),
            owned: driver.owns(at),
        })
        .collect();
    crate::structured::DispatchSection {
        // The table is read as part of the driver object, so having one at all means it read.
        status: crate::structured::SectionStatus::Ok,
        note: None,
        handlers,
        major_count: driver.major_function.len(),
        // **Absent for a null entry rather than a coordinate at zero.** `device_control` is what a
        // caller feeds to `ioctl_map`, and an address of zero is not something to feed anything.
        device_control: driver
            .device_control()
            .filter(|at| *at != 0)
            .map(&mut locate),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The 26100 x64 layout, measured 2026-09-13 from the target's own type information on
    /// `docs/samples/081226-2187-01.dmp` (`dt nt!_DRIVER_OBJECT`).
    ///
    /// **Literal offsets here and derived offsets in production**, which is the split
    /// `a-fixture-cannot-pin-its-own-table` exists for: a fixture that computed its offsets the
    /// way the reader does would agree with the reader about a layout neither had right.
    fn layout() -> Layout {
        Layout {
            pointer: 8,
            size: 0x150,
            device_object: 0x08,
            flags: 0x10,
            driver_start: 0x18,
            driver_size: 0x20,
            driver_name: 0x38,
            driver_init: 0x58,
            driver_start_io: 0x60,
            driver_unload: 0x68,
            fast_io: 0x50,
            major_function: 0x70,
            unicode_length: 0x00,
            unicode_buffer: 0x08,
        }
    }

    /// A driver object as bytes, built the way the kernel lays one out rather than the way the
    /// reader takes one apart.
    fn driver_object(device_object: u64, image_base: u64, image_size: u32) -> Vec<u8> {
        let mut bytes = vec![0u8; 0x150];
        let mut put = |at: usize, value: &[u8]| bytes[at..at + value.len()].copy_from_slice(value);
        put(0x00, &4i16.to_le_bytes()); // Type: IO_TYPE_DRIVER
        put(0x02, &0x150i16.to_le_bytes()); // Size
        put(0x08, &device_object.to_le_bytes());
        put(0x18, &image_base.to_le_bytes());
        put(0x20, &image_size.to_le_bytes());
        bytes
    }

    #[test]
    fn a_driver_objects_fields_are_read_where_the_target_says_they_are() {
        let bytes = driver_object(0xffff_8000_0011_0000, 0xffff_f805_5ebf_0000, 0x1_0000);
        let driver = read_driver(0x1000, layout(), |at, len| {
            (at == 0x1000).then(|| bytes[..len].to_vec())
        })
        .expect("a driver object");

        assert_eq!(driver.device_object, 0xffff_8000_0011_0000);
        assert_eq!(driver.image_base, 0xffff_f805_5ebf_0000);
        assert_eq!(driver.image_size, 0x1_0000);
        // 0x150 - 0x70 = 0xe0, over eight: the ABI's 28, derived rather than asserted.
        assert_eq!(driver.major_function.len(), 28);
    }

    /// The dispatch table is read at the index the ABI fixes, and the index is **not** the one the
    /// reader happens to use.
    #[test]
    fn the_ioctl_handler_is_the_twenty_eighth_tables_fourteenth_entry() {
        let mut bytes = driver_object(0, 0xffff_f805_5ebf_0000, 0x1_0000);
        // Every entry distinct, so an off-by-one reads as a wrong value rather than as a pass.
        for index in 0..28usize {
            let at = 0x70 + index * 8;
            let value = 0xffff_f805_5ebf_1000 + index as u64 * 0x10;
            bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }
        let driver = read_driver(0x1000, layout(), |at, len| {
            (at == 0x1000).then(|| bytes[..len].to_vec())
        })
        .expect("a driver object");

        assert_eq!(
            driver.device_control(),
            Some(0xffff_f805_5ebf_1000 + 0x0e * 0x10),
            "IRP_MJ_DEVICE_CONTROL is index 0x0e of the table"
        );
        assert!(driver.owns(driver.device_control().unwrap()));
    }

    /// A driver whose image extent did not read owns nothing, rather than owning everything below
    /// its size.
    ///
    /// **The half-read case is the one that matters, and the first version of this test missed
    /// it.** That version used a base *and* a size of zero, where the empty range excludes every
    /// address on its own -- so it passed with the `image_base != 0` guard deleted, which is
    /// `a-test-can-pass-on-a-neighbouring-rule` exactly. What the guard is for is a driver object
    /// whose `DriverStart` would not read and whose `DriverSize` would: an image based at zero
    /// then claims every address below its size, and a kernel address is not what that catches --
    /// a *low* one is.
    ///
    /// The `image_size != 0` guard beside it is **redundant** with the strict upper bound, since
    /// an empty range contains nothing. It is kept because the pair states the intent in one
    /// place, and noted here so that nobody deleting the duplication takes the base guard with it.
    #[test]
    fn a_driver_with_no_image_extent_claims_no_address() {
        let read = |bytes: Vec<u8>| {
            move |at: u64, len: usize| (at == 0x1000).then(|| bytes[..len].to_vec())
        };
        let extentless = |base: u64, size: u32| {
            read_driver(0x1000, layout(), read(driver_object(0, base, size)))
                .expect("a driver object")
        };

        // The base did not read and the size did: the case the guard exists for.
        let half = extentless(0, 0x1_0000);
        assert!(
            !half.owns(0x100),
            "an image based at zero must not claim the addresses below its size"
        );

        // Neither read: an empty range, which the bound excludes on its own.
        assert!(!extentless(0, 0).owns(0));

        // And a real extent still answers both ways, so the guards did not simply refuse
        // everything -- without this the three assertions above are satisfied by `owns` returning
        // false unconditionally.
        let real = extentless(0xffff_f805_5ebf_0000, 0x1_0000);
        assert!(real.owns(0xffff_f805_5ebf_0000), "the base is inside");
        assert!(real.owns(0xffff_f805_5ebf_ffff), "the last byte is inside");
        assert!(
            !real.owns(0xffff_f805_5ec0_0000),
            "one past the end is outside"
        );
    }

    #[test]
    fn a_name_is_read_from_the_pool_buffer_the_object_points_at() {
        let mut bytes = driver_object(0, 0, 0);
        let name: Vec<u16> = "\\Driver\\mountmgr".encode_utf16().collect();
        let raw: Vec<u8> = name.iter().flat_map(|unit| unit.to_le_bytes()).collect();
        bytes[0x38..0x3a].copy_from_slice(&(raw.len() as u16).to_le_bytes());
        bytes[0x40..0x48].copy_from_slice(&0x2000u64.to_le_bytes());

        let driver = read_driver(0x1000, layout(), |at, len| match at {
            0x1000 => Some(bytes[..len].to_vec()),
            0x2000 => Some(raw[..len.min(raw.len())].to_vec()),
            _ => None,
        })
        .expect("a driver object");

        assert_eq!(driver.name.as_deref(), Some("\\Driver\\mountmgr"));
    }

    /// **A name that will not read loses the name and nothing else.** The buffer is in pool, which
    /// on a dump is the ordinary thing to be missing, and refusing the whole driver over it would
    /// throw away a dispatch table that read perfectly.
    #[test]
    fn a_driver_whose_name_is_paged_out_is_still_a_driver() {
        let mut bytes = driver_object(0, 0xffff_f805_5ebf_0000, 0x1_0000);
        bytes[0x38..0x3a].copy_from_slice(&32u16.to_le_bytes());
        bytes[0x40..0x48].copy_from_slice(&0x2000u64.to_le_bytes());

        let driver = read_driver(0x1000, layout(), |at, len| {
            (at == 0x1000).then(|| bytes[..len].to_vec())
        })
        .expect("a driver object whose name would not read");

        assert_eq!(driver.name, None);
        assert_eq!(driver.image_base, 0xffff_f805_5ebf_0000);
    }

    /// A `Length` larger than any real name is clamped, not refused and not read in full.
    #[test]
    fn an_absurd_name_length_is_clamped_to_what_a_name_can_be() {
        let mut bytes = driver_object(0, 0, 0);
        bytes[0x38..0x3a].copy_from_slice(&u16::MAX.to_le_bytes());
        bytes[0x40..0x48].copy_from_slice(&0x2000u64.to_le_bytes());
        let mut asked = 0usize;

        let driver = read_driver(0x1000, layout(), |at, len| match at {
            0x1000 => Some(bytes[..len].to_vec()),
            0x2000 => {
                asked = len;
                Some([0x41, 0x00].repeat(len / 2))
            }
            _ => None,
        })
        .expect("a driver object");

        assert_eq!(asked, MAX_NAME_BYTES, "the read is bounded, not the name");
        assert_eq!(driver.name.map(|name| name.len()), Some(MAX_NAME_BYTES / 2));
    }

    /// The whole of [`Layout::check`]'s job: a layout that does not describe a driver object is
    /// refused **before** any of its offsets indexes anything.
    #[test]
    fn a_layout_that_is_not_a_driver_object_is_refused_before_it_is_used() {
        /// A named layout fault and the edit that introduces it.
        type Fault = (&'static str, fn(&mut Layout));
        let cases: &[Fault] = &[
            ("a pointer width nothing has", |l| l.pointer = 3),
            ("a size no object has", |l| l.size = 0x9000),
            ("a field past the end", |l| l.flags = 0x14e),
            ("a pointer past the end", |l| l.device_object = 0x14c),
            ("a name past the end", |l| l.driver_name = 0x14c),
            ("a table at the end", |l| l.major_function = 0x150),
            ("a table past the end", |l| l.major_function = 0x200),
        ];
        for (what, break_it) in cases {
            let mut broken = layout();
            break_it(&mut broken);
            let mut touched = false;
            let result = read_driver(0x1000, broken, |_, _| {
                touched = true;
                None
            });
            assert!(
                matches!(result, Err(DriverError::Malformed { .. })),
                "{what} should be refused: {result:?}"
            );
            assert!(!touched, "{what} was refused only after a read was issued");
        }
    }

    /// A dispatch table that would be **empty** is refused rather than reported.
    ///
    /// Its own case rather than one of the row above, because it is the one bad layout that reads
    /// successfully: `majors()` is a saturating subtraction, so an offset at the end of the object
    /// yields zero entries and a driver that handles no IRP at all -- an answer, shaped exactly
    /// like a real finding about a driver with no dispatch routines.
    #[test]
    fn a_dispatch_table_with_no_entries_is_not_a_driver_that_handles_nothing() {
        let mut empty = layout();
        empty.major_function = 0x150;
        let result = read_driver(0x1000, empty, |_, _| Some(vec![0u8; 0x150]));
        assert!(
            matches!(result, Err(DriverError::Malformed { .. })),
            "{result:?}"
        );
    }

    #[test]
    fn an_unreadable_driver_object_names_what_could_not_be_read() {
        let result = read_driver(0xdead_0000, layout(), |_, _| None);
        assert_eq!(
            result,
            Err(DriverError::Unreadable {
                at: 0xdead_0000,
                len: 0x150
            })
        );
    }

    /// A short read is an unreadable object, not a structure padded with zeros.
    #[test]
    fn a_short_read_is_not_a_driver_object_with_zeros_on_the_end() {
        let result = read_driver(0x1000, layout(), |_, _| Some(vec![0u8; 0x100]));
        assert!(matches!(result, Err(DriverError::Unreadable { .. })));
    }

    // ---- the device chain -------------------------------------------------

    fn chain_of(links: &[(u64, Option<u64>)]) -> impl FnMut(u64) -> Option<u64> + '_ {
        move |at| {
            links
                .iter()
                .find(|(device, _)| *device == at)
                .and_then(|(_, next)| *next)
        }
    }

    #[test]
    fn a_device_chain_is_followed_to_its_end() {
        let links = [(0x100, Some(0x200)), (0x200, Some(0x300)), (0x300, Some(0))];
        let chain = device_chain(0x100, chain_of(&links), || None);
        assert_eq!(chain.devices, vec![0x100, 0x200, 0x300]);
        assert_eq!(chain.stopped, None);
    }

    #[test]
    fn a_driver_with_no_devices_has_an_empty_chain_rather_than_a_halt() {
        let chain = device_chain(0, |_| None, || None);
        assert!(chain.devices.is_empty());
        assert_eq!(chain.stopped, None, "no devices is an answer, not a stop");
    }

    /// **A ring is reported as a ring**, and the device that closes it is not listed twice.
    #[test]
    fn a_circular_chain_stops_rather_than_running_for_ever() {
        let links = [(0x100, Some(0x200)), (0x200, Some(0x100))];
        let chain = device_chain(0x100, chain_of(&links), || None);
        assert_eq!(chain.devices, vec![0x100, 0x200]);
        assert_eq!(chain.stopped, Some(ChainHalt::Cycle));
    }

    /// The cap and the visited-set catch **different** shapes, which is why there are two.
    ///
    /// A chain whose every link is a fresh address never repeats, so the set never fires; without
    /// the cap this walk would follow it until the target ran out of addresses.
    #[test]
    fn a_chain_that_never_repeats_an_address_is_still_bounded() {
        let chain = device_chain(0x1000, |at| Some(at + 0x100), || None);
        assert_eq!(chain.devices.len(), MAX_DEVICES);
        assert_eq!(chain.stopped, Some(ChainHalt::Capped));
    }

    /// An unreadable device is **on** the chain and ends it: the device exists, and what it says
    /// about itself is what is missing.
    #[test]
    fn an_unreadable_device_is_a_link_that_was_seen_and_not_followed() {
        let links = [(0x100, Some(0x200))];
        let chain = device_chain(0x100, chain_of(&links), || None);
        assert_eq!(chain.devices, vec![0x100, 0x200]);
        assert_eq!(chain.stopped, Some(ChainHalt::Unreadable));
    }

    /// The clock is polled **per device**, so a long chain is interruptible partway rather than
    /// only before it starts.
    #[test]
    fn a_chain_is_halted_between_devices_and_not_only_before_the_first() {
        let seen = std::cell::Cell::new(0usize);
        let chain = device_chain(
            0x1000,
            |at| Some(at + 0x100),
            || {
                seen.set(seen.get() + 1);
                (seen.get() > 3).then_some(Halt::Deadline)
            },
        );
        assert_eq!(chain.devices, vec![0x1000, 0x1100, 0x1200]);
        assert_eq!(chain.stopped, Some(ChainHalt::Walk(Halt::Deadline)));
    }
}
