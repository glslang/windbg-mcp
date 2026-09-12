//! What a `_DEVICE_OBJECT` says about itself: the fields that decide who may open it.
//!
//! `device_object` prints `!devobj`, which is the debugger's own rendering of these. This reads
//! them as values, for the same reason [`crate::sd`] reads a security descriptor as fields: the
//! answer to "can a standard user open this device" is assembled from several of them and a
//! renderer's line breaks are not a good place to assemble it from.
//!
//! Engine-free, over a `read` closure, so it is tested against literal bytes rather than against a
//! machine.
//!
//! # Where the numbers come from
//!
//! Every offset is the **target's own**, resolved from type information by the caller and handed in
//! as a [`Layout`] — nothing here is a constant that a build could move. The two **bit** values are
//! a different question and were settled differently, which is worth stating because the difference
//! is the whole reason one of them is trustworthy:
//!
//! * [`DO_EXCLUSIVE`] is **not** something this crate is entitled to assume. It was read out of
//!   `nt!IoCreateDevice` on 26100 x64, which sets `Flags |= 8` on exactly the branch its
//!   `Exclusive` argument selects — the same routine that writes `Characteristics` at `+0x34` and
//!   `DeviceType` at `+0x48`, which is what corroborates the offsets beside it.
//! * [`FILE_DEVICE_SECURE_OPEN`] is a **published** `wdm.h` constant rather than an internal one,
//!   so it is used as published. The distinction matters: guessing an undocumented bit from the
//!   one that sounds right is how a walk comes to read a sandbox flag as a callback flag.

/// Why a device object could not be read.
///
/// Shaped like [`crate::sd::SdError`] on purpose: a caller assembling the openable gate reads a
/// device object and a security descriptor, and two failures of the same kind should not arrive in
/// two different shapes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DeviceError {
    /// Target memory that would not read. A kernel minidump answers this for every device object
    /// in it, which is the honest answer there rather than a device with no fields.
    Unreadable { at: u64, len: usize },
    /// A layout that does not describe a device object.
    Malformed { reason: &'static str },
}

impl std::fmt::Display for DeviceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable { at, len } => {
                write!(
                    f,
                    "{len} byte(s) of a device object at {at:#x} could not be read"
                )
            }
            Self::Malformed { reason } => write!(f, "{reason}"),
        }
    }
}

/// `FILE_DEVICE_SECURE_OPEN`, from `wdm.h`.
///
/// The one characteristic that changes the answer to the question this module is for. Without it
/// the device's own security descriptor is checked when the device is opened **by name** and not
/// when something is opened *beneath* it, so a driver that parses its own paths can be reached
/// through a relative open by a caller the descriptor would have refused.
pub(crate) const FILE_DEVICE_SECURE_OPEN: u32 = 0x0000_0100;

/// `DO_EXCLUSIVE`, read out of `nt!IoCreateDevice` rather than out of a header this crate does not
/// include. Only one handle to the device may be open at a time.
pub(crate) const DO_EXCLUSIVE: u32 = 0x0000_0008;

/// The most a device object may be, in bytes.
///
/// `_DEVICE_OBJECT` is 0x150 on 26100 x64. This is well above that and far below a read that would
/// be an allocation failure rather than a refusal — the bound a [`Layout`] needs so that a caller's
/// field offsets cannot turn into a request for gigabytes.
const MAX_DEVICE: usize = 4096;

/// Where the fields live, from the target's own type information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Layout {
    /// A pointer's width on this target.
    pub(crate) pointer: usize,
    /// `sizeof(_DEVICE_OBJECT)`, which is how much of it is read in one go.
    pub(crate) size: u32,
    /// `_DEVICE_OBJECT::DeviceType`, `::Characteristics`, `::Flags` and `::DriverObject`.
    pub(crate) device_type: u32,
    pub(crate) characteristics: u32,
    pub(crate) flags: u32,
    pub(crate) driver: u32,
}

impl Layout {
    /// Whether this describes a device object, or merely has the right field names.
    ///
    /// **Checked once, here, rather than defended at each read.** Every field is an index into the
    /// bytes this reads, and `Layout` is the caller's to fill in — so an offset past the end takes
    /// a field from whatever follows, and a size in the gigabytes asks the target for a read that
    /// large. Answering those one at a time, where each is used, is a round of review findings per
    /// field; the lesson is borrowed from `dbgscope`'s namespace walk, which took five of them.
    fn check(&self) -> Result<(), DeviceError> {
        let bad = |reason| Err(DeviceError::Malformed { reason });
        if !matches!(self.pointer, 4 | 8) {
            return bad("a pointer on this target is neither four bytes nor eight");
        }
        if self.size as usize > MAX_DEVICE {
            return bad("a device object is not as large as this says");
        }
        let size = self.size as usize;
        let dwords = [self.device_type, self.characteristics, self.flags];
        if dwords
            .iter()
            .any(|offset| (*offset as usize).saturating_add(4) > size)
        {
            return bad("a field sits outside the device object");
        }
        if (self.driver as usize).saturating_add(self.pointer) > size {
            return bad("the driver pointer sits outside the device object");
        }
        Ok(())
    }
}

/// What one device object says about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Device {
    /// `FILE_DEVICE_*`. Reported as the number it is: nothing else in this server names these, and
    /// a table here would be one more thing to be wrong about a build.
    pub(crate) device_type: u32,
    /// `Characteristics`, whole, with the one bit that changes the answer named beside it.
    pub(crate) characteristics: u32,
    pub(crate) secure_open: bool,
    /// `Flags & DO_EXCLUSIVE`.
    pub(crate) exclusive: bool,
    /// `Flags`, whole.
    pub(crate) flags: u32,
    /// The `_DRIVER_OBJECT` behind it, so a caller can join this to `driver_object`.
    pub(crate) driver: u64,
}

/// Reads a device object's fields.
///
/// `read` serves target memory and answers `None` for an address that will not read, which becomes
/// [`DeviceError::Unreadable`] naming what could not be read rather than a zero parsed as a field.
pub(crate) fn read_device(
    at: u64,
    layout: Layout,
    mut read: impl FnMut(u64, usize) -> Option<Vec<u8>>,
) -> Result<Device, DeviceError> {
    layout.check()?;
    let len = layout.size as usize;
    let bytes = match read(at, len) {
        Some(bytes) if bytes.len() >= len => bytes,
        _ => return Err(DeviceError::Unreadable { at, len }),
    };
    let dword = |offset: u32| -> u32 {
        let at = offset as usize;
        u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap_or_default())
    };
    let characteristics = dword(layout.characteristics);
    let flags = dword(layout.flags);
    let driver = {
        let at = layout.driver as usize;
        match layout.pointer {
            4 => u64::from(u32::from_le_bytes(
                bytes[at..at + 4].try_into().unwrap_or_default(),
            )),
            _ => u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap_or_default()),
        }
    };
    Ok(Device {
        device_type: dword(layout.device_type),
        characteristics,
        secure_open: characteristics & FILE_DEVICE_SECURE_OPEN != 0,
        exclusive: flags & DO_EXCLUSIVE != 0,
        flags,
        driver,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The offsets measured on Windows 26100 x64, written out rather than derived from the builder
    /// that lays the bytes down: a fixture sharing its arithmetic with the code under test agrees
    /// with it about a wrong offset, which is the one thing a layout test cannot afford.
    fn layout() -> Layout {
        Layout {
            pointer: 8,
            size: 0x150,
            device_type: 0x48,
            characteristics: 0x34,
            flags: 0x30,
            driver: 0x08,
        }
    }

    /// A device object as `IoCreateDevice` would have left it.
    fn device(device_type: u32, characteristics: u32, flags: u32, driver: u64) -> Vec<u8> {
        let mut bytes = vec![0u8; 0x150];
        bytes[0x08..0x10].copy_from_slice(&driver.to_le_bytes());
        bytes[0x30..0x34].copy_from_slice(&flags.to_le_bytes());
        bytes[0x34..0x38].copy_from_slice(&characteristics.to_le_bytes());
        bytes[0x48..0x4c].copy_from_slice(&device_type.to_le_bytes());
        bytes
    }

    const AT: u64 = 0xffff_a000_0010_0000;

    fn serving(bytes: Vec<u8>) -> impl FnMut(u64, usize) -> Option<Vec<u8>> {
        move |at, len| (at == AT).then(|| bytes.iter().copied().take(len).collect())
    }

    /// The fields come back as fields, and the two that decide anything are named.
    #[test]
    fn a_device_object_reads_as_the_gate_it_is() {
        let found = read_device(
            AT,
            layout(),
            serving(device(
                0x6d,
                FILE_DEVICE_SECURE_OPEN | 0x1,
                DO_EXCLUSIVE | 0x40,
                0xffff_b000_0000_0000,
            )),
        )
        .expect("the device reads");
        assert_eq!(
            (
                found.device_type,
                found.secure_open,
                found.exclusive,
                found.driver
            ),
            (0x6d, true, true, 0xffff_b000_0000_0000)
        );
        assert_eq!(
            (found.characteristics, found.flags),
            (0x101, 0x48),
            "and both words come back whole, since this names only what it acts on"
        );
    }

    /// **Neither bit is read off the other's word.** `Characteristics` and `Flags` are adjacent
    /// dwords holding unrelated bit sets, and `DO_EXCLUSIVE` (8) and `FILE_DEVICE_SECURE_OPEN`
    /// (0x100) would both be plausible in either — so a field read one dword out reports a device
    /// that may be opened relatively as one that may not, which is the wrong answer about the gate.
    #[test]
    fn the_two_words_are_not_read_off_each_other() {
        let secure_only = read_device(
            AT,
            layout(),
            serving(device(0x6d, FILE_DEVICE_SECURE_OPEN, 0, 0)),
        )
        .expect("the device reads");
        assert_eq!(
            (secure_only.secure_open, secure_only.exclusive),
            (true, false)
        );

        let exclusive_only =
            read_device(AT, layout(), serving(device(0x6d, 0, DO_EXCLUSIVE, 0))).expect("reads");
        assert_eq!(
            (exclusive_only.secure_open, exclusive_only.exclusive),
            (false, true)
        );
    }

    /// Memory that will not read is **unreadable**, naming the address — not a device with every
    /// field zero, which would report a device type nobody has and a gate nothing guards.
    #[test]
    fn a_device_that_will_not_read_says_so_rather_than_reading_as_zero() {
        assert_eq!(
            read_device(AT, layout(), |_, _| None),
            Err(DeviceError::Unreadable { at: AT, len: 0x150 })
        );
        // And a short read is the same answer: half a structure is not a structure.
        assert_eq!(
            read_device(AT, layout(), |_, _| Some(vec![0u8; 0x20])),
            Err(DeviceError::Unreadable { at: AT, len: 0x150 })
        );
    }

    /// A layout that does not describe a device object is refused before anything is read.
    #[test]
    fn a_layout_that_is_not_one_is_refused() {
        let refused = |layout: Layout| match read_device(AT, layout, |_, _| Some(vec![0u8; 0x150]))
        {
            Err(DeviceError::Malformed { reason }) => reason,
            other => panic!("a layout that is not one was accepted: {other:?}"),
        };
        assert_eq!(
            refused(Layout {
                pointer: 2,
                ..layout()
            }),
            "a pointer on this target is neither four bytes nor eight"
        );
        assert_eq!(
            refused(Layout {
                size: u32::MAX,
                ..layout()
            }),
            "a device object is not as large as this says"
        );
        assert_eq!(
            refused(Layout {
                device_type: 0x150,
                ..layout()
            }),
            "a field sits outside the device object"
        );
        assert_eq!(
            refused(Layout {
                driver: 0x14c,
                ..layout()
            }),
            "the driver pointer sits outside the device object"
        );
    }
}
