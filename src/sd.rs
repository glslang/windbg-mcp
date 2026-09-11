//! Who may open a device, read out of the security descriptor rather than out of an extension.
//!
//! `!sd` is **not** in the bundled engine, so the walkthroughs decode a device's DACL by hand:
//! `dt nt!_SECURITY_DESCRIPTOR_RELATIVE`, then `dt nt!_ACL`, then `db … L5c` and a person reading
//! the ACEs (`docs/driver-ioctl-walkthrough.md`). This is those three steps as fields.
//!
//! # What an answer here is, and is not
//!
//! It is the descriptor the object **holds**: principals, the access each is granted or denied,
//! and the order the kernel evaluates them in. It is not an answer about a particular caller —
//! that depends on their token's groups, its integrity level, privileges like
//! `SeTakeOwnershipPrivilege`, and on `FILE_DEVICE_SECURE_OPEN` and the namespace rules for a name
//! *under* the device. What this says is what the object grants; who arrives holding what is a
//! different question and needs a token.
//!
//! # Engine-free
//!
//! Like [`crate::pe`], [`crate::ioctl`], [`crate::hazards`] and [`crate::driver`], the entry point
//! takes a `read(addr, len)` closure rather than a `DebugEngine`, so every structure below is
//! tested against literal bytes with no debugger anywhere near it. The layouts are pinned with
//! **byte fixtures**, never with the constants the parser also reads.

use std::fmt::Write as _;

/// Why a descriptor could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SdError {
    /// Bytes that would not read — the ordinary answer on a dump that captured no pool.
    Unreadable { at: u64, len: usize },
    /// A structure that does not hold together, naming what did not.
    Malformed { reason: &'static str },
}

impl std::fmt::Display for SdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable { at, len } => {
                write!(f, "{len} byte(s) at {at:#x} could not be read")
            }
            Self::Malformed { reason } => write!(f, "{reason}"),
        }
    }
}

/// Bounds. A descriptor in target memory is data this server did not write, so every list it
/// produces is capped and every cap is a refusal rather than a truncation: a DACL reported shorter
/// than it is answers "who may open this" wrongly, which is the one thing this must not do.
const MAX_ACES: usize = 1024;
/// The most an ACL may claim to be, which is its `AclSize` field. A real device's is a few hundred
/// bytes; `USHRT_MAX` is the structural limit and this is far below it and far above them.
const MAX_ACL_BYTES: usize = 64 * 1024;
/// A SID's own limit: `SID_MAX_SUB_AUTHORITIES`, which is the structure's, not a choice.
const MAX_SUBAUTHORITIES: usize = 15;

/// `SECURITY_DESCRIPTOR_RELATIVE`'s control bits, the three that change what the rest means.
const SE_DACL_PRESENT: u16 = 0x0004;
const SE_SACL_PRESENT: u16 = 0x0010;
const SE_SELF_RELATIVE: u16 = 0x8000;

/// A security identifier, as the bits say and as a person reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Sid {
    /// `S-1-5-32-544`.
    pub(crate) text: String,
    /// The name Windows would show for a well-known SID — `Everyone`, `SYSTEM`. `None` for one
    /// this does not know, which is most of them: a machine or domain SID names an account this
    /// has no way to look up, and inventing a name for it would be worse than leaving it as the
    /// number it is.
    pub(crate) name: Option<&'static str>,
}

impl std::fmt::Display for Sid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.name {
            Some(name) => write!(f, "{name} ({})", self.text),
            None => f.write_str(&self.text),
        }
    }
}

/// What an ACE does when it matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AceKind {
    /// Grants the mask.
    Allow,
    /// Denies the mask. **Order matters**: the kernel walks the ACEs in order and stops when the
    /// requested access is fully granted or any of it is denied, so a deny after an allow may
    /// never be reached.
    Deny,
    /// Audits rather than deciding — a SACL entry.
    Audit,
    /// A type this does not decode past its header. Reported rather than skipped: an ACE nobody
    /// read is a principal nobody saw.
    Other(u8),
}

impl AceKind {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Audit => "audit",
            Self::Other(_) => "other",
        }
    }
}

/// One access control entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ace {
    pub(crate) kind: AceKind,
    /// The raw `AceType` byte, for a type this does not name.
    pub(crate) ace_type: u8,
    /// `AceFlags` — inheritance and audit bits, as encoded.
    pub(crate) flags: u8,
    /// The access mask, as encoded.
    pub(crate) mask: u32,
    /// The principal, when the ACE carries one where this can find it. An object ACE puts GUIDs
    /// before its SID, and a type this does not decode has one it cannot place.
    pub(crate) sid: Option<Sid>,
}

/// An access control list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Acl {
    pub(crate) revision: u8,
    /// What the header says it holds, which is the count this walked toward.
    pub(crate) ace_count: usize,
    pub(crate) aces: Vec<Ace>,
}

/// A security descriptor, as much of it as is there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Descriptor {
    pub(crate) revision: u8,
    pub(crate) control: u16,
    pub(crate) owner: Option<Sid>,
    pub(crate) group: Option<Sid>,
    /// The discretionary ACL — who may open the object.
    ///
    /// **`None` and an empty list are different answers, and the difference is the whole of this
    /// field.** No DACL at all (`SE_DACL_PRESENT` clear) means *everyone is granted everything*,
    /// which is the most permissive object there is. A DACL present and empty denies everyone.
    pub(crate) dacl: Option<Acl>,
    /// The system ACL, which audits rather than granting.
    pub(crate) sacl: Option<Acl>,
}

impl Descriptor {
    /// Whether a DACL is present at all. See [`Self::dacl`] for why this is not `dacl.is_some()`
    /// dressed up: it reads the control bit, so a descriptor whose DACL offset is zero *with* the
    /// bit set is reported as the "NULL DACL" it is rather than as a missing field.
    pub(crate) fn dacl_present(&self) -> bool {
        self.control & SE_DACL_PRESENT != 0
    }
}

/// Reads a security descriptor.
///
/// `read` serves target memory and answers `None` for an address that will not read, which becomes
/// [`SdError::Unreadable`] naming what could not be read rather than a zero parsed as a structure.
pub(crate) fn read_descriptor(
    at: u64,
    mut read: impl FnMut(u64, usize) -> Option<Vec<u8>>,
) -> Result<Descriptor, SdError> {
    let header = read(at, 20).ok_or(SdError::Unreadable { at, len: 20 })?;
    if header.len() < 20 {
        return Err(SdError::Unreadable { at, len: 20 });
    }
    let revision = header[0];
    if revision != 1 {
        return Err(SdError::Malformed {
            reason: "the security descriptor's revision is not 1",
        });
    }
    let control = u16::from_le_bytes([header[2], header[3]]);
    // **Self-relative only, and refused rather than guessed at.** An absolute descriptor holds
    // *pointers* where this one holds offsets, so reading the same bytes both ways silently
    // produces a different DACL -- and a kernel object's is self-relative. A descriptor that says
    // it is not is one this cannot read, which is an answer.
    if control & SE_SELF_RELATIVE == 0 {
        return Err(SdError::Malformed {
            reason: "the security descriptor is not self-relative, so its fields are pointers \
                     rather than offsets and this cannot read them",
        });
    }
    let offset = |index: usize| u32::from_le_bytes(header[index..index + 4].try_into().unwrap());
    let owner_at = offset(4);
    let group_at = offset(8);
    let sacl_at = offset(12);
    let dacl_at = offset(16);

    let sid_at = |which: u32, read: &mut dyn FnMut(u64, usize) -> Option<Vec<u8>>| match which {
        0 => Ok(None),
        _ => read_sid(at.wrapping_add(u64::from(which)), read).map(Some),
    };
    let owner = sid_at(owner_at, &mut read)?;
    let group = sid_at(group_at, &mut read)?;

    // The control bit decides whether a list is there; the offset only says where. A zero offset
    // with the bit set is a **NULL DACL**, which grants everyone everything -- so it is reported
    // as a present-and-absent list rather than as no DACL at all.
    let dacl = match (control & SE_DACL_PRESENT != 0, dacl_at) {
        (true, 0) => None,
        (true, offset) => Some(read_acl(at.wrapping_add(u64::from(offset)), &mut read)?),
        (false, _) => None,
    };
    let sacl = match (control & SE_SACL_PRESENT != 0, sacl_at) {
        (true, 0) => None,
        (true, offset) => Some(read_acl(at.wrapping_add(u64::from(offset)), &mut read)?),
        (false, _) => None,
    };

    Ok(Descriptor {
        revision,
        control,
        owner,
        group,
        dacl,
        sacl,
    })
}

/// Reads one `ACL` and the ACEs behind it.
fn read_acl(at: u64, read: &mut dyn FnMut(u64, usize) -> Option<Vec<u8>>) -> Result<Acl, SdError> {
    let header = read(at, 8).ok_or(SdError::Unreadable { at, len: 8 })?;
    if header.len() < 8 {
        return Err(SdError::Unreadable { at, len: 8 });
    }
    let revision = header[0];
    let size = usize::from(u16::from_le_bytes([header[2], header[3]]));
    let ace_count = usize::from(u16::from_le_bytes([header[4], header[5]]));
    if size < 8 || size > MAX_ACL_BYTES {
        return Err(SdError::Malformed {
            reason: "the ACL's size is not a size an access control list has",
        });
    }
    if ace_count > MAX_ACES {
        return Err(SdError::Malformed {
            reason: "the ACL claims more entries than an access control list plausibly has",
        });
    }
    // Read whole: an ACE is walked by the size in its own header, and reading each one separately
    // would be a target-controlled number of reads to parse one structure.
    let bytes = read(at, size).ok_or(SdError::Unreadable { at, len: size })?;
    if bytes.len() < size {
        return Err(SdError::Unreadable { at, len: size });
    }

    let mut aces = Vec::new();
    let mut cursor = 8usize;
    for _ in 0..ace_count {
        if cursor + 4 > size {
            // The header said more entries than the size holds. What was read stands, and the
            // count beside it says what was claimed.
            break;
        }
        let ace_type = bytes[cursor];
        let flags = bytes[cursor + 1];
        let ace_size = usize::from(u16::from_le_bytes([bytes[cursor + 2], bytes[cursor + 3]]));
        // A size shorter than the header it sits in, or longer than the list holding it, is not
        // an entry. Both are numbers in memory this server did not write, and the second is the
        // one that matters: without it the ACE's body would be read out of whatever follows the
        // ACL. The first is cheap and explicit -- what actually refuses a two-byte entry is
        // `read_ace` having no mask to read, one level down.
        if ace_size < 4 || cursor + ace_size > size {
            return Err(SdError::Malformed {
                reason: "an ACE's size runs past the end of its ACL",
            });
        }
        let body = &bytes[cursor..cursor + ace_size];
        aces.push(read_ace(ace_type, flags, body)?);
        cursor += ace_size;
    }

    Ok(Acl {
        revision,
        ace_count,
        aces,
    })
}

/// Decodes one ACE from its own bytes.
fn read_ace(ace_type: u8, flags: u8, body: &[u8]) -> Result<Ace, SdError> {
    let kind = match ace_type {
        // ACCESS_ALLOWED, and its callback and compound variants, which put the SID in the same
        // place.
        0x00 | 0x09 | 0x04 => AceKind::Allow,
        // ACCESS_DENIED and its callback variant.
        0x01 | 0x0a => AceKind::Deny,
        // SYSTEM_AUDIT, its callback variant, and the mandatory-label and scoped-policy types,
        // which are SACL entries with the same shape.
        0x02 | 0x0d | 0x11 | 0x13 => AceKind::Audit,
        other => AceKind::Other(other),
    };
    // Every type above this one puts a four-byte mask after the header. An object ACE (0x05, 0x06,
    // 0x07, 0x08) then has flags and up to two GUIDs before its SID, which is why those are
    // `Other` and carry no principal rather than a wrong one.
    let mask = match body.len() >= 8 {
        true => u32::from_le_bytes([body[4], body[5], body[6], body[7]]),
        false => {
            return Err(SdError::Malformed {
                reason: "an ACE is too short to carry an access mask",
            });
        }
    };
    let sid = match kind {
        AceKind::Other(_) => None,
        _ => sid_from(&body[8..]).ok(),
    };
    Ok(Ace {
        kind,
        ace_type,
        flags,
        mask,
        sid,
    })
}

/// Reads a SID from target memory: its header, then the sub-authorities it says it has.
fn read_sid(at: u64, read: &mut dyn FnMut(u64, usize) -> Option<Vec<u8>>) -> Result<Sid, SdError> {
    let header = read(at, 8).ok_or(SdError::Unreadable { at, len: 8 })?;
    if header.len() < 8 {
        return Err(SdError::Unreadable { at, len: 8 });
    }
    let count = usize::from(header[1]);
    if count > MAX_SUBAUTHORITIES {
        return Err(SdError::Malformed {
            reason: "a SID claims more sub-authorities than a SID has",
        });
    }
    let len = 8 + count * 4;
    let bytes = read(at, len).ok_or(SdError::Unreadable { at, len })?;
    if bytes.len() < len {
        return Err(SdError::Unreadable { at, len });
    }
    sid_from(&bytes)
}

/// Decodes a SID that is already in hand.
fn sid_from(bytes: &[u8]) -> Result<Sid, SdError> {
    if bytes.len() < 8 {
        return Err(SdError::Malformed {
            reason: "a SID is too short to carry its own header",
        });
    }
    let revision = bytes[0];
    if revision != 1 {
        return Err(SdError::Malformed {
            reason: "a SID's revision is not 1",
        });
    }
    let count = usize::from(bytes[1]);
    if count > MAX_SUBAUTHORITIES {
        return Err(SdError::Malformed {
            reason: "a SID claims more sub-authorities than a SID has",
        });
    }
    if bytes.len() < 8 + count * 4 {
        return Err(SdError::Malformed {
            reason: "a SID is shorter than the sub-authorities it claims",
        });
    }
    // **The identifier authority is big-endian**, alone among these fields, and reading it the
    // other way turns `S-1-5-…` into `S-1-21474836480-…`. It is six bytes rather than eight, so
    // there is no integer type to read it as either.
    let authority = bytes[2..8]
        .iter()
        .fold(0u64, |value, byte| (value << 8) | u64::from(*byte));
    let mut text = format!("S-{revision}-{authority}");
    let mut subs = Vec::with_capacity(count);
    for index in 0..count {
        let start = 8 + index * 4;
        let sub = u32::from_le_bytes(bytes[start..start + 4].try_into().unwrap());
        subs.push(sub);
        let _ = write!(text, "-{sub}");
    }
    let name = well_known(authority, &subs);
    Ok(Sid { text, name })
}

/// The name Windows shows for a SID everyone has, and nothing for the rest.
///
/// Deliberately short, and every entry is a SID that appears on a device's DACL: the point is to
/// make a device's ACEs readable without a lookup, not to reimplement `LookupAccountSid`, which
/// needs a domain this debugger is not joined to and an account database a dump does not carry.
fn well_known(authority: u64, subs: &[u32]) -> Option<&'static str> {
    Some(match (authority, subs) {
        (0, [0]) => "NULL",
        (1, [0]) => "Everyone",
        (2, [0]) => "LOCAL",
        (3, [0]) => "CREATOR OWNER",
        (3, [1]) => "CREATOR GROUP",
        (5, [1]) => "DIALUP",
        (5, [2]) => "NETWORK",
        (5, [3]) => "BATCH",
        (5, [4]) => "INTERACTIVE",
        (5, [6]) => "SERVICE",
        (5, [7]) => "ANONYMOUS LOGON",
        (5, [11]) => "Authenticated Users",
        (5, [12]) => "RESTRICTED",
        (5, [13]) => "TERMINAL SERVER USER",
        (5, [14]) => "REMOTE INTERACTIVE LOGON",
        (5, [15]) => "This Organization",
        (5, [18]) => "SYSTEM",
        (5, [19]) => "LOCAL SERVICE",
        (5, [20]) => "NETWORK SERVICE",
        (5, [33]) => "WRITE RESTRICTED",
        (5, [113]) => "Local account",
        (5, [114]) => "Local account and member of Administrators group",
        (5, [32, 544]) => "Administrators",
        (5, [32, 545]) => "Users",
        (5, [32, 546]) => "Guests",
        (5, [32, 547]) => "Power Users",
        (5, [32, 551]) => "Backup Operators",
        (5, [32, 555]) => "Remote Desktop Users",
        (5, [32, 559]) => "Performance Log Users",
        (5, [32, 568]) => "IIS_IUSRS",
        (5, [32, 573]) => "Event Log Readers",
        (15, [2, 1]) => "ALL APPLICATION PACKAGES",
        (15, [2, 2]) => "ALL RESTRICTED APPLICATION PACKAGES",
        (16, [0]) => "Untrusted Mandatory Level",
        (16, [4096]) => "Low Mandatory Level",
        (16, [8192]) => "Medium Mandatory Level",
        (16, [8448]) => "Medium Plus Mandatory Level",
        (16, [12288]) => "High Mandatory Level",
        (16, [16384]) => "System Mandatory Level",
        _ => return None,
    })
}

/// The rights an access mask carries, named the way a **device** grants them.
///
/// The low sixteen bits of a mask are object-specific, and this names them as the file-object
/// rights a device is opened with — `FILE_READ_DATA` rather than `KEY_QUERY_VALUE` — because that
/// is what an `IRP_MJ_CREATE` against a device object is checked against. A mask on some other
/// object type would read wrongly, which is why this lives beside the device analysis rather than
/// in a general-purpose place.
pub(crate) fn rights(mask: u32) -> Vec<&'static str> {
    const SPECIFIC: [(u32, &str); 9] = [
        (0x0001, "FILE_READ_DATA"),
        (0x0002, "FILE_WRITE_DATA"),
        (0x0004, "FILE_APPEND_DATA"),
        (0x0008, "FILE_READ_EA"),
        (0x0010, "FILE_WRITE_EA"),
        (0x0020, "FILE_EXECUTE"),
        (0x0040, "FILE_DELETE_CHILD"),
        (0x0080, "FILE_READ_ATTRIBUTES"),
        (0x0100, "FILE_WRITE_ATTRIBUTES"),
    ];
    const STANDARD: [(u32, &str); 5] = [
        (0x0001_0000, "DELETE"),
        (0x0002_0000, "READ_CONTROL"),
        (0x0004_0000, "WRITE_DAC"),
        (0x0008_0000, "WRITE_OWNER"),
        (0x0010_0000, "SYNCHRONIZE"),
    ];
    const GENERIC: [(u32, &str); 5] = [
        (0x0100_0000, "ACCESS_SYSTEM_SECURITY"),
        (0x1000_0000, "GENERIC_ALL"),
        (0x2000_0000, "GENERIC_EXECUTE"),
        (0x4000_0000, "GENERIC_WRITE"),
        (0x8000_0000, "GENERIC_READ"),
    ];
    let mut named = Vec::new();
    for (bit, name) in SPECIFIC.iter().chain(&STANDARD).chain(&GENERIC) {
        if mask & bit != 0 {
            named.push(*name);
        }
    }
    named
}

/// Whether a mask carries the two rights that decide whether a handle can send an IOCTL at all.
///
/// `FILE_READ_DATA` and `FILE_WRITE_DATA` are what the I/O manager checks a control code's
/// `RequiredAccess` against, which is the join between this answer and an IOCTL map: a code
/// requiring `FILE_WRITE_DATA` is unreachable through a handle whose ACE grants neither.
pub(crate) fn data_access(mask: u32) -> (bool, bool) {
    (mask & 0x0001 != 0, mask & 0x0002 != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const AT: u64 = 0xffff_8680_fc69_12a0;

    /// A fake address space holding one buffer, so a read outside it answers `None` exactly as
    /// target memory that will not read does.
    struct Memory {
        base: u64,
        bytes: Vec<u8>,
    }

    impl Memory {
        fn read(&self, at: u64, len: usize) -> Option<Vec<u8>> {
            let offset = usize::try_from(at.checked_sub(self.base)?).ok()?;
            let end = offset.checked_add(len)?;
            (end <= self.bytes.len()).then(|| self.bytes[offset..end].to_vec())
        }
    }

    /// A SID as it sits in memory: revision, sub-authority count, a **big-endian** six-byte
    /// authority, then little-endian sub-authorities.
    fn sid(authority: u64, subs: &[u32]) -> Vec<u8> {
        let mut out = vec![1u8, subs.len() as u8];
        out.extend_from_slice(&authority.to_be_bytes()[2..]);
        for sub in subs {
            out.extend_from_slice(&sub.to_le_bytes());
        }
        out
    }

    /// One ACE: header, mask, SID.
    fn ace(ace_type: u8, flags: u8, mask: u32, sid: &[u8]) -> Vec<u8> {
        let size = (8 + sid.len()) as u16;
        let mut out = vec![ace_type, flags];
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&mask.to_le_bytes());
        out.extend_from_slice(sid);
        out
    }

    /// An ACL around a list of ACEs, with the count the header claims taken from the list unless
    /// a test says otherwise.
    fn acl(revision: u8, aces: &[Vec<u8>], claimed: Option<u16>) -> Vec<u8> {
        let body: Vec<u8> = aces.iter().flatten().copied().collect();
        let size = (8 + body.len()) as u16;
        let mut out = vec![revision, 0];
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&claimed.unwrap_or(aces.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&body);
        out
    }

    /// A self-relative descriptor with a DACL at offset 20, which is where one goes when the
    /// descriptor carries no owner or group.
    fn descriptor(control: u16, dacl: Option<&[u8]>) -> Vec<u8> {
        let mut out = vec![1u8, 0];
        out.extend_from_slice(&control.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // Owner
        out.extend_from_slice(&0u32.to_le_bytes()); // Group
        out.extend_from_slice(&0u32.to_le_bytes()); // Sacl
        out.extend_from_slice(&match dacl {
            Some(_) => 20u32.to_le_bytes(),
            None => 0u32.to_le_bytes(),
        });
        if let Some(dacl) = dacl {
            out.extend_from_slice(dacl);
        }
        out
    }

    /// `\Device\MountPointManager`'s DACL, whose four ACEs `docs/driver-ioctl-walkthrough.md`
    /// published from a hand decode.
    ///
    /// The fixture is **literal bytes**, not the parser's own constants: the layout is the thing
    /// being pinned, and a fixture that shared the constants would agree with any reading of them.
    /// Its ACL is 0x5c bytes, which is the length that walkthrough's `db … L5c` reads -- so the
    /// shape here is the one on the device rather than one that merely parses.
    #[test]
    fn a_device_dacl_reads_as_its_principals_and_their_access() {
        let aces = [
            ace(0, 0, 0x0012_00a0, &sid(1, &[0])),       // Everyone
            ace(0, 0, 0x0012_00a0, &sid(5, &[12])),      // RESTRICTED
            ace(0, 0, 0x001f_01ff, &sid(5, &[18])),      // SYSTEM
            ace(0, 0, 0x001f_01ff, &sid(5, &[32, 544])), // Administrators
        ];
        let dacl = acl(2, &aces, None);
        assert_eq!(dacl.len(), 0x5c, "the ACL the walkthrough reads with `L5c`");
        let memory = Memory {
            base: AT,
            bytes: descriptor(SE_SELF_RELATIVE | SE_DACL_PRESENT, Some(&dacl)),
        };

        let found = read_descriptor(AT, |at, len| memory.read(at, len)).unwrap();

        let dacl = found.dacl.expect("the descriptor has a DACL");
        assert_eq!(dacl.ace_count, 4);
        assert_eq!(
            dacl.aces
                .iter()
                .map(|ace| (
                    ace.kind,
                    ace.sid.as_ref().unwrap().text.as_str(),
                    ace.sid.as_ref().unwrap().name,
                    ace.mask
                ))
                .collect::<Vec<_>>(),
            vec![
                (AceKind::Allow, "S-1-1-0", Some("Everyone"), 0x0012_00a0),
                (AceKind::Allow, "S-1-5-12", Some("RESTRICTED"), 0x0012_00a0),
                (AceKind::Allow, "S-1-5-18", Some("SYSTEM"), 0x001f_01ff),
                (
                    AceKind::Allow,
                    "S-1-5-32-544",
                    Some("Administrators"),
                    0x001f_01ff
                ),
            ],
            "{:?}",
            dacl.aces
        );
        // And the finding that whole section exists for: a standard user matches only the first
        // ACE, which grants neither of the rights an IOCTL is checked against.
        assert_eq!(data_access(dacl.aces[0].mask), (false, false));
        assert_eq!(data_access(dacl.aces[3].mask), (true, true));
    }

    /// A **NULL DACL** grants everyone everything, and reads identically to a missing one unless
    /// the control bit is what decides.
    ///
    /// The two fixtures differ in one bit and in nothing else, which is the only way to see that
    /// the offset is not what is being read: a parser keying off `dacl_at == 0` gives both the
    /// same answer, and one of them is the most permissive object on the system.
    #[test]
    fn a_null_dacl_is_not_a_missing_one() {
        let present = Memory {
            base: AT,
            bytes: descriptor(SE_SELF_RELATIVE | SE_DACL_PRESENT, None),
        };
        let absent = Memory {
            base: AT,
            bytes: descriptor(SE_SELF_RELATIVE, None),
        };

        let with = read_descriptor(AT, |at, len| present.read(at, len)).unwrap();
        let without = read_descriptor(AT, |at, len| absent.read(at, len)).unwrap();

        assert!(with.dacl.is_none() && with.dacl_present(), "a NULL DACL");
        assert!(
            without.dacl.is_none() && !without.dacl_present(),
            "no DACL at all"
        );
    }

    /// The identifier authority is **big-endian**, alone among these fields.
    ///
    /// Read the other way `S-1-5-18` becomes `S-1-21474836480-18`, which is not a SID anything
    /// will match and is not obviously wrong to look at. The fixture writes the bytes by hand for
    /// that reason.
    #[test]
    fn an_identifier_authority_is_big_endian() {
        let bytes = [1u8, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];

        let sid = sid_from(&bytes).unwrap();

        assert_eq!(sid.text, "S-1-5-18");
        assert_eq!(sid.name, Some("SYSTEM"));
    }

    /// An ACE too short to carry its own access mask is refused, not read out of the bytes after
    /// it.
    ///
    /// A zero size is the extreme of it: the entry's body is then empty, and an ACL whose header
    /// claims a thousand entries would otherwise produce a thousand readings of the same offset.
    /// The size comes out of memory this server did not write, so this is a refusal rather than a
    /// clamp -- an ACL that says this is not an ACL, and half of one answers "who may open this"
    /// wrongly.
    #[test]
    fn an_ace_too_short_to_carry_a_mask_is_refused() {
        let mut broken = ace(0, 0, 0x0012_00a0, &sid(1, &[0]));
        broken[2] = 0;
        broken[3] = 0;
        let dacl = acl(2, &[broken], None);
        let memory = Memory {
            base: AT,
            bytes: descriptor(SE_SELF_RELATIVE | SE_DACL_PRESENT, Some(&dacl)),
        };

        let found = read_descriptor(AT, |at, len| memory.read(at, len));

        assert!(matches!(found, Err(SdError::Malformed { .. })), "{found:?}");

        // Six bytes: past the ACL walk's size guard and still too short to hold a mask. It is
        // here because the zero-size case above is refused by **either** of two checks
        // independently, so that one pins the property and neither line; this one reaches only
        // the second.
        let mut short = ace(0, 0, 0x0012_00a0, &sid(1, &[0]));
        short[2..4].copy_from_slice(&6u16.to_le_bytes());
        short.truncate(6);
        let dacl = acl(2, &[short], None);
        let memory = Memory {
            base: AT,
            bytes: descriptor(SE_SELF_RELATIVE | SE_DACL_PRESENT, Some(&dacl)),
        };

        let found = read_descriptor(AT, |at, len| memory.read(at, len));

        assert!(matches!(found, Err(SdError::Malformed { .. })), "{found:?}");
    }

    /// An ACE running past the end of its ACL is refused, rather than read out of whatever
    /// follows the list in memory.
    #[test]
    fn an_ace_running_past_its_acl_is_refused() {
        let mut long = ace(0, 0, 0x0012_00a0, &sid(1, &[0]));
        let size = (long.len() + 16) as u16;
        long[2..4].copy_from_slice(&size.to_le_bytes());
        let dacl = acl(2, &[long], None);
        let memory = Memory {
            base: AT,
            bytes: descriptor(SE_SELF_RELATIVE | SE_DACL_PRESENT, Some(&dacl)),
        };

        let found = read_descriptor(AT, |at, len| memory.read(at, len));

        assert!(matches!(found, Err(SdError::Malformed { .. })), "{found:?}");
    }

    /// A descriptor that is not self-relative is refused, because its fields are pointers.
    ///
    /// The same twenty bytes read as offsets give a DACL address in the low pages, so this is the
    /// difference between an answer and a confident wrong one rather than a missing feature.
    #[test]
    fn a_descriptor_that_is_not_self_relative_is_refused() {
        let memory = Memory {
            base: AT,
            bytes: descriptor(SE_DACL_PRESENT, None),
        };

        let found = read_descriptor(AT, |at, len| memory.read(at, len));

        assert!(matches!(found, Err(SdError::Malformed { .. })), "{found:?}");
    }

    /// An object ACE carries no principal here rather than a wrong one.
    ///
    /// Its SID sits after a flags word and up to two GUIDs, so reading it where an ordinary ACE's
    /// is gives a SID built from a GUID's bytes -- a plausible-looking principal that does not
    /// exist. The entry is still reported, with its type, because an ACE nobody read is a
    /// principal nobody saw.
    #[test]
    fn an_object_ace_carries_no_principal_rather_than_a_wrong_one() {
        let mut body = vec![0x05u8, 0]; // ACCESS_ALLOWED_OBJECT_ACE_TYPE
        let sid = sid(1, &[0]);
        let size = (8 + 4 + 16 + sid.len()) as u16;
        body.extend_from_slice(&size.to_le_bytes());
        body.extend_from_slice(&0x001f_01ffu32.to_le_bytes());
        body.extend_from_slice(&1u32.to_le_bytes()); // Flags: an object type is present
        body.extend_from_slice(&[0xaa; 16]); // the GUID
        body.extend_from_slice(&sid);
        let dacl = acl(4, &[body], None);
        let memory = Memory {
            base: AT,
            bytes: descriptor(SE_SELF_RELATIVE | SE_DACL_PRESENT, Some(&dacl)),
        };

        let found = read_descriptor(AT, |at, len| memory.read(at, len)).unwrap();

        let aces = found.dacl.unwrap().aces;
        assert_eq!(aces.len(), 1);
        assert_eq!(aces[0].kind, AceKind::Other(0x05));
        assert_eq!(aces[0].mask, 0x001f_01ff, "the mask is where it always is");
        assert!(aces[0].sid.is_none(), "{:?}", aces[0].sid);
    }

    /// Bytes that will not read are `Unreadable`, naming what could not be read.
    ///
    /// Which is the ordinary answer on a dump: a device's descriptor is pool, and a minidump
    /// carries none of it. An empty DACL there would read as an object nobody may open.
    #[test]
    fn bytes_that_will_not_read_are_unreadable_rather_than_empty() {
        let found = read_descriptor(AT, |_, _| None);

        assert_eq!(found, Err(SdError::Unreadable { at: AT, len: 20 }));
    }

    /// The mask names the rights a **device** grants, which is the vocabulary an IOCTL's
    /// `RequiredAccess` is checked in.
    #[test]
    fn a_mask_names_the_rights_a_device_grants() {
        assert_eq!(
            rights(0x0012_00a0),
            vec![
                "FILE_EXECUTE",
                "FILE_READ_ATTRIBUTES",
                "READ_CONTROL",
                "SYNCHRONIZE"
            ],
            "no read or write of data, which is what makes this device openable but quiet"
        );
        assert_eq!(rights(0x0000_0000), Vec::<&str>::new());
        assert_eq!(
            rights(0x001f_01ff).len(),
            14,
            "FILE_ALL_ACCESS is the nine specific rights and five standard ones"
        );
    }
}
