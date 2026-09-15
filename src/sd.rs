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
//! # Where a descriptor can be read from
//!
//! **Not from the checked-in kernel minidump**, measured 2026-09-11: `!devobj
//! \Device\MountPointManager` there answers `Unable to get value of ObpRootDirectoryObject`
//! and then `not found`, because a minidump carries no object namespace to walk. So the oracle for
//! this is the live-kernel tier -- the four ACEs `docs/driver-ioctl-walkthrough.md` published --
//! and what a dump can still serve is a descriptor whose address a caller already has.
//!
//! # Engine-free
//!
//! Like [`dbgscope::pe`], [`crate::ioctl`], [`crate::hazards`] and [`crate::driver`], the entry point
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

/// `INHERIT_ONLY_ACE`. The entry exists to be inherited and is **not** applied to the object
/// carrying it, so it decides nothing about who may open this device.
pub(crate) const INHERIT_ONLY_ACE: u8 = 0x08;

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
    /// Audits rather than deciding — a SACL entry. Its mask is still an access mask: it names
    /// the accesses whose use is recorded.
    Audit,
    /// A mandatory integrity label (`SYSTEM_MANDATORY_LABEL_ACE`), whose **mask is not an access
    /// mask at all**: its low three bits are `NO_WRITE_UP`, `NO_READ_UP` and `NO_EXECUTE_UP`, the
    /// policy the label enforces against a lower-integrity caller.
    ///
    /// Its own kind rather than an audit entry, because naming it one puts its mask through a
    /// table of **file** rights and reports `NO_WRITE_UP` as `FILE_READ_DATA` — a device carrying
    /// a label then answers that Everyone may read its data, off a bit that says the opposite.
    /// The principal is an integrity level, which [`Sid::name`] already names.
    Label,
    /// `SYSTEM_SCOPED_POLICY_ID_ACE`, whose mask is reserved and means nothing. Distinct from
    /// [`Self::Other`] because its SID *is* readable and worth reporting; distinct from
    /// [`Self::Audit`] because there is no access in it to name.
    ScopedPolicy,
    /// A type this does not decode past its header. Reported rather than skipped: an ACE nobody
    /// read is a principal nobody saw.
    Other(u8),
}

impl AceKind {
    /// Whether an entry of this kind carries a principal where this reader looks for one.
    ///
    /// True for everything but [`Self::Other`], which is the kind for an ACE whose SID this
    /// cannot place -- an object ACE puts up to two GUIDs before it. So for every other kind a
    /// missing [`Ace::sid`] means the bytes that should have held one did not parse, which is a
    /// different fact from an ACE that has none, and the only way to tell them apart.
    pub(crate) fn carries_sid(self) -> bool {
        !matches!(self, Self::Other(_))
    }

    /// Whether this entry's mask is an **access** mask, and so nameable as device rights.
    ///
    /// The distinction the type exists for: an allow, a deny and an audit entry all carry one, and
    /// a mandatory label and a scoped policy id carry something else in the same four bytes.
    ///
    /// **[`Self::Other`] is not one answer**, and reading it as one was a defect. That kind says
    /// this reader cannot place the ACE's *principal* -- an object ACE puts up to two GUIDs before
    /// it, a compound ACE two SIDs -- which is a different fact from its mask not being access.
    /// Every documented allow/deny/audit/alarm type carries an `ACCESS_MASK` in the same four
    /// bytes, object and callback variants included, so an object ACE granting `FILE_WRITE_DATA`
    /// was reported with no rights and `writes: false`: a client joining this to an IOCTL map
    /// would call a write-required control code unreachable through a handle that has it. A type
    /// outside that range is one nothing here knows, and stays false.
    ///
    /// The run ends at `0x10`, `SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE`, which is the last of them
    /// -- `0x11` is the mandatory label. It was first written `0x04`..=`0x0f` out of doubt about
    /// whether `0x10` was a type at all; it is one, and leaving it out was the same mistake in
    /// miniature as leaving the object-callback types out of [`Ace::callback`].
    pub(crate) fn mask_is_access(self) -> bool {
        match self {
            Self::Allow | Self::Deny | Self::Audit => true,
            Self::Other(ace_type) => (0x04..=0x10).contains(&ace_type),
            Self::Label | Self::ScopedPolicy => false,
        }
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Audit => "audit",
            Self::Label => "label",
            Self::ScopedPolicy => "scoped_policy",
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
    /// Whether this entry carries a **conditional expression**, which the kernel evaluates
    /// against the caller's token before the entry decides anything.
    ///
    /// Implies [`Self::callback`], and is the narrower of the two: a conditional ACE is a callback
    /// ACE whose application data opens with the `artx` signature MS-DTYP fixes for it. This
    /// reader does not evaluate the expression, so an entry with this set grants or denies its
    /// mask *if the condition holds* -- a weaker claim than the [`Self::kind`] beside it makes on
    /// its own.
    pub(crate) conditional: bool,
    /// Whether this entry is a **callback** ACE, whose application data decides whether it
    /// applies.
    ///
    /// Set for every callback type; [`Self::conditional`] says whether that data is the one form
    /// of it this can recognise. The gap between them is an application-defined blob, which this
    /// neither decodes nor pretends is an expression -- and which must still not be reported as an
    /// entry that simply applies.
    pub(crate) callback: bool,
    /// The principal, when the ACE carries one where this can find it.
    ///
    /// **Absent means two different things, and [`AceKind::carries_sid`] is what tells them
    /// apart.** For [`AceKind::Other`] it is an ACE whose SID this cannot place -- an object ACE
    /// puts up to two GUIDs before it. For every other kind the bytes that should have held a SID
    /// did not parse, which on a descriptor read out of a target this server did not write is
    /// evidence rather than a wrinkle: it is an entry granting a mask to somebody nobody can name.
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
    if !(8..=MAX_ACL_BYTES).contains(&size) {
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

/// The four bytes a conditional ACE's application data opens with, per MS-DTYP. A callback ACE
/// without them carries something application-defined instead.
const CONDITIONAL_ACE_SIGNATURE: &[u8] = b"artx";

/// Decodes one ACE from its own bytes.
fn read_ace(ace_type: u8, flags: u8, body: &[u8]) -> Result<Ace, SdError> {
    // **Every callback type, which is the whole documented run `0x09`..=`0x10`**: the plain
    // allow and deny callbacks, their object variants, and the audit and alarm callbacks with
    // theirs. This used to be the three whose principal sits where this reads one, with a comment
    // saying the other five were *deliberately* left out -- which was wrong, and only looked
    // harmless because `Other` reported no rights at all. Widening `mask_is_access` to name an
    // object ACE's mask is what made it bite: an object-callback ACE then printed its rights with
    // nothing beside them, reading as an entry that simply applies when trailing callback data
    // decides whether it applies at all.
    //
    // What stays narrow is `conditional` below, and for a reason about layout rather than about
    // kind: those five put one or two GUIDs before the SID, so the offset the application data
    // starts at is not one this computes.
    let callback = (0x09..=0x10).contains(&ace_type);
    let kind = match ace_type {
        // ACCESS_ALLOWED and its callback variant.
        0x00 | 0x09 => AceKind::Allow,
        // ACCESS_DENIED and its callback variant.
        0x01 | 0x0a => AceKind::Deny,
        // SYSTEM_AUDIT and its callback variant.
        0x02 | 0x0d => AceKind::Audit,
        // **`ACCESS_ALLOWED_COMPOUND_ACE` (0x04) is deliberately not decoded**, and that is a
        // decision reached by two review rounds landing on it. It puts a `CompoundAceType` and a
        // reserved word between the mask and its principals, and then carries *two* of them -- a
        // server SID and a client SID -- granting the mask to the client only while the server
        // impersonates it. Reading the first as "the principal" states a grant to the wrong
        // identity; reading one of two as either is a confident wrong answer, which is the thing
        // this module refuses elsewhere. It is a Windows NT-era type that current Windows does
        // not emit, so there is no target here to check a decode against. `Other` says exactly
        // what is true: the header was read and the body was not.
        //
        // The mask still comes back, and the raw `ace_type` with it, so an entry that does turn
        // up is visible rather than silently dropped.

        // The two SACL types whose four bytes after the header are **not** an access mask.
        0x11 => AceKind::Label,
        0x13 => AceKind::ScopedPolicy,
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
    // Every kind decoded above puts its principal straight after the mask. The types that do not
    // are `Other`, which is what that variant means and why it reports none.
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
        // **A callback ACE decides at evaluation time, and this reads bytes.** Reporting one as a
        // plain allow says the principal has the mask, which is one branch of a question this
        // cannot answer, so the honest thing is to say the decision is not this entry's alone.
        //
        // **But the type alone does not make it a *conditional* ACE**, and saying so rendered an
        // arbitrary application callback as an `[if]` expression. MS-DTYP builds a conditional ACE
        // as a callback ACE whose application data opens with the `artx` signature; without it the
        // data is application-defined, which this does not decode and will not name. The data
        // starts after the header, the mask and the SID, whose length its own sub-authority count
        // gives -- and `body` is the ACE's own bytes, cut to its `AceSize`, so a blob running past
        // the entry reads as absent rather than into the next one. Only the three types asked
        // here put their SID at that offset; the object-callback variants put a GUID there, so
        // their data begins somewhere this does not compute and `conditional` stays false while
        // `callback` above is true -- which is the pair saying "something decides this, and it is
        // not something this can read".
        callback,
        conditional: matches!(ace_type, 0x09 | 0x0a | 0x0d)
            && body
                .get(9)
                .map(|count| 16 + 4 * usize::from(*count))
                .and_then(|at| body.get(at..at.saturating_add(4)))
                .is_some_and(|signature| signature == CONDITIONAL_ACE_SIGNATURE),
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

/// The policy a mandatory integrity label enforces, which is what its four bytes hold instead of
/// an access mask.
///
/// Three published bits, used as published for the reason [`crate::device`]'s module docs give
/// about `FILE_DEVICE_SECURE_OPEN`. They restrict a caller whose integrity is **lower** than the
/// label's, and say nothing about one at or above it.
pub(crate) fn label_policy(mask: u32) -> Vec<&'static str> {
    const POLICY: [(u32, &str); 3] = [
        (0x0001, "NO_WRITE_UP"),
        (0x0002, "NO_READ_UP"),
        (0x0004, "NO_EXECUTE_UP"),
    ];
    POLICY
        .iter()
        .filter(|(bit, _)| mask & bit != 0)
        .map(|(_, name)| *name)
        .collect()
}

/// Whether a mask carries the two rights that decide whether a handle can send an IOCTL at all.
///
/// `FILE_READ_DATA` and `FILE_WRITE_DATA` are what the I/O manager checks a control code's
/// `RequiredAccess` against, which is the join between this answer and an IOCTL map: a code
/// requiring `FILE_WRITE_DATA` is unreachable through a handle whose ACE grants neither.
///
/// **A `GENERIC_*` bit is read as itself and not expanded through the device's generic mapping,
/// because the kernel does not expand one here either.** `nt!RtlMapGenericMask` runs where a
/// descriptor is *assigned* -- `SeAssignSecurity`, `SeSetSecurityDescriptorInfo` -- and it ends
/// `and eax,0FFFFFFFh`, clearing the generic nibble it has just expanded into specific rights. The
/// access check never runs it: `nt!SeAccessCheckWithHint` is 1,192 instructions on 26100 and not
/// one of them reads a generic bit or the mapping. So an effective ACE reaching this function has
/// already been mapped, and one that still carries a generic bit arrived without an assignment, in
/// which case the check accumulates those raw bits and they satisfy no specific request --
/// `(false, false)` is that outcome rather than a gap in this table.
///
/// Measured rather than reasoned, across every distinct descriptor behind every device in
/// `\Device` on that build: 41 descriptors, 149 ACEs, of which 7 carry generic bits and **all 7
/// are `INHERIT_ONLY_ACE`** -- templates for children of types whose mappings differ, which is the
/// one place a generic bit is supposed to survive. None of the other 141 carries one. Those 7 are
/// already reported as granting nothing, by the separate inherit-only rule in
/// [`crate::device`]'s `access_entry`, so the two rules agree on the only ACEs where both apply.
pub(crate) fn data_access(mask: u32) -> (bool, bool) {
    (mask & 0x0001 != 0, mask & 0x0002 != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **An ACE whose principal this cannot place still has an access mask.**
    ///
    /// `Other` is the kind for an ACE this does not decode past its header, and the reason is
    /// always the *principal*: an object ACE puts up to two GUIDs before the SID, a compound ACE
    /// two SIDs. The mask sits at the same offset in all of them and is an `ACCESS_MASK` in every
    /// documented allow/deny/audit/alarm type. Reading `Other` as "no access mask" reported an
    /// object ACE granting `FILE_WRITE_DATA` as granting nothing nameable, which joined to an
    /// IOCTL map says a write-required control code cannot be reached through a handle that has
    /// exactly the right it needs.
    #[test]
    fn an_ace_this_cannot_decode_still_has_an_access_mask() {
        for object_ace in [0x04u8, 0x05, 0x06, 0x07, 0x08, 0x0b, 0x0c, 0x0e, 0x0f, 0x10] {
            assert!(
                AceKind::Other(object_ace).mask_is_access(),
                "type {object_ace:#04x} carries an ACCESS_MASK wherever its principal is"
            );
        }
        // `0x11` is the mandatory label and the first type past the run, which is what makes
        // `0x10` the end of it rather than a guess about where to stop.
        assert!(!AceKind::Other(0x11).mask_is_access());
        // A type nothing here knows is a mask nothing here can name, which is the honest answer
        // and the one the range above is drawn to leave room for.
        assert!(!AceKind::Other(0x40).mask_is_access());
        // And the two whose four bytes really are something else stay out.
        assert!(!AceKind::Label.mask_is_access());
        assert!(!AceKind::ScopedPolicy.mask_is_access());
    }

    /// **A generic bit is not a data right, and mapping it here would invent access.**
    ///
    /// Raised in review as a missing generic mapping, and declined on a measurement: the kernel
    /// maps at assignment and not at the check, so a generic bit surviving in a mask is one no
    /// access check will expand either. Pinned because the suggestion will come back, and because
    /// the mask is still *named* by [`rights`] -- so a reader seeing `GENERIC_ALL` beside
    /// `reads: false` should find the reason here rather than take it for a defect.
    #[test]
    fn a_generic_bit_is_not_read_as_the_rights_it_would_map_to() {
        const GENERIC_ALL: u32 = 0x1000_0000;
        const GENERIC_READ: u32 = 0x8000_0000;
        assert_eq!(data_access(GENERIC_ALL), (false, false));
        assert_eq!(data_access(GENERIC_READ), (false, false));
        assert!(
            rights(GENERIC_ALL).contains(&"GENERIC_ALL"),
            "while the bit is still named, which is how a reader tells this from an empty mask"
        );
        // And the mapped form of the same grant -- what an assignment would have left behind --
        // does answer, which is what makes the pair above a statement about the bits rather than
        // about the rights they stand for.
        assert_eq!(data_access(0x001f_01ff), (true, true));
    }

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

    /// `ACCESS_ALLOWED_COMPOUND_ACE`, which puts a `CompoundAceType` and a `Reserved` word
    /// between the mask and the principal. Written out rather than derived from [`ace`], so the
    /// fixture cannot share the offset with the parser and agree with it about a wrong one.
    fn compound_ace(mask: u32, server: &[u8], sid: &[u8]) -> Vec<u8> {
        let size = (12 + sid.len()) as u16;
        let mut out = vec![0x04u8, 0];
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&mask.to_le_bytes());
        // `CompoundAceType` = 1 (IMPERSONATE), then two reserved bytes. `server` stands for the
        // bytes a reader at offset 8 would take for a SID header.
        out.extend_from_slice(server);
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

    /// **A compound ACE reports no principal rather than one of its two.**
    ///
    /// `ACCESS_ALLOWED_COMPOUND_ACE` carries a `CompoundAceType` and a reserved word, then a
    /// *server* SID and a *client* SID: the mask is granted to the client while the server
    /// impersonates it. Two review rounds landed on this one type -- the first because the SID
    /// was being read at byte 8, which is metadata, the second because byte 12 is only the first
    /// of the two -- so what is wrong is the decoding rather than the offset, and the decoding is
    /// what went.
    ///
    /// The fixture is built so a regression is loud: the bytes at offset 8 parse as a valid SID,
    /// and so do the bytes at 12, so any reader that resumes guessing produces a plausible
    /// principal rather than an error.
    #[test]
    fn a_compound_ace_names_nobody_rather_than_one_of_its_two_principals() {
        let metadata = [1u8, 1, 0, 0];
        let server = sid(5, &[32, 544]);
        let client = sid(5, &[21, 1000]);
        let mut tail = server.clone();
        tail.extend_from_slice(&client);
        let bytes = compound_ace(0x0012_00a0, &metadata, &tail);
        let decoded = read_ace(0x04, 0, &bytes).expect("the header still reads");

        assert_eq!(
            decoded.kind,
            AceKind::Other(0x04),
            "the body is not decoded, and `Other` is what says so: {decoded:?}"
        );
        assert_eq!(
            decoded.sid, None,
            "neither principal is claimed as the principal"
        );
        assert_eq!(
            (decoded.mask, decoded.ace_type),
            (0x0012_00a0, 0x04),
            "while the mask and the raw type still come back, so the entry is visible"
        );
    }

    /// **A callback ACE decides at evaluation time, and only some of them decide by expression.**
    ///
    /// This test used to assert the opposite of half of itself: every callback type was reported
    /// `conditional`, on the type alone, while the bytes after the SID were thrown away. An
    /// application-defined callback therefore rendered as an `[if]`, which is a claim about a
    /// blob nobody had looked at. MS-DTYP builds a conditional ACE as a callback ACE whose
    /// application data opens with `artx`, so that is what is asked, and the two states are
    /// distinguished rather than merged.
    #[test]
    fn a_callback_ace_is_conditional_only_when_it_carries_a_condition() {
        let plain = read_ace(0x00, 0, &ace(0x00, 0, 0x1f01ff, &sid(1, &[0]))).expect("decodes");
        assert_eq!(
            (plain.conditional, plain.callback),
            (false, false),
            "an ordinary allow decides on its own: {plain:?}"
        );

        for callback_type in [0x09u8, 0x0a, 0x0d] {
            // With the signature, and an expression this does not decode behind it.
            let mut carrying = sid(1, &[0]);
            carrying.extend_from_slice(CONDITIONAL_ACE_SIGNATURE);
            carrying.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
            let decoded = read_ace(
                callback_type,
                0,
                &ace(callback_type, 0, 0x1f01ff, &carrying),
            )
            .expect("decodes");
            assert_eq!(
                (decoded.conditional, decoded.callback),
                (true, true),
                "type {callback_type:#04x} with `artx` carries a condition: {decoded:?}"
            );
            assert_eq!(
                decoded.sid.as_ref().map(|sid| sid.text.as_str()),
                Some("S-1-1-0"),
                "and its principal is still where an ordinary one is"
            );

            // Without it: still a callback, and still not something to call an expression. The
            // blob is deliberately four bytes, so what distinguishes this from the case above is
            // the signature and not the presence of data.
            let mut opaque = sid(1, &[0]);
            opaque.extend_from_slice(&[0x00, 0x01, 0x02, 0x03]);
            let decoded = read_ace(callback_type, 0, &ace(callback_type, 0, 0x1f01ff, &opaque))
                .expect("decodes");
            assert_eq!(
                (decoded.conditional, decoded.callback),
                (false, true),
                "type {callback_type:#04x} without `artx` decides elsewhere, not by a condition \
                 this can name: {decoded:?}"
            );

            // And a callback ACE carrying nothing at all is not conditional either, which is the
            // shape the old assertion was actually built on.
            let bare = read_ace(
                callback_type,
                0,
                &ace(callback_type, 0, 0x1f01ff, &sid(1, &[0])),
            )
            .expect("decodes");
            assert_eq!(
                (bare.conditional, bare.callback),
                (false, true),
                "an empty blob is not an expression: {bare:?}"
            );
        }

        // **The five whose data this cannot even find are still callbacks.** They put one or two
        // GUIDs before the SID, so `conditional` cannot be asked -- and reporting them with
        // neither flag left an object-callback ACE printing its rights as though nothing decided
        // them, which is what widening `mask_is_access` to name that mask exposed.
        for object_callback in [0x0bu8, 0x0c, 0x0e, 0x0f, 0x10] {
            let decoded = read_ace(
                object_callback,
                0,
                &ace(object_callback, 0, 0x1f01ff, &sid(1, &[0])),
            )
            .expect("decodes");
            assert_eq!(
                (decoded.conditional, decoded.callback),
                (false, true),
                "type {object_callback:#04x} is a callback whose data this cannot locate: \
                 {decoded:?}"
            );
            assert!(
                decoded.kind.mask_is_access(),
                "and its mask is still an access mask, which is what makes the flag matter"
            );
        }

        // The label past the end of the run is neither, which is what keeps the range honest.
        let label = read_ace(0x11, 0, &ace(0x11, 0, 0x0000_0001, &sid(1, &[0]))).expect("decodes");
        assert_eq!((label.conditional, label.callback), (false, false));

        // **And `conditional` is not merely *false* for those five, it is not asked.** The
        // distinction needs a construction, because asking would read the signature at an offset
        // computed from bytes that are not a SID -- which normally finds nothing and so looks
        // correct. Here it finds something.
        //
        // An object ACE puts a `u32` of its own flags at 8 and the `ObjectType` GUID at 12. The
        // arithmetic for a *plain* callback ACE takes byte 9 for a sub-authority count and lands
        // at `16 + 4 * count`; byte 9 is the second byte of those flags, zero for every real one,
        // so it lands at 16 -- five bytes into the GUID. A GUID carrying `artx` there is
        // therefore an object ACE that a widened test would call conditional, on four bytes of
        // somebody's type identifier.
        let mut guid = [0xaau8; 16];
        guid[4..8].copy_from_slice(CONDITIONAL_ACE_SIGNATURE);
        let principal = sid(1, &[0]);
        let mut body = vec![0x0bu8, 0];
        let size = (12 + guid.len() + principal.len()) as u16;
        body.extend_from_slice(&size.to_le_bytes());
        body.extend_from_slice(&0x001f_01ffu32.to_le_bytes());
        body.extend_from_slice(&1u32.to_le_bytes()); // Flags: an object type is present
        body.extend_from_slice(&guid);
        body.extend_from_slice(&principal);
        assert_eq!(
            &body[16..20],
            CONDITIONAL_ACE_SIGNATURE,
            "the fixture only says anything if the bytes are where the bad arithmetic looks"
        );
        let decoded = read_ace(0x0b, 0, &body).expect("decodes");
        assert_eq!(
            (decoded.conditional, decoded.callback),
            (false, true),
            "an object ACE's GUID is not its application data, and is not read as one: {decoded:?}"
        );
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
