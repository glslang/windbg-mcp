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
//!
//! # Which security descriptor a device has
//!
//! **The one in `_DEVICE_OBJECT` itself, not the one in its `_OBJECT_HEADER`** -- and that is a
//! measurement rather than a preference, because the header's is where every other object keeps
//! it and reading it here is the natural mistake. Measured on a live Windows Server 26100 guest,
//! 2026-09-13:
//!
//! * `\Device\MountPointManager`'s object header has `SecurityDescriptor` **null**, while
//!   `!devobj` reports one at `ffffe506857f53a0` -- which parses as a self-relative descriptor
//!   whose DACL is the four published ACEs.
//! * The reason is the object type's own security method: `_OBJECT_TYPE` for `Device` carries
//!   `TypeInfo.SecurityProcedure = nt!IopGetSetSecurityObject` rather than the object manager's
//!   default, and that routine keeps the descriptor in the device object's field. So for a device
//!   the header's is not merely a second copy -- it is empty.
//!
//! Reading the header's would therefore report every device on that machine as carrying no
//! descriptor at all, which is the most permissive answer there is and the exact opposite of the
//! truth. The offset comes from type information like every other one here.
//!
//! The field is a **plain pointer**, not the `_EX_FAST_REF` the object header's is: the value
//! measured above is already aligned and parses at its unmasked address, so nothing is masked out
//! of it.

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
    /// `_DEVICE_OBJECT::SecurityDescriptor` -- the device's own, which for this object type is
    /// the only one there is. See the module docs for why the object header's is not it.
    pub(crate) security: u32,
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
        let pointers = [self.driver, self.security];
        if pointers
            .iter()
            .any(|offset| (*offset as usize).saturating_add(self.pointer) > size)
        {
            return bad("a pointer field sits outside the device object");
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
    /// The device's own security descriptor, or `None` where the field is empty.
    ///
    /// `None` is the honest answer for a device the I/O manager never gave one, and is **not**
    /// what an unreadable device answers -- that is [`DeviceError::Unreadable`] for the whole
    /// structure, because this is read as one of its fields rather than on its own.
    pub(crate) security_descriptor: Option<u64>,
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
    let pointer = |offset: u32| -> u64 {
        let at = offset as usize;
        match layout.pointer {
            4 => u64::from(u32::from_le_bytes(
                bytes[at..at + 4].try_into().unwrap_or_default(),
            )),
            _ => u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap_or_default()),
        }
    };
    let security = pointer(layout.security);
    Ok(Device {
        device_type: dword(layout.device_type),
        characteristics,
        secure_open: characteristics & FILE_DEVICE_SECURE_OPEN != 0,
        exclusive: flags & DO_EXCLUSIVE != 0,
        flags,
        driver: pointer(layout.driver),
        security_descriptor: (security != 0).then_some(security),
    })
}

/// One symbolic link that reaches a device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Link {
    /// The link's own path, which is what a user-mode caller opens.
    pub(crate) path: String,
    /// What it points at, verbatim. Kept rather than discarded once it has matched: it is the
    /// evidence for the match, and a link to `\Device\Foo\Bar` is a different claim from one
    /// to `\Device\Foo`.
    pub(crate) target: String,
}

/// Whether a device carries a security descriptor, and what came of reading it.
///
/// **Three outcomes rather than an `Option`**, because the three send a reader somewhere
/// different: a descriptor, an object the object manager guards by its parent directory alone, and
/// a target that did not answer -- which on a kernel minidump is every object, and must not be
/// reported as a device nothing guards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Security {
    /// It carries one, at this address, and this is what it says.
    Read {
        at: u64,
        descriptor: crate::sd::Descriptor,
    },
    /// The object header's `SecurityDescriptor` field is empty.
    Absent,
    /// It carries one at this address and those bytes would not read.
    Failed { at: u64, why: crate::sd::SdError },
}

/// Everything an answer about one device is made of, before it is a report.
///
/// The worker fills this in -- resolving a path, reading an object header, listing a directory --
/// and everything below is a pure mapping over it, so the report and its rendering are tested
/// against values rather than against a machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Found {
    /// The object path the answer is about, after a link was followed.
    pub(crate) device: String,
    /// The link the caller named, when they named one rather than the device.
    pub(crate) followed_link: Option<String>,
    /// The `_DEVICE_OBJECT` itself.
    pub(crate) address: u64,
    pub(crate) fields: Device,
    pub(crate) security: Security,
    /// The directory that was searched for links, whether or not it could be listed.
    pub(crate) link_directory: String,
    pub(crate) links: Vec<Link>,
    pub(crate) link_search: crate::structured::LinkSearch,
    pub(crate) links_examined: Option<usize>,
    /// Entries the namespace could not name, which are **not** among those examined.
    pub(crate) links_unnamed: usize,
    /// Examined entries this could not check -- a target that would not read, or a type that
    /// would not -- which **are** among those examined.
    pub(crate) links_unread: usize,
    pub(crate) stopped: Option<crate::walk::Halt>,
}

/// What a directory entry is, for the purpose of finding what reaches a device.
///
/// **Three answers, not two**, and the third is the one that was missing: the namespace reports a
/// type of `None` where it could not deobfuscate the object header's type index, which is not the
/// same as an object that is some other kind. Folded into "not a link" it made an entry that may
/// well be the link disappear from the search without either unchecked counter seeing it -- which
/// left a completed search claimable over a directory that had not been fully checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Candidate {
    /// A symbolic link: resolve its target and compare.
    Link,
    /// Something else. Nothing to check, and nothing missing.
    Other,
    /// The namespace could not say. It may be a link, so it is counted as unchecked.
    Unknown,
}

/// Which of the three an entry's type name is.
///
/// A named function rather than a `match` in the loop because the loop needs an engine and this
/// rule does not, and a rule that can only be exercised against a live kernel is one no test here
/// reaches.
pub(crate) fn candidate(type_name: Option<&str>) -> Candidate {
    match type_name {
        Some(SYMBOLIC_LINK) => Candidate::Link,
        Some(_) => Candidate::Other,
        None => Candidate::Unknown,
    }
}

/// The object type name a symbolic link carries.
pub(crate) const SYMBOLIC_LINK: &str = "SymbolicLink";

/// Whether two object paths name the same object.
///
/// **A textual match, and the two things it is not are the reason this is a named function rather
/// than an `==`.** The object manager is case-insensitive for names, so `\Device\Foo` and
/// `\DEVICE\FOO` are one object; and a trailing separator is a caller's habit rather than part
/// of a name. Neither is true of a *prefix*: a link to `\Device\HarddiskVolume1\dir` is not a
/// link to `\Device\HarddiskVolume1`, and matching it as one would report a volume as reachable
/// under a name that opens a file on it.
pub(crate) fn same_object_path(one: &str, other: &str) -> bool {
    let trim = |path: &str| upcase(path.trim_end_matches('\\'));
    trim(one) == trim(other)
}

/// A name folded the way the object manager folds one: **one UTF-16 code unit in, one out.**
///
/// Read out of `nt!ObpLookupDirectoryEntry` on 26100 rather than assumed, because the first two
/// goes at this were assumed and both were wrong. It compares a name one `WCHAR` at a time, in
/// three bands: `U+0061`..`U+007A` gets `0x20` subtracted inline; **anything else below `U+00C0`
/// is not folded at all**, no table being consulted for it; and at or above `U+00C0` the code unit
/// indexes `UnicodeUpcaseTable844`, an 8-4-4 trie -- high byte, then middle nibble, then low
/// nibble -- whose leaf is a delta added to the code unit. One unit in, one out, no expansion, no
/// context. Case-insensitively, because `nt!ObpCaseInsensitive` is 1 on that build.
///
/// **Rust's `to_lowercase` is the *full* Unicode mapping, and it is wrong in both directions**,
/// which is how two consecutive rounds of review arrived here. It **expands**: `U+0130` lowercases
/// to `i` followed by `U+0307`, so that name and the two-code-unit spelling of it -- two objects to
/// the kernel -- compared equal, and a link to one would be reported as reaching the other. And it
/// is **contextual**: a sigma at the end of a word lowercases to the final form and elsewhere to
/// the medial one, so two spellings the kernel folds together compared unequal, dropping a link
/// that does reach the device while the search still called itself complete.
///
/// So the bands above are reproduced, and each earns its place. Keeping only single-code-unit
/// results is what makes this one-to-one, and it is why `U+00DF` stays put instead of becoming
/// `SS`. The `U+00C0` floor is why `U+00B5` stays put too, its Unicode uppercase being a Greek
/// capital mu and so a change of script the kernel's table does not make. A surrogate is left alone
/// because a `WCHAR` fold is handed half a character at a time and cannot fold a non-BMP letter, so
/// two spellings of one Deseret name are genuinely two objects and folding over scalar values would
/// merge them.
///
/// **What this is not is the target's own table.** That is
/// `PsGetCurrentServerSiloGlobals()->RtlNlsState.UnicodeUpcaseTable844`, which is per-silo and
/// wants a debugger -- and this module deliberately has none, so that every pass here is testable
/// without one. What the substitution leaves is the Unicode version behind each table, for code
/// units at or above `U+00C0`: the silo's is frozen at the target's build and this one moves with
/// the toolchain.
fn upcase(name: &str) -> Vec<u16> {
    name.encode_utf16()
        .map(|unit| match unit {
            // The comparison's own fast path, written the way it writes it.
            0x61..=0x7a => unit - 0x20,
            // Below the floor the kernel reaches for no table, so neither does this.
            0..=0xbf => unit,
            _ => {
                // A surrogate is not a scalar value, so this is also the non-BMP case: the half
                // goes through unfolded, as the kernel's per-`WCHAR` fold leaves it.
                let Some(one) = char::from_u32(u32::from(unit)) else {
                    return unit;
                };
                let mut upper = one.to_uppercase();
                match (upper.next(), upper.next()) {
                    (Some(only), None) => u16::try_from(u32::from(only)).unwrap_or(unit),
                    _ => unit,
                }
            }
        })
        .collect()
}

/// One ACE, as fields a caller can branch on.
fn access_entry(ace: &crate::sd::Ace) -> crate::structured::AccessEntry {
    // **Only an access mask is named as access.** A mandatory label and a scoped policy id carry
    // something else in the same four bytes, and putting those through a table of file rights
    // reports a label's `NO_WRITE_UP` as `FILE_READ_DATA` with `reads: true` -- a bit that says
    // the opposite of what it is printed as. The raw `mask` is carried either way, so nothing is
    // lost by declining to name it.
    let access = ace.kind.mask_is_access();
    // **An inherit-only entry is not applied to the object carrying it.** Its mask says what a
    // child would get, and the access check on this device skips it entirely -- so an inherit-only
    // deny read as effective reports a device nobody may open, and an inherit-only allow reports a
    // grant that does not exist. `reads` and `writes` are about *this* device's gate, which is why
    // they go false here while `rights` still names the mask: the mask is real, its application to
    // this object is not.
    let inherit_only = ace.flags & crate::sd::INHERIT_ONLY_ACE != 0;
    let (reads, writes) = match access && !inherit_only {
        true => crate::sd::data_access(ace.mask),
        false => (false, false),
    };
    let rights = match (access, ace.kind) {
        (true, _) => crate::sd::rights(ace.mask),
        (false, crate::sd::AceKind::Label) => crate::sd::label_policy(ace.mask),
        (false, _) => Vec::new(),
    };
    crate::structured::AccessEntry {
        kind: ace.kind.name().to_string(),
        ace_type: ace.ace_type,
        flags: ace.flags,
        sid: ace.sid.as_ref().map(|sid| sid.text.clone()),
        account: ace
            .sid
            .as_ref()
            .and_then(|sid| sid.name)
            .map(str::to_string),
        conditional: ace.conditional,
        callback: ace.callback,
        inherit_only,
        principal_unreadable: ace.kind.carries_sid() && ace.sid.is_none(),
        mask: format!("{:#010x}", ace.mask),
        rights: rights.into_iter().map(str::to_string).collect(),
        reads,
        writes,
    }
}

fn access_list(acl: &crate::sd::Acl) -> crate::structured::AccessControlList {
    crate::structured::AccessControlList {
        revision: acl.revision,
        ace_count: acl.ace_count,
        entries: acl.aces.iter().map(access_entry).collect(),
    }
}

/// The answer, as a value.
pub(crate) fn structured_report(found: &Found) -> crate::structured::DeviceSecurity {
    let security = match &found.security {
        Security::Read { at, descriptor } => Some(crate::structured::SecurityDescriptor {
            address: format!("{at:#018x}"),
            revision: descriptor.revision,
            control: format!("{:#06x}", descriptor.control),
            owner: descriptor.owner.as_ref().map(|sid| sid.text.clone()),
            owner_account: descriptor
                .owner
                .as_ref()
                .and_then(|sid| sid.name)
                .map(str::to_string),
            group: descriptor.group.as_ref().map(|sid| sid.text.clone()),
            group_account: descriptor
                .group
                .as_ref()
                .and_then(|sid| sid.name)
                .map(str::to_string),
            dacl_present: descriptor.dacl_present(),
            dacl: descriptor.dacl.as_ref().map(access_list),
            sacl: descriptor.sacl.as_ref().map(access_list),
        }),
        _ => None,
    };
    let security_absent = match &found.security {
        Security::Read { .. } => None,
        Security::Absent => Some(
            "this object carries no security descriptor, so the object manager checks the \
             directory holding it rather than the object"
                .to_string(),
        ),
        Security::Failed { at, why } => Some(format!(
            "the descriptor at {at:#018x} could not be read: {why}"
        )),
    };
    crate::structured::DeviceSecurity {
        device: found.device.clone(),
        followed_link: found.followed_link.clone(),
        address: format!("{:#018x}", found.address),
        driver: format!("{:#018x}", found.fields.driver),
        device_type: format!("{:#06x}", found.fields.device_type),
        characteristics: format!("{:#010x}", found.fields.characteristics),
        secure_open: found.fields.secure_open,
        flags: format!("{:#010x}", found.fields.flags),
        exclusive: found.fields.exclusive,
        security,
        security_absent,
        link_directory: found.link_directory.clone(),
        links: found
            .links
            .iter()
            .map(|link| crate::structured::DeviceLink {
                path: link.path.clone(),
                target: link.target.clone(),
            })
            .collect(),
        link_search: found.link_search,
        links_examined: found.links_examined,
        links_unnamed: found.links_unnamed,
        links_unread: found.links_unread,
        stopped: found.stopped.map(|halt| match halt {
            crate::walk::Halt::Deadline => crate::structured::WalkHalt::Deadline,
            crate::walk::Halt::Interrupted => crate::structured::WalkHalt::Interrupted,
        }),
    }
}

/// The same answer for a person to read.
pub(crate) fn render(report: &crate::structured::DeviceSecurity) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "{} at {}", report.device, report.address);
    if let Some(link) = &report.followed_link {
        let _ = writeln!(out, "  reached by following {link}");
    }
    let _ = writeln!(out, "  Driver          {}", report.driver);
    let _ = writeln!(out, "  DeviceType      {}", report.device_type);
    let _ = writeln!(
        out,
        "  Characteristics {}{}",
        report.characteristics,
        match report.secure_open {
            true => "  FILE_DEVICE_SECURE_OPEN",
            false => "",
        }
    );
    let _ = writeln!(
        out,
        "  Flags           {}{}",
        report.flags,
        match report.exclusive {
            true => "  DO_EXCLUSIVE",
            false => "",
        }
    );
    // Said where it is true rather than left to be inferred from an absent word. Whether the
    // descriptor below is checked on a *relative* open is the difference between a gate and a
    // gate with a way around it, and it is the one line here a reader is most likely to act on.
    if !report.secure_open {
        let _ = writeln!(
            out,
            "  [!] no FILE_DEVICE_SECURE_OPEN: the descriptor below is checked when this device \
             is opened by name, and not when a path beneath it is opened -- so a driver that \
             parses its own paths can be reached by a caller the descriptor would refuse"
        );
    }

    match (&report.security, &report.security_absent) {
        (Some(security), _) => {
            let _ = writeln!(out, "  Security descriptor at {}", security.address);
            for (what, sid, account) in [
                ("Owner", &security.owner, &security.owner_account),
                ("Group", &security.group, &security.group_account),
            ] {
                if let Some(sid) = sid {
                    let _ = writeln!(
                        out,
                        "    {what}  {sid}{}",
                        account
                            .as_ref()
                            .map(|name| format!(" ({name})"))
                            .unwrap_or_default()
                    );
                }
            }
            // **Four states, and three of them are the permissive ones a renderer must not
            // blur.** `None` here never means "could not be read" -- a DACL whose bytes would not
            // read fails the whole descriptor, which arrives as `Security::Failed` and is printed
            // above. So the only way to reach `None` is an absent list, and both ways of being
            // absent grant every caller everything. Saying "this could not be read" of either,
            // which is what this did, reports the most permissive device there is as an
            // unanswered question.
            match (&security.dacl, security.dacl_present) {
                (None, false) => {
                    let _ = writeln!(
                        out,
                        "    [!] no DACL at all: every caller is granted every access to this \
                         device"
                    );
                }
                (None, true) => {
                    let _ = writeln!(
                        out,
                        "    [!] a NULL DACL: the list is present and empty of restrictions, so \
                         every caller is granted every access to this device"
                    );
                }
                // The opposite extreme, and it looks almost the same in a listing: a DACL with no
                // entries grants nobody anything. Rendered as `0 ACE(s)` alone it reads like the
                // cases above rather than like their inverse.
                (Some(dacl), _) if dacl.entries.is_empty() && dacl.ace_count == 0 => {
                    let _ = writeln!(
                        out,
                        "    [!] an empty DACL: every caller is denied every access to this \
                         device"
                    );
                }
                (Some(dacl), _) => render_acl(&mut out, "DACL", dacl),
            }
            if let Some(sacl) = &security.sacl {
                render_acl(&mut out, "SACL", sacl);
            }
        }
        (None, Some(why)) => {
            let _ = writeln!(out, "  [!] {why}");
        }
        // Neither, which the report builder does not produce -- said rather than rendered as a
        // device with no gate, because that is the reading to never print by accident.
        (None, None) => {
            let _ = writeln!(out, "  [!] nothing was read about this device's security");
        }
    }

    match report.link_search {
        crate::structured::LinkSearch::Unavailable => {
            let _ = writeln!(
                out,
                "  [!] {} could not be listed, so nothing here says whether this device is \
                 reachable from user mode",
                report.link_directory
            );
        }
        search => {
            if report.links.is_empty() {
                // **The absolute claim is the completed search's alone.** Under `Partial` the
                // warnings below already say the search fell short, and this line contradicted
                // them in the sentence a reader meets first -- which is the half an MCP client
                // renders, so the qualification arrived after the conclusion it was there to
                // prevent.
                let _ = match search {
                    crate::structured::LinkSearch::Complete => writeln!(
                        out,
                        "  No symbolic link in {} points at this device",
                        report.link_directory
                    ),
                    _ => writeln!(
                        out,
                        "  No symbolic link among the entries of {} that were checked points at \
                         this device",
                        report.link_directory
                    ),
                };
            } else {
                let _ = writeln!(out, "  Reachable as:");
                for link in &report.links {
                    let _ = writeln!(out, "    {}  -> {}", link.path, link.target);
                }
            }
            let unchecked = report.links_unnamed + report.links_unread;
            if unchecked > 0 {
                let _ = writeln!(
                    out,
                    "  [!] {unchecked} of {}'s entries could not be checked ({} this could not \
                     name, {} whose type or target would not read), so any of them may reach \
                     this device",
                    report.link_directory, report.links_unnamed, report.links_unread
                );
            }
            // **Only a search that halted stopped part-way.** `Partial` covers a second case
            // since the completeness fix -- the directory was enumerated to its end and some
            // entries could not be checked -- and this sentence, written when `Partial` meant
            // only the first, reported that common case as a deadline or an interrupt. The count
            // above already says what went unchecked, so there is nothing to add when nothing
            // halted.
            if report.stopped.is_some() {
                let _ = writeln!(
                    out,
                    "  [!] the search of {} stopped part-way, so this is some of the links rather \
                     than all of them",
                    report.link_directory
                );
            }
        }
    }
    if let Some(stopped) = &report.stopped {
        let _ = writeln!(
            out,
            "  [!] stopped early ({})",
            match stopped {
                crate::structured::WalkHalt::Deadline => "the call's clock ran out",
                crate::structured::WalkHalt::Interrupted => "interrupted",
            }
        );
    }
    out
}

fn render_acl(out: &mut String, what: &str, acl: &crate::structured::AccessControlList) {
    use std::fmt::Write as _;
    let short = match acl.entries.len() < acl.ace_count {
        true => format!(", {} listed", acl.entries.len()),
        false => String::new(),
    };
    let _ = writeln!(out, "    {what}  {} ACE(s){short}", acl.ace_count);
    for entry in &acl.entries {
        let _ = writeln!(
            out,
            "      {:<6} {:<28} {}  {}",
            entry.kind,
            entry
                .account
                .clone()
                .or_else(|| entry.sid.clone())
                .unwrap_or_else(|| match entry.principal_unreadable {
                    // **Not the same as an ACE that has none.** This entry grants its mask to
                    // somebody, and the bytes naming them did not parse -- so who it lets in is
                    // unknown rather than nobody, which is what `<no principal>` reads as.
                    true => "<principal did not parse>".to_string(),
                    false => "<no principal>".to_string(),
                }),
            entry.mask,
            {
                let rights = entry.rights.join(" ");
                // `[if]` is a claim that there *is* an expression, so it is kept for the
                // entries that carry one. A callback ACE without the signature gets a word that
                // says a decision is made elsewhere without saying what it is -- where plain
                // rights would read as an entry that simply applies.
                match (entry.conditional, entry.callback, entry.inherit_only) {
                    (_, _, true) => format!("[inherit-only] {rights}"),
                    (true, _, false) => format!("[if] {rights}"),
                    (false, true, false) => format!("[callback] {rights}"),
                    (false, false, false) => rights,
                }
            }
        );
    }
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
            security: 0x110,
        }
    }

    /// A device object as `IoCreateDevice` would have left it, with no descriptor.
    fn device(device_type: u32, characteristics: u32, flags: u32, driver: u64) -> Vec<u8> {
        let mut bytes = vec![0u8; 0x150];
        bytes[0x08..0x10].copy_from_slice(&driver.to_le_bytes());
        bytes[0x30..0x34].copy_from_slice(&flags.to_le_bytes());
        bytes[0x34..0x38].copy_from_slice(&characteristics.to_le_bytes());
        bytes[0x48..0x4c].copy_from_slice(&device_type.to_le_bytes());
        bytes
    }

    /// The same, with a descriptor at `+0x110` -- the measured offset, written out rather than
    /// taken from `layout()`, for the reason `layout()` itself gives.
    fn guarded(driver: u64, descriptor: u64) -> Vec<u8> {
        let mut bytes = device(0x12, FILE_DEVICE_SECURE_OPEN, 0, driver);
        bytes[0x110..0x118].copy_from_slice(&descriptor.to_le_bytes());
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

    /// **The descriptor comes from the device object's own field, and is not the driver
    /// pointer.**
    ///
    /// The two are the only pointers this reads and they are 0x108 bytes apart, so an offset
    /// taken from the wrong one of them yields a plausible kernel address either way -- and a
    /// driver object parsed as a security descriptor is refused by `crate::sd` for its revision
    /// byte, which would report a guarded device as one whose descriptor will not read.
    ///
    /// A zero field is `None` and means the device carries none, which is a real state and a
    /// different one from a device that would not read at all.
    #[test]
    fn the_descriptor_is_the_devices_own_field_and_not_its_driver() {
        let guarded = read_device(
            AT,
            layout(),
            serving(guarded(0xffff_b000_0000_0000, 0xffff_8680_fc69_12a0)),
        )
        .expect("the device reads");
        assert_eq!(
            (guarded.driver, guarded.security_descriptor),
            (0xffff_b000_0000_0000, Some(0xffff_8680_fc69_12a0)),
            "each pointer comes from its own field"
        );

        let bare = read_device(
            AT,
            layout(),
            serving(device(0x12, 0, 0, 0xffff_b000_0000_0000)),
        )
        .expect("the device reads");
        assert_eq!(
            (bare.driver, bare.security_descriptor),
            (0xffff_b000_0000_0000, None),
            "and an empty descriptor field is None rather than the driver read twice"
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

    /// A device as [`Found`] would carry it, with everything benign, so each test below moves
    /// exactly the one thing it is about.
    fn found() -> Found {
        Found {
            device: "\\Device\\MountPointManager".to_string(),
            followed_link: None,
            address: AT,
            fields: Device {
                device_type: 0x2d,
                characteristics: FILE_DEVICE_SECURE_OPEN,
                secure_open: true,
                exclusive: false,
                flags: 0x40,
                driver: 0xffff_b000_0000_0000,
                security_descriptor: Some(0xffff_8680_fc69_12a0),
            },
            security: Security::Read {
                at: 0xffff_8680_fc69_12a0,
                descriptor: descriptor(Some(acl(vec![ace(
                    crate::sd::AceKind::Allow,
                    "S-1-1-0",
                    Some("Everyone"),
                    0x0012_00a0,
                )]))),
            },
            link_directory: "\\GLOBAL??".to_string(),
            links: vec![Link {
                path: "\\GLOBAL??\\MountPointManager".to_string(),
                target: "\\Device\\MountPointManager".to_string(),
            }],
            link_search: crate::structured::LinkSearch::Complete,
            links_examined: Some(400),
            links_unnamed: 0,
            links_unread: 0,
            stopped: None,
        }
    }

    fn ace(
        kind: crate::sd::AceKind,
        sid: &str,
        name: Option<&'static str>,
        mask: u32,
    ) -> crate::sd::Ace {
        crate::sd::Ace {
            kind,
            ace_type: match kind {
                crate::sd::AceKind::Allow => 0,
                crate::sd::AceKind::Deny => 1,
                _ => 2,
            },
            flags: 0,
            mask,
            conditional: false,
            callback: false,
            sid: Some(crate::sd::Sid {
                text: sid.to_string(),
                name,
            }),
        }
    }

    fn acl(aces: Vec<crate::sd::Ace>) -> crate::sd::Acl {
        crate::sd::Acl {
            revision: 2,
            ace_count: aces.len(),
            aces,
        }
    }

    /// A self-relative descriptor with `SE_DACL_PRESENT` set exactly when it has a DACL, which is
    /// what makes the NULL-DACL test below about the control bit rather than about a missing field.
    fn descriptor(dacl: Option<crate::sd::Acl>) -> crate::sd::Descriptor {
        crate::sd::Descriptor {
            revision: 1,
            control: match dacl {
                Some(_) => 0x8004,
                None => 0x8000,
            },
            owner: Some(crate::sd::Sid {
                text: "S-1-5-32-544".to_string(),
                name: Some("Administrators"),
            }),
            group: None,
            dacl,
            sacl: None,
        }
    }

    /// **Two paths naming one object, and two that do not.** The object manager is
    /// case-insensitive and a trailing separator is a caller's habit -- but a *prefix* is a
    /// different object, and matching one as this device would report a volume as reachable under
    /// a name that opens a file on it.
    #[test]
    fn a_link_target_matches_the_device_it_names_and_not_the_one_it_is_inside() {
        assert!(same_object_path(
            "\\Device\\MountPointManager",
            "\\DEVICE\\MOUNTPOINTMANAGER"
        ));
        assert!(same_object_path(
            "\\Device\\MountPointManager\\",
            "\\Device\\MountPointManager"
        ));
        assert!(
            !same_object_path(
                "\\Device\\MountPointManager\\sub",
                "\\Device\\MountPointManager"
            ),
            "a link into the device is not a link to it"
        );
        assert!(
            !same_object_path(
                "\\Device\\MountPointManagerExtra",
                "\\Device\\MountPointManager"
            ),
            "nor is a longer name beginning with it"
        );

        // **And the fold is not ASCII's.** The object manager compares through the system's
        // uppercase table, which covers every letter that has a case -- so folding A to Z alone
        // leaves two spellings of one object unequal, drops the link that reaches it, and lets
        // the search call itself complete having missed it.
        assert!(
            same_object_path("\\Device\\Käse", "\\Device\\KÄSE"),
            "a name differing only in the case of a non-ASCII letter is the same object"
        );
    }

    /// The fields a caller branches on come through as fields, and the principal comes through
    /// twice: as the SID it is and as the account it reads as.
    #[test]
    fn the_report_carries_the_gate_as_values() {
        let report = structured_report(&found());
        assert_eq!(
            (
                report.device.as_str(),
                report.secure_open,
                report.exclusive,
                report.characteristics.as_str(),
                report.flags.as_str()
            ),
            (
                "\\Device\\MountPointManager",
                true,
                false,
                "0x00000100",
                "0x00000040"
            )
        );
        let dacl = report
            .security
            .as_ref()
            .and_then(|security| security.dacl.as_ref())
            .expect("the fixture has a DACL");
        let entry = &dacl.entries[0];
        assert_eq!(
            (
                entry.kind.as_str(),
                entry.sid.as_deref(),
                entry.account.as_deref(),
                entry.mask.as_str()
            ),
            ("allow", Some("S-1-1-0"), Some("Everyone"), "0x001200a0")
        );
        assert_eq!(
            (entry.reads, entry.writes),
            (false, false),
            "0x1200a0 carries neither FILE_READ_DATA nor FILE_WRITE_DATA, which is the join to an \
             IOCTL map and has to be read off the mask rather than off the word `allow`"
        );
    }

    /// **The four states a DACL can be in, three of which are about who is let in and only one
    /// of which restricts anybody.**
    ///
    /// No DACL at all and a NULL DACL both grant every caller every access, and an empty DACL --
    /// present, with no entries -- denies everyone. Those are the extremes of the range, and in a
    /// listing the last of them prints as `0 ACE(s)`, which reads like the first two rather than
    /// like their inverse.
    ///
    /// **There is no "could not read it" state here, and believing there was is what this test is
    /// for.** A DACL whose bytes will not read fails the whole descriptor, which arrives as
    /// [`Security::Failed`]; `dacl: None` with the present bit set can only be the offset being
    /// zero, which is the NULL DACL. This renderer said "a DACL is present and this could not read
    /// it" for exactly that, reporting the most permissive device there is as an unanswered
    /// question -- and the first version of this test asserted that wording, which is how a
    /// careful-looking test came to pin the defect.
    #[test]
    fn every_way_a_dacl_can_be_absent_says_who_that_lets_in() {
        let with = |dacl: Option<crate::sd::Acl>, control: u16| {
            let mut descriptor = descriptor(dacl);
            descriptor.control = control;
            render(&structured_report(&Found {
                security: Security::Read {
                    at: 0xffff_8680_fc69_12a0,
                    descriptor,
                },
                ..found()
            }))
        };

        // SE_SELF_RELATIVE alone: no DACL at all.
        let none = with(None, 0x8000);
        assert!(none.contains("no DACL at all"), "{none}");
        assert!(none.contains("granted every access"), "{none}");

        // SE_SELF_RELATIVE | SE_DACL_PRESENT with nothing behind it: a NULL DACL.
        let null = with(None, 0x8004);
        assert!(null.contains("NULL DACL"), "{null}");
        assert!(
            null.contains("granted every access"),
            "a NULL DACL is the most permissive object there is, not an unread one: {null}"
        );
        assert!(
            !null.contains("could not read"),
            "and saying so is the defect this test exists for: {null}"
        );

        // Present, and holding nothing: the opposite extreme.
        let empty = with(Some(acl(vec![])), 0x8004);
        assert!(
            empty.contains("denied every access"),
            "an empty DACL denies everyone, which `0 ACE(s)` alone does not say: {empty}"
        );

        // And a DACL with entries is rendered as entries, not as any of the above.
        let real = render(&structured_report(&found()));
        assert!(
            real.contains("1 ACE(s)") && real.contains("Everyone"),
            "{real}"
        );
        for absent in ["no DACL at all", "NULL DACL", "denied every access"] {
            assert!(
                !real.contains(absent),
                "{absent} was printed for a real DACL: {real}"
            );
        }
    }

    /// **An ACE whose principal did not parse is not an ACE with no principal.**
    ///
    /// `sid_from` is given bytes out of target memory, so a SID whose revision is not 1 or whose
    /// sub-authority count runs past the entry is a thing a corrupt or hostile descriptor
    /// produces. The entry still grants its mask -- to somebody nobody can name -- and rendering
    /// that as `<no principal>`, which is what an ACE this reader cannot place its SID in gets,
    /// reads as "this grants nothing to nobody".
    #[test]
    fn an_ace_whose_principal_did_not_parse_is_not_one_that_has_none() {
        let mut torn = ace(
            crate::sd::AceKind::Allow,
            "S-1-1-0",
            Some("Everyone"),
            0x1f01ff,
        );
        torn.sid = None;
        let entry = access_entry(&torn);
        assert!(
            entry.principal_unreadable,
            "an allow entry always carries a principal, so an absent one did not parse: {entry:?}"
        );

        // An object ACE is the other case: this reader does not look where its SID is, and
        // nothing is wrong with the entry.
        let mut placed = ace(crate::sd::AceKind::Other(0x05), "S-1-1-0", None, 0x1f01ff);
        placed.sid = None;
        assert!(
            !access_entry(&placed).principal_unreadable,
            "an object ACE's SID is somewhere this does not read, which is not a fault"
        );

        // And the two render differently, which is the point of telling them apart at all.
        let with = |entry: crate::structured::AccessEntry| {
            let mut out = String::new();
            render_acl(
                &mut out,
                "DACL",
                &crate::structured::AccessControlList {
                    revision: 2,
                    ace_count: 1,
                    entries: vec![entry],
                },
            );
            out
        };
        assert!(with(access_entry(&torn)).contains("did not parse"));
        assert!(with(access_entry(&placed)).contains("<no principal>"));
    }

    /// **An entry whose type the namespace could not read may be the link.**
    ///
    /// `None` is "this walk could not say", which is a third answer beside "a link" and "not a
    /// link" -- and folding it into the second makes an entry vanish from the search with neither
    /// unchecked counter seeing it, leaving `complete` claimable over a directory that was not
    /// fully checked.
    #[test]
    fn an_entry_of_unknown_type_is_unchecked_rather_than_not_a_link() {
        assert_eq!(candidate(Some("SymbolicLink")), Candidate::Link);
        assert_eq!(candidate(Some("Device")), Candidate::Other);
        assert_eq!(
            candidate(None),
            Candidate::Unknown,
            "a type that would not read is not a type that is not a link"
        );
    }

    /// **The absolute claim belongs to a completed search.**
    ///
    /// "No symbolic link points at this device" is the sentence an MCP client renders first, and
    /// under a partial search it contradicted the warning printed below it -- the qualification
    /// arriving after the conclusion it was there to prevent.
    #[test]
    fn no_links_found_is_only_stated_absolutely_when_everything_was_checked() {
        let rendered = |search, unnamed| {
            render(&structured_report(&Found {
                links: vec![],
                link_search: search,
                links_unnamed: unnamed,
                ..found()
            }))
        };
        let complete = rendered(crate::structured::LinkSearch::Complete, 0);
        assert!(
            complete.contains("No symbolic link in"),
            "a completed search says it plainly: {complete}"
        );

        let partial = rendered(crate::structured::LinkSearch::Partial, 1);
        assert!(
            partial.contains("among the entries") && partial.contains("that were checked"),
            "and a partial one says what it checked instead: {partial}"
        );
        assert!(
            !partial.contains("No symbolic link in "),
            "never the absolute claim: {partial}"
        );
    }

    /// **The fold is the object manager's, and the nearest `str` method is not it.**
    ///
    /// Five constructions, because the two rounds that landed here broke in opposite directions
    /// and each property fails on a case the others reach right past. What is *not* pinned below is
    /// the direction: the kernel upcases, and no construction this is sure of tells a one-to-one
    /// uppercase from a one-to-one lowercase, so that rests on reading the fold out of
    /// `nt!ObpLookupDirectoryEntry` rather than on an assertion.
    #[test]
    fn a_name_is_folded_one_code_unit_at_a_time_as_the_object_manager_folds_it() {
        // **Expansion, downwards.** `to_lowercase` turns `U+0130` into `i` and `U+0307`, which is
        // code unit for code unit the other name -- so these compared equal, and a link to one was
        // reported as reaching the other.
        assert!(
            !same_object_path("\\Device\\\u{0130}", "\\Device\\i\u{0307}"),
            "a fold that expands makes one object out of two"
        );

        // **Context.** `to_lowercase` picks the final sigma at the end of a word and the medial one
        // elsewhere, so these compared unequal -- dropping a link that does reach the device while
        // the search reported itself complete. Both upcase to `U+03A3`.
        assert!(
            same_object_path("\\Device\\\u{0391}\u{03A3}", "\\Device\\\u{0391}\u{03C3}"),
            "one object spelt with either sigma is still one object"
        );

        // **Expansion, upwards**, which the case above does not reach: `U+00DF` fully uppercases to
        // `SS`, and the kernel's one-to-one table leaves it alone.
        assert!(
            !same_object_path("\\Device\\\u{00df}", "\\Device\\SS"),
            "a one-to-one fold does not turn one letter into two"
        );

        // **A surrogate pair is not a letter to a `WCHAR` fold.** The kernel cannot case-fold a
        // non-BMP letter at all, so these are two objects; folding over scalar values would merge
        // them.
        assert!(
            !same_object_path("\\Device\\\u{10400}", "\\Device\\\u{10428}"),
            "what the kernel cannot fold, this does not fold either"
        );

        // **The floor at `U+00C0`.** `U+00B5` is below it, so the comparison consults no table and
        // leaves it alone -- where Unicode would fold it to `U+039C`, a Greek capital mu, changing
        // its script on the way. Two objects to the kernel.
        assert!(
            !same_object_path("\\Device\\\u{00b5}", "\\Device\\\u{039c}"),
            "a fold the kernel does not reach for is not one to make here"
        );
    }

    /// **What the rendering claims about an entry, which is the half a client reads.**
    ///
    /// None of the four markers had a test, and the round that added the fourth is the round that
    /// found the third was wrong: every callback ACE was printed `[if]`, which says a conditional
    /// *expression* is there, on nothing but the ACE type. Pinned here rather than only at the
    /// decode, because a correct field rendered under the wrong word is the same wrong answer.
    #[test]
    fn the_markers_say_what_decides_an_entry_and_do_not_overstate_it() {
        let marked = |conditional: bool, callback: bool, inherit_only: bool| {
            let mut entry = access_entry(&ace(
                crate::sd::AceKind::Allow,
                "S-1-1-0",
                Some("Everyone"),
                0x0012_00a0,
            ));
            entry.conditional = conditional;
            entry.callback = callback;
            entry.inherit_only = inherit_only;
            let acl = crate::structured::AccessControlList {
                revision: 2,
                ace_count: 1,
                entries: vec![entry],
            };
            let mut out = String::new();
            render_acl(&mut out, "DACL", &acl);
            out
        };

        let plain = marked(false, false, false);
        assert!(
            !plain.contains('['),
            "an entry that simply applies is marked with nothing: {plain}"
        );

        let conditional = marked(true, true, false);
        assert!(
            conditional.contains("[if]"),
            "an expression the kernel evaluates is the one thing `[if]` is for: {conditional}"
        );

        // The finding this round: without the `artx` signature there is no expression, so `[if]`
        // would be inventing one -- and plain rights would read as an entry that simply applies,
        // which it does not.
        let opaque = marked(false, true, false);
        assert!(
            opaque.contains("[callback]") && !opaque.contains("[if]"),
            "an application-defined callback is not an expression, and is not nothing: {opaque}"
        );

        // And inheritance wins over both, because neither says anything about *this* device.
        let inherited = marked(true, true, true);
        assert!(
            inherited.contains("[inherit-only]") && !inherited.contains("[if]"),
            "an entry not applied to this device is not a condition on opening it: {inherited}"
        );
    }

    /// **An inherit-only entry decides nothing about this device.**
    ///
    /// `INHERIT_ONLY_ACE` means the entry exists to be handed to children and is skipped by the
    /// access check on the object carrying it. The renderer does not print the flags byte, so
    /// without this an inherit-only deny reads as a device nobody may open and an inherit-only
    /// allow as a grant that is not there.
    #[test]
    fn an_inherit_only_entry_grants_nothing_on_the_device_carrying_it() {
        let mut only = ace(
            crate::sd::AceKind::Allow,
            "S-1-1-0",
            Some("Everyone"),
            0x001f_01ff,
        );
        only.flags = crate::sd::INHERIT_ONLY_ACE;
        let entry = access_entry(&only);
        assert!(entry.inherit_only, "{entry:?}");
        assert_eq!(
            (entry.reads, entry.writes),
            (false, false),
            "the two that answer \"can this handle send a control code\" are about *this* \
             device, and this entry is not applied to it: {entry:?}"
        );
        assert!(
            entry.rights.contains(&"FILE_READ_DATA".to_string()),
            "while the mask is still named, since that is what a child would be given: {entry:?}"
        );

        // The same ACE without the flag is an effective grant, which is the reading the one above
        // must not get.
        let effective = access_entry(&ace(
            crate::sd::AceKind::Allow,
            "S-1-1-0",
            Some("Everyone"),
            0x001f_01ff,
        ));
        assert_eq!((effective.reads, effective.writes), (true, true));
        assert!(!effective.inherit_only);
    }

    /// **Two sentences that outlived the meanings they described.**
    ///
    /// Both are debris from earlier rounds of this change rather than original defects, which is
    /// the failure worth pinning: the count was widened to cover an entry whose *type* would not
    /// read, and `Partial` was widened to cover a search that ran to the end and could not check
    /// everything -- and the prose describing each stayed as it was. So a target with no type
    /// information was told its link *targets* were unreadable, and an ordinary completed search
    /// was told it had been cut short by a deadline.
    #[test]
    fn the_warnings_describe_what_the_counts_and_the_verdict_now_mean() {
        let unresolved = render(&structured_report(&Found {
            links: vec![],
            link_search: crate::structured::LinkSearch::Partial,
            links_unread: 2,
            stopped: None,
            ..found()
        }));
        assert!(
            unresolved.contains("type or target would not read"),
            "the count covers a type that would not read as well: {unresolved}"
        );
        assert!(
            !unresolved.contains("stopped part-way"),
            "and a search that ran to the end did not stop: {unresolved}"
        );

        let halted = render(&structured_report(&Found {
            links: vec![],
            link_search: crate::structured::LinkSearch::Partial,
            stopped: Some(crate::walk::Halt::Deadline),
            ..found()
        }));
        assert!(
            halted.contains("stopped part-way"),
            "while one that halted says so: {halted}"
        );
    }

    /// **A mask is named as access only when it is one.**
    ///
    /// A mandatory integrity label carries `NO_WRITE_UP` / `NO_READ_UP` / `NO_EXECUTE_UP` in the
    /// four bytes an allow entry uses for an access mask. Put through the device-rights table,
    /// `NO_WRITE_UP` (bit 0) comes out as `FILE_READ_DATA` with `reads: true` -- so a device
    /// carrying a label would answer that its caller may read its data, off a bit that restricts
    /// them. The label's own three bits are named instead, and `reads`/`writes` are false because
    /// there is no access in that mask to have.
    #[test]
    fn a_label_is_not_an_allow_and_its_mask_is_not_rights() {
        let label = access_entry(&ace(
            crate::sd::AceKind::Label,
            "S-1-16-8192",
            Some("Medium Mandatory Level"),
            0x0000_0001,
        ));
        assert_eq!(
            (label.kind.as_str(), label.reads, label.writes),
            ("label", false, false),
            "bit 0 of a label is NO_WRITE_UP, not FILE_READ_DATA: {label:?}"
        );
        assert_eq!(label.rights, vec!["NO_WRITE_UP".to_string()]);
        assert_eq!(
            label.mask, "0x00000001",
            "and the raw mask is carried either way, so naming nothing costs nothing"
        );

        // The same bit on an entry whose mask really is an access mask.
        let allow = access_entry(&ace(
            crate::sd::AceKind::Allow,
            "S-1-1-0",
            Some("Everyone"),
            0x0000_0001,
        ));
        assert_eq!(
            (
                allow.kind.as_str(),
                allow.reads,
                allow.rights.first().map(String::as_str)
            ),
            ("allow", true, Some("FILE_READ_DATA")),
            "which is the reading the label must not get: {allow:?}"
        );
    }

    /// **An object with no descriptor and a descriptor that would not read are different facts.**
    /// A kernel minidump answers the second for every object in it, and reporting that as a device
    /// nothing guards is the one reading this must never produce.
    #[test]
    fn a_descriptor_that_will_not_read_is_not_a_device_with_no_descriptor() {
        let mut found = found();
        found.security = Security::Absent;
        let absent = structured_report(&found);
        assert!(absent.security.is_none());
        assert!(
            absent
                .security_absent
                .as_deref()
                .expect("a reason")
                .contains("carries no security descriptor")
        );

        found.security = Security::Failed {
            at: 0xffff_8680_fc69_12a0,
            why: crate::sd::SdError::Unreadable {
                at: 0xffff_8680_fc69_12a0,
                len: 20,
            },
        };
        let failed = structured_report(&found);
        assert!(failed.security.is_none());
        let why = failed.security_absent.as_deref().expect("a reason");
        assert!(why.contains("could not be read"), "{why}");
        assert!(
            !why.contains("carries no security descriptor"),
            "the two outcomes must not read alike: {why}"
        );
    }

    /// **A short list of links must not read as a complete one.** An empty list under
    /// `Complete` is a fact -- nothing reaches this device; under anything else it is an absence,
    /// and the difference is what decides whether a device looks unreachable from user mode.
    #[test]
    fn a_link_search_that_saw_less_than_the_directory_says_so() {
        let complete = render(&structured_report(&Found {
            links: vec![],
            ..found()
        }));
        assert!(
            complete.contains("No symbolic link in"),
            "a completed search that found none says so plainly: {complete}"
        );
        assert!(!complete.contains("[!]"), "and warns about nothing");

        let partial = render(&structured_report(&Found {
            links: vec![],
            link_search: crate::structured::LinkSearch::Partial,
            stopped: Some(crate::walk::Halt::Deadline),
            ..found()
        }));
        assert!(partial.contains("stopped part-way"), "{partial}");
        assert!(
            partial.contains("among the entries"),
            "and the absolute claim is not made either way: {partial}"
        );

        let unavailable = render(&structured_report(&Found {
            links: vec![],
            link_search: crate::structured::LinkSearch::Unavailable,
            links_examined: None,
            ..found()
        }));
        assert!(unavailable.contains("could not be listed"), "{unavailable}");
        assert!(
            !unavailable.contains("No symbolic link in"),
            "a directory nobody listed says nothing about links: {unavailable}"
        );

        // **The two unchecked counts are not one number**, and the identity is what says so:
        // an entry the namespace could not name was never examined, while a link whose target
        // would not read was. Summing them into one figure made `examined + unchecked` overshoot
        // what the directory holds, which the live-kernel differential caught against `!object`.
        let unchecked = render(&structured_report(&Found {
            links: vec![],
            links_examined: Some(400),
            links_unnamed: 2,
            links_unread: 3,
            ..found()
        }));
        assert!(
            unchecked.contains("5 of") && unchecked.contains("2 this could not name"),
            "both are reported, and apart: {unchecked}"
        );
        let report = structured_report(&Found {
            links_unnamed: 2,
            links_unread: 3,
            ..found()
        });
        assert_eq!(
            (
                report.links_examined,
                report.links_unnamed,
                report.links_unread
            ),
            (Some(400), 2, 3),
            "and each keeps its own denominator: what the directory held is examined + unnamed"
        );
    }

    /// The one line a reader is most likely to act on is said where it is true, rather than left
    /// to be inferred from an absent word.
    #[test]
    fn a_device_opened_relatively_is_called_out_rather_than_left_unsaid() {
        let mut relative = found();
        relative.fields.characteristics = 0;
        relative.fields.secure_open = false;
        let text = render(&structured_report(&relative));
        assert!(text.contains("no FILE_DEVICE_SECURE_OPEN"), "{text}");
        assert!(
            !render(&structured_report(&found())).contains("no FILE_DEVICE_SECURE_OPEN"),
            "and not where it is false"
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
        for outside in [
            Layout {
                driver: 0x14c,
                ..layout()
            },
            Layout {
                security: 0x14c,
                ..layout()
            },
        ] {
            assert_eq!(
                refused(outside),
                "a pointer field sits outside the device object",
                "every pointer field is bounded, not just the first one written"
            );
        }
    }
}
