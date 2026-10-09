//! A Hyper-V saved state as a byte source for [`crate::sk`].
//!
//! `FOLLOWUPS.md` item 103, the source half of gate **S1**. Gate S0 measured that a Hyper-V
//! **standard checkpoint** carries a VBS guest's VTL1 pages *and* its VTL1 `CR3`, read through
//! Microsoft's own `vmsavedstatedumpprovider.dll` from the Windows SDK — no driver, no
//! test-signing, no hypercall, and the capture is a file that can be copied off the host and read
//! anywhere. This is that source, bound from Rust: everything above it is
//! [`crate::sk::RawSource`] and does not know which source answered.
//!
//! # Why the SDK header is parsed rather than remembered
//!
//! `GetRegisterValue` takes a `REGISTER_ID`, whose values are **positional** in an enum of some
//! 250 entries. Hand-counting to `X64_RegisterCr3` is exactly the class of remembered constant this
//! investigation has already been bitten by — a wrong index does not fail, it returns a different
//! register's value, and a plausible one. So the enum is read out of `vmsavedstatedump.h` beside
//! the DLL, and an operator who has the DLL has the header.
//!
//! # What a failed provider call is allowed to look like
//!
//! S0's probe needed four review rounds to settle this, each of which found another place where a
//! *failure* arrived looking like an *answer*. The same three contracts hold here, and they are in
//! the types rather than in prose:
//!
//! - **Fatal** — nothing downstream means anything without it: loading, locating. `Err` from
//!   [`Provider::open`], and the run ends.
//! - **Diagnostic** — recorded per field, never fatal, never silent: every register and every
//!   VTL query. A provider that cannot answer `GetPagingMode` must not take the `CR3` down with
//!   it, so each lands in [`crate::sk::GuestShape::unreadable`] on its own.
//! - **Bulk** — called thousands of times and must never panic: [`Capture::read_chunk`], whose
//!   failures are counted inside [`crate::sk::Reader`].
//!
//! `ForceActiveVirtualTrustLevel` is in none of them: **its failure is the control arm's result.**
//! On a VBS-off guest it answers `VM_SAVED_STATE_DUMP_E_VP_VTL_NOT_ENABLED` (`0xC0370509`), which
//! is the measurement, so it is reported as itself in
//! [`crate::sk::GuestShape::switch_refused`] and never folded in with a register that did not come
//! back.
//!
//! # Read-only
//!
//! Nothing here opens a capture for writing or calls the provider's replay-log entry point. A
//! saved state is a file on the host, and `windbg-mcp` has no business modifying one.

use std::collections::BTreeMap;
use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::{FreeLibrary, HMODULE, LocalFree};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_WITH_ALTERED_SEARCH_PATH, LoadLibraryExW,
};
use windows_sys::core::{PCSTR, PCWSTR, PWSTR};

use crate::sk::{Gpa, GuestShape, PAGE, PagingMode, RawSource, ReadFailure};

/// `VM_SAVED_STATE_DUMP_E_VA_NOT_MAPPED`, the provider's answer for an address nothing maps.
///
/// Recognised by value so that *"nothing maps that"* stays distinguishable from *"the call
/// failed"* — see [`TranslateFailure`].
const VA_NOT_MAPPED: i32 = 0xC037_0505u32 as i32;

/// Why the provider would not translate an address.
///
/// Two answers, kept apart for the same reason every other failure in this module is: the first is
/// the oracle **answering**, the second is the oracle being **unavailable**. Folding the second into
/// the first turns a provider error into a disagreement with our own walk — evidence produced by a
/// call that produced none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TranslateFailure {
    NotMapped,
    Failed(String),
}

/// The provider's opaque instance handle. **Never fabricated**: an S0 experiment that passed one it
/// had not been given hung inside the DLL and had to be killed.
type Handle = *mut c_void;

/// The SDK directory the provider ships in, by this build's architecture.
///
/// The DLL has to match the *process*, not the guest: an ARM64 build of this server loads the
/// ARM64 provider and reads an x64 guest's capture through it, which is what S0 measured on this
/// bench.
const ARCH: &str = if cfg!(target_arch = "aarch64") {
    "arm64"
} else if cfg!(target_arch = "x86_64") {
    "x64"
} else {
    "x86"
};

const DLL: &str = "vmsavedstatedumpprovider.dll";
/// The **defs** header, which is where `REGISTER_ID` lives. `VmSavedStateDump.h` beside it
/// declares the functions and mentions the enum nowhere — checked on 10.0.26100.0, where a search
/// for `REGISTER_ID` in it finds nothing at all.
const HEADER: &str = "VmSavedStateDumpDefs.h";
pub(crate) const DEFAULT_KIT_ROOT: &str = r"C:\Program Files (x86)\Windows Kits\10";

/// A Windows Kits installation: where the provider and its header are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Kit {
    pub(crate) dll: PathBuf,
    pub(crate) header: PathBuf,
    pub(crate) version: String,
}

impl Kit {
    /// Find a kit carrying both halves, preferring the highest version that has them.
    ///
    /// Both halves, because either alone is useless: the DLL without the header leaves the register
    /// ids unknown, and the header without the DLL has nothing to call.
    pub(crate) fn find(root: Option<&Path>, version: Option<&str>) -> Result<Kit, String> {
        let root = root
            .unwrap_or_else(|| Path::new(DEFAULT_KIT_ROOT))
            .canonicalize()
            .map_err(|error| format!("canonicalizing Windows Kit root: {error}"))?;
        if let Some(version) = version {
            let mut components = Path::new(version).components();
            if !matches!(components.next(), Some(std::path::Component::Normal(_)))
                || components.next().is_some()
            {
                return Err("kit version must be one directory name, not a path".to_string());
            }
        }
        let mut versions: Vec<String> = match version {
            Some(one) => vec![one.to_string()],
            None => {
                let mut found: Vec<String> = std::fs::read_dir(root.join("bin"))
                    .map_err(|e| format!("{}: {e}", root.join("bin").display()))?
                    .filter_map(|entry| entry.ok())
                    .filter(|entry| entry.path().is_dir())
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .collect();
                found.sort_by_key(|name| version_key(name));
                found
            }
        };
        versions.reverse();
        for candidate in &versions {
            let dll = root.join("bin").join(candidate).join(ARCH).join(DLL);
            let header = root.join("Include").join(candidate).join("um").join(HEADER);
            if dll.is_file() && header.is_file() {
                let dll = dll
                    .canonicalize()
                    .map_err(|error| format!("canonicalizing {}: {error}", dll.display()))?;
                let header = header
                    .canonicalize()
                    .map_err(|error| format!("canonicalizing {}: {error}", header.display()))?;
                if !dll.starts_with(&root) || !header.starts_with(&root) {
                    return Err(format!(
                        "Windows Kit version {candidate} resolves outside admitted root {}",
                        root.display()
                    ));
                }
                return Ok(Kit {
                    dll,
                    header,
                    version: candidate.clone(),
                });
            }
        }
        Err(format!(
            "no Windows Kit under {} has both {ARCH}\\{DLL} and um\\{HEADER} (looked at {} version(s))",
            root.display(),
            versions.len()
        ))
    }
}

/// A dotted version as comparable numbers, so `10.0.26100.0` sorts above `10.0.9999.0`.
fn version_key(name: &str) -> Vec<u64> {
    name.split('.')
        .map(|part| part.parse().unwrap_or(0))
        .collect()
}

/// `REGISTER_ID` as the SDK header spells it: name to positional value.
///
/// The ids are positional in an enum of ~250 entries. An explicit `= value` resets the counter, the
/// way C does.
fn register_ids(header: &Path) -> Result<BTreeMap<String, u32>, String> {
    let text = std::fs::read_to_string(header).map_err(|e| format!("{}: {e}", header.display()))?;
    let start = text
        .find("typedef enum REGISTER_ID")
        .ok_or_else(|| format!("REGISTER_ID enum not found in {}", header.display()))?;
    let open = text[start..]
        .find('{')
        .ok_or_else(|| format!("REGISTER_ID enum has no body in {}", header.display()))?;
    let body = &text[start + open + 1..];
    let end = body
        .find("} REGISTER_ID;")
        .ok_or_else(|| format!("REGISTER_ID enum is unterminated in {}", header.display()))?;
    let mut ids = BTreeMap::new();
    let mut next = 0u32;
    for line in body[..end].lines() {
        let line = match line.find("//") {
            Some(at) => &line[..at],
            None => line,
        };
        let line = line.trim().trim_end_matches(',').trim();
        if line.is_empty()
            || line.starts_with('/')
            || line.starts_with('*')
            || line.starts_with('#')
        {
            continue;
        }
        let (name, explicit) = match line.split_once('=') {
            Some((name, value)) => (name.trim(), Some(value.trim())),
            None => (line, None),
        };
        if name.is_empty()
            || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            || name.chars().next().is_some_and(|c| c.is_ascii_digit())
        {
            continue;
        }
        if let Some(value) = explicit {
            let parsed = match value
                .strip_prefix("0x")
                .or_else(|| value.strip_prefix("0X"))
            {
                Some(hex) => u32::from_str_radix(hex, 16).ok(),
                None => value.parse().ok(),
            };
            match parsed {
                Some(value) => next = value,
                // An entry whose value is an expression rather than a literal would shift every
                // id after it. Refusing is the only safe answer: a silently shifted table reads a
                // different register and returns a plausible number.
                None => {
                    return Err(format!(
                        "REGISTER_ID entry `{name}` has a value this parser cannot evaluate \
                         (`{value}`), so every id after it would be wrong"
                    ));
                }
            }
        }
        ids.insert(name.to_string(), next);
        next += 1;
    }
    if ids.is_empty() {
        return Err(format!(
            "REGISTER_ID enum in {} parsed to nothing",
            header.display()
        ));
    }
    Ok(ids)
}

/// `VIRTUAL_PROCESSOR_REGISTER`, read as its widest member.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct VpRegister {
    low: u64,
    high: u64,
}

type Locate = unsafe extern "system" fn(PCWSTR, PCWSTR, *mut PWSTR, *mut PWSTR, *mut PWSTR) -> i32;
type LoadOne = unsafe extern "system" fn(PCWSTR, *mut Handle) -> i32;
type LoadPair = unsafe extern "system" fn(PCWSTR, PCWSTR, *mut Handle) -> i32;
type Release = unsafe extern "system" fn(Handle) -> i32;
type U32Out = unsafe extern "system" fn(Handle, *mut u32) -> i32;
type VpU32Out = unsafe extern "system" fn(Handle, u32, *mut u32) -> i32;
type VpU8Out = unsafe extern "system" fn(Handle, u32, *mut u8) -> i32;
type VpI32Out = unsafe extern "system" fn(Handle, u32, *mut i32) -> i32;
type ForceVtl = unsafe extern "system" fn(Handle, u32, u8) -> i32;
type VpBoolOut = unsafe extern "system" fn(Handle, u32, *mut i32) -> i32;
type GetRegister = unsafe extern "system" fn(Handle, u32, u32, *mut VpRegister) -> i32;
type ReadGpa = unsafe extern "system" fn(Handle, u64, *mut c_void, u32, *mut u32) -> i32;
type Translate = unsafe extern "system" fn(Handle, u32, u64, *mut u64, *mut u64) -> i32;

/// The entry points this source uses, resolved once.
struct Api {
    locate: Locate,
    load_one: LoadOne,
    load_pair: LoadPair,
    release: Release,
    vp_count: U32Out,
    guest_vtls: U32Out,
    vp_vtls: VpU32Out,
    active_vtl: VpU8Out,
    force_vtl: ForceVtl,
    vtl_enabled: VpBoolOut,
    paging_mode: VpI32Out,
    architecture: VpI32Out,
    register: GetRegister,
    read: ReadGpa,
    translate: Translate,
}

/// The loaded provider DLL.
pub(crate) struct Provider {
    module: HMODULE,
    api: Api,
    ids: BTreeMap<String, u32>,
}

/// Resolve one entry point, or say which one was missing.
///
/// A missing export means a provider older than this code expects, and naming it is the difference
/// between a diagnosable failure and "something went wrong in the DLL".
fn entry<T>(module: HMODULE, name: &str) -> Result<T, String> {
    let mut symbol: Vec<u8> = name.as_bytes().to_vec();
    symbol.push(0);
    let found = unsafe { GetProcAddress(module, symbol.as_ptr() as PCSTR) };
    match found {
        Some(address) => Ok(unsafe { std::mem::transmute_copy(&address) }),
        None => Err(format!("{DLL} exports no {name}")),
    }
}

impl Provider {
    pub(crate) fn load(kit: &Kit) -> Result<Provider, String> {
        let ids = register_ids(&kit.header)?;
        let wide = wide(kit.dll.as_os_str());
        // `LOAD_WITH_ALTERED_SEARCH_PATH` so the provider's own neighbours in the SDK's `bin`
        // directory resolve from there rather than from this process's directory.
        let module = unsafe {
            LoadLibraryExW(
                wide.as_ptr(),
                std::ptr::null_mut(),
                LOAD_WITH_ALTERED_SEARCH_PATH,
            )
        };
        if module.is_null() {
            return Err(format!(
                "{} could not be loaded (os error {})",
                kit.dll.display(),
                std::io::Error::last_os_error()
            ));
        }
        let api = Api {
            locate: entry(module, "LocateSavedStateFiles")?,
            load_one: entry(module, "LoadSavedStateFile")?,
            load_pair: entry(module, "LoadSavedStateFiles")?,
            release: entry(module, "ReleaseSavedStateFiles")?,
            vp_count: entry(module, "GetVpCount")?,
            guest_vtls: entry(module, "GetGuestEnabledVirtualTrustLevels")?,
            vp_vtls: entry(module, "GetEnabledVirtualTrustLevels")?,
            active_vtl: entry(module, "GetActiveVirtualTrustLevel")?,
            force_vtl: entry(module, "ForceActiveVirtualTrustLevel")?,
            vtl_enabled: entry(module, "IsActiveVirtualTrustLevelEnabled")?,
            paging_mode: entry(module, "GetPagingMode")?,
            architecture: entry(module, "GetArchitecture")?,
            register: entry(module, "GetRegisterValue")?,
            read: entry(module, "ReadGuestPhysicalAddress")?,
            translate: entry(module, "GuestVirtualAddressToPhysicalAddress")?,
        };
        Ok(Provider { module, api, ids })
    }

    /// The files Hyper-V holds for one VM's capture.
    ///
    /// Answers the `.vmrs` of a modern capture, or the older `.bin`/`.vsv` pair. **The pair path is
    /// unexercised against a real provider**: S0's bench has never produced a capture of that form,
    /// and saying so is the point — a selection pinned by a test is not a call that has been made.
    pub(crate) fn locate(&self, vm: &str, snapshot: Option<&str>) -> Result<CaptureFiles, String> {
        let vm_wide = wide(std::ffi::OsStr::new(vm));
        let snapshot_wide = snapshot.map(|name| wide(std::ffi::OsStr::new(name)));
        let mut bin: PWSTR = std::ptr::null_mut();
        let mut vsv: PWSTR = std::ptr::null_mut();
        let mut vmrs: PWSTR = std::ptr::null_mut();
        let hr = unsafe {
            (self.api.locate)(
                vm_wide.as_ptr(),
                snapshot_wide
                    .as_ref()
                    .map_or(std::ptr::null(), |w| w.as_ptr()),
                &mut bin,
                &mut vsv,
                &mut vmrs,
            )
        };
        let files = CaptureFiles {
            bin: take_wide(&mut bin),
            vsv: take_wide(&mut vsv),
            vmrs: take_wide(&mut vmrs),
        };
        if hr < 0 {
            return Err(format!("LocateSavedStateFiles failed: {}", hresult(hr)));
        }
        Ok(files)
    }

    /// Open a capture and read everything about the processor that the decode needs.
    pub(crate) fn open(
        &self,
        files: &CaptureFiles,
        vp: u32,
        vtl: u8,
    ) -> Result<Capture<'_>, String> {
        let mut handle: Handle = std::ptr::null_mut();
        let form = match (&files.vmrs, &files.bin, &files.vsv) {
            (Some(vmrs), _, _) => {
                let path = wide(std::ffi::OsStr::new(vmrs));
                let hr = unsafe { (self.api.load_one)(path.as_ptr(), &mut handle) };
                if hr < 0 {
                    return Err(format!(
                        "LoadSavedStateFile({vmrs}) failed: {}",
                        hresult(hr)
                    ));
                }
                CaptureForm::Vmrs
            }
            (None, Some(bin), Some(vsv)) => {
                let (bin_wide, vsv_wide) = (
                    wide(std::ffi::OsStr::new(bin)),
                    wide(std::ffi::OsStr::new(vsv)),
                );
                let hr = unsafe {
                    (self.api.load_pair)(bin_wide.as_ptr(), vsv_wide.as_ptr(), &mut handle)
                };
                if hr < 0 {
                    return Err(format!("LoadSavedStateFiles failed: {}", hresult(hr)));
                }
                CaptureForm::BinVsv
            }
            _ => return Err("no capture files to load".into()),
        };
        if handle.is_null() {
            return Err("the provider loaded the capture and returned a null handle".into());
        }
        let mut capture = Capture {
            api: &self.api,
            handle,
            vp,
            vtl,
            form,
            facts: Facts::default(),
            shape: GuestShape::default(),
        };
        capture.read_facts();
        capture.read_shape(&self.ids);
        Ok(capture)
    }
}

impl Drop for Provider {
    fn drop(&mut self) {
        unsafe { FreeLibrary(self.module) };
    }
}

/// Which capture to read, as **one** value.
///
/// Three independent `Option`s were the shape that let `--vm` and `--vmrs` both be given and one of
/// them silently win, which is what the two matches on them disagreeing would eventually have cost:
/// a report about a different capture than the caller named. Resolving the choice once means
/// nothing downstream has a preference to get wrong.
///
/// **Shared by the command-line role and the tool surface**, which is the reason it lives here
/// rather than in either of them: the rule that exactly one form may be given has a history
/// (`FOLLOWUPS.md` item 103), and two copies of it are two places for the next form to be added to
/// one of. It crosses the supervisor→worker wire as this type, already resolved, so the worker has
/// no choice left to make.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) enum CaptureSpec {
    Vm {
        name: String,
        snapshot: Option<String>,
    },
    Vmrs(PathBuf),
    /// The older pair, which is selected here and — on this bench — called by nothing.
    Pair {
        bin: PathBuf,
        vsv: PathBuf,
    },
}

/// One way of naming a capture, for a refusal that has to spell it the way its caller does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Selector {
    Vm,
    Vmrs,
    Pair,
}

impl Selector {
    /// The argument names this form is given by, unprefixed.
    fn names(self) -> &'static [&'static str] {
        match self {
            Selector::Vm => &["vm"],
            Selector::Vmrs => &["vmrs"],
            Selector::Pair => &["bin", "vsv"],
        }
    }

    /// How it is written in `prefix`'s dialect: `--bin/--vsv` on a command line, `bin/vsv` in a
    /// tool's arguments.
    fn spell(self, prefix: &str) -> String {
        self.names()
            .iter()
            .map(|name| format!("{prefix}{name}"))
            .collect::<Vec<_>>()
            .join("/")
    }
}

/// Why the capture is not exactly one thing.
///
/// **A value rather than a sentence, because the rule is shared and the spelling is not.** The
/// command line names these forms `--vm` and `--vmrs`; the tool surface names them `vm` and `vmrs`,
/// and a refusal that sent a model looking for a flag it cannot pass would be the shared rule
/// leaking its first caller's dialect. Measured: the tool answered *name one capture, not 2: --vm
/// and --vmrs* on the first run that reached it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NotOneCapture {
    NoneGiven,
    Several(Vec<Selector>),
    /// The older pair is two files, and one of them alone is a usage error rather than a capture
    /// that fails to load inside the provider.
    HalfAPair {
        given: &'static str,
        missing: &'static str,
    },
}

impl NotOneCapture {
    /// The refusal, in the dialect `prefix` spells: `"--"` for a command line, `""` for a tool.
    pub(crate) fn explain(&self, prefix: &str) -> String {
        match self {
            NotOneCapture::NoneGiven => format!(
                "name a capture: {}, {}, or {}bin with {}vsv",
                Selector::Vm.spell(prefix),
                Selector::Vmrs.spell(prefix),
                prefix,
                prefix
            ),
            NotOneCapture::Several(forms) => format!(
                "name one capture, not {}: {}",
                forms.len(),
                forms
                    .iter()
                    .map(|form| form.spell(prefix))
                    .collect::<Vec<_>>()
                    .join(" and ")
            ),
            NotOneCapture::HalfAPair { given, missing } => format!(
                "{prefix}bin and {prefix}vsv go together; {prefix}{given} was given without \
                 {prefix}{missing}"
            ),
        }
    }
}

impl CaptureSpec {
    /// Resolve the three ways of naming a capture into one, refusing anything but exactly one.
    ///
    /// **Named as a set rather than resolved by precedence**: giving two is a caller who means
    /// something this cannot do, and picking one of them would read a capture they did not ask for.
    pub(crate) fn one_of(
        vm: Option<String>,
        snapshot: Option<String>,
        vmrs: Option<PathBuf>,
        bin: Option<PathBuf>,
        vsv: Option<PathBuf>,
    ) -> Result<CaptureSpec, NotOneCapture> {
        let mut forms: Vec<Selector> = Vec::new();
        if vm.is_some() {
            forms.push(Selector::Vm);
        }
        if vmrs.is_some() {
            forms.push(Selector::Vmrs);
        }
        if bin.is_some() || vsv.is_some() {
            forms.push(Selector::Pair);
        }
        match forms.as_slice() {
            [] => return Err(NotOneCapture::NoneGiven),
            [_] => {}
            _ => return Err(NotOneCapture::Several(forms)),
        }
        match (vm, vmrs, bin, vsv) {
            (Some(name), _, _, _) => Ok(CaptureSpec::Vm { name, snapshot }),
            (None, Some(path), _, _) => Ok(CaptureSpec::Vmrs(path)),
            (None, None, Some(bin), Some(vsv)) => Ok(CaptureSpec::Pair { bin, vsv }),
            (None, None, bin, _) => Err(if bin.is_some() {
                NotOneCapture::HalfAPair {
                    given: "bin",
                    missing: "vsv",
                }
            } else {
                NotOneCapture::HalfAPair {
                    given: "vsv",
                    missing: "bin",
                }
            }),
        }
    }

    /// The files this names, asking Hyper-V where a checkpoint lives when it is named by VM.
    pub(crate) fn files(&self, provider: &Provider) -> Result<CaptureFiles, String> {
        match self {
            CaptureSpec::Vm { name, snapshot } => provider.locate(name, snapshot.as_deref()),
            CaptureSpec::Vmrs(vmrs) => Ok(CaptureFiles::vmrs(vmrs)),
            CaptureSpec::Pair { bin, vsv } => Ok(CaptureFiles::pair(bin, vsv)),
        }
    }

    /// The paths this names *before* the provider is asked, which is every file a caller supplied.
    ///
    /// A VM has none: Hyper-V answers with them, and until it does there is nothing to protect.
    pub(crate) fn given_paths(&self) -> Vec<&Path> {
        match self {
            CaptureSpec::Vm { .. } => Vec::new(),
            CaptureSpec::Vmrs(vmrs) => vec![vmrs.as_path()],
            CaptureSpec::Pair { bin, vsv } => vec![bin.as_path(), vsv.as_path()],
        }
    }

    /// How this reads in a report, and what a session is named after.
    pub(crate) fn describe(&self) -> String {
        match self {
            CaptureSpec::Vm {
                name,
                snapshot: Some(snapshot),
            } => format!("{name} ({snapshot})"),
            CaptureSpec::Vm {
                name,
                snapshot: None,
            } => name.clone(),
            CaptureSpec::Vmrs(vmrs) => vmrs.display().to_string(),
            CaptureSpec::Pair { bin, .. } => bin.display().to_string(),
        }
    }
}
/// The files one capture is made of. Any subset may be present.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CaptureFiles {
    pub(crate) bin: Option<String>,
    pub(crate) vsv: Option<String>,
    pub(crate) vmrs: Option<String>,
}

impl CaptureFiles {
    /// One `.vmrs`, named directly rather than located through a VM.
    pub(crate) fn vmrs(path: &Path) -> CaptureFiles {
        CaptureFiles {
            vmrs: Some(path.display().to_string()),
            ..CaptureFiles::default()
        }
    }

    /// The older `.bin`/`.vsv` pair, named directly.
    pub(crate) fn pair(bin: &Path, vsv: &Path) -> CaptureFiles {
        CaptureFiles {
            bin: Some(bin.display().to_string()),
            vsv: Some(vsv.display().to_string()),
            vmrs: None,
        }
    }

    pub(crate) fn paths(&self) -> Vec<&str> {
        [
            self.vmrs.as_deref(),
            self.bin.as_deref(),
            self.vsv.as_deref(),
        ]
        .into_iter()
        .flatten()
        .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CaptureForm {
    Vmrs,
    BinVsv,
}

/// What a capture says about itself, beside the registers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Facts {
    pub(crate) vp_count: Option<u32>,
    /// The VTLs the *partition* had enabled when the capture was written. On a VBS-off guest this
    /// is VTL0 only, which is the control arm's first reading.
    pub(crate) guest_vtls: Option<u32>,
    pub(crate) vp_vtls: Option<u32>,
    pub(crate) active_vtl: Option<u8>,
    pub(crate) architecture: Option<i32>,
    /// Questions the provider would not answer, by name, so a report says which went unanswered
    /// rather than looking like a capture with nothing to say.
    pub(crate) unreadable: Vec<(&'static str, String)>,
}

/// One opened capture, as a byte source.
pub(crate) struct Capture<'a> {
    api: &'a Api,
    handle: Handle,
    vp: u32,
    vtl: u8,
    pub(crate) form: CaptureForm,
    pub(crate) facts: Facts,
    shape: GuestShape,
}

impl Capture<'_> {
    fn read_facts(&mut self) {
        let mut vp_count = 0u32;
        match unsafe { (self.api.vp_count)(self.handle, &mut vp_count) } {
            hr if hr < 0 => self.facts.unreadable.push(("vp_count", hresult(hr))),
            _ => self.facts.vp_count = Some(vp_count),
        }
        let mut guest_vtls = 0u32;
        match unsafe { (self.api.guest_vtls)(self.handle, &mut guest_vtls) } {
            hr if hr < 0 => self.facts.unreadable.push(("guest_vtls", hresult(hr))),
            _ => self.facts.guest_vtls = Some(guest_vtls),
        }
        let mut vp_vtls = 0u32;
        match unsafe { (self.api.vp_vtls)(self.handle, self.vp, &mut vp_vtls) } {
            hr if hr < 0 => self.facts.unreadable.push(("vp_vtls", hresult(hr))),
            _ => self.facts.vp_vtls = Some(vp_vtls),
        }
        let mut active = 0u8;
        match unsafe { (self.api.active_vtl)(self.handle, self.vp, &mut active) } {
            hr if hr < 0 => self.facts.unreadable.push(("active_vtl", hresult(hr))),
            _ => self.facts.active_vtl = Some(active),
        }
        let mut arch = 0i32;
        match unsafe { (self.api.architecture)(self.handle, self.vp, &mut arch) } {
            hr if hr < 0 => self.facts.unreadable.push(("architecture", hresult(hr))),
            _ => self.facts.architecture = Some(arch),
        }
    }

    /// Select the VTL and read the registers the decode is gated on, **one question at a time**.
    ///
    /// One function for both VTLs, because in S0's probe two copies of this block drifted apart:
    /// the VTL1 copy was made per-field after review found a shared `try` letting an optional
    /// diagnostic cost the `CR3`, and the VTL0 copy three screens away kept raising — which review
    /// found one round later. A contract that lives only in prose binds nothing.
    fn read_shape(&mut self, ids: &BTreeMap<String, u32>) {
        let hr = unsafe { (self.api.force_vtl)(self.handle, self.vp, self.vtl) };
        if hr < 0 {
            // The control arm's whole result, and deliberately not merged with an unreadable
            // register: `VM_SAVED_STATE_DUMP_E_VP_VTL_NOT_ENABLED` is 0xC0370509.
            self.shape.switch_refused = Some(format!(
                "ForceActiveVirtualTrustLevel(vp{}, vtl{}) refused: {}",
                self.vp,
                self.vtl,
                hresult(hr)
            ));
            return;
        }
        let mut enabled = 0i32;
        match unsafe { (self.api.vtl_enabled)(self.handle, self.vp, &mut enabled) } {
            hr if hr < 0 => self.shape.unreadable.push(("vtl_enabled", hresult(hr))),
            _ => self.shape.vtl_enabled = Some(enabled != 0),
        }
        let mut mode = 0i32;
        match unsafe { (self.api.paging_mode)(self.handle, self.vp, &mut mode) } {
            hr if hr < 0 => self.shape.unreadable.push(("paging_mode", hresult(hr))),
            _ => self.shape.paging_mode = Some(PagingMode::from_raw(mode)),
        }
        for (field, register) in [
            ("cr0", "X64_RegisterCr0"),
            ("cr3", "X64_RegisterCr3"),
            ("cr4", "X64_RegisterCr4"),
            ("efer", "X64_RegisterEfer"),
        ] {
            let Some(id) = ids.get(register) else {
                self.shape.unreadable.push((
                    field,
                    format!("{register} is not in this SDK's REGISTER_ID"),
                ));
                continue;
            };
            let mut value = VpRegister::default();
            let hr = unsafe { (self.api.register)(self.handle, self.vp, *id, &mut value) };
            if hr < 0 {
                self.shape.unreadable.push((field, hresult(hr)));
                continue;
            }
            match field {
                "cr0" => self.shape.cr0 = Some(value.low),
                "cr3" => self.shape.cr3 = Some(value.low),
                "cr4" => self.shape.cr4 = Some(value.low),
                _ => self.shape.efer = Some(value.low),
            }
        }
    }

    /// The provider's own virtual-to-physical translation for the VTL it was forced to.
    ///
    /// Not used by the decode: it is the free differential oracle S0 found, and it is not our code.
    /// A walk that agrees with it on an address has been checked against something independent.
    pub(crate) fn translate(&self, va: u64) -> Result<Gpa, TranslateFailure> {
        let mut gpa = 0u64;
        let mut unmapped = 0u64;
        let hr = unsafe { (self.api.translate)(self.handle, self.vp, va, &mut gpa, &mut unmapped) };
        if hr == VA_NOT_MAPPED {
            return Err(TranslateFailure::NotMapped);
        }
        if hr < 0 {
            return Err(TranslateFailure::Failed(hresult(hr)));
        }
        if unmapped != 0 {
            // Measured on this provider, an unmapped VA fails outright with 0xC0370505 and a mapped
            // one reports an unmapped span of zero, so this is unreachable here. Kept because the
            // alternative is depending on that, and what it would let through is the worst kind: a
            // zero-initialised GPA read as a valid mapping, feeding page 0's bytes into a decode.
            return Err(TranslateFailure::NotMapped);
        }
        Ok(Gpa(gpa))
    }
}

impl Drop for Capture<'_> {
    fn drop(&mut self) {
        unsafe { (self.api.release)(self.handle) };
    }
}

impl RawSource for Capture<'_> {
    fn shape(&self) -> GuestShape {
        self.shape.clone()
    }

    fn max_read(&self) -> usize {
        // A page at a time. The provider will move more, but a page is the unit every decode above
        // asks in, and it keeps the chunking path that a 16-byte live source will need exercised by
        // every run rather than only by a fixture.
        PAGE as usize
    }

    fn read_chunk(&self, gpa: Gpa, out: &mut [u8]) -> Result<(), ReadFailure> {
        let mut read = 0u32;
        let hr = unsafe {
            (self.api.read)(
                self.handle,
                gpa.0,
                out.as_mut_ptr() as *mut c_void,
                out.len() as u32,
                &mut read,
            )
        };
        if hr < 0 {
            return Err(ReadFailure::SourceError {
                detail: hresult(hr),
            });
        }
        if read as usize == out.len() {
            return Ok(());
        }
        // The header says a short read means the end of memory was reached. Nothing at all is a
        // physical address this capture does not cover; a partial answer is a range that runs off
        // the end of one, and the two are different facts about the guest.
        if read == 0 {
            Err(ReadFailure::NotPresent)
        } else {
            Err(ReadFailure::Short {
                got: read as usize,
                want: out.len(),
            })
        }
    }
}

fn wide(text: &std::ffi::OsStr) -> Vec<u16> {
    text.encode_wide().chain(std::iter::once(0)).collect()
}

/// Take a string the provider allocated, and free it as the SDK header requires.
///
/// `LocateSavedStateFiles` documents each returned path as the caller's to `LocalFree`. S0's probe
/// leaks all three; this does not.
fn take_wide(pointer: &mut PWSTR) -> Option<String> {
    if pointer.is_null() {
        return None;
    }
    let mut length = 0usize;
    while unsafe { *pointer.add(length) } != 0 {
        length += 1;
    }
    let text = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(*pointer, length) });
    unsafe { LocalFree(*pointer as *mut c_void) };
    *pointer = std::ptr::null_mut();
    (!text.is_empty()).then_some(text)
}

fn hresult(hr: i32) -> String {
    format!("hresult {:#010X}", hr as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one thing about this module that is testable with no capture, no VM and no SDK: the
    /// positional arithmetic that decides which register `GetRegisterValue` is asked for.
    ///
    /// A wrong index does not fail — it returns a different register's value, and a plausible one —
    /// so this is the parse worth pinning.
    #[test]
    fn the_register_enum_is_positional_and_an_explicit_value_resets_the_count() {
        let header = std::env::temp_dir().join("windbg-mcp-register-id-fixture.h");
        std::fs::write(
            &header,
            "typedef enum REGISTER_ID\n{\n    X64_RegisterRax = 0,\n    // a comment\n    \
             X64_RegisterRcx,\n    X64_RegisterRdx,\n\n    Arm64_RegisterX0 = 0x100,\n    \
             Arm64_RegisterX1,\n} REGISTER_ID;\n",
        )
        .expect("write fixture");
        let ids = register_ids(&header).expect("parse");
        assert_eq!(ids.get("X64_RegisterRax"), Some(&0));
        assert_eq!(
            ids.get("X64_RegisterRdx"),
            Some(&2),
            "a comment must not consume a position"
        );
        assert_eq!(ids.get("Arm64_RegisterX0"), Some(&0x100));
        assert_eq!(
            ids.get("Arm64_RegisterX1"),
            Some(&0x101),
            "counting resumes from the literal"
        );
        std::fs::remove_file(&header).ok();
    }

    #[test]
    fn a_value_this_parser_cannot_evaluate_is_refused_rather_than_shifting_every_id_after_it() {
        let header = std::env::temp_dir().join("windbg-mcp-register-id-expression.h");
        std::fs::write(
            &header,
            "typedef enum REGISTER_ID\n{\n    First,\n    Second = (First + 4),\n    Third,\n} \
             REGISTER_ID;\n",
        )
        .expect("write fixture");
        let error = register_ids(&header).expect_err("an expression must not be guessed at");
        assert!(error.contains("Second"), "{error}");
        std::fs::remove_file(&header).ok();
    }

    #[test]
    fn versions_sort_numerically_rather_than_lexically() {
        let mut versions = ["10.0.9999.0".to_string(), "10.0.26100.0".to_string()];
        versions.sort_by_key(|name| version_key(name));
        assert_eq!(versions.last().map(String::as_str), Some("10.0.26100.0"));
    }

    /// The real kit on this bench, when there is one. Skipped rather than failed elsewhere: the
    /// provider is an SDK component and CI runners do not have it.
    #[test]
    fn the_sdk_on_this_host_carries_both_halves_and_its_register_table_has_cr3() {
        let Ok(kit) = Kit::find(None, None) else {
            eprintln!("SKIPPED: no Windows Kit with {ARCH}\\{DLL} on this host");
            return;
        };
        let ids = register_ids(&kit.header).expect("the SDK header parses");
        assert!(
            ids.contains_key("X64_RegisterCr3"),
            "kit {} has no CR3 id",
            kit.version
        );
        assert!(
            ids.len() > 100,
            "a REGISTER_ID table of {} entries is too small",
            ids.len()
        );
    }
}
