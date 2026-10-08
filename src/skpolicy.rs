//! Operator policy for live Secure Kernel controllers.
//!
//! The policy is read once when the shared session registry is created. MCP requests may select
//! only entries already admitted there; putting an allow-list in the request or its profile would
//! let the caller authorize itself.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

pub(crate) const POLICY_ENV: &str = "WINDBG_MCP_SK_LIVE_POLICY";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    disposable_vm_ids: Vec<String>,
    transport_commands: Vec<String>,
    profile_roots: Vec<PathBuf>,
}

#[derive(Clone, Debug)]
pub(crate) struct Policy {
    disposable_vm_ids: BTreeSet<String>,
    transport_commands: BTreeSet<Vec<String>>,
    profile_roots: Vec<String>,
}

impl Policy {
    pub(crate) fn load_from_env() -> Result<Option<Self>> {
        let Some(path) = std::env::var_os(POLICY_ENV) else {
            return Ok(None);
        };
        let path = PathBuf::from(path);
        let bytes = std::fs::read(&path)
            .with_context(|| format!("reading {} from {}", POLICY_ENV, path.display()))?;
        let file: PolicyFile = serde_json::from_slice(&bytes)
            .with_context(|| format!("parsing Secure Kernel policy {}", path.display()))?;
        Self::from_file(file).map(Some)
    }

    fn from_file(file: PolicyFile) -> Result<Self> {
        if file.disposable_vm_ids.is_empty()
            || file.transport_commands.is_empty()
            || file.profile_roots.is_empty()
        {
            bail!(
                "Secure Kernel policy must admit at least one disposable VM, transport command \
                 and profile root"
            );
        }
        let mut disposable_vm_ids = BTreeSet::new();
        for vm_id in file.disposable_vm_ids {
            validate_vm_id(&vm_id)?;
            disposable_vm_ids.insert(vm_id.to_ascii_lowercase());
        }
        let transport_commands = file
            .transport_commands
            .into_iter()
            .map(|command| normalize_transport("transport command", &command))
            .collect::<Result<_>>()?;
        let profile_roots = file
            .profile_roots
            .into_iter()
            .map(|path| {
                canonical_directory(&path, "profile root").map(|path| normalized_path(&path))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            disposable_vm_ids,
            transport_commands,
            profile_roots,
        })
    }

    pub(crate) fn authorize(
        &self,
        vm_id: &str,
        profile: &Path,
        control_transport: &str,
        live_transport: &str,
    ) -> Result<()> {
        validate_vm_id(vm_id)?;
        if !self.disposable_vm_ids.contains(&vm_id.to_ascii_lowercase()) {
            bail!("VM {vm_id} is not in the startup policy's disposable VM allow-list");
        }

        let profile = canonical_file(profile, "Secure Kernel profile")?;
        let normalized_profile = normalized_path(&profile);
        if !self.profile_roots.iter().any(|root| {
            normalized_profile == *root
                || normalized_profile
                    .strip_prefix(root)
                    .is_some_and(|rest| rest.starts_with('\\') || rest.starts_with('/'))
        }) {
            bail!(
                "Secure Kernel profile {} is outside every startup-policy profile root",
                profile.display()
            );
        }
        self.authorize_transport("control_transport", control_transport)?;
        self.authorize_transport("live_transport", live_transport)?;
        Ok(())
    }

    fn authorize_transport(&self, name: &str, command: &str) -> Result<()> {
        let normalized = normalize_transport(name, command)?;
        if !self.transport_commands.contains(&normalized) {
            bail!("{name} is not an exact transport command admitted by startup policy");
        }
        Ok(())
    }
}

fn normalize_transport(name: &str, command: &str) -> Result<Vec<String>> {
    let mut words = crate::livesrc::split_command(command);
    let program = words
        .first_mut()
        .with_context(|| format!("{name} is empty"))?;
    let path = PathBuf::from(&*program);
    if !path.is_absolute() {
        bail!("{name} must name an absolute executable fixed by startup policy");
    }
    *program = normalized_path(&canonical_file(&path, name)?);
    Ok(words)
}

fn normalized_path(path: &Path) -> String {
    path.as_os_str().to_string_lossy().to_ascii_lowercase()
}

fn validate_vm_id(vm_id: &str) -> Result<()> {
    let bytes = vm_id.as_bytes();
    if bytes.len() != 36
        || !bytes.iter().enumerate().all(|(index, byte)| {
            matches!(index, 8 | 13 | 18 | 23) && *byte == b'-'
                || !matches!(index, 8 | 13 | 18 | 23) && byte.is_ascii_hexdigit()
        })
    {
        bail!("VM id must be a canonical 36-character GUID");
    }
    Ok(())
}

fn canonical_file(path: &Path, what: &str) -> Result<PathBuf> {
    let path = path
        .canonicalize()
        .with_context(|| format!("canonicalizing {what} {}", path.display()))?;
    if !path.is_file() {
        bail!("{what} {} is not a file", path.display());
    }
    Ok(path)
}

fn canonical_directory(path: &Path, what: &str) -> Result<PathBuf> {
    let path = path
        .canonicalize()
        .with_context(|| format!("canonicalizing {what} {}", path.display()))?;
    if !path.is_dir() {
        bail!("{what} {} is not a directory", path.display());
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vm_id_shape_is_canonical_and_case_insensitive() {
        assert!(validate_vm_id("51749A1F-F939-44F5-B251-1251EF5B64A3").is_ok());
        assert!(validate_vm_id("{51749a1f-f939-44f5-b251-1251ef5b64a3}").is_err());
        assert!(validate_vm_id("51749a1f-f939-44f5-b251-1251ef5b64az").is_err());
    }

    #[test]
    fn policy_requires_every_authority_dimension() {
        let empty = PolicyFile {
            disposable_vm_ids: Vec::new(),
            transport_commands: Vec::new(),
            profile_roots: Vec::new(),
        };
        assert!(Policy::from_file(empty).is_err());
    }

    #[test]
    fn transport_policy_covers_the_complete_command_not_only_its_interpreter() {
        let executable = std::env::current_exe().expect("the test executable has a path");
        let quoted = format!("\"{}\" provider.py --vp {{vp}}", executable.display());
        let allowed = normalize_transport("fixture", &quoted).expect("fixture command is valid");
        let policy = Policy {
            disposable_vm_ids: BTreeSet::new(),
            transport_commands: BTreeSet::from([allowed.clone()]),
            profile_roots: Vec::new(),
        };
        assert!(policy.transport_commands.contains(&allowed));

        let injected = format!("\"{}\" -c dangerous", executable.display());
        let injected = normalize_transport("fixture", &injected).expect("injection is parseable");
        assert!(!policy.transport_commands.contains(&injected));
    }
}
