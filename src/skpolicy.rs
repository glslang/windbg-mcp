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
    #[serde(default)]
    disposable_vm_ids: Vec<String>,
    #[serde(default)]
    transport_commands: Vec<String>,
    #[serde(default)]
    profile_roots: Vec<PathBuf>,
    #[serde(default)]
    kit_roots: Vec<PathBuf>,
    #[serde(default)]
    max_pause_ms: Option<u64>,
}

#[derive(Clone, Debug)]
pub(crate) struct Policy {
    disposable_vm_ids: BTreeSet<String>,
    transport_commands: BTreeSet<Vec<String>>,
    profile_roots: Vec<String>,
    kit_roots: Vec<String>,
    max_pause_ms: Option<u64>,
}

#[derive(Clone, Debug)]
pub(crate) struct AuthorizedLive {
    pub(crate) profile: PathBuf,
    pub(crate) control_transport: String,
    pub(crate) live_transport: String,
    pub(crate) max_pause_ms: u64,
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
        let live_dimensions = [
            !file.disposable_vm_ids.is_empty(),
            !file.transport_commands.is_empty(),
            !file.profile_roots.is_empty(),
        ];
        let has_live_authority = live_dimensions.iter().all(|present| *present);
        if live_dimensions.iter().any(|present| *present) && !has_live_authority {
            bail!(
                "Secure Kernel live policy must supply disposable_vm_ids, transport_commands and \
                 profile_roots together"
            );
        }
        if has_live_authority && file.max_pause_ms.is_none() {
            bail!("Secure Kernel live policy must fix max_pause_ms at server startup");
        }
        if !has_live_authority && file.kit_roots.is_empty() {
            bail!("Secure Kernel policy must admit live authority, at least one kit root, or both");
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
        let kit_roots = file
            .kit_roots
            .into_iter()
            .map(|path| {
                canonical_directory(&path, "Windows Kit root").map(|path| normalized_path(&path))
            })
            .collect::<Result<Vec<_>>>()?;
        if let Some(max_pause_ms) = file.max_pause_ms
            && !(crate::skdispatch::MIN_PAUSE_MS..=crate::kdtarget::MAX_MANAGED_TIMEOUT_MS)
                .contains(&max_pause_ms)
        {
            bail!(
                "Secure Kernel policy max_pause_ms must be in {}..={}",
                crate::skdispatch::MIN_PAUSE_MS,
                crate::kdtarget::MAX_MANAGED_TIMEOUT_MS
            );
        }
        Ok(Self {
            disposable_vm_ids,
            transport_commands,
            profile_roots,
            kit_roots,
            max_pause_ms: file.max_pause_ms,
        })
    }

    pub(crate) fn authorize(
        &self,
        vm_id: &str,
        profile: &Path,
        control_transport: &str,
        live_transport: &str,
    ) -> Result<AuthorizedLive> {
        validate_vm_id(vm_id)?;
        if !self.disposable_vm_ids.contains(&vm_id.to_ascii_lowercase()) {
            bail!("VM {vm_id} is not in the startup policy's disposable VM allow-list");
        }

        let profile = canonical_profile(profile)?;
        let normalized_profile = normalized_path(&profile);
        if !self
            .profile_roots
            .iter()
            .any(|root| Path::new(&normalized_profile).starts_with(Path::new(root)))
        {
            bail!(
                "Secure Kernel profile {} is outside every startup-policy profile root",
                profile.display()
            );
        }
        let control_transport = self.authorize_transport("control_transport", control_transport)?;
        let live_transport = self.authorize_transport("live_transport", live_transport)?;
        let max_pause_ms = self.max_pause_ms.context(
            "Secure Kernel startup policy has no max_pause_ms; live control remains disabled",
        )?;
        Ok(AuthorizedLive {
            profile,
            control_transport,
            live_transport,
            max_pause_ms,
        })
    }

    /// Select a canonical Windows Kit root fixed by startup policy. The worker receives this
    /// canonical root even when the request omitted `kit`, so provider discovery cannot fall back
    /// to a path the operator did not admit.
    pub(crate) fn authorize_capture_kit(
        &self,
        requested: Option<&Path>,
        version: Option<&str>,
    ) -> Result<PathBuf> {
        if self.kit_roots.is_empty() {
            bail!(
                "Secure Kernel startup policy has no kit_roots; capture provider loading remains disabled"
            );
        }
        if let Some(version) = version {
            let mut components = Path::new(version).components();
            if !matches!(components.next(), Some(std::path::Component::Normal(_)))
                || components.next().is_some()
            {
                bail!("kit_version must be one directory name, not a path");
            }
        }
        let requested = requested.unwrap_or_else(|| Path::new(crate::savedstate::DEFAULT_KIT_ROOT));
        let canonical = canonical_directory(requested, "Windows Kit root")?;
        let normalized = normalized_path(&canonical);
        if !self
            .kit_roots
            .iter()
            .any(|root| Path::new(&normalized).starts_with(Path::new(root)))
        {
            bail!(
                "Windows Kit root {} is outside every startup-policy kit root",
                canonical.display()
            );
        }
        Ok(canonical)
    }

    fn authorize_transport(&self, name: &str, command: &str) -> Result<String> {
        let (normalized, launch) = canonical_transport(name, command)?;
        if !self.transport_commands.contains(&normalized) {
            bail!("{name} is not an exact transport command admitted by startup policy");
        }
        Ok(render_transport(&launch))
    }
}

fn normalize_transport(name: &str, command: &str) -> Result<Vec<String>> {
    canonical_transport(name, command).map(|(normalized, _)| normalized)
}

fn canonical_transport(name: &str, command: &str) -> Result<(Vec<String>, Vec<String>)> {
    let mut words = crate::livesrc::split_command(command);
    let program = words
        .first_mut()
        .with_context(|| format!("{name} is empty"))?;
    let path = PathBuf::from(&*program);
    if !path.is_absolute() {
        bail!("{name} must name an absolute executable fixed by startup policy");
    }
    *program = canonical_file(&path, name)?.to_string_lossy().into_owned();
    let mut normalized = words.clone();
    normalized[0] = normalized_path(Path::new(&normalized[0]));
    Ok((normalized, words))
}

pub(crate) fn render_transport(words: &[String]) -> String {
    words
        .iter()
        .map(|word| {
            if word.chars().any(char::is_whitespace) {
                format!("\"{word}\"")
            } else {
                word.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
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

fn canonical_profile(path: &Path) -> Result<PathBuf> {
    let path = path
        .canonicalize()
        .with_context(|| format!("canonicalizing Secure Kernel profile {}", path.display()))?;
    if !path.is_file() && !path.is_dir() {
        bail!(
            "Secure Kernel profile {} is neither a file nor a directory",
            path.display()
        );
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
            kit_roots: Vec::new(),
            max_pause_ms: None,
        };
        assert!(Policy::from_file(empty).is_err());
    }

    #[test]
    fn capture_only_policy_does_not_require_live_provider_authority() {
        let root = std::env::temp_dir().canonicalize().unwrap();
        let capture_only = PolicyFile {
            disposable_vm_ids: Vec::new(),
            transport_commands: Vec::new(),
            profile_roots: Vec::new(),
            kit_roots: vec![root.clone()],
            max_pause_ms: None,
        };
        let policy = Policy::from_file(capture_only).unwrap();
        assert_eq!(
            policy.authorize_capture_kit(Some(&root), None).unwrap(),
            root
        );
    }

    #[test]
    fn partial_live_authority_is_rejected_at_startup() {
        let partial = PolicyFile {
            disposable_vm_ids: vec!["51749a1f-f939-44f5-b251-1251ef5b64a3".to_string()],
            transport_commands: Vec::new(),
            profile_roots: Vec::new(),
            kit_roots: vec![std::env::temp_dir()],
            max_pause_ms: Some(600_000),
        };
        assert!(Policy::from_file(partial).is_err());
    }

    #[test]
    fn live_authority_requires_an_operator_fixed_pause_bound() {
        let executable = std::env::current_exe().unwrap();
        let command = format!("\"{}\" --fixture", executable.display());
        let directory = std::env::temp_dir().canonicalize().unwrap();
        let file = PolicyFile {
            disposable_vm_ids: vec!["51749a1f-f939-44f5-b251-1251ef5b64a3".to_string()],
            transport_commands: vec![command],
            profile_roots: vec![directory],
            kit_roots: Vec::new(),
            max_pause_ms: None,
        };

        let error = Policy::from_file(file).unwrap_err();
        assert!(error.to_string().contains("max_pause_ms"), "{error:#}");
    }

    #[test]
    fn startup_pause_bound_uses_the_managed_timeout_domain() {
        let executable = std::env::current_exe().unwrap();
        let command = format!("\"{}\" --fixture", executable.display());
        let directory = std::env::temp_dir().canonicalize().unwrap();

        for max_pause_ms in [
            0,
            crate::skdispatch::MIN_PAUSE_MS - 1,
            crate::kdtarget::MAX_MANAGED_TIMEOUT_MS + 1,
        ] {
            let file = PolicyFile {
                disposable_vm_ids: vec!["51749a1f-f939-44f5-b251-1251ef5b64a3".to_string()],
                transport_commands: vec![command.clone()],
                profile_roots: vec![directory.clone()],
                kit_roots: Vec::new(),
                max_pause_ms: Some(max_pause_ms),
            };
            let error = Policy::from_file(file).unwrap_err();
            assert!(
                error.to_string().contains("max_pause_ms must be in"),
                "{error:#}"
            );
        }

        let minimum = PolicyFile {
            disposable_vm_ids: vec!["51749a1f-f939-44f5-b251-1251ef5b64a3".to_string()],
            transport_commands: vec![command],
            profile_roots: vec![directory],
            kit_roots: Vec::new(),
            max_pause_ms: Some(crate::skdispatch::MIN_PAUSE_MS),
        };
        assert!(Policy::from_file(minimum).is_ok());
    }

    #[test]
    fn capture_kit_must_resolve_beneath_an_operator_root() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let admitted = std::env::temp_dir().join(format!(
            "windbg-mcp-policy-kit-admitted-{}-{unique}",
            std::process::id()
        ));
        let outside = std::env::temp_dir().join(format!(
            "windbg-mcp-policy-kit-outside-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&admitted).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let canonical = admitted.canonicalize().unwrap();
        let policy = Policy {
            disposable_vm_ids: BTreeSet::new(),
            transport_commands: BTreeSet::new(),
            profile_roots: Vec::new(),
            kit_roots: vec![normalized_path(&canonical)],
            max_pause_ms: None,
        };

        assert_eq!(
            policy
                .authorize_capture_kit(Some(&admitted), Some("10.0.26100.0"))
                .unwrap(),
            canonical
        );
        assert!(
            policy
                .authorize_capture_kit(Some(&outside), None)
                .unwrap_err()
                .to_string()
                .contains("outside every startup-policy kit root")
        );
        assert!(
            policy
                .authorize_capture_kit(Some(&admitted), Some("..\\outside"))
                .unwrap_err()
                .to_string()
                .contains("one directory name")
        );

        std::fs::remove_dir_all(admitted).unwrap();
        std::fs::remove_dir_all(outside).unwrap();
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
            kit_roots: Vec::new(),
            max_pause_ms: None,
        };
        assert!(policy.transport_commands.contains(&allowed));

        let injected = format!("\"{}\" -c dangerous", executable.display());
        let injected = normalize_transport("fixture", &injected).expect("injection is parseable");
        assert!(!policy.transport_commands.contains(&injected));
    }

    #[test]
    fn authorized_transport_launches_the_canonical_executable() {
        let executable = std::env::current_exe().expect("the test executable has a path");
        let parent = executable
            .parent()
            .expect("the test executable has a parent");
        let indirect = parent.join(".").join(
            executable
                .file_name()
                .expect("the test executable has a file name"),
        );
        let command = format!("\"{}\" --fixture value", indirect.display());
        let allowed = normalize_transport("fixture", &command).expect("fixture command is valid");
        let policy = Policy {
            disposable_vm_ids: BTreeSet::new(),
            transport_commands: BTreeSet::from([allowed]),
            profile_roots: Vec::new(),
            kit_roots: Vec::new(),
            max_pause_ms: None,
        };

        let launch = policy
            .authorize_transport("fixture", &command)
            .expect("the exact command is authorized");
        let words = crate::livesrc::split_command(&launch);
        assert_eq!(
            Path::new(&words[0]),
            canonical_file(&executable, "fixture").unwrap()
        );
        assert_eq!(&words[1..], ["--fixture", "value"]);
    }

    #[test]
    fn policy_authorizes_a_profile_catalog_beneath_an_admitted_root() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "windbg-mcp-policy-profile-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let executable = std::env::current_exe().unwrap();
        let command = format!("\"{}\" --fixture", executable.display());
        let allowed = normalize_transport("fixture", &command).unwrap();
        let policy = Policy {
            disposable_vm_ids: BTreeSet::from(["51749a1f-f939-44f5-b251-1251ef5b64a3".to_string()]),
            transport_commands: BTreeSet::from([allowed]),
            profile_roots: vec![normalized_path(&directory.canonicalize().unwrap())],
            kit_roots: Vec::new(),
            max_pause_ms: Some(600_000),
        };

        let authorized = policy
            .authorize(
                "51749A1F-F939-44F5-B251-1251EF5B64A3",
                &directory,
                &command,
                &command,
            )
            .unwrap();
        assert!(authorized.profile.is_dir());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn policy_authorizes_a_profile_beneath_a_volume_root() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "windbg-mcp-policy-volume-root-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let profile = directory.join("build.json");
        std::fs::write(&profile, b"{}").unwrap();
        let canonical_directory = directory.canonicalize().unwrap();
        let volume_root = canonical_directory
            .ancestors()
            .last()
            .expect("an absolute Windows path has a volume root");
        let executable = std::env::current_exe().unwrap();
        let command = format!("\"{}\" --fixture", executable.display());
        let allowed = normalize_transport("fixture", &command).unwrap();
        let policy = Policy {
            disposable_vm_ids: BTreeSet::from(["51749a1f-f939-44f5-b251-1251ef5b64a3".to_string()]),
            transport_commands: BTreeSet::from([allowed]),
            profile_roots: vec![normalized_path(volume_root)],
            kit_roots: Vec::new(),
            max_pause_ms: Some(600_000),
        };

        let authorized = policy
            .authorize(
                "51749A1F-F939-44F5-B251-1251EF5B64A3",
                &profile,
                &command,
                &command,
            )
            .unwrap();
        assert!(authorized.profile.is_file());
        std::fs::remove_dir_all(directory).unwrap();
    }
}
