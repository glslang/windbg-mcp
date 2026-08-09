//! Kernel connection strings — the one tool argument that is a **secret**.
//!
//! A KDNET connection string carries the target's debug key (`net:port=50000,key=w.x.y.z`), and a
//! key is all an attacker on the same network needs to take over the debug link. Passing it as a
//! tool argument puts it somewhere this server does not control: an MCP client keeps its own
//! transcript, and a key handed over once is then replicated through messages, tool calls, context
//! snapshots and compaction summaries. That is not the client misbehaving — it is what a
//! transcript *is* — so the fix has to be that the secret never enters the request.
//!
//! Two things here do that:
//!
//! - **Profiles.** `attach_kernel { "profile": "ctf-vm" }` names a connection this process
//!   resolves from its own environment or a local file. The name is not a secret; the string it
//!   resolves to never leaves this process except down the private pipe to the session's own
//!   engine worker.
//! - **[`Connection`], a value that cannot be printed.** Its `Debug` and `Display` render the
//!   redacted form, so the raw string is reachable only through [`Connection::expose`] — one call
//!   site, in the worker, handing it to DbgEng. Every other route to a log line, an error, or a
//!   session report is redacted by construction rather than by remembering to redact.
//!
//! Redaction still matters with profiles in place, because `connection` stays supported: a target
//! whose key is not configured anywhere has to be reachable, and an operator driving this server
//! by hand should not have to write a config file first.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Environment prefix for a single profile: `WINDBG_MCP_PROFILE_CTF_VM=net:port=50000,key=…`
/// defines the profile `ctf-vm`.
const PROFILE_ENV_PREFIX: &str = "WINDBG_MCP_PROFILE_";

/// Overrides where the profile file is read from. Machine-local configuration, so it is expected
/// to be set per host rather than shipped.
const PROFILES_FILE_ENV: &str = "WINDBG_MCP_PROFILES";

/// The profile file's default location under the user's profile directory.
const DEFAULT_PROFILES_FILE: &[&str] = &[".windbg-mcp", "profiles.json"];

/// Connection-string parameters whose value is a secret.
///
/// `key` is KDNET's; `password` is what `.server`/`.remote` connection strings use. Matched
/// case-insensitively and only as a whole parameter name, so `pubkey=` is not mistaken for one.
const SECRET_PARAMS: &[&str] = &["key", "password"];

/// What a redacted secret is replaced with. Deliberately not the same length as any real value —
/// a mask that preserved length would leak the key's shape.
const MASK: &str = "<redacted>";

/// A kernel connection string, with the secret sealed in.
///
/// `Debug` and `Display` both render [`redact`]ed, which is the point: this type exists so that
/// putting a connection string in a log line, an error, or a session report is *safe by default*
/// and exposing it takes a deliberate [`Connection::expose`]. Serialization is transparent — the
/// raw string crosses the supervisor↔worker pipe, which is a pair of anonymous pipes nothing
/// outside those two processes can read (see [`crate::proto`]).
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Connection(String);

impl Connection {
    pub fn new(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }

    /// The raw string, key and all — for handing to DbgEng and nothing else.
    ///
    /// The **only** way the secret leaves this type. Anything that renders a connection for a
    /// human or a log wants `Display`/[`Connection::redacted`] instead.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// The connection as it is safe to report: shape intact, secrets masked.
    pub fn redacted(&self) -> String {
        redact(&self.0)
    }
}

impl fmt::Display for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.redacted())
    }
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Connection({:?})", self.redacted())
    }
}

/// Masks the secret parameters of a connection string, leaving everything else readable.
///
/// `net:port=50000,key=1.2.3.4` → `net:port=50000,key=<redacted>`. The transport and the port are
/// what let a person tell two sessions apart, and neither is a secret, so this masks *values* and
/// never the whole string.
///
/// Scans for `<name>=`, decides on the name, and skips the value: a name is what sits between the
/// preceding delimiter and the `=`, and a value runs to the next `,`/`;`/whitespace. That means an
/// `=` **inside** a masked value is consumed with it rather than restarting the scan — which is
/// the case a naive split-on-`=` gets wrong, and it gets it wrong by emitting the tail of a key.
pub fn redact(connection: &str) -> String {
    const NAME_DELIMS: &[char] = &[',', ';', ':', '=', ' ', '\t'];
    const VALUE_DELIMS: &[char] = &[',', ';', ' ', '\t'];

    let mut out = String::with_capacity(connection.len());
    let mut rest = connection;
    loop {
        let Some(eq) = rest.find('=') else {
            out.push_str(rest);
            return out;
        };
        let (head, tail) = rest.split_at(eq);
        // All the delimiters are ASCII, so a byte index past one is a char boundary.
        let name = &head[head.rfind(NAME_DELIMS).map_or(0, |i| i + 1)..];
        out.push_str(head);
        out.push('=');
        let value = &tail[1..];
        if SECRET_PARAMS.iter().any(|p| p.eq_ignore_ascii_case(name)) {
            let end = value.find(VALUE_DELIMS).unwrap_or(value.len());
            // An empty value has nothing to mask, and masking it would invent a secret that is
            // not there — the honest rendering of `key=` is `key=`.
            if end > 0 {
                out.push_str(MASK);
            }
            rest = &value[end..];
        } else {
            rest = value;
        }
    }
}

/// One configured profile, keyed in [`Profiles`] by its normalized name but remembering the name
/// as it was actually written — that is what an operator will recognise in an error.
struct Profile {
    name: String,
    connection: Connection,
}

/// The kernel connection profiles configured on this host.
///
/// Read afresh for every attach rather than cached at startup, so adding a profile does not mean
/// restarting the server (and, more to the point, does not mean restarting the MCP client).
pub struct Profiles {
    entries: BTreeMap<String, Profile>,
    /// A profile file that exists but could not be used. Kept rather than raised immediately: it
    /// must not break an attach that passes `connection` and needs no profiles at all, but it also
    /// must not make a typo'd file look identical to "no such profile".
    problem: Option<String>,
    /// Where a profile file would be read from, for the "how do I configure one" advice. `None`
    /// only when the host has no `USERPROFILE`, which on Windows means something is very wrong.
    file: Option<PathBuf>,
}

impl Profiles {
    /// Reads the profiles this host defines: environment first, then the file for any name the
    /// environment did not already define.
    ///
    /// Environment wins because it is the more specific of the two — a variable set for this
    /// server's process is a deliberate override of a file that is shared with every other
    /// process the user runs.
    pub fn from_host() -> Self {
        let mut entries = from_env(std::env::vars());

        let file = profiles_file();
        let mut problem = None;
        match file.as_deref().map(read_profile_file) {
            Some(Ok(from_file)) => {
                for (name, connection) in from_file {
                    entries.entry(normalize(&name)).or_insert(Profile {
                        name,
                        connection: Connection::new(connection),
                    });
                }
            }
            Some(Err(why)) => problem = Some(why),
            None => {}
        }

        Self {
            entries,
            problem,
            file,
        }
    }

    /// A fixed set, for tests: resolution has to be provable without mutating the process
    /// environment, which in edition 2024 is `unsafe` and races every other test in the binary.
    #[cfg(test)]
    fn from_pairs(pairs: &[(&str, &str)]) -> Self {
        Self {
            entries: pairs
                .iter()
                .map(|(name, connection)| {
                    (
                        normalize(name),
                        Profile {
                            name: (*name).to_string(),
                            connection: Connection::new(*connection),
                        },
                    )
                })
                .collect(),
            problem: None,
            file: Some(PathBuf::from(r"C:\Users\test\.windbg-mcp\profiles.json")),
        }
    }

    fn get(&self, name: &str) -> Option<&Profile> {
        self.entries.get(&normalize(name))
    }

    /// The configured names, as they were written. Names are not secrets — that is the whole
    /// point of them — so they are safe to put in an error a client will keep.
    fn names(&self) -> Vec<&str> {
        self.entries.values().map(|p| p.name.as_str()).collect()
    }

    /// The tail of an error that has to explain where profiles come from.
    fn how_to_configure(&self) -> String {
        let file = match &self.file {
            Some(path) => format!(
                "or from a JSON object mapping name to connection string in {}",
                path.display()
            ),
            None => format!("or from a JSON file named by {PROFILES_FILE_ENV}"),
        };
        let problem = match &self.problem {
            Some(why) => format!("\n\nThe profile file could not be read: {why}"),
            None => String::new(),
        };
        format!(
            "Profiles are resolved by this server, on this host: from `{PROFILE_ENV_PREFIX}<NAME>` \
             in its environment {file}. Names are matched case-insensitively, with `-` and `_` \
             equivalent. Ask the user to add one — this server cannot.{problem}"
        )
    }

    /// The "which profiles exist" clause, phrased for whichever of the two cases holds.
    fn listed(&self) -> String {
        match self.names().as_slice() {
            [] => "No profiles are configured on this host.".to_string(),
            names => format!("Configured profiles: {}.", names.join(", ")),
        }
    }
}

/// The profiles a set of environment variables defines.
///
/// Split out from [`Profiles::from_host`] so the mapping is testable: `std::env::set_var` is
/// `unsafe` in edition 2024 and mutates state every other test in this binary shares, so the only
/// way to prove `WINDBG_MCP_PROFILE_CTF_VM` defines the profile `ctf-vm` is to hand the scan its
/// variables rather than the process's.
fn from_env(vars: impl Iterator<Item = (String, String)>) -> BTreeMap<String, Profile> {
    let mut entries = BTreeMap::new();
    for (key, value) in vars {
        let Some(suffix) = key.strip_prefix(PROFILE_ENV_PREFIX) else {
            continue;
        };
        if suffix.is_empty() || value.trim().is_empty() {
            continue;
        }
        // The variable's own suffix *is* the profile's name, lowercased — an environment variable
        // cannot carry a hyphen, so `WINDBG_MCP_PROFILE_CTF_VM` lists as `ctf_vm`. Asking for
        // `ctf-vm` still finds it: both normalize to the same key.
        let name = suffix.to_ascii_lowercase();
        entries.insert(
            normalize(&name),
            Profile {
                name,
                connection: Connection::new(value.trim()),
            },
        );
    }
    entries
}

/// Where the profile file lives on this host.
fn profiles_file() -> Option<PathBuf> {
    if let Some(override_path) = std::env::var_os(PROFILES_FILE_ENV)
        && !override_path.is_empty()
    {
        return Some(PathBuf::from(override_path));
    }
    std::env::var_os("USERPROFILE").map(|home| {
        DEFAULT_PROFILES_FILE
            .iter()
            .fold(PathBuf::from(home), |path, part| path.join(part))
    })
}

/// Reads the profile file. A file that is not there is not a problem — configuring no profiles is
/// the default — so that reads as an empty set rather than an error.
///
/// Parsed as a generic `Value` and walked by hand rather than deserialized into a typed map,
/// because the values here are secrets and serde's type errors quote the value they rejected
/// (`invalid type: integer 5`). Walking it means every message this can produce names a *key*, and
/// syntax errors from `serde_json` carry a position rather than any content.
fn read_profile_file(path: &Path) -> Result<BTreeMap<String, String>, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(e) => return Err(format!("{} could not be read ({e})", path.display())),
    };
    let parsed: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| format!("{} is not valid JSON ({e})", path.display()))?;
    let object = parsed.as_object().ok_or_else(|| {
        format!(
            "{} must be a JSON object mapping profile name to connection string",
            path.display()
        )
    })?;
    let mut out = BTreeMap::new();
    for (name, value) in object {
        let connection = value.as_str().ok_or_else(|| {
            format!(
                "profile `{name}` in {} must be a string (its connection string)",
                path.display()
            )
        })?;
        if !connection.trim().is_empty() {
            out.insert(name.clone(), connection.trim().to_string());
        }
    }
    Ok(out)
}

/// The form two profile names are compared in: case-insensitive, and `-`/`_`/`.` interchangeable.
///
/// Needed because the same profile can be written three ways — `ctf-vm` in a request, `ctf-vm` in
/// the file, `WINDBG_MCP_PROFILE_CTF_VM` in the environment, where the variable name cannot carry
/// a hyphen at all. Without normalization an environment-defined profile could not be named the
/// way anyone would write it.
fn normalize(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

/// A resolved kernel target: the string to dial, and how the session may describe itself.
///
/// `Debug`-printable in full, because both fields already are: the label is redacted at
/// construction and [`Connection`]'s own `Debug` is the redacted one.
#[derive(Debug)]
pub struct Selected {
    pub connection: Connection,
    /// What `session_status` (and the "no room to open another" list) shows for this session.
    /// Redacted at construction, so nothing downstream has to remember to redact it.
    pub label: String,
}

/// Turns `attach_kernel`'s two selectors into one target, or explains why it cannot.
///
/// Exactly one of them is required, and that is enforced here rather than in the schema. The
/// alternative — an untagged `oneOf` — renders as a schema composition that clients handle
/// unevenly (the same reason `session_id` is repeated per tool struct instead of flattened), and
/// the cost of enforcing it at runtime is one tool error with text the model can act on.
///
/// Errors never echo a value: a caller who puts a connection string in `profile` by mistake — the
/// most likely way to get this wrong, and the one that would defeat the whole feature — is told
/// what shape a profile name has, not shown what they sent.
pub fn select(connection: Option<String>, profile: Option<String>) -> Result<Selected, String> {
    let connection = connection.filter(|c| !c.trim().is_empty());
    let profile = profile.filter(|p| !p.trim().is_empty());
    match (connection, profile) {
        (Some(_), Some(_)) => Err(
            "attach_kernel takes exactly one of `connection` or `profile`, and both were given. \
             Pass `profile` alone to have this server resolve the connection locally, or \
             `connection` alone to dial the string as given."
                .to_string(),
        ),
        (Some(connection), None) => {
            let connection = Connection::new(connection.trim());
            Ok(Selected {
                label: connection.redacted(),
                connection,
            })
        }
        (None, Some(profile)) => resolve(profile.trim(), &Profiles::from_host()),
        (None, None) => Err(neither(&Profiles::from_host())),
    }
}

/// What a caller who named no target is told. Its job is to make `profile` the obvious next call
/// by naming the profiles that already exist — a caller who has to ask the user anyway will ask
/// for the connection string, and then the key is in the transcript.
fn neither(profiles: &Profiles) -> String {
    format!(
        "attach_kernel takes exactly one of `connection` or `profile`, and neither was given. \
         `profile` names a connection this server resolves on this host, so the target's debug \
         key never enters this request (or the client transcript that keeps it); `connection` is \
         the raw string, e.g. \"net:port=50000,key=<w.x.y.z>\". {} {}",
        profiles.listed(),
        profiles.how_to_configure()
    )
}

/// Looks a profile up, or says what to do about it not being there.
fn resolve(name: &str, profiles: &Profiles) -> Result<Selected, String> {
    if !is_profile_name(name) {
        // The value is not echoed back, deliberately. This is the branch a mistyped
        // `profile: "net:port=50000,key=…"` lands in, and echoing it would write the key into
        // exactly the transcript profiles exist to keep it out of.
        return Err(format!(
            "`profile` must be the *name* of a connection configured on this host — letters, \
             digits, `-`, `_` or `.`, e.g. \"ctf-vm\" — and the value given is not one. If it was \
             a connection string, pass it as `connection` instead. {}",
            profiles.listed()
        ));
    }
    match profiles.get(name) {
        Some(profile) => Ok(Selected {
            label: format!("profile \"{}\" ({})", profile.name, profile.connection),
            connection: profile.connection.clone(),
        }),
        None => Err(format!(
            "no kernel connection profile named `{name}` is configured on this host. {} {}",
            profiles.listed(),
            profiles.how_to_configure()
        )),
    }
}

/// Whether this is a profile name rather than something else that got put in the field.
fn is_profile_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every test here uses this. A real key is `w.x.y.z` dotted decimal; this is the same shape
    /// so the redaction is exercised the way it will be used, and it is not anyone's key.
    const FAKE: &str = "net:port=50000,key=1.2.3.4";
    const FAKE_KEY: &str = "1.2.3.4";

    #[test]
    fn redaction_masks_the_key_and_keeps_the_rest() {
        assert_eq!(redact(FAKE), "net:port=50000,key=<redacted>");
    }

    #[test]
    fn redaction_masks_a_key_wherever_it_sits() {
        assert_eq!(
            redact("net:key=a.b.c.d,port=50000"),
            "net:key=<redacted>,port=50000"
        );
        assert_eq!(redact("key=a.b.c.d"), "key=<redacted>");
        assert_eq!(
            redact("net:port=1,key=a.b.c.d,target=host"),
            "net:port=1,key=<redacted>,target=host"
        );
    }

    #[test]
    fn redaction_is_case_insensitive_and_covers_remote_passwords() {
        assert_eq!(
            redact("net:port=1,KEY=a.b.c.d"),
            "net:port=1,KEY=<redacted>"
        );
        assert_eq!(
            redact("npipe:pipe=dbg,server=box,password=hunter2"),
            "npipe:pipe=dbg,server=box,password=<redacted>"
        );
    }

    /// A parameter that merely *ends* in `key` is a different parameter, and masking it would
    /// hide something a caller needs to read back.
    #[test]
    fn redaction_matches_whole_parameter_names_only() {
        assert_eq!(redact("net:port=1,pubkey=abc"), "net:port=1,pubkey=abc");
        assert_eq!(redact("net:port=1,keying=abc"), "net:port=1,keying=abc");
    }

    /// A key containing `=` must be consumed whole. Split-on-`=` would resume inside the value
    /// and emit its tail — the one failure mode of this function that leaks the thing it hides.
    #[test]
    fn redaction_consumes_a_value_containing_an_equals_sign() {
        let out = redact("net:port=1,password=ab=cd=ef,target=host");
        assert_eq!(out, "net:port=1,password=<redacted>,target=host");
        assert!(!out.contains("cd"), "{out}");
    }

    #[test]
    fn redaction_leaves_a_string_with_no_secret_alone() {
        for s in ["net:port=50000", "com:port=com1,baud=115200", "", "key"] {
            assert_eq!(redact(s), s);
        }
        // Nothing to mask is not the same as something to hide.
        assert_eq!(redact("net:port=1,key="), "net:port=1,key=");
    }

    #[test]
    fn a_connection_never_renders_its_key() {
        let c = Connection::new(FAKE);
        assert!(!format!("{c}").contains(FAKE_KEY));
        assert!(!format!("{c:?}").contains(FAKE_KEY));
        assert_eq!(c.expose(), FAKE, "expose is the one way through");
    }

    /// The wire form has to stay a bare string: the worker deserializes it from JSON that this
    /// type is only a supervisor-side wrapper around.
    #[test]
    fn a_connection_serializes_transparently() {
        let json = serde_json::to_string(&Connection::new(FAKE)).unwrap();
        assert_eq!(json, format!("\"{FAKE}\""));
        let back: Connection = serde_json::from_str(&json).unwrap();
        assert_eq!(back.expose(), FAKE);
    }

    #[test]
    fn selecting_both_or_neither_is_refused() {
        let both = select(Some(FAKE.into()), Some("ctf-vm".into())).unwrap_err();
        assert!(both.contains("exactly one"), "{both}");
        assert!(
            both.contains("`connection`") && both.contains("`profile`"),
            "{both}"
        );

        let neither = select(None, None).unwrap_err();
        assert!(neither.contains("exactly one"), "{neither}");
        assert!(neither.contains("`profile`"), "{neither}");

        // Blank is the same as absent, or a client that helpfully sends `""` gets a report of a
        // session opened on an empty connection string.
        let blank = select(Some("   ".into()), None).unwrap_err();
        assert!(blank.contains("exactly one"), "{blank}");
    }

    #[test]
    fn an_explicit_connection_is_dialed_as_given_and_labelled_redacted() {
        let selected = select(Some(format!("  {FAKE}  ")), None).unwrap();
        assert_eq!(selected.connection.expose(), FAKE, "trimmed, not rewritten");
        assert_eq!(selected.label, "net:port=50000,key=<redacted>");
    }

    #[test]
    fn a_profile_resolves_to_its_connection_without_naming_the_key() {
        let profiles = Profiles::from_pairs(&[("ctf-vm", FAKE)]);
        let selected = resolve("ctf-vm", &profiles).unwrap();
        assert_eq!(selected.connection.expose(), FAKE);
        assert!(selected.label.contains("ctf-vm"), "{}", selected.label);
        assert!(!selected.label.contains(FAKE_KEY), "{}", selected.label);
    }

    /// The same profile is written three ways — request, file, environment variable — and the
    /// environment form cannot carry a hyphen at all.
    #[test]
    fn profile_names_match_across_the_forms_they_are_written_in() {
        let profiles = Profiles::from_pairs(&[("ctf-vm", FAKE)]);
        for asked in ["ctf-vm", "CTF-VM", "ctf_vm", "Ctf_Vm"] {
            assert!(resolve(asked, &profiles).is_ok(), "{asked} should resolve");
        }
    }

    /// The environment half of the same claim, on the real scan: a variable defines a profile
    /// under its own spelling, and the hyphenated name a person would type finds it anyway.
    #[test]
    fn an_environment_variable_defines_the_profile_its_name_spells() {
        let vars = [
            ("WINDBG_MCP_PROFILE_CTF_VM", FAKE),
            // Neither of these is a profile: one is blank, one is a different variable.
            ("WINDBG_MCP_PROFILE_BLANK", "   "),
            ("WINDBG_MCP_CALL_TIMEOUT_SECS", "30"),
        ]
        .map(|(k, v)| (k.to_string(), v.to_string()));

        let profiles = Profiles {
            entries: from_env(vars.into_iter()),
            problem: None,
            file: None,
        };
        assert_eq!(profiles.names(), ["ctf_vm"]);
        for asked in ["ctf-vm", "ctf_vm", "CTF-VM"] {
            let selected =
                resolve(asked, &profiles).unwrap_or_else(|e| panic!("{asked} should resolve: {e}"));
            assert_eq!(selected.connection.expose(), FAKE);
        }
    }

    #[test]
    fn an_unknown_profile_names_the_ones_that_exist() {
        let profiles = Profiles::from_pairs(&[("ctf-vm", FAKE), ("lab", "net:port=1,key=9.9.9.9")]);
        let err = resolve("typo", &profiles).unwrap_err();
        assert!(err.contains("`typo`"), "{err}");
        assert!(err.contains("ctf-vm") && err.contains("lab"), "{err}");
        assert!(!err.contains(FAKE_KEY) && !err.contains("9.9.9.9"), "{err}");
    }

    /// The mistake that would defeat the whole feature: a connection string typed into `profile`.
    /// It has to be refused *and* not quoted back, or the key lands in the transcript anyway.
    #[test]
    fn a_connection_string_in_the_profile_field_is_refused_without_being_echoed() {
        let profiles = Profiles::from_pairs(&[("ctf-vm", FAKE)]);
        let err = resolve(FAKE, &profiles).unwrap_err();
        assert!(err.contains("`connection`"), "{err}");
        assert!(
            !err.contains(FAKE_KEY),
            "the error quoted the key back: {err}"
        );
        assert!(!err.contains("port=50000"), "{err}");
    }

    #[test]
    fn no_error_on_the_profile_path_can_carry_a_secret() {
        let profiles = Profiles::from_pairs(&[("ctf-vm", FAKE)]);
        for asked in [
            "typo",
            FAKE,
            "",
            "key=1.2.3.4",
            "  ",
            "ctf vm",
            &"x".repeat(500),
        ] {
            if let Err(err) = resolve(asked, &profiles) {
                assert!(!err.contains(FAKE_KEY), "for {asked:?}: {err}");
            }
        }
    }

    /// The message a caller gets for naming no target at all has to point at `profile` *and* say
    /// which ones exist — a caller who has to go and ask the user anyway will come back with a
    /// connection string, and then the key is in the transcript after all.
    #[test]
    fn naming_no_target_points_at_the_profiles_that_exist() {
        let err = neither(&Profiles::from_pairs(&[("ctf-vm", FAKE), ("lab", FAKE)]));
        assert!(err.contains("exactly one"), "{err}");
        assert!(err.contains("ctf-vm") && err.contains("lab"), "{err}");
        assert!(err.contains(PROFILE_ENV_PREFIX), "{err}");
        assert!(!err.contains(FAKE_KEY), "{err}");

        let none = neither(&Profiles::from_pairs(&[]));
        assert!(none.contains("No profiles are configured"), "{none}");
    }

    #[test]
    fn a_profile_file_is_optional_but_a_broken_one_is_reported() {
        let dir = std::env::temp_dir().join(format!("windbg-mcp-kdconn-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let missing = dir.join("does-not-exist.json");
        assert!(read_profile_file(&missing).unwrap().is_empty());

        let good = dir.join("good.json");
        std::fs::write(
            &good,
            format!("{{ \"ctf-vm\": \"{FAKE}\", \"blank\": \"\" }}"),
        )
        .unwrap();
        let parsed = read_profile_file(&good).unwrap();
        assert_eq!(parsed.get("ctf-vm").map(String::as_str), Some(FAKE));
        assert!(
            !parsed.contains_key("blank"),
            "an empty value is not a profile"
        );

        let bad = dir.join("bad.json");
        std::fs::write(&bad, "{ not json").unwrap();
        assert!(
            read_profile_file(&bad)
                .unwrap_err()
                .contains("not valid JSON")
        );

        // A non-string value names the key, never the value — serde's own type error would have
        // quoted the value, and the values in this file are keys.
        let typed = dir.join("typed.json");
        std::fs::write(&typed, "{ \"ctf-vm\": 12345 }").unwrap();
        let err = read_profile_file(&typed).unwrap_err();
        assert!(err.contains("`ctf-vm`"), "{err}");
        assert!(!err.contains("12345"), "{err}");

        std::fs::remove_dir_all(&dir).ok();
    }
}
