//! Which client a call belongs to, and how this server knows.
//!
//! # Why this exists
//!
//! The listener used to answer "whose call is this?" with the MCP session id, and serve one client
//! at a time so the answer was always "the only one". `2026-07-28` removed the protocol-level
//! session (SEP-2567), so that identifier is gone on the revision most clients now negotiate, and
//! with it both properties the tenancy gate provided: two clients are served, and neither can be
//! told apart ([#162](https://github.com/glslang/windbg-mcp/issues/162)).
//!
//! **In a stateless protocol the only sound identity is authentication.** There is no connection to
//! key on — requests arrive on whatever socket the client's pool hands them — no session id by
//! design, and `clientInfo` is not retained between requests. What is left is the credential the
//! caller presents, which is exactly how every other stateless HTTP API knows who is asking.
//!
//! So a listener may hold several tokens, each naming a client, and a session belongs to whichever
//! client opened it. A name that another client cannot present is a boundary; a name it chooses for
//! itself would be a label.
//!
//! That boundary is the only one left. The gate that served one client at a time has since been
//! retired outright (`FOLLOWUPS.md` item 28): once a session belongs to a client, one credential
//! opening a second MCP session contests nothing — both reach the same debug sessions, because
//! they are the same client.
//!
//! # How it reaches a tool
//!
//! The same way a progress sink does, and for the same reason: the identity is known at the
//! transport and needed forty-odd tool bodies away, and threading it through every signature would
//! name something none of them uses. It is a task-local, set around the whole MCP call so the
//! routing, the worker handshake and the engine call all run inside the scope.
//!
//! Under stdio there is nothing to authenticate and nothing to separate — one process, one client,
//! by construction — so calls there run as [`Client::LOCAL`] and every lookup behaves as it always
//! has.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Result, bail};

/// The unnamed token, and the prefix of a named one.
const TOKEN_ENV: &str = "WINDBG_MCP_LISTEN_TOKEN";

/// The variable naming a *file* to read a token from, which shares that prefix and is not one.
///
/// Excluded by name rather than by shape: its value is a path, so without this it would configure
/// a client called `file` whose credential is `C:\...\token` — a token nobody holds, under a name
/// nobody chose, and the real token silently absent.
const TOKEN_FILE_ENV: &str = "WINDBG_MCP_LISTEN_TOKEN_FILE";

/// Who a call belongs to.
///
/// A name rather than an opaque id so it can be said out loud — in a log line, in `session_status`,
/// in the message a caller gets when it asks for a session that is not its own. It is chosen by
/// whoever configured the token, never by the client presenting it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Client(Arc<str>);

impl Client {
    /// The client every stdio call belongs to.
    ///
    /// Not a placeholder: under stdio there is exactly one client by construction — it owns the
    /// process's standard handles — so naming it is what lets one set of registry rules serve both
    /// transports rather than one rule and an exception.
    pub const LOCAL: &'static str = "local";

    pub fn new(name: impl AsRef<str>) -> Self {
        Self(Arc::from(name.as_ref()))
    }

    pub fn local() -> Self {
        Self::new(Self::LOCAL)
    }

    pub fn name(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The tokens this listener accepts, and the client each one names.
#[derive(Debug, Clone, Default)]
pub struct Credentials {
    by_token: HashMap<String, Client>,
}

impl Credentials {
    /// The client presenting `token`, or `None` if nothing here accepts it.
    pub fn client_for(&self, token: &str) -> Option<&Client> {
        self.by_token.get(token)
    }

    pub fn len(&self) -> usize {
        self.by_token.len()
    }

    /// Every configured name, sorted — for the one log line that says who may connect.
    pub fn names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.by_token.values().map(Client::name).collect();
        names.sort_unstable();
        names
    }

    /// Builds the set from `(variable, value)` pairs and the file token, if there is one.
    ///
    /// Takes the variables rather than reading the environment for the reason
    /// [`crate::kdconn::env_entries`] does: `set_var` is `unsafe` in edition 2024 and mutates state
    /// the whole test binary shares, so the only way to assert that
    /// `WINDBG_MCP_LISTEN_TOKEN_CI` names the client `ci` is to hand the scan its variables.
    ///
    /// A token appearing twice is refused rather than resolved. Two names for one credential means
    /// a caller's sessions land under whichever name won a `HashMap` insertion, which is a rule
    /// nobody could predict and a boundary that would move.
    pub fn from_entries(
        vars: impl Iterator<Item = (String, String)>,
        file_token: Option<String>,
    ) -> Result<Self> {
        let mut by_token: HashMap<String, Client> = HashMap::new();
        // Client name to the *variable* that configured it — never to the token. Both refusals
        // below are printed at startup, to stderr in the foreground and to the service log under
        // the SCM, so a message quoting the credential it is complaining about would write a
        // working listener token into whatever collects those. The variable is also the more useful
        // half: it is what the operator has to go and change.
        let mut named: HashMap<String, String> = HashMap::new();
        let mut insert = |token: String, name: &str, from: &str| -> Result<()> {
            if let Some(existing) = by_token.get(&token) {
                // One client is one credential (the check below), so the variable that configured
                // this token is the one that configured that client.
                let first = named
                    .get(existing.name())
                    .map_or("another variable", String::as_str);
                bail!(
                    "`{from}` and `{first}` are the same token, configured for `{name}` and \
                     `{existing}`. One credential cannot name two clients: sessions opened with it \
                     would belong to whichever name happened to win."
                );
            }
            // **And the other way round.** Two *different* tokens landing on one name is the more
            // insidious half: nothing looks wrong, both callers authenticate, and they silently
            // share a namespace — routing, listing, capacity, teardown rights, the lot. Names are
            // folded before comparison, so `WINDBG_MCP_LISTEN_TOKEN` and `…_TOKEN_LOCAL` collide
            // (both `local`), as do `…_CI` and `…__CI`. A boundary two credentials can stand on is
            // not a boundary, so this is a configuration error rather than a merge.
            if let Some(other) = named.get(name) {
                bail!(
                    "two different tokens are configured for the client `{name}` (`{other}` and \
                     `{from}`). Each client is one credential: two would share every session, \
                     which is the isolation this is for, silently absent."
                );
            }
            named.insert(name.to_string(), from.to_string());
            by_token.insert(token, Client::new(name));
            Ok(())
        };

        // **A configured file is the *only* credential.** That precedence predates named tokens
        // and is load-bearing: the service installer writes the token to `%ProgramData%` with an
        // ACL of SYSTEM and Administrators precisely because the machine environment is readable by
        // unprivileged processes. Letting an environment token stand beside it would mean a stale
        // or planted variable authenticating to a LocalSystem listener — which has `launch` on it.
        // So a file shuts the environment out entirely rather than merely outranking the unnamed
        // variable.
        if let Some(token) = file_token {
            insert(token, Client::LOCAL, TOKEN_FILE_ENV)?;
            return Ok(Self { by_token });
        }
        for (key, value) in vars {
            let token = value.trim().to_string();
            if token.is_empty() {
                continue;
            }
            if is_token_file(&key) {
                continue;
            }
            match credential_suffix(&key) {
                // The unnamed variable, which is what every existing setup uses.
                Some("") => insert(token, Client::LOCAL, &key)?,
                // `WINDBG_MCP_LISTEN_TOKEN_CI` names the client `ci`, the same lowercasing a
                // kernel profile's variable gets.
                Some(suffix) => {
                    let name = suffix.trim_start_matches('_').to_ascii_lowercase();
                    if name.is_empty() {
                        continue;
                    }
                    insert(token, &name, &key)?;
                }
                None => {}
            }
        }
        Ok(Self { by_token })
    }
}

/// The part of a credential variable's name after the prefix, if it is one.
///
/// **Compared case-insensitively, because Windows environment names are.** `std::env::var` finds
/// `Windbg_Mcp_Listen_Token` for a lookup of `WINDBG_MCP_LISTEN_TOKEN`, and a host configured that
/// way worked until this scan replaced that lookup. Getting it wrong is two failures at once: a
/// listener that refuses to start because it can no longer see its own token, and — worse — a
/// mixed-case variable that [`token_file`]'s `var_os` still resolves while the strip below walks
/// past it, handing a debuggee the credential.
///
/// Length-preserving on ASCII, which every variable here is, so the suffix is taken from the
/// original name rather than the folded copy.
fn credential_suffix(name: &str) -> Option<&str> {
    name.to_ascii_uppercase()
        .starts_with(TOKEN_ENV)
        .then(|| &name[TOKEN_ENV.len()..])
}

/// Whether this variable names the token *file* rather than carrying a token.
fn is_token_file(name: &str) -> bool {
    name.eq_ignore_ascii_case(TOKEN_FILE_ENV)
}

/// Every environment variable that configures a credential, for a process that must not inherit
/// one.
///
/// **Prefix, not a list.** `Credentials::from_entries` accepts anything starting with
/// `WINDBG_MCP_LISTEN_TOKEN`, so a strip that named the variables it knew about would let the next
/// named token through — and the failure would be silent, a debuggee holding a credential nobody
/// meant to hand it. The path in `…_TOKEN_FILE` is stripped for the same reason: a target that
/// knows where the token lives can read it if the file is reachable at all.
pub fn strip_credentials(command: &mut impl EnvRemove) {
    for (name, _) in std::env::vars() {
        if credential_suffix(&name).is_some() {
            command.remove(&name);
        }
    }
}

/// The one thing [`strip_credentials`] needs of a command, so it can serve both the worker spawn
/// (which uses tokio's) and the TTD recorder (which uses the standard library's).
pub trait EnvRemove {
    fn remove(&mut self, name: &str);
}

impl EnvRemove for std::process::Command {
    fn remove(&mut self, name: &str) {
        self.env_remove(name);
    }
}

impl EnvRemove for tokio::process::Command {
    fn remove(&mut self, name: &str) {
        self.env_remove(name);
    }
}

tokio::task_local! {
    /// The client whose call is running on this task.
    ///
    /// Set by the transport — the listener around each MCP call, once it knows which token was
    /// presented — and read wherever a session is opened or looked up. Unset outside a call, and
    /// under stdio, where [`current`] answers [`Client::local`].
    static CALLER: Client;
}

/// The client this call belongs to.
///
/// [`Client::local`] when nothing set one, which is stdio and every in-process test: a server with
/// no authentication has exactly one client, and giving it a name is what keeps the registry rules
/// uniform instead of conditional.
pub fn current() -> Client {
    CALLER
        .try_with(Clone::clone)
        .unwrap_or_else(|_| Client::local())
}

/// Runs `work` as `client`.
pub async fn as_client<F: std::future::Future>(client: Client, work: F) -> F::Output {
    CALLER.scope(client, work).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(pairs: &[(&str, &str)]) -> impl Iterator<Item = (String, String)> + use<> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect::<Vec<_>>()
            .into_iter()
    }

    /// The unnamed variable is what every existing listener uses, so it keeps working and names the
    /// same client stdio calls run as.
    #[test]
    fn the_unnamed_token_names_the_local_client() {
        let creds = Credentials::from_entries(vars(&[(TOKEN_ENV, "s3cret")]), None).expect("valid");
        assert_eq!(creds.client_for("s3cret").map(Client::name), Some("local"));
        assert_eq!(creds.client_for("wrong"), None);
    }

    /// A suffix names a client, lowercased — the same rule a kernel profile's variable follows.
    #[test]
    fn a_suffixed_token_names_its_client() {
        let creds = Credentials::from_entries(
            vars(&[
                ("WINDBG_MCP_LISTEN_TOKEN_CI", "ci-token"),
                ("WINDBG_MCP_LISTEN_TOKEN_Laptop", "laptop-token"),
            ]),
            None,
        )
        .expect("valid");
        assert_eq!(creds.client_for("ci-token").map(Client::name), Some("ci"));
        assert_eq!(
            creds.client_for("laptop-token").map(Client::name),
            Some("laptop")
        );
        assert_eq!(creds.names(), vec!["ci", "laptop"]);
    }

    /// One credential naming two clients is refused at startup rather than resolved, because the
    /// winner would be a `HashMap` ordering detail and the boundary would move between runs.
    #[test]
    fn one_token_may_not_name_two_clients() {
        let clash = Credentials::from_entries(
            vars(&[
                ("WINDBG_MCP_LISTEN_TOKEN_A", "same"),
                ("WINDBG_MCP_LISTEN_TOKEN_B", "same"),
            ]),
            None,
        );
        let why = clash.expect_err("a duplicate token is a configuration error");
        assert!(why.to_string().contains("cannot name two clients"), "{why}");
        assert!(
            why.to_string().contains("WINDBG_MCP_LISTEN_TOKEN_A")
                && why.to_string().contains("WINDBG_MCP_LISTEN_TOKEN_B"),
            "the refusal has to name the two variables, since they are what has to change: {why}"
        );
    }

    /// **Neither refusal may quote the credential it is refusing.** Both are printed at startup —
    /// to stderr in the foreground, to `%ProgramData%\windbg-mcp\service.log` under the SCM — so a
    /// message carrying the token would leave a working listener credential in whatever collects
    /// those, which outlives the misconfiguration by as long as the file does.
    #[test]
    fn a_refusal_never_quotes_the_token_it_refuses() {
        let secrets = ["s3cret-alpha", "s3cret-beta"];
        let refusals = [
            // One credential, two names.
            vec![
                ("WINDBG_MCP_LISTEN_TOKEN_A", secrets[0]),
                ("WINDBG_MCP_LISTEN_TOKEN_B", secrets[0]),
            ],
            // Two credentials, one name.
            vec![
                ("WINDBG_MCP_LISTEN_TOKEN_CI", secrets[0]),
                ("WINDBG_MCP_LISTEN_TOKEN__CI", secrets[1]),
            ],
        ];
        for pairs in refusals {
            let why = Credentials::from_entries(vars(&pairs), None)
                .expect_err("a configuration error")
                .to_string();
            for secret in secrets {
                assert!(
                    !why.contains(secret),
                    "a startup refusal wrote a bearer token into the log: {why}"
                );
            }
        }
    }

    /// Windows environment names are case-insensitive, and `std::env::var` honours that — so a host
    /// configured as `Windbg_Mcp_Listen_Token` worked before this scan existed and has to keep
    /// working. The same fold is what makes the child-process strip see a mixed-case variable that
    /// `var_os` can still resolve.
    #[test]
    fn credential_variables_are_matched_however_they_are_cased() {
        let creds = Credentials::from_entries(
            vars(&[
                ("Windbg_Mcp_Listen_Token", "unnamed"),
                ("windbg_mcp_listen_token_ci", "for-ci"),
            ]),
            None,
        )
        .expect("valid");
        assert_eq!(creds.client_for("unnamed").map(Client::name), Some("local"));
        assert_eq!(creds.client_for("for-ci").map(Client::name), Some("ci"));
        // And the file variable is still not a token, whatever its casing.
        assert!(is_token_file("Windbg_Mcp_Listen_Token_File"));
        assert!(credential_suffix("Windbg_Mcp_Listen_Token_File").is_some());
    }

    /// A token file shuts the environment out completely, named tokens included.
    ///
    /// The file exists because the environment is not trusted on that host — the service installer
    /// ACLs it to SYSTEM and Administrators for exactly that reason — so a variable standing beside
    /// it would reintroduce what it was written to avoid.
    #[test]
    fn a_token_file_is_the_only_credential() {
        let creds = Credentials::from_entries(
            vars(&[
                (TOKEN_ENV, "from-the-environment"),
                ("WINDBG_MCP_LISTEN_TOKEN_CI", "also-from-the-environment"),
            ]),
            Some("from-the-file".to_string()),
        )
        .expect("valid");
        assert_eq!(
            creds.client_for("from-the-file").map(Client::name),
            Some("local")
        );
        assert_eq!(creds.len(), 1, "the environment must not add credentials");
        assert_eq!(creds.client_for("from-the-environment"), None);
        assert_eq!(creds.client_for("also-from-the-environment"), None);
    }

    /// Two credentials normalising to one name is refused, and it is the quieter half of the same
    /// mistake: nothing looks wrong, both tokens authenticate, and their holders silently share a
    /// namespace. `WINDBG_MCP_LISTEN_TOKEN` and `…_TOKEN_LOCAL` are both `local`; `…_CI` and
    /// `…__CI` are both `ci`.
    #[test]
    fn two_tokens_may_not_name_one_client() {
        for pairs in [
            vec![
                (TOKEN_ENV, "unnamed"),
                ("WINDBG_MCP_LISTEN_TOKEN_LOCAL", "named"),
            ],
            vec![
                ("WINDBG_MCP_LISTEN_TOKEN_CI", "one"),
                ("WINDBG_MCP_LISTEN_TOKEN__CI", "two"),
            ],
        ] {
            let why = Credentials::from_entries(vars(&pairs), None)
                .expect_err("a shared namespace is a configuration error");
            assert!(
                why.to_string().contains("two different tokens"),
                "{why} (from {pairs:?})"
            );
        }
    }

    /// An empty value is not a token — it is a variable somebody exported and never set.
    #[test]
    fn an_empty_value_configures_nothing() {
        let creds = Credentials::from_entries(vars(&[("WINDBG_MCP_LISTEN_TOKEN_CI", "   ")]), None)
            .expect("valid");
        assert_eq!(creds.len(), 0);
    }

    /// Unrelated variables are ignored, including the one naming the *file* to read a token from —
    /// its contents are a token, its path is not.
    #[test]
    fn only_the_token_variables_are_read() {
        let creds = Credentials::from_entries(
            vars(&[
                ("WINDBG_MCP_LISTEN_TOKEN_FILE", r"C:\somewhere\token"),
                ("PATH", "/usr/bin"),
            ]),
            Some("from-the-file".to_string()),
        )
        .expect("valid");
        assert_eq!(
            creds.client_for("from-the-file").map(Client::name),
            Some("local")
        );
        assert_eq!(creds.client_for(r"C:\somewhere\token"), None);
    }
}
