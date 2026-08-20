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
use std::path::Path;
use std::sync::Arc;

use anyhow::{Result, anyhow, bail};

/// The unnamed token, and the prefix of a named one.
const TOKEN_ENV: &str = "WINDBG_MCP_LISTEN_TOKEN";

/// The variable naming a *file* to read credentials from, which shares that prefix and is not one.
///
/// Excluded by name rather than by shape: its value is a path, so without this it would configure
/// a client called `file` whose credential is `C:\...\token` — a token nobody holds, under a name
/// nobody chose, and the real token silently absent.
const TOKEN_FILE_ENV: &str = "WINDBG_MCP_LISTEN_TOKEN_FILE";

/// How long a client's name may be — the same bound a kernel profile's name has, and for the same
/// reason: a name is rendered in log lines and in refusals, so it has to be a name.
const NAME_LIMIT: usize = 64;

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
#[derive(Clone, Default)]
pub struct Credentials {
    by_token: HashMap<String, Client>,
}

/// **The names, never the tokens** — the same reason [`crate::kdconn::Connection`]'s is redacted.
/// A derived one would put every credential this listener accepts into whatever formatted it, and
/// the things that format a value like this are a log line and a test's panic message.
impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("clients", &self.names())
            .finish()
    }
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

    /// Builds the set from `(variable, value)` pairs, or from the token file if there is one.
    ///
    /// Takes the variables rather than reading the environment for the reason
    /// [`crate::kdconn::env_entries`] does: `set_var` is `unsafe` in edition 2024 and mutates state
    /// the whole test binary shares, so the only way to assert that
    /// `WINDBG_MCP_LISTEN_TOKEN_CI` names the client `ci` is to hand the scan its variables.
    ///
    /// **A configured file is the *only* credential.** That precedence predates named tokens and
    /// is load-bearing: the service installer writes the file to `%ProgramData%` with an ACL of
    /// SYSTEM and Administrators precisely because the machine environment is readable by
    /// unprivileged processes. Letting an environment token stand beside it would mean a stale or
    /// planted variable authenticating to a LocalSystem listener — which has `launch` on it. So a
    /// file shuts the environment out entirely rather than merely outranking the unnamed variable,
    /// and names its own clients ([`TokenFile`]) rather than leaving the deployment that needs it
    /// most with room for one.
    pub fn from_entries(
        vars: impl Iterator<Item = (String, String)>,
        file: Option<TokenFile>,
    ) -> Result<Self> {
        match file {
            // The environment is not read at all when a file is configured — not even to complain
            // about it, which is the precedence stated as code: a host with a file is a host whose
            // environment is not trusted, so a variable there cannot stop this server starting any
            // more than it can authenticate to it.
            Some(file) => Self::build(&file.entries),
            None => Self::build(&from_env(vars)?),
        }
    }

    /// The two refusals every source of credentials is held to, wherever it was configured.
    ///
    /// A token appearing twice is refused rather than resolved. Two names for one credential means
    /// a caller's sessions land under whichever name won a `HashMap` insertion, which is a rule
    /// nobody could predict and a boundary that would move.
    fn build(configured: &[Configured]) -> Result<Self> {
        let mut by_token: HashMap<String, Client> = HashMap::new();
        // Client name to *what configured it* — never to the token. Both refusals below are
        // printed at startup, to stderr in the foreground and to the service log under the SCM, so
        // a message quoting the credential it is complaining about would write a working listener
        // token into whatever collects those. The source is also the more useful half: it is what
        // the operator has to go and change.
        let mut named: HashMap<&str, &str> = HashMap::new();
        for Configured { name, token, from } in configured {
            if !is_presentable(token) {
                bail!(
                    "the token in {from} cannot travel in an `Authorization` header, so nothing \
                     could ever authenticate with it: this server reads that header back as \
                     visible ASCII, which rules out a line break and anything outside it. It is \
                     not quoted here — this is printed at startup — and it is not repaired \
                     either, since a credential that is quietly not the one you wrote is exactly \
                     what this refuses."
                );
            }
            if let Some(existing) = by_token.get(token) {
                // One client is one credential (the check below), so whatever configured this
                // token is what configured that client.
                let first = named
                    .get(existing.name())
                    .copied()
                    .unwrap_or("another entry");
                bail!(
                    "{from} and {first} are the same token, configured for `{name}` and \
                     `{existing}`. One credential cannot name two clients: sessions opened with it \
                     would belong to whichever name happened to win."
                );
            }
            // **And the other way round.** Two *different* tokens landing on one name is the more
            // insidious half: nothing looks wrong, both callers authenticate, and they silently
            // share a namespace — routing, listing, capacity, teardown rights, the lot. Names are
            // folded before comparison, so `WINDBG_MCP_LISTEN_TOKEN` and `…_TOKEN_LOCAL` collide
            // (both `local`), as do `…_CI` and `…__CI`. (Two spellings of one *key* never reach
            // here: `TokenFile::parse` refuses a repeated name against the file itself, which can
            // say which file and which name.) A boundary two credentials can stand on is not a
            // boundary, so this is a configuration error rather than a merge.
            if let Some(other) = named.get(name.as_str()) {
                bail!(
                    "two different tokens are configured for the client `{name}` ({other} and \
                     {from}). Each client is one credential: two would share every session, which \
                     is the isolation this is for, silently absent."
                );
            }
            named.insert(name.as_str(), from.as_str());
            by_token.insert(token.clone(), Client::new(name));
        }
        Ok(Self { by_token })
    }
}

/// One configured credential: the client it names, the token, and where it came from.
///
/// The third field is what a refusal quotes, and it is deliberately never the token — a variable
/// name, or a key and the file holding it. It arrives already quoted, because how a source is
/// referred to is the source's business: `` `WINDBG_MCP_LISTEN_TOKEN_CI` `` reads as a variable and
/// `` `ci` in C:\ProgramData\windbg-mcp\token `` reads as an entry, and one template cannot
/// render both.
struct Configured {
    name: String,
    token: String,
    from: String,
}

/// The credentials a set of environment variables configures — names derived, nothing validated.
///
/// Validation is [`Credentials::build`]'s, so that the listener and [`env_credentials`] hold a
/// configuration to exactly one standard.
fn from_env(vars: impl Iterator<Item = (String, String)>) -> Result<Vec<Configured>> {
    let mut configured = Vec::new();
    for (key, value) in vars {
        let token = value.trim().to_string();
        // An empty value is not a token — it is a variable somebody exported and never set.
        if token.is_empty() || is_token_file(&key) {
            continue;
        }
        let name = match credential_suffix(&key) {
            // The unnamed variable, which is what every existing setup uses.
            Some("") => Client::LOCAL.to_string(),
            // `WINDBG_MCP_LISTEN_TOKEN_CI` names the client `ci`, the same lowercasing a kernel
            // profile's variable gets.
            Some(suffix) => suffix.trim_start_matches('_').to_ascii_lowercase(),
            None => continue,
        };
        // **Held to the same rule as a key in the file**, rather than skipped as it used to be.
        // Skipping is the shape this module refuses everywhere else: a credential the operator
        // configured, silently not configured, and a client that cannot authenticate for a reason
        // nothing says out loud. It also has to be *this* rule and not a laxer one, because
        // `env_credentials` writes these names into the token file — a name only the environment
        // would take is an install that succeeds and a service that then fails at every start.
        if !is_client_name(&name) {
            bail!(
                "`{key}` does not name a client. What follows `{TOKEN_ENV}_` is the name, and a \
                 name is letters, digits, `-`, `_` or `.`, up to {NAME_LIMIT} characters — \
                 `{TOKEN_ENV}_CI` names `ci`. The token it carries is not quoted here and is not \
                 the problem."
            );
        }
        configured.push(Configured {
            from: format!("`{key}`"),
            name,
            token,
        });
    }
    Ok(configured)
}

/// What this process's environment configures, as `(client, token)` pairs.
///
/// For [`crate::service::install`], which copies the installing shell's credentials into the file
/// the service reads. It validates by building the same [`Credentials`] the listener would, so an
/// install cannot write a file the service then refuses to start on — which is the worst shape
/// this can take, since the SCM registers a service once and it fails at every start afterwards.
pub fn env_credentials(
    vars: impl Iterator<Item = (String, String)>,
) -> Result<Vec<(String, String)>> {
    let configured = from_env(vars)?;
    Credentials::build(&configured)?;
    Ok(configured.into_iter().map(|c| (c.name, c.token)).collect())
}

/// The credentials a token file holds.
///
/// **Two shapes, because the file has two jobs.** A **bare token** names [`Client::LOCAL`]: that is
/// what a hand-written file has always been, and what [`crate::service::install`] writes for a
/// single-client host, so an install predating this keeps working with a file nobody has to touch.
/// A **JSON object of name to token** names several — the shape `WINDBG_MCP_PROFILES` already uses
/// for kernel profiles, so it is one an operator of this server has met before.
///
/// The second shape exists because of the precedence in [`Credentials::from_entries`]: a configured
/// file is the *only* credential, so until it a service-hosted listener could hold exactly one
/// client — and the per-client boundary was unreachable in precisely the deployment
/// `docs/remote-listener.md` recommends (`FOLLOWUPS.md` item 31). It is one file either way, so
/// the ACL that makes the file worth having is unchanged.
///
/// **A leading `{` is what tells them apart**, so a bare token may not begin with one. That is a
/// rule rather than a guess: a token that did would be refused at startup, by name, rather than
/// quietly read as something else.
pub struct TokenFile {
    entries: Vec<Configured>,
}

/// The names, never the tokens — as [`Credentials`]'s is, and for the same reason. [`Configured`]
/// has no `Debug` at all, so a container that grows a derived one fails to compile rather than
/// quietly starting to print credentials.
impl std::fmt::Debug for TokenFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenFile")
            .field(
                "clients",
                &self.entries.iter().map(|c| &c.name).collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl TokenFile {
    /// Parses a token file's text. `path` is here only to name the file in a refusal.
    ///
    /// **No message this can produce quotes a value from the file**, because every value in it is a
    /// credential and every one of these refusals is printed at startup — to stderr in the
    /// foreground, to the service log under the SCM. That is also why the JSON is walked as generic
    /// values rather than deserialized into a typed map, exactly as [`crate::kdconn`] walks the
    /// profile file: serde's type errors quote the value they rejected (`invalid type: integer 5`),
    /// while a syntax error carries a position and nothing else.
    pub fn parse(text: &str, path: &Path) -> Result<Self> {
        // **A leading UTF-8 BOM is not a broken file.** Windows PowerShell 5.1's `Set-Content
        // -Encoding utf8` — an obvious way to write this file — puts one in front, and U+FEFF is
        // not whitespace, so it survives a trim and lands *inside* the token. That is a file which
        // looks exactly right and authenticates nobody.
        let text = text.strip_prefix('\u{feff}').unwrap_or(text).trim();
        if text.is_empty() {
            bail!("{} is empty; that is not a token.", path.display());
        }
        if !text.starts_with('{') {
            // **The copy-paste trap, made loud.** Anything not beginning with `{` is the bare
            // shape, so a JSON object with a comment above it — which is what an operator copies
            // out of a document — is read as one token that happens to span the file.
            // [`Credentials::build`] refuses that anyway, since nothing can present it; this says
            // the more useful thing first. A line break is tested for here rather than
            // presentability at large because it is being read as *evidence about the shape* —
            // what is wrong is that this is not a token file, not that its credential is unusable.
            if text.contains(['\n', '\r']) {
                bail!(
                    "{} is not a token: it runs over more than one line, and a bearer token cannot \
                     contain a line break — nothing could present it. If this was meant to name \
                     clients, it has to be a JSON object and start with `{{`: no comment above it, \
                     since a file that does not begin with `{{` is read as one token.",
                    path.display()
                );
            }
            return Ok(Self {
                entries: vec![Configured {
                    name: Client::LOCAL.to_string(),
                    token: text.to_string(),
                    from: path.display().to_string(),
                }],
            });
        }
        let Entries(object) = serde_json::from_str(text).map_err(|e| {
            anyhow!(
                "{} begins with `{{`, so it is read as a JSON object of client name to token — and \
                 it is not valid JSON ({e}). A file holding one token is still a token file; it \
                 just may not start with `{{`.",
                path.display()
            )
        })?;
        let mut entries: Vec<Configured> = Vec::new();
        for (key, value) in object {
            let name = key.trim().to_ascii_lowercase();
            if !is_client_name(&name) {
                bail!(
                    "an entry in {} is named something that is not a client name (letters, digits, \
                     `-`, `_` or `.`, up to {NAME_LIMIT} characters). It is not quoted here on \
                     purpose: the likeliest way to write this file wrong is back to front, which \
                     would make that name a bearer token — and this refusal is printed at startup.",
                    path.display()
                );
            }
            let Some(token) = value.as_str() else {
                bail!(
                    "`{name}` in {} must be a string: the bearer token that client presents.",
                    path.display()
                );
            };
            let token = token.trim();
            if token.is_empty() {
                bail!(
                    "`{name}` in {} has no token. Give it one or remove the entry: a name nothing \
                     can present is a client that cannot connect.",
                    path.display()
                );
            }
            // **A repeated key is refused, not resolved**, which is why [`Entries`] keeps every
            // pair a `serde_json::Map` would have collapsed. Which of two entries wins is a
            // parser's business, not a boundary's: the operator sees both tokens written down and
            // one of them silently authenticates nobody.
            if entries.iter().any(|e| e.name == name) {
                bail!(
                    "`{name}` appears more than once in {}. Give each client one entry: which of \
                     the two would be accepted is whichever the parser kept, so the other is a \
                     credential you can read in the file and nobody can present.",
                    path.display()
                );
            }
            entries.push(Configured {
                from: format!("`{name}` in {}", path.display()),
                name,
                token: token.to_string(),
            });
        }
        if entries.is_empty() {
            bail!(
                "{} names no clients. It is a JSON object, so it has to map at least one client \
                 name to that client's token — `{{\"local\": \"<token>\"}}`.",
                path.display()
            );
        }
        Ok(Self { entries })
    }
}

/// Whether a token could be presented at all.
///
/// **Asked of the transport rather than described**, the same way the installer asks the reader
/// which file shape round-trips. A bearer token gets here as `Authorization: Bearer <token>`, and
/// `authorised` reads it back with `HeaderValue::to_str` — which yields only visible ASCII. So the
/// question is exactly whether this string survives that round trip: build the header value a
/// client would send, and read it back out the way the listener does. A token that does not
/// survive it authenticates nobody, however right everything else about it is.
///
/// Two rounds of review arrived here one case at a time — a line break first, then non-ASCII text
/// — which is what a hand-written charset would have kept doing. Every source of credentials is
/// held to it in [`Credentials::build`], because it is a fact about the header rather than about
/// where the token was written down: a variable can hold such a token as easily as a JSON string
/// can, and the installer would copy it into the file and report success.
///
/// Refused rather than repaired. What the operator wrote is not what would work, and this module's
/// whole job is that a credential is either configured or said to be absent.
fn is_presentable(token: &str) -> bool {
    hyper::header::HeaderValue::from_str(token).is_ok_and(|value| value.to_str().is_ok())
}

/// A JSON object's entries **in the order they were written, duplicates and all**.
///
/// `serde_json::Map` is the obvious target and the wrong one: it keeps the last of two entries
/// under one key and says nothing, so a file naming `ci` twice would configure one client, and the
/// token that lost is one the operator can read in the file and no client can present. Collecting
/// the pairs is what lets [`TokenFile::parse`] refuse that.
///
/// It quotes nothing either: keys arrive as `String` and values as `serde_json::Value`, so no
/// serde type error can be raised about a value here — the check that a value is a string is
/// [`TokenFile::parse`]'s, which names the key instead.
struct Entries(Vec<(String, serde_json::Value)>);

impl<'de> serde::Deserialize<'de> for Entries {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct EveryPair;
        impl<'de> serde::de::Visitor<'de> for EveryPair {
            type Value = Entries;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON object of client name to token")
            }

            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut map: M,
            ) -> Result<Entries, M::Error> {
                let mut pairs = Vec::new();
                while let Some(pair) = map.next_entry::<String, serde_json::Value>()? {
                    pairs.push(pair);
                }
                Ok(Entries(pairs))
            }
        }
        deserializer.deserialize_map(EveryPair)
    }
}

/// Whether this is a client name rather than something else that got put where one belongs.
///
/// The charset is what makes a name safe to *render*: no line breaks, so nothing configured here
/// can inject a line into the service log, and no `"`, `{` or `=`, so a connection string or a
/// token carrying one cannot pass for a name. The same rule a kernel profile's name follows.
///
/// **One rule, wherever the credential was configured** — a key in the token file and the suffix of
/// a variable are both held to it. The asymmetry that is not there any more is what review found
/// first: an install copies the environment's names *into* the file, so a name only the environment
/// would take is an install that succeeds and a service that then fails at every start.
///
/// **What it cannot do is tell a token from a name**, because a name-shaped token is a name: a file
/// written back to front — `{"<token>": "ci"}` — configures a client called after your token, and
/// the line that says who may connect prints client names. Nothing here can catch that, which is
/// why the refusal it *can* catch does not quote what it rejected, and why the operator-facing
/// documentation says which way round the file goes.
fn is_client_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= NAME_LIMIT
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
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

    /// Where a token file lives on the host this is all written for. Never read: [`TokenFile`]
    /// parses text, so these tests need no filesystem and the path is only what a refusal names.
    const FILE: &str = r"C:\ProgramData\windbg-mcp\token";

    fn file(text: &str) -> TokenFile {
        TokenFile::parse(text, Path::new(FILE)).expect("a token file these tests can use")
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
        // And the same for the file, whose every *value* is a credential — and whose *key* is one
        // too when the entry was written back to front.
        for text in [
            format!(r#"{{"a": "{}", "b": "{}"}}"#, secrets[0], secrets[0]),
            format!(r#"{{"ci": "{} "#, secrets[0]),
            format!(r#"{{"ci": ["{}"]}}"#, secrets[0]),
            // Back to front, with a key no name could be — which is the shape this refuses, and
            // the shape most likely to be holding a credential.
            format!(r#"{{"{}=x": "ci"}}"#, secrets[0]),
        ] {
            let why = TokenFile::parse(&text, Path::new(FILE))
                .and_then(|f| Credentials::from_entries(vars(&[]), Some(f)))
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
            Some(file("from-the-file")),
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

    /// **And because it is the only credential, it has to be able to name more than one.** A
    /// service-hosted listener reads nothing else, so before this the deployment
    /// `docs/remote-listener.md` recommends could hold exactly one client — with the per-client
    /// boundary that #162 built unreachable on the host that most needs it (`FOLLOWUPS.md` 31).
    #[test]
    fn a_token_file_may_name_several_clients() {
        let creds = Credentials::from_entries(
            vars(&[(TOKEN_ENV, "from-the-environment")]),
            Some(file(
                r#"{ "local": "for-local", "ci": "for-ci", "laptop": "for-laptop" }"#,
            )),
        )
        .expect("valid");
        assert_eq!(creds.names(), vec!["ci", "laptop", "local"]);
        assert_eq!(creds.client_for("for-ci").map(Client::name), Some("ci"));
        assert_eq!(
            creds.client_for("for-laptop").map(Client::name),
            Some("laptop")
        );
        // Still the only credential: naming several clients does not let the environment back in.
        assert_eq!(creds.client_for("from-the-environment"), None);
    }

    /// The shape is chosen by the file's first character, so a token stays a token.
    ///
    /// Every file written before this one is a bare token, and the installer still writes one for a
    /// single-client host — so the common file must not need re-writing to keep working.
    #[test]
    fn a_bare_token_file_is_a_token_and_a_json_one_is_a_map() {
        for (text, whose) in [
            ("plain-token", "local"),
            (r#"{"ci": "plain-token"}"#, "ci"),
            // Whitespace and a trailing newline are how a file arrives from an editor, and a BOM is
            // how it arrives from Windows PowerShell 5.1's `Set-Content -Encoding utf8`. U+FEFF is
            // not whitespace, so without the strip it lands inside the token: a file that looks
            // right and authenticates nobody.
            ("\u{feff}  plain-token\r\n", "local"),
            ("\u{feff}{\"ci\": \"plain-token\"}\n", "ci"),
        ] {
            let creds = Credentials::from_entries(vars(&[]), Some(file(text)))
                .unwrap_or_else(|e| panic!("{text:?} is a token file: {e}"));
            assert_eq!(
                creds.client_for("plain-token").map(Client::name),
                Some(whose),
                "{text:?}"
            );
        }
    }

    /// The refusals a badly written token file earns, and every one of them at startup rather than
    /// as a client that cannot connect for reasons nobody can see.
    #[test]
    fn a_token_file_that_names_nothing_usable_is_refused() {
        for (text, expected) in [
            ("", "is empty"),
            ("   \n", "is empty"),
            // The copy-paste trap: a JSON object with the file's path commented above it. It does
            // not begin with `{`, so it is the bare shape — a "token" spanning four lines, which
            // no `Authorization` header could ever carry.
            (
                "// C:\\ProgramData\\windbg-mcp\\token\n{\"ci\": \"one\"}",
                "more than one line",
            ),
            ("{}", "names no clients"),
            (r#"{"ci": }"#, "not valid JSON"),
            (r#"{"ci": 5}"#, "must be a string"),
            (r#"{"ci": "  "}"#, "has no token"),
            // Written back to front, with a token no name could be — the detectable half of that
            // mistake. The other half is not: see `is_client_name`.
            (
                r#"{"net:port=50000,key=1.2.3.4": "ci"}"#,
                "not a client name",
            ),
            // One name written twice, which a `serde_json::Map` would have collapsed to the last
            // of them — leaving a token written in the file that authenticates nobody.
            (r#"{"ci": "one", "ci": "two"}"#, "appears more than once"),
            (r#"{"ci": "one", "ci": "one"}"#, "appears more than once"),
            // Two *spellings* of one name are the same thing, since names are folded before they
            // are compared — which is what makes this a name collision rather than two clients.
            (r#"{"ci": "one", "CI ": "two"}"#, "appears more than once"),
            // And one token under two names is the other half of it.
            (
                r#"{"ci": "same", "laptop": "same"}"#,
                "cannot name two clients",
            ),
        ] {
            let why = TokenFile::parse(text, Path::new(FILE))
                .and_then(|f| Credentials::from_entries(vars(&[]), Some(f)))
                .expect_err(&format!("{text:?} is not a usable token file"))
                .to_string();
            assert!(why.contains(expected), "{text:?} was refused with: {why}");
            assert!(
                why.contains(FILE),
                "a refusal has to name the file it is about: {why}"
            );
        }
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

    /// A token that cannot travel in an `Authorization` header is refused wherever it was
    /// configured — a line break, non-ASCII text, anything `HeaderValue::to_str` will not yield —
    /// because `authorised` reads the header back that way and could never match it. Accepting one
    /// is a listener that starts and authenticates nobody.
    #[test]
    fn a_token_that_cannot_be_presented_is_refused() {
        let refusals = [
            // A line break, from the environment — which the installer would copy into the file.
            Credentials::from_entries(vars(&[(TOKEN_ENV, "s3cret\nalpha")]), None),
            // And from the file, where a JSON string can carry an escaped one.
            TokenFile::parse(r#"{"ci": "s3cret\nalpha"}"#, Path::new(FILE))
                .and_then(|f| Credentials::from_entries(vars(&[]), Some(f))),
            // Non-ASCII, which `HeaderValue::to_str` will not yield either — so `authorised` can
            // never match it, and every request from that client would be a 401.
            Credentials::from_entries(vars(&[(TOKEN_ENV, "s3cret-café")]), None),
            TokenFile::parse(r#"{"ci": "s3cret-café"}"#, Path::new(FILE))
                .and_then(|f| Credentials::from_entries(vars(&[]), Some(f))),
        ];
        for refusal in refusals {
            let why = refusal
                .expect_err("a token nothing can present is a configuration error")
                .to_string();
            assert!(why.contains("`Authorization` header"), "{why}");
            assert!(
                !why.contains("s3cret"),
                "a startup refusal wrote a bearer token into the log: {why}"
            );
        }
    }

    /// A variable whose suffix is not a client name is refused, and the refusal names the variable
    /// rather than what it carries.
    ///
    /// It used to be skipped, which is the failure this module refuses everywhere else: a
    /// credential the operator configured, silently not configured. And it has to be the *same*
    /// rule the file is held to, because `env_credentials` copies these names into the file — a
    /// name only the environment would take is an install that reports success and a service that
    /// fails at every start, which is precisely what validating at install time is for.
    #[test]
    fn a_variable_that_does_not_name_a_client_is_refused() {
        let secret = "s3cret-alpha";
        for key in [
            "WINDBG_MCP_LISTEN_TOKEN_MY CLIENT",
            "WINDBG_MCP_LISTEN_TOKEN_ci=laptop",
            &format!("WINDBG_MCP_LISTEN_TOKEN_{}", "x".repeat(NAME_LIMIT + 1)),
            // The prefix with nothing after it but a separator: a typo, not the unnamed variable.
            "WINDBG_MCP_LISTEN_TOKEN_",
        ] {
            let why = Credentials::from_entries(vars(&[(key, secret)]), None)
                .expect_err(&format!("`{key}` does not name a client"))
                .to_string();
            assert!(why.contains("does not name a client"), "{key}: {why}");
            assert!(
                !why.contains(secret),
                "a startup refusal wrote a bearer token into the log: {why}"
            );
        }
        // And the same variable is *ignored* when a file is configured, rather than refusing the
        // start: a file shuts the environment out entirely, so nothing there can stop this server
        // any more than it can authenticate to it.
        let creds = Credentials::from_entries(
            vars(&[("WINDBG_MCP_LISTEN_TOKEN_MY CLIENT", secret)]),
            Some(file("from-the-file")),
        )
        .expect("a file is read instead of the environment, not beside it");
        assert_eq!(creds.names(), vec!["local"]);
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
            Some(file("from-the-file")),
        )
        .expect("valid");
        assert_eq!(
            creds.client_for("from-the-file").map(Client::name),
            Some("local")
        );
        assert_eq!(creds.client_for(r"C:\somewhere\token"), None);
    }
}
