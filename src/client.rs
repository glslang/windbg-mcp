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
//!
//! # What a name buys besides isolation
//!
//! A **tool surface of its own**. A client is a budget as much as it is a boundary: the
//! arrangement this listener was built for is a local model that can hold twenty tools beside a
//! hosted client that can hold fifty-one, on the same box and against the same debug sessions. So
//! a credential may carry a [`crate::toolset::Toolset`] as well as a name — configured beside the
//! token, under the same variable prefix or in the same file entry — and a client that names none
//! is served whatever the run serves. That is `FOLLOWUPS.md` item 36, and the identity above is
//! what made it a field rather than a feature.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Result, anyhow, bail};

/// The unnamed token, and the prefix of a named one.
const TOKEN_ENV: &str = "WINDBG_MCP_LISTEN_TOKEN";

/// The unnamed tool-surface spec, and the prefix of a named one.
///
/// **Beside the token variable, and read by the same scan**, because a client's surface and a
/// client's credential are configured by the same person in the same place — see
/// [`crate::toolset`] for what a spec is and why one client's is not another's. It carries no
/// secret, so it is not held to [`is_presentable`] and is not stripped from a child process; what
/// it *is* held to is naming a client this listener actually accepts, which is
/// [`from_env`]'s last refusal.
pub const TOOLS_ENV: &str = "WINDBG_MCP_TOOLS";

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
///
/// # The name is what you see; the identity is the pair
///
/// **A name can be given back**, and until this it was the whole of a client's identity. So
/// `--remove-listen-client ci` followed by `--add-listen-client ci` produced two credentials that
/// every structure keyed on identity — session ownership, routing, lease state, the four-session
/// cap — could not tell apart, and the second reached what the first had opened
/// ([#190](https://github.com/glslang/windbg-mcp/issues/190)). That is exactly the isolation this
/// type exists to provide, and exactly what `--rotate-listen-client` exists to do *deliberately*:
/// rotation keeps the name, so it keeps the sessions, while a removal must not.
///
/// So identity is `(name, incarnation)`. The incarnation is invisible — [`Display`](Self::fmt) and
/// [`name`](Self::name) render the name alone, so every log line, refusal and `session_status` row
/// says what it always did — and it is minted in exactly one place, [`Accepted::replace`], which is
/// the only code that knows whether a name is *being given back* or *carrying on*.
///
/// [`Self::new`] deliberately does **not** mint one. It builds the sole holder of a name, which is
/// what stdio has, what every in-process test wants, and what makes `Client::new("ci")` twice mean
/// one client rather than two.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Client {
    name: Arc<str>,
    /// Which holder of that name. `0` is "the only one there has ever been" — see [`Self::new`].
    incarnation: u64,
}

impl Client {
    /// The client every stdio call belongs to.
    ///
    /// Not a placeholder: under stdio there is exactly one client by construction — it owns the
    /// process's standard handles — so naming it is what lets one set of registry rules serve both
    /// transports rather than one rule and an exception.
    pub const LOCAL: &'static str = "local";

    /// The sole holder of `name`.
    ///
    /// Incarnation `0`, which nothing minted and nothing will mint again: under stdio there is one
    /// client and no configuration to give it back to anybody, and in a test two mentions of a name
    /// mean one client. A listener's clients are [minted](Accepted::replace) from `1` up, so they
    /// can never collide with this — and the two never coexist anyway, since a process is one
    /// transport or the other.
    pub fn new(name: impl AsRef<str>) -> Self {
        Self {
            name: Arc::from(name.as_ref()),
            incarnation: 0,
        }
    }

    /// The `n`th holder of `name`, for the one caller that knows what `n` is.
    ///
    /// Crate-visible only so tests elsewhere can build two clients that share a name — in a running
    /// server [`Accepted::replace`] is the sole caller, because it is the only code that can tell a
    /// name carrying on from a name being given back.
    pub(crate) fn incarnate(name: &str, incarnation: u64) -> Self {
        Self {
            name: Arc::from(name),
            incarnation,
        }
    }

    pub fn local() -> Self {
        Self::new(Self::LOCAL)
    }

    /// **The name alone**, which is the whole of what may be rendered. Two clients that share a
    /// name are two clients, and nothing outside this module has any use for which is which — a log
    /// line saying `ci#7` would be noise to an operator who configured one client called `ci`.
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl std::fmt::Display for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.name)
    }
}

/// The tokens this listener accepts, and the client each one **names**.
///
/// A name rather than a [`Client`], and that is the division of labour behind
/// [#190](https://github.com/glslang/windbg-mcp/issues/190): a configuration says which names may
/// connect, and only [`Accepted`] — which can see the set that was in force a moment ago — knows
/// whether a name appearing here is one carrying on or one being given back. Minting an identity
/// from a file that cannot answer that question is what let a re-added name inherit its
/// predecessor's sessions.
#[derive(Clone, Default)]
pub struct Credentials {
    by_token: HashMap<String, String>,
    /// Name to the surface that client is served, for the clients configured with one of their
    /// own. **Absent is not "every tool"** — it is "whatever this run serves", which is the run's
    /// `--tools` and usually every tool. Keeping the two apart is what lets a listener started
    /// with a narrow `--tools` still have a client that was given a wider spec, and what makes an
    /// entry with no `tools` field mean exactly what it meant before there was one.
    surfaces: HashMap<String, crate::toolset::Toolset>,
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
    /// The **name** of the client presenting `token`, or `None` if nothing here accepts it.
    pub fn client_for(&self, token: &str) -> Option<&str> {
        self.by_token.get(token).map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.by_token.len()
    }

    /// Every configured name, sorted — for the one log line that says who may connect.
    pub fn names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.by_token.values().map(String::as_str).collect();
        names.sort_unstable();
        names
    }

    /// The surface configured for this client, or `None` for one that takes the run's.
    pub fn surface_for(&self, name: &str) -> Option<&crate::toolset::Toolset> {
        self.surfaces.get(name)
    }

    /// Every client with a surface of its own, as `(name, summary)`, sorted — for the startup and
    /// reload lines. Empty on the configuration everyone has, where it costs those lines nothing.
    pub fn surfaces(&self) -> Vec<(&str, String)> {
        let mut rows: Vec<(&str, String)> = self
            .surfaces
            .iter()
            .map(|(name, surface)| (name.as_str(), surface.summary()))
            .collect();
        rows.sort_unstable_by(|a, b| a.0.cmp(b.0));
        rows
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
    ///
    /// **A tool surface follows its credential**, so a configured file is the only source of those
    /// too and [`TOOLS_ENV`] is not read at all on a host that has one. Not because a spec is a
    /// secret — it is a list of group names — but because one configuration answering "who may
    /// connect" and another answering "what do they get" is two files to keep in step and a
    /// precedence rule to remember. A client's surface is written where its token is.
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
    ///
    /// A spec is parsed here too, and by the same call the listener's `--tools` goes through, so a
    /// surface an operator writes down is one this server can actually serve — refused at startup
    /// rather than discovered by a caller whose tool list came back empty.
    fn build(configured: &[Configured]) -> Result<Self> {
        let mut by_token: HashMap<String, String> = HashMap::new();
        let mut surfaces: HashMap<String, crate::toolset::Toolset> = HashMap::new();
        // Client name to *what configured it* — never to the token. Both refusals below are
        // printed at startup, to stderr in the foreground and to the service log under the SCM, so
        // a message quoting the credential it is complaining about would write a working listener
        // token into whatever collects those. The source is also the more useful half: it is what
        // the operator has to go and change.
        let mut named: HashMap<&str, &str> = HashMap::new();
        for Configured {
            name,
            token,
            tools,
            from,
        } in configured
        {
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
                    .get(existing.as_str())
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
            if let Some(spec) = tools {
                // Held to the flag's own parser, so `session,inspect` means here what it means on
                // a command line — and so `session` is added to a client's surface for the same
                // reason it is added to a run's. The source is named rather than the flag: this
                // spec was written in a variable or a file, and telling its operator to edit
                // `--tools` would send them to a command line that has nothing to do with it.
                let surface = crate::toolset::Toolset::parse_from(&spec.text, &spec.from)
                    .map_err(|e| anyhow!("{e}"))?;
                surfaces.insert(name.clone(), surface);
            }
            named.insert(name.as_str(), from.as_str());
            by_token.insert(token.clone(), name.clone());
        }
        Ok(Self { by_token, surfaces })
    }
}

/// The credentials a listener is serving *right now*, replaceable while it runs — and the one
/// place a client's identity is minted.
///
/// [`Credentials`] is what a configuration says; this is what the running listener accepts, and the
/// difference is two whole features. Built once at startup, a service-hosted listener's client list
/// would be fixed until the next start, and a restart drops every session it holds — which for a
/// parked kernel attach is the outage that made adding a client a planned one (`FOLLOWUPS.md` item
/// 34). So the set lives behind a lock that [`crate::service::edit_client`] can swap under the
/// accept loop.
///
/// **And swapping is the only moment anyone can tell a name carrying on from a name being given
/// back**, which is why incarnations are minted here and nowhere else
/// ([#190](https://github.com/glslang/windbg-mcp/issues/190)). A name in the new set that was in
/// the old one keeps its identity — that is a `--rotate-listen-client`, which changes a token and
/// deliberately keeps the sessions. A name that was absent gets a fresh one, so a
/// `--remove-listen-client` followed by an `--add-listen-client` yields a client that shares a name
/// with its predecessor and *nothing else*: it cannot route to its sessions, inherit its MCP session
/// ids, or renew its lease, because none of those match on a name.
///
/// **A read lock on the authentication path**, which is the cheapest thing that is also correct: a
/// request takes it uncontended, and the one writer runs once per administrative command. And it
/// is [recovered from poisoning](Self::state) rather than unwrapped — a panic anywhere near the
/// swap must not turn into a listener that refuses every caller for the rest of its life.
pub struct Accepted {
    current: std::sync::RwLock<Arc<State>>,
    /// The next incarnation to hand out. Never reset, so a name given back is never confused with
    /// the holder before it however many times it changes hands.
    next: std::sync::atomic::AtomicU64,
}

/// One generation of the configuration: the tokens, and which holder of each name is current.
struct State {
    credentials: Credentials,
    /// Name to incarnation, for every name [`State::credentials`] accepts.
    incarnations: HashMap<String, u64>,
}

impl State {
    fn client_for(&self, token: &str) -> Option<Client> {
        let name = self.credentials.client_for(token)?;
        // A name the credentials accept always has an incarnation: they are built together in
        // `Accepted::replace`, which is the only writer of either.
        let incarnation = *self.incarnations.get(name)?;
        Some(Client::incarnate(name, incarnation))
    }
}

/// What a [reload](Accepted::replace) changed.
///
/// **Clients, not names**, because the caller acts on them: a removal has to release the sessions
/// of the incarnation that is going, and a name is no longer enough to say which that is. A
/// rotation shows up as neither — the name is unchanged and so is its identity, which is what makes
/// rotation keep the sessions it is documented to keep.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Change {
    pub added: Vec<Client>,
    pub removed: Vec<Client>,
}

impl Change {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }

    /// The names on one side of the change, for a log line.
    pub fn names(clients: &[Client]) -> String {
        clients
            .iter()
            .map(Client::name)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

impl Accepted {
    pub fn new(credentials: Credentials) -> Self {
        let accepted = Self {
            current: std::sync::RwLock::new(Arc::new(State {
                credentials: Credentials::default(),
                incarnations: HashMap::new(),
            })),
            // From 1, so nothing a listener mints can collide with the `0` [`Client::new`] gives
            // the sole holder of a name.
            next: std::sync::atomic::AtomicU64::new(1),
        };
        accepted.replace(credentials);
        accepted
    }

    /// The generation in force, past a poisoned lock.
    ///
    /// `into_inner` rather than `unwrap`, because of what the two do on the request path. The lock
    /// guards an `Arc` that is only ever read or replaced wholesale, so a panic while it was held
    /// cannot have left a half-written set behind — there is no invariant to protect. Propagating
    /// the poison would instead take a listener holding live kernel targets and have it refuse
    /// every caller, its own operator included, until someone restarted it.
    fn state(&self) -> Arc<State> {
        match self.current.read() {
            Ok(guard) => Arc::clone(&guard),
            Err(poisoned) => Arc::clone(&poisoned.into_inner()),
        }
    }

    /// The client presenting `token`, or `None` if nothing here accepts it.
    pub fn client_for(&self, token: &str) -> Option<Client> {
        self.state().client_for(token)
    }

    /// The surface this client is served, or `None` for one that takes the run's.
    ///
    /// **Read where the identity is**, in the listener's service factory: that is the one moment
    /// the caller is knowable, and a surface decided anywhere later would be decided for whichever
    /// task rmcp happened to serve the call from. It is also what fixes when a reload takes
    /// effect — see [`crate::toolset`].
    pub fn surface_for(&self, client: &Client) -> Option<crate::toolset::Toolset> {
        self.state().credentials.surface_for(client.name()).cloned()
    }

    /// Every client with a surface of its own, as `<name> serves <summary>`, for a log line.
    /// Empty on the configuration everyone has.
    pub fn surfaces(&self) -> Vec<String> {
        self.state()
            .credentials
            .surfaces()
            .into_iter()
            .map(|(name, summary)| format!("{name} serves {summary}"))
            .collect()
    }

    /// Every configured name, sorted — for the lines that say who may connect.
    pub fn names(&self) -> Vec<String> {
        self.state()
            .credentials
            .names()
            .into_iter()
            .map(str::to_owned)
            .collect()
    }

    /// Swaps in a freshly read set, and says which clients appeared and which went.
    ///
    /// The *caller* acts on the removals, because what to do about them is not this type's
    /// business: a client whose credential is gone cannot reach the sessions it opened, so the
    /// listener releases them down the path the lease sweep already uses. See
    /// [`crate::listen::reloaded`].
    pub fn replace(&self, credentials: Credentials) -> Change {
        let before = self.state();
        let mut incarnations = HashMap::new();
        let mut added = Vec::new();
        for name in credentials.names() {
            // **Carrying on, or being given back.** The only question this function exists to
            // answer, and the only place in the program that can.
            match before.incarnations.get(name) {
                Some(&existing) => {
                    incarnations.insert(name.to_string(), existing);
                }
                None => {
                    let minted = self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    incarnations.insert(name.to_string(), minted);
                    added.push(Client::incarnate(name, minted));
                }
            }
        }
        let removed = before
            .incarnations
            .iter()
            .filter(|(name, _)| !incarnations.contains_key(name.as_str()))
            .map(|(name, &incarnation)| Client::incarnate(name, incarnation))
            .collect();

        let fresh = Arc::new(State {
            credentials,
            incarnations,
        });
        match self.current.write() {
            Ok(mut guard) => *guard = fresh,
            Err(poisoned) => *poisoned.into_inner() = fresh,
        }
        Change { added, removed }
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
    /// The tool surface this client is served, or `None` for one that takes the run's. See
    /// [`Credentials::surfaces`] for why those two are not the same answer.
    tools: Option<Spec>,
    from: String,
}

/// A tool-surface spec as it was written down, and where that was.
///
/// **Two fields rather than one because the second is not the token's.** Configured from the
/// environment a client's surface and its credential are two variables, so a refusal about the
/// spec has to name the variable holding the spec — and [`Configured::from`] names the other one.
/// In the credential file they are one entry, and this still renders as the field within it.
struct Spec {
    text: String,
    from: String,
}

/// One client as a configuration writes it down.
///
/// What the [client commands](crate::service::edit_client) read out of the credential file, change
/// one of, and write back — so it carries everything that file holds about a client and nothing
/// about where it came from, which is [`Configured`]'s business and stays private.
///
/// **No `Debug`**, for the reason [`Credentials`]'s is hand-written: it holds a token, and the
/// things that format a value like this are a log line and a test's panic message.
pub struct ClientEntry {
    pub name: String,
    pub token: String,
    /// The `--tools` spec this client is served, as text. `None` takes whatever the run serves,
    /// which is what every client had before one could be set.
    pub tools: Option<String>,
}

impl Configured {
    /// The entry as a configuration to be validated, named after the client itself.
    ///
    /// For the writers — [`env_credentials`] and [`TokenFile::credentials`] hand their result
    /// straight back to a caller that writes it to the file the service reads, and a set that
    /// would not start a listener must not be written down as if it would.
    fn of(entry: &ClientEntry, from: String) -> Self {
        Self {
            name: entry.name.clone(),
            token: entry.token.clone(),
            tools: entry.tools.as_ref().map(|text| Spec {
                text: text.clone(),
                from: from.clone(),
            }),
            from,
        }
    }

    fn entry(self) -> ClientEntry {
        ClientEntry {
            name: self.name,
            token: self.token,
            tools: self.tools.map(|spec| spec.text),
        }
    }
}

/// Every [`ClientEntry`] a command is about to write, held to the rules a listener would hold it
/// to — including that each spec is a surface this server can serve.
pub fn check(entries: &[ClientEntry]) -> Result<()> {
    let configured: Vec<Configured> = entries
        .iter()
        .map(|entry| Configured::of(entry, format!("`{}`", entry.name)))
        .collect();
    Credentials::build(&configured).map(|_| ())
}

/// The credentials a set of environment variables configures — names derived, nothing validated.
///
/// Validation is [`Credentials::build`]'s, so that the listener and [`env_credentials`] hold a
/// configuration to exactly one standard.
fn from_env(vars: impl Iterator<Item = (String, String)>) -> Result<Vec<Configured>> {
    let mut configured = Vec::new();
    // Collected rather than attached as they are read, because an iterator over the environment is
    // in no order: `WINDBG_MCP_TOOLS_CI` may arrive before the token that names `ci` exists here.
    let mut specs: HashMap<String, Spec> = HashMap::new();
    for (key, value) in vars {
        let value = value.trim().to_string();
        // An empty value is not a token — it is a variable somebody exported and never set. The
        // same reading for a spec: an empty one is not "serve nothing", which is a surface with no
        // opener in it and cannot be used at all.
        if value.is_empty() || is_token_file(&key) {
            continue;
        }
        if let Some(suffix) = tools_suffix(&key) {
            let name = client_named_by(suffix);
            if !is_client_name(&name) {
                bail!(
                    "`{key}` does not name a client. What follows `{TOOLS_ENV}_` is the name, and \
                     a name is letters, digits, `-`, `_` or `.`, up to {NAME_LIMIT} characters — \
                     `{TOOLS_ENV}_CI` is the tool surface served to `ci`."
                );
            }
            // **Two spellings of one name are refused, not merged**, the same as two tokens for
            // one client and for the same reason: names are folded, so `…_TOOLS_CI` and
            // `…_TOOLS__CI` both name `ci`, and which surface won would be a `HashMap` ordering
            // detail. Unlike a token this is not a boundary, so nothing leaks — but an operator
            // reading two specs in their own shell and getting one of them silently is the shape
            // this module refuses everywhere.
            if let Some(other) = specs.get(&name) {
                bail!(
                    "`{key}` and {} both name the tool surface of the client `{name}`. Give it \
                     one: which of the two took effect would be whichever the scan happened to \
                     read last.",
                    other.from
                );
            }
            specs.insert(
                name,
                Spec {
                    text: value,
                    from: format!("`{key}`"),
                },
            );
            continue;
        }
        let token = value;
        let name = match credential_suffix(&key) {
            // `WINDBG_MCP_LISTEN_TOKEN` names `local` — the unnamed variable every existing setup
            // uses — and `WINDBG_MCP_LISTEN_TOKEN_CI` names `ci`, the same lowercasing a kernel
            // profile's variable gets.
            Some(suffix) => client_named_by(suffix),
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
            tools: None,
        });
    }
    for entry in &mut configured {
        entry.tools = specs.remove(&entry.name);
    }
    // **What is left over is a surface for a client nothing can authenticate as**, which is a
    // setting that would never take effect. Refused rather than ignored, on the precedent of the
    // two collisions above: a spec the operator wrote, silently not configured, is the failure
    // nobody sees — and the likeliest cause of it is the typo that makes `WINDBG_MCP_TOOLS_BENCH`
    // and `WINDBG_MCP_LISTEN_TOKEN_BENCH` disagree about the name.
    // Sorted, so two orphans do not produce a refusal that names a different one on every run —
    // the same reason `Toolset::parse` validates a whole spec before returning on `all`. A message
    // nobody can reproduce is worse than the one it replaced.
    if let Some((name, spec)) = specs.into_iter().min_by(|a, b| a.0.cmp(&b.0)) {
        bail!(
            "{} is the tool surface of a client called `{name}`, and nothing here configures a \
             token for it (`{}`). A surface no credential can reach is a setting that would never \
             take effect.",
            spec.from,
            match name.as_str() {
                // The unnamed variable is what configures `local`, and naming `…_TOKEN_LOCAL`
                // instead would be advice to write the one variable that collides with it.
                Client::LOCAL => TOKEN_ENV.to_string(),
                named => format!("{TOKEN_ENV}_{}", named.to_ascii_uppercase()),
            }
        );
    }
    Ok(configured)
}

/// The client a credential variable's suffix names: `local` for the unnamed one, the folded suffix
/// otherwise.
///
/// One function because [`TOKEN_ENV`] and [`TOOLS_ENV`] have to agree about it exactly — a client
/// whose token variable named `ci` and whose spec variable named `_ci` would be two clients, one
/// of which has no token, and the refusal for that is at the bottom of [`from_env`] rather than
/// anywhere an operator would look.
fn client_named_by(suffix: &str) -> String {
    match suffix {
        "" => Client::LOCAL.to_string(),
        suffix => suffix.trim_start_matches('_').to_ascii_lowercase(),
    }
}

/// What this process's environment configures, one [`ClientEntry`] per client.
///
/// For [`crate::service::install`], which copies the installing shell's credentials into the file
/// the service reads. It validates by building the same [`Credentials`] the listener would, so an
/// install cannot write a file the service then refuses to start on — which is the worst shape
/// this can take, since the SCM registers a service once and it fails at every start afterwards.
///
/// **Surfaces travel with the tokens**, because the file is the whole of what a service reads: a
/// `WINDBG_MCP_TOOLS_CI` left behind in the installing shell would otherwise be a surface that
/// worked in the foreground and vanished the moment the same setup was installed.
pub fn env_credentials(vars: impl Iterator<Item = (String, String)>) -> Result<Vec<ClientEntry>> {
    let configured = from_env(vars)?;
    Credentials::build(&configured)?;
    Ok(configured.into_iter().map(Configured::entry).collect())
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
///
/// **Which is a change of meaning for one pre-existing file**, and review was right to name it: an
/// install predating this wrote whatever the shell held, so a token that begins with `{` — a
/// braced GUID is the plausible way to get one — stops the service at its next start rather than
/// authenticating. That refusal says how to fix it (put the token in a one-entry object), and the
/// changelog carries the same note, because the alternative is worse. Falling back to the bare
/// reading when the JSON does not parse would rescue that file at the cost of the failure this
/// shape exists to prevent: a hand-written object with a typo in it, read as one long token that
/// authenticates nobody and says nothing. A loud refusal on the rare file beats a silent one on
/// the file people will actually hand-edit. No marker helps here either — whatever marks the
/// object, a token could carry it — and only a signal outside the file could be unambiguous, which
/// is a heavier format than a credential file wants.
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
                    // A bare token cannot carry one, which is not a gap: it is the file of a
                    // single-client host, where the run's `--tools` and the client's surface are
                    // the same choice. Setting one rewrites the file into the object shape.
                    tools: None,
                    from: path.display().to_string(),
                }],
            });
        }
        let Entries(object) = serde_json::from_str(text).map_err(|e| {
            anyhow!(
                "{} begins with `{{`, so it is read as a JSON object of client name to token — and \
                 it is not valid JSON ({e}). If this file holds a single bearer token that happens \
                 to begin with `{{` — one written before this file could name clients — write it \
                 as `{{\"local\": \"<that token>\"}}` and it will authenticate exactly as it did.",
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
            let (token, tools) = Self::entry_of(&name, value, path)?;
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
                tools: tools.map(|text| Spec {
                    text,
                    from: format!("`{name}`'s `tools` in {}", path.display()),
                }),
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

    /// One client's entry: the bearer token, and the tool surface if it names one.
    ///
    /// **Two shapes here as well**, and for the same reason the file itself has two: a string is
    /// the token and is what every entry written before this is, so a file nobody has touched
    /// keeps meaning what it meant. An object is the entry that has something to say beyond the
    /// token — today `tools`, which is the only reason it exists.
    ///
    /// **No refusal here quotes a value either.** The unknown-field one is the case worth naming:
    /// a file written back to front puts a credential where a key goes, at every level, so the
    /// message lists the two fields an entry may have rather than the one it found. An operator
    /// can read their own file; a startup log going to a service's log file is not the place to
    /// find out what is in it.
    fn entry_of(
        name: &str,
        value: serde_json::Value,
        path: &Path,
    ) -> Result<(String, Option<String>)> {
        match value {
            serde_json::Value::String(token) => Ok((token, None)),
            serde_json::Value::Object(fields) => {
                let mut token = None;
                let mut tools = None;
                for (field, value) in fields {
                    let slot = match field.trim().to_ascii_lowercase().as_str() {
                        "token" => &mut token,
                        "tools" => &mut tools,
                        _ => bail!(
                            "`{name}` in {} is an object with a field this does not know. An \
                             entry names `token`, and optionally `tools` — the surface that \
                             client is served, in the spelling `--tools` takes. The field is not \
                             quoted here: a file written back to front makes a credential one.",
                            path.display()
                        ),
                    };
                    let Some(text) = value.as_str() else {
                        bail!(
                            "`{name}`'s `{field}` in {} must be a string.",
                            path.display()
                        );
                    };
                    *slot = Some(text.trim().to_string());
                }
                let Some(token) = token else {
                    bail!(
                        "`{name}` in {} is an object, so it needs a `token` field holding the \
                         bearer token that client presents — `{{\"token\": \"<token>\", \
                         \"tools\": \"session,crash\"}}`.",
                        path.display()
                    );
                };
                Ok((token, tools.filter(|spec| !spec.is_empty())))
            }
            _ => bail!(
                "`{name}` in {} must be the bearer token that client presents, or an object \
                 naming it — `{{\"token\": \"<token>\", \"tools\": \"session,crash\"}}`.",
                path.display()
            ),
        }
    }

    /// The clients this file names, validated the way the listener validates them.
    ///
    /// For the [client commands](crate::service), which read the file to change one entry and
    /// write the rest back. It validates rather than merely handing over what parsed, for the
    /// same reason [`env_credentials`] does: what comes out of here is written straight back to
    /// the file the service reads, and a set that would not start a listener must not be written
    /// down as if it would.
    ///
    /// **Sorted by name**, so the file a command writes does not depend on the order the previous
    /// one happened to be in — an operator diffing two of these should see only what changed.
    pub fn credentials(self) -> Result<Vec<ClientEntry>> {
        Credentials::build(&self.entries)?;
        let mut entries: Vec<ClientEntry> =
            self.entries.into_iter().map(Configured::entry).collect();
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(entries)
    }
}

/// How many random bytes a generated token carries.
///
/// 256 bits, hex-encoded to 64 characters. Hex rather than base64 because the only thing this
/// string has to survive is an `Authorization` header and a JSON string, and the encoding that is
/// obviously safe in both without a moment's thought is the one to pick for a credential.
const TOKEN_BYTES: usize = 32;

/// A token nobody has typed, from the system's own generator.
///
/// **The point of generating rather than accepting one** is where the secret is *not*: a token the
/// operator supplies has been through a shell (and its history), and on this host frequently
/// through an agent's transcript as well. One made here reaches the token file directly, and what
/// the command prints is a [fingerprint](fingerprint).
///
/// `BCryptGenRandom` with the system-preferred RNG, which is Windows' answer for exactly this and
/// needs no algorithm handle to be opened or closed. A failure is returned rather than fallen back
/// from: the fallback for a credential's randomness is a credential that is not random.
pub fn generate_token() -> Result<String> {
    use windows_sys::Win32::Security::Cryptography::{
        BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
    };

    let mut bytes = [0u8; TOKEN_BYTES];
    // SAFETY: a null algorithm handle is what `BCRYPT_USE_SYSTEM_PREFERRED_RNG` requires, and the
    // buffer and its length describe the same local array.
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status < 0 {
        bail!("the system random number generator refused (NTSTATUS {status:#010x})");
    }
    Ok(hex(&bytes, false))
}

/// What may be said about a token out loud: `sha256:` and the first eight bytes of its digest.
///
/// A credential-shaped value that a command can print, a log line can carry and an operator can
/// compare against what they installed on the client — without any of those becoming somewhere a
/// working token is written down. Truncated because its job is comparison by eye; it is not a
/// security boundary, and nothing here is ever checked against it.
pub fn fingerprint(token: &str) -> String {
    format!("sha256:{}", hex(&sha256(token.as_bytes())[..8], true))
}

/// SHA-256, via CNG's one-shot hash — no handle to open, nothing to free.
///
/// A `panic` on failure rather than a `Result`, which is the one place in this module that is not
/// a refusal: `BCryptHash` against the SHA-256 pseudo-handle with a correctly sized output buffer
/// has no failure that is not a bug here, and threading an error out of it would spread a
/// `Result` through every line that prints a fingerprint.
fn sha256(data: &[u8]) -> [u8; 32] {
    use windows_sys::Win32::Security::Cryptography::{BCRYPT_SHA256_ALG_HANDLE, BCryptHash};

    let mut digest = [0u8; 32];
    // SAFETY: `BCRYPT_SHA256_ALG_HANDLE` is a pseudo-handle the API takes in place of an opened
    // algorithm; the two pointer/length pairs each describe one slice, and no secret is passed.
    let status = unsafe {
        BCryptHash(
            BCRYPT_SHA256_ALG_HANDLE,
            std::ptr::null(),
            0,
            data.as_ptr(),
            data.len() as u32,
            digest.as_mut_ptr(),
            digest.len() as u32,
        )
    };
    assert!(status >= 0, "BCryptHash(SHA-256) failed: {status:#010x}");
    digest
}

/// Bytes as hex — lower case for a token, upper for a fingerprint, which is the difference between
/// a thing to paste and a thing to compare by eye.
fn hex(bytes: &[u8], upper: bool) -> String {
    bytes
        .iter()
        .map(|b| {
            if upper {
                format!("{b:02X}")
            } else {
                format!("{b:02x}")
            }
        })
        .collect()
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

/// A client name an operator typed, normalised and held to the same rule as a configured one.
///
/// For the [client commands](crate::service::edit_client), which take a name on a command line and
/// write it into the token file. Lowercased, because that is what both configured sources do — a
/// `WINDBG_MCP_LISTEN_TOKEN_CI` names `ci`, and a key in the file is folded on the way in — so
/// `--add-listen-client CI` has to mean the same client `CI` would have named, or the command
/// could add a second entry the listener then refuses to start on.
pub fn client_name(raw: &str) -> Result<String> {
    let name = raw.trim().to_ascii_lowercase();
    if !is_client_name(&name) {
        bail!(
            "`{raw}` is not a client name. A name is letters, digits, `-`, `_` or `.`, up to \
             {NAME_LIMIT} characters — it is what the listener logs as who may connect, and what \
             a refusal names."
        );
    }
    Ok(name)
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

/// The part of a tool-surface variable's name after the prefix, if it is one.
///
/// Case-insensitive for the same reason [`credential_suffix`] is. The two prefixes cannot overlap
/// — `WINDBG_MCP_TOOLS` is not a prefix of `WINDBG_MCP_LISTEN_TOKEN` nor the other way round — so
/// a variable is one kind or the other and never both.
fn tools_suffix(name: &str) -> Option<&str> {
    name.to_ascii_uppercase()
        .starts_with(TOOLS_ENV)
        .then(|| &name[TOOLS_ENV.len()..])
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
///
/// **[`TOOLS_ENV`] is deliberately not stripped**, and sits right beside these, so it is worth
/// saying rather than leaving to be tidied up: it holds a list of this server's own group names,
/// not a credential. What it would leak is that a client called `bench` exists, which a debuggee
/// learns from nothing it can act on.
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
        assert_eq!(creds.client_for("s3cret"), Some("local"));
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
        assert_eq!(creds.client_for("ci-token"), Some("ci"));
        assert_eq!(creds.client_for("laptop-token"), Some("laptop"));
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
        assert_eq!(creds.client_for("unnamed"), Some("local"));
        assert_eq!(creds.client_for("for-ci"), Some("ci"));
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
        assert_eq!(creds.client_for("from-the-file"), Some("local"));
        assert_eq!(creds.len(), 1, "the environment must not add credentials");
        assert_eq!(creds.client_for("from-the-environment"), None);
        assert_eq!(creds.client_for("also-from-the-environment"), None);
    }

    /// The one file whose meaning this changed, and the way out, which the refusal has to carry:
    /// a token written before the file could name clients that happens to begin with `{`. It is
    /// read as the JSON shape now, so the listener refuses to start — and the same token in a
    /// one-entry object authenticates exactly as it did.
    ///
    /// Not softened to "fall back to the bare reading when the JSON does not parse": that would
    /// rescue this file at the cost of turning a hand-written object with a typo in it into one
    /// long token that authenticates nobody and says nothing.
    #[test]
    fn a_legacy_token_beginning_with_a_brace_is_refused_and_told_how_to_survive() {
        let legacy = "{6F9619FF-8B86-D011-B42D-00CF4FC964FF}";
        let why = TokenFile::parse(legacy, Path::new(FILE))
            .expect_err("a file beginning with `{` is the JSON shape")
            .to_string();
        assert!(why.contains(FILE), "{why}");
        assert!(
            why.contains(r#"`{"local": "<that token>"}`"#),
            "the refusal has to carry the way out, since it is all the operator sees: {why}"
        );
        let creds = Credentials::from_entries(
            vars(&[]),
            Some(file(&format!(r#"{{"local": "{legacy}"}}"#))),
        )
        .expect("the same token, in the shape this file now takes");
        assert_eq!(creds.client_for(legacy), Some("local"));
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
        assert_eq!(creds.client_for("for-ci"), Some("ci"));
        assert_eq!(creds.client_for("for-laptop"), Some("laptop"));
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
            assert_eq!(creds.client_for("plain-token"), Some(whose), "{text:?}");
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
            (r#"{"ci": 5}"#, "or an object naming it"),
            (r#"{"ci": "  "}"#, "has no token"),
            // The object shape's own three. A `tools` with no `token` beside it is the shape an
            // operator reaches for when adding a surface to an entry and deleting the wrong line.
            (r#"{"ci": {"tools": "crash"}}"#, "needs a `token` field"),
            (r#"{"ci": {"token": 5}}"#, "must be a string"),
            (
                r#"{"ci": {"token": "t", "surface": "crash"}}"#,
                "a field this does not know",
            ),
            // And a spec that names nothing this server has, which is the same refusal `--tools`
            // gives — named after the entry it is in rather than after a flag nobody typed.
            (
                r#"{"ci": {"token": "t", "tools": "crash,ttdd"}}"#,
                "`ttdd` is neither a group nor a tool",
            ),
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
            assert!(
                !why.contains("\"t\"") && !why.contains("`t`"),
                "a refusal quotes a value out of the file: {why}"
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
        assert_eq!(creds.client_for("from-the-file"), Some("local"));
        assert_eq!(creds.client_for(r"C:\somewhere\token"), None);
    }

    /// A generated token is one a client could actually present, and is not the same twice.
    ///
    /// The first half is the check every configured credential is held to, asked of the one source
    /// nobody proof-reads: a token this server minted and wrote into its own file must not be one
    /// [`Credentials::build`] would then refuse at startup. The second is a sanity check on the
    /// generator being wired to the system RNG rather than to a constant.
    #[test]
    fn a_generated_token_is_one_that_could_be_presented() {
        let first = generate_token().expect("the system RNG answers");
        let second = generate_token().expect("the system RNG answers");
        assert_ne!(first, second, "two tokens in a row were identical");
        assert!(
            is_presentable(&first),
            "`{first}` cannot travel in a header"
        );
        let creds = Credentials::from_entries(vars(&[(TOKEN_ENV, &first)]), None).expect("valid");
        assert_eq!(creds.client_for(&first), Some("local"));
    }

    /// A fingerprint is stable, distinguishing, and says nothing about the token it describes.
    ///
    /// The last clause is the one with a cost attached: this string is printed to a console and
    /// written into log lines precisely so a *token* never has to be, so a fingerprint that
    /// carried any of one would defeat the whole arrangement.
    #[test]
    fn a_fingerprint_identifies_a_token_without_carrying_it() {
        let token = "a-long-random-string";
        let print = fingerprint(token);
        assert_eq!(
            print,
            fingerprint(token),
            "the same token printed differently"
        );
        assert_ne!(print, fingerprint("a-long-random-strinh"));
        assert!(print.starts_with("sha256:"), "{print}");
        assert!(
            !print.contains(token) && !print.contains("random"),
            "the fingerprint quotes the token it is standing in for: {print}"
        );
    }

    /// The known-answer test for the digest behind it, since nothing else here would catch a
    /// fingerprint that was consistently and wrongly computed.
    #[test]
    fn the_digest_is_sha256() {
        assert_eq!(
            hex(&sha256(b"abc"), false),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    /// A name typed on a command line means the same client a configured one would.
    ///
    /// Both configured sources fold case — `WINDBG_MCP_LISTEN_TOKEN_CI` names `ci`, and a key in
    /// the token file is lowercased on the way in — so a command that did not would happily add a
    /// second entry for a client that already exists, and the listener would then refuse to start
    /// on the two-tokens-one-name rule.
    #[test]
    fn a_typed_client_name_is_folded_like_a_configured_one() {
        assert_eq!(client_name("  CI  ").expect("a name"), "ci");
        assert_eq!(client_name("bench.1").expect("a name"), "bench.1");
        for not_a_name in [
            "",
            "   ",
            "two words",
            "a\"quote",
            &"x".repeat(NAME_LIMIT + 1),
        ] {
            assert!(
                client_name(not_a_name).is_err(),
                "`{not_a_name}` was accepted as a client name"
            );
        }
    }

    /// A token file's credentials come back validated and in a stable order.
    ///
    /// The order matters because a client command writes them straight back: without it, adding
    /// one client would reshuffle the file, and an operator diffing two of them could not see what
    /// changed.
    #[test]
    fn a_files_credentials_come_back_sorted() {
        let parsed = file(r#"{"laptop": "l", "ci": "c", "local": "s"}"#)
            .credentials()
            .expect("a valid file");
        assert_eq!(
            rows(&parsed),
            vec![
                ("ci", "c", None),
                ("laptop", "l", None),
                ("local", "s", None)
            ]
        );
    }

    /// The surface a set of variables configures for one client, as its summary.
    fn surface(vars_of: &[(&str, &str)], client: &str) -> Option<String> {
        Credentials::from_entries(vars(vars_of), None)
            .expect("a usable configuration")
            .surface_for(client)
            .map(crate::toolset::Toolset::summary)
    }

    /// A client's surface is configured beside its token, and a client that names none is served
    /// whatever the run serves.
    ///
    /// **`None` rather than every tool** is the half worth asserting: a listener started with
    /// `--tools crash` and one client given `inspect` serves that client `inspect` and everybody
    /// else `crash`, which only works if "no surface configured" stays distinguishable from "all
    /// fifty-one".
    #[test]
    fn a_client_may_be_configured_with_a_surface_of_its_own() {
        let configured = &[
            ("WINDBG_MCP_LISTEN_TOKEN", "for-local"),
            ("WINDBG_MCP_LISTEN_TOKEN_BENCH", "for-bench"),
            ("WINDBG_MCP_TOOLS_BENCH", "crash"),
        ][..];
        assert_eq!(
            surface(configured, "bench").as_deref(),
            Some("11 of 51 tools (session, crash)"),
            "`bench` is served the surface its own variable names"
        );
        assert_eq!(
            surface(configured, "local"),
            None,
            "a client with no spec takes the run's surface rather than every tool"
        );
        // And the unnamed variable names `local`'s, exactly as the unnamed token names `local`.
        assert_eq!(
            surface(
                &[
                    ("WINDBG_MCP_LISTEN_TOKEN", "for-local"),
                    ("WINDBG_MCP_TOOLS", "inspect"),
                ],
                "local"
            )
            .as_deref(),
            Some("19 of 51 tools (session, inspect)")
        );
    }

    /// Every way a tool-surface variable can be configured wrong, refused at startup.
    ///
    /// The orphan is the one this is really for. A surface for a client no credential names is a
    /// setting that would never take effect, and the likeliest way to write one is the typo that
    /// makes the two variables disagree about the name — so it is refused on the precedent of the
    /// two collisions [`Credentials::build`] already refuses, rather than ignored.
    #[test]
    fn a_surface_that_would_never_take_effect_is_refused() {
        for (configured, expected) in [
            (
                &[
                    ("WINDBG_MCP_LISTEN_TOKEN_CI", "for-ci"),
                    ("WINDBG_MCP_TOOLS_BENCH", "crash"),
                ][..],
                "nothing here configures a token for it",
            ),
            // Two spellings of one name, which fold together — the same collision two tokens for
            // one client are, decided by whichever the scan read last.
            (
                &[
                    ("WINDBG_MCP_LISTEN_TOKEN_CI", "for-ci"),
                    ("WINDBG_MCP_TOOLS_CI", "crash"),
                    ("WINDBG_MCP_TOOLS__CI", "inspect"),
                ][..],
                "both name the tool surface of the client `ci`",
            ),
            // A spec naming something this server does not have, refused where a `--tools` spec
            // is — and named after the variable, not after a flag nobody typed.
            (
                &[
                    ("WINDBG_MCP_LISTEN_TOKEN_CI", "for-ci"),
                    ("WINDBG_MCP_TOOLS_CI", "crash,ttdd"),
                ][..],
                "`ttdd` is neither a group nor a tool",
            ),
            (
                &[
                    ("WINDBG_MCP_LISTEN_TOKEN_CI", "for-ci"),
                    ("WINDBG_MCP_TOOLS_two words", "crash"),
                ][..],
                "does not name a client",
            ),
        ] {
            let why = Credentials::from_entries(vars(configured), None)
                .expect_err(&format!("{configured:?} is not a usable configuration"))
                .to_string();
            assert!(
                why.contains(expected),
                "{configured:?} was refused with: {why}"
            );
            for (_, value) in configured {
                assert!(
                    !value.starts_with("for-") || !why.contains(value),
                    "a refusal quotes a token: {why}"
                );
            }
        }
    }

    /// A configured file is the whole configuration — surfaces included.
    ///
    /// The precedence is [`Credentials::from_entries`]'s and predates this, but a surface is the
    /// first thing to be configured beside a token that is *not* a secret, so it is the first
    /// thing anyone would be tempted to let the environment contribute. It does not: one file
    /// answers who may connect and what they are served, rather than two sources and a rule.
    #[test]
    fn a_token_file_shuts_out_the_environments_surfaces_too() {
        let creds = Credentials::from_entries(
            vars(&[
                ("WINDBG_MCP_LISTEN_TOKEN_CI", "ignored"),
                ("WINDBG_MCP_TOOLS_CI", "inspect"),
            ]),
            Some(file(
                r#"{"ci": {"token": "from-the-file", "tools": "crash"}}"#,
            )),
        )
        .expect("a usable configuration");
        assert_eq!(creds.client_for("ignored"), None);
        assert_eq!(creds.client_for("from-the-file"), Some("ci"));
        assert_eq!(
            creds
                .surface_for("ci")
                .map(crate::toolset::Toolset::summary),
            Some("11 of 51 tools (session, crash)".to_string()),
            "the file's surface stands, not the variable's"
        );
    }

    /// A file entry may still be a bare token, which is every entry written before there was
    /// anything else to say — and it means the client takes the run's surface.
    #[test]
    fn a_file_entry_without_a_surface_is_the_entry_it_always_was() {
        let creds = Credentials::from_entries(
            vars(&[]),
            Some(file(
                r#"{"ci": "for-ci", "bench": {"token": "for-bench", "tools": "session"}}"#,
            )),
        )
        .expect("a usable configuration");
        assert_eq!(creds.client_for("for-ci"), Some("ci"));
        assert_eq!(creds.surface_for("ci"), None);
        assert_eq!(
            creds.surfaces(),
            vec![("bench", "10 of 51 tools (session)".to_string())],
            "only the client that named one is listed"
        );
    }

    /// [`ClientEntry`] as something a test can compare and print.
    ///
    /// It has no `Debug` on purpose — it holds a token, and a panic message is exactly the kind of
    /// place one should not appear. These assertions are about a triple, and a test that writes
    /// its own literal tokens is the one place quoting them costs nothing.
    fn rows(entries: &[ClientEntry]) -> Vec<(&str, &str, Option<&str>)> {
        entries
            .iter()
            .map(|e| (e.name.as_str(), e.token.as_str(), e.tools.as_deref()))
            .collect()
    }

    /// A set that would not start a listener is refused on the way out, not just on the way in.
    ///
    /// [`TokenFile::parse`] catches what one *file* can say twice; this is the other refusal —
    /// two names sharing a token — which is [`Credentials::build`]'s and would otherwise be
    /// discovered by the service failing to start after a command reported success.
    #[test]
    fn a_files_credentials_are_held_to_the_startup_rules() {
        let shared = file(r#"{"ci": "same", "laptop": "same"}"#).credentials();
        assert!(
            shared.is_err(),
            "one token naming two clients came back as a usable set"
        );
    }

    /// Swapping the set in says which clients appeared and which went, and takes effect at once.
    #[test]
    fn replacing_the_set_reports_what_moved() {
        let accepted = Accepted::new(
            Credentials::from_entries(
                vars(&[
                    ("WINDBG_MCP_LISTEN_TOKEN", "s"),
                    ("WINDBG_MCP_LISTEN_TOKEN_CI", "c"),
                ]),
                None,
            )
            .expect("valid"),
        );
        assert_eq!(
            accepted.client_for("c").map(|c| c.name().to_string()),
            Some("ci".into())
        );

        let change = accepted.replace(
            Credentials::from_entries(
                vars(&[
                    ("WINDBG_MCP_LISTEN_TOKEN", "s"),
                    ("WINDBG_MCP_LISTEN_TOKEN_BENCH", "b"),
                ]),
                None,
            )
            .expect("valid"),
        );
        assert_eq!(crate::client::Change::names(&change.added), "bench");
        assert_eq!(crate::client::Change::names(&change.removed), "ci");
        assert_eq!(accepted.names(), vec!["bench", "local"]);
        assert_eq!(
            accepted.client_for("c"),
            None,
            "a removed client's token still authenticated"
        );
        assert_eq!(
            accepted.client_for("b").map(|c| c.name().to_string()),
            Some("bench".into())
        );
    }

    /// **The distinction the whole of #190 exists to make**: a rotation is the same client, a
    /// removal-and-re-add is not.
    ///
    /// Both leave a set holding a client called `ci`, and until identity was a pair nothing could
    /// tell them apart — so a name given back reached the debug sessions, MCP session ids and lease
    /// of the credential it replaced. Which is precisely what `--rotate-listen-client` is *for*, and
    /// precisely what `--remove-listen-client` must not do.
    ///
    /// Asserted on identity rather than on any downstream effect, because identity is what every
    /// downstream structure keys on: session ownership, routing, the lease map, the four-session
    /// cap. Get this right and they are all right; get it wrong and they are all wrong in the same
    /// way, which is how one ambiguity produced four separate findings.
    #[test]
    fn a_rotation_is_the_same_client_and_a_name_given_back_is_not() {
        let set = |token: &str| {
            Credentials::from_entries(vars(&[("WINDBG_MCP_LISTEN_TOKEN_CI", token)]), None)
                .expect("valid")
        };
        let accepted = Accepted::new(set("first"));
        let original = accepted.client_for("first").expect("configured");

        // A rotation: the name never leaves the set, so the client never changes.
        let rotated = accepted.replace(set("second"));
        assert!(
            rotated.is_empty(),
            "a rotation reported a client coming or going: {rotated:?}"
        );
        assert_eq!(
            accepted.client_for("second"),
            Some(original.clone()),
            "a rotation minted a new identity, which would strand the sessions it must keep"
        );
        assert_eq!(
            accepted.client_for("first"),
            None,
            "the old token still worked"
        );

        // A removal and an add. Same name, and that is all they share.
        let removal = accepted.replace(
            Credentials::from_entries(vars(&[("WINDBG_MCP_LISTEN_TOKEN_OTHER", "o")]), None)
                .expect("valid"),
        );
        assert_eq!(removal.removed, vec![original.clone()]);
        accepted.replace(set("third"));
        let given_back = accepted.client_for("third").expect("configured again");

        assert_eq!(
            given_back.name(),
            original.name(),
            "the operator configured a client called `ci`, and that is what it must be called"
        );
        assert_ne!(
            given_back, original,
            "a name given back is the same client as the one it replaced, so it reaches its \
             sessions — which is the isolation this boundary exists to provide"
        );
    }

    /// A rotation moves a token and no names — which is what lets the client keep its sessions.
    ///
    /// The reload acts on [`Change`] to release a departed client's targets, so a rotation
    /// reporting a removal and an addition of the same name would tear down exactly the sessions
    /// rotation exists to preserve.
    #[test]
    fn rotating_a_token_moves_no_names() {
        let accepted = Accepted::new(
            Credentials::from_entries(vars(&[("WINDBG_MCP_LISTEN_TOKEN_CI", "old")]), None)
                .expect("valid"),
        );
        let change = accepted.replace(
            Credentials::from_entries(vars(&[("WINDBG_MCP_LISTEN_TOKEN_CI", "new")]), None)
                .expect("valid"),
        );
        assert!(
            change.is_empty(),
            "a rotation was reported as a client coming or going: {change:?}"
        );
        assert_eq!(
            accepted.client_for("old"),
            None,
            "the old token still worked"
        );
        assert_eq!(
            accepted.client_for("new").map(|c| c.name().to_string()),
            Some("ci".into())
        );
    }
}
