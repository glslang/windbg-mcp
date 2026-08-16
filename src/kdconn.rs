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

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

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
pub(crate) const MASK: &str = "<redacted>";

/// Whether `name` names a value that must never be rendered.
///
/// The one test, shared by everything that hides a secret: the connection parser
/// ([`Param::is_secret`]), the text scan ([`secret_at`]), and the transcript's walk over a tool's
/// argument object ([`crate::record`]). A fourth place with its own list is a fourth place to
/// forget an entry.
pub(crate) fn is_secret_name(name: &str) -> bool {
    SECRET_PARAMS
        .iter()
        .any(|p| p.eq_ignore_ascii_case(name.trim()))
}

/// What a connection whose structure cannot be trusted is reported as, in full. See [`redact`].
const OPAQUE: &str = "<connection redacted>";

/// How long a profile name may be. Generous for a name, short enough that nothing anyone would
/// mistake for a connection string or a pasted secret gets in under it.
const NAME_LIMIT: usize = 64;

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
    /// Wraps a raw connection string, and **remembers its secrets** so they can be masked by value
    /// wherever they later turn up — see [`KNOWN_SECRETS`].
    ///
    /// Here because this is the one door: a profile resolved on this host and a raw `connection`
    /// argument both become a `Connection`, and nothing dials without one. Registering at the
    /// parse rather than at each caller is the same reasoning as `is_secret_name` having one
    /// definition — a second place to remember is a place to forget.
    pub fn new(raw: impl Into<String>) -> Self {
        let raw = raw.into();
        remember_secrets(&raw);
        Self(raw)
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

/// Whether a rendering of a connection string may include its secrets.
///
/// `Keep` exists **only under `cfg(test)`**, and that is the point rather than an accident: the
/// unredacted render is how "the parse lost nothing" is checked, and a build that could produce
/// one would be a build with a second way to print a key. There is no such build.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Secrets {
    #[cfg(test)]
    Keep,
    Mask,
}

/// A connection string, split into the parts DbgEng's syntax actually has: a transport prefix
/// (`net:`) and a list of comma- or semicolon-separated parameters, each `name=value` or a bare
/// flag.
///
/// **This exists so that redaction is a property of the structure rather than of a scanner.** The
/// previous implementation walked the raw string deciding, at each `=`, where a name began and a
/// value ended — and every delimiter it did not anticipate was a way to make a secret parameter
/// unrecognisable (`,\r\nkey=…` parsed as a parameter named `"\r\nkey"`) or a value invisible
/// (`key= …` measured as empty, and the remainder then emitted whole). Four such holes were found
/// in review, each individually small, and the reason there were four is that the scanner had no
/// invariant to violate.
///
/// The parse has one, and it is what the fix rests on: **it is total.** Every byte of the input
/// lands in exactly one field — prefix, name, value, or separator — so rendering with
/// [`Secrets::Keep`] reproduces the input exactly, which the tests assert over a generated corpus
/// as well as the awkward cases. Given that, redaction is no longer a hunt: a value is emitted
/// only from a `value` field, and a `value` field belonging to a secret parameter is never emitted
/// at all. Decoration around a parameter — a repeated separator, an empty item, an `=` inside a
/// value — changes which *field* text lands in, and cannot change which parameter owns it, because
/// the only boundaries are the two structural ones DbgEng itself uses: the separators between
/// items, and the first `=` within one.
///
/// **Whitespace is the exception, and it is handled before the parse rather than by it.** It has
/// two readings — separator and filler — that this has now been wrong about in both directions, so
/// a connection carrying any is refused by [`is_dialable`] and reported by [`redact`] as [`OPAQUE`]
/// rather than parsed under a guess.
struct Parsed<'a> {
    /// The transport, `net:` included, or empty. Never a parameter, so never a secret.
    prefix: &'a str,
    params: Vec<Param<'a>>,
}

/// One item of a connection string.
struct Param<'a> {
    /// The name as written. Compared trimmed — a no-op given that a dialable connection carries no
    /// whitespace, and kept so that a future caller reaching [`redact`] by another route does not
    /// silently lose the comparison.
    name: &'a str,
    /// Everything after the first `=`. `None` for a bare flag (`com:port=com1,pipe`), which has no
    /// value to hide.
    value: Option<&'a str>,
    /// The separator that ended this item, or `None` for the last one. Kept so the render is a
    /// faithful reproduction rather than a re-formatting.
    end: Option<char>,
}

impl<'a> Param<'a> {
    fn of(item: &'a str, end: Option<char>) -> Self {
        match item.split_once('=') {
            Some((name, value)) => Self {
                name,
                value: Some(value),
                end,
            },
            None => Self {
                name: item,
                value: None,
                end,
            },
        }
    }

    fn is_secret(&self) -> bool {
        is_secret_name(self.name)
    }

    /// This parameter's value if it is a secret one, for [`remember_secrets`]. Blank values are
    /// not secrets — the same rule [`Self::render`] applies when it decides whether to mask.
    fn secret_value(&self) -> Option<&'a str> {
        self.value
            .filter(|v| self.is_secret() && !v.trim().is_empty())
    }

    fn render(&self, secrets: Secrets, out: &mut String) {
        out.push_str(self.name);
        if let Some(value) = self.value {
            out.push('=');
            // A value that is blank has nothing to hide, and masking it would invent a secret
            // that is not there — the honest rendering of `key=` is `key=`.
            let hide = secrets == Secrets::Mask && self.is_secret() && !value.trim().is_empty();
            out.push_str(if hide { MASK } else { value });
        }
        if let Some(end) = self.end {
            out.push(end);
        }
    }
}

impl<'a> Parsed<'a> {
    fn of(connection: &'a str) -> Self {
        let (prefix, rest) = split_transport(connection);
        let mut params = Vec::new();
        let mut start = 0;
        for (at, c) in rest.char_indices() {
            if matches!(c, ',' | ';') {
                params.push(Param::of(&rest[start..at], Some(c)));
                start = at + c.len_utf8();
            }
        }
        // Always one final item, empty if the string ended on a separator — which is what keeps
        // the render faithful for `net:port=1,`.
        params.push(Param::of(&rest[start..], None));
        Self { prefix, params }
    }

    fn render(&self, secrets: Secrets) -> String {
        let mut out = String::with_capacity(self.prefix.len() + 32);
        out.push_str(self.prefix);
        for param in &self.params {
            param.render(secrets, &mut out);
        }
        out
    }
}

/// Splits the transport prefix from the parameter list.
///
/// The `:` counts only *before* the first `=`. After one it is inside a value — `key=a:b` is a
/// parameter, not a transport called `key=a` — and treating it as a separator would put half a
/// value in the prefix, where nothing is ever masked.
fn split_transport(connection: &str) -> (&str, &str) {
    let before_first_value = connection.find('=').unwrap_or(connection.len());
    match connection[..before_first_value].rfind(':') {
        Some(at) => connection.split_at(at + 1),
        None => ("", connection),
    }
}

/// Masks the secret parameters of a connection string, leaving everything else readable.
///
/// `net:port=50000,key=1.2.3.4` → `net:port=50000,key=<redacted>`. The transport and the port are
/// what let a person tell two sessions apart, and neither is a secret, so this masks *values* and
/// never the whole string. See [`Parsed`] for why it goes through a parse rather than a scan.
///
/// **Interior whitespace makes the whole string opaque**, because it has two readings that cannot
/// both be honoured and each one leaks under the other:
///
/// - `net:port=50000 key=1.2.3.4` — a missing comma, where the space *separates* two parameters.
///   Read as filler, the `key=` is swallowed into `port`'s value and never masked.
/// - `net:port=1,key= 1.2.3.4` — a stray space, where it is *filler* before a value. Read as a
///   separator, `key` has an empty value and `1.2.3.4` becomes a bare flag, rendered verbatim.
///
/// Nothing in the string says which was meant. So rather than pick — the choice this has now been
/// wrong about in both directions — a connection carrying any [`is_ambiguous`] character is
/// reported as [`OPAQUE`] and keeps none of its detail. It costs a readable label for a string
/// that [`is_dialable`] refuses anyway, which is the trade worth making: the label exists to tell
/// two targets apart, and there is no version of that worth disclosing a key for.
fn redact(connection: &str) -> String {
    if connection.chars().any(is_ambiguous) {
        return OPAQUE.to_string();
    }
    Parsed::of(connection).render(Secrets::Mask)
}

/// Every secret this server has been handed, so it can be masked by **value** wherever it turns up.
///
/// This is the half of [`scrub`] that is a guarantee rather than a net, and it exists because the
/// other half kept losing. A scan for `key=…` has to anticipate a syntax; review found it missing
/// whitespace around the separator, then a line break after it, then an escaped quote inside the
/// value, then a backslash-escaped member name — four shapes of one string, and no reason to think
/// the list was finished. Knowing the actual value ends that: a key masked because it *is* the key
/// does not care how it was written, escaped, quoted or split across a sentence.
///
/// Populated by [`Connection::new`], which every connection this server dials goes through, from a
/// profile or from a raw argument alike. Bounded by the number of distinct targets a host talks to,
/// which is a handful; nothing is ever removed, because a key stays a secret after its session ends.
static KNOWN_SECRETS: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

/// Shorter than this and a value is not masked by [`KNOWN_SECRETS`].
///
/// A secret short enough to occur by accident would mask the text around it rather than itself: a
/// key of `1` would blank every digit in a transcript. Real ones are far longer — a KDNET key is
/// four dotted numbers — so the floor costs nothing and stops the mechanism from being worse than
/// the leak it prevents.
const MASKABLE_SECRET: usize = 6;

/// Remembers the secret parameter values of `connection`, so [`scrub`] can mask them by value.
fn remember_secrets(connection: &str) {
    let mut known = KNOWN_SECRETS.lock().unwrap_or_else(|e| e.into_inner());
    for param in &Parsed::of(connection).params {
        if let Some(value) = param.secret_value().filter(|v| v.len() >= MASKABLE_SECRET) {
            known.insert(value.to_string());
        }
    }
}

/// Masks every secret in **arbitrary text**, wherever one appears in it.
///
/// [`redact`] is for a string that *is* a connection: it parses one, and hands back [`OPAQUE`] for
/// anything whose structure it cannot trust — which is the right answer there and the wrong one
/// here, where the input is a blob of JSON or a page of debugger output that happens to contain a
/// connection somewhere inside it. Passing that through `redact` would mask the entire blob.
///
/// Two mechanisms, and the order matters because they are not equally strong:
///
/// 1. **By value.** Every secret this server has been given is masked wherever it occurs, in any
///    syntax at all — see [`KNOWN_SECRETS`]. This is the guarantee: a key that reached this process
///    cannot leave it in a transcript, however the text around it is written.
/// 2. **By pattern**, as a net under it: a *whole* parameter name (`pubkey=` is not `key=`, matched
///    the way [`Param::is_secret`] matches), a separator, and a value — bare (`key=1.2.3.4`, as a
///    connection string writes it) or quoted (`"key": "1.2.3.4"`, as a tool call does, escaped or
///    not). This catches a secret this server has never seen, such as one a target printed itself.
///    It is **best-effort**, and deliberately described as such: it has to guess a syntax, and the
///    guesses that have been wrong so far were all found by someone looking, not by it failing
///    loudly. Anything relying on redaction relies on (1).
pub(crate) fn scrub(text: &str) -> String {
    let masked = mask_known_values(text);
    let text: &str = &masked;
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < bytes.len() {
        match secret_at(text, i) {
            Some((value, end)) => {
                out.push_str(&text[i..value]);
                out.push_str(MASK);
                i = end;
            }
            None => {
                // Advance one *character*, not one byte: the index has to stay on a boundary for
                // the slicing above, and this text is arbitrary — a debugger's output carries
                // whatever the target is named.
                let step = text[i..].chars().next().map_or(1, char::len_utf8);
                out.push_str(&text[i..i + step]);
                i += step;
            }
        }
    }
    out
}

/// Replaces every known secret value with [`MASK`], wherever it occurs.
///
/// Borrowed back unchanged in the ordinary case, which is every call on a host that has never
/// dialled a target with a key.
fn mask_known_values(text: &str) -> std::borrow::Cow<'_, str> {
    let known = KNOWN_SECRETS.lock().unwrap_or_else(|e| e.into_inner());
    let present: Vec<&String> = known.iter().filter(|s| text.contains(s.as_str())).collect();
    if present.is_empty() {
        return std::borrow::Cow::Borrowed(text);
    }
    // Longest first, so a secret that contains another is masked whole rather than being cut into
    // a mask and a remainder.
    let mut present = present;
    present.sort_by_key(|s| std::cmp::Reverse(s.len()));
    let mut out = text.to_string();
    for secret in present {
        out = out.replace(secret.as_str(), MASK);
    }
    std::borrow::Cow::Owned(out)
}

/// A secret parameter starting at `i`, as `(where its value starts, where it ends)`.
///
/// Two syntaxes and no others: `key=…`, how a connection string writes it, and `"key":…`, how JSON
/// does. Requiring the quote before a `:` is what keeps this off ordinary prose — a debugger
/// printing `Key: \REGISTRY\MACHINE\…` is not a parameter, and a transcript that masked it would
/// lose a fact to a rule about a different syntax. The bare `key:` form is not a connection string
/// either, so nothing that can carry a real key is given up for that.
///
/// `None` also when the value is empty, which neither this nor [`Parsed::render`] masks: there is
/// nothing there to hide, and a `key=<redacted>` grown out of `key=` would report a secret that
/// was never supplied.
fn secret_at(text: &str, i: usize) -> Option<(usize, usize)> {
    let rest = &text[i..];
    // `get`, not a slice: `i` is a character boundary but `i + name.len()` need not be, and this
    // text is whatever a target chose to call itself.
    let name = SECRET_PARAMS.iter().find(|p| {
        rest.get(..p.len())
            .is_some_and(|s| s.eq_ignore_ascii_case(p))
    })?;
    // Whole-name matching at the front: `pubkey=` is not `key=`. The back is settled by what may
    // follow — a quote or the separator — so `keyring=` cannot match either.
    if text[..i].chars().next_back().is_some_and(name_char) {
        return None;
    }
    let mut at = i + name.len();
    // A quote, optionally backslash-escaped: debugger output and log lines quote JSON inside
    // strings, so the member name's own delimiter arrives as `\"` rather than `"`.
    let escaped_name = text[at..].starts_with("\\\"");
    let quoted_name = escaped_name || text[at..].starts_with('"');
    at += usize::from(quoted_name) + usize::from(escaped_name);
    // Filler on **both** sides of the separator, because a secret arrives in text somebody typed.
    // `net:port=1, key = 1.2.3.4` is refused by [`is_dialable`] — but only after it has already
    // been recorded as an argument, so a scan that required `key=` exactly would mask the key in
    // the connections this server accepts and miss it in the one it turns away.
    at += inline_gap(text, at);
    match (quoted_name, text[at..].chars().next()?) {
        (false, '=') | (true, ':') => at += 1,
        _ => return None,
    }
    at += inline_gap(text, at);
    let escaped_value = text[at..].starts_with("\\\"");
    let quoted = escaped_value || text[at..].starts_with('"');
    let start = at + usize::from(quoted) + usize::from(escaped_value);
    let body = &text[start..];
    let len = match quoted {
        // Up to the closing quote, which is `\"` when the opening one was escaped and a plain
        // unescaped `"` otherwise. Stopping in the wrong place would mask the head of the value
        // and leave its tail in the file — the one way this scan fails that produces a
        // plausible-looking redacted line with the secret still in it.
        true => closing_quote(body, escaped_value),
        false => body
            .find(|c: char| c.is_whitespace() || matches!(c, ',' | ';' | '"' | '}' | ']'))
            .unwrap_or(body.len()),
    };
    (len > 0).then_some((start, start + len))
}

/// Whether a character can be part of a parameter name, for the whole-name test in [`secret_at`].
fn name_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_' || c == '-'
}

/// How far a quoted value runs, to its closing delimiter or to the end of an unterminated one.
///
/// Which delimiter depends on how it was opened, and both spellings occur in text this server
/// records. In JSON, `"hunter\"x"` is one value of `hunter"x`, so the close is the first quote
/// *not* escaped — a scan stopping at the inner one would mask `hunter\` and leave `x` behind. In
/// JSON that has itself been quoted into a string, which is how a log line carries a request it is
/// quoting, every delimiter is written `\"` and the close is that pair.
///
/// Getting this wrong is the failure worth naming: a line that *looks* redacted while still
/// carrying part of the secret is worse than one that plainly does not.
fn closing_quote(body: &str, escaped: bool) -> usize {
    if escaped {
        return body.find("\\\"").unwrap_or(body.len());
    }
    let mut after_backslash = false;
    for (at, c) in body.char_indices() {
        match c {
            _ if after_backslash => after_backslash = false,
            '\\' => after_backslash = true,
            '"' => return at,
            _ => {}
        }
    }
    body.len()
}

/// How many bytes of filler start at `at`: spaces and tabs, and **never a line break**.
///
/// The distinction is what keeps [`secret_at`] from running off the end of a line. `key=` with
/// nothing after it is an empty value — which is not a secret and is left alone — while a scan
/// that treated the newline as filler would decide the first token of the *next* line was the
/// key's value and mask that instead. Debugger output is full of lines that end in `=`.
fn inline_gap(text: &str, at: usize) -> usize {
    text[at..]
        .bytes()
        .take_while(|b| *b == b' ' || *b == b'\t')
        .count()
}

/// A character with no unambiguous place *between* the parameters of a connection string.
///
/// The single rule behind both gates, and they have to agree: [`is_dialable`] decides whether a
/// connection may be dialled at all, [`redact`] whether one may be rendered in detail, and a
/// character that only one of them refuses is a character that reaches the parse from the route
/// the other guards. That gap is not theoretical — `trim` strips whitespace only, so a name of
/// `"\u{0}key"` compares equal to nothing and its value is emitted verbatim, which is the same
/// failure the whitespace refusal exists to prevent.
///
/// - **Whitespace** reads as either a separator or filler, and each leaks under the other (see
///   [`redact`]).
/// - A **control character** belongs to no parameter, and would let a label forge a line in
///   `session_status`'s multi-line report.
///
/// Applied to the *interior* only: callers trim first, so a pasted string with a trailing newline
/// is fine.
fn is_ambiguous(c: char) -> bool {
    c.is_whitespace() || c.is_control()
}

/// Which of the two sources a profile came from. Carried so that a name defined twice can say
/// whether that was the documented environment-over-file override or a collision inside one
/// source, which are opposite things to tell an operator.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Source {
    Env,
    File,
}

impl Source {
    fn label(self) -> &'static str {
        match self {
            Self::Env => "the environment",
            Self::File => "the profile file",
        }
    }
}

/// One configured profile, keyed in [`Profiles`] by its normalized name but remembering the name
/// as it was actually written — that is what an operator will recognise in an error.
struct Profile {
    name: String,
    connection: Connection,
    source: Source,
    /// Other spellings from the same source that normalize to this name and point somewhere
    /// **else**. Non-empty makes this profile unusable, deliberately: the server cannot tell which
    /// target was meant, and the failure mode of guessing is attaching to the wrong kernel while
    /// believing otherwise. A duplicate that agrees is not recorded here — nothing can go wrong.
    conflicts: Vec<String>,
}

/// The kernel connection profiles configured on this host.
///
/// Read afresh for every attach rather than cached at startup, so adding a profile does not mean
/// restarting the server (and, more to the point, does not mean restarting the MCP client).
pub struct Profiles {
    entries: BTreeMap<String, Profile>,
    /// What had to be refused while reading the sources: a file that could not be parsed, an
    /// entry whose name is not a name, a second spelling of a name already taken. Reported when a
    /// lookup fails rather than raised at read time — none of it should break an attach that
    /// passes `connection` and wants no profiles at all, but a misconfiguration must not look
    /// identical to "no such profile" either.
    notes: Vec<String>,
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
        let file = profiles_file();
        let mut profiles = Self {
            entries: BTreeMap::new(),
            notes: Vec::new(),
            file,
        };
        for (name, connection) in env_entries(std::env::vars()) {
            profiles.admit(name, &connection, Source::Env);
        }
        match profiles.file.as_deref().map(read_profile_file) {
            Some(Ok(from_file)) => {
                for (name, connection) in from_file {
                    profiles.admit(name, &connection, Source::File);
                }
            }
            Some(Err(why)) => profiles.notes.push(why),
            None => {}
        }
        profiles
    }

    /// Takes one configured entry, or records why it could not.
    ///
    /// **Both sources go through here**, and the validation is the reason. A name is *displayed* —
    /// in [`Self::listed`], in a session label, in an unknown-profile error — so a name that is
    /// not a name must never reach the map: the likeliest way to get one is an entry written the
    /// wrong way round, which makes the JSON *key* the connection string. A rejection is therefore
    /// counted and located, never quoted.
    fn admit(&mut self, name: String, connection: &str, source: Source) {
        if is_profile_name(&name) && !is_dialable(connection) {
            // Named, because the name passed its own check and so is safe to print — and the
            // operator needs to know *which* entry to go and fix. The value stays unquoted.
            self.notes.push(format!(
                "profile `{name}` in {} was skipped: its connection string contains a space or a \
                 control character between its parameters, which no connection string does — \
                 parameters are separated by commas. A missing comma is the usual cause.",
                source.label()
            ));
            return;
        }
        if !is_profile_name(&name) {
            self.notes.push(format!(
                "an entry in {} was skipped: its name is not one (letters, digits, `-`, `_` or \
                 `.`, up to {NAME_LIMIT} characters). It is not repeated here, because the usual \
                 cause is an entry written the wrong way round — which would make the name a \
                 connection string.",
                source.label()
            ));
            return;
        }
        match self.entries.entry(normalize(&name)) {
            std::collections::btree_map::Entry::Occupied(mut taken) => {
                let kept = taken.get_mut();
                // Environment over file is the documented precedence, not a mistake, and neither
                // is a duplicate that agrees with itself. Two spellings within *one* source that
                // name **different** targets are: they are one name once `-`, `_` and `.` are
                // treated alike, and nothing here can know which was meant.
                if kept.source == source && kept.connection.expose() != connection {
                    self.notes.push(format!(
                        "`{name}` and `{}` in {} are one name once `-`, `_` and `.` are treated \
                         alike, but name different targets, so neither can be used until one is \
                         renamed or removed.",
                        kept.name,
                        source.label(),
                    ));
                    kept.conflicts.push(name);
                }
            }
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(Profile {
                    name,
                    connection: Connection::new(connection),
                    source,
                    conflicts: Vec::new(),
                });
            }
        }
    }

    /// A fixed set, for tests: resolution has to be provable without mutating the process
    /// environment, which in edition 2024 is `unsafe` and races every other test in the binary.
    #[cfg(test)]
    fn from_pairs(pairs: &[(&str, &str)]) -> Self {
        let mut profiles = Self {
            entries: BTreeMap::new(),
            notes: Vec::new(),
            file: Some(PathBuf::from(r"C:\Users\test\.windbg-mcp\profiles.json")),
        };
        for (name, connection) in pairs {
            profiles.admit((*name).to_string(), connection, Source::File);
        }
        profiles
    }

    fn get(&self, name: &str) -> Option<&Profile> {
        self.entries.get(&normalize(name))
    }

    /// The configured names, as they were written. Names are not secrets — that is the whole
    /// point of them, and [`Self::admit`] is what makes sure a name is one — so they are safe to
    /// put in an error a client will keep.
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
        let notes = match self.notes.as_slice() {
            [] => String::new(),
            notes => format!(
                "\n\nThe configuration was read with problems, which may be why the profile you \
                 want is missing:\n- {}",
                notes.join("\n- ")
            ),
        };
        format!(
            "Profiles are resolved by this server, on this host: from `{PROFILE_ENV_PREFIX}<NAME>` \
             in its environment {file}. Names are matched case-insensitively, with `-` and `_` \
             equivalent.\n\nThis server cannot add one, but the user can, and asking them for that \
             beats asking for a connection string — every later attach then names it, and the key \
             stays on this host. **The file is the one to ask for now**: it is re-read on every \
             attach, so adding `{{ \"<name>\": \"net:port=<n>,key=<w.x.y.z>\" }}` to it works \
             immediately. A `{PROFILE_ENV_PREFIX}<NAME>` variable is read from *this process's* \
             environment, which was fixed when it started — setting one in a shell now changes \
             nothing until this server is restarted, so that route is for the MCP client's server \
             definition rather than for right now.{notes}"
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

/// Every environment variable this module reads, by name.
///
/// Public so [`crate::engine`] can strip them from a worker's environment. A worker is told the
/// one connection it is opening, down its private pipe, and resolves nothing itself — so it has no
/// use for any of these, and a `launch`ed debuggee inherits the worker's environment in turn.
/// Handing an untrusted program every configured kernel key is the outcome being avoided.
pub fn env_names() -> Vec<String> {
    env_names_in(std::env::vars_os().filter_map(|(key, _)| key.into_string().ok()))
}

/// The filter behind [`env_names`], over a supplied set so it can be tested against fixed input
/// rather than against whatever the developer's shell happens to hold.
fn env_names_in(keys: impl Iterator<Item = String>) -> Vec<String> {
    keys.filter(|key| {
        profile_env_suffix(key).is_some() || key.eq_ignore_ascii_case(PROFILES_FILE_ENV)
    })
    .collect()
}

/// The profile name an environment variable defines, if it defines one.
///
/// Matched **case-insensitively**, because Windows environment-variable names are: a variable set
/// as `$env:Windbg_Mcp_Profile_Ctf` is stored and enumerated with that spelling, and a
/// case-sensitive test would then miss it twice over — the profile would not resolve, *and* the
/// variable would survive [`env_names`]'s scrubbing into every worker and every launched debuggee.
/// The second is the one that matters: a name we fail to recognise is still a key in the
/// environment.
fn profile_env_suffix(key: &str) -> Option<&str> {
    let (head, suffix) = key.split_at_checked(PROFILE_ENV_PREFIX.len())?;
    head.eq_ignore_ascii_case(PROFILE_ENV_PREFIX)
        .then_some(suffix)
}

/// The (name, connection) pairs a set of environment variables defines.
///
/// Split out from [`Profiles::from_host`] so the mapping is testable: `std::env::set_var` is
/// `unsafe` in edition 2024 and mutates state every other test in this binary shares, so the only
/// way to prove `WINDBG_MCP_PROFILE_CTF_VM` defines the profile `ctf-vm` is to hand the scan its
/// variables rather than the process's.
fn env_entries(vars: impl Iterator<Item = (String, String)>) -> Vec<(String, String)> {
    vars.filter_map(|(key, value)| {
        let suffix = profile_env_suffix(&key)?;
        if suffix.is_empty() || value.trim().is_empty() {
            return None;
        }
        // The variable's own suffix *is* the profile's name, lowercased — an environment variable
        // cannot carry a hyphen, so `WINDBG_MCP_PROFILE_CTF_VM` lists as `ctf_vm`. Asking for
        // `ctf-vm` still finds it: both normalize to the same key.
        Some((suffix.to_ascii_lowercase(), value.trim().to_string()))
    })
    .collect()
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
    // **A leading UTF-8 BOM is not a broken file.** This is the one config file a Windows user
    // writes by hand, and Windows PowerShell 5.1's own `Set-Content -Encoding utf8` — the obvious
    // way to write it — puts a BOM in front. `serde_json` then rejects the whole file with
    // "expected value at line 1 column 1", which reads as "your JSON is malformed" about a file
    // whose JSON is perfect. Skipping it costs nothing and the alternative is a config that
    // cannot be written with the platform's default text writer.
    let text = text.strip_prefix('\u{feff}').unwrap_or(text.as_str());
    let parsed: serde_json::Value = serde_json::from_str(text)
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
                "{} in {} must be a string (its connection string)",
                referred_to_as(name),
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
            let connection = connection.trim();
            if !is_dialable(connection) {
                return Err(
                    "`connection` contains a space or a control character between its parameters, \
                     which no connection string does — parameters are separated by commas. It is \
                     not repeated here, in case it carries a key. Pass it as one unbroken string, \
                     e.g. \"net:port=50000,key=<w.x.y.z>\"."
                        .to_string(),
                );
            }
            let connection = Connection::new(connection);
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
        // Configured twice, for two different targets. Refused rather than resolved to whichever
        // was read first: this server cannot know which was meant, and the cost of guessing is a
        // session on the wrong kernel that reports itself as the right one. The names are all
        // valid ones (`admit` saw to that), so listing them is safe and is the whole fix.
        Some(profile) if !profile.conflicts.is_empty() => Err(format!(
            "the profile named `{name}` is configured more than once, for different targets: {}. \
             Those are one name to this server, which treats `-`, `_` and `.` alike and ignores \
             case, so it cannot tell which was meant — and dialling the wrong one would open a \
             session on the wrong machine. Ask the user to rename or remove all but one; the \
             others here are usable in the meantime. {}",
            once_each(profile),
            profiles.listed()
        )),
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

/// The colliding spellings of one profile, as an error should list them.
fn once_each(profile: &Profile) -> String {
    std::iter::once(&profile.name)
        .chain(&profile.conflicts)
        .map(|name| format!("`{name}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Whether this is a connection string this server will dial.
///
/// Deliberately a low bar — DbgEng owns the syntax, and reimplementing it here would reject
/// transports nobody here has heard of — refusing exactly what [`is_ambiguous`] describes, which
/// is the same rule [`redact`] renders by. The two must agree: a character only one of them
/// refuses reaches the parse by whichever route the other guards.
///
/// Refusing here *as well as* rendering opaquely there is what lets a caller learn why their
/// label would otherwise have gone blank.
fn is_dialable(connection: &str) -> bool {
    !connection.is_empty() && !connection.chars().any(is_ambiguous)
}

/// Whether this is a profile name rather than something else that got put where one belongs.
///
/// The charset is what makes a name safe to *render*: no `=`, so a connection string cannot pass;
/// no line breaks, so nothing configured here can inject a line into a tool result.
fn is_profile_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= NAME_LIMIT
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// How a configured entry is referred to in a message.
///
/// A name that is not a name is *located*, never quoted: the likeliest reason a JSON key fails
/// [`is_profile_name`] is an entry written the wrong way round, which makes the key the connection
/// string — and quoting it would put the key in the transcript this whole module exists to keep it
/// out of.
fn referred_to_as(name: &str) -> String {
    if is_profile_name(name) {
        format!("profile `{name}`")
    } else {
        "an entry whose name is not a profile name".to_string()
    }
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

    /// The invariant the whole design rests on: **the parse is total.** Every byte of the input
    /// lands in exactly one field, so rendering it back with secrets kept reproduces the input
    /// character for character.
    ///
    /// This is what makes redaction structural rather than anticipatory. If a decoration existed
    /// that the parse silently dropped or duplicated, its bytes would be unaccounted for — and an
    /// unaccounted-for byte is precisely how a scanner leaks half a key. Asserted here over the
    /// awkward shapes rather than the tidy ones, including every input that was a bug.
    #[test]
    fn the_parse_accounts_for_every_byte_of_its_input() {
        let cases = [
            FAKE,
            "",
            ":",
            "=",
            ",",
            "key",
            "key=",
            "net:port=1,key=",
            "net:port=1,",
            "net:port=1,,key=x",
            "net:port=1;key=x",
            "com:port=com1,baud=115200,pipe,reconnect",
            "npipe:server=box,pipe=dbg,password=hunter2",
            "net:port=1,key=a=b=c,target=host",
            "net:port=1,key=a:b,target=host",
            "net:port=1,\r\nkey= 1.2.3.4  ,target=host",
            "  net:port=1 , key = 1.2.3.4 ",
            "key=1.2.3.4",
            "no-parameters-at-all",
            "ünïcödé:port=1,key=1.2.3.4",
        ];
        for case in cases {
            assert_eq!(
                Parsed::of(case).render(Secrets::Keep),
                case,
                "the parse lost or invented bytes for {case:?}"
            );
        }
    }

    /// The same invariant over a generated corpus of **well-formed** connections, with both halves
    /// of the actual claim checked: a secret parameter never survives redaction, and a non-secret
    /// one always does.
    ///
    /// Both directions matter. Leaking is the failure this module exists to prevent; over-masking
    /// is the failure that would make a redacted label useless for telling two targets apart, and
    /// the tempting over-broad fixes (mask anything that looks like a value) fail exactly here.
    ///
    /// Whitespace is deliberately **not** among the decorations: it has no unambiguous reading, so
    /// it is refused by `is_dialable` and rendered opaque by `redact` — asserted separately, in
    /// `an_ambiguous_connection_keeps_none_of_its_detail`. What is varied here is everything a
    /// real connection string can legitimately contain.
    #[test]
    fn no_decoration_around_a_parameter_changes_which_parameter_it_is() {
        const SEPARATORS: &[char] = &[',', ';'];
        // Secret, secret in another case, and three that merely resemble one.
        const NAMES: &[(&str, bool)] = &[
            ("key", true),
            ("KeY", true),
            ("password", true),
            ("pubkey", false),
            ("keyring", false),
            ("port2", false),
        ];
        // Values that have themselves been mistaken for structure.
        const VALUES: &[&str] = &[FAKE_KEY, "a=b=c", "a:b", "1.2.3.4"];
        const PREFIXES: &[&str] = &["net:", "", "npipe:"];

        let mut checked = 0;
        for separator in SEPARATORS {
            for (name, secret) in NAMES {
                for value in VALUES {
                    for prefix in PREFIXES {
                        let input = format!(
                            "{prefix}port=1{separator}{name}={value}{separator}target=host"
                        );
                        assert_eq!(
                            Parsed::of(&input).render(Secrets::Keep),
                            input,
                            "not accounted for: {input:?}"
                        );
                        let redacted = redact(&input);
                        assert_eq!(
                            !redacted.contains(value),
                            *secret,
                            "`{name}={value}` redacted as {redacted:?}"
                        );
                        // Whatever happened to the secret, the readable parts survive — that is
                        // what a redacted label is *for*.
                        assert!(
                            redacted.starts_with(&format!("{prefix}port=1"))
                                && redacted.ends_with("target=host"),
                            "{redacted:?}"
                        );
                        checked += 1;
                    }
                }
            }
        }
        assert_eq!(
            checked, 144,
            "the corpus shrank; the coverage claim moved with it"
        );
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

    /// Whitespace around a secret parameter must not smuggle it past the scan, on either side of
    /// the `=`. Before the name, too narrow a delimiter set parsed `"\r\nkey"` and matched
    /// nothing; after the `=`, the value measured zero length and nothing was masked. Both ended
    /// the same way — the key back in the session label, the one output redaction exists to keep
    /// clean.
    #[test]
    fn no_whitespace_anywhere_in_a_connection_leaves_a_key_readable() {
        for gap in ["\r\n", "\n", "\r", "\t", " ", "\x0c", "  "] {
            for shape in [
                format!("net:port=1,{gap}key={FAKE_KEY}"),
                format!("net:port=1,key={gap}{FAKE_KEY},target=host"),
                format!("net:port=1{gap}key={FAKE_KEY}"),
                format!("net:port=1,key{gap}={FAKE_KEY}"),
            ] {
                let out = redact(&shape);
                assert!(!out.contains(FAKE_KEY), "gap {gap:?} leaked: {out}");
                assert_eq!(out, OPAQUE, "gap {gap:?} in {shape:?}");
            }
        }
    }

    #[test]
    fn redaction_leaves_a_string_with_no_secret_alone() {
        for s in ["net:port=50000", "com:port=com1,baud=115200", "", "key"] {
            assert_eq!(redact(s), s);
        }
        // Nothing to mask is not the same as something to hide.
        assert_eq!(redact("net:port=1,key="), "net:port=1,key=");
    }

    // ---- scrubbing arbitrary text --------------------------------------
    //
    // The transcript's half of redaction. `redact` answers "render this connection safely";
    // `scrub` answers "there may be one somewhere in this blob", which is a different question
    // with a different failure mode — masking the blob.

    /// The case the whole function exists for: a tool call carrying a raw connection, exactly as
    /// it crosses the wire, recorded into a file.
    #[test]
    fn scrubbing_masks_a_key_inside_a_tool_call() {
        let call = format!(r#"{{"connection":"{FAKE}","session_id":null}}"#);
        let out = scrub(&call);
        assert!(!out.contains(FAKE_KEY), "the key survived scrubbing: {out}");
        assert_eq!(
            out,
            r#"{"connection":"net:port=50000,key=<redacted>","session_id":null}"#
        );
    }

    /// The other shape a secret arrives in: a JSON member of its own, quoted both sides.
    #[test]
    fn scrubbing_masks_a_quoted_json_member() {
        assert_eq!(
            scrub(r#"{"key":"1.2.3.4","port":50000}"#),
            r#"{"key":"<redacted>","port":50000}"#
        );
        // Pretty-printed, where a space follows the colon.
        assert_eq!(
            scrub("{\n  \"password\": \"hunter2\"\n}"),
            "{\n  \"password\": \"<redacted>\"\n}"
        );
    }

    /// A blob is not a connection string, so nothing but the parameter may be touched. This is
    /// what `redact` cannot do: given any of these it answers `OPAQUE` for the whole thing.
    #[test]
    fn scrubbing_leaves_the_text_around_a_secret_alone() {
        let text = "attaching to net:port=50000,key=1.2.3.4 (profile CTF)\nlink up in 25s";
        assert_eq!(
            scrub(text),
            "attaching to net:port=50000,key=<redacted> (profile CTF)\nlink up in 25s"
        );
        assert_eq!(scrub(""), "");
        for clean in ["no secret here", "net:port=50000", "{\"tag\":\"Tgsm\"}"] {
            assert_eq!(scrub(clean), clean);
        }
    }

    /// Whole names only, at both ends, and the same rule the parser uses.
    #[test]
    fn scrubbing_matches_whole_parameter_names_only() {
        for untouched in ["pubkey=abc", "keyring=abc", "monkey=abc", "my-key=abc"] {
            assert_eq!(scrub(untouched), untouched);
        }
        // Case-insensitive, like `is_secret`.
        assert_eq!(scrub("KEY=1.2.3.4"), "KEY=<redacted>");
        assert_eq!(scrub("Password=hunter2"), "Password=<redacted>");
    }

    /// The reason a bare `key:` is not a separator. A debugger printing a registry path is prose,
    /// and a transcript that masked it would lose a fact to a rule about connection strings —
    /// while giving up nothing, because no connection string is written that way.
    #[test]
    fn scrubbing_does_not_mask_prose_that_merely_says_key() {
        for prose in [
            r"Key: \REGISTRY\MACHINE\SYSTEM",
            "the key is in the profile",
            "password rotation is monthly",
        ] {
            assert_eq!(scrub(prose), prose);
        }
    }

    /// An empty value is not a secret. `redact` takes the same view, and the two must agree:
    /// reporting `<redacted>` where nothing was supplied describes a target that does not exist.
    #[test]
    fn scrubbing_leaves_an_empty_value_alone() {
        for empty in ["net:port=1,key=", r#"{"key":""}"#, "key= "] {
            assert_eq!(scrub(empty), empty);
        }
    }

    /// Filler around the separator, which is how a *person* writes a connection string.
    ///
    /// This is the shape [`is_dialable`] refuses — and it is refused only after the argument has
    /// already been recorded, so a scan that insisted on `key=` exactly would mask the key in the
    /// connections this server accepts and miss it in the one it turns away.
    #[test]
    fn scrubbing_masks_a_secret_with_filler_around_the_separator() {
        assert_eq!(
            scrub("net:port=50000, key = 1.2.3.4"),
            "net:port=50000, key = <redacted>"
        );
        assert_eq!(scrub("key\t=\t1.2.3.4"), "key\t=\t<redacted>");
        // The JSON spelling of the same thing. `serde_json` does not emit it, but `scrub` also
        // runs over result text, which is whatever the target printed.
        assert_eq!(
            scrub(r#"{"password" : "hunter2"}"#),
            r#"{"password" : "<redacted>"}"#
        );
    }

    /// Masking **by value** is the half of `scrub` that is a guarantee, and this is what it buys:
    /// the same key written four ways that the pattern scan handles differently, and one it does
    /// not handle at all, all masked because they *are* the key.
    ///
    /// Three rounds of review found three separate syntaxes the scan missed. Chasing a fourth was
    /// the wrong move; knowing the value ends the category.
    #[test]
    fn a_known_secret_is_masked_however_it_is_written() {
        // Registered the way every real one is: by being dialled.
        let _ = Connection::new("net:port=50011,key=203.0.113.77");
        for written in [
            // The shapes the scan also catches, for the avoidance of doubt.
            "net:port=50011,key=203.0.113.77",
            r#"{"connection":"net:port=50011,key=203.0.113.77"}"#,
            // And the ones it does not: no parameter name in sight.
            "the key for that box is 203.0.113.77, do not share it",
            "KDNET_KEY=203.0.113.77",
            r#"{"note":"reconnect with 203.0.113.77"}"#,
            "203.0.113.77",
        ] {
            let out = scrub(written);
            assert!(
                !out.contains("203.0.113.77"),
                "a key this server was handed survived as `{out}`"
            );
            assert!(
                out.contains(MASK),
                "and it should say something was masked: {out}"
            );
        }
    }

    /// A value too short to be a real secret is not masked, because masking it would do more
    /// damage than the leak: a key of `1` would blank every digit in a transcript.
    #[test]
    fn a_secret_too_short_to_be_one_is_not_masked_by_value() {
        let _ = Connection::new("net:port=1,key=1.2");
        assert_eq!(
            scrub("the value 1.2 appears often"),
            "the value 1.2 appears often"
        );
        // The pattern scan still covers it where it is written as a parameter, which is the only
        // place a two-character key means anything.
        assert_eq!(scrub("key=1.2"), "key=<redacted>");
    }

    /// A quoted value ends at the first *unescaped* quote.
    ///
    /// The failure this prevents is the worst shape a redaction bug takes: a line that reads as
    /// redacted while still carrying the tail of the secret. Stopping at the escaped quote would
    /// mask `hunter\` and leave `suffix` in the transcript.
    #[test]
    fn scrubbing_masks_a_quoted_value_that_contains_a_quote() {
        assert_eq!(
            scrub(r#"{"password":"hunter\"suffix"}"#),
            r#"{"password":"<redacted>"}"#
        );
        // A trailing backslash is escaped itself, so the quote after it really does close.
        assert_eq!(
            scrub(r#"{"password":"hunter\\"}"#),
            r#"{"password":"<redacted>"}"#
        );
        // Unterminated: everything to the end is the value, which errs toward masking.
        assert_eq!(scrub(r#"{"key":"1.2.3.4"#), r#"{"key":"<redacted>"#);
    }

    /// JSON quoted inside a string arrives with its own delimiters escaped, which is how a
    /// debugger's output and a log line carry a request they are quoting.
    #[test]
    fn scrubbing_masks_a_secret_whose_json_is_itself_escaped() {
        assert_eq!(
            scrub(r#"request was {\"password\":\"hunter2\"}"#),
            r#"request was {\"password\":\"<redacted>\"}"#
        );
        assert_eq!(
            scrub(r#"{\"key\": \"1.2.3.4\"}"#),
            r#"{\"key\": \"<redacted>\"}"#
        );
    }

    /// Filler stops at the end of the line, which is the difference between "no value" and "the
    /// next line".
    ///
    /// A trim that skipped every whitespace character masked the first token *after* the line
    /// break — so `key=` at the end of a line ate the symbol below it, reporting a secret where
    /// there was an empty value and losing a fact from the transcript.
    #[test]
    fn scrubbing_does_not_run_past_the_end_of_a_line() {
        // Values no other test registers: `KNOWN_SECRETS` is process-wide on purpose, so a test
        // asserting something is *not* masked cannot reuse a key another test has dialled.
        for across in [
            "key=\nnt!KeBugCheckEx",
            "net:port=1,key=\n198.51.100.4",
            "password=\r\nnotasecrethere",
        ] {
            assert_eq!(scrub(across), across);
        }
    }

    /// Several in one blob, which is what a batch of tool calls looks like.
    #[test]
    fn scrubbing_masks_every_secret_in_the_text() {
        let out = scrub("key=1.2.3.4 then password=hunter2 then key=5.6.7.8");
        assert_eq!(
            out,
            "key=<redacted> then password=<redacted> then key=<redacted>"
        );
    }

    /// Arbitrary text really is arbitrary: a target names its own modules, and a scan that
    /// advanced by bytes would panic on the first one that is not ASCII.
    #[test]
    fn scrubbing_survives_text_that_is_not_ascii() {
        let text = "модуль ключ ✓ key=1.2.3.4 ✓";
        assert_eq!(scrub(text), "модуль ключ ✓ key=<redacted> ✓");
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

    /// What a worker's environment has to be stripped of. Everything this module reads, and
    /// nothing else — a worker still needs `PATH`, `SystemRoot` and the rest to run at all.
    #[test]
    fn the_variables_a_worker_must_not_inherit_are_this_modules_own() {
        let names = env_names_in(
            [
                "WINDBG_MCP_PROFILE_CTF_VM",
                "WINDBG_MCP_PROFILES",
                "WINDBG_MCP_CALL_TIMEOUT_SECS",
                "PATH",
                "WINDBG_MCP_SMOKE_KERNEL",
            ]
            .into_iter()
            .map(String::from),
        );
        assert_eq!(names, ["WINDBG_MCP_PROFILE_CTF_VM", "WINDBG_MCP_PROFILES"]);
    }

    /// Windows environment-variable names are case-insensitive but keep the spelling they were
    /// created with, so `$env:Windbg_Mcp_Profile_Ctf` enumerates exactly like that. A
    /// case-sensitive test would miss it twice: the profile would not resolve, *and* the variable
    /// would survive the scrubbing into every worker and every launched debuggee — a key we chose
    /// not to recognise is still a key in the environment.
    #[test]
    fn environment_names_are_matched_the_way_windows_matches_them() {
        let spellings = [
            "WINDBG_MCP_PROFILE_CTF",
            "Windbg_Mcp_Profile_Ctf",
            "windbg_mcp_profile_ctf",
        ];
        for spelling in spellings {
            let vars = [(spelling.to_string(), FAKE.to_string())];
            assert_eq!(
                env_entries(vars.into_iter()),
                [("ctf".to_string(), FAKE.to_string())],
                "{spelling} should define the profile `ctf`"
            );
            assert_eq!(
                env_names_in([spelling.to_string()].into_iter()),
                [spelling],
                "{spelling} must be scrubbed from a worker's environment"
            );
        }
        assert_eq!(
            env_names_in([String::from("windbg_mcp_profiles")].into_iter()),
            ["windbg_mcp_profiles"]
        );
    }

    /// Neither a control character nor interior whitespace belongs in a connection string, and
    /// both are refused before a label is ever built. The control character would forge a line in
    /// `session_status`'s multi-line report; the whitespace would make the parameter boundaries
    /// ambiguous, which is what `redact` cannot resolve safely in either direction.
    ///
    /// The outer trim runs first, so a pasted string with a trailing newline is still fine — this
    /// is about what sits *between* parameters.
    #[test]
    fn a_connection_broken_across_parameters_is_refused_without_being_echoed() {
        for broken in [
            format!("net:port=1,\nkey={FAKE_KEY}"), // a control character
            format!("net:port=50000 key={FAKE_KEY}"), // a missing comma
            format!("net:port=1,key= {FAKE_KEY}"),  // a stray space before the value
        ] {
            let err = select(Some(broken.clone()), None).unwrap_err();
            assert!(err.contains("space or a control character"), "{err}");
            assert!(!err.contains(FAKE_KEY), "for {broken:?}: {err}");
        }

        // Trimmed, not refused: whitespace around the whole string is a paste artefact.
        let padded = select(Some(format!("  {FAKE}\n")), None).expect("the outer trim runs first");
        assert_eq!(padded.connection.expose(), FAKE);

        // Same gate on the configured path: the entry is named (its name passed its own check)
        // and the value is not.
        let profiles = Profiles::from_pairs(&[
            ("ctf-vm", FAKE),
            ("broken", &format!("net:port=50000 key={FAKE_KEY}")),
        ]);
        assert_eq!(profiles.names(), ["ctf-vm"]);
        let err = resolve("broken", &profiles).unwrap_err();
        assert!(
            err.contains("`broken`") && err.contains("space or a control character"),
            "{err}"
        );
        assert!(!err.contains(FAKE_KEY), "{err}");
    }

    /// If a connection carrying whitespace reaches redaction anyway, it discloses **nothing**
    /// rather than being read one of the two incompatible ways.
    ///
    /// This is the case that broke the parse and, before it, the scanner — in opposite directions.
    /// Reading the space as filler swallows `key=` into `port`'s value and masks nothing; reading
    /// it as a separator leaves `key` empty and turns the key into a bare flag. Both disclose it,
    /// so neither reading is taken.
    #[test]
    fn an_ambiguous_connection_keeps_none_of_its_detail() {
        for ambiguous in [
            format!("net:port=50000 key={FAKE_KEY}"),
            format!("net:port=1,key= {FAKE_KEY}"),
            format!("net:port=1,key\t={FAKE_KEY}"),
            format!("net:port=1,key={FAKE_KEY} target=host"),
            format!("net:port=1,\r\nkey={FAKE_KEY}"),
            // Control characters that are *not* whitespace. `trim` does not strip these, so a
            // guard that refused only whitespace would let `"\u{0}key"` through the parse as a
            // name matching no secret — and emit the value whole. The two gates share one rule
            // precisely so this cannot differ between them.
            format!("net:port=1,\u{0}key={FAKE_KEY}"),
            format!("net:port=1,\u{7f}key={FAKE_KEY}"),
            format!("net:port=1,key\u{1}={FAKE_KEY}"),
        ] {
            assert!(!is_dialable(&ambiguous), "should be refused: {ambiguous:?}");
            let out = redact(&ambiguous);
            assert!(!out.contains(FAKE_KEY), "{ambiguous:?} leaked: {out}");
            assert_eq!(out, OPAQUE, "for {ambiguous:?}");
        }
        // And it stays opaque through the type, which is what a session label goes through.
        assert_eq!(
            Connection::new(format!("net:port=50000 key={FAKE_KEY}")).to_string(),
            OPAQUE
        );
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

        let mut profiles = Profiles {
            entries: BTreeMap::new(),
            notes: Vec::new(),
            file: None,
        };
        for (name, connection) in env_entries(vars.into_iter()) {
            profiles.admit(name, &connection, Source::Env);
        }
        assert_eq!(profiles.names(), ["ctf_vm"]);
        for asked in ["ctf-vm", "ctf_vm", "CTF-VM"] {
            let selected =
                resolve(asked, &profiles).unwrap_or_else(|e| panic!("{asked} should resolve: {e}"));
            assert_eq!(selected.connection.expose(), FAKE);
        }
    }

    /// A configured *name* is rendered — in the profile list, in a session label — so a name that
    /// is not a name must not get in. The way that happens in practice is an entry written the
    /// wrong way round, which makes the JSON key the connection string; admitting it would print
    /// a key out of the very error that says the entry is wrong.
    #[test]
    fn a_configured_entry_whose_name_is_not_a_name_is_refused_without_being_quoted() {
        let profiles = Profiles::from_pairs(&[
            ("ctf-vm", FAKE),
            (FAKE, "net:port=1,key=9.9.9.9"),
            ("has\na newline", "net:port=2,key=8.8.8.8"),
        ]);
        assert_eq!(profiles.names(), ["ctf-vm"]);

        let err = resolve("typo", &profiles).unwrap_err();
        assert!(err.contains("its name is not one"), "{err}");
        for leaked in [FAKE_KEY, "9.9.9.9", "8.8.8.8", "port=1", "\n a newline"] {
            assert!(!err.contains(leaked), "the note quoted `{leaked}`:\n{err}");
        }
    }

    /// Two spellings of one name in one source, naming **different** targets, must not resolve to
    /// whichever was read first. Nothing here can know which was meant, and the cost of guessing
    /// is a session on the wrong kernel that reports itself as the right one — so both spellings
    /// are refused until an operator picks. A note alone would not do it: notes surface when a
    /// lookup *fails*, and this lookup used to succeed.
    #[test]
    fn one_name_configured_for_two_targets_is_refused_not_guessed() {
        let profiles =
            Profiles::from_pairs(&[("ctf-vm", FAKE), ("ctf.vm", "net:port=1,key=9.9.9.9")]);
        for asked in ["ctf-vm", "ctf.vm", "CTF_VM"] {
            let err = resolve(asked, &profiles)
                .err()
                .unwrap_or_else(|| panic!("`{asked}` must not resolve to a guess"));
            assert!(
                err.contains("`ctf-vm`") && err.contains("`ctf.vm`"),
                "{err}"
            );
            assert!(err.contains("different targets"), "{err}");
            assert!(!err.contains(FAKE_KEY) && !err.contains("9.9.9.9"), "{err}");
        }
    }

    /// The two collisions that are *not* ambiguous, and so must stay usable: the documented
    /// environment-over-file override, and a duplicate that simply agrees with itself.
    #[test]
    fn an_override_and_a_duplicate_that_agrees_are_not_conflicts() {
        let mut override_case = Profiles {
            entries: BTreeMap::new(),
            notes: Vec::new(),
            file: None,
        };
        override_case.admit("ctf_vm".into(), FAKE, Source::Env);
        override_case.admit("ctf-vm".into(), "net:port=1,key=9.9.9.9", Source::File);
        assert_eq!(override_case.entries.len(), 1);
        assert!(
            override_case.notes.is_empty(),
            "the environment overriding the file is documented behaviour, not a problem: {:?}",
            override_case.notes
        );
        let selected = resolve("ctf-vm", &override_case).expect("the override resolves");
        assert_eq!(selected.connection.expose(), FAKE, "the environment wins");

        let agreeing = Profiles::from_pairs(&[("lab-vm", FAKE), ("lab.vm", FAKE)]);
        assert!(agreeing.notes.is_empty(), "{:?}", agreeing.notes);
        assert_eq!(
            resolve("lab.vm", &agreeing)
                .expect("two spellings of one target are not ambiguous")
                .connection
                .expose(),
            FAKE
        );
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

        // Written the way Windows PowerShell 5.1 writes UTF-8: with a BOM in front. Not a
        // hypothetical — it is what `Set-Content -Encoding utf8` produces, and before this was
        // handled the file it wrote was rejected as malformed JSON.
        let bom = dir.join("bom.json");
        std::fs::write(&bom, format!("\u{feff}{{ \"ctf-vm\": \"{FAKE}\" }}")).unwrap();
        assert_eq!(
            read_profile_file(&bom)
                .expect("a UTF-8 BOM is not a broken profile file")
                .get("ctf-vm")
                .map(String::as_str),
            Some(FAKE)
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
