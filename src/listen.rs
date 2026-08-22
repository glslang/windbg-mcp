//! The listener role: MCP over streamable HTTP, for a client on another machine.
//!
//! Started with `--listen <addr>`, this serves the same tool surface as the stdio role over HTTP
//! instead of standard handles. It exists so the model and the client can run somewhere other than
//! the machine DbgEng needs — see `docs/remote-phase0.md` for the setup this replaces.
//!
//! **Bind loopback and reach it through an ssh tunnel.** The listener is, functionally,
//! patch-the-kernel-as-a-service: `execute`, `debug_batch` and `launch` are all on it. The bearer
//! token below is a second lock, not the first one, and it is sent in clear — a routable bind is
//! never the right answer, and a hypervisor's guest network is not private either when the machine
//! being debugged is a sandbox sharing that subnet.
//!
//! ## What HTTP takes away, and what this puts back
//!
//! The stdio role gets one property for free that everything here exists to rebuild. When stdin
//! closes, the client is *definitively* gone, and [`Sessions::shutdown`] releases every target —
//! which for a live kernel is the difference between a machine that comes back and one left
//! frozen. Over HTTP there is no such moment: a client that has stopped talking is
//! indistinguishable from one thinking, and a connection that dropped is indistinguishable from a
//! network that will recover.
//!
//! So a client holds a **lease**. Any request renews it; when it runs out, the sessions that client
//! opened are released exactly as a disconnect would have released them
//! ([`Sessions::release_leased`]). Two consequences worth stating plainly:
//!
//! - **The grace must outlast a call**, or a long `!analyze` — which sends no HTTP request while it
//!   runs — would look like an absent client and have its own session released underneath it. That
//!   is checked at startup rather than documented and hoped for; see [`Lease::new`].
//! - **A returning client adopts what it left.** Sessions are not released the instant a client
//!   goes away, so reconnecting inside the grace finds them still open. That is strictly better
//!   than stdio, where a client restart costs a KDNET attach — and a KDNET attach costs a reboot
//!   of the target.
//!
//! ## A clock, and no longer a gate
//!
//! The lease used to arbitrate as well as time. The registry was one map for the whole server —
//! handles minted from it, `MAX_SESSIONS` shared, `end_session` ending whatever it was handed — so
//! serving one client at a time *was* the boundary between two clients, and a second one was
//! refused with a `409`.
//!
//! Ownership took that job over ([#162]). A session belongs to the client that opened it, a handle
//! routes only for its owner, and the cap, the closed-session history and this lease's own release
//! are all per client. What the gate had left to arbitrate was one credential racing *itself* — a
//! second `initialize` while it held one, or a request bearing an id that was not the one it
//! held — and inside a namespace that is not a boundary at all: both MCP sessions reach the same
//! debug sessions, because they are the same client. So the gate is gone, along with the
//! reservation, the in-flight count and the handover they existed to sequence.
//!
//! Two refusals remain, and neither of them was ever tenancy:
//!
//! - an `Mcp-Session-Id` **another client** holds is reported unknown ([`Admission::NotYours`]).
//!   The MCP service keeps one session table for the whole server, so that id is all that stands
//!   between a client and another's MCP session — and a `DELETE` on it is the sharp end.
//! - a request arriving while this credential's own expired sessions are still being released is
//!   told to ask again ([`Admission::Releasing`]). That is the sweep's, not the gate's: what it
//!   protects is the window between deciding to release and having released.
//!
//! [#162]: https://github.com/glslang/windbg-mcp/issues/162

use std::collections::{BTreeSet, HashMap};
use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::header::AUTHORIZATION;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rmcp::transport::streamable_http_server::SessionManager;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use tokio::net::TcpListener;

use crate::engine::Sessions;
use crate::server::WindbgServer;

/// Turns this process into the listener instead of the stdio server.
pub const LISTEN_FLAG: &str = "--listen";

/// Where the bearer token is read from. An environment variable rather than an argument, because a
/// command line is readable by every process on the machine — including a `launch`ed debuggee.
pub const TOKEN_ENV: &str = "WINDBG_MCP_LISTEN_TOKEN";

/// A file to read credentials from instead, for when an environment variable is not private
/// enough.
///
/// It is not, for a **service**: a service reads the *machine* environment, and that is readable by
/// every local process including unprivileged ones. Since this endpoint's token is the only thing
/// between a caller and `launch`, and a service runs as `LocalSystem`, a machine-scope token is a
/// local privilege escalation rather than an inconvenience — see [`crate::service`], which writes
/// this file with an ACL that excludes ordinary users and points the service at it.
///
/// Read *instead of* [`TOKEN_ENV`] and every named token, not merely before them: a host that has
/// a file is a host whose environment is not trusted. Which is why the file names its own clients —
/// a bare token is `local`, a JSON object of name to token is as many as it lists
/// ([`crate::client::TokenFile`]).
pub const TOKEN_FILE_ENV: &str = "WINDBG_MCP_LISTEN_TOKEN_FILE";

/// How long a session may go unused before it is released, from [`IDLE_ENV`] or [`IDLE_RELEASE`].
///
/// `0` turns it off, which is a supported answer for a host where every client is trusted to hang
/// up — and a footgun anywhere else, so it says so once at startup rather than silently.
fn idle_release(call_timeout: Duration) -> Result<Option<Duration>> {
    idle_release_from(std::env::var(IDLE_ENV).ok().as_deref(), call_timeout)
}

/// The mapping behind [`idle_release`], given the variable's value rather than reading it.
///
/// Split out for the reason `kdconn::env_entries` is: `std::env::set_var` is `unsafe` in edition
/// 2024 and mutates state every other test in this binary shares, so three tests setting the same
/// variable race each other under the default parallel runner. Handing the value in is the only way
/// to assert the floor, the `0` case and the default without that.
fn idle_release_from(configured: Option<&str>, call_timeout: Duration) -> Result<Option<Duration>> {
    let after = match configured {
        Some(raw) => {
            let secs: u64 = raw.trim().parse().with_context(|| {
                format!("`{IDLE_ENV}` must be whole seconds (0 disables), not `{raw}`")
            })?;
            if secs == 0 {
                tracing::warn!(
                    "{IDLE_ENV}=0: a session nobody uses is never released, so a client that goes \
                     away without saying so leaves its target held until this process ends"
                );
                return Ok(None);
            }
            Duration::from_secs(secs)
        }
        None => IDLE_RELEASE,
    };
    // The same floor the lease refuses to start below, and for the same reason: a call can keep a
    // session quiet for its whole budget, and releasing one underneath its own caller is worse than
    // holding an abandoned one.
    let quiet = longest_quiet_call(call_timeout);
    if after <= quiet {
        bail!(
            "`{IDLE_ENV}` ({after:?}) must be longer than the longest a single call can run \
             ({quiet:?}), or a session is released while a call is still using it. Raise it, or \
             set 0 to disable the release entirely."
        );
    }
    Ok(Some(after))
}

/// Overrides how long a client may be silent before its sessions are released, in whole seconds.
const GRACE_ENV: &str = "WINDBG_MCP_LEASE_GRACE_SECS";

/// How much longer than the longest possible call a lease lasts, when nothing says otherwise.
///
/// Defined *from* that bound rather than as a figure of its own, so a host that raises the call
/// timeout raises the grace with it.
const GRACE_HEADROOM: Duration = Duration::from_secs(60);

/// The longest a single tool call can keep the client quiet.
///
/// Not the call timeout on its own. An opener spends up to `WORKER_READY_TIMEOUT` getting a worker
/// up *before* the call budget starts running, so a `301s` grace against a `300s` budget still
/// leaves an attach alive at `301s` — and the sweeper would close the session underneath the very
/// request that opened it. The bound is the sum, and this is where that is written down once.
fn longest_quiet_call(call_timeout: Duration) -> Duration {
    crate::engine::WORKER_READY_TIMEOUT + call_timeout
}

/// How often the SSE stream says it is still there while a call runs quietly.
const SSE_KEEP_ALIVE: Duration = Duration::from_secs(15);

/// How often the sweeper looks for a lease that has run out. Fine enough that a released target is
/// released promptly, coarse enough to cost nothing while idle.
const SWEEP: Duration = Duration::from_secs(5);

/// How long a session may go unused before it is released, and the variable that overrides it.
///
/// **The lease cannot cover this.** A lease is armed by an MCP session, and SEP-2567 removed those
/// from `2026-07-28` — the revision most clients now negotiate — so a client on that revision never
/// gets a clock at all. Without this, one that vanished would leave its targets held until the
/// process ended, which for a live kernel means a machine owned by nobody
/// ([#162](https://github.com/glslang/windbg-mcp/issues/162)).
///
/// Not fixed by identifying the client differently, which the credential now does. The lease
/// releases *everything* a client has, busy or not, on the reasoning that a client which has said
/// nothing for a grace has gone; a `2026-07-28` client is quiet for far longer than that
/// legitimately, and releasing a live kernel under a caller who is merely thinking is worse than
/// holding an abandoned one for half an hour.
///
/// Deliberately much longer than the lease grace. A lease is renewed by *any* request, so a working
/// client renews it constantly; this is per session, and a caller reading a stack for twenty minutes
/// before asking the next question is doing nothing wrong. It is a backstop against abandonment,
/// not a scheduler.
const IDLE_RELEASE: Duration = Duration::from_secs(30 * 60);
const IDLE_ENV: &str = "WINDBG_MCP_SESSION_IDLE_SECS";

/// The header carrying an MCP session id, on the revisions that still have one.
///
/// Read for two things, both of them ownership rather than tenancy: whether the id a request
/// presents belongs to some *other* client, and which ids a client that vanished left resident in
/// the service for the sweep to close. `2026-07-28` sends none ([SEP-2567]) and needs none — the
/// credential is the identity on every revision, and on both transports ([`crate::client`]).
///
/// [SEP-2567]: https://modelcontextprotocol.io/seps/2567-sessionless-mcp
const SESSION_HEADER: &str = "Mcp-Session-Id";

/// Whether this process was asked to listen, and where.
pub fn requested(args: &[String]) -> Option<Result<SocketAddr>> {
    let at = args.iter().position(|arg| arg == LISTEN_FLAG)?;
    Some(match args.get(at + 1) {
        Some(addr) => addr
            .parse()
            .with_context(|| format!("`{LISTEN_FLAG} {addr}` is not a host:port to bind")),
        None => Err(anyhow::anyhow!(
            "`{LISTEN_FLAG}` needs an address to bind, e.g. `{LISTEN_FLAG} 127.0.0.1:8765`"
        )),
    })
}

/// A client's lease: what that credential has open here, and until when.
///
/// One lock over all of it, because the questions are one decision. "Does this credential hold
/// anything" and "has its clock run out" have to read together, or a request is admitted against
/// sessions the sweeper has already decided to release.
struct Lease {
    grace: Duration,
    /// Consulted for the adoption line and nothing else.
    ///
    /// The listener otherwise knows nothing about debug sessions and does not need to: an expiry
    /// hands the registry a *client* and lets it find them, and what this reads back is how many
    /// were still there — the difference between "you picked up three targets" and "nothing was
    /// open".
    sessions: Sessions,
    /// One lease per client, rather than one for the server.
    ///
    /// Sessions are owned ([#162](https://github.com/glslang/windbg-mcp/issues/162)), so one
    /// credential's clock says nothing about anybody else's: an expiry releases the sessions of the
    /// credential whose lease ran out, and a release in flight refuses that credential's requests
    /// and no others. A shared one would mean a client waiting on a boundary the registry already
    /// provides.
    state: Mutex<HashMap<crate::client::Client, Presence>>,
}

/// What one credential has here, and until when.
#[derive(Debug, Default)]
struct Presence {
    /// The MCP sessions this credential has open in the service.
    ///
    /// A **set**, rather than the one holder the gate allowed, because nothing refuses a second
    /// `initialize` any more — and two MCP sessions of one credential reach the same debug
    /// sessions, since they are the same client. They are recorded all the same, for the two things
    /// that need to know whose an id is: refusing another client's ([`Admission::NotYours`]), and
    /// closing what a client that vanished left resident in the service. Tracking only the newest
    /// would leave its older ids owned by nobody, and an id owned by nobody is one any credential
    /// may present.
    ///
    /// How many it holds is the client's own doing — the service keeps a session apiece regardless,
    /// so this mirrors rather than accumulates — and an expiry closes the lot.
    ///
    /// Empty for a `2026-07-28` client, which is sent no id at all — and so is never given a clock
    /// either. Abandonment there is [`IDLE_RELEASE`]'s, per session and far longer.
    mcp: BTreeSet<String>,
    /// This credential's lease has run out and its sessions are being released.
    ///
    /// Held across the release, because the teardown is not instant: deciding to release and having
    /// released are two moments, and in between a request must not be let in to a session this
    /// sweep is closing. That is the window [`Sessions::release_leased`] warns it does not close
    /// itself.
    releasing: bool,
    /// When this credential's sessions are released if nothing renews first. `None` means there is
    /// nothing to release and nothing to wait for.
    ///
    /// Armed only by a request that turned out to have an MCP session behind it
    /// ([`Lease::settle`]), never by one merely arriving: a deadline with nothing behind it is a
    /// lease against nothing, and one grace later it releases whatever that credential has since
    /// opened.
    deadline: Option<Instant>,
    /// This credential has let go of its last MCP session while its debug sessions are still open,
    /// waiting to be adopted by its next one or swept.
    ///
    /// Tracked rather than inferred from `deadline`, so the adoption line says something true: it
    /// is the difference between "you picked up what you left" and "you are the first one here".
    left_open: bool,
    /// This credential has been **taken out of the configuration**, rather than merely gone quiet.
    ///
    /// The difference is what the sweeper does when it finishes: a client that timed out keeps its
    /// entry and may come back to it, while a revoked one is [forgotten](Lease::forget) — lease
    /// state is keyed by client *name*, and an entry left behind is one a client re-added under
    /// that name would inherit, session ids and all.
    revoked: bool,
}

/// What a swept lease left behind.
#[derive(Debug, PartialEq, Eq)]
struct Expired {
    /// The MCP sessions still open when the lease ran out — a client that vanished rather than
    /// saying goodbye. Empty when it said goodbye to each of them, since a `DELETE` closes one.
    ///
    /// Reported so the sweeper can close them in the service too. Releasing the debug sessions
    /// alone would leave those MCP sessions resident and their ids still accepted, and every
    /// disconnect-and-reconnect cycle would add another that no lease will ever sweep again.
    mcp: Vec<String>,
    /// Whether this was a revocation rather than a client going quiet — see [`Presence::revoked`].
    revoked: bool,
}

/// What this listener decided about one request before the MCP service saw it.
///
/// Both refusals are about *whose* sessions are involved, not about how many clients may be served
/// at once — the question the gate used to answer, and that ownership answers now.
#[derive(Debug, PartialEq, Eq)]
enum Admission {
    /// Hand it to the MCP service.
    Serve,
    /// This credential's own sessions are being let go after its lease ran out. It holds nothing at
    /// this moment, and the advice is to ask again once the release is done rather than to change
    /// anything.
    Releasing,
    /// The request carried an MCP session id **another client** holds. Reported to the caller as
    /// unknown, for the reason the registry reports another client's handle that way: the answer
    /// must not confirm a session the caller may not use.
    NotYours,
}

/// A borrow of one client's lease state, so the rules below read as they did when there was one
/// lease for the server — the difference is entirely in *whose* is being consulted.
struct PresenceGuard<'a> {
    all: std::sync::MutexGuard<'a, HashMap<crate::client::Client, Presence>>,
    client: crate::client::Client,
}

impl std::ops::Deref for PresenceGuard<'_> {
    type Target = Presence;

    fn deref(&self) -> &Presence {
        self.all
            .get(&self.client)
            .expect("state_of inserts before handing out a guard")
    }
}

impl std::ops::DerefMut for PresenceGuard<'_> {
    fn deref_mut(&mut self) -> &mut Presence {
        self.all
            .get_mut(&self.client)
            .expect("state_of inserts before handing out a guard")
    }
}

impl Lease {
    /// Fails rather than starting when the grace could expire inside a call.
    ///
    /// The failure mode this prevents is silent and expensive: a `crash_triage` or a pool walk
    /// sends nothing for minutes, so a grace shorter than the call budget reads it as an absent
    /// client and releases the very session the call is running against. Refusing at startup makes
    /// that a message an operator sees once, instead of a target that goes away mid-analysis.
    ///
    /// It carries a second property now that the gate is gone: a sweep fires only after a whole
    /// grace with nothing admitted, so a floor above the longest call means **no request of that
    /// credential's can still be in flight when its lease expires**. That is what the reservation's
    /// claim generations and in-flight epochs were protecting, and it was already enforced here.
    fn new(grace: Duration, call_timeout: Duration, sessions: Sessions) -> Result<Self> {
        let quiet = longest_quiet_call(call_timeout);
        if grace <= quiet {
            bail!(
                "the lease grace ({grace:?}) must be longer than the longest a call can keep a \
                 client quiet ({quiet:?} — a {call_timeout:?} budget after up to \
                 {:?} bringing an engine worker up), or a call that runs to its deadline looks \
                 like a client that went away and its own session is released underneath it. \
                 Raise {GRACE_ENV}, or lower WINDBG_MCP_CALL_TIMEOUT_SECS.",
                crate::engine::WORKER_READY_TIMEOUT
            );
        }
        Ok(Self {
            grace,
            sessions,
            state: Mutex::new(HashMap::new()),
        })
    }

    fn all(&self) -> std::sync::MutexGuard<'_, HashMap<crate::client::Client, Presence>> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Whether an MCP session id belongs to some client other than this one.
    ///
    /// Only a *recorded* id counts. One closed by a `DELETE` is gone from the service too, and one
    /// a sweep closed went with the lease that held it — so an id nobody records is already
    /// unusable, and treating it as owned would refuse a client its own reconnect on the strength
    /// of a record nothing backs.
    fn held_by_another(&self, caller: &crate::client::Client, session: &str) -> bool {
        self.all()
            .iter()
            .any(|(client, held)| client != caller && held.mcp.contains(session))
    }

    /// One client's lease state, created empty on first use — a client that has never connected
    /// holds nothing, which is what a default [`Presence`] says.
    fn state_of(&self, client: &crate::client::Client) -> PresenceGuard<'_> {
        let mut all = self.all();
        all.entry(client.clone()).or_default();
        PresenceGuard {
            all,
            client: client.clone(),
        }
    }

    /// Whether this request may be served — and, the part that does the work, **renewing this
    /// credential's lease when it is**.
    ///
    /// All a request presents is the `Mcp-Session-Id` it carries, or nothing. There is no third
    /// thing to know since the gate went: the revision does not change the answer, so this no
    /// longer reads `MCP-Protocol-Version` and no longer has an opener to tell apart from a client
    /// that will never have a session. Reading the absence of an id as "a client opening one" is
    /// what made every request of a `2026-07-28` client a reservation, and every overlapping pair a
    /// `409` ([#168](https://github.com/glslang/windbg-mcp/issues/168)) — that classification is
    /// gone rather than fixed.
    ///
    /// Every decision is made under one lock, so the answer a request gets is the state it will be
    /// served against.
    fn admit(&self, client: &crate::client::Client, session: Option<&str>) -> Admission {
        // **Before this client's own state is consulted at all**, because the id may not be its to
        // present. The MCP service keeps one session table for the server, so a client that comes
        // by another's `Mcp-Session-Id` reaches that client's MCP session through it — the
        // task-local only decides which *debug* sessions the tools then see. A `DELETE` on it is
        // the sharp end: rmcp closes the session, and its owner then fails every request it sends.
        // That is one authenticated client denying another, which is what ownership is here to stop.
        if let Some(id) = session
            && self.held_by_another(client, id)
        {
            return Admission::NotYours;
        }
        let mut state = self.state_of(client);
        // Nothing is served while a teardown is in flight. Briefly refusing a client that could
        // have been served costs it a reconnect; serving one costs it the session mid-call.
        //
        // **`revoked` is refused too, and for a different reason than it used to be.** It once
        // stood in for identity: a client was its name, so a name given back reached this same
        // `Presence` and had to be held at a `409` until the sweep forgot it. That is not what it
        // is doing any more — a name given back is a different [`Client`]
        // ([#190](https://github.com/glslang/windbg-mcp/issues/190)) arriving at a `Presence` of its
        // own, and it is served at once.
        //
        // What is left is the *revoked incarnation's own* request: one that authenticated in the
        // moment before its credential was swapped out, and reaches here after. Serving it lets a
        // credential the operator has been told is gone route to its sessions once more.
        //
        // **It narrows the window rather than closing it**, and the comment should say so: a
        // request already inside the MCP service when the swap happened is past every check here
        // and runs to completion, as it must — a call against a live kernel cannot be abandoned
        // half way. Revocation stops what has not started, and the sweep releases the rest.
        if state.releasing || state.revoked {
            return Admission::Releasing;
        }
        // **Renewed if there is one; never created.** "Any request renews the lease" is what keeps a
        // working client's sessions alive, and it has to be *any* request rather than any request of
        // a particular shape: a credential holding a legacy session can go on to send stateless
        // ones — a client that upgraded, or restarted inside the grace — and the sweep reads the
        // deadline and nothing else, so a request that skipped this would have those sessions
        // released out from under it while it was using them.
        //
        // Not created, because a deadline with no MCP session behind it is a lease against nothing.
        // It would fire one grace later and release this credential's sessions — for a client that
        // is sent no session id, all of them — on a clock it never started. Abandonment there is
        // [`IDLE_RELEASE`]'s to catch, per session and far longer.
        //
        // And only after both refusals above have returned, deliberately. A refusal that renewed
        // would let a stream of wrong session ids hold an abandoned client's live kernel target
        // open for ever, which is the failure the sweep exists to prevent.
        if state.deadline.is_some() {
            state.deadline = Some(Instant::now() + self.grace);
        }
        Admission::Serve
    }

    /// Records what the service made of a request, and says whether this was an **adoption** — a
    /// credential picking up debug sessions its previous MCP session left inside the grace. Worth
    /// saying out loud, since the alternative reading (that these are sessions this MCP session
    /// opened) is wrong in a way that matters when it ends one.
    ///
    /// This is the only thing that starts a clock. Before an MCP session exists there is nothing
    /// for a lease to be against, which is the whole of the rule in [`Presence::deadline`] — and
    /// the reason the trap that came with reserving cannot arise here. A reservation armed a
    /// deadline on arrival and had to hand it back when the request minted nothing, which a
    /// `2026-07-28` handshake omitting `MCP-Protocol-Version` legitimately does; there is no
    /// arrival-time deadline to hand back any more.
    ///
    /// **And nothing here guards against a teardown running underneath it**, which the claim
    /// machinery this replaces spent a generation counter and an epoch on. A sweep fires only when
    /// nothing has been admitted for a whole grace, and [`Self::new`] refuses a grace shorter than
    /// the longest a single call can take — so when one fires, no request of that credential's is
    /// still in flight to settle into it.
    fn settle(
        &self,
        requested: Option<&str>,
        minted: Option<&str>,
        ok: bool,
        client: &crate::client::Client,
    ) -> bool {
        // The MCP session this request turned out to have: one the handshake minted, or the one it
        // presented and the service honoured. A request whose id the service **rejected** records
        // nothing — an id nothing backs would arm a clock over sessions no client can reach, and
        // claim an id for a credential that cannot use it.
        let session = match (minted, requested) {
            (Some(id), _) => id,
            (None, Some(id)) if ok => id,
            _ => return false,
        };
        let mut state = self.state_of(client);
        let adopted = state.left_open;
        // Recorded whatever else is true, so the sweep closes it: an MCP session minted for a
        // credential that has since been revoked is one nothing else will ever close.
        state.mcp.insert(session.to_string());
        // **But a revoked lease is never renewed.** [`Self::admit`] refuses this credential, so the
        // only request that reaches here after a revocation is one that was already inside the MCP
        // service when the set was swapped — and renewing on its way out would push the deadline a
        // whole grace into the future, so the sweep that was to run on its next pass does not, and
        // the revoked client's debug sessions stay live for as long as the client kept talking. The
        // clock a revocation set is the one that has to fire.
        if !state.revoked {
            state.deadline = Some(Instant::now() + self.grace);
        }
        state.left_open = false;
        adopted
    }

    /// A client said goodbye to one of its MCP sessions. The debug sessions stay; the clock runs.
    fn released(&self, client: &crate::client::Client, id: &str) {
        let mut state = self.state_of(client);
        // A `DELETE` naming something this credential does not hold changes nothing — including the
        // clock, which is the half that would matter: a stray goodbye must not extend a lease.
        if !state.mcp.remove(id) {
            return;
        }
        state.deadline = Some(Instant::now() + self.grace);
        // Only once it has let go of *every* MCP session it had. While it still holds one it has
        // not left, and telling its next request that it adopted what it left would be a sentence
        // about nothing.
        state.left_open = state.mcp.is_empty();
    }

    /// Whether this credential's lease has run out, **claiming the teardown** if so.
    ///
    /// The sessions are marked `releasing` under the same lock that reads the deadline, and stay
    /// that way until [`Self::released_leases`] says the teardown is done. That is what closes the
    /// window [`Sessions::release_leased`] warns it does not close itself: between deciding to
    /// release and having released, this credential cannot be admitted to the sessions being
    /// released.
    fn expired_for(&self, client: &crate::client::Client) -> Option<Expired> {
        let mut state = self.state_of(client);
        match state.deadline {
            Some(at) if Instant::now() >= at => {
                let mcp = std::mem::take(&mut state.mcp).into_iter().collect();
                // Consumed by the sweep that acts on it, so an expiry is reported once rather than
                // on every pass — a second report would release an already-released set.
                state.deadline = None;
                state.left_open = false;
                state.releasing = true;
                Some(Expired {
                    mcp,
                    revoked: state.revoked,
                })
            }
            _ => None,
        }
    }

    /// The clients this lease holds state for, so the sweeper can ask each in turn without holding
    /// the lock across an `await`.
    fn clients(&self) -> Vec<crate::client::Client> {
        self.all().keys().cloned().collect()
    }

    /// The teardown is done; this credential may open sessions again.
    fn released_leases(&self, client: &crate::client::Client) {
        self.state_of(client).releasing = false;
    }

    /// A client is **no longer configured**: expire its lease now.
    ///
    /// **A revocation is an expiry that does not wait**, and saying it that way is the whole design.
    /// The sweeper already releases an expired client's debug sessions, closes the MCP sessions it
    /// left resident and clears its state — the three steps a revocation needs, in that order, on a
    /// path that has been carrying live kernel targets since before this existed. So a revocation
    /// sets the clock to now instead of growing a second teardown beside it, and the sweeper picks
    /// it up on its next pass (at most [`SWEEP`] away).
    ///
    /// What the grace bought is not lost by skipping it, because it was never about this: a lease
    /// waits so that a client which merely went quiet can come back to what it left. A credential
    /// that has been taken out of the configuration is not coming back — the next request carrying
    /// it is a `401` — so there is nothing for a grace to protect.
    ///
    /// The teardown that follows is the sweeper's, not this command's, so nothing an operator waits
    /// on is behind a live kernel letting go.
    fn revoke(&self, client: &crate::client::Client) {
        let mut state = self.state_of(client);
        state.revoked = true;
        state.deadline = Some(Instant::now());
    }

    /// Drops a revoked client's entry entirely, once its teardown is done.
    ///
    /// **Not the same as [`Self::released_leases`]**, and the difference is what review found: that
    /// one clears the `releasing` flag and leaves the entry, which is right for a client that may
    /// come back. Lease state is keyed by client *name*, so an entry left behind is one a client
    /// re-added under the same name inherits — including MCP session ids belonging to whoever held
    /// that name before. A revoked name has to start from nothing.
    fn forget(&self, client: &crate::client::Client) {
        self.all().remove(client);
    }
}
/// How long to keep retrying a bind that fails because the address is not there yet.
///
/// Only reached by a **non-loopback** bind at boot: an auto-start service can be launched before
/// the adapter it names has been given its address, and a single attempt then fails the service
/// permanently — which quietly undoes the "starts at boot" that is half the reason to be a service.
/// Loopback is up before anything starts, so the ordinary configuration never waits here at all.
pub(crate) const BIND_PATIENCE: Duration = Duration::from_secs(90);
const BIND_RETRY_EVERY: Duration = Duration::from_secs(2);

/// Binds `addr`, waiting for the address to exist if it does not yet.
///
/// Retries only what is worth retrying. A port already in use, or one this process may not have, is
/// a configuration error that will not fix itself, and failing immediately says so while an
/// operator is still watching; an address that has not been assigned yet is the one condition that
/// resolves on its own.
async fn bind_when_ready(addr: SocketAddr) -> Result<TcpListener> {
    let deadline = Instant::now() + BIND_PATIENCE;
    let mut said_so = false;
    loop {
        match TcpListener::bind(addr).await {
            Ok(listener) => return Ok(listener),
            Err(e) if e.kind() == std::io::ErrorKind::AddrNotAvailable => {
                if Instant::now() >= deadline {
                    return Err(anyhow::Error::new(e)).with_context(|| {
                        format!("{addr} never appeared on this host within {BIND_PATIENCE:?}")
                    });
                }
                if !said_so {
                    tracing::info!("{addr} is not on this host yet; waiting for it to appear");
                    said_so = true;
                }
                tokio::time::sleep(BIND_RETRY_EVERY).await;
            }
            Err(e) => return Err(anyhow::Error::new(e).context(format!("cannot bind {addr}"))),
        }
    }
}

/// The credentials this listener accepts, from a file if one is named and from the environment
/// otherwise.
fn credentials() -> Result<crate::client::Credentials> {
    let creds = crate::client::Credentials::from_entries(std::env::vars(), token_file()?)?;
    if creds.len() == 0 {
        bail!(
            "neither {TOKEN_FILE_ENV} nor {TOKEN_ENV} is set, and no {TOKEN_ENV}_<NAME> either. \
             The listener will not start without a bearer token: it exposes every tool this server \
             has, including the ones that write to a live kernel."
        );
    }
    Ok(creds)
}

/// The credentials in the file [`TOKEN_FILE_ENV`] names, if it names one.
///
/// The read is here and the parse is in [`crate::client`], which is the same split every other
/// rule about who may connect follows — and it lets the file's two shapes be asserted without a
/// filesystem.
fn token_file() -> Result<Option<crate::client::TokenFile>> {
    let Some(path) = std::env::var_os(TOKEN_FILE_ENV) else {
        return Ok(None);
    };
    let path = std::path::PathBuf::from(path);
    let text = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "{TOKEN_FILE_ENV} names {}, which cannot be read",
            path.display()
        )
    })?;
    crate::client::TokenFile::parse(&text, &path).map(Some)
}

pub async fn serve(
    sessions: Sessions,
    addr: SocketAddr,
    call_timeout: Duration,
    tools: crate::toolset::Toolset,
    reload: Option<tokio::sync::mpsc::UnboundedReceiver<std::sync::mpsc::SyncSender<bool>>>,
    shutdown: impl Future<Output = ()>,
    ready: impl FnOnce(),
) -> Result<()> {
    let credentials = Arc::new(crate::client::Accepted::new(credentials()?));

    let grace = match std::env::var(GRACE_ENV).ok().and_then(|v| v.parse().ok()) {
        Some(secs) if secs > 0 => Duration::from_secs(secs),
        _ => longest_quiet_call(call_timeout) + GRACE_HEADROOM,
    };
    let lease = Arc::new(Lease::new(grace, call_timeout, sessions.clone())?);
    // Read before the bind, like the grace above: a misconfigured backstop should be a message at
    // startup rather than a target nobody releases, discovered hours later.
    let idle_after = idle_release(call_timeout)?;

    if !addr.ip().is_loopback() {
        // Not refused: a host-only adapter is a legitimate choice and this server does not know
        // which interface it was handed. Said out loud every time, because the cost of getting it
        // wrong is not this server's to pay.
        tracing::warn!(
            "listening on {addr}, which is not loopback — anything that can route to it can \
             reach every tool here with the token. Prefer binding loopback and forwarding \
             (`ssh -L`)."
        );
    }

    let manager = Arc::new(LocalSessionManager::default());
    let mcp = {
        let sessions = sessions.clone();
        let tools = tools.clone();
        Arc::new(StreamableHttpService::new(
            // **The one moment the caller is knowable.** rmcp builds a service instance per MCP
            // session — here, on the task handling that session's `initialize`, which
            // [`gate`] has scoped to the credential that authenticated — and then serves every
            // later call to that session from a task it spawned, where nothing of the request
            // remains. So the identity is read here and carried by the instance; see
            // `WindbgServer::client`. On the stateless revision there is no session and no spawn,
            // and this runs per request, which reaches the same answer by the shorter route.
            move || {
                Ok(
                    WindbgServer::for_client(sessions.clone(), crate::client::current())
                        // Server-wide, so every client on this listener sees the same surface.
                        // Per-caller is `FOLLOWUPS.md` item 36, and this is the line it changes.
                        .with_tools(tools.clone()),
                )
            },
            manager.clone(),
            // A tool call can be quiet for minutes; without a keep-alive the stream looks idle to
            // anything between the two machines and gets collected.
            StreamableHttpServerConfig::default().with_sse_keep_alive(Some(SSE_KEEP_ALIVE)),
        ))
    };

    // Pinned here rather than at the accept loop, because the bind is raced against it: a stop
    // arriving while a not-yet-assigned address is being waited for must be answered now, not in
    // ninety seconds' time. Without this the service would sit `Running` with no endpoint and no
    // way to be stopped, which is worse than the boot-time failure the retry exists to survive.
    let mut shutdown = std::pin::pin!(shutdown);
    let listener = tokio::select! {
        () = &mut shutdown => {
            tracing::info!("asked to stop before {addr} could be bound");
            return Ok(());
        }
        bound = bind_when_ready(addr) => bound?,
    };
    // There is an endpoint from here, and not before: a caller that reports itself started does it
    // *now*. See [`crate::service`], where "started" is a thing the SCM and its dependants act on.
    ready();
    tracing::info!(
        "windbg-mcp listening on http://{addr} (lease grace {grace:?}, {}, clients: {}, serving {})",
        match idle_after {
            Some(after) => format!("idle sessions released after {}m", after.as_secs() / 60),
            None => "idle sessions never released".to_string(),
        },
        credentials.names().join(", "),
        // Named here for the same reason the client list is: `--tools` adds the `session` group
        // whatever the spec said, so the surface a run ends up with is not always the one typed.
        tools.summary()
    );

    // Only under the service, which is the only role with a control channel to be asked on.
    //
    // **After the bind, and it was briefly moved before it on a premise that turned out to be
    // false.** The idea was to have something ready to answer a command issued while a slow
    // non-loopback bind held the service in `StartPending` — but the SCM will not deliver a control
    // code to a service in that state at all (`ERROR_SERVICE_CANNOT_ACCEPT_CTRL`, measured), so
    // there was never a request to answer. The only gap left is between the service reporting
    // itself started and this line, which is a `spawn` away and covered anyway: the channel is
    // unbounded, so the handler's send lands and its wait is answered as soon as this task runs.
    if let Some(asked) = reload {
        tokio::spawn(reloaded(
            asked,
            Arc::clone(&credentials),
            sessions.clone(),
            lease.clone(),
        ));
    }

    tokio::spawn(sweep(
        sessions.clone(),
        lease.clone(),
        manager.clone(),
        idle_after,
    ));

    loop {
        let (stream, peer) = tokio::select! {
            // Asked to stop. Returning here is the whole mechanism: the caller's `shutdown` on
            // `Sessions` runs next, and that is what releases a live kernel rather than leaving it
            // frozen. Connections already in flight are dropped — a client mid-call loses that
            // call, which is the lesser of the two, and its session is being released anyway.
            () = &mut shutdown => {
                tracing::info!("no longer accepting connections on {addr}");
                return Ok(());
            }
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(e) => {
                    tracing::warn!("accept failed: {e}");
                    continue;
                }
            },
        };
        let mcp = mcp.clone();
        let lease = lease.clone();
        let credentials = Arc::clone(&credentials);
        tokio::spawn(async move {
            let serve = service_fn(move |req| {
                gate(
                    req,
                    mcp.clone(),
                    lease.clone(),
                    Arc::clone(&credentials),
                    peer,
                )
            });
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), serve)
                .await
            {
                tracing::debug!("connection from {peer} ended: {e}");
            }
        });
    }
}

/// Authenticates, renews the lease, and only then hands the request to MCP.
async fn gate(
    req: Request<Incoming>,
    mcp: Arc<StreamableHttpService<WindbgServer, LocalSessionManager>>,
    lease: Arc<Lease>,
    credentials: Arc<crate::client::Accepted>,
    peer: SocketAddr,
) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
    let Some(caller) = authorised(&req, &credentials) else {
        // No detail: an unauthenticated caller learns that it is unauthenticated and nothing about
        // what is here — including how many credentials this listener holds.
        tracing::warn!("rejected an unauthenticated request from {peer}");
        return Ok(refuse(StatusCode::UNAUTHORIZED, "unauthorized"));
    };

    let session = req
        .headers()
        .get(SESSION_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    match lease.admit(&caller, session.as_deref()) {
        Admission::Serve => {}
        // Not a refusal — an id this caller cannot have is an id this server does not have. The
        // status is the one the spec already gives a session that has gone: a client holding a
        // stale id of its own is told to start again, which is also the right advice here.
        Admission::NotYours => {
            tracing::warn!(
                "refused a request from {peer} carrying an MCP session id another client holds"
            );
            return Ok(refuse(StatusCode::NOT_FOUND, "unknown session"));
        }
        // The sweeper is letting this credential's own sessions go. Transient, and the fix is to
        // ask again rather than to change anything. The only `409` this server has left, now that
        // nothing refuses a credential a second MCP session.
        Admission::Releasing => {
            tracing::warn!(
                "refused a request from {peer}: this credential's expired sessions are still \
                 being released"
            );
            return Ok(refuse(
                StatusCode::CONFLICT,
                "this credential's previous sessions are still being released after its lease ran \
                 out; ask again in a moment",
            ));
        }
    }

    // A DELETE is the client saying it is done. Read before the service handles it, because
    // afterwards the request is gone; whether it *was* a departure also depends on the answer.
    let method = req.method().clone();

    // The whole MCP call runs as this client: the routing, the worker handshake and the engine
    // call all read the identity from here, rather than from a parameter forty-odd tool bodies
    // would have to carry. See [`crate::client`].
    // Kept for the settlement below, which records whose lease this is — the scope moves the
    // identity into the call.
    let caller_for_lease = caller.clone();
    let response = crate::client::as_client(caller, mcp.handle(req)).await;

    let minted = response
        .headers()
        .get(SESSION_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    // Counted rather than asserted. An adoption says a previous MCP session of this credential's
    // ended inside the grace, which is true whether or not it had opened anything — so the
    // unconditional version of this line told an operator a client had adopted sessions that did
    // not exist, on every ordinary reconnect.
    if lease.settle(
        session.as_deref(),
        minted.as_deref(),
        response.status().is_success(),
        &caller_for_lease,
    ) {
        // Asked *for* this client rather than as it. The call's identity scope has closed by here,
        // so anything reading the ambient one would count `local`'s sessions — nobody's, for a
        // named client, which is the reconnect this line exists to describe.
        match lease.sessions.live_count_for(&caller_for_lease) {
            0 => tracing::info!(
                "a client came back to a session this credential had let go; nothing was open"
            ),
            inherited => tracing::info!(
                "a client came back and adopted the {inherited} session(s) it had left open"
            ),
        }
    }
    if is_departure(&method, response.status())
        && let Some(id) = session
    {
        lease.released(&caller_for_lease, &id);
        tracing::info!("the client let go; its sessions are held for the grace period");
    }
    Ok(response)
}

/// Whether this request was a client actually leaving.
///
/// A `DELETE` is the client saying it is done — **if the service agreed**. rmcp refuses one that
/// carries an invalid protocol version, and a refused `DELETE` leaves the MCP session open. Taking
/// it as a departure anyway forgets that session, so the sweep that would have closed it never
/// hears of it: it survives with nothing owning it and nothing that will ever collect it, one per
/// failed attempt ([#136](https://github.com/glslang/windbg-mcp/issues/136)).
///
/// A predicate rather than a condition inline, because it is the one lease rule that lives in the
/// HTTP handler rather than in [`Lease`] — and so the one that had no test until it had a name.
fn is_departure(method: &hyper::Method, status: StatusCode) -> bool {
    method == hyper::Method::DELETE && status.is_success()
}

/// The client whose token this request presented, or `None` if it presented none this listener
/// knows.
///
/// The credential *is* the identity — see [`crate::client`] for why nothing else can be, on a
/// transport whose protocol no longer has sessions in it.
fn authorised(
    req: &Request<Incoming>,
    credentials: &crate::client::Accepted,
) -> Option<crate::client::Client> {
    req.headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .and_then(|presented| credentials.client_for(presented))
}

fn refuse(status: StatusCode, why: &str) -> Response<BoxBody<Bytes, Infallible>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::from(why.to_string())).boxed())
        // The builder only fails on a malformed status or header, and both are literals here.
        .expect("a constant response is well-formed")
}

/// Re-reads the credential file whenever the service is asked to, and says what changed.
///
/// **The other half of the client commands** (`FOLLOWUPS.md` item 34). Without it,
/// `--add-listen-client` writes a file nothing reads until the next start — and a *restart* drops
/// every session the service holds, which is most of what made the reinstall it replaces
/// unfriendly. So the commands would be an improvement in ergonomics and not in outcome.
///
/// **A failed read changes nothing.** [`credentials`] refuses a file it cannot parse and one that
/// names nobody, and neither of those may become a listener that has forgotten who may connect: an
/// operator with a typo in a file gets a loud log line and a service still serving its old set,
/// rather than every client locked out of a live kernel target. The set is only ever replaced by
/// one that would have started this listener from cold.
///
/// **Everything here is instant, and that is deliberate.** Reading a file, swapping a pointer and
/// setting two flags — no `await` between the request and the answer. The command that asked is
/// holding the SCM's control handler open until this replies, and releasing a revoked client's
/// targets takes as long as a live kernel takes to let go: doing it here would time that
/// acknowledgement out, and for a `--remove` or `--rotate` that reads as a *failed revocation*,
/// since neither can tell "not applied yet" from "not applied" (review on #189). The teardown is
/// [`sweep`]'s, which was already releasing expired clients' targets before this existed.
///
/// Ends when the sender is dropped, which is the service's runtime going away.
async fn reloaded(
    mut asked: tokio::sync::mpsc::UnboundedReceiver<std::sync::mpsc::SyncSender<bool>>,
    accepted: Arc<crate::client::Accepted>,
    sessions: Sessions,
    lease: Arc<Lease>,
) {
    while let Some(answer) = asked.recv().await {
        // The same function that decided whether this listener could start at all, and
        // deliberately so: a set that would not have started it does not get to replace the one
        // that did.
        let fresh = match credentials() {
            Ok(fresh) => fresh,
            Err(e) => {
                tracing::error!(
                    "asked to re-read the clients, and could not ({e:#}) — still serving the {} \
                     this listener already had",
                    accepted.names().len()
                );
                // Told, rather than left to time out: the command that asked prints what happened,
                // and "it would not have that file" is the useful half of it.
                let _ = answer.send(false);
                continue;
            }
        };
        let change = accepted.replace(fresh);
        for gone in &change.removed {
            // **The gate closes before the answer goes out**, because a revocation has a window a
            // lease expiry does not. An expiry only fires after the client has been silent for
            // longer than any call can keep it quiet, so nothing of that credential's can still be
            // in flight; here the token stops being accepted at the swap above, but a call that got
            // past authentication a moment earlier is still running and an opener can be seconds
            // from registering, so the sweep below cannot see it.
            //
            // **Never lifted, and it no longer needs to be.** It marks this incarnation, not this
            // name, so a client configured under the same name later is not gated by it — which is
            // what the whole of [#190](https://github.com/glslang/windbg-mcp/issues/190) bought,
            // and it deleted the question of when to take a gate off, which was where two separate
            // findings lived. What is left behind is one name and a `u64` per revocation.
            sessions.revoke(gone);
            // And the clock to now, which is all a revocation is: the sweeper does the rest.
            lease.revoke(gone);
        }
        // **Answered once the swap and the gates are done** — which is exactly what the asking
        // command claims when it returns, and all of it is memory.
        let _ = answer.send(true);
        tracing::info!(
            "re-read the clients: {}",
            match change.is_empty() {
                // A rotation, which changes a token and no name. Worth a line of its own: from
                // out here it looks like nothing happened, and the client whose token moved is
                // about to start failing to authenticate with the old one.
                true => "the same clients, one or more of which may now present a different token"
                    .to_string(),
                false => format!(
                    "added [{}], removed [{}]",
                    crate::client::Change::names(&change.added),
                    crate::client::Change::names(&change.removed)
                ),
            }
        );
    }
}

/// Releases what an absent client left behind, once its lease runs out.
async fn sweep(
    sessions: Sessions,
    lease: Arc<Lease>,
    manager: Arc<LocalSessionManager>,
    idle_after: Option<Duration>,
) {
    loop {
        tokio::time::sleep(SWEEP).await;
        // Independent of the lease, and checked first, because it is the half that covers a
        // `2026-07-28` client: a lease is armed by an MCP session, and that revision has none. See
        // [`IDLE_RELEASE`].
        if let Some(after) = idle_after {
            sessions.release_idle(after).await;
        }
        // Per client, because a lease is per client: one caller's expiry says nothing about
        // another's, and a sweep that stopped at the first would starve the rest.
        for client in lease.clients() {
            let Some(expired) = lease.expired_for(&client) else {
                continue;
            };
            tracing::info!(
                "the lease of client `{client}` ran out; releasing the sessions it left open"
            );
            // **That client's sessions, not every session.** Before ownership this was the same
            // set, because the gate served one client at a time. It is not any more: another
            // client's targets are in the same registry, and this expiry says nothing about them
            // (#162).
            sessions.release_leased(&client).await;
            // The debug sessions are the expensive half, but not the whole of it. A client that
            // vanished never sent the DELETEs that close its MCP sessions, so without this the
            // service keeps them resident and their ids accepted — and every
            // disconnect-and-reconnect cycle would add another one no lease will ever sweep again.
            for id in expired.mcp {
                if let Err(e) = manager.close_session(&id.into()).await {
                    tracing::warn!(
                        "could not close the MCP session of the client that went away: {e}"
                    );
                }
            }
            if expired.revoked {
                // **A revocation ends differently, and this is the only place that has to know.**
                // The entry goes rather than being cleared, because lease state is keyed by name: a
                // client re-added under this one must not inherit the ids of whoever held it
                // before.
                //
                // The admission gate is **not** lifted here, and that is the point of it. This
                // release is one pass over a snapshot, so a revoked credential's opener that had
                // authenticated but not yet registered is invisible to it — an `attach_kernel` is
                // seconds of worker spawn and link wait away from registering — and lifting on
                // "nothing left to release" would let that opener register a target owned by a
                // credential nothing can authenticate as, stranded until the process ends
                // ([#189](https://github.com/glslang/windbg-mcp/pull/189) review). The gate comes
                // off when the *name is given back*, in [`reloaded`], because that is the event
                // that needs it off; until then it stays shut however long the opener takes.
                lease.forget(&client);
            } else {
                // Only now may this client be admitted again: until here, an arriving request would
                // be let in to sessions this release is closing.
                lease.released_leases(&client);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A lease bound to one client, so the rules below read exactly as they did when there was one
    /// lease for the whole server.
    ///
    /// Every test here is about how *a* credential's lease behaves — what it records, what renews
    /// it, what it adopts, what a goodbye and an expiry do to it — and none of them is about which
    /// client it is. Binding the name once keeps that distinction visible: a test that needs two
    /// clients says so by using two of these, or by reaching for the lease directly.
    struct For {
        lease: Lease,
        client: crate::client::Client,
    }

    impl For {
        fn new(lease: Lease, name: &str) -> Self {
            Self {
                lease,
                client: crate::client::Client::new(name),
            }
        }

        fn admit(&self, session: Option<&str>) -> Admission {
            self.lease.admit(&self.client, session)
        }

        fn settle(&self, requested: Option<&str>, minted: Option<&str>, ok: bool) -> bool {
            self.lease.settle(requested, minted, ok, &self.client)
        }

        fn released(&self, id: &str) {
            self.lease.released(&self.client, id);
        }

        fn expired(&self) -> Option<Expired> {
            self.lease.expired_for(&self.client)
        }

        fn released_leases(&self) {
            self.lease.released_leases(&self.client);
        }

        fn revoke(&self) {
            self.lease.revoke(&self.client);
        }

        fn forget(&self) {
            self.lease.forget(&self.client);
        }

        fn state(&self) -> PresenceGuard<'_> {
            self.lease.state_of(&self.client)
        }
    }

    const CALL: Duration = Duration::from_secs(300);

    /// A grace comfortably past the opener's end-to-end bound.
    fn lease() -> For {
        For::new(
            Lease::new(
                longest_quiet_call(CALL) + Duration::from_secs(60),
                CALL,
                Sessions::new(CALL),
            )
            .expect("workable"),
            crate::client::Client::LOCAL,
        )
    }

    /// A lease whose grace expires almost immediately, for the sweep paths.
    fn brief() -> For {
        For::new(
            unchecked(Duration::from_millis(1)),
            crate::client::Client::LOCAL,
        )
    }

    /// A lease with a grace [`Lease::new`] would refuse, for the tests that have to wait one out.
    fn unchecked(grace: Duration) -> Lease {
        Lease {
            grace,
            sessions: Sessions::new(CALL),
            state: Mutex::new(HashMap::new()),
        }
    }

    /// The floor is the same one the lease refuses to start below, and for the same reason: a
    /// single call can keep a session quiet for its whole budget, so a release shorter than that
    /// ends a session while its own caller is still waiting on it.
    #[test]
    fn an_idle_release_shorter_than_a_call_is_refused() {
        let too_short = (longest_quiet_call(CALL) - Duration::from_secs(1))
            .as_secs()
            .to_string();
        let why = idle_release_from(Some(&too_short), CALL)
            .expect_err("a release inside the call budget must be refused");
        assert!(
            why.to_string().contains(IDLE_ENV),
            "the message has to name the variable to change: {why}"
        );
    }

    /// Zero is a supported answer — a host where every client hangs up properly — and it disables
    /// the backstop rather than failing.
    #[test]
    fn zero_disables_the_idle_release() {
        assert_eq!(
            idle_release_from(Some("0"), CALL).expect("zero is allowed"),
            None
        );
    }

    /// And an unconfigured host gets a default that clears the floor, so it starts.
    #[test]
    fn the_default_idle_release_clears_the_floor() {
        assert_eq!(
            idle_release_from(None, CALL).expect("the default has to be workable"),
            Some(IDLE_RELEASE)
        );
    }

    /// A value that is not seconds is refused by name rather than silently taking the default.
    #[test]
    fn an_unparseable_idle_release_is_refused() {
        let why = idle_release_from(Some("half an hour"), CALL).expect_err("not a number");
        assert!(why.to_string().contains(IDLE_ENV), "{why}");
    }

    /// A request the listener served, asserting it was not one of the two it refuses.
    fn served(admission: Admission) {
        assert_eq!(
            admission,
            Admission::Serve,
            "the listener refused a request this test needed served"
        );
    }

    /// One whole request: admitted, then settled with whatever the service made of it. Returns
    /// whether it adopted sessions a previous MCP session of that credential's left open.
    fn request(lease: &For, session: Option<&str>, minted: Option<&str>, ok: bool) -> bool {
        served(lease.admit(session));
        lease.settle(session, minted, ok)
    }

    /// A client's `DELETE`, which is itself an admitted request.
    fn goodbye(lease: &For, id: &str) {
        served(lease.admit(Some(id)));
        lease.released(id);
    }

    /// The check that stops a long call from looking like an absent client.
    ///
    /// The floor is not the call budget: an opener spends up to `WORKER_READY_TIMEOUT` bringing a
    /// worker up *before* that budget starts, so a grace one second past the budget still leaves an
    /// attach running when the sweeper comes for it.
    #[test]
    fn a_grace_that_could_expire_inside_a_call_is_refused_at_startup() {
        assert!(
            Lease::new(Duration::from_secs(120), CALL, Sessions::new(CALL)).is_err(),
            "well under the budget"
        );
        assert!(
            Lease::new(CALL + Duration::from_secs(1), CALL, Sessions::new(CALL)).is_err(),
            "past the call budget but not past the worker handshake in front of it — the case that \
             looks safe and is not"
        );
        assert!(
            Lease::new(longest_quiet_call(CALL), CALL, Sessions::new(CALL)).is_err(),
            "equal is not enough: the call may finish at its deadline, not before it"
        );
        assert!(
            Lease::new(
                longest_quiet_call(CALL) + Duration::from_secs(1),
                CALL,
                Sessions::new(CALL)
            )
            .is_ok()
        );
    }

    /// **Two requests of one credential are both served**, whatever shape they arrive in.
    ///
    /// This is what retiring the gate means, and it is the property the gate's last remaining job
    /// was the negation of. Two overlapping requests with no session id used to be a `409`: the
    /// absence of an id was read as a client opening one, so each reserved the server, and on
    /// `2026-07-28` — where there is never an id to carry — that was *every* request. At its
    /// sharpest a kernel attach whose target never dialled in locked its own credential out of
    /// `session_status` and `end_session`, the two calls that recover it
    /// ([#168](https://github.com/glslang/windbg-mcp/issues/168)).
    ///
    /// The second half is the one that used to be arguable: a second `initialize` from a credential
    /// that already holds an MCP session, and a request bearing an id that is not the one it holds.
    /// Inside a namespace neither is a boundary — both reach the same debug sessions, because they
    /// are the same client.
    #[test]
    fn two_requests_from_one_credential_are_both_served() {
        let lease = lease();

        // Neither of these has finished when the other arrives; the parked case is exactly this.
        served(lease.admit(None));
        served(lease.admit(None));

        request(&lease, None, Some("session-a"), true);
        served(lease.admit(None));
        served(lease.admit(Some("session-b")));
        served(lease.admit(Some("session-a")));
    }

    /// And a credential's second MCP session is recorded beside the first, not instead of it.
    ///
    /// The set is not tidiness. An id that is recorded for nobody is one *any* credential may
    /// present, so keeping only the newest would hand a client another's older session id the
    /// moment that client opened a second one — which is the harm [`Admission::NotYours`] exists to
    /// stop, arriving through the change that removed the refusal in front of it.
    #[test]
    fn a_second_mcp_session_for_one_credential_joins_the_first() {
        let lease = lease();
        request(&lease, None, Some("session-a"), true);
        request(&lease, None, Some("session-b"), true);

        let held = lease.state();
        assert!(
            held.mcp.contains("session-a") && held.mcp.contains("session-b"),
            "both of this credential's MCP sessions have to stay recorded: {:?}",
            held.mcp
        );
    }

    /// **Every admitted request renews an existing lease, and creates none.**
    ///
    /// Both halves are the same rule seen from two sides, and getting either wrong loses a client
    /// sessions it was using. A credential can hold a legacy session and *then* start sending
    /// requests with no id — a client that upgraded, or restarted inside the grace — and since the
    /// sweep reads the deadline and nothing else, a request that did not renew would have those
    /// sessions released out from under it while it was using them. The other way costs as much: a
    /// deadline installed for a credential that holds nothing is a lease against nothing, and it
    /// would release every session a `2026-07-28` client has, one grace after its first call.
    #[test]
    fn every_admitted_request_renews_an_existing_lease_and_creates_none() {
        let lease = lease();

        // Nothing held: no request of any shape may hand this credential a clock to run out.
        served(lease.admit(None));
        assert_eq!(
            lease.state().deadline,
            None,
            "a request that holds nothing must not be given a clock to run out"
        );
        served(lease.admit(Some("session-nobodys")));
        assert_eq!(
            lease.state().deadline,
            None,
            "nor does presenting an id no credential here records"
        );

        // A legacy session, and then the same credential sending a request with no id at all.
        request(&lease, None, Some("session-a"), true);
        let before = lease
            .state()
            .deadline
            .expect("a credential that holds a session has a deadline");

        std::thread::sleep(Duration::from_millis(5));
        served(lease.admit(None));
        let after = lease
            .state()
            .deadline
            .expect("the lease is still this credential's");
        assert!(
            after > before,
            "a request from a credential that holds a session must renew its lease, whatever \
             revision it is on"
        );
    }

    /// A request the listener **refused** renews nothing.
    ///
    /// The qualifier on the rule above is load-bearing in both directions. A credential that is
    /// plainly alive must not be swept mid-call — and a refused request must not renew, or a stream
    /// of wrong session ids would hold an abandoned client's live kernel target open for ever,
    /// which is the failure the sweep exists to prevent.
    #[test]
    fn a_refused_request_renews_nothing() {
        // One lease and two clients, so `NotYours` is reachable at all.
        let lease = Lease::new(
            longest_quiet_call(CALL) + Duration::from_secs(60),
            CALL,
            Sessions::new(CALL),
        )
        .expect("workable");
        let laptop = crate::client::Client::new("laptop");
        let ci = crate::client::Client::new("ci");
        for (client, id) in [(&laptop, "session-laptop"), (&ci, "session-ci")] {
            served(lease.admit(client, None));
            lease.settle(None, Some(id), true, client);
        }

        let before = lease
            .state_of(&ci)
            .deadline
            .expect("a credential that holds a session has a deadline");
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(
            lease.admit(&ci, Some("session-laptop")),
            Admission::NotYours
        );
        assert_eq!(
            lease.state_of(&ci).deadline,
            Some(before),
            "a refused request renewed the lease of the credential that sent it"
        );

        // And the same for a teardown's refusal, which is the other early return.
        let releasing = For::new(unchecked(Duration::from_millis(1)), "laptop");
        request(&releasing, None, Some("session-a"), true);
        std::thread::sleep(Duration::from_millis(5));
        assert!(releasing.expired().is_some());
        assert_eq!(releasing.admit(None), Admission::Releasing);
        assert_eq!(
            releasing.state().deadline,
            None,
            "a refusal must not arm a clock either"
        );
    }

    /// **Nothing arms a clock before an MCP session exists**, which is the trap the reservation
    /// took with it.
    ///
    /// A `2026-07-28` `initialize` may omit the `MCP-Protocol-Version` header — it is the request
    /// that establishes the revision — so it arrives looking like any other request and mints
    /// nothing at all. Reserving armed a deadline on arrival, and one that took nothing had to hand
    /// that deadline back or it would start a teardown one grace later against a credential holding
    /// nothing, release whatever it had since opened, and refuse its next request while it was
    /// working normally. There is no arrival-time deadline to hand back any more; this pins that it
    /// stays that way.
    #[test]
    fn nothing_arms_a_clock_before_an_mcp_session_exists() {
        let lease = lease();

        served(lease.admit(None));
        assert!(!lease.settle(None, None, true));

        assert_eq!(
            lease.state().deadline,
            None,
            "a request that took nothing must not leave a clock running against a credential that \
             holds nothing"
        );
        assert!(
            lease.expired().is_none(),
            "and so there is nothing for the sweep to act on"
        );
    }

    /// An id the service rejected is not recorded as this credential's.
    ///
    /// A returning client presents the id it left with, and only the service knows whether that
    /// session is still there. Recording one it rejected would arm a clock over an id nothing
    /// backs — and claim it for a credential that cannot use it, which is enough to refuse the
    /// client that can.
    #[test]
    fn an_id_the_service_rejected_is_not_recorded_as_this_credentials() {
        let lease = lease();

        served(lease.admit(Some("session-a")));
        assert!(!lease.settle(Some("session-a"), None, false));
        assert!(
            lease.state().mcp.is_empty(),
            "a session id the service rejected must not be recorded: {:?}",
            lease.state().mcp
        );
        assert_eq!(lease.state().deadline, None, "and starts no clock");

        served(lease.admit(Some("session-a")));
        assert!(!lease.settle(Some("session-a"), None, true));
        assert!(
            lease.state().mcp.contains("session-a"),
            "whereas one it honoured is this credential's"
        );
        assert!(lease.state().deadline.is_some());
    }

    /// A returning client finds what it left, and is told that is what happened.
    #[test]
    fn a_client_returning_inside_the_grace_adopts_rather_than_starts_fresh() {
        let lease = lease();
        assert!(
            !request(&lease, None, Some("session-a"), true),
            "the first MCP session adopts nothing — there was nothing open"
        );

        goodbye(&lease, "session-a");
        assert!(
            request(&lease, None, Some("session-b"), true),
            "the next one is told it inherited the sessions still open"
        );
        assert!(
            !request(&lease, Some("session-b"), None, true),
            "and told once: every later request of that MCP session is ordinary work, not another \
             adoption"
        );
    }

    /// Letting go is not the same as expiring: the sessions are still there to come back to.
    #[test]
    fn letting_go_starts_the_clock_rather_than_releasing_anything() {
        let lease = lease();
        request(&lease, None, Some("session-a"), true);
        goodbye(&lease, "session-a");

        assert!(
            lease.state().mcp.is_empty(),
            "the MCP session went with the DELETE that closed it"
        );
        assert!(
            lease.expired().is_none(),
            "a client that said goodbye has its whole grace to change its mind"
        );
        assert!(lease.state().deadline.is_some(), "and the clock is running");
        assert!(
            lease.state().left_open,
            "with whatever it opened waiting to be adopted"
        );
    }

    /// A goodbye naming something this credential does not hold changes nothing — the clock
    /// included.
    #[test]
    fn a_goodbye_for_a_session_this_credential_does_not_hold_changes_nothing() {
        let lease = lease();
        request(&lease, None, Some("session-a"), true);
        let before = lease.state().deadline.expect("the lease is running");

        std::thread::sleep(Duration::from_millis(5));
        lease.released("session-b");
        assert!(
            lease.state().mcp.contains("session-a"),
            "a stray DELETE must not forget a session this credential still holds"
        );
        assert_eq!(
            lease.state().deadline,
            Some(before),
            "nor extend its lease, which is the half a client could otherwise do for ever"
        );
        assert!(!lease.state().left_open);
    }

    /// Only a `DELETE` the service accepted is a departure.
    ///
    /// A refused one leaves the MCP session open. Recording the client as gone then forgets that
    /// session, so the sweep that would have closed it never hears of it — and it survives with
    /// nothing owning it and nothing that will ever collect it (#136).
    #[test]
    fn only_an_accepted_delete_is_a_departure() {
        use hyper::Method;

        assert!(is_departure(&Method::DELETE, StatusCode::OK));
        assert!(
            is_departure(&Method::DELETE, StatusCode::ACCEPTED),
            "202 is what the service actually answers a DELETE with"
        );

        assert!(
            !is_departure(&Method::DELETE, StatusCode::BAD_REQUEST),
            "a DELETE the service refused left the session open, so the client has not left"
        );
        assert!(!is_departure(&Method::DELETE, StatusCode::NOT_FOUND));
        assert!(
            !is_departure(&Method::POST, StatusCode::OK),
            "and no other method is a goodbye, however well it went"
        );
    }

    /// An MCP session id is one client's, and presenting another's is not a way in.
    ///
    /// The service keeps one session table for the whole server, so the id is the only thing
    /// standing between a client and another's MCP session — and a `DELETE` on it closes that
    /// session while its owner still believes it has one, which leaves that client failing every
    /// request it sends. One authenticated client denying another is the harm ownership exists to
    /// stop, so this is checked before the caller's own lease is consulted at all.
    ///
    /// One lease and two clients, deliberately: two `For` bindings would be two leases, which
    /// cannot reach each other whatever the code does.
    #[test]
    fn one_clients_session_id_is_not_a_way_into_anothers() {
        let lease = Lease::new(
            longest_quiet_call(CALL) + Duration::from_secs(60),
            CALL,
            Sessions::new(CALL),
        )
        .expect("workable");
        let laptop = crate::client::Client::new("laptop");
        let ci = crate::client::Client::new("ci");

        served(lease.admit(&laptop, None));
        lease.settle(None, Some("session-laptop"), true, &laptop);

        assert_eq!(
            lease.admit(&ci, Some("session-laptop")),
            Admission::NotYours,
            "another client's session id was admitted, so its owner could be deleted out from \
             under it"
        );
        // And the owner is unaffected — the check must not cost a client its own session.
        served(lease.admit(&laptop, Some("session-laptop")));
        // An id nobody records is not owned by anybody: a client resuming inside the grace has to
        // get through, which is the case this check sits in front of.
        served(lease.admit(&ci, Some("session-nobodys")));
    }

    /// One client's teardown does not refuse another's requests.
    ///
    /// The gate is gone, so the only thing left that can refuse an authenticated client is its own
    /// release — and it has to stay its own. A shared version would mean one client's expiry
    /// stopping every other client for a boundary the registry already provides
    /// ([#162](https://github.com/glslang/windbg-mcp/issues/162)).
    ///
    /// Deliberately *not* written with the `For` binding: two bindings would be two leases, which
    /// cannot interfere whatever the code does, and the test would pass against the bug it is for.
    #[test]
    fn one_clients_release_does_not_refuse_another() {
        let lease = unchecked(Duration::from_millis(1));
        let laptop = crate::client::Client::new("laptop");
        let ci = crate::client::Client::new("ci");

        served(lease.admit(&laptop, None));
        lease.settle(None, Some("session-laptop"), true, &laptop);
        std::thread::sleep(Duration::from_millis(5));

        assert!(lease.expired_for(&laptop).is_some(), "the grace is spent");
        assert_eq!(lease.admit(&laptop, None), Admission::Releasing);
        served(lease.admit(&ci, None));
    }

    /// Nothing of this credential's is admitted between deciding to release and having released.
    #[test]
    fn nothing_is_admitted_while_the_teardown_runs() {
        let lease = brief();
        request(&lease, None, Some("session-a"), true);
        std::thread::sleep(Duration::from_millis(5));

        assert!(lease.expired().is_some(), "the grace is spent");
        assert_eq!(
            lease.admit(None),
            Admission::Releasing,
            "the sessions are still being let go, and saying so is not the same as saying this \
             credential holds one"
        );
        assert_eq!(
            lease.admit(Some("session-a")),
            Admission::Releasing,
            "whatever the request presents: what is being released is the sessions behind it"
        );

        lease.released_leases();
        served(lease.admit(None));
    }

    /// Expiry is a one-shot: the deadline is consumed by the sweep that acts on it.
    #[test]
    fn expiry_is_reported_once_rather_than_on_every_sweep() {
        let lease = brief();
        request(&lease, None, Some("session-a"), true);
        std::thread::sleep(Duration::from_millis(5));

        assert!(lease.expired().is_some(), "the grace is spent");
        assert!(
            lease.expired().is_none(),
            "and expiry is reported once, not on every sweep — a second report would release an \
             already-released set of sessions on each pass"
        );
        assert!(lease.state().mcp.is_empty());
    }

    /// A revocation is an expiry that does not wait, and the sweeper is told which one it swept.
    ///
    /// Three things, and each one is a failure that shows up only much later. Waiting out the grace
    /// would leave a removed credential's sessions live for as long as it lasts — a grace is there
    /// so a client that went *quiet* can come back to what it left, and a revoked one is never
    /// coming back. The sessions have to come back from the sweep, or nothing ever closes them. And
    /// the `revoked` flag has to travel with them, because it is what tells the sweeper to forget
    /// the entry rather than clear it: lease state is keyed by client *name*, so an entry left
    /// behind is one a client re-added under that name would inherit, session ids and all.
    #[test]
    fn revoking_a_client_expires_it_now_and_says_so_to_the_sweeper() {
        let lease = For::new(unchecked(Duration::from_secs(300)), "ci");
        request(&lease, None, Some("session-a"), true);
        request(&lease, None, Some("session-b"), true);
        // Deliberately *not* expired: the grace is the full one and no time has passed.
        assert!(
            lease.expired().is_none(),
            "this client's lease has not run out — the point is that a revocation does not wait"
        );

        lease.revoke();
        let swept = lease
            .expired()
            .expect("a revoked client is expired now, not one grace later");
        assert_eq!(
            swept.mcp,
            vec!["session-a".to_string(), "session-b".to_string()],
            "a revoked client's MCP sessions have to come back, or nothing ever closes them"
        );
        assert!(
            swept.revoked,
            "the sweeper cannot tell which ending to use unless the expiry says which kind it was"
        );

        lease.forget();
        // Asking for the state again is exactly what a client re-added under this name does:
        // `state_of` creates the entry it does not find. It has to find nothing.
        let state = lease.state();
        assert!(
            state.mcp.is_empty() && !state.releasing && !state.revoked,
            "a name re-added after a revocation inherited the entry of whoever held it before"
        );
    }

    /// A name given back reaches none of its predecessor's lease, and does not wait to be served.
    ///
    /// **Both halves changed when a client stopped being a name**
    /// ([#190](https://github.com/glslang/windbg-mcp/issues/190)). While it was one,
    /// `--remove-listen-client ci` then `--add-listen-client ci` produced two credentials that this
    /// map could not tell apart, so the new one had to be held at a `409` until the sweep forgot the
    /// entry — a refusal that existed only because the key was ambiguous. It is a different
    /// [`crate::client::Client`] now, so it arrives at a `Presence` of its own: served at once, and
    /// with nothing of its predecessor's in reach.
    ///
    /// What has *not* changed is the second half, and it is the one with teeth. A request already
    /// inside the MCP service when the set was swapped still settles against the **old** client, and
    /// renewing there would push the revocation's deadline a whole grace out — so the sweep that was
    /// to run on its next pass would not, and that credential's targets would stay live for another
    /// six minutes. An incarnation does not help with that: it is the same client, arriving late.
    #[test]
    fn a_name_given_back_is_a_different_lease_and_waits_for_nothing() {
        let grace = Duration::from_secs(300);
        let lease = For::new(unchecked(grace), "ci");
        request(&lease, None, Some("session-a"), true);
        lease.revoke();

        // The in-flight request of the *revoked* credential. It may record its MCP session, so the
        // sweep closes that too, but it must not move the clock.
        let deadline = lease.state().deadline;
        lease.settle(None, Some("session-b"), true);
        assert_eq!(
            lease.state().deadline,
            deadline,
            "a request settling after the revocation renewed its lease, so the sweep never fires"
        );
        assert!(
            lease.state().mcp.contains("session-b"),
            "an MCP session minted for a revoked credential is one nothing else will ever close"
        );

        // The name, given back: same `Lease`, same name, different client.
        let given_back = crate::client::Client::incarnate("ci", 2);
        assert_eq!(
            lease.lease.admit(&given_back, None),
            Admission::Serve,
            "a client configured under a revoked name was made to wait for a teardown that is not \
             its own"
        );
        assert!(
            lease.lease.state_of(&given_back).mcp.is_empty(),
            "it inherited the MCP session ids of whoever held that name before"
        );
        assert_eq!(
            lease.lease.state_of(&given_back).deadline,
            None,
            "it inherited a clock that was set for its predecessor's revocation"
        );

        // And the incarnation that *was* revoked is still refused — a separate property from the
        // one above, and one briefly lost in gaining it: a request of its own that authenticated in
        // the moment before the swap must not be served afterwards.
        assert_eq!(
            lease.admit(None),
            Admission::Releasing,
            "the revoked credential was served after its removal had been reported complete"
        );
    }

    /// A swept lease says what it left in the service, so the sweeper can close that too.
    #[test]
    fn a_swept_lease_reports_the_sessions_that_never_said_goodbye() {
        let lease = brief();
        request(&lease, None, Some("session-a"), true);
        request(&lease, None, Some("session-b"), true);
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(
            lease.expired().map(|e| e.mcp),
            Some(vec!["session-a".to_string(), "session-b".to_string()]),
            "a client that vanished leaves MCP sessions nothing else will ever close — all of \
             them, not the newest"
        );

        let lease = brief();
        request(&lease, None, Some("session-c"), true);
        goodbye(&lease, "session-c");
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(
            lease.expired().map(|e| e.mcp),
            Some(vec![]),
            "whereas one that said goodbye had its session closed by the DELETE"
        );
    }
}
