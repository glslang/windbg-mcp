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
//! ## One client at a time
//!
//! The registry is global: `session_id` handles are minted from it, `MAX_SESSIONS` is shared, and
//! `end_session` will end anything it is handed. None of that is scoped to a client, so two clients
//! would silently share — and one could end a target the other was using. Rather than pretend
//! otherwise, a second client is refused while the first holds the server. The bearer token is the
//! identity: there is one authorised client, so anyone presenting the token *is* that client, and a
//! reconnect needs nothing further to prove.

use std::collections::HashMap;
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
use rmcp::model::ProtocolVersion;
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

/// A file to read the bearer token from instead, for when an environment variable is not private
/// enough.
///
/// It is not, for a **service**: a service reads the *machine* environment, and that is readable by
/// every local process including unprivileged ones. Since this endpoint's token is the only thing
/// between a caller and `launch`, and a service runs as `LocalSystem`, a machine-scope token is a
/// local privilege escalation rather than an inconvenience — see [`crate::service`], which writes
/// this file with an ACL that excludes ordinary users and points the service at it.
///
/// Read *before* [`TOKEN_ENV`], so a host that has both is using the private one.
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
/// **The lease cannot cover this any more.** It identifies a client by `Mcp-Session-Id`, and
/// SEP-2567 removed sessions from `2026-07-28` — the revision most clients now negotiate — so on
/// that revision no holder is ever installed and no lease ever expires. A client that vanishes
/// would leave its targets held until the process ended, which for a live kernel means a machine
/// owned by nobody ([#162](https://github.com/glslang/windbg-mcp/issues/162)).
///
/// Deliberately much longer than the lease grace. A lease is renewed by *any* request, so a working
/// client renews it constantly; this is per session, and a caller reading a stack for twenty minutes
/// before asking the next question is doing nothing wrong. It is a backstop against abandonment,
/// not a scheduler.
const IDLE_RELEASE: Duration = Duration::from_secs(30 * 60);
const IDLE_ENV: &str = "WINDBG_MCP_SESSION_IDLE_SECS";

/// The header carrying a client's MCP session, which is what identifies the holder.
const SESSION_HEADER: &str = "Mcp-Session-Id";

/// The header naming the revision a request is on.
///
/// `2026-07-28` carries in every request what the handshake used to settle once, and this is the
/// part of that the gate needs: whether a session id is coming.
const PROTOCOL_HEADER: &str = "MCP-Protocol-Version";

/// Whether this request is on a revision that mints no `Mcp-Session-Id`.
///
/// Read from a header because the gate never parses a body — it hands the request to rmcp intact,
/// and buffering it here to look would be a copy of every tool call's arguments for one bit.
///
/// **Matched against the revisions rmcp knows, rather than compared as a string.** The comparison
/// is lexicographic and that is correct for revisions, which are ISO dates — but a header that is
/// not a revision at all (`draft`) sorts above every date, and would be read as newer than the
/// newest thing there is. Anything unrecognised is treated as a revision that has sessions, which
/// is the answer that costs a wrong guess least: it reserves, as this gate always did.
///
/// An `initialize` may legitimately arrive without this header — it is the request that establishes
/// the revision — so a stateless client's *first* request still reserves. That costs nothing: it
/// mints no session, so [`Lease::settle`] gives the reservation straight back.
fn mints_no_session(headers: &hyper::HeaderMap) -> bool {
    headers
        .get(PROTOCOL_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            ProtocolVersion::KNOWN_VERSIONS
                .iter()
                .find(|known| known.as_str() == value)
        })
        .is_some_and(|version| *version >= ProtocolVersion::V_2026_07_28)
}

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

/// The lease: who holds this server, and until when.
///
/// One lock over both, because they are one decision. "Is there a holder" and "has it expired" read
/// together or a request can be admitted against a holder the sweeper is releasing.
struct Lease {
    grace: Duration,
    /// Consulted before tenancy changes hands, never for anything else.
    ///
    /// The listener otherwise knows nothing about debug sessions — but "may this client have the
    /// server" cannot be answered from HTTP alone, because an engine job outlives the request that
    /// asked for it.
    sessions: Sessions,
    /// One tenancy per client, rather than one for the server.
    ///
    /// The gate was written when the registry was global: a second client could see and end the
    /// first's targets, so serving one at a time *was* the boundary. Sessions are owned now
    /// ([#162](https://github.com/glslang/windbg-mcp/issues/162)), and a shared gate would only
    /// mean that one client's long call — a pool walk, an `!analyze` — makes every other client
    /// wait for a boundary it no longer provides. Contention within a client is still real and
    /// still arbitrated; contention *between* them was never about safety.
    state: Mutex<HashMap<crate::client::Client, Tenancy>>,
}

#[derive(Debug, Default)]
struct Tenancy {
    /// The MCP session that owns this server. `None` while nobody is attached — which is *not* the
    /// same as nothing being open, since a departed client's sessions live on until `deadline`.
    holder: Option<String>,
    /// The claim currently reserving the server, if any.
    ///
    /// Without a reservation the gate only *observes* tenancy, and two `initialize` requests
    /// arriving together both see a vacant server, both get sessions, and the second silently
    /// replaces the first as holder while the first stays serviceable — two clients on a registry
    /// whose handles, capacity and `end_session` are all global.
    ///
    /// It is an **identity** rather than a flag because a reservation can outlive its usefulness: a
    /// request still inside `mcp.handle` when the grace runs out has its claim cleared, the sweep
    /// finishes, and a newer client claims the server — and the old request then arrives at
    /// `settle` with no way to know it is no longer the one being waited for. A generation lets
    /// `settle` check that the reservation it is resolving is still its own.
    claim: Option<u64>,
    /// Source of the generation above. Monotonic, so a cleared claim is never re-issued.
    claims_issued: u64,
    /// A lease has run out and its sessions are being released.
    ///
    /// Held across the release, because the teardown is not instant: clearing the holder and then
    /// releasing would leave a window where the server looks vacant and a new client can start
    /// using a session the sweeper is about to close underneath it.
    releasing: bool,
    /// When the sessions are released if nothing renews first. `None` means there is nothing to
    /// release and nothing to wait for.
    deadline: Option<Instant>,
    /// Requests admitted under the current holder that have not finished yet.
    ///
    /// MCP over HTTP is not one connection: a client can send `DELETE` on one while a tool call is
    /// still running on another. Handing the server to the next client at that moment would leave
    /// the old call executing against sessions the new client now owns — free to mutate or end a
    /// target that is no longer its own.
    in_flight: usize,
    /// The holder said goodbye while work it admitted was still running.
    ///
    /// Tenancy is given up when that work drains, not when the `DELETE` arrives.
    farewell: bool,
    /// Which tenancy the counters above belong to.
    ///
    /// Bumped whenever a teardown discards them. An in-flight guard carries the epoch it was
    /// admitted under and subtracts nothing from a later one — without that, a request that
    /// outlived its grace decrements the *next* holder's count when it finally returns, which can
    /// drive that count to zero while a tool call is still running and let a concurrent goodbye
    /// hand the registry to somebody else mid-call.
    epoch: u64,
    /// A previous client's sessions are still open, waiting to be adopted or swept.
    ///
    /// Tracked rather than inferred from `deadline`. It was inferred, until reserving a claim
    /// started arming that deadline too — at which point every first client looked like it was
    /// inheriting sessions that did not exist.
    left_open: bool,
}

/// What a swept lease left behind.
#[derive(Debug, PartialEq, Eq)]
struct Expired {
    /// The MCP session still open at the moment the lease ran out — a client that vanished rather
    /// than saying goodbye. `None` when it sent a DELETE, which already closed it.
    ///
    /// Reported so the sweeper can close it in the service too. Releasing the debug sessions alone
    /// would leave that MCP session resident and its id still accepted, and every reconnect cycle
    /// would add another.
    holder: Option<String>,
}

impl Tenancy {
    /// Reserves the server for a request that is on its way to becoming the holder.
    ///
    /// Renewing the deadline is the load-bearing half. A claim admitted near the end of a grace
    /// would otherwise be adopting sessions the sweeper is entitled to release while
    /// `mcp.handle` is still running — the client would be handed a target that is being let go.
    fn claim(&mut self, grace: Duration) -> u64 {
        self.claims_issued += 1;
        self.claim = Some(self.claims_issued);
        self.deadline = Some(Instant::now() + grace);
        self.claims_issued
    }
}

/// Counts an admitted request out again when it ends.
///
/// A guard rather than a call at each return, because the path that matters most has no return at
/// all: a connection dropped inside `mcp.handle` cancels the future, and an explicit decrement
/// would simply not run — leaving the holder's count permanently above zero and its goodbye
/// deferred for ever.
struct InFlight {
    lease: Arc<Lease>,
    /// Whose tenancy this request was admitted under — the count it has to be taken out of.
    owner: crate::client::Client,
    epoch: u64,
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.lease.leave(&self.owner, self.epoch);
    }
}

/// What became of a request's reservation.
#[derive(Debug, PartialEq, Eq)]
enum Settled {
    /// Tenancy is as this request left it, and the response stands.
    Kept {
        /// Whether this client picked up sessions a previous one left open.
        adopted: bool,
    },
    /// This request no longer owns the server: its claim was swept while it was being handled, or
    /// a teardown started under it. Anything it produced has to be undone — the service may have
    /// minted a session for a client that is not the holder, and nothing else will ever close it.
    Stale,
}

/// A request the gate let through, and what it was let through *as*.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Admitted {
    /// The claim this request reserved, if it reserved one — which [`Lease::settle`] must present
    /// to change tenancy.
    claim: Option<u64>,
    /// The tenancy it was admitted under, which [`Lease::leave`] must present to count it out.
    epoch: u64,
}

/// What a request presents to the gate, which is all tenancy is decided from.
///
/// Three cases rather than `Option<&str>`, because the absence of a session id stopped meaning one
/// thing. It used to mean "a client opening a session"; since [SEP-2567] removed the session from
/// `2026-07-28` it also means "a client that will never have one", and those two want opposite
/// answers — the first is the only moment tenancy is contested, and the second contests nothing.
///
/// [SEP-2567]: https://modelcontextprotocol.io/seps/2567-sessionless-mcp
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Arriving<'a> {
    /// An `Mcp-Session-Id` the client is presenting.
    Holding(&'a str),
    /// No session id, on a revision that mints them: an `initialize`, or a client resuming inside
    /// the grace.
    Opening,
    /// No session id, and none is coming.
    Stateless,
}

/// What the tenancy gate decided about one request.
#[derive(Debug, PartialEq, Eq)]
enum Admission {
    /// Hand it to the MCP service.
    Serve(Admitted),
    /// This credential already has an MCP session here, or is opening one.
    Occupied,
    /// This credential's own sessions are being let go after its lease ran out. Separate from
    /// [`Self::Occupied`] because the advice is the opposite: nothing is held, and the request that
    /// arrives a moment later is served.
    Releasing,
    /// The request carried an MCP session id **another client** minted. Reported to the caller as
    /// unknown, for the reason the registry reports another client's handle that way: the answer
    /// must not confirm a session the caller may not use.
    NotYours,
}

/// A borrow of one client's tenancy, so the rules below read exactly as they did when there was
/// one tenancy for the server — the difference is entirely in *whose* is being consulted.
struct TenancyGuard<'a> {
    all: std::sync::MutexGuard<'a, HashMap<crate::client::Client, Tenancy>>,
    client: crate::client::Client,
}

impl std::ops::Deref for TenancyGuard<'_> {
    type Target = Tenancy;

    fn deref(&self) -> &Tenancy {
        self.all
            .get(&self.client)
            .expect("state_of inserts before handing out a guard")
    }
}

impl std::ops::DerefMut for TenancyGuard<'_> {
    fn deref_mut(&mut self) -> &mut Tenancy {
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

    fn all_tenancies(&self) -> std::sync::MutexGuard<'_, HashMap<crate::client::Client, Tenancy>> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Whether an MCP session id is held by some client other than this one.
    ///
    /// Only the *holder* counts. A departed client's id is closed in the MCP service by the
    /// `DELETE` that departed, and one whose lease expired is closed by the sweep — so an id no
    /// tenancy holds is already unusable, and treating it as owned would refuse a client its own
    /// reconnect on the strength of a record nothing backs.
    fn held_by_another(&self, caller: &crate::client::Client, session: &str) -> bool {
        self.all_tenancies()
            .iter()
            .any(|(client, tenancy)| client != caller && tenancy.holder.as_deref() == Some(session))
    }

    /// One client's tenancy, created empty on first use — a client that has never connected holds
    /// nothing, which is what a default `Tenancy` says.
    fn state_of(&self, client: &crate::client::Client) -> TenancyGuard<'_> {
        let mut all = self.all_tenancies();
        all.entry(client.clone()).or_default();
        TenancyGuard {
            all,
            client: client.clone(),
        }
    }

    /// Decides whether a request may be served, **reserving** the server when one is taking it.
    ///
    /// What the request presents is an [`Arriving`]: the `Mcp-Session-Id` it carries, or which kind
    /// of nothing it carries instead. Every decision is made under one lock, so the answer a
    /// request gets is the state it will be served against.
    fn admit(&self, client: &crate::client::Client, arriving: Arriving<'_>) -> Admission {
        // **Before this client's own tenancy is consulted at all**, because the id may not be its
        // to present. The MCP service keeps one session table for the server, so a client that
        // comes by another's `Mcp-Session-Id` reaches that client's MCP session through it — the
        // task-local only decides which *debug* sessions the tools then see. A `DELETE` on it is
        // the sharp end: rmcp closes the session, while the lease that minted it still holds the
        // id, so the client it belonged to fails every request and its re-`initialize` is refused
        // for a whole grace period. That is one authenticated client denying another, which is
        // exactly what ownership is here to stop.
        if let Arriving::Holding(id) = arriving
            && self.held_by_another(client, id)
        {
            return Admission::NotYours;
        }
        let mut state = self.state_of(client);
        // Nothing is served while a teardown is in flight. Briefly refusing a client that could
        // have been served costs a reconnect; serving one costs it the session mid-call. Its own
        // answer, because at this moment the credential holds nothing and is opening nothing — the
        // reply that says otherwise sends a client looking for a session of its own that it does
        // not have, when what it has to do is ask again.
        if state.releasing {
            return Admission::Releasing;
        }
        // **Nothing to reserve.** The claim exists so that two requests cannot both become the
        // holder; a request that will never mint a session cannot become one, so reserving against
        // it refuses work for a contest that is not happening. It was refusing rather a lot of it:
        // on `2026-07-28` *every* request takes this path, so any two that overlapped contended,
        // and a call that parks — a kernel attach whose target never dials in — locked the
        // credential out of `session_status` and `end_session`, which are the two things that
        // recover it ([#168](https://github.com/glslang/windbg-mcp/issues/168)).
        //
        // Counted in-flight all the same: a goodbye still has to wait for the work admitted here.
        if matches!(arriving, Arriving::Stateless) {
            state.in_flight += 1;
            return Admission::Serve(Admitted {
                claim: None,
                epoch: state.epoch,
            });
        }
        match (arriving, state.holder.as_deref()) {
            // The holder, still talking.
            (Arriving::Holding(id), Some(held)) if id == held => {
                state.deadline = Some(Instant::now() + self.grace);
                state.in_flight += 1;
                Admission::Serve(Admitted {
                    claim: None,
                    epoch: state.epoch,
                })
            }
            // A session id belonging to someone else. This is the arm that made the race above
            // persist rather than pass: serving it leaves both clients working.
            (Arriving::Holding(_), Some(_)) => Admission::Occupied,
            // A session id with nobody holding the server — a client resuming what it left inside
            // the grace. Reserved like an `initialize`, because it is the same contest: a lease
            // expiry leaves the old session id valid in the service, so a resume can race a fresh
            // client and both would pass a gate that only served them. The holder is still not
            // taken until `settle` hears the session was real, or a stale id would lock the server
            // out for a whole grace period.
            (Arriving::Holding(_), None) if state.claim.is_none() => {
                state.in_flight += 1;
                let epoch = state.epoch;
                Admission::Serve(Admitted {
                    claim: Some(state.claim(self.grace)),
                    epoch,
                })
            }
            // A new client, and nobody attached or attaching: it reserves the server here, and
            // inherits whatever the last one left open.
            (Arriving::Opening, None) if state.claim.is_none() => {
                state.in_flight += 1;
                let epoch = state.epoch;
                Admission::Serve(Admitted {
                    claim: Some(state.claim(self.grace)),
                    epoch,
                })
            }
            // Someone is mid-`initialize`, or holds it already.
            _ => Admission::Occupied,
        }
    }

    /// Records what the service made of a request the gate admitted.
    ///
    /// Called for **every** admitted request, because a claim that is never resolved is a server
    /// nobody can take: an `initialize` that fails has to give the reservation back.
    ///
    /// Returns whether this was an **adoption** — a client picking up sessions a previous one left
    /// inside the grace — which is worth saying out loud, since the alternative reading (that these
    /// are its own sessions) is wrong in a way that matters when it ends one.
    fn settle(
        &self,
        claim: Option<u64>,
        requested: Option<&str>,
        minted: Option<&str>,
        ok: bool,
        client: crate::client::Client,
    ) -> Settled {
        let mut state = self.state_of(&client);
        match claim {
            // This request reserved the server. It may only resolve *its own* reservation: one
            // that outlived the grace has already been cleared and possibly re-issued to somebody
            // else, and clearing that would hand two clients the registry at once.
            Some(mine) if state.claim == Some(mine) => state.claim = None,
            Some(_) => return Settled::Stale,
            // A request from the established holder reserved nothing and settles nothing.
            None => return Settled::Kept { adopted: false },
        }
        // A teardown that started while this request was being handled has already decided the
        // sessions are going. Installing a holder now would hand a client something being released
        // out from under it, and the client is better served by being told to come back.
        if state.releasing {
            return Settled::Stale;
        }
        let adopted = state.left_open;
        match (minted, requested) {
            // An `initialize` that produced a session: the claim becomes a holder.
            (Some(id), _) => {
                state.holder = Some(id.to_string());
                state.deadline = Some(Instant::now() + self.grace);
                state.left_open = false;
                Settled::Kept { adopted }
            }
            // A resumed session the service accepted: the returning client is the holder again.
            (None, Some(id)) if ok && state.holder.is_none() => {
                state.holder = Some(id.to_string());
                state.deadline = Some(Instant::now() + self.grace);
                state.left_open = false;
                Settled::Kept { adopted }
            }
            // Anything else, including an `initialize` that failed: the reservation is already
            // given back above, and nobody took the server.
            _ => Settled::Kept { adopted: false },
        }
    }

    /// The holder said goodbye. The sessions stay; the clock starts.
    fn released(&self, client: &crate::client::Client, id: &str) {
        let mut state = self.state_of(client);
        if state.holder.as_deref() != Some(id) {
            return;
        }
        state.deadline = Some(Instant::now() + self.grace);
        // The `DELETE` itself is in flight, so this is always the deferred path in practice — and
        // that is the point: tenancy is given up when the work admitted under it drains, which is
        // at worst this request and at best a tool call still running on another connection.
        state.farewell = true;
        drop(state);
        self.try_give_up_for(client);
    }

    /// One admitted request finished, however it finished.
    ///
    /// `epoch` is the tenancy it was admitted under. A request that outlived a teardown belongs to
    /// a tenancy that no longer exists, and counting it out of the current one would subtract work
    /// it never did — enough for a concurrent goodbye to see zero while a tool call is still
    /// running.
    fn leave(&self, client: &crate::client::Client, epoch: u64) {
        let mut state = self.state_of(client);
        if state.epoch != epoch {
            return;
        }
        state.in_flight = state.in_flight.saturating_sub(1);
        drop(state);
        self.try_give_up_for(client);
    }

    /// Whether the lease has run out, **claiming the teardown** if so.
    ///
    /// The server is marked `releasing` under the same lock that reads the deadline, and stays that
    /// way until [`Self::released_leases`] says the teardown is done. That is what closes the
    /// window [`Sessions::release_leased`] warns it does not close itself: between deciding to
    /// release and having released, no client can be admitted to the sessions being released.
    fn expired_for(&self, client: &crate::client::Client) -> Option<Expired> {
        let mut state = self.state_of(client);
        match state.deadline {
            Some(at) if Instant::now() >= at => {
                let holder = state.holder.take();
                state.deadline = None;
                // Including a claim. A request whose connection died before `settle` would
                // otherwise leave this set for ever — no client could take the server, and no
                // expiry would ever clear it either, because a claim renews the deadline it would
                // have to outlive. Bounded by one grace, and this is the bound.
                state.claim = None;
                state.left_open = false;
                // Everything admitted under that holder is being torn down with it; a count kept
                // past this point would defer a goodbye that has already been overtaken.
                state.in_flight = 0;
                state.farewell = false;
                // Anything still out there was admitted under the tenancy being discarded, and may
                // not count itself out of the next one.
                state.epoch += 1;
                state.releasing = true;
                Some(Expired { holder })
            }
            _ => None,
        }
    }

    /// The clients this lease holds state for, so the sweeper can ask each in turn without holding
    /// the lock across an `await`.
    fn clients(&self) -> Vec<crate::client::Client> {
        self.all_tenancies().keys().cloned().collect()
    }

    /// Hands the server over, if a goodbye is outstanding and nothing is still using it.
    ///
    /// Two conditions, and they are not the same one. `in_flight` is HTTP: the requests this holder
    /// was admitted for. `Sessions::busy` is the engine: a job survives the request that queued it,
    /// so a dropped future or a timed-out call leaves work running against a target the next client
    /// would otherwise be handed. Attempted on every sweep as well as on the two events, because
    /// the engine going idle is not an event this side can see.
    fn try_give_up_for(&self, client: &crate::client::Client) {
        let mut state = self.state_of(client);
        if !state.farewell || state.in_flight != 0 {
            return;
        }
        drop(state);
        if self.sessions.busy() {
            return;
        }
        state = self.state_of(client);
        // Re-checked: the two locks were not held together, so a request could have arrived.
        if !state.farewell || state.in_flight != 0 {
            return;
        }
        state.farewell = false;
        state.holder = None;
        state.deadline = Some(Instant::now() + self.grace);
        state.left_open = true;
    }

    /// The teardown is done; the server may be taken again.
    fn released_leases(&self, client: &crate::client::Client) {
        self.state_of(client).releasing = false;
    }
}

/// Serves MCP over HTTP until the process is asked to stop.
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

/// The bearer token, from a file if one is named and from the environment otherwise.
///
/// Trimmed, because a token in a file arrives with whatever line ending wrote it, and a token that
/// works from an editor but not from `Set-Content` would be an unpleasant afternoon.
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

/// The token in the file [`TOKEN_FILE_ENV`] names, if it names one.
fn token_file() -> Result<Option<String>> {
    if let Some(path) = std::env::var_os(TOKEN_FILE_ENV) {
        let path = std::path::PathBuf::from(path);
        let token = std::fs::read_to_string(&path).with_context(|| {
            format!(
                "{TOKEN_FILE_ENV} names {}, which cannot be read",
                path.display()
            )
        })?;
        if token.trim().is_empty() {
            bail!("{} is empty; that is not a token.", path.display());
        }
        return Ok(Some(token.trim().to_string()));
    }
    Ok(None)
}

pub async fn serve(
    sessions: Sessions,
    addr: SocketAddr,
    call_timeout: Duration,
    shutdown: impl Future<Output = ()>,
    ready: impl FnOnce(),
) -> Result<()> {
    let credentials = Arc::new(credentials()?);

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
        Arc::new(StreamableHttpService::new(
            move || Ok(WindbgServer::new(sessions.clone())),
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
        "windbg-mcp listening on http://{addr} (lease grace {grace:?}, {}, clients: {})",
        match idle_after {
            Some(after) => format!("idle sessions released after {}m", after.as_secs() / 60),
            None => "idle sessions never released".to_string(),
        },
        credentials.names().join(", ")
    );

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
        let manager = manager.clone();
        let lease = lease.clone();
        let credentials = Arc::clone(&credentials);
        tokio::spawn(async move {
            let serve = service_fn(move |req| {
                gate(
                    req,
                    mcp.clone(),
                    manager.clone(),
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

/// Authenticates, decides tenancy, and only then hands the request to MCP.
async fn gate(
    req: Request<Incoming>,
    mcp: Arc<StreamableHttpService<WindbgServer, LocalSessionManager>>,
    manager: Arc<LocalSessionManager>,
    lease: Arc<Lease>,
    credentials: Arc<crate::client::Credentials>,
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

    let arriving = match session.as_deref() {
        Some(id) => Arriving::Holding(id),
        None if mints_no_session(req.headers()) => Arriving::Stateless,
        None => Arriving::Opening,
    };

    let admitted = match lease.admit(&caller, arriving) {
        Admission::Serve(admitted) => admitted,
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
        // ask again rather than to change anything.
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
        Admission::Occupied => {
            // Never another client — tenancy is per client now — and never a *connection* either:
            // requests carrying the session this credential holds are served concurrently, which
            // is how a `DELETE` arrives on one while a tool call runs on another. Two things reach
            // here and the message has to fit both: a second **MCP session** for this credential
            // (a fresh `initialize`, or an id that is not the one it holds), and a second request
            // arriving while one of its own is still opening one. Saying "another client" would
            // send an operator looking for a colleague who is not there, and saying "connection"
            // for one who has a network problem they do not have.
            //
            // A client on a revision with no session id no longer reaches here at all: it opens
            // nothing, so it contests nothing (#168).
            tracing::warn!(
                "refused a request from {peer}: this credential is already being served here"
            );
            return Ok(refuse(
                StatusCode::CONFLICT,
                "this credential is already using this server: it holds an MCP session, or a \
                 request of its own is still opening one. Send the session id it holds, or ask \
                 again once that request has finished.",
            ));
        }
    };
    // From here every exit — a reply, a refusal, or this future being cancelled — counts the
    // request out, and a goodbye waiting on it completes when the last one does.
    let _in_flight = InFlight {
        lease: lease.clone(),
        owner: caller.clone(),
        epoch: admitted.epoch,
    };

    // A DELETE is the client saying it is done. Read before the service handles it, because
    // afterwards the request is gone; whether it *was* a departure also depends on the answer.
    let method = req.method().clone();

    // The whole MCP call runs as this client: the routing, the worker handshake and the engine
    // call all read the identity from here, rather than from a parameter forty-odd tool bodies
    // would have to carry. See [`crate::client`].
    // Kept for the settlement below, which records whose tenancy this is — the scope moves the
    // identity into the call.
    let caller_for_lease = caller.clone();
    let response = crate::client::as_client(caller, mcp.handle(req)).await;

    let minted = response
        .headers()
        .get(SESSION_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    // Every admitted request settles, so a reservation is never left standing by a request that
    // did not become a session.
    match lease.settle(
        admitted.claim,
        session.as_deref(),
        minted.as_deref(),
        response.status().is_success(),
        caller_for_lease.clone(),
    ) {
        // Counted rather than asserted. `left_open` says a previous tenancy ended inside the
        // grace, which is true whether or not that client had opened anything — so the
        // unconditional version of this line told an operator a client had adopted sessions that
        // did not exist, on every ordinary reconnect.
        Settled::Kept { adopted: true } => {
            // Asked *for* this client rather than as it. The call's identity scope has closed by
            // here, so anything reading the ambient one would count `local`'s sessions — nobody's,
            // for a named client, which is the reconnect this line exists to describe.
            match lease.sessions.live_count_for(&caller_for_lease) {
                0 => tracing::info!(
                    "a client attached to a server the previous one had let go; nothing was open"
                ),
                inherited => tracing::info!(
                    "a client attached and adopted the {inherited} session(s) the previous one \
                     left open"
                ),
            }
        }
        Settled::Kept { adopted: false } => {}
        // This request lost the server while it was being handled. If the service minted a session
        // for it, that session belongs to nobody: the holder is someone else, so every request
        // carrying it would be refused, and no lease will ever sweep it. Close it here and tell the
        // client what actually happened, rather than handing it an id that cannot be used.
        Settled::Stale => {
            if let Some(id) = minted
                && let Err(e) = manager.close_session(&id.into()).await
            {
                tracing::warn!("could not close a session minted by a claim that had expired: {e}");
            }
            tracing::warn!(
                "a request from {peer} outlived its claim on this server; its session was closed"
            );
            return Ok(refuse(
                StatusCode::CONFLICT,
                "this request outlived its claim on the server; open a new session",
            ));
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

/// Whether this request was the holder actually leaving.
///
/// A `DELETE` is the client saying it is done — **if the service agreed**. rmcp refuses one that
/// carries an invalid protocol version, and a refused `DELETE` leaves the MCP session open. Taking
/// it as a departure anyway clears the holder, and the sweep that would have closed that session
/// then finds `holder: None` and nothing to close: the session survives with no lease owning it and
/// no sweep that will ever collect it, one per failed attempt
/// ([#136](https://github.com/glslang/windbg-mcp/issues/136)).
///
/// A predicate rather than a condition inline, because it is the one tenancy rule that lives in the
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
    credentials: &crate::client::Credentials,
) -> Option<crate::client::Client> {
    req.headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .and_then(|presented| credentials.client_for(presented))
        .cloned()
}

fn refuse(status: StatusCode, why: &str) -> Response<BoxBody<Bytes, Infallible>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::from(why.to_string())).boxed())
        // The builder only fails on a malformed status or header, and both are literals here.
        .expect("a constant response is well-formed")
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
        // Independent of the lease, and checked first, because it is the half that still works on
        // a stateless transport: the lease needs a client to identify, and on `2026-07-28` there
        // is no session id to identify one by. See [`IDLE_RELEASE`].
        if let Some(after) = idle_after {
            sessions.release_idle(after).await;
        }
        // Per client, because a tenancy is per client: one caller's expiry says nothing about
        // another's, and a sweep that stopped at the first would starve the rest.
        for client in lease.clients() {
            // The engine may have gone idle since the last tick, which is not something the HTTP
            // side is told about.
            lease.try_give_up_for(&client);
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
            // vanished never sent the DELETE that closes its MCP session, so without this the
            // service keeps that session resident and its id accepted — and every
            // disconnect-and-reconnect cycle would add another one no lease will ever sweep again.
            if let Some(id) = expired.holder
                && let Err(e) = manager.close_session(&id.into()).await
            {
                tracing::warn!("could not close the MCP session of the client that went away: {e}");
            }
            // Only now may this client be admitted again: until here, an arriving request would be
            // let in to sessions this release is closing.
            lease.released_leases(&client);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A lease bound to one client, so the rules below read as they did when there was one tenancy
    /// for the server.
    ///
    /// Every test here is about how *a* client's tenancy behaves — claims, adoption, goodbyes,
    /// expiry — and none of them is about which client it is. Binding the name once keeps that
    /// distinction visible: a test that needs two clients says so by using two of these.
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
            self.lease.admit(
                &self.client,
                match session {
                    Some(id) => Arriving::Holding(id),
                    None => Arriving::Opening,
                },
            )
        }

        /// A request on the revision that has no session id to present.
        fn admit_stateless(&self) -> Admission {
            self.lease.admit(&self.client, Arriving::Stateless)
        }

        fn settle(
            &self,
            claim: Option<u64>,
            requested: Option<&str>,
            minted: Option<&str>,
            ok: bool,
        ) -> Settled {
            self.lease
                .settle(claim, requested, minted, ok, self.client.clone())
        }

        fn released(&self, id: &str) {
            self.lease.released(&self.client, id);
        }

        fn leave(&self, epoch: u64) {
            self.lease.leave(&self.client, epoch);
        }

        fn expired(&self) -> Option<Expired> {
            self.lease.expired_for(&self.client)
        }

        fn released_leases(&self) {
            self.lease.released_leases(&self.client);
        }

        fn state(&self) -> TenancyGuard<'_> {
            self.lease.state_of(&self.client)
        }

        fn sessions(&self) -> &Sessions {
            &self.lease.sessions
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
            Lease {
                grace: Duration::from_millis(1),
                sessions: Sessions::new(CALL),
                state: Mutex::new(HashMap::new()),
            },
            crate::client::Client::LOCAL,
        )
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

    /// The claim an admitted request reserved. Panics if the gate refused, since every caller here
    /// is testing what happens *after* admission.
    /// Whether a settlement adopted sessions, asserting it was not rejected.
    fn adopted(settled: Settled) -> bool {
        match settled {
            Settled::Kept { adopted } => adopted,
            Settled::Stale => panic!("the settlement was rejected as stale"),
        }
    }

    fn admitted(admission: Admission) -> Admitted {
        match admission {
            Admission::Serve(admitted) => admitted,
            Admission::Occupied => panic!("the gate refused a request this test needed served"),
            Admission::NotYours => {
                panic!(
                    "the gate took a session id for another client's, which no test here sets up"
                )
            }
            Admission::Releasing => panic!("the gate is letting go of sessions this test needs"),
        }
    }

    /// One whole request: admitted, settled, and finished. Every admitted request is counted out
    /// again in `gate` by a guard, so a test that settles without finishing is modelling a request
    /// that never came back.
    fn request(lease: &For, session: Option<&str>, minted: Option<&str>, ok: bool) -> Settled {
        let it = admitted(lease.admit(session));
        let settled = lease.settle(it.claim, session, minted, ok);
        lease.leave(it.epoch);
        settled
    }

    /// A client's `DELETE`, which is itself an admitted request.
    fn goodbye(lease: &For, id: &str) {
        let it = admitted(lease.admit(Some(id)));
        lease.released(id);
        lease.leave(it.epoch);
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

    /// One client at a time — and admission has to *reserve*, not merely observe.
    #[test]
    fn a_second_client_is_refused_while_the_first_holds_the_server() {
        let lease = lease();
        request(&lease, None, Some("session-a"), true);

        assert!(matches!(lease.admit(None), Admission::Occupied));
        assert!(
            matches!(
                lease.admit(Some("session-a")),
                Admission::Serve(Admitted { claim: None, .. })
            ),
            "the holder is served, and reserves nothing — it already holds the server"
        );
        assert!(
            matches!(lease.admit(Some("session-b")), Admission::Occupied),
            "another client's session id is refused; serving it is what let the losing side of a \
             race keep working"
        );
    }

    /// The race the reservation exists for: two `initialize`s arriving together.
    #[test]
    fn a_claim_in_flight_blocks_a_second_initialize() {
        let lease = lease();
        let first = admitted(lease.admit(None));
        assert!(matches!(lease.admit(None), Admission::Occupied));

        lease.settle(first.claim, None, Some("session-a"), true);
        assert_eq!(lease.state().holder.as_deref(), Some("session-a"));
    }

    /// A claim that comes to nothing must give the server back.
    #[test]
    fn an_initialize_that_fails_does_not_hold_the_server_for_ever() {
        let lease = lease();
        let claim = admitted(lease.admit(None));
        lease.settle(claim.claim, None, None, false);

        assert!(
            lease.state().claim.is_none(),
            "the reservation was returned"
        );
        assert!(matches!(lease.admit(None), Admission::Serve(_)));
    }

    /// **A stale claim may not settle over a newer one.**
    ///
    /// A request still inside `mcp.handle` when the grace runs out has its reservation cleared and
    /// the sweep completed under it. By the time it returns, another client may hold the server.
    /// Settling unconditionally there would clear the newer claim and install the stale session,
    /// and the newer response would then replace it again — two valid MCP sessions overlapping on a
    /// registry whose handles and capacity are global.
    #[test]
    fn a_claim_that_outlived_its_grace_cannot_settle_over_a_newer_one() {
        let lease = brief();
        let stale = admitted(lease.admit(None)).claim;
        std::thread::sleep(Duration::from_millis(5));
        assert!(
            lease.expired().is_some(),
            "the stale request's claim is swept"
        );
        lease.released_leases();

        let fresh = admitted(lease.admit(None)).claim;
        assert_ne!(stale, fresh, "a cleared claim is never re-issued");
        lease.settle(fresh, None, Some("session-new"), true);

        // Now the request nobody is waiting for finally returns.
        assert_eq!(
            lease.settle(stale, None, Some("session-stale"), true),
            Settled::Stale,
            "and is told so, because the session it minted has to be closed and its client told to \
             start again — an id whose every request is refused is worse than an error"
        );
        assert_eq!(
            lease.state().holder.as_deref(),
            Some("session-new"),
            "the holder is whoever legitimately took the server, not whoever answered last"
        );
    }

    /// A request from the established holder settles nothing and is never stale.
    ///
    /// It reserved no claim, so there is nothing to resolve — and treating it as stale would close
    /// the holder's own session out from under it.
    #[test]
    fn an_ordinary_request_from_the_holder_is_not_a_settlement() {
        let lease = lease();
        let claim = admitted(lease.admit(None));
        lease.settle(claim.claim, None, Some("session-a"), true);

        let none = admitted(lease.admit(Some("session-a"))).claim;
        assert_eq!(none, None, "the holder reserves nothing");
        assert_eq!(
            lease.settle(none, Some("session-a"), None, true),
            Settled::Kept { adopted: false }
        );
        assert_eq!(lease.state().holder.as_deref(), Some("session-a"));
    }

    /// A returning client finds what it left, and is told that is what happened.
    #[test]
    fn a_client_returning_inside_the_grace_adopts_rather_than_starts_fresh() {
        let lease = lease();
        assert!(
            !adopted(request(&lease, None, Some("session-a"), true)),
            "the first client adopts nothing — there was nothing open"
        );

        goodbye(&lease, "session-a");
        assert!(
            adopted(request(&lease, None, Some("session-b"), true)),
            "the next client is told it inherited the sessions still open"
        );
    }

    /// A resume takes the server back only once the service says the session was real.
    #[test]
    fn a_resumed_session_takes_the_server_back_only_if_it_existed() {
        let lease = lease();
        request(&lease, None, Some("session-a"), true);
        goodbye(&lease, "session-a");

        request(&lease, Some("session-a"), None, false);
        assert_eq!(
            lease.state().holder,
            None,
            "a session id the service rejected must not lock the server out for a whole grace"
        );

        request(&lease, Some("session-a"), None, true);
        assert_eq!(lease.state().holder.as_deref(), Some("session-a"));
    }

    /// A resume is a contested claim too, not a free pass.
    #[test]
    fn a_resume_reserves_the_server_like_an_initialize_does() {
        let lease = lease();
        request(&lease, None, Some("session-a"), true);
        goodbye(&lease, "session-a");

        assert!(matches!(
            lease.admit(Some("session-a")),
            Admission::Serve(Admitted { claim: Some(_), .. })
        ));
        assert!(
            matches!(lease.admit(None), Admission::Occupied),
            "a fresh client cannot slip in while a resume is being confirmed"
        );
    }

    /// Whatever a request turns out to be, it hands its reservation back.
    #[test]
    fn every_settled_request_resolves_its_reservation() {
        let lease = lease();
        request(&lease, None, Some("session-a"), true);
        goodbye(&lease, "session-a");

        request(&lease, Some("session-a"), None, true);
        assert!(lease.state().claim.is_none(), "a resume that succeeded");

        goodbye(&lease, "session-a");
        assert!(
            matches!(lease.admit(None), Admission::Serve(_)),
            "so the next client is not refused by a reservation nobody holds"
        );
    }

    /// Letting go is not the same as expiring: the sessions are still there to come back to.
    #[test]
    fn letting_go_starts_the_clock_rather_than_releasing_anything() {
        let lease = lease();
        request(&lease, None, Some("session-a"), true);
        goodbye(&lease, "session-a");

        assert!(
            lease.expired().is_none(),
            "a client that said goodbye has its whole grace to change its mind"
        );
        assert!(lease.state().deadline.is_some(), "and the clock is running");
    }

    /// A goodbye does not hand over the server while work admitted under it is still running.
    ///
    /// MCP over HTTP is not one connection: a `DELETE` can arrive while a tool call is executing on
    /// another. Releasing tenancy there would let the next client adopt the debugger sessions while
    /// the old call is still running against them — free to mutate or end a target it no longer
    /// owns.
    #[test]
    fn a_goodbye_waits_for_the_work_it_admitted() {
        let lease = lease();
        request(&lease, None, Some("session-a"), true);

        // A tool call is admitted and is still running.
        let call = admitted(lease.admit(Some("session-a")));
        // The DELETE arrives on another connection, and is itself in flight.
        let delete = admitted(lease.admit(Some("session-a")));
        lease.released("session-a");

        assert_eq!(
            lease.state().holder.as_deref(),
            Some("session-a"),
            "the goodbye is recorded but not acted on — a call is still running"
        );
        assert!(matches!(lease.admit(None), Admission::Occupied));

        lease.leave(delete.epoch); // the DELETE's own request ends
        assert_eq!(
            lease.state().holder.as_deref(),
            Some("session-a"),
            "still held: the tool call has not come back"
        );

        lease.leave(call.epoch); // and now the tool call does
        assert_eq!(
            lease.state().holder,
            None,
            "only now is the server given up"
        );
        assert!(matches!(lease.admit(None), Admission::Serve(_)));
    }

    /// A guard from a torn-down tenancy subtracts nothing from the next one.
    ///
    /// Without the epoch, a request that outlived its grace decrements the *new* holder's count
    /// when it finally returns — which can reach zero while that holder's tool call is still
    /// running, and let a concurrent goodbye hand the registry to somebody else mid-call.
    #[test]
    fn a_stale_guard_cannot_count_out_a_later_holders_work() {
        let lease = brief();
        let stranded = admitted(lease.admit(None)); // never comes back before the sweep
        std::thread::sleep(Duration::from_millis(5));
        assert!(lease.expired().is_some());
        lease.released_leases();

        // A new client takes the server and starts a call.
        request(&lease, None, Some("session-new"), true);
        let call = admitted(lease.admit(Some("session-new")));
        let delete = admitted(lease.admit(Some("session-new")));
        lease.released("session-new");
        lease.leave(delete.epoch);

        // The request from the previous tenancy finally returns.
        lease.leave(stranded.epoch);
        assert_eq!(
            lease.state().holder.as_deref(),
            Some("session-new"),
            "a guard from a dead tenancy must not drain the live one's count"
        );

        lease.leave(call.epoch);
        assert_eq!(
            lease.state().holder,
            None,
            "only the real work ending gives it up"
        );
    }

    /// Tenancy waits on the *engine*, not only on the HTTP request that asked.
    ///
    /// A job outlives the wait for it — `Sessions::call_as` cancels only the waiter and says so —
    /// so a dropped future or a timed-out call leaves work running against a target. Handing that
    /// target to the next client because the HTTP side went quiet is the same overlap the in-flight
    /// count exists to prevent, one layer down.
    #[test]
    fn a_goodbye_waits_for_the_engine_and_not_just_the_request() {
        let lease = lease();
        request(&lease, None, Some("session-a"), true);
        goodbye(&lease, "session-a");
        assert_eq!(
            lease.state().holder,
            None,
            "with an idle engine the handover is immediate"
        );

        // `Sessions::busy` is what the lease consults, and an idle registry is not busy — so this
        // test pins the wiring rather than the debugger, which needs a worker to be busy at all.
        assert!(!lease.sessions().busy());
    }

    /// A request that never came back cannot defer a goodbye for ever.
    #[test]
    fn a_swept_lease_forgets_work_it_was_waiting_on() {
        let lease = brief();
        let claim = admitted(lease.admit(None));
        lease.settle(claim.claim, None, Some("session-a"), true);
        admitted(lease.admit(Some("session-a"))); // a call that never returns
        lease.released("session-a");
        std::thread::sleep(Duration::from_millis(5));

        assert!(lease.expired().is_some());
        assert_eq!(
            lease.state().in_flight,
            0,
            "the teardown took the count with it"
        );
        lease.released_leases();
        assert!(matches!(lease.admit(None), Admission::Serve(_)));
    }

    /// Only a `DELETE` the service accepted is a departure.
    ///
    /// A refused one leaves the MCP session open. Recording the client as gone then clears the
    /// holder, so the sweep that would have closed that session finds nothing to close — and it
    /// survives with no lease owning it and nothing that will ever collect it (#136).
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

    /// A goodbye from something that is not the holder changes nothing.
    #[test]
    fn only_the_holder_can_let_go() {
        let lease = lease();
        request(&lease, None, Some("session-a"), true);
        lease.released("session-b");
        assert_eq!(
            lease.state().holder.as_deref(),
            Some("session-a"),
            "a stray DELETE must not hand the server to whoever sent it"
        );
    }

    /// **Two clients do not contend, on one lease.** The gate serialised the server when the
    /// registry was global and one client could end another's targets. Sessions are owned now, so a
    /// shared gate would only mean that one client's long call — a pool walk, an `!analyze` — makes
    /// every other client wait for a boundary it no longer provides, and per-client namespaces
    /// would be unusable concurrently ([#162](https://github.com/glslang/windbg-mcp/issues/162)).
    ///
    /// Deliberately *not* written with the `For` binding: two bindings would be two leases, which
    /// cannot contend whatever the code does, and the test would pass against the bug it is for.
    #[test]
    fn one_clients_tenancy_does_not_block_another() {
        let lease = Lease::new(
            longest_quiet_call(CALL) + Duration::from_secs(60),
            CALL,
            Sessions::new(CALL),
        )
        .expect("workable");
        let laptop = crate::client::Client::new("laptop");
        let ci = crate::client::Client::new("ci");

        // `laptop` takes its tenancy and holds it — the long-call case.
        let held = admitted(lease.admit(&laptop, Arriving::Opening));
        lease.settle(
            held.claim,
            None,
            Some("session-laptop"),
            true,
            laptop.clone(),
        );

        // Within that client, a second `initialize` is still refused: that contention is real, and
        // it is the one the claim machinery exists to arbitrate.
        assert_eq!(
            lease.admit(&laptop, Arriving::Opening),
            Admission::Occupied,
            "a second session for the same credential still contends"
        );

        // Across clients, on the same lease, it is not.
        assert!(
            matches!(lease.admit(&ci, Arriving::Opening), Admission::Serve(_)),
            "another client must not wait on a tenancy that no longer bounds anything it can reach"
        );
    }

    /// A revision with no session id is not a client opening one, and the gate must not treat it
    /// as one.
    ///
    /// The `2026-07-28` half of [#168](https://github.com/glslang/windbg-mcp/issues/168). Before
    /// [`Arriving`] existed there was one "no session id" case and it meant *opening*, so it
    /// reserved — which on a revision that never sends an id made every request a reservation, and
    /// every overlapping pair a `409`. Two things are asserted, and the second is the one that
    /// bites: they overlap, and they keep overlapping while one of them never finishes.
    #[test]
    fn stateless_requests_do_not_contend_with_each_other() {
        let lease = lease();

        let first = admitted(lease.admit_stateless());
        assert_eq!(
            first.claim, None,
            "a request that cannot become the holder must reserve nothing"
        );
        let second = admitted(lease.admit_stateless());
        assert_eq!(second.claim, None);

        // The parked case: the first never returns, and the client still has to be able to ask what
        // is going on and end it.
        assert!(
            matches!(lease.admit_stateless(), Admission::Serve(_)),
            "a call that never comes back must not lock its own credential out"
        );

        lease.leave(first.epoch);
        lease.leave(second.epoch);
    }

    /// Serving them alongside each other does not make them a tenancy.
    ///
    /// A stateless request settles nothing and holds nothing, so no lease is ever installed for a
    /// client that only sends them — which is deliberate, and why abandonment on this revision is
    /// [`IDLE_RELEASE`]'s to catch rather than the lease's. What must not happen is the middle
    /// state: a holder recorded for a session that does not exist, which nothing would ever sweep.
    #[test]
    fn a_stateless_request_becomes_nobodys_tenancy() {
        let lease = lease();

        let it = admitted(lease.admit_stateless());
        assert!(!adopted(lease.settle(it.claim, None, None, true)));
        lease.leave(it.epoch);

        assert!(
            lease.expired().is_none(),
            "a client that holds nothing has no lease to run out"
        );
        // And an ordinary opener is still free to take the tenancy afterwards.
        assert!(
            matches!(lease.admit(None), Admission::Serve(_)),
            "a stateless request must leave the server takeable"
        );
    }

    /// A teardown still stops one, because what is being released is the sessions behind it.
    ///
    /// The claim is what a stateless request stops taking; the `releasing` check is not, and the
    /// distinction matters: a request admitted mid-teardown reaches a registry whose sessions are
    /// being closed underneath it.
    #[test]
    fn a_stateless_request_waits_for_a_teardown_like_any_other() {
        let lease = brief();
        let claim = admitted(lease.admit(None));
        lease.settle(claim.claim, None, Some("session-a"), true);
        std::thread::sleep(Duration::from_millis(5));

        assert!(lease.expired().is_some(), "the grace is spent");
        assert!(
            matches!(lease.admit_stateless(), Admission::Releasing),
            "a stateless request must not be let in to sessions that are being closed"
        );

        lease.released_leases();
        assert!(
            matches!(lease.admit_stateless(), Admission::Serve(_)),
            "and must be served the moment the teardown is done"
        );
    }

    /// An MCP session id is one client's, and presenting another's is not a way in.
    ///
    /// The service keeps one session table for the whole server, so the id is the only thing
    /// standing between a client and another's MCP session — and a `DELETE` on it closes that
    /// session while the lease that minted it still holds the id, which leaves its owner failing
    /// every request and refused its own re-`initialize` for a grace period. One authenticated
    /// client denying another is the harm ownership exists to stop, so the gate refuses before
    /// this caller's own tenancy is even consulted.
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

        let held = admitted(lease.admit(&laptop, Arriving::Opening));
        lease.settle(
            held.claim,
            None,
            Some("session-laptop"),
            true,
            laptop.clone(),
        );

        assert_eq!(
            lease.admit(&ci, Arriving::Holding("session-laptop")),
            Admission::NotYours,
            "another client's session id was admitted, so its holder could be deleted out from \
             under it"
        );
        // And the owner is unaffected — the check must not cost a client its own session.
        assert!(
            matches!(
                lease.admit(&laptop, Arriving::Holding("session-laptop")),
                Admission::Serve(_)
            ),
            "the holder must still be served its own id"
        );
        // An id nobody holds is not owned by anybody: a client resuming inside the grace has to
        // get through, which is the arm this check sits in front of.
        assert!(
            matches!(
                lease.admit(&ci, Arriving::Holding("session-nobodys")),
                Admission::Serve(_)
            ),
            "an id no tenancy holds is unusable in the service anyway, and refusing it would \
             refuse a legitimate resume"
        );
    }

    /// A claim keeps alive the sessions it is adopting.
    #[test]
    fn reserving_the_server_renews_what_the_claim_is_adopting() {
        let lease = For::new(
            Lease {
                grace: Duration::from_millis(60),
                sessions: Sessions::new(CALL),
                state: Mutex::new(HashMap::new()),
            },
            crate::client::Client::LOCAL,
        );
        request(&lease, None, Some("session-a"), true);
        goodbye(&lease, "session-a");
        std::thread::sleep(Duration::from_millis(40));

        assert!(
            matches!(lease.admit(None), Admission::Serve(_)),
            "still inside the grace"
        );
        std::thread::sleep(Duration::from_millis(40));
        assert!(
            lease.expired().is_none(),
            "the claim pushed the deadline out; without that the sweep would release the sessions \
             this request is in the middle of adopting"
        );
    }

    /// A request that never settles cannot wedge the server for ever.
    #[test]
    fn a_claim_whose_request_died_is_cleared_by_the_grace() {
        let lease = brief();
        admitted(lease.admit(None));
        std::thread::sleep(Duration::from_millis(5));

        assert!(
            lease.expired().is_some(),
            "the claim's own deadline ran out"
        );
        assert!(
            lease.state().claim.is_none(),
            "and took the reservation with it"
        );
        lease.released_leases();
        assert!(matches!(lease.admit(None), Admission::Serve(_)));
    }

    /// A teardown already under way wins over a claim settling into it.
    #[test]
    fn a_claim_that_settles_during_a_teardown_does_not_take_the_server() {
        let lease = brief();
        request(&lease, None, Some("session-a"), true);
        // The holder lets go, so the next request is a genuine resume and reserves a claim of its
        // own — a request from the sitting holder reserves nothing and settles nothing.
        goodbye(&lease, "session-a");
        let resumed = admitted(lease.admit(Some("session-a"))).claim;
        assert!(resumed.is_some(), "a resume reserves the server");
        std::thread::sleep(Duration::from_millis(5));
        assert!(lease.expired().is_some());

        assert_eq!(
            lease.settle(resumed, None, Some("session-b"), true),
            Settled::Stale
        );
        assert_eq!(
            lease.state().holder,
            None,
            "a client must not be handed sessions that are being released out from under it"
        );
    }

    /// Nothing is admitted between deciding to release and having released.
    #[test]
    fn nothing_is_admitted_while_the_teardown_runs() {
        let lease = brief();
        let claim = admitted(lease.admit(None));
        lease.settle(claim.claim, None, Some("session-a"), true);
        std::thread::sleep(Duration::from_millis(5));

        assert!(lease.expired().is_some(), "the grace is spent");
        assert!(
            matches!(lease.admit(None), Admission::Releasing),
            "the server is not vacant yet — the sessions are still being let go, and saying so is \
             not the same as saying this credential holds one"
        );

        lease.released_leases();
        assert!(matches!(lease.admit(None), Admission::Serve(_)));
    }

    /// Expiry is a one-shot: the deadline is consumed by the sweep that acts on it.
    #[test]
    fn expiry_is_reported_once_rather_than_on_every_sweep() {
        let lease = brief();
        let claim = admitted(lease.admit(None));
        lease.settle(claim.claim, None, Some("session-a"), true);
        std::thread::sleep(Duration::from_millis(5));

        assert!(lease.expired().is_some(), "the grace is spent");
        assert!(
            lease.expired().is_none(),
            "and expiry is reported once, not on every sweep — a second `true` would release an \
             already-released set of sessions on each pass"
        );
        assert_eq!(lease.state().holder, None);
    }

    /// A swept lease says what it left in the service, so the sweeper can close that too.
    #[test]
    fn a_swept_lease_reports_the_session_that_never_said_goodbye() {
        let lease = brief();
        let claim = admitted(lease.admit(None));
        lease.settle(claim.claim, None, Some("session-a"), true);
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(
            lease.expired().map(|e| e.holder),
            Some(Some("session-a".to_string())),
            "a client that vanished leaves an MCP session nothing else will ever close"
        );

        let lease = brief();
        request(&lease, None, Some("session-b"), true);
        goodbye(&lease, "session-b");
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(
            lease.expired().map(|e| e.holder),
            Some(None),
            "whereas one that said goodbye had its session closed by the DELETE"
        );
    }
}
