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

use std::convert::Infallible;
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

/// Overrides how long a client may be silent before its sessions are released, in whole seconds.
const GRACE_ENV: &str = "WINDBG_MCP_LEASE_GRACE_SECS";

/// How much longer than one call's budget a lease lasts, when nothing says otherwise.
///
/// The grace has to cover a call that reports nothing while it runs, and the longest of those is
/// bounded by the call timeout — so the default is defined *from* that timeout rather than as a
/// figure of its own, and a host that raises one raises the other with it.
const GRACE_OVER_CALL: Duration = Duration::from_secs(60);

/// How often the SSE stream says it is still there while a call runs quietly.
const SSE_KEEP_ALIVE: Duration = Duration::from_secs(15);

/// How often the sweeper looks for a lease that has run out. Fine enough that a released target is
/// released promptly, coarse enough to cost nothing while idle.
const SWEEP: Duration = Duration::from_secs(5);

/// The header carrying a client's MCP session, which is what identifies the holder.
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

/// The lease: who holds this server, and until when.
///
/// One lock over both, because they are one decision. "Is there a holder" and "has it expired" read
/// together or a request can be admitted against a holder the sweeper is releasing.
#[derive(Debug)]
struct Lease {
    grace: Duration,
    state: Mutex<Tenancy>,
}

#[derive(Debug, Default)]
struct Tenancy {
    /// The MCP session that owns this server. `None` while nobody is attached — which is *not* the
    /// same as nothing being open, since a departed client's sessions live on until `deadline`.
    holder: Option<String>,
    /// A client is opening a session and has not been given an id yet.
    ///
    /// Without this the gate only *observes* tenancy, and two `initialize` requests arriving
    /// together both see a vacant server, both get sessions, and the second silently replaces the
    /// first as holder while the first stays serviceable — two clients on a registry whose handles,
    /// capacity and `end_session` are all global. Admission has to **reserve**.
    claiming: bool,
    /// A lease has run out and its sessions are being released.
    ///
    /// Held across the release, because the teardown is not instant: clearing the holder and then
    /// releasing would leave a window where the server looks vacant and a new client can start
    /// using a session the sweeper is about to close underneath it.
    releasing: bool,
    /// When the sessions are released if nothing renews first. `None` means there is nothing to
    /// release and nothing to wait for.
    deadline: Option<Instant>,
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
    fn claim(&mut self, grace: Duration) {
        self.claiming = true;
        self.deadline = Some(Instant::now() + grace);
    }
}

/// What the tenancy gate decided about one request.
#[derive(Debug, PartialEq, Eq)]
enum Admission {
    /// Hand it to the MCP service.
    Serve,
    /// Someone else holds the server, is taking it, or is being cleaned up after.
    Occupied,
}

impl Lease {
    /// Fails rather than starting when the grace could expire inside a call.
    ///
    /// The failure mode this prevents is silent and expensive: a `crash_triage` or a pool walk
    /// sends nothing for minutes, so a grace shorter than the call budget reads it as an absent
    /// client and releases the very session the call is running against. Refusing at startup makes
    /// that a message an operator sees once, instead of a target that goes away mid-analysis.
    fn new(grace: Duration, call_timeout: Duration) -> Result<Self> {
        if grace <= call_timeout {
            bail!(
                "the lease grace ({grace:?}) must be longer than one call's budget \
                 ({call_timeout:?}), or a call that runs quietly to its deadline looks like a \
                 client that went away — and its own session would be released underneath it. \
                 Raise {GRACE_ENV}, or lower WINDBG_MCP_CALL_TIMEOUT_SECS."
            );
        }
        Ok(Self {
            grace,
            state: Mutex::new(Tenancy::default()),
        })
    }

    fn state(&self) -> std::sync::MutexGuard<'_, Tenancy> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Decides whether a request may be served, **reserving** the server when one is taking it.
    ///
    /// `session` is the request's `Mcp-Session-Id`; its absence means a client opening a new
    /// session, which is the only moment tenancy is contested. Every decision is made under one
    /// lock, so the answer a request gets is the state it will be served against.
    fn admit(&self, session: Option<&str>) -> Admission {
        let mut state = self.state();
        // Nothing is served while a teardown is in flight. Briefly refusing a client that could
        // have been served costs a reconnect; serving one costs it the session mid-call.
        if state.releasing {
            return Admission::Occupied;
        }
        match (session, state.holder.as_deref()) {
            // The holder, still talking.
            (Some(id), Some(held)) if id == held => {
                state.deadline = Some(Instant::now() + self.grace);
                Admission::Serve
            }
            // A session id belonging to someone else. This is the arm that made the race above
            // persist rather than pass: serving it leaves both clients working.
            (Some(_), Some(_)) => Admission::Occupied,
            // A session id with nobody holding the server — a client resuming what it left inside
            // the grace. Reserved like an `initialize`, because it is the same contest: a lease
            // expiry leaves the old session id valid in the service, so a resume can race a fresh
            // client and both would pass a gate that only served them. The holder is still not
            // taken until `settle` hears the session was real, or a stale id would lock the server
            // out for a whole grace period.
            (Some(_), None) if !state.claiming => {
                state.claim(self.grace);
                Admission::Serve
            }
            // A new client, and nobody attached or attaching: it reserves the server here, and
            // inherits whatever the last one left open.
            (None, None) if !state.claiming => {
                state.claim(self.grace);
                Admission::Serve
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
    fn settle(&self, requested: Option<&str>, minted: Option<&str>, ok: bool) -> bool {
        let mut state = self.state();
        // Unconditionally, before anything else: a reservation outliving the request that took it
        // is a server nobody can claim. Every route out of here has resolved it — the arms below
        // decide who holds the server, not whether the claim is over.
        state.claiming = false;
        // A teardown that started while this request was being handled has already decided the
        // sessions are going. Installing a holder now would hand a client something being released
        // out from under it, and the client is better served by being told to come back.
        if state.releasing {
            return false;
        }
        let adopted = state.left_open;
        match (minted, requested) {
            // An `initialize` that produced a session: the claim becomes a holder.
            (Some(id), _) => {
                state.holder = Some(id.to_string());
                state.deadline = Some(Instant::now() + self.grace);
                state.left_open = false;
                adopted
            }
            // A resumed session the service accepted: the returning client is the holder again.
            (None, Some(id)) if ok && state.holder.is_none() => {
                state.holder = Some(id.to_string());
                state.deadline = Some(Instant::now() + self.grace);
                state.left_open = false;
                adopted
            }
            // Anything else, including an `initialize` that failed: the reservation is already
            // given back above, and nobody took the server.
            _ => false,
        }
    }

    /// The holder said goodbye. The sessions stay; the clock starts.
    fn released(&self, id: &str) {
        let mut state = self.state();
        if state.holder.as_deref() == Some(id) {
            state.holder = None;
            state.deadline = Some(Instant::now() + self.grace);
            state.left_open = true;
        }
    }

    /// Whether the lease has run out, **claiming the teardown** if so.
    ///
    /// The server is marked `releasing` under the same lock that reads the deadline, and stays that
    /// way until [`Self::released_leases`] says the teardown is done. That is what closes the
    /// window [`Sessions::release_leased`] warns it does not close itself: between deciding to
    /// release and having released, no client can be admitted to the sessions being released.
    fn expired(&self) -> Option<Expired> {
        let mut state = self.state();
        match state.deadline {
            Some(at) if Instant::now() >= at => {
                let holder = state.holder.take();
                state.deadline = None;
                // Including a claim. A request whose connection died before `settle` would
                // otherwise leave this set for ever — no client could take the server, and no
                // expiry would ever clear it either, because a claim renews the deadline it would
                // have to outlive. Bounded by one grace, and this is the bound.
                state.claiming = false;
                state.left_open = false;
                state.releasing = true;
                Some(Expired { holder })
            }
            _ => None,
        }
    }

    /// The teardown is done; the server may be taken again.
    fn released_leases(&self) {
        self.state().releasing = false;
    }
}

/// Serves MCP over HTTP until the process is asked to stop.
pub async fn serve(sessions: Sessions, addr: SocketAddr, call_timeout: Duration) -> Result<()> {
    let token = std::env::var(TOKEN_ENV).map_err(|_| {
        anyhow::anyhow!(
            "{TOKEN_ENV} is not set. The listener will not start without a bearer token: it \
             exposes every tool this server has, including the ones that write to a live kernel."
        )
    })?;
    if token.trim().is_empty() {
        bail!("{TOKEN_ENV} is set but empty; that is not a token.");
    }

    let grace = match std::env::var(GRACE_ENV).ok().and_then(|v| v.parse().ok()) {
        Some(secs) if secs > 0 => Duration::from_secs(secs),
        _ => call_timeout + GRACE_OVER_CALL,
    };
    let lease = Arc::new(Lease::new(grace, call_timeout)?);

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

    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("cannot bind {addr}"))?;
    tracing::info!(
        "windbg-mcp listening on http://{addr} (lease grace {grace:?}, one client at a time)"
    );

    tokio::spawn(sweep(sessions.clone(), lease.clone(), manager));

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                tracing::warn!("accept failed: {e}");
                continue;
            }
        };
        let mcp = mcp.clone();
        let lease = lease.clone();
        let token = token.clone();
        tokio::spawn(async move {
            let serve =
                service_fn(move |req| gate(req, mcp.clone(), lease.clone(), token.clone(), peer));
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
    lease: Arc<Lease>,
    token: String,
    peer: SocketAddr,
) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
    if !authorised(&req, &token) {
        // No detail: an unauthenticated caller learns that it is unauthenticated and nothing about
        // what is here.
        tracing::warn!("rejected an unauthenticated request from {peer}");
        return Ok(refuse(StatusCode::UNAUTHORIZED, "unauthorized"));
    }

    let session = req
        .headers()
        .get(SESSION_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    if lease.admit(session.as_deref()) == Admission::Occupied {
        tracing::warn!("refused a second client from {peer}: this server is already held");
        return Ok(refuse(
            StatusCode::CONFLICT,
            "another client holds this server; it serves one at a time",
        ));
    }

    // A DELETE is the client saying it is done. Noted before the service handles it, because
    // afterwards the session is gone and there is nothing left to match the holder against.
    let goodbye = req.method() == hyper::Method::DELETE;

    let response = mcp.handle(req).await;

    let minted = response
        .headers()
        .get(SESSION_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    // Every admitted request settles, so a reservation is never left standing by a request that
    // did not become a session.
    if lease.settle(
        session.as_deref(),
        minted.as_deref(),
        response.status().is_success(),
    ) {
        tracing::info!("a client attached and adopted the sessions the previous one left open");
    }
    if goodbye && let Some(id) = session {
        lease.released(&id);
        tracing::info!("the client let go; its sessions are held for the grace period");
    }
    Ok(response)
}

fn authorised(req: &Request<Incoming>, token: &str) -> bool {
    req.headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .is_some_and(|presented| presented == token)
}

fn refuse(status: StatusCode, why: &str) -> Response<BoxBody<Bytes, Infallible>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::from(why.to_string())).boxed())
        // The builder only fails on a malformed status or header, and both are literals here.
        .expect("a constant response is well-formed")
}

/// Releases what an absent client left behind, once its lease runs out.
async fn sweep(sessions: Sessions, lease: Arc<Lease>, manager: Arc<LocalSessionManager>) {
    loop {
        tokio::time::sleep(SWEEP).await;
        let Some(expired) = lease.expired() else {
            continue;
        };
        tracing::info!("a client's lease ran out; releasing the sessions it left open");
        sessions.release_leased().await;
        // The debug sessions are the expensive half, but not the whole of it. A client that
        // vanished never sent the DELETE that closes its MCP session, so without this the service
        // keeps that session resident and its id accepted — and every disconnect-and-reconnect
        // cycle would add another one that no lease will ever sweep again.
        if let Some(id) = expired.holder
            && let Err(e) = manager.close_session(&id.into()).await
        {
            tracing::warn!("could not close the MCP session of the client that went away: {e}");
        }
        // Only now may the server be taken again: until this, an arriving client would be admitted
        // to sessions this release is closing.
        lease.released_leases();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lease() -> Lease {
        Lease::new(Duration::from_secs(360), Duration::from_secs(300)).expect("a workable grace")
    }

    /// The check that stops a long call from looking like an absent client.
    #[test]
    fn a_grace_that_could_expire_inside_a_call_is_refused_at_startup() {
        let call = Duration::from_secs(300);
        assert!(
            Lease::new(Duration::from_secs(120), call).is_err(),
            "120s of grace against a 300s call budget releases the session the call is using"
        );
        assert!(
            Lease::new(call, call).is_err(),
            "equal is not enough: the call may finish at its deadline, not before it"
        );
        assert!(Lease::new(call + Duration::from_secs(1), call).is_ok());
    }

    /// One client at a time — and admission has to *reserve*, not merely observe.
    #[test]
    fn a_second_client_is_refused_while_the_first_holds_the_server() {
        let lease = lease();
        assert_eq!(lease.admit(None), Admission::Serve, "nobody holds it yet");
        lease.settle(None, Some("session-a"), true);

        assert_eq!(
            lease.admit(None),
            Admission::Occupied,
            "a second client opening a session is refused"
        );
        assert_eq!(
            lease.admit(Some("session-a")),
            Admission::Serve,
            "while the holder keeps being served"
        );
        assert_eq!(
            lease.admit(Some("session-b")),
            Admission::Occupied,
            "and another client's session id is refused too — serving it is what would let a \
             racing second client keep working"
        );
    }

    /// The race the reservation exists for: two `initialize`s arriving together.
    ///
    /// Without it both see a vacant server, both get sessions, and the second replaces the first as
    /// holder while the first stays serviceable — two clients on a registry whose handles, capacity
    /// and `end_session` are all global.
    #[test]
    fn a_claim_in_flight_blocks_a_second_initialize() {
        let lease = lease();
        assert_eq!(lease.admit(None), Admission::Serve);
        assert_eq!(
            lease.admit(None),
            Admission::Occupied,
            "the first claim is not resolved yet, so the server is not free"
        );

        lease.settle(None, Some("session-a"), true);
        assert_eq!(lease.state().holder.as_deref(), Some("session-a"));
    }

    /// A claim that comes to nothing must give the server back.
    #[test]
    fn an_initialize_that_fails_does_not_hold_the_server_for_ever() {
        let lease = lease();
        assert_eq!(lease.admit(None), Admission::Serve);
        lease.settle(None, None, false);

        assert!(!lease.state().claiming, "the reservation was returned");
        assert_eq!(
            lease.admit(None),
            Admission::Serve,
            "so the next client can take the server"
        );
    }

    /// A returning client finds what it left, and is told that is what happened.
    #[test]
    fn a_client_returning_inside_the_grace_adopts_rather_than_starts_fresh() {
        let lease = lease();
        lease.admit(None);
        assert!(
            !lease.settle(None, Some("session-a"), true),
            "the first client adopts nothing — there was nothing open"
        );

        lease.released("session-a");
        assert_eq!(
            lease.admit(None),
            Admission::Serve,
            "the server is free again the moment the holder lets go"
        );
        assert!(
            lease.settle(None, Some("session-b"), true),
            "and the next client is told it inherited the sessions still open"
        );
    }

    /// A client resuming the session id it already had becomes the holder again — but only once the
    /// service has confirmed that session is real.
    #[test]
    fn a_resumed_session_takes_the_server_back_only_if_it_existed() {
        let lease = lease();
        lease.admit(None);
        lease.settle(None, Some("session-a"), true);
        lease.released("session-a");

        assert_eq!(lease.admit(Some("session-a")), Admission::Serve);
        lease.settle(Some("session-a"), None, false);
        assert_eq!(
            lease.state().holder,
            None,
            "a session id the service rejected must not lock the server out for a whole grace"
        );

        assert_eq!(lease.admit(Some("session-a")), Admission::Serve);
        lease.settle(Some("session-a"), None, true);
        assert_eq!(lease.state().holder.as_deref(), Some("session-a"));
    }

    /// Letting go is not the same as expiring: the sessions are still there to come back to.
    #[test]
    fn letting_go_starts_the_clock_rather_than_releasing_anything() {
        let lease = lease();
        lease.admit(None);
        lease.settle(None, Some("session-a"), true);
        lease.released("session-a");

        assert!(
            lease.expired().is_none(),
            "a client that said goodbye has its whole grace to change its mind"
        );
        assert!(lease.state().deadline.is_some(), "and the clock is running");
    }

    /// A goodbye from something that is not the holder changes nothing.
    #[test]
    fn only_the_holder_can_let_go() {
        let lease = lease();
        lease.admit(None);
        lease.settle(None, Some("session-a"), true);
        lease.released("session-b");
        assert_eq!(
            lease.state().holder.as_deref(),
            Some("session-a"),
            "a stray DELETE must not hand the server to whoever sent it"
        );
    }

    /// A resume is a contested claim too, not a free pass.
    ///
    /// After a lease expiry the old session id is still valid in the service, so a resume can race
    /// a fresh client. Both would pass a gate that only served them, and the stale one could run a
    /// tool against the global registry while the new client became the holder.
    #[test]
    fn a_resume_reserves_the_server_like_an_initialize_does() {
        let lease = lease();
        lease.admit(None);
        lease.settle(None, Some("session-a"), true);
        lease.released("session-a");

        assert_eq!(lease.admit(Some("session-a")), Admission::Serve);
        assert_eq!(
            lease.admit(None),
            Admission::Occupied,
            "a fresh client cannot slip in while a resume is being confirmed"
        );
    }

    /// Whatever a request turns out to be, it hands the reservation back.
    ///
    /// The leak this pins is the one the resume path introduced: taking the holder without
    /// resolving the claim leaves `claiming` set, and the next goodbye then makes the server
    /// permanently unclaimable — a server nobody can use and nothing will fix.
    #[test]
    fn every_settled_request_resolves_its_reservation() {
        let lease = lease();
        lease.admit(None);
        lease.settle(None, Some("session-a"), true);
        lease.released("session-a");

        lease.admit(Some("session-a"));
        lease.settle(Some("session-a"), None, true);
        assert!(!lease.state().claiming, "a resume that succeeded");

        lease.released("session-a");
        assert_eq!(
            lease.admit(None),
            Admission::Serve,
            "so the next client is not refused by a reservation nobody holds"
        );
    }

    /// A swept lease says what it left in the service, so the sweeper can close that too.
    #[test]
    fn a_swept_lease_reports_the_session_that_never_said_goodbye() {
        let lease = Lease::new(Duration::from_millis(1), Duration::from_micros(1))
            .expect("a grace longer than the budget");
        lease.admit(None);
        lease.settle(None, Some("session-a"), true);
        std::thread::sleep(Duration::from_millis(5));

        assert_eq!(
            lease.expired().map(|e| e.holder),
            Some(Some("session-a".to_string())),
            "a client that vanished leaves an MCP session nothing else will ever close"
        );

        // Whereas one that said goodbye had its session closed by the DELETE.
        let lease = Lease::new(Duration::from_millis(1), Duration::from_micros(1))
            .expect("a grace longer than the budget");
        lease.admit(None);
        lease.settle(None, Some("session-b"), true);
        lease.released("session-b");
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(lease.expired().map(|e| e.holder), Some(None));
    }

    /// A claim keeps alive the sessions it is adopting.
    ///
    /// Admission near the end of a grace would otherwise reserve the server and leave the previous
    /// client's deadline armed, so the sweeper could release the very sessions the request is being
    /// admitted to adopt — while `mcp.handle` is still running.
    #[test]
    fn reserving_the_server_renews_what_the_claim_is_adopting() {
        let lease = Lease::new(Duration::from_millis(60), Duration::from_micros(1))
            .expect("a grace longer than the budget");
        lease.admit(None);
        lease.settle(None, Some("session-a"), true);
        lease.released("session-a");
        std::thread::sleep(Duration::from_millis(40));

        assert_eq!(
            lease.admit(None),
            Admission::Serve,
            "still inside the grace"
        );
        std::thread::sleep(Duration::from_millis(40));
        assert!(
            lease.expired().is_none(),
            "the claim pushed the deadline out; without that the sweep would have released the \
             sessions this request is in the middle of adopting"
        );
    }

    /// A request that never settles cannot wedge the server for ever.
    ///
    /// The reservation introduced this: a connection dropped inside `mcp.handle` never reaches
    /// `settle`, so without expiry clearing the claim, no client could take the server and no sweep
    /// would ever clear it — a claim renews the deadline an expiry would have to outlive.
    #[test]
    fn a_claim_whose_request_died_is_cleared_by_the_grace() {
        let lease = Lease::new(Duration::from_millis(1), Duration::from_micros(1))
            .expect("a grace longer than the budget");
        assert_eq!(lease.admit(None), Admission::Serve);
        std::thread::sleep(Duration::from_millis(5));

        assert!(
            lease.expired().is_some(),
            "the claim's own deadline ran out"
        );
        assert!(!lease.state().claiming, "and took the reservation with it");
        lease.released_leases();
        assert_eq!(lease.admit(None), Admission::Serve);
    }

    /// A teardown already under way wins over a claim settling into it.
    #[test]
    fn a_claim_that_settles_during_a_teardown_does_not_take_the_server() {
        let lease = Lease::new(Duration::from_millis(1), Duration::from_micros(1))
            .expect("a grace longer than the budget");
        lease.admit(None);
        lease.settle(None, Some("session-a"), true);
        std::thread::sleep(Duration::from_millis(5));
        assert!(lease.expired().is_some());

        // The request that was in flight when the sweep started now comes back.
        assert!(!lease.settle(None, Some("session-b"), true));
        assert_eq!(
            lease.state().holder,
            None,
            "a client must not be handed sessions that are being released out from under it"
        );
    }

    /// Nothing is admitted between deciding to release and having released.
    ///
    /// The window this closes is narrow and expensive: a client admitted there starts using a
    /// session the sweeper is in the middle of closing, and the call dies underneath it.
    #[test]
    fn nothing_is_admitted_while_the_teardown_runs() {
        let lease = Lease::new(Duration::from_millis(1), Duration::from_micros(1))
            .expect("a grace longer than the budget");
        lease.admit(None);
        lease.settle(None, Some("session-a"), true);
        std::thread::sleep(Duration::from_millis(5));

        assert!(lease.expired().is_some(), "the grace is spent");
        assert_eq!(
            lease.admit(None),
            Admission::Occupied,
            "and the server is not vacant yet — the sessions are still being let go"
        );

        lease.released_leases();
        assert_eq!(
            lease.admit(None),
            Admission::Serve,
            "only once the teardown is done"
        );
    }

    /// Expiry is a one-shot: the deadline is consumed by the sweep that acts on it.
    #[test]
    fn expiry_is_reported_once_rather_than_on_every_sweep() {
        let lease = Lease::new(Duration::from_millis(1), Duration::from_micros(1))
            .expect("a grace longer than the budget");
        lease.admit(None);
        lease.settle(None, Some("session-a"), true);
        std::thread::sleep(Duration::from_millis(5));

        assert!(lease.expired().is_some(), "the grace is spent");
        assert!(
            lease.expired().is_none(),
            "and expiry is reported once, not on every sweep — the sweeper runs every few \
             seconds, and a second `true` would release an already-released set of sessions on \
             each pass"
        );
        assert_eq!(lease.state().holder, None);
    }
}
