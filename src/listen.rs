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
struct Lease {
    grace: Duration,
    /// Consulted before tenancy changes hands, never for anything else.
    ///
    /// The listener otherwise knows nothing about debug sessions — but "may this client have the
    /// server" cannot be answered from HTTP alone, because an engine job outlives the request that
    /// asked for it.
    sessions: Sessions,
    state: Mutex<Tenancy>,
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
    epoch: u64,
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.lease.leave(self.epoch);
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

/// What the tenancy gate decided about one request.
#[derive(Debug, PartialEq, Eq)]
enum Admission {
    /// Hand it to the MCP service.
    Serve(Admitted),
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
                state.in_flight += 1;
                Admission::Serve(Admitted {
                    claim: None,
                    epoch: state.epoch,
                })
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
            (Some(_), None) if state.claim.is_none() => {
                state.in_flight += 1;
                let epoch = state.epoch;
                Admission::Serve(Admitted {
                    claim: Some(state.claim(self.grace)),
                    epoch,
                })
            }
            // A new client, and nobody attached or attaching: it reserves the server here, and
            // inherits whatever the last one left open.
            (None, None) if state.claim.is_none() => {
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
    ) -> Settled {
        let mut state = self.state();
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
    fn released(&self, id: &str) {
        let mut state = self.state();
        if state.holder.as_deref() != Some(id) {
            return;
        }
        state.deadline = Some(Instant::now() + self.grace);
        // The `DELETE` itself is in flight, so this is always the deferred path in practice — and
        // that is the point: tenancy is given up when the work admitted under it drains, which is
        // at worst this request and at best a tool call still running on another connection.
        state.farewell = true;
        drop(state);
        self.try_give_up();
    }

    /// One admitted request finished, however it finished.
    ///
    /// `epoch` is the tenancy it was admitted under. A request that outlived a teardown belongs to
    /// a tenancy that no longer exists, and counting it out of the current one would subtract work
    /// it never did — enough for a concurrent goodbye to see zero while a tool call is still
    /// running.
    fn leave(&self, epoch: u64) {
        let mut state = self.state();
        if state.epoch != epoch {
            return;
        }
        state.in_flight = state.in_flight.saturating_sub(1);
        drop(state);
        self.try_give_up();
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

    /// Hands the server over, if a goodbye is outstanding and nothing is still using it.
    ///
    /// Two conditions, and they are not the same one. `in_flight` is HTTP: the requests this holder
    /// was admitted for. `Sessions::busy` is the engine: a job survives the request that queued it,
    /// so a dropped future or a timed-out call leaves work running against a target the next client
    /// would otherwise be handed. Attempted on every sweep as well as on the two events, because
    /// the engine going idle is not an event this side can see.
    fn try_give_up(&self) {
        let mut state = self.state();
        if !state.farewell || state.in_flight != 0 {
            return;
        }
        drop(state);
        if self.sessions.busy() {
            return;
        }
        state = self.state();
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
        _ => longest_quiet_call(call_timeout) + GRACE_HEADROOM,
    };
    let lease = Arc::new(Lease::new(grace, call_timeout, sessions.clone())?);

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

    tokio::spawn(sweep(sessions.clone(), lease.clone(), manager.clone()));

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                tracing::warn!("accept failed: {e}");
                continue;
            }
        };
        let mcp = mcp.clone();
        let manager = manager.clone();
        let lease = lease.clone();
        let token = token.clone();
        tokio::spawn(async move {
            let serve = service_fn(move |req| {
                gate(
                    req,
                    mcp.clone(),
                    manager.clone(),
                    lease.clone(),
                    token.clone(),
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

    let admitted = match lease.admit(session.as_deref()) {
        Admission::Serve(admitted) => admitted,
        Admission::Occupied => {
            tracing::warn!("refused a second client from {peer}: this server is already held");
            return Ok(refuse(
                StatusCode::CONFLICT,
                "another client holds this server; it serves one at a time",
            ));
        }
    };
    // From here every exit — a reply, a refusal, or this future being cancelled — counts the
    // request out, and a goodbye waiting on it completes when the last one does.
    let _in_flight = InFlight {
        lease: lease.clone(),
        epoch: admitted.epoch,
    };

    // A DELETE is the client saying it is done. Read before the service handles it, because
    // afterwards the request is gone; whether it *was* a departure also depends on the answer.
    let method = req.method().clone();

    let response = mcp.handle(req).await;

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
    ) {
        Settled::Kept { adopted: true } => {
            tracing::info!("a client attached and adopted the sessions the previous one left open");
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
        lease.released(&id);
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
        // The engine may have gone idle since the last tick, which is not something the HTTP side
        // is told about.
        lease.try_give_up();
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

    const CALL: Duration = Duration::from_secs(300);

    /// A grace comfortably past the opener's end-to-end bound.
    fn lease() -> Lease {
        Lease::new(
            longest_quiet_call(CALL) + Duration::from_secs(60),
            CALL,
            Sessions::new(CALL),
        )
        .expect("workable")
    }

    /// A lease whose grace expires almost immediately, for the sweep paths.
    fn brief() -> Lease {
        Lease {
            grace: Duration::from_millis(1),
            sessions: Sessions::new(CALL),
            state: Mutex::new(Tenancy::default()),
        }
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
        }
    }

    /// One whole request: admitted, settled, and finished. Every admitted request is counted out
    /// again in `gate` by a guard, so a test that settles without finishing is modelling a request
    /// that never came back.
    fn request(lease: &Lease, session: Option<&str>, minted: Option<&str>, ok: bool) -> Settled {
        let it = admitted(lease.admit(session));
        let settled = lease.settle(it.claim, session, minted, ok);
        lease.leave(it.epoch);
        settled
    }

    /// A client's `DELETE`, which is itself an admitted request.
    fn goodbye(lease: &Lease, id: &str) {
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
        assert!(!lease.sessions.busy());
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

    /// A claim keeps alive the sessions it is adopting.
    #[test]
    fn reserving_the_server_renews_what_the_claim_is_adopting() {
        let lease = Lease {
            grace: Duration::from_millis(60),
            sessions: Sessions::new(CALL),
            state: Mutex::new(Tenancy::default()),
        };
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
            matches!(lease.admit(None), Admission::Occupied),
            "the server is not vacant yet — the sessions are still being let go"
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
