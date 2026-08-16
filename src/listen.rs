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
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use tokio::net::TcpListener;

use crate::engine::Sessions;
use crate::server::WindbgServer;

/// Turns this process into the listener instead of the stdio server.
pub const LISTEN_FLAG: &str = "--listen";

/// Where the bearer token is read from. An environment variable rather than an argument, because a
/// command line is readable by every process on the machine — including a `launch`ed debuggee.
const TOKEN_ENV: &str = "WINDBG_MCP_LISTEN_TOKEN";

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
    /// When the sessions are released if nothing renews first. `None` means there is nothing to
    /// release and nothing to wait for.
    deadline: Option<Instant>,
}

/// What the tenancy gate decided about one request.
#[derive(Debug, PartialEq, Eq)]
enum Admission {
    /// Hand it to the MCP service.
    Serve,
    /// Someone else holds the server.
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

    /// Decides whether a request may be served, and renews the lease if so.
    ///
    /// `session` is the request's `Mcp-Session-Id`; its absence means a client opening a new
    /// session, which is the only moment tenancy is actually contested.
    fn admit(&self, session: Option<&str>) -> Admission {
        let mut state = self.state();
        match (session, state.holder.as_deref()) {
            // The holder, still talking.
            (Some(id), Some(held)) if id == held => {
                state.deadline = Some(Instant::now() + self.grace);
                Admission::Serve
            }
            // A session id nobody holds. Let the service answer — it knows whether that session
            // exists, and a 404 from it is a better answer than a guess from here.
            (Some(_), _) => Admission::Serve,
            // A new client, and nobody is attached: it may take the server, and inherits whatever
            // the last one left open.
            (None, None) => Admission::Serve,
            // A new client while someone holds it.
            (None, Some(_)) => Admission::Occupied,
        }
    }

    /// Records that a client took the server, once the service has minted its session id.
    ///
    /// Returns whether this was an **adoption** — a new client picking up sessions a previous one
    /// left inside the grace — which is worth a log line because the alternative reading, that
    /// these are its own sessions, is wrong in a way that matters when it ends one.
    fn take(&self, id: &str) -> bool {
        let mut state = self.state();
        let adopted = state.holder.is_none() && state.deadline.is_some();
        state.holder = Some(id.to_string());
        state.deadline = Some(Instant::now() + self.grace);
        adopted
    }

    /// The holder said goodbye. The sessions stay; the clock starts.
    fn released(&self, id: &str) {
        let mut state = self.state();
        if state.holder.as_deref() == Some(id) {
            state.holder = None;
            state.deadline = Some(Instant::now() + self.grace);
        }
    }

    /// Whether the lease has run out, clearing it if so.
    ///
    /// Clears under the same lock that reads it, so a client connecting exactly now is either
    /// admitted before this and renews the deadline, or arrives after and finds a vacant server —
    /// never admitted against a lease this is about to act on. That is the race
    /// [`Sessions::release_leased`] warns it does not handle itself.
    fn expired(&self) -> bool {
        let mut state = self.state();
        match state.deadline {
            Some(at) if Instant::now() >= at => {
                state.holder = None;
                state.deadline = None;
                true
            }
            _ => false,
        }
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

    let mcp = {
        let sessions = sessions.clone();
        Arc::new(StreamableHttpService::new(
            move || Ok(WindbgServer::new(sessions.clone())),
            Arc::new(LocalSessionManager::default()),
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

    tokio::spawn(sweep(sessions.clone(), lease.clone()));

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

    if let Some(id) = response
        .headers()
        .get(SESSION_HEADER)
        .and_then(|v| v.to_str().ok())
        && lease.take(id)
    {
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
async fn sweep(sessions: Sessions, lease: Arc<Lease>) {
    loop {
        tokio::time::sleep(SWEEP).await;
        if lease.expired() {
            tracing::info!("a client's lease ran out; releasing the sessions it left open");
            sessions.release_leased().await;
        }
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

    /// One client at a time, and the contest is only ever over a *new* session.
    #[test]
    fn a_second_client_is_refused_while_the_first_holds_the_server() {
        let lease = lease();
        assert_eq!(lease.admit(None), Admission::Serve, "nobody holds it yet");
        lease.take("session-a");

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
            Admission::Serve,
            "an unknown session id is the service's to reject, not the gate's"
        );
    }

    /// A returning client finds what it left, and is told that is what happened.
    #[test]
    fn a_client_returning_inside_the_grace_adopts_rather_than_starts_fresh() {
        let lease = lease();
        lease.admit(None);
        assert!(
            !lease.take("session-a"),
            "the first client adopts nothing — there was nothing open"
        );

        lease.released("session-a");
        assert_eq!(
            lease.admit(None),
            Admission::Serve,
            "the server is free again the moment the holder lets go"
        );
        assert!(
            lease.take("session-b"),
            "and the next client is told it inherited the sessions still open"
        );
    }

    /// Letting go is not the same as expiring: the sessions are still there to come back to.
    #[test]
    fn letting_go_starts_the_clock_rather_than_releasing_anything() {
        let lease = lease();
        lease.admit(None);
        lease.take("session-a");
        lease.released("session-a");

        assert!(
            !lease.expired(),
            "a client that said goodbye has its whole grace to change its mind"
        );
        assert!(lease.state().deadline.is_some(), "and the clock is running");
    }

    /// A goodbye from something that is not the holder changes nothing.
    #[test]
    fn only_the_holder_can_let_go() {
        let lease = lease();
        lease.admit(None);
        lease.take("session-a");
        lease.released("session-b");
        assert_eq!(
            lease.state().holder.as_deref(),
            Some("session-a"),
            "a stray DELETE must not hand the server to whoever sent it"
        );
    }

    /// Expiry clears the holder as well as the deadline, so the next client is not refused by a
    /// tenancy nobody is in.
    #[test]
    fn an_expired_lease_leaves_the_server_vacant() {
        let lease = Lease::new(Duration::from_millis(1), Duration::from_micros(1))
            .expect("a grace longer than the budget");
        lease.admit(None);
        lease.take("session-a");
        std::thread::sleep(Duration::from_millis(5));

        assert!(lease.expired(), "the grace is spent");
        assert!(
            !lease.expired(),
            "and expiry is reported once, not on every sweep"
        );
        assert_eq!(lease.state().holder, None);
        assert_eq!(lease.admit(None), Admission::Serve);
    }
}
