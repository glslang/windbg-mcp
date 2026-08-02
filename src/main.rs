//! windbg-mcp — an MCP server exposing WinDbg/DbgEng (live user-mode, kernel, crash dumps,
//! and Time Travel Debugging) to MCP clients over stdio.
//!
//! The process runs in one of two roles. Started normally it is the **supervisor**: it speaks
//! MCP on stdio, holds the tool surface, and never loads DbgEng. Re-executed with
//! [`worker::WORKER_FLAG`] it is an **engine worker**, owning exactly one debug session — which
//! is what dbgeng.dll's one-session-per-process rule makes the natural unit, and what lets a
//! session that cannot be unwound be killed without taking the server with it.

mod engine;
mod proto;
mod server;
mod ttd;
mod worker;

use std::time::Duration;

use anyhow::Result;
use rmcp::ServiceExt;
use rmcp::transport::stdio;
use tracing_subscriber::EnvFilter;

use crate::engine::Sessions;
use crate::server::WindbgServer;

/// Upper bound for any single debugger operation before the tool call reports a timeout.
const ENGINE_CALL_TIMEOUT: Duration = Duration::from_secs(300);

/// Overrides [`ENGINE_CALL_TIMEOUT`], in whole seconds.
///
/// Exists because the budget is also what arms win-kexp's watchdog on the bounded-command path,
/// so the only honest way to exercise that arithmetic end to end is to shrink it — a test that
/// waits out the 300s default is a test nobody runs. Operationally it is the knob for a host
/// where the default is wrong in either direction (a slow symbol server, or an operator who
/// wants to hear about a stuck call sooner).
const CALL_TIMEOUT_ENV: &str = "WINDBG_MCP_CALL_TIMEOUT_SECS";

fn call_timeout() -> Duration {
    match std::env::var(CALL_TIMEOUT_ENV)
        .ok()
        .and_then(|v| v.parse().ok())
    {
        Some(secs) if secs > 0 => Duration::from_secs(secs),
        _ => ENGINE_CALL_TIMEOUT,
    }
}

fn main() -> Result<()> {
    // Read the role before anything else: a worker has no use for a tokio runtime, and its
    // engine thread must be free to block in DbgEng indefinitely.
    let is_worker = std::env::args().any(|arg| arg == worker::WORKER_FLAG);
    init_logging(is_worker);
    if is_worker {
        worker::run();
    }

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(serve())
}

/// stdout is the JSON-RPC transport, so all logging must go to stderr. A worker's stderr is
/// inherited from the supervisor, so both roles' logs land in the same place an MCP client
/// already reads — tagged, so they can be told apart.
fn init_logging(is_worker: bool) {
    let builder = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        );
    if is_worker {
        builder.with_target(false).init();
    } else {
        builder.init();
    }
}

async fn serve() -> Result<()> {
    let sessions = Sessions::new(call_timeout());
    let server = WindbgServer::new(sessions.clone());

    tracing::info!("windbg-mcp starting on stdio");
    let service = server.serve(stdio()).await?;
    let outcome = service.waiting().await;

    // The client disconnected. Every worker is a process holding a debug session — and, for a
    // launch or an attach, a debuggee whose fate is tied to its debugger — so none may outlive
    // the connection that opened it.
    sessions.shutdown();
    outcome?;
    Ok(())
}
