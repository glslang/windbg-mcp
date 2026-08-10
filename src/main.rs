//! windbg-mcp — an MCP server exposing WinDbg/DbgEng (live user-mode, kernel, crash dumps,
//! and Time Travel Debugging) to MCP clients over stdio.
//!
//! The process runs in one of two roles. Started normally it is the **supervisor**: it speaks
//! MCP on stdio, holds the tool surface, and never loads DbgEng. Re-executed with
//! [`worker::WORKER_FLAG`] it is an **engine worker**, owning exactly one debug session — which
//! is what dbgeng.dll's one-session-per-process rule makes the natural unit, and what lets a
//! session that cannot be unwound be killed without taking the server with it.

mod batch;
mod engine;
mod kdconn;
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
    let args: Vec<String> = std::env::args().collect();
    let is_worker = args.iter().any(|arg| arg == worker::WORKER_FLAG);
    init_logging();
    if is_worker {
        // The rest of the command line is the worker's half of the protocol channel — two
        // inherited pipe handles, which is why a worker started by hand cannot get anywhere.
        worker::run(&args);
    }

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(serve())
}

/// stdout is the JSON-RPC transport, so all logging must go to stderr. A worker's stderr is
/// inherited from the supervisor, so both roles' logs land in the same place an MCP client
/// already reads.
///
/// Targets stay on for both, which is what tells them apart: a worker's records carry
/// `windbg_mcp::worker`, the supervisor's `windbg_mcp::engine` and friends. Suppressing them for
/// workers — the first cut here — identified a worker only by the *absence* of a field, which is
/// no help at all when two processes are interleaving lines in one stream.
fn init_logging() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
}

async fn serve() -> Result<()> {
    let sessions = Sessions::new(call_timeout());
    let server = WindbgServer::new(sessions.clone());

    tracing::info!("windbg-mcp starting on stdio");
    let service = server.serve(stdio()).await?;
    let outcome = service.waiting().await;

    // The client disconnected. Every worker is a process holding a debug session — and, for a
    // launch or an attach, a debuggee whose fate is tied to its debugger — so none may outlive
    // the connection that opened it. Released rather than killed: a live kernel that is merely
    // killed is left *frozen*, which outlives the connection in the worst possible way.
    sessions.shutdown().await;
    outcome?;
    Ok(())
}
