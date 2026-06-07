//! windbg-mcp — an MCP server exposing WinDbg/DbgEng (live user-mode, kernel,
//! crash dumps, and Time Travel Debugging) to MCP clients over stdio.
//!
//! The DbgEng engine is driven through win-kexp's `dbgeng` bindings on a dedicated
//! worker thread; tools are exposed via the official `rmcp` SDK.

mod engine;
mod server;
mod ttd;

use std::time::Duration;

use anyhow::Result;
use rmcp::ServiceExt;
use rmcp::transport::stdio;
use tracing_subscriber::EnvFilter;

use crate::engine::EngineHandle;
use crate::server::WindbgServer;

/// Upper bound for any single debugger operation before the tool call reports a timeout.
const ENGINE_CALL_TIMEOUT: Duration = Duration::from_secs(300);

#[tokio::main]
async fn main() -> Result<()> {
    // stdout is the JSON-RPC transport, so all logging must go to stderr.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let engine = EngineHandle::spawn(ENGINE_CALL_TIMEOUT);
    let server = WindbgServer::new(engine);

    tracing::info!("windbg-mcp starting on stdio");
    let service = server.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
