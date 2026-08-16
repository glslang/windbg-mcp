//! windbg-mcp — an MCP server exposing WinDbg/DbgEng (live user-mode, kernel, crash dumps,
//! and Time Travel Debugging) to MCP clients over stdio.
//!
//! The process runs in one of two roles. Started normally it is the **supervisor**: it speaks
//! MCP on stdio, holds the tool surface, and never loads DbgEng. Re-executed with
//! [`worker::WORKER_FLAG`] it is an **engine worker**, owning exactly one debug session — which
//! is what dbgeng.dll's one-session-per-process rule makes the natural unit, and what lets a
//! session that cannot be unwound be killed without taking the server with it.
//!
//! There is also a third, which is not a server at all: [`cast::RENDER_FLAG`] turns a recorded
//! transcript into a terminal recording and exits. It touches neither DbgEng nor MCP, and it is
//! here rather than in a second binary because it reads a format this crate defines — a renderer
//! that could drift out of step with the writer is a renderer that will.

mod batch;
mod cast;
mod engine;
mod kdconn;
mod proto;
mod record;
mod server;
mod structured;
mod triage;
mod ttd;
mod walk;
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
    if let Some(at) = args.iter().position(|arg| arg == cast::RENDER_FLAG) {
        // Before the runtime: this reads a file and writes a file, and neither wants one.
        return render_cast(&args[at + 1..]);
    }

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(serve())
}

/// The renderer role: a transcript in, an asciicast out.
///
/// The one place in this binary that prints to standard output, and it is safe to: this role
/// never speaks MCP, so there is no JSON-RPC transport to corrupt. It exits before `serve` is ever
/// reached.
fn render_cast(args: &[String]) -> Result<()> {
    let options = match cast::Options::parse(args) {
        Ok(options) => options,
        Err(why) => anyhow::bail!("{why}\n\n{}", cast::USAGE),
    };
    let summary = cast::render(&options).map_err(|e| anyhow::anyhow!("{e}"))?;
    println!(
        "wrote {} — {} frame(s) from {} record(s), {:.1}s of session{}",
        options.output.display(),
        summary.frames,
        summary.records,
        summary.duration_ms as f64 / 1000.0,
        // Worth saying, because it explains a recording longer than any one session was: a
        // transcript is appended to, and the runs are laid end to end.
        match summary.runs {
            0 | 1 => String::new(),
            runs => format!(" across {runs} server runs"),
        }
    );
    // Loud, because it means part of the session is missing from the recording, and a renderer
    // that mentioned it only in a return value nobody reads would be hiding that.
    if summary.unreadable > 0 {
        println!(
            "note: {} line(s) of `{}` could not be read and were skipped — the usual cause is a \
             transcript whose last record was cut short by the server exiting mid-write",
            summary.unreadable,
            options.input.display()
        );
    }
    Ok(())
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
    // Opened before anything is served, so the transcript's first record is this run starting
    // rather than whatever the first tool call happened to be.
    let sessions = Sessions::new(call_timeout()).recording(record::Recorder::from_env());
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
