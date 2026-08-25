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
mod client;
mod engine;
mod kdconn;
mod listen;
mod logbridge;
mod progress;
mod proto;
mod record;
mod schema;
mod server;
mod service;
mod structured;
mod toolset;
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

/// What this build calls itself: the crate version, plus the git revision it was built from.
///
/// `0.11.0+g1a2b3c4`, or `0.11.0+g1a2b3c4-dirty`, or a bare `0.11.0` where `build.rs` could not ask
/// git. Reported in two places that had the crate version alone and are the two a reader reaches
/// for when asking *which* build did something: MCP `serverInfo.version`, and the `Start` record of
/// a transcript.
///
/// **The suffix is what makes it an identity rather than a floor.** A crate version moves on
/// release, so every build between two of them is indistinguishable — including the pairs that
/// matter most, since the behaviour a bench or a bug report turns on is often a changed *result*
/// rather than a changed API. `FOLLOWUPS.md` item 46 is the case that forced it: #217 changed what
/// an opener's summary says, which no version, tool count or surface byte count can see.
///
/// It is semver build metadata, ignored for precedence, so a consumer comparing versions reads up
/// to the `+` and is unaffected.
pub const BUILD_VERSION: &str = if env!("WINDBG_MCP_BUILD").is_empty() {
    env!("CARGO_PKG_VERSION")
} else {
    concat!(env!("CARGO_PKG_VERSION"), "+", env!("WINDBG_MCP_BUILD"))
};

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

pub(crate) fn call_timeout() -> Duration {
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
    // A service has no console, so its stderr goes nowhere at all — and the failure most worth
    // seeing is a listener that refuses to start, which happens before `server_log` can be asked
    // anything. Decided here because logging is initialised before the role is acted on.
    let to_file =
        matches!(service::requested(&args), Some(service::Role::Run)).then(service::log_path);
    init_logging(is_worker, to_file);
    if is_worker {
        // The rest of the command line is the worker's half of the protocol channel — two
        // inherited pipe handles, which is why a worker started by hand cannot get anywhere.
        worker::run(&args);
    }
    if let Some(at) = args.iter().position(|arg| arg == cast::RENDER_FLAG) {
        // Before the runtime: this reads a file and writes a file, and neither wants one.
        return render_cast(&args[at + 1..]);
    }

    // Also before the runtime, and for a sharper reason than the renderer's. Installing touches the
    // SCM and nothing else. Running *as* a service has to build its runtime inside the SCM's own
    // dispatcher thread rather than around it, so the one thing this must not do is start one here.
    if let Some(role) = service::requested(&args) {
        return match role {
            service::Role::Install => service::install(
                listen_address(&args)?,
                // Validated here, by the same parser the service will use at every start, so a
                // spec the running service would reject cannot be written into its command line.
                tools_spec(&args)?.as_deref(),
                args.iter().any(|a| a == service::ALLOW_UNPROTECTED_FLAG),
            ),
            service::Role::Uninstall => service::uninstall(),
            service::Role::Run => service::run(),
            // Touches the SCM and one file, like installing — and like installing, it must not
            // build a runtime: the reload it asks for happens in the *service's* process, not
            // this one.
            // The `--tools` on this command line is the *client's* surface here, not this run's:
            // this process serves nothing. `edit_client` refuses it on the edits it means nothing
            // for, rather than accepting a flag it would then ignore.
            service::Role::Client(edit, name) => {
                service::edit_client(edit, &name, tools_spec(&args)?.as_deref())
            }
            // Reads the same file and touches nothing else, so it needs a runtime no more than
            // the edits do. The `--tools` is passed for the same reason: it means nothing here
            // either, and `list_clients` refuses it rather than accepting a flag it would ignore.
            service::Role::ListClients => service::list_clients(tools_spec(&args)?.as_deref()),
        };
    }

    // Decided before the runtime so a bad address fails as a usage error rather than from inside a
    // task, but acted on inside it: both roles need the runtime, and only one of them needs stdio.
    let listen = match listen::requested(&args) {
        Some(addr) => Some(addr?),
        None => None,
    };

    // Same reason, and the same shape: a spec naming a group this server does not have is a usage
    // error, not a surface that quietly serves something else.
    let tools = match toolset::Toolset::requested(&args) {
        Some(surface) => surface.map_err(|e| anyhow::anyhow!(e))?,
        None => toolset::Toolset::all(),
    };

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async {
            match listen {
                // A foreground listener has nobody to ask it to stop — Ctrl+C ends the process and
                // each worker releases its target when its pipe closes — so the shutdown it hands
                // over is one that never fires. Only the service role has a stop to deliver.
                // No reload either, and for the same reason as the shutdown above: the signal
                // is a service control code, and a foreground listener has no SCM to receive one
                // from. Its clients come from the environment it was started with, which is a set
                // that cannot change without the process changing too.
                Some(addr) => serve_http(addr, tools, None, std::future::pending(), || {}).await,
                None => serve(tools).await,
            }
        })
}

/// The listener role. See [`listen`] for what HTTP takes away and what is put back.
///
/// The teardown differs from [`serve`]'s in the one way that matters: there is no disconnect to
/// hang it on, so the shutdown here belongs to the *process* ending rather than to any client, and
/// a client going away is handled by its lease instead.
pub(crate) async fn serve_http(
    addr: std::net::SocketAddr,
    tools: toolset::Toolset,
    reload: Option<tokio::sync::mpsc::UnboundedReceiver<std::sync::mpsc::SyncSender<bool>>>,
    shutdown: impl std::future::Future<Output = ()>,
    ready: impl FnOnce(),
) -> Result<()> {
    let sessions = Sessions::new(call_timeout()).recording(record::Recorder::from_env());
    let outcome = listen::serve(
        sessions.clone(),
        addr,
        call_timeout(),
        tools,
        reload,
        shutdown,
        ready,
    )
    .await;
    // Runs on every route out of `serve`, which is why the shutdown future ends the accept loop
    // rather than the process: a service asked to stop has to reach this line, or it leaves a live
    // kernel frozen — see [`service`].
    sessions.shutdown().await;
    outcome
}

/// The `--tools` spec on this command line, as text, checked before it is written anywhere.
///
/// The same reason [`listen_address`] exists, and it now has two callers whose stored copy nothing
/// re-derives: the command line the SCM keeps for the service, and a client's entry in the
/// credential file. A spec the server would refuse at start is, in the first case, a service that
/// installs cleanly and never runs.
///
/// **Text rather than a [`toolset::Toolset`]**, because both of those store what was typed and
/// parse it again later — and `--tools` with nothing after it has to be the usage error
/// [`toolset::Toolset::requested`] makes it, rather than the `None` that would silently mean "no
/// spec given".
fn tools_spec(args: &[String]) -> Result<Option<String>> {
    match toolset::Toolset::requested(args) {
        Some(Err(e)) => Err(anyhow::anyhow!(e)),
        Some(Ok(_)) => Ok(toolset::Toolset::spec_in(args).map(str::to_string)),
        None => Ok(None),
    }
}

/// The address an install was told to bind, with the same parsing the listener itself uses.
///
/// Its own function because installing and serving must never disagree about what is a valid
/// address: a service registered with something the listener will later refuse is a service that
/// installs cleanly and fails at every start.
fn listen_address(args: &[String]) -> Result<std::net::SocketAddr> {
    match listen::requested(args) {
        Some(addr) => addr,
        None => anyhow::bail!(
            "`{}` needs the address the service will bind, e.g. `{} {} 127.0.0.1:8765`",
            service::INSTALL_FLAG,
            service::INSTALL_FLAG,
            listen::LISTEN_FLAG
        ),
    }
}

/// The renderer role: a transcript in, an asciicast out.
///
/// One of the roles that prints to standard output, and it is safe to for the reason they all
/// are: none of them speaks MCP, so there is no JSON-RPC transport to corrupt. It exits before
/// `serve` is ever reached, as the service and client roles do.
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
/// already reads — when the client is on this machine.
///
/// Targets stay on for both, which is what tells them apart: a worker's records carry
/// `windbg_mcp::worker`, the supervisor's `windbg_mcp::engine` and friends. Suppressing them for
/// workers — the first cut here — identified a worker only by the *absence* of a field, which is
/// no help at all when two processes are interleaving lines in one stream.
///
/// Two layers, not one, and under a **single** filter. Stderr is unchanged and stays the local
/// operator's view; [`logbridge`] is the copy a client reads with `server_log`, which is what
/// makes the records reachable when the client is on another machine (`--listen`). Sharing the
/// filter is deliberate: the tool then shows exactly what the log shows, and `RUST_LOG` widens
/// both together rather than one of them silently.
fn init_logging(is_worker: bool, to_file: Option<std::path::PathBuf>) {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let role = if is_worker {
        logbridge::Role::Worker
    } else {
        logbridge::Role::Supervisor
    };
    // Best-effort, and deliberately so: a service that cannot open its log file should still serve.
    // If this yields `None` the records still reach the ring behind `server_log`, which is the
    // channel a remote operator actually reads.
    let file = to_file.and_then(|path| {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .ok()
            .map(std::sync::Arc::new)
    });
    let base = tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(logbridge::layer(role));
    // Two arms rather than a boxed writer: each is a different subscriber type, and the whole
    // difference between them is where the bytes go.
    match file {
        // No ANSI: nothing renders colour in a log file, and the escapes make it unreadable.
        Some(file) => base
            .with(
                tracing_subscriber::fmt::layer()
                    .with_ansi(false)
                    .with_writer(file),
            )
            .init(),
        None => base
            .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
            .init(),
    }
}

async fn serve(tools: toolset::Toolset) -> Result<()> {
    // Opened before anything is served, so the transcript's first record is this run starting
    // rather than whatever the first tool call happened to be.
    let sessions = Sessions::new(call_timeout()).recording(record::Recorder::from_env());
    let surface = tools.summary();
    // `ForTheRun` without a branch: stdio has one client by construction and no configuration to
    // give it a surface of its own, so `--tools` is the only thing that can have narrowed this.
    let server = WindbgServer::new(sessions.clone()).with_tools(tools, toolset::Chosen::ForTheRun);

    tracing::info!("windbg-mcp starting on stdio, serving {surface}");
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
