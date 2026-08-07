//! The engine worker process: one child process, one DbgEng session.
//!
//! dbgeng.dll holds **one debuggee session per process**, so a session is a process here rather
//! than a thread. The supervisor ([`crate::engine`]) spawns one of these per open target and
//! talks to it over a private pair of inherited pipes ([`crate::proto`]) — *not* over this
//! process's standard handles, which anything linked into it may write to.
//!
//! Inside the worker the old confinement rules still apply — DbgEng wants serialized,
//! single-threaded access, and `WaitForEvent` must run on the session-owning thread — so the
//! [`DebugEngine`] is created on, and never leaves, one dedicated thread. What changed is what
//! happens when that thread cannot be freed: a live-kernel attach whose target never dials in
//! blocks in `WaitForEvent(INFINITE)` with no cancellation path (win-kexp's `SetInterrupt`
//! watchdog cannot reach a wait that is still establishing the link). That used to park the
//! server's only engine thread; here it parks this process, which the supervisor can kill.
//!
//! Which is why the request reader lives on the *main* thread and exits the process outright on
//! EOF instead of joining the engine thread: at EOF the engine thread may be parked forever,
//! and waiting for it would recreate the very wedge this design removes.

use std::io::{BufRead, BufReader, PipeReader, PipeWriter, Write};
use std::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Mutex, OnceLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use win_kexp::dbgeng::{DebugEngine, RunToOutcome};
use win_kexp::pool::query::{self, PoolPageFilter};
use win_kexp::pool::{PoolSpan, PoolState};
use windows_sys::Win32::Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation};

use crate::proto::{EngineOp, PoolOp, ReachabilityOp, WorkerMessage, WorkerRequest};
use crate::server::{
    fmt_addr, format_recipe, format_report, hexdump, parse_eval, parse_lm_base, parse_u64,
    parse_windbg_addr, path_recipe, reachability,
};

/// The argument that turns this executable into a worker. Not a documented CLI: the supervisor
/// re-executes itself with it, and nothing else should.
pub const WORKER_FLAG: &str = "--engine-worker";

/// The flags carrying this worker's two ends of the protocol channel, as raw handle values:
/// requests to read, messages to write ([`crate::proto`]).
///
/// Even less of a CLI than [`WORKER_FLAG`]. A handle number means nothing outside the process
/// that inherited it, so these are only ever valid in the child the supervisor spawned with them.
pub const REQUESTS_FLAG: &str = "--requests-handle=";
pub const MESSAGES_FLAG: &str = "--messages-handle=";

/// Reads the two inherited handle values off the command line.
///
/// There is deliberately no fallback to stdin/stdout when they are missing. Falling back is the
/// exposure this channel exists to remove — a worker that quietly spoke the protocol over its
/// standard handles again would be back to sharing them with whatever an extension DLL prints.
fn channel_handles(args: &[String]) -> Result<(usize, usize), String> {
    let value = |flag: &str| {
        let raw = args
            .iter()
            .find_map(|arg| arg.strip_prefix(flag))
            .ok_or_else(|| format!("no `{flag}<handle>` on the command line"))?;
        match raw.parse::<usize>() {
            // A null handle is not a channel: it would fail every read or write, silently, for
            // the life of the process.
            Ok(0) | Err(_) => Err(format!("`{flag}{raw}` is not a usable handle value")),
            Ok(handle) => Ok(handle),
        }
    };
    Ok((value(REQUESTS_FLAG)?, value(MESSAGES_FLAG)?))
}

/// Clears `HANDLE_FLAG_INHERIT` on a handle this process inherited, so no child of *this* process
/// gets a copy in turn. The supervisor's side of the same flag is `engine::inheritable`.
fn stop_inheriting(handle: RawHandle) -> std::io::Result<()> {
    // SAFETY: the handle is owned by this process for the rest of its life, and this only changes
    // a flag on it.
    let ok = unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// How long to wait for a target to stop after open/attach/launch (ms).
///
/// Advisory for everything but a live kernel: `attach_kernel` needs `WaitForEvent(INFINITE)`
/// (a finite timeout returns `E_NOTIMPL` and never drives the KD link), so win-kexp's
/// `PendingTarget::wait` ignores this for that one case. That unbounded wait is the reason
/// sessions live in their own process.
const LOAD_WAIT_MS: u32 = 60_000;

/// Most bytes a single `read_memory` will fetch.
///
/// A guard against exhausting the worker, not a judgement about what is useful: the buffer costs
/// this much and the hexdump built from it costs roughly four times more, so an unbounded `size`
/// is an out-of-memory away from losing the session. 1 MiB is far past any real inspection —
/// which renders as some 65,000 lines of hex — while leaving no plausible caller short.
const MAX_READ_BYTES: usize = 1024 * 1024;

/// How much of the caller's remaining patience the watchdog keeps for itself: it Ctrl+Breaks the
/// engine this long before the caller's wait expires, so the interrupt has time to land, `Execute`
/// has time to unwind, and this worker is free again before the tool call reports its timeout.
const WATCHDOG_HEADROOM: Duration = Duration::from_secs(15);

/// The watchdog deadline for a command that waited `queued` in this worker's queue, given the
/// `patience` its caller had left when the supervisor sent it.
///
/// The caller's timeout starts at submission, but a command may sit behind another job for the
/// same session (a backgrounded `go`, a long `!ttdext.index`) before the engine reaches it.
/// Budgeting from what *remains* — not from the patience as sent — is what makes the interrupt
/// fire before the caller gives up regardless of queue wait.
///
/// Floored at [`WATCHDOG_HEADROOM`] rather than allowed to reach zero, because zero *disables*
/// win-kexp's watchdog: a command dequeued at or past the deadline would then be the one command
/// that runs unbounded, which is exactly the wedge case. The floor overruns the caller's timeout
/// by design — the caller has already given up by then, and freeing the worker 15s late still
/// beats never.
fn watchdog_budget_ms(patience: Duration, queued: Duration) -> u32 {
    patience
        .saturating_sub(queued)
        .saturating_sub(WATCHDOG_HEADROOM)
        .max(WATCHDOG_HEADROOM)
        .as_millis()
        .min(u32::MAX as u128) as u32
}

/// How long the worker gives its engine to let go of the target when the supervisor disappears
/// without saying goodbye — a Ctrl+C, a crash, anything that is not a clean disconnect.
///
/// Short, because this is a process on its way out and the engine may be parked in a wait that
/// will never end. Long enough for an idle engine to resume and detach a live kernel, which is
/// the case that matters: exiting without it leaves the target machine halted.
const ABRUPT_EXIT_RELEASE: Duration = Duration::from_secs(5);

/// What the request reader hands to the engine thread.
enum Job {
    /// A request from the supervisor, stamped when it was read.
    Run(Instant, WorkerRequest),
    /// The supervisor is gone: release the target and acknowledge.
    Release(mpsc::Sender<()>),
}

/// Runs this process as an engine worker. Never returns.
pub fn run(args: &[String]) -> ! {
    let (requests, messages) = match channel_handles(args) {
        Ok(handles) => handles,
        Err(why) => {
            // Nothing can be *reported*: the channel a supervisor would be listening on is the
            // very thing that is missing. So this goes to stderr, and the exit is what the
            // supervisor reads — its end of the channel closes and it says the worker exited
            // before it was ready, which is exactly what happened.
            tracing::error!("worker: {why}; this executable is not meant to be run by hand");
            std::process::exit(2);
        }
    };
    // SAFETY: these are the two handles the supervisor created for this process and passed on the
    // command line, inherited by `CreateProcess` and owned by nothing else here — the supervisor
    // closed its copies as soon as the spawn returned (`engine::spawn_worker`). Wrapping them
    // takes that ownership; they close when this process does, which is what gives the supervisor
    // its EOF.
    let requests = unsafe { PipeReader::from_raw_handle(requests as RawHandle) };
    let messages = unsafe { PipeWriter::from_raw_handle(messages as RawHandle) };
    // The inheritable flag came with them and has done its job; carrying it further is how the
    // channel would escape this process. DbgEng creates children of its own — a launched debuggee,
    // whatever an extension shells out to — and one that inherited the message end would keep that
    // pipe from reporting EOF after this worker exits, which is exactly the signal the supervisor
    // settles a session on. Warned about rather than fatal: the channel itself still works, and
    // the risk only materializes if something is spawned here at all.
    for (what, handle) in [
        ("requests", requests.as_raw_handle()),
        ("messages", messages.as_raw_handle()),
    ] {
        if let Err(e) = stop_inheriting(handle) {
            tracing::warn!(
                "worker: could not stop the {what} channel being inherited ({e}); a process this \
                 debugger starts could hold it open past this worker's exit"
            );
        }
    }
    // Installed before the engine thread exists, so nothing can reach `emit` without a channel.
    let _ = MESSAGES.set(Mutex::new(messages));

    // Each request is stamped when it is *read*, so the engine thread can tell how long it then
    // waited its turn — the half of the watchdog budget only this process can measure.
    let (tx, rx) = mpsc::channel::<Job>();
    // Reported rather than panicked: the supervisor is waiting for `Ready` or `Fatal`, and a
    // panic here would give it neither — it would see only "the worker exited before it was
    // ready" and lose the reason.
    if let Err(e) = thread::Builder::new()
        .name("dbgeng".into())
        .spawn(move || engine_thread(rx))
    {
        emit(&WorkerMessage::Fatal {
            message: format!("could not start the engine thread: {e}"),
        });
        std::process::exit(1);
    }

    for line in BufReader::new(requests).lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<WorkerRequest>(&line) {
            Ok(request) => {
                if tx.send(Job::Run(Instant::now(), request)).is_err() {
                    break; // the engine thread is gone; nothing can run any more
                }
            }
            // The line itself is never logged. An `AttachKernel` request carries the KD
            // connection string, key and all, and this worker's stderr is the supervisor's —
            // which is to say, the MCP client's log.
            Err(e) => tracing::error!(
                "worker: unreadable request ({e}); {} bytes, discarded",
                line.len()
            ),
        }
    }

    // The request channel closed: the supervisor ended this session, or died. Either way this
    // process has no reason to exist.
    //
    // This is the *only* thing that ends a worker the supervisor did not explicitly kill — it does
    // not set `kill_on_drop`, deliberately (`engine::Sessions::spawn`). So the path below has to
    // be unconditional, and is: whatever the engine thread is doing, and whether or not it ever
    // picks the release up, this process exits within `ABRUPT_EXIT_RELEASE`. Nothing upstream
    // needs a backstop for a worker that "does not exit on EOF", because there is no such worker.
    //
    // On the clean path the supervisor has already had this session release its target, so the
    // engine has nothing left to do. On the other one — Ctrl+C, a crash, anything that kills the
    // supervisor without it running its own shutdown — nobody has, and exiting here would leave a
    // live kernel *halted*, because DbgEng needs an explicit resume-and-detach. So ask for one,
    // bounded: an idle engine obliges in milliseconds, a parked one never will, and either way
    // this process is gone within `ABRUPT_EXIT_RELEASE`.
    //
    // Ctrl+C only reaches this path because a worker is spawned into its own process group
    // (`engine::CREATE_NEW_PROCESS_GROUP`). Without that it would be delivered here too, and the
    // default console handler would end this process where it stands — no EOF, no release.
    //
    // Bounded and then abandoned, never joined: the engine thread may be blocked in DbgEng
    // forever, and this is precisely the case where that must not hold anything up.
    //
    // Logged because it is otherwise invisible: this is the teardown nobody asked for, and an
    // operator looking at a target that came back fine wants to see which path did it.
    tracing::info!("worker: supervisor is gone; releasing the target before exit");
    let (ack, released) = mpsc::channel();
    if tx.send(Job::Release(ack)).is_err() {
        // The engine thread died before this could be asked, so nothing was even attempted --
        // a different failure from the two below, and the only one where no release was tried
        // at all.
        tracing::error!(
            "worker: the engine thread is gone, so nothing was asked to release the target"
        );
    } else {
        // Whichever way this ends the process does, but *which* way is the difference between a
        // target let go and a target still attached to a debugger that no longer exists. Silence
        // here would leave that to be inferred from a guest that never came back.
        match released.recv_timeout(ABRUPT_EXIT_RELEASE) {
            Ok(()) => {}
            Err(mpsc::RecvTimeoutError::Timeout) => tracing::warn!(
                "worker: the engine did not finish releasing within {ABRUPT_EXIT_RELEASE:?} \
                 (parked in DbgEng, most likely); exiting anyway, so a live kernel target may be \
                 left halted"
            ),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                tracing::error!("worker: the engine thread is gone, so nothing released the target")
            }
        }
    }
    std::process::exit(0);
}

/// Owns the [`DebugEngine`] for the life of the process and runs one op at a time.
fn engine_thread(rx: mpsc::Receiver<Job>) {
    // `DebugEngine::new()` panics if the engine can't be created (dbgeng.dll not discoverable,
    // most likely). Report it and exit instead of accepting requests that can only fail: the
    // supervisor is waiting for exactly one of these two messages before it registers a
    // session, so it can report a dead engine as server machinery rather than as a debugger
    // error the model would pointlessly retry.
    let engine = match catch_unwind(AssertUnwindSafe(DebugEngine::new)) {
        Ok(engine) => engine,
        Err(_) => {
            emit(&WorkerMessage::Fatal {
                message: "failed to initialize DbgEng (is dbgeng.dll on the search path?)"
                    .to_string(),
            });
            std::process::exit(1);
        }
    };
    emit(&WorkerMessage::Ready);

    while let Ok(job) = rx.recv() {
        let (arrived, request) = match job {
            Job::Run(arrived, request) => (arrived, request),
            // The supervisor is gone. Let go of the target before this process does, so a live
            // kernel is left running rather than halted, then acknowledge so the main thread can
            // stop waiting. Best-effort by nature: if the engine never reaches this, the main
            // thread times out and exits anyway.
            Job::Release(ack) => {
                // Reported here rather than handed back: the main thread's only move is to exit
                // either way, and this is where the reason still exists. So the ack means
                // "finished trying", not "succeeded" — what the main thread waits for is
                // permission to stop waiting.
                match catch_unwind(AssertUnwindSafe(|| engine.end_session())) {
                    Ok(Ok(_)) => tracing::info!("worker: target released"),
                    Ok(Err(e)) => tracing::error!(
                        "worker: the debugger refused to release the target ({}); a live kernel \
                         target may be left halted",
                        es(e)
                    ),
                    Err(_) => tracing::error!(
                        "worker: releasing the target panicked; a live kernel target may be left \
                         halted"
                    ),
                }
                let _ = ack.send(());
                continue;
            }
        };
        // Measured here, at the front of the queue: this is the wait only this process can see,
        // and the bounded path needs it to size the watchdog.
        let queued = arrived.elapsed();
        // A panic inside a win-kexp method (several use `.expect`) must not kill the session —
        // surface it as an error for this one op. The engine survives, so this stays a
        // debugger-level failure the model can work around by trying something else.
        let result = catch_unwind(AssertUnwindSafe(|| {
            execute(&engine, request.id, request.op, queued)
        }))
        .unwrap_or_else(|_| Err("debugger operation panicked".to_string()));
        let id = request.id;
        // A `Done` is what removes the supervisor's waiter, so one that never arrives costs the
        // caller its session rather than its result: the call times out, the waiter stays, and
        // the session counts as busy — and so stays unreclaimable — for the life of the server.
        // The channel now makes corruption impossible, but delivery is still worth insisting on.
        if let Emit::Unencodable = emit(&WorkerMessage::Done { id, result }) {
            // The result could not be serialized, so send one that cannot fail to be: plain text
            // in the same shape. The caller loses the output, not the session.
            emit(&WorkerMessage::Done {
                id,
                result: Err(
                    "the debugger's result could not be encoded for the supervisor".to_string(),
                ),
            });
        }
        // `Unwritable` gets no retry, and needs none: the supervisor holds the only read end, so
        // a channel that will not take a write means it is gone — its request channel has closed
        // too, and the teardown at the end of `run` is already on its way. The supervisor fails
        // every outstanding call out when this process exits, which answers this caller.
    }
}

/// The channel this worker writes its messages on: its end of the pipe the supervisor is reading
/// ([`crate::proto`]). One per process and for the life of the process, installed by [`run`]
/// before anything exists that could emit.
///
/// Global for the same reason stdout was: `emit` is reached from the engine thread, from inside
/// an opener's milestones, and from the main thread's startup path, and threading a handle
/// through all of that would buy nothing — there is exactly one channel, and no code path may
/// choose a different one.
static MESSAGES: OnceLock<Mutex<PipeWriter>> = OnceLock::new();

/// What became of a message [`emit`] was asked to send.
enum Emit {
    Sent,
    /// It could not be serialized. Every variant is plain data, so this is a bug rather than a
    /// condition — but see the `Done` path in [`engine_thread`] for why it is still handled.
    Unencodable,
    /// It could not be written. The supervisor holds the only read end, so this means it is gone
    /// or going, and the request channel is at EOF or about to be.
    Unwritable,
}

/// Writes one message on the protocol channel.
///
/// The whole message is one `write_all` under one lock, and the channel is private to this pair
/// of processes, so a message always arrives as its own line. Nothing else here holds the handle,
/// and an anonymous pipe has no name for anything else to open — which is what makes framing a
/// matter of what this function does rather than of what nobody else happens to print.
fn emit(message: &WorkerMessage) -> Emit {
    let Ok(mut line) = serde_json::to_string(message) else {
        tracing::error!("worker: could not encode {message:?}");
        return Emit::Unencodable;
    };
    line.push('\n');
    let Some(channel) = MESSAGES.get() else {
        tracing::error!("worker: no protocol channel to write {message:?} on");
        return Emit::Unwritable;
    };
    let mut channel = channel.lock().unwrap_or_else(|e| e.into_inner());
    match channel
        .write_all(line.as_bytes())
        .and_then(|()| channel.flush())
    {
        Ok(()) => Emit::Sent,
        Err(e) => {
            tracing::error!("worker: could not write to the protocol channel ({e})");
            Emit::Unwritable
        }
    }
}

/// Runs one op against this worker's engine. `queued` is how long it waited its turn here, which
/// only the bounded-command path cares about.
fn execute(e: &DebugEngine, id: u64, op: EngineOp, queued: Duration) -> Result<String, String> {
    match op {
        // ---- openers ----
        //
        // Each reads the same way: side effect, `commit`, wait, `opened`, report. That order is
        // the contract the milestones exist to express — see [`open`].
        EngineOp::OpenDump { path } => open(
            id,
            |commit| {
                // `open_dump` is the call that claims the target, so commit right after it: a
                // load wait that times out still leaves DbgEng holding the dump.
                e.open_dump(&path).map_err(es)?;
                commit();
                e.wait_for_event(LOAD_WAIT_MS).map_err(es)
            },
            || {
                // Load the WinDbg extension DLL so `!`-extension commands resolve — most
                // importantly `!ext.analyze -v`, the crash-dump triage workhorse. A bare engine
                // doesn't auto-load it, and even after `.load ext` the unqualified `!analyze`
                // won't resolve, so callers must use `!ext.analyze`. Best-effort: a minimal
                // engine without a bundled `winext\` directory simply won't have ext.dll, which
                // must not fail the open (live/dump state is still usable).
                let _ = e.execute_command(".load ext");
                e.execute_command("lm").map_err(es)
            },
        ),

        EngineOp::OpenTrace { path } => open(
            id,
            |commit| {
                // As in `OpenDump`: commit before the load wait, because a wait that times out
                // still leaves DbgEng holding the trace.
                e.open_trace(&path).map_err(es)?;
                commit();
                e.wait_for_event(LOAD_WAIT_MS).map_err(es)
            },
            || {
                // Check the index state *before* any data-model query: `!ttdext.index -status`
                // only reads the on-disk .idx (never builds), whereas a `dx` on an unindexed
                // trace can itself trigger the long in-memory index build. TtdExt reports a
                // healthy, ready index as exactly "Index file loaded."; per MS guidance treat
                // anything else (missing, out of date, corrupt, unloadable) as needing an index.
                // A blank result means the status query itself failed — don't warn then.
                let needs_index = {
                    let status = e
                        .execute_command("!ttdext.index -status")
                        .unwrap_or_default();
                    !status.trim().is_empty()
                        && !status.to_ascii_lowercase().contains("index file loaded")
                };
                // Confirm TTD replay is active and report the trace's position span. Lifetime
                // is cheap metadata (min/max position); the expensive indexing is triggered by
                // Calls/Memory/Events queries, which is what the note below warns about.
                let mut out = e
                    .execute_command("dx @$curprocess.TTD.Lifetime")
                    .map_err(es)?;
                if needs_index {
                    out.push_str(
                        "\nNote: this trace's index is not loaded (missing, out of date, or \
                         unusable). The first data-model query (ttd_calls/ttd_memory/ttd_events/dx) \
                         then builds an in-memory index and can run long — let it finish before \
                         issuing more queries. Run index_trace to (re)build a persistent .idx \
                         (fast queries and re-opens).",
                    );
                }
                Ok(out)
            },
        ),

        EngineOp::AttachKernelLocal => open(
            id,
            |commit| {
                // The engine has claimed the local kernel once `_begin` returns; the break-in
                // wait (INITIAL_BREAK + the INFINITE wait a live kernel requires) happens in
                // `wait`, after the target is ours.
                let pending = e.attach_local_kernel_begin().map_err(es)?;
                commit();
                pending.wait().map_err(es)
            },
            || kernel_report(e),
        ),

        EngineOp::AttachKernel { connection } => open(
            id,
            |commit| {
                // `_begin` takes the connection; the KD link is dialed and the break-in awaited
                // in `wait`. Committing between them is what stops a failed wait from looking
                // like "nothing happened" — re-dialing a live link is not a clean retry.
                //
                // This `wait` is the one that can never return: `SetInterrupt` cannot reach a
                // wait still establishing the link, so a guest that never dials in parks here
                // for good. It parks *this process*, which the supervisor can kill.
                let pending = e.attach_kernel_begin(&connection).map_err(es)?;
                commit();
                pending.wait().map_err(es)
            },
            || kernel_report(e),
        ),

        EngineOp::AttachProcess { pid } => open(
            id,
            |commit| {
                // Attached once `_begin` returns; the break-in wait follows the commit, so a
                // wait that fails cannot read as "never attached" and get retried into a second
                // attach on the same PID.
                let pending = e.attach_process_begin(pid).map_err(es)?;
                commit();
                pending.wait().map_err(es)
            },
            || e.execute_command("r").map_err(es),
        ),

        EngineOp::Launch { command_line } => open(
            id,
            |commit| {
                // The commit point is *before* the process actually starts: CreateProcessWide is
                // deferred into the wait. That is still the right moment — once `_begin` returns
                // Ok the spawn is committed, so a retry from here means two processes.
                //
                // It is also not too early, which is the natural worry: only the *spawn* is
                // deferred, not validation. CreateProcessWide resolves and checks the image
                // synchronously, so the ways a launch fails with nothing created all land on
                // this `?`, before the commit — verified against a live engine for a missing
                // path (0x80070002), a directory (0x80070005), a non-PE file (0x800700C1) and
                // an empty command line (0x80070057). A failure from `wait` below therefore
                // means the process really was created, which is what makes the post-commit
                // message ("a session exists, do not open again") true rather than a guess.
                let pending = e.launch_process_begin(&command_line).map_err(es)?;
                commit();
                pending.wait().map_err(es)
            },
            || e.execute_command("r").map_err(es),
        ),

        // ---- ordinary work ----
        EngineOp::Command { command } => e.execute_command(&command).map_err(es),
        EngineOp::BoundedCommand {
            command,
            patience_ms,
        } => {
            let budget = watchdog_budget_ms(Duration::from_millis(u64::from(patience_ms)), queued);
            e.execute_command_bounded(&command, budget).map_err(es)
        }
        EngineOp::CommandAndWait {
            command,
            timeout_ms,
        } => e.execute_and_wait(&command, timeout_ms).map_err(es),
        EngineOp::Registers => e.registers().map_err(es),
        EngineOp::ReadMemory { address, size } => {
            let addr = parse_u64(&address)?;
            // Bounded before the allocation, not after. `size` arrives from the caller as a bare
            // `u32`, and a large one costs that many bytes here plus a hexdump several times
            // larger — enough to take the worker down with an OOM, which costs the caller their
            // whole session for a number a model can produce by accident.
            if size as usize > MAX_READ_BYTES {
                return Err(format!(
                    "`size` is {size} bytes; this tool reads at most {MAX_READ_BYTES}. Read the \
                     range you need in pieces, or use `execute` with a `db`/`dd` command if you \
                     want the debugger's own paging."
                ));
            }
            let bytes = e.read_memory(addr, size as usize).map_err(es)?;
            Ok(hexdump(addr, &bytes))
        }
        EngineOp::SymbolPath {
            path,
            append,
            reload,
        } => {
            if append {
                e.append_symbol_path(&path).map_err(es)?;
            } else {
                e.set_symbol_path(&path).map_err(es)?;
            }
            // Reload so the new path takes effect (default: all deferred modules).
            e.reload_symbols(&reload).map_err(es)?;
            // Echo the effective path so the caller can confirm what resolved.
            e.execute_command(".sympath").map_err(es)
        }
        EngineOp::RunToAddress {
            address,
            timeout_ms,
        } => run_to_address(e, &address, timeout_ms),
        EngineOp::Reachability(args) => reachable(e, args),
        EngineOp::Pool(args) => pool(e, args),
        EngineOp::EndSession => e
            .end_session()
            .map(|_| "session ended".to_string())
            .map_err(es),
    }
}

/// Maps any error to a `String` for the wire.
fn es<E: ToString>(e: E) -> String {
    e.to_string()
}

/// Column header for the chunk tables below. Kept next to [`pool_row`] so the two cannot
/// drift out of alignment.
const POOL_COLUMNS: &str =
    "address               size  state          kind                    backend  tag   numa";

/// Renders one chunk as a fixed-width row.
///
/// The address column is `usable_address` — what the allocation call *returned*, and so the
/// value that appears in the target's own pointers. `header_address` is where the allocator's
/// bookkeeping starts and is rarely what a caller is holding.
fn pool_row(span: &PoolSpan) -> String {
    format!(
        "{:<18}  {:>5}  {:<13}  {:<22}  {:<7}  {:<4}  {}",
        fmt_addr(span.usable_address),
        format!("{:#x}", span.size),
        format!("{:?}", span.state),
        format!("{:?}", span.pool_kind),
        format!("{:?}", span.backend),
        span.display_tag,
        span.numa_node,
    )
}

/// Parses a pool address in any form a caller is likely to paste.
///
/// [`parse_windbg_addr`] is tried first because it accepts the backtick form that debugger
/// output actually prints; it requires >= 8 hex digits, so shorter `0x`-hex and decimal fall
/// through to [`parse_u64`]. A bare 8+ digit run is read as hex, matching WinDbg's own
/// convention rather than Rust's.
fn parse_pool_addr(text: &str) -> Result<u64, String> {
    parse_windbg_addr(text).map_or_else(|| parse_u64(text), Ok)
}

/// Replaces the variable parts of a diagnostic — addresses and indices — so that lines
/// describing the same *kind* of problem collapse together.
///
/// A hex-looking run has to be at least 4 characters to count, or short decimal counts
/// ("depth is 16") would be blanked too and lines that differ meaningfully would merge.
fn diagnostic_category(line: &str) -> String {
    line.split_whitespace()
        .map(|word| {
            let trimmed = word.trim_matches(|c: char| !c.is_ascii_alphanumeric());
            let hexish = trimmed.len() >= 4 && trimmed.chars().all(|c| c.is_ascii_hexdigit());
            if trimmed.starts_with("0x") || hexish {
                "<addr>"
            } else {
                word
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Groups diagnostics by category, commonest first.
fn summarize_diagnostics(lines: &[String]) -> Vec<(String, usize)> {
    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for line in lines {
        *counts.entry(diagnostic_category(line)).or_default() += 1;
    }
    let mut grouped: Vec<_> = counts.into_iter().collect();
    grouped.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    grouped
}

/// Appends what the walk itself managed, so an empty answer explains itself.
///
/// Without this, an empty result is ambiguous in the worst way: "the pool holds no such
/// chunk" and "the walk reached almost none of the pool" render identically. The snapshot
/// is already cached by the time this runs, so the extra query costs nothing.
///
/// The diagnostics are *categorised* rather than listed: a real walk emits tens of
/// thousands, and the first forty of those are a sample of whichever heap happened to be
/// walked first, not of the problem. Counts per category say which failures actually
/// dominate; one verbatim example per category keeps the concrete address available.
fn append_walk_report(out: &mut String, e: &DebugEngine) {
    match query::snapshot_report(e, false) {
        Ok(report) => {
            // `complete` is not implied by an empty diagnostics list: a walk can end
            // partway through without saying anything. Report it explicitly, or a caller
            // reads a truncated snapshot as a healthy one.
            out.push_str(&format!(
                "\n--- pool walk ---\nchunks walked: {} ({} allocated), coverage: {}\n",
                report.total_chunks,
                report.allocated_chunks,
                if report.complete {
                    "complete"
                } else {
                    "INCOMPLETE - the walk did not reach everything it set out to"
                }
            ));
            if report.diagnostics.is_empty() {
                out.push_str("the walk reported no diagnostics.\n");
                return;
            }
            let grouped = summarize_diagnostics(&report.diagnostics);
            out.push_str(&format!(
                "{} diagnostic(s) in {} categor{}:\n",
                report.diagnostics.len(),
                grouped.len(),
                if grouped.len() == 1 { "y" } else { "ies" }
            ));
            for (category, count) in grouped.iter().take(25) {
                out.push_str(&format!("  {count:>7}x  {category}\n"));
            }
            if grouped.len() > 25 {
                out.push_str(&format!("  ... {} more categories\n", grouped.len() - 25));
            }
            // The last few verbatim: heaps are walked in order, so the tail is where the
            // most recently discovered ones (special pool included) report.
            out.push_str("\nlast 12 verbatim:\n");
            let tail = report.diagnostics.len().saturating_sub(12);
            for line in report.diagnostics.iter().skip(tail) {
                out.push_str("  ");
                out.push_str(line);
                out.push('\n');
            }
        }
        Err(error) => out.push_str(&format!("\n(could not summarise the walk: {error})\n")),
    }
}

fn pool(e: &DebugEngine, args: PoolOp) -> Result<String, String> {
    match args {
        PoolOp::FindTag {
            tag,
            paged,
            refresh,
            limit,
        } => {
            let filter = paged.map(|paged| {
                if paged {
                    PoolPageFilter::Paged
                } else {
                    PoolPageFilter::NonPaged
                }
            });
            let spans = query::find_tag(e, &tag, filter, refresh).map_err(es)?;
            let mut out = render_find_tag(&tag, filter, &spans, limit);
            if spans.is_empty() {
                append_walk_report(&mut out, e);
            }
            Ok(out)
        }
        PoolOp::Chunk { address, refresh } => {
            let address = parse_pool_addr(&address)?;
            match query::chunk_at(e, address, refresh).map_err(es)? {
                Some(found) => Ok(render_chunk(address, &found)),
                // "Not in the snapshot" and "free" are different answers, and conflating them
                // would be the difference between "this pointer is dangling" and "this pointer
                // never pointed at pool".
                None => {
                    let mut out = format!(
                        "{} is not covered by the pool snapshot.\n\nThat is not the same as \
                         \"free\": a free hole inside a walked region comes back as a chunk \
                         whose state is not Allocated. An address outside every region is \
                         either not pool at all, or sits in a region this walk did not reach. \
                         If the target has run since the snapshot was taken, retry with \
                         refresh=true.",
                        fmt_addr(address)
                    );
                    append_walk_report(&mut out, e);
                    Ok(out)
                }
            }
        }
        PoolOp::Diagnostics {
            filter,
            refresh,
            limit,
        } => {
            let report = query::snapshot_report(e, refresh).map_err(es)?;
            Ok(render_diagnostics(&report, filter.as_deref(), limit))
        }
        // The census *is* the state of the walk, so it always carries the report.
        PoolOp::Census { refresh, limit } => {
            let census = query::tag_census(e, refresh).map_err(es)?;
            let mut out = render_census(&census, limit);
            append_walk_report(&mut out, e);
            Ok(out)
        }
    }
}

fn render_find_tag(
    tag: &str,
    filter: Option<PoolPageFilter>,
    spans: &[PoolSpan],
    limit: usize,
) -> String {
    let scope = match filter {
        Some(PoolPageFilter::Paged) => " in paged pool",
        Some(PoolPageFilter::NonPaged) => " in nonpaged pool",
        None => "",
    };
    if spans.is_empty() {
        return format!(
            "No allocated chunks carry tag `{tag}`{scope}.\n\nOnly *allocated* chunks are \
             indexed by tag: a freed chunk's tag is not reliably preserved by the allocator, so \
             this never reports freed memory. To ask about one address that may have been freed, \
             use `pool_chunk`. If the target has run since the snapshot was taken, retry with \
             refresh=true."
        );
    }
    let total: u64 = spans.iter().map(|span| span.size).sum();
    let mut out = format!(
        "tag `{tag}`{scope}: {} allocation(s), {total:#x} bytes total\n\n{POOL_COLUMNS}\n",
        spans.len()
    );
    for span in spans.iter().take(limit) {
        out.push_str(&pool_row(span));
        out.push('\n');
    }
    if spans.len() > limit {
        out.push_str(&format!(
            "\n... {} more not shown; raise `limit` to see them.\n",
            spans.len() - limit
        ));
    }
    out
}

fn render_chunk(address: u64, found: &query::PoolNeighbourhood) -> String {
    let chunk = &found.chunk;
    let mut out = format!(
        "{} is {:#x} byte(s) into a {:#x}-byte chunk tagged `{}` ({:?}).\n\n{POOL_COLUMNS}\n",
        fmt_addr(address),
        address.saturating_sub(chunk.usable_address),
        chunk.size,
        chunk.display_tag,
        chunk.state,
    );
    if let Some(previous) = &found.previous {
        out.push_str(&format!("{}   prev\n", pool_row(previous)));
    }
    out.push_str(&format!("{}   <== containing chunk\n", pool_row(chunk)));
    if let Some(next) = &found.next {
        out.push_str(&format!("{}   next\n", pool_row(next)));
    }
    if found.previous.is_none() && found.next.is_none() {
        out.push_str("\n(no neighbouring chunks in the same heap)\n");
    }
    if chunk.state != PoolState::Allocated {
        out.push_str(&format!(
            "\nThis chunk is {:?}, not Allocated: any pointer the target still holds to it is a \
             use-after-free.\n",
            chunk.state
        ));
    }
    if chunk.heap.special {
        out.push_str(
            "\nThis is Driver Verifier special pool: the allocation owns a whole page and is \
             butted against a guard page, so an overflow or a touch after free faults at once \
             instead of quietly corrupting a neighbour. A freed special-pool page is unmapped, \
             so its former contents cannot be read back.\n",
        );
    }
    out
}

/// Selects the diagnostics matching `filter` (case-insensitive substring), verbatim.
fn select_diagnostics<'a>(lines: &'a [String], filter: Option<&str>) -> Vec<&'a String> {
    let needle = filter.map(str::to_ascii_lowercase);
    lines
        .iter()
        .filter(|line| {
            needle
                .as_ref()
                .is_none_or(|needle| line.to_ascii_lowercase().contains(needle.as_str()))
        })
        .collect()
}

fn render_diagnostics(
    report: &query::PoolSnapshotReport,
    filter: Option<&str>,
    limit: usize,
) -> String {
    let matching = select_diagnostics(&report.diagnostics, filter);
    let scope = match filter {
        Some(filter) => format!(" matching \"{filter}\""),
        None => String::new(),
    };
    if matching.is_empty() {
        return format!(
            "No diagnostics{scope}.\n\nThe walk emitted {} diagnostic(s) in total over {} \
             chunk(s) ({} allocated). If you expected a match, check the spelling — the \
             filter is a plain case-insensitive substring, not a pattern.",
            report.diagnostics.len(),
            report.total_chunks,
            report.allocated_chunks
        );
    }
    let mut out = format!(
        "{} of {} diagnostic(s){scope}:\n\n",
        matching.len(),
        report.diagnostics.len()
    );
    for line in matching.iter().take(limit) {
        out.push_str("  ");
        out.push_str(line);
        out.push('\n');
    }
    if matching.len() > limit {
        out.push_str(&format!(
            "\n... {} more match; raise `limit` to see them.\n",
            matching.len() - limit
        ));
    }
    out
}

fn render_census(census: &[query::PoolTagSummary], limit: usize) -> String {
    if census.is_empty() {
        return "The pool snapshot contains no allocated chunks.".to_string();
    }
    let mut out = format!(
        "{} distinct tag(s) allocated, heaviest first.\n\ntag      allocs        bytes  \
         nonpaged   paged\n",
        census.len()
    );
    for entry in census.iter().take(limit) {
        out.push_str(&format!(
            "{:<6}  {:>7}  {:>11}  {:>8}  {:>6}\n",
            entry.display_tag,
            entry.allocations,
            format!("{:#x}", entry.total_bytes),
            entry.nonpaged_allocations,
            entry.paged_allocations,
        ));
    }
    if census.len() > limit {
        out.push_str(&format!(
            "\n... {} more not shown; raise `limit` to see them.\n",
            census.len() - limit
        ));
    }
    out
}

/// Runs an opener as **transition, then report**, announcing the two milestones the supervisor
/// needs to tell the failure modes apart.
///
/// The split is where correctness lives. `transition` claims the target; `report` is the
/// diagnostic (`lm`, `vertarget`, `r`, the TTD lifetime query) whose output the caller reads. A
/// failure is one of three things, and they need different advice:
///
/// * before `commit` — nothing was created, and opening again is the correct recovery;
/// * after `commit` — the target exists and the *wait* failed, so opening again would attach a
///   second time or start a second process;
/// * after `Opened` — only the diagnostic failed; the session is fine.
///
/// The supervisor infers which from the milestones that arrived before the `Done`, so the error
/// text lives there, with the session handle it has to quote.
///
/// win-kexp's openers expose the first seam as `x_begin()` returning a `PendingTarget` guard,
/// which cannot exist unless the side effect succeeded — so `commit()` between the guard and its
/// `wait()` is enforced by the type rather than by convention (glslang/win-kexp#71).
fn open<T, R>(id: u64, transition: T, report: R) -> Result<String, String>
where
    T: FnOnce(&dyn Fn()) -> Result<(), String>,
    R: FnOnce() -> Result<String, String>,
{
    transition(&|| {
        emit(&WorkerMessage::Committed { id });
    })?;
    emit(&WorkerMessage::Opened { id });
    report()
}

/// The post-attach diagnostic shared by both kernel openers.
fn kernel_report(e: &DebugEngine) -> Result<String, String> {
    // The driver_object/device_object/irp_stack tools use kernel-extension commands
    // (!drvobj/!devobj/!irp) from kdexts.dll, which a bare engine does not auto-load.
    // Best-effort, like open_dump's `.load ext`; harmless if the extension isn't bundled
    // (those tools then report a clean "no export").
    let _ = e.execute_command(".load kdexts");
    e.execute_command("vertarget").map_err(es)
}

/// Resolve an address/offset expression the way `uf`/WinDbg read it: evaluate `? <expr>` first
/// (the MASM evaluator's default base is hex, so a bare `00401234` is 0x00401234 and
/// `module!Dispatch+0x123` resolves), then fall back to pure parsing (backtick / bare-hex, then
/// `0x`/decimal).
fn resolve(e: &DebugEngine, expr: &str) -> Option<u64> {
    e.execute_command(&format!("? {expr}"))
        .ok()
        .as_deref()
        .and_then(parse_eval)
        .or_else(|| parse_windbg_addr(expr))
        .or_else(|| parse_u64(expr).ok())
}

fn run_to_address(e: &DebugEngine, address: &str, wait: u32) -> Result<String, String> {
    let target =
        resolve(e, address).ok_or_else(|| format!("could not resolve address `{address}`"))?;
    let res = e.run_to_address(target, wait).map_err(es)?;
    let mut msg = match res.outcome {
        RunToOutcome::Hit => format!("VERDICT: HIT — execution reached {}\n", fmt_addr(target)),
        RunToOutcome::StoppedElsewhere { stopped_at } => format!(
            "VERDICT: STOPPED ELSEWHERE — stopped at {} before reaching {}\n  \
             (another breakpoint or exception fired first)\n",
            fmt_addr(stopped_at),
            fmt_addr(target)
        ),
        RunToOutcome::Timeout => format!(
            "VERDICT: TIMEOUT — did not reach {} within {wait} ms\n  \
             (the current input/state likely does not drive execution to this block)\n",
            fmt_addr(target)
        ),
    };
    if !res.output.trim().is_empty() {
        msg.push_str("---- debugger output ----\n");
        msg.push_str(&res.output);
    }
    Ok(msg)
}

fn reachable(e: &DebugEngine, args: ReachabilityOp) -> Result<String, String> {
    // Resolve the target VA: an absolute address, or module+RVA rebased against the module's
    // live base from `lm m <module>`. Both sides go through `resolve`, so a value pasted from
    // WinDbg — a `hi`lo` backtick address or a digit-only 32-bit address — reads consistently.
    let target = match (&args.address, &args.module, &args.rva) {
        // Reject conflicting target forms rather than silently ignoring one — analysing the
        // wrong target would give a misleading verdict.
        (Some(_), Some(_), _) | (Some(_), _, Some(_)) => {
            return Err("provide `address` OR `module`+`rva`, not both".to_string());
        }
        (Some(a), None, None) => {
            resolve(e, a).ok_or_else(|| format!("could not resolve target address `{a}`"))?
        }
        (None, Some(m), Some(r)) => {
            let rva = resolve(e, r).ok_or_else(|| format!("could not resolve rva `{r}`"))?;
            let lm = e.execute_command(&format!("lm m {m}")).map_err(es)?;
            let base = parse_lm_base(&lm)
                .ok_or_else(|| format!("module `{m}` not found (`lm m {m}` returned):\n{lm}"))?;
            base.checked_add(rva)
                .ok_or_else(|| "module base + rva overflowed u64".to_string())?
        }
        _ => return Err("provide `address`, or both `module` and `rva`".to_string()),
    };

    // Resolve `from` to a numeric VA so a mid-function start (a handler scoped past a switch)
    // is honored; `None` (unresolvable) starts at the entry.
    let seed_start = resolve(e, &args.from);

    // A real `uf` lists backtick addresses or at least a "module!Func:" label; error text
    // ("Couldn't resolve...", "no code") lacks both and prunes the branch. parse_uf then
    // discards any non-disassembly. Held in a `&mut` binding so the same disassembler drives
    // both the walk and the recipe.
    let mut uf = |arg: &str| match e.execute_command(&format!("uf {arg}")) {
        Ok(t) if t.contains('`') || t.contains(':') => Some(t),
        _ => None,
    };

    let rpt = reachability(
        &args.from,
        seed_start,
        target,
        args.max_functions,
        args.max_depth,
        &mut uf,
    );

    if rpt.from_entry.is_none() {
        return Err(format!(
            "could not disassemble `from` ({}): `uf` returned no function. Check the \
             symbol/address and that the module is loaded.",
            args.from
        ));
    }

    // On a REACHABLE verdict, re-walk the path functions to emit the directional recipe (which
    // branch each on-path `jcc` must take, and what it tests).
    let mut out = format_report(&rpt);
    if rpt.verdict_reachable && args.recipe {
        let recipes = path_recipe(&args.from, seed_start, &rpt, &mut uf);
        out.push_str(&format_recipe(&recipes));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- pool walk diagnostics ------------------------------------------------------

    /// Addresses vary per boot and per heap; the *kind* of failure is what a reader needs.
    #[test]
    fn diagnostic_categories_collapse_addresses() {
        assert_eq!(
            diagnostic_category("unreadable VS free tree node 0xbb3b57d239731c20: sparse"),
            "unreadable VS free tree node <addr> sparse"
        );
        assert_eq!(
            diagnostic_category("rejecting descriptor 19 at 0xffff8c8f0de00260 with bad sig"),
            "rejecting descriptor 19 at <addr> with bad sig"
        );
    }

    /// Short numbers are meaningful ("depth is 16") and must survive, or lines that differ
    /// in a real way would be merged into one category.
    #[test]
    fn short_numbers_are_not_treated_as_addresses() {
        assert_eq!(
            diagnostic_category("VS list depth is 16, but only 1 entries were readable"),
            "VS list depth is 16, but only 1 entries were readable"
        );
    }

    #[test]
    fn diagnostics_group_by_category_commonest_first() {
        let lines = vec![
            "unreadable VS free tree node 0xaaaaaaaaaaaaaaaa: sparse".to_string(),
            "unreadable VS free tree node 0xbbbbbbbbbbbbbbbb: sparse".to_string(),
            "unreadable VS free tree node 0xcccccccccccccccc: sparse".to_string(),
            "per-session paged heaps are not included".to_string(),
        ];
        let grouped = summarize_diagnostics(&lines);
        assert_eq!(grouped.len(), 2);
        assert_eq!(grouped[0].1, 3);
        assert!(grouped[0].0.contains("<addr>"));
        assert_eq!(grouped[1].1, 1);
    }

    #[test]
    fn diagnostics_filter_is_a_case_insensitive_substring() {
        let lines = vec![
            "cannot fully discover heap 0xffff8c8f0d300000: read failed".to_string(),
            "LFH slot 0xffffb28ac16fcf30+0xe0 would cross a page".to_string(),
            "rejecting page segment 0xdeadbeef with invalid signature".to_string(),
        ];
        // The whole point: find the one line about a specific heap among the noise.
        let hits = select_diagnostics(&lines, Some("FFFF8C8F0D300000"));
        assert_eq!(hits.len(), 1);
        assert!(hits[0].starts_with("cannot fully discover heap"));

        assert_eq!(select_diagnostics(&lines, Some("cross a page")).len(), 1);
        assert_eq!(select_diagnostics(&lines, None).len(), 3);
        assert!(select_diagnostics(&lines, Some("no such text")).is_empty());
    }

    // ---- pool address parsing ------------------------------------------------------

    /// The form debugger output actually prints. Callers paste these straight from a
    /// `dq`/`!pool` line, backtick and all.
    #[test]
    fn pool_addr_accepts_the_backtick_form() {
        assert_eq!(
            parse_pool_addr("ffffc00f`6ec02f90"),
            Ok(0xffffc00f_6ec02f90)
        );
    }

    /// A bare run of 8+ hex digits is hex, matching WinDbg rather than Rust. `6ec02f90`
    /// is a plausible decimal string too, and reading it as decimal would silently point
    /// the query at unrelated memory.
    #[test]
    fn pool_addr_reads_a_bare_run_as_hex() {
        assert_eq!(parse_pool_addr("6ec02f90"), Ok(0x6ec02f90));
        assert_eq!(parse_pool_addr("00401000"), Ok(0x0040_1000));
    }

    /// Shorter tokens fall through to the decimal/`0x` parser, since the WinDbg form
    /// deliberately requires 8+ digits so it cannot swallow a mnemonic or short immediate.
    #[test]
    fn pool_addr_falls_through_to_prefixed_and_decimal() {
        assert_eq!(parse_pool_addr("0x1000"), Ok(0x1000));
        assert_eq!(parse_pool_addr("4096"), Ok(4096));
        // 0x-prefixed stays hex even when long enough to reach the WinDbg parser, because
        // the `x` is not a hex digit and that parser rejects it.
        assert_eq!(
            parse_pool_addr("0xffffc00f6ec02f90"),
            Ok(0xffffc00f_6ec02f90)
        );
    }

    #[test]
    fn pool_addr_rejects_nonsense() {
        assert!(parse_pool_addr("not-an-address").is_err());
        assert!(parse_pool_addr("").is_err());
    }

    // ---- the protocol channel this worker was handed -------------------------------

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|a| a.to_string()).collect()
    }

    /// The ordinary case: the supervisor's command line, read back as the two handles.
    #[test]
    fn the_channel_is_read_off_the_command_line() {
        let handles = channel_handles(&args(&[
            "windbg-mcp.exe",
            WORKER_FLAG,
            "--requests-handle=132",
            "--messages-handle=140",
        ]));
        assert_eq!(handles, Ok((132, 140)));
    }

    /// Every way the pair can be missing or unusable is refused, and none of them may fall back
    /// to a standard handle: a worker that quietly spoke the protocol over stdout again would be
    /// back to sharing it with whatever an extension prints, which is the whole exposure.
    #[test]
    fn a_worker_without_a_usable_channel_is_refused() {
        for line in [
            // Started by hand, with no channel at all.
            args(&["windbg-mcp.exe", WORKER_FLAG]),
            // Half a channel is no channel.
            args(&["windbg-mcp.exe", WORKER_FLAG, "--requests-handle=132"]),
            args(&["windbg-mcp.exe", WORKER_FLAG, "--messages-handle=140"]),
            // Present but unusable: a null handle fails every read and write, silently.
            args(&[
                "windbg-mcp.exe",
                WORKER_FLAG,
                "--requests-handle=0",
                "--messages-handle=140",
            ]),
            args(&[
                "windbg-mcp.exe",
                WORKER_FLAG,
                "--requests-handle=132",
                "--messages-handle=oops",
            ]),
        ] {
            assert!(
                channel_handles(&line).is_err(),
                "accepted a command line that carries no usable channel: {line:?}"
            );
        }
    }

    // The watchdog budget, as arithmetic. What it is *wired to* needs a real engine and a real
    // target, and lives in `tests/mcp_smoke.rs`'s bounded-command tier — the wiring now spans two
    // processes, so the shipped binary is the only place it exists whole.

    /// The everyday case: nothing queued ahead, so the watchdog fires one headroom before the
    /// caller's wait expires. This is the number that keeps a runaway command from outliving the
    /// tool call that started it.
    #[test]
    fn an_unqueued_command_is_bounded_one_headroom_short_of_the_callers_patience() {
        let patience = Duration::from_secs(300);
        assert_eq!(
            watchdog_budget_ms(patience, Duration::ZERO),
            (300 - 15) * 1000
        );
    }

    /// The property the queue-awareness exists for, stated as the invariant rather than as an
    /// arithmetic identity: **queue wait + watchdog budget must not exceed the caller's
    /// patience**, or the caller gives up while the command is still running — the wedge.
    ///
    /// Budgeting from the patience as sent (ignoring the wait) breaks this for every non-zero
    /// wait, which is why it is checked across a spread rather than at one point. That is not a
    /// hypothetical: it is the bug the first cut of the process split shipped, because the
    /// supervisor writes a request the moment it is submitted and the waiting then happens on
    /// the far side of the pipe, where only this process can see it.
    #[test]
    fn a_queued_command_still_aborts_before_its_caller_gives_up() {
        let patience = Duration::from_secs(300);
        for waited in [0, 1, 30, 100, 240, 269] {
            let waited = Duration::from_secs(waited);
            let budget = Duration::from_millis(watchdog_budget_ms(patience, waited) as u64);
            assert!(
                waited + budget <= patience,
                "a command dequeued after {waited:?} gets a {budget:?} budget — it would still \
                 be running at the {patience:?} mark, which is the wedge this bounds"
            );
        }
    }

    /// Past the point where any headroom is left, the budget floors instead of reaching zero —
    /// because zero *disables* win-kexp's watchdog, which would make a command dequeued near the
    /// deadline the one command that runs unbounded.
    ///
    /// The floor deliberately overruns the caller's timeout: by then the caller has already given
    /// up, and the remaining job is to free this worker for the *next* call.
    #[test]
    fn a_command_dequeued_past_the_deadline_is_still_bounded() {
        let patience = Duration::from_secs(300);
        for waited in [290, 300, 600, 86_400] {
            assert_eq!(
                watchdog_budget_ms(patience, Duration::from_secs(waited)),
                15_000,
                "a command dequeued after {waited}s must still arm the watchdog"
            );
        }
    }

    /// A caller whose patience was already exhausted when the request was written (the
    /// supervisor sends 0) must still arm the watchdog, not disable it.
    #[test]
    fn no_patience_left_still_arms_the_watchdog() {
        assert_eq!(watchdog_budget_ms(Duration::ZERO, Duration::ZERO), 15_000);
    }

    /// A patience beyond `u32::MAX` milliseconds (~49 days) must saturate, not wrap: a wrapped
    /// budget could land on 0 and silently disable the watchdog.
    #[test]
    fn an_absurd_patience_saturates_rather_than_wrapping() {
        assert_eq!(
            watchdog_budget_ms(Duration::from_secs(u32::MAX as u64), Duration::ZERO),
            u32::MAX
        );
    }
}
