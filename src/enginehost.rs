//! An engine host of a chosen architecture, run as a child process and driven over DbgEng's
//! remote transport.
//!
//! **Why a second process at all.** An extension DLL is loaded into the debugger's own process,
//! so its architecture is the *host's*, not the target's. A 32-bit `sos.dll` cannot be loaded by
//! an x64 host, and the 64-bit one refuses a 32-bit CLR because the data access DLL behind it is
//! paired to the target as well as the host — so no in-process arrangement reads a 32-bit .NET
//! dump from this server ([#234](https://github.com/glslang/windbg-mcp/issues/234)). Moving the
//! engine into a process of the target's architecture is the only route, and it is the route
//! WinDbg itself takes: its package ships `EngHost.exe` under both `amd64\` and `x86\`.
//!
//! What this server drives over the transport is the **whole typed surface**, not command text —
//! registers, memory, modules, symbols, stacks, disassembly, scope, breakpoints and bounded
//! commands were all measured working against a remote engine. The one call that does not cross
//! is `IDebugAdvanced2::GetSymbolInformation`, so `modules` rows carry no PDB identity on a remote
//! session; `dbgscope::dbgeng::DebugEngine::connect` documents that, and `with_pdb_identity`
//! already drops the field rather than failing the listing.

use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::ttd::Arch;

/// How long to wait for a freshly started host to publish its pipe.
///
/// Generous because the host has to open the target before it serves anything, and that target is
/// a full-memory dump — tens or hundreds of megabytes, off whatever disk it lives on.
const PIPE_TIMEOUT: Duration = Duration::from_secs(60);

/// How often to look for it. The pipe appears once, so this only costs a few wake-ups.
const PIPE_POLL: Duration = Duration::from_millis(100);

/// A debugging server this process started, and the connection string that reaches it.
///
/// **Owned by the worker that spawned it**, which is what makes the teardown below sound: one
/// session, one host, and the host dies with the worker.
pub struct EngineHost {
    child: Child,
    connection: String,
    /// Kept for diagnostics — a log line naming the pipe is how two concurrent sessions are told
    /// apart.
    pipe: String,
}

impl EngineHost {
    /// Locates a `cdb.exe` of the given architecture, or `None` if this host has none.
    ///
    /// Search order, widest-control first — the same shape as [`crate::ttd::find_ttd`], because
    /// the same reasoning applies: an operator who has put a payload where this server can see it
    /// means that one to be used.
    ///
    /// 1. **Beside this executable**, under an architecture directory (`x86\cdb.exe`). This is the
    ///    bundling convention `setup.md` already prescribes for the engine and for `ttd\`, and it
    ///    is the only location an operator can arrange without installing anything.
    /// 2. The SDK's *Debugging Tools for Windows*.
    /// 3. The modern WinDbg (MSIX) package.
    ///
    /// **The bundle cannot live beside `windbg-mcp.exe` itself**, which is why (1) names a
    /// subdirectory: the loader searches an executable's own directory first, so an x86 engine
    /// dropped next to the x64 `dbgeng.dll` this server already bundles would find the wrong one.
    /// The package's own `amd64\`/`x86\` layout is exactly this rule.
    pub fn find(arch: Arch) -> Option<PathBuf> {
        if let Some(dir) = std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(Path::to_path_buf))
        {
            let beside = dir.join(arch.payload_dir()).join("cdb.exe");
            if beside.is_file() {
                return Some(beside);
            }
            // The SDK spells x64 differently from the store package, and an operator copying from
            // one or the other will have used whichever name they found.
            let beside = dir.join(arch.sdk_dir()).join("cdb.exe");
            if beside.is_file() {
                return Some(beside);
            }
        }
        let sdk = PathBuf::from(format!(
            r"C:\Program Files (x86)\Windows Kits\10\Debuggers\{}\cdb.exe",
            arch.sdk_dir()
        ));
        if sdk.is_file() {
            return Some(sdk);
        }
        find_in_windowsapps(arch)
    }

    /// Starts `cdb` as a debugging server holding `dump`, and waits for it to publish its pipe.
    ///
    /// The pipe name carries this process's id and a counter rather than anything guessable being
    /// unnecessary: a name has to be unique among the sessions on this machine, and it is not a
    /// secret — the pipe is reachable by other local users, which for a dump is bounded, since
    /// anyone who can open it could read the dump file itself. That stops being true the day this
    /// is pointed at a live target.
    pub fn start(cdb: &Path, dump: &Path) -> io::Result<Self> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let pipe = format!(
            "windbg-mcp-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );

        let mut command = Command::new(cdb);
        command
            .arg("-server")
            .arg(format!("npipe:pipe={pipe}"))
            .arg("-z")
            .arg(dump)
            // Nothing of ours is read from it, and a host that reached the worker's stdin could
            // consume nothing useful — but it must not inherit a console read either.
            .stdin(Stdio::null())
            // Piped and drained (below). **Not inherited**: this process's stderr is the
            // supervisor's, and a host writing to it interleaves with the server's own log.
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // Every `spawn` in this crate takes this, without exception — see `engine::spawn_guard`.
        // The worker's protocol handles have already had their inheritable flag cleared
        // (`worker::stop_inheriting`), so this child cannot hold the pipe whose EOF tells the
        // supervisor the worker is gone.
        let mut child = {
            let _one_spawn_at_a_time = crate::engine::spawn_guard();
            command.spawn()?
        };

        // Drained rather than left to fill. A `cdb` whose output pipe backs up blocks, and one
        // whose *transport* peer has gone spins — 32k lines of `Could not write to pipe, 1450` in
        // one measured run, which took the machine with it. Neither can happen while something is
        // reading and the teardown below is deliberate.
        if let Some(out) = child.stdout.take() {
            let pipe = pipe.clone();
            std::thread::spawn(move || drain(&pipe, "stdout", Streams::Out(out)));
        }
        if let Some(err) = child.stderr.take() {
            let pipe = pipe.clone();
            std::thread::spawn(move || drain(&pipe, "stderr", Streams::Err(err)));
        }

        let mut host = Self {
            child,
            connection: format!("npipe:pipe={pipe},server=localhost"),
            pipe,
        };
        host.await_pipe()?;
        Ok(host)
    }

    /// The connection string [`dbgscope::dbgeng::DebugEngine::connect`] takes.
    pub fn connection(&self) -> &str {
        &self.connection
    }

    /// The pipe's bare name, for a log line.
    pub fn pipe(&self) -> &str {
        &self.pipe
    }

    /// Waits until the host publishes its pipe, or gives up.
    ///
    /// Polling the pipe namespace rather than sleeping a fixed interval, because the two failures
    /// are different and only this tells them apart: a host that died has to be reported as a host
    /// that died, and a host that is merely slow has to be waited for.
    fn await_pipe(&mut self) -> io::Result<()> {
        let deadline = Instant::now() + PIPE_TIMEOUT;
        loop {
            // A host that exited is never going to publish anything. Checked before the namespace
            // so the error names the real problem.
            if let Some(status) = self.child.try_wait()? {
                return Err(io::Error::other(format!(
                    "the engine host exited before it served its pipe ({status}) — it could not \
                     open the target, or its own engine DLLs are missing"
                )));
            }
            if pipe_exists(&self.pipe) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(io::Error::other(format!(
                    "the engine host did not serve its pipe within {PIPE_TIMEOUT:?}"
                )));
            }
            std::thread::sleep(PIPE_POLL);
        }
    }

    /// Ends the host, **by terminating it**.
    ///
    /// Deliberately not a graceful `qq`. A graceful quit has to be driven through the engine, and
    /// the state this is most needed in is the one where driving the engine is exactly what has
    /// stopped working. What must never happen is the host outliving its client: a `cdb -server`
    /// whose transport peer has gone spins on the broken pipe without bound, and that is a
    /// measured way to take the machine down rather than a theoretical one. Killing first and
    /// asking questions never is the discipline.
    ///
    /// The target is a dump, so there is nothing to leave in a bad state — no live process to
    /// orphan and no kernel to leave halted. That is what makes terminating the right answer here
    /// and would make it the wrong one for a live target.
    pub fn shutdown(&mut self) {
        if let Err(e) = self.child.kill() {
            tracing::debug!("worker: engine host {} was already gone ({e})", self.pipe);
        }
        // Reaped, so the child does not linger as a zombie for the life of the worker.
        let _ = self.child.wait();
    }
}

impl Drop for EngineHost {
    fn drop(&mut self) {
        self.shutdown();
    }
}

enum Streams {
    Out(std::process::ChildStdout),
    Err(std::process::ChildStderr),
}

/// Reads a host's output into the log until it closes.
fn drain(pipe: &str, what: &str, stream: Streams) {
    use std::io::{BufRead, BufReader};
    let lines: Box<dyn BufRead> = match stream {
        Streams::Out(s) => Box::new(BufReader::new(s)),
        Streams::Err(s) => Box::new(BufReader::new(s)),
    };
    for line in lines.lines() {
        match line {
            Ok(line) => tracing::debug!("engine host {pipe} {what}: {line}"),
            Err(_) => break,
        }
    }
}

/// Whether a named pipe of this name is being served.
///
/// The pipe namespace is a directory, so this is a listing rather than an open — opening would
/// *consume* a server instance, and `cdb` serves one at a time.
fn pipe_exists(name: &str) -> bool {
    let Ok(entries) = std::fs::read_dir(r"\\.\pipe\") else {
        return false;
    };
    entries.flatten().any(|entry| {
        entry
            .file_name()
            .to_string_lossy()
            .eq_ignore_ascii_case(name)
    })
}

fn find_in_windowsapps(arch: Arch) -> Option<PathBuf> {
    let root = PathBuf::from(r"C:\Program Files\WindowsApps");
    // Reading WindowsApps may be denied; treat any error as "not found".
    let entries = std::fs::read_dir(&root).ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        if !name.to_string_lossy().starts_with("Microsoft.WinDbg") {
            continue;
        }
        // **Only the architecture asked for.** Unlike the recorder search, which orders every
        // architecture by preference, this one is a requirement: an x64 `cdb.exe` cannot load the
        // extension a caller came here for, so falling back to one would defeat the whole point.
        let candidate = entry.path().join(arch.payload_dir()).join("cdb.exe");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `find` answers about this host, so the only thing that is true everywhere is that it does
    /// not panic and that what it returns, if anything, exists and is named `cdb.exe`.
    #[test]
    fn find_returns_an_existing_cdb_or_nothing() {
        for arch in [Arch::X86, Arch::X64, Arch::Arm64] {
            if let Some(found) = EngineHost::find(arch) {
                assert!(found.is_file(), "{} does not exist", found.display());
                assert_eq!(
                    found.file_name().and_then(|n| n.to_str()),
                    Some("cdb.exe"),
                    "{}",
                    found.display()
                );
            }
        }
    }

    /// A pipe nothing serves is not found — the negative half of the wait, which is what stops
    /// `await_pipe` returning the moment it is called.
    #[test]
    fn a_pipe_nobody_serves_does_not_exist() {
        assert!(!pipe_exists("windbg-mcp-no-such-pipe-4f21a90c"));
    }

    /// **The whole module against a real host**, which is the only thing that shows `find`,
    /// `start`, `await_pipe`, the connection string and `shutdown` agree with each other: serve a
    /// real 32-bit dump from an x86 `cdb`, drive it from this x64 process, and load the 32-bit
    /// SOS that no in-process arrangement can load.
    ///
    /// Gated on a dump this repository does not carry, for the reason `src/dump.rs` gives — a
    /// full-memory capture is many times the size of the repo. Point the variable at one:
    /// `$env:WINDBG_MCP_X86_DUMP = "C:\path\to\x86.dmp"`.
    #[test]
    fn a_real_x86_host_serves_a_managed_dump() {
        let Some(dump) = std::env::var_os("WINDBG_MCP_X86_DUMP") else {
            eprintln!("SKIPPED: set WINDBG_MCP_X86_DUMP to a 32-bit user dump to run this");
            return;
        };
        let Some(cdb) = EngineHost::find(Arch::X86) else {
            eprintln!("SKIPPED: this host has no x86 cdb.exe to serve a 32-bit target with");
            return;
        };
        eprintln!(
            "serving {} with {}",
            Path::new(&dump).display(),
            cdb.display()
        );

        let mut host = EngineHost::start(&cdb, Path::new(&dump)).expect("the engine host starts");
        let engine = dbgscope::dbgeng::DebugEngine::connect(host.connection())
            .expect("the engine host is reachable on its own connection string");

        // `IMAGE_FILE_MACHINE_I386` — the x86 engine sees the target natively, with no
        // `.effmach` and no `!wow64exts`. This is the value #234's error message quotes.
        assert_eq!(
            engine.processor_type().expect("the target has a processor"),
            0x14c
        );

        // The point of the whole exercise: an extension of the *target's* architecture, loaded in
        // the host, answering about managed state.
        engine
            .execute_command(
                r"\.load C:\Windows\Microsoft.NET\Framework\v4.0.30319\sos.dll"
                    .trim_start_matches('\\'),
            )
            .expect("the 32-bit SOS loads into an x86 host");
        let threads = engine
            .execute_command("!threads")
            .expect("SOS answers about managed threads");
        assert!(
            threads.contains("ThreadCount"),
            "SOS loaded but said nothing about threads: {threads}"
        );

        // Disconnect before the host goes, so the teardown is the deliberate one rather than the
        // host discovering a vanished peer.
        drop(engine);
        host.shutdown();
    }
}
