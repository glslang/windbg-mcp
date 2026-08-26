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

use std::os::windows::io::AsRawHandle;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject,
};

use crate::ttd::Arch;

/// How long to wait for a freshly started host to publish its pipe.
///
/// **Bounded by the supervisor's patience, not by ours.** This wait happens before the worker
/// emits `Ready`, and the supervisor gives a worker [`crate::engine::WORKER_READY_TIMEOUT`] to get
/// there before killing it — so anything longer than that is unreachable, and a host still opening
/// its dump at the bound would be killed mid-open with the timeout below never reported. The
/// margin leaves room for the rest of a worker's startup to still fit inside the supervisor's
/// window; `the_pipe_wait_fits_inside_the_supervisors_patience` is the assertion, so the two
/// cannot drift apart silently.
const PIPE_TIMEOUT: Duration = crate::engine::WORKER_READY_TIMEOUT.saturating_sub(
    // Enough for engine creation, the connect, and the worker's own startup either side of them.
    Duration::from_secs(5),
);

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
    /// The job object the host is assigned to, held open for exactly as long as this process is.
    ///
    /// **This, and not [`Drop`], is what guarantees the host dies with its client.** A destructor
    /// would be enough only if this process always unwound, and it never does: the worker leaves
    /// through `std::process::exit` on every one of its own paths, and the supervisor ends it with
    /// `TerminateProcess` ([`crate::engine::Session::kill`]). Rust runs no destructor for either.
    /// A job with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` is enforced by the kernel instead: when the
    /// last handle to it closes — which a dying process does however it dies, including a crash —
    /// everything in it is terminated.
    ///
    /// That matters more here than the usual tidiness argument. A `cdb -server` whose client has
    /// gone does not idle; it spins on the broken transport without bound, which is a measured way
    /// to take a machine down (see [`Self::shutdown`]).
    ///
    /// Never read, and that is the whole design: its value is its `Drop`, and the kernel's
    /// behaviour when the handle closes for reasons no `Drop` would survive.
    #[allow(dead_code, reason = "held for the kill-on-close guarantee, never read")]
    job: Option<OwnedJob>,
}

/// A job object handle, closed when this is dropped **or when the process dies**.
struct OwnedJob(HANDLE);

// SAFETY: a job handle is just a kernel handle; it has no thread affinity.
unsafe impl Send for OwnedJob {}
unsafe impl Sync for OwnedJob {}

impl Drop for OwnedJob {
    fn drop(&mut self) {
        // SAFETY: the handle came from `CreateJobObjectW` and is owned solely by this value.
        unsafe { CloseHandle(self.0) };
    }
}

/// Creates a job that kills everything in it once its last handle closes.
///
/// Returns `None` rather than failing the open: a host without a job still works, and the failure
/// this guards against — an orphaned spinning `cdb` — is worth a warning rather than refusing to
/// debug. The warning is the point, because the alternative is losing the property silently.
fn kill_on_close_job() -> Option<OwnedJob> {
    // SAFETY: a null name creates an anonymous job owned by this process.
    let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if handle.is_null() {
        tracing::warn!(
            "worker: could not create a job object ({}); an engine host could outlive this worker \
             if it is terminated rather than shut down",
            io::Error::last_os_error()
        );
        return None;
    }
    let job = OwnedJob(handle);
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // SAFETY: `limits` matches the class being set and outlives the call.
    let ok = unsafe {
        SetInformationJobObject(
            job.0,
            JobObjectExtendedLimitInformation,
            (&raw const limits).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    if ok == 0 {
        tracing::warn!(
            "worker: could not set kill-on-close on the job object ({}); an engine host could \
             outlive this worker",
            io::Error::last_os_error()
        );
        return None;
    }
    Some(job)
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
    /// secret. `cdb` creates the pipe, not this server, so it carries the **default** named-pipe
    /// security descriptor — full control to `SYSTEM`, administrators and the creator, and *read*
    /// to Everyone. A local user can therefore read the transport, which carries target memory.
    ///
    /// **Bounded under stdio, and not under a service.** Running as the caller, the reader of that
    /// pipe is the caller's own account, which could open the dump file directly — so the pipe
    /// discloses nothing the filesystem does not. A service-hosted listener breaks that: it runs as
    /// `LocalSystem`, so the pipe is created by `SYSTEM` and readable by Everyone while the dump it
    /// serves may be readable only by `SYSTEM`. Then the pipe crosses a privilege boundary the dump
    /// does not. `FOLLOWUPS.md` item 49 carries it; the honest fix is an engine host of our own
    /// rather than `cdb`, since a pipe we do not create is a DACL we cannot set.
    ///
    /// The same qualifier applies to a live target, for the teardown reason in [`Self::shutdown`].
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

        // Assigned **after** the spawn rather than through `CREATE_SUSPENDED`, which is what a
        // hand-rolled `CreateProcess` would allow: `std` gives no hook between creation and
        // resumption. The window is a few instructions of a process that has not yet opened
        // anything, and losing the race costs the kill-on-close property for that host alone —
        // against a `CREATE_SUSPENDED` path that would mean owning process creation here.
        let job = kill_on_close_job().filter(|job| {
            // SAFETY: both handles are live and owned — the job by `job`, the process by `child`.
            let ok = unsafe { AssignProcessToJobObject(job.0, child.as_raw_handle() as HANDLE) };
            if ok == 0 {
                tracing::warn!(
                    "worker: could not put the engine host in a job ({}); it could outlive this \
                     worker if this process is terminated rather than shut down",
                    io::Error::last_os_error()
                );
            }
            ok != 0
        });

        let mut host = Self {
            child,
            connection: format!("npipe:pipe={pipe},server=localhost"),
            pipe,
            job,
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

    /// **The job kills what is in it when its last handle closes** — which is what a dying process
    /// does to its handles however it dies, including the `TerminateProcess` the supervisor uses
    /// and the `process::exit` this worker uses. That is the whole reason the host is put in one:
    /// neither of those runs a `Drop`, so a destructor-based teardown would leave a `cdb -server`
    /// behind, and one whose client has gone spins on the broken transport without bound.
    ///
    /// Tested on a stand-in child rather than a real host, because what is being asserted is the
    /// kernel's behaviour and not `cdb`'s: any process that outlives its parent will do.
    #[test]
    fn a_job_kills_its_children_when_its_last_handle_closes() {
        let job = kill_on_close_job().expect("a job object can be created");
        let mut child = {
            let _one_spawn_at_a_time = crate::engine::spawn_guard();
            Command::new("cmd.exe")
                .args(["/c", "ping -n 30 127.0.0.1"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("a stand-in child starts")
        };
        // SAFETY: both handles are live and owned here.
        let assigned =
            unsafe { AssignProcessToJobObject(job.0, child.as_raw_handle() as HANDLE) } != 0;
        assert!(assigned, "{}", io::Error::last_os_error());

        assert!(
            child.try_wait().expect("the child can be polled").is_none(),
            "the stand-in exited on its own, so this proves nothing"
        );
        drop(job);

        // The kill is not instantaneous, so give it a bounded moment rather than asserting on a
        // race. A second is orders of magnitude more than the kernel needs and far less than the
        // thirty the stand-in would otherwise run for.
        let deadline = Instant::now() + Duration::from_secs(1);
        while Instant::now() < deadline {
            if child.try_wait().expect("the child can be polled").is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = child.kill();
        panic!("closing the job's last handle did not kill the process in it");
    }

    /// This wait happens **before** the worker says `Ready`, so the supervisor's patience is the
    /// real bound: a pipe timeout at or past `WORKER_READY_TIMEOUT` is unreachable, and a host
    /// still opening its dump when it expires is killed with this timeout never reported — a
    /// failure that would read as "the worker died" rather than "the dump took too long".
    ///
    /// Pinned because the two constants live in different modules and nothing else ties them
    /// together. Raising one without the other is the silent way to reintroduce it.
    #[test]
    fn the_pipe_wait_fits_inside_the_supervisors_patience() {
        assert!(
            PIPE_TIMEOUT < crate::engine::WORKER_READY_TIMEOUT,
            "a {PIPE_TIMEOUT:?} pipe wait cannot finish inside the supervisor's {:?}",
            crate::engine::WORKER_READY_TIMEOUT
        );
        // And not so short that it is the ordinary case that fails: opening a full-memory dump off
        // a slow disk is the thing being waited for.
        assert!(PIPE_TIMEOUT >= Duration::from_secs(20), "{PIPE_TIMEOUT:?}");
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
            // `.loadby`, not `.load` with a path: SOS reads CLR-internal structures and has to be
            // the build that shipped with the runtime in the target. `.loadby sos clr` takes it
            // from the directory the loaded `clr.dll` came from, so it is version-matched by
            // construction, where a hardcoded `v4.0.30319` pins one .NET Framework 4.x servicing
            // level and names a directory that does not exist for a 2.0/3.5 target at all.
            .execute_command(".loadby sos clr")
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
