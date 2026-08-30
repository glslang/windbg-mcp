//! End-to-end smoke test: drives the **real binary** over stdio with hand-written JSON-RPC.
//!
//! The unit tests in `src/server.rs` check the tool surface in-process, through the SDK's
//! Rust API. That is the wrong altitude for the two events this file exists for:
//!
//! * **A dependency moved** (`rmcp`, `dbgscope`, `schemars`, `tokio`). The in-process tests
//!   still compile and pass while the bytes on the wire change underneath them — a schema
//!   dialect switch, a crate that starts writing to stdout and corrupts the transport, a
//!   shutdown path that leaves the process alive.
//! * **The MCP spec revved.** New revision, new required field, a capability the SDK now
//!   advertises on our behalf that this server does not actually implement.
//!
//! Seven tiers, so the cheap one can ride `cargo test` everywhere:
//!
//! * **Protocol** (default) — spawns the server, speaks JSON-RPC. No debugger target, no
//!   symbols, no network. This tier also drives the **listener** (`--listen`) over real HTTP on a
//!   loopback port: the bearer check, a token file naming its own clients, the second MCP session
//!   for one credential that the retired tenancy gate used to refuse and this server now serves,
//!   the difference between a client going quiet and a client saying goodbye, and `2026-07-28`
//!   being served at all — the revision that removed the session id, and so arrives with none of
//!   the things the rules above are written in terms of, including on the one request that may
//!   omit its protocol header. Those need no debugger, because the lease is decided before any
//!   session is opened. Three that do — the sweep meeting a real engine worker, a stateless
//!   client working alongside a call of its own that parks, and two credentials that may not
//!   reach each other's sessions — live in the tier below.
//! * **Target** (`WINDBG_MCP_SMOKE_DUMP=1`) — opens the sample crash dump through DbgEng, so
//!   it needs `dbgeng.dll` and may reach a symbol server. Off by default; this is the tier
//!   that catches a `dbgscope` regression. It also runs a `debug_batch` to both outcomes, and
//!   through both teardowns — an `end_session` and a client disconnect landing mid-transaction —
//!   because "the rollback ran inside the worker" is a claim only a real engine can settle. And
//!   it waits out a **lease expiry** against a parked kernel attach, which is the listener's
//!   answer to a closed stdin and the one claim there that costs a target when it is wrong.
//! * **Bounded command** (`#[ignore]`d, run by hand) — deliberately runs away and waits out a
//!   watchdog, so it is measured in minutes rather than seconds. It lives here rather than
//!   beside the budget arithmetic in `src/engine.rs` because the two halves it proves are now
//!   in *different processes* — the budget is computed by the supervisor and armed by the
//!   worker — so the only place the wiring exists as a whole is the shipped binary.
//! * **Live kernel** (`#[ignore]`d **and** `WINDBG_MCP_SMOKE_KERNEL=<connection string>`) — a
//!   real KDNET target. The only tier that touches another machine, and the only one that can
//!   prove a kernel attach still *lands* and lets go cleanly rather than merely parks, that a
//!   pool walk stays inside its budget when every page it reads crosses a wire, or that a
//!   `debug_batch` which patches a byte of the running kernel puts it back — a dump has nothing
//!   worth restoring, so a rollback that did nothing would pass every check the tier above can
//!   make. Run it last, on its own.
//! * **MessageManager CTF** (`#[ignore]`d, `WINDBG_MCP_SMOKE_CTF=1`, and the live-kernel gate)
//!   — deploys a benign allocation fixture over WinRM, then verifies that the real driver and its
//!   pool objects are visible through the structured MCP tools. The PowerShell orchestrator owns
//!   the second gate so an ordinary live-kernel run never assumes this challenge is installed.
//! * **TTD** (`WINDBG_MCP_SMOKE_TTD=1`) — records a trace with `TTD.exe` and reads it back, so it
//!   needs the recorder and **elevation**. The only tier that creates its own target rather than
//!   opening a checked-in one, because a `.run` is tens of MB and none is in the repo — which is
//!   why nothing covered these calls, and why #231, #232 and #233 all shipped. Gated on the
//!   variable alone rather than `#[ignore]`d as well: a stale variable here costs a few tens of MB
//!   in the temp directory, not a wedged VM.
//! * **32-bit managed target** (a 32-bit `dbgeng.dll` in an `x86` directory beside the binary
//!   under test) — the only tier asserting something this server's own engine *cannot do*: a
//!   32-bit `sos.dll` will not load into a 64-bit debugger and the 64-bit one refuses a 32-bit
//!   CLR, so `!sos.threads` answering proves the engine is in a 32-bit process. Two routes to it,
//!   a dump and a live `attach_process`, because a dump carries its architecture in its header
//!   and a process does not. Like the TTD tier it creates its own target — with `csc.exe`, which
//!   every stock Windows ships — since the alternative is a supplied file no repository can carry,
//!   which is why this covered nothing until it did. A **capability** gate rather than a variable:
//!   a host with no 32-bit engine cannot answer the question at all.
//!
//! See `docs/smoke-test.md` for the runbook.

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Write};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use serde_json::{Value, json};

/// The binary built for the current profile. Using Cargo's path (rather than
/// `target/release/windbg-mcp.exe`) keeps the smoke test clear of the release exe that a
/// connected MCP client holds a lock on — see `CLAUDE.md`.
const EXE: &str = env!("CARGO_BIN_EXE_windbg-mcp");

/// Per-request budget for protocol-tier calls. Generous enough that a loaded CI runner never
/// trips it, bounded so a regression fails instead of hanging the suite.
const STEP: Duration = Duration::from_secs(60);

/// Debugger work gets its own budget: opening a dump can pull symbols over the network.
const TARGET_STEP: Duration = Duration::from_secs(240);

/// Revisions `docs/architecture.md` promises this server speaks, newest first.
const SUPPORTED_REVISIONS: &[&str] = &[
    "2026-07-28",
    "2025-11-25",
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
];

/// What a client offering something the SDK does not know gets answered with.
const FALLBACK_REVISION: &str = "2025-11-25";

const GOLDEN: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden/tools_list.json");
/// Companion to [`GOLDEN`], and deliberately the thing it is blind to. That one digests the tool
/// surface down to its *shape* — `digest_tool` drops every `description` on purpose — which is
/// what makes it readable, and what makes it unable to see the bytes. This one records only
/// sizes. See `docs/token-budget.md`.
const BUDGET_GOLDEN: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden/tool_budget.json");
const SAMPLE_DUMP: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/docs/samples/052126-34312-01.dmp"
);
/// A second crash dump, and a deliberately *different* kind of crash: a third-party driver
/// (`MessageManager`, no PDB) freeing a chunk it had already freed, taken from the CTF loop
/// `crash_triage` was written for.
///
/// [`SAMPLE_DUMP`] cannot stand in for it. That one is a `0x9F` watchdog, which fires on an idle
/// CPU's timer DPC: there is no driver frame on its stack at all, so it exercises the *absent*
/// `faulting_frame` branch and never the one the tool exists for. Its process is `System`, which
/// is short enough to fit the 15-byte `_EPROCESS::ImageFileName` field — so it also cannot see the
/// truncation that field caused (`mm_exploit_v5.exe` → `mm_exploit_v5.`), which is exactly how
/// that bug survived a full green run of this tier.
const DRIVER_CRASH_DUMP: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/docs/samples/081226-2187-01.dmp"
);
/// The **ARM64** driver crash, and the counterpart to [`DRIVER_CRASH_DUMP`]: a
/// `0x139 KERNEL_SECURITY_CHECK_FAILURE` raised by HEVD's own `__report_gsfailure` after an
/// `IRP_MJ_DEVICE_CONTROL` overran the `/GS`-protected stack buffer behind
/// `HEVD_IOCTL_BUFFER_OVERFLOW_STACK_GS`.
///
/// It exists because the attribution arithmetic - a captured frame turned into `module+RVA` off
/// the load base - had never run against an **ARM64** stack
/// ([#154](https://github.com/glslang/windbg-mcp/issues/154)). The ARM64 sample that was already
/// here is a `0xFC` fault at a *user-mode* payload and carries no driver frame at all, which is
/// the opposite shape.
///
/// A fail fast is what makes it capturable: HEVD wraps its triggers in `__try/__except`, so its
/// null dereference, its non-paged pool overflow and its UAF double free all return a status and
/// leave the machine running. `brk #0xf003` cannot be caught, so the bug check is raised inside
/// the driver. `docs/smoke-test.md` has the recipe.
const ARM64_DRIVER_CRASH_DUMP: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/docs/samples/082126-7015-01.dmp"
);

/// An **ARM64** kernel dump — `0xFC ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY`, a user-mode process
/// jumping into memory that is not executable — so that an ARM64 run reads an ARM64 `_EPROCESS`,
/// an ARM64 image's headers and an ARM64 stack's frames. Nothing else in this suite does
/// ([#143](https://github.com/glslang/windbg-mcp/issues/143)); its provenance is in
/// `docs/smoke-test.md`.
///
/// Gated to match its only use: [`NATIVE_SAMPLE`] below, whose other arm an x64 build takes
/// instead. Ungated it is dead code on x64 - which is every run of this suite bar the ARM64
/// leg of the matrix, so the warning was the common case rather than the rare one.
#[cfg(target_arch = "aarch64")]
const ARM64_SAMPLE_DUMP: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/docs/samples/121524-4703-01.dmp"
);

/// A checked-in **driver** crash and the facts about it that
/// [`a_driver_crash_names_the_driver_frame_an_all_kernel_walk_would_miss`] asserts, so one test
/// body covers both architectures' stacks rather than naming one file.
struct DriverCrashSample {
    path: &'static str,
    /// What this host has to be able to do before the fixture is opened at all: an ARM64 crash on
    /// an x64 host and the reverse both read fine *with symbols*, so this is a label for the skip
    /// rather than a gate on the architecture.
    what: &'static str,
    /// `bug_check.code`: lowercase, unpadded.
    bug_check: &'static str,
    bug_check_name: &'static str,
    /// The third-party driver the crash belongs to, and the offset into it the faulting frame is
    /// expected at. The RVA is a literal on purpose rather than out of brittleness: it is a fixed
    /// offset into a fixed image, reproducible across every reboot and load base - five x64 dumps
    /// from the same loop reported `0x1654` at five different addresses - so a change in it means
    /// the attribution arithmetic moved.
    module: &'static str,
    rva: &'static str,
    /// A symbolised `nt` frame the same walk has to carry, which is what makes the point that one
    /// stack holds both kinds of frame - the mix every real driver crash has.
    kernel_frame: &'static str,
    /// Whether `!analyze` names [`Self::module`] itself.
    ///
    /// The two fixtures disagree, and the disagreement is the coverage. `MessageManager` has **no
    /// PDB**, so `!analyze` calls the crash `Unknown_Module` and the computed frame is the only
    /// thing that names the driver - which is why the frame is computed rather than taken from the
    /// analysis. `HEVD` ships a PDB, so `!analyze` does name it, and the computed frame is checked
    /// against an independent answer instead.
    analyze_names_the_module: bool,
    /// Whether `!analyze` reports a freed-pool tag, which only a few bug checks produce.
    carries_a_pool_tag: bool,
    /// Whether the crashing process's name is longer than the 15 bytes
    /// `_EPROCESS::ImageFileName` holds, so the audit name is the only way to report it whole.
    /// True for `mm_exploit_v5.exe`, which is what caught that field silently truncating it;
    /// `powershell.exe` fits, so the ARM64 fixture says nothing about that path.
    process_name_needs_the_audit_name: bool,
}

/// Every driver crash checked in, asserted on **every** host rather than paired by architecture.
///
/// Pairing is what the other fixtures do, and it would be wrong here. An engine that resolves
/// symbols reads either dump either way round (measured after
/// [#142](https://github.com/glslang/windbg-mcp/issues/142) turned out to be about symbols rather
/// than architecture), and pairing would mean an ARM64 runner stopped reading the x64 crash it
/// reads today - trading one architecture's coverage for the other's instead of adding it.
const DRIVER_CRASHES: &[DriverCrashSample] = &[
    DriverCrashSample {
        path: DRIVER_CRASH_DUMP,
        what: "the x64 MessageManager crash",
        bug_check: "0x13a",
        bug_check_name: "KERNEL_MODE_HEAP_CORRUPTION",
        module: "MessageManager",
        rva: "0x1654",
        kernel_frame: "nt!ExFreePoolWithTag",
        analyze_names_the_module: false,
        carries_a_pool_tag: true,
        process_name_needs_the_audit_name: true,
    },
    DriverCrashSample {
        path: ARM64_DRIVER_CRASH_DUMP,
        what: "the ARM64 HEVD crash",
        bug_check: "0x139",
        bug_check_name: "KERNEL_SECURITY_CHECK_FAILURE",
        module: "HEVD",
        // `mov w0, #2; brk #0xf003` - the ARM64 spelling of
        // `__fastfail(FAST_FAIL_STACK_COOKIE_CHECK_FAILURE)`, inside the driver's own
        // `__report_gsfailure`.
        rva: "0x10dc",
        kernel_frame: "nt!KeBugCheckEx",
        analyze_names_the_module: true,
        carries_a_pool_tag: false,
        process_name_needs_the_audit_name: false,
    },
];

/// A checked-in kernel dump and the facts about *that crash* a test asserts, so one test body can
/// be pointed at either real crash rather than naming one file.
struct KernelSample {
    path: &'static str,
    /// `bug_check.code`: lowercase, unpadded.
    bug_check: &'static str,
    /// The name out of this build's own table, which is why it needs no `!analyze`.
    bug_check_name: &'static str,
    /// `Arg1`, zero-padded to sixteen digits as the field renders it.
    first_parameter: &'static str,
    /// The crashing process, read out of the current `_EPROCESS`.
    process_name: &'static str,
}

impl KernelSample {
    /// How `!analyze` heads `FAILURE_BUCKET_ID`: `0x9F`, `0xFC` — digits upper-cased and the `0x`
    /// left alone, which is neither spelling of [`Self::bug_check`].
    fn bucket_prefix(&self) -> String {
        format!("0x{}", self.bug_check[2..].to_ascii_uppercase())
    }
}

/// The sample matching this host's architecture, which every test that reads a target opens.
///
/// The pairing is a choice about coverage, not a workaround: an engine with symbols reads either
/// dump either way round, which is why the driver crashes in [`DRIVER_CRASHES`] are all opened on
/// every host instead. See `docs/smoke-test.md`.
#[cfg(target_arch = "aarch64")]
const NATIVE_SAMPLE: KernelSample = KernelSample {
    path: ARM64_SAMPLE_DUMP,
    bug_check: "0xfc",
    bug_check_name: "ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY",
    // The address that was executed, where the x64 sample's `Arg1` is a subtype code.
    first_parameter: "0x0000019e7b820000",
    // Truncated at fifteen bytes: this dump does not capture the page
    // `SeAuditProcessCreationInfo` points at, so the engine falls back to
    // `_EPROCESS::ImageFileName` — the fallback [`DRIVER_CRASH_DUMP`]'s audit name avoids.
    process_name: "stack_buffer_o",
};

/// The x64 pairing, and the fixture this repo had first.
#[cfg(not(target_arch = "aarch64"))]
const NATIVE_SAMPLE: KernelSample = KernelSample {
    path: SAMPLE_DUMP,
    bug_check: "0x9f",
    bug_check_name: "DRIVER_POWER_STATE_FAILURE",
    // The `0x9F` subtype: 3, "a device object has been blocking an IRP for too long".
    first_parameter: "0x0000000000000003",
    // The watchdog fires on an idle CPU. What matters is that it is not the kernel image, which is
    // what `GetCurrentProcessExecutableName` answers on a kernel target for every process there
    // has ever been.
    process_name: "System",
};

// ---- harness ------------------------------------------------------------------

/// A spawned server plus a line-oriented JSON-RPC client for it.
struct Server {
    child: Child,
    stdin: Option<ChildStdin>,
    rx: Receiver<Option<String>>,
    stdout_log: Arc<Mutex<Vec<String>>>,
    stderr_log: Arc<Mutex<Vec<String>>>,
    /// Messages read while waiting for some other id (notifications, out-of-order replies).
    pending: VecDeque<Value>,
    next_id: i64,
}

impl Server {
    fn spawn() -> Self {
        Self::spawn_with(&[])
    }

    /// `env` is extra environment for the server process — the bounded-command tier uses it to
    /// shrink the per-call budget so a runaway command aborts in seconds rather than minutes.
    fn spawn_with(env: &[(&str, &str)]) -> Self {
        Self::spawn_with_args(env, &[])
    }

    /// The same, plus arguments on the server's own command line. `--tools` is the one that needs
    /// it: the surface is a startup decision, so the only way to test what a narrowed one serves is
    /// to start one.
    fn spawn_with_args(env: &[(&str, &str)], args: &[&str]) -> Self {
        let mut command = Command::new(EXE);
        command.args(args);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // Deterministic logging regardless of the developer's shell.
            .env("RUST_LOG", "info");
        for (key, value) in env {
            command.env(key, value);
        }
        let mut child = command
            .spawn()
            .unwrap_or_else(|e| panic!("failed to spawn {EXE}: {e}"));

        let stdout_log = Arc::new(Mutex::new(Vec::new()));
        let stderr_log = Arc::new(Mutex::new(Vec::new()));
        let (tx, rx) = channel();

        // stdout is the transport: every line is forwarded to the client loop *and* kept, so
        // a test can afterwards assert nothing else was written there.
        let out = BufReader::new(child.stdout.take().expect("piped stdout"));
        let log = Arc::clone(&stdout_log);
        std::thread::spawn(move || {
            for line in out.lines() {
                match line {
                    Ok(line) => {
                        log.lock().unwrap().push(line.clone());
                        if tx.send(Some(line)).is_err() {
                            return;
                        }
                    }
                    Err(_) => break,
                }
            }
            let _ = tx.send(None);
        });

        // stderr is drained continuously: left unread it fills the pipe buffer and deadlocks
        // the server mid-test, which would look like a protocol hang.
        let err = BufReader::new(child.stderr.take().expect("piped stderr"));
        let log = Arc::clone(&stderr_log);
        std::thread::spawn(move || {
            for line in err.lines().map_while(Result::ok) {
                log.lock().unwrap().push(line);
            }
        });

        Self {
            stdin: child.stdin.take(),
            child,
            rx,
            stdout_log,
            stderr_log,
            pending: VecDeque::new(),
            next_id: 1,
        }
    }

    /// Everything the server has written to stderr so far, for failure messages. A dep that
    /// breaks the handshake usually says why here.
    fn stderr(&self) -> String {
        self.stderr_log.lock().unwrap().join("\n")
    }

    /// Waits for a line on stderr. stdout and stderr are drained by independent threads with
    /// no ordering between them, so a bare snapshot can miss a line the server has already
    /// written — and that race would surface as an intermittent failure on a loaded runner,
    /// which is the worst kind of test to own.
    fn wait_for_stderr(&self, needle: &str, budget: Duration) -> bool {
        let deadline = Instant::now() + budget;
        loop {
            if self.stderr().contains(needle) {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn stdout_lines(&self) -> Vec<String> {
        self.stdout_log.lock().unwrap().clone()
    }

    fn send_line(&mut self, msg: &Value) {
        let stdin = self.stdin.as_mut().expect("stdin still open");
        writeln!(stdin, "{msg}").expect("write request");
        stdin.flush().expect("flush request");
    }

    fn notify(&mut self, method: &str, params: Value) {
        let msg = json!({ "jsonrpc": "2.0", "method": method, "params": params });
        self.send_line(&msg);
    }

    /// Sends a request and returns the response with the matching id.
    fn request(&mut self, method: &str, params: Value, budget: Duration) -> Value {
        let id = self.send_request(method, params);
        self.await_id(id, method, budget)
    }

    /// Sends a request and returns its id **without waiting for the answer**, so a test can keep
    /// driving the server while a call is still outstanding. That is the whole point of one of
    /// the tests below: a session that will never answer must not stop the others.
    fn send_request(&mut self, method: &str, params: Value) -> i64 {
        let id = self.next_id;
        self.next_id += 1;
        let msg = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        self.send_line(&msg);
        id
    }

    fn await_id(&mut self, id: i64, what: &str, budget: Duration) -> Value {
        let deadline = Instant::now() + budget;
        loop {
            if let Some(pos) = self.pending.iter().position(|m| m["id"] == json!(id)) {
                return self.pending.remove(pos).expect("checked position");
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                panic!(
                    "timed out after {budget:?} waiting for `{what}` (id {id})\n--- stderr ---\n{}",
                    self.stderr()
                );
            }
            match self.rx.recv_timeout(left) {
                Ok(Some(line)) => match serde_json::from_str::<Value>(&line) {
                    Ok(msg) => self.pending.push_back(msg),
                    Err(e) => panic!(
                        "server wrote a non-JSON line to stdout while answering `{what}`: {line:?} ({e})\n\
                         stdout is the JSON-RPC transport — a dependency logging there breaks every client.\n\
                         --- stderr ---\n{}",
                        self.stderr()
                    ),
                },
                Ok(None) | Err(RecvTimeoutError::Disconnected) => panic!(
                    "server closed stdout while answering `{what}` (id {id}) — it crashed or exited\n\
                     --- stderr ---\n{}",
                    self.stderr()
                ),
                Err(RecvTimeoutError::Timeout) => continue,
            }
        }
    }

    /// `initialize` + `notifications/initialized`, the pre-`2026-07-28` opener.
    fn initialize(&mut self, revision: &str) -> Value {
        let response = self.request(
            "initialize",
            json!({
                "protocolVersion": revision,
                "capabilities": {},
                "clientInfo": { "name": "windbg-mcp-smoke", "version": "1" },
            }),
            STEP,
        );
        assert_no_error(&response, &format!("initialize({revision})"));
        self.notify("notifications/initialized", json!({}));
        response["result"].clone()
    }

    /// A ready-to-use session on the newest revision, for tests that are not about the opener.
    fn started() -> Self {
        Self::started_with(&[])
    }

    fn started_with(env: &[(&str, &str)]) -> Self {
        let mut server = Self::spawn_with(env);
        server.initialize(SUPPORTED_REVISIONS[0]);
        server
    }

    fn started_with_args(env: &[(&str, &str)], args: &[&str]) -> Self {
        let mut server = Self::spawn_with_args(env, args);
        server.initialize(SUPPORTED_REVISIONS[0]);
        server
    }

    /// A request in `2026-07-28`'s stateless mode, where there is no handshake to remember the
    /// negotiated revision — so *every* request, not only the opener, has to carry it.
    fn stateless_request(&mut self, method: &str, mut params: Value, budget: Duration) -> Value {
        params["_meta"] = json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
        });
        self.request(method, params, budget)
    }

    fn call_tool(&mut self, name: &str, args: Value, budget: Duration) -> Value {
        self.request(
            "tools/call",
            json!({ "name": name, "arguments": args }),
            budget,
        )
    }

    /// A tool call that asks to be told how it is going. MCP's opt-in is a `progressToken` in the
    /// call's own `_meta`, and nothing is sent to a client that did not put one there.
    fn call_tool_watching(
        &mut self,
        name: &str,
        args: Value,
        token: &str,
        budget: Duration,
    ) -> Value {
        self.request(
            "tools/call",
            json!({
                "name": name,
                "arguments": args,
                "_meta": { "progressToken": token },
            }),
            budget,
        )
    }

    /// The `notifications/progress` this server sent for `token`, oldest first, taken out of the
    /// queue of messages read while waiting for something else.
    ///
    /// That they are *in* that queue is half the assertion: a progress notification arrives while
    /// the call is still running, so by the time its result has been matched they are already
    /// here. One that arrived afterwards would be a notification about a call that was over.
    fn progress_for(&mut self, token: &str) -> Vec<Value> {
        let ours = |m: &Value| {
            m["method"] == json!("notifications/progress")
                && m["params"]["progressToken"] == json!(token)
        };
        let taken: Vec<Value> = self.pending.iter().filter(|m| ours(m)).cloned().collect();
        self.pending.retain(|m| !ours(m));
        taken
    }

    /// The text of a tool call that **worked**, for the callers that only proceed if it did.
    ///
    /// Strict about `isError`, not just about protocol errors, and that is the whole point. This
    /// used to hand back a tool error's text as readily as a result, which reads as harmless —
    /// the text is still there to assert on — and is not: a *failed* call also returns in
    /// milliseconds, and its text contains none of the phrases a happy-path assertion looks for.
    /// So a caller measuring how long something took gets a number produced by nothing happening,
    /// and a caller branching on content takes the `else`. Both were live in the pool tier: a
    /// walk that never ran satisfied its deadline in 6.8ms, and a lookup that had errored was
    /// reported as proof that the tag existed.
    ///
    /// A test that *expects* a failure has always used [`Self::call_tool`] with [`is_tool_error`],
    /// which is the right way round: the dangerous reading should be the one you have to spell out.
    fn tool_text(&mut self, name: &str, args: Value, budget: Duration) -> String {
        let response = self.call_tool(name, args, budget);
        assert_no_error(&response, &format!("tools/call {name}"));
        let text = text_of(&response["result"]);
        assert!(
            !is_tool_error(&response),
            "`{name}` reported a tool error, so nothing that follows is measuring what it \
             thinks:\n{text}"
        );
        text
    }

    /// The **structured** result of a tool call that worked.
    ///
    /// The typed counterpart of [`Self::tool_text`], and the one to reach for: a field is a
    /// contract, where the text it accompanies is a rendering that may be reworded at any time.
    /// Asserts the outcome is the `ok` branch, so a test asking for `matches` cannot silently
    /// read a failure that has no such field.
    fn tool_data(&mut self, name: &str, args: Value, budget: Duration) -> Value {
        let response = self.call_tool(name, args, budget);
        assert_no_error(&response, &format!("tools/call {name}"));
        let result = &response["result"];
        let data = result["structuredContent"].clone();
        assert!(
            !data.is_null(),
            "`{name}` declares an outputSchema, so every result must carry structuredContent; \
             got:\n{}",
            text_of(result)
        );
        assert_eq!(
            data["status"],
            "ok",
            "`{name}` did not succeed: {}",
            text_of(result)
        );
        data
    }

    /// Opens a target and hands back the handle, read as a field.
    ///
    /// The handle used to be recovered from the `session_id:` line an opener prints, which is the
    /// single most-parsed piece of prose this server emits — and the one every client needs.
    fn open_session(&mut self, tool: &str, args: Value, budget: Duration) -> String {
        let data = self.tool_data(tool, args, budget);
        data["session_id"]
            .as_str()
            .unwrap_or_else(|| panic!("`{tool}` opened without minting a handle: {data}"))
            .to_string()
    }

    /// The structured result of a call that was **expected** to fail, with its category checked.
    fn tool_failure(&mut self, name: &str, args: Value, budget: Duration) -> Value {
        let response = self.call_tool(name, args, budget);
        assert_no_error(&response, &format!("tools/call {name}"));
        assert!(
            is_tool_error(&response),
            "`{name}` was expected to fail but did not:\n{}",
            text_of(&response["result"])
        );
        let data = response["result"]["structuredContent"].clone();
        assert_eq!(
            data["status"], "error",
            "a failing `{name}` must carry the error branch of its own output schema, got: {data}"
        );
        data
    }

    /// Terminates the supervisor outright, giving it no chance to run its own shutdown.
    ///
    /// Stdin is *not* closed first — that would be the graceful path this is the opposite of. The
    /// point is to leave the workers with nothing but EOF on their own request channels, as the
    /// dead supervisor's handles are closed.
    fn kill_supervisor(mut self) {
        self.child.kill().expect("terminate the supervisor");
        self.child.wait().expect("reap the supervisor");
    }

    /// Closes stdin and waits for exit, returning the exit code.
    fn shutdown(mut self) -> Option<i32> {
        drop(self.stdin.take());
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            match self.child.try_wait().expect("poll child") {
                Some(status) => return status.code(),
                None if Instant::now() >= deadline => {
                    let _ = self.child.kill();
                    panic!(
                        "server did not exit within 20s of stdin closing — an MCP client would \
                         leave this process behind on every disconnect\n--- stderr ---\n{}",
                        self.stderr()
                    );
                }
                None => std::thread::sleep(Duration::from_millis(50)),
            }
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        drop(self.stdin.take());
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn assert_no_error(response: &Value, what: &str) {
    assert!(
        response["error"].is_null(),
        "`{what}` was answered with a JSON-RPC error: {}",
        response["error"]
    );
}

/// Concatenates the text blocks of a `tools/call` result.
fn text_of(result: &Value) -> String {
    result["content"]
        .as_array()
        .map(|blocks| {
            blocks
                .iter()
                .filter_map(|b| b["text"].as_str())
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default()
}

/// Whether a tool call came back flagged as a *tool* error (`isError: true`), which is the
/// only way a debugger failure is allowed to surface.
fn is_tool_error(response: &Value) -> bool {
    response["result"]["isError"] == json!(true)
}

/// Whether a string still holds the debugger's own address form — `fffff801`3c677ef0`, eight hex
/// digits either side of a backtick. The server normalises those out of instruction text and
/// deliberately leaves every other backtick alone, so this is what an assertion about it can test
/// without depending on which symbols a host resolved.
fn carries_a_backtick_address(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.iter().enumerate().any(|(at, byte)| {
        *byte == b'`'
            && at >= 8
            && at + 8 < bytes.len()
            && bytes[at - 8..at].iter().all(u8::is_ascii_hexdigit)
            && bytes[at + 1..at + 9].iter().all(u8::is_ascii_hexdigit)
    })
}

fn skip(reason: &str) {
    eprintln!("SKIPPED: {reason}");
}

/// The counterpart to [`skip`]: a tier saying it reached the end of its assertions.
///
/// **libtest cannot tell a tier that covered something from one that stood down**, because
/// [`skip`] returns normally — so the test reports `test <name> ... ok` either way, and a CI step
/// checking for that line passes over a run that asserted nothing. That is not a supposition: the
/// step guarding the 32-bit tier was written that way first, and waving through a deliberately
/// stood-down run is how it was found.
///
/// The alternative is a CI-side list of the tier's skip messages, which is a list that has to be
/// kept in step with this file and is silently wrong for one round when a new stand-down is added.
/// A marker the test prints itself cannot drift: a stand-down simply never reaches it.
///
/// Needs `--nocapture` to reach a log, exactly as `SKIPPED` does.
fn ran(what: &str) {
    eprintln!("RAN: {what}");
}

// ---- tier 1: transport --------------------------------------------------------

/// stdout is the JSON-RPC channel. Anything else written there — a dependency's banner, a
/// `println!` that slipped in, a panic message — desynchronizes every client, and the client
/// side of that failure is unreadable ("unexpected token"). Cheapest possible dep tripwire.
#[test]
fn stdout_carries_only_json_rpc_and_logging_goes_to_stderr() {
    let mut server = Server::started();
    server.request("tools/list", json!({}), STEP);
    let text = server.tool_text("decode_ioctl", json!({ "code": "0x70000" }), STEP);
    assert!(!text.is_empty(), "expected decoded output");

    for line in server.stdout_lines() {
        let msg: Value = serde_json::from_str(&line)
            .unwrap_or_else(|e| panic!("non-JSON line on stdout: {line:?} ({e})"));
        assert_eq!(msg["jsonrpc"], "2.0", "non-JSON-RPC line on stdout: {line}");
    }

    // The counterpart: the startup log has to be somewhere, and that somewhere is stderr.
    assert!(
        server.wait_for_stderr("windbg-mcp starting on stdio", STEP),
        "expected the startup log on stderr, got:\n{}",
        server.stderr()
    );
}

/// Closing stdin is how every MCP client disconnects. A server that does not notice leaks a
/// process (and, here, a DbgEng session) per connection.
#[test]
fn server_exits_when_its_stdin_closes() {
    let mut server = Server::started();
    server.request("tools/list", json!({}), STEP);
    assert_eq!(
        server.shutdown(),
        Some(0),
        "clean disconnect should be a clean exit"
    );
}

/// A client that sends garbage — or a framing bug in a client library — must not take the
/// server down with it; the next well-formed request still has to be answered.
#[test]
fn a_malformed_line_does_not_kill_the_server() {
    let mut server = Server::started();
    server.send_line(&json!("this is not a JSON-RPC message"));
    server
        .stdin
        .as_mut()
        .map(|s| writeln!(s, "{{ not even json"))
        .transpose()
        .expect("write malformed line");

    let response = server.request("tools/list", json!({}), STEP);
    assert_no_error(&response, "tools/list after malformed input");
    assert!(
        response["result"]["tools"].is_array(),
        "server should still serve tools after malformed input"
    );
}

// ---- tier 1: the artefact itself ----------------------------------------------

/// What this build calls itself, exactly as `main::BUILD_VERSION` composes it: the crate version,
/// plus the git revision `build.rs` stamped when there was one to stamp.
///
/// Read from `WINDBG_MCP_BUILD` — the build script's own answer — rather than from whether a `.git`
/// is present, because the fallback to a bare crate version is deliberate and a `.git`-exists proxy
/// would fail a perfectly good build that git declined to describe. It also means a `build.rs` that
/// stopped running fails to compile this rather than passing it.
fn stamped_version() -> String {
    let stamp = env!("WINDBG_MCP_BUILD");
    if stamp.is_empty() {
        env!("CARGO_PKG_VERSION").to_string()
    } else {
        format!("{}+{}", env!("CARGO_PKG_VERSION"), stamp)
    }
}

/// The binary has to carry a PE version resource, and `build.rs` will not fail the build if it
/// cannot produce one — so this is the only place that says whether it did.
///
/// **Why the resource matters at all.** Defender quarantined a freshly built `windbg-mcp.exe` as
/// `Trojan:Win32/Bearfoos.B!ml` on 2026-08-26, blocking every test that spawns the server. That is
/// a machine-learning verdict rather than a signature match — the same source lands either side of
/// the line on different days — and an empty `FileVersion`/`CompanyName`/`ProductName` is one of
/// the two causes Microsoft names for exactly that detection on its own shipped binaries
/// (`microsoft/apm#487`, `FOLLOWUPS.md` item 50). A Rust binary carries none by default.
///
/// **Why it is a test and not a hard failure in `build.rs`.** The resource needs `rc.exe`, and the
/// `cargo check --target x86_64-pc-windows-msvc` this repo runs from a Mac has none — a workflow
/// `CLAUDE.md` documents and that must not start failing over metadata. So the build script warns
/// and carries on, and the check moves here, where it only ever runs on the host that can build one.
///
/// The split in what is pinned is deliberate: the fields a *checker* compares are pinned to their
/// values, and the ones a human reads are asserted non-empty, so rewording the prose is not a test
/// edit while renaming the product is.
#[test]
fn the_binary_carries_a_pe_version_resource() {
    let pinned = [
        ("CompanyName", "glslang".to_string()),
        ("ProductName", "windbg-mcp".to_string()),
        ("OriginalFilename", "windbg-mcp.exe".to_string()),
        ("InternalName", "windbg-mcp.exe".to_string()),
        // The release, and — separately — the build under it, which is semver's own split and
        // makes the properties dialog answer the question `serverInfo.version` answers.
        ("FileVersion", env!("CARGO_PKG_VERSION").to_string()),
        ("ProductVersion", stamped_version()),
    ];
    for (field, want) in pinned {
        assert_eq!(read_version_field(EXE, field), want, "{field} in {EXE}");
    }
    for field in ["FileDescription", "LegalCopyright", "Comments"] {
        assert!(
            !read_version_field(EXE, field).is_empty(),
            "{field} must not be empty in {EXE}"
        );
    }
}

/// Every field of that resource, so the test below can assert the 32-bit worker agrees with this
/// build on all of them rather than on a subset chosen by hand.
const VERSION_FIELDS: &[&str] = &[
    "CompanyName",
    "ProductName",
    "OriginalFilename",
    "InternalName",
    "FileVersion",
    "ProductVersion",
    "FileDescription",
    "LegalCopyright",
    "Comments",
];

/// **The 32-bit worker is a shipped binary too, and the test above does not cover it.**
///
/// `EXE` is this build — the host's architecture — so until this existed nothing read
/// `x86\windbg-mcp.exe`'s resource at all, on any host or in CI. That is the same gap the test
/// above was written to close, one binary along: `build.rs` will not fail a build it could not
/// embed a resource into, so a 32-bit worker that quietly lost one would ship in the `.zip` and the
/// `.mcpb` with nothing saying so. An absent version resource is one of the two causes Microsoft
/// names for the `Bearfoos.B!ml` verdict, and a quarantined worker is a server that silently
/// degrades to "SOS is unreachable" rather than one that fails.
///
/// **Asserted against this build's values rather than against literals**, which is why the pins
/// live in the test above and not here: the two binaries are one product from one build, so the
/// claim is that they *agree*. Pinning the strings twice would let the copies drift apart while
/// both tests passed, and would double the edit a reworded `FileDescription` costs.
///
/// **Gated on the worker and not on the 32-bit engine**, unlike [`x86_engine_tier`]. The engine is
/// what makes a 32-bit *target* openable, and none is needed to read a file's resource — CI builds
/// the worker on runners that may carry no x86 engine payload, and gating on the engine would skip
/// this there for a reason that has nothing to do with what it checks.
#[test]
fn the_32_bit_worker_carries_the_same_version_resource() {
    let Some(worker) = std::path::Path::new(EXE)
        .parent()
        .map(|dir| dir.join("x86").join("windbg-mcp.exe"))
        .filter(|p| p.is_file())
    else {
        skip(
            "no `x86\\windbg-mcp.exe` beside the server under test, so there is no 32-bit worker \
             to read a version resource from — `cargo build --target i686-pc-windows-msvc` and \
             `skills/windbg-debugging/setup.md` have the copy block",
        );
        return;
    };
    let worker = worker.to_string_lossy().into_owned();

    for field in VERSION_FIELDS {
        assert_eq!(
            read_version_field(&worker, field),
            read_version_field(EXE, field),
            "`{field}` must match this build's — the 32-bit worker is the same product from the \
             same build, and a client cannot tell which architecture served its session"
        );
    }
    ran("the 32-bit worker's version resource matches this build's");
}

/// One `StringFileInfo` value out of the binary's own version resource, read through the API
/// Explorer's properties dialog reads it through — rather than by scanning the file for the string,
/// which would pass on a resource Windows itself refuses to parse.
///
/// Panics rather than returning an `Option`, because every way this can answer nothing is the same
/// failure: no resource was embedded.
///
/// Takes the executable rather than reading [`EXE`], because the release ships **two** binaries
/// that must each carry one — this build and the 32-bit worker beside it.
fn read_version_field(exe: &str, field: &str) -> String {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW,
    };

    fn wide(text: &str) -> Vec<u16> {
        OsStr::new(text)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    /// One sub-block of a version-info block, as the UTF-16 units it holds — `None` where the block
    /// has no such key.
    ///
    /// **Borrowed from `block`**, so the compiler enforces what a raw pointer out of
    /// `VerQueryValueW` cannot say for itself. Returning the pointer instead put a value with no
    /// lifetime across a function boundary, and nothing but a comment then stopped a later edit
    /// reading it after `block` had gone; CodeQL was right to call that an invalid dereference.
    ///
    /// **`unit_bytes` is what `VerQueryValueW` reports the length *in*, and it is not one answer:**
    /// `\VarFileInfo\Translation` comes back as a **byte** count and a string value as a
    /// **character** count. That asymmetry is documented, and it is exactly what a helper that
    /// picked one unit would turn into a slice running off the end of the block — so the caller
    /// names it.
    fn query<'a>(block: &'a [u8], sub: &str, unit_bytes: u32) -> Option<&'a [u16]> {
        let sub = wide(sub);
        let mut value: *mut core::ffi::c_void = std::ptr::null_mut();
        let mut len: u32 = 0;
        // SAFETY: `block` holds a version-info block written by `GetFileVersionInfoW`, and `sub` is
        // NUL-terminated. `value` and `len` are written only on success.
        let found =
            unsafe { VerQueryValueW(block.as_ptr().cast(), sub.as_ptr(), &mut value, &mut len) };
        let units = (len as usize * unit_bytes as usize) / size_of::<u16>();
        (found != 0 && units > 0).then(|| {
            // SAFETY: on success the value lies inside `block` and spans `units` UTF-16 units, so
            // the slice is in bounds — and the returned lifetime is `block`'s, which is what makes
            // that hold for every read of it rather than only for the ones written today.
            unsafe { std::slice::from_raw_parts(value.cast::<u16>().cast_const(), units) }
        })
    }

    let missing = |what: &str| -> ! {
        panic!(
            "{exe} carries no `{field}` in a PE version resource ({what}). A Rust binary has none \
             by default, so this is what a `build.rs` that could not run a resource compiler \
             leaves behind — the build printed a `cargo::warning` saying why."
        )
    };

    let path = wide(exe);
    // SAFETY: `path` is NUL-terminated and outlives the call. The handle out-parameter is
    // documented as ignorable, and a null pointer is how that is spelled.
    let size = unsafe { GetFileVersionInfoSizeW(path.as_ptr(), std::ptr::null_mut()) };
    if size == 0 {
        missing("the file has no version resource at all");
    }
    let mut block = vec![0u8; size as usize];
    // SAFETY: `block` is exactly the `size` bytes the call above asked for.
    if unsafe { GetFileVersionInfoW(path.as_ptr(), 0, size, block.as_mut_ptr().cast()) } == 0 {
        missing("its version resource would not load");
    }

    // A value's key is qualified by language and codepage, and the block says which pair it wrote:
    // `winresource` emits the *language-neutral* `000004b0`, so the `040904b0` a hard-coded key
    // would name reads nothing at all.
    let Some(translation) = query(&block, r"\VarFileInfo\Translation", 1) else {
        missing("its version resource declares no translation");
    };
    // A `Translation` value is a run of (language, codepage) pairs; the first is the one to use.
    if translation.len() < 2 {
        missing("its translation table is shorter than one language/codepage pair");
    }
    let (language, codepage) = (translation[0], translation[1]);

    let key = format!(r"\StringFileInfo\{language:04x}{codepage:04x}\{field}");
    let Some(text) = query(&block, &key, size_of::<u16>() as u32) else {
        missing("its version resource carries no such field");
    };
    String::from_utf16_lossy(text)
        .trim_end_matches('\0')
        .to_string()
}

// ---- tier 1: protocol revisions -----------------------------------------------

/// `docs/architecture.md` names the revisions this server speaks. When the spec revs, this is the
/// list to extend — and the test that says whether the SDK bump actually delivered it.
#[test]
fn every_documented_protocol_revision_is_served() {
    for revision in SUPPORTED_REVISIONS {
        let mut server = Server::spawn();
        let result = server.initialize(revision);

        let served = result["protocolVersion"]
            .as_str()
            .unwrap_or_else(|| panic!("initialize({revision}) returned no protocolVersion"));
        assert_eq!(
            served, *revision,
            "a client offering `{revision}` must be served that revision, not `{served}`"
        );
        assert!(
            !result["capabilities"]["tools"].is_null(),
            "initialize({revision}) must advertise the tools capability: {result}"
        );

        // The server has to introduce itself as itself on every revision — left to the SDK's
        // default this reads `rmcp` at the SDK's version.
        assert_eq!(result["serverInfo"]["name"], "windbg-mcp", "on {revision}");
        // **A prefix, not an equality.** `build.rs` appends the git revision this binary was built
        // from as semver build metadata (`0.11.0+g1a2b3c4`), so the whole string is not a constant
        // this test can name — and the part that must not drift to the SDK's is the release.
        let reported = result["serverInfo"]["version"]
            .as_str()
            .unwrap_or_else(|| panic!("serverInfo.version must be a string on {revision}"));
        assert!(
            reported.starts_with(env!("CARGO_PKG_VERSION")),
            "the reported version must track this crate, not the SDK (on {revision}): {reported}"
        );
        // And the suffix is checked against **what this build actually stamped**, rather than
        // against whether a `.git` is lying about. `build.rs` falls back to the bare crate version
        // whenever git is unavailable or refuses — a minimal builder, or git's own safe-directory
        // check — which is deliberate and would fail a `.git`-exists proxy on a perfectly good
        // build. `WINDBG_MCP_BUILD` is the build script's own answer, so this asserts the served
        // version *is* the one it produced — and a `build.rs` that stopped running fails to
        // compile this rather than passing it.
        assert_eq!(
            reported,
            stamped_version(),
            "the served version must be the one this build stamped (on {revision})"
        );

        // Tools must be reachable on every revision, not just the newest.
        let tools = server.request("tools/list", json!({}), STEP);
        assert_no_error(&tools, &format!("tools/list on {revision}"));
        assert!(
            tools["result"]["tools"]
                .as_array()
                .is_some_and(|t| !t.is_empty()),
            "tools/list must be non-empty on {revision}"
        );
        assert_cache_fields_match_revision(&tools["result"], revision, "tools/list");
    }
}

/// SEP-2549's `ttlMs`/`cacheScope`, which `2026-07-28` makes **required** on a paginated result.
///
/// A client that validates responses against the spec schema rejects the entire `tools/list`
/// reply when they are missing — the server reads as connected with zero tools. That is not
/// hypothetical: every `rmcp` before 3.1.1 generated exactly that response from the documented
/// macro path, and it shipped (upstream issue #1114, fixed by #1120). The fields come from the
/// SDK, so this is a guard on the dependency floor in `Cargo.toml` — the one test that fails if
/// a resolver ever picks an older 3.x. Older revisions never defined the fields and must not be
/// served them. `assert_no_error` sees none of this: both shapes are valid JSON-RPC results.
fn assert_cache_fields_match_revision(result: &Value, revision: &str, what: &str) {
    if revision >= "2026-07-28" {
        assert_eq!(
            result["ttlMs"], 0,
            "{what} on {revision} must carry a numeric `ttlMs` (SEP-2549): {result}"
        );
        assert_eq!(
            result["cacheScope"], "public",
            "{what} on {revision} must carry `cacheScope` (SEP-2549): {result}"
        );
    } else {
        assert!(
            result["ttlMs"].is_null() && result["cacheScope"].is_null(),
            "{what} on {revision} predates SEP-2549 and must not carry its fields: {result}"
        );
    }
}

/// An unknown revision must be negotiated down, not refused: a newer client than the SDK
/// knows about should still get a usable session.
#[test]
fn an_unknown_protocol_revision_is_negotiated_down() {
    let mut server = Server::spawn();
    let response = server.request(
        "initialize",
        json!({
            "protocolVersion": "2999-01-01",
            "capabilities": {},
            "clientInfo": { "name": "windbg-mcp-smoke", "version": "1" },
        }),
        STEP,
    );
    assert_no_error(&response, "initialize(unknown revision)");
    assert_eq!(
        response["result"]["protocolVersion"], FALLBACK_REVISION,
        "an unknown revision should be answered with the documented fallback"
    );
}

/// `2026-07-28` lets a client skip the handshake entirely. `src/server.rs` pins this over an
/// in-process duplex; here it is the shipped executable, because "can this client connect at
/// all" is a property of the process, not of `get_info`.
#[test]
fn discover_opens_a_session_without_initialize() {
    let mut server = Server::spawn();
    let response = server.stateless_request("server/discover", json!({}), STEP);
    assert_no_error(&response, "server/discover");
    let result = &response["result"];

    // SEP-2322: the discriminator is mandatory, and a client that parses by it cannot read a
    // response without one.
    assert_eq!(result["resultType"], "complete");

    let versions = result["supportedVersions"]
        .as_array()
        .unwrap_or_else(|| panic!("discover must advertise supportedVersions: {result}"));
    for expected in SUPPORTED_REVISIONS {
        assert!(
            versions.iter().any(|v| v == expected),
            "discover must advertise `{expected}`, got {versions:?}"
        );
    }

    // A discover-first client learns the server from this one response and nothing else.
    assert!(
        !result["capabilities"]["tools"].is_null(),
        "discover must advertise the tools capability: {result}"
    );
    let instructions = result["instructions"]
        .as_str()
        .unwrap_or_else(|| panic!("discover must carry the server instructions: {result}"));
    assert!(
        instructions.contains("WinDbg"),
        "instructions should be this server's, got {instructions:?}"
    );
    // **What the client reads, not what the server sends.** Measured at 2,048 characters; the text
    // was 3,147 for a long time, so a third of it was paid for on every connection and never
    // arrived — and what fell off the end was the `debug_batch` paragraph, the one instruction here
    // that stops a mutation being left half-applied. Asserted on both counts because they are the
    // same number only while the text stays ASCII, and an em dash is three bytes.
    const INSTRUCTIONS_BUDGET: usize = 2_048;
    assert!(
        instructions.chars().count() <= INSTRUCTIONS_BUDGET
            && instructions.len() <= INSTRUCTIONS_BUDGET,
        "the instructions are {} chars / {} bytes, past the {INSTRUCTIONS_BUDGET} a client reads — \
         the tail is charged for and discarded, so trim it rather than letting it fall off:\n\
         {instructions}",
        instructions.chars().count(),
        instructions.len(),
    );
    assert!(
        instructions.contains("debug_batch"),
        "the batch guidance is the part that used to be truncated away; it has to survive any \
         future trim: {instructions:?}"
    );

    // Tools have to be reachable on a session opened this way, not merely listed by discover.
    let tools = server.stateless_request("tools/list", json!({}), STEP);
    assert_no_error(&tools, "tools/list after discover");
    assert!(
        tools["result"]["tools"]
            .as_array()
            .is_some_and(|t| !t.is_empty()),
        "tools/list must be non-empty for a discover-first client: {tools}"
    );
    // This client's revision arrives per-request rather than from a handshake, so it reaches
    // the handler by a different route than the loop above covers.
    assert_cache_fields_match_revision(&tools["result"], "2026-07-28", "stateless tools/list");

    // The stateless rule itself: with no handshake to remember the revision, a request that
    // omits the per-request `_meta` is refused. Pinned because a client library that sends it
    // only on the opener would fail here and nowhere else.
    let bare = server.request("tools/list", json!({}), STEP);
    assert_eq!(
        bare["error"]["code"], -32602,
        "a stateless request without `_meta` must be an invalid-params error, got {bare}"
    );
}

/// Advertising a capability the server does not implement is worse than not advertising it:
/// clients route real calls into a `method_not_found`. This asserts the honest surface — if an
/// SDK bump switches something on for us, this test is where you find out and decide whether
/// to implement it or suppress it.
#[test]
fn capabilities_advertise_only_what_is_implemented() {
    let mut server = Server::spawn();
    let result = server.initialize(SUPPORTED_REVISIONS[0]);
    let capabilities = &result["capabilities"];

    assert!(
        !capabilities["tools"].is_null(),
        "tools must be advertised: {capabilities}"
    );
    for unimplemented in ["resources", "prompts", "completions", "logging"] {
        assert!(
            capabilities[unimplemented].is_null(),
            "`{unimplemented}` is advertised but this server implements no such handler — \
             clients will call it and get method_not_found: {capabilities}"
        );
    }

    // Tasks (`io.modelcontextprotocol/tasks`, SEP-2663) are deliberately not implemented —
    // see FOLLOWUPS.md item 8. The advertisement and the behaviour have to agree.
    assert!(
        capabilities["extensions"].is_null(),
        "no protocol extension is implemented yet, so none may be advertised: {capabilities}"
    );
    let tasks = server.request("tasks/get", json!({ "taskId": "nope" }), STEP);
    assert_eq!(
        tasks["error"]["code"], -32601,
        "an unimplemented extension method must be method_not_found, got {tasks}"
    );
}

// ---- tier 1: tool surface -----------------------------------------------------

/// Describes a schema node tightly enough that a dialect or codegen change shows up, without
/// churning on prose edits.
fn describe_type(node: &Value) -> String {
    describe_type_with_defs(node, None)
}

fn enum_values<'a>(
    node: &'a Value,
    definitions: Option<&'a serde_json::Map<String, Value>>,
) -> Option<&'a Vec<Value>> {
    node.get("enum").and_then(Value::as_array).or_else(|| {
        let name = node.get("$ref")?.as_str()?.strip_prefix("#/$defs/")?;
        definitions?.get(name)?.get("enum")?.as_array()
    })
}

fn describe_type_with_defs(
    node: &Value,
    definitions: Option<&serde_json::Map<String, Value>>,
) -> String {
    if let Some(variants) = enum_values(node, definitions) {
        let names: Vec<String> = variants.iter().map(|v| v.to_string()).collect();
        return format!("enum[{}]", names.join("|"));
    }
    if let Some(branches) = node.get("anyOf").and_then(Value::as_array)
        && branches
            .iter()
            .any(|branch| enum_values(branch, definitions).is_some())
    {
        return branches
            .iter()
            .map(|branch| describe_type_with_defs(branch, definitions))
            .collect::<Vec<_>>()
            .join("|");
    }
    if let Some(reference) = node.get("$ref").and_then(|r| r.as_str()) {
        return format!("ref({reference})");
    }
    let base = match &node["type"] {
        Value::String(t) => t.clone(),
        Value::Array(ts) => ts
            .iter()
            .filter_map(|t| t.as_str())
            .collect::<Vec<_>>()
            .join("|"),
        _ => "any".to_string(),
    };
    let base = match node.get("items") {
        Some(items) if base.starts_with("array") => {
            format!("array<{}>", describe_type_with_defs(items, definitions))
        }
        _ => base,
    };
    match node.get("format").and_then(|f| f.as_str()) {
        Some(format) => format!("{base}/{format}"),
        None => base,
    }
}

#[test]
fn nullable_enum_keeps_its_allowed_values_in_the_golden_digest() {
    let schema = json!({
        "anyOf": [
            { "type": "string", "enum": ["lfh", "vs", "segment", "large"] },
            { "type": "null" }
        ]
    });
    assert_eq!(
        describe_type(&schema),
        "enum[\"lfh\"|\"vs\"|\"segment\"|\"large\"]|null"
    );

    let definitions = json!({
        "HeapBackendArg": {
            "type": "string",
            "enum": ["lfh", "vs", "segment", "large"]
        }
    });
    let referenced = json!({
        "anyOf": [
            { "$ref": "#/$defs/HeapBackendArg" },
            { "type": "null" }
        ]
    });
    assert_eq!(
        describe_type_with_defs(&referenced, definitions.as_object()),
        "enum[\"lfh\"|\"vs\"|\"segment\"|\"large\"]|null"
    );
}

/// The structural contract of one tool: everything a client binds against, minus the prose.
fn digest_tool(tool: &Value) -> Value {
    let schema = &tool["inputSchema"];
    let definitions = schema["$defs"].as_object();
    let mut params: Vec<String> = schema["properties"]
        .as_object()
        .map(|props| {
            props
                .iter()
                .map(|(name, node)| {
                    format!("{name}: {}", describe_type_with_defs(node, definitions))
                })
                .collect()
        })
        .unwrap_or_default();
    params.sort();

    let mut required: Vec<String> = schema["required"]
        .as_array()
        .map(|r| {
            r.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    required.sort();

    let annotations = &tool["annotations"];
    json!({
        "name": tool["name"],
        "title": annotations["title"],
        "hints": {
            "readOnly": annotations["readOnlyHint"],
            "destructive": annotations["destructiveHint"],
            "idempotent": annotations["idempotentHint"],
            "openWorld": annotations["openWorldHint"],
        },
        "required": required,
        "params": params,
        "output": digest_output_schema(&tool["outputSchema"]),
    })
}

/// The shape of a tool's declared `outputSchema`, or `null` for a tool that declares none.
///
/// Recorded because this is the half of the contract a client validates *results* against, and
/// it is generated rather than written: a `schemars` bump that changed how a discriminated union
/// is emitted would otherwise land silently on every consumer. The digest keeps the branch shape
/// rather than the whole schema — the point is that the discriminator and its branches survive,
/// not the wording of every field's description.
///
/// The root `type` is in it for the same reason and one sharper one: it is the keyword whose
/// absence costs a strict client every tool on the list rather than the one tool that lacks it
/// (issue #223), and it is supplied by `src/schema.rs` rather than by the generator — so a
/// `schemars` release that started emitting one, or a change that stopped supplying it, is a line
/// of this diff either way. [`output_schemas_are_object_rooted`] is the assertion; this is the
/// record.
fn digest_output_schema(schema: &Value) -> Value {
    if schema.is_null() {
        return Value::Null;
    }
    // Every result schema here is a `oneOf` over the outcome's branches; each branch pins
    // `status` to a const and lists what that branch requires.
    let branches: Vec<Value> = schema["oneOf"]
        .as_array()
        .map(|branches| {
            branches
                .iter()
                .map(|branch| {
                    let mut required: Vec<String> = branch["required"]
                        .as_array()
                        .map(|r| {
                            r.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default();
                    required.sort();
                    json!({
                        "status": branch["properties"]["status"]["const"],
                        // The payload rides in on a `$ref` beside the discriminator, so the
                        // reference is what names *which* result this branch describes.
                        "payload": branch["$ref"],
                        "required": required,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    json!({
        "dialect": schema["$schema"],
        "root": schema["type"],
        "branches": branches,
    })
}

/// The whole `tools/list` surface, normalized: JSON Schema dialect, then one digest per tool.
fn digest_tool_list(tools: &[Value]) -> Value {
    let dialects: Vec<String> = {
        let mut seen: Vec<String> = tools
            .iter()
            .map(|t| match t["inputSchema"]["$schema"].as_str() {
                Some(s) => s.to_string(),
                None => "(none)".to_string(),
            })
            .collect();
        seen.sort();
        seen.dedup();
        seen
    };
    let uses_defs = tools.iter().any(|t| {
        !t["inputSchema"]["$defs"].is_null() || !t["inputSchema"]["definitions"].is_null()
    });

    json!({
        "schemaDialects": dialects,
        "usesDefs": uses_defs,
        "toolCount": tools.len(),
        "tools": tools.iter().map(digest_tool).collect::<Vec<_>>(),
    })
}

/// A golden snapshot of the tool surface as it appears **on the wire**. This is the highest-
/// signal dependency tripwire in the file: a `schemars` bump changing dialect or nullable
/// encoding, an `rmcp` bump changing annotation casing, or an accidental tool rename all land
/// here as a readable diff.
///
/// Intentional changes: re-record with `UPDATE_GOLDEN=1 cargo test --test mcp_smoke` and read
/// the resulting diff before committing it.
#[test]
fn tools_list_matches_the_recorded_wire_surface() {
    let mut server = Server::started();
    let response = server.request("tools/list", json!({}), STEP);
    assert_no_error(&response, "tools/list");
    let tools = response["result"]["tools"]
        .as_array()
        .expect("tools/list returns an array")
        .clone();

    let actual = digest_tool_list(&tools);
    assert_golden(GOLDEN, &actual, "the tools/list wire surface");
}

/// The half every golden shares: re-record when `UPDATE_GOLDEN` is set, otherwise hand back what
/// was recorded. `None` means it re-recorded, so this run has nothing to compare against.
///
/// One env var and one command records every golden in this file, which is the point of it being
/// shared. How each one *reports* a difference is not shared — see below.
fn golden_baseline(path: &str, rendered: &str) -> Option<String> {
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::create_dir_all(std::path::Path::new(path).parent().unwrap())
            .expect("create golden dir");
        std::fs::write(path, rendered).expect("write golden");
        eprintln!("re-recorded {path}");
        return None;
    }
    Some(std::fs::read_to_string(path).unwrap_or_else(|e| {
        panic!(
            "cannot read {path}: {e}\nrecord it with `UPDATE_GOLDEN=1 cargo test --test mcp_smoke`"
        )
    }))
}

/// Compare a rendered snapshot against its golden file, failing with a **line** diff.
///
/// Right for the shape golden, whose entries are mostly names and type strings: a changed line is
/// legible on its own, and the structure only moves when a tool does.
///
/// Wrong for a report of numbers keyed by tool — see [`assert_budget_golden`], which does not use
/// this.
fn assert_golden(path: &str, actual: &Value, what: &str) {
    let rendered = format!("{}\n", serde_json::to_string_pretty(actual).unwrap());
    let Some(expected) = golden_baseline(path, &rendered) else {
        return;
    };
    if rendered.replace("\r\n", "\n") == expected.replace("\r\n", "\n") {
        return;
    }

    // Line diff, so the failure names what moved instead of dumping two large blobs.
    let expected_lines: Vec<&str> = expected.lines().collect();
    let actual_lines: Vec<&str> = rendered.lines().collect();
    let mut diff = String::new();
    for i in 0..expected_lines.len().max(actual_lines.len()) {
        let (was, now) = (expected_lines.get(i), actual_lines.get(i));
        if was != now {
            diff.push_str(&format!(
                "line {}:\n  recorded: {}\n  actual:   {}\n",
                i + 1,
                was.unwrap_or(&"(absent)"),
                now.unwrap_or(&"(absent)")
            ));
            if diff.lines().count() > 60 {
                diff.push_str("  ... (truncated)\n");
                break;
            }
        }
    }
    panic!(
        "{what} changed:\n{diff}\n\
         If this is intended, re-record with `UPDATE_GOLDEN=1 cargo test --test mcp_smoke` \
         and review the diff."
    );
}

/// Compare a budget report against its golden **by tool name**, reporting byte deltas.
///
/// Deliberately not [`assert_golden`]'s line diff, and the reason is a failure that was measured
/// rather than imagined. Each tool occupies seven lines of the report, so adding or removing one
/// shifts every line after it, and a positional differ then blames the first tool whose *line
/// numbers* moved rather than the one that changed. Dropping `backtrace` from a 51-tool report
/// made the failure open with `crash_triage` — which had not changed at all — and truncate at its
/// 60-line cap before reaching anything that had. A report that names the wrong tool is worse than
/// no report: it sends the reader to audit something that is fine.
///
/// Keying the JSON by name instead would not have fixed it. The rows would still be lines, and an
/// insertion would still shift the ones below. What fixes it is comparing the two documents as
/// *values* — matching tools by name, so an insertion is an insertion and every other tool is
/// untouched — which is also how the failure gets to say `modules: modelVisible 2112 -> 4200`
/// instead of a line number.
fn assert_budget_golden(path: &str, actual: &Value, what: &str) {
    let rendered = format!("{}\n", serde_json::to_string_pretty(actual).unwrap());
    let Some(expected_text) = golden_baseline(path, &rendered) else {
        return;
    };
    if rendered.replace("\r\n", "\n") == expected_text.replace("\r\n", "\n") {
        return;
    }
    let expected: Value = serde_json::from_str(&expected_text).unwrap_or_else(|e| {
        panic!("{path} is not readable as JSON ({e}); re-record it with `UPDATE_GOLDEN=1`")
    });

    let by_name = |report: &Value| -> std::collections::BTreeMap<String, Value> {
        report["tools"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|row| Some((row["name"].as_str()?.to_string(), row.clone())))
            .collect()
    };
    let (was, now) = (by_name(&expected), by_name(actual));

    // Per-tool figures, most consequential first, so a truncated report keeps what matters.
    const FIELDS: &[&str] = &[
        "modelVisible",
        "wire",
        "description",
        "inputSchema",
        "outputSchema",
        "annotations",
    ];
    let mut lines: Vec<String> = Vec::new();
    for (name, row) in &now {
        if !was.contains_key(name) {
            lines.push(format!(
                "  + {name} is new: {} B to the model, {} B on the wire",
                row["modelVisible"], row["wire"]
            ));
        }
    }
    for (name, row) in &was {
        if !now.contains_key(name) {
            lines.push(format!(
                "  - {name} is gone: was {} B to the model",
                row["modelVisible"]
            ));
        }
    }
    for (name, new_row) in &now {
        let Some(old_row) = was.get(name) else {
            continue;
        };
        let deltas: Vec<String> = FIELDS
            .iter()
            .filter_map(|field| {
                let (a, b) = (old_row[*field].as_i64()?, new_row[*field].as_i64()?);
                (a != b).then(|| format!("{field} {a} -> {b} ({:+})", b - a))
            })
            .collect();
        if !deltas.is_empty() {
            lines.push(format!("  ~ {name}: {}", deltas.join(", ")));
        }
    }

    let mut totals: Vec<String> = Vec::new();
    if let Some(recorded) = expected["totals"].as_object() {
        for (key, old) in recorded {
            let new = &actual["totals"][key];
            if old == new {
                continue;
            }
            totals.push(match (old.as_i64(), new.as_i64()) {
                (Some(a), Some(b)) => format!("  {key} {a} -> {b} ({:+})", b - a),
                _ => format!("  {key} {old} -> {new}"),
            });
        }
    }

    const MAX_LINES: usize = 25;
    let hidden = lines.len().saturating_sub(MAX_LINES);
    lines.truncate(MAX_LINES);
    if hidden > 0 {
        lines.push(format!("  ... and {hidden} more tool(s)"));
    }

    panic!(
        "{what} changed:\n{}\n\ntotals:\n{}\n\n\
         If this is intended, re-record with `UPDATE_GOLDEN=1 cargo test --test mcp_smoke` \
         and review the diff.",
        lines.join("\n"),
        if totals.is_empty() {
            "  (unchanged)".to_string()
        } else {
            totals.join("\n")
        },
    );
}

// ---- what the surface costs its caller ----------------------------------------
//
// Every other assertion in this file is about whether the server is *correct*. These are about
// what it *costs*, which nothing here measured before: a client pays for the whole tool surface
// at the start of every conversation, and then for each result, out of the same context window
// the debugging itself has to fit in. `docs/token-budget.md` has the findings; this is the part
// that keeps them from drifting unnoticed.

/// Bytes a value occupies as minified JSON — the unit every budget here is counted in.
///
/// Bytes, not tokens, and deliberately. No tokenizer exists in this crate's dependency tree, a
/// real one would pull in BPE data to produce a figure that varies by model, and the golden would
/// then churn on a tokenizer bump rather than on a change to this server. Bytes are
/// deterministic, diff cleanly, and move with tokens for a fixed content style.
/// `docs/token-budget.md` records the ≈4 bytes/token convention used when quoting these as tokens.
fn json_bytes(value: &Value) -> usize {
    serde_json::to_string(value)
        .expect("a value read off the wire re-serializes")
        .len()
}

/// The part of a tool definition that reaches the **model**.
///
/// `outputSchema` and `annotations` are not in it: the Anthropic tool spec carries name,
/// description and input schema, and the rest of a `tools/list` entry is the client's own
/// business — validation, display — never spent on a context window. That split is why this
/// report has two totals instead of one, and it is not a detail: ~58% of what this server puts on
/// the wire is `outputSchema`, and none of it is read by a model. Optimising the two halves means
/// optimising for different things, so conflating them would point any future work at the wrong
/// 100 KB — and the split is what let finding 1 cut that figure from 280 KB without anybody having
/// to argue about whether the model would miss it.
fn model_visible_bytes(tool: &Value) -> usize {
    json_bytes(&json!({
        "name": tool["name"],
        "description": tool["description"],
        "inputSchema": tool["inputSchema"],
    }))
}

/// Bytes of one field of a tool definition, or 0 when the tool does not carry it.
fn field_bytes(tool: &Value, field: &str) -> usize {
    match tool.get(field) {
        None | Some(Value::Null) => 0,
        Some(value) => json_bytes(value),
    }
}

/// The per-tool size table, plus the totals.
///
/// Takes the whole **`tools/list` result** rather than its `tools` array, so the payload figure is
/// the payload rather than a reconstruction of it. Summing the tools misses the array's own commas
/// and every result-level field — and on `2026-07-28` those are `resultType`, `ttlMs` and
/// `cacheScope`, which is not a hypothetical omission in this repo: the `rmcp = "3.1.1"` floor
/// exists *because* of `ttlMs`/`cacheScope`, and a revision that adds another such field is
/// precisely the change a wire budget should notice. 118 bytes today; the number matters less than
/// which side of the boundary it is measured on.
///
/// Rows are ordered **by name**, which is worth stating because the obvious choice is worse:
/// sorting by cost makes the golden read as a ranking, and then a tool that grows moves up it and
/// shifts every row below. The ranking is not lost — the totals carry the worst tool by name.
fn budget_report(result: &Value, instructions: &str) -> Value {
    let mut rows: Vec<Value> = result["tools"]
        .as_array()
        .expect("tools/list returns an array")
        .iter()
        .map(|tool| {
            json!({
                "name": tool["name"],
                "modelVisible": model_visible_bytes(tool),
                "wire": json_bytes(tool),
                "description": field_bytes(tool, "description"),
                "inputSchema": field_bytes(tool, "inputSchema"),
                "outputSchema": field_bytes(tool, "outputSchema"),
                "annotations": field_bytes(tool, "annotations"),
            })
        })
        .collect();
    rows.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));

    let sum = |field: &str| -> u64 { rows.iter().filter_map(|r| r[field].as_u64()).sum() };
    let worst = rows
        .iter()
        .max_by_key(|row| row["modelVisible"].as_u64().unwrap_or(0))
        .expect("tools/list is never empty");
    json!({
        "totals": {
            "tools": rows.len(),
            "modelVisible": sum("modelVisible"),
            // `wire` is the sum of the rows, and exists for attribution: it is what the per-tool
            // figures add up to, so a total that moves can be traced to a tool. `payload` is the
            // serialized result — the actual answer — and is what the ceiling guards. Keeping both
            // means the gap between them is visible, and that gap is the result-level fields.
            "wire": sum("wire"),
            "payload": json_bytes(result),
            "description": sum("description"),
            "inputSchema": sum("inputSchema"),
            "outputSchema": sum("outputSchema"),
            "annotations": sum("annotations"),
            "instructions": instructions.len(),
            "worstTool": worst["name"],
            "worstToolModelVisible": worst["modelVisible"],
        },
        "tools": rows,
    })
}

/// Ceiling on the tool surface a model is given before it has asked anything. 75,547 bytes across
/// 54 tools (~19k tokens), +10% headroom — sized so that rewording a description passes and a new
/// tool arriving with a `debug_batch`-scale schema does not.
///
/// **Raised 76,000 → 83,000 when the three asynchronous-execution tools landed** (2026-08-29), and
/// the raise is the point rather than a formality: those tools cost 4,892 B of model context —
/// `continue_async` 1,987, `wait_for_stop` 1,530, `break_in` 1,375 — which is 7% of the surface,
/// paid by every client served `exec` at the start of every conversation. `--tools` is the answer
/// for a client that cannot afford it.
///
/// **The fourth tool that raise paid for is `interrupt`**, which grew 211 B without being touched:
/// a `TOOL_NOTES` cross-reference to `continue_async`, appended only where that tool is served.
/// So 68,893 + 4,892 came to 73,785 and the measurement is 73,996 — the arithmetic was right and
/// the model of it was not, which is the failure mode a derived figure has and a recorded one
/// does not. It is why `tests/golden/tool_budget.json` is the source and this line is a ceiling.
const MODEL_VISIBLE_CEILING: usize = 83_000;

/// Ceiling on the whole `tools/list` payload — the serialized result, not the sum of its tools, so
/// the array's own punctuation and every result-level field are inside it. 192,971 bytes today,
/// 58% of that `outputSchema` no model reads, which is why this is a separate and much looser
/// number rather than a scaled version of the one above. (The figure said 177,460 until
/// 2026-08-30 — a payload measured two re-recordings ago, which is the way a number in a doc
/// comment goes stale: nothing reads it, so nothing notices.)
///
/// It is a client-side parse and memory cost, and it is the one that grows silently: `schemars`
/// inlines `$defs` per tool, so adding one shared type to one more output shape still lands here
/// several times over while [`MODEL_VISIBLE_CEILING`] does not move.
///
/// **The history is the point.** It was raised 412,000 → 460,000 once, when `PdbInfo` — one
/// optional four-field type on `ModuleInfo` — cost 15,610 B of wire and nothing at all of model
/// context, because `ModuleInfo` is embedded in half a dozen output shapes and each inlined its
/// own copy. Then it came down to 205,000, because `src/schema.rs` stopped putting `description`
/// in an output schema at all: 68% of every one of those bytes was rustdoc prose that no model is
/// given and no validator reads, and dropping it took the payload 394,883 → 177,460. The
/// multiplier is unchanged — the next shared type is still inlined everywhere it can be reached —
/// but what is multiplied is a handful of keywords rather than a paragraph, which is `FOLLOWUPS.md`
/// item 24's first finding done rather than priced.
const WIRE_CEILING: usize = 205_000;

/// Ceiling on any single tool's model-visible definition. `debug_batch` is the worst at 10,021
/// bytes, because its `inputSchema` pulls the whole `StepAction`/`Check` vocabulary from
/// `src/batch.rs`. A tool costing more than this is not necessarily wrong, but it should be a
/// decision somebody made rather than a schema that grew.
const WORST_TOOL_CEILING: usize = 11_200;

/// What the tool surface costs a caller, pinned per tool.
///
/// Two mechanisms, because they fail on different things and neither covers the other:
///
/// * The **golden** shows *where* the bytes are. Any change to any tool's size lands as a
///   readable diff, so the price of a reworded description is visible in review rather than
///   discovered later.
/// * The **ceilings** stop what the golden cannot: a golden re-recorded on every diff is a rubber
///   stamp, and thirty accepted +2% changes are a doubling nobody ever voted for.
///
/// The numbers themselves are recorded, not argued for — this test exists so that changing them
/// is a deliberate act, not so that today's figures are correct.
#[test]
fn tool_surface_stays_within_its_token_budget() {
    let mut server = Server::spawn();
    let initialized = server.initialize(SUPPORTED_REVISIONS[0]);
    let instructions = initialized["instructions"].as_str().unwrap_or_default();

    let response = server.request("tools/list", json!({}), STEP);
    assert_no_error(&response, "tools/list");

    // The whole result, not its `tools` array: what the payload figure has to measure is the
    // answer this server actually sent, result-level fields and all.
    let report = budget_report(&response["result"], instructions);
    let totals = &report["totals"];
    let model_visible = totals["modelVisible"].as_u64().unwrap() as usize;
    let payload = totals["payload"].as_u64().unwrap() as usize;

    // Where you are, next to the ceiling you are under — for a run made by hand, which needs
    // `--nocapture` to see it: libtest prints a passing test's output nowhere. That is why the
    // golden rather than this line is what CI leaves behind.
    eprintln!(
        "tool surface: {} tools, {model_visible} B to the model (ceiling {MODEL_VISIBLE_CEILING}), \
         {payload} B on the wire (ceiling {WIRE_CEILING}), instructions {} B",
        totals["tools"], totals["instructions"],
    );

    let worst = totals["worstTool"].as_str().unwrap_or("?").to_string();
    let worst_bytes = totals["worstToolModelVisible"].as_u64().unwrap() as usize;

    assert!(
        model_visible <= MODEL_VISIBLE_CEILING,
        "the tool surface now costs {model_visible} B of model context, over its \
         {MODEL_VISIBLE_CEILING} B ceiling. That is paid at the start of every conversation, \
         before anything is debugged. The worst single tool is `{worst}` at {worst_bytes} B. \
         Trim a description or an input schema, or raise the ceiling deliberately and say why \
         in docs/token-budget.md."
    );
    assert!(
        payload <= WIRE_CEILING,
        "the tools/list payload is now {payload} B, over its {WIRE_CEILING} B ceiling ({} B of \
         that is the tools themselves, the rest result-level fields). This is mostly \
         outputSchema, which no model reads — check whether a shared type just got inlined into \
         another tool's $defs, or whether a tool declared its schema with rmcp's \
         `schema_for_output` instead of `schema::constraints_of`, before raising the ceiling.",
        totals["wire"],
    );
    assert!(
        worst_bytes <= WORST_TOOL_CEILING,
        "`{worst}` alone costs {worst_bytes} B of model context, over the {WORST_TOOL_CEILING} B \
         per-tool ceiling."
    );

    assert_budget_golden(BUDGET_GOLDEN, &report, "the tools/list token budget");
}

/// Clients validate arguments against these schemas before ever calling. A `$ref` that points
/// outside the document, or two dialects across one tool list, breaks strict validators — and
/// both are things a codegen dependency can introduce without any change here.
///
/// On the dialect: every tool that has parameters declares `2020-12`; the one tool with no
/// parameters at all (`attach_kernel_local`) emits a bare empty object schema with no `$schema`
/// at all. That is schemars' emission, not something this crate chooses, and it is harmless —
/// an empty schema constrains nothing, so there is no keyword whose meaning a dialect could
/// change. What would *not* be harmless is two different declared dialects, so that is what is
/// pinned here.
#[test]
fn tool_schemas_declare_one_dialect_and_are_self_contained() {
    let mut server = Server::started();
    let response = server.request("tools/list", json!({}), STEP);
    let tools = response["result"]["tools"]
        .as_array()
        .expect("tools/list returns an array")
        .clone();
    assert!(!tools.is_empty(), "tools/list must not be empty");

    let mut declared: Vec<(String, String)> = Vec::new();
    for tool in &tools {
        let name = tool["name"].as_str().unwrap_or("<unnamed>");
        let schema = &tool["inputSchema"];
        assert_eq!(
            schema["type"], "object",
            "`{name}` input schema must be an object schema: {schema}"
        );

        match schema["$schema"].as_str() {
            Some(dialect) => declared.push((name.to_string(), dialect.to_string())),
            // Only the constraint-free case may skip the declaration.
            None => assert!(
                schema["properties"]
                    .as_object()
                    .is_none_or(|props| props.is_empty()),
                "`{name}` constrains arguments but declares no $schema dialect: {schema}"
            ),
        }

        let mut refs = Vec::new();
        collect_refs(schema, &mut refs);
        for reference in refs {
            assert!(
                reference.starts_with("#/"),
                "`{name}` has an external $ref `{reference}` — clients cannot resolve it"
            );
            let pointer = reference.trim_start_matches('#');
            assert!(
                schema.pointer(pointer).is_some(),
                "`{name}` has a dangling $ref `{reference}`"
            );
        }
    }

    // One dialect across the whole list. A client picks a validator per dialect; two of them
    // in one `tools/list` means some tools validate under rules the client did not select.
    let (first_tool, first_dialect) = declared.first().expect("some tool declares a dialect");
    if let Some((other_tool, other)) = declared.iter().find(|(_, d)| d != first_dialect) {
        panic!(
            "tools/list mixes JSON Schema dialects: `{first_tool}` declares {first_dialect}, \
             `{other_tool}` declares {other}"
        );
    }
}

/// An `outputSchema` carries constraints; the prose stays in the source and `docs/`.
///
/// 68% of every `outputSchema` byte this server emitted was a `description` — 217,423 B of
/// 320,365 B, and 55% of the whole `tools/list` answer — because `schemars` inlines each type into
/// the `$defs` of every tool that can reach it, so `ErrorCategory`'s doc comment shipped 33 times.
/// None of it had a reader: no model is given an output schema (the measurement
/// `docs/token-budget.md` opens with), and `description` is an annotation keyword, so a validator
/// ignores it. `src/schema.rs` removes them; this is the assertion that they stay removed, because
/// the change is one import line away from being undone and nothing else would report it.
///
/// The **input** schemas are checked in the same pass, as a positive control. They are the half a
/// model does read, their descriptions are load-bearing, and a strip that reached them would be a
/// silent regression in how well this server can be driven — not a size win.
#[test]
fn output_schemas_carry_constraints_not_prose() {
    /// Counts `description` **keywords**, which is not the same as `description` keys: the members
    /// of `properties` and `$defs` are named by the type being described, so a field called
    /// `description` is a name in that position and not documentation. Kept separate from
    /// `src/schema.rs`'s own walk on purpose, and **deliberately the blunter of the two**: that one
    /// descends only where a JSON Schema keyword says a subschema lives, this one descends into
    /// everything. So a keyword it does not know about is a keyword whose prose survives the strip
    /// and fails here — which is the direction the pair has to fail in.
    fn prose(node: &Value, names_not_keywords: bool, found: &mut usize) {
        const NAME_MAPS: &[&str] = &["properties", "patternProperties", "$defs", "definitions"];
        match node {
            Value::Object(members) => {
                for (key, value) in members {
                    let keyword = !names_not_keywords;
                    if keyword && key == "description" {
                        *found += 1;
                    }
                    prose(value, keyword && NAME_MAPS.contains(&key.as_str()), found);
                }
            }
            Value::Array(items) => items.iter().for_each(|item| prose(item, false, found)),
            _ => {}
        }
    }

    let mut server = Server::started();
    let response = server.request("tools/list", json!({}), STEP);
    let tools = response["result"]["tools"]
        .as_array()
        .expect("tools/list returns an array")
        .clone();

    let mut with_schema = 0;
    let mut input_prose = 0;
    for tool in &tools {
        let name = tool["name"].as_str().unwrap_or("<unnamed>");

        if let Some(schema) = tool.get("outputSchema").filter(|s| !s.is_null()) {
            with_schema += 1;
            let mut found = 0;
            prose(schema, false, &mut found);
            assert_eq!(
                found, 0,
                "`{name}`'s outputSchema carries {found} description(s). No model reads an \
                 output schema and no validator reads a description, and every type in it is \
                 inlined into every other tool that can reach it — so each one is paid for once \
                 per tool. Declare it with `schema::constraints_of`, not rmcp's \
                 `schema_for_output`."
            );
        }

        prose(&tool["inputSchema"], false, &mut input_prose);
    }

    assert!(
        with_schema > 20,
        "only {with_schema} tools declare an output schema — this test has stopped covering the \
         surface it is about"
    );
    assert!(
        input_prose > 100,
        "input schemas carry only {input_prose} descriptions: the strip has reached the half a \
         model actually reads"
    );
}

/// Every declared `outputSchema` is rooted at `type: "object"`, which is what keeps a strict
/// client holding **any** of this server's tools.
///
/// The structured results are serde internally-tagged enums, and `schemars` renders one as
/// `{ $schema, oneOf, $defs }` — object-ness stated on each branch of the union and nowhere at the
/// root. rmcp passes that through: `schema_for_input` requires a root `type: "object"` and refuses
/// anything else, while `schema_for_output` deliberately does not, SEP-2106 (`2026-07-28`) having
/// relaxed the requirement for output schemas.
///
/// What that relaxation does not do is reach the clients. Every released
/// `@modelcontextprotocol/sdk` 1.x — 1.30.0 included — parses `Tool.outputSchema` as
/// `z.object({ type: z.literal("object"), … })` and `tools/list` as `z.array(ToolSchema)`, so the
/// array fails on the first non-conforming tool and the client registers **none** of them.
/// Measured against 1.30.0 on the shape this server emitted: 17 conforming tools plus one
/// `oneOf`-rooted schema parses to zero tools, not 17. That is issue #223 — windbg-mcp v0.11.0
/// behind a 1.29.0 client: no tools registered, reconnect loop exhausted, server deregistered.
///
/// It is asserted here rather than in `src/schema.rs` alone because the unit test knows what
/// `constraints_of` returns and this knows what a client is *sent* — and the way the fix comes
/// undone is a tool declaring its schema with rmcp's `schema_for_output` instead, which only the
/// wire would show. The sibling check is
/// [`output_schemas_carry_constraints_not_prose`], which fails the same way for the same reason.
#[test]
fn output_schemas_are_object_rooted() {
    let mut server = Server::started();
    let response = server.request("tools/list", json!({}), STEP);
    assert_no_error(&response, "tools/list");
    let tools = response["result"]["tools"]
        .as_array()
        .expect("tools/list returns an array")
        .clone();

    let mut with_schema = 0;
    for tool in &tools {
        let name = tool["name"].as_str().unwrap_or("<unnamed>");
        let Some(schema) = tool.get("outputSchema").filter(|s| !s.is_null()) else {
            continue;
        };
        with_schema += 1;
        assert_eq!(
            schema["type"],
            json!("object"),
            "`{name}` declares an outputSchema with no root `type: \"object\"`. A strict client \
             rejects the whole `tools/list` on it and registers none of the {} tools this server \
             serves — not {} of them. Declare it with `schema::constraints_of`, not rmcp's \
             `schema_for_output`.",
            tools.len(),
            tools.len() - 1
        );
    }

    assert!(
        with_schema > 20,
        "only {with_schema} tools declare an output schema — this test has stopped covering the \
         surface it is about"
    );
}

/// The eight `--tools` groups name every tool, and no tool twice.
///
/// `src/toolset.rs` unit-tests the table against itself; what it cannot see is the tool surface,
/// which is generated by macros in `src/server.rs`. So the two are joined here, and in the
/// direction that fails: a tool added to `server.rs` and not to a group is missing from the union
/// below, and would otherwise have vanished from every narrowed surface without a word — the
/// default surface, which is what a run with no `--tools` serves, would still have carried it.
#[test]
fn every_tool_belongs_to_exactly_one_group() {
    // Every group there is. A ninth added to `src/toolset.rs` and not to this line fails the same
    // way a missing tool does, because its tools are then absent from the union too.
    const GROUPS: &str = "session,inspect,exec,ttd,ioctl,allocator,crash,batch";

    let listed = |server: &mut Server| -> Vec<String> {
        let response = server.request("tools/list", json!({}), STEP);
        assert_no_error(&response, "tools/list");
        let mut names: Vec<String> = response["result"]["tools"]
            .as_array()
            .expect("tools/list returns an array")
            .iter()
            .map(|t| t["name"].as_str().unwrap_or_default().to_string())
            .collect();
        names.sort();
        names
    };

    let everything = listed(&mut Server::started());
    let grouped = listed(&mut Server::started_with_args(&[], &["--tools", GROUPS]));

    assert_eq!(
        grouped,
        everything,
        "the `--tools` groups do not add up to the tool surface. Missing from every group: {:?}; \
         named by a group but not served: {:?}. Put each new tool in a group in `src/toolset.rs`.",
        everything
            .iter()
            .filter(|n| !grouped.contains(n))
            .collect::<Vec<_>>(),
        grouped
            .iter()
            .filter(|n| !everything.contains(n))
            .collect::<Vec<_>>(),
    );
}

/// A narrowed surface serves fewer tools, and says so rather than pretending the rest never were.
///
/// The measurement behind `--tools` is that 70% of the 75,547-byte tool surface is prose a model
/// needs, so the only way to spend less of a caller's context is to offer fewer tools —
/// `FOLLOWUPS.md` item 24. This asserts the three things that makes true.
#[test]
fn a_narrowed_tool_surface_serves_only_what_it_was_asked_for() {
    let mut server = Server::started_with_args(&[], &["--tools", "crash"]);

    let response = server.request("tools/list", json!({}), STEP);
    assert_no_error(&response, "tools/list");
    let tools = response["result"]["tools"]
        .as_array()
        .expect("tools/list returns an array")
        .clone();
    let names: Vec<&str> = tools
        .iter()
        .map(|t| t["name"].as_str().unwrap_or_default())
        .collect();

    // What was asked for, and the openers that come with every surface — a caller that cannot open
    // a target cannot use any of the rest, since a `session_id` comes from here and nowhere else.
    assert!(names.contains(&"crash_triage"), "{names:?}");
    assert!(
        names.contains(&"open_dump"),
        "an opener is always served: {names:?}"
    );
    assert!(names.contains(&"end_session"), "{names:?}");
    // And nothing else.
    assert!(!names.contains(&"ttd_calls"), "{names:?}");
    assert!(!names.contains(&"pool_find_tag"), "{names:?}");
    assert!(!names.contains(&"debug_batch"), "{names:?}");
    assert_eq!(names.len(), 11, "{names:?}");

    // The point of the exercise, measured the same way `tool_surface_stays_within_its_token_budget`
    // measures the whole surface: this is what the caller stops paying for at the start of every
    // conversation.
    let narrowed: usize = tools.iter().map(model_visible_bytes).sum();
    eprintln!(
        "`--tools crash`: {} tools, {narrowed} B to the model",
        names.len()
    );
    assert!(
        narrowed < MODEL_VISIBLE_CEILING / 2,
        "a `crash` surface costs {narrowed} B, which is not meaningfully less than the whole one"
    );

    // A tool that exists and is not served is refused by name, not as a typo: the model was never
    // given it, and the remedy is on a command line the caller cannot see.
    let refused = server.request(
        "tools/call",
        json!({ "name": "ttd_calls", "arguments": {} }),
        STEP,
    );
    let message = refused["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("not on the surface") && message.contains("--tools"),
        "a tool outside the surface should say so: {refused}"
    );
}

/// A tool that declares an `outputSchema` must return `structuredContent` — on **both** paths.
///
/// The spec's requirement is on the success path, and the failure path is where this would break
/// in practice: every migrated tool has a validation refusal or a session check that returns long
/// before the typed answer is built, and each is a separate `return` a future edit can add without
/// the payload. A client that validates results against the schema then rejects the very message
/// telling it what went wrong.
///
/// Driven with no session open, so every session-scoped tool takes its refusal path without a
/// debugger anywhere near it — which is what keeps this in the default tier.
///
/// The **openers** are the exception, and are handled rather than excluded: each fails on
/// something that cannot exist (a path, a pid, an image), but reaching that failure spawns a
/// worker, and a worker needs DbgEng. On a host without it there is no session at all — the one
/// failure this server reports as a JSON-RPC error — so those rows are skipped by *error code*,
/// visibly, rather than by matching the message or by dropping them from the table.
///
/// The table is checked *against* `tools/list` in both directions: a tool that grows a schema and
/// is not listed here fails, so this cannot quietly stop covering the surface it is about.
#[test]
fn every_tool_with_an_output_schema_answers_with_structured_content() {
    // `attach_kernel_local` is deliberately absent: it is the one schema-bearing tool whose
    // failure path cannot be reached without trying the thing itself, and on a machine booted
    // with debugging enabled it would *succeed* and leave this test holding the local kernel.
    const UNREACHED: &[&str] = &["attach_kernel_local"];
    let cases: &[(&str, Value, &str)] = &[
        // Openers, each failing before anything is created: a path that does not exist, a pid
        // that cannot be attached, an image that cannot be launched, a selector with neither
        // half given.
        ("open_dump", json!({ "path": "Z:\\no\\such.dmp" }), "error"),
        ("open_trace", json!({ "path": "Z:\\no\\such.run" }), "error"),
        ("attach_process", json!({ "pid": 0xffff_fffeu32 }), "error"),
        (
            "launch",
            json!({ "command_line": "Z:\\no\\such\\image.exe" }),
            "error",
        ),
        ("attach_kernel", json!({}), "error"),
        // Both are answered from this server's own bookkeeping, so they succeed with nothing
        // open — and `server_log` has records to answer with whatever else has happened, this
        // server having logged its own startup.
        ("session_status", json!({}), "ok"),
        ("server_log", json!({}), "ok"),
        // Everything else needs a session, and there is none.
        ("end_session", json!({}), "error"),
        ("registers", json!({}), "error"),
        ("modules", json!({}), "error"),
        ("backtrace", json!({}), "error"),
        ("disassemble", json!({}), "error"),
        (
            "set_breakpoint",
            json!({ "expression": "nt!KeBugCheckEx" }),
            "error",
        ),
        (
            "run_to_address",
            json!({ "address": "nt!KeBugCheckEx" }),
            "error",
        ),
        ("go", json!({}), "error"),
        ("step_over", json!({}), "error"),
        ("step_into", json!({}), "error"),
        ("step_back", json!({}), "error"),
        ("step_over_back", json!({}), "error"),
        ("reverse_go", json!({}), "error"),
        // The asynchronous three. `continue_async` refuses on the session like every row above
        // it; the other two carry a handle, and with no session there is nothing to resolve it
        // against — so they take the same session refusal rather than the unknown-handle one,
        // which needs a session to be unknown *within* and is checked in the debugger tier.
        ("continue_async", json!({}), "error"),
        (
            "wait_for_stop",
            json!({ "execution": "exec-nothing" }),
            "error",
        ),
        ("break_in", json!({ "execution": "exec-nothing" }), "error"),
        ("pool_find_tag", json!({ "tag": "Tgsm" }), "error"),
        (
            "pool_chunk",
            json!({ "address": "0xffff800000000000" }),
            "error",
        ),
        ("pool_census", json!({}), "error"),
        ("pool_diagnostics", json!({}), "error"),
        ("heap_list", json!({}), "error"),
        ("heap_allocations", json!({}), "error"),
        (
            "heap_chunk",
            json!({ "address": "0x0000000000010000" }),
            "error",
        ),
        ("heap_census", json!({}), "error"),
        ("heap_diagnostics", json!({}), "error"),
        ("crash_triage", json!({}), "error"),
        // A well-formed request, so it takes the *session* refusal path like every row above it
        // rather than the argument one — which this tool also has, and which is checked in
        // `a_malformed_walk_is_refused_before_a_session_is_needed`.
        (
            "walk_memory",
            json!({ "addresses": ["0xffff800000000000"] }),
            "error",
        ),
        // Well-formed for the same reason: a batch that fails `validate` never reaches a session,
        // and it is the session refusal this row is here for. `status: "error"` is the batch that
        // did not run — a batch that *runs* and fails answers `status: "ok"` on an `isError`
        // result, which the dump tier checks because it needs a target to run against.
        (
            "debug_batch",
            json!({ "steps": [{ "op": "command", "command": "version" }] }),
            "error",
        ),
    ];

    let mut server = Server::started();
    let response = server.request("tools/list", json!({}), STEP);
    let tools = response["result"]["tools"]
        .as_array()
        .expect("tools/list returns an array")
        .clone();
    let mut declared: Vec<&str> = tools
        .iter()
        .filter(|t| !t["outputSchema"].is_null())
        .filter_map(|t| t["name"].as_str())
        .filter(|name| !UNREACHED.contains(name))
        .collect();
    declared.sort_unstable();
    let mut covered: Vec<&str> = cases.iter().map(|(name, _, _)| *name).collect();
    covered.sort_unstable();
    assert_eq!(
        declared, covered,
        "every tool declaring an outputSchema has to be exercised here (or listed in UNREACHED \
         with a reason), or this test stops covering the surface it is named for"
    );

    for (name, args, expected) in cases {
        let response = server.call_tool(name, args.clone(), STEP);
        // `-32603` is `ErrorData::internal_error`, which this server emits for exactly one thing:
        // no engine worker could be started. Every other failure is a tool result by design, so
        // this cannot swallow the case the test is for.
        if response["error"]["code"] == -32603 {
            skip(&format!(
                "`{name}` needs an engine worker and none could be started (no DbgEng on this                  host?), so its structured-result contract was not checked"
            ));
            continue;
        }
        assert_no_error(&response, &format!("tools/call {name}"));
        let result = &response["result"];
        let data = &result["structuredContent"];
        assert!(
            !data.is_null(),
            "`{name}` declares an outputSchema but answered with text alone:\n{}",
            text_of(result)
        );
        assert_eq!(
            data["status"], *expected,
            "`{name}` should have answered `{expected}`: {data}"
        );
        if *expected == "error" {
            assert!(
                is_tool_error(&response),
                "`{name}` reported a structured error but did not set isError: {result}"
            );
            assert!(
                data["error"]["category"].is_string(),
                "`{name}` must name a category a caller can branch on: {data}"
            );
            // The text and the typed message are the same failure, not two accounts of it.
            assert_eq!(
                data["error"]["message"].as_str().unwrap_or_default(),
                text_of(result),
                "`{name}`'s structured message and its text should be one string"
            );
        }
    }
}

fn collect_refs(node: &Value, out: &mut Vec<String>) {
    match node {
        Value::Object(map) => {
            for (key, value) in map {
                if key == "$ref" {
                    if let Some(reference) = value.as_str() {
                        out.push(reference.to_string());
                    }
                } else {
                    collect_refs(value, out);
                }
            }
        }
        Value::Array(items) => items.iter().for_each(|i| collect_refs(i, out)),
        _ => {}
    }
}

/// One tool executed end to end, chosen because it is pure: `decode_ioctl` never reaches the
/// engine, so this proves the call path — arguments in, content blocks out — on any machine.
#[test]
fn a_tool_call_round_trips_over_the_wire() {
    let mut server = Server::started();
    // IOCTL_DISK_GET_DRIVE_GEOMETRY: device 0x7 (DISK), function 0x0, METHOD_BUFFERED, FILE_ANY_ACCESS.
    let text = server.tool_text("decode_ioctl", json!({ "code": "0x70000" }), STEP);
    for expected in ["0x00070000", "METHOD_BUFFERED", "FILE_ANY_ACCESS"] {
        assert!(
            text.contains(expected),
            "decoded output should mention `{expected}`, got:\n{text}"
        );
    }
}

/// The server's own log, read back through a tool.
///
/// In the base tier because the thing being checked is not the debugger: it is that a record this
/// process wrote to stderr is *also* reachable over the transport. That property is what
/// `--listen` needs and stdio got for free — the server's stderr is the client's log only while
/// the two are on one machine — so it has to be asserted somewhere that a client can see, which
/// means over the wire.
#[test]
fn the_servers_own_log_is_readable_over_the_transport() {
    let mut server = Server::started();
    let page = server.tool_data("server_log", json!({}), STEP);
    let records = page["records"]
        .as_array()
        .unwrap_or_else(|| panic!("server_log returns records: {page}"))
        .clone();
    assert!(
        !records.is_empty(),
        "the server logs its own startup, so a bare `server_log` cannot be empty: {page}"
    );
    assert!(
        records.iter().any(|r| r["target"]
            .as_str()
            .is_some_and(|t| t.starts_with("windbg_mcp"))),
        "the records must be this server's own, keyed by tracing target: {records:?}"
    );
    assert!(
        page["capacity"].as_u64().unwrap_or(0) > 0,
        "a report has to say how much the buffer holds: {page}"
    );

    // `since` is the paging contract, and it is the half a poller depends on: a second call with
    // the returned cursor must not re-serve what the first one already handed over.
    let cursor = page["next_since"]
        .as_u64()
        .unwrap_or_else(|| panic!("server_log returns a cursor: {page}"));
    let next = server.tool_data("server_log", json!({ "since": cursor }), STEP);
    for record in next["records"].as_array().into_iter().flatten() {
        assert!(
            record["seq"].as_u64().unwrap_or(0) >= cursor,
            "a `since` page must contain nothing older than its cursor: {record}"
        );
    }

    // A filter that matches nothing answers with an empty page rather than an error — asking
    // after a session that is gone is a fair question with a definite answer.
    let none = server.tool_data(
        "server_log",
        json!({ "session_id": "sess-not-a-real-handle" }),
        STEP,
    );
    assert!(
        none["records"].as_array().is_some_and(Vec::is_empty),
        "no session, no records: {none}"
    );

    // The level filter is a floor on severity, so asking for errors must not hand back the info
    // records above.
    let errors = server.tool_data("server_log", json!({ "level": "error" }), STEP);
    for record in errors["records"].as_array().into_iter().flatten() {
        assert_eq!(
            record["level"], "error",
            "`level: error` returned something less severe: {record}"
        );
    }
}

/// The session transcript, end to end through the shipped binary: recorded by a real server
/// process over a real stdio connection, read back as JSONL, and rendered as an asciicast.
///
/// In the base tier deliberately. Every acceptance criterion in
/// [#87](https://github.com/glslang/windbg-mcp/issues/87) except the ones needing a target is
/// about *this* — the environment variable being read, the file being written beside a live
/// JSON-RPC transport rather than into it, and the renderer being reachable from the same
/// executable — and none of that is provable in-process. `src/record.rs` covers the shapes.
#[test]
fn a_recorded_session_reads_back_as_jsonl_and_renders_as_a_cast() {
    let transcript = marker_path("transcript");
    let _ = std::fs::remove_file(&transcript);
    let mut server = Server::started_with(&[(
        "WINDBG_MCP_TRANSCRIPT",
        transcript.to_str().expect("a UTF-8 temp path"),
    )]);

    server.tool_text("decode_ioctl", json!({ "code": "0x70000" }), STEP);
    // A raw connection carrying a key. Refused here for its shape — so nothing dials and this
    // test never waits on a network — but the key still crossed the wire as a tool argument,
    // which is the only thing this row is about.
    let key = "9.8.7.6";
    server.call_tool(
        "attach_kernel",
        json!({ "connection": format!("net:port=50000, key={key}") }),
        STEP,
    );
    // A failure with a category, so the transcript has one of each verdict.
    server.call_tool("registers", json!({}), STEP);
    // Read before the shutdown consumes the server; asserted after the file is, so a failure
    // reports the transcript's problem rather than this.
    let stdout = server.stdout_lines();
    assert_eq!(server.shutdown(), Some(0), "the server exits cleanly");

    let raw = std::fs::read_to_string(&transcript)
        .unwrap_or_else(|e| panic!("no transcript at {}: {e}", transcript.display()));
    // JSONL: every line is one complete object. Parsed as `Value` rather than as this crate's
    // own type, because a consumer of the file has neither.
    let records: Vec<Value> = raw
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("not JSONL ({e}): {l}")))
        .collect();
    let kinds: Vec<&str> = records.iter().filter_map(|r| r["event"].as_str()).collect();
    assert_eq!(kinds.first(), Some(&"start"), "a run starts with a header");
    assert_eq!(
        kinds.last(),
        Some(&"shutdown"),
        "and ends where the server did, so a truncated file is visibly truncated"
    );
    // Request order, which is the criterion: the calls, in the order they were made, each with
    // its result.
    let calls: Vec<(&str, &str)> = records
        .iter()
        .filter(|r| matches!(r["event"].as_str(), Some("tool_request" | "tool_result")))
        .map(|r| {
            (
                r["event"].as_str().unwrap_or_default(),
                r["tool"].as_str().unwrap_or_default(),
            )
        })
        .collect();
    assert_eq!(
        calls,
        [
            ("tool_request", "decode_ioctl"),
            ("tool_result", "decode_ioctl"),
            ("tool_request", "attach_kernel"),
            ("tool_result", "attach_kernel"),
            ("tool_request", "registers"),
            ("tool_result", "registers"),
        ]
    );
    assert!(
        records
            .windows(2)
            .all(|w| w[0]["seq"].as_u64() < w[1]["seq"].as_u64()),
        "records are numbered in the order they were written"
    );

    // The security criterion, checked against the bytes of the file rather than a parsed field:
    // a key that leaked into some corner of a record nobody thought to look at is still a leak.
    assert!(
        !raw.contains(key),
        "the supplied KD key reached the transcript:\n{raw}"
    );
    assert!(
        raw.contains("<redacted>"),
        "and it should be visible that something was masked:\n{raw}"
    );

    // The transport criterion: stdout carried JSON-RPC and nothing else, so a transcript being
    // written cannot corrupt a client's connection.
    for line in stdout {
        let message: Value = serde_json::from_str(&line)
            .unwrap_or_else(|e| panic!("a non-JSON-RPC line reached stdout ({e}): {line}"));
        assert_eq!(message["jsonrpc"], "2.0", "not a JSON-RPC message: {line}");
    }

    // And the same executable renders it. Anything else would be a second tool to keep in step
    // with a format this one defines.
    let cast = transcript.with_extension("cast");
    let rendered = Command::new(EXE)
        .arg("--render-cast")
        .arg(&transcript)
        .arg("--out")
        .arg(&cast)
        .output()
        .expect("run the renderer");
    assert!(
        rendered.status.success(),
        "the renderer failed: {}",
        String::from_utf8_lossy(&rendered.stderr)
    );

    let cast_text = std::fs::read_to_string(&cast).expect("the cast exists");
    let mut lines = cast_text.lines();
    let header: Value =
        serde_json::from_str(lines.next().expect("a header line")).expect("the header is JSON");
    assert_eq!(header["version"], 2, "asciicast v2: {header}");
    assert!(header["width"].as_u64().unwrap_or(0) > 0, "{header}");
    assert!(header["height"].as_u64().unwrap_or(0) > 0, "{header}");
    let mut previous = -1.0;
    let mut frames = 0;
    for line in lines.filter(|l| !l.trim().is_empty()) {
        let event: Vec<Value> = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("an event line is not an array ({e}): {line}"));
        assert_eq!(event.len(), 3, "an asciicast event is `[time, code, data]`");
        let at = event[0].as_f64().expect("the time is a number");
        assert_eq!(event[1], "o", "this renderer only writes output events");
        assert!(event[2].is_string(), "the data is a string");
        assert!(at >= previous, "an asciicast's times must not go backwards");
        previous = at;
        frames += 1;
    }
    assert!(frames > 0, "the recording has frames");
    assert!(
        !cast_text.contains(key),
        "the key must not survive into the rendering either"
    );

    let _ = std::fs::remove_file(&transcript);
    let _ = std::fs::remove_file(&cast);
}

/// Recording is opt-in, and its absence has to cost nothing at all.
///
/// **The same path, twice**, which is the only way this can mean anything: a path the server was
/// never told about could not be written whatever the default was, so asserting it stays absent
/// asserts nothing. Here the first run proves the server *does* write that exact file when asked,
/// and the second — same path, no variable — proves it does not when it is not.
#[test]
fn nothing_is_recorded_unless_a_transcript_is_asked_for() {
    let path = marker_path("opt-in");
    let _ = std::fs::remove_file(&path);
    let named = path.to_str().expect("a UTF-8 temp path");

    let mut asked = Server::started_with(&[("WINDBG_MCP_TRANSCRIPT", named)]);
    asked.tool_text("decode_ioctl", json!({ "code": "0x70000" }), STEP);
    assert_eq!(asked.shutdown(), Some(0));
    assert!(
        path.exists(),
        "the control half of this test is broken: a server that was asked to record wrote nothing \
         to {}, so the assertion below cannot mean anything",
        path.display()
    );

    std::fs::remove_file(&path).expect("clear the transcript between the two halves");
    let mut unasked = Server::started();
    unasked.tool_text("decode_ioctl", json!({ "code": "0x70000" }), STEP);
    assert_eq!(unasked.shutdown(), Some(0));
    assert!(
        !path.exists(),
        "a server nobody asked to record wrote {}",
        path.display()
    );
}

/// Bad calls have to fail as *protocol* errors, and — the part that matters — the connection
/// has to survive them. A client that gets its own bug back as a dead session cannot recover.
#[test]
fn bad_calls_are_rejected_without_killing_the_session() {
    let mut server = Server::started();

    let unknown = server.call_tool("no_such_tool", json!({}), STEP);
    assert!(
        !unknown["error"].is_null() || is_tool_error(&unknown),
        "an unknown tool must be refused, got {unknown}"
    );

    // `decode_ioctl` requires `code`; omitting it is the everyday client mistake.
    let missing = server.call_tool("decode_ioctl", json!({}), STEP);
    assert!(
        !missing["error"].is_null() || is_tool_error(&missing),
        "a missing required argument must be refused, got {missing}"
    );

    let text = server.tool_text("decode_ioctl", json!({ "code": "0x70000" }), STEP);
    assert!(
        text.contains("METHOD_BUFFERED"),
        "the session must still work after bad calls, got:\n{text}"
    );
}

/// `walk_memory`'s traversal arguments are exclusive, and — the part worth a wire test — the
/// refusal happens **before a session is chosen**.
///
/// It is a fact about the request, not about a target, so a caller finds out now rather than after
/// queueing behind whatever that session is busy with. Driven with nothing open at all: a check
/// that reached the session registry would come back "no session" instead, and the two messages
/// send a caller to opposite places.
#[test]
fn a_malformed_walk_is_refused_before_a_session_is_needed() {
    let mut server = Server::started();

    let both = server.call_tool(
        "walk_memory",
        json!({ "start": "0x1000", "stride": 8, "next_offset": 0 }),
        STEP,
    );
    assert!(is_tool_error(&both), "two traversals must be refused");
    let text = text_of(&both["result"]);
    assert!(
        text.contains("Pass one"),
        "the refusal must name the conflict, got:\n{text}"
    );
    assert!(
        !text.contains("session"),
        "this is refused before any session is needed, got:\n{text}"
    );
    assert_eq!(
        both["result"]["structuredContent"]["error"]["category"], "invalid_argument",
        "a caller branches on the category, not the wording: {both}"
    );

    // And the cap is a refusal rather than a silent clamp, so "every node asked for was visited"
    // is never about a count this server lowered.
    let too_many = server.call_tool(
        "walk_memory",
        json!({ "start": "0x1000", "stride": 8, "count": 100_000 }),
        STEP,
    );
    assert!(is_tool_error(&too_many), "a count past the cap is refused");
    assert!(
        text_of(&too_many["result"]).contains("at most"),
        "the refusal must name the cap, got:\n{}",
        text_of(&too_many["result"])
    );
}

#[test]
fn an_inverted_heap_capacity_range_is_refused_before_a_session_is_needed() {
    let mut server = Server::started();
    let response = server.call_tool(
        "heap_allocations",
        json!({ "min_capacity": 0x2000, "max_capacity": 0x1000 }),
        STEP,
    );
    assert!(is_tool_error(&response), "{response}");
    assert_eq!(
        response["result"]["structuredContent"]["error"]["category"], "invalid_argument",
        "the malformed range must be rejected before session routing: {response}"
    );
    assert!(
        text_of(&response["result"]).contains("min_capacity cannot exceed max_capacity"),
        "{response}"
    );
}

/// A fake KDNET connection for the profile tests, and the key inside it.
///
/// The whole point of asserting on this value is that it must appear **nowhere** a client can see,
/// so it has to be one no real host would produce by coincidence — hence a documentation-range
/// address, and not anyone's key.
const FAKE_PROFILE: (&str, &str) = ("net:port=50008,key=203.0.113.9", "203.0.113.9");

/// Environment defining exactly one profile and no others.
///
/// An environment variable cannot carry a hyphen, so this defines `smoke_kdnet` — which
/// `smoke-kdnet` also resolves to, and the attach below relies on that. `WINDBG_MCP_PROFILES` is
/// pointed at a path that does not exist on purpose: the developer running this may have real
/// profiles configured, and reading them would make these tests vary by host — and put real
/// profile names in a failure message.
fn profile_env() -> [(&'static str, &'static str); 2] {
    [
        ("WINDBG_MCP_PROFILE_SMOKE_KDNET", FAKE_PROFILE.0),
        (
            "WINDBG_MCP_PROFILES",
            r"C:\nonexistent\windbg-mcp-smoke.json",
        ),
    ]
}

/// `attach_kernel`'s two selectors are exclusive, and the check is this server's own — the schema
/// leaves both optional, so nothing upstream enforces it.
///
/// Both failures have to arrive as *tool* errors with the alternative named, not as protocol
/// errors: a model that gets "invalid params" back cannot tell which of the two to drop. Neither
/// costs a worker, which is the other half — a mistyped selector must not leave a session to end.
///
/// Needs no debugger, so it runs in the protocol tier: both refusals happen in the supervisor,
/// before anything is spawned.
#[test]
fn attach_kernel_refuses_both_selectors_and_neither() {
    let mut server = Server::started_with(&profile_env());

    let both = server.call_tool(
        "attach_kernel",
        json!({ "connection": "net:port=50009,key=1.1.1.1", "profile": "smoke" }),
        STEP,
    );
    assert_no_error(&both, "attach_kernel with both selectors");
    let text = text_of(&both["result"]);
    assert!(
        is_tool_error(&both),
        "naming a target twice must be refused, got:\n{text}"
    );
    assert!(
        text.contains("exactly one") && text.contains("`profile`"),
        "the refusal must name the choice, got:\n{text}"
    );

    let neither = server.call_tool("attach_kernel", json!({}), STEP);
    assert_no_error(&neither, "attach_kernel with no selector");
    let text = text_of(&neither["result"]);
    assert!(
        is_tool_error(&neither),
        "naming no target must be refused, got:\n{text}"
    );
    assert!(
        text.contains("`profile`") && text.contains("`connection`"),
        "the refusal must name both ways to say what to attach to, got:\n{text}"
    );

    // Neither refusal reached the engine, so there is nothing to clean up — which is the claim.
    let sessions = server.tool_text("session_status", json!({}), STEP);
    assert!(
        sessions.contains("No debug session"),
        "a refused selector must not leave a session behind:\n{sessions}"
    );
}

/// A profile that is not configured has to be answered with the ones that are — and without the
/// value of any of them. Guessing a name should cost a call; it must never cost a key.
///
/// The second half is the mistake that would defeat the whole feature: a caller who puts a
/// connection string into `profile`. Quoting it back would write the key into exactly the
/// transcript profiles exist to keep it out of, so the refusal names the *shape* of a profile
/// name instead.
///
/// Protocol tier: every one of these is refused in the supervisor, before a worker exists.
#[test]
fn an_unknown_profile_is_refused_with_the_names_that_exist_but_no_values() {
    let (connection, key) = FAKE_PROFILE;
    let mut server = Server::started_with(&profile_env());

    let unknown = server.call_tool("attach_kernel", json!({ "profile": "no-such-vm" }), STEP);
    assert_no_error(&unknown, "attach_kernel with an unknown profile");
    let text = text_of(&unknown["result"]);
    assert!(is_tool_error(&unknown), "got:\n{text}");
    // Listed under the variable's own spelling — an environment variable cannot carry a hyphen —
    // while `smoke-kdnet` still resolves to it, which the tier-2 attach below relies on.
    assert!(
        text.contains("smoke_kdnet"),
        "the refusal must name the profiles that do exist, got:\n{text}"
    );
    assert!(
        !text.contains(key),
        "the refusal disclosed a profile's key:\n{text}"
    );

    let mistyped = server.call_tool("attach_kernel", json!({ "profile": connection }), STEP);
    assert_no_error(
        &mistyped,
        "attach_kernel with a connection string as the profile",
    );
    let text = text_of(&mistyped["result"]);
    assert!(is_tool_error(&mistyped), "got:\n{text}");
    assert!(
        text.contains("`connection`"),
        "the refusal must point at the field that takes a connection string, got:\n{text}"
    );
    assert!(
        !text.contains(key),
        "the refusal echoed the key it was handed:\n{text}"
    );

    // One more round trip before reading the log. stderr is drained by a thread of its own with
    // no ordering against the transport, so a line the server wrote while handling the call above
    // may still be in the pipe — and an assertion that something is *absent* passes on a line
    // nobody has read yet. The response to this call orders the server past both refusals.
    server.tool_text("session_status", json!({}), STEP);

    // The whole point, restated over the transport itself: nothing carrying that key was ever
    // written to the client, and nothing to the log either.
    assert!(
        !server.stdout_lines().iter().any(|l| l.contains(key)),
        "a key reached the JSON-RPC transport"
    );
    assert!(!server.stderr().contains(key), "a key reached the log");
}

/// The same claim about the **third** place this server writes: a session transcript.
///
/// Its own test rather than an extra assertion on the one above, because it needs a server started
/// with recording on, and because it is the other half of a pair — the transcript tier covers a raw
/// `connection`, and this covers `profile`, which is the selector that is *supposed* to make the
/// question moot. "Supposed to" is what a test is for: a profile's key lives in this server's own
/// memory for the life of the process, and a recorder is a new thing that writes memory to a file.
#[test]
fn a_profiles_key_never_reaches_a_session_transcript() {
    let (connection, key) = FAKE_PROFILE;
    let transcript = marker_path("profile-transcript");
    let _ = std::fs::remove_file(&transcript);
    let mut env = profile_env().to_vec();
    env.push((
        "WINDBG_MCP_TRANSCRIPT",
        transcript.to_str().expect("a UTF-8 temp path"),
    ));
    let mut server = Server::started_with(&env);

    // Every route by which a profile's key could plausibly be written: naming a profile that does
    // not exist (the reply lists the ones that do), asking for the list, and the mistake of typing
    // the connection string into `profile`. None of these dials, so none of them waits.
    server.call_tool("attach_kernel", json!({ "profile": "no-such-vm" }), STEP);
    server.call_tool("attach_kernel", json!({}), STEP);
    server.call_tool("attach_kernel", json!({ "profile": connection }), STEP);
    assert_eq!(server.shutdown(), Some(0));

    let raw = std::fs::read_to_string(&transcript)
        .unwrap_or_else(|e| panic!("no transcript at {}: {e}", transcript.display()));
    assert!(!raw.contains(key), "a profile's key reached the transcript");
    // And the recording really did happen — otherwise the assertion above passes on an empty file,
    // which is the way a test like this stops testing anything.
    assert!(
        raw.matches("\"tool\":\"attach_kernel\"").count() >= 3,
        "the three calls should all be recorded:\n{raw}"
    );
    // The profile *name* is not a secret and is the whole point of the feature: a transcript has
    // to say which target a session was pointed at.
    assert!(
        raw.contains("smoke_kdnet"),
        "the profile's name should still be readable:\n{raw}"
    );
    let _ = std::fs::remove_file(&transcript);
}

/// The harness's own guard, pinned because losing it is silent and expensive.
///
/// `tool_text` used to hand back a tool error's text like any other result. Nothing failed when
/// it did — the caller carried on with a string that merely lacked whatever it was about to look
/// for, so an assertion on *content* took its else-branch and an assertion on *elapsed time*
/// measured a call that did nothing and passed comfortably. Both happened in the live pool tier.
///
/// `go` with no session open is the cheapest real tool error: a routing failure, which this
/// server deliberately reports as a result rather than a protocol error.
///
/// `#[should_panic]` rather than `catch_unwind`: catching it means muting the panic hook, so that
/// a passing test does not print what reads as a failure — and that hook is **process-wide**, so
/// any other test panicking in the same moment would lose its message and backtrace while still
/// failing. The attribute buys the same guarantee with none of that, and `expected` stops it
/// passing on an unrelated panic such as the server failing to start.
#[test]
#[should_panic(expected = "reported a tool error")]
fn tool_text_refuses_to_hand_back_a_failed_call() {
    let mut server = Server::started();
    server.tool_text("go", json!({}), STEP);
}

/// Progress is opt-in per call, and a client that did not opt in must be sent none.
///
/// The rule is MCP's: a `notifications/progress` with no `progressToken` behind it is an
/// unsolicited message about a request the client never asked to hear about, and a strict client
/// may treat one as a protocol violation. Asserted on **stdout as a whole** rather than on a
/// message queue, because that is where a stray notification would actually land — a transport
/// this server also has to keep free of anything that is not a reply.
///
/// The call is an open that fails, deliberately. An opener is the one tool with a milestone to
/// report before it has done anything (the engine worker coming up), so this exercises the path
/// that *would* report rather than a tool with nothing to say — on a host with no `dbgeng.dll`
/// the worker never comes up and the assertion is merely weaker, never wrong.
#[test]
fn a_call_that_asked_for_no_progress_is_sent_none() {
    let mut server = Server::started();
    let response = server.call_tool("open_dump", json!({ "path": r"Z:\no\such.dmp" }), STEP);
    assert!(
        !response["error"].is_null() || is_tool_error(&response),
        "opening a path that does not exist must fail: {response}"
    );

    let stray: Vec<String> = server
        .stdout_lines()
        .into_iter()
        .filter(|line| line.contains("notifications/progress"))
        .collect();
    assert!(
        stray.is_empty(),
        "the client asked for no progress and was sent some anyway: {stray:?}"
    );
}

// ---- tier 1: the listener and its lease ---------------------------------------
//
// `--listen` gives up the one property stdio has for free: a closed stdin means the client is
// *definitively* gone, and every target is released. Over HTTP a silent client is
// indistinguishable from one that is thinking, so a **lease** stands in for that moment — and the
// lease is the only part of this server whose failures cost a *target* rather than a call.
//
// Every rule of it has unit tests in `src/listen.rs`, against the state machine directly. What
// those cannot reach is the wiring: the bearer check that runs before any of it, the
// `Mcp-Session-Id` header ownership is keyed on, an HTTP status a client actually branches on, and —
// in the debugger tier — the sweep releasing a real engine worker. That had been checked by hand
// against the guest three times, which is how this tier came to exist.
//
// The client here is hand-written for the same reason the stdio one is: what is being asserted is
// what goes over the wire, and a library that normalises a `409` into an exception, or hides the
// session header, is a library asserting on this server's behalf.

/// The protocol revision the lease is exercised against.
///
/// A lease is armed by an MCP session, so this has to be a revision whose handshake mints one — a
/// `2026-07-28` client is never given a clock at all, and abandonment there is the idle release's.
/// [`STATELESS_REVISION`] is what exercises the rest of the wiring on that revision.
const LEASE_REVISION: &str = "2025-06-18";

/// The revision that removed the session id, and therefore the lease's grip on a client.
///
/// [SEP-2567] made `2026-07-28` stateless: the handshake mints no `Mcp-Session-Id`, so a client on
/// this revision never becomes a holder and never sends an id back. It is also the revision current
/// clients negotiate, which is why "answered the handshake and then refused everything after it"
/// was worth a tier of its own.
///
/// [SEP-2567]: https://modelcontextprotocol.io/seps/2567-sessionless-mcp
const STATELESS_REVISION: &str = "2026-07-28";

/// A free loopback port, taken by binding and letting go.
///
/// Racy in principle and not in practice: the window is microseconds, tests each take their own,
/// and a collision fails loudly at bind rather than silently sharing a server.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("a loopback port")
        .local_addr()
        .expect("a bound address")
        .port()
}

/// One HTTP reply, parsed far enough to assert on.
struct Reply {
    status: u16,
    /// `Mcp-Session-Id`, which is what the lease reads a client's identity from.
    session: Option<String>,
    /// The JSON-RPC payload, whether it arrived as a plain body or inside an SSE frame.
    payload: Option<Value>,
    /// Every JSON-RPC message on this reply's stream, in order. More than one when the call asked
    /// for progress: rmcp routes those notifications onto the stream the call is answered on.
    frames: Vec<Value>,
    body: String,
}

impl Reply {
    /// The `notifications/progress` carried on this reply's own stream, oldest first.
    fn progress(&self, token: &str) -> Vec<&Value> {
        self.frames
            .iter()
            .filter(|frame| {
                frame["method"] == json!("notifications/progress")
                    && frame["params"]["progressToken"] == json!(token)
            })
            .collect()
    }

    fn result(&self, what: &str) -> Value {
        let payload = self
            .payload
            .as_ref()
            .unwrap_or_else(|| panic!("`{what}` answered with no JSON-RPC payload: {}", self.body));
        assert!(
            payload["error"].is_null(),
            "`{what}` failed: {}",
            payload["error"]
        );
        payload["result"].clone()
    }
}

/// A narrowed surface reaches the wire on `--listen` too, not only on stdio.
///
/// Two different lines set it: stdio builds one `WindbgServer` in `main`, the listener builds one
/// per MCP session in its service factory. That factory is where per-client identity was wrong for
/// two months (`FOLLOWUPS.md` item 29) — right in every unit test, wrong on the wire — and the
/// surface is set on the same line, so it is asserted the same way: over real HTTP, against the
/// answer a client actually gets.
#[test]
fn a_listener_serves_the_narrowed_surface_it_was_started_with() {
    let mut listener = Listener::start_with_args(&[], &["--tools", "crash"]);
    let session = listener.initialize();

    let reply = listener.call(Some(&session), "tools/list", json!({}));
    assert_eq!(reply.status, 200, "{}", reply.body);
    let payload = reply.payload.clone().expect("a JSON-RPC payload");
    let names: Vec<String> = payload["result"]["tools"]
        .as_array()
        .expect("tools/list returns an array")
        .iter()
        .map(|t| t["name"].as_str().unwrap_or_default().to_string())
        .collect();

    assert!(names.contains(&"crash_triage".to_string()), "{names:?}");
    assert!(names.contains(&"open_dump".to_string()), "{names:?}");
    assert!(!names.contains(&"debug_batch".to_string()), "{names:?}");
    assert_eq!(names.len(), 11, "{names:?}");

    // And the startup line says which surface it ended up with, which is not always the spec that
    // was typed — `session` is added whatever it said.
    let log = listener.stderr();
    assert!(
        log.contains("serving 11 of 54 tools (session, crash)"),
        "the listener does not report the surface it ended up with: {log}"
    );
}

/// Two clients on one listener get two `tools/list` answers.
///
/// **The assertion that matters for a per-client surface**, and it is the one shape unit tests
/// cannot reach. The surface is chosen on the same line the caller's identity is captured on, and
/// that line was wrong for two months — every call ran as the default `local`, right in every unit
/// test and wrong on the wire, because a task-local does not cross the task rmcp spawns at
/// `initialize` (`FOLLOWUPS.md` item 29). A surface resolved from the wrong client is exactly that
/// bug again, and one client cannot state it: with one credential, "this client's spec" and "the
/// run's spec" are the same answer.
///
/// Protocol tier, not the debugger one: `tools/list` needs no target, and neither does a refusal
/// for a tool that is not on the surface — it is answered before anything is routed.
#[test]
fn two_clients_on_one_listener_are_served_two_surfaces() {
    let bench_token = format!("smoke-bench-{}", std::process::id());
    // The run's own `--tools` is the *default*, not a ceiling: `bench` names `crash` and is served
    // that instead, which is neither a subset nor a superset of what everybody else gets.
    let mut server = Listener::start_with_args(
        &[
            ("WINDBG_MCP_LISTEN_TOKEN_BENCH", &bench_token),
            ("WINDBG_MCP_TOOLS_BENCH", "crash"),
        ],
        &["--tools", "session,inspect"],
    );
    let local_token = server.token.clone();
    assert!(
        server.wait_for_stderr(
            "serving 19 of 54 tools (session, inspect) — except bench serves 11 of 54 tools \
             (session, crash)",
            Duration::from_secs(30)
        ),
        "the startup line does not say what each client is served:\n{}",
        server.stderr()
    );

    let local_mcp = server.initialize_as(&local_token);
    let bench_mcp = server.initialize_as(&bench_token);

    let listed = |server: &mut Listener, token: &str, session: &str| -> Vec<String> {
        let reply = server.call_as(token, Some(session), "tools/list", json!({}));
        assert_eq!(reply.status, 200, "{}", reply.body);
        reply.payload.clone().expect("a JSON-RPC payload")["result"]["tools"]
            .as_array()
            .expect("tools/list returns an array")
            .iter()
            .map(|t| t["name"].as_str().unwrap_or_default().to_string())
            .collect()
    };

    let by_local = listed(&mut server, &local_token, &local_mcp);
    let by_bench = listed(&mut server, &bench_token, &bench_mcp);
    assert_eq!(by_local.len(), 19, "{by_local:?}");
    assert_eq!(by_bench.len(), 11, "{by_bench:?}");
    assert!(by_local.contains(&"registers".to_string()), "{by_local:?}");
    assert!(
        !by_local.contains(&"crash_triage".to_string()),
        "{by_local:?}"
    );
    assert!(
        by_bench.contains(&"crash_triage".to_string()),
        "{by_bench:?}"
    );
    assert!(!by_bench.contains(&"registers".to_string()), "{by_bench:?}");
    // Both hold the openers, because every other tool routes by a handle only this server issues.
    for names in [&by_local, &by_bench] {
        assert!(names.contains(&"open_dump".to_string()), "{names:?}");
    }

    // **The instructions move with the surface too**, which they did not until `FOLLOWUPS.md`
    // item 40: one constant naming twenty-one tools went to every client, so a client served
    // eleven was told about `modules`, `execute` and `debug_batch` and would ask for them. The
    // eval measured that as models inventing tool names; they were reading this server.
    let instructions = |server: &mut Listener, token: &str| -> String {
        let reply = server.call_as(token, None, "initialize", Listener::opening());
        assert_eq!(reply.status, 200, "{}", reply.body);
        reply.payload.clone().expect("a JSON-RPC payload")["result"]["instructions"]
            .as_str()
            .unwrap_or_else(|| panic!("initialize carried no instructions: {}", reply.body))
            .to_string()
    };
    let to_local = instructions(&mut server, &local_token);
    let to_bench = instructions(&mut server, &bench_token);
    for text in [&to_local, &to_bench] {
        // The base half, which every surface includes because every tool routes by a handle.
        assert!(text.contains("WinDbg"), "{text}");
        assert!(text.contains("session_id"), "{text}");
        assert!(text.contains("end_session"), "{text}");
    }
    // Each is told about its own groups and no others. `debug_batch` is the one to keep an eye on:
    // it is a group of one, it is the most destructive tool here, and neither of these clients is
    // served it.
    for absent in [
        "crash_triage",
        "debug_batch",
        "decode_ioctl",
        "ttd_calls",
        "run_to_address",
    ] {
        assert!(
            !to_local.contains(absent),
            "`local` is served session,inspect and was told about `{absent}`: {to_local}"
        );
    }
    for absent in [
        "modules",
        "execute",
        "debug_batch",
        "decode_ioctl",
        "ttd_calls",
    ] {
        assert!(
            !to_bench.contains(absent),
            "`bench` is served crash and was told about `{absent}`: {to_bench}"
        );
    }
    assert!(to_local.contains("modules"), "{to_local}");
    assert!(to_bench.contains("crash_triage"), "{to_bench}");
    assert!(
        to_bench.len() < to_local.len(),
        "the smaller surface should read less prose: bench {} vs local {}",
        to_bench.len(),
        to_local.len()
    );

    // **And so do the tool descriptions**, the third and largest channel of prose. Item 40 left
    // them behind and `FOLLOWUPS.md` item 41 measured what that cost: on `--tools crash` five
    // descriptions of tools the client *is* served named four it is not, and 13 of 61 calls on
    // that surface went to asking for them — three times what the instructions were costing. The
    // budget golden cannot see this, because it records one surface; so it is asserted the way
    // every other per-client property here is, with two credentials on one port.
    let described = |server: &mut Listener, token: &str, session: &str| -> Vec<(String, String)> {
        let reply = server.call_as(token, Some(session), "tools/list", json!({}));
        assert_eq!(reply.status, 200, "{}", reply.body);
        reply.payload.clone().expect("a JSON-RPC payload")["result"]["tools"]
            .as_array()
            .expect("tools/list returns an array")
            .iter()
            .map(|t| {
                (
                    t["name"].as_str().unwrap_or_default().to_string(),
                    t["description"].as_str().unwrap_or_default().to_string(),
                )
            })
            .collect()
    };
    let prose_local = described(&mut server, &local_token, &local_mcp);
    let prose_bench = described(&mut server, &bench_token, &bench_mcp);
    // Backticked, because that is what "names a tool" means here and a bare word is not: this
    // very surface says frames are "attributed to modules" and that a stuck session "does not let
    // go", and neither sentence points anywhere.
    for name in ["`modules`", "`debug_batch`", "`go`", "`backtrace`"] {
        for (tool, text) in &prose_bench {
            assert!(
                !text.contains(name),
                "`bench` is served crash and `{tool}`'s description names {name}:\n{text}"
            );
        }
    }
    let of = |tools: &[(String, String)], want: &str| -> String {
        tools
            .iter()
            .find(|(name, _)| name == want)
            .map(|(_, text)| text.clone())
            .unwrap_or_else(|| panic!("`{want}` is not on this surface"))
    };
    // The other direction, which is the half worth keeping: the client that can act on a pointer
    // still reads it. Deleting the cross-references outright would pass the loop above.
    let opener_local = of(&prose_local, "open_dump");
    let opener_bench = of(&prose_bench, "open_dump");
    assert!(opener_local.contains("`modules`"), "{opener_local}");
    assert!(
        opener_bench.len() < opener_local.len(),
        "the opener should read shorter on the surface that cannot follow its pointer: bench {} \
         vs local {}",
        opener_bench.len(),
        opener_local.len()
    );
    // And it is per reference rather than per tool: `local` has `execute` and not `crash_triage`,
    // so `backtrace` keeps one of its two notes and loses the other.
    let stack = of(&prose_local, "backtrace");
    assert!(!stack.contains("`crash_triage`"), "{stack}");
    assert!(stack.contains(r#"`execute { "command": "k" }`"#), "{stack}");

    // And a tool off the surface is refused by name, with the remedy for *this* caller: `local`
    // takes the run's, so the flag is the answer; `bench` has one of its own, so the client
    // command is. Naming the wrong one sends an operator to widen a spec that is not in force.
    let refused = |server: &mut Listener, token: &str, session: &str, tool: &str| -> String {
        let reply = server.call_as(
            token,
            Some(session),
            "tools/call",
            json!({ "name": tool, "arguments": {} }),
        );
        let payload = reply.payload.clone().expect("a JSON-RPC payload");
        payload["error"]["message"]
            .as_str()
            .unwrap_or_else(|| panic!("`{tool}` was not refused: {}", reply.body))
            .to_string()
    };
    let to_local = refused(&mut server, &local_token, &local_mcp, "crash_triage");
    assert!(to_local.contains("this run advertises"), "{to_local}");
    assert!(to_local.contains("started with `--tools`"), "{to_local}");
    let to_bench = refused(&mut server, &bench_token, &bench_mcp, "registers");
    assert!(to_bench.contains("it serves `bench`"), "{to_bench}");
    assert!(
        to_bench.contains("--set-listen-client-tools bench"),
        "{to_bench}"
    );

    // The same question on `2026-07-28`, which reaches the surface by the other route: no MCP
    // session, so no task spawned to serve one, and the identity arrives with the request itself.
    // Both are asserted because the bug this shape has produced before was one of them losing it.
    let stateless = server.stateless_as(&bench_token, "tools/list", json!({}));
    assert_eq!(stateless.status, 200, "{}", stateless.body);
    let names: Vec<String> = stateless.result("tools/list")["tools"]
        .as_array()
        .expect("tools/list returns an array")
        .iter()
        .map(|t| t["name"].as_str().unwrap_or_default().to_string())
        .collect();
    assert_eq!(
        names, by_bench,
        "a stateless client is served the same surface its session-bearing self is"
    );
}

/// A `--listen` server, and just enough HTTP to drive it.
struct Listener {
    child: Child,
    addr: String,
    token: String,
    stderr_log: Arc<Mutex<Vec<String>>>,
    next_id: i64,
}

impl Listener {
    fn start(env: &[(&str, &str)]) -> Self {
        Self::start_with_args(env, &[])
    }

    /// The same, plus arguments after `--listen <addr>`. `--tools` is the one that needs it: the
    /// surface is applied where the listener builds a server per MCP session, which is a different
    /// line from stdio's and is exactly the kind of wiring that is right in a unit test and wrong
    /// on the wire (`FOLLOWUPS.md` item 29).
    fn start_with_args(env: &[(&str, &str)], args: &[&str]) -> Self {
        let addr = format!("127.0.0.1:{}", free_port());
        // Distinct per listener, so a token left in a stray process cannot reach this one.
        let token = format!("smoke-{}-{addr}", std::process::id());
        let mut command = Command::new(EXE);
        command
            .arg("--listen")
            .arg(&addr)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env("RUST_LOG", "info")
            .env("WINDBG_MCP_LISTEN_TOKEN", &token);
        for (key, value) in env {
            command.env(key, value);
        }
        let mut child = command
            .spawn()
            .unwrap_or_else(|e| panic!("failed to spawn {EXE} --listen {addr}: {e}"));

        // Both drained, for the same reason the stdio harness drains stderr: an unread pipe fills
        // and the server blocks mid-test, which would present as a protocol hang.
        let stderr_log = Arc::new(Mutex::new(Vec::new()));
        let err = BufReader::new(child.stderr.take().expect("piped stderr"));
        let log = Arc::clone(&stderr_log);
        std::thread::spawn(move || {
            for line in err.lines().map_while(Result::ok) {
                log.lock().unwrap().push(line);
            }
        });
        let out = BufReader::new(child.stdout.take().expect("piped stdout"));
        std::thread::spawn(move || out.lines().map_while(Result::ok).for_each(drop));

        let listener = Self {
            child,
            addr,
            token,
            stderr_log,
            next_id: 1,
        };
        listener.wait_until_bound();
        listener
    }

    fn stderr(&self) -> String {
        self.stderr_log.lock().unwrap().join("\n")
    }

    fn wait_for_stderr(&self, needle: &str, budget: Duration) -> bool {
        let deadline = Instant::now() + budget;
        loop {
            if self.stderr().contains(needle) {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Waits for the bind rather than guessing at it — the alternative is a fixed sleep that is
    /// either too short on a loaded runner or wasted on every run.
    fn wait_until_bound(&self) {
        let deadline = Instant::now() + Duration::from_secs(30);
        let addr: std::net::SocketAddr = self.addr.parse().expect("a loopback address");
        loop {
            if std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "the listener never bound {}\n--- stderr ---\n{}",
                self.addr,
                self.stderr()
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// One request, on a connection of its own.
    ///
    /// A connection per request is what a client behind a tunnel looks like anyway, and it makes
    /// "the client went quiet" the default rather than something the test has to arrange: there is
    /// no connection left open for the server to mistake for a client still there.
    fn send(
        &self,
        method: &str,
        token: Option<&str>,
        session: Option<&str>,
        body: Option<&Value>,
    ) -> Reply {
        self.send_with(method, token, session, body, &[])
    }

    /// [`Self::send`], plus headers the caller names.
    ///
    /// Only `2026-07-28` needs this, and it needs it twice over: that revision carries the
    /// negotiated protocol in a header on *every* request rather than in a handshake, and SEP-2243
    /// has each request name its own method in one too. Both are transport-level, so neither is
    /// expressible in the JSON-RPC body the other helpers build.
    fn send_with(
        &self,
        method: &str,
        token: Option<&str>,
        session: Option<&str>,
        body: Option<&Value>,
        extra: &[(&str, &str)],
    ) -> Reply {
        use std::io::Read;

        let mut stream = std::net::TcpStream::connect(&self.addr)
            .unwrap_or_else(|e| panic!("cannot reach the listener at {}: {e}", self.addr));
        // So a server that never answers fails this test rather than hanging the suite.
        stream
            .set_read_timeout(Some(Duration::from_secs(60)))
            .expect("set a read timeout");

        let mut request = format!(
            "{method} / HTTP/1.1\r\nHost: {}\r\nAccept: application/json, text/event-stream\r\n\
             Connection: close\r\n",
            self.addr
        );
        if let Some(token) = token {
            request.push_str(&format!("Authorization: Bearer {token}\r\n"));
        }
        if let Some(session) = session {
            request.push_str(&format!("Mcp-Session-Id: {session}\r\n"));
        }
        for (name, value) in extra {
            request.push_str(&format!("{name}: {value}\r\n"));
        }
        match body.map(|b| b.to_string()) {
            Some(body) => {
                request.push_str(&format!(
                    "Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                ));
            }
            None => request.push_str("\r\n"),
        }
        stream.write_all(request.as_bytes()).expect("write request");
        stream.flush().expect("flush request");

        let mut raw = Vec::new();
        // A read error is not a failure here: `Connection: close` means the server ends the
        // stream, and whatever arrived before that is the reply.
        let _ = stream.read_to_end(&mut raw);
        parse_reply(&raw)
    }

    /// A JSON-RPC request from the authorised client.
    fn call(&mut self, session: Option<&str>, method: &str, params: Value) -> Reply {
        let token = self.token.clone();
        self.call_as(&token, session, method, params)
    }

    /// [`Self::call`], from a credential this helper did not configure.
    ///
    /// Every rule ownership is made of needs **two** of them to be visible at all: a handle
    /// another client opened, an `Mcp-Session-Id` another client holds, a count taken for the
    /// wrong client. One token can state none of those, which is what left the per-client
    /// behaviour unexercised end to end (`FOLLOWUPS.md` item 29).
    fn call_as(
        &mut self,
        token: &str,
        session: Option<&str>,
        method: &str,
        params: Value,
    ) -> Reply {
        let id = self.next_id;
        self.next_id += 1;
        let body = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        self.send("POST", Some(token), session, Some(&body))
    }

    fn opening() -> Value {
        json!({
            "protocolVersion": LEASE_REVISION,
            "capabilities": {},
            "clientInfo": { "name": "windbg-mcp-lease-smoke", "version": "1" },
        })
    }

    /// One `2026-07-28` request, spelled the way that revision requires.
    ///
    /// Three things travel with a stateless request, and the server rejects it if any is absent —
    /// which is the whole of [#168](https://github.com/glslang/windbg-mcp/issues/168):
    ///
    /// - the `MCP-Protocol-Version` header, since there is no handshake left to remember what was
    ///   negotiated;
    /// - `params._meta` carrying `io.modelcontextprotocol/protocolVersion` and
    ///   `…/clientCapabilities`, which SEP-2567 moved into every request when it removed the
    ///   session that used to hold them;
    /// - SEP-2243's `Mcp-Method` header, naming the body's method to whatever is between the two
    ///   machines without it having to parse the body — and, where the method addresses something
    ///   by name, an `Mcp-Name` beside it.
    ///
    /// `initialize` is exempt from the latter two — it is the request that establishes them.
    fn stateless(&mut self, method: &str, params: Value) -> Reply {
        let id = self.next_id;
        self.next_id += 1;
        self.stateless_at(id, method, params)
    }

    /// [`Self::stateless`], from a credential this helper did not configure.
    ///
    /// The stateless revision reaches the registry by a different route — no MCP session, so no
    /// task spawned to serve one — and a boundary that held on only one of the two routes would
    /// depend on which revision a client had negotiated.
    fn stateless_as(&mut self, token: &str, method: &str, params: Value) -> Reply {
        let id = self.next_id;
        self.next_id += 1;
        let (body, name) = Self::stateless_body(id, method, params);
        self.send_with(
            "POST",
            Some(token),
            None,
            Some(&body),
            &Self::stateless_headers(method, name.as_deref()),
        )
    }

    /// [`Self::stateless`] with the request id named rather than counted.
    ///
    /// Immutable, which is the whole reason it is separate: a request that has to run *alongside*
    /// another cannot be sent through a `&mut self` borrow, and overlap is what the stateless
    /// revision makes ordinary.
    fn stateless_at(&self, id: i64, method: &str, params: Value) -> Reply {
        let (body, name) = Self::stateless_body(id, method, params);
        self.send_with(
            "POST",
            Some(&self.token.clone()),
            None,
            Some(&body),
            &Self::stateless_headers(method, name.as_deref()),
        )
    }

    /// The body of a stateless request, and the value its `Mcp-Name` must mirror.
    ///
    /// Split out because one request in this tier is sent *without* waiting for a reply, and
    /// building its shape a second time by hand is how a test ends up measuring something the rest
    /// of the tier no longer sends.
    fn stateless_body(id: i64, method: &str, mut params: Value) -> (Value, Option<String>) {
        params["_meta"] = json!({
            "io.modelcontextprotocol/protocolVersion": STATELESS_REVISION,
            "io.modelcontextprotocol/clientCapabilities": {},
        });
        // SEP-2243 maps the header per method rather than per parameter: `tools/call` and
        // `prompts/get` mirror `params.name`, `resources/read` mirrors `params.uri`, and every
        // other method sends none. Keyed on the method for that reason — a `name` argument that
        // happens to belong to some other method's parameters is not this header's value.
        let name = match method {
            "tools/call" | "prompts/get" => params["name"].as_str().map(str::to_owned),
            "resources/read" => params["uri"].as_str().map(str::to_owned),
            _ => None,
        };
        let body = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        (body, name)
    }

    fn stateless_headers<'h>(method: &'h str, name: Option<&'h str>) -> Vec<(&'h str, &'h str)> {
        let mut headers = vec![
            ("MCP-Protocol-Version", STATELESS_REVISION),
            ("Mcp-Method", method),
        ];
        if let Some(name) = name {
            headers.push(("Mcp-Name", name));
        }
        headers
    }

    /// A stateless request sent for its *effect*, whose reply is never waited for.
    ///
    /// One request in this tier is not expected to answer at all — a kernel attach parked on a
    /// target that will never dial in — and it has to stay running while other requests are made
    /// alongside it. So this neither reads nor parses: it writes the request and hands back the
    /// **still-open connection**, which the caller holds for as long as the request should live.
    /// Closing it is what ends the request, so dropping the returned stream is the cleanup.
    ///
    /// Waiting for it on a second thread was the obvious shape and the wrong one: the reply never
    /// comes, so the join at the end of the test blocks for the whole read timeout and then panics
    /// parsing an empty buffer — reporting the missing reply instead of whichever assertion
    /// actually failed.
    #[must_use = "the connection is what keeps the request alive; dropping it ends the request"]
    fn stateless_unanswered(&self, id: i64, method: &str, params: Value) -> std::net::TcpStream {
        let (body, name) = Self::stateless_body(id, method, params);
        let headers = Self::stateless_headers(method, name.as_deref());
        let body = body.to_string();
        let mut request = format!(
            "POST / HTTP/1.1\r\nHost: {}\r\nAccept: application/json, text/event-stream\r\n\
             Connection: close\r\nAuthorization: Bearer {}\r\n",
            self.addr, self.token
        );
        for (name, value) in &headers {
            request.push_str(&format!("{name}: {value}\r\n"));
        }
        request.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        ));

        let mut stream = std::net::TcpStream::connect(&self.addr)
            .unwrap_or_else(|e| panic!("cannot reach the listener at {}: {e}", self.addr));
        stream
            .set_read_timeout(Some(Duration::from_secs(60)))
            .expect("set a read timeout");
        stream.write_all(request.as_bytes()).expect("write request");
        stream.flush().expect("flush request");
        stream
    }

    /// The `2026-07-28` handshake, which mints nothing and is therefore not a session.
    ///
    /// Sent for the same reason a stateless client sends it: to learn what the server is. Nothing
    /// afterwards depends on it having happened, which is the property being asserted.
    fn stateless_opening(&mut self) -> Reply {
        self.stateless_opening_with(&[("MCP-Protocol-Version", STATELESS_REVISION)])
    }

    /// [`Self::stateless_opening`], with the transport headers named rather than assumed.
    ///
    /// Exists for the empty slice. `initialize` is the one request of this revision that may
    /// arrive **without** `MCP-Protocol-Version` — it is the request that establishes the revision,
    /// so there is nothing yet for a header to restate — and sending it anyway, as the handshake
    /// above does, is legal and is what left the other shape undriven (`FOLLOWUPS.md` item 30).
    fn stateless_opening_with(&mut self, headers: &[(&str, &str)]) -> Reply {
        let id = self.next_id;
        self.next_id += 1;
        let body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "initialize",
            "params": {
                "protocolVersion": STATELESS_REVISION,
                "capabilities": {},
                "clientInfo": { "name": "windbg-mcp-stateless-smoke", "version": "1" },
            },
        });
        self.send_with(
            "POST",
            Some(&self.token.clone()),
            None,
            Some(&body),
            headers,
        )
    }

    /// The handshake, answering with the session id a lease is armed by.
    fn initialize(&mut self) -> String {
        let token = self.token.clone();
        self.initialize_as(&token)
    }

    /// [`Self::initialize`], for the credential named rather than the one configured.
    fn initialize_as(&mut self, token: &str) -> String {
        let reply = self.call_as(token, None, "initialize", Self::opening());
        assert_eq!(
            reply.status,
            200,
            "initialize was refused ({}): {}\n--- stderr ---\n{}",
            reply.status,
            reply.body,
            self.stderr()
        );
        let session = reply
            .session
            .clone()
            .unwrap_or_else(|| panic!("initialize minted no Mcp-Session-Id: {}", reply.body));
        // The credential that opened it, not the configured one: an ack carrying another client's
        // token would present this session id to a namespace that does not hold it, and be
        // answered `404` by the very ownership check the tests below are about.
        let ack = self.send(
            "POST",
            Some(token),
            Some(&session),
            Some(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" })),
        );
        assert!(
            (200..300).contains(&ack.status),
            "the initialized notification was refused ({}): {}",
            ack.status,
            ack.body
        );
        session
    }

    /// The typed half of a tool call that worked.
    fn tool(&mut self, session: &str, name: &str, args: Value) -> Value {
        let token = self.token.clone();
        self.tool_as(&token, session, name, args)
    }

    /// [`Self::tool`], for the credential named rather than the one configured.
    ///
    /// "Worked" here is the **transport** answering, not the tool succeeding: a call refused for
    /// naming another client's handle is a perfectly good `200` carrying an error, which is the
    /// distinction the ownership tests turn on.
    fn tool_as(&mut self, token: &str, session: &str, name: &str, args: Value) -> Value {
        let reply = self.call_as(
            token,
            Some(session),
            "tools/call",
            json!({ "name": name, "arguments": args }),
        );
        assert_eq!(
            reply.status, 200,
            "`{name}` was refused ({}): {}",
            reply.status, reply.body
        );
        reply.result(name)["structuredContent"].clone()
    }

    /// The client saying it is done, which is the only departure the server is ever told about.
    fn goodbye(&self, session: &str) -> Reply {
        self.goodbye_as(&self.token.clone(), session)
    }

    /// [`Self::goodbye`], for the credential named rather than the one configured.
    fn goodbye_as(&self, token: &str, session: &str) -> Reply {
        self.send("DELETE", Some(token), Some(session), None)
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Splits an HTTP reply into what a test asserts on.
///
/// Hand-rolled, and small enough to stay that way: a status, three headers, and a body that is
/// either a JSON document or an SSE frame carrying one. The chunked decode is not optional —
/// rmcp answers a tool call as `text/event-stream`, and scanning the raw stream for `data:` would
/// read a chunk-size line as content the moment a payload spans two chunks.
fn parse_reply(raw: &[u8]) -> Reply {
    let Some(split) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        panic!(
            "not an HTTP reply: {:?}",
            String::from_utf8_lossy(&raw[..raw.len().min(200)])
        );
    };
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("no status line in: {head}"));
    let header = |name: &str| {
        head.lines().skip(1).find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.trim()
                .eq_ignore_ascii_case(name)
                .then(|| value.trim().to_string())
        })
    };
    let chunked = header("transfer-encoding").is_some_and(|v| v.contains("chunked"));
    let raw_body = &raw[split + 4..];
    let body_bytes = if chunked {
        dechunk(raw_body)
    } else {
        raw_body.to_vec()
    };
    let body = String::from_utf8_lossy(&body_bytes).into_owned();
    // SSE frames first, then a plain body: a tool call comes back as the former and a refusal as
    // neither, and no frames at all is a fine answer for a refusal.
    let mut frames: Vec<Value> = body
        .lines()
        .filter_map(|line| line.trim().strip_prefix("data: "))
        .filter_map(|data| serde_json::from_str::<Value>(data).ok())
        .collect();
    if frames.is_empty()
        && let Ok(plain) = serde_json::from_str::<Value>(&body)
    {
        frames.push(plain);
    }
    // The **response**, which is the frame carrying an id — a call that asked for progress is
    // answered on a stream whose earlier frames are notifications, and those have none. Taking
    // the first frame regardless would hand `result` a progress line to look for an answer in.
    let payload = frames
        .iter()
        .find(|frame| !frame["id"].is_null())
        .or_else(|| frames.first())
        .cloned();
    Reply {
        status,
        session: header("mcp-session-id"),
        payload,
        frames,
        body,
    }
}

/// `Transfer-Encoding: chunked`, decoded on bytes — a chunk boundary may split a code point, and
/// slicing a `&str` there would panic on content this server has no control over.
fn dechunk(mut rest: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(eol) = rest.windows(2).position(|w| w == b"\r\n") {
        let header = String::from_utf8_lossy(&rest[..eol]);
        let size = header.split(';').next().unwrap_or("").trim();
        let Ok(len) = usize::from_str_radix(size, 16) else {
            break;
        };
        rest = &rest[eol + 2..];
        if len == 0 {
            break;
        }
        let take = len.min(rest.len());
        out.extend_from_slice(&rest[..take]);
        rest = &rest[take..];
        if rest.starts_with(b"\r\n") {
            rest = &rest[2..];
        }
    }
    out
}

/// The listener exposes every tool this server has, including the ones that write to a live
/// kernel. Starting without a token would put that on a port with no lock at all, so it refuses —
/// and refuses *loudly*, because the failure mode of a quiet default is a server nobody knows is
/// open.
#[test]
fn the_listener_will_not_start_without_a_token() {
    let addr = format!("127.0.0.1:{}", free_port());
    let mut child = Command::new(EXE)
        .arg("--listen")
        .arg(&addr)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_remove("WINDBG_MCP_LISTEN_TOKEN")
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn {EXE}: {e}"));
    // Waited for with a deadline rather than `output()`, because the regression under test is a
    // listener that *serves*: that one never exits, and a bare wait would hang the suite instead
    // of failing it.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match child.try_wait().expect("poll the listener") {
            Some(_) => break,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("the listener started with no token set, and stayed up serving on {addr}");
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    let out = child
        .wait_with_output()
        .expect("collect the listener's output");
    assert!(
        !out.status.success(),
        "the listener started with no token set"
    );
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(
        said.contains("WINDBG_MCP_LISTEN_TOKEN"),
        "it has to name the variable that is missing, or nobody can act on it: {said}"
    );
}

/// Installing the service without an address is refused **before the SCM is touched**.
///
/// Two things at once, and the ordering is the interesting one. The SCM stores the command line
/// once, at install time, and nothing re-derives it — so a service registered without an address is
/// one that installs cleanly and then fails at every start, which is the worst shape this can take.
/// And because the refusal happens before any SCM call, it needs no elevation, which is what lets
/// it live in the tier that runs everywhere rather than in one nobody runs.
#[test]
fn installing_the_service_without_an_address_is_refused_before_anything_is_registered() {
    let registered = service_is_registered();
    let out = Command::new(EXE)
        .arg("--install-service")
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn {EXE}: {e}"));
    assert!(
        !out.status.success(),
        "an install with no address should have been refused"
    );
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(
        said.contains("--listen"),
        "the refusal has to name what is missing, or nobody can act on it: {said}"
    );
    let after = service_is_registered();
    // Nothing was *changed* — asserted through the tool an operator would use, so this also fails
    // if the refusal happened after a partial install rather than before one.
    //
    // "Unchanged" rather than "absent", and deliberately: a developer running the ordinary suite on
    // a host where they have the service installed — which is to say, someone using the feature
    // under test — must not be failed by it. So the state is captured either side and compared.
    assert_eq!(
        registered, after,
        "the refused install changed whether `windbg-mcp` is registered with the SCM"
    );
}

/// A client command that is missing something is refused *before* it opens the SCM or the file.
///
/// The ordering is the assertion, and it is what makes this test run the same on a host that has
/// the service installed and one that does not: every refusal below is a usage error, so none of
/// them reaches the credential file — and a run on a developer's own host cannot disturb the
/// clients their listener is serving.
#[test]
fn a_client_command_says_what_is_missing_before_it_touches_anything() {
    let registered = service_is_registered();
    let refusal = |args: &[&str]| {
        let out = Command::new(EXE)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap_or_else(|e| panic!("failed to spawn {EXE}: {e}"));
        assert!(
            !out.status.success(),
            "`{args:?}` should have been refused, and was not"
        );
        String::from_utf8_lossy(&out.stderr).to_string()
    };

    let no_name = refusal(&["--add-listen-client"]);
    assert!(
        no_name.contains("--add-listen-client"),
        "a client command with no name has to name the flag it belongs to: {no_name}"
    );
    let bad_name = refusal(&["--rotate-listen-client", "two words"]);
    assert!(
        bad_name.contains("not a client name"),
        "a name that is not one has to be refused as that: {bad_name}"
    );
    assert!(
        !bad_name.contains("no service named"),
        "the SCM was consulted before the command line was checked, which makes a usage error \
         depend on whether the service happens to be installed: {bad_name}"
    );

    // **A flag is never a name.** Without this the name would be `--force`, which passes the
    // client-name rule since a name may contain `-`, and the command would mint a credential for a
    // client nobody asked for.
    let flag_as_name = refusal(&["--add-listen-client", "--force"]);
    assert!(
        flag_as_name.contains("--add-listen-client"),
        "a flag standing where a name belongs has to be refused as a missing name: {flag_as_name}"
    );
    assert_eq!(
        registered,
        service_is_registered(),
        "a refused client command changed whether `windbg-mcp` is registered with the SCM"
    );
}

/// The command that only reads answers on any host, says which source it answered for, and never
/// prints a token.
///
/// **Host-independent by construction**, which is what lets it live in the tier everyone runs.
/// The three outcomes are a service host with an elevated shell (the credential file's roster), a
/// service host without one (a refusal naming the ACL), and a host with no service (this shell's
/// own credentials) — and the two claims asserted here hold in all three: it names the source it
/// is answering for, and the token handed to it in the environment appears nowhere in what it
/// wrote. The second is the trap this command was built around (`FOLLOWUPS.md` item 37): a
/// fingerprint is the only comparable thing a roster may carry, and this is the one command in
/// the family an operator would run *because* it is safe to run in a transcript.
#[test]
fn listing_the_clients_names_its_source_and_prints_no_token() {
    let registered = service_is_registered();
    // A token this test can look for. It is also a real one: on a host with no service installed
    // this is the credential the command reports, so the run exercises the roster rather than
    // only the refusal.
    let secret = "this-token-must-not-be-printed-anywhere";
    let out = Command::new(EXE)
        .arg("--list-listen-clients")
        .stdin(Stdio::null())
        .env("WINDBG_MCP_LISTEN_TOKEN", secret)
        .env_remove("WINDBG_MCP_LISTEN_TOKEN_FILE")
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn {EXE}: {e}"));
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !said.contains(secret),
        "the client list printed a token: {said}"
    );
    // Whichever of the two sources it answered for, it has to say which — a roster with no source
    // beside it is one an operator cannot act on, and on this host either answer is legitimate.
    assert!(
        said.contains("WINDBG_MCP_LISTEN_TOKEN") || said.contains(r"windbg-mcp\token"),
        "the client list has to name the source it answered for: {said}"
    );
    assert_eq!(
        registered,
        service_is_registered(),
        "a command that only reads changed whether `windbg-mcp` is registered with the SCM"
    );
}

/// Whether the SCM has a service by this name, for the assertion above to compare against itself.
fn service_is_registered() -> bool {
    Command::new("sc.exe")
        .args(["query", "windbg-mcp"])
        .output()
        .expect("sc.exe is present on every Windows host")
        .status
        .success()
}

/// An unauthenticated caller is refused, told nothing about what is here — and costs the server
/// nothing.
///
/// The last clause is the one worth a test. The bearer check runs *before* the lease is touched, so
/// a wrong token must not renew one or reach the state behind it. It used to matter more sharply
/// than it does: while the gate existed, a request that reserved kept every other request of that
/// credential out, so anything that could reach the port could lock the real client out without
/// ever authenticating.
#[test]
fn an_unauthenticated_request_is_refused_and_costs_the_server_nothing() {
    let mut server = Listener::start(&[]);
    let probe = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} });
    for token in [None, Some("not-the-token"), Some("")] {
        let reply = server.send("POST", token, None, Some(&probe));
        assert_eq!(
            reply.status, 401,
            "a request with token {token:?} was not refused: {}",
            reply.body
        );
        assert!(
            !reply.body.contains("open_dump") && !reply.body.contains("jsonrpc"),
            "a refusal must not describe what is here: {}",
            reply.body
        );
    }
    let session = server.initialize();
    let status = server.tool(&session, "session_status", json!({}));
    assert_eq!(
        status["status"], "ok",
        "the real client must still be able to take a server that only refused strangers: {status}"
    );
}

/// A token file may name **more than one client**, and it is still the only credential there is.
///
/// Both halves matter, and they pull against each other. The precedence is load-bearing: the
/// service installer ACLs that file to SYSTEM and Administrators *because* the machine environment
/// is readable by unprivileged processes, so an environment token standing beside it would
/// reintroduce exactly what the file was written to avoid. But a file that could only ever name one
/// client made the per-client boundary of
/// [#162](https://github.com/glslang/windbg-mcp/issues/162) unreachable in the deployment
/// `docs/remote-listener.md` recommends — a service reads nothing else, so two agents on one host
/// shared a namespace (`FOLLOWUPS.md` item 31).
///
/// Protocol tier: no target, no worker. What is exercised here is the call site — a real listener
/// reading a real file — over the parse and precedence rules unit-tested in `src/client.rs`.
#[test]
fn a_token_file_names_its_own_clients_and_shuts_the_environment_out() {
    let at = marker_path("token-file");
    let for_local = "smoke-file-token-local";
    let for_ci = "smoke-file-token-ci";
    std::fs::write(
        &at,
        format!(r#"{{ "local": "{for_local}", "ci": "{for_ci}" }}"#),
    )
    .unwrap_or_else(|e| panic!("cannot write {}: {e}", at.display()));

    // The helper sets `WINDBG_MCP_LISTEN_TOKEN` on every listener it starts, which is the variable
    // this file has to shut out — so the environment half needs no arranging.
    let mut server = Listener::start(&[("WINDBG_MCP_LISTEN_TOKEN_FILE", &at.to_string_lossy())]);
    assert!(
        server.wait_for_stderr("clients: ci, local", Duration::from_secs(30)),
        "the startup line should name both clients the file configures:\n{}",
        server.stderr()
    );

    let from_the_environment = server.token.clone();
    let refused = server.send(
        "POST",
        Some(&from_the_environment),
        None,
        Some(&json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} })),
    );
    assert_eq!(
        refused.status, 401,
        "a file was configured, so the environment token must authenticate nobody: {}",
        refused.body
    );

    // And each client the file names is served, through the whole handshake.
    for (whose, token) in [("local", for_local), ("ci", for_ci)] {
        server.token = token.to_string();
        let session = server.initialize();
        let status = server.tool(&session, "session_status", json!({}));
        assert_eq!(
            status["status"], "ok",
            "the client `{whose}`, which the token file names, was not served: {status}"
        );
    }

    drop(server);
    let _ = std::fs::remove_file(&at);
}

/// A credential's second MCP session is **served alongside** the first, not refused.
///
/// This was a `409` until the gate was retired, and it was once the whole boundary: handles were
/// minted from one registry, `MAX_SESSIONS` was shared and `end_session` ended whatever it was
/// handed, so two clients would silently share and one could end a target the other was using.
/// Ownership took that job over ([#162](https://github.com/glslang/windbg-mcp/issues/162)), and
/// what the gate had left to arbitrate was one credential racing *itself* — which inside a
/// namespace is not a boundary at all: both MCP sessions reach the same debug sessions, because
/// they are the same client. `FOLLOWUPS.md` item 28 is where that was decided; this is the property
/// that replaces the refusal.
///
/// The half underneath still has to hold, and the last assertion is it: an id **this server never
/// issued** is not served. An id *another client* holds is refused too — that one needs two tokens,
/// so it is unit-tested in `src/listen.rs` and asserted end to end by
/// [`two_clients_on_one_listener_keep_their_sessions_to_themselves`], which is what closed item 29.
#[test]
fn a_second_session_for_one_credential_is_served_alongside_the_first() {
    let mut server = Listener::start(&[]);

    // Both through the full handshake, ack included: the assertion that each was served lives in
    // the helper, which panics with the status and the server's stderr if one is refused.
    let first = server.initialize();
    let second = server.initialize();
    assert_ne!(
        first, second,
        "each initialize mints an MCP session of its own"
    );

    // And both are usable, against the one namespace of debug sessions behind them.
    for (which, id) in [("the first", &first), ("the second", &second)] {
        let status = server.tool(id, "session_status", json!({}));
        assert_eq!(
            status["status"], "ok",
            "{which} MCP session of one credential was not served: {status}"
        );
    }

    // An id nothing here issued is still not served — decided by the service now, which is where
    // an unknown session belongs once the listener has stopped refusing one on tenancy grounds.
    let stranger = server.call(
        Some("not-a-session-this-server-issued"),
        "tools/list",
        json!({}),
    );
    assert_ne!(
        stranger.status, 200,
        "an MCP session id this server never issued was served: {}",
        stranger.body
    );
}

/// The listener serves `2026-07-28` — the handshake *and* everything after it.
///
/// [#168](https://github.com/glslang/windbg-mcp/issues/168) reported the opposite: the handshake
/// answered `200` and the next request `400`, which would leave `--listen` usable only by clients
/// negotiating a legacy revision while advertising the newest one. It was measured with a
/// hand-rolled probe that sent the body and none of the transport contract that revision adds, so
/// what it found was the server enforcing the spec rather than failing to implement it. This is the
/// same sequence, spelled the way the revision requires — and it is the reason
/// [`Listener::stateless`] carries three things instead of one.
#[test]
fn the_listener_serves_the_stateless_revision_it_negotiates() {
    let mut server = Listener::start(&[]);

    let opening = server.stateless_opening();
    assert_eq!(
        opening.status,
        200,
        "the {STATELESS_REVISION} handshake was refused ({}): {}\n--- stderr ---\n{}",
        opening.status,
        opening.body,
        server.stderr()
    );
    assert_eq!(
        opening.result("initialize")["protocolVersion"],
        json!(STATELESS_REVISION),
        "the handshake must negotiate the revision it was offered: {}",
        opening.body
    );
    // SEP-2567 removed the session id, so there is nothing here for a lease to be armed by.
    // Asserted rather than assumed: ownership is what the listener still reads this header for,
    // and its absence is what makes the rest of this test a different client to the ones above.
    assert!(
        opening.session.is_none(),
        "{STATELESS_REVISION} must mint no Mcp-Session-Id: {}",
        opening.body
    );

    // The request the issue said was refused.
    let listed = server.stateless("tools/list", json!({}));
    assert_eq!(
        listed.status,
        200,
        "tools/list on {STATELESS_REVISION} was refused ({}): {}\n--- stderr ---\n{}",
        listed.status,
        listed.body,
        server.stderr()
    );
    let tools = listed.result("tools/list")["tools"].clone();
    assert!(
        tools.as_array().is_some_and(|t| !t.is_empty()),
        "a served tools/list has tools in it: {}",
        listed.body
    );

    // And a call, not only a listing: `tools/call` is the method that carries an `Mcp-Name` beside
    // its `Mcp-Method`, so it exercises a rule `tools/list` cannot reach.
    let called = server.stateless(
        "tools/call",
        json!({ "name": "session_status", "arguments": {} }),
    );
    assert_eq!(
        called.status,
        200,
        "a stateless tools/call was refused ({}): {}\n--- stderr ---\n{}",
        called.status,
        called.body,
        server.stderr()
    );
    assert_eq!(
        called.result("tools/call")["structuredContent"]["status"],
        json!("ok"),
        "a stateless tools/call must answer like any other: {}",
        called.body
    );
}

/// The handshake may omit `MCP-Protocol-Version`, and the client is ordinary afterwards.
///
/// It is the one request of `2026-07-28` that may: `initialize` *establishes* the revision, so rmcp
/// does not require the header that restates it. Nothing here drove that shape until now — stdio
/// has no headers to omit and [`Listener::stateless_opening`] sends one — which left the likeliest
/// handshake a real client sends as the only one untested.
///
/// **The hazard it carried has been deleted rather than covered**, and that is why this asserts
/// what it does. The listener used to classify a request by that header, so a headerless handshake
/// was read as an *opener*: it reserved, minted nothing, and left a deadline armed — a client's own
/// handshake starting the clock that would release whatever it had open, one grace later.
/// [#171](https://github.com/glslang/windbg-mcp/pull/171) deleted the classification and the
/// reservation both, so nothing arms a deadline before a settled MCP session exists. What survives
/// any particular mechanism is that the shape is served and the client works after it
/// (`FOLLOWUPS.md` item 30).
#[test]
fn a_stateless_handshake_may_omit_the_protocol_header() {
    let mut server = Listener::start(&[]);

    let opening = server.stateless_opening_with(&[]);
    assert_eq!(
        opening.status,
        200,
        "a headerless {STATELESS_REVISION} handshake was refused ({}): {}\n--- stderr ---\n{}",
        opening.status,
        opening.body,
        server.stderr()
    );
    assert_eq!(
        opening.result("initialize")["protocolVersion"],
        json!(STATELESS_REVISION),
        "the handshake must negotiate the revision its body offered, header or no header: {}",
        opening.body
    );
    assert!(
        opening.session.is_none(),
        "{STATELESS_REVISION} mints no Mcp-Session-Id, however it arrives: {}",
        opening.body
    );

    // And the client is ordinary afterwards. The exemption is for `initialize` alone, so these
    // carry the full contract — the point is that reaching it by the route that skips the header
    // leaves the server in the same place as the route that does not.
    let listed = server.stateless("tools/list", json!({}));
    assert_eq!(
        listed.status,
        200,
        "tools/list after a headerless handshake was refused ({}): {}\n--- stderr ---\n{}",
        listed.status,
        listed.body,
        server.stderr()
    );
    assert!(
        listed.result("tools/list")["tools"]
            .as_array()
            .is_some_and(|tools| !tools.is_empty()),
        "a served tools/list has tools in it: {}",
        listed.body
    );

    let called = server.stateless(
        "tools/call",
        json!({ "name": "session_status", "arguments": {} }),
    );
    assert_eq!(
        called.status,
        200,
        "a tools/call after a headerless handshake was refused ({}): {}\n--- stderr ---\n{}",
        called.status,
        called.body,
        server.stderr()
    );
    assert_eq!(
        called.result("tools/call")["structuredContent"]["status"],
        json!("ok"),
        "the server has to answer a call like any other: {}",
        called.body
    );
}

/// A stateless request missing part of its contract is refused **and told which part**.
///
/// This is the other half of [#168](https://github.com/glslang/windbg-mcp/issues/168): the two
/// shapes the probe sent, pinned so the same `400` cannot be read as a broken listener a second
/// time. Both bodies are JSON-RPC errors naming the missing piece — the probe reported them as
/// empty because `Invoke-WebRequest` throws on a 4xx and leaves the body on the exception, not
/// because the server sent nothing.
#[test]
fn an_under_specified_stateless_request_is_told_which_part_it_is_missing() {
    let mut server = Listener::start(&[]);
    let token = server.token.clone();
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {},
    });

    // The revision in the header and nothing else: SEP-2567 moved the negotiated protocol and the
    // client's capabilities into every request's `_meta`, and this one has neither.
    let bare = server.send_with(
        "POST",
        Some(&token),
        None,
        Some(&body),
        &[("MCP-Protocol-Version", STATELESS_REVISION)],
    );
    assert_eq!(
        bare.status, 400,
        "a request with no _meta was served: {}",
        bare.body
    );
    assert!(
        bare.body
            .contains("io.modelcontextprotocol/protocolVersion")
            && bare
                .body
                .contains("io.modelcontextprotocol/clientCapabilities"),
        "the refusal has to name the keys it wanted: {}",
        bare.body
    );

    // `_meta` supplied, and still short one thing: SEP-2243 has every request name its own method
    // in a header. This is the shape the issue's probe sent, and the one that made it look like
    // the metadata was not the problem.
    let mut with_meta = body.clone();
    with_meta["params"]["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion": STATELESS_REVISION,
        "io.modelcontextprotocol/clientCapabilities": {},
    });
    let unheaded = server.send_with(
        "POST",
        Some(&token),
        None,
        Some(&with_meta),
        &[("MCP-Protocol-Version", STATELESS_REVISION)],
    );
    assert_eq!(
        unheaded.status, 400,
        "a request with no Mcp-Method header was served: {}",
        unheaded.body
    );
    assert!(
        unheaded.body.contains("Mcp-Method"),
        "the refusal has to name the header it wanted: {}",
        unheaded.body
    );

    // And the server is undamaged by either — a refusal at this layer must not touch the lease
    // state behind it, for the same reason the unauthenticated one must not.
    let listed = server.stateless("tools/list", json!({}));
    assert_eq!(
        listed.status, 200,
        "a well-formed request after two refused ones: {}",
        listed.body
    );
}

/// Going quiet is not leaving; saying goodbye is.
///
/// The distinction is the whole reason a lease exists. Every request here is its own connection —
/// which is what a client behind a tunnel looks like — so "the client is silent" is the resting
/// state, and a server that treated silence as departure would release a working client's targets
/// between two of its calls.
#[test]
fn a_silence_is_not_a_departure_and_a_goodbye_is() {
    let mut server = Listener::start(&[]);
    let holder = server.initialize();

    // Nothing is connected at this moment, and the client is still here: returning with the id it
    // left with is served. That is the property stdio cannot offer, where a client restart costs a
    // KDNET attach and a KDNET attach costs a reboot of the target.
    let resumed = server.call(Some(&holder), "tools/list", json!({}));
    assert_eq!(
        resumed.status, 200,
        "a returning client was not let back in: {}",
        resumed.body
    );

    let farewell = server.goodbye(&holder);
    assert!(
        (200..300).contains(&farewell.status),
        "the DELETE was refused ({}): {}",
        farewell.status,
        farewell.body
    );

    // And a goodbye *is* a departure: the id it said goodbye with is gone. This used to be read off
    // a `409` — a second `initialize` was refused while the first was held, so "still held" was
    // visible in the refusal — and nothing refuses that since the gate was retired. What says the
    // client left is the id it left with no longer being served.
    let stale = server.call(Some(&holder), "tools/list", json!({}));
    assert_ne!(
        stale.status, 200,
        "the id the client said goodbye with was still served: {}",
        stale.body
    );

    let next = server.initialize();
    assert_ne!(next, holder, "the next client gets a session of its own");
    let status = server.tool(&next, "session_status", json!({}));
    assert_eq!(status["status"], "ok", "{status}");
}

// ---- tier 2: a real debugger target -------------------------------------------

/// Gate for the tier that needs DbgEng. Returns the dump path, or `None` when the tier is off.
fn target_tier() -> Option<&'static str> {
    if std::env::var_os("WINDBG_MCP_SMOKE_DUMP").is_none() {
        skip("set WINDBG_MCP_SMOKE_DUMP=1 to run the debugger tier");
        return None;
    }
    if !std::path::Path::new(SAMPLE_DUMP).exists() {
        skip(&format!("sample dump not found at {SAMPLE_DUMP}"));
        return None;
    }
    Some(SAMPLE_DUMP)
}

/// The debugger tier's gate for a test that needs an engine and a **live process** rather than the
/// sample dump.
///
/// The same environment variable, because what it means is "this host has DbgEng"; without the
/// file check, which would stand a launch test down over a dump it never opens.
///
/// A tier of its own would be worse than either: these are the only tests in the suite that drive
/// *execution* on anything but a live kernel, and that is exactly the gap they exist to close
/// (issue #226). A gate nothing sets is a gap that stays open. One of them drives no execution at
/// all — it attaches to a process and ends the session — and is here because what it needs is the
/// same thing: a live user-mode target, which is to say a real engine.
fn launch_tier() -> bool {
    if std::env::var_os("WINDBG_MCP_SMOKE_DUMP").is_none() {
        skip("set WINDBG_MCP_SMOKE_DUMP=1 to run the debugger tier");
        return false;
    }
    true
}

/// A live user-mode target that runs long enough to be driven and exits on its own.
const LIVE_TARGET: &str = "cmd.exe /c ping -n 30 127.0.0.1";

/// Issue #226: a raw `execute` of execution-control text must **move the target**, not set a run
/// state nobody pumps.
///
/// What it did before: `Execute` set the run state and returned, so the call answered with its own
/// echoed command and nothing else, the target had not moved, and every later `g`/`p`/`t` on that
/// session failed with `0x80040205` while `bl`, `r` and `.lastevent` kept working. There was no
/// way back short of `end_session`.
///
/// All three commands the issue names, because all three are doors to the same state and a fix
/// that closed one would look identical from the outside. `t` and `p` stop on their own next
/// instruction; `g` needs somewhere to stop, which is what the breakpoint is for.
///
/// The fix is not a list of command names — it is `settle`, which asks the engine whether it was
/// left running. That is why this test does not have to enumerate every way to reach execution.
#[test]
fn a_raw_execution_control_command_moves_the_target_instead_of_wedging_the_session() {
    if !launch_tier() {
        return;
    }
    let mut server = Server::started();
    let session = server.open_session(
        "launch",
        json!({ "command_line": LIVE_TARGET }),
        TARGET_STEP,
    );
    // Armed before the loop so the `g` has somewhere to stop. Harmless to the two steps, which
    // stop on their own next instruction whatever is armed.
    server.tool_data(
        "set_breakpoint",
        json!({ "session_id": &session, "expression": "ntdll!NtCreateFile" }),
        TARGET_STEP,
    );

    let mut outputs: Vec<String> = Vec::new();
    for command in ["t", "p", "g"] {
        let out = server.tool_text(
            "execute",
            json!({ "session_id": &session, "command": command }),
            TARGET_STEP,
        );
        // The bug's own signature, quoted from the issue: "returns only the echoed command text".
        //
        // For a step the *position* is what says it moved, because DbgEng prints nothing else for
        // one: measured, the pump captures module loads and a stop banner for a `g` and an empty
        // string for a `t`, since the engine prints a step's new location from the command's own
        // completion rather than from the wait.
        assert!(
            out.contains("moved the target"),
            "`execute` with `{command}` answered `{out}`, which does not say the target moved"
        );

        // Checked **per command**, not once at the end: this is the property the issue is about,
        // and one check afterwards can only say that one of three commands broke the session.
        // `.lastevent` goes into the message rather than into an assertion of its own — it is what
        // tells a wedged engine apart from a target that simply went away, and those need opposite
        // responses while producing identical execution-control failures.
        let after = server.call_tool("registers", json!({ "session_id": &session }), TARGET_STEP);
        let last = last_event(&mut server, &session);
        assert!(
            !is_tool_error(&after),
            "the session is unusable after `execute` with `{command}`, which is the bug. Its \
             output was `{out}`; `registers` now answers {after}; the debugger's last event was \
             `{last}`"
        );
        outputs.push(format!("`{command}` -> {out:?}"));
    }

    // And the same property through the **typed** surface, which is what a caller reaches for
    // next and what the issue reports as broken.
    //
    // A step rather than `go`, because the two architectures disagree about what a `go` does here:
    // on x64 nothing stops the target — `cmd.exe` calls `NtCreateFile` while spawning `ping` and
    // then waits thirty seconds for it — so the `go` outlives the target, while on ARM64 it stops
    // at the breakpoint. That ending is now reported properly (issue #242,
    // `a_target_that_ends_during_a_resume_is_an_ending_and_the_session_says_so`, which is about
    // it); it used to be `Catastrophic failure (0x8000FFFF)`. Either way it is not what *this*
    // test is about, and a step completes on the next instruction on every architecture while
    // being execution control just as much as `go` is.
    //
    // Not `tool_data`: its refusal quotes the debugger's error and nothing around it, and what
    // makes a failure here readable is the state the three commands above left behind.
    let where_ = debugger_state(&mut server, &session);
    let stepped = server.call_tool("step_over", json!({ "session_id": &session }), TARGET_STEP);
    assert!(
        !is_tool_error(&stepped),
        "`step_over` failed after three raw execution-control commands, each of which left the \
         session answering `registers`. Their outputs were {outputs:?}. The session held \
         {where_}. `step_over` answered {stepped}"
    );
    let stop = &stepped["result"]["structuredContent"];
    assert_eq!(
        stop["timed_out"], false,
        "a step that completed must not report a bound it never hit: {stop}"
    );
    assert!(
        stop["stopped_at"].is_string(),
        "a step that completed must say where: {stop}"
    );

    // The **other** ending, on the same field the attach tier asserts `true`: a target this server
    // launched goes with the session, and a structured-aware client is told so. Asserted here
    // rather than in a test of its own because this is already a clean teardown of a live launched
    // process, which is exactly the state the claim is about.
    let ended = server.call_tool(
        "end_session",
        json!({ "session_id": &session }),
        TARGET_STEP,
    );
    assert_eq!(
        ended["result"]["structuredContent"]["target_left_running"],
        json!(false),
        "a launched process goes with its session, and the result does not say so: {}",
        ended["result"]["structuredContent"]
    );
}

/// `.lastevent`, or whatever came back instead — for a failure message, never for an assertion.
fn last_event(server: &mut Server, session: &str) -> String {
    raw(server, session, ".lastevent")
}

/// Enough of the session's state to read an execution-control failure: what stopped it last, what
/// breakpoints it holds, and which threads it has. For a message, never for an assertion.
fn debugger_state(server: &mut Server, session: &str) -> String {
    [".lastevent", "bl", "~", "r rip"]
        .into_iter()
        .map(|command| format!("[{command}] {}", raw(server, session, command)))
        .collect::<Vec<_>>()
        .join("; ")
}

fn raw(server: &mut Server, session: &str, command: &str) -> String {
    let response = server.call_tool(
        "execute",
        json!({ "session_id": session, "command": command }),
        TARGET_STEP,
    );
    text_of(&response["result"]).trim().replace('\n', " | ")
}

/// A resume that reaches **no** stop says so, and leaves the session usable.
///
/// The bug underneath #226, and the more serious of the two: `execute_and_wait` used a finite
/// `WaitForEvent` for every target that was not a live kernel, and on expiry that returns
/// `S_FALSE` with the target still running and the engine holding no current process/thread.
/// Measured before the fix: one `go` with nothing to stop it left `registers`, `bl` and `? @$ip`
/// failing with `0x80040205` for the life of the session, while the call itself reported success.
///
/// Nothing caught it because the only tier that drove execution was the live-kernel one, which was
/// already on the bounded wait.
///
/// Driven through a `debug_batch` rather than `go` for the bound: `go`'s own wait is a minute, and
/// three seconds of a target that will not stop proves the same thing. The `timed_out` field `go`
/// answers with is asserted `false` above; `true` is dbgscope's to cover, in
/// `a_go_that_never_stops_is_reported_and_leaves_the_engine_usable`, where a two-second bound
/// costs nothing.
#[test]
fn a_resume_that_reaches_no_stop_says_so_and_leaves_the_session_usable() {
    if !launch_tier() {
        return;
    }
    let mut server = Server::started();
    let session = server.open_session(
        "launch",
        json!({ "command_line": LIVE_TARGET }),
        TARGET_STEP,
    );

    let batch = server.call_tool(
        "debug_batch",
        json!({
            "session_id": &session,
            "steps": [{ "op": "resume", "command": "g", "timeout_ms": 3000 }],
            "timeout_ms": 30000,
        }),
        TARGET_STEP,
    );
    // Asserted on the **text**, because that is where a step's output lives: the structured report
    // carries what each step did and not what the debugger printed while it did it.
    let rendered = text_of(&batch["result"]);
    assert!(
        rendered.contains("had not stopped after 3000 ms"),
        "a resume broken in at its own bound must say so rather than pass for a stop: {rendered}"
    );
    let report = &batch["result"]["structuredContent"];

    // The regression. Read through a *typed* tool, not `execute`, because the failure was the
    // engine losing its current process/thread and every one of these goes through it.
    let after = server.call_tool("registers", json!({ "session_id": &session }), TARGET_STEP);
    assert!(
        !is_tool_error(&after),
        "the session is unusable after a resume that reached no stop: {after}"
    );
    assert_eq!(
        report["after"]["state"], "stopped",
        "the target was broken in, so the batch must report it stopped: {report}"
    );

    server.call_tool(
        "end_session",
        json!({ "session_id": &session }),
        TARGET_STEP,
    );
}

/// A live target that outlives anything these tests could take to drive it.
///
/// [`LIVE_TARGET`]'s thirty seconds is sized for a test that resumes once and asserts; the two
/// below have to be *in* the running state across half a dozen calls, on a runner that may be
/// bringing an engine up cold. A target that ran out mid-preamble would report `target_gone` where
/// they assert `interrupted`, which reads as the break-in having failed rather than as the clock
/// having. Nothing is left behind by the margin: both tests end their session, and a `launch`ed
/// process is terminated with it — including when the test fails and the harness kills the server.
const LONG_LIVE_TARGET: &str = "cmd.exe /c ping -n 120 127.0.0.1";

/// Issue #83: a run started with `continue_async` can be waited for later, and the session says
/// what it is doing throughout.
///
/// The whole lifecycle in one test, because every step here is only meaningful against the one
/// before it and splitting them would cost a launched target apiece. What each assertion is about:
///
/// - **The handle is issued while the target is moving.** `running: true` is the claim `go` cannot
///   make — it answers only once the target has stopped.
/// - **A second run is refused.** One engine thread, one target in motion.
/// - **A read is refused, and the refusal names the run.** This is the acceptance criterion about
///   "a clear *target is running* response instead of queueing ambiguously behind it": queued, a
///   `registers` here would be answered whenever the target next stopped — thirty seconds away for
///   this target — about wherever it happened to be.
/// - **A short wait is a poll.** Running out reports no stop and does not disturb the run, which is
///   what makes it safe to ask again.
/// - **`break_in` ends it**, and the stop that follows says it was broken in on request rather than
///   pretending the target chose to stop there.
/// - **The session takes work again afterwards**, with the stop still readable — a stop is read,
///   not taken.
///
/// `ping -n 30` is what makes the middle of this observable: it runs for half a minute with nothing
/// to stop it, so "the target is moving" is a state the test can be in rather than a race.
#[test]
fn a_run_started_asynchronously_is_waited_for_broken_in_and_read_twice() {
    if !launch_tier() {
        return;
    }
    let mut server = Server::started();
    let session = server.open_session(
        "launch",
        json!({ "command_line": LONG_LIVE_TARGET }),
        TARGET_STEP,
    );

    let started = server.tool_data(
        "continue_async",
        json!({ "session_id": &session, "max_run_ms": 300000 }),
        TARGET_STEP,
    );
    assert_eq!(
        started["running"],
        json!(true),
        "the handle is supposed to mean the target is moving, not that it was asked to: {started}"
    );
    let execution = started["execution"]
        .as_str()
        .expect("a started run mints a handle")
        .to_string();
    assert!(
        started["breaks_in_ms"]
            .as_u64()
            .is_some_and(|left| left > 0),
        "a run with no bound is a wait nobody is accounting for: {started}"
    );

    // One run per session.
    let refused = server.tool_failure(
        "continue_async",
        json!({ "session_id": &session }),
        TARGET_STEP,
    );
    assert_eq!(refused["error"]["category"], "target_running", "{refused}");
    assert!(
        refused["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains(&execution)),
        "a refusal that does not name the run already there leaves nothing to wait for: {refused}"
    );

    // And nothing reads a target while it moves.
    let refused = server.tool_failure("registers", json!({ "session_id": &session }), TARGET_STEP);
    assert_eq!(
        refused["error"]["category"], "target_running",
        "a read of a moving target must be refused as one, not folded into a debugger failure — a \
         caller told the debugger said no goes and looks at the target: {refused}"
    );

    // `session_status` is the tool that answers while everything else is refused, and it has to
    // say what the session is doing rather than just that it is open.
    let status = server.tool_data(
        "session_status",
        json!({ "session_id": &session }),
        TARGET_STEP,
    );
    let running = &status["sessions"][0]["execution"];
    assert_eq!(running["execution"], json!(execution), "{status}");
    assert_eq!(running["stopped"], json!(false), "{status}");

    // A short wait is a poll: it runs out, reports no stop, and leaves the run exactly as it was.
    let polled = server.tool_data(
        "wait_for_stop",
        json!({ "session_id": &session, "execution": &execution, "timeout_ms": 1500 }),
        TARGET_STEP,
    );
    assert!(
        polled["stop"].is_null(),
        "a wait that ran out must not report a stop: {polled}"
    );
    assert!(
        polled["breaks_in_ms"].as_u64().is_some_and(|left| left > 0),
        "the run is still going, so it still has a bound: {polled}"
    );

    // Nothing is going to stop this target on its own, so the break is what ends the run.
    let asked = server.tool_data(
        "break_in",
        json!({ "session_id": &session, "execution": &execution }),
        TARGET_STEP,
    );
    assert_eq!(asked["requested"], json!(true), "{asked}");

    let stopped = server.tool_data(
        "wait_for_stop",
        json!({ "session_id": &session, "execution": &execution, "timeout_ms": 30000 }),
        TARGET_STEP,
    );
    let stop = &stopped["stop"];
    assert!(
        !stop.is_null(),
        "the run was broken in, so the wait after it has to find a stop: {stopped}"
    );
    assert_eq!(
        stop["interrupted"],
        json!(true),
        "a break-in leaves the target where it happened to be, and a stop that does not say so is \
         read as a place the target goes: {stop}"
    );
    // The four facts issue #83 asks a stop to carry. `processor` is deliberately not among them:
    // a user-mode target has none, which is the answer rather than a missing field.
    assert!(
        stop["stopped_at"].as_str().is_some(),
        "a stop with no instruction pointer: {stop}"
    );
    assert!(
        stop["thread"].as_u64().is_some(),
        "a position without its thread does not identify a stop: {stop}"
    );
    assert!(
        stop["processor"].is_null(),
        "a user-mode target has no processor number, and inventing one would be worse than \
         omitting it: {stop}"
    );

    // Read twice: the stop is not consumed by the caller that collected it.
    let again = server.tool_data(
        "wait_for_stop",
        json!({ "session_id": &session, "execution": &execution, "timeout_ms": 1000 }),
        TARGET_STEP,
    );
    assert_eq!(
        again["stop"]["stopped_at"], stop["stopped_at"],
        "a second reader got a different answer: {again}"
    );

    // And the session is ordinary again, which is the other half of the refusal above.
    let after = server.call_tool("registers", json!({ "session_id": &session }), TARGET_STEP);
    assert!(
        !is_tool_error(&after),
        "the session must take reads again once its target has stopped: {after}"
    );

    server.call_tool(
        "end_session",
        json!({ "session_id": &session }),
        TARGET_STEP,
    );
}

/// Issue #83: `end_session` releases a target that is **still running**, rather than waiting for a
/// run that has no reason to end.
///
/// The one teardown that cannot simply queue. Every other operation on a worker's engine thread
/// ends on a clock that process owns; a run ends when the *target* stops, which for this target is
/// thirty seconds and for a live kernel could be an hour — so an `end_session` queued behind one
/// would have its grace expire against a worker that was working perfectly, and the worker would be
/// killed still holding the target.
///
/// Asserted on `released` rather than on the call succeeding: a teardown that killed the worker
/// also "succeeds", and the difference between the two is exactly what this is about.
#[test]
fn a_session_can_be_ended_while_its_target_is_running() {
    if !launch_tier() {
        return;
    }
    let mut server = Server::started();
    let session = server.open_session(
        "launch",
        json!({ "command_line": LONG_LIVE_TARGET }),
        TARGET_STEP,
    );
    let started = server.tool_data(
        "continue_async",
        json!({ "session_id": &session, "max_run_ms": 300000 }),
        TARGET_STEP,
    );
    assert_eq!(started["running"], json!(true), "{started}");

    let ended = server.tool_data(
        "end_session",
        json!({ "session_id": &session }),
        TARGET_STEP,
    );
    assert_eq!(
        ended["released"],
        json!(true),
        "the worker was killed rather than letting go, which is what a teardown that waited out a \
         run it could not stop looks like: {ended}"
    );
}

/// A live target that ends the moment it is resumed, so its exit races whatever is pumping it.
///
/// The other half of [`LIVE_TARGET`], and the difference is the whole point: one never stops on
/// its own and the other is over on the first `go`.
const SHORT_TARGET: &str = "cmd.exe /c exit";

/// Issue #242 and `FOLLOWUPS.md` item 48: a target that **ends** during a resume is an ending, not
/// a failure — and the session says so afterwards instead of half-answering.
///
/// What it did before, measured on both waits so it was never #226's doing: `go` on a debuggee
/// that ran to completion came back `Debug command failed: Catastrophic failure (0x8000FFFF)`,
/// which is the raw `E_UNEXPECTED` DbgEng answers once the wait ends with no debuggee left. The
/// output the run had captured went with it. The session then answered `.echo` and `.lastevent`
/// normally while `k`, `r` and `registers` failed `0x80040205` — indistinguishable, from a
/// caller's side, from the wedged session of #226, which needs the opposite response.
///
/// Both halves are asserted, because either alone is satisfiable by something wrong: reporting the
/// ending while leaving the chain in place fixes a message, and refusing everything afterwards
/// without reporting it turns a program finishing into a call that failed.
#[test]
fn a_target_that_ends_during_a_resume_is_an_ending_and_the_session_says_so() {
    if !launch_tier() {
        return;
    }
    let mut server = Server::started();
    let session = server.open_session(
        "launch",
        json!({ "command_line": SHORT_TARGET }),
        TARGET_STEP,
    );

    // Not `tool_data`: the whole claim is that this is *not* a tool error, so the assertion has to
    // be able to see one rather than panicking on it with a message about something else.
    let resumed = server.call_tool("go", json!({ "session_id": &session }), TARGET_STEP);
    let rendered = text_of(&resumed["result"]);
    assert!(
        !is_tool_error(&resumed),
        "a target running to completion was reported as a failed call: {rendered}"
    );
    let stop = &resumed["result"]["structuredContent"];
    assert_eq!(
        stop["target_gone"],
        json!(true),
        "the target ended and the stop report does not say so: {stop}"
    );
    assert!(
        stop["stopped_at"].is_null(),
        "a target that is gone has no position, and naming one would invent a stop: {stop}"
    );
    assert!(
        rendered.contains("the target is gone"),
        "the text half must carry the ending too — a structured-aware client forwards \
         `structuredContent` and drops the text, and every other client sees only this: {rendered}"
    );

    // The chain. A typed tool and the raw hatch, because they fail by different roads — `backtrace`
    // through the engine's own interfaces, `execute` through `Execute` — and before this each said
    // something different about one fact.
    for (tool, args) in [
        ("backtrace", json!({ "session_id": &session })),
        ("registers", json!({ "session_id": &session })),
        (
            "execute",
            json!({ "session_id": &session, "command": "k 3" }),
        ),
    ] {
        let refused = server.call_tool(tool, args, TARGET_STEP);
        let said = text_of(&refused["result"]);
        assert!(
            is_tool_error(&refused),
            "`{tool}` answered on a session with no target: {said}"
        );
        assert!(
            said.contains("no target left"),
            "`{tool}` refused without saying why, which is the half-dead session again: {said}"
        );
        assert_eq!(
            refused["result"]["structuredContent"]["error"]["category"],
            json!("stale_session"),
            "a caller branching on the category must be told to release this session, not to \
             change what it asked: {refused}"
        );
    }

    // And the one thing that must still work, since it is what every refusal above points at.
    let ended = server.call_tool(
        "end_session",
        json!({ "session_id": &session }),
        TARGET_STEP,
    );
    assert!(
        !is_tool_error(&ended),
        "`end_session` is the answer this session's refusals give, and it failed: {}",
        text_of(&ended["result"])
    );
}

/// The minimal repro from issue #242, which reaches the same ending through the **raw hatch**: the
/// exit races `settle`'s pump rather than a typed resume's wait.
///
/// `execute 'g'` sets the run state and returns its own echo; the pump that #226 added is what
/// moves the target, and it is there that the process runs out. That pump's capture used to be
/// discarded with the wait's error — which is the case where it matters most, since nothing will
/// print those lines again — and the session was left answering `.echo` while `k 3` failed
/// `0x80040205`.
///
/// The output is asserted only to have *survived*. Which lines a `cmd.exe` prints on its way out
/// belongs to the host; that anything crossed at all is the fix.
#[test]
fn a_target_that_ends_during_the_raw_hatchs_pump_reports_it_with_what_the_pump_captured() {
    if !launch_tier() {
        return;
    }
    let mut server = Server::started();
    let session = server.open_session(
        "launch",
        json!({ "command_line": SHORT_TARGET }),
        TARGET_STEP,
    );

    let ran = server.call_tool(
        "execute",
        json!({ "session_id": &session, "command": "g" }),
        TARGET_STEP,
    );
    let rendered = text_of(&ran["result"]);
    assert!(
        !is_tool_error(&ran),
        "the raw hatch reported a target running to completion as a failure: {rendered}"
    );
    assert!(
        rendered.contains("the target is gone"),
        "`execute 'g'` moved the target off the end and did not say so: {rendered}"
    );
    // The note is appended to the pump's own output, so anything ahead of it is what was captured
    // across the ending — and the echo `Execute` puts at the front is always part of it.
    let captured = rendered.split("[windbg-mcp]").next().unwrap_or("").trim();
    assert!(
        !captured.is_empty(),
        "the pump's output was discarded with the ending, which is the reported bug: {rendered}"
    );
    // And the sentence the *other* endings get must not appear: there is no position to name.
    assert!(
        !rendered.contains("now stopped"),
        "a target that is gone is not stopped anywhere: {rendered}"
    );

    let refused = server.call_tool(
        "execute",
        json!({ "session_id": &session, "command": "k 3" }),
        TARGET_STEP,
    );
    assert!(
        is_tool_error(&refused),
        "`k 3` answered on a session whose target had exited: {}",
        text_of(&refused["result"])
    );

    server.call_tool(
        "end_session",
        json!({ "session_id": &session }),
        TARGET_STEP,
    );
}

/// Whether a process this test started is still running, asked of the kernel rather than of
/// `Child::try_wait`.
///
/// `try_wait` is the wrong question and looks like the right one: a debuggee the kernel kills for
/// having lost its debugger has its exit status set before the call that killed it returns, while
/// its process object is not signalled yet — so `try_wait` answers "still running" for a process
/// that is already dead, and a test built on it passes whatever happened (measured in dbgscope,
/// where the first version of this same assertion did exactly that).
fn still_running(child: &std::process::Child) -> bool {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::Threading::GetExitCodeProcess;
    /// `STILL_ACTIVE` — what `GetExitCodeProcess` writes for a process that has not exited.
    const STILL_ACTIVE: u32 = 259;
    let mut code = 0u32;
    let read = unsafe { GetExitCodeProcess(child.as_raw_handle() as _, &mut code) };
    read != 0 && code == STILL_ACTIVE
}

/// A process to attach to that this suite did not create through the debugger — the thing an
/// attach test needs and a launch test cannot supply.
///
/// **Outlives the test by a wide margin on purpose.** Every step here is allowed `TARGET_STEP`,
/// and a fixture that ends on its own inside that budget fails as though `end_session` had killed
/// it — the one thing this test is about — on nothing worse than a slow runner. So the count is
/// far past any plausible run rather than merely past a fast one; the test kills it either way.
fn a_process_to_attach_to() -> std::process::Child {
    Command::new("ping")
        .args(["-n", "3000", "127.0.0.1"])
        .stdout(Stdio::null())
        .spawn()
        .expect("start a process to attach to")
}

/// **`FOLLOWUPS.md` item 51: ending a session must not take a process this server only attached
/// to.**
///
/// The end-to-end half of the fix, and the half no engine-level test can make: what killed the
/// process was `end_session` ending the engine's session passively, and what makes this server's
/// case worse than a plain debugger's is that the same release runs on a **client disconnect** and
/// on a **lease expiry** — so a client that simply went away took the process it was looking at
/// with it. A caller attaching to a running service to look at it has no reason to expect that.
///
/// Two things are asserted and the second is the one that would rot silently. The process is
/// still there afterwards, which is the claim. And the result **says so**, because the two endings
/// are opposite, neither is visible from the caller's side, and a model driving this has no other
/// way to know which one it just got.
///
/// The launch half is not here: dbgscope pins it in-process, where the engine's own teardown is
/// the whole mechanism, and terminating a worker on top of that can only take a target away, not
/// keep one. What this adds over that test is the worker termination — the step the original
/// report blamed, and the one nothing below the supervisor can exercise.
#[test]
fn ending_a_session_leaves_a_process_this_server_only_attached_to_running() {
    if !launch_tier() {
        return;
    }
    let mut target = a_process_to_attach_to();
    let mut server = Server::started();
    let session = server.open_session("attach_process", json!({ "pid": target.id() }), TARGET_STEP);
    // A session that is really holding the process, rather than one that failed to attach and
    // would pass this by never having been in a position to kill anything.
    server.tool_data(
        "registers",
        json!({ "session_id": &session, "filter": "pc" }),
        TARGET_STEP,
    );

    let ended = server.call_tool(
        "end_session",
        json!({ "session_id": &session }),
        TARGET_STEP,
    );
    let rendered = text_of(&ended["result"]);
    assert!(
        still_running(&target),
        "`end_session` killed the process this server had only attached to:\n{rendered}"
    );
    // **Both halves say so**, because a structured-aware client forwards `structuredContent` and
    // drops the text: a disposition on one half is a disposition half the clients never see. Same
    // rule as #242's ending, on the op that ends a session deliberately.
    assert!(
        rendered.contains("detached and left running"),
        "the process survived and the text does not say so:\n{rendered}"
    );
    assert_eq!(
        ended["result"]["structuredContent"]["target_left_running"],
        json!(true),
        "the structured half does not say the target was left running: {}",
        ended["result"]["structuredContent"]
    );

    let _ = target.kill();
    let _ = target.wait();
    ran("the attach-teardown tier");
}

/// The same gate for a test that reads a **target's memory** rather than the structure of the dump
/// around it: [`NATIVE_SAMPLE`], the crash paired with this host's architecture.
fn native_sample_tier() -> Option<&'static KernelSample> {
    if std::env::var_os("WINDBG_MCP_SMOKE_DUMP").is_none() {
        skip("set WINDBG_MCP_SMOKE_DUMP=1 to run the debugger tier");
        return None;
    }
    if !std::path::Path::new(NATIVE_SAMPLE.path).exists() {
        skip(&format!("sample dump not found at {}", NATIVE_SAMPLE.path));
        return None;
    }
    Some(&NATIVE_SAMPLE)
}

/// Whether the engine can read the target's memory at all — `nt`'s own base, asked through
/// `execute` rather than through the tools under test, so a regression in `walk_memory` cannot
/// silence the test that catches it.
///
/// Non-obvious, and what [#142](https://github.com/glslang/windbg-mcp/issues/142) turned out to
/// be: a kernel dump's *structure* — bug check, module list, stack — comes out of its own headers
/// and reads anywhere, while following a **pointer** needs `nt`'s symbols to translate the
/// address, so an engine that resolved none answers `0x8007001E` here.
fn engine_reads_target_memory(server: &mut Server, session_id: &str) -> bool {
    let Some(nt) = nt_module(server, session_id) else {
        return false;
    };
    let Some(base) = nt["start"].as_str() else {
        return false;
    };
    // A numeric address, so the read does not itself need a symbol; `nt` is a PE image, so a real
    // read of its first qword carries `MZ`.
    let read = server.call_tool(
        "execute",
        json!({ "session_id": session_id, "command": format!("dq {base} L1") }),
        TARGET_STEP,
    );
    !is_tool_error(&read) && text_of(&read["result"]).contains("905a4d")
}

/// Whether `nt` resolved to a **PDB**, which is what a walk through its *types* needs: the
/// `_EPROCESS` behind `process_name`, and a stack walk that gets past the bug check's own
/// parameters to name a driver.
///
/// Separate from [`engine_reads_target_memory`] because the two fail apart. A host can read a
/// module base and resolve nothing — the ARM64 CI entry is one — and there a stack walk returns
/// frames made of the bug check parameters, which fails an attribution assertion for a reason
/// that has nothing to do with attribution.
///
/// **Both PDB-backed states count.** `dia` is the same PDB read through the Debug Interface Access
/// API, so it answers types and carries an identity exactly as `pdb` does — and the server treats
/// them alike (`worker::with_pdb_identity`). Accepting only `pdb` would stand these tests down on a
/// host that has everything they need, which is the failure this whole gate exists to avoid,
/// pointed the other way.
fn engine_resolves_kernel_symbols(server: &mut Server, session_id: &str) -> bool {
    nt_module(server, session_id).is_some_and(|nt| nt["symbols"] == "pdb" || nt["symbols"] == "dia")
}

/// The `nt` record out of `modules`, which both probes above start from.
///
/// Filtered rather than read out of the whole table, because the table is capped at `limit` rows
/// and `nt` is nowhere in particular in it — a probe that depends on the kernel falling inside the
/// first page of a listing would stand the tier down for a reason that is not about symbols.
fn nt_module(server: &mut Server, session_id: &str) -> Option<Value> {
    let modules = server.tool_data(
        "modules",
        json!({ "session_id": session_id, "filter": "nt" }),
        TARGET_STEP,
    );
    modules["modules"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|m| m["name"] == "nt")
        .cloned()
}

/// Why a test that reads a target stands down. Shared, so the tests cannot drift into disagreeing
/// about what they need.
const NO_TARGET_READS_SKIP: &str = "this engine could not read `nt`'s own base, so nothing behind \
                                    a pointer in this dump can be asserted; the usual cause is \
                                    symbols it could not resolve (issue #142), for want of a \
                                    `symsrv.dll` beside the engine. The dump's own structure \
                                    still reads, which is what the rest of this tier asserts.";

/// Why a test that walks `nt`'s types stands down, which is a weaker condition than reading.
const NO_KERNEL_SYMBOLS_SKIP: &str = "`nt` resolved no PDB on this host, so the `_EPROCESS` and \
                                      the stack walk behind these fields have nothing to read \
                                      types out of (issue #142). Reads that need no types are \
                                      unaffected and are asserted elsewhere in this tier.";

/// A `disassemble` whose `address` could reach the expression evaluator is refused before a
/// session is needed — and the refusal has to be *typed*, because the tool declares an
/// `outputSchema` and a result that skips `structuredContent` is one a schema-checking client
/// rejects. The coverage test above only exercises each tool's session refusal, so this path is
/// asserted here.
#[test]
fn a_malformed_disassemble_address_is_refused_as_a_typed_error() {
    let mut server = Server::started();
    let response = server.call_tool(
        "disassemble",
        json!({ "address": "nt!KeBugCheckEx; .reload" }),
        STEP,
    );
    assert_no_error(&response, "disassemble with a command breaker");
    assert!(
        is_tool_error(&response),
        "an address carrying a command separator has to be refused: {response}"
    );
    let data = &response["result"]["structuredContent"];
    assert_eq!(
        data["status"], "error",
        "the refusal has to carry structured content, as the schema promises: {response}"
    );
    assert_eq!(
        data["error"]["category"], "invalid_argument",
        "and say which kind of failure it is: {response}"
    );
}

/// An open reports what it is doing while it is doing it, in the order it actually happened.
///
/// The milestones are the supervisor's and the worker's — the engine process coming up, the target
/// being claimed, the target being open — and each already decides something: which of them arrived
/// is how an open's failure is told apart from the two others that look identical. This asserts the
/// mapping onto MCP, which is the only part a client can see: one notification per milestone, on
/// the token the call supplied, all of them **before** the result rather than summarised after it.
///
/// Needs a real target because the sequence is the point. A failed open reports the first milestone
/// and stops, which proves the route and not the order.
#[test]
fn an_open_reports_its_milestones_before_it_answers() {
    let Some(dump) = target_tier() else { return };
    let mut server = Server::started();

    let response =
        server.call_tool_watching("open_dump", json!({ "path": dump }), "open-1", TARGET_STEP);
    assert_no_error(&response, "open_dump");
    assert!(
        !is_tool_error(&response),
        "opening the sample dump failed:\n{}",
        text_of(&response["result"])
    );

    // Read after the result, which is what makes "before" an assertion rather than a hope: these
    // were taken off the wire while the call was still outstanding.
    let steps = server.progress_for("open-1");
    let said: Vec<&str> = steps
        .iter()
        .filter_map(|s| s["params"]["message"].as_str())
        .collect();
    assert_eq!(
        said.len(),
        3,
        "an open has three milestones — worker up, target claimed, target open: {steps:?}"
    );
    assert!(said[0].contains("engine worker started"), "{said:?}");
    assert!(said[1].contains("created or claimed"), "{said:?}");
    assert!(said[2].contains("target is open"), "{said:?}");

    // Seconds elapsed, strictly increasing, and no `total` — the budget differs per tool and an
    // opener spends time outside it, so a denominator here would be a number the server cannot
    // actually stand behind.
    let progress: Vec<f64> = steps
        .iter()
        .map(|s| {
            s["params"]["progress"]
                .as_f64()
                .unwrap_or_else(|| panic!("progress must be a number: {s}"))
        })
        .collect();
    assert!(
        progress.windows(2).all(|pair| pair[1] > pair[0]),
        "progress must increase on every notification: {progress:?}"
    );
    assert!(
        steps.iter().all(|s| s["params"]["total"].is_null()),
        "an unknown total is absent, not guessed: {steps:?}"
    );

    let session_id = session_id_of(&response["result"]);
    server.call_tool(
        "end_session",
        json!({ "session_id": session_id }),
        TARGET_STEP,
    );
}

/// And it reaches a client that is not on this machine, which is the whole reason it exists.
///
/// Over stdio an operator could watch the server's stderr; over `--listen` those records are on the
/// far side and everything else this server offers is pull. rmcp routes a progress notification
/// onto the SSE stream the call itself is being answered on, keyed by the token — so what this
/// checks is that the milestone and the result come back together, in that order, on one stream.
///
/// A **failing** open on purpose: one milestone is enough to prove the route, and it costs a worker
/// coming up rather than a dump load that may go to a symbol server — which would put this test's
/// runtime at the mercy of the network for no extra claim.
#[test]
fn a_remote_client_is_told_how_a_call_is_going() {
    if target_tier().is_none() {
        return;
    }
    let mut server = Listener::start(&[]);
    let client = server.initialize();

    let reply = server.call(
        Some(&client),
        "tools/call",
        json!({
            "name": "open_dump",
            "arguments": { "path": r"Z:\no\such.dmp" },
            "_meta": { "progressToken": "remote-1" },
        }),
    );
    assert_eq!(
        reply.status,
        200,
        "the listener refused the call ({}): {}\n--- stderr ---\n{}",
        reply.status,
        reply.body,
        server.stderr()
    );

    let steps = reply.progress("remote-1");
    assert!(
        steps.iter().any(|s| s["params"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("engine worker started"))),
        "no milestone reached the remote client on the call's own stream: {}",
        reply.body
    );
    // The result is still the last thing on the stream, and still the thing `result` finds.
    assert!(
        !reply.result("open_dump")["content"].is_null(),
        "the call is answered as well as narrated: {}",
        reply.body
    );
}

/// A call with nothing to say still says it is running — the half of this that is not a mapping.
///
/// Milestones alone would leave the two longest silences exactly as they were. One is a kernel
/// attach nothing answers: it claims its connection in the first second and then has nothing
/// further to report, ever. The other is every long call that has **no milestones at all** — a pool
/// walk, a `crash_triage`, a batch — and that is the one used here, because it costs twelve seconds
/// of a sleeping debuggee rather than a parked worker holding a UDP port that then has to be waited
/// out of a twenty-second teardown to give it back. The behaviour asserted is the same one.
///
/// The beat is ten seconds and deliberately not tunable: making a production constant
/// test-configurable is a worse trade than the wall clock, and this runs beside the lease tier's
/// own wait rather than after it.
#[test]
fn a_call_with_nothing_to_report_still_reports_that_it_is_running() {
    let Some(dump) = target_tier() else { return };
    let mut server = Server::started();
    let session_id = server.open_session("open_dump", json!({ "path": dump }), TARGET_STEP);

    let steps: Vec<Value> =
        std::iter::repeat_n(json!({ "op": "command", "command": ".sleep 1000" }), 12).collect();
    let response = server.call_tool_watching(
        "debug_batch",
        json!({
            "session_id": session_id,
            "steps": steps,
            "always": [{ "op": "command", "command": "version", "name": "cleanup" }],
        }),
        "slow-1",
        TARGET_STEP,
    );
    assert_no_error(&response, "debug_batch");

    let said: Vec<String> = server
        .progress_for("slow-1")
        .iter()
        .filter_map(|step| step["params"]["message"].as_str().map(str::to_string))
        .collect();
    assert!(
        said.iter().any(|m| m.starts_with("still running")),
        "twelve seconds of silence and the call never said it was alive: {said:?}"
    );
    // And nothing else, because a batch announces no milestones — which is exactly why the beat
    // has to exist for this shape of call.
    assert!(
        said.iter().all(|m| m.starts_with("still running")),
        "a batch has no milestones of its own to report: {said:?}"
    );

    server.call_tool(
        "end_session",
        json!({ "session_id": session_id }),
        TARGET_STEP,
    );
}

/// The end-to-end debugger path, which is what a `dbgscope` or DbgEng change actually moves:
/// open a real dump, read state out of it through several tools, then close it. Everything
/// here is read-only against a checked-in dump — no live target, no writes.
#[test]
fn a_dump_session_opens_reads_and_closes() {
    let Some(dump) = target_tier() else { return };
    let mut server = Server::started();

    let response = server.call_tool("open_dump", json!({ "path": dump }), TARGET_STEP);
    assert_no_error(&response, "open_dump");
    let opened = text_of(&response["result"]);
    assert!(
        !is_tool_error(&response),
        "opening the sample dump failed — DbgEng may be missing or the dump unreadable:\n{opened}"
    );

    // The handle is what routes every later call, so the open has to mint one.
    let session_id = session_id_of(&response["result"]);
    assert!(
        session_id.starts_with("sess-"),
        "session handles are minted as `sess-…`, got `{session_id}` in:\n{opened}"
    );

    let status = server.tool_data("session_status", json!({}), TARGET_STEP);
    let listed_session = status["sessions"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|s| s["session_id"] == session_id.as_str())
        .unwrap_or_else(|| panic!("session_status omitted the open session: {status}"));
    assert_eq!(listed_session["kind"], "dump");
    assert_eq!(listed_session["state"]["state"], "open");
    assert_eq!(listed_session["current"], true);

    // Read-only inspection through the engine thread. These are the calls that break when a
    // DbgEng binding changes shape.
    // The checked-in sample is a *kernel* crash dump, so the kernel image and HAL are the
    // anchors — not `ntdll`. Symbols are not needed: the rows come from the dump's own module
    // list, which keeps this tier runnable offline.
    //
    // Read as module *records*, not as tokens on a rendered row: `lm` lays its columns out from
    // the address width and the longest module name, so the third-token rule this replaces
    // failed on a layout shift and named the wrong cause.
    let modules = server.tool_data(
        "modules",
        json!({ "session_id": session_id, "limit": 2000 }),
        TARGET_STEP,
    );
    let by_name = |want: &str| -> Value {
        modules["modules"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|m| m["name"] == want)
            .cloned()
            .unwrap_or_else(|| panic!("the module list should include `{want}`: {modules}"))
    };
    for expected in ["nt", "hal"] {
        let module = by_name(expected);
        // The addresses are this server's one representation, and they bound a real image.
        let start = address_of(&module["start"]);
        let end = address_of(&module["end"]);
        assert!(
            start != 0 && end > start,
            "`{expected}` should span a real range, got {module}"
        );
        assert!(
            module["symbols"].is_string(),
            "symbol state is a value, not a parenthesis in a line: {module}"
        );
    }
    assert_eq!(
        modules["loaded"].as_u64().unwrap_or_default() as usize,
        modules["modules"].as_array().map_or(0, Vec::len),
        "the count and the list have to be the same walk: {modules}"
    );
    assert_eq!(
        modules["matched"], modules["loaded"],
        "nothing was filtered and nothing was cut, so every count is the same one: {modules}"
    );

    // Registers come back as values too, with the instruction pointer called out.
    let registers = server.tool_data(
        "registers",
        json!({ "session_id": session_id }),
        TARGET_STEP,
    );
    assert_eq!(
        registers["all_registers"], false,
        "the integer set by default"
    );
    let rip = registers["instruction_pointer"]
        .as_str()
        .unwrap_or_else(|| panic!("a stopped dump has an instruction pointer: {registers}"));
    let named = |want: &str| -> Value {
        registers["registers"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|r| r["name"] == want)
            .cloned()
            .unwrap_or_else(|| panic!("`{want}` should be in the integer set: {registers}"))
    };
    assert_eq!(named("rip")["value"], rip, "the two must be the same read");
    for name in ["rsp", "rax", "efl"] {
        let register = named(name);
        assert_eq!(register["kind"], "int", "{register}");
        assert_eq!(
            register["value"].as_str().map(str::len),
            Some(18),
            "one address representation, zero-padded: {register}"
        );
    }
    // The whole bank is opt-in, and it is a superset.
    let everything = server.tool_data(
        "registers",
        json!({ "session_id": session_id, "all": true }),
        TARGET_STEP,
    );
    assert_eq!(everything["all_registers"], true);
    assert!(
        everything["registers"].as_array().map_or(0, Vec::len)
            > registers["registers"].as_array().map_or(0, Vec::len),
        "`all` should add the x87/vector registers and the subregister views"
    );

    // The stack, as records. Shape first, because it holds on a host that resolves nothing: the
    // walk may come back empty there, and an empty stack is still a well-formed answer.
    let stack = server.tool_data(
        "backtrace",
        json!({ "session_id": session_id }),
        TARGET_STEP,
    );
    let frames = stack["frames"]
        .as_array()
        .unwrap_or_else(|| panic!("`backtrace` answered without a `frames` array: {stack}"))
        .clone();
    assert!(
        stack["frames_truncated"].is_boolean(),
        "`frames_truncated` decides whether a short stack is the stack or the cap: {stack}"
    );
    for (position, frame) in frames.iter().enumerate() {
        assert_eq!(
            frame["index"], position as u64,
            "frames are the walk's own order, innermost first: {stack}"
        );
        assert!(
            frame["address"]
                .as_str()
                .is_some_and(|a| a.starts_with("0x")),
            "every frame has an address whatever else it has: {frame}"
        );
        // The coordinate this tool exists for. Either both halves are there or neither is — an
        // `rva` with no `module` is an offset from nothing.
        assert_eq!(
            frame["module"].is_null(),
            frame["rva"].is_null(),
            "`module` and `rva` are one coordinate and travel together: {frame}"
        );
        if let Some(rva) = frame["rva"].as_str() {
            assert!(
                rva.starts_with("0x") && !rva.starts_with("0x0000"),
                "an RVA is unpadded — it is pasted after `module+`, not sorted: {frame}"
            );
        }
    }

    // The *other* half of the coordinate: which build, and which symbols for it. **Outside the
    // target-read gate**, because it needs no target read — `modules` and the engine's own symbol
    // bookkeeping answer this — and the two premises fail apart, so a host that resolves symbols
    // but cannot read a page would otherwise skip a check it can run. `pdb` is documented as
    // absent for a deferred module, which is what the remaining gate is for.
    if engine_resolves_kernel_symbols(&mut server, &session_id) {
        let nt = nt_module(&mut server, &session_id).expect("nt is in the module list");
        let pdb = &nt["pdb"];
        assert!(
            !pdb.is_null(),
            "a module whose symbols resolved has a PDB identity to report: {nt}"
        );
        let guid = pdb["guid"]
            .as_str()
            .unwrap_or_else(|| panic!("`guid` is a string: {pdb}"));
        assert!(
            guid.len() == 32
                && guid
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_lowercase()),
            "a PDB GUID is spelled as a symbol server path spells it — 32 uppercase hex \
             digits, no braces, no dashes: {pdb}"
        );
        // The key is what a caller pastes into `<pdb>/<key>/<pdb>`, and the age goes in
        // **hex**. Read strictly rather than defaulted: a missing `age` defaulted to zero
        // would agree with a key built from zero, and the schema regression would pass.
        let age = pdb["age"]
            .as_u64()
            .unwrap_or_else(|| panic!("`age` is a number: {pdb}"));
        assert_eq!(
            pdb["key"].as_str().unwrap_or_default(),
            format!("{guid}{age:X}"),
            "the key is the guid and the age in hex: {pdb}"
        );
    } else {
        skip(NO_KERNEL_SYMBOLS_SKIP);
    }

    // Reading a *target*: walking a stack means reading the stack's pages, so a host that cannot
    // read `nt`'s base cannot do this and says so rather than asserting on an empty walk.
    if engine_reads_target_memory(&mut server, &session_id) {
        assert!(
            !frames.is_empty(),
            "a kernel crash dump has a crashing stack: {stack}"
        );
        assert!(
            frames.iter().any(|frame| frame["module"] == "nt"),
            "a kernel stack passes through `nt` — the bug check is raised there: {stack}"
        );

        // **The claim the coordinate rests on**: a frame from `crash_triage` and the same frame
        // from `backtrace` name the same place. They share one walk (`worker::walk_attributed`),
        // and this is what says so from outside. `analyze: false` because `!analyze -v` ends with
        // the scope at the target's default — with it off, neither call moves anything, so the two
        // stacks are the same stack rather than two that ought to match.
        let triage = server.tool_data(
            "crash_triage",
            json!({ "session_id": session_id, "analyze": false }),
            TARGET_STEP,
        );
        let triaged = triage["frames"].as_array().cloned().unwrap_or_default();
        assert!(
            !triaged.is_empty(),
            "the same walk answered `crash_triage` with nothing: {triage}"
        );
        for (from_triage, from_backtrace) in triaged.iter().zip(frames.iter()) {
            for field in ["index", "address", "module", "rva", "symbol"] {
                assert_eq!(
                    from_triage[field], from_backtrace[field],
                    "`crash_triage` and `backtrace` disagree about `{field}` on the same frame, so \
                     a coordinate carried between them names a different place:\n{from_triage}\n\
                     {from_backtrace}"
                );
            }
        }

        // The same coordinate, from the third tool that computes one. `disassemble` with no
        // address starts at the current instruction pointer, which is where frame 0 is — so the
        // first instruction and the innermost frame are the same place, and if the two tools
        // describe it differently then nothing downstream can join them.
        let code = server.tool_data(
            "disassemble",
            json!({ "session_id": session_id }),
            TARGET_STEP,
        );
        let instructions = code["instructions"]
            .as_array()
            .unwrap_or_else(|| panic!("`disassemble` answered without instructions: {code}"))
            .clone();
        assert!(
            !instructions.is_empty(),
            "a stopped target has an instruction at its program counter: {code}"
        );
        let innermost = &frames[0];
        let first = &instructions[0];
        assert_eq!(
            first["address"], innermost["address"],
            "`disassemble` starts where the program counter is, which is frame 0:\n{code}"
        );
        assert_eq!(
            first["rva"], innermost["rva"],
            "the same address has one offset into its image, whichever tool computed it:\n{code}"
        );
        assert_eq!(
            first["module"], innermost["module"],
            "`disassemble` and `backtrace` disagree about which image holds the same address:\n\
             {code}"
        );

        for instruction in &instructions {
            assert!(
                instruction["address"]
                    .as_str()
                    .is_some_and(|a| a.starts_with("0x")),
                "every instruction has an address: {instruction}"
            );
            assert!(
                instruction["text"].as_str().is_some_and(|t| !t.is_empty()),
                "and a mnemonic, or it is not an instruction: {instruction}"
            );
            // The *address* form specifically — eight hex digits, a tick, eight more. Not every
            // backtick: MSVC decorates real symbols with them (`` `anonymous namespace' ``) and
            // those are deliberately kept, so rejecting all of them would make this assertion
            // depend on which symbols the host resolved.
            assert!(
                !carries_a_backtick_address(instruction["text"].as_str().unwrap_or_default()),
                "the debugger's backtick address form is normalised out of operands: {instruction}"
            );
            assert!(
                instruction["bytes"]
                    .as_str()
                    .is_some_and(|b| !b.is_empty() && b.chars().all(|c| c.is_ascii_hexdigit())),
                "and an encoding, which is what identifies the build: {instruction}"
            );
        }

        // Asking for one instruction is not a truncated sixteen: `stopped_early` is about the code
        // running out, and a cap the caller set is not that.
        let one = server.tool_data(
            "disassemble",
            json!({ "session_id": session_id, "count": 1 }),
            TARGET_STEP,
        );
        assert_eq!(
            one["instructions"].as_array().map_or(0, Vec::len),
            1,
            "{one}"
        );
        assert_eq!(
            one["stopped_early"], false,
            "a count the caller chose is not the code ending: {one}"
        );
    } else {
        skip(NO_TARGET_READS_SKIP);
    }

    // `threads` is `~`, which DbgEng only implements in user mode — against this kernel dump
    // it fails, and that is the point: a real engine failure has to come back as a *tool*
    // error carrying the engine's message, not as a protocol error or a killed worker thread.
    let unsupported = server.call_tool("threads", json!({ "session_id": session_id }), TARGET_STEP);
    assert_no_error(&unsupported, "threads on a kernel dump");
    assert!(
        is_tool_error(&unsupported),
        "a command DbgEng cannot run here must set isError, got {unsupported}"
    );
    assert!(
        !text_of(&unsupported["result"]).trim().is_empty(),
        "the failure must explain itself: {unsupported}"
    );

    // A handle this server never issued must be refused rather than silently answered against
    // whatever happens to be open — the contract `Sessions::resolve` owns. The refusal says so
    // as a category, which is what lets a client tell it from a debugger error without reading.
    let stale = server.tool_failure(
        "modules",
        json!({ "session_id": "sess-not-a-real-handle" }),
        TARGET_STEP,
    );
    assert_eq!(stale["error"]["category"], "stale_session", "{stale}");
    assert_eq!(stale["error"]["session_id"], "sess-not-a-real-handle");

    let ended = server.tool_data(
        "end_session",
        json!({ "session_id": session_id }),
        TARGET_STEP,
    );
    assert_eq!(ended["session_id"], session_id.as_str());
    assert_eq!(
        ended["released"], true,
        "a dump session lets go of its target: {ended}"
    );

    // After the session is gone, the old handle must not be honoured.
    let after = server.call_tool("modules", json!({ "session_id": session_id }), TARGET_STEP);
    assert!(
        is_tool_error(&after) || !after["error"].is_null(),
        "a handle from an ended session must be refused, got {after}"
    );
}

/// Waits for a record from `session_id`'s **engine worker** whose message contains `needle`, and
/// hands it back.
///
/// Polled rather than read once, and deliberately not on a fixed sleep: the record is made in
/// another process, queued there, mirrored up the protocol channel and filed by the supervisor,
/// none of which is ordered against the tool call that provoked it.
fn wait_for_log_record(server: &mut Server, session_id: &str, needle: &str) -> Value {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let page = server.tool_data(
            "server_log",
            json!({ "session_id": session_id, "limit": 200 }),
            STEP,
        );
        let found = page["records"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|r| r["message"].as_str().is_some_and(|m| m.contains(needle)))
            .cloned();
        if let Some(found) = found {
            return found;
        }
        assert!(
            Instant::now() < deadline,
            "no record containing `{needle}` from session {session_id}'s engine worker reached \
             the client within 15s — the log bridge is not carrying them: {page}"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// An open answers the three questions it is asked every time — which build, where the target's
/// own image is, which bug check — and **does not** print the module table to do it
/// ([#105](https://github.com/glslang/windbg-mcp/issues/105)).
///
/// The size claim is asserted as a comparison against the table itself rather than a line budget
/// pulled from the air: the report has to be shorter than the inventory it used to carry, on
/// whatever dump this tier runs against.
///
/// Each typed field is checked against the tool that owns it — `modules` for the count and the
/// kernel's base, `crash_triage` for the bug check — because the point of the summary is that it
/// saves those calls, and a summary that disagrees with them would cost more than it saves.
#[test]
fn an_open_summarises_the_target_instead_of_listing_its_modules() {
    let Some(dump) = target_tier() else { return };
    let mut server = Server::started();

    let opened = server.tool_data("open_dump", json!({ "path": dump }), TARGET_STEP);
    let session_id = opened["session_id"]
        .as_str()
        .unwrap_or_else(|| panic!("open_dump mints a handle: {opened}"))
        .to_string();
    let summary = opened["summary"].clone();
    assert_eq!(
        summary["kernel_mode"], true,
        "the checked-in sample is a kernel crash dump: {summary}"
    );

    // The inventory, from the tool that owns it. Nothing loads between the two calls in a dump,
    // so the counts are comparable — and they are the same walk, not two renderings of one.
    let modules = server.tool_data(
        "modules",
        json!({ "session_id": session_id, "filter": "nt" }),
        TARGET_STEP,
    );
    let loaded = modules["loaded"].as_u64().unwrap_or_default();
    assert!(
        loaded > 20,
        "this claim is about a table worth not printing; got {loaded} modules"
    );
    assert_eq!(
        summary["modules_loaded"].as_u64(),
        Some(loaded),
        "the open counted {loaded} modules differently: {summary}"
    );
    let kernel = modules["modules"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|module| module["name"] == "nt")
        .unwrap_or_else(|| panic!("a kernel dump loads `nt`: {modules}"));
    assert_eq!(summary["primary_module"]["name"], "nt", "{summary}");
    assert_eq!(
        summary["primary_module"]["start"], kernel["start"],
        "the base an open reports is the one `modules` reports: {summary}"
    );

    // The report is a summary now: shorter than the table it used to be, and still carrying the
    // build line that answers "which Windows is this?".
    let report = opened["report"].as_str().unwrap_or_default();
    assert!(
        (report.lines().count() as u64) < loaded,
        "the report is longer than the {loaded}-module table it replaced:\n{report}"
    );
    assert!(
        report.contains("Kernel base"),
        "`vertarget`'s own answer is what the open is for:\n{report}"
    );
    assert!(
        report.contains("modules"),
        "the table has to be one named call away:\n{report}"
    );

    // The bug check: the same three fields `crash_triage` reports, spelled the same way. Both
    // read `ReadBugCheckData` through one renderer, so a code rendered two ways here would mean a
    // consumer had to know which tool a value came from. `analyze: false` keeps this cheap —
    // `!analyze`'s own conclusions are that tool's business, not the summary's.
    let triage = server.tool_data(
        "crash_triage",
        json!({ "session_id": session_id, "analyze": false }),
        TARGET_STEP,
    );
    assert_eq!(summary["bug_check"], triage["bug_check"], "{summary}");
    assert_eq!(
        summary["bug_check"]["code"], "0x9f",
        "the sample is a 0x9F: {summary}"
    );
    assert!(
        report.contains("0x9f DRIVER_POWER_STATE_FAILURE"),
        "the text says it too, and points at the tool that reads the rest:\n{report}"
    );
    assert!(report.contains("crash_triage"), "{report}");
}

/// What one call costs the caller, per tool, against the checked-in dump.
///
/// The tool surface above is paid once a conversation; this is paid every time, and it is the
/// larger number in practice — a single `modules` on this dump is ~54 KB, roughly a fifth of a
/// whole tool surface, for one question. The test that precedes this one already defends the
/// principle for openers (#105: an open summarises rather than lists); this generalises it to a
/// recorded figure per tool.
///
/// **Not a golden.** Result sizes move with what the runner can resolve — a symbol server that
/// answers turns `deferred` into paths, and `lm` grows a column — so exact bytes would be flaky in
/// the one tier that runs on two architectures. Ceilings with real headroom catch the regression
/// that matters (a tool that starts returning an order of magnitude more) without pinning a number
/// the environment owns.
///
/// **Two ceilings per call, because one number cannot answer both questions.**
///
/// `model` is what a model is charged: `structuredContent` when a tool has one and the text
/// otherwise, since a client that understands structured results forwards that and drops the
/// rendering. It is why `registers` is measured at ~9.8 KB rather than at the 600 bytes of `r`
/// output it also sends — the compact half is the one nobody reads.
///
/// But that is a *forwarding policy*, not protocol. MCP does not oblige a client to discard the
/// text block, and this server is advertised for several clients, so budgeting only the forwarded
/// half leaves the other one unwatched — for the tools with an output schema, that is 31 of them.
/// `wire` closes it: the whole result as it crosses the pipe, which no client's policy affects.
///
/// The gap that needed closing was not merely an absent assertion, it was a self-concealing one.
/// Text is the *denominator* of the ratio rule at the end of this test, so a rendering that doubles
/// **lowers** the ratio while `model` does not move at all — the single check that mentioned text
/// was the one that would have waved it through. Take `registers` from 618 B of text to 6,180 B and
/// 15.9x becomes 1.59x, and every assertion here passed greener than before.
///
/// Per-*channel* ceilings would say which half moved, and are not here: that needs a decision about
/// which forwarding policies this server intends to be good under, which wants measurements from a
/// second client rather than a guess about one
/// ([#150](https://github.com/glslang/windbg-mcp/issues/150)).
#[test]
fn tool_results_stay_within_their_budget() {
    let Some(dump) = target_tier() else { return };
    let mut server = Server::started();

    // Ceilings are ~35-45% over what this dump produces today — looser than the surface budget
    // above, because these numbers depend on the target and on what symbols resolve, where that
    // one depends only on this crate's own source.
    //
    // `crash_triage` and `backtrace` are looser still, and not by oversight: both change *shape*
    // when symbols resolve rather than merely growing — `!analyze -v` prints a different report,
    // and a stack whose frames resolve carries a `symbol` on every one of them where an offline
    // walk carries none. A ceiling tight enough to be interesting on this host would fail on that
    // one, which would make the tier flaky about the environment instead of watchful about the
    // code.
    //
    // `wire` is not `model` plus the text: it is the whole `result` object, so it also carries the
    // content-block scaffolding and JSON escaping — a rendered table's newlines cost two bytes each
    // there and one in `text`. It is measured rather than derived for exactly that reason.
    //
    // Only calls that succeed on a *kernel* dump are listed. `threads` is deliberately absent: `~`
    // is a user-mode question and answers with a tool error here, which would measure the size of
    // a failure.
    let budgets: &[(&str, Value, usize, usize)] = &[
        // tool, args, model ceiling, wire ceiling
        ("open_dump", json!({ "path": dump }), 2_000, 3_200),
        ("session_status", json!({}), 600, 1_200),
        ("crash_triage", json!({}), 6_000, 9_000),
        // The default set stopped carrying the vector bank's 32-bit lanes, which were 44% of it:
        // 9,804 -> 3,480 B model, and the ceiling 13,500 -> 5,000 with them, since a ceiling left
        // at the old figure is what would let them come back unnoticed.
        ("registers", json!({}), 5_000, 6_000),
        ("backtrace", json!({}), 3_000, 4_000),
        ("disassemble", json!({}), 4_000, 6_000),
        // One page of rows rather than the whole table since the row cap landed — the ceiling
        // moved 73,000 -> 24,000 with it, and is the figure that would catch the cap being lost.
        ("modules", json!({}), 24_000, 32_000),
        ("execute", json!({ "command": "lm" }), 27_000, 28_500),
    ];

    let mut rows = Vec::new();
    for (tool, args, model_ceiling, wire_ceiling) in budgets {
        let response = server.call_tool(tool, args.clone(), TARGET_STEP);
        assert_no_error(&response, &format!("tools/call {tool}"));
        let result = &response["result"];
        assert!(
            !is_tool_error(&response),
            "`{tool}` reported a tool error, so its size would measure a failure:\n{}",
            text_of(result)
        );

        let wire = json_bytes(result);
        let text = text_of(result).len();
        let structured = match &result["structuredContent"] {
            Value::Null => None,
            value => Some(json_bytes(value)),
        };
        let model = structured.unwrap_or(text);
        rows.push((*tool, model, wire, text, structured, *model_ceiling));

        assert!(
            model <= *model_ceiling,
            "`{tool}` answered with {model} B of model context, over its {model_ceiling} B \
             budget. Either it started returning more than it used to, or the budget needs \
             raising with a reason recorded in docs/token-budget.md."
        );
        assert!(
            wire <= *wire_ceiling,
            "`{tool}` put {wire} B on the wire, over its {wire_ceiling} B budget, while its \
             model-visible half ({model} B) is inside its own. So the half this client drops \
             grew — which costs every client that does *not* drop it, and is the case the \
             model-visible budget alone cannot see. See docs/token-budget.md."
        );
    }

    // The table is the deliverable when this passes — the assertions only speak up once something
    // has already gone wrong. Unlike the surface budget, this one *is* visible in CI, because the
    // debugger tier's job passes `--nocapture`; without it libtest would swallow the table.
    eprintln!("\n  model     wire     text  struct  ratio  ceiling  tool");
    for (tool, model, wire, text, structured, ceiling) in &rows {
        let (shown, ratio) = match structured {
            Some(bytes) if *text > 0 => (
                bytes.to_string(),
                format!("{:.1}x", *bytes as f64 / *text as f64),
            ),
            Some(bytes) => (bytes.to_string(), "-".to_string()),
            None => ("-".to_string(), "-".to_string()),
        };
        eprintln!("{model:7} {wire:8} {text:8} {shown:>7} {ratio:>6} {ceiling:8}  {tool}");
    }

    // A rule rather than a number, and the one regression class the byte budgets cannot state: a
    // typed answer is supposed to be the *facts* behind a rendering, so it being many times the
    // size of that rendering means it is carrying scaffolding instead — `"kind":"int"` and
    // `"subregister":false` on every row. `registers` is ~16x today and is named in
    // docs/token-budget.md rather than fixed here; this catches the *next* one, not that one.
    //
    // It is a ratio, so it is only safe to read alongside the `wire` ceiling above: on its own, a
    // rendering that grows satisfies it *more*. That is why the wire budget is not optional.
    const WORST_STRUCTURED_RATIO: f64 = 20.0;
    for (tool, _, _, text, structured, _) in &rows {
        let (Some(bytes), true) = (structured, *text > 0) else {
            continue;
        };
        let ratio = *bytes as f64 / *text as f64;
        assert!(
            ratio <= WORST_STRUCTURED_RATIO,
            "`{tool}`'s structured answer is {ratio:.1}x its own text rendering ({bytes} B vs \
             {text} B). A typed result should be the facts behind the rendering, not a larger \
             restatement of it — see src/structured.rs:1651 for the case where this server \
             already made the other call."
        );
    }
}

/// Every row a `modules` listing prints, as `(start, end, name)` read back out of its text.
///
/// Read as records rather than matched as substrings, which is what the rendering being this
/// server's own makes possible ([#120](https://github.com/glslang/windbg-mcp/issues/120)) — and
/// what an earlier version of this tier got wrong, matching the wrong token in a table `lm` had
/// laid out from the address width and the longest module name.
///
/// The two address columns are fixed width (`0x` and sixteen digits, this server's one
/// representation), and the name is what precedes the last two-space gap on the line — so a name
/// carrying a space, or a symbol state rendered as `other (0x2a)`, still parses.
fn listed_rows(text: &str) -> Vec<(String, String, String)> {
    text.lines()
        .filter(|line| line.starts_with("0x"))
        .map(|line| {
            let (start, rest) = line.split_at(18);
            let (end, rest) = rest.trim_start().split_at(18);
            let name = rest.rsplit_once("  ").map_or(rest, |(name, _)| name);
            (start.into(), end.into(), name.trim().into())
        })
        .collect()
}

/// The same rows as the values name them, in the order they are listed: the loaded half, then the
/// unloaded one. A module that has unloaded has no module name at all, so it is named — in both
/// channels — by its image.
fn valued_rows(data: &Value) -> Vec<(String, String, String)> {
    let field = |module: &Value, name: &str| module[name].as_str().unwrap_or_default().to_string();
    ["modules", "unloaded"]
        .iter()
        .flat_map(|half| data[half].as_array().into_iter().flatten())
        .map(|module| {
            let name = match field(module, "name") {
                name if name.is_empty() => field(module, "image_name"),
                name => name,
            };
            (field(module, "start"), field(module, "end"), name)
        })
        .collect()
}

/// `modules { "filter": … }` answers about one driver without the other two hundred rows — and its
/// two halves describe **exactly** the same set of modules.
///
/// That last part is the claim worth a real engine. Both halves are now rendered from one set of
/// `IDebugSymbols3` records ([#120](https://github.com/glslang/windbg-mcp/issues/120)) rather than
/// the text coming from `lm m <pattern>` and the values from a second implementation of its
/// pattern grammar — so the assertion is equality of the two row-for-row, which is the direction
/// the old "every value appears in the text" could not catch: a row the text had and the values
/// did not. It is also what proves no `lm` ran: its own listing carries backtick addresses, a
/// `Browse full module list` line and an `Unloaded modules:` tail, none of which parse as a row
/// here.
#[test]
fn a_module_filter_narrows_both_halves_of_the_answer_alike() {
    let Some(dump) = target_tier() else { return };
    let mut server = Server::started();
    let session_id = server.open_session("open_dump", json!({ "path": dump }), TARGET_STEP);

    let response = server.call_tool("modules", json!({ "session_id": session_id }), TARGET_STEP);
    assert_no_error(&response, "modules");
    let all = response["result"]["structuredContent"].clone();
    let loaded = all["loaded"].as_u64().unwrap_or_default();
    assert!(loaded > 20, "the table this narrows is small: {loaded}");
    assert!(
        all["filter"].is_null(),
        "an unfiltered listing reports no filter: {all}"
    );
    // The whole claim, on the whole table: the rows and the values are one set of records.
    let text = text_of(&response["result"]);
    assert_eq!(
        listed_rows(&text),
        valued_rows(&all),
        "the listing and its values must name exactly the same modules:\n{text}"
    );
    assert!(
        text.contains(&format!("{loaded} module(s) loaded")),
        "the listing says how big it is:\n{text}"
    );
    // The other half of what `lm` prints, carried as values rather than described in prose.
    // Counted from `unloaded_matched` rather than from the rows: the rows are a page of that half,
    // and what a later filter is compared against is how many there were.
    let every_unloaded = all["unloaded_matched"].as_u64().unwrap_or_default();
    assert!(
        every_unloaded > 0,
        "this kernel dump carries unloaded modules; `lm` prints them: {all}"
    );
    for module in all["unloaded"].as_array().into_iter().flatten() {
        assert_eq!(
            module["unloaded"], true,
            "a row in the unloaded half says so on the row too: {module}"
        );
        assert!(
            module["name"].as_str().unwrap_or_default().is_empty(),
            "an unloaded module has no module name — nothing is left to qualify a symbol \
             with — so it is listed by its image: {module}"
        );
        assert!(
            !module["image_name"].as_str().unwrap_or_default().is_empty(),
            "…and that image name is the one thing it must still have: {module}"
        );
    }

    // A bare name is a substring, so this finds `nt` and everything else with `nt` in its name.
    let response = server.call_tool(
        "modules",
        json!({ "session_id": session_id, "filter": "nt" }),
        TARGET_STEP,
    );
    assert_no_error(&response, "modules with a filter");
    let text = text_of(&response["result"]);
    let narrowed = response["result"]["structuredContent"].clone();
    assert_eq!(
        narrowed["filter"], "*nt*",
        "the applied pattern is reported as applied, not as typed: {narrowed}"
    );
    assert_eq!(
        narrowed["loaded"].as_u64(),
        Some(loaded),
        "a narrowed listing still says how big the inventory is: {narrowed}"
    );
    let matched = narrowed["modules"]
        .as_array()
        .expect("a filtered listing is still a list");
    assert!(
        !matched.is_empty() && (matched.len() as u64) < loaded,
        "`nt` should match some of the {loaded} modules, not all and not none: {narrowed}"
    );
    for module in matched {
        let name = module["name"].as_str().unwrap_or_default();
        assert!(
            name.to_ascii_lowercase().contains("nt"),
            "`{name}` does not contain the pattern it was matched by: {narrowed}"
        );
    }
    // The agreement that matters, on a narrowed listing too: not "every value appears somewhere in
    // the text", but the same rows, in the same order, and no others.
    assert_eq!(
        listed_rows(&text),
        valued_rows(&narrowed),
        "a filtered listing and its values must name exactly the same modules:\n{text}"
    );
    assert!(
        matched.iter().any(|module| module["name"] == "nt"),
        "the kernel itself matches `nt`: {narrowed}"
    );
    assert!(
        text.contains(&format!(
            "{} of {loaded}",
            narrowed["matched"].as_u64().unwrap_or_default()
        )),
        "the text says how much of the table this is:\n{text}"
    );

    // `*` is the same listing as no filter at all — the wildcard path and the plain path agree.
    // Asked for whole, because that is the claim: `limit` is a separate decision from `filter`,
    // and two listings cut to the same 64 rows would agree without saying anything.
    let everything = server.tool_data(
        "modules",
        json!({ "session_id": session_id, "filter": "*", "limit": 2000 }),
        TARGET_STEP,
    );
    assert_eq!(
        everything["modules"].as_array().map_or(0, Vec::len) as u64,
        loaded,
        "`*` matches every module: {everything}"
    );

    // A pattern that matches nothing is not an error, and must not be silence either: a listing
    // with no rows in it reads as a target with no modules.
    let response = server.call_tool(
        "modules",
        json!({ "session_id": session_id, "filter": "nosuchmoduleanywhere" }),
        TARGET_STEP,
    );
    assert_no_error(&response, "modules with a filter that matches nothing");
    assert!(
        !is_tool_error(&response),
        "no match is an answer, not a failure: {response}"
    );
    let empty = response["result"]["structuredContent"].clone();
    assert_eq!(
        empty["modules"].as_array().map(Vec::len),
        Some(0),
        "{empty}"
    );
    assert_eq!(empty["loaded"].as_u64(), Some(loaded), "{empty}");
    assert_eq!(
        empty["unloaded"].as_array().map(Vec::len),
        Some(0),
        "neither half matched, which is what makes this the empty answer: {empty}"
    );
    let text = text_of(&response["result"]);
    assert!(
        text.contains("*nosuchmoduleanywhere*") && text.contains("Nothing matches"),
        "a listing that found nothing has to say so:\n{text}"
    );
    assert!(
        !text.contains("unloaded"),
        "and says nothing about unloaded modules when none matched either:\n{text}"
    );
    assert!(
        listed_rows(&text).is_empty(),
        "no rows either — a heading over nothing is not an empty answer:\n{text}"
    );

    // A filter that matches **only unloaded** modules. The engine tracks those in a second list,
    // and a listing that carried the loaded one alone would answer "nothing matched" where there
    // are rows to show. On the checked-in sample `nvhda` is exactly that case: no loaded module,
    // and a pile of unloaded `nvhda64v.sys`.
    let response = server.call_tool(
        "modules",
        json!({ "session_id": session_id, "filter": "nvhda" }),
        TARGET_STEP,
    );
    assert_no_error(&response, "modules filtered to an unloaded driver");
    let gone = response["result"]["structuredContent"].clone();
    let text = text_of(&response["result"]);
    assert_eq!(
        gone["modules"].as_array().map(Vec::len),
        Some(0),
        "`nvhda64v` is unloaded in this dump, so no *loaded* module matches: {gone}"
    );
    let matched_unloaded = gone["unloaded"]
        .as_array()
        .expect("the unloaded half is a list");
    assert!(
        !matched_unloaded.is_empty()
            && gone["unloaded_matched"].as_u64().unwrap_or_default() < every_unloaded,
        "the filter narrows the unloaded half too, to some of the {every_unloaded} rows: {gone}"
    );
    for module in matched_unloaded {
        let image = module["image_name"].as_str().unwrap_or_default();
        assert!(
            image.to_ascii_lowercase().contains("nvhda"),
            "`{image}` does not match the pattern it was matched by: {gone}"
        );
    }
    // The same agreement demanded of the loaded half — and this is the half that could only ever
    // be checked loosely while the rows were `lm`'s: these images are the rows, and the only rows.
    assert_eq!(
        listed_rows(&text),
        valued_rows(&gone),
        "the unloaded half's rows and values must match exactly:\n{text}"
    );
    assert!(
        text.contains("Unloaded modules"),
        "and stay distinguishable from the loaded half in the text as well:\n{text}"
    );
    assert!(
        text.contains(&format!(
            "{} that have since **unloaded** do",
            gone["unloaded_matched"].as_u64().unwrap_or_default()
        )),
        "matching only unloaded modules is a finding, not a miss:\n{text}"
    );

    // The one refusal left. There used to be three more, all of them there to keep this server's
    // matcher in step with the one inside `lm m`: a `;` that would have ended the command the
    // filter was interpolated into, WinDbg's wider wildcard grammar (`nt[fd]*`, `n\t*`), a space
    // — which `lm m` reads as the start of its own options — and a character outside the range
    // the two folded case alike in. No command and no second matcher, so each of those is now
    // just a character, matched as itself; the loop below is what says so.
    let refused = server.tool_failure(
        "modules",
        json!({ "session_id": session_id, "filter": "  " }),
        TARGET_STEP,
    );
    assert_eq!(
        refused["error"]["category"], "invalid_argument",
        "a filter that narrows by nothing is still an argument fault: {refused}"
    );
    assert!(
        refused["error"]["message"]
            .as_str()
            .is_some_and(|message| !message.is_empty()),
        "a refusal has to say what is wrong: {refused}"
    );

    // What those refusals were protecting: each of these is a pattern with no module named by it,
    // answered as an empty listing rather than as an error — and, crucially, as an empty listing
    // in *both* channels. `nt; .detach` is the one to read twice: it reaches no command, and the
    // session is still the dump it was afterwards. The last is the one the *rendering* has to hold
    // rather than the engine: a filter is quoted into the listing, and this one is shaped to add a
    // row to it — a module in the text that the values do not have, which is the property this
    // whole change is for. The pattern is printed with its newline escaped, so it stays one line.
    for filter in [
        "nt; .detach",
        "nt[fd]*",
        r"n\t*",
        "nt v",
        "nté",
        "zzz\n0xfffff80389200000  0xfffff8038a650000  smuggled  pdb",
    ] {
        let response = server.call_tool(
            "modules",
            json!({ "session_id": session_id, "filter": filter }),
            TARGET_STEP,
        );
        assert_no_error(&response, "modules with a literal-matching filter");
        assert!(
            !is_tool_error(&response),
            "`{filter}` is a pattern that matches nothing, not a fault: {response}"
        );
        let data = response["result"]["structuredContent"].clone();
        let text = text_of(&response["result"]);
        assert_eq!(
            valued_rows(&data),
            Vec::<(String, String, String)>::new(),
            "no module on this target is named `{filter}`: {data}"
        );
        assert!(
            listed_rows(&text).is_empty() && text.contains("Nothing matches"),
            "…and the text says the same, rather than showing rows the values do not have:\n{text}"
        );
    }

    // The session is still the dump it was — nothing above reached a command.
    let after = server.tool_data("modules", json!({ "session_id": session_id }), TARGET_STEP);
    assert_eq!(after["loaded"].as_u64(), Some(loaded), "{after}");
}

/// `modules { "refresh": true }` resynchronises the debugger's inventory with the target before
/// listing it, asked as the **first** call on a freshly opened session
/// ([#85](https://github.com/glslang/windbg-mcp/issues/85)).
///
/// That ordering is the test, not decoration. DbgEng's module list is built from the loads the
/// debugger *saw*, so on a live kernel attach it starts at whatever it can read at connect time
/// and a driver loaded beforehand is simply absent — which read as "the challenge driver is not
/// loaded" on the MessageManager target while the driver was serving IOCTLs. Asking on a *dump*
/// cannot reproduce that gap (a dump carries its own complete module list), so what this tier
/// claims is the other half, and it is the half that would break silently: the refresh **runs
/// against a real engine, succeeds, and costs the listing nothing** — same modules, same counts,
/// reported as a resynchronisation that found the inventory already current. The live tier below
/// covers the gap itself, on a target that has one.
///
/// The default call is checked in the same breath, because "cheap and backward compatible" is a
/// claim about the *absence* of a field: an answer that started carrying `refresh` on every call
/// would tell every caller a refresh had happened when none had.
#[test]
fn a_module_listing_can_resynchronise_the_inventory_before_it_lists_it() {
    let Some(dump) = target_tier() else { return };
    let mut server = Server::started();
    let session_id = server.open_session("open_dump", json!({ "path": dump }), TARGET_STEP);

    // First call on the session, before anything else has made the engine look at a module.
    let response = server.call_tool(
        "modules",
        json!({ "session_id": session_id, "refresh": true, "filter": "nt" }),
        TARGET_STEP,
    );
    assert_no_error(&response, "modules with refresh");
    assert!(
        !is_tool_error(&response),
        "a refresh on an open target is ordinary work, not a fault: {response}"
    );
    let refreshed = response["result"]["structuredContent"].clone();
    let text = text_of(&response["result"]);
    assert_eq!(
        refreshed["refresh"]["synchronized"],
        json!(true),
        "the engine resynchronised, and the field is how a caller knows:\n{text}\n{refreshed}"
    );
    assert!(
        refreshed["refresh"]["error"].is_null(),
        "a synchronisation that worked carries no reason: {refreshed}"
    );
    // A dump's own module list is complete when it opens, so the refresh has nothing to find —
    // and must not *lose* anything either, which is the failure this pins.
    let (before, loaded) = (
        refreshed["refresh"]["before"].as_u64(),
        refreshed["loaded"].as_u64(),
    );
    assert_eq!(
        before, loaded,
        "a dump opens with its inventory already complete, so a refresh changes nothing: \
         {refreshed}"
    );
    assert!(
        loaded.unwrap_or_default() > 20,
        "…and that inventory is the whole table, not an empty one: {refreshed}"
    );
    assert!(
        text.contains("Inventory resynchronised"),
        "the text says a refresh ran, above the listing it qualifies:\n{text}"
    );
    // The rows are still the rows: a refresh is a step before the listing, not a different answer.
    assert_eq!(
        listed_rows(&text),
        valued_rows(&refreshed),
        "a refreshed listing agrees with its own values like any other:\n{text}"
    );
    assert!(
        refreshed["matched"].as_u64().unwrap_or_default() > 0,
        "`nt` matches something on this target with or without a refresh: {refreshed}"
    );

    // And the default, on the same session: the same inventory, and not one word about a refresh
    // nobody asked for.
    let plain = server.tool_data(
        "modules",
        json!({ "session_id": session_id, "filter": "nt" }),
        TARGET_STEP,
    );
    assert!(
        plain["refresh"].is_null(),
        "a call that asked for no refresh must not report one: {plain}"
    );
    assert_eq!(
        plain["loaded"].as_u64(),
        loaded,
        "the refresh left the engine holding what it found: {plain}"
    );
    assert_eq!(
        valued_rows(&plain),
        valued_rows(&refreshed),
        "and the same modules, row for row"
    );
    println!(
        "refresh on {dump}: {}",
        text.lines().next().unwrap_or_default()
    );

    server.tool_data(
        "end_session",
        json!({ "session_id": session_id }),
        TARGET_STEP,
    );
}

/// **A default register set is the integer registers, on whatever architecture this host is.**
///
/// The `all` argument documents the default as excluding the x87 and vector registers, and it did
/// not: DbgEng exposes a vector register twice — `xmm0` as 128 bits of `bytes`, and `xmm0/0` …
/// `xmm0/3` as four 32-bit pseudo-registers that carry no subregister flag — so 64 of the x64
/// sample's 123 default rows were the vector bank, and 44% of the answer's bytes with them.
///
/// The rule that excludes them tests the **name** for the `/` DbgEng puts in a slice's name, which
/// is the only signal the register description offers. That makes it worth an assertion against a
/// real engine rather than a unit test alone, and worth making it against **this host's own**
/// architecture.
///
/// **What that turned up, and why this test asserts less than it might.** On ARM64 the convention
/// does not exist — no register name carries a `/` — but the same *class* of row does: the default
/// set there carries `w0`–`w30`, the 32-bit views of `x0`–`x28`/`fp`/`lr`, which are subregister
/// views by any reading of the argument's own documentation and which DbgEng does not flag as such
/// either (it flags nine `cpsr` bits and nothing else). So the engine's `DEBUG_REGISTER_SUB_REGISTER`
/// is unreliable on both architectures in different ways, and this fix addresses the x64 half.
///
/// The ARM64 half was then measured and declined (`FOLLOWUPS.md` item 35): the rest of the register
/// description says nothing the flag does not, and the obvious second name rule — "drop `w<N>` where
/// `x<N>` exists" — leaves `w29` and `w30` behind, because the engine enumerates `x0`–`x28` and then
/// `fp`, `lr`. So this test deliberately does not assert the ARM64 shape either way: it is a
/// measured cost, not a settled contract.
#[test]
fn a_default_register_set_leaves_out_the_vector_bank_on_this_architecture() {
    let Some(sample) = native_sample_tier() else {
        return;
    };
    let mut server = Server::started();
    let session_id = server.open_session("open_dump", json!({ "path": sample.path }), TARGET_STEP);

    let names = |listing: &Value| -> Vec<String> {
        listing["registers"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|r| r["name"].as_str().map(str::to_string))
            .collect()
    };

    let default = server.tool_data(
        "registers",
        json!({ "session_id": session_id }),
        TARGET_STEP,
    );
    let plain = names(&default);
    assert!(
        !plain.is_empty(),
        "a stopped target has registers: {default}"
    );
    assert_eq!(default["all_registers"], false, "{default}");
    let slices: Vec<_> = plain.iter().filter(|name| name.contains('/')).collect();
    assert!(
        slices.is_empty(),
        "the default set is the integer registers; these are pieces of wider ones: {slices:?}"
    );
    assert!(
        default["registers"]
            .as_array()
            .into_iter()
            .flatten()
            .all(|r| r["subregister"].is_null()),
        "and no row spends bytes saying it is not a view of another: {default}"
    );

    let every = server.tool_data(
        "registers",
        json!({ "session_id": session_id, "all": true }),
        TARGET_STEP,
    );
    let all = names(&every);
    assert!(
        all.len() > plain.len(),
        "`all` returns everything the engine knows, which is more: {} against {}",
        all.len(),
        plain.len()
    );
    // The property that makes the default a *narrowing* rather than a different answer: everything
    // in it is in `all` too. This catches the two answers being computed by rules that have drifted
    // apart — a row the default has and `all` does not — and **not** a register dropped from both,
    // which leaves the subset relation intact. That case needs an oracle from outside the pair, and
    // it is the assertion below (reported by chatgpt-codex-connector on #188).
    let missing: Vec<_> = plain.iter().filter(|name| !all.contains(name)).collect();
    assert!(
        missing.is_empty(),
        "the default has to be a subset of `all`; these are in one and not the other: {missing:?}"
    );

    // The oracle: whatever else a filter drops, it may not drop the two registers every caller of
    // this tool came for. Named per architecture rather than derived, because deriving them from
    // the answer is what a broken filter would break — and both names are checked so this test
    // stays honest on whichever host runs it.
    for wanted in [["rip", "pc"], ["rsp", "sp"]] {
        assert!(
            wanted
                .iter()
                .any(|name| plain.iter().any(|got| got == name)),
            "a default register set that has lost {wanted:?} is not a narrowing, it is a hole — \
             and `all` would still be a superset of it. Got: {plain:?}"
        );
    }
}

/// **What one `modules` call costs the caller, and what a cut listing still tells them.**
///
/// The whole table was this server's largest single answer — ~54 KB of JSON for "which drivers are
/// loaded", a fifth of a whole tool surface, and on a local model a turn of prefill measured in
/// minutes rather than the window it also fills (`docs/local-model.md`). So the default listing is
/// a page of it, and the three things that keeps honest are asserted here against a real dump:
/// the totals do not move, the text says the rows are a page, and the whole table is still one
/// argument away.
///
/// The saving is asserted as a *ratio* rather than as bytes, since the byte figures move with what
/// the runner resolves — a PDB identity per row is the largest thing on a row — while the shape of
/// the claim does not. Both are printed under `--nocapture`, against the same dump
/// `docs/token-budget.md` records its baseline on, so the page and that table read together.
#[test]
fn a_module_listing_is_a_page_of_the_table_and_says_so() {
    let Some(dump) = target_tier() else { return };
    let mut server = Server::started();
    let session_id = server.open_session("open_dump", json!({ "path": dump }), TARGET_STEP);

    let whole = server.call_tool(
        "modules",
        json!({ "session_id": session_id, "limit": 2000 }),
        TARGET_STEP,
    );
    assert_no_error(&whole, "modules with the cap raised");
    let table = whole["result"]["structuredContent"].clone();
    let loaded = table["loaded"].as_u64().unwrap_or_default();
    assert!(
        loaded > 64,
        "this claim is about a table that does not fit in one page; got {loaded} modules"
    );
    assert_eq!(
        table["modules"].as_array().map_or(0, Vec::len) as u64,
        loaded,
        "the cap raised past the table is the whole table: {table}"
    );

    let page = server.call_tool("modules", json!({ "session_id": session_id }), TARGET_STEP);
    assert_no_error(&page, "modules");
    let first = page["result"]["structuredContent"].clone();
    let rows = |listing: &Value| -> usize {
        ["modules", "unloaded"]
            .iter()
            .map(|half| listing[half].as_array().map_or(0, Vec::len))
            .sum()
    };
    assert_eq!(
        rows(&first),
        64,
        "a caller who names no `limit` gets one page of rows, counted across both halves: {first}"
    );
    assert!(
        first["unloaded"]
            .as_array()
            .is_some_and(|half| !half.is_empty()),
        "and the half that can name a driver no longer there is not squeezed out of it by the \
         two hundred loaded rows: {first}"
    );

    // The counts are of the target, not of the page — the one thing a truncated inventory must
    // not get wrong, because a caller reads them as "what is loaded".
    assert_eq!(first["loaded"].as_u64(), Some(loaded), "{first}");
    assert_eq!(
        first["matched"].as_u64(),
        Some(loaded),
        "nothing was filtered, so every loaded module matched: {first}"
    );
    assert_eq!(
        first["unloaded_matched"], table["unloaded_matched"],
        "and the unloaded half is counted the same way in both: {first}"
    );

    // The text says the same thing, and names the argument that undoes it.
    let text = text_of(&page["result"]);
    assert!(
        text.contains(&format!("{loaded} module(s) loaded")),
        "the inventory is still what the note reports:\n{text}"
    );
    assert!(
        // Whether the unloaded half was cut as well depends on how many this dump carries, and
        // the sentence names both halves only when both were — so the assertion is on the count
        // that is always there, which is the loaded rows this page actually printed.
        text.contains(&format!(
            "Showing the first {}",
            first["modules"].as_array().map_or(0, Vec::len)
        )) && text.contains(&format!(
            "`limit: {}` returns all of them",
            loaded + table["unloaded_matched"].as_u64().unwrap_or_default()
        )),
        "a listing that stops short says so, and names the value that returns everything — the \
         count above it is the one that would fall short:\n{text}"
    );
    assert_eq!(
        listed_rows(&text),
        valued_rows(&first),
        "the page's rows and its values are still one set of records:\n{text}"
    );

    // What it bought, in both channels the budget test above measures: what a model is charged
    // (`structuredContent`, which replaces the text for a client that reads it) and what every
    // client pays on the wire.
    let (paged, everything) = (json_bytes(&page["result"]), json_bytes(&whole["result"]));
    let (paged_model, model_everything) = (json_bytes(&first), json_bytes(&table));
    assert!(
        paged * 2 < everything,
        "the default listing has to be a fraction of the table it is a page of, or the cap is \
         costing callers an argument for nothing: {paged} B against {everything} B"
    );
    // Printed, because this is the figure the cap exists for and it is different on every host —
    // the budget table above records what a call costs, and this records what it saved.
    eprintln!(
        "\n  modules: {paged_model} B model / {paged} B wire for the default page, against \
         {model_everything} B / {everything} B for all {loaded} modules\n"
    );

    // And an explicit `limit` is honoured on the way down as well as up, so a caller working in a
    // very small window can ask for a very small answer.
    let five = server.tool_data(
        "modules",
        json!({ "session_id": session_id, "limit": 5 }),
        TARGET_STEP,
    );
    assert_eq!(rows(&five), 5, "{five}");
    assert_eq!(
        five["matched"].as_u64(),
        Some(loaded),
        "a smaller page is still a page of the same table: {five}"
    );
}

/// An address that is unmapped on **any** Windows target, so a hole needs no knowledge of this
/// particular dump.
///
/// The low 64 KB of every process is permanently reserved — that is what makes a null-pointer
/// dereference an access violation rather than a read — so nothing is ever mapped here, in user
/// mode or in the user half of a kernel target's address space.
const UNMAPPED: &str = "0x1000";

/// The claim [#103](https://github.com/glslang/windbg-mcp/issues/103) is about, made against a
/// real engine: a walk with a hole in it comes back with the hole *marked* and everything after it
/// still walked.
///
/// The contrast is the point, so it is asserted rather than described. The same dereference
/// through `execute` — which is how this was done before — fails outright, and a `.for` loop
/// around it takes the whole script down with it, leaving no rows and no iteration number. That
/// failure is what cost a MessageManager session an afternoon of hand-bisecting a 512-entry table.
///
/// Everything here is read-only against the checked-in dump, and the one address it assumes
/// anything about is [`UNMAPPED`], which is unmapped on every Windows target there is.
#[test]
fn a_walk_marks_what_it_cannot_read_and_keeps_going() {
    let Some(sample) = native_sample_tier() else {
        return;
    };
    let mut server = Server::started();
    let session_id = server.open_session("open_dump", json!({ "path": sample.path }), TARGET_STEP);
    if !engine_reads_target_memory(&mut server, &session_id) {
        skip(NO_TARGET_READS_SKIP);
        return;
    }

    // The two anchors of a kernel dump's module list, used as addresses that certainly *are*
    // readable — the alternative is a literal, and a literal would make this test a fact about
    // one file.
    let mut base = |want: &str| -> String {
        // Asked for by name rather than looked for in the whole table, which is a page of rows
        // now — and `nt` is nowhere in particular in it.
        let modules = server.tool_data(
            "modules",
            json!({ "session_id": session_id, "filter": want }),
            TARGET_STEP,
        );
        modules["modules"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|m| m["name"] == want)
            .and_then(|m| m["start"].as_str())
            .unwrap_or_else(|| panic!("the module list should include `{want}`: {modules}"))
            .to_string()
    };
    let (nt, hal) = (base("nt"), base("hal"));

    // The old way, first, so the improvement is measured rather than claimed: one unreadable
    // dereference is a failed call with nothing in it.
    let old = server.call_tool(
        "execute",
        json!({ "session_id": session_id, "command": format!("? poi({UNMAPPED})") }),
        TARGET_STEP,
    );
    assert!(
        is_tool_error(&old),
        "the premise of #103 is that this fails; if it no longer does, this test is measuring \
         nothing:\n{}",
        text_of(&old["result"])
    );

    // The new way: the same address, in the middle of a list, is one row.
    let walk = server.tool_data(
        "walk_memory",
        json!({
            "session_id": session_id,
            "addresses": [nt, UNMAPPED, hal],
        }),
        TARGET_STEP,
    );
    assert_eq!(walk["mode"], "list", "{walk}");
    assert_eq!(
        walk["walked"], 3,
        "the hole must not shorten the walk: {walk}"
    );
    assert_eq!(walk["unreadable"], 1, "{walk}");
    assert_eq!(walk["stopped"]["reason"], "complete", "{walk}");
    let node = |i: usize| walk["nodes"][i].clone();
    assert_eq!(node(1)["readable"], false, "{walk}");
    // `get`, not indexing: indexing a missing key also yields `Null`, so the weaker assertion
    // would pass against a payload that had dropped the field entirely — and an omitted key makes
    // "the debugger could not read this" and "this object is malformed" the same observation for
    // every client. The value is a null, and it is *there*.
    assert!(
        node(1)["fields"][0]
            .get("value")
            .is_some_and(Value::is_null),
        "an unreadable value is an explicit null, not a missing key and not zero: {walk}"
    );
    for i in [0, 2] {
        assert_eq!(node(i)["readable"], true, "{walk}");
        // Both anchors are PE images, so the qword at their base carries `MZ` — which is what
        // makes this a real read of the target rather than an address echoed back.
        let value = address_of(&node(i)["fields"][0]["value"]);
        assert_eq!(
            value & 0xffff,
            0x5a4d,
            "node {i} should read the `MZ` at a module base: {walk}"
        );
    }

    // Array mode over the same header, with narrow fields: `e_magic` is two bytes and `e_lfanew`
    // four, and reading them at their own widths is what a caller does to a real structure.
    let header = server.tool_data(
        "walk_memory",
        json!({
            "session_id": session_id,
            "start": nt,
            "stride": 0,
            "count": 1,
            "fields": [
                { "name": "e_magic", "offset": 0, "size": 2 },
                { "name": "e_lfanew", "offset": 0x3c, "size": 4 },
            ],
        }),
        TARGET_STEP,
    );
    assert_eq!(header["mode"], "array", "{header}");
    assert_eq!(
        address_of(&header["nodes"][0]["fields"][0]["value"]),
        0x5a4d,
        "{header}"
    );
    let lfanew = address_of(&header["nodes"][0]["fields"][1]["value"]);
    assert!(
        (0x40..0x400).contains(&lfanew),
        "`e_lfanew` should point at the PE header just past the DOS stub, got {lfanew:#x}: \
         {header}"
    );

    // A chain is the one traversal a hole really does stop — the address after it lived in the
    // bytes that would not read — and it has to say which node rather than come back empty.
    let chain = server.tool_data(
        "walk_memory",
        json!({
            "session_id": session_id,
            "start": UNMAPPED,
            "next_offset": 0,
        }),
        TARGET_STEP,
    );
    assert_eq!(chain["mode"], "chain", "{chain}");
    assert_eq!(
        chain["walked"], 1,
        "the node it could not read is still a row: {chain}"
    );
    assert_eq!(chain["stopped"]["reason"], "unreadable_link", "{chain}");
    assert_eq!(
        chain["stopped"]["at"], "0x0000000000001000",
        "the stop names the node, so a caller knows where to look: {chain}"
    );
    // Nothing read at all is the one answer this tool cannot make on its own, so the engine's
    // reason rides along with it.
    assert!(
        chain["note"].as_str().is_some_and(|n| !n.is_empty()),
        "a walk that read nothing has to explain itself: {chain}"
    );

    server.tool_data(
        "end_session",
        json!({ "session_id": session_id }),
        TARGET_STEP,
    );
}

/// `crash_triage` against the checked-in bug check — a `0x9F DRIVER_POWER_STATE_FAILURE` on x64,
/// a `0xFC ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY` on ARM64.
///
/// The claim is the one the tool exists for and the one no unit test can make: the fields come
/// off a real dump through a real engine. `src/triage.rs` proves the assembly over scripted
/// values; this proves that `ReadBugCheckData`, the stack walk, the per-frame module attribution
/// and the `!analyze` fallback all reach that assembly with something in them.
///
/// Which crash it is asserted against comes from [`NATIVE_SAMPLE`], because the claim is about the
/// tool and the sample is whichever real crash this host can read. Everything specific to one of
/// them is in that record and nowhere else in this body.
///
/// Deliberately asserts on the *engine-read* half plus the shape of the rest: the sample's
/// parameters and its `nt`-topped stack are facts about the file, while what `!analyze` concludes
/// depends on whether this host has `winext\ext.dll` beside the engine — so the analysis is
/// checked for being coherent, not for having run.
#[test]
fn a_bug_check_is_triaged_into_its_fields() {
    let Some(sample) = native_sample_tier() else {
        return;
    };
    let mut server = Server::started();

    let response = server.call_tool("open_dump", json!({ "path": sample.path }), TARGET_STEP);
    assert_no_error(&response, "open_dump");
    let session_id = session_id_of(&response["result"]);
    if !engine_reads_target_memory(&mut server, &session_id) {
        skip(NO_TARGET_READS_SKIP);
        return;
    }
    if !engine_resolves_kernel_symbols(&mut server, &session_id) {
        skip(NO_KERNEL_SYMBOLS_SKIP);
        return;
    }

    let triage = server.tool_data(
        "crash_triage",
        json!({ "session_id": session_id }),
        TARGET_STEP,
    );

    // The bug check itself, read through `ReadBugCheckData` rather than off any text.
    assert_eq!(triage["bug_check"]["code"], sample.bug_check, "{triage}");
    assert_eq!(
        triage["bug_check"]["name"], sample.bug_check_name,
        "the name comes from this build's table, so it does not need `!analyze`: {triage}"
    );
    let parameters = triage["bug_check"]["parameters"]
        .as_array()
        .expect("four parameters");
    assert_eq!(parameters.len(), 4, "{triage}");
    assert_eq!(parameters[0], sample.first_parameter, "{triage}");
    for parameter in parameters {
        assert_eq!(
            parameter.as_str().map(str::len),
            Some(18),
            "one address representation, zero-padded: {triage}"
        );
    }

    // The stack walk, attributed to modules from their load bases.
    let frames = triage["frames"].as_array().expect("some frames");
    assert!(
        !frames.is_empty(),
        "a crash dump has a stack to walk: {triage}"
    );
    assert!(frames.len() <= 16, "the default frame cap is 16: {triage}");
    // The sample's stack is well short of the cap, so nothing was cut off. Worth asserting because
    // the flag is established by walking one frame *past* the cap and discarding it: a stack that
    // merely reaches the cap exactly must not report as truncated, or an absent `faulting_frame`
    // reads as an artefact of the cap rather than as a fact about the crash.
    assert_eq!(
        triage["frames_truncated"], false,
        "a stack shorter than the cap was not truncated: {triage}"
    );
    // Asking for exactly as many frames as the stack has is the case an equality test on the
    // returned count gets wrong — it is complete, not capped.
    let exact = server.tool_data(
        "crash_triage",
        json!({ "session_id": session_id, "analyze": false, "frames": frames.len() }),
        TARGET_STEP,
    );
    assert_eq!(
        exact["frames"].as_array().map_or(0, Vec::len),
        frames.len(),
        "{exact}"
    );
    assert_eq!(
        exact["frames_truncated"], false,
        "a walk that exactly fills its cap is complete, not truncated: {exact}"
    );
    // One frame short of the stack really is truncated, which is what keeps the check above from
    // passing for the trivial reason that nothing ever reports truncation.
    let capped = server.tool_data(
        "crash_triage",
        json!({ "session_id": session_id, "analyze": false, "frames": frames.len() - 1 }),
        TARGET_STEP,
    );
    assert_eq!(
        capped["frames_truncated"], true,
        "a walk that stopped short of the end has to say so: {capped}"
    );
    let top = &frames[0];
    assert_eq!(top["index"], 0, "{triage}");
    assert_eq!(
        top["module"], "nt",
        "every bug check is topped by the kernel: {triage}"
    );
    // The RVA is an offset within the image, so it is unpadded and short — the distinction from
    // `address`, which is a padded 16-digit target address.
    let rva = top["rva"].as_str().expect("the top frame has an RVA");
    assert!(rva.starts_with("0x") && rva.len() < 18, "{triage}");
    assert_eq!(top["address"].as_str().map(str::len), Some(18), "{triage}");
    // The frames are consecutive from the innermost outwards.
    for (position, frame) in frames.iter().enumerate() {
        assert_eq!(frame["index"], position as u64, "{triage}");
    }

    // Neither sample is a driver bug, so what is asserted is the *rule* rather than an outcome:
    // no frame outside the kernel means no `faulting_frame` and a reason instead of a blamed
    // `nt!KeBugCheckEx`; a frame that does qualify — the ARM64 sample's is the user-mode address
    // that was executed, which belongs to no loaded module — is never the kernel itself.
    // Naming a driver is [`a_driver_crash_names_the_driver_frame_an_all_kernel_walk_would_miss`]'s claim.
    if triage["faulting_frame"].is_null() {
        let note = triage["faulting_frame_note"]
            .as_str()
            .unwrap_or_else(|| panic!("no faulting frame has to come with a reason: {triage}"));
        assert!(note.contains("kernel image"), "{triage}");
    } else {
        let faulting = &triage["faulting_frame"];
        assert_ne!(
            faulting["module"], "nt",
            "the faulting frame is the first one *outside* the kernel: {triage}"
        );
    }

    // `PROCESS_NAME`, read out of the current `_EPROCESS` — the sample's own crashing process, and
    // the check that matters is that it is *not* the kernel image, which is what the engine's own
    // `GetCurrentProcessExecutableName` answers on a kernel target for every process there has
    // ever been.
    assert_eq!(
        triage["process_name"], sample.process_name,
        "the crashing process comes from the EPROCESS, not from the loaded kernel image: {triage}"
    );

    // `!analyze` needs `winext\ext.dll` beside the engine, which CI may not have. Either way the
    // answer has to be coherent: it ran and says which spelling worked, or it did not and says
    // why — never silently absent.
    let analysis = &triage["analysis"];
    if analysis["ran"] == true {
        let command = analysis["command"]
            .as_str()
            .expect("the command that worked");
        assert!(
            command == "!analyze -v" || command == "!ext.analyze -v",
            "{triage}"
        );
        // Shape, not content: the bucket string and how many parameters get an explanation are
        // computed by whichever `ext.dll` this host has, and pinning them exactly would make the
        // tier fail on a different WinDbg rather than on a change in this server.
        let notes = analysis["parameter_notes"].as_array().map_or(0, Vec::len);
        assert!(
            notes <= 4,
            "the notes are positional — one per bug check parameter, of which there are four: \
             {triage}"
        );
        if analysis["truncated"] == false {
            assert!(
                notes > 0,
                "a complete `!analyze` of this bug check explains its parameters: {triage}"
            );
            let bucket_prefix = sample.bucket_prefix();
            assert!(
                analysis["failure_bucket_id"]
                    .as_str()
                    .is_some_and(|bucket| bucket.starts_with(&bucket_prefix)),
                "the bucket is one of the fields only `!analyze` computes, and it is derived from \
                 the bug check code: {triage}"
            );
        }
        // The two provenances agree about the process, which is the check that the extraction is
        // reading the right block rather than something that happens to look like it. Required
        // only of a *complete* run: a truncated one may have been cut off before `PROCESS_NAME`,
        // and demanding a field the tool explicitly says may be missing would fail this tier for
        // the one behaviour it is meant to allow.
        if analysis["truncated"] == false || !analysis["process_name"].is_null() {
            assert_eq!(
                analysis["process_name"], triage["process_name"],
                "`!analyze`'s PROCESS_NAME and the EPROCESS read must be the same process: \
                 {triage}"
            );
        }
    } else {
        assert!(
            analysis["note"].as_str().is_some_and(|n| !n.is_empty()),
            "an analysis that did not run has to say why: {triage}"
        );
        assert!(analysis["pool_tag"].is_null(), "{triage}");
    }

    // The text is the other channel and carries the same headline.
    let text = server.tool_text(
        "crash_triage",
        json!({ "session_id": session_id, "analyze": false }),
        TARGET_STEP,
    );
    assert!(
        text.contains(&format!(
            "BUG CHECK: {} {}",
            sample.bug_check, sample.bug_check_name
        )),
        "{text}"
    );
    assert!(text.contains("STACK ("), "{text}");

    // **The session is where it was left, which is what `read_only_hint = true` claims.** The
    // `!analyze -v` a triage runs resets the debugger's selected scope to the target's default —
    // measured on four targets (glslang/dbgscope#98) — so a caller who had chosen a frame would
    // silently lose it. `crash_triage` saves and restores it; this is that promise, checked the
    // only way it can be: from a scope the analysis would otherwise discard.
    //
    // Frame 3, not frame 0: frame 0 *is* the default, and a check that started there would pass
    // whether the scope was restored or merely reset.
    let moved = server.tool_text(
        "execute",
        json!({ "session_id": session_id, "command": ".frame 3" }),
        TARGET_STEP,
    );
    // The whole rendered frame line — index, offsets and symbol if there is one — so the check
    // does not depend on symbols being available on the host running this.
    let selected = moved
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("03 "))
        .unwrap_or_else(|| panic!("`.frame 3` selected no frame 3 on this dump: {moved}"))
        .to_string();

    // With the analysis on, since that is the half that moves the scope.
    server.tool_data(
        "crash_triage",
        json!({ "session_id": session_id }),
        TARGET_STEP,
    );
    let after = server.tool_text(
        "execute",
        json!({ "session_id": session_id, "command": ".frame" }),
        TARGET_STEP,
    );
    assert!(
        after.lines().map(str::trim).any(|line| line == selected),
        "crash_triage moved the session's scope: it was `{selected}`, and `.frame` now says:\n{after}"
    );

    server.tool_data(
        "end_session",
        json!({ "session_id": session_id }),
        TARGET_STEP,
    );
}

/// `crash_triage` against a **driver** crash — the case the tool was written for, and the one the
/// `0x9F` and `0xFC` samples structurally cannot cover.
///
/// Run once per fixture in [`DRIVER_CRASHES`], because what the tool exists for is on those two
/// crashes and nowhere else in the suite:
///
/// * a `faulting_frame` that exists, several frames below the top, under a stack of kernel
///   internals that a "blame frame 0" rule would name instead;
/// * that frame named `module+RVA` off the load base — the arithmetic this test is really about,
///   and the reason a second fixture was captured: until
///   [#154](https://github.com/glslang/windbg-mcp/issues/154) it had only ever run against x64
///   frames;
/// * `!analyze`'s own attribution beside it, which the two fixtures disagree about on purpose
///   (see [`DriverCrashSample::analyze_names_the_module`]).
#[test]
fn a_driver_crash_names_the_driver_frame_an_all_kernel_walk_would_miss() {
    if target_tier().is_none() {
        return;
    }
    for sample in DRIVER_CRASHES {
        assert_driver_crash_names_its_driver(sample);
    }
}

fn assert_driver_crash_names_its_driver(sample: &DriverCrashSample) {
    if !std::path::Path::new(sample.path).exists() {
        skip(&format!("{} was not found at {}", sample.what, sample.path));
        return;
    }
    let mut server = Server::started();
    let opened = server.call_tool("open_dump", json!({ "path": sample.path }), TARGET_STEP);
    assert_no_error(&opened, "open_dump");
    assert!(
        !is_tool_error(&opened),
        "opening {} failed:\n{}",
        sample.what,
        text_of(&opened["result"])
    );
    let session_id = session_id_of(&opened["result"]);
    if !engine_reads_target_memory(&mut server, &session_id) {
        skip(NO_TARGET_READS_SKIP);
        return;
    }
    if !engine_resolves_kernel_symbols(&mut server, &session_id) {
        skip(NO_KERNEL_SYMBOLS_SKIP);
        return;
    }

    let triage = server.tool_data(
        "crash_triage",
        json!({ "session_id": session_id }),
        TARGET_STEP,
    );

    assert_eq!(triage["bug_check"]["code"], sample.bug_check, "{triage}");
    assert_eq!(
        triage["bug_check"]["name"], sample.bug_check_name,
        "{triage}"
    );

    // The headline: a driver frame, found past the kernel's own.
    let faulting = &triage["faulting_frame"];
    assert!(
        !faulting.is_null(),
        "{} has a driver frame — finding it is what the tool is for: {triage}",
        sample.what
    );
    assert_eq!(
        faulting["module"], sample.module,
        "a host that reads this dump but resolves none of its symbols walks the stack into the bug \
         check's own parameters and names no driver at all — check whether `nt` came back with a \
         PDB before reading this as an attribution bug (issue #142): {triage}"
    );
    assert_eq!(
        faulting["rva"], sample.rva,
        "the RVA is a fixed offset into a fixed image, so it is the same in every dump this bug \
         produces however the driver was loaded: {triage}"
    );
    assert!(
        faulting["index"].as_u64().is_some_and(|index| index > 0),
        "the driver is never frame 0 — the bug check itself is: {triage}"
    );
    assert_eq!(
        triage["frames_truncated"], false,
        "this stack is well inside the default cap: {triage}"
    );

    // The frames above it are kernel internals, symbolised from `nt`'s own PDB — so the same walk
    // carries both kinds of frame, which is the mix a real driver crash always has.
    let frames = triage["frames"].as_array().expect("frames");
    assert!(
        frames.iter().any(|frame| frame["symbol"]
            .as_str()
            .is_some_and(|s| s.starts_with(sample.kernel_frame))),
        "`{}` should be on this stack: {triage}",
        sample.kernel_frame
    );

    let process = triage["process_name"]
        .as_str()
        .unwrap_or_else(|| panic!("the crashing process should be named: {triage}"));
    assert!(process.ends_with(".exe"), "{triage}");
    if sample.process_name_needs_the_audit_name {
        // A name longer than `_EPROCESS::ImageFileName` can hold, which is the whole point of
        // reading the audit name instead.
        assert!(
            process.len() > 15,
            "the full image name, not the 15-byte field's truncation of it: {triage}"
        );
    }

    let analysis = &triage["analysis"];
    if analysis["ran"] == true {
        if sample.analyze_names_the_module {
            // Here the computed frame is checked against an independent answer: this driver ships
            // a PDB, so `!analyze` blames it too and the two have to agree.
            assert_eq!(
                analysis["module_name"], sample.module,
                "`!analyze` and the computed frame disagree about which driver crashed: {triage}"
            );
        } else {
            // And here it is the *only* answer — no PDB, so `!analyze` cannot name the driver,
            // which is precisely why the frame is computed from the load base instead of taken
            // from the analysis.
            assert_ne!(
                analysis["module_name"], sample.module,
                "if `!analyze` learns to attribute a PDB-less driver, this test's premise is stale \
                 and the docs claiming otherwise need revisiting: {triage}"
            );
        }
        // Only where the analysis got that far: a truncated run may have been cut off before
        // `PROCESS_NAME`, and demanding a field the tool says may be missing would fail the tier
        // for the one behaviour it exists to allow. Same guard as the other dump's check.
        if analysis["truncated"] == false || !analysis["process_name"].is_null() {
            assert_eq!(
                analysis["process_name"], triage["process_name"],
                "the audit name and `!analyze`'s PROCESS_NAME are the same process: {triage}"
            );
        }
        if analysis["truncated"] == false && sample.carries_a_pool_tag {
            // The pool tag exists only in `!analyze`'s output, and this bug check is one of the
            // few that produces one.
            assert!(
                analysis["pool_tag"].as_str().is_some_and(|t| !t.is_empty()),
                "a 0x13A carries a freed-pool tag: {triage}"
            );
        }
    }

    // The text names the driver once, not twice — the bare module name is not re-rendered as a
    // symbol beside the offset it already is.
    let text = server.tool_text(
        "crash_triage",
        json!({ "session_id": session_id, "analyze": false }),
        TARGET_STEP,
    );
    let frame = format!("{}+{}", sample.module, sample.rva);
    assert!(text.contains(&format!("FAULTING FRAME: {frame}")), "{text}");
    assert!(!text.contains(&format!("[{frame}]")), "{text}");

    server.tool_data(
        "end_session",
        json!({ "session_id": session_id }),
        TARGET_STEP,
    );
}

/// `debug_batch` end to end against a real engine: a batch that commits, and one that fails an
/// assertion — with the same `always` block on both.
///
/// The claim being tested is the one the tool exists for and the one no in-process test can make:
/// the rollback runs **inside the worker process**, on the failing path, before the tool call
/// returns. `src/batch.rs` proves the executor's logic over a scripted debuggee; this proves the
/// wiring — argument schema, the op crossing the pipe, the engine seam, the report coming back.
///
/// Read-only against the checked-in kernel dump: the mutation the rollback would undo is left to
/// the live-kernel tier, because a dump has nothing worth restoring.
#[test]
fn a_batch_commits_or_fails_and_its_rollback_runs_either_way() {
    let Some(sample) = native_sample_tier() else {
        return;
    };
    let mut server = Server::started();

    let response = server.call_tool("open_dump", json!({ "path": sample.path }), TARGET_STEP);
    assert_no_error(&response, "open_dump");
    let session_id = session_id_of(&response["result"]);
    // The batch disassembles at the captured `@$ip`, which is a read like any other — and needs
    // no symbol, which is why this asks only for the read.
    if !engine_reads_target_memory(&mut server, &session_id) {
        skip(NO_TARGET_READS_SKIP);
        return;
    }

    // A batch that should commit: a capture bound from one step and interpolated into the next,
    // which is the whole of the "named values" contract in three steps.
    let committed_response = server.call_tool(
        "debug_batch",
        json!({
            "session_id": session_id,
            "steps": [
                { "op": "command", "command": "lm m nt",
                  "expect": [{ "check": "contains", "text": "nt" }] },
                { "op": "eval", "expr": "@$ip", "capture": "ip" },
                { "op": "command", "command": "u {{ip}} L1", "name": "disassemble where we are" }
            ],
            "always": [{ "op": "command", "command": "lm m hal" }]
        }),
        TARGET_STEP,
    );
    assert_no_error(&committed_response, "debug_batch");
    let committed = text_of(&committed_response["result"]);
    assert!(
        committed.contains("BATCH: COMMITTED"),
        "the batch should have committed:
{committed}"
    );
    assert!(
        committed.contains("rollback: COMPLETE"),
        "the `always` block should have run:
{committed}"
    );
    assert!(
        committed.contains("session after: STOPPED"),
        "a dump is always stopped; the state probe should say so:
{committed}"
    );
    // The interpolated step is rendered with the *substituted* address, so a `{{ip}}` surviving
    // into the report would mean nothing was bound.
    assert!(
        !committed.contains("u {{ip}}"),
        "the capture was not interpolated:
{committed}"
    );
    // The same verdict as values. Read from the typed half rather than from the sentences above,
    // because that half is what a transcript records and what a client branches on — and the two
    // agreeing is the property that keeps the report honest.
    let data = &committed_response["result"]["structuredContent"];
    assert_eq!(
        data["status"], "ok",
        "a batch that ran answers `ok`: {data}"
    );
    assert_eq!(data["outcome"], "committed", "{data}");
    assert_eq!(data["committed"], true, "{data}");
    assert_eq!(data["rollback_complete"], true, "{data}");
    assert_eq!(
        data["after"]["state"], "stopped",
        "a dump is stopped: {data}"
    );
    assert!(
        data["at"].is_null(),
        "a committed batch stopped at no step: {data}"
    );
    assert_eq!(
        data["steps"].as_array().map(Vec::len),
        Some(3),
        "every step belongs in the typed report: {data}"
    );
    assert_eq!(data["always"].as_array().map(Vec::len), Some(1), "{data}");
    // The interpolation again, from the values: `action` is what ran, not what was written.
    let disassembly = data["steps"][2]["action"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        disassembly.starts_with("u 0x") && !disassembly.contains("{{ip}}"),
        "the typed step should carry the substituted action, not the template: {disassembly}"
    );

    // The same shape with an assertion that cannot hold. The batch must stop at that step, name
    // it, skip what follows — and still run the cleanup.
    let failing = server.call_tool(
        "debug_batch",
        json!({
            "session_id": session_id,
            "steps": [
                { "op": "command", "command": "lm m nt" },
                { "op": "command", "command": "lm m nt",
                  "expect": [{ "check": "contains", "text": "no module is called this" }] },
                { "op": "command", "command": "lm m hal", "name": "must not run" }
            ],
            "always": [{ "op": "command", "command": "version", "name": "cleanup" }]
        }),
        TARGET_STEP,
    );
    assert_no_error(&failing, "debug_batch");
    assert!(
        is_tool_error(&failing),
        "a batch that did not commit must come back as a tool error: {failing}"
    );
    let text = text_of(&failing["result"]);
    assert!(
        text.contains("BATCH: FAILED at step 2 of 3"),
        "the report must name the exact failing step:
{text}"
    );
    assert!(
        text.contains("SKIPPED"),
        "the step after the failure must be reported as skipped:
{text}"
    );
    assert!(
        text.contains("rollback: COMPLETE"),
        "the `always` block must run on the failing path — that is the whole point:
{text}"
    );
    // The pairing this tool is the only one with: the *call* produced its answer (`status: "ok"`,
    // the report), and the *transaction* did not commit (`isError`, asserted above). A caller that
    // read only `status` would think this worked; one that read only `isError` could not tell a
    // batch that failed from one that never ran.
    let failed = &failing["result"]["structuredContent"];
    assert_eq!(failed["status"], "ok", "the batch ran: {failed}");
    assert_eq!(failed["outcome"], "failed", "{failed}");
    assert_eq!(failed["committed"], false, "{failed}");
    assert_eq!(
        failed["at"], 2,
        "the typed report must name the failing position: {failed}"
    );
    assert_eq!(
        failed["steps"][1]["result"], "unmet",
        "an assertion that did not hold is `unmet`, not `failed`: {failed}"
    );
    assert!(
        failed["steps"][1]["detail"].is_string(),
        "the assertion that did not hold must say so: {failed}"
    );
    assert_eq!(failed["steps"][2]["result"], "skipped", "{failed}");
    assert_eq!(
        failed["rollback_complete"], true,
        "the `always` block ran, and the values must say so too: {failed}"
    );

    server.tool_text(
        "end_session",
        json!({ "session_id": session_id }),
        TARGET_STEP,
    );
}

/// `end_session` on a session that is running a batch: the batch stops at its next step, rolls
/// back, and *reports* — which is what makes ending the session the documented way to abort one.
///
/// The client is still here for this one, so unlike the disconnect below it can be asked what
/// happened, and the answer is the point: an `ABANDONED` report with the rollback complete, rather
/// than a session that goes quiet for as long as the batch had left. Both calls are outstanding at
/// once, deliberately — a teardown that had to queue behind the work it is tearing down would be no
/// use for the case it exists for.
#[test]
fn ending_a_session_stops_a_running_batch_and_rolls_it_back() {
    let Some(dump) = target_tier() else { return };
    let running = marker_path("end-session-batch-running");
    let _ = std::fs::remove_file(&running);

    let mut server = Server::started();
    let response = server.call_tool("open_dump", json!({ "path": dump }), TARGET_STEP);
    assert_no_error(&response, "open_dump");
    let session_id = session_id_of(&response["result"]);

    let mut steps = vec![
        json!({ "op": "command", "command": format!(".logopen \"{}\"", running.display()) }),
        json!({ "op": "command", "command": ".echo BATCH-RUNNING" }),
        json!({ "op": "command", "command": ".logclose" }),
    ];
    steps.extend(std::iter::repeat_n(
        json!({ "op": "command", "command": ".sleep 1000" }),
        20,
    ));
    let batch = server.send_request(
        "tools/call",
        json!({
            "name": "debug_batch",
            "arguments": {
                "session_id": session_id,
                "steps": steps,
                "always": [{ "op": "command", "command": "version", "name": "cleanup" }],
            }
        }),
    );

    // As below: end the session only once the batch is demonstrably inside it, or this would be
    // testing the refuse-to-start path instead and passing just as green.
    let deadline = Instant::now() + TARGET_STEP;
    while !running.exists() {
        assert!(
            Instant::now() < deadline,
            "the batch never reached its first step\n--- stderr ---\n{}",
            server.stderr()
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    let asked = Instant::now();
    // Watched, because this is the one call with a milestone of its own to report: a teardown that
    // finds a transaction says how long unwinding it needs, and a client looking at an
    // `end_session` that has not come back is exactly who that is for.
    let response = server.call_tool_watching(
        "end_session",
        json!({ "session_id": session_id }),
        "unwind-1",
        TARGET_STEP,
    );
    let took = asked.elapsed();
    assert_no_error(&response, "end_session");
    let ended = text_of(&response["result"]);
    assert!(
        !is_tool_error(&response),
        "end_session reported a failure: {ended}"
    );
    assert!(!ended.trim().is_empty(), "end_session said nothing");
    let said: Vec<String> = server
        .progress_for("unwind-1")
        .iter()
        .filter_map(|step| step["params"]["message"].as_str().map(str::to_string))
        .collect();
    assert!(
        said.iter().any(|m| m.contains("rolling it back")),
        "the teardown found a transaction and never said so: {said:?}"
    );
    // And the *end* of it, which is the same protocol message carrying zero. This is the only
    // place both readings occur for real, so it is the only place that can catch them being
    // rendered alike — which they were: the retraction used to report a transaction still in
    // flight, "up to 0.0s", at the moment the rollback had finished.
    assert!(
        said.iter().any(|m| m.contains("has been rolled back")),
        "the rollback finished and the client was never told: {said:?}"
    );
    assert!(
        !said.iter().any(|m| m.contains("up to 0.0s")),
        "a finished rollback is being reported as one still running: {said:?}"
    );
    assert!(
        took < Duration::from_secs(15),
        "end_session took {took:?}: it waited out the batch instead of cutting it short"
    );

    // The batch's own reply, which the client is still here to receive.
    let report = text_of(&server.await_id(batch, "debug_batch", TARGET_STEP)["result"]);
    assert!(
        report.contains("BATCH: ABANDONED"),
        "the batch should say it was cut short, not that it failed or timed out:\n{report}"
    );
    assert!(
        report.contains("rollback: COMPLETE"),
        "the rollback is the reason for stopping early:\n{report}"
    );

    let _ = std::fs::remove_file(&running);
}

/// `interrupt` on a session that is running a batch: the batch stops at its next step, rolls back,
/// and reports `BATCH: INTERRUPTED` — while the **session stays open**, which is what separates it
/// from the `end_session` case above.
///
/// The bug this pins is one an interrupt *created*. An on-request interrupt deliberately returns the
/// output the command reached rather than the error the break provoked — that is what makes partial
/// output survivable — so the interrupted step comes back `Ok`, its assertions still hold, and the
/// batch executor sees a step that ran. Without being told separately it carried straight on into
/// the next mutation, for a caller who had just asked it to stop. `src/batch.rs` pins the executor's
/// half against a scripted debuggee; only here is the whole path real, because only a real engine
/// turns a Ctrl+Break into that deceptively successful step.
#[test]
fn interrupting_a_running_batch_stops_it_and_rolls_it_back() {
    let Some(dump) = target_tier() else { return };
    let running = marker_path("interrupt-batch-running");
    let reached_later = marker_path("interrupt-batch-later-step");
    let _ = std::fs::remove_file(&running);
    let _ = std::fs::remove_file(&reached_later);

    // Recorded, because this is the only place the interrupted-transaction half of the transcript
    // contract ([#87](https://github.com/glslang/windbg-mcp/issues/87)) is real: an `interrupt`
    // that actually reached a running batch, and a report that came back saying so.
    let transcript = marker_path("interrupt-batch-transcript");
    let _ = std::fs::remove_file(&transcript);
    let mut server = Server::started_with(&[(
        "WINDBG_MCP_TRANSCRIPT",
        transcript.to_str().expect("a UTF-8 temp path"),
    )]);
    let response = server.call_tool("open_dump", json!({ "path": dump }), TARGET_STEP);
    assert_no_error(&response, "open_dump");
    let session_id = session_id_of(&response["result"]);

    // Announce that the batch is inside its steps, spend long enough to be interrupted, and then —
    // the assertion that matters — write a second marker. A batch that carries on past the
    // interrupt reaches that step; one that stops does not, and the file is the evidence either
    // way, independent of what the report says about itself.
    let mut steps = vec![
        json!({ "op": "command", "command": format!(".logopen \"{}\"", running.display()) }),
        json!({ "op": "command", "command": ".echo BATCH-RUNNING" }),
        json!({ "op": "command", "command": ".logclose" }),
    ];
    steps.extend(std::iter::repeat_n(
        json!({ "op": "command", "command": ".sleep 1000" }),
        20,
    ));
    steps.extend([
        json!({ "op": "command", "command": format!(".logopen \"{}\"", reached_later.display()) }),
        json!({ "op": "command", "command": ".echo REACHED-A-LATER-STEP" }),
        json!({ "op": "command", "command": ".logclose" }),
    ]);
    let batch = server.send_request(
        "tools/call",
        json!({
            "name": "debug_batch",
            "arguments": {
                "session_id": session_id,
                "steps": steps,
                "always": [{ "op": "command", "command": "version", "name": "cleanup" }],
            }
        }),
    );

    // Wait for the batch to be demonstrably inside its steps, as the teardown tests do: timed with
    // a sleep instead, a slow machine would interrupt before the batch started and take the
    // refuse-to-start path, passing just as green.
    let deadline = Instant::now() + TARGET_STEP;
    while !running.exists() {
        assert!(
            Instant::now() < deadline,
            "the batch never reached its first step\n--- stderr ---\n{}",
            server.stderr()
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    let raised = server.tool_text(
        "interrupt",
        json!({ "session_id": session_id }),
        Duration::from_secs(20),
    );
    assert!(
        raised.contains("Interrupted"),
        "the batch was running, so the interrupt should have reached it:\n{raised}"
    );

    let report = text_of(&server.await_id(batch, "debug_batch", TARGET_STEP)["result"]);
    assert!(
        report.contains("BATCH: INTERRUPTED"),
        "an interrupted batch should say so — not COMMITTED, which is what it reported while the \
         interrupt was invisible to the executor, and not ABANDONED, which would send the caller \
         to a new session:\n{report}"
    );
    assert!(
        report.contains("rollback: COMPLETE"),
        "the rollback runs on this path like every other:\n{report}"
    );
    assert!(
        !reached_later.exists(),
        "the batch ran a step *after* the interrupt — the executor was never told, so it treated \
         the interrupted step as one that simply succeeded:\n{report}"
    );

    // And the session is still open, which is the whole difference from `end_session`: the same
    // batch can be resubmitted against it.
    let after = server.call_tool("modules", json!({ "session_id": session_id }), TARGET_STEP);
    assert!(
        !is_tool_error(&after),
        "interrupting a batch must not cost the session:\n{}",
        text_of(&after["result"])
    );

    // The **worker's** account of the same interrupt, read back through `server_log` — the one
    // claim about the log bridge that needs two real processes.
    //
    // A worker's `tracing` output has always gone to its inherited stderr, which is the
    // supervisor's, which under stdio is the client's log; nothing had to carry it. Under
    // `--listen` the client is on another machine and that inheritance reaches nobody, so the
    // record has to cross the pipe as a value and be filed against a session id only the
    // supervisor knows. In process there is neither a second process nor a session to tag.
    //
    // Hung off the interrupt because that is a path a worker is *certain* to log on — a healthy
    // session is quiet by design, which is the point of the level rather than a gap — and because
    // the session survives it, so this is not racing a teardown.
    let worker_said = wait_for_log_record(&mut server, &session_id, "interrupt raised for job");
    assert_eq!(
        worker_said["target"], "windbg_mcp::worker",
        "it has to be the worker's own record, not the supervisor's about it: {worker_said}"
    );
    assert_eq!(
        worker_said["session_id"], session_id,
        "and filed against the session whose worker made it: {worker_said}"
    );

    server.tool_text(
        "end_session",
        json!({ "session_id": session_id }),
        TARGET_STEP,
    );
    assert_eq!(server.shutdown(), Some(0));

    // The transcript's account of the same thing, and the reason it is worth asserting: the report
    // above is a paragraph, and this is what a reader after the fact — or an unattended run — has
    // to be able to act on. The `interrupt` is recorded as its own cause, and the transaction's
    // verdict says it was interrupted and that the rollback finished, as fields.
    let events: Vec<Value> = std::fs::read_to_string(&transcript)
        .unwrap_or_else(|e| panic!("no transcript at {}: {e}", transcript.display()))
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("not JSONL ({e}): {l}")))
        .collect();
    let interrupt = events
        .iter()
        .find(|r| r["event"] == "interrupt")
        .unwrap_or_else(|| panic!("the interrupt is not in the transcript: {events:#?}"));
    assert_eq!(
        interrupt["delivered"], true,
        "the interrupt reached the worker, and the record has to say so: {interrupt}"
    );
    let batch = events
        .iter()
        .find(|r| r["event"] == "batch")
        .unwrap_or_else(|| panic!("the batch verdict is not in the transcript: {events:#?}"));
    assert_eq!(batch["outcome"], "interrupted", "{batch}");
    assert_eq!(batch["committed"], false, "{batch}");
    assert_eq!(
        batch["rollback_complete"], true,
        "the rollback ran, and a transcript that did not say so would be the one fact an \
         unattended run is read for: {batch}"
    );
    // Ordered as cause and effect, which is what makes the pair readable.
    let position = |event: &str| events.iter().position(|r| r["event"] == event);
    assert!(
        position("interrupt") < position("batch"),
        "the interrupt is recorded before the verdict it produced"
    );

    let _ = std::fs::remove_file(&running);
    let _ = std::fs::remove_file(&reached_later);
    let _ = std::fs::remove_file(&transcript);
}

/// An `interrupt` that arrives while a batch is running its **rollback** is refused, and the
/// rollback finishes.
///
/// The severe half of the same problem. Cleanup is reached on every path, including paths no
/// interrupt was involved in, so this needs no earlier interrupt to set it up — a *first* break
/// landing here would hit a restore command, and an interrupted command returns `Ok` with whatever
/// it had produced. The restore would then be recorded as a step that worked and the report would
/// say `rollback: COMPLETE` with the target still changed, which is the one outcome the whole
/// transaction machinery exists to prevent, arriving through the tool meant to be the gentle way
/// out.
///
/// Staged with markers rather than timing, like the teardown tests: the first cleanup step
/// announces that the rollback has begun, and the last one records that it finished. Interrupting
/// on a sleep instead would sometimes land in the steps block and pass for the wrong reason.
#[test]
fn interrupting_a_batch_during_its_rollback_is_refused() {
    let Some(dump) = target_tier() else { return };
    let unwinding = marker_path("interrupt-batch-unwinding");
    let unwound = marker_path("interrupt-batch-unwound");
    let _ = std::fs::remove_file(&unwinding);
    let _ = std::fs::remove_file(&unwound);

    let mut server = Server::started();
    let response = server.call_tool("open_dump", json!({ "path": dump }), TARGET_STEP);
    assert_no_error(&response, "open_dump");
    let session_id = session_id_of(&response["result"]);

    let batch = server.send_request(
        "tools/call",
        json!({
            "name": "debug_batch",
            "arguments": {
                "session_id": session_id,
                "steps": [{ "op": "command", "command": "version" }],
                "always": [
                    { "op": "command", "command": format!(".logopen \"{}\"", unwinding.display()) },
                    { "op": "command", "command": ".echo ROLLBACK-RUNNING" },
                    { "op": "command", "command": ".logclose" },
                    // The window the interrupt has to land in.
                    { "op": "command", "command": ".sleep 0n5000" },
                    { "op": "command", "command": format!(".logopen \"{}\"", unwound.display()) },
                    { "op": "command", "command": ".echo ROLLBACK-FINISHED" },
                    { "op": "command", "command": ".logclose" },
                ],
            }
        }),
    );

    let deadline = Instant::now() + TARGET_STEP;
    while !unwinding.exists() {
        assert!(
            Instant::now() < deadline,
            "the batch never reached its rollback\n--- stderr ---\n{}",
            server.stderr()
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    let refused = server.tool_text(
        "interrupt",
        json!({ "session_id": session_id }),
        Duration::from_secs(20),
    );
    assert!(
        refused.contains("Not interrupted"),
        "a break must not be raised against a rollback — cleanup cut short reports success:\n{refused}"
    );
    assert!(
        refused.contains("rollback"),
        "and the refusal has to say why, or it reads as a bug:\n{refused}"
    );

    let report = text_of(&server.await_id(batch, "debug_batch", TARGET_STEP)["result"]);
    assert!(
        report.contains("rollback: COMPLETE"),
        "the rollback had to finish, which is what refusing the break was for:\n{report}"
    );
    assert!(
        unwound.exists(),
        "the last cleanup step never ran, so the rollback was cut short after all:\n{report}"
    );
    // Nothing was interrupted, so nothing should claim it was.
    assert!(
        !report.contains("INTERRUPTED"),
        "the break was refused, so the batch was not interrupted:\n{report}"
    );

    server.tool_text(
        "end_session",
        json!({ "session_id": session_id }),
        TARGET_STEP,
    );
    let _ = std::fs::remove_file(&unwinding);
    let _ = std::fs::remove_file(&unwound);
}

/// A batch still running when the client disconnects has to finish its rollback before its worker
/// goes — the one guarantee `debug_batch` used to make only against a call *timeout*.
///
/// The teardown is the adversary here: a disconnect is `end_session` on every session, the
/// `EndSession` op queues *behind* the batch, and the grace it waits is deliberately short. So the
/// worker used to be terminated mid-transaction, with whatever the batch had patched still
/// patched — on a live kernel, the exact loss the tool exists to prevent, arriving by the path
/// where nobody is watching.
///
/// Both facts it asserts need a real engine and a real disconnect, which is why this is here rather
/// than in `src/batch.rs`: the abandon signal has to cross the worker's channel and be answered by
/// its *reader* while its engine thread is busy, and the rollback has to leave something behind
/// after the client, the supervisor and the worker are all gone. That last part is what the log
/// files are for — a side effect on this machine outlives every process involved, where a tool
/// result has nobody left to be returned to. A dump has nothing worth restoring, so the mutation is
/// stood in for by writing a file; the byte-level version belongs in the live-kernel tier.
#[test]
fn a_disconnect_lets_a_running_batch_roll_back_first() {
    let Some(dump) = target_tier() else { return };
    let running = marker_path("batch-running");
    let rolled_back = marker_path("batch-rolled-back");
    let _ = std::fs::remove_file(&running);
    let _ = std::fs::remove_file(&rolled_back);

    let mut server = Server::started();
    let response = server.call_tool("open_dump", json!({ "path": dump }), TARGET_STEP);
    assert_no_error(&response, "open_dump");
    let session_id = session_id_of(&response["result"]);

    // Steps: announce that the batch is running, then spend twenty seconds so the disconnect
    // lands squarely inside it. `always` leaves the second marker, and is the thing under test.
    let mut steps = vec![
        json!({ "op": "command", "command": format!(".logopen \"{}\"", running.display()) }),
        json!({ "op": "command", "command": ".echo BATCH-RUNNING" }),
        json!({ "op": "command", "command": ".logclose" }),
    ];
    steps.extend(std::iter::repeat_n(
        json!({ "op": "command", "command": ".sleep 1000" }),
        20,
    ));
    // Sent without waiting: nobody is left to read the answer, which is the whole scenario.
    server.send_request(
        "tools/call",
        json!({
            "name": "debug_batch",
            "arguments": {
                "session_id": session_id,
                "steps": steps,
                "always": [
                    { "op": "command", "command": format!(".logopen \"{}\"", rolled_back.display()) },
                    { "op": "command", "command": ".echo ROLLBACK-RAN" },
                    { "op": "command", "command": ".logclose" },
                ],
            }
        }),
    );

    // Disconnect only once the batch is demonstrably inside its steps. Timing it with a sleep
    // instead would make a slow machine into a test that proves nothing: the batch would not have
    // started, and refusing to start is a *different* correct behaviour with the same green tick.
    let deadline = Instant::now() + TARGET_STEP;
    while !running.exists() {
        assert!(
            Instant::now() < deadline,
            "the batch never reached its first step, so the disconnect below would prove \
             nothing\n--- stderr ---\n{}",
            server.stderr()
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    let disconnected = Instant::now();
    assert_eq!(
        server.shutdown(),
        Some(0),
        "clean disconnect should be a clean exit"
    );
    let took = disconnected.elapsed();

    let rollback = std::fs::read_to_string(&rolled_back).unwrap_or_else(|e| {
        panic!(
            "the `always` block left nothing at {} ({e}) — the batch was terminated \
             mid-transaction, which on a live kernel would leave the patch in place",
            rolled_back.display()
        )
    });
    assert!(
        rollback.contains("ROLLBACK-RAN"),
        "the rollback started but did not finish; it left:\n{rollback}"
    );
    // The steps had twenty seconds left to run. Waiting them out would be a rollback that happened
    // for the wrong reason — the batch finishing normally — and would say nothing about abandoning
    // one.
    assert!(
        took < Duration::from_secs(15),
        "the disconnect took {took:?}: the batch ran on instead of stopping at its next step"
    );

    let _ = std::fs::remove_file(&running);
    let _ = std::fs::remove_file(&rolled_back);
}

/// A path in the temp directory nothing else in this run will pick, for tests that need a side
/// effect outliving the server process.
fn marker_path(what: &str) -> std::path::PathBuf {
    let unique = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    std::env::temp_dir().join(format!(
        "windbg-mcp-smoke-{what}-{}-{unique:x}.log",
        std::process::id()
    ))
}

/// The `session_id` a tool result carries, if it carries one.
///
/// Anchored to the line the openers actually emit (`session_id: sess-…`) rather than to the
/// substring anywhere in the text: the tool prose mentions `session_id` several times, and a
/// loose match would yield a plausible-looking wrong handle whose failure surfaces later as an
/// unrelated mismatch.
///
/// A **failed** opener can carry one too, and that is the case worth remembering: an open that
/// fails *after* claiming its target hands the handle back deliberately, because the session
/// exists and needs cleaning up. So cleanup must key on this, never on `isError`.
fn maybe_session_id(result: &Value) -> Option<String> {
    let data = &result["structuredContent"];
    data["session_id"]
        .as_str()
        .or_else(|| data["error"]["session_id"].as_str())
        .map(str::to_string)
}

/// [`maybe_session_id`], for a call that must have opened something.
fn session_id_of(result: &Value) -> String {
    maybe_session_id(result).unwrap_or_else(|| {
        panic!(
            "expected a session_id in the structured result:\n{}\n--- text ---\n{}",
            result["structuredContent"],
            text_of(result)
        )
    })
}

/// Whether a process is still running. Windows-only, like everything else here.
fn process_alive(pid: u32) -> bool {
    let out = Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/NH"])
        .output()
        .expect("run tasklist");
    // No match prints "INFO: No tasks are running which match…", which never contains the pid.
    String::from_utf8_lossy(&out.stdout).contains(&pid.to_string())
}

/// Reads one of this server's addresses back to a number, checking the representation on the way.
///
/// Every address in a structured result is documented as a `0x`-prefixed, lowercase, 16-digit
/// hex string, and it is documented because clients depend on it: the whole reason it is a string
/// and not a JSON number is that a kernel pointer past 2^53 does not survive a parser that reads
/// numbers as doubles. So the shape is asserted at every point a test reads one.
fn address_of(value: &Value) -> u64 {
    let text = value
        .as_str()
        .unwrap_or_else(|| panic!("an address is a string, got {value}"));
    let digits = text
        .strip_prefix("0x")
        .unwrap_or_else(|| panic!("addresses carry a `0x` prefix, got {text:?}"));
    assert_eq!(
        digits.len(),
        16,
        "addresses are zero-padded to 16 digits so they sort: {text:?}"
    );
    assert!(
        digits
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "addresses are lowercase hex with no backtick: {text:?}"
    );
    u64::from_str_radix(digits, 16).unwrap_or_else(|e| panic!("unreadable address {text:?}: {e}"))
}

/// The pid of the engine process holding a session, from `session_status`'s typed report.
///
/// A field rather than the `[engine pid N, …]` fragment of a rendered line: these tests kill that
/// process and then assert it is gone, so a misread number would make the whole check pass
/// against a process nobody touched.
fn engine_pid_of(status: &Value, session_id: &str) -> u32 {
    let sessions = status["sessions"]
        .as_array()
        .unwrap_or_else(|| panic!("session_status reports a session list, got: {status}"));
    let session = sessions
        .iter()
        .find(|s| s["session_id"] == session_id)
        .unwrap_or_else(|| panic!("`{session_id}` is not in the report: {status}"));
    session["engine_pid"]
        .as_u64()
        .unwrap_or_else(|| panic!("`{session_id}` reports no engine pid: {session}")) as u32
}

/// Sessions are independent processes, so opening a second target must not disturb the first.
///
/// Under the single-engine design this was impossible by construction — one process, one DbgEng
/// session, so the second open *replaced* the first and every handle to it went stale. The whole
/// reason sessions became processes is that a target you cannot unwind must not cost you the
/// server; this is the same property seen from the other side.
#[test]
fn two_sessions_coexist_and_do_not_disturb_each_other() {
    let Some(dump) = target_tier() else { return };
    let mut server = Server::started();

    let first = server.open_session("open_dump", json!({ "path": dump }), TARGET_STEP);
    let second = server.open_session("open_dump", json!({ "path": dump }), TARGET_STEP);
    assert_ne!(first, second, "each open must get its own session");

    // The claim: the first handle still names a live target after the second open landed.
    let response = server.call_tool("modules", json!({ "session_id": first }), TARGET_STEP);
    assert_no_error(&response, "modules on the first session");
    assert!(
        !is_tool_error(&response),
        "the first session must survive a later open:\n{}",
        text_of(&response["result"])
    );

    // Both are listed, and the newest is the one an omitted handle routes to. Read as `current`
    // rather than by finding a line containing `(current)`: that marker is a rendering, and which
    // session it sits on is the routing rule this test is actually about.
    let status = server.tool_data("session_status", json!({}), TARGET_STEP);
    let listed = |id: &str| -> Value {
        status["sessions"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|s| s["session_id"] == id)
            .cloned()
            .unwrap_or_else(|| panic!("`{id}` should be listed: {status}"))
    };
    assert_eq!(
        listed(&first)["current"],
        false,
        "the older session is not the default target: {status}"
    );
    assert_eq!(
        listed(&second)["current"],
        true,
        "the newest session should be the one an omitted handle routes to: {status}"
    );

    // Ending one leaves the other alone — the failure mode that made `end_session` unusable as a
    // recovery before, since there was only ever one session to end.
    server.tool_text("end_session", json!({ "session_id": second }), TARGET_STEP);
    let still_there = server.call_tool("modules", json!({ "session_id": first }), TARGET_STEP);
    assert!(
        !is_tool_error(&still_there),
        "ending one session must not touch another:\n{}",
        text_of(&still_there["result"])
    );
    let gone = server.call_tool("modules", json!({ "session_id": second }), TARGET_STEP);
    assert!(
        is_tool_error(&gone),
        "the ended handle must be refused: {gone}"
    );

    server.tool_text("end_session", json!({ "session_id": first }), TARGET_STEP);
}

/// Issue #66: a caller may make one symbol-path setting the starting point for sessions it opens
/// later, without turning independent workers into shared mutable engine state.
///
/// Unique empty directories are enough to prove the path plumbing and need no symbol server or
/// matching PDB. The contrast carries the claim: a worker that already existed is unchanged, a
/// later worker inherits, a per-session override does not replace the remembered setting, and an
/// explicit clear sends the following worker back to its ambient DbgEng path.
#[test]
fn a_symbol_path_can_seed_future_sessions_without_broadcasting_to_existing_ones() {
    let Some(dump) = target_tier() else { return };
    let remembered = marker_path("remembered-symbols");
    let override_only = marker_path("session-only-symbols");
    std::fs::create_dir_all(&remembered).expect("create the remembered symbol directory");
    std::fs::create_dir_all(&override_only).expect("create the session-only symbol directory");
    let remembered_text = remembered.to_string_lossy().to_string();
    let override_text = override_only.to_string_lossy().to_string();
    let contains_path = |output: &str, path: &str| {
        output
            .to_ascii_lowercase()
            .contains(&path.to_ascii_lowercase())
    };

    let mut server = Server::started();
    let first = server.open_session("open_dump", json!({ "path": dump }), TARGET_STEP);
    let existing = server.open_session("open_dump", json!({ "path": dump }), TARGET_STEP);

    let remembered_result = server.tool_text(
        "set_symbol_path",
        json!({
            "session_id": first,
            "path": remembered_text,
            "append": false,
            "for_new_sessions": true,
        }),
        TARGET_STEP,
    );
    assert!(
        remembered_result.contains("New sessions opened by this client"),
        "the caller was not told the future-session default changed:\n{remembered_result}"
    );
    let existing_path = server.tool_text(
        "execute",
        json!({ "session_id": existing, "command": ".sympath" }),
        TARGET_STEP,
    );
    assert!(
        !contains_path(&existing_path, &remembered_text),
        "the setting was broadcast into a worker that was already running:\n{existing_path}"
    );

    let inherited = server.open_session("open_dump", json!({ "path": dump }), TARGET_STEP);
    let inherited_path = server.tool_text(
        "execute",
        json!({ "session_id": inherited, "command": ".sympath" }),
        TARGET_STEP,
    );
    assert!(
        contains_path(&inherited_path, &remembered_text),
        "a newly opened worker did not inherit the remembered path:\n{inherited_path}"
    );

    server.tool_text(
        "set_symbol_path",
        json!({
            "session_id": inherited,
            "path": override_text,
            "append": false,
        }),
        TARGET_STEP,
    );
    let later = server.open_session("open_dump", json!({ "path": dump }), TARGET_STEP);
    let later_path = server.tool_text(
        "execute",
        json!({ "session_id": later, "command": ".sympath" }),
        TARGET_STEP,
    );
    assert!(
        contains_path(&later_path, &remembered_text),
        "a session-only override replaced the remembered starting path:\n{later_path}"
    );
    assert!(
        !contains_path(&later_path, &override_text),
        "a session-only override leaked into another worker:\n{later_path}"
    );

    let cleared = server.tool_text(
        "set_symbol_path",
        json!({
            "session_id": inherited,
            "path": override_text,
            "append": false,
            "for_new_sessions": false,
        }),
        TARGET_STEP,
    );
    assert!(
        cleared.contains("remembered symbol-path setting") && cleared.contains("cleared"),
        "the caller was not told the future-session default was cleared:\n{cleared}"
    );
    server.tool_text(
        "end_session",
        json!({ "session_id": existing }),
        TARGET_STEP,
    );
    let after_clear = server.open_session("open_dump", json!({ "path": dump }), TARGET_STEP);
    let ambient = server.tool_text(
        "execute",
        json!({ "session_id": after_clear, "command": ".sympath" }),
        TARGET_STEP,
    );
    assert!(
        !contains_path(&ambient, &remembered_text) && !contains_path(&ambient, &override_text),
        "clearing the default did not restore ambient startup behavior:\n{ambient}"
    );

    for session in [first, inherited, later, after_clear] {
        server.tool_text("end_session", json!({ "session_id": session }), TARGET_STEP);
    }
    let _ = std::fs::remove_dir(&remembered);
    let _ = std::fs::remove_dir(&override_only);
}

/// A stateless client can work while one of its own calls is parked — the same property as the
/// test below, over the listener, for the revision that has no session id.
///
/// The second finding of [#168](https://github.com/glslang/windbg-mcp/issues/168), and the one that
/// survived the first. A request carrying no `Mcp-Session-Id` used to take the gate's *opening*
/// path and hold a claim for its whole duration — and on `2026-07-28` there is never an id to
/// carry, so that was **every** request. Two that overlapped contended. The gate has since been
/// retired entirely, so there is no classification left to get wrong; this stays because the
/// property is the client's, not the mechanism's.
///
/// Measured at its sharpest rather than as a race. A kernel attach whose target never dials in
/// parks in `WaitForEvent(INFINITE)` and does not come back; that is a supported state, and
/// `session_status` and `end_session` are how a client sees it and reclaims it. If the claim it
/// held locked its own credential out, a stateless client could do neither, and the property
/// [#61](https://github.com/glslang/windbg-mcp/issues/61) established — that a parked attach costs
/// one session and not the server — was not true for the revision current clients negotiate.
///
/// In this tier and not the one above it, because a park needs a real engine worker: without
/// `dbgeng.dll` the attach fails during initialisation instead of parking, and a test whose whole
/// subject is a call that does not return would quietly become one about a call that failed fast.
#[test]
fn a_stateless_client_can_work_while_one_of_its_own_calls_is_parked() {
    let Some(_) = target_tier() else { return };
    let server = Listener::start(&[]);

    // Nothing is listening on it, so the attach parks rather than failing. Its own port, so a
    // stray listener on this host cannot turn the park into an error and the test into a pass.
    let connection = format!("net:port={},key=1.1.1.1", free_port());
    // Held for the rest of the test: this connection *is* the parked request.
    let _parked = server.stateless_unanswered(
        9001,
        "tools/call",
        json!({ "name": "attach_kernel", "arguments": { "connection": connection } }),
    );

    // **Polled to the `attaching` state, not slept towards it.** A fixed wait would pass for the
    // wrong reason twice over: too short and nothing is holding a claim yet, and an attach that
    // failed fast leaves a kernel record behind that a laxer check would accept. Each poll is
    // itself a second stateless request overlapping the first, so the status asserted here is the
    // contention this test is about.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut id = 1;
    let attaching = loop {
        let status = server.stateless_at(
            id,
            "tools/call",
            json!({ "name": "session_status", "arguments": {} }),
        );
        id += 1;
        assert_eq!(
            status.status,
            200,
            "a second stateless request was refused ({}) while the first was still running:              {}\n--- stderr ---\n{}",
            status.status,
            status.body,
            server.stderr()
        );
        let parked = status.result("tools/call")["structuredContent"]["sessions"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|s| s["kind"] == json!("kernel") && s["state"]["state"] == json!("attaching"))
            .and_then(|s| s["session_id"].as_str().map(str::to_owned));
        if let Some(id) = parked {
            break Some(id);
        }
        if Instant::now() >= deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    let Some(attaching) = attaching else {
        // The attach never parked — most likely the UDP port was taken on this host. Nothing to
        // assert about a park that did not happen, and the same stand-down the test below takes.
        skip("attach_kernel did not reach the parked state (port busy?)");
        return;
    };

    // The plain case, now that the park is established rather than assumed.
    let listed = server.stateless_at(id, "tools/list", json!({}));
    id += 1;
    assert_eq!(
        listed.status,
        200,
        "tools/list was refused ({}) alongside a parked attach: {}\n--- stderr ---\n{}",
        listed.status,
        listed.body,
        server.stderr()
    );

    // And the way out. `200` is not enough on its own here — a tool error is also carried on a
    // `200`, so a refusal inside the call would read as success at the HTTP layer.
    let ended = server.stateless_at(
        id,
        "tools/call",
        json!({ "name": "end_session", "arguments": { "session_id": attaching } }),
    );
    assert_eq!(
        ended.status, 200,
        "end_session is the only way out of a parked attach, and it was refused: {}",
        ended.body
    );
    let payload = ended
        .payload
        .as_ref()
        .expect("end_session answered with no JSON-RPC payload");
    assert!(
        !is_tool_error(payload),
        "end_session reported a tool error while reclaiming the parked attach: {}",
        ended.body
    );
}

/// Issue #61, end to end: a kernel attach whose target never dials in waits forever, and that
/// must cost exactly one session.
///
/// The wait is `WaitForEvent(INFINITE)` and nothing can interrupt it — `SetInterrupt` cannot
/// reach a wait that is still establishing the KD link — so the only way it ends is the process
/// ending. Before process-per-session that process was the server: every later tool call queued
/// behind the parked wait, `end_session` included, and the only recovery was restarting the
/// server. This asserts the two things that changed: other sessions still work, and
/// `end_session` actually ends it.
#[test]
fn a_kernel_attach_that_never_connects_costs_one_session_and_can_be_ended() {
    let Some(dump) = target_tier() else { return };
    let mut server = Server::started();

    // A KDNET connection nothing is listening on. The attach itself succeeds in milliseconds —
    // it is the wait for the target to dial *this* host that never returns.
    let attaching = server.send_request(
        "tools/call",
        json!({
            "name": "attach_kernel",
            "arguments": { "connection": "net:port=50007,key=1.1.1.1" },
        }),
    );

    // Wait for it to reach the parked state rather than assuming a timing. Read as a state, not
    // as a phrase: "attaching" is what the session *is*, where the sentence describing it is
    // several sentences long and rewritten whenever the advice changes.
    let deadline = Instant::now() + Duration::from_secs(30);
    let parked = loop {
        let status = server.tool_data("session_status", json!({}), STEP);
        let attaching = status["sessions"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|s| s["kind"] == "kernel" && s["state"]["state"] == "attaching");
        if attaching {
            break Some(status);
        }
        if Instant::now() >= deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    let Some(status) = parked else {
        // The attach failed outright instead of parking — most likely the UDP port was already
        // taken on this host. Nothing to assert about a park that did not happen.
        skip("attach_kernel did not reach the parked state (port 50007 busy?)");
        return;
    };
    let kernel_session = status["sessions"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|s| s["kind"] == "kernel")
        .and_then(|s| s["session_id"].as_str())
        .expect("the kernel session should be listed")
        .to_string();

    // The point. A parked session used to be the *server's* engine thread; now it is one worker,
    // and everything else carries on.
    let opened = server.call_tool("open_dump", json!({ "path": dump }), TARGET_STEP);
    assert_no_error(&opened, "open_dump while a kernel attach is parked");
    assert!(
        !is_tool_error(&opened),
        "a parked kernel attach must not block another session:\n{}",
        text_of(&opened["result"])
    );
    let dump_session = session_id_of(&opened["result"]);

    // …and the parked session reports itself honestly rather than as an ordinary pending open.
    // The distinction is two fields: the target has been claimed (`attaching`, not `opening`),
    // and this particular wait has no timeout and cannot be interrupted.
    let asked = server.tool_data(
        "session_status",
        json!({ "session_id": kernel_session }),
        STEP,
    );
    let parked = &asked["sessions"][0]["state"];
    assert_eq!(
        parked["state"], "attaching",
        "the target exists, so re-attaching would be a second attach: {asked}"
    );
    assert_eq!(
        parked["waits_indefinitely"], true,
        "a live kernel attach is the wait that cannot end on its own: {asked}"
    );

    // The recovery that did not exist before: `end_session` cannot be answered by a worker that
    // is parked, so the worker is killed. It has to come back, and the process has to be gone.
    let worker = engine_pid_of(&status, &kernel_session);
    let ended = server.tool_data(
        "end_session",
        json!({ "session_id": kernel_session }),
        Duration::from_secs(120),
    );
    assert_eq!(
        ended["released"], false,
        "a parked worker cannot let go of its target: {ended}"
    );
    assert_eq!(
        ended["worker_terminated"], true,
        "a parked session ends by terminating its worker: {ended}"
    );
    assert!(
        !process_alive(worker),
        "the parked engine worker (pid {worker}) is still running after end_session"
    );

    // The abandoned attach call is still outstanding; its session is gone, so it must come back
    // rather than hang forever.
    let answer = server.await_id(attaching, "attach_kernel", Duration::from_secs(60));
    assert_no_error(
        &answer,
        "the abandoned attach must be answered, not dropped",
    );

    server.tool_text(
        "end_session",
        json!({ "session_id": dump_session }),
        TARGET_STEP,
    );
}

/// A lease that runs out releases what the absent client left, and the next client gets a clean
/// server.
///
/// The claim the whole lease exists for, and the only one that costs a *target* when it is wrong.
/// The unit tests in `src/listen.rs` settle the state machine; the fast listener tier settles the
/// HTTP wiring. Neither can reach this, because it is the sweep meeting a real engine worker —
/// which is where the stdio role's teardown lives and where the listener had nothing but a
/// hand-run check against a guest.
///
/// **The target is a kernel attach nothing will answer**, deliberately. A parked attach is the
/// worst case in one move: the session exists, it holds a worker, and its wait cannot be
/// interrupted — so releasing it means terminating a process, not asking politely. A dump would
/// prove the timer and not the teardown.
///
/// **The grace is 32 seconds because that is nearly the floor.** The listener refuses to start
/// with a grace that could expire inside a call, and the bound is the call budget plus the time an
/// engine worker takes to come up (30s). Shrinking the budget to a second is what makes the floor
/// small enough to wait out; nothing here needs a longer one, since the attach is meant to park.
#[test]
fn a_lease_that_runs_out_releases_what_the_absent_client_left() {
    if target_tier().is_none() {
        return;
    }
    let mut server = Listener::start(&[
        ("WINDBG_MCP_CALL_TIMEOUT_SECS", "1"),
        ("WINDBG_MCP_LEASE_GRACE_SECS", "32"),
    ]);
    let client = server.initialize();

    // Its own port, because these tests run in parallel and a KDNET attach takes a UDP port for
    // the life of its session.
    let requested = server.call(
        Some(&client),
        "tools/call",
        json!({
            "name": "attach_kernel",
            "arguments": { "connection": "net:port=50009,key=1.1.1.1" },
        }),
    );
    // The *tool* is expected to report a failure — the attach parks, and the call budget here is
    // one second — but the **listener** has to have admitted it. Without this, a refusal from a
    // regression in the listener — a `401`, the `404` an ownership check answers with, the `409` a
    // teardown does — would fall through to the skip below and be reported as a busy port on the
    // host, and the one assertion in this file that costs a target would pass in silence.
    assert_eq!(
        requested.status,
        200,
        "the listener refused the attach ({}): {}\n--- stderr ---\n{}",
        requested.status,
        requested.body,
        server.stderr()
    );

    // Wait for the park rather than assuming a timing — and read it as a *state*, since the
    // sentence describing one is rewritten whenever the advice changes.
    let deadline = Instant::now() + Duration::from_secs(60);
    let parked = loop {
        let status = server.tool(&client, "session_status", json!({}));
        let found = status["sessions"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|s| s["kind"] == "kernel" && s["state"]["state"] == "attaching")
            .and_then(|s| s["session_id"].as_str().map(str::to_string));
        if found.is_some() {
            break found;
        }
        if Instant::now() >= deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(250));
    };
    let Some(parked) = parked else {
        // The attach failed outright instead of parking — most likely the UDP port was already
        // taken on this host. Nothing to assert about a park that did not happen.
        skip("attach_kernel did not reach the parked state (port 50009 busy?)");
        return;
    };
    let worker = server.tool(&client, "session_status", json!({ "session_id": parked }))["sessions"]
        [0]["engine_pid"]
        .as_u64()
        .unwrap_or_else(|| panic!("the parked session reports no engine pid"))
        as u32;
    assert!(
        process_alive(worker),
        "the parked engine worker (pid {worker}) should be running before the lease expires"
    );

    // And now the client vanishes: no goodbye, no requests. **Nothing below may speak to the
    // server** — every admitted request renews the lease, so a test that polled over HTTP would
    // hold the lease open for as long as it watched. The log is the one channel that costs
    // nothing.
    assert!(
        // The stable half of the line: the message now names *which* client's lease ran out, since
        // an expiry releases that client's sessions and no others.
        server.wait_for_stderr(
            "ran out; releasing the sessions it left open",
            Duration::from_secs(120),
        ),
        "the lease never expired — a client that vanished would hold this target for ever\n\
         --- stderr ---\n{}",
        server.stderr()
    );

    // The half that matters: the worker is gone. `release_leased` is `shutdown` without closing
    // the registry, so a parked attach ends the only way it can — its process terminated.
    let deadline = Instant::now() + Duration::from_secs(60);
    while process_alive(worker) {
        assert!(
            Instant::now() < deadline,
            "the lease expired but the parked engine worker (pid {worker}) is still running\n\
             --- stderr ---\n{}",
            server.stderr()
        );
        std::thread::sleep(Duration::from_millis(250));
    }

    // The old session id is not honoured after the sweep closed it. Without this the service
    // would keep it resident and every reconnect cycle would leave another behind.
    let stale = server.call(Some(&client), "tools/list", json!({}));
    assert_ne!(
        stale.status, 200,
        "a session the sweep closed was still served: {}",
        stale.body
    );

    // And the server is takeable again, with nothing left over. Both halves: a lease that
    // released the sessions but stayed `releasing` would refuse every client for ever, and one
    // that handed over sessions it had just closed would be worse.
    let next = server.initialize();
    assert_ne!(next, client);
    let status = server.tool(&next, "session_status", json!({}));
    assert!(
        status["sessions"].as_array().is_none_or(Vec::is_empty),
        "the next client inherited a session the sweep should have released: {status}"
    );
}

/// The handle an `open_dump` through the listener minted, named by whose it is.
fn opened_handle(opened: &Value, whose: &str) -> String {
    opened["session_id"]
        .as_str()
        .unwrap_or_else(|| panic!("`{whose}`'s open_dump minted no handle: {opened}"))
        .to_string()
}

/// The handles `session_status` reports to one client, which is the whole of what that client can
/// see of this server.
fn sessions_listed(server: &mut Listener, token: &str, mcp: &str) -> Vec<String> {
    server.tool_as(token, mcp, "session_status", json!({}))["sessions"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|s| s["session_id"].as_str().map(str::to_string))
        .collect()
}

/// Two credentials on one listener: neither can see, route to or end the other's session, and a
/// client that comes back adopts what it left.
///
/// Every rule here is unit-tested where it is decided — `Sessions::resolve` and `Sessions::snapshot`
/// in `src/engine.rs`, admission in `src/listen.rs`, the identity scope in `src/client.rs`. What
/// none of them reaches is the **call site**: an HTTP handler, one real registry, and two tokens on
/// one port. The gap has already cost a bug — the adoption diagnostic counted `local`'s sessions
/// for a *named* client, because the count was taken after the identity scope had closed, so the
/// one line an operator reads on reconnect described a client that was not reconnecting
/// (`FOLLOWUPS.md` item 29).
///
/// Debugger tier, and not by preference: every claim here needs a session that exists. A handle
/// another client cannot use has to be a handle, and an adoption counts **debug** sessions rather
/// than the MCP ones the protocol tier can mint on its own.
#[test]
fn two_clients_on_one_listener_keep_their_sessions_to_themselves() {
    let Some(dump) = target_tier() else {
        return;
    };
    // A second credential beside the unnamed one the helper always sets, which names `local`.
    let ci_token = format!("smoke-ci-{}", std::process::id());
    let mut server = Listener::start(&[("WINDBG_MCP_LISTEN_TOKEN_CI", &ci_token)]);
    let local_token = server.token.clone();
    assert!(
        server.wait_for_stderr("clients: ci, local", Duration::from_secs(30)),
        "this listener is supposed to hold two credentials; it says otherwise:\n{}",
        server.stderr()
    );

    let local_mcp = server.initialize_as(&local_token);
    let ci_mcp = server.initialize_as(&ci_token);
    assert_ne!(local_mcp, ci_mcp, "two clients, two MCP sessions");

    let opened = server.tool_as(
        &local_token,
        &local_mcp,
        "open_dump",
        json!({ "path": dump }),
    );
    let local_session = opened_handle(&opened, "local");
    let opened = server.tool_as(&ci_token, &ci_mcp, "open_dump", json!({ "path": dump }));
    let ci_session = opened_handle(&opened, "ci");
    assert_ne!(
        local_session, ci_session,
        "each client opened a session of its own"
    );

    // Seeing. A caller is shown its own sessions and nothing else — another client's handles would
    // be unusable, and listing them would say how many clients this server has and what they are
    // debugging.
    let seen_by_local = sessions_listed(&mut server, &local_token, &local_mcp);
    let seen_by_ci = sessions_listed(&mut server, &ci_token, &ci_mcp);
    assert_eq!(
        seen_by_local,
        vec![local_session.clone()],
        "`local` was shown something other than exactly its own session"
    );
    assert_eq!(
        seen_by_ci,
        vec![ci_session.clone()],
        "`ci` was shown something other than exactly its own session"
    );

    // The same question on `2026-07-28`, which reaches the registry by the other route: no MCP
    // session, so no task spawned to serve one, and the identity arrives with the request itself.
    // Both routes are asserted because the bug this test found was one of them losing it — a fix
    // that held for only one would make the boundary depend on which revision a client negotiated.
    let stateless = server.stateless_as(
        &ci_token,
        "tools/call",
        json!({ "name": "session_status", "arguments": {} }),
    );
    assert_eq!(
        stateless.status, 200,
        "a stateless call from `ci` was refused ({}): {}",
        stateless.status, stateless.body
    );
    let seen: Vec<String> = stateless.result("tools/call")["structuredContent"]["sessions"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|s| s["session_id"].as_str().map(str::to_string))
        .collect();
    assert_eq!(
        seen,
        vec![ci_session.clone()],
        "a stateless call must see its own client's sessions and no others: {}",
        stateless.body
    );

    // And asking after it by name is *unknown* rather than refused: the answer must not confirm a
    // session the caller may not touch, so it is the same one a handle that never existed gets.
    let asked = server.tool_as(
        &ci_token,
        &ci_mcp,
        "session_status",
        json!({ "session_id": local_session }),
    );
    assert_eq!(
        asked["unknown_handle"],
        json!(true),
        "another client's handle must come back unknown: {asked}"
    );
    assert!(
        asked["sessions"].as_array().is_some_and(Vec::is_empty),
        "and it must describe nothing: {asked}"
    );

    // Routing and ending are one check, since `end_session` resolves the handle before it ends
    // anything.
    let refused = server.tool_as(
        &ci_token,
        &ci_mcp,
        "end_session",
        json!({ "session_id": local_session }),
    );
    assert_eq!(
        refused["status"],
        json!("error"),
        "`ci` was allowed to end `local`'s session: {refused}"
    );
    assert!(
        refused["error"]["message"]
            .as_str()
            .is_some_and(|said| said.contains("unknown session handle")),
        "the refusal has to read as unknown rather than as someone else's: {refused}"
    );
    // The half that would have cost somebody a target: it is still there.
    assert_eq!(
        sessions_listed(&mut server, &local_token, &local_mcp),
        vec![local_session.clone()],
        "`ci`'s end_session reached `local`'s session after all"
    );

    // The MCP session id itself. A request bearing another client's is answered `404` — the same
    // status an id this server never issued gets, deliberately: from the caller's side "not yours"
    // and "not a session here" must be indistinguishable.
    let borrowed = server.call_as(&ci_token, Some(&local_mcp), "tools/list", json!({}));
    assert_eq!(
        borrowed.status, 404,
        "`ci` was served on `local`'s Mcp-Session-Id: {}",
        borrowed.body
    );

    // Coming back. `ci` says goodbye and returns inside the grace: what it left open is still open,
    // and it is the returning client's own sessions that the line describes.
    let farewell = server.goodbye_as(&ci_token, &ci_mcp);
    assert!(
        (200..300).contains(&farewell.status),
        "the DELETE was refused ({}): {}",
        farewell.status,
        farewell.body
    );
    let ci_again = server.initialize_as(&ci_token);
    assert_ne!(ci_again, ci_mcp, "a reconnect is a new MCP session");
    assert_eq!(
        sessions_listed(&mut server, &ci_token, &ci_again),
        vec![ci_session.clone()],
        "a client returning inside the grace adopts the session it left open"
    );

    // Read through `server_log` rather than off stderr, because that is the channel a client on
    // another machine has — and because the **count** in it is what was wrong: taken for `local` on
    // a named client's reconnect, an adoption of one session was reported as nothing having been
    // open.
    let page = server.tool_as(&ci_token, &ci_again, "server_log", json!({ "limit": 500 }));
    let said: Vec<String> = page["records"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|r| r["message"].as_str().map(str::to_string))
        .collect();
    assert!(
        said.iter()
            .any(|m| m.contains("adopted the 1 session(s) it had left open")),
        "the adoption line must count the returning client's own sessions: {said:?}"
    );
    assert!(
        !said.iter().any(|m| m.contains("nothing was open")),
        "`ci` came back to a session it had left open, so nothing may report otherwise: {said:?}"
    );

    // And each client can end what it opened, which is the same ownership rule read the other way
    // round — and the cleanup, so neither worker outlives this test.
    for (whose, token, mcp, session) in [
        ("local", &local_token, &local_mcp, &local_session),
        ("ci", &ci_token, &ci_again, &ci_session),
    ] {
        let ended = server.tool_as(token, mcp, "end_session", json!({ "session_id": session }));
        assert_eq!(
            ended["status"],
            json!("ok"),
            "`{whose}` could not end the session it opened: {ended}"
        );
    }
}

/// A profile-named attach opens the session it names, and the key never leaves this process.
///
/// The unit tests prove the resolution and the redaction; only this proves the two hold **over the
/// wire**, which is where the issue actually was. The target is deliberately unreachable, so the
/// attach parks — everything asserted here (the session exists, describes itself, and can be
/// ended) is true of a parked attach, and a park costs no VM.
///
/// Two claims, and the second is the one that matters:
///
/// - `session_status` names the *profile*, so a caller can still tell two kernel sessions apart
///   without either of them printing a key.
/// - The key appears on neither the transport nor the log, at any point in the session's life.
///   That is asserted against every line the server ever wrote, not against one result, because
///   the failure this guards is a key surfacing somewhere nobody looked.
#[test]
fn a_profile_attach_names_its_target_without_disclosing_the_key() {
    if target_tier().is_none() {
        return;
    }
    let (_, key) = FAKE_PROFILE;
    let mut server = Server::started_with(&profile_env());

    let attaching = server.send_request(
        "tools/call",
        json!({
            "name": "attach_kernel",
            "arguments": { "profile": "smoke-kdnet" },
        }),
    );

    let deadline = Instant::now() + Duration::from_secs(30);
    let parked = loop {
        let status = server.tool_text("session_status", json!({}), STEP);
        if status.contains("waiting") && status.contains("kernel target") {
            break Some(status);
        }
        if Instant::now() >= deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    let Some(status) = parked else {
        skip("the profile attach did not reach the parked state (port 50008 busy?)");
        return;
    };

    // Named for the profile *as configured* (`smoke_kdnet`), not as the caller spelled it
    // (`smoke-kdnet`) — the point is that the session is identifiable, and the configured name is
    // the one an operator can look up.
    assert!(
        status.contains("smoke_kdnet"),
        "the session should describe itself by the profile it was opened from:\n{status}"
    );
    assert!(
        status.contains("key=<redacted>"),
        "the connection should be reported with its key masked, not omitted:\n{status}"
    );

    let kernel_session = status
        .lines()
        .find(|l| l.contains("kernel target"))
        .map(|l| l.split_whitespace().next().unwrap_or_default().to_string())
        .expect("the kernel session should be listed");
    server.tool_text(
        "end_session",
        json!({ "session_id": kernel_session }),
        Duration::from_secs(120),
    );
    // The abandoned attach is still outstanding; its session is gone, so it has to be answered.
    server.await_id(attaching, "attach_kernel", Duration::from_secs(60));
    // A round trip after the teardown, for the same reason as in the protocol tier: the log is
    // drained by an unordered thread, and a negative assertion passes on a line nobody read yet.
    server.tool_text("session_status", json!({}), STEP);

    assert!(
        !server.stdout_lines().iter().any(|l| l.contains(key)),
        "the profile's key reached the JSON-RPC transport"
    );
    assert!(
        !server.stderr().contains(key),
        "the profile's key reached the log:\n{}",
        server.stderr()
    );
}

/// A worker is a process holding a debug session — and, for a launch or an attach, a debuggee
/// whose fate is tied to its debugger. None may outlive the client connection that opened it, or
/// every disconnect leaks a debugger process.
#[test]
fn engine_workers_do_not_outlive_the_connection() {
    let Some(dump) = target_tier() else { return };
    let mut server = Server::started();
    let session = server.open_session("open_dump", json!({ "path": dump }), TARGET_STEP);
    let status = server.tool_data("session_status", json!({}), TARGET_STEP);
    let worker = engine_pid_of(&status, &session);
    assert!(process_alive(worker), "the worker should be running");

    assert_eq!(
        server.shutdown(),
        Some(0),
        "clean disconnect should be a clean exit"
    );

    // Two ways it can be gone, and this asserts only the outcome: shutdown asked it to release
    // and then ended it, or — for a worker shutdown never saw — its own request channel closed as
    // the supervisor exited. Either way, no process is left behind.
    let deadline = Instant::now() + Duration::from_secs(20);
    while process_alive(worker) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        !process_alive(worker),
        "engine worker pid {worker} outlived the connection — every disconnect would leak one"
    );
}

/// A call that names no session is still routed to one, and the transcript has to say which.
///
/// Omitting `session_id` is not "no session" — it accepts whatever the current one is — and it is
/// the ordinary way this server is driven. Recording only the argument would put `null` on every
/// such call *and on every event derived from it*, so with two targets open a transcript could not
/// answer the question it exists for: which one was read, and which one was changed.
///
/// Two sessions, deliberately, because with one open the bug is invisible — any answer at all
/// would be the right one.
#[test]
fn a_call_that_names_no_session_records_the_one_it_reached() {
    let Some(dump) = target_tier() else { return };
    let transcript = marker_path("routing");
    let _ = std::fs::remove_file(&transcript);
    let mut server = Server::started_with(&[(
        "WINDBG_MCP_TRANSCRIPT",
        transcript.to_str().expect("a UTF-8 temp path"),
    )]);

    let first = server.open_session("open_dump", json!({ "path": dump }), TARGET_STEP);
    let second = server.open_session("open_dump", json!({ "path": dump }), TARGET_STEP);
    assert_ne!(first, second, "two sessions, or this proves nothing");
    // No `session_id`: this goes to the newest usable session, which is the second one.
    server.tool_text("modules", json!({ "filter": "nt" }), TARGET_STEP);
    assert_eq!(server.shutdown(), Some(0));

    let events: Vec<Value> = std::fs::read_to_string(&transcript)
        .unwrap_or_else(|e| panic!("no transcript at {}: {e}", transcript.display()))
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("not JSONL ({e}): {l}")))
        .collect();
    let result = events
        .iter()
        .find(|r| r["event"] == "tool_result" && r["tool"] == "modules")
        .unwrap_or_else(|| panic!("the unnamed call is not in the transcript: {events:#?}"));
    assert_eq!(
        result["session"], second,
        "the result must name the session the call was routed to, not `null` because the caller \
         named none: {result}"
    );
    // The openers too: an opener mints a session rather than routing to one, and the record has
    // to carry it either way or the call that created a target cannot be joined to it.
    let opened: Vec<&Value> = events
        .iter()
        .filter(|r| r["event"] == "tool_result" && r["tool"] == "open_dump")
        .collect();
    assert_eq!(opened.len(), 2, "{events:#?}");
    assert_eq!(opened[0]["session"], first, "{}", opened[0]);
    assert_eq!(opened[1]["session"], second, "{}", opened[1]);
    let _ = std::fs::remove_file(&transcript);
}

/// What a transcript says about the two teardowns, which is the pair that matters most in a file
/// nobody was watching being written.
///
/// A **disconnect** has no caller to answer, so the transcript is the only account of what became
/// of each target — `released` false means a worker was killed still holding one, which for a live
/// kernel is a machine left halted. That record has to be there, per session, and not only the
/// `shutdown` line saying a teardown began.
///
/// An **`end_session`** must not then be followed by a "lost its engine" record. Its worker is
/// terminated on purpose, so the pipe reaching EOF is the last step of an orderly teardown rather
/// than a loss, and a red line after every successful release would describe a failure that did
/// not happen. Both halves in one test because they are the same claim from opposite ends: the
/// transcript reports the teardown that happened and no teardown that did not.
#[test]
fn a_transcript_records_both_teardowns_and_invents_neither() {
    let Some(dump) = target_tier() else { return };

    // Ended by hand, then disconnected. Two sessions so the disconnect has one of its own.
    let transcript = marker_path("teardowns");
    let _ = std::fs::remove_file(&transcript);
    let mut server = Server::started_with(&[(
        "WINDBG_MCP_TRANSCRIPT",
        transcript.to_str().expect("a UTF-8 temp path"),
    )]);
    let ended = server.open_session("open_dump", json!({ "path": dump }), TARGET_STEP);
    let abandoned = server.open_session("open_dump", json!({ "path": dump }), TARGET_STEP);
    server.tool_text("end_session", json!({ "session_id": ended }), TARGET_STEP);
    assert_eq!(server.shutdown(), Some(0));

    let events: Vec<Value> = std::fs::read_to_string(&transcript)
        .unwrap_or_else(|e| panic!("no transcript at {}: {e}", transcript.display()))
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("not JSONL ({e}): {l}")))
        .collect();
    let for_session = |session: &str, event: &str| -> Vec<Value> {
        events
            .iter()
            .filter(|r| r["event"] == event && r["session"] == session)
            .cloned()
            .collect()
    };

    // The session the client ended, and the one it walked away from, both accounted for.
    for (session, how) in [(&ended, "end_session"), (&abandoned, "the disconnect")] {
        let ends = for_session(session, "session_end");
        assert_eq!(
            ends.len(),
            1,
            "{how} should have recorded exactly one end for {session}: {events:#?}"
        );
        assert_eq!(
            ends[0]["released"], true,
            "a dump session lets go cleanly, and the record is what says so: {}",
            ends[0]
        );
    }

    // And no invented loss. The worker of an ended session is terminated deliberately, so its
    // pipe closing is the teardown finishing rather than an engine that died.
    let lost = for_session(&ended, "worker_lost");
    assert!(
        lost.is_empty(),
        "an orderly end_session reported a lost engine: {lost:#?}"
    );
    let _ = std::fs::remove_file(&transcript);
}

/// A session reclaimed to pay for a new one is a teardown nobody asked for, and the transcript is
/// the only place it is reported.
///
/// The third way a target is let go, after `end_session` and a disconnect: opening at the session
/// limit reclaims the oldest idle one, in a background task, with no caller to answer and nothing
/// in the tool result to say it happened. Whether that target was released cleanly or its worker
/// was killed still holding it is exactly the question a transcript exists for — and for a live
/// kernel it is the difference between a machine that came back and one that is sitting halted.
#[test]
fn a_session_reclaimed_at_the_limit_records_what_became_of_it() {
    let Some(dump) = target_tier() else { return };
    let transcript = marker_path("reclaimed");
    let _ = std::fs::remove_file(&transcript);
    let mut server = Server::started_with(&[(
        "WINDBG_MCP_TRANSCRIPT",
        transcript.to_str().expect("a UTF-8 temp path"),
    )]);

    // One past the limit the server documents, so the oldest idle session pays for the last open.
    const MAX_SESSIONS: usize = 4;
    let opened: Vec<String> = (0..=MAX_SESSIONS)
        .map(|_| server.open_session("open_dump", json!({ "path": dump }), TARGET_STEP))
        .collect();
    let reclaimed = &opened[0];

    // The reclamation releases in a task of its own, so its record can land after the open that
    // provoked it returned. Waited for rather than assumed — and the failure if it never comes is
    // this assertion, not a confusing one later.
    let deadline = Instant::now() + Duration::from_secs(30);
    let ended = loop {
        let found = std::fs::read_to_string(&transcript)
            .unwrap_or_default()
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .find(|r| r["event"] == "session_end" && r["session"] == *reclaimed);
        match found {
            Some(record) => break record,
            None if Instant::now() >= deadline => panic!(
                "session {reclaimed} was reclaimed to make room and the transcript never said \
                 what became of it:\n{}",
                std::fs::read_to_string(&transcript).unwrap_or_default()
            ),
            None => std::thread::sleep(Duration::from_millis(100)),
        }
    };
    assert_eq!(
        ended["released"], true,
        "a dump session lets go cleanly even when it is reclaimed rather than ended: {ended}"
    );
    // And the handle now says it is gone, which is the caller-visible half of the same fact.
    let status = server.tool_data(
        "session_status",
        json!({ "session_id": reclaimed }),
        TARGET_STEP,
    );
    assert_eq!(status["sessions"][0]["live"], false, "{status}");

    assert_eq!(server.shutdown(), Some(0));
    let _ = std::fs::remove_file(&transcript);
}

/// A worker whose supervisor died without saying goodbye still lets go and exits.
///
/// This is the mechanism the whole teardown story now rests on. The supervisor does not terminate
/// its workers when it goes — `Sessions::spawn` deliberately does not set `kill_on_drop` — because
/// killing pre-empts the release: a worker the supervisor never got round to asking (one that
/// registered after shutdown had walked the registry, say) would die with its target still
/// attached, and a live kernel left attached-but-halted is a machine that needs rebooting.
///
/// So the guarantee is the worker's own: EOF on its request channel means "the supervisor is
/// gone", and it asks its engine to release before exiting, bounded. Killed outright here, the
/// supervisor contributes nothing — no shutdown, no `EndSession`, not even a channel closed
/// cleanly — which is exactly the case where nothing else can stand in.
#[test]
fn a_worker_lets_go_and_exits_when_its_supervisor_is_killed_outright() {
    let Some(dump) = target_tier() else { return };
    let mut server = Server::started();
    let session = server.open_session("open_dump", json!({ "path": dump }), TARGET_STEP);
    let status = server.tool_data("session_status", json!({}), TARGET_STEP);
    let worker = engine_pid_of(&status, &session);
    assert!(process_alive(worker), "the worker should be running");

    server.kill_supervisor();

    // Generous against the worker's own release budget (`ABRUPT_EXIT_RELEASE`, 5s), because what
    // is under test is that it exits at all without being killed, not how fast.
    let deadline = Instant::now() + Duration::from_secs(30);
    while process_alive(worker) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        !process_alive(worker),
        "engine worker pid {worker} outlived a killed supervisor — with nothing terminating it, \
         EOF on its request channel is the only thing that ends it, and it did not"
    );
}

/// The `isError` contract, on the wire. A failure the model can act on must arrive as a *result*
/// flagged `isError`, never as a JSON-RPC error the model never really sees.
///
/// Both halves are exercised: a call with no session at all (refused by the supervisor, which now
/// knows there is nowhere to route it) and a command a real engine rejects.
#[test]
fn a_failed_debugger_operation_is_a_tool_error_not_a_protocol_error() {
    let Some(dump) = target_tier() else { return };
    let mut server = Server::started();

    // Nothing is open, so there is no session to route to. That is the model's to fix — by
    // opening one — so it belongs in the result, with the list of tools that would.
    let response = server.call_tool("go", json!({}), TARGET_STEP);
    assert_no_error(
        &response,
        "go with no session (a routing failure is a tool result, not a protocol error)",
    );
    assert!(
        is_tool_error(&response),
        "a call with no session must set isError, got {response}"
    );
    let text = text_of(&response["result"]);
    assert!(
        text.contains("open_dump"),
        "a tool error must explain itself so the model can correct: {response}"
    );

    // And the other half: a real engine failure, carrying the engine's own text. `~` is
    // user-mode-only, so DbgEng rejects it against this kernel dump.
    let session_id = server.open_session("open_dump", json!({ "path": dump }), TARGET_STEP);
    let unsupported = server.call_tool("threads", json!({ "session_id": session_id }), TARGET_STEP);
    assert_no_error(&unsupported, "threads on a kernel dump");
    assert!(
        is_tool_error(&unsupported),
        "a command DbgEng cannot run must set isError, got {unsupported}"
    );
    assert!(
        !text_of(&unsupported["result"]).trim().is_empty(),
        "the failure must explain itself: {unsupported}"
    );

    // The session survives its own failed command — a worker that died on a bad command would
    // turn every tool error into a lost target.
    let after = server.call_tool("modules", json!({ "session_id": session_id }), TARGET_STEP);
    assert!(
        !is_tool_error(&after),
        "the session must survive a failed command:\n{}",
        text_of(&after["result"])
    );
}

/// A pool query's walk is bounded by **this server's** deadline, not by the walker's own default
/// ([#75](https://github.com/glslang/windbg-mcp/issues/75)).
///
/// Asserted against the worker's log rather than against the answer, because on a dump the number
/// has no visible consequence: the pool is local memory and any walk finishes in well under a
/// second, so every budget from 15s to 120s produces the identical result. Only a live kernel makes
/// the difference observable in an answer — which is exactly why this shipped wrong. `Pool` carried
/// no patience at all and quietly took 120s however long its caller was willing to wait, and no
/// test that looked at results could have seen it.
///
/// So this checks the one thing that *is* observable here: the figure the worker derived, which is
/// the whole chain — the supervisor filling the slot in as it writes the request, and the worker
/// turning it into a walk deadline. The query itself is allowed to fail (the sample dump has no
/// symbols for the pool layout on a CI machine, and resolving them is the live tier's job); the
/// budget is computed and logged before any of that is attempted.
#[test]
fn a_pool_walk_takes_this_servers_deadline_not_the_walkers_default() {
    let Some(dump) = target_tier() else { return };
    // 60s of call budget: enough that the 15s headroom leaves a distinctive 45s, and short enough
    // that taking the walker's 120s default would be the bug this pins — a walk outliving its
    // caller.
    let mut server = Server::started_with(&[
        ("WINDBG_MCP_CALL_TIMEOUT_SECS", "60"),
        ("RUST_LOG", "windbg_mcp=debug"),
    ]);
    let session = server.open_session("open_dump", json!({ "path": dump }), TARGET_STEP);

    // Not `tool_text`: whether the walk itself succeeds depends on symbols this tier does not
    // require, and the budget is derived before the first pool page is read either way.
    let _ = server.call_tool(
        "pool_census",
        json!({ "session_id": session, "refresh": true }),
        TARGET_STEP,
    );

    assert!(
        server.wait_for_stderr("pool walk budget", Duration::from_secs(20)),
        "the worker logged no walk budget at all, so the query reached the walker without one \
         and took its 120s default:\n--- stderr ---\n{}",
        server.stderr()
    );
    let log = server.stderr();
    let budget = log
        .lines()
        .find_map(|line| line.split("pool walk budget ").nth(1))
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or_else(|| panic!("no budget on the line that carries it:\n{log}"));
    // A range, not the exact figure: the patience the supervisor sends is what is left of the 60s
    // when the request is *written*, so the milliseconds already spent come off it. Wide enough to
    // ignore those, narrow enough that neither the 15s floor nor the walker's 120s default is
    // inside it. Parsed from `Duration`'s own rendering, so a budget in milliseconds or
    // microseconds fails to parse rather than passing as a small number of seconds.
    let seconds: f64 = budget
        .strip_suffix('s')
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("`{budget}` is not a whole-seconds walk budget"));
    assert!(
        (40.0..=46.0).contains(&seconds),
        "the worker derived a {seconds}s walk budget; the 60s call timeout less the 15s headroom \
         the reply needs is ~45s. 120s means the walker's default, 15s means no patience arrived."
    );
    server.tool_text("end_session", json!({ "session_id": session }), TARGET_STEP);
}

/// A pool query with no time left to walk in is **refused**, not floored to a headroom and run for
/// a caller who has already gone.
///
/// The budget borrowed the bounded command's floor at first, which is right *there* — zero disables
/// that watchdog, so an unbounded command is the worse outcome — and wrong here, where zero merely
/// stops the walk at its first check. Floored, a 10s call budget bought a 15s walk: #75's own
/// complaint at the small end. And it bought nothing for it, since dbgscope caches complete
/// snapshots only, so the truncated result is discarded and the next query walks from scratch
/// regardless.
///
/// A 10s call budget is entirely reply headroom, so this needs no queue wait to stage — which is
/// what keeps it in the tier that runs on a push. The open has to land inside that budget too; if
/// it does not, the test skips rather than reporting a failure about the wrong thing.
#[test]
fn a_pool_query_with_no_time_to_walk_is_refused_rather_than_run() {
    let Some(dump) = target_tier() else { return };
    let mut server = Server::started_with(&[("WINDBG_MCP_CALL_TIMEOUT_SECS", "10")]);

    let opened = server.call_tool("open_dump", json!({ "path": dump }), TARGET_STEP);
    assert_no_error(&opened, "open_dump");
    if is_tool_error(&opened) {
        skip("the sample dump did not open inside a 10s call budget on this machine");
        return;
    }
    let session = session_id_of(&opened["result"]);

    // `refresh`, so the cached snapshot cannot answer it and a walk is unavoidable.
    let response = server.call_tool(
        "pool_census",
        json!({ "session_id": session, "refresh": true }),
        TARGET_STEP,
    );
    assert_no_error(&response, "pool_census with no walk budget");
    let text = text_of(&response["result"]);
    assert!(
        is_tool_error(&response) && text.contains("was not run"),
        "a pool query that must walk, reaching the engine with no time to walk in, should be \
         refused with an explanation naming the call timeout — not floored to a headroom and run \
         for nobody:\n{text}"
    );
    assert!(
        text.contains("WINDBG_MCP_CALL_TIMEOUT_SECS"),
        "and the refusal has to name the knob that fixes it:\n{text}"
    );

    // The session is untouched by the refusal — nothing was read, so nothing is in a odd state.
    let after = server.call_tool("modules", json!({ "session_id": session }), TARGET_STEP);
    assert!(
        !is_tool_error(&after),
        "the session should be unaffected by a refused query:\n{}",
        text_of(&after["result"])
    );
    server.tool_text("end_session", json!({ "session_id": session }), TARGET_STEP);
}

/// The interrupt, end to end: a command that would run for hours is stopped **on request**, the
/// call that started it gets its partial output back as a result, and the session takes the next
/// call at once.
///
/// This is the only place the whole mechanism exists. dbgscope proves `SetInterrupt` reaches a
/// running command; what is unproven there is everything that makes it usable from a client — that
/// the interrupt travels on the session's queue and is *answered by the worker's request reader*
/// rather than queued behind the very operation it means to stop, and that the binding to the
/// running job survives the round trip. Queue it like an ordinary op and every assertion below
/// still passes except the one that matters: the interrupt would be read after the command ended.
///
/// Fast by construction — the interrupt lands in milliseconds, so this stays in the tier that runs
/// on a `WINDBG_MCP_SMOKE_DUMP=1` push rather than in the ignored one that waits out deadlines. It
/// borrows that tier's runaway helpers (below) because the probe is the same: a `.for` that polls
/// for the break and leaves its progress in `$t0`.
#[test]
fn a_running_command_is_interrupted_on_request_and_frees_its_session() {
    let Some(dump) = target_tier() else { return };
    // A short call budget so a failure fails *fast*: if the interrupt never lands, the watchdog
    // ends the runaway at the 15s floor and the assertions below say so, instead of this test
    // sitting out five minutes of the default timeout.
    let mut server = Server::started_with(&[("WINDBG_MCP_CALL_TIMEOUT_SECS", "30")]);
    let session = server.open_session("open_dump", json!({ "path": dump }), TARGET_STEP);

    // An idle session says so and does nothing. Deterministic: the open above has been answered
    // and nothing else is outstanding.
    let idle = server.tool_text(
        "interrupt",
        json!({ "session_id": session }),
        Duration::from_secs(20),
    );
    assert!(
        idle.contains("Nothing was running"),
        "an idle session has nothing to interrupt, and should say so rather than raise a break \
         the next call would wear:\n{idle}"
    );

    // Now the real thing. Sent without waiting, because the interrupt has to reach a session that
    // is *busy* — which is the arrangement the whole design is about.
    let started = Instant::now();
    let runaway = server.send_request(
        "tools/call",
        json!({
            "name": "execute",
            "arguments": { "command": runaway_command("$t0"), "session_id": session },
        }),
    );

    // Retried until it reports it reached something, rather than sent once after a sleep: the
    // command is queued the instant the request is written, but the worker claims it a moment
    // later, and an interrupt that arrives in that gap correctly binds to nothing. Racing it is
    // the test's problem, not the server's.
    let interrupt_deadline = Instant::now() + Duration::from_secs(10);
    let raised = loop {
        std::thread::sleep(Duration::from_millis(100));
        let reply = server.tool_text(
            "interrupt",
            json!({ "session_id": session }),
            Duration::from_secs(20),
        );
        if reply.contains("Interrupted") {
            break reply;
        }
        assert!(
            Instant::now() < interrupt_deadline,
            "10s of interrupts all found the session idle while a command that runs for hours was \
             outstanding — the interrupt is being queued behind it instead of answered by the \
             reader:\n{reply}"
        );
    };
    // The interrupt answers while the command it stopped is still outstanding. That is the part
    // that cannot be true if the request is queued.
    assert!(
        raised.contains("Ctrl+Break"),
        "the interrupt should say what it did:\n{raised}"
    );

    let response = server.await_id(runaway, "the interrupted command", Duration::from_secs(60));
    let elapsed = started.elapsed();
    assert_no_error(&response, "an interrupted command");
    let out = text_of(&response["result"]);
    assert!(
        !is_tool_error(&response),
        "an interrupted command must come back as a result carrying what it reached, not as a \
         failure — the interrupt is not an error condition ({elapsed:?}):\n{out}"
    );
    assert!(
        out.contains("interrupted on request"),
        "the caller of the interrupted command is the one who cannot otherwise know why their \
         result is short, so it has to say:\n{out}"
    );
    // The watchdog's floor is 15s (30s call budget less the headroom), so anything under that
    // could only have been the request. Without this the test would pass on a run where the
    // interrupt did nothing and the deadline did all the work.
    assert!(
        elapsed < Duration::from_secs(14),
        "the command took {elapsed:?}, which is the watchdog's floor rather than the interrupt — \
         this run proves nothing about the request path"
    );
    assert!(
        !out.contains("interrupted after"),
        "and it carries the watchdog's note, so it was the deadline that ended it:\n{out}"
    );

    // Proof it was cut short rather than having finished: the loop counter, as in the bounded
    // tier. A note alone would be produced by an interrupt the engine ignored.
    let counter = server.tool_text(
        "execute",
        json!({ "command": "r $t0", "session_id": session }),
        TARGET_STEP,
    );
    let t0 = pseudo_register(&counter, "$t0")
        .unwrap_or_else(|| panic!("could not read $t0 back from:\n{counter}"));
    println!("interrupted after {elapsed:?}, $t0 = {t0:#x} of {RUNAWAY_ITERATIONS:#x}");
    assert!(t0 > 0, "the loop never started ($t0 = {t0:#x})");
    assert!(
        t0 < RUNAWAY_ITERATIONS,
        "the loop ran to completion ($t0 = {t0:#x}) — nothing cut it short"
    );

    // And the session is genuinely free, not merely answering: `r $t0` above already ran on it,
    // and this is the call that would have been aborted had the break been left pending.
    let after = server.call_tool("modules", json!({ "session_id": session }), TARGET_STEP);
    assert!(
        !is_tool_error(&after),
        "the session was not usable after the interrupt:\n{}",
        text_of(&after["result"])
    );
    server.tool_text("end_session", json!({ "session_id": session }), TARGET_STEP);
}

// ---- tier 3: the bounded-command path -----------------------------------------
//
// These deliberately run a command that would take hours and wait for a watchdog to cut it short,
// so they are `#[ignore]`d rather than gated by an env var — they cost minutes, and no CI runner
// should pay that on every push:
//
//     $env:WINDBG_MCP_SMOKE_DUMP = "1"
//     cargo test --test mcp_smoke -- --ignored --nocapture --test-threads=1 bounded
//
// dbgscope proves the primitive (`execute_command_bounded` aborts a runaway command, and the next
// command survives it). What is unproven *there* is this server's wiring of it, and that wiring is
// now split across two processes: the supervisor computes the budget from what is left of the
// caller's timeout after queue wait, and the worker arms the watchdog with it. Only the shipped
// binary contains both halves, which is why these moved out of `src/engine.rs`.

/// A deliberately runaway command: a tight `.for` in the expression evaluator, which is genuinely
/// CPU-bound and polls for Ctrl+Break exactly as a real runaway command does.
///
/// A broad `s` memory search — the wedge that motivated all of this — is the wrong probe despite
/// being the motivating case: it skips unmapped ranges, so even a whole-address-space search
/// returns almost immediately on this dump. The `.for` also leaves its progress in `$t0`, which is
/// what proves the interruption.
///
/// Sized to run for hours, so "did not finish" cannot mean "finished early on a fast host".
const RUNAWAY_ITERATIONS: u64 = 0x4000_0000;

fn runaway_command(counter: &str) -> String {
    format!(
        ".for (r {counter} = 0; @{counter} < 0x{RUNAWAY_ITERATIONS:x}; r {counter} = @{counter} + 1) {{ }}"
    )
}

/// Reads a user pseudo-register (`$t0`, `$t1`) as a number from `r $tN` output. `None` if the
/// engine printed something unexpected, so a caller can tell "unreadable" from "zero".
fn pseudo_register(text: &str, name: &str) -> Option<u64> {
    text.split_whitespace()
        .find_map(|tok| tok.strip_prefix(&format!("{name}=")))
        .and_then(|v| u64::from_str_radix(&v.replace('`', ""), 16).ok())
}

/// The whole point of the bounded path, end to end through the shipped binary: a command that
/// would run for hours comes back to the caller *as a result* (not as a timeout), and the session
/// is usable afterwards.
#[test]
#[ignore = "runs a command out to the watchdog deadline; run manually with --ignored"]
fn a_bounded_runaway_command_aborts_and_leaves_its_session_usable() {
    let Some(dump) = target_tier() else { return };
    // 30s of call budget leaves the watchdog its 15s floor, which keeps the test short while
    // still exercising the real arithmetic rather than a special case.
    let mut server = Server::started_with(&[("WINDBG_MCP_CALL_TIMEOUT_SECS", "30")]);
    let session = server.open_session("open_dump", json!({ "path": dump }), TARGET_STEP);

    let started = Instant::now();
    let response = server.call_tool(
        "execute",
        json!({ "command": runaway_command("$t0"), "session_id": session }),
        Duration::from_secs(120),
    );
    let elapsed = started.elapsed();
    assert_no_error(&response, "a bounded runaway command");
    let out = text_of(&response["result"]);
    assert!(
        !is_tool_error(&response),
        "a bounded runaway command must return a result, not a timeout ({elapsed:?}):\n{out}"
    );

    // Proof of interruption is the loop counter, not the clock and not the note: the note is
    // appended whenever the watchdog *attempted* an interrupt, so an interrupt the engine ignored
    // would still produce it.
    let counter = server.tool_text(
        "execute",
        json!({ "command": "r $t0", "session_id": session }),
        TARGET_STEP,
    );
    let t0 = pseudo_register(&counter, "$t0")
        .unwrap_or_else(|| panic!("could not read $t0 back from:\n{counter}"));
    println!(
        "bounded command returned after {elapsed:?}, $t0 = {t0:#x} of {RUNAWAY_ITERATIONS:#x}"
    );
    assert!(t0 > 0, "the loop never started ($t0 = {t0:#x})");
    assert!(
        t0 < RUNAWAY_ITERATIONS,
        "the loop ran to completion ($t0 = {t0:#x}) — the watchdog did not cut it short, so the \
         rest of this test would prove nothing"
    );
    assert!(
        out.contains("interrupted after"),
        "no interruption note despite a loop that stopped short:\n{out}"
    );

    // The wedge itself. Before the bounded path this is where every later call timed out, and
    // the only recovery was restarting the server.
    let after = server.call_tool("modules", json!({ "session_id": session }), TARGET_STEP);
    assert!(
        !is_tool_error(&after),
        "the session was not freed by the abort — this is the wedge:\n{}",
        text_of(&after["result"])
    );
    server.tool_text("end_session", json!({ "session_id": session }), TARGET_STEP);
}

/// The queue-aware half of the budget, which is the part that has no equivalent in dbgscope: a
/// bounded command that spent most of the call budget waiting its turn must still abort *before*
/// its caller's timeout, not one full budget after it was dequeued.
///
/// Budgeting from the full call timeout instead of the remainder passes every assertion in the
/// test above and fails here — the command would abort well after the caller had already given
/// up, with the session pinned in between.
///
/// The queue is per-session now, so the blocker has to be sent to the *same* session. A job in
/// another session would not queue behind anything, which is the whole point of the change.
#[test]
#[ignore = "runs a command out to the watchdog deadline; run manually with --ignored"]
fn a_bounded_command_queued_behind_another_job_still_beats_its_caller() {
    let Some(dump) = target_tier() else { return };
    const CALL_TIMEOUT: Duration = Duration::from_secs(60);

    const QUEUE_WAIT: Duration = Duration::from_secs(30);

    let mut server = Server::started_with(&[("WINDBG_MCP_CALL_TIMEOUT_SECS", "60")]);
    let session = server.open_session("open_dump", json!({ "path": dump }), TARGET_STEP);

    // Occupy the session for a known time, then queue the runaway behind it. `.sleep` blocks the
    // engine exactly the way a long command does, and unlike a calibrated spin its duration does
    // not depend on the host — which matters, because the arithmetic under test is about *how
    // long* the wait was.
    //
    // `0n` is not decoration: the MASM evaluator's default base is **hex**, so a bare `.sleep
    // 30000` sleeps for 0x30000 ms — three and a half minutes, not thirty seconds.
    let blocker = server.send_request(
        "tools/call",
        json!({
            "name": "execute",
            "arguments": {
                "command": format!(".sleep 0n{}", QUEUE_WAIT.as_millis()),
                "session_id": session,
            },
        }),
    );

    // Two tool calls in flight at once are dispatched concurrently and reach the session's queue
    // in whichever order wins the race, so "sent first" is not "queued first". This test needs
    // the blocker to be the one holding the engine — with the order reversed it silently becomes
    // the unqueued case and proves nothing — so give it a head start it cannot lose.
    std::thread::sleep(Duration::from_secs(3));

    let started = Instant::now();
    let response = server.call_tool(
        "execute",
        json!({ "command": runaway_command("$t0"), "session_id": session }),
        Duration::from_secs(240),
    );
    let elapsed = started.elapsed();
    let out = text_of(&response["result"]);
    assert_no_error(&response, "a queued bounded runaway command");
    assert!(
        out.contains("interrupted after"),
        "the queued command was not interrupted after {elapsed:?}:\n{out}"
    );
    // The premise: it really did wait behind the blocker. Without this the test would quietly
    // degrade into the unqueued case — which passes the assertion below for the wrong reason —
    // if `.sleep` ever stopped blocking or the head start stopped being enough.
    assert!(
        elapsed > QUEUE_WAIT.mul_f32(0.6),
        "the runaway did not queue behind the blocker ({elapsed:?}) — this run proves nothing \
         about the queue-aware budget"
    );
    // And the claim.
    assert!(
        elapsed < CALL_TIMEOUT,
        "the abort landed after the caller's {CALL_TIMEOUT:?} timeout ({elapsed:?}) — the \
         watchdog budget did not account for the {QUEUE_WAIT:?} spent queued"
    );

    let _ = server.await_id(blocker, "the blocking command", Duration::from_secs(120));
    server.tool_text("end_session", json!({ "session_id": session }), TARGET_STEP);
}

/// What the bounded path *costs* a command that was never going to run away — the evidence behind
/// the coverage split in `DECISIONS.md` (2026-08-02), kept as a test so a dbgscope change to the
/// watchdog can be re-measured rather than re-argued.
///
/// The cost is not a constant overhead but a **quantization**: dbgscope's watchdog thread checks
/// its `done` flag, then sleeps 200ms, so a command takes `ceil(d / 200ms) * 200ms`. The tax on a
/// point query is best read as: anything that takes 1–200ms now takes 200ms.
///
/// Prints rather than asserts. The cost belongs to dbgscope's watchdog, not to this crate, and a
/// threshold pinned here would fail on an unrelated host difference. Measured through the tool
/// surface, so the numbers now include this server's own per-call overhead — one IPC round trip
/// on top of what the in-process version measured, which is the number a caller actually sees.
#[test]
#[ignore = "a measurement, not an assertion; run manually with --ignored --nocapture"]
fn measure_what_the_bounded_path_costs_a_quick_command() {
    let Some(dump) = target_tier() else { return };
    const ROUNDS: usize = 20;

    let mut server = Server::started();
    let session = server.open_session("open_dump", json!({ "path": dump }), TARGET_STEP);

    /// min / median / max, because a mean hides the two modes entirely.
    fn spread(mut samples: Vec<Duration>) -> String {
        samples.sort();
        format!(
            "min {:?}, median {:?}, max {:?}",
            samples[0],
            samples[samples.len() / 2],
            samples[samples.len() - 1]
        )
    }

    // `modules` is `lm` on the unbounded path; `execute` runs whatever it is given on the bounded
    // one. Same engine, same session, one difference: the watchdog.
    for (label, command) in [
        ("lm", "lm".to_string()),
        (
            ".for (short)",
            ".for (r $t0 = 0; @$t0 < 0x4e20; r $t0 = @$t0 + 1) { }".to_string(),
        ),
    ] {
        let mut unbounded = Vec::with_capacity(ROUNDS);
        let mut bounded = Vec::with_capacity(ROUNDS);
        for _ in 0..ROUNDS {
            let t = Instant::now();
            server.tool_text("modules", json!({ "session_id": session }), TARGET_STEP);
            unbounded.push(t.elapsed());

            let t = Instant::now();
            server.tool_text(
                "execute",
                json!({ "command": command.clone(), "session_id": session }),
                TARGET_STEP,
            );
            bounded.push(t.elapsed());
        }
        println!("`{label}` x{ROUNDS}");
        println!("   unbounded (`modules` / lm): {}", spread(unbounded));
        println!("   bounded   (`execute`):      {}", spread(bounded));
    }

    server.tool_text("end_session", json!({ "session_id": session }), TARGET_STEP);
}

// ---- tier 4: a live KDNET kernel target ---------------------------------------
//
// The only tier that touches another machine. Everything above proves the *parked* half of a
// kernel attach — a connection nothing answers — which is the failure #61 was about, but says
// nothing about the half that has to keep working: an attach that actually lands, drives a real
// target through a worker process, and lets go of it cleanly.
//
// Doubly gated, because running it by accident has consequences on a machine that is not this
// one. `#[ignore]` keeps it out of every default run, and it needs a connection string only the
// operator has:
//
//     $env:WINDBG_MCP_SMOKE_KERNEL = "net:port=50000,key=<w.x.y.z>"
//     cargo test --test mcp_smoke -- --ignored --nocapture --test-threads=1 live_kernel
//
// Run it **last**, on its own, as the final step of the manual checklist: it is the only tier
// whose blast radius includes a VM you care about.
//
// Remote (KDNET) only. `attach_kernel_local` is a different code path with a different failure
// mode, it needs Secure Boot off to be attachable at all, and a frozen local kernel is the host
// you are testing from.

/// The connection string for the live-kernel tier, or `None` when it is off.
fn kernel_tier() -> Option<String> {
    match std::env::var("WINDBG_MCP_SMOKE_KERNEL") {
        Ok(connection) if !connection.trim().is_empty() => Some(connection.trim().to_string()),
        _ => {
            skip(
                "set WINDBG_MCP_SMOKE_KERNEL=\"net:port=<n>,key=<w.x.y.z>\" to run the \
                 live-kernel tier",
            );
            None
        }
    }
}

/// An explicit second gate for the MessageManager CTF fixture.
///
/// A live KDNET connection alone must not make a broad `live_kernel` test filter expect a
/// challenge driver and retained `Tgsm` allocations on every target. The PowerShell orchestrator
/// sets this only after deploying the fixture and observing its ready line.
fn messagemanager_ctf_tier() -> bool {
    match std::env::var("WINDBG_MCP_SMOKE_CTF") {
        Ok(value) if value.trim() == "1" => true,
        _ => {
            skip("set WINDBG_MCP_SMOKE_CTF=1 only after the MessageManager fixture reports ready");
            false
        }
    }
}

/// The `port=` field of a KDNET connection string such as `net:port=50000,key=w.x.y.z`.
///
/// The transport prefix sits on the *first* field (`net:port=50000`), not in front of the whole
/// string, so matching `port=` against the raw field silently misses — and a `None` here skips the
/// UDP-ownership assertion rather than failing it, which is how the first version of this went
/// unnoticed through several runs.
fn kdnet_port(connection: &str) -> Option<u16> {
    connection
        .split(',')
        .filter_map(|field| field.rsplit(':').next())
        .find_map(|field| field.trim().strip_prefix("port="))
        .and_then(|port| port.trim().parse().ok())
}

/// Pinned in the default tier, because the failure it guards against is a *silent skip*: the
/// assertion it feeds is conditional on `Some`, so a parser that stops matching takes the proof
/// with it and every run still passes.
#[test]
fn a_kdnet_connection_string_yields_its_port() {
    assert_eq!(kdnet_port("net:port=50000,key=1.1.1.1"), Some(50000));
    assert_eq!(kdnet_port("net:port=50005,key=a.b.c.d,foo=1"), Some(50005));
    // Spacing and field order are the caller's business, not ours.
    assert_eq!(kdnet_port("net: port=50000 , key=x"), Some(50000));
    assert_eq!(kdnet_port("net:key=1.1.1.1,port=50000"), Some(50000));
    // Transports with no port at all must not produce a bogus one.
    assert_eq!(kdnet_port("com:pipe,port=\\\\.\\pipe\\kd"), None);
    assert_eq!(kdnet_port("net:key=1.1.1.1"), None);
}

/// Whether a `registers` dump shows a thread context at all.
///
/// The instruction pointer is the marker, and **its name is architectural**: `rip` on x64, `pc` on
/// ARM64. Matching one spelling made this a test of the debugger *host's* architecture rather than
/// of the debugger, and that is exactly how it failed — against a live ARM64 kernel it rejected a
/// perfectly good `x0`–`x30`/`fp`/`lr`/`sp`/`pc` context, stopped at `nt!DbgBreakPointWithStatus`.
/// Same family as [#142](https://github.com/glslang/windbg-mcp/issues/142), which found the
/// x64 assumptions in the *dump* tier; this one survived because the live tier had only ever been
/// pointed at an x64 KDNET target.
///
/// Deliberately not a list of every register: what is being asserted is "there is a context here",
/// and the program counter is the one register every architecture has.
fn has_thread_context(registers: &str) -> bool {
    registers.contains("rip=") || registers.contains("pc=")
}

/// Whether the attached target is the **x64** kernel the pool tools require.
///
/// Read from the opener's own `vertarget` report rather than from `cfg!(target_arch)`, because the
/// architecture that decides this is the *target's* and not the debugger host's — those are
/// routinely different, and on this project's own bench they are. `vertarget` names it:
/// `Free x64` against `Free ARM 64-bit (AArch64)`.
///
/// The pool tools say "Needs a broken-in x64 kernel target" in their own descriptions
/// (`src/server.rs`), and the walker decodes x64 pool descriptors. Against anything else the two
/// tests below have no premise, so they say so instead of failing.
fn target_is_x64(report: &str) -> bool {
    !report.contains("AArch64") && !report.contains("ARM 64") && report.contains("x64")
}

/// Why the two pool tests stand down. Shared, so the pair cannot drift into disagreeing about
/// what they need.
const NOT_X64_SKIP: &str = "the pool tools need a broken-in x64 kernel target; this one is not, so \
                            there is nothing here for them to be right or wrong about";

/// Pinned in the default tier, like the two predicates above, because the tier that would catch a
/// regression needs a kernel on the other end of a wire.
#[test]
fn a_targets_architecture_is_read_from_its_own_report() {
    assert!(target_is_x64(
        "Windows 10 Kernel Version 26100 MP (4 procs) Free x64"
    ));
    assert!(!target_is_x64(
        "Windows 10 Kernel Version 26100 MP (4 procs) Free ARM 64-bit (AArch64)"
    ));
    // Nothing to go on is not x64: this gates work that would otherwise fail confusingly, so the
    // safe answer to "cannot tell" is to skip it.
    assert!(!target_is_x64("Windows 10 Kernel Version 26100 MP"));
}

/// Pinned in the default tier for the same reason as the port parser above: the assertion it feeds
/// lives in a tier that needs a kernel on the other end of a wire, so a spelling quietly dropped
/// here would not be noticed until someone had one.
#[test]
fn a_thread_context_is_recognised_on_either_architecture() {
    assert!(has_thread_context(
        "rax=0000000000000001 rip=fffff80012345678"
    ));
    assert!(has_thread_context(
        " fp=fffff8003d7c2740   lr=fffff8004205cb24   sp=fffff8003d7c2740\n \
         pc=fffff80042001370  psr=80000344 N--- EL1"
    ));
    // A dump with no context at all, and one whose other registers must not stand in for the
    // program counter — `psr` on ARM64 is the near miss.
    assert!(!has_thread_context("Unable to get current machine context"));
    assert!(!has_thread_context("psr=80000344 N--- EL1"));
}

/// `System Uptime` out of `.time` output, e.g. `0 days 0:05:31.599`.
///
/// A halted kernel's uptime does not advance — no CPU is running to take the clock interrupt — so
/// this is the one signal that distinguishes a target that was *left running* from one that was
/// merely left reachable. Returns `None` if the shape is not what this expects, so a caller can
/// tell "did not advance" from "could not tell".
fn system_uptime(time_output: &str) -> Option<Duration> {
    let value = time_output
        .lines()
        .find_map(|line| line.split_once("System Uptime:"))?
        .1
        .trim();
    let (days, hms) = match value.split_once("day") {
        Some((days, rest)) => (
            days.trim().parse::<u64>().ok()?,
            rest.trim_start_matches('s').trim(),
        ),
        None => (0, value),
    };
    let mut parts = hms.split(':');
    let hours: u64 = parts.next()?.trim().parse().ok()?;
    let minutes: u64 = parts.next()?.trim().parse().ok()?;
    let seconds: f64 = parts.next()?.trim().parse().ok()?;
    Some(Duration::from_secs_f64(
        (days * 86_400 + hours * 3_600 + minutes * 60) as f64 + seconds,
    ))
}

/// Whether `pid` owns a UDP endpoint on `port`, per `netstat -ano`.
fn owns_udp_port(pid: u32, port: u16) -> bool {
    let out = Command::new("netstat")
        .args(["-ano", "-p", "UDP"])
        .output()
        .expect("run netstat");
    // `  UDP    0.0.0.0:50000    *:*    1234` — local address second, owning pid last.
    String::from_utf8_lossy(&out.stdout).lines().any(|line| {
        let local = line.split_whitespace().nth(1).unwrap_or_default();
        let owner = line.split_whitespace().last().unwrap_or_default();
        local.ends_with(&format!(":{port}")) && owner == pid.to_string()
    })
}

/// A live KDNET session, end to end: attach, work, coexist with another session, detach cleanly.
///
/// The claims that need a real target, and that the dead-port test cannot make:
///
/// * an attach that **lands** still works through a worker process — the `Committed`/`Opened`
///   milestones cross the pipe and leave the session `Open` rather than stuck mid-attach;
/// * the KD transport endpoint belongs to the **worker**, which is the premise of the whole fix.
///   A thread-based design leaves that endpoint claimed for the life of the server, and each
///   retry claims another;
/// * a second session works *alongside* a live kernel attach — impossible by construction before
///   — checked here on the target it matters most for;
/// * `end_session` takes the **graceful** path on a live kernel. That is not tidiness: DbgEng
///   leaves a detached-but-halted kernel frozen, so dbgscope resumes and *actively* detaches. A
///   session that fell through to the worker kill instead would leave the guest halted — one CPU
///   stopped, the rest spinning — and its KD stub wedged until a reboot.
///
/// Which is also why the body runs under `catch_unwind`: from the attach onward the target is
/// broken in and stays that way until the session ends, so a panic that skipped the detach would
/// leave someone's VM frozen because a test failed.
#[test]
#[ignore = "needs a live KDNET target and its connection string; run manually, last"]
fn a_live_kernel_session_attaches_coexists_and_detaches_cleanly() {
    let Some(connection) = kernel_tier() else {
        return;
    };
    // Recorded, because this is the only place the transcript's redaction claim can be made
    // against an attach that **landed**. The protocol tier passes a raw connection too, but its
    // attach is refused for its shape before anything dials — so it proves the argument is
    // scrubbed and nothing about a session that then exists, gets a label, opens a target and
    // reports on it. Checked at the end of this test, after the detach.
    let transcript = marker_path("live-attach");
    let _ = std::fs::remove_file(&transcript);
    let mut server = Server::started_with(&[(
        "WINDBG_MCP_TRANSCRIPT",
        transcript.to_str().expect("a UTF-8 temp path"),
    )]);

    let attached = server.call_tool(
        "attach_kernel",
        json!({ "connection": connection }),
        TARGET_STEP,
    );
    let report = text_of(&attached["result"]);
    // Whether there is anything to clean up is decided by the *handle*, not by `isError`: an
    // attach that claims its target and then fails the wait comes back as a tool error carrying a
    // valid `session_id`, and that session is live, halted, and needs detaching just as much as a
    // successful one. Nothing below panics until that has happened.
    let Some(session) = maybe_session_id(&attached["result"]) else {
        assert_no_error(&attached, "attach_kernel");
        panic!(
            "the attach did not land, and left no session behind. The target must be booted with \
             debugging enabled and dialling this host, and the KD transport is single-owner — if \
             WinDbg's EngHost already holds the port, nothing else can attach:\n{report}"
        );
    };

    // Everything from here runs under `catch_unwind`, because the target is now broken in and
    // stays that way until the detach below — including the `vertarget` check, which has no
    // business being the one assertion that can leave a machine frozen.
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        assert_no_error(&attached, "attach_kernel");
        assert!(
            !is_tool_error(&attached),
            "the attach reported a failure but left a session behind, so it claimed the target \
             and then failed — the detach below still has to run:\n{report}"
        );
        // `vertarget`, run by the opener inside the worker.
        assert!(
            report.contains("Kernel"),
            "the post-attach report should be `vertarget` output naming the kernel:\n{report}"
        );

        // The milestones made it across: not still "attaching", which is where a parked one sits.
        let status = server.tool_data("session_status", json!({ "session_id": session }), STEP);
        assert_eq!(
            status["sessions"][0]["state"]["state"], "open",
            "a landed attach must report as open, not mid-attach: {status}"
        );

        // The transport lives in the worker — the process `end_session` can terminate.
        if let Some(port) = kdnet_port(&connection) {
            let worker = engine_pid_of(&status, &session);
            assert!(
                owns_udp_port(worker, port),
                "UDP {port} is not owned by the engine worker (pid {worker}) — if the KD endpoint \
                 belonged to the server instead, a session that cannot unwind could not be \
                 reclaimed, which is the whole premise of running sessions in their own processes"
            );
        }

        // A routed call reaches the right worker, and the target is real.
        let modules = server.tool_text("modules", json!({ "session_id": session }), TARGET_STEP);
        let listed: Vec<&str> = modules
            .lines()
            .filter_map(|line| line.split_whitespace().nth(2))
            .collect();
        assert!(
            listed.contains(&"nt"),
            "the kernel image should be in the module list:\n{modules}"
        );

        // And the same listing asked to resynchronise the inventory first, which is the only tier
        // where that call reaches a target whose module list the debugger did not watch being
        // built ([#85](https://github.com/glslang/windbg-mcp/issues/85)). This target carries no
        // fixture, so what is claimed here is the mechanism rather than a find: the reload runs
        // over the KD wire, succeeds, and leaves a listing at least as complete as the one above
        // — a refresh that lost modules would be worse than no refresh at all. The CTF tier makes
        // the other claim, on a driver that is actually missing before it.
        let refreshed = server.tool_data(
            "modules",
            json!({ "session_id": session, "refresh": true }),
            TARGET_STEP,
        );
        assert_eq!(
            refreshed["refresh"]["synchronized"],
            json!(true),
            "a live kernel is the target a resynchronisation exists for: {refreshed}"
        );
        let (before, after) = (
            refreshed["refresh"]["before"].as_u64().unwrap_or_default(),
            refreshed["loaded"].as_u64().unwrap_or_default(),
        );
        assert!(
            after >= before && after > 1,
            "the refresh left {after} module(s) where the engine held {before}: {refreshed}"
        );
        println!("live kernel inventory: {before} module(s) before the refresh, {after} after");

        let registers =
            server.tool_text("registers", json!({ "session_id": session }), TARGET_STEP);
        assert!(
            has_thread_context(&registers),
            "a broken-in kernel should have a thread context:\n{registers}"
        );

        // `crash_triage` against a kernel that is merely *broken in* — the state the crash/reboot
        // exploitation loop sits in between fires, and the one a dump can never be in. It has to
        // refuse, and refuse for the right reason: this is a kernel target with no bug check, not
        // the user-mode session the other refusal is about, and the two arms are only ever both
        // reachable here.
        let refused = server.tool_failure("crash_triage", json!({ "session_id": session }), STEP);
        assert_eq!(refused["error"]["category"], "debugger", "{refused}");
        let why = refused["error"]["message"].as_str().unwrap_or_default();
        assert!(
            why.contains("not stopped at a bug check"),
            "a live kernel that has not crashed must be told so, not handed an HRESULT: {refused}"
        );
        assert!(
            !why.contains("user-mode"),
            "this is a kernel target; the user-mode arm must not be the one that fires: {refused}"
        );

        // And the refusal costs the session nothing — the loop attaches once and fires many times,
        // so a triage that came too early must leave the session exactly as usable as it found it.
        let after_refusal =
            server.tool_text("registers", json!({ "session_id": session }), TARGET_STEP);
        assert!(
            has_thread_context(&after_refusal),
            "the session must survive a triage that had nothing to triage:\n{after_refusal}"
        );

        // The payoff, on the target it matters most for: another session opened and used while a
        // live kernel attach is held, and the kernel session untouched by it.
        if std::path::Path::new(SAMPLE_DUMP).exists() {
            let opened = server.call_tool("open_dump", json!({ "path": SAMPLE_DUMP }), TARGET_STEP);
            assert_no_error(&opened, "open_dump alongside a live kernel session");
            assert!(
                !is_tool_error(&opened),
                "opening a dump must not be blocked by a live kernel session:\n{}",
                text_of(&opened["result"])
            );
            let dump_session = session_id_of(&opened["result"]);
            let after = server.call_tool("modules", json!({ "session_id": session }), TARGET_STEP);
            assert!(
                !is_tool_error(&after),
                "the kernel session must survive another session being opened:\n{}",
                text_of(&after["result"])
            );
            server.tool_text(
                "end_session",
                json!({ "session_id": dump_session }),
                TARGET_STEP,
            );
        } else {
            eprintln!("NOTE: sample dump missing, skipping the second-session check");
        }
    }));

    // Always, whatever happened above — the target is frozen until this runs.
    let ended = server.call_tool("end_session", json!({ "session_id": session }), TARGET_STEP);
    let ended_text = text_of(&ended["result"]);
    // Same ordering as the pool tier, and for the same reason: resuming the original panic first
    // would skip every check below it, so a failed detach is masked exactly when the machine is
    // most likely to be sitting halted. A caught panic has already printed itself.
    match (outcome, ungraceful_detach(&ended, &ended_text)) {
        (Err(_), Some(why)) => panic!(
            "THE TARGET MAY STILL BE HALTED — {why}\n\nThis run had already failed, for the \
             reason printed above; that is what to investigate, but check the machine first."
        ),
        (Err(panic), None) => resume_unwind(panic),
        (Ok(()), Some(why)) => panic!("{why}"),
        (Ok(()), None) => {}
    }

    assert!(
        ended_text.contains("closed"),
        "end_session should report the session closed:\n{ended_text}"
    );

    // The redaction claim, against a real attach. Last, so a failure here can never be the reason
    // a machine is left halted — the detach above has already run.
    let raw = std::fs::read_to_string(&transcript)
        .unwrap_or_else(|e| panic!("no transcript at {}: {e}", transcript.display()));
    // First, unconditionally: the session really is in there. Otherwise everything below would be
    // satisfied by a transcript that recorded nothing at all.
    assert!(
        raw.contains("\"event\":\"session_open\"") && raw.contains("\"kind\":\"kernel target\""),
        "the transcript has no record of the kernel session it was recording ({})",
        transcript.display()
    );
    let key = connection
        .split("key=")
        .nth(1)
        .and_then(|rest| rest.split(',').next())
        .unwrap_or_default();
    // Conditional for the same reason the UDP-ownership check above is: the claim belongs to the
    // *transport*, not to this tier. A KD key is a KDNET thing, and a serial target
    // (`com:port=COM1,baud=115200`) carries no secret at all — so there is nothing for the
    // transcript to redact, and demanding a `<redacted>` marker would fail a target that is
    // behaving perfectly. Keyless is announced rather than skipped silently, so a `net:` run that
    // somehow lost its key cannot pass by taking this branch.
    if key.len() < 4 {
        println!(
            "NOTE: this connection carries no `key=`, so the redaction claim is not exercised — \
             that check needs a KDNET target"
        );
    } else {
        // Deliberately *not* printing the file on failure: it would put the key in the test
        // output, which is the thing being checked. The path is enough to go and look.
        assert!(
            !raw.contains(key),
            "the supplied KD key reached the transcript of a landed attach ({})",
            transcript.display()
        );
        assert!(
            raw.contains("<redacted>"),
            "nothing in the transcript was masked, so the check above proves nothing ({})",
            transcript.display()
        );
    }
    let _ = std::fs::remove_file(&transcript);
    println!("live kernel session detached cleanly:\n{ended_text}");
}

/// Disconnecting with a live kernel session open must **release** it, not kill its worker.
///
/// This is the same hazard as the detach above, arriving by the path nobody is watching. A client
/// disconnect is an ordinary event — closing a laptop lid ends one — and the sessions it finds are
/// whatever happened to be open. Killing a worker that holds a broken-in kernel leaves the target
/// halted: DbgEng needs the resume-and-active-detach that only a real teardown performs.
///
/// Caught by running this tier for the first time: shutdown killed workers outright, so a
/// disconnect froze the target machine. The dump-based tier could never have found it — killing a
/// worker that holds a *dump* costs nothing at all.
///
/// The proof is the target's own **uptime**, read either side of the disconnect. A halted kernel
/// takes no clock interrupt, so its uptime stands still; a released one keeps counting. Re-attaching
/// alone would not show this — a frozen target still answers its KD stub — which is exactly the
/// trap that made the bug survive a first round of manual checking.
#[test]
#[ignore = "needs a live KDNET target and its connection string; run manually, last"]
fn disconnecting_releases_a_live_kernel_session_rather_than_killing_it() {
    let Some(connection) = kernel_tier() else {
        return;
    };

    let mut server = Server::started();
    let attached = server.call_tool(
        "attach_kernel",
        json!({ "connection": connection }),
        TARGET_STEP,
    );
    let report = text_of(&attached["result"]);
    // As above: a tool error can still carry a live session, so refuse to bail before there is
    // something to bail on. From here the disconnect is the release, so nothing needs a detach —
    // but the assertion order still has to survive an attach that half-failed.
    assert_no_error(&attached, "attach_kernel");
    let session = maybe_session_id(&attached["result"])
        .unwrap_or_else(|| panic!("the attach left no session behind:\n{report}"));
    assert!(
        !is_tool_error(&attached),
        "the attach claimed its target and then failed; this test needs one that landed:\n{report}"
    );
    let status = server.tool_data("session_status", json!({}), STEP);
    let worker = engine_pid_of(&status, &session);
    // `call_tool`, for the reason the block below spells out: at this point the target is broken
    // in and the release is still several steps away, so a panic here would leave it halted. The
    // uptime is a nice-to-have — the comparison at the end already reports honestly when it could
    // not be read — and nothing worth freezing a machine over.
    let timed = server.call_tool(
        "execute",
        json!({ "command": ".time", "session_id": session }),
        TARGET_STEP,
    );
    let before = if is_tool_error(&timed) {
        eprintln!(
            "NOTE: `.time` failed before the disconnect, so the uptime comparison cannot be \
             made:\n{}",
            text_of(&timed["result"])
        );
        None
    } else {
        system_uptime(&text_of(&timed["result"]))
    };

    // --- act, and *collect* rather than assert -------------------------------------------
    //
    // Nothing below panics until the target has been re-attached and detached again. Asserting
    // as it goes reads better and is wrong here: the first version of this test failed at the
    // release check and left the target halted, because the recovery came after the assertion.
    // A test for a bug that freezes a machine must not freeze the machine when it fails.

    // Disconnect the way a client does: close stdin and let the server wind itself up. No
    // `end_session` — that is the whole point. The log is captured before `shutdown` consumes
    // the harness, since what it says is half the evidence.
    let log = Arc::clone(&server.stderr_log);
    // `shutdown` panics if the server does not exit in 20s, and the kernel is broken in right
    // now — so even this is collected rather than allowed to propagate.
    let exit = catch_unwind(AssertUnwindSafe(|| server.shutdown()));

    // The stderr reader is a separate thread draining a pipe the process just closed, so poll
    // rather than snapshot — a bare read races the drain and fails intermittently.
    let deadline = Instant::now() + Duration::from_secs(5);
    let stderr = loop {
        let stderr = log.lock().unwrap().join("\n");
        if stderr.contains("releasing 1 session") || Instant::now() >= deadline {
            break stderr;
        }
        std::thread::sleep(Duration::from_millis(20));
    };

    let deadline = Instant::now() + Duration::from_secs(20);
    while process_alive(worker) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    let worker_gone = !process_alive(worker);

    // Give the target time to visibly run, if it is running at all.
    const RUNNING_FOR: Duration = Duration::from_secs(4);
    std::thread::sleep(RUNNING_FOR);

    // Re-attach: needed to read the uptime again, and it is also how the target gets left
    // detached and running rather than broken in.
    let mut again = Server::started();
    let reattached = again.call_tool(
        "attach_kernel",
        json!({ "connection": connection }),
        TARGET_STEP,
    );
    let report = text_of(&reattached["result"]);
    let landed = reattached["error"].is_null() && !is_tool_error(&reattached);
    // Keyed on the handle, not on `landed`: a re-attach that claimed the target and then failed
    // its wait comes back as a tool error *with* a session, and skipping the release for it would
    // leave the target halted — the one thing this test exists to catch.
    let (after, ended, released) = match maybe_session_id(&reattached["result"]) {
        Some(session) => {
            // `call_tool`, not `tool_text`. This `.time` is *expected* to fail on the very path
            // the handle-keyed match above exists for — a re-attach that claimed the target and
            // then failed its wait answers nothing — and `tool_text` is strict now, so a panic
            // here would skip the release below and leave the target halted. That is the failure
            // this whole test exists to detect, arriving through the test itself.
            let timed = again.call_tool(
                "execute",
                json!({ "command": ".time", "session_id": session }),
                TARGET_STEP,
            );
            let after = if is_tool_error(&timed) {
                eprintln!(
                    "NOTE: `.time` failed on the re-attached session, so the uptime comparison \
                     below cannot be made:\n{}",
                    text_of(&timed["result"])
                );
                None
            } else {
                system_uptime(&text_of(&timed["result"]))
            };
            // The release. From here the target is running again whatever the assertions say.
            let released =
                again.call_tool("end_session", json!({ "session_id": session }), TARGET_STEP);
            let ended = text_of(&released["result"]);
            (after, ended, Some(released))
        }
        None => (None, String::new(), None),
    };

    // --- now assert ----------------------------------------------------------------------
    //
    // The detach first, before the disconnect's own outcome and before any earlier failure is
    // propagated. Every one of those would otherwise mask it, and a masked ungraceful detach is a
    // machine left halted — the loudest fact available and the only one needing action now. The
    // failures below are all diagnosis, and they keep.
    if let Some(released) = &released
        && let Some(why) = ungraceful_detach(released, &ended)
    {
        panic!(
            "THE TARGET MAY STILL BE HALTED — the final detach was not graceful: {why}\n\n\
             Anything else this run has to say is below; check the machine first."
        );
    }
    match exit {
        Ok(code) => assert_eq!(code, Some(0), "a disconnect should still be a clean exit"),
        Err(panic) => resume_unwind(panic),
    }
    assert!(
        stderr.contains("releasing 1 session"),
        "the disconnect should have *released* the kernel session, not killed its worker — a \
         killed worker leaves the target halted:\n{stderr}"
    );
    assert!(
        worker_gone,
        "engine worker pid {worker} outlived the connection"
    );
    assert!(
        landed,
        "the target was not reattachable after a disconnect — the previous session did not let go \
         of it cleanly, and this run could not put it back:\n{report}"
    );
    match (before, after) {
        (Some(before), Some(after)) => {
            let ran_for = after.saturating_sub(before);
            println!("target uptime advanced {ran_for:?} across a {RUNNING_FOR:?} disconnect");
            assert!(
                ran_for >= RUNNING_FOR / 2,
                "the target's uptime barely moved across the disconnect ({ran_for:?} over \
                 {RUNNING_FOR:?}) — it was left halted, which is what killing a worker that holds \
                 a broken-in kernel does instead of releasing it"
            );
        }
        // Not a failure: the check is only as good as `.time`'s shape, and the release itself is
        // asserted above. Say so loudly rather than pass quietly on the weaker claim.
        _ => eprintln!(
            "NOTE: could not read System Uptime either side of the disconnect, so this run \
             proved only that the session was released and the target stayed reachable"
        ),
    }
}

/// How long a pool query may take before the budget it carries has failed to do its job.
///
/// dbgscope's `DEFAULT_WALK_BUDGET` is 120s and this server currently takes that default (#75),
/// so the walk is bounded there; the slack covers the reads already in flight when the deadline
/// passes, the render, and the round trip. Deliberately well under `TARGET_STEP`, so a breach
/// fails *here* with a diagnosis rather than as an opaque harness timeout.
const POOL_CEILING: Duration = Duration::from_secs(170);

/// How long a call made *after* a walk returned may wait.
///
/// Generous by an order of magnitude — `registers` on a broken-in kernel is one `r` over the
/// wire. The failure this catches is not slowness, it is **queueing**: a walk that outlived its
/// caller leaves the engine busy, and everything behind it waits out the rest of the walk.
const NOT_QUEUED: Duration = Duration::from_secs(30);

/// What the pool tier's server is told its per-call timeout is, rather than inheriting one.
///
/// Comfortably above dbgscope's 120s walk budget, so a walk that behaves is never cut off, and
/// below [`POOL_CALL_BUDGET`] so the server is always the one to answer first.
const SERVER_CALL_TIMEOUT: Duration = Duration::from_secs(300);

/// How long this *harness* waits on a pool call — deliberately longer than the server's own.
///
/// `TARGET_STEP` is 240s, below the server's timeout, so a walk that ran away would have the
/// harness give up first. That is the wrong order here. The client panicking while the walk is
/// still running means the `end_session` in the cleanup queues behind it, misses its grace period,
/// and the worker is **killed** — which on a broken-in kernel leaves the guest halted. On the
/// exact failure path this test exists to detect, that would freeze the machine it is diagnosing.
///
/// The ordering only holds if the server's timeout is known, which is why the test pins
/// [`SERVER_CALL_TIMEOUT`] rather than letting an operator's `WINDBG_MCP_CALL_TIMEOUT_SECS`
/// through: a short value times out mid-walk and a long one puts the harness first again.
const POOL_CALL_BUDGET: Duration = Duration::from_secs(330);

/// What a query served from a cached snapshot may take.
///
/// A fixed bound rather than a fraction of the first walk's time, because two live walks vary and
/// a second one that happened to be quicker would satisfy a relative comparison while having
/// re-walked the entire pool — proving the opposite of what it claims. A cached answer is a lookup
/// over an in-memory index and does not touch the wire at all; the measured walk it is being told
/// apart from is ~20s.
const CACHED_QUERY_CEILING: Duration = Duration::from_secs(5);

/// A tag no allocator will have used, so answering has to walk the whole pool.
///
/// If it ever collides the test says so and stays honest rather than failing; change it then.
const ABSENT_TAG: &str = "Zq7x";

/// The global the pool walker needs before it can read anything: the allocator's root.
///
/// It is not an export, so resolving it is the cheapest honest proof that full `nt` symbols are
/// actually in hand — and it is the exact name the walker fails on, so a probe that passes here
/// and a walk that fails afterwards would be telling us something new.
const POOL_ROOT_SYMBOL: &str = "nt!ExPoolState";

/// The `x` that resolves [`POOL_ROOT_SYMBOL`], as one string so its output can be told apart
/// from every other command's by comparing against the command that produced it.
const POOL_ROOT_PROBE: &str = "x nt!ExPoolState";

/// The `lm` that reports what `nt` loaded, kept as one string for the same reason.
const LOADED_MODULE_PROBE: &str = "lm m nt";

/// Where downloaded PDBs are kept — named explicitly, because the default is not a path.
///
/// `.symfix` and a bare `srv*` both expand to `cache*;SRV*<msdl>`, and that `cache*` names no
/// directory at all. A symbol *server* element with no usable downstream store is skipped, and a
/// skipped element looks exactly like an absent PDB: `DBGHELP: ntkrnlmp.pdb - file not found`,
/// with no `SYMSRV:` line above it because nothing was ever asked. Four runs of this tier were
/// spent reading that as evidence about the target. `.symfix+ <cache>` is the documented spelling.
///
/// `target\release\sym` rather than somewhere fresh: this repo's release builds have been caching
/// there already, so a dev run finds what a release run fetched instead of filling a second store.
/// Backslashes throughout — a store path is not the place to find out how DbgHelp feels about
/// mixed separators.
const SYMBOL_CACHE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "\\target\\release\\sym");

/// The debugging engine a debugger process needs *beside its own exe*.
///
/// `dbgeng.dll` exists in System32, so a binary without these still opens targets, runs commands
/// and passes almost every test here — it just cannot do symbols. `symsrv.dll` is what reads a
/// symbol *store*, and `msdia140.dll` is what parses a PDB once found; without them a PDB sitting
/// in the cache is reported as `file not found`, complete with a SYMSRV error summary blaming the
/// store. Which is what four runs of this tier were actually looking at.
const ENGINE_DLLS: [&str; 6] = [
    "dbgeng.dll",
    "dbghelp.dll",
    "dbgcore.dll",
    "dbgmodel.dll",
    "msdia140.dll",
    "symsrv.dll",
];

/// Puts the engine beside the binary this harness spawns, copying from a release build if needed.
///
/// `setup.md` has the operator copy these next to the **release** binary, because that is what the
/// plugin runs. The harness spawns the **dev** build, and nothing had ever put them there — so the
/// tiers that need symbols could not work from a `cargo test` at all, and said so in a way that
/// pointed at the target instead.
///
/// Returns what it did, for the transcript. A failure here is reported by the caller rather than
/// panicking, since the tier's own message explains what is missing far better than a copy error.
fn ensure_engine_beside_test_binary() -> String {
    let Some(dir) = std::path::Path::new(EXE).parent() else {
        return "cannot locate the test binary's directory".into();
    };
    let missing: Vec<&str> = ENGINE_DLLS
        .iter()
        .copied()
        .filter(|dll| !dir.join(dll).exists())
        .collect();
    if missing.is_empty() {
        return format!("engine already beside {}", dir.display());
    }
    // The release tree is where `setup.md` has them put, so it is the one place worth looking.
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target\\release");
    let mut copied = Vec::new();
    for dll in &missing {
        match std::fs::copy(source.join(dll), dir.join(dll)) {
            Ok(_) => copied.push(*dll),
            Err(error) => {
                return format!(
                    "{} is not beside {} and could not be copied from {}: {error}. Follow the \
                     engine-bundling step in skills/windbg-debugging/setup.md — without \
                     symsrv.dll a symbol store cannot be read at all, and without msdia140.dll a \
                     PDB cannot be parsed once found.",
                    dll,
                    dir.display(),
                    source.display()
                );
            }
        }
    }
    format!("copied {} into {}", copied.join(", "), dir.display())
}

/// A symbol path the operator knows works for this target, overriding [`SYMBOL_CACHE`].
///
/// Getting a kernel's PDB onto a debugging host is an environment problem — a reachable store, a
/// proxy, the right build — and one this test is in no position to solve. Where it has already
/// been solved, this is how to say so.
const SYMBOLS_ENV: &str = "WINDBG_MCP_SMOKE_SYMBOLS";

/// Gets full `nt` type information in front of the walker, and returns the transcript.
///
/// The walker decodes segment-heap internals — `_EX_POOL_HEAP_MANAGER_STATE`, the page-range
/// descriptors, the VS and LFH headers — none of which is in the public export table, and none of
/// which a fresh attach force-loads. Symbols are never fetched over the KD wire either, so this is
/// entirely about *this* host.
///
/// Both forms *append*, so a host with a curated path keeps it. `!sym noisy` wraps the reload
/// because a failed symbol load is otherwise **completely silent** — several runs of this tier
/// were spent on a `.reload` that printed nothing and loaded nothing, which is indistinguishable
/// from success until something asks for a symbol.
///
/// `.reload /f` unqualified, not `.reload /f nt`. The original reason was wrong — `.reload /f nt`
/// looked like it "quietly did nothing" when the actual fault was a missing `symsrv.dll`, and the
/// module name was never the variable. It stays unqualified anyway, for a smaller reason: this is
/// a manual tier run against one machine, the unqualified form is what was measured working end to
/// end, and it removes the module name from the set of things a future failure here could be. The
/// cost is a slower run, which nothing on this path is optimising for. Anywhere symbol *speed*
/// matters, `.reload /f <mod>` is the right instruction — see `skills/windbg-debugging/setup.md`.
fn load_kernel_symbols(server: &mut Server, session: &str) -> KernelSymbols {
    // DbgHelp will create the store, but only once it has decided to use it; making it first
    // removes one way for a symbol-server element to be quietly unusable.
    let _ = std::fs::create_dir_all(SYMBOL_CACHE);
    let path = std::env::var(SYMBOLS_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| {
            format!("srv*{SYMBOL_CACHE}*https://msdl.microsoft.com/download/symbols")
        });

    // The typed tool, not `.sympath+` through `execute`: it goes through DbgEng's
    // Append/SetSymbolPath, so it cannot fall foul of `.sympath` swallowing the rest of the
    // command line — the quirk this repo documents and works around everywhere else.
    let configured = server.call_tool(
        "set_symbol_path",
        json!({ "path": path, "append": true, "session_id": session }),
        TARGET_STEP,
    );
    let mut transcript = format!(
        "\n$ set_symbol_path append={path}{}\n{}\n",
        if is_tool_error(&configured) {
            " [FAILED]"
        } else {
            ""
        },
        text_of(&configured["result"]).trim()
    );

    let mut probe = String::new();
    let mut loaded = String::new();
    for command in [
        "!sym noisy",
        ".reload /f",
        "!sym quiet",
        // `!lmi` says whether an identity was available at all: it prints the debug directory's
        // PDB name, GUID and age when the image headers could be read, and says so when they
        // could not. The two failures look identical without it.
        "!lmi nt",
        // The line that settles whether a PDB actually loaded.
        LOADED_MODULE_PROBE,
        POOL_ROOT_PROBE,
    ] {
        let call = server.call_tool(
            "execute",
            json!({ "command": command, "session_id": session }),
            TARGET_STEP,
        );
        let output = text_of(&call["result"]);
        let failed = if is_tool_error(&call) {
            " [FAILED]"
        } else {
            ""
        };
        transcript.push_str(&format!("\n$ {command}{failed}\n{}\n", output.trim()));
        // Each answer kept apart from the echoed command that produced it, and from every other
        // command's output. Searching the whole transcript conflates them: `x`'s echo contains
        // the symbol name whether or not it resolved, and `.reload /f` loads *every* module, so a
        // `(pdb symbols)` anywhere in it says nothing about `nt`.
        let answer = output.replace(command, "").trim().to_string();
        match command {
            POOL_ROOT_PROBE => probe = answer,
            LOADED_MODULE_PROBE => loaded = answer,
            _ => {}
        }
    }
    KernelSymbols {
        transcript,
        probe,
        loaded,
    }
}

/// What [`load_kernel_symbols`] managed, kept apart so each can be checked on its own terms.
struct KernelSymbols {
    /// Everything that was run and what it said — the failure message's whole value.
    transcript: String,
    /// `x <pool root>` with the echoed command removed: empty means it did not resolve.
    probe: String,
    /// `lm m nt` with the echo removed, so `(pdb symbols)` is read about **`nt`** and not about
    /// whichever of the couple of hundred modules `.reload /f` also touched.
    loaded: String,
}

/// What `pool_census` had to say about the heaviest tag it found.
///
/// Two outcomes, and it used to be three. The third was "the heaviest tag does not render
/// unambiguously", which stood down the cross-check below on any tag `display_tag` could not
/// print — and on this bench that was the *common* case, since the two heaviest tags on a live
/// kernel are routinely binary and both render `....`. It stood down because the rendering was
/// the only identifier the census emitted, and handing it back queries a different tag rather
/// than failing.
///
/// The census now carries `raw_tag` beside it, so every tag it lists can be queried and the
/// stand-down has nothing left to describe. A missing `raw_tag` is a defect in the server, not a
/// fact about the pool, so it fails here rather than skipping.
enum HeaviestTag {
    /// A tag that can be handed straight back to `pool_find_tag`.
    Queryable(String),
    /// The census listed no allocated chunk at all.
    NothingListed,
}

/// The heaviest tag in a `pool_census` result.
///
/// Reads the first entry of the census's own ordering rather than parsing a fixed-width column
/// out of the table. The column-reading version had a trap worth remembering: `display_tag`
/// keeps trailing spaces, so a real tag like `Ntf ` had to be taken as exactly four characters
/// and never split on whitespace, or the cross-check below queried a tag nobody allocated and
/// blamed the walk for not finding it. A field cannot be mis-sliced.
fn heaviest_census_tag(census: &Value) -> HeaviestTag {
    let Some(first) = census["tags"].as_array().and_then(|tags| tags.first()) else {
        return HeaviestTag::NothingListed;
    };
    // The raw form, never `tag`. `tag` is a rendering: it maps every unprintable byte to `.`,
    // and a literal `.` to the same thing, so feeding it back to `pool_find_tag` asks about the
    // four ASCII bytes `....` — a tag nobody allocated — and reads as the walk having lost the
    // heaviest tag in the pool.
    let raw = first["raw_tag"].as_str().unwrap_or_default();
    assert!(
        !raw.is_empty(),
        "every census entry names its tag's bytes, or the heaviest tag in the pool cannot be \
         queried at all: {first}"
    );
    HeaviestTag::Queryable(raw.to_string())
}

/// A walk's diagnostic total has to account for the categories reported under it.
///
/// The arithmetic is trivial — a sum is at least the part of it you can see — and it is exactly
/// what broke. The total used to be the number of *lines that survived* the walk's collapsing, so
/// a real run reported "71 diagnostic(s)" beside a category reading "5621x" (#77): a statement
/// about this code's own truncation, presented as a measurement of the target. Fixtures cannot
/// catch it because nothing collapses until a category floods, so this live tier is the only
/// place the two numbers are ever far enough apart to disagree.
fn assert_diagnostic_total_covers_its_categories(diagnostics: &Value) {
    let emitted = diagnostics["walk"]["diagnostics_emitted"]
        .as_u64()
        .unwrap_or_else(|| panic!("the walk reports how much it complained: {diagnostics}"));
    if emitted == 0 {
        return;
    }
    let categories: Vec<u64> = diagnostics["categories"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|category| category["total"].as_u64())
        .collect();
    assert!(
        !categories.is_empty(),
        "a diagnostic total with no categories under it means the walk grouped nothing, and a          check that silently matches nothing is not a check: {diagnostics}"
    );
    let listed: u64 = categories.iter().sum();
    assert!(
        emitted >= listed,
        "the walk reported {emitted} diagnostic(s) but the categories under it account for          {listed} — so the total is counting something other than the messages the walk emitted,          and a reader takes it for a property of the target (#77): {diagnostics}"
    );
}

/// A pool walk over a live kernel: the query that used to take the session with it.
///
/// This is the tier the budget in glslang/dbgscope#88 was written for, and the only one that can
/// exercise it. Against the checked-in dump a walk is local memory and finishes in well under a
/// second, so every assertion below would pass for the wrong reason. Against a live KDNET target
/// it is every committed pool page over the wire — which is where the walk ran for minutes, the
/// tool call timed out, and the engine kept going, leaving the session unusable until it was
/// killed. Killing a worker that holds a broken-in kernel leaves the guest halted.
///
/// What that means for the assertions: the interesting one is *not* that a chunk was found. It is
/// that the call **came back**, that the session took work **immediately afterwards**, and that
/// whatever came back said how much of the pool it had actually seen. A truncated walk is an
/// acceptable outcome here, and an expected one on a busy kernel, so this asserts that coverage is
/// **stated** — never that it is total. Asserting completeness would fail on exactly the targets
/// this exists to cover.
///
/// Runs under `catch_unwind` for the reason every test in this tier does: from the attach onward
/// the target is broken in, and a panic that skipped the detach would leave someone's VM frozen.
#[test]
#[ignore = "needs a live KDNET target and its connection string; run manually, last"]
fn a_live_kernel_pool_walk_is_bounded_and_leaves_its_session_usable() {
    let Some(connection) = kernel_tier() else {
        return;
    };
    // Before the server starts, because the engine is loaded when the worker does. This is the
    // only tier that needs symbols, and so the only one that ever noticed they were impossible.
    let engine = ensure_engine_beside_test_binary();
    println!("engine: {engine}");
    // Pinned, not inherited. Every cleanup-safety argument here rests on the server's own call
    // timeout sitting *below* `POOL_CALL_BUDGET`, so that the server answers first and the
    // `end_session` below never queues behind a running walk. `WINDBG_MCP_CALL_TIMEOUT_SECS` is an
    // operational knob an operator may well have set, and either direction breaks that ordering: a
    // short value times out mid-walk, a value above the harness budget puts the harness first
    // again. Both end with the worker killed and the kernel left halted.
    let mut server = Server::started_with(&[(
        "WINDBG_MCP_CALL_TIMEOUT_SECS",
        &SERVER_CALL_TIMEOUT.as_secs().to_string(),
    )]);

    let attached = server.call_tool(
        "attach_kernel",
        json!({ "connection": connection }),
        TARGET_STEP,
    );
    let report = text_of(&attached["result"]);
    let Some(session) = maybe_session_id(&attached["result"]) else {
        assert_no_error(&attached, "attach_kernel");
        panic!(
            "the attach did not land, and left no session behind. The target must be booted with \
             debugging enabled and dialling this host, and the KD transport is single-owner:\n\
             {report}"
        );
    };

    let outcome = catch_unwind(AssertUnwindSafe(|| {
        assert_no_error(&attached, "attach_kernel");

        // The pool walker decodes x64 pool descriptors, which the tools' own descriptions say. On
        // any other target this test has no premise, so it says so — before paying for symbols,
        // and while still falling through to the detach below, since the target is broken in from
        // the attach onward whatever we decide here.
        if !target_is_x64(&report) {
            skip(NOT_X64_SKIP);
            return;
        }

        // The documented precondition, satisfied rather than assumed — and then *checked*.
        // Asking for symbols and carrying on regardless is what made the previous run report a
        // pool failure with no way to tell whether the path, the reload, or the walker was at
        // fault.
        let symbols = load_kernel_symbols(&mut server, &session);
        let transcript = &symbols.transcript;
        // Keyed on `lm` reporting a PDB, not on the absence of an error string. `x` against an
        // unresolved symbol prints *nothing at all* — no "Couldn't resolve", no diagnostic — so
        // an earlier version of this check passed a run in which nothing had loaded and let the
        // failure surface three calls later as an unexplained pool error.
        assert!(
            symbols.loaded.contains("pdb symbols"),
            "`nt` loaded without a PDB, so the pool walker has no types to decode with and this \
             tier can prove nothing about it.\n\nSymbols never cross the KD wire, so this is \
             always about *this* machine. Read `!lmi nt` below first: `Symbol Type: EXPORT - PDB \
             not found` **with a CODEVIEW GUID present** means the identity was known and the \
             lookup still failed — which is the engine or the store, not the target. That is what \
             `symsrv.dll` (reads a symbol store) and `msdia140.dll` (parses the PDB) are for, and \
             this run reports them as: {engine}. A CODEVIEW line that is *absent* is the other \
             failure, and a different fix. If you have a symbol path known to work here, set \
             {SYMBOLS_ENV} to it.\n{transcript}"
        );
        // A PDB for `nt` is necessary and not sufficient: the walker wants this *private* global,
        // and a public-only PDB would satisfy the check above while leaving every pool query to
        // fail. Checked on the probe's own output, since searching the whole transcript for the
        // name would match the echoed command and pass no matter what.
        assert!(
            !symbols.probe.is_empty(),
            "`nt` has a PDB but {POOL_ROOT_SYMBOL} did not resolve, so the pool walker still has \
             nothing to start from — the PDB may lack private symbols.\n{transcript}"
        );

        // A forced walk. `refresh` is the expensive path and the one that wedged; nothing is
        // cached this early anyway, but asking for it says so rather than relying on it.
        let started = Instant::now();
        let walk = server.call_tool(
            "pool_find_tag",
            json!({ "tag": ABSENT_TAG, "refresh": true, "session_id": session }),
            POOL_CALL_BUDGET,
        );
        let walked_for = started.elapsed();
        let absent = text_of(&walk["result"]);
        // Before the timing, because a call that *failed* also returns fast: the first live run
        // of this test measured 6.8ms and passed every deadline assertion below, having never
        // walked a single page. Both kinds of failure, because they look nothing alike from here:
        // a JSON-RPC error carries no `result` at all, so `is_tool_error` reads false and an
        // empty `absent` would sail through every check that follows.
        assert_no_error(&walk, "pool_find_tag on a live kernel");
        assert!(
            !is_tool_error(&walk),
            "the pool walk failed outright, so nothing below would be measuring a walk. If this \
             names missing allocator symbols after the probe above resolved, then the walker \
             wants type information the public store does not carry, which is a different \
             problem from an unset symbol path.\n{absent}\n\nsymbol setup said:{transcript}"
        );
        println!("a forced pool walk over a live kernel returned in {walked_for:?}");
        assert!(
            walked_for < POOL_CEILING,
            "the walk took {walked_for:?}, past the {POOL_CEILING:?} its budget should hold it \
             to — either the deadline is not enforced, or some loop in the walk is not polling it"
        );

        // The engine is free the moment the walk returns. Before the budget it was not: the
        // caller's timeout fired, the walk carried on, and this call waited out the remainder.
        let follow_up = Instant::now();
        let registers =
            server.tool_data("registers", json!({ "session_id": session }), TARGET_STEP);
        let waited = follow_up.elapsed();
        assert!(
            registers["instruction_pointer"].is_string(),
            "the session should still be a broken-in kernel after a pool walk: {registers}"
        );
        assert!(
            waited < NOT_QUEUED,
            "a call made after the walk returned waited {waited:?} — it queued behind an engine \
             that was still walking, which is the failure the budget exists to prevent"
        );

        // An empty answer has to say what the walk managed, or "no such chunk" and "the walk
        // reached almost none of the pool" are the same answer. As fields now: `matches: 0`
        // beside the coverage the count came from, which is what makes a zero readable.
        let empty = walk["result"]["structuredContent"].clone();
        assert_eq!(empty["status"], "ok", "checked above: {absent}");
        if empty["matches"] == 0 {
            assert!(
                empty["walk"]["chunks_walked"].as_u64().unwrap_or_default() > 0,
                "an empty result must carry the walk's own coverage: {empty}"
            );
            assert!(
                empty["walk"]["coverage"].is_string(),
                "coverage is one of complete/deadline_truncated/partial: {empty}"
            );
        } else {
            eprintln!(
                "NOTE: `{ABSENT_TAG}` really is allocated on this target, so the empty-answer \
                 check was skipped. Change ABSENT_TAG."
            );
        }

        // The census is the state of the walk, so it carries the report whatever it found.
        //
        // Timed, because it runs *between* the walk and the reuse check below and would otherwise
        // hide the very regression that check is for: if the walk's snapshot were discarded, this
        // call would quietly take a fresh one and cache *that*, and the later `reuse < walked_for`
        // would still pass while proving nothing about the original walk.
        let census_started = Instant::now();
        let census_call = server.call_tool(
            "pool_census",
            json!({ "session_id": session, "limit": 8 }),
            POOL_CALL_BUDGET,
        );
        let census_took = census_started.elapsed();
        let census = text_of(&census_call["result"]);
        assert_no_error(&census_call, "pool_census on a live kernel");
        assert!(
            !is_tool_error(&census_call),
            "pool_census failed:\n{census}"
        );
        let totals = census_call["result"]["structuredContent"].clone();
        assert!(
            totals["walk"]["chunks_walked"].as_u64().unwrap_or_default() > 0,
            "the census must always report the walk behind it: {totals}"
        );
        let coverage = totals["walk"]["coverage"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let complete = coverage == "complete";
        println!("the census reports this walk {coverage}");
        // The gap figures, printed rather than asserted on: they are the only place a live run
        // reports what the walk could not decode, and the two issues they were built for
        // (glslang/dbgscope#103, #104) are settled by comparing them across runs. A threshold
        // here would fail on an idle machine or pass on a busy one; a number in the log will not.
        println!("what the walk did and could not reach: {}", totals["walk"]);
        // An incomplete walk is an acceptable outcome, but "incomplete" on its own is not a
        // finding — *why*, and the categories, are. `deadline_truncated` and `partial` want
        // opposite responses, which is the whole reason coverage is three values and not a bool.
        // Measured 21.9s and INCOMPLETE against Server 26100, which is well inside the budget:
        // on that target the coverage gap is not the deadline, and now the result says so.
        if !complete {
            assert!(
                coverage == "deadline_truncated" || coverage == "partial",
                "a walk that fell short says which way: {totals}"
            );
            let diagnostics = server.tool_data(
                "pool_diagnostics",
                json!({ "session_id": session, "limit": 40 }),
                POOL_CALL_BUDGET,
            );
            // The categories, which is what the extra call was made for — the census text says
            // only *that* the walk fell short, and this tier runs on a machine an operator had to
            // set up, so losing the one output that explains it wastes the whole run.
            println!(
                "why the walk fell short ({} diagnostic(s)): {}",
                diagnostics["walk"]["diagnostics_emitted"], diagnostics["categories"]
            );
            // The categories fold every number into `#`, which is what makes them countable and
            // also what makes them useless for reading a *value* back off a live target. The
            // verbatim samples are the only place those survive, and this tier is the only place
            // they are ever produced.
            println!("verbatim samples: {}", diagnostics["examples"]);
            // Filtered, because the unfiltered sample is shared across every shape the walk met
            // and the interesting one is crowded out. glslang/dbgscope#104 turns on which of two
            // answers the engine gives when it cannot advance — a region reported *behind* the
            // cursor, meaning the region is over and the page step is pointless, or a zero-length
            // region reported ahead of it, meaning the step is right. The numbers separate them
            // and exist nowhere but here.
            let stalls = server.tool_data(
                "pool_diagnostics",
                json!({
                    "session_id": session,
                    "filter": "made no progress",
                    "limit": 40,
                }),
                POOL_CALL_BUDGET,
            );
            println!("stall samples: {}", stalls["examples"]);
            assert_diagnostic_total_covers_its_categories(&diagnostics);
        }

        match heaviest_census_tag(&totals) {
            // What one tool saw, the other has to find. Only meaningful when the walk completed:
            // an incomplete snapshot is deliberately not cached, so these would be two separate
            // walks of a moving target and could honestly disagree.
            HeaviestTag::Queryable(tag) if complete => {
                // The census had to come off the cached snapshot too, or the reuse below is
                // measured against a snapshot *it* took rather than the walk's.
                //
                // Against a fixed bound, not against `walked_for`: two live walks vary, and a
                // second one that happened to be quicker than the first would satisfy a relative
                // comparison while having re-walked the whole pool. A cached answer is a lookup
                // over an in-memory index and is not in the same order of magnitude.
                assert!(
                    census_took < CACHED_QUERY_CEILING,
                    "the census took {census_took:?}, past the {CACHED_QUERY_CEILING:?} a lookup \
                     over a cached snapshot should need, so it walked again rather than reusing \
                     the completed one — anything the reuse check says after that is about the \
                     census's walk, not the first one"
                );
                let cached = Instant::now();
                let found = server.tool_data(
                    "pool_find_tag",
                    json!({ "tag": tag, "session_id": session }),
                    POOL_CALL_BUDGET,
                );
                let reuse = cached.elapsed();
                assert_eq!(found["tag"], tag.as_str(), "{found}");
                assert!(
                    found["matches"].as_u64().unwrap_or_default() > 0,
                    "the census called `{tag}` the heaviest tag, so find_tag must find it in the \
                     same snapshot: {found}"
                );
                // The two tools drew on one walk, so their counts for this tag have to agree.
                // Comparing numbers rather than the phrase `allocation(s)` is the point: a count
                // that disagreed used to render identically to one that did not.
                let censused = totals["tags"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .find(|t| t["raw_tag"] == tag.as_str())
                    .cloned()
                    .unwrap_or_else(|| panic!("the census listed `{tag}`: {totals}"));
                assert_eq!(
                    censused["allocations"], found["matches"],
                    "one snapshot, two answers about `{tag}`: {censused} vs {found}"
                );
                assert!(
                    reuse < CACHED_QUERY_CEILING,
                    "a second query took {reuse:?}, past the {CACHED_QUERY_CEILING:?} a cached \
                     lookup should need — a complete snapshot is meant to be reused, not walked \
                     again (the first walk, for scale, took {walked_for:?})"
                );
                println!("`{tag}` found again from the cached snapshot in {reuse:?}");
            }
            HeaviestTag::Queryable(tag) => eprintln!(
                "NOTE: the walk was incomplete, so the census/find_tag cross-check on `{tag}` was \
                 skipped — those would be two different walks"
            ),
            HeaviestTag::NothingListed => assert!(
                !complete,
                "a walk reporting itself complete on a live kernel, with no allocated chunk at \
                 all, is not credible:\n{census}"
            ),
        }
    }));

    // Always, whatever happened above — the target is frozen until this runs.
    let ended = server.call_tool("end_session", json!({ "session_id": session }), TARGET_STEP);
    let ended_text = text_of(&ended["result"]);
    let ungraceful = ungraceful_detach(&ended, &ended_text);

    // Four outcomes, and the ordering is the point. A panic caught here has *already* printed its
    // own message and location — `catch_unwind` does not suppress the hook — so leading with the
    // target costs nothing and puts the fact needing action first. The alternative, resuming the
    // original panic and letting the detach checks below go unrun, hides a halted machine behind
    // whichever assertion happened to fail earlier.
    match (outcome, ungraceful) {
        (Err(_), Some(why)) => panic!(
            "THE TARGET MAY STILL BE HALTED — {why}\n\nThis run had already failed, for the \
             reason printed above; that is what to investigate, but check the machine first."
        ),
        (Err(panic), None) => {
            eprintln!("the target was released cleanly despite the failure above");
            resume_unwind(panic);
        }
        (Ok(()), Some(why)) => panic!("{why}"),
        (Ok(()), None) => {}
    }
}

// ---- tier 4b: a batch that actually mutates a live kernel ---------------------
//
// `debug_batch` is proved at two altitudes elsewhere: `src/batch.rs` drives the executor over a
// scripted debuggee with a virtual clock, and the dump tier drives a real engine to both outcomes
// and through both teardowns. Neither covers the case the tool exists for — **a write that is then
// restored, on a target that would notice**. A crash dump has nothing worth restoring: a byte
// "patched" in it is patched in a file nobody reads again, so a rollback that silently did nothing
// would pass every assertion the dump tier can make. The disconnect test there proves the rollback
// ran by the *file it wrote*, which is the shape of the claim rather than its substance.
//
// Here the claim is settled by reading the byte back — from a later call, from a re-attached
// session, or from a whole new server process — and the value either is the original or it is not.

/// The byte this tier patches, and what it was.
///
/// `nt`'s DOS header `e_res2` field: reserved by the PE format, zero in every image MSVC has ever
/// linked, read by the loader never and by Windows never. It is real kernel memory, it is stable
/// across a detach and re-attach (the image does not move without a reboot), and nothing in the
/// running system can observe it changing — which is exactly the combination this tier needs, since
/// the whole point is to leave the target patched for a while and then prove something put it back.
/// Anything with a *purpose* would satisfy the first two and bugcheck the machine on the third.
struct KernelScratch {
    address: u64,
    original: u64,
}

impl KernelScratch {
    /// The address as the debugger and the tools both take it.
    fn addr(&self) -> String {
        format!("{:#x}", self.address)
    }

    /// A byte value that is definitely not the original, so "the patch landed" is a real check
    /// rather than a comparison that would hold either way.
    fn patched(&self) -> u64 {
        self.original ^ 0xa5
    }

    /// A third value, distinct from both of the others, for the step that must **not** run: with
    /// two values a "it never wrote this" check could pass by coinciding with the original.
    fn never(&self) -> u64 {
        self.original ^ 0x5a
    }
}

/// `nt`'s load base, from the module list — read as a **value**, not off the listing.
///
/// This used to pick the first token of the line whose third token was `nt` and strip the backtick
/// out of it, which was reading `lm`'s rendering back in. The listing is this server's own now
/// ([#120](https://github.com/glslang/windbg-mcp/issues/120)) and the field was always there.
fn nt_base(server: &mut Server, session: &str) -> u64 {
    let modules = server.tool_data(
        "modules",
        json!({ "session_id": session, "filter": "nt" }),
        TARGET_STEP,
    );
    let start = modules["modules"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|module| module["name"] == "nt")
        .and_then(|module| module["start"].as_str())
        .unwrap_or_else(|| panic!("no `nt` in the module list: {modules}"))
        .to_string();
    u64::from_str_radix(start.trim_start_matches("0x"), 16)
        .unwrap_or_else(|e| panic!("`{start}` is not a module base ({e})"))
}

/// What the debugger makes of a MASM expression, or `None` if it would not say.
///
/// Deliberately *not* `tool_text`: several callers below use this on paths where a failure is
/// possible and must not panic, because a panic there would skip a detach and leave a kernel
/// halted.
fn eval_expr(server: &mut Server, session: &str, expr: &str) -> Option<u64> {
    let call = server.call_tool(
        "execute",
        json!({ "command": format!("? {expr}"), "session_id": session }),
        TARGET_STEP,
    );
    if !call["error"].is_null() || is_tool_error(&call) {
        eprintln!(
            "NOTE: `? {expr}` failed: {}",
            text_of(&call["result"]).trim()
        );
        return None;
    }
    // `Evaluate expression: 84 = 00000000`00000054` — the value is what follows the last `=`.
    let text = text_of(&call["result"]);
    let (_, value) = text.rsplit_once('=')?;
    u64::from_str_radix(&value.replace('`', "").trim().replace(' ', ""), 16).ok()
}

/// Reads the scratch byte and proves this target lets a debugger write it, leaving it as found.
///
/// A probe rather than an assumption, and it runs *before* any batch does, because the two ways
/// this can be unavailable are both about the host being debugged rather than about this code:
/// a header page that is not resident cannot be read, and a guest with memory integrity enabled
/// refuses debugger writes to image pages outright. Finding that out from a batch would mean
/// finding it out with a transaction already open.
///
/// `None` means the check could not be made here — reported loudly, and the caller stops. What it
/// must never do is carry on: a batch whose patch never landed would "restore" a byte that was
/// never changed and pass every assertion below while proving nothing at all.
fn kernel_scratch(server: &mut Server, session: &str) -> Option<KernelScratch> {
    // +0x28 is `e_res2[0]`; `e_lfanew` (the one header field anything reads at runtime) is at
    // +0x3c, well clear of it.
    let address = nt_base(server, session) + 0x28;
    let Some(original) = eval_expr(server, session, &format!("by({address:#x})")) else {
        eprintln!(
            "NOTE: {address:#x} (nt's DOS header) could not be read, so this run cannot patch and \
             restore a byte. Skipped rather than failed: an unreadable header page is a fact \
             about the guest, not about the server."
        );
        return None;
    };
    let scratch = KernelScratch { address, original };

    // Write it, read it back, put it back — the shortest thing that distinguishes "the debugger
    // can write here" from "the debugger accepted a write here and nothing happened".
    //
    // Under `catch_unwind`, because between the write and the restore is the one window in this
    // whole tier where a panic leaves the *guest* changed rather than merely halted: a call that
    // times out in transit has still reached DbgEng, so the byte is patched and the reply that
    // would have let this function continue never arrives. The restore below then has to run
    // anyway — the outer handlers end the session, which puts a halted kernel back but not a
    // patched one.
    let wrote = catch_unwind(AssertUnwindSafe(|| {
        server.tool_text(
            "execute",
            json!({
                "command": format!("eb {} {:#x}", scratch.addr(), scratch.patched()),
                "session_id": session,
            }),
            TARGET_STEP,
        );
        eval_expr(server, session, &format!("by({})", scratch.addr()))
    }));
    // Restore before judging the result: the assertion is the caller's business, the byte is the
    // target's, and a failed probe must not be the reason a guest is left modified.
    server.tool_text(
        "execute",
        json!({
            "command": format!("eb {} {:#x}", scratch.addr(), scratch.original),
            "session_id": session,
        }),
        TARGET_STEP,
    );
    let back = eval_expr(server, session, &format!("by({})", scratch.addr()));
    assert_eq!(
        back,
        Some(scratch.original),
        "the probe could not put {} back the way it found it ({:#x}) — stop and look at the \
         guest before running anything else here",
        scratch.addr(),
        scratch.original
    );
    // Only now, with the byte confirmed back: whatever went wrong above is worth reporting, and
    // it is worth reporting *after* the guest is whole rather than instead of making it whole.
    let wrote = match wrote {
        Ok(wrote) => wrote,
        Err(panic) => resume_unwind(panic),
    };
    if wrote != Some(scratch.patched()) {
        eprintln!(
            "NOTE: writing {} was accepted and did not take (read back {wrote:?}, wanted {:#x}), \
             so this guest does not let a debugger patch image pages — memory integrity (HVCI) \
             does exactly this. Skipped: nothing below could tell a rollback that worked from a \
             patch that never landed.",
            scratch.addr(),
            scratch.patched()
        );
        return None;
    }
    Some(scratch)
}

/// Attaches, runs `body` against the session, and **releases the target whatever `body` did**.
///
/// The ceremony every test in this tier needs and none of them may skip: from the attach onward
/// the guest is broken in, so a panic that escaped before the detach would leave someone's machine
/// frozen because an assertion failed. The ordering at the end is deliberate — a failed detach is
/// reported *first*, even when the body already failed, because it is the only outcome that needs
/// action now and the earlier failure keeps.
fn with_live_kernel_session<R>(
    server: &mut Server,
    connection: &str,
    body: impl FnOnce(&mut Server, &str) -> R,
) -> R {
    let attached = server.call_tool(
        "attach_kernel",
        json!({ "connection": connection }),
        TARGET_STEP,
    );
    let report = text_of(&attached["result"]);
    // The handle decides whether there is anything to clean up, not `isError`: an attach that
    // claimed its target and then failed the wait comes back as a tool error carrying a live,
    // halted session.
    let Some(session) = maybe_session_id(&attached["result"]) else {
        assert_no_error(&attached, "attach_kernel");
        panic!(
            "the attach did not land, and left no session behind. The target must be booted with \
             debugging enabled and dialling this host, and the KD transport is single-owner:\n\
             {report}"
        );
    };
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        assert_no_error(&attached, "attach_kernel");
        assert!(
            !is_tool_error(&attached),
            "the attach claimed its target and then failed:\n{report}"
        );
        body(server, &session)
    }));
    let ended = server.call_tool("end_session", json!({ "session_id": session }), TARGET_STEP);
    let ended_text = text_of(&ended["result"]);
    match (outcome, ungraceful_detach(&ended, &ended_text)) {
        (Err(_), Some(why)) => panic!(
            "THE TARGET MAY STILL BE HALTED — {why}\n\nThis run had already failed, for the \
             reason printed above; that is what to investigate, but check the machine first."
        ),
        (Err(panic), None) => resume_unwind(panic),
        (Ok(_), Some(why)) => panic!("{why}"),
        (Ok(value), None) => value,
    }
}

/// [`with_live_kernel_session`], for a body that only means anything against an **x64** target.
///
/// The architecture is read from the target's own `vertarget` rather than from `cfg!`, for the
/// reason [`target_is_x64`] gives: what decides this is the target, not the debugger host. That
/// costs one engine-local call, and it is asked *after* attaching because there is nowhere earlier
/// to ask — which is fine, since the detach the wrapped helper performs runs either way.
fn with_live_x64_kernel_session(
    server: &mut Server,
    connection: &str,
    body: impl FnOnce(&mut Server, &str),
) {
    with_live_kernel_session(server, connection, |server, session| {
        let report = server.tool_text(
            "execute",
            json!({ "command": "vertarget", "session_id": session }),
            TARGET_STEP,
        );
        if !target_is_x64(&report) {
            skip(NOT_X64_SKIP);
            return;
        }
        body(server, session);
    });
}

/// The steps that save a byte, patch it, and prove the patch landed — the opening of every
/// mutating batch below, and the part that has to be true before a rollback means anything.
fn patch_steps(scratch: &KernelScratch) -> Vec<Value> {
    vec![
        json!({
            "op": "eval", "expr": format!("by({})", scratch.addr()), "capture": "orig",
            "name": "save the byte we are about to overwrite",
        }),
        json!({
            "op": "command", "command": format!("eb {} {:#x}", scratch.addr(), scratch.patched()),
            "name": "patch it",
        }),
        // An assertion, because DbgEng reports most write failures by printing them and returning
        // success — so "the `eb` step succeeded" is not the same claim as "the byte changed", and
        // only the second one makes the restore below worth measuring.
        json!({
            "op": "eval", "expr": format!("by({})", scratch.addr()),
            "name": "the patch is really in the target",
            "expect": [{
                "check": "eval",
                "expr": format!("by({})", scratch.addr()),
                "equals": format!("{:#x}", scratch.patched()),
            }],
        }),
    ]
}

/// The `always` block: put the captured byte back, whatever happened.
fn restore_steps(scratch: &KernelScratch) -> Vec<Value> {
    vec![json!({
        "op": "command", "command": format!("eb {} {{{{orig}}}}", scratch.addr()),
        "name": "restore the byte",
    })]
}

/// A batch that patches a live kernel and then fails: the `always` block has to put the byte back,
/// and a **later, separate call** has to see it back.
///
/// This is the claim `debug_batch` was built for, made where it can actually be false. Everything
/// the dump tier can say about a rollback is about control flow — the block ran, its steps reported
/// OK. Here the target holds a byte that either changed back or did not, and nothing in the batch's
/// own report is trusted to settle it: the verification is a separate tool call, made after the
/// batch has returned, exactly as a caller would make it.
#[test]
#[ignore = "needs a live KDNET target and its connection string; run manually, last"]
fn a_mutating_batch_on_a_live_kernel_restores_its_patch_when_a_step_fails() {
    let Some(connection) = kernel_tier() else {
        return;
    };
    let mut server = Server::started_with(&[(
        "WINDBG_MCP_CALL_TIMEOUT_SECS",
        &SERVER_CALL_TIMEOUT.as_secs().to_string(),
    )]);

    with_live_kernel_session(&mut server, &connection, |server, session| {
        let Some(scratch) = kernel_scratch(server, session) else {
            return;
        };
        println!(
            "scratch byte {} reads {:#x}",
            scratch.addr(),
            scratch.original
        );

        let mut steps = patch_steps(&scratch);
        steps.push(json!({
            "op": "command", "command": "version",
            "name": "an assertion that cannot hold",
            "expect": [{ "check": "contains", "text": "no version banner says this" }],
        }));
        steps.push(json!({
            "op": "command", "command": format!("eb {} {:#x}", scratch.addr(), scratch.never()),
            "name": "must not run",
        }));
        let call = server.call_tool(
            "debug_batch",
            json!({
                "session_id": session,
                "steps": steps,
                "always": restore_steps(&scratch),
            }),
            TARGET_STEP,
        );
        let report = text_of(&call["result"]);
        assert_no_error(&call, "debug_batch on a live kernel");
        assert!(
            is_tool_error(&call),
            "a batch that did not commit must come back as a tool error:\n{report}"
        );
        assert!(
            report.contains("BATCH: FAILED at step 4 of 5"),
            "the batch had to stop at the assertion that cannot hold:\n{report}"
        );
        assert!(
            report.contains("rollback: COMPLETE"),
            "the `always` block must run on the failing path — that is the whole point:\n{report}"
        );

        // The claim, from outside the batch: the byte is what it was before any of this ran.
        let now = eval_expr(server, session, &format!("by({})", scratch.addr()));
        assert_eq!(
            now,
            Some(scratch.original),
            "the rollback reported COMPLETE and {} still reads {now:?} rather than {:#x} — the \
             restore ran and did not take, which is worse than not running:\n{report}",
            scratch.addr(),
            scratch.original
        );
        // And the step after the failure never wrote its own value, so "SKIPPED" is a fact about
        // the target and not only about the report.
        assert_ne!(
            now,
            Some(scratch.never()),
            "the step after the failure ran anyway"
        );
        println!("the patch was applied inside the batch and restored by its rollback");
    });
}

/// The same batch under a **call budget shorter than the batch asks for**: the clamp in
/// `worker::batch_budget` has to keep the whole report — steps, rollback and all — inside the
/// caller's own timeout.
///
/// Only a live target can test this honestly. Against a dump every step returns in microseconds, so
/// a batch never reaches its deadline and the clamp is arithmetic nobody exercises; here the steps
/// take real time and the batch is deliberately given more of it than the call has. What must come
/// back is a *report* — not a timeout from the server, and not silence — with the byte restored.
#[test]
#[ignore = "needs a live KDNET target and its connection string; run manually, last"]
fn a_live_kernel_batch_reports_and_rolls_back_before_its_callers_timeout() {
    let Some(connection) = kernel_tier() else {
        return;
    };
    /// Short enough that a batch of real steps runs out of time inside it, long enough that the
    /// attach and the probe are unaffected.
    const CALL_BUDGET: Duration = Duration::from_secs(60);
    let mut server = Server::started_with(&[(
        "WINDBG_MCP_CALL_TIMEOUT_SECS",
        &CALL_BUDGET.as_secs().to_string(),
    )]);

    with_live_kernel_session(&mut server, &connection, |server, session| {
        let Some(scratch) = kernel_scratch(server, session) else {
            return;
        };

        let mut steps = patch_steps(&scratch);
        // Nearly a minute of work in a budget that will be clamped to well under it, so the
        // deadline is certain to expire. Many short steps rather than a few long ones on purpose:
        // the clock is then crossed *between* steps, where the executor stops cleanly, instead of
        // inside one, where the outcome depends on whether the engine honours an interrupt during
        // a `.sleep` — a property of DbgEng that this test has no business asserting.
        steps.extend(std::iter::repeat_n(
            json!({ "op": "command", "command": ".sleep 1000" }),
            55,
        ));
        let started = Instant::now();
        let call = server.call_tool(
            "debug_batch",
            json!({
                "session_id": session,
                "steps": steps,
                // Ten minutes, which this call does not have. The clamp is what stops that being
                // a rollback report nobody is left to read.
                "timeout_ms": 600_000,
                "always": restore_steps(&scratch),
            }),
            TARGET_STEP,
        );
        let took = started.elapsed();
        let report = text_of(&call["result"]);
        assert_no_error(&call, "debug_batch under a short call budget");
        assert!(
            report.contains("BATCH: TIMED OUT"),
            "the batch should have run out of its (clamped) time and said so:\n{report}"
        );
        assert!(
            report.contains("rollback: COMPLETE"),
            "the reserve exists so the rollback still runs when the steps use the clock up:\n\
             {report}"
        );
        assert!(
            took < CALL_BUDGET,
            "the report took {took:?}, past the {CALL_BUDGET:?} its caller was waiting — the \
             batch outlived the call it belongs to, which is what the clamp exists to prevent"
        );
        println!("a 10-minute batch reported in {took:?}, inside a {CALL_BUDGET:?} call budget");

        let now = eval_expr(server, session, &format!("by({})", scratch.addr()));
        assert_eq!(
            now,
            Some(scratch.original),
            "the byte was not restored when the batch ran out of time:\n{report}"
        );
    });
}

/// A client **disconnect** while a live kernel batch holds a patch: the rollback has to run before
/// the worker goes, and the byte has to be back when somebody else looks.
///
/// The dump tier proves this by the log file the `always` block writes, because by then there is no
/// client, no supervisor and no worker left to ask. That proves the block *ran*; it cannot prove
/// what it did to a target, because a dump has nothing to do anything to. Here the evidence is the
/// guest's own memory, read by a **new server process** over a fresh attach — the byte outlives
/// every process that was involved in patching it.
#[test]
#[ignore = "needs a live KDNET target and its connection string; run manually, last"]
fn a_disconnect_lets_a_live_kernel_batch_restore_its_patch_first() {
    let Some(connection) = kernel_tier() else {
        return;
    };
    let running = marker_path("live-kernel-batch-running");
    let _ = std::fs::remove_file(&running);

    let mut server = Server::started_with(&[(
        "WINDBG_MCP_CALL_TIMEOUT_SECS",
        &SERVER_CALL_TIMEOUT.as_secs().to_string(),
    )]);
    let attached = server.call_tool(
        "attach_kernel",
        json!({ "connection": connection }),
        TARGET_STEP,
    );
    let report = text_of(&attached["result"]);
    assert_no_error(&attached, "attach_kernel");
    let session = maybe_session_id(&attached["result"])
        .unwrap_or_else(|| panic!("the attach left no session behind:\n{report}"));
    assert!(
        !is_tool_error(&attached),
        "the attach claimed its target and then failed; this test needs one that landed:\n{report}"
    );
    // Everything up to the disconnect runs under `catch_unwind`: from the attach onward the guest
    // is broken in, and the release is the disconnect itself, so a panic before it would leave the
    // machine frozen for the sake of a failed assertion. That includes the two lines below, which
    // look harmless and would still cost a VM.
    let ready = catch_unwind(AssertUnwindSafe(|| {
        // Read now, because the re-attach below has to wait for this process to be gone: the KD
        // transport is single-owner, so a second attach that races the first worker's exit fails
        // on the port rather than on anything this test is about.
        let status = server.tool_data("session_status", json!({}), STEP);
        let worker = engine_pid_of(&status, &session);
        let scratch = kernel_scratch(&mut server, &session)?;

        // Patch, announce, then spend twenty seconds so the disconnect lands squarely inside the
        // batch with the byte already changed. The marker is written *after* the patch for exactly
        // that reason: waiting on it means waiting for a target that is genuinely modified.
        let mut steps = patch_steps(&scratch);
        steps.push(
            json!({ "op": "command", "command": format!(".logopen \"{}\"", running.display()) }),
        );
        steps.push(json!({ "op": "command", "command": ".echo BATCH-RUNNING" }));
        steps.push(json!({ "op": "command", "command": ".logclose" }));
        steps.extend(std::iter::repeat_n(
            json!({ "op": "command", "command": ".sleep 1000" }),
            20,
        ));
        // Sent without waiting: nobody will be here to read the answer, which is the whole
        // scenario.
        server.send_request(
            "tools/call",
            json!({
                "name": "debug_batch",
                "arguments": {
                    "session_id": session,
                    "steps": steps,
                    "always": restore_steps(&scratch),
                }
            }),
        );

        // Disconnect only once the patch is demonstrably in the target. Timing it with a sleep
        // would make a slow machine into a test that proves nothing: the batch would not have
        // started, and refusing to start is a *different* correct behaviour with the same green
        // tick.
        let deadline = Instant::now() + TARGET_STEP;
        while !running.exists() {
            assert!(
                Instant::now() < deadline,
                "the batch never got past its patch steps, so the disconnect below would prove \
                 nothing\n--- stderr ---\n{}",
                server.stderr()
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        Some((scratch, worker))
    }));
    let (scratch, worker) = match ready {
        Ok(Some(ready)) => ready,
        // Either nothing to prove (no writable scratch byte) or an assertion failed. Both leave a
        // halted kernel that has to be released the ordinary way, since the disconnect below is
        // now not going to happen.
        other => {
            let ended =
                server.call_tool("end_session", json!({ "session_id": session }), TARGET_STEP);
            let text = text_of(&ended["result"]);
            if let Some(why) = ungraceful_detach(&ended, &text) {
                panic!("THE TARGET MAY STILL BE HALTED — {why}");
            }
            match other {
                Err(panic) => resume_unwind(panic),
                _ => return,
            }
        }
    };
    let (base, expected) = (scratch.address, scratch.original);

    let disconnected = Instant::now();
    let exit = catch_unwind(AssertUnwindSafe(|| server.shutdown()));
    let took = disconnected.elapsed();

    // The worker outlives the supervisor by however long its rollback and release take, and it
    // owns the KD endpoint until it exits.
    let deadline = Instant::now() + Duration::from_secs(20);
    while process_alive(worker) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    let worker_gone = !process_alive(worker);

    // Re-attach from a *new server process* and ask the guest what the byte says now. Everything
    // is collected rather than asserted until the target has been released again.
    let mut again = Server::started_with(&[(
        "WINDBG_MCP_CALL_TIMEOUT_SECS",
        &SERVER_CALL_TIMEOUT.as_secs().to_string(),
    )]);
    let (base_now, byte_now) =
        with_live_kernel_session(&mut again, &connection, |server, session| {
            (
                nt_base(server, session),
                eval_expr(server, session, &format!("by({:#x})", base)),
            )
        });

    match exit {
        Ok(code) => assert_eq!(code, Some(0), "a disconnect should still be a clean exit"),
        Err(panic) => resume_unwind(panic),
    }
    assert!(
        worker_gone,
        "engine worker pid {worker} outlived the connection"
    );
    assert_eq!(
        base_now + 0x28,
        base,
        "the guest rebooted between the two attaches, so the byte read back is not the byte that \
         was patched and this run can say nothing about the rollback"
    );
    assert_eq!(
        byte_now,
        Some(expected),
        "{:#x} still reads {byte_now:?} rather than {expected:#x} after a disconnect — the batch \
         was terminated with its patch in place, which on a real target is the loss this tool \
         exists to prevent",
        base
    );
    // The steps had twenty seconds left. Waiting them out would be a rollback that happened for
    // the wrong reason — the batch finishing normally — and would say nothing about abandoning one.
    assert!(
        took < Duration::from_secs(15),
        "the disconnect took {took:?}: the batch ran on instead of stopping at its next step"
    );
    println!(
        "a disconnect mid-patch left {:#x} restored to {expected:#x}",
        base
    );
    let _ = std::fs::remove_file(&running);
}

/// `end_session` while a live kernel batch holds a patch — the same guarantee with a client still
/// present to be told about it.
///
/// Two things have to be true at once here, and only the first is testable against a dump: the
/// batch's own call comes back saying `BATCH: ABANDONED` with the rollback complete, *and* the
/// guest's memory agrees. The session is gone by then, so the byte is read over a second attach.
#[test]
#[ignore = "needs a live KDNET target and its connection string; run manually, last"]
fn ending_a_live_kernel_session_mid_batch_restores_its_patch() {
    let Some(connection) = kernel_tier() else {
        return;
    };
    let running = marker_path("live-kernel-end-session-batch");
    let _ = std::fs::remove_file(&running);

    let mut server = Server::started_with(&[(
        "WINDBG_MCP_CALL_TIMEOUT_SECS",
        &SERVER_CALL_TIMEOUT.as_secs().to_string(),
    )]);

    // The first session is ended *by the test itself*, mid-batch, so it cannot use the helper —
    // but everything it does before that still has to be unwound if it fails.
    let attached = server.call_tool(
        "attach_kernel",
        json!({ "connection": connection }),
        TARGET_STEP,
    );
    let report = text_of(&attached["result"]);
    assert_no_error(&attached, "attach_kernel");
    let session = maybe_session_id(&attached["result"])
        .unwrap_or_else(|| panic!("the attach left no session behind:\n{report}"));
    assert!(
        !is_tool_error(&attached),
        "the attach claimed its target and then failed:\n{report}"
    );
    // Under `catch_unwind` from here: the guest is broken in, and the `end_session` below is what
    // releases it — so nothing in between may propagate a panic past it, including the two
    // bookkeeping calls that open this block.
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        // The second attach has to wait for this worker to exit before it can claim the KD
        // transport, which is single-owner.
        let status = server.tool_data("session_status", json!({}), STEP);
        let worker = engine_pid_of(&status, &session);
        let scratch = kernel_scratch(&mut server, &session)?;
        let mut steps = patch_steps(&scratch);
        steps.push(
            json!({ "op": "command", "command": format!(".logopen \"{}\"", running.display()) }),
        );
        steps.push(json!({ "op": "command", "command": ".echo BATCH-RUNNING" }));
        steps.push(json!({ "op": "command", "command": ".logclose" }));
        steps.extend(std::iter::repeat_n(
            json!({ "op": "command", "command": ".sleep 1000" }),
            20,
        ));
        let batch = server.send_request(
            "tools/call",
            json!({
                "name": "debug_batch",
                "arguments": {
                    "session_id": session,
                    "steps": steps,
                    "always": restore_steps(&scratch),
                }
            }),
        );

        let deadline = Instant::now() + TARGET_STEP;
        while !running.exists() {
            assert!(
                Instant::now() < deadline,
                "the batch never got past its patch steps\n--- stderr ---\n{}",
                server.stderr()
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        Some((scratch, batch, worker))
    }));

    // Whatever happened above, this session is ending now — it is either the act under test or the
    // cleanup, and on a broken-in kernel it is not optional.
    let asked = Instant::now();
    let ended = server.call_tool("end_session", json!({ "session_id": session }), TARGET_STEP);
    let ended_text = text_of(&ended["result"]);
    let took = asked.elapsed();
    if let Some(why) = ungraceful_detach(&ended, &ended_text) {
        panic!("THE TARGET MAY STILL BE HALTED — {why}");
    }
    let started = match outcome {
        Ok(started) => started,
        Err(panic) => resume_unwind(panic),
    };
    let Some((scratch, batch, worker)) = started else {
        return;
    };

    // The batch's own reply, which the client is still here to receive.
    let report = text_of(&server.await_id(batch, "debug_batch", TARGET_STEP)["result"]);
    assert!(
        report.contains("BATCH: ABANDONED"),
        "the batch should say it was cut short, not that it failed or timed out:\n{report}"
    );
    assert!(
        report.contains("rollback: COMPLETE"),
        "the rollback is the reason for stopping early:\n{report}"
    );
    assert!(
        took < Duration::from_secs(15),
        "end_session took {took:?}: it waited out the batch instead of stopping it at its next step"
    );

    // The KD transport is single-owner, so the second attach has to wait for the first worker to
    // be gone rather than race it.
    let deadline = Instant::now() + Duration::from_secs(20);
    while process_alive(worker) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        !process_alive(worker),
        "engine worker pid {worker} outlived the session that was ended"
    );

    let byte_now = with_live_kernel_session(&mut server, &connection, |server, session| {
        assert_eq!(
            nt_base(server, session) + 0x28,
            scratch.address,
            "the guest rebooted between the two attaches, so nothing below is about the byte that \
             was patched"
        );
        eval_expr(server, session, &format!("by({})", scratch.addr()))
    });
    assert_eq!(
        byte_now,
        Some(scratch.original),
        "the batch reported its rollback complete, but {} reads {byte_now:?} rather than {:#x} on \
         a fresh attach:\n{report}",
        scratch.addr(),
        scratch.original
    );
    println!("`end_session` mid-batch left the guest with its byte restored");
    let _ = std::fs::remove_file(&running);
}

/// A batch step that asks the **pool** about a pointer it just captured — the one shape the CTF
/// workflow needed and `debug_batch` could not express (`FOLLOWUPS.md` item 17).
///
/// Live-only, and not incidentally: the pool tools walk the allocator's own descriptors, which
/// needs a broken-in x64 kernel with `nt` private symbols. What it proves beyond the unit tests is
/// the part that only exists over a wire — that a step's walk is armed with the *batch's* budget
/// rather than the walker's own default, and still answers.
#[test]
#[ignore = "needs a live KDNET target and its connection string; run manually, last"]
fn a_live_kernel_batch_step_can_ask_the_pool_about_a_captured_pointer() {
    let Some(connection) = kernel_tier() else {
        return;
    };
    let engine = ensure_engine_beside_test_binary();
    println!("engine: {engine}");
    // Pinned below `POOL_CALL_BUDGET`, exactly as the pool tier is, and that ordering is not
    // adjustable: the server has to answer before the *harness* gives up, or the `end_session` in
    // the cleanup queues behind a walk that is still running, misses its grace, and the worker is
    // killed — which on a broken-in kernel leaves the guest halted. Raising this above the harness
    // budget to buy the batch more room would buy it by inverting that.
    let mut server = Server::started_with(&[(
        "WINDBG_MCP_CALL_TIMEOUT_SECS",
        &SERVER_CALL_TIMEOUT.as_secs().to_string(),
    )]);

    with_live_x64_kernel_session(&mut server, &connection, |server, session| {
        let symbols = load_kernel_symbols(server, session);
        assert!(
            symbols.loaded.contains("pdb symbols") && !symbols.probe.is_empty(),
            "a pool step needs full `nt` symbols and the pool-root global, same as the pool tools. \
             If a known-good path exists, set {SYMBOLS_ENV}. Engine setup said: {engine}\n{}",
            symbols.transcript
        );

        // `@$proc` is the current process's EPROCESS — a real pool allocation, and a pointer the
        // debugger will hand over without any of this having to know an address in advance.
        let call = server.call_tool(
            "debug_batch",
            json!({
                "session_id": session,
                // The walk is the expensive part and it is inside the batch, so give the batch
                // room for it — the point is that the *step* bounds the walk, not that nothing
                // ever has to wait. Asking for the whole call budget is deliberate and the clamp
                // to it (minus the reply's headroom) is the expected outcome: what the steps then
                // have is ~255s, against a walk measured at ~52s over KDNET.
                "timeout_ms": 300_000,
                "steps": [
                    { "op": "eval", "expr": "@$proc", "capture": "proc",
                      "name": "the EPROCESS the target is running on" },
                    { "op": "pool_chunk", "address": "{{proc}}", "refresh": true,
                      "name": "what the allocator says that pointer is" },
                    { "op": "pool_census", "limit": 8, "name": "and what the pool holds overall",
                      "expect": [{ "check": "contains", "text": "chunks walked:" }] }
                ]
            }),
            POOL_CALL_BUDGET,
        );
        let report = text_of(&call["result"]);
        assert_no_error(&call, "debug_batch with pool steps");
        assert!(
            !is_tool_error(&call),
            "the pool steps failed inside the batch:\n{report}\n\nsymbol setup said:{}",
            symbols.transcript
        );
        assert!(
            report.contains("BATCH: COMMITTED"),
            "a read-only batch of pool queries should commit:\n{report}"
        );
        // Nothing was written, and the report must not claim otherwise: a pool walk reads
        // descriptors, however long it takes to do it.
        assert!(
            report.contains("mutations: none recognised"),
            "pool queries change nothing:\n{report}"
        );
        // The captured pointer reached the query — a `{{proc}}` surviving into the report would
        // mean nothing was bound.
        assert!(
            !report.contains("{{proc}}"),
            "the capture was not interpolated into the pool step:\n{report}"
        );
        // Either answer is correct and they are different facts, so accept both by name rather
        // than asserting the walk covered this particular chunk.
        assert!(
            report.contains("chunk tagged") || report.contains("not covered by the pool snapshot"),
            "the pool_chunk step answered neither of the two things it can say:\n{report}"
        );
        println!("a pool query inside a live-kernel batch:\n{report}");
    });
}

/// End-to-end CTF regression: a real MessageManager image and its retained `Tgsm` objects must be
/// visible through the shipped MCP transport, DbgEng worker, symbol setup, and structured pool
/// tools. The target-side fixture is deployed by `examples/messagemanager/ctf_regression.ps1`.
///
/// This has its own environment gate in addition to `#[ignore]` and the KDNET connection string,
/// because the generic live-kernel tier is useful on machines that do not have this driver.
#[test]
#[ignore = "needs the live MessageManager CTF fixture; use ctf_regression.ps1"]
fn a_messagemanager_ctf_fixture_is_visible_through_mcp() {
    if !messagemanager_ctf_tier() {
        return;
    }
    let Some(connection) = kernel_tier() else {
        return;
    };
    let engine = ensure_engine_beside_test_binary();
    println!("engine: {engine}");
    let mut server = Server::started_with(&[(
        "WINDBG_MCP_CALL_TIMEOUT_SECS",
        &SERVER_CALL_TIMEOUT.as_secs().to_string(),
    )]);

    let attached = server.call_tool(
        "attach_kernel",
        json!({ "connection": connection }),
        TARGET_STEP,
    );
    let report = text_of(&attached["result"]);
    let Some(session) = maybe_session_id(&attached["result"]) else {
        assert_no_error(&attached, "attach_kernel for MessageManager CTF");
        panic!(
            "the CTF attach did not land and left no session to release. Confirm the guest is \
             booted with debugging enabled and dialling this host:\n{report}"
        );
    };

    let outcome = catch_unwind(AssertUnwindSafe(|| {
        assert_no_error(&attached, "attach_kernel for MessageManager CTF");
        assert!(
            !is_tool_error(&attached),
            "the CTF attach reported a tool failure:\n{report}"
        );

        // **Before any symbol work**, which is the whole of what this assertion now claims
        // ([#85]). The driver was loaded before the debugger dialled in, so it is in the target
        // and not yet in DbgEng's inventory — a fresh attach here lists `nt` and little else, and
        // a `modules` call straight after one read as "the challenge driver is not loaded" while
        // it was open and serving IOCTLs. It used to be found only *after* `load_kernel_symbols`
        // below, whose unqualified `.reload /f` resynchronised the inventory as a side effect of
        // fetching every PDB: the answer was right and the caller had no way to know that a full
        // symbol load was what made it right. `refresh` is that resynchronisation on its own, and
        // asking here means a pass cannot be borrowed from the reload that follows.
        //
        // Matched against module *names*, not against a substring of the whole `lm` listing:
        // "messagemanager appears somewhere in that text" was true of a symbol path echoed into
        // the same output, which is the kind of accidental pass a field cannot give.
        //
        // [#85]: https://github.com/glslang/windbg-mcp/issues/85
        let modules = server.tool_data(
            "modules",
            json!({ "session_id": session, "filter": "MessageManager", "refresh": true }),
            TARGET_STEP,
        );
        assert_eq!(
            modules["refresh"]["synchronized"],
            json!(true),
            "the resynchronisation itself failed, so nothing below it says anything about the \
             fixture: {modules}"
        );
        let driver = modules["modules"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|m| {
                m["name"]
                    .as_str()
                    .is_some_and(|name| name.eq_ignore_ascii_case("MessageManager"))
            })
            .cloned();
        assert!(
            driver.is_some(),
            "the fixture reported ready, but KD does not list MessageManager.sys after an \
             inventory refresh the engine reports it made, from {} module(s):\n{}",
            modules["refresh"]["before"],
            text_of(
                &server.call_tool(
                    "modules",
                    json!({ "session_id": session, "limit": 2000 }),
                    TARGET_STEP
                )["result"]
            ),
        );

        let symbols = load_kernel_symbols(&mut server, &session);
        assert!(
            symbols.loaded.contains("pdb symbols") && !symbols.probe.is_empty(),
            "the CTF pool check needs full `nt` symbols and the pool-root global. If a known-good \
             path exists, set {SYMBOLS_ENV}. Engine setup said: {engine}\n{}",
            symbols.transcript
        );

        let started = Instant::now();
        let call = server.call_tool(
            "pool_find_tag",
            json!({
                "tag": "Tgsm",
                "paged": false,
                "refresh": true,
                "stop_after_matches": 1,
                "limit": 1,
                "session_id": session,
            }),
            POOL_CALL_BUDGET,
        );
        let found = text_of(&call["result"]);
        assert_no_error(&call, "pool_find_tag Tgsm on MessageManager CTF");
        assert!(
            !is_tool_error(&call),
            "the structured pool query failed:\n{found}\n\nsymbol setup said:{}",
            symbols.transcript
        );
        let matches = call["result"]["structuredContent"].clone();
        assert_eq!(
            matches["matches"].as_u64(),
            Some(1),
            "the target fixture retained `Tgsm` messages, but the MCP pool snapshot did not find \
             them. Read the walk's coverage before treating an incomplete walk as an allocator \
             result: {matches}"
        );
        assert_eq!(
            matches["walk"]["coverage"], "match_limit_reached",
            "an existence query must report its deliberate early stop separately from a deadline \
             or decoder failure: {matches}"
        );
        assert_eq!(matches["walk"]["stop_after_matches"], 1, "{matches}");
        // Every chunk it hands back really carries the tag that was asked for, at an address in
        // this server's one representation — the two claims a caller acts on.
        for chunk in matches["chunks"].as_array().into_iter().flatten() {
            assert_eq!(chunk["tag"], "Tgsm", "{chunk}");
            assert_eq!(
                chunk["state"], "allocated",
                "find_tag indexes only allocated chunks"
            );
            assert!(address_of(&chunk["address"]) != 0, "{chunk}");
        }
        println!(
            "MessageManager `Tgsm` allocations found through MCP in {:?}: {} chunk(s), {} bytes, \
             walk {}",
            started.elapsed(),
            matches["matches"],
            matches["total_bytes"],
            matches["walk"]["coverage"],
        );

        let registers =
            server.tool_data("registers", json!({ "session_id": session }), TARGET_STEP);
        assert!(
            registers["instruction_pointer"].is_string(),
            "the kernel session did not remain usable after the CTF pool walk: {registers}"
        );
    }));

    // Whatever the assertion outcome, release the broken-in kernel before propagating it.
    let ended = server.call_tool("end_session", json!({ "session_id": session }), TARGET_STEP);
    let ended_text = text_of(&ended["result"]);
    match (outcome, ungraceful_detach(&ended, &ended_text)) {
        (Err(_), Some(why)) => panic!(
            "THE TARGET MAY STILL BE HALTED — {why}\n\nThe CTF check had already failed; check \
             the VM before investigating the earlier assertion."
        ),
        (Err(panic), None) => resume_unwind(panic),
        (Ok(()), Some(why)) => panic!("{why}"),
        (Ok(()), None) => println!("MessageManager CTF session detached cleanly"),
    }
}

/// Why a detach cannot be called graceful, or `None` when it can.
///
/// Three ways to fail and they are easy to conflate. A protocol error means the call did not
/// arrive; a *tool* error means it did and the session could not be released — a worker that
/// exited or crashed, whose text need not contain "terminated" — and "terminated" itself means the
/// worker was killed. Only the last was checked for a long time, so the first two passed as clean
/// detaches. All three leave a broken-in kernel halted, which is the one outcome this tier must
/// never report as success.
fn ungraceful_detach(ended: &Value, text: &str) -> Option<String> {
    if !ended["error"].is_null() {
        return Some(format!(
            "end_session was answered with a JSON-RPC error, so nothing released the target: {}",
            ended["error"]
        ));
    }
    if is_tool_error(ended) {
        return Some(format!(
            "end_session reported a failure, so no graceful detach was confirmed:\n{text}"
        ));
    }
    if text.contains("terminated") {
        return Some(format!(
            "the worker was killed instead of detaching, and DbgEng leaves a detached-but-halted \
             kernel frozen:\n{text}"
        ));
    }
    None
}

// ---- tier 5: recording a TTD trace, and reading it back -----------------------

/// Gate for the tier that drives the **TTD recorder** and replays what it wrote.
///
/// One environment variable and no `#[ignore]`, unlike the two tiers above it. Those are
/// double-gated because a stale variable there costs something real — a wedged VM, a run measured
/// in minutes — where the worst this does is leave a few tens of MB in the temp directory. Against
/// that, [`launch_tier`]'s rule applies with full force: a gate nothing sets is a gap that stays
/// open, and this tier exists because three defects shipped with nothing exercising these calls
/// (#231, #232, #233).
///
/// The **host's** two reasons to stand down are deliberately not this gate's: a machine with no
/// recorder, and a server that is not elevated, are read off the recorder's own refusal in
/// [`recorded`]. Probing for them here would mean a second copy of `ttd::find_ttd`'s search in a
/// file that cannot call it, which is the kind of duplicate that goes quietly out of date.
fn ttd_tier() -> bool {
    if std::env::var_os("WINDBG_MCP_SMOKE_TTD").is_none() {
        skip("set WINDBG_MCP_SMOKE_TTD=1 to run the TTD recording tier");
        return false;
    }
    true
}

/// A recording is generous with its clock: `TTD.exe` is located on disk, spawned, and watched for
/// its whole startup window before the call can answer at all.
const RECORD_STEP: Duration = Duration::from_secs(120);

/// An empty directory of this tier's own to record into.
///
/// Per test and per process, and emptied first, because [`recorded_trace`] identifies a recording
/// by what is in the directory — a `.run` left by an earlier run of the same test would be read as
/// this one's, and the assertion would be about the wrong file.
fn recording_dir(what: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "windbg-mcp-smoke-ttd-{what}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create the recording directory");
    dir
}

/// Runs one `record_trace`, standing the tier down for the two reasons that are the **host's**
/// rather than this server's.
///
/// Returns the success text, or `None` having printed a `SKIPPED` line. Every other failure fails
/// the test, and that separation is the point: "not elevated" and "recording is broken" are
/// indistinguishable to a helper that treats any error as a skip, which is how a tier comes to
/// pass while covering nothing.
fn recorded(server: &mut Server, out_dir: &std::path::Path, args: Value) -> Option<String> {
    let mut arguments = args;
    arguments["out_dir"] = json!(out_dir.to_string_lossy());
    let response = server.call_tool("record_trace", arguments.clone(), RECORD_STEP);
    assert_no_error(&response, "tools/call record_trace");
    let text = text_of(&response["result"]);
    if is_tool_error(&response) {
        let lower = text.to_ascii_lowercase();
        // No recorder installed, and not elevated — the two states a developer's machine is
        // legitimately in. `0x80070005` is the code the un-elevated refusal carries.
        if lower.contains("ttd.exe not found")
            || lower.contains("administrative privileges")
            || lower.contains("access is denied")
            || lower.contains("0x80070005")
        {
            skip(&format!("this host cannot record a TTD trace: {text}"));
            return None;
        }
        panic!("`record_trace {arguments}` failed for a reason that is not the host's:\n{text}");
    }
    Some(text)
}

/// The `.run` a recording left behind, read off the directory rather than out of the message.
///
/// Deliberately not parsed from `record_trace`'s prose, though the prose names it: the claim under
/// test is that a finished recording *exists*, and a test that took the path from the sentence
/// asserting it would be checking that sentence against itself.
fn recorded_trace(out_dir: &std::path::Path) -> std::path::PathBuf {
    let mut traces: Vec<std::path::PathBuf> = std::fs::read_dir(out_dir)
        .expect("read the recording directory")
        .flatten()
        .map(|entry| entry.path())
        .filter(|p| p.extension().is_some_and(|e| e.eq_ignore_ascii_case("run")))
        .collect();
    traces.sort();
    assert_eq!(
        traces.len(),
        1,
        "one recording should leave exactly one trace in {}, found {traces:?}",
        out_dir.display()
    );
    let trace = traces.remove(0);
    let size = std::fs::metadata(&trace).expect("stat the trace").len();
    assert!(size > 0, "`{}` is an empty trace", trace.display());
    trace
}

/// The lower-cased file name of a trace, which is how this tier reads *which program* was
/// recorded: `TTD.exe` names a trace after the program it launched, so `cmd01.run` is evidence
/// about the process that ran and not merely about the call returning.
fn trace_name(trace: &std::path::Path) -> String {
    trace
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default()
}

/// Issue #233: a target that finishes inside the startup watch is a **complete recording**, not a
/// failed one.
///
/// `hostname.exe` runs in about 150ms against a 2.5s watch, so it exits while the recorder is
/// still being watched for a fast failure — and every exit in that window used to be reported as
/// one, quoting TTD's `Launching '<target>'` banner as the reason. The trace was on disk and
/// replayed correctly the whole time, which is what makes this the worst shape of the three: the
/// tool said the opposite of what had happened.
#[test]
fn ttd_records_a_target_that_finishes_inside_the_startup_watch_as_complete() {
    if !ttd_tier() {
        return;
    }
    let out_dir = recording_dir("short");
    let mut server = Server::started();
    let Some(text) = recorded(&mut server, &out_dir, json!({ "target": "hostname.exe" })) else {
        return;
    };

    // The claim, and then the file — deliberately two different sources for the one fact.
    assert!(
        text.contains("recording complete"),
        "a target that has already exited should be reported as complete, not as started:\n{text}"
    );
    let trace = recorded_trace(&out_dir);
    assert!(
        text.contains(trace.to_string_lossy().as_ref()),
        "the message should name the trace it left, so a caller need not go looking for it:\n{text}"
    );

    let _ = std::fs::remove_dir_all(&out_dir);
}

/// Issue #232: the arguments in `target` reach the program instead of becoming part of its name.
///
/// The whole string went to `TTD.exe` as one argv entry, so the recorder looked for a file called
/// `cmd.exe /c dir …` and answered `0x80004005` — "cannot find the file specified", a message
/// about the program when the fault was in the quoting. Recording at all is most of the claim,
/// since the old behaviour could not; the trace's **name** is the rest, and is what would catch a
/// split that succeeded while resolving the first token to something else.
#[test]
fn ttd_records_the_program_a_target_with_arguments_names() {
    if !ttd_tier() {
        return;
    }
    let out_dir = recording_dir("arguments");
    let mut server = Server::started();
    let target = "cmd.exe /c dir C:\\Windows\\System32\\ntdll.dll";
    let Some(text) = recorded(&mut server, &out_dir, json!({ "target": target })) else {
        return;
    };
    assert!(text.contains("recording complete"), "{text}");

    let name = trace_name(&recorded_trace(&out_dir));
    assert!(
        name.starts_with("cmd"),
        "`{name}` should be named after `cmd.exe`; a trace named after anything else means the \
         first token resolved to a different program"
    );

    let _ = std::fs::remove_dir_all(&out_dir);
}

/// A relative `target` is resolved where the **recorder** runs, not where this server does.
///
/// The review finding on [#235](https://github.com/glslang/windbg-mcp/pull/235), and the one
/// failure in this area that was not an error. `record_trace` probes whether `target` names an
/// existing file before deciding it is a program rather than a command line, and that probe used
/// this process's working directory while `TTD.exe` is given the caller's. With `working_dir`
/// holding `a program.exe` the probe declined, the target was split on its space, and TTD recorded
/// **`a.exe`** — a different program — into a trace reported as a complete recording.
///
/// The fixture is a copy of a real system binary rather than a stub, because the claim is about
/// which program was *recorded*, and TTD has to be able to launch it.
#[test]
fn ttd_resolves_a_relative_target_against_the_recorders_working_directory() {
    if !ttd_tier() {
        return;
    }
    let work_dir = recording_dir("relative-work");
    let out_dir = recording_dir("relative-out");
    let fixture = work_dir.join("a program.exe");
    let system = std::path::PathBuf::from(std::env::var("SystemRoot").unwrap_or_default())
        .join("System32")
        .join("hostname.exe");
    if std::fs::copy(&system, &fixture).is_err() {
        skip(&format!(
            "could not copy {} to build the spaced-name fixture",
            system.display()
        ));
        return;
    }

    let mut server = Server::started();
    // Path-qualified, because TTD does not search its own cwd for a *bare* relative name —
    // measured on 1.01.11, where `-launch aprogram.exe` fails and `-launch ./aprogram.exe`
    // records. So this is the form that has to work, and the form that recorded the wrong program.
    let Some(text) = recorded(
        &mut server,
        &out_dir,
        json!({
            "target": ".\\a program.exe",
            "working_dir": work_dir.to_string_lossy(),
        }),
    ) else {
        return;
    };
    assert!(text.contains("recording complete"), "{text}");

    let name = trace_name(&recorded_trace(&out_dir));
    assert!(
        name.starts_with("a program"),
        "`{name}` is not a recording of `a program.exe` — the target resolved to some other \
         program and the recording succeeded anyway, which is the shape of the defect"
    );

    let _ = std::fs::remove_dir_all(&work_dir);
    let _ = std::fs::remove_dir_all(&out_dir);
}

/// Issue #231: a TTD query answers with **records**, not with a column of bare indices.
///
/// `dx` renders one level unless asked for more, and these queries return containers of records,
/// so the tools answered with the right number of rows and nothing in any of them. There is no
/// error in that — three blank rows read as "three calls, details unavailable" — which is why it
/// survived from the initial commit in two of the three query tools.
///
/// Driven through `ttd_memory` and `ttd_events`, the two that need **no symbols**: the fields are
/// then a property of the query rather than of what this host can resolve, so the tier does not
/// stand down on a machine with no symbol server. `ttd_events` is not redundant beside it — it is
/// the one of the three that always carried the depth, which makes the pair diagnostic. Measured
/// by putting each defect back: setting the shared `TTD_QUERY_DEPTH` to `-r1` blanks **both**, and
/// this assertion is the one that fires; `ttd_memory` alone going blank is instead the original
/// #231 shape, one query written differently from its siblings and off the constant they share.
#[test]
fn ttd_queries_answer_with_the_fields_they_promise() {
    if !ttd_tier() {
        return;
    }
    let out_dir = recording_dir("replay");
    let mut server = Server::started();
    if recorded(&mut server, &out_dir, json!({ "target": "hostname.exe" })).is_none() {
        return;
    }
    let trace = recorded_trace(&out_dir);

    let response = server.call_tool(
        "open_trace",
        json!({ "path": trace.to_string_lossy() }),
        TARGET_STEP,
    );
    assert_no_error(&response, "tools/call open_trace");
    if is_tool_error(&response) {
        let text = text_of(&response["result"]);
        // Stand down for the **one** reason that is the host's: no replay engine beside the
        // binary. Any other `open_trace` failure — a regression, a trace that will not load — has
        // to fail, or this test passes having exercised neither query, which is the shape
        // [`recorded`] exists to avoid one function above.
        //
        // Keyed on the server's own diagnostic, not on `0x80070057`. That code is the engine's
        // "the parameter is incorrect" and a trace that failed to load for some other reason can
        // carry it too; the sentence below is appended by `worker::explain_trace_failure` only
        // when `replay_engine_bundled()` is false, which is exactly the condition being excused.
        // A `ttd\` of the wrong architecture is deliberately *not* excused — it gets the engine's
        // error with no such sentence, and a misconfigured bundle should be loud.
        if text.to_ascii_lowercase().contains("cannot replay") {
            skip(&format!(
                "this host recorded a trace it cannot replay: {text}"
            ));
            let _ = std::fs::remove_dir_all(&out_dir);
            return;
        }
        panic!("`open_trace` failed for a reason that is not the host's:\n{text}");
    }
    let session = maybe_session_id(&response["result"])
        .unwrap_or_else(|| panic!("`open_trace` opened without minting a handle: {response}"));

    // Events first. Module loads are in every trace, and this is the query that always rendered
    // its fields, so a failure here is about the trace rather than about the depth.
    let events = server.tool_text("ttd_events", json!({ "session_id": session }), TARGET_STEP);
    assert!(
        events.contains("ModuleLoaded") && events.contains("Position"),
        "`ttd_events` should render each event's own fields:\n{events}"
    );

    // And then the one the issue was about. An image base is read every time it is mapped — the
    // `MZ` of the PE header — so it is an address certain to have been accessed, and naming it
    // needs no symbol.
    let modules = server.tool_data(
        "modules",
        json!({ "session_id": session, "limit": 2000 }),
        TARGET_STEP,
    );
    let base = modules["modules"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|m| address_of(&m["start"]))
        .find(|&start| start != 0)
        .unwrap_or_else(|| panic!("the trace should have a module with a base: {modules}"));

    let memory = server.tool_text(
        "ttd_memory",
        json!({ "session_id": session, "address": format!("0x{base:x}"), "size": 8 }),
        TARGET_STEP,
    );
    assert!(
        memory.contains("AccessType") && memory.contains("Value"),
        "`ttd_memory` should render each access as a record — the defect was a column of bare \
         indices with the right count and no payload:\n{memory}"
    );

    server.tool_text("end_session", json!({ "session_id": session }), TARGET_STEP);
    let _ = std::fs::remove_dir_all(&out_dir);
}

// ---- tier 6: a 32-bit managed target, served by a worker of its architecture ---

/// The fixture these two tests build for themselves, in the one language every stock Windows can
/// compile with nothing installed.
///
/// It does two things and nothing else. `dump <path>` writes a **full-memory** minidump of itself
/// and exits, which is the 32-bit managed dump this tier used to have to be handed; `wait` prints
/// a line and blocks, which is the 32-bit managed *process* the other test attaches to.
///
/// **It dumps itself rather than being dumped**, which is what makes the capture 32-bit with no
/// debugger package on the host: `MiniDumpWriteDump` is in the `dbghelp.dll` this process loads,
/// and a 32-bit process loads the 32-bit one. A 64-bit writer pointed at the same target produces
/// a dump that reports itself as the *host's* architecture — which is why a 32-bit `procdump` was
/// the instruction before this existed, and why `cdb -p` was the fallback once
/// `comsvcs.dll MiniDump` had been measured writing a near-empty file and reporting nothing
/// wrong. Whatever writes it, the **size** is the check: [`made_x86_dump`] asserts it, because
/// "the file is there" is exactly what that failure looked like.
const X86_FIXTURE: &str = r#"
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

static class Fixture
{
    [DllImport("dbghelp.dll", SetLastError = true)]
    static extern bool MiniDumpWriteDump(IntPtr hProcess, uint pid, IntPtr hFile,
                                         int dumpType, IntPtr ex, IntPtr user, IntPtr cb);

    static int Main(string[] args)
    {
        if (args.Length == 2 && args[0] == "dump")
        {
            using (var file = new FileStream(args[1], FileMode.Create, FileAccess.ReadWrite))
            {
                var self = Process.GetCurrentProcess();
                const int WithFullMemory = 0x2, WithHandleData = 0x4,
                          WithFullMemoryInfo = 0x800, WithThreadInfo = 0x1000;
                bool ok = MiniDumpWriteDump(self.Handle, (uint)self.Id,
                                            file.SafeFileHandle.DangerousGetHandle(),
                                            WithFullMemory | WithHandleData
                                                | WithFullMemoryInfo | WithThreadInfo,
                                            IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
                if (!ok)
                {
                    Console.Error.WriteLine("MiniDumpWriteDump failed: "
                                            + Marshal.GetLastWin32Error());
                    return 1;
                }
            }
            return 0;
        }
        if (args.Length == 1 && args[0] == "wait")
        {
            Console.WriteLine("ready");
            Console.Out.Flush();
            Console.In.ReadLine();
            return 0;
        }
        Console.Error.WriteLine("usage: fixture dump <path> | fixture wait");
        return 2;
    }
}
"#;

/// The **32-bit** `csc.exe`, which is an OS component rather than something to install.
///
/// `Framework`, not `Framework64`: the two are the same compiler built for different
/// architectures, and this tier needs the one whose `-platform:x86` output is a genuine 32-bit
/// process on every host — including an ARM64 one, where x86 runs under emulation like any other
/// x86 program.
///
/// A directory scan rather than a pinned `v4.0.30319`, because that version directory is the
/// CLR's and not the compiler's: pinning it names a path that is right today and becomes a silent
/// skip the day it is not.
fn csc_x86() -> Option<std::path::PathBuf> {
    let framework = std::path::PathBuf::from(std::env::var_os("WINDIR")?)
        .join("Microsoft.NET")
        .join("Framework");
    let mut candidates: Vec<std::path::PathBuf> = std::fs::read_dir(framework)
        .ok()?
        .flatten()
        .map(|entry| entry.path().join("csc.exe"))
        .filter(|csc| csc.is_file())
        .collect();
    candidates.sort();
    candidates.pop()
}

/// This tier's scratch directory, per process.
fn x86_fixture_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("windbg-mcp-smoke-x86-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create the 32-bit fixture directory");
    dir
}

/// The compiled fixture, built once for however many of this tier's tests run.
///
/// `OnceLock` rather than a build per test: two tests want the same 4 KB program, and compiling it
/// twice in parallel into one path is a race with a file lock in it.
fn x86_fixture() -> Option<&'static std::path::Path> {
    static FIXTURE: std::sync::OnceLock<Option<std::path::PathBuf>> = std::sync::OnceLock::new();
    FIXTURE
        .get_or_init(|| {
            let csc = csc_x86()?;
            let dir = x86_fixture_dir();
            let source = dir.join("fixture.cs");
            std::fs::write(&source, X86_FIXTURE).expect("write the fixture source");
            let exe = dir.join("fixture.exe");
            let built = Command::new(&csc)
                .arg("-nologo")
                // The whole point of the fixture: `csc` here is 32-bit, but its default `anycpu`
                // output would still run 64-bit on a 64-bit host and this tier would then be
                // measuring nothing at all.
                .arg("-platform:x86")
                .arg(format!("-out:{}", exe.display()))
                .arg(&source)
                .output()
                .expect("run the C# compiler");
            assert!(
                built.status.success() && exe.is_file(),
                "the 32-bit C# fixture did not compile:\n{}\n{}",
                String::from_utf8_lossy(&built.stdout),
                String::from_utf8_lossy(&built.stderr)
            );
            Some(exe)
        })
        .as_deref()
}

/// The gate for this tier: **a 32-bit engine beside the server under test**.
///
/// Deliberately the engine and not the worker, and that split is the whole design. A host with no
/// 32-bit `dbgeng.dll` in its `x86` directory has no 32-bit debugger at all and cannot answer the
/// question this tier asks, so it stands down. A host that has one but no 32-bit
/// `windbg-mcp.exe` beside it is a *half-populated* directory — the failure `setup.md` warns
/// fails quietly, because the target still opens and only the one thing you came for is missing —
/// so that case is left to fail on the `limitation` assertion, loudly, rather than skipped.
///
/// It also keeps this from being a second copy of `engine::x86_worker_image`'s rule, which is the
/// real hazard in gating on the worker: that rule has a fallback in it for a renamed running
/// image, and a gate that reimplemented it would drift out of step with the code it is checking.
fn x86_engine_tier() -> bool {
    let beside = std::path::Path::new(EXE)
        .parent()
        .map(|dir| dir.join("x86").join("dbgeng.dll"));
    if beside.as_deref().is_some_and(std::path::Path::is_file) {
        return true;
    }
    skip(
        "no 32-bit engine in an `x86` directory beside the server under test, so nothing here \
         can open a 32-bit target — `skills/windbg-debugging/setup.md` has the copy block",
    );
    false
}

/// A 32-bit managed dump: the one this tier makes for itself, or one the caller supplied.
///
/// **Made rather than supplied is the default**, which is what lets this tier run unattended —
/// the reason it covered nothing for as long as it needed a file no repository can carry. Being
/// handed one is still honoured, because a real capture off a real application is a better target
/// than a fixture and there is no reason to refuse it.
fn made_x86_dump() -> Option<X86Dump> {
    if let Some(supplied) = std::env::var_os("WINDBG_MCP_X86_DUMP") {
        let supplied = supplied.to_string_lossy().into_owned();
        assert!(
            std::path::Path::new(&supplied).is_file(),
            "WINDBG_MCP_X86_DUMP points at nothing: {supplied}"
        );
        return Some(X86Dump {
            path: supplied,
            ours: false,
        });
    }
    let fixture = x86_fixture()?;
    let dump = x86_fixture_dir().join("managed-x86.dmp");
    let _ = std::fs::remove_file(&dump);
    let wrote = Command::new(fixture)
        .arg("dump")
        .arg(&dump)
        .output()
        .expect("run the 32-bit fixture");
    assert!(
        wrote.status.success(),
        "the fixture could not dump itself:\n{}",
        String::from_utf8_lossy(&wrote.stderr)
    );
    // **The size, not the existence.** A writer that produces a near-empty file and reports
    // nothing wrong is a measured failure mode here, and it passes every check that only asks
    // whether the dump is there. A full-memory capture of even a trivial managed process is tens
    // of megabytes; this floor is far below that and far above anything a failed write leaves.
    let size = std::fs::metadata(&dump).expect("stat the dump").len();
    assert!(
        size > 4 * 1024 * 1024,
        "{} is {size} bytes, which is not a full-memory capture",
        dump.display()
    );
    Some(X86Dump {
        path: dump.to_string_lossy().into_owned(),
        ours: true,
    })
}

/// A 32-bit dump for the tier, and **whether this tier is allowed to delete it**.
///
/// The flag is the whole reason this is a struct rather than a `String`. The made dump is tens of
/// megabytes and worth clearing; a dump the caller supplied through `WINDBG_MCP_X86_DUMP` is
/// theirs, may be the only copy of a capture off a real incident, and must survive the run. Those
/// two paths are indistinguishable once they are both a `String`, which is exactly how a test
/// cleaning up after itself comes to delete somebody's evidence.
struct X86Dump {
    path: String,
    /// True only for the dump [`made_x86_dump`] wrote into [`x86_fixture_dir`].
    ours: bool,
}

/// The session an opener minted, plus the assertion that it went to a worker of the target's own
/// architecture.
///
/// `summary.limitation`, not `limitation`: the opener's payload is an `OpenedSession` and the
/// field lives on the `TargetSummary` inside it. Indexing the top level produced JSON null
/// whatever the session actually reported, so this assertion passed unconditionally — it claimed
/// to prove the routing had worked and proved nothing.
fn session_on_a_worker_of_its_own_architecture(data: &Value) -> String {
    let limitation = &data["summary"]["limitation"];
    assert!(
        limitation.is_null(),
        "this host could not give the target a 32-bit worker, so SOS is unreachable — an `x86` \
         directory holding an engine but no 32-bit `windbg-mcp.exe` is the usual cause: \
         {limitation}"
    );
    data["session_id"]
        .as_str()
        .expect("an opener mints a handle")
        .to_string()
}

/// Loads SOS and asks it about managed threads, which is the one thing a wrong-architecture
/// engine cannot do — and so the only assertion that settles where this session's engine lives.
///
/// `.loadby`, not `.load` with a path. SOS reads CLR-internal structures and has to be the build
/// that shipped with the runtime in the *target*, so this takes it from wherever the loaded
/// runtime came from — version-matched by construction. A hardcoded 4.x `sos.dll` path would pin
/// one .NET Framework servicing level, and would name a directory a 2.0/3.5 target (which loads
/// `mscorwks.dll`) does not have at all.
///
/// It also resolves on the **host's** filesystem, which is the same machine — the point being
/// that it is the 32-bit build, which is exactly the file this server's own process cannot load.
///
/// **Both runtime module names**, because this tier accepts any .NET Framework target: 4.x loads
/// `clr.dll` and 2.0/3.5 loads `mscorwks.dll`. Whichever does not match fails harmlessly — there
/// is no such module to load beside — so running both costs one command and avoids narrowing a
/// fixture nothing else here narrows. Which of them worked is settled by SOS answering, not by
/// either of these.
fn sos_answers_about_managed_threads(server: &mut Server, session: &str) {
    let mut loaded = String::new();
    for runtime in ["clr", "mscorwks"] {
        let reply = server.call_tool(
            "execute",
            json!({ "session_id": session, "command": format!(".loadby sos {runtime}") }),
            TARGET_STEP,
        );
        assert_no_error(&reply, "execute .loadby sos");
        loaded.push_str(&text_of(&reply["result"]));
    }
    assert!(
        !loaded.contains("0n193") && !loaded.contains("not a valid Win32 application"),
        "the 32-bit SOS was refused, so this session's engine is not 32-bit:\n{loaded}"
    );

    // **Module-qualified, and it has to be.** An open loads `ext.dll`, which exports a `!threads`
    // of its own — the native thread table — and a bare `!threads` resolves to that one, so it
    // answers on any engine and would prove nothing about SOS. Same reason the crash-dump path
    // prefers `!ext.analyze -v` over `!analyze`.
    let threads = server.call_tool(
        "execute",
        json!({ "session_id": session, "command": "!sos.threads" }),
        TARGET_STEP,
    );
    assert_no_error(&threads, "execute !sos.threads");
    let threads = text_of(&threads["result"]);
    assert!(
        threads.contains("ThreadCount"),
        "SOS loaded but did not answer about managed threads:\n{threads}"
    );
}

/// A 32-bit managed **dump** is served by an engine that can load its SOS.
///
/// This is the whole of [#234](https://github.com/glslang/windbg-mcp/issues/234) end to end, and
/// it is the one claim no other tier makes: an extension is loaded into the debugger's own
/// process, so a 32-bit `sos.dll` is unreachable from this server's own x64 engine and the 64-bit
/// one refuses a 32-bit CLR. Getting `!threads` to answer therefore proves the engine is in a
/// 32-bit *process*.
///
/// Asserts through the **tool surface** rather than against `engine::worker_images` directly,
/// because the unit tests beside it already cover which image is chosen. What this adds is that
/// the routing happens at all: that opening a dump by path lands on the 32-bit worker without the
/// caller asking, and that everything the session then does crosses no boundary the caller can
/// see.
#[test]
fn a_32_bit_managed_dump_is_served_by_an_engine_that_can_load_its_sos() {
    if !x86_engine_tier() {
        return;
    }
    let Some(dump) = made_x86_dump() else {
        skip("this host has no 32-bit C# compiler, so this tier cannot make itself a dump");
        return;
    };
    let mut server = Server::started();

    let data = server.tool_data("open_dump", json!({ "path": &dump.path }), TARGET_STEP);
    let session = session_on_a_worker_of_its_own_architecture(&data);
    sos_answers_about_managed_threads(&mut server, &session);
    server.call_tool(
        "end_session",
        json!({ "session_id": &session }),
        TARGET_STEP,
    );
    // Tens of megabytes, and the only part of this tier's scratch worth clearing — the compiled
    // fixture is 4 KB and is shared with the test below, which may still be running.
    //
    // **Only the dump this tier made.** A supplied `WINDBG_MCP_X86_DUMP` may be the one copy of a
    // capture off a real incident, and deleting it is not a tidy-up this test gets to do.
    if dump.ours {
        let _ = std::fs::remove_file(&dump.path);
    }
    ran("the 32-bit managed dump tier");
}

/// A 32-bit managed **live process** is too — and it is routed on a different fact.
///
/// A dump says what it is in its own header; an attach has no header to read, which is why this
/// route was still unbuilt when the dump one landed. The architecture of a live process is
/// `IsWow64Process2`, asked in the supervisor before the spawn (`target::process_arch`), and its
/// answer feeds exactly the same image choice.
///
/// The fixture is the same program as the dump test's, running rather than captured, which is
/// deliberate: the two tests then differ in the *route* and in nothing else, so a failure here
/// while the dump test passes is about the routing rather than about the target.
#[test]
fn a_32_bit_managed_process_is_attached_by_an_engine_that_can_load_its_sos() {
    if !x86_engine_tier() {
        return;
    }
    let Some(fixture) = x86_fixture() else {
        skip("this host has no 32-bit C# compiler, so this tier cannot make itself a target");
        return;
    };
    let mut child = Command::new(fixture)
        .arg("wait")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("start the 32-bit fixture");
    // Waited for rather than slept past: the process has to be *running managed code* before the
    // attach, or the CLR may not be loaded yet and SOS would have nothing to answer about — for a
    // reason that has nothing to do with which architecture the engine is.
    let mut ready = String::new();
    BufReader::new(child.stdout.take().expect("the fixture's stdout"))
        .read_line(&mut ready)
        .expect("the fixture says when it is up");
    assert_eq!(ready.trim(), "ready", "the fixture did not start");

    let mut server = Server::started();
    let data = server.tool_data("attach_process", json!({ "pid": child.id() }), TARGET_STEP);
    let session = session_on_a_worker_of_its_own_architecture(&data);
    sos_answers_about_managed_threads(&mut server, &session);

    // **`end_session` detaches, so the `kill` below is what actually ends the fixture.** It used
    // to be the other way round — a passive end and then a terminated worker, which the kernel
    // answered by killing the debuggee — and this is where that was found (`FOLLOWUPS.md` item
    // 51). Asserted here as well as in the tier that is about it, cheaply, because the 32-bit
    // worker is a *second image* being terminated and nothing else in this file would notice if
    // that one alone went back to taking its target with it.
    server.call_tool(
        "end_session",
        json!({ "session_id": &session }),
        TARGET_STEP,
    );
    assert!(
        still_running(&child),
        "`end_session` on the 32-bit worker killed the process it had attached to"
    );
    let _ = child.kill();
    let _ = child.wait();
    ran("the 32-bit managed attach tier");
}
