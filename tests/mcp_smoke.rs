//! End-to-end smoke test: drives the **real binary** over stdio with hand-written JSON-RPC.
//!
//! The unit tests in `src/server.rs` check the tool surface in-process, through the SDK's
//! Rust API. That is the wrong altitude for the two events this file exists for:
//!
//! * **A dependency moved** (`rmcp`, `win-kexp`, `schemars`, `tokio`). The in-process tests
//!   still compile and pass while the bytes on the wire change underneath them — a schema
//!   dialect switch, a crate that starts writing to stdout and corrupts the transport, a
//!   shutdown path that leaves the process alive.
//! * **The MCP spec revved.** New revision, new required field, a capability the SDK now
//!   advertises on our behalf that this server does not actually implement.
//!
//! Five tiers, so the cheap one can ride `cargo test` everywhere:
//!
//! * **Protocol** (default) — spawns the server, speaks JSON-RPC. No debugger target, no
//!   symbols, no network.
//! * **Target** (`WINDBG_MCP_SMOKE_DUMP=1`) — opens the sample crash dump through DbgEng, so
//!   it needs `dbgeng.dll` and may reach a symbol server. Off by default; this is the tier
//!   that catches a `win-kexp` regression. It also runs a `debug_batch` to both outcomes, and
//!   through both teardowns — an `end_session` and a client disconnect landing mid-transaction —
//!   because "the rollback ran inside the worker" is a claim only a real engine can settle.
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

/// Revisions the README promises this server speaks, newest first.
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
        let mut command = Command::new(EXE);
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

fn skip(reason: &str) {
    eprintln!("SKIPPED: {reason}");
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

// ---- tier 1: protocol revisions -----------------------------------------------

/// The README names the revisions this server speaks. When the spec revs, this is the list to
/// extend — and the test that says whether the SDK bump actually delivered it.
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
        assert_eq!(
            result["serverInfo"]["version"],
            env!("CARGO_PKG_VERSION"),
            "the reported version must track this crate, not the SDK (on {revision})"
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
    let rendered = format!("{}\n", serde_json::to_string_pretty(&actual).unwrap());

    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::create_dir_all(std::path::Path::new(GOLDEN).parent().unwrap())
            .expect("create golden dir");
        std::fs::write(GOLDEN, &rendered).expect("write golden");
        eprintln!("re-recorded {GOLDEN}");
        return;
    }

    let expected = std::fs::read_to_string(GOLDEN).unwrap_or_else(|e| {
        panic!("cannot read {GOLDEN}: {e}\nrecord it with `UPDATE_GOLDEN=1 cargo test --test mcp_smoke`")
    });
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
        "the tools/list wire surface changed:\n{diff}\n\
         If this is intended, re-record with `UPDATE_GOLDEN=1 cargo test --test mcp_smoke` \
         and review the diff."
    );
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
        // Answered from this server's own bookkeeping, so it succeeds with nothing open.
        ("session_status", json!({}), "ok"),
        // Everything else needs a session, and there is none.
        ("end_session", json!({}), "error"),
        ("registers", json!({}), "error"),
        ("modules", json!({}), "error"),
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

/// The end-to-end debugger path, which is what a `win-kexp` or DbgEng change actually moves:
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
    let modules = server.tool_data("modules", json!({ "session_id": session_id }), TARGET_STEP);
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

    let response = server.call_tool(
        "backtrace",
        json!({ "session_id": session_id }),
        TARGET_STEP,
    );
    assert_no_error(&response, "backtrace");
    assert!(
        !is_tool_error(&response) && !text_of(&response["result"]).trim().is_empty(),
        "`backtrace` failed against the sample dump:\n{}",
        text_of(&response["result"])
    );

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
    let modules = server.tool_data("modules", json!({ "session_id": session_id }), TARGET_STEP);
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
    let every_unloaded = all["unloaded"]
        .as_array()
        .expect("the unloaded tail is a list, empty or not")
        .len();
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
        text.contains(&format!("{} of {loaded}", matched.len())),
        "the text says how much of the table this is:\n{text}"
    );

    // `*` is the same listing as no filter at all — the wildcard path and the plain path agree.
    let everything = server.tool_data(
        "modules",
        json!({ "session_id": session_id, "filter": "*" }),
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
        !matched_unloaded.is_empty() && matched_unloaded.len() < every_unloaded,
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
            matched_unloaded.len()
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
    let Some(dump) = target_tier() else { return };
    let mut server = Server::started();
    let session_id = server.open_session("open_dump", json!({ "path": dump }), TARGET_STEP);

    // The two anchors of a kernel dump's module list, used as addresses that certainly *are*
    // readable — the alternative is a literal, and a literal would make this test a fact about
    // one file.
    let modules = server.tool_data("modules", json!({ "session_id": session_id }), TARGET_STEP);
    let base = |want: &str| -> String {
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

/// `crash_triage` against the checked-in bug check, which is a `0x9F DRIVER_POWER_STATE_FAILURE`.
///
/// The claim is the one the tool exists for and the one no unit test can make: the fields come
/// off a real dump through a real engine. `src/triage.rs` proves the assembly over scripted
/// values; this proves that `ReadBugCheckData`, the stack walk, the per-frame module attribution
/// and the `!analyze` fallback all reach that assembly with something in them.
///
/// Deliberately asserts on the *engine-read* half plus the shape of the rest: the sample's
/// parameters and its `nt`-topped stack are facts about the file, while what `!analyze` concludes
/// depends on whether this host has `winext\ext.dll` beside the engine — so the analysis is
/// checked for being coherent, not for having run.
#[test]
fn a_bug_check_is_triaged_into_its_fields() {
    let Some(dump) = target_tier() else { return };
    let mut server = Server::started();

    let response = server.call_tool("open_dump", json!({ "path": dump }), TARGET_STEP);
    assert_no_error(&response, "open_dump");
    let session_id = session_id_of(&response["result"]);

    let triage = server.tool_data(
        "crash_triage",
        json!({ "session_id": session_id }),
        TARGET_STEP,
    );

    // The bug check itself, read through `ReadBugCheckData` rather than off any text.
    assert_eq!(triage["bug_check"]["code"], "0x9f", "{triage}");
    assert_eq!(
        triage["bug_check"]["name"], "DRIVER_POWER_STATE_FAILURE",
        "the name comes from this build's table, so it does not need `!analyze`: {triage}"
    );
    let parameters = triage["bug_check"]["parameters"]
        .as_array()
        .expect("four parameters");
    assert_eq!(parameters.len(), 4, "{triage}");
    // Arg1 is the 0x9F subtype: 3, "a device object has been blocking an IRP for too long".
    assert_eq!(parameters[0], "0x0000000000000003", "{triage}");
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

    // The sample's crash is entirely inside the kernel's watchdog path, so there is no driver
    // frame to name — and the tool says why rather than blaming `nt!KeBugCheckEx`.
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

    // `PROCESS_NAME`, read out of the current `_EPROCESS`. The sample's watchdog fires on an idle
    // CPU, so the answer is `System` — and the check that matters is that it is *not* the kernel
    // image, which is what the engine's own `GetCurrentProcessExecutableName` answers on a kernel
    // target for every process there has ever been.
    assert_eq!(
        triage["process_name"], "System",
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
                "a complete `!analyze` of a 0x9F explains its parameters: {triage}"
            );
            assert!(
                analysis["failure_bucket_id"]
                    .as_str()
                    .is_some_and(|bucket| bucket.starts_with("0x9F")),
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
        text.contains("BUG CHECK: 0x9f DRIVER_POWER_STATE_FAILURE"),
        "{text}"
    );
    assert!(text.contains("STACK ("), "{text}");

    // **The session is where it was left, which is what `read_only_hint = true` claims.** The
    // `!analyze -v` a triage runs resets the debugger's selected scope to the target's default —
    // measured on four targets (glslang/win-kexp#98) — so a caller who had chosen a frame would
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
/// `0x9F` sample structurally cannot cover.
///
/// [`DRIVER_CRASH_DUMP`] is a `0x13A KERNEL_MODE_HEAP_CORRUPTION` raised out of
/// `nt!ExFreePoolWithTag` by `MessageManager.sys`, a driver with **no PDB**. Everything the issue
/// behind this tool asked for is here and nowhere else in the suite:
///
/// * a `faulting_frame` that exists, six frames below the top, under a stack of kernel allocator
///   internals that would otherwise be blamed;
/// * that frame named `module+RVA` off the load base, because there is no symbol to name it with —
///   and `!analyze` calling the same crash `Unknown_Module`, which is why the frame is computed
///   here rather than taken from it;
/// * a `pool_tag`, which only `!analyze` can produce;
/// * a process name longer than 15 characters, which is what caught `_EPROCESS::ImageFileName`
///   silently truncating `mm_exploit_v5.exe` to `mm_exploit_v5.`.
///
/// The RVA is asserted as a literal. That is the point rather than brittleness: `0x1654` is a
/// fixed offset into a fixed image, so it is reproducible across every reboot and load base — five
/// dumps from the same loop reported it at five different addresses — and a change in it means the
/// attribution arithmetic moved.
#[test]
fn a_driver_crash_names_the_driver_frame_that_analyze_cannot() {
    if target_tier().is_none() {
        return;
    }
    if !std::path::Path::new(DRIVER_CRASH_DUMP).exists() {
        skip(&format!(
            "driver crash dump not found at {DRIVER_CRASH_DUMP}"
        ));
        return;
    }
    let mut server = Server::started();
    let opened = server.call_tool(
        "open_dump",
        json!({ "path": DRIVER_CRASH_DUMP }),
        TARGET_STEP,
    );
    assert_no_error(&opened, "open_dump");
    assert!(
        !is_tool_error(&opened),
        "opening the driver crash dump failed:\n{}",
        text_of(&opened["result"])
    );
    let session_id = session_id_of(&opened["result"]);

    let triage = server.tool_data(
        "crash_triage",
        json!({ "session_id": session_id }),
        TARGET_STEP,
    );

    assert_eq!(triage["bug_check"]["code"], "0x13a", "{triage}");
    assert_eq!(
        triage["bug_check"]["name"], "KERNEL_MODE_HEAP_CORRUPTION",
        "{triage}"
    );

    // The headline: a driver frame, found past the kernel's allocator frames.
    let faulting = &triage["faulting_frame"];
    assert!(
        !faulting.is_null(),
        "this crash has a driver frame — finding it is what the tool is for: {triage}"
    );
    assert_eq!(faulting["module"], "MessageManager", "{triage}");
    assert_eq!(
        faulting["rva"], "0x1654",
        "the RVA is a fixed offset into a fixed image, so it is the same in every dump this bug \
         produces however the driver was loaded: {triage}"
    );
    assert!(
        faulting["index"].as_u64().is_some_and(|index| index > 0),
        "the driver is never frame 0 — `nt!KeBugCheckEx` is: {triage}"
    );
    // No PDB, so no symbol. Reported as absent rather than filled in with the module's own name,
    // which is what the engine offers and which would read as "this frame resolved".
    assert!(faulting["symbol"].is_null(), "{triage}");
    assert!(faulting["displacement"].is_null(), "{triage}");
    assert_eq!(
        triage["frames_truncated"], false,
        "this stack is well inside the default cap: {triage}"
    );

    // The frames above it are the allocator path, symbolised from `nt`'s own PDB — so the same
    // walk carries both kinds of frame, which is the mix a real driver crash always has.
    let frames = triage["frames"].as_array().expect("frames");
    assert!(
        frames.iter().any(|frame| frame["symbol"]
            .as_str()
            .is_some_and(|s| s.starts_with("nt!ExFreePoolWithTag"))),
        "the free that raised the bug check should be on the stack: {triage}"
    );

    // A name longer than `_EPROCESS::ImageFileName` can hold, which is the whole point of reading
    // the audit name instead.
    let process = triage["process_name"]
        .as_str()
        .unwrap_or_else(|| panic!("the crashing process should be named: {triage}"));
    assert!(
        process.len() > 15 && process.ends_with(".exe"),
        "the full image name, not the 15-byte field's truncation of it: {triage}"
    );

    let analysis = &triage["analysis"];
    if analysis["ran"] == true {
        // `!analyze` cannot name this driver — it has no PDB — which is precisely why the frame
        // above is computed from the load base instead of taken from here.
        assert_ne!(
            analysis["module_name"], "MessageManager",
            "if `!analyze` learns to attribute a PDB-less driver, this test's premise is stale \
             and the docs claiming otherwise need revisiting: {triage}"
        );
        // Only where the analysis got that far: a truncated run may have been cut off before
        // `PROCESS_NAME`, and demanding a field the tool says may be missing would fail the tier
        // for the one behaviour it exists to allow. Same guard as the other dump's check.
        if analysis["truncated"] == false || !analysis["process_name"].is_null() {
            assert_eq!(
                analysis["process_name"], triage["process_name"],
                "the audit name and `!analyze`'s PROCESS_NAME are the same process: {triage}"
            );
        }
        if analysis["truncated"] == false {
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
    assert!(
        text.contains("FAULTING FRAME: MessageManager+0x1654"),
        "{text}"
    );
    assert!(!text.contains("[MessageManager+0x1654]"), "{text}");

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
    let Some(dump) = target_tier() else { return };
    let mut server = Server::started();

    let response = server.call_tool("open_dump", json!({ "path": dump }), TARGET_STEP);
    assert_no_error(&response, "open_dump");
    let session_id = session_id_of(&response["result"]);

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
    let ended = server.tool_text(
        "end_session",
        json!({ "session_id": session_id }),
        TARGET_STEP,
    );
    let took = asked.elapsed();
    assert!(!ended.trim().is_empty(), "end_session said nothing");
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
/// complaint at the small end. And it bought nothing for it, since win-kexp caches complete
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
/// This is the only place the whole mechanism exists. win-kexp proves `SetInterrupt` reaches a
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
// win-kexp proves the primitive (`execute_command_bounded` aborts a runaway command, and the next
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

/// The queue-aware half of the budget, which is the part that has no equivalent in win-kexp: a
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
/// the coverage split in `DECISIONS.md` (2026-08-02), kept as a test so a win-kexp change to the
/// watchdog can be re-measured rather than re-argued.
///
/// The cost is not a constant overhead but a **quantization**: win-kexp's watchdog thread checks
/// its `done` flag, then sleeps 200ms, so a command takes `ceil(d / 200ms) * 200ms`. The tax on a
/// point query is best read as: anything that takes 1–200ms now takes 200ms.
///
/// Prints rather than asserts. The cost belongs to win-kexp's watchdog, not to this crate, and a
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
///   leaves a detached-but-halted kernel frozen, so win-kexp resumes and *actively* detaches. A
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
    let mut server = Server::started();

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
        let registers =
            server.tool_text("registers", json!({ "session_id": session }), TARGET_STEP);
        assert!(
            registers.contains("rip="),
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
            after_refusal.contains("rip="),
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
/// win-kexp's `DEFAULT_WALK_BUDGET` is 120s and this server currently takes that default (#75),
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
/// Comfortably above win-kexp's 120s walk budget, so a walk that behaves is never cut off, and
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
/// Three outcomes, not two, and collapsing the last two is a real bug: "the census listed
/// nothing" is a claim about the *pool* and worth asserting on, while "the heaviest tag does not
/// render unambiguously" is a fact about **rendering** that says nothing about the walk. Treating
/// the second as the first fails a perfectly healthy run whose busiest tag happens to be binary.
enum HeaviestTag {
    /// A tag that can be handed straight back to `pool_find_tag`.
    Queryable(String),
    /// A tag is listed, but this test cannot reconstruct the bytes behind it. `display_tag`
    /// maps every unprintable byte to `.` — and a literal `.` to the same thing — so a rendering
    /// containing one could have come from either.
    Ambiguous,
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
    let tag = first["tag"].as_str().unwrap_or_default().to_string();
    if tag.chars().count() != 4 || tag.contains('.') {
        // Still a rendering, and still ambiguous: the *tag* is four raw bytes, and every
        // unprintable one — like a literal `.` — comes back as `.`.
        return HeaviestTag::Ambiguous;
    }
    HeaviestTag::Queryable(tag)
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
/// This is the tier the budget in glslang/win-kexp#88 was written for, and the only one that can
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
        // (glslang/win-kexp#103, #104) are settled by comparing them across runs. A threshold
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
            // and the interesting one is crowded out. glslang/win-kexp#104 turns on which of two
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
                    .find(|t| t["tag"] == tag.as_str())
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
            // Not a failure, and not evidence about the walk: plenty of drivers use tag bytes
            // that do not render, and the busiest allocator on this target may be one of them.
            HeaviestTag::Ambiguous => eprintln!(
                "NOTE: the heaviest tag does not render unambiguously, so the census/find_tag \
                 cross-check was skipped"
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

    with_live_kernel_session(&mut server, &connection, |server, session| {
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

        let symbols = load_kernel_symbols(&mut server, &session);
        assert!(
            symbols.loaded.contains("pdb symbols") && !symbols.probe.is_empty(),
            "the CTF pool check needs full `nt` symbols and the pool-root global. If a known-good \
             path exists, set {SYMBOLS_ENV}. Engine setup said: {engine}\n{}",
            symbols.transcript
        );

        // A fresh kernel attach may initially expose only `nt`; the unqualified reload above
        // populates DbgEng's full module inventory as well as loading the pool types.
        // Matched against module *names*, not against a substring of the whole `lm` listing:
        // "messagemanager appears somewhere in that text" was true of a symbol path echoed into
        // the same output, which is the kind of accidental pass a field cannot give.
        let modules = server.tool_data("modules", json!({ "session_id": session }), TARGET_STEP);
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
            "the fixture reported ready, but KD does not list MessageManager.sys after the full \
             module reload:\n{}\n\nsymbol setup said:{}",
            text_of(
                &server.call_tool("modules", json!({ "session_id": session }), TARGET_STEP)["result"]
            ),
            symbols.transcript
        );

        let started = Instant::now();
        let call = server.call_tool(
            "pool_find_tag",
            json!({
                "tag": "Tgsm",
                "paged": false,
                "refresh": true,
                "limit": 32,
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
        assert!(
            matches["matches"].as_u64().unwrap_or_default() > 0,
            "the target fixture retained `Tgsm` messages, but the MCP pool snapshot did not find \
             them. Read the walk's coverage before treating an incomplete walk as an allocator \
             result: {matches}"
        );
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
