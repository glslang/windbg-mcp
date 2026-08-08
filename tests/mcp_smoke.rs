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
//! Three tiers, so the cheap one can ride `cargo test` everywhere:
//!
//! * **Protocol** (default) — spawns the server, speaks JSON-RPC. No debugger target, no
//!   symbols, no network.
//! * **Target** (`WINDBG_MCP_SMOKE_DUMP=1`) — opens the sample crash dump through DbgEng, so
//!   it needs `dbgeng.dll` and may reach a symbol server. Off by default; this is the tier
//!   that catches a `win-kexp` regression.
//! * **Bounded command** (`#[ignore]`d, run by hand) — deliberately runs away and waits out a
//!   watchdog, so it is measured in minutes rather than seconds. It lives here rather than
//!   beside the budget arithmetic in `src/engine.rs` because the two halves it proves are now
//!   in *different processes* — the budget is computed by the supervisor and armed by the
//!   worker — so the only place the wiring exists as a whole is the shipped binary.
//! * **Live kernel** (`#[ignore]`d **and** `WINDBG_MCP_SMOKE_KERNEL=<connection string>`) — a
//!   real KDNET target. The only tier that touches another machine, and the only one that can
//!   prove a kernel attach still *lands* and lets go cleanly rather than merely parks, or that a
//!   pool walk stays inside its budget when every page it reads crosses a wire. Run it last, on
//!   its own.
//!
//! See `docs/smoke-test.md` for the runbook.

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Write};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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

    /// The text a tool call produced, whether it succeeded or reported a tool error.
    fn tool_text(&mut self, name: &str, args: Value, budget: Duration) -> String {
        let response = self.call_tool(name, args, budget);
        assert_no_error(&response, &format!("tools/call {name}"));
        text_of(&response["result"])
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
    if let Some(variants) = node.get("enum").and_then(|e| e.as_array()) {
        let names: Vec<String> = variants.iter().map(|v| v.to_string()).collect();
        return format!("enum[{}]", names.join("|"));
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
        Some(items) if base.starts_with("array") => format!("array<{}>", describe_type(items)),
        _ => base,
    };
    match node.get("format").and_then(|f| f.as_str()) {
        Some(format) => format!("{base}/{format}"),
        None => base,
    }
}

/// The structural contract of one tool: everything a client binds against, minus the prose.
fn digest_tool(tool: &Value) -> Value {
    let schema = &tool["inputSchema"];
    let mut params: Vec<String> = schema["properties"]
        .as_object()
        .map(|props| {
            props
                .iter()
                .map(|(name, node)| format!("{name}: {}", describe_type(node)))
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
    let session_id = session_id_of(&opened);
    assert!(
        session_id.starts_with("sess-"),
        "session handles are minted as `sess-…`, got `{session_id}` in:\n{opened}"
    );

    let status = server.tool_text("session_status", json!({}), TARGET_STEP);
    assert!(
        status.contains(&session_id),
        "session_status should report the open session `{session_id}`, got:\n{status}"
    );

    // Read-only inspection through the engine thread. These are the calls that break when a
    // DbgEng binding changes shape.
    // The checked-in sample is a *kernel* crash dump, so the kernel image and HAL are the
    // anchors — not `ntdll`. Symbols are not needed: the rows come from the dump's own module
    // list, which keeps this tier runnable offline.
    //
    // Matched as whitespace-separated tokens rather than by column position: `lm` lays out its
    // columns from the address width and the longest module name, so a layout shift would
    // otherwise fail here and name the wrong cause.
    let modules = server.tool_text("modules", json!({ "session_id": session_id }), TARGET_STEP);
    let listed: Vec<&str> = modules
        .lines()
        // `start end name [flags]` — the module name is the third token on a row.
        .filter_map(|line| line.split_whitespace().nth(2))
        .collect();
    for expected in ["nt", "hal"] {
        assert!(
            listed.contains(&expected),
            "the module list should include `{expected}`, got:\n{modules}"
        );
    }
    for tool in ["registers", "backtrace"] {
        let response = server.call_tool(tool, json!({ "session_id": session_id }), TARGET_STEP);
        assert_no_error(&response, tool);
        let text = text_of(&response["result"]);
        assert!(
            !is_tool_error(&response) && !text.trim().is_empty(),
            "`{tool}` failed against the sample dump:\n{text}"
        );
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
    // whatever happens to be open — the contract `Sessions::resolve` owns.
    let stale = server.call_tool(
        "modules",
        json!({ "session_id": "sess-not-a-real-handle" }),
        TARGET_STEP,
    );
    assert!(
        is_tool_error(&stale) || !stale["error"].is_null(),
        "a stale session handle must be refused, got {stale}"
    );

    let ended = server.tool_text(
        "end_session",
        json!({ "session_id": session_id }),
        TARGET_STEP,
    );
    assert!(!ended.trim().is_empty(), "end_session said nothing");

    // After the session is gone, the old handle must not be honoured.
    let after = server.call_tool("modules", json!({ "session_id": session_id }), TARGET_STEP);
    assert!(
        is_tool_error(&after) || !after["error"].is_null(),
        "a handle from an ended session must be refused, got {after}"
    );
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
fn maybe_session_id(text: &str) -> Option<String> {
    text.lines()
        .find_map(|line| line.trim().strip_prefix("session_id:"))
        .map(|id| id.trim().to_string())
}

/// [`maybe_session_id`], for a call that must have opened something.
fn session_id_of(text: &str) -> String {
    maybe_session_id(text).unwrap_or_else(|| panic!("expected a session_id in:\n{text}"))
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

/// The `pid` `session_status` reports for a session, from its `[engine pid N, …]` line.
fn engine_pid_of(status: &str, session_id: &str) -> u32 {
    let line = status
        .lines()
        .find(|l| l.contains(session_id) && l.contains("engine pid"))
        .unwrap_or_else(|| panic!("no engine pid reported for `{session_id}` in:\n{status}"));
    let after = line.split("engine pid ").nth(1).expect("checked above");
    after
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .unwrap_or_else(|e| panic!("unreadable engine pid in {line:?}: {e}"))
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

    let first = session_id_of(&server.tool_text("open_dump", json!({ "path": dump }), TARGET_STEP));
    let second =
        session_id_of(&server.tool_text("open_dump", json!({ "path": dump }), TARGET_STEP));
    assert_ne!(first, second, "each open must get its own session");

    // The claim: the first handle still names a live target after the second open landed.
    let response = server.call_tool("modules", json!({ "session_id": first }), TARGET_STEP);
    assert_no_error(&response, "modules on the first session");
    assert!(
        !is_tool_error(&response),
        "the first session must survive a later open:\n{}",
        text_of(&response["result"])
    );

    // Both are listed, and the newest is the one an omitted handle routes to.
    let status = server.tool_text("session_status", json!({}), TARGET_STEP);
    for id in [&first, &second] {
        assert!(
            status.contains(id.as_str()),
            "`{id}` should be listed:\n{status}"
        );
    }
    let current_line = status
        .lines()
        .find(|l| l.contains("(current)"))
        .unwrap_or_else(|| panic!("some session must be current:\n{status}"));
    assert!(
        current_line.contains(&second),
        "the newest session should be current, got:\n{current_line}"
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

    // Wait for it to reach the parked state rather than assuming a timing.
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
        // The attach failed outright instead of parking — most likely the UDP port was already
        // taken on this host. Nothing to assert about a park that did not happen.
        skip("attach_kernel did not reach the parked state (port 50007 busy?)");
        return;
    };
    let kernel_session = status
        .lines()
        .find(|l| l.contains("kernel target"))
        .map(|l| l.split_whitespace().next().unwrap_or_default().to_string())
        .expect("the kernel session should be listed");

    // The point. A parked session used to be the *server's* engine thread; now it is one worker,
    // and everything else carries on.
    let opened = server.call_tool("open_dump", json!({ "path": dump }), TARGET_STEP);
    assert_no_error(&opened, "open_dump while a kernel attach is parked");
    assert!(
        !is_tool_error(&opened),
        "a parked kernel attach must not block another session:\n{}",
        text_of(&opened["result"])
    );
    let dump_session = session_id_of(&text_of(&opened["result"]));

    // …and the parked session reports itself honestly rather than as an ordinary pending open.
    let asked = server.tool_text(
        "session_status",
        json!({ "session_id": kernel_session }),
        STEP,
    );
    assert!(
        asked.contains("Do not re-run the open"),
        "the target exists, so re-attaching would be a second attach:\n{asked}"
    );

    // The recovery that did not exist before: `end_session` cannot be answered by a worker that
    // is parked, so the worker is killed. It has to come back, and the process has to be gone.
    let worker = engine_pid_of(&status, &kernel_session);
    let ended = server.tool_text(
        "end_session",
        json!({ "session_id": kernel_session }),
        Duration::from_secs(120),
    );
    assert!(
        ended.contains("terminated"),
        "a parked session ends by terminating its worker:\n{ended}"
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

/// A worker is a process holding a debug session — and, for a launch or an attach, a debuggee
/// whose fate is tied to its debugger. None may outlive the client connection that opened it, or
/// every disconnect leaks a debugger process.
#[test]
fn engine_workers_do_not_outlive_the_connection() {
    let Some(dump) = target_tier() else { return };
    let mut server = Server::started();
    let session =
        session_id_of(&server.tool_text("open_dump", json!({ "path": dump }), TARGET_STEP));
    let status = server.tool_text("session_status", json!({}), TARGET_STEP);
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
    let session =
        session_id_of(&server.tool_text("open_dump", json!({ "path": dump }), TARGET_STEP));
    let status = server.tool_text("session_status", json!({}), TARGET_STEP);
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
    let session_id =
        session_id_of(&server.tool_text("open_dump", json!({ "path": dump }), TARGET_STEP));
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
    let session =
        session_id_of(&server.tool_text("open_dump", json!({ "path": dump }), TARGET_STEP));

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
    let session =
        session_id_of(&server.tool_text("open_dump", json!({ "path": dump }), TARGET_STEP));

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
    let session =
        session_id_of(&server.tool_text("open_dump", json!({ "path": dump }), TARGET_STEP));

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
    let Some(session) = maybe_session_id(&report) else {
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
        let status = server.tool_text("session_status", json!({ "session_id": session }), STEP);
        assert!(
            status.contains("ready for work"),
            "a landed attach must report as open, not mid-attach:\n{status}"
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
            let dump_session = session_id_of(&text_of(&opened["result"]));
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
    if let Err(panic) = outcome {
        eprintln!("detached after the failure below:\n{ended_text}");
        resume_unwind(panic);
    }

    assert_no_error(&ended, "end_session on a live kernel");
    assert!(
        !ended_text.contains("terminated"),
        "the worker was killed instead of detaching — DbgEng leaves a detached-but-halted kernel \
         frozen, so this would have left the target stopped and its KD stub wedged:\n{ended_text}"
    );
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
    let session = maybe_session_id(&report)
        .unwrap_or_else(|| panic!("the attach left no session behind:\n{report}"));
    assert!(
        !is_tool_error(&attached),
        "the attach claimed its target and then failed; this test needs one that landed:\n{report}"
    );
    let status = server.tool_text("session_status", json!({}), STEP);
    let worker = engine_pid_of(&status, &session);
    let before = system_uptime(&server.tool_text(
        "execute",
        json!({ "command": ".time", "session_id": session }),
        TARGET_STEP,
    ));

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
    let (after, ended) = match maybe_session_id(&report) {
        Some(session) => {
            let after = system_uptime(&again.tool_text(
                "execute",
                json!({ "command": ".time", "session_id": session }),
                TARGET_STEP,
            ));
            // The release. From here the target is running again whatever the assertions say.
            let ended =
                again.tool_text("end_session", json!({ "session_id": session }), TARGET_STEP);
            (after, ended)
        }
        None => (None, String::new()),
    };

    // --- now assert ----------------------------------------------------------------------
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
    assert!(
        !ended.contains("terminated"),
        "the final detach must be graceful, or the target is left frozen:\n{ended}"
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

/// A tag no allocator will have used, so answering has to walk the whole pool.
///
/// If it ever collides the test says so and stays honest rather than failing; change it then.
const ABSENT_TAG: &str = "Zq7x";

/// Microsoft's public symbol store, appended so the walker can resolve `nt`'s private types.
///
/// The pool walker decodes segment-heap internals — `_EX_POOL_HEAP_MANAGER_STATE`,
/// `_HEAP_PAGE_RANGE_DESCRIPTOR`, the VS and LFH headers — and none of that is in the public
/// export table. Without full type information every pool query fails before it reads a byte.
const MS_SYMBOL_SERVER: &str = "srv*https://msdl.microsoft.com/download/symbols";

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

/// The heaviest tag in `pool_census` output.
fn heaviest_census_tag(census: &str) -> HeaviestTag {
    let mut lines = census
        .lines()
        .skip_while(|line| !(line.starts_with("tag ") && line.contains("allocs")));
    if lines.next().is_none() {
        return HeaviestTag::NothingListed;
    }
    let Some(row) = lines.find(|line| !line.trim().is_empty()) else {
        return HeaviestTag::NothingListed;
    };
    // A fixed-width column, read as one. Splitting on whitespace looks equivalent and is not:
    // `display_tag` keeps spaces, so a real tag like `Ntf ` would come back as `Ntf`, which is a
    // *different* four bytes — the cross-check below would then query a tag nobody allocated and
    // blame the walk for not finding it. Every rendering is exactly four characters.
    let tag: String = row.chars().take(4).collect();
    if tag.chars().count() != 4 || tag.contains('.') {
        return HeaviestTag::Ambiguous;
    }
    HeaviestTag::Queryable(tag)
}

/// Pinned in the default tier, because the failure it guards against is a *silent skip*: the
/// cross-check it feeds only runs on `Queryable`, so a parser that stops matching takes the proof
/// with it and the live run still passes. The three-way split matters just as much — collapsing
/// `Ambiguous` into `NothingListed` turns an unremarkable target into a test failure.
#[test]
fn a_census_table_yields_its_heaviest_tag() {
    const HEADER: &str = "tag      allocs        bytes  nonpaged   paged";
    let table = |rows: &str| {
        format!(
            "3 distinct tag(s) allocated, heaviest first.\n\n{HEADER}\n{rows}\n\
             \n--- pool walk ---\nchunks walked: 5 (4 allocated), coverage: complete\n"
        )
    };

    assert!(matches!(
        heaviest_census_tag(&table(
            "MmSt        912       0x1f40       912       0\n\
             Tgsm          4         0x1a0         4       0"
        )),
        HeaviestTag::Queryable(tag) if tag == "MmSt"
    ));

    // A three-byte tag is rendered padded with the space it actually contains, and `parse_tag`
    // takes it straight back. Splitting on whitespace would hand `pool_find_tag` the three-byte
    // `Ntf` instead — a different tag, which nothing allocated, blamed on the walk.
    assert!(matches!(
        heaviest_census_tag(&table("Ntf         912       0x1f40       912       0")),
        HeaviestTag::Queryable(tag) if tag == "Ntf "
    ));

    // A walk that found nothing has no heaviest tag, and nothing may invent one.
    assert!(matches!(
        heaviest_census_tag("The pool snapshot contains no allocated chunks."),
        HeaviestTag::NothingListed
    ));

    // Unprintable tag bytes render as `.`, and so does a literal `.` — the rendering cannot be
    // turned back into bytes. That is a fact about rendering, not about the pool, so it must not
    // read as "the walk found nothing".
    assert!(matches!(
        heaviest_census_tag(&table("Nt.f        912       0x1f40       912       0")),
        HeaviestTag::Ambiguous
    ));
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
    let mut server = Server::started();

    let attached = server.call_tool(
        "attach_kernel",
        json!({ "connection": connection }),
        TARGET_STEP,
    );
    let report = text_of(&attached["result"]);
    let Some(session) = maybe_session_id(&report) else {
        assert_no_error(&attached, "attach_kernel");
        panic!(
            "the attach did not land, and left no session behind. The target must be booted with \
             debugging enabled and dialling this host, and the KD transport is single-owner:\n\
             {report}"
        );
    };

    let outcome = catch_unwind(AssertUnwindSafe(|| {
        assert_no_error(&attached, "attach_kernel");

        // The walker needs full nt type information — `_EX_POOL_HEAP_MANAGER_STATE` and the rest
        // of the allocator's private types — and a fresh attach does not force-load it. This is
        // the documented precondition; doing it here rather than assuming it is what lets the
        // tier set up its own target. Symbols are never fetched over the KD wire, so this is
        // about *this* host's symbol path, not the target's.
        server.tool_text(
            "set_symbol_path",
            json!({ "path": MS_SYMBOL_SERVER, "append": true, "session_id": session }),
            TARGET_STEP,
        );
        let reloaded = server.tool_text(
            "execute",
            json!({ "command": ".reload /f nt", "session_id": session }),
            TARGET_STEP,
        );

        // A forced walk. `refresh` is the expensive path and the one that wedged; nothing is
        // cached this early anyway, but asking for it says so rather than relying on it.
        let started = Instant::now();
        let walk = server.call_tool(
            "pool_find_tag",
            json!({ "tag": ABSENT_TAG, "refresh": true, "session_id": session }),
            TARGET_STEP,
        );
        let walked_for = started.elapsed();
        let absent = text_of(&walk["result"]);
        // Before the timing, because a call that *failed* also returns fast: the first live run
        // of this test measured 6.8ms and passed every deadline assertion below, having never
        // walked a single page. A tool error is text like any other to `tool_text`, so nothing
        // here may be believed until this holds.
        assert!(
            !is_tool_error(&walk),
            "the pool walk failed outright, so nothing below would be measuring a walk. If this \
             names missing kernel pool symbols, this host cannot resolve full type information \
             for `nt`; the walker needs it and it is never fetched over the KD wire. Fix the \
             symbol path and re-run — the tier proves nothing without it.\n{absent}\n\n\
             `.reload /f nt` had said:\n{reloaded}"
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
            server.tool_text("registers", json!({ "session_id": session }), TARGET_STEP);
        let waited = follow_up.elapsed();
        assert!(
            registers.contains("rip="),
            "the session should still be a broken-in kernel after a pool walk:\n{registers}"
        );
        assert!(
            waited < NOT_QUEUED,
            "a call made after the walk returned waited {waited:?} — it queued behind an engine \
             that was still walking, which is the failure the budget exists to prevent"
        );

        // An empty answer has to say what the walk managed, or "no such chunk" and "the walk
        // reached almost none of the pool" are the same sentence. Reachable only because the
        // call succeeded — the first live run took this branch on an *error* text and announced
        // that the tag existed, inventing a fact about the pool out of a failure to look at it.
        if absent.contains("No allocated chunks carry tag") {
            assert!(
                absent.contains("--- pool walk ---") && absent.contains("chunks walked:"),
                "an empty result must carry the walk's own coverage:\n{absent}"
            );
        } else {
            eprintln!(
                "NOTE: `{ABSENT_TAG}` really is allocated on this target, so the empty-answer \
                 check was skipped. Change ABSENT_TAG."
            );
        }

        // The census is the state of the walk, so it carries the report whatever it found.
        let census_call = server.call_tool(
            "pool_census",
            json!({ "session_id": session, "limit": 8 }),
            TARGET_STEP,
        );
        let census = text_of(&census_call["result"]);
        assert!(
            !is_tool_error(&census_call),
            "pool_census failed:\n{census}"
        );
        assert!(
            census.contains("--- pool walk ---") && census.contains("chunks walked:"),
            "the census must always report the walk behind it:\n{census}"
        );
        let complete = census.contains("coverage: complete");
        println!(
            "the census reports this walk {}",
            if complete { "complete" } else { "INCOMPLETE" }
        );

        match heaviest_census_tag(&census) {
            // What one tool saw, the other has to find. Only meaningful when the walk completed:
            // an incomplete snapshot is deliberately not cached, so these would be two separate
            // walks of a moving target and could honestly disagree.
            HeaviestTag::Queryable(tag) if complete => {
                let cached = Instant::now();
                let call = server.call_tool(
                    "pool_find_tag",
                    json!({ "tag": tag, "session_id": session }),
                    TARGET_STEP,
                );
                let reuse = cached.elapsed();
                let found = text_of(&call["result"]);
                assert!(
                    !is_tool_error(&call),
                    "looking up the census's own heaviest tag `{tag}` failed:\n{found}"
                );
                assert!(
                    found.contains(&format!("tag `{tag}`")) && found.contains("allocation(s)"),
                    "the census called `{tag}` the heaviest tag, so find_tag must find it in the \
                     same snapshot:\n{found}"
                );
                assert!(
                    reuse < walked_for,
                    "a second query took {reuse:?} against the first walk's {walked_for:?} — a \
                     complete snapshot is meant to be cached and reused, not walked again"
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
    if let Err(panic) = outcome {
        eprintln!("detached after the failure below:\n{ended_text}");
        resume_unwind(panic);
    }
    assert_no_error(&ended, "end_session after a pool walk");
    assert!(
        !ended_text.contains("terminated"),
        "the worker was killed instead of detaching, which leaves the target halted:\n{ended_text}"
    );
}
