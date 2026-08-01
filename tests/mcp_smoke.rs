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
//! Two tiers, so the cheap half can ride `cargo test` everywhere:
//!
//! * **Protocol** (default) — spawns the server, speaks JSON-RPC. No debugger target, no
//!   symbols, no network.
//! * **Target** (`WINDBG_MCP_SMOKE_DUMP=1`) — opens the sample crash dump through DbgEng, so
//!   it needs `dbgeng.dll` and may reach a symbol server. Off by default; this is the tier
//!   that catches a `win-kexp` regression.
//!
//! See `docs/smoke-test.md` for the runbook.

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Write};
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
        let mut child = Command::new(EXE)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // Deterministic logging regardless of the developer's shell.
            .env("RUST_LOG", "info")
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
        let id = self.next_id;
        self.next_id += 1;
        let msg = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        self.send_line(&msg);
        self.await_id(id, method, budget)
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
        let mut server = Self::spawn();
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
    let stderr = server.stderr();
    assert!(
        stderr.contains("windbg-mcp starting on stdio"),
        "expected the startup log on stderr, got:\n{stderr}"
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
/// outside the document, or a mix of dialects, breaks strict validators — and both are things
/// a codegen dependency can introduce without any change here.
#[test]
fn tool_schemas_are_self_contained() {
    let mut server = Server::started();
    let response = server.request("tools/list", json!({}), STEP);
    let tools = response["result"]["tools"]
        .as_array()
        .expect("tools/list returns an array")
        .clone();
    assert!(!tools.is_empty(), "tools/list must not be empty");

    for tool in &tools {
        let name = tool["name"].as_str().unwrap_or("<unnamed>");
        let schema = &tool["inputSchema"];
        assert_eq!(
            schema["type"], "object",
            "`{name}` input schema must be an object schema: {schema}"
        );

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

    // The handle is what every later call is checked against, so the open has to mint one.
    let session_id = opened
        .lines()
        .find_map(|l| l.split("session_id").nth(1))
        .map(|rest| {
            rest.trim_start_matches([':', ' ', '=', '"'])
                .trim_end_matches(['"', ',', '.'])
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .trim_end_matches(['"', ',', '.'])
                .to_string()
        })
        .unwrap_or_else(|| panic!("open_dump must return a session_id, got:\n{opened}"));
    assert!(!session_id.is_empty(), "empty session_id in:\n{opened}");

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
    let modules = server.tool_text("modules", json!({ "session_id": session_id }), TARGET_STEP);
    for expected in ["   nt ", "   hal "] {
        assert!(
            modules.contains(expected),
            "the module list should include `{}`, got:\n{modules}",
            expected.trim()
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

    // A handle from a session that is not current must be refused rather than silently
    // answered against whatever happens to be open — the contract `check_session_handle` owns.
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

/// The `isError` contract, on the wire. `engine.rs` splits debugger failures (the model can
/// retry) from engine failures (it cannot); the first kind must arrive as a *result* flagged
/// `isError`, never as a JSON-RPC error the model never really sees.
#[test]
fn a_failed_debugger_operation_is_a_tool_error_not_a_protocol_error() {
    if target_tier().is_none() {
        return;
    }
    let mut server = Server::started();

    // No target is open, so execution control has nothing to run.
    let response = server.call_tool("go", json!({}), TARGET_STEP);
    assert_no_error(
        &response,
        "go with no debuggee (a debugger failure is a tool result, not a protocol error)",
    );
    assert!(
        is_tool_error(&response),
        "a failed debugger operation must set isError, got {response}"
    );
    let text = text_of(&response["result"]);
    assert!(
        !text.trim().is_empty(),
        "a tool error must explain itself so the model can correct: {response}"
    );
}
