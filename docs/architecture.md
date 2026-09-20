# Architecture

**One debug session per process.** dbgeng.dll holds a single debuggee session per process — that is
why `.opendump` *replaces* the target rather than opening a second one — so this server runs the MCP
protocol in a **supervisor** process and each open target in its own **engine worker** child
process. Two things follow, and they are why it is built this way:

- **A session that cannot be unwound costs a process, not the server.** A live-kernel attach waits
  for its target with `WaitForEvent(INFINITE)`, and nothing can interrupt a wait that has not yet
  connected — so a guest that never dials in blocks forever. That blocks one worker, which
  `end_session` can terminate. It used to block the server's only engine thread, and the only
  recovery was restarting the server.
- **Sessions are concurrent.** Triage a crash dump while a kernel attach is live; keep a TTD trace
  open while you look at another. Up to four at once.

- **`engine.rs`** — the supervisor: the session registry, worker spawn/teardown, and the routing
  that turns a `session_id` into "which worker". Each session has one queue with one consumer, so
  calls against a session are *serialized* — one runs at a time, and the one running finishes
  before the next starts. Serialized is not ordered: two calls submitted before either has
  answered reach that queue in whichever order wins the race, so await each result before sending
  the next call that depends on it.
- **`worker.rs`** — the child process. The `DebugEngine` is created on, and confined to, one OS
  thread inside it (DbgEng requires serialized, single-thread access, and `WaitForEvent` must run on
  the session-owning thread). A `catch_unwind` guard turns a panic in one operation into a failed
  call rather than a dead session. The *request reader* is a second thread that only ever reads and
  hands on, so it is never blocked by the engine — which is what makes `interrupt` and the
  abandon-a-batch signal deliverable to a worker that is busy.
- **`proto.rs`** — the line-delimited JSON protocol between the two. A closure cannot cross a
  process boundary, so what used to be closures marshalled onto the engine thread are now
  serializable operations — deliberately *tool*-shaped rather than DbgEng-shaped, so a tool that is
  several engine calls (`reachable_from_dispatch`'s call-graph walk) stays one indivisible job. It
  travels on a pair of anonymous pipes the worker inherits, not on its standard handles: an
  extension DLL that prints to the console writes to the worker's stdout, which is drained into the
  log and carries nothing else.
- **`server.rs`** — the MCP tools (listed in the [README](../README.md#tools)), built with `rmcp`'s `#[tool_router]`/`#[tool_handler]`.
- **`kdconn.rs`** — kernel connection strings, the one tool argument that is a secret: profile
  resolution, and the `Connection` type whose `Debug`/`Display` are redacted so a key can only be
  unwrapped deliberately (see [Kernel connection profiles](./kernel-profiles.md)).
- **`ttd.rs`** — locates `TTD.exe` and launches trace recording.
- **`main.rs`** — role selection (supervisor or worker) and, for the supervisor, which transport it
  serves on: tokio with stdio, or HTTP when `--listen` names an address. **Logs go to
  stderr** (under stdio, stdout is the JSON-RPC channel); worker stderr is piped through the
  supervisor, so both roles' records land in the same place. A disconnect attempts concurrent release with a **five-second** grace.
  Non-kernel workers that do not finish are terminated. **Unresolved remote kernel controllers
  survive**, including after their request channel closes; only explicit operator handoff may
  terminate them unless a late reply confirms release. Their stdout and stderr are drained by
  unjoined OS threads rather than Tokio's Windows blocking pipe readers. An orphan's open pipes
  therefore neither keep the supervisor runtime alive nor hold the MCP host's stderr open.
  A session running a `debug_batch` is told to abandon it by that same request, and
  then gets as long as the batch says it still needs on top of the grace — the only case where a
  disconnect waits longer, and never longer than the batch's own budget allowed.
  End a live kernel session explicitly with `end_session`, which allows a longer grace, and
  verify its result and target health out of band. Worker termination proves neither resume nor
  detach. See [unresolved-controller recovery](sessions.md#unresolved-remote-kernel-controllers).

**MCP protocol revision:** built on `rmcp` 3.x, this server accepts every revision that SDK knows —
`2026-07-28` and the `initialize`-handshake ("legacy") era before it (`2025-11-25`, `2025-06-18`,
`2025-03-26`, `2024-11-05`) — and serves whichever the client selects. A `2026-07-28` client gets the
stateless, per-request model (`server/discover`, `resultType`, per-request `_meta`) and opens with
`server/discover` rather than `initialize`; older clients keep the handshake, and a client that
offers an unknown revision is answered with `2025-11-25`.

**How a client selects it is not the same question on both sides of that line**, and it is worth
being exact because the two look alike from the outside. `2026-07-28` did not add an option to the
handshake — [SEP-2567](https://modelcontextprotocol.io/seps/2567-sessionless-mcp) *abolished* the
handshake, moving what it settled into per-request `_meta`. So the revision is selected per request
by a client on `2026-07-28`, and by `initialize` for the legacy era; and an `initialize` that names
`2026-07-28` anyway is answered with `2025-11-25`, because a handshake cannot negotiate its way to a
revision that has none. That is `rmcp` 3.2.0's rule rather than this server's (upstream #1228), and
it is why the dependency carries a `3.2.0` floor — earlier 3.x echoed the offer back, so the same
client saw a different answer depending on which patch release was resolved.

`2026-07-28` also makes SEP-2549's cache fields mandatory on a paginated result, so `tools/list`
answers a client **on** that revision with `ttlMs: 0` and `cacheScope: public`, and omits both for
the older revisions, which never defined them. Since the fields follow the revision actually in
force, they appear on the stateless path and not after a handshake that negotiated down. This is the
other half of why `rmcp` has a floor at all: every 3.x before `3.1.1` omitted the fields on every
revision, and a client that validates against the spec schema then rejects the whole tool list.
