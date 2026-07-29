# Follow-ups

Deferred work, in two clusters: items 1–6 come from the reachability-confirmation effort (path
recipe + `run_to_address`, merged 2026-07-04), items 7–11 from surveying this server against the
MCP `2026-07-28` extensions (tasks, apps). Each item notes its repo, why it was deferred, and where
it picks up. See [`DECISIONS.md`](./DECISIONS.md) for the design rationale (D1–D5) items 1–6 extend.

Items are roughly ordered by how soon they're worth doing, within each cluster.

## 1. [win-kexp] Managed breakpoint lifecycle for `run_to_address`

`run_to_address` uses a one-shot `g <addr>` (WinDbg's temporary breakpoint), which DbgEng does **not**
hand back a handle for. On a non-live timeout the target is now broken in (SetInterrupt + WaitForEvent),
but the one-shot breakpoint at `address` can remain armed. Replace `g <addr>` with an explicitly
managed `AddBreakpoint2` + `RemoveBreakpoint` lifecycle so the breakpoint is cleaned up deterministically
in **all** exit paths (hit, stopped-elsewhere, timeout, error).

- **Why deferred:** the interrupt + breakpoint-teardown semantics need a live KDNET/VM kernel target to
  validate; landing it blind risks a worse regression (hang, or clearing the caller's breakpoints).
- **Tracked as:** [glslang/win-kexp#63](https://github.com/glslang/win-kexp/issues/63) (picks up from
  win-kexp PR #62's `src/dbgeng.rs` review thread on the `Timeout` branch). A stale one-shot at
  `address` is currently harmless to this API's own flow (a later `run_to`/`go` arms its own), so it is
  low-severity until an explicit rewrite is validated on hardware.

## 2. [win-kexp] Typed write primitives

`write_virtual`, a typed register **write**, and `ba` (data) breakpoints. Today only the `execute` raw
text path exists (`eb`/`ed`/`r reg=`).

- **Why deferred:** primarily needed by the state-injection path (item 3); no consumer without it.
- **Note:** win-kexp is the right home for these (DECISIONS.md D3 — typed `DebugEngine` methods, not the
  text hatch), mirroring how `run_to_address`/`instruction_pointer` were added.

## 3. [windbg-mcp + win-kexp] State-injection confirmation path (DECISIONS.md D4)

Alternative to driving a real IOCTL client: break at the dispatch entry, craft an IRP +
IO_STACK_LOCATION + SystemBuffer in memory, set `rcx`/`rdx`, and run to the target block.

- **Why deferred:** a wrong/partial IRP mutates live kernel state and can bugcheck the target,
  destroying the reproducible state the analysis depends on. Deprioritized behind the drive-a-client
  path (`ioctl_harness.ps1` + `run_to_address`).
- **Depends on:** item 2 (typed write primitives) and the item-1 breakpoint work; the same path-recipe
  data the drive path uses. Prefer a snapshot-restorable VM when building it.

## 4. [win-kexp] Typed `read_register`

Generalize the private `instruction_pointer` helper (added for `run_to_address`) into a public typed
register read, per DECISIONS.md D5 step 1. Only the instruction pointer is implemented today.

## 5. [windbg-mcp] Path-recipe decode limits (heuristic boundary)

The operand → IO_STACK_LOCATION field mapping (`+0x18`/`+0x10`/`+0x08`) is heuristic: it holds only
when the compare's memory base is the current stack-location pointer, and complex predicates
(multi-instruction conditions, computed offsets, table lookups) aren't decoded. This is the documented
boundary where item 6 would take over.

## 6. [windbg-mcp] Concolic/symbolic buffer synthesis (DECISIONS.md D2 — scoped out)

Auto-emit a concrete `(code, buffer, lengths)` by SMT-solving the on-path branch predicates, rather
than the human/LLM-readable recipe emitted today.

- **Status:** scoped **out** of the current effort. If ever needed, offload to angr/Triton over a
  debugger memory snapshot rather than building an in-house solver — kernel state modeling, loops,
  hashing, and stateful protocols make it brittle and a separate project.

## 7. [win-kexp + windbg-mcp] On-demand engine interrupt

Expose `SetInterrupt` as a public win-kexp method (and a `Send` handle obtainable from a
`&DebugEngine`), then plumb it through `EngineHandle` as `interrupt()`. Today the primitive exists
but is only ever *timeout-driven*: `execute_command_bounded` (win-kexp `src/dbgeng.rs:607`) and
`wait_for_event_bounded` (`:716`) each spawn a watchdog thread holding an `InterruptHandle` and
Ctrl+Break the engine when a deadline passes. There is no way for a caller to ask for that now.

`InterruptHandle` (`src/dbgeng.rs:115-119`) already carries the reasoning: `SetInterrupt` is the one
DbgEng call documented as safe from another thread, so this needs no new threading model — the
engine stays confined to its one thread (`src/engine.rs`) and the interrupt arrives from outside it,
exactly as it does today.

- **Why it comes first:** it is what would give item 8's `tasks/cancel` anything to do — the spec's
  cancellation is cooperative, so acknowledging one conforms, but a server whose engine thread is
  blocked inside DbgEng cannot act on it at all. It stands alone too: it gives an operator a way to
  abort a runaway `execute` before `ENGINE_CALL_TIMEOUT` (`src/main.rs:22`, 300s) elapses.
- **Known limit, carried from win-kexp `src/dbgeng.rs:726`:** `SetInterrupt` cannot unblock a
  live-kernel wait until the target is *connected*. So the `attach_kernel` KDNET park documented in
  `CLAUDE.md` — the case that most wants cancelling — is not cancellable this way; only tearing down
  the client or the process ends it. That limit is what motivates item 10.

## 8. [windbg-mcp] Tasks extension (`io.modelcontextprotocol/tasks`, SEP-2663)

Nothing here speaks tasks today. `#[rmcp::tool_handler]` generates `get_info` as
`ServerCapabilities::builder().enable_tools().build()` and nothing else, so no `extensions` map is
advertised and `tasks/get` / `tasks/update` / `tasks/cancel` fall through to the `ServerHandler`
trait defaults (`method_not_found`).

The fit is unusually good, because the server already models the problem tasks exist to solve.
`EngineError::Timeout` documents that a timeout abandons "the *waiter*, not the engine, so it may
still be running" (`src/engine.rs:37-42`), and the `opens: VecDeque<(String, OpenOutcome)>` ring
(`src/server.rs:43`) plus `session_status` (`:1963`) exist **only** so a caller whose open timed out
can ask afterwards whether it is still pending, landed, or failed. That is a hand-rolled `tasks/get`;
the extension replaces it with the standard one.

Wiring is mechanical. rmcp 3.0.0 ships the whole server-side runtime — `rmcp::task_manager::{TaskManager,
TaskOptions, TaskContext, TaskExit}`, `CallToolResponse::Task(CreateTaskResult)`,
`ClientCapabilities::supports_tasks()`, TTL expiry, cooperative cancel — and the macro does not fight
it: `tool_handler` only synthesizes `call_tool`/`list_tools`/`get_tool`/`get_info` when the impl block
does not already define them, so hand-writing `call_tool` and `get_info` inside the existing
`impl rmcp::ServerHandler for WindbgServer` leaves the rest generated.

Suggested order, chosen so the protocol work is proved before it touches DbgEng:

1. `record_trace` — already off the engine thread (`spawn_blocking`, `src/server.rs:2675`), so
   converting it is pure protocol work with no debugger risk.
2. `open_dump` / `open_trace` / `index_trace` / `attach_kernel` — where the pain actually is, and
   where the `opens` ring can shrink to a thin adapter over `tasks/get`.
3. `go` / `run_to_address` / `execute` — best held until item 7 lands. `tasks/cancel` is
   *cooperative* by spec: acknowledging it while the work runs on to some terminal state is
   conformant, so these are implementable without an interrupt. But for exactly these three the
   engine thread is blocked inside DbgEng, so until item 7 there is no effort the server could
   make — cancel would be a no-op until the operation ends on its own. Conformant, useless.

Fast, pure tools (`decode_ioctl`, `registers`, `read_memory`, `modules`, `threads`, `disassemble`,
`backtrace`, `session_status`) should stay synchronous.

- **Two things to get right, not plumbing:**
  - **TTL must not re-introduce the lie.** `DEFAULT_TASK_TTL_MS` is 5 minutes and expiry marks a task
    `failed`; a kernel attach waits indefinitely by design. Attaches need `ttl_ms: None`, or the task
    reports a failure while the attach is still genuinely pending — the exact false report the
    conversion was meant to remove.
  - **The session-handle contract needs a task-path clause.** The queued-precheck design survives
    untouched (a task's gate still runs in the same queued job, so the ordering guarantee in the
    CHANGELOG holds), but if an opener returns a task then the `session_id` arrives in the task
    *result*, not the immediate response. "Commit the handle as soon as the target transition
    succeeds" has to be restated for that path.
- **Note:** tasks are client-negotiated (`supports_tasks()`), so every converted tool keeps its
  synchronous path. This is additive, never a replacement.

## 9. [win-kexp + windbg-mcp] Incremental output from a running command

A second `IDebugClient` (via `IDebugClient::CreateClient`, already wrapped as
`create_from_windbg_client`, win-kexp `src/dbgeng.rs:197`) can own its own `IDebugOutputCallbacks`.
That is the route to partial output from a long `g` or `execute` — a task's `statusMessage`, or a
progress line — without the engine call returning. Today `OutputCallbacks` is installed on the one
client for the duration of a command, so output only lands when the command ends.

- **Why deferred:** worth little before item 8 gives it somewhere to go.
- **Does not buy concurrency.** A second client joins the *same* session and serializes on the same
  engine lock; while one thread is in `WaitForEvent`/`Execute`, calls from the other block. It would
  swap `engine.rs`'s queue for DbgEng's internal one and gain nothing. Only item 10 delivers
  parallelism.

## 10. [windbg-mcp] Process-per-session, for actual concurrency

dbgeng.dll holds **one debuggee session per process**. That is not a win-kexp limitation — it is why
`.opendump` *replaces* the target, and why the `session_id` design exists at all (a handle that
detects the swap, because there is nothing to swap *between*). So analysing a dump while a kernel
attach sits parked in `WaitForEvent(INFINITE)` requires one engine process per session.

This is what makes item 8 pay off rather than merely report honestly: with a single engine thread a
`working` task still owns the engine and every other tool queues behind it — the `submitted.elapsed()`
budget arithmetic in `EngineHandle::run_command` exists because of exactly that queue. Under
process-per-session, `session_id` stops meaning "detect that the target changed underneath you" and
starts meaning "route to the worker that owns this target".

- **Why deferred:** large. Needs process supervision, per-worker symbol state (`.sympath`, caches),
  and moving the `opens` / `session_status` bookkeeping up into a supervisor. DbgEng's own remoting
  (`.server` / `DebugConnect`) is the same shape with more moving parts — the remote session is still
  its own engine process.
- **Watch:** `unsafe impl Send/Sync for DebugEngine` (win-kexp `src/dbgeng.rs:164-165`) is sound
  *because* `src/engine.rs` confines the engine to one thread. Any design that calls it from several
  threads turns those impls from bookkeeping into a real, unchecked claim.

## 11. [windbg-mcp] MCP Apps (`ui://` resources) — scoped out

Apps needs a resource surface serving `text/html;profile=mcp-app` over an iframe/postMessage host
bridge. This server has no resources at all (no `list_resources`/`read_resource`), every tool returns
a single text block (`text_result`, `src/server.rs:51`), and the payloads are raw WinDbg text — `lm`,
`k`, `u`, `!ttdext` output — which a model reads fine and a terminal already renders as a code block.
The primary client is the Claude Code CLI (this also ships as a plugin/mcpb for it), which is not an
iframe host.

- **Status:** scoped **out**. Three outputs do have structure that text flattens —
  `reachable_from_dispatch` (a call graph plus branch recipe; the edge set is already built at
  `src/server.rs:302-474`), `driver_object`/`device_object` (a tree), and `ttd_calls`/`ttd_memory`
  (events on a trace-position axis).
- **Cheaper alternative, if those three ever need it:** `structuredContent` + `outputSchema`. Same
  data, lossless to the model, works in every client, no UI runtime. Do that before any HTML.
