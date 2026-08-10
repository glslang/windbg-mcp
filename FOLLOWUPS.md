# Follow-ups

Deferred work, in five clusters: items 1–6 come from the reachability-confirmation effort (path
recipe + `run_to_address`, merged 2026-07-04), items 7–11 from surveying this server against the
MCP `2026-07-28` extensions (tasks, apps), item 12 from the opener split
(glslang/win-kexp#71, 2026-08-01), items 13–14 from the bounded-command coverage review
(#46, 2026-08-02), item 15 from the private worker channel (#65 / #72, 2026-08-04), and items 16–18
from transactional batches (#82, 2026-08-09/10 — item 17 is what validating the tool against the CTF
session's own transcript turned up, and item 18 what reviewing it did). Each item notes its repo,
why it was deferred, and where it picks up. See [`DECISIONS.md`](./DECISIONS.md) for the design rationale (D1–D5) items 1–6 extend,
and the 2026-08-02 entries that items 13–14 and item 10 extend.

Items are roughly ordered by how soon they're worth doing, within each cluster. **Item 10 has
landed** (process-per-session, 2026-08-02); it is kept here rather than deleted because items 7, 8
and 9 were all written against the single-engine design it replaced, and each now says what moved.
**Item 18 has landed** (2026-08-10) and is kept for the opposite reason: it turned out to need much
less of item 7 than it claimed to, and item 7 should be read knowing which half of it is still owed.

## 1. [win-kexp] Managed breakpoint lifecycle for `run_to_address` — **done upstream**

`run_to_address` used a one-shot `g <addr>` (WinDbg's temporary breakpoint), which DbgEng does **not**
hand back a handle for, so every exit but a hit could leave it armed.

Fixed in win-kexp (`05df6b7`, closing
[glslang/win-kexp#63](https://github.com/glslang/win-kexp/issues/63)) and picked up here by the pin
bump. Building it surfaced two further defects on the same path, both of which mattered more than
the stale breakpoint this item was filed for: the `Timeout` outcome was **unreachable** (it tested
`GetExecutionStatus() == DEBUG_STATUS_GO`, but an expired finite wait reports `DEBUG_STATUS_BREAK`),
so a timed-out `run_to_address` returned `0x8000FFFF` "catastrophic failure" and left the session
with no current process — and the recovery it would have run does not work either, because a finite
wait stops the engine pumping events and `SetInterrupt` can no longer be delivered. Every target
type now uses the watchdog-bounded `WaitForEvent(INFINITE)` the live-kernel path already used.

Nothing changed in this crate: `run_to_address` is a thin wrapper and its `RunToOutcome::Timeout`
branch simply became reachable. The verdict text it renders was already correct for a target that
ends up broken in.

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
`&DebugEngine`), then plumb it through to a per-session `interrupt()`. Today the primitive exists
but is only ever *timeout-driven*: `execute_command_bounded` (win-kexp `src/dbgeng.rs:607`) and
`wait_for_event_bounded` (`:716`) each spawn a watchdog thread holding an `InterruptHandle` and
Ctrl+Break the engine when a deadline passes. There is no way for a caller to ask for that now.

`InterruptHandle` (`src/dbgeng.rs:115-119`) already carries the reasoning: `SetInterrupt` is the one
DbgEng call documented as safe from another thread, so this needs no new threading model — the
engine stays confined to its one thread (`src/worker.rs`) and the interrupt arrives from outside it,
exactly as it does today.

**Reshaped by item 10.** The interrupt is now a *per-session* concern: it has to reach one worker's
engine, and it cannot travel as an ordinary op, because a worker whose engine is wedged is exactly
the one not draining its *engine* queue — it needs a request the worker's reader thread acts on
where it reads it.

**Item 18 built that half.** `worker::run`'s reader loop acts on `EngineOp::EndSession` where it
reads it, before queueing it, so the signal lands while the engine is busy. What is left for this
item is the part that touches DbgEng — `SetInterrupt` as a public win-kexp method, bound to job
identity so a cancel cannot Ctrl+Break an unrelated job. The channel question is settled; no side
channel was needed, because the reader was never blocked.
The urgency dropped with the same change: `end_session` already ends any call by terminating the
session, so an interrupt is no longer the only way out of a runaway command, just the graceful one
that keeps the target.

- **Why it comes first:** it is what would give item 8's `tasks/cancel` anything to do — the spec's
  cancellation is cooperative, so acknowledging one conforms, but a session blocked inside DbgEng
  cannot act on it at all *without being thrown away*. It stands alone too: it gives an operator a
  way to abort a runaway `execute` before `ENGINE_CALL_TIMEOUT` (`src/main.rs`, 300s) elapses,
  keeping the target that `end_session` would discard.
- **A bare `interrupt()` would hit the wrong job.** `SetInterrupt` addresses one engine, meaning
  whichever operation that session is *currently running* — but each session's queue is FIFO with
  one consumer, and item 8 makes several calls in flight at once the normal case rather than the
  exception. Cancelling a task whose job is still queued would then Ctrl+Break an unrelated
  task's running operation, and the cancelled job would go on to execute anyway when its turn came:
  `Sessions::call` already documents that a timeout abandons the wait and that the job itself is
  *not* cancelled. So the interrupt has to be bound to job identity — the engine tracks which job
  is active, a cancel for a queued job drops it from the queue, and `SetInterrupt` fires only when
  the cancelled job is the running one. That is the substance of this item, not an add-on to it.
- **Known limit, carried from win-kexp `src/dbgeng.rs:726`:** `SetInterrupt` cannot unblock a
  live-kernel wait until the target is *connected*. So the `attach_kernel` KDNET park documented in
  `CLAUDE.md` — the case that most wants cancelling — is not cancellable this way; only tearing down
  the process ends it. That limit is what motivated item 10, which has since landed and made that
  teardown a supported, in-band operation (`end_session`).

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

1. `record_trace` — already off any engine (`spawn_blocking`, `src/server.rs`), so converting it is
   pure protocol work with no debugger risk.
2. `open_dump` / `open_trace` / `index_trace` / `attach_kernel` — where the pain actually is, and
   where `session_status` can shrink to a thin adapter over `tasks/get`.
3. `go` / `run_to_address` / `execute` — best held until item 7 lands. `tasks/cancel` is
   *cooperative* by spec: acknowledging it while the work runs on to some terminal state is
   conformant, so these are implementable without an interrupt. But for exactly these three the
   session's engine is blocked inside DbgEng, so until item 7 the only effort the server can make
   is ending the session outright — a heavier answer than a cancel should be.

Fast, pure tools (`decode_ioctl`, `registers`, `read_memory`, `modules`, `threads`, `disassemble`,
`backtrace`, `session_status`) should stay synchronous.

- **Three things to get right, not plumbing:**
  - **TTL must not re-introduce the lie.** `DEFAULT_TASK_TTL_MS` is 5 minutes and expiry marks a task
    `failed`; a kernel attach waits indefinitely by design. Attaches need `ttl_ms: None`, or the task
    reports a failure while the attach is still genuinely pending — the exact false report the
    conversion was meant to remove.
  - **An `attach_kernel` task must not report `cancelled`.** Item 7's interrupt cannot unblock a
    KDNET wait before the target connects, so a cancel cannot end that job — and the job is not
    inert while it runs: the attach self-heals and *lands* the moment the target dials in, replacing
    the current target. A task that went `cancelled` on request would therefore have the session
    swapped underneath a client that believes the operation is over. Cooperative cancellation is the
    escape hatch here rather than the problem: acknowledge the request, decline to transition, and
    leave the task `working` until the engine job actually resolves. A cancel that genuinely ends the
    wait needs item 10's worker teardown, which has landed: `end_session` terminates the session's
    process, so a client that genuinely wants out has a way — it just is not `tasks/cancel`.
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
  swap the worker's queue for DbgEng's internal one and gain nothing. Concurrency *between* targets
  came from item 10 instead.

## 10. [windbg-mcp] Process-per-session — **done** (2026-08-02, issue #61)

dbgeng.dll holds **one debuggee session per process**. That is not a win-kexp limitation — it is why
`.opendump` *replaces* the target, and why the `session_id` design existed at all (a handle that
detects the swap, because there was nothing to swap *between*).

Landed: the binary now runs the MCP protocol in a supervisor process (`src/engine.rs`) and each open
target in an engine worker child process (`src/worker.rs`), talking over a line-delimited JSON
protocol (`src/proto.rs`). `session_id` stopped meaning "detect that the target changed underneath
you" and started meaning "route to the worker that owns this target". Sessions are concurrent (up to
`MAX_SESSIONS`), and `end_session` can terminate a worker that will not unwind — which is what
issue #61 needed, since a kernel attach whose target never dials in cannot be interrupted at all.

What moved, for anyone picking up the items that referenced this:

- The queue is **per session**, so a busy or parked session no longer blocks any other. The
  budget arithmetic moved with it: the supervisor sends the caller's remaining *patience* and the
  worker derives the watchdog deadline, because only the worker can measure the wait on its own
  side of the pipe.
- The `opens` ledger became the session registry, and `session_status` reports session *state* —
  including how long an open has been waiting, which is what distinguishes a KDNET link that is
  coming up from one that never will.
- `unsafe impl Send/Sync for DebugEngine` (win-kexp `src/dbgeng.rs:164-165`) is still sound for the
  same reason as before: `src/worker.rs` confines the engine to one thread *inside* the worker. The
  supervisor never touches a `DebugEngine` at all, which is a stronger position than the one that
  claim was written for.

Not done, and no longer blocking anything: **per-worker symbol state** —
[#66](https://github.com/glslang/windbg-mcp/issues/66). Each worker has its own `.sympath` and symbol
cache, which is correct (sessions are independent) but means a `set_symbol_path` does not carry to a
session opened later. The fix is a supervisor-held default applied at worker startup, not shared
state between running workers.

Fixed since, from the same review: [#67](https://github.com/glslang/windbg-mcp/issues/67) — workers
were spawned with `kill_on_drop`, so a worker shutdown missed was terminated with its target still
attached. `kill_on_drop` is gone (EOF on the worker's stdin is now the only teardown, which it
already handled), and registration re-checks the shutdown gate so the missable window is closed
rather than merely survivable.

Two ordering details the review of #62 raised and that PR deliberately left alone, both filed:
[#64](https://github.com/glslang/windbg-mcp/issues/64) (`end_session` keeps accepting calls while it
tears the session down — the fix wants the `Gate` treatment `retires` already has) and
[#65](https://github.com/glslang/windbg-mcp/issues/65) (the worker protocol shares stdout with
anything the engine prints; mitigated, not structurally prevented).

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

## 12. [win-kexp] Validate the opener split against a live KDNET target

The split that made per-opener handle commits possible (glslang/win-kexp#71) was validated on
user-mode targets only — split launch, fused launch, split attach, via `examples/split_open.rs`.
The two **kernel** halves ran on no hardware: `attach_local_kernel_begin`/`wait` and
`attach_kernel_begin`/`wait`.

- **What specifically needs a target:** the connection-string buffer now rides across the seam
  inside the `PendingTarget` guard, because a KDNET link is only established during the wait and
  DbgEng may still read the string after `AttachKernel` returns. Before the split that buffer
  stayed alive by accident of scope, so nothing proves the engine reads it late — only that
  assuming it doesn't is unsafe. A real attach over `net:port=...,key=...` settles it. Second,
  `wait_for_kernel_break_in`'s bookkeeping (clear `INITIAL_BREAK`, absorb the spurious re-break,
  map a watchdog-forced return to `KernelBreakTimeout`) all moved behind the guard and wants a
  live break-in plus a deliberate timeout against an unreachable target.
- **Why deferred:** no KDNET target was available. The split cannot change *whether* an attach
  succeeds — `x_begin` makes the identical `AttachKernel` call — so the buffer lifetime is the
  only genuinely new failure mode.
- **Where it picks up:** `examples/kdtest.rs` already drives `attach_kernel` over KDNET; add a
  `attach_kernel_begin` + `wait()` pass beside the existing fused one. Prefer a
  snapshot-restorable VM, per item 1.
- **Tracked as:** [glslang/win-kexp#73](https://github.com/glslang/win-kexp/issues/73).

## 13. [windbg-mcp] A job-level deadline for `reachable_from_dispatch`

`reachable_from_dispatch` runs its whole breadth-first walk — up to `max_functions` × one `uf`
command each — inside a *single* engine job. Both `max_functions` (default 256) and `max_depth`
(default 32) come from the caller and are uncapped, so a large enough pair pins that session's
engine for as long as the walk takes. That is the same wedge the bounded path fixed, arriving by a
different route — smaller now that it costs one session rather than the server, but still a session
that answers nothing until the walk ends.

- **Why the bounded path doesn't reach it:** the bounded path bounds *one* command string. Here no
  individual `uf` is the problem — the aggregate is.
- **Where it picks up:** the walk already drives every disassembly through one `&mut uf` closure
  (`src/server.rs`), which is the natural place to check a deadline and stop with a partial,
  honestly-labelled verdict — "NOT REACHABLE within the budget" is already the tool's contract for
  an exhausted bound, so a time bound reports as a bound rather than as a new failure mode.
  A cap on `max_functions` is the cheaper half-measure; it bounds the walk in nodes, not seconds.
- **Why deferred:** the defaults are safe (a 256-function walk against a loaded dump is seconds),
  so this is reachable only by a caller asking for it. Recorded by the coverage review in
  DECISIONS.md (2026-08-02) rather than fixed there, because it needs a different mechanism than
  the review's subject.

## 14. [win-kexp] Make arming the bounded watchdog ~free

`execute_command_bounded` spawns a watchdog thread that polls a `done` flag on a
`thread::sleep(200ms)` loop, and joins it once `Execute` returns. Because the flag is set while
that thread is mid-sleep, the join waits out the remainder — so a bounded command takes
`ceil(d / 200ms) * 200ms`. Measured (`measure_what_the_bounded_path_costs_a_quick_command`,
`src/engine.rs`): a 127ms command takes 201ms, a 377ms one takes 401ms, and a 0.2ms `lm` takes
either ~0.3ms or ~200ms depending on whether it beats the watchdog thread's first poll.

Parking on a condvar (or `thread::park_timeout` + `unpark`) instead of sleeping would let `done`
wake the watchdog immediately and drop that to ~0.

- **Why it matters here:** the cost is the *only* reason windbg-mcp's cheap point-query tools stay
  off the bounded path (DECISIONS.md, 2026-08-02). Remove it and the coverage rule simplifies to
  "bound everything except `index_trace`", with no per-call tax to weigh against a rare wedge.
- **Why deferred:** it is a win-kexp change with its own review, and the current split is correct
  as long as the cost stands — this is an improvement to the tradeoff, not a fix to a defect.

## 15. [windbg-mcp] Make handle inheritance a property of the spawn, not of the process

The worker protocol channel (#65, landed in #72) is a pair of anonymous pipes whose child ends are
marked inheritable across the spawn. Marking is **process-wide for as long as it lasts**:
`CreateProcess` inherits every inheritable handle, and cannot be told "only these" without a
`STARTUPINFOEX` handle list (`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`). So "only this worker gets these
handles" is currently kept by serializing *every* process this server creates — `spawn_worker`, the
TTD recorder, the test stand-ins — through `engine::spawn_guard`.

A handle list would make it structural: the spawn names what it passes, nothing else is inherited,
and no other spawn site needs to know the rule exists.

- **What it costs today:** the rule is conventional. A spawn added anywhere — a new tool that shells
  out, another recorder — silently reopens the hole, and the failure is quiet and expensive: a
  process holding a worker's *message write end* keeps that pipe from ever reporting EOF, so the
  supervisor never learns the worker exited, `reader`'s tail never runs, the calls it owed replies
  to wait for ever, and the session can never be reclaimed. The first cut of #72 missed two existing
  spawn sites, which is how much the convention is worth unaided.
- **Why deferred:** doing it now means leaving `std::process::Command` for a raw `CreateProcessW`,
  and with it tokio's `Child` — process reaping, `start_kill`, `id()` — all of which
  `Session::kill` and shutdown depend on. That is a large, risk-bearing rewrite for a hazard the
  lock already covers.
- **Where it picks up:** std already has the API, unstable — `CommandExt::raw_attribute` +
  `ProcThreadAttributeList` ([rust-lang/rust#114854](https://github.com/rust-lang/rust/issues/114854))
  — and tokio exposes the inner command through `Command::as_std_mut()`, so on stabilization this
  is a handful of lines in `spawn_worker` with tokio's `Child` intact. **That stabilization is the
  trigger**; there is no reason to hand-roll it first.
- **Meanwhile:** `every_process_spawn_in_this_crate_takes_the_spawn_lock` (`src/engine.rs`) reads
  the crate's own source and fails if a `.spawn()` appears without `spawn_guard` held in the same
  function. The convention is pinned rather than merely documented, which is what makes this an
  improvement to *how* the property is held rather than a fix to a live hole.

## 16. [windbg-mcp] Exercise a *mutating* `debug_batch` against a live kernel target

`debug_batch` (#82) is proved at two altitudes: `src/batch.rs` drives the executor over a scripted
debuggee with a virtual clock (assertion failure, a command failure after a mutation, deadline
expiry, a rollback that itself fails), and the debugger tier drives a real engine to both outcomes
over the wire. Neither covers the case the tool was built for — a **write that is then restored**
on a target that would notice.

- **Why deferred:** a crash dump has nothing worth restoring, and the live-kernel tier is
  `#[ignore]`d and gated on a connection string precisely so an ordinary `cargo test` can never
  reach a VM. So this belongs beside the existing `live_kernel` tests, run by hand.
- **What it should assert:** save a byte with an `eval`+`capture`, patch it, fail an assertion
  deliberately, and confirm from a *later, separate* call that the `always` block put the original
  back — the point being that nothing after the batch had to be sent for that to happen. Then the
  same batch with the call budget shortened (`WINDBG_MCP_CALL_TIMEOUT_SECS`) below the batch's own
  deadline, to check the clamp in `worker::batch_budget` really keeps the report ahead of the
  caller's timeout on a target where steps take real time.
- **And now the teardown paths too** (item 18, landed): patch a byte, disconnect mid-batch, and
  read the byte back over a *fresh* attach — the dump tier proves the rollback ran by the file it
  wrote, which is the shape of the claim but not the substance of it. Same again for `end_session`
  arriving mid-batch, where the batch's own `BATCH: ABANDONED` report comes back to the client.
- **Where it picks up:** `tests/mcp_smoke.rs`, the `live_kernel` filter; the harness for setting and
  reading back a byte already exists in the MessageManager tier.

## 17. [windbg-mcp] Let a `debug_batch` step call a typed tool, starting with the pool queries

The one gap the MessageManager transcript found in `debug_batch` (#82). Its step vocabulary reaches
anything that is a *debugger command*, which is almost every typed tool in this server — but not the
ones that are not commands at all. The pool tools are win-kexp walks over the allocator's own
structures, so `pool_find_tag`, `pool_chunk` and `pool_census` have no `execute` equivalent to fall
back on.

- **How much it cost the workflow it is measured against:** 9 of 1,681 steps (`@chunkt1`, `@census`,
  `@find`, `@findr`). Small, but not incidental — `@chunkt1` sat *inside* the 32-step transaction,
  between a code patch and its restore, so a batch expressing that sequence today has to drop it.
- **Why deferred:** the shape is a design question, not a missing wire. `PoolOp` already crosses to
  the worker and `worker::pool` already renders it, so the plumbing is short; what needs deciding is
  whether a step names a *tool* generically (open-ended, and every tool's arguments then have to
  exist in the batch schema twice) or whether the batch grows one variant per typed tool worth
  having in a transaction. The second is smaller and matches how `StepAction` is already justified —
  variants exist for what a raw command cannot express — but it is a list that will keep growing.
- **Where it picks up:** `StepAction` in `src/batch.rs`, `PoolOp` in `src/proto.rs`, and
  `batch::Debuggee`, which would gain one method per capability so the executor stays engine-free.
  `@chunkt1`'s real shape is the test case: capture a register with `eval`, then ask `pool_chunk`
  about `{{that}}` — the capture half already works.

## 18. [windbg-mcp] Let a running batch finish its rollback when the client disconnects — **done**

`debug_batch` (#82) made one guarantee totally and a weaker version of it partially. Against a call
**timeout** the rollback is safe by construction: the batch budget is clamped to the caller's
remaining patience, so `always` has run and the report has been written before the wait expires.
Against a **teardown** it was not. `Sessions::shutdown` treats a disconnect as `end_session` on every
session; the `EndSession` op queues behind the batch, `release` waits `SHUTDOWN_RELEASE_TIMEOUT`
(5s), and then the worker was killed — mid-transaction, with the patch still applied. `end_session`
itself was the same shape with a longer number on it.

Landed (2026-08-10) as the *signal* this item proposed rather than a longer wait, and it needed less
than item 7 to build: a worker busy in DbgEng **is** draining its request queue, because the reader
lives on the main thread and only hands work to the engine thread. So the reader acts on the
teardown's own `EndSession` where it reads it, before queueing it for an engine thread that is by
definition busy. It sets a flag `batch::run` checks between steps; the batch stops there, runs
`always`, and reports `BATCH: ABANDONED`.

What made the wait conditional without the supervisor tracking op identity: the worker answers with
`WorkerMessage::RollingBack { within_ms }` — a milestone, so it arrives while the teardown is still
waiting on that same op's reply — and the wait extends itself by that figure once its ordinary grace
runs out. `within_ms` is the batch's own remaining budget, so it covers the step in flight as well
as the rollback; sizing it from the reserve instead (the first cut, caught in review) expires inside
a long step and terminates the worker mid-patch, which is the same failure one step later.

Carrying the signal on the release rather than on an op of its own was also review's doing, and for
a sharper reason: telling a batch to stop is sticky and one-way, so it must not be possible for a
teardown that does not happen. Two separately gated requests can come apart — a target-changing call
between them retires the session, the release is refused as stale, and the abandon has already
aborted a transaction and left a flag no later batch could get past on a session that survives. On
one request the property is structural: a gate refusal stops it before the worker sees it, and every
request the worker does see is followed by that worker being terminated. An ordinary disconnect is untouched, and not
merely by arithmetic: the signal is skipped entirely when the worker owes no reply. A batch reaching
the engine *after* the signal does not start, which is the same "nothing ran, resubmitting is safe"
answer as an unaffordable budget, and the worker's own EOF path sets the flag too, so a supervisor
killed outright still gets the rollback rather than a truncated transaction.

- **What is still true, and now documented as the whole of the boundary:** no signal *shortens* a
  step already inside DbgEng, so a batch stops at its *next* step. The teardown waits that step out
  rather than cutting it off, so the cost is latency rather than a lost rollback — but a step that
  outlives its own watchdog is still terminated mid-transaction. Shortening it is item 7
  (`SetInterrupt` bound to job identity), and that is the only part of this that needs it.
- **Proof:** `src/batch.rs` unit-tests the executor's two new behaviours (stop and roll back; and
  the rollback keeping the same budget every other path gets, whichever step the signal landed in),
  `src/worker.rs` pins the pairing that makes "a batch runs while the teardown thinks nothing is
  running" unreachable and the remaining-budget figure the grace is sized from, and the dump tier
  drives both teardowns end to end — the disconnect one asserting against a file the rollback wrote,
  because by then there is no client, supervisor or worker left to ask.
