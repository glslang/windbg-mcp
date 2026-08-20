# Follow-ups

Deferred work, in twelve clusters: items 1–6 come from the reachability-confirmation effort (path
recipe + `run_to_address`, merged 2026-07-04), items 7–11 from surveying this server against the
MCP `2026-07-28` extensions (tasks, apps), item 12 from the opener split
(glslang/win-kexp#71, 2026-08-01), items 13–14 from the bounded-command coverage review
(#46, 2026-08-02), item 15 from the private worker channel (#65 / #72, 2026-08-04), items 16–18
from transactional batches (#82, 2026-08-09/10 — item 17 is what validating the tool against the CTF
session's own transcript turned up, and item 18 what reviewing it did), item 19 from
`walk_memory` (#103, 2026-08-13), items 20–22 from standing the server up on an ARM64 guest
(#131, #132, #134, 2026-08-16), item 23 from making the listener usable rather than merely
working (2026-08-17), item 24 from first measuring what this server costs the model driving it
(2026-08-17), items 25–26 from giving the debugger tier an ARM64 *target* (#143, #152,
2026-08-18), item 27 from completing the coordinate work (#156–#158, 2026-08-18), items 28–29
from giving each client its own sessions (#162, #164–#166, 2026-08-19), and item 30 from serving
the stateless revision concurrently (#168 / #169, 2026-08-19). Each item notes its repo,
why it was deferred, and where it picks up. See [`DECISIONS.md`](./DECISIONS.md) for the design rationale (D1–D5) items 1–6 extend,
and the 2026-08-02 entries that items 13–14 and item 10 extend.

Items are roughly ordered by how soon they're worth doing, within each cluster. **Item 10 has
landed** (process-per-session, 2026-08-02); it is kept here rather than deleted because items 8 and
9 were both written against the single-engine design it replaced, and each now says what moved.
**Items 16, 17 and 18 have landed** (2026-08-10) and are kept for the opposite reason: each turned
out to need something its entry did not anticipate — item 18 needed much less of item 7 than it
claimed to, item 17 needed a walk deadline nothing had asked for, and item 16 needed a probe before
it could measure anything at all. **Items 20 and 22 have landed** (2026-08-16, #131 and #134) and are kept because each needed
something its entry did not see — item 22's job rename silently removed a required status check.
Item 20's fix needed something the entry did not see: the two installers spell x64 differently, so the reordering it proposed would have
picked the wrong architecture by another route. **Item 7 has landed** too (2026-08-10, the
`interrupt` tool), and
is kept because item 8 rests on it: what it built is the job binding, and what it deliberately did
not build is the queued-job half that only `tasks/cancel` can ask for. **Item 12 has landed**
(2026-08-02) and is kept because what validating it *disproved* outlives what it confirmed: a kernel
attach whose target never dials in has no bound at all, which is the constraint item 10 contains.

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

## 7. [win-kexp + windbg-mcp] On-demand engine interrupt — **done** (2026-08-10)

Expose `SetInterrupt` as a public win-kexp method (and a `Send` handle obtainable from a
`&DebugEngine`), then plumb it through to a per-session `interrupt()`. The primitive existed but was
only ever *timeout-driven*: `execute_command_bounded` and `wait_for_event_bounded` each spawn a
watchdog thread holding an `InterruptHandle` and Ctrl+Break the engine when a deadline passes, and
no caller could ask for the same.

`InterruptHandle` already carried the reasoning: `SetInterrupt` is the one DbgEng call documented as
safe from another thread, so this needed no new threading model — the engine stays confined to its
one thread (`src/worker.rs`) and the interrupt arrives from outside it, exactly as it always did.

**Reshaped by item 10, half-built by item 18.** The interrupt is a *per-session* concern: it has to
reach one worker's engine, and it cannot travel as an ordinary op, because it would be read only
once the operation it means to stop had ended. Item 18 built that half — `worker::run`'s reader acts
on a request where it reads it — and settled the channel question: no side channel was needed,
because the reader was never blocked.

Landed as the `interrupt` tool. What each half turned out to be:

- **win-kexp:** `InterruptHandle` is public, `Send + Sync`, and holds an owned `IDebugControl4`
  rather than a borrowed pointer — a handle a host can keep would otherwise dangle past the engine
  it came from. Both watchdogs now go through it, which is what makes the second part work: the
  handle and the engine share a `raised` flag, so `execute_command_bounded` can tell an aborted
  `Execute` from a failed one **without being the thread that asked**. Without that, an interrupt on
  request came back as `CommandFailed` and threw away every line the command had produced — most of
  what an interrupted search is worth. No note is appended for a requested interrupt, unlike the
  watchdog's: that one explains a deadline nobody saw pass, whereas this caller is the one who
  asked.
- **windbg-mcp:** the reader answers `EngineOp::Interrupt` outright and never queues it. Job
  identity is a `Running { job, interrupted }` under one lock: the reader reads the running job and
  raises under it, the engine thread claims and releases under it, so an interrupt reaches the job
  that was running when it arrived or nothing at all. The job it reached **spends** it — a pending
  break is drained before the next job starts, and only that caller's reply is marked cut short.

- **Why it came first:** it is what would give item 8's `tasks/cancel` anything to do — the spec's
  cancellation is cooperative, so acknowledging one conforms, but a session blocked inside DbgEng
  cannot act on it at all *without being thrown away*. It stands alone too, which is how it shipped:
  an operator can abort a runaway `execute` before `ENGINE_CALL_TIMEOUT` (`src/main.rs`, 300s)
  elapses, keeping the target that `end_session` would discard.
- **A bare `interrupt()` would hit the wrong job**, and this is the part that needed designing
  rather than plumbing. `SetInterrupt` addresses one engine, meaning whichever operation that
  session is *currently running* — so raised a moment late it Ctrl+Breaks whatever started next.
  Today that is a race against a job boundary; under item 8, with several calls in flight as the
  normal case, it is the ordinary outcome of cancelling a task whose job is still queued. The lock
  above closes the race and is the foundation the queued case needs: `tasks/cancel` for a job that
  has not started should drop it from the queue rather than raise anything, and that is a *second*
  variant of this request (one naming a job id) rather than a change to what landed. It is not
  built, because nothing can name a job id yet — a tool call names a session.
- **Known limit, unchanged:** `SetInterrupt` cannot unblock a live-kernel wait until the target is
  *connected*. So the `attach_kernel` KDNET park documented in `CLAUDE.md` — the case that most
  wants cancelling — is not cancellable this way; only tearing down the process ends it, which
  item 10 made an in-band operation (`end_session`). The tool says so rather than reporting a
  success that does nothing.
- **Proof:** win-kexp's `test_command_interrupted_on_request_keeps_its_output` (live, `#[ignore]`d)
  holds the partial-output-as-`Ok` claim the shared flag exists for; `src/worker.rs` unit-tests the
  binding against a local `Running` (both orderings of the race, staged — which against the real
  one would mean interrupting an engine at an exact instant); and `tests/mcp_smoke.rs`'s
  `a_running_command_is_interrupted_on_request_and_frees_its_session` drives the whole thing through
  the shipped binary, which is the only place both halves exist. That last one is in the ordinary
  dump tier rather than the ignored one: the interrupt lands in milliseconds, so nothing waits out a
  deadline — measured at 203ms against a `.for` sized to run for hours.

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
3. `go` / `run_to_address` / `execute` — these were held for item 7, which has landed. `tasks/cancel`
   is *cooperative* by spec, so they were implementable without an interrupt; what they lacked was
   any way to make an effort short of ending the session outright, since for exactly these three the
   engine is blocked inside DbgEng. Now a cancel for the *running* job can raise the interrupt item 7
   built, and the job returns what it reached. A cancel for a job still **queued** is the half item 7
   did not build, and this is what would ask for it: drop it from the queue and answer its waiter,
   rather than raise anything — a bare interrupt would Ctrl+Break the unrelated job that is actually
   running. It needs a second request variant naming a job id, and the lock item 7 put in is what
   makes both safe together.

Fast, pure tools (`decode_ioctl`, `registers`, `read_memory`, `modules`, `threads`, `disassemble`,
`backtrace`, `session_status`) should stay synchronous.

- **Three things to get right, not plumbing:**
  - **TTL must not re-introduce the lie.** `DEFAULT_TASK_TTL_MS` is 5 minutes and expiry marks a task
    `failed`; a kernel attach waits indefinitely by design. Attaches need `ttl_ms: None`, or the task
    reports a failure while the attach is still genuinely pending — the exact false report the
    conversion was meant to remove.
  - **An `attach_kernel` task must not report `cancelled`.** Item 7's interrupt does not unblock a
    KDNET wait before the target connects — `SetInterrupt` cannot reach it — so a cancel cannot end
    that job — and the job is not
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
- **Since done, for a different set of tools** ([#84](https://github.com/glslang/windbg-mcp/issues/84),
  DECISIONS 2026-08-12): sessions, execution control, registers, modules, breakpoints and the pool
  answers now carry both channels. The three outputs named above are *not* among them and are still
  text — they are the ones whose structure is a graph or a tree rather than a record, which is the
  same reason they were the candidates for Apps. The plumbing they would need now exists
  (`src/structured.rs`, `proto::Output`), so the remaining work is their shapes, not the seam.

## 12. [win-kexp] Validate the opener split against a live KDNET target — **done** (2026-08-02)

The split that made per-opener handle commits possible (glslang/win-kexp#71) was validated on
user-mode targets only — split launch, fused launch, split attach, via `examples/split_open.rs`.
The two **kernel** halves ran on no hardware: `attach_local_kernel_begin`/`wait` and
`attach_kernel_begin`/`wait`.

`attach_kernel_begin`/`wait` then ran against a Windows Server 26100 guest over KDNET, from the
harness added in win-kexp#77 (`examples/kdtest.rs` now drives the split path beside the fused one),
and passes on both counts. `attach_local_kernel_begin` shares `wait_for_kernel_break_in` and differs
only in its begin half; on a host with local KD off it can exercise nothing but that half's
`E_NOTIMPL`, which is not evidence about the wait.

- **The connection string outlives the seam.** `AttachKernel` returned in **28.5ms** with the link
  demonstrably not up, and the link came up **5.7s later, inside `wait()`** — on the far side of the
  seam — after which `vertarget` read a real machine. Stated as precisely as the item was written:
  this proves the parking is correct, not that the engine reads the string late. Had the buffer been
  freed at the end of `attach_kernel_begin` the attach would very likely still have *appeared* to
  work, freed memory usually retaining its contents — which is why holding it was the right call
  rather than something a test could have argued for.
- **The bookkeeping runs on the `wait()` side.** `go` stopped at `Breakpoint 0 hit`. That is the
  discriminator: an `INITIAL_BREAK` left armed, or its spurious re-break left unabsorbed, stops the
  target at `nt!DbgBreakPointWithStatus` and never reaches the breakpoint.

**The third thing this item asked for does not exist, and finding that out is what it was worth.**
It wanted "a deliberate timeout against an unreachable target". Dialing a dead port returned from
`AttachKernel` in 7.9ms and then blocked past **300s** — five times the 60s `KERNEL_ATTACH_WAIT_MS`
— before the run was killed, and the same VM booted *without* `bcdedit /debug on` did the same at
0.7s of CPU, parked in the transport rather than spinning. The watchdog is `SetInterrupt`, which
only reaches a wait whose target has **connected**, so the bound covers a connected-but-unresponsive
guest and nothing else. `KernelBreakTimeout` is reachable only from a target that connects and
*then* fails to break in — wedged, or spinning at high IRQL — and stays unexercised. It is also
three lines the split did not touch (`wait_for_kernel_break_in` is byte-identical; only its call
site moved), which is why win-kexp#73 closed without it.

What that leaves this repo is not a test but a constraint, and it is the one item 10 exists for: the
most common kernel-debugging mistake there is — a guest not booted with `/debug on` — blocks the
attaching thread with **no bound at all**, and no in-process mitigation is possible, because the
inability to cancel is DbgEng's. A caller that must stay responsive needs a process it can abandon.
This server has one: the attach parks a *worker*, `session_status` reports how long it has waited,
and `end_session` terminates it — covered end to end by the live smoke tier (a kernel attach parked
on a dead port, reclaimed by `end_session`). win-kexp now documents the bound's real reach on
`attach_kernel` itself ("Blocks indefinitely if the target never connects", `src/dbgeng.rs`), so the
next caller does not have to measure it again.

- **Tracked as:** [glslang/win-kexp#73](https://github.com/glslang/win-kexp/issues/73) — closed
  2026-08-14.

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

## 16. [windbg-mcp] Exercise a *mutating* `debug_batch` against a live kernel target — **done**

`debug_batch` (#82) was proved at two altitudes: `src/batch.rs` drives the executor over a scripted
debuggee with a virtual clock (assertion failure, a command failure after a mutation, deadline
expiry, a rollback that itself fails), and the debugger tier drives a real engine to both outcomes
over the wire. Neither covered the case the tool was built for — a **write that is then restored**
on a target that would notice.

Landed (2026-08-10) as five tests in the `live_kernel` filter of `tests/mcp_smoke.rs`: a failing
batch whose `always` block restores a patched byte (confirmed by a *later, separate* call, so
nothing after the batch had to be sent for it to happen); the same under a
`WINDBG_MCP_CALL_TIMEOUT_SECS` shorter than the batch's own deadline, where the clamp in
`worker::batch_budget` is what keeps the report ahead of the caller; a disconnect mid-batch, read
back by a **new server process** over a fresh attach; an `end_session` mid-batch, where the client is
still there to receive `BATCH: ABANDONED` *and* a second attach agrees about the byte; and a pool
step inside a batch (item 17).

Two things the writing of it settled, both worth keeping:

- **What to patch.** `nt`'s DOS-header `e_res2` field (`nt+0x28`) — reserved by the format, read by
  nothing at runtime, and stable across a detach and re-attach, which the teardown tests need and a
  stack address could not give. Anything with a *purpose* satisfies the first two conditions and
  bugchecks the guest on the third.
- **The probe is not optional.** A guest with memory integrity (HVCI) enabled accepts a debugger
  write to an image page and silently drops it, so every one of these tests reads, writes, reads
  back and restores the byte *before* it opens a transaction. Without that, a rollback that did
  nothing and a patch that never landed are the same green tick.

## 17. [windbg-mcp] Let a `debug_batch` step call a typed tool, starting with the pool queries — **done**

The one gap the MessageManager transcript found in `debug_batch` (#82). Its step vocabulary reaches
anything that is a *debugger command*, which is almost every typed tool in this server — but not the
ones that are not commands at all. The pool tools are win-kexp walks over the allocator's own
structures, so `pool_find_tag`, `pool_chunk` and `pool_census` had no `execute` equivalent to fall
back on. It cost the workflow this is measured against 9 of 1,681 steps (`@chunkt1`, `@census`,
`@find`, `@findr`) — small, but not incidental: `@chunkt1` sat *inside* the 32-step transaction,
between a code patch and its restore.

Landed (2026-08-10) as **one `StepAction` variant per question** — `pool_chunk`, `pool_find_tag`,
`pool_census` — rather than a generic "call a tool" step, for the reason this item guessed at: the
generic form would have every tool's arguments living in the batch schema twice. `pool_diagnostics`
is deliberately not among them; it explains a *walk* rather than the target, and belongs to the
interactive look that follows a batch. `batch::Debuggee` gained one method, `pool`, so the executor
stays engine-free, and the defaults and caps moved onto `PoolOp` constructors in `src/proto.rs` so a
step and a tool cannot drift apart on what `limit` means.

The design question the item did *not* anticipate, and the part worth remembering: **a walk needs a
deadline from the batch.** win-kexp bounds a walk at `DEFAULT_WALK_BUDGET` (120s), which is longer
than an ordinary batch's whole budget — so a `refresh` step taking that default could spend the
reserve the rollback lives on and overrun the bound the worker advertises to a teardown (item 18),
which is a worker terminated mid-transaction. `PoolWalk::within` already existed for exactly this
("a host that knows its own deadline should pass that instead of taking this"), so a pool step now
passes its own step budget and a walk cut short reports its coverage as it always did. The pool
*tools* took the default until [#75](https://github.com/glslang/windbg-mcp/issues/75) gave them the
call's patience on the same arithmetic (2026-08-10); `None` — the walker's own default — is now
reachable from neither caller, which is right, because neither is a human at a prompt who could
Ctrl+C a walk that ran long.

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
runs out. `within_ms` is the batch's own remaining budget plus the overrun its executor is allowed,
so it covers the step in flight as well as the rollback; sizing it from the reserve instead (the
first cut, caught in review) expires inside a long step and terminates the worker mid-patch, which
is the same failure one step later. The wait re-reads it rather than committing once, because a
batch that finishes early hands the rest back and keeps only what the release still needs.

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
- **Proof:** `src/batch.rs` unit-tests the executor's two new behaviours (stop and roll back, and
  the rollback keeping the same budget every other path gets, whichever step the signal landed in),
  `src/worker.rs` pins the pairing that makes "a batch runs while the teardown thinks nothing is
  running" unreachable and the remaining-budget figure the grace is sized from, and the dump tier
  drives both teardowns end to end — the disconnect one asserting against a file the rollback wrote,
  because by then there is no client, supervisor or worker left to ask.

## 19. [windbg-mcp] Let a `debug_batch` step walk a structure

`walk_memory` (#103) is a supervisor-validated op like the pool queries, and item 17 already built
the machinery a batch needs to call one: a `StepAction` variant, a `Debuggee` method, and a
rendering the step's `expect` checks can match on. It was left out because the two tools answer
different questions — a batch exists so that a *mutation* is undone on every path, and a walk
mutates nothing.

Where it would earn its place is the assertion half. A batch that patches a driver's dispatch table
and has to prove it put every entry back currently asserts on `execute` text, which is exactly the
all-or-nothing read this issue removed everywhere else: one unreadable entry and the assertion fails
for a reason that has nothing to do with the restore. A `walk` step whose `expect` matched on the
rendered table would state the postcondition as what it is — "these sixteen pointers are these
sixteen values" — instead of on a command that may not survive being asked.

Picks up at `batch::StepAction` (the variant and its `owns` keys), `batch::Debuggee::walk`
alongside `pool`, and `worker::walk_memory`, which already returns the text a check would run
against. The one design question is the budget: a walk step is up to 1024 reads inside a
transaction whose whole point is that its rollback still fits, so the step's share has to come out
of the batch's deadline the way `pool`'s does rather than out of the call's.

## 20. [windbg-mcp] Pick the TTD recorder by architecture, not by a fixed list — **done** (2026-08-16, #131)

`find_ttd` probed x64 before arm64 in both layouts it knows — `["x64", "arm64"]` for the classic
SDK, and a list headed by `amd64\TTD\TTD.exe` for the MSIX package. On an ARM64 host that was
always the wrong answer, because the ARM64 WinDbg package ships **all three** recorders (`amd64`,
`arm64`, `x86`) and the first probe therefore always hit. `record_trace` picked the x64 recorder on
exactly the hosts where the choice is not free, and a native ARM64 target cannot be recorded with
it.

Found while setting up a Parallels ARM64 guest for [`docs/remote-phase0.md`](./docs/remote-phase0.md).

**Resolved as the first cut this entry described**, and the deferral reasoning stands: the probe
order now leads with *this build's* architecture and keeps the others behind it, because it is an
ordering and not a filter — an emulated x64 debuggee on an ARM64 host genuinely wants the `amd64`
recorder. The target's architecture is still the correct selector and still unavailable here:
`record_trace` receives a command line, and resolving that to a file to read a PE header from is a
separate problem with its own failure modes. `PATH` is searched first and overrides all of it, which
is now documented at the point of the guess rather than only in the issue.

**What the entry did not anticipate** is the reason it is kept rather than deleted. The two
installers disagree about one spelling — the SDK ships `Debuggers\x64` where the store package's
payload directory is `amd64` — so reordering the string lists, which is what this entry describes,
would have selected the wrong architecture by a different route. That is the same class of mistake
as the ordering itself, and it is why the fix introduced an `Arch` type with the two names as
separate accessors instead of reordering literals.

Two smaller things it also turned out to need: the bare `TTD\TTD.exe` layout moved from second to
last, since a package has either an architecture-specific tree or that one; and the ordering is
covered by unit tests rather than a live probe, because the ARM64 host it was found on no longer has
a TTD in either layout — its recorder is the `PATH` copy, which is the workaround this removes the
need for.

## 21. [windbg-mcp] TTD replay on a host where the store package will not install

`open_trace` needs the replay engine — `TTDReplay*.dll`, `TtdExt.dll`, `TTDAnalyze.dll` — in a
`ttd\` directory beside `windbg-mcp.exe`. System32's `dbgeng.dll` ships none of it and rejects every
trace with `0x80070057`, so there is no degraded mode: replay either has the files or does not
happen.

Two things compound to make that unreachable on some hosts. The **SDK Debugging Tools do not ship
`ttd\`** (nor `msdia140.dll`), so the one source that installs cleanly from a command line supplies
everything *except* replay. And **MSIX registration fails from a non-interactive session** —
`Add-AppxPackage` returns `0x80070005` even when elevated — staging the payload into
`WindowsApps` without registering it, where the ACLs then deny execute. The result is a host that
records traces and cannot replay them.

Deferred because the two halves that could be done cheaply already have been, and what is left is a
judgement call rather than a task. `open_trace` now says *why* a trace will not open instead of
surfacing `0x80070057`, and `setup.md` carries a recipe for unpacking `ttd\` from the
`.msixbundle`, which is an ordinary zip. So the failure is legible and there is a way through it.

What is undecided is whether unpacking a Microsoft package by hand should be a **supported** path
in this project's own documentation — it is currently written down as a fallback, not endorsed — or
whether the answer is to require an interactive install and say so plainly. That is a maintainer's
call about what this repo is willing to tell people to do, not an engineering problem.

Picks up at [`setup.md`](./skills/windbg-debugging/setup.md)'s *When the store package will not
install*, and [#132](https://github.com/glslang/windbg-mcp/issues/132).

## 22. [windbg-mcp] Run the debugger tier on an ARM64 runner — **done** (2026-08-16, #134)

Both CI jobs that touch a debugger were `runs-on: windows-latest`, which is x64, while `setup.md`
told readers an ARM64 engine reads an **x64** kernel minidump in full — a claim resting on one
manual session. The debugger tier now runs on both, and only that tier: the crate is
architecture-independent Rust, so `fmt`, clippy and the unit tests have no reason to differ, and
what differs on ARM64 is the engine.

The `Swatinem/rust-cache` key carries the architecture, as this entry said it would have to.

**Two things it did not anticipate, which is why it is kept.**

The first is the reason the entry existed and still cost a correction: the ARM64 run **failed on its
first attempt**, four assertions of forty-five, and the claim in `setup.md` was wrong. The engine
parses the dump — bug check, module list, stack attribution — and cannot read *virtual memory* out
of it, so `walk_memory`, `disassemble` and the `EPROCESS` behind `crash_triage`'s `process_name` all
fail ([#142](https://github.com/glslang/windbg-mcp/issues/142)). Those four were gated to `x86_64`,
because the constraint was taken to belong to the **sample**: the checked-in dump is x64, and on
another architecture they were thought to have nothing to assert.

**That diagnosis was wrong, and the correction is the more useful half of this entry** (2026-08-17,
while capturing the ARM64 dump for [#143](https://github.com/glslang/windbg-mcp/issues/143)). The
architectures are not the variable — **symbols** are. A kernel dump's virtual addresses are
translated through structures the engine locates with `nt`'s symbols, so a host that resolves none
reads the dump's headers and nothing behind them. On an ARM64 host with the SDK's `dbghelp.dll` and
`symsrv.dll` beside the binary, one engine reads the x64 samples *and* an ARM64 one completely —
including the `EPROCESS` and the driver frame at its literal RVA; strip the symbol path from that
same engine and it reads neither. System32 ships `dbghelp.dll` and no `symsrv.dll`, which is why a
runner with nothing beside the binary downloads no PDB and fails these four. The tests now ask the
host — `nt`'s base reading, and a resolved PDB for the two that walk its types — rather than
asking `cfg!(target_arch)`, and
the ARM64 dump is checked in for the coverage it genuinely adds: an ARM64 *target*, which nothing
else here reads. **Both halves of that question, because they fail apart**, which the ARM64 CI
entry demonstrated on the first attempt: a gate that asked only for the read let the driver-crash
test through on a runner that reads a module base and resolves nothing, where it walked a stack
made of the bug check's own parameters and failed an attribution assertion for an environmental
reason.

The second is a trap with nothing to do with architecture. **Renaming the job removed a required
status check.** `Smoke test (debugger tier)` is a required context in the repository ruleset,
matched by name — so adding `, ${{ matrix.arch }}` did not rename the requirement, it deleted the
only job that could satisfy it, and every PR in the repo would have blocked on a check that can
never report again. It surfaced as a PR that was `MERGEABLE` but `BLOCKED` with nothing failing that
was required. The x64 entry now keeps the original name exactly, so adding a matrix is not a rename.
Worth knowing before touching any job name in this repository, not just this one.

## 23. [windbg-mcp] The listener is transport-complete, not usable-complete — **done** (2026-08-17)

All of it is **done** (2026-08-17): `server_log` reaches a client on any machine with
the records *both* processes made — bounded, and saying so when a record was dropped or evicted
rather than leaving a gap to be read as quiet ([`DECISIONS.md`](./DECISIONS.md) records why it is a
tool rather than MCP's deprecated logging capability); the lease has a **smoke tier** — four
assertions in the protocol tier and one, against a parked kernel attach, in the debugger tier; a
long call reports **progress**; and the listener installs as a **Windows service**.

**Progress notifications — done** (`src/progress.rs`). The milestones were already protocol
messages, so what was added is the route out: a `progressToken` read off the call's `_meta` in
`call_tool`, a task-local sink read on the caller's task and left beside that call's waiter — the
milestones arrive on the session's reader task, where the peer and the token are out of reach — and
a relay that turns each step into `notifications/progress`. Two things it settled that this entry
did not anticipate. `progress` counts **seconds elapsed with no `total`**, because a denominator
would have to be a per-tool budget that in an opener's case does not even cover the 30s worker
handshake before it starts. And the milestones alone would have left the two longest silences
exactly as they were — a parked attach reports `Committed` in the first second and may never report
again, and a pool walk or a `crash_triage` has no milestones at all — so **ten seconds without a
word is itself reported**, which incidentally makes progress a liveness signal a client can extend
its own request timeout on.

**Service installation — done** (`src/service.rs`). `--install-service --listen <addr>` registers
the listener with the SCM as `windbg-mcp`, auto-start, `LocalSystem`; `--uninstall-service` stops it
and removes it. Three things it turned up that the entry did not anticipate.

The **stop** is the whole of the difficulty, and it is why `listen::serve` grew a shutdown future:
nothing else in this server needs one — under stdio the disconnect *is* the signal, and a foreground
listener has nobody to ask it — but a service that is killed rather than asked leaves a
detached-but-halted kernel frozen. The SCM is told `StopPending` with a wait hint sized from what
releasing every worker can actually take, rather than being left on the default.

`LocalSystem` **does not read your `profiles.json`** — its `%USERPROFILE%` is
`C:\Windows\system32\config\systemprofile` — so kernel profiles have to be configured machine-wide
or the service sees none. Verified, not assumed, and `install` says so where an operator will read
it. The token is the same problem one scope out, and machine-scope is a real widening.

And a service has **no console**, so the role writes to `%ProgramData%\windbg-mcp\service.log`: the
`server_log` ring is the better channel, but it is only reachable once the listener is up, which is
exactly the case not worth diagnosing that way.

Verified end to end on the ARM64 bench: installed, started, served an authorised MCP call and
refused an unauthenticated one, **attached a live kernel and was then stopped** — the guest kept
running rather than freezing, and no worker outlived the service.

**What the smoke tier does not reach**, now that there is one: the grace is waited out at 32
seconds because the listener's own floor is the call budget plus `WORKER_READY_TIMEOUT`, and that
30s constant is not configurable — so the test costs 40s of wall clock to assert a timer. Lowering
it would mean making a production constant test-tunable, which is a worse trade than the 40s. Worth
revisiting only if that tier's runtime starts to matter.

Picks up at `src/listen.rs` and the tiers in `tests/mcp_smoke.rs`.

## 24. [windbg-mcp] Spend fewer of the caller's tokens

`docs/token-budget.md` and the two budget tests in `tests/mcp_smoke.rs` measured what this server
costs the model driving it. Nothing had, and the numbers were larger than a careful reading of the
source predicted — 90–130 KB estimated, 358 KB actual. This item is the list of things the
measurement found. None of them is a bug; all of them were invisible.

**Why deferred:** the baseline had to be recorded *before* anything was optimised for it, or every
later fix would be a diff against a number somebody had already tidied. The tests and the golden
landed on their own so that each of the items below can be argued, and measured, separately.

- **`$defs` are inlined per tool** — `schemars` emits each output schema self-contained, so
  `ErrorCategory` (2,089 B) ships 31 times and the allocator/pool subtree nine. **200,571 B, 70% of
  all `outputSchema`.** Wire and client-parse cost only; no model reads it. The lever is
  `output_schema = schema_for_output::<T>()` on each `#[rmcp::tool]`, or a `list_tools` that emits
  shared definitions.

  **This one has a price now** (2026-08-18): adding `PdbInfo`, one optional four-field type on one
  field of `ModuleInfo`, grew the wire by **15,610 B** and model context by **zero**, because
  `ModuleInfo` is embedded in the openers' summary, in `modules` and in the allocator shapes. That
  is the compounding this finding predicts, measured on a change small enough that nobody would
  have thought to look. `WIRE_CEILING` moved 412,000 → 460,000 to record it; the next such type
  costs the same again, and fixing this item is what stops that.
- **Six openers carry a byte-identical 11,093 B output schema**, six step tools a byte-identical
  4,418 B one. 77,555 B of the above, and the cheapest to collapse.
- **`session_id` was documented in three wordings** — **done**, and the figure in this bullet was
  wrong. It counted the copies inside `outputSchema`, which no model reads; the model-visible total
  was 4,695 B across 32 fields, not 9,514 across 43. One shared wording — plus documenting the five
  heap tools whose `session_id` had none at all — moved the surface **−537 B**. Review then found
  that all three original wordings described only the staleness guard and not the field's actual
  job, which is routing, so the corrected wording gives most of that back: a right description of
  two behaviours is not shorter than a wrong description of one. A number not measured in the
  channel it is claimed for is not a finding, which is worth remembering for the rest of this list.
- **The instructions overran what the client reads** — **done**. 3,147 chars sent against 2,048
  read, so the `debug_batch` paragraph — the one instruction that stops a mutation being left
  half-applied — was charged for on every connection and discarded. Now 1,990 chars with that
  guidance inside the budget, ASCII so characters and bytes cannot diverge, and asserted in the
  protocol tier.
- **`registers` returns 15.9x more JSON than its own text** (9,804 B vs 618 B), because every row
  carries `"kind":"int"` and `"subregister":false`. `modules` is 2.7x and is the largest single
  answer this server gives at 53,875 B. The ratio rule in `tool_results_stay_within_their_budget`
  stops this spreading; it does not fix these two.
- **Five tools are a third of the model-visible surface**, and it is their input schemas:
  `debug_batch` 9,746 B (7,980 of it the `StepAction`/`Check` vocabulary), `walk_memory` 4,076,
  `crash_triage` 2,912, `reachable_from_dispatch` 2,628, `server_log` 2,599 — 21,961 B against a
  median tool of 900 B. This is where the weight actually is, and unlike the items above it is not
  waste but one tool honestly describing a rich argument. The levers are design choices: a smaller
  step vocabulary, a `$ref` the client resolves, or a surface that does not offer every tool to
  every caller.
- **`modules` has neither a `limit` nor a cap**, alone among the high-volume tools. Everything else
  uncapped is raw debugger text — `ttd_calls`, `ttd_memory`, `threads`,
  `execute`, `dx`, `ioctl_trace`, `reachable_from_dispatch` — and `read_memory` returns up to
  ~4 MiB of hex by design (`src/worker.rs:117`). Every cap that does exist (`MAX_ROWS`,
  `MAX_NODES`, `MAX_READ_BYTES`) is justified in its own comment as a worker out-of-memory guard.
  A caller-context guard is a different constraint and does not exist yet.

**Where this bites first is a local model**, whose window is bought in RAM rather than rented:
[`docs/local-model.md`](./docs/local-model.md) is the runbook, and it names the three client-side
knobs the split-plane plan proposed — a tool-surface profile, a per-call response budget, a
text-or-data switch — none of which this server has. The two bullets above are the server-side half
of the same problem.

**Depends on nothing**, but it **collides with item 11**, which proposes adding `structuredContent`
to `ttd_calls`, `ttd_memory` and `driver_object` — three of the highest-volume text-only tools.
Under the client rule measured here, structured content *replaces* the text rather than
supplementing it, so that change is a size decision as much as a typing one, and it also partly
reverses the reasoning in `DECISIONS.md`'s #84 entry ("a second channel, not a replacement"), which
was argued against a Python client and never against a model one. Whichever is done first should
say what it means for the other.

Picks up at [`docs/token-budget.md`](./docs/token-budget.md) and the two budget tests in
`tests/mcp_smoke.rs`.

## 25. [windbg-mcp] The ARM64 CI runner resolves no symbols, so its target reads never run

Since #152 the debugger tier's target-reading assertions decide for themselves whether the host can
support them, and the two CI entries decide differently: on `windows-latest` all four run and pass,
on `windows-11-arm` all four print `SKIPPED`. Same code, same dumps. Windows ships `dbghelp.dll` in
System32 and **no `symsrv.dll`** outside the Debugging Tools, so a runner without them downloads no
PDB — and without `nt`'s symbols a kernel dump's pointers cannot be followed at all
([#142](https://github.com/glslang/windbg-mcp/issues/142)).

- **Why deferred:** the job's stated position is that it runs the runner's *stock* engine, on the
  reasoning that "a runner whose DbgEng cannot open a checked-in dump is something this repo wants
  to hear about". Provisioning symbols moves it away from what a bare machine gets — and toward
  what a user following this repo's own setup gets, since that setup copies the engine bundle
  beside the exe. That is a decision about what the job is *for*, not a fix.
- **What it costs today:** `docs/samples/121524-4703-01.dmp`, added so an ARM64 run reads an ARM64
  target, is exercised only on a bench with the engine bundle. CI proves the protocol and the
  session machinery there and nothing about reading.
- **Picks up at** [#153](https://github.com/glslang/windbg-mcp/issues/153), which lists the two
  probes (`dir` of the arm64 Debuggers directory, `where.exe symsrv.dll`) that would confirm this
  is an image difference rather than something this repo can fix in the workflow.

## 26. [windbg-mcp] No ARM64 driver crash, so frame attribution is asserted only on x64 stacks

`a_driver_crash_names_the_driver_frame_that_analyze_cannot` opens the x64 `MessageManager` dump on
every architecture. It passes there — an engine with symbols reads either dump either way round —
but the arithmetic that turns a captured frame into `module+RVA` off the load base has never been
run against an **ARM64** stack. #143 closed the other three assertions this way and left this one.

- **Why deferred:** it needs a crash to be produced rather than a sample to be found, and the two
  obvious candidates are already ruled out. The checked-in ARM64 sample and every one of its
  siblings on that bench are `0xFC` faults at a *user-mode payload* — HEVD's stack-overflow client
  with an incomplete ROP chain, so nothing disables privileged execution of a user page and the
  stack carries no `HEVD` frame at all. Completing that chain would remove the crash rather than
  reshape it.
- **What it needs:** an HEVD path that faults **inside** the driver (null dereference, pool
  corruption), plus a few lines of client to send that IOCTL — `hevd-exp` on the bench holds only
  the stack-overflow one. The driver itself loads again as of 2026-08-18 (`testsigning` on, its
  certificate in `LocalMachine\Root`; see `CLAUDE.md`).
- **One decision first:** `HEVD.pdb` ships beside the driver, so its frame *will* symbolize if that
  PDB is reachable — the opposite of the x64 assertion, which pins `symbol` absent because
  `MessageManager` has no PDB. Either keep the PDB off the path so both tests make one claim, or
  assert the symbolized form and let the pair cover both.
- **Picks up at** [#154](https://github.com/glslang/windbg-mcp/issues/154).

## 27. [windbg-mcp + win-kexp] A deferred module reports no PDB identity — **measured and declined** (2026-08-20)

`modules` carries `pdb` — the GUID, age and symbol-server `key` — only for a module whose symbols
the engine has **already resolved** (`symbols: pdb` or `dia`). On a freshly opened dump that is one
module out of two hundred: everything else is `deferred`, and a client that wants the right PDB for
a driver it has not touched yet cannot get the key from here.

That is the honest contract — the field reports the PDB this engine *has*, not the one that exists
— and it is documented that way in [`docs/coordinates.md`](./docs/coordinates.md). It is also not a
dead end today: the same identity lives in the image's own CodeView debug directory, so a client
that has fetched the image by `timestamp` + `size` can read it there, which is exactly how the
acceptance test did it before this field existed.

**What would close it** is reading the debug directory from the target rather than waiting for a
symbol load — the headers are mapped, and `.reload` finds the PDB that way itself. Two cautions the
work would have to respect. Headers in a *minidump* may not be present, so it has to degrade to the
current behaviour rather than fail. And the plan's rule stands: reading a header structure is not
"reconstructing an image from target memory", but the boundary is worth stating in the code, since
the next step past it is the thing that must never happen.

**Why deferred:** the acceptance test measured that this saves a download rather than enabling
anything, so it is a convenience whose cost — a per-module target read, on the tool that already
returns the largest answer this server gives — needs weighing against the convenience. Forcing a
symbol load to populate it would be strictly worse: that is a `.reload` per module, on a listing.

**Depends on nothing.** Picks up at `worker::with_pdb_identity` and
`win_kexp::DebugEngine::module_pdb`.

**Built and measured, 2026-08-20 — and declined.** The parse is small and was not the problem: ~60
lines reading the DOS stub, the optional header's data directories, the debug directory and the
`RSDS` record, unit-testable against a synthetic image without a debugger. Wired in as a fallback
for every module the engine has no PDB for, on the ARM64 kernel sample:

| | baseline | with the image fallback |
| --- | --- | --- |
| `modules`, model-visible | 53,897 B | **73,597 B** (+37%, over its 73,000 B budget) |
| `tool_results_stay_within_their_budget` | 1.31 s | **179.6 s** cold, **10.6 s** warm |

**The cold number is the finding.** Reading a header the dump did not capture makes the engine go
and *get the image* — from the image path, which on this host is a symbol server — so a listing of
two hundred modules becomes two hundred image downloads. Which means the field cannot save the
download it exists to save: on a minidump the answer is paid for with the very fetch a client would
otherwise do itself, only on the debugger host and with 60 bytes to show for it. Warm, it is still
8× the baseline, because each row is a symsrv cache hit.

Where it would be cheap is a target whose headers are already in memory — a live target, or a
full-memory dump — and that is also the case where the caller can just load symbols for the one
module they care about and read the engine's own answer.

So: not always-on (the numbers), not behind a `pdb: true` argument either (a knob whose honest
description is "this may download two hundred images" is a knob nobody can use safely), and not
behind a match-count threshold (an answer whose *content* varies with how many rows matched). The
contract in [`docs/coordinates.md`](./docs/coordinates.md) stands as written: this field reports the
PDB the engine **has**.

**What would change the answer** is a way to read a header without the engine paging the image in —
`SYMOPT_NO_IMAGE_SEARCH` would do it, but it is a global symbol option and setting it for one field
would change how every symbol on the target resolves. Worth revisiting only with a per-read way to
say "from the dump only".

## 28. [windbg-mcp] The tenancy gate no longer earned its place — **done** (2026-08-20)

The listener's **lease** was built when the registry was one map for the whole server: handles minted
from it, the cap shared, `end_session` ending whatever it was handed. Serving one client at a time
was the only thing standing between two clients and each other's targets, so the gate was
load-bearing.

Ownership took that job over ([#162](https://github.com/glslang/windbg-mcp/issues/162), merged
2026-08-19) — a handle routes only for its owner, the cap and the closed-session history are per
client, and an `Mcp-Session-Id` another client holds is reported unknown — which left the gate
arbitrating one credential racing *itself*: a second MCP session for one token, refused with a
`409`. **Inside a namespace that is not a boundary**, because both of that credential's MCP sessions
reach the same debug sessions. So the gate is gone, and what it cost is gone with it: a client that
lost its session id to a crash or a restart was told `409` and had to wait out the grace, where
adopting its own sessions was what it wanted and what ownership had made safe.

**Retired, with the clock kept.** The question this item asked was whether idle release
(`WINDBG_MCP_SESSION_IDLE_SECS`, #164) already covers the teardown the lease was kept for. It does
not, and the measurement is two lines of `Sessions`: `release_idle` skips a session with a call
outstanding — which is exactly the parked `attach_kernel` a vanished client leaves behind, since a
park is one call that never returns — and it knows nothing about MCP sessions, so an abandoned one
would stay resident in the service with its id accepted, one per reconnect cycle. `release_leased`
does both. So the lease stays as a **clock**: any request renews it, an expiry releases that
client's sessions and closes its MCP sessions, and the `releasing` refusal stays too, since it is
the sweep's and not the gate's.

**The lease is still armed by an MCP session**, so a `2026-07-28` client still has no clock —
deliberately, now that the credential could carry one. A lease releases everything that credential
holds, busy or not, on the reasoning that a client silent for a grace has gone; a stateless client is
legitimately silent for far longer than 390 seconds, and releasing a live kernel from under a caller
who is thinking is worse than holding an abandoned one for the idle window. `docs/remote-listener.md`
says so where it explains why both mechanisms exist.

**Both rules this item said the deletion must not take with it survived, one of them by becoming
unreachable.**

- An **admitted** request renews an existing deadline and never creates one. It is no longer a rule
  about stateless requests but the whole of what `admit` does, for every request shape — and both
  refusals still return before the renewal, so a stream of wrong session ids cannot hold an
  abandoned client's target open.
- A reservation that minted nothing had to give its **deadline** back. Nothing arms a deadline before
  a settled MCP session exists, so there is no clock for a request that takes nothing to hand back.
  The test that pinned it is now `nothing_arms_a_clock_before_an_mcp_session_exists`.

And the sweep's own safety turned out to be already enforced a layer below the machinery that was
protecting it: a sweep fires only after a whole grace with nothing admitted, and `Lease::new` refuses
a grace shorter than the longest a call can keep a client quiet — so no request of that credential's
can still be in flight when its lease expires. That is what the claim generations and in-flight
epochs were for, one level above the thing being protected, which is the pattern `DECISIONS.md`
already named for this code.

**What went:** `Tenancy` (now `Presence`), the reservation and `claims_issued`, `Admission::Occupied`
and its `409`, `Settled::Stale` and the minted session it had to close, `InFlight`/`leave`/`epoch`,
`farewell`/`try_give_up_for`, `Sessions::busy`, `Arriving`, `mints_no_session` and every read of
`MCP-Protocol-Version`. A credential's MCP sessions became a **set**, because an id recorded for
nobody is one any credential may present — tracking only the newest would have re-opened the hole
the ownership check closes. Ninety lease tests became twenty; the ones that went were about
sequencing a handover that no longer happens.

## 29. [windbg-mcp] The listener smoke tier only ever runs one, unnamed client — **done** (2026-08-20)

Every listener assertion in `tests/mcp_smoke.rs` starts the server with a single
`WINDBG_MCP_LISTEN_TOKEN`, so everything the tier proves is proved for the `local` client alone. The
per-client behaviour — routing, the unknown-handle answer, per-client capacity and history, the
per-client lease and the release that refuses only its own client, the session-id ownership check —
is covered by unit tests in `src/engine.rs`, `src/listen.rs` and `src/client.rs`, and by nothing end
to end.

The gap has already cost one bug: the adoption diagnostic counted `local`'s sessions for a named
client reconnecting, because the count was taken after the identity scope had closed. A unit test
pins the mechanism now, but the call site — an HTTP handler — is still unexercised.

**What would close it:** a tier that starts the listener with two tokens (`…_TOKEN_CI` beside the
unnamed one), opens a session as each, and asserts that neither can see, route to or end the
other's — including the `404` for a request bearing the other's `Mcp-Session-Id`, which is now the
only cross-client refusal there is; then walks one client through open → `DELETE` → reconnect-inside-the-grace and reads the
adoption line back out of `server_log`. All of it is dump-tier work — none of it needs a live
target.

**Why deferred:** the per-client rules are unit-tested at the level they are decided, so this buys
call-site coverage rather than new claims. Picks up at the listener helpers in `tests/mcp_smoke.rs`.

**What landed** (2026-08-20) is the tier this entry asked for —
`two_clients_on_one_listener_keep_their_sessions_to_themselves`: two tokens on one port, a dump open
as each, neither able to see, route to or end the other's, the `404` for a request bearing the
other's `Mcp-Session-Id`, and the adoption line read back out of `server_log` after an
open → `DELETE` → reconnect. **It was not call-site coverage. Its first assertion failed**: both
clients saw both sessions.

**The identity never reached a tool call.** `listen::gate` scopes the caller around
`mcp.handle(req)` — the HTTP task — while rmcp serves a legacy MCP session from a task it
`tokio::spawn`s at `initialize` (`spawn_session_worker`), and a task-local does not cross a spawn.
So every call ran as the default `local`, both clients' sessions were owned by `local`, and the
whole of [#162](https://github.com/glslang/windbg-mcp/issues/162) was correct machinery being handed
the wrong caller — in the transport it was written for. `WindbgServer` now carries the client it was
built for, captured in the listener's service factory (which does run inside the gate's scope) and
re-entered in `call_tool`.

**Worth keeping: "unit-tested where it is decided" is not coverage of the thing being decided.**
Each rule's test supplied the identity itself, so the one input that was wrong in production was the
one input no test ever provided. The reasoning that deferred this item — that it buys call-site
coverage rather than new claims — was sound and still wrong, because the call site was where the
input came from.

## 30. [windbg-mcp] Nothing covers a `2026-07-28` handshake that omits the protocol header — **done** (2026-08-20)

rmcp allows a stateless `initialize` to arrive without `MCP-Protocol-Version` — it is the request
that establishes the revision, so the header is optional on exactly that one. Nothing here drives
that shape: `Listener::stateless_opening` sends the header, and stdio has no headers to omit.

**The mechanism that made it a bug is gone**, which is most of what this item was for. The listener
used to classify a request by that header, so a headerless handshake was read as an *opener*,
reserved, minted nothing, and left its *deadline* armed — a client's own handshake starting a clock
that released whatever it had since opened, one grace later. Item 28 deleted the classification and
the reservation both: nothing arms a deadline before a settled MCP session exists, and the listener
does not read the header at all. What is left to cover is that rmcp serves the shape and that the
server behaves normally afterwards.

**What would close it:** a listener assertion that opens with a headerless `2026-07-28` handshake
and then works normally — a `tools/list` and a `tools/call`. Protocol-tier work, no target needed.

The half that would watch a session *survive the grace* after such a handshake is not: having a
session means an opener (`open_dump`), which means a real engine worker and therefore the **debugger
tier** — the same rule the parked test was moved for. It is also the half that no longer has a
mechanism to catch, so it is worth doing only if the arming rule ever grows a second arm.

**Why deferred:** it buys call-site coverage of a path whose hazard has been deleted rather than
handled. Picks up at the listener helpers in `tests/mcp_smoke.rs`, beside
`the_listener_serves_the_stateless_revision_it_negotiates`.

**What landed** (2026-08-20): `a_stateless_handshake_may_omit_the_protocol_header`, in the place
this entry named. The handshake is served, negotiates the revision out of its body, mints no
`Mcp-Session-Id`, and the `tools/list` and `tools/call` after it are ordinary. Nothing surprising,
which is what the entry predicted — item 28 deleted the mechanism that made this shape dangerous, so
what is pinned here is the shape and not the hazard. The half that would watch a session survive the
grace after such a handshake is still not done, for the reason above: it needs an opener, and so a
worker.

## 31. [windbg-mcp] A service-hosted listener can hold only one client — **done** (2026-08-20)

`Credentials::from_entries` treated a configured `WINDBG_MCP_LISTEN_TOKEN_FILE` as the **only**
credential, and read one token out of it: it loaded that token as `local` and returned, ignoring
every environment token including named ones. That precedence is deliberate and load-bearing — the service installer ACLs the file to
SYSTEM and Administrators precisely because the machine environment is readable by unprivileged
processes, and a variable standing beside it would let a stale or planted one authenticate to a
LocalSystem listener that has `launch` on it.

The consequence was that **the per-client work of [#162](https://github.com/glslang/windbg-mcp/issues/162)
was unreachable in the deployment `docs/remote-listener.md` recommends.** A foreground listener could
hold `local`, `ci` and `laptop`; the service could hold one client, so two agents on one
service-hosted host shared a namespace — which is exactly what ownership was built to stop.

It surfaced from the other end, in review of [#173](https://github.com/glslang/windbg-mcp/pull/173):
a local-model driver must not share a credential with the editor, because a client over the
four-session cap has its oldest idle session reclaimed, so the driver's `open_dump` can evict the
editor's target with nothing naming it. That driver now **requires** a credential of its own rather
than defending against sharing one — which is the right shape, and made this item the only thing
standing between it and the recommended deployment: under the service there was no second credential
to give it.

**What would close it:** a token file that can name more than one client. The obvious shape is the
same one `WINDBG_MCP_PROFILES` already uses for kernel profiles — a JSON object of name to token,
with a bare string still read as `local` so every existing install keeps working. The ACL story is
unchanged, since it is one file either way.

**Why it was deferred:** it is a file-format change to the one file that holds credentials, and it
wanted to land on its own rather than inside a runbook PR.

**What landed.** The obvious shape, as predicted: `client::TokenFile` reads either a **bare token**
— which names `local`, so every file written before this keeps working untouched — or a **JSON
object of client name to token**, the shape `WINDBG_MCP_PROFILES` already uses. A leading `{` is
what tells them apart, which makes "a bare token may not begin with `{`" a rule rather than a guess:
a file that does is refused at startup by name. The precedence is untouched — a configured file is
still the only credential — and `service::install` now copies **every** `WINDBG_MCP_LISTEN_TOKEN*`
variable in the installing shell, writing a bare token for a lone `local` and the object otherwise,
validated through the same `Credentials` the listener builds so a shell that could not start a
foreground listener cannot register a service.

Two things worth carrying:

- **The parse is the same problem `kdconn` solved for profiles, and gets the same answer**: values
  are walked as generic JSON rather than deserialized into a typed map, because serde's type errors
  quote the value they rejected — and every value in this file is a credential. `Credentials` and
  `TokenFile` grew hand-written `Debug`s that print names only, for the same reason `Connection`
  has one.
- **A name-shaped token is a name.** A charset check on client names catches a connection string or
  anything carrying a line break, but it cannot catch an entry written back to front, since a
  bearer token is a perfectly good client name — and that entry configures a client named after
  your token, which the startup line prints. That is not fixable in code; it is why the refusal
  that *is* detectable quotes nothing, and why `docs/remote-listener.md` says which way round the
  file goes.

Review found the two gaps that came of writing the file's rules as *the file's*. A name from the
environment was not held to the charset check, which an install then copies into the file — so a
variable the listener accepted could install cleanly and fail the service at every start; there is
one name rule now, wherever the credential was configured, and the environment is still not read at
all when a file is present. And a repeated key in the file was collapsed by `serde_json::Map` to the
last of the two, silently, which is the shape this module refuses everywhere else — so the object is
deserialized through a visitor that keeps every pair, and a name written twice is a refusal that
names the file. The third finding was the same shape from the writer's side — a token that happens
to begin with `{` cannot go in the file bare, because the reader takes a leading brace as the JSON
shape — and the fix is the general one: the installer asks the reader whether the bare form reads
back as what it meant, rather than restating the rule in a second place. Worth knowing that the
first version of *that* asked the wrong question — it checked the client's name, which a token that
is itself a one-entry object satisfies while carrying a different token — so the round trip is on
the whole credential: exactly one, and it is this token naming `local`. The last one was a *document*
— a JSON example with the file's path commented above it, which does not begin with `{` and is
therefore read as one token spanning four lines. The example lost its comment, and the parse now
refuses, from any source, a token that cannot travel in an `Authorization` header at all — a
listener that accepts one is a listener that accepts nobody.

One finding was taken as a fact rather than as its proposed remedy: a token file written by an
earlier install whose token *begins* with `{` — a braced GUID is the plausible way to have one —
now reads as the JSON shape and stops the service at its next start. The remedy offered was a
format marker or a fallback to the bare reading when the JSON does not parse; both are worse than
the problem. A marker is not unambiguous either, since a token can carry whatever marks the object,
and the fallback rescues that rare file by turning the likely one — a hand-written object with a
typo in it — into one long token that authenticates nobody and explains nothing. So the rule stands
and the refusal carries the way out (`{"local": "<that token>"}`), with the same note in the
changelog and a test pinning it.

**The lesson of the review rounds is one thing said three times.** A rule about a value was
*described* in the code — a name charset, then a line-break test — and each round found the next
character class it had not thought of. The two checks that stopped generating findings are the two
that ask the thing that will actually do the work: the installer asks the reader whether the file
shape round-trips, and `is_presentable` builds the header a client would send and reads it back the
way `authorised` does. Where a rule belongs to something else, deriving it beats restating it.

The end-to-end half is one protocol-tier smoke assertion
(`a_token_file_names_its_own_clients_and_shuts_the_environment_out`): a real listener, a real file
naming two clients, the environment token refused `401`, and both file clients served through a full
handshake.
