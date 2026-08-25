# Follow-ups

Deferred work, in twenty-three clusters: items 1–6 come from the reachability-confirmation effort (path
recipe + `run_to_address`, merged 2026-07-04), items 7–11 from surveying this server against the
MCP `2026-07-28` extensions (tasks, apps), item 12 from the opener split
(glslang/win-kexp#71, 2026-08-01), items 13–14 from the bounded-command coverage review
(#46, 2026-08-02), item 15 from the private worker channel (#65 / #72, 2026-08-04), items 16–18
from transactional batches (#82, 2026-08-09/10 — item 17 is what validating the tool against the CTF
session's own transcript turned up, and item 18 what reviewing it did), item 19 from
`walk_memory` (#103, 2026-08-13), items 20–22 from standing the server up on an ARM64 guest
(#131, #132, #134, 2026-08-16), item 23 from making the listener usable rather than merely
working (2026-08-17), items 24, 35 and 36 from measuring what this server costs the model driving
it — the surface and the results first (2026-08-17), then what a `registers` answer is actually
made of, and then `--tools` landing server-wide on a listener whose clients are already named
(both 2026-08-22) — items 25–26 from giving the debugger tier an ARM64 *target* (#143, #152,
2026-08-18), item 27 from completing the coordinate work (#156–#158, 2026-08-18), items 28–29
from giving each client its own sessions (#162, #164–#166, 2026-08-19), item 30 from serving
the stateless revision concurrently (#168 / #169, 2026-08-19), item 31 from giving a service-hosted
listener more than one client (2026-08-20), item 32 from running the debugger tier on the
ARM64 runner image that replaces `windows-11-arm` in September 2026, and items 33–34 from driving
the server with a **local model** — the lease grace measured against the wrong slow party, and a
service's clients fixed at install time (both 2026-08-22), and items 37–38 from the credential
file gaining a fourth writer while still having no reader, and from exercising what that reader
says against a real service (both 2026-08-23), and items 39–40 from running the surface, the window
and the model as a **grid** rather than as a sighting, and from what that grid found leaking
through the one thing `--tools` does not narrow (both 2026-08-23), and item 41 from re-running
the narrowed cells against that fix and finding two of the same names arriving by a second route
(2026-08-24), and items 42–43 from measuring item 41 and having two readings of that measurement
corrected in review (2026-08-24; **both have since landed** — item 42 the same day, item 43 on
2026-08-25, once #217 had shown that its "`taught` is zero" premise was false), and item 44 from
the first run those two made possible: five draws of the narrowed cells, where a task failing in
all twenty-five turned out to be failing at its own wording (2026-08-25, **landed** the same day),
and items 45–46 from what closing it opened up: the suite's answer key is a set of facts read off
the sample dumps that nothing re-checks, so it can rot while every model goes on scoring against
it, and a run can be graded but not *compared*, because nothing records the model weights or the
server build it ran against (both 2026-08-25; **item 45 has since landed**, the same day). Each item notes its repo, why it was deferred, and where it picks up. See [`DECISIONS.md`](./DECISIONS.md) for the design rationale (D1–D5) items 1–6 extend,
and the 2026-08-02 entries that items 13–14 and item 10 extend.

Items are roughly ordered by how soon they're worth doing, within each cluster. **Item 10 has
landed** (process-per-session, 2026-08-02); it is kept here rather than deleted because items 8 and
9 were both written against the single-engine design it replaced, and each now says what moved.
**Items 16, 17 and 18 have landed** (2026-08-10) and are kept for the opposite reason: each turned
out to need something its entry did not anticipate — item 18 needed much less of item 7 than it
claimed to, item 17 needed a walk deadline nothing had asked for, and item 16 needed a probe before
it could measure anything at all. **Items 25 and 26 have landed** (2026-08-21, #153 and #154), and both are kept because each turned
out to rest on something that was not so: item 25's premise about what Windows ships was only true
on one of the two runner images, and item 26's "one decision first" was the wrong decision to be
weighing. **Items 20 and 22 have landed** (2026-08-16, #131 and #134) and are kept because each needed
something its entry did not see — item 22's job rename silently removed a required status check.
Item 20's fix needed something the entry did not see: the two installers spell x64 differently, so the reordering it proposed would have
picked the wrong architecture by another route. **Item 7 has landed** too (2026-08-10, the
`interrupt` tool), and
is kept because item 8 rests on it: what it built is the job binding, and what it deliberately did
not build is the queued-job half that only `tasks/cancel` can ask for. **Item 12 has landed**
(2026-08-02) and is kept because what validating it *disproved* outlives what it confirmed: a kernel
attach whose target never dials in has no bound at all, which is the constraint item 10 contains.
**Item 42 has landed** (2026-08-24) and is kept for the same reason as item 41 above: what it built
is the capability to repeat a cell, and what it deliberately did not run is the A/B that motivated
it — plus one of its own sentences turned out to be false on this bench, which the entry now records.
**Item 44 has landed** (2026-08-25) and is kept because its own proposed wording was not the wording
that shipped: closing the reading it identified needed the prompt to say what the answer is *not*,
which is a judgement nothing has measured, and the entry now records what would settle it.
**Item 45 has landed** (2026-08-25) and is kept because three things it needed are not in the entry
that proposed it: `expect` turned out not to be *derivable* from a binding — two of one task's
groups are phrasings of a relation rather than strings the server prints — a tool with no
structured half needed a second verb, and the ratchet is the coverage rule rather than any pin.

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

## 24. [windbg-mcp] Spend fewer of the caller's tokens — **done** (2026-08-22)

`docs/token-budget.md` and the two budget tests in `tests/mcp_smoke.rs` measured what this server
costs the model driving it. Nothing had, and the numbers were larger than a careful reading of the
source predicted — 90–130 KB estimated, 358 KB actual. This item is the list of things the
measurement found. None of them is a bug; all of them were invisible.

**Why deferred:** the baseline had to be recorded *before* anything was optimised for it, or every
later fix would be a diff against a number somebody had already tidied. The tests and the golden
landed on their own so that each of the items below can be argued, and measured, separately.

- **`$defs` are inlined per tool** — **done** (2026-08-22), and neither lever this bullet named
  was the one. `schemars` emits each output schema self-contained, so `ErrorCategory` (2,089 B)
  shipped 33 times and the allocator/pool subtree nine: **222,579 B, 69% of all `outputSchema`**,
  duplicated beyond its first copy. Wire and client-parse cost only; no model reads it.

  **The duplication cannot be removed.** MCP gives each tool one `outputSchema` and no document
  above it, and `#/$defs/…` resolves against the schema it appears in, so there is nowhere a client
  could look up a definition another tool declared — "a `list_tools` that emits shared definitions"
  has no reader. And `output_schema = schema_for_output::<T>()` was already on every tool; it names
  the type, not where the type is written.

  What moved was **what gets multiplied**. Measuring the payload found **68% of every `outputSchema`
  byte was a `description`** — 217,423 B of 320,365 B, 55% of the whole answer — so the schemas now
  carry constraints and nothing else (`src/schema.rs`): **394,883 → 177,460 B, model-visible
  unmoved.** `WIRE_CEILING` 460,000 → 205,000. The prose is not lost; it stays in the rustdoc it is
  generated from and in `README.md`'s structured-results table, which is where it is read. Nothing
  reads it in a schema — no model is given one, and `description` is an annotation keyword, so an
  instance that validated before validates now.

  Two things worth carrying. The strip is **structural, not textual**: a field named `description`
  is a property *name*, and dropping every `"description"` key would delete the field rather than
  its documentation — no structured type has such a field today, which is exactly why nothing would
  have reported it. And the same answer does **not** transfer to the input schemas below: there the
  prose is most of what tells a model how to drive the tool.

  **This one had a price** (2026-08-18): adding `PdbInfo`, one optional four-field type on one
  field of `ModuleInfo`, grew the wire by **15,610 B** and model context by **zero**, because
  `ModuleInfo` is embedded in the openers' summary, in `modules` and in the allocator shapes. That
  is the compounding this finding predicted, measured on a change small enough that nobody would
  have thought to look. The multiplier is still there — it is the protocol's — but the same type
  costs roughly a seventh of that now.
- **Six openers carry a byte-identical 13,386 B output schema**, six step tools a byte-identical
  4,433 B one. 89,095 B of the above, and it looked like the cheapest to collapse. It is the same
  protocol fact as the bullet above with the same answer: those schemas are 3,838 B and 1,185 B
  each now, and there is still nowhere to say either of them once.
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
- **`registers` returned 15.9x more JSON than its own text** (9,804 B vs 618 B) — **done**
  (2026-08-22), and the bullet's diagnosis was half of it. `"kind":"int"` and `"subregister":false`
  were 41% of the payload, but measuring it rather than reasoning about it found **64 of the 123
  rows were the vector bank**: DbgEng reports `xmm0/0` … `xmm0/3` as 32-bit pseudo-registers without
  the subregister flag, so they passed a filter meaning "integer, not a view" and sat in an answer
  documented as excluding the vector registers. Now 3,480 B and 5.6x, ceiling 13,500 → 5,000. The
  claim that the text "says the same thing better" was wrong too: `r` prints 17 registers and the
  values carried 123, so the ratio compared two different sets. `modules` is the other half of this
  bullet and is done above.
- **Five tools are a third of the model-visible surface**, and it is their input schemas — **done**
  (2026-08-22) by serving fewer tools rather than smaller ones. `debug_batch` 9,746 B (7,980 of it
  the `StepAction`/`Check` vocabulary), `walk_memory` 4,076, `crash_triage` 2,912,
  `reachable_from_dispatch` 2,628, `server_log` 2,599 — 21,961 B against a median tool of 900 B.
  Unlike the items above this is not waste but one tool honestly describing a rich argument, and
  the levers were design choices: a smaller step vocabulary, a `$ref` the client resolves, or a
  surface that does not offer every tool to every caller.

  **The first bullet's answer does not transfer, and measuring that is what chose between them.**
  Prose came out of the output schemas because nothing read it; prose in an *input* schema is most
  of what tells a model how to drive the tool, and `debug_batch` is where getting that wrong leaves
  a patched byte in a running kernel. Across all 51 tools **74% of the model-visible surface is
  prose** — 24,794 B of tool descriptions, 25,333 B inside the input schemas. The structural
  remainder does not pay for the risk: `"default": null` is 1,744 B (2.6%) and is the only free one,
  since `$schema` is how a client picks a validator dialect and `minimum`/`format` are constraints.
  **~1.7 KB of 67,658** was the whole honest total for trimming, so trimming was not done.

  So the third lever: **`--tools`** (`src/toolset.rs`), a named subset advertised at startup. No
  description loses a word; a caller reading a crash dump stops paying for nine TTD tools and ten
  allocator ones. `session,inspect,crash` is 20 tools / 25,265 B; `crash` is 11 / 15,073 B against
  51 / 67,658 B. A spec names groups, individual tools, or `all`, and anything else is refused at
  startup rather than quietly serving something different. (Every figure in this item is as
  measured on 2026-08-17. Item 41 has since moved all of them — the narrowed surfaces down and the
  whole one up; `docs/token-budget.md` carries today's.)

  Three things it settled that the bullet did not anticipate. **`session` has to be in every
  surface** — every other tool routes by a `session_id` this server is the only issuer of, so a
  surface with `registers` and no opener is not a smaller surface but a broken one; 12,161 B was
  the floor then and `--tools crash` is eleven tools. **A tool that exists and is not served needs its own
  refusal**: rmcp answers `tool not found`, which is what a typo gets, while this is an operator's
  flag the caller cannot see. And **the group table needs joining to the live surface**, because a
  tool added to `src/server.rs` and not put in a group vanishes from every *narrowed* surface while
  the default still carries it — `every_tool_belongs_to_exactly_one_group` is that join, and it
  found `set_symbol_path` missing from the README's tool table on the way in.
- **`modules` had neither a `limit` nor a cap**, alone among the high-volume tools — **done**
  (2026-08-21). Everything else uncapped is raw debugger text — `ttd_calls`, `ttd_memory`,
  `threads`, `execute`, `dx`, `ioctl_trace`, `reachable_from_dispatch` — and `read_memory` returns
  up to ~4 MiB of hex by design (`src/worker.rs:117`). Every cap that existed (`MAX_ROWS`,
  `MAX_NODES`, `MAX_READ_BYTES`) was justified in its own comment as a worker out-of-memory guard;
  `DEFAULT_MODULE_ROWS` is the first whose constraint is the **caller's** context, and it says so
  where it is defined. Default 64 rows, maximum 2000, measured at 12,268 B model / 16,871 B wire
  against 53,933 B / 74,052 B for the whole 227-module table — for 383 B of tool surface, paid once
  a conversation rather than per call.

  Two things it turned on that this bullet did not see. The cap is only safe because the **counts
  are values**: `matched` and `unloaded_matched` were added beside `loaded` so a page can never be
  read as the inventory, which is the same rule `frames_truncated` keeps for a stack. And one
  budget is shared between the loaded and unloaded halves rather than one each — through the
  `split_row_budget` the heap diagnostics already used, whose own test says why: two sections that
  each restart the budget quietly double the ceiling it was chosen to be. Reaching for a cap
  per half was the first thing tried here, and this repo had already argued it down one tool over.

**This item is done.** Every bullet is fixed, measured-and-declined, or answered; what came out of
it was one *new* item — a per-caller tool surface, item 36, itself since closed — rather than
anything left over here.

**Where this bites first is a local model**, whose window is bought in RAM rather than rented:
[`docs/local-model.md`](./docs/local-model.md) is the runbook, and it names the three client-side
knobs the split-plane plan proposed — a tool-surface profile, a per-call response budget, a
text-or-data switch — none of which this server had. The `modules` bullet above is the first of
them landing as a *per-tool* answer rather than a caller-wide one: a response budget one tool at a
time, chosen by whoever owns that tool's shape. Whether the general knob is still wanted is now a
question about the tools that have no bound at all, not about the one that did the most damage.

**Depends on nothing**, but it **collides with item 11**, which proposes adding `structuredContent`
to `ttd_calls`, `ttd_memory` and `driver_object` — three of the highest-volume text-only tools.
Under the client rule measured here, structured content *replaces* the text rather than
supplementing it, so that change is a size decision as much as a typing one, and it also partly
reverses the reasoning in `DECISIONS.md`'s #84 entry ("a second channel, not a replacement"), which
was argued against a Python client and never against a model one. Whichever is done first should
say what it means for the other.

Picks up at [`docs/token-budget.md`](./docs/token-budget.md) and the two budget tests in
`tests/mcp_smoke.rs`.

## 25. [windbg-mcp] The ARM64 CI runner resolves no symbols, so its target reads never run — **done** (2026-08-21, #153)

Since #152 the debugger tier's target-reading assertions decide for themselves whether the host can
support them, and the two CI entries decided differently: on `windows-latest` all four ran and
passed, on `windows-11-arm` all four printed `SKIPPED`. Same code, same dumps.

**The probe the entry asked for answered it, and not the way either the entry or the issue
guessed.** The reasoning here was that Windows ships `dbghelp.dll` in System32 and no `symsrv.dll`
outside the Debugging Tools, so a runner with neither downloads no PDB. Measured on both runners:

- `windows-latest` **has** a `symsrv.dll` in System32, servicing-versioned like an inbox component.
  That, not the kit, is where its stock engine gets its symbol store — which is why it resolves
  symbols with `_NT_SYMBOL_PATH` unset;
- `windows-11-arm` has none anywhere in System32, matching this project's own ARM64 bench;
- **both** images carry the Debugging Tools, `symsrv.dll` and a full `dbgeng.dll` included.

So the deferral rested on a premise that was only half true, and the thing that was supposedly
unavailable was already on the runner's disk. The fix is the issue's option 1, one entry only: copy
the kit's `dbghelp.dll` and `symsrv.dll` beside the binary under test on the ARM64 entry.

**What the entry called a decision about what the job is for turned out to be smaller than that.**
The job's position is that it runs the runner's *stock* engine. `dbgeng.dll` is deliberately not
copied, so it still does — the entry goes on loading the image's own engine, which is the claim it
was matrixed for (#134). What it gains is the symbol *half*, which this repo had already measured
to be all an inbox engine needs. "Stock" was never a single thing anyway: the two images' System32
differ, and that difference alone produced the asymmetry.

**A skip passes, so the fix needed a guard of its own.** The job now fails if either target-read
stand-down appears in the output; without that, a copy that stopped working would read exactly like
a green run — which is the shape of failure this whole item is about.

## 26. [windbg-mcp] No ARM64 driver crash, so frame attribution is asserted only on x64 stacks — **done** (2026-08-21, #154)

`a_driver_crash_names_the_driver_frame_that_analyze_cannot` opened the x64 `MessageManager` dump on
every architecture. It passed there — an engine with symbols reads either dump either way round —
but the arithmetic that turns a captured frame into `module+RVA` off the load base had never been
run against an **ARM64** stack. #143 closed the other three assertions this way and left this one.

**What it needed was a crash produced, and producing it was the whole difficulty.** HEVD wraps its
triggers in `__try/__except`, so every access violation it can raise is caught and returned as a
status: the null dereference returns `STATUS_ACCESS_VIOLATION` with the machine still running, the
non-paged pool overflow returns success, and the UAF double free returns success *twice* and is
detected minutes later on a heap-maintenance worker thread — a `0x13A` whose stack is `nt`-only,
which is precisely the fixture this was not looking for. What SEH cannot catch is a **fail fast**:
`HEVD_IOCTL_BUFFER_OVERFLOW_STACK_GS` compiles its trigger with `/GS`, so overrunning the buffer
corrupts the cookie and the driver's own `__report_gsfailure` raises
`0x139 KERNEL_SECURITY_CHECK_FAILURE` from `mov w0, #2; brk #0xf003`. `docs/samples/082126-7015-01.dmp`.

**The decision the entry said to make first went the other way, and the fixture decided it.**
`HEVD.pdb` ships beside the driver, so the entry expected to choose between keeping the PDB off the
symbol path and asserting the symbolized form. What the capture showed is that the interesting
disagreement is not `symbol` but **`!analyze`**: it names `HEVD` by name, where it calls the
PDB-less `MessageManager` crash `Unknown_Module`. So the pair covers both — for one fixture the
computed frame is the *only* thing that names the driver, and for the other it is checked against
an independent answer.

**And the test is not paired by architecture, which is what the entry proposed.** It is a table run
on every host. Pairing would have meant an ARM64 runner stopped reading the x64 crash it reads
today, trading one architecture's coverage for the other's rather than adding it.

Three faults in `tools/ioctl_harness.ps1` came out of using it for this, all of them Windows
PowerShell 5.1-only and each fatal before an IOCTL was sent: em dashes in a BOM-less UTF-8 file
(decoded in the ANSI code page, so `—` ended a string), `0x80000000` read as a negative Int32 for
the access mask, and an empty `-InputHex` returning `$null` because the pipeline unrolls an empty
array. All three are fixed; a 7-only tool that documents itself as needing no compiler was not
much use on a target that has only 5.1.

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

## 32. [windbg-mcp] Two ARM64 CI entries, one of which expires

The debugger tier's ARM64 half is a **pair**: `windows-11-arm` and `windows-11-vs2026-arm`. That is
deliberate and temporary. GitHub's Visual Studio 2026 ARM64 image went generally available on
2026-08-20 under the new label, and the `windows-11-arm` label is migrated onto it between 21 and
30 September 2026 — so today the two labels are two *OS builds* (10.0.26200.9168 against .8875 when
this was written) and therefore two inbox `dbgeng.dll`s, which is the one thing this job exists to
load. Running both is what makes a break during that window attributable to the image rather than
to the change under review, and what gives the repo notice before every PR meets it at once.

- **What to do, and when:** after the migration completes, the two labels name the same image and
  the pair buys a second run of the same tier. Drop the `windows-11-arm` entry — not the new one:
  the new label is the stable name for that image, and `windows-11-arm` is the one whose meaning
  moved. The x64 entry is untouched either way; `windows-latest` migrated to the Visual Studio 2026
  Windows Server 2025 image before this.
- **How you will know it converged:** the two entries stop differing in the OS build they report,
  and `actions/runner-images`' `Windows11-Arm64-Readme.md` stops naming a separate VS2022 image.
  Until then, an entry that fails alone is the interesting one — read which label it is before
  reading the diff.
- **What it could still turn up in the meantime:** the copy step assumes the kit at
  `C:\Program Files (x86)\Windows Kits\10\Debuggers\arm64`, which both images carry today (the
  same WDK build, 10.1.26100.6584). It throws by name if that stops being true, which is the
  failure this pair is here to catch early rather than on the migration date.

## 33. [windbg-mcp] The lease grace assumes the server is the slow party

A client's lease is renewed by its requests, and the grace is derived from how long a *call* may
take — which is the right bound when the thing that goes quiet is the server working. Driving a
**local model** inverts it: a turn is the model thinking, with no request in flight, and one
measured on this repo's own bench took **440s against a 390s grace** (2026-08-22,
[`docs/local-model.md`](./docs/local-model.md)). The sweep released the client's sessions
mid-investigation, and every later call came back `404 Session not found` — indistinguishable, from
the caller's side, from a server that had fallen over.

The client half is fixed: `tools/local_model_drive.py` pings after 120s of silence. That is the
right layer for a *known* slow client, and it is not an answer for any other one — a client that
does not know to ping is exactly the client this bites.

- **The question:** should a lease be renewed by something other than a request — an MCP session
  that is still connected, say? The pieces are already there: rmcp knows whether a session's stream
  is live, and `Lease::admit` already refuses on two grounds before renewing. The risk is the
  reason the lease exists at all: a client that vanished with a live kernel target open must not
  hold it for ever, and "still connected" is exactly what a half-open TCP connection claims to be
  ([`split-plane` phase 1's own argument](./docs/remote-listener.md)). So a connection is evidence,
  not proof, and the shape that survives that is probably *a longer grace for a connected client*
  rather than an exemption.
- **Where it picks up:** `Lease` in `src/listen.rs`, and the startup floor in `Lease::new` that
  makes "no request of that credential's can still be in flight when its lease expires" true. Any
  change here has to keep that property — it is what lets the sweep zero nothing and wait for
  nothing.
- **What it is not:** a reason to raise the default grace. 390s is derived from the call timeout for
  a reason, and a client that thinks for seven minutes is a fact about local models rather than
  about this server.

## 34. [windbg-mcp] A service-hosted listener's clients are fixed at install time — **done** (2026-08-22)

`--install-service` is the **only** writer of `%ProgramData%\windbg-mcp\token`, and it leaves the
file granting `SYSTEM` and `Administrators` *read* — deliberately, since the token is the one thing
between an unprivileged local process and `launch` running its command line as `LocalSystem`. The
SCM then refuses a second registration under the same name. So adding or rotating a client means
`--uninstall-service`, set every credential variable again, `--install-service`, `Start-Service` —
which **drops every session the service holds**, a parked kernel attach included.

Found the hard way (2026-08-22): giving a local-model bench a credential of its own turned into an
attempt to edit that file, which failed on the ACL — correctly. The fallback that worked, and is now
the documented one, is a second *foreground* listener on another port with its own token
([`docs/local-model.md`](./docs/local-model.md)); this item is about the case where the service is
the listener you have.

**The reinstall is not a decision anyone made** — it is what falls out of there being no writer but
the installer. Two properties *were* chosen deliberately, and neither of them requires it: "only the
installer writes this file" becomes "only **this program**, running elevated, writes it", since the
command below is the same binary; and "never write through a file it did not create" survives a
fresh temp created with `create_new` in the same protected directory and renamed over the old one.
So the hardening and the fix are compatible, which is the reason to build the fix rather than
document the dance.

- **What to build, and it is three commands rather than one:** `--add-listen-client <name>`,
  `--remove-listen-client <name>` and `--rotate-listen-client <name>`. Rotation is the one with a
  schedule attached — rotating the *only* credential is today's same uninstall/reinstall — and
  removal is what keeps a bench credential from outliving the bench. Each writes the file the way
  `finish_install` does (a fresh file, `create_new`, the same ACL re-applied), **generates the token
  itself**, and prints only a fingerprint (`sha256:701E4CF3…`). Three things fall out: no reinstall,
  no secret through a shell history or an agent's transcript, and an operation narrow enough to
  allow-list in a permission rule, where "let this write `%ProgramData%` over ssh" is not.
- **The reload is the other half, not a footnote.** `Credentials` is built once at startup
  (`client::Credentials::from_entries`), so a client added under a running service is not admitted
  until the next start — and a *restart* still drops every session, which is most of what makes the
  reinstall unfriendly in the first place. Without a live reload this item is an improvement in
  ergonomics and not in outcome. Preferred mechanism: a **user-defined service control code** the
  command sends after writing, which is explicit, needs no background watcher, and fits the plumbing
  that already handles Stop and Preshutdown. A file watcher is the alternative and costs more: it
  needs the writes to be atomic to be safe, and it mainly serves hand-editing, which the ACL is
  there to discourage. Removing a client that still holds sessions is its own decision — refuse, or
  release them down the path the lease sweep already uses.
- **What not to do:** relax the ACL, or teach the installer to update in place. The refusal to write
  through a file it did not create is what stops an unprivileged user pre-creating the path and
  ending up owning the credential.
- **The second listener is a development workflow, and stays one.** The recipe in
  [`docs/local-model.md`](./docs/local-model.md) is right for a bench — a borrowed box with no
  administrator, a credential that should vanish with the process, a run that must not share a
  process with the listener an editor depends on, a build that is not the installed one — and every
  one of those is a *developer's* problem. It is not an operator's answer and must not become one:
  **if someone running a deployed listener ever has to start a second one to add a client, these
  commands are incomplete.** That is the bar to build against, and the reason the reload above is
  not optional.

**Built as described.** `--add-listen-client <name>`, `--remove-listen-client <name>` and
`--rotate-listen-client <name>` (`src/service.rs`), each generating the token, writing it to the
`--token-out <path>` it requires, and printing only a fingerprint. The write is
`service::write_credentials` — a fresh sibling created with `create_new` in the protected
directory, ACL'd there, renamed over the old name — and `finish_install` now shares it, so the
installer and the commands write that file to one standard and the replacement is atomic for a
service reading it. The reload is user-defined control code **128**, sent by the command and
answered in `serve_as_service`'s handler; it reaches `listen::reloaded`, which re-reads through the
same `credentials()` that decides whether the listener may start at all — so a set that would not
have started it cannot replace the one that did — swaps it into `client::Accepted`, and releases a
departed client's sessions down the lease-sweep path. A removal of the *last* client is refused,
since a listener with no credentials will not start.

**Verified on the ARM64 bench against the installed service** (2026-08-22), one process throughout
(pid 9108, never restarted): `--add-listen-client bench` → the log says `re-read the clients: added
[bench], removed []` and that token completes an MCP `initialize` (`200`, `mcp-session-id`);
`--rotate-listen-client bench` → the old token `401`, the new one `200`; `--remove-listen-client
bench` → `401` again, and the credential file back **byte-for-byte** to its pre-test hash, `local`'s
token untouched and the file returned from the JSON shape to the bare one. Removing `local` (the
only remaining client) was refused.

**What review then corrected** (both bots, on the first commit). The reload was asynchronous while
the command said it was not, so the printed claim is now backed by an acknowledgement the control
handler blocks on — and a re-read that failed comes back as a failed control code, which is an
*error* for the two commands that revoke a credential. A revoked client kept half its state:
`reloaded` released the debug sessions where the sweep does three things, so its MCP sessions stayed
resident and — lease state being keyed by name — a re-added name inherited the ids of whoever held
it before (`Lease::revoked_for` and `Lease::forget`). The `--token-out` ACL went on *after* the
secret; moving it earlier then exposed a close-and-reopen race, so the flag is **gone** — the token
is written into the state directory, which is already `SYSTEM`-and-`Administrators`-only with no
traverse for anyone else, and the choice that generated both findings is deleted rather than patched
a third time. A revocation also had a window a lease expiry does not (`Sessions::revoke`): the token
stops being accepted at the swap, but an opener that authenticated a moment earlier can be seconds
from registering, and a one-pass release cannot see it.

**And then the shape changed rather than growing again.** Three rounds of findings had clustered on
two things — how the secret reaches the operator, which the `--token-out` deletion settled, and
revocation, which by then had four mechanisms of its own and a task with an ordering rule. The
second cluster is gone the same way: a revocation is now **an expiry that does not wait**, so it
sets the lease clock to now and the sweeper does the teardown it was already doing for expired
clients. Deleted with it: the teardown task, its channel, the ordering rule between `forget` and
`unrevoke`, and `Lease::revoked_for`. What is left is a flag on `Presence`, a branch in the sweep,
and the admission gate — which stays, because it is the one thing an expiry genuinely does not need.
A grace is there so a client that went *quiet* can come back to what it left; a revoked credential
is never coming back, so skipping it costs nothing.

**What it did not settle, and is now [#190](https://github.com/glslang/windbg-mcp/issues/190).** A
`Client` is a name, so `--remove-listen-client ci` then `--add-listen-client ci` makes two
credentials that everything keyed on identity — session ownership, routing, lease state, the
revocation gate — treats as one. Four of #189's findings were different consumers of that one
ambiguity, and the four fixes that shipped (a `409` on a revoked presence, a lease that does not
renew for one, an admission gate on the owner name, and lifting that gate on re-add rather than on
an empty release) each narrow the window without closing it: at the moment a session registers there
is nothing in it that says *which* `ci` opened it. Giving `Client` an incarnation would delete all
four rather than add a fifth. **Done** (2026-08-22): identity is `(name, incarnation)`, minted only
where a set of credentials is swapped in — the one place that can tell a name carrying on from a
name being given back — and the name stays the whole of what is rendered. That deleted the `409` a
re-added name used to wait out, `Sessions::unrevoke` and the question of when to lift a gate, and it
closed the residual: an in-flight opener of the revoked credential registers against an identity no
live client shares. Two elevated shells
could each write a whole file from its own snapshot (`token.lock`, `share_mode(0)`). And
`--add-listen-client --token-out C:\x` took `--token-out` as the client *name*, which passes the
name rule since a name may contain `-`.

**What was left alone deliberately.** The ACL, and the refusal to write through a file it did not
create. The environment is still read only by `--install-service`. And the second foreground
listener stays a development workflow — the bar in this item ("if someone running a deployed
listener ever has to start a second one to add a client, these commands are incomplete") is met:
add, revoke and rotate are all in place, and all three take effect without stopping anything.


## 35. [windbg-mcp + win-kexp] The engine's subregister flag misses the views that matter — **measured and declined** (2026-08-22)

`registers` narrows its default set with `DEBUG_REGISTER_SUB_REGISTER`, and that flag does not mean
what the filter needs it to mean:

- **x64**: it catches `eax`/`ax`/`al` (67 rows of a full set) and misses the vector bank's slices —
  `xmm0/0` … `xmm15/3`, 64 rows, four 32-bit pieces of each 128-bit register. Excluded since item 24
  by the `/` DbgEng puts in a slice's name (`plain_integer`, `src/worker.rs`).
- **ARM64**: it catches **nine** rows, all `cpsr` bits, and misses `w0`–`w30` — the 32-bit views of
  `x0`–`x28`/`fp`/`lr`, 31 of the 109 default rows, ~28% of that answer.

**The question this item existed to ask has been asked**, with a win-kexp branch exposing the whole
`DEBUG_REGISTER_DESCRIPTION` and an example printing it for a dump (`register-descriptions`,
unmerged). The answer is that the engine offers nothing better:

| | x64 | ARM64 |
| --- | --- | --- |
| unflagged `int32` rows | `efl`, `mxcsr`, **and all 64 `xmm` slices** | `cpsr`, `spsr`, `fpsr`, `fpcr`, `bcr*`, **and all 31 `w` views** |
| any sub-register field set where the flag is clear (master, length, mask or shift) | none, of 355 rows | none, of 205 rows |
| where the flag is set | master and `SubregLength` are populated (`eax`: master `rax`, length 32) | the same, for the nine `cpsr` bits |

So `Type` puts a view in the same bucket as a register that is simply narrow — `w0` beside `cpsr`,
`xmm0/0` beside `efl` — and the sub-register group is untouched unless the flag already said so.
There is no derived rule to be had from the description.

The test behind that middle row is deliberately *not* `SubregMaster != 0`: index 0 is a real
register (`rax`, `x0`) and is precisely the master these rows would name if they named one, so
treating zero as "unset" throws away the case the probe exists to find — reported by
chatgpt-codex-connector on glslang/win-kexp#115. What the row counts is any of the four fields being
non-zero, and none of them is, on either architecture.

**Declined rather than solved**, and the reasoning is worth keeping because it is what a future
attempt will re-derive. The remaining option is a second name rule, and the obvious one does not
survive contact with the register set: "exclude `w<N>` where `x<N>` exists" leaves `w29` and `w30`
in, because ARM64 enumerates `x0`–`x28` and then `fp`, `lr`, `sp`, `pc` — so the rule immediately
needs the table of exceptions this item was filed to avoid. The `/` rule stands as the one exception
because it tests a *convention for slices* rather than pairing two registers by name, and it is
asserted against whatever architecture the host is
(`a_default_register_set_leaves_out_the_vector_bank_on_this_architecture`).

- **What would reopen it:** a DbgEng build that sets the flag for these registers, or populates
  `SubregMaster` without it. The example above is how to check in one command, and is the reason the
  win-kexp branch is worth landing even though nothing consumes it yet — that is a judgement call
  left open rather than made here.
- **What it is worth if reopened:** ~1.8 KB of a ~6.3 KB answer, on ARM64 only. Real, and smaller
  than the 6.3 KB item 24 already took off the same tool.

## 36. [windbg-mcp] The tool surface is server-wide, not per caller — **done** (2026-08-22)

`--tools` (item 24's last bullet) narrows what a run advertises, and it narrows it for *everybody*
on that run. That is the right answer for stdio, which has one client by construction, and it is
the right answer for a listener serving one purpose. It is the wrong shape for the case the
listener was built for: a local model that can hold twenty tools and a hosted client that can hold
fifty-one, pointed at the same Windows box and the same debug sessions, told apart by their bearer
tokens already.

**It was three lines of plumbing and three decisions**, which is what the item predicted: the
identity was already there, `Toolset` was already an instance field beside it, and `listen.rs`'s
factory is the line that sets both. What the work actually was:

- **A per-client spec, from the source that already existed.** `WINDBG_MCP_TOOLS_<NAME>` beside the
  token variable, and a `tools` field in the credential file — where an entry may now be
  `{"token": "…", "tools": "session,crash"}` as well as the bare token it always was.
  `Credentials::build` parses it with the flag's own parser, so a spec the listener would refuse is
  refused at startup rather than served as an empty tool list; `Toolset::parse_from` takes the
  source's rendered name, because the vocabulary is written down in three places now and a refusal
  that always said `--tools` would send an operator to a command line they never typed. A spec
  naming a client with no token is refused on the precedent the item pointed at — the collision
  refusals — since it is a setting that could never take effect.

- **Two-client coverage**, which is the half the item said had bitten before, and it is
  `mcp_smoke::two_clients_on_one_listener_are_served_two_surfaces`: two tokens on one port, two
  `tools/list` answers, on the session-bearing route *and* the stateless one. Protocol tier — a
  tool list and a surface refusal need no target, and the tier's contract is that they must not.

- **`tools/list_changed` is not sent**, and that is the decision rather than a gap. This server
  keeps no peer handle to notify an MCP session through, and `2026-07-28` has no session to notify
  at all, so it would be a guarantee on one revision and silence on the other. A surface is instead
  fixed where the caller is identified — `initialize`, or every request on the stateless
  revision — so a change reaches a client the next time it is identified, one rule for both.
  `--set-listen-client-tools` says so where an operator reads it.

**The run's flag became a default rather than a ceiling.** A client's own spec replaces it, wider or
narrower: intersecting the two can produce a surface neither the operator nor the client ever named,
and "which of these two is in force" is a question with an answer either way, while "what is the
overlap of these two" is not one anybody would predict.

**Two things the change had to correct rather than add.** The refusal for a tool off the surface
told every caller to widen `--tools`, which is the wrong command for a client with an entry of its
own — it now names whichever configuration chose the surface (`Toolset::refusal`, `Chosen`). And
`--add-listen-client` printed "it gets the whole tool surface, as every client here does", which
this makes false; it says what the client is actually served.

Landed in [`src/toolset.rs`](./src/toolset.rs), [`src/client.rs`](./src/client.rs),
[`src/listen.rs`](./src/listen.rs) and [`src/service.rs`](./src/service.rs).

## 37. [windbg-mcp] The credential file has four writers and no reader — **done** (2026-08-23)

`--add-listen-client`, `--remove-listen-client`, `--rotate-listen-client` and now
`--set-listen-client-tools` all edit `%ProgramData%\windbg-mcp\token`, and each prints the whole
roster afterwards — name, token fingerprint, and the `--tools` spec where one is set. There is no
way to ask for that roster **without changing something**. `roster` is a private function with two
call sites, both inside `edit_client`.

That was survivable while every client was identical: the question "who may connect" had one other
answer, the listener's startup line, and a client either connected or did not. Item 36 made it a
question with a second half — *and what is each of them served?* — that an operator now has to
answer before changing a spec, and the only routes to it are to make a change they may not want, or
to read the service's log file and hope the line has not aged out. The file itself grants read to
`SYSTEM` and `Administrators` and is deliberately not theirs to open.

- **What to build:** `--list-listen-clients`. It is `roster` and the existing read half of
  `edit_client` — take the lock, read the file, parse, print — with no write and no reload, so it
  is the one command in the family that changes nothing and could be allow-listed accordingly.
- **The trap is what it must not print.** Not the tokens: a fingerprint is the only comparable
  thing, which is the rule the other four already follow and the reason they are safe to run in a
  transcript. And it must not *invent* one for a client whose entry it could not parse — a file
  that will not start the service has to read as that, not as a shorter roster.
- **It has two sources and only one of them has a command.** A service's clients are in the file;
  a *foreground* listener's are in the environment it was started with, and `edit_client` refuses
  outright where no service is installed. So either this reads whichever applies — which means it
  is not a service command at all — or it says which of the two it is answering for. The same
  asymmetry made a refusal wrong in [#196](https://github.com/glslang/windbg-mcp/pull/196): the
  message for a tool off a client's own surface named the service command alone, and a foreground
  listener's operator could not take that advice.

**Worth doing when** a host has more than one client with more than one surface, which is exactly
the arrangement item 36 exists for — until then the startup line names everything there is to know.
**Not blocked on anything.**

**Built as `--list-listen-clients`** (2026-08-23), and the third bullet is the one that cost more
than a line to get right. The other two fell out as written: the roster is `roster`, so no token
can reach the output, and the parse is the listener's own, so a file with one bad entry refuses
whole rather than printing a shorter list. The source question did not fall out. "Read whichever
applies" is wrong on the host both apply to — a service *and* a developer's foreground bench, which
`docs/remote-listener.md` recommends in the same breath — so the answer is **both, each saying what
it is**: the file where a service is installed, this shell's credentials where none is or where it
carries some anyway, and the shell's half labelled as what a listener started *from here* would
accept rather than what one already running elsewhere does. It reads the environment through
`listen::named_token_file` and not `client::env_credentials` alone, because a shell naming
`WINDBG_MCP_LISTEN_TOKEN_FILE` has its variables ignored by the listener — listing them would be a
roster of credentials nothing accepts.

Two things the entry did not anticipate. **The entry's "take the lock" is wrong**, and review
found it (fifth round): `lock_credentials` opens its file with `create(true)` and nothing else
creates it — not the installer — so a reader that took the lock would write into `%ProgramData%`
on any host where no client edit had yet run, which is the one property this command exists to
have. It buys almost nothing anyway, because `write_credentials` renames a finished file over the
old one, so a read racing an edit sees one complete version or the other. So the reader does not
lock, and the unelevated refusal comes from the credential file's own ACL, which is the object
being protected. (The lock's *message* was stale for a different reason and is fixed with it: it
named three commands of four, item 36 having added the fourth.) And **`--tools` beside it is
refused** rather than ignored, on the rule `--rotate-` and `--remove-listen-client` already follow:
it reads exactly like a filter over the list it is about to print.

A third thing came out of review: the roster is the **file**, and `edit_client` deliberately leaves
a window where the file and the running service disagree — a `--remove` or `--rotate` whose reload
could not be delivered writes the file, exits non-zero, and says the credential may still be
authenticating. An operator checking *that* with this command would have read "`windbg-mcp` holds"
as proof the token was gone. There is no live roster to ask for (a service control code carries a
status back and no data), so the answer is the caveat plus the state the service is in: `in_force`,
three arms, one sentence each. The next round found the *other* half of the same gap, and it is
not the same claim: a credential is in force at the reload every editing command waits for, while a
**surface** is fixed when the client is identified, so a reload that succeeded still leaves a
connected client listing what it listed then. That one is said wherever a client carries a spec of
its own and the service is running. That gate was itself wrong, three rounds later: clearing the
*last* per-client spec leaves a file with no surface in it and a connected client still being
served the old one. So the gate is gone and the sentence is folded into the one clause that was
already about file-versus-service — one rule, true whenever the service is running, rather than two
conditions each with a state it is wrong in.

**Three rounds all landed on that one clause, and they had one cause**: every wrong sentence was a
claim about what the service was *accepting*, made by a command that reads a file. The seam is
bounded rather than open — this service accepts `STOP` and `PRESHUTDOWN` and no pause control, so
the SCM can only put it in four states — so the answer was to enumerate all four and let no arm
claim acceptance where it cannot know it. The catch-all had been claiming "nothing is accepting
anything", which is false of `StopPending`: a stop ends the accept loop and then releases every
target (minutes, on a host holding a live kernel) while the connections already accepted go on
being served by tasks nothing awaits or aborts. The comment in [`src/listen.rs`](./src/listen.rs)
that said those connections "are dropped" is what produced the wrong sentence, and it is now
exact — the shutdown ends the *accepting*, not the serving.

A fourth round found the same shape one sentence over, and it is worth recording as the rule this
command is really under: **it may not assert anything about a process it cannot see.** The empty
environment branch said the service's roster was "the whole of what this host has", which a second
foreground listener on another port — recommended two paragraphs earlier in
`docs/remote-listener.md` — makes false, and which the non-empty branch beside it had always
qualified correctly.

Landed in [`src/service.rs`](./src/service.rs) (`list_clients`, `in_force`, `service_clients`,
`shell_clients`), [`src/listen.rs`](./src/listen.rs) and [`src/main.rs`](./src/main.rs).

## 38. [windbg-mcp] A client command can write a file the installed service cannot read — **done** (2026-08-23)

Item 36 (0.11.0) let a credential file entry be an **object** — `{"bench": {"token": "…", "tools":
"crash"}}` — beside the bare tokens it always held. A service installed from an earlier build
refuses that shape, so `--add-listen-client x --tools …` or `--set-listen-client-tools`, run from a
*newer* copy of this program than the one the SCM starts, writes a file the running service cannot
read.

**Nothing breaks at the time, which is the problem.** The reload only ever swaps in a set that
would have started this listener from cold, so a file it cannot parse changes nothing, says so in
the service log, and the command reports it. The failure is the **next start** — a reboot away from
the cause, and by then the command that caused it is far out of mind.

Measured on the ARM64 bench (2026-08-23) while exercising item 37's listing against a real service:
the installed service was running `target\release` from before item 36 while the client commands
were being run from `target\debug` after it. A fresh install cannot reach this, and neither can an
ordinary upgrade — Windows will not overwrite a running image, so an operator replacing the exe has
already stopped the service. A development tree with two builds in it is the case that does.

- **What to build:** a warning, not an error. [`edit_client`](./src/service.rs) already holds the
  service handle, and `Service::query_config()` returns the `executable_path` the SCM stores, so
  comparing that against `std::env::current_exe()` names the divergence at the moment it matters —
  no new channel, and the same shape as the other notes that command prints. It must not refuse:
  running the command from another copy of the *same* version is legitimate, and this cannot tell
  versions apart, only paths.
- **Not the version.** There is no channel that carries one: the only thing reaching the running
  service is a control code, which returns a status and no data (`FOLLOWUPS.md` item 37 settled
  that). A path comparison is a proxy, and the warning has to be worded as one.

**Worth doing when** a second service-hosted deployment exists, or the next time this tree grows a
third build. Until then `docs/remote-listener.md` says the operational half: replace the exe *and*
restart, and run the client commands from the binary the service runs.
**Not blocked on anything.**

Picks up at [`src/service.rs`](./src/service.rs) (`edit_client`, where the SCM handle is already
open) and [`docs/remote-listener.md`](./docs/remote-listener.md).

**Built as a warning printed by all five client commands** (2026-08-23), and
verified against the real service on the ARM64 bench — installed from `target\release`, told about
by `target\debug`, which is the arrangement the entry was measured in. Four things the entry did not
anticipate, one of which would have shipped a warning that was wrong on every host.

**`query_config()` does not return a path.** The entry says it "returns the `executable_path` the
SCM stores", and the field is called that, but `QueryServiceConfigW` hands back `lpBinaryPathName` —
the whole line the SCM starts, the exe *and* the `--service --listen 127.0.0.1:8765` after it.
Compared against `current_exe()` as it comes, it differs from the running image on **every** host
including every correct one, so the feature would have been a warning that is always wrong: worse
than the silence it replaces, since it trains an operator to ignore the one time it is right. The
image is read back out of the line (`image_in`), which is exact rather than approximate for a
reason worth writing down — `windows-service` escapes the line the way `CommandLineToArgvW` reads
it, and the only characters escaping introduces are `\"` and a doubled trailing `\`, neither of
which a Windows path can hold. So there are two shapes and they are the two the SCM shows: quoted
when the path has a space in it (`WinDefend` on this bench), bare when it does not (this service).

**"`edit_client` already holds the service handle" is a trap rather than a shortcut.** That handle
is opened with `QUERY_STATUS | USER_DEFINED_CONTROL`, the rights the command needs; adding
`QUERY_CONFIG` to it means a host that has narrowed the service's security descriptor cannot run
`--remove-listen-client` at all, because a *warning* wanted a right. The default descriptor grants
that right to Authenticated Users so it would almost always work, which is exactly what makes it
the wrong shape. The config is read on a handle of its own, and a refusal there costs the warning
rather than the command.

**It belongs on the reader too, and the entry scopes it to the writer.** `edit_client` is where the
divergence is *created*, but `--list-listen-clients` (item 37) is where an operator goes when a
service did not come back after a reboot — and the roster it prints is **this** build's reading of
a file **that** build has to read, under a clause (`in_force`) saying the running service re-reads
that file whenever a client command changes it, which on a divergent host it may not be able to do
at all. Silence there is the shape item 37's fourth review round ruled on: it may not assert
anything about a process it cannot see. Both print the warning, each naming its own stake in one
clause; everything after that clause is one string.

**Where it prints is decided by the path that fails.** Beside the notes at the bottom of
`edit_client` it would be skipped exactly when it explains most: a revocation whose reload did not
land returns an error before reaching them, and a service that cannot read the new file is one of
the two ways that reload fails. So it is printed before the change, which also settles the gate the
entry did not raise — a reload that lands *is* proof the other copy read what this one wrote, and
a warning printed first cannot be conditioned on it. It says what was compared rather than what it
concluded, which stays true whatever the reload goes on to do.

Landed in [`src/service.rs`](./src/service.rs) (`image_in`, `same_image`, `foreign_image`, and one
call in each of `edit_client` and `list_clients`) and
[`docs/remote-listener.md`](./docs/remote-listener.md).

## 39. [windbg-mcp] The eval measures single questions, not an investigation

[`docs/local-model-eval.md`](./docs/local-model-eval.md) runs six tasks across three tool surfaces,
three context windows and five models, and its strongest finding is a negative one: at a **served**
8,192-token window a 17,300-token surface was evaluated in full and answered correctly, so the
window is not the binding constraint the plan expected. That finding is true of the conversations
the grid runs, and **every one of them is short** - one question, one or two tool calls, an answer.

What is untested is the case where the *transcript* fills the window rather than the surface. The
surface is paid once per conversation and the runtime caches the prefix (`docs/local-model.md`
measured 86.5s cold against under 5s warm); a growing investigation is paid in full, every turn,
and a `modules` page or a `read_memory` answer lands in it whole. So the honest scope of "the
window did not bite" is *a question at a time*, and the interesting failure - the tenth turn of a
kernel triage, three large results deep - has not been run.

**Why it was deferred rather than added.** The driver already has the mechanism:
`WINDBG_MCP_SCENARIO=1` makes a task list one continuing investigation with one transcript and one
set of sessions. What it does not have is a way to *grade* one. A scenario has no per-task answer
key - a wrong turn at step 3 makes steps 4 to 8 unanswerable, so per-task scoring reports eight
failures for one mistake, and the thing worth measuring is the step at which the run stopped being
recoverable. That is a different unit of measurement and a different key, not a flag on this grid.

**Where it picks up.** A scenario key would want: an ordered list of facts the run must have
established by the end, the turn index at which each first appears, and the transcript length at
that point. `local_model_eval.py` grades from records that already carry every turn's prompt token
count, so the growth curve is in the log this eval already writes - what is missing is the key and
a `--scenario` mode in the grader that reads it.

Two smaller things the same run left open:

- **Nothing measures the mutating tools.** The harness executes a read-only allow-list, so
  `debug_batch`, `launch` and `execute` are offered and never run. gemma calling `debug_batch` four
  times on a surface that does not serve it - and being refused four times - is a hint that this is
  where a wrong pick would be expensive rather than merely wasted: a batch that *does* run patches
  the target. Measuring it wants a throwaway target and a rollback assertion, which is the
  live-kernel tier's shape rather than this one's.
- **One bench, one architecture, for the timings.** Every wall-clock number in that document is an
  ARM64 Mac serving MLX builds. The correctness columns should travel; the timings should not be
  quoted anywhere else.

## 40. [windbg-mcp] `--tools` narrows the tool list and not the instructions — **done** (2026-08-23)

A client's surface is per credential since [#196](https://github.com/glslang/windbg-mcp/pull/196),
and what that narrows is the **router**: `tools/list` answers with the client's own set, and a call
for anything else is refused by name. The `instructions` string sent at `initialize` is not
narrowed. It is a compile-time constant on `#[rmcp::tool_handler]` in `src/server.rs`, it names
**twenty-one tools**, and every client gets all of it.

Measured on the eval bench (2026-08-23,
[`docs/local-model-eval.md`](./docs/local-model-eval.md)): the `min` client is served **11** tools
and told about **21**, of which **17 it cannot call** — `modules`, `execute`, `decode_ioctl`,
`debug_batch`, the whole TTD family and the whole IOCTL family. Both halves of that are a cost:

- **Wasted turns, and the eval measured them.** Every off-surface call in the grid is one of those
  seventeen — gemma spent a task's entire turn budget re-asking for `debug_batch`, and both control
  rows asked for `modules` and `execute`. The eval first recorded this as models *inventing* tool
  names; they were reading this server's own advertising. The metric is now called `unserved`.
- **Context, on the surface least able to pay it.** 1,990 characters, ~497 tokens, identical for
  every client — of which **59% is sentences naming only tools a `min` client cannot call**, and
  the whole string is ~12% of that client's prompt. `--tools crash` drops 54,000 bytes of schemas
  and keeps every word of the prose selling what it dropped.

**Why it was deferred rather than fixed with the eval.** The fix is not a filter over the existing
text: the prose is sentences, each naming several tools, and cutting by keyword would leave
mangled English in the one string a model reads before anything else. The shape that works is the
same one the tool table already has — a base paragraph plus a fragment per **group**, assembled for
the client's own `Toolset`, so `crash` gets the base and the crash sentence and nothing about TTD.
That is a rewrite of the instructions as data rather than a constant, and it moves a string three
tests assert on (`the_instructions_fit_what_the_client_reads`, the discovery assertion in
`src/server.rs`, and the tool-budget golden).

**Where it picks up — and it did.** `#[rmcp::tool_handler]` supplies `get_info` only when the impl
does not, the same rule `call_tool` already relies on, so the override is a hand-written `get_info`
assembling the text from the surface `WindbgServer` already holds (`crate::client::current()` is
not right here: the surface is captured in the listener's factory).

**The invariant, which is not the one this entry first proposed:** a fragment ships only when
**every tool it names** is served. The first attempt asked whether the fragment's *group* was
served at all, and review caught what that costs — `--tools registers` is a valid spec, and the
inspect sentence names `modules`, `dx` and `execute` in one breath, so a client served one tool of
that family read about three it could not call. That is this item's own defect, reintroduced for
partial surfaces. Each fragment therefore carries the tools it names, `instructions()` requires all
of them, and `instructions_never_name_a_tool_the_client_cannot_call` asserts it over eight specs —
it fails on the group-level predicate, which was checked by putting that predicate back rather than
by reasoning about it.

Two things the entry did not anticipate. **`name` had to move with `instructions`**, because both
are literals on the same attribute and the macro reads them only while generating the `get_info`
that is now hand-written — left behind, the server would introduce itself as `rmcp` at the SDK's
version, which a protocol-tier assertion catches. And **the budget golden moves by seven
characters**: the whole-surface assembly is 1,983 against the constant's 1,990, which is the only
part of this a golden can see. What it cannot see is the direction that mattered — `crash` reading
927 characters instead of 1,990 — so that is asserted with two credentials on one listener, which
is the same shape every other per-client property here needs.

**What it actually bought, measured** (2026-08-24, the five `min` cells of
[`docs/local-model-eval.md`](./docs/local-model-eval.md) re-run against the fix). Unserved calls
went from 17 to 14, and both names that lived nowhere but the instructions — `execute` (3 calls)
and `decode_ioctl` (1) — went to zero and stayed there. The other two did not move: `debug_batch`
(9 calls, then 10) and `modules` (4, then 3), because the tools a `min` client *is* served name
them in their own descriptions. That remainder is item 41.

And **the context half of this entry is smaller than it reads** for anything but a client that
injects the string. The eval's own ollama driver discards `initialize`'s result past the protocol
version, so the three local rows' prompts never carried the 1,990 characters and their token counts
did not move by one. The 12%-of-prompt figure describes a client like Claude Code, whose rows sit
at ~27,500 tokens on this surface — where the saving is ~265 tokens, about 1%. The wasted *turns*
were always the larger cost of the two this item names.

## 41. [windbg-mcp] A served tool's description advertises tools the client is not served — **done** (2026-08-24)

Item 40 narrowed the `instructions` string per client. It is not the only prose a client reads: the
**description of every tool it is served** is the other, and those cross-reference tools that a
narrowed surface has removed. On `--tools crash` (eleven tools) there are five such references,
naming four tools:

| The client is served | and its description names |
| --- | --- |
| `open_dump` | `modules` — "not its module table, which `modules` lists" |
| `interrupt` | `go` — "a broad `s` search, a `go` that …" |
| `interrupt` | `debug_batch` |
| `end_session` | `debug_batch` |
| `crash_triage` | `backtrace` |

`--tools session,inspect,crash` keeps the three on `interrupt` and `end_session`; the whole surface
has none, by definition. Count them with a scan that skips plain `//` comments as well as code:
`interrupt`'s doc block is separated from its `#[rmcp::tool(…)]` by a note to the reader of the
source, so a walk-back that stops at the first non-`///` line misses two of the five — which is how
this entry first said four.

**Measured, on the same bench that found item 40** (2026-08-24): with item 40's fix live, the five
`min` cells still produced **14** unserved calls, and **13 of them** name `modules` or
`debug_batch` — exactly the three descriptions above. The fourteenth, Opus asking for
`list_modules`, is a name this server does not have anywhere, which is the floor this class has:
narrowing every string cannot take it to zero.

**What it took.** The shape item 40 used, moved one level down: a cross-reference comes out of the
doc comment into `TOOL_NOTES` (`src/server.rs`), which pairs the sentence with **every tool it
names**, and `WindbgServer::annotate` appends it in `router()` — after `Toolset::narrow`, so a note
whose own tool was dropped has nothing to attach to. `router()` is what `list_tools`, `get_tool`
and `call_tool` all take, so the surface is applied in one place and the call path pays sixteen
`format!`s it never reads, which is the trade the alternative (a second assembly for listing alone)
would have bought back at the price of a second place to get the surface wrong.

Four things the entry did not anticipate, and the first is why the fix is bigger than the table
above.

**Five was one surface's count, not the class.** Across *every* valid spec there are **22**
(tool, tool-it-names) pairs in **16** descriptions, carried by fifteen sentences. Six of the pairs
are inside one group — `backtrace`, `modules`,
`disassemble` and `dx` all point at `execute`; the three pool tools point at each other — and no
group spec reaches those, only `--tools <single tool>`, which is exactly the case review made this
server honour on item 40. Two more (`step_back` → `step_into`, `step_over_back` → `step_over`) were
invisible to any backtick-based count, because they were written bare.

**"Names a tool" needed a predicate, and both obvious ones are wrong.** Plain word-boundary
containment flags English: this prose says frames are "attributed to modules" and that a stuck
session "does not let go", and a rule that forbids the words *modules* and *go* is not one anyone
can write under. "Inside a backtick span" flags the debugger command a TTD tool quotes —
`dx @$cursession.TTD.Calls(...)` names the command `dx` is built on, not the `dx` tool. What works,
and is now shared with the instructions test: a code span that **is** the name or opens a call with
it (`execute { "command": "k" }`), plus bare-if-underscored, since an underscored name is an
identifier and never an English word. That last half is the only thing that catches `step_back`'s
"Reverse of step_into." — as copyable as any backticked name.

**The budget golden did not have to record a surface**, which this entry expected and used as an
argument against the fix. A note is a `const` appended to the description the macro already built,
so the *whole* surface reads what it read before plus 108 bytes and the golden still records
one row per tool — `docs/token-budget.md`'s per-tool rows keep their meaning. Lifting a trailing
paragraph out of a doc comment costs nothing at all: rmcp joins `///` lines with `\n`, so each
newline becomes a space inside one literal and five of the sixteen tools moved by zero bytes. What
*did* lose its meaning is **additivity of the group table**: `--tools crash` is 14,138 B against the
15,093 its two groups sum to, because narrowing now shortens the descriptions of the tools that
stay as well as dropping the ones it drops.

**Three references were reworded rather than moved**, because a note appends at the end and a
cross-reference in the middle of an argument does not survive the move. `interrupt`'s "a `go` that
has not hit anything" and `walk_memory`'s "a MASM `.for` loop through `execute`" are illustrations
rather than pointers — nobody calls either tool because they read the name there — and
`step_back`/`step_over_back` now name the WinDbg command they reverse (`t`, `p`), which the line
beside them already gives.

**What it cost and what it bought, statically.** The whole surface grows 67,658 → **67,766 B**
(+0.16%), which is the price of keeping the pointer for the client that can follow it. Every
narrowed surface shrinks: `crash` 15,073 → **14,138** (−6.2%), `session,inspect,crash` 25,265 →
**24,445**, and the floor — `session` alone — 12,161 → **11,265**. Off-surface names go to zero on
every spec, asserted two ways: `no_description_names_a_tool_the_client_cannot_call` walks the
tightest surface each tool can be served on (`--tools <that tool>`), which is the whole invariant
rather than a sample of it — a note ships only when its own names are served, so all a wider
surface can add is a sentence already cleared — and `two_clients_on_one_listener_are_served_two_surfaces`
puts `crash` and `session,inspect` on one port, since a golden records one surface and cannot see
the direction that matters. `the_whole_surface_reads_every_note` is the other direction, and is
what stops the fix degenerating into the "delete the cross-reference" option: deleting them would
pass every other assertion here.

**Measured** (2026-08-24, the same five `min` cells re-run against this;
[`docs/local-model-eval.md`](./docs/local-model-eval.md)). **Fourteen unserved calls became six**,
and the composition is the finding rather than the total.

**Every name this server was teaching is gone.** `debug_batch` was ten of the fourteen — gemma's
whole turn budget on one task — and is now zero, which with item 40's `execute` and `decode_ioctl`
empties that category. Harness refusals fall 9 → 4 with it, since `debug_batch` is what the
read-only fence was catching. Every row's prompt shrank too, unlike item 40: a description travels
in `tools/list`, which every row reads, where the `instructions` reach only a client that injects
them — −223 tokens on each ollama row, −307 on both Claude rows.

**But this entry overstated the `modules` calls, and the re-run shows the evidence does not carry
it.** It named `open_dump`'s description as what was advertising them. `open_dump` no longer names
`modules`, checked on the wire, and three calls came anyway — so the description is **not
necessary**. It does not follow that it caused none of the earlier three, because the callers
changed: nemotron, Opus and Sonnet before, qwen, gemma and Opus after, only Opus repeating. An
aggregate holding at three across a different set of models, one sample each, is a coincidence of
composition rather than a rate. Cause was claimed where the evidence supports a contributor.

**Every survivor is on `unloaded_driver`**, the one task whose answer lives in a tool a `crash`
client is not served, and each is a direct reach for a module listing (three `modules`, three
`run_command` carrying the same `lm m nvhda64v`). That is what a floor looks like — the surface
cannot answer the question, so a model that spots the missing capability is right and no prose
change stops it. **The 4 → 0 on answerable tasks does not prove it and was our own double count**:
all four were gemma's `debug_batch`, so they are the row above counted twice, not independent
evidence.

## 42. [windbg-mcp] The eval cannot tell a cause from a coincidence, because n=1 — **done** (2026-08-24)

Three runs of the `min` cells have now produced a correlation that review had to take back, and the
same shape each time: an aggregate that moved (or did not) across cells whose *composition* also
changed, read as though the surface were the only thing varying.

- **#209**: the re-run's cleanest correlation stated as a controlled test, which at one sample per
  cell it cannot be.
- **#212**, twice. `modules` held at 3 → 3 and was read as proving `open_dump`'s description had
  never caused it — but the callers went nemotron/Opus/Sonnet → qwen/gemma/Opus, only Opus
  repeating, so a steady total is composition rather than a rate. And "unserved on answerable tasks
  went 4 → 0" was a **double count**: all four were gemma's `debug_batch`, already counted in the
  row above it.

**What the grid can and cannot answer.** It runs one draw per (model, context, surface, task), which
is enough for what it was built for — failure *modes*, and whether a surface fits at all — and is
not enough for any statement of the form "X caused Y". `docs/local-model-eval.md` says so in as many
words ("one sample per cell is one draw") and that has not stopped three write-ups, mine included,
from reaching past it. The rule is not missing; the grid's shape is what makes it easy to ignore.

**What would close it**, and why it is a different experiment rather than a bigger one: *n* draws of
**one** cell with one thing varied, rather than more cells. The question that actually needs it —
did a description ever contribute to a `modules` call? — is a single A/B: the same model, the same
task, the same surface, with and without the sentence, repeated enough times to see a rate. That is
`local_model_drive.py` in a loop and a seed column in the record, not a change to the matrix runner.
It is deferred because the answer is worth little now: the sentence is gone either way, and the fix
does not depend on which of the two it was.

**Where it picks up.** The grader already keeps the last record per (cell, task), which is the thing
that would have to change first — repeated draws need to accumulate rather than replace. Give the
record a `draw` index, key on it, and report a distribution instead of a mark.

**What landed** (2026-08-24), which is the capability rather than the experiment — the A/B it was
written for is still not worth running, for the reason above. A record carries `draw` and `seed`
from both backends; a cell group asks for repeats with `draws: n`, which is a loop around the cell
and not a fourth axis; and every reader keys on the draw index, so `already_done` resumes per draw
(3 done and 5 asked for runs 4 and 5), `records` accumulates instead of keeping the last, and
`--matrix` prints `3Y2n` where it printed `Y`. **A record with no `draw` is draw 1** (`draw_of`),
so a run already recorded grades to exactly what it graded to — checked against the two logs this
bench still has, whose `--grade` and `--matrix` output is byte-identical either side of the
change.

**Two things the entry did not see.** The first is a measurement that contradicts it: *"a seed
column in the record"* was written on the assumption that a seeded draw can be replayed, and on
this bench it cannot — four identical requests to `qwen3.8:27b-mlx` under `seed: 7` returned four
different answers (ollama 0.32.15, MLX). The seed is still sent and recorded — sending it costs
nothing, and a runtime that does reproduce under it would pair the arms of an A/B — but every
sentence around it now says the column is what was *asked for*. Unmeasured, it would have shipped
as a replay guarantee in the comments and in all three documents this touched. The second is smaller and is the deletion trap in reverse:
the rule that a cell-level failure note is superseded by later records of that cell had to learn
about draws too, or draw 4 dying would be un-recorded by draw 5 completing afterwards.

## 43. [windbg-mcp] `unserved` is two different measurements sharing a column — **done** (2026-08-25)

The metric was renamed from `hallucinated` when the first grid found that a model asking for a tool
it could not call was usually reading this server's own advertising. Items 40 and 41 removed that
advertising, and the number that remains is no longer measuring the same thing:

- **Names this server taught.** `execute`, `decode_ioctl` (item 40), `debug_batch` (item 41). Now
  **zero**, and a regression here is a defect in this server.
- **Capabilities the surface does not have.** The six survivors, all on `unloaded_driver`, whose
  answer lives in `modules`'s `unloaded` list — three asking for `modules` and three for
  `run_command`, which does not exist. A model that spots a missing capability and reaches for it is
  *right*; the surface is what says no.

Summed, they hide each other: the first going to zero looks like a 57% improvement rather than an
elimination, and the second could grow without anything being wrong. The task's own `possible_on`
already carries what separates them, so this is a grader change and not a new measurement — split
the column into `taught` and `wanted`, and let a regression test assert only the first.

**Why it was deferred, and what changed.** The argument was that `taught` was zero, so the sum
happened to be the interesting number by accident, and the split would re-grade runs to prove a
partition no present data disagreed with. Both halves of that turned out to be wrong: `taught` was
not zero (the paragraphs below), and the re-grade is what *demonstrates* the partition rather than
what costs it — the two logs on disk split **4+10** and **0+6**, so item 41's fix reads as an
elimination of the half it was aimed at rather than a 57% improvement in a total.

**What landed.** `possible` already said whether the answer key was reachable on this surface, so
the split is that predicate and no new measurement: `taught` when the task *was* answerable here
and the model still reached off-surface, `wanted` when it was not. The table prints `t+n` in the
slot that held one number, so the sum stays readable and the halves stop hiding each other.
`--grade --assert-no-taught` exits non-zero on a taught call, which is the regression this item
asked for; `wanted` is deliberately not assertable, being a property of the task list and the
surface rather than of this server. And `taught` prints its offenders by name — "`debug_batch` on
`arm64_pc`" is checkable, where "taught: 4" is a number to argue about.

**What the split does not do**, stated here because the entry that proposed it did not know yet:
it attributes by **need, not provenance**. This server taught `modules` through an opener's result
until [#217](https://github.com/glslang/windbg-mcp/pull/217), on `unloaded_driver`, which is also a
task `min` cannot answer — so those calls are `wanted`. `taught` is a lower bound on advertising
and `wanted` an upper bound on need. Separating them properly needs one cell repeated with the
sentence varied, which is item 42's `draws` and not a fourth column.

**A third channel was checked, and the checking is worth more than the result** (2026-08-24,
prompted by the reasonable question of how a model on an eleven-tool surface produces the *exact*
name `modules` with its real `filter` argument). Items 40 and 41 closed the `instructions` string
and the tool descriptions; nobody had looked at what a **result** says, which is the third thing a
model reads and the only one that arrives on every call.

**The first scan reported "none" without having compared anything.** It read each call's `text`,
and a call record carries `excerpt` — so the loop body never ran, and "none" meant "nothing was
looked at". The number quoted beside it was audited and the scan behind it was not: a "59-name
superset" is 51 tool names plus the eight JSON field names (`annotations`, `description`,
`instructions`, `name`, `payload`, `tools`, `totals`, `wire`) that a recursive walk of
`tests/golden/tool_budget.json` picks up, which Codex asked about on
[#216](https://github.com/glslang/windbg-mcp/pull/216) and which is how the empty loop surfaced.
The rule underneath is the one this repo already writes down twice — *a grep is not an
enumeration*, and a monitor's *silence is not success*: *a scan that can only print on a hit proves
nothing until it has been shown printing on a known one.*

**Redone against `excerpt`, sixteen results do name a tool their client is not served — and every
one is the model's own request coming back.** Nine are the ollama driver's own refusal — the one
that names the tool it is refusing, "`debug_batch` is not permitted in this harness" — four are
Claude Code's "No such tool available: `mcp__windbg__…`", and three are **this server's**
`-32602`. Nothing is *introduced* **in the part of a result the log kept** — and the qualifier is
the whole finding, because outside it something was.

**It was wrong, and the truncation bound is what was hiding it** (2026-08-25, one day later). An
opener's summary ended with "`modules` lists a page of the table and `modules {"filter":
"<name>"}` answers for one", built by `summary_text` in the **worker** — which owns one session and
has never heard of a client, let alone its surface. `modules` is `inspect`, so on the bench's own
eleven-tool `crash` surface the *first result a client ever saw* handed it the exact name together
with its real argument. `crash_triage` rode along the same way, and `post_commit_failure` sent any
caller to `execute`. So `taught` was **not** zero on this channel; it was the largest of the three,
and it is the one that arrives on every call rather than once a conversation.

Three things about how it stayed hidden, each of which is the real lesson:

- **The scan could not have found it.** The excerpt is 300 characters of a 2,508-character summary,
  and the sentence is at the end. Codex's round-2 bound was not a hedge about a hypothetical; it was
  a description of where this was sitting.
- **What found it took no run at all.** The question is what this server *prints*, not what a model
  does with it, so it is answerable by reading `src/` — a scan of string literals against the tool
  table, seconds on a laptop, no bench and no VM. Two channels' worth of eval work had been spent
  on a question that was static all along.
- **The eval's `modules` calls have a documented cause now**, so the "a mixture is what guessing
  looks like" reading above is undercut for `modules` specifically: the name and its `filter`
  argument were both in front of the model. The invented ones (`list_modules`, `run_command`) still
  read as guesses, but that is a claim about the survivors, not about the three.

Fixed by `SUMMARY_NOTES` and `WindbgServer::annotated_report` — [`ToolNote`]'s rule one channel
over, with `no_opener_report_names_a_tool_the_client_cannot_call` as its invariant. The same scan
found two more: a post-commit failure's `execute` example, and `crash_triage`'s user-mode refusal,
which pointed at `backtrace` and `execute` — both `inspect`, while `crash_triage` is `crash`, so
the caller most likely to reach it could act on neither half. A third was left alone as
unreachable: the "a `debug_batch` is running its rollback" message needs a client served
`debug_batch` to have started one.

**What is still open here** is the count, not the leak. `unserved` is still one number, and the
three runs on disk cannot be re-graded into `taught` and `wanted` — but the partition now has a
known instance on the `taught` side rather than none, which is the evidence the entry above says
it was missing. The next run against a prose change is where it gets made.

**That is zero within the prefixes the log keeps, and it cannot be stated wider than that**
(Codex's second round on #216, and correct). `local_model_drive.py` records `text[:300]`, so 96 of
the 114 results are truncated and 29,946 characters of a 208,266-character corpus were compared: a
name mentioned late in a long module listing is invisible to this scan by construction.

**The whole-result version needs no new code, and it is not the same corpus** — the third round of
the same review, also correct. `Recorder::tool_result` writes each result's text into the server
transcript, scrubbed then capped, and `WINDBG_MCP_TRANSCRIPT_MAX_FIELD=0` lifts the cap, so
`WINDBG_MCP_TRANSCRIPT` on the bench listener records every *served* call's result whole. It
records none of the sixteen: an off-surface call is refused at the top of `WindbgServer::dispatch`
(`src/server.rs`) and returns before `rec.tool_request` runs, and the other two refusals are the
ollama driver's and Claude Code's, which never reach this server at all. That is not a gap in the
answer, because those three classes are exactly the ones that **cannot** introduce a name: each
quotes the tool the caller just asked for, and ours adds only group names — a group that is also a
tool name is refused outright (`src/toolset.rs`) — and, for a partly-held group,
tools the client *is* served. So the transcript covers the bodies, which is where an introduction
could hide; the eval log covers the refusals, which are echoes by construction; a scan wanting the
model's whole view reads both.

**And a transcript scan can only over-count, which is why a null from it still means something**
(fourth round, same reviewer). The transcript holds *both* halves of a result, and a client that
understands structured results forwards `structuredContent` and drops the rendering — a forwarding
policy, not protocol, which `tool_results_stay_within_their_budget` exists to keep both sides of and
which applies to the 31 tools that have an output schema. So a name living only in the half the
client discarded was never read by the model, and a transcript hit is a *candidate* rather than a
sighting. It bites the two Claude Code rows and not the three ollama ones, whose driver appends the
result's text verbatim as the tool message. The consequence is one-directional and worth stating in
the entry that plans the scan: a **null** result from the transcript is sound, since neither half
named anything; a **positive** has to be checked against which half that client forwarded, and
capturing the whole `tool_result` in `claude_code_drive.py` is what would settle it without
reproducing a policy that can change under us.

What no route reaches is *these* two runs: nothing kept the bytes the driver discarded, so this one
cannot be answered backwards.

Names have to be matched the way
`no_description_names_a_tool_the_client_cannot_call` matches them — bare if the name has an
underscore, in call context otherwise — because plain containment scores `execute` eight times
inside `ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY` and "the attempted execute", and because a
lookbehind of `[A-Za-z0-9_]` silently drops `mcp__windbg__debug_batch`.

**The one of those three that is ours is not neutral, and the split has no box for it.**
`Toolset::refusal` (`src/toolset.rs`) answers a narrowed client with "`modules` is a tool this
server has, but it is not on the surface it serves `min` (11 of 51 tools (session, crash))", and
then how to widen it. That is deliberate, and the doc comment says why: the reader it is written
for is an operator who can see neither this server's command line nor its client list. On the
bench the reader is the model, and what it gets is a **guessed name confirmed as real**, beside the
surface's group names and the size of the full one. It teaches no name — the model supplied it — so
it is not `taught`; it is not nothing either. A third count, *a refusal that says yes*, is what
this channel would contribute to the split. In these logs it changed no behaviour — nobody retried
a name after being told it was real: gemma went from `modules` to `run_command` three times and
opus to `list_modules`, while the retries that did happen (`debug_batch` five times, then four)
follow the *driver's* refusal, which confirms nothing. That is one draw per cell, though, and a
retry is precisely what the confirmation would buy.

**What the survivors' *shape* says, and where it stops.** The names asked for are a mixture of real
and invented — `modules` (3) beside `list_modules` (1) before item 41, and `modules` (3) beside
`run_command` (3) after it, the latter carrying `{"command": "lm m nvhda64v"}`, which is the right
idea under a name this server does not have. A model copying an advertisement produces exact names
only; a mixture is what guessing looks like, which is evidence for the `wanted` reading of the
remainder. Two things keep it from being proof. The *concept* is still on the narrow surface even
though the name is not — `open_dump` ends "…module count and the bug check a crash dump stopped on
— not its module table", and the task prompt says "how many **modules** are loaded" — so a model is
told a module table exists and has to name a tool for it. And this is a public repository, so
prior exposure cannot be excluded at one draw per cell. Separating memorised-from-GitHub from
guessed-by-convention is item 42's machinery (the same cell repeated with that sentence varied),
not this item's.

## 44. [windbg-mcp] `arm64_pc` is answered the way it reads, not the way it is keyed — **done** (2026-08-25)

The eval's `arm64_pc` task asked for "the value of the `pc` register at the point of the crash" on
the ARM64 sample, and its key is `0xfffff8013c65bca8`. **Across the 35 runs of it in the three logs
still on disk, no model on any surface gave that answer, and 32 gave `0x0000019e7b820000`** — the
bug check's first parameter. Five draws of five models on `min` (2026-08-25) is `5n` in every row,
frontier rows included, which is what made it visible: at one draw per cell it read as a hard task.

**It has been answered correctly once**, in the original grid — qwen, reasoning that frame 0 of the
bug-check stack *is* the `pc`, which is exactly the route the key wants and is written up in
`docs/local-model-eval.md`. That log is no longer on disk, so the honest figure is roughly one in
fifty rather than none in thirty-five (Codex caught the stronger claim on
[#219](https://github.com/glslang/windbg-mcp/pull/219), against this repo's own published text).
It matters in the right direction: the task *is* reachable and the route *does* work, so what is
wrong is only that almost nobody reads the question that way.

**Both answers are defensible, and the debugger says so.** Measured on the dump:

- `registers` reports `pc = 0xfffff8013c65bca8`, and `crash_triage` frame 0 is the same address,
  `nt!KeBugCheck2+0x2e8`. So the key is literally right and the note claiming `min` can reach it
  through frame 0 is right too - the route works.
- That address is inside the **bug-check path**, which the machine reached *after* the fault. The
  address whose execution faulted is parameter 1, `0x0000019e7b820000` (also in `x24`), and
  `nt!MiCheckSystemNxFault` two frames up is the handler for exactly that.

So a model answering "the pc at the point of the crash" with the faulting address is reading the
question the way a person would, and the key wants the register's literal value in a context that
is not the crash. **A task passed once in about fifty attempts is measuring its own wording**, not
the surface it was written to probe.

**What landed.** The prompt, not the key: it now asks for "what value the pc register holds in the
crash context the dump saved - the register's own value as the debugger reports it, not an address
taken from the bug check's parameters". Widening `expect` to accept parameter 1 stayed rejected for
the reason above, and re-measuring on the dump gave it a second one this entry had not stated:
`open_dump`'s summary carries all four parameters, so a key accepting parameter 1 would let the
task pass off the *opener's* result with neither `registers` nor `crash_triage` called - the exact
route it exists to check would be the one route not taken.

**The entry's own suggested wording was not enough, and that is a judgement rather than a
measurement.** "In the crash context, as the debugger reports it" removes the phrase that invites
the faulting-address reading, but it leaves the reading itself available to a model that believes
the bug check's parameter *is* the `pc` - which is what 32 of the 35 recorded runs believed. So the
prompt names what the answer is not. That cannot hand the answer over, and it keeps the tool route
required; what it costs is that the question now mentions the bug check at all. Nobody has measured
the shorter wording, and what would settle it is item 42's `draws` on one cell with the sentence
varied - the same A/B this bench keeps deferring.

**Re-verified before rewriting anything**, since the numbers above were the whole argument and
were inherited rather than measured here. Both dump readings again, and the log breakdown finer
than "no model gave that answer": of the 35 runs, **0** gave the key, **32** gave parameter 1, and
the remaining **3** answered nothing at all - two closing the session and reporting that, one
empty. So the split is not 33 wrong readings and 2 failures; every run that produced an answer
produced the same wrong one.

**The other five were checked, and none has it - but the corpus only stretches to four.** The three
logs are `min` cells, so `unloaded_driver` and `ioctl_decode` have no answers in them at all
(neither is answerable on that surface); those two were checked by reading the prompt against the
key. The other three grade **33 of 35** correct each, and all six failures between them are
non-answers or noise - three that closed the session and said so, one empty, one turn that ran out
mid-narration, one invented module count - rather than a second reading anything agreed on.

**`driver_blame` is the near miss, and it is what sharpened the rule.** It asks "at what offset into
that driver did it fault", and the key `0x1654` is frame 7: the address `nt!ExFreePoolWithTag`
returns to, not an instruction that itself faulted. So the prompt is loose in exactly the way
`arm64_pc` was - and it is *not* the same defect, because no model takes the other reading: 33 of
35 give the key, and `crash_triage` calls that frame `faulting_frame`, which is the vocabulary the
question borrowed in the first place. **A wording defect shows up as agreement on a different
answer, not as imprecision**, which is the check to run rather than re-reading prompts for rigour.
Recorded in that task's `note` rather than fixed, so its published numbers stay comparable.

**A reworded task un-grades its own history, which review caught and the first attempt had not**
([#220](https://github.com/glslang/windbg-mcp/pull/220), Codex). `usable()` drops any record whose
stored `prompt` differs from the one the suite asks now - deliberate machinery, added when this
bench reworded `unloaded_driver` mid-flight - so changing the live suite quietly took `arm64_pc`
out of every checked-in plan. Measured on `after-217.jsonl`: the denominator went **20 to 15** per
cell and 25 of the 150 records became `UNCOUNTED`. Worse, a *resume* of either checked-in plan
would re-run the task and append new-wording answers under the same `(cell, draw, task)` key as the
old ones, where `records()` keeps the later - one log, two experiments, nothing saying so. **A
run's identity includes the question it asked**, so the old wording is frozen as
`tools/eval_tasks_v1.json` and both historical plans name it: `after-217.jsonl` grades to 20 again
and resume counts 150 of 150 done. The live suite is `v2`. And the one uncounted reason a reader
can *act* on now says so under the table, since a served window that was not the one asked for is
unrecoverable while a changed question is only the wrong suite - `stale_prompt` is split out of
`usable` rather than restated inside it, so the predicate keeps one home.

**My own verification of this was wrong, and the way it was wrong is worth keeping.** "Grades
unchanged" was checked by running `--grade` and reading the numerators, which did match. The
denominators did not, and the rows said `UNCOUNTED x5` in plain sight. Re-grading proves nothing
unless the comparison is against the *previous output* rather than against expectations.

**Where the published numbers stand.** `docs/local-model-eval.md` now says, once and above every
table, that every score in it was graded against the old wording and is not comparable with a run
against the new one on this task. The suite `note` in `tools/eval_tasks.json` says the same for
anyone reading the task file first. Nothing about the server was wrong here, so the grid's *server*
findings (items 40, 41, 43, and #217) are unaffected, and the next run starts against a question
with one reading.

## 45. [windbg-mcp] The eval's answer key is a snapshot, and nothing checks it still holds — **done** (2026-08-25)

The six tasks are graded against facts read off the checked-in dumps **with this server's own
tools**, before any model saw them. That is what makes the bench mechanical, and it is also the
whole exposure: if one of those facts stops being what the server reports, the suite keeps grading,
every model keeps scoring, and the number measures nothing. A key that rots is indistinguishable
from a model that got worse.

**Part of it was already pinned, in `tests/mcp_smoke.rs`** — the debugger tier reads the same dumps
and asserts bug check code and name, `Arg1`, the crashing process, and each driver crash's
`module` + `rva` + kernel frame (`DRIVER_CRASHES`, `NATIVE_SAMPLE`). What was *not* pinned was the
rest of what the tasks depend on:

| Fact a task is keyed to | Asserted by the tier? |
| --- | --- |
| bug check `0x13a` / `0x9f`, and the names | yes |
| `MessageManager+0x1654` | yes |
| `nvhda64v.sys` unloaded | yes, as a **relation** — not the **26** records `unloaded_driver` asks for |
| module counts **227** / **158** / **177** | no |
| the four `0x22200B` fields | no — the tier exercises `0x70000` |
| `pc = 0xfffff8013c65bca8` | **no** |

**The last row is the one that made the case**, and it is exactly item 44 wearing its other face.
`NATIVE_SAMPLE` pins `first_parameter: "0x0000019e7b820000"` — the address 32 of 35 recorded runs
gave — while nothing in this repo pinned the `pc` the task is actually keyed to. Both halves of the
ambiguity are named in the codebase, in two different files, and the half the eval depends on was
the unasserted one.

**What closed it.** `--verify-key`, beside `--grade` in `tools/local_model_eval.py`, driving the
server and re-reading every fact through the tools a model would call. That was the first of the
three shapes this entry weighed, and the argument for it is unchanged: the oracle is `present()`,
whose three rules were each learned from a wrong verdict, so a Rust gate would need a **second copy
of it** — and two copies drifting apart is this item's own failure mode reached through this item's
own fix. The cost taken deliberately is that CI cannot run it: it needs a listener and a
credential, so it is a command for after a `win-kexp` bump, a symbol-path change or a new sample,
and the run says so on every pass. The Rust tier goes on pinning what it already pins.

**The binding is per task and carries the inputs**, which is what review found this entry lacking
and what defeated all three shapes as first written: `expect` said what an answer must contain and
nothing structured said what to *call* to get it. Each task now carries `verify` — an ordered list
of `(tool, args)` steps with the values expected back — and the prompt is checked as a **rendering**
of it: every string a step sends must appear in the question, and every dump the question names
must be one a step opens. A prompt repointed at another sample is now a failure rather than a
verifier quietly querying the old one.

**Three things it needed that this entry did not anticipate.**

- **`expect` cannot be *derived* from the binding**, which is what this entry's own sentence
  claimed. Two of `unloaded_driver`'s three groups are phrasings of a **relation** — "not loaded"
  is what `matched: 0` *means*, not a string the server prints — so the binding **grounds**
  `expect` rather than generating it, and each run reports which groups are tied by `value`, which
  by `relation`, and which were `skipped` at a gate on this host. The relation groups are not a
  hole: the fact behind them is pinned exactly, and only the phrasing is beyond a mechanical check.
  **But which groups those are has to be declared, not inferred** — a correction review made, and
  the sharpest finding on the PR. Reading "no pinned value matched" *as* a relation meant a group
  edited to a value the tools do not answer (`ACCESS_VIOLATION` for a bug check that is
  `KERNEL_MODE_HEAP_CORRUPTION`) reported `relation` and passed: a broken key, against which every
  model would be graded wrong, reached through the very mode meant to catch one. So `grounds` is a
  value claim and **fails** when nothing renders it, `states` is the declared-relational one, and
  the exemption covers the two groups that earn it rather than spreading to whatever happens not to
  match. The next round found the same hole pointed the other way — *appending* an alternative
  beside one that still matches widens what the grader accepts while the run stays green — so a
  `grounds` group is checked **alternative by alternative**: each must render, or be a *spelling*
  of one that does (letters and digits only). That is what lets the suite keep `heap corruption`
  beside `heap_corruption`, and refuses `access_violation` as a second fact rather than a second
  spelling.
- **A second verb, for a tool with no structured half.** `decode_ioctl` answers in prose alone, so
  a binding that could only name a field would have had nothing to say about the one task needing
  no target at all — the cheapest half this entry singled out. `is` is exact typed equality against
  a named field; `has` is `present()` over the text, used exactly once.
- **The ratchet is coverage, not the pins.** A group **no** step grounds is a failure, which is what
  stops `expect` growing an alternative the binding does not fetch, and stops a new task arriving
  unpinned. Verified against a deliberately rotted copy of the suite: a moved fact, a renamed
  field, a repointed prompt, an ungrounded group, a group edited to something the server does not
  say, a group widened to also accept something else, a relation whose supporting pin was
  deleted, a gated step ordered before its opener, and a stale text pin all fail — nine channels —
  and the clean suite passes. Five rounds found one shape — a value that could not be obtained read
  as a benign default — in five places, so the choice generating it was deleted rather than patched
  a fifth time: one helper reads a structured field and answers a value or a reason, and nothing in
  this mode carries an `or []`. A sixth round found the last place it could hide - a renamed
  `symbols` on the `nt` record reads as `None`, which is not a PDB-backed state and so closed the
  gate on drift - and two blind spots in the cleanup this mode had newly come to depend on: the
  driver's `end_sessions` read a structured tool error but not a top-level protocol one, and
  `close_transport_session` printed a failed `DELETE` without reporting it. Both are fixed in the
  driver rather than worked around here, since three callers share them. A seventh round took the
  same rule to its end - a `symbols` that is no longer a *string* would have read as "no PDB" - and
  found that the pins themselves were laxer than their own docstring: Python's `==` accepts
  `False == 0` and `227.0 == 227`, so a `matched` turning from the integer `0` into `false` passed
  the pin *and* the relation resting on it. Types are compared now. Half of that round's remedy
  was declined: checking `symbols` against a *recognized* set would fail on a state win-kexp
  legitimately adds, and a new symbol state is not a rotted key.

**And a pin can be too tight.** The first cut pinned the `pc` register as `registers.32.value` —
its position in the ARM64 bank, which is an engine detail rather than anything the key rests on, so
a reordered bank would have failed a key that had not rotted. A `read` path now enters a list two
ways: `frames.0` by position, `registers.name=pc.value` by the register's own name.

**Which corpus, said rather than implied.** The run names the dumps it re-read and then names the
one it did not: `answer_key` is prose and nothing reads it — `grep` still finds no consumer, and
`matches()` grades from `expect` alone — and it documents `082126-7015-01.dmp`, which no task
references. Reporting the gap is the honest form of the choice, rather than a test covering more
than the suite asks or less than the key claims.

**And the gate is per dump, not per host** — the second thing review caught, and this repo already
had the measurement: `docs/smoke-test.md` records an engine failing *differently per dump*, because
each sample has its own `nt` with its own PDB identity. A gate probed once off the first opener
would therefore have stood the ARM64 frame-0 step down because an *x64* PDB was missing, and
reported success without checking the route `arm64_pc`'s `possible_on: min` rests on. It is asked
of each task's own session now, as the Rust tier asks it — and **a probe that fails is not a closed
gate**, which the round after that caught: a gate that closes stands its steps down and *passes*,
so a probe answering an error would have turned every gated assertion into a silent no-op. The
round after *that* took it one level in: a `modules` answer with no module list, and a kernel target
with no `nt` in a listing filtered for it, are drift too - only "`nt` resolved, without a PDB"
closes the gate. And a `states` group now **names the pins its relation rests on**, because claiming
it by the step alone meant deleting the `matched` pin left the relation reported and nothing
failing. And a gated step with **no target to probe** - a binding reordered so it precedes its
opener - is a binding failure rather than a closed gate, since the closed answer stands it down and
passes.

**Two lifecycle defects came in with it, both from plumbing this reimplemented rather than reused.**
An opener that registers a session and *then* fails reports the only handle that can reach it inside
the error, and the first cut dropped the result on that path — so the target leaked, and repeated
runs against one drift would have met the four-session cap instead of reporting the drift;
`local_model_drive.opened_session` already reads both places that handle can be, and is now what
reads it — and an opener whose *answer went missing* may have opened a target too, so the driver's
`reconcile_opened` handles that ambiguity here as it does there, which in turn made the ownership
baseline load-bearing: without it a reconciliation adopts, and then ends, whatever the credential
already held. And the MCP transport session was never closed, so repeated verifications piled up on
the listener until the lease grace; what `end_sessions` could *not* release is now retried once and
reported, since discarding it announces a clean namespace the run has not got. Both are the same shape as the accumulation rule in `CLAUDE.md`,
seen small: a parallel path beside one that already worked. The cleanup then had to move one
request earlier still, since the handshake is *two* requests and a failure between them leaves an
id nothing deletes.

**Gating: `docs/smoke-test.md` draws that line and this keeps no second copy of it.** Three review
rounds on [#221](https://github.com/glslang/windbg-mcp/pull/221) were corrections to a second copy
kept in this entry — first too wide, then too narrow — so `GATES` holds the sentence a stood-down
step *prints* and that file holds the rule. `arm64_pc` is asserted through **both** routes, since
its `possible_on: min` rests on `crash_triage` frame 0 and `registers` alone would not be checking
it; the frame-0 half takes the gate, opens the dump itself rather than inheriting a session, and
passes `analyze: false` — frame 0 is the crash context on a freshly opened dump and otherwise
whatever the session has selected.

**Nothing was wrong when it landed**, which is what makes this protection against future drift
rather than a bug fix: all three dumps were re-read on 2026-08-25 and every fact the tasks depend
on still holds. What will move it is an engine or `win-kexp` bump, a symbol-path change, or a new
sample replacing an old one.

**Where it picks up.** `tools/local_model_eval.py` (`--verify-key` and the helpers under it),
`tools/eval_tasks.json`'s `verify` blocks, and `docs/local-model-eval.md`. `tools/eval_tasks_v1.json`
deliberately carries **no** binding — it is the wording published logs were graded against, and the
mode refuses it by name rather than skipping it quietly.


## 46. [windbg-mcp] A run can be graded but not compared, because nothing records what it ran against

**Re-running a cell is the point, not a hazard.** As models are updated the same question on the
same surface will be asked again, and what will matter is run N against run N-1 - the frozen suite
(#220) exists so a *reworded question* cannot silently un-grade its own history, which is a
different thing from discouraging a rerun. A rerun into a new log with a new plan is exactly what
this bench is for. What it cannot do today is **compare two of them**.

**A record identifies the question and the surface, and neither of the two things that change over
time.** It carries `prompt` (the question identity #220 leaned on), `surface` with its client,
tool count, byte size and names, plus `served_context`, `seed` and `draw`. It does not carry which
*model weights* answered or which *server build* was asked.

- **The model is a mutable tag.** `qwen3.8:27b-mlx` is a name that can be re-pulled onto different
  weights, so two runs a month apart can agree on every recorded field and have been different
  models. This is the axis the whole comparison is about.
- **The server build is absent entirely.** `surface.bytes` is a real fingerprint of the tool prose
  and did move when item 41 landed (8,654 -> 7,732 on `min`), but it is a fingerprint of one
  channel: [#217](https://github.com/glslang/windbg-mcp/pull/217) changed an **opener's result**,
  which no tool-list byte count can see. So the field that looks like a build identity is silent on
  exactly the channel the last three findings were about.

**Both facts are already on the wire and already parsed, and both are thrown away** - which is the
same shape as the `served_context` lesson and should be read the same way:

- `local_model_drive.py:served_context()` calls `/api/ps` and reads `context_length` off the
  matching entry. That response also carries the model's **`digest`**, which is a content address
  rather than a name. **This is the ollama rows only**, and the entry should not have implied
  otherwise: `claude_code_drive.py` records `"model": MODEL` — `opus`, `sonnet` — which are
  mutable aliases resolved inside a client this bench does not own, and there is no `/api/ps` to
  ask. So the two control rows keep the ambiguity the digest removes from the other three, and
  what is available to them (the `claude` CLI version, the alias as written) is a floor rather
  than an identity. That file already has the right habit for this: its `seed` is `None` with a
  comment saying why the row cannot have one, which is what a null digest should look like beside
  it rather than an absent field. Naming a real version source for a Claude row is open, and
  scoping the claim to what can actually be recorded is the minimum.
- The handshake at `local_model_drive.py:264` returns `out["result"]["protocolVersion"]` and drops
  the rest of the `initialize` result - including `serverInfo.version`, which this server does
  send (`src/server.rs`, `with_server_info(... env!("CARGO_PKG_VERSION") ...)`).

**But the crate version is a floor, not an identity**, and the entry should not pretend otherwise:
it moves on release, so two builds of one version are indistinguishable - the same trap the
service-image warning already names in `CLAUDE.md`. Recording it is strictly better than recording
nothing and is not sufficient; a build SHA would be, and that means deciding whether this server
reports one. That decision is the item, not the two lines that record what is already there.

**What would close it.** Identity fields on every record - model digest where one exists, server
version (or SHA), suite id - and a **compare mode** over two logs, with two rules that are not the
same rule.

**Pairing refuses at the task, it does not annotate.** A cell pairs on `(backend, model, ctx,
surface, task)`, but a task id is not the question: `arm64_pc` has the same id in
`tools/eval_tasks_v1.json` and `tools/eval_tasks.json` and a materially different prompt, so
pairing on id would put two distributions side by side that #220 established are not comparable -
and would be *weaker than the grader already is*, since `usable()` refuses such a record outright.
The predicate for this already exists and has a home: `stale_prompt`, split out of `usable` in
#220 so the reason could be named rather than restated. A compare mode reuses it and renders that
row as incomparable with the reason, at the row rather than in a header - which is the same
principle as the `UNCOUNTED` line beside it. (`expect` can move too; a pairing predicate that
reads only the prompt is a floor.)

**The run-identity line is for what is left**, and that is its actual job: the uncontrolled
variables that are *not* the question - model weights, server build, served window. Naming them
above the table is not a nicety, because this repo has three times read a moved aggregate as a
controlled result (items 42 and 43, and twice in
[#212](https://github.com/glslang/windbg-mcp/pull/212)), and every one was a *composition* error -
the callers changed and the total held. But a note is the right instrument only for a variable a
reader can weigh. A changed question is not one of those; it blocks the comparison.

**And the reporting is the other half.** `docs/local-model-eval.md` accumulates a prose section per
run, which reads well and cannot be diffed: the three tables in it measure three different servers,
which the page says in words and no reader can check. A machine-readable series - one row per run,
keyed by the identity above - is what makes "comparison with historic data" a query rather than a
re-reading.

**Why deferred.** Nothing already published is wrong, because each write-up names its own server
build in prose; what is missing is the ability to *check* that, and to do it for a run nobody has
written up yet. It wants doing before the next model refresh rather than after, since a run
recorded without identity cannot have it added later - which is the one part of this that expires.

**Where it picks up.** `tools/local_model_drive.py` - `served_context()` and the handshake, both of
which already make the call that carries the fact; `tools/local_model_eval.py` for the compare mode
beside `--grade` and `--matrix`; and `docs/local-model-eval.md` for what a versioned report looks
like.
