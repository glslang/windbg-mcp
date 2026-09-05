# Follow-ups

Deferred work, in sixteen clusters: items 2–6 come from the reachability-confirmation effort (path
recipe + `run_to_address`, merged 2026-07-04), items 8–9 and 11 from surveying this server against
the MCP `2026-07-28` extensions (tasks, apps), item 13 from the bounded-command coverage review (#46,
2026-08-02), item 15 from the private worker channel (#65 / #72, 2026-08-04), item 19 from
`walk_memory` (#103, 2026-08-13), item 27 from completing the coordinate work (#156–#158,
2026-08-18), item 32 from running the debugger tier on the ARM64 runner image that replaces
`windows-11-arm` in September 2026, items 33 and 39 from driving the server with a **local model** —
the lease grace measured against the wrong slow party (2026-08-22), and then running the surface,
the window and the model as a **grid** rather than as a sighting (2026-08-23) — item 35 from
measuring what a `registers` answer is actually made of (2026-08-22), item 47 from fixing
[#226](https://github.com/glslang/windbg-mcp/issues/226), where making every target take the bounded
wait left one target type nobody on this bench can measure (2026-08-25), item 50 from Windows
Defender quarantining this project's own binary while the 32-bit worker was being tested
(2026-08-26), items 52–53 from [#83](https://github.com/glslang/windbg-mcp/issues/83)'s asynchronous
execution handles, where the invariant that stops a description naming a tool its client cannot call
turned out to cover only half the prose a client is served (2026-08-29), and where a break arriving
in the microseconds after a run built its stop is recorded in that result's prose and not in its flag
(2026-08-30), item 54 from
[#85](https://github.com/glslang/windbg-mcp/issues/85)'s module-inventory refresh, whose engine call
no watchdog in either crate can currently cut short (2026-08-30), item 56 from closing item 14 —
collapsing the coverage rule to "bound every command except `index_trace`" meant enumerating the
`Execute` calls rather than the ops, which found one left on a shared helper that three callers
reach on three different clocks (2026-08-31) — and item 58 from
[#286](https://github.com/glslang/windbg-mcp/pull/286)'s user-mode fault triage, where the engine
call that names a target's machine turns out to name the *processor's* (2026-09-05).
Each item notes its repo, why it was deferred, and where it picks up. See
[`DECISIONS.md`](./DECISIONS.md) for the design rationale (D1–D5) items 2–6 extend, and the
2026-08-02 entries that item 13 extends.

**Items that have landed are in [`DONE.md`](./DONE.md), under the numbers they were filed with**,
which is why the numbering here is sparse — its index is the list of them, and is the one list, so
there is nothing here to fall out of step with it.

Nothing is renumbered when it moves, and **nothing that cites an item is retargeted either**. Some
twenty files say "`FOLLOWUPS.md` item N" — doc comments in eleven modules and in `tests/`,
`CHANGELOG.md`, `DECISIONS.md`, every `docs/*.md`, `build.rs`, `ci.yml` and the eval tooling — so a
citation whose *file* half followed the entry would make closing an item a sweep of source
comments, with nothing to catch the ones missed. "Item N" is the stable name; this paragraph is
what answers *which file*, for whoever followed a citation here.
`engine::every_followups_citation_names_an_item_that_exists` is what keeps that true: an entry
deleted, renumbered, or moved without reaching `DONE.md`'s index fails the build rather than a
reader.

Two kinds of item stay here rather than moving. One that is **measured and declined** (27, 35): each
records the measurement that settled it and the condition that would reopen it, and item 35 leaves a
judgement call open. And one that has **half** landed (2, 50) — the entry is narrowed to the half
that is left rather than split across two files.

Items are roughly ordered by how soon they're worth doing, within each cluster.

## 2. [dbgscope] Typed write primitives

`write_virtual` and a typed register **write**. Today only the `execute` raw text path exists
(`eb`/`ed`/`r reg=`).

- **Narrowed 2026-09-02**: the `ba` (data) breakpoint half is **done**. dbgscope's `BreakpointSpec`
  takes a `DataWatch` — access and size — and `BreakpointInfo` reads the pair back through
  `GetDataParameters`, so a data breakpoint can be set and confirmed rather than only reported
  ([dbgscope#126](https://github.com/glslang/dbgscope/issues/126),
  [dbgscope#127](https://github.com/glslang/dbgscope/pull/127)). Size and alignment are refused
  before the engine sees them, on the **resolved** address, because the engine takes a bad pair at
  the set and rejects it at the next *resume* — against a `go` that did nothing wrong. No windbg-mcp
  tool exposes it yet: `set_breakpoint` takes an expression and nothing else, so a caller wanting
  `ba` still reaches for `execute`. That is a tool-surface question rather than a primitive one now.
- **Why the rest is deferred:** primarily needed by the state-injection path (item 3); no consumer
  without it.
- **Note:** dbgscope is the right home for these (DECISIONS.md D3 — typed `DebugEngine` methods, not the
  text hatch), mirroring how `run_to_address`/`instruction_pointer` were added.

## 3. [windbg-mcp + dbgscope] State-injection confirmation path (DECISIONS.md D4)

Alternative to driving a real IOCTL client: break at the dispatch entry, craft an IRP +
IO_STACK_LOCATION + SystemBuffer in memory, set `rcx`/`rdx`, and run to the target block.

- **Why deferred:** a wrong/partial IRP mutates live kernel state and can bugcheck the target,
  destroying the reproducible state the analysis depends on. Deprioritized behind the drive-a-client
  path (`ioctl_harness.ps1` + `run_to_address`).
- **Depends on:** item 2 (typed write primitives) and the item-1 breakpoint work; the same path-recipe
  data the drive path uses. Prefer a snapshot-restorable VM when building it.

## 4. [dbgscope] Typed `read_register`

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

## 9. [dbgscope + windbg-mcp] Incremental output from a running command

A second `IDebugClient` (via `IDebugClient::CreateClient`, already wrapped as
`create_from_windbg_client`, dbgscope `src/dbgeng.rs:197`) can own its own `IDebugOutputCallbacks`.
That is the route to partial output from a long `g` or `execute` — a task's `statusMessage`, or a
progress line — without the engine call returning. Today `OutputCallbacks` is installed on the one
client for the duration of a command, so output only lands when the command ends.

- **Why deferred:** worth little before item 8 gives it somewhere to go.
- **Does not buy concurrency.** A second client joins the *same* session and serializes on the same
  engine lock; while one thread is in `WaitForEvent`/`Execute`, calls from the other block. It would
  swap the worker's queue for DbgEng's internal one and gain nothing. Concurrency *between* targets
  came from item 10 instead.

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
- **Meanwhile:** `every_process_created_in_this_crate_takes_the_spawn_lock` (`src/engine.rs`) reads
  the crate's own source and fails if a process is created without `spawn_guard` held in the same
  function — `.spawn()` anywhere, and `.output()`/`.status()`, which fuse the spawn with the wait,
  in a function that also builds a `Command`. The convention is pinned rather than merely
  documented, which is what makes this an improvement to *how* the property is held rather than a
  fix to a live hole.

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

## 27. [windbg-mcp + dbgscope] A deferred module reports no PDB identity — **measured and declined** (2026-08-20)

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
`dbgscope::DebugEngine::module_pdb`.

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

## 35. [windbg-mcp + dbgscope] The engine's subregister flag misses the views that matter — **measured and declined** (2026-08-22)

`registers` narrows its default set with `DEBUG_REGISTER_SUB_REGISTER`, and that flag does not mean
what the filter needs it to mean:

- **x64**: it catches `eax`/`ax`/`al` (67 rows of a full set) and misses the vector bank's slices —
  `xmm0/0` … `xmm15/3`, 64 rows, four 32-bit pieces of each 128-bit register. Excluded since item 24
  by the `/` DbgEng puts in a slice's name (`plain_integer`, `src/worker.rs`).
- **ARM64**: it catches **nine** rows, all `cpsr` bits, and misses `w0`–`w30` — the 32-bit views of
  `x0`–`x28`/`fp`/`lr`, 31 of the 109 default rows, ~28% of that answer.

**The question this item existed to ask has been asked**, with a dbgscope branch exposing the whole
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
chatgpt-codex-connector on glslang/dbgscope#115. What the row counts is any of the four fields being
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
  dbgscope branch is worth landing even though nothing consumes it yet — that is a judgement call
  left open rather than made here.
- **What it is worth if reopened:** ~1.8 KB of a ~6.3 KB answer, on ARM64 only. Real, and smaller
  than the 6.3 KB item 24 already took off the same tool.

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

## 47. [windbg-mcp + dbgscope] The bounded wait is unmeasured on a TTD replay target

**What changed under it.** Fixing [#226](https://github.com/glslang/windbg-mcp/issues/226) made
`execute_and_wait` use the watchdog-bounded wait — `WaitForEvent(INFINITE)` with a watchdog that
`SetInterrupt`s at the bound — for **every** target type, where before only a live kernel took it
and everything else took a finite `WaitForEvent`. That was not a tidy-up: the finite wait returns
`S_FALSE` on expiry with the target still running and the engine holding no current process/thread,
and nothing recovers from that, which is the second bug that issue turned out to contain.

**What is measured, and what is not.** Live user-mode is measured both ways on the ARM64 bench — a
`go` that reaches no stop leaves the session usable, and left it unusable before. Live kernel was
already on this path and the live-kernel tier exercises it. A dump cannot resume at all, so the wait
is unreachable there. **TTD replay is the gap**: `go`, `step_back` and the rest of the reverse
family go through this function, and TTD replay did not work on **that** bench at all
(item 21 / [#132](https://github.com/glslang/windbg-mcp/issues/132)), so nothing there could ask
whether `SetInterrupt` unblocks a replay wait the way it unblocks a live one. (Named explicitly
because "this host" in an item whose measurements are ARM64's has already been read as the x64
one.)

**That blocker is gone as of 2026-08-29**, and it is the ARM64 bench that changed: item 21 landed,
the WinDbg payload was bundled beside its release build, and the host now records a trace, opens it
and steps backward through it. So the gap here is no longer "no bench can ask" — it is that nobody
has asked. The measurement this item wants can now be taken where every one of its siblings was
taken, which removes the "generalised from one backend" caveat it raises against itself below.

**Why it is not alarming, and why it is still open.** The watchdog only ever fires at the bound, so
for every go/step that stops in time the change is a no-op — which is every TTD navigation anyone
has run. What is unknown is the *timeout* path: a `reverse_go` that reaches no stop within 60s
either breaks in cleanly or does not, and if it does not, the failure shape is the one this issue
was about. `run_to_address` has used the same wait for every target type since it was written and
documents it as working everywhere, but that is a doc comment rather than a measurement, and
"generalised from one backend" is a mistake this repo has made before
(`.claude/skills/handoff/SKILL.md`).

**The blocker moved to a different host rather than lifting, and the tier it wanted now exists**
(2026-08-26). The deferral above is about the **ARM64 bench**, and nothing since has re-checked it.
What changed is the **x64 bench**: it has the `ttd\` payload beside `target\debug` and
`target\release` — item 21's unpack recipe — so replay works *there*, and the **TTD tier** records
a trace, opens it and queries it.

So the prerequisite is satisfied on a machine, just not the one this item was written on. That is
probably enough, because the gap here is a **target type** and not an architecture — but every
sibling measurement in this item was taken on ARM64, and an x64 answer inherits the caveat this
item already cites against itself: "generalised from one backend" is a mistake this repo has made
before. Whoever closes it should say which bench, and think for a moment about whether the other
one would answer differently.

(Written down because it was got wrong once already: "this host" was read as the x64 bench, on the
strength of a TTD tier passing there, and the correction is what produced the paragraph above.)

**What would close it.** Record a trace, `go` past the end of it or `reverse_go` with nothing to
stop at, and assert the session still answers `registers` afterwards — the same assertion the two
debugger-tier launch tests make. One test, in the TTD tier, on either bench — the ARM64 one is now
capable and is where this item's other measurements were taken. **Establish first
that the bound is reachable at all**: a replay target has ends, so a `go` or a `reverse_go` with no
breakpoint may simply stop at the trace boundary in well under the 60s bound, in which case the
timeout path is *unreachable* on this target type rather than untested — which closes this item as
an answer rather than as a test, and is worth writing down either way. Deciding that costs one
measurement and is what the next person should do before writing anything.

**Where it picks up.** `dbgscope`'s `DebugEngine::execute_and_wait` and `DebugEngine::pump`
(`src/dbgeng.rs` — `wait_for_event_bounded` was folded into that one pump by
[dbgscope#136](https://github.com/glslang/dbgscope/issues/136), and what this item wants to see on a
replay target is now a `WaitOutcome::Deadline`); `worker::resumed`; and the pair
`a_raw_execution_control_command_moves_the_target_instead_of_wedging_the_session` /
`a_resume_that_reaches_no_stop_says_so_and_leaves_the_session_usable` in `tests/mcp_smoke.rs`,
which are the shape a TTD one would copy.

---

## 50. [windbg-mcp] The released binary is unsigned — only the certificate is left

**What happened.** On 2026-08-26 Windows Defender quarantined a freshly built
`target\debug\windbg-mcp.exe` as `Trojan:Win32/Bearfoos.B!ml`, blocking every smoke test that
spawns the server (`os error 225`). Three detections in one minute, the flagged artefact being the
executable each time — no dump or other file appears in any detection's `Resources`. It stopped
reproducing on the next rebuild without any change to the code, which is what an `!ml` verdict does:
it is a machine-learning score with a cloud lookup behind it, not a signature match, so the same
source can land either side of the line.

**Why this is not a local curiosity.** The released binary has the same profile as the one that was
quarantined, so a user downloading the release zip can hit it. `microsoft/apm#487` is the **same
detection name on Microsoft's own shipped binary**, and two of the causes it lists applied here.
(Its other two — UPX compression and a stock PyInstaller bootloader — do not.)

**What has landed.** The **PE version resource**, via a `winresource` build-dependency in
`build.rs`: `FileVersion`, `CompanyName` and `ProductName` were all empty, measured, on both the
debug and the release binary, because Rust embeds none by default. They are now filled in, along
with `FileDescription`, `LegalCopyright`, `OriginalFilename`, `InternalName` and `Comments`, and
`ProductVersion` carries the git-stamped identity so Explorer's properties dialog answers the same
question `serverInfo.version` does. Four things that entry did not see:

- **`INPUTS` needed no change, because the resource has no file.** The warning this entry carried
  was about adding a resource input to the watch list and not to the dirty check; the way to not
  have that problem is to compose the resource in `build.rs` from `CARGO_PKG_*` and literals, with
  no `.rc` template and no icon beside it. An icon *would* be a new input, and is the thing to think
  about `INPUTS` for if one is ever added.
- **`[package]` gained `description`, `repository` and `license`**, which it had never carried. The
  resource is what wanted them; nothing else in this repo did, and the crate is not published.
- **The build must not fail when there is no resource compiler**, because `cargo check --target
  x86_64-pc-windows-msvc` from the Mac has neither `rc.exe` nor `llvm-rc`, and that is a documented
  routine workflow. So `build.rs` warns and carries on — which means the assertion has to live
  somewhere that only runs where a resource *can* be built:
  `mcp_smoke::the_binary_carries_a_pe_version_resource` reads it back through
  `GetFileVersionInfoW`. Point `RC_PATH` at nothing and touch `build.rs` to check that test still
  catches the case it is for; it was verified that way rather than by assuming.
- **Reading it back is not the same as finding the string in the file.** The test asks the API
  Explorer and the reputation systems ask, so a resource Windows itself refuses to parse fails it.

**What is left, and it needs a decision rather than a patch:**

- **A per-release developer submission** to Microsoft's file submission portal, which is what to do
  *now* because it needs no certificate and costs nothing. Submitting as a **software developer**
  rather than as a customer runs automated analysis and clears a clean file for every machine rather
  than for the one that reported it. It is per artifact — the previous release having been cleared
  says nothing about the next, since an `!ml` verdict is scored on the file in front of it — and it
  is a human action with an account behind it, so it belongs in `docs/releasing.md` (where it now
  is) rather than in a workflow.
- **Authenticode signing** in `release.yml`. **The plumbing has landed and only the certificate is
  missing**, which is the whole of what is left here: the sign and verify steps sit between `Test`
  and `Package` — before the archives that embed the exes, the checksum file, `server.json`'s hash
  and the provenance attestation, all of which would otherwise describe unsigned bytes — gated on
  `CODE_SIGNING_PFX` being set, so they skip with a build-log notice until it is. Two secrets switch
  them on; [`docs/releasing.md`](./docs/releasing.md) has the names and the dry-run check. The
  verification step is not decoration: `signtool verify /pa /tw` was confirmed to **fail on the
  current unsigned exe**, so a signing step that silently no-ops cannot pass a release through.

  Two things about signing are easy to get backwards. It **does not guarantee** an `!ml`
  detection goes away — Microsoft's own issue files signing under a later tier than the metadata —
  and it is not a prerequisite for the submission above; what it buys is a *stable identity for
  reputation to attach to*, so the submission stops starting from nothing each release, plus the fix
  for SmartScreen's "unknown publisher" prompt, which nothing else addresses. And **price is not
  what is blocking it — eligibility is**, which is the distinction to get right before deferring it
  again on the wrong ground:

  - **Azure Trusted Signing** is the CI-friendly route and is the obvious suggestion, at roughly ten
    dollars a month. It is **not available here**: individual subscribers must be legally based in
    the United States or Canada, and this project's maintainer is not. Cross it off rather than
    re-proposing it.
  - **An EV certificate** is the only thing that earns SmartScreen reputation *immediately* rather
    than accumulating it, and it is also the one a solo maintainer cannot buy: EV issuance requires
    a registered legal entity, so it is a company-formation decision before it is a few hundred a
    year.
  - **SignPath's Foundation programme** signs open-source projects for free and has no geographic
    or entity bar — it was the first ask here, and on 2026-09-04 the maintainer ruled it out: its
    criteria require the project to be **findable at the top of a web search for its name**, and
    this one is both small and named generically enough that it is not. That is not a bar effort
    closes, so it is crossed off rather than deferred.
  - **Certum's open-source certificates on SimplySign** were the next candidate and are **out**, on
    2026-09-04, for a reason worth keeping: SimplySign is "cloud" in the sense that the key sits in
    Certum's HSM rather than on a USB token, but reaching it needs **SimplySign Desktop creating a
    virtual card reader plus a mobile OTP**. That is an interactive session, not a credential a
    runner can hold, so it is no more automatable from GitHub than a token is. "Cloud signing" is
    not the property to shop for — *a credential that fits in a secret* is.
  - **SSL.com's IV (Individual Validated) tier with eSigner** is the route that clears every gate,
    and is **deferred on price rather than eligibility** — $129/year, not worth it until this
    project has confirmed users (decided 2026-09-04). It is the first candidate that is genuinely
    CI-native: the **TOTP secret itself** goes in a repository secret and CodeSignTool computes the
    one-time code, so there is no phone in the loop — `ES_USERNAME`, `ES_PASSWORD`, `CREDENTIAL_ID`,
    `ES_TOTP_SECRET`. IV needs no business registration (government ID only), and the only geography
    on their page is US shipping *for the hardware token*, which cloud enrolment sidesteps.
    **Two things to confirm before paying**, both being the exact shape that has caught this three
    times: that they issue IV to an individual in this maintainer's country, and that **IV** rather
    than EV alone works with CodeSignTool — their comparison says IV/OV/EV are all eSigner
    compatible, CodeSignTool's own blurb says "EV". Prefer downloading and SHA-verifying
    CodeSignTool over the `SSLcom/esigner-codesign` action, which is the pattern `release.yml`
    already uses for the MCP registry publisher and avoids giving a third-party action a job holding
    `contents: write` and `id-token: write`.
  - **DigiCert KeyLocker** is out: OV and EV only, both of which need a legal entity.

  So the one option left standing is below EV, and reputation accumulates rather than arriving —
  which is an argument for doing the per-release submission above *regardless* of what gets signed,
  not for treating signing as the thing that makes it unnecessary. Prices and programme terms move;
  treat these as the shape of the choice, not as quotes. Note also what the release *does* carry and why it does not help here:
  `release.yml` produces a Sigstore build-provenance attestation, which is a supply-chain claim a
  user verifies deliberately with `gh attestation verify`. Nothing on the machine reads it, and it
  establishes provenance rather than benignity — a compromised dependency or runner would be
  attested just as faithfully, which is why `skills/windbg-debugging/setup.md` no longer treats a
  verified attestation as grounds to restore a quarantined file.

**Where it picks up.** The *Build & publish binary* job in `.github/workflows/release.yml`, and
[`docs/releasing.md`](./docs/releasing.md) if the submission becomes a step.


## 52. [windbg-mcp] The "no description names a tool the client cannot call" invariant does not cover **input schemas**

**Where it came from.** Writing #83's three tools (2026-08-29). Their argument docs wanted to say
"the handle `continue_async` reported", which is the natural sentence — and
`no_description_names_a_tool_the_client_cannot_call` would not have caught it, because it walks
`descriptions_for(spec)` and an argument's doc comment ends up in the **input schema**, not the
description. The schema is model-visible: `docs/token-budget.md` counts it inside `modelVisible`,
and `tool_budget.json` has an `inputSchema` column of its own. So a `--tools wait_for_stop` client
would read a pointer to a tool it is refused, which is exactly what item 41 exists to prevent, on
the one channel item 41 did not look at.

**This is pre-existing, and there is at least one live instance.** `RunToAddressArgs::address` says
"Typically a block from `reachable_from_dispatch`" (`src/server.rs`). `run_to_address` is `exec` and
`reachable_from_dispatch` is `ioctl`, so any surface with the first and not the second — `exec`
alone, `session,exec,crash`, the bench's `lean` — ships that pointer to a client that cannot follow
it. #83's own tools were reworded to name no tool rather than adding a second instance while
reporting the first.

**What would close it.** Extend the walk to the input schema — `descriptions_for` already builds a
router per spec, so the schema is in hand beside the description and it is the same `names_tool`
predicate over a second string. Then either move the `reachable_from_dispatch` sentence into
`TOOL_NOTES` (which appends per-tool and already has the all-of rule) or reword it, and check
whether the fix wants a third table for *schema* notes, since `annotate` rewrites descriptions and
nothing today rewrites a schema.

**Why it was deferred.** It is a second channel with a second mechanism, and finding it in the
middle of a feature is the wrong moment to build one: the fix has to decide whether an argument's
prose can carry a cross-reference at all, and that decision changes how every future argument is
documented. The immediate hazard is one sentence, on surfaces that hold `exec` without `ioctl`.

**Where it picks up.** `no_description_names_a_tool_the_client_cannot_call` and `descriptions_for`
in `src/server.rs`'s tests, `TOOL_NOTES` and `annotate` beside them, and item 41 for the argument
about which channels a narrowed surface has to narrow.

## 53. [windbg-mcp] A break raised *after* a run's stop is built labels the result cut short

**What it is.** `run_job` calls `release(id)` when an operation ends, and a `true` there — a break
was raised for this job and the engine had not consumed it — applies `cut_short`, which appends
"this is what it had reached, not a complete result" to the result's **text**. But a run's
`StopReport` is built inside the operation, before `release` runs, and `stop_report` sets
`interrupted` from `run.cut_short` alone — from what `settle` reported. A break lodged after
`settle` returned is therefore in the note and not in the flag.

**Why the flag is the one that is right.** The target had already stopped when that break was
raised, at a breakpoint it reached. `docs/sessions.md` defines `interrupted` as the case where the
position "is where the target happened to be rather than a stop it reached" — so setting it for a
late break would send a caller past a real breakpoint hit, which is worse than the note. This was
proposed in review on #257 and declined for that reason.

**What is left.** The note and the flag disagree, in a window of microseconds, for a caller that
reads the text. On the **asynchronous** path there is no such caller — `wait_for_stop` builds its
answer from `Output::stop` and never reads `Output::text`, so the note is dropped — which is why
#257 changed nothing here. On the **synchronous** path (`go`, the stepping tools) a text-reading
client sees "interrupted, incomplete" beside a `data` that says `interrupted: false`; a
structured-aware client sees only the second, since `structuredContent` replaces the text block.

**What would close it.** Not labelling a result cut short when the operation has already reported
its own stop. The async half is one line (`Output::stop` is `Some` exactly for those), the
synchronous half is not, because its report is inside `data` as JSON and digging it out in
`run_job` is worse than the wart. The honest shape is for the executor to say whether it has
already accounted for the interruption, rather than for `run_job` to infer it from the payload —
which is a change to how every op reports, for a disagreement that needs a microsecond race and a
text-only client to observe. `crate::batch`'s `ran_told` already answers the same question the
other way (`|| self.broken()`), correctly for a batch, which is worth reading before choosing.

**Where it picks up.** `run_job`'s `release`/`cut_short` block and `cut_short` itself in
`src/worker.rs`, `stop_report` beside them, and `Ran::ran_told` for the path that already consults
the late-break flag.

## 54. [dbgscope + windbg-mcp] `modules { "refresh": true }` has no wall-clock bound

**What it is.** The resynchronisation behind `refresh`
([#85](https://github.com/glslang/windbg-mcp/issues/85)) is `IDebugSymbols::Reload("")` — a direct
engine call, not a command — so no watchdog can cut it short and `EngineOp::Modules` carries no
`patience_ms`. What bounds it is the caller's own call timeout and `interrupt`, which reaches the
engine from off the engine thread. That is the same position `EngineOp::Backtrace` is in, and its
doc comment says so for the same reason: carrying a `patience_ms` would imply a bound that does not
exist.

**Why it was deferred.** The acceptance criterion it was written against is about *symbol-server*
cost, and that one is closed by construction: the reload is unqualified and unforced, so what it
discovers is `deferred` and nothing is fetched. What is left is the time the reload itself takes,
which is a walk of the target's loaded-module list. Measured on the CTF guest over KDNET on
2026-08-30, that is imperceptible — a whole `modules { "refresh": true }` inside a test that ran in
1.96s including attach and detach. The wire it would be slow on is the one this repo already
documents as unusable for a pool walk: **115200-baud serial**, where a per-module round trip is
tens of milliseconds and 158 modules is a wait with no upper bound and no way to tell it from a
hung debugger.

**What would close it.** A bounded `Reload` in dbgscope — arm the crate's `Watchdog` around the
call, as `execute_command_bounded` and `settle` already do, and report an interruption the way they
do rather than as an error. `SetInterrupt` is expected to reach a `Reload` (a person Ctrl+Breaks
one in WinDbg), but that is an expectation and not a measurement: **measure it first**, because a
bound that cannot actually break the call in is worse than no bound, and dbgscope's watchdog tests
arm one over a counter precisely so this can be tried without a debuggee. Then give
`EngineOp::Modules` a `patience_ms` and add it to `EngineOp::patience_slot`'s match — the arm whose
absence silently gave `Self::Pool` dbgscope's default walk budget instead of this server's
deadline.

**Where it picks up.** `worker::resynchronise` and `EngineOp::Modules` in `src/proto.rs`,
`DebugEngine::reload_symbols` and `Watchdog` in dbgscope's `src/dbgeng.rs`, and
`execute_command_bounded` beside it for the shape a bounded direct call takes here.
## 56. [windbg-mcp] `resolve`'s `? <expr>` is a caller's command on nobody's clock

`worker::resolve` evaluates an address expression by running `? <expr>` through
`execute_command` — unbounded. The text is the **caller's**: `disassemble { "address":
"nt!KeBugCheck+0x2e8" }` reaches it verbatim, and `?` makes the MASM evaluator resolve the symbol,
which on a deferred module with a `srv*` path is a fetch from a symbol server. That is minutes with
the session's engine held and nothing able to cut it short — the same wedge the bounded path exists
to stop, arriving through a helper rather than through an op.

Found while closing item 14 (the coverage rule collapsing to "bound every command except
`index_trace`"), by enumerating the `Execute` calls left in `src/worker.rs` rather than the ops —
which is also how the `set_breakpoint` instance was found, by Codex, on
[#271](https://github.com/glslang/windbg-mcp/pull/271). That one was fixed in the same PR because
its op is its own; this one is not, for the reason below.

- **Why deferred:** `resolve` is a shared helper with three callers on three different clocks, and
  two of them have no clock to offer. `run_to_address` has a `timeout_ms` it could pass down.
  `EngineOp::Disassemble` carries no `patience_ms` at all and would have to grow one — the first
  typed op to carry a deadline for a command *inside* it, which `SetBreakpoint` has now made a
  shape rather than a novelty. And `reachable` calls it up to `max_functions` times in one job,
  where a per-call bound is the wrong instrument for the same reason item 13 gives. So the fix is
  three decisions, not one, and one of them is item 13's.
- **What would close it:** a `patience_ms` on `EngineOp::Disassemble`, `resolve` taking a budget
  and running `execute_command_bounded`, and item 13's job-level deadline covering the
  reachability caller. Done together, `resolve` leaves the allowlist in
  `worker::tests::every_unbounded_execute_in_this_worker_is_accounted_for`, which is where
  the deferral is recorded in code.
- **Depends on:** item 13 for the `reachable` third of it.
- **Note the hazard is not fully closable by a watchdog anyway.** `backtrace` resolves a symbol per
  frame through direct engine calls, with no `Execute` for a watchdog to break, so a cold symbol
  server can block that too — see `EngineOp::Backtrace`. This item is worth doing because a
  *command* is bounded cheaply and there is no reason to leave one that is not; it is not worth
  doing as a claim that the symbol-server hazard is gone.

## 58. [dbgscope + windbg-mcp] `GetEffectiveProcessorType` is the question, and is not bound

`worker::target_bitness` decides how wide to lay a fault's `EXCEPTION_RECORD` out, and asks two
sources that each answer a slightly different question. `GetActualProcessorType` answers for the
**physical processor** — measured, by launching `C:\Windows\SysWOW64\cmd.exe`: `0x8664`, under a
64-bit worker, for a process whose every C++ throw raises three parameters and whose record is 80
bytes. `IsWow64Process2`, through `target::process_arch`, answers for the **process**. Between them
a WoW64 target comes out right, which is what
[#286](https://github.com/glslang/windbg-mcp/pull/286) shipped after Codex found the case.

Neither is the question actually being asked. `IDebugControl::GetEffectiveProcessorType` is: the
machine the engine is *currently decoding for*, which follows a WoW64 target across the transition
— measured on that same launch, `x64 (AMD64)` at the initial break and `x86 compatible (x86)` once
the process is running in its own code.

- **Why deferred:** it is not in the pinned `dbgscope`, so closing this is the two-repo flow — a
  typed method on `DebugEngine`, a `rev` pin moved, and both committed together — for a correction
  the pair of calls already makes on every target this bench can build.
- **What would close it:** `DebugEngine::effective_processor_type` in dbgscope, and
  `worker::decide_bitness` taking it as a third source, ahead of both: a 32-bit answer from it is
  decisive, and the two existing sources become what answers before the target has been resumed.
- **What the approximation costs meanwhile:** the two disagree only at the initial breakpoint of a
  WoW64 launch, where the engine is still 64-bit and the process has not entered its own code. That
  break carries no C++ throw to decode, so nothing reads a record at the wrong width there. It is
  an approximation with a known gap rather than one that happens to hold.

**Where it picks up.** `worker::target_bitness` and `worker::decide_bitness` in `src/worker.rs`,
the module docs in `src/target.rs` — which already name this call as the authoritative one, and say
why the *routing* cannot use it — and dbgscope's `src/dbgeng.rs` beside `processor_type`.

## 59. [dbgscope + windbg-mcp] Nothing can ask which thread the engine has selected

`exception_triage` reads the fault from the stored event where there is one and from `last_event`
otherwise. `DebugEvent` carries `thread` — the **engine** thread index the event belongs to — so on
a live target the tool could check whether the thread it is about to walk is the one that raised the
exception, and it cannot: `IDebugSystemObjects::GetCurrentThreadId` is used inside dbgscope's
`current_processor` and is not public, and the only public thread call,
`current_thread_system_id`, answers in a different namespace from `DebugEvent::thread`. There is no
public listing pairing the two either.

So a live session where the caller has selected another thread since the fault — `~Ns`, or an
`execute` of one — gets this fault's record beside that thread's frames, and the buried-throw scan
searches that thread's stack. Found by Codex on
[#286](https://github.com/glslang/windbg-mcp/pull/286).

- **Why deferred:** the fix is a typed getter in dbgscope and a `rev` pin moved, which is the
  two-repo flow, for a case that needs the caller to have changed threads between the fault and the
  call.
- **What would close it:** `DebugEngine::current_thread_id` (the engine index, beside
  `current_thread_system_id`), and `worker::exception_triage` comparing it to `DebugEvent::thread`
  — reporting the mismatch as a field rather than silently combining the two, in the shape
  `stored_crash_context` already established. Walking the *right* thread would mean selecting it,
  which this tool does not do: leaving the selection alone is what makes it read-only where
  `crash_triage` needed a scope guard.
- **What it costs meanwhile:** the result says which stack it walked rather than claiming it is the
  crash's — the tool description, the `STACK` line and the scanned-record caution all say the
  stack is the selected thread's when no stored context was found. That is honest and it is not the
  same as knowing, which is what this item buys.

**Where it picks up.** `worker::exception_triage` in `src/worker.rs`, `fault::render`'s `STACK`
line, and dbgscope's `src/dbgeng.rs` beside `current_thread_system_id`.

## 60. [windbg-mcp] Structured dispatch reachability paths for the Binary Ninja bridge

Preserve `reachable_from_dispatch` text while exposing typed paths and branch recipes.
Attribute coordinate-bearing addresses to modules on the worker's engine thread and carry
PE matching metadata plus RVA. This is separate from the bridge's guarded breakpoint,
run-to, memory, and current-location contracts. Runtime coverage, if imported later, must
mean observed execution only; an unobserved location is not proof of unreachability.
