# Follow-ups

Deferred work, grouped by origin: items 2–6 come from the reachability-confirmation effort (path
recipe + `run_to_address`, merged 2026-07-04), items 8–9, 11 and 88 from surveying this server
against the MCP `2026-07-28` extensions (tasks, apps) and then re-measuring the tasks half of it
(2026-09-19) — where rmcp and the reference TypeScript SDK turn out to implement two
wire-incompatible generations of SEP-2663 while the client this server is actually driven by
declares neither, and where the one thing a task would genuinely have bought surfaced as item 88
instead: a call that outlives its budget finishes its work in the worker and has the answer
thrown away — item 15 from the private worker channel (#65 / #72,
2026-08-04), item 19 from
`walk_memory` (#103, 2026-08-13), item 27 from completing the coordinate work (#156–#158,
2026-08-18), item 32 from running the debugger tier on the ARM64 runner image that replaced
`windows-11-arm` in September 2026 — now in [`DONE.md`](./DONE.md), the migration having landed on
2026-09-23 — items 33 and 39 from driving the server with a **local model** —
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
reach on three different clocks (2026-08-31) — items 58–59 from
[#286](https://github.com/glslang/windbg-mcp/pull/286)'s user-mode fault triage, where the engine
call that names a target's machine turns out to name the *processor's*, and where nothing can ask
which thread the engine has selected (2026-09-05), items
61–62 and 64–65 from completing Personal similarity delivery while separating CVE-specific investigation,
upstream Binary Ninja limitations, and unaffordable Ultimate validation (2026-09-12), and items
66–67 from the IOCTL recovery in [#305](https://github.com/glslang/windbg-mcp/pull/305) and
[#307](https://github.com/glslang/windbg-mcp/pull/307): thirty-nine review findings over fourteen
rounds that were one default — a backwards walk refusing what it trips over rather than recognising
what a compiler emits — and then, from the differential oracle those rounds produced, the walk
reporting a code down the dead edge of a branch whose condition is a constant (2026-09-12), and items
68–69 from `device_security` ([#311](https://github.com/glslang/windbg-mcp/pull/311)), where
eleven rounds of review on one tool ended with its own live-kernel measurement contradicting the
item an earlier round of it had produced (2026-09-13), and item 71 from `driver_surface`, the
fourth driver tool, whose specification included a dispatch-to-sink traversal that did not land
with it, and item 72 from running that tool's live-kernel tier, where a fresh attach turns out to
leave the debugger's module inventory nearly empty and the driver tools with nothing to resolve
against (2026-09-13), and items 73–74 from checking the four driver tools against Ghidra and
Driver Buddy Revolutions over `mountmgr` and HEVD — an import directory the loader may have
freed, and the one section of the ported program with no counterpart here (2026-09-14) — and item
79 from item 78's own fix, which got the user-mode heap walker past the layout refusal and one step
into the next wall: the PEB lists one heap where the debugger sees four (2026-09-16), and item 80
from adding Apple's on-device model as the eval's third backend (#335 / #336, 2026-09-17), where
two review rounds found `identity()` reporting something false about a run because it worked out
what a record contributes by testing the backend again in each field that needs it — both now in
[`DONE.md`](./DONE.md) — as is item 81 from
[#341](https://github.com/glslang/windbg-mcp/pull/341)'s breakpoint-command guard, where both
review bots independently reached the same finding: a command scanner that reads the first token
of a segment cannot see `.opendump` inside an `.if`, a `.foreach` or an alias that resolves only
when it runs (filed 2026-09-18, closed 2026-09-25 by reading the target rather than the command).
And item **84** from running
`ioctl_map` against a live **ARM64** target for the first time
([#345](https://github.com/glslang/windbg-mcp/pull/345), 2026-09-19): an `adrp`+`add` table base
lost at the `add`. That run filed five more, all now in
[`DONE.md`](./DONE.md) -- the literal pool the fact walk could not read (item 82, which was the
whole of why 235 codes carried no proven size or refusal), the switch tables the reachability
walk did not follow while the map resolved them (item 83), the two things item 83's own
fourteen review rounds left behind -- a resolver cap discarding the targets it had proved (item 90)
and the last uncounted way a `NOT REACHABLE` can be short of the graph (item 89) -- and the ARM64
second opinion that had never been diffed (item 85), whose lane, once written, found the published
`mountmgr` agreement to have been between two different builds. And item 87 from verifying one of the review findings on
[#347](https://github.com/glslang/windbg-mcp/pull/347), where checking which `untracked` entries
`volmgr` actually had turned up a code the map loses beside three identical ones it keeps
(2026-09-19), and item 91 from the one-sided half of that diff (2026-09-20): after item 82's
literal-pool read landed, `rdyboost`'s thirteen length checks are all still `exact: false`, because
the refusal they branch to returns through a shared epilogue the walk stops at the head of. And
item 92 from item 85's lane finding a driver the two implementations disagree about (2026-09-20):
A64 writes `a || b || c` as three compares feeding one branch, and this walk reads the last of them
and files the rest in `untracked`. And item 94 from giving the multiprocessor hypervisor
investigation's harness the tools it was written against (2026-09-20) -- that investigation is
item 93 and is now in [`DONE.md`](./DONE.md): a typed breakpoint listing and removal landed, and
`bd`/`be` deliberately did not. And item 97 from running the heap tools on ARM64 for the
first time ([dbgscope#177](https://github.com/glslang/dbgscope/pull/177), 2026-09-23), with the
target's own `HeapWalk` as the oracle: an LFH block awaiting a delayed free, which `HeapWalk`
calls free and the heap tools call allocated. That run filed two more, both now in
[`DONE.md`](./DONE.md) — item 96, the pool walker's LFH reading, which it showed is not `nt`'s,
and the ARM64 pool gate behind it; and item 98, the uncommitted memory that kept every live walk
measured at `Partial` once the diagnostics were gone, which turned out to want the memory
manager's answer rather than the allocator's. And items 100–101 from checking its fixes end to
end through the tool surface once they had merged (2026-09-23) — the VS chunk chain coming apart
on **29671**, found while confirming those fixes were not fitted to 26100, which they are not; and
the same chain drifting 0x10 on 26100, which is all that is left of item 99 now that it too is in
[`DONE.md`](./DONE.md). They were filed as possibly one question and are **not** (2026-09-24):
item 100 is the target's paged pool being trimmed out from under a KD link, with nothing in the
walker to fix, and is measured and declined; item 101 is a real placement defect in readable
memory.
And item 102 from closing item 81 (2026-09-25): the fingerprint that now retires a session's
handles when its target is swapped does not stop a `debug_batch` mid-flight, so the batch's
`always` block can run its rollback against the replacement — a write into a target that never had
the mutation.
Each item notes its repo, why it was deferred, and where it picks up. See
[`DECISIONS.md`](./DECISIONS.md) for the design rationale (D1–D5) items 2–6 extend, and its
2026-08-02 entries for the bounded-command coverage review that produced item 13, now in
[`DONE.md`](./DONE.md).

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

Two kinds of item stay here rather than moving. One that is **measured and declined** (27, 35, 100):
each records the measurement that settled it and the condition that would reopen it, item 35 leaves
a judgement call open, and item 100 answers its own question against itself — the walk it was filed
about turns out to be right, and what the run found instead went into item 98, now in
[`DONE.md`](./DONE.md). And one that has
**half** landed (2, 50) — the entry is narrowed to the half that is left rather than split across
two files.

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
  the set and rejects it at the next *resume* — against a `go` that did nothing wrong. **And the
  tool surface caught up on 2026-09-17**: `set_breakpoint` takes a `watch`, so `ba` no longer needs
  `execute`, and the whole of dbgscope#126 is closed with it. What remains under this item is the
  rest of the first line — `write_virtual` and a typed register write — and nothing about
  breakpoints.
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

**Half of it is closed, and the half that is left is the recipe's.** `ioctl_map` (`src/ioctl.rs`)
does not infer from the displacement: it follows the chain from the dispatch routine's IRP argument
through `+0xb8` into the stack location, reports per case whether the value it tested came that way
or from a bare displacement, and accepts a length check only when its base is a register the walk
watched the stack location reach. What still reads a displacement alone is
`crate::driver::field_from_operands`, which fills `BranchPredicate.field` in a reachability recipe
— so a recipe step naming `IoControlCode` is still a hint about a compare rather than a fact about a
structure, and `docs/structured-results.md` says so. Closing that half means giving the recipe pass
the same tracking, which is the same shape of work one function over.

## 6. [windbg-mcp] Concolic/symbolic buffer synthesis (DECISIONS.md D2 — scoped out)

Auto-emit a concrete `(code, buffer, lengths)` by SMT-solving the on-path branch predicates, rather
than the human/LLM-readable recipe emitted today.

- **Status:** scoped **out** of the current effort. If ever needed, offload to angr/Triton over a
  debugger memory snapshot rather than building an in-house solver — kernel state modeling, loops,
  hashing, and stateful protocols make it brittle and a separate project.

## 8. [windbg-mcp] Tasks extension (`io.modelcontextprotocol/tasks`, SEP-2663) — **measured and deferred** (2026-09-19)

Nothing here speaks tasks today. The hand-written `get_info` advertises
`ServerCapabilities::builder().enable_tools()` and no `extensions` map, so `tasks/get` /
`tasks/update` / `tasks/cancel` fall through to the `ServerHandler` trait defaults
(`method_not_found`), which `capabilities_advertise_only_what_is_implemented` pins from the wire.

The fit still looks unusually good, because the server models the problem tasks exist to solve.
`EngineError::Timeout` documents that "the job was abandoned by the *waiter*, not by the worker, so
it may still be running and may still succeed", and `Sessions::call_within` says the same of the job
— *"the job itself is **not** cancelled — only this wait for it"*. **Deferred anyway**, because the
measurement below says the wire has two mutually incompatible generations of this feature on it, and
the generation the client end speaks is the one that is in a released schema.

- **What is stale in the analysis this entry used to carry**, all of it written 2026-07-29 and last
  touched 2026-08-10, and worth recording because each was cited as the reason to do the work:
  - The `opens: VecDeque<(String, OpenOutcome)>` ring it called a hand-rolled `tasks/get` is
    **gone**. Item 10 replaced it with the supervisor's session registry — `engine::Registry`,
    `SessionState`'s six states, `SessionSnapshot` carrying `state`, `in_state_for`, `age`,
    `current` and `execution`, filtered to the caller by `Sessions::snapshot`. So
    "`session_status` can shrink to a thin adapter over `tasks/get`" is **false**: that tool
    answers about a **session** and a task is about a **call**, and `tasks/get` has a field for
    none of it.
  - `record_trace`, offered as the first conversion because it is "already off any engine", is no
    longer a long call at all: `ttd::record_launch` returns after `STARTUP_WATCH`, 2,500 ms, and
    never waits for the recording. The tools that reach no engine at all are `decode_ioctl`,
    `session_status`, `server_log` and this one, and the first three answer from arithmetic or from
    this server's own state — so the "no debugger risk" tool the conversion was to be proved on no
    longer takes long enough to be worth converting.
  - "Hand-writing `call_tool` and `get_info` leaves the rest generated" is already done, for
    item 40's per-client instructions and for the recording and progress hooks. That half of the
    wiring exists.
  - Its step 3 — `go` / `run_to_address` / `execute` as tasks, with `tasks/cancel` raising item 7's
    interrupt, and a queued-job cancel named as the half item 7 did not build — is overtaken by
    [#83](https://github.com/glslang/windbg-mcp/issues/83). `continue_async` + `wait_for_stop` +
    `break_in` are a create/poll/cancel triple already, with domain rules tasks cannot express (one
    run per session, reads of a moving target refused, a stop read rather than taken, a break bound
    to a job id), and `Running::barred` is the queued-cancel half.
  - Its line/column citations (`src/engine.rs:37-42`, `src/server.rs:43`, `:1963`) had all moved.
    This entry names symbols instead, which is the reason.

- **The two generations, measured 2026-09-19.** rmcp 3.3.0 implements SEP-2663 (status **Final**)
  faithfully. The reference TypeScript SDK 1.30.0 — which Claude Code 2.1.278 bundles, under
  `dist/esm/experimental/tasks/` — implements the tasks defined in the released
  `schema/2025-11-25/schema.json` instead, which SEP-2663 *removes* from the core protocol and
  calls experimental. The SEP says outright that the two are "**not wire-compatible**":

  | | rmcp 3.3.0 (SEP-2663) | SDK 1.30.0 / Claude Code 2.1.278 |
  |---|---|---|
  | Capability | `capabilities.extensions["io.modelcontextprotocol/tasks"]` | `capabilities.tasks{list,cancel,requests:{tools:{call}}}` |
  | Who opts in | the server, per request | the **client**, via `params.task` |
  | Create result | `{resultType:"task", taskId, …}`, flattened | `{task:{…}}`, nested |
  | Poll | `tasks/get` — payload inlined | `tasks/get` — status only |
  | Payload fetch | (inlined above) | `tasks/result` |
  | Enumerate | (none, deliberately) | `tasks/list` |
  | In-task input | `tasks/update` | (none) |
  | Cancel result | empty acknowledgement | the `Task` |
  | Push | `notifications/tasks` | `notifications/tasks/status` |
  | TTL / poll fields | `ttlMs` / `pollIntervalMs` | `ttl` / `pollInterval` |

  What the two ends share is the extension identifier and the *spelling* of `tasks/get` and
  `tasks/cancel`, and they disagree about what both of those return.

- **And the client this server is actually driven by declares neither.** Measured with a throwaway
  stdio server registered through `claude -p --mcp-config --strict-mcp-config`, which records the
  handshake and needs no VM:
  - `initialize` sends `protocolVersion: "2025-11-25"` and
    `capabilities: {roots:{listChanged:true}, elicitation:{}}` — no `tasks`, no `extensions`.
    SDK 1.30.0's own `LATEST_PROTOCOL_VERSION` is `2025-11-25` and `2026-07-28` is absent from its
    `SUPPORTED_PROTOCOL_VERSIONS`.
  - Given a probe advertising the SDK's *own* `capabilities.tasks` shape, its `tools/call` carried
    **no** `params.task`, and a bare `CreateTaskResult` came back to the model as a failed tool
    call — reported as *"content is required when the body carries 'task' — another result family
    cannot default into an empty tools/call success"*. Returning a task to this client is a broken
    call, not a deferred one.
  - That same `tools/call` carried `progressToken: 2`. Progress is the asynchrony channel this
    client reads.

- **At the revision every handshake settles on, the SEP forbids it anyway.** This is the part that
  makes the deferral conformance rather than judgement. `is_legacy_version` is `< "2026-07-28"` and
  `negotiate_protocol_version` answers `newest_legacy_version` for anything that is not itself a
  supported legacy version, so **every client arriving through `initialize` settles on a legacy
  revision — `2025-11-25` at newest** — whatever its body named. SEP-2663's
  backward-compatibility table gives that revision its own row: *"This extension is not defined
  under the `2025-11-25` protocol version. Servers **MUST NOT** treat this capability as enabling
  tasks under that protocol version; requests proceed as if the client had declared no task
  capability at all."* Its canonical row is
  `2026-06-30`. So a task could only ever be materialised for a client arriving the **sessionless**
  way — `server/discover`, per-request `_meta` — which in this repository is driven from
  `mcp_smoke` and `src/server.rs`'s own tests and from nowhere else, and is not the route the
  client measured above takes.

- **Converting a tool would also give up the channel that works.** `progress::Watch::run` wraps the
  tool's future in `dispatch`; a tool that answers with a task handle completes that future at once,
  so the heartbeat stops and the real work runs detached with no token. Nothing replaces it:
  rmcp's `TaskManager` never sends `notifications/tasks` (and `subscriptions/listen` refuses to
  route one, saying `SubscriptionFilter` has no `taskIds` field yet), so a client polls or learns
  nothing.

- **What tasks would genuinely buy, which is one thing and not the openers.** A call that outlives
  the budget has its **answer thrown away while the work completes**: `reader`'s
  `WorkerMessage::Done` arm sends the result into a `oneshot` whose receiver went with the
  timed-out caller, and acts on the failed send for `OPENER_JOB` alone. A refreshing `modules` past
  300 s therefore runs to the end in the worker and is reported as a timeout with nothing to
  collect — item 88 carries the rule for which jobs can reach that state, the allocator walks having
  a budget of their own that stops them first. The openers already escape this — their timeout hands back a
  `session_id` and `session_status` resolves it — and **item 88 is what would close the rest**,
  with `continue_async`'s filing task rather than a protocol extension.

- **Three things to get right, not plumbing** — the durable half of the original entry, carried
  over (the third is compressed, and its reference to item 10's worker teardown dropped now that
  `end_session` terminating a worker is simply how this server behaves):
  - **TTL must not re-introduce the lie.** `DEFAULT_TASK_TTL_MS` is 5 minutes and expiry marks a
    task `failed`; a kernel attach waits indefinitely by design. Attaches need `ttl_ms: None`, or
    the task reports a failure while the attach is still genuinely pending — the exact false report
    the conversion was meant to remove.
  - **An `attach_kernel` task must not report `cancelled`.** Item 7's interrupt does not unblock a
    KDNET wait before the target connects — `SetInterrupt` cannot reach it — and the job is not
    inert while it runs: the attach self-heals and *lands* the moment the target dials in, replacing
    the current target. A task that went `cancelled` on request would have the session swapped
    underneath a client that believes the operation is over. Cooperative cancellation is the escape
    hatch rather than the problem: acknowledge, decline to transition, leave the task `working`
    until the engine job resolves. A cancel that genuinely ends the wait is `end_session`, which
    terminates the session's process — it just is not `tasks/cancel`.
  - **The session-handle contract needs a task-path clause.** The queued-precheck design survives
    untouched (a task's gate still runs in the same queued job, so the CHANGELOG's ordering
    guarantee holds), but if an opener returns a task then the `session_id` arrives in the task
    *result*, not the immediate response. "Commit the handle as soon as the target transition
    succeeds" has to be restated for that path.

- **And two prerequisites the original entry did not have, both of which review would find.**
  - **`TaskManager` has no owner scoping, and the SEP requires one.** Ids are `Uuid::new_v4`, and
    `get_task` / `cancel_task` take an id and nothing else — so on a listener serving several
    credentials, any of them holding an id reaches that task. SEP-2663's own security section says
    servers *"**MUST** perform authentication and authorization checks on each task-related
    request"*. This server already draws that line for sessions (`Sessions::snapshot` filters
    `s.owner == caller`), so the check is a `crate::client::current()` comparison the SDK does not
    provide and each of the three handler methods has to make.
  - **A task-shaped answer is invisible to the transcript.** `dispatch` records
    `CallToolResponse::Complete` and has `Ok(_) => {}` for everything else — deliberate for MRTR,
    where no result exists yet — so every converted tool would lose its result from
    `WINDBG_MCP_TRANSCRIPT` until that arm learns to file a task's eventual payload.

- **What would reopen it**, either half being enough to make the work mean something:
  the client this server is driven by declares `io.modelcontextprotocol/tasks` and reaches the
  server on a revision where the extension applies; or rmcp and the reference SDK agree on the
  wire. And the asymmetry runs the wrong way for building early, because the **client's**
  generation is the standardised one. `schema/2025-11-25/schema.json` defines `Task`, `CreateTaskResult`,
  `GetTaskPayloadRequest` and `tasks/get` / `tasks/result` / `tasks/list` / `tasks/cancel` /
  `notifications/tasks/status` — the SDK's shape exactly — while SEP-2663, which removes all of it,
  has reached no released schema at all: `schema/2026-07-28/schema.json` is byte-identical to
  `schema/draft/schema.json` on `main` and defines no task type, the extension living only in
  `seps/`, deliberately, "to incubate and evolve based on additional real-world implementation
  feedback… Once the extension has stabilized and achieved broad adoption, it is intended to be
  promoted into the core protocol." Other SDKs are mid-migration
  ([mcp-go#980](https://github.com/mark3labs/mcp-go/issues/980),
  [kotlin-sdk#1003](https://github.com/modelcontextprotocol/kotlin-sdk/issues/1003)).
- **Note:** tasks are client-negotiated, so every converted tool keeps its synchronous path. This
  is additive, never a replacement — which is also why building it early buys nothing: under
  rmcp's own gates (`validate_tasks_capability`, and the `CallToolResponse::Task` check in
  `handle_request`) a client that declares nothing takes the synchronous path and never reaches a
  line of it.

## 9. [dbgscope + windbg-mcp] Incremental output from a running command

A second `IDebugClient` (via `IDebugClient::CreateClient`, already wrapped as
`create_from_windbg_client`, dbgscope `src/dbgeng.rs:197`) can own its own `IDebugOutputCallbacks`.
That is the route to partial output from a long `g` or `execute` — a task's `statusMessage`, or a
progress line — without the engine call returning. Today `OutputCallbacks` is installed on the one
client for the duration of a command, so output only lands when the command ends.

- **Why deferred:** it used to read "worth little before item 8 gives it somewhere to go", and item
  8 is now deferred with a trigger — but the somewhere arrived from the other direction. A
  `progressToken` on a call is a channel `src/progress.rs` already owns and the client measured in
  item 8 already sends, so a partial line has a destination today with no task and no extension.
  What still defers this is which *milestones* belong on that channel: `progress::Step` is
  deliberately a closed set of transitions the supervisor acts on, and free-text debugger output is
  the opposite of that, so the design question is what to admit rather than how to carry it.
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

**What [dbgscope#95](https://github.com/glslang/dbgscope/issues/95) settled, and what it did not**
(2026-09-17). That issue asked the identical question of `read_memory` — a direct engine call with
no bound, where the watchdog was the obvious answer and nobody had measured whether `SetInterrupt`
reaches one. It could not be measured: the target it needs is a live kernel behind a link slow
enough for the call to sit in, and this bench had none. So it did **not** arm a watchdog on an
expectation, and shipped a different lever instead — read the range a page at a time and check the
deadline between chunks ([#332](https://github.com/glslang/windbg-mcp/pull/332)).

That lever does not transfer here. `Reload("")` is one opaque engine call with nothing to split, so
there is nothing to poll between, and the measurement this item asks for stays the only thing that
decides it. What does transfer is the second half of the paragraph above: `EngineOp::ReadMemory`
carries a `patience_ms` and is in `patience_slot`'s match, so there is a worked example of that
change rather than a description of one. And the doctrine it rests on has been corrected in
`EngineOp::Backtrace`'s doc — the absence of a `patience_ms` is a claim about whether the call
underneath can be **stopped**, not about whether the op runs a command, which is the form this
item's first paragraph was already stating it in.

**Where it picks up.** `worker::resynchronise` and `EngineOp::Modules` in `src/proto.rs`,
`DebugEngine::reload_symbols` and `Watchdog` in dbgscope's `src/dbgeng.rs`, and
`execute_command_bounded` beside it for the shape a bounded direct call takes here.
`DebugEngine::read_memory_bounded` is the shape an *unbounded* direct call takes when the watchdog
cannot be shown to reach it, and `EngineOp::ReadMemory` is the `patience_ms` half already done.
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
  shape rather than a novelty. So the fix is three decisions, not one.
- **The `reachable` third is done** ([#299](https://github.com/glslang/windbg-mcp/pull/299)), and
  the paragraph above used to say two wrong things about it. `reachable` does **not** call
  `resolve` up to `max_functions` times: at most **twice**, once for the target coordinate
  (`address`, or the `rva` half of `module`+`rva` — the two forms are mutually exclusive) and once
  for `from`, both before the walk starts. The `max_functions` figure belongs to the `uf`, which is
  a different command. And "a per-call bound is the wrong instrument for the same reason item 13
  gives" was wrong outright, as [#296](https://github.com/glslang/windbg-mcp/pull/296) measured: a
  `uf` blocked on a deferred symbol load blocks the one thread the session has, so no poll between
  calls can run. That op now spends its deadline on every command it causes — the `uf`, the
  `lm m <module>` that rebases a `module`+`rva` target, and the `? <expr>` behind both address
  arguments, through a `resolve_within` that takes a budget.
- **And the allowlist could not have caught that**, which is worth knowing before trusting it for
  the other two thirds. It counts `Execute` call sites by the function they are *written* in, so
  an unbounded command inside `resolve` is charged to `resolve` however many ops reach it: backing
  one of `reachable`'s preliminaries out to the unbounded helper leaves that test green. Measured,
  not assumed. `worker::tests::the_reachability_op_resolves_nothing_unbounded` asserts the one op
  that carries a deadline reaches no unbounded helper; the general version of that check does not
  exist.
- **What would close it:** a `patience_ms` on `EngineOp::Disassemble`, and `run_to_address` passing
  down the `timeout_ms` it already has. Done together, `resolve` leaves the allowlist in
  `worker::tests::every_unbounded_execute_in_this_worker_is_accounted_for`, which is where
  the deferral is recorded in code.
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

## 61. [windbg-mcp] Attribute the CVE-2026-83498 fix independently of similarity scores

Personal comparison and export coverage are complete, but the Windows component filenames
remain candidates: MSRC did not identify an affected file, and cumulative-update differences
do not establish which change fixes the CVE.

**2026-09-15 implementation:** [the attribution investigation](docs/cve-2026-83498-attribution.md)
refreshes CVRF and all eight ARM64 artifacts, reviews the complete retained comparisons,
and verifies a concrete stale-pointer cleanup fix with a hash-gated instruction checker.
The competing CVE-2026-69501 fits that change more closely. A Windows 10 ARM64
discriminating pair was identified, but its exact files collide on a symbol-server key
serving a third hash. Attribution to CVE-2026-83498 remains unresolved.

- **Why deferred:** the user requested delivery and tracking, rather than further investigation,
  on 2026-09-12. This does not gate Personal delivery.
- **What would close it:** evidence tying a specific component and changed behavior across the
  applicable fix boundary to the CVE; retain alternative explanations and distinguish inferred
  attribution from authoritative confirmation. No exploit trigger is required.
- **Where it picks up:** [CVE acceptance](docs/cve-patch-diff-acceptance.md),
  [securekernel export follow-up](docs/secure-kernel/securekernel-export-followup.md), and the
  [MSRC patch-diff skill](skills/msrc-patch-diff/SKILL.md). Under Codex the investigation uses
  `gpt-daybreak-blue-latest` as the skill specifies.

## 62. [windbg-mcp + binja-windbg-mcp] Capture a live securekernel handoff

The benign ARM64 fixture closes generic similarity-to-WinDbg acceptance. It does not establish
a live securekernel handoff. Existing evidence identifies no disposable, paused session with
the exact selected securekernel build already loaded.

**2026-09-15 implementation:** the maintained
[read-only probe and offline checks](docs/secure-kernel/securekernel-handoff-acceptance.md) are implemented.
Authenticated discovery found no sessions on the existing WinDbg listener; live handoff
remains `not_run`. The probe leaves supplied sessions open and restricts debugger calls
to inspection, including a fixed `bl` command for breakpoint comparison.

- **Why deferred:** the user requested tracking on 2026-09-12. Acquiring a PE or comparing it
  does not authorize loading a driver, resuming a target, or creating a vulnerability trigger.
- **What would close it:** identify an existing suitable session and loaded-module identity,
  navigate to a target match, capture a guarded read/runtime-byte comparison, and record refusal
  for the other build's identity. Preserve execution state and unrelated sessions. Record
  breakpoint/run-to evidence separately if such execution is subsequently authorized.
- **Where it picks up:** [generic handoff](docs/similarity-windbg-acceptance.md),
  [securekernel capture](docs/secure-kernel/securekernel-export-followup.md), and the skill's live-handoff
  preconditions. This is an optional CVE-specific extension, not a Personal release gate.

## 64. [Binary Ninja upstream] Verify the FirstSetupDialog shutdown fix

[Vector35/binaryninja-api#8549](https://github.com/Vector35/binaryninja-api/issues/8549) tracks
the macOS application Quit path attempting to delete a stack-allocated first-run wizard.
The guarded capture workflow avoids that trigger; it does not fix Binary Ninja itself.

**2026-09-15 implementation:** the maintained
[isolated launcher and shutdown captures](docs/followups-validation.md#shutdown-observations)
reproduce the wizard's SIGABRT on 6.0.10601 and pass wizard-disabled, modal-guard,
active-export and active-matching controls. The upstream issue is still open with no
fixed build identified. No installed application was patched.

- **Why deferred:** the upstream issue remained open at the 2026-09-12 delivery check.
- **What would close it:** an upstream fix and an isolated reproduction showing normal exit
  with the original wizard scenario, followed by the documented active-export/matching checks.
  Retain modal startup/quit guards unless the supported-version contract changes.
- **Where it picks up:** [shutdown investigation](docs/bn-shutdown-investigation.md) and the
  upstream issue, including their native stack evidence. Run one disposable GUI at a time.

## 65. [binja-windbg-mcp] Native Ultimate validation — deferred due to cost

Ultimate is unavailable and prohibitively expensive for the user. Purchasing it is not a
requirement, and its absence does not gate Personal/external BinDiff delivery.

**2026-09-15 implementation:** real GUI provider discovery confirms native BinDiff and
WARP are unavailable in the installed Personal edition. The
[conditional acceptance checklist](docs/followups-validation.md#conditional-ultimate-checklist)
is ready; no native comparison execution is claimed.

- **Why deferred:** explicitly excluded from further work by the user on 2026-09-12.
- **What would reopen it:** access to an appropriate Ultimate installation without requiring
  purchase, and a user decision to validate it. Then capture provider discovery, BinDiff/WARP
  comparisons, cancellation, and lifecycle behavior against the native backend.
- **Where it picks up:** [similarity plan](docs/binja6-similarity-plan.md). Native-boundary
  test doubles do not count as Ultimate execution evidence.

## 66. [windbg-mcp] The switch resolver refuses what it trips over rather than matching what a compiler emits

`ioctl::follow_table` reasons **backwards** from an indirect jump: it walks the block for whatever
defined the register, accepts a shape it recognises, and refuses when something stops it. That is
the wrong way round for a pass whose answer is published as fact. Every instruction the walk has not
been told about is a hole that fails toward a resolved table, so the rule list grows one review
round at a time — one fold and not two, a `DWORD` entry and not a `QWORD`, no `call` in the chain,
no second byte map, a pointer-width copy, a bound read at the load. Each is locally right and none
of them is the general statement.

The general statement is short, because the thing being recognised is short: MSVC and Clang emit two
or three switch idioms, and a driver's dispatch routine is one of them or is not a switch this can
follow. Matching those **positively** — a pattern over the block, tried in order, with anything
unmatched left unresolved — says the same thing the accumulated refusals say, and says it in a form
where an instruction nobody anticipated falls out rather than falls through.

- **Why deferred:** it is a rewrite of the resolver rather than a fix, and it lands after the two
  changes that cost less and buy more: the decoder's write set
  ([dbgscope#155](https://github.com/glslang/dbgscope/issues/155)), which closes the
  implicit-destination family at the source, and the differential oracle in
  `src/ioctl/tests/differential.rs`, which is what would tell a rewrite it had not lost anything. Both are
  in [#307](https://github.com/glslang/windbg-mcp/pull/307).
- **What would close it:** `follow_table` replaced by a small set of named idioms — the one-table
  `lea`/`mov`/`add`/`jmp` form, the two-table dense switch, and the 32-bit `jmp [table+idx*4]` —
  each matched forwards over the block with its own test, and the refusals that exist today deleted
  rather than kept beside them. `mountmgr` in the checked-in dump is the oracle: 48 case records
  over 24 codes with both 81-entry tables followed, asserted by
  `an_ioctl_map_of_a_driver_in_a_dump_is_its_chain_and_both_its_tables`.
- **What it costs meanwhile:** nothing a measured driver shows. Every refusal added on #305 left
  that oracle unmoved, which is the evidence that these shapes are adversarial rather than
  compiled — and also the reason this is worth doing on a clock somebody chooses rather than under
  a review round.

**Where it picks up.** `ioctl::follow_table` and `keeps_a_bound` in `src/ioctl.rs`, the fixtures
around `a_two_table_switch_is_read_through_its_byte_map`, and the generated routines in
`src/ioctl/tests/differential.rs`, which is where a rewrite would be shown not to have lost a shape.

## 67. [windbg-mcp] A branch with a constant condition has a dead edge the walk still reads

`ioctl::map_within` explores **both** edges of every conditional branch, which is what a
path-insensitive walk does and is right whenever the condition depends on anything. It is wrong when
the condition is a constant. `xor ecx,ecx` immediately before a `je` sets the zero flag, so that
branch is taken for every input and its fall-through is unreachable — and every compare the walk
then finds along it is a case the driver has, in a block execution never enters. The map reports
those codes with landings, handlers and sizes, and nothing in the answer says the path was
hypothetical.

The walk already does half of this correctly: an instruction that writes the flags drops the pending
compare (`instruction.writes_flags`, pinned by
`a_compare_survives_an_instruction_that_writes_no_flags`), so no case is invented **at** the poisoned
branch. What it does not do is stop believing the edge.

- **Why deferred:** the shape needs a flag write between a compare and its branch, which a compiler
  cannot emit — its own branch would break — so this is a hand-written or obfuscated driver rather
  than a compiled one, and no measured driver moves. The general fix is path sensitivity, which this
  module deliberately does not have; the specific one below is small but is a new kind of fact in
  `Facts` and belongs on a clock somebody chooses.
- **What would close it:** fold the self-cancelling idioms — `xor r,r`, `sub r,r`, and `test r,r`
  against a register known to hold a literal — into a known zero flag, and drop the edge the
  condition excludes rather than sweeping it. A case recovered in a block no live edge reaches is
  then not recovered at all. The alternative, marking such cases rather than dropping them, needs a
  field on `IoctlCase` and a sentence in every renderer.
- **How it was found, which is the part worth keeping:** the differential oracle in
  `src/ioctl/tests/differential.rs`, on seed 102 of the 512 it ran then, the first time its
  interpreter modelled the flags the logical operations write. The walk said code `0x6dfffe` reached a landing; execution
  took the earlier branch and never arrived. The generator now keeps flag writes out from between a
  compare and its branch — see `noise` — so the property measures the walk's **recovery** rather
  than this assumption, and closing this item is what would let that restriction go.

**Where it picks up.** The terminator arm in `ioctl::map_within` that reads `compared` against
`Flow::Branch`, the `writes_flags` fold above it, and `noise` in `src/ioctl/tests/differential.rs`,
whose `flags` parameter exists only because of this.

## 68. [windbg-mcp] Whether a device can have no security descriptor at all

**Repo:** `windbg-mcp`.

**This item's original premise was wrong, and the correction is the content.** It was filed saying
that most devices carry no descriptor of their own, so the gate that applies is the directory's and
`device_security` stops one lookup short of it. `\Device\KsecDD` and `\Device\Tcp` were named as
examples. Both of them do carry one.

What was being read was the **object header's** `SecurityDescriptor`, which is null for every
device -- the `Device` object type carries
`TypeInfo.SecurityProcedure = nt!IopGetSetSecurityObject`, so the descriptor lives in the body at
`_DEVICE_OBJECT+0x110` instead. That confusion is the same defect the tool itself had at the time
and which a later round of the same PR fixed; this entry was written from the buggy reading and
nobody re-derived it afterwards.

- **Re-measured 2026-09-13**, on the same live Windows Server 26100 guest, against the field the
  tool now reads. First every device object in `\Device` -- **157 of them, zero nulls** -- and then,
  because that sweep can only see devices the namespace names, every device object reachable from
  every driver object in `\Driver` and `\FileSystem`: **231 devices off 122 driver chains, zero
  nulls**, of which **66 carry no name at all** (`_OBJECT_HEADER.InfoMask` is `0`, against `2` on
  `\Device\MountPointManager`). Both runs carried a negative control -- the object header's
  descriptor field, null on all 231 and printed -- so an empty result is a measurement rather than
  a query that silently matched nothing. `\Device\KsecDD` is `0xffffe50685598320` and `\Device\Tcp`
  is `0xffffe506857f53a0`.
- **So an unnamed device does not answer this either**, which is worth stating because it is the
  obvious place to look: `IoCreateDevice` called with no name still leaves a descriptor on all 66
  measured here. A test fixture in `src/device.rs` claimed the opposite in a doc comment and is
  corrected in the same commit as this entry.
- **Half of this has now landed, and the entry is what is left.** `Security::Absent`'s sentence no
  longer claims the directory holding the object is checked instead: it states what was read and
  says the rest is not something it looked at. That was one of the two closing options below,
  taken because a tool asserting an unmeasured mechanism is worse than one admitting a gap.
- **What is actually left**, and it is much smaller: whether a **path-resolvable** device can lack
  its body descriptor at all. `ObInsertObject` assigns one from the type's default, which is why it
  may be unreachable by construction, and `device::Security::Absent` is a branch nothing on this
  build reaches. Whether the object manager really does fall back to the directory is still
  unmeasured -- it is simply no longer *claimed* anywhere.
- **Scoped to a named device deliberately.** `device_security` takes an object path and refuses an
  address, reaching the descriptor by walking the namespace, so a device with no name is outside
  what it can be asked about however it is built -- and has no parent directory to supply the
  fallback this entry is about. Widening the question to "any device object" would make it one
  this tool could not act on the answer to.
- **Why deferred:** it is a question about an unreachable branch's honesty, not a missing feature.
  Deleting the branch needs proof that it cannot be reached on any build, which is a stronger claim
  than one guest supports; keeping it needs its sentence checked rather than assumed.
- **What would close it:** a construction that produces a path-resolvable device with a null
  descriptor -- at which point the directory-fallback question becomes real, is worth measuring
  against `nt!ObpCheckObjectAccess`, and the original entry can be rewritten back. Failing that, a
  decision that an unreachable branch carrying an honest sentence is a resting state rather than a
  defect, which closes it with no code change at all.

**Where it picks up.** The `Security` enum and `render` in `src/device.rs`, and the
`security_absent` field in `src/structured.rs`.

## 69. [windbg-mcp] Record what the ACE-kind rules were measured against

**Repo:** `windbg-mcp`.

Rounds eight and ten of [#311](https://github.com/glslang/windbg-mcp/pull/311) classified ACE types
this tool will not meet. `AceKind::mask_is_access` names `0x04`..=`0x10` and `Ace::callback` covers
`0x09`..=`0x10`, which pulls in the object-callback types and `SYSTEM_ALARM_CALLBACK`. Both changes
are correct, and nothing observed here exercises either: an object ACE's `ObjectType` GUID names a
directory service property set or extended right, which is meaningless for a device, and the
`SYSTEM_ALARM_*` family has never been implemented by Windows at all.

**Unexercised is not unreachable, and the distinction is the whole of why this is a trim and not a
removal.** A device's DACL is whatever was assigned to it, so an installer is free to put any
documented ACE type in one, and a descriptor read off a target is bytes rather than something
Windows vouches for. The sweep below bounds what one machine's *defaults* contain; it does not
bound the parser's input.

Measured the same day and not applied to the finding: across every distinct descriptor behind every
device in `\Device` on a 26100 guest -- 41 descriptors, 149 ACEs -- **every ACE is type `0x00`**.
Not one callback ACE of any kind, let alone an object-callback one.

- **Why deferred:** the code is right and the tests are right, so nothing here is a fix. What is
  left is writing the measurement down where the next reader of those rules will meet it.
- **What would close it:** put the 149-of-149 figure in `sd.rs` beside the ACE-kind rules, with
  the bound stated -- one machine's *defaults*, not the parser's input domain -- so the next
  finding in this family is weighed against it rather than implemented, and so nobody reads the
  measurement as licence to delete the handling.
- **Two deletions were considered and both are rejected**, which is most of why this entry exists
  rather than a commit. **The classifications stay**, `0x10` included: it carries an `ACCESS_MASK`
  at the documented offset whether or not Windows implements alarms, so naming it is right
  independently of whether it is ever met. **And the object-ACE GUID fixture stays**, which is a
  reversal: this entry first proposed dropping it as the artificial part, and that contradicted
  the paragraph above it in this same entry -- if an installer may put any documented ACE type in
  a device's DACL, then an object ACE is valid input and the fixture covers a valid layout. It is
  also the only thing standing under that rule: the `conditional`-widened mutation was **not**
  caught by the suite until that construction existed, so deleting it restores an uncaught
  mutation. A contrived fixture pinning a real rule beats no fixture.
- **How it was found:** the maintainer, reading the round-ten commit and calling it artificial --
  which it read as, and which turned out to be about the entry's framing rather than the test.

**Where it picks up.** `AceKind::mask_is_access` and `read_ace` in `src/sd.rs`, and that test.

## 71. [windbg-mcp] `driver_surface` does not say which control code reaches which sink

**Repo:** `windbg-mcp`.

`docs/binja-windbg-mcp-plan.md:138` specifies a bounded dispatch-to-sink traversal -- "disabled for
ordinary map calls and enabled by `driver_surface`", default depth 2 and 128 functions, hard maxima
of depth 8 and 1,024 functions, with cancellation and deadline checks. **That did not land.** The
composite reports `ioctl_map`'s cases and `driver_hazards`' sinks side by side, and nothing joins
them: a reader gets "this driver accepts `0x222003`" and "this driver calls `MmMapIoSpace` at 79
sites" and has to ask `reachable_from_dispatch` per pair to find out whether the first reaches the
second.

That join is the analysis Driver Buddy Revolutions is actually valued for, and it is the one thing a
composite is better placed to do than its parts -- it already holds the case list, the sink call
sites and one disassembly budget.

- **Why deferred:** it is a fifth analysis rather than a composition of the four, it needs the
  traversal bounds the plan fixes and a per-case halt story of its own, and the composite is worth
  having without it. Landing it inside the branch that added the tool would have put a new walk
  behind a surface change that was already the largest wire raise in this file's history.
- **What would close it:** the traversal, bounded as the plan's figures say, reported per case
  rather than per driver -- a case that reaches a sink, with the path, and a case whose reachability
  was not settled within the bounds saying so rather than reading as one that reaches nothing. The
  asymmetry `reachable_from_dispatch` already documents is the shape to follow: reachable is sound,
  not-reachable is bounded-effort, and the two must not be a boolean.
- **How it was found:** writing `driver_surface` against the plan that specifies it, and comparing
  what shipped with `docs/binja-windbg-mcp-plan.md:138` line by line (2026-09-13).

**Where it picks up.** `driver_surface` in `src/worker.rs`, the walk in `src/driver.rs`, and the
bounds at `docs/binja-windbg-mcp-plan.md:138`.

## 72. [windbg-mcp] The driver tools name a module refresh they could run themselves

**Repo:** `windbg-mcp`.

A fresh kernel attach leaves the debugger's module inventory holding `nt` and little else --
measured on a KDNET target 2026-09-13, **1** module at attach against **156** after `modules
{ "refresh": true }`. Every driver loaded before the attach is absent from the inventory rather
than from the target, and the driver tools have nothing to resolve a module extent against.

They still answer, and answer worse: `driver_surface` on `mountmgr` recovered **19** control codes
instead of **45**, both 81-entry jump tables unresolved, every address unattributed and the hazard
section `unavailable`. Following a table needs the image's executable ranges, which need the module
extent, which needs the inventory.

The tools are honest about it -- the map lists the tables under `unresolved`, so it reads as the
lower bound it is, and `unattributed_image` now says the inventory looks like a fresh attach and
names the refresh. What they do not do is *run* it, so a caller gets a poorer answer and a second
call to make.

- **Why deferred:** resynchronising has **no wall-clock bound** of its own -- that is item 54, still
  open -- so starting one inside a deadline-bounded composite is a way to spend a caller's whole
  budget on a call nothing can cut short. Fixing item 54 first makes this safe; doing it before
  makes the composite's deadline a fiction.
- **What would close it:** a bounded refresh, run **once** and only where a module lookup has
  already failed, with the result reported (a section that says "the inventory was resynchronised
  and the module was still not there" is a different answer from one that never looked). It should
  stay opt-outable: a caller driving many tools over one attach wants to pay for it once, not per
  tool.
- **How it was found:** running the live-kernel tier for `driver_surface` after
  [#314](https://github.com/glslang/windbg-mcp/pull/314) merged, which is the only tier where a
  module inventory can be stale at all -- a dump's is complete the moment it opens (2026-09-13).

**Where it picks up.** `unattributed_image` and `scan_of` in `src/worker.rs`, `modules`'s own
`refresh` in the same file, and item 54 for the bound it needs.

## 73. [windbg-mcp] A driver's import directory can be in a section the loader freed

**Repo:** `windbg-mcp`.

`driver_hazards` cannot answer for **HEVD** on a live kernel, and the reason is structural rather
than incidental. Its import directory is at RVA `0x8a4a0`, inside `INIT`, whose characteristics
carry `IMAGE_SCN_MEM_DISCARDABLE` (`0x62000020`) -- Windows frees those pages once `DriverEntry`
returns. The bytes are not paged out; they are gone. `mountmgr` keeps its directory in `.idata` and
is unaffected, which is why every measurement before HEVD was clean.

The tool now says so precisely, and says it having been **measured**: an executable image path plus
`.reload /f` leaves `dd HEVD+0x8a4a0 L4` reading `????????` on a live target, because the engine
substitutes an image file's bytes where a *capture* has none and a live target's freed pages are
mapped-and-invalid instead. The same driver in a **dump** scans fine, where the file does supply it.

What that costs is not small: HEVD imports **six** names on this tool's own sink list --
`ExAllocatePoolWithTag`, `IoCreateSymbolicLink`, `ProbeForRead`, `ProbeForWrite`, `ZwCreateFile`,
`ZwWriteFile` -- and Driver Buddy Revolutions, reading the same bytes from the file, reports 20
`ProbeForRead` and 4 `ProbeForWrite` call sites. The canonical vulnerable driver is the one this
cannot answer about.

- **Why deferred:** the fix is for the tool to read the image **file** itself rather than asking the
  engine for bytes nobody has, and that needs a file the *host* can open. The module row carries
  `\??\C:\HEVD\bin\HEVD.sys`, which is a path on the **target**, and a kernel debugger has no
  file transport. So this is a new input (an image path argument, or a symbol-store lookup by the
  module's timestamp and `SizeOfImage`) rather than a change to the parse -- `src/pe.rs` already
  takes a `read(addr, len)` closure and would need nothing.
- **What would close it:** `driver_hazards` accepting an image file to read the PE structures from
  when the target's copy will not answer, with the result saying which source each half came from.
  The code scan still wants target memory -- relocations and the IAT are applied there and a file's
  are not -- so this is the *headers and imports* half only, which is exactly the half that fails.
- **How it was found:** running Driver Buddy Revolutions and Ghidra over the same image as an
  independent oracle (`tools/ghidra_oracle/`), then tracing the failing read to a section and
  reading its characteristics (2026-09-14).

**Where it picks up.** `hazards_at` in `src/worker.rs`, `pe_failure` beside it for the message this
already produces, and `pe::Section::discardable`.

## 74. [windbg-mcp] The driver tools report no pool tags

**Repo:** `windbg-mcp`.

Driver Buddy Revolutions recovers a driver's own pool tags and the functions that pass them --
`MntA` in forty-four functions and `MntB` in one, for `mountmgr` -- and none of the four driver
tools reports them at all. It is the one section of the program these were ported from that has no
counterpart here.

The repo is not without the capability: `pool_find_tag` walks a target's pool for a tag somebody
already knows. What is missing is the other direction -- which tags *this driver* uses, read from
its own code, which is what makes the walk worth starting.

- **Why deferred:** it is a genuine addition rather than a correction, and the recovery is a
  heuristic with a false-positive rate somebody has to choose: a four-byte printable immediate
  passed to an allocator is a tag, and a four-byte printable immediate is also a magic number, a
  FourCC and a small string. Driver Buddy's own HEVD run shows the cost of getting that wrong in
  the neighbouring IOCTL pass, where it reported `0xbad0b0b0` and `0x2ddfa232` as control codes.
- **What would close it:** tags read from the **call sites of the allocators already on the sink
  list** rather than from a scan of every immediate -- `ExAllocatePool2`, `ExAllocatePoolWithTag`
  and their family take the tag as an argument, so the evidence is the call rather than the
  constant, and a tag recovered that way says which allocation it belongs to. Reported beside
  `sinks[]`, and joined to `pool_find_tag` by a `TOOL_NOTES` cross-reference.
- **How it was found:** comparing all four tools against Driver Buddy Revolutions over `mountmgr`
  and HEVD (2026-09-14).

**Where it picks up.** `src/hazards.rs`'s sink call-site recovery, which already has the call sites
these arguments belong to, and `pool_find_tag` in `src/worker.rs` for the join.

## 84. [windbg-mcp] An `adrp`+`add` table base is lost at the `add`

**Repo:** `windbg-mcp`.

A compiler materialises a page-relative address in two instructions -- `adrp x8,<page>` /
`add x8,x8,#<offset>` -- and `ioctl::update` models `Effect::Add` only as `Value::Code +
immediate`, so the `add` clears the register and a table base built that way is gone. The jump goes
back `unresolved`, which is the safe direction but is silent about *why*.

**It is not a size threshold, and the first draft of this item said it was.** `adr` reaches ±1 MB,
so it is tempting to reason that only a driver larger than that needs the pair -- but a compiler
picks `adrp`+`add` for ordinary globals and relocatable references well inside that range, which is
a codegen choice rather than a reach one. Raised on review of
[#347](https://github.com/glslang/windbg-mcp/pull/347), and `mountmgr` proves it at **139 KB**:
`mountmgr+0x19450` is `adrp x8,mountmgr!QueryPointsFromMemory+0x610` / `add x22,x8,#0x4E8`, four
instructions after one of the jump tables this branch reads. So the shape is already on this bench
and in the smallest fixtures; what none of them does is use it for a **table base**, which is the
only position `follow_table` asks about.

**Why deferred:** no measurement here reaches the position that matters, and the fix is one arm
whose blast radius is every `Value::Address` consumer -- worth doing beside item 82, which opens
the same function. A fixture for it should be one of the small drivers rather than a hypothetical
large one.

**Where it picks up:** `ioctl::update`'s `Effect::Add` arm (`src/ioctl.rs`), where the
`_ => set(facts, &destination, None)` fall-through is.

## 87. [windbg-mcp] A code materialised in the previous block is lost at the join

**Repo:** `windbg-mcp`.

`volmgr!VmDeviceControl` on the live ARM64 target runs a chain of compares against the traced
control code, each constant built `mov w9,#<low>` / `movk w9,#0x76,lsl #0x10` and tested
`cmp w8,w9` / `b.eq`. Four such compares sit at `+0x1cf0`, `+0x1d04`, `+0x1d18` and `+0x1d28` --
spaced 20, 20 and 16 bytes, the wider gaps being the two that carry a `b.hi` as well. Three
constants were read off the target; the fourth was not, so it is left out rather than guessed at:

| site | constant | branch target? | result |
|---|---|---|---|
| `volmgr+0x1d04` | `0x764328` | no | case |
| `volmgr+0x1d18` | `0x760320` | no | case |
| `volmgr+0x1d28` | `0x764324` | **yes** | **absent**, site in `untracked` |

`+0x1cf0` is a recovered site too; its constant was not read, which is why it is not a row. The
first draft of this item said "four constants in twenty bytes" and gave a distance of twelve for
`+0x1d04`; both were wrong, and review caught them.

**The third column is the cause.** Something else in the routine branches to `+0x1d28`, so the
`cmp` *begins a basic block* and the `mov`/`movk` that build `w9` are in the block before it. What
a block knows is what every path into it agrees on, and the other path does not carry that literal
-- so `w9` is unresolved at the compare, `compare` answers `code: None` with an `index`, and the
site is filed in `untracked`. Measured from `uf volmgr!VmDeviceControl`: `+0x1d28` appears as a
branch target in the listing and `+0x1d04`, `+0x1d10`, `+0x1d18` and `+0x1d20` do not.

So this is the **mirror** of the defect `tools/ghidra_oracle/README.md` records finding on x64
`mountmgr` -- there a `cmp` / `ja` / `je` put the compare in one block and the equality in the
next; here the compare and its branch are together and the *operand's materialisation* is in the
block before. Same seam, opposite side, and this one is A64-shaped because A64 needs two
instructions to build the constant at all, which gives the join something to fall between.

**Not silently short.** `untracked` carries the site, which is what item 82 is about, and `volmgr`
reports five of them against 63 recovered cases. What is missing is the code's *value*.

**The remedy this item first proposed is a no-op, and that is the useful part of it.** The draft
said the decision was whether a value *every* predecessor sets identically may survive the join.
`Facts::join` already does exactly that -- it retains a register only where the incoming value
equals the one it holds (`src/ioctl.rs`) -- so implementing that sentence changes nothing. Raised
on review of [#347](https://github.com/glslang/windbg-mcp/pull/347), and checking it is what makes
the real shape of the work visible: the predecessors here **do not** agree. One edge into `+0x1d28`
falls through the `mov`/`movk` and carries `0x764324`; the other arrives from elsewhere and does
not. The join is right to drop it.

**So closing this needs path sensitivity, not a better merge.** The compare has to be evaluated on
the edge that carries the literal -- per-edge facts, or a representation that keeps a register's
value qualified by where it came from -- which is a different and larger change from anything in
items 82 to 84. Doing it loosely invents a code the driver does not accept, which is the failure
this module is arranged against above all others.

**How it was found:** verifying a review finding on
[#347](https://github.com/glslang/windbg-mcp/pull/347) that item 82 overstated its diagnostic gap.
The finding was right, and checking *which* `untracked` entries `volmgr` had turned up this
underneath it.

**Where it picks up:** `ioctl::compare` and `scalar_of` (`src/ioctl.rs`), the
`(Condition::Equal | Condition::NotEqual, None)` arm that files an `untracked` entry, and the
block-entry merge that decides what `Facts` a block starts with. A fixture has to be built from the
real block sequence -- a hand-written four-compare chain has no join in it and already passes.

## 91. [windbg-mcp] A refusal that returns through a shared epilogue is not recognised

**Repo:** `windbg-mcp`.

`rdyboost!SmdDispatchDeviceControl` on the live ARM64 target answers 17 cases, **13** of which
carry an `input` length check and **every one** of those reports `exact: false`. Measured
2026-09-20 against `windbg-mcp 0.18.0+gfb1d1a28`, which carries item 82's literal-pool read -- so
this is what is left after that landed, not a restatement of it.

The condition half is right, and so is the value. `rdyboost+0xf2f4` is `cmp w2,#4` /
`bne rdyboost+0xf068`, which is the `Condition::NotEqual` the `exact` rule wants; the branch target
is `ldr w20,<rdyboost+0xf3d8>` / `b rdyboost+0xef84`, and that pool entry holds `0xc000000d`
(`STATUS_INVALID_PARAMETER`), read off the target. What the refusal never does is write the return
register **in that block**: it parks the status in `w20` and jumps to the routine's shared
epilogue, where `mov w0,w20` / `ret` is what returns it.

**The blocker is one line of policy, and it is a defensible line.** `ioctl::refuses_in`
(`src/ioctl.rs`) follows up to three hops of tail jump and follows **only unconditional** ones --
*"a block that decides something is deciding it, and whatever it reaches is not simply this block's
answer"*. `rdyboost`'s epilogue begins `cbnz w23,rdyboost+0xf37c`, so hop one lands on a block that
decides something, the walk stops, and the `mov w0,w20` one instruction further on is never read. The
facts are carried along tail edges rather than joined (`carried` in the same function), so the
`w20` the refusal set would still be in hand if the walk got there.

**Why this is not just "raise the hop count".** Following a conditional means choosing an edge, and
choosing the wrong one reports a refusal on a path that accepts -- which takes a handler away from
a code the driver serves, the failure this module is arranged against. What might be sound is
narrower: a block whose *only* work is a conditional branch decides nothing about the status, so
both its successors continue the same status, and the walk could follow the edge that returns.
That is a claim about this shape rather than a general one, and it needs the mutation test before
it is believed -- back the rule out and watch an existing assertion fail
(`.claude/rules/measurement-provenance.md`).

**Why deferred:** it is a change to the one function every case's `accepted` and `exact` flow
through, in a module whose IOCTL recovery drew thirty-nine review findings over fourteen rounds
(items 66--67), and the
payoff is sizes on drivers nobody has asked this of yet. **And the second opinion does not help
here**, which item 85 expected it to: its lane now runs `rdyboost` through the Binary Ninja
companion (2026-09-20) and that implementation proves **no** size on any of the three ARM64
fixtures, so there is no independent answer to check a fix against -- only the driver's own
instructions, which is what the paragraph above reads.

**Where it picks up:** `ioctl::refuses_in` and `failure_block` (`src/ioctl.rs`), the
`(true, [next])` arm that decides which tail jump is followed, and `sizes_in`'s fourth rule --
*"only the branch target being a refusal says the fall-through is the accepted path"* -- which is
what consumes the answer.

## 92. [windbg-mcp] An A64 conditional-compare chain is a compare chain the walk does not read

**Repo:** `windbg-mcp`.

A64 has `ccmp`, so a compiler writes `if (code == A || code == B || code == C)` as **one** branch
fed by three compares. `ioctl_map` reads the instruction before the branch and files the rest in
`untracked`, so every code in such a chain is lost. Measured on `rdyboost` on the live ARM64
target, 2026-09-20, against `windbg-mcp 0.18.0+g30c4af94`:

```
rdyboost+0xef00  mov    w11,#0xC008 / movk w11,#0x56,lsl #0x10   ; w11 = 0x0056c008
rdyboost+0xef08  mov    w10,#0xA0   / movk w10,#7,lsl #0x10      ; w10 = 0x000700a0
rdyboost+0xef10  cmp    w8,w11
rdyboost+0xef14  ccmpne w8,w12,#4
rdyboost+0xef18  ccmpne w8,w10,#4
rdyboost+0xef1c  beq    rdyboost+0xef7c
```

Three codes, one handler. The map reports **`untracked` at `0xef18`** -- the last `ccmp` -- and
names none of them. The second chain is the same shape: `rdyboost+0xf00c` is `cmp w8,#0` /
`ccmpne w8,w10,#0` / `bne`, with `w10 = 0x00224194` built two instructions earlier, and
`untracked` carries `0xf010`. So on this driver the map's 17 cases are short by at least
**`0x0056c008`**, **`0x000700a0`** and **`0x00224194`** -- `w12`'s value was not read and is left
out rather than guessed at.

**This is the mirror of the x64 defect that made `tools/ghidra_oracle/` worth building.** There,
`cmp` / `ja` / `je` was *one* compare feeding two branches, which put the compare in one basic
block and the equality in the next. Here it is several compares feeding one branch, inside a single
block. Same seam, opposite side, and this one is A64-shaped because x86 has no `ccmp`.

**Not silently short**, which is the one thing already right: both sites are in `untracked`, so the
answer says it is a lower bound and points at the instruction. What is missing is the values.

**How it was found, and what that says about the fix.** The ARM64 diff lane (item 85, now in
[`DONE.md`](./DONE.md)) reported two codes only the Binary Ninja companion had, at exactly the two
sites this walk had filed as `untracked` -- so the two implementations agreed about *where* they
could not read something, and reading the target settled what was there. The companion is **also**
wrong here, differently: it publishes the chain's *first* operand as a case and misses the `ccmp`
operands -- and on the second chain that first operand is the arm the routine **rejects**, so its
map carries `0x00000000` and not the `0x00224194` the block actually accepts. Filed as
[`binja-windbg-mcp` issue 14](https://github.com/glslang/binja-windbg-mcp/issues/14). So there is
no implementation to copy, and a fix here cannot be validated by agreeing with that one.

**Where it picks up:** `ioctl::compare` and the `Condition` it derives (`src/ioctl.rs`), which
pairs a branch with the comparison before it. A `ccmp` carries its own condition and an `nzcv`
immediate for the not-taken case, so reading a chain means folding several comparisons into one
branch's condition -- and **the immediate is what decides the shape**, which the two chains above
demonstrate in opposite directions. `ccmpne w8,w10,#4` leaves `Z` *set* when the previous compare
already matched, so a match at any link reaches the `beq` and the chain is a disjunction of three
accepted codes. `ccmpne w8,w10,#0` leaves `Z` *clear*, so `w8 == 0` takes the `bne` away from the
case and only the `ccmp`'s own operand falls into it -- one accepted code, and the first compare's
operand is the rejected one. An earlier draft of this entry read the first of those onto both,
which would have had a fix accept `0x00000000`. A fixture has to be the real instruction sequence:
a hand-written chain of ordinary `cmp`s has no `ccmp` in it and already passes.

## 88. [windbg-mcp] A call that outlives its budget finishes its work and has the answer discarded

`Sessions::call_within` says it plainly — *"Note the job itself is not cancelled — only this wait
for it"* — and `reader`'s `WorkerMessage::Done` arm is where that lands: it removes the waiter,
sends the result into a `oneshot` whose receiver went with the timed-out caller, and treats the
failure as expected. Which it is, and the comment there says so: *"For an ordinary call that is
fine — removing the entry above is what mattered, and it is how the session stops counting as
busy."*

**It is fine for the session and not for the work.** A job that outruns the 300 s
`ENGINE_CALL_TIMEOUT` and finishes anyway produces the whole answer and has it dropped on the
floor — the caller is told the call timed out and has no way to ask for what it computed.
Re-running it pays the same minutes again, against a target that may have moved in between. The
**openers** already escape this, and by exactly the mechanism worth copying: their timeout hands
back a `session_id`, the same `Done` arm special-cases `OPENER_JOB` so the state settles with
nobody waiting, and `session_status` answers afterwards.

**Which jobs can actually get there is a much shorter list than it looks, and this entry first
named the wrong ones.** Review caught `pool_census` and `heap_census` as its headline examples:
both go through `worker::walk_budget`, which takes the caller's remaining patience less
`WATCHDOG_HEADROOM` and has **no floor**, so the walk stops itself and returns an *incomplete but
delivered* answer rather than running past the deadline. That is deliberate and documented — the
budget exists, in its own words, to prevent "a walk still running after its caller gave up", and a
truncated walk is not even cached, so there is nothing to collect.

**So the rule, and deliberately not a list of ops.** An op is in scope if **any part of its work has
no clock** — not if the op as a whole looks unbounded. **Five of the six review findings on
[#349](https://github.com/glslang/windbg-mcp/pull/349) landed on this one paragraph** (counted from
its comments on 2026-09-19), each naming an arm the version before it had got wrong, which is what
says the list is the wrong artefact for a follow-up entry to carry: the arms are a thing only
`worker.rs` knows, and it moves. What is durable is the rule, the method, and the two cases that
show why the obvious shortcut fails.

**The shortcut is `EngineOp::patience_slot`**, which is already this crate's enumeration of what
carries the caller's clock — and it answers about a **field**, not about the work, so it is wrong in
both directions:

  - **An op can carry a patience and still have an unbounded tail.** `CrashTriage`: `bug_check` and
    `is_kernel_target` before the analysis and the stack walk after it are direct engine calls, and
    only the `!analyze` in the middle is bounded. `TRIAGE_READ_RESERVE` *reserves* time for those
    reads rather than bounding them — a reservation a symbol server can outlast.
  - **And an op can carry no patience and still be mostly bounded, with an unbounded step in front
    of it.** `RunToAddress`: the run itself is bounded by `timeout_ms`, but `run_to_address` reaches
    the target through the **unbounded** `resolve` — the same call
    `the_reachability_op_resolves_nothing_unbounded` exists to keep out of the reachability op, and
    which `proto.rs` says is deliberate here because this op "carr[ies] no deadline to spend"
    (item 56). A symbolic address whose symbol has to be fetched blocks with nothing able to stop
    it.

So the set cannot be read off a field, and this entry does not pretend to have it: **deriving it is
part of the work, and the audit is unstarted.** It names ops that *are* in scope and deliberately
certifies **none** as out — all five of those findings were about an op this entry had **excluded**,
and not one about an op it had included, so the exclusions are the half that cannot be written here
honestly. In scope, non-exhaustively: `Modules` (item 54 — `Reload("")` has no
wall-clock bound and is a wait with no upper bound on 115200-baud serial), `SymbolPath`
(`reload_symbols` plus a raw `.sympath`, and the tool reached for *because* symbols are not
resolving, i.e. against the slow source), `ExceptionTriage`, `Backtrace`, `Registers`,
`Disassemble`, `CurrentLocation`, `UnboundedCommand`, and `CrashTriage` and `RunToAddress` by the
rule above.

**And the trap that made half those rounds, which is the thing actually worth carrying:** classify
the **dispatch arm**, never the helper it calls. The unbounded work sits in a *prelude*, before the
clock is armed, so reading `fn set_breakpoint` says nothing about `EngineOp::SetBreakpoint`. The
worked case is `resolve_coordinate`, shared by **three** arms — `SetBreakpoint`, `ReadMemory` and
`RunToAddress` — which runs `e.modules()` (itself an op on the in-scope list above) and
`with_pdb_identity` before any of the three reaches its watchdog. Two of those three carry a
patience, so `patience_slot` clears all three. One precision while doing that audit, because it is
easy to inflate: `with_pdb_identity` calls `module_pdb` only where `module.symbols` is already
`Pdb` or `Dia`, so it *reads* an identity the engine holds rather than fetching a PDB — the
unbounded part is the enumeration and that read, not a symbol download.

**One half of this is a clamp rather than a store, and is worth doing on its own.**
`run_to_address` passes the caller's `timeout_ms` straight through
(`args.timeout_ms.unwrap_or(EXEC_WAIT_MS)`), where `wait_for_stop` caps its own wait below the call
timeout with a `.min(…)` and `STOP_WAIT_MARGIN` for exactly this reason. So a caller may name a run
bound *longer* than the server's call timeout and guarantee the discard: the supervisor gives up
first, the run continues, and the verdict — `HIT`, `STOPPED ELSEWHERE` — is thrown away. Capping it
the way `wait_for_stop` does needs none of the machinery below.

**The pattern to build it from is already here**, which is why this is worth doing without the tasks
extension (`FOLLOWUPS.md` item 8, where the measurement says no client on this wire can drive one
today). `continue_async` spawns a task that files a run's stop into the session's `execution` slot
**keyed by job** rather than by handle, precisely so a caller who has gone away still leaves a result
somebody can read, and `wait_for_stop` reads it rather than taking it. A late answer to an ordinary
call is the same shape with a different payload.

**Five things the design has to answer, and the third is the one that makes this more than plumbing.**

- **Where the caller gets the key.** The opener's timeout names a `session_id`; an ordinary call's
  timeout names nothing it could come back with. So the job id has to reach the caller, which is a
  change to the `EngineError::Timeout` message *and* to the structured half a client parses — not
  just prose.
- **How much of it to keep.** A stop is one `StopReport`, while these are the largest answers this
  server gives — `docs/token-budget.md`'s *Results* section and
  `tool_results_stay_within_their_budget` are where their sizes are recorded, and item 27's
  baseline column measures one `modules` listing at 53,897 B model-visible. A per-session ring of
  them is a memory bound with no natural size, so the store wants to be small and to **say what it
  dropped** rather than silently keeping the last one.
- **A late answer describes a moment, and a stale one read as current is worse than none.** This is
  the asymmetry with a stop, which *is* a moment by construction. A `backtrace` or a `modules`
  listing describes the target as it stood when the job ran, and between then and the collection an
  `execute`, a `go` or a `continue_async` may have moved it — so the record has to carry when it
  was taken and what happened to the session since, or a caller reads a minutes-old stack as the
  present one. The conservative answer may well be that a late answer is invalidated by any
  intervening mutation, which is a rule the session already has the information to apply.
- **It must not keep the session alive.** `Session::busy` reads the waiter map *and* the execution
  slot, and `last_used` is what reclamation reads. A late-answer store that either of those noticed
  would make a session un-reclaimable for holding a result nobody asked for — the opposite of the
  `Done` arm's "it is how the session stops counting as busy".
- **Which ops are eligible.** A read's late answer is a convenience; a *mutating* command's is a
  report about a change that has already happened, and `end_session`'s is moot. Worth deciding by
  op rather than filing everything, and `EngineOp` is where that distinction already lives.

**Why deferred:** it is a new store, a new key on the wire and a staleness rule, on a path whose
current behaviour is deliberate and documented rather than broken — so it wants weighing against
simply raising `WINDBG_MCP_CALL_TIMEOUT_SECS` for the handful of tools that reach it. What argues
for building it is that the timeout is per *call* and these tools' cost scales with the target, so
no one constant fits a small dump and a live kernel both.

**Picks up at** `engine::reader`'s `WorkerMessage::Done` arm, `Sessions::call_within`'s timeout
path, and `continue_async`'s filing task as the worked example. Independent of item 8, and cheaper:
no capability negotiation, no extension, and it works for the client item 8 measured.

## 94. [windbg-mcp] Disabling a breakpoint has no typed tool

`clear_breakpoints` removes; nothing arms or disarms one in place. dbgscope has had
`DebugEngine::enable_breakpoint` since its typed breakpoint API landed, so this is a tool-surface
gap rather than a missing primitive -- the same shape item 2 records for `ba`, which was
*reported* for weeks before `set_breakpoint` grew a `watch` to set it.

- **Why deferred:** no consumer asked for it. The two tools added on 2026-09-20 were filed against
  a measured need -- a hypervisor regression calling a listing tool that did not exist, and a
  narrowed `session,exec` surface that could arm a breakpoint on a live kernel and had no typed
  way to take it off -- and `bd`/`be` has neither half of that. `execute` still reaches it.
- **What closes it:** a consumer, then `enabled` on the existing removal tool or a tool of its
  own, plus the debugger-tier round trip the other two have. Decide which *before* writing it: a
  disable that shares `clear_breakpoints`' argument shape would make `ids` mean two different
  mutations depending on a second field, which is the combination that tool refuses to guess at
  today.
- **Picks up at:** `worker::clear_breakpoints` and `ClearBreakpointsArgs`, and
  `breakpoints_are_listed_and_cleared_through_their_own_tools` for the round trip.

## 97. [dbgscope] An LFH block awaiting a delayed free is reported allocated

**Repo:** `dbgscope`.

`ntdll!RtlpHpLfhSubsegmentWalk`, which `HeapWalk` reaches, copies the subsegment's block bitmap
and then walks `State.DelayFreeList` — the list head holds a slot index plus one, and each block on
the list holds the next in its first two bytes — clearing both of that block's bits in the copy
before it tests any. So a block freed but not yet returned to the bitmap is free to `HeapWalk` and
busy in the bitmap as stored, which is what the heap tools read. Read from the disassembly on x64
26100.8972 and ARM64 26100.1, 2026-09-23; `nt` has the same list
(`RtlpHpLfhSubsegmentDelayFreeListProcess`).

- **Why deferred:** not seen. `user_heap_smoke` frees nothing, and every subsegment measured had
  `DelayFreeCount` zero, so the walker and `HeapWalk` agreed exactly without it — which also means
  nothing here would catch it.
- **What would close it:** read the chain at discovery, bounded by `BlockCount` and
  `DelayFreeCount`, and report those slots `CachedFree` — the state the heap tools already give a
  VS chunk on a delay-free list. And give `user_heap_smoke` a free that lands on the list, which
  first means finding what sends one there (`RtlpHpLfhSubsegmentDelayFreeListBatch` is where to
  start).
- **Where it picks up:** the LFH arm of `discover_segment_context` in dbgscope's
  `src/pool/snapshot.rs`, and `_HEAP_LFH_SUBSEGMENT_STATE` in `src/pool/layout.rs`.

## 100. [dbgscope] The VS chunk chain comes apart on 29671 — the target's paging, not the build

**Repo:** `dbgscope`. **Measured and declined 2026-09-24.**

**The chain is not coming apart: the headers it names are paged out.** On `lab-nt` the memory each
lost extent points back into holds a committed, written, *trimmed* page, and a KD link cannot fault
one in. The walk declines to invent chunks there and says so, which is what it is built to do —
so there is nothing in `walk_vs` to fix, and the 29671 hypothesis below is unnecessary rather than
merely unproven. What the run did leave is a **third** memory state — a page that will not read is
reserved, *or* committed and trimmed, *or* committed and present — and that is what settled item 98
against the remedy it had specified: no allocator commit record separates the last two, and the
memory manager answers all three (now in [`DONE.md`](./DONE.md), dbgscope#183).

### What settled it

Server `windbg-mcp 0.19.0+g46737cc4` (the stdio release exe), both guests walked through the tool
surface within two minutes of each other:

| | `ctf-vm` | `lab-nt` |
|---|---|---|
| Build | 26100.33438 `lt_release_svc_prod1.260904-1524` | 29671.1000 `rs_prerelease.260911-1426` |
| Uptime at attach | 17:07:24 | 19:40:42 |
| Walked / allocated | 783,042 / 690,128 (88.1%) | 756,638 / 617,425 (81.6%) |
| Diagnostics | 207, in 4 shapes | 3,616, in 9 shapes |
| `does not begin on a chunk boundary` | **0** | 459 |
| `cannot be placed` | **0** | 332 |
| `unplaced_bytes` | **0** (no `gaps` block) | 15,626,240 |
| Modified pages (`!vm 1`) | **170** (680 Kb) | **41,614** (166,456 Kb) |

**Uptime is eliminated.** `ctf-vm` was walked at *longer* uptime than the 3h34m this item was filed
against and produced none of either shape, so "a busier, more fragmented pool" in the sense of age
is not the explanation.

**What the two guests' holes actually are, which is the whole answer.** `!pte` on the pages the
chain names:

- `ctf-vm` — PTE contains `0000000000000080`: **DemandZero**, `Protect: 4 - ReadWrite`. Never
  written, so no chunk header was ever in it and the chain is never orphaned. These are the kernel
  equivalent of item 98's uncommitted tails — and only the *equivalent*: item 98's fix is
  `QueryVirtual`, which a kernel session cannot be asked, so the kernel walk still counts these.
- `lab-nt` — PTE contains `0x0003330700002088`, and four more with the same low word and a
  different `PageFileHigh` (`0x1695`, `0x16d8`, `0x33321`, `0x33338`, over the pages
  `0xffffabecca216000`, `…26e000`, `…2cb000`, `…30f000` and `…34f000`):
  `Valid=0, Prototype=0, Transition=0, Protection=4 ReadWrite, PageFileLow=2`. **Pagefile PTEs**,
  5 of 5 sampled. Only *paged* pool can carry one, so these are paged-pool headers written and then
  trimmed — and `lab-nt` is trimming hard, at 245× `ctf-vm`'s modified-page count.

The readable side confirms the reading rather than resting on it: at `0xffffabecca217000`, the first
byte of an extent whose predecessor is unreadable, the bytes are
`00 00 2b 03 4d 69 52 72` — a genuine `_POOL_HEADER` tagged `MiRr` — its PTE is a valid hardware one
(`0x86000000f5fc8943`, `Valid=1`), and `pool_chunk` on it answers `covered: false`. The cost is real
and it is exactly the 15.6 MB reported.

### The build comparison this item asked for, and why it was never going to answer

`_HEAP_VS_CHUNK_HEADER` does differ: at `+0x008`, 26100 has `SkipDuringWalk` at `Pos 9, 1 Bit` with
`Spare` at `Pos 10, 22 Bits`, while 29671 has no such field and `Spare` starts at `Pos 9, 23 Bits`.
`_HEAP_VS_CHUNK_HEADER_SIZE` is unchanged in offsets.

**That is the expected case, not a finding.** These structures change between builds, and the walker
is built for it: every type and field is resolved by name from the PDB at run time
(`type_id`/`type_size`/`field_offset` in `src/pool/layout.rs`), which is what keeps one walker
correct across builds, and `layout.fingerprint` on every answer moves when an offset does. A
layout diff therefore cannot by itself explain a behaviour split — the code compensates for exactly
that. `SkipDuringWalk` additionally goes unread on both builds; the pinned checkout (`9bd539d`)
contains no reference to it.

Recorded so the next person diffing these builds does not stop here: the diff is real, it is
routine, and it is not the mechanism.

- **Why it stays here rather than moving to `DONE.md`:** nothing was built. The reopening condition
  is the content above.
- **What would reopen it:** a target that loses the chain where the named page is **not** a pagefile
  PTE. That would be a placement defect and belongs with item 101.
- **The confound that remains, and it does not matter here:** one guest per build, and `lab-nt` is
  also a hypervisor root partition (`Partition Pages: 4096`), so "29671" and "this guest under this
  load" are not separated. The mechanism found is build-independent — any target trimming paged pool
  does this — so no build change is needed to explain the split. VBS was checked and is *not* the
  discriminator: both guests run the Secure Kernel (`SkPagesInUnchargedSlabs` 5,931 on `ctf-vm`
  against 5,437 on `lab-nt`).

### Three `!` extensions do not work on 29671, and they do not say so

Named individually, because "partly degraded" — which is what this entry said before — is not a
usable warning. Each of these ran to completion and printed a confident wrong number:

- **`!pte` does not work.** It computes from a **zero** PTE base: for `0xffffabecca2167e0` it
  printed `PTE at 00000055F66510B0`, while `nt!MmPteBase` reads `0xffffa90000000000` and the entry
  is really at `0xffffa955f66510b0` — same low bits, base lost. Every PTE quoted above was read at
  an address computed by hand from `nt!MmPteBase` for that reason.
- **`!vm`'s system-PTE and paged-pool figures do not work.** It prints
  `Unable to get offset of nt!_MI_VISIBLE_STATE.SystemPteInfo` — `dt` confirms the field is absent
  on this build — and then reports `Free System PTEs: 0` and `Running out of system PTEs` on a
  healthy guest, and `PagedPool Commit: 0` on a machine whose paged pool is demonstrably in the
  pagefile. The rest of its output is fine, which is what makes it dangerous.
- **`!pool`'s region classification does not work**, as this entry already noted:
  `No page table info`, `MI_SYSTEM_INFORMATION.Vs.SystemVaType not initialized`, region `Unknown`.

**The common failure is the substitution, not the missing field.** Each looks a field up by name,
does not find it on this build, and carries on with zero instead of refusing. That is the opposite
of what `src/pool/layout.rs` does with the same lookup — a type or field it cannot resolve is an
error carrying the name, and the answer reports the layout it did resolve. So on a build this new,
these three are not oracles; the walker's own reading and the raw bytes are.

- **Where it picks up if reopened:** `walk_vs` and the extent placement in dbgscope's
  `src/pool/snapshot.rs`.

<details>
<summary>The original 2026-09-23 reading, kept for the numbers it established</summary>

The pool walker was run against `lab-nt` — Windows **29671** (`rs_prerelease`, 260911-1426), some
3,500 builds past the 26100 everything else here is measured on — 2026-09-23, to check the item 96
fixes were not fitted to one build. They are not: `_HEAP_LFH_SUBSEGMENT` and `_POOL_HEADER` have
identical offsets, `RtlpHpLfhSubsegmentCountAllocatedBlocks` is the same popcount less padding less
withheld, `ExpAddTagForBigPages` still shifts the whole pointer and multiplies 64 bits wide, and
the walk reports **457,457 allocated of 552,676** (82.8%, against 83.0% on the fixed `ctf-vm`).
Every block checked against `!pool` agreed, including ones `pool_find_tag` had not returned.

What is new there is the diagnostics: **2,160** against 172, in two shapes that `ctf-vm` produces
none of —

- `VS extent at # does not begin on a chunk boundary: the chunk chain names # # bytes back inside
  unreadable memory; # bytes not decoded` — 254
- `VS extent at # cannot be placed: the chain was already lost earlier in this region; # bytes not
  decoded` — 204

— beside 272 unreadable VS free tree nodes and `unplaced_bytes: 7,700,480`.

The deferral then read: *one reading of one machine, and the confound is not ruled out — that guest
is a hypervisor lab's root partition with 3h34m uptime, `ctf-vm` had minutes, and a busier, more
fragmented pool is a complete explanation.* Both counts roughly doubled by the next day's walk as
uptime went 3h34m → 19h40m (254 → 459, 204 → 332, 7.7 MB → 15.6 MB), so load does scale them; what
it does not do is produce them, which is what the 26100 control settled.

</details>

## 101. [dbgscope] The VS chunk chain drifts 0x10, and not from where it starts

**Repo:** `dbgscope`, surfaced by `windbg-mcp`'s `pool_*` tools.

Left over from item 99, and now the only thing left in it. On a live 26100.33438 kernel
(2026-09-24) the walk places a VS chunk's `_POOL_HEADER` **0x10 before** where one really is, for
every chunk in certain subsegments. Read from the bytes rather than from `!pool`'s heuristic: at
`0xffff8b836d46f000` sits a genuine `_POOL_HEADER` — `BlockSize` `0x21`, `PoolType` `0x02`, tag
`MmLd`, matching `!pool`'s `size: 210` exactly — while the walk read the eight bytes 0x10 earlier,
which are a pointer, and reported the tag `0x838bffff`: the top half of a kernel address.

It is **not a lost chain**: the walk's chunk starts 0x10 early *and* is 0x10 long, so each chunk
ends where the real one does and the next is found. The size it reports is over by the same 0x10 —
528 against `!pool`'s 0x210 less its header.

Item 99's fix removed the part of this that was about tags: a chunk too large for
`_POOL_HEADER.BlockSize` is now named from `nt!PoolBigPageTable` by containment, so its placement
does not matter. What is left is the chunks *under* that limit, which do carry a header and whose
header the walk mislocates — 1,047 of them under `0x838bffff` alone, 2.0 MB, on the run that
measured this.

- **Why deferred:** the obvious cause is ruled out and no other is established. It would be a
  guess, and item 99's remedy was built specifically so that it did not have to wait for this.
- **What would close it:** find which chunk introduces the 0x10. **The chunk area's start is not
  it** — `sizeof(_HEAP_VS_SUBSEGMENT)` is `0x28`, the first chunk header is at `+0x30` where
  `discover_segment_context` computes it, and a real `MiSe` `_POOL_HEADER` sits at `+0x40`. So the
  chain begins correctly and drifts later, which points at a chunk whose `UnsafeSize` covers
  something the walk does not expect — a big-pool chunk is the obvious candidate, since those are
  the ones with no header and the drift shows up after them. Read
  `nt!RtlpHpVsChunkSplit`/`RtlpHpVsSubsegmentInitialize` for what a header-less chunk's
  `UnsafeSize` counts.
- **Where it picks up:** `walk_vs`'s chain arithmetic in dbgscope's `src/pool/snapshot.rs`, and
  `decode_vs_chunk` in `src/pool/decode.rs`. **This is not item 100**, which that entry's
  measurement settled on 2026-09-24: item 100's extents begin on a boundary the walk cannot *read*
  — the page holding the previous header is paged out — whereas this one mislocates a header in
  memory that reads fine. The drift here is a uniform 0x10; there, the gap between the chain's
  expectation and the next readable boundary runs to 0x820 and more, and varies per site. A target
  that loses the chain where the named page is **not** a pagefile PTE would belong here.

## 102. [windbg-mcp] A `debug_batch` runs its rollback against whatever target it ends up holding

**Repo:** `windbg-mcp`.

Found while closing item 81, and **not introduced by it** — item 81's fingerprint retires the
session's handles when a batch's op ends holding a different target, which is the *handle*
guarantee. What it does not do is stop the batch, and that is the sharper half.

`batch::run` watches one thing between steps: `done.target_gone`, which ends the batch with
`BatchOutcome::TargetGone`. A target that has been **replaced** rather than released reads as an
ordinary step, so every remaining step runs against the replacement — and so does the `always`
block. `always` exists to put a mutation back, so on this path it writes a restore into a target
that never had the mutation, at an address that means something else there. On a live kernel that
is a write into somebody else's machine.

Nothing upstream stops it. `batch::validate` refuses unknown fields and bad operands and says
nothing about command text; `batch::retires_handle` and `batch::mutation` both ask
`server::changes_debug_target`, which matches the first token of each `;`-separated segment and so
cannot see `.opendump` inside a `.if`, a `.foreach` or an alias — and `retires_handle` retires the
*handle* in any case, which does not stop a batch that is already running. So
`debug_batch { steps: [{op: "command", command: ".if (1) { .opendump C:\\other.dmp }"}, …],
always: [{op: "command", command: "eb <addr> <saved>"}] }` reaches it.

**Reached independently by Codex** on [#389](https://github.com/glslang/windbg-mcp/pull/389) while
that PR was in review, which is the useful part: two readings converging on the same remedy —
recheck at step boundaries and abort the remaining steps *including the cleanup* — is worth more
than either.

**Why this was not folded into item 81.** The mechanism is cheap — the worker already computes the
fingerprint (`worker::replacement_now`), and `batch::Debuggee` is the trait the step loop asks
about the target — but the *decision* is not: `always` is sold as "cleanup cannot be lost", and the
right answer here is to **lose** it, because running it is worse than skipping it.

**And there is no existing skip to reuse for that**, which is the thing to know before pricing it.
The rollback block runs on **every** path today, `BatchOutcome::TargetGone` included — that case is
survivable only because a target that is *gone* refuses every cleanup step, so they fail and are
reported as failures rather than succeeding somewhere else. A *replaced* target accepts them. So
the main-loop decision is new code rather than a second trigger on an existing one; what does
already exist is the per-step half, `StepOutcome::skipped(position, step, reason)`, which the
`always` loop uses for the out-of-time case and which is the right shape for this one. That needs a `BatchOutcome` for it, a
`rollback` disposition that says "not attempted, and deliberately", and both of those move the
output schema and its goldens. It is a contract change to the one tool whose contract is about
what survives failure, and it deserves its own review rather than a third round on somebody
else's PR.

**Where it picks up.** `batch::run`'s between-steps checks and its `ended` flag
(`src/batch.rs`), `batch::Debuggee` and the worker's implementation of it, `BatchOutcome` and
`structured::BatchReportInfo`'s `rollback_complete`. The fingerprint to ask is
`worker::replacement_now`, which already answers exactly this question for an op and would need to
answer it for a step. `docs/debug-batch.md` states the rollback contract and would move with it.

## 103. [windbg-mcp] H5b — expose the Secure Kernel reads, without forcing them through DbgEng

**Repo:** `windbg-mcp`. **Origin:** the H5 route decision in
[`docs/secure-kernel/secure-kernel-hypercall-feasibility.md`](docs/secure-kernel/secure-kernel-hypercall-feasibility.md),
2026-09-26. H0–H4 passed: a root partition can read a VBS guest's VTL1 and `securekernel.exe`,
`KdDebuggerDataBlock` and `SkLoadedModuleList` were all located and identified. H5a — driving
DbgEng through EXDI — is parked behind a two-part reversal condition, so this is the route.

**One setup constraint, one open question, and two capabilities — an earlier draft of this item
overstated the first two into blockers and got the third wrong.**

- **The driver is a setup cost, not a shipping blocker.** It remains true that no such driver can
  be WHQL-signed and that every alternative makes the operator reconfigure their machine. What does
  **not** follow is that nothing ships: this repo already ships capabilities behind documented
  manual setup — the live-kernel tier needs KDNET wiring and a local profile, and the engine bundle
  needs a one-time copy. So H5b ships as an **opt-in research feature with manual steps**, where the
  repo distributes no driver and the operator supplies the transport. That is an install step and a
  security-posture note to write down, not a reason to build less. **Once it is in place, the rest
  is drivable from it.**
- **Execution control is an open question, not a settled impossibility.** What is established is
  narrower than "there is none": post-26100 `securekernel.exe` ships no KD transport **of its own**,
  every `Kd`-prefixed symbol in it being data. But the **hypervisor** carries VTL1 debug machinery —
  a root VTL1 debug context and an active port `0xC35C` (50012) were measured; it was configured,
  did not activate, and the initialization failure was never named. The validation record declines
  the stronger claim in terms: *"They do not establish that this Windows build lacks Secure Kernel
  debugging support."* And `kdnet.exe` on this bench reports network debugging supported for the VM.
  So stepping is **an item to settle** (S5), not a door to close.
- **Writes: measured by S4 on 2026-09-26, and the answer differs per route.** An earlier draft of
  this item asserted VTL1 was patchable from the existence of a wrapper; the ABI argued otherwise
  (`HV_ACCESS_GPA_RESULT_CODE` defines `HvAccessGpaWriteIntercept` (3) beside the `ReadIntercept`
  (2) H4 measured), and the ABI was right. **`HvCallWriteGpa` writes VTL0 and is refused on VTL1
  with `WriteIntercept`** — symmetric with the read, and with `HV_STATUS` reading `SUCCESS` on the
  refusal, so a refused write looks like one that landed. **The direct route accepts a VTL1 write**
  while refusing an unmapped one, so its return value discriminates; whether the bytes land is
  unproven and needs a differing-bytes write, which S4 excluded by design.

### S0 — the gate that decides how much setup a user needs. Do it first

**Is there a driver-free memory source that contains VTL1 pages?** Everything below is the same
code with a different byte source, so this does not decide whether H5b ships — the manual-setup
route does that — but **how far the audience reaches**: a driver-free source means an operator with
no weakened bench, no test-signing and no loaded driver can use S1–S3 against a captured guest,
while a driver-only answer means every user pays the full posture cost. It is a measurement rather
than a design choice, and it is cheap, so it goes first.

The asymmetry to test, and the reason it is not obvious: **a guest kernel crash dump cannot work**,
because the guest's own NT cannot read VTL1 memory and therefore cannot write it into a dump — the
same refusal H4 measured from the outside. A **Hyper-V saved state** is written by the *host*, so
it is the candidate that could contain those pages. Whether it does is unmeasured, and what turns
on it is **the audience and the setup cost**, not whether the item ships — consistent with the
failure branch below and with the first constraint above, where the operator-supplied transport
carries S1–S3 either way.

- **Pass:** SK's PML4, `securekernel.exe` and the `KDBG` block are reachable from a saved state of
  the VBS guest, with no driver loaded, matching what the live path found for the same boot.
- **Control:** the same read against a saved state of the **VBS-off** guest finds no SK — H4's
  Control 1 repeated on the new source, which is what separates "read the guest" from "read
  something".
- **If it fails:** S1–S3 still ship, behind the operator-supplied transport and its documented
  setup. What changes is the install instructions and who can follow them, so write that down
  rather than treating a driver-only answer as a failure of the item.

### S1 — the decode layer, source-agnostic. The bulk of the work, and offline-testable

Everything H4 did, expressed over a single `read(gpa, len)` seam so the byte source is a parameter:
the guarded four-level page-table walk, PE identification against an on-disk image, the
`KdDebuggerDataBlock` decode, and the `SkLoadedModuleList` walk.

**It is testable with no bench, no driver and no VM** — recorded pages as fixtures — which is what
makes it worth building even if S0 fails. Three things must be pinned by tests rather than
discovered again:

- **Cycle guards.** SK's PML4 self-maps (index 388 on the measured build), so an unguarded descent
  re-enters the table 512× per level. Unguarded, this took the bench down twice and needed a
  reboot each time. Pin: skip entries whose target PFN is the table they came from, a visited set
  per level, and hard budgets on reads *and* collected leaves that **report** a partial result.
- **Read width.** `HvCallReadGpa` moves at most 16 bytes, and judging a 4096-byte page on its first
  sixteen is what made SK's PML4 read as all-zero for most of a session. Any source-side chunking
  must not leak into the decode layer's view of a page.
- **The status/result split.** A refused read can answer `HV_STATUS_SUCCESS` with a per-access
  `ReadIntercept` and zeros. A source that collapses the two produces silent zeros exactly where
  the protected memory is; the seam must carry *why* a read failed, not just bytes-or-not.

### S2 — symbols, which is the one place DbgEng earns its keep

Resolve `securekernel.exe`'s symbols and types against a base supplied by S1. This is the part
worth keeping DbgEng for, and **the only part**: the remaining primitives are reads this server
already has from S1, and routing those through an engine that has no target buys nothing.

**Unknown to settle before committing:** `dbgscope`'s symbol methods (`symbol_offset`,
`symbol_for`, `module_symbol_file`) all assume a session with a target. Image-only resolution —
load `securekernel.exe` at a given base with no debuggee and resolve against it — is not obviously
available, and if it needs an engine call it is a **typed `dbgscope` method**, per this repo's rule
that a new DbgEng primitive belongs there rather than behind the `execute` text hatch. Size that
before promising symbols.

### S3 — the tool surface

Shape it after S0 and S2 answer, not now. What the plan asked for is SK base and size, structure
walks, and symbol resolution against the image. Note that a reader with no debuggee fits this
server's existing session model awkwardly — the one-worker-per-debuggee reason for the worker
process does not apply — so whether this is a session kind, a sessionless tool group or a separate
surface is a real design question, and **S0 and S5 both move it**: a live driver-backed source is
not a fixed snapshot, and an S5 pass would bring execution state back into a surface shaped on the
assumption that there is none.

### S4 — settle the write routes — **RUN 2026-09-26, mostly settled**

**Result in the feasibility record.** The hypercall refuses VTL1 writes symmetrically with the read
(`AccessResult = 3 WriteIntercept`), writes VTL0 fine, and honours the address field — so
`HvCallWriteGpa` cannot patch VTL1 and a software breakpoint is not available through hypercalls at
all. The direct route **accepts** a VTL1 write while **refusing** an unmapped one, so its return
value discriminates; what remains open is whether the bytes land, which only a **differing-bytes**
write can show and which this gate excluded by design. That residue is a decision about risking the
guest, not a measurement. The original specification follows.

#### S4 as specified — settle the write routes, with a test that changes nothing

Run this before anything in the repo tells an implementer that patching is available, and note it
is **not** a prerequisite for S0–S3, which need no writes at all. The test is a round-trip that is
a no-op on success: **read 16 bytes, write the identical bytes back, read again.** It exercises
the whole path and returns an `AccessResult` either way, while leaving the guest byte-for-byte as
it was — so a refusal costs nothing and a success corrupts nothing. Run it on a VTL0 page as the
control, then on a VTL1-protected page, on each of the two routes independently, since H4 already
showed the two routes disagree about VTL1 for reads.

- **Pass / fail is per route**, and the interesting outcome is the asymmetry: the direct route
  reading VTL1 where the hypercall will not says nothing about whether it *writes* there.
- **Do not** write different bytes into a running guest to test this.

**And the hazard, stated conditionally because the premise is unproven.** A software breakpoint
*is* a memory patch, so **if** S4 finds VTL1 writable, an `int 3` is one write away — and without a
delivered trap it bugchecks the guest, with SKPG/HyperGuard in the business of noticing exactly
that. So breakpoints are gated on **both** S4 (can we write?) and S5 (can we catch it?), and
neither answer alone is a licence. Until S4 runs, nothing here should be read as saying VTL1 can be
patched.

### S5 — can VTL1 execution be controlled at all? Independent of S0–S3, and worth its own answer

Not required for S1–S3 to be useful, and it decides whether this ends as an inspector or a
debugger. The thread to pull is the one the validation record left open rather than a new idea:
the hypervisor's **root VTL1 debug context was configured and did not activate**, the failure was
never named, and a port (`0xC35C`, 50012) was already allocated. Two things were explicitly not
done and are the cheapest next steps — an early-boot trace capturing the activation return
directly, and the earlier handler guards that the bounded trace narrowed to. `kdnet.exe` reports
network debugging supported for this VM, so the transport side is not obviously the blocker.

- **Pass:** a VTL1 execution stop is delivered to a debugger, by any route.
- **Stop condition:** an activation failure that is named and is a deliberate refusal — that is an
  answer, and it retires the question rather than leaving it open.
- **Do not** plant an `int 3` in VTL1 to test this. Without a delivered trap it bugchecks the guest
  and is a plausible SKPG trip; the write primitive existing is not a reason to use it here.

### Out of scope, with the reason rather than as a list

- **Writes as a *tool surface***: the primitive exists and S1's seam should not pretend otherwise,
  but exposing "patch a live guest's VTL1" as a tool needs its own justification and confirmation,
  and nothing in S0–S3 needs it. Note the adjacency hazard when it is built: `HvCallWriteGpa` is
  `0x0054`, one off the read.
- **H5a / EXDI**: parked with its two-part reversal condition recorded. Not re-litigated here.
- **Distributing a driver**: the repo ships none; the operator supplies the transport, per the
  first constraint.

### Unknowns, in the order they change the plan

1. **S0's saved-state source** — decides how much setup a user needs, not whether it ships.
   Cheapest, and first.
2. **Image-only symbol resolution** — decides whether S2 is small or is a `dbgscope` change.
3. **S5's activation failure** — decides inspector versus debugger, and is the one that would
   change the shape of S3's tool surface rather than its contents. Independent of the rest, so it
   can run in parallel or not at all.
4. **Build stability of the offsets, and the derivation that replaces them.**
   `KdDebuggerDataBlock` at `+0x1335E0` and `SkLoadedModuleList` at `+0x127770` are **one build**,
   and the block's `Size` already disagreed with an earlier static reading (`0x3A0` live against
   `0x3A8` from the image). So the offsets are a fast path to *verify*, never the lookup — but
   "locate them by signature" is not the instruction either, and an earlier draft of this item said
   it: **`SkLoadedModuleList` is a bare `LIST_ENTRY` with nothing to search for.** Only the block
   has a signature. The derivation H4 actually used, and which an implementation should follow:

   1. Find `KdDebuggerDataBlock` by its **`KDBG` owner tag** within SK's address space, and *report*
      the `Size` found rather than matching a remembered constant — matching `0x3A8` exactly is
      what made a first scan report zero occurrences while the tag sat three pages away.
   2. **Validate it**: `KernBase` at `+0x18` must equal the SK base the PE walk established.
   3. **`SkLoadedModuleList` is then read out of it** — the `PsLoadedModuleList` field at `+0x48` —
      rather than located independently.
   4. **Validate that**: walk one entry and check its `DllBase` equals the same SK base.

   Keep the structural route — search for a `KLDR_DATA_TABLE_ENTRY` whose `DllBase` is the SK base
   with `SizeOfImage` sixteen bytes later, then follow its `Blink` — as the **cross-check** rather
   than the primary. It is what found the head independently in H4, and the two agreeing is what
   made either believable.
