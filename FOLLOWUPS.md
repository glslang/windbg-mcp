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
manager's answer rather than the allocator's. And item 105 from review on that item's PR after it had merged (2026-09-27): the
measurement item 102 took to correct its own example contradicts a claim this server's design is
introduced with, in about a dozen places that were never swept. And item 104 from closing item 102 (2026-09-26): the target fingerprint spells
*"this field does not apply"* and *"this field could not be read"* the same way, so two failures
compare equal and a recovery reads as a replacement — which a handle survives and a batch's
rollback does not.
And items 100–101 from checking its fixes end to
end through the tool surface once they had merged (2026-09-23) — the VS chunk chain coming apart
on **29671**, found while confirming those fixes were not fitted to 26100, which they are not; and
the same chain drifting 0x10 on 26100, which is all that is left of item 99 now that it too is in
[`DONE.md`](./DONE.md). They were filed as possibly one question and are **not** (2026-09-24):
item 100 is the target's paged pool being trimmed out from under a KD link, with nothing in the
walker to fix, and is measured and declined; item 101 is a real placement defect in readable
memory.
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
  is drivable from it.** And **S0 has since found that most users will not need it at all**: a
  Hyper-V saved state carries VTL1 and its page-table root with no driver in the picture, so the
  operator-supplied transport is what buys a *live* target rather than what buys access.
- **Execution control is an open question, and the hypervisor half of it already works.** What is
  established is narrower than "there is none": post-26100 `securekernel.exe` ships no KD transport
  **of its own**, every `Kd`-prefixed symbol in it being data. The **hypervisor's** VTL1 debug
  machinery is a separate thing and is **initialised**: its activation failure was identified
  (`0x1D`, debug free-page list exhausted), raising `hypervisordebugpages` resolved it, and active
  port `0xC35C` (50012) with both buffers allocated proves the allocations completed. **What is
  unresolved is Secure Kernel-side attachment** — a working port with nothing on the guest side
  connecting to it, which sits uncomfortably beside SK shipping no KD transport and may be the same
  wall. The validation record declines the stronger claim in terms: *"They do not establish that
  this Windows build lacks Secure Kernel debugging support."* So stepping is **an item to settle**
  (S5), starting at attachment rather than at activation.
- **Writes: measured by S4 on 2026-09-26, and the answer differs per route.** An earlier draft of
  this item asserted VTL1 was patchable from the existence of a wrapper; the ABI argued otherwise
  (`HV_ACCESS_GPA_RESULT_CODE` defines `HvAccessGpaWriteIntercept` (3) beside the `ReadIntercept`
  (2) H4 measured), and the ABI was right. **`HvCallWriteGpa` writes VTL0 and is refused on VTL1
  with `WriteIntercept`** — symmetric with the read, and with `HV_STATUS` reading `SUCCESS` on the
  refusal, so a refused write looks like one that landed. **The direct route writes VTL1** —
  differing bytes landed in `securekernel.exe`'s `.text` padding and read back, then restored. So
  VTL1 is fully read/write from the root by that route and refused both directions by the
  hypercall, and the **patch** half of a software breakpoint is solved while the **catch** half
  (S5) is not. **S5h has since measured a catch for VTL1 *user* mode** — a parent-installed exception
  intercept holds a `#BP` raised there and hands it back on removal, and **S5i has since read the
  hypervisor and found that intercept applied at every enabled VTL by design**. **Step 9's arm has
  since measured that the root receives a stop raised in VTL0** — a `#BP` raised there under a
  standing raw intercept arrives at `Vid!VidInterceptPreprocess`, which copies the message, stamps
  the VP and selects `VidHandleExceptionIntercept`. So a receiver exists **for the VTL0 stop**, and
  that is the whole of what is measured: the *catch* half is not closed generally, because the stop
  S5h held was a **VTL1** raise and step 9's arm did not read the markers for one. Whether any of it
  reaches Secure Kernel's own code remains an architectural inference after S5i rather than an open
  mechanism, because VTL1 user mode is not VTL1 kernel mode.

### S0 — the gate that decides how much setup a user needs — **RUN 2026-09-26, PASS**

**Yes, and it is Microsoft's own.** A Hyper-V **standard checkpoint** carries the guest's VTL1 pages
*and* its VTL1 `CR3`, read through `vmsavedstatedumpprovider.dll` from the Windows SDK — a
user-mode DLL with a documented header (`VmSavedStateDump.h`) and explicit VTL support
(`GetGuestEnabledVirtualTrustLevels`, `ForceActiveVirtualTrustLevel`). No driver, no test-signing,
no hypercall, no HVCI concession; the capture is a **file**, which was copied off Hyper-V's own
directory and read there with no VM named. The probe is
[`tools/sk_savedstate_probe.py`](tools/sk_savedstate_probe.py) and the full record, with both arms
and every number, is the **S0 result** section of
[`docs/secure-kernel/secure-kernel-hypercall-feasibility.md`](docs/secure-kernel/secure-kernel-hypercall-feasibility.md).

- **Same-boot agreement with the live route, landmark for landmark**: VTL1 `CR3` `0x1201000`,
  self-map index 388, 26 present entries, 123 non-zero bytes, first present entry at `0x850`, 11,326
  leaf pages from 166 table reads, `securekernel.exe` at GPA `0x00CD0000` identified against the
  on-disk image, `KdDebuggerDataBlock` at `+0x1335E0` with `Size` `0x3A0`, `SkLoadedModuleList` at
  `+0x127770`, the same six VTL1 modules, and the same four `KDBG` tags of which one is real.
- **Control, on the VBS-off twin**: the partition reports VTL0 only,
  `ForceActiveVirtualTrustLevel(vp0, 1)` is **refused by name** —
  `VM_SAVED_STATE_DUMP_E_VP_VTL_NOT_ENABLED` (`0xC0370509`) — and the same 32768-page physical scan
  finds **more** PE images than the VBS guest — 143 against 101, and 100 against 86 on a second
  capture of the same boot — with **0** `securekernel.exe` and **0** `KDBG` tags either time.
  The header counts move because a running guest's memory does; what is stable is 1-against-0
  matching images and 4-against-0 tags. The positive arm is what makes the negative mean
  anything.
- **A third boot broke a landmark this plan believed.** An older capture of the same guest carries
  VTL1 `CR3` `0x107593000`, self-map index 309, 29 present entries and SK based at
  `0xFFFFF8070EDA9000` — while the image-relative offsets and the GPA are unchanged. So the `CR3` is
  **not** reboot-stable, `docs/secure-kernel/README.md` said it was, and the correction is now
  there. **This is the measured case for the source contract**: an implementation carrying
  `0x1201000` forward would have walked from the wrong root on that capture and not been told.

**What it changes.** Not whether H5b ships — the manual-setup route already decided that — but who
can run it: an operator with no weakened bench can now do S1–S3 against a capture, and the
driver-backed live source is kept for what a snapshot cannot do. S1's source contract is confirmed
and satisfied as written, and it gains a free differential oracle in the provider's own VA→GPA
translator, which agreed with our walk. S3's design question gets a default: the common source is a
fixed snapshot with no debuggee, so the sessionless shape is the case to design for. **S5 is
untouched** — a capture has no execution to control, and if anything that sharpens the
inspector-versus-debugger question rather than answering it. The specification as written follows.

#### S0 as specified

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

**Two things have to come out of the source, not one.** Bytes are the obvious half; the other is the
**VTL1 page-table root**, which on the live path came from `HvCallGetVpRegisters` against a running
VP. A saved state has no VP to ask, so S0 is only a pass if the capture also yields VTL1's `CR3` —
from saved register state, or from a structure the walk can start at. Without it there is nothing
to walk *from*, and hard-coding the one measured `0x1201000` is not an answer.

- **Pass:** SK's PML4, `securekernel.exe` and the `KDBG` block are reachable from a saved state of
  the VBS guest, with no driver loaded, matching what the live path found for the same boot —
  **with the page-table root obtained from the capture** rather than carried over from a live run.
- **Control:** the same read against a saved state of the **VBS-off** guest finds no SK — H4's
  Control 1 repeated on the new source, which is what separates "read the guest" from "read
  something".
- **If it fails:** S1–S3 still ship, behind the operator-supplied transport and its documented
  setup. What changes is the install instructions and who can follow them, so write that down
  rather than treating a driver-only answer as a failure of the item.

#### S0 arm 4 — does the encryption knob cover the capture? — **RUN 2026-09-27: it does, and the provider crashes rather than refusing**

**The mitigation holds, so the verdict below stands.** With
`EncryptStateAndVmMigrationTraffic = $true`, **no VTL1 comes out** — and not because the walk found
nothing: `LoadSavedStateFile` never returns. The provider **fast-fails**, and the OS names it:
`windbg-mcp.exe 0.20.0.0`, faulting module **`vmsavedstatedumpprovider.dll 10.0.26100.7705`**,
exception **`0xC0000409`** — the status every `__fastfail` raises, whose legacy name
`STATUS_STACK_BUFFER_OVERRUN` is **not** a diagnosis — WER event name `BEX64`, fault offset
`0xD569`. Measured on **both** guests: the VBS-off control (arm 4a) and the VBS guest (arm 4b),
the second being the one that has a VTL1 to withhold.

**The control is what makes that attributable to the knob**, and it is the arm's whole rigour. A
*fresh plaintext* checkpoint of the same guest, taken minutes later on the next boot and read with
the identical command, **loads normally**: partition VTLs `0x1`, and the VTL1 switch refused with
`0xC0370509` as every plaintext control has been, exit 0. So the failure is not "a fresh capture",
not "this boot" and not the command — the one thing that differs is the setting.

**What this does not establish, and the distinction matters.** The capture is unreadable **by this
provider**; nothing here inspected its bytes, so "encrypted" is Hyper-V's claim about what it wrote
rather than something measured — an entropy reading would have been cheap and was not taken. Nor was
the encrypted checkpoint *applied*: Hyper-V presumably reads what it writes, but that is an
inference, and `Apply-VMSnapshot` is the check that would have made the capture's well-formedness a
measurement rather than an assumption. Shielded VMs are untested.

**And the arm found something it was not looking for, which is the part worth reporting.** A
**documented SDK API fast-fails on an input Microsoft's own hypervisor produced** — not a refusal,
not an `HRESULT`, a crash. **Measured under this server's own debugger**: subcode
**`0x7 FAST_FAIL_FATAL_APP_EXIT`**, the CRT's `abort`, reached from
`gsl::details::terminate` under `PartitionStateParser::GetPartitionStateVirtualProcessors` inside
`LoadSavedStateFile` — a **Guidelines Support Library contract violation** while parsing the
partition state, not a corruption check. So it is a robustness defect with a named cause: a parser
asserted on input it has no key for instead of returning an error. This entry said "the corruption
was *detected*" for one commit, reading `0xC0000409`'s name as its meaning; `src/fault.rs`'s own
`STATUS_STACK_BUFFER_OVERRUN` comment exists to stop exactly that, review caught it by citing it, and
the measurement then settled it. That `vmsavedstatedumpprovider.dll` bug was **reported to Microsoft via Feedback
Hub on 2026-09-27** and needs raising again by nobody; what remains is re-testing a later SDK against
the checked-in repro. It is a different
thing from the VBS-boundary question the arm was run to answer — which came back negative, as the
verdict says.

**It is written up as a sendable report**, in
[`docs/secure-kernel/vmsavedstatedumpprovider-crash.md`](docs/secure-kernel/vmsavedstatedumpprovider-crash.md),
and writing it moved three things the arm itself had left open:

- **The repro is twelve lines and calls one export**
  ([`tools/vmsavedstate_load_probe.py`](tools/vmsavedstate_load_probe.py)), so the defect is no
  longer stated through this server. It crashes at the **same fault offset** `0xD569` from CPython as
  from the Rust binary — two hosts sharing nothing but the DLL, which is what says the fault is the
  provider's and deterministic.
- **The trigger is specific, and a control matrix says so.** The same call **refuses** 4 MiB of
  random bytes, a truncated real capture and one with its first 512 bytes zeroed — all three
  `0x80070570` (`ERROR_FILE_CORRUPT`), no crash. So this is not a parser that dies on anything it
  dislikes; the encrypted path is the unhandled one.
- **"Encrypted" is now measured rather than Hyper-V's claim**, which the arm's own caveat said it was
  not: the two captures share the container magic `14 20 28 01` and the field at `+0x08`, while the
  payload entropy is **8.000** bits/byte against the plaintext capture's **7.246**. A well-formed
  container whose contents the provider has no key for — the case that should have been a clean
  refusal. The `Apply-VMSnapshot` check remains unrun, so Hyper-V reading what it wrote is still an
  inference.

**The bench was left as found**: both knobs back to `False`, the two pinned checkpoints intact and
the three this arm created removed, both guests running, and the pinned VBS capture re-read
afterwards to the same landmarks.

#### S0 arm 4 as specified, before it ran

**Why this arm exists.** S0's result invites the question whether a checkpoint carrying VTL1 is a
defect worth reporting to Microsoft, and the answer recorded in
[`docs/secure-kernel/secure-kernel-hypercall-feasibility.md`](docs/secure-kernel/secure-kernel-hypercall-feasibility.md)
is **no** — the SDK documents the capability, and the host is inside the TCB for a guest that is not
hardware-isolated. Part of that answer is that **Microsoft ships a mitigation for the at-rest half
and it is off on this bench**: `EncryptStateAndVmMigrationTraffic` is `False` on both lab guests. Arm
4 is the one case in that verdict that could overturn it, so it is worth running rather than
asserting: **turn the knob on and see whether VTL1 still comes out.**

**Method.** Record the guest's current `Get-VMSecurity` first — the arm changes VM configuration and
has to put it back. `Set-VMSecurity -EncryptStateAndVmMigrationTraffic $true` is **refused while the
VM runs** (measured: *"The SecuritySettingData property cannot be modified because the virtual
machine is running"*), so the sequence is: graceful shutdown, set the knob, start, take a
`CheckpointType = Standard` checkpoint, run `windbg-mcp --sk-inspect` against it, then **shut down a
second time** to revert the knob, and start again. The revert hits the same running-VM refusal as the
set, which an earlier draft of this method missed — it is **two** stop/start transitions per guest,
not one. A key protector already exists on both guests (5,207 bytes, measured 2026-09-27),
so the knob has one to use and this should need no new key material.

- **Expected pass — the boundary holds:** the provider cannot read the capture at all, and **the
  refusal names a reason at load or read**. That last clause is the whole rigour of this arm: a
  `LocateSavedStateFiles` that found nothing, a path typo or a checkpoint that was never written
  produce the same "no VTL1" as encryption working, and the first three say nothing. So the file's
  existence and plausible size are checked, and the failure has to come from `LoadSavedStateFile` or
  from the reads — not from the file not being there.
- **Finding — worth reporting, and weaker than it looks:** the provider loads it and VTL1 is still
  reachable. **That alone would not have been the finding**, because this arm runs on the owning host
  with the VM's key protector available, where a successful read is authorized decryption and says
  nothing about how the bytes are stored. What would settle *that* is the file: a payload entropy
  reading, or the same capture read on a host lacking the guardian key. Review raised this against
  the run, and the run had in fact taken the entropy reading — 8.000 bits/byte against a plaintext
  capture's 7.246 — so the conclusion stands on the file rather than on the provider.
- **The control has to be a *fresh* capture of the same workflow**, not the pinned one. An older
  checkpoint reading fine leaves "this capture is malformed or capture-specific" confounded with
  "encryption did it", and a named load error does not separate them. The run therefore took a fresh
  **plaintext** checkpoint of the same guest after reverting the knob and read it with the identical
  command; this bullet asked only for the pinned one, which review correctly called insufficient.
- **The arms differ by a boot as well as by the setting**, unavoidably, since the knob needs a power
  cycle. That is why the comparison is *whether it reads at all* rather than a value-for-value one —
  S0 already measured that the `CR3` moves across a boot while the image-relative offsets do not.
- **Cost:** **two** power cycles of a lab guest — one to set the knob, one to revert it — plus a
  checkpoint per arm, each a good fraction of the guest's RAM. The guest must be one whose
  in-guest state is expendable, which is a question for whoever owns the bench rather than an
  implementation detail.

**And one case in that verdict is already true here, which is not about Microsoft.** Reading a
checkpoint needs read access to a *file*, not the Hyper-V role — and this bench's
`D:\Hyper-V\Virtual Machines\Snapshots\<id>.vmrs` grants `BUILTIN\Users: ReadAndExecute` and
`Authenticated Users: Modify`, **inherited from `D:\`** rather than set by Hyper-V. So any
authenticated local user can read a file holding the guest's whole RAM, VTL1 included. It is a
storage-path configuration hazard rather than a product defect, it is not part of arm 4, and it
wants fixing on its own.

### S1 — the decode layer, source-agnostic — **BUILT AND RUN 2026-09-27**

**Built in Rust, in this server, and measured against a real capture.** `src/sk.rs` is the decode
layer over a `RawSource` seam (`root()` beside `read(gpa, len)`, both carrying *why* a read failed),
`src/savedstate.rs` is the Hyper-V saved-state source bound through the SDK's
`vmsavedstatedumpprovider.dll`, and `--sk-inspect` is a fourth non-server role beside
`--render-cast` that drives the two and prints a report. **Not a tool surface** — that is S3, whose
design question is still open, and a CLI role is what lets the decode be exercised without
prejudging it.

**It reproduces S0's probe on the capture it was run against, landmark for landmark**, which is what
makes it measured rather than merely self-consistent. Run against the `Lab Guest Hyper-V` checkpoint
(`H1 pinned 26200.9457 VBS+HVCI`, the **third-boot** capture) with
`--image C:\Windows\System32\securekernel.exe`: VTL1 `CR3` **`0x107593000`** read out of the capture,
root page **29 present entries** with the **self-map at index 309** and 139 non-zero bytes,
`securekernel.exe` at GPA **`0xCD0000`** and base VA **`0xFFFFF8070EDA9000`**,
`KdDebuggerDataBlock` at **`+0x1335E0`** with `Size` **`0x3A0`**, `SkLoadedModuleList` at
**`+0x127770`**, the same **six** VTL1 modules with the same sizes, and **4** `KDBG` tags of which
three are refused on `KernBase` and one accepted. Every one of those figures is S0's for this
capture, including the `215` decodes from `179` table reads. What it adds: **16,437** leaf mappings
over **4,545** distinct pages with **7,803** alias prefixes counted as unexpanded, 0 malformed
entries, 0 unreadable tables, **18,253** reads of which **0** failed, and two checks S0 did not run —
the **structural cross-check** (find the loader entry whose `DllBase` is the base, follow its
`Blink`) found head `0xFFFFF8070EED0770`, **the same address the block names**, and the
**provider's own translator** agreed with the walk on **373 of 373** pages of the image, with zero
pages mapped by one and not the other.

**The control arm refuses by name.** The same command against `Lab Guest Control`
(`H1 control 26200.9457 VBS off`) reports partition VTLs `0x1` against the VBS guest's `0x3` and
`ForceActiveVirtualTrustLevel(vp0, vtl1)` refused with `0xC0370509`
(`VM_SAVED_STATE_DUMP_E_VP_VTL_NOT_ENABLED`) — reported as the **switch** being refused rather than
as a guest with no Secure Kernel, which is the distinction `NotWalkable` exists to keep.

**34 tests, all synthetic** — 26 in `sk`, 4 in `savedstate`, 4 in `skinspect` — inside the default
`cargo test` (1,059 unit tests now, from 1,025). Six guards were **mutation-verified**: the self-map
cut, the list-confirms-the-block rule, the poison fill, whole-or-nothing reads, the large-page frame
mask, and unknown-is-not-wrong in the shape gate. The poison one **failed its mutation** and that is
the finding worth keeping: the assertion compared against the `POISON` constant the code fills with,
so changing the fill to zero moved both sides and the test passed on exactly the bug it exists for.
It asserts the literal `0xAA` now.

**What this does not establish.** The decode has been run against **one** capture, of one build, on
one host — the `0x1201000` capture S0 also used is no longer on this bench, so the reboot-moved root
is pinned by S0's record rather than re-measured here. The `.bin`/`.vsv` pair path is selected by
code and **called by nothing**, this bench never having produced a capture of that form. Nothing
here reads a *live* guest: `ReadFailure::Refused` is constructed by the fixtures alone, because a
capture has nothing to refuse with and the hypercall source that answers
`HV_STATUS_SUCCESS`-with-`ReadIntercept` is not built. And no symbol is resolved — that is S2, which
the base this now produces is the input to.

#### S1 as specified — the bulk of the work, and offline-testable

Everything H4 did, expressed over a source seam so the byte source is a parameter: the guarded
four-level page-table walk, PE identification against an on-disk image, the `KdDebuggerDataBlock`
decode, and the `SkLoadedModuleList` walk.

**The seam is not `read(gpa, len)` alone, and saying it was left a hole.** The decode cannot start
from reads: it starts from the **VTL1 page-table root**, which H4 obtained from
`HvCallGetVpRegisters` at `TargetVtl=1` — a hypercall against a **live VP**. A saved state has no
live VP to issue it on, so a source that is a captured image must either surface the saved register
state or supply the root directly. **The page-table root is therefore part of the source contract**
(`root() -> Gpa` beside `read(gpa, len)`), not something the decode layer derives. The alternative
is hard-coding the one measured `0x1201000`, which is a single build on a single boot and is
exactly what unknown 4 says not to rely on. S0 has to answer this for whatever source it finds.

**S0 answered it, and the hole this paragraph was written to close turned out to be real.** The
saved-state provider supplies the root as a register read — `GetRegisterValue` for `CR3` with the VP
forced to VTL1 — so `root()` is satisfied by the source rather than derived by the decode layer, as
specified. And a second capture of the same guest from an earlier boot carries `0x107593000`, so an
implementation that had hard-coded `0x1201000` would have walked from the wrong root on it. The
contract is measured, not argued.

**It is testable with no bench, no driver and no VM**, which is what makes it worth building even if
S0 fails — but **not with pages recorded off a live Secure Kernel.** Those are machine-specific
memory-dump material and would carry whatever guest and host state happened to be in them, and
`AGENTS.md` requires dumps and credentials to stay out of version control. Fixtures must be
**synthetic** — page tables and a PE header constructed to exercise each rule — or demonstrably
minimized and scrubbed, with what was removed stated. A synthetic fixture is better on the merits
anyway: it can be built to hit the self-map, the 16-byte window and the refusal path deliberately,
which a captured page only does by luck.

Three things must be pinned by tests rather than discovered again:

- **Cycle guards.** SK's PML4 self-maps (index 388 on the measured build), so an unguarded descent
  re-enters the table 512× per level. Unguarded, this took the bench down twice and needed a
  reboot each time. Pin: skip entries whose target PFN is the table they came from, a visited set
  per level, and hard budgets on reads *and* collected leaves that **report** a partial result.
  **And report what the visited set skips**, which S0's run had to add after review asked for it:
  6,773 alias prefixes go unexpanded on a walk whose 11,326 leaf mappings cover 4,189 distinct
  pages, and on the other capture 215 decodes come from 179 reads — 36 tables serving at more than
  one level. Expanding them all is combinatorial on a self-mapped tree — measured by building it,
  which exhausted a 200,000-leaf budget over 509 pages and identified nothing — so the guard stays
  and the omission is counted rather than silent.
- **Identification is per candidate, not per first match, and acceptance is two things agreeing.**
  Section names, timestamp and `SizeOfImage` say the bytes *are* the image; they do not say the VA
  is the base it was loaded at, and a second mapping of one image matches all three (the
  2026-09-25 capture has a duplicate `symcryptk.dll` the module list does not name). `KernBase`
  inside the data block distinguishes them and is **necessary, not sufficient**: the block is
  populated selectively, so a stale or zero `PsLoadedModuleList` still walks into plausible names
  and sizes. Accept a candidate only when the list's first `DllBase` names it back, record the
  reason for each rejection, and move to the next hit and then the next candidate. Which candidate
  the walk reaches first is prefix order and means nothing.
- **A docstring that states an invariant is a claim to check against the code.** `walk_module_list`
  said in prose that the first `DllBase` had to equal the identified base and then only decoded,
  for four rounds. Auditing every docstring in the probe found that one and no other, which is
  the cheap version of waiting for review to find them one at a time.
- **Gate the walk on the paging shape, not just on having a root.** The four-level descent
  hard-codes nine-bit indices and a 48-bit canonical form; a capture in any other mode, or with
  `CR4.LA57` set, would be traversed with the wrong strides and yield missing or invented leaves
  rather than an error — the walk cannot tell it is reading the wrong tables. Refuse and say
  which mode it was. An *unread* paging mode does not block it, for the same reason an unread
  `enabled` does not: unknown is not wrong.
- **A refused VTL switch and a failed register read are different answers.** Collapsing them makes
  a provider that cannot return one register look like a guest with no Secure Kernel — the same
  *refused*-as-*absent* collapse the read seam is guarded against, one level up.
- **Count failed reads at the source, not only at each caller.** Four review rounds on S0's probe
  each found another place where a failure arrived as a result, and a per-caller contract in prose
  did not stop the fifth: two scans wrote `if reason: continue` and reported a clean negative.
  A counter inside the read primitive is the one thing no consumer can bypass, and a run that
  found nothing with a non-zero count is a run whose negative has not been earned. Each scan keeps
  its own count beside it for locality.
- **Read width.** `HvCallReadGpa` moves at most 16 bytes, and judging a 4096-byte page on its first
  sixteen is what made SK's PML4 read as all-zero for most of a session. Any source-side chunking
  must not leak into the decode layer's view of a page.
- **The status/result split.** A refused read can answer `HV_STATUS_SUCCESS` with a per-access
  `ReadIntercept` and zeros. A source that collapses the two produces silent zeros exactly where
  the protected memory is; the seam must carry *why* a read failed, not just bytes-or-not.

### S2 — symbols, which is the one place DbgEng earns its keep — **BUILT AND RUN 2026-09-27**

**Names yes, types no, and no new `dbgscope` primitive.** `src/sksym.rs` opens
`securekernel.exe` as a DbgEng target in its own right, loads `securekernel.pdb` from the public
symbol server, and rebases it onto the base gate S1 found — so a VTL1 address has a name and a name
has a VTL1 address, with no debuggee anywhere. `--sk-inspect --symbols` is the opt-in that drives
it, and it is opt-in because it is the only part of that role that loads an engine.

**The unknown is settled, and the answer was the cheapest of the three it could have been.** DbgEng
accepts a PE image as a target: `OpenDumpFileWide` on `C:\Windows\System32\securekernel.exe`
produces a session with exactly **one** module, at the image's own `ImageBase` `0x140000000`, and
`.reload /f` against it downloads the PDB. Everything the gate needs is `dbgscope` methods that
already existed — `open_dump`, `wait_for_event`, `modules`, `module`, `reload_symbols`,
`module_pdb`, `module_symbol_file`, `symbol_offset`, `symbol_for`, `type_id` — so there is no stacked
`dbgscope` PR, and the `execute` hatch is not used either. The whole of this module's own work is
the **rebase**.

**The measurement, and it is the strongest cross-check this item has produced.** Against the image
on this bench (10.0.26100.9457, PDB key `C2C0D1A62E3269F40C69EA44FDB230C41`, `symbols: pdb`), the
PDB puts `KdDebuggerDataBlock` at RVA **`0x1335E0`** and `SkLoadedModuleList` at **`0x127770`** —
**the same two offsets S0's tag scan and S1's decode found inside the capture**, derived from a file
that has never seen it. Run end to end against the `H1 pinned 26200.9457 VBS+HVCI` checkpoint, both
rebase onto the decode's own addresses (`0xFFFFF8070EEDC5E0` and `0xFFFFF8070EED0770`) and the
engine names each of those addresses with displacement **0**, asked in the other direction. Every S1
figure reproduced unchanged in the same run — root `0x107593000`, 29 present entries, self-map 309,
16,437 leaves over 4,545 pages, 179 table reads, 215 decodes, six modules, the structural
cross-check agreeing with the block, the oracle 373 of 373, 18,253 reads and 0 failed.

**And the report now names the build that produced it**, which it did not under S1: `--sk-inspect`
prints `BUILD_VERSION` as its first line and carries it in the JSON, so a figure quoted out of this
role can be re-derived. The runs above were taken from **this change's own working tree** — a
`0.20.0+g3552d867-dirty.<digest>` build, and the digest is deliberately not written here: it covers
the uncommitted diff, so it moved four times while these paragraphs were being edited. The committed
equivalent is the commit that adds this. **Re-measured after rebasing onto `44428f5`** — every figure
above is identical on both parents, which is the one thing a rebase of a measurement has to be
checked for rather than assumed.

**So the module list is now reachable three ways, and one of them needs no block.** Unknown 4 asked
for a derivation to replace two remembered offsets; the PDB *is* that derivation, per build, and it
reaches `SkLoadedModuleList` directly — which the tag scan cannot, the list being a bare `LIST_ENTRY`
with no signature to search for. The block route stays: it is what works with no symbol server.

**The control arm is the other half of what makes the two halves independent.** Same command against
the VBS-off twin: symbols load and report normally, and the capture refuses the VTL switch by name
(`0xC0370509`). The report and the JSON keep those apart — a run where the engine had symbols and
the capture had no VTL1 must not read like a run where neither half worked.

#### What S2 does **not** deliver, measured rather than assumed

- **The public `securekernel.pdb` carries no type information.** `dt securekernel!_LIST_ENTRY` is
  *not found*, `dt securekernel!*` lists symbols rather than types, every data symbol prints
  `= <no type information>` under `x /t`, and four `GetTypeId` probes in the shipped code answer
  **`E_NOINTERFACE` (`0x80004002`), *no such interface supported*, every one of them** — the engine
  declining to service type queries for this module rather than four names it looked for and missed,
  which is a better corroboration than a sample of four could be. That detail only appeared once the
  probes stopped being booleans (round 5). The plan asked for "symbols **and types**"; the types half
  is not available to ask for, so structure walks over VTL1 stay hand-decoded the way `src/sk.rs`
  already does them. A finite probe cannot prove a PDB has none, which is why the code reports the
  engine's reason per probe rather than a verdict.
- **`SymbolKind::has_type_info` is wrong about this image, and must not be the test.** It reads
  `DEBUG_SYMTYPE_PDB` as private type information; this module is `symbols: pdb` with no types at
  all, because the engine does not distinguish a stripped public PDB from a private one. Asking for
  a type is the only answer. Worth a `dbgscope` doc fix on its own, and not a blocker here.
- **Rebasing inside the engine is a trap, and it was measured being one.** DbgEng will load the
  image a second time at the guest's base — `.reload /i securekernel.exe=fffff8070eda9000,175000`
  with `.exepath` set — and resolves the same PDB there. But it cannot reuse the module name, so the
  second module comes up `securekernel_exe`, and **both answer to `securekernel!`**: with the pair
  loaded, `? securekernel!KdDebuggerDataBlock` answers `0x1401335E0`, the *preferred* base. A
  name-based lookup would silently return an address in the wrong space. One module plus arithmetic
  has no such ambiguity and is testable with no engine.
- **Only two symbols are asked for.** The gate resolves the landmarks S1 already found, in both
  directions; it does not enumerate the PDB, name the other five VTL1 modules (their symbols are in
  *their* images, which nothing here opens), or resolve anything S1 did not locate.
- **It has read one PDB, for one build, on one host.** A module with no symbol **provider** after
  `Symbols::open` has made a resolving query is refused — `Deferred` and `Export` included — with the
  kind and `.reload /f`'s own error named, before any capture is read. Round 1 of the review narrowed
  that to `None` alone, reasoning that `Deferred` means nobody has looked; **that reasoning died the
  moment the forcing probe was added, and rounds 2 and 3 are what it cost** (see below).
  **And the refusal is now measured rather than reasoned about**, which it was not when this bullet
  first said "unmeasured": `--sympath C:\nonexistent-symbol-store` leaves the module reading
  **`Export`** and not `Deferred` — the engine falls back to the image's export table — and the run
  reports *no symbols loaded (the module still reads Export after a resolving query)* while the decode
  proceeds. Refusing `Export` costs the gate nothing, also measured: with symbols failing to load,
  `x securekernel!KdDebuggerDataBlock` and `x securekernel!SkLoadedModuleList` both answer nothing
  against roughly 280 exported names. What is still unmeasured is a build whose PDB is *served but
  wrong* — the `unmatched` arm.
- **Eight tests, seven of them with no engine at all** (1,088 unit tests now, from 1,080 — re-derived
  after rebasing onto `44428f5`, which moved both figures from the 1,071-from-1,065 this said when
  it was branched off `2466abc2`, and again when review round 6 added one). The five pure
  ones pin the rebase: the two landmark offsets against literals, the half-open end of the image,
  an address below the base refused rather than wrapped, both bases checked for overflow, and an
  unresolved symbol reading as *unknown* rather than as a disagreement. All four guards were
  mutation-verified — widen the end to `>`, swap `checked_sub` for `wrapping_sub`, drop the
  preferred base from the overflow loop, make `agrees()` answer `Some(false)` — and each failed the
  one test it belongs to and no other. A sixth is about neither the rebase nor the engine and reads
  the crate's own source: exactly two files may **construct** a `DebugEngine`, which is the review
  finding below turned into a ratchet. Only the seventh needs an engine, a symbol store and a real
  image, and it is gated on the image path so the gate and the input are one thing:
  `WINDBG_MCP_SMOKE_SKSYM=<path to securekernel.exe>`. **It asserts nothing about the type probes**:
  whether a Microsoft public PDB carries type records is Microsoft's to change, and pinning today's
  answer would fail on the build this gate would most want to hear about.
- **The `dbghelp` load order was a hazard and is now a measurement.** The engine bundle beside this
  binary carries its own `dbghelp.dll`, and whichever of DbgEng and the SDK provider loads first is
  the one the other inherits by name. The engine opens first, because it needs its own; the run
  above is what says the provider still reads a capture afterwards.
- **Narrowing that refusal opened a hole, which round 2 of the review found.** Accepting `Deferred`
  left the engine free to load the PDB on the first *landmark* query — after the only `unmatched`
  check had run, so another build's names could have been printed as this build's, and the reported
  provenance would have said `kind Deferred` and "no PDB signature" above addresses a PDB had just
  resolved. That is the `.claude/skills/review-round` rule about what a deleted check was *also*
  load-bearing for, and the whole suite stayed green through it. Fixed by **collapsing** the state
  rather than reporting it: `Symbols::open` now issues one deliberately-failing lookup to make the
  engine look before the provenance is read. Measured, twice: a module reading `symbols: deferred`
  straight after the open moves to `symbols: pdb` with its PDB key on a single failing
  `? securekernel!ThisSymbolDoesNotExistAnywhere`; and with `reload_symbols` not issued at all the
  probe alone still gets `Pdb` and resolves both landmarks, so the two halves are independent and the
  reload stays because it is the one that yields a *named* error. With **neither** issued, the gated
  test fails on exactly the reported state (`symbols Deferred, pdb None, file securekernel.exe`),
  which is what says its two new assertions are not vacuous.
- **Round 3 then found the probe can fail to settle it, and that is when the choice went rather than
  the symptom.** Accepting `Deferred` *after* a resolving query was the thing generating both
  rounds — the probe made the argument for accepting it false, since a module still deferred once the
  engine has looked is one whose symbols did not load. So the refusal is back to requiring a
  provider, now justified by a measurement instead of a guess, and nothing downstream can move the
  kind: that is what makes reading the provenance once and keeping it safe, with the residual
  assumption stated (no further `.reload` is issued) rather than hidden. `Export` goes with it and
  costs nothing this gate wants — neither landmark is an export of `securekernel.exe`. The same round
  found two more, both enumerated rather than patched one at a time: `SymbolFailure::Open`'s message
  said *the engine refused the image as a target* for **four** different engine calls, of which it was
  true for one (review named `--sympath`, where `open_dump` has not run yet), so it is now
  `Engine { step, detail }` and each site names its step; and the symbol file was captured only on the
  success arm, so a refusal that had *read* a PDB left it unprotected — `SymbolFailure::file_read` is
  now the one place that answers what a failure read, and `NoSymbols` was in the same position as the
  `unmatched` case review named.
- **Round 4, two findings, both taken and one remedy declined.** Asking the engine *which* PDB it
  loaded can fail, and `.ok().flatten()` turned that into "there is no signature" — so *could not ask*
  was published as a fact and the mismatch check was skipped with nothing saying so, which is
  `sk::ReadFailure`'s own lesson committed one level up. `PdbUnmatched` is now `PdbUnvouched` carrying
  *why*: both halves are "this PDB is not vouched for", so they are one refusal rather than two cases
  a fifth round can find a third of. And the engine ratchet was bypassable by renaming the type
  (`use … DebugEngine as E; E::new()`); CodeRabbit asked for alias-tracking, which is a parser in a
  test, so instead the **rename** fails the check — a name that cannot be renamed cannot be
  constructed through a rename, and both forms are mutation-verified. What it covers is stated as an
  inclusion: a literal construction and the two rename forms, not a macro-generated call.
- **Round 5 found the third of that class, so the class is now enumerated in the module.** `type_id`'s
  `is_ok_and` collapsed every failure into *absent*, and those negatives are what this gate offers as
  evidence that the PDB has no types — so a DIA that could not answer would have read as a stripped
  PDB. The probes carry the engine's own message now, and counting the rest of the module found a
  third site review had not named: `module_symbol_file`'s `unwrap_or_default`, where an error became
  `""` and an empty path **silently disables** the `--json` guard built on it. That one is a refusal.
  `src/sksym.rs` carries a table of every engine call and what a failure becomes, including the two
  that are answers rather than omissions — the discarded forcing probe, and `symbol_for`, whose `None`
  is `dbgscope`'s own contract.
- **Round 6 found a flag being eaten as a value, and the test that should have caught it was named
  for exactly that.** `--symbols --sympath --cross-check` took `--cross-check` as the symbol path and
  left cross-checking silently off. `a_flag_with_no_value_is_a_usage_error_rather_than_eating_the_next_flag`
  — S1's — puts the flag **last**, so there is no next flag to eat: the name claimed the general
  property and the body covered the trivial half, which is `.claude/skills/review-round`'s "a test can
  pass on a neighbouring rule" from the other side. The helper is shared by all twelve flags that take
  a value, so the fix is central and the assertion is a table over every one of them; `--json` is the
  worst of the twelve, since it would have written the report to a file named `--cross-check`.
  Mutation-verified: backing the guard out fails the new test on `--vm` and leaves the old one green.
- **Round 7 was the fourth on the vouching seam, so the set is now closed rather than extended.** A
  module the engine reports as `Pdb`/`Dia` while having **no** signature for it was still accepted, so
  `symbol_offset` results were trusted with nothing having checked which build they came from. Taken —
  and written as a *requirement on the kind* rather than as a fourth enumerated failure, because the
  three arms of `Unvouched` are the whole set: the identity says the wrong thing, the engine will not
  say, or it has none. Any future shape of "no identity" lands in the third without a new arm.
  `CodeView` and `Sym` keep `None`, those providers genuinely having no signature. Unmeasured like the
  other refusal arms — this bench only produces `Pdb` with an identity, which is what the gated test
  asserts, and that assertion is now a ratchet on the refusal rather than a discovery.
- **Round 8: the same swallow, surviving in the one branch this bench cannot reach.** The text report
  printed a failed probe's reason only when *every* probe failed, so a mixed result — one type
  answered, another query broken — showed the successes and dropped the error. Every probe fails
  against this PDB, so that branch never runs here and round 5's fix looked complete. The loop is
  outside the branch now. Not unit-tested, stated rather than hidden: `report_symbols` takes the
  engine-holding `Symbols`, so splitting a printable provenance out to test a `println!` is more
  structure than the fix is worth. Codex filed nothing at that head, so round 7's closure of the
  vouching set held from its side.
- **The loaded PDB is now an input, and the mutation says the finding's stronger form is wrong.**
  Review also found that `symbol_file()` — a file this run read, discovered only once the engine had
  loaded it — never reached `Inputs`, so `--json` could name it. Taken: it is added where it is first
  known and the alias check re-runs, exactly as the capture paths are. But backing the guard out does
  **not** truncate the PDB on this bench: the write fails with `os error 32`, *being used by another
  process*, because DbgEng still holds it. The guard stays because that protection is incidental —
  it would vanish if symbols were released or `symbol_file` named something the engine had closed —
  and because a sharing violation reported as a failed report-write is the wrong answer to *you named
  an input*. Verified both ways with the cache file hashed before and after.
- **It is a third process in this crate that loads DbgEng, and that was a P1 on the review.** Review
  on [#399](https://github.com/glslang/windbg-mcp/pull/399) asked for image resolution to be routed
  through an engine worker, citing `AGENTS.md`. The fact is right and the remedy is declined: the
  rule's constraint is one debuggee session per process, every call on the thread that made it, and
  no engine in the process that serves MCP — and `--sk-inspect` meets all three, opening **one**
  target which is a *file*, on a single thread, in a role that speaks no MCP and returns from `main`
  before a runtime exists. Routing would mean building a session registry and a `proto` channel
  inside a report writer, and would **pre-decide S3's own open question** for a research CLI. So
  `AGENTS.md` now states the constraint rather than the shape, and
  `sksym::tests::only_the_worker_and_this_module_build_an_engine` fails if a third file constructs an
  engine — mutation-verified both ways: a construction in `engine.rs` fails it, a prose mention of
  the same name does not.

#### S2 as specified

Resolve `securekernel.exe`'s symbols and types against a base supplied by S1. This is the part
worth keeping DbgEng for, and **the only part**: the remaining primitives are reads this server
already has from S1, and routing those through an engine that has no target buys nothing.

**Unknown to settle before committing:** `dbgscope`'s symbol methods (`symbol_offset`,
`symbol_for`, `module_symbol_file`) all assume a session with a target. Image-only resolution —
load `securekernel.exe` at a given base with no debuggee and resolve against it — is not obviously
available, and if it needs an engine call it is a **typed `dbgscope` method**, per this repo's rule
that a new DbgEng primitive belongs there rather than behind the `execute` text hatch. Size that
before promising symbols.

### S3 — the tool surface — **BUILT AND RUN 2026-09-27**

**Four tools, one session per capture, and the whole decode on the open.** `open_sk_capture`,
`sk_modules`, `sk_read_memory` and `sk_symbol` are a `--tools` group of their own
(`securekernel`); `src/sksession.rs` is the session they open, `EngineOp::OpenSecureKernel` and
three siblings carry them to a worker, and `crate::engine::refuse_op_on_kind` is what keeps every
other tool off a capture. The three questions this gate was deferred to answer are answered below,
and two of the three answers are forced rather than chosen.

**1. Where does the engine live? In a worker — and the half of that which is *measured* is the half
about the engine-free code.** The rule (`AGENTS.md`) already keeps DbgEng out of the process serving
MCP, which settles the symbol half and nothing else: the decode needs no engine at all, so nothing
in the rule stopped it living in the supervisor beside the session registry. What stops it is
**S0 arm 4**: `vmsavedstatedumpprovider.dll` `__fastfail`s on a capture it has no key for —
`0xC0000409`, subcode `FAST_FAIL_FATAL_APP_EXIT`, reached from a GSL contract violation inside
`LoadSavedStateFile`, measured from two different hosts and reported to Microsoft
(`docs/secure-kernel/vmsavedstatedumpprovider-crash.md`). A vendor DLL that aborts the process on a
path a *caller* supplies cannot be loaded into the supervisor, where it would take every other
client's session with it; in a worker it costs the one session that named the capture, which is what
process-per-session is for. So the arm that was run to answer a question about the VBS boundary
turned out to decide this one.

**2. One session handle or two? One, with symbols opt-in on it.** The symbols are the capture's only
because the mapping was identified against the same `securekernel.exe` on disk, and the rebase needs
the base the decode found — so a symbol handle without a capture handle can answer nothing in guest
coordinates, and two handles would be two halves of a join nothing checks. `symbols: true` stays
opt-in because it is the only part that needs a debugger bundle and a reachable symbol store, and
the decode stands without it: the control arm below has symbols loaded and no VTL1, which is exactly
the pair a caller must be able to tell from a run where neither worked.

**3. What is a "structure walk" with no types? The decoders `src/sk.rs` already has.** The public
`securekernel.pdb` carries no type information, so there is no `dt` over VTL1 to offer and none is
offered. What the surface exposes is what was hand-decoded — the root page, the walk, the identified
image, the debugger data block and the loader list — plus `sk_read_memory` for anything else, and
the four type probes travel with the session so a caller is **told** why there is no type-driven
walk rather than finding out one failed call at a time.

**And a fourth question nobody asked, which the first answer creates.** A worker holding a capture
has at most one DbgEng target and it is the *image*, at its own preferred base. `read_memory` there
would read a file and answer as though it had read the guest; `registers` would answer about no
thread. Neither *fails*. So the supervisor refuses every op that is not one of this session's own,
in `submit_gated` — the one funnel every non-opener passes — and it is an **allow-list in both
directions**: a tool added to `EngineOp` later is refused on a capture until somebody decides what it
means for one, where a deny-list's cost for forgetting is a wrong answer rather than a refusal. The
refusal names what the engine is actually holding, because "this tool is not available here" sends a
reader looking for a missing feature.

That rule is also what makes the session's answers stable: nothing in a capture session can execute a
command, so the engine's target cannot be replaced under the symbols, and the capture is a file that
does not change. Every figure the open reports is as true at the end of the session as at the
beginning — which is why the **whole decode travels with the opener** rather than being re-read by a
later call, and why a structured-aware client (which drops the text block) gets the read counters
that say whether a negative was earned.

#### What it was run against, and what reproduced

Driven over MCP against the same `H1 pinned 26200.9457 VBS+HVCI` checkpoint gates S0, S1 and S2 were
run on, with `--tools` defaulted, on build `0.20.0+g7606eac3` plus this change's own tree. **Every
S1 and S2 figure came back unchanged through the tool surface**: root `0x107593000` read out of the
capture, root page 29 present entries with the self-map at 309 and 139 non-zero bytes, 16,437 leaf
mappings over 4,545 distinct pages from 179 table reads and 215 decodes with 7,803 alias prefixes
unexpanded, 0 malformed entries and 0 unreadable tables, 16,437 pages scanned with 7 PE headers of
which 1 matches the image, `securekernel.exe` at `0xFFFFF8070EDA9000` (GPA `0xCD0000`),
`KdDebuggerDataBlock` at `+0x1335E0` with `Size` `0x3A0`, `SkLoadedModuleList` at `+0x127770`, the
same six VTL1 modules with the same sizes, three `KDBG` tags rejected on `KernBase` and one accepted,
the structural cross-check reaching head `0xFFFFF8070EED0770` — the address the block names — and
18,253 reads of which **0** failed. Symbols: PDB key `C2C0D1A62E3269F40C69EA44FDB230C41`, both
landmarks agreeing in both directions, and all four type probes answering `E_NOINTERFACE`.

**And one thing the CLI role could not show, which is the point of a read tool.** `sk_read_memory` at
the block's own address returns `C0C5ED0E07F8FFFF C0C5ED0E07F8FFFF 4B444247 A0030000 0090DA0E07F8FFFF`
— a `LIST_ENTRY` pointing at itself, then **`KDBG`** as the owner tag, then `0x3A0` as the `Size`,
then `0xFFFFF8070EDA9000` as `KernBase`. Three of the decode's own conclusions, read back as bytes
through a different code path, and the engine names that address `securekernel!KdDebuggerDataBlock`
beside them. A read across a page boundary (`0xFFFFF8070EDA9FF0`, 64 bytes) comes back whole and
stitched.

**The control arm is the other half.** The same command against the VBS-off twin's capture
(`H1 control 26200.9457 VBS off`) reports partition VTLs `0x1` against the VBS guest's `0x3`, the
provider refusing the VTL switch by name (`0xC0370509`), and the session **opens** carrying that as
its `not_walkable` reason and its `limitation` — after which `sk_modules` and `sk_read_memory` are
refused with the same sentence rather than answering zeroes. Symbols loaded normally on it, which is
the pair that had to stay distinguishable.

The four refusals were exercised in the same run: `read_memory`, `registers`, `modules` and `execute`
against the capture session, each answered with what the engine is holding instead.

#### What it cost, stated because a reader will ask whether it should have been paid

**The surface grew by 7,501 B of model-visible context**, from 95,792 to 103,293 across 63 to 67
tools: `open_sk_capture` 3,918, `sk_symbol` 1,466, `sk_read_memory` 1,277, `sk_modules` 840. That is
paid at the start of **every** conversation, by every caller, because the default surface is every
tool — and the overwhelming majority of callers have no Hyper-V checkpoint, no Windows SDK and no VBS
guest. `--tools` is the lever that exists for it and it is opt-*out*. Whether a group should be able
to be *outside* the default surface is a real question and is left as one (item 106 below), because
it is a change to what `--tools` means rather than something this gate should decide. The four
descriptions were trimmed from 8,340 B first, which took out sentences that explained rather than
told.

**And the wire payload found a multiplication, which is the first time that ceiling has caught one.**
`SecureKernelReport` was first held in `structured::TargetSummary`, whose schema is reached by all
seven openers — so `schemars` inlined the whole report into seven `$defs` closures and `tools/list`
measured **341,057 B**. Moving it into an outcome of its own (`SkOpenOutcome`, declared by one tool)
took **50,844 B** back off the wire for a change no client can observe; the payload settled at
290,213 B, of which the four tools' own output schemas are 14,257 and **378 is `SessionKindName`
gaining a `secure_kernel` variant** — one enum variant paid eight times over, which the per-tool
golden keyed by *name* is what made visible. Both ceilings were raised with the arithmetic recorded
beside them (96,500 → 105,000 and 268,000 → 295,000).

#### Review round 1 on [#401](https://github.com/glslang/windbg-mcp/pull/401): six findings, five taken

Worth recording as a set, because four of the five are the same shape — **a claim nothing compared**:

- **The cross-check reported agreement for any successful search.** `cross_check_within` finds a
  loader entry whose `DllBase` is the identified base and follows its `Blink`; whether that head is
  the one the block names is the *question*, and `decoded` answered `agrees: true` without asking it.
  `--sk-inspect` compared and the tool surface did not, which is why the comparison is now a method
  on `CrossCheck` used by both — a rule with two renderers is a rule one of them gets wrong. The
  field is `Option<bool>` now, for `SkLandmark::agrees`'s reason: a search that found nothing is not
  a disagreement.
- **An interrupt during a capture op marked the job**, so a complete decode was reported cut short
  and its caller was told the operation was stopping. Sealed at the door now, with a `Cleanup`
  variant whose doc says why it belongs in an enum named for cleanup: the other three are sealed to
  protect work that must not stop halfway, and this one because there is nothing there to stop. The
  test that pinned "a teardown is the only op sealed at the door" had a **name claiming a general
  property** over a body that checked one case, which is review round 6 of #399's shape; it now
  states the rule and enumerates both halves.
- **`open_sk_capture`'s three argument refusals answered in the wrong shape.** The tool declares
  `SkOpenOutcome`, whose error branch carries `target`; `typed_error` serialises `Outcome<()>`, which
  does not — so a schema-validating client would reject the message telling it what was wrong.
  `attach_kernel`'s argument refusals have always used `open_failure`, so this was the outlier rather
  than a new rule, and the test now asserts it of **both** openers.
- **The tier's prose claimed four tools and its body reached three.** `sk_symbol` was never called
  against a capture. Rather than narrow the sentence, the test now calls it and asserts the refusal a
  session opened *without* symbols gives — which pins a state that had no test at all, and makes the
  sentence true.
- **`docs/tool-surface.md`'s headline still said 95,792 B** while its own table said 103,293. The
  `.claude/rules/tool-surface.md` trap exactly as written: the tables are checked against a running
  server and a figure in a *sentence* is not.

The sixth is declined with its fact taken, and is the timeout bullet in *What this does not
establish* below.

#### Review round 2: two findings, both taken, both about a claim being wrong for most of its cases

- **`sk_read_memory`'s size bound was the worker's, and arrived as a debugger failure.** A size this
  tool will not serve is the *caller's* argument, and a refusal categorised `debugger` sends them to
  look at the capture for a number they chose. It is checked in the supervisor now — before any
  session is routed to, which is what makes it reachable with nothing open — and the worker keeps its
  own, because a bound only one side holds is one the other side's callers walk past. The bound is
  also **in the schema** now (`minimum: 1`, `maximum: 65536`, the only `schemars(range)` on this
  surface, 28 B): a cap a caller can only discover by exceeding it is a cap they will exceed.
- **The session's `limitation` gave the VBS-off reading for all six `NotWalkable` variants**, and it
  is true of two. A guest whose paging shape this walk does not decode **has** a VTL1, and a register
  the provider would not answer for is the provider's failure rather than a fact about the guest —
  three readings that send a reader to three different places. `what_no_vtl1_means` is the per-cause
  sentence, and the test asserts the VBS-off wording appears for exactly the two variants that
  support it. This is the same class as round 1's four: a sentence asserting more than was
  established, one level up from a value doing it.

#### Review round 3: one finding, and the third time the rule already existed next door

**A read whose last byte is past the top of the address space was not refused.** `Gva::offset` wraps
— deliberately, since a loader record starts `0x30` *before* its `DllBase` and the subtraction is
done the same way — so two bytes at `0xFFFF_FFFF_FFFF_FFFF` continued at zero: the answer stitched
from both ends of the space where something is mapped low, and a refusal naming a page the caller
never asked about where nothing is. Codex.

Refused in **`sk::Space::read_span`**, which is the reader every part of the decode goes through, so
`gather_image` and the module walk are covered rather than the one call site that was in mind — with
its own `VaFailure::Wraps`, because reporting it as the low page it wrapped onto is the reason the
finding was worth filing. The caller's own range is checked in the supervisor too, as an argument and
before any routing, for round 2's reason.

**And `sksym::Rebase` has refused exactly this since gate S2** — `RangeOverflows`, with a test named
`a_range_that_runs_off_the_top_is_refused`. That makes three findings in three rounds where the rule
was already established in a sibling and the new code was the outlier: `attach_kernel`'s
`open_failure`, `--sk-inspect`'s cross-check comparison, and now this. The lesson is cheaper than the
rounds were: when adding a path beside an existing one, read what the existing one *refuses*, not
only what it does.

#### What this does **not** establish

- **One capture, one build, one host.** The same limitation S1 and S2 carry, and the tier is written
  so it does not pretend otherwise: `WINDBG_MCP_SMOKE_SK_CAPTURE` names a `.vmrs` and the test
  asserts the *shape* of the answer — a decode, or the reason there is none, never neither — because
  whether a given capture has VTL1 in it is a property of somebody's guest. Both arms have been run
  here; nothing in the suite pins a figure, deliberately.
- **No live source.** Every tool reads a capture. The operator-supplied transport that reads a
  *running* guest is unbuilt, and so is `ReadFailure::Refused`'s only real producer — a capture has
  nothing to refuse with, so the refusal path is still fixture-only. Two things follow if a live
  source is ever added behind these tools: the session stops being a fixed snapshot, which is the
  premise the decode-on-open rests on, and `sk_read_memory` acquires a target that can change
  between two reads.
- **No writes.** S4 settled that the direct route writes VTL1, and nothing here exposes it. That
  stays out for the reason the plan's *Out of scope* section gives.
- **The capture ops are not interruptible, and they say so.** `interrupt` reaches DbgEng, and a
  page-table walk is this server's own code: a break raised during one has nothing to land on. Round
  1 of review found what that cost before it was said out loud — the interrupt marked the job, so a
  decode that ran to the end came back through `cut_short` labelled as truncated, and the interrupt's
  caller was told an operation was stopping that was not. The ops are sealed at the door now
  (`worker::Cleanup::NotInterruptible`) and the refusal names what it cannot do. What bounds them is
  the walk's own budgets (20,000 table reads, 200,000 leaves) and the read counters that report them,
  not a caller's clock.
- **An open that times out loses its decode, and the recovery is to open again.** The measured open
  is ~16s against a 300s default call timeout, so the window is wide — but the decode travels on the
  opener's reply *only*, and a caller who abandoned that wait cannot get it back: `sk_modules` still
  answers, `session_status` reports state, and the root, the walk, the candidate rejections and the
  read counters are gone until the capture is read again. Raised by Codex on
  [#401](https://github.com/glslang/windbg-mcp/pull/401), **taken as a fact and declined as a
  change**: the remedies are a fifth tool or a field on `session_status`, and both put another copy
  of the report's ten-kilobyte schema on the wire for every caller — which is what item 106 is about,
  arriving in the same review as the item. An earlier draft of this bullet said a timeout costs what
  it costs "exactly as a slow dump open does", and that analogy is the part that was wrong: a dump's
  summary is re-derivable from `modules` and `crash_triage`, and a capture's decode is not. The
  recovery is `end_session` and a second open, which is the 16s again.
- **`sk_read_memory`'s 64 KiB cap is a policy, not a measurement.** A capture is a file and the bytes
  are cheap; what is not cheap is the hex in a result a model pays for.
- **The `.bin`/`.vsv` pair is still called by nothing.** It is selected by code in both roles and
  this bench has never produced a capture of that form.
- **Nothing was measured about a second client.** A capture session is owned like any other and the
  four-session cap is shared with debugger sessions, but no run here had two credentials open one.

#### S3 as specified

Shape it after S0 and S2 answer, not now — **both have answered**, so this is the next gate. What
the plan asked for is SK base and size, structure walks, and symbol resolution against the image.
Note that a reader with no debuggee fits this
server's existing session model awkwardly — the one-worker-per-debuggee reason for the worker
process does not apply — so whether this is a session kind, a sessionless tool group or a separate
surface is a real design question, and **S0 and S5 both move it**: a live driver-backed source is
not a fixed snapshot, and an S5 pass would bring execution state back into a surface shaped on the
assumption that there is none. **S0 has moved it**: the source most users will have is a capture, so
the sessionless shape is the case to design for and the live one is the variant.

**And S2 has moved it in the other direction, which is the part to design around rather than
discover.** The decode is engine-free and the symbols are not: `src/sksym.rs` holds a DbgEng session
on an image file, which is a debuggee-less target and so needs no worker by the
one-session-per-process rule — but it is still an engine in *some* process, and `--sk-inspect` is a
short-lived one. A tool surface is not: it would hold that engine for the life of a session, beside
whatever engine the caller's other sessions hold. **Three things follow, and none of them is
answered.** Whether the symbol half is part of the same session handle as the capture or a separate
thing a caller opens; whether it lives in the supervisor (which has never loaded DbgEng, and where
`dbgeng.dll` in-process would be a new property of that role) or in a worker of its own; and what
`structure walks` means now that types are **not** available, since the plan's wording assumed a PDB
that would format them. Two of the three are about where an engine lives, which is this repo's
oldest architectural line — decide them before writing a tool, not after. And that is now enforced
rather than remembered: `sksym::tests::only_the_worker_and_this_module_build_an_engine` fails on a
third file constructing an engine, so a tool surface that puts one in the supervisor fails
`cargo test` with the reason rather than reaching a review round.

### S4 — settle the write routes — **RUN 2026-09-26, settled; do not repeat as written**

**Repeating it needs a quiesced guest or disposable state, which the run did not have.** Two
defects in the method, both real and neither fatal to the result:

- **"Identical bytes" is only identical at the instant of the first read.** The run reduced that
  window with a stability check — read twice, require agreement — but a running guest can change
  those 16 bytes between the read and the write, and then the write restores *stale* bytes. On a
  page-table or kernel-state page that is corruption, dressed as a no-op.
- **A scratch page was chosen from two all-zero reads and exclusion from known images, and that
  does not establish the page is unowned.** The guest can be using it for anonymous data, or can
  allocate it between the check and the write. The differing-bytes pattern makes this sharper than
  the identical-bytes case it replaced.

Neither invalidates what was measured — the writes landed and were verified restored, and the guest
ran on — but a repeat should **pause the guest**, or use a page the guest explicitly reserved, or
run against a snapshot that is thrown away afterwards. Detecting an intervening write (re-read and
compare immediately before the write) is the cheap partial mitigation and is not a substitute.

**Result in the feasibility record. Settled, both routes.** `HvCallWriteGpa` writes VTL0, honours
the address field, and is **refused on VTL1 with `AccessResult = 3 WriteIntercept`** — per-page,
confirmed on two different pages — so a software breakpoint is unavailable through hypercalls
outright. The **direct route writes VTL1**: differing bytes (`deadbeef…`) were written into
`securekernel.exe`'s `.text` alignment padding and read back, then restored to `0xCC` and verified,
with the guest running on. The mechanism was proven first on an ordinary scratch page, since until
then *neither* route had been shown to write anything — every prior write wrote bytes already
there. **So the patch half of a software breakpoint is solved and the catch half is not**: planting
an `int 3` in Secure Kernel is now a question of S5's transport, not of the write. The original
specification follows.

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
debugger.

**An earlier draft of this section started at the wrong boundary and would have cost a reboot to
find out.** It said the hypervisor's root VTL1 debug context "was configured and did not activate"
with "the failure never named", and asked for an early-boot trace of the activation return. All
three are wrong, because they read the validation record's state at one point and missed its
resolution two experiments later:

- the activation return **was** captured directly — `0x1D`, propagated from the debug buffer
  allocator when the **debug free-page list is exhausted**;
- raising the `hypervisordebugpages` reservation from 1000 to 2000 **fixed it**: active port moved
  from `0xFFFF` to `0xC35C` (50012) and both buffers allocated (`0x1000`/2 and `0x1000`/`0xA0`),
  and the activation routine assigns the port only after both allocations succeed;
- the record's own conclusion is **"the allocation failure is resolved, but Secure Kernel
  attachment is not"**, and it names where to go next: *"Secure Kernel-side debugger
  startup/transport beyond the initialized hypervisor port, not another unsupported increase in
  reservation or VM RAM."*

**So the hypervisor side works and the Secure Kernel side does not connect to it.** That is a much
more specific question, and it sits uncomfortably beside a fact this plan already established:
post-26100 `securekernel.exe` ships no KD transport, every `Kd`-prefixed symbol in it being data.
S5 should start by asking whether those are the same wall — a hypervisor port with nothing on the
guest side to speak to it — rather than by re-running a completed experiment.

#### S5a — **RUN 2026-09-27: they are the same wall. Do not repeat; S5 continues below it**

**Secure Kernel has no hypercall or MSR route to that port**, measured offline across ten builds
from 19041.207 to 29667.1000 with `tools/sk_hypercall_scan.py`. The three debug hypercall codes are
never written at any instruction boundary the scan recognises — every occurrence of `0x69`, `0x6A`
or `0x6B` at one is a `cmp` in unrelated code — no sample materialises a synthetic-debugger MSR
number `0x400000F0`–`0x400000FF` at all, and there is no `vmcall`/`vmmcall` instruction in any of
them. The enumerated
hypercall repertoire (19–38 distinct codes per build, `0x0002`–`0x0103`) contains none of them
either; that reading is a heuristic lower bound acting as the negative control, and the verdict
comes from the immediate scan, which covers 100% of each image's executable sections. The positive
control is `kdhvcom.dll`, Windows' own KD-over-hypervisor transport, which is those three hypercalls
behind the five-function KD export contract and which the same scanner reads correctly. Full result,
limits, and the four traps that each produced a wrong reading first — a sample whose *filename*
silently defeats symbol resolution, a control code that is also the rep-count bound, resting the
negative on one approximate evaluator, and bug check codes being read as hypercall codes — are in
[the feasibility record](docs/secure-kernel/secure-kernel-hypercall-feasibility.md).

**What this closes is one route, not the gate.** S5's pass condition is untouched. The remaining
candidate is the one that needs no guest-side code at all: a VTL1 stop driven entirely from the
hypervisor or the root, which Secure Kernel neither cooperates with nor can refuse. **Start there**,
and note that the receiver half was *not* re-derived statically — two attempts on `hvix64.exe` found
the IDT and a page-table walk rather than the hypercall dispatch, so the hypervisor side still rests
on the live trace in the validation record.

**And the mechanism to try is named rather than hypothetical, because Secure Kernel uses it.**
`ShvlInstallExceptionIntercept` (+`0x092C4C` in 26100.9457) issues **`HvCallInstallIntercept`
(`0x004D`)** with intercept type **3** — `HvInterceptTypeException`; 4 is the *access* mask,
`EXECUTE`, and this line had the two adjacent dwords the wrong way round until S5b read the block
against the TLFS — and a 0x18-byte parameter block, and registers the vector in a
bitmask afterwards — so exception interception is a real hypervisor primitive with a VTL1 caller on
this very build. SK aims it at VTL0. **The S5 question is whether a parent partition can aim the
same primitive at a child's VTL1**, which would deliver a `#BP` to the root instead of to SK's own
dispatcher — the missing catch half, on a route that needs nothing from SK. Unmeasured, and the
obvious hazard is that `HvCallInstallIntercept` may be partition-scoped with no VTL parameter to ask
with, which is exactly how `HvCallReadGpa` failed in H4. Test the *install* on its own, against a
VTL0 control, before anything is patched. **Run on 2026-09-28 as S5b, below: the hazard was the
answer.**

- **Do not** re-run S5a, and **do not** go looking for a differently-spelled KD transport in
  `securekernel.exe`. The scan is over the whole image, not over a name.
- **Do not** re-capture the activation return, and **do not** raise the reservation further. Both
  are done, and the record says the second is unsupported.
- **Pass:** a VTL1 execution stop is delivered to a debugger.
- **Necessary but not sufficient for software breakpoints.** A stop arriving by *some* route does
  not show that a VTL1 `int 3` reaches a debugger, and those can differ — the trap has to be routed
  by whatever handles VTL1 exceptions, which is not the same question as whether a debug transport
  exists. So S4 (we can write) plus a generic S5 pass is still **not** a licence to plant one;
  breakpoints stay excluded until **route-specific trap delivery** is demonstrated.
- **Do not** plant an `int 3` in VTL1 to test S5 itself. Without a delivered trap it bugchecks the
  guest and is a plausible SKPG trip; S4 having shown the write lands is not a reason to use it.

#### S5b — **RUN 2026-09-28: the install works on a child, and cannot name a VTL. Do not repeat**

**The hazard the S5a section named is the result.** `HvCallInstallIntercept` is partition-scoped
with no VTL parameter to ask with — the TLFS documents the whole 0x18-byte block
(`PartitionId`, `AccessType`, `InterceptType`, `InterceptParameter`), `HV_INTERCEPT_PARAMETERS`'
exception member is a bare `UINT16 ExceptionVector`, and both known callers write exactly that —
the 26100.9457 SK sample and this host's `winhvr.sys`, neither of them the guests' running SK —
read once with capstone and once with Ghidra. Live, from the root: a parent **can** install an
exception intercept on a child and remove it — `SUCCESS` on both guests, teardown clean — and every
byte put where a VTL might hide (the union's six spare bytes, eight bytes past the block) is
accepted **identically on the child with no VTL1**, while a variable-header declaration is refused
outright, so there is no extended form either. The full record, with the arm table, is the
[S5b result](docs/secure-kernel/secure-kernel-hypercall-feasibility.md) section.

- **The control is what makes it readable, and the first run had none that worked.** Vector `0x1F`
  was picked because no hardware raises it; the hypervisor refuses it as `INVALID_PARAMETER`, every
  arm including the baseline failed the same way, and that reads exactly like a clean negative about
  VTL1. The script now *discovers* an accepted vector on the VTL0-only guest before any VTL arm
  runs — `0x05` (#BR), which the hypervisor takes.
- **"The vector cannot fire" is retracted, and the lesson is about the search rather than the
  vector.** Two rounds each named a way #BR reaches a running x64 guest — MPX's bound-check
  instructions, and the legacy `BOUND` still decoding in **32-bit compatibility mode**, which is
  every WOW64 process — and an `int 5` is a third without looking far. No CPUID reading settles a
  claim about every instruction a guest might execute. What protected the run was the disposable
  guests and the install paired with its removal microseconds later; the vector made a fire
  unlikely, not impossible. **A re-run needing a genuinely inert arm pauses the target or uses one
  it is willing to lose.**
- **Do not** re-run S5b, and **do not** re-test the spare bytes: the same acceptance on a partition
  with no VTL1 is what settles them, and that control has been taken.
- **Aiming is what is closed; scope is not, and the route stays open.** A draft of this block said
  S5b closed the parent-side candidate, and Codex was right that it does not: with no VTL selector
  in the ABI, an intercept is either implicitly VTL0 or implicitly **every VTL**, and the second
  needs no selector because it would already deliver a VTL1 exception to the parent. S5's pass
  condition is untouched, and this run provoked no exception and held no intercept port, so it
  cannot tell the two apart.
- **So S5 has two live candidates, and interception is the first of them.** *Does a parent-installed
  exception intercept fire for a VTL1 exception?* Two ways in: a static read of `hvix64.exe`'s
  intercept dispatch for a check on the active VTL — two attempts have failed on that image, and
  Ghidra is on this bench now where it was not then — or a live test, which needs a port of its own
  to receive on and a VTL1 exception that is **not** a planted `int 3`. Cheaper than the second
  candidate, and it would make it unnecessary. **Half-answered on 2026-09-28 by S5h, below, taking
  the live route**: S5g's enclave supplied the VTL1 exception, and a `#BP` raised there is held and
  handed back without any port — so the *behaviour* was measured while the scope was not: the live
  test cannot separate the hypervisor taking the trap in VTL1 from it taking a VTL0 event that
  dispatching the VTL1 exception produces. **Fully answered on 2026-09-29 by S5i**, which took the
  other way in this bullet names and found the parent's mask seeded into every enabled VTL's
  effective bitmap. Both ways in were needed in the end, and neither made the other unnecessary.
- **The second was measured as S5c on 2026-09-28** — `HvCallSetVpRegisters` (`0x0051`) writing
  `HvRegisterExplicitSuspend` — and it **works, without being the stop S5 asks for**. See below.

#### S5c — **RUN 2026-09-28: the VP stops, VTL1 is readable stopped, and S5 does not pass**

**A parent can halt a running child's virtual processor and read its VTL1 while it is halted** —
`HvCallSetVpRegisters` writing `HvRegisterExplicitSuspend`, with no guest-side code, no exception,
no intercept and no port. VP runtime while suspended was **430** (control, VTL0) and **1,032**
(test, VTL1) per 2000 ms against an idle band of **41,291–84,075**, with a no-suspend null model
beside it. Refused with `0x0015` at VTL1 on the twin with no VTL1, so the `TargetVtl` field is
validated. The full record is the
[S5c result](docs/secure-kernel/secure-kernel-hypercall-feasibility.md) section.

- **It is a VP stop, not a VTL1 stop.** Set by naming VTL1, `ExplicitSuspend` reads `1` at VTL0
  too; the symmetric arm — naming VTL0 on the same VBS guest — reads `1` at VTL1 and stops the VP
  just as hard. One VP-wide suspend behind a VTL parameter that decides who may ask, which is the
  same shape S5b found on the intercept block.
- **S5 still does not pass, and this is the reading rather than modesty.** Its condition wants a
  stop *of VTL1*, at a *chosen point*, *delivered* as an event. This is the whole VP, at an
  arbitrary point, found by polling. `ActiveVtl` read `0` in all 80 read-only samples and in every
  arm, so Secure Kernel was never caught executing.
- **What is genuinely new is the inspector, it must halt *every* VP, and the whole of it has now
  run as one thing.** Stop the guest, read VTL1 registers (H3) and VTL1 memory by **whichever of
  the two routes serves each page** (H4's direct route alone returns a zero page for the very
  address S5e walked to), resume. One halted VP brackets per-VP register reads and does **not** make memory
  consistent — a second VP goes on running Secure Kernel and mutating the page tables a walk reads,
  which is S4's "identical only at the instant of the first read" arriving on the read side.
  `s5d.py` drives `h3probe.sys` and LiveCloudKd's `hvmm.sys` in one process, with the SDK's own
  freeze and pause **off** so the only stop is the measured one: both VPs halted (`SUCCESS`,
  runtimes 11,149 → 379 and 32,119 → 188), **3 of 3** VTL1 GPAs returning content while halted,
  each read twice inside the halt and agreeing 3/3, with two of the three (across two boots,
  so a recurring value rather than one state read twice) byte-identical to H4's
  recorded values. **Not** shown: that the halt was necessary — the same double reads while running
  were stable too, because an idle guest changes nothing and these guests cannot be loaded from
  this host.
- **S5e joined the halves by data flow, and the answer is that the routes are complementary.**
  Those three GPAs were preselected, so they never tested whether the halted *registers* can drive
  the memory path. Taking `CR3` from the halted VP and walking it through the direct route
  **works** — `PML4E[496]` → `PDPTE[24]` → `PDE[76]` → `PTE[400]`, all present with sane flags —
  and the leaf reads too, **through the hypercall rather than the direct route**. Censused whole,
  4,096 bytes each: the `RIP`'s leaf `0x81F000` gives 0 non-zero bytes direct and **4,084** by
  hypercall; `0x3BE1000` gives 200 direct and 0 by hypercall; the page table itself 8 direct and 0
  by hypercall. **Each page readable by exactly one route, and which one differs per page** — so a
  live inspector tries both per page, and neither alone reads VTL1's address space. **One address
  walked, three pages censused** — enough to show the chain completes, not enough to claim an
  arbitrary VTL1 address will: which property decides the serving route is unmeasured and is the
  open question, and H4's `0x3600000` is unretested by either route.
- **A correction to H4 fell out of it**: its "the VTL1 `CR3` page reads as zeros by both routes" is
  a **16-byte prefix** of a page whose first present entry is at offset `0x830`. Read whole, it has
  122 non-zero bytes and **26 present entries**. What proves the row wrong is H4's *own* table for
  that boot — first present entry at offset `0x850`, so a 16-byte read returns zeros whether or not
  the page reads. The S5e census is a **later boot** (the guest restarted 2026-09-27; self-map at
  index 463, not 388) and is not a second opinion on the first: **a VTL1 `CR3` value can repeat
  across boots**, so `CR3` equality is not evidence of the same boot — which is what made two
  correct censuses look contradictory. The same prefix trap caught this gate's own step 3 at 64
  bytes, and its census helper again at the wrong extent. **A prefix is not a page.**
- **Do not** re-run S5c's controls; the suspend bit, the refusal code and the VP-wide scope are
  taken. **Do** read the record before building on the halted context, and note what it does *not*
  say: over eight halt cycles the VTL1 `RIP` equalled its own pre-halt value 8/8 while the
  **VTL0**-labelled `RIP`/`RSP` came back as the VTL1 values 8/8 — but **every** reading in the
  gate was taken with `VsmVpStatus.ActiveVtl = 0`, and a sampler that took 8,000 reads across both
  VPs with no delay caught `ActiveVtl = 1` **zero** times. The halt with Secure Kernel actually
  executing is unmeasured and unreachable from this bench. **And the condition cannot be enforced
  with what this gate has**: reading `ActiveVtl` before the suspend races entry into VTL1, and
  reading it after depends on the suspension preserving it — which is the same unresolved question
  as the VTL0-labelled `RIP` reading as VTL1's. There is no atomic stop-and-observe here, so the
  condition is reportable and not checkable. The record states the observation with its condition
  and gives no consumer rule at all, three attempts at one having been three review findings.
- **S5f, 2026-09-28: the guests were reachable the whole time, over PowerShell Direct.** "Neither
  guest answers ICMP or WinRM, so there is no way to load them" appeared three times in the record
  and equated *no network path* with *no guest access*; `Invoke-Command -VMName` needs no network
  path and no WinRM, wanting a running Windows guest, Hyper-V administration on the host, the VMBus
  and guest credentials. Three things follow, and only the first two are results.
  **The register interface is live for VTL0** (and only VTL0: the spin ran there, every sample is a
  VTL0 `RIP`, and a live VTL0 read is compatible with an inactive VTL1 query returning saved
  context — so the VTL1 readings rest on an instrument validated for the other VTL) — under a
  user-mode spin, 110,638 samples per VP return
  **6,675 / 6,603 distinct** VTL0 `RIP`s, **88%** of them ring-3, so S5c's whole instrument samples
  the running processor rather than a cached exit record, which nothing had checked. **The stop,
  measured on a busy guest, is 23,854×** — 19,512,433 → **818** → 19,447,557 per 2000 ms, before
  and after within 0.3% — against the 40× the idle guest could show. And **the two open questions
  stayed open**: `ActiveVtl = 1` was never observed in **832,560+** samples now spanning idle, a
  two-VP spin and **twelve freshly loaded HVCI-verified kernel images**, and the halt's necessity
  is still unshown (80,399 reads over a matched 3 s window, one distinct value per page — those
  pages are static and a user-mode spin does not mutate SK's memory).
- **Why VTL1 cannot be caught here is now a number, and it names the next experiment.** What holds
  a VP in VTL1 long enough to sample is a **trustlet** (an IUM process, VTL1 *user* mode), not an
  HVCI check. This guest has one, `LsaIso`, and it is inert: **0.3593750 s of CPU in 27.6 hours**,
  unchanged to the tick across a logon burst, because Credential Guard is not configured
  (`LsaCfgFlags` unset, `RequiredSecurityProperties = 0`). At that duty cycle 832,560 samples expect
  about **1.5** hits if that time were spread evenly across two VPs -- 832,560 is the combined
  total, which an earlier draft divided as though it were per-VP and called ~3 -- and under uniform
  sampling zero still has roughly a **22%** probability. So this is *compatibility with rare
  `LsaIso` activity*, *not* validation of the sampler; S5g's known VTL1 workloads later produced
  zero hits too, which points at `ActiveVtl` not reporting rather than at the sampler missing.
- **S5g, 2026-09-28: one route closed, one unresolved, and the enclave route OPEN and measured.**
  Run with the
  operator's authorisation to reconfigure and reboot the VBS guest. **Credential Guard** is **unresolved**, and an earlier
  draft wrongly closed it *by edition* — Microsoft's table says Windows Pro: No, but the operator's
  Pro machine reports Credential Guard protecting it and this bench's own Pro host runs `LsaIso`,
  so Pro does run it; worse, that host reads `SecurityServicesRunning = 0` while its UI says CG is
  on, so the field the guest was judged by is not a sound test. What was seen: `LsaCfgFlags`, the DeviceGuard scenario key and `EnableVirtualizationBasedSecurity`
  all set, **Secure Boot `On` for both reboots** (a documented CG prerequisite, disabled only later
  for the enclave route, so not a confounder), `SecurityServicesRunning` still `2` and no DeviceGuard
  events — because Microsoft's edition table reads *Windows Pro: **No***. `LsaCfgFlags = 1` is
  *enabled with UEFI lock*; `2` is without, and a repeat on an eligible edition should use `2`. **Writing a trustlet** is closed by
  signing policy: IUM needs a Microsoft certificate with the IUM EKU plus membership in SK's
  identity list, and test-signing is deliberately not honoured there. **A VBS enclave WORKS**, once Microsoft's
  `windows-classic-samples/Samples/VbsEnclave` was used as the reference rather than building from
  first principles: `LoadEnclaveImage ok` / `InitializeEnclave ok`, and our own `Spin` running **in
  VTL1 user mode**. The decisive difference was `PolicyFlags = IMAGE_ENCLAVE_POLICY_DEBUGGABLE`
  against the `0` used here while the host passes `ENCLAVE_VBS_FLAG_DEBUG`; beside it non-zero
  Family/Image IDs, a 0x10000000 size the host must match, **no `/ENTRY` override** so the enclave
  CRT starts, `/GUARD:MIXED`, `SubSystem CONSOLE` and a `.def`. Before the reference it was: `CreateEnclave` with the debug flag succeeds every run, and
  `LoadEnclaveImage` refuses with **193 `ERROR_BAD_EXE_FORMAT`** through nine eliminated suspects —
  enclave config, load config, page hashes, a `vertdll` import, the enclave-signing EKU, TLS, the
  enclave CRT, `/INTEGRITYCHECK` (which moved characteristics `0x160` → `0x1E0`), and chain trust
  (in-guest status `UnknownError` → **`Valid`**). Test-signing moved the error 577 → 193 and trust
  left it at 193, so the signature path is satisfied and an unidentified **shape** rule remains.
  **Done — that diff is what opened the route**: Microsoft's sample was used as the reference and
  the differences are listed above, so do not repeat it. Note `veclient.lib` does not exist in SDK 10.0.26100; `vertdll.lib` was used
  instead and whether that substitution is the defect is unmeasured.
- **The condition every halted-register reading was qualified on is now measured, and `ActiveVtl`
  is not the way to it.** With the enclave spinning and the VPs measurably busy (**25.8%** and
  **52.4%** by `HvRegisterVpRuntime`), `ActiveVtl` still read `0` in 274,566 samples — so the parent
  cannot use it to tell whether VTL1 is running. Halting anyway catches VTL1 mid-execution: **6 of 6
  halts** found VP 1's VTL1 `RIP` in **user mode inside the enclave** (`0x21456DE509B`–`…50BC`, five
  distinct addresses across six halts, each stable over 10 reads within its halt), while VP 0 stayed
  parked at Secure Kernel's `0xFFFFF80679FB0035`. So the halted VTL1 context behaves exactly as it
  did parked — readable, frozen by the halt, its own rather than VTL0's — and **#411's scoping of the
  liveness result to VTL0 is superseded: the VTL1 read is live too.**
- **A method error was caught by that same measurement.** An earlier "zero while our code spins in
  VTL1" used `Invoke-Command -AsJob`, and each PowerShell invocation here is its own process, so the
  job and its session died with the call — VP runtime read **0.7%** busy while the spin was
  supposedly running. A guest-side workload only exists when **detached** with `Start-Process`,
  which is why the CPU-load arms were real and the first enclave ones were not.
- **`ActiveVtl` has now read `0` in over 1.15 million samples across four workloads** — idle, a
  user-mode spin, twelve HVCI-verified kernel image loads, and an enclave create/terminate loop.
  **The fourth is weaker than it first looked**: `CreateEnclave` does log a `Secure Trustlet
  started/stopped` pair, but counting them gave **ten in three minutes against 400,000 cycles**, so
  the creates after the first are mostly VTL0 bookkeeping and "a sustained VTL1 workload" was a
  claim from a mechanism rather than a count. Two readings still fit — VTL1 windows shorter than
  the ~55 µs sampling interval, or **the parent-side `ActiveVtl` cannot report a VP executing
  VTL1** — with the second now likelier and neither established.
- **The VBS guest is changed and a later gate must know.** Secure Boot **off**, test-signing **on**
  (VBS/HVCI verified still running after both), a self-signed `CN=VTL1 Enclave Test` cert in
  `LocalMachine\Root`, Credential Guard keys set and inert, `C:\encl\` staged, and **four reboots**
  — so the `CR3`, self-map index and SK base have all moved again from the figures in S5c–S5f.
- **Bench note (historical, S5f only — the S5g reboots cleared them; verified none running).**
  Eleven inbox driver images started in the VBS guest to provoke VTL1 would not stop
  and stay loaded until it reboots. Harmless — drivers for hardware the VM lacks — but a later gate
  reading its module list should know why they are there.
- **S5h, 2026-09-28: a VTL1-raised exception is held and handed back.** S5g's enclave supplies a
  VTL1 exception that is not a planted `int 3`, so S5b's leftover could finally be provoked. What
  came back answered the *behaviour* and not S5b's scope question — **S5i settled that separately
  on 2026-09-29**, by reading the hypervisor; the retraction two bullets down is about what the
  halt evidence could carry, and it stands.
  One binary raises `#BP` in both VTLs and counts what
  its own `__except` catches, so the arms differ in the VTL and nothing else. With the intercept
  standing, **the guest handled 0 of 20,000 in every arm** — 120 consecutive zero samples over 24.4 s
  in VTL0, in VTL1, and on the VTL0-only twin, and 198/218/291 zeroes over 40–60 s in runs without a
  release. **Removing it mid-arm lets all three finish 20,000/20,000**, so the traps are *held and
  handed back*, not discarded — a resumable stop rather than a swallowed exception. Both controls
  hold: an intercept on `#BR` that nothing raises, and a `#DE` raised against a `#BP` intercept, each
  leave both VTLs at their null rates (`0.82–0.96 us` VTL0, `9.36–10.12 us` VTL1). The guest keeps
  serving while an intercept stands — a second PowerShell Direct connection answered during every
  arm — though that says the partition is not wedged and **not** that only the raising thread was
  held, which nothing here arranged a control for: treat a standing `#BP` intercept as freezing
  every thread in the partition that raises that vector. No intercept was left standing and no
  guest needed a reboot. Full record, with the arm tables, in the
  [S5h result](docs/secure-kernel/secure-kernel-hypercall-feasibility.md) section.
- **Two claims in the first write-up of that gate are retracted, both found by review.** *"Six halts
  catch the VTL1 arm inside the enclave, which rules out a VTL0 excursion being what is
  intercepted"* — it does not: a VTL1 exception reflected into VTL0 leaves VTL1 **saved at the
  faulting instruction** while VTL0 sits in kernel code, which is exactly the pair measured, so the
  halt discriminates nothing. The VTL0-labelled read lands in Secure Kernel's own page, which is the
  S5c anomaly's signature rather than a trustworthy VTL0 context, and the 11x cost of a VTL1
  exception over a VTL0 one is if anything a reason to take the excursion seriously. And *"only the
  raising thread is held"* was inferred from a connection that raises no `#BP` at all. **What would
  settle the first** is the route S5b named and this gate skipped: `hvix64.exe`'s intercept dispatch,
  read for a check on the active VTL. **Run as S5i on 2026-09-29, and it found one**: the check is
  at install time rather than in delivery, and it sets the VTL to 0 for any child while seeding that
  slot into every VTL's effective mask — so the intercept does cover VTL1 and the retraction above
  stands as a statement about the halt evidence, not about the conclusion. **And the other route
  S5h named — *delivery metadata from an actual receiver* — was taken by step 9's VTL1 arm on
  2026-09-30 and settles it**: the intercept message's `Rip` is the **enclave's** `int3`, matching
  this halt table's VTL1 value in its low 16 bits on a different boot. An intercept fired on a VTL0
  excursion would name the VTL0 instruction, so the excursion is excluded and the trap is taken at
  the VTL1 raise.
- **The first four runs read the VTL1 arm as *advancing* and that is retracted.** The counts
  reported — 1,902, 6,396, 15,076, 18,486 — were all written by the monitor's final sample, *after*
  teardown removed the intercept and the raiser finished, and one of them became a "405x slower but
  advancing" rate supporting a reading in which the two VTLs were reached differently. The trace says
  the count first moves at sample 121/121 and 219/219. **Read where a count first moved, not what it
  ended at**; the last sample is on the wrong side of the release.
- **S5i, 2026-09-29: the dispatch read is done, and the intercept reaches VTL1 by design.** The
  route S5b named and S5h skipped, run against this host's own `hvix64.exe` `10.0.26100.9444`
  (SHA-256 `CF5AF317…40CE8A`) with [`tools/sk_vmcs_scan.py`](tools/sk_vmcs_scan.py). **It worked
  where two earlier attempts failed because it asked an architectural question instead of a
  structural one**: on Intel VMX an exception intercept *is* the VMCS exception bitmap, field
  `0x4004`, so the anchor is one constant in one instruction rather than a table to recognise. Five
  steps carry it: `HvCallInstallIntercept` at `+0x295800`; the VTL decision at `+0x295879`, which
  compares the target partition against `gs:[0x360]` and sets **VTL := 0 for any child** while the
  self branch takes the caller's own VTL and refuses VTL 0; `InterceptType == 3` landing at
  `+0x2C9430`, which ORs `1 << vector` into `array[VTL].0x1A04` indexed `[partition + VTL*8 +
  0x63C8]`; the recompute at `+0x2BECC8`, which descends the enabled-VTL set **seeded with
  `array[0].0x1A04`** so that a parent's mask lands in *every* VTL's effective mask at `+0x1A0C`;
  and `+0x331AA8`, which programs the bitmap for whichever VTL the VP is running. **So S5b's scope
  question closes in the second direction — implicitly every VTL — and S5h's hold was genuine VTL1
  interception.** #412 was right to withdraw that claim from the halt evidence, which did not carry
  it; the claim is true on different evidence. Full record, with the cross-checks against S5b's live
  arms, in the [S5i result](docs/secure-kernel/secure-kernel-hypercall-feasibility.md) section.
- **The Secure Kernel limit narrows but is still not measured.** A VMCS exception bitmap does not
  distinguish CPL 0 from CPL 3, and step 5 selects it by VTL alone, so nothing in the mechanism
  separates VTL1 *user* mode from VTL1 *kernel* mode. That retires the specific reason to doubt the
  extension to Secure Kernel's own code without making it a measurement, and S5a's prohibition on
  planting an `int 3` there to check is unchanged.
- **S5j, 2026-09-29: the message is already addressed to the parent, and binding to it may displace
  Hyper-V's handler.** The gate's first half, run with the same instrument as S5i
  plus `winhvr.sys` and `Vid.sys` read with symbols. **Routing**: `HvMessageTypeX64ExceptionIntercept`
  (`0x80010003`) appears once in `hvix64.exe`, at `+0x2C9A9E`; the recipient is chosen at `+0x2C95B8`
  by scanning VTLs from the active one upward and then wrapping to the lowest, delivering to the
  first whose **own** `+0x1A04` holds the faulting vector. A `#BP` in VTL1 whose vector the parent
  installed therefore wraps to VTL0, matches, and is delivered as a VTL0 intercept — and `+0x2EB134`
  forks on that byte, sending VTL0 to the parent-directed post at `+0x2EC204` and any higher VTL to
  its own SynIC. **So nothing needs redirecting — the route is not what is missing**, and
  **what happened at the other end is not established** — the read shows where the message is sent,
  and `Vid.sys` has a handler for this very type, so "nothing was bound" and "the existing handler
  received it and retained it" are both live explanations of S5h's hold, wanting different next
  gates. Telling them apart is what comes next. **S5k, below, killed the first and added a third**:
  Vid is bound, and its handler *drops* a message whose vector nothing claimed — which competes with
  the second rather than retiring it, the two being separated by a runtime byte S5k did not read.
  **Build**: the plan's hand-rolled `HvCallCreatePort`/SynIC page is the wrong build. `winhvr.sys`
  exports the lot — `WinHvCreatePort`, `WinHvConnectPort`, `WinHvAllocatePartitionSintIndex`,
  `WinHvGetSintMessage`, `WinHvSetEndOfMessage`, `WinHvSetInterceptRoutine` and
  `WinHvCompleteIntercept`, which is **half** of the resume a debugger needs — for a *software*
  exception Vid first calls `VidInterceptAdvanceInstructionPointer` and only then completes, and
  without that advance the faulting instruction is re-entered rather than resumed — and `Vid.sys`
  already consumes
  them, including a `VidExceptionInterceptReturnCallback` for this very message type.
  **Hazard, and it is why this is a finding rather than a green light**: `WinHvSetInterceptRoutine`
  stores **one** routine and context per table entry, assigned rather than chained, and `Vid.sys`
  imports it. **What follows from that is narrower than an earlier draft said**: the import proves
  `Vid.sys` calls the function, not that its call selects the same entry ours would, so whether a
  registration displaces anything turns on the table's key — which this read did not identify.
  Per-partition means one child; per-message-type or per-SINT means every VM on the host, since the
  displaced handler services IO-port, MSR and CPUID intercepts; an allocated per-client handle means
  no displacement at all. Assume displacement because the cost of being wrong is asymmetric, and
  **do not call `WinHvSetInterceptRoutine` on this bench until the key is known** — read it from `Vid.sys`'s own call sites, which pass it.
  **S5k read them: the key is the partition id, so the blast radius is one child — and the
  prohibition hardens into a permanent one**, because the routine a registration would displace is
  the one that dispatches to Vid's own per-vector table. Do not call it at all. Full record in
  the [S5j result](docs/secure-kernel/secure-kernel-hypercall-feasibility.md) section.
- **S5k, 2026-09-29: an unclaimed vector is dropped inside `Vid.sys`, and the receiver is an IOCTL
  rather than a build.** Both reads S5j called for, against the same two images — `winhvr.sys` `10.0.26100.8972`
  and `Vid.sys` `10.0.26100.9278`, opened as DbgEng image targets with public PDBs. **The table
  key** is the `HV_PARTITION_ID`: `WinHvSetInterceptRoutine` (`+0x8020`) calls
  `WinHvpReferencePartition`, which binary-searches `WinHvpPartitionArray` by 64-bit key and fails
  with `0xC035000D`, *"a partition with the specified partition Id does not exist"*; the routine and
  context land at `+0x10`/`+0x18` of the partition object, and `WinHvpOnInterception` (`+0x4438`)
  looks the same array up by the message header's **Sender** and calls exactly that pair. So the
  blast radius is **one child**, displacement is real, and Vid's only two call sites are an
  activate/deactivate pair on that one field — it relies on assignment replacing. The slot is also
  written at creation (`WinHvpCreatePartitionObject`, `+0x1D42C`), so holding it without displacing
  anyone means creating the partition. **Vid's path**: `VidInterceptIsrCallback` has no filter that
  could lose an exception intercept, `VidInterceptPreprocess` recognises `0x80010003` through a jump
  table at RVA `0x3D137` and selects `VidHandleExceptionIntercept` — which then gates on
  `byte [[partition+0xB68] + vector]`, a `0x100`-byte per-vector table `VidPartitionInitialize`
  fills with `0xFF`. **`0xFF` means no registration, and the handler returns 0 having enqueued
  nothing.** What claims a slot is `VidHandlerpExceptionRegisterEntry` (`+0x63B80`), and it does so
  *before* calling `WinHvInstallIntercept` with the byte-for-byte descriptor S5b read — type 3,
  `AccessType` 4, the same vector field — reached from `VidHandlerIoctlExceptionRegister`
  (`+0x63630`). **So S5b's install was not wrong, it was half of the arming sequence**, and the half
  it skipped is the half that makes anyone listen. Of S5j's two explanations of S5h's hold the first
  is dead — Vid was bound and its routine ran — and the second gains a **competitor rather than a
  refutation**: the drop. **Which of the two S5h met turns on `[partition+0xB68][3]`, a runtime byte
  this gate did not read and nothing already measured stands in for.** An attempt to substitute
  S5h's controls was retracted in review: Vid's register and unregister paths do set and clear the
  slot and the hypervisor intercept together, but `h3probe.sys` writes that mask too — **every probe
  install is paired with a raw `AccessType = 0` removal that touches nothing in `Vid.sys`** — and
  whether that removal clears the shared bit is unread, S5i having read the install as an
  unconditional `OR` and not the removal. An implication needing *no other writer* to be able to
  clear the bit is therefore unestablished, which retracted the argument whichever way the removal
  turned out — **and S5l then read the removal clearing the bit, so it is false rather than merely
  unestablished.** What settles the question itself is reading that byte **inside a replicated
  intercept arm** — it is mutable, so a later read reports the reproduction and says nothing about
  the historical runs beyond an unchanged bench — and it comes before the IOCTL read.
  **Second hazard, mechanism confirmed by S5l**: a VID client holding a vector this probe installs
  *would* have its intercept stripped by the probe's teardown while Vid went on believing it armed,
  silently, on the child under test. Six runs executed that teardown and none read the slot, so
  what is established is the exposure, not a loss. **New hazard**: `VidInterceptPreprocess` ends its switch in `__fastfail(FAST_FAIL_INVALID_ARG)`
  in the **root** — a host bugcheck, not a guest one — for any intercept message type it does not
  handle, including the holes `0x80010005`, `0x80010009`–`0x8001000F` and `0x80010012` inside the
  range it otherwise covers. Full record in the
  [S5k result](docs/secure-kernel/secure-kernel-hypercall-feasibility.md) section.
- **S5l, 2026-09-29: the exception mask is one bit with no owner, so an install/remove pair is not
  free.** The removal read S5k left open, same image and instrument as S5i — `hvix64.exe`
  `10.0.26100.9444`, `--self-test` 20/20, `+0x1A04` still 9 sites / 2 writers and `+0x6124` still
  6 / 3. **Install and remove are the same function and the same bit**: `+0x2C9430` branches on
  `AccessType` alone — `or edx, 1 << vector` for `4`, `not`/`and` for `0` — stores back to
  `array[VTL].0x1A04` and calls the `+0x2BECC8` recompute S5i read. **No refcount, and nowhere for
  one**: two writers in the whole image, this store and a partition-teardown zeroing, and a 32-bit
  bitmask has no room to count. So **two parties holding one vector are one bit**, and since removal
  is a plain `and ~bit` the **first** removal clears it for both, whichever party makes it — so the
  probe's `finally` would strip a VID client's intercept while `[partition+0xB68]` still said armed.
  The hazard's *mechanism* is established; whether a client ever held one is not, no arm having read
  the slot. The controls
  argument S5k retracted is **false on a probed child** rather than merely unestablished. It does
  **not** say which branch S5h met — that is still the replicated arm. **Three bounds read free
  from the same 215 bytes**: `AccessType` must be exactly `0` or `4` (status `5` otherwise, which
  is where S5b's negative control landed); the vector is a `word` at `+8` of the
  `InterceptParameter` and must be `<= 0x1F`; and a per-partition allowed-vector mask at `+0x6124`
  gates installs **except** that target VTL 0 admits vectors `3` (`#BP`) and `4` (`#OF`)
  unconditionally — which, with S5i's "a parent naming a child always installs at VTL 0", is why
  `#BP` on a child never depended on the partition's configuration. **No remediation, and the one
  that suggests itself does not work**: reading a slot before installing is a *diagnostic*, not a
  guard, because the per-partition lock serialises one update and not
  read-then-install-then-remove — a client registering inside that window still loses its bit.
  Making the pair safe needs exclusive coordination with every other installer, which nothing here
  has. The diagnostic itself would be Vid's `[partition+0xB68][vector]`, not the hypervisor mask
  (`array[0].0x1A04` is hypervisor memory the root cannot read, and the ABI has no query beside its
  install and remove). **Even that read is not available on this bench**: local kernel debugging is
  off (`bcdedit /dbgsettings` says
  `debugtype Local`, which is the global store, not the boot entry; `{current}` carries no
  `debug Yes` and `attach_kernel_local` answers `0x80004001`), so it needs a host reboot into debug
  mode or a kernel-read path in `h3probe.sys`. Until then the constraint stands without a remedy:
  an install/remove pair is not free. Full record in the
  [S5l result](docs/secure-kernel/secure-kernel-hypercall-feasibility.md) section.
- **S5m, 2026-09-29: the receiver is a user-mode export, and there is no driver left to write.**
  The IOCTL read S5k named, against `Vid.sys` `10.0.26100.9278`, `vid.dll` `10.0.26100.8457` and
  `WinHvPlatform.dll` `10.0.26100.9278`. **The code is `0x221148`** —
  `CTL_CODE(FILE_DEVICE_UNKNOWN, 0x452, METHOD_BUFFERED, FILE_ANY_ACCESS)`, read from
  `VidIoControlPartition`'s compare chain, with input `{ u8 Vector; u8 pad[3]; u32 Parameter;
  u64 Context; }` and an `8`-byte handle out. `FILE_ANY_ACCESS` is not the access control: the
  dispatcher is reached with a *partition* in `rcx`, so what gates it is holding a partition handle.
  **`vid.dll` exports a wrapper for it** — `VidRegisterExceptionHandler`, one of 215 exports,
  carrying that code and layout into a single `NtDeviceIoControlFile` — **and exports attach,
  receive, complete and unregister beside it**: `VidAttachPartition`, `VidGetHvPartitionId`
  (which translates a VID handle to the `HV_PARTITION_ID` every hypercall gate has been passing),
  `VidMessageSlotMap`, `VidSetupMessageQueue`, `VidMessageSlotHandleAndGetNext`,
  `VidHandleMessageAndGetNextMessage`, `VidUnregisterHandler`. **So no driver, no port, no
  hypercall** — the third downward re-scope in a row, each one deleting the build the previous gate
  specified — **conditional on getting a partition handle**, which every call in the sequence takes
  and which this gate does not test; if a second process cannot obtain one for a running VM, the
  sequence is unavailable and a driver may be back on the table.
  **But it is not a documented call**: `WinHvPlatform.dll` delay-imports 31 `vid.dll`
  functions and this is not one of them — what WHP imports is the *Exo* family, its own partitions'
  mechanism. So S5 is not one supported call from passing; it is one *observed, exported* call from
  passing, which is a different and weaker thing to build on.
  **It covers S5l's hazard for one class of owner, not in general**: the kernel side refuses a
  claimed slot with `STATUS_VID_DUPLICATE_HANDLER` before touching the hypervisor, and unregister
  clears slot and bit together — but that check reads `[partition+0xB68]`, so it sees only parties
  that registered *through Vid*. A raw `WinHvInstallIntercept` owner — this plan's own probe since
  S5b — leaves the slot `0xFF`, a Vid registration succeeds beside it, and unregister later clears
  the shared bit out from under them. The rule that follows is *one installer per vector per
  partition, and let it be the Vid registration*, not "the hazard is solved".
  **And the registration's return value supersedes the replicated arm** S5k and S5l wanted —
  **read as `GetLastError()`, not as the `BOOL`**: the wrapper passes failures through
  `RtlNtStatusToDosError`, and VID-facility statuses have no Win32 mapping, so `0xC0370001` comes
  back verbatim and is unambiguous against invalid-handle (`6`), access-denied (`5`) and
  allocation failure (`1450`) — all measured. Duplicate means the slot was claimed, success means
  it was `0xFF`, anything else classifies nothing. Full record in the
  [S5m result](docs/secure-kernel/secure-kernel-hypercall-feasibility.md) section.
- **S5n, 2026-09-29: a VID partition takes no second *open*, so the receiver has no reachable
  handle.** The first live arm since S5h, and it cost the bench nothing: no VM touched, no
  intercept installed, no reboot. Opening a partition is one `CreateFileW` on
  `\\?\root#vid#0000#{7896e901-fe60-446e-828d-d65920654a23}\<VM Id>` with `OPEN_EXISTING` —
  the path `vid!VidpCreateVidObject` builds, with `GUID_DEVICEINTERFACE_VID` read out of `vid.dll`.
  **Both running guests' VM Ids refuse with `ERROR_BAD_COMMAND` (22)**, while a well-formed unused
  name **opens** and a malformed one gives `0xC0370005` — so the name is recognised and the open
  refused rather than not found. **Two controls reproduce `22` with no VM in them**: a second open
  of the same name fails under either share mask and frees when the handle closes, and — across two
  processes — a name a *child* holds refuses the parent while a **different** unused name opens at
  the same moment. So the rule is global rather than per-process, and per name rather than per
  device; it is not share-mode negotiation.
  **What that does not establish** is that the live VM's `22` has the same cause: `0xC0000184` has
  62 sites in `Vid.sys` and the create dispatcher was not located, so the controls narrow the
  alternatives without eliminating them. The constraint measured is *no second open*, not *one
  handle* — `DuplicateHandle` and inheritance are untested and untried — and the caller was never
  varied, so privilege is an unlikely explanation rather than an excluded one.
  **Also corrected**: `VidAttachPartition` is not "join a partition". IOCTL `0x221014` reaches
  `VidPartitionIoctlAttach`, which loops the VPs calling `VidVpAttach` — the VM worker's *start the
  virtual processors* operation. It was not called.
  **So S5's obstacle has changed shape**: the mechanism exists and is exported, and what blocks it
  is a refused open. A stopped-VM arm
  was proposed and **dropped**: stopping the guest moves both candidate causes at once, and if the
  partition object goes with the VM then its Id is just another unused name, so neither outcome
  discriminates. The order of what was left runs in the numbered plan below rather than here. Full
  record in the
  [S5n result](docs/secure-kernel/secure-kernel-hypercall-feasibility.md) section.
- **S5o, 2026-09-29: the refusal is a partition-state test with no token in it, and the branch
  behind it is an ownership handoff.** A static read of `Vid.sys` — DbgEng opening the image as a
  target, no debuggee, nothing executed — answered the plan's next **two** steps at once.
  `Vid.sys` is KMDF, which is why S5n could find no `IRP_MJ_CREATE` dispatcher — not for want of a
  `MajorFunction` table, which `Wdf01000!FxDriver::Initialize` fills with the framework's own
  dispatch for all 28 entries, but for want of a *VID-owned* one. The callback is
  `VidFileCreate` → `VidFileObjectCreate`, and the refusal is a single site testing
  `[partition+0x3060] == 2` and `[partition+0x3079] == 1`. **It consults no token**, so the
  `SYSTEM` arm cannot change the outcome and was not run — and the one token check on the path,
  `VidSidPartitionCheck`, gates *creating* a partition, admitting any administrator outright and
  otherwise demanding the caller's own `NT VIRTUAL MACHINE` SID match the name. S5n's matched error
  becomes a **common cause**: on the non-Exo arm that site is the only `0xC0000184`.
  **And the branch behind the refusal is not what the plan wanted.** `VidPartitionAttach` makes the
  opener the partition's owning process — storing `PsGetCurrentProcess()` and switching the thread
  pool — and the one route into it this gate located runs through the current owner's detach IOCTL,
  which first calls `VidHandlerUnregister` and detaches every VP. So *on that route*, the step that
  would admit us dismantles the receive path S5m found. **This also corrects S5n on
  `VidPartitionIoctlAttach`**: it is the second half of a handoff, not merely "start the virtual
  processors", and it refuses a partition nobody has detached. **It is not established to be the
  only route in** — the gate enumerates no writers of either gating field, so another path into the
  admitting state would leave registration alongside Hyper-V open, and closing the question needs a
  writer census or live confirmation. It also decodes neither state value, reads one build,
  executed nothing, and leaves Exo partitions and handle duplication untouched. Full record in the
  [S5o result](docs/secure-kernel/secure-kernel-hypercall-feasibility.md) section.
- **S5 still does not pass, and after S5i there is one next gate rather than two.** Its condition wants a
  stop *delivered to a debugger*, and nothing here was delivered to **us** — this probe holds no
  port. That is not the same as nothing receiving it: the root's own stack owns a port for each
  child (S5b found eleven `Vid.sys` sites installing intercepts on children), and an exception
  intercept it never asked for landing there would produce exactly this hold — as would nothing
  being bound at all, which is why the next gate must tell them apart rather than assume one.
  **That first half was run as S5j, above, and it replaced the plan this bullet used to carry.**
  Establishing where the message goes was the right first step and it answered two things: the
  message is already addressed to the parent, so nothing needs redirecting; and the hand-rolled
  `HvCallCreatePort`/`HvCallConnectPort` plus SynIC page named here is **not** the build, because
  `winhvr.sys` exports the whole API and `Vid.sys` already consumes it. What is left is narrower and
  differently shaped, and it is **two reads, not one** — because S5j could not tell whether the hold
  it explains is an absent binding or Hyper-V's own handler keeping the intercept:
  - **The table key** that `WinHvSetInterceptRoutine` searches, from `Vid.sys`'s call sites and from
    whatever creates the entries. It decides whether a registration collides with Hyper-V's at all,
    and if it does, whether that costs one child or every VM on the host.
  - **Vid's own path for `0x80010003`** — preprocess, process, `VidExceptionInterceptReturnCallback`,
    completion. The key alone says nothing about *why the intercept stays outstanding*, which is the
    other live explanation of S5h's hold and the one a receiver would not fix. If Vid receives and
    retains it, building a second receiver is the wrong move whatever the key turns out to be.

  Only after both is there a receiver to build. The dispatch read that used to sit beside this **was
  run as S5i and is done**; nothing in it touches message delivery, so it neither helps nor blocks.

  **Both reads were run as S5k, and there is no receiver to build.** The key is the partition id;
  Vid is bound and recognises the message, and its handler drops one whose vector is not claimed in
  `[partition+0xB68]`, the per-vector table it consults. The receiving path — message,
  completion and instruction-pointer advance — already exists per partition and per vector, and what
  arms it is `VidHandlerIoctlExceptionRegister`, which claims the slot and *then* issues the same
  `WinHvInstallIntercept` S5b read. That pointed at a replicated arm reading `[partition+0xB68][3]`,
  **and S5m supersedes half of it.** The IOCTL has an exported user-mode wrapper, so *"is the slot
  claimed"* is answered by the registration's own return value, read as `GetLastError()`:
  `0xC0370001` means claimed, success means it was `0xFF`. **It does not supersede the other half**,
  because registering *claims* the slot — so a `#BP` raised afterwards exercises the registered
  receive path and cannot reproduce the unregistered drop, and a success says what the slot holds at
  that call rather than what it held during S5h. The other half, and the second candidate —
  **whether the hold is a loop**, since nothing on the drop path injects the exception or advances
  `RIP`, so the faulting instruction is presumably re-entered, an inference S5k did not measure —
  are **both blocked by the standing constraint below**, and the replicated arm additionally needs
  root kernel-memory access this bench does not have. **Both ran on 2026-09-30** once the
  constraint lifted and S5q's IOCTL supplied the kernel read — see step 6 below.

  **Standing constraint, from S5l: no arm may install an exception vector on a child until the
  teardown hazard has a remedy.** The pair is unremediable here — per S5l a pre-read is a
  diagnostic rather than a guard, and safety would need exclusive coordination with every other
  installer, which nothing on this bench has — so the removal can clear a vector another party
  holds. This is a property of *any* arm that arms and disarms a vector, not of a particular one,
  and it is written here rather than against each candidate because blocking them individually is
  how the loop arm stayed runnable after its twin was stopped. **It lifts on exactly two things**:
  an arm redesigned to install nothing, or a way to hold every other installer off for the window.
  Gaining the ability to read Vid's slot is **not** one of them — an earlier version of this
  sentence listed it, contradicting the line above it. A read is a diagnostic: a client can register
  between the read and the teardown, and the removal still clears its bit.

  **A `vid.dll` registration is not an exemption, it is the second lift condition partially met.**
  Vid claims and releases the slot with the bit, so it cannot collide with another *VID* client —
  the duplicate check holds every one of them off. It does not hold off a **raw**
  `WinHvInstallIntercept` installer, which leaves the slot `0xFF`, and against one of those the
  unregister still clears a bit it does not own. So the registration arm is permitted **only while
  no raw installer holds the vector**, and on this bench the only known raw installer is
  `h3probe.sys`, which this plan controls and is retiring for exception vectors. A third-party raw
  installer cannot be excluded, so this is a condition to check rather than a property to rely on.
  **Lifted 2026-09-29 by the operator, for guests the bench owns.** Both lift conditions above are
  about *other parties* — the constraint exists because a removal can clear a vector someone else
  holds. On a guest this bench owns and is willing to lose there is no other party whose loss
  matters, and the operator has authorised exactly that: the lab was built to be spent on this. So
  the constraint stands unchanged for any guest that is shared or that something depends on, and it
  does **not** block S5q below. Two things do not lift with it. The hazard S5q actually carries is
  not the one this paragraph is about — the receiver's callback runs in the **root's** dispatch
  path, where a fault is a host bugcheck rather than a guest one, and no authorisation about guests
  reaches it. And S5a's prohibition on planting an `int 3` in Secure Kernel is untouched: it is a
  different prohibition for a different reason, and S5r below is the route to that question that
  does not need it.

- **A working receiver would still leave Secure Kernel's own code untested**, which is now the only
  gap rather than one of two. Before S5i it was the mechanism question that governed it: an
  excursion-mediated hold would not have reached Secure Kernel at all. S5i retires that — the bitmap
  is selected by VTL and a VMCS bitmap is privilege-blind — so what remains is an architectural
  inference rather than an open mechanism. S5a's prohibition on planting an `int 3` in Secure Kernel
  to check is unchanged.

- **S5q — WRITTEN BEFORE THE RUN, 2026-09-29: chain Vid's intercept routine and receive a VTL1
  `#BP`.** With the standing constraint lifted above for disposable guests, the route S5k
  prohibited becomes the cheapest one to S5's pass condition. `WinHvSetInterceptRoutine` is a
  `winhvr.sys` **kernel** export keyed by `HV_PARTITION_ID` (S5k read the key out of
  `WinHvpReferencePartition`'s binary search), so a root driver reaches it with no VID partition
  handle at all — **S5n's and S5o's refused `CreateFileW` is a fact about the *user-mode* route and
  does not bind this one**, which is the thing the ordered plan below had stopped seeing. What S5k
  called a permanent prohibition was a policy about shared guests, and its stated cost — one
  child's intercepts — is one the operator accepts on a guest the bench owns.

  **Replacing the routine defeats the arm, so chaining is the design rather than a refinement.**
  `WinHvpOnInterception` (`+0x4438`) dispatches IO-port, MSR and CPUID intercepts through the same
  routine it looks up at `+0x10`/`+0x18` of the partition object, so a receiver that merely assigns
  over Vid's stops the child being serviced — and a child that is not serviced runs no enclave and
  raises no `#BP`. The receiver must save the previous routine and context, handle **only**
  `HvMessageTypeX64ExceptionIntercept` (`0x80010003`) carrying the vector it installed, and
  tail-call the saved pair for everything else. That else-branch is also what keeps the arm clear of
  `VidInterceptPreprocess`'s `__fastfail` holes (S5k): nothing is synthesised, only forwarded.

  **The swap is not atomic, and the ABI offers nothing that would make it so.**
  `WinHvSetInterceptRoutine` stores the routine and the context in two separate stores and
  `WinHvpOnInterception` loads them in two separate loads, so an intercept dispatched *during*
  either the install or the restore can pair the new routine with Vid's context, or Vid's routine
  with ours — and either is the host bug check this gate exists to avoid, with both callbacks
  perfectly correct. There is no quiesce: nothing exported pauses or drains intercept dispatch for
  a partition, so this cannot be remedied, only narrowed and declared. **What narrows it** is the
  ordering the arms use, which is deliberate rather than incidental: chain **before** arming any
  vector and remove the vector **before** unchaining, so no exception intercept is ever armed
  across a swap and only an IO-port, MSR or CPUID intercept could land in the window. **What it
  does not do is close it**, and the window is real on any busy partition. Both arms swapped with
  the forward counter at zero throughout, so on this bench it was never exercised — which is an
  absence of dispatch, not evidence that the race is benign.

  **Build**, all in `h3probe.sys`: a kernel-read IOCTL — the capability S5l named as missing, which
  unblocks the replicated `[partition+0xB68][3]` read as a side effect — the chaining receiver, and
  on the resume path **`VidInterceptAdvanceInstructionPointer` and then** `WinHvCompleteIntercept`:
  completing a software exception without advancing `RIP` re-enters the faulting instruction, so a
  receiver that only completes would intercept the same `int 3` for ever and read as a broken chain.

  **Resolution, read 2026-09-29 before anything was built.** The WDK ships **no kernel-mode import
  library for `winhvr.sys`** — the only `WinHv*` libraries in `10.0.26100.0` are user-mode
  `WinHvPlatform.lib` and `WinHvEmulation.lib`, which are the WHP *Exo* family S5m already found to
  be the wrong mechanism. And `MmGetSystemRoutineAddress`, which is how `h3probe.c` resolves
  `nt!HvlInvokeHypercall` today, is documented to cover `ntoskrnl` and `hal` only. **So the receiver
  resolves its imports itself**: find `winhvr.sys`'s base in the loaded-module list and parse its
  export directory by name. The eight exports the gate needs were read out of this host's own
  `winhvr.sys` (201 exports) rather than taken from S5j's record — `WinHvSetInterceptRoutine`,
  `WinHvCompleteIntercept`, `WinHvInstallIntercept`, `WinHvGetSintMessage`, `WinHvSetEndOfMessage`,
  `WinHvCreatePort`, `WinHvConnectPort` and `WinHvAllocatePartitionSintIndex`, all present. That
  export walk is the one piece of this gate with no precedent in the driver, so it is written and
  tested before the intercept goes anywhere near it.

  **Staged, because the dangerous part is the smallest part.** A fault in our callback is a **host**
  bugcheck, and the callback is the only new code executing in the root's dispatch path — so it runs
  first with nothing in it. **Arm 0, the null receiver**: chain in, forward *every* message to the
  saved routine, handle nothing, install no intercept at all. **Pass:** the guest keeps serving —
  a second PowerShell Direct session answers and the enclave completes a full `L<n>` cycle — and
  teardown restores the saved pointer. **That sentence was wrong and the arm 0 result below says
  so**: this exercises registration and restore, not dispatch, because with no intercept installed
  nothing is dispatched. What it does test is real, and it
  is also the only arm that can be run without installing a vector, so the standing constraint does
  not reach it. Only if arm 0 is stable does the exception handling go in. **If arm 0 bugchecks the
  host, the in-kernel receiver is retired** — the same stop condition as below, reached for a
  tenth of the cost. It used to add *and step 8's own-partition build is selected*; step 8 has
  since been costed and the costing **did not settle** the build, so a host bugcheck retires the
  receiver and leaves this line pointed at a route whose cost is still unbounded.

  **Pass:** a `#BP` raised in VTL1 user mode is delivered to **our** callback, its context is
  readable, and `WinHvCompleteIntercept` resumes the raiser. Nothing in S5 has met this; S5h
  measured a hold with no receiver at all.

  **Controls, and the gate is withdrawn rather than caveated without them:**

  - **`BP0` on the same guest.** A VTL0-raised `#BP` must arrive first, or the receiver is unproven
    and nothing VTL1 rests on anything.
  - **The VTL0-only twin.** Same install, same raise, must arrive. If a delivered message cannot
    distinguish a VTL1 arrival from a VTL0 one, **say so** rather than inferring the VTL from the
    arm that produced it — S5i's dispatch read is what carries the VTL claim, and this gate does
    not re-derive it.
  - **`#BR` installed with nothing raising it** — must deliver nothing. S5h's null arm, unchanged.
  - **The chaining control, which is the one a green run would skip.** With the receiver installed
    and no `#BP` raised, the guest keeps serving: a second PowerShell Direct session answers and the
    enclave completes a full `L<n>` cycle. A wedged guest means the chain is wrong, and every
    reading downstream of it is measuring that instead.

  **Stop conditions.** A **host** bugcheck retires the in-kernel receiver — the callback runs in
  the root's dispatch path, so a fault there takes the bench rather than a guest. It no longer
  *selects* step 8's own-partition build: step 8 is costed, and the costing did not settle the
  build either way.
  **That, and not the displacement, is the hazard this gate carries**;
  the displacement is bounded to one child and is what the lift above accepts. A guest that wedges
  only with the chain installed stops the gate until the chain is fixed. **Teardown order is part
  of the gate**: remove the hypervisor intercept bit **first**, then restore the saved routine, and
  pair both in a `finally` — per S5l the removal is an unconditional `and ~bit` with no refcount.
  **An earlier draft of this sentence had the order the other way round**, which contradicted the
  non-atomic-swap paragraph above and the order arm 1 actually used: restoring while the vector is
  still armed leaves an exception able to dispatch through a half-swapped pair, which is the host
  bug check that paragraph is about.

  **What it was expected to settle, and cannot.** A draft here said a delivered message would show
  which branch S5h met. **It would not**: this arm *replaces* Vid's routine, so our receiver is
  reached before Vid's slot check ever runs, and delivery looks identical whether Vid would have
  dropped the message or retained it. Recovering that branch needs Vid's decision instrumented
  while it happens, or S5h reproduced with the slot recorded — neither of which this is. **A draft
  here then said arm 1 made the question moot from the other side, "nothing was delivered at all".
  That is disproven**: step 9's combined arm reads the message arriving at
  `VidInterceptPreprocess` with the chain standing and `forwarded = 0`, so what arm 1 saw nothing
  of was the **chained callback**. The branch question is not moot — it is open, and open for the
  reason this paragraph gives rather than for want of a message.

- **S5r — WRITTEN BEFORE THE RUN, 2026-09-29: reproduce the published IUM-debugging patch from the
  root, with no outer hypervisor.** Quarkslab's
  [*Debugging Windows Isolated User Mode (IUM) processes*](https://blog.quarkslab.com/debugging-windows-isolated-user-mode-ium-processes.html)
  (2023-09-07) debugs VTL1 **user** mode — breakpoints, single-stepping, registers, against
  Microsoft's own shipped trustlets — by patching Secure Kernel's `SkpsIsProcessDebuggingEnabled`
  in physical memory so that the guest's own VTL0 debugger is permitted to attach. Their access to
  that memory is an **outer hypervisor**: VMware Workstation as L1 with its GDB stub enabled,
  Hyper-V nested inside it, the target as L2, IDA driving the patch. **S4's direct route reaches
  the same bytes from the Hyper-V root with no nesting and no second hypervisor**, which is the rig
  [the EXDI stub plan](docs/secure-kernel/exdi-stub-plan.md) went looking for and this plan escaped.
  So the question is not whether the technique works — it is published — but whether this plan's
  primitive is a **strictly cheaper delivery** of it.

  **Pass:** the patch is applied from the root, a debugger attaches to a trustlet in the VBS guest,
  and a breakpoint in VTL1 user mode is hit. **Read that condition strictly when the arm runs**: the
  `int 3` Windows injects into a debuggee on attach is not a breakpoint planted at a chosen address,
  and only the second demonstrates breakpoint *setting*.

  **Controls:** the same attach **before** the patch must fail, or the patch is not what admitted
  it; and the patched bytes are read back and restored against the on-disk image, as S4 did with
  the `.text` cave rather than from memory.

  **What a pass is worth, stated now so it is not overread.** It is a *reproduction with a simpler
  rig*, not a new capability, and the write-up says so in its own first sentence. Its second value
  is evidential and points at a question S4 left open: their patch **persists** for the length of a
  debugging session, which is exactly the persistent-modification experiment S4 declined to run —
  so a pass is evidence that Secure Kernel's own `.text` is not checksummed in a way that catches
  this. That is a reading of one function's page on one build, **not** a property of VBS, and the
  claim goes no further than the bytes touched.

  **Stop:** a bugcheck on applying the patch stops the gate, and it is taken against a throwaway
  checkpoint so that it can. **It would not by itself answer S4's open question**: a stale offset,
  wrong patch bytes or an unrelated fault produce the same outcome, so it counts as integrity
  detection only with evidence attributing it to that mechanism, and is otherwise recorded as
  inconclusive. Verify the details against the original write-up before building on this summary: the
  gate was written from a fetched précis, and the function name, the build it was read on, and
  whether the patch is applied once or re-applied are each load-bearing.

- **S5s — WRITTEN BEFORE THE RUN, 2026-09-29: does LiveCloudKd's active CLSID deliver a VTL1
  breakpoint, or is it inspection of a paused VM?** E2a in
  [the EXDI stub plan](docs/secure-kernel/exdi-stub-plan.md) named this arm and **it was never
  run**, which is why this plan has carried "the active CLSID's breakpoint support is undemonstrated
  by its own write-up" as an observation about someone's documentation rather than a measurement.
  It decides what every novelty claim here is worth. The tool's headline is a *debugger*; its
  published write-up claims you can "(potentially) set breakpoints and walk through code" and
  demonstrates module enumeration and memory reads through `dx` — no breakpoint, no step, no
  exception anywhere in it.

  **Binary, and either outcome is useful.** Register the active CLSID
  (`{67030926-1754-4FDA-9788-7F731CBDAE42}`; the passive one is
  `{53838F70-0936-44A9-AB4E-ABB568401508}`), attach to the VBS guest from its Hyper-V host, and set
  a breakpoint in `securekernel.exe`. **If it is hit**, execution control over VTL1 exists today,
  and what S5 contributes is the route rather than the capability — say that plainly and rewrite
  the claims. **If it is not**, what the tool provides is inspection of a paused VM, which is then
  the accurate description of **what this build of this tool provides** — and of nothing else. It
  says nothing about the other published routes, which rest on their own evidence and which the
  route table keeps separate; the 2025 thesis in particular reaches execution control that this
  sentence once implied nobody had.

  **Controls:** the same breakpoint set in `nt` through the same CLSID must be hit, or a miss
  measures the rig and not VTL1. And the **passive** CLSID must first resolve SK symbols against
  live memory with the VBS-off twin finding no SK data block — E2a's original control, unchanged,
  and the one that says the tool is pointed at a Secure Kernel at all.

  **Cost and hazard, which are on the debugger host rather than a guest.** `hvmm.sys` carries a
  revoked certificate (`CN=Atheros Communications Inc.`, expired 2013) and needs re-signing plus
  test signing on the **Hyper-V host of the target**, and its own `Start-ExdiDebugger.ps1` carries a
  `Stop-ExdiContainingDllHosts` because the surrogate outlives the debugger — the same E0 activation
  stall this plan already hit. Both weakenings outlive the run: record them and reverse them.

- **S5s — RUN 2026-09-29: the active CLSID refuses to start, so the answer is the "if it is not"
  branch.** `kd -kx exdi:CLSID={67030926-…}` against release `v3.3.2.20260720` produces one modal
  dialog carrying a string hardcoded in `ExdiHvSrv.dll` — *"That build of EXDI plugin is not
  supported live Hyper-V debugging"* — and kd's log ends at the version banner with no connection,
  no target and no `bp`. **The gate's `nt` breakpoint control was never reached and did not need to
  be**: it exists to separate a broken rig from a refused VTL1, and the server declined before a
  target existed, which is neither. A breakpoint in `securekernel.exe` cannot be attempted through
  this build at all. **So what LiveCloudKd provides is inspection with Secure Kernel symbols on
  top**, and every novelty claim in this plan may be stated against that — for **this release**,
  the refusal being build-conditional by its own wording.
- **Narrowed 2026-09-30: S5s tested the main release line, not the asset the procedure links.** The
  maintainer's live-debugging page links `LiveCloudKd.EXDI.debugger.v1.0.20251103.zip` (tag
  `v1.0.20251103`, confirmed in the release list) and says to register **`ExdiKdSample.dll`** — a
  separate download post-dating `v2.8.4.20241221`'s *"EXDI plugin renamed to `ExdiHvSrv.dll`"* by
  eleven months, and those notes never name the old spelling, so `exdi-stub-plan.md`'s "the article's
  naming is stale" was an inference from two filenames and is corrected. **Its contents were not
  read**, so whether its DLL is a distinct binary is open — and since the refusal string is
  build-conditional, only that zip answers whether its build carries the same gate. **It is not
  queued, for two reasons that are already on the record**: its procedure
  requires the **Classic** scheduler against this host's **Root** (the 2026-09-19 preflight decision,
  which also declined to change a shared host), and it reaches VTL1 by **duplicating handles from
  `vmwp.exe`** — step 7 below, declined on scope grounds rather than open on technical ones. So this
  is a decision for the maintainer, not a compatibility investigation.
- **And the inspector half passes, with its control.** The passive CLSID connects, finds
  `ntkrnlmp`, resolves NT symbols and walks the process list; `IeXdiControlComponentFunctions` is
  unimplemented (`0x80004002`), so `.exdicmd` is missing beside the execution control.
  `hvlib.dll`'s own classes give the VBS guest `InfoSecureKernelBase` `0xFFFFF80629B4A000`, size
  `0x175000`, `InfoHvddGetCr3Securekernel` `0x1201000` — and the twin **`0x0` on all three**. In the
  debugger, `.reload /f securekernel.exe=<base>` loads `securekernel` **with PDB symbols** and
  `db` at that base reads `4d 5a 90 00`, while the **identical commands at the identical address on
  the VBS-off twin** give all zeros, *Unable to verify timestamp* and one page with no symbols. **No
  `RegCr3` override was needed**, though the value name exists. `SkpsEnableDebugging` (**+0xA4658**)
  and `SkpsSendDebugAttachNotifications` (**+0xA4D50**) resolve, and
  **`SkpsIsProcessDebuggingEnabled` does not exist in this build's public PDB** — which corrects
  S5r, written with that name from a fetched précis rather than from the write-up. The new name is
  a **candidate** for the gate that work patches, not an identification.
- **The partition identity was established three ways before any VTL1 reading was taken**, because
  the host reset below left the twins matched on uptime to under a second and killed the
  discriminator earlier gates used: NT kernel base, the presence of `Secure System` and
  `LsaIso.exe` in VTL0, and hvlib's own `InfoPartitionId`/name — all agreeing with the host's
  `Get-VMSecurity`, and all saying `VmId` 0 is the control and `VmId` 1 the VBS guest. `VmId` is a
  DWORD index over **VMs only**; 2 and 3 fail with `CO_E_SERVER_EXEC_FAILURE`, so the VSM scan adds
  no pseudo-partition to select.
- **The first attempt hung the host, and the cause was the harness rather than the attach.** `kd`
  launched with `Start-Process -NoNewWindow -RedirectStandardOutput` wrote **281 KB of
  `kd: Could not write to pipe, 1450`** while a modal blocked it — the modal being the plugin asking
  for `VmId`, a DWORD in `HKLM\SOFTWARE\LiveCloudKd\Parameters` that did not exist yet. Kernel-Power
  41, unexpected shutdown, **no dump**: a reset of a hung machine, not a bug check, and the same
  signature this bench recorded for `cdb -server`, so the rule is about **any** debugger child and
  `-RedirectStandardOutput` is not the "redirect to a file" it means. Both guests rebooted with the
  host, so the S5g landmarks have moved again. The replacement harness — pre-supplied settings, the
  child in **its own window**, kd's own `-logo`, a **job object** with `KILL_ON_JOB_CLOSE`, a bounded
  wait, an explicit kill on every path and a `dllhost` sweep — then ran six times with no
  recurrence. **No guest was modified, no intercept installed and nothing written to VTL1.** Full
  record in the [S5s result](docs/secure-kernel/secure-kernel-hypercall-feasibility.md) section.

- **S5r — RUN 2026-09-29: PASS, end to end, and the gate had to be found rather than looked up.** A
  `#BP` raised in **VTL1 user mode** was caught by a **VTL0 debugger** and continued, with the guest
  under one hypervisor and no nesting — against the published route's VMware L1 plus nested Hyper-V
  plus IDA. **The claim is a cheaper delivery of a published capability, not a new one**, and the
  write-up says so first.
- **The original work is the gate.** `SkpsIsProcessDebuggingEnabled` does not exist in 26100, so the
  equivalent was located by dumping SK's image out of live VTL1 (`.writemem`, 1,527,808 bytes) and
  **computing `E8`/`E9` displacements over the dump** to find call sites into
  `securekernel!SkpsEnableDebugging`. Two of the three are inside **`IumInvokeSecureService`**, the
  VTL0→VTL1 secure-call dispatcher. `SkpsEnableDebugging` is a **setter**, not a predicate — S5r's own
  gate text treated it as the gate and that was wrong. The guard is at `securekernel.exe+0x1434C`:
  `test bl,bl` / `jne` / `mov ebx,0C0000022h` (`STATUS_ACCESS_DENIED`) / `jmp`, with `bl` from
  `sete bl` on `cmp eax,80430006h`. **One byte opens it** — `0x75` → `0xEB` at **`+0x1434E`** — and
  only the opcode is written, the displacement being identical in both encodings so a torn write
  cannot retarget the branch.
- **The A-B-A is the result, not the middle arm.** `DebugActiveProcess` against `LsaIso.exe`
  (pid 928, a Microsoft-signed trustlet in VTL1 user mode) over PowerShell Direct: **before**
  `False`/`ERROR_ACCESS_DENIED (5)`; **patched** `True`, then `CREATE_PROCESS_DEBUG_EVENT`, five
  `LOAD_DLL_DEBUG_EVENT` and **`EXCEPTION_BREAKPOINT 0x80000003` at `0x7FFE381E3AB0`** on tid 4432,
  continued with `DBG_CONTINUE` and detached cleanly; **after restore** `False`/`5` again. The before
  arm ties the disassembly to the observable — Win32 `5` is the mapping of the `0xC0000022` the guard
  writes — and the after arm makes the middle one a result rather than a trustlet that happened to be
  debuggable.
- **`SdkWriteVirtualMemory` segfaults on a VTL1 address while `SdkReadVirtualMemory` at the same
  address works**, so the write goes through S4's physical route: SK base and SK `CR3` read per run
  (`0xFFFFF80629B4A000`, `0x1201000` this boot), a four-level walk to GPA **`0xCE534E`** agreeing with
  an independent `!vtop`, and the page identified by diffing **48 live bytes against the dumped image**
  with the gate byte masked. **The crash printed nothing** — Python's stdout buffer dies with the
  process — so what established the write had not half-landed was a re-read, not the absence of output.
- **Twelve minutes of live Secure Kernel code modification, exercised, with no bugcheck.** Bounded by
  guest uptime `1:03:31` at the patch and `1:17:43` at the post-restore check, across two complete
  debug-attach cycles. S4's write lasted milliseconds between two reads and the record rightly said
  that showed nothing about a periodic check; this one stood while the modified path was *used*.
  **It is one byte on one build and not a property of VBS** — no check was located, so this is not a
  measurement *of* one — but it retires the specific reason this plan gave for not trying, which was
  that a bugcheck is the expected outcome. Bench restored and verified; checkpoint `pre-S5r-patch`
  unused. Full record in the
  [S5r result](docs/secure-kernel/secure-kernel-hypercall-feasibility.md) section.

- **S5q steps 1 and 2 — RUN 2026-09-29, both read-only: the imports resolve and the table is read.**
  Neither installs an intercept, registers a routine nor writes to a partition; **arm 0 has not
  run**, and no code of ours has executed in the root's dispatch path. **Step 1**, `IOCTL_H3_RESOLVE`:
  there is **no kernel-mode import library for `winhvr.sys`** — the WDK's only `WinHv*` libraries are
  the user-mode WHP *Exo* pair — and `MmGetSystemRoutineAddress` covers `ntoskrnl` and `hal` only, so
  the driver finds the module with `AuxKlibQueryModuleInformation` and parses the export directory
  itself, bounding every RVA against `SizeOfImage` and **refusing forwarded exports** rather than
  handing back a `"Dll.Name"` string. **8 of 8 resolved, all inside the image**, and
  `WinHvSetInterceptRoutine` at **`+0x8020`** is the RVA S5k read statically from the same build —
  a static read and a runtime walk agreeing on one offset is what makes the other seven worth
  anything.
- **Step 2, `IOCTL_H3_WHVPART`: the layout was re-derived from this build rather than taken from
  S5k's note**, and `WinHvpReferencePartition` (`+0x2B40`) and `WinHvpOnInterception` (`+0x4438`)
  agree — `WinHvpPartitionArray` (`+0x152D0`) points at `{ULONG Count}` followed by sorted 16-byte
  `{ULONG64 PartitionId; PVOID Object}` entries at `+8`; the object carries a refcount at `+0x00`,
  the **routine at `+0x10`** and the **context at `+0x18`**; and the dispatch is
  **`Routine(Context, Message)`**. Live: **two partitions, `0x2` and `0x3`**, both with
  `0xFFFFF807502E4170` = **`Vid!VidInterceptIsrCallback`** (`Vid.sys+0x4170`, `VidInterceptPreprocess`
  the next symbol) — so **S5k's static claim that Vid is bound is now confirmed at runtime**, for
  both partitions.
- **The constraint step 2 produced, and a static read could not have.** **One routine, two different
  contexts** (`0xFFFF818A46AB3000` against `0xFFFF818A46DF5000`): the routine is Vid's single
  dispatcher and the **context** is what identifies the partition. A chain must therefore save and
  forward **both**, passing the *original* context — one that saved only the routine pointer and
  passed its own looks correct and makes Vid dereference the wrong partition object, a **host** bug
  check on the first non-exception intercept. This is why arm 0 exists and why it came before the
  exception work.
- **Two guards, both load-bearing, and one hazard that is bench-dependent.**
  `WinHvpPartitionArray` is **not exported**, so its RVA is a build-specific constant that would read
  arbitrary kernel memory on another build: the IOCTL refuses unless the **loaded** image's
  `TimeDateStamp` **and** `SizeOfImage` match the build it was read from (`0x31B98FBA` / `0x29000`),
  reporting what it saw either way. And it takes the **same shared push lock**
  `WinHvpReferencePartition` takes, because a concurrently torn-down partition leaves a stale object
  pointer whose dereference at `+0x10` faults in the root. **The hazard**: the dispatch is
  `guard_dispatch_icall`, so a chained routine must be an acceptable **CFG** indirect-call target —
  a real constraint on an HVCI host, and not on this bench — **measured**, not inferred:
  `NtQuerySystemInformation(SystemCodeIntegrityInformation)` gives `CodeIntegrityOptions`
  `0x282203` with **`HVCI_KMCI_ENABLED` (`0x400`) clear** and the scenario key at `Enabled = 0`,
  while **`HVCI_IUM_ENABLED` is set**, so it is *kernel-mode* HVCI that is off. An earlier draft
  inferred it from test-signed drivers loading, which is unsound — they load under HVCI too. Full record in the
  [S5q steps result](docs/secure-kernel/secure-kernel-hypercall-feasibility.md) section.

- **S5q arm 0 — RUN 2026-09-29: the chain installs and restores, and it cannot test what it was
  written to test.** Registration and restore **completed and were verified exactly**, on a partition
  where nothing was dispatched across the swap — which is not the same as safe, the swap being
  non-atomic per the paragraph above; **dispatch is untested**, and the
  gate text above that called arm 0 the step which "exercises the whole hazard with no logic in it"
  is **wrong**. Established: the chain installs on partition `0x3` saving
  `Vid!VidInterceptIsrCallback` and that partition's own context, leaves partition `0x2` untouched
  throughout, the guest keeps serving (two concurrent PowerShell Direct sessions, 0.9 s round trip,
  `LsaIso` alive, the enclave completing 20 VTL1 calls), and the restore is **exact** — routine and
  context back byte for byte — after which the driver unloaded clean. No host reboot, no
  Kernel-Power 41, no dump.
- **The forward counter read `0`, and it is the only reason that is known.** Our routine was never
  called — not during the enclave's VTL1 calls, not during twelve seconds of guest CPU and
  file-system churn. Without the counter every other measure reads as a clean pass and the arm would
  have been written up as *"our code ran in the dispatch path and nothing broke"*, on evidence that
  says nothing of the kind. Zero is **consistent with S5k**: `VidHandlerpExceptionRegisterEntry`
  claims its slot and *then* installs the intercept, so with no intercept installed there are no
  exception-intercept messages to dispatch, and ordinary guest activity produced no IO-port, MSR or
  CPUID intercept routed to VTL0 either.
- **So there are two hazards where the gate assumed one**, and the cheap-arm-first ordering does not
  survive it. **Registration and restore** — replacing a pointer Hyper-V holds and putting it back —
  is what arm 0 tests, and it passes. **Dispatch** — our code running when Hyper-V calls it — cannot
  be reached without an intercept existing, and an intercept means installing a vector. That moves
  the dispatch hazard into **arm 1**, beside the vector-install hazards S5l described, rather than
  ahead of them. Arm 0 is still worth what it measured: a failed restore or a forwarded-wrong context
  would each have been a host bug check, and both were live before this run. Full record in the
  [S5q arm 0 result](docs/secure-kernel/secure-kernel-hypercall-feasibility.md) section.

- **S5q arm 1 — RUN 2026-09-29: the trap is held and the partition's routine is never called —
  which is the chained callback, not delivery.** (This bullet said *"so the message is not
  delivered"*; step 9's arm measured the message arriving at `VidInterceptPreprocess` by a path that
  never reads that slot, so the result stands for the callback and never stood for delivery.)
  Partition `0x3` with our routine chained into its slot,
  `HvCallInstallIntercept` type 3 / access 4 / vector `0x03`, and `spin_host.exe BP0` — S5h's own
  VTL0 raiser — launched detached. The install succeeded, the **raiser was held** at all ten
  2-second samples across 20 s (against **878 µs** to finish all 1000 rounds with no intercept
  standing, measured immediately before), and **`forwarded` stayed 0 throughout**. Teardown removed
  the intercept, released the raiser, restored the chain, left nothing standing; host and both
  guests untouched. **So this is not arm 0's vacuous zero**: the trap fired, the hypervisor took it,
  and our routine still was not called.
- **The alternative had to be excluded before the zero meant anything**, because this instrument has
  never been observed to carry a message — zero in arm 0 across guest churn and 20 VTL1 enclave
  calls, zero here with a trap held. The alternative was *the field we patched is not the field this
  dispatch consults*, and it is a static question.
  [`tools/winhv_partition_readers.py`](tools/winhv_partition_readers.py) answers it: a census of
  `+0x10` alone cannot (365 accesses in `winhvr.sys` by `vid_field_census.py`'s count), so it first
  finds the **28 of 497** functions that can hold a partition object at all — those calling
  `WinHvpReferencePartition` or loading `WinHvpPartitionArray` — and only then reports `+0x10`/`+0x18`
  with capstone's read/write classification and stack traffic dropped. **Two sites trace end to end
  to the same field**: `WinHvSetInterceptRoutine` (`+0x8020`) writes `[rax+0x10]`/`[rax+0x18]` off
  `WinHvpReferencePartition`'s return, and `WinHvpOnInterception` (`+0x4438`) reads the same pair off
  the array-derived object. **So what the zero measures is that *our registered routine was not
  called*.** That is as far as it goes: the census is a lower bound over two anchors, so it cannot
  establish that `WinHvpOnInterception` did not run, and the readings it leaves open — an argument-
  passed holder, a helper this does not follow — are exactly the ones that would let it run and
  consult something else. **That the message was never delivered is an inference from the zero, not
  a measurement of the delivery path**, and the path itself is unresolved. **Step 9's combined arm
  has since disproven that inference by measurement** — same slot chained, same intercept, message
  arriving at `VidInterceptPreprocess` with `forwarded` still `0`. The hedge was right to be one.
- **The limit, stated rather than glossed.** The census is function-scoped, not provenance-scoped.
  Three other functions read the pair — `WinHvpOnMirroringNotification`,
  `WinHvpSendRestartNotificationToAllPartitions`, `WinHvIssueSnpPspGuestRequest` — and their names
  say they serve other message types, but their objects were not identified, so a dispatch consulting
  one of those instead is **narrowed, not eliminated**. **The `.pdata` hole is narrowed, and what
  closed it was giving up on a question the image cannot answer** (re-derived 2026-09-30): `.pdata`
  claims no leaf functions, so the tool decodes the bytes the table leaves out — **9,599 here, 9,569
  of them `0xCC`/`0x00`, five spans holding anything else, 0 distinct bytes refused**. A gap has no
  unwind record, and four attempts to infer where a leaf begins or ends were each wrong differently:
  one stream from the span start loses an island after an odd-length `0x00` run (`00 00` is a two-byte
  `add byte ptr [rax], al`); splitting at *every* `0xCC`/`0x00` byte cuts instructions apart, since **a
  single zero byte is not padding**; one region per span loses provenance, crediting one leaf's field
  access to another leaf's anchor load; and ending an island at padding fixed that only for *padded*
  neighbours, leaving two leaves emitted back to back collapsed. Adding `ret` as a second boundary
  would split a real two-return function instead, then `jmp` and `int 29h` in turn — a predicate per
  round. **So boundaries are not inferred at all.** A `.pdata` entry is a function (exact bounds,
  decoded whole), and **that is where 28 and 42 come from** — and nowhere else by construction, since
  `analyse` iterates the `.pdata` table only and a gap span is never keyed into the reaching set.
  A gap span is a *detector*: the union over its candidate starts, reported in its own section,
  **excluded from both counts**, labelled *boundaries unknown*. Here that section prints **"none: no
  span reaches an anchor or touches `+0x10`, `+0x18`"** — the negative stated as a measurement rather
  than inferred from an empty list. And **`rbp` is no longer assumed to be a
  frame pointer**, being suppressed only where the function's `UNWIND_INFO` names it as the frame
  register — 16 such operands exist image-wide and none is in a reaching function. **The answer did not
  move** through any of the five: 28 and 42 throughout, under every broken reading too, which is why
  the gap scan needed its own test. **The reaching set is still a lower bound**: a function handed the
  partition object as an *argument*, or getting one from a helper other than
  `WinHvpReferencePartition`, calls neither anchor and is absent from the 28 even if it reads the
  pair — and none of the gap work above touches that, because it is a provenance limit rather than a
  coverage one. Closing it needs provenance carried across calls and returns, which the tool does not
  do. **The tool now has `--self-test`, 24/24** — detection under each alignment hazard, no-attribution in both the padded
  and unpadded shapes, a byte refused twice counted once, and a `.pdata`-claimed function as the
  control that attribution still happens where bounds are exact; mutation-verified so the scores share
  a denominator — attributing gap spans as functions scores 20/24, a single start 15/24, a summed
  refusal count 23/24. Every index in it returns empty rather than raising, so a mutation reports the
  assertions it broke instead of aborting. Treat its function set as a reading.
- **What it does to S5j's two explanations, and to the build.** S5k killed *nothing was bound*;
  step 2 confirmed Vid bound at runtime for both partitions. Arm 1 bears against the second, *the
  handler received it and retained it*: the routine chained into `[partition+0x10]` is **not
  called**, so the hold is not something *that routine* retains. **Corrected 2026-09-30 — this entry
  and the doc both said "it happens before the root's intercept dispatch runs", and that does not
  follow.** This host runs the **root** scheduler (Hyper-V-Hypervisor event ID 2 reports `0x4` on each
  of the three most recent boots, latest 2026-09-29 17:58:30, read 2026-09-30) and `Vid.sys`
  `10.0.26100.9278` has **two further paths into `VidInterceptPreprocess` that never read the
  partition callback**: `VidXSchedulerpVpRun` (`+0x2CB80`) calls `[_imp_WinHvRunVpDispatchLoop]` at
  `+0x2CC09` and `VidInterceptPreprocess` **directly** at `+0x2CC2A`, and
  `VidXSchedulerVpThreadStartRoutine` (`+0x2D900`) does the same at `+0x2DAA8` and **`+0x2DAC8`**;
  both test the returned reason and load the message at `[VP+0x8D8]`. So `forwarded = 0` is
  consistent with VID having received the intercept through its dispatch loop, and S5j's second
  explanation is **narrowed to the chained slot, not eliminated**. S5k had flagged this fork
  (`VidDeviceExtension+0x288` bit `0x40`) and scoped its finding to the bit-clear path; S5q did not
  carry that forward. **Three arms now survive, all inferences, and the two paths widen the fork
  rather than picking an arm** — *(3) was later eliminated by step 9's arm, which read the message
  arriving; the fork is kept as written because it is what that arm was built from)*: (1) delivered
  with the per-vector slot unclaimed, so VID took the
  unregistered-vector branch — a raw install neither claims that slot **nor establishes its state**;
  (2) delivered with the slot already claimed by another VID client, so the handler *enqueued* to it,
  which is S5j's received-and-retained reading and stays live because `[partition+0xB68][3]` **was
  never read** and S5l showed a claim survives a probe removal; or (3) not delivered, S5k's "half of
  the arming sequence" being the port and SINT plumbing `winhvr.sys` exports rather than a per-vector
  flag. Both delivery arms travel the same two paths, so the measurement bears on *delivered versus
  not* and not on the branch — an earlier version of this entry called arm 1 "the better supported,
  since its paths are measured", which reads a shared mechanism as evidence for one of the things
  sharing it. Arrivals at the convergence point separate (3) from (1)–(2); only a contemporaneous slot
  read in the same arm separates (1) from (2). **What arm 1 does establish is that the
  receiver is not a routine to chain**: chaining installs and restores cleanly and receives nothing.
  What it does **not** establish is that no delivery path exists, so it leaves the delivery question
  open rather than answered against, and step 8 is where the *chaining* failure points rather than
  where the evidence forces the build. **The successor is step 9 below, not step 8** — and step 9's
  arm has since closed the delivery question **in the affirmative** and eliminated arm (3): the
  message arrives at `VidInterceptPreprocess`, so `forwarded = 0` here was the chained slot being
  bypassed rather than nothing arriving. Full record in the
  [S5q arm 1 result](docs/secure-kernel/secure-kernel-hypercall-feasibility.md) section.

### Out of scope, with the reason rather than as a list

- **Writes as a *tool surface***: the primitive exists and S1's seam should not pretend otherwise,
  but exposing "patch a live guest's VTL1" as a tool needs its own justification and confirmation,
  and nothing in S0–S3 needs it. Note the adjacency hazard when it is built: `HvCallWriteGpa` is
  `0x0054`, one off the read.
- **H5a / EXDI**: parked with its two-part reversal condition recorded. Not re-litigated here.
- **Distributing a driver**: the repo ships none; the operator supplies the transport, per the
  first constraint.

### Unknowns, in the order they change the plan

1. ~~**S0's saved-state source**~~ — **answered 2026-09-26**: a Hyper-V standard checkpoint carries
   VTL1 and its `CR3`, read driver-free through the SDK's `vmsavedstatedumpprovider.dll`. The
   remaining setup is Hyper-V administrator on the host plus the SDK, and the live driver route is
   now what a *running* target costs rather than what access costs.
2. ~~**Image-only symbol resolution**~~ — **answered 2026-09-27**: small, and no `dbgscope` change.
   DbgEng opens a PE image as a target of its own and loads its PDB there, so `symbol_offset` and
   `symbol_for` work against `securekernel.exe` with no debuggee and the rebase onto S1's base is
   arithmetic in `src/sksym.rs`. What the answer *cost* is the half the question did not ask about:
   the public PDB carries **no types**, so "symbols and types" is one of the two.
3. **S5's unresolved Secure Kernel *attachment*** — not its activation, which is done, and since
   2026-09-27 not its *transport* either: **S5a settled why SK does not connect to the port, which
   is that it has nothing to connect with.** No debug hypercall, no `vmcall`, no SynDbg MSR, across
   ten builds. So the remaining unknown is narrower and differently shaped — whether a VTL1 stop can
   be driven from the hypervisor or the root *without* guest-side code. **S5b split the
   named candidate for that in two**: a parent can install an exception intercept on a child and has
   no field to aim one at a VTL, which left *whether it covers VTL1 anyway* unresolved. **S5h then
   measured the behaviour and S5i the scope**: with the intercept standing, a `#BP` raised in VTL1
   user mode never reaches the guest's own dispatch and is handed back intact when it comes down,
   and the hypervisor seeds a parent's installed mask into *every* enabled VTL's effective exception
   bitmap. So the unknown is back to one, and it is the one this gate has never had — whether the
   root can **receive** what the intercept produces. **S5j narrowed even that**: the message is
   already delivered to the parent, `winhvr.sys` exports the receiving API, and the open question is
   the key of the table `WinHvSetInterceptRoutine` searches, which decides whether registering
   displaces the entry Hyper-V holds or takes one of its own. **S5k closed that and moved the
   unknown again**: the key is the partition id, Vid holds the entry, and the receiving path already
   exists — Vid is bound and recognises the message, and drops one whose vector is not claimed in
   its own per-vector table. **S5m then read the IOCTL and found it wrapped by an exported
   `vid.dll` call**, and **S5n and S5o between them settled what that is worth on a VM Hyper-V
   runs: nothing.** The sequence needs a partition handle, a second open is refused, the refusal is
   a partition-state test with no token in it, and the branch it guards hands the partition to a
   new owner only after the old one has torn the receive path down. **So the unknown is no longer
   "can the root receive" but "can the root own", and the ordered plan for it lives here, in one
   place, because keeping a schedule in each gate section produced a run of review findings against
   lists a later gate had invalidated:**

   1. ~~**Open a running child's VID partition.**~~ **Run as S5n: refused.** `CreateFileW` on the VID
      device interface path plus the VM Id, `OPEN_EXISTING`, from an elevated process, gives
      `ERROR_BAD_COMMAND` (22) on both running guests, while a well-formed unused name opens — an
      error matching a single-open rule that S5n could not trace to its check.
   2. ~~**Vary the caller upward.**~~ **Answered by S5n's successor without running it — see
      step 3**, which read the check and found it consults no token. The arm — a run as `SYSTEM`
      carrying the unused-name control — was never performed, and performing it now would add
      nothing: `SeTokenIsAdmin` is true for both that account and the elevated one already
      measured, so it reaches the same instruction with the same two fields. Recorded as *not run*
      rather than as *refused*, because those are different readings and only the second would have
      been a measurement.
   3. ~~**Locate the refusing check.**~~ **Run as S5o: located, statically.** `Vid.sys` is a WDF
      driver, which is why no `IRP_MJ_CREATE` dispatcher was findable by name; the callback is
      `VidFileCreate` → `VidFileObjectCreate`, and the refusal is one site (RVA `0x8f6f`) testing
      `[partition+0x3060] == 2` and `[partition+0x3079] == 1`. **This step's cost estimate here was
      wrong** — it said a host reboot into kernel-debug mode, and the answer came from opening the
      image in DbgEng with no target attached. The error S5n matched is now a common cause: on the
      non-Exo arm there is exactly one such site.
   4. ~~**Register `#BP` through `vid.dll` and receive.**~~ **Not reachable by the route S5o
      located, and not merely gated on a handle.** S5o read the branch the refusal guards: it is
      `VidPartitionAttach`, which makes the opener the partition's owning process, and the way in
      that this gate found runs through the current owner's detach IOCTL — which first calls
      `VidHandlerUnregister` and detaches every VP. So on that route the sequence S5m found cannot
      be run *alongside* Hyper-V; the step that would admit us dismantles what we came for. It
      remains the pass condition for a partition **we** own, which is step 6.
   5. ~~**Census the writers of `[p+0x3060]` and `[p+0x3079]`.**~~ **Run as S5p: done, and it
      confirms step 4.** `[p+0x3079]` has **19 accesses and 4 writers**, with no site taking its
      address in one step or two and nothing touching it in the 52 bytes of code outside `.pdata`;
      three writers clear it and **exactly one sets it**,
      `VidPartitionIoctlDetach+0x43`. Since the create path needs `0x3079 == 1` **and**
      `0x3060 == 2`, and the first has exactly one located producer, **every admission this census
      can account for** was enabled by an owner's detach — a claim about located writes, not a
      proof, since the method sees neither an inter-procedural pointer nor a bulk copy. Built
      [`tools/vid_field_census.py`](tools/vid_field_census.py) for it — decoded operands, a `.pdata`
      function walk plus the executable bytes `.pdata` does not claim, an intra-procedural alias
      table for split addresses, `--self-test` 9/9 — because a byte scan cannot do this: it scans
      aligned, it matches immediates, and it cannot see a write through a taken address, of which
      S5p found a real one (`VsmmPhuPartitionTeardown` doing `and dword ptr [rsi],0` after
      `lea rsi,[rcx+3060h]`). **Review then found two holes in the instrument itself** — leaf
      functions absent from `.pdata`, and addresses formed in two steps — and both are closed or
      measured, with neither changing the result. **Residuals**: an inter-procedural pointer, a
      bulk copy spanning the field, and `[p+0x3060]`'s writers being bounded rather than closed.
   6. ~~**The two blocked arms** — the replicated slot read, and whether the hold is a loop.~~
      **BOTH RUN 2026-09-30, in one window, with a control.** The constraint lifted for guests the
      bench owns on 2026-09-29 and S5q's kernel-read IOCTL supplied the rest.
      **The slot read**: `[P+0xB68]` reads `FF FF FF FF FF FF FF FF` at **all twelve** samples
      at every sample across 24 s of a standing intercept, plus before the install and after the
      removal — not "throughout", since sampling cannot see a claim-and-release inside a gap — the
      contemporaneous, **non-mutating** read S5k has wanted since it was written, and which S5m
      could only half-answer because registering *claims* the slot. It narrows S5j's retained
      explanation without closing it: a claimant would have had to claim and release inside one 2 s
      gap and coincide with the raise. **The loop arm ran without answering its question**, and a
      later arm answered it: `handled = 0` shows only that the guest's `__except` never ran, and
      the 20 fresh stamps are twenty calls to `VidInterceptPreprocess` rather than twenty
      executions — but **the hypervisor's own per-VP `Total Messages/sec` supports re-entry over
      re-preprocessing, under the stated assumption** (see *the loop
      question* below): tens of thousands of deliveries a second armed against **zero** in five
      control phases — one of them the vector armed with the raiser absent, the only arm that
      could have shown an unrelated `#BP` source. The rates are **aggregate** and name no vector
      or `RIP`, so they do not bind an individual delivery to the enclave instruction: S5k's
      re-entry inference is **supported**, not proven. **And a
      third reading came free**: per-VP
      `HvRegisterInterceptSuspend` is **transient**, seen on both VPs at different instants and `0`
      at every sample of a control that raised **1.87 million** `#BP`s with no intercept standing,
      while both VPs keep accumulating `VpRuntime`. **The VPs are being resumed**, which removes the
      necessary-condition objection review round 3 on #428 raised against the ping-pong reading —
      and removing an objection to one explanation is not evidence for it over another, so the
      two-VP question stayed open at this arm. **It was answered by the loop question below**,
      which supplied the missing correlation: `Other Intercepts/sec` is zero on both VPs unarmed
      and nonzero on **both** armed, and that counter moves because an instruction trapped on that
      VP. What performs the resumption is still unmeasured. Full record in the **step 6's two blocked
      arms** section of
      [`docs/secure-kernel/secure-kernel-hypercall-feasibility.md`](docs/secure-kernel/secure-kernel-hypercall-feasibility.md).
   7. ~~**Handle duplication and inheritance, which S5n excluded rather than closed and which this
      plan twice wrote out of existence.**~~ **ATTEMPTED 2026-09-30 — the handle is takeable, and
      the first read through it is refused.** S5n's reason for declining does not hold here:
      `vmwp.exe` is **not** protected (0x00, measured against positive controls with a poisoned
      buffer) and `PROCESS_ALL_ACCESS` succeeds from an elevated admin. Each worker holds **four**
      handles to the VID device, and all four duplicate out with an ordinary `DuplicateHandle`. But
      `VidGetHvPartitionId` through all **eight** (four per worker, both reported) returns
      `ERROR_INVALID_FUNCTION` on six and **`ERROR_ACCESS_DENIED`** on two — the same 3-and-1 split
      in each worker independently — against `ERROR_INVALID_HANDLE` for a non-VID control, so they
      reach `Vid.sys` and are turned away. **Not established**: that the route reaches the exported
      receiver, which *this* arm does not test — the receiver arm below does. A draft inferred
      that read-only duplicated access is
      insufficient; **withdrawn — wrong axis, and S5m already said so**: the receiver is IOCTL
      `0x221148` with `FILE_ANY_ACCESS`, and what gates it is *holding a partition handle*, not an
      access mask. Testing it means invoking `VidRegisterExceptionHandler`, and a draft justified
      skipping that with the wrong hazard — the call **refuses** a claimed slot with
      `STATUS_VID_DUPLICATE_HANDLER` before touching the hypervisor rather than displacing anyone;
      the documented hazard is collision with a **raw** `WinHvInstallIntercept` installer, which
      the duplicate check cannot see. So the test is more available than claimed and still a
      decision: an unclaimed slot would be claimed by us on a running VM. **THAT ARM HAS SINCE RUN
      — see the receiver-arm section — and the route is closed from user mode: the IOCTL is issued
      directly for a lossless `NTSTATUS`, and on both workers three handles return
      `STATUS_NOT_IMPLEMENTED` and the fourth `STATUS_ACCESS_DENIED`. Nothing was mutated — the
      poisoned output survived every arm, so no slot was ever claimed. Why it refuses is a limit,
      not a finding: every wider duplicate is refused by `DuplicateHandle` itself, so the driver's
      ownership check and the driver wanting write access predict the same result. LiveCloudKd's
      procedure therefore needs more than duplication, measured.**
      **Inheritance of a VID handle a worker still holds is excluded** on object identity —
      no child holds any of the workers' four current VID file objects. **Not excluded**: one
      inherited and since closed in the parent, which a snapshot cannot see. The children's own
      single `File` object is **unidentified** (duplication refused three ways, sole holder, module
      list unavailable), so that case is unfalsifiable here; closing it needs handle lifetimes
      captured across a child creation, which is a new arm. The same comparison shows the four VID handles are **two** file objects,
      three sharing one and one separate, which maps exactly onto the error split.
      **LiveCloudKd narrowed only as far as the handles**: they exist and are takeable, so its
      procedure is plausible rather than describing an older Windows — any further inference goes
      with the access-bit one, read off our summary of the tool, not its source. Full record, with
      the controls and the near-miss that a name search caused, in the **Step 7** section of
      [`docs/secure-kernel/secure-kernel-hypercall-feasibility.md`](docs/secure-kernel/secure-kernel-hypercall-feasibility.md).
   8. ~~**The fallback S5q's host-bugcheck stop selects, and a decision rather than an arm.**~~
      **COSTED 2026-09-30 — and the costing did not yield the decision.** What it establishes is a
      negative: the documented partition API cannot reach VTL, so the rig rests entirely on the
      undocumented VID surface and private COM contracts. What it does **not** establish is the
      cost — a first draft decided *do not build* on a buffer size read as a field count and a
      module list read as code to be rewritten, and review rejected both. **Two named probes would
      narrow it and neither settles it**, both unrun: a census of `Vid.sys`'s `0x2211A0` handler for
      the fields it validates — one call of about a dozen — and an activation probe on one of the 24
      device-model CLSIDs, which are registered rather than shown to activate. **No call was made**,
      so *no known obstacle* still rests on S5o, S5p and S5n's control of the first step only.
      Figures, decoded gates, the three tiers and both retractions are in the **Step 8** section of
      [`docs/secure-kernel/secure-kernel-hypercall-feasibility.md`](docs/secure-kernel/secure-kernel-hypercall-feasibility.md).
   9. ~~**Measure delivery at the convergence point, which is what S5q's zero could not.**~~
      **RUN 2026-09-30, and the message IS delivered** — feasibility, the read, and the arm, all
      three; the result is below and the reasoning is kept because the next arm (a VTL1 raise) is
      built from it. Added
      2026-09-30 with the correction above. All three known callers of `VidInterceptPreprocess`
      converge on it, and only one of them reads `[partition+0x10]`, so **arrivals counted at
      `VidInterceptPreprocess` itself answer delivery whichever path carried the message** where a
      counter on the chained slot is blind to two of three. **Closes when** a raise under a standing
      raw install is correlated with an arrival there, *with a positive control* — a raise under a
      Vid-installed intercept, which must arrive — and with the backed-out arm interleaved rather
      than run as a clean batch afterwards. A zero on its own repeats arm 0's uninterpretable
      reading. **And it must carry the `[partition+0xB68][3]` read in the same arm**, because an
      arrival count separates *not delivered* from *delivered* and cannot separate the unclaimed-slot
      branch from an enqueue to a pre-existing claimant — the slot is mutable, so a read taken
      afterwards reports afterwards. That read is the one the
      "was the slot claimed?" section has been asking for since S5k; this step is where it belongs
      rather than as an arm of its own. **Ahead of steps 7 and 8 in the order**,
      because it can move the delivery question without owning a partition or taking a handle out of
      a protected process.

      **Feasibility answered 2026-09-30, and it is the third branch: neither a patch nor a
      breakpoint, but a read.** The step asked how the root's `Vid.sys` can be instrumented at all
      and said to cost that first; the answer is that it does not need to be, because
      `VidInterceptPreprocess` **stores what it received before it branches on anything**. Its
      entry block runs straight to `+0x4f` with no branch: it copies the whole `HV_MESSAGE` to
      `[VP+0x30]` and timestamps `[VP+0x208]`, and the type switch then leaves the chosen handler
      at `[VP+0x158]` and its reason index at `[VP+0x200]` — so a delivered `#BP` is four values
      naming each other (`0x80010003`, vector `3` at `[VP+0x68]`,
      `Vid!VidHandleExceptionIntercept`, `2`). The VP is reached from the context S5q step 2
      already reads live — `[P+0xAB0] + VpIndex*0x980`, validated by `[VP+0] == P`, which
      `VidHandleExceptionIntercept` itself relies on — and `[P+0xB68]` hangs off the **same** `P`,
      so *"in the same arm"* costs nothing extra: one request — **not** one instant, since a
      single IOCTL reading several fields is not an atomic snapshot and the claim table is
      writable by any VID client while it runs. Sound because
      `[VP+0x208]` has one writer with this structure's fingerprint and **0 address-taken** sites
      across `Vid.sys`, and because `VidHandleExceptionIntercept` has **exactly one reference in
      the whole image** — the `lea` inside `VidInterceptPreprocess`. That is what is visible in one
      image and **not** a proof that every invocation goes through preprocess; the positive control
      does not close that gap either, since it is delivered by VID's own registration path and so
      says nothing about a raw-installed one. What the instrument reports is *an arrival was or was
      not observed at the convergence point*, and a raw-arm negative is **inconclusive about
      delivery** — the three limits below say the same thing and this sentence used to contradict
      them. Built
      [`tools/pe_xref.py`](tools/pe_xref.py) for that second reading, `--self-test` 26/26 and
      mutation-verified, because a reachability *negative* over an image is the one
      claim a byte scan cannot make: a branch encodes a displacement, not an address, and the
      address appears in immediates that transfer control nowhere. **Cost**: one bounded kernel-read
      IOCTL in `h3probe.sys` and a client script, against a patch route that fits mechanically
      (5-byte first instruction, 10 bytes of padding, `rel32` in range) but buys a **PatchGuard**
      exposure this gate did not measure, and a host-breakpoint route that needs a reboot this bench
      has not configured (`debug` is off) and is read-only when it arrives. The full record, with
      every offset and both censuses, is the **step 9 feasibility** section of
      [`docs/secure-kernel/secure-kernel-hypercall-feasibility.md`](docs/secure-kernel/secure-kernel-hypercall-feasibility.md).

      **Steps 1 and 2 are RUN, 2026-09-30: the read is built and the walk holds at run time.**
      `IOCTL_H3_VIDVP` (`0x80A`) takes a partition **id**, resolves the context through
      `H3ReadPair` under Hyper-V's own lock, refuses unless the registered routine lands inside the
      loaded `Vid.sys`, and reads everything through a canonical-address + `MmIsAddressValid` +
      SEH helper. On both lab partitions: `[V+0] == P` for all four VPs, `[P+0xAA8]` = 2 against
      Hyper-V's own report of **2 vCPUs** per guest, and `[P+0xB68]` reading `FF FF FF FF FF FF FF
      FF` — so **`[P+0xB68][3]` is `0xFF`, unclaimed**, which S5k asked for and nobody had ever
      read. **The strongest reading is a differential**: the live markers reproduce the type switch
      the feasibility gate read out of `Vid+0x3D137`, on two message types and two partitions —
      `0x80000000` → `VsmmHandleMemoryIntercept` / reason `7`, `0x80010000` →
      `VidHandleIoPortIntercept` / reason `5`, both predicted by the `lea`/`mov esi` pairs beside
      the jump table. Bench untouched: nothing written, no intercept installed, driver stopped
      after, host uptime continuous, no bug check, both guests up throughout. One caveat the output
      made plain: `[V+0x68]` is the exception vector **only** for message type `0x80010003` — on
      the IO-port message it read `0x71`, which is payload.

      **THE ARM IS RUN, 2026-09-30, AND THE MESSAGE IS DELIVERED.** A `#BP` raised in the guest
      under a standing raw `HvCallInstallIntercept` (type 3 / `AccessType` 4 / vector `0x03`)
      arrives at `Vid!VidInterceptPreprocess` on **both** VPs of partition `0x3`: `[V+0x30]` =
      `0x80010003`, `[V+0x68]` = `3`, `[V+0x158]` = `Vid+0x11690` `VidHandleExceptionIntercept`,
      `[V+0x200]` = `2` — every marker as the static read of the jump table predicted — with stamps
      **+27,772,140** and **+32,260,001** past baselines taken immediately before the raise. The
      copied message decodes as itself: `Sender` = partition `3`, `VpIndex` `0` on VP 0 and `1` on
      VP 1 (so the message's own view of which processor raised agrees with the slot it was read
      from), `InstructionLength` `1`, `InterceptAccessType` `2`. The raiser was **held** — S5h's
      signature — and the interleaved backed-out arms on **both** sides show no exception markers
      and a raiser that completes. **So S5q arm 1's third explanation, *not delivered because the
      arming sequence is incomplete*, is eliminated, and `forwarded = 0` there was the chained slot
      being bypassed rather than nothing arriving — and that is now ONE run, not an inference across
      two.** A **combined arm** chains the callback, installs the intercept and reads the markers
      and `forwarded` at the same samples: with the chain standing, `forwarded = 0` while both VPs
      read `0x80010003` / vector `3` / `Vid+0x11690` / reason `2` at stamps ~**1.08 × 10⁹** ticks
      past baselines taken *after* chaining. Review round 3 on #427 asked for exactly that rather
      than accepting the cross-run pairing. **Its own first run was vacuous and the driver's guard
      caught it**: while chained the pair Hyper-V holds is *ours*, so the read was refused with
      `OBJECT_TYPE_MISMATCH` — and the client reported "no arrival observed" from the zeroed buffer
      because it never checked the status. The driver now takes the saved pair from its own chain
      record, the client raises on a refusal, and the arm asserts positively that the saved pair was
      used. What is measured is reception **at preprocess**
      and nothing about retention: "held" is produced by *both* branches of
      `VidHandleExceptionIntercept`, so calling this S5j's received-and-retained reading — as an
      earlier version of this paragraph did — reads a branch out of an observation that does not
      distinguish the branches, and contradicts the next paragraph.

      **What the arm did NOT settle.** Which branch `VidHandleExceptionIntercept` took:
      `[P+0xB68][3]` read `0xFF` before the install and `0xFF` after the removal, consistent with
      arm 1 and corroborated by the trap staying held while nothing completed it, but not decided —
      a claim-and-restore between samples reads as unchanged. And the raise was in **VTL0**, as
      S5q arm 1's was; reading the markers for a **VTL1** raise was the cheap next arm rather than
      something this one covered. The Secure Kernel scope limit stands exactly as S5i left it:
      VTL1 user mode is not VTL1 kernel mode.

      **The VTL1 arm is RUN, 2026-09-30, and it reaches VID too — and it settles S5h's fork.**
      `spin_host.exe BP1` raising inside the VBS enclave, same instrument and partition: both VPs
      read `0x80010003` / vector `3` / reason `2`, with the interleaved backed-out VTL1 arms on
      either side reading nothing and completing 2,000 rounds at **7.63** and **7.49 µs** each.
      **The message's `Rip` is the enclave's `int3`** — `0x00000243071E500D`, `0x123` bytes from the
      routine the raiser named in that same run — and an intercept fired on a VTL0 excursion would
      name the VTL0 instruction instead, so the excursion S5h could not dismiss is excluded and the
      trap is taken at the VTL1 raise. **It agrees with S5h across gates**: both arms' message
      `Rip`s match S5h's halted `RIP`s in their low 16 bits (`500D`, `748D`) on a different boot.
      **`ExecutionState` bits 7-10 track the VTL, measured across two vectors**: `0x0097` in VTL1
      and `0x001F` in VTL0 for **both** `#BP` (vector 3) and `#DE` (vector 0), which separates *the
      active VTL* from *something about `#BP` in an enclave* the way one vector could not. A draft
      said that check was not runnable because the hypervisor takes exception intercepts only for
      vectors 3 and 4 — **false**, and review caught it: S5i read a per-partition allowed-vector
      mask at `+0x6124` with an unconditional *exemption* for 3 and 4, and `#BR` already installed
      through the mask. The vector-0 install was then tried and **succeeded**, which adds a vector
      to what this child's mask is known to admit. **And the freeze is now measured.** Reading the guest's progress counter WHILE the intercept stands — the
      side of the release S5h's retracted "advancing" reading got wrong — gives `handled = 0` at
      ten samples over 30 s, against **2,282** the moment teardown releases it, reproducing S5h's
      artefact one line below the correct reading. Interceptions kept arriving throughout: 20 new
      stamps on both VPs at **one** `Rip`, with nothing retiring — twenty calls to
      `VidInterceptPreprocess`, which is not the same as twenty executions of the instruction.
      **Where the
      second VP's events come from was unresolved for two more arms.** Step 6's arms measured the
      guest VPs' run
      state and found `InterceptSuspend` **transient** with both VPs accumulating runtime, so the
      VPs **are** resumed and round 3's necessary-condition objection to migration is removed — but
      nothing correlates the single raising thread with either VP, so that does not choose between
      migration and one pending intercept being re-preprocessed — **and the loop question then
      supplied that correlation**: `Other Intercepts/sec`, the bucket the exception lands in, is
      zero on both VPs unarmed and nonzero on **both** armed, and that counter moves because an
      instruction trapped on that VP. Migration is the supported reading, on the stated
      assumption that nothing else in the guest raises `#BP`. Two drafts got it wrong in
      turn before that: the first
      called the two VPs "consistent with one held raise", which review refused because the raise
      loop is one thread; the second called it that thread ping-ponging between vCPUs, which review
      refused again because migrating needs the VP resumed and `WinHvCompleteIntercept` — the thing
      that resumes an intercepted VP — is exactly what nothing is *observed* calling. Settling it meant
      measuring the delivery mechanism, which is an arm. Nothing else rests on it: delivery, the
      `Rip`, the `ExecutionState` 2×2 and the freeze are each measured independently. The first
      draft also wrote the unarmed loop's **15.3 ms** as "15 s", three orders out.
      Scope unchanged: VTL1 user mode is not Secure Kernel.

      **One defect worth keeping, because it was this plan's own warning landing in this plan's own
      code.** Run 1 reported the arm CONFOUNDED: the second backed-out arm showed an exception
      marker. It was **stale** — that VP had taken the intercept during the armed arm and gone
      idle, so the marker stood with a stamp byte-identical to the previous phase's read. The hit
      test compared type and vector and ignored the timestamp, which is exactly the defect review
      round 3 filed against this plan. The rule now requires a stamp later than that arm's own
      baseline. The interleaved backed-out arm *after* an armed one is the one case that walks into
      staleness, and interleaving is what the plan asked for — the two requirements interact and
      only running them together showed it.

      Bench: intercept installed once per armed arm and removed in the phase after it, teardown
      reporting **0 standing** every time across three unchained runs and two combined ones, raiser
      killed after every arm, driver stopped between rebuilds, guest responsive with 105 processes,
      both guests up **3h26m** unbroken, host uptime continuous, no bug check since boot. Nothing
      written to a partition object; the **combined** arm chained and unchained the callback — which
      arm 0 had already characterised — and its `unchain` returned `SUCCESS` with the saved pair
      restored. Full record in the
      **step 9, the arm** section of
      [`docs/secure-kernel/secure-kernel-hypercall-feasibility.md`](docs/secure-kernel/secure-kernel-hypercall-feasibility.md).

      (The three checks this paragraph used to name as the arm's first act —
      `[VP+0] == P`, a plausible `[P+0xAA8]`, and `[P+0xB68]` pointing at a table of mostly
      `0xFF` — are the ones steps 1–2 ran, and all three passed.) **The arm's shape, settled across three
      review rounds and cheaper than any of them sounded: one IOCTL called three times per raise —
      before, during the hold, and after.** Delivery is `V+0x208` **moving**, never its value,
      because a previous `#BP` on that VP leaves all four markers already reading as a delivery and
      a post-raise sample cannot tell that from a new arrival; the timestamp works as the version
      stamp precisely because preprocess writes it unconditionally and before the type dispatch.
      The third read is a spoiler *filter* on `[P+0xB68][3]`. **Three limits carry into that design
      rather than being retired by it**, and the doc states them once rather than per paragraph,
      because three review rounds landed on one sentence that kept reclaiming coverage. First, the
      read is **last-arrival state, not a count**, so the positive control has to show the markers
      are still there when sampled. Second, that control shows the *instrument* works and **not**
      that a raw-installed delivery shares VID's own route, so a raw-arm negative means *no arrival
      was observed at the convergence point* and not *not delivered*. Third, nothing durable
      records which branch `VidHandleExceptionIntercept` took, and sampling cannot supply it at any
      cadence — a claim-and-restore between two samples reads as unchanged — so **arms 1 and 2 are
      not separable by this instrument at all**, and the remedies that would separate them are
      stabilising the table or instrumenting the handler, which is the patch route this gate
      declined. Delivery itself rests on the VP markers alone and is unaffected by the third.

   **The list above is the *ownership* route, and S5q goes around it rather than continuing it.**
   Every step in it exists because the exported user-mode receiver needs a partition handle.
   `WinHvSetInterceptRoutine` needs none — it is a `winhvr.sys` kernel export keyed by partition id
   — so with the standing constraint lifted for disposable guests the active work is **S5q**, and
   steps 6 to 8 are what matters only if S5q's stop conditions fire. Step 7 stays open on its own
   terms; step 8 was the fallback the host-bugcheck condition selected, and is now **costed
   without a decision**, so that condition selects a route whose cost is still unbounded. **Step 9 went ahead of both
   and is now RUN** — it was put there because arm 1's conclusion was narrowed from *answered
   against* to *open*, and putting the cheapest thing that could move it before the routes needing
   ownership or a duplicated handle is what got the question answered: the message is delivered.
   **What the answer does to this list: nothing yet, deliberately.** Steps 6–8 exist to get the
   root a *receiver it owns*, and delivery being established does not supply one — it removes the
   possibility that there was nothing to receive. Whether that changes the case for owning a
   partition depends on the next arm (a VTL1 raise) rather than on this one, so the order below is
   left as it stands rather than rewritten on a result it does not turn on. **This is the second time
   this plan has kept walking a route after a cheaper one opened beside it** — S5m already deleted
   the driver S5k specified — and the cause both times was a schedule written against the obstacle
   in front of it rather than against the question. **This correction is a third instance of the same
   cause**, caught by re-reading rather than by an arm: the conclusion was written against the
   instrument in front of it rather than against every path into the receiver.

   The other candidate was **answered by S5c**: the
   suspend register is writable from
   the parent and halts the VP, VTL1 state is readable across the halt, and the halt is VP-wide
   rather than VTL-selective — so it buys a live *inspector* and not the stop S5 asks for. Still
   decides inspector
   versus debugger, and still the one that would change the shape of S3's tool surface rather than
   its contents. **That surface now exists**, so the change is to something built rather than to a
   design: a capture session is a fixed snapshot whose whole decode travels with the open, and
   execution state would make it neither. Independent of the rest, so it can run in parallel or not
   at all.
4. **Build stability of the offsets, and the derivation that replaces them.** **Half-answered
   2026-09-27 by S2**: the PDB derives both offsets per build and agrees with the scan on this one,
   and it reaches `SkLoadedModuleList` directly where the scan cannot. What is *not* answered is the
   no-symbols case, which is the one the recipe below is for — a host with no symbol store, or a
   build whose PDB is not served, still has only the tag scan. So both routes stay, and the scan is
   still the primary rather than the fallback.

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

## 104. [windbg-mcp] A fingerprint field that was *refused* is indistinguishable from one that does not apply

**Repo:** `windbg-mcp`. **Origin:** raised by Codex on
[#392](https://github.com/glslang/windbg-mcp/pull/392) while item 102 was in review, and reached
independently by CodeRabbit on the same PR two rounds later, against a hazard item 81 introduced
and item 102 made more expensive. Two readings converging on one remedy is the part worth keeping:
neither priced it, and pricing it is what this entry is.

`worker::TargetFingerprint::read` builds its four fields with `.ok()`, so every query's **error**
becomes `None` — the same value a field takes when the question does not apply to that kind of
target. `connection` is `None` on every non-kernel target because `GetKernelConnectionOptions`
*refuses* there, and `processes` is `None` on every kernel target because the gate never asks. The
comparison then treats `None == None` as agreement, which is two different claims sharing a
spelling: *"neither reading has one of these"* and *"neither reading could get one"*.

Two consequences, and they point in opposite directions:

- **Two failures compare equal.** A query that fails at the baseline *and* again afterwards leaves
  the two readings agreeing on that field, so a swap only that field would have caught goes
  unseen — two dumps of one process if `dump_files` is the one failing, two live kernels if it is
  `kernel_connection_options`. For a *handle* that costs a stale handle; since item 102 it also
  costs a `debug_batch` rollback written into the replacement, which is the whole hazard that item
  was filed for.
- **A recovery reads as a replacement.** A field that starts failing and then answers makes the
  readings differ with nothing having happened to the target: the handle is retired and, since
  item 102, the batch's cleanup is withheld and a replacement it cannot see is reported.

- **Why deferred:** the obvious fix is not available, and the available one is a change to a type
  both halves of the mechanism share. **The error cannot be read to tell the two apart**: DbgEng
  answers `E_UNEXPECTED` both for a question that does not apply to this target and for one asked
  at the wrong time — dbgscope measures the second on `GetNumberProcesses` with no debuggee and on
  `WaitForEvent` after an ending, and the first is what `GetKernelConnectionOptions` gives on every
  user-mode target. So separating them needs a **per-target-kind table of which fields are
  required**, and that is the claim `TargetFingerprint`'s own doc records as having been wrong
  three review rounds running — which is why that doc states *what is covered* rather than what
  the gaps are. It also needs a decision **per caller**, as the readings already do: a handle
  over-matches on purpose (a wrong retirement costs one re-open) while a batch withholds (a wrong
  restore costs whatever that address means in somebody else's target), so one answer will not do
  for both.
- **What is already closed, and it is the cheap half.** A batch will not start against a reading
  whose `kind` is missing (`worker::usable_baseline`), because that field decides which of the
  others are even asked for — so a reading without it has a *shape* chosen by a guess, and the
  next reading differs because the guess changed rather than because the target did. That is one
  field and needs no table; the rest of this entry is the fields whose absence is legitimate.

  **And the *selection* is closed outright, which is the worked example of what this asks for.**
  A batch measures the current process beside the fingerprint (`worker::BatchTarget`), and that
  field had the same `.ok()` and the same double meaning until Codex raised it on
  [#392](https://github.com/glslang/windbg-mcp/pull/392) as well. It is now `worker::Selection`,
  three-valued — `NotAsked` / `Process` / `Refused` — so a refused reading is not a process and
  not an agreement with the next refusal: `usable_baseline` will not start a batch against one and
  `BatchTarget::moved` answers `Held::Uncertain` when one arrives mid-batch, with a sentence saying
  the engine would not say rather than claiming the selection moved. **What made that one closable
  is exactly what the four below are missing**: whether it applies is a *gate in the code*
  (`fingerprints_the_process`, on the target's kind) rather than an inference from an error, and
  the refusal is narrowed by a second rule that costs nothing — a session holding one process has
  nowhere for the selection to be, so a write lands there or fails and the refusal is accepted.
  Neither trick is available inside `TargetFingerprint`, which is why this entry stands.
- **What would close it:** a reading that records, per field, whether the query was *not asked*,
  *answered*, or *refused* — the first two from the gates that already exist
  (`fingerprints_the_process`, and a second one for the connection query, which is the one that
  needs the per-kind judgement) — and a comparison in which a `refused` on either side answers
  *cannot tell* rather than *same*. `batch::Held::Uncertain` is already that answer on the batch
  side and already withholds cleanup.

  **Most of it needs no table, and that is the part to build first.** `kind` and `dumps` are asked
  of every target and `processes` is asked behind a gate that already exists, so a baseline that
  *refused* any of those three can be rejected without deciding anything per kind — which closes
  the double-failure for a swapped dump and for a `.attach`, and leaves only `connection`, whose
  absence is legitimate on every target but a live kernel. And a field whose **readability flips**
  between the two readings can answer *cannot tell* for any of the four, table or no table.

  **The handle's half is what makes it a redesign rather than a patch.** `Held::Uncertain` would
  have to say *why*: a flip is the case `worker::replacement` retires on today (a field that stops
  answering has changed what the engine says), while an unreadable `has_target` is the case it
  deliberately does **not** retire on — so one value cannot serve both, and the variant needs a
  reason the two callers can read differently.
- **Where it picks up:** `TargetFingerprint`, `TargetFingerprint::read`, `replacement` and
  `usable_baseline` in `src/worker.rs`; `batch::Held` and `Debuggee::replaced` in `src/batch.rs`
  for the batch's half of the decision. The measurement to take first is whether any of the three
  always-required queries can actually fail on an engine that answers `GetExecutionStatus` — none
  of this is reachable if they cannot, and nothing here has been able to make one do it.

## 105. [windbg-mcp] `.opendump` is documented as replacing the target, and the one measurement of it says it adds one

**Repo:** `windbg-mcp`. **Origin:** two prose sites raised by CodeRabbit on
[#392](https://github.com/glslang/windbg-mcp/pull/392) after it merged, and fixed there. The wider
version is this repo contradicting itself: item 102 measured the command it had used as its own
example of a replacement and found it is not one — driven live over stdio against the dev build
(dbgeng 10.0.26100.1742, ARM64, 2026-09-26), `.if (1) { .opendump C:\other.dmp }` on a dump session
left `||` listing **two systems** with the original still current, and `? @$ip`, `version` and `lm`
all still answering from it. That reading is recorded in `DONE.md`; the *claim* it contradicts is
still in about a dozen places, including the sentence this server's whole shape is introduced with
(`docs/architecture.md`'s opening and `src/engine.rs`'s module doc): *"dbgeng.dll holds one
debuggee session per process … which is why `.opendump` **replaces** the target rather than opening
a second one"*.

- **Why deferred:** one command, one target kind, one engine build, and a rewrite of that sentence
  would trade a claim that is wrong on one kind for one that is unmeasured on three. What it wants
  first is the matrix: `.opendump` on a **dump** session (measured: adds a system), on a **live
  user-mode** target, on a **live kernel** one, and `.opendump` of the *same* file; and then which
  command actually switches, which this server has never observed at all — `||1s` through
  `ExecuteWide` failed here with `0x80040205`, so "the switch is what replaces a target" is
  currently an inference rather than a reading.
- **What does not change whatever the matrix says, and is worth writing down before anyone starts.**
  `server::changes_debug_target` keeps `.opendump` on its list and `batch::retires_handle` keeps
  pre-retiring for it: over-matching there costs a caller one re-open, the scan cannot see a
  wrapper anyway, and since item 81 the *actual* retirement is decided by comparing what the engine
  holds rather than by the command's name. The batch's own reading is likewise unaffected — it
  compares holdings, so a `.opendump` that adds a system and leaves the current one alone correctly
  reads as **nothing changed**, which is what the live run showed. So this is a documentation
  defect with a measurement behind it, not a behaviour one.
- **Where it picks up:** `docs/architecture.md`'s opening paragraph and `src/engine.rs`'s module
  doc, which state it as the reason for one worker per session; `docs/sessions.md` (three places),
  `docs/tool-surface.md`, `src/server.rs`'s `changes_debug_target` and `src/proto.rs`'s op
  commentary, which use it as the canonical example. The measurement needs the debugger tier plus a
  live kernel target (`.claude/skills/live-kernel/SKILL.md`), and it should be taken on a build
  named in the write-up, since this is a per-engine-version answer.

## 106. [windbg-mcp] A tool group every caller pays for and few can use

**Repo:** `windbg-mcp`. **Origin:** item 103's gate S3, 2026-09-27 — raised by the change that
created the cost rather than by a reviewer, because the arithmetic is unarguable and the remedy is
not.

**The four `securekernel` tools are 7,501 B of model-visible surface** (`open_sk_capture` 3,918,
`sk_symbol` 1,466, `sk_read_memory` 1,277, `sk_modules` 840, measured 2026-09-27 against a
103,293 B surface), and they are paid **once per conversation by every caller**, because the default
surface is every tool. What they need to be usable is a Hyper-V standard checkpoint of a VBS guest,
the Windows SDK's saved-state provider, and the `securekernel.exe` that guest was running. Almost
nobody driving a crash dump has any of the three.

`--tools` is the lever that exists for exactly this, and its shape is the problem: it is opt-**out**,
so a caller who wants no capture tools has to name every group it *does* want, and the default a
client gets when it says nothing is the widest one. That was the right default while every group was
something most callers might reach for; a research capability behind a three-part setup is the first
group for which it is not.

**What *not* to do, and it is the obvious thing.** Dropping the group from the default surface makes
`--tools` mean two things — a selection, and an exception list — and breaks the property
`mcp_smoke::every_tool_belongs_to_exactly_one_group` exists for: that the groups **add up** to the
surface, in both directions, so a tool added and forgotten is still served. A surface where some
groups are in the default and some are not needs that test rewritten around a second concept, and it
needs a story for the client that asks for `all`.

**Three shapes worth weighing, and the measurement to take first.**

- **An `extra` marker on a group**, so the default is *every group that is not marked*, and `all`
  means all. Smallest change, one new concept, and the join test becomes "the marked groups plus the
  default ones are the surface".
- **A spec that subtracts** (`--tools all,-securekernel`). No change to what a group is, and it
  leaves the default surface as it is — which is the thing being complained about, so it helps the
  operator who already knows and nobody else.
- **Nothing, and say so in the docs.** Still on the table, and it does not need the measurement
  below: 7.3% of the surface is not obviously noise, but the surface is 26k tokens against context
  windows that are now much larger than they were when item 24 measured it — and *that* comparison is
  one nobody here has re-taken, needs no model and no bench, and would settle whether this item is
  about anything at all.

**The measurement that would settle it is not available here, and saying which of two reasons that
is matters.** The question is whether a model served the wider surface is measurably worse at the
tasks it *is* for — `tools/local_model_eval.py` is the only thing in this repo that can answer it
(`.claude/skills/eval-bench`). Two things stand between the item and that answer:

- **The grid has no arm for this question.** Its surfaces are `full`, `lean`
  (`session,inspect,crash`) and `min` (`crash`), narrowed **toward** `crash` — so what it measures is
  what a *small* surface costs, and three of its six tasks cannot be answered on the 11-tool one at
  all. This item asks the opposite: what the extra 7,529 B on the **full** surface costs. That needs a
  new arm — every tool *except* `securekernel` — which is a plan change and a fourth credential rather
  than a run. An earlier draft of this item said "the grid already varies the surface", which is true
  and beside the point.
- **And the model side is not on this bench.** The ollama arms need the weights somewhere with the
  compute for them, which for this project is a **Mac**, with the listener here behind an ssh forward
  (`docs/local-model.md`'s second row — the arrangement every published figure came from). The
  checked-in plan says so itself rather than this paragraph asserting it: all three models on its
  **ollama** rows are `-mlx` builds, and MLX runs on Apple silicon. (Its third row is
  `backend: claude-code`, which is hosted and names no local weights — so the constraint is on the
  ollama arms, which are the ones this question needs.) The Windows debugging
  host has no compute for local models at all, so *row one of that table is not an option here*,
  whatever the product supports. A grid run is hours, so this is a two-machine arrangement to
  schedule rather than an afternoon.

**So the honest status is blocked, and deciding it without the measurement is a legitimate outcome
rather than a lesser one.** The case for an `extra` marker does not rest on the eval: the setup this
group needs is three-part (a checkpoint, the SDK, a VBS guest), which is a stronger statement about
the audience than any accuracy delta would be, and the cost is arithmetic that is already taken. What
the eval would add is the *size* of the harm, which decides how much machinery the remedy is worth —
so if it runs, run it **after** deciding the shape, to price the change rather than to authorise it.

**Where it picks up:** `GROUPS` and `Toolset::parse` in `src/toolset.rs`, the join test in
`tests/mcp_smoke.rs`, `docs/tool-surface.md`'s table, and the two ceilings in `tests/mcp_smoke.rs`
whose doc comments record what each raise bought. If the eval arm is ever added it is a surface in
`tools/eval_plan.json` plus a credential in whatever `EVAL_TOKENS` names — and note that plan's
`"tools": 51` label for `full`, which was the count when it was written and is 67 now: the records
carry the served surface, so the label is a reader's hint rather than a measurement, and a new arm is
the moment to re-derive it.

## 107. [windbg-mcp] A misspelt tool argument is silently ignored, and the call answers `status: ok`

**Repo:** `windbg-mcp`. **Origin:** hit live, 2026-09-29, during item 103's S5o gate. Three
`disassemble` calls passed `target` — which is not a parameter; the parameter is `address` — and
each was served as though it had asked for nothing: `address` deserialised to `None`, the tool
disassembled at the current instruction pointer, and the result came back `"status": "ok"` with a
`start` that was the image entry point. It read as a tool defect for several minutes, and the gate
fell back to `execute` + `uf` to get the disassembly it wanted — which is the text hatch this repo
tries not to reach for.

**The failure shape is the one this repo has already written down, in `src/batch.rs`:** *"Serde
ignores unknown fields by default, which is the wrong default for a step: a misspelt `expect` is a
step that asserts nothing while reading as though it asserts, and it fails open."* A misspelt
`address` is a call that disassembles somewhere else while reading as though it disassembled where
asked, and it fails open the same way. **So this is an unfinished class fix rather than a new
idea** — `#[serde(deny_unknown_fields)]` is already the convention here and reaches **3 of the 52**
`*Args` structs in `src/server.rs` (`BreakpointArgs`, `ClearBreakpointsArgs`, `DebugBatchArgs`).

**The MCP spec neither requires nor forbids rejecting unknown arguments, and that shapes the fix
rather than excusing it.** The 2025-06-18 tools page makes servers responsible — *"Servers MUST:
Validate all tool inputs"* — and lists *"Invalid arguments"* among the protocol errors carrying
JSON-RPC `-32602`. What it does not say is that a property absent from `inputSchema` is invalid,
and **JSON Schema's default is that it is not**: without `additionalProperties: false`, an extra
key conforms. So a client sending `target` is, today, sending something our own published contract
calls valid, and rejecting it while advertising otherwise would be the server breaking its own
schema.

**Which makes the remedy two halves that must land together**, and is the reason this is an item
rather than a one-line patch:

1. `#[serde(deny_unknown_fields)]` on the remaining `*Args` structs, so the argument is refused
   rather than dropped; and
2. the published `inputSchema` carrying `additionalProperties: false` to match, so a client can see
   the constraint before it violates it. `schemars` emits that from the same attribute, so the two
   halves are one change per struct — but **verify it reaches the served schema**, since
   `src/schema.rs` walks and rewrites schemas for per-client surfaces and treats
   `additionalProperties` as a subschema keyword (`SUBSCHEMA`), with a boolean form handled
   specially at `schema.rs:293`.

**Two things to check before doing it wholesale.** `deny_unknown_fields` and `#[serde(flatten)]`
are mutually exclusive, which is exactly why `batch.rs` collects leftovers by hand instead — so any
args struct that flattens needs the `batch.rs` treatment rather than the attribute. And the
per-client surface work means a tool's schema is not always served verbatim; a test that asserts
the refusal should drive it through the served surface, not the struct, or it pins the wrong thing.

**Worth a regression test of the shape this repo prefers**: not "an unknown field is refused" on
one struct, but a test that enumerates the `*Args` types and asserts the property holds for each,
so the next tool added cannot quietly opt out. The three that already carry it would pass today and
the other 49 would not, which is the point.

## 108. [windbg-mcp] The driver tools assume a WDM dispatch table, and every in-box Hyper-V driver is KMDF

**Repo:** `windbg-mcp`. **Origin:** item 103's S5o gate, 2026-09-29, where it cost a gate's worth of
detour and produced a wrong sentence in a checked-in document before review caught it.

**What the tools assume.** `driver_object`, `ioctl_map`, `reachable_from_dispatch`,
`driver_surface` and the `MajorFunction[0x0e]` recipes in `skills/windbg-debugging/driver-ioctl.md`
and `.claude/skills/live-kernel/SKILL.md` all read a driver's dispatch out of
`DRIVER_OBJECT->MajorFunction` and expect the entries to name routines **in that driver**. For a
WDM driver they do. For a KMDF driver they do not, and the tools do not say so.

**Measured on this bench, from the images themselves** (`Wdf01000.sys 1.35.26100.3323`,
`Vid.sys 10.0.26100.9278`, both opened as PE targets with public PDBs):
`Wdf01000!FxDriver::Initialize` runs a loop over `0` through `0x1B` — 28 entries,
`IRP_MJ_MAXIMUM_FUNCTION_CODE + 1` — writing `Wdf01000!FxDevice::Dispatch` or
`FxDevice::DispatchWithLock` into every slot, chosen per device by `FxDevice::_RequiresRemLock`.
So **all 28 entries point into `Wdf01000.sys`**, none into the client driver, and the driver's own
handlers are callbacks the framework holds: an `IRP_MJ_CREATE` travels `FxDevice::Dispatch` →
`FxPkgGeneral::OnCreate` → the driver's file-object create callback, and device control reaches an
I/O queue's `EvtIoDeviceControl` rather than a dispatch routine.

**What that costs today.** `driver_object` on a KMDF driver reports 28 identical framework pointers
and looks like a driver that dispatches nothing of its own; `ioctl_map` and
`reachable_from_dispatch` start from an entry that is not the driver's code and find no IOCTL
switch, because there is not one to find — the codes are compared inside the queue callback the
framework calls. None of that is *wrong* as a reading of the table; it is the tools answering a
question the caller did not mean to ask, which is the same failure mode as item 107.

**Why it matters here rather than in general.** The secure-kernel line of work reads in-box Hyper-V
components, and they are KMDF: `Vid.sys` is the one measured, and `DriverEntry` → `FxDriverEntry`
→ `WdfVersionBind` is the tell that costs nothing to check. S5n spent an arm looking for an
`IRP_MJ_CREATE` dispatcher by symbol name and concluded none existed, which was right about the
symbol and wrong about the cause; S5o then shipped *"there is no `MajorFunction` table to read"*,
which is wrong outright, and both bots caught it.

**Sketch of the fix, cheapest first, and the first is most of the value.**

1. **Recognise the case and say so.** A driver importing `WdfVersionBind`, or carrying a
   `WdfBindInfo`, is KMDF. `driver_object` reporting that — and that its `MajorFunction` entries
   belong to the framework — turns a silently useless answer into a true one, and is a field on an
   existing result rather than new machinery.
2. **Resolve the real callbacks.** The framework's per-device config holds them; the create/close/
   cleanup trio comes from the file-object config, device control from the I/O queue's. This is
   structure-walking against `Wdf01000.sys`'s public types and is the part that wants a measured
   layout per framework version rather than a constant — `Wdf01000.sys` carries its own version
   line (1.35 here) independent of the OS build, which is the trap to design around.
3. **UMDF is a different image again** (`WUDFx02000.dll`, user mode) and is out of scope until
   something needs it. Say so rather than implying coverage.

**Do not start with step 2.** The layout work is the expensive half and buys nothing until a caller
knows they are looking at a KMDF driver, which step 1 tells them — and step 1 would have prevented
both wrong sentences above on its own.

## 109. [windbg-mcp] The server can walk a call graph forward and find calls to imports, and cannot answer "who calls this address"

**Origin:** gate S5q arm 1 needed the callers of one internal function in `securekernel.exe` and had
to hand-roll it in Python, then hand-roll it a second time for `winhvr.sys`
([`tools/winhv_partition_readers.py`](tools/winhv_partition_readers.py)). Both are analyses this
server is otherwise well placed to do, and neither is Secure Kernel-specific: *who calls this
internal helper* is a constant question in the IOCTL work the driver tools exist for.

**What exists, and the shape of the gap.** `reachable_from_dispatch` walks **forward** from a known
root — is this block reachable from the dispatch routine — over a bounded breadth-first call graph.
`driver_hazards` finds call sites **to imports**, by IAT slot, with decoded instructions, bounded
output and explicit accounting for windows it could not read. Neither answers the reverse question
about an **internal** address, which is the one you have when a symbol is absent, a PDB is public
and typeless, or the interesting thing is a callback slot rather than a named routine.

**A tool would be `xrefs_to <address>`**, reporting call and jump sites with module and RVA beside
each, and it should be built on `hazards.rs`'s scan rather than beside it: the bounded section walk,
the decoded-instruction loop, the unreadable-window accounting and the cap-with-exact-count pattern
are all there and are the parts that took the review rounds to get right.

**Two things to get right that the ad-hoc versions did not.**

- **Decode, do not pattern-match.** S5q's Python matched `E8`/`E9` displacements over raw bytes,
  computing for each offset whether `i + 5 + rel32` hit the target. That is cheap and **unsound**: a
  coincidental `0xE8` inside another instruction's immediate, or inside data, matches exactly as
  well. It was adequate as a *lead generator* because both hits were then verified by disassembling
  them, and it is not adequate as a tool. The house style is already right — `hazards.rs` decodes,
  and `reachable_from_dispatch` parsing `uf` **text** is the habit not to extend
  (`.claude/rules/tool-surface.md`, and the standing lesson about reading a disassembler's prose).
- **Answering for an address is not answering for an object.** The winhvr census had to filter by
  *provenance of the base pointer* before a field offset meant anything, because `+0x10` alone had
  365 accesses in one image. A call-site tool does not have that problem — a call target is
  unambiguous — but any sibling that censuses a **field** does, and shipping the second without the
  first would repeat S5p's review rounds.

**Why it is worth doing beyond this gate:** it works with **no debuggee** against an image target,
so `securekernel.exe`, `winhvr.sys`, `Vid.sys` and any driver answer offline — which is the mode
most of item 103's static work has actually run in.
