# Follow-ups

Deferred work on this server and on [`dbgscope`](https://github.com/glslang/dbgscope), one entry per
item. **The [index](#index) below is the way in**, and each entry then says which repo it belongs to,
why it was deferred, and where it picks up. See [`DECISIONS.md`](./DECISIONS.md) for the design
rationale (D1–D5) that items 2, 3, 5 and 6 extend.

**What each item came out of is [at the end](#where-these-items-came-from) rather than here.** That
record is worth keeping — it is where the shape of a cluster lives, and which measurement produced
which item — but most of what it narrates has since closed, so a reader who opens this file to find
open work would meet several pages about items that are no longer in it.

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
deleted, renumbered, or moved without reaching the other file's index fails the build rather than a
reader. It holds **both** indexes to the same rule — every entry in this file is named by the index
below, at an anchor that resolves, and so is every entry in `DONE.md`.

Two kinds of item stay here rather than moving. One that is **declined**: what it proposed did
not land, and the entry records what settled that and the condition that would reopen it. And one
that has **half** landed, whose entry is narrowed to the half that is left rather than split
across two files. **Which items those are is on their index lines
below**, and is not enumerated here as well: `DONE.md` kept a second copy of both lists and had
drifted three items behind this one by the time the index was written.

Three of them carry something a marker cannot. Item 35 leaves a judgement call open. Item 100
answers its own question against itself — the walk it was filed about turns out to be right, and
what the run found instead went into item 98, now in [`DONE.md`](./DONE.md). And item 108's
first step landed on 2026-10-02, so its entry now carries what that step measured, what step 2
should start from, and the three claims of its own that measurement did not support.

Items are roughly ordered by how soon they're worth doing, within each cluster.

## Index

Every entry in this file, in the order it appears. A line carries a status only where the
entry's own title does not: **half landed** (the rest of it is still open) and **declined**
(it was decided against, and the entry holds what settled that and the condition that would
reopen it). An unmarked line is simply open.

- [Item 2](#2-dbgscope-typed-write-primitives) — [dbgscope] Typed write primitives — **half landed**
- [Item 3](#3-windbg-mcp--dbgscope-state-injection-confirmation-path-decisionsmd-d4) — [windbg-mcp + dbgscope] State-injection confirmation path (DECISIONS.md D4)
- [Item 5](#5-windbg-mcp-path-recipe-decode-limits-heuristic-boundary) — [windbg-mcp] Path-recipe decode limits (heuristic boundary)
- [Item 6](#6-windbg-mcp-concolicsymbolic-buffer-synthesis-decisionsmd-d2--declined-2026-07-04) — [windbg-mcp] Concolic/symbolic buffer synthesis (DECISIONS.md D2) — **declined** (2026-07-04)
- [Item 8](#8-windbg-mcp-tasks-extension-iomodelcontextprotocoltasks-sep-2663--declined-2026-09-19) — [windbg-mcp] Tasks extension (`io.modelcontextprotocol/tasks`, SEP-2663) — **declined** (2026-09-19)
- [Item 9](#9-dbgscope--windbg-mcp-incremental-output-from-a-running-command) — [dbgscope + windbg-mcp] Incremental output from a running command
- [Item 11](#11-windbg-mcp-mcp-apps-ui-resources--declined-2026-07-29) — [windbg-mcp] MCP Apps (`ui://` resources) — **declined** (2026-07-29)
- [Item 15](#15-windbg-mcp-make-handle-inheritance-a-property-of-the-spawn-not-of-the-process) — [windbg-mcp] Make handle inheritance a property of the spawn, not of the process
- [Item 19](#19-windbg-mcp-let-a-debug_batch-step-walk-a-structure--declined-2026-10-13) — [windbg-mcp] Let a `debug_batch` step walk a structure — **declined** (2026-10-13)
- [Item 27](#27-windbg-mcp--dbgscope-a-deferred-module-reports-no-pdb-identity--declined-2026-08-20) — [windbg-mcp + dbgscope] A deferred module reports no PDB identity — **declined** (2026-08-20)
- [Item 33](#33-windbg-mcp-the-lease-grace-assumes-the-server-is-the-slow-party) — [windbg-mcp] The lease grace assumes the server is the slow party
- [Item 35](#35-windbg-mcp--dbgscope-the-engines-subregister-flag-misses-the-views-that-matter--declined-2026-08-22) — [windbg-mcp + dbgscope] The engine's subregister flag misses the views that matter — **declined** (2026-08-22)
- [Item 50](#50-windbg-mcp-the-released-binary-is-unsigned--only-the-certificate-is-left) — [windbg-mcp] The released binary is unsigned — only the certificate is left — **half landed**
- [Item 53](#53-windbg-mcp-a-break-raised-after-a-runs-stop-is-built-labels-the-result-cut-short) — [windbg-mcp] A break raised *after* a run's stop is built labels the result cut short
- [Item 56](#56-windbg-mcp-resolves--expr-is-a-callers-command-on-nobodys-clock) — [windbg-mcp] `resolve`'s `? <expr>` is a caller's command on nobody's clock
- [Item 59](#59-dbgscope--windbg-mcp-nothing-can-ask-which-thread-the-engine-has-selected) — [dbgscope + windbg-mcp] Nothing can ask which thread the engine has selected
- [Item 61](#61-windbg-mcp-attribute-the-cve-2026-83498-fix-independently-of-similarity-scores) — [windbg-mcp] Attribute the CVE-2026-83498 fix independently of similarity scores
- [Item 62](#62-windbg-mcp--binja-windbg-mcp-capture-a-live-securekernel-handoff) — [windbg-mcp + binja-windbg-mcp] Capture a live securekernel handoff
- [Item 64](#64-binary-ninja-upstream-verify-the-firstsetupdialog-shutdown-fix) — [Binary Ninja upstream] Verify the FirstSetupDialog shutdown fix
- [Item 65](#65-binja-windbg-mcp-native-ultimate-validation--declined-2026-09-12) — [binja-windbg-mcp] Native Ultimate validation — **declined** (2026-09-12)
- [Item 68](#68-windbg-mcp-whether-a-device-can-have-no-security-descriptor-at-all) — [windbg-mcp] Whether a device can have no security descriptor at all
- [Item 71](#71-windbg-mcp-driver_surface-does-not-say-which-control-code-reaches-which-sink) — [windbg-mcp] `driver_surface` does not say which control code reaches which sink
- [Item 72](#72-windbg-mcp-the-driver-tools-name-a-module-refresh-they-could-run-themselves) — [windbg-mcp] The driver tools name a module refresh they could run themselves
- [Item 74](#74-windbg-mcp-the-driver-tools-report-no-pool-tags) — [windbg-mcp] The driver tools report no pool tags
- [Item 87](#87-windbg-mcp-a-code-materialised-in-the-previous-block-is-lost-at-the-join) — [windbg-mcp] A code materialised in the previous block is lost at the join
- [Item 91](#91-windbg-mcp-a-refusal-that-returns-through-a-shared-epilogue-is-not-recognised) — [windbg-mcp] A refusal that returns through a shared epilogue is not recognised
- [Item 88](#88-windbg-mcp-a-call-that-outlives-its-budget-finishes-its-work-and-has-the-answer-discarded) — [windbg-mcp] A call that outlives its budget finishes its work and has the answer discarded
- [Item 94](#94-windbg-mcp-disabling-a-breakpoint-has-no-typed-tool) — [windbg-mcp] Disabling a breakpoint has no typed tool
- [Item 97](#97-dbgscope-an-lfh-block-awaiting-a-delayed-free-is-reported-allocated) — [dbgscope] An LFH block awaiting a delayed free is reported allocated
- [Item 100](#100-dbgscope-the-vs-chunk-chain-comes-apart-on-29671--the-targets-paging-not-the-build) — [dbgscope] The VS chunk chain comes apart on 29671 — the target's paging, not the build — **declined** (2026-09-24)
- [Item 104](#104-windbg-mcp-a-fingerprint-field-that-was-refused-is-indistinguishable-from-one-that-does-not-apply) — [windbg-mcp] A fingerprint field that was *refused* is indistinguishable from one that does not apply
- [Item 108](#108-windbg-mcp-a-kmdf-drivers-real-callbacks--step-1-landed-the-frameworks-per-device-config-is-what-is-left) — [windbg-mcp] A KMDF driver's real callbacks — step 1 landed, the framework's per-device config is what is left — **half landed**
- [Item 113](#113-windbg-mcp-the-device-descriptor-sweeps-own-figures-do-not-add-up) — [windbg-mcp] The `\Device` descriptor sweep's own figures do not add up
- [Item 114](#114-dbgscope-a-big-pool-entry-in-no-region-the-walk-discovers) — [dbgscope] A big-pool entry in no region the walk discovers
- [Item 117](#117-windbg-mcp-the-kd-facade-pipe-has-only-the-default-acl-no-client-authentication-and-no-break-in) — [windbg-mcp] The KD facade pipe has only the default ACL, no client authentication and no break-in
- [Item 121](#121-windbg-mcp-tracing-pool-allocations-on-an-x86-kernel) — [windbg-mcp] Tracing pool allocations on an x86 kernel — **half landed** (the x86 reader, measured in user mode, 2026-10-13; a trace on a live x86 kernel is what is left)
- [Item 122](#122-windbg-mcp-a-live-secure-kernel-session-has-no-image-to-resolve-names-or-instructions-against) — [windbg-mcp] A live Secure Kernel session has no image to resolve names or instructions against
- [Item 125](#125-windbg-mcp--dbgscope-an-interrupted-replay-is-left-where-ttd-puts-it-not-where-it-had-got-to) — [windbg-mcp + dbgscope] An interrupted replay is left where TTD puts it, not where it had got to
- [Item 127](#127-windbg-mcp-the-code-scans-decode-by-the-stops-effective-machine-not-the-images) — [windbg-mcp] The code scans decode by the stop's effective machine, not the image's
- [Item 128](#128-windbg-mcp-the-ttd-tier-records-whichever-hostname-the-shells-path-resolves) — [windbg-mcp] The TTD tier records whichever hostname the shell's PATH resolves
- [Item 129](#129-windbg-mcp-the-live-secure-kernel-tier-takes-a-boots-coordinates-from-a-private-prep-the-kd-gate-discovers-for-itself) — [windbg-mcp] The live Secure Kernel tier takes a boot's coordinates from a private prep the KD gate discovers for itself
- [Item 130](#130-windbg-mcp-a-transcript-cannot-be-joined-to-the-clients-opentelemetry-trace) — [windbg-mcp] A transcript cannot be joined to the client's OpenTelemetry trace
- [Item 131](#131-windbg-mcp-the-eval-never-runs-a-mutating-tool) — [windbg-mcp] The eval never runs a mutating tool
- [Item 132](#132-windbg-mcp-no-scenario-has-outgrown-a-models-own-window) — [windbg-mcp] No scenario has outgrown a model's own window
- [Item 133](#133-windbg-mcp-the-live-vtl1-driver-and-its-providers-live-outside-this-repository) — [windbg-mcp] The live VTL1 driver and its providers live outside this repository
- [Item 134](#134-windbg-mcp-the-transition-drain-faults-on-an-unattributed-ntdlldbgbreakpoint-stop-in-vmwp) — [windbg-mcp] The transition drain faults on an unattributed `ntdll!DbgBreakPoint` stop in `vmwp`
- [Item 135](#135-windbg-mcp-a-secure-kernel-debuggers-public-peer-is-kept-unresolved-after-its-controller-has-released) — [windbg-mcp] A Secure Kernel debugger's public peer is kept unresolved after its controller has released
- [Item 136](#136-windbg-mcp-dispatcher-discovery-waits-sixty-seconds-for-one-arrival-that-sometimes-never-comes) — [windbg-mcp] Dispatcher discovery waits sixty seconds for one arrival that sometimes never comes
- [Item 137](#137-windbg-mcp-the-shadow-stack-half-of-stack-lineage-has-not-run-against-a-cet-target) — [windbg-mcp] The shadow-stack half of stack lineage has not run against a CET target
- [Item 138](#138-dbgscope--windbg-mcp-stack-lineage-recognises-a-dispatcher-by-name-not-by-its-unwind-record) — [dbgscope + windbg-mcp] Stack lineage recognises a dispatcher by name, not by its unwind record

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
- **The register half has had a consumer since 2026-10-03** (`500bc36`), which this entry still
  said it did not; noticed on 2026-10-10 while closing item 4.
  `skdispatch::write_register` writes `rax`/`rcx`/`rdx`/`r8`/`r9`/`rip` on a held `vmwp` thread
  through `execute_command("r {name}={value:016x}")`, and verifies each write by reading the
  register back — typed, since item 4 closed. So the text hatch is down to the write alone there.
- **Why the rest is deferred:** `write_virtual` is needed primarily by the state-injection path
  (item 3), which has no consumer without it. The register write has the one above, and is deferred
  on a different ground: that call site passes six whitelisted names and reads each write back, so
  nothing it does is blocked on a typed write.
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

## 6. [windbg-mcp] Concolic/symbolic buffer synthesis (DECISIONS.md D2) — **declined** (2026-07-04)

Auto-emit a concrete `(code, buffer, lengths)` by SMT-solving the on-path branch predicates, rather
than the human/LLM-readable recipe emitted today.

- **Status:** scoped **out** of the current effort. If ever needed, offload to angr/Triton over a
  debugger memory snapshot rather than building an in-house solver — kernel state modeling, loops,
  hashing, and stateful protocols make it brittle and a separate project.

## 8. [windbg-mcp] Tasks extension (`io.modelcontextprotocol/tasks`, SEP-2663) — **declined** (2026-09-19)

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

## 11. [windbg-mcp] MCP Apps (`ui://` resources) — **declined** (2026-07-29)

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

## 19. [windbg-mcp] Let a `debug_batch` step walk a structure — **declined** (2026-10-13)

The proposal was a `walk` step: `walk_memory` (#103) run inside a batch, so that a transaction
patching a driver's dispatch table could assert that every entry was put back. The case for it was
that such a batch "currently asserts on `execute` text" — the all-or-nothing read `walk_memory`
exists to replace — so one unreadable entry would fail the assertion for a reason that has nothing
to do with the restore.

**That premise was already false when it was written.** `debug_batch` landed on 2026-08-10
(`e4a6e7ed`) with two typed ways to state the postcondition, and this item was filed three days
later with `walk_memory` (`00a09608`) without mentioning either:

- **The `eval` check**, `{"check": "eval", "expr": "poi(<entry>)", "equals": "{{orig}}"}`,
  against a value an `eval` step captured before the patch. That is "this pointer is this value" stated as itself,
  with no command text in between. `batch::run_step` stops a step at the first check that does not
  hold, and the report names that expression and what the debugger answered — so an unreadable
  entry ends the step *at that entry*, which is the right verdict for a postcondition: an entry the
  batch cannot read is one it cannot claim to have restored.
- **The `read_memory` step**, a bounded read that keeps the bytes it reached and says where it
  stopped.

**And the walk's own advantage is the wrong behaviour for this question.** `walk_memory` carries
on past a hole in an address list or an array — a handle table with freed entries, say — which is
what is wanted when the question is what is there; a chain whose link will not read stops there.
A restore's postcondition asks something else, and for it an entry that will not read is a failed
check, not a hole to step over.

**What would reopen it** is a transaction that has to follow a pointer chain *after* a mutation and
assert on what it finds — a list unlinked and relinked, say — where the nodes cannot be named in
advance as `poi()` checks or covered by one contiguous read. Nothing has asked for that. Building
it would cost a `StepAction` variant and its `owns` keys, a budget share drawn from the batch's
deadline the way `pool`'s is (a walk is up to 1024 nodes, inside a transaction whose rollback still
has to fit), and another variant in `debug_batch`'s input schema on every surface that serves it.

## 27. [windbg-mcp + dbgscope] A deferred module reports no PDB identity — **declined** (2026-08-20)

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

## 35. [windbg-mcp + dbgscope] The engine's subregister flag misses the views that matter — **declined** (2026-08-22)

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
- **The `disassemble` op's patience has a second place to go, and nothing will ask for it.** Its
  decode is `e.disassemble(start, count)`, which renders each line and so resolves symbols, and
  [dbgscope#200](https://github.com/glslang/dbgscope/pull/200) gave that call a bounded form,
  `disassemble_bounded`, which the walk's `function_listing` already spends its deadline on. A
  `patience_ms` threaded only into `resolve` would bound the address and leave the listing
  unbounded, and the allowlist above counts `Execute` call sites, so it cannot see a typed call.
- **Note the hazard is not fully closable by a watchdog anyway.** `backtrace` resolves a symbol per
  frame through direct engine calls, with no `Execute` for a watchdog to break, so a cold symbol
  server can block that too — see `EngineOp::Backtrace`. This item is worth doing because a
  *command* is bounded cheaply and there is no reason to leave one that is not; it is not worth
  doing as a claim that the symbol-server hazard is gone.

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

## 65. [binja-windbg-mcp] Native Ultimate validation — **declined** (2026-09-12)

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

- **Why deferred:** resynchronising had **no wall-clock bound** of its own, so starting one inside
  a deadline-bounded composite would have spent a caller's whole budget on a call nothing could cut
  short. Item 54 closed that on 2026-10-13 (`DONE.md`): a refresh now carries its call's clock. What
  it found changes this item's shape rather than merely unblocking it -- **a refresh cut short
  leaves the inventory smaller than it started**, because the engine rebuilds its list rather than
  adding to it (20, 43 and 91 of 181 modules for stops at 0.5s, 1s and 2s on the ARM64 bench). So a
  composite that starts one with too little of its budget left can make the very lookup it was for
  worse, and only a cold refresh is slow enough for that: the first after an attach took 3.9s over
  serial there, a repeat 57ms.
- **What would close it:** a bounded refresh, run **once** and only where a module lookup has
  already failed, with the result reported (a section that says "the inventory was resynchronised
  and the module was still not there" is a different answer from one that never looked) -- and one
  that stopped part-way reported as *that*, since it leaves the composite worse placed than before
  it asked. It should stay opt-outable: a caller driving many tools over one attach wants to pay for
  it once, not per tool.
- **How it was found:** running the live-kernel tier for `driver_surface` after
  [#314](https://github.com/glslang/windbg-mcp/pull/314) merged, which is the only tier where a
  module inventory can be stale at all -- a dump's is complete the moment it opens (2026-09-13).

**Where it picks up.** `unattributed_image` and `scan_of` in `src/worker.rs`, `modules`'s own
`refresh` in the same file, and `resynchronise` for the bound item 54 gave it.

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
honestly. In scope, non-exhaustively: `Modules` (its reload carries the caller's clock
since item 54 closed, but the reads that build the listing after it -- the unloaded half, each
row's PDB identity -- are on no clock), `SymbolPath`
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
  PTE. That would be a placement defect; item 101 was the one found, now in
  [`DONE.md`](./DONE.md), and a new one would be filed beside it.
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

## 108. [windbg-mcp] A KMDF driver's real callbacks — step 1 landed, the framework's per-device config is what is left

**Repo:** `windbg-mcp`. **Origin:** item 103's S5o gate, 2026-09-29, where it cost a gate's worth of
detour and produced a wrong sentence in a checked-in document before review caught it. **Step 1
landed 2026-10-02 and step 3 with it; this entry is narrowed to step 2**, which is the expensive half
and was deliberately not started first.

**What the tools assumed.** `driver_object`, `driver_surface` and the `MajorFunction[0x0e]` recipes
in `skills/windbg-debugging/driver-ioctl.md` and `.claude/skills/live-kernel/SKILL.md` read a
driver's dispatch out of `DRIVER_OBJECT->MajorFunction` and expected its entries to name routines
**in that driver**; `ioctl_map` and `reachable_from_dispatch` are *handed* one of those entries as
an address and inherit the expectation from whoever read the table. For a WDM driver the entries
are the driver's. For a KMDF driver they are not — all 28 are the framework's — so
`driver_object` reported a driver that dispatches nothing of its own, and `ioctl_map` started at one
of those entries found no IOCTL switch because there is none there to find. None of that was *wrong*
as a reading of the table; it was the tools answering a question the caller did not mean to ask,
which is the same failure mode as item 107.

### What step 1 shipped (2026-10-02)

`src/framework.rs` recognises a framework from facts the tools already read, and `driver_surface`,
`driver_hazards`, `ioctl_map` and `reachable_from_dispatch` each carry a `framework` field when one
of them fires. **Two tells, because neither implies the other**: a `WdfVersionBind` import from
`WdfLdr.sys` (a fact about the *image*, so it answers with no debuggee) and every `MajorFunction`
entry read being in the framework's image (a fact about the *driver object*). `driver_surface`'s
IOCTL section names the framework as the third reason a handler can sit outside the driver's image,
beside the kernel's stub and a filter — the sentence that previously enumerated two and explained a
KMDF table as one of them. Measured through the dev build against real images on 2026-10-02:
`driver_hazards` on `Vid.sys` reports `kmdf` with tell `bind_import`; `ioctl_map` at
`Wdf01000+0x51c90` reports `kmdf` with tell `framework_image` beside `case_count: 0`; and
`Wdf01000.sys` and `mountmgr.sys` report no framework at all.

**Absence is deliberately not a negative** anywhere: the field is added when a tell fires and nothing
is added when none does, so an image whose import names could not be read is reported as a driver
nothing said anything about rather than as a WDM driver.

### What is left: step 2, the real callbacks

The framework's per-device config holds them; the create/close/cleanup trio comes from the
file-object config, and device control from an I/O queue's. This is structure-walking against
`Wdf01000.sys`'s public types and is the part that wants a **measured layout per framework version**
rather than a constant — `Wdf01000.sys` carries its own version line (1.35.26100.3323 on this bench)
independent of the OS build, which is the trap to design around. Until it lands, the `framework`
field tells a reader where *not* to look rather than where to look, and `docs/limitations.md` says so.

**And do not scope step 2 against a list of callbacks, which is the one thing the step-1 PRs
established at length.** `EvtIoDeviceControl` is not where a client's control codes necessarily are;
neither is any other slot, nor any registered callback at all — a driver using a manual queue takes
requests out of it in a worker or timer routine that was registered as nothing. So *"walk what the
driver registered"* is not the scope either, and no enumeration this repo writes is the scope.
`src/framework.rs`'s module docs hold what was measured about this build, as names to look for, and
deliberately stop there; WDF's own documentation owns the taxonomy.

**What that leaves is the shape of the answer, which is the conclusion worth carrying.** Step 2
reports **candidate sites with what was read at each** rather than a single address, and it has to be
able to say *"this driver's comparison was not located"* without that reading as "it has none".

**Seven review findings across the two step-1 PRs went into that sentence**, every one of them
correcting a claim of mine about which route is *the* route, what a route *must* do, or which list is
complete — against a framework this repo does not own, in prose no code depends on, each correction
becoming the next round's finding. The lesson is cheaper than the route table: a tool that cannot
resolve a callback should not describe where the callback might be.

**What step 1 measured that step 2 should start from**, stated as the reading rather than as an
interpretation of it. Disassembled on this bench, `Wdf01000.sys 1.35.26100.3323`:
`FxDevice::Dispatch(DEVICE_OBJECT*, IRP*)` takes the current `IO_STACK_LOCATION` from `[Irp+0xB8]`
and reads its `MajorFunction` at `+0` and `MinorFunction` at `+1`. It then reaches
`[[DeviceObject+0x40]-0x30]`, adds `0x170`, and walks the **linked list** whose head is there —
`r9 = [r9]` per step. At each link it indexes by `3 * major` in qwords: `+0x10` of that triple is
the handler, `+0x18` a count, `+0x20` a byte array the minor function is searched in. A link whose
`+0x10` is null is skipped and the walk continues; otherwise the handler is called through
`Wdf01000!_guard_dispatch_icall`. **So a per-major handler is a field reached through a list rather
than a slot in a table**, and the walk that finds one is what step 2 has to write — whether those
links are the "packages" KMDF's own naming calls them is an inference this reading does not settle.
Separately, S5o traced an `IRP_MJ_CREATE` by hand as `FxDevice::Dispatch` → `FxPkgGeneral::OnCreate`
→ the driver's file-object create callback, which is consistent with the above and is a second
source rather than the same one.

**Step 3 is answered and needs nothing.** UMDF is a different image again (`WUDFx02000.dll`, user
mode) and is recognised nowhere; the `framework` note says so rather than implying coverage.

### Three claims this entry made that measurement did not support

Corrected here rather than quietly dropped, since this entry is what anyone picking step 2 up will
read, and all three were written from the S5o gate rather than re-derived.

- **"every in-box Hyper-V driver is KMDF"** — the old title, and false. Censused off disk on
  2026-10-02: **132 of the 445** driver images in `System32\drivers` import `WdfVersionBind`, and of
  25 Hyper-V-ish ones **13** do. `Vid`, `vmbus`, `vmbusr`, `vpci`, `vpcivsp`, `storvsp`, `vmstorfl`,
  `vmgid`, `vmgencounter`, `vms3cap`, `hvcrash` are KMDF; `vmswitch`, `winhv`, `winhvr`, `hvsocket`,
  `hvservice`, `vmbkmcl`, `vmbkmclr`, `vmbusproxy`, `VmsProxy`, `VmsProxyHNic`, `VMBusHID`,
  `vmsvcext`, `videoprt` carry no bind import at all.
- **"chosen per device by `FxDevice::_RequiresRemLock`"** — it is chosen per **major function**. The
  fill loop at `FxDriver::Initialize+0x200` calls `_RequiresRemLock(cl, 0)` with `cl` being the major
  index it is about to write, once per iteration.
- **The fill is conditional, which the entry did not say.** `FxDriver::Initialize+0x1b8` is a
  `test cl,2` on the driver config's flags with a `jne` over the whole loop —
  `WdfDriverInitNoDispatchOverride` — so a KMDF client that sets it keeps a dispatch table of its
  own. That is why step 1 reports two independent tells rather than inferring the table's contents
  from the import.

**Also worth knowing before step 2, and not about KMDF.** A library-only rule misclassifies the
framework as its own client: `Wdf01000.sys` imports `WdfRegisterLibrary` and
`WdfLdrDiagnosticsValueByNameAsULONG` from `WdfLdr.sys` and neither bind routine — and a name-only
rule admits any image importing something *called* `WdfVersionBind` from anywhere, so the tell is
**both**, which took a review round to get right. And `uf Wdf01000!FxDevice::Dispatch` fails `0x80040205` on this image because `x` matches
that name twice — the routine and an inline caller inside `DispatchWithLock` — so anything driving
the framework by symbol wants module+RVA.

## 113. [windbg-mcp] The `\Device` descriptor sweep's own figures do not add up

**Repo:** `windbg-mcp`.

`data_access` in `src/sd.rs` rests on a sweep of 2026-09-13: across every distinct descriptor
behind every device in `\Device` on a live Windows Server 26100 guest, **41 descriptors** and
**149 ACEs**, of which **7** carry generic bits and **all 7 are `INHERIT_ONLY_ACE`**. Those figures
cannot all be right -- 7 and the "other 141" the note carried come to 148 -- and the one-off is in
the **record** rather than in any later reading of it: `4630c7c`'s commit message, `data_access`'s
doc comment and item 69's entry state the same three numbers, because all three were written from
the one run.

**The remainder was dropped rather than corrected** when item 69 closed on
[#458](https://github.com/glslang/windbg-mcp/pull/458): it is the only one of the three that is
pure arithmetic, the other side of a partition needs no count, and writing 142 would have been a
guess about which number was mistyped. So nothing in the tree is wrong today; what is unsettled is
which figure is.

**It matters because the `7` is load-bearing and the other two are not.** The sentence carrying a
rule is *all 7 are `INHERIT_ONLY_ACE`*, and what it buys is **agreement**: those 7 are already
reported as granting nothing by the separate inherit-only rule in `device`'s `access_entry`, so the
two rules meet on the only ACEs where both apply. If the generic-bit count on that guest was
really **8**, what follows is **not** a counterexample, and an earlier draft of this entry said it
was. The eighth ACE
is *unclassified* rather than known to be anything: the record says seven were inherit-only, `7` is
itself one of the figures in doubt, and the eighth may be inherit-only too with the claim simply
mistyped. What an 8 establishes is that the agreement covers seven of eight and is **unverified**
for one -- weaker than a falsified rule, and still worth settling, because if that ACE is *not*
inherit-only then it is one whose `GENERIC_*` bits `rights` names with `reads: false` beside them
and nothing to explain why, which is the reading the note exists to prevent. Which of the two it is
is exactly what the fourth figure below answers and what nothing in the records can. It would
**not** reopen the declined generic-mapping finding either way, that resting on the kernel's own
behaviour rather than on any count (`nt!SeAccessCheckWithHint`, 1,192 instructions on 26100 with no
read of a generic bit or the mapping). And if instead the total is 148, or the
remainder 142, no rule moves and only the denominator item 69's bound is quoted against does.

- **Why deferred:** it cannot be settled from the records, which are one measurement written three
  times, and re-taking it wants a live kernel on that guest -- the half of this bench that was not
  reachable from the Mac the close was written on. Nothing is wrong in the meantime, which is why
  this is a provenance defect in prose rather than a defect in `data_access`.
- **What would close it, by superseding the record rather than repairing it:** re-take the sweep
  and record **four** figures with what produced them -- descriptors, ACEs, ACEs carrying generic
  bits, and how many of *those* are inherit-only -- so nothing in it is reached by subtraction,
  whichever of the three moved. What it will **not** do is say which figure was mistyped, and this
  entry's own first paragraph is why: a DACL is whatever was assigned to it, so one driver
  installed or removed on that guest since 2026-09-13 moves the counts legitimately, and a fresh
  sweep is then a *new sample* rather than a second reading of the old one. Nor can the original be
  reproduced -- nothing recorded that guest's state beyond "26100", not even a revision. So the
  archaeology stays open for good, and what closing this buys is an inconsistent record replaced by
  a consistent, dated one that carries what produced it.
- **The *rule* is what a new sample settles, and it is the half worth having.** Whether every
  generic-bit ACE is `INHERIT_ONLY_ACE` is a claim about what installers assign, testable on
  whatever inventory is in front of you: a count with one of them *not* inherit-only is a finding
  about `data_access`'s agreement sentence on its own terms, rather than evidence about what was
  there in September. The correction then lands where the rule is read -- that doc comment and the
  sweep note on `AceKind::mask_is_access`, where item 69's bound can also be re-stated against a
  count the sweep printed. Item 69's entry in [`DONE.md`](./DONE.md) is the record of what was
  known at its close and is not rewritten, which is how this repo treats its other records.
- **Record what produced the figures, and leave the form of that open.** A first draft of this
  bullet ruled out a committed sweep script because "what drifted was a derivation rather than a
  measurement" -- which assumes 141 is the wrong number, the very thing this item exists to settle,
  and is false if the mistyped figure is `7` or `149`. The requirement is the provenance and not
  the vehicle: record the command or the tool calls beside the four figures, and whether that ends
  up a transcript in this entry or a script under `tools/` is for whoever re-takes it to judge --
  with the answer in hand, which is the opposite order from the one that draft used.
- **How it was found:** CodeRabbit on #458, reading "the other 141" against the 149 in the same
  sentence and proposing 142. The finding was right that the arithmetic does not close and wrong
  that it is a typo to correct -- `git log -S` for the figure found the same three numbers in the
  commit that first recorded them (2026-10-06).

**Where it picks up.** `data_access` and the sweep note on `AceKind::mask_is_access` in
`src/sd.rs`, and item 69 in [`DONE.md`](./DONE.md).

## 114. [dbgscope] A big-pool entry in no region the walk discovers

**Repo:** `dbgscope`, surfaced by `windbg-mcp`'s live pool tier.

Found on 2026-10-07 while closing the trimmed-page half of item 99's class
([dbgscope#191](https://github.com/glslang/dbgscope/pull/191); the addendum under item 99 in
[`DONE.md`](./DONE.md)). The tier's `BigPageOracle` takes the first live entries of
`nt!PoolBigPageTable` and puts each to `pool_chunk`. On the 29671 lab guest four of the five came
back carrying the table's tag and one came back `covered: false`: `Key` `smCB` at
`0xffffe67bde598000`, `NumberOfBytes` 0x1000, flags dword `0x00004000` — `PoolFlags` 0x40, which
the public `POOL_FLAGS` numbers as `POOL_FLAG_NON_PAGED` — in the same `0xffffe67b…` range as
the table itself (`0xffffe67bdf2b0000`). `pool_find_tag smCB` finds nothing, on the fixed build as
on the one before it. So it is not the trimmed-page case: the walk has **no region containing
that address at all**, which is a question about discovery rather than about decoding.

- **Why deferred:** the tier reports an uncovered sample rather than asserting on it, and the
  class is one entry in five on one guest — so what it is (a heap discovery does not enumerate, a
  nonpaged allocation served from outside the segment heap, a region `walk_region` refused) needs
  a live read before anything is built, and building from the name of a flag would be the mistake
  item 99 was filed on.
- **What would close it:** against that guest, which heap and segment, if any, hold
  `0xffffe67bde598000` — `!pool` names the region, and `ExPoolState`'s heaps say whether discovery
  should have reached it — and then the same question of every uncovered big-page entry rather
  than of one, since the oracle samples the first few and one in five is a rate rather than a
  count.
- **Where it picks up:** `discover_pool_regions` and `discover_segment_context` in dbgscope's
  `src/pool/snapshot.rs`; the tier prints the addresses under `big-pool allocation(s) the walk has
  no span for`.

## 117. [windbg-mcp] The KD facade pipe has only the default ACL, no client authentication and no break-in

**Repo:** `windbg-mcp`. **Origin:** the 2026-10-07 review (item 115's origin).

The pipe is `ServerOptions::new().first_pipe_instance(true).create()` with no explicit security
attributes, in the target and in the wire probe, so Windows assigns the default descriptor derived
from the process token — not a null DACL, which would grant everyone everything; the first draft
of this entry said "null security descriptor" (Codex, round 5). This repository measured what
that default grants on its own bench when it audited the old cdb pipe (`DONE.md`, the control
row of the cdb-pipe DACL table under item 49): SYSTEM and Administrators full access, Everyone
and Anonymous read. The name is operator-chosen and
checked for charset and length only; the first client to send a KD reset is served; a read-only
client can take the single instance, after which the reset wait times out and the session closes.
Three input shapes end the session rather than answering a KD status: a manipulate packet shorter
than `0x38` bytes, a `GetContextEx` range outside the context, and any framing error, a checksum
mismatch included, with no resend request although `PACKET_TYPE_RESEND` is defined. The break-in
byte is honoured only while the target runs, and only as a cancellation of the `vmwp` wait, which
is a fault with recovery and a process exit; while stopped the flag is set and never read. The
2026-10-05 run is the leading suspect for a Kernel-Power 41 host reboot with no dump: a KD process
left in its reconnect loop outlived the runner's short wait and blocked VM cleanup. The mitigations
live in the private runner, not in the facade.

- **Why deferred:** the ACL and name changes are small and want a live WinDbg to confirm the
  client still connects; break-in needs a design — a natural-mode arm on an address the guest
  reaches often, which the research record already uses (`securekernel!KiTimerInterrupt`), or an
  honest refusal — and the review did not want to pick one without a run.
- **What would close it:** an explicit DACL (creating user and SYSTEM), a pipe name from the
  system RNG the controller already uses, the client's process identity checked before the reset
  is answered; `failure_response` for the short packet and the bad range, a resend on checksum
  failure, a bound on consecutive failures rather than the first; a break-in that produces a real
  stop — and, until that exists, treating the byte as unsupported without faulting the retained
  session, with the refusal visible in the facade's log or server status rather than as an invented
  KD reply (the serial break-in byte has no request to which an NTSTATUS can be returned); the facade
  refusing to exit while it retains an owned event and bounding the reconnect window itself; and a
  `cargo fuzz` target over `kdwire::Decoder` and `ManipulateRequest::decode` seeded from the inline
  vectors in `kdapi.rs`'s tests.
- **Where it picks up:** `kdtarget.rs`'s `run_async` (the pipe is built just before the connect
  wait) and `read_transport`; `kdwire.rs`'s `Decoder` and `TargetLink`; the mitigations list in
  `target/private/securekernel-windbg-kd-plan.md` (private).

**Implementation status, 2026-10-07:** the facade now creates the pipe with a protected DACL,
admits only the server account or LocalSystem after checking the connected process token, uses a
server-generated random name for MCP sessions, sends resend packets for framing errors and faults
only after three consecutive errors. Short manipulate packets and invalid context ranges receive
failure replies without losing the retained stop. A stopped-state break-in is logged and refused,
and the managed reconnect and absolute-pause windows are bounded. A real running-state break-in
and the decoder fuzz target remain open, so this item is not closed.

**Transport evidence, 2026-10-11:** item 116's forced-disconnect run did not reach reconnecting:
the terminated kd retained its pipe until idle expiry. The controller then restored and released
successfully. The separate passing symbol/stack gate uses MCP teardown and establishes no forced
reconnect result. The exact builds, runs and limits are recorded in
[item 116's close](./DONE.md#116-windbg-mcp-the-kd-facade-answers-windbg-with-fabricated-state-it-cannot-tell-apart-from-guest-state--done-2026-10-11).
**Reproduced 2026-10-13** on the dev build at `008bfa6` plus
[#494](https://github.com/glslang/windbg-mcp/pull/494), a fresh K3 boot and the redirect-mode
smoke config: `a_managed_secure_kernel_kd_session_steps_in_windbg_and_releases_through_mcp` ran
its `lm`/`t`/`r` script, terminated the authenticated client, and then read the session as
`released` where it waits for `reconnecting` — "KD disconnect lost the retained session: released",
80.5 s in all, the 60 s `idle_timeout_ms` having run out while the terminated kd still held its
pipe. The controller released cleanly: the VM stayed running with a healthy heartbeat and no
worker, provider or debugger survived. So the lifecycle test is red on this bench for the reason
recorded above, and a green run of it is what would retire this paragraph.

**Running break-in landed and was repeated live, 2026-10-28.** A server-owned DbgEng worker on the
facade pipe completed 75 `g`-without-breakpoint / typed `break_in` cycles across three clean K3
boots. Each serial break-in was bound to the exact running wait and returned the controller's M2
stop; every ordered composite teardown then passed a 60-second audit with that boot's same `vmwp`,
stable Secure Kernel text, DR0--DR3 zero, DR7 `0x400`, TF/RF clear and a healthy heartbeat. This
closes the break-in half of the item. The decoder fuzz target remains open, so the item itself stays
here.

## 121. [windbg-mcp] Tracing pool allocations on an x86 kernel

**Half landed, 2026-10-13: the x86 reader is built and measured in user mode; a trace on a live
x86 kernel has still never been armed.** What is left is the second half, and this entry is
narrowed to it.

`pool_trace` read an allocator's arguments from registers at the call and its result from the
return register after it -- `rcx`, `rdx`, `r8` and `rax` on x64, `x0`–`x2` and `x0` on ARM64 --
and an x86 kernel passes neither way: its exports are `__stdcall`, so the arguments are on the
stack, and read as x64's registers every hit would have recorded three unrelated values as a size,
a tag and a pool type. So x86 was **refused** before anything was scanned or armed. Raised by
review on [#473](https://github.com/glslang/windbg-mcp/pull/473), where the first version fell
through to x64's registers for anything that was not ARM64.

**What landed.** `worker::call_registers` became `worker::Convention` -- `Registers` for x64 and
ARM64, `Stack` for x86, `None` (still refused) for a machine the build does not know -- and
`call_arguments` reads a `Stack` site at `[esp]`, or at `[esp+4]` for a site that *jumps* to the
allocator, whose own return address is already on the stack. The layout stopped being a list of
positions: `pooltrace::Layout::x86_stack` derives byte offsets from widths, so `ExAllocatePool2`'s
`POOL_FLAGS` -- a `ULONG64`, two slots -- puts its size at `+8` and its tag at `+12` where
`ExAllocatePoolWithTag`'s are at `+4` and `+8`, and `pooltrace::arguments_from_stack` parses one
read of exactly those bytes into the `[u64; 3]` the read side already consumes. A short read is
`None`, counted in `unreadable_hits` like a register that would not read.

**What the measurement established**, through `mcp_smoke`'s
`an_x86_stdcall_call_holds_its_arguments_at_esp_and_its_result_in_eax` on a 32-bit C program the
harness compiles, driven by the x64 engine with its effective machine switched to x86 -- the engine
an x86 kernel is debugged by too: at a `__stdcall` call `esp` names the first argument and three
four-byte arguments are at `[esp]`, `[esp+4]`, `[esp+8]`; a 64-bit first argument takes two slots,
low first, with the next two at `+8` and `+12`, read at `[esp]` at the call and at `[esp+4]` on
entry to the callee; `eax` holds the result at the instruction after the call, which is the call's
own length past it; and the hazard scan on a PE32 image lists `RtlMoveMemory`'s
`call dword ptr [abs32]` site by the very slot the six bytes encode, so `called_slot` reads x86's
absolute displacement as it reads x64's RIP-relative one -- the bullet this entry had as
*unmeasured*. The sixteen bytes read at the call are the fixture
`pooltrace::tests::x86_stack_bytes_parse_to_the_arguments_an_allocation_is_read_by` parses
([`docs/smoke-test.md`](./docs/smoke-test.md), *The x86 calling convention, measured at a call*).

- **What it does not establish, which is the open half.** The convention is the compiler's and is
  the same in both modes, but nothing has run the *trace* on an x86 kernel: `pool_trace` refuses a
  user-mode target, so `call_arguments`' engine half -- the `esp` read, the memory read and the
  `+4` at a jump -- has run inside no breakpoint callback. The `+4` itself is measured since
  2026-10-13, at the linker's import thunk in the fixture's second source (a `jmp` through the
  slot entered by a `call`, under a frame still up), and no longer only derived. The sign
  extension of `esp` and `eax` is the engine's documented rule for a 32-bit
  target, measured on a 32-bit user-mode process in the 32-bit engine -- where a zero-extended
  upper-half address read as well as the sign-extended one -- and on no x86 kernel. Nor has the
  scan read a real 32-bit **driver**: the import-address-table fallback for a freed import
  directory is untried on a PE32 image, `ExAllocatePool2` exists on 32-bit Windows 10 only from
  2004 on, and whether `current_thread_data_offset` is the `KTHREAD` on an x86 kernel is assumed
  from x64.
- **The cost moves too.** A register read is microseconds; this is a 12- or 16-byte memory read per
  call, measured at about 1 ms for 8 uncached bytes over the ARM64 bench's serial link -- small
  beside a trap's ~25 ms, but it is a read that can fail, and it is counted where a register that
  would not read is.
- **Why the rest is deferred:** there is no x86 kernel to measure against. The ARM64 bench's
  debuggee is Windows 11, which ships no x86 edition, so the target is a 32-bit Windows 10 guest
  (2004 or later for `ExAllocatePool2`). Checked 2026-10-13 on the x64 bench: `Get-VM` lists six
  guests, all x64; the only ISO on disk is a Windows 11 x64 one; the WDK carries kernel libraries
  for x64 and ARM64 only, so an x86 HEVD would come from its release rather than this
  toolchain; and C: and D: have about 11 GB free each, against a 3-4 GB ISO and a guest to install.
  A Gen 1 guest with serial KD over a named pipe would do, and the live-kernel tier's shape would
  then transfer: arm on HEVD's x86 build, fire the IOCTLs from the guest, read. That shape ran on
  x64 on 2026-10-13 -- `ctf-vm`'s HEVD, fourteen sites armed, four allocations recorded, nothing
  unreadable; the reading is in `CHANGELOG.md`'s pool-trace entry -- so the live trace is measured
  on x64 and ARM64 and unmeasured only here.
- **A side finding, filed as item 127:** at the x64 engine's first initial break in a WoW64
  process the effective machine is x64, and the scan decoded the 32-bit image as x64 code --
  listing the import with no call site at all. The measurement reads after the stop in 32-bit code
  for that reason, and the test says so.

**Where it picks up.** `Convention`, `call_arguments` and the refusal in `arm_pool_trace`
(`src/worker.rs`); `Layout::x86_stack` and `arguments_from_stack` in `src/pooltrace.rs`; the
measurement in `tests/mcp_smoke.rs` and its section in `docs/smoke-test.md`; and the sentence in
[`docs/limitations.md`](./docs/limitations.md) that says the reader is measured in user mode, which
is the sentence a live run would retire.
## 122. [windbg-mcp] A live Secure Kernel session has no image to resolve names or instructions against

**Repo:** `windbg-mcp`. **Origin:** a live VTL1 stop/step run against an HVCI image-validation
address, 2026-10-10.

`SkLiveArmArgs::address` is documented as the "exact VTL1 virtual address to stop before", and
`SkLiveBreakpointArgs::address` is the same for the additional slots; `SkLiveStepArgs::address` for
a repeated step likewise. There is no build-relative alternative, so a caller arming a *named*
Secure Kernel function has to resolve the image base before it can form the argument. The server
does not need the *base* from the caller: the live-memory provider reports it, and the profile
carries build-relative RVAs of its own for the debugger-data head, block and loaded-module list,
which it resolves against that base — `open_sk_live_control`'s own report says the
first arm "discovers and validates the partition, provider CR3 and Secure Kernel memory source
before changing debug registers". Every other per-boot coordinate on that opener is an **optional
assertion** for exactly this reason: `vmwp_pid`, `dispatcher_vnd`, `partition_id` and
`expected_cr3` are all discovered by the worker and merely checked if supplied. `address` is the
one coordinate with no discovered counterpart, which is the inconsistency rather than the hazard.

**And the image itself is missing, which has to be settled before any of the rest.** A live-control
profile pins `vmwp_image` and its hash; its optional Secure Kernel section carries a **build number
and RVAs**, not a file — so there is nothing for a live session to load or compare against.
`open_sk_capture` sidesteps this by taking its image as a separate required `image` argument. So
this item's first step is not a symbol lookup at all: it is deciding where an authoritative Secure
Kernel image comes from for a *live* session and how its identity is validated against the running
build, which the capture path answers by asking the caller and the live path does not answer at all.
An earlier draft of this entry said "the profile already pins the exact build" and was wrong: it
pins a build *number*, which identifies no file.

**The resolution this needs is already built, for the sibling session kind.** `open_sk_capture`
points an engine at `securekernel.exe` *as a file* at its preferred base
([`src/sksession.rs`](./src/sksession.rs)), and `sk_symbol` resolves an unqualified symbol in that
image to an address or names an address back. That is exactly what arming a named Secure Kernel
function wants. It is unreachable from a live session for one reason: `engine::refuse_op_on_kind`
sorts ops into `capture_op`, `live_op` and `kd_op`, and `EngineOp::SkSymbol` is a `capture_op`. The
allow-list is right to exist — it is what stops a tool answering about `vmwp` as though it were the
guest — but the effect here is that the caller does out of band what the server already does, from
the same bytes. **From the *caller's* image, though, not the profile's**: `open_sk_capture` is given
`securekernel.exe` as a required argument, so what makes the sibling path work is an image somebody
supplied, which is exactly what a live session has no way to obtain (above).

`sk_live_step` has the same shape one layer in. A *repeated* step must state `address` and the exact
instruction `bytes`, and a stop record cannot supply them: its `instruction` field is the
instruction that was just *stepped*, so feeding it back fails with "the step instruction address ...
does not match the stopped RIP". The byte guard should stay — it is the interlock against stepping
blind — but a guard the **server** derives from an image of its own is stronger than one the caller
asserts, because a caller can assert bytes that are merely self-consistent. That is a statement
about the step's design and not about today: deriving it needs the image this item's first step is
about, so it is conditional on that step rather than available now. As it stands a caller stepping a
sequence opens a *second* session on an image it supplies itself to disassemble it, which is how the
2026-10-10 run finally worked.

The hazard is what resolving it costs the caller. The base is randomised per guest boot, so it is
per-boot work; reading it means opening the live-memory provider against a partition; and binding a
partition to a *specific* VM is the privileged `vmwp` walk through `vid!VidGetHvPartitionId`,
because the provider deliberately refuses to select a partition merely for having a Secure Kernel —
on a host with two VBS guests that would bind the wrong VTL1. So an argument whose purpose is
exactness obliges every caller to run the most privileged step in the system to obtain a number the
worker is about to compute anyway. Measured on 2026-10-10, that step took the VM's own worker
process down mid-run (Hyper-V event 3040, "could not initialize"), ending the guest.

- **Why deferred:** orchestration, not capability — and it is worth saying plainly, because the
  first draft of this entry inflated it into a structural question it is not. Every *mechanism* is
  already here, and each of them is conditional on the image above. `vmwp` is an ordinary user-mode
  process on the host and the live worker's engine is **already attached to it**, so nothing about
  the engine's target forbids resolving symbols alongside it — once there is an image to resolve
  them in, a name is answered without reading the guest at all, since that is a PDB and
  export-table lookup. The *live* half needs nothing new: `sk_live_read_memory` already reads VTL1
  memory while the stop is held, which is how the 2026-10-10 run confirmed the live prologue
  matched the image byte-for-byte — against a file the operator supplied by hand, which is the
  whole of what is missing. So the server could read what it is about to step and check it, and
  cannot yet, because nothing gives it the thing to check against. (A purely static route is a
  different tool's job; the point of this one is that it is live.) What is unsettled beyond the
  image itself is narrow: VTL1 maps more than the Secure Kernel image, so a bare name or RVA is
  unambiguous only for the one image a session is given, and an arm into `skci` or a trustlet would
  have to name its module.
- **What would close it:** first, an authoritative Secure Kernel image for a live session — where
  it comes from, and how its identity is checked against the running build — since the profile
  supplies only a build number and RVAs. Then a live session able to turn a **name** into a VTL1
  address against that image. **Not** by admitting `EngineOp::SkSymbol` for `SecureKernelLive` in
  `refuse_op_on_kind`, which was this entry's first suggestion and does not work: that dispatch arm
  calls `held_capture(sk)?` unconditionally, and a live-control session initialises only its own
  live state and holds no capture, so every lookup would fail before reaching DbgEng. It needs a
  live-specific symbol path that loads the pinned image and rebases it onto the base the
  live-memory provider reports — so that `sk_live_arm` can be given a
  symbol, or an RVA, instead of an address the caller had to compute; the same resolution used to
  supply a repeated `sk_live_step`'s instruction, with the byte guard then checked by the server
  against the pinned image rather than asserted by the caller; both an address and a name supplied
  at once refused rather than one silently winning; and the live tier's config carrying a
  build-relative target instead of `instruction_address`, which is currently a required per-boot
  absolute and so cannot be checked in.
- **Where it picks up:** `refuse_op_on_kind`'s `capture_op`/`live_op` split in `src/engine.rs`;
  `SkLiveArmArgs`, `SkLiveBreakpointArgs`, `SkLiveStepArgs` and `SkSymbolArgs` in `src/server.rs`;
  the image-as-target session in [`src/sksession.rs`](./src/sksession.rs) and its doc section *"The
  engine's target is the image, and that is why the debugger tools are refused"*; the arm and guard
  path in `src/sklive.rs`; the required-field list in `secure_kernel_live_tier` and its consuming
  test in `tests/mcp_smoke.rs`; and the live-tier field list in
  [`docs/smoke-test.md`](./docs/smoke-test.md).

## 125. [windbg-mcp + dbgscope] An interrupted replay is left where TTD puts it, not where it had got to

**What happens.** On a TTD replay target, a run that is broken in — at its own bound
(`timed_out`) or by a `break_in` (`interrupted`) — is not left where the replay was when the break
landed. TTD prints *"Replay was interrupted by the user. The current position is approximately how
far we had gone."*, and then, in eleven of thirteen runs measured with a breakpoint ahead, the
cursor is **past** that breakpoint: at the trace's end for a forward run and at its start for a
reverse one, wherever the position was read. The other two stopped *at* the breakpoint, with no
`Breakpoint 0 hit` in the output. Neither is "how far we had gone": a 2 s bound on a replay that
takes 16.6 s unbounded left the cursor at `Percent: 100.000000`.

**Why it matters more than it looks.** The breakpoint is skipped silently. The stop reads
`timed_out: true` at the end-of-trace IP, and the *next* `go` answers `TTD: End of trace reached.`
with `timed_out: false` — an ordinary stop, from which a caller concludes the breakpoint is never
hit. `reverse_go` then finds it, which is the only recovery, and nothing points there. This
server's model-visible prose says the opposite: `interrupt`'s description and the detail
`worker::interrupt_running` returns both say an interrupted operation "returns whatever it had
reached". On a live target that is true; on a replay it is not. `StopReport::interrupted`'s doc
comment said the same and now carries the exception; the two client-facing sentences are left for
the fix, to be reworded against whichever behaviour it lands rather than ahead of it.

**Measured** on the ARM64 bench, 2026-10-13, through the service's shipped tools at
`0.22.0+gbfd1f388`, TTD 1.11.610.0, `dbgeng` 10.0.29617.1000. The traces are `cmd.exe /c for /L`
loops of 200,000 and 1,000,000 iterations, and `hostname.exe`:

| Trace | Breakpoint ahead | Unbounded | Broken in | Left at |
| --- | --- | --- | --- | --- |
| 692 MB, unindexed | `ntdll!LdrShutdownProcess`, `6E00C:DB3` | hit at 16,760 ms | `continue_async`, `max_run_ms: 2000` — 2,035 ms | `6E01E:0`, the end |
| same | same | — | `break_in` at about 2.5 s | `6E01E:0`, the end |
| same, `g-` from the end | `kernel32!BaseThreadInitThunk` | hit at 16,695 ms | `debug_batch` `resume` step, 2,000 ms — 2,049 ms | the start-of-trace IP |
| 172 MB, **indexed** | `ntdll!LdrShutdownProcess`, `165EB:DB3` | hit at 106 ms | `max_run_ms: 1` — 128 ms | `165FB:0`, the end |
| `hostname.exe`, two recordings | `LdrShutdownProcess`, then `RtlExitUserProcess` | hit | `max_run_ms: 1`, five runs by hand | the end, all five |
| `hostname.exe`, the TTD tier's test | `ntdll!RtlExitUserProcess` | hit | `max_run_ms: 1`, four runs | past it twice, **at** it twice |

Every run *without* a breakpoint ahead — five, both directions, bounds of 1 ms to 2 s — was left at
the boundary too. So it is not the index, not the direction and not who asked for the break, and
it is not this server: the position is the engine's own (`dx @$curthread.TTD.Position`).

**What would close it is a choice, which is why it was filed rather than done with item 47.**

- **Put the cursor back.** Read the position before a resume on a replay target and, when the run
  comes back cut short, travel back to it and say so. A cut-short replay has then made no progress
  — which is the truth, since TTD threw the progress away — no breakpoint is skipped, and the
  caller retries with a longer bound. It wants a typed position read and seek in dbgscope (a new
  primitive is a typed method there, never the `execute` text hatch), which TTD exposes through the
  data model (`@$curthread.TTD.Position` and its `SeekTo`) and dbgscope does not bind yet. All
  three bounded paths end in dbgscope's `pump` — `execute_and_wait`, `settle`, `run_to_address` —
  so that is where it belongs, rather than in three callers here.
- **Report it.** A typed field on the stop saying the position is TTD's rather than where the run
  was, so a caller knows to reverse. Cheaper, and leaves the trap armed for any caller that does
  not read the field.

The first is the one that makes "returns whatever it had reached" true on every target; the second
is what to fall back to if the seek turns out to cost something on a large unindexed trace, which
nobody has measured.

**The x64 bench answers the same way** (2026-10-13, the dev build at `008bfa6`, the tier run from
PowerShell): the test's own line read `item 125: a replay broken in at its bound was left PAST the
breakpoint, which going on never reached` — the eleven-of-thirteen case above, on a `hostname.exe`
trace. One run, so it says the behaviour is not ARM64's alone and nothing about how often each
landing occurs there. The tier's test prints its landing on every run (`item 125: …` under
`--nocapture`).

**Where it picks up.** dbgscope's `DebugEngine::pump` and the three of its callers a run goes
through, in `src/dbgeng.rs`;
here `worker::resumed`, `worker::pump_a_resume` and `worker::run_to_address`; `StopReport` in
`src/structured.rs`; `interrupt`'s description in `src/server.rs` and the detail in
`worker::interrupt_running`; and `ttd_a_replay_broken_in_at_its_bound_says_so_and_leaves_the_session_usable`
in `tests/mcp_smoke.rs`, whose printed line is the measurement to turn into an assertion once there
is a behaviour to assert.

## 127. [windbg-mcp] The code scans decode by the stop's effective machine, not the image's

**Repo:** `windbg-mcp`. **Origin:** item 121's measurement, 2026-10-13.

`driver_hazards` on a 32-bit image in a WoW64 process, asked at the x64 engine's **first** initial
break -- the 64-bit loader's, in the 64-bit `ntdll` -- listed the `RtlMoveMemory` import with its
slot and **zero** call sites. The same call after the target had stopped in 32-bit code listed two,
one of them `main`'s. Nothing about the image had changed between the two: what changed was
`GetEffectiveProcessorType`, which `scan_driver` passes to the scan as the mnemonic vocabulary and
which dbgscope's `decode_range` uses to pick the decoder's bitness. Decoded as x64, x86's
`ff 15 disp32` is a RIP-relative `call qword ptr [rip+disp]` rather than `call dword ptr [abs32]`,
so the operand's address lands nowhere near an import slot, and the scan reports a driver that
calls none of its sensitive imports -- the answer shaped like a clean image that the module's own
doc comment warns about, produced here by an ordering rather than by a target.

The same read is made by every scan on this seam -- `ioctl_map`, `xrefs_to`,
`reachable_from_dispatch` and the pool trace's own arm all take `e.instruction_set()` -- and the
image already in hand says what it is: `pe::read_image` has parsed its optional header, whose magic
is `pe::Bitness`. On a kernel target the two cannot disagree, one machine being the whole target;
on a WoW64 process they disagree at exactly the stop a `launch` hands back.

- **What would close it:** decode a scanned image by its **own** bitness rather than the stop's --
  which is a dbgscope primitive, since `decode_range` takes the engine's effective machine and
  offers no way to name one -- or, cheaper and narrower, refuse the scan when the image's machine
  and the effective one disagree, saying which stop would make them agree. The first is the fix;
  the second is what keeps the wrong answer from being an answer until then.
- **Why deferred:** item 121's measurement reads after the stop in 32-bit code and asserts the
  switch, so nothing checked in depends on the ordering, and no kernel target can reach it. It is
  a user-mode defect in tools whose subject is drivers.
- **Where it picks up:** `scan_driver` and the `instruction_set()` reads beside it in
  `src/worker.rs`; `DebugEngine::decode_range` in dbgscope, which would grow a bitness argument;
  and the measurement's own ordering comment in `tests/mcp_smoke.rs`, which is the reproduction.

## 128. [windbg-mcp] The TTD tier records whichever hostname the shell's PATH resolves

**What happens.** Three of the TTD tier's five tests ask `record_trace` for `hostname.exe` by bare
name — `ttd_records_a_target_that_finishes_inside_the_startup_watch_as_complete`,
`ttd_queries_answer_with_the_fields_they_promise` and
`ttd_a_replay_broken_in_at_its_bound_says_so_and_leaves_the_session_usable` — so which program is
recorded is whatever the PATH the harness inherited resolves. Launched from Git Bash, whose PATH
puts `/usr/bin` ahead of System32, that is Git's MSYS `hostname.exe`, and the third test fails its
own **control**: an unbounded `go` with a breakpoint on `ntdll!RtlExitUserProcess` runs to
`TTD: End of trace reached` instead of stopping. Measured 2026-10-13 on the x64 bench, on two
fresh recordings: the opened trace names `C:\Program Files\Git\usr\bin\hostname.exe`,
`ttd_calls ntdll!RtlExitUserProcess` returns nothing, and `ttd_calls ntdll!NtTerminateProcess`
returns one call from a `kernelbase` return address at `122A:176` — the Cygwin runtime terminates
the process directly and never passes the export the test breaks on. From PowerShell, which
resolves `C:\WINDOWS\system32\HOSTNAME.EXE`, the same five tests pass in 1.14 s.

**Why it matters more than a shell preference.** The other two tests pass on either binary — a
recording completes and a module base reads back whichever `hostname.exe` it was — so a green tier
from bash has recorded the wrong program for one of them and said nothing, which is the shape of
[#235](https://github.com/glslang/windbg-mcp/pull/235)'s relative-target finding and the reason
`ttd_resolves_a_relative_target_against_the_recorders_working_directory` asserts the trace's name.
And that fourth test already does the right thing: it copies its fixture from
`%SystemRoot%\System32\hostname.exe` by path, so the fix is three call sites catching up with the
one beside them.

- **What would close it:** name the System32 path at the three `recorded(...)` calls, from
  `SystemRoot` as the fixture copy does, so the recorded program is a property of the test rather
  than of the shell. The run from bash is the mutation check — it fails the control before and
  must pass after — and the `tiers` skill's "PowerShell, not `VAR=1 cmd`" line gains the reason it
  was missing.
- **Why deferred:** found during the release run of 2026-10-13, after the tier had been re-run
  green from PowerShell, and the fix is a test-only change that wants its own measured round
  rather than a line in a release-prep commit.
- **Where it picks up:** the three `recorded(&mut server, &out_dir, json!({ "target":
  "hostname.exe" }))` calls in `tests/mcp_smoke.rs`, and the `SystemRoot` join a few lines above
  the relative-target test's `std::fs::copy`.

## 129. [windbg-mcp] The live Secure Kernel tier takes a boot's coordinates from a private prep the KD gate discovers for itself

**What happens.** `a_live_secure_kernel_session_stops_steps_inspects_resumes_and_closes` makes
`vmwp_pid`, `dispatcher_vnd`, `partition_id`, `expected_cr3` and `instruction_address` **required**
in its config — `expected_cr3` may be `null`, which is what the one conformant prep writes, but the
key has to be there — and every one of them is a coordinate of one boot: the worker pid and the
partition change with each start, the dispatcher pointer with each worker, the root is whatever
the provider discovers, and the instruction is a VTL1 virtual address — the Secure Kernel's base
plus an RVA, and the base moves. The managed KD gate beside it (`managed_secure_kernel_kd_gate`)
**forbids** `vmwp_pid`, `dispatcher_vnd`, `partition_id`, `expected_cr3` and `kernel_base`,
"because discovering those is part of the gate", and has no instruction address to forbid: it
takes its instruction as a build-relative RVA with a byte guard from the profile's
`secure_kernel_kd.initial`. The server
treats the live opener's copies as assertions and resolves the worker from `vm_id` for both openers
alike (`skdispatch::resolve_vmwp_pid`, called from `open_sk_live_control` and `open_sk_kd`), so the
requirement is the test's, not the server's. The live tier is therefore runnable only through a
private prep under `target/private` that boots the VM, attaches `cdb` to `vmwp` and hijacks a
thread to read the dispatcher and partition, pauses the guest, samples both VPs' CR3 until they
converge, and writes the config.

**What that cost on 2026-10-13**, driving both tiers for the release run. Three such preps exist
and they disagree with the policy and with each other. `prepare_natural_flow_acceptance.py` writes
transports as bare `python … --partition-id 0x9d --expected-cr3 0x1201000`, which the 9 October
policy's templates — absolute interpreter, quoted paths, a `{partition_id}` placeholder, no
`--expected-cr3` — refuse as a near miss, so its output from 3 October is unusable.
`prepare_rust_adapter.py`, which the KD tier's post-release audit depends on, hands the sentinel
reader a module constant `EXPECTED_CR3 = 0x1201000` while that boot's VTL1 root was `0x2601000`
(the scheduler prep's convergence and hvlib's own `reported SK CR3` agreed); it was run through a
wrapper that discovers the root first. Only `prepare_scheduler_selected_acceptance.py` writes the
policy's form. The KD symbol-gate test has no prepared config — `symbol_path` appears in none — and
ran on one derived by hand (`arm_mode: natural`, a `srv*` path at the store holding the 26100.9457
`securekernel.pdb`) — and failed before its pipe was published, "the debugger wait reached its
deadline" after the opener's 60 s window, because the profile's guarded initial RVA `0xB12B` is
`securekernel!SkmiFreeNar+0x5cb`, a five-byte `nop` in the memory manager's NAR-free path that an
idle guest does not reach in a minute. Redirect mode fires on it at once by construction; a natural
stop needs an ambient entry, which is what the private runner arms and no KD config names. The
live tier's VTL0 half printed `NOT ASSERTED`, because no prep writes the
`vtl0_profile`/`vtl0_guest` pair item 124 needs. And the `cdb` hijack **killed `vmwp`** — the
runner's own comment records one earlier kill, as Hyper-V event 3040: right after the partition
discovery's `.detach /h`, `vmwp.exe` faulted `0x80000003`, Hyper-V logged event 14070 "quit
unexpectedly" and restarted the VM two seconds later on a new worker, and the prep died reading the
dead partition's registers (`HV_STATUS 0x000d`) with its bench stop swallowed. A retry worked. The
tier then passed on the retry's input in 39 s, and its audit — three healthy same-pid samples, both
VPs' debug registers back at baseline, TF/RF clear, the guarded text unchanged — passed too; every
workaround above is a measurement of the gap, not a fix of it.

- **What would close it:** give the live tier the KD gate's shape. Forbid the KD gate's five —
  `vmwp_pid`, `dispatcher_vnd`, `partition_id`, `expected_cr3`, `kernel_base` — and let the
  server's discovery supply them, as it already does for the opener; take the
  guarded instruction and its slots as RVAs with byte guards, resolved against the base the
  live-memory provider reports, the way `open_sk_kd` resolves the profile's `initial.rva`; and have
  the audit read the root the provider reported rather than a constant. The private prep then
  reduces to booting the VM, both tiers' configs become static files — including the symbol-gate
  one and the `vtl0_profile`/`vtl0_guest` pair — and the thread hijack that kills `vmwp` is not
  run at all, since the server discovers the dispatcher without it. `docs/smoke-test.md` then
  names the steps rather than "the bench's wrapper".
- **Why deferred:** it is a change to the tier's contract and to the address form `sk_live_arm`
  takes, with a run on the disposable VM per round, and the release run had a passing path through
  the workarounds. Item 122 (no image to resolve against) is adjacent: an RVA form is half of what
  it asks for.
- **Where it picks up:** `secure_kernel_live_tier` and the `required(...)` reads under it in
  `tests/mcp_smoke.rs`, against `managed_secure_kernel_kd_gate`'s forbidden list; `open_sk_kd`'s
  use of `secure_kernel_kd.initial` in `src/server.rs` and `skdispatch::discover_identity`; the
  VTL0 block the live test runs only when configured; and, outside the repository, the three preps
  and `run_k4_stop_step.py`'s `discover_dispatcher`/`discover_partition` under `target/private`.

## 130. [windbg-mcp] A transcript cannot be joined to the client's OpenTelemetry trace

**What happens.** Claude Code exports OpenTelemetry traces with a span per tool call — a beta, off
unless `CLAUDE_CODE_ENABLE_TELEMETRY=1` and `CLAUDE_CODE_ENHANCED_TELEMETRY_BETA=1` are both set —
and its monitoring page says *"Outbound HTTP MCP requests carry `traceparent`"* (read 2026-10-15).
So under `--listen` a `tools/call` can arrive carrying the W3C context of the client's span for
that call, and this server drops it: nothing reads the header, `Event::ToolRequest` has no field
for it, and a transcript record can be matched to the client's trace only by lining up wall
clocks. MCP has a convention for the same context in the request body — SEP-414, Final:
`params._meta.traceparent`, `tracestate` and `baggage`, deliberately unprefixed — and nothing here
reads that either. The two halves do not overlap. The client's span times the call from outside
and knows the prompt and model turn behind it; only this server knows which session the call was
routed to, the worker round trip, and the stops, mutations, batch rollbacks, timeouts and worker
deaths the transcript records.

**What is not proposed: a live OTLP exporter in the server.** Four reasons, each read against the
tree on 2026-10-15, and the derived form below avoids all four.

- **There is nothing span-shaped to export.** `src/` and `tests/` contain no `span!`, no
  `#[instrument]` and no `.instrument(`, so a `tracing-opentelemetry` layer in `init_logging`
  (`src/main.rs`) would ship log events with no trace structure; real spans mean instrumenting the
  supervisor by hand.
- **It would lose the transcript's crash property.** A batching exporter flushes at shutdown,
  while `Recorder::write` is one `write_all` per record so that an abrupt exit leaves whole records
  behind — and a worker death or a lost supervisor are the exits worth reading afterwards.
- **A collector endpoint is egress of debugger output**, which `docs/transcripts.md` says to treat
  like a crash dump. `kdconn::scrub` masks secrets, not memory, so an exporter would need a content
  policy of its own.
- **The OTel crates and an OTLP transport would join both builds**, the i686 worker's included.

- **What would close it:** two pieces, the first useful without the second.
  1. **Record the inbound contexts on `tool_request`, kept apart by where each came from**: the one
     in `params._meta` (SEP-414) and, on the listener, the one in the `traceparent` header, each
     kept as its whole `traceparent` value with any `tracestate` beside it — not as the ids parsed
     out of it, which would drop the trace flags and with them whether the client sampled the
     trace — and left out rather than recorded when it does not parse as the W3C format. They are
     two fields and not one
     because they are not the same thing: the OpenTelemetry MCP conventions (status
     *Development*, read 2026-10-15) treat the MCP and transport contexts as independent — one HTTP
     request can carry several MCP messages, and one message can take several requests — and say
     a server *"SHOULD, by default, use context extracted from MCP `params._meta` as a parent for
     MCP server span and SHOULD link current ambient context"*. No new dependency and nothing sent
     anywhere; a transcript record then carries the client's trace id, which `jq` can join on.
  2. **`windbg-mcp --render-otlp <transcript.jsonl>`**, a role beside `--render-cast` and derived
     the same way (`src/cast.rs`, *Derived, not written twice*). A session is a span from
     `session_open` to `session_end`. Each tool call is a span timed from `mono_ms`, with **one**
     parent: the `_meta` context where the call carried one, which puts it in the client's trace,
     and its session's span where it did not. A session outlives a prompt, so its calls can belong
     to several client traces, and no single span can parent them all. Every call therefore names
     its session as an attribute; a call parented in the client's trace also links to its
     session's span; and any call that recorded a header context links to that one, as the
     conventions' link to the transport. The derived records (`stop`, `mutation`, `batch`,
     `call_timeout`, `worker_lost`) are span events. The output is an OTLP/JSON file. Metadata
     only by default — tool, session kind, elapsed, verdict, category — with `args`, `text` and
     `data` behind an explicit flag, since the file exists to be sent somewhere.

  It closes on one Claude Code session driven over `--listen` with its traces on, whose rendered
  file reaches the client's span for the same call. **As Claude Code documents itself that is a
  link and not a parent**: it sends the header and says nothing of `_meta`, so by the conventions
  its context is the transport's, and a call carrying only that one stays under its session.
- **Why deferred:** the payoff is narrow, and nothing has asked for it — this was filed from
  reading Claude Code's OpenTelemetry docs, not from an investigation that needed the join. Claude
  Code sends the header only with the traces beta on, and by default only when
  `ANTHROPIC_BASE_URL` is unset or points at the Anthropic API (`CLAUDE_CODE_PROPAGATE_TRACEPARENT=1`
  overrides that). Its docs cover HTTP MCP requests only: they do not mention `_meta`, and of stdio
  servers they say only that `OTEL_*` variables are not passed to them — so a stdio registration
  gains nothing from Claude Code as documented, and piece 1 there waits on a client that implements
  SEP-414. Without the join, piece 2 is a timeline for what `--render-cast` and a `jq` over the
  JSONL already show.
- **Where it picks up:** **measure the premise first** — one `tools/call` from Claude Code with
  its traces on, through the listener, with the request's headers and `_meta` logged. The docs say
  the header is sent; nothing in this repository has seen one arrive. Then `call_tool` in
  `src/server.rs`, at its `self.rec.tool_request(tcc.name(), args.as_ref())`:
  `tcc.request_context` carries `meta`, and on the listener the HTTP request's `Parts`, which rmcp
  3.5.1 inserts into the request's `extensions` on both its stateless and session paths
  (`streamable_http_server/tower.rs`). Reading it there and not in `listen::gate` is for the reason
  `.claude/rules/listener-clients.md` gives about rmcp's spawned session task. The fields go on
  `Recorder::tool_request` and `Event::ToolRequest` in `src/record.rs`; the renderer beside
  `src/cast.rs`, selected in `src/main.rs` the way `cast::RENDER_FLAG` is; and both into
  `docs/transcripts.md`.

## 131. [windbg-mcp] The eval never runs a mutating tool

**Repo:** `windbg-mcp`. **Origin:** split out of item 39 when it closed on 2026-10-17, where it was
one of two things the grid's first run had left open. The other, that every timing in
`docs/local-model-eval.md` is one ARM64 Mac serving MLX builds, is a caveat rather than work, and
went into that document's *What this does not cover*.

The harness runs only what each tool's `readOnlyHint` allows (`adopt_fence` in
`tools/local_model_drive.py`), so `debug_batch`, `launch` and `execute` are offered and never run. A
model that picks one is recorded `refused_by_harness`. That is not a rare pick:

- **The 2026-08-23 grid:** gemma called `debug_batch` four times on a surface that does not serve
  it.
- **Both scenario runs of 2026-10-17:** both models reached for `execute` (`!devobj`, `dt nt!_IRP`,
  `dps`) and were refused.

A wrong pick there is expensive rather than wasted, since a batch that does run patches the target.

- **Why deferred:** running one needs a target it is safe to change and a way to show it was put
  back, and nothing the bench opens today is either. The samples are dumps.
- **What would close it:** a throwaway live target, either a launched process or a
  snapshot-restorable VM, with a rollback assertion after each run. `debug_batch`'s `always` block
  is the server's half of that assertion. That is the live-kernel tier's shape rather than this
  one's, so it likely wants a cell type of its own rather than a hole in the read-only fence.
- **Where it picks up:** `permitted()` and `ALLOW_ANYWAY`/`DENY_ANYWAY` in
  `tools/local_model_drive.py`, and `grade_record`'s `refused_by_harness` verdict, which is what a
  run of this kind would stop producing.

## 132. [windbg-mcp] No scenario has outgrown a model's own window

**Repo:** `windbg-mcp`. **Origin:** review of item 39's close on
[#504](https://github.com/glslang/windbg-mcp/pull/504), 2026-10-18. The close had reported a
transcript "2.4 times the window" that ended nothing, measured against the 32,768 `/api/ps` said it
served. That window is not what bounds a prompt on this runtime.

Item 39 was filed for the transcript filling the window, "the tenth turn of a kernel triage, three
large results deep", and its scenario never got there:

- **Both bench models' own window is 262,144** (`ollama show`), and the longest prompt in the ten
  scenario conversations was 122,107, 47% of it. With reasoning on, the peaks were 73,095 and
  63,926.
- **A smaller served figure is not enforced.** A cell `/api/ps` reported at 32,768 evaluated a
  79,352-token prompt and answered step 8 from text about 49,000 tokens before its end (ollama
  0.40.6, MLX builds). The 2026-08-23 grid found the same of a served 8,192. So on this runtime the
  window axis is one condition run twice, and the plan's two windows were exactly that.

What a transcript past the window does is therefore unmeasured: whether the runtime refuses the
request (graded `error`), truncates the front of the transcript and loses the surface or the early
facts (a break with cause `answer` at the first fact that needed them), or degrades quietly.

- **Why deferred:** it needs either a longer investigation or a smaller window that is actually in
  force, and neither existed when item 39 closed.
- **What would close it:** a scenario run whose prompt passes the window the runtime enforces, with
  `served_context` and the model card both recorded beside the break. Three routes, cheapest first:
  `muse-glimmer:30b-mlx`, already on the bench, whose card is 131,072, against which the off-arm
  qwen cell's 122,107 is 93%; more whole-table steps in `tools/eval_scenario.json`; or a runtime
  shown to enforce `num_ctx`.
- **Where it picks up:** `tools/eval_plan_scenario_reasoning.json` for the plan shape, and the
  break causes in `local_model_eval.grade_conversation`, whose `error` and `answer` are the two a
  window would produce.

## 133. [windbg-mcp] The live VTL1 driver and its providers live outside this repository

**Repo:** `windbg-mcp`, with the matching removals in `secure-kernel-lab` (sklab). **Origin:**
preparing sklab for a public push on 2026-10-30.

Every live Secure Kernel session runs two providers this repository does not carry,
`k4_control_provider.py` and `gpa_server.py`, over a driver it does not carry either, `h3probe.sys`.
All three are in sklab. They were kept out by item 103's standing decision that the repository
distributes no driver and the operator supplies the transport. Its reason was privacy, and that
reason ended when sklab was published on 2026-10-31. The plan keeps the rest of the posture: no binary is
distributed, the server never installs or starts a driver, and the providers stay child processes.

- **Why deferred:** it is eight phases, most of them with live runs on the disposable VM, and the
  path through sklab works today.
- **What would close it:** the final acceptance in
  [`docs/secure-kernel/h3probe-provider-plan.md`](docs/secure-kernel/h3probe-provider-plan.md).
  The policy admits `builtin:h3probe` and no interpreter; the live tier, the KD gate and sklab's M8
  acceptance pass on three fresh boots; and sklab's `src/` opens no device.
- **Where it picks up:** the plan's Phase 0, a protocol transcript and memory corpus from the Python
  providers on one boot. Item 129 removes one row of the plan's map outright: the coordinates sklab
  reads before an open.

## 134. [windbg-mcp] The transition drain faults on an unattributed `ntdll!DbgBreakPoint` stop in `vmwp`

**Repo:** `windbg-mcp`. **Origin:** an independent M8 qualification on K3, 2026-10-30, sklab run
`20261030T191050-validate-m8-3c21df` — exe SHA-256 `7081FACE…3942109`, `serverInfo`
`0.23.0+g30ebbdfc`.

**What happened.** The composite
(`a_managed_secure_kernel_kd_session_is_driven_by_this_servers_own_kernel_attach`) panicked with
`break-in cycle 6 produced no interrupted stop` after `wait_for_stop` ran its full 120 s. The cycle
counter is zero-based, so this was the seventh break-in on that boot, and the six before it had
completed. On the controller's side the Ctrl+Break was bound at 19:12:33.277, just as the free run
started. `pump_pending_transition_before_pause` then began draining the prior cycle's Hyper-V
transition. It pumped `vmwp` for 2.65 s and carried one foreign event at the site at 19:12:35.928.
Then it failed with `vmwp stopped at 0x7ff870603f40 for an event the live-control adapter does not
own while draining the prior Hyper-V transition`. The qualification report resolves that address as
`ntdll!DbgBreakPoint`; the log carries only the address.

Recovery then ran, in this order:

- a second pump;
- a VM pause;
- DR7, DR6 and RFLAGS written back to baseline;
- the site breakpoint removed, with its original bytes verified;
- a handled detach and a resume.

It logged `recovery_errors=0, target_left_paused=false`, and the controller session reached
`released` at 19:12:42.839. The VM passed the next 60-second audit. Item 135 is what happened to the
public session afterwards.

**What is not known: whose break it was.** The error records the RIP and nothing else: no thread, no
exception code and no `.lastevent`. So this run cannot attribute the stop. The leading hypothesis is
that the stop was the adapter's own:

- Each `g` the pump issues is a bounded wait of `DISARM_PUMP_SLICE`, 250 ms.
- dbgscope ends a wait that reaches its bound with `SetInterrupt(DEBUG_INTERRUPT_ACTIVE)`
  (`break_in_only`).
- On a running user-mode process, DbgEng usually delivers that as a break-in thread that executes
  `ntdll!DbgBreakPoint`. That delivery has not been measured on `vmwp` here.
- If a slice's deadline break was raised just as the site event arrived, the wait would return for
  the event and leave the break queued for the next `g`.
- That `g` would then stop with no `cut_short`, which `transition_pump_step` maps to `UnownedStop`.

The shape fits: about ten silent slices before the carried event, and 4 ms between that event and
the recovery's pump. That does not establish it.

The pump already drains one queued event of exactly this kind, `queued_owned_native_return_event`:
DbgEng's native-return breakpoint, removed but already queued. The other candidate is the KD
break-in's own `SetInterrupt` (`kdtarget::WaitWaker::spawn_interrupt`). The log does not say whether
cycle 6's wake went that way, or took the path `WaitActivity::enter` returns without an interrupt.

- **What would close it:** first, make the stop attributable. `UnownedStop` should carry the event
  as fields: the thread id, that thread's start address, the exception code and the first-chance
  flag. A RIP in prose is not enough. This applies to this pump and to the running disarm's
  `disarm_pump_step`, which has the same `(None, _)` arm under the same slices.

  If the next occurrence turns out to be the engine's own break-in, consume it handled, the way the
  native-return drain does. Match it on what makes it provably this adapter's: a DbgEng break-in
  thread at `DbgBreakPoint`, after a deadline break this pump raised. Every other stop stays
  fail-closed. If it is not the adapter's, the item becomes the question of what raised a breakpoint
  in `vmwp`.
- **Why deferred:** the failure fails safe: recovery restored the target and the audit passed. It has
  been seen once in 57 free-run break-ins attempted under that build. That count is the six before
  it, the failure itself, and 25 on each of the other two composite boots under the build. Boot 1's
  25 ran under a different build, which the origin record below explains. A drain matched on a
  guess could consume a stop that belongs to someone else, so the attribution comes first. M8's
  acceptance in [`docs/secure-kernel/m8-debugger.md`](docs/secure-kernel/m8-debugger.md) (three
  clean boots, 75/75) is a pass on three boots, not a failure rate.
- **Where it picks up:**
  - `pump_pending_transition_before_pause`, `transition_pump_step` and `disarm_pump_step` in
    `src/skdispatch.rs`, with `queued_owned_native_return_event` as the precedent;
  - dbgscope's `break_in_only`, for how a slice ends;
  - lines 1425–1495 of the run's `m8-composite.stderr.log`, for the sequence.

## 135. [windbg-mcp] A Secure Kernel debugger's public peer is kept unresolved after its controller has released

**Repo:** `windbg-mcp`. **Origin:** the same run as item 134.

**What happened.** `open_sk_debugger` opens two workers as one session:

- a hidden controller that serves the KD facade (`sess-18e364629d231a58-1`, worker pid 2168);
- the public DbgEng peer the caller drives, attached to the facade's pipe (`sess-18e3646353bd376c-2`,
  pid 7824).

When item 134's fault ended the KD service, the controller recovered. The supervisor recorded its
session as `releasing` at 19:12:37.485 and `released` at 19:12:42.839. Nothing told the peer, whose
run `exec-18e36478160034f0-8` went on waiting on a pipe whose server had gone. After its full 120 s,
`wait_for_stop` answered that the run's bound had passed and "a stop is on its way". None came.

`end_session` followed 6 ms later. It set `kernel_unresolved` and waited out its 60 s budget with no
reply from the worker. It then returned `recovery_required: true, released: false`, with automatic
termination refused and pid 7824 retained. The qualification cleared that worker by exact-PID
recovery. The transcript is the run's `mcp.jsonl`, sequence numbers 104–115.

**Why this is a gap rather than the preservation rule working.** Keeping the worker is right for a
remote kernel the server cannot see. Here the server holds the evidence itself.

`release_tree` (`src/engine.rs`) releases the public peer first, because dropping the facade first
"severs the KD pipe under DbgEng and turns an orderly detach into an ambiguous kernel failure". The
peer's only route to the target is that pipe into its companion controller. This run reached the
order that comment guards against, from the other side: the controller ended on its own and severed
the pipe. What the controller confirmed on the way out is the state the peer's preservation exists
to protect: DR7 and DR6 at baseline, the original bytes verified, a handled detach and the VM
resumed.

Two separate things went wrong:

- the peer was not told that its companion had ended, so a caller waited two minutes on a stop that
  could not arrive;
- its release was judged as if the target were unknown.

The worker's wait on the severed pipe did not return in the 60 s after the run's bound had broken it
in (by `wait_for_stop`'s own account).

- **What would close it:** when a companion confirms its release, end the public peer's run with a
  stop that says so: `target_gone`, or a typed reason naming the controller's outcome. Then decide
  the peer's teardown from that outcome rather than from its own unanswerable wait.

  Whether the peer worker can then be terminated with nothing left to recover is a claim to test,
  not to assume. The worker holds a DbgEng kernel client over a pipe to a process that has already
  detached. "Terminating it touches nothing on the target" is the kind of fails-safe sentence
  `.claude/rules/measurement-provenance.md` says needs a test. A controller that ended *preserved*,
  rather than released, must keep both workers, as it does today.
- **Why deferred:** it changes the composite lifecycle that `.claude/rules/session-teardown.md`
  binds. Only a controller fault reaches this case. A fake-provider test can stage the order, but
  the "nothing left to recover" claim needs a live run.
- **Where it picks up:**
  - `release_tree`, `open_secure_kernel_debugger` and `preserve_composite_controller` in
    `src/engine.rs`;
  - the controller's session transitions, which the supervisor already records;
  - [`docs/sessions.md`](docs/sessions.md), for the preservation contract a change must keep.

## 136. [windbg-mcp] Dispatcher discovery waits sixty seconds for one arrival that sometimes never comes

**Repo:** `windbg-mcp`. **Origin:** the same qualification's fault-gate block, sklab runs
`20261030T214508-fault-debugger-loss-3240d2` and `20261030T215010-fault-identity-change-0fa73d`.

**What happened.** `discover_identity` (`src/skdispatch.rs`) runs these steps:

1. pause the VM;
2. attach to `vmwp`;
3. plant a breakpoint at the profile's discovery entry, `vmwp+0x2c360`;
4. start a Resume on a helper;
5. run `vmwp` toward the breakpoint for `DEBUG_WAIT`, which is 60 s.

Both runs failed at step 5. The Resume completed and was verified, but no dispatcher thread reached
the entry, and the wait expired with `the debugger wait reached its deadline`. Discovery then
removed the breakpoint with its original bytes verified, detached with the event handled and
resumed the VM. `vmwp` was not lost and nothing was retained, unlike the `cdb` discovery that item
129 records killing `vmwp`.
Each gate passed on its next fresh boot.

**The arrival is all-or-nothing, so a longer bound would not help.** The evening ran twelve
standalone `--sk-discover-identity` discoveries:

- the ten that passed reached the entry 0.10–0.19 s after the Resume was verified;
- the two that failed reached nothing in 59.65 s.

Discovery depends on one callback that the Resume normally provokes at once, and on those two boots
it provoked none.

Nine of the twelve ran under the qualified exe (`7081FACE…`), and both failures are among those
nine. The other three ran under `12C827C8…`. The same function also runs inside each opener: the
seven in-process discoveries in the four `validate.m8` runs under `7081FACE…` all reached `arming`
in 1.4–2.0 s.

Both failures came straight after a fault gate that ended faulted. The first followed a provider
death that left the target paused. The second followed an injected debugger loss. With n=2 that is
an ordering to check against the gates before the successes, not a cause.

This is a second case of the problem item 129 recorded on 2026-10-13: a stop that needs an ambient
entry, which an idle guest may not supply. There it was a guarded VTL1 RVA; here it is `vmwp`'s own
dispatcher.

- **What would close it:** discovery that does not hinge on one arrival. There are two routes:
  - Provoke a callback discovery can count on: re-kick the VM transition from a helper while `vmwp`
    runs under the planted breakpoint. The kick comes after a bound well above the 0.19 s worst
    success and well below 60 s, with a fixed number of kicks. It must not happen with `vmwp`
    debugger-stopped, which `.claude/rules/secure-kernel-live.md` forbids.
  - Or find out why the Resume provoked no callback on those boots.

  Either way, record at the deadline what each `vmwp` thread was doing and what Hyper-V reported for
  the VM, so the next failure shows which of the two it was.
- **Why deferred:** the failure fails safe, and a retry on a fresh boot passed both times. The kick
  also changes the order of Hyper-V calls around a debugger-held process, which needs live runs on
  the disposable VM.
- **Where it picks up:**
  - `discover_identity`, `run_to_current_breakpoint` and `VmTransition` in `src/skdispatch.rs`;
  - the completion kick the transition drain already issues from a helper (`COMPLETION_KICK_AFTER`),
    as the precedent;
  - the two runs' `k4-auto-k3-sk-live-identity.log`.

## 137. [windbg-mcp] The shadow-stack half of stack lineage has not run against a CET target

**Repo:** `windbg-mcp`. **Origin:** building `stack_lineage` on 2026-10-31
([`docs/stack-lineage-plan.md`](docs/stack-lineage-plan.md) §6.2).

`stack_lineage` compares each return address with the thread's hardware shadow stack, read through
the engine's `ssp` and `cetumsr` registers and `read_memory`. Every rule of that comparison is a unit
test on synthetic entries (`lineage::tests`), and **none of it has met a real shadow stack**: the
debugger guest is ARM64, which has no `ssp` register at all (measured, "bad register"), and the x64
samples were written by emulated processes whose extended context records XSTATE features `0x7` —
no `CET_U` — and read `ssp=0`. So the tier measures the `unavailable` half on every sample and the
`compared` half nowhere.

- **Why deferred:** it needs an x64 host with hardware-enforced stack protection on, and this bench
  has none.
- **What would close it:** on such a host, a small x64 fixture with a control arm (ordinary nested
  calls, paused at a breakpoint: expected `consistent`, every frame `matched`, slots in order) and a
  planted arm (a return address pushed with no call, paused before the `ret` that would fault:
  expected `suspicious` with `missing_from_shadow_stack` on that frame), run live and from a full
  dump of each. Four things are measured on the way, each of which the design assumes: that
  `integer_register("ssp")` and `"cetumsr"` answer non-zero for a CET-enforced thread, live and from
  a dump that recorded `CET_U`; that the shadow-stack pages read; that a stack through
  `KiUserExceptionDispatcher` matches with the dispatcher's frame exempt; and that a restore token
  is where the read stops. The fixture is a detector's ground truth, a paused process the tool
  observes, and is not to be grown into anything else.
- **Where it picks up:** `worker::observe_shadow_stack`, which is the only code between the engine
  and the tested rules.

## 138. [dbgscope + windbg-mcp] Stack lineage recognises a dispatcher by name, not by its unwind record

**Repo:** `dbgscope` for the primitive, `windbg-mcp` for the adoption. **Origin:** building
`stack_lineage` on 2026-10-31.

The frame under an exception, APC, callback or trap dispatcher is an interrupted PC rather than a
return address, so no call ends at it and the CPU pushed nothing for it. `stack_lineage` exempts it
(`resumed_context`) when the frame above is a `Ki*` routine of `nt` or `ntdll` — a curated rule,
applied only where the bytes have already failed to show a call. The fact itself is in the unwind
record: `UWOP_PUSH_MACHFRAME` on x64, and on ARM64 the custom trap-frame code `E8` that `.fnent`
shows for `nt!KiArm64ExceptionVectors` (measured on `082126-7015-01.dmp`). A dispatcher the rule
misses makes the frame under it `not_preceded_by_call`; a module with no symbols makes every one of
them miss.

- **Why deferred:** reading the record needs a primitive dbgscope does not have.
  `DebugEngine::function_extent` consumes the raw entry and returns only the region.
- **What would close it:** a typed dbgscope method returning the unwind record's machine-frame /
  trap-frame fact for an address (x64 and ARM64, the two layouts `function_extent` already decodes),
  and `lineage::resumes_context` reading it instead of the name.
- **Where it picks up:** `lineage::resumes_context`.

## Where these items came from

Each cluster above, and what filing it measured. Items named here as *"now in `DONE.md`"* have
closed since this record was written, and the record is kept with them in it: what a cluster was
filed against is most of why the items left in it are worded the way they are.

Grouped by origin: items 2–6 — item 4 now in [`DONE.md`](./DONE.md) — come from the
reachability-confirmation effort (path
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
the window and the model as a **grid** rather than as a sighting (2026-08-23; item 39 now in [`DONE.md`](./DONE.md)) — item 35 from
measuring what a `registers` answer is actually made of (2026-08-22), item 47 from fixing
[#226](https://github.com/glslang/windbg-mcp/issues/226), where making every target take the bounded
wait left one target type nobody on this bench can measure (2026-08-25 — now in
[`DONE.md`](./DONE.md), measured on 2026-10-13), item 50 from Windows
Defender quarantining this project's own binary while the 32-bit worker was being tested
(2026-08-26), items 52–53 from [#83](https://github.com/glslang/windbg-mcp/issues/83)'s asynchronous
execution handles, where the invariant that stops a description naming a tool its client cannot call
turned out to cover only half the prose a client is served (2026-08-29 — item 52 is now in
[`DONE.md`](./DONE.md), the other half having been walked on 2026-10-05, which found eleven leaks
where the entry recorded one), and where a break arriving
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
item an earlier round of it had produced (2026-09-13; 69 is now in [`DONE.md`](./DONE.md)), and
item 71 from `driver_surface`, the
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
lost at the `add`, **now in [`DONE.md`](./DONE.md)**, closed 2026-10-04 by modelling
`Value::Address + immediate` in that `add` -- plus the width guard the entry had not asked for,
without which the same arm hands the resolver a base execution never formed. That run filed five
more, which are in [`DONE.md`](./DONE.md) as well -- the literal pool the fact walk could not read (item 82, which was the
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
item 92 from item 85's lane finding a driver the two implementations disagree about
(2026-09-20) -- A64 writes `a || b || c` as three compares feeding one branch, and this walk read
the last of them and filed the rest in `untracked` -- is **now in [`DONE.md`](./DONE.md)**, closed
2026-10-02 by reading the `nzcv` immediate the chain carries rather than by folding conditions; the
companion's half of that disagreement is open in its own repository, so the lane's answer for that
driver now differs in the other direction. And item 94 from giving the multiprocessor hypervisor
investigation's harness the tools it was written against (2026-09-20) -- that investigation is
item 93 and is now in [`DONE.md`](./DONE.md): a typed breakpoint listing and removal landed, and
`bd`/`be` deliberately did not. And item 97 from running the heap tools on ARM64 for the
first time ([dbgscope#177](https://github.com/glslang/dbgscope/pull/177), 2026-09-23), with the
target's own `HeapWalk` as the oracle: an LFH block awaiting a delayed free, which `HeapWalk`
calls free and the heap tools call allocated. That run filed two more, both now in
[`DONE.md`](./DONE.md) — item 96, the pool walker's LFH reading, which it showed is not `nt`'s,
and the ARM64 pool gate behind it; and item 98, the uncommitted memory that kept every live walk
measured at `Partial` once the diagnostics were gone, which turned out to want the memory
manager's answer rather than the allocator's. And item 105, now in [`DONE.md`](./DONE.md), from review on that item's PR after it had merged (2026-09-27): the
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
walker to fix, and is measured and declined; item 101 was a real placement defect in readable
memory — not a drift of the chain but the allocator moving a user block off a page end under a
flag the walk had never read — closed 2026-10-14 and in [`DONE.md`](./DONE.md).
And item 110 from the 2026-10-01 VTL1 controlled-stop probe (item 103's control axis): stopping and
resuming real `securekernel.exe` image code on a partition we own does not reach an *initialized*
Secure Kernel, and the route that would needs the experiment to own a Windows/VBS boot — filed as a
decision with its falsification first, because its one unvalidated step is likely to close it.
**Item 103 closed on 2026-10-02 and is in [`DONE.md`](./DONE.md)** — the Secure Kernel capture route
with its four tools, plus a live source since gate S5w, plus the four attempts that had kept it open.
What decided the close was the **route** rather than the deliverable: inspection of VTL1 kernel mode
is complete in both directions, and a controlled stop inside a *real* guest's Secure Kernel has no
mechanism on a VM Hyper-V manages — so the realistic route is to own the boot, which is **item 110**.
Its last two arms are declined on that ground rather than left open, each with the condition that
reverses it, and exactly one moved to 110. Two drafts of that entry's status got the close wrong in
opposite directions and both are recorded in it.
And item 113 from closing item 69 on
[#458](https://github.com/glslang/windbg-mcp/pull/458), where a review finding read the sweep's
"other 141" as a typo for 142 and reading the commit that first recorded the figures showed all
three written that way on the day — so what the close could record was the gap, and what it could
not do from a Mac was settle which of the three is wrong (2026-10-06).
And items 115–119 from the 2026-10-07 review of the whole VTL1 surface — items 115, 116, 118 and 119 are now
in [`DONE.md`](./DONE.md) — capture decode, live
control, and the KD facade [#463](https://github.com/glslang/windbg-mcp/pull/463) had merged the
day before — read against `main` with the private bench runs beside it: a facade that shipped with
no operator-facing record of itself and six statements the code had moved past (115); the answers it
invents for WinDbg and cannot mark as invented (116); a pipe any local account can open, three
inputs that end the session instead of being refused, and a break-in that only faults (117); the
live-control tools being default-on, running client-supplied programs, and holding a guest paused
with no bound (118); and the distance from one guarded `t` to a debugging session, filed as one
ordered ladder rather than a defect per rung (119). The review itself is private, under
`target/private/`, because it cites the bench's runners and logs.
Item 121 came from review round 1 on [#473](https://github.com/glslang/windbg-mcp/pull/473)
(2026-10-09), the pool allocation trace, which read x64's argument registers on any target that was
not ARM64; the round refused x86 and filed the reader it would need. The reader landed on
2026-10-13, measured on a 32-bit user-mode process for want of an x86 kernel, and the item holds
the live half. Item 127 came out of taking that measurement: the scan's first answer at a WoW64
launch's initial break listed the import with no call site, because the stop's effective machine
and not the image's decided the decoder.
Item 120, now in [`DONE.md`](./DONE.md), came from checking that review against the stated product
goal the same day: the standalone KD role and the MCP live-control session were alternative owners,
so the server could not create, observe or release the WinDbg-facing session it presented to an
operator.
Items 122–124 came from the first live VTL1 stop/step runs driven through the seven live tools
(2026-10-10), the day the `secure-kernel-live` rule was written from them: a session with no image
to resolve names or instruction lengths against (122), a step refused at the instruction that
changes CR3 rather than carried over it (123), and a review of what a passing run actually
establishes, which found that every assertion is of the Secure Kernel being *readable* and none of
the memory being *protected* (124). Items 123 and 124 are now in [`DONE.md`](./DONE.md).
Item 125 came from closing item 47 (2026-10-13): asking whether a replay can be broken in at its
bound found that it can, and that TTD then leaves it somewhere it never reached.
Item 126 came from closing item 105 the same day: the `||1s` failure item 102 could not explain
had a reason all along, which `cdb` prints and this server did not pass on — now in
[`DONE.md`](./DONE.md).
Items 128 and 129 came from the release test run of 2026-10-13, which ran every tier including the
four live ones: the TTD tier failing its own control when launched from Git Bash, which had
recorded the MSYS `hostname.exe` (128), and the two Secure Kernel tiers being reachable only
through private preps whose boot-specific values, policy shape and thread-hijacking discovery each
cost a workaround that day (129). The same run found the capture tier red since the 9 October
hardening narrowed its server's surface, fixed on
[#494](https://github.com/glslang/windbg-mcp/pull/494).
Item 130 came from asking, on 2026-10-15, whether this server should export OpenTelemetry now that
Claude Code does: the answer was the inbound context recorded and a renderer rather than an
exporter, and the item records why, together with what Claude Code's documentation does and does
not promise to send.
Item 131 came from closing item 39 on 2026-10-17: of the two things its first run had left open,
measuring the mutating tools is work and needed an entry of its own.
Item 132 came from the review of that close on 2026-10-18, when the window its runs were measured
against turned out not to be the model's, and nothing in them had come within half of the model's.
Item 133 came from preparing `secure-kernel-lab` for a public push on 2026-10-30: with the driver
and both providers about to be public there, the privacy that had kept them out of this repository
no longer did.
Items 134–136 came from an independent qualification of the M8 debugger and the h3probe-only bench
on K3 on 2026-10-30. It passed its functional gates and filed three reliability findings:

- boot 2's composite faulting in the transition drain on a stop nothing owned (134);
- the public peer that this fault left unresolved after its controller had released (135);
- two discoveries that timed out before their fault gates began (136).

Boot 2's failure is two items rather than one because its halves close independently, in different
files.

The qualification named one build: exe SHA-256 `7081FACE…` at HEAD `30ebbdfc`. But the tree was
dirty, and two builds reported that HEAD. The evening's first eight runs, through
`20261030T185815-validate-m8-ebc6a9` (the first of its four composite boots), ran under
`12C827C8…`, and what differed between the two builds is not recorded. Under the named build there
were three composite boots, two of them clean.

The four commits since then (`eae8cea0`–`052e6ff5`) change a doc comment in `src/livesrc.rs` and a
test bound in `tests/mcp_smoke.rs`. They touch no server code path, and the qualification did not
cover them.

Items 137 and 138 came from building `stack_lineage` on 2026-10-31: its shadow-stack comparison is
unit-tested and has never met a real shadow stack, because no machine on this bench has CET (137),
and the frame under a dispatcher is recognised by a curated `Ki*` name rule where the unwind record
holds the fact (138).
`DECISIONS.md`'s 2026-08-02 entries are the bounded-command coverage review that produced
item 13, now in [`DONE.md`](./DONE.md).
