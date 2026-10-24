# Secure Kernel call-debugging roadmap

## Outcome

Build a guarded debugger workflow that can stop on real VTL0-to-VTL1 secure-service traffic,
inspect the VTL0 caller, hypervisor transition and VTL1 callee, resume to another meaningful
event, and break in on demand. The intended investigation combines the debugger loop in
[LiveCloudKd's live-debugging guide](https://github.com/gerhart01/LiveCloudKd/blob/master/ExdiKdSample/LiveDebugging.md)
with the cross-layer call analysis in
[Dor00tkit's Secure Kernel investigation](https://dor00tkit.github.io/Dor00tkit/posts/debugging-the-windows-hypervisor-inspecting-sk-calls/),
while keeping this repository's existing worker isolation, exact-build guards, bounded pause and
restoration rules.

The useful end state is not merely a WinDbg prompt. It is a correlated record such as:

```text
call_id  vtl0.thread  vtl0.site                 hypercall       vtl1.service
42       ...          nt!VslpEnterIumSecureMode HvCallVtlCall   IumInvokeSecureService
         service=...  input=... output=...       vp=...          dispatch=... status=...
```

WinDbg is one possible front end for that record. EXDI is optional and does not gate the
controller or the investigation.

## Constraints learned from the current rig

- The Secure Kernel does not provide a usable native KD transport on the measured build. The
  current debugger is a facade over root-partition register control, protected-memory reads and a
  guarded `vmwp` dispatcher hook.
- A live controller session owns one disposable VM and one worker. DbgEng stays on that worker's
  engine thread; the supervisor never touches it.
- Hardware execution breakpoints remain the primary VTL1 mutation primitive. M3 proved guarded,
  one-shot software breakpoints for the single-vCPU Secure Kernel controller, and M5 separately
  proved DbgEng-owned software breakpoints in the hypervisor. Neither result authorizes general KD
  memory writes, multiprocessor patching or reuse of one layer's restoration proof in another.
- Every stop and transition is tied to an opaque epoch, exact instruction bytes, VM identity,
  partition, VP, VTL and CR3. Stale coordinates are refusals, not best-effort operations.
- The 2026-10-18 `g` qualification is a failed facade gate: after WinDbg armed
  `securekernel!KiTimerInterrupt`, the next VTL1 stop was not observed and K3 reset. The KD facade
  continues to refuse non-trace requests. M1 and M2 subsequently passed on the direct controller;
  routing WinDbg onto those proved paths is M8 and requires its own packet-race and recovery gate.
- Break-on-demand cannot be emulated by an arbitrary cross-thread DbgEng call. `SetInterrupt` is
  used only during the worker's explicitly scoped owned-event wait; target-side interruption needs
  a separate controller primitive.
- K3's large running footprint is a lab issue, not debugger evidence. Before repeated destructive
  runs, record fixed/dynamic VHDX layout, checkpoints, VMRS/runtime memory, pagefile and smart
  paging separately. Do not “fix” storage by deleting state during debugger qualification.

## Architecture

```text
PowerShell / MCP client / optional WinDbg facade
                    |
              supervisor (no DbgEng)
                    |
        one live-control worker process
          | engine thread: vmwp DbgEng
          | provider child: VTL1 registers
          | memory child: VTL1 page-table reads
          ` dispatcher hook: retain/release vector-1 event

separate sessions, joined only by typed trace records:
  VTL0 KDNET worker ---- hypervisor KDNET worker ---- VTL1 live-control worker
```

No phase may create a shared multi-target DbgEng process. Cross-layer correlation happens above
the workers using timestamps, VP, thread/call identifiers and decoded arguments.

## Event contract

The correlation layer will consume versioned structured events rather than debugger text. The
initial schema is:

- identity: schema version, session id, target boot id, build/hash, VM id, partition, VP and VTL;
- position: monotonic host timestamp, target RIP, symbol plus displacement and stop epoch;
- VTL0 call: process/thread, secure-service number and argument pointers captured at
  `VslpEnterIumSecureMode` (or the exact build's equivalent);
- hypervisor transition: hypercall code, intercepted VP/VTL state and, where a supported
  architectural debugger API can read them, saved guest RIP/CR3 values; otherwise the exact VMCS
  fields and physical coordinates plus an explicit `coordinate_only` availability state;
- VTL1 dispatch: service number, SSCN/dispatch target, arguments, return status and selected
  memory snapshots;
- provenance: which fields were measured, symbol-derived or inferred, with read failures retained
  as fields rather than silently omitted.

Addresses never stand alone across boots. Persistent coordinates are module identity plus RVA,
resolved to a VA only after that boot's module base is proved.

## Milestones

### M0 — freeze the safety and evidence contract

Status: complete. These constraints remain invariants for every later milestone.

- Preserve the worker/process/thread ownership rules above.
- Keep KD `g`, KD-originated software breakpoints and arbitrary register writes refused until their
  own later gates. M3's direct-controller software-breakpoint path is a separate, policy-gated
  capability.
- Treat K3 as disposable, but require a post-run health and debug-register audit.
- Use deterministic guest workloads; timer interrupts are not an acceptance workload.

Exit: this document, existing provider/dispatcher contracts, and the live-control policy name the
same authority and cleanup boundaries.

### M1 — repeatable VTL1 run/break/run

Status: complete as of 2026-10-20.

Deliver a direct MCP loop over natural hardware execute breakpoints. The first qualification
surface accepts exactly one selected VP; re-arming a multi-VP session needs a new VM-wide
quiescence proof and is refused without consuming its held stop.

1. from a held epoch, verify replacement instruction bytes before changing state;
2. restore the old owned debug state and install the replacement DR set while the event is held;
3. release to running, end the old pause accounting, then use the existing interruptible
   `sk_live_wait` as a distinct job for the next stop;
4. on no-hit, timeout or validation failure, prove baseline restoration and leave the VM running
   or retain ownership fail-closed with an explicit recovery result;
5. expose the transition in MCP, but do not route KD `g` to it yet.

The two jobs are intentional. The transition is non-interruptible while registers and the retained
event are being changed. The following wait is interruptible. Combining them would allow a
Ctrl+Break to land during mutation, violating the worker contract.

Live qualification uses a build-guarded site reached by a deterministic guest action (prefer
`IumInvokeSecureService` or its measured caller path), not `KiTimerInterrupt`. It must pass:

- 100 consecutive stop/resume cycles in one boot;
- the same test across three clean boots with coordinates re-resolved each time;
- stale-byte, stale-epoch, no-hit/timeout and forced-teardown cases;
- final DR0–DR3/DR6/DR7/RFLAGS equality with the saved baseline;
- K3 uptime/identity unchanged, no unexpected reset, and no retained `vmwp` debugger attachment.

Those checks authorize M8 to translate WinDbg `g` into this path; they do not make that packet
translation safe by implication. M8 separately tests KD packet ordering, running break-in,
disconnect and teardown races before the facade's refusal is removed.

Qualification record (machine-local raw evidence under ignored `target/` paths):

- `target/codex-m1/forced-teardown-probes/20261020T135835` proved teardown from a
  naturally held `KiSystemCall64` stop: the provider baseline and event were released, the worker
  was terminated, and K3 was left running.
- `target/codex-m1/m1-qualification/20261020T135928` passed 300/300 transitions: 100 cycles on
  each of three clean boots, with distinct `vmwp` processes, partition ids, Secure Kernel bases
  and guest boot times.
- Boot 1 passed stale-epoch, stale-byte and no-hit timeout cases. Boot 2 passed forced teardown.
  Every cycle ended with exact DR0-DR3, DR6, DR7 and RFLAGS restoration, released ownership and a
  running target. No boot reset or retained `vmwp` debugger attachment was observed.
- The fixed VHDX length remained 13,281,263,616 bytes. Runtime free-space changes followed the
  running VM's memory state and were reclaimed by the clean-boot shutdowns; the qualification did
  not grow the disk image.

### M2 — break on demand

Status: complete as of 2026-10-20.

Add a target-side break request that can stop a naturally running VTL1 session without depending
on a preselected code address. First prove the exact build's supported request path; if none exists,
use a guarded transient hardware-breakpoint strategy with a bounded rendezvous. The request must be
job-bound, race-tested against stop arrival and teardown, and must not broaden the one documented
cross-thread DbgEng exception.

Exit: break requests in running, already-stopped, teardown and timeout races each have a unique,
tested result and restore the complete baseline.

The first implementation slice adds direct `sk_live_break`: for one naturally armed VP it proves
a VM pause, samples RIP/CR3, guards a transient execute breakpoint at that instruction and reuses
the ordinary bounded vector-1 wait. The second binds a request racing an in-flight `sk_live_wait`
to that exact worker job. The request reader uses scoped `SetInterrupt` only to leave the host
wait; the engine thread performs the pause, register writes and target-side rendezvous, and both
callers receive the same retained epoch. A natural event already at the owned dispatcher site wins
the race and keeps its `hardware_breakpoint` reason. Teardown also wakes that scoped wait so the
controller can run its proved recovery before release.

Offline tests cover a transient hit, the job and result-publication race bindings, a natural
breakpoint winning the request race, an already-stopped refusal that preserves its epoch, and
no-hit recovery with exact baseline restoration. The request reader is the race's linearization
point:

| First fact observed | Break result |
|---|---|
| An active `sk_live_wait` claim | Bound to that job; both calls return its exact stop epoch |
| A natural stop while the bound request is waking the wait | The same retained stop with `hardware_breakpoint`; no transient reason is invented |
| The bound wait's timeout or recovery failure | The same error category and cause, plus a note that no second rendezvous ran |
| A retained stop after the wait claim was released | Direct already-stopped refusal; the retained epoch is unchanged |
| `end_session` read first | `stale_session` refusal from the reader; no interrupt or target mutation occurs |

If the break is read first, it is accepted and teardown later releases whatever stop it produces.
If teardown is read first, teardown wins and the break is refused. A second break cannot replace a
request already bound to the wait; it queues normally and observes the stopped or faulted state
left by the first.

M2 implementation slices:

1. **Direct rendezvous — complete:** add the guarded transient-break operation and its typed stop
   reason.
2. **Job-bound wake — complete:** route a break request racing `sk_live_wait` to that
   exact wait, never the operation before or after it.
3. **Race contract — complete:** distinguish natural stop won, already stopped, teardown,
   timeout and request-accepted outcomes without consuming a retained epoch accidentally.
4. **Live qualification — complete:** repeat running, already-stopped, timeout and teardown races
   on one live boot, with final debug-state, attachment, VM identity and uptime audits.

Qualification record (machine-local raw evidence under ignored `target/` paths):

- `target/codex-m2/live-qualification/20261020T173513` passed the concurrent break, timeout,
  teardown and complete debug-state audit on K3.
- The concurrent request interrupted its exact owned wait and both callers received the same
  `break_request` stop epoch. A second request refused the retained stop without replacing it,
  after which continue and teardown released the session normally.
- The timeout case entered fail-closed recovery, refused a later break against the faulted
  control, and ended with the target running. In the teardown-first race, teardown interrupted
  its exact wait and the later break returned `stale_session` without filing an interrupt or
  starting a target-side rendezvous.
- DR0–DR3, DR6, DR7 and the complete RFLAGS value exactly matched the pre-test baseline. The VM
  remained running with a healthy heartbeat, the same `vmwp` PID and the same immutable
  Kernel-General boot-event identity while Hyper-V uptime advanced. The audit deliberately uses
  that boot event because `Win32_OperatingSystem.LastBootUpTime` moves after Hyper-V pauses.

### M3 — optional guarded writes and software breakpoints

Only if four hardware slots are insufficient, add compare-before-write, original-byte retention,
cache-coherency handling and unconditional rollback. Keep it behind an explicit capability and
policy gate. A failure to prove restoration contains the VM instead of resuming it.

Status: **complete**. The first slice is the deliberately
non-executing mutation primitive:
`sk_live_write_memory` accepts 1–64 compare bytes at a retained stop, converts its native event to
a proved VM-wide pause, resolves exactly one virtual/physical page, writes and reads back, and
retains the original for reverse-order verified rollback. Startup policy and transport capability
are independent gates. Continue, step, recovery and teardown cannot release guest execution while
any original remains unproved. The second slice, `sk_live_continue_to_software_breakpoints`, owns
vector 3 through a separately registered callback context. It accepts up to 64 exact instruction
guards, installs one-byte `INT3` patches under a proved VM-wide pause, and is the only path allowed
to retain patches across guest execution. The immediately following wait retains the original
absolute pause deadline, installs the `vmwp` event-site breakpoint, and only then starts Resume-VM.
A stop must report RIP at an owned patch or exactly one byte past it, the two forms VID exposes for
an intercepted `INT3`; adjacent patch addresses are refused so the mapping is unique. The controller
uses that retained event on the proved sole VP as an execution barrier, restores and verifies every
patch, normalizes RIP to the patch, and converts the event to a VM-wide pause before exposing the
stop. The patches are one-shot and must be explicitly rearmed. Write-enabled target preparation
caches the Hyper-V processor count before target discovery can pause or debugger-stop `vmwp`; the
software-breakpoint slice requires that
cached count to prove a single-vCPU VM, so an unselected VP cannot consume an `INT3` without issuing
a management query during the retained stop. Each patch is also bound to the exact accepted stop
CR3 where its instruction guard was verified, including an allowed transition CR3; vector 3 must
return in that address space. Multi-VP software breakpoints remain future work. The generic write
tool never persists across execution.

Live qualification on 2026-10-21 used the one-vCPU K3 guest and a long-lived divide-error VTL1
workload. A hardware vector-1 stop and the subsequent software vector-3 stop both reported CR3
`0x1071df000`; the software stop named `0xfffff80546604900`, restored `48 83 EC 08`, and returned
RIP normalized to the patched byte. VID exposed the native vector-3 RIP at that byte rather than
one past it, confirming the bounded two-form contract and the need to refuse adjacent patches.
Teardown restored DR0–DR3, DR6, DR7 and the complete RFLAGS baseline, terminated the worker, and
left the same booted VM running with a healthy heartbeat and advancing Hyper-V uptime. The
machine-local evidence is under
`target/codex-m3/software-breakpoint-probes/20261021T080255/`.

### M4 — VTL0 secure-call tracer

Use the existing ordinary kernel worker to instrument the exact-build entry to
`VslpEnterIumSecureMode`, capture calling context and decode the secure-service arguments. Add a
small deterministic guest harness that issues known calls and labels each invocation.

Status: complete, including the administrator-run K3 live gate on 2026-10-21.

`sk_call_trace` and `sk_call_trace_read` use the ordinary kernel worker's one breakpoint-callback
slot and are mutually exclusive with `pool_trace`. The arm resolves exactly
`nt!VslpEnterIumSecureMode`, binds it to one `nt` image identity, and validates the measured
10.0.26100.9457 prefix through the instructions that consume CL, DX, R8D and R9. This makes the
private calling convention fail closed on a different build. Each bounded event retains the
service registers, 0x68-byte raw argument block, caller, symbol-checked
`_ETHREAD.Cid.UniqueProcess`/KTHREAD/processor, exact
image/RVA provenance, a host-wide monotonic timestamp and named typed-read failures. The optional
label is copied from the arm into the report; the guest harness emits the same label and an ordinal
for every supported `CreateEnclave`/`LoadEnclaveImage`/`InitializeEnclave`/
`TerminateEnclave`/`DeleteEnclave` invocation.

Offline qualification covers ownership by id plus marker, fill/stop/drop bounds, exact register
widths, typed callback reads, structured-result coverage and the complete MCP wire golden. The
machine-local live driver and elevation wrapper are under `target/codex-m4/`. The passing record is
`target/codex-m4/live-qualification/20261021T202417/report.json`: the guarded one-byte processor
execution breakpoint retained 256 calls, 199 from the labelled workload PID, with no dropped or
unreadable hit. Those calls covered ten service numbers and callers including `VslCreateEnclave`,
`VslLoadEnclaveModule`, `VslInitializeEnclave`, `VslCallEnclave` and `PsTerminateVsmEnclave`.
All three guest invocations completed create/load/initialize/terminate/delete, `stop: true`
removed the owned breakpoint, detach terminated the worker, guest boot identity and `vmwp` PID
were unchanged, heartbeat stayed healthy, and no process was retained.

### M5 — hypervisor transition tracer

Use a separate hypervisor KD session to capture `HvCallVtlCall` (and the measured return path), VP,
target VTL and saved-state coordinates. Do not infer VTL1 state from VTL0 registers when the
hypervisor provides the authoritative frame.

Status: complete on the measured K3 profile.

`hv_transition_trace` and `hv_transition_trace_read` run only in a distinct hypervisor KD worker.
The first profile admits the collected K3 Intel `hvix64.exe` 10.0.26100.9444 by timestamp, image
size and checksum, then independently matches the two handler prefixes and relocated descriptors
for hypercall codes 0x11 and 0x12. Two DbgEng-owned software breakpoints retain the VP,
processor, source VTL and the target VTL already selected by each handler. Per-VTL state pointers
lead to the inline VMCS descriptor and its physical address; the report pairs those coordinates
with guest-RIP field 0x681e and guest-CR3 field 0x6802, but deliberately does not parse raw VMCS
memory or substitute VTL0 registers. The event provenance separates measured values,
exact-build-derived layout and architectural decoding, with named read failures and no inferred
target VTL.

Processor execution breakpoints were rejected by the live evidence rather than by their setter:
DbgEng accepted and retained both for a full 120-second run containing three successful enclave
lifecycles, but neither fired. A one-shot code breakpoint at the identical call site fired in
161 ms, restored its original byte exactly, detached cleanly and passed same-boot heartbeat and
process audits. M5 therefore uses owned software breakpoints and makes byte restoration part of
the live exit gate; the multiprocessor stop drain is the already-qualified `DONE.md` item 93 path.

The K3 collection record is under ignored `target/codex-m5/`: it copied the exact Intel/AMD images,
proved the guest currently had no hypervisor KD endpoint, and found no existing K3 hypervisor
profile. `prepare-m5-hypervisor.ps1` creates a separate port-50021 `k3-hypervisor` endpoint and
profile while preserving `k3-nt` on 50020, then reboots and verifies VBS plus the complete redacted
configuration.

Because K3 is nested, the outer VM also has virtualization extensions exposed. BCD
`hypervisorlaunchtype Auto` and VBS status did not prove that condition: without the host processor
setting, the guest logged Hyper-V event 41 (VMX unavailable) and emitted no hypervisor KDNET
traffic. The preparation gate now distinguishes launch intent from a running nested hypervisor.

The passing live record is
`target/codex-m5/live-qualification/20261022T203416/report.json`. Its labelled workload began
strictly inside the trace window and completed three create/load/initialize/terminate/delete
lifecycles. The bounded trace retained 1,024 transitions: 512 calls and 512 returns, covering
authoritative VTL0-to-VTL1 and VTL1-to-VTL0 selections on VP index 3, with no dropped event,
unreadable hit or inferred value. `stop: true` removed both owned breakpoints; immediate rereads
matched both complete handler guards and both relocated descriptors. Detach released the target
and terminated the worker, boot identity and `vmwp` PID were unchanged, heartbeat stayed healthy,
and no debugger process remained.

### M6 — VTL1 semantic tracer

Status: complete as of 2026-10-24. M6.0 through M6.3, including the three-clean-boot matrix and
every live and offline control, have passed.

Resolve and stop at `IumInvokeSecureService`, one selected dispatch target and its measured return
site(s). Decode the SSCN/service number, bounded input/output buffers and status using exact-build
symbols plus checked structure layouts. M6 remains a selected-VP, single-vCPU qualification: it
must refuse a VM with more than one runnable VP before arming anything. It uses guarded hardware
execution breakpoints first; a need for code patches is a new gate, not a fallback hidden inside
the tracer.

#### M6.0 — choose and prove the first service

The first service is an output of this phase, not a number guessed from M4 frequency. Extend the
guest harness with cumulative stages (baseline, create, load, initialize, terminate and delete),
each with a label, ordinal and before/after guest tick. Compare repeated M4 traces and the exact
Secure Kernel dispatch walk to select one service whose entry and return cardinality are stable.
Record a repository-tracked, machine-readable manifest consumed by both the implementation and its
tests; prose must not carry a second copy of its constants. The manifest contains:

- Secure Kernel PE identity and PDB identity, entry/dispatch/return RVAs and complete instruction
  guards;
- the service number and the register or checked structure field from which it is read;
- every layout offset, width, alignment and bound used for arguments, output and status;
- the expected number of selected-service calls per positive workload ordinal; and
- the maximum number of hardware slots required, which must not exceed four.

Pass: three positive and three negative workload runs in one unchanged boot reproduce the manifest
exactly. Control: a workload stage before the selected operation produces no selected-service
record, and an offline fixture or submitted guard with one changed image byte, RVA or layout offset
is refused before a debug register changes. Stop: ambiguous service mapping, more than four simultaneous sites, a public
symbol with no independently checked layout, or any path that can return without a guarded return
site sends the design back to a narrower service.

**M6.0 result, 2026-10-22: passed.** The cumulative harness mode separated a life-cycle-free baseline
from the supported create operation and reported all later resource release as cleanup. Three
independent baseline arms and three independent create arms ran on one unchanged guest boot and
`vmwp`; every arm passed with zero trace drop, unreadable hit or retained process. The baseline
never emitted the selected service and every positive ordinal emitted it exactly once. Offline
symbol/disassembly work tied that service to `SkmmCreateEnclave`, one guarded call and one guarded
return path.

The [checked machine-readable manifest](manifests/securekernel-10.0.26100.9457-service-47.json) is
the only copy of the exact image/PDB identity, service number, RVAs, instruction bytes, request
layout, cardinality and hardware-slot count. `src/skservice.rs` consumes it, rejects internal
inconsistency, and checks observed identity plus all target bytes before mutation. Its negative
tests alter an image byte, RVA, layout offset, image identity and slot count independently. The
six local raw reports named by the manifest remain under `target/codex-m6/discovery/`; generated
reports are intentionally not versioned.

#### M6.1 — versioned event and recorder

Add a bounded `sk_service_trace` / `sk_service_trace_read` lifecycle to the existing
`secure_kernel_live` worker. The arm starts one worker-owned asynchronous job and returns a trace id
only after every guard and hardware slot is acknowledged. A read without `stop` may copy only the
immutable completed prefix and recorder counters; it touches no engine or provider. A read with
`stop: true` binds to that exact job, uses only the approved scoped interrupt to wake its wait, and
returns only after engine-thread restoration. One record carries the trace id, capture label, exact
target and image identity, selected VP/VTL/CR3 and three ordered semantic phases:

1. dispatcher entry — service/SSCN, caller coordinate and raw register arguments;
2. selected dispatch — checked handler coordinate plus bounded input/output coordinates and bytes;
3. return — status, bounded post-call bytes and the site that supplied the result.

Every value is tagged as measured, exact-build/layout-derived or unavailable; inference is an
explicit empty list for the first service. Reads are whole-or-named-failure. A caller chooses a
per-buffer limit from 0 through 4,096 bytes, and the recorder also enforces a total byte and event
limit so a target cannot expand an MCP result without bound. A missing entry, dispatch or return is
an incomplete record with its last observed phase, never a completed call assembled from adjacent
hits.

Offline tests must cover schema round trips, exact register widths, all layout guards, page-boundary
reads, unreadable and short buffers, zero/max limits, fill/drop accounting, nested or repeated
entries, an unexpected return, stale epoch/CR3/image identity and rendering of every incomplete
state. Mutation tests must fail if a guard or typed read is removed.

The tool-surface tests must also pin both schemas, `securekernel` group membership, model-visible
and wire budgets, and the `tools/list` golden before either name is considered public. The current
complete surface leaves only 1,318 model-visible bytes, so the schema is drafted and measured
before implementation: either both tools fit, or the ceiling moves in one explicit, attributed
budget change. Silently weakening descriptions or omitting output fields to satisfy the old number
is not a pass.

**M6.1 implementation checkpoint, 2026-10-22:** `src/skservicetrace.rs` now defines the versioned
armed, trace and per-call records plus an engine-free bounded recorder. Its public-facing snapshot
copies only terminal records and counters; an entry or dispatch being filled remains private and is
represented only by `pending_phase`. Every retained call repeats its trace/capture identity, exact
target and manifest image identity, selected CR3 and typed phases. Captures split at page
boundaries, retain bytes only after the complete bounded read succeeds, and otherwise carry one
named failure. Event capacity drops whole records, byte capacity counts the whole dropped capture,
and a zero-byte budget still permits metadata-only records.

Offline tests pin schema round trips and integer widths, the 0/4,096-byte endpoints,
page-boundary, short and unreadable reads, immutable-prefix behavior, non-selected traffic,
nested/repeated/out-of-order phases, stale epoch and CR3 refusal, both capacity dimensions,
provenance and every incomplete rendering. The two input-schema drafts and stripped output schemas
measure **2,937 model-visible bytes and 15,124 estimated wire bytes** together. They exceed the
current model headroom by 1,619 bytes, so M6.2 must make one explicit ceiling change when the real
registered `tools/list` measurement replaces this estimate; no description or result field was
weakened to fit. Neither tool is registered yet: exposing a recorder without the asynchronous
engine-thread restoration lifecycle below would claim a safety property it does not have.

The staged M6.2 arm gate is also present but unexposed. From one exact retained epoch it requires
one selected VP, reads and verifies the live mapped PE identity, CodeView/PDB identity and every
manifest guard, derives all hardware breakpoints only from that proved manifest, and only then
enters the existing atomic replacement transition. Unit tests reject truncated PE declarations
and ratchet that proof-before-mutation ordering. The gate stays private until the worker-owned
run/stop loop below can guarantee restoration on every exit.

**M6.2 core checkpoint, 2026-10-23:** the retained-stop decoder now consumes the manifest's exact
slot, guard, register and typed request layout. Fake live stops prove a complete
entry→dispatch→return record, caller and page-bounded before/after bytes, the caller-selected
buffer cap, non-selected dispatch/return pairing and changed-guard refusal. The engine-free shared
trace exposes only completed records and one stop bit; concurrent stop requests have exactly one
winner, stale ids change nothing, and a stop linearized before an observation consumes no epoch.
The before bytes come from entry-time `rcx`, stay private until a selected dispatch proves the same
request at `r14`, and are never reconstructed from a later stop; changed and missing entry
coordinates have explicit refusal/unavailability tests. Because the entry site is common to every
service, entries remain in a bounded private request-keyed queue: a checked selected dispatch
consumes only its matching earlier candidate, while unrelated nested entries stay private and
cannot truncate or be spliced into that call. A return without a selected dispatch is ignored.
Incomplete records begin only after the checked dispatch has proved service 47, so ambient Secure
Kernel traffic cannot be mislabeled as a selected call.

The engine-thread loop prepares the recorder, decoder and derived breakpoints before its
first mutation, publishes only after the exact live arm succeeds, and seals before the existing
`continue_from` restoration transition. Stop, capacity and observation failures all converge on
that helper; wait/re-arm failures retain the live controller's existing fault recovery. Source
ratchets pin proof-before-mutation and seal-before-restore ordering.

**M6.2 integration checkpoint, 2026-10-23:** `sk_service_trace` and
`sk_service_trace_read` are now registered in the `securekernel` group. The arm call waits for a
dedicated worker milestone emitted only after proof, slot installation and resume; its final job
reply is retained until sealing and restoration. Prefix reads are answered by the request reader
without reaching the engine or provider. A stopping read first linearizes the exact trace id,
wakes only that job's scoped `WaitActivity`, and queues behind it so the response cannot overtake
restoration. Generic `break_in` and unrelated calls are refused while the trace owns the engine;
`end_session` sets the same stop before closing new waits. Provider reads occur outside the shared
recorder lock, so a stop arriving during one wins and discards the decoded observation. The actual
88-tool golden measures 136,123 model-visible and 402,689 wire bytes; the explicit ceilings are
138,000 and 410,000.

**M6.2 offline exit, 2026-10-23:** the production run/stop orchestration now crosses one narrow
fakeable controller/provider boundary. Its matrix exercises entry→dispatch→return, non-selected
traffic, re-entry, out-of-order return, capacity reached after selection at dispatch, nested entry
and return, no-hit,
reader stop/interrupt, re-arm failure, teardown-before-publication, teardown while waiting,
restoration failure and reused epochs. It caught two cleanup gaps before live use: a changed guard
during re-arm now seals and restores the retained epoch instead of only sealing, and teardown read
during the sealed arm transition is inherited at publication, suppresses the arm milestone and
takes the ordinary stop/restore path. Supervisor tests separately pin arm-before-wake and exact
failure-before-arm ordering. Terminal re-arm/restoration failure is retained beside the shared
prefix before `Done`, so a queued or later read reports it even though the supervisor consumes the
asynchronous job reply in the background. M6.2 is complete; M6.3 live qualification is next.

**M6.3 live-integration checkpoint, 2026-10-23:** the first live probes exposed two facts that the
offline source could not simulate. The Hyper-V GPA helper cached mutable physical pages across
retained stops, so a later dispatch could read a stale request even though its register coordinate
was current. The live-source protocol now requires and negotiates
`read_coherency=explicit_refresh`; every stop-scoped root bind sends `REFRESH`, and the provider
discards its page cache before acknowledging the new read epoch. A source without that capability
is refused before the trace mutates debug state. The same probes showed unrelated nested common
entries between both entry and selected dispatch and between selected dispatch and return, which
led to the bounded request-keyed candidate queue above. The diagnostic one-record arm at
`target/codex-m6/live-qualification/20261023T215214/report.json` completed with status zero, no
drops or unreadable data, exact debug-state restoration, unchanged Secure Kernel text, the same
boot and `vmwp`, healthy heartbeat and no retained process. It is a path proof, not the three-boot
M6.3 exit record.

**M6.3 qualification checkpoint, 2026-10-23:** three clean boots passed 100/100 selected calls in
`target/codex-m6/live-qualification/20261023T223744/`, `20261023T225031/` and
`20261023T230342/`. Their guest boot identities, `vmwp` PIDs, nested partition ids and randomized
Secure Kernel bases were all distinct. Every record was complete, returned status zero and carried
one measured 64-byte before/after request pair; every run had zero dropped records/bytes,
unreadable fields, inference or pending phase. The causally gated baseline completed before the
positive task could enter the API, and each guest emitted exactly 100 successful create/cleanup
rows. Each arm restored DR0-DR3/DR6/DR7/RFLAGS exactly, preserved the mapped image base/RVA/size and
text hash, stayed on its original boot and `vmwp`, released its worker without recovery, retained a
healthy heartbeat and left no debugger/provider process.

The separate one-record capacity arm is
`target/codex-m6/live-qualification/20261023T222002/`; it sealed `full` at its exact limit and
passed the same audits. The live no-hit and forced-teardown controls are respectively
`20261023T231728/` and `20261023T231911/`: the former retained a clean zero-record prefix for six
reads before explicit stop/restoration, and the latter ended an actively armed zero-record trace
through `end_session`; both restored all state without recovery. The stale-image, stale-byte and
stale-layout controls plus the proof-before-mutation ratchet passed in
`target/codex-m6/offline-controls.json`.

Provider death reached its intended fail-closed result in
`target/codex-m6/live-qualification/20261023T232322/`: terminating the exact control-provider child
made the trace report the closed pipe with `target_left_paused=true`, and `end_session` reported
`recovery_required=true`, `released=false` while retaining the isolated worker. The exact recovery
then removed that worker and its remaining memory-provider child and power-cycled only K3. After
Windows recovery, the strict final audit in `target/codex-m6/provider-death-control.json` proved a
new guest boot identity, heartbeat `OK`, active VBS and zero retained debugger/provider processes.
The fail-closed containment and subsequent recovery therefore form one passing provider-death
control rather than treating containment alone as success.

`target/codex-m6/m6-qualification.json` is the final machine-checkable M6.3 record. Its companion
`finalize-m6-qualification.ps1` independently re-checks and hashes all three 100-call reports, the
one-record capacity run, no-hit and forced-teardown runs, all four offline controls and the finalized
provider-death control. It passed with three distinct boot identities, `vmwp` PIDs, partition ids
and randomized Secure Kernel bases. M6.3's exit gate is satisfied, so M7 may consume an M6 record as
a semantic endpoint.

#### M6.2 — guarded run/stop loop

Arming starts from a retained epoch. It verifies the manifest and complete baseline before writing
DR0–DR3/DR6/DR7, owns every installed slot, releases through the M1 transition, and re-arms only
after the next owned VTL1 stop has been converted back to a retained epoch. No tool call may expose
a half-mutated debug-register set. Capacity completion seals the recorder before restoration;
`stop: true`, timeout, no-hit, client loss and `end_session` do the same. Every path restores and
verifies the complete baseline before execution is released; an unproved restoration contains the
VM and reports the recovery action.

The fake provider/dispatcher tier must exercise entry→dispatch→return, a non-selected service,
re-entry, out-of-order stops, capacity on each phase, no-hit, interrupt, teardown-before-arm,
teardown-while-waiting and a restoration failure. Each race has one linearization point and tests
that the same epoch cannot be consumed twice.

#### M6.3 — live qualification

Run only after M6.0 has emitted the checked manifest. On each of three clean boots, collect 100
complete selected-service records from the deterministic workload plus its negative control. The
clean records must have the manifest's exact cardinality, no drop, no unreadable required field and
no inferred value; decoded status and bounded output must agree with the guest's supported-API
result. Separately run stale-image, stale-byte, stale-layout, no-hit, capacity, forced-teardown and
provider-death controls.

Exit: every boot ends with exact DR0–DR3/DR6/DR7/RFLAGS equality, unchanged Secure Kernel text,
released ownership, the same guest boot and `vmwp`, healthy heartbeat and no retained debugger or
provider process. The qualification record names the manifest, raw run directories and every
negative control. Only then may M7 treat an M6 record as a semantic endpoint.

### M7 — cross-layer correlation and investigations

Status: in progress. M6's live exit gate and M7.0 are complete. M7.1's offline transaction,
line-protocol and one-boot topology-refusal gates are complete. The live coexistence exit gate is
blocked because the qualified M5 and M6 providers require mutually exclusive K3 processor shapes;
M7.2 does not start until one provider is qualified in a shape that exposes all three layers.

Join M4–M6 without putting two targets in one DbgEng process. The coordinator owns session ids and
lifecycles, not engines: each layer remains in its existing worker and contributes an immutable
trace. The first accepted configuration is the same one-vCPU K3 VM used by M3–M6. A VM reporting
more than one runnable VP is refused before any layer is armed; total-VP coverage and mapping are a
separate future gate, not an optimistic extension of this result.

The first coordinator is a repository-owned live driver over the public MCP surface plus a pure
Rust join module. It holds only session/trace ids and serialized records. It is not a new DbgEng
role and does not run in a worker. Promoting the transaction itself to an MCP tool is a later
tool-surface decision with its own schema and token-budget gate; M7 does not hide that expansion in
the correlation implementation.

#### M7.0 — common identity, clock and availability contract

Mint one `capture_id` before opening the three sessions and bind it to the allowlisted VM id, guest
boot identity, `vmwp` PID, profile names, workload label, processor count and each layer's image
identity. Worker session ids remain separate. Values observed only by the coordinator are carried
in a coordinator envelope and are never presented as target-measured fields.

The existing millisecond-derived `host_monotonic_us` can collide at M5's event rate. Have the three
workers and coordinator sample one common high-resolution Windows counter, record its raw tick and
frequency, and bracket every arm/read RPC with coordinator ticks. Use point timestamps only if all
four processes report one frequency and ordered samples stay within a recorded skew bound;
otherwise retain only the measured RPC intervals. Stop if those intervals overlap where a causal
decision is required rather than inventing microsecond precision. Preserve the old field for wire
compatibility until a schema revision explicitly retires it.

M7.0 also owns M5's VMCS-value question. Probe a supported architectural debugger API for guest RIP
and CR3. A successful value records its API and field; an unsupported API leaves the exact field
encoding and physical coordinate with `availability: coordinate_only`. Raw VMCS memory parsing is
forbidden, and the value is not a correlation key, so coordinate-only is an admitted result rather
than an inferred value.

Pass: two independent processes produce ordered/collision test vectors with a stated resolution
and skew; the coordinator rejects a changed boot, `vmwp`, image, profile or processor count between
preflight and arm. Controls deliberately collide old timestamps and mutate each identity field.
Any new clock fields are optional for old records, required for a new complete M7 capture, and move
the schema goldens and both surface budgets by an explicitly measured delta.

**M7.0 result, 2026-10-24: passed.** M4, M5 and M6 arm/read envelopes and events now retain an
optional raw `host_qpc` tick and frequency while preserving `host_monotonic_us`. The engine-free
`--m7-clock-probe` role exits before the MCP runtime; the smoke gate launched two independent
processes, observed one frequency and ordered QPC ticks in both, and also observed the intended
collisions in the old millisecond coordinate. The pure `src/skcorrelate.rs` admission gate records
the QPC resolution and caller-selected skew bound, permits point order only when every worker
sample has the common frequency and lies inside its coordinator bracket, and otherwise retains
interval-only authority with named reasons. Touching/overlapping intervals never become a causal
order. Mutation controls independently reject every capture, VM, boot, `vmwp`, workload,
one-processor, layer-profile and exact-image binding between preflight and arm.

The supported debugger API exposes no architectural VMCS guest-state read. M5 therefore adds a
typed `coordinate_only` availability result beside each exact field/physical coordinate and a
source ratchet forbids virtual or physical memory reads in that conversion; raw VMCS parsing and
VTL0-register substitution are not fallbacks. All new result fields remain optional when reading
pre-M7 records; a complete M7 capture will require them at transaction admission. The six output
schemas add 0 model-visible and 2,729 wire bytes, moving the complete payload from 402,689 to
405,418 bytes under
unchanged 138,000/410,000 ceilings.

#### M7.1 — three-worker capture transaction

Implement an explicit transaction with `preflight`, `opening`, `armed`, `workload`, `draining`,
`restoring` and `closed` states. First prove that all three sessions can coexist, arm and disarm on
an idle VM without a workload. Then choose and record one arm order; workload launch is forbidden
until all three workers have acknowledged `armed`. Cleanup runs for every session that reached
opening, in reverse successful-arm order, and never force-kills a worker that still owns a patch or
retained VTL1 event.

Offline transaction tests inject failure and timeout at every state and for every worker. They
assert that unopened layers are untouched, opened layers are ended once, all restoration results
are retained, and the top-level result cannot be `pass` while a child is running, held, dropped or
unreadable. The live coexistence control arms and removes all instruments without starting the
guest harness, then proves the same boot, heartbeat, breakpoint bytes, debug-register baseline and
zero retained processes.

**M7.1 implementation result, 2026-10-24: offline passed; live incomplete.** The pure transaction
runner now owns the seven states above, fixes the arm order as M5 hypervisor -> M4 VTL0 -> M6
VTL1, withholds the workload until all three acknowledgements say they are ready, and drains
successful arms in reverse order before ending every reachable session. Its driver has no
force-kill operation. Failed and timed-out opens retain a public recovery session handle when one
was returned, so that handle is ended exactly once rather than being mistaken for an unopened
layer. Unit controls inject failure and timeout at every operation and layer, mutate arm-time
identity, and independently make every restoration field unsafe. A real-binary smoke test drives
the engine-free `--m7-transaction-protocol` through both the complete idle order and a timed-out
open carrying a recovery handle. Neither role constructs a debugger engine.

The original live adapter passed identity, one-VP, image, profile, boot, `vmwp`, QPC and
clean-process preflight on three bounded runs, then the first M5 `attach_kernel` failed to land
inside the server's 300-second call bound. Event 41 in the guest subsequently proved the cause:
K3 had `ExposeVirtualizationExtensions=false`, so no nested guest hypervisor existed to answer
M5. Enabling the setting and obtaining guest Hyper-V event 1 fixed that prerequisite, but exposed
the deeper topology conflict below. A separate attempt to start the VM while a hypervisor listener
was already bound entered Windows repair; that boot-priming path remains rejected and removed.
Every failed attempt withheld the workload and was recovered to heartbeat `OK` with no debugger
process retained.

#### M7.1a — one-boot topology admission and provider refinement

The three records must describe one boot. Switching `ExposeVirtualizationExtensions` between
layers changes the boot identity and is never a correlation mechanism. The measured matrix is:

| K3 processor shape | M4 guest NT | M5 hypervisor | existing M6 outer-`vmwp` VTL1 |
| --- | --- | --- | --- |
| non-nested | available | unavailable: no guest hypervisor | available |
| nested, guest hypervisor started | available | available | unavailable: outer partition has no K3 Secure Kernel VTL1 |

The capture identity now carries the measured nesting flag, guest-hypervisor-started evidence,
outer-partition VTL1 availability and selected M6 provider boundary. The pure gate enumerates
unavailable layers and refuses before the first worker opens. Matrix tests cover both measured
partial shapes and the only admissible future shape (nested plus a separately qualified
`nested_root` M6 provider); mutation tests freeze every shape field between preflight and arm. The
live refusal in `target/codex-m7/live-coexistence/20261024T102334/report.json` measured a running
nested hypervisor, outer-partition VTL1 register status 21 and `m6_provider: outer_vmwp`, then
closed with no sessions opened, no workload, unchanged boot/`vmwp`, heartbeat `OK` and no retained
process.

A bounded read-only feasibility probe tested the shortest nested-root path. Inside K3, the pinned
test-signed H3 driver issued only `HvCallGetVpRegisters` against partition `SELF`: VTL0 CR3 and
`VsmVpStatus` succeeded, and the latter reported VTL1 enabled, while VTL1 CR3 and RIP both returned
Hyper-V status 6 (`ACCESS_DENIED`). The temporary service and files were removed and K3 retained
heartbeat `OK`; the local evidence is
`target/codex-m7/m7-nested-vtl1-feasibility.json`. Therefore raw SELF/VTL1 hypercalls are a
rejected provider design, not an implicit fallback.

Refinement proceeds as three separately gated phases:

1. **Provider choice.** Either prove a supported nested-root mechanism that can read and restore
   the complete M6 register/event state, or use a separate debugger machine to observe the L0
   hypervisor while K3 remains non-nested. A proposal must bind its observation to the exact K3
   partition and boot before any mutation test. Cross-boot joins and raw VMCS parsing remain
   forbidden.
2. **Provider qualification.** A read-only RIP/CR3 positive control comes first. Then reproduce
   M6's arm, held-event, reverse restoration, provider-death and three-clean-boot controls through
   the chosen boundary. Access denied, unavailable state, identity ambiguity or incomplete
   restoration fails the phase; none may be converted to coordinate-only for semantic tracing.
3. **Idle coexistence.** Only after phase 2 may the transaction open M5 -> M4 -> M6 on one boot,
   arm all three without a workload, drain in reverse order and prove byte/register baselines,
   heartbeat, unchanged boot/`vmwp` and zero retained processes. Failure/timeout injection remains
   part of this gate. M7.2 stays closed until this exact live control passes.

#### M7.2 — deterministic join

The workload label and `capture_id` select a capture; neither proves that two events are one call.
Within the admitted one-VP capture, assign a `call_id` only when the observed order is:

```text
M4 VTL0 entry -> M5 vtl_call -> M6 entry -> M6 selected dispatch -> M6 return -> M5 vtl_return
```

Use per-layer sequence numbers, direction, the selected service, VTLs and non-overlapping clock
intervals. Pair nesting with a stack, not nearest-timestamp matching. If zero or more than one
candidate survives, retain the candidate ids and reason as `unmatched` or `ambiguous`; never pick
the nearest silently. A layer's dropped counter or incomplete call marks the affected interval and
prevents a complete verdict across it.

Publish versioned JSON containing the capture envelope, original events, correlation decisions,
unmatched/ambiguous sets, drops and restoration audit. Render a bounded table/timeline from that
JSON; the table is not an independent source. Property tests generate nested calls, equal
timestamps, reordered arrivals, missing phases, unmatched returns and drops, and assert that input
permutation does not change a decision once layer sequence numbers are fixed.

#### M7.3 — correlated live gate and investigations

Across three clean boots, run at least 25 positive workload ordinals and five negative controls per
boot. Every invocation of M6's selected service must produce the manifest's exact number of
complete six-stage chains, with no ambiguity, unmatched required event, drop, unreadable required
field or inferred value. Guest result/status must agree with M4 arguments and M6 return data.

Fault arms deliberately cap each layer in turn, drop a coordinator connection at a state where the
worker owns no mutation, collide legacy timestamps and fail one cleanup call. Each must yield the
named incomplete/ambiguous result and still complete all reachable restoration. Add three
repeatable investigations only after the clean gate passes: selected-service dispatch, bounded
guest-originated input variation observed without a debugger write, and return-status propagation.

Exit: structured JSON and its table reproduce the same decisions, all three layers prove their own
restoration, the VM remains on the same boot with a healthy heartbeat, and no worker/provider is
retained. The qualification record includes preflight identity, clock evidence, raw child reports,
the joined result and negative controls.

### M8 — debugger front ends

Status: planned. M1 and M2 authorize implementation, but the facade keeps refusing ordinary `g`
and running break-in until this milestone's own gate passes. M8 is independent of M6/M7's trace
schema; it is scheduled after them so controller behavior is not changed underneath their live
qualification.

#### M8.0 — packet-to-controller contract

Write the translation table before changing the facade:

- KD `WriteBreakpoint` reads and retains the complete instruction guard and reserves one of at most
  four hardware slots; `RestoreBreakpoint` removes only that handle.
- legacy Continue and non-trace Continue2 (`g`) with breakpoints call the proved M1 guarded
  continue-to-breakpoints path and enter one owned wait.
- `g` with no breakpoint enters a distinct bounded running wait that can be stopped only by M2
  break-on-demand, teardown or its recovery deadline; it is not implemented as an infinite resume.
- running Ctrl+Break binds to that exact wait and invokes the M2 rendezvous. A natural breakpoint
  winning the race remains a natural breakpoint. Ctrl+Break while already stopped preserves and
  resends the retained stop.
- trace Continue2 (`t`, and only packet forms proved equivalent) keeps the existing guarded
  fall-through step. Unsupported branch/call/return steps remain refusals.
- reset, disconnect, idle expiry and MCP teardown recover the currently owned run before any
  reconnect; memory/register writes and a fifth breakpoint remain refused.

The request-reader thread may use only the already approved scoped `SetInterrupt` wake. Every
controller mutation remains on the engine thread. Unit tests feed raw KD packets through all table
rows, malformed lengths, duplicate handles and all pairwise stop/break/disconnect/teardown races.
The response must name whether execution moved, which epoch stopped and whether recovery is owed.

#### M8.1 — facade integration and launchers

Route the two continue forms through the direct controller without creating a second engine or a
second session registry. Preserve one absolute pause/run deadline across packet handling, controller
transition and wait. A rejected guard or stale epoch resends the old stop; a failure after release
must recover or contain the VM and terminate the KD connection with the exact disposition.

Add PowerShell launchers for classic WinDbg and WinDbgX that resolve the executable and generated
pipe from any working directory, keep credentials/keys off command lines and logs, and always end
the MCP session after the debugger exits. Script tests use paths containing spaces, missing
debuggers, early debugger exit and a fake client so they need neither elevation nor a live VM.

#### M8.2 — live compatibility and safety gate

Qualify classic WinDbg and WinDbgX separately on each of three clean boots. Each client must pass:

- 100 `bp` → `g` → owned-stop cycles at the deterministic M1 site, including set/list/remove;
- 25 `g`-without-breakpoint → Ctrl+Break cycles using the M2 request;
- natural-stop-wins, Ctrl+Break-wins, already-stopped, no-hit/timeout, reset, disconnect,
  reconnect and MCP-teardown races; and
- `r`, bounded memory reads, `lm`, symbols, stack, one fall-through `t`, refused writes and a
  refused fifth breakpoint before and after the run tests.

Every arm audits exact DR0–DR3/DR6/DR7/RFLAGS restoration, unchanged Secure Kernel text, one
selected VP, same boot/`vmwp`, heartbeat and retained processes. A reset, hang, ambiguous stop or
unproved restoration fails the gate and leaves ordinary `g` disabled.

Exit: both front ends perform `bp`/`g`/Ctrl+Break repeatedly through the managed session, all race
controls have unique results, launchers work outside the repository, and the refusal is removed
only for the qualified single-VP shape. EXDI is evaluated after this exit and is not a prerequisite;
it is accepted only if it adds compatibility without host registration, in-process vendor loading
or weaker worker isolation.

## M1 implementation record

All five slices are complete; this list records what passed rather than work still queued:

1. **Transition surface — complete:** the replacement-breakpoint transition is in the live
   worker/MCP protocol while the KD facade refusal remains explicit.
2. **Failure harness — complete:** fake provider/dispatcher tests cover replacement, no-hit
   recovery, stale guards, deadline propagation and one-shot epoch consumption.
3. **Opt-in live smoke — complete:** `WINDBG_MCP_SMOKE_SK_LIVE` covers guarded replacement and
   always runs teardown plus baseline/VM health checks.
4. **Deterministic trigger — complete:** the guest workload and exact symbol/RVA record select the
   live site.
5. **Qualification — complete:** the 100-cycle/three-boot matrix and raw evidence are recorded in
   M1 above. Changing KD behavior remains M8 work.

## Verification commands

Offline changes must pass:

```powershell
cargo fmt --all --check
cargo test
cargo clippy --all-targets -- -D warnings
```

The destructive live tier remains opt-in and runs alone against an explicitly disposable VM:

```powershell
$env:WINDBG_MCP_SK_LIVE_POLICY = '<private policy path>'
$env:WINDBG_MCP_SMOKE_SK_LIVE = '<private live config path>'
cargo test --test mcp_smoke a_live_secure_kernel_session_stops_steps_inspects_resumes_and_closes -- --ignored --exact --nocapture
```

Passing offline tests proves state-machine behavior, not live safety. M1's live-safety gate is the
recorded qualification matrix above; later milestones need their own live evidence.
