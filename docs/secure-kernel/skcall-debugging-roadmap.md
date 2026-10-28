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
- Hardware execution breakpoints remain the primary VTL1 mutation primitive, and VTL1 is the only
  layer that holds them (decided 2026-10-25 under M7.1a: DR0-DR6 are shared between VTLs on a VP,
  so a VTL0 hardware breakpoint and a VTL1 one collide). M4 and M5 arm DbgEng-owned software
  breakpoints. M3 proved guarded, one-shot software breakpoints for the single-vCPU Secure Kernel
  controller, and M5 separately proved DbgEng-owned software breakpoints in the hypervisor. Neither
  result authorizes general KD memory writes, multiprocessor patching or reuse of one layer's
  restoration proof in another.
- Every stop and transition is tied to an opaque epoch, exact instruction bytes, VM identity,
  partition, VP, VTL and CR3. Stale coordinates are refusals, not best-effort operations.
- The 2026-10-18 `g` qualification is a failed facade gate: after WinDbg armed
  `securekernel!KiTimerInterrupt`, the next VTL1 stop was not observed and K3 reset. The KD facade
  refused non-trace requests from then until 2026-10-25, when M8.0's rows were routed onto the
  M1 and M2 paths the direct controller had since passed; M8.2's packet-race and recovery gate is
  still what qualifies them, and a failure there brings the refusal back.
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
patch, normalizes RIP to the patch, and retains the vector-3 event while exposing the stop. Native
completion cannot be used to manufacture a stopped snapshot here: the restored instruction may
execute before Suspend-VM finishes. The patches are one-shot and must be explicitly rearmed.
Write-enabled target preparation
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

On 2026-10-25 the breakpoint was changed to a DbgEng-owned software breakpoint, the kind M5 arms,
because the processor execution breakpoint occupied DR0 on the traced VP and DR0-DR6 are shared
with VTL1 on the same VP (M7.1a, run `20261024T212721`). Its first live arm (M7.1a run
`20261025T073515`) deadlocked the one-processor child on the first hit: the debugger inserts and
removes a software breakpoint in HVCI-protected text through `MiDbgCopyMemory` ->
`MiDbgWriteCheck` -> `MiCopyToUntrustedMemory` -> `MiDbgCopyPrivilegedData` ->
`VslWriteProtectedPage` -> `VslpEnterIumSecureMode`, so the write that services the breakpoint
executes the `int 3` it is servicing, a second breakpoint trap is dispatched while
`KdDebuggerLock` is held, and the processor spins in `KeFreezeExecution` for ever. The arm is a
processor execution breakpoint again, with that measured reason in place of the earlier unmeasured
one; the record above stands, and the collision with M6 is the open design item under M7.1a.

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

Status: in progress. M6's live exit gate, M7.0 and M7.1 (under its criterion as revised
2026-10-25) are complete. M7.1's offline transaction,
line-protocol and live-topology admission gates are complete, its provider-choice gate selected a
nested L2 workload under K3, and the nested-parent provider is qualified: the read-only, no-op
write, arm/restore and natural held-event controls, the provider-death control and the complete
positive sequence on three clean child boots all passed. The admitted-topology coexistence driver
exists and opened and armed all three layers once; the live coexistence exit gate was blocked on
two findings from the reruns under the inverted arm order: M6's stop of a running trace asserted
that no event arrives during its settle run and its recovery hangs on VMMS, and the child VP's
DR0-DR6 are shared between VTLs, so M4's hardware breakpoint and M6's slot-0 breakpoint cannot
both be armed on it. The running disarm now holds an arriving event as its disarm point instead
of faulting and awaits its live proof. The debug-register collision is resolved by partition: a
software breakpoint at `nt!VslpEnterIumSecureMode` was armed live on 2026-10-25 and deadlocked the
child on its first hit, because the kernel debugger's own protected-text write path enters VTL1
through that entry (run `20261025T073515`, measured under M7.1a), so M4 keeps its processor
breakpoint in slot 0 and M6 reserves that slot, arming its sites in slots 1-3 and touching only
those; M6 is armed before M4 and drained after it. Run `20261025T084354` measured the partition
holding after M6's arm, and then measured the blocker beneath it: the VTL1 dispatcher's exception
intercept also receives VTL0 debug exceptions and its completion suppresses them, so M4's KD
break-in never reached the VTL0 kernel while M6's handler was registered. Built 2026-10-25:
every event at the dispatcher's site is put to the controller, whose provider reads the executing
VTL from the hypervisor, and another VTL's exception is carried through the native completion
with the site re-armed, so M6 stays armed and healthy beside the VTL0 debugger. Measured the same
day across five runs: the root-side ways tried to hand that exception back to VTL0 do not work
on this hypervisor and no root-side redelivery path has been demonstrated, so the VTL0 debugger
loses every break and breakpoint hit while M6's handler is registered, and M4 and M6 cannot
share a VP in one window with what exists. Decided 2026-10-25: M7.1's idle gate runs M6 and M4
in alternation, a revision of its acceptance criterion recorded under M7.1, and it passed that
way the same afternoon (run `20261025T145507`: M6 armed, drained and closed, the switch read
clean, M4 and M5 armed and closed, the switch read clean again, M6 reopened and closed, the
independent finalize check passing with no failure); M7.2 is to be designed off M4's hardware
breakpoints, with M6's entry data still to be proved against M4's fields; the in-`vmwp`
redelivery stays a fallback. M7.1 is complete under the revised criterion. M7.2's join is built
and qualified offline (2026-10-25), with the first-stage field table recorded under it; a chain
that is `complete` live waits on M7.3's capture, which needs M4 and M6 in one window or an
M6-entry first stage, and a clock common to M5 and M6.

Join M4–M6 without putting two targets in one DbgEng process. The coordinator owns session ids and
lifecycles, not engines: each layer remains in its existing worker and contributes an immutable
trace. The first accepted configuration is a one-vCPU L2 workload under the one-vCPU K3 root used
by M3–M6. A workload reporting more than one runnable VP is refused before any layer is armed;
total-VP coverage and mapping are a separate future gate, not an optimistic extension of this
result.

The first coordinator is a repository-owned live driver over the public MCP surface plus a pure
Rust join module. It holds only session/trace ids and serialized records. It is not a new DbgEng
role and does not run in a worker. Promoting the transaction itself to an MCP tool is a later
tool-surface decision with its own schema and token-budget gate; M7 does not hide that expansion in
the correlation implementation.

#### M7.0 — common identity, clock and availability contract

Mint one `capture_id` before opening the three sessions and bind it to the workload VM id, boot
identity and `vmwp` PID; for a child workload also bind its parent VM id, boot identity and outer
`vmwp` PID. Freeze the profile names, workload label, processor count, placement, provider
boundaries and each layer's image identity. Worker session ids remain separate. Values observed
only by the coordinator are carried in a coordinator envelope and are never presented as
target-measured fields.

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
order. Mutation controls independently reject every capture, workload or parent VM/boot/`vmwp`,
placement, provider boundary, one-processor, layer-profile and exact-image binding between
preflight and arm.

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

**Criterion revision, 2026-10-25.** "All three sessions coexist, arm and disarm" assumed the
three could be armed at once. The VTL1 dispatcher's exception intercept is per partition and no
root-side way to hand a VTL0 exception back has been demonstrated (M7.1a, continuation item 2),
so the idle gate is revised: M6 is armed, drained and **closed** before M4 opens, M4 is drained
and closed before M6 reopens, and M5 keeps its place last. Each switch carries transition checks
the harness proves before the next layer opens: M6's exception handler fully unregistered, read
from `vmwp` (the dispatcher's deferred cleanup reached and its scratch freed), no VTL1 slot
enabled, and no exception or trap-flag state pending on the child's VP read from K3
(`pending_event0` and `pending_interruption` clear, `rflags.TF` clear in both VTLs). The
same-window arm of all three is not claimed by M7.1 any more; it is what M7.2's join would need
and is open there. The revised gate passed on 2026-10-25, run `20261025T145507`; the live
result below has the readings.

Offline transaction tests inject failure and timeout at every state and for every worker. They
assert that unopened layers are untouched, opened layers are ended once, all restoration results
are retained, and the top-level result cannot be `pass` while a child is running, held, dropped or
unreadable. The live coexistence control arms and removes all instruments without starting the
guest harness, then proves the same boot, heartbeat, breakpoint bytes, debug-register baseline and
zero retained processes.

**M7.1 implementation result, 2026-10-24: offline passed; live incomplete.** The pure transaction
runner now owns the seven states above plus `transition`, fixes the one-window arm order as M6
VTL1 -> M4 VTL0 -> M5 hypervisor (M5 last since the evening of 2026-10-24, when the live run
recorded under M7.1a showed that a stopped hypervisor holds every layer beneath it; M6 before
M4 since 2026-10-25, the slot partition), and since 2026-10-25 runs the alternating plan under
`--m7-alternate` (`ALTERNATING_WINDOWS`: M6 alone, then M4 with M5, then M6 again), asking the
adapter for a `transition` between windows whose typed acknowledgement must read clean before
the next window opens and refusing a workload for that plan, since no window holds every
layer. It withholds the workload until all
three acknowledgements say they are ready, and drains
successful arms in reverse order before ending every reachable session. Its driver has no
force-kill operation. Failed and timed-out opens retain a public recovery session handle when one
was returned, so that handle is ended exactly once rather than being mistaken for an unopened
layer. Unit controls inject failure and timeout at every operation and layer, mutate arm-time
identity, independently make every restoration field unsafe, and for the alternating plan make
each leftover a switch can read (the handler still registered or unread, a VTL1 or VTL0 slot
enabled, a pending event, the trap flag, an engine worker) open nothing further and let a window
that fails end the plan after its own cleanup. A real-binary smoke test drives the engine-free
`--m7-transaction-protocol` through the complete idle order, the alternating plan with its two
transitions, and a timed-out open carrying a recovery handle. Neither role constructs a
debugger engine.

The original live adapter passed identity, one-VP, image, profile, boot, `vmwp`, QPC and
clean-process preflight on three bounded runs, then the first M5 `attach_kernel` failed to land
inside the server's 300-second call bound. Event 41 in the guest subsequently proved the cause:
K3 had `ExposeVirtualizationExtensions=false`, so no nested guest hypervisor existed to answer
M5. Enabling the setting and obtaining guest Hyper-V event 1 fixed that prerequisite, but exposed
the deeper topology conflict below. A separate attempt to start the VM while a hypervisor listener
was already bound entered Windows repair; that boot-priming path remains rejected and removed.
Every failed attempt withheld the workload and was recovered to heartbeat `OK` with no debugger
process retained.

**M7.1 live result, 2026-10-25: passed under the revised criterion.** Run
`live-coexistence/20261025T145507/`, build `0.23.0+gcda1c8e1-dirty.3fa83efb` on host and K3
alike, 3 min 22 s end to end on the one-vCPU L2 child (`vmwp` 7964, child boot
`2026-10-25T13:13:00Z`) under the K3 parent (boot `2026-10-24T18:28:16Z`, unchanged by the
run). Window 1: M6 opened in 3.1 s, armed in 65.6 s (the bootstrap trigger, held in VTL1 and
completed), drained in 4.6 s with 0 records and ended in 11.1 s with the target released and
the worker terminated. Switch 1 (4.8 s): the dispatcher's verification of its handler
unregistration present once in the listener's log for its two registrations and no
containment, no slot enabled in either VTL's DR7, no pending event or interruption under any
InputVtl encoding, the trap flag clear in both VTLs, 0 engine workers, the VTL1 baseline
restored and the Secure Kernel text unchanged. Window 2: M4 opened in 0.8 s and M5 in 1.7 s,
M4 armed in 0.8 s with VTL0 DR7 enabling slot 0 alone at M4's entry and VTL1 enabling nothing,
M5 armed in 0.1 s; M5 drained first with 0 transitions and the hypervisor resumed, M4 drained
with 2 calls recorded on the idle child and its entry bytes restored; both ended released.
Switch 2 (2.6 s): clean on every field, with no VTL1 handler to read. Window 3: M6 reopened in
2.9 s, armed in 56.6 s, drained with 0 records, ended released. Postflight: both boots and both
`vmwp` pids unchanged, VTL1 debug state restored, text unchanged, 0 engine workers in K3, 0
staged host processes, both heartbeats `OK`; the harness's cleanup completed with nothing owed
and no residue in K3 (no staging, listener task, firewall rule or driver service), and the
independent finalize check (`finalize-m7-nested-coexistence.ps1`, reading the raw records and
the live lab) wrote `m7-nested-coexistence.json` as `pass` with no failures. Clock admission
was `interval_only`, as in every nested run: M6's worker QPC is K3's clock and sits outside the
host bracket. Two attempts that hour failed in the driver, not the lab, and left nothing
behind: `144453` read the switch's handler evidence from the wrong log line (the clean release
writes one `verified handler unregistration and callback scratch release` line per session,
after the last of its two registered contexts' deferred cleanup, not the per-context free
line), and `145011` read M4's slot at the stop where the trace armed, where VTL0 DR7 is `0x400`:
a kernel debugger's `ba` reaches the processor's DR7 with the continue that resumes the
target, so the slot is measured once the bounded run is under way. One reading to keep: after
M4's window closed, VTL0's DR0 still held M4's entry address with its enable clear, so the
detach clears the enable and not the value; the switch reads enabled slots, and M6 reserves
slot 0 regardless.

#### M7.1a — live-topology admission and provider refinement

The three records must describe one simultaneously live topology. Switching
`ExposeVirtualizationExtensions` between layers changes the parent boot identity and is never a
correlation mechanism. A child workload binds both its own boot and the parent boot that owns its
`vmwp`. The measured and selected matrix is:

| topology and workload placement | M4 guest NT | M5 boundary | M6 boundary | admission |
| --- | --- | --- | --- | --- |
| non-nested K3 root | K3 | guest nested: unavailable | outer `vmwp`: available | refuse M5 |
| nested K3 root | K3 | guest nested: available | outer `vmwp`: no K3 VTL1 | refuse M6 |
| nested K3 root with SELF provider | K3 | guest nested: available | SELF/VTL1: access denied | rejected design |
| nested K3 parent plus L2 child | L2 | guest nested: available | nested parent: child VTL1 available | **selected** |

The capture identity now carries workload placement, the optional parent identity, measured
nesting and guest-hypervisor-started evidence, outer and child VTL1 availability, and selected M5
and M6 provider boundaries. The pure gate enumerates unavailable layers and refuses before the
first worker opens. Matrix tests cover both measured partial shapes, the rejected SELF design, the
selected nested child and the unselected external-L0 fallback; mutation tests freeze every field
between preflight and arm. The live refusal in
`target/codex-m7/live-coexistence/20261024T102334/report.json` measured a running nested
hypervisor, outer-partition VTL1 register status 21 and `m6_provider: outer_vmwp`, then closed with
no sessions opened, no workload, unchanged boot/`vmwp`, heartbeat `OK` and no retained process.

A bounded read-only feasibility probe tested the shortest nested-root path. Inside K3, the pinned
test-signed H3 driver issued only `HvCallGetVpRegisters` against partition `SELF`: VTL0 CR3 and
`VsmVpStatus` succeeded, and the latter reported VTL1 enabled, while VTL1 CR3 and RIP both returned
Hyper-V status 6 (`ACCESS_DENIED`). The temporary service and files were removed and K3 retained
heartbeat `OK`; the local evidence is
`target/codex-m7/m7-nested-vtl1-feasibility.json`. Therefore raw SELF/VTL1 hypercalls are a
rejected provider design, not an implicit fallback.

**Provider choice passed on 2026-10-24.** K3 now owns one exact generation-2 L2,
`e35248f3-d779-44c1-8f69-8a8cc27bc11b`, on a pinned differencing disk. Its first bounded boot
reached PowerShell Direct, heartbeat `OK`, VBS status 2 and boot identity
`2026-10-24T09:31:24.6653173Z`. From K3, the pinned H3 driver enumerated exactly one child,
partition `0x2`, and read VP0 VTL0 CR3, VTL1 CR3, `VsmVpStatus` and `VsmPartitionStatus` with
status zero; the low partition-status bits report both VTL0 and VTL1. The raw record is
`target/codex-m7/m7-child-vtl1-feasibility.json`. That first-start boot id is historical evidence,
not the capture identity; the later qualification below records and freezes the current child boot.

The independent identity binding also passed. WMI bound that exact L2 id to nested `vmwp` PID
4124. A bounded handle census found one identity-bound VID candidate (`ERROR_ACCESS_DENIED` when
duplicated, as the earlier qualified probe requires); CDB attached to that exact process, called
`vid!VidGetHvPartitionId` in-process on source handle `0x2c0`, and received partition `0x2`.
It restored the one-byte return breakpoint, detached, left no CDB process or staging directory,
and both K3 and L2 retained heartbeat `OK`. The record is
`target/codex-m7/m7-l2-binding.json`. The command-line startup handle `0x334` was tested and
correctly rejected by VID; it is not used as a partition identity.

**The first provider-qualification control passed on 2026-10-24.** On parent boot
`2026-10-24T09:08:18.5667664Z` and child boot `2026-10-24T09:32:31.5773667Z`, the provider ran
inside K3 against the exact nested PID/handle/partition chain above. With only L2 paused, it read
VTL1 CR3 `0x1e381000`, RIP `0xfffff80509560035`, found the pinned Secure Kernel image at
`0xfffff8050fb1a000`, matched its PE identity and all seven manifest byte guards, and produced
identical complete register snapshots before and after with `writes: 0`. It resumed L2, removed
the temporary H3/hvmm services and runtime staging, and left both heartbeats `OK`. The record is
`target/codex-m7/m7-provider-readonly.json`. This passes only the read-only subgate; it is not the
arm/event/restoration qualification.

**The first nested-parent write/event/restoration controls passed on 2026-10-24.** The no-op
debug-register round trip wrote and read back DR0-DR3, DR6 and DR7, then proved the complete before
and after snapshots equal. Its record is `target/codex-m7/m7-provider-roundtrip.json`. The separate
arm/restore control installed DR0 and DR7, restored DR0-DR3, DR6, DR7 and RFLAGS in its `finally`
path, and again proved exact final-state equality. Its record is
`target/codex-m7/m7-provider-arm-restore.json`. Both controls resumed the child, removed the
temporary H3/hvmm services and staging, and left its heartbeat `OK`.

The first natural held-event control then passed on parent boot
`2026-10-24T14:01:53.5683807Z` and child boot `2026-10-24T14:17:57.5748892Z`. It rebound the exact
child to nested `vmwp` PID 5860, source VID handle `0x2c4` and partition `0x6`; matched the image,
mapped text and manifest guards; armed a hardware breakpoint; and retained a vector-1 slot-0 event
at the guarded instruction `0xfffff8060d394900` without redirecting execution. Teardown released
the event, proved the entire saved register snapshot equal, removed the worker, listener, services
and staging, and left both VMs running with heartbeat `OK`. The result reports
`released=true`, `target_left_running=true`, `worker_terminated=true`,
`recovery_required=false`, no error and no reported secret. Its record is
`target/codex-m7/m7-provider-event.json`. This is one successful natural-event run, not the
three-clean-boot qualification and not the provider-death control.

**The nested-parent provider-death control passed on 2026-10-24.** On the same parent boot
`2026-10-24T14:01:53.5683807Z` and child boot `2026-10-24T14:17:57.5748892Z`, the control
provider ran with `--exit-before-response publish_stop`, the acknowledgement boundary the earlier
live provider-death injection used, over the exact chain nested `vmwp` PID 5860, VID handle
`0x2c4` and partition `0x6`. The natural slot-0 event at `0xfffff8060d394900` arrived, the
provider exited before acknowledging it, and `sk_live_wait` returned the terminal fault
`provider closed its stdout` with `target_left_paused=true` and the recovery error `control
protocol desynchronised`. `end_session` reported `recovery_required=true`, `released=false` and
`worker_terminated=false`, naming retained worker PID 4192. The independent read taken while that
worker was retained found DR0 still armed at the guarded address, DR7 `0x401`, DR6 `0xffff0ff1`,
RIP on the guarded instruction, every manifest guard matching and the mapped text hash unchanged;
the control-provider child was gone with its injected exit in the listener log and the live-memory
child remained. A bounded `Get-VM` of the child did not answer within 30 seconds, and the first
recovery attempt's `Get-VM` failed after six minutes with `object not found`, so no Hyper-V health
reading of the contained child exists and continued guest health is not claimed. That evidence was
sealed to `target/codex-m7/m7-provider-death-evidence.json` before recovery.

The first harness attempt's evidence block and the first recovery attempt both failed on exactly
that VMMS query; the recovery attempt took no action and its record is kept as
`m7-provider-death-recovery-attempt1.json`. The standalone collector and the corrected recovery
read only the `vmwp` process until the debugger is gone. The dedicated recovery then issued a
bounded power-off request, which timed out while the debugger held `vmwp`, terminated the exact
worker tree, which ended the contained `vmwp`, turned off the replacement boot Hyper-V started on
its own, and restarted the child deliberately: new child boot `2026-10-24T15:39:51.5768400Z`,
`vmwp` 5812, heartbeat `OK`, VBS status 2, zero retained processes, the listener, drivers, firewall
rule and staging removed, and the parent on its original boot with heartbeat `OK`.
`finalize-m7-provider-death.ps1` re-checked every field from the raw records and the live lab and
wrote `target/codex-m7/m7-provider-death-control.json` with result `pass`. This proves containment
and recovery, not restoration by the dead provider.

**The three-clean-boot provider qualification passed on 2026-10-24.**
`run-m7-provider-qualification.ps1` recreated the child from its pinned parent before each run and
then drove the complete positive sequence through the K3-hosted listener: baseline read-only probe,
`open_sk_live_control`, natural slot-0 arm at base plus `0xEA900`, guest-triggered VTL1 event,
`end_session`, independent restoration audit and cleanup. The runs are
`target/codex-m7/live-qualification/20261024T154937/`, `20261024T155332/` and `20261024T155743/`,
each holding its reset record and its event record. Their child boots
(`2026-10-24T15:50:52.5847177Z`, `15:54:46.5753379Z` and `15:58:58.5915607Z`), nested `vmwp`
PIDs (1920, 1468 and 2324), H3 partition ids (`0xb`, `0xc` and `0xd`) and randomized Secure
Kernel bases were all distinct; the parent stayed on boot `2026-10-24T14:01:53.5683807Z`
throughout, and the staged server, image and profile hashes were identical across runs. Every run
froze its VID handle, partition id, CR3 `0x1201000`, image and every manifest guard at the
baseline, retained one owned vector-1 slot-0 VTL1 event at the guarded instruction, released with
`released=true`, `worker_terminated=true`, `target_left_running=true` and
`recovery_required=false`, and audited DR0-DR3/DR6/DR7 and TF/RF equal to the baseline with the
mapped text hash unchanged within the run, zero engine workers, zero retained processes, no
residual services or staging, and both heartbeats `OK`. The mapped `.text` hash differs between
runs because the image is relocated to a different base on every boot; within a run it is the
invariant. Two earlier driver launches aborted on PowerShell 5.1 script faults after a reset and
before any session opened; their reset-only directories `20261024T154328/` and `20261024T154623/`
are not part of the qualification. `finalize-m7-provider-qualification.ps1` re-checked every field
of the three reset and event records against each other, the provider-death control and the live
lab, and wrote `target/codex-m7/m7-provider-qualification.json` with result `pass`.

Refinement proceeds as three separately gated phases:

1. **Provider choice: passed.** Use the nested L2 workload and run M6's provider in its K3 parent.
   The parent/child ids, both boots, nested `vmwp`, identity-bound VID handle and H3 partition id
   are one required chain. The external-L0 design remains an unqualified fallback, not a second
   active path. Cross-boot joins and raw VMCS parsing remain forbidden.
2. **Provider qualification: passed.** The read-only L2 RIP/CR3, exact-image and manifest-guard
   control, the no-op debug-register round trip, arm/reverse restoration, one natural held-event
   control, the nested-parent provider-death control and the complete positive sequence on three
   clean child boots through the nested-parent boundary all passed, as recorded above. Access
   denied, unavailable state, identity ambiguity or incomplete restoration would have failed the
   phase; none was converted to coordinate-only for semantic tracing.
3. **Idle coexistence: attempted, blocked.** Phase 2 is satisfied; the transaction opened and
   armed all three layers in one live parent/child topology on 2026-10-24, first as
   M5 -> M4 -> M6 until M5's trace cap froze the parent and child, then as M4 -> M6 -> M5 until
   M6's drain faulted under its own bootstrap traffic, a third run showed M4's and M6's
   hardware breakpoints sharing the child VP's DR0, and a fourth, with M4 on a software
   breakpoint, deadlocked the child on that breakpoint's first hit (all recorded below). It must
   still arm all three without a workload,
   drain in reverse order and prove byte/register baselines, both heartbeats, unchanged
   boots/`vmwp` processes and zero retained processes, with failure/timeout injection. M7.2 stays
   closed until this exact live control passes.

**The admitted-topology driver exists and ran, 2026-10-24 evening; the gate is blocked by the
protocol's arm order, not by the topology or by the trace.** `target/codex-m7/run-m7-nested-coexistence.py` drives M5
over `k3-hypervisor` and M4 over a new `l2-nt` profile from the host server, and M6 through the
K3-hosted listener, under the same `--m7-transaction-protocol` process. Its wiring is recorded
in `m7-nested-kd-wiring.json`, `m7-k3-boot-repair.json` and `m7-l2-kdnet.json`: both of K3's
KDNET host IPs and the child's point at the host's current switch address, which moves on every
host boot, so `configure-m7-l2-kdnet.ps1` reapplies the child's wiring after each reset. Three
measurements along the way decide how the driver must behave:

- A `continue_async` issued straight after `attach_kernel` on the nested hypervisor is
  acknowledged and does not resume K3: heartbeat `Lost Communication`, PowerShell Direct dead,
  guest clock unreadable, both NICs silent, with and without a child running
  (`m7-m5-network-effect-with-l2.json`, `-without-l2.json`). A 5 s bounded run whose break-in is
  collected at the bound, followed by the real run, leaves K3 running with heartbeat `OK` and
  its clock advancing while the session stays open. That is the cycle the M5 qualification runner
  used; the coordinator now performs it in `settle_hypervisor` before M5's bounded run. The
  first nested run, taken before this was measured, parked M4's attach for its 300 s bound and
  left the child at a KD break; a serial-pipe transport for M5 was tried on that misreading, its
  attach parked, and the `kd.exe` probe against the pipe hung this bench. The serial path is
  removed and rejected.
- With M5 settled and running, `l2-nt` lands in 1.7 s and releases cleanly while the hypervisor
  session is open (`m7-hv-coexistence-probe.json`).
- In the full run `live-coexistence/20261024T190156/`, preflight, all three opens and the M5 and
  M4 arms succeeded. M5's trace then retained its 1,024-transition cap in 2.09 s, 512 calls and
  512 returns at about 490 transitions per second on an idle child, and `hv_transition_trace`
  stops the hypervisor at the event that reaches `max_transitions`, whose largest accepted value
  is 1,024. K3 and L2 froze about two seconds after M5 was armed and resumed: M6's arm could not
  reach the child to register its trigger, M4's break-in never arrived inside its 60 s wait, and
  M4 ended unresolved. The protocol closed M5 and M6 cleanly and reported the M4 child unsafe,
  which is the specified behaviour. The child was released afterwards by a fresh attach and
  `end_session`, and the lab audited clean. The stop itself is by design: a hypervisor held by
  its debugger holds every partition under it, so nothing beneath M5 can be armed, drained or
  reached while M5 is stopped. The transaction arms M5 first and drains it last, which is the
  one order that cannot work; the trace cap is only where that stop first landed.
- In `live-coexistence/20261024T210251/`, under the inverted order, preflight, all three opens,
  all three arms and M5's drain succeeded, with M5 attached and settled last beside the open M4
  and M6 sessions. The M6 arm's bootstrap (`spin_host.exe DE1 2000` as a scheduled task in the
  child) drove the VTL1 trigger at about ten events per second for 37 s, 371 retained stops; the
  coordinator drained M6 about 0.4 s after the last one, and the running-trace stop path settled
  `vmwp` for its 1 s window with the arrival breakpoint installed and DR7 still armed, so one more
  event faulted it ("vmwp stopped unexpectedly while settling native event completion"). Its
  recovery asked VMMS to pause the child while the dispatcher held `vmwp` stopped, which hung for
  60 s; the session failed closed with the child paused, M4's break-in never landed, both workers
  were retained, and terminating the M6 worker took `vmwp` with it and left the child Off, started
  again from K3. The K3 listener log is saved beside the report.
- In `live-coexistence/20261024T212721/`, with a quiescence wait added to the driver's M6 arm,
  M6's arm failed on its first event: the provider's guarded writes logged
  `Dr0 expected=0xfffff804a105eeb0`, which is `nt+0x2eeeb0` at that boot's kernel base, M4's
  `nt!VslpEnterIumSecureMode` breakpoint, and `Dr6 expected=0xffff0ff1`, M4's B0, while VTL1's
  DR7 read `0x400`. The first event, 9 ms after the arm's VM resume, carried `DR6=0xffff4ff0`,
  single-step only, and was refused as "hardware-stop DR6 must name exactly one breakpoint slot".
  M6 recovered cleanly with the child running; M4's drain found no stop in 60 s because the child
  sat in a KD break its dead orphan could not answer, and a fresh `l2-nt` attach read
  `dr0=fffff804a105eeb0 dr6=ffff0ff0 dr7=400` from VTL0 and released it. The same overwrite
  happened unnoticed in the previous run, whose 371 events were all clean slot-0 hits. Both runs'
  host and K3 residue was removed by exact PID and the staging cleanup, and both guests ended
  healthy.
- In `live-coexistence/20261025T073515/`, on build `0.23.0+g2296ed9c`, preflight, all three opens
  and M4's arm succeeded, the first live arm of M4's software breakpoint. M6's arm then failed in
  the driver's bootstrap step: PowerShell Direct into the child broke 33 s after M4 armed, M4's
  drain break-in produced no stop in 60 s, and M4's worker was retained with the child's KDNET
  port. From K3 the child read Running, CPU 79%, heartbeat lost, and a fresh `l2-nt` attach from
  the host parked. The child's VTL0 state and stack were read from K3 and are the measurement in
  continuation item 2: a nested breakpoint trap under a held `KdDebuggerLock`, raised by the
  debugger's own protected-text write entering VTL1 through the patched entry. M6's stop fix was
  never reached. The host orphan was terminated by exact PID, the parked attach handed off with
  `kernel_handoff_pid`, and the K3 staging removed; the child needs a turn-off and start from K3.
- In `live-coexistence/20261025T084128/` and `20261025T084354/`, on build `0.23.0+gb108cd87`
  with the slot partition and the order M6 -> M4 -> M5: the first run was refused at M6's arm by
  the driver's own slot-0 bootstrap breakpoint and released everything cleanly; the second armed
  M6 on slots 1-3 with the partition measured from K3, then lost M4's break-in to the VTL1
  dispatcher's intercept (continuation item 2). Both runs cleaned up completely with both guests
  healthy; no residue on the host or in K3.
- In `live-coexistence/20261025T113332/`, on build `0.23.0+gb108cd87-dirty.fde8a56f` (the
  committed tree plus a record dump at the event site and an `HV_INPUT_VTL` sweep in the K3
  probe): M6 armed on slots 1-3, the sweep at idle and at the VTL1 hold measured the active-VTL
  encoding (continuation item 2), M4's break-in was lost exactly as in `084354`, and both
  guests were healthy at cleanup. The record dumps scrolled out of the 16 KB log tail the
  harness kept; it now keeps the whole listener log beside the run.
- In `live-coexistence/20261025T115420/`, on build `0.23.0+gb108cd87-dirty.0e1a862e` (the
  pass-through built): M6's service trace, still at a 16-record limit, filled on the bootstrap
  trigger and restored its slots within a second, so the partition check read VTL1 DR7 `0x400`
  and failed before M4 armed; the driver's emergency `end_session` of M4 then broke into the
  child, and that `int 3` reached M6's dispatcher during its capacity disarm. The triage
  worked to the last step: the provider read the active VTL as 0 (the record dump read
  `03 01 01`, vector 3, software, length 1), and the re-delivery write naming target VTL 0 was
  refused with `HV_STATUS 0x0005`. The provider died on the refusal, recovery held the event
  as its own with no register access left, and the child was left paused under a contained
  `vmwp` with VMMS blocked; M4's host worker was orphaned by its supervisor's exit. Recovered
  with `recover-m7-provider-death.ps1` (bounded CIM off, exact worker and provider kill,
  staging removal, deliberate restart: child up on a fresh boot at 12:07Z, K3's boot
  unchanged) and the orphan killed by exact PID and path. Fixes: the provider writes the
  pending interruption with the InputVtl byte clear, as VID's own completion does, and
  answers an error instead of exiting; the driver's trace keeps the server's 1024-record
  limit so M6 stays armed through M4's window.
- In `live-coexistence/20261025T121217/`, on the same build with those fixes: M6 armed and
  stayed armed, every VTL1 event of the trace was triaged as its own (the provider answered
  `active_vtl` 1 for each), the partition check passed, and M4's break-in reached M6's wait
  loop as the `int 3` it is: triage read the active VTL as 0 and asked for the re-delivery,
  and the pending-interruption write was refused with `HV_STATUS 0x0005` again, this time
  with the InputVtl byte clear. So that register is refused in this state whichever way it
  is addressed, and the typed interruption form is not the hypervisor's door here. The
  provider answered an error, the session faulted with recovery intact (`recovery_errors`
  none, the child left running), M4's break-in was lost once more, and everything released:
  both guests healthy, no residue. Next attempt: the pending exception event
  (`HvRegisterPendingEvent0`, the form WHP documents for exception injection) first, the
  typed interruption as fallback, with the dispatcher asking VID's completion to advance past
  a software exception's instruction when the event form is used.
- In `live-coexistence/20261025T122621/`, on build `0.23.0+gb108cd87-dirty.5def51e9`: the
  hypervisor accepted the pending exception event (`HvRegisterPendingEvent0`, value
  `0x30001`, written with the InputVtl byte clear), the dispatcher wrote the record's advance
  byte, carried the `int 3` natively and re-armed its site, and `vmwp` then stopped at the
  site some 430 times in the next minute for events the dispatcher does not own, about every
  60 ms in pairs, while the VTL0 debugger still saw no stop. The second break-in, the
  driver's emergency end of M4, faulted at retention: the record is the VP's fixed message
  slot and VID does not clear the advance byte for the next message, so it still read 1 and
  recovery, finding the same byte, left `vmwp` contained and the child paused. Recovered as
  before (bounded off, exact worker kill, staging removed, deliberate restart; K3's boot
  unchanged). Fixes: the carry clears the byte again once completion has consumed it, the
  dispatcher logs the events it passes at its site, the provider reads the armed register
  back after the write, and the driver reads the child's VTL0 RIP when a break-in times out,
  so the next run says whether the re-delivered exception reached the kernel debugger and,
  if not, where VTL0 is instead.
- In `live-coexistence/20261025T124429/`, on build `0.23.0+gb108cd87-dirty.b0bb8d71`: the
  armed event read back `0x30001` right after the write, and when the break-in timed out the
  probe read it as `0x30000`, consumed, with VTL0 back at its idle RIP and stack, DR6 clean
  and no trap taken, while the host's debugger session still pumped its run. So the
  completion of the intercepted message discards whatever pending event is armed at that
  moment, which is also what it does to the intercepted exception itself. The 949 events the
  dispatcher passed at its site in the following minute were 933 of VND message type `0x1`
  on VP 0 through one `vmwp` handler context, about every 64 ms, a handful of type `0x7` and
  `0x9` with no VP, and one `0x1000003`; their meaning is unmeasured. The trace's wait then
  reached its own deadline, recovery's pump met a stop at `ntdll!DbgBreakPoint` it refused
  as not its own, and the session was left contained; recovered as before. The redelivery
  is now two halves around the completion: the provider holds the VP with
  `HvRegisterExplicitSuspend` before the dispatcher completes the message, and once the
  completion is behind it arms the pending exception event and releases the suspension.
  During the running disarm's pump no redelivery is attempted, because its own resume could
  undo the pause the pump is waiting for; the loss is logged.
- In `live-coexistence/20261025T130540/`, on build `0.23.0+gb108cd87-dirty.54c2925d`, the two
  halves ran in order: the provider held the VP with `HvRegisterExplicitSuspend`, the
  dispatcher wrote the advance byte and ran `vmwp` toward its native return, and that return
  took 13.3 s to arrive, when the dispatcher's own delayed completion kick paused the VM at
  13:08:07; the event was then armed (readback `0x30001`) and the suspension released with
  status 0, yet at the break-in's timeout VTL0 was again at its idle RIP with the event read
  as `0x30000`, no trap taken, and the kick's resume failed with "VM did not resume", so the
  trace's wait reached its deadline and the session was left contained; recovered as before.
  Three ways of handing the exception back are now measured not to work, and the code is
  back to triage and carry: the typed pending interruption (refused), the pending event armed
  before the completion (discarded with the intercepted exception), and the pending event
  armed under an explicit suspension held across the completion (blocks VID's completion,
  consumed without a trap). What re-delivers an exception nobody claims is `vmwp`'s own
  handler writing through VID's deferred VP-state path, flushed in the completion's own
  hypercall; no root-side path into that batch has been demonstrated.
- In `live-coexistence/20261025T144453/`, the first run of the alternating plan: window 1
  (M6) opened, armed, drained and ended clean, and the first switch read every field clean
  except the handler, which the driver's evidence looked for under the per-context free line
  the clean release does not write; the coordinator refused the next window on it, as built.
- In `live-coexistence/20261025T145011/`, the switch passed and M4's arm was refused by the
  driver's own slot check: VTL0 DR7 read `0x400` with the target stopped at the arm, because the
  kernel debugger's `ba` reaches DR7 with the continue. M4 and M5 were ended, nothing retained.
- In `live-coexistence/20261025T145507/`, with the slot read after the bounded run starts: the
  three windows and both switches passed, and the finalize check passed on the raw records and
  the live lab; the M7.1 live result paragraph has the readings.

Continuation order from this checkpoint:

1. **Done, 2026-10-24 evening.** The transaction arms M4 VTL0, then M6 VTL1, then M5 hypervisor
   immediately before the workload, and drains M5 first, reading its trace while the hypervisor
   is stopped and then resuming it before M6 and M4 are drained and before any session is ended.
   `ARM_ORDER` and its rationale in `src/skcorrelate.rs` moved, with the offline tests that pin
   the order and the reverse restoration (the 14 unit controls and the two engine-free protocol
   smoke tests pass), the M7.1 changelog entry, and the driver's recorded order and M5 drain,
   which now resumes the hypervisor after its read. Opening follows the same order, so the
   hypervisor is attached and settled last, beside sessions that hold nothing a brief stop can
   disturb. The cap stays as it is: on an idle child it is reached about 2 s after
   M5 is armed and becomes M5's drain point, and for M7.2 it is the latency budget inside which
   the workload must land, a measurement for that gate rather than a coexistence blocker.
2. **Decided 2026-10-25 and done in the tree: the two layers partition the child VP's slots.**
   M4 keeps its processor breakpoint in slot 0; M6 opens with `reserved_hardware_slots: [0]`, arms
   the manifest's three sites in slots 1-3 (`ServiceManifest::breakpoints_outside`, mapped back by
   the decoder's `SlotMap`), writes, restores and compares only the slots it armed, and reads DR6
   only through its own B bits (`LiveControl::owned_slots`, `owned_cause_mask`). DR7 is per VTL, so
   each VTL enables only its own slots and neither fires on the other's address. Because the
   kernel debugger writes its whole cached debug-register block back at every stop, M6's slot
   writes must never overlap a VTL0 debugger stop: the transaction arms M6 before M4 and drains M4
   before M6 (`ARM_ORDER` is now M6 -> M4 -> M5), and M6's per-event writes happen while the VP is
   held in VTL1. Offline: a reserved slot is refused at arm and skipped by a break request, a
   restore leaves a foreign slot's value alone, a foreign sticky DR6 bit does not disqualify an
   owned stop while a stop naming only the foreign slot is refused, the manifest remaps to slots
   1-3 and the decoder follows, and the coordinator's order tests moved; each controller test was
   mutation-verified against the half of the discipline it pins. What the rerun measures and
   nothing offline can: that the VTL0 debugger's write-back at its stops preserves slot 1-3 values
   it did not set, read as DR0-DR3 and both DR7s from K3 after each arm.
   **Measured 2026-10-25, runs `20261025T084128` and `20261025T084354`.** The first failed at
   once because the driver's own bootstrap `sk_live_arm` still named slot 0; the reservation
   refused it cleanly and everything released. In the second, M6's arm succeeded on slots 1-3
   and the K3 probe read, after it, VTL1 DR7 `0x454` (slots 1-3 enabled), VTL0 DR7 `0x400`
   (nothing enabled), DR1-DR3 holding the three Secure Kernel sites identically in both VTL
   views, DR0 zero, and the bootstrap stop on slot 1: the partition holds and DR7 is per VTL.
   M4's arm then failed: its break-in at 08:45:40.5 produced no VTL0 stop in 60 s, and 1.2 s
   after it M6's trace faulted on "the dispatcher event context does not match the registered
   exception handler", the vector-3 handler's context. The kernel debugger's break-in is an
   `int 3` in VTL0; the dispatcher's exception intercept delivered it to vmwp as if it were a
   VTL1 event, the dispatcher held it, live control refused it, recovery completed it natively,
   and native completion reports the event *handled* (`rax == 1` at `handle_return` is
   required), which suppresses the exception rather than injecting it, so the VTL0 kernel never
   saw its break and the child re-executed the `int 3` until M6's teardown unregistered the
   handler, after which the child read healthy. Yesterday's single-step-only event in run
   `20261024T212721` was the same mechanism on vector 1: DbgEng's TF step over M4's breakpoint in
   VTL0, delivered to M6's dispatcher 9 ms after its VM resume. So the exception intercept is
   VTL-agnostic, M4's own `ba` hits and single steps would be eaten the same way while M6's
   handler is registered (and a suppressed execute-breakpoint fault re-fires at the same RIP),
   and the `vsm_vp_status` the provider reads is `0x30010` at genuine VTL1 holds and at idle
   alike, so it does not tell the VTLs apart. Coexistence therefore needs the dispatcher to hand
   VTL0 exceptions back to VTL0.
   **Measured and built 2026-10-25, run `20261025T113332`.** Three things decided the shape. The
   user-side message VID builds carries no VTL: Ghidra over `Vid.sys` shows
   `VidHandleExceptionIntercept` writing the vector (`+0x20`), its software flag (`+0x21`), the
   raising instruction's length (`+0x22`), the error code and the parameter, and
   `VidMessageBufferPrep` the type, VP and context, nothing else, so the `ExecutionState.Vtl`
   this item hoped to read lives in the kernel's record only. The forced completion was never
   an answer: in `VndCompletionThread::RunSelf` the handler's return at `handle_return` only
   picks the flags of the next `VidMessageSlotHandleAndGetNext` (3 against 1), and a zero would
   leave the message outstanding with the VP suspended; what re-delivers an exception nobody
   claims is `vmwp`'s own `WorkerExceptionHandler::Notify`, which writes
   `HvRegisterPendingInterruption` (`0x00010002`) with pending, type 3 for a hardware exception
   or 6 for a software one (5 for `INT1`), the instruction length at bits 5-8 and the vector at
   bits 16-31. Written from the root while the VP sits in its intercept, that register was
   refused with `HV_STATUS 0x0005` both naming target VTL 0 (run `20261025T115420`) and with
   the InputVtl byte clear, the way `VidCompleteInterceptReturnCallback` writes VP registers
   (run `20261025T121217`). `HvRegisterPendingEvent0` was accepted, read back `0x30001`, and
   consumed without a trap, armed before the completion (run `20261025T124429`) or under an
   explicit suspension held across the completion, which also blocked VID's completion for 13 s
   (run `20261025T130540`). And the hypervisor does say which VTL is executing: `HvGetVpRegisters` with
   `HV_INPUT_VTL` UseTargetVtl clear returned VTL0's CR3, RIP and RSP in three idle samples and
   VTL1's while VP0 was held at the bootstrap breakpoint, with `vsm_vp_status` read the same way
   at `0x30010` and `0x30001`; read as a target VTL (`0x10 | vtl`) the status names the VTL asked
   about, which is why the provider's reading never discriminated. What stays in the tree is
   triage and carry: the provider gained the `active_vtl` capability and operation, the dispatcher puts
   every event at its site to the controller's `EventTriage` before holding it, in a wait and in
   the running disarm's pump, and a foreign event is carried natively with the site re-armed,
   so M6 neither takes it as its own stop nor faults; the profile layout locates VID's two
   bytes for the record. Offline: a foreign event is carried and the wait continues, a provider
   without the capability keeps every event, and the running disarm carries one before its
   pause; each pinned against the mutation it is for. **The conclusion, 2026-10-25:** with the
   intercept per partition and no demonstrated root-side path to hand the exception back (the
   runs rule out the pending-interruption and pending-event registers written from the root on
   this build, not every conceivable path), the VTL0 debugger loses every break-in, breakpoint
   hit and single step while M6's handler is registered, and the slot partition does not change
   that. **Decided the same day:** (a) alternate at session level, closing M6 between M4's
   windows, as the interim containment for M7.1's idle gate; this revises that gate's acceptance
   criterion and is recorded under M7.1 with the transition checks each switch must prove;
   **done the same afternoon**, run `20261025T145507`, finalized `pass`. (c)
   Design M7.2 off M4's hardware breakpoints and off the shared VP's exception path, reading the
   NT-side arguments from M6's entry phase; before adopting it, prove field by field that M6's
   entry data preserves every required M4 field or name the replacement, recorded under M7.2.
   (b) Re-delivering from inside `vmwp` through VID's own deferred VP-state path, which
   `WorkerExceptionHandler::Notify` reaches through a VND VP-state vtable (`+0x1b8`) and the
   dispatcher would reach by calling it on the callback thread as it calls the handler
   registration, stays a fallback: a brittle private-ABI dependency inside `vmwp`, with its own
   live proof still to run and every M4 `ba` hit then costing a `vmwp` round trip. Two smaller
   facts from the same runs, both unmeasured further: after a lost break-in `vmwp` saw a VND
   message of type `0x1` on VP 0 about every 64 ms, and recovery's pump once refused a stop at
   `ntdll!DbgBreakPoint` as not its own.
   The alternatives considered and the measurement that ruled out the first answer follow.
   The history: DR0-DR6 are shared between VTL0 and VTL1 on a VP and only DR7 is per VTL, as run
   `20261024T212721` measured: M6's arm found M4's `nt!VslpEnterIumSecureMode` address in DR0 and
   M4's B0 in DR6, overwrote both, and refused its first event. The first answer, a DbgEng software
   breakpoint at the same entry, was armed live in run `20261025T073515` and deadlocked the child
   on its first hit. Read from K3 while the child answered neither heartbeat nor KDNET: VP0's VTL0
   state was identical in six samples, one byte past a `pause` in `nt!KxTryToAcquireSpinLock`
   spinning on `nt!KdDebuggerLock` (word 1) under `KeFreezeExecution` <- `KdEnterDebugger` <-
   `KdpReport` <- `KdpTrap` <- `KdTrap` <- `KiDispatchException`; the deeper frames were
   `KiBreakpointTrap` with trap RIP `VslpEnterIumSecureMode+1` under `VslWriteProtectedPage` <-
   `MiDbgCopyPrivilegedData` <- `MiCopyToUntrustedMemory` <- `MiDbgWriteCheck` <-
   `MiDbgCopyMemory`, and the entry's first byte was still `cc`. So the kernel debugger writes
   HVCI-protected text by asking the Secure Kernel through the very entry that was patched: the
   write that inserts or removes the breakpoint executes it, the second trap finds the debugger
   lock held, and the single processor never returns. The old no-patch comment was right for a
   reason it never stated; it is measured now, and the arm is a processor execution breakpoint
   again. Any software breakpoint on the debugger's protected-write path (`VslWriteProtectedPage`,
   `VslpEnterIumSecureMode` and what they call) has the same effect; software breakpoints
   elsewhere in protected text are what that path exists for. The candidates weighed before
   the partition: M4 arms
   software breakpoints at the `call` sites inside the callers the workload exercises
   (`VslCreateEnclave`, `VslLoadEnclaveModule`, `VslInitializeEnclave`, `VslCallEnclave`,
   `PsTerminateVsmEnclave`), where CL, DX, R8D and R9 are already loaded and the debugger's write
   path never runs, refusing any site on that path; or M4 arms nothing and the NT-side arguments
   come from M6's entry phase, with the VTL0 process and caller identity supplied another way.
   The partition keeps M4's own instrument and needs no new VTL0 site. The
   single-step bit that reached VTL1's first event after a VM resume still needs its path
   measured; M6's exactly-one-slot check reads only the four B bits, so it does not count it.
   Records: `live-coexistence/20261025T073515/l2-vtl0-hang-sample.json`,
   `l2-vtl0-hang-deeper-stack.json` and `l2-vtl0-hang-symbols.txt`.
3. **Done in the tree, 2026-10-25: the stop of a running natural trace holds an arriving event
   as its disarm point.** Run `20261024T210251` measured the fault: the last event's completion
   re-armed the trace, arrival breakpoint installed and DR7 live, and 1.3 ms later the stop
   request's wake sent the next wait into break-on-demand, whose running disarm ran
   `settle_native_completion`, a 1 s `g` whose only accepted ending is its own deadline. The
   armed trace fired at the arrival site, as an armed trace does, and the code called that
   "unexpected"; the fail-closed recovery then asked VMMS to pause a `vmwp` the dispatcher itself
   held stopped, which hung for 60 s. The assertion held only while the trigger was idle, a
   property of the guest's activity and not of the dispatcher's state, and the solo qualification
   never exercised it because its drains ran long after the trigger went quiet. The replacement is
   `pause_or_hold_running_target` in `src/skdispatch.rs`: the running disarm asks Hyper-V to
   pause from a helper thread and pumps `vmwp` in 250 ms slices under the installed event-site
   breakpoint until either the pause is reported complete at a watchdog break, so no VP can raise
   an event, or an owned event arrives and is retained exactly as a wait retains one. Live
   control restores the VTL1 baseline under that event; a wait adopts it as its stop, a break
   request takes it in place of a transient slot, and a close completes it into the pause teardown
   needs. Recovery from a running arm takes the same path, so no path pauses a debugger-held
   `vmwp`. This also folds in the VTL1 debug-exception hazard: the breakpoint stays installed and
   `vmwp` stays attached until no VP can raise an event, so an intercept never reaches `vmwp`'s
   handler with nothing watching it, and what the native handler would do with a VTL1 `#DB` nobody
   is waiting for stays unmeasured by design. Offline, 130 dispatcher and live-control tests pass,
   including the new pump-decision, adoption and close tests, each mutation-verified against the
   half of the fix it pins. Two things the rerun measures that offline tests cannot: that
   Suspend-VM completes while `vmwp` runs attached under DbgEng (Resume-VM already does, in the
   post-step wait), and that a pending pause completes once the held event has been carried
   natively. The driver's `await_m6_quiescence` gate is removed so the drain is issued while the
   trigger may still fire; a non-stopping trace read before the drain stays as a reading. The
   multi-provider stop keeps its pre-existing window (a winner completed before its pause with
   DR7 still armed); M7 selects one VP and that path is out of this item's scope. Run
   `20261025T073515` never reached M6's arm (the child hung on M4's first hit, item 2), and this
   paragraph said "still unproven live" until it was read against the later runs' listener logs
   on 2026-10-25. **Both branches ran live that day.** The hold branch fired four times, once each
   in `20261025T121217` and `20261025T145011` and twice in `20261025T145507`: in the last, at
   14:57:00.98 the dispatcher asked Hyper-V to pause and pumped `vmwp` under its event-site
   breakpoint, 13 ms later logged that it held a VTL1 event that arrived during the disarm as the
   disarm point, the wait adopted it, and the controller retained it as a slot-1 hardware stop;
   the third window repeated the sequence at 14:58:29.43, and the pending pause then completed
   after the held event was carried (Hyper-V's pause verified at 14:58:30.28, the native
   completion settled, the resume with the VTL1 baseline restored at 14:58:32.01). The
   pause-proved branch, where the pump ends at a watchdog break with no event outstanding, fired
   once, in `20261025T122621`. So the two things the rerun was to measure are measured. What has
   not run live is narrower than the item: all four holds came through the arm's bootstrap break
   request, whose wait adopts the event; the other consumer, a trace drain or close receiving a
   held event and releasing it into a proved pause, has had no occasion, because every drain so
   far ran with the trigger idle and zero records. The first M7.3 workload run drains while
   events are in flight and exercises it without a dedicated control.
4. Then rerun `run-m7-nested-coexistence.ps1`: open all three, arm M4 -> M6 -> M5, launch no
   workload, drain M5 -> M6 -> M4, and repeat the relevant failure and timeout injections. M4's
   software breakpoint is first exercised live here. The gate requires
   unchanged identities and byte/register baselines, healthy parent and child, and no retained
   process. Any Hyper-V management query of the child while a layer holds its `vmwp` must be
   bounded, for the reason the provider-death control measured.
5. Only after that live coexistence result is recorded may M7.2 implement and qualify the
   deterministic join below. **Done 2026-10-25**, after M7.1 passed under its revised criterion:
   the join is implemented and qualified offline under M7.2, and its live qualification is M7.3's.

The event, provider-death and qualification harnesses depend on the `src/listen.rs` change that
adds the explicitly bound non-loopback IP to rmcp's Host-header allowlist while retaining the
loopback defaults; its matching `CHANGELOG.md` entry is beside it, and both land in the same commit
as this checkpoint. The staged server identity in every record above,
`0.23.0+ga7a37906-dirty.f64e9801`, is the build that carried them before that commit. The lab
harness and raw reports remain intentionally ignored under `target/codex-m7/`.

#### M7.2 — deterministic join

The workload label and `capture_id` select a capture; neither proves that two events are one call.
Within the admitted one-VP capture, assign a `call_id` only when the observed order is:

```text
M4 VTL0 entry -> M5 vtl_call -> M6 entry -> M6 selected dispatch -> M6 return -> M5 vtl_return
```

**Open before the chain can start from M6, 2026-10-25.** The chain begins with an M4 VTL0 entry
event, and M7.1a's continuation item 2 decided to design M7.2 off M4's hardware breakpoints.
Replacing the first stage with M6's entry phase is sound only if M6's entry data preserves every
required M4 field or names its replacement: the VTL0 PID and TID, the caller's provenance (return
address and module) and the raw argument block M4 reads at `nt!VslpEnterIumSecureMode`. Until
that equality is demonstrated field by field, M6's values are VTL1-observed copies of the NT
arguments and the chain's first stage is unproven.

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

**M7.2 implementation result, 2026-10-25: the join is built and passes offline; a chain's first
stage stays provisional until a capture holds M4 and M6 on one VP.** `src/skjoin.rs` is the pure
join and `windbg-mcp --m7-join <input.json>` the engine-free role over it. The input is the three
drained trace reads as the workers answered them, the validated capture identity, the
transaction's clock admission, each layer's arm and drain brackets, and the two values only the
coordinator knows: the expected selected-call count and the workload process. The output is one
versioned record (`windbg-mcp.sk-correlation-join.v1`) carrying the sources verbatim, the events
normalized and ordered by their own sequence numbers, the hypervisor round trips, one chain per
VTL1 record with a decision per stage, the unmatched and ambiguous sets with their candidates as
sequence ranges, the marks that stop a complete verdict, the per-chain cross-checks of the fields
M4 and M6 both carry, and the first-stage field table; `--m7-join-table` renders a bounded table
from that record and from nothing else. `target/codex-m7/join-m7-run.py` assembles the input from
a run's `report.json` and leaves `join-input.json`, `join.json` and `join.txt` beside it.

How it decides. Within a layer the order is the sequence number and nothing else, so arrival order
cannot change a decision. Across layers a point order is used only when the admission is `point`
and both events carry a sample on the admitted frequency; an equal tick proves nothing and keeps
both candidates. A chain's M4 entry is the one selected secure-service entry (kind 2, the selected
service) after the previous VTL1 record's latest phase and before this record's entry. Its M5
stages are the round trips enclosing the VTL1 entry and the VTL1 return, the round trips paired by
a stack over the hypervisor's calls and returns, so the normal-mode calls inside a service appear
as `nested_round_trips` rather than breaking the pairing. Without a point order the coordinator's
brackets relate two recording windows and no more: disjoint windows leave a stage unmatched; one
window certainly recording throughout the other's, with both traces complete runs of equal
length, pairs by rank; anything else leaves every candidate in place. A round trip with no
recorded return bounds nothing when its trace was capped, dropped events or was still armed,
because the trace stopping says nothing about where the VP was; a trace that ran to a clean end
left the VP in VTL1, and its open round trip encloses what follows up to the layer's window. A
chain is `complete` when all six stages matched from an M4 entry and every cross-check agreed,
`provisional` when every observed stage matched but the first stage is M6's entry phase standing
in for an M4 entry the capture did not record, and `incomplete` otherwise; a `call_id` is assigned
to the first two only. Zero VTL1 records is `incomplete` with that reason, not a vacuous pass, and
a chain count that differs from the expected one is a reason, never a correction.

The first stage, field by field, as the record carries it (`first_stage.fields`). The layout rows
rest on the two K3 records of service 47 taken two days apart, M4's of 2026-10-21 and M6's of
2026-10-23: a layout correspondence across runs, not an identity on one call, which is why they
say *copied* and why the join cross-checks `service`, `transition_kind` against `dispatch_mode`,
and bytes 8..64 of the block against the request on every chain whose M4 entry is matched.

| M4 field at `nt!VslpEnterIumSecureMode` | M6 counterpart | Without M4 | Basis |
| --- | --- | --- | --- |
| `transition_kind` (CL) | `dispatch.fields.dispatch_mode`, request+0 | copied | 2 at 255 of the 256 entries of the M4 record (the one kind-1 entry was `nt!VslCallEnclave`, service 0) and 2 at request+0 in all 100 service-47 requests of the M6 record |
| `service` (DX) | `entry.service`; `service_number` at request+2 | copied | one number space |
| `call_context` (R8D) | none | unavailable | 0 in all 256 entries; no VTL1 field carries it |
| `argument_block` (0x68 bytes at R9) | `request.before`, bytes 8..64 at `rcx` | copied | the two service-47 blocks agree in layout from offset 8: an address in the harness image (`0x140000288` against `0x140000284`), a user allocation, `0x10000000`, two kernel pointers, a small count; bytes 0..8 differ by construction (zero in VTL0, the header in VTL1) and 64..104 are not captured by M6 |
| `argument_block_pointer` (R9) | `entry.raw_arguments.rcx` | replaced | a VTL1 address of the request, never equal |
| `caller`, `caller_symbol` | none | unavailable | VTL1 sees no VTL0 stack; the manifest's `caller_symbol` is an exact-build expectation, not a reading |
| `process_id` | none; `workload_process_id` from the coordinator's envelope | coordinator envelope | no VTL1 object names the VTL0 caller of a secure service |
| `thread` | none | unavailable | as above |
| `processor` | `target.vp` | copied | one runnable VP is an admission condition |
| `target_rip`, `stack_pointer` | `entry.site.coordinate` | replaced | VTL1 coordinates |

Offline: fourteen unit tests over a seeded generator of one-VP timelines (selected and ambient
secure calls, enclave calls, normal-mode calls inside a service and ambient secure calls inside
those) assert that a clean point capture joins every selected call to its six stages with the
truth's events and nesting count; that shuffling all three layers' arrival order changes no
decision; that a capture without M4 is provisional with the field table saying what the first
stage lacks; that a capped hypervisor trace leaves stages past the cut unmatched or ambiguous and
never matched to a transition still recorded; that an incomplete VTL1 record yields no call id and
leaves its neighbours' decisions unchanged; that a stray return is marked and changes no
decision; that an equal tick is ambiguous and two candidates stay two when the record between
them is gone; that interval-only clocks pair by rank only under containment with equal counts and
otherwise leave ranges, with disjoint windows unmatched; that a differing cross-check refuses the
chain; that the expected count is a reason and zero records are incomplete; that the table is a
projection of the JSON; and that input which cannot be joined is an error rather than a verdict.
Four of those rules were mutation-verified the same day by flipping the rule and watching its
test fail: an open round trip treated as bounding, an equal tick treated as before, the first
candidate taken when several survive, and the hypervisor layer left in arrival order. The
real-binary smoke test drives the role over one point-mode chain in the public wire shapes and
reads `complete` back from the JSON and from the table.

Two exercises on real records, neither evidence about a call. The three K3 qualification records
(M4 2026-10-21, M5 2026-10-22, M6 2026-10-23: three boots) assembled under a synthetic identity
and an interval-only admission parsed as 256, 1,024 and 100 events, all three traces at capacity,
and joined to 100 incomplete chains: the one selected M4 entry stays a single ambiguous candidate
because a capped trace is not a complete run, and every M5 stage holds all 512 round trips. The
M7.1 run `20261025T145507` joined to zero chains, `incomplete` for that reason, with the M4 and
M5 windows disjoint from M6's as the alternating plan makes them, and neither of its two idle M4
entries a selected-service entry.

What M7.3 needs before any chain can be `complete` live, and neither is a change to the join. One
window holding M4 and M6 on one VP (M7.1a continuation item 2's options), or a capture definition
whose first stage is M6's entry with the workload process from the coordinator's envelope, which
the join already reports as `provisional`. And a clock common to M5 and M6: in the nested lab M6's
worker runs in K3 and its samples are K3's counter, so the admission is `interval_only` and every
M5 stage is ambiguous however clean the capture. The candidate is the partition's reference
counter, read by M6's provider at each held stop and by M5's trace at each hit, with the admission
extended to say which layer pairs it orders; that is a provider and record change with its own
measurement, not a rule the join can adopt from here.

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

Status: M8.0 and M8.1 complete; M8.2's server-owned composite gate complete, with external-client
compatibility rows still in progress. M8.0's translation table is implemented in the facade: a
non-trace continue with breakpoints is M1's continue-to-breakpoints, one with none is a bounded
free run (`LiveControl::continue_running_until`, which arms nothing and stops only at a break
request, teardown or the recovery deadline), a running Ctrl+Break binds to the exact wait and
runs M2's rendezvous on the engine thread (the reader marks the wait's break request before its
scoped interrupt, so the dispatcher answers a break wake rather than a cancellation; a natural
stop that wins arrives as itself), a stopped Ctrl+Break resends the retained stop, and a
Ctrl+Break during a trace step stays a cancellation. The facade's refusal of ordinary `g` is
retired on that basis; the direct M1 and M2 gates authorize it and M8.2 qualifies it. Offline, the
controller's free run and its break request are tested against the fake dispatcher, the wake
ordering and the trace-step exclusion are unit tests, and a source ratchet pins the routing. The
live probe is the ignored `a_managed_secure_kernel_kd_session_is_driven_by_this_servers_own_kernel_attach`.
The new `open_sk_debugger` owns both workers as one supervisor composite, exposes only the ordinary
DbgEng handle, and drives breakpoint, run, trigger, stop, registers, stack, step, free run,
break-in and ordered release through the generic tools. The original `open_sk_kd` external-WinDbg
facade remains available. That probe first passed on 2026-10-26 against Secure Kernel 26100.9457 on
K3: all three execution routes completed, composite release restored the baseline, and the
post-release audit found no enabled DR slot, no TF/RF, no engine worker, unchanged guarded text and
a healthy child without forced recovery. On 2026-10-28 the strengthened probe passed 25 consecutive
free-run/break-in cycles through the same composite, followed by the same release audit. M8.1 now
also has a checked-in classic-WinDbg/WinDbgX launcher: it consumes
the facade's typed generated connection, keeps the live config off child command lines, and always
ends a post-commit session after the debugger exits or fails to start. Its fake-client contract is
an ordinary smoke test; the real front ends remain unqualified until M8.2. M8 is independent of
M6/M7's trace schema and of item 122's direct-`sk_live_*` image-resolution work: the composite
already gets modules, symbols and disassembly through its ordinary DbgEng peer.

#### M8.0 — packet-to-controller contract

Write the translation table before changing the facade:

- KD `WriteBreakpoint` reads and retains the complete instruction guard. The composite and a
  read-only standalone facade reserve one of at most four hardware slots; a standalone facade
  admitted for memory writes uses M3's guarded one-shot INT3 path. `RestoreBreakpoint` removes
  only that handle.
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

Expose the facade as an ordinary DbgEng kernel session without putting an engine in the supervisor
or sharing one across sessions. The supervisor owns a composite: one hidden worker runs the facade
and controller, and one public worker owns the DbgEng session attached to that private pipe. Only
the public handle enters the session registry. Preserve one absolute pause/run deadline across
packet handling, controller transition and wait. A rejected guard or stale epoch resends the old
stop; a failure after release must recover or contain the VM and terminate the KD connection with
the exact disposition. Both workers remain in the supervisor's internal registry, but only the
public handle is visible and routable. Teardown closes the managed DbgEng peer first and lets only the hidden
controller restore and release VTL1; generic KD `qd` cannot encode a distinct detach to this facade.

The composite half is implemented and has one live route proof. The PowerShell launcher is now
checked in at `tools/launch_sk_kd.ps1`: it resolves classic WinDbg or WinDbgX and the server from
any working directory, reads the open arguments from JSON, consumes `open_sk_kd`'s typed generated
connection, keeps configuration and policy values off child command lines, and always sends
`end_session` after the debugger exits. Its offline fake-client test covers paths containing spaces,
missing debuggers, early debugger exit and a failed open that still returned a recovery handle.
The remaining acceptance is the real-client matrix in M8.2, not more launcher mechanics.

#### M8.2 — live compatibility and safety gate

Qualify classic WinDbg and WinDbgX separately on each of three clean boots. Each client must pass:

- 100 `bp` → `g` → owned-stop cycles at the deterministic M1 site with the read-only policy's
  hardware-slot mapping, including set/list/remove;
- 100 more cycles with the write-authorized standalone facade's M3 guarded-INT3 mapping, including
  proof that the original byte is restored at every stop and release;
- 25 `g`-without-breakpoint → Ctrl+Break cycles using the M2 request;
- natural-stop-wins, Ctrl+Break-wins, already-stopped, no-hit/timeout, reset, disconnect,
  reconnect and MCP-teardown races; and
- `r`, bounded memory reads, `lm`, symbols, stack, one fall-through `t`, refused writes and a
  refused fifth breakpoint before and after the run tests.

Every arm audits exact DR0–DR3/DR6/DR7/RFLAGS restoration, unchanged Secure Kernel text, one
selected VP, same boot/`vmwp`, heartbeat and retained processes. A reset, hang, ambiguous stop or
unproved restoration fails the gate and leaves ordinary `g` disabled.

Run this in two engineering slices. M8.2a is an ignored qualification runner, completed offline
before another live attempt: it takes explicit classic-WinDbg and WinDbgX paths, separate read-only
and write-authorized startup policies, one counted guest trigger and the existing post-release
audit; emits one JSON artifact per frontend/backend arm; and records boot identity before and after
every arm. It must coordinate each `g` from transcript markers rather than sleeps, and a failed arm
must still end the MCP session and run the audit. M8.2b is the three-boot execution of that fixed
runner. On each boot it runs classic/hardware, classic/INT3, WinDbgX/hardware and WinDbgX/INT3 in
that order, then the shared free-run and race rows. A code or config edit resets the boot count.

M8.2a started on 2026-10-26 with the offline contract in `tests/support/sk_m8.rs`. The private
config is schema-versioned, denies unknown and per-boot discovery fields, fixes the breakpoint and
free-run counts at 100 and 25, requires distinct classic/WinDbgX executables and policies that
differ only by `allow_memory_writes`, and gives the counted trigger one `{count}` substitution.
The generated debugger script has an exact ready/arm/hit/complete marker grammar with no sleeps or
`q`; its parser rejects stale, duplicate and reordered markers. The per-arm artifact cannot pass
without all cycles, one healthy single-VP boot identity before and after, and a passing post-release
audit, and artifact publication is an atomic, no-overwrite rename. The ignored read-only preflight
entry validates both debugger and policy files, requires the policies to differ only by the INT3
write authority, and binds the configured VM to one healthy boot/`vmwp`/VP report. The destructive
runner now owns the four breakpoint arms in their required order: it starts a fresh policy-bound
facade for each arm, launches the selected real debugger with a generated command file through
WinDbg's `-c $<file` surface, starts the 100-call trigger only after cycle zero is visibly armed,
derives progress only from ordered log
markers, ends the MCP session before terminating the client, then runs the audit and boot probe
even after an arm failure. Its JSON artifact embeds both the debugger transcript and facade log.
Before and after the 100 cycles, the generated client script exercises registers, a bounded live
read, modules, symbol lookup, stack, disassembly and one step, sends an arbitrary virtual write
that the facade must refuse, and proves the fifth breakpoint is refused; the runner checks both
the client markers and the facade's typed-path log evidence rather than treating command echo as
success.
It then runs 25 marker-driven `g`/Ctrl+Break cycles through each frontend under the read-only
policy. Ctrl+Break is an explicit per-frontend host command with exactly one authenticated-client
PID substitution; both the helper's success and the facade's running-wait wake are required in the
free-run artifact. This orchestration is compiled and tested offline but has not yet been run
against the bench. The eight race rows now have a fixed one-to-one control/outcome contract, so a
disconnect result cannot accidentally satisfy reconnect and a resent stopped event cannot satisfy
a running break-in. That contract is now executable for both frontends: each row owns its debugger
script and session, reset is delivered by a separate authenticated-PID helper, disconnect kills the
authenticated pipe client, reconnect requires a distinct second client, and running teardown waits
for facade-side proof of `g` before MCP release. Every row publishes its transcript(s), facade log,
audit and before/after boot identity. M8.2a completed offline on 2026-10-27; the first live
execution begins M8.2b's boot count, and any resulting code or config correction resets it.

The first live attempt on 2026-10-27 did not count as an M8.2b boot. It found two harness defects
before a guest trigger: GUI WinDbg does not implement KD/CDB's `-cf` option, so the launcher now
uses WinDbg's documented `-c $<file` command surface, and the old audit input was bound to a stale
`vmwp` PID, so M8 uses a current-boot discovery audit. Cleanup left no debugger, server or worker
and the guest heartbeat remained healthy. A fresh K3 boot with both provider drivers already
running, followed by a guest-initiated full restart to exclude Fast Startup, initially exposed only
VTL0 to the root provider: partition status `0x10001` and a VTL1 CR3 status of `0x15`, including
throughout a four-second enclave secure call. This was the expected nested-root topology left by
M7, not a provider regression: K3 still had `ExposeVirtualizationExtensions=true`, which launches
its nested hypervisor and removes K3's own VTL1 from the outer provider view. With the nested L2
off, K3 was cleanly stopped, restored to `ExposeVirtualizationExtensions=false`, and started again.
Build 26100.9457 then reported VBS running while the root provider enumerated one child with
`EnabledVtlSet=3`; VTL1 CR3 `0x2601000` and RIP both read with status zero. No breakpoint arm was
started during diagnosis, so the next clean run begins M8.2b boot 1.

The four breakpoint arms then passed on one boot: classic/hardware, classic/INT3,
WinDbgX/hardware and WinDbgX/INT3 each completed 100 ordered stops and their release audit. That
boot does not count after the controller corrections which followed. The GUI free-run arm also
showed that synthesizing Ctrl+Break through window messages or a second remote DbgEng connection is
not a safe qualification control: neither path reliably reaches the authenticated KD client, and
the remote experiment reset the host. Those experiments are not repeated. The product path is the
server-owned composite, where `break_in` is a typed request bound to the exact public execution;
Classic and WinDbgX remain separate packet/launcher compatibility evidence rather than the means
by which the generic-tool session proves its running interrupt.

The first 25-cycle composite run on 2026-10-28 found a real controller race at cycle 1. A break
could bind after continue released the old stop but before the owned DbgEng wait became active;
the prior event's delayed Hyper-V completion kick was still pending, and synchronously joining its
Resume-VM after debugger-stopping `vmwp` consumed the break deadline. The corrected dispatcher
returns a pre-entry break as a bound wake without issuing `SetInterrupt`, and pumps an outstanding
completion transition in bounded `g` slices under its event-site breakpoint before asking for the
new pause. The rerun passed all 25 cycles on the same K3 boot, with stops in 14.1--14.9 seconds,
then released the composite and passed the 60-second audit: the same `vmwp` PID and SK text at all
three samples, heartbeat healthy, no recent `vmwp` errors, DR0--DR3 zero, DR7 `0x400`, and TF/RF
clear.

The next clean boot found the other side of that pump at cycle 22. DbgEng had already queued the
dispatcher-owned native-return breakpoint event before its breakpoint was removed and original
bytes restored; when that event surfaced on the later `g`, the pump treated it as an unowned stop
and failed closed. Recovery restored VTL1 and resumed the VM, but the public worker did not
acknowledge release before the smoke process exited, so the guarded recovery powered off only K3,
removed the exact orphan and restarted it. Its 60-second audit passed before work resumed. The
final pump consumes this event with one `gh` only when all ownership proofs agree: exact
native-return address, first-chance `STATUS_BREAKPOINT`, restored original bytes, no native-return
breakpoint still installed, the event-site breakpoint still owned, the ready-for-stop phase and a
pending prior transition. Every other stop remains fail-closed.

That final code passed the composite gate on three clean boots on 2026-10-28: `vmwp` PIDs 6952,
11188 and 11464, partition IDs 7, 8 and 9, and a different discovered Secure Kernel relocation on
each. All 75 free-run/break-in cycles returned the M2 stop, and every boot also passed modules,
symbols, registers, stack, disassembly, a hardware breakpoint and one fall-through step through
the generic tools. Each ordered release terminated both workers and passed its 60-second audit
with the same `vmwp` at all three samples, stable SK text, heartbeat healthy, no recent `vmwp`
errors, DR0--DR3 zero, DR7 `0x400`, and TF/RF clear. This closes the server-owned M8.2b gate.
The external clients' remaining compatibility rows stay separate; GUI input automation is not on
the product's critical path.

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
