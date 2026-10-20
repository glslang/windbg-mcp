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
- Hardware execution breakpoints are the first mutation primitive. Software breakpoint and code
  writes remain out of scope until restoration and instruction-cache behavior have their own live
  proof.
- Every stop and transition is tied to an opaque epoch, exact instruction bytes, VM identity,
  partition, VP, VTL and CR3. Stale coordinates are refusals, not best-effort operations.
- The 2026-10-18 `g` qualification is a failed gate: after WinDbg armed
  `securekernel!KiTimerInterrupt`, the next VTL1 stop was not observed and K3 reset. The KD facade
  must continue to refuse non-trace continue requests until the direct controller passes the
  repeatability and recovery gates below.
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
- hypervisor transition: hypercall code, intercepted VP/VTL state and saved guest RIP/CR3;
- VTL1 dispatch: service number, SSCN/dispatch target, arguments, return status and selected
  memory snapshots;
- provenance: which fields were measured, symbol-derived or inferred, with read failures retained
  as fields rather than silently omitted.

Addresses never stand alone across boots. Persistent coordinates are module identity plus RVA,
resolved to a VA only after that boot's module base is proved.

## Milestones

### M0 — freeze the safety and evidence contract

Status: complete enough to begin M1.

- Preserve the worker/process/thread ownership rules above.
- Keep KD `g`, software breakpoints and arbitrary register writes refused.
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

Only after those checks may the KD facade translate WinDbg `g` into this path.

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

Add a target-side break request that can stop a naturally running VTL1 session without depending
on a preselected code address. First prove the exact build's supported request path; if none exists,
use a guarded transient hardware-breakpoint strategy with a bounded rendezvous. The request must be
job-bound, race-tested against stop arrival and teardown, and must not broaden the one documented
cross-thread DbgEng exception.

Exit: break requests in running, already-stopped, teardown and timeout races each have a unique,
tested result and restore the complete baseline.

### M3 — optional guarded writes and software breakpoints

Only if four hardware slots are insufficient, add compare-before-write, original-byte retention,
cache-coherency handling and unconditional rollback. Keep it behind an explicit capability and
policy gate. A failure to prove restoration contains the VM instead of resuming it.

### M4 — VTL0 secure-call tracer

Use the existing ordinary kernel worker to instrument the exact-build entry to
`VslpEnterIumSecureMode`, capture calling context and decode the secure-service arguments. Add a
small deterministic guest harness that issues known calls and labels each invocation.

### M5 — hypervisor transition tracer

Use a separate hypervisor KD session to capture `HvCallVtlCall` (and the measured return path), VP,
target VTL and saved-state coordinates. Do not infer VTL1 state from VTL0 registers when the
hypervisor provides the authoritative frame.

### M6 — VTL1 semantic tracer

Resolve and break on `IumInvokeSecureService` and selected dispatch targets. Decode SSCN/service
number, input/output buffers and status using exact-build symbols plus checked structure layouts.
Start with one known service before generalizing.

### M7 — cross-layer correlation and investigations

Join M4–M6 events by deterministic workload id, VP, ordering and bounded time windows. Produce
structured JSON plus a concise table/timeline. Explicitly mark ambiguous matches and dropped
events. Add repeatable investigations for service dispatch, argument mutation and return status.

### M8 — debugger front ends

After M1 and M2 pass, enable normal WinDbg `bp`/`g`/break behavior in the managed KD facade and add
PowerShell helpers that launch WinDbgX from any working directory. Evaluate EXDI last: it is useful
only if it improves compatibility without weakening process isolation or requiring unsafe host
registration/in-process loading.

## M1 implementation slices

1. **Transition surface:** promote the already unit-tested replacement-breakpoint transition into
   the live worker/MCP protocol; preserve the KD refusal.
2. **Failure harness:** extend the fake provider/dispatcher tests through replacement, no-hit
   recovery, stale guards, deadline propagation and one-shot epoch consumption.
3. **Opt-in live smoke:** extend `WINDBG_MCP_SMOKE_SK_LIVE` with guarded replacement breakpoint
   cases and always run teardown plus baseline/VM health checks.
4. **Deterministic trigger:** add the guest workload and exact symbol/RVA resolution record.
5. **Qualification:** execute the 100-cycle/three-boot matrix and record raw run directories and
   the result here before changing KD behavior.

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
