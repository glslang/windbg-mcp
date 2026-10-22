# Hypervisor VTL-transition trace

M5 records the layer between the ordinary-kernel M4 trace and the selected-VP VTL1 controller. It
uses a **separate hypervisor KD session**: its DbgEng instance lives in its own ordinary worker and
never shares a process, engine, callback slot or target with either adjacent layer.

## Exact-build gate

`hv_transition_trace` currently admits one measured K3 Intel hypervisor image:

| field | value |
|---|---:|
| image | `hvix64.exe` 10.0.26100.9444 |
| SHA-256 of the collected file | `cf5af317f300b7da25f37d5dc6ca75bff91b6b868d89f337d23ec1773340ce8a` |
| `TimeDateStamp` | `0x1525065d` |
| `SizeOfImage` | `0x415000` |
| PE checksum | `0x001f700b` |

The public PDB for that identity is not served. The tool therefore does not accept a guessed
private symbol. It verifies the live image tuple, both measured handler prefixes and both relocated
24-byte hypercall descriptors. A mismatch refuses the arm.

The admitted sites are `hv+0x2931f5` in the handler reached by hypercall descriptor `0x11`
(`HvCallVtlCall`) and `hv+0x2932a1` in the handler reached by descriptor `0x12`
(`HvCallVtlReturn`). Both are DbgEng-owned software breakpoints. The exact handler and descriptor
guards are read before either breakpoint is created, and `stop: true` removes both through their
engine handles before detach.

That choice is measured rather than assumed. On the M5 K3 target, two enabled processor execution
breakpoints were retained across a 120-second run containing three successful enclave lifecycles
and recorded zero hits. A one-shot software breakpoint at the identical call site then fired in
161 ms; removal left an empty breakpoint inventory and read back the original guarded byte `0x40`, boot identity stayed
unchanged, heartbeat and uptime advanced, and no debugger process remained. The repository's
existing hypervisor teardown drain covers breakpoint exceptions already owed by other processors
when shared patched code is restored (`DONE.md` item 93).

## What one event means

At the call site, the handler has already selected the target VTL in ESI. At the return site, it
has already selected the lower active target in ECX. The trace reports those values directly. It
does **not** calculate the target as source plus or minus one.

Each event retains:

- host-wide monotonic time and time since arm;
- breakpoint RIP/RSP, debugger processor, hypervisor VP pointer and exact-build VP index;
- source VTL, handler-selected target VTL and hypercall control value;
- the current guest-register frame pointer;
- source and target per-VTL state pointers;
- each state's inline VMCS descriptor and the VMCS physical address the measured switch path uses.

The trace envelope names VMCS field encoding `0x681e` for guest RIP and `0x6802` for guest CR3.
Those are **coordinates**, not claimed values: VMCS memory is implementation-defined and this tool
does not decode it. In particular, it never substitutes the stopped VTL0 RIP or CR3 for the saved
VTL1 frame. Every failed typed register or memory read is retained by stable field name.

## Workflow

Create a distinct profile with `role: "hypervisor"` and the same `guest` claim as the ordinary
kernel profile. On the K3 bench the private administrator wrapper creates `k3-hypervisor` on port
50021 while preserving `k3-nt` on port 50020. A BCD change requires a guest restart.

K3 is itself a Hyper-V VM, so its outer VM processor must expose virtualization extensions before
the nested hypervisor can launch. The VM must be off when
[`Set-VMProcessor -ExposeVirtualizationExtensions $true`](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/enable-nested-virtualization)
is applied. `hypervisorlaunchtype Auto` and VBS status alone were not sufficient on this bench:
before that host setting, the guest logged Hyper-V event 41 (VMX unavailable) and emitted no
hypervisor KDNET packets. Qualification therefore verifies the running nested hypervisor, not only
its BCD intent.

Then use a surface containing `securekernel` and `exec`:

```text
attach_kernel { "profile": "k3-hypervisor" }
hv_transition_trace { "session_id": "...", "label": "create-enclave-01", "max_transitions": 64 }
continue_async { "session_id": "...", "max_run_ms": 30000 }
wait_for_stop { "session_id": "...", "execution": "...", "timeout_ms": 30000 }
hv_transition_trace_read { "session_id": "...", "stop": true }
end_session { "session_id": "..." }
```

Arming never resumes the hypervisor. The event that fills the bound stops it; later hits are
counted as dropped and auto-continued. `stop: true` removes only the two breakpoints whose ids and
private marker are both still owned, then unregisters the callback.

## Live qualification

The passing K3 record is
`target/codex-m5/live-qualification/20261022T203416/report.json` (machine-local and ignored). The
labelled enclave workload started strictly within the recorded trace interval and completed all
three create/load/initialize/terminate/delete cycles. The trace reached its explicit 1,024-event
bound with 512 calls and 512 returns, both VTL0-to-VTL1 and VTL1-to-VTL0 pairs, zero drops, zero
unreadable hits and no inferred fields. After `stop: true`, all bytes in both handler guards and
both relocated descriptors matched the copied image profile. Explicit detach terminated the
worker; boot identity and `vmwp` PID stayed fixed, heartbeat remained `OK`, and no debugger process
was retained.

## Limits

- The admitted build and offsets are K3-specific. Supporting another image requires a new measured
  profile; similar bytes are not accepted as compatibility.
- The event reports the processor and VP it actually observed, but M5 does not yet prove total-VP
  coverage; `total_vp_count` stays an explicit identity gap. M7 therefore refuses a multi-VP
  correlation instead of treating this trace as complete coverage.
- These are software breakpoints in hypervisor code. A failed removal is an error and leaves the
  trace held; callers must not force-kill its worker. The live gate audits the restored bytes,
  explicit detach, same boot, heartbeat and retained processes.
- The optional label is correlation authority supplied by the caller, not something the
  hypervisor can observe in the guest workload. M7 uses it to select a capture, never as proof that
  two events are the same call.
- The first implementation reports saved-state coordinates. Reading the named VMCS fields through
  an architectural debugger API is assigned to M7's admission phase; `coordinate_only` remains a
  valid explicit result if that API is unavailable. Raw VMCS memory parsing is not a fallback.
