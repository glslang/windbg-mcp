# Tracing VTL0 Secure Kernel calls

M4 of the [call-debugging roadmap](skcall-debugging-roadmap.md) records the VTL0 side of a
secure-service transition. It uses an ordinary live x64 Windows-kernel session; it does not open a
Secure Kernel capture or share a DbgEng engine with the supervisor.

## Contract

`sk_call_trace` sets one one-byte processor execution breakpoint (`ba e1`) at exactly
`nt!VslpEnterIumSecureMode`. It does not patch an `int 3` into the VTL-transition path. Before
accepting it, the worker proves all of the following:

- the session is a live x64 kernel target;
- the symbol resolves at displacement zero inside the current `nt` image;
- that image has one reportable timestamp/size/PDB identity; and
- the 77-byte entry prefix matches the measured Windows 10.0.26100.9457 implementation through
  the instructions that consume CL, DX, R8D and R9.

The last check is the calling-convention guard. A kernel with the same private symbol but different
code is refused; adding a build requires measuring its entry before extending the guard table.

Every breakpoint callback runs on the worker's engine thread and uses typed DbgEng reads. It
retains:

- a host-boot monotonic timestamp and elapsed time since arm;
- RIP, RSP, process id, KTHREAD and processor (the process id comes from the symbol-checked
  `_ETHREAD.Cid.UniqueProcess` belonging to that KTHREAD, because a kernel target has no DbgEng
  current-process system id);
- CL as the transition kind, DX as the secure-service number, R8D as the call context and R9 as
  the argument-block pointer;
- a bounded 0x68-byte raw copy of that block; and
- the return address with its symbol and exact `nt` module/RVA coordinate where possible.

Read failures are named in `provenance.read_failures`; missing values are not replaced with zeroes.
The report also names identities this worker record cannot provide: the MCP session id, target boot
id, VM id, partition id, Hyper-V VP and VTL1 stop epoch. The caller still knows the session it
routed the operation to, but M7 must join that explicitly and must not infer any of the others from
an address or from the Windows processor number.

The trace is bounded to 1–1024 entries (64 by default). The hit that fills it stops the target.
Arming alone never resumes. DbgEng exposes one breakpoint callback slot, so a pool trace and a
Secure Kernel call trace cannot coexist in one session.

## Run it

Serve the opt-in group and attach the ordinary-kernel profile:

```text
attach_kernel { "profile": "k3-nt" }
set_symbol_path { "path": "<store containing the matching nt PDB>", "reload": "/f nt" }
sk_call_trace { "label": "create-enclave-01", "max_calls": 12 }
continue_async { "max_run_ms": 60000 }
```

The fresh attach may hold only export symbols. Force-load `nt` from a store containing the PDB
whose CodeView identity matches the running kernel before arming; the trace refuses an export-only
module because its build identity is incomplete.

While that execution is running, start the guest workload below. Then pass the execution handle to
`wait_for_stop`, read and disarm the trace, and release the KD session:

```text
wait_for_stop { "execution": "exec-…", "timeout_ms": 60000 }
sk_call_trace_read { "stop": true }
end_session {}
```

If `wait_for_stop` times out, the execution may still be running. Read the trace without `stop` to
inspect progress, or break in and then read it with `stop`. Always disarm before using another
callback trace.

## Deterministic guest workload

[`tools/skcall_guest_harness.c`](../../tools/skcall_guest_harness.c) uses supported Windows APIs
only. Each invocation creates a debug VBS enclave, loads and initializes a valid enclave image,
then terminates and deletes it. Reserving and deleting an *empty* enclave is not sufficient on this
build: live qualification measured no entry from that process until `LoadEnclaveImage` and
`InitializeEnclave` were added. The harness emits one JSON line carrying the supplied label,
actual process id, ordinal and each supported API result. It neither calls a private kernel address
nor embeds the private service ABI.

Build it on the host with Visual Studio's x64 C++ tools:

```pwsh
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\build_skcall_guest_harness.ps1 `
  -Output .\target\skcall_guest_harness.exe
```

Place a valid, debuggable VBS enclave image named `spin_enclave.dll` beside the harness (or pass an
explicit image path as the sixth optional argument). The image must satisfy the guest's ordinary
enclave signing policy. After copying both to the disposable guest:

```pwsh
C:\encl\skcall_guest_harness.exe create-enclave-01 3 5000
```

Use the same label when arming the trace. The guest record identifies each supported API
invocation; the trace identifies every private entry it caused. M4 deliberately does not claim a
one-to-one relationship between them—M7 joins layers by label, ordered host timestamps and bounded
windows. The third optional argument delays the first VBS operation, which lets a scheduled
launcher finish before the kernel trace can stop the guest. Fourth and fifth arguments can name
stdout and stderr files; the harness opens them before that delay so no remoting pipe owns its
lifetime. The sixth names the enclave image.

The 2026-10-21 exact-build live gate retained 256 complete calls before the bound stopped the
target. Of those, 199 carried the single PID emitted by the three labelled harness records; every
typed read succeeded, the owned breakpoint disarmed, and the guest remained on the same boot with
the same `vmwp` process and a healthy heartbeat.

## Safety and cleanup

This trace owns its breakpoint by both DbgEng id and an unambiguous private command marker, because
DbgEng can reuse ids. `sk_call_trace_read { "stop": true }` finds the marker, removes the breakpoint
and clears the callback. If either step fails, the operation reports the trace as still held rather
than pretending it is disarmed. `end_session` remains the final detach boundary and leaves an
attached kernel running.

An unresolved remote-kernel attach may require a forced power cycle of the disposable guest.
Configure that guest's current loader with `bcdedit /set {current} bootstatuspolicy
IgnoreShutdownFailures` before qualification. This suppresses automatic recovery only for an
unclean shutdown; genuine boot failures still enter recovery.
