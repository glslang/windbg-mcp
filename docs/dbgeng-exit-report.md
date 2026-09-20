# Microsoft report draft: accepted EXIT interrupts do not unwind KDNET WaitForEvent

Prepared 2026-09-20. **Draft only; not submitted to Microsoft.** This report separates a minimal
unconnected reproduction from supporting synchronized-target observations. It does not claim a
documented universal restriction or a complete explanation of the separate post-ACTIVE freeze.

## Expected and observed behavior

Microsoft documents `DEBUG_INTERRUPT_EXIT` as ending an outstanding wait without requesting a
target break; `SetInterrupt` may be called from another thread and returns after registering the
request. See [SetInterrupt](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/dbgeng/nf-dbgeng-idebugcontrol-setinterrupt).
Live-kernel `WaitForEvent` requires `INFINITE`, so a finite timeout is not an alternative. See
[WaitForEvent](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/dbgeng/nf-dbgeng-idebugcontrol-waitforevent).

Observed on two AMD64 engine environments: 150 EXIT requests returned `S_OK` (`0x00000000`) while
the initial unconnected KDNET `WaitForEvent(0, INFINITE)` did not return before a 100-second external
deadline. The external process kill is **not** a successful cancellation or detach. No ACTIVE
interrupt, target VM, MCP server, dbgscope session driver, or callback is required for this repro.

## Minimal reproduction

Retained [direct-COM source](https://github.com/glslang/dbgscope/blob/b77ffe9/examples/raw_kernel_exit.rs)
and [full investigation](https://github.com/glslang/dbgscope/blob/b77ffe9/docs/kernel-exit-watchdog.md).

1. Build `cargo build --example raw_kernel_exit` at the linked dbgscope revision.
2. Confirm UDP port `50192` or `50193` is unused and no target is configured to use it. The example
   accepts only those port numbers and supplies a synthetic key internally; do not substitute a
   real profile or credential.
3. Run `raw_kernel_exit.exe 50192` (or `50193`) under an external 100-second process deadline,
   capturing both output streams. Verify the actual loaded `dbgeng.dll`, not just a DLL beside
   the executable. Separate executable directories select the two engine environments.
4. The owner thread creates `IDebugClient`, queries `IDebugControl`, attaches the synthetic kernel
   transport, then calls `WaitForEvent(0, INFINITE)`. No callbacks or engine options are installed.
5. After 60 seconds, a scoped helper calls only `SetInterrupt(DEBUG_INTERRUPT_EXIT)`, 150 times
   at 200 ms intervals. COM reference management stays on the owner thread. Each raw HRESULT and
   elapsed time is printed. The connection buffer and interfaces outlive the helper and wait.
6. Observe `RAW_REQUESTS_COMPLETE` without `RAW_WAIT_RETURN`. Reclaim only the exact synthetic
   child at the outer deadline, then independently verify that process exit and endpoint release
   occurred. Never use this forced-cleanup harness against a live target.

## Measured environments and timing

These are locally installed engine environments, not a controlled swap with every dependent DLL
held identical. Raw runs were not under CDB and were not paused for tracing.

| Loaded DbgEng | Accepted EXIT calls | Last EXIT return | Wait returned | Outer elapsed |
|---|---|---|---|---|
| `10.0.29617.1000` | 150, all `S_OK` | 90.763 s | No | 100.0952016 s |
| `10.0.26100.1` (System32) | 150, all `S_OK` | 90.734 s | No | 100.5128272 s |

SHA-256 identifiers:

- Newer DbgEng: `4352756685E7325288E54ABB3281E768637987517BE8575EC4450E4B4421842F`.
- System32 DbgEng: `BFA188B10EB64A94F1EB59BFB0F8D85EB5DFC803CD0F6B5C554816FE311A236E`.
- Identical repro executable: `1D686673505807DC4F26C1A7348DD0E13C2134DEEAC0E8BB1D0AD0FE631F0E9F`.

## Separate native tracing evidence

Earlier native tracing on `10.0.29617.1000` observed the EXIT branch setting bit 11 of an internal
flags word (`0x1` to `0x801`). Build-specific RVAs, not supported interfaces:

- `SetInterrupt`: `0x164990`; EXIT bit write: `0x1649dd`; flags: `0xa3bfe8`.
- Outer receive-path EXIT check: `0x1778e9`; synchronization-loop check: `0x177b24`.
- Unconnected transport backend: `0x5a8fb0`.
- Synchronized packet receiver: `0x5a5a90`; helper: `0x5a3d10`.

The synchronized trace's engine-thread stack remained under `WaitForEvent`, through the packet
receiver and socket `recvfrom`. Three EXIT calls returned `S_OK`; no instrumented exit-check or
wait-return marker appeared before the outer debugger paused the probe. Its observation after the
deadline was only about **0.4 seconds**. The earlier uninstrumented 143-second synchronized wait
is separate evidence and cannot be used as the duration of this traced run.

Sanitized call-site excerpt from `exit-watchdog-live-20260920-080437.log` (top to caller; raw
addresses and argument values omitted, ordinal labels retained because private symbols were
unavailable):

```text
WS2_32!WahReferenceContextByHandle
mswsock+0xa6f6
mswsock!Tcpip6_WSHSetSocketInformation+0x2e2c
WS2_32!recvfrom+0x160
dbgeng!Ordinal671+0x2a45e
dbgeng!Ordinal671+0x29dd8
dbgeng!Ordinal671+0x2bb94
dbgeng!Ordinal367+0x1f9da
dbgeng!Ordinal367+0x20345
dbgeng!Ordinal367+0xabd8b
dbgeng!Ordinal367+0xaa370
dbgeng!Ordinal367+0xb017
dbgeng!Ordinal367+0xd8e8
kernel_attach_probe!IDebugControl4::WaitForEvent+0x111
kernel_attach_probe!DebugEngine::pump+0x2d7
kernel_attach_probe!AnnouncementGuard::wait_with_timeout+0x7b
```

The final three Rust paths are shortened for readability. This stack is from the synchronized
dbgscope probe, **not** either raw-COM comparison run.

Some receive results bypass the instrumented outer EXIT check, so an absent marker does not prove
the backend never returned. The exact failing return branch has not been traced. Public-symbol
lookup for `dbgeng.pdb/0CEEC4D9B35CD3847CDB119BBFCFD90C1` returned 404 on the bench. Full native
stack excerpts and disassembly context are retained in the linked investigation and local logs.

No ACTIVE interrupt was sent in that synchronized trace. Independent guest health checks passed
before and after guarded reclamation, on the same boot. In a separate experiment, one ACTIVE
request after a stalled wait froze the target; native KD later collected a pending stop and one
acknowledged `qd` recovered it. That does not establish the complete cause or a safe retry loop.

## Evidence package and open questions

Local artifacts to sanitize and attach through an approved support channel, **not committed raw
logs**:

- `raw-kernel-exit-bundled-20260920-082923.log` and
  `raw-kernel-exit-system-20260920-082938.log`: direct-COM output and loaded-module checks.
- `run-raw-kernel-exit.ps1`: external deadlines and exact-child cleanup checks.
- `exit-watchdog-live-20260920-080437.log` and `exit-watchdog-live-health-20260920.md`:
  native return values, thread stacks, and independent synchronized-target health.
- `exit-watchdog-image_06ac_2026-09-20_07-43-29-985.log` and
  `exit-watchdog-transport_22a4_2026-09-20_07-46-06-772.log`: native disassembly context.

Before submission, add the debugger-host OS build and dependent-module inventory from these
artifacts; do not confuse the outer VM host's build with the debugger
host's build. Keep target credentials, machine-specific paths, and dumps out of public attachments.

Questions for Microsoft: should EXIT cancel both initial KDNET connection and synchronized packet
reception? Is there a supported way to unwind these waits without breaking the target or destroying
the controller? Which engine builds, if any, change this behavior?

The synchronized comparison on the older engine remains **deferred to a disposable nested lab**.
No configuration changes on the hardened outer host are required or authorized by this report.
Until native cancellation is confirmed, windbg-mcp preserves unresolved controllers and offers
only an [explicit operator recovery handoff](sessions.md#unresolved-remote-kernel-controllers).
