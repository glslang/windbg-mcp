# Hypervisor detach packet trace, 2026-09-19

The candidate **does send a continue packet**. In this reproduction the hypervisor acknowledged
it, yet the guest remained unavailable until additional stops were released. Safe detach remains
unresolved; the working hypothesis is repeated break-in stops, not an omitted continue.

## Scope and instrumentation

The target was the existing four-processor 29671.1000 lab hypervisor. The server source was
`2c89032`, with candidate dbgscope `16403fae3db026df7896bdd17ea0af80323c6527` plus a temporary
logging-only hook. DbgEng was 10.0.29617.1000. No target/outer-host configuration changed and no
reset or reboot occurred during this reproduction or recovery.

The hook ran in `DebugEngine::new`, on the engine thread, before attaching. It ORed
`DEBUG_IOUTPUT_KD_PROTOCOL` (`0x80000000`, present in the installed Windows bindings) into both
the client's output mask and the control's log mask, then opened a unique per-worker log with
`OpenLogFileWide`. The old masks were obtained with `GetOutputMask` and `GetLogMask`; the setters
were `SetOutputMask` and `SetLogMask`. This changed diagnostic output, not execution control.
The hook and local dependency override were removed after measurement. They are not a shipped
environment-variable feature or a new cross-thread DbgEng call.

The instrumented build first passed `a_dump_session_opens_reads_and_closes` with the dump gate
enabled and created its log. The live run used `a_live_hypervisor_detaches_at_the_initial_break`,
with a profile loaded locally, and independently checked WinRM identity, boot time, and uptime.
An MCP JSONL transcript recorded the tool reports separately. Raw logs remain local because
debugger output can contain sensitive target data; no keys or raw logs are committed here.

## Observed sequence

During connection the candidate logged three `Send Break in ...` messages. It synchronized and
then reported the initial exception on CPU 0. All stops below were at this image's
`hv+0x404a60` (`int 3`); the resume path set the current PC to `hv+0x404a61`.

| Controller and stop | Resume observed on the wire | Subsequent observation |
|---|---|---|
| Candidate, CPU 0 | Its attach helper executed `g`; `DbgKdContinue(10001)` was acknowledged | Another state-change exception, CPU 3 |
| Candidate, CPU 3 | Typed teardown executed `qd`; `DbgKdContinue(10002)` was acknowledged | MCP test passed; WinRM timed out |
| Native KD recovery, CPU 1 | `qd`; `DbgKdContinue(10002)` was acknowledged | KD exited 0; WinRM still timed out |
| Native KD recovery without `-bonc`, CPU 2 | `qd`; `DbgKdContinue(10002)` was acknowledged | KD exited 0; WinRM answered twice and uptime advanced |

The final recovery log contains no `Send Break in ...` line. It received a state-change event
and identified CPU 2 without an explicit break-in send in the trace. This is stronger evidence
of an outstanding stop than a recovery connection that requested an initial break, but does not
by itself explain the hypervisor's handling of the earlier break packets or reconnect handshake.

After recovery, guest uptime advanced from 2363.90 to 2367.20 seconds. Boot time was unchanged
from the preflight. No debugger remained attached. Native recovery was sequential: never two
controllers on the hypervisor endpoint.

## What this changes

The candidate's log shows the same final context-write, control-space-write, and acknowledged
`DbgKdContinue(10002)` shape seen during native recovery. Missing transmission is therefore not
the explanation for this measured failure. An acknowledged continue is still not proof that
the guest remains running after the debugger closes its transport.

The attach path deserves investigation alongside teardown. In the measured dbgscope revision,
`wait_for_kernel_break_in` clears `DEBUG_ENGOPT_INITIAL_BREAK`, then calls
`absorb_initial_break_artifact`. That helper unconditionally executes `g` with a five-second
bound and discards its result. Its comment assumes exactly one extra break-in, based on NT
behavior. The packet trace shows that this does not establish a clean final stop for this
hypervisor run. The test name means the initial stop *returned by the attach helper*, not that
no resume happened inside attach.

Next, isolate the initial-break requests from the target's subsequent stops: compare attach-time
initial break with a controlled post-synchronization break, and retain event/processor evidence
through resume. Do not implement a fixed count of resumes from this four-CPU observation, skip
unknown exception events, patch PCs by an assumed RVA, or add an unbounded teardown wait. Live
NT behavior and owning-engine drop still require separate validation before changing shared code.

## Local evidence index

These filenames identify the retained bench artifacts, not portable repository inputs:

- `kd-protocol-6084.log`: instrumented candidate, including both acknowledged continues.
- `traced-detach-20260919-143832.jsonl`: MCP reports for that candidate session.
- `native-hv-recovery-20260919-143913.log`: CPU-1 recovery, followed by failed WinRM check.
- `native-hv-recovery-20260919-144042.log`: CPU-2 recovery without `-bonc`, followed by successful health checks.
