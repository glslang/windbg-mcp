# Hypervisor detach packet trace, 2026-09-19

The candidate **does send a continue packet**. In this reproduction the hypervisor acknowledged
it, yet the guest remained unavailable until additional stops were released. Safe detach remains
unresolved; the working hypothesis is repeated break-in stops, not an omitted continue.
Later controlled comparisons below passed twice with native KD and three times with the
candidate's typed teardown when a single break was requested **after synchronization**. Those
comparisons bypassed the server's automatic attach helper; they do not validate that helper.

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

The follow-up below isolates initial-break requests from subsequent stops by comparing attach-time
initial break with a controlled post-synchronization break. Do not implement a fixed count of resumes from this four-CPU observation, skip
unknown exception events, patch PCs by an assumed RVA, or add an unbounded teardown wait. Live
NT behavior and owning-engine drop still require separate validation before changing shared code.

## Post-synchronization break comparison

The same guest and boot were retained. Native KD was started without `-bonc` and without an
explicit-target poke. Its trace reached `Target synchronized successfully`, then waited for a
state-change packet. WinRM still answered at that point: synchronizing alone had not made the
guest unavailable. One Ctrl+F request was then sent through the controller's stdin. At the resulting
prompt, `.lastevent;bl;qd` recorded the event and breakpoint list before detaching. This was repeated
with a fresh controller only after independent guest-health checks passed.

Both native runs logged exactly one `Send Break in ...`. Their stop was the same first-chance
`0x80000003` at `hv+0x404a60`; each `qd` produced an acknowledged `DbgKdContinue(10002)` and
exited 0. The trace's earlier `Kd sync initial break: on` message also appeared **without**
`-bonc`; that text alone is not evidence that a break-in packet was sent.

A local Rust probe then tested the candidate teardown without the native KD frontend. It linked
the pinned dbgscope `16403fa` artifact and loaded the same DbgEng 10.0.29617.1000. Its sequence was:

1. Create the client and a borrowed `DebugEngine`, install diagnostic output, and remove
   `DEBUG_ENGOPT_INITIAL_BREAK` on the engine thread.
2. Call `AttachKernel(DEBUG_ATTACH_KERNEL_CONNECTION, ...)`, retaining the connection buffer
   through teardown, and call `engine.wait_for_event(u32::MAX)` on that thread. This intentionally
   bypasses `attach_kernel` and its artifact-absorption `g`.
3. After manually observing transport synchronization and checking WinRM, create a one-use local
   control file. A reader thread calls the existing `InterruptHandle::interrupt()` once and exits.
   Only `SetInterrupt` crosses the engine thread boundary, as permitted by its
   [documented threading contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/dbgeng/nf-dbgeng-idebugcontrol-setinterrupt).
4. Record the typed wait outcome, execution status, processor, instruction pointer, last event,
   and breakpoint list. Call the unchanged candidate `engine.end_session()` on the engine thread.
5. Check guest identity, unchanged boot time, and advancing uptime twice through WinRM before
   opening another controller.

The first probe initially received no packets because its new executable path had inbound block
rules on the workspace's Public profile. The owner approved its network-access prompt; the same
waiting probe then synchronized. No agent-created firewall rule or VELKO change was needed. This
pre-connection wait is not a detach failure.

| Controller | Stop CPU | Break-in sends | Post-detach uptime samples (seconds) |
|---|---|---|---|
| Native KD, first comparison | 0 | 1 | 2899.17 → 2902.49 |
| Native KD, second comparison | 2 | 1 | 2984.48 → 2987.78 |
| Typed teardown probe, first comparison | 0 | 1 | 3245.93 → 3249.24 |
| Typed teardown probe, second comparison | 1 | 1 | 3318.32 → 3321.61 |
| Typed teardown probe, third comparison | 3 | 1 | 3371.17 → 3374.48 |

Each typed probe returned `OnRequest` from the wait, `DEBUG_STATUS_BREAK` before teardown, an
empty breakpoint list, `Ok(KernelRunning)` from `end_session`, and `DEBUG_STATUS_NO_DEBUGGEE`
afterward. All three stopped at the same first-chance exception address as the native comparisons.
Their independent health checks passed; no reboot or recovery attachment was needed. No controller
remained on the hypervisor endpoint afterward.

This strengthens the hypothesis that attach-time break delivery contributes to the failure. It
does not prove a one-to-one relationship between sent packets and later processor stops. The
comparison also bypassed the attach helper's automatic `g`, so initial-break timing and artifact
absorption have not yet been isolated from each other. The typed probes' console callbacks were
replaced internally during teardown: their recorded teardown result is API-level evidence plus
independent health, not an additional complete packet trace of `qd`.

**The production attach path is unchanged and remains unvalidated.** A next implementation needs
an explicit break policy and a defensible connection-readiness signal; this manual experiment
does not justify a fixed sleep, a fixed number of resumes, or parsing diagnostic text as a shipped
transport contract. The probe's infinite wait is a controlled diagnostic, not a new bounded-wait
guarantee. Stepping, breakpoint hits, live NT teardown, and owning-engine drop remain separate tests.

## Callback readiness and automatic diagnostic

A follow-up instrumented session, engine-state, and debuggee-state callbacks without requesting an
initial break. `ChangeEngineState(EXECUTION_STATUS, GO)` arrived before synchronization;
`SessionStatus(ACTIVE)` arrived only after the manually requested break. Neither supplied a usable
pre-break readiness signal in this run. Microsoft's
[session callback contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/dbgeng/nf-dbgeng-idebugeventcallbacks-sessionstatus)
describes session activation, not transport synchronization. The guest remained healthy after this
probe's typed teardown (uptime 5029.86 → 5033.13 seconds).

Next, one explicit `SetInterrupt` was issued before the first wait with the initial-break option
disabled. The trace logged one send before synchronization, but no stop followed and WinRM remained
responsive. A later manual interrupt produced a second send and reached CPU 0. Typed teardown then
passed independent health checks (5115.95 → 5119.27 seconds). Moving the request before the wait
therefore did not reproduce the successful post-synchronization behavior.

Finally, an automatic diagnostic watched the normal-output `Connected to target` announcement prefix
(mask `0x1`), signaled a channel, and requested one interrupt from its reader thread. This text was
emitted before the synchronization-complete trace; the break-in send appeared afterward. The callback
made no DbgEng call. Only the existing `InterruptHandle` crossed the engine thread boundary.

| Automatic diagnostic | Stop CPU | Recorded break-in sends | Post-detach uptime samples (seconds) |
|---|---|---|---|
| Local prototype, first run | 3 | 1 | 5234.84 → 5238.15 |
| Local prototype, second run | 1 | 1 | 5356.23 → 5359.52 |
| Retained example source, tested stream matcher | 3 | 1 | 5560.96 → 5564.28 |
| Final example source, input/result checks added | 1 | 1 | 5845.34 → 5848.65 |

All four returned `OnRequest`, reached the same first-chance exception at `hv+0x404a60`, and reported
`Ok(KernelRunning)` followed by `DEBUG_STATUS_NO_DEBUGGEE`. Independent WinRM checks passed after
each run with the same boot time. No recovery attach, reset, reboot, or host configuration change
was required. No hypervisor controller was retained after the checks.

The reproducible source is `examples/kernel_attach_probe.rs` on dbgscope's `fix/safe-kernel-detach`
branch, with a runbook in `docs/kernel-attach-probe.md`. It includes manual, pre-wait, and announcement
modes and five offline tests for the bounded, line-anchored, one-shot announcement matcher. The
retained example suppresses raw DbgEng text to avoid exposing connection keys. Its live measurement
used the already-approved diagnostic executable path and pinned candidate library, not an MCP test.

That stage implemented an **automatic diagnostic**, not a production attach fix. The text is an observed
engine behavior rather than a documented readiness contract, and the wait remains unbounded if the
announcement never arrives. No server option, default attach behavior, or installed binary changed.
Production integration still needs an explicit policy and tested failure/reconnect handling; the
successful diagnostic is not grounds for silently changing NT attach or retrying breaks in a loop.

## Explicitly opt-in integration

The next implementation adds `experimental_break_on_connect: true` to `attach_kernel`; omitted
or false leaves the existing path unchanged. dbgscope `2d49a88` provides the typed
`attach_kernel_announcement_begin` method. Its scoped wide output callback requests one interrupt
on the callback thread, forwards the prior callback's mask, and restores the prior callback and
mask afterward. No engine call other than `SetInterrupt` crosses threads. The existing watchdog
uses `SetInterrupt(EXIT)` for this mode, avoiding a second target break at the deadline.

Success requires an observed announcement, successful interrupt request, a stopped wait outcome,
and typed `DEBUG_STATUS_BREAK`. Failure does not trigger an ordinary-attach fallback. Missing and
duplicate announcements, a fresh observer for the next attach, and callback restoration are
covered locally. A missing-announcement deadline and an already-halted reconnect are not yet
live-validated; an unconnected transport still has no guaranteed cancellation bound.

The direct integration probe recorded one send and stopped on CPU 2. Typed detach returned
`KernelRunning` and `NO_DEBUGGEE`; independent uptime advanced from 8886.065 to 8889.403 seconds
on the same boot. Three subsequent MCP detach-only cycles using the new option each passed,
with identity, unchanged boot time, and advancing uptime checked over WinRM after every cycle.
No reset, reboot, recovery controller, installed-server replacement, or VELKO configuration
change was required. Broader stepping, breakpoint-hit, live NT, drop, and cross-build coverage
remain separate work.

## Live timeout and recovery probe

The example's `timeout` mode replaces the scoped announcement observer with its passive trace
before waiting. This injects a missing announcement without changing the production 60-second
watchdog or sending an automatic target break.

The first run synchronized but remained in the wait at 143 seconds. No break-in send was logged,
and WinRM answered immediately before the probe process was reclaimed. Guest uptime subsequently
advanced from 11414.365 to 11417.691 seconds on the same boot, with the endpoint free. A fresh
MCP experimental attach/detach passed the independent guest-health wrapper. Thus process
reclamation followed by a new attach worked in this verified-running, never-broken case; it is
not permission to kill a debugger whose target may be stopped.

A second run tested a single explicit interrupt after the deadline, keeping the same controller.
The guest answered before that interrupt. One break-in send appeared, but no stop/wait result
followed and WinRM then timed out. The original probe was held until the owner confirmed a
black/frozen console. It never reported a stop or performed teardown.

### Manual recovery after the stalled wait

The operator verified the original probe's exact process identity and exclusive endpoint
ownership, terminated only that probe, and checked the endpoint was free before starting native
KD. This was a deliberate recovery handoff, not successful cancellation or routine cleanup.
Native KD ran without `-bonc` and without an explicit target-address poke. It synchronized and
collected a first-chance `0x80000003` on CPU 0 at `hv+0x404a60`; no break-in send appeared in its
trace. `.lastevent;bl` confirmed the exception and listed no breakpoints. One `qd` advanced the
PC by one byte and received an acknowledged `DbgKdContinue(10002)` before native KD exited 0.

Independent WinRM checks identified the same guest and boot, with uptime advancing from
12612.9890683 to 12616.3650664 seconds. The debugger endpoint was free. No reboot/reset or second
explicit break was issued. This is one successful manual native-KD recovery of a frozen target,
not validation of same-controller or automatic timeout recovery. It supports a pending-stop
interpretation but does not establish why the original wait failed to return. Do not turn the
observed single `qd` into a fixed-count recovery loop.

The 60-second exit-only watchdog cannot be treated as a cancellation guarantee even when the
transport has printed synchronization success. These diagnostic runs did not change the server
binary, target boot settings, or VELKO configuration.

## Local-only watchdog follow-up, 2026-09-20

The follow-up [dbgscope watchdog investigation](https://github.com/glslang/dbgscope/blob/fix/safe-kernel-detach/docs/kernel-exit-watchdog.md)
used the same DbgEng build but a synthetic key and unused endpoint, not the recovered guest.
Native-call tracing observed repeated `SetInterrupt(EXIT)` requests returning `S_OK`, with the
exit bit set and the engine thread still in the KDNET socket receive path. The completed extended
run recorded 150 successful requests, no wait return, and neither instrumented outer exit check
reached with the bit set before the local probe was terminated at about 91 seconds. This excludes a
missing watchdog or rejected request in those local runs, not in the earlier live run, whose
watchdog HRESULT was not captured. Local-process deadline and callback-restoration tests passed
with the same engine. Automatic recovery remains unimplemented and unvalidated.

## Local evidence index

These filenames identify the retained bench artifacts, not portable repository inputs:

- `kd-protocol-6084.log`: instrumented candidate, including both acknowledged continues.
- `traced-detach-20260919-143832.jsonl`: MCP reports for that candidate session.
- `native-hv-recovery-20260919-143913.log`: CPU-1 recovery, followed by failed WinRM check.
- `native-hv-recovery-20260919-144042.log`: CPU-2 recovery without `-bonc`, followed by successful health checks.
- `native-hv-recovery-20260919-144633.log`: first synchronized-then-break native comparison.
- `native-hv-recovery-20260919-145033.log`: second native comparison.
- `hv_synchronized_detach_probe.rs` and `run-synchronized-detach-probe.ps1`: local diagnostic source and redacting runner.
- `synchronized-detach-probe-20260919-145358.log`: first typed comparison, including the firewall delay.
- `synchronized-detach-probe-20260919-145628.log`: second typed comparison.
- `synchronized-detach-probe-20260919-145720.log`: third typed comparison.
- `synchronized-detach-probe-20260919-152410.log`: callback ordering, followed by manual break and successful teardown.
- `synchronized-detach-probe-20260919-152601.log`: ineffective pre-wait interrupt, then successful manual completion.
- `synchronized-detach-probe-20260919-152843.log`: first automatic announcement-trigger prototype.
- `synchronized-detach-probe-20260919-152958.log`: second automatic prototype.
- `synchronized-detach-probe-20260919-153400.log`: retained example source, automatic trigger and successful teardown.
- `synchronized-detach-probe-20260919-153857.log`: final example source, including secret-safe input errors and resume-result checks.
- `synchronized-detach-probe-20260919-162939.log`: first typed experimental attach integration, one send and successful detach.
- `synchronized-detach-probe-20260919-170924.log`: injected missing announcement; reclaimed still-waiting process with independently responsive guest, then fresh MCP attach/detach passed.
- `synchronized-detach-probe-20260919-171404.log`: second injected timeout; one manual break-in send, wait still blocked and WinRM unavailable at the recorded checkpoint.
- `native-hv-recovery-20260919-173050.log`: recovery after the owner confirmed the frozen console; no break-in send, CPU-0 stop, acknowledged `qd`, native KD exit 0.
- `timeout-recovery-health-20260919-1732.md`: independent same-boot uptime checks and free endpoint after that recovery.
