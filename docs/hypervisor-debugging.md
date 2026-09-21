# Microsoft hypervisor debugging

**Experimental: use only on a disposable lab target.** The first MCP probe left the
guest unresponsive despite reporting a successful resume/detach; native KD subsequently
recovered it without a reset. The candidate passed one independently checked detach cycle,
but its second cycle lost WinRM reachability despite passing MCP assertions.
The new opt-in announcement attach passed three independently checked MCP cycles on the measured
build. The default attach path remains unchanged. See [Validation](#validation) before use.

**Do not set a breakpoint inside NT's hypercall code page.** On the measured one-vCPU lab it froze
the guest so completely that the guest's own hypervisor endpoint stopped answering and a reset was
the only recovery — twice, on two different stubs. Break on the `ntoskrnl` wrappers instead; they
carry the hypercall input value in a register. The measurements, the control that isolates the
cause, and the pairing of an NT session with a hypervisor one are in
[2026-09-21](#2026-09-21-the-drain-placement-validated-live-and-an-nt-side-hazard).

Use `attach_kernel` with a profile for the **hypervisor's** KDNET endpoint. The existing
DbgEng kernel transport handles this; no EXDI backend, separate attach tool, or Secure Kernel
debug setting is required. This debugs the Microsoft hypervisor, not the NT kernel and not VTL1.

## Lab and connection

Use a disposable target with recovery access and a checkpoint. The debugger must run **outside
the hypervisor being stopped**: a break pauses its partitions, including its root Windows OS.
Do not attach to a production or hardened outer host. A sibling debugger VM can debug the
hypervisor running inside a separate lab VM when that lab supports nested virtualization.

Configure the target separately, with the owner's approval. The MCP server does not enable
Hyper-V, change boot/security settings, or reboot machines. Read the installed `kdnet.exe` help
and use its hypervisor (`h`) option. Microsoft documents separate kernel and hypervisor ports
when both are enabled; use the actual emitted endpoint rather than assuming the NT port/key
identifies the hypervisor. Hypervisor launch and debugging must both be enabled on the target.
[KDNET setup](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/setting-up-a-network-debugging-connection-automatically),
[hypervisor debugger settings](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--hypervisorsettings).

Save that endpoint as a machine-local [connection profile](kernel-profiles.md), for example
`lab-hypervisor`. Keep the key out of tool arguments, transcripts, and version control. Before
attaching, verify the configured debugger address still matches this host and that no other
debugger owns the same port. Do not operate two controllers on one endpoint.

## Through MCP

For a known-running lab hypervisor, explicitly select the experimental attach path:

```json
{ "profile": "lab-hypervisor", "experimental_break_on_connect": true }
```

This KDNET-only option requests one break upon DbgEng's English connection announcement, with no
persistent initial-break flag or extra attach resume. That text is observed behavior, **not a
documented readiness contract**. The observer is scoped to the attach; duplicate announcements
do not request another break, and a later attach gets fresh state. Missing output, failed
interrupt, interrupted wait, or unconfirmed stopped status fails the attach. A 60-second watchdog
requests exit from the wait without requesting a second target break; an unconnected transport
may still block, including after a transport synchronization announcement. On failure the claimed
session must be inspected or ended, not blindly retried.
Already-halted targets and failure recovery are not live-validated. Omitting the option retains
the ordinary attach behavior, including the failure shape documented below.

Check the returned identity before doing anything else. On the measured x64 target, the report
says `Microsoft Hypervisor Kernel Version`, and `summary.primary_module` names `hv` with image
`hvix64.exe`. The summary now includes `kernel_target: "hypervisor"` and a limitation explaining
that NT process/driver/object/pool inspection does not apply. `kernel_mode: true` alone does
**not** distinguish a hypervisor from NT. Classification uses the engine's kernel-mode flag and
primary module name; an unrecognised inventory leaves `kernel_target` absent, not guessed.

Use the returned `session_id` on subsequent calls:

```jsonc
// modules
{ "session_id": "<session>", "filter": "hv" }
// registers
{ "session_id": "<session>" }
// disassemble at the current instruction
{ "session_id": "<session>", "count": 8 }
// read_memory: substitute the address returned by registers or modules
{ "session_id": "<session>", "address": "<address>", "size": 16 }
// end_session: resume and detach explicitly when finished
{ "session_id": "<session>" }
```

The existing execution and breakpoint tools use the same session. Symbols are not a prerequisite
for address-based work. Record image identity before using `hv+RVA`: RVAs from a different build
are not interchangeable. A missing public hypervisor PDB is not evidence that the attach failed.
Do not apply NT-specific tools or extensions to hypervisor structures, or expect NT process lists,
IRPs, or pool layouts to describe this target. These limitations are guidance, not a new access
restriction on the raw command interface.

## Ending and recovery

Always call `end_session`. For a connected live target, require `released: true` and
`target_left_running: true`; a terminated worker alone is not proof of a graceful detach.

Attach timeout or unconfirmed release now preserves the worker in `kernel_unresolved`.
Ordinary teardown, lease expiry, and shutdown do not kill it. Follow the
[explicit recovery handoff](sessions.md#unresolved-remote-kernel-controllers), not another break-in
or competing attach. This applies to remote NT kernel sessions too: target subtype is not known
while the initial attach is blocked. The [Microsoft report draft](dbgeng-exit-report.md) separates
the two-build unconnected reproduction from the single-build synchronized evidence.
Then check the target console and management channel independently. A successful debugger resume
does not prove that Windows services recovered or that the target did not immediately stop again.

If attach times out, inspect `session_status` and end that session before retrying. The worker
may still be waiting for the target; a second attach is another controller, not a retry of the
first. Do not forcibly terminate a connected debugger or reset the target to clear a timeout.
Keep console access available and investigate the reported state first.

## Validation

The 2026-09-20 preservation change passed five explicitly enabled, synthetic-endpoint DbgEng
regressions: parked attach with PID-confirmed handoff, graceful/abrupt supervisor loss, lease
expiry with same-credential recovery, stateless overlapping requests, and profile-key redaction.
The supervisor-loss test first exposed a runtime shutdown hang from the retained worker's stdout;
moving that drain to an unjoined OS thread fixed it, and both shutdown modes then passed.
Unit coverage includes sticky late replies, confirmed/refused release, cross-client reservation
isolation, cancellation-safe handoff, and automatic-cleanup refusal. Removing the kill guard made
its regression fail; restoring it passed. These checks establish controller bookkeeping and
process lifetime, **not live guest health or native cancellation**. No guest, hardened-host
configuration, or installed release binary was changed for this implementation.

The older-engine synchronized comparison remains deferred to a disposable nested lab. The
[Microsoft report draft](dbgeng-exit-report.md) is prepared but not submitted.

On 2026-09-19, the existing development server at `9a664e0` attached through MCP to the
already-configured 29671.1000 x64 lab hypervisor. Module enumeration identified `hvix64.exe`;
register reads and raw disassembly succeeded without a hypervisor PDB. Explicit teardown reported
`released: true` and `target_left_running: true`. No reboot, target configuration change, or outer
host change was made. WinRM timed out afterward, and an NT-endpoint control attempt did not
connect. The owner reported a black Hyper-V console with its status still showing Running.
That VM status did not establish that the guest was executing.

After the MCP controllers exited, native KD reconnected to the hypervisor. Its `qd` command
sent a `DbgKdContinue` packet that the target acknowledged, and KD exited successfully.
WinRM then responded and independent uptime readings advanced, without a reset, reboot, or
configuration change. This is an observed recovery on this build, not a general guarantee
that `qd` supports every hypervisor target.

The native debugger and MCP worker used identical `dbgeng.dll` files (10.0.29617.1000,
SHA-256 `4352756685e7325288e54abb3281e768637987517be8575ec4450e4b4421842f`).
An engine-version mismatch therefore does not explain this result. The probe's pinned dbgscope
revision requested `SetExecutionStatus(DEBUG_STATUS_GO)` followed by
`EndSession(DEBUG_END_ACTIVE_DETACH)` and derives its running report from the first call's
success. Microsoft documents that execution requested by
[SetExecutionStatus](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/dbgeng/nf-dbgeng-idebugcontrol-setexecutionstatus)
does not occur until the next `WaitForEvent`. The teardown sequence is the leading suspect,
but the exact cause and the replacement sequence's live behavior remain unproven. Do not interpret
`target_left_running: true` as independent evidence of hypervisor execution.

The development branch now pins a candidate dbgscope change: remove breakpoints with checked
typed calls, execute the engine's fixed `qd` path, require that the engine no longer holds a target,
then perform passive cleanup. Failure before cleanup reports resume as unconfirmed rather than
deriving success from `SetExecutionStatus`. Explicit teardown and owning-engine drop share this
path. The server's message also requests an independent guest-health check.

Local tests cover the no-target guard, the postcondition, breakpoint cleanup, and quit/detach
leaving a disposable attached user-mode process alive. A later lab diagnostic stalled during
initial KDNET synchronization **before testing any candidate detach sequence**. WinRM stopped
answering; native KD's explicit-target retry crashed, and passive reconnection did not reach a
session. No reboot or target/outer-host configuration change was made. A temporary workspace-only
firewall rule for the diagnostic was removed. Guest recovery and live validation remained pending
at that point.

Further recovery on the same day narrowed the connection failure:

- The owner's firewall approval left inbound rules for native KD and the diagnostic on the
  workspace's active Public profile. This alone did not recover the guest.
- The native-KD crash dump showed an access violation in DbgEng's AES-related instruction
  sequence during initial connection. Without matching symbols, the function and root cause
  remain unidentified; this is not evidence that the candidate teardown ran.
- One explicit-target native-KD retry without `-bonc` avoided that crash and received
  `STATE_CHANGE64` packets. KD rejected their packet ID `0x1b8` because it expected `0x0`.
  Repeated transport reset requests did not resolve the mismatch.
- The documented [Ctrl+R resynchronization command](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/ctrl-r--re-synchronize-)
  completed a reset handshake, but subsequent state packets retained the rejected ID. There
  was no usable command prompt. A transport reset is not a reboot of the guest.
- KD exited cleanly through Ctrl+B while waiting; its listener was released. The guest's WinRM
  TCP port still timed out. No guest reset, reboot, or VELKO configuration change was performed.

Receiving and decoding target packets rules out a completely blocked inbound path for that
retry. It does not establish why the transport sequence became inconsistent, nor prove the
original detach failure has the same cause. Preserve this distinction when resuming the lab.
The candidate dbgscope revision also passed its manually dispatched
[Miri workflow](https://github.com/glslang/dbgscope/actions/runs/35441987860); that does not
validate live kernel transport or recovery.

The owner subsequently approved and performed a reset of the lab guest. After the owner confirmed
a responsive console, WinRM initially timed out, then became reachable without a debugger attach.
Preflight verified guest identity, the current debugger host address, hypervisor launch/debug
settings, and the endpoint key by hash. The candidate server was rebuilt from `c0032f0`, pinning
dbgscope `16403fae3db026df7896bdd17ea0af80323c6527`.

The detach-only live test then ran twice, sequentially, against the recovered guest:

- The first cycle passed the MCP assertions. Independent WinRM checks answered twice afterward,
  with unchanged boot time and advancing uptime. This was a confirmed pass for that cycle.
- The second cycle also passed the MCP assertions, but its post-detach WinRM check timed out.
  A later TCP reachability check timed out too. The wrapper stopped; the planned third cycle
  did not run. No MCP process or hypervisor-port listener remained after the failure.

The owner confirmed a black/frozen console after the second cycle. A single native-KD recovery
connection then reached the hypervisor without an explicit-target poke. Its trace initially rejected
state packet ID `0x1e6` while expecting `0x0`, but subsequently received a target `RESET` packet
and set its expected ID to `0x1e6`. Unlike the earlier failed recovery, synchronization progressed
to a usable prompt. The last event was a first-chance break-in exception at `hv+0x404a60` on CPU 0,
and the new controller's breakpoint list was empty.

Native KD's `qd` set the program counter to `hv+0x404a61`, wrote control space, and sent
`DbgKdContinue(10002)`, which the target acknowledged. KD exited successfully. WinRM subsequently
answered twice with uptime advancing from 1444.51 to 1447.88 seconds and the same boot time
as before the two candidate cycles. Recovery required no further reset, reboot, or configuration
change. The recovery controller requested an initial break; its observed stop alone therefore does
not establish precisely where the candidate originally left the target.

This does **not** validate reliable safe detach. The frozen console and failed management checks
establish an unusable guest after the second cycle, but do not distinguish a failed resume from an
immediate subsequent stop. Do not treat the passing Rust test alone as an independently confirmed
resume. A subsequent [candidate-side packet trace](hypervisor-detach-trace.md) captured an
acknowledged continue from the candidate itself, followed by additional stops on different CPUs.
Two sequential native recovery sessions were needed for that run. This narrows the investigation
to break-in/stop handling but does not establish a safe replacement sequence.

Further [post-synchronization comparisons](hypervisor-detach-trace.md#post-synchronization-break-comparison)
passed twice with native KD and three times with the same candidate's typed teardown. Each run
connected without requesting an initial break, verified synchronization and guest health, then
requested one break before detaching. Independent WinRM checks confirmed stable boot time and
advancing uptime after every run. These comparisons bypassed the server's automatic attach helper
and its unconditional artifact-absorption `g`; that production path is unchanged and still requires
a fix and validation. No reset, reboot, or VELKO configuration change was needed for the comparisons.
An [automatic diagnostic](hypervisor-detach-trace.md#callback-readiness-and-automatic-diagnostic)
subsequently passed four runs using the normal-output connection announcement to request one
break. Its reproducible source and matcher tests are retained in dbgscope's `kernel_attach_probe`
example. Those diagnostic runs preceded the explicitly opt-in server integration described above.

The first integration pinned dbgscope `2d49a887bb0fb9376dd8865b4524d59046992b6c`. One direct library
probe and then three sequential MCP detach-only cycles passed on DbgEng 10.0.29617.1000 and
the four-processor Hyper-V 29671 target. The wrapper verified guest identity, unchanged boot
time, and advancing uptime twice after each MCP cycle. No recovery attach, reboot, reset,
installed-server replacement, or VELKO configuration change was needed. Local tests cover
missing and repeated announcements, callback restoration, argument validation, and worker
option forwarding. This does not establish live deadline-failure or already-halted reconnect
behavior, owning-engine drop, live NT behavior, or cross-version safety.

The integration passed 960 server unit tests and 117 default smoke tests (18 opt-in tests
ignored), plus the enabled real-debugger NT dump summary regression. Formatting and server
Clippy checks passed. dbgscope passed 393 tests and four doctests, with 13 tests ignored;
its Clippy run retained only pre-existing warnings. Three pure announcement/failure tests
passed local Miri. These offline results do not substitute for the live checks above.

The follow-up pin `1767cf2c151d8375aa447b854919edb9f9afd2b3` adds real-engine local-process
tests for missing-announcement deadline cleanup and exit-deadline attribution, bringing the
library run to 395 passed, 13 ignored, and four passing doctests. Removing restoration before
the error return makes the new cleanup test fail. These are not hypervisor timeout-recovery
tests: the initial probe read execution status `BREAK` after an exit deadline, so status alone
must not be treated as independent liveness evidence. No lab guest was touched by this follow-up.

The later [live timeout probe](hypervisor-detach-trace.md#live-timeout-and-recovery-probe)
remained blocked beyond 60 seconds despite transport synchronization. Reclaiming the probe while
the guest was independently verified running, then attaching afresh, passed. A second attempt
using one explicit break on the same controller remained blocked and lost WinRM reachability;
the owner confirmed a black/frozen console. After reclaiming only that verified stalled probe
and checking the endpoint was free, native KD without an initial-break request collected a
pending CPU-0 breakpoint. One `qd` was acknowledged, and independent checks confirmed the same
boot with advancing uptime. This validates one manual native-KD recovery, not same-controller
or automatic timeout recovery. No reset was needed. Keep these recovery cases distinct from
the passing normal attach/detach cycles.

The subsequent [synchronized watchdog trace](hypervisor-detach-trace.md#synchronized-watchdog-follow-up-2026-09-20)
captured three native EXIT requests returning `S_OK` and setting the exit bit while the engine
thread remained in packet reception. No ACTIVE interrupt was sent, and independent guest health
passed before and after reclaiming the probe. This points to a cancellation gap in the tested
DbgEng/KDNET build, not a proven cross-version limitation or safe automatic-recovery procedure.

A later [direct-COM comparison](hypervisor-detach-trace.md#direct-com-cross-build-follow-up-2026-09-20)
reproduced the unconnected cancellation failure without dbgscope on both `10.0.29617.1000` and
`10.0.26100.1`: 150 accepted EXIT requests per run, no wait return before the 100-second outer
limit. This extends the unconnected evidence across two builds, not the synchronized live claim.

The reporting changes passed the default unit/protocol suite and the real-debugger NT crash-dump
summary regression before the teardown change. The broader live test below has not run; hypervisor
stepping and breakpoint management remain unvalidated by this implementation run. Live NT and
owning-engine-drop validation of the candidate teardown also remain outstanding.

The detach-only regression preserves the original failure shape: it ends at the initial break
without stepping first. After recovering the lab, use its independent WinRM health wrapper:

```powershell
.\examples\hypervisor_detach_regression.ps1 -Profile lab-hypervisor `
    -ComputerName '<guest-address>' -ExpectedComputerName '<guest-computer-name>' `
    -ExperimentalBreakOnConnect
```

Verify beforehand that the profile names that guest's hypervisor endpoint and its debugger host
address matches this workspace. The wrapper checks guest identity, stable boot time, and advancing
uptime after each of three cycles. It stops on failure and performs no reset or automatic recovery.
The original default-path runs used one cycle, followed by a two-cycle invocation that stopped
after its first failed health check. The later opt-in run passed all three requested cycles.

The broader regression test is also opt-in, and the same wrapper runs it with the health checks
around it:

```powershell
.\examples\hypervisor_detach_regression.ps1 -Profile lab-hypervisor `
    -ComputerName '<guest-address>' -ExpectedComputerName '<guest-computer-name>' `
    -ExperimentalBreakOnConnect -Session
```

It requires a separately configured profile and disposable target. It checks the hypervisor
summary, modules, registers, memory reads, typed disassembly, one single-step, breakpoint
creation/removal through the typed `breakpoints`/`clear_breakpoints` tools, and explicit detach.
By default the breakpoint check tests management, **not a breakpoint hit**. Cleanup runs even when
a test-body assertion fails. It does not establish Secure Kernel access, boot tracing, symbol
availability, or guest responsiveness; verify the latter out of band.

Adding `-BreakpointHit` also runs to a return address read off the stopped processor's stack and
asserts execution reached it. That is the sequence whose four-processor run left the guest frozen
(`FOLLOWUPS.md` item 93), so the wrapper refuses it unless the guest reports exactly one logical
processor, and the refusal is checked before every cycle rather than once. `docs/smoke-test.md`
has the three environment variables, for a run made without the wrapper — which is a run with no
independent postcondition, and the 2026-09-20 measurements are what says why that matters.
Do not run the NT live-kernel tier against this profile: that tier deliberately expects NT and
Windows driver/pool structures.

## 2026-09-21: the drain placement validated live, and an NT-side hazard

Two results from one session on the one-vCPU lab, against the server identifying itself as
**`0.19.0+g023a294a`** -- read from the built binary rather than assumed from the checkout, since
the two routinely differ. That is the commit which moved the break-in drain out of this server and
into dbgscope's `quit_and_detach_target`, and whose own message recorded "Live hypervisor
re-validation against this placement is still outstanding". The hypervisor target was 29671,
`hvix64.exe`, image size `6393856`, timestamp `3152137373`, checksum `2578329`, no symbols -- the
same image identity the 2026-09-20 pages record.

**The teardown is validated for that placement, on one vCPU.** An NT session and a hypervisor
session were held open simultaneously, both targets halted, and released in the documented order
-- hypervisor resumed first, NT ended, then the hypervisor. Each `end_session` answered
`released: true`, `target_left_running: true`, `recovery_required: false`. Independent WinRM then
answered twice with the boot identity unchanged and uptime advancing, 572.21 s to 575.59 s, and
both KD endpoints were free with no worker process left. That is one run, one vCPU, one engine
build; the four-processor case remains `FOLLOWUPS.md` item 93's.

**Two sessions coexist, and the freeze asymmetry is now measured in both directions.** With NT
halted at a breakpoint, a hypervisor attach connected and broke in -- so an NT stop does not stop
the hypervisor, and the hypervisor session stays usable across one. With the hypervisor halted, a
`read_memory` on the NT session for a page DbgEng had not already fetched blocked, and returned
the moment the hypervisor was resumed. The causal direction is therefore observed rather than
inferred from silence.

**The trap in that second half:** a halted hypervisor does not make the NT session look dead.
Anything the engine already holds still answers at once -- `registers` returned the full context
captured when NT stopped, and a read near the stopped instruction pointer came from an
already-fetched page. The session looks healthy until it is asked for something it does not have,
and then the call blocks for its whole budget. A fast, correct-looking answer from the NT session
is not evidence that the guest is executing.

**A software breakpoint in NT's hypercall code page freezes this guest, and a reset was the only
recovery.** The page whose address is in `nt!HvcallCodeVa` holds a short table of stubs, each
ending in `vmcall; ret` -- a generic entry taking the call code in a register, plus dedicated
stubs for individual codes. Breaking on the generic entry froze the guest; breaking on the
dedicated stubs froze it again. Both times the console went black, the break-in was never
serviced, and the guest's own hypervisor endpoint -- with hypervisor debugging confirmed enabled
for that boot -- would not connect either, so no debugger could reach the machine and the native-KD
recovery this document describes elsewhere had nothing to answer it. The `int 3` costs nothing
across the reset, since that page is dynamically mapped rather than file-backed.

Three placements separate the cause. A control run with **nothing** armed took its bounded
break-in cleanly at 15021 ms, which rules out the KD link itself; breakpoints on the NT wrappers
in `ntoskrnl` (`HvcallInitiateHypercall`, `HvcallFastExtended`, `HvcallpExtendedFastHypercall`,
`HvcallpExtendedFastHypercallWithOutput`) ran and were hit without incident. The surviving
explanation is that the debugger's own path for reporting a trap re-enters the page it trapped in,
so the stop can never be delivered; that mechanism has not been instrumented. **Break on the
wrappers, not on the page** -- they carry the hypercall input value in a register and answer the
same question. On the measured build that value was `0x8001005D` at `HvcallInitiateHypercall`,
whose low 16 bits are the call code and whose bit 16 is the fast flag.

Measured with one logical processor throughout. Whether a second processor changes the freeze --
by leaving something able to service the transport -- is untested in either direction.
