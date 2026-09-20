# Microsoft hypervisor debugging

**Experimental: use only on a disposable lab target.** The first MCP probe left the
guest unresponsive despite reporting a successful resume/detach; native KD subsequently
recovered it without a reset. The candidate passed one independently checked detach cycle,
but its second cycle lost WinRM reachability despite passing MCP assertions.
The new opt-in announcement attach passed three independently checked MCP cycles on the measured
build. The default attach path remains unchanged. See [Validation](#validation) before use.

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
Then check the target console and management channel independently. A successful debugger resume
does not prove that Windows services recovered or that the target did not immediately stop again.

If attach times out, inspect `session_status` and end that session before retrying. The worker
may still be waiting for the target; a second attach is another controller, not a retry of the
first. Do not forcibly terminate a connected debugger or reset the target to clear a timeout.
Keep console access available and investigate the reported state first.

## Validation

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

The broader regression test is also opt-in and ignored by normal `cargo test`:

```powershell
$env:WINDBG_MCP_SMOKE_HYPERVISOR_PROFILE = 'lab-hypervisor'
cargo test --test mcp_smoke -- --ignored --nocapture --test-threads=1 a_live_hypervisor_session
```

It requires a separately configured profile and disposable target. It checks the hypervisor
summary, modules, registers, memory reads, typed disassembly, one single-step, breakpoint
creation/removal, and explicit detach. The breakpoint check tests management, **not a breakpoint
hit**. Cleanup runs even when a test-body assertion fails. It does not establish Secure Kernel
access, boot tracing, symbol availability, or guest responsiveness; verify the latter out of band.
Do not run the NT live-kernel tier against this profile: that tier deliberately expects NT and
Windows driver/pool structures.
