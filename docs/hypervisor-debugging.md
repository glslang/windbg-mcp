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

**Give both endpoints of the guest the same `guest` name, and give each a `role`.** The two
sessions here interact only through the guest underneath them, so a hypervisor profile paired with
some *other* machine's NT profile is two sessions that never interact — which reads as a bug for a
long time before it reads as a configuration mistake. A profile's value may be an object that says
so, and that is the only **explicit record** of it — not a verification. Nothing this server can
ask confirms that two endpoints are one machine, so check the pairing out of band before relying on
it: the endpoints' own boot identity over WinRM, as the detach regressions here already read, is
what settles it. What the record beats is reading the pairing off the names, which is a guess.

```jsonc
{
  "lab-nt": { "connection": "net:port=50000,key=<w.x.y.z>", "role": "nt", "guest": "lab" },
  "lab-hypervisor": { "connection": "net:port=50005,key=<w.x.y.z>", "role": "hv", "guest": "lab" }
}
```

`role` is the half this server checks: the attach derives the same fact from its primary module
(`nt` or `hv`), and a profile that claims one and reaches the other has that claim withdrawn, with
the reason reported beside it. `guest` is checked by nothing — no debugger question asks two endpoints whether they
are the same machine — so it is worth writing down precisely because it cannot be recovered later.
See [kernel profiles](kernel-profiles.md#saying-what-an-endpoint-reaches).

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
(item 93), so the wrapper refuses it on a multiprocessor guest unless `-AllowMultiprocessor` is
passed, and the check is made before every cycle rather than once. `docs/smoke-test.md`
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

## 2026-09-21: one hypercall, seen from both ends

The NT half was measured above: a wrapper breakpoint with the input value in a register. This is
the other half and the join between them -- the **same hypercall instance** observed at the NT
wrapper before its `vmcall` and inside the hypervisor after the VM exit. One vCPU, against the
server identifying itself as **`0.19.0+g023a294a`**, read from the built binary's version resource,
which on this bench was built from `023a294a` while the checkout stood at `1c749a9`. Hypervisor
target 29671, `hvix64.exe`, image size `6393856`, timestamp `3152137373`, checksum `2578329`,
`symbols: none` -- the same identity the 2026-09-20 pages record.

### Finding the dispatch in the image

From the saved image alone, with no debugger attached: `sk-29671-static/hvix64.exe`, SHA-256
re-checked as `AD601A86...886DBAB1`, and its disassembly `DD72301A...BE0657D45`, both matching the
2026-09-20 record. Addresses are image-relative, preferred base `0x140000000`.

| RVA | What it is |
|---|---|
| `hv+0x406307` / `hv+0x40630F` | the VP loop's `vmresume` / `vmlaunch` |
| `hv+0x406536` | `mov eax,4402h; vmread` -- the exit reason |
| `hv+0x406577` | `call hv+0x25F460`, reason in `edx` |
| `hv+0x25F460` | the exit handler; that call is its only caller in the image |
| `hv+0x25F9D4` | `cmp r12d,12h` -- the **VMCALL** case, calling `hv+0x21AFF0` |
| `hv+0x21AFF0` | the hypercall entry: calls `hv+0x247850` first and returns early if that answers, otherwise `hv+0x210520` |
| `hv+0x210520` | the dispatcher: guest register array from `[[r9]+0x10C0]`, input value from guest `RCX`, or `RDX:RAX` for the 32-bit form |
| `hv+0x21056D` | the instruction after `mov rbx,[rcx+8]`: **`rbx` is the input value, `rcx` the guest register array** |
| `hv+0x210663` | `jmp rcx` into a switch over call codes `0x02`--`0x5D`, through a byte table at `hv+0x14452` and target RVAs at `hv+0x14446` |

That switch has three targets rather than one per code: `hv+0x2107E5` for codes `0x02`, `0x03`,
`0x13` and `0x14`; `hv+0x210669` for `0x5C` and `0x5D`, which additionally requires **bit 31** of
the input value (`test ebx,ebx; jns`) and otherwise falls through; and `hv+0x210A26` for the rest.

**There is a second VP entry/exit pair in this image, and it is not the one in play.** `hv+0x405860`
with its handler `hv+0x375F3C`, whose VMCALL case calls `hv+0x402D9C` -- a dispatcher that rejects
fast hypercalls and ones with bit 31 set, and whose caller routes that refusal into what reads as a
bugcheck path -- read off the code shape, not observed. It is named here because it reads exactly
like the hypercall path and is not it; nothing measured below went through it.

### The landmarks, checked against the live target

At base `0xfffff877c8a00000`, three reads matched the saved image byte for byte before anything was
armed:

| Site | Bytes read from the target |
|---|---|
| `hv+0x210520` | `48895c241055565741544155415641574883ec60` |
| `hv+0x21AFF0` | `40534883ec40488b8140010000` |
| `hv+0x25F9D4` | `4183fc12750d498bcee80eb6fbff` |

The attach itself broke in at `hv+0x404a60`, the documented `int 3`, reproducing 2026-09-20 on a
fresh boot. At the first dispatcher stop `r12` held `0x12`, the exit reason still in the register
the exit handler put it in -- which is how the live path was confirmed to be the one read above.

### The guest register array

The array the entry stub fills on a VM exit, confirmed by what it contained rather than by its
shape:

| Offset | Register | Offset | Register |
|---|---|---|---|
| `+0x00` | `rax` | `+0x40` | `r8` |
| `+0x08` | `rcx` | `+0x48` | `r9` |
| `+0x10` | `rdx` | `+0x50` | `r10` |
| `+0x18` | `rbx` | `+0x58` | `r11` |
| `+0x28` | `rbp` | `+0x60` | `r12` |
| `+0x30` | `rsi` | `+0x68` | `r13` |
| `+0x38` | `rdi` | `+0x70` | `r14` |
| | | `+0x78` | `r15` |

The stub writes that array at `hv+0x406451` and **never writes `+0x20`** -- which is why that slot,
which read as zero throughout, is not the guest stack pointer. That lives in the VMCS rather than in
this array, and `+0x08` is written separately from the `rcx` the stub stashed before the exit.

### The crossing

NT was stopped at `nt!HvcallInitiateHypercall` by a conditional breakpoint, released, and the
hypervisor stopped **714 ms** into the run that followed, at `hv+0x21056D`, on a matching input
value. Every one of the
fifteen registers the array carries then agrees with the NT-side capture -- either carried
through untouched, or transformed exactly as that wrapper's prologue transforms it:

| Register | NT, at the wrapper | Hypervisor, at the exit | Why |
|---|---|---|---|
| `rax` | `0` | `fffff80404460000` | `mov rax,[nt!HvcallCodeVa]` -- the page NT called through |
| `rcx` | `0000000000010068` | `0000000000010068` | the input value, passed through |
| `rdx` | `0` | `0` | the parameter |
| `rbx` | `0` | `0000000000010068` | `mov rbx,rcx` |
| `rbp` | `fffffed1d7aa3910` | `fffff93150df76d9` | `lea rbp,[rsp-27h]` after 7 pushes: `rsp` was `fffff93150df7738` |
| `rsi` | `fffff804ee6092d0` | `fffff804ee609200` | `xor sil,sil` |
| `rdi` | `fffffed1d3477d30` | `fffffed1d3477d30` | never touched before the call |
| `r8` | `0` | `0` | passed through |
| `r9` | `0` | `0` | never touched |
| `r10` | `fffff80477af3490` | `fffff80477af3490` | never touched -- and it is the wrapper's own address |
| `r11` | `0000000040000010` | `0000000040000010` | never touched |
| `r12` | `0` | `0` | `xor r12d,r12d` |
| `r13` | `fffffed1d15912c0` | `fffffed1d15912c0` | never touched |
| `r14` | `0` | `0` | `mov r14,rdx` |
| `r15` | `fffff804ee614420` | `0` | `mov r15,r8` |

`rbp` and `rsi` are the two that lift this above a value match: `rbp` is NT's own stack pointer
minus seven pushes minus `0x27`, to the byte, and `rsi` is NT's `rsi` with exactly its low byte
cleared. **Neither is unique**, and it is worth being exact about why not: the same thread calling
the same wrapper again at the same stack depth would reproduce both, along with `rdi` and `r13`.
What rules that out here is the ordering rather than the values -- NT was parked at that call,
released, and this was the first hypercall matching it, 714 ms into the run that followed.

For context on how distinctive that is: sampled with NT parked, four consecutive dispatcher hits
carried input values `0x12`, `0x6A`, `0x6A`, `0x6A`, and four more while NT's resume was pending
carried `0x6A`, `0x100010050`, `0x30015` and `0x12`. The crossing's `0x10068` appeared in none of them.

### What did not cross, and what that does not prove

**`0x8001005D` was never seen hypervisor-side.** That value -- call code `0x5D`, fast bit, bit 31 --
is what NT's generic wrapper held on both occasions it was caught there with an unconditional
breakpoint. A register-only conditional at `hv+0x21056D` hunting it ran 60 s with the guest
running free and never fired, while the *other* value from the same wrapper reached that same
instruction 714 ms after NT was released.

**Three earlier runs hunted the same value and none of them is evidence**, for two different
reasons -- worth separating, because "no hit" means nothing until the condition is known to have
been evaluated on every hypercall in the window:

| Run | Site | Condition | Why it does not count |
|---|---|---|---|
| 120 s | `hv+0x210520` | fixed VP address, dereferences memory | reached its bound with no hit, but only the session's running/stopped state was read and its stop record never was, so whether the condition faulted part-way through is unverified |
| 90 s | `hv+0x21AFF0` | fixed VP address, dereferences memory | printed `Memory access error` and stopped -- coverage from that point on is nil |
| 120 s | `hv+0x21AFF0` | exiting VP from `@rcx`, still dereferences | same, which is what showed the fault was not the fixed address |

The 60 s run is the one that counts because its condition reads a register and nothing else, so it
cannot fault, and the guest was running free throughout.

That measures an absence at the dispatcher, and no more. It does **not** separate "this hypervisor
never receives it" from "`hv+0x247850` answers it before `hv+0x210520` is reached", and nothing here
was instrumented to tell those apart. Bit 31 is documented in the TLFS as the flag directing a
hypercall at the parent hypervisor, and this guest runs its own `hvix64` nested under the bench's
host hypervisor, so a call aimed past it is a plausible reading -- and taking it as the explanation
needs the specification and a measurement on the host, neither of which is here. What *is* measured
is that this build's own `0x5C`/`0x5D` branch requires that bit set, so it does expect such values.

### Four things that cost a run each

- **A conditional breakpoint whose expression faults stops the target.** `j (poi(poi(<vp>+0x10c0)+8)
  == <value>) ''; 'gc'` printed `Memory access error at ...` and stopped -- and a stopped hypervisor
  freezes the guest, so the run ends there having learned nothing. Two runs, 90 s and 120 s -- the
  last two rows of the table above -- died
  this way; using the exiting VP from `@rcx` rather than a fixed address did not save it. A
  condition reading **only registers** cannot fault, which is the whole reason to prefer
  `hv+0x21056D`, where the input value is already in `rbx`.
- **An unconditional hypervisor breakpoint on a hypercall site deadlocks the NT session.** Every
  hypercall stops the world, so the guest executes for microseconds per resume and NT never
  accumulates enough time to take its KD resume packet off the NIC: NT stays parked however many
  times the hypervisor is continued. Twelve stop/resume cycles did not deliver one resume. The
  conditional form, which auto-continues on everything else, had NT running again within a second.
  `... Retry sending the same data packet for 4160 times.` in the NT session's output is what the
  deadlock looks like from the other end.
- **NT's breakpoints can only be edited while the hypervisor runs.** `bp` and `bc` write to NT
  memory over a transport NT services only when it is executing, so with the hypervisor halted they
  block like any other uncached read. The order is: resume the hypervisor, edit NT's breakpoints,
  then park NT again.
- **A bounded hypervisor run that expired left a break-in owing, twice.** The next resume stopped
  immediately at `hv+0x404a60` with the CTRL+BREAK banner and nothing armed -- the pending break-in
  being spent. Harmless, and the same leftover the teardown drain exists for, but it costs a cycle
  and reads like a breakpoint hit. **Stated as a rule it is too strong**: the four-processor
  section below did not reproduce it, and a drain that reads a deadline-terminated run as a free
  one is sound on the evidence there.

### Teardown and guest health

**The two clears interleave with the resume and cannot be done in one pass.** The hypervisor's
breakpoint comes off while it is halted at the crossing; the hypervisor is resumed; and only then
can NT's come off -- NT is stopped at that point, but a breakpoint write to it still travels over a
transport NT services only while the guest executes, which is the trap above. Saying "both sides
cleared, then the hypervisor resumed" describes a sequence that blocks. Then the documented order:
NT `end_session`, hypervisor `end_session`. Each answered `released: true`,
`target_left_running: true`,
`recovery_required: false`. Independent WinRM twice afterwards: boot identity unchanged across the
whole session -- during which the guest was frozen for minutes at a stretch -- and uptime advancing
5479.30 s to 5483.69 s. Both KD ports free, no worker process left.

**A dispatcher breakpoint is hypervisor-side code every processor runs, and on one processor it was
uneventful**: no freeze, no stray stops, guest healthy afterwards. That is one vCPU. It says nothing
about four, which is `FOLLOWUPS.md` item 93.

## 2026-09-21: four processors, and the stop each of the others owes

The lab guest was restarted with **four** virtual processors, which is the configuration
`FOLLOWUPS.md` item 93 was filed on and had not been re-run against since the drain landed. Same
guest and same images as the sections above -- NT 29671, hypervisor 29671, `hvix64.exe`, image size
`6393856`, timestamp `3152137373`, checksum `2578329` -- and the same server, `0.19.0+g023a294a`,
read off the binary that answered. The hypervisor's own attach report names the topology:
`Microsoft Hypervisor Kernel Version 29671 MP (4 procs) Free x64`.

### The mechanism, measured directly

An `experimental_break_on_connect` attach landed at `hv+0x404a60` as always, and two bounded
1500 ms resumes both ran to their deadline -- so **that attach shape owes no break-in**, which is
consistent with it removing `INITIAL_BREAK` rather than arming it. The stops came back on
processors 3 and 0, at `hv+0x404a60`, with the CTRL+BREAK banner.

`[rsp]` at the stop held `hv+0x312024`, the same return site the 2026-09-20 demonstration used.
`run_to_address` to it returned `verdict: hit`, `stopped_at` equal to the address asked for, and
the breakpoint inventory afterwards was **empty**. The next three resumes then stopped
**immediately**:

| Resume | Ran for | Processor | Stop | Stack pointer |
|---|---|---|---|---|
| 1 | 2 ms | 2 | first-chance `0x80000003` at `hv+0x312024` | -- |
| 2 | 3 ms | 3 | first-chance `0x80000003` at `hv+0x312024` | -- |
| 3 | 1 ms | 1 | first-chance `0x80000003` at `hv+0x312024` | `0xffffe70000205be0` |
| 4 | 1534 ms | 3 | deadline; CTRL+BREAK banner at `hv+0x404a60` | -- |

Three stops, one per processor other than the one the hit was reported on, all at the breakpoint's
own address, none carrying the CTRL+BREAK banner, and then the target ran free. The four stack
pointers seen across the session sit 2 MiB apart -- `0xffffe70000005ad8`, `0xffffe70000205be0`,
`0xffffe70000405830`, `0xffffe70000605828` -- so each is a different processor's stack rather than
one processor stopping repeatedly. The reading is that the other processors reached the patched
instruction before `run_to_address` removed it, and their break exceptions are delivered one per
resume, **after** the tool that armed the breakpoint has reported success and taken it off. One
processor has nobody to owe, which is why every one-vCPU run of this sequence was clean.

Draining those three by hand and then ending the session left the guest healthy: same boot, uptime
advancing 536.99 s to 539.35 s. Re-attaching afterwards found nothing owing.

### What it does to a detach, and that it is a race

`qd` sends one `DbgKdContinue`. A queued stop takes it and the target stops again with **no
debugger attached**: the guest goes black while `end_session` answers `released: true`,
`target_left_running: true`, `recovery_required: false`. Whether that happens depends on the timing
of the delivery against the quit, so it is intermittent. **2 of 4** four-processor hit-then-detach
runs froze the guest on this build -- one by hand, one through the tier, and two more through the
tier with the drain deliberately backed out.

Both freezes had the same signature and both were recovered **in this server**, with no reset and
no native KD:

```jsonc
{ "profile": "<hv-profile>" }   // attach_kernel, plain -- no experimental_break_on_connect
{ "session_id": "<hv>" }        // end_session
```

The plain attach found the target stopped at `hv+0x312024` -- the breakpoint's own address --
with `.lastevent` reporting a first-chance `0x80000003`, on a stack region belonging to another
processor (`0xffffe70000405830` the first time, `0xffffe70000605830` the second). `end_session`
then released it: WinRM answered on the **same boot** each time, with uptime advancing (962.23 s
onwards, then 1671.1 s onwards) -- the boot the guest had come up on before any of this work
started.

### The fix, and the before-and-after

The drain existed and did not run. `spend_pending_break_ins` was gated on
`ClientState::kd_initial_break_attach`, which the announcement attach clears -- so the one attach
shape a *running* hypervisor has to be opened with was the one shape the drain skipped. And its cap
of five attempts was three stops plus two free runs: four processors exactly, by coincidence.
[dbgscope#175](https://github.com/glslang/dbgscope/pull/175) drops the gate, sizes the attempts
from `GetNumberProcessors`, and bounds the wall clock with a four-second `DRAIN_BUDGET` where the
attempt count no longer does.

Measured through `examples/hypervisor_detach_regression.ps1` on the four-processor guest, each
cycle carrying its own WinRM boot-identity and advancing-uptime check:

| Drain | Answering binary | Cycles | Guest healthy afterwards |
|---|---|---|---|
| Backed out | local `[patch]`, identity not read | 4 | 2 |
| Present, sized per processor | local `[patch]`, identity not read | 10 | 10 |
| Present, sized per processor | **`0.19.0+g1ac1abc0`**, pinned `192e3486` | 5 | 5 |
| Present, sized per processor | pinned `192e3486`, identity not read | 5 | 5 |

The ten `[patch]` cycles were two batches of five with the backed-out runs interleaved between
them, on the same guest and the same boot, so the difference is the drain rather than the guest
settling. The third row is the one to quote: it was taken after dbgscope#175 merged and
`Cargo.toml`'s `rev` moved to it, from a clean tree, and the version is the server's own
`serverInfo` read out of the binary that answered rather than the checkout beside it. The fourth
row is the same sequence run before that commit, on a tree dirty with the pin change -- the result
is real and the identity was not captured, which is exactly the gap the row above closes and the
reason it is not folded into it. All twenty-four cycles ran against the one boot the guest came up
on that afternoon.

### What this does not say

One lab, one guest, one engine build, four processors. Nothing here was measured above four, so the
one-resume-per-processor rule is what sizes the drain beyond it rather than a second measurement.
The mechanism was read off delivery order and stack pointers; nothing instrumented the KD stub to
show where the queued exceptions are held. And `threads` is not available on a hypervisor session
to confirm the processor identities independently -- it fails `0x80040205` -- so the processor
numbers here are the stop reports' own.

## 2026-09-22: both sessions at once, on four processors

The two-session work -- the asymmetry, the hypercall crossing and the ordered teardown -- had only
ever been done on the one-vCPU configuration. Re-run here on the **four**-processor guest, against
the registered stdio server `0.19.0+gb22a2583` (dbgscope `192e3486`, the sized drain), on the same
boot the guest had been up on for ten hours.

### Two sessions, independently routed

`attach_kernel { "profile": "<nt>" }` answered `kernel_target: "windows"`,
`Windows 10 Kernel Version 29671 MP (4 procs)`, `nt` with `symbols: "pdb"`.
`attach_kernel { "profile": "<hv>", "experimental_break_on_connect": true }` answered
`kernel_target: "hypervisor"`, `MP (4 procs)`, `symbols: "none"`. One `session_status` then listed
both as `state: open`, `live: true`, on **separate engine pids** (10340 and 6316) -- one worker
process each, as the design says, with no interaction inside the server.

Both profiles on this host are bare connection strings, so those two identities are the *engine's*
answer about each target rather than a `role` read back from configuration -- worth saying now that
a profile can declare one (item 95, `docs/kernel-profiles.md`), because a reader meeting both
features at once cannot otherwise tell which of them produced the words above.

**The hypervisor attach was made while NT was halted at a breakpoint**, and it connected and broke
in. So an NT break does not stop the hypervisor on four processors either.

### The crossing, and it keeps its processor

NT was parked at `nt!HvcallInitiateHypercall` holding input value `0x00010068` -- call code `0x68`,
fast bit -- on **processor 1**. Lodging NT's resume, then resuming the hypervisor, then waiting on
the hypervisor stopped it at `hv+0x21056D` after **1131 ms** (the one-vCPU run: 714 ms) with
`rbx = 0x10068`, on **processor 1 as well**. That correspondence is new: with one processor there
was nothing to correspond.

The guest register array at `rcx = 0xffffe70000207080` carries every relationship the one-vCPU run
measured, unchanged:

| Offset | Value | Against NT's capture |
|---|---|---|
| `+0x08`, `+0x18` | `0x0000000000010068` | the input value, twice |
| `+0x28` | `0xffff93d2cc53f6d9` | NT's `rsp` `0xffff93d2cc53f738` less seven pushes (`0x38`) less `0x27` |
| `+0x30` | `0xfffff805b3759200` | NT's `rsi` `0xfffff805b37592d0` with exactly its low byte cleared |
| `+0x38` | `0xffffdc39399ead30` | NT's `rdi`, untouched |
| `+0x50` | `0xfffff805c44f3490` | NT's `r10`, untouched -- the wrapper's own address |
| `+0x58` | `0x0000000040000010` | NT's `r11`, untouched |
| `+0x68` | `0xffffdc3936613a60` | NT's `r13`, untouched |

It does not carry `rsp`, as before.

### Two things this run adds

**Excluding the non-crossing value needs a mask, not a literal.** The 2026-09-21 run met
`0x8001005D` twice and skipped it by equality. The first capture today was `0x8000005C` -- a
different code, the same bit 31 -- so a `@rcx != 0x8001005d` condition would have parked on it.
`j ((@rcx & 0x80000000) == 0) ''; 'gc'` reached a crossing value in 8.5 s.

**NT's KD transport reports itself lost while the hypervisor holds the world, and recovers.** With
the hypervisor halted across the crossing, the NT session's output carried
`... Retry sending the same data packet for 64 times.` followed by *"The transport connection
between host kernel debugger and target Windows seems lost. please try resync with target, recycle
the host debugger, or reboot the target Windows."* None of those remedies is right here: the
session resynchronised by itself once the hypervisor ran, answered `vertarget` with a fresh debug
session time and advancing uptime, and detached cleanly. The lodged resume reported
`running_for_ms: 38974` for a run that was frozen for most of it.

### Teardown

The documented order, both targets held: resume the hypervisor, `end_session` NT, `end_session` the
hypervisor. Each answered `released: true`, `target_left_running: true`, `recovery_required: false`.
Independent WinRM twice afterwards: boot identity unchanged and uptime advancing, 38858.8 s to
38861.1 s. Both KD endpoints free, no worker process left, and the server's session list empty.

**A bounded hypervisor run that expires freezes the guest until the next resume**, which is the one
thing to watch in this sequence: the 20-second bound used between the crossing and the teardown ran
out, and NT then had no machine to execute on until the hypervisor was resumed again. `end_session`
on NT before that would have been asking a frozen kernel to detach.
