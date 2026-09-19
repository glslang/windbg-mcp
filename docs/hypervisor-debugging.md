# Microsoft hypervisor debugging

**Experimental: safe hypervisor detach is not yet validated.** The first MCP probe left the
guest unresponsive despite reporting a successful resume/detach; native KD subsequently
recovered it without a reset. See [Validation](#validation) before attempting a live session.

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

Call `attach_kernel`:

```json
{ "profile": "lab-hypervisor" }
```

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
firewall rule for the diagnostic was removed. Guest recovery and live validation remain pending.

The reporting changes passed the default unit/protocol suite and the real-debugger NT crash-dump
summary regression before the teardown change. Neither new live test below has run: further live
checks require guest recovery and validation of the candidate teardown. Hypervisor stepping and breakpoint
management are not yet validated by this implementation run.

The detach-only regression preserves the original failure shape: it ends at the initial break
without stepping first. After recovering the lab, use its independent WinRM health wrapper:

```powershell
.\examples\hypervisor_detach_regression.ps1 -Profile lab-hypervisor `
    -ComputerName '<guest-address>' -ExpectedComputerName '<guest-computer-name>'
```

Verify beforehand that the profile names that guest's hypervisor endpoint and its debugger host
address matches this workspace. The wrapper checks guest identity, stable boot time, and advancing
uptime after each of three cycles. It stops on failure and performs no reset or automatic recovery.
It has been syntax-checked but has not yet run against the recovered lab.

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
