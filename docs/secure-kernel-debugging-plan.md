# Validate software-only Secure Kernel debugging, then integrate the working route

## Handoff status

- Exploration date: 2026-09-12.
- The current host is ARM64. Move lab execution to an **x64 Windows host**; ARM64 support is outside this initial milestone.
- This is a saved plan, not a validated setup. No target was configured, no live debugger experiment was run, and no MCP implementation was changed during the exploration.
- The selected approach is **setup first**: prove a working lab, then make only the MCP changes required by the successful route.
- Success requires breakpoints, register and memory inspection, single-stepping, and resume inside Secure Kernel. Live memory inspection alone is insufficient.

## Findings

**Live Secure Kernel debugging is viable without a dedicated hardware probe. Extra setup is needed, but native KDNET may now make it substantially simpler.** This exploration established published capabilities; it did not exercise a live target.

Ordinary NT kernel debugging operates in VTL0. Secure Kernel runs in VTL1, whose memory protections the hypervisor enforces against VTL0. Attaching to NT therefore does not automatically provide Secure Kernel access. [Microsoft's VSM architecture](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/vsm)

| Route | Evidence and setup implications |
|---|---|
| **Native Secure Kernel KDNET** | The supplied release notes explicitly add `kdnet.exe -s` configuration support in **WinDbg 1.2606.22001.0**. This is the first route to test. The notes do not establish minimum target builds, retail-build restrictions, or VM compatibility. [Microsoft release notes](https://github.com/MicrosoftDocs/windows-driver-docs/blob/staging/windows-driver-docs-pr/debuggercmds/windbg-release-notes.md) |
| **Hyper-V + LiveCloudKd EXDI debugger** | A documented software-only route supporting Secure Kernel breakpoints and single-stepping. Requires the live debugger distribution, EXDI setup, symbols, and a compatible Hyper-V configuration. [Maintainer's instructions](https://github.com/gerhart01/LiveCloudKd/blob/master/ExdiKdSample/LiveDebugging.md) |
| **QEMU/KVM or VMware debugger** | Published research demonstrates Secure Kernel debugging through the outer virtual machine debugger. More manual work is involved in locating the image and handling address translation. [2025 research, chapter 4](https://www.cs.ru.nl/masters-theses/2025/J_Jagt___Analysis_of_Windows_Secure_Kernel_security_bugs.pdf) |
| **JTAG/SourcePoint** | An established physical-target alternative requiring compatible hardware. It is unnecessary for the VM routes above. [Vendor's setup guide](https://www.asset-intertech.com/wp-content/uploads/2024/03/SourcePoint-WinDbg-Getting-Started-Guide-for-the-UP-Xtreme-i11-v1.1.pdf) |

"Software-only" here means ordinary virtualization-capable x64 hardware, with no specialized debug probe. The debugger must run outside the Windows instance being stopped.

## Setup validation

1. **Establish one reproducible lab.** Use a Windows Server 2025 x64 Hyper-V host and a Windows 11 25H2 x64 Generation 2 guest with fixed memory, Secure Boot, virtual TPM, and VBS enabled. Record exact OS, debugger, and binary versions. Confirm VBS is actually running through `Win32_DeviceGuard`, rather than merely configured. [Microsoft's verification guidance](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity)

2. **Test native KDNET first.** Install WinDbg 1.2606.22001.0 or newer and inspect its bundled `kdnet.exe` help. Establish ordinary NT KDNET as a connectivity control, then configure Secure Kernel debugging using the utility's actual `-s` syntax and emitted connection instructions. Record required boot changes and any policy restrictions; verify VBS remains running afterward. Do not infer Secure Kernel ports or BCD switches from the older hypervisor recipe.

3. **Prove attachment in WinDbg before changing MCP.** Load matching Secure Kernel symbols and hit a breakpoint inside `securekernel.exe`. A connected debugger or a loaded PDB alone does not satisfy this milestone.

4. **Use LiveCloudKd if native attachment cannot pass.** Restore the guest baseline and use the separate **EXDI live debugger** distribution. Follow its documented configuration: fixed guest memory, one vCPU for the initial debugging experiment, Secure Kernel scanning enabled, and matching symbols. Keep nested virtualization disabled on this target guest, following the published Hyper-V recipe. Record the working host scheduler and EXDI versions. [LiveCloudKd instructions](https://github.com/gerhart01/LiveCloudKd/blob/master/ExdiKdSample/LiveDebugging.md), [independent reproduction](https://windows-internals.com/secure-kernel-research-with-livecloudkd/)

If neither route passes, finish with the captured failure conditions. QEMU/VMware remain documented alternatives; implementing another debugger backend is outside this first validation milestone.

## Minimum MCP integration

- **If native KDNET works:** first try the existing `attach_kernel` tool with a machine-local Secure Kernel connection profile. Its worker already delegates the connection to DbgEng. No new public API is planned for this route. Use the same debugger-engine version that passed the WinDbg experiment.
- **If EXDI is required:** add an optional `backend: "kernel" | "exdi"` argument to `attach_kernel`, defaulting to `"kernel"`. Preserve the existing connection/profile selectors. Carry the selection through the worker protocol and add a typed `dbgscope` EXDI attach method using `DEBUG_ATTACH_EXDI_DRIVER`. The inspected pinned implementation (`1e829ad9c0830ae980355b8fbab94b892735f38f`) uses only `DEBUG_ATTACH_KERNEL_CONNECTION` for remote kernel attachment. These are distinct DbgEng attachment modes. [AttachKernel API](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/dbgeng/nf-dbgeng-idebugclient-attachkernel)
- Preserve one worker per session and engine-thread ownership. Reuse existing execution controls where the experiment proves they work.
- Check target summaries for NT-specific assumptions. Document which operations work in Secure Kernel context; EXDI provides less OS information, so NT process, driver, and pool inspection cannot be assumed to transfer. [Microsoft's EXDI limitations](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/configuring-the-exdi-debugger-transport)

## Acceptance and deliverables

- Hit a breakpoint such as `securekernel!IumInvokeSecureService`; verify the stopped instruction belongs to the matching Secure Kernel image.
- Read registers and memory, disassemble, single-step, remove the breakpoint, and resume successfully.
- Repeat across three guest boots and ten breakpoint/resume cycles.
- Repeat the successful workflow through MCP. Verify interruption, failed-attach cleanup, and detach leave the server usable; verify normal detach resumes the guest.
- For code changes, run formatting, Clippy, unit tests, MCP protocol smoke tests, and a separate opt-in Secure Kernel test. Existing NT kernel tests do not establish VTL1 support.
- Deliver a version-pinned setup runbook, redacted validation transcript, recovery procedure, and explicit capability limits. Keep keys and machine-specific configuration outside version control.

The chosen approach is **setup first**, targeting x64 and full breakpoint/step debugging. Hardware purchases, ARM64 support, and general EXDI expansion are outside this initial milestone.
