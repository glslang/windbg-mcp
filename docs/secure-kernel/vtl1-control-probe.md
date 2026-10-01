# VTL1 kernel controlled-stop probe

`tools/vtl1_control_probe.c` is a build-locked experiment for the control half
of `FOLLOWUPS.md` item 103. It creates and owns a disposable VID partition,
starts one VP in VTL0, enters VTL1 through a fixed interrupt targeted at VTL1,
and holds the VP when a selected VTL1 `int3` raises `#BP`.

This is a VTL1 **kernel-mode** test. The VBS enclave work already exercises
VTL1 user mode. The probe does not boot Windows and it is not Secure Kernel; it
occupies the same trust level and privilege level with a tiny long-mode image
whose entire state is controlled by the probe.

OpenVMM is not part of this path. OpenVMM is a host user-mode VMM, which does
not constrain the guest's CPL, but adopting it would add another VMM stack
without testing the inbox VID receive path this gate depends on. Calling the
guarded VID surface directly keeps the experiment to one source file and the
partition lifecycle under test.

## Scope and build guard

The program never enumerates, opens, or attaches to an existing VM. Its only
partition handle comes from `VidCreatePartition`, under a freshly generated
bare GUID name, and every normal or failed run deletes that partition. An
unexpected mapped message is never completed; the disposable partition is
deleted instead.

VID is an undocumented, build-specific interface. The executable refuses to
load unless both inbox files match the pair whose wrappers and handlers were
decoded:

| file | fixed version | size |
|---|---:|---:|
| `C:\Windows\System32\vid.dll` | `10.0.26100.5074` | 263,552 bytes |
| `C:\Windows\System32\drivers\Vid.sys` | `10.0.26100.9278` | 910,816 bytes |

The displayed product version of `vid.dll` differs from its fixed file
version. The guard reads `VS_FIXEDFILEINFO`.

## Build and offline verification

From a normal PowerShell prompt:

```powershell
.\tools\build_vtl1_control_probe.ps1
.\target\vtl1-control-probe\vtl1_control_probe.exe --self-test
```

The build discovers the installed Visual C++ toolchain and compiles as x64 C17
with `/W4 /WX /O2 /guard:cf`. The self-test makes no VID call. It checks the
private ABI sizes, bare-GUID partition name, setup and VSM bytes, memory-block
flags, page tables, GDT, TSS, IDT, initial VP contexts, selected `int3`, and
exact mapped-message filter.

`--create-only` exercises the narrowest live gate: create the owned partition,
read its hypervisor partition ID, and delete it. The VID device ACL requires an
elevated token on the measured host. From a non-elevated prompt it stops at
`VidCreatePartition` with Win32 error 5.

## Controlled-stop run

Run this from an elevated PowerShell prompt on the guarded build:

```powershell
.\target\vtl1-control-probe\vtl1_control_probe.exe `
    --controlled-stop --timeout-ms 10000 --hold-ms 250
```

`--timeout-ms` bounds the wait for the mapped exception message. `--hold-ms`
controls how long the accepted intercept remains pending and is limited to 60
seconds. The defaults are 10 seconds and 250 milliseconds.

The sequence is:

1. Allocate the `0xCAE0` setup buffer, create a one-VP owner partition, attach
   its sole client, and read its partition ID.
2. Enable partition VTL1 with a 24-byte VSM configuration. MBEC is disabled;
   VTL1's default protection allows read, write, kernel execute, and user
   execute.
3. Create a 1 MiB VSM-capable, VA-backed memory block and a GPA range with the
   apply-VTL-protections flag. That pairing is required: an ordinary range is
   mapped without the read permission needed by this long-mode image. Map the
   block, copy the image, write it through VID, verify a page by reading it
   back, and release the user mapping before execution.
4. Map the sole message slot and register vector 3 with a probe-specific
   marker.
5. Set VTL0's long-mode context, enable VP 0's VTL1 with its own
   `WHV_INITIAL_VP_CONTEXT`, and start the VP through the normal flags-zero
   path.
6. Issue the first `GET_NEXT` on a receiver thread, then assert fixed vector
   `0x20` to VTL1. Its IDT gate enters the handler at GPA `0x10000`; the handler
   writes a witness byte and executes `int3` at GPA `0x10008`.
7. Accept a stop only when the mapped record has VID type `0x01000002`, payload
   size `0x10`, the registered marker, VP 0, and vector 3, then verify the
   VTL1 handler's witness byte. VID keeps the VP stopped while that message is
   pending.
8. After the requested hold, return success with instruction advance, complete
   the owned message with flags 2, stop the VP, destroy the GPA range and
   memory block, and delete the partition. Handler registration is partition
   lifetime state; this build exposes no unregister step.

The success line names the hypervisor partition ID, VTL, VP, vector, and
selected instruction GPA. It proves the controlled stop only when the whole
run exits zero. A timeout, a different message, or any failed VID call fails
the gate.

## ABI derivation

The probe uses the Windows SDK's `WHV_INITIAL_VP_CONTEXT`; its size is asserted
as `0xE0`. The remaining signatures and layouts were checked against both
`vid.dll` wrappers and the corresponding `Vid.sys` handlers on the guarded
pair. The Ghidra helpers in `tools/ghidra_oracle` bind the matching PDB before
decompilation, decompile named functions or RVAs, and find callers of an import
or RVA.

The analysis established several details that are easy to get wrong:

- `VidMapMemoryBlockPageRange` returns the mapped address before the mapping
  token.
- `VidRegisterExceptionHandler` has four arguments and no output handle.
- `VidAssertVirtualProcessorInterrupt` receives a fixed-interrupt type and a
  separate one-byte target VTL.
- Message flags 1 get the next message, flags 2 complete the current message,
  and flags 4 cancel a wait.

The mapped VID type is deliberately not the raw hypervisor exception type.
`VidHandleExceptionIntercept` asks for `0x01000002`, writes the vector into its
16-byte payload, and reads the advance byte at mapped offset `0x148` when the
message is completed. Completing any other message would acknowledge traffic
the probe does not own, so the exact filter is part of the safety boundary.

## Validation status

The guarded end-to-end run passed on 2026-10-01 from a high-integrity token:

```text
owner partition 0x43 created
controlled stop: partition=0x43 vtl=1 vp=0 vector=3 instruction_gpa=0x10008
held pending intercept for 266 ms
completed the owned VTL1 breakpoint intercept
deleted owner partition
```

The partition ID is ephemeral. The evidence is the zero exit together with the
marked VTL1 vector-3 message, the measured hold, successful completion, and
owned-partition deletion. The native `/W4 /WX` build and offline self-test pass
on the same source.
