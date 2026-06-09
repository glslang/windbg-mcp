# Crash-dump walkthrough: a `0x9F DRIVER_POWER_STATE_FAILURE`

A hands-on tour of the crash-dump tools against a real kernel minidump,
[`docs/samples/052126-34312-01.dmp`](samples/052126-34312-01.dmp) (a 5.8 MB
kernel-generated triage dump). It mirrors the skill's
[`crash-dump.md`](../skills/windbg-debugging/crash-dump.md) playbook and shows the
real `windbg` MCP tool calls, their output, and the gotchas — ending with the
culprit driver named by a manual device-stack walk when `!analyze` couldn't.

> **Verdict up front:** Bug check **`0x9F DRIVER_POWER_STATE_FAILURE`**, subtype 3 — the
> NVIDIA display driver **`nvlddmkm.sys`** failed to complete an `IRP_MN_SET_POWER`
> request within the power-manager watchdog timeout.

## 1. Open the dump

```jsonc
open_dump { "path": "…/docs/samples/052126-34312-01.dmp" }
```

`open_dump` loads the dump, waits for it to settle, **loads `ext.dll`** (so
`!ext.analyze` resolves — see [§5](#5-why-ext-analyze-and-not-analyze)), and returns the
module list (`lm`). The module list already tells a story: third-party drivers present
include `nvlddmkm` (NVIDIA), `nvhda64v` (NVIDIA HD-audio, many unloaded instances),
`RzDev_*`/`RzCommon` (Razer), and the virtualization stack (`VBox*`, `vmx86`/`hcmon`/`vmnet*`,
plus Hyper-V `Vid`/`winhvr`). `nt` resolves to `(pdb symbols)`.

## 2. Triage with `!ext.analyze -v`

```jsonc
execute { "command": "!ext.analyze -v" }
```

The essential fields:

```text
DRIVER_POWER_STATE_FAILURE (9f)
Arg1: 0000000000000003, A device object has been blocking an IRP for too long a time
Arg2: ffffe284ffe59060, Physical Device Object of the stack
Arg3: ffffd38c2d84f580, nt!TRIAGE_9F_POWER …
Arg4: ffffe2850787bc20, The blocked IRP

*** WARNING: Unable to verify timestamp for nvlddmkm.sys

DRVPOWERSTATE_SUBCODE:  3
DRIVER_OBJECT: ffffe284fe503e10
FAULTING_THREAD:  ffffe284fe4dd040   (PROCESS_NAME: System)

MODULE_NAME: Unknown_Module
IMAGE_NAME:  Unknown_Image
FAILURE_BUCKET_ID:  0x9F_3
```

`!analyze` already hints at NVIDIA (the timestamp warning) but leaves
`MODULE_NAME: Unknown_Module` — it didn't auto-attribute the bug to a driver. The
faulting stack is the watchdog firing from a timer DPC on an idle CPU (normal for `0x9F`;
the blame is on whoever holds the IRP, not this stack):

```text
nt!KeBugCheckEx
nt!PopIrpWatchdogBugcheck
nt!PopIrpWatchdog
nt!KiProcessExpiredTimerList
nt!KiTimerExpiration
nt!KiRetireDpcList
nt!KiIdleLoop
```

## 3. Name the culprit by walking the device stack

`!analyze` left the module unknown, so resolve it from the bug-check arguments by hand.
Arg2 is the **PDO** and Arg4 is the **blocked IRP** — these address-based reads work even
on this partial minidump:

```jsonc
// PDO's owning driver — the bus driver, not the culprit
execute { "command": "dt nt!_DEVICE_OBJECT ffffe284ffe59060 DriverObject AttachedDevice" }
//   +0x008 DriverObject   : 0xffffe284fe503e10 _DRIVER_OBJECT   ("\Driver\pci")
//   +0x018 AttachedDevice : 0xffffe284fe535df0 _DEVICE_OBJECT

// The blocked power IRP and where it is stuck
execute { "command": "dt nt!_IRP ffffe2850787bc20 Type StackCount CurrentLocation" }
execute { "command": "dt nt!_IO_STACK_LOCATION poi(ffffe2850787bc20+b8) MajorFunction MinorFunction DeviceObject" }
//   MajorFunction : 0x16 (IRP_MJ_POWER)   MinorFunction : 0x2 (IRP_MN_SET_POWER)
//   DeviceObject  : 0xffffe28503b85030   <- top of the stack, holds the IRP

// Whose driver owns that device object?
execute { "command": "dt nt!_DRIVER_OBJECT poi(ffffe28503b85030+8) DriverName DriverStart" }
//   +0x018 DriverStart : 0xfffff803`32320000 Void          (matches the nvlddmkm module range)
//   +0x038 DriverName  : _UNICODE_STRING "\Driver\nvlddmkm"
```

The full device stack for the stalled PCI device:

```text
PDO  ffffe284ffe59060   \Driver\pci         (bus driver — owns the PDO)
 └ FDO ffffe284fe535df0  \Driver\ACPI        (ACPIDispatchIrp)
    └ FiDO ffffe28503b85030  \Driver\nvlddmkm  <-- blocked IRP_MN_SET_POWER sits here
```

So **`nvlddmkm` did not complete a `SET_POWER` IRP in time** → `0x9F`. This matches the
`Unable to verify timestamp for nvlddmkm.sys` note. In practice this is the GPU driver
hanging during a power transition (sleep/resume, monitor power-off, or a TDR/restart).
Remediation for the machine: update / clean-reinstall the NVIDIA driver; if it recurs,
test with sleep / fast-startup disabled.

## 4. Pitfall: partial minidumps and `0x80040205`

This is a small triage minidump, so most of pool isn't captured. Reads of non-captured
pages don't return a clean "memory read error" — the engine raises an exception that the
server surfaces as:

```text
Debug command failed: An unexpected exception was raised (0x80040205)
```

`dq`/`dps` of an uncaptured range, or a full-struct `dt` that has to follow a pointer into
a missing page, will hit this. **Query the exact field you need** (e.g.
`dt _DRIVER_OBJECT <addr> DriverName`) rather than dumping whole structures, and prefer the
addresses `!analyze` hands you (PDO, IRP, DRIVER_OBJECT) — those are in the triage data.

## 5. Why `!ext.analyze` and not `!analyze`?

The bundled WinDbg engine has no debugger extensions next to it unless you copy the
`winext\` directory (see [setup.md](../skills/windbg-debugging/setup.md) /
[README](../README.md)). Without it, `!analyze` returns **empty** with
*"No export analyze found."* With `winext\` bundled:

- `open_dump` runs `.load ext` for you, **but** the unqualified `!analyze` still won't
  resolve on this minimal engine — only the module-qualified **`!ext.analyze -v`** does.
- All `!`-extension commands (`!ext.analyze`, `!process`, …) similarly need the
  module-qualified form or an explicit `.load`.

That's why this walkthrough uses `!ext.analyze -v`.
