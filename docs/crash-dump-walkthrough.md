# Crash-dump walkthrough: a `0x9F DRIVER_POWER_STATE_FAILURE`

A hands-on tour of the crash-dump tools against a real kernel minidump,
[`docs/samples/052126-34312-01.dmp`](samples/052126-34312-01.dmp) (a 5.8 MB
kernel-generated triage dump). It mirrors the skill's
[`crash-dump.md`](../skills/windbg-debugging/crash-dump.md) playbook and shows the
real `windbg` MCP tool calls, their output, and the gotchas — from `crash_triage`'s
one-call summary through to the culprit driver named by a manual device-stack walk
when `!analyze` couldn't.

> **Verdict up front:** Bug check **`0x9F DRIVER_POWER_STATE_FAILURE`**, subtype 3 — the
> NVIDIA display driver **`nvlddmkm.sys`** failed to complete an `IRP_MN_SET_POWER`
> request within the power-manager watchdog timeout.

## 1. Open the dump

```jsonc
open_dump { "path": "…/docs/samples/052126-34312-01.dmp" }
```

`open_dump` loads the dump, waits for it to settle, **loads `ext.dll`** so
`!ext.analyze` resolves (see [§6](#6-why-extanalyze-and-not-analyze)), and returns the
module list (`lm`). The module list already tells a story: third-party drivers present
include `nvlddmkm` (NVIDIA), `nvhda64v` (NVIDIA HD-audio, many unloaded instances),
`RzDev_*`/`RzCommon` (Razer), and the virtualization stack (`VBox*`, `vmx86`/`hcmon`/`vmnet*`,
plus Hyper-V `Vid`/`winhvr`). `nt` resolves to `(pdb symbols)`.

## 2. Triage in one call

```jsonc
crash_triage {}
```

One call, and the fields §3 reads ~150 lines of `!ext.analyze -v` output to find:

```text
BUG CHECK: 0x9f DRIVER_POWER_STATE_FAILURE
  Arg1: 0x0000000000000003  A device object has been blocking an IRP for too long a time
  Arg2: 0xffffe284ffe59060  Physical Device Object of the stack
  Arg3: 0xffffd38c2d84f580  nt!TRIAGE_9F_POWER on Win7 and higher, otherwise the Functional Device Object of the stack
  Arg4: 0xffffe2850787bc20  The blocked IRP
PROCESS: System
FAULTING FRAME: none — every one of the 7 captured frames is in the kernel image or the HAL, so no
driver frame can be named: the bug check is either in the kernel's own path or the stack did not
reach the culprit. The innermost frame is nt!KeBugCheckEx.
FAILURE BUCKET: 0x9F_3
!analyze blamed: Unknown_Module

STACK (7 frames):
  00 nt!KeBugCheckEx  [nt+0x4f8450]
  01 nt!PopIrpWatchdogBugcheck+0x1f5  [nt+0x5ca7fd]
  02 nt!PopIrpWatchdog+0xc  [nt+0x5ca5fc]
  03 nt!KiProcessExpiredTimerList+0x505  [nt+0x327af5]
  04 nt!KiTimerExpiration+0x2b5  [nt+0x326d45]
  05 nt!KiRetireDpcList+0xd0e  [nt+0x2ab44e]
  06 nt!KiIdleLoop+0x9e  [nt+0x6a9f7e]
```

and the same answer as `structuredContent`, which is what a script reads:

```jsonc
{
  "status": "ok",
  "bug_check": {
    "code": "0x9f", "name": "DRIVER_POWER_STATE_FAILURE",
    "parameters": ["0x0000000000000003", "0xffffe284ffe59060",
                   "0xffffd38c2d84f580", "0xffffe2850787bc20"]
  },
  "process_name": "System",
  "frames": [
    { "index": 0, "address": "0xfffff803896f8450", "module": "nt",
      "rva": "0x4f8450", "symbol": "nt!KeBugCheckEx", "displacement": "0x0" },
    // …
  ],
  "frames_truncated": false,
  "faulting_frame_note": "every one of the 7 captured frames is in the kernel image or the HAL…",
  "analysis": {
    "ran": true, "command": "!analyze -v", "failure_bucket_id": "0x9F_3",
    "module_name": "Unknown_Module", "image_name": "Unknown_Image", "process_name": "System",
    "parameter_notes": ["A device object has been blocking an IRP for too long a time", /* … */]
  }
}
```

Two things to read off this crash in particular:

- **`faulting_frame` is `null`, and that is the finding.** `0x9F` is a *watchdog* bug check: it
  fires on an idle CPU's timer DPC, so the stack that bug-checked belongs to the watchdog and not
  to the driver holding the IRP. `frames_truncated: false` says the walk saw the whole stack, so
  raising `frames` would not help — the culprit genuinely is not on this stack, and §4 goes and
  finds it from the arguments instead. On a driver bug (`0x13A` out of a pool free, say) the same
  field is where the answer *is*: the topmost frame outside `nt`/`hal`, named `module+RVA` off the
  load base, which resolves even for a driver with no PDB.
- **`analysis` is `!analyze`'s half, kept apart.** `failure_bucket_id`, the `Arg` explanations and
  the pool tag (`FREED_POOL_TAG`, on the bug checks that have one) come from nowhere else. Its
  `module_name` is a *guess*, and the text says so whenever it disagrees with the frame.

`crash_triage { "analyze": false }` skips the `!analyze` — everything above except the `analysis`
block is read from the engine and comes back in well under a second.

## 3. Triage with `!ext.analyze -v`

`crash_triage` above is a summary; the full analysis carries things it does not lift out — the
`DRIVER_OBJECT` and `FAULTING_THREAD` this walkthrough goes on to use, and the timestamp warning
that first hints at NVIDIA.

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

## 4. Name the culprit by walking the device stack

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

## 5. Pitfall: partial minidumps and `0x80040205`

This is a small triage minidump, so most of the pool isn't captured. Reads of non-captured
pages don't return a clean "memory read error" — the engine raises an exception that the
server surfaces as:

```text
Debug command failed: An unexpected exception was raised (0x80040205)
```

`dq`/`dps` of an uncaptured range, or a full-struct `dt` that has to follow a pointer into
a missing page, will hit this. **Query the exact field you need** (e.g.
`dt _DRIVER_OBJECT <addr> DriverName`) rather than dumping whole structures, and prefer the
addresses `!analyze` hands you (PDO, IRP, DRIVER_OBJECT) — those are in the triage data.

## 6. Why `!ext.analyze` and not `!analyze`?

The bundled WinDbg engine has no debugger extensions next to it unless you copy the
`winext\` directory (see [setup.md](../skills/windbg-debugging/setup.md) /
[README](../README.md)). Without it, `!analyze` returns **empty** with
*"No export analyze found."* With `winext\` bundled:

- `open_dump` runs `.load ext` for you, **but** the unqualified `!analyze` still won't
  resolve on this minimal engine — only the module-qualified **`!ext.analyze -v`** does.
- All `!`-extension commands (`!ext.analyze`, `!process`, …) similarly need the
  module-qualified form or an explicit `.load`.

That's why this walkthrough uses `!ext.analyze -v`.
