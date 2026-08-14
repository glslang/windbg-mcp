# Crash-dump walkthrough: a `0x9F DRIVER_POWER_STATE_FAILURE`

A hands-on tour of the crash-dump tools against two real kernel minidumps:
[`052126-34312-01.dmp`](samples/052126-34312-01.dmp) (5.8 MB) for §1–§6, and
[`081226-2187-01.dmp`](samples/081226-2187-01.dmp) in [§7](#7-the-other-shape-of-crash-a-driver-frame-analyze-cant-name),
where a driver crashes in its own code and `!analyze` cannot name it. It mirrors the skill's
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
`!ext.analyze` resolves (see [§6](#6-why-extanalyze-and-not-analyze)), and answers with a
summary of the target — `vertarget`'s build and kernel base, the bug check, and how many
modules are loaded:

```text
Windows 10 Kernel Version 26100 MP (12 procs) Free x64
Kernel base = 0xfffff803`89200000 PsLoadedModuleList = 0xfffff803`8a0f52d0
Debug session time: Thu May 21 12:44:54.667 2026 (UTC + 1:00)

Bug check 0x9f DRIVER_POWER_STATE_FAILURE, parameters 0x0000000000000003 …
227 module(s) loaded, `nt` at 0xfffff80389200000; `modules` lists the table and `modules { "filter": "<name>" }` answers for one.
```

The same fields come back as `structuredContent.summary`. The **table** is `modules`, which is
worth one call here because it already tells a story: third-party drivers present include
`nvlddmkm` (NVIDIA), `nvhda64v` (NVIDIA HD-audio, many unloaded instances),
`RzDev_*`/`RzCommon` (Razer), and the virtualization stack (`VBox*`, `vmx86`/`hcmon`/`vmnet*`,
plus Hyper-V `Vid`/`winhvr`). Each row carries its symbol state as its own column — `nt` reads
`pdb` on a host with symbols for this build, and `deferred` (not fetched *yet*) is not the same
answer as `none`.

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
  // no "faulting_frame" key at all — every optional field in this server's structured results is
  // omitted rather than null, so this is how "there isn't one" looks. The note says why:
  "faulting_frame_note": "every one of the 7 captured frames is in the kernel image or the HAL…",
  "analysis": {
    "ran": true, "truncated": false, "command": "!analyze -v", "failure_bucket_id": "0x9F_3",
    "module_name": "Unknown_Module", "image_name": "Unknown_Image", "process_name": "System",
    "parameter_notes": ["A device object has been blocking an IRP for too long a time", /* … */]
  }
}
```

Two things to read off this crash in particular:

- **`faulting_frame` is absent, and that is the finding.** `0x9F` is a *watchdog* bug check: it
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

Reading one field across *many* objects is where this bites hardest: inside a `.for` loop the
first uncaptured page ends the whole script, so a table with one missing page in it comes back
empty rather than nearly complete. Use **`walk_memory`** for that — it reads each value on its
own, marks the ones it could not read, and walks the rest:

```jsonc
{ "addresses": ["0xffffb00a1c2d3000", "0xffffb00a1c2d4000", …],
  "fields": [{ "name": "DriverName", "offset": 56 }] }
```

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

## 7. The other shape of crash: a driver frame `!analyze` can't name

The `0x9F` above is a *watchdog* bug check, and its stack belongs to the watchdog. The
commoner case — and the one `crash_triage` was written for — is a third-party driver
crashing in its own code. A second sample is checked in for it,
[`docs/samples/081226-2187-01.dmp`](samples/081226-2187-01.dmp): a `0x13A` raised out of
`nt!ExFreePoolWithTag` by **`MessageManager.sys`**, a CTF driver with **no PDB**.

```jsonc
open_dump { "path": "…/docs/samples/081226-2187-01.dmp" }
crash_triage {}
```

```text
BUG CHECK: 0x13a KERNEL_MODE_HEAP_CORRUPTION
  Arg1: 0x0000000000000008  A free block was passed to an operation that is only valid for busy blocks.
  Arg2: 0xffff998228000140  Address of the heap that reported the corruption
  Arg3: 0xffff99823034eb10  Address at which the corruption was detected
  Arg4: 0x0000000000000000
PROCESS: mm_exploit_v5.exe
POOL TAG: TNf_
FAULTING FRAME: MessageManager+0x1654 (frame 07)
FAILURE BUCKET: 0x13a_8_TNf_
!analyze blamed: Unknown_Module — it disagrees with the faulting frame above. …

STACK (11 frames):
  00 nt!KeBugCheckEx  [nt+0x4f93c0]
  01 nt!RtlpHeapHandleError+0x40  [nt+0x5ea108]
  02 nt!RtlpHpHeapHandleError+0x58  [nt+0x5ea168]
  03 nt!RtlpLogHeapFailure+0x45  [nt+0x2e14e9]
  04 nt!RtlpHpVsSlotFreeList+0x150  [nt+0x2e1d00]
  05 nt!RtlpHpVsContextFree+0x155  [nt+0x2e1715]
  06 nt!ExFreePoolWithTag+0xc79  [nt+0xb68949]
  07 MessageManager+0x1654
  08 0xffff99823034eb30
  09 0xffff8784f840ee10
  10 0xffff998228000000
```

Four things to read off this, none of which the `0x9F` can show:

- **`!analyze` says `Unknown_Module`; the frame says `MessageManager+0x1654`.** The driver has
  no PDB, which is the case `!analyze`'s attribution handles worst and the case `module+RVA`
  handles fine — the engine knows which image holds the address and where it is loaded, and the
  offset falls out. Frame 07 is six frames below the top, under a stack of kernel allocator
  internals that a "blame frame 0" rule would have named instead.
- **`0x1654` is the whole point of an RVA.** Five dumps from the same crash/reboot loop reported
  that frame at five *different* addresses — `0xfffff8020a5e1654`, `0xfffff80561281654`,
  `0xfffff8070b001654`, … — because the driver loads somewhere new after every reboot. The RVA is
  identical in all five, so it is what tells an intended fire (`+0x1654`, the `SetData` free)
  from an incidental one.
- **Frames 08–10 are in no module and say so.** They are stack residue past the driver frame,
  reported as bare addresses rather than attributed to whatever image happens to be nearest.
- **`symbol` is absent, not invented.** The engine will happily answer an address in a PDB-less
  module with the *module's own name* and a displacement; that is `module`+`rva` in disguise, so
  it is not reported as a symbol. Compare frames 01–06, which have real `nt!` symbols and carry
  their displacements.

`analysis.pool_tag` (`TNf_` here) is the one field with no API behind it at all — `!analyze`
recovers it from the header of the chunk the bug check is about, and on this crash that header is
already corrupt, which is why the tag reads as garbage rather than as the driver's own `Tfub`.
That is a true reading of a corrupted chunk, not a parsing failure.
