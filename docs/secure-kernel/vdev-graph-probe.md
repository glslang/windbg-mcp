# Inbox device graph probe

`tools/vdev_graph_probe.py` composes the six K1.1 inbox devices in one
owner-created VID partition. It is the K1.2 composition and lifecycle subgate
for `FOLLOWUPS.md` item 110.

The probe passed three consecutive runs on the guarded Windows 11 build. Each
run created one fresh process-local partition, activated all six devices,
supplied concrete VMBus, BIOS, and IOAPIC interfaces to their consumers,
initialized every device, began resource reservation, configured VSM, installed
the measured fixed 4 GiB Windows RAM topology, ran the recovered RAM-complete
and reservation-finish phases, freed every reservation, tore down in reverse
order, released the objects and repositories, destroyed both memory ranges, and
deleted the partition.

This does not start a VP. Firmware execution, synthetic-disk attachment, and a
VTL0 boot remain later gates.

## Run

Use an elevated x64 PowerShell prompt:

```powershell
python .\tools\vdev_graph_probe.py
```

The parent runs three children with independent VM GUIDs and 30-second
deadlines. A fault, hang, binary mismatch, stale contract manifest, unexpected
callback, memory-layout or readback failure, lifecycle failure, retained
reference after object destruction, or cleanup failure makes the parent exit
nonzero.

The graph probe imports the guards and device definitions from
`vdev_initialization_probe.py`. The generated source of truth is
[`vdev-contract-26100.8457.json`](vdev-contract-26100.8457.json); the ordinary
initialization probe refuses to run when that file is stale.

## Composed service graph

The initialization order is:

1. `VmbusVdev`
2. `IoApicVdev`
3. `BiosVdev`
4. `RtcVdev`
5. `GuestEmulationDevice`
6. `SynthStor`

Teardown uses the exact reverse order. Three object-provided interfaces replace
the corresponding recording stubs:

| provider | interface | IID | consumers |
|---|---|---|---|
| `VmbusVdev` | `IVmbusServices` | `{ECE3F556-F87F-4120-9E37-AAA55E5E0CA9}` | BIOS, guest emulation, SynthStor |
| `IoApicVdev` | `IVmIoApic` | `{9D33829B-58BE-4BBF-AB6E-3B16DBCEF954}` | BIOS, RTC |
| `BiosVdev` | `IVmBios` | `{9BE0B79F-68DF-4C59-9D88-4BFC1BF7A73D}` | RTC, guest emulation |

All three providers return `S_OK` from `QueryInterface`. The remaining services
are typed recording objects. Their only initialization calls remain the
measured K1.1 set: VMBus tries handle-broker slot 3, BIOS calls security slots
12, 13, and 10, and guest emulation calls security slot 11.

`BiosVdev` retains its repository after `Teardown` and releases it when the COM
object is destroyed. The probe therefore checks repository ownership after it
closes graph-held provider interfaces and releases every device object. This is
the observed object lifetime, not a leak hidden by process exit.

## Fixed Windows RAM topology

Paired one-VP managed checkpoints establish the same two memory chunks for the
VBS and VBS-off disks. The positive arm reports VTL0+VTL1 enabled and a valid
initialized Secure Kernel module list; the control reports only VTL0. Both give
this fixed 4 GiB physical layout:

| span | start | size | pages |
|---|---:|---:|---:|
| low RAM | `0x0` | `0xF8000000` | `0xF8000` |
| PCI/MMIO hole | `0xF8000000` | `0x08000000` | not RAM |
| high RAM | `0x100000000` | `0x08000000` | `0x8000` |

The probe initializes the devices first and calls slot 6,
`StartReservingResources`, in graph order. It then enables VTL0 and VTL1 in the
24-byte VSM configuration, creates one VSM-capable VA-backed memory block per
RAM span, binds both blocks to the partition's notification queue, and creates
GPA ranges with default VTL protections. It maps and reads back one marked page
from each block, then clears the markers. The RAM-complete query runs only after
both ranges exist. Slot 7, `FinishReservingResources`, then runs in graph order
with rollback clear. Slot 8, `FreeReservedResources`, and teardown run in
reverse. A partial failure calls `FinishReservingResources` with rollback set
and frees each successfully started reservation before object teardown.

The guarded slot 6 through 8 RVAs are:

| device | start | finish | free |
|---|---:|---:|---:|
| VMBus | `0xFEE0` | `0xFEE0` | `0xFEE0` |
| IOAPIC | `0x12890` | `0x37FB0` | `0x38020` |
| BIOS | `0x4A480` | `0x44650` | `0x446B0` |
| RTC | `0x12890` | `0x37FB0` | `0x38020` |
| guest emulation | `0x6B450` | `0x62390` | `0x62770` |
| SynthStor | `0x23EA0` | `0x17BD0` | `0x17CD0` |

The probe checks those entries before making a lifecycle call. Teardown then
destroys both ranges and blocks before deleting the partition.

## RAM-construction-complete lifecycle

The exact `vmwp.exe` symbols place
`VirtualMotherboard::NotifyAllDevicesRamConstructionComplete` at RVA
`0x218780`. Decompilation of the guarded image shows that it:

1. walks every device;
2. queries `IID_IVirtualDeviceMemoryInfo`,
   `{2E223C59-62C4-4D03-93E4-05674B3B94EB}`;
3. when supported, calls interface slot 4 with a 32-bit argument; and
4. logs a failed method result but continues the walk.

Its only direct caller on this path, RVA `0x97928`, passes argument `0`. The
probe mirrors that behavior after every device has initialized. All six devices
return `E_NOINTERFACE` both before and after initialization, so this minimum
graph receives no slot-4 call. The phase is still issued and asserted on every
run; its measured outcome is a six-device no-op.

## Measured result

The resource-lifecycle acceptance passed on 2026-10-02:

| run | partition | start/finish/free | RAM-complete phase | teardown | deleted |
|---:|---:|---|---|---|---|
| 1 | `0x1A` | six devices, all `S_OK` | issued; zero supporting devices | six devices, `S_OK` | yes |
| 2 | `0x1B` | six devices, all `S_OK` | issued; zero supporting devices | six devices, `S_OK` | yes |
| 3 | `0x1C` | six devices, all `S_OK` | issued; zero supporting devices | six devices, `S_OK` | yes |

This closes the uncertainty around object composition, concrete cross-device
interfaces, the final fixed RAM map, the pre-power resource lifecycle, repeated
unwind, and the `vmwp` RAM-complete loop. The next owner-side step is to replace
the firmware-time service stubs, create the first VP, and reach a deterministic
no-boot-device outcome before attaching a disk.
