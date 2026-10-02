# Inbox device graph probe

`tools/vdev_graph_probe.py` composes the six K1.1 inbox devices in one
owner-created VID partition. It is the K1.2 composition and lifecycle subgate
for `FOLLOWUPS.md` item 110.

The probe passed three consecutive runs on the guarded Windows 11 build. Each
run created one fresh process-local partition, activated all six devices,
supplied concrete VMBus, BIOS, and IOAPIC interfaces to their consumers,
initialized every device, ran the recovered RAM-construction-complete loop,
tore down in reverse order, released the objects and repositories, and deleted
the partition.

This does not start a VP. It also does not yet construct the final Windows RAM
topology. Firmware, synthetic-disk attachment, and a VTL0 boot remain later
gates.

## Run

Use an elevated x64 PowerShell prompt:

```powershell
python .\tools\vdev_graph_probe.py
```

The parent runs three children with independent VM GUIDs and 30-second
deadlines. A fault, hang, binary mismatch, stale contract manifest, unexpected
callback, lifecycle failure, retained reference after object destruction, or
partition-cleanup failure makes the parent exit nonzero.

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

The three-run elevated acceptance passed on 2026-10-02:

| run | partition | initialize | RAM-complete phase | teardown | deleted |
|---:|---:|---|---|---|---|
| 1 | `0x85` | six devices, `S_OK` | issued; zero supporting devices | six devices, `S_OK` | yes |
| 2 | `0x86` | six devices, `S_OK` | issued; zero supporting devices | six devices, `S_OK` | yes |
| 3 | `0x87` | six devices, `S_OK` | issued; zero supporting devices | six devices, `S_OK` | yes |

This closes the uncertainty around object composition, concrete cross-device
interfaces, ordering, repeated unwind, and the `vmwp` RAM-complete loop. The
next owner-side step is to reproduce the final managed-VM RAM topology and
firmware configuration, then reach a deterministic no-boot-device outcome
before attaching a disk.
