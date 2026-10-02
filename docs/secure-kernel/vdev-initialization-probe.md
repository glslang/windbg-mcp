# Inbox device initialization probe

`tools/vdev_initialization_probe.py` is the K1.1 contract probe for
`FOLLOWUPS.md` item 110. It asks whether the six inbox device models in the
minimum Windows boot can initialize in an ordinary owner process, without
`vmwp.exe`, VMMS-managed state, or a second VID receive loop.

The answer on the guarded Windows 11 build is **yes for each independent
initialization path**. `GuestEmulationDevice`, `BiosVdev`, `RtcVdev`,
`IoApicVdev`, `VmbusVdev`, and `SynthStor` return `S_OK` from
`IVirtualDevice::Initialize`, return `S_OK` from `Teardown`, and release every
supplied dependency. Every device except RTC runs against a fresh process-local
VID partition created and deleted by its child process.

This result narrows K1.2 to composition. It does not prove that the six objects
can share one service graph, accept the RAM-construction-complete notification,
execute firmware, or perform synthetic disk I/O. Those remain separate gates.
The exact build-bound record is
[`vdev-contract-26100.8457.json`](vdev-contract-26100.8457.json).

## Run

Use an elevated x64 PowerShell prompt:

```powershell
python .\tools\vdev_initialization_probe.py
```

The parent starts all six devices in separate children, gives each child 30
seconds, and emits one JSON result. A child fault, timeout, identity mismatch,
stale contract manifest, unexpected callback, failed initialization, or failed
teardown makes the parent exit nonzero. Each partition-backed child has its own
process and fresh VM GUID, so terminating a timed-out child also closes its
ownership boundary.

The read-only binary check works without elevation:

```powershell
python .\tools\vdev_initialization_probe.py --identity-only
```

Check the committed contract without making a VID call:

```powershell
python .\tools\vdev_initialization_probe.py --check-contract
```

`--contract-only` prints the canonical JSON used to regenerate the committed
manifest. Normal and identity-only runs refuse a stale manifest.

Do not run the internal `--child` mode directly. The parent supplies a fresh VM
GUID and enforces the deadline.

## Build guard

The probe refuses a different size or SHA-256 before loading private
interfaces. It also requires the device DLLs' embedded CodeView identity and
checks that `IVirtualDevice` slots 3 through 5 come from the guarded module at
the recovered RVAs.

| file | guarded version | bytes | SHA-256 | PDB identity |
|---|---:|---:|---|---|
| `vmchipset.dll` | 10.0.26100.8457 | 1,177,064 | `8C13A65575EC35C73B4AABA631F7E7E1E52F88D503A3186B3EAECD375C2BE2D9` | `{2E91C425-4BBA-1675-375F-8AF8720410F8}`, age 1 |
| `vmbusvdev.dll` | 10.0.26100.8457 | 271,840 | `64104CEFE36B4E7695D39550FF64CE94A0CD21F2D9693171E8331BCC60A51736` | `{A1F04F82-DB3B-3AF6-6744-C606F24BEEB9}`, age 1 |
| `vmsynthstor.dll` | 10.0.26100.8457 | 517,624 | `E7972B586FA2E8540ED9738C3CA5B6D9D0EF0EB02C1A7FAAABAC33689790446B` | `{894A49E8-F56D-3957-E8EB-2214733ECA28}`, age 1 |
| `vmwp.exe` | 10.0.26100.8457 | 3,720,352 | `AC076752BD5424B57C994D4529C5179BB153F9DA0119FB23AD1C13AC9A571B20` | `{DC281C89-2BE3-8A04-AC2B-1C27F20A2865}`, age 1 |
| `vmfirmware.dll` | 10.0.26100.7623 | 6,436,256 | `4FE86E4B71D814F2D679D32BFC813B9B2600A4F1CBFE67C3FEB6689E681A53F6` | no CodeView record |
| `vid.dll` | 10.0.26100.8457 | 263,552 | `9B538C07FA65C09D406956371EF3C68F4BCE4E1FA9F694E4CCB727409366FA26` | no PDB guard |
| `Vid.sys` | 10.0.26100.9278 | 910,816 | `6611BCD768EFCFF90C13D39C4D9770315269C43201B3A58B638977486AB06697` | no PDB guard |

The recovered common interface is:

| `IVirtualDevice` slot | method |
|---:|---|
| 3 | `GetDependencies(repository, count, services, required_count)` |
| 4 | `Initialize(repository, uint64_argument, services)` |
| 5 | `Teardown()` |

The probe also pins `IID_IVirtualDevice` to
`{0693ED7D-8A8A-4D87-A468-1103B8C63D9C}`, the repository IID to
`{355AC5A8-8A94-44A9-BE14-ECF7FB8F7C3B}`, and the service-map IID to
`{20BEEF08-C3AB-44D8-92C3-03EC0CF398DC}`.

## Minimum measured contracts

The manifest records every IID in the exact order returned by
`GetDependencies`, including the required count and optional suffix. It also
records the complete recovered configuration-field list and the minimum XML
used in the passing run. The compact result is:

| device | dependencies | initialization-specific calls |
|---|---:|---|
| `GuestEmulationDevice` | 13 required, 3 optional | `ISecurityManager` slot 11 returns zero; repository `/generation_id` returns the zero GUID |
| `BiosVdev` | 16 required, 4 optional | repository `/generation_id` returns the zero GUID; `ISecurityManager` slots 12, 13, and 10 return zero |
| `RtcVdev` | 6 required | no service method; missing exported configuration is accepted |
| `IoApicVdev` | 4 required, 1 optional | no service method |
| `VmbusVdev` | 4 required | handle-broker slot 3 returns `E_NOTIMPL` |
| `SynthStor` | 4 required | runtime configuration is absent; repository `/PreallocatedResources` returns `false` |

The optional IID order from `GetDependencies` is the reverse of the order in
which the guest and BIOS initialization templates query those optional
services. The probe asserts both the returned IID order and the observed
initialization behavior rather than inferring one from the other.

VMBus accepts repository version `0x201` and this minimum exported
configuration:

```xml
<VMBusDevice><VDEVVersion>513</VDEVVersion><version>1</version><MessageRedirection>false</MessageRedirection></VMBusDevice>
```

The handle-broker lookup for `VmbusVdevHandle` deliberately returns
`E_NOTIMPL`. VMBus then opens `\\.\VMBus\vdev\{vm-id}` itself. That open succeeds
only while the probe owns a direct VID partition with the same bare GUID, which
is the measured link between the inbox device and the owner-created partition.
No other supplied service method is called by `Initialize` or `Teardown`.

## Measured result

The expanded elevated run passed on 2026-10-02. All six devices initialized and
tore down in isolated children. The five partition-backed children opened IDs
`0x77` through `0x7B` in the recorded run and deleted them before exiting.
Partition IDs and GUIDs are intentionally fresh on every run.

The pass disproves the K1.1 hypotheses that any of these six independent
initialization paths inherently requires `vmwp` process identity, an
identity-bearing VMMS repository, managed VM state, or a competing receive
loop. The separate graph probe subsequently replaced the relevant recording
stubs with shared services, composed the six objects in one partition, issued
the RAM-complete query loop, and proved reverse-order teardown three times.
