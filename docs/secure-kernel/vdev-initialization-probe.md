# Inbox device initialization probe

`tools/vdev_initialization_probe.py` is the fatal K1.1 spike for
`FOLLOWUPS.md` item 110. It asks whether the inbox RTC and VMBus device models
can initialize in an ordinary owner process, without `vmwp.exe`, VMMS-managed
state, or a second VID receive loop.

The answer on the guarded Windows 11 build is **yes**. Both devices return
`S_OK` from `IVirtualDevice::Initialize`, return `S_OK` from `Teardown`, and
release every supplied dependency. VMBus does so against a fresh process-local
VID partition created and deleted by its child process.

This result opens the owner-hosted device-graph work in K1.2. It does not prove
that firmware, synthetic storage, or the complete boot device graph can run
outside `vmwp`; those interfaces and lifecycle calls still have to be traced.

## Run

Use an elevated x64 PowerShell prompt:

```powershell
python .\tools\vdev_initialization_probe.py
```

The parent starts RTC and VMBus in separate children, gives each child 30
seconds, and emits one JSON result. A child fault, timeout, identity mismatch,
unexpected callback, failed initialization, or failed teardown makes the
parent exit nonzero. The VMBus partition is process-local, so terminating a
timed-out child also closes its ownership boundary.

The read-only binary check works without elevation:

```powershell
python .\tools\vdev_initialization_probe.py --identity-only
```

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
| `vid.dll` | 10.0.26100.8457 | 263,552 | `9B538C07FA65C09D406956371EF3C68F4BCE4E1FA9F694E4CCB727409366FA26` | not used by this probe |
| `Vid.sys` | 10.0.26100.9278 | 910,816 | `6611BCD768EFCFF90C13D39C4D9770315269C43201B3A58B638977486AB06697` | not used by this probe |

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

RTC requests six services:

| service | IID |
|---|---|
| `IVmBios` | `{9BE0B79F-68DF-4C59-9D88-4BFC1BF7A73D}` |
| `IVmAmd64EmulationServices` | `{FCACE8D2-AB0D-480D-B979-55C2DA5F9579}` |
| `IVmIoApic` | `{9D33829B-58BE-4BBF-AB6E-3B16DBCEF954}` |
| `IVmManagementAccess` | `{BB011455-A4F6-4E08-9982-09AFD303DF20}` |
| `ISecurityManager` | `{5315507B-19F0-4E86-AB51-18F159F1A197}` |
| `IVmTimeSource` | `{E162FE7A-72C6-4D0E-93DD-7DF91A5B979D}` |

It accepts repository version `0x100`, tolerates a missing exported
configuration, and calls no dependency method during initialization.

VMBus requests four services:

| service | IID |
|---|---|
| `ISecurityManager` | `{5315507B-19F0-4E86-AB51-18F159F1A197}` |
| `IVmMemoryManagement` | `{E7BB1D35-AD97-464B-8A3F-95F43E0F4389}` |
| `IVmPartitionServices` | `{773E9A95-1B2D-4479-955F-402000EBE6C2}` |
| `IVmHandleBrokerServices` | `{E9E61D12-A2C3-4E55-AC35-B8F26D216A69}` |

It accepts repository version `0x201` and the following minimum exported
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

The elevated run passed on 2026-10-02. RTC initialized and tore down with the
repository call sequence `11, 3, 17, 7, 40, 18, 39`. VMBus initialized and tore
down with `11, 3, 17, 7, 40, 18`, opened partition ID `0x51` in that run, and
the child then deleted it. Partition IDs and GUIDs are intentionally fresh on
every run.

The pass is narrow: it disproves the K1.1 hypotheses that initialization itself
requires `vmwp` process identity, an identity-bearing VMMS repository, managed
VM state, or a competing receive loop. K1.2 must still recover and implement
the callback semantics needed by the complete minimum device graph.
