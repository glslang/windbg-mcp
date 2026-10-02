# Diskless inbox firmware preflight

`tools/vdev_firmware_probe.py` is the K1.3 preflight for `FOLLOWUPS.md` item
110. It composes the six-device graph in a fresh owner-created VID partition,
installs the minimum firmware-time services, powers the five devices that do
not require a storage LUN, captures the inbox BIOS's UEFI boot state, writes it
to guest RAM, and applies its register state to VP0.

The probe passed three consecutive runs on the guarded Windows 11 build. It
does **not** start VP0. The result proves boot-state construction and application,
not firmware execution, a boot-device outcome, synthetic storage, or a Windows
boot.

## Run

Use an elevated x64 PowerShell prompt:

```powershell
python .\tools\vdev_firmware_probe.py
```

The parent runs three children with independent VM GUIDs and 45-second
deadlines. Each child owns its partition and deletes it on every normal or
exceptional exit. A fault, hang, binary mismatch, stale device contract,
unexpected import, page-readback difference, critical register change,
lifecycle failure, retained reference, or cleanup failure makes the parent exit
nonzero.

## Firmware services

The graph probe established the shared device objects and fixed 4 GiB memory
map. This probe supplies the additional callbacks used by the diskless cold
power path:

| service | slot | supplied value |
|---|---:|---|
| `IVmMemoryTopology` | 3 | 144-byte SRAT |
| `IVmMemoryTopology` | 4 | PCI and MMIO page ranges |
| `IVmMemoryTopology` | 7, 10 | one package and one thread |
| `IVmMemoryTopology` | 11 | 80-byte MADT |
| `IVmMemoryTopology` | 13, 14 | empty SLIT and PPTT |
| `IVmBootMemoryTopology` | 6 | the low and high RAM spans |
| `IVmProcessorServices` | 3 | one VP |
| `IVmBootStateImporter` | 4 | checked, zero-padded GPA-page import |
| `IVmBootStateImporter` | 5 | 16-byte VP register import |
| `IVmBootStateImporter` | 6 | isolation type zero |
| `IVmMemoryManagement` | 14 | memory mode zero |
| `IVmPowerManagementDevice` | 3 | successful diskless power notification |
| `ISecurityManager` | 15 | no TPM |

Every callback catches errors at the native callback boundary, records the
failure, and returns an `HRESULT`; no Python exception is allowed to unwind
through inbox code. The service collection contains only dependencies required
by at least one device. Optional service queries therefore receive
`E_NOINTERFACE` rather than a permissive stub.

The MADT describes one enabled local APIC, the IOAPIC at `0xFEC00000`, IRQ 9's
interrupt-source override, and the local-APIC NMI. The SRAT describes one
processor and the two measured RAM affinities. Both tables carry the recovered
`VRTUAL` / `MICROSOFT` OEM fields, their declared lengths match their buffers,
and their checksums are zero.

## Boot-state import

`BiosVdev::PowerOnCold` makes these five nonoverlapping page imports. The probe
writes each through `VidWriteMemoryBlockPageRange` in at most 16-page chunks,
zero-fills the unused part of the requested range, reads the complete range
back through VID, and requires byte equality before returning `S_OK` to the
BIOS.

| GPA page | pages | source bytes | role |
|---:|---:|---:|---|
| `0x100` | `0x600` | `0x600000` | inbox UEFI image |
| `0x700` | 6 | `0x6000` | initial firmware data |
| `0x706` | 1 | 24 | loader data |
| `0x707` | 2 | 0 | zero-filled pages |
| `0x709` | 1 | 704 | final loader data |

The importer then receives 19 VP0 state records in this exact order:

```text
70001 60003 60000 60004 60005 60002 60001
40000 40002 40003 80001 80004
20011 20005 20010 20008 20009 2000A 2000B
```

The measured scalar state is `CR0=0x80000023`, `CR3=0x700000`,
`CR4=0x660`, `EFER=0xD00`, `PAT=0x7040600070406`, `RFLAGS=0x2`,
`RBP=0x6E0000`, and `RIP=0x6E1474`. `RIP` is also required to fall inside the
imported UEFI image rather than merely match this observation.

All 19 records are applied in one `VidSetVirtualProcessorStateEx` call and read
back in one `VidGetVirtualProcessorStateEx` call. VID canonicalizes the fixed
x86 `CR0.ET` bit, so `CR0` reads as `0x80000033`. That is the only changed
record. The probe requires this exact canonicalization and exact low-64-bit
readback for the critical scalars; every other 16-byte record must remain exact.

## Guarded power lifecycle

The probe checks the cold-power and power-off vtable entries before calling
them:

| device | `PowerOnCold` slot 10 | `PowerOff` slot 12 |
|---|---:|---:|
| VMBus | `0x146B0` | `0x145B0` |
| IOAPIC | `0x781D0` | `0x77E80` |
| BIOS | `0x8900` | `0x47AA0` |
| RTC | `0x7D210` | `0x7D170` |
| guest emulation | `0x6A1F0` | `0x69A10` |
| SynthStor | `0x1E970` | `0x1D410` |

VMBus, IOAPIC, BIOS, RTC, and guest emulation return `S_OK` from cold power.
SynthStor is initialized and participates in resource reservation, but it is
not powered because this gate deliberately supplies no LUN. Power-off, free
reservation, and teardown run in reverse order; both memory blocks and GPA
ranges are then destroyed before the partition is deleted.

## Measured result

The acceptance run passed on 2026-10-03:

| run | partition | page imports | VP records | powered devices | VP started | deleted |
|---:|---:|---:|---:|---:|---|---|
| 1 | `0x33` | 5, all exact readback | 19 | 5, all `S_OK` | no | yes |
| 2 | `0x34` | 5, all exact readback | 19 | 5, all `S_OK` | no | yes |
| 3 | `0x35` | 5, all exact readback | 19 | 5, all `S_OK` | no | yes |

This closes the minimum UEFI configuration and boot-state-import boundary. The
next gate must attach a real SynthStor LUN and implement the owner-side VID
completion dispatcher before starting VP0. A start without that dispatcher did
not advance the imported `RIP`, so it is not evidence of firmware execution.
