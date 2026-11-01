# h3probe

`h3probe.sys` is the minimal root-partition driver behind windbg-mcp's built-in live VTL1
providers. Its device, `\\.\H3Probe`, serves VTL0/VTL1 register calls, guest-physical memory through
an exact-build VID operation, and the decoder's refusing `HvCallReadGpa` negative control.

The memory operation replaced LiveCloudKd's `hvmm.sys`. How its primitive was found in `Vid.sys`
and measured against hvmm, and the gates that qualify it, are recorded in the
[hypercall feasibility record](../../docs/secure-kernel/secure-kernel-hypercall-feasibility.md).
The derivation is also kept beside `IOCTL_H3_VIDTRANSLATE` in `h3probe.c`.

## Provenance

The file moved byte-identical from public `secure-kernel-lab` commit `3f5526c`; the imported CRLF
working copy's SHA-256 was
`4DAA87B6ACD7BC97A77ECA7419F66AED2247AEEB099DC4F505702B3D0FBF6672`. This copy is now the source
of truth. Its older provenance remains visible in that repository: the original H3 gate came from
`exdi-rig` commit `1f962cd`, then grew the measured VID operations in sklab.

`build.cmd` is that repository's build script with four changes: it builds beside itself whatever
the current directory, `VSROOT` and `KV` override the Build Tools root and WDK version, an optional
certificate thumbprint test-signs the result, and it links `wdmsec.lib` for `IoCreateDeviceSecure`.

## Who can open it

Only SYSTEM and Administrators. Every control code is `FILE_ANY_ACCESS`, so the device's descriptor
is the only check on who reaches them. The device is created with `SDDL_DEVOBJ_SYS_ALL_ADM_ALL` and
`FILE_DEVICE_SECURE_OPEN`, so the descriptor also covers an open of a path under the device. Every
legitimate caller is an elevated administrator already, as any debugger is.

Before 2026-10-31 it was created with `IoCreateDevice` and no descriptor. Measured that day, the
default descriptor granted Everyone read and write. A medium-integrity token with Administrators
disabled, which is what an unelevated process runs with, opened `\\.\H3Probe` and reached the
dispatch routine. Tightening the descriptor at runtime refused that token at `\\.\H3Probe` but not
at `\\.\H3Probe\x`. The rebuilt image refuses it at both and still admits an elevated caller.

## What the server calls

| IOCTL | Function | Used by |
|---|---|---|
| `0x800` `IOCTL_H3_RUN` | enumerate children and prove VTL1 is enabled | provider startup identity |
| `0x801` `IOCTL_H3_READGPA` | `HvCallReadGpa` for one guest-physical range | `--sk-h3-memory --pages hypercall` negative control |
| `0x804` `IOCTL_H3_CALL` | one bounded `HvCallGetVpRegisters` / `HvCallSetVpRegisters`; every other hypercall code is rejected | `--sk-h3-control` and memory-provider identity |
| `0x810` `IOCTL_H3_VIDTRANSLATE` | measurement probe: which VID range holds one guest page | gated driver qualification |
| `0x812` `IOCTL_H3_MEMREAD` | one in-page byte range with a typed answer | `--sk-h3-memory` |
| `0x813` `IOCTL_H3_MEMWRITE` | one in-page read-patch-write with full-page readback | guarded live breakpoints and the driver tier |

The memory operation's request is `{Version, OwnerPid, PartitionHandle, PartitionId, Gpa, Length,
Reserved}` (40 bytes) and its answer `{Version, Result, Stage, Status, Length, Reserved, Gpn}` (32
bytes), followed for a read by the page's bytes; `C_ASSERT`s pin both. `Result` is `ok`,
`not-present`, `refused`, `error` or `identity`, and `Stage` names the step that decided it. The
caller supplies no pointer: the driver checks the exact `Vid.sys` build, attaches to the named vmwp,
refuses a kernel-handle value, requires the handle's partition to record that process as its owner
and to carry the caller's partition ID, and detaches and dereferences on every path.

Every handle shares one hypercall input/output page pair. A driver fast mutex covers composing,
issuing, and copying each call, so concurrent providers cannot splice their operations. An unknown
IOCTL returns `STATUS_INVALID_DEVICE_REQUEST` rather than a zero-byte success.

The dispatch surface exposes only the six rows above. Gate-era raw write, callback-chain, internal
VID inspection, VTL-enable and read-probe controls are no longer dispatched; an old client gets the
same unknown-IOCTL refusal.

## Qualification

The opt-in driver tier is `tests/h3probe_live.rs`, configured by
`WINDBG_MCP_SMOKE_H3PROBE`; [`docs/smoke-test.md`](../../docs/smoke-test.md) defines its private
schema and command. Its foreground `--sk-h3-qualify` role checks the typed corpus and VID range
map, concurrent register reads, unknown-IOCTL refusal, and a bounded byte write with readback and
restoration. The harness adds a killed provider, service stop/start under load, and refusal of the
old vmwp identity after a disposable-VM restart. The server itself performs none of the lifecycle
operations.

## Build, sign, install

From a Visual Studio Build Tools + WDK install (the defaults are Build Tools 18 and WDK
10.0.26100.0):

```powershell
cd drivers\h3probe              # from the repository root
.\build.cmd                    # compile and link: h3probe.sys beside the source
.\build.cmd <thumbprint>       # ...and sign with that code-signing cert from CurrentUser\My
```

The build output (`*.obj`, `*.pdb`, `*.sys`) is ignored by Git. A test-signed driver loads only on a
host with test signing enabled and the signing certificate trusted in `LocalMachine\Root` and
`LocalMachine\TrustedPublisher`.

Install it once as a demand-start kernel service, elevated and from this directory:

```powershell
sc.exe create h3probe type= kernel start= demand binPath= "$PWD\h3probe.sys"
```

Then pin the image in the operator's lab configuration. The server never installs, starts or stops
this service; its providers only open the already-running device. A lab may keep service-lifecycle
commands such as:

```powershell
uv run sklab driver            # status of h3probe
uv run sklab driver start
uv run sklab driver stop
```

The convention is to leave it stopped between runs. Stop only when no live session holds the
device; `driver stop` reports the state the service actually reached rather than assuming the stop
took.

For the server's provider policy, VM and profile setup, use
[`m8-debugger.md`](../../docs/secure-kernel/m8-debugger.md).
