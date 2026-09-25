# Plan: an EXDI stub for Secure Kernel debugging

Expands **Phase 4** of [the Secure Kernel plan](secure-kernel-debugging-plan.md), which this
replaces as the working detail for that phase. The measurements it rests on are in
[the validation record](secure-kernel-debugging-validation.md#secure-call-dispatch-of-the-debug-break-request-and-exdi-reassessment-2026-09-22).
Nothing here is authorized by writing it down: every gate below names what it changes on a host,
and the host changes need their own approval.

## Why this route rather than native KDNET

Measured 2026-09-22, offline, across eight `securekernel.exe` images:

- **No KD transport.** Every `Kd`-prefixed symbol in the six post-26100 images is data — eleven of
  them — and none is a function. The two pre-26100 samples have no `Kd`-prefixed symbol at all.
  There is no packet loop in the image to configure, which is why no amount of `bcdedit` or
  `kdnet` work reached a VTL1 session.
- **A complete self-description.** `SkdInitDebuggerDataBlock` fills `KdDebuggerDataBlock` — `KDBG`
  signature, size `0x3A8`, `SkLoadedModuleList` in the loaded-module-list slot, `SkeProcessorBlock`,
  `SkiBugCheckData`, the `Skmm*` address bounds, `DbgBreakPointWithStatus`, the PTE swizzle bit.

**SK ships the metadata a debugger keys off and no transport to deliver it.** That is exactly the
split EXDI closes: EXDI does not ask the target to speak a protocol, it asks something outside the
target to serve registers and memory and lets DbgEng supply the kernel awareness. Both halves of
that sentence are about these images' inspected routines and do not exclude a path not inspected.

## The shape

```text
windbg-mcp worker
  └─ dbgscope: AttachKernel(DEBUG_ATTACH_EXDI_DRIVER, "CLSID={29f9906e-…},Kd=…")
       └─ dbgeng.dll
            └─ ExdiGdbSrv.dll          ← Microsoft's, ships in the WinDbg package
                 └─ TCP, GDB remote serial protocol
                      └─ our stub      ← the only new component
                           └─ backend (QEMU for the experiments, Hyper-V for the product)
```

**The backend contract is a GDB stub, not a COM server.** `ExdiGdbSrv.dll` is a generic EXDI COM
server that speaks RSP, and it ships for `amd64` and `arm64` inside the installed WinDbg package
with `exdiConfigData.xml` beside it (measured 2026-09-22). So there is no LiveCloudKd dependency,
no EXDI COM interface to implement, and no third-party distribution to install — only a
registration, which is host setup the MCP server cannot do.

**That exclusion is about what this server would *ship*, and it does not extend to what may be used
to answer a question.** LiveCloudKd is a third-party distribution and stays out of the product for
the reasons above; it is also, on its author's account, an existing EXDI route into VTL1 —
`ExdiKdSample.dll`, registering its own CLSIDs `{53838F70-0936-44A9-AB4E-ABB568401508}` (passive,
read-only) and `{67030926-1754-4FDA-9788-7F731CBDAE42}` (active), with **no gdbstub anywhere in
it** ([windows-internals.com](https://windows-internals.com/secure-kernel-research-with-livecloudkd/),
read 2026-09-25). Read access to secure-kernel memory is the solid claim there; breakpoints and
single-stepping are described but not demonstrated by that write-up, so treat the active mode as
untested rather than available. Its constraints are that it runs **on the Hyper-V host of the
target** — no remote debugging is described — and that the guest has VBS on and nested
virtualisation **off**, which is consistent with the validation record's note that exposing
virtualisation extensions "enables the nested-hypervisor route, not a universal prerequisite for
Hyper-V guest VBS". That host requirement is a topology constraint rather than a detail: it places
the debugger on whichever machine hosts the target's hypervisor.

### Where each component runs

**The guest's own IP address is not the debug endpoint, and that is the first thing to get wrong.**
The GDB stub is opened by the per-VM `vmware-vmx` process on the **VMware host**, on that host's
TCP stack; the guest's NAT address is for KDNET or WinRM and the driver never dials it.
`ExdiGdbSrv.dll` is a *client* of that stub and loads inside the debugger process, so it belongs
wherever `dbgeng.dll` runs — which can be a different machine from the VMware host:

```text
VMware host
  ├─ vmware-vmx ──► GDB stub, TCP 8864        ◄── the endpoint the debugger dials
  │    └─ Windows guest ── NAT ── <guest-ip>  ◄── KDNET/WinRM only
  └─ (the stub binds 127.0.0.1 unless debugStub.listen.guest64.remote is set)

debugger host  ── windbg-mcp worker ─ dbgeng.dll ─ ExdiGdbSrv.dll ──TCP──► <vmware-host>:8864
```

Checked 2026-09-24 on this bench, which is a Hyper-V guest of the box running VMware: the VMware
host answers on the Hyper-V NAT network, so guest-to-host is the direction the transport needs and
the one NAT allows. The stub's port was closed, the debugger host had no route to the VMware NAT
segment at all, and of the parent's management ports only SMB answered — so the `.vmx` edit and the
firewall rule are console work on the VMware host rather than something the debugger host can
arrange for itself. The `.vmx` keys and the 8864/8832 defaults are **recalled and not measured
here**, no VMware being installed on the debugger host to check them against.

**When Hyper-V owns the box, VMware runs on the Windows Hypervisor Platform, and that costs the
guest its VBS.** Nested virtualisation (`vhv.enable`) is what lets a guest run VBS/HVCI, and
without VBS there is no Secure Kernel in it to debug — which is E2's whole subject, while E0 and E1
need only a plain NT guest. Reported from the host 2026-09-25: the guest's `msinfo32` gives VBS as
not enabled, VMware is running on WHP, and virtualisation is not available to hand to the guest.
Hyper-V stays enabled there, the Hyper-V guests on that box being the rest of this lab, so the
guest cannot acquire VBS later either.

**That closes the E0-to-E2 path on a Hyper-V-locked host one step earlier than the stop conditions
below anticipate.** Those are written for E2 *running* and finding SK pages unreadable; here E2
cannot run at all, because no hypervisor on the box both exposes a gdbstub and can host a VBS
guest. Hyper-V can host one and exposes no gdbstub; VMware exposes a gdbstub and, under WHP, has no
nested virtualisation to give. QEMU on that host meets the same wall through WHPX, and its TCG mode
does not implement VMX/SVM for a guest hypervisor to run on — so the emulation fallback is not one.

**A second, bare-metal Linux host restores E2 without moving the driver.** VMware Workstation on
Linux uses its own kernel modules rather than the platform's hypervisor, so `vhv.enable` is
available and a Windows guest there can run VBS; a guest built under Workstation on Windows moves
across as its `.vmx` and disks. QEMU/KVM on that same host is the alternative, and is what E0's
register block is lifted from. `ExdiGdbSrv.dll` dials out, so the debugger host stays where it is
and reaches the new box over TCP — measured on this bench 2026-09-25, outbound TCP and DNS leave
the Hyper-V NAT segment, which is the direction this needs and the opposite of the inbound path E0
requires. Neither host has been built.

**What that rules out is a gdbstub-backed VBS guest, which is narrower than it first reads, and the
closing sentence here used to overstate it as "why the single-box arrangement cannot work".** A VBS
*target* on this hardware is available and always was: Hyper-V is the box's primary hypervisor, so
`Set-VMProcessor -ExposeVirtualizationExtensions` on one of its own guests is the supported,
documented feature rather than the second-hypervisor-on-WHP case that defeats VMware there. The
validation record's [sibling layout](secure-kernel-debugging-validation.md) already writes that
procedure down, and it costs this workspace nothing: the flag goes on the *target* VM, KDNET runs
between it and the debugger over a virtual network, and no nesting, memory or reboot is asked of
the debugger host.

**Multi-level nesting is demonstrated rather than impossible, which is the other half of the
correction.** The deferred nested layout was recorded as adding "another virtualization layer whose
suitability remains to be demonstrated", and a published VTL1 write-up runs exactly that shape — a
Hyper-V guest as the debugger machine, passing Hyper-V through to a Windows 11 25H2 target inside
it ([fluxsec.red](https://fluxsec.red/what-does-hyperguard-skpg-monitor-vtl1-windows-internals-secure-kernel-patch-guard),
read 2026-09-25). So depth of nesting is not the objection to either layout.

**Neither layout supplies a transport, and that is the whole of what is missing.** Both give a
guest with `securekernel` running and its NT side reachable over KDNET; neither exposes a gdbstub,
and the native KD route into SK is dead for the reasons at the top of this document. That write-up
does not close the gap either: its setup section is explicitly deferred to a later post, and the
commands it shows are ordinary kernel-debugger commands against `nt`. Treat it as evidence about
topology, not about reaching VTL1.

## Gates

Each gate has a pass condition and a control. **A gate without its control passing first is not
evidence**, because an SK failure and a rig failure look identical from the debugger side.

### E0 — prove EXDI works at all, on NT

Nothing to do with Secure Kernel. Establishes the rig.

1. **Register the COM server. This is a real prerequisite — DbgEng does not do it for you on a
   plain attach.** Measured 2026-09-22 on this workspace, elevated, with the CLSID absent:
   `kd -kx exdi:CLSID={29f9906e-…},Kd=Guess,DataBreaks=Exdi` fails with
   `0x80040154 Class not registered` and registers nothing. An earlier revision of this step
   claimed the opposite, reading the registration strings in `dbgeng.dll` as proof the engine
   self-registers; it has the code and did not run it. **The strings were evidence of a code path,
   not of when it executes** — the same mistake
   [`measurement-provenance.md`](../.claude/rules/measurement-provenance.md) is about.

   **Do not reach for `Inproc=` to avoid registering.** It exists, and it is a trap. The value is a
   *bare filename* resolved against the debugger's own directory — an absolute path is
   concatenated onto that directory and fails `LoadLibraryExW` with error 126. With
   `Inproc=ExdiGdbSrv.dll` the engine prints its own warning and nothing further:

   ```text
   EXDI WARNING! The /Inproc option is not compatible with connecting remote clients.
                 Consider removing it if you encounter hangs or strange behavior.
   ```

   **On this bench that attempt hung the host hard enough to need a reset** (2026-09-22; the box
   came back with a 2-minute uptime and no surviving processes). The RSP responder on the far end
   logged **no connection at all**, so nothing reached the transport and neither a runaway
   `Kd=Guess` scan nor the responder's replies were involved — `heuristicScanSize` was already
   `0xffe`. The hang was not observed directly, so *in-process COM load* is where the evidence
   points rather than a proven cause; what is established is that the warning is the last output
   and the machine did not recover. Nothing was left registered, so there was no cleanup to do.
   This is the same hazard class as a `cdb -server` spinning on a broken pipe: a debugger child
   that cannot be killed from outside takes the host with it.

   **What the registration actually produces is an out-of-process server, and that shapes the
   rest of this gate.** Run 2026-09-25 on this bench, elevated: `regsvr32` writes
   `HKLM\SOFTWARE\Classes\CLSID\{29f9906e-…}` as `LiveExdiGdbSrvServer Class`, with
   `InprocServer32` naming the DLL and `ThreadingModel = Apartment` — **and an `AppID`
   `{1FC9AD2A-EEC4-467E-AA40-951987327C81}` (`ExdiTestServer1`) whose `DllSurrogate` is the empty
   string**, which is the registration that asks COM to host the server in `dllhost.exe`. So on
   the registered path the "EXDI server" is a separate process owned by RPCSS rather than a DLL
   inside the debugger.

   **And it cannot be registered where it ships.** `LoadLibraryExW` against the package's own copy
   returns error 5, `Access is denied`, under plain flags, `ALTERED_SEARCH_PATH` and
   `SEARCH_DEFAULT_DIRS` alike — WindowsApps ACLs — so `regsvr32` exits 3 and writes nothing, which
   shows up only in the registry and not in the exit code. Copy the DLL to an ordinary directory
   and register it there; its imports are `ADVAPI32`, `KERNEL32`, `OLEAUT32`, `SHLWAPI`, `USER32`,
   `WS2_32`, `XmlLite` and `ole32`, all system DLLs, so it travels alone. `kd.exe` runs from
   WindowsApps unchanged, so only the DLL needs moving.
2. Point the engine at **your own copy** of the config rather than editing the package's, with the
   `PathToSrvCfgFiles` connection option or the `EXDI_GDBSRV_XML_CONFIG_FILE` environment variable
   (both read out of `dbgeng.dll`). Add an `<ExdiTarget Name="WindbgMcp">` entry and set
   `CurrentTarget` to it. Start from the `QEMU` entry: it already carries a 66-entry **X64**
   register block, and all seven of its memory-command flags are `no`, meaning plain `m`/`M` with
   virtual addresses and no special-memory path. That is the smallest contract to serve.

   **Copy the `QEMU` entry's X64 block rather than the `VMWare` entry's, unless you check which
   `exdiConfigData.xml` you are reading.** The package ships two that differ, and the `winext\` one
   — which this repo bundles — has `VMWare` as `X86` with no X64 register block at all, where the
   copy beside the debugger binaries has it as `X64`. `QEMU` is identical in both. Measured
   2026-09-24 and tabulated in
   [the validation record](secure-kernel-debugging-validation.md#exdi-transport-experiments-and-the-host-reset-2026-09-23).

   **Those two ways of naming the config are not interchangeable once the server is
   surrogate-hosted, and this step used to present them as equivalent.**
   `EXDI_GDBSRV_XML_CONFIG_FILE` is read from the *server's* environment; a surrogate is spawned by
   RPCSS rather than by the debugger, so it inherits that service's environment and never sees a
   variable set for `kd`. `PathToSrvCfgFiles` travels inside the connection string, across the COM
   boundary, and is the one that can reach an out-of-process server. Measured 2026-09-25 with the
   variable set for `kd` and a private config naming a listener on loopback: nothing connected.
3. Boot an ordinary Windows guest under QEMU with its gdbstub on `1234`, and attach with the
   documented form: `-kx exdi:CLSID={29f9906e-…},Kd=Guess,DataBreaks=Exdi` — no `Inproc`.
4. **Bound the debugger so a spin cannot take the host.** Run `kd` in a job object that can be
   terminated, not merely as a child with a `WaitForExit` timeout: the 2026-09-22 attempt had a
   60-second kill on it and the kill did not save the machine. And make the far end answer
   *unmapped* reads with an RSP error rather than zeroes, so a scan terminates on its own.

   **The job object does not contain the EXDI server, which is the gap this step was written to
   close.** Measured 2026-09-25 over two runs: `kd` was created suspended, assigned to a job
   carrying `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, then resumed — and the `dllhost.exe` holding the
   EXDI server had **svchost (RPCSS) as its parent**, so it was never in the job. Both runs left a
   surrogate running after the job was terminated and its handle closed, and each had to be swept
   afterwards by matching `DllHost.exe` command lines against the `/Processid:` of that `AppID`.
   So a harness needs the job **and** that sweep. Whether the September host reset involved a
   surrogate is not established: nothing was registered then, so that attempt had none to leave
   behind, and the two failures are not being claimed as one.

**Pass:** `lm` lists `nt`, `!process 0 0` returns, a breakpoint on a kernel routine hits, and
resume works. **Control:** the same guest debugged over ordinary KDNET, to show the guest and
symbols are not the variable.

#### E0 splits in two, and the first half needs no guest

Only the pass criteria above need a kernel. Whether the rig *connects and negotiates* —
registration, config parsing, the RSP handshake, the register contract — can be answered against a
bare TCP listener, which is worth doing first because it is the half that has twice ended in a hang
rather than an error.

Run 2026-09-25 on this bench, against a minimal RSP responder on loopback, `Kd=Guess`, no `Inproc`,
`kd` bounded in a job object. **The transport half did not pass.** Two runs, 75 s and 60 s: the
responder logged **no connection at all**, and the surrogate, where one appeared, held **no
socket** — so the stall is before anything is dialled, not in the exchange. Activation alone
reproduces it without `kd` in the picture: a bare `CreateInstance` on the CLSID blocked for more
than 17 s having launched **no surrogate at all**, with no DCOM `10010` in the System log inside
that window. An earlier reading of this as a hung `CoCreateInstance` rested on a test that also
called `Get-Member`, which can block on COM type info by itself; the call was then timed in
isolation, and it does block, but the first evidence for it did not show that.

What the run *did* establish, beyond the registration and ACL facts in step 1: the register block
this gate depends on is **66 entries, 608 bytes, 1216 hex characters for a `g` reply** — `Size` is
decimal and `Order` is hex in that file, so a reader treating both as one radix gets 752 or 776
bytes instead. That figure matches the validation record's independently.

**The untried step is deliberate.** Removing the `AppID` from the CLSID key would drop the
surrogate and load the server in-process, which is materially what `Inproc=` arranges — and step 1
records a host reset pointing at exactly that. It needs a window where losing the host is
affordable, not a slot in a sequence of experiments.

### E1 — how DbgEng locates the kernel over EXDI — answered 2026-09-22

Read offline out of `dbgeng.dll` **10.0.29617.1000** (`target\release\dbgeng.dll`, the engine this
repo bundles). **No PDB is served for this build**, so functions are unnamed and the reading is
from string cross-references, structure and imports rather than from symbols.

The connection string's `Kd=` value selects one of **six** kernel-discovery modes, not one. The
parser is a single function spanning image RVA `0x2FC810`–`0x2FCB46`; each option is a string
compare followed by a mode number stored at `ctx+0x20`:

| `Kd=` value | Mode | Compared with | Carries an address |
|---|---|---|---|
| `Ioctl` | 1 | `_wcsicmp` | no |
| `GsPcr` | 2 | `_wcsicmp` | no |
| **`VerAddr:<addr>`** | **3** | `_wcsnicmp`, length 8 | **yes** — `%I64i` into `ctx+0x28` |
| `Guess` | 4 | `_wcsicmp` | no |
| `NTBaseAddr` | 5 | `_wcsicmp` | no |
| `HwDbgBlock` | 6 | `_wcsicmp` | no; also sets `ctx+0x44` |

A malformed address returns `0x80070057` (`E_INVALIDARG`) and the conversion is checked for exactly
one field, so `VerAddr:` is **parsed rather than merely recognised**. All six have matching
telemetry names in the image: `IoctlSession`, `GsPcrSession`, `VerAddrSession`,
`GuessSessionSucceeded`/`Failed`, `NtBaseSessionSucceeded`/`Failed`, `HwDbgBlockSessionFailed`.
The remaining option keywords, from the same `.rdata` run: `CLSID`, `DataBreaks`, `Desc`, `EBC`,
`Exdi`, `ForceX86`, `Args`, `Linux`, `Inproc`, `PathToSrvCfgFiles`.

**And DbgEng carries an `sk` record — whose reachability is the next subsection's subject, and is
not established.** A table of 40-byte records in `.data` at RVA `0xA1F718`, referenced from three
code sites, maps an EXDI memory space to a kernel module and the symbol its version block is
found by:

| Index | Tag | Memory space | Module | Version-block symbol |
|---|---|---|---|---|
| 0 | `0x8673` | User Mode | `nt` | `nt!KdVersionBlock` |
| 1 | `0x8673` | Supervisor-Kernel | `nt` | `nt!KdVersionBlock` |
| 2 | `0x8674` | Hypervisor | `hv` | `hv!KdVersionBlock` |
| 2 | `0x8673` | Hypervisor | **`sk`** | **`sk!KdVersionBlock`** |
| 3 | `0x8676` | Unknown Memory Space | — | — |

Those memory-space names are the ones `exdiConfigData.xml` gates with `SupervisorMemory` and
`HypervisorMemory`. DbgEng's kernel-image name list carries **`securekernel.exe` and
`securekernella57.exe`** beside `hvix64.exe`, `hvax64.exe` and `ntkrnlmp.exe`.

**Verdict on the option: `Kd=VerAddr:<addr>` is solid.** It is parsed, range-checked and stored,
and it is the lever that lets a caller name the version block instead of letting the engine hunt
for NT's.

**Verdict on the `sk` record: much weaker than it first looked, and it does not reach a KD
session.** Followed up 2026-09-23 by mapping `.pdata` and classifying every function that touches
the table:

| Question | Measurement |
|---|---|
| Who reaches the three table readers? | Only functions that also reference **EXDI** strings (`0x3042F4`, `0x305900`, `0x42EE70`) |
| Any KD-transport caller? | **None.** 0 of the 91 KD-transport strings appear in any function touching the table |
| The `hv`-vs-`sk` selector at `0x42EDE0` | **No direct callers, and its address is never taken** |

So **a hypervisor KD session cannot be steered to `sk` by this machinery** — the path is
EXDI-gated, and the one function that distinguishes the `sk` record from the `hv` record is
unreferenced in this build. The record is real; its reachability is not established, and may be
vestigial. Treat "DbgEng ships a Secure Kernel bootstrap" as *a table entry exists*, not as
*a working path*.

**One string is a red herring, recorded so it is not re-read as evidence.** The `securekernel`
occurrence at RVA `0x814178` is the only one with a code reference, and it sits in a
*partially-mapped-image diagnostic* (`"a partially mapped image"`, `"DBGENG: %s - Mapped image
memor…"`), not a bootstrap. The `securekernel.exe` and `securekernella57.exe` names at
`0x813E60`/`0x813EC0` have no code reference at all — they live in a name table.

Caveats on the negative: absence of a direct caller is not proof of dead code (a computed jump
table would not show in this scan), and this is one engine build. But it is enough to stop
planning around the `sk` record as a shortcut.

### E2 — point it at `securekernel` (the pivotal gate)

**The question is whether DbgEng can be driven against SK at all, and building a stub is one way to
ask it rather than the only one.** E0's transport half has not passed, the gdbstub-backed rig needs
hardware that does not exist here yet, and LiveCloudKd reports reaching VTL1 through EXDI today
with no gdbstub involved. So E2 is ordered **oracle first, stub second**: use LiveCloudKd to find
out whether the answer is yes, and keep the stub work for a backend that could ship, which is E3's
subject. A no from the oracle is worth far more than a slow yes, because it would say the engine
cannot be steered at SK by any EXDI route and would retire the stub programme rather than sequence
it.

- **E2a, the oracle.** LiveCloudKd's passive CLSID against a VBS guest, with the debugger on that
  guest's Hyper-V host. **Pass:** SK symbols resolve against live memory and SK structures can be
  walked. **Control:** the same reads against a VBS-off guest must *not* find an SK data block.
  This answers the gate's question and settles nothing about a shippable backend.
- **E2b, the stub path below**, unchanged, and now what it is for is a backend rather than an
  answer.

**Check EXDI activation before either.** Both routes are the same dbgeng plumbing, and E0 found
activation stalling on this bench — registration writes an `AppID` with an empty `DllSurrogate`,
hosting the server in `dllhost.exe`, and a bare `CreateInstance` blocked past 17 s having launched
no surrogate. Whether `ExdiKdSample.dll` registers the same way is not established and is cheap to
read off its registration; if it does, that stall is a prerequisite for both and is better found
before a lab is built around either.

Same rig, VBS/HVCI enabled in the guest.

- **Assumption under test:** that SK's pages are readable through QEMU's gdbstub, because QEMU sees
  guest-physical memory beneath the nested hypervisor's SLAT. This is the reason to run the
  experiment, not a result.
- **First try the built-in path.** E1 found `sk!KdVersionBlock` in DbgEng's memory-space table
  under the *Hypervisor* space, so the `SupervisorMemory`/`HypervisorMemory` flags in the
  `<ExdiTarget>` entry are the lever to exercise first — they are what selects that space.
- **Then the explicit one.** `Kd=VerAddr:<address>` takes an arbitrary `KdVersionBlock` address
  (E1, mode 3). Locate SK's block in guest memory and hand it over directly. This is the path that
  does not depend on guessing which memory space the stub advertises.
- **The fallback is still worth running if both miss**: attach with `Kd=Guess` so DbgEng binds to
  `nt`, then `.reload /f securekernel.exe=<base>` and read SK's data block through ordinary memory
  reads.

**Pass:** SK symbols resolve against live memory and SK structures can be walked. **Partial pass
is the likely outcome and is not a failure** — the fallback yields read-only SK inspection while
losing DbgEng's native kernel awareness for SK (thread and process context, the `!` extensions
that assume NT). **Control:** the same reads against a VBS-off guest must *not* find an SK data
block, or the read is measuring something else.

### E3 — the Hyper-V stub

Entered only if E2 established that DbgEng can be driven against SK. Until then, **no stub is
needed at all**: QEMU already is one, which is what makes E0–E2 cheap.

The stub's own work splits in two, and the first half is worth shipping alone:

- **Read-only first.** Serve registers and memory for a stopped VTL1 context. That is enough for
  module lists, structure walks, disassembly and symbol resolution — most of what the original
  question was about.
- **Execution control second.** Breakpoints, stepping, resume. This is where the difficulty is,
  and the plan's acceptance criteria require it for "success" rather than "access".

**VTL selection: one stub instance serves one VTL, chosen at startup, one TCP port each.** Two
sessions rather than one multiplexed target. That mirrors the NT-plus-hypervisor pattern this
bench already runs, and it avoids mapping VTLs onto RSP "cores", which DbgEng reads as processors.

Backend candidates, cheapest first, each with its unknown named:

| Candidate | Why it is a candidate | What is unknown |
|---|---|---|
| Drive the working hvix64 KD session | Hypervisor KD attach already passes here, and gives machine-wide memory | KD is a debugger protocol, not an API; the pointer chains are pinned to a hypervisor build and move with it |
| `vid.sys` / worker-process interfaces | The route LiveCloudKd demonstrates is viable | Undocumented; a large reverse-engineering effort; the technique is available even though the dependency is excluded |
| Windows Hypervisor Platform | Documented and supported | Aimed at partitions the caller creates, so applicability to an existing VM's VTL1 is doubtful and should be checked before it is costed |

Whatever supplies VTL-qualified register state needs privileged access to the target's partition.
**That requirement does not go away in any of the three**, and it is the reason a custom hypervisor
would not be a shortcut: it would add nested virtualization, address translation and processor
coordination on top of the same problem.

### E4 — windbg-mcp integration

Only once a gate has actually passed. The [existing integration
sketch](secure-kernel-debugging-plan.md) still stands; these are the concrete edits.

- **dbgscope.** A sibling of `attach_kernel_begin` (`src/dbgeng.rs:4174`), identical in shape,
  passing `DEBUG_ATTACH_EXDI_DRIVER` instead of `DEBUG_ATTACH_KERNEL_CONNECTION`. The constant is
  reachable with the features dbgscope already enables — `windows` 0.62.2,
  `Win32_System_Diagnostics_Debug_Extensions`, value `2`. House rule applies: a typed method
  returning `Result<_, DbgEngError>`, never the `execute` text hatch.
- **`EngineOp::AttachKernel`** gains a `transport` field rather than a new variant, `#[serde(default)]`
  so the wire stays compatible. `experimental_break_on_connect` is precedent that a field is the
  shape here, and `target_origin`'s `AttachKernel { .. }` arm keeps matching.
- **`Endpoint` gains an EXDI variant, and this is required rather than cosmetic.**
  `Endpoint::conflicts` (`src/kdconn.rs:99`) treats `Unknown` as conflicting with everything, and
  `Sessions::admit` (`src/engine.rs:3200`) *refuses* the open on a conflict. An EXDI connection
  string is not `net:`, so it lands on `Unknown` and would be refused alongside any live kernel
  session — and would block every later one. The identity to key on is **the stub's host and
  port**, which is the thing two EXDI sessions actually differ by; the CLSID is shared by all of
  them and cannot separate them.
- **Redaction.** An EXDI connection string carries no `key` or `password`, so it renders verbatim,
  which is correct. It must still travel as a `Connection` — one type, one `expose()` call site.
  Worth a test that it round-trips unredacted *and* that a `password=` added to it is masked, so
  the exemption is the string's content rather than its transport.
- **Tool surface.** `attach_kernel` gains the argument; read
  [`.claude/rules/tool-surface.md`](../.claude/rules/tool-surface.md) first — the group in
  `src/toolset.rs` is the half that fails silently, and any prose naming another tool belongs in
  `TOOL_NOTES`, not in a doc comment.
- **Capability matrix.** The deliverable the Secure Kernel plan already names, and EXDI is what
  makes it urgent: an SK target has no `nt`, no NT-shaped `PsLoadedModuleList` and no `EPROCESS`
  list, so `crash_triage`, `driver_object`, `device_object` and the pool tools will either fail or
  answer for something else. **Which of those two it is has to be measured per tool**, because a
  tool that answers wrongly is worse than one that refuses.
- **Test tier.** A new opt-in gate, per [`.claude/skills/tiers/SKILL.md`](../.claude/skills/tiers/SKILL.md),
  keyed on an env var naming a reachable stub.

## Stop conditions

Write these down before starting, so a sunk cost does not decide:

- **E0 fails** — EXDI does not work against a known-good gdbstub on this rig. Then the problem is
  the rig or the registration, and nothing about SK has been learned.
- **E2 finds SK pages unreadable** through the gdbstub. Then the nested-SLAT assumption is wrong,
  and the QEMU shortcut is gone; E3's cost rises to "the whole thing" and should be re-decided
  rather than continued into.
- **E2 cannot be reached on the host available**, which is a different stop from the one above and
  was the one that actually fired — see [where each component runs](#where-each-component-runs).
  A host whose hypervisor slot is already taken can leave no backend that both exposes a gdbstub
  and can host a VBS guest, so the nested-SLAT assumption never gets tested and nothing has been
  learned about SK. The answer is a second host rather than a redesign, and E0 and E1 do not wait
  for it: they need only a plain NT guest behind a gdbstub, which such a host can still provide.
- **E1 finds no forcing option and the E2 fallback also fails.** Then DbgEng cannot be driven
  against a non-NT kernel by configuration, and the remaining route is a debugger that is not
  DbgEng — which is outside this milestone and outside this server.

## Deliverables

- The `<ExdiTarget>` entry, version-pinned, as a file rather than as prose.
- A runbook in the shape of [`.claude/skills/live-kernel/SKILL.md`](../.claude/skills/live-kernel/SKILL.md),
  written from a cold bench rather than a warm one.
- The capability matrix above, measured.
- A redacted transcript, recorded with `WINDBG_MCP_TRANSCRIPT` and rendered with `--render-cast`.
- Whatever of the stub E3 reaches, with its backend named and its VTL selection explicit.
