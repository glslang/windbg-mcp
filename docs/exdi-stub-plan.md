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
2. Point the engine at **your own copy** of the config rather than editing the package's, with the
   `PathToSrvCfgFiles` connection option or the `EXDI_GDBSRV_XML_CONFIG_FILE` environment variable
   (both read out of `dbgeng.dll`). Add an `<ExdiTarget Name="WindbgMcp">` entry and set
   `CurrentTarget` to it. Start from the `QEMU` entry: it already carries a 66-entry **X64**
   register block, and all seven of its memory-command flags are `no`, meaning plain `m`/`M` with
   virtual addresses and no special-memory path. That is the smallest contract to serve.
3. Boot an ordinary Windows guest under QEMU with its gdbstub on `1234`, and attach with the
   documented form: `-kx exdi:CLSID={29f9906e-…},Kd=Guess,DataBreaks=Exdi` — no `Inproc`.
4. **Bound the debugger so a spin cannot take the host.** Run `kd` in a job object that can be
   terminated, not merely as a child with a `WaitForExit` timeout: the 2026-09-22 attempt had a
   60-second kill on it and the kill did not save the machine. And make the far end answer
   *unmapped* reads with an RSP error rather than zeroes, so a scan terminates on its own.

**Pass:** `lm` lists `nt`, `!process 0 0` returns, a breakpoint on a kernel routine hits, and
resume works. **Control:** the same guest debugged over ordinary KDNET, to show the guest and
symbols are not the variable.

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
