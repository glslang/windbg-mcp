# Secure Kernel research

Can a debugger reach **VTL1** — the Secure Kernel — on a VBS-enabled Windows guest, and can
`windbg-mcp` drive it? These documents are the record of finding out. They are a **research log**
first, and several sections record what did not work and why, which is most of the value.

**Part of it is now code in this server**, and the rest is not. `src/sk.rs` decodes a guest's
VTL1 — the page-table walk, the image identification, the debugger data block and the module list —
over a source seam, `src/savedstate.rs` reads a Hyper-V capture through the Windows SDK's provider,
`src/sksym.rs` resolves `securekernel.exe`'s symbols against that decode with no debuggee at all,
and `windbg-mcp --sk-inspect` drives them from the command line (`FOLLOWUPS.md` item 103, gates S1
and S2).

**And since gate S3 there are four MCP tools** (`open_sk_capture`, `sk_modules`, `sk_read_memory`,
`sk_symbol`, the `--tools securekernel` group): a capture opens as a **session of its own** whose
worker holds the file rather than a debuggee, and the debugger tools are refused on it because the
engine beside it has at most `securekernel.exe` open for symbols —
[`docs/sessions.md`](../sessions.md#secure-kernel-captures) is the caller's half. What that reaches
is a **capture**: its session reads a file, and a file does not execute. The separate live-control
session below drives a running guest through operator-supplied providers.

**A live decode source exists since gate S5w, as a command-line role rather than a tool.**
`src/livesrc.rs` implements the same [`sk::RawSource`] seam over a transport the **operator**
supplies — a child process speaking a line protocol on its stdio — and
`windbg-mcp --sk-live --transport "<command>" --image <path>` runs gate S1's whole decode through
it. This repository ships **no transport**: reading another partition's VTL1 live needs a kernel
component it will not distribute, which is the same arrangement as the live-kernel tier's KDNET
wiring. It is not a fifth tool on purpose — gate S5x measured a page of `securekernel.exe`'s
`.data` changing inside twenty seconds, so a live source cannot keep the promise a capture
session's decode-on-open makes.

**The live execution-control contract now exists too.** `src/skcontrol.rs` is a versioned JSON-line
client for an operator-supplied provider. Exact VM/partition/VP/VTL/CR3 identity and an opaque epoch
travel on every request; reads and compare-and-write register updates are refused while running;
and the debugger-owned process publishes the exact held dispatcher event without giving the
provider a VID receive loop. `--sk-control-probe` validates the non-mutating handshake. The contract
and its state machine are documented in
[`live-control-provider.md`](live-control-provider.md). Seven MCP tools open and drive that
dedicated worker session: `open_sk_live_control`, `sk_live_arm`, `sk_live_wait`,
`sk_live_registers`, `sk_live_read_memory`, `sk_live_step` and `sk_live_continue`.

**And since 0.22.0 an installed WinDbg can sit in front of that controller.**
`open_sk_kd` owns the controller as an MCP session, returns a generated local named pipe, and
serves the serial KD packet stream to WinDbg while MCP retains lifecycle and recovery. The
standalone `windbg-mcp --sk-kd-target` role remains for compatibility and diagnostics. The facade
translates the requests it understands — context, virtual reads, hardware breakpoints, a
fall-through single step, continue to a breakpoint, quit — into the same guarded operations the
seven tools make ([#463](https://github.com/glslang/windbg-mcp/pull/463)). It is a facade for the
debugger over the root-driven controller, not a KD transport inside the guest: Secure Kernel still
ships none, which is gate S5a below. What it can do, what WinDbg is told that the guest never held,
and the one live run it rests on are in [`kd-facade.md`](kd-facade.md).

## The answer so far

**Yes, from the root partition of the hypervisor that runs the guest — and it takes two primitives
with different permission models, not one.**

```text
HvCallGetVpRegisters(TargetVtl=1)   ->  VTL1 CR3            (documented, parent-callable)
   that GPA holds Secure Kernel's PML4
   walk SK's page tables              <-  NOT via HvCallReadGpa, which refuses these pages
   -> securekernel.exe, its module list, its debugger data block
```

The hypervisor **grants** a parent partition a child's VTL1 *registers* and **refuses** it that
child's VTL1 *memory* through `HvCallReadGpa`. The refusal is real and measured — 4608 protected
pages against **0** in a VBS-off control — but it belongs to that one hypercall, which has no VTL
parameter to ask with. A memory route that is not that hypercall reads the same pages. So the
hypervisor guards one door and hands over the key to the building through another.

**And a third route needs no door at all.** A **Hyper-V saved state** — an ordinary standard
checkpoint, written by the host — carries the guest's VTL1 pages *and* its VTL1 `CR3`, readable
through Microsoft's own `vmsavedstatedumpprovider.dll` from the Windows SDK. No driver, no
test-signing, no hypercall, and the file can be copied off the host and read anywhere. Every
**capture-derived** landmark below reproduces from one — which is all of them except the
withheld-pages row, marked *live route*: that one is a measurement **of** `HvCallReadGpa`, and a
capture involves no hypercall to refuse anything. That decides *who* can do this work rather
than whether it can be done, since the live driver route remains the only way to read a guest
**as it runs**.

Measured on the bench, 2026-09-26. The **Repeated** column is not decoration, and it is where this
table was wrong once: a landmark seen twice is not thereby stable.

| landmark | value | repeated across a reboot |
|---|---|---|
| VTL1 `CR3` (guest physical) | `0x1201000` | **no** — identical on two boots, `0x107593000` on a third |
| pages the hypercall withholds *(live route only)* | 18 MiB in 7 runs, every run 2 MiB-aligned | **yes** — same runs, same 4608 pages, control still 0 |
| `securekernel.exe` GPA | `0x00CD0000` | **yes** — two boots |
| `securekernel.exe` base VA | `0xFFFFF80220D89000` | **no** — `0xFFFFF8070EDA9000` on another boot |
| `KdDebuggerDataBlock` | `securekernel.exe` **+0x1335E0**, `Size` = `0x3A0` | **yes** — two boots |
| `SkLoadedModuleList` | `securekernel.exe` **+0x127770** | **yes** — two boots |
| VTL1 modules | `securekernel.exe`, `skci.dll`, `symcryptk.dll`, `cng.sys`, `vmsvc.dll`, `vmsvcext.sys` | **yes** — same six, same sizes |

The two image-relative **offsets** are properties of the build rather than of the boot, so they are
the coordinates to carry forward; the VAs beside them depend on the load base, and **the `CR3` has
to be read, never remembered** — the third boot above is what a hard-coded `0x1201000` would have
walked from.

That the offsets are the build's is now checkable rather than inferred: gate S2 reads both out of
this build's `securekernel.pdb` and gets `+0x1335E0` and `+0x127770`, the same two values searching
the capture produced. The PDB is therefore where a *different* build's offsets come from — but only
where one is served, which is why the tag scan stays the primary route and not the fallback.

**The capture path and minimum live execution session are complete.** Item 103's **S0** is
answered above and **S1**, the decode layer, is now in
`src/sk.rs` and reproduces every capture-derived landmark in the table below from a checkpoint, with
two checks the probe did not run: a structural route to the module list that agrees with the block,
and the provider's own address translator agreeing with the walk on every page of the image.
**S2**, symbols, is now `src/sksym.rs`: DbgEng opens `securekernel.exe` as a target in its own right
with no debuggee, and the PDB puts both offsets in the table below exactly where searching the
capture put them — a third route to the module list, and the only one that needs no debugger data
block. It also settles what symbols *cannot* give: the public `securekernel.pdb` carries **no type
information**, so structure walks stay hand-decoded. **S3**, the tool surface, is now four tools in
the `securekernel` group: a capture is a session whose worker holds a file, the decode travels with
the open, and the debugger tools are refused on it — the three questions that gate was deferred to
answer (where the engine lives, one handle or two, and what a structure walk means with no types) are
answered in `src/sksession.rs` and in `FOLLOWUPS.md`. VTL1 kernel execution can now be controlled
in a disposable owner partition: the guarded probe holds and completes its selected CPL0 `#BP`.
Private VBS and VBS-off disk clones also pass the managed preflight three times
with one VP, fixed 4 GiB RAM, Secure Boot and TPM off; saved-state reads prove
the positive clone has an initialized Secure Kernel and the control has no VTL1.
The first owned-boot gate also passes: all six minimum inbox devices initialize and tear down in
isolated children outside `vmwp`; five do so against fresh direct-VID partitions. That originally
left firmware, storage, and Windows/VBS boot before the stop could be reproduced. The next
composition gate passed too: the six devices share one partition and real
VMBus/BIOS/IOAPIC interfaces for three runs, including the exact fixed 4 GiB Windows RAM topology,
the recovered start/finish/free resource lifecycle, the RAM-complete query loop, and reverse
teardown. The direct owner-built boot was then retired when the narrower managed-Windows route
passed. A normal Hyper-V VBS boot now reaches its initialized Secure Kernel through the existing
`vmwp` dispatcher: one run held and released the image's published `DbgBreakPointWithStatus`, and a
second used DR0/DR7 to stop before a selected five-byte instruction, set TF, held the next vector-1
event at the decoded successor, restored the original state, completed both events through the
native dispatcher, removed the handler after deferred cleanup, and survived for more than 60
seconds. Secure Kernel text was unchanged. The remaining work is repeatable automation, not
another boot path.
Driving a live Secure Kernel target through
**DbgEng/EXDI is parked**, for two independent reasons: EXDI activation does not work on this bench
and is unresolved, and — measured separately — DbgEng's Secure Kernel record is unreachable, so even
a working EXDI would supply a generic memory target rather than any SK awareness. Since the reads
now exist, that is a trade with nothing on one side. What it costs is DbgEng's symbol handling —
and S2 has since measured how much of that comes back against the *image* without a live target:
the **names** completely, the **types** not at all.

**Is a checkpoint carrying Secure Kernel a defect to report?** Asked and answered **no**, 2026-09-27,
with the evidence in gate 4's document: the SDK documents VTL selection in a capture as a feature
(`ForceActiveVirtualTrustLevel` is commented *"useful to force register state … from a different
VTL"*), VBS claims a VTL0→VTL1 boundary *inside* the guest rather than one against the host, and
every route here needs Hyper-V Administrator, which can already read a running guest's memory. The
three cases that *would* be reportable are named there. The interesting one has since been
**measured** (S0 arm 4, 2026-09-27) and came back negative: turn
`EncryptStateAndVmMigrationTraffic` on and no VTL1 comes out, because the provider cannot load the
capture at all — so the mitigation holds. That arm did surface a **different** defect, and it is the
one to raise with Microsoft: the SDK's provider **fast-fails** (`0xC0000409`) on an encrypted capture
that Hyper-V itself wrote, rather than refusing it, which is a robustness bug and not a boundary
bypass. It is written up as a report in
[`vmsavedstatedumpprovider-crash.md`](vmsavedstatedumpprovider-crash.md), with a twelve-line repro,
the control matrix that makes the trigger specific — corrupt, truncated and random input are all
refused cleanly with `ERROR_FILE_CORRUPT` — and the container-header and entropy readings that show
the input is a well-formed file with an encrypted payload. The remaining case needs no Microsoft involvement and is true today: these `.vmrs` files
inherit `D:\`'s ACL, so any authenticated local user can read a guest's whole RAM.

**The initialized-Secure-Kernel control question is now answered on the guarded bench build.** The
owner-partition probe first supplied VTL1 kernel privilege; the managed-Windows run then reproduced a
resumable stop in the normally initialized guest Secure Kernel, and the vector-1 run added a hardware
execution breakpoint plus one architectural step. The earlier question about the unused VTL1 debug
port remains useful because it explains why this route is root-driven rather than a native KD link.
**Those were the same wall**, measured 2026-09-27 as gate S5a:
Secure Kernel has no hypercall or MSR route to that port. Across ten builds from 19041.207 to
29667.1000 it never writes the three debug hypercall codes at any instruction boundary the scan
recognises — every occurrence at one is a `cmp` — it never materialises a synthetic-debugger MSR
number at all, and it contains no `vmcall` instruction of its own. Its enumerated hypercall repertoire (19–38 codes per build)
holds none of them either, and that reading is a lower bound serving as the negative control rather
than the verdict.
The control is Windows' own KD-over-hypervisor transport, `kdhvcom.dll`, which is nothing but those
three hypercalls behind the five-function KD export contract. So the hypervisor's VTL1 debug port is
a receiver with no sender, and what remains for S5 is the one route that needs no guest-side code:
a stop driven entirely from the hypervisor or the root. And whether VTL1 can be *written* is settled
per route — `HvCallWriteGpa` refuses it symmetrically with the read, the direct driver route accepts
it — so the patch half of a software breakpoint exists and the catch half has now been shown to have
no Secure Kernel-side transport to arrive on.

## The documents

Read them in this order; each assumes the one before it.

| # | Document | What it covers |
|---|---|---|
| 1 | [Secure Kernel debugging plan](secure-kernel-debugging-plan.md) | The original plan: validate software-only SK debugging, then integrate whichever route works. Carries the handoff status and the `Kd=` option set read out of `dbgeng.dll` — six kernel-discovery modes, of which `Kd=VerAddr:<addr>` is the one a Secure Kernel bind would use. |
| 2 | [Secure Kernel debugging validation](secure-kernel-debugging-validation.md) | The measurement record behind everything else. NT and hypervisor debugging pass; **native SK attachment does not**. Why post-26100 `securekernel.exe` ships no KD transport, and what `SkdInitDebuggerDataBlock` does instead. The longest document here and the one to cite. |
| 3 | [EXDI stub plan](exdi-stub-plan.md) | Expands Phase 4 of (1). What an EXDI stub would have to be, where each component runs, why the EXDI server is surrogate-hosted, and the analysis of LiveCloudKd as an existing implementation — including its GPL-3.0 licence and its revoked-certificate driver. |
| 4 | [Hypercall feasibility](secure-kernel-hypercall-feasibility.md) | **The main result.** A falsifiable gate-by-gate plan — H0 to H5 — for reading a guest's VTL1 from the root, each gate with a pass condition, a control and a stop condition written before the work. H0 to H4 pass. H2 passes on its **second** mechanism — its cheap driver-free probe failed, and the Code Integrity policy that blocked it is not the one it looks like. H5's route is decided — **H5b**, exposing the reads directly, because driving DbgEng through EXDI is blocked *and* would add no Secure Kernel awareness — and the record carries the H5b gates run so far: **S4**, which settles writes per route, **S0**, which finds a driver-free source that carries VTL1 and its page-table root, **S1**, the decode layer over that source, **S2**, symbols against the image with no debuggee — which also settles that the public PDB has no types — and **S5a**, which joins the hypervisor's live-but-unused VTL1 debug port to Secure Kernel shipping no KD transport, and finds them to be the same wall. |
| 5 | [VTL1 control probe runbook](vtl1-control-probe.md) | The build-locked native probe, live procedure, private ABI derivation, safety boundary, successful high-integrity result, and guarded Secure Kernel image breakpoint/return mode. |
| 6 | [Live VTL1 control provider](live-control-provider.md) | The repository-owned provider protocol: exact target identity, running/arming/stopped epochs, guarded register access, held-event identity, capability probe, and the boundary that keeps VID receipt in the managed `vmwp` debugger process. |
| 7 | [Inbox device initialization probe](vdev-initialization-probe.md) | K1.1's guarded six-device contract and live result: guest emulation, BIOS, RTC, IOAPIC, VMBus, and SynthStor independently initialize and tear down outside `vmwp`; the build-bound JSON records every dependency and minimum configuration. |
| 8 | [Inbox device graph probe](vdev-graph-probe.md) | K1.2's result: the six devices share one owned partition and the measured two-span 4 GiB Windows RAM map for three clean initialization, RAM-complete, reverse-teardown, memory-destruction, and partition-deletion cycles. Firmware and VP start remain open. |
| 9 | [Diskless inbox firmware preflight](vdev-firmware-probe.md) | K1.3's result: the inbox BIOS builds five exact-readback UEFI memory regions and 19 VP0 state records, five diskless devices cold-power successfully, and the state applies cleanly in three fresh partitions. The boot-memory callback uses byte ranges; a private execution check reaches DXE. VP0 remains outside the tracked acceptance run; storage and the owner-side completion dispatcher remain open. |
| 10 | [The Secure Kernel KD facade](kd-facade.md) | `open_sk_kd`: a server-managed, authenticated local WinDbg session over the live controller. The measured managed gate covers validated live debugger metadata, `lm m securekernel`, `t`, `r`, `q`, MCP release and an independent 60-second audit; four hardware breakpoints, symbol loading, stack walking, asynchronous break-in and writes remain bounded as the page describes. |

Two older side-investigations, kept because they are about the same binary:

| Document | What it covers |
|---|---|
| [Securekernel ARM64 export follow-up](securekernel-export-followup.md) | Why eight matches went unresolved in an ARM64 `securekernel.exe` comparison — undecoded instructions in Binary Ninja, not missing inputs or failed matching. |
| [Read-only Secure Kernel handoff](securekernel-handoff-acceptance.md) | The handoff probe and its refusal/preservation tests. Live acceptance is **not run**; the record says so rather than implying coverage. |
| [`vmsavedstatedumpprovider.dll` fast-fails on an encrypted saved state](vmsavedstatedumpprovider-crash.md) | A defect in a Microsoft SDK component, found by gate S0 arm 4 and written as a report that can be sent as it stands: a twelve-line repro, the control matrix that makes the trigger specific, what the OS records, and what was deliberately not tested. Not a VBS boundary bypass — that question is answered in document 4. |

Supporting captures live in
[`docs/samples/secure-kernel-debugger-investigation/`](../samples/secure-kernel-debugger-investigation/README.md),
including the secure-call dispatch trace the EXDI reassessment rests on.

## How to read the H0–H5 record

Gate 4's document is written in the order the work happened, **including the parts that were
wrong**, because how a negative was overturned is as much the result as the pass is. H4 in
particular reads: a clean negative, then its narrowing by an independent oracle, then a correction
about the sampling window, then the pass. Section headings say which is which. Do not quote an
early H4 heading as the conclusion.

Three methodological findings there generalise beyond this topic, and each cost a run:

- **A zeroed output buffer cannot tell data from silence.** Poison it (`0xAA`) and use a
  deliberately invalid call as the control, or "the target returned zeros" and "nothing was written"
  are the same observation.
- **`HvCallReadGpa` moves at most 16 bytes**, so a naive probe judges every 4096-byte page on its
  first sixteen. Secure Kernel's PML4 reads as all-zero that way, and it is not.
- **Page tables are cyclic.** Windows paging roots self-map, so an unguarded four-level walk
  re-enters itself 512× per level. Guard it or exhaust the machine.

## The lab, and the bench posture it needs

Two Hyper-V guests on one host, differing in **one** variable — one with VBS on, one with it off —
so that every VTL1 claim has a control. The control is what makes the numbers mean anything:
`ReadIntercept` appears 4608 times in the VBS guest and **zero** times in the other, across the same
fixed grid.

**It also guards a failure that would invalidate everything else, and that is not obvious:** the
*host* runs VBS too, so the root partition has its own Secure Kernel in memory. A read path landing
in host memory would find `securekernel.exe` and confirm it against the on-disk image just as
happily. Running the identical scan in both guests settles it — 1 SK image and 1 `KDBG` block in the
VBS guest, **0 and 0** in the VBS-off one, which yields *more* PE headers overall (152 against 112)
and so is not simply failing to read.

Reproducing the **live** route from gate 3 onward needs a bench that is **deliberately
weakened**, and the instruments live outside this repository on purpose:

- **Test-signing on, Secure Boot off, HVCI off.** A driver that reads another partition's memory is
  not something Microsoft will sign.
- **A loaded kernel driver** issuing hypercalls via `nt!HvlInvokeHypercall`.
- Gate 4's oracle additionally needs LiveCloudKd's driver, which ships signed by a **revoked**
  certificate and must be re-signed for the bench to load it.

None of that is a configuration to leave running. The feasibility document's stop conditions and
its record of which Code Integrity policy actually blocks what are part of the result, not
housekeeping.

**The saved-state route needs none of it**, which is what S0 was run to find out: Hyper-V
administrator on the host, a standard checkpoint, and the Windows SDK's
`vmsavedstatedumpprovider.dll`. Nothing is signed, nothing is loaded, and the capture is a file
that can be read on another machine. The probe that does it is checked in as
[`tools/sk_savedstate_probe.py`](../../tools/sk_savedstate_probe.py), one of the two instruments
from this investigation that can be, because it needs no driver to go with it. The other is
[`tools/sk_hypercall_scan.py`](../../tools/sk_hypercall_scan.py), gate S5a's scanner, which needs
less still: it reads `securekernel.exe` as a file, with no debugger, no target and no VM. Everything
else here stays out of the repository, because it needs the weakened bench above to mean anything.
