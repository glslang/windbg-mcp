# Secure Kernel research

Can a debugger reach **VTL1** — the Secure Kernel — on a VBS-enabled Windows guest, and can
`windbg-mcp` drive it? These documents are the record of finding out. They are a **research log**
first, and several sections record what did not work and why, which is most of the value.

**One part of it is now code in this server**, and the rest is not. `src/sk.rs` decodes a guest's
VTL1 — the page-table walk, the image identification, the debugger data block and the module list —
over a source seam, `src/savedstate.rs` reads a Hyper-V capture through the Windows SDK's provider,
and `windbg-mcp --sk-inspect` drives the two from the command line (`FOLLOWUPS.md` item 103, gate
S1). There is **no MCP tool**: that is gate S3, and its shape is still an open question. So no
`tools/list` changes, nothing a client can call, and everything below about the *live* route still
needs the bench posture it describes.

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

**What is still open:** turning those reads into tools (gate H5), which is scoped as `FOLLOWUPS.md`
item 103 and is part-built — **S0** is answered above and **S1**, the decode layer, is now in
`src/sk.rs` and reproduces every capture-derived landmark in the table below from a checkpoint, with
two checks the probe did not run: a structural route to the module list that agrees with the block,
and the provider's own address translator agreeing with the walk on every page of the image. What
remains is symbols against the image (S2), the tool surface (S3), and whether VTL1 execution can be
controlled at all (S5). Its route is decided, and the
decision is the opposite of where this work began. Driving a live Secure Kernel target through
**DbgEng/EXDI is parked**, for two independent reasons: EXDI activation does not work on this bench
and is unresolved, and — measured separately — DbgEng's Secure Kernel record is unreachable, so even
a working EXDI would supply a generic memory target rather than any SK awareness. Since the reads
now exist, that is a trade with nothing on one side. What it costs is DbgEng's symbol handling, most
of which is recoverable against the *image* without a live target.

**Two things are open beneath that.** Whether VTL1 *execution* can be controlled at all is
unresolved and decides inspector versus debugger: the hypervisor's VTL1 debug port is up and Secure
Kernel does not connect to it. And whether VTL1 can be *written* is settled per route —
`HvCallWriteGpa` refuses it symmetrically with the read, the direct driver route accepts it — so the
patch half of a software breakpoint exists and the catch half does not.

## The documents

Read them in this order; each assumes the one before it.

| # | Document | What it covers |
|---|---|---|
| 1 | [Secure Kernel debugging plan](secure-kernel-debugging-plan.md) | The original plan: validate software-only SK debugging, then integrate whichever route works. Carries the handoff status and the `Kd=` option set read out of `dbgeng.dll` — six kernel-discovery modes, of which `Kd=VerAddr:<addr>` is the one a Secure Kernel bind would use. |
| 2 | [Secure Kernel debugging validation](secure-kernel-debugging-validation.md) | The measurement record behind everything else. NT and hypervisor debugging pass; **native SK attachment does not**. Why post-26100 `securekernel.exe` ships no KD transport, and what `SkdInitDebuggerDataBlock` does instead. The longest document here and the one to cite. |
| 3 | [EXDI stub plan](exdi-stub-plan.md) | Expands Phase 4 of (1). What an EXDI stub would have to be, where each component runs, why the EXDI server is surrogate-hosted, and the analysis of LiveCloudKd as an existing implementation — including its GPL-3.0 licence and its revoked-certificate driver. |
| 4 | [Hypercall feasibility](secure-kernel-hypercall-feasibility.md) | **The main result.** A falsifiable gate-by-gate plan — H0 to H5 — for reading a guest's VTL1 from the root, each gate with a pass condition, a control and a stop condition written before the work. H0 to H4 pass. H2 passes on its **second** mechanism — its cheap driver-free probe failed, and the Code Integrity policy that blocked it is not the one it looks like. H5's route is decided — **H5b**, exposing the reads directly, because driving DbgEng through EXDI is blocked *and* would add no Secure Kernel awareness — and the record carries the H5b gates run so far: **S4**, which settles writes per route, and **S0**, which finds a driver-free source that carries VTL1 and its page-table root. |

Two older side-investigations, kept because they are about the same binary:

| Document | What it covers |
|---|---|
| [Securekernel ARM64 export follow-up](securekernel-export-followup.md) | Why eight matches went unresolved in an ARM64 `securekernel.exe` comparison — undecoded instructions in Binary Ninja, not missing inputs or failed matching. |
| [Read-only Secure Kernel handoff](securekernel-handoff-acceptance.md) | The handoff probe and its refusal/preservation tests. Live acceptance is **not run**; the record says so rather than implying coverage. |

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
[`tools/sk_savedstate_probe.py`](../../tools/sk_savedstate_probe.py) — the one instrument from
this investigation that can be, because it needs no driver to go with it.
