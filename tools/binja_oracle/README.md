# The ARM64 second opinion, diffed

[`tools/ghidra_oracle/`](../ghidra_oracle/README.md) runs Ghidra and Driver Buddy Revolutions over
an x64 driver and diffs their control codes against `ioctl_map`'s. This lane is the same idea on
**ARM64**, against a different second implementation: the Binary Ninja companion
[`binja-windbg-mcp`](https://github.com/glslang/binja-windbg-mcp), whose
`binja_windbg_mcp.analysis.ioctl_map` recovers the same shape from a capture of a Binary Ninja
database.

**Two directories rather than one, and that is the decision.** The two lanes share a diff
discipline and nothing else runnable: Ghidra's half needs a Windows host with Ghidra, a JDK,
PyGhidra and Driver Buddy installed, and this one needs a Python checkout and — for the diff — no
disassembler at all. Merging them would give one script whose preconditions are the union of two
benches, on a repo where each bench is on a different machine. What is shared is written down
instead: read the x64 README's *"What to read"* list first, because the rules there — a code only
one implementation has is a **candidate** rather than a finding, a switch's default is not
inferred — are the same rules here and are not repeated.

## The two halves

| | `oracle.py` — the diff | `capture.py` — the capture |
|---|---|---|
| needs | the companion checkout and its `.venv` | plus Binary Ninja and its licence |
| Binary Ninja | **not** run | the real GUI, owned and disposable |
| costs | about eight seconds a driver | two to four minutes a driver |
| run it | every time | once per driver *per build* |

A capture is the companion adapter's own reading of a binary; replaying one needs no disassembler,
which is why the diff is cheap and the capture is not. **Personal has no headless API**, so
`capture.py` starts the real GUI with its own `BN_USER_DIRECTORY` and a generated plugin that runs
the probe and quits — the mechanism `tools/bn_followup_probe.py` already uses for the CLRBHB
probes, whose process-group handling it imports rather than copies.

### Making a capture

```console
python tools/binja_oracle/capture.py --image ~/drivers/rdyboost.sys \
    --capture-path ~/captures/rdyboost-arm64.json --output /tmp/cap-rdyboost \
    --dispatch-rva 0xeeb0
```

Three things it has to do that are not obvious, each of which cost a run:

- **The NT types have to be in the view.** The adapter reads `_DRIVER_OBJECT`,
  `_IO_STACK_LOCATION` and `_UNICODE_STRING` out of the database, and the recovery depends on
  Binary Ninja's type propagation over the IO stack location. They are declared in `bn_capture.py`
  rather than imported from a PDB, and **every offset was checked against the live ARM64 kernel**
  with `dt` — `Parameters` at 8, `MajorFunction` at 0x70 in a 0x150-wide struct, `_IRP` 0xd0 wide
  with `Tail.Overlay.CurrentStackLocation` at 0xb8. The probe refuses if the view parses them into
  a different layout, because a struct one padding rule out reads every displacement against the
  wrong field and fails as an *empty map* rather than as an error.
- **`__security_push_cookie` destroys the parameter binding.** Applying `DriverEntry`'s prototype
  is not enough: the helper preserves the argument registers and is not declared to, so Binary
  Ninja models it as *returning* `x0` and `x1` and the typed parameter dies at the first call.
  Measured on `rdyboost`, the signature applies and the table fill still reads
  `*(x0 + 0x70) = SmdDispatchGeneric`. So the probe types the **entry register** as
  `PDRIVER_OBJECT` too.
- **That is an assertion, so it is checked.** `--dispatch-rva` is the device-control handler the
  **live driver object** names — the OS's own answer, not this server's — and a recovered
  `MajorFunction[14]` that disagrees with it is a refusal rather than a published capture. It is
  the one fact a capture does not derive, and the provenance records it. Every control *code*
  still comes out of Binary Ninja alone, which is what the diff compares.

**The GUI does not always exit, and the capture does not depend on it.** The probe clears
`file.modified` on every view — this work defines types and applies prototypes, so the database
really is modified — and then issues the `Quit` action; measured on both ARM64 captures, no modal
is up when it checks and the process still does not exit, with no crash report. What bounds that
is `--quit-grace` (45s), which starts when the probe writes its verdict rather than at launch: the
capture is on disk by then, so a Quit that never completes costs the leash and the launcher's
`SIGTERM`. A `forced: true` in `process-exit.json` beside an `ok: true` result is that, and is not
a failed capture.

The probe applies the prototype outward from the entry point a call at a time (`--entry-hops`),
stopping at the first hop that recovers a registration, and only then falls back to typing whoever
takes the dispatch routine's address. `rdyboost` needed all of it; `mountmgr` did not.

**A capture is not a companion test fixture.** Those carry `expected_mappings` reviewed by hand in
the UI. This is one implementation's answer, which is all a diff wants and all it claims.

### Running the diff

```console
python tools/binja_oracle/oracle.py --capture ~/captures/rdyboost-arm64.json \
    --ssh <user>@<debugger host> --server 'C:\workspace\windbg-mcp\target\debug\windbg-mcp.exe' \
    --profile <kernel profile> --dispatch 'rdyboost!SmdDispatchDeviceControl' \
    --module rdyboost --record run.json
```

`--ssh` is what makes the lane runnable from the Mac this repo is edited on: the MCP stdio
transport is newline-delimited JSON-RPC either way, so an `ssh` to the debugger guest is the same
pipe as a local child. A live kernel is attached **by profile name**, never by connection string,
so the target's debug key stays on the host that resolves it and out of this argument, this
terminal and `--record`'s output.

`--record` writes both halves; `--tool-json`/`--companion-json` read one back, so a run can be
re-read without touching the target. `--selftest` runs the diff over small synthetic documents and
checks it answers 0, 1 and 2 where it should — a diff that cannot fail is what this lane replaces.

Exit status: **0** the two agree, **1** they do not, **2** they cannot be compared.

## How to read it

Three things make a raw record-level diff of these two implementations report disagreement where
there is none, and each is handled explicitly rather than absorbed.

- **The build.** The companion's half is a capture taken once; this side's is a driver read off a
  live target, and the target's copy moves underneath the capture with nothing in either answer
  saying so. So the two PE identities are compared first — `timestamp` and `size`, plus the PDB
  where both carry one — and a mismatch stops the lane at exit 2. This is the ARM64 restatement of
  the x64 lane's third trap, and it is what this lane found first: see below.
- **Where a case *is*.** The companion names *"the first source-mapped statement"* of a case and
  this walk names the block the branch enters, which on A64 begins by materialising an address. So
  the companion's address is at or after this one, by the length of that prologue: a constant
  `0x18` on all 29 of HEVD's cases, and `0`, `4`, `8`, `0xc` or `0x10` across `rdyboost`'s. The
  lane therefore pairs destinations inside a **stated forward window** (`--route-window`, 0x20 by
  default, shorter than the gap between two case blocks on these drivers) and reports the
  displacements it saw. A window is a property of the two conventions; a constant fitted to
  whichever value lines the most records up would be a parameter tuned to hide disagreement.
- **The jump-table slots that route to the default.** The companion publishes a record per slot;
  this walk drops a slot whose target is the bounds check's own branch, so it emits fewer records
  *by design* — on `mountmgr`, 45 fewer. Each surplus record is set aside on **the companion's own
  evidence**, not on a count: it publishes `{"kind": "switch", …}` beside `goto_target` on a record
  it took from a table and `{"kind": "comparison", …}` on one it took from a compare, and the
  switch site has to be one this walk resolved too. Measured 2026-09-20: `mountmgr`'s 45 all carry
  switch evidence at `0x1940c`, `0x1944c` and `0x19730` — exactly this side's three tables — while
  `rdyboost`'s two carry `comparison` and are real misses. The **count** is checked separately,
  against `entries` minus `followed`, and only where the records are counted — at route level.
  Both, in that order, and neither alone: equal counts are not provenance, since one missed
  compare beside one dropped slot balances perfectly while hiding the finding this lane exists to
  make; and attribution is not a licence either, since a table slot that is not one of the ones
  dropped here is a difference too. Keeping the count out of the *code* comparison matters for a
  third shape — a driver whose dropped slots carry codes it also handles elsewhere leaves no
  unrouted code at all, and comparing the two numbers there would report that as a disagreement.

**The whole list of difference classes is in `oracle.py`'s diff section**, written after several
review rounds had landed on one of them: the build, a code only one side has, a code routed
elsewhere, a code with no address, and a length both sides prove differently on a paired route. The last of those
was found by writing the list rather than by a review round — the sizes were counted on each side
and never compared, so two implementations proving one length each, differently, read as `1, 1`.
It is what the lane checks, not a proof that nothing else can differ.

The surplus itself is **whatever did not pair**, and that is a decision rather than an
implementation detail: four rounds of review found records falling between the parts of a surplus
assembled from placed records plus companion-only codes — one with no address, then one with no
address whose code was shared. Every record is paired now, addressed ones on their destination and
an addressless one against a leftover of the same code, so what is left over is the whole of the
difference by construction rather than by enumeration. A record the other side attributed and this
one did not still pairs — they agree about the code and one of them cannot say where it lands —
and the count of such pairs is printed, so "routed the same" never quietly means "agreed about the
code and nothing else".

And one thing the lane prints because the *absence* of a difference is easy to over-read: **what a
fixture cannot decide.** Two implementations both proving no buffer size is correct behaviour
agreeing with correct behaviour whenever the driver's length checks are not in the dispatch
routine's case blocks. None of the three fixtures below proves a single size on either side, so
none of them separates the two implementations on sizes at all.

## Measured 2026-09-20

All three read off the live ARM64 kernel target, against `windbg-mcp 0.18.0+g30c4af94` — the
`30c4af9` this work was written on, which is not `main` any more and is a build `src/ioctl.rs` has
not moved in since — with captures from Binary Ninja `6.0.10601 Personal`. The version string is
the authority for a figure here, not the date on the exe
(`.claude/rules/measurement-provenance.md`).

| fixture | identity | codes | routes | verdict |
|---|---|---|---:|---|
| ARM64 HEVD | matches | 29 = 29 | 29 of 29, every one `+0x18` | agree, exit 0 |
| ARM64 `mountmgr` 10.0.26100.1 | matches | 24 = 24 | 24 of 24, 48 records | agree, exit 0 |
| ARM64 `rdyboost` | matches | 17 agreed, **2 only the companion** | 17 of 17 | **differ, exit 1** |

`mountmgr`'s 93 companion records against this side's 48 are not a disagreement: the 45 surplus
land on the two destinations no route reaches, and this side dropped exactly 45 table slots
(`21-5`, `21-5`, `17-4`).

**The first thing this lane found was that the published agreement had never been tested.** The
companion's checked-in `mountmgr` capture pins `timestamp 2826447139`, `size 0x21000`, PDB
`93E8BD6D…`; the driver the debuggee is running is `timestamp 1169727331`, `size 0x22000`, PDB
`60A98336…`. Both call themselves `10.0.26100.1` and their file hashes differ, so no RVA in one is
an RVA in the other. Recapturing from the build the target actually runs is what turns that row
into the clean one above.

**`rdyboost` is the fixture that separates the two, and it faults both.** The lane pointed at two
codes only the companion has, at `0xf010` and `0xef14` — which are exactly the two sites
`ioctl_map` reports in `untracked`, so the two agree about *where* they could not read something.
The target settles what is there: an A64 **conditional-compare chain**, `cmp` / `ccmpne` / `ccmpne`
/ `beq`, three codes reaching one handler. Neither implementation reads one. The companion
publishes the chain's first operand as a case — which is how a meaningless `0x00000000` reached
its map — and misses the `ccmp` operands; this walk publishes neither and records the site. That
is `FOLLOWUPS.md` item 92 for this side; the companion's half belongs to its own repository.

**The captures are not checked in.** Each is a reading of the build the debuggee is running at the
time, and a stale one is the exact failure the identity gate above exists to catch. Make one with
`capture.py` when you need it.
