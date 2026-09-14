# A second opinion on the driver tools

`ioctl_map`, `driver_hazards`, `device_security` and `driver_surface` are a native port of
[Driver Buddy Revolutions][dbr], a Ghidra script. Everything that checked them until 2026-09-14 was
derived from **my own reading of the same drivers**: the dump-tier oracle comes from
[`docs/driver-ioctl-walkthrough.md`](../../docs/driver-ioctl-walkthrough.md), which is a hand
recovery, and `src/ioctl/tests/differential.rs` runs a concrete interpreter over fixtures written
beside the pass it checks. Both are worth having and neither is independent — if the model is wrong
the same way twice, it agrees with itself.

This lane runs the *other* implementations over the same bytes and diffs the answers **by code**.
It is manual: a run takes about a minute per driver and needs Ghidra on the host, so it belongs
nowhere near `cargo test`.

It has already paid for itself. On its first run it found `0x6dc000`
(`IOCTL_MOUNTMGR_CREATE_POINT`) missing from `ioctl_map` — a code `mountmgr` accepts, with a name
string and a handler, at two sites. The cause was `cmp` / `ja` / `je`: one compare feeding two
conditional branches, which puts the compare in one basic block and the equality in the next. The
walkthrough's published figure had the same miss, so the dump-tier assertion agreed with it.

## What this bench needs

| | where | note |
|---|---|---|
| Ghidra | `C:\ghidra_12.1.3_PUBLIC` | not on `PATH`; `JAVA_HOME` must be set |
| JDK | Temurin 25 | `C:\Program Files\Eclipse Adoptium\jdk-25.0.4.101-hotspot` |
| PyGhidra | `pip` package `pyghidra` | 3.1.0, matching the one Ghidra ships |
| Driver Buddy Revolutions | `~/ghidra_scripts/ghidra_vuln_finder.py` | with `Windows_Driver_functons.gdt` beside it |

Three traps, each of which cost a run:

- **`analyzeHeadless -postScript` refuses a `.py`** ("Ghidra was not started with PyGhidra"), which
  is why the Java script is Java and Driver Buddy goes through `pyghidra.run_script` instead.
- **Never run this from a directory containing a folder called `ghidra`.** `sys.path[0]` is the
  script's own directory, so `import ghidra` finds that folder as a namespace package and
  pyghidra's meta-path finder — which resolves `ghidra.*` by importing `ghidra.framework` — recurses
  until the stack runs out. The failure is a bare `RecursionError` naming neither, and raising the
  recursion limit does nothing: it is a cycle, not depth.
- **The image has to be the one the dump mapped.** `target/release/sym/mountmgr.sys/` holds two
  cached copies and only one matches; the directory name ends in `SizeOfImage`, so
  `F7AA24C61f000` is `0x1f000` = 126,976 bytes, which is what `modules` reports for the driver in
  `docs/samples/081226-2187-01.dmp`. The other has no instruction at the dispatch RVA.

## Running it

```console
python tools/ghidra_oracle/oracle.py
```

It captures `ioctl_map`'s answer from the checked-in dump, runs both oracles over the cached image,
and prints a table of every code with a column per implementation. What to read:

- **A code only `ioctl_map` lacks, that both other implementations have**, is the
  interesting one, and is what found the bug above. One that only *one* of them has is a
  **candidate**: Ghidra's provenance check says a compared value came from memory, not
  that it came from the IRP's control-code field, and tracing it to that field would be
  this lane adopting the assumption of the pass it exists to check. So the diff reports
  the two lists apart and neither is silently promoted.
- **A code only Driver Buddy lacks** is the native tool being better, which is worth knowing but
  is not a defect here: it missed `0x6d4008` and `0x6d4028` on `mountmgr`.
- **Constants that are not the driver's device type** are Driver Buddy's false positives — it
  reported `0x80000005`, `0x8000002d` and `0xc0000004`, which are NTSTATUS values, because its
  heuristic accepts any plausible-looking constant. `ioctl_map` does not, because it traces the
  value from the IRP and says so in `code_proved`.
- **Only equality compares are codes.** The Java script emits every comparison constant it finds,
  with the p-code operator beside each, so what is excluded is visible rather than decided silently
  inside it — and the diff then keeps the `INT_EQUAL`/`INT_NOTEQUAL` ones. `< 0x6dc001` and
  `< 0x6d4021` bracket `mountmgr`'s switch and are not codes; reporting them as missing from
  `ioctl_map` was an oracle contradicting this file.
- **A switch's default is not inferred, and the tables are checked as a subset.** Taking the most
  frequent destination works on `mountmgr` — 68 of 81 slots — and fails on a switch whose real
  labels share a handler or whose destinations are all distinct. Ghidra's metadata does not name
  the default arm, so the lane reports every label grouped by the block it reaches and asks the one
  question that needs no default: is every code `ioctl_map` took from a table a label Ghidra put on
  the same switch? The grouping is worth reading on its own, but read it as a question: a destination with
  many labels and no recovered cases is a **candidate** for the default — or a group of
  labels `ioctl_map` did not take, which is the other thing it could be and the one worth
  chasing. Which of the two it is needs the decompiled C beside the JSON; the grouping
  poses that question rather than answering it.

## A second driver, and what it showed

`mountmgr` is one compiler's output of one shape: immediate compares and two dense jump tables. Run
the lane over **HEVD** as well -- it is a different shape, and it is the one with a published
answer:

```console
python tools/ghidra_oracle/oracle.py --image <HEVD.sys> --dispatch <its MajorFunction[0x0e]> \
    --device-type 0x22
```

HEVD's own header defines its codes (`IOCTL(0x800)` through `IOCTL(0x81B)`, each
`CTL_CODE(FILE_DEVICE_UNKNOWN, Function, METHOD_NEITHER, FILE_ANY_ACCESS)`), so for once the right
answer is known rather than agreed: **28**, `0x222003`-`0x22206F`. Measured 2026-09-14 against the
driver running on the KDNET target, with the image and the header taken off the guest:

| | codes | false positives |
|---|---:|---|
| source (ground truth) | 28 | -- |
| `ioctl_map` **before** | 4 | none |
| `ioctl_map` after | **28** | none |
| Ghidra | 28 | 3 binary-search bounds, which this script emits by design |
| Driver Buddy Revolutions | 24 | 2 (`0xbad0b0b0`, `0x2ddfa232` -- magic constants) |

The four that `ioctl_map` did find were the binary search's pivots; the other twenty-four are a
chain stepped by a register, which the walk read only as immediates. It also reported the map
**complete**, which was the more serious half and is what `untracked[]` now prevents.

`driver_hazards` cannot answer for HEVD on a live kernel: its dispatch is in `PAGE`, and the hazard
scan's header reads fail against sections that are not resident. That is the target's state rather
than a defect, and the section says so.

[dbr]: https://github.com/jsacco/driverbuddyrevolutions
