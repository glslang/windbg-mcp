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

- **A code only `ioctl_map` lacks** is the interesting one, and is what found the bug above.
- **A code only Driver Buddy lacks** is the native tool being better, which is worth knowing but
  is not a defect here: it missed `0x6d4008` and `0x6d4028` on `mountmgr`.
- **Constants that are not the driver's device type** are Driver Buddy's false positives — it
  reported `0x80000005`, `0x8000002d` and `0xc0000004`, which are NTSTATUS values, because its
  heuristic accepts any plausible-looking constant. `ioctl_map` does not, because it traces the
  value from the IRP and says so in `code_proved`.
- **`INT_LESS` constants from the Java script** are range bounds, not codes: `< 0x6dc001` and
  `< 0x6d4021` bracket the switch. It emits every comparison constant deliberately, so that what
  is excluded is a decision made here rather than one made silently in the script.

[dbr]: https://github.com/jsacco/driverbuddyrevolutions
