# Personal similarity → WinDbg acceptance — 2026-09-11

The generic Personal handoff acceptance passed through real authenticated MCP
connections: external BinDiff comparison, target navigation, runtime-byte
comparison, run-to, breakpoint, and refusal of the other build's identity.

## Setup

Binary Ninja Personal 6.0.10601 ran on Apple Silicon macOS 26.6.2 with the external
BinDiff helper and CLI used by the lifecycle captures. The companion was based on
`0fded637340b4f5eb07d91e72d2b3ab18fb767a0`, with the tested close-notification fix
from [lifecycle acceptance](similarity-lifecycle-acceptance.md). The Windows ARM64
listener ran windbg-mcp `17f5d7300b92b9510822c805c972317cbc9b92e1`.

Two locally built, benign ARM64 executables shared the image name
`handoff_probe.exe`. Their exported `probe_step` functions differed only in an
addend, 7 versus 11; `probe_finish` was unchanged. The entry point calls both
functions and exits. The debugger launched only the target fixture, with no
pre-existing sessions. A private SSH tunnel connected the companion to the
existing loopback listener; credentials were excluded from the evidence.

The PE identities differ in timestamp and PDB GUID, with the same SizeOfImage
(`0x4000`). The initial module inventory had deferred symbols and no PDB metadata,
so initial validation used the available timestamp and size. After execution
stopped in the fixture, WinDbg coordinates included the target PDB identity.
These metadata checks are not cryptographic authentication.

| Build | SHA-256 | Timestamp | PDB GUID / age |
| --- | --- | --- | --- |
| Reference | `39540f3215b279d1b3a4c0536a0786189742da2f97b473e14fd23813be01ca39` | `1789155882` | `D7BC3A19BABC4E9D89FA6AE761087F66` / 1 |
| Target | `4ec29723e87ff3a017dd0a02222645bf5829f3f8b927a737f272831c0f0aeb22` | `1789155883` | `1E080823700E4350AB5739A242442337` / 1 |

## Results

| Check | Recorded result |
| --- | --- |
| Real Personal export and BinDiff | Completed; three matches, complete coverage, zero omitted functions or unresolved rows |
| Changed-function inspection | Instruction diff reports `add w9, w0, #0x7` → `add w9, w0, #0xb` at RVA `0x1038` |
| Target navigation | Navigated using the match's target binary ID, generation, PE identity, and RVA `0x1034` |
| Guarded runtime bytes | All 16 requested bytes read; static/runtime equality, no differences or relocation ranges |
| Wrong-build read, breakpoint, run-to | All three returned `status: error`, category `debugger`, message `coordinate PE identity mismatch`; stopped IP unchanged |
| Guarded run-to | `run_to_here` returned `verdict: hit` at `probe_step`, runtime address `0x00007ff6104e1034` |
| Guarded breakpoint | `set_breakpoint_here` installed a resolved code breakpoint at `probe_finish`; `go` hit RVA `0x1028`, runtime address `0x00007ff6104e1028` |
| Cleanup | Unpaired, closed comparison, ended owned debugger session, restored empty session inventory, fixture process gone, original listener still running |
| GUI and transport shutdown | Companion listener thread joined; BN emitted `aboutToQuit` and exited 0 without forced termination; owned tunnel exited; no BN/BinDiff processes remained |

ASLR loaded the target at `0x00007ff6104e0000`, different from the BN image base
`0x140000000`. Both debugger stops resolved the selected build's RVA correctly.
BinDiff assigned structural similarity 1.0 to the changed function; its score
does not imply identical instructions. The independent textual diff exposes the
changed immediate.

The first probe stopped because it expected an `identity_mismatch` error category.
The live API correctly returned category `debugger` with the explicit identity
mismatch message. Only the probe assertion changed; the second run passed all
checks. Both runs restored the session inventory and exited BN normally.

## Evidence and reproduction

- [Sanitized capture](samples/similarity-windbg-20260911.json) records the MCP
  results, fixture/helper/source hashes, initial assertion failure, and cleanup.
- [Executed GUI probe](samples/similarity-windbg-probe-20260911.py) records the
  exact diagnostic source. It uses disposable local paths and private profile
  configuration; adapt those paths and supply your own loopback connection before
  running it. It launches and resumes only the named fixture, then ends its session.
- [Target fixture source](samples/similarity-windbg-fixture-20260911.rs) is the
  exact target input. Build the reference after replacing `wrapping_add(11)` with
  `wrapping_add(7)`, in a separate directory with the same executable name.

Each fixture was built on Windows ARM64 with Rust 1.96.1 and the MSVC linker:

```powershell
rustc fixture.rs --edition 2024 --crate-name handoff_probe `
  -C opt-level=1 -C debuginfo=2 -C panic=abort `
  -C link-arg=/ENTRY:handoff_entry -C link-arg=/SUBSYSTEM:CONSOLE `
  -C link-arg=/EXPORT:probe_step -C link-arg=/EXPORT:probe_finish `
  -o handoff_probe.exe
```

A rebuild has new timestamp/PDB metadata; acquire identities from those files
instead of copying the captured coordinates. Launch one BN GUI at a time with a
fresh disposable profile, `ui.allowWelcome: false` set before launch, and modal
startup/quit guards as documented in the [shutdown investigation](bn-shutdown-investigation.md).

This capture closes the plan's generic Personal similarity-to-debugger acceptance,
including live run-to and breakpoint checks. It does not execute securekernel or
establish a live CVE-specific handoff. The eight unresolved securekernel rows
remain a separate exporter follow-up; native Ultimate execution stays tentative.
