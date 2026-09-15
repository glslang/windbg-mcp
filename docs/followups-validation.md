# Follow-ups 61–65: implementation and validation

## Status — 2026-09-15

The investigation tools and runnable validation probes from
[the implementation plan](followups-61-65-plan.md) are implemented. Initial acceptance
harnesses live in this repository alongside their retained evidence. The maintained
native replacement and its acceptance tooling live in `binja-windbg-mcp`. No production
Rust or companion API change was needed for these checks.

| Item | Delivered | Remaining closure condition |
|---|---|---|
| 61 | Fresh CVRF and artifact verification, complete retained comparison review, exact-byte stale-pointer checker and a competing-CVE investigation. [Report](cve-2026-83498-attribution.md). | The real cleanup fix is not yet attributable to CVE-2026-83498; exact discriminating artifacts could not be acquired from the colliding symbol-server key. |
| 62 | Read-only guarded handoff probe, refusal/preservation tests, authenticated live session discovery. [Report](securekernel-handoff-acceptance.md). | No existing debugger sessions were available for Secure Kernel handoff. |
| 63 | Companion-maintained, SDK-pinned native ARM64 replacement; all sixteen endpoints and the complete external comparison pass. [Report](clrbhb-native-validation.md). | **Closed locally.** Upstream PR draft prepared for later submission. |
| 64 | Isolated launcher; wizard crash, safe control, modal guard and active export/matching shutdown captures. | Upstream #8549 is still open; the original scenario still crashes. |
| 65 | Real GUI capability discovery confirms native BinDiff/WARP unavailable; conditional native checklist below. | Appropriate Ultimate access without purchase. |

Follow-up 63 is closed locally; 61, 62, 64 and 65 remain open. Historical Personal
delivery acceptance remains separate from these closure conditions.

The initial [implementation manifest](samples/followups-61-65-implementation-20260915.json)
indexes source/capture hashes and per-item outcomes. On 2026-09-15, all 16 new
offline tests and 11 existing probe-cleanup tests passed, along with Ruff,
formatting and changed-documentation lint. The two exact ARM64 instruction paths
were rechecked independently. Final process inspection found no Binary Ninja or
BinDiff processes left running.

## GUI probe launcher

[bn_followup_probe.py](../tools/bn_followup_probe.py) launches one owned macOS GUI
process with a fresh user directory and QSettings suffix. It refuses an existing
Binary Ninja GUI, serializes its own launchers with a file lock, drains output to
a private log, and records the child exit code and newly observed crash reports.
Timeout cleanup signals only the owned process group. The output directory must
be new; the normal user profile and application bundle are preserved.

Use the existing license file and supply the companion checkout plus its Python
3.13 dependencies for decoder and active-work cases:

```console
python3 tools/bn_followup_probe.py --case decode \
  --binaryninja '/Applications/Binary Ninja.app/Contents/MacOS/binaryninja' \
  --license-file /private/lab/license.dat --output /tmp/bn-decode-new \
  --python-path /path/to/companion --python-path /path/to/python313/site-packages \
  --reference /private/lab/reference/securekernel.exe \
  --target /private/lab/target/securekernel.exe --bindiff /path/to/bindiff
```

`result.json` contains in-process observations; `process-exit.json` combines them
with the actual exit outcome. A capture's `ok` flag alone cannot pass the
launcher. `normal_exit` requires exit zero, no forced termination and no new
crash report. Source hashes are captured, and the final launcher archives its
source and GUI probe under the private output's `sources/` directory. Review
private captures for paths and credentials before publishing.

| Case | Purpose |
|---|---|
| `decode` | Exact CLRBHB instruction and synthetic analysis; with the verified pair, all sixteen real endpoints and gated full comparison |
| `wizard` | Original application Quit with FirstSetupDialog active; deliberately exercises the known crash in an empty disposable GUI |
| `no-wizard` | Empty control with onboarding disabled |
| `qt-wizard` | Direct Qt quit; records whether the wizard remains alive after three seconds, then dismisses it and requests ordinary Quit |
| `guard` | Temporary modal dialog causes ordinary Quit to be refused; post-dismissal Quit succeeds |
| `quit` | Application Quit during confirmed active in-process export |
| `quit_matching` | Application Quit during confirmed active external BinDiff matching |

The active-work cases observe the companion's actual application-shutdown hook.
They record active work immediately before Quit and inspect completion,
export/reader threads, child process reaping, temporary files and listener state
after its hook. Failure to reach the requested active stage fails the check.

## Shutdown observations

[Sanitized shutdown evidence](samples/bn-shutdown-validation-20260915.json) records
Binary Ninja 6.0.10601 Personal with companion
`22cd24fbce81014402be32e490e39206c741440e`:

| Case | Result |
|---|---|
| Original FirstSetupDialog application Quit | Failed: SIGABRT, child exit −6 |
| Direct Qt quit with wizard active | Failed to quit: still alive after three seconds; dismissal followed by application Quit exited zero |
| Wizard-disabled empty control | Passed: exit zero |
| Modal guard, followed by dismissal and Quit | Passed: refusal recorded, then exit zero |
| Active export Quit | Passed: active exporter observed; threads/listener stopped, temporary files removed, exit zero |
| Active external matching Quit | Passed: live BinDiff observed; child terminated/reaped, reader/export threads stopped, files removed, exit zero |

Both active-work jobs report stop reason `stale`: application Quit closes views
and invalidates their comparisons before the final shutdown observation. This
is the recorded lifecycle, not a manually requested pre-Quit plugin shutdown.

Earlier harness failures are retained in the evidence: an invalid synthetic
platform name, an output-directory conflict, and attempted reuse of a lifecycle
probe that supported restart/rebase/close but not Quit. The maintained harness
uses the architecture's standalone platform and a dedicated active-Quit observer.

[Upstream #8549](https://github.com/Vector35/binaryninja-api/issues/8549) remained
open with no comments at the execution check. The original scenario still needs
an upstream fix and a passing recapture. Keep ordinary startup/quit modal guards.

## Conditional Ultimate checklist

The decoder GUI queried the companion's actual native provider boundary. Both
Google BinDiff and WARP were unavailable on the installed Personal edition;
[the capability capture](samples/clrbhb-native-validation-20260915.json) is
discovery evidence, not native comparison acceptance.

If an appropriate Ultimate installation becomes available without purchase, use
the companion's `tools/similarity_capture.py` with explicit `--backend native`
and `--provider 'Google BinDiff'`, then WARP and their supported combined
selection. Record the installation, providers, backend and exact fixtures.

Capture identical, relocated and changed fixtures; all match/unmatched/diff pages;
unchanged names, types, comments and bytes; cancellation and deadlines;
edit/rebase/close invalidation; listener restart and quit during active work;
native-object retention until completion and subsequent cleanup. Check unavailable
providers and that native execution does not switch to external mid-run.
Compare against the native contract in [the similarity plan](binja6-similarity-plan.md).
Do not reuse the external-only active-work probe as native acceptance evidence.

## Checks

Run the focused offline suite and source checks:

```console
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tools -p test_followup_probes.py
ruff check --no-cache --select E4,E7,E9,F,I tools/*probe*.py tools/clrbhb_decoder_compare.py
cargo fmt --all --check
```

The attribution scripts have their own hash-gated invocations in the attribution
report. The native C regression and corpus check have a separate
[runbook](clrbhb-native-validation.md#reproduce). Documentation uses the repository's
markdownlint-cli2 0.23.2 gate. Rust tests and Windows debugger tiers are required if
a subsequent production change touches those paths; no Rust source changed here.
