# Binary Ninja shutdown investigation — 2026-09-10–11

Upstream report: [Vector35/binaryninja-api #8549](https://github.com/Vector35/binaryninja-api/issues/8549),
including the reproduction, native evidence, and investigation document.

The shutdown aborts were triggered by the disposable-profile test harness invoking
the application **Quit** action while BN's **FirstSetupDialog** was still open.
The same abort occurs without loading the companion or opening a binary. Disabling
the first-run wizard in the disposable profile removes this trigger: baseline,
active native export, and active external BinDiff matching all exited with code zero.

This relates the failures to how the acceptance work launched and closed BN.
It does not implicate the similarity implementation or metadata invalidation fix.
The 2026-09-11 native follow-up confirmed the ownership defect: destruction of the
main window tries to heap-delete its stack-allocated wizard child. These tests do
not rule out other shutdown failures.

## Controlled results

Each case used BN 6.0.10601 Personal on Apple Silicon macOS, a fresh user directory
and QSettings suffix, and one owned GUI process at a time. Baseline cases loaded
only a small observation/quit probe; their Python module inventories contained no
companion modules. No application bundle or normal user profile was changed.

| Case | State at Quit | Result |
|---|---|---|
| Empty baseline, default fresh profile | `FirstSetupDialog` active; no input files or companion | `SIGABRT`, exit −6; same first 37 crash frames as the earlier companion run |
| Empty baseline, `ui.allowWelcome: false` | No modal dialog; no companion | `aboutToQuit` observed; exit 0 |
| Companion `2eb95c5`, native export active | No modal dialog; exporter thread running | Job stopped for `shutdown`; export thread ended; temporary directory removed; listener stopped; exit 0 |
| Companion `2eb95c5`, external matching active | No modal dialog; live BinDiff process and output reader | BinDiff terminated and reaped; reader/export thread ended; temporary directory removed; listener stopped; exit 0 |
| Updated capture helper | Temporary modal dialog, then no modal dialog | Quit refused while modal; application Quit succeeded after dismissal; exit 0 |

The four successful cases required no forced termination. The active cases reused
the verified ARM64 securekernel input pair from the earlier acceptance record.
No input binary was executed. A final process check found no running BN or BinDiff
processes.

The matching native stacks pass through the allocator's invalid-free report,
`QObjectPrivate::deleteChildren()`, `QWidget::~QWidget()`, BN image offsets
`0xfaed8` and `0xfb0a4`, and a nested `QDialog::exec()` loop. The baseline's modal
widget inspection identifies that dialog as `FirstSetupDialog`. The experiment
established the trigger. The following native breakpoint identifies the exact
object that the deletion path tries to free.

## Native ownership proof — 2026-09-11

The wizard's C++ address, read through `shiboken6.getCppPointer`, lies within the
main thread's stack bounds reported by `pthread_get_stackaddr_np` and
`pthread_get_stacksize_np`. Its Qt parent is `MainWindow`. In the debugger probe:

- Wizard address: `0x16b4d9db0`.
- Main-thread stack: `[0x16ace0000, 0x16b4dc000)`.
- Immediately before `operator delete`, ARM64 argument register `x0`:
  **`0x16b4d9db0`**, exactly the wizard address.

LLDB stopped at BN image offset `0x146c0`, the tail of the wizard's deleting
destructor. Its next instruction branches to `operator delete(void*)`. The caller
is `QObjectPrivate::deleteChildren()`, reached through main-window destruction and
the same BN image offsets `0xfaed8` and `0xfb0a4` seen in the original crash.
The debugger terminated only this owned probe before executing the invalid free.

Static disassembly independently shows the wizard constructor receiving
`sp + 0x1e0` at image offset `0xff488`. The same address is passed to
`QDialog::exec()` and then the normal destructor when the modal loop returns.
Main-window destruction during that loop instead takes the deleting-destructor
path, which is inappropriate for this stack object. Qt documents that parent
destruction deletes children and that stack-allocated objects require compatible
[construction/destruction order](https://doc.qt.io/qt-6/objecttrees.html).

This is a confirmed native lifetime error in the tested BN build, triggered by the
automated application-action path while onboarding is active. It does not require
the companion, a loaded input, or BinDiff. An upstream correction would need to
keep the parent alive until the modal loop and stack destructor have finished, or
change the dialog's allocation/ownership consistently. No installed BN executable
was patched, and ordinary keyboard/menu interaction was not tested.

The LLDB probe is **not** clean-quit acceptance. Its launcher reported zero after
the debugger killed/reaped the process; LLDB explicitly recorded termination with
status 9. For a traced process, use the debugger's exit observation. The earlier
successful baseline/export/matching cases ran without a debugger attached.

## Lingering-process controls — 2026-09-11

Two additional empty-profile controls used no companion and called
`QCoreApplication.instance().quit()`:

| Startup state | Observation |
|---|---|
| First-run wizard active | BN and `FirstSetupDialog` remained alive three seconds after the call; a timer still fired. Dismissing the wizard and then invoking application Quit exited with code zero |
| Wizard disabled in the disposable profile | The same direct Qt quit emitted `aboutToQuit` and exited with code zero |

This reproduces the earlier lingering-instance symptom in the startup modal state,
without any comparison worker or listener. It is distinct from the invalid-free
path: the direct Qt call was ineffective there, while the application Quit action
destroyed the main window too early. The capture helper's modal guards and the
one-instance-at-a-time launcher procedure address both observed cases.

[Native follow-up evidence](samples/bn-shutdown-native-20260911.json) records the
pointer equality, stack bounds, debugger frames and termination, executable hash,
disassembly offsets, and both Qt-quit controls. All three owned probes exited;
the debugger probe was deliberately killed at the breakpoint.

## Reproduction and correction

To reproduce only in a disposable BN process, use a fresh `BN_USER_DIRECTORY` and
`BN_QSETTINGS_POSTFIX`, launch with `--new-instance`, and leave the first-run wizard
open. A minimal Python plugin can reproduce the observed application-action path:

```python
import binaryninja as bn
from binaryninjaui import UIContext
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication

def reproduce():
    modal = QApplication.instance().activeModalWidget()
    assert modal is not None
    assert modal.metaObject().className() == "FirstSetupDialog"
    context, = UIContext.allContexts()
    context.getCurrentActionHandler().executeAction("Quit")

bn.execute_on_main_thread(lambda: QTimer.singleShot(10000, reproduce))
```

This deliberately reproduces the crash and is not a capture launcher. The control
uses the same launch setup with `{"ui.allowWelcome": false}` in the disposable
profile's `settings.json` before launch, then requests Quit with no active modal.
The setting is BN's built-in **Allow First Run Wizard** option. The isolation
variables are documented in [BN troubleshooting](https://docs.binary.ninja/guide/troubleshooting.html).

The shipped [capture helper](../skills/msrc-patch-diff/scripts/gui_capture.py) now
checks for modal dialogs before starting or opening files and again before quit.
It requests the application's Quit action and records a refusal in `cleanup_errors`.
The [capture instructions](../skills/msrc-patch-diff/references/acquisition.md#gui-capture-fallback)
document wizard suppression for automated disposable profiles and require recording
the actual exit code. A successful in-process capture or quit request alone is not
clean-shutdown evidence. No companion shutdown code needed changing.

The helper's 17 offline tests and Ruff pass. A real GUI check confirmed that its
modal guard refuses quit, then exits normally once the modal is dismissed.

## Windows Rust validation

`cargo test --locked -- --nocapture` passed on the Windows ARM64 debugger VM in a
separate detached worktree of PR #300 revision
`8eafc8fb8b57ae5824d4b7a6c53e7687d0ac9a52`, using Rust 1.96.1 for
`aarch64-pc-windows-msvc`. The existing checkout and running debugger service were
left untouched.

- Unit-test harness: **724 passed**, zero failures.
- MCP smoke harness: **105 passed**, zero failures, **12 ignored**.
- Opt-in debugger, kernel and TTD tiers were disabled. Gated smoke tests may report
  `ok` after printing `SKIPPED`; the count does not imply those tiers ran.

These results replace the earlier macOS-only compilation limitation for that PR's
Rust revision. This investigation changes Python helpers and documentation, not
Rust source.

## Evidence and remaining acceptance

[Sanitized isolation evidence](samples/bn-shutdown-isolation-20260910.json) contains
the five outcomes, pre/post shutdown resource observations, source hashes, matching
crash frames, and Windows test summaries. The
[original lifecycle evidence](samples/similarity-lifecycle-20260910.json) remains
unchanged, including failed and forcibly terminated probes.

Normal quit during active export and matching is now established with the
corrected harness. The subsequent
[lifecycle follow-up](similarity-lifecycle-acceptance.md#final-lifecycle-follow-up--2026-09-11)
also passed listener restart, rebase, and view closure after fixing the companion's
close notification. A separate [ARM64 fixture run](similarity-windbg-acceptance.md)
also passed guarded WinDbg handoff and clean GUI shutdown. Ultimate remains tentative.
