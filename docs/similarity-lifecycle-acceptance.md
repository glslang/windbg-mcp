# Similarity lifecycle acceptance — 2026-09-10–11

The follow-up exercised BN 6.0.10601 Personal with the external BinDiff 8 backend
against the verified ARM64 securekernel pair from the
[CVE capture](cve-patch-diff-acceptance.md). Each case used an isolated GUI profile
and an owned loopback listener. Tests observed a real active exporter or BinDiff
process before issuing the action. No Windows binary was executed.

The companion baseline is `0742c5e` (the same tree as the earlier `82f2d3a` capture).
The comment-edit rerun also includes the `data_metadata_updated` notification fix
and its regression test, now committed as `2eb95c5` in
[companion PR #3](https://github.com/glslang/binja-windbg-mcp/pull/3).
No other companion behavior was changed.

## Recorded outcomes

| Check | Result | Evidence and limits |
|---|---|---|
| Cancel during native export | Passed | Active export stopped; thread ended; temporary directory removed |
| Cancel during external matching | Passed | Live BinDiff process reaped with SIGTERM; output reader stopped; temporary directory removed |
| Close an active comparison | Passed | Matching process and temporary resources cleaned up; comparison removed |
| Invalidate after a view comment edit | Passed with fix | Baseline missed the metadata notification; rerun staled the comparison and refused navigation with the old generation |
| Rebase during export | Passed | Replacement notifications observed during export; actual base changed; results stale; old-generation navigation refused without moving selection |
| Close a view during export | Passed with fix | Exact target tab closed; close callback invalidated the comparison before BN removed the file from its registry; closed-view navigation refused |
| Listener restart during comparison | Passed | Old matching process reaped and listener port closed; restarted listener answered MCP and completed a new comparison |
| Normal application quit | Passed after harness correction | Initial runs failed; wizard-free reruns during export and matching cleaned up resources and exited with code zero; see [shutdown investigation](bn-shutdown-investigation.md) |
| Guarded WinDbg handoff | Passed separately | [2026-09-11 ARM64 fixture capture](similarity-windbg-acceptance.md): runtime bytes, run-to, breakpoint, and wrong-build refusal |

Cancelled/stale result retrieval may preserve partial evidence. Stale navigation
must refuse the old generation; requiring every results call to throw was a probe
error, not the companion contract. The initial rebase run remains partial evidence;
the corrected 2026-09-11 rerun supplies full lifecycle acceptance.

The metadata fix handles `BinaryDataNotification.data_metadata_updated`, which
view-level comment changes emit. It invalidates cached analysis, advances the view
generation, and requests cancellation of affected comparisons. The real rerun
refused stale navigation, and all 180 companion tests plus Ruff passed. This fix
does not address the separate native shutdown crash.

## Final lifecycle follow-up — 2026-09-11

Listener restart and rebase passed on companion `2eb95c5`. Actual view closure
exposed one further bug: BN delivers `OnAfterCloseFile` while the closing file is
still present in `FileContext.getOpenFileContexts()`. Refreshing that registry
alone missed the closure, and the comparison continued without a stale reason.
The callback now invalidates the closing file's tracked sessions immediately,
then refreshes the view registry. Unrelated comparisons retain their generations.

The same close-view case passed with this fix. The observer recorded the close
notification while export was active and both file sessions were still listed;
the target session subsequently disappeared, leaving only the reference open.
The comparison stopped as stale, the exporter ended, and temporary files were
removed. Navigation using the closed target's old ID/generation was refused and
left the reference selection unchanged. The probe deliberately avoids calling
`Workspace._views()` while waiting, so a poll cannot mask a missing callback.

The rebase case observed both replacement notifications during export and checked
the actual image base changed from `0x140000000` to `0x141000000`. Stale results
remained readable; navigation with the old generation failed with
`view generation changed` and did not move selection.

The restart case stopped the listener during real external matching. BinDiff was
terminated and reaped, its reader/export thread ended, temporary files disappeared,
the old comparison was removed, and the old port refused connections. A new
listener thread answered authenticated MCP requests and ran another comparison:
3,109 matches, with the known eight unresolved securekernel rows. That result is
still partial coverage, but it establishes comparison recovery after restart.

All three successful cases emitted `aboutToQuit`, stopped the listener, and exited
with code zero without forced termination. Tests used one disposable GUI at a time,
with the first-run wizard disabled. The initial restart attempt did not run its
test because the old temporary Python environment had missing files; it was stopped
and the environment rebuilt from the companion's pinned requirements.

The new regression test failed on the original callback and passes with the fix.
All **181 companion tests** and Ruff passed. The
[final captures](samples/similarity-lifecycle-20260911.json) retain the original
close-view failure, the fixed rerun, restart, rebase, and tested source hashes.
The [instrumented GUI probe](samples/similarity-lifecycle-probe-20260911.py)
preserves the executed assertions. Its `start(case, reference, target, bindiff,
output)` entry point expects an empty, wizard-free disposable GUI and a new output
directory; it creates its own listener and requests application exit after cleanup.

## Shutdown crash and process cleanup

The recorded native crashes terminate with `SIGABRT` after an invalid-free report
from the allocator, through `QObjectPrivate::deleteChildren()` and
`QWidget::~QWidget()`. Repeated reports have the same leading stack frames and BN
image offsets. The loaded Qt/PySide libraries in the inspected report come from
the BN application bundle; no second Qt installation was observed there.

The initial probes did not isolate the cause. The subsequent
[shutdown investigation](bn-shutdown-investigation.md) reproduced the same crash
without the companion or any open binary: the harness invoked application Quit
while the first-run wizard was still open. Suppressing the wizard only in the
disposable profile allowed normal shutdown during both export and matching.
An earlier ARM64 capture process (PID 7840) also has this crash signature, so
observing that a process has exited is insufficient evidence of clean shutdown.
Its completed comparison data remains valid; its exit is not clean-quit evidence.

All owned GUI probes were stopped and a subsequent process check found no running
Binary Ninja processes. The initial round stopped after the user flagged the
crashes and multiple instances; the later, explicitly requested investigation ran
one instance at a time. The handoff investigation left no owned debugger session
or tunnel open. Subsequent GUI probes should use the corrected startup/quit
procedure and verify the actual process exit status.

## Evidence

[Sanitized lifecycle evidence](samples/similarity-lifecycle-20260910.json) contains
eight case captures, process-exit outcomes, handoff cleanup status, and selected
native crash frames with source hashes. A probe's `ok` flag covers its in-process
assertions only; consult the separate `gui_exit` record before drawing shutdown
conclusions. The edit rerun was terminated by the parent agent; its launcher's
`forced: false` does not indicate a normal exit. Original
failed probes were retained, including the assertions that need correction.

Lifecycle actions use the companion API and real GUI/listener events; the final
restart case also checks authenticated MCP responses before and after restart.
Personal lifecycle acceptance is complete with the close-notification fix. Live
WinDbg handoff passed in the separate [ARM64 fixture capture](similarity-windbg-acceptance.md).
Native Ultimate support remains unvalidated.
