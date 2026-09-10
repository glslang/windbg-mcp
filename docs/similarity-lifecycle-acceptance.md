# Similarity lifecycle acceptance — 2026-09-10

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
| Rebase during export | Partial evidence | Comparison became stale; probe subsequently used an incorrect assertion about retained stale results |
| Close a view during export | Not established | Probe did not establish completed view closure before comparison completion |
| Listener restart during comparison | Not run | Further GUI testing stopped after repeated shutdown crashes |
| Normal application quit | Failed | Direct Qt quit left processes alive; application Quit produced repeatable native aborts |
| Guarded WinDbg handoff | Not run | Reachable WinDbg service reported zero sessions; dump-based follow-up stopped before opening a session |

Cancelled/stale result retrieval may preserve partial evidence. Stale navigation
must refuse the old generation; requiring every results call to throw was a probe
error, not the companion contract. The rebase run is therefore retained as partial
evidence rather than counted as full acceptance.

The metadata fix handles `BinaryDataNotification.data_metadata_updated`, which
view-level comment changes emit. It invalidates cached analysis, advances the view
generation, and requests cancellation of affected comparisons. The real rerun
refused stale navigation, and all 180 companion tests plus Ruff passed. This fix
does not address the separate native shutdown crash.

## Shutdown crash and process cleanup

The recorded native crashes terminate with `SIGABRT` after an invalid-free report
from the allocator, through `QObjectPrivate::deleteChildren()` and
`QWidget::~QWidget()`. Repeated reports have the same leading stack frames and BN
image offsets. The loaded Qt/PySide libraries in the inspected report come from
the BN application bundle; no second Qt installation was observed there.

The cause is not yet isolated to Binary Ninja, the companion, or the probe.
An earlier ARM64 capture process (PID 7840) also has this crash signature, so
observing that a process has exited is insufficient evidence of clean shutdown.
Its completed comparison data remains valid; normal-quit acceptance does not.

All owned GUI probes were stopped and a subsequent process check found no running
Binary Ninja processes. No new GUI runs were launched after the user flagged the
crashes and multiple instances. The handoff investigation left no owned debugger
session or tunnel open. Further GUI acceptance should first isolate the crash in
one disposable instance and verify its actual exit status.

## Evidence

[Sanitized lifecycle evidence](samples/similarity-lifecycle-20260910.json) contains
eight case captures, process-exit outcomes, handoff cleanup status, and selected
native crash frames with source hashes. A probe's `ok` flag covers its in-process
assertions only; consult the separate `gui_exit` record before drawing shutdown
conclusions. The edit rerun was terminated by the parent agent; its launcher's
`forced: false` does not indicate a normal exit. Original
failed probes were retained, including the assertions that need correction.

These runs use the companion API and real GUI/listener lifecycle, rather than an
additional MCP transport capture. They do not establish live WinDbg handoff,
active listener restart, full view-close acceptance, or native Ultimate support.
