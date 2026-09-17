---
paths:
  - "tools/**"
  - "docs/**/*.md"
---

**A number measured against the VM is a reading of the binary that answered, not of the checkout it
was taken beside.** Those are routinely different things here, and nothing in the output says so.

`initialize` returns `serverInfo`, and its version carries the commit — `windbg-mcp
0.16.0+g57a47e9c`. That is the authority, and it is already in every eval record's `server` field
(`local_model_drive.SERVER_INFO`). **Read it before quoting any figure, and record it beside the
figure**, because a page of numbers with no build named cannot be re-derived or aged.

The case this exists for: the surface figures in
[`docs/apple-foundation-models.md`](../../docs/apple-foundation-models.md) were captured from a
listener answering **0.16.0** while the tree was **0.18.0** and the VM's own checkout sat on a
third, unrelated branch. The gap was visible the whole time and misread — `crash` measured
18,396 B against the 19,078 B [`docs/tool-surface.md`](../../docs/tool-surface.md) records, and a
3.6% difference was explained away as a serialisation detail for a full review round before anyone
asked which build had answered. Two smells, both of which should go straight to `serverInfo`:

- **A measurement that disagrees with a checked-in golden by a few percent.** A serialisation
  difference is a *structural* one — a wrapper per entry, a sorted key order — and it does not
  drift by single-digit percentages. A small unexplained gap is almost always a different build.
- **A number that does not move when the code under it moved**, or moves when it did not.

**The exe's date proves nothing**, which is the trap under the trap. The service runs whatever was
last built into `target\release`, the checkout moves without rebuilding, and a `git pull` on the
guest updates neither. A fresh timestamp on a binary built from a branch nobody remembers is
indistinguishable from a current one.

**Re-measuring means stopping the service**, because it holds `target\release\windbg-mcp.exe` open
and a build otherwise fails at the final replace with `Access is denied (os error 5)` — after
compiling successfully, so it reads as a flake. `sc stop windbg-mcp`, build, `sc start windbg-mcp`.
Check free space first (`Get-PSDrive C`): this guest fills up, and a release build that runs out
dies inside `rustc-LLVM ERROR: IO failure on output stream`, which names no disk.
`target\debug\incremental` is the usual culprit and is regenerable and git-ignored.

And **a narrowed surface must be captured from a listener serving that spec.** Filtering a full
`tools/list` by name leaves the cross-references the server strips for a client that cannot see the
tools they point at — 1,155 B on `crash` alone. One capture per `--tools` spec, or the narrowed
figures are inflated and internally consistent about it.
