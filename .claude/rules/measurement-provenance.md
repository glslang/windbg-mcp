---
paths:
  - "tools/**"
  - "docs/**/*.md"
  - "src/**/*.rs"
  - "tests/**/*.rs"
  - "build.rs"
---

## "This fails safe" is a hypothesis, not a property you can read off the code

**A claim about which *direction* a guard is wrong in needs a test as much as a number does.** The
rest of this file is about numbers — which build answered, which listener was captured — and the
same standard applies to a sentence like *this errs towards refusing*, *the fallback is
conservative*, or *a false positive only costs a handle*. Those feel self-evident while you are
writing the code that makes them true, and they are the claims that have actually been wrong here.

Three from one afternoon on `set_breakpoint`'s command guard, each stated in a commit message
before it was checked:

- *"An unbalanced quote hands back the original, which is the safe direction."* It is not. A quote
  sitting against a name leaves `.kill"` as the token, matching nothing — so the one command the
  scanner could not parse was the one it waved through. Found because a test for a *different* case
  failed on the `\r\n` variant.
- *"A `gc` in a breakpoint command does not resume the target."* Measured through a tool that was
  silently dropping the `command` argument, so every breakpoint under test had no command at all. A
  plain breakpoint stopping is correct behaviour. The claim reached a merged PR.
- *"`.printf` is screened the same way the location is, so the two agree."* They agree on what
  counts and not on what a false positive **costs** — retiring a handle the caller reopens, against
  refusing the call outright. Same predicate, different price, and the price decides how
  conservative the reading should be.

The test is cheap and the habit is the whole of it: **write the input that would prove you wrong and
run it.** A characterisation assertion is a fine home for the answer when the gap stays open —
`server::tests::a_breakpoint_command_that_changes_the_target_is_refused` pins three bypasses that
are closed and one class that is not, so the limit is recorded rather than implied. And
**mutation-verify a guard's test**: back the guard out and watch the assertion fail, or it may be
passing for a reason that has nothing to do with the guard.

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
