---
paths:
  - "Cargo.toml"
  - "Cargo.lock"
  - "build.rs"
---

## Changing dbgscope (the DbgEng bindings)

`dbgscope` is a **git dependency pinned to an exact `rev`**, not a path dependency — a `windbg-mcp`
build pulls it from GitHub, so **local edits to a dbgscope checkout are invisible to a `windbg-mcp`
build until they are pushed** and the pin is moved. (The rule that a new DbgEng primitive is a
typed method rather than an `execute` text hatch is in `CLAUDE.md`, not here: it binds a Rust-only
change, which never loads this file.)

**`cargo update -p dbgscope` does not move the pin.** `Cargo.toml` names a 40-character `rev`, so
the update command only re-resolves *that* revision; the pin is moved by editing the `rev` and then
running `cargo update -p dbgscope` to refresh `Cargo.lock`. Commit both. (This file used to say the
update command alone was enough, which silently leaves you building the old code.)

**Develop against the feature branch, not a `[patch]`.** Push the dbgscope branch and point
`Cargo.toml`'s `rev` at that branch commit while iterating: it needs no local checkout on the build
machine, it works identically on every machine, and it travels through git like everything else.
Repoint before the dependent PR merges — and **"the merge commit" may not exist**, which is how
this was got wrong on 2026-08-27. dbgscope#120 was *rebase*-merged, so its commits landed on `main`
under new SHAs and the branch head this repo pinned was an ancestor of nothing there. It went on
building only because the merged branch had not been deleted yet; deleting it — the ordinary tidy —
would have left `main` unable to resolve its own dependency. So the rule is **repoint at whatever
`dbgscope`'s `main` now is**, and check rather than assume:

```console
git -C ../dbgscope merge-base --is-ancestor <pinned-rev> origin/main   # 0, or the pin is dangling
```

Both PRs merging together is the ordinary case, not a mistake, so the check belongs after the merge
as well as before it. A `[patch]` section still works for a quick local `cargo check` but must never
be committed:

```toml
[patch.'https://github.com/glslang/dbgscope']
dbgscope = { path = "../dbgscope" }
```
`git checkout -- Cargo.toml Cargo.lock` afterwards.

**A green dbgscope PR says nothing about Miri**, since 2026-08-22: it is by far the longest job
there (9 minutes median against `ci.yml`'s 1) and had never failed in a hundred runs, so it runs on
the merge to `main`, weekly for nightly-toolchain drift, and on `workflow_dispatch` — **not** on
pull requests. Dispatch it against the branch when a change touches unsafe code; the alternative is
`main` going red after your merge. A path filter was measured and rejected there, and the workflow's
own header says why, so it is not worth re-proposing.

**Both repos require an approving review**, and a solo maintainer cannot self-approve, so a green
PR still needs `gh pr merge --admin`. In this harness that call is refused by the permission
classifier — so **the human merges**, and an agent's job ends at "green and waiting". Plan the two
PRs around that: dbgscope first, then repoint and re-verify.

## A dependency a grep cannot see, and an "outdated" that is not one

**`dbgscope`'s `windows-core` is required by a macro expansion, not by any source path.** Nothing in
that crate writes `windows_core::` — every use is `windows::core::`, the re-export — so searching for
the crate name finds nothing and the dependency reads as dead. It is not: the
`#[windows::core::implement(..)]` attribute on the two callback objects in `dbgscope/src/dbgeng.rs`
expands to **absolute `::windows_core::` paths**. Remove the dependency and the build fails with
*"could not find `windows_core` in the list of imported crates"*, which is the giveaway — `::name`
resolves against extern crates only, so a `use windows::core as windows_core;` alias does not satisfy
it either. Both were tried on 2026-09-15; both fail.

The general shape, which is the part worth carrying: **a proc macro's expansion is a dependency
edge, and no amount of reading the source shows it.** A dependency is unused when the compiler says
so, not when a grep does.

**And "the compiler says so" means every target, not `cargo build`.** A bare build selects this
package's library and binary targets — not its tests, examples or benches — so a dependency whose
only consumer is one of those, or a feature, is certified unused by a command that never compiled
its consumer. This repo has two entries that would fall for exactly that: `windows-sys` appears
twice, the second a dev-dependency taking
`Win32_Storage_FileSystem` and `Win32_System_Console` so `mcp_smoke` can read a PE version resource
and check a worker's console; and `tokio` appears twice, the second a dev-dependency taking
`test-util` for `src/progress.rs`'s heartbeat assertions. Delete either dev entry and `cargo build`
stays green while the test targets stop compiling.

So the check is this repo's own gate — `cargo test` and `cargo clippy --all-targets` — and a
dependency behind an optional feature needs that feature turned on as well, since no target in the
default set reaches it. `--all-targets` is what compiles the examples and `tests/`; it is the
minimum, and it is what the `windows-core` experiment above was run with.

**And its version is pinned to `windows`, not stale.** `windows 0.62.2` requires
`windows-core ^0.62.2`, while crates.io's latest `windows-core` is **0.100.0** (2026-09-15) — the
sub-crate is versioned independently and has raced far ahead of the umbrella. A dependency check will
flag 0.62.2 as outdated. Taking 0.100 is not an upgrade but a **second copy in the graph**: the macro
then emits paths into 0.100 while the interfaces still come from `windows`'s 0.62.2, and the build
fails with `the trait bound IDebugOutputCallbacks: windows_core::Interface is not satisfied`. It also
wants Rust 1.95 against that crate's 1.88 floor. Move it only when `windows` moves, and keep the two
in step. The reasoning is written beside the dependency in `dbgscope`'s own `Cargo.toml`, which is
where someone about to bump it is looking.
