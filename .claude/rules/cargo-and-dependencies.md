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

