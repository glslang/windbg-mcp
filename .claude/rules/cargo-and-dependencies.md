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


## Verifying from a machine with no Windows

**The whole crate type-checks from the Mac, which this repo believed it could not.** `cargo
check` does not link, so `rustup target add x86_64-pc-windows-msvc` (and the `aarch64` one) is
enough to run `cargo check --target <msvc> --all-targets` and `cargo clippy` over `src/`,
`tests/` *and* the dependency, on a machine with no Windows anywhere. It takes seconds and needs
no VM. What it does **not** do is run anything: a behavioural claim still wants `cargo test` on
the VM, and the debugger tiers still want a real `dbgeng.dll`. But every mistake that is a *type*
error — a wrong signature, a missing `windows` feature, an API that moved under a dependency bump
— is answerable here, and that is most of what a dependency bump breaks. Doing the `dbgscope`
split this way caught a `windows` feature trimmed by module path (`IMAGE_NT_HEADERS64` is gated
behind `Win32_System_SystemInformation`, not the `Debug` feature its path suggests) that would
otherwise have been a red VM build.

**One warning from that check is expected and is not a break.** `build.rs` compiles the binary's PE
version resource (item 50 — an empty `FileVersion`/`CompanyName`/`ProductName` is half of why
Defender scored this project's own exe as `Bearfoos.B!ml`), and that needs `rc.exe`, which no Mac
has. The script prints `cargo::warning=no PE version resource was embedded: …` and carries on,
because failing there would cost this whole workflow for the sake of metadata. Which means the
warning is the *only* thing between a Windows build that quietly lost its resource and a release, so
the assertion is a test instead — `mcp_smoke::the_binary_carries_a_pe_version_resource`, which reads
the resource back through `GetFileVersionInfoW` on the one host that can build one. To check that
test still catches what it is for, break the compiler rather than the code:
`$env:RC_PATH = "C:\nope\rc.exe"`, touch `build.rs`, re-run it, then unset and touch again. And note
the resource is composed **in `build.rs`** from `CARGO_PKG_*` and literals for a reason: an `.rc`
template or an icon file would be a new build input, and `INPUTS` is one const precisely so the
watch list and the dirty check cannot disagree about what a clean build is.

**A `[patch]` cannot verify against a repo that does not exist yet.** Cargo resolves the original
source *before* applying the patch, so pointing one at a local checkout still fetches the git URL
and fails on a repo not yet created or renamed — which is exactly the middle of a rename. Swap the
dependency itself to `path = "../dbgscope"` for the check and restore it afterwards; the `[patch]`
recipe above works only once the remote is real.

**A dependency's source can be read on the Mac, and the copy there may not be the pinned one.**
`~/.cargo/registry/src/` holds only what this machine has *fetched*, and nothing fetches after a
bump the Mac never built — on 2026-08-24 it had `rmcp-3.1.2` while `Cargo.lock` pinned `3.1.4`
(dependabot #207 bumped it two days earlier). That reads as nothing at all: the API was unchanged,
so a change written against the older source compiled on the VM first try, and it was luck rather
than method.

**So `cargo fetch --locked`, and then let Cargo say where the source is** — do not build the path:

```console
cargo fetch --locked
cargo metadata --locked --format-version 1 |
  jq -r '.packages[] | select(.name=="rmcp")
         | "\(.version) \(.manifest_path | rtrimstr("/Cargo.toml"))"'
```

The fetch resolves and downloads without compiling, so the Windows-only dependencies are no
obstacle, and it takes seconds. `--locked` on both is not decoration: bare `cargo fetch`
re-resolves whenever `Cargo.toml` and `Cargo.lock` are out of step — which is exactly what the
middle of a `dbgscope` `rev` bump is — and would unpack a version nobody reviewed while moving the
pin under you. Neither command touches the lock (measured).

**Reading the path out of `cargo metadata` rather than assembling one is the whole point**, because
a hand-built `registry/src/*/<crate>-<ver>/` is wrong three different ways and this is wrong none:
the `*` matches a copy fetched earlier as readily as the pinned one (`tokio-1.53.0` and `1.53.1`
are both unpacked here); a crate can be in the graph twice, so a name alone does not identify a
version (`syn` is at 2.0.117 and 3.0.3); and a **git** dependency is not under `registry/src` at
all — `dbgscope` is at `~/.cargo/git/checkouts/dbgscope-<hash>/<short-rev>/`, which is both the
dependency most worth reading here and the one a registry path misses silently.

Anything read this way is still a claim about source, not about behaviour; `cargo test` on the VM is
where the pinned version is the one that compiles.

