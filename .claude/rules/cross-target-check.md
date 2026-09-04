---
paths:
  - "src/**/*.rs"
  - "tests/**/*.rs"
  - "build.rs"
---

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
recipe in `.claude/rules/cargo-and-dependencies.md` works only once the remote is real.

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

