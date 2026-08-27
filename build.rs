//! Stamps the revision this binary was built from into the version it reports.
//!
//! **Why a crate version is not an identity.** `serverInfo.version` and the transcript's `Start`
//! record both carried `CARGO_PKG_VERSION` and nothing else, so every build between two releases
//! called itself the same thing — and the changes that matter most to somebody reading a recording
//! or a bench log are exactly the ones that do not move it.
//! [#217](https://github.com/glslang/windbg-mcp/pull/217) changed what an *opener's result* says,
//! which no version, no tool count and no surface byte count can see (`FOLLOWUPS.md` item 46).
//! A short git revision is a content address for the source, and answers it.
//!
//! **The suffix is semver build metadata** (`0.11.0+g1a2b3c4`), which is ignored for precedence, so
//! nothing that compares versions is affected by its presence — a consumer that wants the release
//! reads up to the `+`.
//!
//! **`-dirty` is scoped to the same paths this asks Cargo to watch, and that is deliberate.** A
//! build script cannot re-run on "any file changed" and also name the git files it needs, because
//! emitting one `rerun-if-changed` replaces Cargo's default of watching the whole package. So both
//! the watch list and the dirty check are the inputs that actually reach the binary and its tests;
//! an edit to `docs/` leaves the stamp clean, which is true of the *code* this build is, rather
//! than a staleness bug. The alternative — watching the whole tree — reruns this on every prose
//! commit for a distinction nothing can act on.
//!
//! **And a dirty build carries a digest of what makes it dirty**, because `-dirty` alone is not an
//! identity: the workflow this exists for is edit, rebuild, evaluate, and two iterations on one
//! `HEAD` would otherwise stamp the same string while behaving differently — the exact confusion
//! the whole item is about, one level below the commit. The digest is over `git diff HEAD` for
//! those same inputs, so it is stable for a given working tree and different for any other.
//!
//! Absent git, an unpacked tarball, or a `git` that fails for any reason: the variable is empty and
//! the reported version is the bare crate version. A build must never fail over telemetry.
//!
//! # And stamps the PE version resource
//!
//! Rust embeds none by default, so `FileVersion`, `CompanyName` and `ProductName` were all empty on
//! every binary this project has ever shipped — which is one of the two causes
//! [`microsoft/apm#487`](https://github.com/microsoft/apm/issues/487) lists for the
//! `Trojan:Win32/Bearfoos.B!ml` verdict Defender handed a freshly built `windbg-mcp.exe` on
//! 2026-08-26 (`FOLLOWUPS.md` item 50). An `!ml` verdict is a machine-learning score rather than a
//! signature match, so a binary with no metadata at all is scored on what little there is; filling
//! the resource in is the free half of the fix, and the half that also makes Explorer's properties
//! dialog answer *which build is this*.
//!
//! **No new build input.** The resource is composed here from `CARGO_PKG_*` and literals, with no
//! `.rc` template and no icon file beside it, so [`INPUTS`] is unchanged and still names every file
//! that reaches the binary. A resource input added to the watch list and not to the dirty check (or
//! the reverse) would make two builds of one tree disagree about whether it is clean — the two are
//! one const precisely so they cannot.
//!
//! **A missing resource compiler warns rather than fails**, for the same reason the git stamp falls
//! back: `cargo check --target x86_64-pc-windows-msvc` from a Mac has no `rc.exe` and no `llvm-rc`,
//! and that check is a routine workflow here. What keeps the warning from being a silent release is
//! that the assertion lives where it can run — `mcp_smoke::the_binary_carries_a_pe_version_resource`
//! reads the resource back off the built exe, on Windows, which is the only host that builds one.

use std::process::Command;

/// The build inputs: what goes into the binary or the tests, and nothing else. The watch list, the
/// dirty check and the dirty digest all read this, so they cannot disagree about what a build is.
const INPUTS: [&str; 5] = ["src", "tests", "build.rs", "Cargo.toml", "Cargo.lock"];

fn main() {
    for input in INPUTS {
        println!("cargo::rerun-if-changed={input}");
    }
    // `HEAD` moves on a commit and on a checkout; the ref it names moves when the branch does,
    // which is what a `git commit` on the current branch changes without touching `HEAD` itself.
    // Watching only the first would keep a stale revision through every commit made on one branch.
    //
    // **Resolved through git rather than assembled from `.git/`**, because `.git` is not always a
    // directory: a `git worktree` checkout has a *file* there pointing at the real git directory,
    // so a literal `.git/HEAD` names a path that does not exist — and Cargo treats a watched path
    // that is missing as changed, re-running this script and recompiling the crate on every
    // otherwise no-op build. `--git-path` answers with the real location in every layout.
    let head_ref = git(&["symbolic-ref", "-q", "HEAD"]);
    for path in ["HEAD"]
        .into_iter()
        .chain(head_ref.as_deref())
        .filter_map(git_path)
    {
        println!("cargo::rerun-if-changed={path}");
    }
    // **A 32-bit build gets the full 4 GB of user address space, not 2.** `link.exe` defaults an
    // x86 image to 2 GB, and the x86 `cdb.exe` a debugger package ships is built the other way
    // (`IMAGE_FILE_LARGE_ADDRESS_AWARE`, read off the header) — so the engine a 32-bit worker
    // loads already expects the wider space. The headroom is not needed on the measurements taken:
    // against that same `cdb`, DbgEng reads a dump on demand rather than mapping it, and peak
    // virtual size stayed flat near 256 MB across dumps of 445 MB, 846 MB and 1,346 MB. This is
    // here so that the margin is a decision rather than an accident of the linker's default.
    //
    // Emitted from the build script rather than set in `.cargo/config.toml`, because a `RUSTFLAGS`
    // in the environment replaces that file's `rustflags` wholesale — this must not be something a
    // shell can drop without noticing.
    if std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("x86") {
        println!("cargo::rustc-link-arg-bins=/LARGEADDRESSAWARE");
    }
    let revision = revision().unwrap_or_default();
    println!("cargo::rustc-env=WINDBG_MCP_BUILD={revision}");
    version_resource(&revision);
}

/// Compose and compile the `VS_VERSION_INFO` resource — see the module comment for why.
///
/// The numeric `FILEVERSION`/`PRODUCTVERSION` and the `FileVersion`/`ProductName` strings come free
/// from `CARGO_PKG_*`; what is set here is the rest, and one override. **`ProductVersion` carries
/// the stamped identity** (`0.12.1+g1a2b3c4`) where `FileVersion` stays the bare release, which is
/// semver's own split between a release and the build metadata under it — so the properties dialog
/// answers the same question `serverInfo.version` does, and the field anything numeric compares is
/// left alone. **`FileDescription` is deliberately short**: Windows uses it as the application name
/// in Task Manager and in dialogs, where the package description would not fit; that goes in
/// `Comments`.
fn version_resource(revision: &str) {
    // Not `cfg!(windows)`: this is a question about the artefact, and a Mac cross-checking a
    // Windows target should take this path and report what it finds, not skip it silently.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let version = std::env::var("CARGO_PKG_VERSION").unwrap_or_default();
    let product_version = if revision.is_empty() {
        version
    } else {
        format!("{version}+{revision}")
    };

    let mut resource = winresource::WindowsResource::new();
    resource
        // The repo owner, which is also the registry namespace (`io.github.glslang/windbg-mcp`)
        // and the account an `Authenticode` certificate would eventually name — so a reader has
        // one identity to check rather than two that have to be reconciled.
        .set("CompanyName", "glslang")
        .set("FileDescription", "WinDbg MCP server")
        // Tracks `LICENSE`, which is where the year and the holder are authoritative.
        .set(
            "LegalCopyright",
            "Copyright (c) 2026 Gonçalo Carvalho. MIT.",
        )
        .set("OriginalFilename", "windbg-mcp.exe")
        .set("InternalName", "windbg-mcp.exe")
        .set("ProductVersion", &product_version);
    if let Ok(description) = std::env::var("CARGO_PKG_DESCRIPTION") {
        resource.set("Comments", &description);
    }
    if let Err(err) = resource.compile() {
        // Never fatal — see the module comment. The test is what makes this loud where it matters.
        println!("cargo::warning=no PE version resource was embedded: {err}");
    }
}

/// Where git keeps one of its own files, if that file exists.
///
/// The argument is a path **relative to the git directory**, not a revision — `--git-path @`
/// answers `.git/@`, which is nothing, so the branch's own file is found by asking
/// `symbolic-ref` for the ref name first. A detached head has no such ref (and `symbolic-ref -q`
/// says so by failing), and a branch whose ref is *packed* has no file: `--git-path` answers with
/// a path either way, and the `exists` check is what keeps a nonexistent one out of the watch
/// list, where Cargo would read it as perpetually changed.
fn git_path(spec: &str) -> Option<String> {
    let path = git(&["rev-parse", "--git-path", spec])?;
    std::path::Path::new(&path).exists().then_some(path)
}

/// `g<short sha>`, plus `-dirty.<digest>` when the build inputs differ from it.
///
/// The `g` prefix is `git describe`'s own convention for "the thing after this is a git revision",
/// and it keeps the suffix from being read as a number by anything scanning a version string.
fn revision() -> Option<String> {
    let short = git(&["rev-parse", "--short=8", "HEAD"])?;
    // Scoped to [`INPUTS`] rather than to the whole tree — see the module comment. The diff is
    // asked for directly rather than `status --porcelain` first: empty output is the same answer
    // to "is anything different", and a non-empty one is what the digest is taken over.
    let mut diff = vec!["diff", "HEAD", "--"];
    diff.extend(INPUTS);
    Some(match git(&diff) {
        // Clean: this build *is* that commit, and says so with nothing after it.
        Some(changes) if changes.is_empty() => format!("g{short}"),
        Some(changes) => format!("g{short}-dirty.{:08x}", fingerprint(&changes)),
        // The diff itself failed, which `rev-parse` succeeding makes exotic — but "could not tell"
        // must not be spelled the same way as "clean", since the bare form is a claim that this
        // build is exactly that commit.
        None => format!("g{short}-unknown"),
    })
}

/// A 32-bit FNV-1a of the working-tree diff — an identity tag, not a digest anybody should trust
/// against an adversary.
///
/// Hand-rolled because a build script is the wrong place to gain a dependency for eight lines —
/// which the `winresource` above does not change, since that one buys a resource compiler rather
/// than arithmetic. `DefaultHasher` would have been the obvious alternative and is wrong here for a
/// reason worth writing down: its output is explicitly not stable across Rust releases, so two
/// machines on different toolchains would tag one working tree two ways — which is the failure this
/// is meant to remove rather than relocate.
fn fingerprint(text: &str) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for byte in text.as_bytes() {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

/// One git invocation, or `None` if git is missing, this is not a repository, or it failed. Never
/// an error: a build that cannot describe itself still builds.
fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}
