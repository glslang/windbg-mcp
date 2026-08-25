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
    println!(
        "cargo::rustc-env=WINDBG_MCP_BUILD={}",
        revision().unwrap_or_default()
    );
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
/// Hand-rolled because this crate has no build dependencies and a build script is the wrong place
/// to gain one for eight lines. `DefaultHasher` would have been the obvious alternative and is
/// wrong here for a reason worth writing down: its output is explicitly not stable across Rust
/// releases, so two machines on different toolchains would tag one working tree two ways — which
/// is the failure this is meant to remove rather than relocate.
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
