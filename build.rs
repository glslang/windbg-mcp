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
//! Absent git, an unpacked tarball, or a `git` that fails for any reason: the variable is empty and
//! the reported version is the bare crate version. A build must never fail over telemetry.

use std::path::Path;
use std::process::Command;

/// The build inputs: what goes into the binary or the tests, and nothing else. Both the watch list
/// and the dirty check read this, so the two cannot disagree about what a clean build is.
const INPUTS: [&str; 5] = ["src", "tests", "build.rs", "Cargo.toml", "Cargo.lock"];

fn main() {
    for input in INPUTS {
        println!("cargo::rerun-if-changed={input}");
    }
    // `HEAD` moves on a commit and on a checkout; the ref it names moves when the branch does, which
    // is what a `git commit` on the current branch changes without touching `HEAD` itself. Watching
    // only the first would keep a stale revision through every commit made on one branch.
    println!("cargo::rerun-if-changed=.git/HEAD");
    if let Some(head_ref) = head_ref() {
        println!("cargo::rerun-if-changed=.git/{head_ref}");
    }
    println!(
        "cargo::rustc-env=WINDBG_MCP_BUILD={}",
        revision().unwrap_or_default()
    );
}

/// The ref `HEAD` points at, or `None` on a detached head — where there is no second file to watch
/// and `HEAD` itself already holds the revision.
fn head_ref() -> Option<String> {
    let head = std::fs::read_to_string(".git/HEAD").ok()?;
    let named = head.trim().strip_prefix("ref: ")?.to_string();
    // A packed ref has no file of its own, so watching it would name a path that does not exist.
    Path::new(".git").join(&named).exists().then_some(named)
}

/// `g<short sha>`, plus `-dirty` when the build inputs differ from it.
///
/// The `g` prefix is `git describe`'s own convention for "the thing after this is a git revision",
/// and it keeps the suffix from being read as a number by anything scanning a version string.
fn revision() -> Option<String> {
    let short = git(&["rev-parse", "--short=8", "HEAD"])?;
    // Scoped to [`INPUTS`] rather than to the whole tree — see the module comment. `--porcelain`
    // prints one line per changed path and nothing at all when there are none, which is the only
    // thing this needs to know.
    let mut status = vec!["status", "--porcelain", "--"];
    status.extend(INPUTS);
    let dirty = git(&status).is_some_and(|out| !out.is_empty());
    Some(format!("g{short}{}", if dirty { "-dirty" } else { "" }))
}

/// One git invocation, or `None` if git is missing, this is not a repository, or it failed. Never
/// an error: a build that cannot describe itself still builds.
fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}
