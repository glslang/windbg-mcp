//! Time Travel Debugging recording support.
//!
//! There is no in-process recording API, so we shell out to `TTD.exe` (the
//! standalone recorder). Replay of the resulting `.run` trace is done through the
//! normal engine path ([`crate::engine`] → `open_trace`).

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime};

/// A recorder's architecture, and the two different names the installers give it.
///
/// Worth a type rather than a string because the two layouts disagree about the spelling: the SDK
/// ships `Debuggers\x64`, while the store package's payload directory for the same thing is
/// `amd64`. Getting that crossed silently selects a recorder for the wrong architecture.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Arch {
    Arm64,
    X64,
    X86,
}

impl Arch {
    /// The one this build of `windbg-mcp` is, which is the best guess available here about what it
    /// will be asked to record.
    ///
    /// Deliberately the *binary's* architecture and not the machine's, for the same reason
    /// `setup.md` matches the engine DLLs to the executable: an x64 build running under emulation
    /// on an ARM64 host is being used for x64 work, and its debuggee is far more likely to be x64
    /// than native.
    fn of_this_build() -> Self {
        match std::env::consts::ARCH {
            "aarch64" => Self::Arm64,
            "x86" => Self::X86,
            // x86_64, and anything unforeseen: x64 is the overwhelmingly common case and the only
            // one every installer ships.
            _ => Self::X64,
        }
    }

    /// The SDK's directory under `Windows Kits\10\Debuggers`.
    pub(crate) fn sdk_dir(self) -> &'static str {
        match self {
            Self::Arm64 => "arm64",
            Self::X64 => "x64",
            Self::X86 => "x86",
        }
    }

    /// The store package's payload directory, which spells x64 differently.
    pub(crate) fn payload_dir(self) -> &'static str {
        match self {
            Self::Arm64 => "arm64",
            Self::X64 => "amd64",
            Self::X86 => "x86",
        }
    }
}

/// Every architecture, this build's first.
///
/// An **ordering, not a filter**. Recording an emulated x64 process on an ARM64 host genuinely
/// wants the `amd64` recorder, so no architecture is excluded — but the native one is tried first
/// because it is right whenever the debuggee is what this build is for, which is the ordinary case.
///
/// The honest selector is the *target's* architecture, and nothing here knows it: `record_trace`
/// receives a command line, and resolving that to a file to read a PE header from is a different
/// problem with its own failure modes. When this guess is wrong, put the right recorder on `PATH`
/// — [`find_ttd`] looks there first, and that is the documented escape hatch
/// ([#131](https://github.com/glslang/windbg-mcp/issues/131)).
fn probe_order() -> [Arch; 3] {
    match Arch::of_this_build() {
        Arch::Arm64 => [Arch::Arm64, Arch::X64, Arch::X86],
        Arch::X64 => [Arch::X64, Arch::Arm64, Arch::X86],
        Arch::X86 => [Arch::X86, Arch::X64, Arch::Arm64],
    }
}

/// Best-effort search for `TTD.exe` from an installed Windows debugging toolset.
pub fn find_ttd() -> Option<PathBuf> {
    // 1. Anything already on PATH. First, and so the way to override everything below.
    if let Some(p) = search_path("TTD.exe") {
        return Some(p);
    }
    // 2. Classic SDK "Debugging Tools for Windows".
    for arch in probe_order() {
        let p = PathBuf::from(format!(
            r"C:\Program Files (x86)\Windows Kits\10\Debuggers\{}\TTD\TTD.exe",
            arch.sdk_dir()
        ));
        if p.is_file() {
            return Some(p);
        }
    }
    // 3. Modern WinDbg (MSIX) package layout.
    find_in_windowsapps()
}

fn search_path(exe: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(exe))
        .find(|c| c.is_file())
}

fn find_in_windowsapps() -> Option<PathBuf> {
    let root = PathBuf::from(r"C:\Program Files\WindowsApps");
    // Reading WindowsApps may be denied; treat any error as "not found".
    let entries = std::fs::read_dir(&root).ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("Microsoft.WinDbg") {
            continue;
        }
        let base = entry.path();
        // Architecture-specific first, in the order above: an ARM64 package carries *all three*
        // payloads, so whichever is probed first is what a package like that always returns.
        for arch in probe_order() {
            let candidate = base.join(format!(r"{}\TTD\TTD.exe", arch.payload_dir()));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        // A layout with no architecture directory at all, last: there is only ever one of these, so
        // reaching it means none of the above matched and it is the whole of what the package has.
        let candidate = base.join(r"TTD\TTD.exe");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// How long to watch a freshly-spawned `TTD.exe` for an immediate failure
/// (e.g. the access-denied that happens when not elevated) before assuming
/// recording has genuinely started.
const STARTUP_WATCH: Duration = Duration::from_millis(2500);

/// Starts recording a TTD trace by launching `target` under `TTD.exe`, writing the
/// `.run`/`.idx` into `out_dir`.
///
/// Recording is usually long-lived — it finalizes only when the recorded process exits — so the
/// ordinary success path is fire-and-forget. But TTD fails *fast* on common misconfigurations,
/// most notably "Administrative privileges are required" when the server isn't elevated, so we
/// capture its startup output to a log file and watch the recorder for [`STARTUP_WATCH`].
///
/// **Exiting inside that window is not itself a failure**, which is what the watch used to assume
/// ([#233](https://github.com/glslang/windbg-mcp/issues/233)): a short target — `hostname.exe`
/// finishes in 156ms — runs to completion before the watch elapses, and the recorder then exits
/// **0** having written a finished trace. So the decision is on the recorder's exit *status* and
/// on what it left in `out_dir`, and this returns one of three answers: recording underway, a
/// recording already complete (naming the trace, which is the more useful answer of the two), or
/// the failure the watch was built to surface.
///
/// Requires Administrator privileges.
pub fn record_launch(
    ttd: &Path,
    out_dir: &str,
    target: &str,
    env: &[String],
    working_dir: Option<&str>,
) -> Result<String, String> {
    // Validate the caller-supplied environment and target up front — before any filesystem side
    // effect — so a malformed one doesn't leave a stray directory and log file behind.
    let mut parsed_env = Vec::with_capacity(env.len());
    for kv in env {
        parsed_env.push(split_env_entry(kv)?);
    }
    let argv = split_target(target, working_dir)?;

    // Resolve out_dir to an absolute path. When `working_dir` is set, TTD.exe would otherwise
    // resolve a relative `-out` against the *target's* cwd — mismatching where we create the
    // directory and log (the server's cwd). `absolute` makes it absolute lexically: no cwd
    // dependence, and unlike `canonicalize` it needs no existing path and adds no `\\?\` prefix.
    let out_dir = std::path::absolute(out_dir)
        .map_err(|e| format!("failed to resolve output dir `{out_dir}`: {e}"))?;
    std::fs::create_dir_all(&out_dir)
        .map_err(|e| format!("failed to create output dir `{}`: {e}", out_dir.display()))?;

    // Capture the recorder's banner/diagnostics to a file (not a pipe): a pipe would
    // deadlock a long, successful recording once its buffer filled and we stopped
    // draining it.
    let log_path = out_dir.join("ttd_record.log");
    let log = std::fs::File::create(&log_path)
        .map_err(|e| format!("failed to create log `{}`: {e}", log_path.display()))?;
    let log_err = log
        .try_clone()
        .map_err(|e| format!("failed to set up TTD logging: {e}"))?;

    let mut cmd = Command::new(ttd);
    cmd.arg("-accepteula")
        .arg("-out")
        .arg(&out_dir)
        // `-launch` is last, and the program and each of its arguments follow it as separate
        // entries. TTD.exe's own help requires both — "This must be the last option in the
        // command-line, followed by the program + <arguments>" — and its example is
        // `TTD.exe ping.exe msn.com`. Handing the whole line over as one `.arg` made TTD look for
        // a file literally named `cmd.exe /c dir C:\...`, which it reported as "cannot find the
        // file specified": a message pointing at the program rather than at the quoting
        // ([#232](https://github.com/glslang/windbg-mcp/issues/232)).
        .arg("-launch")
        .args(&argv)
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err));
    // Configured kernel connections do not reach the recorder. TTD.exe launches `target` with
    // this environment inherited, and the recorded target is an arbitrary binary — frequently the
    // least trustworthy program on the machine, which is usually *why* it is being recorded. Same
    // scrub as `engine::spawn_worker`, for the same reason: this is the other process this server
    // creates, and nothing about recording needs a KDNET key.
    for name in crate::kdconn::env_names() {
        cmd.env_remove(name);
    }
    // And the listener's bearer token, which is the same hazard one step further on: the recorded
    // target is chosen by the caller and inherits this environment, so a token left here is a
    // credential handed to an arbitrary binary. With it, that binary could dial the listener on
    // loopback and claim the server once the current holder goes quiet. Stripped in both places
    // this server creates a process, because either one is enough to leak it.
    crate::client::strip_credentials(&mut cmd);
    // Pass through the validated environment (e.g. an anti-analysis env guard) and cwd to the
    // recorded target. TTD.exe launches `target` with this environment inherited. Applied after
    // the scrub above, so an entry the caller passed deliberately still wins.
    for (key, val) in parsed_env {
        cmd.env(key, val);
    }
    if let Some(dir) = working_dir {
        cmd.current_dir(dir);
    }
    // Read before the spawn, so a `.run` an *earlier* recording left in this same `out_dir` can
    // never be mistaken for this one's. See [`finished_trace`].
    let started = SystemTime::now();

    // Under the server's spawn lock, like every other process this server creates. Nothing here
    // wants an inherited handle — but a worker being spawned at this moment has its protocol
    // channel marked inheritable, and marking is process-wide: a recorder started inside that
    // window would inherit that worker's message write end and, since it outlives the whole
    // recording, keep the pipe from ever reporting EOF when the worker exits. That session would
    // then never settle. See `engine::SPAWN_LOCK`.
    let mut child = {
        let _one_spawn_at_a_time = crate::engine::spawn_guard();
        cmd.spawn()
    }
    .map_err(|e| format!("failed to launch TTD.exe: {e}"))?;

    let pid = child.id();

    // Watch for an early exit — which is a fast failure, or a target that has already finished.
    let deadline = Instant::now() + STARTUP_WATCH;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let log_text = std::fs::read_to_string(&log_path).unwrap_or_default();
                if !status.success() {
                    // The case the watch was built for: the recorder refused. Report the captured
                    // reason (e.g. the access-denied message).
                    let detail = failure_detail(&log_text)
                        .unwrap_or("see log for details")
                        .to_string();
                    return Err(format!(
                        "TTD recording failed to start ({status}): {detail}. Full log: {}",
                        log_path.display()
                    ));
                }
                // Exited *successfully*: the target ran to completion inside the watch window, so
                // the recording is not merely underway but done. Say so and name the trace — a
                // caller told "recording started, finalizes when the target exits" about a target
                // that has already exited would go looking for a file this function knows the
                // name of.
                return match finished_trace(&log_text, &out_dir, started) {
                    Some(trace) => Ok(format!(
                        "TTD recording complete (recorder pid {pid} exited successfully): \
                         `{target}` ran to completion inside the {}ms startup watch, so the whole \
                         run is recorded. The trace is finished and ready to `open_trace`: `{}`. \
                         Recorder log: {}",
                        STARTUP_WATCH.as_millis(),
                        trace.display(),
                        log_path.display()
                    )),
                    // Exit 0 and nothing on disk is neither of the two answers above, and saying
                    // "complete" about a trace that is not there would be the same class of
                    // mistake this arm exists to fix.
                    None => Err(format!(
                        "TTD.exe exited successfully but wrote no .run trace to `{}`. Full log: {}",
                        out_dir.display(),
                        log_path.display()
                    )),
                };
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    // Still running after the watch window → recording is underway.
                    return Ok(format!(
                        "TTD recording started (recorder pid {pid}). Tracing `{target}`; \
                         output (.run/.idx) goes to `{}`. Recording finalizes when the \
                         target exits — there is no trace to open until then. Recorder log: {}",
                        out_dir.display(),
                        log_path.display()
                    ));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(format!("failed while waiting on TTD.exe: {e}")),
        }
    }
}

/// Splits a `KEY=VALUE` environment entry. The value may itself contain `=`; the key must
/// be non-empty. Returns a clear error for malformed input rather than silently dropping it.
fn split_env_entry(entry: &str) -> Result<(&str, &str), String> {
    match entry.split_once('=') {
        Some((key, val)) if !key.is_empty() => Ok((key, val)),
        _ => Err(format!("invalid env entry `{entry}` (expected KEY=VALUE)")),
    }
}

/// Splits a caller's `target` into the program to launch and its arguments.
///
/// `TTD.exe` takes them as separate argv entries and [`Command::arg`] makes exactly one entry per
/// call, so the whole string in one call was a filename with spaces in it as far as the recorder
/// was concerned (#232).
///
/// Refuses an empty target rather than letting `TTD.exe` report it, because at the point this runs
/// nothing has been created yet — the same reason the environment is validated here.
///
/// `working_dir` is the caller's, and is taken because the probe below has to ask about the
/// directory the *recorder* will use — see [`names_a_file`].
fn split_target(target: &str, working_dir: Option<&str>) -> Result<Vec<String>, String> {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return Err(
            "`target` is empty — pass the program to record, with any arguments after it".into(),
        );
    }
    // A path that exists exactly as written is one program, not a command line — even when it
    // holds spaces, and `C:\Program Files\...` is where they live. This is what passing the whole
    // string as a single argument got right, and splitting on whitespace would look for
    // `C:\Program`; quoting only becomes necessary once such a path is followed by arguments.
    // Skipped when the caller has quoted anything, since then they have said how it parses.
    if !trimmed.contains('"') && names_a_file(trimmed, working_dir) {
        return Ok(vec![trimmed.to_string()]);
    }
    let argv = split_argv(trimmed);
    match argv.first() {
        Some(program) if !program.trim().is_empty() => Ok(argv),
        // Reachable from a target that is nothing but quotes: `""` parses to one argument, and
        // that argument is the empty program.
        _ => Err(format!(
            "`target` names no program to launch (`{target}` parses to no program)"
        )),
    }
}

/// Does `candidate` name a file **where `TTD.exe` will look for it**?
///
/// Not the same question as [`Path::is_file`], and getting it wrong does not produce an error.
/// The recorder is spawned with the caller's `working_dir` as its cwd and resolves a relative
/// program against that, so a probe against *this process's* cwd answers for a directory nothing
/// in the recording is using — the probe then declines, the target is split on its spaces, and
/// `TTD.exe` launches whatever the first token resolves to.
///
/// Measured on `TTD.exe` 1.01.11 with `target: ".\\a program.exe"` and a `working_dir` holding
/// that file: the split handed it `.\a` and `program.exe`, and it recorded **`a.exe`** — a
/// different program — into a 29 MB trace that `record_trace` then reported as a complete
/// recording. A wrong answer rather than a refusal, which is why this asks the right directory
/// rather than falling back to both.
///
/// Worth knowing for the near miss beside it: TTD does **not** search its own cwd for a *bare*
/// relative name (`aprogram.exe` in the cwd is not found; `.\aprogram.exe` is). So a bare name is
/// a target neither this nor the code before it could launch, and keeping it whole is still the
/// better answer — it fails naming the program the caller asked for.
fn names_a_file(candidate: &str, working_dir: Option<&str>) -> bool {
    let path = Path::new(candidate);
    match working_dir {
        Some(dir) if path.is_relative() => Path::new(dir).join(path).is_file(),
        _ => path.is_file(),
    }
}

/// Parses a command line into argv the way Windows does.
///
/// These are `CommandLineToArgvW`'s rules, and they are the right ones because the string makes a
/// round trip: this splits it, [`Command::arg`] re-quotes each entry by the matching rules, and
/// `TTD.exe` — then the recorded target — parse the result back. Whitespace separates (space and
/// tab only, which is what Windows treats as a separator); double quotes group; a backslash is
/// literal unless it runs into a quote, where `2n` backslashes are `n` backslashes plus a
/// delimiter and `2n+1` are `n` plus a literal quote; and `""` inside a quoted argument is a
/// literal quote that leaves it quoted.
///
/// Not a general shell splitter: there is no variable expansion, no globbing and no single-quote
/// handling, because none of those is what will parse the line at the other end.
fn split_argv(line: &str) -> Vec<String> {
    let chars: Vec<char> = line.chars().collect();
    let mut argv = Vec::new();
    let mut current = String::new();
    // Distinct from `current.is_empty()`: `""` is an argument, and an empty one.
    let mut in_arg = false;
    let mut in_quotes = false;
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '\\' => {
                let mut slashes = 0;
                while i < chars.len() && chars[i] == '\\' {
                    slashes += 1;
                    i += 1;
                }
                if i < chars.len() && chars[i] == '"' {
                    for _ in 0..slashes / 2 {
                        current.push('\\');
                    }
                    if slashes % 2 == 1 {
                        // The quote is escaped: consume it as a literal.
                        current.push('"');
                        i += 1;
                    }
                    // An even run leaves the quote for the arm below, where it delimits.
                } else {
                    for _ in 0..slashes {
                        current.push('\\');
                    }
                }
                in_arg = true;
            }
            '"' => {
                i += 1;
                if in_quotes && i < chars.len() && chars[i] == '"' {
                    current.push('"');
                    i += 1;
                } else {
                    in_quotes = !in_quotes;
                }
                in_arg = true;
            }
            ' ' | '\t' if !in_quotes => {
                if in_arg {
                    argv.push(std::mem::take(&mut current));
                    in_arg = false;
                }
                i += 1;
            }
            c => {
                current.push(c);
                in_arg = true;
                i += 1;
            }
        }
    }
    if in_arg {
        argv.push(current);
    }
    argv
}

/// The finished `.run` this recorder wrote, if it wrote one.
///
/// Asked only of a recorder that has already exited **successfully**, which is what makes either
/// answer meaningful: a trace named in the log is complete, and its absence is a real anomaly
/// rather than a recording still in progress.
///
/// The log is the primary source because it names the file exactly. The directory is a fallback
/// for a recorder whose log does not — the format of that line is TTD's, not ours — and it is
/// restricted to a file written since the recorder was spawned, so a `.run` an earlier recording
/// left in the same `out_dir` cannot be reported as this one's.
fn finished_trace(log: &str, out_dir: &Path, since: SystemTime) -> Option<PathBuf> {
    if let Some(named) = trace_named_in(log) {
        let path = PathBuf::from(named);
        if path.is_file() {
            return Some(path);
        }
    }
    // Coarse timestamps are a real filesystem (FAT's are two-second), so the window is widened
    // rather than compared exactly. The cost of being wrong here is bounded: at worst it names a
    // trace from a recording seconds old, in a directory this recording also wrote to.
    let floor = since.checked_sub(Duration::from_secs(2)).unwrap_or(since);
    let mut newest: Option<(SystemTime, PathBuf)> = None;
    for entry in std::fs::read_dir(out_dir).ok()?.flatten() {
        let path = entry.path();
        if !path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("run"))
        {
            continue;
        }
        let Ok(written) = entry.metadata().and_then(|m| m.modified()) else {
            continue;
        };
        if written >= floor && newest.as_ref().is_none_or(|(seen, _)| written > *seen) {
            newest = Some((written, path));
        }
    }
    newest.map(|(_, path)| path)
}

/// The path TTD names as the trace it finished writing.
///
/// Several of its lines carry the same path and they mean different things: a real log has
/// `Initializing the recording of process (PID:N) on trace file: <path>` and
/// `Recording has started … on trace file: <path>` before the target has run, and
/// `Full trace dumped to <path>` once it is finished. Only the last of those is matched, so this
/// cannot name a trace that was begun and never finalised. Read in reverse, so that if a log ever
/// holds more than one the newest wins.
fn trace_named_in(log: &str) -> Option<&str> {
    const DUMPED: &str = "full trace dumped to ";
    log.lines().rev().find_map(|line| {
        let line = line.trim();
        // Matched anywhere in the line rather than at its start: the log interleaves the recorded
        // target's own stdout, so nothing guarantees this banner begins one.
        let at = line.to_ascii_lowercase().find(DUMPED)?;
        // `to_ascii_lowercase` maps ASCII in place, so the byte offset is the same in both.
        let path = line[at + DUMPED.len()..].trim().trim_end_matches('.');
        (!path.is_empty()).then_some(path)
    })
}

/// The line of a failed recorder's log that says *why*.
///
/// [`first_meaningful_line`] skips the banner, which was enough for the not-elevated case it was
/// written for, where the refusal is the first thing after it. It is not enough in general: TTD
/// prints `Launching '<target>'` before it tries, so any failure past that point was reported with
/// a line that says nothing was wrong — the "reason" quoted back for #232 was the banner for the
/// launch that then failed two lines later.
fn failure_detail(log: &str) -> Option<&str> {
    /// Words TTD's own failures use: `Error: Failed starting the guest process ...`,
    /// `Administrative privileges are required to record a trace.`
    fn reports_a_failure(line: &str) -> bool {
        let lower = line.to_ascii_lowercase();
        ["error", "failed", "failure", "cannot ", "denied", "unable"]
            .iter()
            .any(|word| lower.contains(word))
            || lower.contains("are required")
    }

    log.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .find(|l| reports_a_failure(l))
        // A failure that named itself in none of those words still has to report something, and
        // the first line past the banner is the best guess available.
        .or_else(|| first_meaningful_line(log))
}

/// First non-empty, non-banner line of TTD's output — the part that usually carries
/// the actual error (e.g. the "Administrative privileges are required" line).
fn first_meaningful_line(log: &str) -> Option<&str> {
    log.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .find(|l| {
            let lower = l.to_ascii_lowercase();
            !lower.starts_with("microsoft (r) ttd")
                && !lower.starts_with("release:")
                && !lower.starts_with("copyright")
                && !lower.starts_with("eula")
        })
}

#[cfg(test)]
mod tests {
    use super::{
        Arch, failure_detail, finished_trace, first_meaningful_line, probe_order, split_argv,
        split_env_entry, split_target, trace_named_in,
    };
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime};

    /// A directory of this module's own, named per test and per process so two of these can run at
    /// once, and emptied first so a `.run` left by an earlier run of the same test cannot be
    /// mistaken for the one under test.
    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("windbg-mcp-ttd-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create the scratch directory");
        dir
    }

    #[test]
    fn split_env_entry_parses_key_value() {
        assert_eq!(
            split_env_entry("QT_QPA_PLATFORM_PLUGIN_PATH=C:\\app"),
            Ok(("QT_QPA_PLATFORM_PLUGIN_PATH", "C:\\app"))
        );
    }

    #[test]
    fn split_env_entry_allows_equals_and_empty_value() {
        assert_eq!(split_env_entry("K=a=b"), Ok(("K", "a=b")));
        assert_eq!(split_env_entry("K="), Ok(("K", "")));
    }

    #[test]
    fn split_env_entry_rejects_missing_equals_or_empty_key() {
        assert!(split_env_entry("NOEQUALS").is_err());
        assert!(split_env_entry("=value").is_err());
    }

    // ---- the target's command line (#232) -------------------------------

    /// The bug, in the shape the issue reported it: a program and its arguments are separate
    /// entries, because that is how `TTD.exe -launch` reads them.
    #[test]
    fn a_target_with_arguments_becomes_a_program_and_its_arguments() {
        assert_eq!(
            split_target("cmd.exe /c dir C:\\Windows\\System32\\ntdll.dll", None).unwrap(),
            vec![
                "cmd.exe",
                "/c",
                "dir",
                // A backslash run that never reaches a quote is literal, so a Windows path
                // survives unchanged — which is most of what a target's arguments are.
                "C:\\Windows\\System32\\ntdll.dll"
            ]
        );
        assert_eq!(
            split_target("hostname.exe", None).unwrap(),
            vec!["hostname.exe"]
        );
    }

    /// A quoted path with spaces is one entry, not three — the case the split exists to respect.
    #[test]
    fn a_quoted_path_holding_spaces_is_one_argument() {
        assert_eq!(
            split_target("\"C:\\Program Files\\App\\app.exe\" --flag \"a b\"", None).unwrap(),
            vec!["C:\\Program Files\\App\\app.exe", "--flag", "a b"]
        );
    }

    /// And an *unquoted* one still is, when it names a file that exists.
    ///
    /// This is what handing the whole string to `TTD.exe` as one argument got right, and it is the
    /// property a split on whitespace would have taken away silently: `C:\Program Files\...` is
    /// where programs live, and the caller who was relying on it gets no error, just a recorder
    /// looking for `C:\Program`.
    #[test]
    fn an_unquoted_path_that_exists_is_not_split_on_its_spaces() {
        let dir = scratch("unquoted-path");
        let program = dir.join("a program.exe");
        std::fs::write(&program, b"not really an exe").expect("write the fixture");
        let target = program.to_string_lossy().to_string();

        assert_eq!(
            split_target(&target, None).unwrap(),
            vec![target.clone()],
            "an existing path is a program, whatever whitespace it holds"
        );
        // Once it is followed by an argument the string is no longer a path, so it parses as the
        // command line it is — and quoting is how the caller keeps the program whole.
        assert_eq!(
            split_target(&format!("\"{target}\" --flag"), None).unwrap(),
            vec![target, "--flag".to_string()]
        );
    }

    /// A *relative* one is probed against the directory the recorder will run in, not this one.
    ///
    /// The two are different directories whenever `working_dir` is set, and the consequence is not
    /// an error: probing here declines, the target is split on its spaces, and `TTD.exe` launches
    /// whatever the first token resolves to. Measured on 1.01.11 with `.\a program.exe` — it
    /// recorded `a.exe`, a different program, into a 29 MB trace reported as a complete recording.
    #[test]
    fn a_relative_path_is_probed_where_the_recorder_will_look_for_it() {
        let dir = scratch("relative-working-dir");
        std::fs::write(dir.join("a program.exe"), b"not really an exe").expect("write the fixture");
        let working_dir = dir.to_string_lossy().to_string();

        for target in [".\\a program.exe", "a program.exe"] {
            assert_eq!(
                split_target(target, Some(&working_dir)).unwrap(),
                vec![target],
                "`{target}` is one program in the recorder's own directory"
            );
            // And with no `working_dir` the recorder inherits this process's, where the fixture is
            // not — so the same string is the command line it looks like. This is the half that
            // makes the assertion above about the *directory* rather than about the string.
            assert_eq!(
                split_target(target, None).unwrap().len(),
                2,
                "`{target}` names nothing here, so it parses as a command line"
            );
        }
    }

    /// Rejected here rather than by `TTD.exe`, which is the difference between an error and an
    /// error plus an output directory and a log file nobody asked for.
    #[test]
    fn an_empty_target_is_refused_before_anything_is_created() {
        for empty in ["", "   ", "\t\n", "\"\"", "\" \""] {
            let refused = split_target(empty, None).expect_err("this target names no program");
            assert!(refused.contains("target"), "{refused}");
        }
        // A quoted argument that is *followed* by something is a different case: the empty
        // program is still the problem, and it is still the first entry.
        assert!(split_target("\"\" --flag", None).is_err());
    }

    /// The backslash rules, which are the half of Windows argv parsing that is not obvious — and
    /// they matter here because every path in a target's arguments is full of backslashes.
    #[test]
    fn backslashes_are_literal_until_they_reach_a_quote() {
        // No quote in sight: every backslash is itself, doubled runs included.
        assert_eq!(split_argv("a\\\\b c"), vec!["a\\\\b", "c"]);
        // An even run before a quote halves, and the quote delimits.
        assert_eq!(split_argv("\"a\\\\\" b"), vec!["a\\", "b"]);
        // An odd run before a quote halves and the quote survives as a character.
        assert_eq!(split_argv("a\\\"b"), vec!["a\"b"]);
        // A trailing backslash on a quoted path is the classic one: `"C:\dir\\"` is the directory,
        // not an unterminated string.
        assert_eq!(
            split_argv("\"C:\\dir\\\\\" next"),
            vec!["C:\\dir\\", "next"]
        );
        // `""` inside a quoted argument is a literal quote and leaves it quoted.
        assert_eq!(split_argv("\"say \"\"hi\"\" now\""), vec!["say \"hi\" now"]);
        // An empty argument is an argument.
        assert_eq!(split_argv("a \"\" b"), vec!["a", "", "b"]);
        // Tabs separate as spaces do, and runs of either collapse.
        assert_eq!(split_argv("a\t\t b   c"), vec!["a", "b", "c"]);
    }

    // ---- what an exited recorder wrote (#233) ---------------------------

    /// The success discriminator: the log names the finished trace, and it is on disk.
    #[test]
    fn a_completed_recording_is_found_by_the_path_its_log_names() {
        let dir = scratch("completed");
        let trace = dir.join("hostname01.run");
        std::fs::write(&trace, b"trace").expect("write the fixture trace");

        let log = format!(
            "Microsoft (R) TTD 1.01.11\n\
             Launching 'hostname.exe'\n\
             Recording has started of process (PID:5568) on trace file: {}\n\
             hostname.exe(x64) (PID:5568): Process exited with exit code 0 after 156ms\n\
             Full trace dumped to {}\n",
            trace.display(),
            trace.display()
        );
        assert_eq!(
            finished_trace(&log, &dir, SystemTime::now()).as_deref(),
            Some(trace.as_path())
        );
    }

    /// And by what is in the directory when the log does not say — that line's wording is TTD's,
    /// so the ground truth is the file.
    #[test]
    fn a_completed_recording_is_still_found_without_the_log_line() {
        let dir = scratch("no-log-line");
        let trace = dir.join("target01.run");
        std::fs::write(&trace, b"trace").expect("write the fixture trace");
        // Beside a file that is not a trace, and one that is only named like the index.
        std::fs::write(dir.join("ttd_record.log"), b"log").expect("write the log");
        std::fs::write(dir.join("target01.idx"), b"idx").expect("write the index");

        assert_eq!(
            finished_trace("nothing useful here\n", &dir, SystemTime::now()).as_deref(),
            Some(trace.as_path())
        );
    }

    /// A `.run` older than this recorder is somebody else's, and reporting it would be the same
    /// false claim in the other direction — "complete", naming a trace of a different run.
    #[test]
    fn a_trace_an_earlier_recording_left_behind_is_not_claimed() {
        let dir = scratch("stale");
        std::fs::write(dir.join("older01.run"), b"trace").expect("write the fixture trace");

        // As if the recorder had been spawned an hour after that file was written.
        let spawned = SystemTime::now() + Duration::from_secs(3600);
        assert_eq!(finished_trace("", &dir, spawned), None);
        // Nothing at all is the same answer, and so is a directory that is not there.
        assert_eq!(
            finished_trace("", &scratch("empty"), SystemTime::now()),
            None
        );
        assert_eq!(
            finished_trace("", &dir.join("does-not-exist"), SystemTime::now()),
            None
        );
    }

    /// The started line names a trace that may never be finalised, so only the finished one counts.
    #[test]
    fn only_the_finished_line_names_a_trace() {
        assert_eq!(
            trace_named_in("Recording has started of process (PID:1) on trace file: C:\\t\\a.run"),
            None
        );
        assert_eq!(
            trace_named_in("Full trace dumped to C:\\t\\a.run"),
            Some("C:\\t\\a.run")
        );
        // The last one wins: one recorder run can finish several traces.
        assert_eq!(
            trace_named_in("Full trace dumped to C:\\t\\a.run\nFull trace dumped to C:\\t\\b.run"),
            Some("C:\\t\\b.run")
        );
        assert_eq!(trace_named_in("Full trace dumped to \n"), None);
    }

    /// The reported reason has to be the line that says what went wrong.
    ///
    /// `Launching '<target>'` is printed *before* the attempt, so it is the first meaningful line
    /// of every log including the failing ones — which is how #232's failure came to be reported
    /// with a line saying nothing was wrong.
    #[test]
    fn the_reason_for_a_failure_is_read_past_the_launch_banner() {
        let log = "Microsoft (R) TTD 1.01.11\n\
                   Launching '\"cmd.exe /c dir C:\\Windows\"'\n\
                   Error: Failed starting the guest process \"cmd.exe /c dir C:\\Windows\"\n\
                        : error:(2)The system cannot find the file specified.\n";
        let detail = failure_detail(log).expect("a failing log has a reason");
        assert!(detail.starts_with("Error: Failed starting"), "{detail}");
        assert!(
            first_meaningful_line(log).is_some_and(|l| l.starts_with("Launching")),
            "the banner is what the old reading returned, which is why this test exists"
        );
    }

    /// And the case the watch was built for still reports the same line it always did.
    #[test]
    fn the_not_elevated_refusal_is_still_the_reason() {
        let log = "Microsoft (R) TTD 1.01.11\n\
                   Release: 1.11.428.0\n\
                   Administrative privileges are required to record a trace.\n";
        assert_eq!(
            failure_detail(log),
            Some("Administrative privileges are required to record a trace.")
        );
        // A log with no failure word in it still has to say something.
        assert_eq!(
            failure_detail("Launching 'x.exe'\n"),
            Some("Launching 'x.exe'")
        );
        assert_eq!(failure_detail(""), None);
    }

    #[test]
    fn empty_or_whitespace_has_no_meaningful_line() {
        assert_eq!(first_meaningful_line(""), None);
        assert_eq!(first_meaningful_line("   \n\t\n  "), None);
    }

    #[test]
    fn banner_only_has_no_meaningful_line() {
        let log = "Microsoft (R) TTD 1.01.11\n\
                   Release: 1.11.428.0\n\
                   Copyright (C) Microsoft Corporation. All rights reserved.\n\
                   EULA accepted.\n";
        assert_eq!(first_meaningful_line(log), None);
    }

    #[test]
    fn banner_prefix_match_is_case_insensitive() {
        let log = "MICROSOFT (R) TTD 1.01.11\nRELEASE: 1.11\nCOPYRIGHT foo\nEULA bar\n";
        assert_eq!(first_meaningful_line(log), None);
    }

    #[test]
    fn returns_first_error_after_banner_trimmed() {
        let log = "Microsoft (R) TTD 1.01.11\n\
                   Release: 1.11.428.0\n\
                   \n\
                   \tAdministrative privileges are required to record a trace.\n\
                   Some later line.\n";
        assert_eq!(
            first_meaningful_line(log),
            Some("Administrative privileges are required to record a trace.")
        );
    }

    #[test]
    fn skips_leading_blank_lines() {
        let log = "\n\n   \nactual message\n";
        assert_eq!(first_meaningful_line(log), Some("actual message"));
    }

    /// The native recorder is tried first, and nothing is excluded.
    ///
    /// The bug this fixes was an ordering, not a missing candidate: an ARM64 WinDbg package ships
    /// `amd64`, `arm64` and `x86` payloads, so a fixed list headed by `amd64` returned the
    /// emulation recorder on every ARM64 host — a native ARM64 target cannot be recorded with it.
    #[test]
    fn the_native_recorder_is_probed_first_and_the_others_still_follow() {
        let order = probe_order();
        assert_eq!(
            order[0],
            Arch::of_this_build(),
            "the build's own architecture leads"
        );

        let mut seen = order.to_vec();
        seen.sort_by_key(|a| format!("{a:?}"));
        seen.dedup();
        assert_eq!(
            seen.len(),
            3,
            "and every architecture is still reachable — recording an emulated target wants one of \
             the others, so this is an ordering and not a filter"
        );
    }

    /// Each host leads with itself, so the rule is not "arm64 first" hard-coded.
    #[test]
    fn every_architecture_leads_its_own_order() {
        for arch in [Arch::Arm64, Arch::X64, Arch::X86] {
            let order = match arch {
                Arch::Arm64 => [Arch::Arm64, Arch::X64, Arch::X86],
                Arch::X64 => [Arch::X64, Arch::Arm64, Arch::X86],
                Arch::X86 => [Arch::X86, Arch::X64, Arch::Arm64],
            };
            assert_eq!(order[0], arch);
        }
    }

    /// The two installers spell x64 differently, and crossing them selects the wrong recorder.
    #[test]
    fn the_sdk_and_the_store_package_disagree_about_x64() {
        assert_eq!(Arch::X64.sdk_dir(), "x64");
        assert_eq!(
            Arch::X64.payload_dir(),
            "amd64",
            "the store payload directory is `amd64` where the SDK's is `x64` — the one difference \
             between the two layouts that is not a path prefix"
        );

        // And the two agree everywhere else, which is why only x64 is a trap.
        assert_eq!(Arch::Arm64.sdk_dir(), Arch::Arm64.payload_dir());
        assert_eq!(Arch::X86.sdk_dir(), Arch::X86.payload_dir());
    }

    /// Whatever this build is, it maps onto an architecture the installers actually ship.
    #[test]
    fn this_build_resolves_to_a_shipped_recorder() {
        let own = Arch::of_this_build();
        assert!(!own.sdk_dir().is_empty() && !own.payload_dir().is_empty());
        assert_eq!(
            own,
            match std::env::consts::ARCH {
                "aarch64" => Arch::Arm64,
                "x86" => Arch::X86,
                _ => Arch::X64,
            }
        );
    }
}
