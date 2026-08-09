//! Time Travel Debugging recording support.
//!
//! There is no in-process recording API, so we shell out to `TTD.exe` (the
//! standalone recorder). Replay of the resulting `.run` trace is done through the
//! normal engine path ([`crate::engine`] → `open_trace`).

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Best-effort search for `TTD.exe` from an installed Windows debugging toolset.
pub fn find_ttd() -> Option<PathBuf> {
    // 1. Anything already on PATH.
    if let Some(p) = search_path("TTD.exe") {
        return Some(p);
    }
    // 2. Classic SDK "Debugging Tools for Windows".
    for arch in ["x64", "arm64"] {
        let p = PathBuf::from(format!(
            r"C:\Program Files (x86)\Windows Kits\10\Debuggers\{arch}\TTD\TTD.exe"
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
        for rel in [
            r"amd64\TTD\TTD.exe",
            r"TTD\TTD.exe",
            r"arm64\TTD\TTD.exe",
            r"x64\TTD\TTD.exe",
        ] {
            let candidate = base.join(rel);
            if candidate.is_file() {
                return Some(candidate);
            }
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
/// Recording is long-lived (it finalizes only when the recorded process exits), so
/// this is fire-and-forget for the success path. But TTD fails *fast* on common
/// misconfigurations — most notably "Administrative privileges are required" when the
/// server isn't elevated — so we capture its startup output to a log file and watch
/// the recorder briefly: if it dies during [`STARTUP_WATCH`], we surface the real
/// error instead of falsely reporting success.
///
/// Requires Administrator privileges.
pub fn record_launch(
    ttd: &Path,
    out_dir: &str,
    target: &str,
    env: &[String],
    working_dir: Option<&str>,
) -> Result<String, String> {
    // Validate the caller-supplied environment up front — before any filesystem side effect —
    // so a malformed entry doesn't leave a stray log file behind.
    let mut parsed_env = Vec::with_capacity(env.len());
    for kv in env {
        parsed_env.push(split_env_entry(kv)?);
    }

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
        .arg("-launch")
        .arg(target)
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
    // Pass through the validated environment (e.g. an anti-analysis env guard) and cwd to the
    // recorded target. TTD.exe launches `target` with this environment inherited. Applied after
    // the scrub above, so an entry the caller passed deliberately still wins.
    for (key, val) in parsed_env {
        cmd.env(key, val);
    }
    if let Some(dir) = working_dir {
        cmd.current_dir(dir);
    }
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

    // Watch for an early exit (a fast failure).
    let deadline = Instant::now() + STARTUP_WATCH;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                // Exited during startup → recording did not take. Report the captured
                // reason (e.g. the access-denied message).
                let log_text = std::fs::read_to_string(&log_path).unwrap_or_default();
                let detail = first_meaningful_line(&log_text)
                    .unwrap_or("see log for details")
                    .to_string();
                return Err(format!(
                    "TTD recording failed to start ({status}): {detail}. Full log: {}",
                    log_path.display()
                ));
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    // Still running after the watch window → recording is underway.
                    return Ok(format!(
                        "TTD recording started (recorder pid {pid}). Tracing `{target}`; \
                         output (.run/.idx) goes to `{}`. Recording finalizes when the \
                         target exits. Recorder log: {}",
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
    use super::{first_meaningful_line, split_env_entry};

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
}
