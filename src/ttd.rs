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
pub fn record_launch(ttd: &Path, out_dir: &str, target: &str) -> Result<String, String> {
    // TTD requires the output directory to exist; create it up front.
    std::fs::create_dir_all(out_dir)
        .map_err(|e| format!("failed to create output dir `{out_dir}`: {e}"))?;

    // Capture the recorder's banner/diagnostics to a file (not a pipe): a pipe would
    // deadlock a long, successful recording once its buffer filled and we stopped
    // draining it.
    let log_path = Path::new(out_dir).join("ttd_record.log");
    let log = std::fs::File::create(&log_path)
        .map_err(|e| format!("failed to create log `{}`: {e}", log_path.display()))?;
    let log_err = log
        .try_clone()
        .map_err(|e| format!("failed to set up TTD logging: {e}"))?;

    let mut child = Command::new(ttd)
        .arg("-accepteula")
        .arg("-out")
        .arg(out_dir)
        .arg("-launch")
        .arg(target)
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err))
        .spawn()
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
                         output (.run/.idx) goes to `{out_dir}`. Recording finalizes when the \
                         target exits. Recorder log: {}",
                        log_path.display()
                    ));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(format!("failed while waiting on TTD.exe: {e}")),
        }
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
    use super::first_meaningful_line;

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
