"""Launch one isolated Binary Ninja GUI for CLRBHB or shutdown validation."""

import argparse
import fcntl
import hashlib
import json
import os
import signal
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

CASES = ("decode", "wizard", "no-wizard", "qt-wizard", "guard", "quit", "quit_matching")


def outcome(returncode, forced, capture, crash_reports):
    clean = returncode == 0 and not forced and not crash_reports
    return {
        "status": "passed" if clean and capture.get("ok") is True else "failed",
        "returncode": returncode,
        "forced": forced,
        "normal_exit": clean,
        "crash_reports": crash_reports,
    }


def signal_owned_group(process, sig):
    """Signal descendants even when the session leader has already exited."""
    try:
        os.killpg(process.pid, sig)
    except ProcessLookupError:
        pass


def cleanup_owned(process):
    signal_owned_group(process, signal.SIGKILL)
    process.wait(timeout=5)


def wait_owned(process, timeout, *, clock=time.monotonic, sleep=time.sleep):
    try:
        deadline = clock() + timeout
        while process.poll() is None and clock() < deadline:
            sleep(0.2)
        forced = process.poll() is None
        if forced:
            signal_owned_group(process, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                signal_owned_group(process, signal.SIGKILL)
        return process.wait(timeout=5), forced
    finally:
        cleanup_owned(process)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=CASES, required=True)
    parser.add_argument(
        "--binaryninja",
        type=Path,
        required=True,
        help="GUI executable inside the app bundle",
    )
    parser.add_argument("--license-file", type=Path, required=True)
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="New disposable directory; must not exist",
    )
    parser.add_argument("--python-path", type=Path, action="append", default=[])
    parser.add_argument("--reference", type=Path)
    parser.add_argument("--target", type=Path)
    parser.add_argument("--bindiff", type=Path)
    parser.add_argument("--timeout", type=int, default=240)
    args = parser.parse_args()
    if not 15 <= args.timeout <= 900:
        parser.error("timeout must be 15–900 seconds")
    if args.case in ("quit", "quit_matching") and not all(
        (args.reference, args.target, args.bindiff)
    ):
        parser.error("active-work checks need reference, target and bindiff")
    if bool(args.reference) != bool(args.target):
        parser.error("reference and target must be supplied together")
    for path in (
        args.binaryninja,
        args.license_file,
        *args.python_path,
        args.reference,
        args.target,
        args.bindiff,
    ):
        if path is not None and not path.exists():
            parser.error("a supplied input path does not exist")
    # Serialize our launchers; do not close an unrelated GUI to make room.
    lock_path = (
        Path(os.environ.get("TMPDIR", "/tmp")) / f"windbg-bn-probe-{os.getuid()}.lock"
    )
    with lock_path.open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        listing = subprocess.run(
            ["ps", "-axo", "comm="], check=True, capture_output=True, text=True
        )
        if any(
            Path(line.strip()).name == "binaryninja"
            for line in listing.stdout.splitlines()
        ):
            parser.error(
                "an existing Binary Ninja GUI must finish before this isolated probe"
            )
        root = args.output.resolve()
        root.mkdir(mode=0o700, parents=True, exist_ok=False)
        profile = root / "profile"
        plugin = profile / "plugins" / "followup_probe"
        plugin.mkdir(parents=True)
        (profile / "settings.json").write_text(
            json.dumps({"ui.allowWelcome": args.case in ("wizard", "qt-wizard")})
        )
        config = {
            "case": args.case,
            "output": str(root),
            "reference": str(args.reference.resolve()) if args.reference else None,
            "target": str(args.target.resolve()) if args.target else None,
            "bindiff": str(args.bindiff.resolve()) if args.bindiff else None,
        }
        config_path = root / "config.json"
        config_path.write_text(json.dumps(config))
        script = Path(__file__).with_name("bn_followup_gui.py").resolve()
        sources = root / "sources"
        sources.mkdir()
        for source in (script, Path(__file__).resolve()):
            (sources / source.name).write_bytes(source.read_bytes())
        paths = [str(script.parent), *(str(p.resolve()) for p in args.python_path)]
        plugin_code = (
            "import sys\n" + f"sys.path[:0] = {paths!r}\n"
            "import binaryninja as bn\nfrom PySide6.QtCore import QTimer\n"
            "from bn_followup_gui import start\n"
            f"bn.execute_on_main_thread(lambda: QTimer.singleShot(2000, lambda: start({str(config_path)!r})))\n"
        )
        (plugin / "__init__.py").write_text(plugin_code)
        env = dict(
            os.environ,
            BN_USER_DIRECTORY=str(profile),
            BN_QSETTINGS_POSTFIX="followup-" + uuid.uuid4().hex,
        )
        env["BN_LICENSE"] = args.license_file.read_text()
        crash_dir = Path.home() / "Library/Logs/DiagnosticReports"
        before_crashes = set(crash_dir.glob("binaryninja*"))
        report = {
            "schema_version": 1,
            "case": args.case,
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "executable_sha256": hashlib.sha256(
                args.binaryninja.read_bytes()
            ).hexdigest(),
            "probe_sha256": hashlib.sha256(script.read_bytes()).hexdigest(),
            "launcher_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        }
        revision_file = args.binaryninja.parent.parent / "Resources/api_REVISION.txt"
        if revision_file.is_file():
            report["api_revision"] = revision_file.read_text().strip()
        with (root / "gui.log").open("wb") as log:
            process = subprocess.Popen(
                [str(args.binaryninja), "--new-instance", "--stderr-log"],
                env=env,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        try:
            report["pid"] = process.pid
            (root / "launch.json").write_text(json.dumps(report, indent=2) + "\n")
            print(
                "Started owned Binary Ninja", args.case, "PID", process.pid, flush=True
            )
            returncode, forced = wait_owned(process, args.timeout)
        finally:
            cleanup_owned(process)
        # Crash reports are asynchronous; also use the actual child status, never the launcher status.
        time.sleep(2)
        crashes = sorted(
            p.name for p in set(crash_dir.glob("binaryninja*")) - before_crashes
        )
        capture_path = root / "result.json"
        if (
            args.case in ("quit", "quit_matching")
            and (root / "capture/result.json").exists()
        ):
            capture_path = root / "capture/result.json"
        try:
            capture = json.loads(capture_path.read_text())
        except (OSError, ValueError):
            capture = {}
        report.update(outcome(returncode, forced, capture, crashes))
        report["capture"] = capture
        (root / "process-exit.json").write_text(json.dumps(report, indent=2) + "\n")
        print(
            args.case,
            report["status"],
            "returncode",
            returncode,
            "forced",
            forced,
            flush=True,
        )
        raise SystemExit(0 if report["status"] == "passed" else 1)


if __name__ == "__main__":
    main()
