"""Make a companion capture of one driver in an owned, disposable Binary Ninja GUI.

Binary Ninja **Personal has no headless API**, so a capture cannot be taken by importing the API:
this starts the real GUI with its own `BN_USER_DIRECTORY`, a generated plugin that runs
`bn_capture.start` two seconds in, and no state shared with whatever profile you use yourself. The
launcher owns the process group and kills it if the probe wedges.

The process-group handling is imported from `tools/bn_followup_probe.py` rather than copied: it is
the half that is easy to get subtly wrong -- a GUI that ignores SIGTERM, a session leader that has
already exited leaving children behind -- and a second copy of it would be a second thing to fix.

    python tools/binja_oracle/capture.py --image ~/drivers/rdyboost.sys \
        --output /tmp/cap-rdyboost --capture-path ~/captures/rdyboost-arm64.json
"""

import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bn_followup_probe import cleanup_owned, signal_owned_group  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
COMPANION = Path(
    os.environ.get("BINJA_WINDBG_MCP", Path.home() / "workspace" / "binja-windbg-mcp")
)
BINARY_NINJA = Path("/Applications/Binary Ninja.app/Contents/MacOS/binaryninja")
LICENSE = Path.home() / "Library/Application Support/Binary Ninja/license.dat"


def companion_site_packages(checkout: Path):
    """The companion's own dependencies, which its `analysis` module cannot run without.

    A disposable `BN_USER_DIRECTORY` has no installed packages, so the probe's first act inside
    the GUI is `import pydantic` and its first failure is that import. Rather than installing into
    the throwaway profile, the checkout's `.venv` is put on the path: Binary Ninja bundles
    **CPython 3.13** and that venv is 3.13, so its one compiled dependency (`pydantic_core`, a
    `cpython-313-darwin.so`) is loadable by the interpreter already running.
    """
    found = sorted(checkout.glob(".venv/lib/python3.*/site-packages"))
    return found[-1] if found else None


def reported(path: Path):
    """Whether the probe has written a verdict, which is what makes the rest of the wait a quit."""
    try:
        result = json.loads(path.read_text())
    except (OSError, ValueError):
        return False
    return result.get("ok") is True or "error" in result


def wait_for_probe(process, result_path: Path, timeout: int, grace: int):
    """Wait for the owned GUI, with a short leash once the probe has answered.

    **A Quit can be refused by a modal.** This probe defines types and applies prototypes, so the
    database really is modified and Binary Ninja is entitled to ask whether to save it -- and a
    prompt nobody can click holds the process until the full timeout. The artifact is written
    before the quit is attempted, so once the probe has reported there is nothing left to wait for
    and the leash is `grace` rather than `timeout`.
    """
    deadline = time.monotonic() + timeout
    answered = None
    while process.poll() is None and time.monotonic() < deadline:
        if answered is None and reported(result_path):
            answered = time.monotonic()
        if answered is not None and time.monotonic() - answered > grace:
            break
        time.sleep(0.2)
    forced = process.poll() is None
    if forced:
        signal_owned_group(process, signal.SIGTERM)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            signal_owned_group(process, signal.SIGKILL)
    return process.wait(timeout=5), forced, answered is not None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, required=True, help="the driver to capture")
    parser.add_argument("--capture-path", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="new disposable directory")
    parser.add_argument("--companion", type=Path, default=COMPANION)
    parser.add_argument("--binaryninja", type=Path, default=BINARY_NINJA)
    parser.add_argument("--license-file", type=Path, default=LICENSE)
    parser.add_argument(
        "--entry-rva",
        help="the real DriverEntry, when the image entry is a /GS stub and the probe's own "
        "escalation does not reach it. Recorded in the capture",
    )
    parser.add_argument(
        "--entry-hops",
        type=int,
        default=3,
        help="how far from the entry point the DriverEntry prototype may be applied",
    )
    parser.add_argument(
        "--dispatch-rva",
        help="the device-control dispatch, for a driver whose registration the probe cannot "
        "follow. Recorded in the capture, because it is a fact the capture did not derive",
    )
    parser.add_argument(
        "--site-packages",
        type=Path,
        help="the companion's dependencies; default: its `.venv` for this Python version",
    )
    parser.add_argument(
        "--dump-hlil",
        action="append",
        default=[],
        help="also record this function's signature and HLIL when the capture fails",
    )
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument(
        "--quit-grace",
        type=int,
        default=45,
        help="how long to wait for the GUI to exit *after* the probe has reported. The capture is "
        "already on disk by then, so a Quit blocked by a save-database prompt costs this rather "
        "than the whole --timeout",
    )
    args = parser.parse_args()
    if not 15 <= args.timeout <= 3600:
        parser.error("timeout must be 15-3600 seconds")
    for path in (args.image, args.binaryninja, args.license_file, args.companion):
        if not path.exists():
            parser.error(f"not found: {path}")
    if args.capture_path.exists():
        parser.error(f"refusing to overwrite {args.capture_path}")

    # An owned probe must not adopt, or close, a GUI somebody is using: `BN_USER_DIRECTORY` makes
    # the profile disposable but a second instance still shares the licence seat.
    listing = os.popen("ps -axo comm=").read()
    if any(Path(line.strip()).name == "binaryninja" for line in listing.splitlines()):
        parser.error("close the running Binary Ninja GUI before this isolated probe")

    root = args.output.resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    profile = root / "profile"
    plugin = profile / "plugins" / "binja_oracle_capture"
    plugin.mkdir(parents=True)
    (profile / "settings.json").write_text(json.dumps({"ui.allowWelcome": False}))
    config = {
        "image": str(args.image.resolve()),
        "capture_path": str(args.capture_path.resolve()),
        "output": str(root),
        "dispatch_rva": args.dispatch_rva,
        "entry_rva": args.entry_rva,
        "entry_hops": args.entry_hops,
        "dump_hlil": args.dump_hlil,
    }
    config_path = root / "config.json"
    config_path.write_text(json.dumps(config))

    probe = Path(__file__).with_name("bn_capture.py").resolve()
    sources = root / "sources"
    sources.mkdir()
    for source in (probe, Path(__file__).resolve()):
        (sources / source.name).write_bytes(source.read_bytes())
    packages = args.site_packages or companion_site_packages(args.companion.resolve())
    if packages is None or not Path(packages).is_dir():
        parser.error("give --site-packages: the companion's dependencies are not importable")
    paths = [str(sources), str(args.companion.resolve()), str(Path(packages).resolve())]
    (plugin / "__init__.py").write_text(
        "import sys\n" + f"sys.path[:0] = {paths!r}\n"
        "import binaryninja as bn\nfrom PySide6.QtCore import QTimer\n"
        "from bn_capture import start\n"
        f"bn.execute_on_main_thread(lambda: QTimer.singleShot(2000, "
        f"lambda: start({str(config_path)!r})))\n"
    )

    env = dict(
        os.environ,
        BN_USER_DIRECTORY=str(profile),
        BN_QSETTINGS_POSTFIX="binja-oracle-" + uuid.uuid4().hex,
        BN_LICENSE=args.license_file.read_text(),
    )
    crash_dir = Path.home() / "Library/Logs/DiagnosticReports"
    before = set(crash_dir.glob("binaryninja*"))
    report = {
        "schema_version": 1,
        "image": str(args.image.resolve()),
        "image_sha256": hashlib.sha256(args.image.read_bytes()).hexdigest(),
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "executable_sha256": hashlib.sha256(args.binaryninja.read_bytes()).hexdigest(),
        "probe_sha256": hashlib.sha256(probe.read_bytes()).hexdigest(),
        "python_path": paths,
    }
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
        print(f"started owned Binary Ninja, pid {process.pid}, log {root / 'gui.log'}", flush=True)
        returncode, forced, verdict_at = wait_for_probe(
            process, root / "result.json", args.timeout, args.quit_grace
        )
        report["quit_after_verdict"] = verdict_at
    finally:
        cleanup_owned(process)
    # Crash reports are written asynchronously, and the child's status is the one that counts.
    time.sleep(2)
    crashes = sorted(p.name for p in set(crash_dir.glob("binaryninja*")) - before)
    try:
        result = json.loads((root / "result.json").read_text())
    except (OSError, ValueError):
        result = {}
    report.update(
        {"returncode": returncode, "forced": forced, "crash_reports": crashes, "result": result}
    )
    (root / "process-exit.json").write_text(json.dumps(report, indent=2) + "\n")
    ok = result.get("ok") is True and not crashes
    print(json.dumps({k: result.get(k) for k in ("ok", "error", "cases", "dispatch_rvas",
                                                 "capture_path", "view")}, indent=1))
    if not ok:
        print(f"the probe did not finish; read {root / 'result.json'} and {root / 'gui.log'}")
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
