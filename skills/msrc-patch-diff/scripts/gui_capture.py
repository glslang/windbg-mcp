"""Run start() from an empty BN6 Personal GUI with the companion on sys.path."""

import hashlib
import json
import threading
import time
import traceback
from pathlib import Path


def state(workspace, binaries):
    result = {}
    for item in binaries:
        _, view, _, _ = workspace.acquire(item["binary_id"])
        analysis = {
            "functions": [
                [f.start, f.name, str(f.type), sorted(f.comments.items())]
                for f in sorted(view.functions, key=lambda f: f.start)
            ],
            "types": sorted((str(k), str(v)) for k, v in view.types.items()),
        }
        digest = hashlib.sha256()
        for segment in sorted(view.segments, key=lambda s: s.start):
            for address in range(segment.start, segment.end, 1024 * 1024):
                digest.update(address.to_bytes(8, "little"))
                digest.update(
                    view.read(address, min(1024 * 1024, segment.end - address))
                )
        result[item["binary_id"]] = {
            "analysis_sha256": hashlib.sha256(
                json.dumps(analysis, sort_keys=True).encode()
            ).hexdigest(),
            "bytes_sha256": digest.hexdigest(),
            "function_count": len(analysis["functions"]),
        }
    return result


def pages(method, *args, **kwargs):
    rows, offset = [], 0
    while True:
        result = method(*args, offset=offset, limit=100, **kwargs)
        rows.extend(result["items"])
        following = result["next_offset"]
        if following is None:
            return rows
        if following <= offset:
            raise RuntimeError("pagination did not advance")
        offset = following


def full_acceptance(status, analysis_unchanged, inputs_unchanged):
    return (
        status["state"] == "completed"
        and status["coverage_complete"]
        and analysis_unchanged
        and inputs_unchanged
    )


def finalize_capture(report, output, workspace, comparison_id, request_quit=None):
    def save():
        (output / "capture.json").write_text(json.dumps(report, indent=2) + "\n")

    def attempt(stage, action):
        try:
            action()
        except Exception:  # noqa: BLE001 -- retain cleanup failures with the original evidence
            report.setdefault("cleanup_errors", []).append(
                {"stage": stage, "error": traceback.format_exc()}
            )
            report["ok"] = False
        save()

    # Preserve evidence even if native cleanup never returns.
    save()
    if workspace is not None:
        if comparison_id is not None:
            attempt("comparison_close", lambda: workspace.similarity.close(comparison_id))
        attempt("workspace_shutdown", workspace.shutdown)
    if request_quit is not None:
        attempt("quit_request", request_quit)


def prepare_target(workspace, binaries, target, rva):
    if type(rva) is not int or rva < 0:
        raise ValueError("prepare_target_rva must be a nonnegative integer")
    for item in binaries:
        _, view, _, _ = workspace.acquire(item["binary_id"])
        if Path(view.file.original_filename).resolve() != target:
            continue
        coordinate = workspace.coordinate(view, view.start + rva)
        navigation = workspace.navigate(item["binary_id"], coordinate)
        # Displaying a function can request lazy analysis. Finish it before the baseline.
        view.update_analysis_and_wait()
        return {"stage": "before_baseline", "navigation": navigation}
    raise ValueError("target view unavailable for preparation")


def run(reference, target, bindiff, output, quit_on_finish, prepare_target_rva=None):
    import binaryninja as bn
    from binaryninjaui import UIContext
    from binja_windbg_mcp.adapter import Workspace, main_thread
    from binja_windbg_mcp.core import Coordinate
    from PySide6.QtCore import QCoreApplication

    workspace, comparison_id = None, None
    report = {"bn_version": bn.core_version(), "ok": False}
    try:
        for path in (reference, target):

            def open_file(path=path):
                contexts = list(UIContext.allContexts())
                if len(contexts) != 1:
                    raise RuntimeError("expected one disposable GUI context")
                return contexts[0].openFilename(str(path))

            if not main_thread(open_file):
                raise RuntimeError("could not open input")
        workspace = Workspace()
        workspace.similarity.backend.backends["external"].configure(str(bindiff))
        binaries = workspace.list_binaries()["binaries"]
        if len(binaries) != 2:
            raise RuntimeError("expected exactly two input views")
        for item in binaries:
            _, view, _, _ = workspace.acquire(item["binary_id"])
            view.update_analysis_and_wait()
        if prepare_target_rva is not None:
            report["preparation"] = prepare_target(
                workspace, binaries, target, prepare_target_rva
            )
        before = workspace.list_binaries()["binaries"]
        ids = {}
        for item in before:
            _, view, _, _ = workspace.acquire(item["binary_id"])
            ids[Path(view.file.original_filename).resolve()] = item["binary_id"]
        report["before"] = before
        report["analysis_before"] = state(workspace, before)
        report["capabilities"] = workspace.similarity.status()["capabilities"]
        started = workspace.similarity.start(
            ids[reference],
            ids[target],
            providers=["Google BinDiff"],
            backend="external",
            timeout_ms=120000,
        )
        comparison_id = started["comparison_id"]
        while True:
            status = workspace.similarity.status(comparison_id)
            if not status["active"]:
                break
            time.sleep(0.1)
        report["comparison"] = status
        report["matches"] = pages(workspace.similarity.results, comparison_id)
        report["unmatched"] = {
            side: pages(
                workspace.similarity.results, comparison_id, side=side, kind="unmatched"
            )
            for side in ("reference", "target")
        }
        report["capture_collected"] = True
        changed = sorted(
            report["matches"], key=lambda r: (r["similarity"], r["result_id"])
        )[:10]
        report["diffs"] = []
        for match in changed:
            result = workspace.similarity.diff(
                comparison_id, match["result_id"], limit=1
            )
            result["items"] = pages(
                workspace.similarity.diff, comparison_id, match["result_id"]
            )
            result["next_offset"], result["truncated"] = None, False
            report["diffs"].append(result)
        if not changed:
            raise RuntimeError("no matched function for navigation acceptance")
        endpoint = changed[0]["target"]
        report["navigation"] = workspace.navigate(
            endpoint["binary_id"],
            Coordinate.model_validate(endpoint["coordinate"]),
            expected_generation=endpoint["generation"],
        )
        after = workspace.list_binaries()["binaries"]
        report["after"] = after
        report["analysis_after"] = state(workspace, after)
        report["analysis_unchanged"] = (
            report["analysis_before"] == report["analysis_after"]
        )
        report["inputs_unchanged"] = all(
            all(
                item[k]
                == next(a for a in after if a["binary_id"] == item["binary_id"])[k]
                for k in ("generation", "identity", "modified", "file_sha256")
            )
            for item in before
        )
        report["ok"] = full_acceptance(
            status, report["analysis_unchanged"], report["inputs_unchanged"]
        )
    except Exception:  # noqa: BLE001 -- persist native API failures in the acceptance artifact
        report["error"] = traceback.format_exc()
    finally:
        finalize_capture(
            report,
            output,
            workspace,
            comparison_id,
            (lambda: bn.execute_on_main_thread(lambda: QCoreApplication.instance().quit()))
            if quit_on_finish
            else None,
        )


def start(reference, target, bindiff, output, quit_on_finish=False, prepare_target_rva=None):
    """Analyze two downloaded PE files; leave views open unless this disposable GUI should quit."""
    from binaryninjaui import FileContext
    from PySide6.QtCore import QTimer

    if FileContext.getOpenFileContexts():
        raise ValueError("use an empty disposable BN6 GUI process")
    reference, target, bindiff = (
        Path(p).resolve(strict=True) for p in (reference, target, bindiff)
    )
    if reference == target:
        raise ValueError("reference and target must be distinct")
    output = Path(output).resolve()
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    QTimer.singleShot(
        100,
        lambda: threading.Thread(
            target=run,
            args=(reference, target, bindiff, output, quit_on_finish, prepare_target_rva),
            daemon=True,
        ).start(),
    )
