"""GUI-side probes. Import only inside the owned process from bn_followup_probe.py."""

import hashlib
import importlib.util
import json
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

CLRBHB = bytes.fromhex("df2203d5")
SYNTHETIC = CLRBHB + bytes.fromhex("00040091c0035fd6")  # add x0, x0, #1; ret
INPUT_HASHES = {
    "reference": "65a014d83be9d2262e913d020425dc9bf0a301b6403dffa13e6fe7ae5460a57b",
    "target": "9a2eeb0e4a3d76aa9a6bfaf287540f5f1f7562d814e8ecb3c3f6df6b57a557b6",
}


def decode_instruction(arch, data, address):
    info = arch.get_instruction_info(data, address)
    text = arch.get_instruction_text(data, address)
    return {
        "address": hex(address),
        "bytes": data[:4].hex(),
        "length": info.length if info else None,
        "branches": [str(b.type) for b in info.branches] if info else None,
        "text": "".join(str(t) for t in text[0]) if text else None,
        "text_length": text[1] if text else None,
    }


def decoded_clrbhb(row):
    return (
        row["bytes"] == CLRBHB.hex()
        and row["length"] == 4
        and row["text_length"] == 4
        and row["branches"] == []
        and (row["text"] or "").strip().casefold() == "clrbhb"
    )


def endpoint_analysis_complete(row):
    function = row.get("function", {})
    instructions = function.get("instructions", [])
    address = int(row["address"], 16)
    return (
        function.get("found") is True
        and not function.get("instructions_truncated")
        and [(int(i["address"], 16), i["length"]) for i in instructions]
        == [(address + offset, 4) for offset in (0, 4, 8)]
        and [
            [int(start, 16), int(end, 16)] for start, end in function.get("bounds", [])
        ]
        == [[address, address + 12]]
        and any("SystemHintOp_CLRBHB" in i for i in (function.get("llil") or []))
    )


def function_evidence(view, address):
    function = view.get_function_at(address)
    if function is None:
        return {"address": hex(address), "found": False}
    instructions = []
    for block in function.basic_blocks:
        at = block.start
        for tokens, size in block:
            instructions.append(
                {
                    "address": hex(at),
                    "length": size,
                    "text": "".join(str(t) for t in tokens),
                }
            )
            at += size
            if len(instructions) >= 256:
                break
        if len(instructions) >= 256:
            break
    il = function.low_level_il
    return {
        "address": hex(address),
        "found": True,
        "name": function.name,
        "bounds": [[hex(b.start), hex(b.end)] for b in function.basic_blocks],
        "instructions": instructions,
        "instructions_truncated": len(instructions) >= 256,
        "llil": [str(i) for block in il for i in block][:256]
        if il is not None
        else None,
    }


def endpoint_matches(matches):
    expected = {
        (0x10FC00 + offset, 0x11AC00 + offset) for offset in range(0, 0x400, 0x80)
    }
    targets = {target for _, target in expected}
    selected = [
        row for row in matches if int(row["target"]["coordinate"]["rva"], 16) in targets
    ]
    actual = {
        (
            int(row["reference"]["coordinate"]["rva"], 16),
            int(row["target"]["coordinate"]["rva"], 16),
        )
        for row in selected
    }
    if len(selected) != len(expected) or actual != expected:
        raise ValueError(
            "comparison must contain each of the eight expected endpoint pairs once"
        )
    return selected


def endpoint_diff_complete(diff, match):
    items = diff.get("items", [])
    if len(items) != 3 or diff.get("truncated") or diff.get("next_offset") is not None:
        return False
    for side in ("reference", "target"):
        if diff.get("instructions_truncated", {}).get(side) is not False:
            return False
        base = int(match[side]["coordinate"]["rva"], 16)
        for index, item in enumerate(items):
            instruction = item.get(side)
            if not instruction or instruction.get("text_truncated") is not False:
                return False
            text = instruction.get("text", "").strip().casefold().split()
            if (
                int(instruction["rva"], 16) != base + 4 * index
                or int(instruction["address"], 16) != 0x140000000 + base + 4 * index
                or not text
            ):
                return False
            if text[0] != ("clrbhb", "isb", "b")[index]:
                return False
            if index == 0 and text != ["clrbhb"]:
                return False
            if index == 1 and text not in (["isb"], ["isb", "sy"], ["isb", "#0xf"]):
                return False
            if index == 2:
                if len(text) != 2:
                    return False
                try:
                    destination = int(text[1], 16)
                except ValueError:
                    return False
                # Both hash-pinned PEs load at this preferred base. Each stub
                # jumps to the corresponding handler exactly 0x5000 bytes on.
                if destination != 0x140000000 + base + 0x5000:
                    return False
    return True


def compare_endpoints(workspace, config, report, save):
    source = (
        Path(__file__).resolve().parents[1]
        / "skills/msrc-patch-diff/scripts/gui_capture.py"
    )
    spec = importlib.util.spec_from_file_location("comparison_capture", source)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    comparison_id = None
    evidence = {"status": "failed"}
    report["comparison"] = evidence
    try:
        if not config.get("bindiff"):
            raise RuntimeError("external comparison requires a BinDiff path")
        workspace.similarity.backend.backends["external"].configure(config["bindiff"])
        before = workspace.list_binaries()["binaries"]
        ids = {}
        for binary in before:
            _, view, _, _ = workspace.acquire(binary["binary_id"])
            ids[Path(view.file.original_filename).resolve()] = binary["binary_id"]
        evidence["before"] = before
        evidence["analysis_before"] = helper.state(workspace, before)
        started = workspace.similarity.start(
            ids[Path(config["reference"]).resolve()],
            ids[Path(config["target"]).resolve()],
            backend="external",
            providers=["Google BinDiff"],
            timeout_ms=120000,
        )
        comparison_id = started["comparison_id"]
        deadline = time.monotonic() + 150
        while True:
            status = workspace.similarity.status(comparison_id)
            if not status["active"]:
                break
            if time.monotonic() > deadline:
                raise TimeoutError("comparison deadline exceeded")
            time.sleep(0.1)
        evidence["result"] = status
        matches = helper.pages(workspace.similarity.results, comparison_id)
        unmatched = {
            side: helper.pages(
                workspace.similarity.results, comparison_id, side=side, kind="unmatched"
            )
            for side in ("reference", "target")
        }
        evidence["retained_results"] = {
            "matches": len(matches),
            "unmatched": {side: len(rows) for side, rows in unmatched.items()},
        }
        selected = endpoint_matches(matches)
        evidence["diffs"] = []
        for match in selected:
            diff = workspace.similarity.diff(comparison_id, match["result_id"], limit=1)
            diff["items"] = helper.pages(
                workspace.similarity.diff, comparison_id, match["result_id"]
            )
            diff["next_offset"], diff["truncated"] = None, False
            evidence["diffs"].append(diff)
            save()
        after = workspace.list_binaries()["binaries"]
        evidence["after"] = after
        evidence["analysis_after"] = helper.state(workspace, after)
        unchanged = evidence["analysis_before"] == evidence["analysis_after"] and all(
            any(
                all(
                    a.get(k) == b.get(k)
                    for k in (
                        "binary_id",
                        "generation",
                        "identity",
                        "modified",
                        "file_sha256",
                    )
                )
                for a in after
            )
            for b in before
        )
        evidence["inputs_unchanged"] = unchanged
        text_complete = len(selected) == 8 and all(
            endpoint_diff_complete(diff, match)
            for diff, match in zip(evidence["diffs"], selected)
        )
        evidence["status"] = (
            "passed"
            if helper.full_acceptance(status, unchanged, unchanged) and text_complete
            else "failed"
        )
    except Exception as error:
        evidence["error"] = type(error).__name__ + ": " + str(error)
    finally:
        save()
        if comparison_id:
            try:
                workspace.similarity.close(comparison_id)
            except Exception as error:
                evidence["cleanup_error"] = type(error).__name__
                evidence["status"] = "failed"
        save()
    return evidence["status"] == "passed"


def capture_decode(config, report, save):
    import binaryninja as bn
    from binaryninjaui import UIContext
    from binja_windbg_mcp.adapter import Workspace, main_thread
    from binja_windbg_mcp.similarity_adapter import NativeSimilarity

    arch = bn.Architecture["aarch64"]
    report["native_capabilities"] = NativeSimilarity(None).capabilities()
    report["synthetic_instruction"] = decode_instruction(arch, SYNTHETIC, 0x1000)
    synthetic = bn.BinaryView.new(SYNTHETIC)
    try:
        synthetic.platform = arch.standalone_platform
        synthetic.add_function(0)
        synthetic.update_analysis_and_wait()
        report["synthetic_function"] = function_evidence(synthetic, 0)
    finally:
        synthetic.file.close()
    report["native_decode_passed"] = decoded_clrbhb(report["synthetic_instruction"])
    report["synthetic_analysis_passed"] = endpoint_analysis_complete(
        {"address": "0x0", "function": report["synthetic_function"]}
    )
    save()
    report["endpoints"] = []
    workspace = None
    try:
        if config.get("reference"):
            for side in ("reference", "target"):
                path = config[side]
                if (
                    hashlib.sha256(Path(path).read_bytes()).hexdigest()
                    != INPUT_HASHES[side]
                ):
                    raise RuntimeError(
                        "endpoint RVAs require the recorded ARM64 Secure Kernel pair"
                    )

                def open_file(path=path):
                    (context,) = UIContext.allContexts()
                    return context.openFilename(path)

                if not main_thread(open_file):
                    raise RuntimeError("could not open selected PE in GUI")
            workspace = Workspace()
            for binary in workspace.list_binaries()["binaries"]:
                _, view, _, _ = workspace.acquire(binary["binary_id"])
                view.update_analysis_and_wait()
                path = Path(view.file.original_filename).resolve()
                side = (
                    "reference"
                    if path == Path(config["reference"]).resolve()
                    else "target"
                )
                first = 0x10FC00 if side == "reference" else 0x11AC00
                report.setdefault("inputs", {})[side] = {
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    "architecture": binary["architecture"],
                    "identity": binary["identity"],
                }
                for offset in range(8):
                    at = view.start + first + offset * 0x80
                    row = decode_instruction(view.arch, view.read(at, 12), at)
                    row.update(
                        {
                            "side": side,
                            "rva": hex(at - view.start),
                            "function": function_evidence(view, at),
                        }
                    )
                    report["endpoints"].append(row)
                save()
        report["endpoint_decoding_passed"] = len(report["endpoints"]) == 16 and all(
            decoded_clrbhb(row) for row in report["endpoints"]
        )
        report["endpoint_analysis_passed"] = len(report["endpoints"]) == 16 and all(
            endpoint_analysis_complete(row) for row in report["endpoints"]
        )
        # Full comparison is meaningful after native decoding succeeds. Keep the old
        # fallback capture as evidence when this prerequisite still fails.
        report["comparison"] = {
            "status": "not_run",
            "reason": "native decoding/analysis prerequisite not met",
        }
        prerequisites = (
            report["native_decode_passed"]
            and report["synthetic_analysis_passed"]
            and report["endpoint_decoding_passed"]
            and report["endpoint_analysis_passed"]
        )
        report["ok"] = prerequisites and compare_endpoints(
            workspace, config, report, save
        )
    finally:
        if workspace:
            workspace.shutdown()
        save()


def active_shutdown(config, report, save, quit_action):
    """Observe the real aboutToQuit hook while export or BinDiff is still active."""
    import binaryninja as bn
    from binaryninjaui import FileContext, UIContext
    from binja_windbg_mcp.adapter import Workspace, main_thread
    from binja_windbg_mcp.bootstrap import Plugin
    from binja_windbg_mcp.profiles import Profiles
    from binja_windbg_mcp.server import Listener
    from PySide6.QtWidgets import QApplication

    plugin = None

    def wait(predicate, timeout=150):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            time.sleep(0.01)
        raise TimeoutError("active-work observation timed out")

    def resources(active):
        process = active.process
        return {
            "export_thread_alive": bool(active.thread and active.thread.is_alive()),
            "temporary_directory_exists": active.root.exists(),
            "process_created": process is not None,
            "process_returncode": process.process.poll() if process else None,
            "output_reader_alive": process.reader.is_alive() if process else False,
        }

    try:
        for side in ("reference", "target"):

            def open_file(side=side):
                (context,) = UIContext.allContexts()
                return context.openFilename(config[side])

            if not main_thread(open_file):
                raise RuntimeError("could not open lifecycle input")
        workspace = Workspace()
        main_thread(workspace.attach_ui_notifications)
        profiles = Profiles(Path(config["output"]) / "private-profile")
        profiles._data["similarity"] = {"bindiff_path": config["bindiff"]}
        listener = Listener(workspace, profiles, port=0)
        plugin = main_thread(lambda: Plugin(bn))
        globals()["active_plugin"] = plugin
        plugin.listener = listener
        main_thread(plugin.attach_shutdown_hooks)
        main_thread(plugin.start)
        wait(lambda: listener.state == "listening", 30)
        ids = {}
        for item in workspace.list_binaries()["binaries"]:
            _, view, _, _ = workspace.acquire(item["binary_id"])
            view.update_analysis_and_wait()
            ids[Path(view.file.original_filename).resolve()] = item["binary_id"]
        backend = workspace.similarity.backend.backends["external"]
        captured = []
        prepare = backend.prepare

        def observe_prepare(*args, **kwargs):
            active = prepare(*args, **kwargs)
            captured.append(active)
            return active

        backend.prepare = observe_prepare
        started = workspace.similarity.start(
            ids[Path(config["reference"]).resolve()],
            ids[Path(config["target"]).resolve()],
            backend="external",
        )
        job = workspace.similarity._jobs[started["comparison_id"]]
        active = wait(lambda: captured and captured[0])
        stage = "matching" if config["case"] == "quit_matching" else "exporting"
        wait(
            lambda: (
                active.stage == stage
                and active.thread.is_alive()
                and (
                    stage != "matching"
                    or (active.process and active.process.process.poll() is None)
                )
            )
        )

        def on_quit():
            # Registered after the companion's shutdown hook, so this observes its cleanup.
            try:
                report["job_done"] = job.done.is_set()
                report["job_reason"] = job.reason
                report["resources_after"] = after = resources(active)
                report["listener_thread_alive"] = listener.thread.is_alive()
                report["ok"] = (
                    report["job_done"]
                    and not report["listener_thread_alive"]
                    and not after["export_thread_alive"]
                    and not after["temporary_directory_exists"]
                    and not after["output_reader_alive"]
                    and (
                        not after["process_created"]
                        or after["process_returncode"] is not None
                    )
                )
            except Exception as error:
                report["ok"] = False
                report["cleanup_error"] = type(error).__name__
            save()

        def act():
            report["before_action"] = workspace.similarity.status(
                started["comparison_id"]
            )
            report["active_resources_before"] = resources(active)
            if (
                not report["before_action"]["active"]
                or active.stage != stage
                or not active.thread.is_alive()
            ):
                raise RuntimeError(
                    "comparison ended before Quit; active-work check not exercised"
                )
            if stage == "matching" and (
                not active.process or active.process.process.poll() is not None
            ):
                raise RuntimeError("BinDiff ended before Quit")
            report["observed_stage"] = stage
            QApplication.instance().aboutToQuit.connect(on_quit)
            for context in FileContext.getOpenFileContexts():
                for view in context.getAllDataViews():
                    view.file.modified = False
            save()
            quit_action()

        main_thread(act)
    except Exception as error:
        report["error"] = type(error).__name__ + ": " + str(error)
        report["ok"] = False
        save()
        if plugin:
            try:
                main_thread(plugin.shutdown)
            except Exception as cleanup_error:
                report["cleanup_error"] = type(cleanup_error).__name__
                save()
        main_thread(quit_action)


def start(config_path):
    import binaryninja as bn
    from binaryninjaui import UIContext
    from PySide6.QtCore import QTimer
    from PySide6.QtWidgets import QApplication

    config = json.loads(Path(config_path).read_text())
    output = Path(config["output"])
    report = {
        "schema_version": 1,
        "case": config["case"],
        "ok": False,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "bn_version": bn.core_version(),
        "edition": bn.core_product_type(),
    }

    def save():
        (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")

    app = QApplication.instance()

    def about_to_quit():
        report["about_to_quit"] = True
        save()

    app.aboutToQuit.connect(about_to_quit)

    def quit_action(guard=True):
        if guard and app.activeModalWidget() is not None:
            raise RuntimeError("modal dialog blocks ordinary Quit")
        (context,) = UIContext.allContexts()
        handler = context.getCurrentActionHandler()
        if not handler.isValidAction("Quit"):
            raise RuntimeError("Quit action unavailable")
        handler.executeAction("Quit")

    def background():
        try:
            capture_decode(config, report, save)
        except Exception as error:
            report["error"] = type(error).__name__ + ": " + str(error)
            report["ok"] = False
        finally:
            save()

            def finish():
                try:
                    # These views exist only in this disposable process.
                    from binaryninjaui import FileContext

                    for context in FileContext.getOpenFileContexts():
                        for view in context.getAllDataViews():
                            view.file.modified = False
                    quit_action()
                except Exception as error:
                    report["cleanup_error"] = str(error)
                    report["ok"] = False
                    save()

            bn.execute_on_main_thread(finish)

    try:
        case = config["case"]
        if case == "decode":
            if app.activeModalWidget() is not None:
                raise RuntimeError("modal dialog blocks decoding probe")
            threading.Thread(
                target=background, name="clrbhb-probe", daemon=True
            ).start()
            return
        if case in ("quit", "quit_matching"):
            if app.activeModalWidget() is not None:
                raise RuntimeError("modal dialog blocks active-work probe")
            threading.Thread(
                target=active_shutdown,
                args=(config, report, save, quit_action),
                name="shutdown-probe",
                daemon=True,
            ).start()
            return
        modal = app.activeModalWidget()
        report["modal"] = modal.metaObject().className() if modal else None
        save()
        if case in ("wizard", "qt-wizard"):
            if report["modal"] != "FirstSetupDialog":
                raise RuntimeError("original wizard scenario was not present")
            report["ok"] = True
            save()  # Child-exit evidence, not this flag, determines success.
            if case == "wizard":
                quit_action(guard=False)
            else:
                app.quit()

                def observe():
                    report["alive_after_qt_quit"] = True
                    report["ok"] = False
                    save()
                    if app.activeModalWidget() is not None:
                        app.activeModalWidget().reject()
                    QTimer.singleShot(100, quit_action)

                QTimer.singleShot(3000, observe)
        elif case == "guard":
            from PySide6.QtWidgets import QDialog

            dialog = QDialog()
            dialog.setModal(True)
            dialog.show()
            globals()["guard_dialog"] = dialog

            def check_guard():
                try:
                    quit_action()
                    raise RuntimeError("modal guard did not refuse")
                except RuntimeError as error:
                    if str(error) != "modal dialog blocks ordinary Quit":
                        raise
                    report["guard_refused"] = True
                dialog.reject()
                report["ok"] = True
                save()
                QTimer.singleShot(100, quit_action)

            QTimer.singleShot(100, check_guard)
        else:
            if modal is not None:
                raise RuntimeError("wizard-disabled control has an active modal")
            report["ok"] = True
            save()
            quit_action()
    except Exception as error:
        report["error"] = type(error).__name__ + ": " + str(error)
        report["ok"] = False
        save()
        if app.activeModalWidget() is None:
            try:
                quit_action()
            except Exception as cleanup_error:
                report["cleanup_error"] = type(cleanup_error).__name__
                save()
