import json
import threading
import time
import traceback
from pathlib import Path


def start(reference, target, output):
    thread = threading.Thread(target=run, args=(reference, target, output), daemon=True)
    thread.start()


def run(reference, target, output):
    import binaryninja as bn
    from binaryninjaui import UIContext
    from PySide6.QtWidgets import QApplication
    from binja_windbg_mcp.adapter import Workspace, main_thread
    from binja_windbg_mcp.binexport import BinExport

    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    report = {"bn_version": bn.core_version(), "ok": False}

    def context():
        app = QApplication.instance()
        assert app is not None and app.activeModalWidget() is None
        contexts = list(UIContext.allContexts())
        assert len(contexts) == 1
        return contexts[0]

    def quit_app():
        handler = context().getCurrentActionHandler()
        assert handler.isValidAction("Quit")
        handler.executeAction("Quit")

    try:
        main_thread(context)
        for path in (reference, target):
            assert main_thread(lambda path=path: context().openFilename(path))
        workspace = Workspace()
        binaries = workspace.list_binaries()["binaries"]
        assert len(binaries) == 2
        rows = []
        omissions = {
            Path(reference).resolve(): range(0x10FC00, 0x110000, 0x80),
            Path(target).resolve(): range(0x11AC00, 0x11B000, 0x80),
        }
        exporter = BinExport()
        for item in binaries:
            _, view, _, _ = workspace.acquire(item["binary_id"])
            view.update_analysis_and_wait()
            path = Path(view.file.original_filename).resolve()
            export = exporter.export(view, output / ("reference.BinExport" if path == Path(reference).resolve() else "target.BinExport"), lambda: None)
            for rva in omissions[path]:
                address = view.start + rva
                function = view.get_function_at(address)
                assert function is not None
                blocks = []
                for block in function.basic_blocks:
                    instructions = []
                    for tokens, instr_address in block:
                        instructions.append({"address": hex(instr_address), "text": "".join(t.text for t in tokens)})
                    blocks.append({"start": hex(block.start), "end": hex(block.end), "length": block.length, "instructions": instructions})
                section = view.get_sections_at(address)
                rows.append({
                    "path": str(path), "rva": hex(rva), "address": hex(address),
                    "name": function.name, "highest_address": hex(function.highest_address),
                    "total_bytes": function.total_bytes, "block_count": len(blocks),
                    "blocks": blocks, "bytes_32": view.read(address, 32).hex(),
                    "sections": [s.name for s in section],
                    "export_reports_flow_graph": address in export["functions"],
                    "code_refs_to": sorted(hex(ref.address) for ref in view.get_code_refs(address))[:50],
                })
        report["binaries"] = binaries
        report["functions"] = rows
        report["ok"] = True
    except Exception:
        report["error"] = traceback.format_exc()
    finally:
        (output / "diagnostic.json").write_text(json.dumps(report, indent=2) + "\n")
        try:
            main_thread(quit_app)
        except Exception:
            report["quit_error"] = traceback.format_exc()
            (output / "diagnostic.json").write_text(json.dumps(report, indent=2) + "\n")
