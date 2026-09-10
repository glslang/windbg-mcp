"""Offline regression checks: python3 -m unittest discover -s scripts -v."""

import copy
import hashlib
import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

import evidence
import gui_capture


class EvidenceTests(unittest.TestCase):
    def test_target_preparation_navigates_then_finishes_analysis(self):
        target = Path("target.dll").resolve()
        reference_view, target_view = Mock(), Mock()
        reference_view.file.original_filename = str(Path("reference.dll").resolve())
        target_view.file.original_filename = str(target)
        target_view.start = 0x180000000
        workspace = Mock()
        workspace.acquire.side_effect = [
            (None, reference_view, None, None),
            (None, target_view, None, None),
        ]
        calls = []
        workspace.navigate.side_effect = lambda *args: calls.append("navigate") or {"rva": "0x1000"}
        target_view.update_analysis_and_wait.side_effect = lambda: calls.append("analysis")
        result = gui_capture.prepare_target(
            workspace, [{"binary_id": "reference"}, {"binary_id": "target"}], target, 0x1000
        )
        workspace.coordinate.assert_called_once_with(target_view, 0x180001000)
        workspace.navigate.assert_called_once_with("target", workspace.coordinate.return_value)
        self.assertEqual(calls, ["navigate", "analysis"])
        self.assertEqual(result["stage"], "before_baseline")
        reference_view.update_analysis_and_wait.assert_not_called()

    def test_target_preparation_refuses_invalid_rva_and_missing_view(self):
        for rva in (-1, True, "0x1000"):
            with self.subTest(rva=rva), self.assertRaises(ValueError):
                gui_capture.prepare_target(Mock(), [], Path("target.dll"), rva)
        with self.assertRaisesRegex(ValueError, "target view unavailable"):
            gui_capture.prepare_target(Mock(), [], Path("target.dll"), 0x1000)

    def test_capture_survives_cleanup_failures_and_still_requests_quit(self):
        for failures in (
            {"comparison_close"},
            {"workspace_shutdown"},
            {"comparison_close", "workspace_shutdown", "quit_request"},
        ):
            with self.subTest(failures=failures), tempfile.TemporaryDirectory() as folder:
                output = Path(folder)
                report = {"ok": False, "error": "original analysis failure"}
                calls = []

                def action(stage):
                    saved = json.loads((output / "capture.json").read_text())
                    self.assertEqual(saved["error"], report["error"])
                    calls.append(stage)
                    if stage in failures:
                        raise RuntimeError(stage)

                workspace = Mock()
                workspace.similarity.close.side_effect = lambda _: action("comparison_close")
                workspace.shutdown.side_effect = lambda: action("workspace_shutdown")
                gui_capture.finalize_capture(
                    report, output, workspace, "comparison", lambda: action("quit_request")
                )
                saved = json.loads((output / "capture.json").read_text())
                self.assertEqual(calls, ["comparison_close", "workspace_shutdown", "quit_request"])
                self.assertEqual({e["stage"] for e in saved["cleanup_errors"]}, failures)
                self.assertEqual(saved["error"], "original analysis failure")
                self.assertFalse(saved["ok"])

    def test_cleanup_failure_invalidates_otherwise_successful_capture(self):
        with tempfile.TemporaryDirectory() as folder:
            workspace = Mock()
            workspace.shutdown.side_effect = RuntimeError("shutdown failed")
            output = Path(folder)
            gui_capture.finalize_capture({"ok": True}, output, workspace, None)
            saved = json.loads((output / "capture.json").read_text())
            self.assertFalse(saved["ok"])
            self.assertIn("shutdown failed", saved["cleanup_errors"][0]["error"])
            workspace.similarity.close.assert_not_called()

    def test_provenance_omits_signed_redirect_credentials(self):
        source = "https://msdl.microsoft.com/download/symbols/a.dll/1234/a.dll"
        final = "https://example.blob.core.windows.net/file?sv=1&sig=secret#token"
        result = evidence.provenance(source, final, b"binary")
        self.assertEqual(result["url"], source)
        self.assertEqual(
            result["final_url"], "https://example.blob.core.windows.net/file"
        )
        self.assertEqual(result["sha256"], hashlib.sha256(b"binary").hexdigest())

    def test_gui_capture_pages_all_results(self):
        records = [{"result_id": str(i)} for i in range(203)]

        def results(*args, offset, limit):
            end = min(offset + limit, len(records))
            return {
                "items": records[offset:end],
                "next_offset": end if end < len(records) else None,
            }

        self.assertEqual(gui_capture.pages(results, "comparison"), records)

    def test_gui_capture_refuses_nonadvancing_pages(self):
        with self.assertRaisesRegex(RuntimeError, "did not advance"):
            gui_capture.pages(lambda *a, **k: {"items": [], "next_offset": 0})

    def test_partial_results_are_explicitly_not_full_acceptance(self):
        self.assertFalse(
            gui_capture.full_acceptance(
                {"state": "partial", "coverage_complete": False}, True, True
            )
        )
        self.assertTrue(
            gui_capture.full_acceptance(
                {"state": "completed", "coverage_complete": True}, True, True
            )
        )

    def test_exact_cve_product_join_preserves_remediation(self):
        record = {
            "CVE": "CVE-2026-83498",
            "Remediations": [
                {
                    "ProductID": ["12390"],
                    "FixedBuild": "10.0.26100.9445",
                    "AffectedFiles": [],
                }
            ],
        }
        document = {
            "Vulnerability": [{"CVE": "CVE-2026-11111"}, record],
            "ProductTree": {
                "Branch": [
                    {"Items": [{"ProductID": "12390", "Value": "Windows 11 24H2 x64"}]}
                ]
            },
        }
        result = evidence.extract_cve(document, "CVE-2026-83498")
        self.assertEqual(result["vulnerability"], record)
        self.assertEqual(result["products"], {"12390": "Windows 11 24H2 x64"})
        with self.assertRaises(ValueError):
            evidence.extract_cve(document, "CVE-2026-22222")

    def test_inventory_requires_exact_kb_lane_and_architecture(self):
        row = {
            "fileInfo": {"machineType": 0x8664},
            "windowsVersions": {
                "11-24H2": {
                    "KB123": {"updateInfo": {"otherWindowsVersions": ["11-25H2"]}}
                }
            },
        }
        data = {"a" * 64: row}
        self.assertEqual(
            len(evidence.inventory_rows(data, "x64", "11-24H2", "KB123")), 1
        )
        self.assertEqual(
            len(evidence.inventory_rows(data, "x64", "11-25H2", "KB123")), 1
        )
        for arch, lane, kb in [
            ("arm64", "11-24H2", "KB123"),
            ("x64", "11-23H2", "KB123"),
            ("x64", "11-24H2", "KB12"),
        ]:
            self.assertEqual(evidence.inventory_rows(data, arch, lane, kb), [])

    def test_inventory_retains_ambiguous_same_version_candidates(self):
        row = {
            "fileInfo": {"machineType": 0x8664},
            "windowsVersions": {"11-24H2": {"KB123": {"updateInfo": {}}}},
        }
        data = {"a" * 64: row, "b" * 64: copy.deepcopy(row)}
        self.assertEqual(
            len(evidence.inventory_rows(data, "x64", "11-24H2", "KB123")), 2
        )

    def test_symbol_url_uses_padded_timestamp_and_unpadded_image_size(self):
        self.assertEqual(
            evidence.symbol_url("A.DLL", {"timestamp": 0x123AB, "virtualSize": 0x3000}),
            "https://msdl.microsoft.com/download/symbols/a.dll/000123AB3000/a.dll",
        )
        for name in ["../a.dll", "a/b.dll", "a.dll?token=x", "a.dll\\other.sys"]:
            with self.assertRaises(ValueError):
                evidence.filename(name)

    def test_hash_and_each_pe_identity_field_are_verified(self):
        data = bytearray(512)
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 0x3C, 0x80)
        data[0x80:0x84] = b"PE\0\0"
        struct.pack_into("<H", data, 0x84, 0x8664)
        struct.pack_into("<I", data, 0x88, 123)
        struct.pack_into("<H", data, 0x94, 240)
        struct.pack_into("<H", data, 0x98, 0x20B)
        struct.pack_into("<Q", data, 0x98 + 24, 0x180000000)
        struct.pack_into("<I", data, 0x98 + 56, 0x3000)
        row = {
            "sha256": hashlib.sha256(data).hexdigest(),
            "file_info": {
                "size": 512,
                "timestamp": 123,
                "virtualSize": 0x3000,
                "machineType": 0x8664,
            },
        }
        self.assertEqual(
            evidence.verify_binary(data, row, "x64")["image_base"], "0x0000000180000000"
        )
        for key in row["file_info"]:
            wrong = copy.deepcopy(row)
            wrong["file_info"][key] += 1
            with self.assertRaises(ValueError):
                evidence.verify_binary(data, wrong, "x64")
        wrong = copy.deepcopy(row)
        wrong["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            evidence.verify_binary(data, wrong, "x64")

    def test_non_pe_and_truncated_pe_are_refused(self):
        for data in [b"<html>not a DLL</html>", b"MZ" + b"\xff" * 70]:
            with self.assertRaises(ValueError):
                evidence.pe_identity(data)


if __name__ == "__main__":
    unittest.main()
