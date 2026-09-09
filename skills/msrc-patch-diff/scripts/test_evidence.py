"""Offline regression checks: python3 -m unittest discover -s scripts -v."""

import copy
import hashlib
import struct
import unittest

import evidence
import gui_capture


class EvidenceTests(unittest.TestCase):
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
