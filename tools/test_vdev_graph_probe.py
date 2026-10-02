"""Offline checks for the inbox-device graph helpers."""

import ctypes
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import vdev_graph_probe as graph  # noqa: E402
import vdev_firmware_probe as firmware  # noqa: E402
import vdev_initialization_probe as contract  # noqa: E402


class DependencyMergeTests(unittest.TestCase):
    def test_required_consumer_wins_over_optional_consumer(self):
        iid = "{00000000-0000-0000-0000-000000000001}"
        merged = graph.merge_dependencies(
            [
                contract.dependency("Example", iid, required=False),
                contract.dependency("Example", iid, required=True),
            ]
        )
        self.assertEqual(len(merged), 1)
        self.assertTrue(merged[0].required)

    def test_conflicting_names_are_rejected(self):
        iid = "{00000000-0000-0000-0000-000000000002}"
        with self.assertRaisesRegex(RuntimeError, "dependency name mismatch"):
            graph.merge_dependencies(
                [
                    contract.dependency("First", iid),
                    contract.dependency("Second", iid),
                ]
            )


class RamLocationTests(unittest.TestCase):
    def test_low_and_high_ranges_map_to_block_offsets(self):
        self.assertEqual(graph.locate_ram_pages(0x100, 2), (0, 0x100))
        self.assertEqual(graph.locate_ram_pages(0x100020, 3), (1, 0x20))

    def test_a_range_cannot_cross_the_mmio_hole(self):
        with self.assertRaisesRegex(ValueError, "outside one RAM span"):
            graph.locate_ram_pages(0xF7FFF, 2)

    def test_invalid_ranges_are_rejected(self):
        for gpa_page, page_count in ((-1, 1), (0, 0), (0, -1)):
            with self.subTest(gpa_page=gpa_page, page_count=page_count):
                with self.assertRaises(ValueError):
                    graph.locate_ram_pages(gpa_page, page_count)

    def test_page_writer_chunks_and_zero_pads(self):
        class Owner:
            handle = 0x1234

        topology = graph.WindowsRamTopology.__new__(graph.WindowsRamTopology)
        topology.owner = Owner()
        topology.blocks = [0xAA, 0xBB]
        calls = []

        def write(_owner, block, block_page, page_count, data, data_size):
            calls.append(
                (block, block_page, page_count, ctypes.string_at(data, data_size))
            )
            return 1

        topology.write_pages_api = write
        payload = b"A" * (16 * graph.PAGE_SIZE + 3)
        topology.write_pages(0x100, 17, payload)

        self.assertEqual([len(call[3]) for call in calls], [0x10000, 0x1000])
        self.assertEqual(calls[0][:3], (0xAA, 0x100, 16))
        self.assertEqual(calls[1][:3], (0xAA, 0x110, 1))
        self.assertEqual(calls[1][3][:3], b"AAA")
        self.assertEqual(calls[1][3][3:], bytes(graph.PAGE_SIZE - 3))

    def test_page_writer_rejects_more_data_than_the_range(self):
        topology = graph.WindowsRamTopology.__new__(graph.WindowsRamTopology)
        with self.assertRaisesRegex(ValueError, "exceed"):
            topology.write_pages(0, 1, bytes(graph.PAGE_SIZE + 1))


class FirmwareAcpiTests(unittest.TestCase):
    def test_measured_tables_have_expected_lengths_and_checksums(self):
        tables = firmware.firmware_acpi_tables()
        self.assertEqual(len(tables["madt"]), 80)
        self.assertEqual(len(tables["srat"]), 144)
        self.assertEqual(tables["slit"], b"")
        self.assertEqual(tables["pptt"], b"")
        for name in ("madt", "srat"):
            with self.subTest(name=name):
                self.assertEqual(sum(tables[name]) & 0xFF, 0)
                self.assertEqual(
                    struct.unpack_from("<I", tables[name], 4)[0], len(tables[name])
                )

    def test_acpi_signature_must_be_four_bytes(self):
        with self.assertRaisesRegex(ValueError, "four bytes"):
            firmware.acpi_table(b"BAD", 1, b"")


if __name__ == "__main__":
    unittest.main()
