"""Offline tests for the saved-state probe's decode half.

No bench, no driver and no VM: every fixture here is **synthetic**, built to hit the rule under
test deliberately rather than by luck, and none of it is memory recorded off a real Secure Kernel
(`AGENTS.md` keeps captures out of version control, and a real page would only exercise whichever
rules it happened to touch).

The three that matter are the ones an earlier run of this work paid for: a page-table walk that
re-enters a self-mapping root, a page judged on a 16-byte prefix, and a `KDBG` tag believed without
its `KernBase` being checked.

    python -m unittest discover -s tools -p 'test_*.py'
"""

import struct
import unittest
import unittest.mock

import sk_savedstate_probe as probe

PAGE = probe.PAGE


def entry(pfn_gpa, present=True, large=False):
    value = pfn_gpa & probe.PFN_MASK
    if present:
        value |= 1
    if large:
        value |= 0x80
    return value


def table(entries):
    """A 4 KiB page holding 512 qwords, with `entries` as {index: value}."""
    page = bytearray(PAGE)
    for index, value in entries.items():
        struct.pack_into("<Q", page, index * 8, value)
    return bytes(page)


class FakeSource:
    """Stands in for `SavedState`, offering only the `read` the decode half uses."""

    def __init__(self, pages, unreadable=()):
        self.pages = pages
        self.unreadable = set(unreadable)
        self.reads = 0

    def read(self, gpa, size):
        self.reads += 1
        base = gpa & ~(PAGE - 1)
        if base in self.unreadable:
            return b"", "hresult 0x80004005"
        page = self.pages.get(base)
        if page is None:
            return b"", "unmapped"
        offset = gpa & (PAGE - 1)
        return page[offset : offset + size], None


ROOT = 0x1000
SELF_MAP_INDEX = 100
UPPER_INDEX = 256


def four_level_tree(extra_pdpt_entries=None, pd_large=False):
    """A minimal PML4 -> PDPT -> PD -> PT tree whose root self-maps at index 100."""
    pdpt_entries = {0: entry(0x3000)}
    if extra_pdpt_entries:
        pdpt_entries.update(extra_pdpt_entries)
    pages = {
        ROOT: table({SELF_MAP_INDEX: entry(ROOT), UPPER_INDEX: entry(0x2000)}),
        0x2000: table(pdpt_entries),
        0x3000: table({0: entry(0x400000, large=True) if pd_large else entry(0x4000)}),
        0x4000: table({0: entry(0x5000), 1: entry(0x6000)}),
        0x5000: b"\x00" * PAGE,
        0x6000: b"\x00" * PAGE,
        0x400000: b"\x00" * PAGE,
    }
    return FakeSource(pages)


class WalkGuards(unittest.TestCase):
    def test_a_self_mapping_root_is_not_descended_into(self):
        source = four_level_tree()
        leaves, reads, truncated = probe.walk(source, ROOT)
        self.assertIsNone(truncated)
        # Exactly the two real leaves. Dropping the PFN-equality guard makes the descent take the
        # self-map down three levels and collect that table's own entries as leaves too.
        self.assertEqual(len(leaves), 2)
        self.assertEqual(reads, 4)

    def test_leaf_virtual_addresses_are_canonical_and_unsigned(self):
        source = four_level_tree()
        leaves, _, _ = probe.walk(source, ROOT)
        for va, _gpa, _size in leaves:
            self.assertGreater(va, 0, "a sign-extended VA compares false against a guest pointer")
            self.assertEqual(va >> 48, 0xFFFF)

    def test_a_large_page_leaf_reports_its_own_size(self):
        source = four_level_tree(pd_large=True)
        leaves, _, truncated = probe.walk(source, ROOT)
        self.assertIsNone(truncated)
        self.assertEqual([size for _va, _gpa, size in leaves], [1 << 21])

    def test_exhausting_the_read_budget_is_reported_not_absorbed(self):
        source = four_level_tree()
        with unittest.mock.patch.object(probe, "MAX_TABLE_READS", 2):
            leaves, reads, truncated = probe.walk(source, ROOT)
        self.assertIsNotNone(truncated)
        self.assertIn("table read budget", truncated)
        self.assertLessEqual(reads, 2)
        self.assertEqual(leaves, [])

    def test_exhausting_the_leaf_budget_is_reported_not_absorbed(self):
        source = four_level_tree()
        with unittest.mock.patch.object(probe, "MAX_LEAVES", 1):
            leaves, _reads, truncated = probe.walk(source, ROOT)
        self.assertIsNotNone(truncated)
        self.assertIn("leaf budget", truncated)
        self.assertEqual(len(leaves), 1)

    def test_an_unreadable_table_is_skipped_rather_than_ending_the_walk(self):
        source = four_level_tree(extra_pdpt_entries={1: entry(0x7000)})
        source.unreadable.add(0x7000)
        leaves, _reads, truncated = probe.walk(source, ROOT)
        self.assertIsNone(truncated)
        self.assertEqual(len(leaves), 2)


class RootDescription(unittest.TestCase):
    def test_a_page_is_judged_whole_and_not_on_its_first_sixteen_bytes(self):
        page = bytearray(PAGE)
        struct.pack_into("<Q", page, 266 * 8, entry(0x9000))
        struct.pack_into("<Q", page, 388 * 8, entry(ROOT))
        source = FakeSource({ROOT: bytes(page)})
        described = probe.describe_root(source, ROOT)
        self.assertTrue(described["readable"])
        self.assertEqual(described["present_entries"], 2)
        self.assertEqual(described["self_map_indexes"], [388])
        self.assertEqual(described["first_present_index"], 266)
        self.assertEqual(described["first_present_byte_offset"], 0x850)
        self.assertEqual(described["upper_half_present"], 2)
        self.assertEqual(bytes(page[:16]), b"\x00" * 16, "the fixture's prefix is deliberately empty")

    def test_an_unreadable_root_carries_the_reason(self):
        source = FakeSource({}, unreadable=[ROOT])
        described = probe.describe_root(source, ROOT)
        self.assertFalse(described["readable"])
        self.assertIn("0x80004005", described["reason"])


def pe64(sections, timestamp, size_of_image, magic=0x20B):
    """A synthetic PE64 header: DOS stub, signature, file header, optional header, sections."""
    e_lfanew = 0x80
    optional_size = 0xF0
    buffer = bytearray(PAGE)
    buffer[0:2] = b"MZ"
    struct.pack_into("<I", buffer, 0x3C, e_lfanew)
    buffer[e_lfanew : e_lfanew + 4] = b"PE\0\0"
    struct.pack_into("<HHI", buffer, e_lfanew + 4, 0x8664, len(sections), timestamp)
    struct.pack_into("<H", buffer, e_lfanew + 20, optional_size)
    struct.pack_into("<H", buffer, e_lfanew + 24, magic)
    struct.pack_into("<I", buffer, e_lfanew + 24 + 56, size_of_image)
    table_start = e_lfanew + 24 + optional_size
    for index, name in enumerate(sections):
        start = table_start + index * 40
        buffer[start : start + 8] = name.encode("ascii").ljust(8, b"\0")
    return bytes(buffer)


class PeIdentity(unittest.TestCase):
    def test_a_pe64_header_yields_sections_timestamp_and_size(self):
        identity = probe.pe_identity(pe64([".text", "TRNS", "CFGRO"], 0x94DED27F, 0x175000))
        self.assertEqual(identity["sections"], 3)
        self.assertEqual(identity["timestamp"], 0x94DED27F)
        self.assertEqual(identity["size_of_image"], 0x175000)
        self.assertEqual(identity["section_names"], [".text", "TRNS", "CFGRO"])

    def test_a_pe32_header_is_refused(self):
        self.assertIsNone(probe.pe_identity(pe64([".text"], 1, 2, magic=0x10B)))

    def test_a_page_that_is_not_an_image_is_refused(self):
        self.assertIsNone(probe.pe_identity(b"\xAA" * PAGE))

    def test_identity_differs_on_a_single_section_name(self):
        left = probe.pe_identity(pe64([".text", "TRNS"], 7, 0x1000))
        right = probe.pe_identity(pe64([".text", "SNRT"], 7, 0x1000))
        self.assertFalse(probe.same_image(left, right))
        self.assertTrue(probe.same_image(left, dict(left)))


BASE_VA = 0xFFFFF80220D89000


def image_with_kdbg(blocks):
    """An image buffer carrying a `KDBG` tag per (offset, size, kern_base, psl) in `blocks`."""
    buffer = bytearray(b"\x00" * 0x4000)
    for offset, size, kern_base, psl in blocks:
        buffer[offset + 0x10 : offset + 0x14] = b"KDBG"
        struct.pack_into("<I", buffer, offset + 0x14, size)
        struct.pack_into("<Q", buffer, offset + 0x18, kern_base)
        struct.pack_into("<Q", buffer, offset + 0x48, psl)
    return bytes(buffer)


class KdbgSearch(unittest.TestCase):
    def test_a_coincidental_tag_is_reported_and_marked_unvalidated(self):
        image = image_with_kdbg(
            [
                (0x100, 0x2C058948, 0x74250D8D48000874, 0x874160D89480009),
                (0x1000, 0x3A0, BASE_VA, BASE_VA + 0x127770),
            ]
        )
        hits = probe.find_kdbg(image, BASE_VA)
        self.assertEqual(len(hits), 2)
        self.assertEqual([hit["kern_base_matches"] for hit in hits], [False, True])
        good = hits[1]
        self.assertEqual(good["size"], 0x3A0)
        self.assertEqual(good["ps_loaded_module_list"] - BASE_VA, 0x127770)

    def test_the_size_is_reported_rather_than_matched(self):
        # A block whose Size is neither 0x3A0 nor 0x3A8 is still found and still validated by
        # KernBase -- searching for tag-plus-remembered-size is what once reported zero hits.
        image = image_with_kdbg([(0x200, 0x999, BASE_VA, BASE_VA + 8)])
        hits = probe.find_kdbg(image, BASE_VA)
        self.assertEqual(len(hits), 1)
        self.assertTrue(hits[0]["kern_base_matches"])
        self.assertEqual(hits[0]["size"], 0x999)

    def test_a_tag_spanning_a_page_boundary_is_found(self):
        # gather_image produces one contiguous buffer precisely so this case is not lost.
        pages = {
            BASE_VA: b"\x11" * (PAGE - 4) + b"KDBG",
            BASE_VA + PAGE: struct.pack("<I", 0x3A0) + struct.pack("<Q", BASE_VA) + b"\x00" * (PAGE - 12),
        }
        image, missing = probe.gather_image(lambda va: pages.get(va), BASE_VA, 2 * PAGE)
        self.assertEqual(missing, [])
        hits = probe.find_kdbg(image, BASE_VA)
        self.assertEqual([hit["size"] for hit in hits], [0x3A0])


class GatherImage(unittest.TestCase):
    def test_an_unreadable_page_is_poisoned_and_reported(self):
        pages = {BASE_VA: b"\x01" * PAGE}
        image, missing = probe.gather_image(lambda va: pages.get(va), BASE_VA, 2 * PAGE)
        self.assertEqual(missing, [PAGE])
        self.assertEqual(image[PAGE : PAGE + 8], b"\xAA" * 8)
        self.assertNotEqual(image[PAGE : PAGE + 8], b"\x00" * 8, "zeros would read as captured data")


class RegisterIdParsing(unittest.TestCase):
    def test_positions_are_counted_and_an_explicit_value_restarts_the_count(self):
        header = (
            "typedef enum REGISTER_ID\n"
            "{\n"
            "    // a comment\n"
            "    X64_RegisterRax = 0,\n"
            "    X64_RegisterRcx,\n"
            "    X64_RegisterCr3 = 46,\n"
            "    X64_RegisterCr4,\n"
            "} REGISTER_ID;\n"
        )
        import pathlib
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory, "defs.h")
            path.write_text(header, encoding="utf-8")
            ids = probe.register_ids(path)
        self.assertEqual(ids["X64_RegisterRax"], 0)
        self.assertEqual(ids["X64_RegisterRcx"], 1)
        self.assertEqual(ids["X64_RegisterCr3"], 46)
        self.assertEqual(ids["X64_RegisterCr4"], 47)

    def test_a_header_without_the_enum_is_refused(self):
        import pathlib
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory, "defs.h")
            path.write_text("typedef enum SOMETHING_ELSE { A } SOMETHING_ELSE;\n", encoding="utf-8")
            with self.assertRaises(probe.ProbeError):
                probe.register_ids(path)


if __name__ == "__main__":
    unittest.main()
