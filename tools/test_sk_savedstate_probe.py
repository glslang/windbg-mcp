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


class EntryDecoding(unittest.TestCase):
    def test_a_large_leaf_with_pat_set_keeps_its_own_alignment(self):
        # Bit 12 is PAT on a large mapping, not the low bit of the frame. Masking at 4 KiB puts
        # the base one page high, so the leaf starts inside the mapping and ends past it.
        for level, size in ((1, 1 << 30), (2, 1 << 21)):
            with self.subTest(size=size):
                base = size * 3
                decoded = probe.decode_entry(entry(base | 0x1000, large=True), level)
                self.assertEqual(decoded.kind, probe.LEAF)
                self.assertEqual(decoded.size, size)
                self.assertEqual(decoded.address, base)
                self.assertFalse(decoded.malformed)

    def test_a_large_leaf_with_a_reserved_bit_set_is_malformed(self):
        for level, size in ((1, 1 << 30), (2, 1 << 21)):
            with self.subTest(size=size):
                decoded = probe.decode_entry(entry((size * 3) | 0x2000, large=True), level)
                self.assertTrue(decoded.malformed, "bit 13 is reserved on every large mapping")

    def test_the_page_size_bit_has_no_meaning_in_a_pml4_entry(self):
        self.assertTrue(probe.decode_entry(entry(0x2000, large=True), 0).malformed)
        self.assertFalse(probe.decode_entry(entry(0x2000), 0).malformed)

    def test_a_table_entry_keeps_four_kilobyte_granularity(self):
        decoded = probe.decode_entry(entry(0x1234000), 2)
        self.assertEqual(decoded.kind, probe.TABLE)
        self.assertEqual(decoded.address, 0x1234000)
        self.assertIsNone(decoded.size)

    def test_an_absent_entry_decodes_to_nothing(self):
        self.assertIsNone(probe.decode_entry(entry(0x2000, present=False), 2))


class WalkGuards(unittest.TestCase):
    def test_a_self_mapping_root_is_not_descended_into(self):
        source = four_level_tree()
        leaves, stats = probe.walk(source, ROOT)
        self.assertIsNone(stats["truncated"])
        # Exactly the two real leaves. Dropping the path guard takes the self-map down three
        # levels and collects that table's own entries as leaves too.
        self.assertEqual(len(leaves), 2)
        self.assertEqual(stats["table_reads"], 4)

    def test_a_loop_back_to_an_ancestor_terminates_within_the_budgets(self):
        # Four-level paging bounds the depth, so a loop cannot recurse forever; what it can do is
        # multiply leaves, and that is what the budgets and the visited set are between us and.
        source = four_level_tree(extra_pdpt_entries={1: entry(ROOT)})
        leaves, stats = probe.walk(source, ROOT)
        self.assertIsNone(stats["truncated"])
        self.assertLess(stats["table_reads"], 10)
        self.assertLess(len(leaves), 10)

    def test_an_alias_is_skipped_once_and_counted(self):
        # Two parents legitimately point at one table, and this walk expands it under the first
        # prefix only -- deliberately, because Secure Kernel's tables are recursively self-mapped
        # and expanding every prefix is combinatorial. What it owes is to say so, not to be silent.
        source = four_level_tree()
        source.pages[ROOT] = table(
            {SELF_MAP_INDEX: entry(ROOT), UPPER_INDEX: entry(0x2000), UPPER_INDEX + 1: entry(0x2000)}
        )
        leaves, stats = probe.walk(source, ROOT)
        self.assertIsNone(stats["truncated"])
        self.assertEqual(len(leaves), 2)
        self.assertEqual(stats["alias_prefixes_skipped"], 1)

    def test_the_visited_set_is_per_level_so_a_shared_page_serves_at_each(self):
        # One physical page used as both a PD and a PT is ordinary in a self-mapped tree; a single
        # global visited set would decode it at the first level it appeared on and never again.
        pages = {
            ROOT: table({UPPER_INDEX: entry(0x2000)}),
            0x2000: table({0: entry(0x3000), 1: entry(0x4000)}),
            0x3000: table({5: entry(0x5000)}),  # reached at level 2 here, and at level 3 below
            0x4000: table({0: entry(0x3000)}),
            0x5000: table({7: entry(0x6000)}),
            0x6000: b"\x00" * PAGE,
        }
        leaves, stats = probe.walk(FakeSource(pages), ROOT)
        self.assertIsNone(stats["truncated"])
        self.assertEqual(stats["tables_decoded"], 6, "0x3000 is decoded as a PD and again as a PT")
        self.assertEqual(stats["alias_prefixes_skipped"], 0)
        # 0x6000 comes from the level-2 reading of 0x3000; 0x5000 is a leaf only because 0x3000 is
        # also decoded at level 3, which a single global visited set would never reach.
        self.assertEqual(sorted(gpa for _va, gpa, _size in leaves), [0x5000, 0x6000])

    def test_leaf_virtual_addresses_are_canonical_and_unsigned(self):
        source = four_level_tree()
        leaves, _stats = probe.walk(source, ROOT)
        for va, _gpa, _size in leaves:
            self.assertGreater(va, 0, "a sign-extended VA compares false against a guest pointer")
            self.assertEqual(va >> 48, 0xFFFF)

    def test_a_large_page_leaf_reports_its_own_size(self):
        source = four_level_tree(pd_large=True)
        leaves, stats = probe.walk(source, ROOT)
        self.assertIsNone(stats["truncated"])
        self.assertEqual([size for _va, _gpa, size in leaves], [1 << 21])

    def test_a_malformed_entry_is_counted_rather_than_walked(self):
        source = four_level_tree(extra_pdpt_entries={1: entry((1 << 30) | 0x2000, large=True)})
        leaves, stats = probe.walk(source, ROOT)
        self.assertEqual(stats["malformed_entries"], 1)
        self.assertEqual(len(leaves), 2, "the reserved-bit mapping is not invented as a leaf")

    def test_exhausting_the_read_budget_is_reported_not_absorbed(self):
        source = four_level_tree()
        with unittest.mock.patch.object(probe, "MAX_TABLE_READS", 2):
            leaves, stats = probe.walk(source, ROOT)
        self.assertIsNotNone(stats["truncated"])
        self.assertIn("table read budget", stats["truncated"])
        self.assertLessEqual(stats["table_reads"], 2)
        self.assertEqual(leaves, [])

    def test_exhausting_the_leaf_budget_is_reported_not_absorbed(self):
        source = four_level_tree()
        with unittest.mock.patch.object(probe, "MAX_LEAVES", 1):
            leaves, stats = probe.walk(source, ROOT)
        self.assertIsNotNone(stats["truncated"])
        self.assertIn("leaf budget", stats["truncated"])
        self.assertEqual(len(leaves), 1)

    def test_an_unreadable_table_is_skipped_rather_than_ending_the_walk(self):
        source = four_level_tree(extra_pdpt_entries={1: entry(0x7000)})
        source.unreadable.add(0x7000)
        leaves, stats = probe.walk(source, ROOT)
        self.assertIsNone(stats["truncated"])
        self.assertEqual(len(leaves), 2)


class FakeVp:
    """A VP whose force and whose register reads can be made to fail independently."""

    def __init__(self, force_error=None, failing_register=None):
        self.force_error = force_error
        self.failing_register = failing_register

    def force_vtl(self, _vp, _vtl):
        if self.force_error:
            raise probe.ProbeError(self.force_error)

    def active_vtl_enabled(self, _vp):
        return True

    def paging_mode(self, _vp):
        return "Long"

    def register(self, _vp, name):
        if name == self.failing_register:
            raise probe.ProbeError(f"GetRegisterValue({name}) failed: 0x80004001")
        return {"X64_RegisterCr3": 0x1201000}.get(name, 0x1234)


class VtlSwitch(unittest.TestCase):
    def test_a_refused_switch_is_reported_as_a_refusal(self):
        vtl1 = probe.read_vtl(FakeVp(force_error="VTL not enabled"), 0, 1, compare_cr3=0x7D5000)
        self.assertFalse(vtl1["forced"])
        self.assertIn("VTL not enabled", vtl1["force_error"])
        self.assertNotIn("enabled", vtl1)
        self.assertNotIn("cr3", vtl1)

    def test_a_failed_query_after_a_good_switch_is_not_a_refusal(self):
        # The control arm's whole result is "the provider refused VTL1". A provider that cannot
        # return one register must not be able to manufacture that reading.
        vtl1 = probe.read_vtl(FakeVp(failing_register="X64_RegisterEfer"), 0, 1, compare_cr3=0x7D5000)
        self.assertTrue(vtl1["forced"], "the switch succeeded and the report must keep saying so")
        self.assertEqual(sorted(vtl1["errors"]), ["efer"])
        self.assertNotIn("force_error", vtl1)
        self.assertEqual(vtl1["cr3"], 0x1201000, "the fields that answered are kept")

    def test_a_clean_switch_carries_the_comparison_against_vtl0(self):
        vtl1 = probe.read_vtl(FakeVp(), 0, 1, compare_cr3=0x7D5000)
        self.assertTrue(vtl1["forced"])
        self.assertTrue(vtl1["differs_from_vtl0_cr3"])
        self.assertNotIn("errors", vtl1)


class FailingVp(FakeVp):
    """A VP where any named query raises, to check one cannot suppress the others."""

    def __init__(self, failing=()):
        super().__init__()
        self.failing = set(failing)

    def active_vtl_enabled(self, vp):
        if "enabled" in self.failing:
            raise probe.ProbeError("IsActiveVirtualTrustLevelEnabled failed: 0x80004001")
        return super().active_vtl_enabled(vp)

    def paging_mode(self, vp):
        if "paging_mode" in self.failing:
            raise probe.ProbeError("GetPagingMode failed: 0x80004001")
        return super().paging_mode(vp)

    def register(self, vp, name):
        if name in self.failing:
            raise probe.ProbeError(f"GetRegisterValue({name}) failed: 0x80004001")
        return super().register(vp, name)


class DiagnosticsDoNotSuppressTheRoot(unittest.TestCase):
    def test_an_earlier_failing_query_does_not_cost_the_page_table_root(self):
        # The CR3 is the run's primary output. A provider that cannot answer an optional
        # diagnostic must not be able to take it down, which a single try/except did.
        vtl1 = probe.read_vtl(
            FailingVp(failing={"enabled", "paging_mode", "X64_RegisterCr0"}),
            0,
            1,
            compare_cr3=0x7D5000,
        )
        self.assertTrue(vtl1["forced"])
        self.assertEqual(vtl1["cr3"], 0x1201000)
        self.assertTrue(vtl1["differs_from_vtl0_cr3"])
        self.assertEqual(sorted(vtl1["errors"]), ["cr0", "enabled", "paging_mode"])
        self.assertTrue(probe.walkable(vtl1)[0], "the walk still has what it needs")

    def test_a_failure_is_recorded_per_field_rather_than_as_one_flag(self):
        record = {}
        probe.probed(record, "good", lambda: 7)
        probe.probed(record, "bad", lambda: (_ for _ in ()).throw(probe.ProbeError("nope")))
        self.assertEqual(record["good"], 7)
        self.assertNotIn("bad", record)
        self.assertEqual(record["errors"], {"bad": "nope"})


class Vtl0IsReadTheSameWay(unittest.TestCase):
    def test_a_failing_vtl0_diagnostic_does_not_abort_the_run(self):
        # The VTL0 block used to be a second copy of this code that still raised, so a provider
        # that could not answer one diagnostic lost the VTL1 CR3 three screens later.
        vtl0 = probe.read_vtl(FailingVp(failing={"paging_mode", "X64_RegisterEfer"}), 0, 0)
        self.assertTrue(vtl0["forced"])
        self.assertEqual(vtl0["cr3"], 0x1201000)
        self.assertEqual(sorted(vtl0["errors"]), ["efer", "paging_mode"])
        self.assertEqual(vtl0["vtl"], 0)

    def test_long_mode_is_unknown_rather_than_false_when_a_register_is_missing(self):
        # Answering False would make a provider that cannot return EFER look like a machine that
        # is not in long mode -- the control for the register indexing, inverted.
        self.assertIsNone(probe.long_mode_consistent({"cr0": 0x80050033, "cr4": 0xB50EF8}))
        self.assertTrue(
            probe.long_mode_consistent({"cr0": 0x80050033, "cr4": 0xB50EF8, "efer": 0xD01})
        )
        self.assertFalse(
            probe.long_mode_consistent({"cr0": 0x33, "cr4": 0xB50EF8, "efer": 0xD01})
        )


class FailedReadsAreCounted(unittest.TestCase):
    def test_an_unreadable_leaf_is_not_a_leaf_without_an_image(self):
        pages = {0x5000: b"\x00" * PAGE}
        source = FakeSource(pages, unreadable=[0x6000])
        leaves = [(BASE_VA, 0x5000, PAGE), (BASE_VA + PAGE, 0x6000, PAGE)]
        images, scan = probe.scan_leaves_for_images(source, leaves, {"sections": 1})
        self.assertEqual(images, [])
        self.assertEqual(scan["scanned"], 2)
        self.assertEqual(scan["unreadable"], 1, "a refused page is not a page with no header")
        self.assertFalse(scan["capped"])

    def test_a_kdbg_record_split_across_a_page_boundary_is_found(self):
        # A PE image is page-aligned so its MZ never straddles; a debugger data block sits
        # wherever it sits, and the control's negative is over both.
        joined = bytearray(b"\x00" * (2 * PAGE))
        joined[PAGE - 2 : PAGE + 2] = b"KDBG"  # the tag itself is split across the boundary
        header = PAGE - 2 - 0x10
        struct.pack_into("<I", joined, header + 0x14, 0x3A0)
        struct.pack_into("<Q", joined, header + 0x18, BASE_VA)
        source = FakeSource({0x0: bytes(joined[:PAGE]), PAGE: bytes(joined[PAGE:])})
        _images, kdbg, scan = probe.scan_physical_for_images(
            source, [{"start_page": 0, "pages": 2}], PAGE, {"sections": 1}, 10
        )
        self.assertEqual([hit["gpa"] for hit in kdbg], [header])
        self.assertEqual(kdbg[0]["size"], 0x3A0)
        self.assertEqual(kdbg[0]["kern_base"], BASE_VA)
        self.assertEqual(scan["boundary_incomplete"], 0)

    def test_a_record_whose_fields_continue_into_the_next_page_is_decoded(self):
        first = bytearray(b"\x00" * PAGE)
        second = bytearray(b"\x00" * PAGE)
        at = PAGE - 0x14  # tag near the end: size and kern_base land in the next page
        first[at : at + 4] = b"KDBG"
        joined = bytearray(first + second)
        struct.pack_into("<I", joined, at - 0x10 + 0x14, 0x3A0)
        struct.pack_into("<Q", joined, at - 0x10 + 0x18, BASE_VA)
        source = FakeSource({0x0: bytes(joined[:PAGE]), PAGE: bytes(joined[PAGE:])})
        _images, kdbg, _scan = probe.scan_physical_for_images(
            source, [{"start_page": 0, "pages": 2}], PAGE, {"sections": 1}, 10
        )
        self.assertEqual(len(kdbg), 1)
        self.assertEqual(kdbg[0]["size"], 0x3A0)
        self.assertEqual(kdbg[0]["kern_base"], BASE_VA)

    def test_a_record_is_reported_once_and_not_by_both_pairings(self):
        page = bytearray(b"\x00" * PAGE)
        page[0x100 : 0x100 + 4] = b"KDBG"
        struct.pack_into("<I", page, 0xF0 + 0x14, 0x3A0)
        pages = {0: b"\x00" * PAGE, PAGE: bytes(page), 2 * PAGE: b"\x00" * PAGE}
        source = FakeSource(pages)
        _images, kdbg, _scan = probe.scan_physical_for_images(
            source, [{"start_page": 0, "pages": 3}], PAGE, {"sections": 1}, 10
        )
        self.assertEqual([hit["gpa"] for hit in kdbg], [PAGE + 0xF0])

    def test_a_record_with_nowhere_to_continue_is_counted_not_dropped(self):
        page = bytearray(b"\x00" * PAGE)
        page[PAGE - 8 : PAGE - 4] = b"KDBG"  # header at PAGE-0x18: its fields run off the end
        source = FakeSource({0: bytes(page)})
        _images, kdbg, scan = probe.scan_physical_for_images(
            source, [{"start_page": 0, "pages": 1}], PAGE, {"sections": 1}, 10
        )
        self.assertEqual(kdbg, [])
        self.assertEqual(scan["boundary_incomplete"], 1, "the end of the range, not an absence")

    def test_an_unexpected_chunk_granularity_is_refused(self):
        with self.assertRaises(probe.ProbeError):
            probe.scan_physical_for_images(
                FakeSource({}), [{"start_page": 0, "pages": 1}], 0x2000, {"sections": 1}, 10
            )

    def test_an_unreadable_physical_page_is_counted_by_the_control_scan(self):
        pages = {0x0: b"\x00" * PAGE, 0x2000: b"\x00" * PAGE}
        source = FakeSource(pages, unreadable=[0x1000])
        chunks = [{"start_page": 0, "pages": 3}]
        _images, _kdbg, scan = probe.scan_physical_for_images(
            source, chunks, PAGE, {"sections": 1}, 10
        )
        self.assertEqual(scan["scanned"], 3)
        self.assertEqual(scan["unreadable"], 1)

    def test_an_unreadable_table_is_counted_by_the_walk(self):
        source = four_level_tree(extra_pdpt_entries={1: entry(0x7000)})
        source.unreadable.add(0x7000)
        _leaves, stats = probe.walk(source, ROOT)
        self.assertEqual(stats["unreadable_tables"], 1)

    def test_the_source_counts_failures_no_consumer_can_hide(self):
        class FakeReadLib:
            def __init__(self, results):
                self.results = list(results)

            def ReadGuestPhysicalAddress(self, _handle, _gpa, _buffer, size, read_ref):
                hr, got = self.results.pop(0)
                read_ref._obj.value = size if got is None else got
                return hr

        state = probe.SavedState.__new__(probe.SavedState)
        state.lib = FakeReadLib([(0, None), (-2147467259, 0), (0, 8)])
        state.handle = None
        state.reads = state.failed_reads = state.failed_translations = 0
        state.read_bytes = 0
        state.failure_kinds = {}
        self.assertIsNone(state.read(0x1000, 16)[1])
        self.assertIn("hresult", state.read(0x2000, 16)[1])
        self.assertIn("short read", state.read(0x3000, 16)[1])
        self.assertEqual(state.reads, 3)
        self.assertEqual(state.failed_reads, 2)
        self.assertEqual(state.failure_kinds, {"hresult": 1, "short": 1})


class WalkableGate(unittest.TestCase):
    def test_a_refused_switch_blocks_the_walk(self):
        proceed, why = probe.walkable({"forced": False, "force_error": "refused"})
        self.assertFalse(proceed)
        self.assertIn("not switched", why)

    def test_a_provider_saying_the_vtl_is_not_enabled_blocks_the_walk(self):
        proceed, why = probe.walkable({"forced": True, "enabled": False, "cr3": 0x1201000})
        self.assertFalse(proceed)
        self.assertIn("not enabled", why)

    def test_an_unreadable_enabled_flag_does_not_block_the_walk(self):
        # Unknown is not False. The walk's own output is the stronger evidence, and the report
        # already says the question went unanswered.
        proceed, why = probe.walkable(
            {"forced": True, "cr3": 0x1201000, "errors": {"enabled": "0x80004001"}}
        )
        self.assertTrue(proceed)
        self.assertIsNone(why)

    def test_no_root_blocks_the_walk(self):
        proceed, why = probe.walkable({"forced": True, "enabled": True})
        self.assertFalse(proceed)
        self.assertIn("no VTL1 CR3", why)


class FakeChunkLib:
    """Stands in for the provider on `GetGuestPhysicalMemoryChunks` alone."""

    def __init__(self, sizing_hr, sizing_count, chunks=(), fill_hr=0):
        self.sizing_hr = sizing_hr
        self.sizing_count = sizing_count
        self.chunks = chunks
        self.fill_hr = fill_hr

    def GetGuestPhysicalMemoryChunks(self, _handle, page_size_ref, buffer, count_ref):
        if buffer is None:
            count_ref._obj.value = self.sizing_count
            return self.sizing_hr
        page_size_ref._obj.value = PAGE
        for index, (start, pages) in enumerate(self.chunks):
            buffer[index].StartPageIndex = start
            buffer[index].PageCount = pages
        count_ref._obj.value = len(self.chunks)
        return self.fill_hr


class MemoryChunkSizing(unittest.TestCase):
    @staticmethod
    def state(lib):
        state = probe.SavedState.__new__(probe.SavedState)
        state.lib = lib
        state.handle = None
        return state

    def test_the_documented_sizing_failure_is_not_treated_as_a_failure(self):
        # Measured on this bench: the null-buffer call answers 0x8007000E with the count filled
        # in. Checking that HRESULT would reject every healthy capture.
        lib = FakeChunkLib(sizing_hr=-2147024882, sizing_count=2, chunks=((0, 100), (200, 50)))
        page_size, chunks = self.state(lib).memory_chunks()
        self.assertEqual(page_size, PAGE)
        self.assertEqual(chunks, [{"start_page": 0, "pages": 100}, {"start_page": 200, "pages": 50}])

    def test_a_sizing_failure_with_no_count_is_propagated(self):
        # Otherwise it arrives as memory_pages: 0, and --scan-pages turns a provider failure into
        # a clean-looking negative on a capture nothing was ever read from.
        lib = FakeChunkLib(sizing_hr=-2147467259, sizing_count=0)
        with self.assertRaises(probe.ProbeError):
            self.state(lib).memory_chunks()

    def test_an_honest_empty_map_is_not_an_error(self):
        lib = FakeChunkLib(sizing_hr=0, sizing_count=0)
        page_size, chunks = self.state(lib).memory_chunks()
        self.assertEqual(chunks, [])


class ImageIdentification(unittest.TestCase):
    @staticmethod
    def gatherer(blocks_by_va):
        def gather(va, size):
            return image_with_kdbg(blocks_by_va.get(va, []))[:size], []

        return gather

    def test_a_second_mapping_is_tried_when_the_first_does_not_name_itself(self):
        # Two mappings of one image: the alias's block still names the real base, so its KernBase
        # check fails. Stopping at the first candidate reports no data block for an image that has
        # one -- and which candidate the walk reaches first is prefix order, not meaning.
        alias_va, real_va = 0xFFFFB300199C3000, BASE_VA
        candidates = [
            {"va": alias_va, "gpa": 0x10746A000, "size_of_image": 0x4000},
            {"va": real_va, "gpa": 0xCD0000, "size_of_image": 0x4000},
        ]
        gather = self.gatherer(
            {
                alias_va: [(0x100, 0x3A0, real_va, real_va + 0x127770)],
                real_va: [(0x100, 0x3A0, real_va, real_va + 0x127770)],
            }
        )
        chosen, attempts = probe.identify_image(candidates, gather)
        self.assertIsNotNone(chosen)
        self.assertEqual(chosen["candidate"]["va"], real_va)
        self.assertEqual(chosen["block"]["ps_loaded_module_list_image_offset"], 0x127770)
        self.assertEqual([a["validated"] for a in attempts], [False, True])
        self.assertEqual(len(attempts), 2, "every candidate examined is reported")

    def test_no_candidate_validating_is_reported_for_all_of_them(self):
        candidates = [
            {"va": BASE_VA, "gpa": 0xCD0000, "size_of_image": 0x4000},
            {"va": BASE_VA + 0x10000, "gpa": 0xCE0000, "size_of_image": 0x4000},
        ]
        gather = self.gatherer({BASE_VA: [(0x100, 0x3A0, 0xDEADBEEF, 0)]})
        chosen, attempts = probe.identify_image(candidates, gather)
        self.assertIsNone(chosen)
        self.assertEqual(len(attempts), 2)
        self.assertEqual([a["validated"] for a in attempts], [False, False])
        self.assertEqual([a["kdbg_hits"] for a in attempts], [1, 0])


def module_list_reader(pages):
    return lambda va: pages.get(va)


def kldr_entry(flink, dll_base, size_of_image):
    record = bytearray(0x70)
    struct.pack_into("<Q", record, 0x00, flink)
    struct.pack_into("<Q", record, 0x30, dll_base)
    struct.pack_into("<I", record, 0x40, size_of_image)
    return bytes(record)


class ModuleListValidation(unittest.TestCase):
    """The docstring claimed the first `DllBase` was checked; the code only decoded."""

    HEAD_VA = 0xFFFFF80220EB0770
    ENTRY_VA = 0xFFFFF80220EB1000

    def pages_for(self, dll_base):
        head_page = bytearray(PAGE)
        struct.pack_into("<Q", head_page, self.HEAD_VA & (PAGE - 1), self.ENTRY_VA)
        entry_page = bytearray(PAGE)
        entry_page[0:0x70] = kldr_entry(self.HEAD_VA, dll_base, 0x175000)
        return {
            self.HEAD_VA & ~(PAGE - 1): bytes(head_page),
            self.ENTRY_VA & ~(PAGE - 1): bytes(entry_page),
        }

    def test_a_list_whose_first_entry_names_the_image_is_valid(self):
        listing = probe.walk_module_list(
            module_list_reader(self.pages_for(BASE_VA)), self.HEAD_VA, BASE_VA
        )
        self.assertTrue(listing["valid"])
        self.assertTrue(listing["closed"])
        self.assertEqual(listing["entries"][0]["dll_base"], BASE_VA)

    def test_a_list_reached_through_a_stale_pointer_is_rejected(self):
        # It still decodes: plausible entries, a closed list, sensible sizes. Only the base says
        # it is somebody else's list.
        listing = probe.walk_module_list(
            module_list_reader(self.pages_for(0xFFFFF80299999000)), self.HEAD_VA, BASE_VA
        )
        self.assertFalse(listing["valid"])
        self.assertIn("is not the identified base", listing["invalid_reason"])
        self.assertEqual(len(listing["entries"]), 1, "the entries are still reported")

    def test_every_failing_exit_says_why_in_the_same_field(self):
        # The caller records `invalid_reason` and nothing else, so an exit that reports its
        # failure anywhere else is a rejection with no explanation -- which reads the same as an
        # unexplained one.
        unreadable_head = probe.walk_module_list(lambda _va: None, self.HEAD_VA, BASE_VA)

        empty_page = bytearray(PAGE)
        struct.pack_into("<Q", empty_page, self.HEAD_VA & (PAGE - 1), self.HEAD_VA)
        empty = probe.walk_module_list(
            module_list_reader({self.HEAD_VA & ~(PAGE - 1): bytes(empty_page)}),
            self.HEAD_VA,
            BASE_VA,
        )

        head_only = bytearray(PAGE)
        struct.pack_into("<Q", head_only, self.HEAD_VA & (PAGE - 1), self.ENTRY_VA)
        unreadable_entry = probe.walk_module_list(
            module_list_reader({self.HEAD_VA & ~(PAGE - 1): bytes(head_only)}),
            self.HEAD_VA,
            BASE_VA,
        )

        wrong_base = probe.walk_module_list(
            module_list_reader(self.pages_for(0xFFFFF80299999000)), self.HEAD_VA, BASE_VA
        )

        for name, listing in (
            ("unreadable head", unreadable_head),
            ("empty list", empty),
            ("unreadable first entry", unreadable_entry),
            ("wrong base", wrong_base),
        ):
            with self.subTest(exit=name):
                self.assertIs(listing["valid"], False)
                self.assertTrue(listing["invalid_reason"], "a rejection with no reason")
        self.assertIn("not readable", unreadable_head["invalid_reason"])
        self.assertIn("empty", empty["invalid_reason"])
        self.assertIn("not readable", unreadable_entry["invalid_reason"])
        self.assertIn("identified base", wrong_base["invalid_reason"])

    def chain(self, bases, close=True):
        """Pages for a list of `len(bases)` entries, optionally not linked back to the head."""
        entry_vas = [self.ENTRY_VA + i * PAGE for i in range(len(bases))]
        pages = {}
        head_page = bytearray(PAGE)
        struct.pack_into("<Q", head_page, self.HEAD_VA & (PAGE - 1), entry_vas[0])
        pages[self.HEAD_VA & ~(PAGE - 1)] = bytes(head_page)
        for index, (va, base) in enumerate(zip(entry_vas, bases)):
            nxt = entry_vas[index + 1] if index + 1 < len(entry_vas) else (self.HEAD_VA if close else 0)
            page = bytearray(PAGE)
            page[0:0x70] = kldr_entry(nxt, base, 0x175000)
            pages[va & ~(PAGE - 1)] = bytes(page)
        return pages

    def test_a_list_that_does_not_close_still_confirms_the_block_and_says_it_is_partial(self):
        # Rejecting it outright is the round-2 defect from the other side: it would report "no
        # debugger data block" for a capture that has one, and a build with more than `limit`
        # VTL1 modules would trigger that by itself.
        listing = probe.walk_module_list(
            module_list_reader(self.chain([BASE_VA, BASE_VA + 0x200000], close=False)),
            self.HEAD_VA,
            BASE_VA,
        )
        self.assertTrue(listing["valid"], "the block is still identified by the first entry")
        self.assertFalse(listing["complete"])
        self.assertEqual(listing["incomplete_reason"], "the forward link is null")

    def test_a_list_that_closes_is_complete(self):
        listing = probe.walk_module_list(
            module_list_reader(self.chain([BASE_VA, BASE_VA + 0x200000])), self.HEAD_VA, BASE_VA
        )
        self.assertTrue(listing["valid"])
        self.assertTrue(listing["complete"])
        self.assertNotIn("incomplete_reason", listing)

    def test_the_entry_limit_is_named_as_the_reason_it_stopped(self):
        listing = probe.walk_module_list(
            module_list_reader(self.chain([BASE_VA] * 4)), self.HEAD_VA, BASE_VA, limit=2
        )
        self.assertTrue(listing["valid"])
        self.assertFalse(listing["complete"])
        self.assertIn("2-entry limit", listing["incomplete_reason"])

    def test_an_unreadable_later_entry_is_named_rather_than_folded_into_the_limit(self):
        pages = self.chain([BASE_VA, BASE_VA + 0x200000])
        del pages[(self.ENTRY_VA + PAGE) & ~(PAGE - 1)]
        listing = probe.walk_module_list(module_list_reader(pages), self.HEAD_VA, BASE_VA)
        self.assertTrue(listing["valid"])
        self.assertFalse(listing["complete"])
        self.assertIn("is not readable", listing["incomplete_reason"])

    def test_an_unreadable_list_is_rejected_with_its_reason_carried_to_the_hit(self):
        image = image_with_kdbg([(0x100, 0x3A0, BASE_VA, 0xDEAD0000)])
        candidates = [{"va": BASE_VA, "gpa": 0xCD0000, "size_of_image": 0x4000}]

        def confirm(candidate, hit):
            listing = probe.walk_module_list(
                lambda _va: None, hit["ps_loaded_module_list"], candidate["va"]
            )
            return bool(listing.get("valid")), listing

        chosen, attempts = probe.identify_image(
            candidates, lambda _va, _size: (image, []), confirm=confirm
        )
        self.assertIsNone(chosen)
        hit = attempts[0]["hits"][0]
        self.assertIs(hit["confirmed"], False)
        self.assertIsNotNone(hit["rejected_by"], "an unreadable list is not an unexplained one")
        self.assertIn("not readable", hit["rejected_by"])


class ConfirmationGetsTheLastWord(unittest.TestCase):
    def test_a_rejected_hit_is_recorded_and_the_next_one_tried(self):
        # Both tags name the right image; only one leads to a list that names it back.
        image = image_with_kdbg(
            [
                (0x100, 0x3A0, BASE_VA, 0xDEAD0000),
                (0x1000, 0x3A0, BASE_VA, BASE_VA + 0x127770),
            ]
        )
        candidates = [{"va": BASE_VA, "gpa": 0xCD0000, "size_of_image": 0x4000}]

        def confirm(_candidate, hit):
            ok = hit["ps_loaded_module_list"] == BASE_VA + 0x127770
            return ok, {"valid": ok, "invalid_reason": None if ok else "wrong list"}

        chosen, attempts = probe.identify_image(
            candidates, lambda _va, _size: (image, []), confirm=confirm
        )
        self.assertIsNotNone(chosen)
        self.assertEqual(chosen["block"]["ps_loaded_module_list"], BASE_VA + 0x127770)
        self.assertEqual(chosen["hits"][0]["rejected_by"], "wrong list")
        self.assertEqual(attempts[0]["kern_base_matches"], 2)

    def test_a_candidate_whose_every_hit_is_rejected_is_not_chosen(self):
        image = image_with_kdbg([(0x100, 0x3A0, BASE_VA, 0xDEAD0000)])
        candidates = [{"va": BASE_VA, "gpa": 0xCD0000, "size_of_image": 0x4000}]
        chosen, attempts = probe.identify_image(
            candidates,
            lambda _va, _size: (image, []),
            confirm=lambda _c, _h: (False, {"invalid_reason": "no"}),
        )
        self.assertIsNone(chosen)
        self.assertEqual(attempts[0]["kern_base_matches"], 1)
        self.assertFalse(attempts[0]["validated"])

    def test_the_rejected_hits_and_their_reasons_survive_the_rejection(self):
        # "Four tags found, all refused" and "no tags found" are different results, and the
        # reasons are the only thing that tells a coincidental tag from a stale module list.
        image = image_with_kdbg(
            [(0x100, 0x2C058948, 0xDEADBEEF, 0), (0x1000, 0x3A0, BASE_VA, 0xDEAD0000)]
        )
        candidates = [{"va": BASE_VA, "gpa": 0xCD0000, "size_of_image": 0x4000}]
        chosen, attempts = probe.identify_image(
            candidates,
            lambda _va, _size: (image, []),
            confirm=lambda _c, _h: (False, {"invalid_reason": "the list names somebody else"}),
        )
        self.assertIsNone(chosen)
        hits = attempts[0]["hits"]
        self.assertEqual(len(hits), 2, "both tags are reported, not just the plausible one")
        self.assertFalse(hits[0]["kern_base_matches"])
        self.assertIs(hits[1]["confirmed"], False)
        self.assertEqual(hits[1]["rejected_by"], "the list names somebody else")

    def test_a_chosen_candidate_carries_its_hits_in_the_same_place(self):
        image = image_with_kdbg([(0x1000, 0x3A0, BASE_VA, BASE_VA + 0x127770)])
        candidates = [{"va": BASE_VA, "gpa": 0xCD0000, "size_of_image": 0x4000}]
        chosen, attempts = probe.identify_image(
            candidates, lambda _va, _size: (image, []), confirm=lambda _c, _h: (True, {"valid": True})
        )
        self.assertIsNotNone(chosen)
        self.assertEqual(len(attempts[0]["hits"]), 1)
        self.assertIs(attempts[0]["hits"][0]["confirmed"], True)


class DistinctLeafPages(unittest.TestCase):
    def test_a_large_leaf_counts_every_frame_it_covers(self):
        # Counting base GPAs reports 1 where leaf_pages reports 512, so the two figures would be
        # in different units the first time a large mapping appears.
        self.assertEqual(probe.distinct_leaf_pages([(0, 0x400000, 1 << 21)]), 512)
        self.assertEqual(probe.distinct_leaf_pages([(0, 0x40000000, 1 << 30)]), 262144)

    def test_overlapping_and_repeated_spans_are_counted_once(self):
        leaves = [(0, 0x1000, PAGE), (1, 0x1000, PAGE), (2, 0x2000, PAGE)]
        self.assertEqual(probe.distinct_leaf_pages(leaves), 2)
        self.assertEqual(probe.distinct_leaf_pages([(0, 0x400000, 1 << 21), (1, 0x400000, PAGE)]), 512)

    def test_no_leaves_is_zero(self):
        self.assertEqual(probe.distinct_leaf_pages([]), 0)


class CaptureProvenance(unittest.TestCase):
    """The rule is an *ordering*, so it is tested through the function that owns the ordering.

    A first version of this tested `describe_file` instead, which was never where the defect was:
    backing the re-stat out of `main` left that test green.
    """

    def test_the_recorded_size_is_the_file_the_results_come_from(self):
        import pathlib
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory, "capture.vmrs")
            path.write_bytes(b"before")
            record = probe.capture_provenance(
                [path], "vmrs", lambda: path.write_bytes(b"after the replay log")
            )
        self.assertTrue(record["replay_log_applied"])
        self.assertEqual(record["files"][0]["size"], 20, "the bytes that were analysed")
        self.assertEqual(record["files_before_replay"][0]["size"], 6, "and what arrived")

    def test_without_a_replay_log_there_is_one_reading_and_no_before(self):
        import pathlib
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory, "capture.vmrs")
            path.write_bytes(b"untouched")
            record = probe.capture_provenance([path], "vmrs")
        self.assertEqual(record["files"][0]["size"], 9)
        self.assertNotIn("files_before_replay", record)
        self.assertNotIn("replay_log_applied", record)


class CaptureSelection(unittest.TestCase):
    def test_a_vmrs_is_chosen_when_one_is_located(self):
        located = {"bin": "", "vsv": "", "vmrs": r"D:\s\a.vmrs"}
        self.assertEqual(probe.choose_capture(located), ("vmrs", (r"D:\s\a.vmrs",)))

    def test_the_legacy_pair_is_chosen_when_there_is_no_vmrs(self):
        # `LoadSavedStateFiles` exists for this form, and requiring a .vmrs made it unreachable.
        located = {"bin": r"D:\s\a.bin", "vsv": r"D:\s\a.vsv", "vmrs": ""}
        self.assertEqual(
            probe.choose_capture(located), ("bin+vsv", (r"D:\s\a.bin", r"D:\s\a.vsv"))
        )

    def test_a_half_located_pair_is_not_chosen(self):
        self.assertEqual(probe.choose_capture({"bin": r"D:\s\a.bin", "vsv": "", "vmrs": ""}), (None, ()))
        self.assertEqual(probe.choose_capture({"bin": "", "vsv": "", "vmrs": ""}), (None, ()))


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
