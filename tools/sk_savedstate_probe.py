"""S0: does a Hyper-V saved state carry a guest's VTL1, and its page-table root?

`FOLLOWUPS.md` item 103 gate S0. H0-H4 reached Secure Kernel from the root partition with a
test-signed driver in the loop; this asks whether a *capture* written by the host reaches the same
places with no driver at all, which decides how much setup an operator needs rather than whether
item 103 ships.

The source is Microsoft's own saved-state reader, `vmsavedstatedumpprovider.dll`, shipped in the
Windows SDK/WDK `bin\\<ver>\\x64` directory. It is VTL-aware by declaration --
`GetGuestEnabledVirtualTrustLevels`, `ForceActiveVirtualTrustLevel` -- and whether that declaration
extends to VTL1 *memory* and a VTL1 `CR3` is what this measures.

Two things have to come out of the capture, not one: the bytes, and the VTL1 page-table root. The
root is read with `GetRegisterValue` after forcing VP0 to VTL1 and there is deliberately no way to
supply one -- a remembered `CR3` from a live run is the failure this gate exists to rule out, and
the two captures it was first run against had different ones.

Nothing here writes to the guest or to the capture. `--apply-replay-log` is the one exception and
is off by default; it opens the file read-write, so point it at a throwaway checkpoint.

**What a failed provider call does, enumerated once rather than decided per call site.** Three
review rounds each found another place where a *failure* could arrive looking like an *answer* --
an alias silently dropped, a refused VTL switch indistinguishable from an unreadable register, an
unchecked sizing call turning into an empty memory map -- so every entry point into the DLL is
listed here with which of four contracts it is under. A new one joins a row; it does not get a
decision of its own.

| contract | calls | on failure |
|---|---|---|
| **fatal** -- nothing downstream means anything without it | `LocateSavedStateFiles`, `LoadSavedStateFile(s)`, `ApplyPendingSavedStateFileReplayLog` | raise `ProbeError`; the run ends |
| **diagnostic** -- recorded per field, never fatal, never silent | `GetVpCount`, `GetGuestEnabledVirtualTrustLevels`, `GetEnabledVirtualTrustLevels`, `GetActiveVirtualTrustLevel`, `GetArchitecture`, `GetPagingMode`, `IsActiveVirtualTrustLevelEnabled`, `GetRegisterValue` | `probed()` writes the reason under `errors[<field>]`; every other field is still asked for |
| **bulk** -- called thousands of times, must never raise | `ReadGuestPhysicalAddress`, `GuestVirtualAddressToPhysicalAddress` | return `(nothing, reason)`, **and count the failure at the source**; every consumer also counts its own |
| **sized** -- a failure HRESULT is part of the protocol | `GetGuestPhysicalMemoryChunks` | see its own docstring: measured `0x8007000E` on the sizing call, so the count decides |

`ForceActiveVirtualTrustLevel` is deliberately in none of them: its failure **is** the control
arm's result, so it is caught at one call site and reported as itself. And the provider is never
handed a handle it did not give us -- an experiment that passed it a fabricated one hung inside the
DLL and had to be killed.

**The table binds the producer; it took another round to bind the consumers.** A contract saying
"return a reason" leaves every caller free to write `if reason: continue` and report a clean zero,
and two of them did. So `read()` counts its own failures in `reads.failed` -- a number no consumer
can suppress and no section can explain away -- and each scan carries its own `unreadable` count
beside its findings. A run reporting nothing found with a non-zero `reads.failed` is a run whose
negative has not been earned.

Run against a capture (a checkpoint taken with `CheckpointType = Standard`, or a saved VM):

    python tools/sk_savedstate_probe.py --vm "Lab Guest Hyper-V" --snapshot "S0 capture" \
        --image C:/Windows/System32/securekernel.exe --json report.json

The control arm is the same command against the VBS-off twin, where the pass is finding nothing.
"""

import argparse
import ctypes
import json
import os
import re
import struct
import sys
from collections import namedtuple
from ctypes import wintypes
from datetime import datetime, timezone
from pathlib import Path

PAGE = 0x1000
PFN_MASK = 0x000FFFFFFFFFF000
ENTRY_PRESENT = 1
ENTRY_LARGE = 0x80

DEFAULT_KIT = Path(r"C:\Program Files (x86)\Windows Kits\10")

# Budgets for the page-table descent. Exceeding one is reported, never absorbed: an unguarded walk
# of SK's self-mapping PML4 took this bench down twice and cost a reboot each time.
MAX_TABLE_READS = 20000
MAX_LEAVES = 200000


class ProbeError(RuntimeError):
    """A failure with a reason worth printing rather than a traceback."""


class VpRegister(ctypes.Structure):
    """VIRTUAL_PROCESSOR_REGISTER, read as its widest member."""

    _fields_ = [("Low64", ctypes.c_uint64), ("High64", ctypes.c_uint64)]


class GpaMemoryChunk(ctypes.Structure):
    _fields_ = [("StartPageIndex", ctypes.c_uint64), ("PageCount", ctypes.c_uint64)]


PAGING_MODE = {0: "Invalid", 1: "NonPaged", 2: "32Bit", 3: "Pae", 4: "Long", 5: "Armv8"}
ARCH = {0: "Unknown", 1: "x86", 2: "x64", 3: "Armv8"}


def register_ids(header):
    """Parse REGISTER_ID out of the SDK header.

    The ids are positional in an enum of ~250 entries, and hand-counting to `X64_RegisterCr3`
    is exactly the kind of remembered constant this investigation has already been bitten by.
    """
    text = Path(header).read_text(encoding="utf-8", errors="replace")
    body = re.search(r"typedef enum REGISTER_ID\s*\{(.*?)\}\s*REGISTER_ID;", text, re.S)
    if not body:
        raise ProbeError(f"REGISTER_ID enum not found in {header}")
    ids, value = {}, 0
    for line in body.group(1).splitlines():
        line = re.sub(r"//.*$", "", line).strip().rstrip(",").strip()
        if not line or line.startswith(("/*", "*", "#")):
            continue
        name, _, explicit = (part.strip() for part in line.partition("="))
        if not re.fullmatch(r"[A-Za-z_]\w*", name):
            continue
        if explicit:
            value = int(explicit, 0)
        ids[name] = value
        value += 1
    return ids


class SavedState:
    """A loaded saved state, and the reads this gate needs from it."""

    def __init__(self, dll_path, header_path):
        directory = str(Path(dll_path).parent)
        if hasattr(os, "add_dll_directory"):
            self._cookie = os.add_dll_directory(directory)
        self.dll_path = str(dll_path)
        self.lib = ctypes.WinDLL(self.dll_path)
        self.ids = register_ids(header_path)
        self.handle = ctypes.c_void_p()
        self.reads = 0
        self.read_bytes = 0
        self.failed_reads = 0
        self.failed_translations = 0
        self.failure_kinds = {}
        self._declare()

    def _declare(self):
        lib = self.lib
        H = ctypes.c_void_p
        lib.LocateSavedStateFiles.argtypes = [
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            ctypes.POINTER(wintypes.LPWSTR),
            ctypes.POINTER(wintypes.LPWSTR),
            ctypes.POINTER(wintypes.LPWSTR),
        ]
        lib.LoadSavedStateFile.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(H)]
        lib.LoadSavedStateFiles.argtypes = [
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            ctypes.POINTER(H),
        ]
        lib.ApplyPendingSavedStateFileReplayLog.argtypes = [wintypes.LPCWSTR]
        lib.ReleaseSavedStateFiles.argtypes = [H]
        lib.GetVpCount.argtypes = [H, ctypes.POINTER(ctypes.c_uint32)]
        lib.GetGuestEnabledVirtualTrustLevels.argtypes = [
            H,
            ctypes.POINTER(ctypes.c_uint32),
        ]
        lib.GetEnabledVirtualTrustLevels.argtypes = [
            H,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
        ]
        lib.GetActiveVirtualTrustLevel.argtypes = [
            H,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint8),
        ]
        lib.ForceActiveVirtualTrustLevel.argtypes = [H, ctypes.c_uint32, ctypes.c_uint8]
        lib.IsActiveVirtualTrustLevelEnabled.argtypes = [
            H,
            ctypes.c_uint32,
            ctypes.POINTER(wintypes.BOOL),
        ]
        lib.GetArchitecture.argtypes = [H, ctypes.c_uint32, ctypes.POINTER(ctypes.c_int)]
        lib.GetPagingMode.argtypes = [H, ctypes.c_uint32, ctypes.POINTER(ctypes.c_int)]
        lib.GetRegisterValue.argtypes = [
            H,
            ctypes.c_uint32,
            wintypes.DWORD,
            ctypes.POINTER(VpRegister),
        ]
        lib.ReadGuestPhysicalAddress.argtypes = [
            H,
            ctypes.c_uint64,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
        ]
        lib.GuestVirtualAddressToPhysicalAddress.argtypes = [
            H,
            ctypes.c_uint32,
            ctypes.c_uint64,
            ctypes.POINTER(ctypes.c_uint64),
            ctypes.POINTER(ctypes.c_uint64),
        ]
        lib.GetGuestPhysicalMemoryChunks.argtypes = [
            H,
            ctypes.POINTER(ctypes.c_uint64),
            ctypes.POINTER(GpaMemoryChunk),
            ctypes.POINTER(ctypes.c_uint64),
        ]
        for name in (
            "LocateSavedStateFiles",
            "LoadSavedStateFile",
            "LoadSavedStateFiles",
            "ApplyPendingSavedStateFileReplayLog",
            "ReleaseSavedStateFiles",
            "GetVpCount",
            "GetGuestEnabledVirtualTrustLevels",
            "GetEnabledVirtualTrustLevels",
            "GetActiveVirtualTrustLevel",
            "ForceActiveVirtualTrustLevel",
            "IsActiveVirtualTrustLevelEnabled",
            "GetArchitecture",
            "GetPagingMode",
            "GetRegisterValue",
            "ReadGuestPhysicalAddress",
            "GuestVirtualAddressToPhysicalAddress",
            "GetGuestPhysicalMemoryChunks",
        ):
            getattr(lib, name).restype = ctypes.c_long

    @staticmethod
    def _check(hr, what):
        if hr < 0:
            raise ProbeError(f"{what} failed: 0x{hr & 0xFFFFFFFF:08X}")
        return hr

    def locate(self, vm_name, snapshot_name):
        bin_path = wintypes.LPWSTR()
        vsv_path = wintypes.LPWSTR()
        vmrs_path = wintypes.LPWSTR()
        self._check(
            self.lib.LocateSavedStateFiles(
                vm_name,
                snapshot_name,
                ctypes.byref(bin_path),
                ctypes.byref(vsv_path),
                ctypes.byref(vmrs_path),
            ),
            "LocateSavedStateFiles",
        )
        found = {
            "bin": bin_path.value or "",
            "vsv": vsv_path.value or "",
            "vmrs": vmrs_path.value or "",
        }
        for pointer in (bin_path, vsv_path, vmrs_path):
            ctypes.windll.kernel32.LocalFree(pointer)
        return found

    def load(self, vmrs=None, bin_file=None, vsv_file=None):
        if vmrs:
            self._check(
                self.lib.LoadSavedStateFile(str(vmrs), ctypes.byref(self.handle)),
                "LoadSavedStateFile",
            )
        else:
            self._check(
                self.lib.LoadSavedStateFiles(
                    str(bin_file), str(vsv_file), ctypes.byref(self.handle)
                ),
                "LoadSavedStateFiles",
            )

    def apply_replay_log(self, vmrs):
        self._check(
            self.lib.ApplyPendingSavedStateFileReplayLog(str(vmrs)),
            "ApplyPendingSavedStateFileReplayLog",
        )

    def release(self):
        if self.handle:
            self.lib.ReleaseSavedStateFiles(self.handle)
            self.handle = ctypes.c_void_p()

    def vp_count(self):
        count = ctypes.c_uint32()
        self._check(self.lib.GetVpCount(self.handle, ctypes.byref(count)), "GetVpCount")
        return count.value

    def guest_vtls(self):
        mask = ctypes.c_uint32()
        self._check(
            self.lib.GetGuestEnabledVirtualTrustLevels(self.handle, ctypes.byref(mask)),
            "GetGuestEnabledVirtualTrustLevels",
        )
        return mask.value

    def vp_vtls(self, vp):
        mask = ctypes.c_uint32()
        self._check(
            self.lib.GetEnabledVirtualTrustLevels(self.handle, vp, ctypes.byref(mask)),
            "GetEnabledVirtualTrustLevels",
        )
        return mask.value

    def active_vtl(self, vp):
        vtl = ctypes.c_uint8()
        self._check(
            self.lib.GetActiveVirtualTrustLevel(self.handle, vp, ctypes.byref(vtl)),
            "GetActiveVirtualTrustLevel",
        )
        return vtl.value

    def force_vtl(self, vp, vtl):
        self._check(
            self.lib.ForceActiveVirtualTrustLevel(self.handle, vp, vtl),
            f"ForceActiveVirtualTrustLevel(vp={vp}, vtl={vtl})",
        )

    def active_vtl_enabled(self, vp):
        enabled = wintypes.BOOL()
        self._check(
            self.lib.IsActiveVirtualTrustLevelEnabled(
                self.handle, vp, ctypes.byref(enabled)
            ),
            "IsActiveVirtualTrustLevelEnabled",
        )
        return bool(enabled.value)

    def architecture(self, vp):
        arch = ctypes.c_int()
        self._check(
            self.lib.GetArchitecture(self.handle, vp, ctypes.byref(arch)),
            "GetArchitecture",
        )
        return ARCH.get(arch.value, f"({arch.value})")

    def paging_mode(self, vp):
        mode = ctypes.c_int()
        self._check(
            self.lib.GetPagingMode(self.handle, vp, ctypes.byref(mode)), "GetPagingMode"
        )
        return PAGING_MODE.get(mode.value, f"({mode.value})")

    def register(self, vp, name):
        if name not in self.ids:
            raise ProbeError(f"{name} is not in this SDK's REGISTER_ID")
        value = VpRegister()
        self._check(
            self.lib.GetRegisterValue(
                self.handle, vp, self.ids[name], ctypes.byref(value)
            ),
            f"GetRegisterValue({name})",
        )
        return value.Low64

    def read(self, gpa, size):
        """Read a GPA range. Returns (bytes, reason) -- reason is None on a full read.

        The reason is the point: a source that collapses "refused", "not captured" and "zeros"
        into an empty buffer reports silent zeros exactly where the protected memory is.
        """
        buffer = (ctypes.c_ubyte * size)()
        read = ctypes.c_uint32()
        hr = self.lib.ReadGuestPhysicalAddress(
            self.handle, gpa, ctypes.byref(buffer), size, ctypes.byref(read)
        )
        self.reads += 1
        self.read_bytes += read.value
        if hr < 0:
            return b"", self._failed(f"hresult 0x{hr & 0xFFFFFFFF:08X}")
        if read.value != size:
            return bytes(buffer[: read.value]), self._failed(f"short read {read.value}/{size}")
        return bytes(buffer), None

    def _failed(self, reason):
        """Count a failed read at the source, and hand the reason on unchanged.

        **A caller that drops the reason cannot also drop the fact.** Three review rounds have now
        found a failed call arriving as a negative result, and the contract that says "return a
        reason" only binds the producer -- a consumer is still free to write `if reason: continue`
        and report a clean zero. Counting here is the backstop that no consumer can bypass: a run
        whose scans found nothing while `reads.failed` is non-zero is a run to distrust, whatever
        any individual section says. Per-section counts still matter for locality and are kept
        beside this one.
        """
        kind = reason.split()[0]
        self.failed_reads += 1
        self.failure_kinds[kind] = self.failure_kinds.get(kind, 0) + 1
        return reason

    def va_to_gpa(self, vp, va):
        gpa = ctypes.c_uint64()
        unmapped = ctypes.c_uint64()
        hr = self.lib.GuestVirtualAddressToPhysicalAddress(
            self.handle, vp, va, ctypes.byref(gpa), ctypes.byref(unmapped)
        )
        if hr < 0:
            self.failed_translations += 1
            return None, f"hresult 0x{hr & 0xFFFFFFFF:08X}"
        return gpa.value, None

    def memory_chunks(self):
        """The guest's physical memory layout, refusing to read a failure as an empty map.

        The sizing call **returns a failure HRESULT by design** -- measured `0x8007000E`,
        `E_OUTOFMEMORY`, with `count` filled in and `page_size` left at zero -- because passing a
        null buffer is how the caller asks how big one to allocate. So neither checking it nor
        ignoring it is right: checking rejects every healthy capture, and ignoring lets a genuine
        provider failure arrive as `memory_pages: 0`, which `--scan-pages` then turns into a
        clean-looking negative on a capture nothing was ever read from. What distinguishes them is
        whether a count came back with the failure.
        """
        page_size = ctypes.c_uint64()
        count = ctypes.c_uint64(0)
        hr = self.lib.GetGuestPhysicalMemoryChunks(
            self.handle, ctypes.byref(page_size), None, ctypes.byref(count)
        )
        if count.value == 0:
            self._check(hr, "GetGuestPhysicalMemoryChunks (sizing)")
            return page_size.value, []  # succeeded, and the guest really has no chunks
        chunks = (GpaMemoryChunk * count.value)()
        self._check(
            self.lib.GetGuestPhysicalMemoryChunks(
                self.handle, ctypes.byref(page_size), chunks, ctypes.byref(count)
            ),
            "GetGuestPhysicalMemoryChunks",
        )
        return page_size.value, [
            {"start_page": c.StartPageIndex, "pages": c.PageCount}
            for c in chunks[: count.value]
        ]


def describe_root(state, root_gpa):
    """What a page read whole says about a claimed page-table root.

    Judged on all 4096 bytes: SK maps nothing in the low canonical half, so its PML4's first
    entries are legitimately zero and a 16-byte window reads the whole page as empty.
    """
    page, reason = state.read(root_gpa, PAGE)
    if reason:
        return {"gpa": root_gpa, "readable": False, "reason": reason}
    entries = struct.unpack("<512Q", page)
    present = [i for i, e in enumerate(entries) if e & 1]
    self_map = [i for i in present if (entries[i] & PFN_MASK) == (root_gpa & PFN_MASK)]
    return {
        "gpa": root_gpa,
        "readable": True,
        "present_entries": len(present),
        "nonzero_bytes": sum(1 for b in page if b),
        "self_map_indexes": self_map,
        "first_present_index": present[0] if present else None,
        "first_present_byte_offset": present[0] * 8 if present else None,
        "upper_half_present": sum(1 for i in present if i >= 256),
    }


DecodedEntry = namedtuple("DecodedEntry", "kind address size malformed")
LEAF = "leaf"
TABLE = "table"


def decode_entry(entry, level):
    """One paging-structure entry: where it points, whether that is a leaf, and whether it is legal.

    **The address field is not `entry & PFN_MASK` for every entry**, and holding that in one place
    is the point of this function. In a large-page PDPTE or PDE, bit 12 is the **PAT** flag rather
    than the low bit of the frame, and the frame is aligned to the mapping's own size -- so masking
    at 4 KiB granularity lands one page high on any large mapping with PAT set, and a scan of that
    leaf then starts a page inside the mapping and runs a page past its end.

    `malformed` means the processor would fault on this entry rather than follow it: reserved bits
    set between bit 13 and the mapping's alignment on a large leaf, or the page-size bit set in a
    PML4E where it has no meaning. The walk skips those and **counts** them.
    """
    if not entry & ENTRY_PRESENT:
        return None
    if level == 0:
        return DecodedEntry(TABLE, entry & PFN_MASK, None, bool(entry & ENTRY_LARGE))
    if level == 3:
        return DecodedEntry(LEAF, entry & PFN_MASK, PAGE, False)
    if entry & ENTRY_LARGE:
        size = 1 << (39 - 9 * level)
        frame = entry & PFN_MASK
        reserved = frame & (size - 1) & ~0x1FFF  # bit 12 is PAT and is legal; 13 and up are not
        return DecodedEntry(LEAF, frame & ~(size - 1), size, reserved != 0)
    return DecodedEntry(TABLE, entry & PFN_MASK, None, False)


def walk(state, root_gpa):
    """A guarded four-level descent, returning leaf (va, gpa, size) runs and how the walk went.

    **Each table is expanded once per level, and the prefixes that would have re-expanded it are
    counted rather than passed over in silence.** Three guards: an entry pointing at the table it
    came from is skipped, each level keeps a visited set, and reads and leaves are budgeted so that
    exhausting one sets `truncated` rather than quietly returning a short answer.

    A reviewer asked for the visited set to be replaced by path-based cycle cutting, on the correct
    ground that two parents may legitimately point at one table and a visited set drops the second
    prefix. **That was built and measured, and it does not work here**: Secure Kernel's VTL1 tables
    are recursively self-mapped, so one page is a PML4, a PDPT, a PD *and* a PT depending on the
    route taken to it -- 36 tables appear at more than one level on the measured build, one PD is
    referenced 1023 times and one PT 2300 times. Walking every prefix is therefore 512-ish paths
    per level: the path-based walk exhausted a 200,000-leaf budget over **509 distinct pages** and
    identified nothing, where this one costs 166 reads and finds the image. Complete VA enumeration
    of a self-mapped address space is combinatorial by construction and is not what this walk is
    for; what it owes instead is to **say how much it left out**, which `alias_prefixes_skipped`
    does. The identification that rests on it is cross-checked twice over -- against the provider's
    own translator, and against `KernBase` inside the data block.
    """
    leaves = []
    stats = {
        "table_reads": 0,
        "tables_decoded": 0,
        "alias_prefixes_skipped": 0,
        "malformed_entries": 0,
        "unreadable_tables": 0,
        "truncated": None,
    }
    visited = [set(), set(), set(), set()]
    cache = {}

    def canonical(va):
        # Kept as an unsigned 64-bit value. Sign-extending into a negative Python int prints
        # correctly and then fails every comparison against a pointer read out of the guest.
        return va | 0xFFFF000000000000 if va & (1 << 47) else va

    def table_entries(table_gpa):
        if table_gpa in cache:
            return cache[table_gpa]
        if stats["table_reads"] >= MAX_TABLE_READS:
            stats["truncated"] = f"table read budget {MAX_TABLE_READS} exhausted"
            return None
        page, reason = state.read(table_gpa, PAGE)
        stats["table_reads"] += 1
        if reason:
            # A table that could not be read is a subtree that is not in this answer. Counted,
            # because "the walk found no image" and "the walk could not read part of the tree"
            # are different results and the leaf list does not distinguish them.
            stats["unreadable_tables"] += 1
        cache[table_gpa] = None if reason else struct.unpack("<512Q", page)
        return cache[table_gpa]

    def descend(table_gpa, level, va):
        if stats["truncated"]:
            return
        if table_gpa in visited[level]:
            stats["alias_prefixes_skipped"] += 1
            return
        visited[level].add(table_gpa)
        entries = table_entries(table_gpa)
        if entries is None:
            return
        stats["tables_decoded"] += 1
        shift = 39 - 9 * level
        for index, entry in enumerate(entries):
            decoded = decode_entry(entry, level)
            if decoded is None:
                continue
            if decoded.malformed:
                stats["malformed_entries"] += 1
                continue
            child_va = va | (index << shift)
            if decoded.kind == LEAF:
                if len(leaves) >= MAX_LEAVES:
                    stats["truncated"] = f"leaf budget {MAX_LEAVES} exhausted"
                    break
                leaves.append((canonical(child_va), decoded.address, decoded.size))
                continue
            if decoded.address == (table_gpa & PFN_MASK):
                # The self-map, and any other cycle of one. The per-level visited set would
                # otherwise let it through once at each of the three levels beneath this one. A
                # *leaf* landing on this page is ordinary data and is kept, above.
                continue
            descend(decoded.address, level + 1, child_va)
            if stats["truncated"]:
                break

    descend(root_gpa & PFN_MASK, 0, 0)
    return leaves, stats


def pe_identity(header_bytes):
    """Sections, timestamp and SizeOfImage from a PE header, or None if it is not one."""
    if len(header_bytes) < 0x40 or header_bytes[:2] != b"MZ":
        return None
    e_lfanew = struct.unpack_from("<I", header_bytes, 0x3C)[0]
    if e_lfanew + 0x108 > len(header_bytes):
        return None
    if header_bytes[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        return None
    machine, sections, timestamp = struct.unpack_from("<HHI", header_bytes, e_lfanew + 4)
    optional_size = struct.unpack_from("<H", header_bytes, e_lfanew + 20)[0]
    magic = struct.unpack_from("<H", header_bytes, e_lfanew + 24)[0]
    if magic != 0x20B:
        return None
    size_of_image = struct.unpack_from("<I", header_bytes, e_lfanew + 24 + 56)[0]
    table = e_lfanew + 24 + optional_size
    names = []
    for i in range(sections):
        start = table + i * 40
        if start + 8 > len(header_bytes):
            break
        names.append(header_bytes[start : start + 8].rstrip(b"\0").decode("latin-1"))
    return {
        "machine": machine,
        "sections": sections,
        "timestamp": timestamp,
        "size_of_image": size_of_image,
        "section_names": names,
    }


def image_on_disk(path):
    data = Path(path).read_bytes()
    identity = pe_identity(data[:PAGE])
    if not identity:
        raise ProbeError(f"{path} is not a PE64 image")
    identity["path"] = str(path)
    identity["file_size"] = len(data)
    return identity


def same_image(found, disk):
    return (
        found["sections"] == disk["sections"]
        and found["timestamp"] == disk["timestamp"]
        and found["size_of_image"] == disk["size_of_image"]
        and found["section_names"] == disk["section_names"]
    )


def scan_leaves_for_images(state, leaves, disk):
    """One 0x400-byte read per leaf page start, looking for a PE header at offset 0.

    A prefix is the right window here -- an image base is page-aligned and the header sits at
    offset 0, so this is reading the thing itself, not judging a page by a sample of it.

    **A leaf that could not be read is not a leaf without an image.** Dropping the reason here
    lets a refused or short read arrive as "no PE header", and the section then reports zero
    matching images with nothing capped -- an incomplete scan wearing the shape of a negative
    result. So failures are counted and the scan says whether it was complete.
    """
    images = []
    scanned = 0
    unreadable = 0
    for va, gpa, size in leaves:
        # A large-page leaf covers many page-aligned bases, so it is expanded rather than
        # sampled at its first page -- an image inside one would otherwise be invisible.
        for offset in range(0, size, PAGE):
            if scanned >= MAX_LEAVES:
                return images, {"scanned": scanned, "unreadable": unreadable, "capped": True}
            head, reason = state.read(gpa + offset, PAGE)
            scanned += 1
            if reason:
                unreadable += 1
                continue
            if head[:2] != b"MZ":
                continue
            identity = pe_identity(head)
            if not identity:
                continue
            identity.update(
                {
                    "va": va + offset,
                    "gpa": gpa + offset,
                    "matches_disk": same_image(identity, disk),
                }
            )
            images.append(identity)
    return images, {"scanned": scanned, "unreadable": unreadable, "capped": False}


def scan_physical_for_images(state, chunks, page_size, disk, limit_pages):
    """The route that needs no CR3: walk backed physical pages testing for a PE header.

    This is what the VBS-off control runs, since it has no VTL1 root to walk from -- **which is
    why a page it could not read has to be counted rather than skipped.** The control's entire
    result is "no Secure Kernel here", and a scan that silently omitted some fraction of its pages
    would produce that reading whether or not one of them held the image.

    **`KDBG` records are searched across the page boundary, images are not, and the asymmetry is
    structural rather than an oversight.** A PE image is page-aligned, so its `MZ` is always at
    offset 0 of some page and a per-page test cannot miss one. A debugger data block sits wherever
    it sits: a page-local search cannot see a tag split across the boundary, and rejects one whose
    header starts in the page before or whose fields continue into the page after. That is about
    1.4% of placements silently absent from a negative the control rests on -- and the image-side
    search has read a contiguous buffer since the first commit for exactly this reason, so the two
    searches for one needle disagreed. Each page is therefore paired with its physical successor,
    and a record is attributed to the page its **header** starts in, so no pairing reports it
    twice. A header at the end of the scanned range with nowhere to continue is counted in
    `boundary_incomplete` rather than dropped.

    **What that pairing still cannot see, stated rather than fixed.** Two pages that are adjacent
    in *virtual* memory can sit in frames that are not adjacent, and a record split across them is
    invisible here. Following the mapping to join them would need page tables -- which is the one
    thing this route is defined as not having, and which the VBS-off control does not possess at
    all, its VTL1 being refused outright. Making the physical scan virtual would delete the
    independence that makes it a cross-check of the walk rather than a second reading of it. So
    the limit is reported in `limitation` instead, and the exposure was measured rather than
    guessed: `securekernel.exe` on the measured build spans 373 pages with **one** physical
    discontinuity, in two runs of 304 and 69 pages, and the debugger data block sits at page 307
    offset `0x5E0` -- inside a frame, not across one, with an adjacent successor. The image-side
    search has no such blind spot, reading the image by VA through the translator, and it is the
    authoritative one.
    """
    if page_size != PAGE:
        # The reads below are PAGE-sized and the pairing assumes a PAGE stride. A capture with a
        # different chunk granularity is a shape this scanner has never seen; refusing beats
        # striding wrongly and reporting the result as a clean negative.
        raise ProbeError(f"memory chunk page size {page_size} is not {PAGE}")
    images, kdbg = [], []
    scanned = 0
    unreadable = 0
    boundary_incomplete = 0

    def emit(page_gpa, buffer):
        """Record every `KDBG` whose header starts in this page, decoding into the next."""
        nonlocal boundary_incomplete
        at = buffer.find(b"KDBG")
        while at != -1:
            header = at - 0x10
            if 0 <= header < PAGE:
                if header + 0x20 <= len(buffer):
                    kdbg.append(
                        {
                            "gpa": page_gpa + header,
                            "size": struct.unpack_from("<I", buffer, header + 0x14)[0],
                            "kern_base": struct.unpack_from("<Q", buffer, header + 0x18)[0],
                        }
                    )
                else:
                    boundary_incomplete += 1
            at = buffer.find(b"KDBG", at + 1)

    def outcome(capped):
        return {
            "scanned": scanned,
            "unreadable": unreadable,
            "boundary_incomplete": boundary_incomplete,
            "capped": capped,
            # Stated beside the count, because a reader who sees `kdbg_tags: 0` is reading a
            # negative and is owed its bound. See the docstring: joining non-adjacent frames
            # needs page tables, which is the one thing this route is defined as not having.
            "limitation": (
                "joins physically adjacent frames only; a record split across frames that are "
                "virtually adjacent but physically apart is not detectable by this route"
            ),
        }

    for chunk in chunks:
        base = chunk["start_page"] * page_size
        pending = None  # (gpa, bytes) of the previous readable page, awaiting its successor
        for page_index in range(chunk["pages"]):
            if scanned >= limit_pages:
                if pending:
                    emit(*pending)
                return images, kdbg, outcome(True)
            gpa = base + page_index * page_size
            data, reason = state.read(gpa, PAGE)
            scanned += 1
            if reason:
                unreadable += 1
                if pending:
                    emit(*pending)  # no successor to decode into; take what fits
                    pending = None
                continue
            if data[:2] == b"MZ":
                identity = pe_identity(data)
                if identity:
                    identity.update({"gpa": gpa, "matches_disk": same_image(identity, disk)})
                    images.append(identity)
            if pending and pending[0] + PAGE == gpa:
                emit(pending[0], pending[1] + data)
            elif pending:
                emit(*pending)
            pending = (gpa, data)
        if pending:
            emit(*pending)
    return images, kdbg, outcome(False)


def gather_image(reader, base_va, size_of_image):
    """Read an image's mapped range into one buffer, poisoning what could not be read.

    0xAA rather than zero: a zero fill would make "this page was not in the capture" read as
    "this page is zeros", which is the one distinction this whole gate turns on. Contiguity also
    means a structure straddling a page boundary is found rather than skipped.
    """
    buffer = bytearray(b"\xAA" * size_of_image)
    missing = []
    for offset in range(0, size_of_image, PAGE):
        page = reader(base_va + offset)
        if page is None:
            missing.append(offset)
            continue
        end = min(offset + PAGE, size_of_image)
        buffer[offset:end] = page[: end - offset]
    return bytes(buffer), missing


def find_kdbg(image, base_va):
    """Find `KDBG` owner tags in an image buffer and report what sits beside each.

    The tag alone is the needle and the `Size` beside it is *reported* rather than matched: a
    needle built from a remembered `0x3A8` is what made an earlier scan report zero occurrences
    with the block three pages away.
    """
    hits = []
    at = image.find(b"KDBG")
    while at != -1:
        if at >= 0x10 and at + 0x50 <= len(image):
            header = at - 0x10
            size = struct.unpack_from("<I", image, at + 4)[0]
            kern_base = struct.unpack_from("<Q", image, at + 8)[0]
            hits.append(
                {
                    "va": base_va + header,
                    "image_offset": header,
                    "size": size,
                    "kern_base": kern_base,
                    "kern_base_matches": kern_base == base_va,
                    "ps_loaded_module_list": struct.unpack_from("<Q", image, header + 0x48)[0],
                }
            )
        at = image.find(b"KDBG", at + 1)
    return hits


def probed(record, field, call):
    """Ask the provider one question, recording either the answer or why there was none.

    **A diagnostic must not be able to suppress the primary output.** The fields below are asked
    for one at a time precisely so that a provider which cannot answer, say, `GetPagingMode` does
    not take the VTL1 `CR3` -- the whole point of the run -- down with it. A failure is written
    into `errors` beside the fields that did answer, so the report says which question went
    unanswered rather than looking like a guest that had nothing to say.
    """
    try:
        record[field] = call()
    except ProbeError as error:
        record.setdefault("errors", {})[field] = str(error)
        return None
    return record[field]


def read_vtl(state, vp, vtl, compare_cr3=None):
    """Force a VP to one VTL and read what it then reports, one question at a time.

    **One function for both VTLs, because two copies of this block drifted apart.** The VTL1 copy
    was made per-field after review found that a shared `try` let an optional diagnostic cost the
    `CR3`; the VTL0 copy, three screens away, kept raising -- and review found that too, one round
    later. A contract that says "diagnostics are recorded per field" and lives only in prose binds
    nothing; there is now one place where a VP's registers are read and it is the place the rule
    is written into.

    **A refused switch and a failed query have the same shape and opposite meanings.** "The
    provider will not put this VP in VTL1" is the control arm's entire result; "the switch worked
    and a register did not come back" says nothing about whether the VTL is enabled.
    """
    record = {"vtl": vtl, "requested": True}
    try:
        state.force_vtl(vp, vtl)
    except ProbeError as error:
        record["forced"] = False
        record["force_error"] = str(error)
        return record
    record["forced"] = True
    probed(record, "enabled", lambda: state.active_vtl_enabled(vp))
    probed(record, "paging_mode", lambda: state.paging_mode(vp))
    for field, register in (
        ("cr0", "X64_RegisterCr0"),
        ("cr3", "X64_RegisterCr3"),
        ("cr4", "X64_RegisterCr4"),
        ("efer", "X64_RegisterEfer"),
        ("rip", "X64_RegisterRip"),
    ):
        probed(record, field, lambda r=register: state.register(vp, r))
    if compare_cr3 is not None and "cr3" in record:
        record["differs_from_vtl0_cr3"] = record["cr3"] != compare_cr3
    return record


def long_mode_consistent(record):
    """Whether this register set is a long-mode processor, or None if it cannot be judged.

    The control that says the `REGISTER_ID` indexing is right rather than off by one -- and it has
    to answer *unknown* rather than *false* when a register did not come back, or a provider that
    cannot return `EFER` would read as a machine that is not in long mode.
    """
    if any(field not in record for field in ("cr0", "cr4", "efer")):
        return None
    return bool(
        record["cr0"] & (1 << 31)
        and record["cr0"] & 1
        and record["cr4"] & (1 << 5)
        and record["efer"] & (1 << 10)
    )


def walkable(vtl1):
    """Whether this VTL1 reading is one to walk from, and if not, why not.

    `enabled` is the provider's own warning that a *forced* VTL is not actually on the VP, in
    which case its register state is meaningless -- so a `False` there blocks the walk. An
    `enabled` that could not be read does **not**: the walk's own output, a root page that
    self-maps and an image that matches the one on disk, is the stronger evidence anyway, and the
    report says the question went unanswered.
    """
    if not vtl1.get("forced"):
        return False, "the VP was not switched to VTL1"
    if vtl1.get("enabled") is False:
        return False, "the provider reports VTL1 not enabled on this VP"
    if not vtl1.get("cr3"):
        return False, "no VTL1 CR3 came back from the capture"
    return True, None


def identify_image(candidates, gather, confirm=None):
    """Try each candidate mapping until one is vouched for by a data block's own `KernBase`.

    `matches_disk` says the bytes at this VA *are* that image; it does not say this VA is the base
    the image was **loaded** at. A second mapping of one image carries the same section names,
    timestamp and `SizeOfImage` -- the 2026-09-25 capture has exactly that, a duplicate of
    `symcryptk.dll` at a VA the module list does not name -- and which of them the walk reaches
    first is decided by prefix order, not by anything meaningful. Stopping at the first therefore
    reports "no debugger data block" for an image whose block is under the next candidate.

    Returns the chosen candidate with its hits, and an attempt record for **every** candidate
    tried, so a report says which mappings were examined rather than implying there was one.

    **`KernBase` matching is necessary and was being treated as sufficient.** A block can name the
    right image and still carry a stale or uninitialised `PsLoadedModuleList` -- the measured block
    has 26 of its 116 qwords non-zero, so fields that mean nothing here legitimately are -- and a
    list walked from a bad pointer yields plausible names and sizes rather than an error. So a
    caller may supply `confirm`, which gets the last word; a hit it rejects is recorded and the
    search moves to the next hit, then to the next candidate.
    """
    attempts = []
    for candidate in candidates:
        image, missing = gather(candidate["va"], candidate["size_of_image"])
        hits = find_kdbg(image, candidate["va"])
        accepted = None
        for hit in hits:
            # Only meaningful once `KernBase` has vouched for the alignment; on a coincidental
            # tag the field is whatever bytes happened to sit at +0x48.
            if not hit["kern_base_matches"]:
                continue
            hit["ps_loaded_module_list_image_offset"] = (
                hit["ps_loaded_module_list"] - candidate["va"]
            )
            if confirm is None:
                accepted = {"hit": hit, "confirmation": None}
                break
            ok, detail = confirm(candidate, hit)
            hit["confirmed"] = ok
            if ok:
                accepted = {"hit": hit, "confirmation": detail}
                break
            hit["rejected_by"] = detail.get("invalid_reason") if isinstance(detail, dict) else detail
        attempts.append(
            {
                "va": candidate["va"],
                "gpa": candidate["gpa"],
                "image_pages_unreadable": len(missing),
                "kdbg_hits": len(hits),
                "kern_base_matches": sum(1 for hit in hits if hit["kern_base_matches"]),
                "validated": accepted is not None,
                # The hits travel with the attempt, annotated with why each was rejected. A run
                # where every tag was found and every one refused is the case those reasons exist
                # for, and it is exactly the case that used to report no tags at all.
                "hits": hits,
            }
        )
        if accepted:
            return (
                {
                    "candidate": candidate,
                    "hits": hits,
                    "block": accepted["hit"],
                    "confirmation": accepted["confirmation"],
                },
                attempts,
            )
    return None, attempts


def describe_file(path):
    """Path, size and mtime of one capture file, read at the moment it is called."""
    stat = path.stat()
    return {
        "path": str(path),
        "size": stat.st_size,
        "mtime_utc": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(
            timespec="seconds"
        ),
    }


def capture_provenance(files, form, apply_replay_log=None):
    """Describe the capture, **after** anything that rewrites it has run.

    `--apply-replay-log` opens the `.vmrs` read-write and mutates it, so a stat taken before that
    describes the input and not the bytes the results come from -- provenance for a different
    file, in a report whose whole subject is which bytes answered. The ordering is the rule here,
    so it lives in a function a test can drive rather than inline in `main`, where the defect was
    and where nothing could reach it.
    """
    record = {"form": form, "files": [describe_file(path) for path in files]}
    if apply_replay_log is None:
        return record
    apply_replay_log()
    record["replay_log_applied"] = True
    record["files_before_replay"] = record["files"]
    record["files"] = [describe_file(path) for path in files]
    return record


def choose_capture(located):
    """Pick which of the located files to load, and name the form.

    `LocateSavedStateFiles` answers with **either** a `.vmrs` **or** a `.bin`/`.vsv` pair, the
    other fields coming back as empty strings -- so the caller has to choose, and requiring a
    `.vmrs` makes the older form unreachable even though the provider loads it.

    Returning the form beside the paths is what makes the choice testable without a capture of
    each kind, which matters because **this bench has only ever produced the first**: the
    `.bin`/`.vsv` branch below is selected correctly and its provider call is unexercised here.
    """
    if located.get("vmrs"):
        return "vmrs", (located["vmrs"],)
    if located.get("bin") and located.get("vsv"):
        return "bin+vsv", (located["bin"], located["vsv"])
    return None, ()


def walk_module_list(reader, head_va, expected_base, limit=32):
    """Walk the `LIST_ENTRY` the debugger data block points at, as `KLDR_DATA_TABLE_ENTRY`.

    **Validation rather than discovery**, and this function is where a docstring said that while
    the code below only decoded. The first entry's `DllBase` has to equal the base the PE walk
    established independently, or the list was read at the wrong alignment, or through a stale
    pointer, or through a coincidental `KDBG` hit -- and in every one of those cases it still
    yields plausible names and sizes, which is exactly why it has to be checked rather than
    looked at. The result carries `valid`, and a caller that gets `False` should move on to the
    next hit or the next candidate rather than publish the entries.

    **Every exit says `valid`, and every failing one says why in the same field.** An earlier
    version returned the unreadable-head case under `error` instead, so the caller -- which reads
    `invalid_reason` -- recorded the rejection with no reason at all, making an unreadable list
    indistinguishable from a list that named somebody else. One field, four ways to fail:
    unreadable head, empty list, unreadable first entry, and a first `DllBase` that is not the
    identified base.

    **`valid` and `complete` are deliberately two answers, not one.** `valid` is about the
    *block*: does the list this `KDBG` points at begin with an entry naming the image whose base
    the block already claims? Two independent structures agreeing on one address is what makes the
    identification implausible as a coincidence. `complete` is about the *enumeration*: did the
    walk close back on its head without running out of entries or readable memory? A review round
    asked for a list that does not close to be rejected outright, and that would be the round-2
    defect from the other side -- refusing a genuine block and reporting "no debugger data block"
    on a capture that has one, which a build with more than `limit` VTL1 modules would trigger by
    itself. So a truncated or broken enumeration confirms the block and says it is partial.
    """

    def read_span(va, size):
        out = bytearray()
        while len(out) < size:
            page = reader((va + len(out)) & ~(PAGE - 1))
            if page is None:
                return None
            start = (va + len(out)) & (PAGE - 1)
            out += page[start : start + min(size - len(out), PAGE - start)]
        return bytes(out)

    head = read_span(head_va, 0x10)
    if head is None:
        return {
            "head_va": head_va,
            "entries": [],
            "closed": False,
            "valid": False,
            "invalid_reason": f"list head at 0x{head_va:X} is not readable",
        }
    entries = []
    current = struct.unpack_from("<Q", head, 0)[0]
    while current and current != head_va and len(entries) < limit:
        record = read_span(current, 0x70)
        if record is None:
            entries.append({"entry_va": current, "error": "entry not readable"})
            break
        dll_base, = struct.unpack_from("<Q", record, 0x30)
        size_of_image, = struct.unpack_from("<I", record, 0x40)
        name_length, = struct.unpack_from("<H", record, 0x58)
        name_buffer, = struct.unpack_from("<Q", record, 0x60)
        name = ""
        if 0 < name_length <= 512 and name_buffer:
            raw = read_span(name_buffer, name_length)
            if raw is not None:
                name = raw.decode("utf-16-le", errors="replace")
        entries.append(
            {
                "entry_va": current,
                "dll_base": dll_base,
                "size_of_image": size_of_image,
                "name": name,
            }
        )
        current = struct.unpack_from("<Q", record, 0)[0]
    result = {"head_va": head_va, "entries": entries, "closed": current == head_va}
    if result["closed"]:
        result["complete"] = True
    else:
        result["complete"] = False
        if entries and "dll_base" not in entries[-1]:
            result["incomplete_reason"] = f"entry at 0x{entries[-1]['entry_va']:X} is not readable"
        elif len(entries) >= limit:
            result["incomplete_reason"] = f"stopped at the {limit}-entry limit"
        elif not current:
            result["incomplete_reason"] = "the forward link is null"
        else:
            result["incomplete_reason"] = f"the walk left the list at 0x{current:X}"
    first = entries[0] if entries else None
    if first is None:
        result.update(valid=False, invalid_reason="the list is empty")
    elif "dll_base" not in first:
        result.update(
            valid=False,
            invalid_reason=f"first entry at 0x{first['entry_va']:X} is not readable",
        )
    elif first.get("dll_base") != expected_base:
        result.update(
            valid=False,
            invalid_reason=(
                f"first DllBase 0x{first.get('dll_base', 0):X} is not the identified base "
                f"0x{expected_base:X}"
            ),
        )
    else:
        result["valid"] = True
    return result


def distinct_leaf_pages(leaves):
    """How many 4 KiB frames the leaves cover, counted without materialising them.

    `len({gpa for ...})` counts a 2 MiB leaf as one page while `leaf_pages` counts it as 512, so
    the two figures would be in different units the first time a large mapping appears. The
    obvious repair -- a set of every frame -- is the wrong one here: a single 1 GiB leaf is
    262,144 frames and the leaf budget allows 200,000 leaves, which is the memory explosion this
    walk's guards exist to prevent. Merging the spans instead is bounded by the leaf count.
    """
    spans = sorted((gpa, gpa + size) for _va, gpa, size in leaves)
    total = 0
    current_start = current_end = None
    for start, end in spans:
        if current_end is None or start > current_end:
            if current_end is not None:
                total += current_end - current_start
            current_start, current_end = start, end
        else:
            current_end = max(current_end, end)
    if current_end is not None:
        total += current_end - current_start
    return total // PAGE


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--vm", help="VM name to locate a saved state for")
    source.add_argument("--vmrs", help="path to a .vmrs file, instead of locating one")
    parser.add_argument("--snapshot", help="snapshot/checkpoint name under --vm")
    parser.add_argument(
        "--image",
        default=r"C:\Windows\System32\securekernel.exe",
        help="on-disk image to identify the in-guest one against",
    )
    parser.add_argument("--vp", type=int, default=0, help="virtual processor to read (default 0)")
    parser.add_argument("--kit", default=str(DEFAULT_KIT), help="Windows Kit root")
    parser.add_argument("--kit-version", default="10.0.26100.0")
    parser.add_argument(
        "--scan-pages",
        type=int,
        default=0,
        help="physical pages to scan for PE headers and KDBG tags (0 = skip; the control arm needs it)",
    )
    parser.add_argument(
        "--apply-replay-log",
        action="store_true",
        help="open the capture read-write first to apply a pending replay log",
    )
    parser.add_argument("--json", help="write the full report here")
    args = parser.parse_args(argv)

    kit = Path(args.kit)
    dll = kit / "bin" / args.kit_version / "x64" / "vmsavedstatedumpprovider.dll"
    header = kit / "Include" / args.kit_version / "um" / "VmSavedStateDumpDefs.h"
    for path in (dll, header):
        if not path.exists():
            raise ProbeError(f"missing {path}")

    state = SavedState(dll, header)
    report = {
        "probe": "sk_savedstate_probe",
        "run_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "provider": {
            "path": str(dll),
            "size": dll.stat().st_size,
            "mtime_utc": datetime.fromtimestamp(
                dll.stat().st_mtime, timezone.utc
            ).isoformat(timespec="seconds"),
        },
        "register_id_cr3": state.ids.get("X64_RegisterCr3"),
    }

    if args.vm:
        located = state.locate(args.vm, args.snapshot)
        report["vm"] = {"name": args.vm, "snapshot": args.snapshot, "located": located}
        form, paths = choose_capture(located)
        if form is None:
            raise ProbeError(
                f"no saved state for {args.vm!r}"
                + (f" snapshot {args.snapshot!r}" if args.snapshot else "")
                + f" (bin={located['bin']!r} vsv={located['vsv']!r} vmrs={located['vmrs']!r})"
            )
    else:
        form, paths = "vmrs", (args.vmrs,)
        report["vm"] = {"name": None, "snapshot": None, "located": {"vmrs": args.vmrs}}

    files = [Path(path) for path in paths]
    if args.apply_replay_log and form != "vmrs":
        raise ProbeError("a replay log belongs to a .vmrs; this capture is a .bin/.vsv pair")
    report["capture"] = capture_provenance(
        files,
        form,
        (lambda: state.apply_replay_log(files[0])) if args.apply_replay_log else None,
    )

    if form == "vmrs":
        state.load(vmrs=files[0])
    else:
        state.load(bin_file=files[0], vsv_file=files[1])
    try:
        vp = args.vp
        page_size, chunks = state.memory_chunks()
        guest = {
            "memory_page_size": page_size,
            "memory_chunks": chunks,
            "memory_pages": sum(c["pages"] for c in chunks),
        }
        # Each asked for separately: these are diagnostics, and one an older provider cannot
        # answer must not abort a run that would otherwise produce the reads this gate is about.
        probed(guest, "vp_count", state.vp_count)
        probed(guest, "guest_enabled_vtls", state.guest_vtls)
        probed(guest, "vp_enabled_vtls", lambda: state.vp_vtls(vp))
        probed(guest, "vp_active_vtl", lambda: state.active_vtl(vp))
        probed(guest, "architecture", lambda: state.architecture(vp))
        report["guest"] = guest

        # VTL0 first, as the control that says the register indexing is right: a CR0 with PG and
        # PE set, CR4 with PAE, and EFER with LMA is a long-mode processor and not an off-by-one.
        vtl0 = read_vtl(state, vp, 0)
        vtl0["long_mode_consistent"] = long_mode_consistent(vtl0)
        if "cr3" in vtl0:
            vtl0["root"] = describe_root(state, vtl0["cr3"] & PFN_MASK)
        report["vtl0"] = vtl0

        vtl1 = read_vtl(state, vp, 1, compare_cr3=vtl0.get("cr3"))
        report["vtl1"] = vtl1

        disk = image_on_disk(args.image)
        report["disk_image"] = disk

        proceed, refusal = walkable(vtl1)
        report["walk_refused"] = refusal
        if proceed:
            root_gpa = vtl1["cr3"] & PFN_MASK
            vtl1["root"] = describe_root(state, root_gpa)
            leaves, walk_stats = walk(state, root_gpa)
            report["walk"] = {
                "root_gpa": root_gpa,
                "root_from": "GetRegisterValue at forced VTL1, this capture",
                "leaf_pages": sum(leaf[2] // PAGE for leaf in leaves),
                "leaf_entries": len(leaves),
                "distinct_leaf_pages": distinct_leaf_pages(leaves),
                **walk_stats,
            }
            images, leaf_scan = scan_leaves_for_images(state, leaves, disk)
            report["walk"]["pe_images"] = images
            report["walk"]["leaf_scan"] = leaf_scan
            matches = [i for i in images if i["matches_disk"]]
            report["walk"]["matching_images"] = len(matches)
            if matches:
                reader_cache = {}

                def read_va(va):
                    if va in reader_cache:
                        return reader_cache[va]
                    gpa, reason = state.va_to_gpa(vp, va)
                    page = None
                    if gpa is not None:
                        data, why = state.read(gpa, PAGE)
                        page = None if why else data
                    reader_cache[va] = page
                    return page

                def confirm(candidate, hit):
                    # The last word on a candidate: a block naming the right image still has to
                    # produce a module list whose first entry names it back.
                    listing = walk_module_list(
                        read_va, hit["ps_loaded_module_list"], candidate["va"]
                    )
                    return bool(listing.get("valid")), listing

                chosen, attempts = identify_image(
                    matches,
                    lambda va, size: gather_image(read_va, va, size),
                    confirm=confirm,
                )
                # One home for the tags, always populated: every candidate's hits ride in its own
                # attempt record, so a run that found four tags and refused all four says so
                # instead of reporting none.
                report["kdbg"] = {
                    "candidates": attempts,
                    "chosen_va": chosen["candidate"]["va"] if chosen else None,
                }
                if chosen:
                    found = chosen["candidate"]
                    report["module_list"] = chosen["confirmation"]
                else:
                    # Every matching mapping was examined and none produced a block that named
                    # itself *and* a module list that named it back.
                    found = matches[0]

                # The provider's own translator, at the forced VTL, cross-checked against the
                # walk: two routes to the same GPA agreeing is what makes either believable.
                provider_gpa, provider_reason = state.va_to_gpa(vp, found["va"])
                report["translate_cross_check"] = {
                    "va": found["va"],
                    "walk_gpa": found["gpa"],
                    "provider_gpa": provider_gpa,
                    "provider_reason": provider_reason,
                    "agree": provider_gpa == found["gpa"],
                }

        if args.scan_pages:
            images, kdbg, physical_scan = scan_physical_for_images(
                state, chunks, page_size, disk, args.scan_pages
            )
            report["physical_scan"] = {
                **physical_scan,
                "pe_images": len(images),
                "matching_images": [i for i in images if i["matches_disk"]],
                "kdbg_tags": kdbg,
            }

        # The backstop the per-section counts cannot replace: any section can forget to report
        # its own failures, and none of them can make this one read zero.
        report["reads"] = {
            "count": state.reads,
            "bytes": state.read_bytes,
            "failed": state.failed_reads,
            "failure_kinds": state.failure_kinds,
            "failed_translations": state.failed_translations,
        }
    finally:
        state.release()

    text = json.dumps(report, indent=2)
    if args.json:
        Path(args.json).write_text(text, encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ProbeError as error:
        print(f"refused: {error}", file=sys.stderr)
        sys.exit(2)
