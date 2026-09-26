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
            return b"", f"hresult 0x{hr & 0xFFFFFFFF:08X}"
        if read.value != size:
            return bytes(buffer[: read.value]), f"short read {read.value}/{size}"
        return bytes(buffer), None

    def read_exact(self, gpa, size, what):
        data, reason = self.read(gpa, size)
        if reason:
            raise ProbeError(f"read of {what} at GPA 0x{gpa:X} failed: {reason}")
        return data

    def va_to_gpa(self, vp, va):
        gpa = ctypes.c_uint64()
        unmapped = ctypes.c_uint64()
        hr = self.lib.GuestVirtualAddressToPhysicalAddress(
            self.handle, vp, va, ctypes.byref(gpa), ctypes.byref(unmapped)
        )
        if hr < 0:
            return None, f"hresult 0x{hr & 0xFFFFFFFF:08X}"
        return gpa.value, None

    def memory_chunks(self):
        page_size = ctypes.c_uint64()
        count = ctypes.c_uint64(0)
        self.lib.GetGuestPhysicalMemoryChunks(
            self.handle, ctypes.byref(page_size), None, ctypes.byref(count)
        )
        if count.value == 0:
            return page_size.value, []
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
    """
    images = []
    scanned = 0
    for va, gpa, size in leaves:
        # A large-page leaf covers many page-aligned bases, so it is expanded rather than
        # sampled at its first page -- an image inside one would otherwise be invisible.
        for offset in range(0, size, PAGE):
            if scanned >= MAX_LEAVES:
                return images, scanned, True
            head, reason = state.read(gpa + offset, PAGE)
            scanned += 1
            if reason or head[:2] != b"MZ":
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
    return images, scanned, False


def scan_physical_for_images(state, chunks, page_size, disk, limit_pages):
    """The route that needs no CR3: walk backed physical pages testing for a PE header.

    This is what the VBS-off control runs, since it has no VTL1 root to walk from.
    """
    images, kdbg = [], []
    scanned = 0
    for chunk in chunks:
        base = chunk["start_page"] * page_size
        for page_index in range(chunk["pages"]):
            if scanned >= limit_pages:
                return images, kdbg, scanned, True
            gpa = base + page_index * page_size
            data, reason = state.read(gpa, PAGE)
            scanned += 1
            if reason:
                continue
            if data[:2] == b"MZ":
                identity = pe_identity(data)
                if identity:
                    identity.update({"gpa": gpa, "matches_disk": same_image(identity, disk)})
                    images.append(identity)
            offset = data.find(b"KDBG")
            while offset != -1:
                if offset >= 0x10 and offset + 0x28 <= PAGE:
                    size = struct.unpack_from("<I", data, offset + 4)[0]
                    kern_base = struct.unpack_from("<Q", data, offset + 8)[0]
                    kdbg.append(
                        {
                            "gpa": gpa + offset - 0x10,
                            "size": size,
                            "kern_base": kern_base,
                        }
                    )
                offset = data.find(b"KDBG", offset + 1)
    return images, kdbg, scanned, False


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


def read_vtl1(state, vp, vtl0_cr3):
    """Force a VP to VTL1 and read what it then reports, keeping two failures apart.

    **A refused switch and a failed query have the same shape and opposite meanings.** "The
    provider will not put this VP in VTL1" is the control arm's entire result; "the switch worked
    and a later register did not come back" says nothing at all about whether VTL1 is enabled. One
    handler over both writes `forced: false` beside a `cr3` it had already read, and turns a
    provider that cannot answer one register into evidence that a guest has no Secure Kernel --
    which is the same collapsing of *refused* into *absent* that this probe exists to avoid.
    """
    vtl1 = {"requested": True}
    try:
        state.force_vtl(vp, 1)
    except ProbeError as error:
        vtl1["forced"] = False
        vtl1["force_error"] = str(error)
        return vtl1
    vtl1["forced"] = True
    try:
        vtl1["enabled"] = state.active_vtl_enabled(vp)
        vtl1["paging_mode"] = state.paging_mode(vp)
        vtl1["cr0"] = state.register(vp, "X64_RegisterCr0")
        vtl1["cr3"] = state.register(vp, "X64_RegisterCr3")
        vtl1["cr4"] = state.register(vp, "X64_RegisterCr4")
        vtl1["efer"] = state.register(vp, "X64_RegisterEfer")
        vtl1["rip"] = state.register(vp, "X64_RegisterRip")
        vtl1["differs_from_vtl0_cr3"] = vtl1["cr3"] != vtl0_cr3
    except ProbeError as error:
        vtl1["query_error"] = str(error)
    return vtl1


def identify_image(candidates, gather):
    """Try each candidate mapping until one is vouched for by a data block's own `KernBase`.

    `matches_disk` says the bytes at this VA *are* that image; it does not say this VA is the base
    the image was **loaded** at. A second mapping of one image carries the same section names,
    timestamp and `SizeOfImage` -- the 2026-09-25 capture has exactly that, a duplicate of
    `symcryptk.dll` at a VA the module list does not name -- and which of them the walk reaches
    first is decided by prefix order, not by anything meaningful. Stopping at the first therefore
    reports "no debugger data block" for an image whose block is under the next candidate.

    Returns the chosen candidate with its hits, and an attempt record for **every** candidate
    tried, so a report says which mappings were examined rather than implying there was one.
    """
    attempts = []
    for candidate in candidates:
        image, missing = gather(candidate["va"], candidate["size_of_image"])
        hits = find_kdbg(image, candidate["va"])
        for hit in hits:
            # Only meaningful once `KernBase` has vouched for the alignment; on a coincidental
            # tag the field is whatever bytes happened to sit at +0x48.
            if hit["kern_base_matches"]:
                hit["ps_loaded_module_list_image_offset"] = (
                    hit["ps_loaded_module_list"] - candidate["va"]
                )
        validated = [hit for hit in hits if hit["kern_base_matches"]]
        attempts.append(
            {
                "va": candidate["va"],
                "gpa": candidate["gpa"],
                "image_pages_unreadable": len(missing),
                "kdbg_hits": len(hits),
                "validated": bool(validated),
            }
        )
        if validated:
            return {"candidate": candidate, "hits": hits, "block": validated[0]}, attempts
    return None, attempts


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


def walk_module_list(reader, head_va, limit=32):
    """Walk the `LIST_ENTRY` the debugger data block points at, as `KLDR_DATA_TABLE_ENTRY`.

    Validation rather than discovery: the first entry's `DllBase` has to equal the base the PE
    walk established, or the block was read at the wrong alignment and everything above it is a
    coincidence.
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
        return {"head_va": head_va, "error": "list head not readable"}
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
    return {"head_va": head_va, "entries": entries, "closed": current == head_va}


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
    report["capture"] = {
        "form": form,
        "files": [
            {
                "path": str(path),
                "size": path.stat().st_size,
                "mtime_utc": datetime.fromtimestamp(
                    path.stat().st_mtime, timezone.utc
                ).isoformat(timespec="seconds"),
            }
            for path in files
        ],
    }

    if args.apply_replay_log:
        if form != "vmrs":
            raise ProbeError("a replay log belongs to a .vmrs; this capture is a .bin/.vsv pair")
        state.apply_replay_log(files[0])
        report["capture"]["replay_log_applied"] = True

    if form == "vmrs":
        state.load(vmrs=files[0])
    else:
        state.load(bin_file=files[0], vsv_file=files[1])
    try:
        vp = args.vp
        page_size, chunks = state.memory_chunks()
        report["guest"] = {
            "vp_count": state.vp_count(),
            "guest_enabled_vtls": state.guest_vtls(),
            "vp_enabled_vtls": state.vp_vtls(vp),
            "vp_active_vtl": state.active_vtl(vp),
            "architecture": state.architecture(vp),
            "memory_page_size": page_size,
            "memory_chunks": chunks,
            "memory_pages": sum(c["pages"] for c in chunks),
        }

        # VTL0 first, as the control that says the register indexing is right: a CR0 with PG and
        # PE set, CR4 with PAE, and EFER with LMA is a long-mode processor and not an off-by-one.
        state.force_vtl(vp, 0)
        vtl0 = {
            "enabled": state.active_vtl_enabled(vp),
            "paging_mode": state.paging_mode(vp),
            "cr0": state.register(vp, "X64_RegisterCr0"),
            "cr3": state.register(vp, "X64_RegisterCr3"),
            "cr4": state.register(vp, "X64_RegisterCr4"),
            "efer": state.register(vp, "X64_RegisterEfer"),
            "rip": state.register(vp, "X64_RegisterRip"),
        }
        vtl0["long_mode_consistent"] = bool(
            vtl0["cr0"] & (1 << 31) and vtl0["cr0"] & 1 and vtl0["cr4"] & (1 << 5) and vtl0["efer"] & (1 << 10)
        )
        vtl0["root"] = describe_root(state, vtl0["cr3"] & PFN_MASK)
        report["vtl0"] = vtl0

        vtl1 = read_vtl1(state, vp, vtl0["cr3"])
        report["vtl1"] = vtl1

        disk = image_on_disk(args.image)
        report["disk_image"] = disk

        if vtl1.get("enabled") and vtl1.get("cr3"):
            root_gpa = vtl1["cr3"] & PFN_MASK
            vtl1["root"] = describe_root(state, root_gpa)
            leaves, walk_stats = walk(state, root_gpa)
            report["walk"] = {
                "root_gpa": root_gpa,
                "root_from": "GetRegisterValue at forced VTL1, this capture",
                "leaf_pages": sum(leaf[2] // PAGE for leaf in leaves),
                "leaf_entries": len(leaves),
                "distinct_leaf_gpas": len({leaf[1] for leaf in leaves}),
                **walk_stats,
            }
            images, page_scanned, capped = scan_leaves_for_images(state, leaves, disk)
            report["walk"]["pe_images"] = images
            report["walk"]["leaf_pages_scanned"] = page_scanned
            report["walk"]["leaf_scan_capped"] = capped
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

                chosen, attempts = identify_image(
                    matches, lambda va, size: gather_image(read_va, va, size)
                )
                report["kdbg"] = {"candidates": attempts}
                if chosen:
                    found = chosen["candidate"]
                    report["kdbg"]["chosen_va"] = found["va"]
                    report["kdbg"]["hits"] = chosen["hits"]
                    report["module_list"] = walk_module_list(
                        read_va, chosen["block"]["ps_loaded_module_list"]
                    )
                else:
                    # Every matching mapping was examined and none carried a block naming itself.
                    found = matches[0]
                    report["kdbg"]["hits"] = []

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
            images, kdbg, scanned, hit_limit = scan_physical_for_images(
                state, chunks, page_size, disk, args.scan_pages
            )
            report["physical_scan"] = {
                "pages_scanned": scanned,
                "hit_limit": hit_limit,
                "pe_images": len(images),
                "matching_images": [i for i in images if i["matches_disk"]],
                "kdbg_tags": kdbg,
            }

        report["reads"] = {"count": state.reads, "bytes": state.read_bytes}
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
