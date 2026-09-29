"""Who reads a Hyper-V partition object's intercept-routine field, and from where.

`FOLLOWUPS.md` item 103, gate S5q arm 1. The arm chained a routine into
`[partition_object+0x10]`, verified the field read back, held a `#BP` trap --
and the chained routine was never called. Two explanations survive that:
the message does not reach the partition's registered routine, or *the field we
patched is not the one this message's dispatch consults*. They want opposite
next steps, and a live arm cannot separate them, because every reading from an
instrument never observed to work is uninterpretable.

This separates them statically. A census of `+0x10` alone cannot: 0x10 is one of
the most common displacements in any image, and `tools/vid_field_census.py`
reports 365 accesses to it in `winhvr.sys`. What makes an access a *partition
object* access is not the offset but the provenance of the base pointer, so this
first finds every function that can hold one at all -- by calling
`WinHvpReferencePartition`, or by loading `WinHvpPartitionArray` and walking it
-- and only then looks at what those functions do with `+0x10` and `+0x18`.

Both anchors are read from the image's PDB by the caller and passed in, because
they are build-specific and this script must not carry a remembered constant for
a structure it would then misreport.

Decoded, not byte-scanned, for the reason `vid_field_census.py` records: a
displacement is not a byte pattern, and a `call` target is not an immediate that
a search for bytes can recognise.

What it does NOT see, and the reason the count below is a lower bound rather
than an enumeration: a function that receives the partition object as an
**argument**, or obtains it from some helper other than
`WinHvpReferencePartition`, calls neither anchor, so it is absent from the
reaching set even when it reads the callback pair. Closing that needs provenance
propagated across calls and returns, which this does not do. Read
"functions that can hold a partition object" as "functions that can obtain one
by the two routes this looks for".
"""
import argparse
import struct
import sys

try:
    import capstone
except ImportError:
    sys.exit("capstone is required; run this from the repo, not the scratchpad")


def sections(data):
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, pe + 6)[0]
    optsz = struct.unpack_from("<H", data, pe + 20)[0]
    base = struct.unpack_from("<Q", data, pe + 24 + 24)[0]
    out = []
    so = pe + 24 + optsz
    for i in range(nsec):
        b = so + i * 40
        name = data[b:b + 8].rstrip(b"\0").decode("ascii", "replace")
        vs, va, rs, pr, _, _, _, ch = struct.unpack_from("<IIIIIIHH", data, b + 8)
        ch = struct.unpack_from("<I", data, b + 36)[0]
        out.append(dict(name=name, va=va, vs=vs, raw=pr, rs=rs, exec=bool(ch & 0x20000000)))
    return base, out


def decode_all(md, code, base):
    """Decode a byte range, resuming past anything capstone refuses.

    `md.disasm` STOPS at the first undecodable byte and reports no error, so a
    single bad byte silently hides every instruction after it in that range --
    which in a `.pdata` gap means hiding exactly the leaf code the gap scan
    exists to find. Returns the instructions and the count of bytes skipped, so
    "scanned" is reported with what it could not read.
    """
    out, skipped, at = [], 0, 0
    while at < len(code):
        got = list(md.disasm(code[at:], base + at))
        if not got:
            at += 1
            skipped += 1
            continue
        out.extend(got)
        at = (got[-1].address + got[-1].size) - base
    return out, skipped


def rva_to_off(secs, rva):
    for s in secs:
        if s["va"] <= rva < s["va"] + max(s["vs"], s["rs"]):
            return s["raw"] + (rva - s["va"])
    return None


def pdata_functions(data, secs):
    """Each entry is (start, end, unwind_rva); the third is what says whether
    `rbp` is this function's frame register or just another callee-saved
    general-purpose register, which decides whether `[rbp+0x10]` is a stack
    access or a field access."""
    for s in secs:
        if s["name"] == ".pdata":
            n = s["rs"] // 12
            out = []
            for i in range(n):
                b = s["raw"] + i * 12
                start, end, unwind = struct.unpack_from("<III", data, b)
                if start and end > start:
                    out.append((start, end, unwind))
            return sorted(set(out))
    return []


RBP_ENCODING = 5


def frame_register(data, secs, unwind_rva):
    """UNWIND_INFO byte 3 is FrameRegister:4 | FrameOffset:4, and FrameRegister
    is 0 when the function establishes none. Returns the register encoding, or
    0 when there is no usable unwind record."""
    if not unwind_rva:
        return 0
    off = rva_to_off(secs, unwind_rva)
    if off is None or off + 4 > len(data):
        return 0
    if (data[off] & 0x07) != 1:          # UNWIND_INFO version 1 only
        return 0
    return data[off + 3] & 0x0F


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--image", required=True)
    ap.add_argument("--ref-partition-rva", required=True,
                    help="RVA of WinHvpReferencePartition, from the PDB")
    ap.add_argument("--partition-array-rva", required=True,
                    help="RVA of the WinHvpPartitionArray cell, from the PDB")
    ap.add_argument("--fields", default="0x10,0x18",
                    help="displacements to report inside the reaching functions")
    a = ap.parse_args()

    ref_rva = int(a.ref_partition_rva, 0)
    arr_rva = int(a.partition_array_rva, 0)
    fields = [int(x, 0) for x in a.fields.split(",")]

    data = open(a.image, "rb").read()
    _, secs = sections(data)
    funcs = pdata_functions(data, secs)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    # `.pdata` is exact for the functions it claims and does not claim leaf
    # functions, so a leaf that loads the array or reads the pair would be
    # invisible to a scan that stopped here. `vid_field_census.py` decodes the
    # executable bytes `.pdata` leaves out, and so does this: the gap runs are
    # scanned as regions of their own, padding skipped.
    regions = [(s, e, False, frame_register(data, secs, u)) for s, e, u in funcs]
    claimed = sorted((s, e) for s, e, _ in funcs)
    gap_bytes = pad_bytes = 0
    gap_runs = 0
    for sec in secs:
        if not sec["exec"]:
            continue
        at, end_rva = sec["va"], sec["va"] + min(sec["vs"] or sec["rs"], sec["rs"])
        covered = [(s, e) for s, e in claimed if e > at and s < end_rva]
        cursor = at
        holes = []
        for s, e in covered:
            if s > cursor:
                holes.append((cursor, s))
            cursor = max(cursor, e)
        if cursor < end_rva:
            holes.append((cursor, end_rva))
        for hs, he in holes:
            off = rva_to_off(secs, hs)
            if off is None:
                continue
            blob = data[off:off + (he - hs)]
            gap_bytes += len(blob)
            # Split at EVERY padding run, not just the outer edges: one span can
            # hold several leaf-code islands separated by 0xCC/0x00, and
            # decoding the whole span as one stream misaligns across the padding
            # and loses the later islands.
            i = 0
            while i < len(blob):
                if blob[i] in (0xCC, 0x00):
                    pad_bytes += 1
                    i += 1
                    continue
                j = i
                while j < len(blob) and blob[j] not in (0xCC, 0x00):
                    j += 1
                gap_runs += 1
                # A gap run has no unwind record, so nothing licenses treating
                # its `rbp` as a frame pointer: keep those operands.
                regions.append((hs + i, hs + j, True, 0))
                i = j
    print("executable bytes .pdata does not claim: %d (%d of them 0xCC/0x00 padding); "
          "%d gap run(s) held anything else, each split at padding and scanned as its own region"
          % (gap_bytes, pad_bytes, gap_runs))

    reaching = {}   # region start -> set of reasons
    bodies = {}
    from_gap = set()
    framereg = {}
    undecoded = 0
    for start, end, is_gap, fr in regions:
        off = rva_to_off(secs, start)
        if off is None:
            continue
        code = data[off:off + (end - start)]
        ins, skipped = decode_all(md, code, start)
        undecoded += skipped
        bodies[start] = ins
        framereg[start] = fr
        if is_gap:
            from_gap.add(start)
        why = set()
        for i in ins:
            if i.mnemonic in ("call", "jmp") and i.operands:
                op = i.operands[0]
                if op.type == capstone.x86.X86_OP_IMM and op.imm == ref_rva:
                    why.add("calls WinHvpReferencePartition")
            for op in i.operands:
                if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                    if i.address + i.size + op.mem.disp == arr_rva:
                        why.add("loads WinHvpPartitionArray")
        if why:
            reaching[start] = why

    print("image                : %s" % a.image)
    print(".pdata functions     : %d" % len(funcs))
    print("regions scanned      : %d (.pdata functions plus decoded gap runs)" % len(bodies))
    print("bytes capstone refused, skipped and resumed past: %d" % undecoded)
    print("regions that can hold a partition object: %d" % len(reaching))
    print()
    for start in sorted(reaching):
        tag = " [gap run, not a .pdata function]" if start in from_gap else ""
        print("  +0x%06X  (%s)%s" % (start, ", ".join(sorted(reaching[start])), tag))
    print()

    print("=== accesses to %s inside those functions ===" %
          ", ".join("+0x%X" % f for f in fields))
    total = 0
    for start in sorted(reaching):
        hits = []
        for i in bodies[start]:
            for op in i.operands:
                if op.type != capstone.x86.X86_OP_MEM:
                    continue
                # Stack frames are not partition objects, and rsp-relative
                # traffic at these offsets is spill noise that swamps the
                # answer. `rbp` is NOT stack traffic by default: in optimized
                # x64 it is an ordinary callee-saved register unless the
                # function's UNWIND_INFO names it as the frame register, so it
                # is suppressed only when that record says so and is otherwise
                # reported and tagged for classification by hand.
                if op.mem.base in (capstone.x86.X86_REG_RIP,
                                   capstone.x86.X86_REG_RSP):
                    continue
                if (op.mem.base == capstone.x86.X86_REG_RBP
                        and framereg.get(start) == RBP_ENCODING):
                    continue
                if op.mem.disp not in fields:
                    continue
                # capstone's own classification, not a guess from the mnemonic.
                rw = ""
                if op.access & capstone.CS_AC_WRITE:
                    rw += "W"
                if op.access & capstone.CS_AC_READ:
                    rw += "R"
                tag = ""
                if op.mem.base == capstone.x86.X86_REG_RBP:
                    tag = "  <== rbp base, not this function's frame register"
                hits.append((i.address, rw or "?", i.mnemonic, i.op_str + tag))
        if not hits:
            continue
        print("  function +0x%06X" % start)
        for addr, rw, mn, ops in hits:
            total += 1
            print("      +0x%06X  [%-2s]  %s %s" % (addr, rw, mn, ops))
    print()
    print("total: %d non-stack access(es) to the named fields in functions that"
          " can hold a partition object" % total)


if __name__ == "__main__":
    main()
