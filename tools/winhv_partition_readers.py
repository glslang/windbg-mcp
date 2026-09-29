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


def rva_to_off(secs, rva):
    for s in secs:
        if s["va"] <= rva < s["va"] + max(s["vs"], s["rs"]):
            return s["raw"] + (rva - s["va"])
    return None


def pdata_functions(data, secs):
    for s in secs:
        if s["name"] == ".pdata":
            n = s["rs"] // 12
            out = []
            for i in range(n):
                b = s["raw"] + i * 12
                start, end, _ = struct.unpack_from("<III", data, b)
                if start and end > start:
                    out.append((start, end))
            return sorted(set(out))
    return []


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

    reaching = {}   # func start -> set of reasons
    bodies = {}
    for start, end in funcs:
        off = rva_to_off(secs, start)
        if off is None:
            continue
        code = data[off:off + (end - start)]
        ins = list(md.disasm(code, start))
        bodies[start] = ins
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
    print("functions that can hold a partition object: %d" % len(reaching))
    print()
    for start in sorted(reaching):
        print("  +0x%06X  (%s)" % (start, ", ".join(sorted(reaching[start]))))
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
                # Stack frames are not partition objects. rsp/rbp-relative
                # traffic at these offsets is spill noise and swamps the answer.
                if op.mem.base in (capstone.x86.X86_REG_RIP,
                                   capstone.x86.X86_REG_RSP,
                                   capstone.x86.X86_REG_RBP):
                    continue
                if op.mem.disp not in fields:
                    continue
                # capstone's own classification, not a guess from the mnemonic.
                rw = ""
                if op.access & capstone.CS_AC_WRITE:
                    rw += "W"
                if op.access & capstone.CS_AC_READ:
                    rw += "R"
                hits.append((i.address, rw or "?", i.mnemonic, i.op_str))
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
