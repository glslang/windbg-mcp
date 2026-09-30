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

`--self-test` exercises the gap decoding against images built here, including
the two readings of a `.pdata` gap that each lost real leaf code. Run it after
any change to `decode_union` or `gap_decode_starts`; a run against a real image
cannot detect a gap-scan regression, because the answer on `winhvr.sys` does not
move through either defect.
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


def gap_decode_starts(blob):
    """Offsets in a `.pdata` gap worth decoding from, and the padding count.

    The starts are the span's own start and the first byte of every non-padding
    island in it. Padding is counted for the report only -- it is NOT used to
    cut the span up, for the reason in `decode_union`.
    """
    starts, pad = [0], 0
    for i, b in enumerate(blob):
        if b in (0xCC, 0x00):
            pad += 1
        elif i and blob[i - 1] in (0xCC, 0x00):
            starts.append(i)
    return starts, pad


def decode_union(md, code, base, starts):
    """Decode from several candidate offsets and union what they find.

    A `.pdata` gap carries no unwind record, so nothing in the image says where
    an instruction in it begins. Two single-alignment readings were tried here
    and **each one lost real leaf code**:

    - Decoding the span as one stream loses an island after an odd-length run of
      `0x00`, because `00 00` decodes as a two-byte `add byte ptr [rax], al` --
      so a zero run of odd length shifts every instruction after it by one and
      the island is read as garbage. (`0xCC` is one byte and keeps alignment,
      which is why the defect needs a zero run to show up.)
    - Splitting the span at every `0xCC`/`0x00` byte cuts instructions apart. A
      single zero byte is not padding: almost every RIP-relative load in a
      driver carries one in its high displacement byte, so the split lands
      inside the very instruction the scan exists to find.

    Decoding from each candidate start across the whole remaining span and
    unioning by `(address, size)` is subject to neither. The union is a lower
    bound with possible phantoms rather than an enumeration -- a misaligned
    start decodes bytes that are not instructions -- so it can only widen the
    reaching set, never narrow it, and the sites that matter are read back as
    disassembly by hand rather than trusted from the count.
    """
    seen, skipped = {}, 0
    for s in sorted(set(starts)):
        if s >= len(code):
            continue
        got, miss = decode_all(md, code[s:], base + s)
        skipped += miss
        for i in got:
            seen.setdefault((i.address, i.size), i)
    return [seen[k] for k in sorted(seen)], skipped


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


def regions_of(data, secs, funcs):
    """Every region to decode: each `.pdata` function, plus each executable span
    `.pdata` does not claim. A region is (start, end, is_gap, frame_reg,
    decode_starts); `decode_starts` are relative to `start`.

    `.pdata` is exact for the functions it claims and does not claim leaf
    functions, so a leaf that loads the array or reads the pair would be
    invisible to a scan that stopped at the table. `vid_field_census.py` decodes
    the executable bytes `.pdata` leaves out, and so does this.
    """
    out = [(s, e, False, frame_register(data, secs, u), (0,)) for s, e, u in funcs]
    claimed = sorted((s, e) for s, e, _ in funcs)
    gap_bytes = pad_bytes = gap_spans = 0
    for sec in secs:
        if not sec["exec"]:
            continue
        at = sec["va"]
        end_rva = sec["va"] + min(sec["vs"] or sec["rs"], sec["rs"])
        covered = [(s, e) for s, e in claimed if e > at and s < end_rva]
        cursor, holes = at, []
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
            starts, pad = gap_decode_starts(blob)
            pad_bytes += pad
            if pad == len(blob):
                continue                 # padding only, nothing to decode
            gap_spans += 1
            # A gap span has no unwind record, so nothing licenses treating its
            # `rbp` as a frame pointer: keep those operands.
            out.append((hs, he, True, 0, tuple(starts)))
    return out, gap_bytes, pad_bytes, gap_spans


def analyse(data, secs, md, regions, ref_rva, arr_rva):
    """For each region, whether it can hold a partition object and why."""
    reaching, bodies, framereg, from_gap, undecoded = {}, {}, {}, set(), 0
    for start, end, is_gap, fr, starts in regions:
        off = rva_to_off(secs, start)
        if off is None:
            continue
        code = data[off:off + (end - start)]
        ins, skipped = decode_union(md, code, start, starts)
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
    return reaching, bodies, framereg, from_gap, undecoded


def field_hits(bodies, framereg, start, fields):
    """Non-stack accesses to `fields` inside one region, capstone-classified."""
    hits = []
    for i in bodies[start]:
        for op in i.operands:
            if op.type != capstone.x86.X86_OP_MEM:
                continue
            # Stack frames are not partition objects, and rsp-relative traffic
            # at these offsets is spill noise that swamps the answer. `rbp` is
            # NOT stack traffic by default: in optimized x64 it is an ordinary
            # callee-saved register unless the function's UNWIND_INFO names it
            # as the frame register, so it is suppressed only when that record
            # says so and is otherwise reported and tagged for classification
            # by hand.
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
    return hits


# --------------------------------------------------------------------------
# Self-test. The images below are built here, because the gap-scan defects it
# pins are invisible on `winhvr.sys`: the answer there is 28 reaching regions
# and 42 accesses under both of the readings `decode_union` replaced.
# --------------------------------------------------------------------------

def _leaf(at, anchor):
    """A 12-byte leaf that loads the partition-array anchor and reads +0x10:

        mov rax, [rip+disp32]   ; disp32 reaches `anchor`
        mov rax, [rax+0x10]
        ret

    `disp32` carries zero bytes for any anchor inside the first 16 MiB of the
    image, which is what the split-at-every-zero reading cut in half.
    """
    disp = anchor - (at + 7)
    return (bytes([0x48, 0x8B, 0x05]) + struct.pack("<i", disp)
            + bytes([0x48, 0x8B, 0x40, 0x10])
            + bytes([0xC3]))


TEXT_VA, TEXT_RAW, TEXT_SZ = 0x1000, 0x400, 0x200
PDATA_VA, PDATA_RAW = 0x2000, 0x600
ANCHOR_VA = 0x3000


def _synthetic_image(text):
    """A minimal PE32+ whose `.text` holds `text` and whose `.pdata` claims only
    a one-byte stub at the section start -- so everything after it is a gap."""
    body = bytearray(text)
    body += bytes([0xCC]) * (TEXT_SZ - len(body))
    pdata = struct.pack("<III", TEXT_VA, TEXT_VA + 1, 0)
    opt = bytearray(240)
    struct.pack_into("<H", opt, 0, 0x20B)                 # PE32+
    struct.pack_into("<Q", opt, 24, 0x140000000)          # ImageBase
    secs = b""
    for name, va, vs, raw, rs, ch in (
            (b".text", TEXT_VA, TEXT_SZ, TEXT_RAW, TEXT_SZ, 0x60000020),
            (b".pdata", PDATA_VA, len(pdata), PDATA_RAW, len(pdata), 0x40000040)):
        secs += name.ljust(8, bytes(1)) + struct.pack("<IIII", vs, va, rs, raw)
        secs += struct.pack("<IIHH", 0, 0, 0, 0) + struct.pack("<I", ch)
    pe = 0x80
    img = bytearray(0x800)
    img[0:2] = b"MZ"
    struct.pack_into("<I", img, 0x3C, pe)
    img[pe:pe + 4] = b"PE" + bytes(2)
    struct.pack_into("<HHIIIHH", img, pe + 4, 0x8664, 2, 0, 0, 0, len(opt), 0x22)
    img[pe + 24:pe + 24 + len(opt)] = opt
    img[pe + 24 + len(opt):pe + 24 + len(opt) + len(secs)] = secs
    img[TEXT_RAW:TEXT_RAW + len(body)] = body
    img[PDATA_RAW:PDATA_RAW + len(pdata)] = pdata
    return bytes(img)


def _reaching_on(data, md, arr_rva):
    _, secs = sections(data)
    funcs = pdata_functions(data, secs)
    regions, _, _, _ = regions_of(data, secs, funcs)
    reaching, bodies, framereg, from_gap, _ = analyse(data, secs, md, regions,
                                                     TEXT_VA, arr_rva)
    accesses = sum(len(field_hits(bodies, framereg, s, [0x10, 0x18]))
                   for s in reaching)
    spans = {s: e for s, e, is_gap, _, _ in regions if is_gap}
    return reaching, accesses, from_gap, spans


def self_test():
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    results = []

    def check(name, got, want):
        results.append((name, got == want, got, want))

    # --- the encoding the regression turned on -----------------------------
    leaf_at = 0x1020
    leaf = _leaf(leaf_at, ANCHOR_VA)
    check("leaf is 12 bytes", len(leaf), 12)
    check("its displacement carries zero bytes", leaf.count(0), 2)

    # --- defect A: split at every 0x00/0xCC cut the leaf in half -----------
    # Pin the cause, not just the cure: the cut start set must NOT be what we
    # decode from, and the union must find the anchor load.
    cut = decode_union(md, leaf[:leaf.index(bytes([0])[0])], leaf_at, (0,))[0]
    check("a span cut at the first zero byte loses the anchor load",
          any(i.mnemonic == "mov" and "rip" in i.op_str for i in cut), False)
    ins, _ = decode_union(md, leaf, leaf_at, gap_decode_starts(leaf)[0])
    check("the union decodes the anchor load",
          [(i.mnemonic, i.op_str) for i in ins][0],
          ("mov", "rax, qword ptr [rip + 0x1fd9]"))

    # --- defect B: one stream lost an island after an odd zero run ---------
    # Three 0x00 bytes: `00 00` is a two-byte `add byte ptr [rax], al`, so the
    # third shifts the island after it. Pin that the one-stream reading misses
    # island two and the union finds it.
    second_at = leaf_at + len(leaf) + 3
    span = leaf + bytes(3) + _leaf(second_at, ANCHOR_VA)
    one_stream, _ = decode_union(md, span, leaf_at, (0,))
    starts, _ = gap_decode_starts(span)
    unioned, _ = decode_union(md, span, leaf_at, starts)

    def anchor_loads(ins_list):
        n = 0
        for i in ins_list:
            for op in i.operands:
                if (op.type == capstone.x86.X86_OP_MEM
                        and op.mem.base == capstone.x86.X86_REG_RIP
                        and i.address + i.size + op.mem.disp == ANCHOR_VA):
                    n += 1
        return n

    check("island start after the zero run is a decode start",
          second_at - leaf_at in starts, True)
    check("one stream finds only the first island's anchor load",
          anchor_loads(one_stream), 1)
    check("the union finds both", anchor_loads(unioned), 2)

    # --- end to end, through the CLI's own path ---------------------------
    img = _synthetic_image(bytes([0xCC]) * (leaf_at - TEXT_VA) + leaf)
    reaching, accesses, from_gap, spans = _reaching_on(img, md, ANCHOR_VA)
    check("a leaf in a gap reaches, end to end", len(reaching), 1)
    check("and its +0x10 read is reported", accesses, 1)
    # The region is the whole gap span, not the island inside it -- so pin that
    # it is a gap span CONTAINING the leaf rather than an RVA equal to it, which
    # was the per-island shape this replaced.
    got = sorted(reaching)[0] if reaching else None
    check("the reaching region is a gap span holding the leaf",
          got in from_gap and got <= leaf_at < spans.get(got, 0), True)

    # --- control: the assertions above must be able to fail ---------------
    blind, blind_n, _, _ = _reaching_on(img, md, ANCHOR_VA + 8)
    check("an anchor the image does not load reaches nothing",
          (len(blind), blind_n), (0, 0))
    empty, empty_n, _, _ = _reaching_on(_synthetic_image(bytes([0xCC]) * 32), md,
                                        ANCHOR_VA)
    check("an image with no leaf reaches nothing", (len(empty), empty_n), (0, 0))

    ok = sum(1 for _, good, _, _ in results if good)
    for name, good, got, want in results:
        print("  %-4s %s" % ("PASS" if good else "FAIL", name))
        if not good:
            print("         got %r, wanted %r" % (got, want))
    print("self-test: %d/%d" % (ok, len(results)))
    return ok == len(results)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--image")
    ap.add_argument("--ref-partition-rva",
                    help="RVA of WinHvpReferencePartition, from the PDB")
    ap.add_argument("--partition-array-rva",
                    help="RVA of the WinHvpPartitionArray cell, from the PDB")
    ap.add_argument("--fields", default="0x10,0x18",
                    help="displacements to report inside the reaching functions")
    ap.add_argument("--self-test", action="store_true",
                    help="run the gap-decoding regression cases and exit")
    a = ap.parse_args()

    if a.self_test:
        sys.exit(0 if self_test() else 1)
    if not (a.image and a.ref_partition_rva and a.partition_array_rva):
        ap.error("--image, --ref-partition-rva and --partition-array-rva are "
                 "required without --self-test")

    ref_rva = int(a.ref_partition_rva, 0)
    arr_rva = int(a.partition_array_rva, 0)
    fields = [int(x, 0) for x in a.fields.split(",")]

    data = open(a.image, "rb").read()
    _, secs = sections(data)
    funcs = pdata_functions(data, secs)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    regions, gap_bytes, pad_bytes, gap_spans = regions_of(data, secs, funcs)
    print("executable bytes .pdata does not claim: %d (%d of them 0xCC/0x00 "
          "padding); %d span(s) held anything else, each decoded from its own "
          "start and from every island start in it" % (gap_bytes, pad_bytes, gap_spans))

    reaching, bodies, framereg, from_gap, undecoded = analyse(
        data, secs, md, regions, ref_rva, arr_rva)

    print("image                : %s" % a.image)
    print(".pdata functions     : %d" % len(funcs))
    print("regions scanned      : %d (.pdata functions plus decoded gap spans)" % len(bodies))
    print("bytes capstone refused, skipped and resumed past: %d" % undecoded)
    print("regions that can hold a partition object: %d" % len(reaching))
    print()
    spans = {s: e for s, e, is_gap, _, _ in regions if is_gap}
    for start in sorted(reaching):
        # A gap region is a SPAN, so print its range: its start is where
        # `.pdata` stopped claiming, not a function entry, and reading it as one
        # is how a span start gets quoted as a routine's RVA.
        tag = ("  [gap span +0x%06X..+0x%06X, not a .pdata function]"
               % (start, spans[start])) if start in from_gap else ""
        print("  +0x%06X  (%s)%s" % (start, ", ".join(sorted(reaching[start])), tag))
    print()

    print("=== accesses to %s inside those functions ===" %
          ", ".join("+0x%X" % f for f in fields))
    total = 0
    for start in sorted(reaching):
        hits = field_hits(bodies, framereg, start, fields)
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
