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

One more limit, which is the boundary rule's own and is measured rather than
assumed: a genuine `int3` at an instruction boundary inside gap code ends the
island there, so a real leaf containing one is split in two -- the half holding
the anchor load reaches and the half holding the field access does not, and that
access is **dropped**. That undercounts, which is the direction that matters for a
census meant to license a negative. It does not reach `.pdata`-claimed functions,
which have exact bounds, are decoded whole, and never see this rule -- and on
`winhvr.sys` every reaching region is one of those, so the exposure there is
hypothetical rather than current.

`--self-test` exercises the gap decoding against images built here: the two
readings of a `.pdata` gap that each lost real leaf code, the span-wide region
that attributed one leaf's field access to another leaf's anchor load, and the
truncation just described, pinned as behaviour. Run it
after any change to `decode_island`, `gap_decode_starts` or `regions_of`; a run
against a real image cannot detect any of those, because the answer on
`winhvr.sys` does not move through them.
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
    exists to find. Returns the instructions and the ADDRESSES it could not read,
    so that "scanned" is reported with what it could not read and so that a byte
    refused by two overlapping decode attempts is counted once.
    """
    out, refused, at = [], [], 0
    while at < len(code):
        got = list(md.disasm(code[at:], base + at))
        if not got:
            refused.append(base + at)
            at += 1
            continue
        out.extend(got)
        at = (got[-1].address + got[-1].size) - base
    return out, refused


def gap_decode_starts(blob):
    """Offsets in a `.pdata` gap worth decoding from, and the padding count.

    The starts are the span's own start and the first byte of every non-padding
    island in it. Padding is counted for the report only -- it is NOT used to cut
    an instruction in half, for the reason in `decode_island`, which applies the
    padding test at instruction boundaries instead.
    """
    starts, pad = [0], 0
    for i, b in enumerate(blob):
        if b in (0xCC, 0x00):
            pad += 1
        elif i and blob[i - 1] in (0xCC, 0x00):
            starts.append(i)
    return starts, pad


def decode_island(md, blob, base, start):
    """Decode ONE island of a `.pdata` gap, and say where it ended.

    A gap carries no unwind record, so nothing in the image says where an
    instruction in it begins, nor where one leaf ends and the next starts. Three
    readings were tried here and the first two each lost real leaf code:

    - Decoding a whole span as one stream loses an island after an odd-length
      run of `0x00`, because `00 00` decodes as a two-byte
      `add byte ptr [rax], al` -- so the odd byte shifts everything after it and
      the island is read as garbage. (`0xCC` is one byte and keeps alignment,
      which is why the defect needs a zero run to show up.)
    - Splitting the span at every `0xCC`/`0x00` byte cuts instructions apart. A
      single zero byte is not padding: almost every RIP-relative load in a
      driver carries one in its high displacement byte, so the split lands
      inside the very instruction the scan exists to find.

    The rule subject to neither is to apply the padding test **where an
    instruction begins** rather than to every byte: decode linearly from
    `start`, let an instruction swallow whatever interior `0xCC`/`0x00` bytes its
    own encoding contains, and stop when the next *instruction boundary* lands on
    padding. A zero inside a displacement is then not a boundary, and a genuine
    padding run between two leaves is.

    Stopping there is also what keeps **provenance** per leaf. A span-wide region
    would let `field_hits` attribute one island's `+0x10` read to a *different*
    island that loaded the anchor -- an anchor-loading leaf, padding, then an
    unrelated field-reading leaf, reported as one reaching function. The islands
    are decoded separately so that correlation cannot cross a real boundary.

    Returns (instructions, end_offset, refused_addresses). The refusals are
    addresses rather than a count because callers decode islands that can
    overlap, and a count would add the same byte up once per attempt.
    """
    ins, refused, p = [], [], start
    while p < len(blob):
        if blob[p] in (0xCC, 0x00):
            break                    # instruction boundary on padding: island over
        got = next(md.disasm(blob[p:], base + p, count=1), None)
        if got is None:
            refused.append(base + p)
            p += 1
            continue
        ins.append(got)
        p += got.size
    return ins, p, refused


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
    """Every region to decode: each `.pdata` function, and each ISLAND of each
    executable span `.pdata` does not claim. A region is
    (start, limit, is_gap, frame_reg) -- `limit` bounds the decode, and a gap
    island's decode stops earlier, wherever `decode_island` finds its boundary.

    `.pdata` is exact for the functions it claims and does not claim leaf
    functions, so a leaf that loads the array or reads the pair would be
    invisible to a scan that stopped at the table. `vid_field_census.py` decodes
    the executable bytes `.pdata` leaves out, and so does this.

    **One region per island, not per span.** A span-wide region would make
    `field_hits` attribute one leaf's `+0x10` read to a different leaf that
    loaded the anchor, since both would sit in the same body -- so an
    anchor-loading leaf, padding, and an unrelated field-reading leaf would read
    as one reaching function. Islands can overlap (a zero inside a displacement
    puts a candidate start mid-instruction), and overlapping candidates are kept
    rather than pruned: a pruned start could drop a real leaf that a misaligned
    neighbour's decode had run over, and a spurious island is either not reaching
    -- contributing nothing -- or reaching and hand-read.
    """
    out = [(s, e, False, frame_register(data, secs, u)) for s, e, u in funcs]
    claimed = sorted((s, e) for s, e, _ in funcs)
    gap_bytes = pad_bytes = gap_spans = gap_islands = 0
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
            for rel in starts:
                if rel >= len(blob) or blob[rel] in (0xCC, 0x00):
                    continue             # a start that is itself padding decodes nothing
                gap_islands += 1
                # A gap island has no unwind record, so nothing licenses treating
                # its `rbp` as a frame pointer: keep those operands.
                out.append((hs + rel, he, True, 0))
    return out, gap_bytes, pad_bytes, gap_spans, gap_islands


def analyse(data, secs, md, regions, ref_rva, arr_rva):
    """For each region, whether it can hold a partition object and why.

    Each region is decoded on its own, so `bodies` never mixes two islands --
    which is what keeps `field_hits` from correlating one leaf's field access
    with another leaf's anchor load.
    """
    reaching, bodies, framereg, from_gap, ends = {}, {}, {}, set(), {}
    refused = set()
    for start, limit, is_gap, fr in regions:
        off = rva_to_off(secs, start)
        if off is None:
            continue
        code = data[off:off + (limit - start)]
        if is_gap:
            ins, stopped, miss = decode_island(md, code, start, 0)
            refused.update(miss)
            ends[start] = start + stopped
        else:
            # `.pdata` gives exact bounds, so decode the whole body; a zero byte
            # inside a claimed function is not a boundary and there is nothing to
            # infer about where it ends.
            ins, miss = decode_all(md, code, start)
            refused.update(miss)
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
    return reaching, bodies, framereg, from_gap, len(refused), ends


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
# Self-test. The images below are built here, because every defect it pins is
# invisible on `winhvr.sys`: the answer there is 28 reaching regions and 42
# accesses under all three gap readings AND under the span-wide attribution.
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


def _field_leaf():
    """A 5-byte leaf that reads `+0x18` off a register and loads NO anchor:

        mov rax, [rcx+0x18]
        ret

    Used to pin that its access is not attributed to a neighbouring leaf that
    did load the anchor. No zero bytes, so it is not itself a defect-A case.
    """
    return bytes([0x48, 0x8B, 0x41, 0x18, 0xC3])


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
    regions, _, _, _, _ = regions_of(data, secs, funcs)
    reaching, bodies, framereg, from_gap, _, ends = analyse(
        data, secs, md, regions, TEXT_VA, arr_rva)
    accesses = sum(len(field_hits(bodies, framereg, s, [0x10, 0x18]))
                   for s in reaching)
    return reaching, accesses, from_gap, ends


def _only(reaching):
    """The single reaching region's start, or None. See `_nth` for why."""
    return sorted(reaching)[0] if len(reaching) == 1 else None


def _nth(seq, i):
    """`seq[i]`, or an empty list when it is not there.

    **Every index in this self-test goes through `_only` or `_nth`**, because a
    mutation that empties a result must make the case depending on it report
    FAIL: a bare `seq[i]` raises `IndexError`, which aborts the run and hides
    every case after it -- so the mutation reads as a crash rather than as the
    specific assertions it broke. That happened twice here, the second time in a
    case added one commit after the first was fixed, which is why this is a
    helper rather than a guard written per site.
    """
    return seq[i] if i < len(seq) else []


def self_test():
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    results = []

    def check(name, got, want):
        results.append((name, got == want, got, want))

    def anchor_loads(ins_list):
        n = 0
        for i in ins_list:
            for op in i.operands:
                if (op.type == capstone.x86.X86_OP_MEM
                        and op.mem.base == capstone.x86.X86_REG_RIP
                        and i.address + i.size + op.mem.disp == ANCHOR_VA):
                    n += 1
        return n

    # --- the encoding every one of these turns on --------------------------
    leaf_at = 0x1020
    leaf = _leaf(leaf_at, ANCHOR_VA)
    check("leaf is 12 bytes", len(leaf), 12)
    check("its displacement carries zero bytes", leaf.count(0), 2)

    # --- defect A: splitting at every 0x00/0xCC cut the leaf in half --------
    # Pin the cause as well as the cure: a span cut at the first zero byte
    # cannot yield the anchor load, and the boundary rule must.
    cut, _, _ = decode_island(md, leaf[:leaf.index(0)], leaf_at, 0)
    check("a span cut at the first zero byte loses the anchor load",
          anchor_loads(cut), 0)
    ins, stopped, _ = decode_island(md, leaf, leaf_at, 0)
    check("the boundary rule decodes the anchor load",
          (ins[0].mnemonic, ins[0].op_str),
          ("mov", "rax, qword ptr [rip + 0x1fd9]"))
    check("and swallows the zero bytes inside its displacement", stopped, 12)

    # --- defect B: one stream lost an island after an odd zero run ----------
    # Three 0x00 bytes: `00 00` is a two-byte `add byte ptr [rax], al`, so the
    # third shifts the island after it out of alignment.
    second_at = leaf_at + len(leaf) + 3
    span = leaf + bytes(3) + _leaf(second_at, ANCHOR_VA)
    one_stream, _ = decode_all(md, span, leaf_at)
    starts, _ = gap_decode_starts(span)
    check("one stream finds only the first island's anchor load",
          anchor_loads(one_stream), 1)
    check("island start after the zero run is a decode start",
          second_at - leaf_at in starts, True)
    per_island = []
    for rel in starts:
        if span[rel] in (0xCC, 0x00):
            continue
        per_island += decode_island(md, span, leaf_at, rel)[0]
    check("decoding each island finds both", anchor_loads(per_island), 2)
    check("and the first island stops at the zero run",
          decode_island(md, span, leaf_at, 0)[1], 12)

    # --- defect C: a span-wide region correlated across two leaves ----------
    # An anchor-loading leaf, padding, then an UNRELATED field-reading leaf.
    # With one region per span the second leaf's +0x18 read was attributed to
    # the first leaf's anchor load, inventing a partition-field hit.
    other_at = leaf_at + len(leaf) + 4
    img = _synthetic_image(bytes([0xCC]) * (leaf_at - TEXT_VA)
                           + leaf + bytes([0xCC]) * 4 + _field_leaf())
    reaching, accesses, from_gap, ends = _reaching_on(img, md, ANCHOR_VA)
    check("only the anchor-loading leaf reaches", len(reaching), 1)
    check("the unrelated leaf's +0x18 is NOT attributed to it", accesses, 1)
    check("the reaching island starts at the leaf, not at the span",
          _only(reaching), leaf_at)
    check("and its decode ends at the leaf's own end",
          ends.get(leaf_at), leaf_at + len(leaf))
    check("the unrelated leaf is a region of its own, and not reaching",
          other_at in from_gap and other_at not in reaching, True)

    # --- a refused byte reached by two overlapping islands is counted once --
    # The zero bytes in the displacement make leaf_at+7 a candidate start, so
    # two islands both run onto the trailing lone 0x0F. Summing per-island
    # counts reported it twice.
    ov = leaf[:7] + bytes([0x0F])
    ov_starts, _ = gap_decode_starts(ov)
    per_chain = [decode_island(md, ov, leaf_at, r)[2]
                 for r in ov_starts if ov[r] not in (0xCC, 0x00)]
    check("two islands each refuse the same byte", [len(x) for x in per_chain], [1, 1])
    check("and it is reported once", len(set(a for x in per_chain for a in x)), 1)

    # --- the boundary rule's own limit, recorded rather than fixed ----------
    # A GENUINE `int3` at an instruction boundary inside gap code ends the island
    # there, so a real leaf containing one is split: the half with the anchor load
    # reaches, the half with the field access does not, and the access is
    # DROPPED. That is an undercount, which is the direction that matters for a
    # census meant to license a negative -- so it is pinned as behaviour, with
    # the prose in the docs saying so, rather than papered over. It does not
    # touch `.pdata`-claimed functions: those have exact bounds, are decoded
    # whole, and never see this rule.
    split = (leaf[:7] + bytes([0xCC]) + leaf[7:])
    sp_starts, _ = gap_decode_starts(split)
    halves = [decode_island(md, split, leaf_at, r)[0]
              for r in sp_starts if split[r] not in (0xCC, 0x00)]
    check("an int3 inside gap code splits the leaf in two",
          [len(h) for h in halves], [1, 2])
    check("the anchor load is still found", anchor_loads(_nth(halves, 0)), 1)
    check("but the +0x10 read lands in the other half, so it is undercounted",
          (any("0x10" in i.op_str for i in _nth(halves, 0)),
           any("0x10" in i.op_str for i in _nth(halves, 1))), (False, True))

    # --- end to end on the bare leaf --------------------------------------
    bare = _synthetic_image(bytes([0xCC]) * (leaf_at - TEXT_VA) + leaf)
    reaching, accesses, from_gap, _ = _reaching_on(bare, md, ANCHOR_VA)
    check("a leaf in a gap reaches, end to end", len(reaching), 1)
    check("and its +0x10 read is reported", accesses, 1)
    check("as a gap island rather than a .pdata function",
          _only(reaching) in from_gap, True)

    # --- controls: the assertions above must be able to fail ---------------
    blind, blind_n, _, _ = _reaching_on(bare, md, ANCHOR_VA + 8)
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

    regions, gap_bytes, pad_bytes, gap_spans, gap_islands = regions_of(data, secs, funcs)
    print("executable bytes .pdata does not claim: %d (%d of them 0xCC/0x00 "
          "padding); %d span(s) held anything else, decoded as %d island(s), each "
          "from its own start and each bounded at an instruction boundary that "
          "lands on padding" % (gap_bytes, pad_bytes, gap_spans, gap_islands))

    reaching, bodies, framereg, from_gap, undecoded, ends = analyse(
        data, secs, md, regions, ref_rva, arr_rva)

    print("image                : %s" % a.image)
    print(".pdata functions     : %d" % len(funcs))
    print("regions scanned      : %d (.pdata functions plus decoded gap islands)" % len(bodies))
    print("distinct bytes capstone refused, skipped and resumed past: %d" % undecoded)
    print("regions that can hold a partition object: %d" % len(reaching))
    print()
    for start in sorted(reaching):
        # A gap region is an ISLAND, so print where its decode actually ended:
        # its start is a candidate entry rather than a `.pdata` function entry,
        # and reading it as one is how a gap RVA gets quoted as a routine's.
        tag = ("  [gap island +0x%06X..+0x%06X, not a .pdata function]"
               % (start, ends[start])) if start in from_gap else ""
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
