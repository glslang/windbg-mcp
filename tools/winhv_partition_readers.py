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

`.pdata` entries and gap spans are two different kinds of thing and are reported
apart. A `.pdata` entry is a function -- exact bounds -- so an anchor load and a
field access inside one are the same function's, and those are the counts this
census licenses. A gap span has no boundary information at all, so nothing inside
it may be grouped: it is decoded as a DETECTOR (see `decode_span`) and reported in
a section of its own, out of the counts, for a human to disassemble. Four attempts
to infer gap boundaries were each wrong in a different direction, which is why
there is no longer one.

`--self-test` exercises this against images built here: detection under each
alignment hazard, the no-attribution rule in both the padded and the unpadded
shape, a byte refused by two overlapping starts counted once, and a
`.pdata`-claimed function as the control that attribution still happens where the
bounds are exact. Run it after any change to `decode_span`, `gap_decode_starts`,
`regions_of` or `analyse_gaps`; a run against a real image cannot detect any of
them, because the answer on
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
    run in it. Padding is counted for the report only: it is NOT a boundary and
    NOT a place to cut, for the reasons in `decode_span`. These are candidate
    *entries* for a decoder, nothing more -- a byte after padding is a plausible
    place for a leaf to begin, and a leaf that begins elsewhere is still reached
    by whichever start's stream runs into it.
    """
    starts, pad = [0], 0
    for i, b in enumerate(blob):
        if b in (0xCC, 0x00):
            pad += 1
        elif i and blob[i - 1] in (0xCC, 0x00):
            starts.append(i)
    return starts, pad


def decode_span(md, blob, base, starts):
    """Decode a `.pdata` gap span from every candidate start and union the result.

    This is a **detector**, not a parser, and that distinction is the whole of
    what three review rounds taught. A gap carries no unwind record, so nothing
    in the image says where an instruction begins, where one leaf ends, or where
    the next starts -- and every attempt here to infer a boundary was wrong in a
    different way:

    - Decoding a span as one stream from its first byte loses an island after an
      odd-length run of `0x00`, because `00 00` decodes as a two-byte
      `add byte ptr [rax], al` and the odd byte shifts everything after it.
    - Splitting at every `0xCC`/`0x00` byte cuts instructions apart: a single
      zero byte is not padding, and almost every RIP-relative load carries one
      in its high displacement byte.
    - Making each span one region restored the instructions and lost provenance,
      so a field access in one leaf was credited to another leaf's anchor load.
    - Ending an island at a padding byte on an instruction boundary fixed the
      padded case and left the unpadded one: two leaves emitted back to back
      have no padding between them, so they still collapsed -- and adding `ret`
      as a second boundary would split a real function with two return paths
      instead, dropping its tail.

    So boundaries are **not inferred at all** any more. The union maximises what
    is *found*, which is what a detector owes: decoding from the span start and
    from the first byte after every padding run, a leaf reachable by neither
    alignment is not reachable at all, and a leaf sitting immediately after a
    `ret` is still decoded because the previous start's stream runs into it.
    Because nothing here is a function, callers must not attribute one
    instruction in a span to another -- `main` reports gap spans in a section of
    their own, out of the per-function counts, for a human to read.

    Returns (instructions, refused_addresses); refusals are addresses so that a
    byte reached by two overlapping starts is counted once.
    """
    seen, refused = {}, []
    for s in sorted(set(starts)):
        if s >= len(blob) or blob[s] in (0xCC, 0x00):
            continue
        got, miss = decode_all(md, blob[s:], base + s)
        refused += miss
        for i in got:
            seen.setdefault((i.address, i.size), i)
    return [seen[k] for k in sorted(seen)], refused


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
    """Every `.pdata` function as (start, end, frame_reg), plus every executable
    span `.pdata` does not claim as (start, end, candidate_starts).

    They are returned **separately, and reported separately**, because they are
    different kinds of thing. A `.pdata` entry is a function: exact bounds, so an
    anchor load and a field access inside one are genuinely the same function's.
    A gap span is a run of bytes with no boundary information at all, so no
    grouping inside it means anything -- see `decode_span`.

    `.pdata` claims no leaf functions, so a leaf loading the array would be
    invisible to a scan that stopped at the table; `vid_field_census.py` decodes
    what the table leaves out and so does this.
    """
    pdata = [(s, e, frame_register(data, secs, u)) for s, e, u in funcs]
    claimed = sorted((s, e) for s, e, _ in funcs)
    gaps = []
    gap_bytes = pad_bytes = 0
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
            gaps.append((hs, he, tuple(starts)))
    return pdata, gaps, gap_bytes, pad_bytes


def why_reaching(ins, ref_rva, arr_rva):
    """Which of the two anchors these instructions reach, if either."""
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
    return why


def analyse(data, secs, md, pdata, ref_rva, arr_rva):
    """Which `.pdata` FUNCTIONS can hold a partition object, and why.

    Only `.pdata` entries, deliberately: a gap span is not a function, so asking
    whether "it" can hold a partition object has no answer to give. Gaps go
    through `analyse_gaps`.
    """
    reaching, bodies, framereg, refused = {}, {}, {}, set()
    for start, end, fr in pdata:
        off = rva_to_off(secs, start)
        if off is None:
            continue
        ins, miss = decode_all(md, data[off:off + (end - start)], start)
        refused.update(miss)
        bodies[start] = ins
        framereg[start] = fr
        why = why_reaching(ins, ref_rva, arr_rva)
        if why:
            reaching[start] = why
    return reaching, bodies, framereg, len(refused)


def analyse_gaps(data, secs, md, gaps, ref_rva, arr_rva, fields):
    """Per gap span: what it reaches and what field traffic it contains, with the
    two NOT correlated -- they are co-located in a span, nothing more.

    A span is reported when it reaches an anchor *or* touches a field, because
    either is a reason for a human to read it, and neither licenses a claim about
    the other."""
    out, refused = [], set()
    for start, end, starts in gaps:
        off = rva_to_off(secs, start)
        if off is None:
            continue
        ins, miss = decode_span(md, data[off:off + (end - start)], start, starts)
        refused.update(miss)
        why = why_reaching(ins, ref_rva, arr_rva)
        hits = field_hits({start: ins}, {}, start, fields)
        if why or hits:
            out.append((start, end, why, hits))
    return out, len(refused)


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


def _synthetic_image(text, claim=None):
    """A minimal PE32+ whose `.text` holds `text`.

    `.pdata` claims `claim` as (start, end), defaulting to a one-byte stub at the
    section start so that everything after it is a gap. Passing a real range is
    how the test checks that a *claimed* function still attributes, which is the
    control for the gap rules: they must differ."""
    body = bytearray(text)
    body += bytes([0xCC]) * (TEXT_SZ - len(body))
    lo, hi = claim if claim else (TEXT_VA, TEXT_VA + 1)
    pdata = struct.pack("<III", lo, hi, 0)
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


def _run(data, md, arr_rva, ref_rva=None):
    """Run both halves of the analysis over an in-memory image."""
    _, secs = sections(data)
    funcs = pdata_functions(data, secs)
    pdata, gaps, _, _ = regions_of(data, secs, funcs)
    ref = TEXT_VA if ref_rva is None else ref_rva
    reaching, bodies, framereg, _ = analyse(data, secs, md, pdata, ref, arr_rva)
    fn_accesses = sum(len(field_hits(bodies, framereg, s, [0x10, 0x18]))
                      for s in reaching)
    gap_hits, _ = analyse_gaps(data, secs, md, gaps, ref, arr_rva, [0x10, 0x18])
    return reaching, fn_accesses, gap_hits


def self_test():
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    results = []

    def check(name, got, want):
        results.append((name, got == want, got, want))

    def anchor_loads(ins_list):
        return sum(1 for i in ins_list
                   for op in i.operands
                   if op.type == capstone.x86.X86_OP_MEM
                   and op.mem.base == capstone.x86.X86_REG_RIP
                   and i.address + i.size + op.mem.disp == ANCHOR_VA)

    leaf_at = 0x1020
    leaf = _leaf(leaf_at, ANCHOR_VA)
    check("leaf is 12 bytes", len(leaf), 12)
    check("its displacement carries zero bytes", leaf.count(0), 2)

    # === DETECTION: the union must find a leaf under every alignment hazard ===

    # (A) a span cut at the first zero byte cannot yield the anchor load; the
    #     union over candidate starts must.
    cut, _ = decode_span(md, leaf[:leaf.index(0)], leaf_at, (0,))
    check("a span cut at the first zero byte loses the anchor load",
          anchor_loads(cut), 0)
    found, _ = decode_span(md, leaf, leaf_at, gap_decode_starts(leaf)[0])
    check("the union finds it", anchor_loads(found), 1)

    # (B) an island after an ODD-length 0x00 run is invisible to a single stream
    #     from the span start, because `00 00` is a two-byte add.
    second_at = leaf_at + len(leaf) + 3
    span_b = leaf + bytes(3) + _leaf(second_at, ANCHOR_VA)
    one_stream, _ = decode_all(md, span_b, leaf_at)
    check("one stream finds only the first", anchor_loads(one_stream), 1)
    union_b, _ = decode_span(md, span_b, leaf_at, gap_decode_starts(span_b)[0])
    check("the union finds both", anchor_loads(union_b), 2)

    # (C) a leaf immediately after a `ret`, with NO padding, gets no candidate
    #     start of its own -- the union still reaches it from the previous start.
    span_c = leaf + _field_leaf()
    union_c, _ = decode_span(md, span_c, leaf_at, gap_decode_starts(span_c)[0])
    check("an unpadded neighbour is still decoded",
          any("0x18" in i.op_str for i in union_c), True)

    # === ATTRIBUTION: it must never happen across a gap, padded or not ===
    # Both shapes below put an anchor-loading leaf and an unrelated +0x18-reading
    # leaf in one span. Three rounds of findings were each one of these being
    # credited to a single function. The rule now is that NEITHER is.
    for label, body, other in (
            ("padded", leaf + bytes([0xCC]) * 4 + _field_leaf(), leaf_at + 16),
            ("unpadded", leaf + _field_leaf(), leaf_at + 12)):
        img = _synthetic_image(bytes([0xCC]) * (leaf_at - TEXT_VA) + body)
        reaching, fn_accesses, gap_hits = _run(img, md, ANCHOR_VA)
        check("%s: no gap span is counted as a function" % label, len(reaching), 0)
        check("%s: no gap access reaches the per-function total" % label,
              fn_accesses, 0)
        check("%s: the span is reported for a human instead" % label,
              len(gap_hits), 1)
        why = gap_hits[0][2] if gap_hits else set()
        hits = gap_hits[0][3] if gap_hits else []
        check("%s: with the anchor it reaches" % label,
              why == {"loads WinHvpPartitionArray"}, True)
        check("%s: and both field accesses, uncorrelated" % label,
              sorted(a for a, _, _, _ in hits), [leaf_at + 7, other])

    # === a byte refused by two overlapping starts is counted once ===
    ov = leaf[:7] + bytes([0x0F])
    ov_starts, _ = gap_decode_starts(ov)
    each = [len(decode_all(md, ov[r:], leaf_at + r)[1])
            for r in ov_starts if ov[r] not in (0xCC, 0x00)]
    _, refused = decode_span(md, ov, leaf_at, ov_starts)
    check("two starts each refuse the same byte", each, [1, 1])
    check("and it is reported once", len(set(refused)), 1)

    # === a .pdata function still attributes, because its bounds are exact ===
    # The displacement is RVA-relative, so this leaf has to be assembled AT the
    # address it is placed at -- reusing the 0x1020 one here made the control fail
    # for a reason that had nothing to do with attribution.
    claimed_leaf = _leaf(TEXT_VA, ANCHOR_VA)
    fn = _synthetic_image(claimed_leaf + bytes([0xCC]) * 4,
                          claim=(TEXT_VA, TEXT_VA + len(claimed_leaf)))
    reaching, fn_accesses, gap_hits = _run(fn, md, ANCHOR_VA)
    check("a claimed function reaches", len(reaching), 1)
    check("and its own +0x10 read is attributed to it", fn_accesses, 1)
    check("and it is not reported as a gap", len(gap_hits), 0)

    # === controls: the assertions above must be able to fail ===
    bare = _synthetic_image(bytes([0xCC]) * (leaf_at - TEXT_VA) + leaf)
    _, _, blind = _run(bare, md, ANCHOR_VA + 8)
    check("an anchor the image does not load is not reached",
          [w for _, _, w, _ in blind], [set()])
    _, _, none = _run(_synthetic_image(bytes([0xCC]) * 32), md, ANCHOR_VA)
    check("an image with no leaf reports no span", none, [])

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

    pdata, gaps, gap_bytes, pad_bytes = regions_of(data, secs, funcs)
    reaching, bodies, framereg, fn_refused = analyse(
        data, secs, md, pdata, ref_rva, arr_rva)
    gap_hits, gap_refused = analyse_gaps(
        data, secs, md, gaps, ref_rva, arr_rva, fields)

    print("image                : %s" % a.image)
    print(".pdata functions     : %d (exact bounds, decoded whole)" % len(funcs))
    print("executable bytes .pdata does not claim: %d (%d of them 0xCC/0x00 padding); "
          "%d span(s) held anything else" % (gap_bytes, pad_bytes, len(gaps)))
    print("distinct bytes capstone refused, skipped and resumed past: %d in functions, "
          "%d in gap spans" % (fn_refused, gap_refused))
    print("functions that can hold a partition object: %d" % len(reaching))
    print()
    for start in sorted(reaching):
        print("  +0x%06X  (%s)" % (start, ", ".join(sorted(reaching[start]))))
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

    # Gap spans are reported apart and are NOT added to the total above. A span
    # has no boundary information, so an anchor load and a field access in one
    # are co-located and nothing more -- grouping them as a function is the
    # defect three review rounds kept finding. Anything listed here is for a
    # human to disassemble; an empty list is the negative the census needs.
    print()
    print("=== gap spans `.pdata` does not claim: co-located findings, NOT attributed ===")
    if not gap_hits:
        print("  none: no span reaches an anchor or touches %s"
              % ", ".join("+0x%X" % f for f in fields))
    for start, end, why, hits in gap_hits:
        print("  span +0x%06X..+0x%06X" % (start, end))
        if why:
            print("      reaches: %s" % ", ".join(sorted(why)))
        for addr, rw, mn, ops in hits:
            print("      +0x%06X  [%-2s]  %s %s" % (addr, rw, mn, ops))
        print("      ^ boundaries unknown: read this span by hand before "
              "treating any of the above as one function")


if __name__ == "__main__":
    main()
