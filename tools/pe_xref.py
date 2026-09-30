"""Every place in a PE image that can reach a given RVA, by decoding.

`FOLLOWUPS.md` item 103, step 9. That step asks how the root partition's
`Vid.sys` can be *instrumented* to say whether an intercept message is delivered
at all, and the answer it reaches -- read the state `Vid!VidInterceptPreprocess`
leaves in the per-VP structure, rather than patch the function or break on it --
is only worth anything if that state is on the path of every arrival the
question is about. That is a **negative** over a whole image: *nothing else
reaches `Vid!VidHandleExceptionIntercept`*. A negative needs a sound reading, so
it is decoded rather than searched for.

**Why a byte search is the wrong instrument here, in both directions.** A `call`
or a `jmp` to a function encodes a *relative* displacement that depends on where
the instruction sits, so there is no byte pattern to look for; and the four
bytes of a function's image-based address appear in immediates, in unrelated
displacements and in data that is not a pointer, so a search for them reports
sites that cannot transfer control anywhere. `tools/vid_field_census.py` records
the same two failures for a struct field and this is the call-target form of it.

**What is decoded, and what that licenses.** A `.pdata` entry is a function with
exact bounds, so a reference found inside one is attributed to it by name. The
executable bytes `.pdata` does not claim carry no boundary information at all --
no unwind record says where an instruction begins -- so a gap run is decoded as
a DETECTOR: the union over every start in the run, which maximises what is found
and claims nothing about which function found it. Gap hits are reported
separately and labelled, because a misaligned start decodes bytes that are not
instructions and can manufacture a reference that is not there. That direction
is the safe one for a negative: the union can only widen the set, so an empty
gap section is a measurement rather than an artefact of one reading.

**Two data encodings are searched as well**, in EVERY section including the
executable ones, because a function reached from a table is reached without any
instruction naming it: the 8-byte image-based VA (a function pointer, which
carries a base relocation) and the 4-byte RVA (the form
`Vid!VidInterceptPreprocess`'s own type switch uses -- `mov eax,[rdx+rax*4+X];
add rax,rdx; jmp rax`). Both are byte searches and are reported as such: they
are here to keep a negative honest, not to attribute anything. A hit in a code
section is labelled rather than suppressed, because those bytes may be a table
entry or may be an instruction and only reading the span settles it -- and
suppressing them, which the first version of this did, blinded BOTH halves at
once for a dispatch table living in `.text`: an indirect call through a
RIP-relative slot names the slot, so the decoder cannot recover the target
either.

**What it does not see.** This list is the whole of it, enumerated in one pass
rather than a line at a time, because review round 1 on #425 filed four findings
that were each one omission from it:

1. **A target computed at run time** -- an address assembled over two
   instructions, arriving as an argument, or read from a table in any encoding
   other than the two above.
2. **A branch into the middle of the target.** RVAs are matched exactly, so
   `call target+0x10` is not reported for `target`.
3. **A gap-run instruction no candidate start decodes as one instruction.** The
   union over starts makes this unlikely rather than impossible.
4. **Bytes present at run time but not in the file** -- a section whose
   `SizeOfRawData` is shorter than its virtual size has an uninitialised tail
   that is not read here.
5. **Anything in another image.** This reads one file.

Items 1 and 5 are the ones that actually bite. What used to be on this list and
is not any more: sections were selected by NAME, so an executable section called
anything unexpected had its gap bytes skipped in silence -- now they are selected
by `IMAGE_SCN_MEM_EXECUTE`, which is the property the question is about.

So "0 references" means "no instruction in this image names it, and no section of
it holds its address in either of the two searched forms" -- which is what a
reachability claim scoped to one file can be, and is NOT "nothing else calls it".
A reader turning this into a statement about reachability has to say which of the
five above they ruled out by other means.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import struct
import sys
from dataclasses import dataclass, field

try:
    import capstone
    from capstone import x86
except ImportError:  # pragma: no cover - reported, not raised
    capstone = None
    x86 = None

# Which sections hold code is read from each section's own characteristics, not
# from its name. A name list is a hand-maintained inventory of an open set --
# `Vid.sys` alone ships `NONPAGED`, `PAGE`, `PAGED`, `INIT` and `fothk` beside
# `.text` -- and the first image with a name not on it would have its gap bytes
# skipped in silence, which turns this tool's whole output into a negative taken
# without looking. Review round 1 on #425 named that from both bots.
IMAGE_SCN_MEM_EXECUTE = 0x20000000

PADDING = (0x00, 0xCC)

# Two sections hold a function's RVA as part of the image's own structure
# rather than as a dispatch table, so a hit in either transfers control
# nowhere. They are labelled rather than filtered: a real table can live
# anywhere, and a reader who does not see them cannot tell that they were
# considered.
STRUCTURAL = {
    ".pdata": "  -- its own RUNTIME_FUNCTION, not a dispatch table",
    "GFIDS": "  -- the CFG indirect-call target list, not a dispatch table",
}


@dataclass
class Section:
    name: str
    va: int
    vsize: int
    raw: int
    rawsize: int
    characteristics: int = 0

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & IMAGE_SCN_MEM_EXECUTE)


@dataclass
class Image:
    data: bytes
    sections: list[Section]
    image_base: int
    pdata: list[tuple[int, int]] = field(default_factory=list)

    def rva_to_off(self, rva: int) -> int | None:
        for s in self.sections:
            if s.va <= rva < s.va + max(s.vsize, s.rawsize):
                delta = rva - s.va
                return s.raw + delta if delta < s.rawsize else None
        return None

    def read(self, rva: int, n: int) -> bytes | None:
        off = self.rva_to_off(rva)
        return None if off is None else self.data[off : off + n]


@dataclass
class Ref:
    rva: int
    mnemonic: str
    text: str
    target: int
    where: str  # a `.pdata` function name, or "" for a gap hit
    exact: bool  # True for a `.pdata` attribution, False for a gap detection


def load(path: str) -> Image:
    with open(path, "rb") as fh:
        data = fh.read()
    if data[:2] != b"MZ":
        raise ValueError("not a PE image")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        raise ValueError("no PE signature")
    coff = e_lfanew + 4
    (nsec,) = struct.unpack_from("<H", data, coff + 2)
    (opt_size,) = struct.unpack_from("<H", data, coff + 16)
    opt = coff + 20
    (magic,) = struct.unpack_from("<H", data, opt)
    if magic != 0x20B:
        raise ValueError("only PE32+ (x64) images are supported")
    (image_base,) = struct.unpack_from("<Q", data, opt + 24)
    exc_rva, exc_size = struct.unpack_from("<II", data, opt + 112 + 3 * 8)

    sec_off = opt + opt_size
    sections = []
    for i in range(nsec):
        base = sec_off + i * 40
        name = data[base : base + 8].rstrip(b"\0").decode("latin-1")
        vsize, va, rawsize, raw = struct.unpack_from("<IIII", data, base + 8)
        (chars,) = struct.unpack_from("<I", data, base + 36)
        sections.append(Section(name, va, vsize, raw, rawsize, chars))

    img = Image(data, sections, image_base)
    if exc_rva and exc_size:
        blob = img.read(exc_rva, exc_size)
        if blob:
            for off in range(0, len(blob) - 11, 12):
                begin, end, _unwind = struct.unpack_from("<III", blob, off)
                if begin and end > begin:
                    img.pdata.append((begin, end))
    return img


def load_symbols(path: str, image_base: int) -> dict[int, str]:
    """Read a `x Mod!*` dump: an address column, then the symbol name."""
    syms: dict[int, str] = {}
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            parts = line.split()
            if len(parts) < 2:
                continue
            addr = parts[0].replace("`", "")
            try:
                va = int(addr, 16)
            except ValueError:
                continue
            name = parts[1]
            if "!" not in name:
                continue
            syms.setdefault(va - image_base, name.split("!", 1)[1])
    return syms


def name_for(rva: int, syms: dict[int, str]) -> str:
    if rva in syms:
        return syms[rva]
    best = max((s for s in syms if s <= rva), default=None)
    return f"{syms[best]}+0x{rva - best:x}" if best is not None else f"sub_{rva:x}"


def gap_runs(img: Image) -> list[tuple[int, int]]:
    """Maximal runs of executable bytes `.pdata` does not claim, padding-only
    runs dropped. A run's boundaries are known; nothing inside it is."""
    runs: list[tuple[int, int]] = []
    for s in img.sections:
        if not s.executable:
            continue
        end = min(s.vsize, s.rawsize)
        marks = bytearray(end)
        for beg, fin in img.pdata:
            if s.va <= beg < s.va + end:
                for i in range(beg - s.va, min(fin - s.va, end)):
                    marks[i] = 1
        i = 0
        while i < end:
            if marks[i]:
                i += 1
                continue
            j = i
            while j < end and not marks[j]:
                j += 1
            blob = img.data[s.raw + i : s.raw + j]
            if any(b not in PADDING for b in blob):
                runs.append((s.va + i, s.va + j))
            i = j
    return runs


def targets_of(insn, image_base: int) -> list[int]:
    """Every RVA this one instruction names: a relative branch's destination,
    and any RIP-relative operand's address (which covers `lea` taking a
    function's address and a load through a pointer that happens to sit there)."""
    out = []
    if insn.group(x86.X86_GRP_CALL) or insn.group(x86.X86_GRP_JUMP):
        for op in insn.operands:
            if op.type == x86.X86_OP_IMM:
                out.append(op.imm - image_base)
    for op in insn.operands:
        if op.type == x86.X86_OP_MEM and op.mem.base == x86.X86_REG_RIP:
            out.append(insn.address + insn.size + op.mem.disp - image_base)
    return out


def scan(img: Image, wanted: set[int], syms: dict[int, str]) -> tuple[list[Ref], dict]:
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    refs: list[Ref] = []
    for beg, end in img.pdata:
        blob = img.read(beg, end - beg)
        if not blob:
            continue
        for insn in md.disasm(blob, img.image_base + beg):
            for t in targets_of(insn, img.image_base):
                if t in wanted:
                    rva = insn.address - img.image_base
                    # Named from the instruction, not from the `.pdata` entry:
                    # a function with chained unwind info has several entries,
                    # and naming the entry start reports an offset into an
                    # offset. The entry is printed beside it.
                    refs.append(
                        Ref(rva, insn.mnemonic, f"{insn.mnemonic} {insn.op_str}", t,
                            f"{name_for(rva, syms)}  [.pdata entry 0x{beg:x}]", True)
                    )

    runs = gap_runs(img)
    starts = 0
    for beg, end in runs:
        blob = img.read(beg, end - beg)
        if not blob:
            continue
        for k in range(len(blob)):
            starts += 1
            # ONE instruction, from a window of the longest an x86-64
            # instruction can be. That is the same union as decoding to the end
            # of the run from every start, because any instruction such a pass
            # would reach begins at an offset that is itself a start -- and it
            # is linear rather than quadratic, which is what a run of tens of
            # thousands of bytes needs. Verified as a differential against the
            # quadratic version on `Vid.sys` and `winhvr.sys` before the change
            # was kept, not reasoned about alone.
            for insn in md.disasm(blob[k : k + 15], img.image_base + beg + k, count=1):
                for t in targets_of(insn, img.image_base):
                    if t in wanted:
                        refs.append(
                            Ref(insn.address - img.image_base, insn.mnemonic,
                                f"{insn.mnemonic} {insn.op_str}", t, "", False)
                        )

    # Every section, including the executable ones. Suppressing those was
    # wrong in the direction that matters here: an indirect call through a
    # RIP-relative slot names the *slot*, so `targets_of` cannot recover the
    # function, and a dispatch table sitting in a code section would have been
    # invisible to both halves of this tool at once. Code hits are labelled as
    # possibly instruction bytes rather than hidden -- a four-byte pattern in a
    # megabyte of code is often just code, and saying so is the reader's job to
    # finish, not this tool's to pre-empt.
    data_hits = []
    for w in sorted(wanted):
        for s in img.sections:
            blob = img.data[s.raw : s.raw + s.rawsize]
            for pat, kind in (
                ((img.image_base + w).to_bytes(8, "little"), "VA (8 bytes)"),
                (w.to_bytes(4, "little"), "RVA (4 bytes)"),
            ):
                i = blob.find(pat)
                while i != -1:
                    data_hits.append((s.name, s.va + i, kind, w, s.executable))
                    i = blob.find(pat, i + 1)

    return refs, {
        "functions": len(img.pdata),
        "gap_runs": len(runs),
        "gap_starts": starts,
        "data": data_hits,
    }


def report(refs: list[Ref], extra: dict, wanted: set[int], syms: dict[int, str]) -> None:
    for w in sorted(wanted):
        mine = [r for r in refs if r.target == w]
        exact = [r for r in mine if r.exact]
        gaps = [r for r in mine if not r.exact]
        print(f"=== 0x{w:x} {name_for(w, syms)}: {len(exact)} in .pdata code, "
              f"{len(gaps)} in gap runs")
        for r in exact:
            print(f"  0x{r.rva:06x}  {r.where}   {r.text}")
        if gaps:
            for r in gaps:
                print(f"  0x{r.rva:06x}  [OUTSIDE .pdata -- boundaries unknown, "
                      f"read this span by hand]   {r.text}")
        else:
            print("  gap runs: none reaches it")
        rows = [d for d in extra["data"] if d[3] == w]
        if rows:
            for name, rva, kind, _w, is_exec in rows:
                note = STRUCTURAL.get(name, "")
                if not note and is_exec:
                    note = ("  -- in an executable section: these bytes may be a "
                            "table entry or may be an instruction; read the span")
                print(f"  stored: {name} rva 0x{rva:x} holds its {kind}{note}")
        else:
            print("  stored VA/RVA: none in any section")
    print(
        f"{extra['functions']} .pdata functions; {extra['gap_starts']} candidate "
        f"starts in {extra['gap_runs']} non-padding gap run(s)"
    )


def parse_targets(spec: str) -> set[int]:
    """`0x`-prefixed is hex, bare is decimal -- `int(x, 0)`, the same rule
    `vid_field_census.py --fields` uses, so the two tools do not read the same
    string two ways. The first version of this took a bare value as hex while
    its own `--help` said "hex or decimal", which makes a wrong destination look
    like a clean negative."""
    return {int(t, 0) for t in spec.split(",") if t.strip()}


def _img(text: bytes, base: int = 0x140000000, claim=None, data: bytes = b"",
         code_name: str = ".text") -> Image:
    """A synthetic image: one executable section at rva 0x1000, one read-only
    data section at 0x8000, and whatever `.pdata` claims (by default the whole
    code section). `code_name` exists so a case can give the code section a
    name no list would guess."""
    secs = [
        Section(code_name, 0x1000, len(text), 0x400, len(text), IMAGE_SCN_MEM_EXECUTE),
        Section(".rdata", 0x8000, len(data), 0x400 + len(text), len(data), 0x40000040),
    ]
    img = Image(b"\0" * 0x400 + text + data, secs, base)
    img.pdata = [(0x1000, 0x1000 + len(text))] if claim is None else list(claim)
    return img


TOTAL = 15

# Mutation-verified, so the cases below share one denominator and none of them
# is passing for a reason unrelated to the rule it names. Backing each of these
# out of the code above, every one applied and every one was caught:
#
#   gap union -> a single start                      13/15
#   decode window shrunk below one instruction       11/15
#   sections selected by name again                  14/15
#   the data scan skips executable sections again    13/15
#   every immediate counts as a branch target        14/15
#   gap hits attributed as `.pdata` hits             11/15
#   padding-only runs kept as runs                   14/15
#   `--targets` reads a bare value as hex            14/15
#
# Two of those earn the comment. The immediate case's FIRST version used
# `mov eax,0x40001000`, whose immediate is a *neighbouring* number rather than
# the target's VA, so it scored a clean sheet under the very mutation it existed
# for -- a case that cannot fail is pinning nothing. And `report` is rendered
# into a sink for every case above, because the counts come from `scan` and
# without that the printing path was never run by the self-test: the round-1 fix
# crashed there, on a tuple that had grown a field, while still reporting 15/15.


def self_test() -> int:
    failures = 0

    def case(label, img, wanted, want_exact, want_gap, want_data, want_runs=None):
        nonlocal failures
        refs, extra = scan(img, wanted, {})
        # Render every case through `report` as well, into nothing. The counts
        # below are computed from `scan`, so without this the printing path is
        # never executed by the self-test -- and it was exactly there that the
        # first version of the round-1 fix crashed, on a tuple that had grown a
        # field, with 15/15 still reported.
        with contextlib.redirect_stdout(io.StringIO()):
            report(refs, extra, wanted, {})
        got = (len([r for r in refs if r.exact]),
               len([r for r in refs if not r.exact]),
               len(extra["data"]))
        want = (want_exact, want_gap, want_data)
        if want_runs is not None:
            got += (extra["gap_runs"],)
            want += (want_runs,)
        ok = got == want
        shape = "exact/gap/data" + ("/runs" if want_runs is not None else "")
        print(f"  {'ok  ' if ok else 'FAIL'} {label}: "
              f"{'/'.join(str(g) for g in got)} {shape} "
              f"(wanted {'/'.join(str(w) for w in want)})")
        failures += int(not ok)

    # 0x1000 is the code section's start, so a `call` from 0x1005 to 0x1000 is
    # rel32 -0xa.  The tool must find it from the displacement, not from bytes.
    call_back = b"\x90" * 5 + b"\xe8\xf6\xff\xff\xff"  # call 0x140001000
    case("call rel32 to the target", _img(call_back), {0x1000}, 1, 0, 0)

    jmp_back = b"\x90" * 5 + b"\xe9\xf6\xff\xff\xff"  # jmp 0x140001000
    case("jmp rel32 to the target", _img(jmp_back), {0x1000}, 1, 0, 0)

    # lea rax,[rip-0xc] at 0x1005 -> 0x1000: taking the address is how a
    # function reaches a dispatch slot, which is the case step 9 turns on.
    lea = b"\x90" * 5 + b"\x48\x8d\x05\xf4\xff\xff\xff"
    case("lea rip-relative to the target", _img(lea), {0x1000}, 1, 0, 0)

    # The byte-scan trap, and the one case that must not regress: the target's
    # full VA appears as an immediate, which transfers control nowhere.
    # `movabs rax,0x140001000` -- 48 b8 00 10 00 40 01 00 00 00.  The immediate
    # is the VA and not some neighbouring number, or the case would pass under
    # a reading that counts every immediate: mutation-checked, and the first
    # version of it (`mov eax,0x40001000`) did exactly that.  It draws one
    # *stored* hit, because the byte scan sees the same eight bytes and says so
    # rather than deciding for the reader -- that is the shape of every
    # code-section stored hit and the reason they are labelled.
    case("an immediate is not a reference, and is reported as bytes",
         _img(b"\x48\xb8\x00\x10\x00\x40\x01\x00\x00\x00"), {0x1000}, 0, 0, 1)

    # A reference the relative encoding hides from any byte search: the same
    # destination from two call sites encodes two different displacements.
    two = b"\xe8\x0b\x00\x00\x00" + b"\x90" * 6 + b"\xe8\x00\x00\x00\x00" + b"\xc3"
    case("two calls to one target encode differently", _img(two), {0x1010}, 2, 0, 0)

    # A gap: `.pdata` claims only the first 5 bytes, and the call sits after it.
    case("a reference outside .pdata is detected, not attributed",
         _img(call_back, claim=[(0x1000, 0x1005)]), {0x1000}, 0, 1, 0)

    # ...and a padding-only gap is not decoded at all, so it cannot manufacture
    # one.  0xCC and 0x00 are the two the linker emits.  The run count is
    # asserted rather than the hit count, because a run of `int3` decodes to no
    # reference under either reading and a case that passes that way would be
    # pinning nothing.
    case("a padding-only gap is not a run at all",
         _img(b"\x90" * 5 + b"\xcc" * 8, claim=[(0x1000, 0x1005)]),
         {0x1000}, 0, 0, 0, want_runs=0)

    # The other half of that rule, and the one it would be easy to break while
    # fixing the first: a run that is mostly padding but holds a real reference
    # is still decoded.
    mostly = b"\x90" * 5 + b"\xcc" * 8 + b"\xe8\xee\xff\xff\xff"
    case("a mostly-padding gap holding a call is still decoded",
         _img(mostly, claim=[(0x1000, 0x1005)]), {0x1000}, 0, 1, 0, want_runs=1)

    # Data: an 8-byte pointer and a 4-byte RVA, the two encodings a table uses.
    case("a stored VA in a data section is reported",
         _img(b"\x90" * 8, data=(0x140001000).to_bytes(8, "little")), {0x1000}, 0, 0, 1)
    case("a stored RVA in a data section is reported",
         _img(b"\x90" * 8, data=(0x1000).to_bytes(4, "little")), {0x1000}, 0, 0, 1)

    # A dispatch table inside a code section is the case the first version of
    # this tool could not see at all: an indirect call through a RIP-relative
    # slot names the slot, so the code scan cannot recover the target, and
    # suppressing code sections in the byte scan hid the table as well. Both
    # halves blind at once is the one way a negative here can be badly wrong.
    case("a stored RVA in an executable section is reported",
         _img(b"\x90" * 4 + (0x1000).to_bytes(4, "little")), {0x1000}, 0, 0, 1)

    # Section *names* are an open set -- `Vid.sys` ships five beside `.text` --
    # so a gap in a section this tool has never heard of must still be decoded.
    case("an executable section with an unknown name is still scanned",
         _img(call_back, claim=[(0x1000, 0x1005)], code_name="WHOKNOWS"),
         {0x1000}, 0, 1, 0, want_runs=1)

    # A gap run whose only decode as one instruction needs a start the naive
    # reading would not pick: the run begins with a stray byte, so a single
    # pass from the span start shifts every instruction after it.  The union
    # over starts is what finds the call; this is the case that mutation-checks
    # `scan`'s inner `for k in range(len(blob))`.
    stray = b"\x90" * 5 + b"\x00" + b"\xe8\xf5\xff\xff\xff"
    case("a gap reference reachable only from a later start",
         _img(stray, claim=[(0x1000, 0x1005)]), {0x1000}, 0, 1, 0)

    # An unrelated target is not reported for any of the shapes above, which is
    # what makes the zeros elsewhere mean something.
    case("an unrelated RVA draws nothing", _img(call_back), {0x2000}, 0, 0, 0)

    # `--targets` reads the same way `vid_field_census.py --fields` does, which
    # is what its own `--help` says: bare is decimal, `0x` is hex. Taking a
    # bare value as hex scans a destination the caller did not name and reports
    # the clean negative that follows.
    decimal, hexed = parse_targets("4096"), parse_targets("0x4096")
    ok = decimal == {0x1000} and hexed == {0x4096}
    print(f"  {'ok  ' if ok else 'FAIL'} --targets: 4096 -> "
          f"{[hex(g) for g in decimal]}, 0x4096 -> {[hex(g) for g in hexed]}")
    failures += int(not ok)

    print(f"{'PASS' if not failures else 'FAIL'}: "
          f"{TOTAL - failures}/{TOTAL} cases")
    return 1 if failures else 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--image", help="PE image to scan")
    ap.add_argument("--symbols", help="an `x Mod!*` dump, for function names")
    ap.add_argument("--targets", help="comma-separated RVAs, hex or decimal")
    ap.add_argument("--self-test", action="store_true", help="run the self-test")
    args = ap.parse_args(argv[1:])

    if capstone is None:
        print("capstone is required: pip install capstone", file=sys.stderr)
        return 2
    if args.self_test:
        return self_test()
    if not args.image or not args.targets:
        ap.error("--image and --targets are required unless --self-test")

    img = load(args.image)
    syms = load_symbols(args.symbols, img.image_base) if args.symbols else {}
    wanted = parse_targets(args.targets)
    refs, extra = scan(img, wanted, syms)
    report(refs, extra, wanted, syms)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
