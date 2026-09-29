"""Census every instruction that touches a given structure field, by decoding.

Written for `FOLLOWUPS.md` item 103's S5 line, where the question is *who writes*
`[partition+0x3060]` and `[partition+0x3079]` in `Vid.sys` -- the two fields the
VID create path tests before it will hand a second process a partition handle.

**Why this exists rather than a byte scan.** The obvious search is for the
displacement bytes (`60 30 00 00`), and it is wrong in both directions. It finds
them in immediates, in relative offsets and in data, none of which are memory
operands at all; and a `s -d` style search that scans dword-aligned misses every
occurrence whose displacement does not land on a 4-byte boundary -- which in
x86-64 is most of them, since the displacement sits after a variable-length
opcode and ModRM. The first attempt at this census used exactly that and its
site list was incomplete without saying so.

So this decodes. It walks the image's own function table (`.pdata`, which is
exact on x86-64 and needs no symbols), disassembles each function, and reports
only instructions with a real memory operand at the displacement asked for --
with capstone's own read/write classification rather than a guess from the
mnemonic, and with `lea` reported separately, because taking a field's address
is how a write can happen somewhere this census would otherwise never look.

It does not know what a partition object is, and cannot: a displacement is a
number, and several unrelated `Vid` structures have fields at these offsets. What
it reports instead is the **displacement fingerprint** of each base register in
each hit's function -- the other offsets reached off the same pointer -- which is
what lets a reader tell a partition from a memory block by hand.
"""

from __future__ import annotations

import argparse
import struct
import sys
from dataclasses import dataclass, field

try:
    import capstone
except ImportError:  # pragma: no cover - the message is the whole value here
    sys.exit(
        "capstone is required: py -m pip install capstone\n"
        "Note it is a native extension, so run this from the repo rather than a "
        "scratchpad directory."
    )


@dataclass
class Section:
    name: str
    va: int
    vsize: int
    raw: int
    rawsize: int


@dataclass
class Hit:
    rva: int
    func_rva: int
    func_name: str
    mnemonic: str
    text: str
    base: str
    disp: int
    kind: str  # "write", "read", "readwrite" or "lea"


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
                if delta < s.rawsize:
                    return s.raw + delta
                return None
        return None

    def read(self, rva: int, n: int) -> bytes | None:
        off = self.rva_to_off(rva)
        if off is None:
            return None
        return self.data[off : off + n]


def load(path: str) -> Image:
    with open(path, "rb") as fh:
        data = fh.read()
    if data[:2] != b"MZ":
        raise ValueError("not a PE image")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        raise ValueError("no PE signature")
    coff = e_lfanew + 4
    nsec, = struct.unpack_from("<H", data, coff + 2)
    opt_size, = struct.unpack_from("<H", data, coff + 16)
    opt = coff + 20
    magic, = struct.unpack_from("<H", data, opt)
    if magic != 0x20B:
        raise ValueError("only PE32+ (x64) images are supported")
    image_base, = struct.unpack_from("<Q", data, opt + 24)
    # The data directory follows the 112-byte PE32+ optional-header prefix.
    dd = opt + 112
    exc_rva, exc_size = struct.unpack_from("<II", data, dd + 3 * 8)

    sec_off = opt + opt_size
    sections = []
    for i in range(nsec):
        base = sec_off + i * 40
        name = data[base : base + 8].rstrip(b"\0").decode("latin-1")
        vsize, va, rawsize, raw = struct.unpack_from("<IIII", data, base + 8)
        sections.append(Section(name, va, vsize, raw, rawsize))

    img = Image(data, sections, image_base)

    # .pdata: RUNTIME_FUNCTION[] of {BeginAddress, EndAddress, UnwindInfo}, all RVAs.
    if exc_rva and exc_size:
        blob = img.read(exc_rva, exc_size)
        if blob:
            for off in range(0, len(blob) - 11, 12):
                begin, end, _unwind = struct.unpack_from("<III", blob, off)
                if begin and end > begin:
                    img.pdata.append((begin, end))
    return img


def load_symbols(path: str, image_base: int) -> dict[int, str]:
    """Read a `x Vid!*` dump: an address column, then the symbol name.

    Addresses are WinDbg's `00000001`40008d20` form or plain hex, and are
    turned into RVAs by subtracting the image base the engine loaded the PE
    target at -- which for a PE-as-target is its preferred base, so the image's
    own header is the authority. Masking the low 32 bits instead is wrong and
    silently so: `0x1400a54d0 & 0xFFFFFFFF` is `0x400a54d0`, which resolves
    nothing and reports every function as `sub_...`.

    Lines that are not symbol rows are skipped rather than fatal, because the
    dump carries headers and `= <no type information>` rows.
    """
    syms: dict[int, str] = {}
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            parts = line.split()
            if len(parts) < 2:
                continue
            addr = parts[0].replace("`", "")
            try:
                value = int(addr, 16)
            except ValueError:
                continue
            name = parts[1]
            if "!" not in name:
                continue
            rva = value - image_base
            if 0 <= rva < (1 << 32):
                syms.setdefault(rva, name.split("!", 1)[1])
    return syms


def name_for(func_rva: int, syms: dict[int, str]) -> str:
    return syms.get(func_rva, "")


ACCESS = {
    (True, False): "read",
    (False, True): "write",
    (True, True): "readwrite",
}


def census(img: Image, wanted: set[int], syms: dict[int, str]) -> tuple[list[Hit], dict]:
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    hits: list[Hit] = []
    # base register -> displacements seen, per function, for the fingerprint.
    prints: dict[tuple[int, str], set[int]] = {}
    stats = {"functions": 0, "instructions": 0, "undecodable": 0}

    for begin, end in img.pdata:
        code = img.read(begin, end - begin)
        if not code:
            continue
        stats["functions"] += 1
        decoded = list(md.disasm(code, img.image_base + begin))
        stats["instructions"] += len(decoded)
        consumed = sum(i.size for i in decoded)
        if consumed < len(code):
            stats["undecodable"] += 1
        for ins in decoded:
            rva = ins.address - img.image_base
            for op in ins.operands:
                if op.type != capstone.x86.X86_OP_MEM:
                    continue
                base_reg = op.mem.base
                if base_reg == 0 or base_reg == capstone.x86.X86_REG_RIP:
                    continue
                base = ins.reg_name(base_reg)
                disp = op.mem.disp
                if disp > 0:
                    prints.setdefault((begin, base), set()).add(disp)
                if disp not in wanted:
                    continue
                if ins.mnemonic == "lea":
                    kind = "lea"
                else:
                    kind = ACCESS.get(
                        (
                            bool(op.access & capstone.CS_AC_READ),
                            bool(op.access & capstone.CS_AC_WRITE),
                        ),
                        "unknown",
                    )
                hits.append(
                    Hit(
                        rva=rva,
                        func_rva=begin,
                        func_name=name_for(begin, syms),
                        mnemonic=ins.mnemonic,
                        text=f"{ins.mnemonic} {ins.op_str}",
                        base=base,
                        disp=disp,
                        kind=kind,
                    )
                )
    return hits, {"stats": stats, "prints": prints}


def report(hits: list[Hit], extra: dict, wanted: set[int]) -> None:
    stats = extra["stats"]
    prints = extra["prints"]
    print(
        f"decoded {stats['instructions']} instructions in {stats['functions']} "
        f"functions from .pdata ({stats['undecodable']} with an undecodable tail)"
    )
    for disp in sorted(wanted):
        rows = [h for h in hits if h.disp == disp]
        writes = [h for h in rows if h.kind in ("write", "readwrite")]
        leas = [h for h in rows if h.kind == "lea"]
        print(f"\n=== +0x{disp:X}: {len(rows)} accesses, {len(writes)} writing, "
              f"{len(leas)} address-taken")
        for h in sorted(rows, key=lambda r: r.rva):
            mark = {"write": "W", "readwrite": "RW", "lea": "&", "read": " "}.get(h.kind, "?")
            who = h.func_name or f"sub_{h.func_rva:x}"
            fp = sorted(prints.get((h.func_rva, h.base), set()))
            near = [f"0x{d:X}" for d in fp if d != disp][:12]
            print(f"  [{mark:>2}] {h.rva:#08x} {who}+{h.rva - h.func_rva:#x}")
            print(f"       {h.text}")
            print(f"       base {h.base} also at: {', '.join(near) if near else '(nothing else)'}")


# --- self-test -------------------------------------------------------------
#
# The bytes are real ones read out of Vid.sys 10.0.26100.9278 during S5o, so a
# pass means the decoder agrees with what the debugger showed for the same
# instructions -- not merely that it is internally consistent.

SELF_TEST = [
    # (bytes, expected kind, expected disp, expected base)
    (b"\xc6\x83\x79\x30\x00\x00\x01", "write", 0x3079, "rbx"),  # mov byte [rbx+3079h],1
    (b"\x83\xbb\x60\x30\x00\x00\x02", "read", 0x3060, "rbx"),   # cmp dword [rbx+3060h],2
    (b"\x80\xbb\x79\x30\x00\x00\x00", "read", 0x3079, "rbx"),   # cmp byte [rbx+3079h],0
    (b"\x40\x38\xb8\x79\x30\x00\x00", "read", 0x3079, "rax"),   # cmp byte [rax+3079h],dil
    (b"\x48\x8d\x8b\x79\x30\x00\x00", "lea", 0x3079, "rbx"),    # lea rcx,[rbx+3079h]
    (b"\x83\xb8\x60\x30\x00\x00\x02", "read", 0x3060, "rax"),   # cmp dword [rax+3060h],2
]


def self_test() -> int:
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    failures = 0
    for code, want_kind, want_disp, want_base in SELF_TEST:
        ins = next(iter(md.disasm(code, 0x140000000)), None)
        if ins is None or ins.size != len(code):
            print(f"  FAIL {code.hex()}: did not decode as one instruction")
            failures += 1
            continue
        mem = [o for o in ins.operands if o.type == capstone.x86.X86_OP_MEM]
        if not mem:
            print(f"  FAIL {code.hex()}: no memory operand")
            failures += 1
            continue
        op = mem[0]
        base = ins.reg_name(op.mem.base)
        kind = (
            "lea"
            if ins.mnemonic == "lea"
            else ACCESS.get(
                (bool(op.access & capstone.CS_AC_READ), bool(op.access & capstone.CS_AC_WRITE)),
                "unknown",
            )
        )
        ok = kind == want_kind and op.mem.disp == want_disp and base == want_base
        print(
            f"  {'ok  ' if ok else 'FAIL'} {ins.mnemonic} {ins.op_str}"
            f"  -> {kind} +0x{op.mem.disp:X} base {base}"
        )
        if not ok:
            failures += 1

    # A byte scan would find this displacement; a decoder must not, because the
    # bytes are an immediate rather than a memory operand. This is the whole
    # reason the tool exists, so it is the one case that must not regress.
    ins = next(iter(md.disasm(b"\xb8\x60\x30\x00\x00", 0x140000000)), None)  # mov eax,3060h
    bad = ins is not None and any(
        o.type == capstone.x86.X86_OP_MEM and o.mem.disp == 0x3060 for o in ins.operands
    )
    print(f"  {'FAIL' if bad else 'ok  '} mov eax,3060h is not a memory access")
    failures += int(bad)

    total = len(SELF_TEST) + 1
    print(f"\n  {total - failures}/{total} passed")
    return 1 if failures else 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--image", help="PE image to census")
    ap.add_argument("--symbols", help="a `x Mod!*` dump for function names")
    ap.add_argument(
        "--fields",
        default="0x3060,0x3064,0x3079",
        help="comma-separated displacements, hex or decimal",
    )
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()
    if not args.image:
        ap.error("--image is required unless --self-test")

    wanted = {int(f, 0) for f in args.fields.split(",") if f.strip()}
    img = load(args.image)
    syms = load_symbols(args.symbols, img.image_base) if args.symbols else {}
    hits, extra = census(img, wanted, syms)
    report(hits, extra, wanted)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
