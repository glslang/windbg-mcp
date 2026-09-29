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
    flags: int = 0


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
        flags, = struct.unpack_from("<I", data, base + 36)
        sections.append(Section(name, va, vsize, raw, rawsize, flags))

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


# Volatile registers: a call may clobber them, so an alias held in one stops
# being trustworthy across a call and is dropped there.
VOLATILE = {"rax", "rcx", "rdx", "r8", "r9", "r10", "r11"}

_NARROW = {
    "eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx",
    "esi": "rsi", "edi": "rdi", "ebp": "rbp", "esp": "rsp",
}


def widen(name: str) -> str:
    """Normalise a 32-bit register name to its 64-bit container.

    `lea eax,[rbx+3000h]` and a later `[rax+0x79]` name the same physical
    register, and an alias table that treats them as different misses exactly
    the split-address pattern it exists to catch.
    """
    if name in _NARROW:
        return _NARROW[name]
    if len(name) > 2 and name[0] == "r" and name.endswith("d") and name[1:-1].isdigit():
        return "r" + name[1:-1]
    return name


def census(img: Image, wanted: set[int], syms: dict[int, str]) -> tuple[list[Hit], dict]:
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    hits: list[Hit] = []
    seen: set[tuple[int, int, str]] = set()
    # base register -> displacements seen, per function, for the fingerprint.
    prints: dict[tuple[int, str], set[int]] = {}
    stats = {
        "functions": 0,
        "instructions": 0,
        "undecodable": 0,
        "gap_bytes": 0,
        "gap_padding": 0,
        "gap_instructions": 0,
        "gap_runs": 0,
        "unexamined_bytes": 0,
    }

    def scan(start: int, code: bytes, label: int, outside: bool) -> None:
        """Decode one run of bytes and record every hit in it.

        `aliases` maps a register to `(root register, offset)`, built from
        `lea r,[b+k]`, register-to-register `mov` and `add r,imm`. It is what
        catches a field written as `lea rax,[rbx+3000h]` then
        `mov byte ptr [rax+79h],1`, where no encoded displacement equals the
        field at all and a displacement-only census sees nothing.
        """
        aliases: dict[str, tuple[str, int]] = {}
        decoded = list(md.disasm(code, img.image_base + start))
        consumed = sum(i.size for i in decoded)
        if outside:
            stats["gap_instructions"] += len(decoded)
        else:
            stats["instructions"] += len(decoded)
            if consumed < len(code):
                stats["undecodable"] += 1
        # Capstone stops at an invalid encoding, leaving everything after it
        # unexamined. Counting those bytes is the difference between "nothing
        # writes this field" and "nothing in the part I could read does".
        stats["unexamined_bytes"] += len(code) - consumed

        # Alias state is only sound inside a straight-line run. A join point can
        # be reached with a different value in the register, and following this
        # decode's physical order across one would let a later block's `lea`
        # answer for a path that never executed it -- so the table is dropped at
        # every branch target and after every control transfer. That trades a
        # class of false positives for a stated blind spot: an alias formed in
        # one basic block and used in another is not resolved.
        targets = {
            ins.operands[0].imm
            for ins in decoded
            if ins.group(capstone.x86.X86_GRP_JUMP)
            and ins.operands
            and ins.operands[0].type == capstone.x86.X86_OP_IMM
        }

        for ins in decoded:
            if ins.address in targets:
                aliases.clear()
            if ins.mnemonic == "call":
                for reg in [r for r in aliases if r in VOLATILE]:
                    del aliases[reg]

            for op in ins.operands:
                if op.type != capstone.x86.X86_OP_MEM:
                    continue
                if op.mem.base in (0, capstone.x86.X86_REG_RIP):
                    continue
                base = widen(ins.reg_name(op.mem.base))
                disp = op.mem.disp
                # Resolve through the alias *before* comparing, never only when
                # the raw displacement misses: after `lea rax,[rbx+0x3000]`, a
                # `[rax+0x3079]` is `rbx+0x6079` and reporting it as `+0x3079`
                # is a false hit on the field this census exists to count.
                root, off = aliases.get(base, (base, 0))
                effective = off + disp
                via = f"{base} = {root}{off:+#x}" if off else ""
                if effective > 0:
                    prints.setdefault((label, root), set()).add(effective)
                if effective not in wanted:
                    continue

                kind = (
                    "lea"
                    if ins.mnemonic == "lea"
                    else ACCESS.get(
                        (
                            bool(op.access & capstone.CS_AC_READ),
                            bool(op.access & capstone.CS_AC_WRITE),
                        ),
                        "unknown",
                    )
                )
                text = f"{ins.mnemonic} {ins.op_str}"
                if via:
                    text += f"   [via {via}]"
                if outside:
                    text += "   [OUTSIDE .pdata]"
                if (ins.address, effective, text) in seen:
                    continue  # a gap decoded from several starts repeats itself
                seen.add((ins.address, effective, text))
                hits.append(
                    Hit(
                        rva=ins.address - img.image_base,
                        func_rva=label,
                        func_name=name_for(label, syms),
                        mnemonic=ins.mnemonic,
                        text=text,
                        base=root,
                        disp=effective,
                        kind=kind,
                    )
                )

            # Update the alias table *after* reading operands, so an instruction
            # that both reads and redefines a register is read before the kill.
            #
            # Only 64-bit destinations are tracked. `lea eax,[rbx+0x3000]` writes
            # the 32-bit register, which zero-extends into `rax` -- so `rax` is
            # NOT `rbx+0x3000` for any pointer above 4 GiB, and treating it as
            # one manufactures a hit on a later `[rax+0x79]`.
            handled = False
            ops = ins.operands
            if ins.mnemonic == "lea" and len(ops) == 2 and ops[0].size == 8:
                mem = ops[1].mem
                if mem.base and mem.index == 0 and mem.base != capstone.x86.X86_REG_RIP:
                    dst = widen(ins.reg_name(ops[0].reg))
                    src = widen(ins.reg_name(mem.base))
                    prev = aliases.get(src)
                    aliases[dst] = (
                        (prev[0], prev[1] + mem.disp) if prev else (src, mem.disp)
                    )
                    handled = True
            elif ins.mnemonic == "mov" and len(ops) == 2 and ops[0].size == 8:
                if (
                    ops[0].type == capstone.x86.X86_OP_REG
                    and ops[1].type == capstone.x86.X86_OP_REG
                ):
                    dst = widen(ins.reg_name(ops[0].reg))
                    src = widen(ins.reg_name(ops[1].reg))
                    aliases[dst] = aliases.get(src, (src, 0))
                    handled = True
            elif ins.mnemonic == "add" and len(ops) == 2 and ops[0].size == 8:
                if (
                    ops[0].type == capstone.x86.X86_OP_REG
                    and ops[1].type == capstone.x86.X86_OP_IMM
                ):
                    dst = widen(ins.reg_name(ops[0].reg))
                    # Seed from the register's own pre-`add` value when it is not
                    # already an alias, or `add rbx,0x3000` followed by
                    # `[rbx+0x79]` records nothing and the write is missed --
                    # which the docstring claimed was covered when it was not.
                    # The root then names the register's *earlier* value, which
                    # is the same convention `lea rax,[rbx+k]` already uses.
                    root, off = aliases.get(dst, (dst, 0))
                    aliases[dst] = (root, off + ops[1].imm)
                    handled = True
            if not handled:
                # `regs_write` carries only IMPLICIT writes -- measured here,
                # `xor eax,eax` reports `rflags` alone and `mov rax,[rbx]`
                # reports nothing at all -- so invalidating from it leaves a
                # stale alias exactly where a pointer was overwritten.
                # `regs_access()` is the one that includes the destination, and
                # `tools/sk_vmcs_scan.py` already learned this the same way.
                _, writes = ins.regs_access()
                for reg in writes:
                    aliases.pop(widen(ins.reg_name(reg)), None)

            # End of a straight-line run: nothing after a control transfer is
            # reached with this state guaranteed.
            if ins.group(capstone.x86.X86_GRP_JUMP) or ins.group(capstone.x86.X86_GRP_RET):
                aliases.clear()

    for begin, end in img.pdata:
        code = img.read(begin, end - begin)
        if code:
            stats["functions"] += 1
            scan(begin, code, begin, outside=False)

    # Everything executable that .pdata does not claim. A leaf function -- no
    # stack frame, no calls, no saved non-volatiles -- needs no unwind data and
    # may be absent from the table, so walking .pdata alone cannot support a
    # claim that a census is complete: such a function could write the field and
    # never be looked at. Measure the uncovered bytes, report how many are
    # padding, and decode whatever is left.
    covered = sorted(img.pdata)
    for sec in img.sections:
        if not (sec.flags & 0x20000000) or not sec.rawsize:  # IMAGE_SCN_MEM_EXECUTE
            continue
        limit = sec.va + min(sec.vsize or sec.rawsize, sec.rawsize)
        cursor = sec.va
        spans = [(b, e) for b, e in covered if b < limit and e > sec.va]
        for b, e in spans + [(limit, limit)]:
            if b > cursor:
                blob = img.read(cursor, b - cursor) or b""
                stats["gap_bytes"] += len(blob)
                # Count padding bytes outright rather than by stripping the
                # ends: a gap of padding/code/padding would otherwise report
                # its whole length as padding and hide the code in the middle.
                stats["gap_padding"] += sum(1 for byte in blob if byte in (0xCC, 0x00))
                starts = [
                    i
                    for i, byte in enumerate(blob)
                    if byte not in (0xCC, 0x00)
                    and (i == 0 or blob[i - 1] in (0xCC, 0x00))
                ]
                if starts:
                    stats["gap_runs"] += 1
                    # A linear decode from one boundary can begin mid-instruction
                    # and swallow or skip what follows, so no single pass licenses
                    # a negative here. These runs are tiny, so decode from every
                    # plausible start -- each first byte after padding -- and take
                    # the union. `seen` keeps the repeats out of the report.
                    for offset in starts:
                        scan(cursor + offset, blob[offset:], cursor, outside=True)
            cursor = max(cursor, e)
    return hits, {"stats": stats, "prints": prints}


def report(hits: list[Hit], extra: dict, wanted: set[int]) -> None:
    stats = extra["stats"]
    prints = extra["prints"]
    print(
        f"decoded {stats['instructions']} instructions in {stats['functions']} "
        f"functions from .pdata ({stats['undecodable']} with an undecodable tail); "
        f"{stats['unexamined_bytes']} bytes left unexamined after a decode stop"
    )
    print(
        f"executable bytes .pdata does not claim: {stats['gap_bytes']} "
        f"({stats['gap_padding']} of them 0xCC/0x00 padding); "
        f"{stats['gap_runs']} gap run(s) held anything else, decoding to "
        f"{stats['gap_instructions']} instructions, decoded from every start "
        f"after padding"
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

    # The split address, which review caught the first version of this tool
    # missing entirely: `lea rax,[rbx+3000h]` then `mov byte ptr [rax+79h],1`
    # writes +0x3079 with no encoded 0x3079 anywhere. A pass here means the
    # alias table resolved it; a fail means the census is displacement-only and
    # must not claim completeness.
    split = b"\x48\x8d\x83\x00\x30\x00\x00" b"\xc6\x40\x79\x01"
    img = Image(data=b"", sections=[], image_base=0x140000000)
    img.read = lambda rva, n: split if rva == 0x1000 else None  # type: ignore[method-assign]
    img.pdata = [(0x1000, 0x1000 + len(split))]
    hits, _ = census(img, {0x3079}, {})
    found = [h for h in hits if h.kind == "write" and "via" in h.text]
    print(
        f"  {'ok  ' if found else 'FAIL'} split address lea+disp8 resolves to +0x3079"
        + (f" ({found[0].text})" if found else " (not resolved)")
    )
    failures += int(not found)

    # And the same shape must NOT fire when the halves do not add up, or the
    # alias table would manufacture writers wherever two small numbers appear.
    #
    # The rest of these are the false positives review found in the first
    # version of the alias table. Each one reported a write to +0x3079 that the
    # code does not perform, so each is a way the census could have overcounted
    # while looking more thorough. They are listed as (bytes, why).
    NEGATIVE = [
        (
            b"\x48\x8d\x83\x00\x30\x00\x00" b"\xc6\x40\x7a\x01",
            "a split address to +0x307a is not reported",
        ),
        (
            # lea rax,[rbx+3000h]; xor eax,eax; mov byte ptr [rax+79h],1
            b"\x48\x8d\x83\x00\x30\x00\x00" b"\x31\xc0" b"\xc6\x40\x79\x01",
            "an alias killed by `xor eax,eax` is not still live",
        ),
        (
            # lea rax,[rbx+3000h]; mov rax,[rbx]; mov byte ptr [rax+79h],1
            b"\x48\x8d\x83\x00\x30\x00\x00" b"\x48\x8b\x03" b"\xc6\x40\x79\x01",
            "an alias killed by a load is not still live",
        ),
        (
            # lea eax,[rbx+3000h]; mov byte ptr [rax+79h],1 -- 32-bit lea
            b"\x8d\x83\x00\x30\x00\x00" b"\xc6\x40\x79\x01",
            "a 32-bit lea does not carry a 64-bit pointer alias",
        ),
        (
            # lea rax,[rbx+3000h]; jne +2; lea rax,[rcx+20h]; mov byte [rax+79h],1
            b"\x48\x8d\x83\x00\x30\x00\x00" b"\x75\x04" b"\x48\x8d\x41\x20"
            b"\xc6\x40\x79\x01",
            "an alias is not carried across a branch",
        ),
    ]
    for code, why in NEGATIVE:
        probe = Image(data=b"", sections=[], image_base=0x140000000)
        probe.read = lambda rva, n, c=code: c if rva == 0x1000 else None  # type: ignore[method-assign]
        probe.pdata = [(0x1000, 0x1000 + len(code))]
        got, _ = census(probe, {0x3079}, {})
        print(f"  {'FAIL' if got else 'ok  '} {why}")
        failures += int(bool(got))

    # `add` with no prior alias, which the first version silently ignored while
    # the docstring claimed to cover it -- a false NEGATIVE, and those are the
    # dangerous ones for a census whose product is "nothing else writes this".
    code = b"\x48\x81\xc3\x00\x30\x00\x00" b"\xc6\x43\x79\x01"  # add rbx,3000h
    probe = Image(data=b"", sections=[], image_base=0x140000000)
    probe.read = lambda rva, n: code if rva == 0x1000 else None  # type: ignore[method-assign]
    probe.pdata = [(0x1000, 0x1000 + len(code))]
    got, _ = census(probe, {0x3079}, {})
    ok = len(got) == 1 and got[0].kind == "write"
    print(
        f"  {'ok  ' if ok else 'FAIL'} an add-formed pointer with no prior alias "
        f"resolves to +0x3079"
    )
    failures += int(not ok)

    # And the matching-displacement case, which is a false positive in the other
    # direction: on an aliased base, an encoded 0x3079 is NOT the field.
    code = b"\x48\x8d\x83\x00\x30\x00\x00" b"\xc6\x80\x79\x30\x00\x00\x01"
    probe = Image(data=b"", sections=[], image_base=0x140000000)
    probe.read = lambda rva, n: code if rva == 0x1000 else None  # type: ignore[method-assign]
    probe.pdata = [(0x1000, 0x1000 + len(code))]
    wrong, _ = census(probe, {0x3079}, {})
    right, _ = census(probe, {0x6079}, {})
    ok = not wrong and len(right) == 1
    print(
        f"  {'ok  ' if ok else 'FAIL'} an aliased base with an encoded 0x3079 "
        f"resolves to +0x6079, not +0x3079"
    )
    failures += int(not ok)

    total = len(SELF_TEST) + 2 + len(NEGATIVE) + 2
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
