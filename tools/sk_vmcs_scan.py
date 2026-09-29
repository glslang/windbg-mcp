r"""Find where a hypervisor programs the VMX exception bitmap, and whether it is per-VTL.

`FOLLOWUPS.md` item 103 gate S5. S5h measured the behaviour: with a parent-installed
exception intercept standing, a `#BP` raised in VTL1 user mode never reaches the guest's
own dispatch, and is handed back intact when the intercept comes down. What S5h could
**not** settle is the mechanism -- whether the hypervisor takes the trap in VTL1, or
takes a VTL0 event that dispatching the VTL1 exception produces. Its halt readings are
consistent with both, and that question governs whether any of it reaches Secure Kernel,
which dispatches its own exceptions without returning to VTL0.

**Why the VMCS and not the dispatch table.** Two earlier static attempts on this image
went looking for a hypercall dispatch table by structural heuristics and found the IDT
and a 512-entry page-table walk instead (S5a's record). This asks an architectural
question instead. On Intel VMX an exception intercept *is* the VMCS **exception bitmap**,
field encoding `0x4004`: the hypervisor must `vmwrite` it, and a guest exception whose
bit is clear never exits to the hypervisor at all. Hyper-V runs each VTL on its own VMCS.
So:

  * if the bitmap a parent installs is programmed into **every** VTL's VMCS, a VTL1 `#BP`
    exits directly and S5h's hold is genuine VTL1 interception;
  * if it reaches only VTL0's, a VTL1 `#BP` cannot exit on it, and the hold must be
    mediated by something else.

`0x4004` is a specific constant in a specific instruction, which is a far narrower thing
to look for than "a dispatch table".

What this tool does NOT do, and the limits are the same family as `sk_hypercall_scan.py`'s:
it reads **immediates**, so a field encoding that arrives computed or loaded from data is
invisible to it; it decodes each function from the exception directory rather than
sweeping, so bytes in no `RUNTIME_FUNCTION` are not covered and the tool reports how many;
and finding a write site is not the same as knowing what VTL state feeds it -- that is the
read this tool exists to make possible, not one it performs.
"""
import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import capstone                                        # noqa: E402
from sk_hypercall_scan import PE                       # noqa: E402

# Intel SDM vol 3, VMCS field encodings. The 32-bit control fields; the exception bitmap
# is the one this gate is about, and the neighbours are here so a hit can be read in
# context rather than in isolation -- a function that writes several of these is the
# VMCS setup path, one that writes only 0x4004 is an update.
VMCS_FIELDS = {
    0x0000: "VPID",
    0x4000: "PIN_BASED_VM_EXEC_CONTROL",
    0x4002: "CPU_BASED_VM_EXEC_CONTROL",
    0x4004: "EXCEPTION_BITMAP",
    0x4006: "PAGE_FAULT_ERROR_CODE_MASK",
    0x4008: "PAGE_FAULT_ERROR_CODE_MATCH",
    0x400A: "CR3_TARGET_COUNT",
    0x400C: "VM_EXIT_CONTROLS",
    0x4012: "VM_ENTRY_CONTROLS",
    0x4016: "VM_ENTRY_INTR_INFO_FIELD",
    0x401E: "SECONDARY_VM_EXEC_CONTROL",
    0x4402: "EXIT_REASON",
    0x4404: "VM_EXIT_INTR_INFO",
    0x681E: "GUEST_RIP",
}

EXCEPTION_BITMAP = 0x4004

SUB64 = {}    # capstone gives sub-registers; normalise to the 64-bit name
WIDE = set()  # the names whose write defines the whole 64-bit value


def _norm(name):
    """eax/ax/al -> rax, r8d/r8w/r8b -> r8. A field encoding is loaded as a 32-bit
    immediate into eax and then used as rax by vmwrite, so tracking must span the two."""
    if not name:
        return None
    return SUB64.get(name.lower(), name.lower())


def _defines_full(name):
    """Does writing this register name determine all 64 bits?

    Only the 64- and 32-bit forms do: a 32-bit write zero-extends, while `mov ax, 0x4004`
    and `xor al, al` leave the upper bits as they were. Treating those as full writes
    let a stale upper half be reported as a resolved field encoding, which review caught.
    """
    return bool(name) and name.lower() in WIDE


def _build_subregs():
    for a, b, c, d in (("rax", "eax", "ax", "al"), ("rbx", "ebx", "bx", "bl"),
                       ("rcx", "ecx", "cx", "cl"), ("rdx", "edx", "dx", "dl"),
                       ("rsi", "esi", "si", "sil"), ("rdi", "edi", "di", "dil"),
                       ("rbp", "ebp", "bp", "bpl"), ("rsp", "esp", "sp", "spl")):
        for s in (a, b, c, d):
            SUB64[s] = a
        WIDE.update((a, b))
    # The high-byte aliases, which have no `r`-prefixed spelling and so are easy to
    # leave out of a table built from the other four. Capstone reports a write to `ah`
    # as `ah`, and without this `mov eax, 0x4004; mov ah, 0x41; vmwrite rax, rdx` kept
    # a tracked 0x4004 for a register that now holds 0x4104. They are never in WIDE.
    for full, high in (("rax", "ah"), ("rbx", "bh"), ("rcx", "ch"), ("rdx", "dh")):
        SUB64[high] = full
    for i in range(8, 16):
        for suf in ("", "d", "w", "b"):
            SUB64["r%d%s" % (i, suf)] = "r%d" % i
        WIDE.update(("r%d" % i, "r%dd" % i))


_build_subregs()


def _branch_targets(insns, lo, hi):
    """Every address inside the function that a branch lands on.

    These are join points: what a register holds there depends on which edge arrived,
    so the tracker cannot carry a value across one. Collected in a first pass because a
    backward jump's target precedes the jump.
    """
    out = set()
    for ins in insns:
        t = branch_target(ins)
        if t is not None and lo <= t < hi:
            out.add(t)
    return out


def scan_function(md, code, base):
    """Walk one function, tracking reg <- immediate, and report every vmwrite/vmread
    with the field encoding it used when that encoding is a tracked constant.

    A constant is reported only when it was set **in the same basic block**, by a write
    that defines all 64 bits. Three ways an earlier version got this wrong, all found by
    review on #413 and all able to invent a resolved field that the instruction does not
    use:

    * it carried constants across branches, so a `mov eax, 0x4004` jumped over could
      still label a later `vmwrite`. The map is now cleared at every branch target and
      after every unconditional transfer, which is conservative: it loses real
      resolutions rather than inventing false ones;
    * it treated `mov ax, 0x4004` as defining `rax`, when only the 64- and 32-bit forms
      do;
    * it let `vmread` leave its destination's old constant in place, so
      `mov eax, 0x4004; vmread rax, rcx; vmwrite rax, rdx` reported the third
      instruction as the exception bitmap.

    It still cannot follow an encoding through memory or arithmetic, which is the
    `immediates` limit the module docstring states.
    """
    regs = {}
    hits = []
    insns = list(md.disasm(code, base))
    targets = _branch_targets(insns, base, base + len(code))
    for i, ins in enumerate(insns):
        if ins.address in targets:
            regs.clear()          # a join: what arrives here depends on the edge
        m = ins.mnemonic
        if m in ("vmwrite", "vmread"):
            ops = [o.strip() for o in ins.op_str.split(",")]
            # vmwrite FIELD, VALUE  /  vmread DEST, FIELD
            field_op = ops[0] if m == "vmwrite" else (ops[1] if len(ops) > 1 else None)
            value_op = ops[1] if m == "vmwrite" and len(ops) > 1 else None
            field = regs.get(_norm(field_op))
            hits.append(dict(rva=ins.address, mnemonic=m, op_str=ins.op_str,
                             field=field, field_reg=_norm(field_op),
                             value_reg=_norm(value_op), index=i))
            _invalidate(regs, ins)
            continue
        # Every register this instruction writes loses its tracked value, taken from
        # capstone rather than from the operand text. An earlier version invalidated
        # only the first of two comma-separated operands, so `inc eax`, `pop rax`,
        # `neg`, `not` and every other single-operand write left a stale constant
        # behind -- `mov eax, 0x4004; inc eax; vmwrite rax, rdx` reported the write as
        # the exception bitmap. Review caught it; the ask is broader than the operand
        # string can answer, because some writes are implicit.
        _invalidate(regs, ins)
        if m == "mov" and "," in ins.op_str:
            dst, src = (x.strip() for x in ins.op_str.split(",", 1))
            if "[" not in dst and _defines_full(dst) and (src.startswith("0x")
                                                          or src.isdigit()):
                try:
                    regs[_norm(dst)] = int(src, 0)
                except ValueError:
                    pass
        elif m == "xor" and "," in ins.op_str:
            dst, src = (x.strip() for x in ins.op_str.split(",", 1))
            if dst == src and _defines_full(dst):
                regs[_norm(dst)] = 0
        elif m == "call":
            regs.clear()
        if m in ("ret", "jmp"):
            regs.clear()          # the next instruction begins a new block
    return hits, insns


def _invalidate(regs, ins):
    """Drop every register capstone says this instruction writes."""
    try:
        _, written = ins.regs_access()
    except capstone.CsError:
        return
    for r in written:
        regs.pop(_norm(ins.reg_name(r)), None)


def imm_equal(value, want, encoded_size=0):
    """Is a decoded immediate the one asked for?

    Exact, with one deliberate exception: an **imm32** operand can be decoded already
    sign-extended to 64 bits, so `0x80010003` may arrive as `0xFFFFFFFF80010003`.

    Two earlier versions got the exception wrong in opposite ways. The first compared
    the low 32 bits of everything, so `--imm 0x4004` matched `movabs rax, 0x100004004`.
    The second applied the sign-extension equivalence to *any* pair of values, so
    `--imm 0x80010003` matched `movabs rax, 0xffffffff80010003` -- an instruction
    carrying a genuinely distinct 64-bit immediate. Both bots reported the second
    independently.

    The discriminator is how many bytes were **encoded**, which capstone reports as
    `encoding.imm_size` and which is 8 for a `movabs` and 4 for an imm32 however wide
    the destination register is. The equivalence applies only at 4.
    """
    if value == want:
        return True
    if encoded_size != 4:
        return False
    for small, big in ((want, value), (value, want)):
        if small <= 0xFFFFFFFF and small & 0x80000000:
            if big == (small | 0xFFFFFFFF00000000):
                return True
    return False


def mem_operands(ins):
    """(displacement, writes) for each memory operand, from capstone rather than text.

    Two things the rendered string cannot answer. A small displacement prints as
    `[rcx + 8]`, with no `0x8` in it, so a substring search for one silently finds
    nothing; and a memory operand's position does not say whether it is written --
    `call qword ptr [rax + 0x1a04]` has it first and only reads it.
    """
    out = []
    try:
        ops = ins.operands
    except capstone.CsError:
        return out
    for op in ops:
        if op.type == capstone.x86.X86_OP_MEM:
            out.append((op.mem.disp, bool(op.access & capstone.CS_AC_WRITE)))
    return out


def branch_target(ins, include_conditional=True):
    """The address a direct branch transfers to, or None.

    Capstone reports a `call`/`jmp`/`jcc` destination as an ordinary `X86_OP_IMM`, so
    the same operand is a code address here and a data constant in `immediates()`.
    Keeping the two apart in one place is what stops `--imm 0x4004` reporting a call
    that happens to land on `0x4004`.

    `include_conditional` is the difference between the two callers. Collecting basic
    block boundaries wants **every** edge, `jcc` included. Enumerating who *calls* a
    function does not: a `je` landing on the entry is a control-flow edge and not a
    caller, and counting it inflates the very numbers a chain is walked by.
    """
    try:
        groups, ops = ins.groups, ins.operands
    except capstone.CsError:
        return None
    is_call = capstone.CS_GRP_CALL in groups
    is_jump = capstone.CS_GRP_JUMP in groups
    if not (is_call or is_jump):
        return None
    if not include_conditional and not is_call and ins.mnemonic != "jmp":
        return None
    if len(ops) == 1 and ops[0].type == capstone.x86.X86_OP_IMM:
        return ops[0].imm & 0xFFFFFFFFFFFFFFFF
    return None


def immediates(ins):
    """The instruction's immediate operands, as (unsigned value, encoded byte width).

    Capstone's structured operands, not the printed text. A substring test over
    `op_str` matches `0x40040` and `[rcx + 0x4004]` when asked for `0x4004` -- neither
    of which is an immediate equal to it -- and the option that used one advertised
    itself as sound. Review caught both halves.
    """
    if branch_target(ins) is not None:
        return []          # its only immediate is a code address, not a constant
    out = []
    try:
        ops = ins.operands
    except capstone.CsError:
        return out
    try:
        size = ins.encoding.imm_size
    except (capstone.CsError, AttributeError):
        size = 0
    for op in ops:
        if op.type == capstone.x86.X86_OP_IMM:
            out.append((op.imm & 0xFFFFFFFFFFFFFFFF, size))
    return out


# Hand-assembled counterexamples, one per soundness rule, each taken from the review
# finding that named it. A rule nobody can break is a rule nobody has tested: these
# exist so that backing any of the three fixes out fails here rather than silently
# producing a confident wrong anchor in a later gate.
SELF_TEST = [
    ("a constant jumped over does not resolve the write",
     bytes([0xB8, 0x04, 0x40, 0x00, 0x00,      # mov eax, 0x4004
            0xEB, 0x05,                        # jmp +5 -> the vmwrite
            0xB8, 0x02, 0x40, 0x00, 0x00,      # mov eax, 0x4002 (skipped)
            0x0F, 0x79, 0xC2]),                # vmwrite rax, rdx
     None),
    ("a 16-bit write does not define the field register",
     bytes([0x66, 0xB8, 0x04, 0x40,            # mov ax, 0x4004
            0x0F, 0x79, 0xC2]),                # vmwrite rax, rdx
     None),
    ("vmread clobbers its destination",
     bytes([0xB8, 0x04, 0x40, 0x00, 0x00,      # mov eax, 0x4004
            0x0F, 0x78, 0xC8,                  # vmread rax, rcx
            0x0F, 0x79, 0xC2]),                # vmwrite rax, rdx
     None),
    ("a single-operand write invalidates the field register",
     bytes([0xB8, 0x04, 0x40, 0x00, 0x00,      # mov eax, 0x4004
            0xFF, 0xC0,                        # inc eax  -> now 0x4005
            0x0F, 0x79, 0xC2]),                # vmwrite rax, rdx
     None),
    ("a high-byte write invalidates the whole register",
     bytes([0xB8, 0x04, 0x40, 0x00, 0x00,      # mov eax, 0x4004
            0xB4, 0x41,                        # mov ah, 0x41  -> now 0x4104
            0x0F, 0x79, 0xC2]),                # vmwrite rax, rdx
     None),
    ("the positive control still resolves",
     bytes([0xB9, 0x04, 0x40, 0x00, 0x00,      # mov ecx, 0x4004
            0x0F, 0x79, 0xC8]),                # vmwrite rcx, rax
     0x4004),
]

# For the immediate matcher, which does not go through scan_function.
IMM_TEST = [
    ("an exact immediate matches", bytes([0xB8, 0x04, 0x40, 0x00, 0x00]), True),
    ("a longer constant does not", bytes([0xB8, 0x40, 0x00, 0x04, 0x00]), False),
    ("a memory displacement is not an immediate",
     bytes([0x8B, 0x81, 0x04, 0x40, 0x00, 0x00]), False),   # mov eax, [rcx+0x4004]
    ("a 64-bit constant sharing the low half does not",
     bytes([0x48, 0xB8, 0x04, 0x40, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]),
     False),                                                # movabs rax, 0x100004004
    ("a branch target is a code address, not a data immediate",
     bytes([0xE9, 0xFF, 0x2F, 0x00, 0x00]), False),         # jmp 0x4004 (from 0x1000)
    # Both review bots reported this one independently: a true imm64 must not be
    # equated with the imm32 whose sign-extension it happens to equal.
    ("a real imm64 is not the imm32 it sign-extends from",
     bytes([0x48, 0xB8, 0x04, 0x40, 0x00, 0x80, 0xFF, 0xFF, 0xFF, 0xFF]),
     False),                                                # movabs rax, 0xffffffff80004004
]

# imm32 sign-extension is a real equivalence and must survive the fix above.
SEXT_TEST = [
    ("an imm32 sign-extended into a 64-bit register still matches",
     bytes([0x48, 0xC7, 0xC0, 0x04, 0x40, 0x00, 0x80]),     # mov rax, 0xffffffff80004004
     0x80004004, True),
]

# direct_callers must not count a conditional edge as a call.
CALLER_TEST = [
    ("a call is a caller", bytes([0xE8, 0xFF, 0x2F, 0x00, 0x00]), True),   # call 0x4004
    ("a tail jmp is a caller", bytes([0xE9, 0xFF, 0x2F, 0x00, 0x00]), True),
    ("a conditional branch is not",
     bytes([0x0F, 0x84, 0xFE, 0x2F, 0x00, 0x00]), False),                  # je 0x4004
]

# For the memory-operand matcher: a displacement too small to render as hex, and an
# instruction whose memory operand comes first and is only read.
MEM_TEST = [
    ("a small displacement is found at all",
     bytes([0x8B, 0x41, 0x08]), 8, True, False),            # mov eax, [rcx+8]
    ("an indirect call reads its pointer, it does not write it",
     bytes([0xFF, 0x90, 0x04, 0x1A, 0x00, 0x00]), 0x1A04, True, False),
    ("a genuine store is a write",
     bytes([0x89, 0x90, 0x04, 0x1A, 0x00, 0x00]), 0x1A04, True, True),
]


def self_test():
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    bad = 0
    for name, code, want in IMM_TEST:
        ins = next(md.disasm(code, 0x1000), None)
        got = bool(ins) and any(imm_equal(v, 0x4004, n)
                                for v, n in immediates(ins))
        ok = (got == want)
        bad += not ok
        print(f"  [{'ok ' if ok else 'BAD'}] {name}\n"
              f"        0x4004 among immediates of `{ins.mnemonic} {ins.op_str}`: "
              f"{got}, expected {want}")
    for name, code, want, expect in SEXT_TEST:
        ins = next(md.disasm(code, 0x1000), None)
        got = bool(ins) and any(imm_equal(v, want, n) for v, n in immediates(ins))
        ok = (got == expect)
        bad += not ok
        print(f"  [{'ok ' if ok else 'BAD'}] {name}\n"
              f"        `{ins.mnemonic} {ins.op_str}` vs {want:#x}: {got}, "
              f"expected {expect}")
    for name, code, expect in CALLER_TEST:
        ins = next(md.disasm(code, 0x1000), None)
        got = bool(ins) and branch_target(ins, include_conditional=False) == 0x4004
        ok = (got == expect)
        bad += not ok
        print(f"  [{'ok ' if ok else 'BAD'}] {name}\n"
              f"        `{ins.mnemonic} {ins.op_str}`: counted={got}, "
              f"expected {expect}")
    for name, code, disp, want_found, want_write in MEM_TEST:
        ins = next(md.disasm(code, 0x1000), None)
        mems = [w for d, w in mem_operands(ins)] if ins else []
        found = bool(ins) and any(d == disp for d, _ in mem_operands(ins))
        writes = any(mems) if found else False
        ok = (found == want_found and writes == want_write)
        bad += not ok
        print(f"  [{'ok ' if ok else 'BAD'}] {name}\n"
              f"        `{ins.mnemonic} {ins.op_str}`: found={found} writes={writes}, "
              f"expected found={want_found} writes={want_write}")
    for name, code, want in SELF_TEST:
        hits, _ = scan_function(md, code, 0x1000)
        writes = [h for h in hits if h["mnemonic"] == "vmwrite"]
        got = writes[-1]["field"] if writes else "no vmwrite decoded"
        ok = (got == want)
        bad += not ok
        print(f"  [{'ok ' if ok else 'BAD'}] {name}\n"
              f"        expected {want if want is None else hex(want)}, got "
              f"{got if not isinstance(got, int) else hex(got)}")
    total = (len(SELF_TEST) + len(IMM_TEST) + len(MEM_TEST) + len(SEXT_TEST)
             + len(CALLER_TEST))
    print(f"\n  {total - bad}/{total} passed")
    return 1 if bad else 0


def disasm_range(md, pe, start, end, limit=None):
    code = pe.read(start, end - start)
    out = []
    for ins in md.disasm(code or b"", start):
        out.append(f"  0x{ins.address:X}  {ins.mnemonic:<9} {ins.op_str}")
        if limit and len(out) >= limit:
            break
    return out


def direct_callers(pe, md, funcs, target):
    """Every function containing a direct `call`/`jmp` whose rel32 lands on `target`.

    Direct only: a call through a pointer table is invisible here, which is why the
    caller also greps the data sections for the address as a qword. Saying which of the
    two found a caller matters -- an indirect one is a weaker link than a rel32.
    """
    out = []
    for b, e in funcs:
        code = pe.read(b, e - b)
        if not code:
            continue
        for ins in md.disasm(code, b):
            if branch_target(ins, include_conditional=False) == target:
                out.append((b, e, ins.address, ins.mnemonic))
    return out


def data_references(pe, target_rva):
    """The target's VA appearing as a qword anywhere -- a function-pointer table."""
    va = pe.image_base + target_rva
    needle = struct.pack("<Q", va)
    hits = []
    for s in pe.sections:
        if not s["rawsize"]:
            continue
        blob = pe.data[s["rawptr"]:s["rawptr"] + s["rawsize"]]
        start = 0
        while True:
            i = blob.find(needle, start)
            if i < 0:
                break
            hits.append((s["name"], s["vaddr"] + i))
            start = i + 1
    return hits


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("image", nargs="?", default=r"C:\Windows\System32\hvix64.exe")
    ap.add_argument("--disasm", type=lambda v: int(v, 0), default=None,
                    help="disassemble the function containing this RVA and stop")
    ap.add_argument("--callers", type=lambda v: int(v, 0), default=None,
                    help="find direct callers of this function RVA, and any data "
                         "reference to it, then stop")
    ap.add_argument("--context", type=int, default=0,
                    help="with --callers, disassemble this many instructions before "
                         "each call site")
    ap.add_argument("--offset", type=lambda v: int(v, 0), default=None,
                    help="find every instruction with this displacement in a memory "
                         "operand, split by whether it reads or writes. Once a field "
                         "is identified by what consumes it, its writers are what say "
                         "who can change it and under what scope.")
    ap.add_argument("--writes-only", action="store_true",
                    help="with --offset, show only sites where it is the destination")
    ap.add_argument("--imm", type=lambda v: int(v, 0), default=None,
                    help="find every instruction carrying this immediate. Unlike the "
                         "field resolution it needs no register tracking, so it is "
                         "sound where that is merely conservative.")
    ap.add_argument("--range", default=None,
                    help="disassemble START:END regardless of function bounds. The "
                         "exception directory splits some functions across several "
                         "RUNTIME_FUNCTIONs, so --disasm can stop after a few bytes.")
    ap.add_argument("--self-test", action="store_true",
                    help="run the scanner against the counterexamples its soundness "
                         "rules exist for, and stop")
    ap.add_argument("--field", type=lambda v: int(v, 0), default=EXCEPTION_BITMAP,
                    help="the VMCS field encoding to report on (default 0x4004)")
    ap.add_argument("--all-fields", action="store_true",
                    help="list every vmwrite/vmread site with a resolved field")
    args = ap.parse_args(argv)

    if args.self_test:
        print("=== scanner self-test ===")
        return self_test()

    pe = PE(args.image)
    print(f"image   : {args.image}")
    print(f"sha256  : {pe.sha256}")
    print(f"machine : 0x{pe.machine:04X}   image base 0x{pe.image_base:X}")
    print("sections:")
    for s in pe.sections:
        x = "X" if s["chars"] & 0x20000000 else " "
        print(f"  {s['name']:<8} rva 0x{s['vaddr']:08X} vsize 0x{s['vsize']:08X} "
              f"raw 0x{s['rawsize']:08X} {x}")

    funcs = pe.runtime_functions()
    exec_bytes = pe.executable_bytes()
    covered = sum(e - b for b, e in funcs)
    print(f"\nexception directory: {len(funcs)} functions covering {covered:,} bytes "
          f"of {exec_bytes:,} executable ({100.0 * covered / exec_bytes:.1f}%)")

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True   # regs_access() and structured operands both need it

    if args.range is not None:
        lo, _, hi = args.range.partition(":")
        lo, hi = int(lo, 0), int(hi, 0)
        # An empty print and exit 0 is how a mistyped range looks exactly like a
        # successful read of a region with nothing in it. Refuse instead.
        if hi <= lo:
            print(f"\n--range needs START < END (got 0x{lo:X}:0x{hi:X})")
            return 2
        # Validating only `lo` is not enough: PE.read translates the first RVA and then
        # slices contiguous FILE bytes, so a range running off the end of its section
        # decodes whatever follows in the file and labels it with RVAs it does not have.
        # Requiring the interval to stay contiguous in both spaces rules that out.
        o_lo, o_hi = pe.rva_to_off(lo), pe.rva_to_off(hi - 1)
        if o_lo is None or o_hi is None:
            print(f"\n0x{lo:X}-0x{hi:X} is not fully inside a mapped section")
            return 2
        if o_hi - o_lo != (hi - 1) - lo:
            print(f"\n0x{lo:X}-0x{hi:X} crosses a section or a gap, so its file bytes "
                  f"are not contiguous;\nread it in pieces instead")
            return 2
        lines = disasm_range(md, pe, lo, hi)
        if not lines:
            print(f"\n0x{lo:X}-0x{hi:X} decoded to no instructions")
            return 2
        print(f"\n=== 0x{lo:X}-0x{hi:X} ===")
        print("\n".join(lines))
        return 0

    if args.disasm is not None:
        owner = [(b, e) for b, e in funcs if b <= args.disasm < e]
        if not owner:
            print(f"\nrva 0x{args.disasm:X} is in no RUNTIME_FUNCTION")
            return 1
        b, e = owner[0]
        print(f"\n=== func 0x{b:X}-0x{e:X} ({e - b} bytes) ===")
        print("\n".join(disasm_range(md, pe, b, e)))
        return 0

    if args.imm is not None:
        needle = "0x%x" % args.imm
        want = args.imm & 0xFFFFFFFFFFFFFFFF
        found = []
        for b, e in funcs:
            code = pe.read(b, e - b)
            if not code:
                continue
            for ins in md.disasm(code, b):
                if any(imm_equal(v, want, n) for v, n in immediates(ins)):
                    found.append((ins.address, b, e, ins.mnemonic, ins.op_str))
        print(f"\n=== immediate {needle}: {len(found)} site(s) ===")
        for addr, b, e, mn, ops in sorted(found):
            print(f"  0x{addr:X}  {mn:<9} {ops}   in func 0x{b:X}-0x{e:X}")
        print(f"\n  {len({f[1] for f in found})} distinct function(s)")
        return 0

    if args.offset is not None:
        found = []
        for b, e in funcs:
            code = pe.read(b, e - b)
            if not code:
                continue
            for ins in md.disasm(code, b):
                hits = [w for disp, w in mem_operands(ins) if disp == args.offset]
                if not hits:
                    continue
                writes = any(hits)
                if args.writes_only and not writes:
                    continue
                found.append((ins.address, b, e, ins.mnemonic, ins.op_str, writes))
        w = sum(1 for f in found if f[5])
        print(f"\n=== displacement +0x{args.offset:X}: {len(found)} site(s), "
              f"{w} writing ===")
        for addr, b, e, mn, ops, writes in sorted(found):
            kind = "W" if writes else "r"
            print(f"  [{kind}] 0x{addr:X}  {mn:<9} {ops}   in func 0x{b:X}-0x{e:X}")
        return 0

    if args.callers is not None:
        callers = direct_callers(pe, md, funcs, args.callers)
        print(f"\n=== direct callers of 0x{args.callers:X}: {len(callers)} ===")
        for b, e, site, mn in callers:
            print(f"  {mn} at rva 0x{site:X} in func 0x{b:X}-0x{e:X}")
            if args.context:
                lines = disasm_range(md, pe, b, e)
                idx = next((i for i, l in enumerate(lines)
                            if l.strip().startswith(f"0x{site:X} ")), None)
                if idx is not None:
                    for l in lines[max(0, idx - args.context):idx + 2]:
                        print("   " + l)
                print()
        refs = data_references(pe, args.callers)
        print(f"=== data references to its VA: {len(refs)} ===")
        for name, rva in refs:
            print(f"  {name} at rva 0x{rva:X}")
        return 0

    all_hits = []
    for b, e in funcs:
        code = pe.read(b, e - b)
        if not code:
            continue
        hits, _ = scan_function(md, code, b)
        for h in hits:
            h["func"] = b
            h["func_end"] = e
        all_hits.extend(hits)

    resolved = [h for h in all_hits if h["field"] is not None]
    print(f"vmwrite/vmread sites: {len(all_hits)} total, {len(resolved)} with a "
          f"resolved immediate field encoding")

    if args.all_fields:
        print("\n=== every resolved site ===")
        for h in sorted(resolved, key=lambda h: h["rva"]):
            name = VMCS_FIELDS.get(h["field"], "")
            print(f"  {h['mnemonic']:<8} field 0x{h['field']:04X} {name:<28} "
                  f"at rva 0x{h['rva']:X} in func 0x{h['func']:X}")

    want = [h for h in resolved if h["field"] == args.field]
    name = VMCS_FIELDS.get(args.field, "")
    print(f"\n=== field 0x{args.field:04X} {name} ===")
    if not want:
        print("  no site resolved to this field. That is not the same as none existing: "
              "an\n  encoding that arrives computed or loaded from memory is invisible "
              "to an\n  immediate scan. See the module docstring.")
    for h in sorted(want, key=lambda h: h["rva"]):
        print(f"  {h['mnemonic']:<8} at rva 0x{h['rva']:X}  ({h['op_str']})  "
              f"in func 0x{h['func']:X}-0x{h['func_end']:X}")

    funcs_with = sorted({h["func"] for h in want})
    if funcs_with:
        print(f"\n  {len(funcs_with)} distinct function(s) touch it: "
              + ", ".join(f"0x{f:X}" for f in funcs_with))
    return 0


if __name__ == "__main__":
    sys.exit(main())
