#!/usr/bin/env python3
"""Enumerate a Secure Kernel image's hypercall repertoire, and check it for debug hypercalls.

`FOLLOWUPS.md` item 103 gate S5a. The question it answers is whether `securekernel.exe`
contains any route to the hypervisor's debugging facility - the three hypercalls a Windows
KD transport uses (`HvPostDebugData` 0x0069, `HvRetrieveDebugData` 0x006A,
`HvResetDebugSession` 0x006B) or the synthetic-debugger MSRs (0x400000F0-0x400000FF).

It is a pure PE parse plus capstone: no debugger, no target, no driver, no VM.

Two readings, and only the first is sound
-----------------------------------------
**A. Are the debug codes present as immediates, and are there privileged instructions?**
Decided over *every executable byte*, by three overlapping passes - the functions the
exception directory declares, a linear sweep of each executable section, and a raw opcode
byte search that cannot desynchronise. This reading does not use the evaluator below and is
the one the gate's conclusion rests on.

**B. What is the hypercall repertoire?** Recovered by an abstract evaluator that walks in
address order without following control flow, so it is a **heuristic lower bound**: a code
built across a branch can be missed, and a block after an unconditional jump can contribute
one that no path reaches. Its job is to be the *negative control* - an image that issues no
hypercall at all means the scan is broken rather than that the image is clean - and it is
never allowed to produce the verdict. That belongs to A, which is why B being approximate
does not weaken the conclusion: A shows none of the three values is present as an immediate
anywhere, so no branch arrangement can route one into a wrapper as an immediate.

That split is deliberate. An earlier version let a single straight-line evaluator carry the
whole conclusion, and a review round found six independent ways it could invent a code or
miss one - partial-register writes, joins, `and reg, 0` against a tracked parameter, tail
calls, MSR indices mutated between the load and the `rdmsr`, and a function that both
forwards a parameter and calls with a literal. Each was individually fixable; what generated
them was resting a negative on a component that can only ever be approximately right.

Controls, because a scan that finds nothing is indistinguishable from a broken one
---------------------------------------------------------------------------------
* `--control <kdhvcom.dll>` runs the same passes over Windows' own KD-over-hypervisor
  transport, which must show all three *distinct* debug codes and at least one hypercall
  instruction. If it does not, every negative is void. It demonstrates that the immediate
  scan finds these values where they are known to be; it does not trace them into the
  `vmcall`, which reading A does not attempt for any image.
* the repertoire is its own negative control: a Secure Kernel that issues *no* hypercall is
  a broken scan rather than a finding.
* `--coverage` reports executable bytes examined by each pass, and any left over.

Symbols
-------
`--symbols` is **required to enumerate the repertoire**: reading B needs the two hypercall
page globals, which are found by name. Reading A needs no symbols at all. Without them the
scan still reports A and marks B unperformed - it does not report a clean repertoire it
never enumerated. Note that cdb names a module after its *file*, so a sample kept as
`securekernel-10.0.29648.1000.exe` answers to `securekernel_10_0_29648_1000!` and every
`x securekernel!...` silently returns nothing; this script stages each sample under the real
image name before asking.

Usage
-----
    python sk_hypercall_scan.py --control C:\\Windows\\System32\\kdhvcom.dll \
        --symbols <path> securekernel.exe [more.exe ...]

`--control` is not optional for an image scan. This file says a failing control voids every
negative; a run with no control is the same situation with less information, so scanning
images without one prints UNVALIDATED and exits non-zero rather than handing back a clean
result nothing checked. x64 images only - an ARM64 `securekernel.exe` is PE32+ too, and is
refused rather than decoded as x86-64.

Exit status is 0 only when a control was run and passed, and every image reached a
well-founded negative: no debug immediate at a recognised boundary, no SynDbg MSR number at
any alignment, no hypercall instruction, and nothing left unexamined. Note what that does
*not* include: wrapper sites whose control code did not resolve do not block it. Every
sampled build has some, so blocking on them would make every run inconclusive and delete
the reading rather than qualify it -- instead the count is printed with the verdict, since
such a site could carry a value by one of the routes the limits name.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile

try:
    from capstone import (Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_IMM, CS_OP_MEM, CS_OP_REG)
except ImportError:  # pragma: no cover - the message is the whole handling
    sys.exit('this scan needs capstone: python -m pip install capstone')

DEBUG_CODES = {0x0069: 'HvPostDebugData',
               0x006A: 'HvRetrieveDebugData',
               0x006B: 'HvResetDebugSession'}
SYNDBG_LO, SYNDBG_HI = 0x400000F0, 0x400000FF
PAGE_GLOBALS = ('HvcallCodeVa', 'ShvlpHypercallCodePage')

# Raw encodings, for the pass that cannot desynchronise.
RAW_OPCODES = {b'\x0f\x01\xc1': 'vmcall', b'\x0f\x01\xd9': 'vmmcall',
               b'\x0f\x32': 'rdmsr', b'\x0f\x30': 'wrmsr'}
PRIVILEGED = ('vmcall', 'vmmcall', 'rdmsr', 'wrmsr')


def hypercall_input_code(imm):
    """The control code in a hypercall input value, or None if it cannot be one.

    A caller does not have to materialise a bare `0x69`: the ABI puts the control code in
    bits 0-15 of one input value, with the fast flag at bit 16, the variable header size at
    17-26, and the rep count at 32-43 - which is why the repertoire reading masks with
    `& 0xFFFF`. An exact-equality test on the immediate therefore misses `0x00010069`, and
    this file modelled that in one reading and not the other.

    Masking alone is too loose, and measuring said so: across the ten samples it matches 0-5
    further immediates per build, nearly all of them *branch targets* like `jmp 0x140060069`
    where the value is a code address. So the reserved fields decide - bits 27-30, 44-47 and
    60-63 are zero in any real input value - and the caller excludes control-transfer
    operands, whose immediate is an address rather than data.
    """
    if (imm >> 60) or ((imm >> 44) & 0xF) or ((imm >> 27) & 0xF):
        return None
    code = imm & 0xFFFF
    return code if code in DEBUG_CODES else None

MD = Cs(CS_ARCH_X86, CS_MODE_64)
MD.detail = True


# --------------------------------------------------------------------------- PE

class PE:
    """Just enough PE for this scan: sections, the exception directory, exports."""

    def __init__(self, path):
        self.path = path
        with open(path, 'rb') as f:
            self.data = f.read()
        d = self.data
        if d[:2] != b'MZ':
            raise ValueError('not a PE image: %s' % path)
        nt = struct.unpack_from('<I', d, 0x3C)[0]
        if d[nt:nt + 4] != b'PE\0\0':
            raise ValueError('not a PE image: %s' % path)
        coff = nt + 4
        self.machine, nsec, self.timestamp = struct.unpack_from('<HHI', d, coff)
        opt_size = struct.unpack_from('<H', d, coff + 16)[0]
        opt = coff + 20
        if struct.unpack_from('<H', d, opt)[0] != 0x20B:
            raise ValueError('not PE32+: %s' % path)
        # PE32+ is not the same as x64, and an ARM64 `securekernel.exe` is both. Every
        # decode here is CS_ARCH_X86/CS_MODE_64 and the exception directory is read as
        # 12-byte x64 RUNTIME_FUNCTIONs, so an ARM64 image would produce a confident and
        # meaningless verdict rather than an error. One such image is already on this
        # bench (docs/secure-kernel/securekernel-export-followup.md).
        if self.machine != 0x8664:
            raise ValueError('not an x64 image (machine %04X): %s -- this scan decodes '
                             'x86-64 only' % (self.machine, path))
        self.image_base = struct.unpack_from('<Q', d, opt + 24)[0]
        self.size_of_image = struct.unpack_from('<I', d, opt + 56)[0]
        ndir = struct.unpack_from('<I', d, opt + 108)[0]
        self.dirs = [struct.unpack_from('<II', d, opt + 112 + i * 8) for i in range(ndir)]
        self.sections = []
        for i in range(nsec):
            off = opt + opt_size + i * 40
            vsize, vaddr, rawsize, rawptr = struct.unpack_from('<IIII', d, off + 8)
            self.sections.append(dict(name=d[off:off + 8].rstrip(b'\0').decode('latin1'),
                                      vaddr=vaddr, vsize=vsize, rawptr=rawptr,
                                      rawsize=rawsize,
                                      chars=struct.unpack_from('<I', d, off + 36)[0]))

    @property
    def sha256(self):
        return hashlib.sha256(self.data).hexdigest().upper()

    def rva_to_off(self, rva):
        for s in self.sections:
            if s['vaddr'] <= rva < s['vaddr'] + max(s['vsize'], s['rawsize']):
                delta = rva - s['vaddr']
                return s['rawptr'] + delta if delta < s['rawsize'] else None
        return None

    def read(self, rva, n):
        off = self.rva_to_off(rva)
        return self.data[off:off + n] if off is not None else None

    def code_sections(self):
        return [s for s in self.sections if s['chars'] & 0x20000000]

    def executable_bytes(self):
        return sum(min(s['vsize'], s['rawsize']) for s in self.code_sections())

    def runtime_functions(self):
        if len(self.dirs) < 4 or not self.dirs[3][0]:
            return []
        rva, size = self.dirs[3]
        off = self.rva_to_off(rva)
        out = []
        for i in range(size // 12):
            b, e, _u = struct.unpack_from('<III', self.data, off + i * 12)
            if b and e > b:
                out.append((b, e))
        return sorted(set(out))

    def exports(self):
        if len(self.dirs) < 1 or not self.dirs[0][0]:
            return {}
        off = self.rva_to_off(self.dirs[0][0])
        fields = struct.unpack_from('<IIHHIIIIIII', self.data, off)
        nname, afunc, aname, aord = fields[7], fields[8], fields[9], fields[10]
        out = {}
        noff, ooff, foff = (self.rva_to_off(aname), self.rva_to_off(aord),
                            self.rva_to_off(afunc))
        if None in (noff, ooff, foff):
            return {}
        for i in range(nname):
            nrva = struct.unpack_from('<I', self.data, noff + i * 4)[0]
            o = self.rva_to_off(nrva)
            nm = self.data[o:self.data.index(b'\0', o)].decode('latin1')
            ordi = struct.unpack_from('<H', self.data, ooff + i * 2)[0]
            out[nm] = struct.unpack_from('<I', self.data, foff + ordi * 4)[0]
        return out

    def functions(self):
        """(begin, end, [instructions]) for every function the exception directory declares.

        This is the evaluator's view, and it is deliberately *not* the scan's view of the
        image: on x64 a leaf function needs no unwind data, so a leaf containing `vmcall`
        or an MSR access has no entry here at all. Reading A uses `sweep_code` below.
        """
        for (b, e) in self.runtime_functions():
            code = self.read(b, e - b)
            if code:
                yield b, e, list(MD.disasm(code, self.image_base + b))

    def sweep_code(self):
        """Every executable section, decoded linearly. Yields (section, [instructions]).

        Capstone stops at the first byte it cannot decode, so a single embedded constant
        would end the sweep and leave the rest of the section unexamined while the run
        still reported a negative. Restart one byte on from each failure instead, which
        costs a little re-decoding and covers the section. A linear sweep can still
        desynchronise, which is why `raw_opcode_sites` runs beside it rather than
        instead of it.
        """
        for s in self.code_sections():
            n = min(s['vsize'], s['rawsize'])
            code = self.read(s['vaddr'], n)
            if not code:
                continue
            out, pos = [], 0
            while pos < len(code):
                got = list(MD.disasm(code[pos:], self.image_base + s['vaddr'] + pos))
                if not got:
                    pos += 1
                    continue
                out.extend(got)
                pos = (got[-1].address + got[-1].size) - (self.image_base + s['vaddr'])
            yield s, out

    def call_targets(self, insns):
        out = set()
        for ins in insns:
            if ins.mnemonic in ('call', 'jmp') and ins.operands \
                    and ins.operands[0].type == CS_OP_IMM:
                rva = ins.operands[0].imm - self.image_base
                if any(s['vaddr'] <= rva < s['vaddr'] + min(s['vsize'], s['rawsize'])
                       for s in self.code_sections()):
                    out.add(rva)
        return out

    def aligned_instructions(self):
        """Instructions at every boundary any pass recognises: {rva: (mnemonic, ops, [imms])}.

        Three seeds, unioned. The exception directory gives declared function starts; a
        linear sweep of each section gives everything between them; and a recursive descent
        from every direct call and jump target, iterated to a fixpoint, gives the **leaf
        functions** - which need no unwind data, are therefore absent from `.pdata`, and are
        exactly what a linear sweep can stride past if it desynchronises on embedded data.
        A leaf is reached by being called, so its entry is a call target even when nothing
        else names it.
        """
        found = {}

        def absorb(insns):
            for ins in insns:
                rva = ins.address - self.image_base
                if rva not in found:
                    found[rva] = (ins.mnemonic, ins.op_str,
                                  [op.imm for op in ins.operands if op.type == CS_OP_IMM],
                                  ins.size)

        for _b, _e, insns in self.functions():
            absorb(insns)
        for _s, insns in self.sweep_code():
            absorb(insns)

        # Exports are authoritative entry points and the recursive pass would otherwise
        # miss a leaf reachable only through one: such a function has no .pdata record and
        # no in-image direct call or jmp naming it, so call targets alone never decode
        # from its real entry.
        seeds = set(self.exports().values())
        for _s, insns in self.sweep_code():
            seeds |= self.call_targets(insns)
        for _b, _e, insns in self.functions():
            seeds |= self.call_targets(insns)

        seen_seeds = set()
        while seeds:
            rva = seeds.pop()
            if rva in seen_seeds:
                continue
            seen_seeds.add(rva)
            if rva in found:
                continue
            blob = self.read(rva, 4096)
            if not blob:
                continue
            insns = list(MD.disasm(blob, self.image_base + rva))
            absorb(insns)
            seeds |= (self.call_targets(insns) - seen_seeds)
        return found

    def immediate_sites(self, values, lookback=15, anchor_bytes=1, match=None):
        """Every instruction anywhere in executable bytes carrying one of `values` as an
        immediate - anchored on the constant's own bytes, so no decode alignment can hide it.

        This is the pass the whole conclusion rests on, and it is anchored this way because
        the two cheaper ideas both leak. A linear sweep only restarts after an *undecodable*
        byte, so data that decodes successfully but desynchronised carries the cursor past a
        real leaf-function boundary - and a leaf is absent from `.pdata` too, so a genuine
        `mov ecx, 0x69` there is missed while every coverage figure still reads 100%.

        What cannot leak is the constant itself. An immediate is encoded little-endian, so
        the low byte of the value appears verbatim in the instruction whatever the operand
        width. So: find every occurrence of that low byte, then decode from all 16 possible
        instruction starts that could cover it, and keep any decoding whose immediate is the
        value and whose extent actually spans the anchor byte. Sound by construction, and it
        never needs to know where an instruction begins.
        """
        anchors = {}
        for v in values:
            token = (v & ((1 << (8 * anchor_bytes)) - 1)).to_bytes(anchor_bytes, 'little')
            anchors.setdefault(token, []).append(v)
        out = {}
        for s in self.code_sections():
            n = min(s['vsize'], s['rawsize'])
            blob = self.read(s['vaddr'], n) or b''
            for token, candidates in anchors.items():
                start = 0
                while True:
                    i = blob.find(token, start)
                    if i < 0:
                        break
                    start = i + 1
                    lo_off = max(i - lookback, 0)
                    window = blob[lo_off:i + lookback + 1]
                    for off in range(len(window)):
                        addr = self.image_base + s['vaddr'] + lo_off + off
                        for ins in MD.disasm(window[off:], addr, count=2):
                            rva = ins.address - self.image_base
                            if not (rva <= s['vaddr'] + i < rva + ins.size):
                                continue
                            transfer = (ins.mnemonic.startswith('j')
                                        or ins.mnemonic.startswith('loop')
                                        or ins.mnemonic == 'call')
                            for op in ins.operands:
                                if op.type == CS_OP_IMM and (
                                        op.imm in candidates
                                        or (match is not None and not transfer
                                            and match(op.imm) in candidates)):
                                    out[(rva, ins.mnemonic, ins.op_str)] = (
                                        rva, ins.mnemonic, ins.op_str, op.imm, ins.size)
                                    break
        return sorted(out.values())

    def raw_opcode_sites(self):
        """Byte-pattern search for the privileged opcodes, over executable sections.

        Decoding can desynchronise and miss an instruction; a byte search cannot. It can
        over-report - the bytes may be an operand or data - so a hit is a thing to go and
        look at rather than a finding, and zero hits is a sound negative.
        """
        out = []
        for s in self.code_sections():
            n = min(s['vsize'], s['rawsize'])
            blob = self.read(s['vaddr'], n) or b''
            for pattern, name in RAW_OPCODES.items():
                start = 0
                while True:
                    i = blob.find(pattern, start)
                    if i < 0:
                        break
                    out.append((s['name'], s['vaddr'] + i, name))
                    start = i + 1
        return out


# ------------------------------------------------------------------ abstract eval

# Full-width writes only. A 32-bit write zero-extends and so sets the whole register; an
# 8- or 16-bit write preserves the other bytes, so `mov ecx, 0x100` then `mov cl, 0x69`
# is control code 0x0169 and not 0x0069. Those are modelled as *unknown* rather than
# tracked bit-by-bit, which is the safe direction: it produces an unresolved site, and an
# unresolved site makes the whole scan inconclusive rather than silently wrong.
_WIDE = {'eax': 'rax', 'ecx': 'rcx', 'edx': 'rdx', 'ebx': 'rbx',
         'esi': 'rsi', 'edi': 'rdi', 'ebp': 'rbp', 'esp': 'rsp',
         'r8d': 'r8', 'r9d': 'r9', 'r10d': 'r10', 'r11d': 'r11',
         'r12d': 'r12', 'r13d': 'r13', 'r14d': 'r14', 'r15d': 'r15'}
_PARTIAL = {'ax': ('rax', 0xFFFF), 'al': ('rax', 0xFF), 'ah': ('rax', None),
            'cx': ('rcx', 0xFFFF), 'cl': ('rcx', 0xFF), 'ch': ('rcx', None),
            'dx': ('rdx', 0xFFFF), 'dl': ('rdx', 0xFF), 'dh': ('rdx', None),
            'bx': ('rbx', 0xFFFF), 'bl': ('rbx', 0xFF), 'bh': ('rbx', None),
            'si': ('rsi', 0xFFFF), 'sil': ('rsi', 0xFF),
            'di': ('rdi', 0xFFFF), 'dil': ('rdi', 0xFF),
            'r8w': ('r8', 0xFFFF), 'r8b': ('r8', 0xFF),
            'r9w': ('r9', 0xFFFF), 'r9b': ('r9', 0xFF),
            'r10w': ('r10', 0xFFFF), 'r10b': ('r10', 0xFF),
            'r11w': ('r11', 0xFFFF), 'r11b': ('r11', 0xFF)}
VOLATILE = ('rax', 'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11')
PARAM_RCX = ('param', 'rcx')


def _target(reg):
    """(parent_register, is_full_width) for a write to `reg`."""
    if reg in _WIDE:
        return _WIDE[reg], True
    if reg in _PARTIAL:
        return _PARTIAL[reg][0], False
    return reg, True


def _read(regs, ins, op):
    """Value of a register operand, masked when a subregister is read."""
    nm = ins.reg_name(op.reg)
    if nm in _PARTIAL:
        parent, mask = _PARTIAL[nm]
        v = regs.get(parent)
        if mask is None or v == PARAM_RCX:
            return None if mask is None else v
        return (v & mask) if isinstance(v, int) else v
    parent = _WIDE.get(nm, nm)
    return regs.get(parent)


def _slot(ins, op, rsp_delta, regs):
    """Frame-relative key for a stack operand, following aliases of rsp.

    A parameter is often homed through a copy of the stack pointer - `mov rax, rsp` then
    `mov dword ptr [rax+8], ecx` - so matching only `[rsp+disp]` loses the home slot and
    with it every wrapper that reloads its control code from one.
    """
    if op.type != CS_OP_MEM or not op.mem.base or op.mem.index:
        return None
    base = ins.reg_name(op.mem.base)
    if base == 'rsp':
        return rsp_delta + op.mem.disp
    v = regs.get(_WIDE.get(base, base))
    if isinstance(v, tuple) and v[0] == 'rsp':
        return v[1] + op.mem.disp
    return None


def _eval(pe, insns, on_call, also=()):
    """Walk one function keeping an abstract value per register and per frame slot.

    **This walks in address order and does not follow control flow**, so for
    `mov ecx, 0x68; jnz L; xor ecx, ecx; L: add ecx, 1; call wrapper` it records 1 and does
    not see the feasible 0x69, and a block after an unconditional jump contaminates what
    follows. That is a real limit and it is why this evaluator does not decide anything:
    reading A already establishes that none of the three debug values appears as an
    immediate anywhere in the image, so no arrangement of branches can route one into a
    wrapper *as an immediate*, and the only residual is a value computed arithmetically.
    The two readings compose; this one on its own would not be worth much.

    Discarding state at every branch target was tried, and it is sound but useless here: it
    took the recovered repertoire on 26100.9457 from 38 control codes to **1**, which
    destroys the negative control the repertoire exists to be. A real fix is a CFG with a
    merge at each join, and that is more machinery than a corroborating reading justifies.

    `on_call(insn, regs)` is invoked at every call and at every jump, direct or indirect:
    a tail call is a call, and the callbacks distinguish an invoker from a local branch by
    checking the target themselves. `also` names further mnemonics to report at - `rdmsr`
    and `wrmsr` - so their operand can be read from the same abstract state rather than
    from a second, differently-wrong tracker.
    """
    regs, slots, rsp_delta = {'rcx': PARAM_RCX}, {}, 0
    for ins in insns:
        ops, m = ins.operands, ins.mnemonic

        if m in also:
            on_call(ins, regs)
            continue

        if m == 'call':
            on_call(ins, regs)
            for r in VOLATILE:
                regs[r] = None
            continue
        if m == 'jmp':
            on_call(ins, regs)
            continue
        if m == 'push':
            rsp_delta -= 8
            continue
        if m == 'pop':
            rsp_delta += 8
            continue
        if m in ('sub', 'add') and len(ops) == 2 and ops[0].type == CS_OP_REG \
                and ins.reg_name(ops[0].reg) == 'rsp' and ops[1].type == CS_OP_IMM:
            rsp_delta += -ops[1].imm if m == 'sub' else ops[1].imm
            continue

        if m in ('mov', 'movabs', 'movzx', 'movsx', 'movsxd'):
            if len(ops) != 2:
                continue
            dst, src = ops
            if src.type == CS_OP_IMM:
                val = src.imm
            elif src.type == CS_OP_REG:
                sname = ins.reg_name(src.reg)
                val = ('rsp', rsp_delta) if sname == 'rsp' else _read(regs, ins, src)
            else:
                k = _slot(ins, src, rsp_delta, regs)
                if k is None and src.mem.base and ins.reg_name(src.mem.base) == 'rip':
                    val = ('@', ins.address + ins.size + src.mem.disp - pe.image_base)
                else:
                    val = slots.get(k) if k is not None else None
            if dst.type == CS_OP_REG:
                parent, full = _target(ins.reg_name(dst.reg))
                regs[parent] = val if full else None
            else:
                k = _slot(ins, dst, rsp_delta, regs)
                if k is not None:
                    slots[k] = val
        elif m == 'xor' and len(ops) == 2 and ops[0].type == ops[1].type == CS_OP_REG \
                and ins.reg_name(ops[0].reg) == ins.reg_name(ops[1].reg):
            parent, full = _target(ins.reg_name(ops[0].reg))
            regs[parent] = 0 if full else None
        elif m in ('or', 'bts', 'add', 'and', 'sub', 'shl', 'imul') and len(ops) == 2:
            if ops[1].type == CS_OP_IMM:
                src = ops[1].imm
            elif ops[1].type == CS_OP_REG:
                src = _read(regs, ins, ops[1])
            else:
                k = _slot(ins, ops[1], rsp_delta, regs)
                src = slots.get(k) if k is not None else None

            def apply(cur):
                # `and x, 0` is zero whatever x was, including a tracked parameter - so it
                # has to be decided before provenance is propagated, or a fixed-code page
                # call reads as a wrapper and its real code is dropped.
                if m == 'and' and src == 0:
                    return 0
                if cur == PARAM_RCX or src == PARAM_RCX:
                    return PARAM_RCX
                if not isinstance(cur, int) or not isinstance(src, int):
                    return None
                if m == 'bts':
                    return cur | (1 << src)
                return {'or': lambda a, b: a | b, 'and': lambda a, b: a & b,
                        'add': lambda a, b: a + b, 'sub': lambda a, b: a - b,
                        'shl': lambda a, b: a << b,
                        'imul': lambda a, b: a * b}[m](cur, src)
            if ops[0].type == CS_OP_REG:
                parent, full = _target(ins.reg_name(ops[0].reg))
                regs[parent] = apply(regs.get(parent)) if full else None
            else:
                k = _slot(ins, ops[0], rsp_delta, regs)
                if k is not None:
                    slots[k] = apply(slots.get(k))
        elif m == 'lea' and len(ops) == 2 and ops[0].type == CS_OP_REG \
                and ops[1].type == CS_OP_MEM:
            # `lea ecx,[r9+16h]` after `xor r9d,r9d` is how a small control code is built.
            mem, val = ops[1].mem, None
            base = ins.reg_name(mem.base) if mem.base else None
            if base == 'rip':
                val = ('@', ins.address + ins.size + mem.disp - pe.image_base)
            elif not mem.index:
                if base == 'rsp':
                    val = ('rsp', rsp_delta + mem.disp)
                else:
                    bv = 0 if base is None else regs.get(_WIDE.get(base, base))
                    if isinstance(bv, tuple) and bv[0] == 'rsp':
                        val = ('rsp', bv[1] + mem.disp)
                    elif isinstance(bv, int):
                        val = bv + mem.disp
            parent, full = _target(ins.reg_name(ops[0].reg))
            regs[parent] = val if full else None
        elif ops and ops[0].type == CS_OP_REG and m not in ('cmp', 'test'):
            parent, _full = _target(ins.reg_name(ops[0].reg))
            regs[parent] = None


# ------------------------------------------------------------ reading A: sound passes

def privileged_instructions(pe):
    """Privileged instructions, by three passes; returns (by_pass, union_of_rvas)."""
    declared, swept = set(), set()
    for _b, _e, insns in pe.functions():
        for ins in insns:
            if ins.mnemonic in PRIVILEGED:
                declared.add((ins.address - pe.image_base, ins.mnemonic))
    for _s, insns in pe.sweep_code():
        for ins in insns:
            if ins.mnemonic in PRIVILEGED:
                swept.add((ins.address - pe.image_base, ins.mnemonic))
    raw = {(rva, name) for _sec, rva, name in pe.raw_opcode_sites()}
    # The raw byte pass is sound for *absence* and must not be used as evidence of
    # *presence*: `0F 01 C1` can sit inside an immediate or in embedded data, and counting
    # such a match as a `vmcall` would let an image report a route it does not have, and
    # let the positive control pass with no decoded hypercall in it. So presence comes from
    # the decoders, and a raw-only hit is a candidate to go and look at - which is the one
    # thing the raw pass is uniquely able to tell you, since it is what a desynchronised
    # decode would have missed.
    decoded = declared | swept
    return (dict(declared=declared, swept=swept, raw=raw, raw_only=raw - decoded),
            decoded)


def covered_bytes(pe, aligned):
    """Bitmap of bytes lying inside some instruction a decoder placed at a boundary.

    The discriminator for every "could something hide here?" question this scan faces: a
    candidate whose bytes are all covered is a misreading of the instruction covering them,
    and one whose bytes are not is unexamined code. Used for the byte-anchored immediate
    superset and for raw opcode matches alike, because the question is the same.
    """
    covered = bytearray(pe.size_of_image)
    for rva, (_m, _o, _i, size) in aligned.items():
        for k in range(rva, min(rva + size, len(covered))):
            covered[k] = 1
    return covered


def debug_immediates(pe):
    """Debug-code immediates, anchored on the constants' bytes over all executable sections.

    Split by whether the value is written or only compared: the control writes all three
    and compares none, and every occurrence in every Secure Kernel sample is a `cmp`.
    """
    written, compared = {}, {}
    aligned = pe.aligned_instructions()
    for rva, (mnem, ops, imms, _sz) in aligned.items():
        transfer = mnem.startswith('j') or mnem.startswith('loop') or mnem == 'call'
        for imm in imms:
            hit = imm if imm in DEBUG_CODES else (
                None if transfer else hypercall_input_code(imm))
            if hit is not None:
                key = (rva, '%s %s' % (mnem, ops))
                (compared if mnem in ('cmp', 'test') else written)[key] = hit
                break
    # The byte-anchored superset: every decoding at *any* offset, most of which are not
    # instruction boundaries at all - on 26100.9457 it turns 0 written into 61, forms like
    # `in al, 0x6b` and `enter -0x6e18, 0x6b`. The same composed-value rule applies, or the
    # superset would model a hypercall input value in the reading that decides and not in
    # the one that bounds it.
    #
    # Reporting the whole superset and acting on none of it was the previous shape, and it
    # left a real gap: a candidate sitting in bytes no aligned instruction covers is not a
    # misreading of anything, it is unexamined code. So split them. A candidate every one
    # of whose bytes lies inside some aligned instruction is a shadow of that instruction
    # and is dismissible on evidence; anything else is a residual the verdict has to carry.
    covered = covered_bytes(pe, aligned)
    shadowed, unexamined = [], []
    for t in pe.immediate_sites(DEBUG_CODES, match=hypercall_input_code):
        if t[0] in aligned:
            continue
        span = range(t[0], min(t[0] + t[4], len(covered)))
        (shadowed if all(covered[k] for k in span) else unexamined).append(t)
    return written, compared, shadowed, unexamined


def syndbg_immediates(pe):
    """Any synthetic-debugger MSR number materialised as an immediate, anywhere.

    The `rdmsr`/`wrmsr` reading below resolves an index where it can and leaves 16-19 sites
    per build unresolved, so on its own it cannot support "no SynDbg MSR access": an index
    it could not follow might be in the range. This reading can, and needs no control flow
    - reaching one of these MSRs means putting its number in ecx, and every encoding of
    that number contains its low byte.
    """
    return pe.immediate_sites(range(SYNDBG_LO, SYNDBG_HI + 1), anchor_bytes=4)


def msr_sites(pe, lo, hi):
    """`rdmsr`/`wrmsr` whose ecx is a tracked value in [lo, hi].

    Reads the index from the evaluator's own state, so an index mutated between the load
    and the instruction - `mov ecx, 0x400000EF; inc ecx; rdmsr` - is followed rather than
    read as the stale load, and an intervening call or unmodelled write invalidates it
    rather than leaving a value to be reported against the wrong instruction. Sites whose
    index does not resolve are returned separately: they are a reason the scan is
    inconclusive, not something to drop.
    """
    hits, unresolved = [], []
    for b, _e, insns in pe.functions():
        found = []

        def at_msr(ins, regs, _f=found):
            # `_eval` reports at calls and jumps as well, so filter: without this every
            # call site in the image is counted as an MSR access with an unresolved
            # index, which on one build read as 19,671 "unresolved MSR sites" against
            # 236 privileged instructions in the whole image.
            if ins.mnemonic in ('rdmsr', 'wrmsr'):
                _f.append((ins.address - pe.image_base, ins.mnemonic, regs.get('rcx')))

        _eval(pe, insns, at_msr, also=('rdmsr', 'wrmsr'))
        for rva, mnem, v in found:
            if isinstance(v, int) and lo <= (v & 0xFFFFFFFF) <= hi:
                hits.append((b, rva, mnem, v & 0xFFFFFFFF))
            elif not isinstance(v, int):
                unresolved.append((b, rva, mnem))
    return hits, unresolved


def page_global_rvas(pe, symbols):
    return {symbols[g] for g in PAGE_GLOBALS if g in symbols}


# ------------------------------------------------------- reading B: the repertoire

def derive_invokers(pe, page_rvas):
    """Classify every *page call site*, not every function that contains one.

    A function can both call the page with a literal and call it with the code it was
    handed; classifying the whole function as a wrapper discards the literal and drops it
    from the repertoire. So the unit is the site:

    * a literal site contributes its code, and says nothing about this function's callers;
    * a parameter site makes the function a wrapper, whose callers are where codes live;
    * an unresolved site makes the scan inconclusive.

    `SkeBugCheckEx` is why this matters in the other direction too: it reaches the page
    with a literal 0x0087, and treating it as a wrapper made every `KeBugCheckEx(code, ...)`
    call site look like a hypercall and read each **bug check code** as a control code.
    Bug check 0x69 exists, so that was a route to a false positive on this exact question.
    """
    literal, wrapper, unresolved, reference = {}, set(), [], set()
    for b, _e, insns in pe.functions():
        refs = False
        for ins in insns:
            for op in ins.operands:
                if op.type == CS_OP_MEM and op.mem.base \
                        and ins.reg_name(op.mem.base) == 'rip' \
                        and (ins.address + ins.size + op.mem.disp - pe.image_base) in page_rvas:
                    refs = True
        if not refs:
            continue

        sites = []

        def at_call(ins, regs, _s=sites):
            ops = ins.operands
            if not ops:
                return
            through = False
            if ops[0].type == CS_OP_REG:
                v = regs.get(_WIDE.get(ins.reg_name(ops[0].reg), ins.reg_name(ops[0].reg)))
                through = isinstance(v, tuple) and v[0] == '@' and v[1] in page_rvas
            elif ops[0].type == CS_OP_MEM and ops[0].mem.base \
                    and ins.reg_name(ops[0].mem.base) == 'rip':
                through = (ins.address + ins.size + ops[0].mem.disp
                           - pe.image_base) in page_rvas
            if through:
                _s.append((ins.address - pe.image_base, regs.get('rcx')))

        _eval(pe, insns, at_call)
        if not sites:
            reference.add(b)
            continue
        for rva, v in sites:
            if v == PARAM_RCX:
                wrapper.add(b)
            elif isinstance(v, int):
                literal.setdefault(v & 0xFFFF, []).append((b, rva))
            else:
                unresolved.append((b, rva))
    return dict(literal=literal, wrapper=sorted(wrapper),
                unresolved=unresolved, reference=sorted(reference))


def close_forwarders(pe, wrappers):
    """Add wrappers that hand on a control code derived from their own first argument.

    `ShvlpInitiateFastHypercall` and friends never touch the hypercall page themselves -
    they call something that does - so a set derived only from page references stops one
    level short and loses most of the call sites. Derived rather than equal, because the
    fast path folds the code into the hypercall input value (`or rcx, r10`, `bts rcx,
    0x10`) rather than passing it untouched.
    """
    invokers = set(wrappers)
    while True:
        added = set()
        targets = {pe.image_base + r for r in invokers}
        for b, _e, insns in pe.functions():
            if b in invokers:
                continue
            forwards = [False]

            def at_call(ins, regs, _f=forwards):
                ops = ins.operands
                if ops and ops[0].type == CS_OP_IMM and ops[0].imm in targets \
                        and regs.get('rcx') == PARAM_RCX:
                    _f[0] = True
            _eval(pe, insns, at_call)
            if forwards[0]:
                added.add(b)
        if not added:
            return sorted(invokers)
        invokers |= added


def control_codes(pe, invoker_rvas):
    """Every call or tail-jump into an invoker, with rcx where it resolves."""
    targets = {pe.image_base + r for r in invoker_rvas}
    sites = []
    for b, _e, insns in pe.functions():
        def at_call(ins, regs, _b=b):
            ops = ins.operands
            if ops and ops[0].type == CS_OP_IMM and ops[0].imm in targets:
                v = regs.get('rcx')
                sites.append(dict(caller=_b, site=ins.address - pe.image_base,
                                  code=v if isinstance(v, int) else None))
        _eval(pe, insns, at_call)
    return sites


def coverage(pe):
    declared = sum(e - b for b, e in pe.runtime_functions())
    decoded = 0
    truncated = 0
    for b, e, insns in pe.functions():
        got = sum(i.size for i in insns)
        decoded += got
        if got < (e - b) - 15:
            truncated += 1
    swept = 0
    for _s, insns in pe.sweep_code():
        swept += sum(i.size for i in insns)
    return dict(declared=declared, decoded=decoded, truncated=truncated,
                executable=pe.executable_bytes(), swept=swept)


# ------------------------------------------------------------------------ symbols

def load_symbols(path, sympath, names):
    """Resolve names via cdb, staging the image under its real module name first."""
    cdb = shutil.which('cdb') or _find_cdb()
    if not cdb or not sympath:
        return {}
    pe = PE(path)
    with tempfile.TemporaryDirectory() as tmp:
        staged = os.path.join(tmp, 'securekernel.exe')
        shutil.copyfile(path, staged)
        cmds = ';'.join('x securekernel!%s' % n for n in names) + ';q'
        try:
            p = subprocess.run([cdb, '-z', staged, '-y', sympath, '-c', cmds],
                               capture_output=True, text=True, timeout=600)
        except (OSError, subprocess.SubprocessError):
            return {}
    out = {}
    for line in p.stdout.splitlines():
        m = re.match(r'^([0-9a-f`]+)\s+securekernel!(\w+)\b', line.strip())
        if m:
            out[m.group(2)] = int(m.group(1).replace('`', ''), 16) - pe.image_base
    return out


def _find_cdb():
    root = r'C:\Program Files\WindowsApps'
    if not os.path.isdir(root):
        return None
    for d in sorted(os.listdir(root), reverse=True):
        if d.startswith('Microsoft.WinDbg_') and d.endswith('_x64__8wekyb3d8bbwe'):
            c = os.path.join(root, d, 'amd64', 'cdb.exe')
            if os.path.exists(c):
                return c
    return None


# --------------------------------------------------------------------------- main

def scan_image(path, sympath, show_coverage=False):
    pe = PE(path)
    inconclusive = []
    print('=' * 78)
    print('%s' % os.path.basename(path))
    print('  sha256 %s' % pe.sha256)
    print('  timestamp %08X   declared functions %d' % (pe.timestamp, len(pe.runtime_functions())))

    residual = {'repertoire': 0}
    cov = coverage(pe)
    if show_coverage:
        print('  declared-function bytes: %d decoded of %d (%.2f%%), %d truncated'
              % (cov['decoded'], cov['declared'],
                 100.0 * cov['decoded'] / max(cov['declared'], 1), cov['truncated']))
        print('  executable-section bytes: %d swept of %d (%.2f%%)'
              % (cov['swept'], cov['executable'],
                 100.0 * cov['swept'] / max(cov['executable'], 1)))
        print('  bytes in executable sections not covered by any declared function: %d'
              % max(cov['executable'] - cov['declared'], 0))

    # ---- reading A: sound over every executable byte
    passes, union = privileged_instructions(pe)
    print('  privileged instructions (vmcall/vmmcall/rdmsr/wrmsr): %d' % len(union))
    raw_shadowed, raw_unexamined = [], []
    _cov = covered_bytes(pe, pe.aligned_instructions())
    for rva, name in sorted(passes['raw_only']):
        width = 3 if name in ('vmcall', 'vmmcall') else 2
        span = range(rva, min(rva + width, len(_cov)))
        (raw_shadowed if all(_cov[k] for k in span) else raw_unexamined).append((rva, name))
    if passes['raw_only']:
        print('  raw opcode byte matches no decoder placed at a boundary: %d'
              ' (%d shadowed by an instruction covering their bytes, %d unexamined)'
              % (len(passes['raw_only']), len(raw_shadowed), len(raw_unexamined)))
        for rva, name in raw_unexamined[:5]:
            print('     UNEXAMINED %-8s +%06X' % (name, rva))
    if raw_unexamined:
        inconclusive.append('%d raw opcode byte match(es) in bytes no recognised'
                            ' instruction covers' % len(raw_unexamined))
    print('     by pass: declared-functions %d, linear sweep %d, raw opcode bytes %d'
          % (len(passes['declared']), len(passes['swept']), len(passes['raw'])))
    for rva, name in sorted(union)[:12]:
        print('     %-8s +%06X' % (name, rva))

    written, compared, shadowed, unexamined = debug_immediates(pe)
    print('  0069/006A/006B at a recognised instruction boundary: %d written,'
          ' %d compared-only' % (len(written), len(compared)))
    for (rva, text) in sorted(written):
        print('     WRITTEN +%06X  %s' % (rva, text))
    print('  ... and at offsets no pass recognises as a boundary: %d candidate decoding(s)'
          % (len(shadowed) + len(unexamined)))
    print('        of which %d are shadows of an instruction that covers their bytes, and'
          ' %d sit in bytes no recognised instruction covers' % (len(shadowed), len(unexamined)))
    for rva, mnem, ops, _imm, _sz in unexamined[:5]:
        print('     UNEXAMINED +%06X  %s %s' % (rva, mnem, ops))
    if unexamined:
        inconclusive.append('%d debug-code candidate(s) in bytes no recognised instruction'
                            ' covers' % len(unexamined))

    syndbg_imm = syndbg_immediates(pe)
    print('  SynDbg MSR numbers (400000F0-FF) as an immediate anywhere: %d' % len(syndbg_imm))
    for rva, mnem, ops, _imm, _sz in syndbg_imm[:8]:
        print('     +%06X  %s %s' % (rva, mnem, ops))

    syndbg, syndbg_unres = msr_sites(pe, SYNDBG_LO, SYNDBG_HI)
    synthetic, _ = msr_sites(pe, 0x40000000, 0x4FFFFFFF)
    print('  rdmsr/wrmsr with a resolved SynDbg index: %d   (any synthetic MSR, as the'
          ' scanner control: %d; indices that did not resolve: %d -- which is why the'
          ' immediate reading above is the one that decides)'
          % (len(syndbg), len(synthetic), len(syndbg_unres)))

    # ---- reading B: the repertoire, a lower bound
    symbols = load_symbols(path, sympath, list(PAGE_GLOBALS))
    page = page_global_rvas(pe, symbols)
    codes = {}
    if not page:
        print('  hypercall page globals: NOT RESOLVED -- repertoire NOT ENUMERATED')
        print('     (reading B needs --symbols; reading A above stands on its own)')
        inconclusive.append('hypercall page globals unresolved, so no repertoire was enumerated')
    else:
        roles = derive_invokers(pe, page)
        for code, sites in roles['literal'].items():
            codes.setdefault(code, []).extend(sites)
        invokers = close_forwarders(pe, roles['wrapper'])
        print('  page call sites: %d literal, %d wrapper function(s), %d unresolved;'
              ' %d reference-only function(s)'
              % (sum(len(v) for v in roles['literal'].values()), len(roles['wrapper']),
                 len(roles['unresolved']), len(roles['reference'])))
        for r in invokers:
            kind = 'wrapper' if r in roles['wrapper'] else 'forwarder'
            print('     %-10s +%06X' % (kind, r))
        sites = control_codes(pe, invokers)
        for s in sites:
            if s['code'] is not None:
                codes.setdefault(s['code'] & 0xFFFF, []).append((s['caller'], s['site']))
        unresolved = sum(1 for s in sites if s['code'] is None)
        print('  call sites into a wrapper: %d (%d resolved, %d unresolved here,'
              ' %d unresolved at a page call)'
              % (len(sites), len(sites) - unresolved, unresolved,
                 len(roles['unresolved'])))
        print('  distinct control codes resolved: %d  (a heuristic lower bound, not the'
              ' verdict)' % len(codes))
        if not codes:
            # The repertoire exists to show the scan is not broken. If it recovered
            # nothing, it has not done that, and a negative resting beside it is not
            # supported whatever the other readings say.
            inconclusive.append('the repertoire resolved no control code at all, so the'
                                ' negative control did not run')
        residual['repertoire'] = unresolved + len(roles['unresolved'])
        line = ['%04X' % c for c in sorted(codes)]
        for i in range(0, len(line), 16):
            print('     %s' % ' '.join(line[i:i + 16]))

    # The verdict is reading A's. B can raise an alarm - a debug code it *did* resolve is
    # a finding - but it can never clear one, because it does not follow control flow.
    # Every mechanism the clean line claims is absent has to be tested here, or the
    # sentence is broader than the condition that prints it.
    hypercall_insns = [(r, m) for r, m in union if m in ('vmcall', 'vmmcall')]
    hits = [c for c in DEBUG_CODES if c in codes]
    found = []
    if hits:
        found.append('repertoire resolves %s'
                     % ', '.join('%04X %s' % (c, DEBUG_CODES[c]) for c in hits))
    if written:
        found.append('%d debug code(s) written as an immediate' % len(written))
    if syndbg_imm:
        found.append('%d SynDbg MSR number(s) present as an immediate' % len(syndbg_imm))
    if hypercall_insns:
        found.append('%d vmcall/vmmcall instruction(s)' % len(hypercall_insns))

    if found:
        print('  DEBUG HYPERCALL ROUTE FOUND: %s' % '; '.join(found))
    elif inconclusive:
        print('  DEBUG HYPERCALL ROUTE: none found -- INCONCLUSIVE, because:')
        for why in inconclusive:
            print('     - %s' % why)
    else:
        # Deliberately not "no debug hypercall is issued". Each clause below names the
        # check that produced it, and the residual is printed with them rather than left
        # for a reader to remember: a wrapper site whose rcx did not resolve could carry
        # a code this scan cannot see, by the same data-loaded or computed routes the
        # limits name. Making those sites invalidate the run was considered and declined
        # -- every sampled build has some, so it would render every result inconclusive
        # and delete the reading rather than qualify it.
        print('  NO DEBUG HYPERCALL ROUTE VISIBLE TO THIS SCAN')
        print('     (across %d executable bytes: no debug code as an immediate at a'
              ' recognised instruction boundary -- %d unaligned candidate(s), all shadows'
              ' of instructions that cover their bytes -- no SynDbg MSR number as an'
              ' immediate at any alignment, no vmcall/vmmcall)'
              % (cov['executable'], len(shadowed)))
        print('     residual: %d repertoire site(s) and %d rdmsr/wrmsr site(s) whose'
              ' operand did not resolve, any of which could carry a value this scan does'
              ' not read -- a constant in a data section is not an immediate in a code'
              ' section' % (residual['repertoire'], len(syndbg_unres)))

    return dict(path=path, codes=sorted(codes), debug=hits, written=len(written),
                privileged=len(union), syndbg=len(syndbg_imm), found=found,
                inconclusive=inconclusive)


def scan_control(path):
    """The positive control: Windows' KD transport over the hypervisor debug facility."""
    pe = PE(path)
    print('=' * 78)
    print('POSITIVE CONTROL  %s' % path)
    print('  sha256 %s' % pe.sha256)
    ex = pe.exports()
    print('  exports: %s' % (', '.join(sorted(ex)) if ex else 'none'))
    _passes, union = privileged_instructions(pe)
    print('  privileged instructions: %d  %s'
          % (len(union), ', '.join('%s@+%06X' % (m, r) for r, m in sorted(union))))
    written, compared, _shadowed, _unexamined = debug_immediates(pe)
    distinct = sorted(set(written.values()))
    print('  0069/006A/006B as an immediate: %d written (%d distinct: %s), %d compared-only'
          % (len(written), len(distinct), ' '.join('%04X' % c for c in distinct), len(compared)))
    for (rva, text) in sorted(written):
        print('     WRITTEN +%06X  %s' % (rva, text))
    # Specifically a hypercall instruction: `union` also holds rdmsr/wrmsr, and a control
    # that passes on those would validate the scanner without exercising the mechanism it
    # exists to demonstrate.
    hypercall_insns = [(r, m) for r, m in union if m in ('vmcall', 'vmmcall')]
    ok = set(distinct) == set(DEBUG_CODES) and bool(hypercall_insns)
    print('  hypercall instructions among them: %d  %s'
          % (len(hypercall_insns),
             ', '.join('%s@+%06X' % (m, r) for r, m in sorted(hypercall_insns)) or '(none)'))
    print('  CONTROL %s -- the scanner %s all three distinct debug codes and a'
          ' vmcall/vmmcall where they are known to be'
          % ('PASSES' if ok else 'FAILS', 'finds' if ok else 'does NOT find'))
    print('     (this shows the immediate scan works; it does not trace a code into the'
          ' vmcall, which no image is scanned for)')
    return ok


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('images', nargs='*', help='securekernel.exe samples to scan')
    ap.add_argument('--control', metavar='KDHVCOM',
                    help='run the positive control over kdhvcom.dll')
    ap.add_argument('--symbols', metavar='PATH', default=os.environ.get('_NT_SYMBOL_PATH'),
                    help='symbol path for cdb; required to enumerate the repertoire')
    ap.add_argument('--coverage', action='store_true',
                    help='report executable bytes examined by each pass')
    args = ap.parse_args(argv)

    if not args.control and not args.images:
        ap.error('give at least one image, or --control')

    ok = True
    controlled = False
    if args.control:
        ok = scan_control(args.control)
        controlled = True
    rows = [scan_image(p, args.symbols, args.coverage) for p in args.images]

    if rows and not controlled:
        # This file says a failing control voids every negative. A run with no control
        # at all is the same situation with less information, so it cannot be allowed to
        # exit 0 -- a scanner regression or a capstone change would otherwise show up as
        # a clean result.
        print()
        print('UNVALIDATED: no positive control was run, so these negatives are not'
              ' supported.')
        print('  Re-run with --control <path to kdhvcom.dll> (Windows ships it in'
              ' System32).')
        ok = False

    if rows:
        print()
        # `route`, not `debugHC`: the column is populated from every mechanism the
        # verdict tests, not from the debug-hypercall reading alone.
        print('%-42s %6s %8s %8s %6s %s'
              % ('image', 'codes', 'route', 'written', 'privil', 'verdict'))
        for r in rows:
            verdict = ('ROUTE FOUND' if r['found']
                       else ('inconclusive' if r['inconclusive'] else 'none'))
            print('%-42s %6d %8s %8d %6d %s'
                  % (os.path.basename(r['path']), len(r['codes']),
                     ('YES' if r['found'] else 'none'), r['written'],
                     r['privileged'], verdict))
        # `found` rather than `debug`: a debug code the immediate scan saw but the
        # heuristic repertoire did not resolve is still a definitive finding, and exiting
        # 0 on it would hand automation a clean result for the opposite of one.
        if any(r['found'] or r['inconclusive'] for r in rows):
            ok = False
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
