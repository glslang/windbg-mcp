#!/usr/bin/env python3
"""Enumerate a Secure Kernel image's hypercall repertoire, and check it for debug hypercalls.

`FOLLOWUPS.md` item 103 gate S5a. The question it answers is whether `securekernel.exe`
contains *any* route to the hypervisor's debugging facility - the three hypercalls a Windows
KD transport uses (`HvPostDebugData` 0x0069, `HvRetrieveDebugData` 0x006A,
`HvResetDebugSession` 0x006B) or the synthetic-debugger MSRs (0x400000F0-0x400000FF).

It is a pure PE parse plus capstone: no debugger, no target, no driver, no VM. Symbols are
optional and are used only to *name* what the scan has already found structurally.

Why it derives the invoker set rather than naming it
----------------------------------------------------
A first pass listed the hypercall wrappers by symbol and missed two things at once: the
generic invoker is `HvcallpInitiateHypercall` before 26100 and `HvcallInitiateHypercall`
after, and some callers (`ShvlNotifyLongSpinWait`, `ShvlNotifyRootCrashdump`) load the
hypercall page and call it inline rather than going through a wrapper. Both misses are
silent - they subtract call sites from a scan whose whole output is "we found no debug
hypercall". So the set is derived instead: no sampled `securekernel.exe` contains a
`vmcall`/`vmmcall` instruction, which means every hypercall goes through the hypercall code
page, and the page lives in two globals. Every function that loads one of them and calls
through it is an invoker, whatever it is called.

Controls, because a scan that finds nothing is indistinguishable from a broken one
---------------------------------------------------------------------------------
* `--coverage` reports how much of the image's declared code capstone actually decoded.
* the repertoire itself is the negative control: a Secure Kernel that issues *no* hypercall
  is a broken scan, not a finding.
* `--control <kdhvcom.dll>` runs the same scanner over Windows' own KD-over-hypervisor
  transport, which must show all three debug codes. If it does not, every negative is void.

Usage
-----
    python sk_hypercall_scan.py securekernel.exe [more.exe ...]
    python sk_hypercall_scan.py --control C:\\Windows\\System32\\kdhvcom.dll
    python sk_hypercall_scan.py --coverage securekernel.exe

`--symbols <path>` names a symbol path for cdb; without it the scan still runs and reports
addresses instead of names. Note that cdb names a module after its *file*, so a sample kept
as `securekernel-10.0.29648.1000.exe` answers to `securekernel_10_0_29648_1000!` and every
`x securekernel!...` silently returns nothing - this script stages each sample under the
real image name before asking.
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
        """(begin, end, [instructions]) for every function the image declares."""
        for (b, e) in self.runtime_functions():
            code = self.read(b, e - b)
            if code:
                yield b, e, list(MD.disasm(code, self.image_base + b))


# ------------------------------------------------------------------ abstract eval

_PARENT = {'eax': 'rax', 'ax': 'rax', 'al': 'rax', 'ecx': 'rcx', 'cx': 'rcx', 'cl': 'rcx',
           'edx': 'rdx', 'dx': 'rdx', 'dl': 'rdx', 'ebx': 'rbx', 'bx': 'rbx', 'bl': 'rbx',
           'esi': 'rsi', 'edi': 'rdi', 'ebp': 'rbp',
           'r8d': 'r8', 'r9d': 'r9', 'r10d': 'r10', 'r11d': 'r11',
           'r12d': 'r12', 'r13d': 'r13', 'r14d': 'r14', 'r15d': 'r15'}
VOLATILE = ('rax', 'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11')


def _norm(reg):
    return _PARENT.get(reg, reg)


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
    v = regs.get(_norm(base))
    if isinstance(v, tuple) and v[0] == 'rsp':
        return v[1] + op.mem.disp
    return None


PARAM_RCX = ('param', 'rcx')


def _eval(pe, insns, on_call):
    """Walk one function keeping an abstract value per register and per frame slot.

    Straight-line only - no branch merging - so a value set on one side of a branch reads
    as unknown rather than as a guess. `on_call(insn, regs)` is invoked at every call.

    rcx starts as PARAM_RCX rather than unknown, so a wrapper that passes its own first
    argument straight through can be told apart from one that computes a code. That
    distinction is what makes the forwarder closure below sound: a function is only added
    to the invoker set when the control code it passes is the one it was given.
    """
    regs, slots, rsp_delta = {'rcx': PARAM_RCX}, {}, 0
    for ins in insns:
        ops, m = ins.operands, ins.mnemonic
        if m == 'call':
            on_call(ins, regs)
            for r in VOLATILE:
                regs[r] = None
            continue
        if m == 'jmp' and ops and ops[0].type in (CS_OP_REG, CS_OP_MEM):
            # An indirect jmp is a tail call - `jmp rax` through the hypercall page is how
            # one of these wrappers reaches the hypervisor. A `jmp imm` is a local branch
            # and is deliberately not treated as one.
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
                val = ('rsp', rsp_delta) if sname == 'rsp' else regs.get(_norm(sname))
            else:
                k = _slot(ins, src, rsp_delta, regs)
                if k is None and src.mem.base and ins.reg_name(src.mem.base) == 'rip':
                    val = ('@', ins.address + ins.size + src.mem.disp - pe.image_base)
                else:
                    val = slots.get(k) if k is not None else None
            if dst.type == CS_OP_REG:
                regs[_norm(ins.reg_name(dst.reg))] = val
            else:
                k = _slot(ins, dst, rsp_delta, regs)
                if k is not None:
                    slots[k] = val
        elif m == 'xor' and len(ops) == 2 and ops[0].type == ops[1].type == CS_OP_REG \
                and ins.reg_name(ops[0].reg) == ins.reg_name(ops[1].reg):
            regs[_norm(ins.reg_name(ops[0].reg))] = 0
        elif m in ('or', 'bts', 'add', 'and', 'sub', 'shl', 'imul') and len(ops) == 2:
            # A wrapper does not necessarily hand its control code on untouched: the fast
            # path folds it into the hypercall input value (`or rcx, r10` then
            # `bts rcx, 0x10`). So the parameter marker has to survive arithmetic, or the
            # forwarder closure stops at the wrappers that matter most.
            if ops[1].type == CS_OP_IMM:
                src = ops[1].imm
            elif ops[1].type == CS_OP_REG:
                src = regs.get(_norm(ins.reg_name(ops[1].reg)))
            else:
                k = _slot(ins, ops[1], rsp_delta, regs)
                src = slots.get(k) if k is not None else None

            def apply(cur):
                if cur == PARAM_RCX or src == PARAM_RCX:
                    return PARAM_RCX
                if m == 'and' and src == 0:
                    return 0
                if not isinstance(cur, int) or not isinstance(src, int):
                    return None
                if m == 'bts':
                    return cur | (1 << src)
                return {'or': lambda a, b: a | b, 'and': lambda a, b: a & b,
                        'add': lambda a, b: a + b, 'sub': lambda a, b: a - b,
                        'shl': lambda a, b: a << b,
                        'imul': lambda a, b: a * b}[m](cur, src)
            if ops[0].type == CS_OP_REG:
                r = _norm(ins.reg_name(ops[0].reg))
                regs[r] = apply(regs.get(r))
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
                    bv = 0 if base is None else regs.get(_norm(base))
                    if isinstance(bv, tuple) and bv[0] == 'rsp':
                        val = ('rsp', bv[1] + mem.disp)
                    elif isinstance(bv, int):
                        val = bv + mem.disp
            regs[_norm(ins.reg_name(ops[0].reg))] = val
        elif ops and ops[0].type == CS_OP_REG and m not in ('cmp', 'test'):
            regs[_norm(ins.reg_name(ops[0].reg))] = None


# ----------------------------------------------------------------- the scan itself

def hypercall_instructions(pe):
    out = []
    for b, _e, insns in pe.functions():
        for ins in insns:
            if ins.mnemonic in ('vmcall', 'vmmcall'):
                out.append((b, ins.address - pe.image_base, ins.mnemonic))
    return out


def page_global_rvas(pe, symbols):
    return {symbols[g] for g in PAGE_GLOBALS if g in symbols}


def derive_invokers(pe, page_rvas):
    """Classify every function that loads a hypercall-page global.

    Returns {function_rva: (role, codes)} where role is:

    * ``'literal'``    - it calls the page with the control code built in place. Those codes
                         are the answer for this function and its *callers* say nothing, so
                         they must not be enumerated. `SkeBugCheckEx` is the case that
                         forces this: it reaches the page with a literal 0x0087, and
                         treating it as a wrapper made every `KeBugCheckEx(code, ...)` call
                         site in the image look like a hypercall and read each **bug check
                         code** as a control code. Bug check 0x69 exists, so that is a route
                         to a false positive on exactly the question being asked.
    * ``'wrapper'``    - it reaches the page with the control code it was handed, so its
                         callers are where the codes are.
    * ``'unresolved'`` - it calls the page with a code this scan cannot recover.
    * ``'reference'``  - it names the page without calling it: a range check, or the code
                         that installs it.
    """
    found = {}
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

        seen = []

        def at_call(ins, regs, _seen=seen):
            ops = ins.operands
            if not ops:
                return
            through = False
            if ops[0].type == CS_OP_REG:  # also reached as `jmp rax`, a tail call
                v = regs.get(_norm(ins.reg_name(ops[0].reg)))
                through = isinstance(v, tuple) and v[0] == '@' and v[1] in page_rvas
            elif ops[0].type == CS_OP_MEM and ops[0].mem.base \
                    and ins.reg_name(ops[0].mem.base) == 'rip':
                through = (ins.address + ins.size + ops[0].mem.disp
                           - pe.image_base) in page_rvas
            if through:
                _seen.append(regs.get('rcx'))

        _eval(pe, insns, at_call)
        if not seen:
            found[b] = ('reference', [])
        elif any(v == PARAM_RCX for v in seen):
            found[b] = ('wrapper', [])
        elif all(isinstance(v, int) for v in seen):
            found[b] = ('literal', [v & 0xFFFF for v in seen])
        else:
            found[b] = ('unresolved', [v & 0xFFFF for v in seen if isinstance(v, int)])
    return found


def close_forwarders(pe, invokers):
    """Add wrappers that pass their own first argument through to an invoker.

    `ShvlpInitiateFastHypercall`, `HvcallpExtendedFastHypercallWithOutput` and
    `ShvlpInitiateRepListHypercall` never touch the hypercall page themselves - they call
    something that does, handing on the control code they were given - so a set derived
    only from page references stops one level short and silently loses most of the call
    sites. Iterate to a fixpoint, adding a function only when the rcx it hands on is
    *derived from* the rcx it received - derived rather than equal, because the fast path
    folds the code into the hypercall input value (`or rcx, r10`, `bts rcx, 0x10`) rather
    than passing it untouched, and an equality test stops at the wrappers that matter most.
    """
    invokers = set(invokers)
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
    """Every call into an invoker, with the control code in rcx where it is a literal."""
    targets = {pe.image_base + r for r in invoker_rvas}
    sites = []
    for b, _e, insns in pe.functions():
        def at_call(ins, regs):
            ops = ins.operands
            if ops and ops[0].type == CS_OP_IMM and ops[0].imm in targets:
                v = regs.get('rcx')
                sites.append(dict(caller=b, site=ins.address - pe.image_base,
                                  invoker=ops[0].imm - pe.image_base,
                                  code=v if isinstance(v, int) else None))
        _eval(pe, insns, at_call)
    return sites


def debug_immediates(pe):
    """0069/006A/006B immediates, split by whether they are written or only compared."""
    written, compared = [], []
    for _b, _e, insns in pe.functions():
        for ins in insns:
            for op in ins.operands:
                if op.type == CS_OP_IMM and op.imm in DEBUG_CODES:
                    rec = (ins.address - pe.image_base, '%s %s' % (ins.mnemonic, ins.op_str))
                    (compared if ins.mnemonic in ('cmp', 'test') else written).append(rec)
                    break
    return written, compared


def msr_sites(pe, lo, hi):
    out = []
    for b, _e, insns in pe.functions():
        last = {'v': None}
        for ins in insns:
            if ins.mnemonic in ('rdmsr', 'wrmsr'):
                if last['v'] is not None and lo <= last['v'] <= hi:
                    out.append((b, ins.address - pe.image_base, ins.mnemonic, last['v']))
                continue
            ops = ins.operands
            if ins.mnemonic == 'mov' and len(ops) == 2 and ops[0].type == CS_OP_REG \
                    and ops[1].type == CS_OP_IMM \
                    and _norm(ins.reg_name(ops[0].reg)) == 'rcx':
                last['v'] = ops[1].imm & 0xFFFFFFFF
            elif ins.mnemonic == 'xor' and ins.op_str in ('ecx, ecx', 'rcx, rcx'):
                last['v'] = 0
    return out


def coverage(pe):
    declared = decoded = truncated = 0
    for b, e, insns in pe.functions():
        n = e - b
        declared += n
        got = sum(i.size for i in insns)
        decoded += got
        if got < n - 15:
            truncated += 1
    return declared, decoded, truncated


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
    print('=' * 78)
    print('%s' % os.path.basename(path))
    print('  sha256 %s' % pe.sha256)
    print('  timestamp %08X   declared functions %d' % (pe.timestamp, len(pe.runtime_functions())))

    if show_coverage:
        declared, decoded, trunc = coverage(pe)
        print('  decode coverage: %d of %d bytes (%.2f%%), %d functions truncated'
              % (decoded, declared, 100.0 * decoded / max(declared, 1), trunc))

    hv = hypercall_instructions(pe)
    print('  vmcall/vmmcall instructions: %d' % len(hv))

    symbols = load_symbols(path, sympath, list(PAGE_GLOBALS))
    page = page_global_rvas(pe, symbols)
    if not page:
        print('  hypercall page globals: NOT RESOLVED - control codes not enumerated')
        print('  (supply --symbols; without them this scan cannot find the invokers)')
        codes, sites = {}, []
    else:
        roles = derive_invokers(pe, page)
        wrappers = [r for r, (v, _c) in roles.items() if v == 'wrapper']
        invokers = close_forwarders(pe, wrappers)
        codes = {}
        print('  functions touching the hypercall page: %d' % len(roles))
        for r in sorted(roles):
            role, found = roles[r]
            extra = ('  codes ' + ' '.join('%04X' % c for c in found)) if found else ''
            print('     %-10s +%06X%s' % (role, r, extra))
            for c in found:
                codes.setdefault(c, []).append(dict(caller=r, site=r, invoker=r, code=c))
        for r in invokers:
            if r not in wrappers:
                print('     forwarder  +%06X  (hands on the code it was given)' % r)

        sites = control_codes(pe, invokers)
        for s in sites:
            if s['code'] is not None:
                codes.setdefault(s['code'] & 0xFFFF, []).append(s)
        unresolved = sum(1 for s in sites if s['code'] is None)
        print('  call sites into a wrapper: %d (%d resolved, %d unresolved)'
              % (len(sites), len(sites) - unresolved, unresolved))
        print('  distinct control codes: %d' % len(codes))
        line = ['%04X' % c for c in sorted(codes)]
        for i in range(0, len(line), 16):
            print('     %s' % ' '.join(line[i:i + 16]))

    hits = [c for c in DEBUG_CODES if c in codes]
    print('  DEBUG HYPERCALLS ISSUED: %s'
          % (', '.join('%04X %s' % (c, DEBUG_CODES[c]) for c in hits) if hits else 'none'))

    written, compared = debug_immediates(pe)
    print('  0069/006A/006B as an immediate: %d written, %d compared-only'
          % (len(written), len(compared)))
    for rva, text in written:
        print('     WRITTEN +%06X  %s' % (rva, text))

    syndbg = msr_sites(pe, SYNDBG_LO, SYNDBG_HI)
    synthetic = msr_sites(pe, 0x40000000, 0x4FFFFFFF)
    print('  SynDbg MSR sites: %d   (any synthetic MSR, as the scanner control: %d)'
          % (len(syndbg), len(synthetic)))
    return dict(path=path, codes=sorted(codes), sites=len(sites), debug=hits,
                written=len(written), vmcall=len(hv), syndbg=len(syndbg))


def scan_control(path):
    """The positive control: Windows' KD transport over the hypervisor debug facility."""
    pe = PE(path)
    print('=' * 78)
    print('POSITIVE CONTROL  %s' % path)
    print('  sha256 %s' % pe.sha256)
    ex = pe.exports()
    print('  exports: %s' % ', '.join(sorted(ex)) if ex else '  exports: none')
    hv = hypercall_instructions(pe)
    print('  vmcall/vmmcall instructions: %d  %s'
          % (len(hv), ', '.join('%s@+%06X' % (m, r) for _f, r, m in hv)))
    written, compared = debug_immediates(pe)
    print('  0069/006A/006B as an immediate: %d written, %d compared-only'
          % (len(written), len(compared)))
    for rva, text in written:
        print('     WRITTEN +%06X  %s' % (rva, text))
    ok = len(written) == 3 and len(hv) >= 1
    print('  CONTROL %s - the scanner %s find the debug hypercalls where they are known to be'
          % ('PASSES' if ok else 'FAILS', 'does' if ok else 'does NOT'))
    return ok


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('images', nargs='*', help='securekernel.exe samples to scan')
    ap.add_argument('--control', metavar='KDHVCOM',
                    help='run the positive control over kdhvcom.dll')
    ap.add_argument('--symbols', metavar='PATH', default=os.environ.get('_NT_SYMBOL_PATH'),
                    help='symbol path for cdb (default: _NT_SYMBOL_PATH)')
    ap.add_argument('--coverage', action='store_true',
                    help='report how much declared code was decoded')
    args = ap.parse_args(argv)

    if not args.control and not args.images:
        ap.error('give at least one image, or --control')

    ok = True
    if args.control:
        ok = scan_control(args.control)
    rows = [scan_image(p, args.symbols, args.coverage) for p in args.images]

    if rows:
        print()
        print('%-42s %6s %6s %8s %8s %7s' % ('image', 'sites', 'codes', 'debugHC', 'written', 'vmcall'))
        for r in rows:
            print('%-42s %6d %6d %8s %8d %7d'
                  % (os.path.basename(r['path']), r['sites'], len(r['codes']),
                     ('YES' if r['debug'] else 'none'), r['written'], r['vmcall']))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
