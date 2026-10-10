// What the pane knows, folded from windbg-mcp tool calls. Pure functions over `View`, so the
// tests can drive them with payloads recorded from a real server.

import type { Bp, Frame, Ins, LogEntry, Reg, Session, SkStop, View } from '../types'

export const EMPTY: View = { n: 0, current: null, sessions: [], log: [], autoOpened: false, lastShape: '' }

const LOG_KEEP = 80
const DIS_KEEP = 64
const MEM_KEEP = 512

export const OPEN =
  /^(launch|open_dump|open_trace|open_sk_capture|open_sk_live_control|open_sk_kd|attach_kernel|attach_kernel_local|attach_process)$/
export const RUN =
  /^(go|step_into|step_over|reverse_go|step_back|step_over_back|run_to_address|continue_async|wait_for_stop|goto_position)$/
/** The live Secure Kernel calls that put the VP back to running and answer with an epoch alone. */
export const SK_RESUME = /^(sk_live_arm|sk_live_step|sk_live_continue)$/

/** The windbg-mcp tool a Claude Code tool name calls, or null: any MCP server whose name says windbg. */
export function windbgTool(name: string): string | null {
  if (!name.startsWith('mcp__')) return null
  const cut = name.lastIndexOf('__')
  if (cut <= 5) return null
  return /windbg/i.test(name.slice(5, cut)) ? name.slice(cut + 2) : null
}

/** An address as lower-case hex with no prefix, padding or WinDbg backtick; null if it is not one. */
export function norm(a: unknown): string | null {
  if (typeof a !== 'string' && typeof a !== 'number') return null
  let s = String(a).trim().toLowerCase().replace(/`/g, '')
  if (s.startsWith('0x')) s = s.slice(2)
  if (!/^[0-9a-f]+$/.test(s)) return null
  return s.replace(/^0+(?=.)/, '')
}

/** WinDbg's 64-bit spelling: sixteen digits, a backtick between the halves. */
export function wd(a: unknown): string {
  const n = norm(a)
  if (n === null) return String(a)
  if (n.length > 16) return n
  const p = n.padStart(16, '0')
  return p.slice(0, 8) + '`' + p.slice(8)
}

export function regHex(v: unknown): string {
  const n = norm(v)
  if (n === null) return String(v)
  return n.length <= 16 ? n.padStart(16, '0') : n
}

/** The WinDbg command a call stands for, where there is one; null means show the tool call itself. */
export function commandFor(tool: string, args: Record<string, unknown>): string | null {
  const s = (k: string) => (typeof args[k] === 'string' ? (args[k] as string) : undefined)
  const n = (k: string) => (typeof args[k] === 'number' ? (args[k] as number) : undefined)
  switch (tool) {
    case 'go': return 'g'
    case 'step_over': return 'p'
    case 'step_into': return 't'
    case 'reverse_go': return 'g-'
    case 'step_back': return 't-'
    case 'step_over_back': return 'p-'
    case 'registers': return 'r'
    case 'backtrace': return 'k'
    case 'modules': return 'lm'
    case 'threads': return '~'
    case 'breakpoints': return 'bl'
    case 'disassemble': return 'u' + (s('address') ? ' ' + s('address') : '') + (n('count') ? ' L0n' + n('count') : '')
    case 'read_memory': return s('address') && n('size') ? 'db ' + s('address') + ' L0n' + n('size') : null
    case 'set_breakpoint':
      if (args.watch || !s('expression')) return null
      return 'bp' + (args.one_shot ? ' /1' : '') + ' ' + s('expression')
    case 'dx': return s('expression') ? 'dx ' + s('expression') : null
    case 'execute': return s('command') ?? null
    // Live Secure Kernel control. `natural` mode arms a debug register, so `ba e1` is the honest
    // equivalent; `sk_live_wait` is the debugger blocking for the stop and has no WinDbg spelling.
    case 'sk_live_arm': return s('address') ? 'ba e1 ' + s('address') : null
    case 'sk_live_step': return 't'
    case 'sk_live_continue': return 'g'
    case 'sk_live_registers': return 'r'
    case 'sk_live_read_memory':
      return s('address') ? 'db ' + s('address') + (n('size') ? ' L0n' + n('size') : '') : null
    default: return null
  }
}

export function argsText(args: Record<string, unknown>): string {
  const copy: Record<string, unknown> = { ...args }
  delete copy.session_id
  const t = JSON.stringify(copy)
  return t === '{}' ? '' : t
}

type Obj = Record<string, unknown>
const obj = (v: unknown): Obj | null => (v !== null && typeof v === 'object' && !Array.isArray(v) ? (v as Obj) : null)

function blocksText(blocks: unknown[]): string {
  return blocks
    .map(b => (obj(b) && typeof (b as Obj).text === 'string' ? ((b as Obj).text as string) : ''))
    .join('')
}

function parseObj(t: string): Obj | null {
  const s = t.trim()
  if (!s.startsWith('{')) return null
  try {
    return obj(JSON.parse(s))
  } catch {
    return null
  }
}

/**
 * The typed half of a windbg-mcp answer, from whichever shape the call result carries it in:
 * the MCP result's `structuredContent`, its text blocks holding the JSON, or the text the model read.
 */
export function payloadOf(result: unknown, text: unknown): Obj | null {
  const r = obj(result)
  if (r) {
    const sc = obj(r.structuredContent)
    if (sc) return sc
    if (Array.isArray(r.content)) {
      const p = parseObj(blocksText(r.content))
      if (p) return p
    }
    if (typeof r.status === 'string') return r
  }
  if (Array.isArray(result)) {
    const p = parseObj(blocksText(result))
    if (p) return p
  }
  if (typeof result === 'string') {
    const p = parseObj(result)
    if (p) return p
  }
  return typeof text === 'string' ? parseObj(text) : null
}

/** A one-line description of a result's shape, for checking what the host hands the hook. */
export function shapeOf(result: unknown, text: unknown): string {
  const r = obj(result)
  const what = r
    ? 'object {' + Object.keys(r).join(', ') + '}'
    : Array.isArray(result) ? 'array of ' + result.length : typeof result
  return 'result: ' + what + '; text: ' + (typeof text === 'string' ? text.length + ' chars' : typeof text)
}

function freshSession(v: View, id: string): Session {
  return {
    id, label: 's' + (v.sessions.length + 1), kind: '', target: '', state: 'open',
    regs: null, prevRegs: null, regsAt: -1, ip: null, ipAt: -1, movedAt: -1,
    disasm: null, frames: null, framesTruncated: false, framesAt: -1, mem: null, memAt: -1, bps: null, gone: false,
    bugCheck: null, sk: null, skPhase: '',
  }
}

/**
 * The registers of a live Secure Kernel stop, which arrive as `registers.values[]` carrying
 * `low`/`high`/`status` rather than as the flat `{ name, value }` rows every other target reports.
 * The server keeps the high half and the status on purpose, so neither is dropped here.
 */
function skRegisters(d: Obj): Reg[] | null {
  const rows = obj(d.registers)?.values
  if (!Array.isArray(rows)) return null
  return (rows as unknown[]).flatMap(x => {
    const o = obj(x)
    if (!o || typeof o.name !== 'string') return []
    const high = norm(o.high)
    const reg: Reg = { name: o.name, value: str(o.low) }
    if (high !== null && high !== '0') reg.high = str(o.high)
    if (o.status !== undefined && norm(o.status) !== '0') reg.failed = true
    return [reg]
  })
}

/** The bytes at a stop, which come as a byte array rather than as a hex string. */
function insBytes(v: unknown): string {
  if (!Array.isArray(v)) return str(v)
  return (v as unknown[])
    .map(b => (typeof b === 'number' ? b.toString(16).padStart(2, '0') : ''))
    .join('')
}

/**
 * An x64 machine frame recognised in a memory read: `rip, cs, rflags, rsp, ss` at eight-byte
 * stride — what `iretq` pops, and what the Secure Kernel's syscall prologue builds by hand. As hex
 * it is five indistinguishable quadwords; as fields, `cs` and `ss` say which ring the caller was
 * in, and at a CPL0 stop that is the whole point.
 *
 * Recognised rather than assumed, because most reads are not frames: selectors occupy the low 16
 * bits with the rest zero, `rflags` bit 1 is always set and its top half reserved, and `rip`/`rsp`
 * are non-zero. A read failing any of those gets no interpretation.
 */
export function readFrame(hex: string): NonNullable<Session['mem']>['frame'] {
  if (hex.length < 80) return undefined
  const q: bigint[] = []
  for (let i = 0; i < 5; i++) {
    let v = 0n
    for (let j = 7; j >= 0; j--) {
      const byte = hex.slice((i * 8 + j) * 2, (i * 8 + j) * 2 + 2)
      if (!/^[0-9a-fA-F]{2}$/.test(byte)) return undefined
      v = (v << 8n) | BigInt(parseInt(byte, 16))
    }
    q.push(v)
  }
  const [rip, cs, rflags, rsp, ss] = q as [bigint, bigint, bigint, bigint, bigint]
  const selector = (v: bigint) => v > 0n && v <= 0xffffn
  if (!selector(cs) || !selector(ss)) return undefined
  if ((rflags & 2n) === 0n || rflags > 0x3fffffn) return undefined
  if (rip === 0n || rsp === 0n) return undefined
  const hx = (v: bigint) => '0x' + v.toString(16).padStart(16, '0')
  return {
    rip: hx(rip),
    cs: '0x' + cs.toString(16).padStart(4, '0'),
    rflags: hx(rflags),
    rsp: hx(rsp),
    ss: '0x' + ss.toString(16).padStart(4, '0'),
    ring: Number(cs & 3n),
  }
}

/** Where a live Secure Kernel stop happened, and whether the trustlet's CR3 was still loaded. */
function skStopOf(d: Obj, regs: Reg[] | null): SkStop | null {
  const ev = obj(d.event)
  const t = obj(d.target)
  if (!ev || !t) return null
  const reason = obj(ev.reason)
  const num = (v: unknown): number => (typeof v === 'number' ? v : -1)
  const cr3 = regs?.find(r => r.name === 'cr3')?.value ?? ''
  return {
    vtl: num(ev.vtl), cpl: num(ev.cpl), vp: num(ev.vp), vector: num(ev.vector),
    reason: str(reason?.reason, str(ev.reason)),
    slot: typeof reason?.slot === 'number' ? reason.slot : null,
    partition: str(t.partition_id), expectedCr3: str(t.expected_cr3), cr3,
    epoch: str(d.epoch),
  }
}

/** A bug check from an opener's `summary` or from `crash_triage`, with whatever it blames. */
function bugCheckOf(d: Obj): Session['bugCheck'] {
  const bc = obj(d.bug_check) ?? obj(obj(d.summary)?.bug_check)
  if (!bc) return null
  const blamed = obj(d.faulting_frame)
  const analysis = obj(d.analysis)
  return {
    code: str(bc.code),
    name: str(bc.name),
    blamed: blamed
      ? str(blamed.module) + '+' + str(blamed.rva)
      : str(analysis?.module_name),
  }
}

/** A call arrived: log it as running. Returns the new view and the call's number. */
export function begin(v: View, tool: string, args: Record<string, unknown>): [View, number] {
  const n = v.n + 1
  const wdc = commandFor(tool, args)
  const sid = typeof args.session_id === 'string' ? args.session_id : OPEN.test(tool) ? null : v.current
  const entry: LogEntry = {
    n, tool, command: wdc ?? tool + (argsText(args) ? ' ' + argsText(args) : ''), isWinDbg: wdc !== null,
    session: sid, status: 'running', note: '', ms: 0,
  }
  return [{ ...v, n, log: [...v.log, entry].slice(-LOG_KEEP) }, n]
}

export type Outcome = { ok: boolean; data: Obj | null; error: string; ms: number }

function where(s: Session, ip: string | null): string {
  if (!ip) return ''
  const row = s.disasm?.rows.find(x => norm(x.address) === ip)
  return row && row.module ? row.module + '+' + row.rva : wd(ip)
}

const str = (v: unknown, d = ''): string => (typeof v === 'string' ? v : typeof v === 'number' ? String(v) : d)

/** A call answered: fold its typed result into the session it was routed to. */
export function finish(v: View, n: number, tool: string, args: Record<string, unknown>, out: Outcome): View {
  const d = out.data
  const opened = OPEN.test(tool) && out.ok && d && typeof d.session_id === 'string' ? (d.session_id as string) : null
  // An opener that fails *after* creating or claiming a target reports the only handle that
  // reaches it in its structured error, and says in `target` whether something was left behind:
  // `yes` (loaded, spawned or dialled), `pending` (the wait was abandoned, the open may still
  // land) or `unknown` (controller ownership unresolved). Openers take no `session_id` argument,
  // so without reading this the pane falls back to the previous current session — attributing the
  // failed open to an unrelated target and hiding one that may need `session_status` or
  // `end_session`. `no` is the clean case and is left alone.
  const failure = !out.ok && d ? obj(d.error) : null
  const left = !out.ok && d ? str(d.target) : ''
  const stranded =
    failure && typeof failure.session_id === 'string' && left !== '' && left !== 'no'
      ? (failure.session_id as string)
      : null
  const sid = opened ?? stranded ?? (typeof args.session_id === 'string' ? args.session_id : v.current)
  let sessions = v.sessions
  let s: Session | null = null
  if (sid) {
    const found = sessions.find(x => x.id === sid)
    // A session is otherwise invented only by a call that *succeeded*. A failure carrying an
    // unknown, expired or mistyped `session_id` would mint one, label it open with no target, and
    // — through `current` below — make the pane switch to it, hiding the real session at exactly
    // the moment a stale-handle error needed reading. A failure against a session already known
    // still updates its log, which is all a failure has to say.
    if (found) {
      s = { ...found }
      sessions = sessions.map(x => (x.id === sid ? s! : x))
    } else if (out.ok || sid === stranded) {
      s = freshSession(v, sid)
      sessions = [...sessions, s]
    }
  }
  let note = ''
  if (!out.ok) {
    note = out.error.split(/\r?\n/).find(l => l.trim()) ?? 'failed'
    if (s && sid === stranded) {
      // Not 'open': the open failed. What the pane has to carry is that a target exists and this
      // is the handle for it, which is the difference between recovering and attaching twice.
      s.kind = str(d?.kind, tool)
      s.state = left === 'pending' ? 'opening' : left === 'unknown' ? 'unresolved' : 'stranded'
      s.target = left === 'pending' ? 'open may still land' : 'target left by a failed ' + tool
      note = 'open failed, ' + (left === 'pending' ? 'may still land' : 'target left') + ' as ' + s.label + ': ' + note
    }
  } else if (s && d) {
    if (opened) {
      s.kind = str(d.kind, tool)
      s.target = str(d.target)
      s.state = 'open'
      s.gone = false
      s.bugCheck = bugCheckOf(d)
      note = 'session ' + s.label + ' opened' + (s.bugCheck ? ', bug check ' + s.bugCheck.code : '')
    }
    if (Array.isArray(d.registers)) {
      s.prevRegs = s.regs
      s.regs = (d.registers as unknown[]).flatMap(x => {
        const o = obj(x)
        return o && typeof o.name === 'string' ? [{ name: o.name, value: str(o.value) } as Reg] : []
      })
      s.regsAt = n
      const ip = norm(d.instruction_pointer)
      if (ip) { s.ip = ip; s.ipAt = n }
      note = ip ? 'rip=' + regHex(ip) : ''
    }
    // A live Secure Kernel stop, answered by `sk_live_wait` and by `sk_live_registers` alike. None
    // of the branches around this one see it: the registers are `registers.values[]` rather than an
    // array of `{ name, value }`, and the position comes from the `rip` row rather than a field.
    const skRegs = skRegisters(d)
    if (skRegs) {
      s.prevRegs = s.regs
      s.regs = skRegs
      s.regsAt = n
      const ip = norm(skRegs.find(r => r.name === 'rip')?.value)
      if (ip) { s.ip = ip; s.ipAt = n }
      const stop = skStopOf(d, skRegs)
      if (stop) {
        s.sk = stop
        s.skPhase = 'stopped'
        note = 'VTL' + stop.vtl + ' CPL' + stop.cpl + ' ' + stop.reason +
          (stop.slot !== null ? ' slot ' + stop.slot : '') + ' at ' + regHex(ip)
      } else {
        note = ip ? 'rip=' + regHex(ip) : ''
      }
      const failed = skRegs.filter(r => r.failed)
      if (failed.length) note += ', ' + failed.length + ' register(s) unreadable'
    }
    const ins = obj(d.instruction)
    if (ins && ins.address !== undefined) {
      // Live control reports the bytes it guarded and no disassembly, so the row carries no text.
      s.disasm = {
        start: str(ins.address), bytesOnly: true,
        rows: [{ address: str(ins.address), bytes: insBytes(ins.bytes), module: '', rva: '', text: '' }],
      }
    }
    if (SK_RESUME.test(tool) && typeof d.phase === 'string') {
      s.skPhase = d.phase
      s.movedAt = n
      note = d.phase + (typeof d.epoch === 'string' ? ', epoch …' + d.epoch.slice(-4) : '')
    }
    if (Array.isArray(d.instructions)) {
      const rows = (d.instructions as unknown[]).slice(0, DIS_KEEP).flatMap(x => {
        const o = obj(x)
        return o ? [{ address: str(o.address), bytes: str(o.bytes), module: str(o.module), rva: str(o.rva), text: str(o.text) } as Ins] : []
      })
      s.disasm = { start: str(d.start, rows[0]?.address ?? ''), rows }
      note = rows.length + ' instructions'
    }
    if (Array.isArray(d.frames)) {
      s.frames = (d.frames as unknown[]).flatMap(x => {
        const o = obj(x)
        return o ? [{
          index: typeof o.index === 'number' ? o.index : 0, symbol: str(o.symbol), displacement: str(o.displacement),
          module: str(o.module), rva: str(o.rva), address: str(o.address),
        } as Frame] : []
      })
      s.framesTruncated = d.frames_truncated === true
      s.framesAt = n
      note = s.frames.length + ' frames'
    }
    if (/^(read_memory|sk_live_read_memory)$/.test(tool) && typeof d.data === 'string' && d.address !== undefined) {
      const hex = d.data.replace(/[^0-9a-fA-F]/g, '')
      s.mem = { address: str(d.address), hex: hex.slice(0, MEM_KEEP * 2), size: hex.length / 2 }
      // A live VTL1 read resolves through the guest's own page tables, so it can say which physical
      // page answered — and a read shorter than the request is a fact the size alone would hide.
      if (d.gpa !== undefined) s.mem.gpa = str(d.gpa)
      const frame = readFrame(s.mem.hex)
      if (frame) s.mem.frame = frame
      s.memAt = n
      note = hex.length / 2 + ' bytes' + (d.gpa !== undefined ? ' at gpa ' + regHex(d.gpa) : '')
      if (typeof d.requested_size === 'number' && d.requested_size !== hex.length / 2) {
        note += ', ' + d.requested_size + ' requested'
      }
    }
    if (Array.isArray(d.modules) && typeof d.loaded === 'number') {
      // A fresh kernel attach holds only what it could read at connect time, so the jump a
      // refresh produces is the fact worth showing (windbg-mcp#85).
      const before = obj(d.refresh)?.before
      note = d.loaded + ' loaded' + (typeof before === 'number' && before !== d.loaded ? ', refreshed from ' + before : '')
    }
    if (Array.isArray(d.breakpoints)) {
      s.bps = (d.breakpoints as unknown[]).flatMap(x => {
        const o = obj(x)
        return o ? [{
          id: typeof o.id === 'number' ? o.id : 0, address: str(o.address), expression: str(o.expression),
          enabled: o.enabled !== false, oneShot: o.one_shot === true,
        } as Bp] : []
      })
      if (tool === 'set_breakpoint') note = s.bps.length + ' breakpoint(s)'
    }
    // Three different shapes report a run, and reading only the synchronous one left an async run
    // invisible: the pane kept prior registers, stack and memory marked current while the target
    // was moving, then never picked up the stop. `go`/`step_*` answer with `stopped_at` at the top
    // level; `continue_async` answers with `moved`/`running` and no stop at all, because the point
    // of it is that the caller left; `wait_for_stop` nests the stop under `stop`; and
    // `run_to_address` reports an ending through `verdict` rather than the boolean.
    const stop = obj(d.stop) ?? d
    const gone = stop.target_gone === true || d.verdict === 'target_gone'
    // `run_to_address` reports a timeout as a verdict and deliberately omits `stopped_at`, since
    // echoing the address asked for would say execution got there. The target still ran for the
    // whole wait, so this is movement with no position — the one combination that reads as "no
    // movement" if only the position is looked for.
    const ranOn = d.verdict === 'timeout' || (d.running === true && !('stopped_at' in stop))
    if (RUN.test(tool) && ('stopped_at' in stop || gone || ranOn || d.moved === true)) {
      s.movedAt = n
      if (gone) {
        s.gone = true
        s.ip = null
        note = 'target ended'
      } else if (ranOn) {
        // Deliberately no position: the target moved, so every earlier read is now stale and
        // saying where it *was* would be the misreading this exists to prevent.
        note =
          d.verdict === 'timeout'
            ? 'ran on, no stop within the wait'
            : 'running' + (typeof d.execution === 'string' ? ', execution ' + d.execution : '')
      } else {
        const ip = norm(stop.stopped_at)
        if (ip) { s.ip = ip; s.ipAt = n }
        note = (stop.interrupted === true ? 'broken in at ' : stop.timed_out === true ? 'wait ran out at ' : 'stopped at ') + where(s, ip)
      }
    }
    // Last, deliberately: `crash_triage` also carries `frames`, and the bug check is the headline
    // rather than how many frames came with it.
    if (tool === 'crash_triage') {
      const bc = bugCheckOf(d)
      if (bc) {
        s.bugCheck = bc
        note = bc.code + ' ' + bc.name + (bc.blamed ? ', blaming ' + bc.blamed : '')
      }
    }
    if (tool === 'end_session') {
      s.state = d.released === false ? 'unresolved' : 'closed'
      note = d.released === false ? 'released: false' : 'released'
    }
  } else if (s && RUN.test(tool)) {
    // A successful run with no typed payload still moved the target. `goto_position` seeks a TTD
    // trace by running `!tt`, which answers with debugger text, so there is nothing to fold and
    // every branch above is skipped — leaving the pane showing the position before the seek and
    // calling the registers, stack and memory read at it current. The movement is known from the
    // call succeeding; the new position is not, so it is marked moved and nothing is invented.
    s.movedAt = n
    note = 'moved, position not reported'
  }
  const current = opened ?? (sid && sessions.some(x => x.id === sid) ? sid : v.current)
  const log = v.log.map(e =>
    e.n === n ? { ...e, session: sid, status: out.ok ? ('ok' as const) : ('error' as const), note, ms: out.ms } : e,
  )
  return { ...v, sessions, current, log }
}
