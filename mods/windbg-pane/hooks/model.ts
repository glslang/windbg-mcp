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
    case 'read_memory':
    // The captured VTL1 read has no WinDbg spelling of its own; `db` is what it does.
    case 'sk_read_memory': return s('address') && n('size') ? 'db ' + s('address') + ' L0n' + n('size') : null
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

/**
 * Whether a call answered, from all three places a failure can arrive in.
 *
 * The host sets `isError` on the result `next` resolves to when a tool "answered an error", and an
 * MCP server's own `isError` rides on the nested record beside the payload — the same record
 * `payloadOf` reads — so which of the two carries it depends on how the host passed the call
 * through. Reading only the outer one treated every error as a success: an error payload folded
 * into the session's registers, stack and position, and an opener's failure could still mint a
 * session. And the server says so itself without either: `Outcome` is tagged on `status`
 * (`src/structured.rs`), so `status: "error"` is the one statement that is there whichever way the
 * host conveyed it, and it is the authority the other two are reporting.
 */
export function answered(result: unknown, isError: unknown, data: Obj | null): boolean {
  if (isError === true) return false
  const r = obj(result)
  if (r && r.isError === true) return false
  return !(data && data.status === 'error')
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
    disasm: null, frames: null, framesTruncated: false, framesAt: -1, mem: null, memAt: -1, bps: null, bpsAt: -1, gone: false,
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

/**
 * Whether `s.ip` is where the target is **now**, rather than where it was before the last movement.
 *
 * Every fold that sees movement with no position deliberately keeps the old `ip` and does not stamp
 * `ipAt` — a text-only `goto_position`, a `run_to_address` timeout, a stop with no thread context,
 * an outstanding asynchronous run, a raw `execute`. That care was being discarded at the draw: the
 * header printed the old address as `ip`, the disassembly marked it `▶`, and the panel note read
 * "ip is elsewhere" about a position nothing had re-read. The register grid already asked a version
 * of this question and the other three sites did not, which is how one rule came to be half
 * applied. Exported so the renderer and the tests share the one predicate.
 */
export function ipIsCurrent(s: Session): boolean {
  return !!s.ip && !s.gone && s.ipAt >= s.movedAt
}

/**
 * Whether the breakpoint inventory may have been consumed since it was read.
 *
 * The other four reads go stale on any movement; this one does not — an ordinary breakpoint
 * survives a `go`, and greying the panel on every step would be wrong. A **one-shot** does not:
 * DbgEng removes it when it is hit, so a run after the inventory was read can have deleted an
 * entry the pane would otherwise go on drawing as armed. So the condition is the two facts
 * together, which is why this is a predicate and not a `stale` flag like the others.
 */
export function bpsMayBeStale(s: Session): boolean {
  return !!s.bps && s.movedAt > s.bpsAt && s.bps.some(b => b.oneShot)
}

/**
 * The states `SessionState::accepts_default` refuses that this pane can actually name.
 *
 * `accepts_default` is `accepts_handle() || Retired`, and `accepts_handle` admits `Opening`,
 * `Attaching`, `Open` and six of the Secure Kernel KD phases — so `Failed`, `KernelUnresolved`,
 * `LiveControlUnresolved`, `Closed` and the remaining KD phases are all refused. The pane sees
 * display strings rather than that enum, so this names the four it can recognise and **cannot** be
 * complete: the KD phases in particular are a list it would have to keep in step. That is why the
 * server's own answer wins wherever it has been read — see `routed` below.
 */
const NOT_ROUTABLE = new Set(['closed', 'failed', 'unresolved', 'unknown to the server'])

/**
 * The newest session that could take an unaddressed call: `Sessions::current`'s `rev().find(…)`,
 * as far as the pane can tell. Used only as the fallback when the believed session has stopped
 * being eligible and no status call has said which one took over.
 */
function newestOpen(sessions: Session[]): string | null {
  for (let i = sessions.length - 1; i >= 0; i--) {
    if (!NOT_ROUTABLE.has(sessions[i]!.state)) return sessions[i]!.id
  }
  return null
}

function where(s: Session, ip: string | null): string {
  if (!ip) return ''
  const row = s.disasm?.rows.find(x => norm(x.address) === ip)
  return row && row.module ? row.module + '+' + row.rva : wd(ip)
}

const str = (v: unknown, d = ''): string => (typeof v === 'string' ? v : typeof v === 'number' ? String(v) : d)

/** The breakpoint rows of any listing that carries them — `breakpoints`, or a clear's `remaining`. */
function readBps(rows: unknown[]): Bp[] {
  return rows.flatMap(x => {
    const o = obj(x)
    return o
      ? [{
          id: typeof o.id === 'number' ? o.id : 0, address: str(o.address), expression: str(o.expression),
          enabled: o.enabled !== false, oneShot: o.one_shot === true,
        } as Bp]
      : []
  })
}

/**
 * A `session_status` row's state, which is tagged on `state` and carries its own reason.
 *
 * `attaching` also says whether it has been waiting longer than a healthy open ever takes, which
 * is the fact that separates a KD link coming up from a guest that was never booted in debug mode
 * — the state alone cannot. Both unresolved variants read as `unresolved`, which is what the pane
 * already calls them: the pane says what is refused, and the reason is in the log line.
 */
function sessionState(st: Obj | null): string {
  const tag = st ? str(st.state) : ''
  switch (tag) {
    case 'attaching':
      return st?.overdue === true ? 'attaching, overdue' : 'attaching'
    case 'kernel_unresolved':
    case 'live_control_unresolved':
      return 'unresolved'
    case 'secure_kernel_kd':
      return ('sk kd ' + str(st?.phase)).trim()
    default:
      return tag
  }
}

/**
 * What a `debug_batch` left the session holding, from its `after` report.
 *
 * A batch can resume, step or release the target, and `after` is the only thing that says where
 * that left the session — the step list cannot. Without reading it a batch holding a `resume` or a
 * `run_to` left the old registers, stack, memory, position and target state on screen marked
 * current.
 *
 * It is folded off the success branch because **a batch that failed still carries this report**: a
 * batch that did not commit, or whose rollback did not finish, is answered as an MCP error wrapped
 * around an `Outcome::Ok` report (`server::batch_settled`), and `after` is then the only statement
 * about what the session holds. That is the case the pane least wants to skip — `uncertain` is
 * precisely the answer that says the earlier reads can no longer be trusted.
 */
/**
 * What a batch's steps say they changed, from `BatchStepInfo::changes` in both blocks.
 *
 * Read because it is the only thing that invalidates the **disassembly**, and the stale marks the
 * other panels carry cannot stand in for it: `movedAt` is movement, and movement does not change
 * code — a listing greyed on every step would be wrong. A *patched byte* does change it, and
 * patching a byte is what `debug_batch` is for. The field is the executor's own record, "recorded
 * whether or not the step then succeeded", since a command that errors may already have written;
 * the `always` block counts too, because a rollback writes.
 */
function batchChanges(d: Obj): string[] {
  const blocks = [d.steps, d.always].flatMap(b => (Array.isArray(b) ? (b as unknown[]) : []))
  return blocks.flatMap(x => {
    const o = obj(x)
    const c = o ? str(o.changes) : ''
    return c ? [c] : []
  })
}

function foldBatch(s: Session, d: Obj, n: number): string {
  // Before the `after` guard: a batch can report what it wrote and fail to probe the session, and
  // what it wrote is true either way.
  const changed = batchChanges(d)
  // Dropped rather than stamped. A stamp would say the listing is old; this says the pane does not
  // know what is at those addresses any more, which is the honest claim once a step has written.
  if (changed.length) s.disasm = null
  const wrote = changed.length ? '; wrote ' + changed.join(', ') : ''
  const after = obj(d.after)
  if (!after) return wrote ? wrote.slice(2) : ''
  const state = str(after.state)
  const ip = norm(after.ip)
  const why = str(after.why) ? ': ' + str(after.why) : ''
  const by = str(after.by) ? ' by ' + str(after.by) : ''
  if (state === 'stopped') {
    // **The final position is not evidence that nothing ran**, and treating it as such was this
    // branch's own bug. `SessionAfterInfo::Stopped` carries the instruction pointer and nothing
    // else — there is no execution flag — and a step's `action` is rendered debugger *text*, which
    // `.claude/rules/execution-waits.md` records as unfinishable to read for whether it reaches
    // execution. A resume that loops back to the same breakpoint therefore stops exactly where it
    // started, having changed every register and whatever the target wrote.
    //
    // An earlier round was right that marking every batch as movement makes an inspection look
    // like execution, and that reading is kept — in the **note**, which is where a reading
    // belongs. It cannot be kept in the staleness, because the two errors do not cost the same: a
    // read drawn as current when the target has moved under it is the defect this whole pane is
    // about, and a panel greyed after an inspection costs one re-read.
    s.movedAt = n
    if (!ip) return 'batch stopped, position not reported' + wrote
    const same = ip === s.ip
    s.ip = ip
    s.ipAt = n
    return 'batch stopped at ' + where(s, ip) + (same ? ', position unchanged' : '') + wrote
  }
  if (state === 'running') {
    s.movedAt = n
    return 'batch left the target running' + why + wrote
  }
  if (state === 'detached') {
    s.movedAt = n
    s.state = 'detached'
    return 'batch detached the target' + by + wrote
  }
  if (state === 'ended') {
    s.movedAt = n
    s.gone = true
    s.ip = null
    return 'batch ended the target' + by + wrote
  }
  if (state === 'uncertain') {
    // The server reports not knowing rather than guessing, so neither does the pane: what it
    // cannot claim is that the reads taken before the batch still describe the target.
    s.movedAt = n
    return 'batch left the session uncertain' + why + wrote
  }
  return ''
}

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
  // `begin` already pinned which session this call was routed to, so use that rather than asking
  // `v.current` again: calls overlap, and recomputing here misfiles a result whenever another call
  // changed the current session while this one was outstanding — an implicit call that started on
  // s1 folding into s2, which then draws s1's registers, stack and memory under the wrong target.
  // The fallback is only for a call whose log entry has aged out of the ring.
  const pinned = v.log.find(e => e.n === n)?.session
  const sid =
    opened ??
    stranded ??
    (pinned !== undefined ? pinned : typeof args.session_id === 'string' ? args.session_id : v.current)
  let sessions = v.sessions
  // Set only from `SessionInfo::current`, which is the server's own answer to which session an
  // unaddressed call reaches. See the `current` computation at the end of this function.
  let routed: string | null = null
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
    // The host's text is the ordinary source. A failure the *payload* alone reported — `status`
    // with no `isError` beside it, which `answered` now catches — arrives with nothing in `text`,
    // and its message is in the structured error.
    note = out.error.split(/\r?\n/).find(l => l.trim()) ?? (failure ? str(failure.message, 'failed') : 'failed')
    if (s && sid === stranded) {
      // Not 'open': the open failed. What the pane has to carry is that a target exists and this
      // is the handle for it, which is the difference between recovering and attaching twice.
      //
      // The three words are the three `TargetCreated` variants, said as that enum says them.
      // `yes` is **not** an abandoned target: its doc is "the target exists … Do not open again;
      // use the handle, or `end_session`", and it covers both a wait that failed and an open that
      // worked whose follow-up report failed — the second being a session that is simply usable.
      // Only the message prose tells those apart (`server.rs`, `report_only`), and prose is not
      // something to branch on, so the pane says what is true of both rather than calling a
      // working session stranded.
      s.kind = str(d?.kind, tool)
      s.state = left === 'pending' ? 'opening' : left === 'unknown' ? 'unresolved' : 'held'
      s.target =
        left === 'pending'
          ? 'open may still land'
          : left === 'unknown'
            ? 'controller ownership unresolved'
            : 'target exists; use this handle or end the session'
      const what = left === 'pending' ? 'may still land' : left === 'unknown' ? 'ownership unresolved' : 'target held'
      note = 'open failed, ' + what + ' as ' + s.label + ': ' + note
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
    // `current_location` is the authoritative answer to "where is it now", and after a text-only
    // seek it is the *only* one: `goto_position` reports no position at all, so a caller asking
    // here is the pane's one way to learn it. Nothing but the register and run folds set the
    // position, so a location query that succeeded left the previous instruction drawn and marked
    // current. `location_state` is what says whether there is an address to read — a
    // `context_unavailable` position has none, and carrying the state is better than reporting a
    // query that answered as one that did nothing.
    if (tool === 'current_location') {
      const ip = norm(d.address)
      if (ip) {
        s.ip = ip
        s.ipAt = n
        const co = obj(d.coordinate)
        note = 'at ' + (co && str(co.module) ? str(co.module) + '+' + str(co.rva) : where(s, ip))
      } else {
        note = 'no position: ' + str(d.location_state, 'unknown')
      }
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
    // Three tools answer with bytes, and `sk_read_memory` was missing from the list — the one that
    // matters most for the session it belongs to, because it is the *only* guest-memory read an
    // `open_sk_capture` session has. Every capture read was therefore folded nowhere, leaving the
    // Memory panel empty or still showing an older read with nothing saying so. Its
    // `SecureKernelRead` carries the same `address`, `gpa`, `requested_size` and `data` as the live
    // control's `LiveMemoryRead`, and a `symbol` beside them where the capture's own PDBs named the
    // address.
    if (/^(read_memory|sk_read_memory|sk_live_read_memory)$/.test(tool) && typeof d.data === 'string' && d.address !== undefined) {
      const hex = d.data.replace(/[^0-9a-fA-F]/g, '')
      s.mem = { address: str(d.address), hex: hex.slice(0, MEM_KEEP * 2), size: hex.length / 2 }
      // A Secure Kernel read resolves through the guest's own page tables, so it can say which
      // physical page answered — and a read shorter than the request is a fact the size would hide.
      if (d.gpa !== undefined) s.mem.gpa = str(d.gpa)
      const frame = readFrame(s.mem.hex)
      if (frame) s.mem.frame = frame
      s.memAt = n
      note = hex.length / 2 + ' bytes' + (d.gpa !== undefined ? ' at gpa ' + regHex(d.gpa) : '')
      if (typeof d.symbol === 'string' && d.symbol) note += ', ' + d.symbol
      if (typeof d.requested_size === 'number' && d.requested_size !== hex.length / 2) {
        // `read_size` cannot say *why* a read came up short — that is what `stopped` is for, and
        // the two answers have different remedies: a deadline sends the caller back for the rest,
        // an interrupt was their own doing. `WalkHalt::phrase` writes both in one place precisely
        // so a wording invented per site cannot differ at one of them, so these are its words.
        const halt = d.stopped === 'deadline' ? ', ran out of time' : d.stopped === 'interrupted' ? ', was interrupted' : ''
        note += ', ' + d.requested_size + ' requested' + halt
      }
    }
    if (Array.isArray(d.modules) && typeof d.loaded === 'number') {
      // A fresh kernel attach holds only what it could read at connect time, so the jump a
      // refresh produces is the fact worth showing (windbg-mcp#85).
      const before = obj(d.refresh)?.before
      note = d.loaded + ' loaded' + (typeof before === 'number' && before !== d.loaded ? ', refreshed from ' + before : '')
    }
    // `breakpoints` means two different things by tool, and the difference is in the field's own
    // doc comment. On the `breakpoints` listing it *is* the answer, so empty means the session
    // holds none. On a `set_breakpoint` it is an inspection taken after a mutation that has
    // already happened, and best-effort: empty means it could not be read, and says nothing about
    // the breakpoint this call made — that one is reported separately and authoritatively in
    // `breakpoint`, which "there is no case in which it is unavailable". Replacing the inventory
    // with the empty list hid both the breakpoint just armed and everything already known, drawing
    // an unreadable session as a clean one.
    if (Array.isArray(d.breakpoints) && (tool !== 'set_breakpoint' || d.breakpoints.length > 0)) {
      s.bps = readBps(d.breakpoints)
      s.bpsAt = n
      if (tool === 'set_breakpoint') note = s.bps.length + ' breakpoint(s)'
    } else if (tool === 'set_breakpoint') {
      const set = readBps([d.breakpoint])
      // `replaced` names the breakpoints the engine removed to make room at the same resolved
      // address, so they go rather than staying on screen beside their replacement.
      const replaced = Array.isArray(d.replaced) ? d.replaced : []
      const kept = (s.bps ?? []).filter(b => !replaced.includes(b.id) && !set.some(x => x.id === b.id))
      s.bps = [...kept, ...set]
      s.bpsAt = n
      note = (set.length ? 'breakpoint ' + set[0]!.id + ' set' : 'set') + ', inventory could not be read'
    }
    // A clear answers with `remaining` and carries no `breakpoints` at all, so the branch above
    // never fired and the pane went on drawing the cleared entries as armed. `remaining` is
    // nullable where every other listing is not, deliberately: an empty array is the success state
    // after clearing everything, and `null` means the inventory could not be read. The pane's own
    // `bps: Bp[] | null` says the same thing — null hides the panel rather than asserting a count —
    // so the two meanings are kept apart instead of collapsing an unreadable session into a clean
    // one.
    if (tool === 'clear_breakpoints' && 'remaining' in d) {
      const remaining = d.remaining
      if (Array.isArray(remaining)) {
        s.bps = readBps(remaining)
        s.bpsAt = n
        note = s.bps.length === 0 ? 'all breakpoints cleared' : s.bps.length + ' breakpoint(s) remaining'
      } else {
        s.bps = null
        s.bpsAt = n
        note = 'cleared, inventory could not be read'
      }
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
    // **A stop that cannot say where is still a stop**, and looking for the position alone read it
    // as no movement at all. `StopReport::stopped_at` is absent "for a target that is running,
    // gone, or has **no thread context**" — a module-load break, a bare `goto_position` to the
    // start of a trace — and `target_gone`'s own doc says it is a separate field precisely because
    // "a target with no thread context also produces" an absent position. So a successful `go`,
    // step, reverse or nested `wait_for_stop` can carry none of the four conditions above while
    // having moved the target, and the pane went on marking the pre-run registers, stack and memory
    // current. The tell is the report itself: `command` and `output` are plain `String`s that every
    // `StopReport` carries, where `ExecutionStarted` has the first and not the second and
    // `RunToReport` the second and not the first — so this recognises a stop without claiming one
    // from either of those.
    const stopped = typeof stop.command === 'string' && typeof stop.output === 'string'
    if (RUN.test(tool) && ('stopped_at' in stop || stopped || gone || ranOn || d.moved === true)) {
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
        const how = stop.interrupted === true ? 'broken in' : stop.timed_out === true ? 'wait ran out' : 'stopped'
        // No position is not no movement, and `where` answers the empty string for one — so the
        // note said "stopped at " and the panels would have kept the position the target left.
        note = ip ? how + ' at ' + where(s, ip) : how + ', no position reported'
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
    // `session_status` is the only tool that reports what the *server* holds, and it is the answer
    // to a session a failed open left `opening`, `stranded` or `unresolved`: the comment at the
    // top of this function sends a caller here, and the pane read nothing back — so a provisional
    // state stayed on screen after the worker had resolved it one way or the other, which is the
    // recovery flow those sessions are kept for. Rows fold into the sessions the pane already
    // knows; a listing does not mint one, because the pane follows calls and a session it has seen
    // no call for has no reads to draw under it.
    if (tool === 'session_status' && Array.isArray(d.sessions)) {
      const said: string[] = []
      for (const row of d.sessions as unknown[]) {
        const o = obj(row)
        const id = o ? str(o.session_id) : ''
        const known = id ? sessions.find(x => x.id === id) : undefined
        if (!o || !known) continue
        const t = known === s ? s : { ...known }
        if (t !== known) sessions = sessions.map(x => (x === known ? t : x))
        const state = sessionState(obj(o.state))
        if (state) t.state = state
        t.kind = str(o.kind, t.kind)
        if (str(o.target)) t.target = str(o.target)
        // `execution.stopped` is the one field here that is not about the session's lifetime: it
        // says whether the run this session has outstanding has ended, and while it is false "the
        // target is moving and every tool that reads it is refused". So this is also the recovery
        // answer for a `continue_async` whose own call timed out — that failure advances nothing,
        // and until this is read the pane goes on drawing the pre-run reads as current.
        const moving = obj(o.execution)?.stopped === false
        if (moving) t.movedAt = n
        // `SessionInfo::current` — "whether a call that names no session is routed here" — is the
        // authority, and declining to read it last round was wrong. The objection was that it
        // answers about one instant and would need somewhere to live; `current` on the view is
        // that somewhere, now that it is a belief rather than a per-call derivation. It is the
        // only way the pane learns that the server has moved off a session whose ineligible state
        // the pane cannot name — a KD phase, say.
        if (o.current === true) routed = t.id
        said.push(t.label + ' ' + t.state + (moving ? ', target moving' : ''))
      }
      // An `unknown_handle` is the complement in the same payload, and reading `sessions` alone
      // conflates them: the list is empty either way, so a handle the server has never heard of
      // would read exactly like one that closed. Only the session actually asked about is touched.
      if (d.unknown_handle === true && s && str(d.asked) === s.id) {
        s.state = 'unknown to the server'
        said.push(s.label + ' unknown')
      }
      note = said.length ? said.join(', ') : (d.sessions as unknown[]).length + ' session(s)'
    }
    // `released` says whether the **worker** let go of the target itself, not whether the session
    // is still open: one that had to be killed holding its target answers `false` while the
    // supervisor has closed the session anyway, and reading it as the state left such a session
    // marked `unresolved` for ever. `recovery_required` is the field that says a teardown is
    // unconfirmed and wants out-of-band work — "this response is not a confirmed detach" — and
    // only the preserved live-control case sets it. So it decides the state, and the other two
    // facts go where facts go.
    if (tool === 'end_session') {
      s.state = d.recovery_required === true ? 'unresolved' : 'closed'
      // `target_left_running` is absent for a dump or a trace, which have nothing that outlives
      // the session. For a live kernel `false` is the one that matters: it was *not* resumed, so
      // it is halted at a break with one processor stopped and the rest spinning.
      const left = d.target_left_running === true
        ? ', target left running'
        : d.target_left_running === false ? ', target did not outlive the session' : ''
      note = (d.released === false ? 'the worker did not release the target' : 'released') + left +
        (d.recovery_required === true ? ', recovery required' : '')
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
  // The raw `execute` hatch can move the target and cannot say so: it declares no output schema,
  // so the whole answer is debugger text and there is no field to read. What the pane must not do
  // is go on claiming the earlier reads are current — a `g` through this hatch leaves registers,
  // stack and memory describing a target that is somewhere else now.
  //
  // There is deliberately **no list of command names**, which is what review asked for.
  // `.claude/rules/execution-waits.md` records why one cannot be finished: `bp X; g`, an alias,
  // `.if (1) { g }` and `dx …ExecuteCommand("g")` all reach execution without saying so, and the
  // server's own fix was to ask the engine rather than the text. The pane cannot ask the engine, so
  // the honest reading is that a raw command *may* have moved the target — `movedAt` says only
  // that the reads before it are no longer known to be current, which is exactly the claim left.
  // Reading the text instead would be inventing a position out of a rendering.
  if (s && out.ok && tool === 'execute') {
    s.movedAt = n
    if (!note) note = 'raw command, target state not reported'
  }
  // Outside that chain on purpose — see `foldBatch`. A failed batch keeps the failure in front of
  // what the report says the session is left holding, since both are facts the reader wants.
  if (s && d && tool === 'debug_batch') {
    const said = foldBatch(s, d, n)
    if (said) note = note ? note + '; ' + said : said
  }
  // **An explicitly addressed call does not move the server's default, so it must not move this
  // one.** `Sessions::current` is `self.all.iter().rev().find(|s| s.state().accepts_default())` —
  // the newest session the caller owns that still takes an unaddressed call — and nothing a call
  // naming a `session_id` does changes it. Assigning from any such call pointed the pane at the
  // older of two open sessions while the server went on routing implicit calls to the newer, so
  // `begin` pinned the next one to the wrong session and drew one target's reads under another:
  // the misfiling an earlier round fixed, arrived at from the other end. An opener moves it
  // (the new session *is* the newest), `session_status` overrides it with the server's own answer,
  // and otherwise it moves only when the session it names has closed — mirroring that `rev()`.
  // **A belief updated by the events that change it, not a value derived on every call.** That was
  // the mistake in the previous fix: recomputing it meant encoding `accepts_default`, and the
  // pane's states are display strings rather than that enum — so a newest session that had gone
  // `failed` or `unresolved` was still chosen while the server had moved on to the older one, which
  // is the same misfiling one layer down. It moves on exactly three things: an opener (the new
  // session is the newest and accepts a default call), a `session_status` row saying `current`
  // (the server's own answer, and the authority), and the believed session ceasing to be eligible
  // — where the fallback is a guess that the next status call corrects.
  const believed = v.current && sessions.some(x => x.id === v.current && !NOT_ROUTABLE.has(x.state))
  const current = opened ?? routed ?? (believed ? v.current : newestOpen(sessions) ?? v.current)
  const log = v.log.map(e =>
    e.n === n ? { ...e, session: sid, status: out.ok ? ('ok' as const) : ('error' as const), note, ms: out.ms } : e,
  )
  return { ...v, sessions, current, log }
}
