/**
 * One register. A live Secure Kernel stop reports a `high` half and a read `status` beside the
 * value and keeps both deliberately — `cs` carries its descriptor in the high half, and a
 * non-zero status is a register that could not be read rather than one that is zero — so both
 * are carried here rather than flattened away.
 */
export type Reg = { name: string; value: string; high?: string; failed?: boolean }

export type Ins = { address: string; bytes: string; module: string; rva: string; text: string }

/**
 * A live Secure Kernel VTL1 stop. `cr3` differing from `expectedCr3` is the transition case: the
 * trustlet's address space is still loaded at the Secure Kernel entry, which is what
 * `allow_transition_cr3` admits.
 */
export type SkStop = {
  vtl: number
  cpl: number
  vp: number
  vector: number
  reason: string
  slot: number | null
  partition: string
  expectedCr3: string
  cr3: string
  epoch: string
}

export type Frame = {
  index: number
  symbol: string
  displacement: string
  module: string
  rva: string
  address: string
}

export type Bp = { id: number; address: string; expression: string; enabled: boolean; oneShot: boolean }

/** What the pane knows about one windbg-mcp session, each read stamped with the call that made it. */
export type Session = {
  id: string
  label: string
  kind: string
  target: string
  state: string
  regs: Reg[] | null
  prevRegs: Reg[] | null
  regsAt: number
  ip: string | null
  ipAt: number
  movedAt: number
  /** `bytesOnly` where the source reported instruction bytes and no disassembly, as SK live does. */
  disasm: { start: string; rows: Ins[]; bytesOnly?: boolean } | null
  frames: Frame[] | null
  framesTruncated: boolean
  framesAt: number
  /**
   * `gpa` is the guest physical address a live VTL1 page-table walk resolved the read to, and
   * `frame` is an x64 machine frame recognised in the bytes — `rip, cs, rflags, rsp, ss` — offered
   * only where the shape fits, since most reads are not frames.
   */
  mem: {
    address: string
    hex: string
    size: number
    gpa?: string
    frame?: { rip: string; cs: string; rflags: string; rsp: string; ss: string; ring: number }
  } | null
  memAt: number
  bps: Bp[] | null
  gone: boolean
  /** Set on a target that has bug checked, from the opener's summary or from `crash_triage`. */
  bugCheck: { code: string; name: string; blamed: string } | null
  /** The last live Secure Kernel stop, where this is one of those sessions. */
  sk: SkStop | null
  /** `running` once an SK arm/step/continue was accepted, until the next stop is collected. */
  skPhase: string
}

export type LogEntry = {
  n: number
  tool: string
  command: string
  isWinDbg: boolean
  session: string | null
  status: 'running' | 'ok' | 'error'
  note: string
  ms: number
}

export type View = {
  n: number
  current: string | null
  sessions: Session[]
  log: LogEntry[]
  autoOpened: boolean
  lastShape: string
}

declare module 'claude-code' {
  interface PluginState {
    'windbg-pane': { view: View }
  }
}
