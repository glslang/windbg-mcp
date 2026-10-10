import { atom, read, update } from 'claude-code'
import type { Register } from 'claude-code'

import type { LogEntry, Session } from '../types'
import { EMPTY, begin, finish, norm, payloadOf, regHex, shapeOf, wd, windbgTool } from './model'

const PANE = 'windbg'
const TITLE = 'WinDbg'
const view = atom({ plugin: 'windbg-pane', key: 'view' } as const, EMPTY)

// Theme keys, so the pane follows the person's Claude Code theme.
const ACCENT = 'claude'
const BAD = 'error'
const WARN = 'warning'
const GOOD = 'success'
const MNEMONIC = 'suggestion'

// Register banks, each measured from this server's own `registers` payloads rather than assumed:
// an x64 target reports `rax`.., an ARM64 one `x0`.., and neither set appears on the other. A name
// in no bank is still counted on screen, so a bank missing a whole class shows as a number rather
// than vanishing — which is how `cr3` was found missing on a kernel target, and `x0`.. on ARM64.
const run = (prefix: string, count: number, from = 0) =>
  Array.from({ length: count }, (_, i) => prefix + (i + from))

type Bank = { ip: string; main: string[]; debug: string[] }

const X64: Bank = {
  ip: 'rip',
  main: [
    'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rip', 'rsp', 'rbp',
    ...run('r', 8, 8), 'efl',
    'cs', 'ds', 'es', 'fs', 'gs', 'ss',
    // Kernel only, and `cr3` is the page-table root — the register a kernel session is read for.
    'cr0', 'cr2', 'cr3', 'cr4', 'cr8', 'xcr0', 'gdtr', 'gdtl', 'idtr', 'idtl', 'tr', 'ldtr',
  ],
  debug: ['dr0', 'dr1', 'dr2', 'dr3', 'dr6', 'dr7'],
}

const A64: Bank = {
  ip: 'pc',
  main: [...run('x', 29), 'fp', 'lr', 'sp', 'pc', 'cpsr', 'elr', 'spsr', 'fpsr', 'fpcr'],
  // Breakpoint/watchpoint value and control registers, and the kernel's own copies.
  debug: [
    ...run('bvr', 8), ...run('bcr', 8), ...run('wvr', 2), ...run('wcr', 2),
    ...run('kbvr', 8), ...run('kbcr', 8), ...run('kwvr', 2), ...run('kwcr', 2),
  ],
}

// Live Secure Kernel control reports a fixed twelve and nothing else (`SNAPSHOT_REGISTERS` in
// `sklive.rs`). `rflags` and `vsm_vp_status` are in neither bank above, so without this the two
// registers that say what the VP was doing would land in the "not shown" line.
const SK: Bank = {
  ip: 'rip',
  main: ['rip', 'rsp', 'rflags', 'cr3', 'cs', 'vsm_vp_status'],
  debug: ['dr0', 'dr1', 'dr2', 'dr3', 'dr6', 'dr7'],
}

/** `w0`..`w30` are 32-bit views of `x0`..`x30`, so they are duplicates rather than omissions. */
const VIEW = /^w([0-9]|[12][0-9]|30)$/

const bankFor = (map: Map<string, string>): Bank =>
  map.has('vsm_vp_status') ? SK : map.has('x0') ? A64 : X64

export const register: Register = on => {
  on('session.start', async ($, e, next) => {
    await $.command.register({
      name: 'windbg-pane',
      description: 'Show the WinDbg pane for windbg-mcp sessions (open, close, clear, shape)',
      argumentHint: '[open|close|clear|shape]',
    })
    return next(e)
  })

  on('command.run', { command: 'windbg-pane' }, async ($, e) => {
    const arg = e.args.trim().toLowerCase()
    if (arg === 'close') {
      await $.ui.close({ id: PANE })
      return { text: 'WinDbg pane closed.' }
    }
    if (arg === 'clear') {
      await update($, view, v => ({ ...EMPTY, autoOpened: v.autoOpened }))
      return { text: 'WinDbg pane cleared.' }
    }
    if (arg === 'shape') {
      const v = await read($, view)
      return { text: v.lastShape ? 'Last windbg-mcp result: ' + v.lastShape : 'No windbg-mcp call has answered yet.' }
    }
    const opened = await $.ui.open({ id: PANE, title: TITLE })
    return { text: opened.isPlaced ? 'WinDbg pane opened.' : 'WinDbg pane is open but needs a wider terminal to show.' }
  })

  // Every windbg-mcp call passes through untouched; the pane only watches it.
  on('tool.call', async ($, e, next) => {
    const tool = windbgTool(String(e.tool))
    if (tool === null) return next(e)
    const args: Record<string, unknown> = {}
    for (const [k, val] of Object.entries(e as Record<string, unknown>)) {
      if (k !== 'tool' && k !== 'tool_use_id' && k !== 'agentId' && k !== 'requestMeta' && k !== 'consent') args[k] = val
    }
    let n = 0
    try {
      await update($, view, v => {
        const [nv, k] = begin(v, tool, args)
        n = k
        return nv
      })
    } catch {
      // the pane is a convenience; never let it stand in the way of the call
    }
    const started = Date.now()
    const ran = await next(e)
    try {
      const ok = ran.deny === undefined && ran.isError !== true
      const data = ran.deny === undefined ? payloadOf(ran.result, ran.text) : null
      const error = ran.deny !== undefined ? 'denied: ' + ran.deny : typeof ran.text === 'string' ? ran.text : ''
      let first = false
      await update($, view, v => {
        const nv = finish(v, n, tool, args, { ok, data, error, ms: Date.now() - started })
        first = !v.autoOpened
        return { ...nv, autoOpened: true, lastShape: ran.deny === undefined ? shapeOf(ran.result, ran.text) : 'denied' }
      })
      if (first) $.ui.open({ id: PANE, title: TITLE }).catch(() => undefined)
    } catch {
      // as above
    }
    return ran
  }).catch(($, e, next) => next(e))

  on('ui.render', { component: 'Pane', requestId: PANE }, async ($, e) => {
    const { Box, Text } = $.ui.resolve(e)
    const v = await read($, view)
    const width = Math.max(32, e.props.bodyColumns)
    const rows = Math.max(12, e.props.scroll.bodyRows)
    const s = v.sessions.find(x => x.id === v.current) ?? null

    const title = (name: string, note: string, stale = false) => (
      <Text wrap="truncate-end">
        <Text bold color={ACCENT}>{name.toUpperCase()}</Text>
        {note ? <Text dimColor={!stale} color={stale ? WARN : undefined}>{'  ' + note}</Text> : null}
      </Text>
    )

    // The headline of a live Secure Kernel stop: which VTL and privilege level the VP stopped in,
    // what stopped it, and whether the calling trustlet's address space was still loaded at the
    // Secure Kernel entry — the case `allow_transition_cr3` admits and a step must not cross.
    const skBanner = (x: Session) => {
      if (!x.sk) return null
      const k = x.sk
      const moved = !!k.cr3 && !!k.expectedCr3 && norm(k.cr3) !== norm(k.expectedCr3)
      return (
        <Text wrap="truncate-end">
          <Text bold color={ACCENT}>{'VTL' + k.vtl + ' CPL' + k.cpl}</Text>
          <Text dimColor>{'  vp ' + k.vp + '  vector ' + k.vector + '  '}</Text>
          <Text bold>{k.reason + (k.slot !== null ? ' slot ' + k.slot : '')}</Text>
          {x.skPhase === 'running' ? <Text color={WARN}>{'  VP running'}</Text> : null}
          {moved ? (
            <Text>
              <Text color={WARN}>{'  trustlet cr3 ' + regHex(k.cr3)}</Text>
              <Text dimColor>{'  sk ' + regHex(k.expectedCr3)}</Text>
            </Text>
          ) : null}
        </Text>
      )
    }

    const header = () => {
      const others = v.sessions.filter(x => x !== s && x.state === 'open')
      return (
        <Box flexDirection="column">
          <Text wrap="truncate-end">
            <Text bold color={ACCENT}>{s!.label}</Text>
            {' ' + s!.kind + '  '}
            <Text dimColor>{s!.target}</Text>
            {'  '}
            <Text color={s!.state === 'open' ? GOOD : s!.state === 'unresolved' ? BAD : undefined} dimColor={s!.state === 'closed'}>
              {s!.gone ? 'target ended' : s!.state}
            </Text>
            {others.length ? <Text dimColor>{'   also open: ' + others.map(x => x.label + ' ' + x.kind).join(', ')}</Text> : null}
          </Text>
          {s!.bugCheck ? (
            <Text wrap="truncate-end">
              <Text color={BAD} bold>{'BUGCHECK ' + s!.bugCheck.code + ' ' + s!.bugCheck.name}</Text>
              {s!.bugCheck.blamed ? <Text dimColor>{'  blaming ' + s!.bugCheck.blamed}</Text> : null}
            </Text>
          ) : null}
          {skBanner(s!)}
          <Text wrap="truncate-end">
            {s!.ip ? (
              <Text>
                <Text dimColor>ip </Text>
                <Text bold>{wd(s!.ip)}</Text>
                <Text dimColor>{'  ' + locate(s!, s!.ip)}</Text>
              </Text>
            ) : (
              <Text dimColor>{s!.gone ? 'the target has ended' : 'no position read yet'}</Text>
            )}
          </Text>
        </Box>
      )
    }

    const disasm = (w: number, budget: number) => {
      if (!s!.disasm) return <Box flexDirection="column">{title('Disassembly', '')}<Text dimColor>no disassembly read yet</Text></Box>
      const all = s!.disasm.rows
      const at = s!.ip ? all.findIndex(x => norm(x.address) === s!.ip) : -1
      const from = at > 2 ? Math.min(at - 2, Math.max(0, all.length - budget)) : 0
      const shown = all.slice(from, from + budget)
      const bps = new Set((s!.bps ?? []).filter(b => b.enabled).map(b => norm(b.address)))
      const wideLoc = w >= 76
      const wideBytes = w >= 60
      // A listing read at an explicit address need not contain the stop — reading a driver's
      // dispatch while stopped in `nt` is the ordinary case. Say where the ip is instead of
      // flagging it, since the position is known and nothing is wrong.
      const elsewhere = !!s!.ip && at < 0 && !s!.gone
      // Live Secure Kernel control answers with the bytes it guarded and no disassembly, so say so
      // rather than letting an empty mnemonic column read as a failed read.
      const note = (s!.disasm.bytesOnly ? 'bytes at the stop, no disassembly · ' : '') +
        'u ' + wd(s!.disasm.start) +
        (elsewhere ? ' · ip is elsewhere, at ' + (locate(s!, s!.ip!) || wd(s!.ip)) : '')
      return (
        <Box flexDirection="column">
          {title('Disassembly', note)}
          {shown.map(x => {
            const a = norm(x.address)
            const cur = !s!.gone && a === s!.ip
            const sp = x.text.indexOf(' ')
            const mn = sp < 0 ? x.text : x.text.slice(0, sp)
            const ops = sp < 0 ? '' : x.text.slice(sp)
            return (
              <Text wrap="truncate-end">
                <Text color={BAD}>{bps.has(a) ? '●' : ' '}</Text>
                <Text color={ACCENT} bold>{cur ? '▶ ' : '  '}</Text>
                <Text dimColor={!cur}>{wd(x.address) + ' '}</Text>
                {wideLoc ? <Text dimColor>{(x.module ? x.module + '+' + x.rva : '').padEnd(20) + ' '}</Text> : null}
                {wideBytes ? <Text dimColor>{x.bytes.padEnd(16) + ' '}</Text> : null}
                <Text color={cur ? ACCENT : MNEMONIC} bold={cur}>{mn}</Text>
                <Text bold={cur}>{ops}</Text>
              </Text>
            )
          })}
        </Box>
      )
    }

    const registers = (w: number) => {
      if (!s!.regs) return <Box flexDirection="column">{title('Registers', '')}<Text dimColor>no registers read yet</Text></Box>
      const stale = s!.movedAt > s!.regsAt
      const map = new Map(s!.regs.map(r => [r.name, r.value]))
      const prev = new Map((s!.prevRegs ?? []).map(r => [r.name, r.value]))
      const bank = bankFor(map)
      const named = bank.main.filter(x => map.has(x))
      // dr6/dr7 read non-zero on an ordinary kernel target, so this is "armed", not "interesting".
      const debug = bank.debug.filter(x => map.has(x) && norm(map.get(x)) !== '0')
      const drawn = [...named, ...debug]
      const rest = [...map.keys()].filter(x => !drawn.includes(x))
      const views = rest.filter(x => VIEW.test(x))
      const others = rest.filter(x => !VIEW.test(x))
      // Sized from the longest name actually drawn rather than from a constant: `vsm_vp_status` is
      // thirteen characters, and a fixed 22-column cell truncated the line it shared.
      const nameW = Math.max(3, ...drawn.map(x => x.length))
      const perLine = Math.max(1, Math.floor((w + 1) / (nameW + 18)))
      const lines: string[][] = []
      for (const name of drawn) {
        const last = lines[lines.length - 1]
        if (!last || last.length >= perLine) lines.push([name])
        else last.push(name)
      }
      return (
        <Box flexDirection="column">
          {title('Registers', stale ? 'read before the target last moved' : 'current', stale)}
          {lines.map(line => (
            <Text wrap="truncate-end">
              {line.map(name => {
                const live = name === bank.ip && !!s!.ip && s!.ipAt > s!.regsAt
                const value = live ? s!.ip! : map.get(name) ?? ''
                const before = prev.get(name)
                const changed = !live && before !== undefined && norm(before) !== norm(value)
                const reg = s!.regs!.find(r => r.name === name)
                return (
                  <Text>
                    <Text dimColor>{name.padStart(nameW) + '='}</Text>
                    <Text
                      color={reg?.failed ? BAD : live ? ACCENT : changed ? BAD : undefined}
                      bold={live || changed}
                      dimColor={stale && !live}
                    >
                      {reg?.failed ? '?'.repeat(16) : regHex(value)}
                    </Text>
                    {' '}
                  </Text>
                )
              })}
            </Text>
          ))}
          {/* A high half is kept by the server rather than discarded after validation — `cs` carries
              its descriptor there — so it is shown rather than silently halved. */}
          {drawn.filter(x => s!.regs!.find(r => r.name === x)?.high).map(x => (
            <Text wrap="truncate-end" dimColor>
              {x + '.high=' + regHex(s!.regs!.find(r => r.name === x)!.high)}
            </Text>
          ))}
          {others.length ? (
            <Text wrap="truncate-end" dimColor>{'+' + others.length + ' not shown: ' + others.join(' ')}</Text>
          ) : null}
          {views.length ? (
            <Text wrap="truncate-end" dimColor>{views.length + ' 32-bit views of the above hidden'}</Text>
          ) : null}
        </Box>
      )
    }

    const stack = (w: number, budget: number) => {
      if (!s!.frames) return <Box flexDirection="column">{title('Stack', '')}<Text dimColor>no stack read yet</Text></Box>
      const stale = s!.movedAt > s!.framesAt
      const more = s!.frames.length > budget || s!.framesTruncated
      return (
        <Box flexDirection="column">
          {title('Stack', stale ? 'read before the target last moved' : s!.frames.length + ' frames' + (s!.framesTruncated ? ', more not read' : ''), stale)}
          {s!.frames.slice(0, budget).map(f => {
            const disp = f.displacement && norm(f.displacement) !== '0' ? '+' + f.displacement : ''
            return (
              <Text wrap="truncate-end" dimColor={stale}>
                <Text dimColor>{String(f.index).padStart(2, '0') + ' '}</Text>
                {(f.symbol || (f.module ? f.module + '+' + f.rva : wd(f.address))) + disp}
                {w >= 60 ? <Text dimColor>{'  ' + (f.module ? f.module + '+' + f.rva : wd(f.address))}</Text> : null}
              </Text>
            )
          })}
          {more && s!.frames.length > budget ? <Text dimColor>{'  ' + (s!.frames.length - budget) + ' more'}</Text> : null}
        </Box>
      )
    }

    const memory = (w: number, budget: number) => {
      if (!s!.mem) return <Box flexDirection="column">{title('Memory', '')}<Text dimColor>no memory read yet</Text></Box>
      const stale = s!.movedAt > s!.memAt
      const per = w >= 84 ? 16 : 8
      const hex = s!.mem.hex
      const base = BigInt('0x' + (norm(s!.mem.address) ?? '0'))
      const lines: string[] = []
      for (let off = 0; off * 2 < hex.length && lines.length < budget; off += per) {
        let h = ''
        let asc = ''
        for (let j = 0; j < per && (off + j) * 2 < hex.length; j++) {
          const b = parseInt(hex.slice((off + j) * 2, (off + j) * 2 + 2), 16)
          h += hex.slice((off + j) * 2, (off + j) * 2 + 2) + (j === 7 && per === 16 ? '-' : ' ')
          asc += b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.'
        }
        lines.push(wd((base + BigInt(off)).toString(16)) + '  ' + h.padEnd(per * 3) + ' ' + asc)
      }
      return (
        <Box flexDirection="column">
          {title('Memory', (stale ? 'read before the target last moved · ' : '') + 'db ' + wd(s!.mem.address) +
            ' · ' + s!.mem.size + ' bytes' + (s!.mem.gpa ? ' · gpa ' + wd(s!.mem.gpa) : ''), stale)}
          {lines.map(l => <Text wrap="truncate-end" dimColor={stale}>{l}</Text>)}
          {/* An x64 machine frame read as fields rather than five identical-looking quadwords.
              `cs`/`ss` naming ring 3 at a CPL0 stop is the evidence the caller was user mode, so it
              is spelled out instead of left to be decoded from the hex above. */}
          {s!.mem.frame ? (
            <Box flexDirection="column" marginTop={1}>
              <Text wrap="truncate-end">
                <Text color={ACCENT}>{'machine frame'}</Text>
                <Text dimColor>{'  interpreted · '}</Text>
                <Text bold color={s!.mem.frame.ring === 3 ? WARN : undefined}>
                  {'ring ' + s!.mem.frame.ring + (s!.mem.frame.ring === 3 ? ' (user mode)' : '')}
                </Text>
              </Text>
              {([
                ['+00', 'rip', s!.mem.frame.rip],
                ['+08', 'cs', s!.mem.frame.cs],
                ['+10', 'rflags', s!.mem.frame.rflags],
                ['+18', 'rsp', s!.mem.frame.rsp],
                ['+20', 'ss', s!.mem.frame.ss],
              ] as const).map(([off, name, value]) => (
                <Text wrap="truncate-end">
                  <Text dimColor>{off + ' '}</Text>
                  <Text>{name.padEnd(7)}</Text>
                  <Text bold>{name === 'cs' || name === 'ss' ? value : wd(value)}</Text>
                  <Text dimColor>
                    {name === 'cs' || name === 'ss'
                      ? '  ring ' + (parseInt(value, 16) & 3)
                      : name === 'rflags'
                        ? ''
                        : BigInt(value) < 1n << 47n ? '  user address' : '  kernel address'}
                  </Text>
                </Text>
              ))}
            </Box>
          ) : null}
        </Box>
      )
    }

    const breakpoints = (budget: number) => {
      if (!s!.bps) return null
      return (
        <Box flexDirection="column">
          {title('Breakpoints', s!.bps.length + ' set')}
          {s!.bps.slice(0, budget).map(b => (
            <Text wrap="truncate-end" dimColor={!b.enabled}>
              <Text color={BAD}>{'● '}</Text>
              {String(b.id).padEnd(3) + (b.enabled ? 'e ' : 'd ') + (b.address ? wd(b.address) : 'deferred') + '  ' + b.expression + (b.oneShot ? '  /1' : '')}
            </Text>
          ))}
        </Box>
      )
    }

    const log = (budget: number) => {
      const entries = v.log.slice(-Math.max(1, budget))
      return (
        <Box flexDirection="column">
          {title('Command', v.log.length + ' calls')}
          {entries.map(x => logLine(x))}
        </Box>
      )
    }

    const logLine = (x: LogEntry) => {
      const label = x.session ? v.sessions.find(o => o.id === x.session)?.label ?? '' : ''
      return (
        <Text wrap="truncate-end">
          <Text color={ACCENT}>{(v.sessions.length > 1 && label ? label + ' ' : '') + '> '}</Text>
          <Text bold={x.isWinDbg} color={x.isWinDbg ? undefined : MNEMONIC}>{x.command}</Text>
          <Text dimColor>{'  ' + x.tool + ' '}</Text>
          <Text color={x.status === 'error' ? BAD : x.status === 'running' ? WARN : GOOD}>
            {x.status === 'running' ? 'running' : x.status === 'error' ? 'failed' : 'ok'}
          </Text>
          {x.note ? <Text dimColor={x.status !== 'error'} color={x.status === 'error' ? BAD : undefined}>{' — ' + x.note}</Text> : null}
        </Text>
      )
    }

    if (!s) {
      return (
        <Box flexDirection="column">
          <Text bold color={ACCENT}>WinDbg</Text>
          <Text dimColor>
            {v.log.length ? 'No session is open.' : 'Waiting for a windbg-mcp call. Open a target (launch, open_dump, attach_kernel, ...) and this pane follows it.'}
          </Text>
          {v.log.length ? log(rows - 3) : null}
        </Box>
      )
    }

    if (width >= 110) {
      const left = Math.floor(width * 0.56)
      const right = width - left - 2
      const disBudget = Math.max(6, Math.floor((rows - 4) * 0.55))
      return (
        <Box flexDirection="column">
          {header()}
          <Box flexDirection="row" columnGap={2} marginTop={1}>
            <Box flexDirection="column" width={left} rowGap={1}>
              {disasm(left, disBudget)}
              {log(Math.max(3, rows - disBudget - 6))}
            </Box>
            <Box flexDirection="column" width={right} rowGap={1}>
              {registers(right)}
              {stack(right, 8)}
              {memory(right, 6)}
              {breakpoints(4)}
            </Box>
          </Box>
        </Box>
      )
    }

    return (
      <Box flexDirection="column" rowGap={1}>
        {header()}
        {disasm(width, 7)}
        {registers(width)}
        {stack(width, 5)}
        {memory(width, 4)}
        {breakpoints(3)}
        {log(6)}
      </Box>
    )
  })
}

function locate(s: Session, ip: string): string {
  const row = s.disasm?.rows.find(x => norm(x.address) === ip)
  if (row && row.module) return row.module + '+' + row.rva
  const top = s.frames?.[0]
  if (top && norm(top.address) === ip) return top.symbol || top.module + '+' + top.rva
  return ''
}
