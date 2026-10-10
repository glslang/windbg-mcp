import { expect, test } from 'claude-code/testing'
import type { On } from 'claude-code'

import type { View } from '../types'
import { EMPTY, begin, finish, payloadOf, readFrame, windbgTool } from '../hooks/model'
import { RECORDED } from './recorded'
import { RECORDED_KERNEL } from './recorded-kernel'
import { RECORDED_DUMP } from './recorded-dump'

/** Folds a whole recorded run, as the hook does call by call. */
function fold(calls: typeof RECORDED): View {
  let v = EMPTY
  for (const call of calls) {
    const [started, n] = begin(v, call.tool, call.args)
    v = finish(started, n, call.tool, call.args, { ok: call.ok, data: call.data, error: '', ms: 1 })
  }
  return v
}

/** Answers each call with exactly what the real server answered, in MCP result shape. */
function serve(on: On, calls: typeof RECORDED) {
  let i = 0
  on('tool.call', async () => {
    const call = calls[i++]!
    const text = JSON.stringify(call.data)
    return { result: { content: [{ type: 'text', text }], isError: false, structuredContent: call.data }, text }
  })
}

const SESSION = 'sess-18dd16613e6a0bfc-1'

/** Folds the recorded calls, in order, up to and including the `upto`-th. */
function replay(upto = RECORDED.length): View {
  let v = EMPTY
  for (const call of RECORDED.slice(0, upto)) {
    const [started, n] = begin(v, call.tool, call.args)
    v = finish(started, n, call.tool, call.args, { ok: call.ok, data: call.data, error: '', ms: 1 })
  }
  return v
}

const at = (tool: string, nth = 0) => RECORDED.map((c, i) => [c.tool, i] as const).filter(([t]) => t === tool)[nth]![1] + 1

test('only windbg-mcp tools are followed, whatever the server is registered as', () => {
  expect(windbgTool('mcp__windbg__registers')).toBe('registers')
  expect(windbgTool('mcp__plugin_windbg-mcp_windbg__set_breakpoint')).toBe('set_breakpoint')
  expect(windbgTool('mcp__windbg-sk__open_sk_live_control')).toBe('open_sk_live_control')
  expect(windbgTool('mcp__github__get_issue')).toBe(null)
  expect(windbgTool('Bash')).toBe(null)
})

test('the typed half is found in each shape a result can carry it', () => {
  const data = { status: 'ok', stopped_at: '0x10' }
  const json = JSON.stringify(data)
  expect(payloadOf({ content: [{ type: 'text', text: 'prose' }], isError: false, structuredContent: data }, 'prose')).toEqual(data)
  expect(payloadOf({ content: [{ type: 'text', text: json }], isError: false }, json)).toEqual(data)
  expect(payloadOf([{ type: 'text', text: json }], json)).toEqual(data)
  expect(payloadOf(undefined, json)).toEqual(data)
  expect(payloadOf(undefined, 'Breakpoint 0 set')).toBe(null)
})

test('a breakpoint hit puts the session at the breakpoint', () => {
  const v = replay(at('go'))
  expect(v.current).toBe(SESSION)
  const s = v.sessions[0]!
  expect(s.kind).toBe('launch')
  expect(s.ip).toBe('7ffed96277f0')
  expect(s.bps?.map(b => b.expression)).toEqual(['kernelbase!CreateFileW'])
})

test('a step moves the position and marks the earlier reads stale', () => {
  const v = replay(at('step_over'))
  const s = v.sessions[0]!
  expect(s.ip).toBe('7ffed96277f3')
  expect(s.movedAt).toBeGreaterThan(s.regsAt)
  expect(s.movedAt).toBeGreaterThan(s.framesAt)
  expect(s.movedAt).toBeGreaterThan(s.memAt)
  expect(v.log[v.log.length - 1]!.note).toBe('stopped at KERNELBASE+0x277f3')
})

test('the second register read flags what changed since the first', () => {
  const v = replay(at('registers', 1))
  const s = v.sessions[0]!
  const now = new Map(s.regs!.map(r => [r.name, r.value]))
  const before = new Map(s.prevRegs!.map(r => [r.name, r.value]))
  expect(before.get('rax')).toBe('0x0000000000000000')
  expect(now.get('rax')).not.toBe(before.get('rax'))
  expect(s.regsAt).toBeGreaterThan(s.movedAt)
})

test('the target running to exit and the session ending are both kept', () => {
  const ended = replay(at('go', 1))
  expect(ended.sessions[0]!.gone).toBe(true)
  expect(ended.sessions[0]!.ip).toBe(null)
  const closed = replay()
  expect(closed.sessions[0]!.state).toBe('closed')
  expect(closed.log.map(e => e.status).every(st => st === 'ok')).toBe(true)
})

test('a live kernel attach keeps its control registers and reports the refresh', () => {
  let v = EMPTY
  for (const call of RECORDED_KERNEL) {
    const [started, n] = begin(v, call.tool, call.args)
    v = finish(started, n, call.tool, call.args, { ok: call.ok, data: call.data, error: '', ms: 1 })
  }
  const s = v.sessions[0]!
  expect(s.kind).toBe('kernel')
  const map = new Map(s.regs!.map(r => [r.name, r.value]))
  // cr3 is the page-table root: a kernel target reports it and a user-mode one does not.
  expect(map.get('cr3')).toBe('0x00000000007d5000')
  expect(map.get('xcr0')).toBeDefined()
  expect(v.log.find(e => e.tool === 'modules')!.note).toBe('156 loaded, refreshed from 1')
  expect(v.log.find(e => e.tool === 'end_session')!.note).toBe('released')
})

test('the kernel pane draws cr3, drops nothing silently, and says where the ip is', async ($, on) => {
  let answering = 0
  on('tool.call', async () => {
    const call = RECORDED_KERNEL[answering++]!
    const text = JSON.stringify(call.data)
    return { result: { content: [{ type: 'text', text }], isError: false, structuredContent: call.data }, text }
  })
  for (const call of RECORDED_KERNEL.slice(0, RECORDED_KERNEL.length - 1)) {
    const tool = `mcp__windbg__${call.tool}` as const
    await $.tool.call({ tool, ...call.args })
  }
  const ui = await $.ui.mount({
    plugin: 'windbg-pane',
    surface: 'terminal',
    component: 'Pane',
    requestId: 'windbg',
    props: { title: 'WinDbg', isFocused: false, bodyColumns: 140, placement: 'dock', scroll: { offset: 0, bodyRows: 48 }, view: {} },
    viewport: { columns: 220, rows: 50, isFullscreen: true },
  })
  const drawn = (await ui.findAll({ type: 'Text' })).map(x => x.text).join('\n')
  expect(drawn).toMatch(/cr3=00000000007d5000/)
  // The disassembly was read at the driver's dispatch while the stop was in nt.
  expect(drawn).toMatch(/ip is elsewhere, at nt!DbgBreakPointWithStatus/)
  // Whatever is not drawn is counted rather than dropped without trace.
  expect(drawn).toMatch(/\+\d+ not shown: .*kdr0/)
  expect(drawn).toMatch(/MessageManager\+0x1247/)
  await ui.unmount()
})

test('an ARM64 kernel dump keeps its own register bank and its bug check', () => {
  const v = fold(RECORDED_DUMP)
  const s = v.sessions[0]!
  const map = new Map(s.regs!.map(r => [r.name, r.value]))
  // This target has no rax and no cr3: its registers are x0.. and pc, which is the whole point.
  expect(map.has('rax')).toBe(false)
  expect(map.get('pc')).toBe('0xfffff802e9e5d5ac')
  expect(map.has('x28')).toBe(true)
  expect(s.bugCheck).toEqual({ code: '0x139', name: 'KERNEL_SECURITY_CHECK_FAILURE', blamed: 'HEVD+0x10dc' })
  expect(v.log.find(e => e.tool === 'crash_triage')!.note)
    .toBe('0x139 KERNEL_SECURITY_CHECK_FAILURE, blaming HEVD+0x10dc')
})

test('the dump pane draws the ARM64 bank, the bug check, and hides only duplicate views', async ($, on) => {
  serve(on, RECORDED_DUMP)
  for (const call of RECORDED_DUMP.slice(0, RECORDED_DUMP.length - 1)) {
    const tool = `mcp__windbg__${call.tool}` as const
    await $.tool.call({ tool, ...call.args })
  }
  const ui = await $.ui.mount({
    plugin: 'windbg-pane',
    surface: 'terminal',
    component: 'Pane',
    requestId: 'windbg',
    props: { title: 'WinDbg', isFocused: false, bodyColumns: 150, placement: 'dock', scroll: { offset: 0, bodyRows: 60 }, view: {} },
    viewport: { columns: 230, rows: 62, isFullscreen: true },
  })
  const drawn = (await ui.findAll({ type: 'Text' })).map(x => x.text).join('\n')
  expect(drawn).toMatch(/BUGCHECK 0x139 KERNEL_SECURITY_CHECK_FAILURE/)
  expect(drawn).toMatch(/blaming HEVD\+0x10dc/)
  expect(drawn).toMatch(/\bpc=fffff802e9e5d5ac/)
  expect(drawn).toMatch(/\bx28=/)
  // w0..w30 are views of x0..x30, so they are hidden as duplicates, not reported as omissions.
  expect(drawn).toMatch(/31 32-bit views of the above hidden/)
  expect(drawn).not.toMatch(/not shown: .*\bw0\b/)
  await ui.unmount()
})

test('the pane draws the recorded session, narrow and wide', async ($, on) => {
  // Stands for the windbg-mcp server: answers each call with what the real one answered.
  let answering = 0
  on('tool.call', async () => {
    const call = RECORDED[answering++]!
    const text = JSON.stringify(call.data)
    return { result: { content: [{ type: 'text', text }], isError: false, structuredContent: call.data }, text }
  })
  for (const call of RECORDED.slice(0, at('step_over'))) {
    const tool = `mcp__windbg__${call.tool}` as const
    await $.tool.call({ tool, ...call.args })
  }
  for (const bodyColumns of [72, 140]) {
    const ui = await $.ui.mount({
      plugin: 'windbg-pane',
      surface: 'terminal',
      component: 'Pane',
      requestId: 'windbg',
      props: { title: 'WinDbg', isFocused: false, bodyColumns, placement: 'dock', scroll: { offset: 0, bodyRows: 48 }, view: {} },
      viewport: { columns: bodyColumns + 80, rows: 50, isFullscreen: true },
    })
    expect(await ui.find({ type: 'Text', text: /^ip 00007ffe`d96277f3  KERNELBASE\+0x277f3$/ })).toBeDefined()
    expect(await ui.find({ type: 'Text', text: /^REGISTERS  read before the target last moved$/ })).toBeDefined()
    expect(await ui.find({ type: 'Text', text: /^> p  step_over ok — stopped at KERNELBASE\+0x277f3$/ })).toBeDefined()
    // The wide layout has room for the whole log; the narrow one keeps its last lines.
    const bp = await ui.find({ type: 'Text', text: /^> bp kernelbase!CreateFileW  set_breakpoint ok/ })
    if (bodyColumns >= 110) expect(bp).toBeDefined()
    else expect(bp).toBeUndefined()
    await ui.unmount()
  }
})

test('a machine frame is recognised only where the shape fits', () => {
  // Synthetic, so this travels: a ring-3 frame built to the layout rather than captured from a VM.
  const ring3 =
    '0040302010000000' + '3300000000000000' + '8602000000000000' + '0088776655000000' + '2b00000000000000'
  expect(readFrame(ring3)).toEqual({
    rip: '0x0000001020304000',
    cs: '0x0033',
    rflags: '0x0000000000000286',
    rsp: '0x0000005566778800',
    ss: '0x002b',
    ring: 3,
  })
  // The ring is read from the selector rather than assumed.
  expect(
    readFrame('0000000000F0FFFF10000000000000000202000000000000F0FFFFFFFFFFFFFF1800000000000000')?.ring,
  ).toBe(0)
  // Instruction bytes, zeroes, a short read and a zero selector are none of them frames.
  expect(readFrame('4883EC0855564881EC5001000033F6488DAC2480000000C645AB00488945B048')).toBeUndefined()
  expect(readFrame('00'.repeat(48))).toBeUndefined()
  expect(readFrame('4AAD9CB3330200003300000000000000')).toBeUndefined()
  expect(readFrame('0040302010000000' + '00'.repeat(40))).toBeUndefined()
})

test('a failed call never invents a session, and never steals the current one', () => {
  // A good session exists, then a call fails against a handle nobody knows.
  let v = EMPTY
  for (const call of RECORDED.slice(0, at('launch'))) {
    const [started, n] = begin(v, call.tool, call.args)
    v = finish(started, n, call.tool, call.args, { ok: call.ok, data: call.data, error: '', ms: 1 })
  }
  const live = v.current
  expect(live).not.toBe(null)

  const args = { session_id: 'sess-does-not-exist' }
  const [started, n] = begin(v, 'registers', args)
  const after = finish(started, n, 'registers', args, {
    ok: false,
    data: null,
    error: 'session handle is unknown or has expired',
    ms: 1,
  })
  // No ghost session, and the pane still points at the one that is real.
  expect(after.sessions.map(s => s.id)).not.toContain('sess-does-not-exist')
  expect(after.sessions).toHaveLength(v.sessions.length)
  expect(after.current).toBe(live)
  // The failure is still reported.
  expect(after.log[after.log.length - 1]!.status).toBe('error')
  expect(after.log[after.log.length - 1]!.note).toBe('session handle is unknown or has expired')
})

test('an asynchronous run marks the target moving, and its stop is read from `stop`', () => {
  const sid = 'sess-async'
  // Open a session so there is something to fold into.
  let v = EMPTY
  {
    const [started, n] = begin(v, 'launch', { command: 'x.exe' })
    v = finish(started, n, 'launch', { command: 'x.exe' }, {
      ok: true,
      data: { status: 'ok', kind: 'launch', session_id: sid, target: 'x.exe' },
      error: '',
      ms: 1,
    })
  }
  // A register read, so there is something that can go stale.
  {
    const a = { session_id: sid }
    const [started, n] = begin(v, 'registers', a)
    v = finish(started, n, 'registers', a, {
      ok: true,
      data: { status: 'ok', registers: [{ name: 'rax', value: '0x1' }], instruction_pointer: '0x1000' },
      error: '',
      ms: 1,
    })
  }
  expect(v.sessions[0]!.regsAt).toBeGreaterThan(v.sessions[0]!.movedAt)

  // `continue_async` reports `moved`/`running` at the top level and carries no stop.
  {
    const a = { session_id: sid }
    const [started, n] = begin(v, 'continue_async', a)
    v = finish(started, n, 'continue_async', a, {
      ok: true,
      data: { status: 'ok', running: true, moved: true, handle: 'run-1' },
      error: '',
      ms: 1,
    })
  }
  const moving = v.sessions[0]!
  // The earlier reads are now stale, which is the whole point.
  expect(moving.movedAt).toBeGreaterThan(moving.regsAt)
  expect(v.log[v.log.length - 1]!.note).toBe('running, handle run-1')

  // `wait_for_stop` nests the stop under `stop`.
  {
    const a = { session_id: sid }
    const [started, n] = begin(v, 'wait_for_stop', a)
    v = finish(started, n, 'wait_for_stop', a, {
      ok: true,
      data: { status: 'ok', running: false, stop: { stopped_at: '0x2000' } },
      error: '',
      ms: 1,
    })
  }
  expect(v.sessions[0]!.ip).toBe('2000')

  // `run_to_address` reports an ending through `verdict`, not the boolean.
  {
    const a = { session_id: sid }
    const [started, n] = begin(v, 'run_to_address', a)
    v = finish(started, n, 'run_to_address', a, {
      ok: true,
      data: { status: 'ok', verdict: 'target_gone' },
      error: '',
      ms: 1,
    })
  }
  expect(v.sessions[0]!.gone).toBe(true)
  expect(v.sessions[0]!.ip).toBe(null)
})
