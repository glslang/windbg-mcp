import { expect, test } from 'claude-code/testing'
import type { On } from 'claude-code'

import type { View } from '../types'
import { EMPTY, answered, begin, bpsMayBeStale, finish, payloadOf, readFrame, windbgTool } from '../hooks/model'
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
  // The recordings carry `target_left_running`, which the note now reads: a live kernel
  // resumed and actively detached is the only teardown fact not recoverable afterwards.
  expect(v.log.find(e => e.tool === 'end_session')!.note).toBe('released, target left running')
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
      data: { status: 'ok', running: true, moved: true, execution: 'run-1' },
      error: '',
      ms: 1,
    })
  }
  const moving = v.sessions[0]!
  // The earlier reads are now stale, which is the whole point.
  expect(moving.movedAt).toBeGreaterThan(moving.regsAt)
  expect(v.log[v.log.length - 1]!.note).toBe('running, execution run-1')

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

test('a failed opener that left a target keeps its handle in view', () => {
  // A good session first, so there is a current one the failure could wrongly be attributed to.
  let v = EMPTY
  for (const call of RECORDED.slice(0, at('launch'))) {
    const [started, n] = begin(v, call.tool, call.args)
    v = finish(started, n, call.tool, call.args, { ok: call.ok, data: call.data, error: '', ms: 1 })
  }
  const live = v.current

  // `attach_kernel` dialled the link and then failed. The handle is only in the error.
  const args = { profile: 'some-profile' }
  const [started, n] = begin(v, 'attach_kernel', args)
  const after = finish(started, n, 'attach_kernel', args, {
    ok: false,
    data: {
      status: 'error',
      target: 'yes',
      error: { category: 'debugger', message: 'symbols could not be loaded', session_id: 'sess-stranded' },
    },
    error: 'symbols could not be loaded',
    ms: 1,
  })
  const stranded = after.sessions.find(x => x.id === 'sess-stranded')
  expect(stranded).toBeDefined()
  // Not 'open' — the open failed — but visible, and not attributed to the live session. And not
  // abandoned either: `yes` means the target exists and this handle reaches it, which `end_session`
  // or further work both take, so the pane must not send a usable session to recovery.
  expect(stranded!.state).toBe('held')
  expect(stranded!.target).toBe('target exists; use this handle or end the session')
  expect(after.log[after.log.length - 1]!.note).toContain('target held')
  // The pane does **not** move its current session to it. An opener that failed leaves a session
  // `accepts_default` refuses, so the server goes on routing unaddressed calls to the live one —
  // and switching would pin the next implicit call to a session the server is not using. The
  // handle is in the list either way, which is what this test is named for.
  expect(after.current).toBe(live)

  // `pending` says the open may still land; `no` leaves nothing behind and invents nothing.
  const mk = (target: string, id: string) => {
    const [st, m] = begin(v, 'attach_kernel', args)
    return finish(st, m, 'attach_kernel', args, {
      ok: false,
      data: { status: 'error', target, error: { category: 'timeout', message: 'timed out', session_id: id } },
      error: 'timed out',
      ms: 1,
    })
  }
  expect(mk('pending', 'sess-pending').sessions.find(x => x.id === 'sess-pending')!.state).toBe('opening')
  expect(mk('unknown', 'sess-unknown').sessions.find(x => x.id === 'sess-unknown')!.state).toBe('unresolved')
  const clean = mk('no', 'sess-none')
  expect(clean.sessions.find(x => x.id === 'sess-none')).toBeUndefined()
  expect(clean.current).toBe(live)
})

test('movement is folded from a text-only seek and from a run that timed out', () => {
  const sid = 'sess-moves'
  let v = EMPTY
  {
    const [st, n] = begin(v, 'open_trace', { trace: 't.run' })
    v = finish(st, n, 'open_trace', { trace: 't.run' }, {
      ok: true,
      data: { status: 'ok', kind: 'trace', session_id: sid, target: 't.run' },
      error: '',
      ms: 1,
    })
  }
  {
    const a = { session_id: sid }
    const [st, n] = begin(v, 'registers', a)
    v = finish(st, n, 'registers', a, {
      ok: true,
      data: { status: 'ok', registers: [{ name: 'rax', value: '0x1' }], instruction_pointer: '0x1000' },
      error: '',
      ms: 1,
    })
  }
  expect(v.sessions[0]!.regsAt).toBeGreaterThan(v.sessions[0]!.movedAt)

  // `goto_position` runs `!tt` and answers with debugger text: no payload to fold at all.
  {
    const a = { session_id: sid, position: '1A:2B' }
    const [st, n] = begin(v, 'goto_position', a)
    v = finish(st, n, 'goto_position', a, { ok: true, data: null, error: '', ms: 1 })
  }
  const seeked = v.sessions[0]!
  expect(seeked.movedAt).toBeGreaterThan(seeked.regsAt)
  expect(v.log[v.log.length - 1]!.note).toBe('moved, position not reported')
  // The old position is not invented into a new one.
  expect(seeked.ip).toBe('1000')
  expect(seeked.ipAt).toBeLessThan(seeked.movedAt)

  // A fresh read, then a run that times out: the target ran, so that read is stale again.
  {
    const a = { session_id: sid }
    const [st, n] = begin(v, 'registers', a)
    v = finish(st, n, 'registers', a, {
      ok: true,
      data: { status: 'ok', registers: [{ name: 'rax', value: '0x2' }], instruction_pointer: '0x2000' },
      error: '',
      ms: 1,
    })
  }
  expect(v.sessions[0]!.regsAt).toBeGreaterThan(v.sessions[0]!.movedAt)
  {
    const a = { session_id: sid, address: '0x4000' }
    const [st, n] = begin(v, 'run_to_address', a)
    v = finish(st, n, 'run_to_address', a, {
      ok: true,
      data: { status: 'ok', verdict: 'timeout', timeout_ms: 5000, output: '' },
      error: '',
      ms: 1,
    })
  }
  const timedOut = v.sessions[0]!
  expect(timedOut.movedAt).toBeGreaterThan(timedOut.regsAt)
  expect(timedOut.gone).toBe(false)
  expect(v.log[v.log.length - 1]!.note).toBe('ran on, no stop within the wait')
})

test('a result is folded into the session its call began on, not the current one', () => {
  // Two sessions open. s2 becomes current.
  let v = EMPTY
  const open = (id: string, target: string) => {
    const a = { command: target }
    const [st, n] = begin(v, 'launch', a)
    v = finish(st, n, 'launch', a, {
      ok: true,
      data: { status: 'ok', kind: 'launch', session_id: id, target },
      error: '',
      ms: 1,
    })
  }
  open('sess-1', 'one.exe')
  open('sess-2', 'two.exe')
  expect(v.current).toBe('sess-2')

  // An explicit call to s1 must **not** make s1 current. `Sessions::current` takes the newest
  // session that accepts an unaddressed call and nothing a call naming a `session_id` changes it,
  // so moving the pane's would pin the next implicit call to a session the server is not routing
  // it to — one target's registers, stack and memory drawn under another.
  {
    const a = { session_id: 'sess-1' }
    const [st, n] = begin(v, 'registers', a)
    v = finish(st, n, 'registers', a, {
      ok: true,
      data: { status: 'ok', registers: [{ name: 'rax', value: '0x1' }], instruction_pointer: '0x1111' },
      error: '',
      ms: 1,
    })
  }
  expect(v.current).toBe('sess-2')

  // A slow implicit call starts here — pinned to s2, the current session at `begin`.
  const slow = begin(v, 'backtrace', {})
  v = slow[0]
  // Opening a third session *does* move it, legitimately: the new session is the newest.
  open('sess-3', 'three.exe')
  expect(v.current).toBe('sess-3')

  // Now the slow one answers. Its frames belong to s2, where it began — not to s3.
  v = finish(v, slow[1], 'backtrace', {}, {
    ok: true,
    data: { status: 'ok', frames: [{ index: 0, address: '0x2222', symbol: 'two!main' }] },
    error: '',
    ms: 1,
  })
  const s2 = v.sessions.find(x => x.id === 'sess-2')!
  const s3 = v.sessions.find(x => x.id === 'sess-3')!
  expect(s2.frames!.map(f => f.symbol)).toEqual(['two!main'])
  // Null rather than empty: s3 has had no stack read at all, which is what being misfiled would
  // have changed.
  expect(s3.frames).toBe(null)
  // And the log entry still names the session it began on.
  expect(v.log.find(e => e.n === slow[1])!.session).toBe('sess-2')
})

test('clearing breakpoints replaces the inventory, and an unreadable one is not a clean one', () => {
  const sid = 'sess-bp'
  let v = EMPTY
  {
    const a = { command: 'x.exe' }
    const [st, n] = begin(v, 'launch', a)
    v = finish(st, n, 'launch', a, {
      ok: true,
      data: { status: 'ok', kind: 'launch', session_id: sid, target: 'x.exe' },
      error: '',
      ms: 1,
    })
  }
  const arm = (w: View) => {
    const a = { session_id: sid, address: 'x!f' }
    const [st, n] = begin(w, 'set_breakpoint', a)
    return finish(st, n, 'set_breakpoint', a, {
      ok: true,
      data: {
        status: 'ok',
        breakpoints: [
          { id: 0, address: '0x1000', expression: 'x!f', enabled: true },
          { id: 1, address: '0x2000', expression: 'x!g', enabled: true },
        ],
      },
      error: '',
      ms: 1,
    })
  }
  v = arm(v)
  expect(v.sessions[0]!.bps).toHaveLength(2)

  // A clear carries `remaining` and no `breakpoints`: an empty array is the success state.
  const cleared = (() => {
    const a = { session_id: sid }
    const [st, n] = begin(v, 'clear_breakpoints', a)
    return finish(st, n, 'clear_breakpoints', a, { ok: true, data: { status: 'ok', remaining: [] }, error: '', ms: 1 })
  })()
  expect(cleared.sessions[0]!.bps).toEqual([])
  expect(cleared.log[cleared.log.length - 1]!.note).toBe('all breakpoints cleared')

  // One of two removed: `remaining` is the authoritative post-removal inventory.
  const one = (() => {
    const a = { session_id: sid, id: 0 }
    const [st, n] = begin(v, 'clear_breakpoints', a)
    return finish(st, n, 'clear_breakpoints', a, {
      ok: true,
      data: { status: 'ok', remaining: [{ id: 1, address: '0x2000', expression: 'x!g', enabled: true }] },
      error: '',
      ms: 1,
    })
  })()
  expect(one.sessions[0]!.bps!.map(b => b.expression)).toEqual(['x!g'])

  // `null` means the listing could not be read — not that nothing is armed.
  const unknown = (() => {
    const a = { session_id: sid }
    const [st, n] = begin(v, 'clear_breakpoints', a)
    return finish(st, n, 'clear_breakpoints', a, {
      ok: true,
      data: { status: 'ok', remaining: null },
      error: '',
      ms: 1,
    })
  })()
  expect(unknown.sessions[0]!.bps).toBe(null)
  expect(unknown.log[unknown.log.length - 1]!.note).toBe('cleared, inventory could not be read')
})

test('a batch is folded from what the session holds afterwards', () => {
  const sid = 'sess-batch'
  let v = EMPTY
  {
    const a = { command: 'x.exe' }
    const [st, n] = begin(v, 'launch', a)
    v = finish(st, n, 'launch', a, {
      ok: true,
      data: { status: 'ok', kind: 'launch', session_id: sid, target: 'x.exe' },
      error: '',
      ms: 1,
    })
  }
  {
    const a = { session_id: sid }
    const [st, n] = begin(v, 'registers', a)
    v = finish(st, n, 'registers', a, {
      ok: true,
      data: { status: 'ok', registers: [{ name: 'rax', value: '0x1' }], instruction_pointer: '0x1000' },
      error: '',
      ms: 1,
    })
  }
  const base = v
  expect(base.sessions[0]!.regsAt).toBeGreaterThan(base.sessions[0]!.movedAt)

  const batch = (after: Record<string, unknown>) => {
    const a = { session_id: sid, steps: [] }
    const [st, n] = begin(base, 'debug_batch', a)
    return finish(st, n, 'debug_batch', a, {
      ok: true,
      data: { status: 'ok', outcome: 'committed', committed: true, rollback_complete: true, after },
      error: '',
      ms: 1,
    })
  }

  // A batch that resumed and re-stopped elsewhere: movement, with the new position.
  const moved = batch({ state: 'stopped', ip: '0x4000' }).sessions[0]!
  expect(moved.movedAt).toBeGreaterThan(moved.regsAt)
  expect(moved.ip).toBe('4000')

  // A batch that stops where it started is **not** evidence that nothing ran: `after` carries the
  // position and no execution flag, and a resume that loops back to the same breakpoint lands here
  // having changed every register. So the reads are stale, and the note is where the distinction
  // an inspection deserves is kept.
  const sameSpot = batch({ state: 'stopped', ip: '0x1000' })
  const read = sameSpot.sessions[0]!
  expect(read.movedAt).toBeGreaterThan(read.regsAt)
  expect(read.ip).toBe('1000')
  expect(sameSpot.log[sameSpot.log.length - 1]!.note).toBe('batch stopped at 00000000`00001000, position unchanged')

  // Running, detached, ended and uncertain all stale the earlier reads.
  const running = batch({ state: 'running', why: 'a resume step' }).sessions[0]!
  expect(running.movedAt).toBeGreaterThan(running.regsAt)

  const detached = batch({ state: 'detached', by: 'step 3' }).sessions[0]!
  expect(detached.state).toBe('detached')
  expect(detached.gone).toBe(false)

  const ended = batch({ state: 'ended', by: 'step 2' }).sessions[0]!
  expect(ended.gone).toBe(true)
  expect(ended.ip).toBe(null)

  const uncertain = batch({ state: 'uncertain', why: 'the probe failed' }).sessions[0]!
  expect(uncertain.movedAt).toBeGreaterThan(uncertain.regsAt)
  expect(uncertain.gone).toBe(false)
})

test('a failure is read from the nested result and from the payload, not the outer flag alone', () => {
  const payload = { status: 'error', target: 'no', error: { category: 'stale_session', message: 'no such session' } }
  // The host's own flag, which is all the hook used to read.
  expect(answered({ content: [], isError: false }, true, payload)).toBe(false)
  // The MCP record's flag, beside the payload `payloadOf` reads out of that same record.
  expect(answered({ content: [], isError: true, structuredContent: payload }, undefined, payload)).toBe(false)
  // And the record's flag with no payload at all to corroborate it, which is not a contrivance:
  // `server::tool_error` answers a refusal with text and no structured content, so this is the
  // only thing that says the call failed. Without it this assertion passes on the payload below.
  expect(answered({ content: [{ type: 'text', text: 'session is not open' }], isError: true }, undefined, null)).toBe(false)
  // And the server's own statement, which is there whichever way the host passed the call through.
  expect(answered({ content: [], isError: false, structuredContent: payload }, undefined, payload)).toBe(false)
  // A success is still a success in every shape, including one with no typed half at all.
  const ok = { status: 'ok', stopped_at: '0x10' }
  expect(answered({ content: [], isError: false, structuredContent: ok }, undefined, ok)).toBe(true)
  expect(answered({ content: [{ type: 'text', text: 'Breakpoint 0 set' }], isError: false }, undefined, null)).toBe(true)

  // End to end: the record a host hands the hook for a windbg-mcp error, through both functions.
  const record = { content: [{ type: 'text', text: JSON.stringify(payload) }], isError: true }
  const data = payloadOf(record, undefined)
  expect(answered(record, undefined, data)).toBe(false)
  // So the opener's failure cannot mint a session, and its message is the log line even where the
  // host passed no text beside it.
  const args = { profile: 'p' }
  const [st, n] = begin(EMPTY, 'attach_kernel', args)
  const v = finish(st, n, 'attach_kernel', args, { ok: false, data, error: '', ms: 1 })
  expect(v.sessions).toEqual([])
  expect(v.log[0]!.status).toBe('error')
  expect(v.log[0]!.note).toBe('no such session')
})

test('a breakpoint set with an unreadable inventory keeps the one it armed', () => {
  const sid = 'sess-arm'
  let v = EMPTY
  {
    const a = { command: 'x.exe' }
    const [st, n] = begin(v, 'launch', a)
    v = finish(st, n, 'launch', a, { ok: true, data: { status: 'ok', kind: 'launch', session_id: sid, target: 'x.exe' }, error: '', ms: 1 })
  }
  const arm = (w: View, data: Record<string, unknown>) => {
    const a = { session_id: sid, address: 'x!f' }
    const [st, n] = begin(w, 'set_breakpoint', a)
    return finish(st, n, 'set_breakpoint', a, { ok: true, data: { status: 'ok', ...data }, error: '', ms: 1 })
  }
  const first = { id: 0, address: '0x1000', expression: 'x!f', enabled: true }
  const second = { id: 1, address: '0x2000', expression: 'x!g', enabled: true }

  // The inspection read: it is the inventory, this call's breakpoint included.
  v = arm(v, { breakpoint: first, breakpoints: [first] })
  expect(v.sessions[0]!.bps!.map(b => b.id)).toEqual([0])

  // It could not be read: `breakpoints` is empty and says nothing, while `breakpoint` is the
  // engine's own report of what this call made. Neither it nor the inventory may vanish.
  const blind = arm(v, { breakpoint: second, breakpoints: [] })
  expect(blind.sessions[0]!.bps!.map(b => b.id)).toEqual([0, 1])
  expect(blind.log[blind.log.length - 1]!.note).toBe('breakpoint 1 set, inventory could not be read')

  // A breakpoint the engine replaced to make room is not left armed beside its replacement.
  const replaced = arm(blind, { breakpoint: { ...second, address: '0x3000', expression: 'x!h' }, breakpoints: [], replaced: [0] })
  expect(replaced.sessions[0]!.bps!.map(b => b.expression)).toEqual(['x!h'])

  // And the `breakpoints` listing is unaffected: there an empty list *is* the answer.
  const listed = (() => {
    const a = { session_id: sid }
    const [st, n] = begin(blind, 'breakpoints', a)
    return finish(st, n, 'breakpoints', a, { ok: true, data: { status: 'ok', breakpoints: [] }, error: '', ms: 1 })
  })()
  expect(listed.sessions[0]!.bps).toEqual([])
})

test('a provisional session is resolved by the status the recovery flow asks for', () => {
  // An opener that dialled the link and failed, leaving the handle in its error.
  const args = { profile: 'p' }
  const [st, n] = begin(EMPTY, 'attach_kernel', args)
  const v = finish(st, n, 'attach_kernel', args, {
    ok: false,
    data: { status: 'error', target: 'pending', error: { category: 'timeout', message: 'timed out', session_id: 'sess-p' } },
    error: 'timed out',
    ms: 1,
  })
  expect(v.sessions[0]!.state).toBe('opening')

  const status = (w: View, data: Record<string, unknown>, a: Record<string, unknown> = {}) => {
    const [s2, m] = begin(w, 'session_status', a)
    return finish(s2, m, 'session_status', a, {
      ok: true,
      data: { status: 'ok', max_sessions: 4, unknown_handle: false, ...data },
      error: '',
      ms: 1,
    })
  }

  // The worker dialled in after all: the provisional state is replaced by what the server holds.
  const open = status(v, {
    sessions: [{ session_id: 'sess-p', kind: 'kernel', target: 'profile "p" (net:port=50000,key=<redacted>)', state: { state: 'open' }, current: true, live: true }],
  })
  expect(open.sessions[0]!.state).toBe('open')
  expect(open.sessions[0]!.kind).toBe('kernel')
  expect(open.sessions[0]!.target).toContain('key=<redacted>')
  expect(open.log[open.log.length - 1]!.note).toBe('s1 open')

  // The attach is still parked, and `overdue` is the half that says which kind of parked.
  const parked = status(v, {
    sessions: [{ session_id: 'sess-p', kind: 'kernel', target: 't', state: { state: 'attaching', waits_indefinitely: true, overdue: true }, current: true, live: true }],
  })
  expect(parked.sessions[0]!.state).toBe('attaching, overdue')

  // It failed with the controller retained: refused, and not a clean session.
  const unresolved = status(v, {
    sessions: [{ session_id: 'sess-p', kind: 'kernel', target: 't', state: { state: 'kernel_unresolved', why: 'release unconfirmed' }, current: true, live: true }],
  })
  expect(unresolved.sessions[0]!.state).toBe('unresolved')

  // A listing mints nothing: a session the pane has seen no call for has no reads to draw under it.
  const other = status(v, {
    sessions: [{ session_id: 'sess-other', kind: 'dump', target: 'x.dmp', state: { state: 'open' }, current: false, live: true }],
  })
  expect(other.sessions.map(x => x.id)).toEqual(['sess-p'])
  expect(other.sessions[0]!.state).toBe('opening')
  expect(other.log[other.log.length - 1]!.note).toBe('1 session(s)')

  // An empty list and an unknown handle are the same list; only the second says it is gone.
  const gone = status(v, { sessions: [], unknown_handle: true, asked: 'sess-p' }, { session_id: 'sess-p' })
  expect(gone.sessions[0]!.state).toBe('unknown to the server')
  const quiet = status(v, { sessions: [], asked: 'sess-p' }, { session_id: 'sess-p' })
  expect(quiet.sessions[0]!.state).toBe('opening')
})

test('a location query moves the displayed position after a seek that reported none', () => {
  const sid = 'sess-loc'
  let v = EMPTY
  {
    const a = { trace: 't.run' }
    const [st, n] = begin(v, 'open_trace', a)
    v = finish(st, n, 'open_trace', a, { ok: true, data: { status: 'ok', kind: 'trace', session_id: sid, target: 't.run' }, error: '', ms: 1 })
  }
  {
    const a = { session_id: sid }
    const [st, n] = begin(v, 'registers', a)
    v = finish(st, n, 'registers', a, {
      ok: true,
      data: { status: 'ok', registers: [{ name: 'rax', value: '0x1' }], instruction_pointer: '0x1000' },
      error: '',
      ms: 1,
    })
  }
  {
    // `goto_position` runs `!tt` and answers with debugger text: moved, position unreported.
    const a = { session_id: sid, position: '12:0' }
    const [st, n] = begin(v, 'goto_position', a)
    v = finish(st, n, 'goto_position', a, { ok: true, data: null, error: '', ms: 1 })
  }
  expect(v.sessions[0]!.ip).toBe('1000')

  const locate = (data: Record<string, unknown>) => {
    const a = { session_id: sid }
    const [st, n] = begin(v, 'current_location', a)
    return finish(st, n, 'current_location', a, { ok: true, data: { status: 'ok', ...data }, error: '', ms: 1 })
  }
  const found = locate({
    location_state: 'mapped',
    address: '0x7ffed9627800',
    thread: 1,
    coordinate: { module: 'KERNELBASE', image_name: 'KernelBase.dll', rva: '0x27800' },
  })
  expect(found.sessions[0]!.ip).toBe('7ffed9627800')
  expect(found.sessions[0]!.ipAt).toBe(found.n)
  expect(found.log[found.log.length - 1]!.note).toBe('at KERNELBASE+0x27800')

  // No thread context carries no address, and inventing one is the misreading this prevents.
  const none = locate({ location_state: 'context_unavailable' })
  expect(none.sessions[0]!.ip).toBe('1000')
  expect(none.sessions[0]!.ipAt).toBe(v.sessions[0]!.ipAt)
  expect(none.log[none.log.length - 1]!.note).toBe('no position: context_unavailable')
})

test('a batch that did not settle is a failure whose report is still read', () => {
  const sid = 'sess-unsettled'
  let v = EMPTY
  {
    const a = { command: 'x.exe' }
    const [st, n] = begin(v, 'launch', a)
    v = finish(st, n, 'launch', a, { ok: true, data: { status: 'ok', kind: 'launch', session_id: sid, target: 'x.exe' }, error: '', ms: 1 })
  }
  {
    const a = { session_id: sid }
    const [st, n] = begin(v, 'registers', a)
    v = finish(st, n, 'registers', a, {
      ok: true,
      data: { status: 'ok', registers: [{ name: 'rax', value: '0x1' }], instruction_pointer: '0x1000' },
      error: '',
      ms: 1,
    })
  }
  const before = v.sessions[0]!

  // `server::batch_settled` answers an uncommitted batch, or one whose rollback did not finish,
  // as an MCP error wrapped around an `Outcome::Ok` report — so `status` is `ok`, the call is a
  // failure, and `after` is the only thing that says what the session holds. The pane must not
  // skip it: `uncertain` is the statement that the reads above can no longer be trusted.
  const a = { session_id: sid, steps: [{ op: 'command', command: 'eb 1000 90' }] }
  const [st, n] = begin(v, 'debug_batch', a)
  const unsettled = finish(st, n, 'debug_batch', a, {
    ok: false,
    data: {
      status: 'ok',
      committed: false,
      rollback_complete: false,
      after: { state: 'uncertain', why: 'the probe after the rollback failed' },
    },
    error: 'the batch did not settle',
    ms: 1,
  })
  const s = unsettled.sessions[0]!
  expect(s.movedAt).toBeGreaterThan(s.regsAt)
  // Both facts, in the order a reader wants them: what went wrong, then where it left the session.
  expect(unsettled.log[unsettled.log.length - 1]!.status).toBe('error')
  expect(unsettled.log[unsettled.log.length - 1]!.note).toBe(
    'the batch did not settle; batch left the session uncertain: the probe after the rollback failed',
  )

  // A failure that carries no report at all — refused before it started — folds nothing.
  const [st2, n2] = begin(v, 'debug_batch', a)
  const refused = finish(st2, n2, 'debug_batch', a, {
    ok: false,
    data: { status: 'error', error: { category: 'target_running', message: 'the target is running' } },
    error: 'the target is running',
    ms: 1,
  })
  expect(refused.sessions[0]!.movedAt).toBe(before.movedAt)
  expect(refused.log[refused.log.length - 1]!.note).toBe('the target is running')
})

test('a status that reports an outstanding run stales the reads taken before it', () => {
  const sid = 'sess-async'
  let v = EMPTY
  {
    const a = { command: 'x.exe' }
    const [st, n] = begin(v, 'launch', a)
    v = finish(st, n, 'launch', a, { ok: true, data: { status: 'ok', kind: 'launch', session_id: sid, target: 'x.exe' }, error: '', ms: 1 })
  }
  {
    const a = { session_id: sid }
    const [st, n] = begin(v, 'registers', a)
    v = finish(st, n, 'registers', a, {
      ok: true,
      data: { status: 'ok', registers: [{ name: 'rax', value: '0x1' }], instruction_pointer: '0x1000' },
      error: '',
      ms: 1,
    })
  }
  {
    // A `continue_async` whose own call timed out: the run was submitted and the failure advances
    // nothing, so the pane is still drawing the registers above as current.
    const a = { session_id: sid }
    const [st, n] = begin(v, 'continue_async', a)
    v = finish(st, n, 'continue_async', a, {
      ok: false,
      data: { status: 'error', error: { category: 'timeout', message: 'the call expired', session_id: sid } },
      error: 'the call expired',
      ms: 1,
    })
  }
  expect(v.sessions[0]!.movedAt).toBeLessThan(v.sessions[0]!.regsAt)

  const status = (execution: Record<string, unknown> | undefined) => {
    const a = { session_id: sid }
    const [st, n] = begin(v, 'session_status', a)
    return finish(st, n, 'session_status', a, {
      ok: true,
      data: {
        status: 'ok',
        max_sessions: 4,
        unknown_handle: false,
        sessions: [{ session_id: sid, kind: 'launch', target: 'x.exe', state: { state: 'open' }, current: true, live: true, ...(execution ? { execution } : {}) }],
      },
      error: '',
      ms: 1,
    })
  }

  // `stopped: false` is the server saying the target is moving and every read of it is refused.
  const moving = status({ execution: 'exec-1', command: 'g', running_for_ms: 4200, stopped: false, breaks_in_ms: 60000 })
  expect(moving.sessions[0]!.movedAt).toBeGreaterThan(moving.sessions[0]!.regsAt)
  expect(moving.log[moving.log.length - 1]!.note).toBe('s1 open, target moving')

  // **A run that has ended is movement unless the pane already accounted for it**, and the handle
  // is what tells those apart — `ExecutionInfo` keeps a finished run's block "until another run
  // replaces it", so its mere presence says nothing about whether the pane saw the run.
  //
  // `exec-9` is a run this session never reported: the case is a `continue_async` whose own call
  // timed out, where the pane saw a failure and folded nothing, and the run then finished before
  // the first recovery poll. `stopped: true` and the reads are still untrustworthy.
  const unseen = status({ execution: 'exec-9', command: 'g', running_for_ms: 4200, stopped: true })
  expect(unseen.sessions[0]!.movedAt).toBeGreaterThan(unseen.sessions[0]!.regsAt)
  expect(unseen.log[unseen.log.length - 1]!.note).toBe('s1 open, a run this session had not reported')

  // Whereas a run the pane folded itself does not re-stale reads taken after its stop. Drive the
  // `continue_async` so the handle is known, then read the registers again.
  {
    const a = { session_id: sid }
    const [st, n] = begin(v, 'continue_async', a)
    v = finish(st, n, 'continue_async', a, {
      ok: true,
      data: { status: 'ok', session_id: sid, execution: 'exec-1', command: 'g', running: true, moved: true },
      error: '',
      ms: 1,
    })
  }
  expect(v.sessions[0]!.execSeen).toBe('exec-1')
  {
    const a = { session_id: sid }
    const [st, n] = begin(v, 'registers', a)
    v = finish(st, n, 'registers', a, {
      ok: true,
      data: { status: 'ok', registers: [{ name: 'rax', value: '0x7' }], instruction_pointer: '0x7000' },
      error: '',
      ms: 1,
    })
  }
  const settled = status({ execution: 'exec-1', command: 'g', running_for_ms: 4200, stopped: true })
  expect(settled.sessions[0]!.movedAt).toBeLessThan(settled.sessions[0]!.regsAt)
  expect(settled.log[settled.log.length - 1]!.note).toBe('s1 open')

  // And a session with no run outstanding carries no `execution` at all.
  expect(status(undefined).sessions[0]!.movedAt).toBeLessThan(v.sessions[0]!.regsAt)
})

test('a raw command leaves the pane unable to claim the earlier reads are current', () => {
  const sid = 'sess-raw'
  let v = EMPTY
  {
    const a = { command: 'x.exe' }
    const [st, n] = begin(v, 'launch', a)
    v = finish(st, n, 'launch', a, { ok: true, data: { status: 'ok', kind: 'launch', session_id: sid, target: 'x.exe' }, error: '', ms: 1 })
  }
  {
    const a = { session_id: sid }
    const [st, n] = begin(v, 'registers', a)
    v = finish(st, n, 'registers', a, {
      ok: true,
      data: { status: 'ok', registers: [{ name: 'rax', value: '0x1' }], instruction_pointer: '0x1000' },
      error: '',
      ms: 1,
    })
  }
  expect(v.sessions[0]!.movedAt).toBeLessThan(v.sessions[0]!.regsAt)

  // `execute` declares no output schema: the whole answer is text, so there is no field saying
  // whether the target moved — and no list of command names can decide it, which is why this is
  // read as "may have moved" rather than either claim.
  const raw = (command: string, ok = true) => {
    const a = { session_id: sid, command }
    const [st, n] = begin(v, 'execute', a)
    return finish(st, n, 'execute', a, { ok, data: null, error: ok ? '' : 'the target is running', ms: 1 })
  }
  const went = raw('bp x!f; g')
  expect(went.sessions[0]!.movedAt).toBeGreaterThan(went.sessions[0]!.regsAt)
  expect(went.log[went.log.length - 1]!.note).toBe('raw command, target state not reported')
  // The position is not touched: the pane knows the reads are stale, not where the target is.
  expect(went.sessions[0]!.ip).toBe('1000')

  // The WinDbg column still shows the command itself, which is how a reader sees what was run.
  expect(went.log[went.log.length - 1]!.command).toBe('bp x!f; g')
  expect(went.log[went.log.length - 1]!.isWinDbg).toBe(true)

  // A call that did not answer says only what failed.
  const refused = raw('g', false)
  expect(refused.sessions[0]!.movedAt).toBe(v.sessions[0]!.movedAt)
  expect(refused.log[refused.log.length - 1]!.note).toBe('the target is running')
})

test('a captured Secure Kernel read reaches the memory panel, where only the live one did', () => {
  const sid = 'sess-capture'
  let v = EMPTY
  {
    const a = { capture: 'vtl1.dmp' }
    const [st, n] = begin(v, 'open_sk_capture', a)
    v = finish(st, n, 'open_sk_capture', a, {
      ok: true,
      data: { status: 'ok', kind: 'sk_capture', session_id: sid, target: 'vtl1.dmp' },
      error: '',
      ms: 1,
    })
  }
  // `sk_read_memory` is the only guest-memory read an `open_sk_capture` session has, and it answers
  // with a different type from the live control's — the same `address`, `gpa`, `requested_size` and
  // `data`, plus the `symbol` the capture's own PDBs resolved. Reading only the live tool's name
  // left every capture read folded nowhere.
  const a = { session_id: sid, address: '0xfffff80012340000', size: 8 }
  const [st, n] = begin(v, 'sk_read_memory', a)
  v = finish(st, n, 'sk_read_memory', a, {
    ok: true,
    data: {
      status: 'ok',
      address: '0xfffff80012340000',
      gpa: '0x1a2b3000',
      requested_size: 8,
      read_size: 8,
      data: '48895C2408574883',
      symbol: 'securekernel!SkmmAccessFault',
    },
    error: '',
    ms: 1,
  })
  const s = v.sessions[0]!
  expect(s.mem?.address).toBe('0xfffff80012340000')
  expect(s.mem?.size).toBe(8)
  expect(s.mem?.gpa).toBe('0x1a2b3000')
  expect(s.memAt).toBe(n)
  const last = v.log[v.log.length - 1]!
  expect(last.note).toBe('8 bytes at gpa 000000001a2b3000, securekernel!SkmmAccessFault')
  // And the command window names the read rather than leaving the row as the raw tool call.
  expect(last.command).toBe('db 0xfffff80012340000 L0n8')
  expect(last.isWinDbg).toBe(true)
})

test('a stop that reports no position is still movement, and claims no position', () => {
  const sid = 'sess-noctx'
  let v = EMPTY
  {
    const a = { program: 'cmd.exe' }
    const [st, n] = begin(v, 'launch', a)
    v = finish(st, n, 'launch', a, {
      ok: true,
      data: { status: 'ok', kind: 'launch', session_id: sid, target: 'cmd.exe' },
      error: '',
      ms: 1,
    })
  }
  {
    const a = { session_id: sid }
    const [st, n] = begin(v, 'registers', a)
    v = finish(st, n, 'registers', a, {
      ok: true,
      data: { status: 'ok', registers: [{ name: 'rax', value: '0x1' }], instruction_pointer: '0x7ff600001000' },
      error: '',
      ms: 1,
    })
  }
  expect(v.sessions[0]!.regsAt).toBeGreaterThan(v.sessions[0]!.movedAt)

  // `StopReport::stopped_at` is absent "for a target that is running, gone, or has no thread
  // context", and `target_gone` is a field of its own precisely because an absent position does not
  // say which. A module-load break is the ordinary case: the run happened, `target_gone` is false,
  // and there is no position, no `verdict`, no `running` and no `moved` — so every condition the
  // pane looked for was false and it went on marking the pre-run reads current.
  {
    const a = { session_id: sid }
    const [st, n] = begin(v, 'go', a)
    v = finish(st, n, 'go', a, {
      ok: true,
      data: {
        status: 'ok',
        command: 'g',
        interrupted: false,
        timed_out: false,
        target_gone: false,
        output: 'ModLoad: 00007ffa`27180000 00007ffa`27450000   ntdll.dll',
      },
      error: '',
      ms: 1,
    })
  }
  const moved = v.sessions[0]!
  expect(moved.movedAt).toBeGreaterThan(moved.regsAt)
  expect(moved.gone).toBe(false)
  expect(v.log[v.log.length - 1]!.note).toBe('stopped, no position reported')
  // The position the target left is not re-asserted as where it is now.
  expect(moved.ip).toBe('7ff600001000')
  expect(moved.ipAt).toBeLessThan(moved.movedAt)

  // The same report nested under a `wait_for_stop`, which is where the async path reads it. A fresh
  // register read first, so there is something for the stop to stale.
  {
    const a = { session_id: sid }
    const [st, n] = begin(v, 'registers', a)
    v = finish(st, n, 'registers', a, {
      ok: true,
      data: { status: 'ok', registers: [{ name: 'rax', value: '0x2' }], instruction_pointer: '0x7ff600002000' },
      error: '',
      ms: 1,
    })
  }
  expect(v.sessions[0]!.regsAt).toBeGreaterThan(v.sessions[0]!.movedAt)
  {
    const a = { session_id: sid, execution: 'run-1' }
    const [st, n] = begin(v, 'wait_for_stop', a)
    v = finish(st, n, 'wait_for_stop', a, {
      ok: true,
      data: {
        status: 'ok',
        session_id: sid,
        execution: 'run-1',
        running_for_ms: 12,
        stop: {
          command: 'g',
          interrupted: false,
          timed_out: false,
          target_gone: false,
          output: 'ModLoad: 00007ffa`27450000 00007ffa`27600000   kernel32.dll',
        },
      },
      error: '',
      ms: 1,
    })
  }
  const waited = v.sessions[0]!
  expect(waited.movedAt).toBeGreaterThan(waited.regsAt)
  expect(v.log[v.log.length - 1]!.note).toBe('stopped, no position reported')
  expect(waited.ip).toBe('7ff600002000')
  expect(waited.ipAt).toBeLessThan(waited.movedAt)
})

test('a short read says why it stopped, which the byte count cannot', () => {
  const sid = 'sess-short'
  let v = EMPTY
  {
    const a = { program: 'cmd.exe' }
    const [st, n] = begin(v, 'launch', a)
    v = finish(st, n, 'launch', a, {
      ok: true,
      data: { status: 'ok', kind: 'launch', session_id: sid, target: 'cmd.exe' },
      error: '',
      ms: 1,
    })
  }
  // `MemoryRead::stopped` exists because `read_size` cannot answer it: a read that ran out of time
  // and one a caller interrupted both come back with fewer bytes and nothing else to tell them
  // apart, and the next move differs. The pane reported the shortfall and not the reason.
  const read = (stopped: string | undefined) => {
    const a = { session_id: sid, address: '0x7ff600001000', size: 8 }
    const [st, n] = begin(v, 'read_memory', a)
    v = finish(st, n, 'read_memory', a, {
      ok: true,
      data: { status: 'ok', address: '0x7ff600001000', requested_size: 8, read_size: 4, data: '48895C24', ...(stopped ? { stopped } : {}) },
      error: '',
      ms: 1,
    })
    return v.log[v.log.length - 1]!.note
  }
  expect(read('deadline')).toBe('4 bytes, 8 requested, ran out of time')
  expect(read('interrupted')).toBe('4 bytes, 8 requested, was interrupted')
  // Absent means the whole range was read — so a short read with no reason claims none.
  expect(read(undefined)).toBe('4 bytes, 8 requested')
})

test('a position the target has moved away from is never drawn as the ip', async ($, on) => {
  // The pane folds a stop, then a run that reports no position. The model deliberately keeps the
  // old `ip` and does not stamp `ipAt`; the renderer has to honour that or the care is undone at
  // the draw — the header printed the old address as `ip`, the disassembly marked it `▶`, and the
  // panel note said "ip is elsewhere" about a position nothing had re-read.
  const answers: unknown[] = [
    { status: 'ok', kind: 'launch', session_id: 'sess-stale', target: 'x.exe' },
    { status: 'ok', start: '0x1000', instructions: [
      { address: '0x1000', bytes: '90', module: 'x', rva: '0x1000', text: 'nop' },
      { address: '0x1001', bytes: '90', module: 'x', rva: '0x1001', text: 'nop' },
    ] },
    { status: 'ok', command: 'g', interrupted: false, timed_out: false, target_gone: false, output: 'Breakpoint 0 hit', stopped_at: '0x1000' },
  ]
  let i = 0
  on('tool.call', async () => {
    const data = answers[i++]!
    const text = JSON.stringify(data)
    return { result: { content: [{ type: 'text', text }], isError: false, structuredContent: data }, text }
  })
  await $.tool.call({ tool: 'mcp__windbg__launch', command: 'x.exe' })
  await $.tool.call({ tool: 'mcp__windbg__disassemble', address: '0x1000', count: 2 })
  await $.tool.call({ tool: 'mcp__windbg__go' })

  const mount = () => $.ui.mount({
    plugin: 'windbg-pane',
    surface: 'terminal',
    component: 'Pane',
    requestId: 'windbg',
    props: { title: 'WinDbg', isFocused: false, bodyColumns: 140, placement: 'dock', scroll: { offset: 0, bodyRows: 48 }, view: {} },
    viewport: { columns: 220, rows: 50, isFullscreen: true },
  })
  const text = async (ui: Awaited<ReturnType<typeof mount>>) =>
    (await ui.findAll({ type: 'Text' })).map(x => x.text).join('\n')

  // Stopped at a known position: it is the ip, and its row is marked.
  const first = await mount()
  const atStop = await text(first)
  expect(atStop).toMatch(/ip 00000000`00001000/)
  expect(atStop).toMatch(/▶/)
  await first.unmount()

  // A positionless stop — a module-load break, where the engine answers no thread context.
  answers.push({ status: 'ok', command: 'g', interrupted: false, timed_out: false, target_gone: false, output: 'ModLoad: ntdll.dll' })
  await $.tool.call({ tool: 'mcp__windbg__go' })
  const second = await mount()
  const after = await text(second)
  expect(after).toMatch(/moved from 00000000`00001000, position not reported/)
  // Not as the ip, not marked in the listing, and not called "elsewhere".
  expect(after).not.toMatch(/ip 00000000`00001000/)
  expect(after).not.toMatch(/▶/)
  expect(after).not.toMatch(/ip is elsewhere/)
  await second.unmount()
})

test('a teardown is unresolved only where the server says recovery is required', () => {
  const end = (payload: Record<string, unknown>) => {
    let v = EMPTY
    const a = { command: 'x.exe' }
    const [o, m] = begin(v, 'launch', a)
    v = finish(o, m, 'launch', a, {
      ok: true,
      data: { status: 'ok', kind: 'launch', session_id: 'sess-end', target: 'x.exe' },
      error: '',
      ms: 1,
    })
    const b = { session_id: 'sess-end' }
    const [st, n] = begin(v, 'end_session', b)
    v = finish(st, n, 'end_session', b, { ok: true, data: { status: 'ok', session_id: 'sess-end', ...payload }, error: '', ms: 1 })
    return { state: v.sessions[0]!.state, note: v.log[v.log.length - 1]!.note }
  }

  // `released` says whether the *worker* let go of the target, not whether the session is still
  // open: one killed holding its target answers `false` while the supervisor has closed the
  // session anyway. Reading it as the state left such a session marked `unresolved` for ever.
  expect(end({ released: false, worker_terminated: true, recovery_required: false, target_left_running: false }))
    .toEqual({ state: 'closed', note: 'the worker did not release the target, target did not outlive the session' })

  // `recovery_required` is the field that says a teardown is unconfirmed — "this response is not a
  // confirmed detach" — and only the preserved live-control case sets it.
  expect(end({ released: false, worker_terminated: true, recovery_required: true }))
    .toEqual({ state: 'unresolved', note: 'the worker did not release the target, recovery required' })

  // An attached process detached and left running; and a dump, which has nothing that outlives it.
  expect(end({ released: true, worker_terminated: false, recovery_required: false, target_left_running: true }))
    .toEqual({ state: 'closed', note: 'released, target left running' })
  expect(end({ released: true, worker_terminated: false, recovery_required: false }))
    .toEqual({ state: 'closed', note: 'released' })
})

test('the current session follows the server, not whichever session is newest', () => {
  let v = EMPTY
  const open = (id: string, target: string) => {
    const a = { command: target }
    const [st, n] = begin(v, 'launch', a)
    v = finish(st, n, 'launch', a, {
      ok: true,
      data: { status: 'ok', kind: 'launch', session_id: id, target },
      error: '',
      ms: 1,
    })
  }
  open('sess-1', 'one.exe')
  open('sess-2', 'two.exe')
  expect(v.current).toBe('sess-2')

  // s2 turns out to be releasing a Secure Kernel KD session. `accepts_handle` admits six of the
  // nine KD phases and `Releasing` is **not** one, so the server routes an unaddressed call to s1
  // and says so in `SessionInfo::current`.
  //
  // The phase is the whole point of the construction. Any state the pane can *name* as ineligible
  // — `failed`, `closed` — is caught by its own exclusion list, so a test using one of those would
  // pass with this fix backed out, on the neighbouring rule. `sk kd releasing` is a display string
  // no list can keep up with, which is why the server's own answer has to be the authority.
  {
    const a = { session_id: 'sess-2' }
    const [st, n] = begin(v, 'session_status', a)
    v = finish(st, n, 'session_status', a, {
      ok: true,
      data: {
        status: 'ok',
        asked: 'sess-2',
        max_sessions: 4,
        sessions: [
          { session_id: 'sess-1', kind: 'launch', target: 'one.exe', state: { state: 'open' }, current: true },
          { session_id: 'sess-2', kind: 'launch', target: 'two.exe', state: { state: 'secure_kernel_kd', phase: 'releasing' }, current: false },
        ],
      },
      error: '',
      ms: 1,
    })
  }
  expect(v.sessions.find(x => x.id === 'sess-2')!.state).toBe('sk kd releasing')
  expect(v.current).toBe('sess-1')

  // And it stays there: a later addressed call to s2 does not take it back, and neither does
  // anything else short of an opener or another status row.
  {
    const a = { session_id: 'sess-2' }
    const [st, n] = begin(v, 'registers', a)
    v = finish(st, n, 'registers', a, {
      ok: true,
      data: { status: 'ok', registers: [{ name: 'rax', value: '0x9' }], instruction_pointer: '0x9000' },
      error: '',
      ms: 1,
    })
  }
  expect(v.current).toBe('sess-1')

  // A third opener does move it, and the belief survives without another status call.
  open('sess-3', 'three.exe')
  expect(v.current).toBe('sess-3')
  {
    const a = { session_id: 'sess-1' }
    const [st, n] = begin(v, 'backtrace', a)
    v = finish(st, n, 'backtrace', a, { ok: true, data: { status: 'ok', frames: [] }, error: '', ms: 1 })
  }
  expect(v.current).toBe('sess-3')
})

test('a one-shot breakpoint is not drawn as armed after the target has run', () => {
  let v = EMPTY
  const call = (tool: string, a: Record<string, unknown>, data: Record<string, unknown> | null) => {
    const [st, n] = begin(v, tool, a)
    v = finish(st, n, tool, a, { ok: true, data, error: '', ms: 1 })
  }
  call('launch', { command: 'x.exe' }, { status: 'ok', kind: 'launch', session_id: 'sess-1s', target: 'x.exe' })

  // Two breakpoints, one of them one-shot. DbgEng deletes a one-shot when it is hit.
  call('breakpoints', { session_id: 'sess-1s' }, {
    status: 'ok',
    breakpoints: [
      { id: 0, address: '0x1000', expression: 'x!main', enabled: true, one_shot: false },
      { id: 1, address: '0x2000', expression: 'x!once', enabled: true, one_shot: true },
    ],
  })
  const fresh = v.sessions[0]!
  expect(bpsMayBeStale(fresh)).toBe(false)
  expect(fresh.bpsAt).toBeGreaterThan(fresh.movedAt)

  // A run. The ordinary breakpoint survives it; the one-shot may not have.
  call('go', { session_id: 'sess-1s' }, {
    status: 'ok', command: 'g', interrupted: false, timed_out: false, target_gone: false,
    output: 'Breakpoint 1 hit', stopped_at: '0x2000',
  })
  const ran = v.sessions[0]!
  expect(ran.movedAt).toBeGreaterThan(ran.bpsAt)
  expect(bpsMayBeStale(ran)).toBe(true)

  // Re-reading the inventory settles it, and the panel stops hedging.
  call('breakpoints', { session_id: 'sess-1s' }, {
    status: 'ok',
    breakpoints: [{ id: 0, address: '0x1000', expression: 'x!main', enabled: true, one_shot: false }],
  })
  const after = v.sessions[0]!
  expect(after.bps!.map(b => b.id)).toEqual([0])
  expect(bpsMayBeStale(after)).toBe(false)

  // And an inventory with no one-shot in it is never put in doubt by movement alone.
  call('go', { session_id: 'sess-1s' }, {
    status: 'ok', command: 'g', interrupted: false, timed_out: false, target_gone: false,
    output: 'Breakpoint 0 hit', stopped_at: '0x1000',
  })
  const plain = v.sessions[0]!
  expect(plain.movedAt).toBeGreaterThan(plain.bpsAt)
  expect(bpsMayBeStale(plain)).toBe(false)
})

test('a batch that writes drops the disassembly rather than redrawing it', () => {
  let v = EMPTY
  const call = (tool: string, a: Record<string, unknown>, data: Record<string, unknown> | null) => {
    const [st, n] = begin(v, tool, a)
    v = finish(st, n, tool, a, { ok: true, data, error: '', ms: 1 })
  }
  call('launch', { command: 'x.exe' }, { status: 'ok', kind: 'launch', session_id: 'sess-w', target: 'x.exe' })
  call('disassemble', { session_id: 'sess-w', address: '0x1000', count: 2 }, {
    status: 'ok',
    start: '0x1000',
    instructions: [
      { address: '0x1000', bytes: '90', module: 'x', rva: '0x1000', text: 'nop' },
      { address: '0x1001', bytes: '90', module: 'x', rva: '0x1001', text: 'nop' },
    ],
  })
  expect(v.sessions[0]!.disasm!.rows.length).toBe(2)

  // A batch whose steps report no change leaves the listing alone — code does not change because
  // the target moved, which is why `movedAt` is not the stamp for it.
  call('debug_batch', { session_id: 'sess-w', steps: [] }, {
    status: 'ok', outcome: 'committed', committed: true, rollback_complete: true,
    steps: [{ position: 1, label: 'read', action: 'r', result: 'ok', cut_short: false, target_gone: false }],
    always: [],
    after: { state: 'stopped', ip: '0x1000' },
  })
  expect(v.sessions[0]!.disasm!.rows.length).toBe(2)

  // One that patched a byte does not. `BatchStepInfo::changes` is the executor's own record of a
  // mutation, and patching a byte is what a batch is for — so the pane no longer knows what is at
  // those addresses and says so by dropping the panel rather than drawing stale bytes.
  call('debug_batch', { session_id: 'sess-w', steps: [] }, {
    status: 'ok', outcome: 'committed', committed: true, rollback_complete: true,
    steps: [{ position: 1, label: 'patch', action: 'eb 0x1000 cc', result: 'ok', changes: '1 byte at 0x1000', cut_short: false, target_gone: false }],
    always: [{ position: 1, label: 'restore', action: 'eb 0x1000 90', result: 'ok', changes: '1 byte at 0x1000', cut_short: false, target_gone: false }],
    after: { state: 'stopped', ip: '0x1000' },
  })
  expect(v.sessions[0]!.disasm).toBe(null)
  // Both blocks count: a rollback writes too.
  expect(v.log[v.log.length - 1]!.note).toContain('wrote 1 byte at 0x1000, 1 byte at 0x1000')
})

test('every panel asks one place whether a one-shot is still armed', async ($, on) => {
  // The breakpoint panel hedged a consumed one-shot and the disassembly went on drawing its red
  // marker, because each site computed its own view of freshness from the raw fields. `drawable`
  // answers once and both read it — this asserts the two agree, which is the property that kept
  // being broken one site at a time.
  const answers: Record<string, unknown>[] = [
    { status: 'ok', kind: 'launch', session_id: 'sess-marks', target: 'x.exe' },
    { status: 'ok', start: '0x1000', instructions: [
      { address: '0x1000', bytes: '90', module: 'x', rva: '0x1000', text: 'nop' },
      { address: '0x2000', bytes: '90', module: 'x', rva: '0x2000', text: 'nop' },
    ] },
    { status: 'ok', breakpoints: [
      { id: 0, address: '0x1000', expression: 'x!main', enabled: true, one_shot: false },
      { id: 1, address: '0x2000', expression: 'x!once', enabled: true, one_shot: true },
    ] },
  ]
  let i = 0
  on('tool.call', async () => {
    const data = answers[i++]!
    const text = JSON.stringify(data)
    return { result: { content: [{ type: 'text', text }], isError: false, structuredContent: data }, text }
  })
  await $.tool.call({ tool: 'mcp__windbg__launch', command: 'x.exe' })
  await $.tool.call({ tool: 'mcp__windbg__disassemble', address: '0x1000', count: 2 })
  await $.tool.call({ tool: 'mcp__windbg__breakpoints' })

  const draw = async () => {
    const ui = await $.ui.mount({
      plugin: 'windbg-pane',
      surface: 'terminal',
      component: 'Pane',
      requestId: 'windbg',
      props: { title: 'WinDbg', isFocused: false, bodyColumns: 140, placement: 'dock', scroll: { offset: 0, bodyRows: 48 }, view: {} },
      viewport: { columns: 220, rows: 50, isFullscreen: true },
    })
    const text = (await ui.findAll({ type: 'Text' })).map(x => x.text).join('\n')
    await ui.unmount()
    return text
  }

  // Freshly read: both marked armed, and the panel claims the count.
  const fresh = await draw()
  expect(fresh).toMatch(/2 set/)
  expect(fresh).toMatch(/●/)
  expect(fresh).not.toMatch(/◌/)

  // A run that may have consumed the one-shot. The panel hedges *and* the listing stops drawing
  // that one as armed — while the ordinary breakpoint keeps its marker.
  answers.push({
    status: 'ok', command: 'g', interrupted: false, timed_out: false, target_gone: false,
    output: 'Breakpoint 1 hit', stopped_at: '0x2000',
  })
  await $.tool.call({ tool: 'mcp__windbg__go' })
  const after = await draw()
  expect(after).toMatch(/a one-shot may have been hit since this was read/)
  expect(after).not.toMatch(/2 set/)
  // Both markers are present: the ordinary one armed, the one-shot in doubt.
  expect(after).toMatch(/●/)
  expect(after).toMatch(/◌/)
})

test('the instruction a live step just ran is not drawn as the stop', async ($, on) => {
  // A live Secure Kernel stop reports the instruction it *stepped*, so RIP is the one after it —
  // `.claude/rules/secure-kernel-live.md` says so, and `sk_live_step` refuses that record fed back
  // as the next instruction. Synthetic here so a clone covers the path; the recorded SK fixtures
  // hold a lab VM's addresses and are not in the repository.
  const answers: Record<string, unknown>[] = [
    { status: 'ok', kind: 'sk_live_control', session_id: 'sess-sk', target: 'vtl1' },
    {
      status: 'ok',
      vtl: 1,
      cpl: 0,
      reason: 'single_step',
      slot: null,
      registers: { values: [
        { name: 'rip', low: '0x1008', high: '0x0', status: '0x0' },
        { name: 'cr3', low: '0x1ab000', high: '0x0', status: '0x0' },
      ] },
      instruction: { address: '0x1000', bytes: [72, 139, 5, 1, 0, 0, 0, 144] },
    },
  ]
  let i = 0
  on('tool.call', async () => {
    const data = answers[i++]!
    const text = JSON.stringify(data)
    return { result: { content: [{ type: 'text', text }], isError: false, structuredContent: data }, text }
  })
  await $.tool.call({ tool: 'mcp__windbg__open_sk_live_control', vp: 0 })
  await $.tool.call({ tool: 'mcp__windbg__sk_live_registers' })

  const ui = await $.ui.mount({
    plugin: 'windbg-pane',
    surface: 'terminal',
    component: 'Pane',
    requestId: 'windbg',
    props: { title: 'WinDbg', isFocused: false, bodyColumns: 140, placement: 'dock', scroll: { offset: 0, bodyRows: 48 }, view: {} },
    viewport: { columns: 220, rows: 50, isFullscreen: true },
  })
  const drawn = (await ui.findAll({ type: 'Text' })).map(x => x.text).join('\n')
  expect(drawn).toMatch(/the instruction just executed, no disassembly/)
  expect(drawn).not.toMatch(/bytes at the stop/)
  // RIP is 0x1008 and the row is 0x1000. Saying the ip is "elsewhere" would read as a listing
  // taken somewhere else, when it is the instruction this stop just ran.
  expect(drawn).not.toMatch(/ip is elsewhere/)
  await ui.unmount()
})
