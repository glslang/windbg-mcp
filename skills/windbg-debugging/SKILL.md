---
name: windbg-debugging
description: Drive WinDbg/DbgEng via the `windbg` MCP server to debug Windows crash dumps, live user-mode and kernel targets, and Time Travel Debugging (.run) traces. Use when analyzing a .dmp, attaching to a process or the kernel, or recording/navigating/analyzing a TTD trace.
---

# WinDbg debugging via the `windbg` MCP server

This skill drives the `windbg` MCP server, which wraps WinDbg/DbgEng for four kinds of
Windows debugging: **crash-dump** analysis, **live user-mode** debugging, **kernel**
debugging, and **Time Travel Debugging (TTD)** of `.run` traces.

**Verify the environment first.** Most failures are setup, not debugging — wrong engine
DLL, missing symbols, or no elevation. Read **[setup.md](setup.md)** before the first
session of a workflow you haven't run yet in this environment.

## Pick a playbook

| Task | Playbook |
|------|----------|
| Build / engine bundling / symbols / elevation | [setup.md](setup.md) |
| Triage a `.dmp` crash dump | [crash-dump.md](crash-dump.md) |
| Launch/attach a process, or debug the kernel | [live-and-kernel.md](live-and-kernel.md) |
| Record / open / navigate / analyze a `.run` trace | [ttd.md](ttd.md) |

## Tool map

Knowing which verb exists keeps you from reaching for raw `execute` when a typed tool
already does the job.

| Group | Tools |
|-------|-------|
| Session | `open_dump`, `open_trace`, `attach_kernel_local`, `attach_kernel`, `attach_process`, `launch`, `end_session` |
| State | `registers`, `read_memory`, `backtrace`, `modules`, `threads`, `disassemble`, `dx` |
| Control | `go`, `step_over`, `step_into`, `set_breakpoint` |
| TTD nav | `step_back` (`t-`), `step_over_back` (`p-`), `reverse_go` (`g-`), `goto_position` (`!tt`) |
| TTD analysis | `ttd_calls`, `ttd_memory`, `ttd_events`, `index_trace`, `record_trace` |
| Raw | `execute` — run any debugger command, returns full text output |

The forward control tools (`go`/`step_over`/`step_into`) and the reverse ones
(`reverse_go`/`step_over_back`/`step_back`) mirror a debugger UI's F9/F8/F7 and their
Shift variants. They issue the command **and pump the engine to the next stop** — unlike
a bare `execute`, which only sets the run state and doesn't move the target.

## Cross-cutting gotchas (apply to every workflow)

- **One debug session, and one command at a time** (single engine instance, run serially on
  one thread). End a session with `end_session` before opening another target. Issue tool calls
  **sequentially — await each result before the next**: concurrent in-flight requests aren't
  ordered, so a pipelined call can run before `open_dump` establishes a target and fail with
  `0x80040205`, and pipelining stateful debugger commands is unsafe regardless. (Normal MCP
  clients serialize call→result; this only bites custom/batched callers.)
- **Symbol *names* (`module!func`) need three things together:** (a) `msdia140.dll`
  bundled next to the binary, (b) a symbol path (`execute` →
  `.sympath srv*C:\ProgramData\Dbg\sym*https://msdl.microsoft.com/download/symbols`), and
  (c) a `.reload /f` at a *stopped* position (after a `go`/breakpoint, **not** straight off
  a `goto_position`/`!tt`). Without these you silently get export symbols only and
  `module!name` lookups fail. Address-based queries, navigation, and memory reads still
  work without symbols — query by address.
- **`read_memory` takes a numeric/`0x`-hex address only.** For a register/symbol
  expression use `execute` with `db`/`dd` (e.g. `db @rip`).
- **Single-stepping needs a live thread context** — valid only once the target is stopped
  after a `go`/step or a breakpoint hit. Stepping straight after `goto_position 0` (before
  any thread is live) returns `0x80040205`; `go` to a breakpoint first.
- **`dx` is the escape hatch for the data model** — any LINQ query beyond the
  `ttd_calls`/`ttd_memory`/`ttd_events` wrappers, e.g.
  `@$cursession.TTD.Calls("ntdll!NtCreateFile").Where(c => c.ReturnValue != 0)`.
- **TTD is user-mode only** (a Microsoft limitation) — you cannot time-travel a kernel target.
- **Each tool call is bounded by a per-call timeout** (~60s for load/exec waits); a `go`
  against a long-running live target may hit it.
