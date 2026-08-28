# windbg-mcp

[![CI](https://github.com/glslang/windbg-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/glslang/windbg-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CodeRabbit Pull Request Reviews](https://img.shields.io/coderabbit/prs/github/glslang/windbg-mcp?utm_source=oss&utm_medium=github&utm_campaign=glslang%2Fwindbg-mcp&labelColor=171717&color=FF570A&label=CodeRabbit+Reviews)](https://coderabbit.ai)
[![Latest release](https://img.shields.io/badge/release-v0.13.1-blue)](https://github.com/glslang/windbg-mcp/releases/latest)
[![Platform: Windows x64](https://img.shields.io/badge/platform-Windows%20x64-0078D6)](https://github.com/glslang/windbg-mcp/blob/main/docs/install.md#requirements)

An [MCP](https://modelcontextprotocol.io) server that exposes **WinDbg/DbgEng** to AI agents
(Claude Code, Claude Desktop, Cursor, …) over stdio. It drives a live debugger engine for
**user-mode**, **kernel-mode**, **crash-dump**, and **Time Travel Debugging (TTD)** workflows.

The low-level engine bindings live in [`dbgscope`](https://github.com/glslang/dbgscope)
(`src/dbgeng.rs`); this crate adds process-per-session engine supervision and the `rmcp` tool
surface on top.

## Documentation

This file is the map. Each topic is one document, and each document is the whole of that topic.

| | |
|---|---|
| [Install and engine setup](docs/install.md) | Requirements, prebuilt binaries, Scoop, and the one-time WinDbg engine copy that TTD replay, `!analyze`, the driver tools and 32-bit .NET SOS need |
| [Use with an MCP client](docs/mcp-clients.md) | Client config, running the server on another machine (`--listen`), the Claude Code plugin, the MCP registry |
| [Architecture](docs/architecture.md) | Why a supervisor process and one engine worker per session, what each source file owns, and which MCP revisions are served |
| [The tool surface](docs/tool-surface.md) | Serving fewer tools with `--tools`, what a typed operand may contain, and how the control-flow and TTD tools behave |
| [Sessions and session handles](docs/sessions.md) | `session_id` routing, the four-session cap, `interrupt`, progress notifications, and recovering a parked attach |
| [Kernel connection profiles](docs/kernel-profiles.md) | Keeping a KDNET debug key out of tool arguments and out of the client's transcript |
| [Structured results](docs/structured-results.md) | Which tools answer with `structuredContent`, what each carries, and the error categories a caller can branch on |
| [Transactional batches](docs/debug-batch.md) | `debug_batch`: a mutating sequence whose cleanup runs on every path, including a timeout or a disconnect |
| [Walking a structure](docs/walk-memory.md) | `walk_memory`: lists, arrays and chains where an unreadable node is a row rather than the end of the walk |
| [Session transcripts](docs/transcripts.md) | `WINDBG_MCP_TRANSCRIPT`: a JSONL record of every call, what is redacted, and rendering one as an asciicast |
| [Limitations & notes](docs/limitations.md) | The honest edges — TTD is user-mode only, static reachability is best-effort, pool and heap walks need a stopped x64 target |
| [Walkthroughs](docs/walkthroughs.md) | Worked sessions end to end: crash-dump triage, TTD, a Flare-On solve, driver IOCTL surfaces |
| [The local-model eval](docs/local-model-eval.md) | A grid of model × tool surface × context window against a verified answer key: what a laptop-sized model can drive, and the two defects it found in this server |

Operator and reference material: [remote listener](docs/remote-listener.md),
[driving it with ollama](docs/local-model.md), [disassembler coordinates](docs/coordinates.md),
[smoke test](docs/smoke-test.md), [token budget](docs/token-budget.md),
[releasing](docs/releasing.md).

## Quick start

Windows x64, with `dbgeng.dll` from `System32` — enough for live user-mode, kernel and crash-dump
work. TTD `.run` replay, `!analyze` and the driver tools each need files that engine does not ship;
[`docs/install.md`](docs/install.md) is the one-time copy.

Download a prebuilt `windbg-mcp-vX.Y.Z-windows-x64.zip` from a
[release](https://github.com/glslang/windbg-mcp/releases), or build it:

```pwsh
cargo build --release
```

Then point a client at the binary:

```jsonc
// .mcp.json  (or claude_desktop_config.json under "mcpServers")
{
  "mcpServers": {
    "windbg": {
      "command": "C:\\workspace\\windbg-mcp\\target\\release\\windbg-mcp.exe"
    }
  }
}
```

The client and the model do not have to run where DbgEng does: `--listen <addr>` serves the same
tools over HTTP, one bearer token per client, so a Mac can drive a Windows VM — see
[`docs/mcp-clients.md`](docs/mcp-clients.md) and [`docs/remote-listener.md`](docs/remote-listener.md).

`cargo test` covers the unit tests plus an end-to-end smoke test that drives the built binary over
stdio; run it after a dependency bump or an MCP spec revision — [`docs/smoke-test.md`](docs/smoke-test.md).

## How it works

**One debug session per process.** dbgeng.dll holds a single debuggee session per process, so this
server runs the MCP protocol in a **supervisor** and each open target in its own **engine worker**
child process. Two things follow: a session that cannot be unwound — a live-kernel attach waiting on
a guest that never dials in — costs a process rather than the server, and sessions are **concurrent**
(triage a crash dump while a kernel attach is live, up to four at once).

Every tool that touches a target takes the `session_id` an opener returned, and that is what routes
the call. Omit it and the call goes to the current session. [`docs/architecture.md`](docs/architecture.md)
has the process model and the file-by-file breakdown; [`docs/sessions.md`](docs/sessions.md) has the
handle rules, the cap, and what to do when a session is stuck.

**A 32-bit target gets a 32-bit worker.** An extension DLL is loaded into the debugger's own
process, so .NET's SOS on a 32-bit target is reachable only from a 32-bit host — which a process
cannot become after its image has loaded. So the release ships a second build of this same server
at `x86\windbg-mcp.exe`, and a 32-bit dump or a WoW64 `attach_process` is opened by that worker
instead of by a re-execution of the x64 one. A client cannot tell: one server, one handle, one tool
surface. Where that worker or its 32-bit engine is absent the target still opens on the x64 build —
native analysis of it works and always has — and says so in the opener's `limitation`.

## Tools

Fifty-one tools in eight `--tools` groups; the rows below split some of those groups by theme. The
`--tools` column is the name that selects one — see
[Serving fewer tools](docs/tool-surface.md#serving-fewer-tools---tools).

| Group | `--tools` | Tools |
|-------|-----------|-------|
| Session | `session` | `open_dump`, `open_trace`, `attach_kernel_local`, `attach_kernel`, `attach_process`, `launch`, `interrupt`, `end_session`, `session_status` |
| Server   | `session` | `server_log` — the server's own log: the supervisor's records, plus those of the sessions you opened, tagged with the session each belongs to |
| State   | `inspect` | `registers`, `read_memory`, `backtrace` (the stack as typed frames, each carrying `module`+`RVA` where the engine can place it, as well as its symbol), `modules`, `threads`, `disassemble` (instructions as records, each with its encoding and, where the engine can place it, its `RVA`), `dx`, `set_symbol_path` |
| Crash   | `crash` | `crash_triage` — a bug check as fields: code and parameters, crashing process, the stack as `module+RVA`, and the faulting driver frame |
| Control | `exec` | `go`, `step_over`, `step_into`, `set_breakpoint`, `run_to_address` |
| Transaction | `batch` | `debug_batch` — an ordered sequence with assertions and a rollback the engine process runs on every path |
| TTD nav | `ttd` | `step_back` (`t-`), `step_over_back` (`p-`), `reverse_go` (`g-`), `goto_position` (`!tt`) |
| TTD analysis | `ttd` | `ttd_calls`, `ttd_memory`, `ttd_events`, `index_trace`, `record_trace` |
| Driver IOCTL | `ioctl` | `decode_ioctl`, `driver_object`, `device_object`, `irp_stack`, `ioctl_trace`, `reachable_from_dispatch` |
| Kernel pool | `allocator` | `pool_find_tag`, `pool_chunk`, `pool_census`, `pool_diagnostics` |
| User Segment Heap | `allocator` | `heap_list`, `heap_allocations`, `heap_chunk`, `heap_census`, `heap_diagnostics` |
| Structure walk | `allocator` | `walk_memory` |
| Raw     | `inspect` | `execute` — run any debugger command, returns full text output |

All of them are served unless you say otherwise, and the definitions cost the model **68,322 bytes —
about 17k tokens — before it has asked anything**. `--tools session,inspect,crash` cuts that to
24,894 B for twenty tools, and a `--listen` client can be given a narrower surface than the run's
default. [`docs/tool-surface.md`](docs/tool-surface.md) has the arithmetic, the rule that `session`
is always included, and what a typed operand may not contain.

Most of the tools also answer with MCP `structuredContent`, so a program can read a field
instead of parsing prose, and a failure carries a stable category (`invalid_argument`, `debugger`,
`timeout`, `stale_session`, …) rather than wording —
[`docs/structured-results.md`](docs/structured-results.md).

## Walkthroughs

Worked sessions with the real outputs and the gotchas — the long form is in
[`docs/walkthroughs.md`](docs/walkthroughs.md).

- [Crash-dump triage](docs/crash-dump-walkthrough.md) — a `0x9F DRIVER_POWER_STATE_FAILURE` traced to
  `nvlddmkm.sys`, and a `0x13A` in a driver with no PDB.
- [TTD tour](docs/ttd-walkthrough.md) — opening a `.run`, forward/reverse navigation, and counting
  `printf` calls with symbols.
- [Flare-On 12 #8](docs/flareauthenticator-ttd-walkthrough.md) — a full TTD → Z3 solve of an
  obfuscated Qt crackme.
- [Driver IOCTL surface](docs/driver-ioctl-walkthrough.md) — recovering a dispatch switch on a live
  KDNET kernel and deciding user-mode reachability.
- [Explorer won't start](docs/explorer-crash-walkthrough.md) — the server debugging its own host:
  a dead Windows shell traced through three faults to a malformed State Repository.
- [Disassembler coordinates](docs/coordinates.md) — joining a `crash_triage` frame to a function in
  an image fetched on another machine.

## Driving it with a local model

The tool surface is paid on every turn, so *"can a model that runs on a laptop actually drive
this?"* is a question about **this server** as much as about the model. The repo ships the
benchmark rather than the assertion: `tools/local_model_eval.py` runs a grid of model × tool
surface × context window, `tools/bench_listener.ps1` serves all three surfaces from one listener as
three separately-budgeted clients, and the answer key is read off the checked-in crash dumps with
this server's own tools before any model sees them. Claude is in the grid as the control, not as a
competitor. [`docs/local-model-eval.md`](docs/local-model-eval.md) is the write-up.

- **The context window was not the binding constraint.** A 17,300-token surface answered all six
  tasks at a *served* 8,192-token window — multi-turn ones carrying 10,000 characters of tool
  output included. The arithmetic that predicted otherwise is in `docs/local-model.md`, and it was
  wrong.
- **Cutting 51 tools to 11 costs two of six answers.** Most facts here are reachable by more than
  one route, so a narrow surface keeps the ones that matter.
- **It measures this server before it measures the model.** Every off-surface tool call the first
  grid recorded was a name this server had advertised and would then refuse — in the `instructions`
  sent at connect time, and in the descriptions of the tools it *does* serve. Both are narrowed per
  client now, and re-running the narrow cells took those calls from 17 to 6, with every
  server-taught name at zero.

[**The Tool Surface Grid**](https://claude.ai/code/artifact/aad9956d-47f3-450a-a436-1d2b29939a39)
is the visual write-up — 33 cells, five models, the three axes, and what the two fixes it produced
did and did not buy.

## Limitations

The full list, with what each one means for a workflow, is in
[`docs/limitations.md`](docs/limitations.md). The four that catch people first:

- **TTD is user-mode only** — a Microsoft limitation, so a kernel target cannot be time-travelled.
- **One command at a time per session.** Sessions run concurrently, but each is one engine running
  operations serially: await each result before sending the next call against that session.
- **Symbol *names* need setup on the debugger host** — `msdia140.dll` beside the binary, a symbol
  path, and (for TTD) a reload at a stopped position. Without them, address-based queries still work.
- **The pool and heap walkers need a stopped x64 target.** They decode x64 allocator structures, so
  a 32-bit target has no `heap_*` tools whichever worker holds it — SOS's own `!dumpheap`/`!eeheap`
  are the managed equivalent, and reaching those is what the 32-bit worker and its `x86\` engine
  payload ([`docs/install.md`](docs/install.md)) are for.
