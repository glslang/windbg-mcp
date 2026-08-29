# windbg-mcp

[![CI](https://github.com/glslang/windbg-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/glslang/windbg-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CodeRabbit Pull Request Reviews](https://img.shields.io/coderabbit/prs/github/glslang/windbg-mcp?utm_source=oss&utm_medium=github&utm_campaign=glslang%2Fwindbg-mcp&labelColor=171717&color=FF570A&label=CodeRabbit+Reviews)](https://coderabbit.ai)
[![Latest release](https://img.shields.io/badge/release-v0.13.2-blue)](https://github.com/glslang/windbg-mcp/releases/latest)
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
tools over HTTP, one bearer token per client, so a Mac can drive a Windows VM — and the model
itself can be a local one. [Driving it](#driving-it--hosted-or-local-here-or-on-another-machine)
below has the configurations.

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

All of them are served unless you say otherwise, and the definitions cost the model **68,893 bytes —
about 17k tokens — before it has asked anything**. `--tools session,inspect,crash` cuts that to
25,465 B for twenty tools, and a `--listen` client can be given a narrower surface than the run's
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

## Driving it — hosted or local, here or on another machine

Anything that speaks MCP can hold this server, and **DbgEng is the only part pinned to Windows**.
So the model may be a hosted one inside an editor, a local one in ollama, or an ollama cloud model,
and it does not have to run on the machine being debugged.

| What drives it | Where that runs | The server | Reached over |
|---|---|---|---|
| An MCP client — Claude Code, Cursor, Claude Desktop | the Windows machine | launched by the client | stdio |
| An MCP client | a Mac, or any other machine | a Windows host, `--listen`, usually as a service | HTTP through an ssh forward |
| A model in **ollama** | the Windows machine | the same machine, `--listen` on loopback | HTTP on loopback |
| A model in **ollama** | a Mac | a Windows host, `--listen` as a service | HTTP through an ssh forward |
| A model in **ollama's cloud** | wherever ollama runs | either of the above | unchanged — the tag is all that differs |

**One machine needs no configuration at all**: the client launches the binary and talks to it over
stdio, which is the Quick start above.

**Two machines need a listener.** For a session you are driving anyway, run it in the foreground on
the Windows host — this works wherever the binary happens to live:

```pwsh
$env:WINDBG_MCP_LISTEN_TOKEN = "<a long random string>"   # this shell only
windbg-mcp.exe --listen 127.0.0.1:8765
```

**For anything longer-lived, install it as a service — from a protected directory.** The SCM stores
that exact path for a `LocalSystem` auto-start service, so whoever can write the directory, or drop
an engine DLL beside the exe, gets their code run as SYSTEM at the next start.
`--install-service` therefore refuses an exe outside `%ProgramFiles%`, `%ProgramFiles(x86)%` or
`%SystemRoot%` — which a downloaded zip, a Scoop shim or a `target\release` build all are — so move
the **whole** deployment first: the exe, the engine DLLs beside it, and `x86\`. Then, elevated:

```pwsh
$env:WINDBG_MCP_LISTEN_TOKEN = "<a long random string>"   # this shell only
& "$env:ProgramFiles\windbg-mcp\windbg-mcp.exe" --install-service --listen 127.0.0.1:8765
Start-Service windbg-mcp          # --install-service only *registers* it
```

On a machine that is entirely yours, `--allow-unprotected-path` says so out loud and installs in
place; that is a development install, not a deployment.

Either way, from the machine you are actually working on, for as long as you want the link:

```console
ssh -N -L 8765:127.0.0.1:8765 <windows-host>
```

The listener **refuses to start without a token**, because it serves `execute`, `launch` and
`debug_batch` — an open port here is arbitrary code on the host holding your kernel debugger. Bind
loopback and forward over ssh rather than exposing it. Each client authenticates as itself, and can
be served a narrower `--tools` surface than the run's default, which is how a local model and an
editor share one listener without sharing sessions.
[`docs/remote-listener.md`](docs/remote-listener.md) is the operator's reference.

**Pointing ollama at it is the client's job, not this server's.** An MCP client that drives an
ollama model holds the listener exactly as an editor does — nothing here has to be installed, and
this server never learns which kind of model answered. ollama ships integrations for a number of
those clients; `ollama launch` lists them, and `ollama launch claude --model <tag>` is one. A local
tag and an ollama **cloud** tag are the same route, differing only in the model name.

[`docs/local-model.md`](docs/local-model.md) is the runbook: the arrangements, choosing a model that
can actually run, which of two clocks a quiet model loses its sessions to, and what a cloud tag can no longer
tell you about its own run.

## Whether a local model copes — the benchmark

The tool surface is paid on every turn, so *"can a model that runs on a laptop actually drive
this?"* is a question about **this server** as much as about the model. The repo ships the
benchmark rather than the assertion: `tools/local_model_eval.py` runs a grid of model × tool
surface × context window, `tools/bench_listener.ps1` serves all three surfaces from one listener as
three separately-budgeted clients, and the answer key is read off the checked-in crash dumps with
this server's own tools before any model sees them. Claude is in the grid as the control, not as a
competitor. [`docs/local-model-eval.md`](docs/local-model-eval.md) is the write-up.

Running the grid yourself needs a **development environment rather than a release**: the release
zip is `windbg-mcp.exe`, the `x86\` worker and `LICENSE`, so `tools/` comes from a checkout, and the
driver and grader are Python 3. Nothing above this section needs either — driving the server with a
local model is a client's job, and the driver here exists to *measure* that, one task list at a
time, with no interactive mode.
[`agent-sandbox-vm`](https://github.com/glslang/agent-sandbox-vm) is the Hyper-V / Parallels VM
setup this project is developed and benchmarked in.

- **The context window was not the binding constraint** — on that bench's runtime, which is the
  qualifier that matters. A 17,300-token surface answered all six tasks at a *served* 8,192-token
  window, multi-turn ones carrying 10,000 characters of tool output included. The arithmetic that
  predicted otherwise is in `docs/local-model.md`, and it was wrong; ask `ollama ps` what your own
  runtime serves rather than generalising either result.
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
