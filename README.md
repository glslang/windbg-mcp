# windbg-mcp

[![CI](https://github.com/glslang/windbg-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/glslang/windbg-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CodeRabbit Pull Request Reviews](https://img.shields.io/coderabbit/prs/github/glslang/windbg-mcp?utm_source=oss&utm_medium=github&utm_campaign=glslang%2Fwindbg-mcp&labelColor=171717&color=FF570A&label=CodeRabbit+Reviews)](https://coderabbit.ai)
[![Latest release](https://img.shields.io/badge/release-v0.2.1-blue)](https://github.com/glslang/windbg-mcp/releases/latest)
[![Platform: Windows x64](https://img.shields.io/badge/platform-Windows%20x64-0078D6)](https://github.com/glslang/windbg-mcp#requirements)

An [MCP](https://modelcontextprotocol.io) server that exposes **WinDbg/DbgEng** to AI agents
(Claude Code, Claude Desktop, Cursor, …) over stdio. It drives a live debugger engine for
**user-mode**, **kernel-mode**, **crash-dump**, and **Time Travel Debugging (TTD)** workflows.

The low-level engine bindings live in [`win-kexp`](https://github.com/glslang/win-kexp)
(`src/dbgeng.rs`); this crate adds a dedicated engine thread and the `rmcp` tool surface on top.

## Architecture

- **`engine.rs`** — DbgEng requires serialized, single-thread access (`WaitForEvent` must run on the
  session-owning thread), so the `DebugEngine` is created on, and confined to, one OS worker thread.
  Async tool handlers marshal closures onto it via an `mpsc` channel with `oneshot` replies and a
  per-call timeout. A `catch_unwind` guard turns a panic in one operation into a failed call rather
  than a dead thread.
- **`server.rs`** — the MCP tools (see below), built with `rmcp`'s `#[tool_router]`/`#[tool_handler]`.
- **`ttd.rs`** — locates `TTD.exe` and launches trace recording.
- **`main.rs`** — tokio + stdio transport. **Logs go to stderr** (stdout is the JSON-RPC channel).

**MCP protocol revision:** this server speaks the `initialize`-handshake ("legacy") era of MCP —
`2025-11-25` and `2025-06-18`, whichever the client negotiates — because that is what `rmcp` 1.x
implements. The `2026-07-28` revision replaces the handshake with a stateless, per-request model
(`server/discover`, `resultType`, per-request `_meta`); clients that speak *only* `2026-07-28` cannot
talk to this server. Support for it waits on a stable `rmcp` 3.x (`2026-07-28` support currently
exists only in its beta line).

## Requirements

- Windows x64 (host bitness must match the target).
- `dbgeng.dll` / `dbghelp.dll` — present in `System32` on modern Windows 11 (verified with
  `10.0.26100`). This is enough for live user-mode/kernel debugging and crash-dump analysis.
- **For crash-dump `!analyze`** (and any other `!`-extension command), the engine needs the
  WinDbg `winext\` extensions bundled next to the binary — System32's engine ships none, so
  `!analyze` would return *"No export analyze found"*. See *Bundling the WinDbg engine* below.
- **For Time Travel Debugging (`.run`) replay**, the System32 engine is *not* enough — it rejects
  `.run` traces (`0x80070057`). You need the **WinDbg engine** (which bundles the TTD replay
  components) loaded next to the binary — see *TTD engine* below.
- `TTD.exe` (the standalone Time Travel Debugging recorder) for `record_trace` — ships with the
  WinDbg / TTD store packages; put it on `PATH`.
- A reachable symbol server (e.g. `srv*https://msdl.microsoft.com/download/symbols`) for symbol-name
  queries like `ttd_calls("ucrtbase!_stdio_common_vfprintf")`. Offline, address-based queries and the
  data model still work; symbol *names* won't resolve.
- **Administrator** for live kernel debugging and TTD recording (not for replay).

## Build or download

Prebuilt Windows x64 binaries are attached to each
[GitHub release](https://github.com/glslang/windbg-mcp/releases) as
`windbg-mcp-vX.Y.Z-windows-x64.zip` (with a `SHA256SUMS.txt` to verify the download
against — the skill's `setup.md` snippet does this for you) — no Rust toolchain needed.
To build from source instead:

```pwsh
cargo build --release
```

`win-kexp` is fetched automatically as a git dependency from [`glslang/win-kexp`](https://github.com/glslang/win-kexp) — no sibling checkout needed.

### Bundling the WinDbg engine

Needed for two things: TTD `.run` replay (System32's engine rejects traces with `0x80070057`) and
crash-dump `!analyze` (which lives in the `winext\` extensions that System32 doesn't ship).
`DebugCreate` binds to whichever `dbgeng.dll` the loader finds first, and the app directory is
searched before `System32`, so the copied **WinDbg** engine (which replays TTD traces and ships the
extensions) wins. One-time, from the installed WinDbg store package:

```pwsh
$wd  = (Get-AppxPackage Microsoft.WinDbg).InstallLocation + "\amd64"
$dst = "C:\workspace\windbg-mcp\target\release"
Copy-Item "$wd\dbgeng.dll","$wd\dbghelp.dll","$wd\dbgcore.dll","$wd\dbgmodel.dll",`
          "$wd\symsrv.dll","$wd\msdia140.dll" $dst -Force
Copy-Item "$wd\ttd"    "$dst\ttd"    -Recurse -Force   # TTDReplay*.dll, TtdExt.dll, TTDAnalyze.dll, ...
Copy-Item "$wd\winext" "$dst\winext" -Recurse -Force   # ext.dll (!analyze), kext.dll, … — crash-dump triage
```

- The `ttd\` subdir provides the `@$cursession.TTD` / `@$curprocess.TTD` data model and the `!tt`
  time-travel commands.
- The `winext\` subdir provides `ext.dll` (which exports `!analyze`) and the other `!`-extensions.
  `open_dump` runs `.load ext` for you, but note the **unqualified `!analyze` does not resolve** on
  this minimal engine — use the module-qualified **`!ext.analyze -v`** for crash-dump triage. Without
  `winext\`, `!analyze` returns *"No export analyze found"*.
- **`msdia140.dll` is required for PDB symbols.** Without it, `dbghelp` can't parse any PDB
  (`dia error 0x8007007e`) and silently falls back to *export* symbols — which makes `module!name`
  lookups (and so `ttd_calls("ucrtbase!__stdio_common_vfprintf")`) fail even with the right PDB in
  the cache. `symsrv.dll` is needed to read a symbol-store cache.

(`cargo clean` wipes `target\`, so re-copy after one.) Live and dump debugging work with or without
the TTD engine; PDB symbol *names* need `msdia140.dll` + a symbol path
(`execute` → `.sympath srv*C:\ProgramData\Dbg\sym*https://msdl.microsoft.com/download/symbols`).

## Use with an MCP client

Point your client at the built binary, e.g. Claude Code:

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

### As a Claude Code plugin

This repo is also a single-plugin [Claude Code marketplace](https://code.claude.com/docs/en/plugin-marketplaces):
installing it registers the `windbg` MCP server **and** a `windbg-debugging` skill that
knows how to drive it (setup, crash-dump, live/kernel, and TTD playbooks).

```text
/plugin marketplace add glslang/windbg-mcp
/plugin install windbg-mcp@windbg-mcp
```

The plugin ships source, not a binary, so after installing you still put the server binary in
place — download a prebuilt release or build from source — and (for `.run` replay and
crash-dump `!analyze`) bundle the WinDbg engine — the skill's `setup.md`
walks through it, and it mirrors the [*Build or download*](#build-or-download) and
[*Bundling the WinDbg engine*](#bundling-the-windbg-engine) sections above. Then `/reload-plugins`
to connect the server. The plugin points at `${CLAUDE_PLUGIN_ROOT}/target/release/windbg-mcp.exe`.

### From the official MCP registry

The server is listed in the [official MCP registry](https://registry.modelcontextprotocol.io) as
**`io.github.glslang/windbg-mcp`**. Clients that support the registry — or that install
[MCPB](https://github.com/anthropics/mcpb) bundles directly — can add it by name: the client
downloads that release's `.mcpb` bundle, verifies its SHA-256, and wires up the `windbg-mcp.exe`
inside it as an stdio server, with no Rust build or manual binary placement.

The bundle is **Windows x64 only** and ships just the server binary, so the one-time engine setup
still applies — for TTD `.run` replay and crash-dump `!analyze`, drop the WinDbg engine DLLs next
to the client-extracted `windbg-mcp.exe` (the skill's `setup.md` covers it). Basic live and
crash-dump work runs on the in-box `System32` engine without them.

### Releasing

The plugin sets an explicit `version` in
[`.claude-plugin/plugin.json`](.claude-plugin/plugin.json), so users only receive an update
when that version changes — pushing commits alone does not trigger one. To cut a release, bump
`version` in `plugin.json` and `Cargo.toml`, bump the release badge near the top of this README,
add a matching entry to
[`CHANGELOG.md`](CHANGELOG.md), and tag the commit `vX.Y.Z`. Run
`claude plugin validate . --strict` before publishing. Pushing the tag runs
[`release.yml`](.github/workflows/release.yml), which verifies the tag matches both manifest
versions and the README badge, builds `windbg-mcp.exe`, and attaches the zip + SHA256 checksum to the GitHub release.
It also builds an [MCPB](https://github.com/anthropics/mcpb) bundle
(`windbg-mcp-vX.Y.Z-windows-x64.mcpb`, described by
[`packaging/mcpb/manifest.json`](packaging/mcpb/manifest.json)) and publishes a
[`server.json`](server.json) entry to the [official MCP Registry](https://registry.modelcontextprotocol.io)
(`io.github.glslang/windbg-mcp`) with the `mcp-publisher` CLI over GitHub OIDC — no secrets. CI
stamps the release version into both files and the bundle's SHA-256 into `server.json`, so
neither is part of the manual bump list above.
The zip also gets a signed
[build-provenance attestation](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations)
tying it to the workflow run that built it — verify with:

```pwsh
gh attestation verify <zip> --repo glslang/windbg-mcp `
   --signer-workflow glslang/windbg-mcp/.github/workflows/release.yml
```

(`--repo` alone only proves the attestation came from *some* workflow in this repo;
`--signer-workflow` pins it to the release workflow.)

## Walkthroughs

- [`docs/crash-dump-walkthrough.md`](docs/crash-dump-walkthrough.md) — triaging a real kernel
  minidump ([`docs/samples/052126-34312-01.dmp`](docs/samples/052126-34312-01.dmp)): a
  `0x9F DRIVER_POWER_STATE_FAILURE` traced to `nvlddmkm.sys` via `!ext.analyze -v` and a manual
  device-stack walk, with the real outputs and the partial-minidump (`0x80040205`) gotcha.
- [`docs/ttd-walkthrough.md`](docs/ttd-walkthrough.md) — a hands-on tour of the TTD tools against the
  [`xusheng6/TTD_lab`](https://github.com/xusheng6/TTD_lab) `helloworld` sample: opening a `.run`,
  surveying events/threads, forward/reverse navigation, memory analysis, and counting `printf` calls
  with symbols (with the real outputs and the gotchas). It maps each tool to the lab's exercises.
- [`docs/flareauthenticator-ttd-walkthrough.md`](docs/flareauthenticator-ttd-walkthrough.md) — a full
  **TTD → Z3 solve** of an obfuscated Qt crackme (Flare-On 12 #8). Defeats an anti-analysis env guard,
  records a wrong-guess run, and uses `ttd_calls`/`ttd_memory`/reverse-navigation to peel control-flow
  flattening + computed calls + encrypted strings down to the exact check: a per-keystroke rolling hash
  that reduces to a pure weighted sum. The 25 weights come from the replay, the 250 `g` values from
  debugger function-evaluation, and Z3 finds a satisfying code — which reveals the flag (the code is
  intentionally non-unique). Runnable solver in [`examples/flareauthenticator/`](examples/flareauthenticator/);
  recorded terminal session in [`docs/flareauthenticator.cast`](docs/flareauthenticator.cast)
  (`asciinema play`) — [rendered as a GIF](docs/flareauthenticator.gif) in the walkthrough.
- [`docs/driver-ioctl-walkthrough.md`](docs/driver-ioctl-walkthrough.md) — enumerating a driver's IOCTL
  surface and deciding user-mode reachability on a live KDNET kernel: `driver_object`/`uf` to recover
  the `\Driver\mountmgr` dispatch switch, `decode_ioctl` for the access tiers, the device DACL parsed
  from memory, and an `ioctl_trace` sweep — ending with a reachability report (which codes a standard
  user can reach vs. what the I/O manager blocks).

## Tools

| Group | Tools |
|-------|-------|
| Session | `open_dump`, `open_trace`, `attach_kernel_local`, `attach_kernel`, `attach_process`, `launch`, `end_session` |
| State   | `registers`, `read_memory`, `backtrace`, `modules`, `threads`, `disassemble`, `dx` |
| Control | `go`, `step_over`, `step_into`, `set_breakpoint` |
| TTD nav | `step_back` (`t-`), `step_over_back` (`p-`), `reverse_go` (`g-`), `goto_position` (`!tt`) |
| TTD analysis | `ttd_calls`, `ttd_memory`, `ttd_events`, `index_trace`, `record_trace` |
| Driver IOCTL | `decode_ioctl`, `driver_object`, `device_object`, `irp_stack`, `ioctl_trace`, `reachable_from_dispatch` |
| Raw     | `execute` — run any debugger command, returns full text output |

### Session handles

The six Session tools that open a target (`open_dump`, `open_trace`, `attach_kernel_local`,
`attach_kernel`, `attach_process`, `launch`) return a **`session_id`**. Every tool that touches the
debug target accepts it as an optional argument and refuses to run if it no longer matches the
session the engine is attached to.

This matters because one server process drives one DbgEng session, while an MCP connection is *not*
a session: a client may interleave unrelated requests over the same stdio process. Without a handle,
a `read_memory` issued after someone else's `open_dump` silently reads the wrong target. Passing
`session_id` turns that into a visible error instead.

The check runs **on the engine thread**, in the same queued job as the debugger call it guards.
That ordering is what makes it sound: checking on the caller side would leave a window in which a
concurrently-issued `open_dump` is queued ahead of a call that already passed validation, so the
call would still execute against the replaced target.

The guarantee is *detection, not exclusion*: the opening tools deliberately take no `session_id`, so
holding a handle does not stop another caller replacing your target — it guarantees that any later
call of yours which supplies the handle fails loudly instead of acting on a target you did not open.

The argument is optional — omit it and a call operates on whatever session is current, exactly as
before. `decode_ioctl` (pure) and `record_trace` (independent of the debug session) do not take it.

### Error reporting

A failed *debugger operation* — an unresolvable symbol, an unreadable address, a target that never
stopped — comes back as a normal tool result with `isError: true` and the debugger's own text, so
the model can read it and correct itself. Only a dead engine thread is reported as a JSON-RPC
protocol error.

The forward (`go`/`step_over`/`step_into`) and reverse (`reverse_go`/`step_over_back`/`step_back`)
control tools mirror a debugger UI's F9/F8/F7 and Shift+F9/F8/F7, so an agent can drive a trace in
both directions and jump anywhere with `goto_position`. All of these issue the command **and pump the
engine to the next stop** (a plain `Execute` only sets the run state — it doesn't move the target),
which is what makes both live stepping and TTD forward/reverse navigation actually advance.

`ttd_calls`/`ttd_memory`/`ttd_events` are convenience wrappers over the TTD data model: `ttd_calls`
and `ttd_memory` query `@$cursession.TTD.{Calls,Memory}` (every call to a function / every access to
an address range), and `ttd_events` queries `@$curprocess.TTD.Events` (the module/thread/exception
timeline). For anything else, `dx` evaluates arbitrary data-model/LINQ expressions, e.g.
`@$cursession.TTD.Calls("ntdll!NtCreateFile").Where(c => c.ReturnValue != 0)`.

## Limitations & notes

- **TTD is user-mode only** (a Microsoft limitation): kernel debugging and TTD are distinct session
  types — you can't time-travel a kernel target.
- `launch` and `attach_process` stop the target at its initial/break-in point with a live
  process/thread context. (The binding enables the initial-breakpoint event filter — `sxe ibp` —
  which a bare `DebugCreate` host leaves off; without it the target would run free.) Note: on
  Windows 11 `notepad` is a Store app, so attaching by the PID that `Start-Process notepad` returns
  can hit `0xD000010A` (that PID is a transient launcher) — attach to a classic Win32 process.
- `read_memory` takes a numeric/`0x`-hex address only; for register/symbol expressions use
  `execute` with `db`/`dd` (e.g. `db @rip`).
- `reachable_from_dispatch` is a **static** call-graph walk over `uf` disassembly: it follows
  direct calls and cross-function tail jumps but **not** indirect calls through function pointers
  or unresolved compiler jump tables. So a `REACHABLE` verdict is sound (a concrete static path
  exists, and the path is reported), while `NOT REACHABLE` is best-effort within the explored
  bounds. If the dispatch uses a `switch(IoControlCode)` jump table (common), pass the specific
  handler VA as `from` to scope past it, or confirm dynamically with a breakpoint + `go`.
- **Crash-dump triage uses `!ext.analyze -v`**, not `!analyze` — the bundled engine only resolves
  the module-qualified form (see *Bundling the WinDbg engine*). On a **partial minidump**, reads of
  pages that weren't captured raise `An unexpected exception was raised (0x80040205)` rather than a
  clean "memory read error"; query the specific field you need (e.g.
  `dt nt!_DRIVER_OBJECT <addr> DriverName`) instead of dumping whole structures. See the
  [crash-dump walkthrough](docs/crash-dump-walkthrough.md).
- Single-stepping is only valid once the target is stopped with a real thread context (after a
  `go`/step or a breakpoint hit). Stepping straight after a bare `goto_position` to the very start of
  a trace (before any thread is live) returns `0x80040205` — `go` to a breakpoint first.
- Symbol *names* (`module!func`) need (a) `msdia140.dll` bundled next to the binary, (b) a symbol
  path pointing at the PDBs (`.sympath …`), and (c) for TTD, reloading at a *stopped* position
  (after a `go`/breakpoint, not straight off a `!tt`) so the module's PDB is matched and loaded.
  With those, e.g. `ttd_calls("ucrtbase!__stdio_common_vfprintf")` returns the exact call count.
  Without symbols, the data model, navigation, and memory reads still work — query by address.
- **One debug session, one command at a time.** A single engine instance runs on a dedicated
  thread and processes operations serially. Issue tool calls **sequentially — await each result
  before sending the next**; the server does not order concurrent in-flight requests, so pipelining
  them (firing several calls before their results return) can run a command before the one that
  establishes its state (a call racing ahead of `open_dump` fails with `0x80040205`), and is
  meaningless for stateful, order-dependent debugger commands anyway. Standard MCP clients already
  serialize call→result, so this is only a concern for custom/batched callers. End a session with
  `end_session` before opening another target.
- TTD **replay** (`open_trace`) needs `TTDReplay.dll` discoverable but **not** elevation; TTD
  **recording** (`record_trace`) needs `TTD.exe` **and** Administrator. `record_trace` captures the
  recorder's startup output to `<out_dir>\ttd_record.log` and watches it briefly, so a fast failure
  (e.g. running un-elevated → `0x80070005 Access is denied`) is reported as an error rather than a
  false "recording started".
- Control-flow tools (`go`/`step*`) issue the corresponding debugger command; precise stop/wait
  semantics for long-running `go` against a live target are bounded by the per-call timeout.
