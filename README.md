# windbg-mcp

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

### Releasing

The plugin sets an explicit `version` in
[`.claude-plugin/plugin.json`](.claude-plugin/plugin.json), so users only receive an update
when that version changes — pushing commits alone does not trigger one. To cut a release, bump
`version` in `plugin.json` and `Cargo.toml`, add a matching entry to
[`CHANGELOG.md`](CHANGELOG.md), and tag the commit `vX.Y.Z`. Run
`claude plugin validate . --strict` before publishing. Pushing the tag runs
[`release.yml`](.github/workflows/release.yml), which verifies the tag matches both manifest
versions, builds `windbg-mcp.exe`, and attaches the zip + SHA256 checksum to the GitHub release.

## Walkthroughs

- [`docs/crash-dump-walkthrough.md`](docs/crash-dump-walkthrough.md) — triaging a real kernel
  minidump ([`docs/samples/052126-34312-01.dmp`](docs/samples/052126-34312-01.dmp)): a
  `0x9F DRIVER_POWER_STATE_FAILURE` traced to `nvlddmkm.sys` via `!ext.analyze -v` and a manual
  device-stack walk, with the real outputs and the partial-minidump (`0x80040205`) gotcha.
- [`docs/ttd-walkthrough.md`](docs/ttd-walkthrough.md) — a hands-on tour of the TTD tools against the
  [`xusheng6/TTD_lab`](https://github.com/xusheng6/TTD_lab) `helloworld` sample: opening a `.run`,
  surveying events/threads, forward/reverse navigation, memory analysis, and counting `printf` calls
  with symbols (with the real outputs and the gotchas). It maps each tool to the lab's exercises.

## Tools

| Group | Tools |
|-------|-------|
| Session | `open_dump`, `open_trace`, `attach_kernel_local`, `attach_kernel`, `attach_process`, `launch`, `end_session` |
| State   | `registers`, `read_memory`, `backtrace`, `modules`, `threads`, `disassemble`, `dx` |
| Control | `go`, `step_over`, `step_into`, `set_breakpoint` |
| TTD nav | `step_back` (`t-`), `step_over_back` (`p-`), `reverse_go` (`g-`), `goto_position` (`!tt`) |
| TTD analysis | `ttd_calls`, `ttd_memory`, `ttd_events`, `index_trace`, `record_trace` |
| Raw     | `execute` — run any debugger command, returns full text output |

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
