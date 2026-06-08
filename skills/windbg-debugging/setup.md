# Setup: build, engine bundling, symbols, elevation

Most `windbg` failures are environment problems, not debugging mistakes. Work through the
section for the workflow you're about to run before blaming the target.

## Platform

- **Windows x64 only.** Host bitness must match the target.
- `dbgeng.dll` / `dbghelp.dll` ship in `System32` on modern Windows 11 (verified on
  `10.0.26100`). That is enough for live user-mode/kernel debugging and crash-dump
  analysis — **but not for TTD `.run` replay** (see below).

## Build the server

The plugin ships the source, not a binary. Build it in place so the path in
`plugin.json` (`${CLAUDE_PLUGIN_ROOT}/target/release/windbg-mcp.exe`) resolves:

```pwsh
# From the installed plugin / repo directory. Expects win-kexp as a sibling: ..\win-kexp
cargo build --release
```

This crate has a path dependency on [`win-kexp`](https://github.com/glslang/win-kexp) and
needs its dbgeng MCP-support changes. Until those merge upstream, check out the matching
branch in the sibling checkout, e.g.:

```pwsh
git -C ..\win-kexp fetch origin dbgeng-dump-launch-attach-ttd
git -C ..\win-kexp checkout dbgeng-dump-launch-attach-ttd
```

After `cargo build`, run `/reload-plugins` so Claude Code connects the `windbg` MCP server.

## TTD engine — required for `.run` replay only

System32's `dbgeng.dll` **rejects** `.run` traces with `0x80070057`. `DebugCreate` binds to
whichever `dbgeng.dll` the loader finds first, and the app directory is searched before
`System32` — so drop the **WinDbg** engine next to the built binary. One-time, from the
installed WinDbg store package:

```pwsh
$wd  = (Get-AppxPackage Microsoft.WinDbg).InstallLocation + "\amd64"
$dst = "<plugin dir>\target\release"
Copy-Item "$wd\dbgeng.dll","$wd\dbghelp.dll","$wd\dbgcore.dll","$wd\dbgmodel.dll",`
          "$wd\symsrv.dll","$wd\msdia140.dll" $dst -Force
Copy-Item "$wd\ttd" "$dst\ttd" -Recurse -Force   # TTDReplay*.dll, TtdExt.dll, TTDAnalyze.dll, ...
```

- The `ttd\` subdir provides the `@$cursession.TTD` / `@$curprocess.TTD` data model and the
  `!tt` time-travel commands.
- `cargo clean` wipes `target\`, so re-copy after one.

## Symbols — required for `module!func` name resolution

Symbol *names* fail silently without all three of:

1. **`msdia140.dll` bundled next to the binary** (the copy above). Without it `dbghelp`
   can't parse any PDB (`dia error 0x8007007e`) and falls back to *export* symbols, so
   `module!name` lookups fail even with the right PDB cached. `symsrv.dll` is needed to
   read a symbol-store cache.
2. **A symbol path:** `execute` →
   `.sympath srv*C:\ProgramData\Dbg\sym*https://msdl.microsoft.com/download/symbols`
3. **A `.reload /f` at a stopped position** (after a `go`/breakpoint, not off a bare
   `!tt`). Confirm with `execute` → `lm m <mod>`: `(pdb symbols)` means it worked,
   `(export symbols)` means it didn't.

Offline / no symbols? Navigation, memory reads, disassembly, and the data model still work
— query by address instead of by name.

## Elevation matrix

| Operation | Administrator? |
|-----------|----------------|
| Crash-dump analysis (`open_dump`) | No |
| TTD replay (`open_trace`) | No |
| Live user-mode (`launch` / `attach_process`) | No (unless the target requires it) |
| Live kernel (`attach_kernel_local` / `attach_kernel`) | **Yes** |
| TTD recording (`record_trace`) | **Yes** + `TTD.exe` on `PATH` |

`record_trace` captures the recorder's startup output to `<out_dir>\ttd_record.log` and
watches it briefly, so a fast failure (e.g. un-elevated → `0x80070005 Access is denied`)
is reported as an error rather than a false "recording started".
