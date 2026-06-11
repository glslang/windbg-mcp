# Setup: build, engine bundling, symbols, elevation

Most `windbg` failures are environment problems, not debugging mistakes. Work through the
section for the workflow you're about to run before blaming the target.

## Platform

- **Windows x64 only.** Host bitness must match the target.
- `dbgeng.dll` / `dbghelp.dll` ship in `System32` on modern Windows 11 (verified on
  `10.0.26100`). That is enough for live user-mode/kernel debugging and crash-dump
  analysis — **but not for TTD `.run` replay** (see below).

## Get the server binary

The plugin ships the source, not a binary. Put `windbg-mcp.exe` in place so the path in
`plugin.json` (`${CLAUDE_PLUGIN_ROOT}/target/release/windbg-mcp.exe`) resolves — either
option below lands it there.

### Option A — download a prebuilt release (no Rust required)

Each `vX.Y.Z` tag publishes a Windows x64 build on the
[releases page](https://github.com/glslang/windbg-mcp/releases). From the installed
plugin / repo directory:

```pwsh
$dst = "target\release"
New-Item $dst -ItemType Directory -Force | Out-Null
$rel   = Invoke-RestMethod https://api.github.com/repos/glslang/windbg-mcp/releases/latest
$asset = $rel.assets | Where-Object name -Like 'windbg-mcp-*-windows-x64.zip'
$zip   = Join-Path $env:TEMP $asset.name
Invoke-WebRequest $asset.browser_download_url -OutFile $zip
$sum = ((Invoke-RestMethod ($rel.assets | Where-Object name -EQ 'SHA256SUMS.txt').browser_download_url) -split '\s+')[0]
if ((Get-FileHash $zip -Algorithm SHA256).Hash.ToLower() -ne $sum) { throw "SHA256 mismatch for $($asset.name)" }
Unblock-File $zip   # clear Mark-of-the-Web so the extracted exe isn't blocked
Expand-Archive $zip $dst -Force
```

### Option B — build from source

```pwsh
# From the installed plugin / repo directory.
cargo build --release
```

[`win-kexp`](https://github.com/glslang/win-kexp) is fetched automatically as a git
dependency — no sibling checkout needed.

Either way, run `/reload-plugins` afterwards so Claude Code connects the `windbg` MCP server.

## WinDbg engine + extensions — for `.run` replay and crash-dump `!analyze`

Drop the **WinDbg** store-package binaries next to the built binary for two reasons:

- **TTD `.run` replay** — System32's `dbgeng.dll` **rejects** traces with `0x80070057`.
- **Crash-dump `!analyze`** — it lives in the `winext\` extensions, which System32 doesn't ship
  (so a `.dmp`-only user still needs the `winext\` copy below, even though dump *loading* itself
  works on System32's engine).

`DebugCreate` binds to whichever `dbgeng.dll` the loader finds first, and the app directory is
searched before `System32`, so the copied engine wins. One-time, from the installed WinDbg store
package:

```pwsh
$wd  = (Get-AppxPackage Microsoft.WinDbg).InstallLocation + "\amd64"
$dst = "<plugin dir>\target\release"
Copy-Item "$wd\dbgeng.dll","$wd\dbghelp.dll","$wd\dbgcore.dll","$wd\dbgmodel.dll",`
          "$wd\symsrv.dll","$wd\msdia140.dll" $dst -Force
Copy-Item "$wd\ttd"    "$dst\ttd"    -Recurse -Force   # TTDReplay*.dll, TtdExt.dll, TTDAnalyze.dll, ...
Copy-Item "$wd\winext" "$dst\winext" -Recurse -Force   # ext.dll (!analyze), kext.dll, … — for crash dumps
```

- The `ttd\` subdir provides the `@$cursession.TTD` / `@$curprocess.TTD` data model and the
  `!tt` time-travel commands.
- The `winext\` subdir provides `ext.dll` (which exports `!analyze`) and the other `!`-extensions.
  Required for crash-dump triage — without it `!analyze` returns *"No export analyze found"*.
- `cargo clean` (when building from source) wipes `target\`, so re-copy after one.

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
