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

> **Installing from the [MCP registry](https://registry.modelcontextprotocol.io) or an
> [MCPB](https://github.com/anthropics/mcpb) bundle instead?** Add
> **`io.github.glslang/windbg-mcp`** and your client fetches + SHA-256-verifies the prebuilt
> `.mcpb` itself — skip Options A/B, which exist to populate the plugin's source layout. You
> still do the one-time **engine bundling below**, dropping those DLLs next to the
> *client-extracted* `windbg-mcp.exe` (its `${__dirname}`).

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

Optionally, with the [GitHub CLI](https://cli.github.com/), verify the zip's build provenance
(proves it was built by this repo's release workflow, not tampered with):

```pwsh
gh attestation verify $zip --repo glslang/windbg-mcp `
   --signer-workflow glslang/windbg-mcp/.github/workflows/release.yml
```

### Option B — build from source

```pwsh
# From the installed plugin / repo directory.
cargo build --release
```

[`win-kexp`](https://github.com/glslang/win-kexp) is fetched automatically as a git
dependency — no sibling checkout needed.

> **Developing from the repo? Disconnect the `windbg` MCP server before a release build.**
> While the server is connected it *runs* `target\release\windbg-mcp.exe`, so the file is
> locked and `cargo build --release` fails with `failed to remove file … windbg-mcp.exe:
> Access is denied (os error 5)`. End-to-end testing of a change can't happen until the
> rebuilt binary is in place, so:
>
> 1. Disconnect it — disable the `windbg` server (the `/mcp` menu) or the plugin for this session.
> 2. `cargo build --release` (or download a release), then `/reload-plugins` to reconnect.
>
> To iterate on logic without disconnecting, use the **dev profile** (writes `target\debug`,
> which is *not* locked): `cargo test` compiles everything and runs the unit tests, and
> `cargo clippy --all-targets` lints — neither touches the locked release binary.

Either way, run `/reload-plugins` afterwards so Claude Code connects the `windbg` MCP server.

## WinDbg engine + extensions — for `.run` replay and crash-dump `!analyze`

Drop the **WinDbg** store-package binaries next to `windbg-mcp.exe` (the `$dst` below — for a
registry/MCPB install that's the client's extraction directory, **not** `target\release`) for
two reasons:

- **TTD `.run` replay** — System32's `dbgeng.dll` **rejects** traces with `0x80070057`.
- **Crash-dump `!analyze`** — it lives in the `winext\` extensions, which System32 doesn't ship
  (so a `.dmp`-only user still needs the `winext\` copy below, even though dump *loading* itself
  works on System32's engine).

`DebugCreate` binds to whichever `dbgeng.dll` the loader finds first, and the app directory is
searched before `System32`, so the copied engine wins. One-time, from the installed WinDbg store
package:

```pwsh
$wd  = (Get-AppxPackage Microsoft.WinDbg).InstallLocation + "\amd64"
# $dst = the folder that actually holds windbg-mcp.exe:
#   plugin / build-from-source layout      -> <plugin dir>\target\release
#   installed from the MCP registry / MCPB -> the client's extraction dir (the
#     extension's ${__dirname}; e.g. under the client's extensions folder)
$dst = "<plugin dir>\target\release"
Copy-Item "$wd\dbgeng.dll","$wd\dbghelp.dll","$wd\dbgcore.dll","$wd\dbgmodel.dll",`
          "$wd\symsrv.dll","$wd\msdia140.dll" $dst -Force
Copy-Item "$wd\ttd"    "$dst\ttd"    -Recurse -Force   # TTDReplay*.dll, TtdExt.dll, TTDAnalyze.dll, ...
Copy-Item "$wd\winext" "$dst\winext" -Recurse -Force   # ext.dll (!analyze), kext.dll, … — for crash dumps
New-Item   "$dst\winxp" -ItemType Directory -Force | Out-Null
Copy-Item "$wd\winxp\kdexts.dll" "$dst\winxp" -Force   # !drvobj/!devobj/!irp — for the driver-IOCTL tools (kernel)
```

- The `ttd\` subdir provides the `@$cursession.TTD` / `@$curprocess.TTD` data model and the
  `!tt` time-travel commands.
- The `winext\` subdir provides `ext.dll` (which exports `!analyze`) and the other `!`-extensions.
  Required for crash-dump triage — without it `!analyze` returns *"No export analyze found"*.
- `winxp\kdexts.dll` provides the kernel-object extensions `!drvobj`/`!devobj`/`!irp` used by the
  `driver_object`/`device_object`/`irp_stack` tools. `attach_kernel` / `attach_kernel_local`
  `.load kdexts` automatically; without the file those tools return *"No export drvobj found"*.
  (Note it lives in `winxp\`, not `winext\`, and the engine already searches a `WINXP` subdir.)
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
