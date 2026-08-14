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

A package-manager install lands outside the plugin layout in the same way:

> **Already installed with [Scoop](https://scoop.sh)** from the community
> [`gitfool/scoop-dungeon`](https://github.com/gitfool/scoop-dungeon) bucket? That also skips
> Options A/B — point the client at
> `%USERPROFILE%\scoop\apps\windbg-mcp\current\windbg-mcp.exe` rather than the plugin path. Its
> `post_install` does the **engine bundling below** — the DLLs plus `ttd\`, `winext\` and `winxp\`,
> copied from the `Microsoft.WinDbg` store package on the machine, when one is installed. Check the
> directory for `dbgeng.dll` before repeating any of it; if it is missing, WinDbg wasn't installed
> when Scoop was, and the copy below (or `scoop update --force windbg-mcp`) is still needed.
>
> **Never run `scoop install` on the user's behalf.** That bucket is community-maintained, outside
> this project's control, and a Scoop manifest is code: `post_install` is arbitrary PowerShell, run
> against whatever download URL and hash the manifest carries at that moment — and excavator
> rewrites both automatically on each new release, so what a reader once checked is not what a
> later install fetches. Options A/B are the paths this project can vouch for: a SHA-256 published
> with the release, and `gh attestation verify` tying the zip to the workflow that built it. If the
> user wants Scoop, they ask for it and they run it.

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

## WinDbg engine + extensions — for `.run` replay, crash-dump `!analyze`, and the kernel driver tools

Drop the **WinDbg** store-package binaries next to `windbg-mcp.exe` (the `$dst` below — for a
registry/MCPB install that's the client's extraction directory, **not** `target\release`) for
three reasons:

- **TTD `.run` replay** — System32's `dbgeng.dll` **rejects** traces with `0x80070057`.
- **Crash-dump `!analyze`** — it lives in the `winext\` extensions, which System32 doesn't ship
  (so a `.dmp`-only user still needs the `winext\` copy below, even though dump *loading* itself
  works on System32's engine).
- **`driver_object`/`device_object`/`irp_stack`** — they run `!drvobj`/`!devobj`/`!irp` from
  `winxp\kdexts.dll`, which System32 doesn't ship either (so a live-kernel-only user needs the
  `winxp\` copy below, even though the attach itself works on the System32 engine).

`DebugCreate` binds to whichever `dbgeng.dll` the loader finds first, and the app directory is
searched before `System32`, so the copied engine wins. One-time, from the installed WinDbg store
package:

```pwsh
$wd  = (Get-AppxPackage Microsoft.WinDbg).InstallLocation + "\amd64"
# Set $dst to the folder that actually holds windbg-mcp.exe — pick the one for
# your install (do not leave it as the placeholder):
#   plugin / build-from-source layout      -> <plugin dir>\target\release
#   installed from the MCP registry / MCPB -> the client's extraction dir (the
#     extension's ${__dirname}, under the client's extensions folder)
$dst = "<folder that holds windbg-mcp.exe>"
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
2. **A symbol path:** use the **`set_symbol_path`** tool with
   `srv*C:\ProgramData\Dbg\sym*https://msdl.microsoft.com/download/symbols` and
   `append: true`. It goes through DbgEng's `Append/SetSymbolPath`, so it avoids
   `.sympath`'s habit of swallowing the rest of the command line. Naming the cache
   explicitly is *recommended*, not required — `.symfix` with no argument uses the `sym`
   subdirectory of the debugger's installation directory — but an explicit path is
   predictable and lets several binaries share one store.
3. **A `.reload /f <mod>` at a stopped position** (after a `go`/breakpoint, not off a bare
   `!tt`), module-qualified so it fetches the PDB you actually want rather than walking
   every loaded module. Under `!sym noisy` when it does not work, so the search is
   visible. Confirm with `execute` → `lm m <mod>`: `(pdb symbols)` means it worked,
   `(export symbols)` means it didn't.

### Check the engine before blaming the path

**This is the one that actually bit, and the path is the tempting explanation.** The same
`file not found` appears when the PDB *is* in the cache and the engine simply cannot read
it. `dbgeng.dll` exists in System32, so a binary with no DLLs beside it opens targets and
runs commands quite happily — it just has no `symsrv.dll` to read a symbol store and no
`msdia140.dll` to parse a PDB. Under `!sym noisy` you get:

```text
DBGHELP: ntkrnlmp.pdb - file not found
DBGHELP: nt - export symbols
```

with **no `SYMSRV:` line above it**, and an error summary blaming the store (`invalid UNC
store`, `pingme.txt` missing) when the store is fine and the PDB is sitting in it. Nothing
in that output points at the engine, which is why it is worth knowing.

`!lmi <mod>` separates the two, and is worth running before changing any path:

```text
Debug Data Dirs: Type  Size     VA  Pointer
             CODEVIEW    25, 54ea8,   54ea8 RSDS - GUID: {3E0BF93D-...-9CDCB8C7}
               Age: 1, Pdb: ntkrnlmp.pdb
    Symbol Type: EXPORT   - PDB not found
```

A **CODEVIEW line with a GUID** means the identity was read from the image and the lookup
still failed — engine or store, not the target. The store directory for that PDB is the GUID
with the age appended (`3E0BF93D…9CDCB8C71`), so you can check by hand whether it is already
cached. **No CODEVIEW line** is the other failure: the image headers could not be read, and
no symbol server can be queried without them.

Two more things that mislead here:

- `.reload /f <mod>` fetches one module's PDB; bare `.reload /f` walks every loaded module,
  which on a live kernel is a couple of hundred of them and correspondingly slow. Reach for
  the unqualified form only to rule the module name out as the variable.
- `x <mod>!<symbol>` prints **nothing at all** for an unresolved name — no error, no
  diagnostic. Its silence is not confirmation. `lm m <mod>` is the check that answers.

Symbols are never fetched from the target over the KD wire, so all of this is about the
**debugging host**, whatever the target is.

### Allocator tools need private `nt` or `ntdll` types

`pool_find_tag`, `pool_census`, `pool_chunk` and `pool_diagnostics` decode the kernel pool's
segment allocator internals (`_EX_POOL_HEAP_MANAGER_STATE`, the page-range descriptors, the VS and LFH
headers). Exports are not enough. Without full type information every pool query fails up
front with `missing allocator symbols (ExPoolState); run '.reload /f nt' and retry` — which
is a symbol problem on this host, not a statement about the target's pool.

Offline / no symbols? Navigation, memory reads, disassembly, and the data model still work
— query by address instead of by name.

The user-mode `heap_list`, `heap_allocations`, `heap_chunk`, `heap_census` and
`heap_diagnostics` tools have the same requirement for the exact loaded `ntdll` PDB. Use
`.reload /f ntdll.dll` for them, and `.reload /f nt` for `pool_*`; the error guidance is deliberately
module-specific. `heap_list` still lists classic NT heaps as unsupported once the PDB is loaded;
use `!heap` for those rather than treating them as missing Segment Heap coverage.

## Kernel connection profiles — configure once, keep the key out of the transcript

A KDNET connection string carries the target's debug key (`net:port=50000,key=<w.x.y.z>`), and a
key passed as a tool argument is in the MCP client's transcript from then on — copied through
messages, tool calls, context snapshots and compaction summaries. Configure the connection on
**this host** instead and `attach_kernel { "profile": "<name>" }` names it without the key ever
entering the request.

Either source works; the environment is checked first, then the file. **They differ in when a
change takes effect**, which decides which one to reach for:

**File** — `%USERPROFILE%\.windbg-mcp\profiles.json`, or wherever `WINDBG_MCP_PROFILES` points.
Re-read on **every attach**, so an edit works immediately, with nothing restarted. This is the one
to add a profile to mid-session:

```json
{
  "ctf-vm": "net:port=50000,key=1.2.3.4",
  "lab":    "net:port=50001,key=5.6.7.8"
}
```

**Environment**, in whatever launches the MCP server — the client's server definition, or the shell
the client itself was started from. The variable's suffix is the profile name, lowercased, so this
defines `ctf_vm` (and `ctf-vm` resolves to it too):

```pwsh
$env:WINDBG_MCP_PROFILE_CTF_VM = "net:port=50000,key=1.2.3.4"
```

The server reads its *own* environment, which was fixed when it started, so setting this in a shell
alongside a running server changes nothing until that server is restarted. Use it for a profile you
want configured permanently; use the file for one you want now.

This file holds keys: keep it out of every repository, and out of any directory that gets synced
or shared. Names are matched case-insensitively with `-`, `_` and `.` equivalent, and the sources
are re-read on every attach — adding a profile does not mean restarting the MCP client. Two
consequences of that matching worth knowing:

- `ctf-vm` and `ctf.vm` in the **same** source are one name. If they point at different targets,
  *neither* resolves until you rename or remove one — guessing would open a session on the wrong
  machine while reporting it as the right one. (Two spellings of the *same* connection are fine,
  and the environment overriding the file is the documented precedence, not a conflict.)
- An entry whose name is not a name (letters, digits, `-`, `_`, `.`) is skipped, and not quoted
  back in the error — the usual cause is an entry written the wrong way round, which would make
  the name the connection string.

Raw connection strings stay supported (`attach_kernel { "connection": "net:port=…,key=…" }`) for a
target no profile covers. Either way the session reports itself with the key masked —
`kernel target: profile "ctf-vm" (net:port=50000,key=<redacted>)` — so `session_status` can still
tell two kernel targets apart. `attach_kernel` with no arguments lists the profiles this host has.

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
