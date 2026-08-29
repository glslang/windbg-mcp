# Install and engine setup

## Requirements

- Windows x64 (host bitness must match the target).
- `dbgeng.dll` / `dbghelp.dll` — present in `System32` on modern Windows 11 (verified with
  `10.0.26100`). This is enough for live user-mode/kernel debugging and crash-dump analysis.
- **For crash-dump `!analyze`** (and any other `!`-extension command), the engine needs the
  WinDbg `winext\` extensions bundled next to the binary — System32's engine ships none, so
  `!analyze` would return *"No export analyze found"*. See *Bundling the WinDbg engine* below.
- **For the kernel driver tools** (`driver_object` / `device_object` / `irp_stack`), the engine
  needs `winxp\kdexts.dll` bundled next to the binary — it exports `!drvobj`/`!devobj`/`!irp`, which
  System32 doesn't ship, so without it those three return *"No export drvobj found"* even though the
  kernel attach itself succeeded. See *Bundling the WinDbg engine* below.
- **For Time Travel Debugging (`.run`) replay**, the System32 engine is *not* enough — it rejects
  `.run` traces (`0x80070057`). You need the **WinDbg engine** (which bundles the TTD replay
  components) loaded next to the binary — see *Bundling the WinDbg engine* below.
- `TTD.exe` (the standalone Time Travel Debugging recorder) for `record_trace` — it sits at
  `ttd\TTD.exe` inside the WinDbg payload, so the engine copy below already brings it; put it on
  `PATH`.
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

`dbgscope` is fetched automatically as a git dependency from [`glslang/dbgscope`](https://github.com/glslang/dbgscope) — no sibling checkout needed.

`cargo test` covers the unit tests plus an end-to-end smoke test that drives the built binary over
stdio. Run it after a dependency bump or an MCP spec revision — see
[`smoke-test.md`](smoke-test.md). It also budgets what the tool surface and each result
cost the model driving them, which a schema change can move without breaking anything —
[`token-budget.md`](token-budget.md).

### Install with Scoop

A community-maintained [Scoop](https://scoop.sh) manifest lives in
[`gitfool/scoop-dungeon`](https://github.com/gitfool/scoop-dungeon)
([#109](https://github.com/glslang/windbg-mcp/issues/109)), which turns the download — and every
later update — into one command:

```pwsh
scoop bucket add dungeon https://github.com/gitfool/scoop-dungeon
scoop install windbg-mcp
scoop update windbg-mcp    # later; the manifest's checkver/autoupdate tracks releases here
```

It unpacks the release zip and — when the `Microsoft.WinDbg` store package is installed on your
machine — its `post_install` copies that package's engine DLLs and its `ttd\`, `winext\` and
`winxp\` subdirectories next to the binary: the whole
[*Bundling the WinDbg engine*](#bundling-the-windbg-engine) step below, done for you on install and
on every update. That copy is local, from a WinDbg you already installed; neither the release zip
nor the bucket redistributes Microsoft's engine. Without that package you get the in-box `System32`
engine: live and crash-dump debugging work, TTD `.run` replay, `!analyze` and the kernel driver
tools don't. The copy happens at install time, so if you add WinDbg afterwards, re-run
`post_install` with `scoop update --force windbg-mcp` (`scoop reset` won't — it only re-links) or
copy the files by hand as below, with `$dst` set to `…\scoop\apps\windbg-mcp\current`.

Point your MCP client at the `current` junction, so an update needs no config change:

```jsonc
{
  "mcpServers": {
    "windbg": { "command": "C:\\Users\\<you>\\scoop\\apps\\windbg-mcp\\current\\windbg-mcp.exe" }
  }
}
```

A connected client holds that binary open (and each engine worker re-executes the same image), so
disconnect the `windbg` server — `/mcp` in Claude Code — before `scoop update`, then reconnect to
actually run the new build.

**The bucket is community-maintained — not by this repo, and not audited by it.** A Scoop manifest
is code, not just a URL: `post_install` is arbitrary PowerShell, run against whatever download URL
and hash the manifest carries at the time, and autoupdate rewrites both on each new release. So
installing from it is a trust decision about that bucket, taken on your own judgement.

Scoop is not required either way. It installs the same
[release asset](https://github.com/glslang/windbg-mcp/releases) described above, which you can
download directly, check against the published `SHA256SUMS.txt`, and verify with
`gh attestation verify` — see [*Releasing*](./releasing.md) — none of which a third-party manifest can
promise on this project's behalf.

## Bundling the WinDbg engine

Basic live and crash-dump debugging works on the `dbgeng.dll` already in `System32`. These do not,
and each needs files that engine does not ship:

| Wanted | Needs |
| --- | --- |
| TTD `.run` replay | `ttd\` — System32's engine rejects traces with `0x80070057` |
| Crash-dump `!analyze` | `winext\` for the extension, `triage\` for its module attribution |
| `driver_object` / `device_object` / `irp_stack` | `winxp\kdexts.dll` |
| `module!name` symbols anywhere | `msdia140.dll` + `symsrv.dll`, plus a symbol path |
| SOS on a 32-bit .NET target | an `x86\` subdirectory holding a 32-bit engine **and** `x86\windbg-mcp.exe` — an extension loads into the debugger's own process, so only a 32-bit host can load a 32-bit `sos.dll` |

The fix is a one-time file copy: `DebugCreate` binds to whichever `dbgeng.dll` the loader finds
first and the app directory is searched before `System32`, so a WinDbg engine copied next to
`windbg-mcp.exe` wins. Note the kernel row — a live-kernel-only user needs this too, even though
the attach itself works on the System32 engine. The last row is that same loader rule rather than an
exception to it: the 32-bit engine goes *inside* `x86\` because it is the 32-bit worker sitting
there that has to find it, and dropping it beside the 64-bit one instead breaks both.

**The copy list, what each file buys, and the three sources it can come from — an installed store
package, the same package's `.msixbundle` unpacked without installing it, or the Windows SDK
Debugging Tools, which ship everything except `msdia140.dll` and `ttd\` — are in the skill's
[`setup.md`](../skills/windbg-debugging/setup.md).**
It is one document rather than two so the list cannot drift; it is also where symbols, elevation,
kernel connection profiles and the differences an ARM64 host brings are written down.

Most of these fail *quietly* rather than loudly — a missing `triage\` turns `!analyze` into
`ANALYSIS_INCONCLUSIVE`, a missing `msdia140.dll` silently downgrades symbols to exports — so it is
worth doing deliberately rather than discovering later.
