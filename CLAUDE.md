# CLAUDE.md

Guidance for Claude Code working in this repo. See `README.md` for architecture and the full tool
surface; this file covers the non-obvious operational workflows.

## What this is

`windbg-mcp` is a Rust MCP server (stdio, `rmcp`) exposing **WinDbg/DbgEng** for live user-mode,
kernel, crash-dump, and Time Travel Debugging (TTD) work. The low-level DbgEng bindings come from
the sibling crate [`win-kexp`](https://github.com/glslang/win-kexp) (a **path/git dependency we grow
ourselves** — do not add third-party DbgEng crates). Key source: `src/engine.rs` (single dedicated
engine thread), `src/server.rs` (the MCP tools), `src/ttd.rs`, `src/main.rs`.

## Updating the running windbg MCP after code changes

The MCP server registered for this repo runs `target\release\windbg-mcp.exe`. **While that server is
connected in a Claude Code session, it holds an open handle to the exe**, so a plain
`cargo build --release` fails at the final replace step with `Access is denied (os error 5)` — but
only *after* compilation has already succeeded.

To rebuild and load the new code without stopping the session:

1. **Rename the locked exe out of the way** (Windows allows renaming a running image, just not
   deleting/overwriting it):
   ```
   mv target/release/windbg-mcp.exe target/release/windbg-mcp.exe.stale
   ```
2. **Build** into the now-free path:
   ```
   cargo build --release
   ```
   This builds the `win-kexp` revision pinned in `Cargo.lock` and writes a fresh
   `target\release\windbg-mcp.exe`. If this `windbg-mcp` change depends on a newly pushed
   `win-kexp` commit, run `cargo update -p win-kexp` first and commit the resulting `Cargo.lock`
   bump with the `windbg-mcp` change. The running server keeps executing the *old* code from the
   renamed `.stale` file until its connection is recycled.
3. **Load the new binary** by reconnecting the server: `/mcp` → reconnect `windbg` (or restart
   Claude Code). Only after this reconnect do the windbg tools run the new code.
4. Once reconnected (the old process is gone), delete `target/release/windbg-mcp.exe.stale`. Do
   **not** delete it while the old process is still alive — it demand-pages code from that file.

## Changing win-kexp (the DbgEng bindings)

`win-kexp` is a **git dependency pinned to `main`**, not a path dependency — a `windbg-mcp` build
pulls it from GitHub, so **local edits to `C:\workspace\win-kexp` are invisible to a `windbg-mcp`
build until they are pushed to `win-kexp` `main`** (then bump the pin / rebuild). Add new DbgEng
primitives as typed `win-kexp` methods (returning `Result<_, DbgEngError>`, not `panic!`/`.expect`),
not via the `execute` text hatch.

After pushing a required `win-kexp` change to `main`, run `cargo update -p win-kexp` in this repo and
commit the resulting `Cargo.lock` change before building or opening the dependent `windbg-mcp` PR.

To compile-check a `windbg-mcp` change that depends on un-pushed `win-kexp` edits, add a temporary
patch and `cargo check`, then revert it (do **not** commit it — it breaks CI/other contributors):

```toml
[patch.'https://github.com/glslang/win-kexp']
win-kexp = { path = "../win-kexp" }
```
`git checkout -- Cargo.toml Cargo.lock` afterwards.

## Local verification (no session restart needed)

For a compile/behavior check without touching the locked release exe, use the **dev profile**
(writes `target/debug`, never locked): `cargo test` and `cargo clippy --all-targets`. The release
build differs only in optimization and is exercised by CI on a fresh runner.

`cargo test` includes `tests/mcp_smoke.rs`, which spawns the **dev** binary (via
`CARGO_BIN_EXE_windbg-mcp`) and drives it over stdio — so it is also clear of the release lock.
After a dependency bump (`rmcp`, `schemars`, `tokio`, `cargo update -p win-kexp`) or an MCP spec
revision, run it and follow [`docs/smoke-test.md`](./docs/smoke-test.md). To include the tier that
opens the sample dump through DbgEng, set the gate first (PowerShell, not `VAR=1 cmd`):

```pwsh
$env:WINDBG_MCP_SMOKE_DUMP = "1"; cargo test --test mcp_smoke
```

## Live kernel + driver IOCTL gotchas (learned driving HEVD over KDNET)

**KDNET attach is a blocking wait, by design.** A live kernel needs `WaitForEvent(INFINITE)` (a finite
timeout returns `E_NOTIMPL` and never drives the link). So if the target isn't reachable, the
`attach_kernel` MCP call reports a *timeout* while the engine thread stays **parked** in the wait —
it self-heals and completes the attach the moment the target actually connects. Consequences:
- When an attach "hangs", **diagnose out-of-band** (PowerShell), never by firing more windbg tools —
  they queue behind the parked engine thread and also time out. Check the debugger is listening
  (`Get-NetUDPEndpoint -LocalPort 50000` → owned by `windbg-mcp.exe`) and whether any VM is running.
- The **target must dial this host**: on the target, `bcdedit /dbgsettings net hostip:<debugger-ip>
  port:50000 key:<key>` — **colons, not `=`**. `hostip` must be the debugger host's current IP.
  Symbols are **not** pulled over the KD wire (see below).
- After a target reboot, the settling KD link shows repeated break-ins in **`kdnic.sys`** (the KD NIC
  transport: `nt!DbgBreakPointWithStatus` ← `kdnic!TXTransmitQueuedSends`). These are not real stops —
  `go` through them until boot proceeds.

**Walking a service-loaded driver's IOCTLs live.** `sxe ld:<drv>.sys` breaks on module load, which is
**before DriverEntry runs** — so the driver object's `MajorFunction` table is *not* populated yet
(`driver_object` shows defaults / "is not a driver object"). To let DriverEntry run and populate it:
1. Compute the PE entry point from the header: `? <base> + dwo(<base> + dwo(<base>+0x3c) + 0x28)`.
2. `bp` it, `go`. At entry, `@rcx` = `DriverObject`, `poi(@rsp)` = return addr (into
   `nt!PnpCallDriverEntry`). `bp` that return, `go` — now the table is populated.
3. `MajorFunction[0x0e]` (IRP_MJ_DEVICE_CONTROL, the IOCTL dispatch) is at **`DriverObject+0xe0`**.
   In the dispatch, the `IoControlCode` is `IO_STACK_LOCATION+0x18`; the current stack location is
   `IRP+0xB8`. `uf` the dispatch to read the (usually binary-search) IOCTL switch, `decode_ioctl`
   each code, and read each case's `DbgPrintEx` string (`da`) for the human name.

**Symbols must be on the debugger host.** PDBs are never fetched from the target over KD. Find the
exact PDB identity the engine wants with `!sym noisy; .reload /f <mod>` (it prints `<pdb>\<GUID>\...`),
then get that PDB onto this host. **Gotcha: `.sympath` / `.sympath+` swallow the *rest of the command
line* — they ignore `;`, so anything chained after them (`; .reload ...`) is parsed as path text.**
Issue `.sympath` alone, or use the **`set_symbol_path`** tool (goes through the DbgEng
`AppendSymbolPath`/`SetSymbolPath` API, immune to the quirk; appends + reloads). When a driver's
`module!Symbol` names don't resolve, **ask the user for the PDB folder** and apply it with that tool.

## Plugin vs. dev build

This project is also installed as a user-scope Claude Code plugin (`windbg-mcp@windbg-mcp`), which is
a snapshot of the last *published* release and does **not** track working-tree edits. In this repo
the plugin is **disabled locally** (`.claude/settings.local.json`) so the dev build above is what
runs. Keep machine-specific server wiring (absolute paths) out of version control.
