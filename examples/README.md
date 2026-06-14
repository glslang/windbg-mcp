# Example drivers

Throwaway stdio JSON-RPC drivers written while developing the live-kernel support,
kept for re-use in future debugging. They are plain PowerShell (`.ps1`) — Cargo does
not build them.

Each script spawns `..\target\release\windbg-mcp.exe` and drives it over stdio (MCP),
so build the server first: `cargo build --release`. For symbol resolution, set
`_NT_SYMBOL_PATH` (e.g. `srv*C:\ProgramData\Dbg\sym*https://msdl.microsoft.com/download/symbols`).

- **`drive_kernel_test.ps1`** — attach to a live KDNET kernel, break in, set
  `bp nt!NtCreateFile`, `go` to it, then resume and detach. Pass your target's real
  connection string: `-Connection "net:port=<n>,key=<w.x.y.z>"`.
- **`test_usermode.ps1`** — launch `cmd.exe` under the debugger and exercise the
  user-mode break-in (registers, modules, breakpoint).
- **`verify_fixes.ps1`** — regression checks: `go`/step with no debuggee returns a
  clean "No active debuggee" error (no process crash), and a failed kernel attach is a
  clean error (no panic). The kernel-attach check needs a real KDNET key filled in.
