# Examples

## Worked solve: `flareauthenticator/`

A full **TTD → Z3** solve of an obfuscated Qt crackme (Flare-On 12 #8), driven entirely through this
server. TTD reduces a per-keystroke rolling hash to a pure weighted sum; the recovered constants go to
an SMT solver for the flag. See [`flareauthenticator/README.md`](flareauthenticator/README.md), the
narrated walkthrough [`docs/flareauthenticator-ttd-walkthrough.md`](../docs/flareauthenticator-ttd-walkthrough.md),
and the recorded terminal session [`docs/flareauthenticator.cast`](../docs/flareauthenticator.cast).

## Example drivers

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
- **`ctrl_c_teardown.ps1`** — checks that a console Ctrl+C lets an engine worker release its
  target instead of killing it mid-session. Unlike the others this one is a *test*: it prints
  `PASS`/`FAIL` and exits 0/1 (2 if inconclusive), needs nothing but the checked-in sample dump,
  and runs the scenario in a console of its own because Ctrl+C reaches every process on a console —
  including, otherwise, your shell. `-Exe ..\target\debug\windbg-mcp.exe` to test a working-tree
  build.
- **`sweep_ioctls.ps1`** — driver IOCTL sweep, **host side** (see
  [`driver-ioctl.md`](../skills/windbg-debugging/driver-ioctl.md)). Attaches over KDNET,
  prints the driver's dispatch table (`driver_object`) and load base, and — given the
  rebased dispatch VA via `-Dispatch` — installs the `ioctl_trace` logging breakpoint and
  collects the IOCTL log during a `go` window. Needs a real `-Connection` and a benign test
  driver.
- **`send_ioctls_target.ps1`** — the **target-side** companion: run it on the target VM
  during the `go` window (once as a normal user, once elevated). It opens the device and
  fires each `-Codes` IOCTL via `DeviceIoControl`; comparing which codes reach the host log
  under each token is the per-token reachability answer.
- **`messagemanager/ctf_regression.ps1`** — builds and deploys a benign MessageManager pool
  fixture over WinRM, then runs the doubly gated live-KD smoke test through the real MCP stdio
  transport. It requires the challenge driver, a `PSCredential`, KDNET, and full `nt` symbols;
  see the [CTF regression runbook](../docs/smoke-test.md#messagemanager-ctf-regression).
