# Smoke test

`tests/mcp_smoke.rs` drives the **built binary** over stdio with hand-written JSON-RPC. It exists
for the two moments the in-process unit tests in `src/server.rs` cannot cover: **a dependency
moved**, and **the MCP spec revved**. Both change the bytes on the wire while the Rust API this
crate compiles against stays identical — so the unit tests keep passing and clients break.

## Running it

```pwsh
cargo test --test mcp_smoke              # protocol tier (default)
$env:WINDBG_MCP_SMOKE_DUMP = "1"; cargo test --test mcp_smoke   # + the debugger tier
```

It builds and runs against `target/debug`, so it never touches the `target/release` exe a
connected MCP client holds a lock on (see [`CLAUDE.md`](../CLAUDE.md)). Whole suite is ~1s.

### Tiers

| Tier | Gate | Needs | Catches |
| --- | --- | --- | --- |
| **Protocol** | always | nothing — no debugger, no target, no network | transport, revision negotiation, tool-surface drift |
| **Debugger** | `WINDBG_MCP_SMOKE_DUMP=1` | `dbgeng.dll`, the checked-in sample dump | `win-kexp` / DbgEng regressions |
| **Live** | manual | KDNET target, TTD engine, elevation | see [Manual checklist](#manual-checklist) |

The protocol tier rides `cargo test`, so CI already runs it. The debugger tier is opt-in: it
reaches real DbgEng and is available in CI on demand via the **Smoke test (debugger tier)** job
(Actions → CI → *Run workflow*). The live tier is not automated — no runner has a kernel target.

## What it asserts, and why each one is a dependency tripwire

**Transport.** Every line the server writes to stdout parses as JSON-RPC, and the startup log
appears on **stderr**. A dependency that prints a banner or a warning to stdout desynchronizes
every client, and the client-side symptom is an unreadable parse error. Also: closing stdin exits
the process within 20s (otherwise each client disconnect leaks a process and a DbgEng session),
and a malformed input line does not kill the session.

**Protocol revisions.** Every revision the README promises — `2026-07-28`, `2025-11-25`,
`2025-06-18`, `2025-03-26`, `2024-11-05` — is offered a handshake, served *that* revision, and can
reach `tools/list`. An unknown revision negotiates down to `2025-11-25`. `server/discover` opens a
session with no handshake at all, and — the rule that is easy to get wrong — in that stateless mode
**every** request must carry the `_meta` protocol keys, not just the opener; a request without them
is refused with `-32602`.

**Capability honesty.** `tools` is advertised; `resources`, `prompts`, `completions`, `logging` and
`extensions` are not, because none are implemented. `tasks/get` answers `method_not_found`
(deliberate — [`FOLLOWUPS.md`](../FOLLOWUPS.md) item 8). If an SDK bump starts advertising something
on this server's behalf, this test is where you find out, and the choice is implement it or
suppress it — not ship an advertisement clients will call into a dead end.

**Tool surface golden.** `tests/golden/tools_list.json` records the *structural* `tools/list`
surface as it appears on the wire: JSON Schema dialect, `$defs` usage, tool count, and per tool its
name, title, four behaviour hints, required arguments, and each parameter's type/format/enum. It
deliberately excludes descriptions, so prose edits do not churn it while a `schemars` dialect
switch, an `rmcp` annotation-casing change, or an accidental tool rename all land as a readable
line diff.

Re-record after an *intended* change, and read the diff before committing:

```pwsh
$env:UPDATE_GOLDEN = "1"; cargo test --test mcp_smoke tools_list_matches
```

**Schema resolvability.** Every tool's input schema is an object schema whose `$ref`s all resolve
inside the same document. External or dangling refs break strict client-side validators, and a
codegen dependency can introduce them with no change here.

**Debugger tier.** Opens the checked-in kernel crash dump, confirms it mints a `session_id` that
`session_status` reports, reads it through `modules` / `registers` / `backtrace`, then checks the
session-handle contract on the wire (a stale handle is refused; the handle stops working once
`end_session` runs). It also pins the `isError` contract against a real engine: `threads` is `~`,
which DbgEng implements only in user mode, so on a kernel dump it must come back as a **tool error
carrying the engine's message** — not a JSON-RPC error, and not a dead worker thread. Read-only
throughout, and it needs no symbols, so it runs offline.

## When to run it

### A dependency moved

`rmcp`, `schemars`, `tokio`, or a `win-kexp` pin bump (`cargo update -p win-kexp`). Note Dependabot
only watches GitHub Actions here, so cargo bumps arrive by hand.

1. `cargo test` — the protocol tier plus the existing unit tests.
2. For a `win-kexp` bump, add the debugger tier — the only automated thing that touches DbgEng:

   ```pwsh
   $env:WINDBG_MCP_SMOKE_DUMP = "1"; cargo test --test mcp_smoke
   ```
3. If the golden diff fires, read it before re-recording. A changed dialect or nullable encoding is
   a **client-visible** change and belongs in `CHANGELOG.md`, not in a silent re-record.

### The MCP spec revved

1. Add the new revision to the front of `SUPPORTED_REVISIONS` in `tests/mcp_smoke.rs` and run it.
   A failure means the SDK does not speak it yet — that is the answer to "do we need an `rmcp`
   bump", and until then the README's revision list must not claim it.
2. Check `capabilities_advertise_only_what_is_implemented`. New spec revisions add capabilities and
   extensions; this test fails the moment the SDK advertises one this server does not implement.
3. Re-read the stateless assertions in `discover_opens_a_session_without_initialize` against the new
   revision's `_meta` requirements — that is where per-request metadata rules land.
4. Update the revision list in `README.md` and this file's list above to match what actually passes.

## Manual checklist

Not automated: no runner has a kernel target, a TTD-capable engine, or elevation. Run these by hand
before a release, or when a change touches the relevant path. Drivers live in
[`examples/`](../examples/README.md) and need `cargo build --release` first.

- **Live user-mode** — `examples/test_usermode.ps1`: launch `cmd.exe` under the debugger, break in,
  read registers/modules, set a breakpoint.
- **Failure paths** — `examples/verify_fixes.ps1`: execution control with no debuggee returns a
  clean "No active debuggee" error, and a failed kernel attach is a clean error rather than a panic.
- **Live kernel (KDNET)** — `examples/drive_kernel_test.ps1 -Connection "net:port=<n>,key=<w.x.y.z>"`:
  attach, `bp nt!NtCreateFile`, `go` to it, resume, detach. See the KDNET gotchas in `CLAUDE.md`
  before diagnosing a hang.
- **TTD replay** — needs the WinDbg store engine next to the binary (System32's engine rejects
  `.run` traces with `0x80070057`). Open a trace, then exercise `ttd_calls` / `ttd_memory` /
  `ttd_events` and reverse execution. The worked example is
  [`docs/flareauthenticator-ttd-walkthrough.md`](flareauthenticator-ttd-walkthrough.md).
- **TTD recording** — `record_trace` needs elevation and `TTD.exe` on `PATH`.
- **Driver IOCTL sweep** — `examples/sweep_ioctls.ps1` plus the target-side
  `examples/send_ioctls_target.ps1`; needs a benign test driver on a KDNET target.
