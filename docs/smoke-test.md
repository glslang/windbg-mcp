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
| **Bounded command** | `--ignored` | `dbgeng.dll`, the sample dump, ~1 minute | the watchdog wiring, which now spans two processes |
| **Live kernel** | `--ignored` + `WINDBG_MCP_SMOKE_KERNEL` | a KDNET target you can freeze | that a kernel attach *lands*, coexists, and is let go — by `end_session` and by a disconnect |
| **Live (other)** | manual | TTD engine, elevation, a test driver | see [Manual checklist](#manual-checklist) |

The protocol tier rides `cargo test`, so CI already runs it. The debugger tier is opt-in
*locally* but runs on every push and PR in CI, as the **Smoke test (debugger tier)** job — it is
the only automated check of the properties process-per-session exists for, and it needs no symbols
and no network. The bounded-command and live-kernel tiers are `#[ignore]`d — one is measured in
minutes, the other touches another machine; see below. Neither is automated, and the rest of the
live checklist is not either: no runner has a kernel target, a TTD engine, or elevation.

## What it asserts, and why each one is a dependency tripwire

**Transport.** Every line the server writes to stdout parses as JSON-RPC, and the startup log
appears on **stderr**. A dependency that prints a banner or a warning to stdout desynchronizes
every client, and the client-side symptom is an unreadable parse error. Also: closing stdin exits
the process within 20s (otherwise each client disconnect leaks a process and a DbgEng session),
and a malformed input line does not kill the session. Under process-per-session that last one has
teeth: a disconnect must also take every **engine worker** process with it, which the debugger tier
checks by pid.

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
carrying the engine's message** — not a JSON-RPC error, and not a dead session. Read-only
throughout, and it needs no symbols, so it runs offline.

It also covers process-per-session, which cannot be checked any other way — the claims are about
processes, so they need real ones:

- *Two sessions coexist.* Two dumps open at once, and the first handle still works after the second
  open landed. Under the single-engine design this was impossible by construction.
- *A kernel attach that never connects costs one session.* An `attach_kernel` at a dead port parks
  exactly as a guest that is not in debug mode would; the test then opens a dump **while it is
  parked** (the regression test for [#61](https://github.com/glslang/windbg-mcp/issues/61)) and
  reclaims the parked session with `end_session`, checking by pid that the worker process is gone.
  It skips itself if the attach fails outright instead of parking (a busy UDP port), because there
  is nothing to assert about a park that did not happen.
- *No worker outlives the connection.* Reads the engine pid out of `session_status`, disconnects,
  and checks the process is gone — otherwise every disconnect leaks a debugger process, and for a
  launch or an attach, a debuggee with it.

This tier is also the only end-to-end check of the **protocol channel** — the inherited pipe pair a
worker speaks on ([`proto.rs`](../src/proto.rs)). Handles are passed on the worker's command line
and inherited across the spawn, so a mistake there is not a compile error: the worker exits without
a usable channel, or comes up and is never heard from, and either way every test here that opens a
target fails on the open. Run it after touching `engine::spawn_worker` or `worker::run`.

## When to run it

### A dependency moved

`rmcp`, `schemars`, `tokio`, or a `win-kexp` pin bump (`cargo update -p win-kexp`). Note Dependabot
only watches GitHub Actions here, so cargo bumps arrive by hand.

1. `cargo test` — the protocol tier plus the existing unit tests.
2. For a `win-kexp` bump, add the debugger tier locally too — CI runs it on the PR, but a local
   run tells you sooner:

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

## The bounded-command tier

A third tier in the same file, `#[ignore]`d rather than env-gated because it deliberately runs
commands out to a watchdog deadline — minutes, not seconds. It needs the debugger tier's gate too.

```pwsh
$env:WINDBG_MCP_SMOKE_DUMP = "1"
cargo test --test mcp_smoke -- --ignored --nocapture --test-threads=1 bounded
```

`--test-threads=1` is required: each test spawns a server that opens the checked-in sample dump, and
these are timing tests that must not compete for the machine. Total runtime is a bit over a minute,
most of it deliberate waiting. They shrink the per-call budget with
`WINDBG_MCP_CALL_TIMEOUT_SECS`, so the arithmetic under test is the real one rather than a special
case.

- `a_bounded_runaway_command_aborts_and_leaves_its_session_usable` — a `.for` loop sized to run for
  hours is cut short by the watchdog, and the session executes the *next* command normally. This is
  the wedge that used to need a server restart. Proof of interruption is the loop counter left in
  `$t0`, not the clock and not the "interrupted after" note (which is appended whenever the watchdog
  *attempted* an interrupt, even one the engine ignored).
- `a_bounded_command_queued_behind_another_job_still_beats_its_caller` — the same, from behind a
  `.sleep` that occupies the session for half the call budget. This is the half win-kexp cannot
  cover, because the queue belongs to this crate: budgeting from the patience as sent, instead of
  from what remains after the queue wait, passes every other assertion and fails here. Two details
  the test documents because both silently void it — `.sleep` needs a `0n` prefix (the MASM
  evaluator's default base is hex, so a bare `30000` is 0x30000 ms), and the blocker needs a head
  start, since two tool calls in flight at once reach the session's queue in whichever order wins
  the race.
- `measure_what_the_bounded_path_costs_a_quick_command` — prints what arming the watchdog costs, as
  a distribution. It asserts nothing; it is the evidence behind which tools take the bounded path
  ([`DECISIONS.md`](../DECISIONS.md), 2026-08-02), namely that a bounded command is rounded up to a
  multiple of 200ms. Re-run it after a win-kexp watchdog change — if that cost goes away, so does
  the reason for the split.

These live with the wire tests rather than beside the arithmetic because the wiring they prove now
spans two processes: the supervisor sends the caller's remaining patience, the worker derives the
watchdog deadline from it, and only the shipped binary contains both halves.

Each half is unit-tested where it lives, and both ride `cargo test` everywhere — so a regression in
the common case fails in CI rather than waiting for a manual run. What is sent is
`remaining_patience_ms` in [`src/engine.rs`](../src/engine.rs); what is derived from it is
`watchdog_budget_ms` in [`src/worker.rs`](../src/worker.rs). The tests above are what checks that
the two agree across the pipe, which is the part neither module can prove alone.

## The live-kernel tier

The only tier that touches another machine, and the last thing to run. It needs a KDNET target you
are willing to freeze for the duration, booted with debugging enabled and dialling *this* host —
see the KDNET gotchas in [`CLAUDE.md`](../CLAUDE.md) before diagnosing a failure.

```pwsh
$env:WINDBG_MCP_SMOKE_KERNEL = "net:port=50000,key=<w.x.y.z>"
cargo test --test mcp_smoke -- --ignored --nocapture --test-threads=1 live_kernel
```

`--test-threads=1` is required, not tidiness: the filter matches **three** tests, and the KD
transport is single-owner. Run them in parallel and the later attaches fail, which can leave the
target halted.

The connection string is the one from `bcdedit /dbgsettings` on the target (or the `kd -k` command
you would otherwise use). It is **never** guessable, so the tier is gated on it rather than on a
boolean — and gated on `#[ignore]` as well, so a variable left set from an earlier session cannot
freeze a VM during an ordinary `cargo test`.

Everything else about kernel attaches is proved against a *dead* port, which is the failure #61 was
about. This is the other half — an attach that lands:

- **It still lands through a worker process.** The `Committed`/`Opened` milestones cross the pipe
  and leave the session reporting *open*, not stuck mid-attach.
- **The KD transport endpoint belongs to the worker**, checked against `netstat -ano`. That is the
  premise of process-per-session: a thread-based design leaves that endpoint claimed for the life
  of the server, and every retry claims another. If this assertion ever fails, a parked session is
  no longer reclaimable and the fix is undone.
- **A second session works alongside it** — a dump opened and used while the kernel attach is held,
  with the kernel session unaffected. Impossible by construction before.
- **`end_session` detaches gracefully rather than killing the worker.** This one has teeth: DbgEng
  leaves a detached-but-halted kernel *frozen*, so win-kexp resumes and actively detaches. A run
  that took the kill path instead would leave the guest halted with a wedged KD stub, needing a
  reboot. For the same reason the test body runs under `catch_unwind` — a failed assertion must
  still detach, or a test failure costs you the VM.
- **A disconnect releases a live kernel session rather than killing its worker.** Same hazard by
  the path nobody watches: closing the connection is an ordinary event, and whatever sessions are
  open at the time are whatever happened to be open. Checked against the **target's own uptime**
  read either side of the disconnect — a halted kernel takes no clock interrupt, so its uptime
  stands still while a released one keeps counting. Re-attaching alone proves nothing here: a
  frozen target still answers its KD stub.
- **A pool walk is bounded and gives the session back.** Needs **full `nt` symbols on this host**,
  which is a real precondition rather than a formality: the walker decodes segment-heap internals
  (`_EX_POOL_HEAP_MANAGER_STATE`, the page-range descriptors, the VS and LFH headers) and none of
  that is in the export table, so without them every pool query fails before reading a byte.
  Symbols are never fetched over the KD wire. The test runs `.symfix+` and `.reload /f nt` itself
  under `!sym noisy` and prints `!lmi nt`, `lm m nt` and `x nt!ExPoolState` when it cannot get
  them. Two traps live here. The symbol *cache* belongs to the debugger binary — a bare `srv*`
  expands to `cache*;SRV*<msdl>`, and that cache sits beside the exe — so the dev build the harness
  spawns does not inherit what a release build downloaded; the tier names one shared store to avoid
  that. And a symbol server can only be queried by PDB **GUID**, read from the image's debug
  directory: if that cannot be read, `!sym noisy` shows `ntkrnlmp.pdb - file not found` with no
  `SYMSRV:` line above it, which is a lookup that never happened rather than a download that
  failed. Where you already have a symbol path that works for the target, set
  `WINDBG_MCP_SMOKE_SYMBOLS` to it and the tier will use that instead. `pool_find_tag` with
  `refresh` then walks every
  committed pool page, which over KDNET is the query that used to run for minutes past its caller's
  timeout and leave everything behind it queued. Only this tier can show it: against the sample dump
  the same walk is local memory and finishes in well under a second, so the assertions would pass
  for the wrong reason. The claims are that the call **returns** inside its budget, that the very
  next call is served **immediately** rather than waiting out the rest of a walk, and that whatever
  came back **states its own coverage**. A truncated walk is a perfectly good outcome here, and the
  expected one on a busy kernel — so the test never asserts the walk was complete, only that it said
  which it was. Where the walk *does* complete it also checks the snapshot was cached rather than
  re-walked, and that `pool_census` and `pool_find_tag` agree about the heaviest tag in it. That
  last comparison additionally needs the census to expose a tag that renders unambiguously: pool
  tags are four raw bytes, unprintable ones render as `.` — and so does a literal `.` — so a tag
  containing one cannot be turned back into the bytes it came from. That is a fact about rendering
  and says nothing about the walk, so it skips the comparison with a note rather than failing.

The first run of this tier found a real bug — shutdown killed workers outright, so a disconnect
froze the target — which no dump-based tier could have found, because killing a worker that holds
a *dump* costs nothing. Both tests therefore collect their evidence and assert only after the
target has been released: an earlier draft asserted as it went, failed at the release check, and
left the target halted. A test for a bug that freezes a machine must not freeze the machine when
it fails.

## Manual checklist

Not automated: no runner has a kernel target, a TTD-capable engine, or elevation. Run these by hand
before a release, or when a change touches the relevant path. Drivers live in
[`examples/`](../examples/README.md) and need `cargo build --release` first.

- **Live user-mode** — `examples/test_usermode.ps1`: launch `cmd.exe` under the debugger, break in,
  read registers/modules, set a breakpoint.
- **Ctrl+C teardown** — `examples/ctrl_c_teardown.ps1`: a console Ctrl+C must leave a worker time
  to release its target, not kill it where it stands. Unattended, and it needs no target beyond the
  sample dump — but it is here rather than in `cargo test` because Ctrl+C cannot be aimed: the
  script runs the whole scenario in a console of its own, since an event sent to the test runner's
  console would take the runner with it. Self-checking (`PASS`/`FAIL`, exit 0/1/2); what it reads
  is whether the worker logged the release before exiting, because the worker process is gone
  either way. Run it when anything touches worker spawning or the EOF teardown.
- **Failure paths** — `examples/verify_fixes.ps1`: execution control with no debuggee returns a
  clean "No active debuggee" error, and a failed kernel attach is a clean error rather than a panic.
- **Live kernel (KDNET)** — the [live-kernel tier](#the-live-kernel-tier) covers the session
  lifecycle (attach, coexist, detach). For execution control on a real target, additionally run
  `examples/drive_kernel_test.ps1 -Connection "net:port=<n>,key=<w.x.y.z>"`: attach,
  `bp nt!NtCreateFile`, `go` to it, resume, detach. See the KDNET gotchas in `CLAUDE.md` before
  diagnosing a hang.
- **TTD replay** — needs the WinDbg store engine next to the binary (System32's engine rejects
  `.run` traces with `0x80070057`). Open a trace, then exercise `ttd_calls` / `ttd_memory` /
  `ttd_events` and reverse execution. The worked example is
  [`docs/flareauthenticator-ttd-walkthrough.md`](flareauthenticator-ttd-walkthrough.md).
- **TTD recording** — `record_trace` needs elevation and `TTD.exe` on `PATH`.
- **Driver IOCTL sweep** — `examples/sweep_ioctls.ps1` plus the target-side
  `examples/send_ioctls_target.ps1`; needs a benign test driver on a KDNET target.
