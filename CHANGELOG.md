# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **The bounded-command path now has a stated coverage rule, and tests that prove it works.**
  0.3.0 routed `execute`, `dx` and the `ttd_*` tools through a watchdog that Ctrl+Breaks a
  runaway command before it can pin the engine thread, but nothing exercised that interrupt
  end to end, and "why these five?" had no written answer.

  `src/engine.rs` gains both. The queue-aware budget arithmetic is now a pure function with
  unit tests that ride `cargo test`; three `#[ignore]`d tests drive a real engine, proving a
  runaway command self-aborts and leaves the engine usable — including from behind a queued
  job, which is the half win-kexp's own tests cannot cover because the queue belongs to this
  crate. See [`docs/smoke-test.md`](./docs/smoke-test.md).

  The coverage rule, recorded in [`DECISIONS.md`](./DECISIONS.md): bound a command when its
  cost scales with the target's size or with an arbitrary caller-supplied expression; leave
  point queries (`k`, `lm`, `u`, `!irp`, …) unbounded. Arming the watchdog measurably rounds a
  command's duration up to a multiple of 200ms, so bounding a 30ms query would make it a 200ms
  one for a runaway case it does not have. `index_trace` is a deliberate exception and
  now says so: it is O(trace), but `-force` deletes before it rebuilds, so an abort can leave no
  usable index at all — its tool description now tells callers to wait rather than re-issue it.

### Fixed

- **Every opener now commits its session handle, including the four that attach or launch.**
  0.3.0 shipped this guarantee for `open_dump` and `open_trace` only, and documented the gap
  for the rest: win-kexp fused the target-creating call and the wait for the initial break
  into one `Result`, so a failure could mean "nothing happened" or "the process started /
  the attach succeeded, then the wait failed" — indistinguishable from here, and needing
  opposite recovery. Those four tools hedged accordingly, telling callers to check
  `vertarget` before opening again instead of claiming a retry was safe.

  win-kexp split them (glslang/win-kexp#71): each opener is now a `x_begin()` returning a
  `PendingTarget` guard, plus a `wait()` on that guard. The guard cannot exist unless the
  side effect succeeded, so there is finally a seam to commit at. `opened_result` hands its
  `transition` a `commit` callback to invoke at that seam, and every opener reads the same
  way — side effect, `commit()`, wait.

  So a failed break-in wait on `attach_process`, `attach_kernel`, `attach_kernel_local` or
  `launch` now returns the error *with* a usable `session_id`, exactly as a failed load wait
  on a dump already did. The hedge is gone: the server knows which side of the seam a failure
  fell on, and says so — re-open when nothing was created, never re-open when the target is
  already there. For `launch` that is the difference between one process and two.

## [0.3.0] - 2026-08-01

### Added

- **Explicit session handles.** The tools that open a target (`open_dump`, `open_trace`,
  `attach_kernel_local`, `attach_kernel`, `attach_process`, `launch`) now return a
  `session_id`, and every tool that touches the debug target accepts it as an optional
  argument, refusing to run when it no longer matches the session the engine holds. One
  process drives one DbgEng session, but an MCP connection is not a session — a client may
  interleave unrelated requests over the same stdio process — so without a handle a call
  could silently act on a target it never opened. Omitting the argument keeps the previous
  behaviour, so existing callers are unaffected. `decode_ioctl` (pure) and `record_trace`
  (independent of the session) do not take it.

  The check and the session transition both run **on the engine thread**, in the same
  queued job as the debugger call, so they are ordered by the queue that already serialises
  DbgEng access. Validating on the caller side would leave a time-of-check/time-of-use
  window: with session A current, an `open_dump` for B can be in flight while the session
  still reads A, so an `end_session(session_id=A)` would pass, queue behind the open, and
  close B. The guarantee is detection rather than exclusion — the opening tools take no
  handle, so holding one does not prevent a replacement, it makes any later call of yours
  that supplies the handle fail instead of acting on the wrong target.

  The opening tools commit the handle as soon as the target transition succeeds — the
  transition being exactly the one DbgEng call that replaces the target, and nothing else.
  Everything after it (the load wait, and the `lm` / `vertarget` / `r` / TTD lifetime
  diagnostic) runs post-commit, so a failure there reports the error *with* the `session_id`
  rather than swallowing it. The target is genuinely open at that point, and the only other
  way to obtain a handle is to open again, which for `launch` means spawning a second
  process. A `wait_for_event` that times out counts: the dump or trace is loaded either way.
  So does a *panic* in the report — several win-kexp methods use `.expect`, and an unwind
  would otherwise skip straight past the code that attaches the handle.

  One limit is documented rather than fixed: win-kexp bundles the wait for the initial
  break into `launch_process`, `attach_process` and the kernel attaches, so from this server
  a failure there can mean "nothing happened" or "the process started / the attach
  succeeded, then the wait failed", and the two are indistinguishable. Those tools therefore
  say so on failure and point at `vertarget` rather than advising a blind retry, which for
  `launch` would start a second process. Splitting them properly is a win-kexp change.

  `execute` and `dx` are the two paths that can swap the target without going through a
  typed tool. For `execute` the session-control commands (`.opendump`, `.attach`, `.detach`,
  `.kill`, `.restart`, `.abandon`, `.remote`, `q`/`qd`/`qq`) retire the current handle,
  matched per command across every DbgEng command boundary — `;` and line breaks alike,
  since `r\n.opendump other.dmp` is two commands and a scanner that split only on `;` would
  see nothing but `r`. `dx`
  reaches command execution through the data model's
  `Debugger.Utility.Control.ExecuteCommand`, which runs any command string, so an expression
  touching command execution retires the handle too — conservatively, because the command is
  a runtime string this server never sees. Both matches are biased toward retiring —
  over-matching costs a re-open, under-matching would let a stale handle through — and
  neither can be exhaustive, so inside `execute` and `dx` a handle is a strong hint rather
  than a guarantee. Everywhere else it is a guarantee.
- **`session_status`.** Reports the handle of the session the server currently holds, or
  that none is open. It exists to recover a `session_id` a caller never received: the
  per-call timeout can fire while the engine thread is still working, and if that job then
  succeeds it commits a handle no reply ever carried. A live `attach_kernel` is the case
  that matters — it waits indefinitely by design, so the call reporting a timeout while the
  attach completes later is normal, not exceptional. Recovering the handle beats the
  alternative of retrying an attach or launch that would connect or spawn a second time.
  Deliberately does not queue on the engine thread, since the situation it addresses is
  that thread being parked.

  It reports *the current* handle, not *your* handle, so recovery is a two-step check. A
  timed-out open now names the handle it would commit — the id is minted before the job is
  queued, so it can be stated up front — and the caller adopts the session only if
  `session_status` reports that same id. Without that correlation, "ask for the current
  handle" would quietly hand the wrong target to a caller following the documented recovery
  flow, with every later session check passing.

  The current handle alone cannot say *which* of those a mismatch means — "not yours" is
  equally true while an open is still queued and after it has permanently failed — and the
  two need opposite responses: a pending open must not be re-run (that attaches or launches
  a second time), while a failed one must be, since nothing else will produce a target. So
  each opener's outcome is recorded (pending / landed / failed) and `session_status` takes
  an optional `session_id` to ask about one. Outcomes are written from inside the job, under
  `catch_unwind`, so a panicking transition cannot leave an open recorded as pending
  forever; a job that never reaches the engine is recorded as failed on the caller side.

  Only *settled* outcomes are evicted when the history fills. Forgetting a pending open
  would be worse than remembering it indefinitely: `session_status` would report it as
  unknown, which tells the caller to open again — duplicating an attach or a launch, and
  letting the original land afterwards and replace the target underneath them. The history
  can therefore exceed its bound while opens are in flight, which is self-limiting, since
  the engine runs jobs one at a time and every job settles.
- **Tool behaviour annotations.** All 37 tools now declare a title and the
  read-only / destructive / idempotent / open-world hints, so a client can tell
  `read_memory` apart from `execute` before prompting the user. `openWorldHint` is true for
  everything that touches a debug target and false only for `decode_ioctl` and
  `session_status`, which never reach the engine. Two reasons put the rest over the line: a
  symbol server on the path
  means almost any command can pull a PDB (`r` symbolizes the current instruction, `k`
  symbolizes every frame, `bp module!Symbol` resolves a name), and a KDNET session puts the
  target itself across a network link, so even a raw `read_memory` is remote traffic. A
  client may be gating network consent on that hint.
- **End-to-end smoke test** (`tests/mcp_smoke.rs`), for the two events the in-process tests
  cannot see: a dependency moving, and the MCP spec revving. Both change the bytes on the wire
  while the Rust API this crate compiles against stays identical, so the existing tests keep
  passing and clients break. It spawns the built binary and speaks hand-written JSON-RPC to it,
  asserting that stdout carries only JSON-RPC (a dependency logging there corrupts the
  transport), that closing stdin exits the process, that every protocol revision the README
  promises is served — including `2026-07-28`'s handshake-free `server/discover` and its rule
  that *every* request, not just the opener, carries the `_meta` protocol keys — and that no
  capability is advertised that this server does not implement. A golden snapshot
  (`tests/golden/tools_list.json`) records the structural `tools/list` surface (schema dialect,
  hints, parameter types) so a `schemars` or `rmcp` bump lands as a readable diff rather than a
  silent client-visible change; re-record with `UPDATE_GOLDEN=1`. The protocol tier needs no
  debugger, target, or network and runs under plain `cargo test`; a second tier
  (`WINDBG_MCP_SMOKE_DUMP=1`) opens the checked-in sample dump through DbgEng and is the
  automated check for a `win-kexp` regression, available in CI on manual dispatch. Runbook,
  including the manual checklist for the live/TTD paths no runner can host, in
  [`docs/smoke-test.md`](docs/smoke-test.md).

### Changed

- **Upgraded the `rmcp` SDK from 1.x to 3.x**, now that the 3.x line is released rather than beta.
  The practical gain is protocol coverage: 3.x knows the `2026-07-28` revision, so the server now
  answers `server/discover` and the stateless per-request lifecycle in addition to the
  `initialize` handshake, and a client that speaks *only* `2026-07-28` can now talk to it. Both
  come from the SDK's defaults (`supported_protocol_versions` covers every known revision, and
  `serve` dispatches a non-`initialize` opening request through the inline lifecycle), so no
  handler code was needed. The only source change the bump required is the `Content` →
  `ContentBlock` rename in `rmcp::model`; the tool surface, its schemas, and the tool-call wire
  format are unchanged.

- **Debugger failures are now tool-execution errors, not protocol errors.** An unresolvable
  symbol, an unreadable address, a target that never stopped, or a recorder that won't
  start now comes back as a normal tool result with `isError: true` and the debugger's text
  intact, which is what lets the model see the failure and correct itself. Previously every
  such failure became a JSON-RPC `-32603`, which clients surface as a transport-level fault
  and models largely cannot act on. Only a dead engine thread remains a protocol error.
  Semantic input validation (`decode_ioctl`'s code, `ttd_memory`'s address) moved the same
  way — the request satisfies the schema, so the complaint belongs in the result.

  The classification is made by the engine worker, which is the only place that can tell a
  failed operation apart from an engine that never came up: a `DebugEngine::new()` failure
  (missing or unusable `dbgeng.dll`) is permanent and now reports as a protocol error, not
  as a retryable tool error that invites the model to try again forever.

- **`index_trace` is now annotated destructive.** It runs `!ttdext.index -force`, which
  deletes and rebuilds an unloadable `.idx` — replacing an on-disk artifact, whatever the
  intent. `destructiveHint: false` told clients otherwise and could bypass confirmation.
- **Typed tools reject operands that would end the command they build.** They interpolate
  their arguments — `u {address}`, `bp {expression}`, `!drvobj {name} 7` — and DbgEng reads
  `;` as a command separator, so `disassemble { address: "rip; .opendump C:\other.dmp" }`
  ran a target swap from a tool advertising `readOnlyHint: true`, and did it without going
  through the check that retires session handles. Quotes are the same problem deferred:
  `bp <location> "command"` is real WinDbg syntax — `ioctl_trace` builds exactly that form —
  so a quote in a breakpoint location arms a target swap that fires on the next hit, outside
  any tool call. `;`, line breaks, and `"` are now refused with a tool error, the last
  everywhere except `dx`, whose data-model expressions use quoted literals legitimately.
  These parameters were always documented as single operands, so nothing legitimate is
  lost: `execute` remains available for command lists, and is annotated destructive and
  handle-checked accordingly.

### Fixed

- **The server no longer introduces itself as the SDK.** `serverInfo` reported
  `{"name": "rmcp", "version": "<sdk version>"}` to every client, on both the `initialize`
  handshake and the `2026-07-28` `server/discover` response — so anything that names or
  keys off the connected server (client UIs, logs, per-server config) saw "rmcp" rather
  than "windbg-mcp", and saw the SDK's version where it wanted this crate's. The
  `#[tool_handler]` macro defaults to `Implementation::from_build_env()`, whose
  `env!("CARGO_CRATE_NAME")` / `env!("CARGO_PKG_VERSION")` resolve inside `rmcp` rather
  than here; naming the server on the attribute takes both from this crate instead. The
  bug predates the `rmcp` 3.x upgrade — 1.x reported the same — so this is the first
  release in which clients see the right identity.

### Documentation

- README now states which MCP protocol revisions the server speaks — `2026-07-28` and the
  `initialize`-handshake era before it — and what a client gets from each.

## [0.2.1] - 2026-07-23

### Added

- **Discoverable via the official MCP Registry.** Each release now also builds an
  `.mcpb` bundle (`windbg-mcp-vX.Y.Z-windows-x64.mcpb`) next to the existing zip and
  publishes a [`server.json`](server.json) entry (`io.github.glslang/windbg-mcp`) to
  [registry.modelcontextprotocol.io](https://registry.modelcontextprotocol.io) via the
  `mcp-publisher` CLI, authenticated with GitHub OIDC (no secrets). The bundle's
  descriptor is [`packaging/mcpb/manifest.json`](packaging/mcpb/manifest.json); CI stamps
  the release version into both files and the bundle's SHA-256 into `server.json`, so a
  release keeps the same manual bump list as before — Cargo.toml, plugin.json, the README
  badge, and CHANGELOG.

## [0.2.0] - 2026-07-22

### Added

- **Static IOCTL dispatch reachability.** A new `reachable_from_dispatch` tool answers
  whether a code block — given as an absolute address or `module`+`rva` — is reachable from
  a driver's IOCTL dispatch routine, via a bounded breadth-first walk over the call graph
  built from repeated `uf` disassembly. It follows direct calls and cross-function tail
  jumps; it does **not** follow indirect calls through function pointers or unresolved
  compiler jump tables, so a `REACHABLE` verdict is sound (and reports the call path) while
  `NOT REACHABLE` is a best-effort within-bounds result. The `uf`-parsing and graph-walk
  logic is pure and unit-tested (no debugger needed).
- **Driver IOCTL discovery & user-mode reachability.** A new
  [`driver-ioctl.md`](skills/windbg-debugging/driver-ioctl.md) playbook documents a
  static-first, dynamic-confirm workflow for enumerating a driver's IOCTL surface and
  testing whether each code is reachable from user mode (the openable → namespace →
  deliverable → handled gate model), with WinDbg-native (`uf`) static enumeration by
  default and Binary Ninja as an optional escalation. Five supporting tools:
  - `decode_ioctl` — decode a 32-bit control code into its `CTL_CODE` fields and flag
    `METHOD_NEITHER` / `FILE_ANY_ACCESS` (pure; no session needed).
  - `driver_object` — dump a driver's dispatch table + devices (`!drvobj <name> 7`).
  - `device_object` — inspect a device object's type/characteristics/SecurityDescriptor
    (`!devobj`) to answer the *openable* gate.
  - `irp_stack` — dump an IRP's current `IO_STACK_LOCATION` (`!irp`), defaulting the IRP
    to `@rdx` at a dispatch break.
  - `ioctl_trace` — install a conditional logging breakpoint at the IOCTL dispatch
    routine that prints each `IoControlCode` + buffer lengths and continues.
  - An `examples/sweep_ioctls.ps1` harness (host) + `examples/send_ioctls_target.ps1`
    (target-side `DeviceIoControl` sender) driving the dynamic confirm sweep.
  - `attach_kernel` / `attach_kernel_local` now `.load kdexts` automatically so the
    `!drvobj`/`!devobj`/`!irp` commands behind `driver_object`/`device_object`/`irp_stack`
    resolve; `setup.md` bundles `winxp\kdexts.dll`. Verified end-to-end against a live
    KDNET kernel (the tools captured real mountmgr IOCTLs).
  - [`docs/driver-ioctl-walkthrough.md`](docs/driver-ioctl-walkthrough.md): a worked
    `\Driver\mountmgr` enumeration + reachability report against a live kernel. The
    playbook now ends with a "Write the report" step + template.
- **`record_trace` `env` and `working_dir` options** — pass extra `KEY=VALUE` environment
  entries and a working directory to the recorded target, for programs that refuse to run
  without a specific environment (e.g. a Qt app's `QT_QPA_PLATFORM_PLUGIN_PATH`, or an
  anti-analysis "run me from here" guard). Previously the recorder only inherited the
  server's environment.

### Fixed

- **`index_trace` now works.** It invoked `!tt.index`, which fails with `LoadLibrary(tt)` —
  there is no `tt` extension. The bundled engine exposes trace indexing through `TtdExt.dll`,
  so `index_trace` now runs `!ttdext.index` (building a persistent `.idx` next to the `.run`).
- **`open_trace` flags an unindexed trace.** A freshly recorded `.run` has no `.idx`, so the
  first data-model query silently builds an in-memory index and can run long; `open_trace`
  now says so up front (via `!ttdext.index -status`) and points at `index_trace`.
- **`registers` no longer returns a blank result** when there is no thread context (a
  module-load break or a bare `goto_position 0`); it explains why and how to get a context.
- **A runaway debugger command no longer wedges the session.** `execute`, `dx`, and the
  `ttd_*` query tools now run through a bounded path
  ([`win-kexp`](https://github.com/glslang/win-kexp)'s `execute_command_bounded`) that
  `SetInterrupt`s the engine shortly before the per-call timeout. Previously an unbounded
  command — most importantly a broad `s` memory search — could pin the single engine thread
  indefinitely, so every later tool call timed out behind it and the only recovery was to
  kill and reconnect the server. Now such a command self-aborts (with a note) and the engine
  stays usable. (win-kexp pin bumped to include `execute_command_bounded` + its interrupt drain.)

## [0.1.3] - 2026-06-14

### Fixed

- Ending a live-kernel session (`end_session`) no longer leaves the target
  **frozen**. It was a passive detach, which never tells the target to run, so
  detaching while halted at a break left the guest frozen — one CPU halted, the
  rest spinning — with the breakpoint `int3` still patched. `end_session` now
  clears breakpoints, resumes the target, and does an active detach, leaving the
  kernel running. (win-kexp `777b5c2`.)

## [0.1.2] - 2026-06-14

### Fixed

- **Live kernel debugging now works.** `attach_kernel` / `attach_kernel_local`
  connect, request an initial break-in, and wait with the INFINITE timeout a live
  kernel requires — a finite timeout returned `E_NOTIMPL` and never drove the
  connection — so the engine breaks in, breakpoints resolve, and `go` runs to them.
  The wait is bounded by a watchdog (`SetInterrupt`) so the single engine thread
  can't hang on an unresponsive target; a forced timeout is reported as an error.
- A failed kernel attach now returns a clean error instead of panicking the
  debugger worker thread.
- `go`/step with no active debuggee now returns a clear "No active debuggee" error
  instead of crashing the server (a previously uncatchable engine fault).

### Added

- Example stdio JSON-RPC drivers under `examples/` (live-kernel attach, user-mode
  launch, and robustness regression checks).

### Changed

- The live/kernel skill now instructs asking the user for the target's actual KDNET
  connection string (the port and key can't be guessed).
- CI auto-approves and auto-merges Dependabot PRs.

## [0.1.1] - 2026-06-12

### Added

- Prebuilt Windows x64 binary releases: pushing a `vX.Y.Z` tag now builds
  `windbg-mcp.exe` and attaches `windbg-mcp-vX.Y.Z-windows-x64.zip` (plus a SHA256
  checksum) to the GitHub release, and the setup docs gained a no-Rust install path
  that downloads it into `target\release\`.
- Signed build-provenance attestations for release zips, verifiable with
  `gh attestation verify` (see the README's *Releasing* section).

### Security

- GitHub Actions in the CI and release workflows are pinned to immutable
  commit SHAs, with Dependabot configured to keep the pins (and their
  version comments) up to date.

## [0.1.0]

Initial release, packaged as a single-plugin Claude Code marketplace.

### Added

- **`windbg` MCP server** (Rust, stdio) exposing DbgEng-backed debugging tools:
  session management (open dump/trace, attach to process/kernel, launch, end),
  state queries (registers, memory read, backtrace, modules, threads,
  disassemble, `dx`), execution control (go, step over/into, breakpoints), Time
  Travel Debugging navigation (step back, reverse go, goto position) and
  analysis (`ttd_calls`, `ttd_memory`, `ttd_events`, index), TTD trace recording,
  and a raw `execute` command passthrough.
- **`windbg-debugging` skill** with task playbooks: setup, crash-dump triage,
  live/kernel debugging, and TTD recording/replay/analysis.
- Crash-dump `!analyze` support via automatic WinDbg extension DLL loading.
- Windows CI (format, clippy, build, test) and walkthrough docs with sample dumps.

[Unreleased]: https://github.com/glslang/windbg-mcp/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/glslang/windbg-mcp/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/glslang/windbg-mcp/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/glslang/windbg-mcp/compare/v0.1.3...v0.2.0
[0.1.3]: https://github.com/glslang/windbg-mcp/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/glslang/windbg-mcp/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/glslang/windbg-mcp/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/glslang/windbg-mcp/releases/tag/v0.1.0
