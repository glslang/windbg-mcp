# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/glslang/windbg-mcp/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/glslang/windbg-mcp/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/glslang/windbg-mcp/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/glslang/windbg-mcp/releases/tag/v0.1.0
