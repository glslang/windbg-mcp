# Binary Ninja bridge validation

## Companion 0.2 refactor (2026-09-06)

The companion targets Binary Ninja 6.0.10601 Personal and Python 3.13. Its reduced surface
contains 16 tools; general inspection and editing use native MCP. The hash-pinned
`mcp==2.1.1` runtime lock was resolved for 3.13 and installed with hash checking in a fresh
CPython 3.13.15 environment. The installed application bundles 3.13.14.

- Python tests after dependency/UI/shutdown and pairing fixes: 78 passed, including original/fixed HEVD captures and a real typed-input replay; no skips.
- The official-SDK loopback test passed and checked the regenerated 16-tool golden.
- Regression tests cover binary selection independent of active view, cache invalidation,
  stale/mismatched evidence refusal, inactive-cursor pairing validation, and retired profile
  groups failing before listener startup with migration guidance.
- Ruff format/lint and documentation lint passed.
- Compact serialization of the tool-schema snapshot fell from 17,283 to 10,368 bytes. This
  compares the snapshots only; it excludes server instructions and protocol envelopes.

The [native MCP test drive](binja6-native-mcp-test-drive.md) exercised 32 of the installed
server's 75 tools. The companion has now also passed the limited UI smoke below. The completed UI
lifecycle and identified-driver acceptance results appear below.

## Pairing failure regression checks (2026-09-06)

Fault injection through the official SDK's in-memory client/server reproduced and fixed
HTTP 401/403 failures being retried when wrapped in exception groups. Direct and nested
failures now stop polling with `authentication_failed` and close the client.

Every polling-task exit resolves queued actions as unsent, including terminal session
errors, invalid structured contracts, authentication failure and explicit unpairing.
Cancelled callers are skipped. Unpairing during an active request now resolves that
request with an uncertain outcome while rejecting its queued successors; no mutation
is retried. Eight new regression cases failed before the fixes and pass afterward.

The complete Python suite passed: **78 tests, no skips**. Ruff formatting/lint and
Markdown lint passed. These are automated failure-path checks; they do not complete
the live reconnect and module-replacement acceptance gates below.

## Native dependency installation and companion UI smoke (2026-09-06)

A separate Binary Ninja **6.0.10601 Personal** GUI instance loaded the actual symlinked
checkout. Its bundled **Python 3.13.14** parsed all 28 `requirements.txt` pins, then the
plugin invoked `BNInstallScriptingProviderModules` through the registered Python provider.
The native installer populated the shared `python313/site-packages` directory. No custom
Python search path, external installer, or application-bundle modification was needed.

Binary Ninja bundles `idna==3.10`; the SDK's HTTP dependency requires at least 3.18. The
native installer successfully placed the tested 3.19 in the user package directory. The
plugin reported the required restart. After restarting the test instance, all pinned
packages were visible and the authenticated listener started successfully.

The official SDK client then verified:

- 16 tools, missing bearer credentials returning 401, and invalid Host/Origin returning 403.
- `list_binaries` returning the x64 PE fixture at base `0x0000000180000000`, timestamp
  `1788542977`, and `SizeOfImage` `12288`.
- Original-byte SHA-256 `d49bf95e9cbef15b832021dedd3827968186de3d17f9be30fad3c17e3dbc93f2`,
  matching the synthetic fixture from the native test drive.
- Explicit-binary `current_location` returning metadata with no cursor for the inactive view.
- `wait_for_analysis` completing immediately on the already idle view.
- `driver_surface` preserving import inventory success and unavailable dispatch/security/IOCTL
  sections. This synthetic PE does not provide a real-driver dispatch recovery fixture.

Live calls exposed and corrected three adapter assumptions: use `BinaryView.length`, use
its typed `analysis_state` property, and check for idle analysis after subscribing to future
completion events. Focused regression tests cover these and zipped bundled-package metadata,
shared-package conflicts, setup retries, and Stop during installation.

The dedicated test instance was closed after read-only verification. The fixture bytes
were unchanged. Existing Binary Ninja sessions were not restarted. At this stage, menu interaction,
evidence undo and close/rebase races had not yet been exercised. Active navigation and direct
WinDbg pairing subsequently passed the HEVD test below.

## Application quit verification (2026-09-06)

A temporary, environment-gated probe in a separate empty Binary Ninja 6.0.10601 Personal
instance exercised normal Qt application quit after an authenticated companion MCP call.
The process exited with code 0 in 0.327 seconds. At the quit signal, cleanup had marked
the plugin shutting down, stopped its listener thread, and left no local pairing. The
TCP port refused connections after exit. The probe was removed after the test; the
existing Binary Ninja instance was not restarted or closed.

The native command registry also confirmed the four controls with an empty binary-view
context: Start disabled while listening, Stop enabled, and Status/Connection Information
enabled. Automated regressions cover duplicate quit/exit hooks, late dependency setup,
cancelled analysis subscriptions and budgets, abandoned UI dispatch, polling-task cleanup,
and Stop arriving before the HTTP server is constructed. These checks do not establish
shutdown against a live paired WinDbg VM or force-quit cleanup.

## Live HEVD bridge test (2026-09-06)

Binary Ninja 6.0.10601 Personal and the updated Windows ARM64 WinDbg MCP service passed
an end-to-end run against the installed HEVD build with original SHA-256
`8cd7546a42fe11308e512e54282c0d8b60f8c8774ec8823c5550ba5e53ac706e`.
PE timestamp `1734099220`, SizeOfImage `585728`, and PDB GUID
`A75E3B9A77BD44C4A5C5E8F7F563A002`, age `1`, identify the fixture.

The run verified matching coordinates, three wrong-identity refusals, a complete equal
32-byte comparison, companion breakpoint installation and hit at RVA `0x87078`, stop
following, manual-navigation preservation, and run-to at the actual IL cursor `0x87098`.
A zero-access device open/close triggered the routine; no IOCTLs were sent. The test
removed its breakpoint, closed the pairing, ended the disposable session and released
the guest. This runtime access observation used SYSTEM, not an unprivileged user.

The test exposed and fixed loss of the selected cursor when macOS deactivates Binary
Ninja. The sole window's selected tab remains available; multiple inactive windows are
still refused as ambiguous. Real adapter output now covers 108 HEVD functions and is
replayed offline. Dispatch registration, import inventory and bounded traversal succeed;
the initial IOCTL input failure was subsequently fixed using the actual database layout.
The ordinary map now recovers all 29 cases for this build, with no unresolved entries,
verified against independent ARM64 branch evidence and through authenticated MCP.
The original partial capture is retained alongside the successful capture and a real
input-layout replay. Buffer sizes remain unproven; no IOCTLs were executed. Callbacks shared
with other major functions and missing layouts remain conservative. The companion repository
contains `docs/hevd-e2e.md`, selected structured results, both captures and the opt-in
`tools/hevd_e2e.py` runner.

## WinDbg verification (2026-09-05)

Verification used an isolated temporary checkout on the running Windows ARM64 debugger VM,
after rebasing the WinDbg changes onto upstream `2f9cce0` (2026-09-05).
The VM's working checkout, release executable, and live kernel sessions were left untouched.
The native-MCP refactor changes no Rust source; these WinDbg results remain the verification
record for the existing guarded coordinate/memory contracts.

| Check | Result |
|---|---|
| Rust formatting | `cargo fmt --all --check` passed |
| Windows cross-target lint | x64 and ARM64 `cargo clippy --all-targets` passed; expected missing PE-resource compiler warnings on macOS |
| Windows unit suite | 695 passed, zero failures |
| Windows protocol suite | 104 passed, 12 explicitly ignored manual tiers; both surface goldens regenerated and checked |
| Enabled debugger tier | `WINDBG_MCP_SMOKE_DUMP=1 cargo test --test mcp_smoke -- --nocapture`: 104 passed, 12 ignored, 149.74 seconds |
| Bridge debugger smoke | Mapped location, guarded memory bytes, and mismatched-identity breakpoint refusal passed |
| Result budgets | Current location: 284 B structured, 427 B wire; 32-byte memory result stayed below 400 B structured |
| Documentation | Repository Markdown lint passed |

The enabled debugger run still prints skips for separately gated TTD/live-kernel checks
and for the absent x86 worker. It does not establish those workflows. No `!analyze` extension
bundle was added to the isolated build. The new bridge assertions themselves ran against
the checked-in dump and did not skip.

## Binary Ninja compatibility evidence

Before the 0.2 refactor, core API and native UI type signatures were inspected locally
against **5.3.9757 Personal** with Python 3.10, including file/view enumeration,
main-thread scheduling, completion events, undo APIs, relocation ranges, and UI notifications.
The public API intentionally refuses `binaryninjaui` in a headless context. Signature
inspection is not a substitute for running the adapter inside the application.

## Mountmgr and remaining live acceptance (2026-09-06)

The complete ARM64 mountmgr 10.0.26100.1 fixture pins SHA-256
`734b4a45381ca6850d827f895e86e50ad03a882689483510402d96757fe15497`, PE/PDB identity,
explicit type prerequisites, 184 functions and independent instruction/table evidence.
All 93 code/site records match the adapter and authenticated MCP: 48 host/silo routes for
24 recognized codes and 45 explicit default-rejection table slots. Three jump tables and
real branch shapes are retained. Exact buffer sizes remain unproven. The ordinary map
succeeds; the composite retains partial security and bounded traversal results.

The companion's [mountmgr report](https://github.com/glslang/binja-windbg-mcp/blob/main/docs/mountmgr-e2e.md)
contains the full mapping, structured results and reproduction tools. It is separate from
the older abbreviated WinDbg walkthrough, which used a different build.

Live checks passed for equal bytes, breakpoint/hit at RVA `0x18eb4`, following, manual
navigation, run-to at `0x18ec4`, and successful completion of a read-only query. Independent
SYSTEM and standard-user tests confirmed mountmgr access restrictions, the live DACL and
namespace, and successful standard-user `QUERY_AUTO_MOUNT` on a zero-access handle.
HEVD standard-user opens also succeeded; no HEVD IOCTL was sent.

Real GUI acceptance covered evidence undo, cache invalidation after native symbol/type
edits, Start/Stop/restart and disabled menu states, busy-analysis cancellation/completion,
rebase, stale responses, close and reopen. A forwarding fault proxy verified reconnect
module validation, terminal authentication failure and an uncertain breakpoint timeout
with exactly one forwarded mutation. A disposable DLL loader replaced the paired image
at the same address; all guarded actions refused without changing breakpoints or IP.
Normal GUI quit while paired closed the listener/client and preserved the debugger
session, which was explicitly released afterward. Temporary users and loader files were
removed, and the test guest was resumed.

Live testing exposed and fixed generic goto/fallthrough/block case destinations, abandoned
analysis requests in the SDK's JSON-only response mode, and loss of HTTP 401/403 identity
through SDK error normalization. Regressions now use the actual HTTP transport. The final
Python suite passed **88 tests, no skips**; Ruff formatting/lint, independent routing replay
and Markdown lint passed. No Rust source changed in this acceptance pass.

A temporary probe crashed the owned BN instance by passing an invalid object to a native
UI binding. The fixture/database survived; the test restarted and completed using valid
registered UI actions. The probe is not part of the delivered plugin.

## Acceptance scope

The previously outstanding mountmgr and live lifecycle gates are completed for these
identified ARM64 HEVD/mountmgr builds in Binary Ninja 6.0.10601 Personal. These results do
not establish recovery for other builds, runtime execution of every static case, silo
runtime behavior, force-quit cleanup, or other Windows security configurations. Partial
security recovery and bounded sink traversal remain explicit supported outcomes.
Structured `reachable_from_dispatch` remains follow-up #60; broader coverage import and
report export remain deferred as specified in the [plan](binja-windbg-mcp-plan.md).
