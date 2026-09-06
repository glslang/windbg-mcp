# Binary Ninja bridge validation

## Companion 0.2 refactor (2026-09-06)

The companion targets Binary Ninja 6.0.10601 Personal and Python 3.13. Its reduced surface
contains 16 tools; general inspection and editing use native MCP. The hash-pinned
`mcp==2.1.1` runtime lock was resolved for 3.13 and installed with hash checking in a fresh
CPython 3.13.15 environment. The installed application bundles 3.13.14.

- Python tests after dependency/UI/shutdown fixes: 70 passed, including original/fixed HEVD captures and a real typed-input replay; no skips.
- The official-SDK loopback test passed and checked the regenerated 16-tool golden.
- Regression tests cover binary selection independent of active view, cache invalidation,
  stale/mismatched evidence refusal, inactive-cursor pairing validation, and retired profile
  groups failing before listener startup with migration guidance.
- Ruff format/lint and documentation lint passed.
- Compact serialization of the tool-schema snapshot fell from 17,283 to 10,368 bytes. This
  compares the snapshots only; it excludes server instructions and protocol envelopes.

The [native MCP test drive](binja6-native-mcp-test-drive.md) exercised 32 of the installed
server's 75 tools. The companion has now also passed the limited UI smoke below. Full UI
lifecycle and real-driver acceptance remain separate gates.

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
were unchanged. Existing Binary Ninja sessions were not restarted. Manual menu interaction,
evidence undo and close/rebase races remain outstanding. Active navigation and direct
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

## Outstanding acceptance gates

- Complete companion UI acceptance in Binary Ninja 6 Personal: manual startup menu
  interaction, view close/rebase, busy analysis completion/cancellation, and evidence
  undo. Exercise cache invalidation through actual native MCP symbol/type edits.
- Capture and validate a complete mountmgr build, pinning file hash, architecture, analysis
  version and independent mapping expectations. Extend HEVD coverage to other builds;
  this build's 29 verified static cases do not establish universal driver recovery.
- Compare static security defaults with independently observed runtime access, including
  ordinary-user access. HEVD's runtime bridge trigger only exercised open/close as SYSTEM.
- Extend the passing live pairing workflow to reconnect, rebase, stale responses and deliberate
  module replacement between pairing and an action. Changed-coordinate refusal alone does not
  exercise an actual unload/reload race.

These gates remain open. The implementation should not be represented as accepted for
real-driver analysis until they are completed. See the [plan](binja-windbg-mcp-plan.md) and [installation instructions](../README.md).
