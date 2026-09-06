# Binary Ninja bridge validation

## Companion 0.2 refactor (2026-09-06)

The companion targets Binary Ninja 6.0.10601 Personal and Python 3.13. Its reduced surface
contains 16 tools; general inspection and editing use native MCP. The hash-pinned
`mcp==2.1.1` runtime lock was resolved for 3.13 and installed with hash checking in a fresh
CPython 3.13.15 environment. The installed application bundles 3.13.14.

- Python tests after dependency/UI fixes: 40 passed; one real-driver capture parameterization skipped.
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
active-view navigation, evidence undo, close/rebase races, and direct WinDbg pairing still
require acceptance testing.

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
  interaction, view close/rebase, busy analysis completion/cancellation, navigation, and evidence
  undo. Exercise cache invalidation through actual native MCP symbol/type edits.
- Capture real HEVD and mountmgr adapter outputs for identified builds. Pin their original
  file hashes, architecture, analysis version, and independently reviewed expected mappings.
  The capture helper and replay test are provided; synthetic tests do not satisfy this gate.
- Validate the actual HEVD dispatch mapping and a complete mountmgr mapping. Compare static
  security defaults with independently observed runtime access for that build.
- Exercise pairing against the Windows VM from the Binary Ninja UI, including reconnect,
  rebase, stale responses, and deliberate module replacement between pairing and an action.

These gates remain open. The implementation should not be represented as accepted for
real-driver analysis until they are completed. See the [plan](binja-windbg-mcp-plan.md) and [installation instructions](../README.md).
