# Binary Ninja bridge validation

## Automated results

Verification used an isolated temporary checkout on the running Windows ARM64 debugger VM,
after rebasing the WinDbg changes onto upstream `2f9cce0` (2026-09-05).
The VM's working checkout, release executable, and live kernel sessions were left untouched.

| Check | Result |
|---|---|
| Official SDK | `mcp==2.1.1`, Python 3.10.21; real loopback Streamable HTTP interoperability passed |
| Plugin tests | 17 passed; one real-capture parameterization skipped because no captured driver fixtures exist yet |
| Plugin lifecycle coverage | Authentication, Host/Origin rejection, port collision, restart, closed/duplicate views, cancelled completion subscription |
| Pairing coverage | Serialized polling/actions, unchanged-location preservation, outside-module stops, running state, coordinate forwarding, ambiguous timeout without mutation retry |
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

The installed application reports **5.3.9757 Personal** and bundles Python 3.10. The core
API and native UI type signatures were inspected locally, including file/view enumeration,
main-thread scheduling, completion events, undo APIs, relocation ranges, and UI notifications.
The public API intentionally refuses `binaryninjaui` in a headless context. Signature
inspection is not a substitute for running the adapter inside the application.

## Outstanding acceptance gates

- Run the plugin inside Binary Ninja 5.3 Personal: startup menus, view close/rebase, analysis
  completion/cancellation, navigation, and undo for each edit.
- Capture real HEVD and mountmgr adapter outputs for identified builds. Pin their original
  file hashes, architecture, analysis version, and independently reviewed expected mappings.
  The capture helper and replay test are provided; synthetic tests do not satisfy this gate.
- Validate the actual HEVD dispatch mapping and a complete mountmgr mapping. Compare static
  security defaults with independently observed runtime access for that build.
- Exercise pairing against the Windows VM from the Binary Ninja UI, including reconnect,
  rebase, stale responses, and deliberate module replacement between pairing and an action.

These gates remain open. The implementation should not be represented as accepted for
real-driver analysis until they are completed. See the [plan](binja-windbg-mcp-plan.md). Installation instructions and plugin tests live
in the separate `binja-windbg-mcp` repository.
