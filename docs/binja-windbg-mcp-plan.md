# Binary Ninja–WinDbg MCP Bridge

## Summary

Create `binja-windbg-mcp`, a macOS-first Binary Ninja Python UI plugin exposing authenticated Streamable HTTP MCP. Initial support targets Apple Silicon macOS, Binary Ninja 5.3 Personal, and its Python 3.10 environment.

Use the official [modelcontextprotocol/python-sdk](https://github.com/modelcontextprotocol/python-sdk), distributed as `mcp`, for both the server and outbound WinDbg client. Pin a tested v2 release and its dependencies. Use its protocol and transport implementation; exclude third-party MCP frameworks and bridge projects.

The MCP host orchestrates both servers through `(module, PE identity, RVA)` coordinates. Optional direct pairing follows a selected debugger session and provides explicit breakpoint, run-to, and byte-comparison actions.

V1 supports driver analysis, navigation, and evidence capture. Breakpoint installation and run-to execution are the only direct debugger mutations exposed by this plugin. Automatic execution, arbitrary debugger commands, memory/register writes, exploitation, vulnerability verdicts, and report submission are outside V1.

## Shared contract and WinDbg changes

- Use the following coordinate across servers:

  ```json
  {
    "module": "driver",
    "image_name": "driver.sys",
    "identity": {
      "timestamp": 1234567890,
      "size": 65536
    },
    "rva": "0x1234"
  }
  ```

  `size` means PE `SizeOfImage`. Preserve existing conventions: lowercase, zero-padded 64-bit address strings and lowercase, unpadded RVAs. Image paths are descriptive metadata; cross-server mapping requires image identity and RVA.

- Treat timestamp and size as matching metadata, without claiming cryptographic identity. Record architecture and a SHA-256 of available original file bytes for reproducibility; mark the hash unavailable when original bytes cannot be recovered reliably. Validate additional PDB identity when both sides supply it.
- Add `current_location` to the `inspect` group. Return the current instruction pointer, available thread/processor identifiers, and containing image coordinate. Collect these in one worker job on the DbgEng thread. Distinguish unmapped addresses, attribution failures, and unavailable execution context.
- Extend `read_memory` with structured address, requested size, actual read size, and lowercase byte-order hexadecimal data. Preserve its text rendering, existing allocation bound, and the shared batch-reading behavior. Successes and failures use the existing typed outcome convention.
- Add an optional `coordinate` alternative to the existing location arguments of `set_breakpoint`, `run_to_address`, and `read_memory`. Require exactly one location form and an explicit session for coordinate-based calls. Preserve existing callers. Inside the worker job, resolve the uniquely matching loaded module, validate identity and range, and execute against the resulting numeric address without another client's job interleaving. Refuse missing or ambiguous modules and mismatches.
- Update tool registration, worker protocol/types, structured-result documentation, coordinate documentation, playbooks, and smoke coverage. Refresh both tool-surface goldens; evaluate result growth separately through result-budget checks. No new cross-thread DbgEng exception is introduced.

## Binary Ninja server and analysis

Run one listener per Binary Ninja process on `127.0.0.1:8766/mcp`, using a dedicated network thread and asyncio loop. Expose Streamable HTTP only; exclude legacy SSE endpoints and stdio. Autostart by default, with Start, Stop, Status, and Connection Information menu actions. Port collisions are visible startup failures.

Generate a 32-byte bearer token. Validate HTTP host and origin information. Store credentials and named WinDbg profiles in a user-only `profiles.json` under Binary Ninja's per-user data directory, with macOS mode `0600`. Tokens never appear in tool arguments, logs, or BNDB metadata. WinDbg connections use loopback/tunneled HTTP or authenticated HTTPS, with certificate verification and no credential-bearing redirects.

Expose 24 tools with startup-configured groups:

| Group | Tools |
|---|---|
| `workspace` | `list_binaries`, `current_location`, `navigate`, `wait_for_analysis` |
| `analysis` | `get_code`, `function_info`, `function_cfg`, `xrefs`, `search` |
| `driver` | `driver_entry`, `sink_imports`, `device_security`, `ioctl_map`, `driver_surface` |
| `edit` | `set_comment`, `add_evidence`, `rename_symbol`, `apply_type` |
| `pair` | `pair_windbg`, `windbg_pair_status`, `unpair_windbg` |
| `debug` | `set_breakpoint_here`, `run_to_here`, `compare_runtime_bytes` |

All groups are enabled by default. `workspace` is always included; selecting `debug` also includes `pair`. Each tool belongs to exactly one group.

### Workspace and analysis behavior

- Return process-lifetime opaque binary IDs, path/display name, active state, architecture, analysis state, current image base, and PE identity. Read identity from PE headers, including for rebased BNDBs.
- Require a selected binary and matching identity for debugger-origin navigation. Reject ambiguous views, invalid RVAs, and unmapped destinations.
- `get_code` supports disassembly, LLIL, MLIL, and HLIL. `auto` selects the best available representation and reports the actual choice. Preserve source-address mappings. CFG, xref, search, and code responses are typed and capped, with explicit truncation.
- Perform short UI operations on the main thread and analysis work outside the UI and network loops. Implement `wait_for_analysis` through completion notifications with cancellation and a deadline.
- Retain BinaryView handles only for active jobs or completion subscriptions. Cache immutable results by binary identity, view generation, analysis revision, and analysis parameters. Invalidate on relevant edits, reanalysis, rebase, or close; discard stale results before rendering or navigating.

### Driver analysis behavior

- `driver_entry` recovers supported dispatch registrations and reports WDM/KMDF evidence, roots, and unresolved callbacks.
- `sink_imports` performs a cheap import inventory against a documented, versioned sink list. Import presence does not imply a reachable call; absence does not exclude dynamic resolution or equivalent code.
- `device_security` reports creation call sites, recovered SDDL defaults, class GUIDs, device characteristics, and symbolic-link literals. Effective access and namespace visibility remain dynamic findings because installation/runtime configuration can override defaults.
- `ioctl_map` recovers cases tied to an identified control-code input using structured IL. Support resolved switches and comparison chains; retain unsupported and unresolved control flow explicitly. Binary Ninja improves recovery opportunities without guaranteeing resolution.
- Put bounded dispatch-to-sink traversal in an optional `ioctl_map` analysis, disabled for ordinary map calls and enabled by `driver_surface`. Default depth is 2 and the function limit is 128; enforce hard maxima of depth 8 and 1,024 functions, with cancellation and deadline checks.
- Implement `driver_surface` as a composite over the same four core functions. Preserve per-section success, partial, unavailable, and error outcomes, including prerequisites and traversal bounds. A failed dispatch recovery must not discard import or security evidence.

Define one shared IOCTL-case shape using `code`, `device_type`, `function`, `method`, `required_access`, `dispatch_rva`, `case_rva`, `in_size`, and `out_size`. Derive decoded fields from the numeric code. Size fields contain proven exact sizes or `null`; retain minimum/conditional checks separately as evidence. Multiple case sites remain separate records. Exclude `predicted_reachable`.

Correct the playbook example: `0x0022e004` requires read and write access. Probe evidence records observed sites and analysis coverage; it does not certify safe buffer handling or establish a vulnerability.

Use available NT types and report their provider, architecture, and missing prerequisites. Analysis tools do not apply types automatically. Explicit `apply_type` may import an available named type and apply it within an undoable edit. Validate required layouts rather than assuming libraries named `wdm` or `ntddk` exist.

All edits are explicit and undoable. Comments append by default. Evidence stores the image coordinate, available file identity, session ID, profile name, runtime address, context, timestamp, and note. It never stores bearer tokens or kernel connection strings. Function/data renaming and typing are supported; local-variable edits are deferred.

## Direct pairing and focused actions

- Support one active pairing per plugin process. `pair_windbg(profile, session_id, binary_id, poll_interval_ms=500)` requires explicit unpairing before replacement. Use the same WinDbg bearer credential as the host, validate the selected module, and check that required tools and structured contracts are available. Disable unsupported focused actions with an explanatory status.
- Poll with one outstanding request at a time. Clamp the requested interval to 200–5000 ms. Treat `target_running` as normal running state and use at least a one-second interval. Back off transient connection failures exponentially to ten seconds. Authentication failures and terminal session errors stop polling.
- Poll latency includes the worker queue; sub-second following is a best-effort target on an idle, responsive session. Polling never interrupts the host's work or refreshes module/symbol inventories automatically.
- Pin the selected binary. Stops elsewhere update status without navigating. Navigate only when the debugger location/context changes; repeated identical samples preserve manual navigation. Discard late responses after unpairing, view closure, or generation changes. Revalidate after reconnecting or rebasing.
- Serialize focused actions with polling. The cursor must belong to the paired view. Capture its coordinate and use the guarded WinDbg calls. Never automatically retry breakpoint or run-to mutations after an ambiguous timeout; report that the outcome is uncertain.
- `compare_runtime_bytes` reads 32 bytes by default, capped at 256. Compare against the current BinaryView, identifying that source and its modification state. Report actual bytes, differing offsets, incomplete reads, and relocation-overlapping ranges. Report raw differences without attributing them automatically to hotpatching or build mismatch.
- Unpairing cancels local work and closes the outbound MCP client without ending the debugger session or removing existing breakpoints. Pairings are not persisted. Document that authenticated polling renews applicable lease/idle activity and can keep sessions alive.

## Verification and delivery

Deliver in this order: official-SDK/UI compatibility proof; coordinate and memory contracts; workspace and static analysis; explicit edits; direct pairing and focused actions. Keep the existing host-orchestrated workflow usable throughout.

Verification must cover:

- **WinDbg:** mapped/unmapped/failed-attribution locations, running-target refusals, memory boundaries and partial reads, batch compatibility, structured errors, group membership, both surface goldens, and result budgets. Test module replacement between pairing and action: guarded operations must refuse without applying changes.
- **Binary Ninja core:** rebased coordinates, duplicate views, identity mismatch, CTL decoding, conditional sizes, compare chains, jump tables, unresolved KMDF dispatch, missing types, bounded sink paths, partial composite results, and cache invalidation.
- **Lifecycle and transport:** official-SDK client/server interoperability, authentication, loopback binding, group selection, start/stop/restart, closed views, cancelled analysis waits, stale poll responses, reconnect validation, manual navigation, and ambiguous mutation timeouts.
- **Real analysis fixtures:** capture adapter outputs from Binary Ninja and replay immutable fixtures in offline tests. Pin binary hashes, architecture, analysis version, and expected code-to-handler mappings. Mocks supplement these captures.
- **End-to-end validation:** rerun the HEVD and mountmgr workflows against identified builds. Verify HEVD's actual dispatch mapping rather than a published table. Establish a complete mountmgr fixture separately from its abbreviated walkthrough, and compare static security evidence with independently observed runtime access.
- **Required checks:** formatting and documentation lint; Windows-target checks/clippy from macOS; Windows `cargo test` and the explicitly enabled debugger smoke tier. Manually validate on Binary Ninja 5.3 Personal and a Windows WinDbg VM.

Keep structured `reachable_from_dispatch` output as a separate follow-up: preserve text, expose paths and branch recipes, and perform worker-side module attribution for coordinate-bearing addresses. Allocate its follow-up number when filed.

Defer automatic binary acquisition, bulk runtime coverage import, local-variable edits, and report export. Any later coverage import must describe observed execution only; an unobserved location is not proof of unreachability.
