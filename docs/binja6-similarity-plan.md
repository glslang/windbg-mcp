# BN6 similarity in the Binary Ninja–WinDbg companion

Status: implemented in the companion checkout, 2026-09-07. The six tools, background
comparison lifecycle, textual differences, and capture runner have automated
coverage. Native Ultimate execution, real similarity captures, and the live
similarity-to-debugger acceptance workflow remain release gates. This document
retains the agreed design; it does not claim Ultimate validation.

The companion suite passed 125 tests with no skips, including 31 similarity cases
and the HTTP tool golden. Ruff lint/format checks and documentation lint passed.

The companion's `docs/similarity.md` documents the implementation, limits, and
opt-in acceptance procedure.

## Summary

Extend `binja-windbg-mcp` with an optional Ultimate feature that compares two open
Windows PE views or BNDBs. Support BinDiff structural matching, WARP exact matching,
agent-readable disassembly differences, and navigation into the existing debugging
workflow.

Use BN6's Python similarity API directly. The framework requires Ultimate; existing
Personal workflows remain supported. See the
[BN6 announcement](https://binary.ninja/2026/09/03/binary-ninja-6.0-krypton.html#binary-similarity)
and the [existing companion integration plan](binja-windbg-mcp-plan.md).

## Public interface

Add a `similarity` tool group, included by `groups: "all"`:

| Tool | Behavior |
|---|---|
| `similarity_start` | Accept reference and target companion binary IDs, provider selection, and timeout; return a comparison ID. |
| `similarity_status` | Return progress and state; without an ID, report capabilities and retained comparisons. |
| `similarity_results` | Page through matches or unmatched functions, with side, provider, and score filters. |
| `similarity_diff` | Return paginated paired disassembly differences for a selected match. |
| `similarity_cancel` | Request cancellation while retaining completed results. |
| `similarity_close` | Release a comparison; request cancellation first if it is running. |

On Personal, status explains that Ultimate is required; comparison requests return
a structured unavailable result without affecting other tools.

Extend existing `navigate` with an optional expected generation, reusing the
adapter's existing generation check. Similarity results supply the coordinate and
generation for either side.

## Implementation

- **Inputs and providers:** Require two distinct, analyzed PE views of the same
  architecture. Use existing companion IDs, metadata, hashes, and generation stamps.
  Default to both providers; report unavailable requested providers explicitly.
  Use session-local provider settings without changing global WARP configuration
  or enabling network services.
- **Matching:** Create a reference-to-target session graph with no resolvers and
  never call provider application methods. BN documents that resolvers can transfer
  analysis during a run. See the
  [similarity guide](https://docs.binary.ninja/guide/similarity.html#providers-and-resolvers).
- **Execution:** Run preparation and result extraction outside the UI/network
  loops. Track BN's background completion object and cooperative stop requests.
  Allow one active comparison and four retained comparisons; require explicit
  closure when full. Default deadline: 120 seconds, configurable up to 600 seconds.
- **Lifecycle:** Connect comparisons to workspace invalidation and listener
  shutdown. Edits, reanalysis, rebase, replacement, or closure mark affected
  comparisons stale and request cancellation. Retain native objects until execution
  finishes; cancellation must not free objects still in use. Results are
  process-local and disappear on restart.
- **Results:** Freeze terminal results into immutable records containing both
  functions' coordinates, names, captured generations, provider, and separate
  similarity/confidence scores. Preserve BN's documented `0–255` scores and
  competing candidates. Resolve node/entity references directly; never infer
  correspondence from names or equal RVAs. See the
  [Python API](https://api.binary.ninja/binaryninja.similarity-module.html).
- **Pagination:** Return 100 records by default, maximum 500, with deterministic
  ordering and continuation information. Preserve partial results after
  cancellation or failure. Describe unmatched functions as unmatched under the
  selected providers, without asserting that they were added or removed.
- **Disassembly differences:** Read instruction tokens directly from both BN
  functions and align instruction text using
  `difflib.SequenceMatcher(autojunk=False)`. Exclude each instruction's own address
  from comparison while retaining addresses and RVAs in output. Return
  equal/insert/delete/replace groups, bounded to 2,000 instructions per side, with
  explicit truncation. Label this as a textual comparison; provider scores remain
  independent.
- **Debugging:** Navigate explicitly to the chosen build, then reuse pairing,
  breakpoint, run-to, and runtime-byte tools. Each build retains its own identity
  and RVA. Similarity never substitutes for WinDbg's loaded-module identity checks.

Keep implementation in the companion repository. Update its README, tool golden,
and workflow documentation, plus the integration plan in this repository. No Rust
tool or worker-protocol changes are required.

## Validation and delivery

1. Verify provider discovery, session execution, result references, and cancellation
   in BN6 Ultimate using disposable PE fixtures.
2. Add offline tests for score preservation, competing matches, reversed result
   ownership, unmatched functions, pagination, text differences, and partial results.
3. Test Personal availability reporting, busy analysis, stale generations,
   close/rebase races, cancellation, listener restart, and shutdown. Verify
   comparison leaves names, types, comments, and bytes unchanged.
4. Capture Ultimate results for identical, relocated, changed, and unmatched
   functions; replay immutable captures in ordinary tests.
5. Exercise comparison → target navigation → existing guarded debugger action,
   including wrong-build refusal.
6. Run the companion's pytest, Ruff, transport/golden, and documentation checks.
   Ultimate execution acceptance remains a release requirement; mocks alone do not
   establish it.

## Assumptions and defaults

V1 targets Apple Silicon macOS, BN6/Python 3.13, two open PE views, and agent-readable
differences. Annotation transfer, native visual comparison, arbitrary file loading,
cross-architecture matching, persistent comparison storage, and multi-build corpora
are deferred.
