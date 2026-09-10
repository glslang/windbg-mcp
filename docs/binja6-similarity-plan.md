# BN6 similarity in the Binary Ninja–WinDbg companion

Status: revised and implemented 2026-09-08 in the companion. Personal GUI exports,
real external BinDiff comparisons, textual differences, and target navigation passed
on synthetic identical, relocated and changed PE fixtures. The changed fixture's
additional function was reported unmatched. Names, types, comments, bytes,
generations, identities and modification flags stayed unchanged.

The helper built on Apple Silicon against BN6 ABI 187. Personal capture and
reproduction instructions are in the companion's `docs/similarity.md`. Native
Ultimate execution remains unvalidated and tentative: Ultimate is unavailable due
to cost, and purchasing it is not a requirement for Personal delivery. The live
similarity-to-WinDbg operation remains a separate acceptance check.

## Summary

Extend `binja-windbg-mcp` with optional Personal and Ultimate backends comparing two open
Windows PE views or BNDBs. Support BinDiff structural matching, WARP exact matching,
agent-readable disassembly differences, and navigation into the existing debugging
workflow.

Personal automatically exports views inside the running GUI and invokes a
user-installed external BinDiff. Ultimate retains the native Python similarity
API with BinDiff and WARP. Native similarity requires Ultimate. See the
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

Add `backend="auto" | "native" | "external"` to `similarity_start`. With omitted
providers, auto prefers native BinDiff plus WARP when both are available; otherwise
it selects external BinDiff. Explicit providers must all be supported by one
backend, preferring native under auto. Explicit external WARP is unavailable.
Never switch backends after execution begins.

Status reports availability, versions, providers, and setup errors separately for
each backend. Status and results record backend provenance. Local optional
`similarity.bindiff_path` takes precedence over PATH discovery; do not download or
install BinDiff automatically.

Extend existing `navigate` with an optional expected generation, reusing the
adapter's existing generation check. Similarity results supply the coordinate and
generation for either side.

## External backend implementation

- Build a small helper from pinned open-source BinExport and the BN6 public SDK.
  Expose a versioned C interface accepting an existing BinaryView and an explicit
  destination, returning export metadata or an error. Package an Apple Silicon
  build, reproducible build instructions, and required license notices.
- Run inside Personal's GUI process on the comparison background thread. Serialize
  exports, retain view ownership, validate ABI compatibility, and propagate write
  failures. Do not invoke save dialogs or launch BN headlessly. See the
  [BinExport source](https://github.com/google/binexport/blob/main/binaryninja/main_plugin.cc).
- Use private temporary files per job. Capture generations, identities, image
  bases, function inventories, export metadata and hashes. Check both generations
  before and after export and before publishing results.
- Invoke external BinDiff using an argument array, explicit primary/reference and
  secondary/target exports, output directory, binary format, and disabled UI.
  Target the [BinDiff 8 CLI](https://github.com/google/bindiff/blob/v8/main_portable.cc).
- Read completed `.BinDiff` output using read-only SQLite. Validate schema and input
  ownership. Map addresses directly to captured functions, recovering unsigned
  64-bit addresses. Preserve raw similarity/confidence and map validated `0–1`
  scores to existing `0–255` fields using `floor(score * 255 + 0.5)`.
- Derive unmatched from exported eligible functions. Report omitted and unresolved
  functions separately; missing export coverage must not imply unmatched functions.
- Report export, matching and import stages without invented percentages. Bound
  retained stdout/stderr. Cancel, timeout, invalidation and shutdown terminate only
  the owned process group, escalate if necessary, and reap before deleting files.
- Export cancellation is cooperative: retain views until the in-process exporter
  returns. Never read an interrupted database; preserve only validated partial
  records. Neither backend transfers annotations or changes analysis.

## Shared and native implementation

- **Inputs and providers:** Require two distinct, analyzed PE views of the same
  architecture. Use existing companion IDs, metadata, hashes, and generation stamps.
  Default providers depend on the selected backend; report unavailable providers explicitly.
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

1. Validate GUI export and external BinDiff on BN6 Personal using disposable PE
   fixtures. Native provider discovery, sessions and cancellation stay tentative
   until an Ultimate installation is available; they do not gate Personal delivery.
2. Add offline tests for score preservation, competing matches, reversed result
   ownership, unmatched functions, pagination, text differences, and partial results.
3. Test backend selection, missing/incompatible dependencies, exporter failures,
   corrupt SQLite, input ownership, high addresses, score conversion, omitted
   functions, paths with spaces, process cleanup, busy analysis, stale generations,
   close/rebase races, cancellation, listener restart, and shutdown. Verify
   comparison leaves names, types, comments, and bytes unchanged.
4. Adapt the capture runner to select backend/providers. Capture Personal results for identical, relocated, changed, and unmatched
   functions; replay immutable captures in ordinary tests.
5. Exercise comparison → target navigation → existing guarded debugger action,
   including wrong-build refusal.
6. Run the companion's pytest, Ruff, transport/golden, and documentation checks.
   Build/check the helper and update existing PR descriptions. Personal release
   requires real GUI export and BinDiff execution; mocks alone do not establish it.
   Track Ultimate acceptance as tentative, independently of Personal delivery.

### CVE-driven Personal acceptance

The [MSRC patch-diff skill](../skills/msrc-patch-diff/SKILL.md) accepts a CVE,
resolves a specific Windows product and architecture, records the current and
previous non-preview releases, and acquires exact component binaries for external
BinDiff. If both stable releases contain the fix, also compare the first fixed
release with its applicable predecessor. Preserve MSRC/KB evidence, file hashes,
PE identities and backend provenance; inferred component filenames remain candidates.

Use a real run to extend the synthetic fixture acceptance with Windows component
comparisons, unchanged-analysis checks and target navigation. Record each result
with its capture; creating the skill or downloading binaries alone closes none of
those checks. A suitable disposable WinDbg session can additionally validate the
guarded read-only handoff and wrong-build refusal. Breakpoint/run-to and active
cancellation/edit/rebase/close/quit checks still require their own recorded runs.
Without a suitable loaded module, keep live handoff pending. Native Ultimate
acceptance remains tentative.

The [2026-09-09 CVE-driven capture](cve-patch-diff-acceptance.md) passed exact
acquisition, a 525-match Personal comparison, unchanged analysis and target
navigation on a real Windows component candidate. It did not identify the CVE fix
or close live handoff/active-lifecycle acceptance.
Its ARM64 follow-up recorded a partial secure-kernel comparison and a complete
519-match vertdll comparison. Both preserved analysis hashes and navigated to the
target, but failed strict generation stability; these captures do not close full
ARM64 acceptance.

The 2026-09-10 follow-up resolved generation stability by preparing the selected
target UI location and finishing lazy analysis before the capture baseline.
Both reruns preserved strict generations and analysis; vertdll passed full
acceptance. Securekernel remains partial because eight function starts per side
lack exported flow-graph entries, accounting for all eight unresolved BinDiff rows.
Full coverage would require further exporter investigation; the guards remain
unchanged. The captures and exact omissions are in the
[follow-up acceptance record](cve-patch-diff-acceptance.md#arm64-generation-follow-up--2026-09-10).

## Assumptions and defaults

V1 targets Apple Silicon macOS, BN6/Python 3.13, two open PE views, and agent-readable
differences. Annotation transfer, native visual comparison, arbitrary file loading,
cross-architecture matching, persistent comparison storage, and multi-build corpora
are deferred.
