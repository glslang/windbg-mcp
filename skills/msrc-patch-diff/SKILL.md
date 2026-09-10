---
name: msrc-patch-diff
description: Investigate a Windows CVE through MSRC, acquire verified current and previous stable component binaries for the same Windows product and architecture, and compare them with Binary Ninja Personal and external BinDiff. Use for CVE patch comparisons and similarity acceptance captures.
---

# MSRC patch comparison

Turn a CVE number or MSRC URL into a reproducible comparison: MSRC evidence,
an explicit release pair, verified downloads, paginated similarity results, and a
report separating observed changes from CVE attribution. Use BN6 Personal and the
companion's external BinDiff backend. Ultimate support is tentative and not required.

## Codex model

Use `gpt-daybreak-blue-latest` for this investigation when running under Codex,
unless the user explicitly selects another model. If the current session uses a
different model and model-selecting delegation is available, delegate the CVE
investigation to that exact model, passing the CVE, product, architecture and
existing evidence paths. Otherwise ask the user to select it in Codex before
continuing the investigation. Report unavailable model access rather than silently
substituting another model. Other agent hosts keep their configured model.

For a new Codex CLI session:

```console
codex --model gpt-daybreak-blue-latest '$msrc-patch-diff for CVE-2026-83498 on Windows 11 24H2 ARM64'
```

The skill's UI prompt expresses this preference; it does not change the session
model by itself. [Daybreak Blue](https://developers.openai.com/api/docs/models/gpt-daybreak-blue-latest)
is the selected model for this defensive patch-comparison workflow.

## Establish the comparison

1. Read the MSRC page and retrieve its CVRF record with
   [scripts/evidence.py](scripts/evidence.py). Save source responses and retrieval
   time. Use the exact CVE, product IDs, remediation KBs, fixed builds and revision
   history. A blank JavaScript page is not evidence that a CVE is absent.
2. Use the user's product/version and architecture. Otherwise inspect the connected
   WinDbg target; if it does not identify one affected product, ask which to use.
   Keep client/server editions, servicing branches and architectures distinct.
   Do not infer Windows architecture from the Mac running Binary Ninja.
3. For **current and previous stable**, select the latest generally available
   security or out-of-band update and its preceding non-preview release in that
   product's Microsoft update history, as of the research date. Exclude Insider
   and optional previews. Record KBs, dates, OS builds and source links. File version
   ordering, PE timestamps and index upload dates do not establish release order.
   A component's file version need not equal the OS build.
4. Check whether the pair crosses the fix boundary. If both include the fix, retain
   the requested stable comparison and add the first fixed update versus its last
   applicable stable predecessor. Label the two purposes. MSRC's `Supercedence`
   is a candidate predecessor, not proof of adjacency or an unpatched component.
   Explain intervening previews, backports or ambiguity.
5. Identify filenames from MSRC affected files, Microsoft KB file lists, package
   manifests or component documentation. If MSRC names only a subsystem, label
   inferred files as **candidates**. Changes in a cumulative update do not by
   themselves identify the CVE fix.

Read [references/acquisition.md](references/acquisition.md) for commands, package
fallbacks and the worked CVE-2026-83498 example.

## Acquire evidence

List Winbindex entries for each filename, architecture, exact Windows version and
KB with the helper. Resolve multiple assembly/path candidates before selecting a
SHA-256. Download that entry from Microsoft's symbol server. The helper verifies
the hash, file size and PE identity before publishing the file. Keep reference and
target in separate directories outside the repository, with their metadata and URLs.

Do not substitute another version if an entry is missing. Use Microsoft Update
Catalog packages and file lists, or report the exact missing artifact. Extract
complete PE files; a servicing delta alone is not a DLL. Do not install updates,
load drivers or execute downloaded code as part of acquisition. Record signature
verification separately from Winbindex's signature metadata.

## Compare in Personal

Discover the native Binary Ninja MCP and companion tool schemas; their view IDs
are different. Native MCP opens the downloads in the GUI. Personal's headless API
is not a substitute. Companion `list_binaries` identifies the views by path, PE
identity and hash. Finish analysis with `wait_for_analysis` for each companion ID.

Check `similarity_status` for the optional ABI-compatible export helper and
user-installed BinDiff. Follow the companion's setup if either is missing; do not
switch to Ultimate or install BinDiff implicitly.

- Record capabilities, input identities, hashes and generations. For acceptance,
  also capture function names/types/comments, defined types and analysis bytes
  before and after, using native BN APIs as needed. Generations alone do not prove
  every analysis property stayed unchanged.
- Start with the older build as `reference_binary_id`, newer as `target_binary_id`,
  `backend: "external"`, and `providers: ["Google BinDiff"]`. Poll until inactive;
  comparison timeout ends before report downloading.
- Page all matches and both unmatched lists until `next_offset` is null. Retain
  coverage, omitted/unresolved counts, scores and both endpoints. Cancelled or
  partial results remain partial evidence.
- Inspect changed matches with `similarity_diff` and page each selected diff fully.
  Prefer score changes and functions relevant to the candidate component. Neither
  a high score proves equivalence nor a low score proves CVE relevance. Reuse the
  companion's `tools/similarity_capture.py` when its authenticated connection file
  is available; use direct MCP calls otherwise. Keep tokens out of reports/output.
- Navigate to a target endpoint with its coordinate and `expected_generation`.
  Save the navigation result. Close comparisons owned by this run in cleanup;
  preserve unrelated views, comparisons and sessions.

## Acceptance and report

Write `report.md` and a JSON manifest beside raw MSRC records, release evidence,
download manifests and comparison captures. Include reproducible commands, backend
versions, changed-function coordinates and limitations. Treat observed text/control
flow changes as candidates until independently tied to the CVE.

Record each acceptance item as `passed`, `failed`, `not_run` or `tentative`, with
artifact paths. Creating the skill or downloading files does not pass comparison
acceptance. A real GUI run can pass acquisition, comparison, unchanged-analysis and
navigation checks only when those observations were captured.

For live handoff, use an existing disposable WinDbg session and a loaded module
matching the selected build. Navigate to the target match, then use guarded
`read_memory` with its coordinate or paired `compare_runtime_bytes`. Repeat a read
with the other build's mismatched identity and record the refusal. This validates
the read-only handoff; breakpoint/run-to acceptance needs its own authorized run.
A CVE comparison does not authorize loading the candidate driver, resuming a target
or creating an exploit trigger. If no suitable module/session is available, keep
live handoff `not_run` and complete the static report.

Cancellation, edit/rebase/close races, restart and quit while active are separate
opt-in checks on disposable views. A completed diff does not pass them. Native
Ultimate acceptance stays `tentative` unless an actual run becomes available;
do not make purchasing it a prerequisite.
