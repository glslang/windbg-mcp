# Implementation plan for follow-ups 61–65

The later user decision for item 63 is implemented: a companion-maintained native
replacement passes decoding, IL and full comparison acceptance. See the
[closure evidence](clrbhb-native-validation.md#companion-maintained-replacement--accepted).
The original plan below is retained as written.

## Scope and starting point

Prepared 2026-09-15 from [follow-ups 61–65](../FOLLOWUPS.md#61-windbg-mcp-attribute-the-cve-2026-83498-fix-independently-of-similarity-scores)
and their retained acceptance evidence. The investigation and runnable capture
tooling are now implemented; see [implementation results](followups-validation.md)
for measured outcomes and remaining closure conditions. The sections below retain
the intended work and acceptance criteria.

Personal/external BinDiff delivery is already accepted. These follow-ups add CVE
attribution, a specific live handoff, and upstream/backend validation. Implement
capture tooling first and change production code only where a reproduced failure
requires it. Preserve the dated captures and append new evidence.

| Item | Work and ownership | Completion dependency |
|---|---|---|
| 61 | CVE attribution investigation; evidence in this repository | A defensible link between changed behavior and the applicable CVE fix boundary |
| 62 | Read-only Secure Kernel handoff probe; this repository and companion | An existing disposable, paused session exposing the exact selected Secure Kernel image |
| 63 | Native decoder/analysis validation; Binary Ninja upstream and companion regression coverage | An upstream build decoding CLRBHB correctly |
| 64 | Isolated shutdown reproduction; upstream fix and local capture harness | An upstream fix passing the original wizard scenario and active-work checks |
| 65 | Conditional native backend validation; companion | Appropriate Ultimate access without purchase and a decision to run validation |

Upstream status checked through the GitHub API on 2026-09-15:
[issue #8549](https://github.com/Vector35/binaryninja-api/issues/8549) is open,
last updated 2026-09-11, with no comments identifying a fixed build. Searching
that repository's issues for `CLRBHB` returned no matches; this does not establish
whether its decoder source or a released build already supports the instruction.
Item 63 therefore starts with source/build verification.

## Sequence and delivery units

1. **Baseline and capture contracts:** verify input hashes and tool revisions,
   refresh upstream status, and define the per-check evidence manifest below.
2. **Item 63:** build a native decoding probe and test available upstream builds.
   Better instruction text helps item 61; lack of a decoder fix does not block
   inspection of retained bytes and other decoded functions.
3. **Item 61:** investigate the existing ARM64 release pair and candidate components,
   adding acquisitions only when release or component evidence requires them.
4. **Item 62:** implement and offline-test the read-only probe, then run it if the
   required session exists. It can complete independently of CVE attribution.
5. **Item 64:** prepare the isolated reproduction and validate a fixed build when
   available. Run GUI experiments sequentially, one owned process at a time.
6. **Item 65:** retain a conditional checklist; run it only when access is available.
   This planning request includes the item but does not imply purchasing Ultimate.

Acceptance harnesses landed under this repository's `tools/` beside their evidence;
no companion production change was needed. Any later companion changes belong in
its own repository. A capture harness can ship while its live/upstream acceptance remains
`not_run`. Move an item to `DONE.md` only when its stated closure evidence exists.

## 61 — Attribute the CVE fix

Follow the [MSRC patch-diff skill](../skills/msrc-patch-diff/SKILL.md). The execution
phase delegates the CVE investigation to `gpt-daybreak-blue-latest`, as that skill
requires, with the product, architecture, CVE and existing evidence paths. Planning
does not require starting that investigation.

1. Refresh MSRC/CVRF revision history, affected product IDs, remediation and release
   sources. Begin with the recorded Windows 11 24H2 ARM64 pair; independently
   re-establish that it crosses the fix boundary. Keep any newly requested
   current/previous stable comparison separate if both builds already contain the fix.
2. Reverify hashes and PE identities against
   [the acquisition and comparison record](cve-patch-diff-acceptance.md).
   Review `securekernel.exe`, `vertdll.dll`, `iumdll.dll` and `iumbase.dll` as
   candidates. Keep the x64 vertdll control separate from the ARM64 observations.
3. Build a candidate-change table from all retained matches and unmatched entries,
   covering executable sections outside ordinary matched functions and relevant
   data changes. Include the unexplained ARM64 vertdll `fothk` changes. Prioritize
   relevant behavior and call context; scores alone do not establish relevance.
4. For each serious candidate, record reference/target coordinates, exact bytes,
   instruction or IL evidence, callers, changed conditions and expected effects.
   Test alternative explanations such as unrelated cumulative fixes, compiler
   changes and metadata changes. Compare nearby releases or related architectures
   only where that comparison can discriminate between explanations.
5. Write `docs/cve-2026-83498-attribution.md` and a sanitized sample manifest with
   source links, retrieval dates and hashes. Separate observed facts, supported
   inference, authoritative confirmation and unresolved alternatives.

Reuse `skills/msrc-patch-diff/scripts/evidence.py`, `gui_capture.py`, and the
companion's `tools/similarity_capture.py`. No exploit trigger is required. Close
61 only when independent evidence ties a specific component and behavior change
across the fix boundary to the CVE; label inferred attribution explicitly.
If evidence remains ambiguous, deliver the investigation and keep 61 open.

## 62 — Capture a read-only live Secure Kernel handoff

Add a maintained `tools/securekernel_handoff_probe.py` accepting an explicit
session ID, companion binary ID, selected match and private connection configuration.
Reuse the reporting patterns from
[the generic handoff](similarity-windbg-acceptance.md), but implement separate
session ownership and cleanup logic: its existing fixture probe launches, resumes
and ends an owned debuggee.

1. Discover schemas and inspect session status, execution state and loaded-module
   identity. Require a paused disposable session that actually exposes Secure
   Kernel, plus matching architecture, image identity and a valid target RVA.
   An ordinary NT kernel connection alone does not prove VTL1 access.
2. Capture the selected comparison endpoint and generation, navigate to it, and
   issue a bounded guarded `read_memory` or paired `compare_runtime_bytes`.
   Record requested and returned bytes, partial reads, differences and relocation
   overlaps without automatically attributing differences to a fix or hotpatch.
3. Repeat the read with the other build's identity and retain the structured
   identity-mismatch refusal. Ensure the refusal is distinguishable from an
   unrelated transport, running-target or memory-read failure.
4. Verify the selected session remains paused at the same instruction/context,
   session IDs remain present, and debugger breakpoints were not changed. Close
   only pairings/comparisons/connections created by the probe. Never end the
   pre-existing debugger session, including on capture or cleanup failure.

Offline tests must reject running/mismatched sessions before the read, verify
wrong-build refusal classification, and inject cleanup failures without losing
the original failure. A recording client should reject any launch, resume,
breakpoint, run-to or session-teardown call from this probe.

Deliver `docs/securekernel-handoff-acceptance.md` and sanitized JSON. If no suitable
session exists, record the missing prerequisite and leave live acceptance
`not_run`. The separate local `docs/secure-kernel-debugging-plan.md` proposes an
x64 lab and full execution tests; it remains a separate setup project. An x64
lab requires its own x64 selected binaries and comparison, rather than reusing
ARM64 coordinates. Breakpoint/step/resume validation is separate from closing 62.

## 63 — Verify native CLRBHB decoding and analysis

First check upstream issues, release notes and the architecture source for a fix;
pin the tested build and matching SDK/API revision. If no fix exists, prepare a
minimal reproduction and proposed regression locally for upstream review.

Add a GUI-native probe, proposed as companion `tools/clrbhb_decode_probe.py`, with:

- Exact `df2203d5` bytes in an aligned AArch64 synthetic function followed by
  ordinary instructions and a return; retain instruction text, instruction length,
  fallthrough, basic-block boundaries and IL observations.
- The sixteen affected endpoints from the retained Secure Kernel pair: all eight
  reference and target `FrontendBhbClrKiUser*Handler` entries. Inspect fresh analysis
  for truncation and compare function boundaries against actual surrounding code.
- A new full external comparison and paginated textual diffs for those entries,
  with before/after analysis state captured separately for each tested BN version.
  Version-to-version analysis changes are expected evidence, not mutation during a run.

Keep companion `native/binexport/clrbhb.h`, `processor.cpp` and their exact-encoding
fallback for older supported versions. Preserve `clrbhb_test.cpp` coverage of
wrong architecture, alignment, short input and adjacent HINT encodings. Test that
native successful decoding takes precedence and unknown instructions remain honest
omissions. Do not claim that a fallthrough/no-op IL representation models the
instruction's microarchitectural security effect.

Close 63 with native CLRBHB text, valid instruction information, inspected function
analysis and comparison evidence. Exported fallback bytes alone cannot close it.
Record the first verified upstream version in
[the export follow-up](secure-kernel/securekernel-export-followup.md).

## 64 — Verify the FirstSetupDialog shutdown fix

Use [the shutdown investigation](bn-shutdown-investigation.md) as the reproduction
specification. Add a maintained isolated launcher/probe with explicit scenarios
and actual child-exit/crash-report capture. Record the upstream fix/build reference.

Run one disposable GUI at a time, using a fresh user directory and QSettings suffix:

1. Original application Quit action with `FirstSetupDialog` still active and no
   companion or input files. The validation probe deliberately exercises this
   scenario; ordinary capture helpers retain their modal guards.
2. Wizard-disabled empty control.
3. Companion shutdown during confirmed active native export.
4. Companion shutdown during confirmed active external matching.
5. Existing modal-guard refusal and post-dismissal quit regression.

Record application exit status, signal/crash report, `aboutToQuit`, active-work
observations, thread/process cleanup and temporary-file cleanup. Check the direct
Qt-quit lingering behavior separately from the application-action crash. Forced
termination or a debugger launcher's zero exit code is not normal-exit evidence.

Reuse the lifecycle probe and its cleanup-failure tests where appropriate. Keep
normal profiles and the installed application bundle untouched. Close 64 only
with an upstream fix and normal exit in the original scenario plus active-work
checks; retain startup/quit guards for older supported versions.

## 65 — Conditional Ultimate validation

When suitable Ultimate access exists, record the installation/version and run the
companion's real native adapter through the existing similarity tools:

- Provider discovery and explicit `backend: "native"`; BinDiff, WARP and the
  supported combined selection. Retain backend/provider provenance in each capture.
- Identical, relocated and changed fixtures; all matches, unmatched pages and
  diffs; unchanged names, types, comments and bytes during each run.
- Cancellation, deadline, edit/rebase/close invalidation, listener restart and quit
  during active work. Verify native objects remain alive until work finishes and
  resources are released afterward.
- Backend-selection regressions, including unavailable providers and no switch
  to external execution after a native run begins.

Start in companion `similarity_adapter.py`, `similarity_backends.py`,
`tests/test_similarity.py` and its capture tooling. Fix only reproduced adapter
defects. Publish a versioned native acceptance record in the companion and link
it from [the similarity plan](binja6-similarity-plan.md). Without real execution,
keep Ultimate tentative and 65 deferred; test doubles do not close it.

## Evidence and validation gates

Each new manifest records item/check IDs; `passed`, `failed`, `not_run` or
`tentative`; reason; UTC capture time; repository and tool revisions; architecture;
input hashes and PE identities; source/capture paths and hashes; and cleanup outcomes.
Keep raw evidence locally and sanitized publishable captures under `docs/samples/`.
Do not include downloaded PEs, credentials, kernel keys or machine-specific profiles.

Run the focused Python tests for each changed helper and the companion tests for
changed adapter/export behavior. Run native fallback tests for exporter changes.
GUI and live checks remain explicit acceptance gates; offline tests do not replace them.

For documentation, run `cargo fmt --all --check` and the repository's markdownlint
command. If a demonstrated gap requires Rust or public tool changes, run Windows
`cargo test`, `cargo clippy --all-targets`, protocol smoke and the appropriate
explicitly enabled debugger tier; update surface goldens for schema changes.
Keep DbgEng on the worker engine thread and implement new primitives in typed
`dbgscope` APIs. No new Rust tool or DbgEng primitive is assumed by this plan.
