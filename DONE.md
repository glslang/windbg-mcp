# Done

Follow-ups that have landed, moved out of [`FOLLOWUPS.md`](./FOLLOWUPS.md) so that file holds only
work that is still open. **An item keeps the number it was filed under**, wherever it lives:
`CLAUDE.md`, `CHANGELOG.md`, `docs/*.md`, `.github/workflows/ci.yml` and `build.rs` all cite items
as "`FOLLOWUPS.md` item N", and renumbering would break every one of those references silently —
they are prose, so nothing would fail. The numbers here are therefore sparse, and gaps are items still
open in `FOLLOWUPS.md` rather than items deleted.

**Entries are kept in full rather than reduced to a line**, because in this repo the durable half of
a finished item is usually the part its own proposal got wrong. Each says what it was filed for,
what actually landed, and what building it disproved — which is what the next change to that seam
meets first.

Two kinds of entry are *not* here. An item that is **measured and declined** stays in
`FOLLOWUPS.md` — nothing was built, and each carries the condition that would reopen it — and
so does one that has only **half** landed, its entry narrowed to the half that is left rather
than split in two. **Which items those are is marked on the lines of
[`FOLLOWUPS.md`](./FOLLOWUPS.md)'s index**, and deliberately not listed again here: this
paragraph used to carry its own copy of both lists, and by the time the index was written that
copy was three items behind — it named 27 and 35 where the first class now has 100 as well, and
50 alone where the second has 2 and 108 with it.

A third kind *is* here and is neither: an item **deleted unbuilt** (76), where the thing it
described stopped existing before anyone built it. It keeps its number and its entry because the
number was committed and cited before that happened, and because why a filed item evaporated is
worth as much as why one landed.

**A shipped capability is not by itself a closed item**, and item 103 is the worked example — now a
complete one, which is why it is worth reading before closing anything here. Its four Secure Kernel
capture tools were built, tested and verified live while the item stayed **open** for another five
days, because attempts its own plan named had not been made. What decided the move was not the
deliverable: it was making those attempts and finding out which *route* the remaining ones belonged
to. Two of the four landed as **retractions of that entry's own claims**, which is the outcome an
unmade attempt most often has. Two drafts of its status got the close wrong first — one closed it on
the strength of the tools, one recast an already-agreed constraint as a refusal — and both are kept
in the entry. **An attempt nobody has ruled out is not refusable just because a deliverable exists**;
what it takes to decline one is a measurement that puts it on a route nothing needs, plus the
condition that would put it back.

## Why each of these is worth reading after it landed

**Item 10** (process-per-session, 2026-08-02) is here because items 8 and 9 were both written
against the single-engine design it replaced, and each now says what moved. **Items 16, 17 and 18**
(2026-08-10) are here for the opposite reason: each turned out to need something its entry did not
anticipate — item 18 needed much less of item 7 than it claimed to, item 17 needed a walk deadline
nothing had asked for, and item 16 needed a probe before it could measure anything at all.
**Items 25 and 26** (2026-08-21, #153 and #154) each rest on something that was not so: item 25's
premise about what Windows ships was only true on one of the two runner images, and item 26's "one
decision first" was the wrong decision to be weighing. **Items 20 and 22** (2026-08-16, #131
and #134) each needed something its entry did not see — item 22's job rename silently removed a
required status check, and item 20's fix met two installers that spell x64 differently, so the
reordering it proposed would have picked the wrong architecture by another route. **Item 7** (2026-08-10, the
`interrupt` tool) is what item 8 rests on: what it built is the job binding, and what it deliberately
did not build is the queued-job half that only `tasks/cancel` can ask for. **Item 12** (2026-08-02)
is here because what validating it *disproved* outlives what it confirmed: a kernel attach whose
target never dials in has no bound at all, which is the constraint item 10 contains. **Item 14**
(2026-08-31) is the one nobody built: what it asked for landed upstream six days earlier as a side
effect of an unrelated fix, and closing it here meant re-reading a `DECISIONS.md` Status line whose
revisit trigger had already fired. It is worth reading for what that cost — the measurement
justifying the decision was `#[ignore]`d, so it went on passing while its own subject disappeared. **Item 42**
(2026-08-24) is here because what it built is the capability to repeat a cell and what it
deliberately did *not* run is the A/B that motivated it — plus one of its own sentences turned out
to be false on this bench, which the entry now records. **Item 44** (2026-08-25)
did not ship its own proposed wording: closing the reading it identified needed the prompt to say
what the answer is *not*, which is a judgement nothing has measured, and the entry records what would
settle it. **Item 45** (2026-08-25) needed three things that are not in the entry that proposed it:
`expect` turned out not to be *derivable* from a binding — two of one task's groups are phrasings of
a relation rather than strings the server prints — a tool with no structured half needed a second
verb, and the ratchet is the coverage rule rather than any pin. **Item 46** (2026-08-25) records the
decision it deferred: this server *does* report a build revision, stamped by a `build.rs` whose watch
list and dirty check have to be one list or they disagree — which is the sort of thing an entry
proposing "record a build SHA" cannot see from where it is written. **Item 49** (2026-08-27) is here
for two reasons, one per half: the thing it was filed to design turned out to be the thing to delete,
and the plan written for what that left over was right about every seam and wrong about the fixture's
writer. **Item 51** (2026-08-28) had its account of *why* the process died wrong in the one way that
mattered: it blamed the worker's termination, a step later than the passive `EndSession` that
actually does it — which is what let the fix be tested inside one process at all. It also records two
probes for that fact which look correct and are not, one of which passed with the fix backed out.
**Item 80** (2026-09-25) is here because its proposal was right about the fix and wrong about the
result: it asked for a per-field backend test to be *deleted*, and a grader that still has to read
logs written before the change can only freeze one — the deletion is real on the path that grows and
impossible on the path that cannot. Building it also moved three published identity lines nobody had
filed, each an overclaim the old rendering made by choosing between two spellings of "no answer" per
backend. **Item 81** (2026-09-25) is here because the instruction it left for whoever closed it was
written for a different one of the three shapes it weighed: flip two assertions to `assert!`,
which is right if you parse the command language and wrong if you read the target instead — and
reading the target is the shape it called the only sound one. It also records the primitive that
reads as though it already answered the question and does not (`dbgscope`'s `target_identity`),
and the one case that looks identical to a replacement and must not be treated as one. **Item 102**
(2026-09-26) is here for a measurement that contradicts its own example: the command every draft of
it used to illustrate a replacement, a wrapped `.opendump`, turns out not to make one on this
engine — it adds a target and leaves the current one alone. The entry records what does.

## What is in here

- [Item 1](#1-dbgscope-managed-breakpoint-lifecycle-for-run_to_address--done-upstream) — [dbgscope] Managed breakpoint lifecycle for `run_to_address` — done upstream
- [Item 7](#7-dbgscope--windbg-mcp-on-demand-engine-interrupt--done-2026-08-10) — [dbgscope + windbg-mcp] On-demand engine interrupt — done (2026-08-10)
- [Item 10](#10-windbg-mcp-process-per-session--done-2026-08-02-issue-61) — [windbg-mcp] Process-per-session — done (2026-08-02, issue #61)
- [Item 12](#12-dbgscope-validate-the-opener-split-against-a-live-kdnet-target--done-2026-08-02) — [dbgscope] Validate the opener split against a live KDNET target — done (2026-08-02)
- [Item 13](#13-windbg-mcp-a-job-level-deadline-for-reachable_from_dispatch--done-2026-09-10-296) — [windbg-mcp] A job-level deadline for `reachable_from_dispatch` — done (2026-09-10, #296)
- [Item 14](#14-dbgscope-make-arming-the-bounded-watchdog-free--done-2026-08-25-upstream-2026-08-31-here) — [dbgscope] Make arming the bounded watchdog ~free — done (2026-08-25 upstream, 2026-08-31 here)
- [Item 16](#16-windbg-mcp-exercise-a-mutating-debug_batch-against-a-live-kernel-target--done) — [windbg-mcp] Exercise a *mutating* `debug_batch` against a live kernel target — done
- [Item 17](#17-windbg-mcp-let-a-debug_batch-step-call-a-typed-tool-starting-with-the-pool-queries--done) — [windbg-mcp] Let a `debug_batch` step call a typed tool, starting with the pool queries — done
- [Item 18](#18-windbg-mcp-let-a-running-batch-finish-its-rollback-when-the-client-disconnects--done) — [windbg-mcp] Let a running batch finish its rollback when the client disconnects — done
- [Item 20](#20-windbg-mcp-pick-the-ttd-recorder-by-architecture-not-by-a-fixed-list--done-2026-08-16-131) — [windbg-mcp] Pick the TTD recorder by architecture, not by a fixed list — done (2026-08-16, #131)
- [Item 21](#21-windbg-mcp-ttd-replay-on-a-host-where-the-store-package-will-not-install--done-2026-08-29-132) — [windbg-mcp] TTD replay on a host where the store package will not install — done (2026-08-29, #132)
- [Item 22](#22-windbg-mcp-run-the-debugger-tier-on-an-arm64-runner--done-2026-08-16-134) — [windbg-mcp] Run the debugger tier on an ARM64 runner — done (2026-08-16, #134)
- [Item 23](#23-windbg-mcp-the-listener-is-transport-complete-not-usable-complete--done-2026-08-17) — [windbg-mcp] The listener is transport-complete, not usable-complete — done (2026-08-17)
- [Item 24](#24-windbg-mcp-spend-fewer-of-the-callers-tokens--done-2026-08-22) — [windbg-mcp] Spend fewer of the caller's tokens — done (2026-08-22)
- [Item 25](#25-windbg-mcp-the-arm64-ci-runner-resolves-no-symbols-so-its-target-reads-never-run--done-2026-08-21-153) — [windbg-mcp] The ARM64 CI runner resolves no symbols, so its target reads never run — done (2026-08-21, #153)
- [Item 26](#26-windbg-mcp-no-arm64-driver-crash-so-frame-attribution-is-asserted-only-on-x64-stacks--done-2026-08-21-154) — [windbg-mcp] No ARM64 driver crash, so frame attribution is asserted only on x64 stacks — done (2026-08-21, #154)
- [Item 28](#28-windbg-mcp-the-tenancy-gate-no-longer-earned-its-place--done-2026-08-20) — [windbg-mcp] The tenancy gate no longer earned its place — done (2026-08-20)
- [Item 29](#29-windbg-mcp-the-listener-smoke-tier-only-ever-runs-one-unnamed-client--done-2026-08-20) — [windbg-mcp] The listener smoke tier only ever runs one, unnamed client — done (2026-08-20)
- [Item 30](#30-windbg-mcp-nothing-covers-a-2026-07-28-handshake-that-omits-the-protocol-header--done-2026-08-20) — [windbg-mcp] Nothing covers a `2026-07-28` handshake that omits the protocol header — done (2026-08-20)
- [Item 31](#31-windbg-mcp-a-service-hosted-listener-can-hold-only-one-client--done-2026-08-20) — [windbg-mcp] A service-hosted listener can hold only one client — done (2026-08-20)
- [Item 34](#34-windbg-mcp-a-service-hosted-listeners-clients-are-fixed-at-install-time--done-2026-08-22) — [windbg-mcp] A service-hosted listener's clients are fixed at install time — done (2026-08-22)
- [Item 36](#36-windbg-mcp-the-tool-surface-is-server-wide-not-per-caller--done-2026-08-22) — [windbg-mcp] The tool surface is server-wide, not per caller — done (2026-08-22)
- [Item 37](#37-windbg-mcp-the-credential-file-has-four-writers-and-no-reader--done-2026-08-23) — [windbg-mcp] The credential file has four writers and no reader — done (2026-08-23)
- [Item 38](#38-windbg-mcp-a-client-command-can-write-a-file-the-installed-service-cannot-read--done-2026-08-23) — [windbg-mcp] A client command can write a file the installed service cannot read — done (2026-08-23)
- [Item 40](#40-windbg-mcp---tools-narrows-the-tool-list-and-not-the-instructions--done-2026-08-23) — [windbg-mcp] `--tools` narrows the tool list and not the instructions — done (2026-08-23)
- [Item 41](#41-windbg-mcp-a-served-tools-description-advertises-tools-the-client-is-not-served--done-2026-08-24) — [windbg-mcp] A served tool's description advertises tools the client is not served — done (2026-08-24)
- [Item 42](#42-windbg-mcp-the-eval-cannot-tell-a-cause-from-a-coincidence-because-n1--done-2026-08-24) — [windbg-mcp] The eval cannot tell a cause from a coincidence, because n=1 — done (2026-08-24)
- [Item 43](#43-windbg-mcp-unserved-is-two-different-measurements-sharing-a-column--done-2026-08-25) — [windbg-mcp] `unserved` is two different measurements sharing a column — done (2026-08-25)
- [Item 44](#44-windbg-mcp-arm64_pc-is-answered-the-way-it-reads-not-the-way-it-is-keyed--done-2026-08-25) — [windbg-mcp] `arm64_pc` is answered the way it reads, not the way it is keyed — done (2026-08-25)
- [Item 45](#45-windbg-mcp-the-evals-answer-key-is-a-snapshot-and-nothing-checks-it-still-holds--done-2026-08-25) — [windbg-mcp] The eval's answer key is a snapshot, and nothing checks it still holds — done (2026-08-25)
- [Item 46](#46-windbg-mcp-a-run-can-be-graded-but-not-compared-because-nothing-records-what-it-ran-against--done-2026-08-25) — [windbg-mcp] A run can be graded but not compared, because nothing records what it ran against — done (2026-08-25)
- [Item 48](#48-dbgscope--windbg-mcp-a-target-that-exits-during-a-go-is-reported-as-a-catastrophic-failure--landed-2026-08-26) — [dbgscope + windbg-mcp] A target that exits during a `go` is reported as a catastrophic failure — landed (2026-08-26)
- [Item 49](#49-windbg-mcp-the-x86-engine-host-is-gone--a-worker-of-the-targets-architecture-replaced-it--done-2026-08-26-to-27) — [windbg-mcp] The x86 engine host is gone — a worker of the target's architecture replaced it — done (2026-08-26 to 27)
- [Item 51](#51-windbg-mcp--dbgscope-end_session-on-a-user-mode-attach-kills-the-process-it-attached-to--done-2026-08-28) — [windbg-mcp + dbgscope] `end_session` on a user-mode attach kills the process it attached to — done (2026-08-28)
- [Item 55](#55-windbg-mcp-a-retired-handle-cannot-release-its-own-session--done-2026-08-31) — [windbg-mcp] A retired handle cannot release its own session — done (2026-08-31)
- [Item 57](#57-windbg-mcp-ioctl_trace-installs-a-breakpoint-and-reports-nothing-about-it--done-2026-09-02) — [windbg-mcp] `ioctl_trace` installs a breakpoint and reports nothing about it — done (2026-09-02)
- [Item 60](#60-windbg-mcp-structured-dispatch-reachability-paths-for-the-binary-ninja-bridge--done-2026-09-10) — [windbg-mcp] Structured dispatch reachability paths for the Binary Ninja bridge — done (2026-09-10)
- [Item 63](#63-binja-windbg-mcp-decode-aarch64-clrbhb-in-instruction-text-and-analysis--done-locally-2026-09-15) — [binja-windbg-mcp] Native CLRBHB decoding and analysis — done locally (2026-09-15)
- [Item 70](#70-dbgscope-a-path-component-is-matched-by-folding-ascii--done-2026-09-14) — [dbgscope] A path component is matched by folding ASCII — done (2026-09-14)
- [Item 75](#75-dbgscope--windbg-mcp-an-instructions-operands-are-not-every-register-it-reads--done-2026-09-14) — [dbgscope + windbg-mcp] An instruction's operands are not every register it reads — done (2026-09-14)
- [Item 76](#76-dbgscope-a-fold-that-cannot-decide-one-code-unit-declines-the-whole-comparison--deleted-unbuilt-2026-09-14) — [dbgscope] A fold that cannot decide one code unit declines the whole comparison — deleted unbuilt (2026-09-14)
- [Item 77](#77-dbgscope-the-fold-is-the-hosts-upcase-table-not-the-targets--done-2026-09-15-dbgscope162) — [dbgscope] The fold is the *host's* upcase table, not the target's — done (2026-09-15, dbgscope#162)
- [Item 78](#78-dbgscope-the-vs-allocator-layout-moved-again-and-the-pool-walker-refuses-the-build--done-2026-09-15-dbgscope167) — [dbgscope] The VS allocator layout moved again, and the pool walker refuses the build — done (2026-09-15, dbgscope#167)
- [Item 86](#86-windbg-mcp-a-pool-walk-test-caps-the-whole-server-including-the-open-it-needs-first--done-2026-09-19) — [windbg-mcp] A pool-walk test caps the whole server, including the open it needs first — done (2026-09-19)
- [Item 82](#82-windbg-mcp-a64-puts-constants-in-a-literal-pool-and-the-walk-cannot-read-one--done-2026-09-19) — [windbg-mcp] A64 puts constants in a literal pool, and the walk cannot read one — done (2026-09-19)
- [Item 83](#83-windbg-mcp-reachable_from_dispatch-does-not-follow-the-jump-tables-ioctl_map-now-reads--done-2026-09-19) — [windbg-mcp] `reachable_from_dispatch` does not follow the jump tables `ioctl_map` now reads — done (2026-09-19)
- [Item 90](#90-windbg-mcp-the-resolver-reads-a-whole-function-so-scoping-from-does-not-narrow-it--done-2026-09-19) — [windbg-mcp] The resolver reads a whole function, so scoping `from` does not narrow it — done (2026-09-19)
- [Item 89](#89-windbg-mcp-a-switch-that-would-not-resolve-is-the-one-incompleteness-the-report-does-not-count--done-2026-09-20) — [windbg-mcp] A switch that would not resolve is the one incompleteness the report does not count — done (2026-09-20)
- [Item 85](#85-windbg-mcp-the-arm64-second-opinion-exists-and-has-never-been-diffed--done-2026-09-20) — [windbg-mcp] The ARM64 second opinion exists and has never been diffed — done (2026-09-20)
- [Item 93](#93-windbg-mcp--dbgscope-multiprocessor-hypervisor-stops-after-a-temporary-breakpoint-and-detach--done-2026-09-21) — [windbg-mcp + dbgscope] Multiprocessor hypervisor stops after a temporary breakpoint and detach — done (2026-09-21)
- [Item 95](#95-windbg-mcp-a-connection-profile-carries-a-name-and-a-string-and-nothing-about-the-target--done-2026-09-21) — [windbg-mcp] A connection profile carries a name and a string, and nothing about the target — done (2026-09-21)
- [Item 79](#79-dbgscope-a-heap-outside-the-pebs-processheaps-is-invisible-to-the-heap-tools--done-2026-09-22-dbgscope176) — [dbgscope] A heap outside the PEB's `ProcessHeaps` is invisible to the heap tools — done (2026-09-22, dbgscope#176)
- [Item 96](#96-dbgscope--windbg-mcp-the-pool-walker-on-arm64-and-an-lfh-reading-that-is-not-nts--done-2026-09-23-dbgscope179) — [dbgscope + windbg-mcp] The pool walker on ARM64, and an LFH reading that is not `nt`'s — done (2026-09-23, dbgscope#179)
- [Item 99](#99-dbgscope-a-big-page-tag-the-engine-resolves-and-the-walker-does-not--done-2026-09-24-dbgscope180-dbgscope181) — [dbgscope] A big-page tag the engine resolves and the walker does not — done (2026-09-24, dbgscope#180, dbgscope#181)
- [Item 98](#98-dbgscope-uncommitted-memory-is-an-unreadable-gap-so-a-live-heap-walk-is-not-complete--done-2026-09-24-dbgscope183) — [dbgscope] Uncommitted memory is an unreadable gap, so a live heap walk is not `Complete` — done (2026-09-24, dbgscope#183)
- [Item 80](#80-windbg-mcp-identity-re-derives-the-backend-distinction-once-per-field--done-2026-09-25) — [windbg-mcp] `identity()` re-derives the backend distinction once per field — done (2026-09-25)
- [Item 32](#32-windbg-mcp-two-arm64-ci-entries-one-of-which-expires--done-2026-09-25) — [windbg-mcp] Two ARM64 CI entries, one of which expires — done (2026-09-25)
- [Item 81](#81-windbg-mcp--dbgscope-changes_debug_target-reads-a-name-and-a-wrapper-does-not-say-one--done-2026-09-25) — [windbg-mcp + dbgscope] `changes_debug_target` reads a name, and a wrapper does not say one — done (2026-09-25)
- [Item 102](#102-windbg-mcp-a-debug_batch-runs-its-rollback-against-whatever-target-it-ends-up-holding--done-2026-09-26) — [windbg-mcp] A `debug_batch` runs its rollback against whatever target it ends up holding — done (2026-09-26)
- [Item 103](#103-windbg-mcp-h5b--expose-the-secure-kernel-reads-without-forcing-them-through-dbgeng--done-2026-10-02) — [windbg-mcp] H5b — expose the Secure Kernel reads, without forcing them through DbgEng — done (2026-10-02)
- [Item 107](#107-windbg-mcp-a-misspelt-tool-argument-is-silently-ignored-and-the-call-answers-status-ok--done-2026-10-02) — [windbg-mcp] A misspelt tool argument is silently ignored, and the call answers `status: ok` — done (2026-10-02)
- [Item 92](#92-windbg-mcp-an-a64-conditional-compare-chain-is-a-compare-chain-the-walk-does-not-read--done-2026-10-02) — [windbg-mcp] An A64 conditional-compare chain is a compare chain the walk does not read — done (2026-10-02)
- [Item 109](#109-windbg-mcp-the-server-can-walk-a-call-graph-forward-and-find-calls-to-imports-and-cannot-answer-who-calls-this-address--done-2026-10-04) — [windbg-mcp] The server can walk a call graph forward and find calls to imports, and cannot answer "who calls this address" — done (2026-10-04)
- [Item 111](#111-windbg-mcp--dbgscope-an-image-targets-memory-reads-only-after-something-else-has-read-it-and-a-walk-counts-what-it-did-not-get-as-scanned--done-2026-10-04-the-second-half-withdrawn) — [windbg-mcp] An image target's memory does not read until its module is loaded — done (2026-10-04), with the entry's second claim withdrawn

## 1. [dbgscope] Managed breakpoint lifecycle for `run_to_address` — **done upstream**

`run_to_address` used a one-shot `g <addr>` (WinDbg's temporary breakpoint), which DbgEng does **not**
hand back a handle for, so every exit but a hit could leave it armed.

Fixed in dbgscope (`05df6b7`, closing
[glslang/dbgscope#63](https://github.com/glslang/dbgscope/issues/63)) and picked up here by the pin
bump. Building it surfaced two further defects on the same path, both of which mattered more than
the stale breakpoint this item was filed for: the `Timeout` outcome was **unreachable** (it tested
`GetExecutionStatus() == DEBUG_STATUS_GO`, but an expired finite wait reports `DEBUG_STATUS_BREAK`),
so a timed-out `run_to_address` returned `0x8000FFFF` "catastrophic failure" and left the session
with no current process — and the recovery it would have run does not work either, because a finite
wait stops the engine pumping events and `SetInterrupt` can no longer be delivered. Every target
type now uses the watchdog-bounded `WaitForEvent(INFINITE)` the live-kernel path already used.

Nothing changed in this crate: `run_to_address` is a thin wrapper and its `RunToOutcome::Timeout`
branch simply became reachable. The verdict text it renders was already correct for a target that
ends up broken in.

## 7. [dbgscope + windbg-mcp] On-demand engine interrupt — **done** (2026-08-10)

Expose `SetInterrupt` as a public dbgscope method (and a `Send` handle obtainable from a
`&DebugEngine`), then plumb it through to a per-session `interrupt()`. The primitive existed but was
only ever *timeout-driven*: `execute_command_bounded` and `wait_for_event_bounded` each spawn a
watchdog thread holding an `InterruptHandle` and Ctrl+Break the engine when a deadline passes, and
no caller could ask for the same.

`InterruptHandle` already carried the reasoning: `SetInterrupt` is the one DbgEng call documented as
safe from another thread, so this needed no new threading model — the engine stays confined to its
one thread (`src/worker.rs`) and the interrupt arrives from outside it, exactly as it always did.

**Reshaped by item 10, half-built by item 18.** The interrupt is a *per-session* concern: it has to
reach one worker's engine, and it cannot travel as an ordinary op, because it would be read only
once the operation it means to stop had ended. Item 18 built that half — `worker::run`'s reader acts
on a request where it reads it — and settled the channel question: no side channel was needed,
because the reader was never blocked.

Landed as the `interrupt` tool. What each half turned out to be:

- **dbgscope:** `InterruptHandle` is public, `Send + Sync`, and holds an owned `IDebugControl4`
  rather than a borrowed pointer — a handle a host can keep would otherwise dangle past the engine
  it came from. Both watchdogs now go through it, which is what makes the second part work: the
  handle and the engine share a `raised` flag, so `execute_command_bounded` can tell an aborted
  `Execute` from a failed one **without being the thread that asked**. Without that, an interrupt on
  request came back as `CommandFailed` and threw away every line the command had produced — most of
  what an interrupted search is worth. No note is appended for a requested interrupt, unlike the
  watchdog's: that one explains a deadline nobody saw pass, whereas this caller is the one who
  asked.
- **windbg-mcp:** the reader answers `EngineOp::Interrupt` outright and never queues it. Job
  identity is a `Running { job, interrupted }` under one lock: the reader reads the running job and
  raises under it, the engine thread claims and releases under it, so an interrupt reaches the job
  that was running when it arrived or nothing at all. The job it reached **spends** it — a pending
  break is drained before the next job starts, and only that caller's reply is marked cut short.

- **Why it came first:** it is what would give item 8's `tasks/cancel` anything to do — the spec's
  cancellation is cooperative, so acknowledging one conforms, but a session blocked inside DbgEng
  cannot act on it at all *without being thrown away*. It stands alone too, which is how it shipped:
  an operator can abort a runaway `execute` before `ENGINE_CALL_TIMEOUT` (`src/main.rs`, 300s)
  elapses, keeping the target that `end_session` would discard.
- **A bare `interrupt()` would hit the wrong job**, and this is the part that needed designing
  rather than plumbing. `SetInterrupt` addresses one engine, meaning whichever operation that
  session is *currently running* — so raised a moment late it Ctrl+Breaks whatever started next.
  Today that is a race against a job boundary; under item 8, with several calls in flight as the
  normal case, it is the ordinary outcome of cancelling a task whose job is still queued. The lock
  above closes the race and is the foundation the queued case needs: `tasks/cancel` for a job that
  has not started should drop it from the queue rather than raise anything, and that is a *second*
  variant of this request (one naming a job id) rather than a change to what landed. It is not
  built, because nothing can name a job id yet — a tool call names a session.
- **Known limit, unchanged:** `SetInterrupt` cannot unblock a live-kernel wait until the target is
  *connected*. So the `attach_kernel` KDNET park documented in `CLAUDE.md` — the case that most
  wants cancelling — is not cancellable this way; only tearing down the process ends it, which
  item 10 made an in-band operation (`end_session`). The tool says so rather than reporting a
  success that does nothing.
- **Proof:** dbgscope's `test_command_interrupted_on_request_keeps_its_output` (live, `#[ignore]`d)
  holds the partial-output-as-`Ok` claim the shared flag exists for; `src/worker.rs` unit-tests the
  binding against a local `Running` (both orderings of the race, staged — which against the real
  one would mean interrupting an engine at an exact instant); and `tests/mcp_smoke.rs`'s
  `a_running_command_is_interrupted_on_request_and_frees_its_session` drives the whole thing through
  the shipped binary, which is the only place both halves exist. That last one is in the ordinary
  dump tier rather than the ignored one: the interrupt lands in milliseconds, so nothing waits out a
  deadline — measured at 203ms against a `.for` sized to run for hours.

## 10. [windbg-mcp] Process-per-session — **done** (2026-08-02, issue #61)

dbgeng.dll holds **one debuggee session per process**. That is not a dbgscope limitation — it is why
`.opendump` *replaces* the target, and why the `session_id` design existed at all (a handle that
detects the swap, because there was nothing to swap *between*).

Landed: the binary now runs the MCP protocol in a supervisor process (`src/engine.rs`) and each open
target in an engine worker child process (`src/worker.rs`), talking over a line-delimited JSON
protocol (`src/proto.rs`). `session_id` stopped meaning "detect that the target changed underneath
you" and started meaning "route to the worker that owns this target". Sessions are concurrent (up to
`MAX_SESSIONS`), and `end_session` can terminate a worker that will not unwind — which is what
issue #61 needed, since a kernel attach whose target never dials in cannot be interrupted at all.

What moved, for anyone picking up the items that referenced this:

- The queue is **per session**, so a busy or parked session no longer blocks any other. The
  budget arithmetic moved with it: the supervisor sends the caller's remaining *patience* and the
  worker derives the watchdog deadline, because only the worker can measure the wait on its own
  side of the pipe.
- The `opens` ledger became the session registry, and `session_status` reports session *state* —
  including how long an open has been waiting, which is what distinguishes a KDNET link that is
  coming up from one that never will.
- `unsafe impl Send/Sync for DebugEngine` (dbgscope `src/dbgeng.rs:164-165`) is still sound for the
  same reason as before: `src/worker.rs` confines the engine to one thread *inside* the worker. The
  supervisor never touches a `DebugEngine` at all, which is a stronger position than the one that
  claim was written for.

Fixed since: **per-worker symbol state** —
[#66](https://github.com/glslang/windbg-mcp/issues/66). Each worker still owns its own `.sympath`
and symbol cache, but `set_symbol_path { "for_new_sessions": true, … }` records a client-scoped
starting mutation in the supervisor and applies it before that client's later workers open their
targets. Session-only overrides remain the default, and no update is pushed into a running worker.

Fixed since, from the same review: [#67](https://github.com/glslang/windbg-mcp/issues/67) — workers
were spawned with `kill_on_drop`, so a worker shutdown missed was terminated with its target still
attached. `kill_on_drop` is gone (EOF on the worker's stdin is now the only teardown, which it
already handled), and registration re-checks the shutdown gate so the missable window is closed
rather than merely survivable.

Two ordering details the review of #62 raised and that PR deliberately left alone. The first is
fixed since: [#64](https://github.com/glslang/windbg-mcp/issues/64) — `end_session` now closes its
session at the teardown's exact place in the pump queue, using the same `Gate` treatment `retires`
already had. The second remains filed: [#65](https://github.com/glslang/windbg-mcp/issues/65) (the
worker protocol shares stdout with anything the engine prints; mitigated, not structurally
prevented).

## 12. [dbgscope] Validate the opener split against a live KDNET target — **done** (2026-08-02)

The split that made per-opener handle commits possible (glslang/dbgscope#71) was validated on
user-mode targets only — split launch, fused launch, split attach, via `examples/split_open.rs`.
The two **kernel** halves ran on no hardware: `attach_local_kernel_begin`/`wait` and
`attach_kernel_begin`/`wait`.

`attach_kernel_begin`/`wait` then ran against a Windows Server 26100 guest over KDNET, from the
harness added in dbgscope#77 (`examples/kdtest.rs` now drives the split path beside the fused one),
and passes on both counts. `attach_local_kernel_begin` shares `wait_for_kernel_break_in` and differs
only in its begin half; on a host with local KD off it can exercise nothing but that half's
`E_NOTIMPL`, which is not evidence about the wait.

- **The connection string outlives the seam.** `AttachKernel` returned in **28.5ms** with the link
  demonstrably not up, and the link came up **5.7s later, inside `wait()`** — on the far side of the
  seam — after which `vertarget` read a real machine. Stated as precisely as the item was written:
  this proves the parking is correct, not that the engine reads the string late. Had the buffer been
  freed at the end of `attach_kernel_begin` the attach would very likely still have *appeared* to
  work, freed memory usually retaining its contents — which is why holding it was the right call
  rather than something a test could have argued for.
- **The bookkeeping runs on the `wait()` side.** `go` stopped at `Breakpoint 0 hit`. That is the
  discriminator: an `INITIAL_BREAK` left armed, or its spurious re-break left unabsorbed, stops the
  target at `nt!DbgBreakPointWithStatus` and never reaches the breakpoint.

**The third thing this item asked for does not exist, and finding that out is what it was worth.**
It wanted "a deliberate timeout against an unreachable target". Dialing a dead port returned from
`AttachKernel` in 7.9ms and then blocked past **300s** — five times the 60s `KERNEL_ATTACH_WAIT_MS`
— before the run was killed, and the same VM booted *without* `bcdedit /debug on` did the same at
0.7s of CPU, parked in the transport rather than spinning. The watchdog is `SetInterrupt`, which
only reaches a wait whose target has **connected**, so the bound covers a connected-but-unresponsive
guest and nothing else. `KernelBreakTimeout` is reachable only from a target that connects and
*then* fails to break in — wedged, or spinning at high IRQL — and stays unexercised. It is also
three lines the split did not touch (`wait_for_kernel_break_in` is byte-identical; only its call
site moved), which is why dbgscope#73 closed without it.

What that leaves this repo is not a test but a constraint, and it is the one item 10 exists for: the
most common kernel-debugging mistake there is — a guest not booted with `/debug on` — blocks the
attaching thread with **no bound at all**, and no in-process mitigation is possible, because the
inability to cancel is DbgEng's. A caller that must stay responsive needs a process it can abandon.
This server has one: the attach parks a *worker*, `session_status` reports how long it has waited,
and `end_session` terminates it — covered end to end by the live smoke tier (a kernel attach parked
on a dead port, reclaimed by `end_session`). dbgscope now documents the bound's real reach on
`attach_kernel` itself ("Blocks indefinitely if the target never connects", `src/dbgeng.rs`), so the
next caller does not have to measure it again.

- **Tracked as:** [glslang/dbgscope#73](https://github.com/glslang/dbgscope/issues/73) — closed
  2026-08-14.

## 13. [windbg-mcp] A job-level deadline for `reachable_from_dispatch` — **done** (2026-09-10, #296)

**What it was filed for.** The walk ran its whole breadth-first traversal — up to `max_functions`
disassemblies — inside a single engine job, with `max_functions` (256) and `max_depth` (32) coming
from the caller **uncapped** and nothing polled between them. A large enough pair pinned that
session's engine for as long as the walk took: the same wedge the bounded path fixed, arriving by a
route the bounded path could not reach.

**What landed.** `ReachabilityOp` carries a `patience_ms` the supervisor's pump fills, as the
allocator ops' does, and the walk polls it between functions **and once after its queue drains** —
the second of those is not symmetry, it is the only place a halt reached while decoding the *last*
function can be seen. The bounds are clamped at 4,096 functions and 256 depth, far above the
defaults: what is prevented is absurdity, not ambition. And half the fix is the rendering, because a
walk that ran out of time did not explore the graph it was *bounded* to either — a halt outranks the
bound in the report, and "the reachable call graph was fully explored" is a sentence a halted walk
must never produce. A recipe cut short the same way is labelled `INCOMPLETE`: a prefix of a recipe
is not a weaker version of one, and satisfying it does not put control on the target.

**This entry's central claim was wrong, and that is why it is worth keeping.** It said "no
individual `uf` is the problem — the aggregate is", and deferred any per-command bound on that
basis; item 56 then repeated the reasoning. Review round six measured it and it does not hold: a
`uf` blocked on a deferred symbol load blocks the one thread the session has, so **no poll between
calls can run while it does**, and a job-level deadline is unenforceable without one. The `uf` is
`execute_command_bounded` on the remainder of the caller's clock now, with a `walk_budget_ms` that
refuses to run a command whose budget rounds down to zero — zero arms no watchdog, which would make
the call with least time to spare the only unbounded one in the walk.

**What is still unbounded, and is not this server's to fix.** The typed instruction decodes under
that `uf` have no bound of their own: `disassemble` renders each line, so it resolves symbols, and
dbgscope has no bounded form of that call. Filed as
[dbgscope#149](https://github.com/glslang/dbgscope/issues/149), cited at the call site and in
`docs/limitations.md`, which says what the bound there actually is — the number of calls, not the
time they take.

- **Where it landed:** `src/driver.rs` (the walk and its rendering), `src/worker.rs` (`reachable`,
  `walk_budget_ms`, `halt_for`), `src/server.rs` (`walk_bound` and the two ceilings),
  `src/proto.rs` (`ReachabilityOp::patience_ms`).

## 14. [dbgscope] Make arming the bounded watchdog ~free — **done** (2026-08-25 upstream, 2026-08-31 here)

Filed against dbgscope: `execute_command_bounded` spawned a watchdog thread that polled a `done`
flag on a `thread::sleep(200ms)` loop and joined it once `Execute` returned, so the join waited out
the remainder of the nap and a bounded command took `ceil(d / 200ms) * 200ms`. Measured then: a
127ms command took 201ms, a 377ms one 401ms, and a 0.2ms `lm` took either ~0.3ms or ~200.7ms
depending on whether it beat the watchdog thread's first poll. Parking on a condvar would drop that
to ~0, and the point of doing so was never the milliseconds — it was that the tax was the **only**
reason windbg-mcp's cheap point queries stayed off the bounded path (`DECISIONS.md`, 2026-08-02).

**The dbgscope half landed on its own, through work aimed at something else.** `Watchdog` parks on
a `Condvar` in the pinned revision, so a disarm is immediate and a bound costs nothing until it is
actually reached. It arrived through [#226](https://github.com/glslang/windbg-mcp/issues/226) — the
sleep was what made a *finite* `WaitForEvent` look attractive, and that finite wait was destroying
sessions — so nobody was looking at this item when the thing it asked for shipped.

**What closed it here was reading a Status line, not writing code.** The 2026-08-02 decision ended
"revisit if dbgscope's watchdog stops quantizing to 200ms … at which point 'bound everything except
`index_trace`' becomes the cheaper and simpler rule". That is the whole close: the trigger had
fired six days earlier and the rule was already the cheaper one. `threads`, `goto_position`,
`driver_object`, `device_object`, `irp_stack` and `ioctl_trace` moved to
`EngineOp::BoundedCommand`; `index_trace` keeps the unbounded path, now named
`EngineOp::UnboundedCommand`, because `!ttdext.index -force` deletes an unloadable `.idx` before
rebuilding it and a break part-way through can leave a trace with no index at all.

Four things this turned up that the entry could not have said:

- **The measurement had to be re-taken, and it was worth insisting on.** The old table's numbers
  were the in-process engine's, and the current test compares a *typed* `modules` against a
  bounded `execute` rather than one command on two paths — so "the tax is gone" was a claim about
  a program nobody had run. Re-run twice on the x64 bench (sample dump, 20 rounds): bounded `lm`
  medians 3.0ms and 3.3ms against 4.1ms and 4.2ms for the unbounded `modules` beside it, and the
  ~170ms `.for` loop costs ~171ms and ~185ms rather than 200ms. The second mode — `lm` racing the
  first poll and landing on ~0.3ms or ~200.7ms run to run — did not appear in either run.
- **The measurement went on passing across the change it exists to catch**, because it prints and
  is `#[ignore]`d. Its comment still described the sleep six days after the sleep was gone. The
  numbers stay a print — they are dbgscope's and this host's, and a threshold pinned here would
  fail on an unrelated host difference — but the *shape* is now asserted in the debugger tier,
  un-`#[ignore]`d, by `arming_the_watchdog_does_not_round_a_quick_command_up`: the **ratio**
  between two bounded commands of very different cost, which a fixed quantum collapses to ~1 by
  rounding both up to the same multiple. A margin against an unbounded baseline was tried first
  and is the wrong shape — the baseline grows into the margin on exactly the slow host the guard
  was advertised as surviving.
- **Collapsing a split needs the thing that stops it re-forming.** The rule is a sentence in two
  markdown files, and the way it comes back is a tool added by copy-paste taking the unbounded op
  with nobody deciding to — which no runtime test can see, because that tool works perfectly until
  the day its command runs away. Hence the rename and
  `server::tests::only_index_trace_runs_a_command_unbounded`, which reads the source the way
  `record`'s stdout rule does. Verified by breaking it: routing `threads` back reports
  `["threads", "index_trace"]`.
- **"Bound everything" is a rule about *commands*, and stating it over **ops** cost two
  instances.** A watchdog Ctrl+Breaks an `Execute`, and a *typed* op can run one — nothing in the
  op's name says so. `set_breakpoint` was doing exactly that, `execute_command("bp <the caller's
  expression>")`, while every op around it moved; Codex found it on
  [#271](https://github.com/glslang/windbg-mcp/pull/271) against a first draft whose test
  certified only the enum variant, which is to say the check agreed with the mistake. Fixed there
  — `EngineOp::SetBreakpoint` carries a `patience_ms` like any other command — and the check
  rewritten to read `Execute` calls out of `src/worker.rs` and enumerate the five functions that
  legitimately run one unbounded. Enumerating rather than reasoning immediately turned up a second:
  `resolve`'s `? <expr>`, also caller text, now item 56. **The general lesson is the cheap one:** a
  test written from the same sentence as the change inherits the sentence's blind spot, and the way
  out is to check the thing the rule is *about* rather than the thing the change touched.
- **What no phrasing of it reaches.** The typed ops — `modules`, `backtrace`, `disassemble`,
  `registers`, `read_memory` — are direct engine calls with nothing for a watchdog to break, so a
  frame whose symbol has to be fetched can still block inside one however the rule is written; the
  walks and `crash_triage` bound themselves between nodes instead. And `reachable_from_dispatch` is
  still unbounded in aggregate: many `uf` commands inside one job, which needs a job-level deadline
  and is still item 13.

## 16. [windbg-mcp] Exercise a *mutating* `debug_batch` against a live kernel target — **done**

`debug_batch` (#82) was proved at two altitudes: `src/batch.rs` drives the executor over a scripted
debuggee with a virtual clock (assertion failure, a command failure after a mutation, deadline
expiry, a rollback that itself fails), and the debugger tier drives a real engine to both outcomes
over the wire. Neither covered the case the tool was built for — a **write that is then restored**
on a target that would notice.

Landed (2026-08-10) as five tests in the `live_kernel` filter of `tests/mcp_smoke.rs`: a failing
batch whose `always` block restores a patched byte (confirmed by a *later, separate* call, so
nothing after the batch had to be sent for it to happen); the same under a
`WINDBG_MCP_CALL_TIMEOUT_SECS` shorter than the batch's own deadline, where the clamp in
`worker::batch_budget` is what keeps the report ahead of the caller; a disconnect mid-batch, read
back by a **new server process** over a fresh attach; an `end_session` mid-batch, where the client is
still there to receive `BATCH: ABANDONED` *and* a second attach agrees about the byte; and a pool
step inside a batch (item 17).

Two things the writing of it settled, both worth keeping:

- **What to patch.** `nt`'s DOS-header `e_res2` field (`nt+0x28`) — reserved by the format, read by
  nothing at runtime, and stable across a detach and re-attach, which the teardown tests need and a
  stack address could not give. Anything with a *purpose* satisfies the first two conditions and
  bugchecks the guest on the third.
- **The probe is not optional.** A guest with memory integrity (HVCI) enabled accepts a debugger
  write to an image page and silently drops it, so every one of these tests reads, writes, reads
  back and restores the byte *before* it opens a transaction. Without that, a rollback that did
  nothing and a patch that never landed are the same green tick.

## 17. [windbg-mcp] Let a `debug_batch` step call a typed tool, starting with the pool queries — **done**

The one gap the MessageManager transcript found in `debug_batch` (#82). Its step vocabulary reaches
anything that is a *debugger command*, which is almost every typed tool in this server — but not the
ones that are not commands at all. The pool tools are dbgscope walks over the allocator's own
structures, so `pool_find_tag`, `pool_chunk` and `pool_census` had no `execute` equivalent to fall
back on. It cost the workflow this is measured against 9 of 1,681 steps (`@chunkt1`, `@census`,
`@find`, `@findr`) — small, but not incidental: `@chunkt1` sat *inside* the 32-step transaction,
between a code patch and its restore.

Landed (2026-08-10) as **one `StepAction` variant per question** — `pool_chunk`, `pool_find_tag`,
`pool_census` — rather than a generic "call a tool" step, for the reason this item guessed at: the
generic form would have every tool's arguments living in the batch schema twice. `pool_diagnostics`
is deliberately not among them; it explains a *walk* rather than the target, and belongs to the
interactive look that follows a batch. `batch::Debuggee` gained one method, `pool`, so the executor
stays engine-free, and the defaults and caps moved onto `PoolOp` constructors in `src/proto.rs` so a
step and a tool cannot drift apart on what `limit` means.

The design question the item did *not* anticipate, and the part worth remembering: **a walk needs a
deadline from the batch.** dbgscope bounds a walk at `DEFAULT_WALK_BUDGET` (120s), which is longer
than an ordinary batch's whole budget — so a `refresh` step taking that default could spend the
reserve the rollback lives on and overrun the bound the worker advertises to a teardown (item 18),
which is a worker terminated mid-transaction. `PoolWalk::within` already existed for exactly this
("a host that knows its own deadline should pass that instead of taking this"), so a pool step now
passes its own step budget and a walk cut short reports its coverage as it always did. The pool
*tools* took the default until [#75](https://github.com/glslang/windbg-mcp/issues/75) gave them the
call's patience on the same arithmetic (2026-08-10); `None` — the walker's own default — is now
reachable from neither caller, which is right, because neither is a human at a prompt who could
Ctrl+C a walk that ran long.

## 18. [windbg-mcp] Let a running batch finish its rollback when the client disconnects — **done**

`debug_batch` (#82) made one guarantee totally and a weaker version of it partially. Against a call
**timeout** the rollback is safe by construction: the batch budget is clamped to the caller's
remaining patience, so `always` has run and the report has been written before the wait expires.
Against a **teardown** it was not. `Sessions::shutdown` treats a disconnect as `end_session` on every
session; the `EndSession` op queues behind the batch, `release` waits `SHUTDOWN_RELEASE_TIMEOUT`
(5s), and then the worker was killed — mid-transaction, with the patch still applied. `end_session`
itself was the same shape with a longer number on it.

Landed (2026-08-10) as the *signal* this item proposed rather than a longer wait, and it needed less
than item 7 to build: a worker busy in DbgEng **is** draining its request queue, because the reader
lives on the main thread and only hands work to the engine thread. So the reader acts on the
teardown's own `EndSession` where it reads it, before queueing it for an engine thread that is by
definition busy. It sets a flag `batch::run` checks between steps; the batch stops there, runs
`always`, and reports `BATCH: ABANDONED`.

What made the wait conditional without the supervisor tracking op identity: the worker answers with
`WorkerMessage::RollingBack { within_ms }` — a milestone, so it arrives while the teardown is still
waiting on that same op's reply — and the wait extends itself by that figure once its ordinary grace
runs out. `within_ms` is the batch's own remaining budget plus the overrun its executor is allowed,
so it covers the step in flight as well as the rollback; sizing it from the reserve instead (the
first cut, caught in review) expires inside a long step and terminates the worker mid-patch, which
is the same failure one step later. The wait re-reads it rather than committing once, because a
batch that finishes early hands the rest back and keeps only what the release still needs.

Carrying the signal on the release rather than on an op of its own was also review's doing, and for
a sharper reason: telling a batch to stop is sticky and one-way, so it must not be possible for a
teardown that does not happen. Two separately gated requests can come apart — a target-changing call
between them retires the session, the release is refused as stale, and the abandon has already
aborted a transaction and left a flag no later batch could get past on a session that survives. On
one request the property is structural: a gate refusal stops it before the worker sees it, and every
request the worker does see is followed by that worker being terminated. An ordinary disconnect is untouched, and not
merely by arithmetic: the signal is skipped entirely when the worker owes no reply. A batch reaching
the engine *after* the signal does not start, which is the same "nothing ran, resubmitting is safe"
answer as an unaffordable budget, and the worker's own EOF path sets the flag too, so a supervisor
killed outright still gets the rollback rather than a truncated transaction.

- **What is still true, and now documented as the whole of the boundary:** no signal *shortens* a
  step already inside DbgEng, so a batch stops at its *next* step. The teardown waits that step out
  rather than cutting it off, so the cost is latency rather than a lost rollback — but a step that
  outlives its own watchdog is still terminated mid-transaction. Shortening it is item 7
  (`SetInterrupt` bound to job identity), and that is the only part of this that needs it.
- **Proof:** `src/batch.rs` unit-tests the executor's two new behaviours (stop and roll back, and
  the rollback keeping the same budget every other path gets, whichever step the signal landed in),
  `src/worker.rs` pins the pairing that makes "a batch runs while the teardown thinks nothing is
  running" unreachable and the remaining-budget figure the grace is sized from, and the dump tier
  drives both teardowns end to end — the disconnect one asserting against a file the rollback wrote,
  because by then there is no client, supervisor or worker left to ask.

## 20. [windbg-mcp] Pick the TTD recorder by architecture, not by a fixed list — **done** (2026-08-16, #131)

`find_ttd` probed x64 before arm64 in both layouts it knows — `["x64", "arm64"]` for the classic
SDK, and a list headed by `amd64\TTD\TTD.exe` for the MSIX package. On an ARM64 host that was
always the wrong answer, because the ARM64 WinDbg package ships **all three** recorders (`amd64`,
`arm64`, `x86`) and the first probe therefore always hit. `record_trace` picked the x64 recorder on
exactly the hosts where the choice is not free, and a native ARM64 target cannot be recorded with
it.

Found while setting up a Parallels ARM64 guest for [`docs/remote-phase0.md`](./docs/remote-phase0.md).

**Resolved as the first cut this entry described**, and the deferral reasoning stands: the probe
order now leads with *this build's* architecture and keeps the others behind it, because it is an
ordering and not a filter — an emulated x64 debuggee on an ARM64 host genuinely wants the `amd64`
recorder. The target's architecture is still the correct selector and still unavailable here:
`record_trace` receives a command line, and resolving that to a file to read a PE header from is a
separate problem with its own failure modes. `PATH` is searched first and overrides all of it, which
is now documented at the point of the guess rather than only in the issue.

**What the entry did not anticipate** is the reason it is kept rather than deleted. The two
installers disagree about one spelling — the SDK ships `Debuggers\x64` where the store package's
payload directory is `amd64` — so reordering the string lists, which is what this entry describes,
would have selected the wrong architecture by a different route. That is the same class of mistake
as the ordering itself, and it is why the fix introduced an `Arch` type with the two names as
separate accessors instead of reordering literals.

Two smaller things it also turned out to need: the bare `TTD\TTD.exe` layout moved from second to
last, since a package has either an architecture-specific tree or that one; and the ordering is
covered by unit tests rather than a live probe, because the ARM64 host it was found on no longer has
a TTD in either layout — its recorder is the `PATH` copy, which is the workaround this removes the
need for.

## 21. [windbg-mcp] TTD replay on a host where the store package will not install — **done** (2026-08-29, #132)

`open_trace` needs the replay engine — `TTDReplay*.dll`, `TtdExt.dll`, `TTDAnalyze.dll` — in a
`ttd\` directory beside `windbg-mcp.exe`. System32's `dbgeng.dll` ships none of it and rejects every
trace with `0x80070057`, so there is no degraded mode: replay either has the files or does not
happen.

Two things compound to make that unreachable on some hosts. The **SDK Debugging Tools do not ship
`ttd\`** (nor `msdia140.dll`), so the one source that installs cleanly from a command line supplies
everything *except* replay. And **MSIX registration fails from a non-interactive session** —
`Add-AppxPackage` returns `0x80070005` even when elevated — staging the payload into
`WindowsApps` without registering it, where the ACLs then deny execute. The result is a host that
records traces and cannot replay them.

Deferred because the two halves that could be done cheaply already have been, and what is left is a
judgement call rather than a task. `open_trace` now says *why* a trace will not open instead of
surfacing `0x80070057`, and `setup.md` carries a recipe for unpacking `ttd\` from the
`.msixbundle`, which is an ordinary zip. So the failure is legible and there is a way through it.

What was undecided is whether unpacking a Microsoft package by hand should be a **supported** path
in this project's own documentation — it was written down as a fallback, not endorsed — or whether
the answer is to require an interactive install and say so plainly. That is a maintainer's call
about what this repo is willing to tell people to do, not an engineering problem.

**Resolved as endorsed**, and the deciding evidence came from somewhere this entry was not looking:
**item 47**. The TTD tier records a trace, opens it and queries it on the x64 bench, and that
bench's `ttd\` came from this entry's own unpack recipe — so the path the documentation called a
fallback was already the one this repository's own coverage stood on. A project cannot hold a route
at arm's length and depend on it at the same time; that, rather than any argument about what MSIX
is for, is what settled it.

**Three things the entry did not anticipate**, which is why it is kept rather than deleted.

The first is that endorsing removed a step instead of adding one. The store package's
`InstallLocation\$arch` and the unpacked `.msix`'s `$arch\` are the **same layout** — same files,
same subdirectories — so the two sources differ only in how `$wd` is set, and the copy block after
it is one block rather than two. The old shape had the bundle copying `ttd\` *alone* into a
payload otherwise taken from the SDK, which is the more complicated arrangement as well as the
less supported one.

The second is that **the recipe did not work, and had not since the day it was written** —
`8bd98a5`, 2026-08-16, unchanged for the thirteen days until this. Its first line read the
`.appinstaller` with `(Invoke-WebRequest …).Content` and cast it to `[xml]`; under Windows
PowerShell 5.1 that property is a `Byte[]` for this content type, so the cast throws
*"Cannot convert value \"System.Byte[]\" to type \"System.Xml.XmlDocument\""* and nothing is
downloaded at all. Whatever it was derived from, nobody had run **that text** start to finish, and
it read perfectly plausibly for thirteen days. Fetching to a file and reading it back with
`Get-Content -Raw` is version-proof, and is what it does now. **A documented recipe nobody executes
is a claim, not a procedure** — which is the general lesson, and the reason the end-to-end run
below was worth its 1.1 GB.

The third is that the honest verification step was cheap. `Get-AuthenticodeSignature` answers on a
`.msixbundle` — `Valid`, `SignatureType Authenticode`, `CN=Microsoft Corporation` — so "unpack a
Microsoft package by hand" could become "verify the publisher, then unpack", which is what makes it
defensible to write down. It settles provenance and not fitness, and `setup.md` says so in those
terms rather than letting a green check stand for more than it is.

**What the end-to-end run measured** (ARM64 bench, Windows PowerShell 5.1.26100.1, 2026-08-29):
the `.appinstaller` resolves to `windbg.download.prss.microsoft.com/.../1-2606-22001-0`; the bundle
is 1,188,564,441 bytes and verifies as above; it holds `windbg_win-arm64.msix`, `windbg_win-x64.msix`
and `windbg_win-x86.msix`, so the recipe's guessed name is right; and **all three** payload trees
inside the ARM64 one — `amd64\`, `arm64\`, `x86\` — carry the entire copy list, `msdia140.dll`
included, plus `ttd\TTD.exe`, which means the engine copy already brings the *recorder* rather than
only the replay engine.

**And then the bench was bundled from it, which closed the issue where it was filed.** The ARM64
payload went beside `target\release\windbg-mcp.exe` and the host that could only record now
replays: `hostname.exe` recorded to a 40 MB `.run` with the bundled `ttd\TTD.exe`, `open_trace`
answered with the trace's lifetime (`[E:0, 7F8:EB0]`, 9 modules) rather than the missing-`ttd\`
diagnostic it gave twenty minutes earlier, and `step_back` reached the start of the trace. So
"an engine bundled this way replays" is measured on ARM64 as well as on the x64 tier.

Two things that copy turned up, neither of them anticipated:

- **The running server holds `dbgeng.dll` open**, so bundling or updating an engine needs the
  service *stopped* — having no sessions open is not enough. The supervisor never uses DbgEng, but
  the DLL is an import-table dependency of the image, so the loader maps it before `main` whatever
  role the process goes on to play. `Copy-Item` fails with *"being used by another process"*
  against a supervisor sitting idle with an empty session list. Same mechanism this file already
  records for the 32-bit worker, which is why an `x86\windbg-mcp.exe` with no engine beside it
  fails to *start* rather than failing to open a dump.
- **`find_ttd` did not look beside the executable** — it probed `PATH`, the SDK layout and
  `WindowsApps`, so the `ttd\TTD.exe` the engine copy delivers was reachable only by *also* putting
  it on `PATH`. The probe this project's own documentation tells people to create was the one
  layout it did not know, which meant a host bundled exactly as documented could replay a trace and
  not record one. Fixed here (`recorder_beside`), ranked below `PATH` so the
  [#131](https://github.com/glslang/windbg-mcp/issues/131) override still wins and above the
  machine-wide installs, because the payload beside the executable is the pair to the engine this
  process actually loads. Note the ARM64 bench cannot *demonstrate* the old failure: `TTD.exe` is
  on its `PATH`, which is [#132](https://github.com/glslang/windbg-mcp/issues/132)'s own stated
  workaround — "the recorder is a plain executable and can be extracted to any directory on
  `PATH`". That is the workaround this removes the need for, and since `PATH` is still probed
  first the fix changes nothing on a host that took it. The failure is covered by unit test
  instead, which is also how item 20's ordering is covered and for the same reason.

Picks up at [`setup.md`](./skills/windbg-debugging/setup.md)'s *WinDbg engine + extensions* — the
three sources and the one copy — and its *Unpacking the `.msixbundle`* subsection, plus
[#132](https://github.com/glslang/windbg-mcp/issues/132).

**Nothing left open, and one thing deliberately not done.** `worker::replay_engine_bundled` asks
whether `ttd\` is non-empty and *not* whether its contents match the binary's architecture, which
is a decision rather than a gap: the alternative is a PE read per file against a layout WinDbg owns
and may change. A wrong-architecture copy therefore still surfaces as DbgEng's bare `0x80070057` —
the behaviour without the diagnostic rather than a regression from it — and `setup.md` states the
rule at the point the copy is made, which is the only place it can be acted on. Revisit only if
someone actually lands a mismatched bundle; nobody has.

## 22. [windbg-mcp] Run the debugger tier on an ARM64 runner — **done** (2026-08-16, #134)

Both CI jobs that touch a debugger were `runs-on: windows-latest`, which is x64, while `setup.md`
told readers an ARM64 engine reads an **x64** kernel minidump in full — a claim resting on one
manual session. The debugger tier now runs on both, and only that tier: the crate is
architecture-independent Rust, so `fmt`, clippy and the unit tests have no reason to differ, and
what differs on ARM64 is the engine.

The `Swatinem/rust-cache` key carries the architecture, as this entry said it would have to.

**Two things it did not anticipate, which is why it is kept.**

The first is the reason the entry existed and still cost a correction: the ARM64 run **failed on its
first attempt**, four assertions of forty-five, and the claim in `setup.md` was wrong. The engine
parses the dump — bug check, module list, stack attribution — and cannot read *virtual memory* out
of it, so `walk_memory`, `disassemble` and the `EPROCESS` behind `crash_triage`'s `process_name` all
fail ([#142](https://github.com/glslang/windbg-mcp/issues/142)). Those four were gated to `x86_64`,
because the constraint was taken to belong to the **sample**: the checked-in dump is x64, and on
another architecture they were thought to have nothing to assert.

**That diagnosis was wrong, and the correction is the more useful half of this entry** (2026-08-17,
while capturing the ARM64 dump for [#143](https://github.com/glslang/windbg-mcp/issues/143)). The
architectures are not the variable — **symbols** are. A kernel dump's virtual addresses are
translated through structures the engine locates with `nt`'s symbols, so a host that resolves none
reads the dump's headers and nothing behind them. On an ARM64 host with the SDK's `dbghelp.dll` and
`symsrv.dll` beside the binary, one engine reads the x64 samples *and* an ARM64 one completely —
including the `EPROCESS` and the driver frame at its literal RVA; strip the symbol path from that
same engine and it reads neither. System32 ships `dbghelp.dll` and no `symsrv.dll`, which is why a
runner with nothing beside the binary downloads no PDB and fails these four. The tests now ask the
host — `nt`'s base reading, and a resolved PDB for the two that walk its types — rather than
asking `cfg!(target_arch)`, and
the ARM64 dump is checked in for the coverage it genuinely adds: an ARM64 *target*, which nothing
else here reads. **Both halves of that question, because they fail apart**, which the ARM64 CI
entry demonstrated on the first attempt: a gate that asked only for the read let the driver-crash
test through on a runner that reads a module base and resolves nothing, where it walked a stack
made of the bug check's own parameters and failed an attribution assertion for an environmental
reason.

The second is a trap with nothing to do with architecture. **Renaming the job removed a required
status check.** `Smoke test (debugger tier)` is a required context in the repository ruleset,
matched by name — so adding `, ${{ matrix.arch }}` did not rename the requirement, it deleted the
only job that could satisfy it, and every PR in the repo would have blocked on a check that can
never report again. It surfaced as a PR that was `MERGEABLE` but `BLOCKED` with nothing failing that
was required. The x64 entry now keeps the original name exactly, so adding a matrix is not a rename.
Worth knowing before touching any job name in this repository, not just this one.

## 23. [windbg-mcp] The listener is transport-complete, not usable-complete — **done** (2026-08-17)

All of it is **done** (2026-08-17): `server_log` reaches a client on any machine with
the records *both* processes made — bounded, and saying so when a record was dropped or evicted
rather than leaving a gap to be read as quiet ([`DECISIONS.md`](./DECISIONS.md) records why it is a
tool rather than MCP's deprecated logging capability); the lease has a **smoke tier** — four
assertions in the protocol tier and one, against a parked kernel attach, in the debugger tier; a
long call reports **progress**; and the listener installs as a **Windows service**.

**Progress notifications — done** (`src/progress.rs`). The milestones were already protocol
messages, so what was added is the route out: a `progressToken` read off the call's `_meta` in
`call_tool`, a task-local sink read on the caller's task and left beside that call's waiter — the
milestones arrive on the session's reader task, where the peer and the token are out of reach — and
a relay that turns each step into `notifications/progress`. Two things it settled that this entry
did not anticipate. `progress` counts **seconds elapsed with no `total`**, because a denominator
would have to be a per-tool budget that in an opener's case does not even cover the 30s worker
handshake before it starts. And the milestones alone would have left the two longest silences
exactly as they were — a parked attach reports `Committed` in the first second and may never report
again, and a pool walk or a `crash_triage` has no milestones at all — so **ten seconds without a
word is itself reported**, which incidentally makes progress a liveness signal a client can extend
its own request timeout on.

**Service installation — done** (`src/service.rs`). `--install-service --listen <addr>` registers
the listener with the SCM as `windbg-mcp`, auto-start, `LocalSystem`; `--uninstall-service` stops it
and removes it. Three things it turned up that the entry did not anticipate.

The **stop** is the whole of the difficulty, and it is why `listen::serve` grew a shutdown future:
nothing else in this server needs one — under stdio the disconnect *is* the signal, and a foreground
listener has nobody to ask it — but a service that is killed rather than asked leaves a
detached-but-halted kernel frozen. The SCM is told `StopPending` with a wait hint sized from what
releasing every worker can actually take, rather than being left on the default.

`LocalSystem` **does not read your `profiles.json`** — its `%USERPROFILE%` is
`C:\Windows\system32\config\systemprofile` — so kernel profiles have to be configured machine-wide
or the service sees none. Verified, not assumed, and `install` says so where an operator will read
it. The token is the same problem one scope out, and machine-scope is a real widening.

And a service has **no console**, so the role writes to `%ProgramData%\windbg-mcp\service.log`: the
`server_log` ring is the better channel, but it is only reachable once the listener is up, which is
exactly the case not worth diagnosing that way.

Verified end to end on the ARM64 bench: installed, started, served an authorised MCP call and
refused an unauthenticated one, **attached a live kernel and was then stopped** — the guest kept
running rather than freezing, and no worker outlived the service.

**What the smoke tier does not reach**, now that there is one: the grace is waited out at 32
seconds because the listener's own floor is the call budget plus `WORKER_READY_TIMEOUT`, and that
30s constant is not configurable — so the test costs 40s of wall clock to assert a timer. Lowering
it would mean making a production constant test-tunable, which is a worse trade than the 40s. Worth
revisiting only if that tier's runtime starts to matter.

Picks up at `src/listen.rs` and the tiers in `tests/mcp_smoke.rs`.

## 24. [windbg-mcp] Spend fewer of the caller's tokens — **done** (2026-08-22)

`docs/token-budget.md` and the two budget tests in `tests/mcp_smoke.rs` measured what this server
costs the model driving it. Nothing had, and the numbers were larger than a careful reading of the
source predicted — 90–130 KB estimated, 358 KB actual. This item is the list of things the
measurement found. None of them is a bug; all of them were invisible.

**Why deferred:** the baseline had to be recorded *before* anything was optimised for it, or every
later fix would be a diff against a number somebody had already tidied. The tests and the golden
landed on their own so that each of the items below can be argued, and measured, separately.

- **`$defs` are inlined per tool** — **done** (2026-08-22), and neither lever this bullet named
  was the one. `schemars` emits each output schema self-contained, so `ErrorCategory` (2,089 B)
  shipped 33 times and the allocator/pool subtree nine: **222,579 B, 69% of all `outputSchema`**,
  duplicated beyond its first copy. Wire and client-parse cost only; no model reads it.

  **The duplication cannot be removed.** MCP gives each tool one `outputSchema` and no document
  above it, and `#/$defs/…` resolves against the schema it appears in, so there is nowhere a client
  could look up a definition another tool declared — "a `list_tools` that emits shared definitions"
  has no reader. And `output_schema = schema_for_output::<T>()` was already on every tool; it names
  the type, not where the type is written.

  What moved was **what gets multiplied**. Measuring the payload found **68% of every `outputSchema`
  byte was a `description`** — 217,423 B of 320,365 B, 55% of the whole answer — so the schemas now
  carry constraints and nothing else (`src/schema.rs`): **394,883 → 177,460 B, model-visible
  unmoved.** `WIRE_CEILING` 460,000 → 205,000. The prose is not lost; it stays in the rustdoc it is
  generated from and in `README.md`'s structured-results table, which is where it is read. Nothing
  reads it in a schema — no model is given one, and `description` is an annotation keyword, so an
  instance that validated before validates now.

  Two things worth carrying. The strip is **structural, not textual**: a field named `description`
  is a property *name*, and dropping every `"description"` key would delete the field rather than
  its documentation — no structured type has such a field today, which is exactly why nothing would
  have reported it. And the same answer does **not** transfer to the input schemas below: there the
  prose is most of what tells a model how to drive the tool.

  **This one had a price** (2026-08-18): adding `PdbInfo`, one optional four-field type on one
  field of `ModuleInfo`, grew the wire by **15,610 B** and model context by **zero**, because
  `ModuleInfo` is embedded in the openers' summary, in `modules` and in the allocator shapes. That
  is the compounding this finding predicted, measured on a change small enough that nobody would
  have thought to look. The multiplier is still there — it is the protocol's — but the same type
  costs roughly a seventh of that now.
- **Six openers carry a byte-identical 13,386 B output schema**, six step tools a byte-identical
  4,433 B one. 89,095 B of the above, and it looked like the cheapest to collapse. It is the same
  protocol fact as the bullet above with the same answer: those schemas are 3,838 B and 1,185 B
  each now, and there is still nowhere to say either of them once.
- **`session_id` was documented in three wordings** — **done**, and the figure in this bullet was
  wrong. It counted the copies inside `outputSchema`, which no model reads; the model-visible total
  was 4,695 B across 32 fields, not 9,514 across 43. One shared wording — plus documenting the five
  heap tools whose `session_id` had none at all — moved the surface **−537 B**. Review then found
  that all three original wordings described only the staleness guard and not the field's actual
  job, which is routing, so the corrected wording gives most of that back: a right description of
  two behaviours is not shorter than a wrong description of one. A number not measured in the
  channel it is claimed for is not a finding, which is worth remembering for the rest of this list.
- **The instructions overran what the client reads** — **done**. 3,147 chars sent against 2,048
  read, so the `debug_batch` paragraph — the one instruction that stops a mutation being left
  half-applied — was charged for on every connection and discarded. Now 1,990 chars with that
  guidance inside the budget, ASCII so characters and bytes cannot diverge, and asserted in the
  protocol tier.
- **`registers` returned 15.9x more JSON than its own text** (9,804 B vs 618 B) — **done**
  (2026-08-22), and the bullet's diagnosis was half of it. `"kind":"int"` and `"subregister":false`
  were 41% of the payload, but measuring it rather than reasoning about it found **64 of the 123
  rows were the vector bank**: DbgEng reports `xmm0/0` … `xmm0/3` as 32-bit pseudo-registers without
  the subregister flag, so they passed a filter meaning "integer, not a view" and sat in an answer
  documented as excluding the vector registers. Now 3,480 B and 5.6x, ceiling 13,500 → 5,000. The
  claim that the text "says the same thing better" was wrong too: `r` prints 17 registers and the
  values carried 123, so the ratio compared two different sets. `modules` is the other half of this
  bullet and is done above.
- **Five tools are a third of the model-visible surface**, and it is their input schemas — **done**
  (2026-08-22) by serving fewer tools rather than smaller ones. `debug_batch` 9,746 B (7,980 of it
  the `StepAction`/`Check` vocabulary), `walk_memory` 4,076, `crash_triage` 2,912,
  `reachable_from_dispatch` 2,628, `server_log` 2,599 — 21,961 B against a median tool of 900 B.
  Unlike the items above this is not waste but one tool honestly describing a rich argument, and
  the levers were design choices: a smaller step vocabulary, a `$ref` the client resolves, or a
  surface that does not offer every tool to every caller.

  **The first bullet's answer does not transfer, and measuring that is what chose between them.**
  Prose came out of the output schemas because nothing read it; prose in an *input* schema is most
  of what tells a model how to drive the tool, and `debug_batch` is where getting that wrong leaves
  a patched byte in a running kernel. Across all 51 tools **74% of the model-visible surface is
  prose** — 24,794 B of tool descriptions, 25,333 B inside the input schemas. The structural
  remainder does not pay for the risk: `"default": null` is 1,744 B (2.6%) and is the only free one,
  since `$schema` is how a client picks a validator dialect and `minimum`/`format` are constraints.
  **~1.7 KB of 67,658** was the whole honest total for trimming, so trimming was not done.

  So the third lever: **`--tools`** (`src/toolset.rs`), a named subset advertised at startup. No
  description loses a word; a caller reading a crash dump stops paying for nine TTD tools and ten
  allocator ones. `session,inspect,crash` is 20 tools / 25,265 B; `crash` is 11 / 15,073 B against
  51 / 67,658 B. A spec names groups, individual tools, or `all`, and anything else is refused at
  startup rather than quietly serving something different. (Every figure in this item is as
  measured on 2026-08-17. Item 41 has since moved all of them — the narrowed surfaces down and the
  whole one up; `docs/token-budget.md` carries today's.)

  Three things it settled that the bullet did not anticipate. **`session` has to be in every
  surface** — every other tool routes by a `session_id` this server is the only issuer of, so a
  surface with `registers` and no opener is not a smaller surface but a broken one; 12,161 B was
  the floor then and `--tools crash` is eleven tools. **A tool that exists and is not served needs its own
  refusal**: rmcp answers `tool not found`, which is what a typo gets, while this is an operator's
  flag the caller cannot see. And **the group table needs joining to the live surface**, because a
  tool added to `src/server.rs` and not put in a group vanishes from every *narrowed* surface while
  the default still carries it — `every_tool_belongs_to_exactly_one_group` is that join, and it
  found `set_symbol_path` missing from the README's tool table on the way in.
- **`modules` had neither a `limit` nor a cap**, alone among the high-volume tools — **done**
  (2026-08-21). Everything else uncapped is raw debugger text — `ttd_calls`, `ttd_memory`,
  `threads`, `execute`, `dx`, `ioctl_trace`, `reachable_from_dispatch` — and `read_memory` returns
  up to ~4 MiB of hex by design (`src/worker.rs:117`). Every cap that existed (`MAX_ROWS`,
  `MAX_NODES`, `MAX_READ_BYTES`) was justified in its own comment as a worker out-of-memory guard;
  `DEFAULT_MODULE_ROWS` is the first whose constraint is the **caller's** context, and it says so
  where it is defined. Default 64 rows, maximum 2000, measured at 12,268 B model / 16,871 B wire
  against 53,933 B / 74,052 B for the whole 227-module table — for 383 B of tool surface, paid once
  a conversation rather than per call.

  Two things it turned on that this bullet did not see. The cap is only safe because the **counts
  are values**: `matched` and `unloaded_matched` were added beside `loaded` so a page can never be
  read as the inventory, which is the same rule `frames_truncated` keeps for a stack. And one
  budget is shared between the loaded and unloaded halves rather than one each — through the
  `split_row_budget` the heap diagnostics already used, whose own test says why: two sections that
  each restart the budget quietly double the ceiling it was chosen to be. Reaching for a cap
  per half was the first thing tried here, and this repo had already argued it down one tool over.

**This item is done.** Every bullet is fixed, measured-and-declined, or answered; what came out of
it was one *new* item — a per-caller tool surface, item 36, itself since closed — rather than
anything left over here.

**Where this bites first is a local model**, whose window is bought in RAM rather than rented:
[`docs/local-model.md`](./docs/local-model.md) is the runbook, and it names the three client-side
knobs the split-plane plan proposed — a tool-surface profile, a per-call response budget, a
text-or-data switch — none of which this server had. The `modules` bullet above is the first of
them landing as a *per-tool* answer rather than a caller-wide one: a response budget one tool at a
time, chosen by whoever owns that tool's shape. Whether the general knob is still wanted is now a
question about the tools that have no bound at all, not about the one that did the most damage.

**Depends on nothing**, but it **collides with item 11**, which proposes adding `structuredContent`
to `ttd_calls`, `ttd_memory` and `driver_object` — three of the highest-volume text-only tools.
Under the client rule measured here, structured content *replaces* the text rather than
supplementing it, so that change is a size decision as much as a typing one, and it also partly
reverses the reasoning in `DECISIONS.md`'s #84 entry ("a second channel, not a replacement"), which
was argued against a Python client and never against a model one. Whichever is done first should
say what it means for the other.

Picks up at [`docs/token-budget.md`](./docs/token-budget.md) and the two budget tests in
`tests/mcp_smoke.rs`.

## 25. [windbg-mcp] The ARM64 CI runner resolves no symbols, so its target reads never run — **done** (2026-08-21, #153)

Since #152 the debugger tier's target-reading assertions decide for themselves whether the host can
support them, and the two CI entries decided differently: on `windows-latest` all four ran and
passed, on `windows-11-arm` all four printed `SKIPPED`. Same code, same dumps.

**The probe the entry asked for answered it, and not the way either the entry or the issue
guessed.** The reasoning here was that Windows ships `dbghelp.dll` in System32 and no `symsrv.dll`
outside the Debugging Tools, so a runner with neither downloads no PDB. Measured on both runners:

- `windows-latest` **has** a `symsrv.dll` in System32, servicing-versioned like an inbox component.
  That, not the kit, is where its stock engine gets its symbol store — which is why it resolves
  symbols with `_NT_SYMBOL_PATH` unset;
- `windows-11-arm` has none anywhere in System32, matching this project's own ARM64 bench;
- **both** images carry the Debugging Tools, `symsrv.dll` and a full `dbgeng.dll` included.

So the deferral rested on a premise that was only half true, and the thing that was supposedly
unavailable was already on the runner's disk. The fix is the issue's option 1, one entry only: copy
the kit's `dbghelp.dll` and `symsrv.dll` beside the binary under test on the ARM64 entry.

**What the entry called a decision about what the job is for turned out to be smaller than that.**
The job's position is that it runs the runner's *stock* engine. `dbgeng.dll` is deliberately not
copied, so it still does — the entry goes on loading the image's own engine, which is the claim it
was matrixed for (#134). What it gains is the symbol *half*, which this repo had already measured
to be all an inbox engine needs. "Stock" was never a single thing anyway: the two images' System32
differ, and that difference alone produced the asymmetry.

**A skip passes, so the fix needed a guard of its own.** The job now fails if either target-read
stand-down appears in the output; without that, a copy that stopped working would read exactly like
a green run — which is the shape of failure this whole item is about.

## 26. [windbg-mcp] No ARM64 driver crash, so frame attribution is asserted only on x64 stacks — **done** (2026-08-21, #154)

`a_driver_crash_names_the_driver_frame_that_analyze_cannot` opened the x64 `MessageManager` dump on
every architecture. It passed there — an engine with symbols reads either dump either way round —
but the arithmetic that turns a captured frame into `module+RVA` off the load base had never been
run against an **ARM64** stack. #143 closed the other three assertions this way and left this one.

**What it needed was a crash produced, and producing it was the whole difficulty.** HEVD wraps its
triggers in `__try/__except`, so every access violation it can raise is caught and returned as a
status: the null dereference returns `STATUS_ACCESS_VIOLATION` with the machine still running, the
non-paged pool overflow returns success, and the UAF double free returns success *twice* and is
detected minutes later on a heap-maintenance worker thread — a `0x13A` whose stack is `nt`-only,
which is precisely the fixture this was not looking for. What SEH cannot catch is a **fail fast**:
`HEVD_IOCTL_BUFFER_OVERFLOW_STACK_GS` compiles its trigger with `/GS`, so overrunning the buffer
corrupts the cookie and the driver's own `__report_gsfailure` raises
`0x139 KERNEL_SECURITY_CHECK_FAILURE` from `mov w0, #2; brk #0xf003`. `docs/samples/082126-7015-01.dmp`.

**The decision the entry said to make first went the other way, and the fixture decided it.**
`HEVD.pdb` ships beside the driver, so the entry expected to choose between keeping the PDB off the
symbol path and asserting the symbolized form. What the capture showed is that the interesting
disagreement is not `symbol` but **`!analyze`**: it names `HEVD` by name, where it calls the
PDB-less `MessageManager` crash `Unknown_Module`. So the pair covers both — for one fixture the
computed frame is the *only* thing that names the driver, and for the other it is checked against
an independent answer.

**And the test is not paired by architecture, which is what the entry proposed.** It is a table run
on every host. Pairing would have meant an ARM64 runner stopped reading the x64 crash it reads
today, trading one architecture's coverage for the other's rather than adding it.

Three faults in `tools/ioctl_harness.ps1` came out of using it for this, all of them Windows
PowerShell 5.1-only and each fatal before an IOCTL was sent: em dashes in a BOM-less UTF-8 file
(decoded in the ANSI code page, so `—` ended a string), `0x80000000` read as a negative Int32 for
the access mask, and an empty `-InputHex` returning `$null` because the pipeline unrolls an empty
array. All three are fixed; a 7-only tool that documents itself as needing no compiler was not
much use on a target that has only 5.1.

## 28. [windbg-mcp] The tenancy gate no longer earned its place — **done** (2026-08-20)

The listener's **lease** was built when the registry was one map for the whole server: handles minted
from it, the cap shared, `end_session` ending whatever it was handed. Serving one client at a time
was the only thing standing between two clients and each other's targets, so the gate was
load-bearing.

Ownership took that job over ([#162](https://github.com/glslang/windbg-mcp/issues/162), merged
2026-08-19) — a handle routes only for its owner, the cap and the closed-session history are per
client, and an `Mcp-Session-Id` another client holds is reported unknown — which left the gate
arbitrating one credential racing *itself*: a second MCP session for one token, refused with a
`409`. **Inside a namespace that is not a boundary**, because both of that credential's MCP sessions
reach the same debug sessions. So the gate is gone, and what it cost is gone with it: a client that
lost its session id to a crash or a restart was told `409` and had to wait out the grace, where
adopting its own sessions was what it wanted and what ownership had made safe.

**Retired, with the clock kept.** The question this item asked was whether idle release
(`WINDBG_MCP_SESSION_IDLE_SECS`, #164) already covers the teardown the lease was kept for. It does
not, and the measurement is two lines of `Sessions`: `release_idle` skips a session with a call
outstanding — which is exactly the parked `attach_kernel` a vanished client leaves behind, since a
park is one call that never returns — and it knows nothing about MCP sessions, so an abandoned one
would stay resident in the service with its id accepted, one per reconnect cycle. `release_leased`
does both. So the lease stays as a **clock**: any request renews it, an expiry releases that
client's sessions and closes its MCP sessions, and the `releasing` refusal stays too, since it is
the sweep's and not the gate's.

**The lease is still armed by an MCP session**, so a `2026-07-28` client still has no clock —
deliberately, now that the credential could carry one. A lease releases everything that credential
holds, busy or not, on the reasoning that a client silent for a grace has gone; a stateless client is
legitimately silent for far longer than 390 seconds, and releasing a live kernel from under a caller
who is thinking is worse than holding an abandoned one for the idle window. `docs/remote-listener.md`
says so where it explains why both mechanisms exist.

**Both rules this item said the deletion must not take with it survived, one of them by becoming
unreachable.**

- An **admitted** request renews an existing deadline and never creates one. It is no longer a rule
  about stateless requests but the whole of what `admit` does, for every request shape — and both
  refusals still return before the renewal, so a stream of wrong session ids cannot hold an
  abandoned client's target open.
- A reservation that minted nothing had to give its **deadline** back. Nothing arms a deadline before
  a settled MCP session exists, so there is no clock for a request that takes nothing to hand back.
  The test that pinned it is now `nothing_arms_a_clock_before_an_mcp_session_exists`.

And the sweep's own safety turned out to be already enforced a layer below the machinery that was
protecting it: a sweep fires only after a whole grace with nothing admitted, and `Lease::new` refuses
a grace shorter than the longest a call can keep a client quiet — so no request of that credential's
can still be in flight when its lease expires. That is what the claim generations and in-flight
epochs were for, one level above the thing being protected, which is the pattern `DECISIONS.md`
already named for this code.

**What went:** `Tenancy` (now `Presence`), the reservation and `claims_issued`, `Admission::Occupied`
and its `409`, `Settled::Stale` and the minted session it had to close, `InFlight`/`leave`/`epoch`,
`farewell`/`try_give_up_for`, `Sessions::busy`, `Arriving`, `mints_no_session` and every read of
`MCP-Protocol-Version`. A credential's MCP sessions became a **set**, because an id recorded for
nobody is one any credential may present — tracking only the newest would have re-opened the hole
the ownership check closes. Ninety lease tests became twenty; the ones that went were about
sequencing a handover that no longer happens.

## 29. [windbg-mcp] The listener smoke tier only ever runs one, unnamed client — **done** (2026-08-20)

Every listener assertion in `tests/mcp_smoke.rs` starts the server with a single
`WINDBG_MCP_LISTEN_TOKEN`, so everything the tier proves is proved for the `local` client alone. The
per-client behaviour — routing, the unknown-handle answer, per-client capacity and history, the
per-client lease and the release that refuses only its own client, the session-id ownership check —
is covered by unit tests in `src/engine.rs`, `src/listen.rs` and `src/client.rs`, and by nothing end
to end.

The gap has already cost one bug: the adoption diagnostic counted `local`'s sessions for a named
client reconnecting, because the count was taken after the identity scope had closed. A unit test
pins the mechanism now, but the call site — an HTTP handler — is still unexercised.

**What would close it:** a tier that starts the listener with two tokens (`…_TOKEN_CI` beside the
unnamed one), opens a session as each, and asserts that neither can see, route to or end the
other's — including the `404` for a request bearing the other's `Mcp-Session-Id`, which is now the
only cross-client refusal there is; then walks one client through open → `DELETE` → reconnect-inside-the-grace and reads the
adoption line back out of `server_log`. All of it is dump-tier work — none of it needs a live
target.

**Why deferred:** the per-client rules are unit-tested at the level they are decided, so this buys
call-site coverage rather than new claims. Picks up at the listener helpers in `tests/mcp_smoke.rs`.

**What landed** (2026-08-20) is the tier this entry asked for —
`two_clients_on_one_listener_keep_their_sessions_to_themselves`: two tokens on one port, a dump open
as each, neither able to see, route to or end the other's, the `404` for a request bearing the
other's `Mcp-Session-Id`, and the adoption line read back out of `server_log` after an
open → `DELETE` → reconnect. **It was not call-site coverage. Its first assertion failed**: both
clients saw both sessions.

**The identity never reached a tool call.** `listen::gate` scopes the caller around
`mcp.handle(req)` — the HTTP task — while rmcp serves a legacy MCP session from a task it
`tokio::spawn`s at `initialize` (`spawn_session_worker`), and a task-local does not cross a spawn.
So every call ran as the default `local`, both clients' sessions were owned by `local`, and the
whole of [#162](https://github.com/glslang/windbg-mcp/issues/162) was correct machinery being handed
the wrong caller — in the transport it was written for. `WindbgServer` now carries the client it was
built for, captured in the listener's service factory (which does run inside the gate's scope) and
re-entered in `call_tool`.

**Worth keeping: "unit-tested where it is decided" is not coverage of the thing being decided.**
Each rule's test supplied the identity itself, so the one input that was wrong in production was the
one input no test ever provided. The reasoning that deferred this item — that it buys call-site
coverage rather than new claims — was sound and still wrong, because the call site was where the
input came from.

## 30. [windbg-mcp] Nothing covers a `2026-07-28` handshake that omits the protocol header — **done** (2026-08-20)

rmcp allows a stateless `initialize` to arrive without `MCP-Protocol-Version` — it is the request
that establishes the revision, so the header is optional on exactly that one. Nothing here drives
that shape: `Listener::stateless_opening` sends the header, and stdio has no headers to omit.

**The mechanism that made it a bug is gone**, which is most of what this item was for. The listener
used to classify a request by that header, so a headerless handshake was read as an *opener*,
reserved, minted nothing, and left its *deadline* armed — a client's own handshake starting a clock
that released whatever it had since opened, one grace later. Item 28 deleted the classification and
the reservation both: nothing arms a deadline before a settled MCP session exists, and the listener
does not read the header at all. What is left to cover is that rmcp serves the shape and that the
server behaves normally afterwards.

**What would close it:** a listener assertion that opens with a headerless `2026-07-28` handshake
and then works normally — a `tools/list` and a `tools/call`. Protocol-tier work, no target needed.

The half that would watch a session *survive the grace* after such a handshake is not: having a
session means an opener (`open_dump`), which means a real engine worker and therefore the **debugger
tier** — the same rule the parked test was moved for. It is also the half that no longer has a
mechanism to catch, so it is worth doing only if the arming rule ever grows a second arm.

**Why deferred:** it buys call-site coverage of a path whose hazard has been deleted rather than
handled. Picks up at the listener helpers in `tests/mcp_smoke.rs`, beside
`the_listener_serves_the_stateless_revision_it_negotiates`.

**What landed** (2026-08-20): `a_stateless_handshake_may_omit_the_protocol_header`, in the place
this entry named. The handshake is served, negotiates the revision out of its body, mints no
`Mcp-Session-Id`, and the `tools/list` and `tools/call` after it are ordinary. Nothing surprising,
which is what the entry predicted — item 28 deleted the mechanism that made this shape dangerous, so
what is pinned here is the shape and not the hazard. The half that would watch a session survive the
grace after such a handshake is still not done, for the reason above: it needs an opener, and so a
worker.

## 31. [windbg-mcp] A service-hosted listener can hold only one client — **done** (2026-08-20)

`Credentials::from_entries` treated a configured `WINDBG_MCP_LISTEN_TOKEN_FILE` as the **only**
credential, and read one token out of it: it loaded that token as `local` and returned, ignoring
every environment token including named ones. That precedence is deliberate and load-bearing — the service installer ACLs the file to
SYSTEM and Administrators precisely because the machine environment is readable by unprivileged
processes, and a variable standing beside it would let a stale or planted one authenticate to a
LocalSystem listener that has `launch` on it.

The consequence was that **the per-client work of [#162](https://github.com/glslang/windbg-mcp/issues/162)
was unreachable in the deployment `docs/remote-listener.md` recommends.** A foreground listener could
hold `local`, `ci` and `laptop`; the service could hold one client, so two agents on one
service-hosted host shared a namespace — which is exactly what ownership was built to stop.

It surfaced from the other end, in review of [#173](https://github.com/glslang/windbg-mcp/pull/173):
a local-model driver must not share a credential with the editor, because a client over the
four-session cap has its oldest idle session reclaimed, so the driver's `open_dump` can evict the
editor's target with nothing naming it. That driver now **requires** a credential of its own rather
than defending against sharing one — which is the right shape, and made this item the only thing
standing between it and the recommended deployment: under the service there was no second credential
to give it.

**What would close it:** a token file that can name more than one client. The obvious shape is the
same one `WINDBG_MCP_PROFILES` already uses for kernel profiles — a JSON object of name to token,
with a bare string still read as `local` so every existing install keeps working. The ACL story is
unchanged, since it is one file either way.

**Why it was deferred:** it is a file-format change to the one file that holds credentials, and it
wanted to land on its own rather than inside a runbook PR.

**What landed.** The obvious shape, as predicted: `client::TokenFile` reads either a **bare token**
— which names `local`, so every file written before this keeps working untouched — or a **JSON
object of client name to token**, the shape `WINDBG_MCP_PROFILES` already uses. A leading `{` is
what tells them apart, which makes "a bare token may not begin with `{`" a rule rather than a guess:
a file that does is refused at startup by name. The precedence is untouched — a configured file is
still the only credential — and `service::install` now copies **every** `WINDBG_MCP_LISTEN_TOKEN*`
variable in the installing shell, writing a bare token for a lone `local` and the object otherwise,
validated through the same `Credentials` the listener builds so a shell that could not start a
foreground listener cannot register a service.

Two things worth carrying:

- **The parse is the same problem `kdconn` solved for profiles, and gets the same answer**: values
  are walked as generic JSON rather than deserialized into a typed map, because serde's type errors
  quote the value they rejected — and every value in this file is a credential. `Credentials` and
  `TokenFile` grew hand-written `Debug`s that print names only, for the same reason `Connection`
  has one.
- **A name-shaped token is a name.** A charset check on client names catches a connection string or
  anything carrying a line break, but it cannot catch an entry written back to front, since a
  bearer token is a perfectly good client name — and that entry configures a client named after
  your token, which the startup line prints. That is not fixable in code; it is why the refusal
  that *is* detectable quotes nothing, and why `docs/remote-listener.md` says which way round the
  file goes.

Review found the two gaps that came of writing the file's rules as *the file's*. A name from the
environment was not held to the charset check, which an install then copies into the file — so a
variable the listener accepted could install cleanly and fail the service at every start; there is
one name rule now, wherever the credential was configured, and the environment is still not read at
all when a file is present. And a repeated key in the file was collapsed by `serde_json::Map` to the
last of the two, silently, which is the shape this module refuses everywhere else — so the object is
deserialized through a visitor that keeps every pair, and a name written twice is a refusal that
names the file. The third finding was the same shape from the writer's side — a token that happens
to begin with `{` cannot go in the file bare, because the reader takes a leading brace as the JSON
shape — and the fix is the general one: the installer asks the reader whether the bare form reads
back as what it meant, rather than restating the rule in a second place. Worth knowing that the
first version of *that* asked the wrong question — it checked the client's name, which a token that
is itself a one-entry object satisfies while carrying a different token — so the round trip is on
the whole credential: exactly one, and it is this token naming `local`. The last one was a *document*
— a JSON example with the file's path commented above it, which does not begin with `{` and is
therefore read as one token spanning four lines. The example lost its comment, and the parse now
refuses, from any source, a token that cannot travel in an `Authorization` header at all — a
listener that accepts one is a listener that accepts nobody.

One finding was taken as a fact rather than as its proposed remedy: a token file written by an
earlier install whose token *begins* with `{` — a braced GUID is the plausible way to have one —
now reads as the JSON shape and stops the service at its next start. The remedy offered was a
format marker or a fallback to the bare reading when the JSON does not parse; both are worse than
the problem. A marker is not unambiguous either, since a token can carry whatever marks the object,
and the fallback rescues that rare file by turning the likely one — a hand-written object with a
typo in it — into one long token that authenticates nobody and explains nothing. So the rule stands
and the refusal carries the way out (`{"local": "<that token>"}`), with the same note in the
changelog and a test pinning it.

**The lesson of the review rounds is one thing said three times.** A rule about a value was
*described* in the code — a name charset, then a line-break test — and each round found the next
character class it had not thought of. The two checks that stopped generating findings are the two
that ask the thing that will actually do the work: the installer asks the reader whether the file
shape round-trips, and `is_presentable` builds the header a client would send and reads it back the
way `authorised` does. Where a rule belongs to something else, deriving it beats restating it.

The end-to-end half is one protocol-tier smoke assertion
(`a_token_file_names_its_own_clients_and_shuts_the_environment_out`): a real listener, a real file
naming two clients, the environment token refused `401`, and both file clients served through a full
handshake.

## 34. [windbg-mcp] A service-hosted listener's clients are fixed at install time — **done** (2026-08-22)

`--install-service` is the **only** writer of `%ProgramData%\windbg-mcp\token`, and it leaves the
file granting `SYSTEM` and `Administrators` *read* — deliberately, since the token is the one thing
between an unprivileged local process and `launch` running its command line as `LocalSystem`. The
SCM then refuses a second registration under the same name. So adding or rotating a client means
`--uninstall-service`, set every credential variable again, `--install-service`, `Start-Service` —
which **drops every session the service holds**, a parked kernel attach included.

Found the hard way (2026-08-22): giving a local-model bench a credential of its own turned into an
attempt to edit that file, which failed on the ACL — correctly. The fallback that worked, and is now
the documented one, is a second *foreground* listener on another port with its own token
([`docs/local-model.md`](./docs/local-model.md)); this item is about the case where the service is
the listener you have.

**The reinstall is not a decision anyone made** — it is what falls out of there being no writer but
the installer. Two properties *were* chosen deliberately, and neither of them requires it: "only the
installer writes this file" becomes "only **this program**, running elevated, writes it", since the
command below is the same binary; and "never write through a file it did not create" survives a
fresh temp created with `create_new` in the same protected directory and renamed over the old one.
So the hardening and the fix are compatible, which is the reason to build the fix rather than
document the dance.

- **What to build, and it is three commands rather than one:** `--add-listen-client <name>`,
  `--remove-listen-client <name>` and `--rotate-listen-client <name>`. Rotation is the one with a
  schedule attached — rotating the *only* credential is today's same uninstall/reinstall — and
  removal is what keeps a bench credential from outliving the bench. Each writes the file the way
  `finish_install` does (a fresh file, `create_new`, the same ACL re-applied), **generates the token
  itself**, and prints only a fingerprint (`sha256:701E4CF3…`). Three things fall out: no reinstall,
  no secret through a shell history or an agent's transcript, and an operation narrow enough to
  allow-list in a permission rule, where "let this write `%ProgramData%` over ssh" is not.
- **The reload is the other half, not a footnote.** `Credentials` is built once at startup
  (`client::Credentials::from_entries`), so a client added under a running service is not admitted
  until the next start — and a *restart* still drops every session, which is most of what makes the
  reinstall unfriendly in the first place. Without a live reload this item is an improvement in
  ergonomics and not in outcome. Preferred mechanism: a **user-defined service control code** the
  command sends after writing, which is explicit, needs no background watcher, and fits the plumbing
  that already handles Stop and Preshutdown. A file watcher is the alternative and costs more: it
  needs the writes to be atomic to be safe, and it mainly serves hand-editing, which the ACL is
  there to discourage. Removing a client that still holds sessions is its own decision — refuse, or
  release them down the path the lease sweep already uses.
- **What not to do:** relax the ACL, or teach the installer to update in place. The refusal to write
  through a file it did not create is what stops an unprivileged user pre-creating the path and
  ending up owning the credential.
- **The second listener is a development workflow, and stays one.** The recipe in
  [`docs/local-model.md`](./docs/local-model.md) is right for a bench — a borrowed box with no
  administrator, a credential that should vanish with the process, a run that must not share a
  process with the listener an editor depends on, a build that is not the installed one — and every
  one of those is a *developer's* problem. It is not an operator's answer and must not become one:
  **if someone running a deployed listener ever has to start a second one to add a client, these
  commands are incomplete.** That is the bar to build against, and the reason the reload above is
  not optional.

**Built as described.** `--add-listen-client <name>`, `--remove-listen-client <name>` and
`--rotate-listen-client <name>` (`src/service.rs`), each generating the token, writing it to the
`--token-out <path>` it requires, and printing only a fingerprint. The write is
`service::write_credentials` — a fresh sibling created with `create_new` in the protected
directory, ACL'd there, renamed over the old name — and `finish_install` now shares it, so the
installer and the commands write that file to one standard and the replacement is atomic for a
service reading it. The reload is user-defined control code **128**, sent by the command and
answered in `serve_as_service`'s handler; it reaches `listen::reloaded`, which re-reads through the
same `credentials()` that decides whether the listener may start at all — so a set that would not
have started it cannot replace the one that did — swaps it into `client::Accepted`, and releases a
departed client's sessions down the lease-sweep path. A removal of the *last* client is refused,
since a listener with no credentials will not start.

**Verified on the ARM64 bench against the installed service** (2026-08-22), one process throughout
(pid 9108, never restarted): `--add-listen-client bench` → the log says `re-read the clients: added
[bench], removed []` and that token completes an MCP `initialize` (`200`, `mcp-session-id`);
`--rotate-listen-client bench` → the old token `401`, the new one `200`; `--remove-listen-client
bench` → `401` again, and the credential file back **byte-for-byte** to its pre-test hash, `local`'s
token untouched and the file returned from the JSON shape to the bare one. Removing `local` (the
only remaining client) was refused.

**What review then corrected** (both bots, on the first commit). The reload was asynchronous while
the command said it was not, so the printed claim is now backed by an acknowledgement the control
handler blocks on — and a re-read that failed comes back as a failed control code, which is an
*error* for the two commands that revoke a credential. A revoked client kept half its state:
`reloaded` released the debug sessions where the sweep does three things, so its MCP sessions stayed
resident and — lease state being keyed by name — a re-added name inherited the ids of whoever held
it before (`Lease::revoked_for` and `Lease::forget`). The `--token-out` ACL went on *after* the
secret; moving it earlier then exposed a close-and-reopen race, so the flag is **gone** — the token
is written into the state directory, which is already `SYSTEM`-and-`Administrators`-only with no
traverse for anyone else, and the choice that generated both findings is deleted rather than patched
a third time. A revocation also had a window a lease expiry does not (`Sessions::revoke`): the token
stops being accepted at the swap, but an opener that authenticated a moment earlier can be seconds
from registering, and a one-pass release cannot see it.

**And then the shape changed rather than growing again.** Three rounds of findings had clustered on
two things — how the secret reaches the operator, which the `--token-out` deletion settled, and
revocation, which by then had four mechanisms of its own and a task with an ordering rule. The
second cluster is gone the same way: a revocation is now **an expiry that does not wait**, so it
sets the lease clock to now and the sweeper does the teardown it was already doing for expired
clients. Deleted with it: the teardown task, its channel, the ordering rule between `forget` and
`unrevoke`, and `Lease::revoked_for`. What is left is a flag on `Presence`, a branch in the sweep,
and the admission gate — which stays, because it is the one thing an expiry genuinely does not need.
A grace is there so a client that went *quiet* can come back to what it left; a revoked credential
is never coming back, so skipping it costs nothing.

**What it did not settle, and is now [#190](https://github.com/glslang/windbg-mcp/issues/190).** A
`Client` is a name, so `--remove-listen-client ci` then `--add-listen-client ci` makes two
credentials that everything keyed on identity — session ownership, routing, lease state, the
revocation gate — treats as one. Four of #189's findings were different consumers of that one
ambiguity, and the four fixes that shipped (a `409` on a revoked presence, a lease that does not
renew for one, an admission gate on the owner name, and lifting that gate on re-add rather than on
an empty release) each narrow the window without closing it: at the moment a session registers there
is nothing in it that says *which* `ci` opened it. Giving `Client` an incarnation would delete all
four rather than add a fifth. **Done** (2026-08-22): identity is `(name, incarnation)`, minted only
where a set of credentials is swapped in — the one place that can tell a name carrying on from a
name being given back — and the name stays the whole of what is rendered. That deleted the `409` a
re-added name used to wait out, `Sessions::unrevoke` and the question of when to lift a gate, and it
closed the residual: an in-flight opener of the revoked credential registers against an identity no
live client shares. Two elevated shells
could each write a whole file from its own snapshot (`token.lock`, `share_mode(0)`). And
`--add-listen-client --token-out C:\x` took `--token-out` as the client *name*, which passes the
name rule since a name may contain `-`.

**What was left alone deliberately.** The ACL, and the refusal to write through a file it did not
create. The environment is still read only by `--install-service`. And the second foreground
listener stays a development workflow — the bar in this item ("if someone running a deployed
listener ever has to start a second one to add a client, these commands are incomplete") is met:
add, revoke and rotate are all in place, and all three take effect without stopping anything.


## 36. [windbg-mcp] The tool surface is server-wide, not per caller — **done** (2026-08-22)

`--tools` (item 24's last bullet) narrows what a run advertises, and it narrows it for *everybody*
on that run. That is the right answer for stdio, which has one client by construction, and it is
the right answer for a listener serving one purpose. It is the wrong shape for the case the
listener was built for: a local model that can hold twenty tools and a hosted client that can hold
fifty-one, pointed at the same Windows box and the same debug sessions, told apart by their bearer
tokens already.

**It was three lines of plumbing and three decisions**, which is what the item predicted: the
identity was already there, `Toolset` was already an instance field beside it, and `listen.rs`'s
factory is the line that sets both. What the work actually was:

- **A per-client spec, from the source that already existed.** `WINDBG_MCP_TOOLS_<NAME>` beside the
  token variable, and a `tools` field in the credential file — where an entry may now be
  `{"token": "…", "tools": "session,crash"}` as well as the bare token it always was.
  `Credentials::build` parses it with the flag's own parser, so a spec the listener would refuse is
  refused at startup rather than served as an empty tool list; `Toolset::parse_from` takes the
  source's rendered name, because the vocabulary is written down in three places now and a refusal
  that always said `--tools` would send an operator to a command line they never typed. A spec
  naming a client with no token is refused on the precedent the item pointed at — the collision
  refusals — since it is a setting that could never take effect.

- **Two-client coverage**, which is the half the item said had bitten before, and it is
  `mcp_smoke::two_clients_on_one_listener_are_served_two_surfaces`: two tokens on one port, two
  `tools/list` answers, on the session-bearing route *and* the stateless one. Protocol tier — a
  tool list and a surface refusal need no target, and the tier's contract is that they must not.

- **`tools/list_changed` is not sent**, and that is the decision rather than a gap. This server
  keeps no peer handle to notify an MCP session through, and `2026-07-28` has no session to notify
  at all, so it would be a guarantee on one revision and silence on the other. A surface is instead
  fixed where the caller is identified — `initialize`, or every request on the stateless
  revision — so a change reaches a client the next time it is identified, one rule for both.
  `--set-listen-client-tools` says so where an operator reads it.

**The run's flag became a default rather than a ceiling.** A client's own spec replaces it, wider or
narrower: intersecting the two can produce a surface neither the operator nor the client ever named,
and "which of these two is in force" is a question with an answer either way, while "what is the
overlap of these two" is not one anybody would predict.

**Two things the change had to correct rather than add.** The refusal for a tool off the surface
told every caller to widen `--tools`, which is the wrong command for a client with an entry of its
own — it now names whichever configuration chose the surface (`Toolset::refusal`, `Chosen`). And
`--add-listen-client` printed "it gets the whole tool surface, as every client here does", which
this makes false; it says what the client is actually served.

Landed in [`src/toolset.rs`](./src/toolset.rs), [`src/client.rs`](./src/client.rs),
[`src/listen.rs`](./src/listen.rs) and [`src/service.rs`](./src/service.rs).

## 37. [windbg-mcp] The credential file has four writers and no reader — **done** (2026-08-23)

`--add-listen-client`, `--remove-listen-client`, `--rotate-listen-client` and now
`--set-listen-client-tools` all edit `%ProgramData%\windbg-mcp\token`, and each prints the whole
roster afterwards — name, token fingerprint, and the `--tools` spec where one is set. There is no
way to ask for that roster **without changing something**. `roster` is a private function with two
call sites, both inside `edit_client`.

That was survivable while every client was identical: the question "who may connect" had one other
answer, the listener's startup line, and a client either connected or did not. Item 36 made it a
question with a second half — *and what is each of them served?* — that an operator now has to
answer before changing a spec, and the only routes to it are to make a change they may not want, or
to read the service's log file and hope the line has not aged out. The file itself grants read to
`SYSTEM` and `Administrators` and is deliberately not theirs to open.

- **What to build:** `--list-listen-clients`. It is `roster` and the existing read half of
  `edit_client` — take the lock, read the file, parse, print — with no write and no reload, so it
  is the one command in the family that changes nothing and could be allow-listed accordingly.
- **The trap is what it must not print.** Not the tokens: a fingerprint is the only comparable
  thing, which is the rule the other four already follow and the reason they are safe to run in a
  transcript. And it must not *invent* one for a client whose entry it could not parse — a file
  that will not start the service has to read as that, not as a shorter roster.
- **It has two sources and only one of them has a command.** A service's clients are in the file;
  a *foreground* listener's are in the environment it was started with, and `edit_client` refuses
  outright where no service is installed. So either this reads whichever applies — which means it
  is not a service command at all — or it says which of the two it is answering for. The same
  asymmetry made a refusal wrong in [#196](https://github.com/glslang/windbg-mcp/pull/196): the
  message for a tool off a client's own surface named the service command alone, and a foreground
  listener's operator could not take that advice.

**Worth doing when** a host has more than one client with more than one surface, which is exactly
the arrangement item 36 exists for — until then the startup line names everything there is to know.
**Not blocked on anything.**

**Built as `--list-listen-clients`** (2026-08-23), and the third bullet is the one that cost more
than a line to get right. The other two fell out as written: the roster is `roster`, so no token
can reach the output, and the parse is the listener's own, so a file with one bad entry refuses
whole rather than printing a shorter list. The source question did not fall out. "Read whichever
applies" is wrong on the host both apply to — a service *and* a developer's foreground bench, which
`docs/remote-listener.md` recommends in the same breath — so the answer is **both, each saying what
it is**: the file where a service is installed, this shell's credentials where none is or where it
carries some anyway, and the shell's half labelled as what a listener started *from here* would
accept rather than what one already running elsewhere does. It reads the environment through
`listen::named_token_file` and not `client::env_credentials` alone, because a shell naming
`WINDBG_MCP_LISTEN_TOKEN_FILE` has its variables ignored by the listener — listing them would be a
roster of credentials nothing accepts.

Two things the entry did not anticipate. **The entry's "take the lock" is wrong**, and review
found it (fifth round): `lock_credentials` opens its file with `create(true)` and nothing else
creates it — not the installer — so a reader that took the lock would write into `%ProgramData%`
on any host where no client edit had yet run, which is the one property this command exists to
have. It buys almost nothing anyway, because `write_credentials` renames a finished file over the
old one, so a read racing an edit sees one complete version or the other. So the reader does not
lock, and the unelevated refusal comes from the credential file's own ACL, which is the object
being protected. (The lock's *message* was stale for a different reason and is fixed with it: it
named three commands of four, item 36 having added the fourth.) And **`--tools` beside it is
refused** rather than ignored, on the rule `--rotate-` and `--remove-listen-client` already follow:
it reads exactly like a filter over the list it is about to print.

A third thing came out of review: the roster is the **file**, and `edit_client` deliberately leaves
a window where the file and the running service disagree — a `--remove` or `--rotate` whose reload
could not be delivered writes the file, exits non-zero, and says the credential may still be
authenticating. An operator checking *that* with this command would have read "`windbg-mcp` holds"
as proof the token was gone. There is no live roster to ask for (a service control code carries a
status back and no data), so the answer is the caveat plus the state the service is in: `in_force`,
three arms, one sentence each. The next round found the *other* half of the same gap, and it is
not the same claim: a credential is in force at the reload every editing command waits for, while a
**surface** is fixed when the client is identified, so a reload that succeeded still leaves a
connected client listing what it listed then. That one is said wherever a client carries a spec of
its own and the service is running. That gate was itself wrong, three rounds later: clearing the
*last* per-client spec leaves a file with no surface in it and a connected client still being
served the old one. So the gate is gone and the sentence is folded into the one clause that was
already about file-versus-service — one rule, true whenever the service is running, rather than two
conditions each with a state it is wrong in.

**Three rounds all landed on that one clause, and they had one cause**: every wrong sentence was a
claim about what the service was *accepting*, made by a command that reads a file. The seam is
bounded rather than open — this service accepts `STOP` and `PRESHUTDOWN` and no pause control, so
the SCM can only put it in four states — so the answer was to enumerate all four and let no arm
claim acceptance where it cannot know it. The catch-all had been claiming "nothing is accepting
anything", which is false of `StopPending`: a stop ends the accept loop and then releases every
target (minutes, on a host holding a live kernel) while the connections already accepted go on
being served by tasks nothing awaits or aborts. The comment in [`src/listen.rs`](./src/listen.rs)
that said those connections "are dropped" is what produced the wrong sentence, and it is now
exact — the shutdown ends the *accepting*, not the serving.

A fourth round found the same shape one sentence over, and it is worth recording as the rule this
command is really under: **it may not assert anything about a process it cannot see.** The empty
environment branch said the service's roster was "the whole of what this host has", which a second
foreground listener on another port — recommended two paragraphs earlier in
`docs/remote-listener.md` — makes false, and which the non-empty branch beside it had always
qualified correctly.

Landed in [`src/service.rs`](./src/service.rs) (`list_clients`, `in_force`, `service_clients`,
`shell_clients`), [`src/listen.rs`](./src/listen.rs) and [`src/main.rs`](./src/main.rs).

## 38. [windbg-mcp] A client command can write a file the installed service cannot read — **done** (2026-08-23)

Item 36 (0.11.0) let a credential file entry be an **object** — `{"bench": {"token": "…", "tools":
"crash"}}` — beside the bare tokens it always held. A service installed from an earlier build
refuses that shape, so `--add-listen-client x --tools …` or `--set-listen-client-tools`, run from a
*newer* copy of this program than the one the SCM starts, writes a file the running service cannot
read.

**Nothing breaks at the time, which is the problem.** The reload only ever swaps in a set that
would have started this listener from cold, so a file it cannot parse changes nothing, says so in
the service log, and the command reports it. The failure is the **next start** — a reboot away from
the cause, and by then the command that caused it is far out of mind.

Measured on the ARM64 bench (2026-08-23) while exercising item 37's listing against a real service:
the installed service was running `target\release` from before item 36 while the client commands
were being run from `target\debug` after it. A fresh install cannot reach this, and neither can an
ordinary upgrade — Windows will not overwrite a running image, so an operator replacing the exe has
already stopped the service. A development tree with two builds in it is the case that does.

- **What to build:** a warning, not an error. [`edit_client`](./src/service.rs) already holds the
  service handle, and `Service::query_config()` returns the `executable_path` the SCM stores, so
  comparing that against `std::env::current_exe()` names the divergence at the moment it matters —
  no new channel, and the same shape as the other notes that command prints. It must not refuse:
  running the command from another copy of the *same* version is legitimate, and this cannot tell
  versions apart, only paths.
- **Not the version.** There is no channel that carries one: the only thing reaching the running
  service is a control code, which returns a status and no data (`FOLLOWUPS.md` item 37 settled
  that). A path comparison is a proxy, and the warning has to be worded as one.

**Worth doing when** a second service-hosted deployment exists, or the next time this tree grows a
third build. Until then `docs/remote-listener.md` says the operational half: replace the exe *and*
restart, and run the client commands from the binary the service runs.
**Not blocked on anything.**

Picks up at [`src/service.rs`](./src/service.rs) (`edit_client`, where the SCM handle is already
open) and [`docs/remote-listener.md`](./docs/remote-listener.md).

**Built as a warning printed by all five client commands** (2026-08-23), and
verified against the real service on the ARM64 bench — installed from `target\release`, told about
by `target\debug`, which is the arrangement the entry was measured in. Four things the entry did not
anticipate, one of which would have shipped a warning that was wrong on every host.

**`query_config()` does not return a path.** The entry says it "returns the `executable_path` the
SCM stores", and the field is called that, but `QueryServiceConfigW` hands back `lpBinaryPathName` —
the whole line the SCM starts, the exe *and* the `--service --listen 127.0.0.1:8765` after it.
Compared against `current_exe()` as it comes, it differs from the running image on **every** host
including every correct one, so the feature would have been a warning that is always wrong: worse
than the silence it replaces, since it trains an operator to ignore the one time it is right. The
image is read back out of the line (`image_in`), which is exact rather than approximate for a
reason worth writing down — `windows-service` escapes the line the way `CommandLineToArgvW` reads
it, and the only characters escaping introduces are `\"` and a doubled trailing `\`, neither of
which a Windows path can hold. So there are two shapes and they are the two the SCM shows: quoted
when the path has a space in it (`WinDefend` on this bench), bare when it does not (this service).

**"`edit_client` already holds the service handle" is a trap rather than a shortcut.** That handle
is opened with `QUERY_STATUS | USER_DEFINED_CONTROL`, the rights the command needs; adding
`QUERY_CONFIG` to it means a host that has narrowed the service's security descriptor cannot run
`--remove-listen-client` at all, because a *warning* wanted a right. The default descriptor grants
that right to Authenticated Users so it would almost always work, which is exactly what makes it
the wrong shape. The config is read on a handle of its own, and a refusal there costs the warning
rather than the command.

**It belongs on the reader too, and the entry scopes it to the writer.** `edit_client` is where the
divergence is *created*, but `--list-listen-clients` (item 37) is where an operator goes when a
service did not come back after a reboot — and the roster it prints is **this** build's reading of
a file **that** build has to read, under a clause (`in_force`) saying the running service re-reads
that file whenever a client command changes it, which on a divergent host it may not be able to do
at all. Silence there is the shape item 37's fourth review round ruled on: it may not assert
anything about a process it cannot see. Both print the warning, each naming its own stake in one
clause; everything after that clause is one string.

**Where it prints is decided by the path that fails.** Beside the notes at the bottom of
`edit_client` it would be skipped exactly when it explains most: a revocation whose reload did not
land returns an error before reaching them, and a service that cannot read the new file is one of
the two ways that reload fails. So it is printed before the change, which also settles the gate the
entry did not raise — a reload that lands *is* proof the other copy read what this one wrote, and
a warning printed first cannot be conditioned on it. It says what was compared rather than what it
concluded, which stays true whatever the reload goes on to do.

Landed in [`src/service.rs`](./src/service.rs) (`image_in`, `same_image`, `foreign_image`, and one
call in each of `edit_client` and `list_clients`) and
[`docs/remote-listener.md`](./docs/remote-listener.md).

## 40. [windbg-mcp] `--tools` narrows the tool list and not the instructions — **done** (2026-08-23)

A client's surface is per credential since [#196](https://github.com/glslang/windbg-mcp/pull/196),
and what that narrows is the **router**: `tools/list` answers with the client's own set, and a call
for anything else is refused by name. The `instructions` string sent at `initialize` is not
narrowed. It is a compile-time constant on `#[rmcp::tool_handler]` in `src/server.rs`, it names
**twenty-one tools**, and every client gets all of it.

Measured on the eval bench (2026-08-23,
[`docs/local-model-eval.md`](./docs/local-model-eval.md)): the `min` client is served **11** tools
and told about **21**, of which **17 it cannot call** — `modules`, `execute`, `decode_ioctl`,
`debug_batch`, the whole TTD family and the whole IOCTL family. Both halves of that are a cost:

- **Wasted turns, and the eval measured them.** Every off-surface call in the grid is one of those
  seventeen — gemma spent a task's entire turn budget re-asking for `debug_batch`, and both control
  rows asked for `modules` and `execute`. The eval first recorded this as models *inventing* tool
  names; they were reading this server's own advertising. The metric is now called `unserved`.
- **Context, on the surface least able to pay it.** 1,990 characters, ~497 tokens, identical for
  every client — of which **59% is sentences naming only tools a `min` client cannot call**, and
  the whole string is ~12% of that client's prompt. `--tools crash` drops 54,000 bytes of schemas
  and keeps every word of the prose selling what it dropped.

**Why it was deferred rather than fixed with the eval.** The fix is not a filter over the existing
text: the prose is sentences, each naming several tools, and cutting by keyword would leave
mangled English in the one string a model reads before anything else. The shape that works is the
same one the tool table already has — a base paragraph plus a fragment per **group**, assembled for
the client's own `Toolset`, so `crash` gets the base and the crash sentence and nothing about TTD.
That is a rewrite of the instructions as data rather than a constant, and it moves a string three
tests assert on (`the_instructions_fit_what_the_client_reads`, the discovery assertion in
`src/server.rs`, and the tool-budget golden).

**Where it picks up — and it did.** `#[rmcp::tool_handler]` supplies `get_info` only when the impl
does not, the same rule `call_tool` already relies on, so the override is a hand-written `get_info`
assembling the text from the surface `WindbgServer` already holds (`crate::client::current()` is
not right here: the surface is captured in the listener's factory).

**The invariant, which is not the one this entry first proposed:** a fragment ships only when
**every tool it names** is served. The first attempt asked whether the fragment's *group* was
served at all, and review caught what that costs — `--tools registers` is a valid spec, and the
inspect sentence names `modules`, `dx` and `execute` in one breath, so a client served one tool of
that family read about three it could not call. That is this item's own defect, reintroduced for
partial surfaces. Each fragment therefore carries the tools it names, `instructions()` requires all
of them, and `instructions_never_name_a_tool_the_client_cannot_call` asserts it over eight specs —
it fails on the group-level predicate, which was checked by putting that predicate back rather than
by reasoning about it.

Two things the entry did not anticipate. **`name` had to move with `instructions`**, because both
are literals on the same attribute and the macro reads them only while generating the `get_info`
that is now hand-written — left behind, the server would introduce itself as `rmcp` at the SDK's
version, which a protocol-tier assertion catches. And **the budget golden moves by seven
characters**: the whole-surface assembly is 1,983 against the constant's 1,990, which is the only
part of this a golden can see. What it cannot see is the direction that mattered — `crash` reading
927 characters instead of 1,990 — so that is asserted with two credentials on one listener, which
is the same shape every other per-client property here needs.

**What it actually bought, measured** (2026-08-24, the five `min` cells of
[`docs/local-model-eval.md`](./docs/local-model-eval.md) re-run against the fix). Unserved calls
went from 17 to 14, and both names that lived nowhere but the instructions — `execute` (3 calls)
and `decode_ioctl` (1) — went to zero and stayed there. The other two did not move: `debug_batch`
(9 calls, then 10) and `modules` (4, then 3), because the tools a `min` client *is* served name
them in their own descriptions. That remainder is item 41.

And **the context half of this entry is smaller than it reads** for anything but a client that
injects the string. The eval's own ollama driver discards `initialize`'s result past the protocol
version, so the three local rows' prompts never carried the 1,990 characters and their token counts
did not move by one. The 12%-of-prompt figure describes a client like Claude Code, whose rows sit
at ~27,500 tokens on this surface — where the saving is ~265 tokens, about 1%. The wasted *turns*
were always the larger cost of the two this item names.

## 41. [windbg-mcp] A served tool's description advertises tools the client is not served — **done** (2026-08-24)

Item 40 narrowed the `instructions` string per client. It is not the only prose a client reads: the
**description of every tool it is served** is the other, and those cross-reference tools that a
narrowed surface has removed. On `--tools crash` (eleven tools) there are five such references,
naming four tools:

| The client is served | and its description names |
| --- | --- |
| `open_dump` | `modules` — "not its module table, which `modules` lists" |
| `interrupt` | `go` — "a broad `s` search, a `go` that …" |
| `interrupt` | `debug_batch` |
| `end_session` | `debug_batch` |
| `crash_triage` | `backtrace` |

`--tools session,inspect,crash` keeps the three on `interrupt` and `end_session`; the whole surface
has none, by definition. Count them with a scan that skips plain `//` comments as well as code:
`interrupt`'s doc block is separated from its `#[rmcp::tool(…)]` by a note to the reader of the
source, so a walk-back that stops at the first non-`///` line misses two of the five — which is how
this entry first said four.

**Measured, on the same bench that found item 40** (2026-08-24): with item 40's fix live, the five
`min` cells still produced **14** unserved calls, and **13 of them** name `modules` or
`debug_batch` — exactly the three descriptions above. The fourteenth, Opus asking for
`list_modules`, is a name this server does not have anywhere, which is the floor this class has:
narrowing every string cannot take it to zero.

**What it took.** The shape item 40 used, moved one level down: a cross-reference comes out of the
doc comment into `TOOL_NOTES` (`src/server.rs`), which pairs the sentence with **every tool it
names**, and `WindbgServer::annotate` appends it in `router()` — after `Toolset::narrow`, so a note
whose own tool was dropped has nothing to attach to. `router()` is what `list_tools`, `get_tool`
and `call_tool` all take, so the surface is applied in one place and the call path pays sixteen
`format!`s it never reads, which is the trade the alternative (a second assembly for listing alone)
would have bought back at the price of a second place to get the surface wrong.

Four things the entry did not anticipate, and the first is why the fix is bigger than the table
above.

**Five was one surface's count, not the class.** Across *every* valid spec there are **22**
(tool, tool-it-names) pairs in **16** descriptions, carried by fifteen sentences. Six of the pairs
are inside one group — `backtrace`, `modules`,
`disassemble` and `dx` all point at `execute`; the three pool tools point at each other — and no
group spec reaches those, only `--tools <single tool>`, which is exactly the case review made this
server honour on item 40. Two more (`step_back` → `step_into`, `step_over_back` → `step_over`) were
invisible to any backtick-based count, because they were written bare.

**"Names a tool" needed a predicate, and both obvious ones are wrong.** Plain word-boundary
containment flags English: this prose says frames are "attributed to modules" and that a stuck
session "does not let go", and a rule that forbids the words *modules* and *go* is not one anyone
can write under. "Inside a backtick span" flags the debugger command a TTD tool quotes —
`dx @$cursession.TTD.Calls(...)` names the command `dx` is built on, not the `dx` tool. What works,
and is now shared with the instructions test: a code span that **is** the name or opens a call with
it (`execute { "command": "k" }`), plus bare-if-underscored, since an underscored name is an
identifier and never an English word. That last half is the only thing that catches `step_back`'s
"Reverse of step_into." — as copyable as any backticked name.

**The budget golden did not have to record a surface**, which this entry expected and used as an
argument against the fix. A note is a `const` appended to the description the macro already built,
so the *whole* surface reads what it read before plus 108 bytes and the golden still records
one row per tool — `docs/token-budget.md`'s per-tool rows keep their meaning. Lifting a trailing
paragraph out of a doc comment costs nothing at all: rmcp joins `///` lines with `\n`, so each
newline becomes a space inside one literal and five of the sixteen tools moved by zero bytes. What
*did* lose its meaning is **additivity of the group table**: `--tools crash` is 14,138 B against the
15,093 its two groups sum to, because narrowing now shortens the descriptions of the tools that
stay as well as dropping the ones it drops.

**Three references were reworded rather than moved**, because a note appends at the end and a
cross-reference in the middle of an argument does not survive the move. `interrupt`'s "a `go` that
has not hit anything" and `walk_memory`'s "a MASM `.for` loop through `execute`" are illustrations
rather than pointers — nobody calls either tool because they read the name there — and
`step_back`/`step_over_back` now name the WinDbg command they reverse (`t`, `p`), which the line
beside them already gives.

**What it cost and what it bought, statically.** The whole surface grows 67,658 → **67,766 B**
(+0.16%), which is the price of keeping the pointer for the client that can follow it. Every
narrowed surface shrinks: `crash` 15,073 → **14,138** (−6.2%), `session,inspect,crash` 25,265 →
**24,445**, and the floor — `session` alone — 12,161 → **11,265**. Off-surface names go to zero on
every spec, asserted two ways: `no_description_names_a_tool_the_client_cannot_call` walks the
tightest surface each tool can be served on (`--tools <that tool>`), which is the whole invariant
rather than a sample of it — a note ships only when its own names are served, so all a wider
surface can add is a sentence already cleared — and `two_clients_on_one_listener_are_served_two_surfaces`
puts `crash` and `session,inspect` on one port, since a golden records one surface and cannot see
the direction that matters. `the_whole_surface_reads_every_note` is the other direction, and is
what stops the fix degenerating into the "delete the cross-reference" option: deleting them would
pass every other assertion here.

**Measured** (2026-08-24, the same five `min` cells re-run against this;
[`docs/local-model-eval.md`](./docs/local-model-eval.md)). **Fourteen unserved calls became six**,
and the composition is the finding rather than the total.

**Every name this server was teaching is gone.** `debug_batch` was ten of the fourteen — gemma's
whole turn budget on one task — and is now zero, which with item 40's `execute` and `decode_ioctl`
empties that category. Harness refusals fall 9 → 4 with it, since `debug_batch` is what the
read-only fence was catching. Every row's prompt shrank too, unlike item 40: a description travels
in `tools/list`, which every row reads, where the `instructions` reach only a client that injects
them — −223 tokens on each ollama row, −307 on both Claude rows.

**But this entry overstated the `modules` calls, and the re-run shows the evidence does not carry
it.** It named `open_dump`'s description as what was advertising them. `open_dump` no longer names
`modules`, checked on the wire, and three calls came anyway — so the description is **not
necessary**. It does not follow that it caused none of the earlier three, because the callers
changed: nemotron, Opus and Sonnet before, qwen, gemma and Opus after, only Opus repeating. An
aggregate holding at three across a different set of models, one sample each, is a coincidence of
composition rather than a rate. Cause was claimed where the evidence supports a contributor.

**Every survivor is on `unloaded_driver`**, the one task whose answer lives in a tool a `crash`
client is not served, and each is a direct reach for a module listing (three `modules`, three
`run_command` carrying the same `lm m nvhda64v`). That is what a floor looks like — the surface
cannot answer the question, so a model that spots the missing capability is right and no prose
change stops it. **The 4 → 0 on answerable tasks does not prove it and was our own double count**:
all four were gemma's `debug_batch`, so they are the row above counted twice, not independent
evidence.

## 42. [windbg-mcp] The eval cannot tell a cause from a coincidence, because n=1 — **done** (2026-08-24)

Three runs of the `min` cells have now produced a correlation that review had to take back, and the
same shape each time: an aggregate that moved (or did not) across cells whose *composition* also
changed, read as though the surface were the only thing varying.

- **#209**: the re-run's cleanest correlation stated as a controlled test, which at one sample per
  cell it cannot be.
- **#212**, twice. `modules` held at 3 → 3 and was read as proving `open_dump`'s description had
  never caused it — but the callers went nemotron/Opus/Sonnet → qwen/gemma/Opus, only Opus
  repeating, so a steady total is composition rather than a rate. And "unserved on answerable tasks
  went 4 → 0" was a **double count**: all four were gemma's `debug_batch`, already counted in the
  row above it.

**What the grid can and cannot answer.** It runs one draw per (model, context, surface, task), which
is enough for what it was built for — failure *modes*, and whether a surface fits at all — and is
not enough for any statement of the form "X caused Y". `docs/local-model-eval.md` says so in as many
words ("one sample per cell is one draw") and that has not stopped three write-ups, mine included,
from reaching past it. The rule is not missing; the grid's shape is what makes it easy to ignore.

**What would close it**, and why it is a different experiment rather than a bigger one: *n* draws of
**one** cell with one thing varied, rather than more cells. The question that actually needs it —
did a description ever contribute to a `modules` call? — is a single A/B: the same model, the same
task, the same surface, with and without the sentence, repeated enough times to see a rate. That is
`local_model_drive.py` in a loop and a seed column in the record, not a change to the matrix runner.
It is deferred because the answer is worth little now: the sentence is gone either way, and the fix
does not depend on which of the two it was.

**Where it picks up.** The grader already keeps the last record per (cell, task), which is the thing
that would have to change first — repeated draws need to accumulate rather than replace. Give the
record a `draw` index, key on it, and report a distribution instead of a mark.

**What landed** (2026-08-24), which is the capability rather than the experiment — the A/B it was
written for is still not worth running, for the reason above. A record carries `draw` and `seed`
from both backends; a cell group asks for repeats with `draws: n`, which is a loop around the cell
and not a fourth axis; and every reader keys on the draw index, so `already_done` resumes per draw
(3 done and 5 asked for runs 4 and 5), `records` accumulates instead of keeping the last, and
`--matrix` prints `3Y2n` where it printed `Y`. **A record with no `draw` is draw 1** (`draw_of`),
so a run already recorded grades to exactly what it graded to — checked against the two logs this
bench still has, whose `--grade` and `--matrix` output is byte-identical either side of the
change.

**Two things the entry did not see.** The first is a measurement that contradicts it: *"a seed
column in the record"* was written on the assumption that a seeded draw can be replayed, and on
this bench it cannot — four identical requests to `qwen3.8:27b-mlx` under `seed: 7` returned four
different answers (ollama 0.32.15, MLX). The seed is still sent and recorded — sending it costs
nothing, and a runtime that does reproduce under it would pair the arms of an A/B — but every
sentence around it now says the column is what was *asked for*. Unmeasured, it would have shipped
as a replay guarantee in the comments and in all three documents this touched. The second is smaller and is the deletion trap in reverse:
the rule that a cell-level failure note is superseded by later records of that cell had to learn
about draws too, or draw 4 dying would be un-recorded by draw 5 completing afterwards.

## 43. [windbg-mcp] `unserved` is two different measurements sharing a column — **done** (2026-08-25)

The metric was renamed from `hallucinated` when the first grid found that a model asking for a tool
it could not call was usually reading this server's own advertising. Items 40 and 41 removed that
advertising, and the number that remains is no longer measuring the same thing:

- **Names this server taught.** `execute`, `decode_ioctl` (item 40), `debug_batch` (item 41). Now
  **zero**, and a regression here is a defect in this server.
- **Capabilities the surface does not have.** The six survivors, all on `unloaded_driver`, whose
  answer lives in `modules`'s `unloaded` list — three asking for `modules` and three for
  `run_command`, which does not exist. A model that spots a missing capability and reaches for it is
  *right*; the surface is what says no.

Summed, they hide each other: the first going to zero looks like a 57% improvement rather than an
elimination, and the second could grow without anything being wrong. The task's own `possible_on`
already carries what separates them, so this is a grader change and not a new measurement — split
the column into `taught` and `wanted`, and let a regression test assert only the first.

**Why it was deferred, and what changed.** The argument was that `taught` was zero, so the sum
happened to be the interesting number by accident, and the split would re-grade runs to prove a
partition no present data disagreed with. Both halves of that turned out to be wrong: `taught` was
not zero (the paragraphs below), and the re-grade is what *demonstrates* the partition rather than
what costs it — the two logs on disk split **4+10** and **0+6**, so item 41's fix reads as an
elimination of the half it was aimed at rather than a 57% improvement in a total.

**What landed.** `possible` already said whether the answer key was reachable on this surface, so
the split is that predicate and no new measurement: `taught` when the task *was* answerable here
and the model still reached off-surface, `wanted` when it was not. The table prints `t+n` in the
slot that held one number, so the sum stays readable and the halves stop hiding each other.
`--grade --assert-no-taught` exits non-zero on a taught call, which is the regression this item
asked for; `wanted` is deliberately not assertable, being a property of the task list and the
surface rather than of this server. And `taught` prints its offenders by name — "`debug_batch` on
`arm64_pc`" is checkable, where "taught: 4" is a number to argue about.

**What the split does not do**, stated here because the entry that proposed it did not know yet:
it attributes by **need, not provenance**. This server taught `modules` through an opener's result
until [#217](https://github.com/glslang/windbg-mcp/pull/217), on `unloaded_driver`, which is also a
task `min` cannot answer — so those calls are `wanted`. `taught` is a lower bound on advertising
and `wanted` an upper bound on need. Separating them properly needs one cell repeated with the
sentence varied, which is item 42's `draws` and not a fourth column.

**A third channel was checked, and the checking is worth more than the result** (2026-08-24,
prompted by the reasonable question of how a model on an eleven-tool surface produces the *exact*
name `modules` with its real `filter` argument). Items 40 and 41 closed the `instructions` string
and the tool descriptions; nobody had looked at what a **result** says, which is the third thing a
model reads and the only one that arrives on every call.

**The first scan reported "none" without having compared anything.** It read each call's `text`,
and a call record carries `excerpt` — so the loop body never ran, and "none" meant "nothing was
looked at". The number quoted beside it was audited and the scan behind it was not: a "59-name
superset" is 51 tool names plus the eight JSON field names (`annotations`, `description`,
`instructions`, `name`, `payload`, `tools`, `totals`, `wire`) that a recursive walk of
`tests/golden/tool_budget.json` picks up, which Codex asked about on
[#216](https://github.com/glslang/windbg-mcp/pull/216) and which is how the empty loop surfaced.
The rule underneath is the one this repo already writes down twice — *a grep is not an
enumeration*, and a monitor's *silence is not success*: *a scan that can only print on a hit proves
nothing until it has been shown printing on a known one.*

**Redone against `excerpt`, sixteen results do name a tool their client is not served — and every
one is the model's own request coming back.** Nine are the ollama driver's own refusal — the one
that names the tool it is refusing, "`debug_batch` is not permitted in this harness" — four are
Claude Code's "No such tool available: `mcp__windbg__…`", and three are **this server's**
`-32602`. Nothing is *introduced* **in the part of a result the log kept** — and the qualifier is
the whole finding, because outside it something was.

**It was wrong, and the truncation bound is what was hiding it** (2026-08-25, one day later). An
opener's summary ended with "`modules` lists a page of the table and `modules {"filter":
"<name>"}` answers for one", built by `summary_text` in the **worker** — which owns one session and
has never heard of a client, let alone its surface. `modules` is `inspect`, so on the bench's own
eleven-tool `crash` surface the *first result a client ever saw* handed it the exact name together
with its real argument. `crash_triage` rode along the same way, and `post_commit_failure` sent any
caller to `execute`. So `taught` was **not** zero on this channel; it was the largest of the three,
and it is the one that arrives on every call rather than once a conversation.

Three things about how it stayed hidden, each of which is the real lesson:

- **The scan could not have found it.** The excerpt is 300 characters of a 2,508-character summary,
  and the sentence is at the end. Codex's round-2 bound was not a hedge about a hypothetical; it was
  a description of where this was sitting.
- **What found it took no run at all.** The question is what this server *prints*, not what a model
  does with it, so it is answerable by reading `src/` — a scan of string literals against the tool
  table, seconds on a laptop, no bench and no VM. Two channels' worth of eval work had been spent
  on a question that was static all along.
- **The eval's `modules` calls have a documented cause now**, so the "a mixture is what guessing
  looks like" reading above is undercut for `modules` specifically: the name and its `filter`
  argument were both in front of the model. The invented ones (`list_modules`, `run_command`) still
  read as guesses, but that is a claim about the survivors, not about the three.

Fixed by `SUMMARY_NOTES` and `WindbgServer::annotated_report` — [`ToolNote`]'s rule one channel
over, with `no_opener_report_names_a_tool_the_client_cannot_call` as its invariant. The same scan
found two more: a post-commit failure's `execute` example, and `crash_triage`'s user-mode refusal,
which pointed at `backtrace` and `execute` — both `inspect`, while `crash_triage` is `crash`, so
the caller most likely to reach it could act on neither half. A third was left alone as
unreachable: the "a `debug_batch` is running its rollback" message needs a client served
`debug_batch` to have started one.

**What is still open here** is the count, not the leak. `unserved` is still one number, and the
three runs on disk cannot be re-graded into `taught` and `wanted` — but the partition now has a
known instance on the `taught` side rather than none, which is the evidence the entry above says
it was missing. The next run against a prose change is where it gets made.

**That is zero within the prefixes the log keeps, and it cannot be stated wider than that**
(Codex's second round on #216, and correct). `local_model_drive.py` records `text[:300]`, so 96 of
the 114 results are truncated and 29,946 characters of a 208,266-character corpus were compared: a
name mentioned late in a long module listing is invisible to this scan by construction.

**The whole-result version needs no new code, and it is not the same corpus** — the third round of
the same review, also correct. `Recorder::tool_result` writes each result's text into the server
transcript, scrubbed then capped, and `WINDBG_MCP_TRANSCRIPT_MAX_FIELD=0` lifts the cap, so
`WINDBG_MCP_TRANSCRIPT` on the bench listener records every *served* call's result whole. It
records none of the sixteen: an off-surface call is refused at the top of `WindbgServer::dispatch`
(`src/server.rs`) and returns before `rec.tool_request` runs, and the other two refusals are the
ollama driver's and Claude Code's, which never reach this server at all. That is not a gap in the
answer, because those three classes are exactly the ones that **cannot** introduce a name: each
quotes the tool the caller just asked for, and ours adds only group names — a group that is also a
tool name is refused outright (`src/toolset.rs`) — and, for a partly-held group,
tools the client *is* served. So the transcript covers the bodies, which is where an introduction
could hide; the eval log covers the refusals, which are echoes by construction; a scan wanting the
model's whole view reads both.

**And a transcript scan can only over-count, which is why a null from it still means something**
(fourth round, same reviewer). The transcript holds *both* halves of a result, and a client that
understands structured results forwards `structuredContent` and drops the rendering — a forwarding
policy, not protocol, which `tool_results_stay_within_their_budget` exists to keep both sides of and
which applies to the 31 tools that have an output schema. So a name living only in the half the
client discarded was never read by the model, and a transcript hit is a *candidate* rather than a
sighting. It bites the two Claude Code rows and not the three ollama ones, whose driver appends the
result's text verbatim as the tool message. The consequence is one-directional and worth stating in
the entry that plans the scan: a **null** result from the transcript is sound, since neither half
named anything; a **positive** has to be checked against which half that client forwarded, and
capturing the whole `tool_result` in `claude_code_drive.py` is what would settle it without
reproducing a policy that can change under us.

What no route reaches is *these* two runs: nothing kept the bytes the driver discarded, so this one
cannot be answered backwards.

Names have to be matched the way
`no_description_names_a_tool_the_client_cannot_call` matches them — bare if the name has an
underscore, in call context otherwise — because plain containment scores `execute` eight times
inside `ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY` and "the attempted execute", and because a
lookbehind of `[A-Za-z0-9_]` silently drops `mcp__windbg__debug_batch`.

**The one of those three that is ours is not neutral, and the split has no box for it.**
`Toolset::refusal` (`src/toolset.rs`) answers a narrowed client with "`modules` is a tool this
server has, but it is not on the surface it serves `min` (11 of 51 tools (session, crash))", and
then how to widen it. That is deliberate, and the doc comment says why: the reader it is written
for is an operator who can see neither this server's command line nor its client list. On the
bench the reader is the model, and what it gets is a **guessed name confirmed as real**, beside the
surface's group names and the size of the full one. It teaches no name — the model supplied it — so
it is not `taught`; it is not nothing either. A third count, *a refusal that says yes*, is what
this channel would contribute to the split. In these logs it changed no behaviour — nobody retried
a name after being told it was real: gemma went from `modules` to `run_command` three times and
opus to `list_modules`, while the retries that did happen (`debug_batch` five times, then four)
follow the *driver's* refusal, which confirms nothing. That is one draw per cell, though, and a
retry is precisely what the confirmation would buy.

**What the survivors' *shape* says, and where it stops.** The names asked for are a mixture of real
and invented — `modules` (3) beside `list_modules` (1) before item 41, and `modules` (3) beside
`run_command` (3) after it, the latter carrying `{"command": "lm m nvhda64v"}`, which is the right
idea under a name this server does not have. A model copying an advertisement produces exact names
only; a mixture is what guessing looks like, which is evidence for the `wanted` reading of the
remainder. Two things keep it from being proof. The *concept* is still on the narrow surface even
though the name is not — `open_dump` ends "…module count and the bug check a crash dump stopped on
— not its module table", and the task prompt says "how many **modules** are loaded" — so a model is
told a module table exists and has to name a tool for it. And this is a public repository, so
prior exposure cannot be excluded at one draw per cell. Separating memorised-from-GitHub from
guessed-by-convention is item 42's machinery (the same cell repeated with that sentence varied),
not this item's.

## 44. [windbg-mcp] `arm64_pc` is answered the way it reads, not the way it is keyed — **done** (2026-08-25)

The eval's `arm64_pc` task asked for "the value of the `pc` register at the point of the crash" on
the ARM64 sample, and its key is `0xfffff8013c65bca8`. **Across the 35 runs of it in the three logs
still on disk, no model on any surface gave that answer, and 32 gave `0x0000019e7b820000`** — the
bug check's first parameter. Five draws of five models on `min` (2026-08-25) is `5n` in every row,
frontier rows included, which is what made it visible: at one draw per cell it read as a hard task.

**It has been answered correctly once**, in the original grid — qwen, reasoning that frame 0 of the
bug-check stack *is* the `pc`, which is exactly the route the key wants and is written up in
`docs/local-model-eval.md`. That log is no longer on disk, so the honest figure is roughly one in
fifty rather than none in thirty-five (Codex caught the stronger claim on
[#219](https://github.com/glslang/windbg-mcp/pull/219), against this repo's own published text).
It matters in the right direction: the task *is* reachable and the route *does* work, so what is
wrong is only that almost nobody reads the question that way.

**Both answers are defensible, and the debugger says so.** Measured on the dump:

- `registers` reports `pc = 0xfffff8013c65bca8`, and `crash_triage` frame 0 is the same address,
  `nt!KeBugCheck2+0x2e8`. So the key is literally right and the note claiming `min` can reach it
  through frame 0 is right too - the route works.
- That address is inside the **bug-check path**, which the machine reached *after* the fault. The
  address whose execution faulted is parameter 1, `0x0000019e7b820000` (also in `x24`), and
  `nt!MiCheckSystemNxFault` two frames up is the handler for exactly that.

So a model answering "the pc at the point of the crash" with the faulting address is reading the
question the way a person would, and the key wants the register's literal value in a context that
is not the crash. **A task passed once in about fifty attempts is measuring its own wording**, not
the surface it was written to probe.

**What landed.** The prompt, not the key: it now asks for "what value the pc register holds in the
crash context the dump saved - the register's own value as the debugger reports it, not an address
taken from the bug check's parameters". Widening `expect` to accept parameter 1 stayed rejected for
the reason above, and re-measuring on the dump gave it a second one this entry had not stated:
`open_dump`'s summary carries all four parameters, so a key accepting parameter 1 would let the
task pass off the *opener's* result with neither `registers` nor `crash_triage` called - the exact
route it exists to check would be the one route not taken.

**The entry's own suggested wording was not enough, and that is a judgement rather than a
measurement.** "In the crash context, as the debugger reports it" removes the phrase that invites
the faulting-address reading, but it leaves the reading itself available to a model that believes
the bug check's parameter *is* the `pc` - which is what 32 of the 35 recorded runs believed. So the
prompt names what the answer is not. That cannot hand the answer over, and it keeps the tool route
required; what it costs is that the question now mentions the bug check at all. Nobody has measured
the shorter wording, and what would settle it is item 42's `draws` on one cell with the sentence
varied - the same A/B this bench keeps deferring.

**Re-verified before rewriting anything**, since the numbers above were the whole argument and
were inherited rather than measured here. Both dump readings again, and the log breakdown finer
than "no model gave that answer": of the 35 runs, **0** gave the key, **32** gave parameter 1, and
the remaining **3** answered nothing at all - two closing the session and reporting that, one
empty. So the split is not 33 wrong readings and 2 failures; every run that produced an answer
produced the same wrong one.

**The other five were checked, and none has it - but the corpus only stretches to four.** The three
logs are `min` cells, so `unloaded_driver` and `ioctl_decode` have no answers in them at all
(neither is answerable on that surface); those two were checked by reading the prompt against the
key. The other three grade **33 of 35** correct each, and all six failures between them are
non-answers or noise - three that closed the session and said so, one empty, one turn that ran out
mid-narration, one invented module count - rather than a second reading anything agreed on.

**`driver_blame` is the near miss, and it is what sharpened the rule.** It asks "at what offset into
that driver did it fault", and the key `0x1654` is frame 7: the address `nt!ExFreePoolWithTag`
returns to, not an instruction that itself faulted. So the prompt is loose in exactly the way
`arm64_pc` was - and it is *not* the same defect, because no model takes the other reading: 33 of
35 give the key, and `crash_triage` calls that frame `faulting_frame`, which is the vocabulary the
question borrowed in the first place. **A wording defect shows up as agreement on a different
answer, not as imprecision**, which is the check to run rather than re-reading prompts for rigour.
Recorded in that task's `note` rather than fixed, so its published numbers stay comparable.

**A reworded task un-grades its own history, which review caught and the first attempt had not**
([#220](https://github.com/glslang/windbg-mcp/pull/220), Codex). `usable()` drops any record whose
stored `prompt` differs from the one the suite asks now - deliberate machinery, added when this
bench reworded `unloaded_driver` mid-flight - so changing the live suite quietly took `arm64_pc`
out of every checked-in plan. Measured on `after-217.jsonl`: the denominator went **20 to 15** per
cell and 25 of the 150 records became `UNCOUNTED`. Worse, a *resume* of either checked-in plan
would re-run the task and append new-wording answers under the same `(cell, draw, task)` key as the
old ones, where `records()` keeps the later - one log, two experiments, nothing saying so. **A
run's identity includes the question it asked**, so the old wording is frozen as
`tools/eval_tasks_v1.json` and both historical plans name it: `after-217.jsonl` grades to 20 again
and resume counts 150 of 150 done. The live suite is `v2`. And the one uncounted reason a reader
can *act* on now says so under the table, since a served window that was not the one asked for is
unrecoverable while a changed question is only the wrong suite - `stale_prompt` is split out of
`usable` rather than restated inside it, so the predicate keeps one home.

**My own verification of this was wrong, and the way it was wrong is worth keeping.** "Grades
unchanged" was checked by running `--grade` and reading the numerators, which did match. The
denominators did not, and the rows said `UNCOUNTED x5` in plain sight. Re-grading proves nothing
unless the comparison is against the *previous output* rather than against expectations.

**Where the published numbers stand.** `docs/local-model-eval.md` now says, once and above every
table, that every score in it was graded against the old wording and is not comparable with a run
against the new one on this task. The suite `note` in `tools/eval_tasks.json` says the same for
anyone reading the task file first. Nothing about the server was wrong here, so the grid's *server*
findings (items 40, 41, 43, and #217) are unaffected, and the next run starts against a question
with one reading.

## 45. [windbg-mcp] The eval's answer key is a snapshot, and nothing checks it still holds — **done** (2026-08-25)

The six tasks are graded against facts read off the checked-in dumps **with this server's own
tools**, before any model saw them. That is what makes the bench mechanical, and it is also the
whole exposure: if one of those facts stops being what the server reports, the suite keeps grading,
every model keeps scoring, and the number measures nothing. A key that rots is indistinguishable
from a model that got worse.

**Part of it was already pinned, in `tests/mcp_smoke.rs`** — the debugger tier reads the same dumps
and asserts bug check code and name, `Arg1`, the crashing process, and each driver crash's
`module` + `rva` + kernel frame (`DRIVER_CRASHES`, `NATIVE_SAMPLE`). What was *not* pinned was the
rest of what the tasks depend on:

| Fact a task is keyed to | Asserted by the tier? |
| --- | --- |
| bug check `0x13a` / `0x9f`, and the names | yes |
| `MessageManager+0x1654` | yes |
| `nvhda64v.sys` unloaded | yes, as a **relation** — not the **26** records `unloaded_driver` asks for |
| module counts **227** / **158** / **177** | no |
| the four `0x22200B` fields | no — the tier exercises `0x70000` |
| `pc = 0xfffff8013c65bca8` | **no** |

**The last row is the one that made the case**, and it is exactly item 44 wearing its other face.
`NATIVE_SAMPLE` pins `first_parameter: "0x0000019e7b820000"` — the address 32 of 35 recorded runs
gave — while nothing in this repo pinned the `pc` the task is actually keyed to. Both halves of the
ambiguity are named in the codebase, in two different files, and the half the eval depends on was
the unasserted one.

**What closed it.** `--verify-key`, beside `--grade` in `tools/local_model_eval.py`, driving the
server and re-reading every fact through the tools a model would call. That was the first of the
three shapes this entry weighed, and the argument for it is unchanged: the oracle is `present()`,
whose three rules were each learned from a wrong verdict, so a Rust gate would need a **second copy
of it** — and two copies drifting apart is this item's own failure mode reached through this item's
own fix. The cost taken deliberately is that CI cannot run it: it needs a listener and a
credential, so it is a command for after a `dbgscope` bump, a symbol-path change or a new sample,
and the run says so on every pass. The Rust tier goes on pinning what it already pins.

**The binding is per task and carries the inputs**, which is what review found this entry lacking
and what defeated all three shapes as first written: `expect` said what an answer must contain and
nothing structured said what to *call* to get it. Each task now carries `verify` — an ordered list
of `(tool, args)` steps with the values expected back — and the prompt is checked as a **rendering**
of it: every string a step sends must appear in the question, and every dump the question names
must be one a step opens. A prompt repointed at another sample is now a failure rather than a
verifier quietly querying the old one.

**Three things it needed that this entry did not anticipate.**

- **`expect` cannot be *derived* from the binding**, which is what this entry's own sentence
  claimed. Two of `unloaded_driver`'s three groups are phrasings of a **relation** — "not loaded"
  is what `matched: 0` *means*, not a string the server prints — so the binding **grounds**
  `expect` rather than generating it, and each run reports which groups are tied by `value`, which
  by `relation`, and which were `skipped` at a gate on this host. The relation groups are not a
  hole: the fact behind them is pinned exactly, and only the phrasing is beyond a mechanical check.
  **But which groups those are has to be declared, not inferred** — a correction review made, and
  the sharpest finding on the PR. Reading "no pinned value matched" *as* a relation meant a group
  edited to a value the tools do not answer (`ACCESS_VIOLATION` for a bug check that is
  `KERNEL_MODE_HEAP_CORRUPTION`) reported `relation` and passed: a broken key, against which every
  model would be graded wrong, reached through the very mode meant to catch one. So `grounds` is a
  value claim and **fails** when nothing renders it, `states` is the declared-relational one, and
  the exemption covers the two groups that earn it rather than spreading to whatever happens not to
  match. The next round found the same hole pointed the other way — *appending* an alternative
  beside one that still matches widens what the grader accepts while the run stays green — so a
  `grounds` group is checked **alternative by alternative**: each must render, or be a *spelling*
  of one that does (letters and digits only). That is what lets the suite keep `heap corruption`
  beside `heap_corruption`, and refuses `access_violation` as a second fact rather than a second
  spelling.
- **A second verb, for a tool with no structured half.** `decode_ioctl` answers in prose alone, so
  a binding that could only name a field would have had nothing to say about the one task needing
  no target at all — the cheapest half this entry singled out. `is` is exact typed equality against
  a named field; `has` is `present()` over the text, used exactly once.
- **The ratchet is coverage, not the pins.** A group **no** step grounds is a failure, which is what
  stops `expect` growing an alternative the binding does not fetch, and stops a new task arriving
  unpinned. Verified against a deliberately rotted copy of the suite: a moved fact, a renamed
  field, a repointed prompt, an ungrounded group, a group edited to something the server does not
  say, a group widened to also accept something else, a relation whose supporting pin was
  deleted, a gated step ordered before its opener, and a stale text pin all fail — nine channels —
  and the clean suite passes. Five rounds found one shape — a value that could not be obtained read
  as a benign default — in five places, so the choice generating it was deleted rather than patched
  a fifth time: one helper reads a structured field and answers a value or a reason, and nothing in
  this mode carries an `or []`. A sixth round found the last place it could hide - a renamed
  `symbols` on the `nt` record reads as `None`, which is not a PDB-backed state and so closed the
  gate on drift - and two blind spots in the cleanup this mode had newly come to depend on: the
  driver's `end_sessions` read a structured tool error but not a top-level protocol one, and
  `close_transport_session` printed a failed `DELETE` without reporting it. Both are fixed in the
  driver rather than worked around here, since three callers share them. A seventh round took the
  same rule to its end - a `symbols` that is no longer a *string* would have read as "no PDB" - and
  found that the pins themselves were laxer than their own docstring: Python's `==` accepts
  `False == 0` and `227.0 == 227`, so a `matched` turning from the integer `0` into `false` passed
  the pin *and* the relation resting on it. Types are compared now. Half of that round's remedy
  was declined: checking `symbols` against a *recognized* set would fail on a state dbgscope
  legitimately adds, and a new symbol state is not a rotted key.
- **A task nothing checked is not a task that passed**, which an eighth round caught and which the
  gating design had quietly licensed. `driver_blame`'s only fact-checking step is gated, so on a
  symbol-poor host every group of it stands down and the run printed that every fact the suite
  grades against still reads off the dumps - having read none of that task's. It is `INCOMPLETE` by
  name and non-zero now, kept apart from key rot in the wording, since the key has not moved and
  this host cannot say either way. `arm64_pc` is the contrast that made the rule easy to state: its
  `registers` route is ungated, so one half standing down still leaves the fact verified. The
  gate's stood-down sentence also stopped claiming "the facts behind this step are asserted through
  their other route", which is true of one of those two tasks and false of the other.
- **The unit is the `expect` group, not the task** - a refinement the round after made, and the
  reason it matters is that a task can come back *mixed*: one group grounded by an ungated step and
  another only by a gated one. Treating that as verified reports a graded fact as checked having
  read nothing of it. And an **empty suite** is not a verified one, which the same round caught:
  the run printed "every fact 0 tasks are graded against still reads off the dumps" and exited
  zero, so a file an edit had emptied was indistinguishable from a key that holds.
- **And a task with no `expect` at all** is the unpinned hole at the other end, found a round later:
  `matches()` runs `all()` over the group list and `all([])` is true, so such a task grades *every*
  non-empty answer correct - while a suite with no groups also has no ungrounded ones, so nothing
  downstream complained. It is refused beside the unbound ones.

**And a pin can be too tight.** The first cut pinned the `pc` register as `registers.32.value` —
its position in the ARM64 bank, which is an engine detail rather than anything the key rests on, so
a reordered bank would have failed a key that had not rotted. A `read` path now enters a list two
ways: `frames.0` by position, `registers.name=pc.value` by the register's own name.

**Which corpus, said rather than implied.** The run names the dumps it re-read and then names the
one it did not: `answer_key` is prose and nothing reads it — `grep` still finds no consumer, and
`matches()` grades from `expect` alone — and it documents `082126-7015-01.dmp`, which no task
references. Reporting the gap is the honest form of the choice, rather than a test covering more
than the suite asks or less than the key claims.

**And the gate is per dump, not per host** — the second thing review caught, and this repo already
had the measurement: `docs/smoke-test.md` records an engine failing *differently per dump*, because
each sample has its own `nt` with its own PDB identity. A gate probed once off the first opener
would therefore have stood the ARM64 frame-0 step down because an *x64* PDB was missing, and
reported success without checking the route `arm64_pc`'s `possible_on: min` rests on. It is asked
of each task's own session now, as the Rust tier asks it — and **a probe that fails is not a closed
gate**, which the round after that caught: a gate that closes stands its steps down and *passes*,
so a probe answering an error would have turned every gated assertion into a silent no-op. The
round after *that* took it one level in: a `modules` answer with no module list, and a kernel target
with no `nt` in a listing filtered for it, are drift too - only "`nt` resolved, without a PDB"
closes the gate. And a `states` group now **names the pins its relation rests on**, because claiming
it by the step alone meant deleting the `matched` pin left the relation reported and nothing
failing. And a gated step with **no target to probe** - a binding reordered so it precedes its
opener - is a binding failure rather than a closed gate, since the closed answer stands it down and
passes.

**Two lifecycle defects came in with it, both from plumbing this reimplemented rather than reused.**
An opener that registers a session and *then* fails reports the only handle that can reach it inside
the error, and the first cut dropped the result on that path — so the target leaked, and repeated
runs against one drift would have met the four-session cap instead of reporting the drift;
`local_model_drive.opened_session` already reads both places that handle can be, and is now what
reads it — and an opener whose *answer went missing* may have opened a target too, so the driver's
`reconcile_opened` handles that ambiguity here as it does there, which in turn made the ownership
baseline load-bearing: without it a reconciliation adopts, and then ends, whatever the credential
already held. And the MCP transport session was never closed, so repeated verifications piled up on
the listener until the lease grace; what `end_sessions` could *not* release is now retried once and
reported, since discarding it announces a clean namespace the run has not got. Both are the same shape as the accumulation rule in `CLAUDE.md`,
seen small: a parallel path beside one that already worked. The cleanup then had to move one
request earlier still, since the handshake is *two* requests and a failure between them leaves an
id nothing deletes.

**Gating: `docs/smoke-test.md` draws that line and this keeps no second copy of it.** Three review
rounds on [#221](https://github.com/glslang/windbg-mcp/pull/221) were corrections to a second copy
kept in this entry — first too wide, then too narrow — so `GATES` holds the sentence a stood-down
step *prints* and that file holds the rule. `arm64_pc` is asserted through **both** routes, since
its `possible_on: min` rests on `crash_triage` frame 0 and `registers` alone would not be checking
it; the frame-0 half takes the gate, opens the dump itself rather than inheriting a session, and
passes `analyze: false` — frame 0 is the crash context on a freshly opened dump and otherwise
whatever the session has selected.

**Nothing was wrong when it landed**, which is what makes this protection against future drift
rather than a bug fix: all three dumps were re-read on 2026-08-25 and every fact the tasks depend
on still holds. What will move it is an engine or `dbgscope` bump, a symbol-path change, or a new
sample replacing an old one.

**Where it picks up.** `tools/local_model_eval.py` (`--verify-key` and the helpers under it),
`tools/eval_tasks.json`'s `verify` blocks, and `docs/local-model-eval.md`. `tools/eval_tasks_v1.json`
deliberately carries **no** binding — it is the wording published logs were graded against, and the
mode refuses it by name rather than skipping it quietly.


## 46. [windbg-mcp] A run can be graded but not compared, because nothing records what it ran against — **done** (2026-08-25)

**Re-running a cell is the point, not a hazard.** As models are updated the same question on the
same surface will be asked again, and what will matter is run N against run N-1 - the frozen suite
(#220) exists so a *reworded question* cannot silently un-grade its own history, which is a
different thing from discouraging a rerun. A rerun into a new log with a new plan is exactly what
this bench is for. What it could not do was **compare two of them**.

**A record identified the question and the surface, and neither of the two things that change over
time.** It carried `prompt` (the question identity #220 leaned on), `surface` with its client, tool
count, byte size and names, plus `served_context`, `seed` and `draw`. It did not carry which
*model weights* answered or which *server build* was asked.

- **The model is a mutable tag.** `qwen3.8:27b-mlx` is a name that can be re-pulled onto different
  weights, so two runs a month apart can agree on every recorded field and have been different
  models. This is the axis the whole comparison is about.
- **The server build was absent entirely.** `surface.bytes` is a real fingerprint of the tool prose
  and did move when item 41 landed (8,654 -> 7,732 on `min`), but it is a fingerprint of one
  channel: [#217](https://github.com/glslang/windbg-mcp/pull/217) changed an **opener's result**,
  which no tool-list byte count can see. So the field that looked like a build identity was silent
  on exactly the channel the last three findings were about.

**What closed it.** Identity fields on every record - `server`, `model_digest`, `suite`, and
`harness_version` for the row that can have no digest - plus `--compare` over two logs and
`--series` over any number of them. Both facts were already on the wire and both were being thrown
away: the handshake kept `protocolVersion` and dropped `serverInfo`, and `/api/ps` was read for the
served window and not for the `digest` beside it.

**And the decision this entry said *was* the item: yes, this server reports a build revision.** A
crate version is a floor, not an identity - it moves on release, so two builds of `0.11.0` were
indistinguishable, which is the same trap the service-image warning names in `CLAUDE.md`. `build.rs`
now stamps the short git revision into the version the server reports, as semver build metadata
(`0.11.0+g1a2b3c4`, `-dirty.<digest>` where the build inputs differ from that commit), and the transcript's
`start` record carries the same string - it had the same weakness and nothing had noticed.

**Four things it needed that this entry did not anticipate.**

- **A build script that names git files loses Cargo's default of watching the whole package**, so
  the watch list and the dirty check have to be *the same list* or they disagree: a stamp saying
  clean on a tree that is not is worse than no stamp. Both read one `INPUTS` const - what actually
  reaches the binary and its tests - which also gives `-dirty` a meaning that can be stated: the
  build inputs differ from that commit, and an edit under `docs/` does not make a binary a
  different binary. **And those git paths must be resolved by git**, which review caught: a
  `git worktree` checkout has a `.git` *file*, so a literal `.git/HEAD` is a watched path that does
  not exist - Cargo reads that as perpetually changed and recompiles the whole crate on every
  otherwise no-op build. `rev-parse --git-path` answers in every layout, with the branch's ref name
  from `symbolic-ref` first, since `--git-path` takes a path relative to the git directory and not
  a revision (`--git-path @` answers `.git/@`, which is nothing - checked, after writing it the
  wrong way).
- **And `-dirty` alone is not an identity**, which review caught too and which is this item's own
  argument one level below the commit: the workflow this exists for is edit, rebuild, evaluate, and
  two iterations on one `HEAD` would stamp the same string while behaving differently. It carries a
  digest of the working-tree diff now. The hash is hand-rolled FNV-1a rather than `DefaultHasher`
  for a reason worth writing down - that one is explicitly not stable across Rust releases, so two
  machines on different toolchains would tag one working tree two ways, relocating the failure
  rather than removing it.
- **The two version assertions had to become prefix checks, and that is a weakening** - so the
  smoke test gained one that is not: built from a git checkout, the version *must* carry a
  revision. Without it a `build.rs` that silently stopped running would leave every assertion
  passing on the bare crate version, which is the legitimate tarball answer.
- **The two `/api/ps` facts are one call, not two.** This entry treated the digest as a second
  field to read; it is the same question about the same live state, and two calls could catch
  different instances - a record pairing one model's window with another's digest would be worse
  than either field missing. `served_context()` became `runtime_identity()`.
- **`--compare` needed the *wording* kept per cell-task**, which `matrix()` did not carry. A task
  id is not the question, and the record is the only place the wording survives. Two rounds on that
  one: the placeholder a dead draw writes already carries `prompt: None`, so a `setdefault` froze
  the null and `comparable()` then read "no prompt recorded" as "comparable" - pairing two
  different questions rather than blocking them.
- **A surface and a served window are per cell, not per run**, so the identity line could not hold
  them and the first cut simply omitted both. `surface.client` is a *label*: `min` was 11 tools and
  8,654 B before item 41 and 7,732 B after, so pairing on the label alone presented a surface change
  as a model comparison - the very intervention these runs exist to measure, silently. And a cell
  that asks for no window records `num_ctx: null` while the runtime serves what it likes. Both are
  named per cell beneath the table now, on the same rule as everything else that is not the
  question: weighable, so named rather than blocking. And the surface is compared **by digest**,
  not by length - the round after found that a byte count moves for almost any prose edit and for
  none reliably, so a same-length reword or an equal-sized allowlist swap said nothing had happened;
  the drivers record a digest of the surface exactly as it went over the wire. Pointed at the two
  published logs it reports one at once: `min` was 15,544 B in `after-206` and 14,606 B in
  `after-210`, a difference those write-ups compared across in silence. And the round after *that*
  caught the mirror image: adopting the digest is not a surface change, so a comparison spanning
  the rollout would have read every cell as moved on a telemetry format. It falls back to what both
  runs recorded, and reports `unverifiable` rather than agreement where one side has no digest —
  once beneath the table, rather than per cell, where *neither* side has one, since then it is true
  of every cell equally and the per-cell wording would be false. The **weights** joined those two
  as a per-cell fact a round later, for the same reason the surface did: the identity line's
  `weights` is a run-wide set, and two runs assigning the same two digests to opposite cells - one
  model at two contexts, a tag re-pulled between the runs - compare equal there while pairing
  results from different weights. And a row label carries its **backend**, since a cell is keyed by
  one and an ollama tag may be the same string as a Claude alias.

**Two rounds were declined after being built, which is the more useful record.** Review asked for
the model weights and then the server build to become per-cell facts beside the surface and the
window, on a sound argument: a run-wide *set* cannot say which digest or revision answered which
cell, so two logs assigning the same two to opposite cells compare equal. Both were implemented and
then taken back out, because the premise is not reachable on this bench - a model cannot be
re-pulled while a run holds it, and a run that spanned a rebuild of the server is invalid for
reasons no comparison could repair. A surface and a window are different in kind: the grid varies
both deliberately, cell by cell, every run. What survives is the one thing a historical row cannot
recover from the identity line, the surface digest per cell in the series. **`tools/` is a
developer script, not the server**, and the bar for defending it against states its own workflow
cannot produce is lower than `src/`'s.
- **Absent is not the same as deliberately null**, which the same round caught. A Claude row's
  `model_digest` is null *on purpose* - an alias resolved inside a client this bench does not own
  has no content address - and folding that into `unrecorded` labelled every current run containing
  a Claude cell as a log predating the field. `unavailable` is the second word, and one predicate
  reads presence for all four fields rather than four special cases.
- **A cell-failure note carries no identity and must not contribute one.** `run_cell` writes it
  with the cell's coordinates and nothing else, so counting it put an `unrecorded` beside the real
  server a current run *had* recorded - a partially failed cell reading as a second, unknown
  build.

**Pairing refuses at the task, it does not annotate.** A cell pairs on `(backend, model, ctx,
surface, task)`, but `arm64_pc` has the same id in `tools/eval_tasks_v1.json` and
`tools/eval_tasks.json` and a materially different prompt, so pairing on the id would put two
distributions side by side that #220 established are not comparable - and would be *weaker than the
grader already is*, since `usable()` refuses such a record outright. It reuses `stale_prompt`, the
predicate split out of `usable` in #220 so the reason could be named, and renders the row as `--`
with that reason beneath the table - the same principle as the `UNCOUNTED` line beside it. It is a
floor: `expect` can move too, and a pairing predicate that reads only the prompt does not see that.

**The run-identity line is for what is left**, and that is its actual job: the uncontrolled
variables that are *not* the question - model weights, server build, harness, suite. Naming them
above the table is not a nicety, because this repo has three times read a moved aggregate as a
controlled result (items 42 and 43, and twice in
[#212](https://github.com/glslang/windbg-mcp/pull/212)), and every one was a *composition* error -
the callers changed and the total held. But a note is the right instrument only for a variable a
reader can weigh; a changed question is not one of those, which is why the two rules are separate.

**And the reporting is the other half.** `docs/local-model-eval.md` accumulates a prose section per
run, which reads well and cannot be diffed: the tables in it measure different servers, which the
page says in words and no reader can check. `docs/eval-runs.json` is the machine-readable series,
one row per run keyed by the identity above, regenerated rather than appended to so a log re-graded
under a corrected key updates its own row.

**The three runs already in that series read `unrecorded` for every identity field**, which is the
part of this that expires rather than an omission: a run recorded without identity cannot have it
added later. Nothing already published is wrong - each write-up names its own server build in prose
- and what was missing is the ability to *check* that, and to do it for a run nobody has written up
yet.

**Verified rather than described.** `/api/ps` carries `digest` beside `context_length`, measured
against a loaded model rather than read off a document; the live listener's `serverInfo` is
captured by the driver; the stamp reads the branch head's short revision, and gains `-dirty.<digest>` after a one-line
edit under `src/` — which exercises the rerun trigger and the dirty check together; and `--compare`'s
blocked-pairing and one-sided-cell paths were run against a doctored log. `cargo test` on the ARM64
bench: 540 unit tests and 76 smoke tests, no new clippy warning.

**Left open.** Naming a real version source for a Claude row. `harness_version` is `claude
--version`, which moves when the client does and says nothing about the weights behind `opus` or
`sonnet` - a floor, recorded as one, exactly as the crate version was before `build.rs`.

**Where it picks up.** `build.rs` and `src/main.rs`'s `BUILD_VERSION`;
`tools/local_model_drive.py` (`handshake`, `runtime_identity`, `load_tasks`) and
`tools/claude_code_drive.py`; `tools/local_model_eval.py` for `identity`, `--compare` and
`--series`; and `docs/local-model-eval.md` beside `docs/eval-runs.json`.

---

## 48. [dbgscope + windbg-mcp] A target that exits during a `go` is reported as a catastrophic failure — **landed** (2026-08-26)

**Landed** with [#242](https://github.com/glslang/windbg-mcp/issues/242), which reported the same
seam from the other end (an exit racing `settle`'s pump, and the access violation beside it). Kept
because two of the things this entry says are wrong, and both were wrong in a way worth recording.

**"The engine's output buffer holds exactly that text" — it does not.** This entry said WinDbg
prints `cmd.exe exited with code 0` and that the `Err` path throws that away. Measured on dbgeng
10.0.26100.1 (ARM64), the buffer across a `g` that ends the target holds the echo and the module
loads and **no exit banner at all**; `GetExitCode` fails `E_UNEXPECTED` by then and `.lastevent`
answers `<no event>`, so the engine will not say *how* it ended, only that there is nothing left.
The output is still worth keeping — it is the only copy of what the run printed — but the sentence
that justified keeping it was describing a banner this engine does not emit.

**And the decision it deferred was the smaller half.** "Is an exited target an error at all" is
answered by one field; what the work actually needed was the *other* half this entry did not
mention, which is that execution control reaching an engine with no debuggee is a
`STATUS_ACCESS_VIOLATION` that takes the worker down. That is what made this a fault rather than a
message, and it is why the fix is a guard in dbgscope's primitives rather than a variant here.

**What it became.** An ending, not an error: `CommandRun::target_gone` and
`RunToOutcome::TargetGone` in dbgscope, each carrying the run's output;
`structured::StopReport::target_gone` and `RunToVerdict::TargetGone` here, on both halves of the
result; and `worker::refuse_when_the_target_is_gone`, so every tool answers one refusal naming
`end_session` rather than each failing its own way. A `debug_batch` stops there rather than running
on, with `BatchOutcome::TargetGone` and `SessionAfter::Ended` — reached only because review found
the ending stopping at every seam below the tool: the raw hatch's pump, the batch's assertion loop,
the state probe, the transcript and the tool description each had to be told separately, which is
what a terminal fact costs when it is added to a system that had no notion of one. The session is
**not** retired on the supervisor's side — see below.

**What is left, and it is deliberate — but the reason is not the one first written here.** The
supervisor never learns that a target went away, so the session stays `Open`. The first draft of
this paragraph called that a wrong status string and left it there. Review (Codex, on
[#243](https://github.com/glslang/windbg-mcp/pull/243)) supplied the consequence that makes it more
than one, and it is worth having in writing:

**a dead session is still the default route.** `Registry::current` takes the most recent session
whose state `accepts_default`, and `Open` does — so every call that names no `session_id` goes to
the session with no target, and a perfectly good older session of the same client is shadowed by
it. `session_status` lists it as live beside the working one.

**It is pre-existing, and that is why it is still deferred rather than fixed here.** On `main` the
only transitions are `Closed` (teardown, worker death, the sweep), `Failed` (an open that created
nothing), `Retired` (a target-changing *command*, decided from its text) and the opening pair —
nothing has ever watched a target leave. A session whose process exited was already `Open` and
already the default route before any of this; what changed is that it now says so on every call
instead of failing with `0x80040205`.

**What would close it.** A `WorkerMessage` milestone beside `Committed`/`Opened` — the worker
already asks `has_target` once per op in `refuse_when_the_target_is_gone`, so there is one place to
emit it from — and a `SessionState::Ended` that refuses both `accepts_handle` and `accepts_default`
while staying `is_live` (the worker exists, owes an `end_session`, and counts against the
four-session cap until it gets one). `Retired` cannot be reused: it means "the worker still holds a
target", which is the opposite. Mind the promotion rule at `engine.rs`'s opener settle, which
already has to protect `Retired` from being promoted back to `Open` by a late result and would have
to protect this the same way.

**Why not in the PR that found it.** It is session lifecycle, which is the part of this server
where a mistake costs a *target* rather than a call — a live kernel left halted — and it is
orthogonal to the ending this change is about. It wants its own change, its own tier run, and a
reviewer looking at nothing else.

<details>
<summary>The original entry, as written on 2026-08-25</summary>

**What happens.** `go`, a step, or a `resume` whose debuggee exits while the engine is waiting comes
back as `Debug command failed: Catastrophic failure (0x8000FFFF)`. That is the raw `E_UNEXPECTED`
DbgEng answers once the wait ends with no debuggee left — reported, unchanged, for the ordinary
outcome of running a program to completion. The *next* call then says "No active debuggee", which
is the accurate half arriving one call too late.

**Measured, and pre-existing.** `cmd.exe /c exit`, launched and then `execute_and_wait("g",
10_000)`: `Catastrophic failure` on the first call and "No active debuggee" on the two after it —
**identical** with the bounded wait of #226 and with the finite wait it replaced, so this is not
that change. It was found by an x64 CI runner failing a new test where both ARM64 runners passed:
`cmd.exe` calls `NtCreateFile` while spawning `ping` and then waits thirty seconds for it, so a
`go` there outlives the target where on ARM64 it stops again first.

**Why it was not fixed alongside #226.** The message is the small half. The real question is
whether an exited target is an **error at all** — WinDbg treats it as a stop and prints
`cmd.exe exited with code 0`, and the engine's output buffer holds exactly that text, which the
`Err` path currently throws away. Answering "it is a stop" means deciding what the *session* then
holds: a handle whose target is gone is what `changes_debug_target` and the retirement machinery
exist to prevent, and nothing today notices a target that left without being told to. That is a
seam worth one deliberate change rather than a message tweak smuggled into a bug fix.

**What would close it.** Decide the question above first. If it stays an error, it needs a variant
of its own carrying the exit banner, and a category (`ErrorCategory`) a caller can act on — "the
target is gone, open a new session" rather than "something catastrophic happened". If it becomes a
stop, the session has to be retired the way `.detach` retires it, and `session_status` has to say
so. Either way it wants the tier that now launches a process (`launch_tier`), where the shape is
one line: launch `cmd.exe /c exit`, `go`, read the answer.

**Where it picks up.** `DebugEngine::execute_and_wait`'s tail in dbgscope's `src/dbgeng.rs`
(`waited.map_err(DbgEngError::CommandFailed)?`), `DbgEngError::NoDebuggee` beside it, and
`worker::resumed`. The workaround in the meantime is in
`a_raw_execution_control_command_moves_the_target_instead_of_wedging_the_session`, which asserts
with a step rather than a `go` and says why.

</details>

## 49. [windbg-mcp] The x86 engine host is gone — a **worker of the target's architecture** replaced it — **done** (2026-08-26 to 27)

**What this item was.** Routing a 32-bit .NET dump to an engine that can load its SOS landed on
2026-08-26 by running an `x86\cdb.exe` as a debugging server and driving it over DbgEng's `npipe:`
transport. This entry recorded what that left open and told whoever picked it up to **measure the
pipe's exposure before designing anything**. Measuring it closed the question the other way: the
transport was not worth keeping, and it is gone.

**What landed instead.** The supervisor spawns a **second worker image** — `x86\windbg-mcp.exe`, a
32-bit build of this same crate — rather than re-executing itself, when the target is a 32-bit
user-mode one. `src/enginehost.rs` is deleted: no `cdb` child, no named pipe, no transport
password, no job object, no kill teardown. `engine::worker_images` picks the image from the
architecture `src/target.rs` reads without an engine, `engine::x86_worker_image` finds it, and a
worker that will not come up falls back to this build with the limitation the *worker* computes by
asking the same question again.

**Why that was the answer and not a mitigation.** Four findings, all measured on the ARM64 bench and
all recorded in full below: the pipe grants **Everyone `FULL ACCESS`** with no `SYSTEM` or
`Administrators` ACE at all, so the password was the only barrier; a non-administrative token drove
a real DbgEng client over it; the name is a squat primitive two different ways, one of which hands
the *next* client's connection and its password to the squatter; and there is no authenticated
DbgEng transport to move to, `spipe:` and `ssl:` both being refused outright by this build. Two of
those had no fix inside that design, so the design went.

**What closed with it, beyond the transport.**

- **`modules` rows carry a `pdb` again.** `IDebugAdvanced2::GetSymbolInformation` did not cross the
  remote transport; there is no remote transport, and the engine is in-process for the worker that
  holds it.
- **Teardown is not a kill.** A 32-bit worker is an ordinary worker and exits when its request
  channel closes. The `cdb -server` spinning on a broken pipe — 32,089 lines of
  `Could not write to pipe, 1450`, which hung a VM — cannot happen because there is no `cdb`.
- **"Untested over the transport"** (execution control, breakpoint arming, event waits, the
  user-mode heap walker) is moot rather than a suite still owed.
- The two facts left unmeasured — whether an unprivileged user can read another account's command
  line, and whether the x86 `cdb.exe` sets the same descriptor as the ARM64 one — are moot for the
  same reason.

**Two things about the implementation that are easy to get wrong later.**

- **The engine is bound by the loader, before `main`.** An `x86\windbg-mcp.exe` with no
  `dbgeng.dll` beside it fails to *start*, as a loader error with no Rust in it — so
  `x86_worker_image` refuses to name an image unless both are there, and the fallback stays a
  fallback rather than a crash.
- **`WorkerMessage::Ready` now carries the build identity, and the supervisor refuses a mismatch.**
  It could not have differed while the supervisor re-executed itself; a second image an operator
  copies by hand can be a release behind, and nothing else in the protocol would notice — an older
  worker deserializes a close-enough JSON shape and goes wrong somewhere that surfaces as a debugger
  error much later.

**The address space does not bind, and was measured before any of this was built.** The
`x86\cdb.exe` in the payload *is* a 32-bit DbgEng in a 32-bit address space, so it answered for the
worker that did not exist yet: against full user-mode dumps of 445 MB, 846 MB and 1,346 MB its peak
virtual size was **290, 256 and 256 MB** — flat rather than proportional, because DbgEng reads a
dump on demand instead of mapping it — and a full `!address`, `!heap -h 0` and `!heap -a 0` against
the largest moved it no further than 238–255 MB. The ceiling is 4 GB rather than 2 because
`x86\cdb.exe` is linked `LARGE_ADDRESS_AWARE` (`0x0122`); `build.rs` now emits
`/LARGEADDRESSAWARE` for an x86 build so that margin is a decision rather than the linker's default.
What this bounds is **the engine, not this repo's walkers** — and the walkers turned out not to
need bounding at all. This entry said dbgscope's heap and pool walks build structures proportional
to chunk count and that in a 32-bit worker those are our code in that address space, so the
walker's own footprint was "what is left to watch". Measured once the worker existed (x64 bench,
2026-08-27): **neither walk runs against a 32-bit target in the first place.** `heap::validate_target`
refuses anything but `IMAGE_FILE_MACHINE_AMD64` on the *target's* effective processor type
(`dbgscope/src/heap.rs:695`), exactly as `pool/query.rs` does, so all five heap tools answer
`heap walking supports x64 targets only (machine 0x14c)` on a 32-bit dump and on a live WoW64
process alike. The address space this worker has is spent on the engine and nothing else.

**What closed the rest of it** (built 2026-08-27 on the **x64 bench**, against the plan written
that morning from the Mac; that plan is kept below where it was right about a seam, and the one
place the build went the other way says why).

- **The fixture is made, not supplied.** The tier took `WINDBG_MCP_X86_DUMP` and stood down without
  one, so CI never ran it and a machine without a 32-bit dump proved nothing. It now creates its
  own target the way the TTD tier does: `csc.exe` ships on every stock Windows, so it compiles a
  `-platform:x86` C# program that either **dumps itself** with `MiniDumpWriteDump` or prints a line
  and waits, and the two tests take one each. Measured: 76 MB written in 0.14s. It asserts the
  dump's **size**, as the plan said to — `comsvcs.dll MiniDump` wrote a near-empty file on the
  ARM64 bench and reported nothing wrong, and that is the failure a check for existence cannot see.
- **A live 32-bit target** (a WoW64 `attach_process`) is built and covered, and the plan had the
  seam exactly right: `EngineOp::dump_path` answered for `OpenDump` alone, so a pid could not
  travel that way at all. It is now `EngineOp::opening`, answering `target::Opening` — a dump path,
  a pid, or nothing — and `worker_images` asks *it* rather than the header parser. Everything below
  was already the right shape, as predicted. The worker's half stays a second call: it travels on
  `TARGET_FLAG`, whose value is now **tagged** (`dump:<path>` / `process:<pid>`) because a bare one
  would have to be told apart by guessing — is `1234` a pid or a file called `1234`? — in the one
  process that cannot ask anyone. `launch` is out of scope deliberately, and `Opening`'s doc
  comment says so beside the two that are in.

**Where the build went the other way, and the argument.** The plan said to do the live half first
and get the fixture nearly free: attach to the SysWOW64 PowerShell and write the dump with
`execute { ".dump /ma /f <path>" }`, on the grounds that a 32-bit engine in a 32-bit process is
"the only writer whose architecture cannot be wrong". It is not, and the counter-example is the
plan's own hazard arriving by a different door: that writer's architecture is *whatever the routing
gave it*, so a regression in the live half puts the session on the x64 worker, `.dump /ma` writes a
capture that reads as x64, and the dump test then fails at `.loadby sos` — the mis-made fixture
wearing the face of a broken feature, produced by the very mechanism under test. It also makes one
failure fail both tests, which costs the property that makes a pair worth having.

A `-platform:x86` program dumping *itself* takes its architecture from the loader instead — a
32-bit process loads the 32-bit `dbghelp.dll` — so nothing in this repository is upstream of the
fixture's correctness. What that bought is checkable rather than argued: mutating the
`AttachProcess` arm of `EngineOp::opening` to `None` fails the attach test and leaves the dump test
green. The cost is the `csc.exe` step the plan wanted to drop, which is the original bullet's own
ingredient and is gated with a stand-down.

**What the gate is now, and why it is the engine.** The tier stands down on a host with no 32-bit
`dbgeng.dll` in an `x86` directory beside the binary under test, and *fails* on one that has the
engine but no `x86\windbg-mcp.exe` — the half-populated directory `setup.md` warns fails quietly.
Gating on the worker instead would have put a second copy of `x86_worker_image`'s renamed-image
fallback in a file that cannot call it. CI sets that gate on every debugger-tier entry, from the
Debugging Tools' `x86` payload or from `SysWOW64` — the four DLLs there were measured on the x64
bench to be enough for a tier that loads SOS and resolves no PDB — and a stand-down is a red build
on the x64 entry, where an ARM64 one is entitled to stand down instead, x86 under emulation being
new ground and issue #153 the precedent for not assuming two runner images ship the same things.

That step was the one part of this not verified against GitHub's images, and the first run settled
it (2026-08-27): **all three images have a 32-bit engine, and it is the Debugging Tools' `x86`
payload rather than `SysWOW64` on every one of them**, so both tests ran on ARM64 too. The ARM64
stand-down is a fallback nothing has taken rather than a description of what happens — worth
knowing before reading that entry's silence as coverage.

**What the Mac plan called right, kept because being right about it was not obvious.**
`IsWow64Process2` is behind windows-sys's `Win32_System_SystemInformation` and not the
`Win32_System_Threading` its declaration sits in — met exactly as an unresolved import, and fixed
by the dependency edit the plan named. `cargo check --target i686-pc-windows-msvc --all-targets` is
indeed clean, and so is `cargo clippy` for that target on the bench. And the ARM64 routing arms
cannot be reached from an x64 bench, so they are covered by a unit test over the mapping
(`a_pe_machine_type_and_a_processor_architecture_are_read_apart`) exactly as the plan required —
which also pins the thing that mapping exists for: 9 is x64 to a minidump and nothing at all as a
PE machine type, and 332 is the other way round, so one shared table is how a value from the wrong
namespace becomes a plausible wrong answer.

**And what it settled in [#234](https://github.com/glslang/windbg-mcp/issues/234), the bug report
all of this came from** (x64 bench, 2026-08-27). Its two reported errors reproduce **exactly**, on
the fallback path this build still takes when there is no 32-bit worker — the 32-bit `sos.dll`
answers `0n193` / *"not a valid Win32 application"*, and the 64-bit one loads and then says *"SOS
does not support the current target architecture (14c)"*, naming the same machine value. That
matters beyond confirming the report: those two sentences are what `NO_X86_WORKER` tells a caller,
so the limitation this server ships is now measured rather than quoted. And #234's own
recommendation for *future* captures — take them with the 64-bit procdump so the x64 engine can use
`!wow64exts.sw` — still routes correctly: a 64-bit capture of a WoW64 process reads as x64, stays
on this build's worker, and reports no limitation, so nothing here has taken that path away.

Two things about #234 that are **not** confirmations:

- **We route on x86, where the issue proposed "x86 *and managed*".** Deliberate: "managed" is not
  in a minidump header, and there is nothing to lose by routing every 32-bit user target to the
  32-bit worker — native analysis is the same on either, so the narrower test would buy only a
  second way to get the decision wrong.
- **Its workaround's SOS half did not complete on this bench**, and that is not evidence about the
  issue. `!wow64exts.sw` switches to guest mode; `.loadby sos clr` then resolves the **32-bit** SOS
  beside the WoW64 `clr.dll` and fails `0n193` — so that path wants `.load <Framework64 sos>`
  rather than `.loadby` — and the explicit load then fails on the DAC (*"path is pointing to
  clr.dll as well"*), which is `mscordacwks` pairing and wants a symbol path this bench has not got.
  Report it as not reproduced here, never as broken.

**What neither issue weighed, and a live attach now makes real: the 32-bit worker cannot see the
64-bit half of a WoW64 process.** Both issues are about *dumps*, where a 32-bit capture has no
64-bit side in it to lose. A running WoW64 process has one, and the two workers see different
things — measured on the same fixture, one attach each: this build's worker lists **36** modules
including `ntdll`, `wow64`, `wow64base`, `wow64cpu`, `wow64con` and `wow64win`, five of them above
4 GiB; the 32-bit worker lists **30**, none above 4 GiB, and none of the WoW64 layer. So
`attach_process` on a WoW64 process trades the emulation layer for SOS. That is the right trade for
the debugging this feature exists for, and it is a trade rather than a free win, so
`skills/windbg-debugging/setup.md` says it where an operator will meet it.

**What this let us go back and measure in [#240](https://github.com/glslang/windbg-mcp/issues/240),
which argued for this design and shipped two claims it could not check.** Both now check out, and
one of them is stronger than the issue's own argument (x64 bench, 2026-08-27, driving the shipped
tool surface at a 32-bit dump and a live WoW64 process in turn):

- *"`cargo check --target i686-pc-windows-msvc` has not been run, so 'it compiles' is an
  expectation rather than a measurement."* It compiles, it is clippy-clean, and the worker it
  produces opens real targets.
- *"The 32-bit-truncation risk reads low ... every `as usize` inspected is buffer-length shaped
  rather than address shaped."* Measured rather than read: `0xffffffff12345678` and
  `0x7fffffffffffffff` come back **whole** from a 32-bit worker, in the structured result and in
  the error text alike, and `modules`, `registers`, `backtrace`, `read_memory` and `disassemble`
  all report addresses in the target's real range with nothing truncated or sign-extended. The
  counts the issue quoted have drifted, as counts do — `as usize` is 82 in dbgscope and 28 here
  against its 81 and 27.
- *"The kernel pool walkers — the most 64-bit-assuming code — never run in an x86 user-mode
  worker."* True, and **more is true than the issue claimed**: the *user-mode heap* walker does not
  run either, which is the correction recorded above. The issue's argument did not need it, but
  this entry's address-space worry did.

**Why `process_arch` does not enable `SeDebugPrivilege`, since review asked twice over.** The
worry is real in shape: `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` is a DACL check, DbgEng
enables `SeDebugPrivilege` before attaching and an enabled `SeDebugPrivilege` *bypasses* the DACL,
so in principle the probe can be refused a process the attach then opens — and `worker_images`
reads a refusal as "nothing to say" and takes this build's worker, losing the routing silently. On
a service, which is what [#234](https://github.com/glslang/windbg-mcp/issues/234)'s reporter
debugs, that would be the reported bug arriving by a back door.

**Measured, it does not arise in the ordinary case** (x64 bench, 2026-08-27). With
`SeDebugPrivilege` explicitly **disabled** in an elevated token, `PROCESS_QUERY_LIMITED_INFORMATION`
still opens `services.exe` and the `System` process itself — the two most locked-down pids on the
box. That is what the access right is *for*: it was added so a caller can ask what a process is
without being able to read it, and the default process DACL grants it. The window that remains
needs a **non-default** DACL denying it to a caller who nonetheless holds `SeDebugPrivilege`;
without that privilege there is no divergence to have, because the attach fails too.

Both remedies review proposed are worse than the gap:

- **Enabling `SeDebugPrivilege` for the probe** buys nothing measurable and widens the
  *supervisor's* ambient authority — the process that holds the listener's credentials and spawns
  every worker — to improve a routing hint.
- **"Preserve an x86 retry path when the architecture cannot be queried"** is actively harmful.
  `worker_images` returns images *tried in order*, and a 32-bit worker starts perfectly well
  holding a 64-bit target: the fallback is driven by a worker failing to come up, not by the
  target being wrong for it. So an unknown-architecture retry would put 64-bit targets on a
  32-bit engine and the session would come up broken rather than fall through.

What the failed probe gets instead is a **`warn`** rather than a `debug` line, which is the honest
mitigation: the routing may have been downgraded and this is the only place that can say so. The
rest is the operator's — a target whose architecture cannot be read is one whose session says
nothing about SOS either way.

**Two things bite next.** The build identity on `WorkerMessage::Ready` refuses an
`x86\windbg-mcp.exe` built from any other state of the tree, and on a dirty tree it carries a
digest over the uncommitted diff of `build.rs`'s `INPUTS` — so `cargo fmt` invalidates it as surely
as a code change, and the stale worker's failure reads as *this host could not give the target a
32-bit worker*, which sounds like a missing file. And `process_arch` must read `ProcessMachine`
falling back to `NativeMachine`, never the native one alone: the native machine is the *host's*, so
reading it would report an ARM64 box's x86 processes as ARM64, which is the case the whole thing
exists for.

**Where it picks up.** `src/target.rs` — which is `src/dump.rs` renamed, because the module now
answers for a live process as well as a file — specifically `Opening` and `process_arch`;
`engine::worker_images` / `engine::x86_worker_image` / `engine::start_worker`,
`worker::limitation_for`, `EngineOp::opening` in `src/proto.rs`, `worker::TARGET_FLAG`,
`Cargo.toml`'s `windows-sys` features, the `x86\` copy block in
`skills/windbg-debugging/setup.md`, and the *Give the runner a 32-bit worker and engine* step in
`.github/workflows/ci.yml`. The tier is *32-bit managed target* in
[`docs/smoke-test.md`](./docs/smoke-test.md); `WINDBG_MCP_X86_DUMP` no longer gates anything and
now only *overrides* the made dump, in the two places that read it —
`mcp_smoke::made_x86_dump` and `target::tests::a_real_x86_user_minidump_reads_as_x86`, the second
being the only one that can call the parser directly, since this crate has no lib target. The
probes behind the measurements below were `pipe_probe9`–`pipe_probe12` and
`addr_probe2`–`addr_probe3`, whose shape is worth reusing: start `cdb -server` on a sample dump,
wait for the name in `\\.\pipe\`, then read, connect or squat.

<details>
<summary>The engine host this replaced, and the measurements that ended it (2026-08-26 to 27)</summary>

**This entry told whoever picked it up to measure the exposure before designing anything. Measured,
it is worse than the entry supposed in every direction.** ARM64 bench, Windows 10.0.26100.0, SDK
`cdb.exe` 10.0.26100.1742. Everything below is a measurement, not a reading of the documentation.

**The DACL is Everyone `FULL ACCESS`, not the default descriptor's Everyone *read*.**

```text
cdb's pipe         O:BAG:S-1-5-21-…-513D:(D;;WDWO;;;WD)(A;;FA;;;WD)
a NULL-SA control  O:BAG:S-1-5-21-…-513D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;BA)(A;;FR;;;WD)(A;;FR;;;AN)
```

`cdb` sets its own descriptor rather than inheriting the default, and there is **no `SYSTEM` ACE and
no `Administrators` ACE in it at all** — `(A;;FA;;;WD)` is the only grant, so an administrator gets
in through the *Everyone* entry like everyone else. The one denial is `WRITE_DAC|WRITE_OWNER`: you
may do anything with this pipe except fix it. Identical across all four combinations of `hidden` and
`password=`, so it is DbgEng's transport code and not an effect of the options this server passes.

Reading it needs `CreateFileW(READ_CONTROL)` then `GetKernelObjectSecurity` — `Get-Acl`,
`GetNamedSecurityInfo` and `GetSecurityInfo(SE_FILE_OBJECT)` each refuse a pipe path (`win32 87`),
which is the wall this item recorded hitting twice and is why the assertion went in unmeasured.

**And an unprivileged token drives a real debug session over it.** Under a *Basic User* restricted
token (`runas /trustlevel:0x20000` — same user SID, `Administrators` deny-only, privileges stripped
to `SeChangeNotifyPrivilege`, `IsInRole(Administrator)` false), `cdb -remote
npipe:server=localhost,pipe=…,password=…` connected and ran `lm` against the served dump: 18,044
bytes, byte-identical to the administrator baseline against the same server. The branch this entry
hoped for — "if the answer is nothing, this whole item shrinks to a documentation note" — is closed.

Two things the entry therefore had the wrong way round:

- **The `password` is the entire barrier, not a marginal extra.** Nothing in the DACL stops anybody.
  Twelve characters do.
- **The stdio bound as written is false.** *"The server runs as the caller, so a local user who can
  read the pipe could open the dump file directly"* — the grant is to **Everyone**, not to the
  caller, so on a multi-user machine another local account reaches a dump it has no rights to. The
  boundary is smaller under stdio than under a service; the entry claimed it was absent.

**Squatting, which this entry did not consider, and the pipe's own DACL is the primitive.** `FA`
includes `FILE_CREATE_PIPE_INSTANCE`, and the name is `windbg-mcp-<pid>-<counter>` with the counter
starting at 0 — predictable, and enumerable in any case (`hidden` is measured **not** to remove the
pipe from `\\.\pipe\`, exactly as the code comment claims). Two outcomes, and they are different
bugs:

- **Own the name before `cdb` does and `cdb` refuses to start**: `StartServer failed, Win32 error
  0n183`, then it exits. That is a **denial of service, not a hijack**, and it is handled — the
  `try_wait()` in `await_pipe` sees the dead child and the fallback reports the limitation. But any
  local user can hold the name and keep the hosted path unavailable, which is cheap given the name.
  (An earlier probe reported `cdb` surviving this; that was a stale `Process` object read without
  `Refresh()`. `cdb`'s own stdout settles it.)
- **Add an instance to a name `cdb` is already serving, and the handout order does the rest.**
  Measured: the first client lands on `cdb`'s instance, the **second lands on the squatter's**. So
  an attacker parks a dummy client on `cdb`'s single instance, adds an instance of their own, and
  receives the real client's connection — which hands over the transport password and puts a
  hostile DbgEng *server* in front of a client that, under a service, is `SYSTEM`. The window is the
  `PIPE_POLL` interval plus the connect, and it is retryable.

**`spipe:` and `ssl:` are not the way out, and the measured reason is not the documented one.** This
entry declined them because both "require a certificate". On this build neither starts at all: every
spelling of `proto=` — `negotiate`, `ntlm`, `kerberos`, with and without `certuser=`/`machuser=` —
is refused `StartServer failed, Win32 error 0n87`, and so is `ssl:proto=…,certuser=…,port=…`.
`spipe:pipe=<name>` with **no** `proto=` does start, carries the same `(A;;FA;;;WD)` descriptor, and
no client can reach it: `DebugConnect failed, Win32 error 0n30`, for an administrator and a
restricted token alike. There is no authenticated transport here to reach for.

**The password landed and this entry never said so.** `c1ff61f` implemented it and did not touch
`FOLLOWUPS.md`, so this item went on describing as an open question a thing that had shipped — and
`src/enginehost.rs`'s own comment still calls `password=`'s value "an open question rather than an
oversight" three lines above the code that passes it. Both are wrong in the same direction now: the
question is not whether it is worth adding, it is that it is the only thing holding.

**`modules` rows carry no `pdb` on a remote session.**
`IDebugAdvanced2::GetSymbolInformation` does not cross DbgEng's remote transport — measured against
an in-process engine on the same target *and* with both ends on the same architecture, so it is the
transport rather than a struct size the two ends disagree about, which is what its `E_INVALIDARG`
invites you to think. `with_pdb_identity` already drops the field rather than failing the listing,
so nothing is broken; what is lost is the GUID/age coordinate on exactly the sessions this feature
creates. **What would close it:** parse the PDB signature out of the image's own debug directory
rather than asking dbghelp — `read_memory` marshals fine, this repo already reads PE structures, and
it would close the gap for every transport instead of special-casing this one. (Option 5 below
closes it a second way, by having no transport.)

### What to do about the transport, priced

1. **Give the pipe an unguessable name.** `transport_password`'s CSPRNG generator is already in the
   same file, so this is a line. It closes the pre-create denial of service outright. Against the
   instance-add hijack it removes *prediction* only — an attacker can still poll `\\.\pipe\`, see
   the new name and race the connect — so it narrows the window rather than closing it. Worth doing
   whatever else happens, and the code comment arguing an unguessable name is "unnecessary… it is
   not a secret" has to go with it: it is true of confidentiality and false of squatting.
2. **Refuse the hosted path under `--service` and report the limitation.** This is the deployment
   where the boundary is a *privilege* boundary, and it is the only one no in-design mitigation
   reaches. It costs a service-hosted caller SOS on 32-bit managed dumps and costs nobody else
   anything. Note the plumbing: the worker is never told it is under a service (`SERVICE_FLAG` is
   the supervisor's alone), so this is a fact to pass down, not a check to write in
   `src/enginehost.rs`.
3. **Say it in the operator documentation, which today says nothing.** Neither *32-bit .NET dumps
   need an x86 engine host* in `skills/windbg-debugging/setup.md` nor `docs/remote-listener.md`
   mentions the pipe, let alone who can reach it. Owed regardless of which of the rest happens.
   **Paid on 2026-08-28, and only ever half a debt by then.** The pipe half went with the transport
   — there is no pipe for `docs/remote-listener.md` to disclose. The other half outlived option 5
   exactly as *"regardless of which of the rest happens"* predicted, and outlived the fix as well:
   `setup.md` gained its *32-bit .NET targets need a 32-bit server* section with the implementation
   on 2026-08-27, and every route to it stayed silent. `SKILL.md` said nothing at all, so its
   routing table gave a model holding a 32-bit dump no reason to open `setup.md` and nothing warned
   it that a fallback answers with a `limitation` rather than an error; `docs/install.md`'s *Wanted
   / Needs* table — the index of what fails quietly without which files — had no row for it;
   `docs/limitations.md` recorded neither the fallback nor what such a session loses; and
   `README.md` did not mention the second worker image at all. All four now do. **The lesson is the
   shape, not the four files:** a feature whose own setup page is written the day it lands still has
   no reader, because nothing that *routes* to that page moved with it.
4. **Drive `x86\cdb.exe` as a plain text child over inherited anonymous pipes** instead of using
   DbgEng's remote transport at all. It removes the named pipe and with it every finding above, and
   it needs no new build target. **Rejected on function rather than effort**, and recorded here so
   it is not re-proposed: everything in `worker.rs` reaches the engine through dbgscope's typed
   interfaces, and a text child leaves text — `modules`, `backtrace` and `threads` would each need a
   parser, which is the failure mode the `execute` hatch exists to keep out of the typed surface.
5. **An `--engine-worker` built for `i686-pc-windows-msvc`**, talking the inherited-handle protocol
   this server already uses, with no named pipe anywhere. The alternative weighed in
   [#234](https://github.com/glslang/windbg-mcp/issues/234) and set aside for a second build target
   and release artefact. It is the only close.

**On "it needs a second `.exe`", which is the objection worth answering head-on.** It does, and it
cannot not: a process's architecture is fixed when its image loads, so an x64 or ARM64
`windbg-mcp.exe` can never host a 32-bit `dbgeng.dll`, and there is no fat-binary escape — ARM64X
pairs ARM64 with ARM64EC, not with i386, and an x64 host would need i386 either way. What makes it
a smaller objection than it sounds is that **the hosted path already runs a second image — somebody
else's**: `x86\cdb.exe`, out of a payload the operator must already have unpacked beside the
binary, and the x86 `dbgeng.dll` an i686 worker would load is that same payload in that same `x86\`
directory. Option 5 does not add a process to the machine. It replaces a foreign one with ours and
deletes the named pipe between them. The rest of the objection is about the *build*, and the
section below prices it.

### Option 5 in detail

**One MCP server, not two — a second *worker image*, not a second server.** The MCP server is the
supervisor: stdio or `--listen`, no DbgEng in it. A worker is not an MCP server and never speaks
MCP; it speaks `src/proto.rs` down a pair of inherited anonymous pipes and has never heard of a
client. So the client sees one process, one `tools/list`, one session registry, one four-session
cap and one transcript, exactly as today, and cannot tell which architecture served a session
except by what that session can do. It is the relationship the supervisor already has with
`x86\cdb.exe` — with the foreign process replaced by ours, and the named pipe between them replaced
by the inherited pair every other worker already uses.

**The wire is already architecture-neutral, and that is not luck.** `src/proto.rs` is one line of
JSON in each direction, because what process-per-session imposed was *serializability* — a closure
cannot cross a process boundary, so the closures became `EngineOp` variants. JSON has no pointer
width and no alignment, so a 32-bit worker deserializes the same `EngineOp` an x64 one does.
Nothing in `src/` types a target address as `usize` (DbgEng's are `ULONG64` and stay `u64`); the
`usize` fields in `proto.rs` are row limits, clamped to `MAX_ROWS` far below `u32::MAX`. Had this
channel been `#[repr(C)]` structs, reconciling two pointer widths would be the expensive part of
option 5; as it is, it is free.

**The seam is one function: `engine::worker_exe`.** Its doc comment states the invariant this
breaks — *"The supervisor re-executes itself, so worker and server can never drift apart in version
or in protocol"* — and it already carries an override for tests, so the shape is there. Three
edits:

- The supervisor reads the target's architecture **before** spawning. `crate::dump::read` answers
  `UserMinidump(Arch::X86)` from the header with no engine and no DbgEng, which is the whole reason
  it exists ("the decision has to precede the engine"). Today that call is at `src/worker.rs:766`,
  inside the worker, one process too late for this; it moves up.
- `worker_exe` takes that architecture and answers `x86\windbg-mcp.exe` for the one case,
  `current_exe()` for the rest. `spawn_worker` already takes the image as a parameter, so nothing
  below it changes at all — not the pipes, not the credential stripping, not `TARGET_FLAG`, whose
  comment already says *"which process it exists in is what this decides"*.
- `src/enginehost.rs` is **deleted**, and with it the `cdb` search and its shared deadline, the
  transport password, `await_pipe`, `pipe_exists`, the kill teardown, and `HostState`/`limitation`
  in `build_engine`.

**Where the image goes, and why the directory does the work.** In `x86\`, beside the x86
`dbgeng.dll` the payload already puts there. `dbgeng` is an import-table dependency resolved by the
loader's ordinary search order, which looks in the **executable's own directory first** — the exact
mechanism `enginehost.rs` records as the reason the x86 payload cannot sit next to
`windbg-mcp.exe`. Put the 32-bit worker inside `x86\` and that mechanism loads the right engine
with no code written for it, out of the same directory the operator already unpacks for
`x86\cdb.exe`. Nothing new has to reach the host.

**Two consequences of letting the loader do it.** A static import means a worker placed where there
is no x86 `dbgeng.dll` fails to *start* — a loader error, before `main`, not a `DebugCreate`
failure — so the supervisor has to check that the image and its engine are both present before
spawning and report the same limitation the fallback reports today; `EngineHost::candidates` is
that check already, in a shape that can be reused. And the worker never chooses an engine, so the
search-and-fallback across `cdb` candidates has no counterpart, which retires the shared-`deadline`
reasoning along with it.

**Version skew becomes ours, which is the point rather than the cost.** Two images built from one
crate can be stamped by one build and checked at the handshake — the worker already reports
`Ready`, and `build.rs` already stamps a git revision into the version, so the check is a string
compare on a message that exists. Set that against the skew this design has now, which is between
our `cdb` client and *somebody else's* `cdb` server: unfixable by us, and reported as
`0x8007053D`, *"The server is currently disabled"*, naming neither end.

**What building it costs.** `cargo build --release --target i686-pc-windows-msvc` on the same
`windows-latest` runner `release.yml` already uses — the MSVC toolchain ships the x86 linker — and
one more file in its `Compress-Archive` list. The crate type-checks for the target today, clean, in
9.6 seconds, from a Mac. At the bench it costs a second `.stale` rename in `CLAUDE.md`'s rebuild
dance, because a second image can be held open by a second live worker.

**The address space does not bind — measured, and without an i686 build existing.** A 32-bit
worker's ceiling is the obvious worry about option 5, and the `x86\cdb.exe` already in the payload
answers it: that *is* a 32-bit DbgEng in a 32-bit address space. Against full user-mode dumps of
445 MB, 846 MB and 1,346 MB it peaked at **290, 256 and 256 MB of virtual size** (33, 29 and 29 MB
private) — flat rather than proportional, because DbgEng reads a dump on demand instead of mapping
it — while listing 80 modules and running `!address -summary` and `!heap -s` on each. The heaviest
enumeration to hand does not move it either: a full `!address`, `!heap -h 0` and `!heap -a 0`
against the 1,346 MB dump peaked at 238–255 MB and finished in one to two seconds. The dumps were
made by pointing that same `cdb` (`.dump /ma`) at an x86 PowerShell committing 260, 662 and
1,164 MB; ARM64 Windows runs both the x86 target and the x86 engine under emulation, which is the
configuration this bench would be using anyway.

Two qualifiers. **The ceiling is 4 GB rather than 2**, because `x86\cdb.exe` is linked
`LARGE_ADDRESS_AWARE` (characteristics `0x0122`, against `0x0102` for the SysWOW64 binaries beside
it) — an i686 `windbg-mcp.exe` wants the same flag deliberately rather than inheriting the x86
default, which is a `-C link-arg=/LARGEADDRESSAWARE` we control. And this bounds **the engine, not
this repo's walkers**: dbgscope's heap and pool walks build structures proportional to chunk count,
and in a 32-bit worker those are our code in that address space. The synthetic target measured here
is one large allocation, not millions of small chunks, so the walker's own footprint is what is
left to watch — measurable the day the worker exists, and not before.

**What it does not buy.** Nothing for a 32-bit *live* target — that needs the teardown question
below answered on its own terms — and nothing for the fixture problem, since the tier still has no
dump of its own to open.

**And it closes more of this item than the transport findings alone.** No named pipe means no DACL,
no password, no squat and no hijack. `GetSymbolInformation` works again because the engine is
in-process, which is the first open thread above. Teardown stops being a kill, because an i686
worker is an ordinary worker that exits when its request channel closes. And *untested over the
transport*, below, becomes moot rather than a suite to write. What it costs against that is the
second build target, the second release artefact and the two-image skew question priced above.

**Disposition.** 1, 2 and 3 are cheap and are worth doing whichever way 5 goes. 5 is the only thing
that closes the hijack, and the objection to it is a second *artefact* rather than a second
*process* — which is worth deciding deliberately rather than by default.

**The teardown has the same shape of qualifier.** It is a kill, which is safe because the target is
a dump — no live process to orphan, no kernel to leave halted — and would not be for a live 32-bit
target, the obvious next ask (a WoW64 `attach_process`). Neither the transport's security nor the
teardown should be inherited unexamined into that.

**Untested over the transport:** execution control, breakpoint arming and event waits — a dump
cannot exercise them — and the user-mode heap walker, which is in scope for x86 dumps and is
`ReadVirtual`-heavy, so likely correct but chatty over a pipe. (That last one was **wrong**, and
measuring it needed the worker this design was replaced by: the heap walker is *not* in scope for
an x86 target, it refuses one outright. See the correction above the details block.)

**Still unmeasured, and both are now second-order.** Whether an unprivileged local user can read
another account's command line — the fact this entry said would decide the password's worth. The
restricted-token stand-in cannot answer it (WMI refuses a restricted token outright, `Access
denied`), so it needs a real second local account; it matters less than it did, because the
instance-add hijack recovers the password without reading any command line. And whether the **x86**
`cdb.exe` sets the same descriptor as the ARM64 one measured here — assumed, since it is the same
transport code, but only one architecture was probed.

**Where this picked up, as it stood then**, and kept only because it names what the measurements
were taken against: `src/enginehost.rs` (the pipe name at `start`, the password comment above it,
and `await_pipe`), `build_engine` in `src/worker.rs`, `engine::spawn_worker`, and
`dbgscope::dbgeng::DebugEngine::connect`, whose doc comment records both transport quirks. That
file is deleted and `src/dump.rs` is now `src/target.rs`; the current pointers are in the item
above. The probes are `pipe_probe9`–`pipe_probe12` plus their restricted-token halves, and their
shape is worth reusing: start `cdb -server` on a sample dump, wait for the name in `\\.\pipe\`,
then read, connect or squat.

</details>

## 51. [windbg-mcp + dbgscope] `end_session` on a user-mode **attach** kills the process it attached to — **done** (2026-08-28)

**What was measured** (x64 bench, 2026-08-27, found while testing
[#234](https://github.com/glslang/windbg-mcp/issues/234) against the design it asked for).
`attach_process` on a running process, then `end_session`, and the process is **gone**: not
suspended, not detached, terminated. Identical for a 32-bit .NET target on the 32-bit worker and a
64-bit `cmd.exe` on this build's own, so it is nothing to do with item 49's second image — that is
only what made it reachable, by adding the first tier that attaches to a live process at all.

**Why it happens, which is two decisions meeting.** `DebugEngine::end_session` uses
**`DEBUG_END_PASSIVE`** for every target but a live kernel, and a passive end does not detach: it
disconnects the client and leaves the process marked as being debugged. The supervisor then
terminates the worker — `end_session` reports `worker_terminated: true`, which it reports for a
*dump* session too, so that half is simply how a session ends here. A debuggee whose debugger exits
without detaching is killed by the kernel, because `DebugSetProcessKillOnExit` defaults to true.
Neither half is wrong on its own and the combination is not written down anywhere.

**Why it is worth deciding rather than leaving.** The two openers are not alike. `launch` created
the process, so taking it away is the honest end of that session. `attach_process` did not: a
caller attaching to a running service to look at it has no reason to expect the session's end to
be the service's, and `end_session` is also what a *disconnect* and a lease expiry run, so a client
that simply goes away takes the process with it. dbgscope already has the other primitive and
already reasons about exactly this: `resume_and_detach_live_kernel` uses `DEBUG_END_ACTIVE_DETACH`
so a kernel target is left **running** rather than frozen, with a comment saying why. The user-mode
attach never got the same treatment.

**What would close it.** Almost certainly: an active detach for a session whose target this server
attached to rather than launched, leaving `DEBUG_END_PASSIVE` for a dump, a trace and a `launch`.
Three things to settle first, and none is obvious from here.

- **Which opener a session came from has to reach the engine.** `SessionKind` is the supervisor's,
  and `end_session` is served in the worker; the worker knows what op opened it, so this is a
  fact it already holds rather than a new field, but it is not one `end_session` currently reads.
- **`launch` is genuinely the other way, and possibly not uniformly.** A `launch`ed debuggee that
  the caller wants to *keep* running after the session is a real request, and DbgEng can do it —
  which makes this a question about the tool surface, not only about a flag.
- **An active detach can fail**, where a passive one is local. `.detach` on a target that has
  already exited, or one wedged mid-break, is a call that can hang or error, and it would sit on
  the teardown path a disconnect and a lease expiry both run. Whatever lands must degrade to the
  present behaviour rather than to a worker that will not go.

**Where it picks up.** `DebugEngine::end_session` and `resume_and_detach_live_kernel` in dbgscope's
`src/dbgeng.rs`, `EngineOp::EndSession` in `src/worker.rs`, and `end_session`'s own description in
`src/server.rs`, which says a session's target is "released" and does not say that for an attach
that means terminated. The measurement is reproducible in a dozen lines: attach, `end_session`,
poll the pid. `mcp_smoke::a_32_bit_managed_process_is_attached_by_an_engine_that_can_load_its_sos`
is the tier that meets it, and deliberately does not assert the behaviour either way — pinning it
would make something undecided read as decided.

**What landed** (2026-08-28, glslang/dbgscope#121 and the windbg-mcp change pinning it). The
proposal above, taken as written: an active detach for a session whose target the engine attached
to, `DEBUG_END_PASSIVE` kept for a dump, a trace and a `launch`, and `bc *` first so an `int3` this
engine patched in does not stay patched in a process that goes on running. All three of the things
the entry said had to be settled first were, and none of them the way it guessed:

- **Which opener a session came from does not have to cross the pipe.** The entry looked for the
  fact in the worker, which does hold it. It belongs in the *engine*, because `Drop` has to make the
  same decision with nobody left to ask it — the same reason `resume_and_detach_live_kernel` is
  reachable from both. So `attach_process_begin` records it and `end_session` reads it. DbgEng
  cannot be asked: `GetDebuggeeType` answers `DEBUG_CLASS_USER_WINDOWS` /
  `DEBUG_USER_WINDOWS_PROCESS` for a launch and an attach alike.
- **`launch` stays the other way, and the "possibly not uniformly" half is still not built.**
  Keeping a launched process alive past its session is a question about the tool surface — an
  argument on `launch` or on `end_session` — and nothing has asked for it. What did change is that
  all three tools now *say* what ending will do to their kind of target, which is the half of this
  entry that was about prose.
- **An active detach can fail, and it degrades to the passive end** — but it still returns the
  error, which the entry did not consider and which matters more than the degradation: this
  teardown is on the disconnect path, where a session that will not close is worse than a killed
  debuggee, and a caller told "released" would have no reason to go and look at a target that had
  just been killed.

**And the mechanism the entry gave was half wrong, in the way that mattered for testing it.** It
read the kill as the *supervisor terminating the worker*, one step after `end_session`. It is not:
the passive `EndSession` destroys the debug port itself, and the debuggee dies there — exit code
`0xC0000354`, `STATUS_DEBUGGER_INACTIVE`, set before the call returns. That is what makes this
testable inside a single process, which is why dbgscope carries the mechanism test and windbg-mcp's
tier carries only what needs a real worker to terminate.

**Two probes that look right and are not**, both discarded after they passed with the fix backed
out or would have:

- **`Child::try_wait`** answers `Ok(None)` — "still running" — for a process the kernel has already
  killed, because the exit status is set while the process object is not yet signalled. The first
  version of the dbgscope test was built on it and passed either way.
- **`CheckRemoteDebuggerPresent`** reads `false` after *either* ending. The passive end really does
  tear the debug port down; that is precisely why the process dies. "Is it still being debugged"
  cannot separate the two.

`GetExitCodeProcess` separates them completely — `STILL_ACTIVE` against `STATUS_DEBUGGER_INACTIVE`,
ten runs each way on dbgeng 10.0.26100.1 (ARM64) — and is what both repos now use.

**What is deliberately still open, and all three are now written down where a caller can read
them rather than only here.**

- **A worker killed while holding an attached target still takes the process down.**
  `Release::Parked` terminates a worker that never answered, so nothing runs `end_session` and
  nothing detaches. `DEBUG_PROCESS_DETACH_ON_EXIT` at attach time would close it and was weighed
  and rejected: it leaves the process alive with whatever breakpoints were patched into it, which
  is a target that faults minutes later with nothing connecting it to the debugger, and it would
  make the two paths disagree about what a breakpoint means. The case is rare and the outcome is
  the one that was always there. Review was right that the *documentation* had not said so, which
  is the half that was fixed: `docs/sessions.md`, the skill and `end_session`'s own description now
  carry the exception, because "attached processes survive a disconnect" read as unconditional and
  is the sort of promise someone attaches to a production service on.
- **A process added through the raw `execute` hatch is not tracked.** `.attach <pid>` reaches
  DbgEng without going through `attach_process_begin`, so nothing records it and the teardown takes
  it. Not a regression — before this it was killed like everything else — and the remedies are both
  worse than the gap: matching command text is the "list of command names" this codebase rejects
  wherever it has met it, and inverting the rule to *detach everything this engine did not create*
  would make a lost record leave a launched process running instead. Documented in the two places
  that describe the hatch, and left alone.
- **The pid-reuse window is narrowed, not closed.** `CreateProcessWide` is deferred, so an attached
  process that exits after the opener's prune and has its number handed to the launch is still
  misread. The fix that would work is a **retained handle**, which also stops Windows reusing the
  pid at all; declined because reaching the window needs an exit inside milliseconds *and* an
  immediate reuse of that exact number, and it costs a stray process where this whole path exists
  to stop somebody else's being killed. The reason is in `prune_dead_attachments`' doc comment.

**Two rounds of review landed on the same seam, and the second one says the shape was wrong.** The
first version recorded one flag for the whole session, set by `attach_process_begin`. Round one:
nothing else cleared it, so "attach, lose the target, launch something else on the same engine" —
which needs no teardown in between, since `end_session` is documented as leaving the engine reusable
— left the launched process taking the detach branch and outliving its session. Round two is the
one that matters: **DbgEng holds several user-mode processes in one session**. `|` lists them and
says `attach` or `create` against each, measured on this bench, so an engine can hold somebody
else's running service beside a program it launched itself — and `EndSession` takes one flag for
all of them, so *no* choice of flag is right. Both orderings were wrong, in opposite directions,
depending on which opener ran last.

So the mechanism went rather than the symptom, which is the rule this file's own header states:
provenance is a **set of pids**, and the teardown detaches each attached process individually with
`DetachCurrentProcess` before ending the session. Whatever is still there when the passive end runs
is a target the engine created, and `DEBUG_END_ACTIVE_DETACH` has left the user-mode path entirely.
None of it is reachable through *this* server — a worker holds one target for its whole life and
`EngineOp` has no second opener — so it is a dbgscope-API bug, fixed there.

**One check was built, measured and removed** on the way: guarding the detach on `has_target`
looked necessary, since an active detach with nothing to detach from ought to fail and would then
report an error for a program that had merely finished. It does not fail — `EndSession` with
`DEBUG_END_ACTIVE_DETACH` succeeds on an engine holding no debuggee — so a test asserting the
teardown is not an error holds the property instead of a condition that protects against nothing
measurable. The same question came back in a form that *did* need answering, which is worth the
contrast: `GetNumberProcesses` **does** fail (`E_UNEXPECTED`) with no debuggee, so the process walk
answers empty rather than asking.

**A third round found a pid-reuse alias and asked for one thing that was declined.** A pid outlives
the process it named, so an attached process that exits leaves a record matching nothing — harmless,
until the operating system hands that number to a process the engine then *launches*, which would be
detached and left running. The openers now prune records the session no longer holds, pruning rather
than clearing so a live attachment beside a launch survives. Declined in the same round: sharing the
record across two `DebugEngine` wrappers of one client. True that they cannot see each other's, and
equally true of `deferred_inputs` — a session belongs to the wrapper that opened it — while the
identity registry is keyed by client because it is a **cache tag**, which is what lets it evict on
overflow. Losing an attachment kills a process, so it must not sit behind an eviction policy. The
reason is in the field's doc comment, where the next round will meet it rather than re-raise it.

**And the test for it cost a round of "the fix does not work" against a fix that did.** `@$tpid`
answers for whichever process is *current*, and after a launch that is the launched process on a
fresh engine and the **earlier** one on an engine that has held a target before — so the same
assertion passed alone and failed in the full suite, naming the attached process as the launched
one. Nothing about the ordering is documented; it was found by printing `|` and noticing which line
carried the dot. A test that has to identify one of several processes should name it by elimination,
not by asking which is current.

**One observation not reproduced**, recorded because a flake here would be worth recognising: on
the very first paired run after a full rebuild, the detached `ping` exited `0xC0000005` instead of
surviving. It has not recurred in the twenty-four consecutive runs since, on either the paired or
the single-test path, and no later run has produced it. If it comes back it is about what the
active detach leaves in the target, not about which branch was taken.

## 55. [windbg-mcp] A **retired** handle cannot release its own session — **done** (2026-08-31)

**What it is.** A raw `execute` that replaces or releases the target — `qd`, `q`, `.detach`,
`.kill`, `.opendump` — retires the handle naming that session (`changes_debug_target` →
`SessionState::Retired`). Retirement refuses every call that *supplies* the handle while leaving
the worker live and reachable by a call that supplies none
(`a_retired_handle_is_refused_but_still_the_default_target`), and `end_session` is not exempt: it
resolves through `Sessions::resolve` like every other tool. Two things then fail to line up.

The `execute` that retires the handle appends "`end_session` releases it" — and `end_session` with
that handle is refused, which is the server contradicting its own instruction one call later. And
the refusal's own advice, "omit `session_id` to operate on it anyway", routes to the **current**
session, which is the newest one `accepts_default` admits. With anything newer open that is a
different session, so the retired one cannot be released by its owner at all: it comes back when
everything newer has gone, or on a client disconnect, or on a lease expiry. Until then it holds one
of the four slots and a live engine process with a live target.

**Measured** on the release build, 2026-08-31, through the shipped MCP transport rather than from
the source: two launches, the older retired with `execute { "command": "qd" }`. `end_session` by
handle was refused with the retirement message; `session_status` then reported that session
`live: true, current: false` holding its own `engine_pid`, and the *newer* one `current: true` — so
an un-handled `end_session` would have taken the wrong session. Ending the newer one first made the
retired one current, and an un-handled `end_session` released it.

**Why it was deferred.** It was found by the session fuzz
(`a_randomised_command_sequence_leaves_the_session_in_one_state_and_the_server_serving`) on
the round-teardown path rather than in the fuzz's own oracle, and a test is the wrong place to
decide what `end_session` should do about a handle the server has deliberately stopped honouring.
There is a real argument for today's behaviour — the handle no longer names what it was issued for,
and honouring it for one tool is a hole in the rule every other tool keeps — so the fix has to pick
a side rather than patch a sentence.

**What would close it.** Either of two, and they are not the same claim:

- **Exempt `end_session` from retirement.** It does not read the target, it releases the worker,
  and it is the answer every other refusal on this session gives — the same argument that already
  exempts it from `worker::refuse_when_the_target_is_gone`. Cheapest, and it makes the note
  `execute` already appends true.
- **Or keep the refusal and fix what it promises.** "Omit `session_id`" is a recovery only while
  nothing newer is open, so the refusal should not offer it unconditionally — and there is then no
  way at all to release *that* session by name, which is the part worth not shipping.

The first is what `execute`'s own output already tells a caller, so it is the one to take unless
someone argues for the second.

**What was done.** Both, because the second was not an alternative to the first once the first was
taken — it is the sentence the fix leaves behind.

`SessionState::accepts_teardown` is a third predicate beside `accepts_handle` and
`accepts_default`, admitting the same set as the latter and answering a different question:
retirement says the handle no longer names the *target* it was issued for, and a teardown does not
touch the target — it releases the **session**, which the handle still names exactly. Its own
predicate rather than a second caller of `accepts_default`, whose set is the same today, because a
state that ever wants one without the other should be a change there rather than a surprise.

**Both gates had to widen, and that is measured rather than reasoned.** There is a caller-side
check (`Sessions::resolve`, now `resolve_for_teardown` beside it) and a queue-front one
(`Gate::admits`, reached through the new `On::Teardown` and `Call::releasing`). Backing out either
half alone was tried, and the end-to-end test fails identically both ways: widening only the
resolve trades the refusal for the same refusal a moment later, from a place with no caller to
explain it to. `a_teardown_gate_admits_exactly_what_a_teardown_resolve_does` is the unit-level
join that says they agree on every state.

The refusal text changed too. It now names `end_session` **with the handle in it** as the recovery
that always works, and mentions omitting `session_id` second and *qualified* — "only while this is
still your current session" — because unqualified it reads as a way back to this target and is a
way to act on another.

**Covered by `a_handle_a_raw_command_retired_can_still_end_its_own_session`**, and the second
launch in it is the test rather than scenery: with one session open the retired one is still
current, so an un-handled `end_session` reaches it and the defect is invisible. That is why the
fuzz found this on its round teardown and no single-session test ever did. It asserts both
directions — a tool that reads the target is *still* refused, so the widening did not delete the
guarantee — and it was checked by backing the fix out, where it fails.

`fuzz_reclaim` lost its fallback: a round that cannot release by name is now a regression rather
than a documented detour, over a 50-round soak that draws every retiring command in the corpus.

**Where it picks up.** `end_session` and `changes_debug_target` in `src/server.rs`,
`SessionState::accepts_teardown` with `accepts_handle`/`accepts_default`, `On::Teardown`,
`Call::releasing` and `Sessions::resolve_for_teardown` in `src/engine.rs`, and `fuzz_reclaim` in
`tests/mcp_smoke.rs`.

## 57. [windbg-mcp] `ioctl_trace` installs a breakpoint and reports nothing about it — **done** (2026-09-02)

**What it was filed for.** `ioctl_trace` built a `bp <dispatch> ".printf …; gc"` and ran it as a raw
command, so its answer was whatever `bp` printed — which on success is **nothing at all**. No id, no
confirmation anything was armed, and no way to tell "installed" from "silently did nothing" without
a separate `bl`. Bounding the command (item 14) sharpened it: a cut-short `bp` may have installed the
breakpoint before the break, and this tool could not say which happened.

**What landed.** The tool routes through `EngineOp::SetBreakpoint` with the logging command as a
typed `command` parameter, so it inherits the whole typed report —
`structured::BreakpointSet`, with the breakpoint the engine created, what it replaced, and whether
the location resolve was cut short. It declares an `outputSchema` to match, which is not a detail: a
structured-aware client **replaces** the text block with `structuredContent`, so a tool that sends
one without declaring a schema hands those clients an undeclared shape and takes their text away.

**The entry's own cheap version was the wrong one, and knowing why is the point of keeping this.**
It proposed passing `<dispatch> ".printf …; gc"` as `EngineOp::SetBreakpoint`'s **expression**,
reasoning that `worker::set_breakpoint` built `bp {expression}` so the command would come out
identical "and the whole typed report comes for free". That was true of the code as it stood and is
now false in a way that would not have failed loudly: the op no longer builds a command line, so an
expression carrying a quoted command string would be handed to `SetOffsetExpression` as a *location*
and refused, or worse, silently resolved to something else. The cheap version was a shortcut through
an implementation detail rather than through the interface, and the detail moved.

**What the better version cost, and what it removed.** It depended on
[dbgscope#126](https://github.com/glslang/dbgscope/issues/126) — a typed breakpoint API — which
landed as [dbgscope#127](https://github.com/glslang/dbgscope/pull/127). What it deleted is the
hand-escaping this entry named as "the one place in this server where `bp`'s syntax is the point":
the command was `\\\"` per quote and `\\n` for the newline, written inside a Rust format string,
and `dispatch` had to be screened for `;` and `"` because either would have closed the quote and
appended a command of the caller's choosing. As a parameter there is nothing to escape and nothing
to screen — `reject_command_breakers` stays on the tool as defence in depth rather than as the only
defence.

**Where it picks up.** `ioctl_trace` in `src/server.rs`, `EngineOp::SetBreakpoint` in
`src/proto.rs`, and `worker::set_breakpoint`.
## 60. [windbg-mcp] Structured dispatch reachability paths for the Binary Ninja bridge — **done** (2026-09-10)

**What it was filed for.** `reachable_from_dispatch` answered in prose alone, so a program that
wanted to act on a path had to parse the rendering — and the addresses in it were bare virtual
addresses, which are facts about one boot of one machine and join to nothing.

**What landed.** The tool declares an `outputSchema` and returns `structured::Reachability` beside
the text it always returned, which is unchanged: both halves are built from the same `Report`,
neither derived from the other, because deriving one from the other is how the two come to disagree
about a figure. The typed answer carries the verdict, the call path as `{site, kind, callee}` hops,
the branch recipe as a segment per function with a decoded predicate per step, and each of the three
independent reasons a `not_reachable` may be incomplete — a work bound, a halt, and instructions the
walk could not see past. `structured_report` lives in `src/driver.rs` and takes a **closure** for
turning an address into a location, exactly as every other pass in that file takes one: attribution
is an engine call and that file has never seen an engine, which is also what makes the mapping
unit-testable against a locator a test invents.

**The entry read "carry PE matching metadata plus RVA" as a per-address field, and measuring said
otherwise.** Built that way first, and it works: every location was self-describing, carrying its
module, image name, timestamp, size and PDB GUID. On the real `mountmgr` walk that is the same
150-odd bytes repeated across a path, a containing function, and five recipe steps — one image, said
eleven times. The identity is a property of the **image**, so it moved to an `images[]` beside the
locations and each location carries the module name and RVA that key into it. That is also what the
tools emitting the most addresses already do: `disassemble` and `backtrace` carry `module` + `rva`
and no identity. Payload on that walk: 1,979 B of values against 1,472 B of text.

**And `from` is an `Option`.** A walk whose seed never disassembled has explored nothing to have a
verdict about, and the tool reports that as an error rather than a verdict — so the field is
unreachable through the tool. It was briefly a zero address instead, which is a coordinate nobody
produced; a missing field is the smaller lie.

**Attribution is one call per module, not one per address.** `worker::Attributor` holds a single
module and re-asks only when an address falls outside it, which is right for everything it
attributes: a disassembly is a contiguous range, and a call path is a driver's own routines with an
occasional hop into `nt`. The guess can only save a call, never change an answer.

**What this does not do.** The last sentence of the original entry is a constraint on work that has
not happened rather than a deliverable: if runtime coverage is ever imported, it must mean *observed
execution* only, and an unobserved location is still not proof of unreachability. The verdict here
stays asymmetric for the same reason — `reachable` is sound, `not_reachable` is best-effort within
everything that bounded the walk.

- **Where it landed:** `src/structured.rs` (`Reachability`, `CodeLocation`, `ImageRef` and the
  enums beside them), `src/driver.rs` (`structured_report`), `src/worker.rs` (`Attributor`),
  `src/server.rs` (the schema and the typed refusals), `docs/structured-results.md`,
  `docs/coordinates.md`.

## 63. [binja-windbg-mcp] Decode AArch64 CLRBHB in instruction text and analysis — **done locally** (2026-09-15)

**Original report and first investigation (retained):**

BN 6.0.10601 exposes the affected entries as four-byte functions without instruction text.
The companion's exact-encoding export fallback supplies flow-graph bytes without changing
Binary Ninja's decoder, IL, or function boundaries.

**2026-09-15 implementation:** [native validation](docs/clrbhb-native-validation.md)
reproduces the failure on all sixteen endpoints and identifies a missing operand-conversion
case in current upstream source. A proposed patch fixes standalone decoding and adds a
proposed IL intrinsic. The new C regression passes after the decoder correction and
42,639 existing corpus entries are unchanged. The IL/plugin build and upstream GUI
analysis/comparison acceptance remain unvalidated; the older-version fallback stays.

- **Why deferred:** exporter acceptance is complete; correcting native analysis is separate
  upstream work. Textual similarity for these entries remains limited by the decoder.
- **What would close it:** verify an upstream version decodes `df2203d5` as CLRBHB and provides
  instruction text, then check the affected function analysis and comparison output. Keep the
  fallback for older supported versions unless their support is explicitly dropped.
- **Where it picks up:** [diagnosis and retained graph evidence](docs/secure-kernel/securekernel-export-followup.md).
  Check upstream decoder status before proposing or removing a workaround.

**Closure — 2026-09-15:** the user chose a companion-maintained native replacement
so this item no longer depends on waiting for an upstream release. The patch,
version-pinned builder, reversible installer, and disposable GUI capture now live
in `binja-windbg-mcp/native/arm64` and its `tools` directory. The package is pinned
to Binary Ninja 6.0.10601 / SDK ABI 187 on Apple Silicon; an upstream PR draft is
prepared locally for later submission.

The [replacement acceptance](docs/clrbhb-native-validation.md#companion-maintained-replacement--accepted)
proves the user-profile native library loaded with the bundled architecture disabled.
All sixteen endpoints now decode and analyze as three-instruction, 12-byte functions
with `SystemHintOp_CLRBHB` IL. External BinDiff completed with 3,101 matches, zero
omitted functions and all eight complete endpoint diffs. Input bytes, analysis and
generations were unchanged; the GUI exited zero without a new crash report.
The companion's 197 tests pass, including ten new package tests. The app bundle and
normal profile were not modified. Older-build exporter fallback remains in place.
Upstream submission and eventual removal of the replacement are subsequent work;
items 61, 62, 64 and 65 retain their separate closure conditions.

## 70. [dbgscope] A path component is matched by folding ASCII — **done** (2026-09-14)

**Repo:** `dbgscope` ([#161](https://github.com/glslang/dbgscope/pull/161)), with the consumer in
`windbg-mcp`.

`Namespace::object_at` resolved each component with `object.name.eq_ignore_ascii_case(component)`.
The object manager compares through the system's uppercase table, not through the twenty-six
letters of ASCII, so a name differing only outside ASCII -- `K` `U+00E4` `se` against `K` `U+00C4`
`SE`, one object to the kernel -- came back
`ObjectError::NotFound`, which is the answer a caller acts on.

**The settled shape was copied rather than re-derived, and that was the whole of the entry's
advice.** `nt!ObpLookupDirectoryEntry` on 26100 folds one `WCHAR` at a time in three bands: `a`-`z`
inline, nothing below `U+00C0`, and the 8-4-4 `UnicodeUpcaseTable844` trie above it. Rust's
`to_uppercase` is the *full* Unicode mapping and is wrong in both directions -- it expands
(`U+0130` against `i` `U+0307`, two objects made one) and it is contextual (either sigma, one
object made two). Where a host cannot show the kernel's one-unit mapping the fold answers
`NameMatch::Undecided`, and `object_at` does not return `NotFound` for it.

**`NotFoundInPart` gained a third count rather than a fourth variant, and that is the part worth
carrying.** The obvious shape is a variant of its own -- the message's framing is about entries
that could not be *read*, and an undecided fold is about a comparison. It does not compose: a
directory can have both an unreadable entry and an undecidable name at once, and two variants then
need a third for the pair. One variant with three counts kept apart extends by one figure. They
stay apart for the reason the first two do, plus one: a page that was out will be back, an entry
the object manager cannot have written will not, and a name this crate could not fold is a limit of
*this crate* -- so summing them would tell a reader to retry the one thing retrying cannot fix.

**The fold is public, and `windbg-mcp`'s copy is deleted.** The entry proposed copying, and
copying a three-band reproduction of a kernel routine into a second repository is a second thing to
keep in step. `same_object_name` takes `&str` and folds per code unit, so `device::same_object_path`
hands it a whole path and keeps only what is about a *path* -- the trailing separator, and the
refusal to match a prefix.

**And then the reproduction itself turned out to be the bug, which no part of this entry
predicted.** The fold was `char::to_uppercase`, and `std` exposes only the **full** Unicode case
mapping -- so 102 code units had no one-unit answer and the fold declined to speak for them. That
was the known limit, and it drove a three-way `NameMatch` with an `Undecided` arm. Checked against
a live 26100 kernel's own `RtlNlsState.UnicodeUpcaseTable844`, dumped over KD and walked as an
8-4-4 trie, there were **224 further code units where the fold was confident and wrong** -- folding
where Windows does not, so two objects compared equal. `U+0131`'s Unicode simple uppercase is `I`
and the system's table leaves it alone, so `\Device\ı` and `\Device\I` were one object. Windows'
table is not Unicode's: it declines mappings that would break round-tripping (`U+0131`, `U+017F`,
the titlecase digraphs) and predates the `U+A7xx` additions.

**So the fold is performed rather than reproduced**, by calling the `RtlUpcaseUnicodeChar` that
`nt!ObpLookupDirectoryEntry` calls -- established by disassembling it on that target, where it has
two `bl` sites to that function and inlines the same trie against the same table pointer. The two
bands that read no table (`a`-`z` inline, and the `U+00C0` floor) stay reproduced, because those
are knowledge rather than guesses.

**Which deleted the three-way answer rather than fixing it.** `NameMatch::Undecided`,
`Match::Unknown`, `NotFoundInPart`'s `undecided` count and `device_security`'s `links_unfolded`
all existed because a stand-in could not speak for the table; performing the fold leaves no
comparison undecided, so every one of them lost its producer. `FOLLOWUPS.md` item 76 -- filed
during this work, about the stickiness of that third answer -- was deleted unbuilt for the same
reason. **The general lesson is the one the `device.rs` comment had inverted**: it said no
character could make the fold answer *wrongly* any more, only vaguely, and the opposite was true.
Three rounds of review had hardened the *reporting* of an approximation nobody had checked against
the thing it approximated.

**What is left is one assumption, and it is `FOLLOWUPS.md` item 77**: the call reads the debugger
host's NLS table rather than the target's. Measured identical across all 65,536 units on this
bench, and nothing detects a host and target of different vintages.

**Verified by mutation, not by a green run.** Restoring the `char::to_uppercase` reproduction fails
exactly the two tests that are about the table and nothing else; folding `upcase` back to
ASCII-only fails the three `object.rs` fold tests.

## 75. [dbgscope + windbg-mcp] An instruction's operands are not every register it reads — **done** (2026-09-14)

**Repo:** `dbgscope` ([#161](https://github.com/glslang/dbgscope/pull/161)) and `windbg-mcp`.

`Instruction::writes` exists because inferring a destination from the first operand is right for
the shapes a compiler usually emits and wrong for two it also emits. The read side had the same gap
and no equivalent, so `ioctl_map`'s loss check asked `operands` -- which names the explicit reads.
`Instruction::reads` is the same answer in the other direction, from the same `used_registers()`
call with the `OpAccess` filter mirrored, under the two contracts `writes` states: a register named
as the read reaches it, and empty meaning "not decoded" rather than "reads nothing". Both halves
now come from **one** factory call, since `used_registers()` is one list carrying every access.

**The entry's own account of the gap was wrong, and finding a test is what exposed it.** Swapping
`note_loss` to `reads` passed the whole suite, and so did putting it back -- so the clause was
unexercised, which is the same as untested. Finding a shape that discriminates meant measuring what
`reads` actually adds: over every flag-writing instruction iced decodes in 64-bit mode, the
registers `reads` names that neither the operand list nor `writes` do are, for every mnemonic a
compiler emits, the registers that form a **memory address**. The three shapes the entry named --
`mul` reading `eax`, `cmpxchg` reading `rax`, the string instructions reading `rsi`/`rdi`/`rcx` --
do go unnamed by the operand list, and every one of them also **writes** the register, so the
carried-and-gone half had them already. The entry's premise held about `operands` and not about
what the pass had.

**So the shape that discriminates is `test dword ptr [rcx+8],3` with the code in `rcx`**, where all
three clauses answer no: a memory operand has no register for `register_full`, the probe beside it
asks about the slot rather than the base, and `test` writes no register. That is the test, and it
asserts its own premise -- the decoder names `rcx` as a read, the operand list names no register at
all -- so a fixture drifting off that shape fails rather than passing for a reason that is not this
rule.

**And it is conservative rather than exact, stated rather than papered over.** The flags there are
computed from a load at an address derived from the code, not from the code. A pass that believes a
control code is being dereferenced has lost the value whichever half is wrong, and the direction to
be wrong in is the one that stops claiming -- which is the direction the whole of `ioctl_map` is
already in.

**What this bought is the shape of the question rather than a case that was reading short**, which
is what the entry predicted and is worth recording as confirmed: the pass now asks the decoder
which registers an instruction reads instead of which ones its spelling names, so the next shape
that matters needs no clause.

## 76. [dbgscope] A fold that cannot decide one code unit declines the whole comparison — **deleted unbuilt** (2026-09-14)

**Repo:** `dbgscope`. Filed and deleted the same day, and here rather than gone because the number
was committed and cited in between.

It was a real defect in what item 70 had just landed. `same_object_name` folded both names and
compared the sequences whole, so *any* mismatch where either side carried a code unit the fold
could not decide came back `NameMatch::Undecided` — including a mismatch with nothing to do with
that unit. Because `object_at` counted per **directory entry**, one object named `Straße` would
make every unrelated miss in that directory `NotFoundInPart` rather than `NotFound`, indefinitely.
The fix was to be two refinements resting on the fold's own one-to-one contract: unequal lengths
are `Different` certainly, and equal lengths compare pairwise so a certain-certain mismatch
anywhere proves `Different`.

**None of that was built, because `Undecided` stopped existing.** The reason the fold declined 102
code units was that it *reproduced* the object manager's table out of `char::to_uppercase`, and
`std` exposes only the full Unicode mapping. Verifying that reproduction against a live kernel's
own table found it also **confidently wrong about 224 other code units** — so the answer was to
call `RtlUpcaseUnicodeChar` rather than to refine an approximation of it, and a fold that performs
the real thing has no comparison it declines to make. `NameMatch` collapsed to a predicate and this
item's subject went with it.

**Worth reading for the ordering.** This was filed as the careful thing to do: a precision
improvement, deliberately not slipped into a copy because it would flip an expectation two
repositories pinned with a review-settled reason. That instinct was right and the analysis was
aimed one level too high. The pinned expectation was not a considered trade-off to be respected —
it was a symptom, and measuring the thing underneath it deleted the trade-off rather than resolving
it. Item 70's entry has what the measurement said.

## 77. [dbgscope] The fold is the *host's* upcase table, not the target's — **done** (2026-09-15, dbgscope#162)

**Repo:** `dbgscope` ([#162](https://github.com/glslang/dbgscope/pull/162)) and, through it,
`windbg-mcp` ([#323](https://github.com/glslang/windbg-mcp/pull/323)).

`object::upcase_unit` called `RtlUpcaseUnicodeChar`, which reads **this machine's** NLS upcase
table. The object manager reads the target's, at
`PsGetCurrentServerSiloGlobals()->RtlNlsState.UnicodeUpcaseTable844`. On the bench where that was
settled the two agreed on **all 65,536** code units -- the target's table was dumped over KD and
walked, and the host's `RtlUpcaseUnicodeChar` matched it everywhere -- but both machines were
26100-era ARM64 Windows, which is the easy case rather than the general one.

Nothing detected a disagreement. A debugger host several Windows versions older or newer than its
target could differ exactly as Unicode's table differs from Windows': the `U+A7xx` additions are
the ones that moved most recently, and they are 40 of the 224 code units the previous fold was
wrong about. The failure would have been silent and would have looked like item 70's -- two objects
reported as one, or one as two. It was found verifying item 70's replacement fold against the
target's own table on a live 26100 ARM64 kernel, which established the agreement and, with it, that
nothing checked for it (2026-09-14).

**What landed.** `Upcase` walks the target's own table -- the 8-4-4 trie transcribed instruction
for instruction from `RtlUpcaseUnicodeChar`, whose disassembly is in its doc comment -- and falls
back to the host's call when the target will not say where its table is, with `source()` reporting
which answered so a fallback no longer reads as a measurement. `Globals::upcase` carries the three
coordinates, resolved by symbol and type the way `Layout` is. `Namespace::upcase()` is the walk's
own fold, and `device::same_object_path` here now takes one rather than reaching for the host's.

**What the entry got right.** `Globals` was the shape to follow, the walk is the 8-4-4 trie, the
two ASCII bands stay ahead of the table, and a missing `nt!PspHostSiloGlobals` needed an answer
that already existed. The design change it warned about did not materialise: `same_object_name`
still takes two `&str` and needs no `Namespace`, because the fold became a *value* rather than a
method, so the walk's rules are still testable with no target at all.

**And what it got wrong, which is the part worth keeping.** It expected the fallback to want an
answer meaning "undecided" -- `NameMatch` again. It does not, and the reason is a distinction the
entry did not have: a table that will not **read** and a table pointer that reads as **null** are
opposite facts. The first says nothing about the target, so the host's table stands in. The second
is the target's own answer -- `RtlUpcaseUnicodeChar` tests that pointer and returns the code unit
unchanged -- so answering it from the host's table would fold where the target does not, which is
exactly the failure item 70 fixed. Two answers, both determinate; nothing left for a third.

**Measured on a live kernel (2026-09-15), which is what this entry shipped without.** It shipped
saying the read itself was inference: the bench had no reachable kernel and no full dump, a
minidump's `PspHostSiloGlobals` page reads `????????` -- exercising the fallback and only the
fallback -- so the symbol and both offsets were confirmed against a 26100 x64 kernel PDB and
`PsGetCurrentServerSiloGlobals` was disassembled, but *that the pointer at that address is the
table* was not observed. It is now, against a rebooted CTF guest over KDNET:

| | |
|---|---|
| target | 26100 x64, `26100.33438.amd64fre.lt_release_svc_prod1.260904-1524` |
| `nt!PspHostSiloGlobals` | `fffff802ed9ce940` |
| `_ESERVERSILO_GLOBALS::RtlNlsState` | `+0x408` |
| `_RTL_NLS_STATE::UnicodeUpcaseTable844` | `+0xa8`, so the pointer is at `+0x4b0` |
| the pointer there | `fffff8027f670004` -- a table, `u16`-aligned inside a larger NLS block |
| the table | 10,240 bytes, 5,120 `u16` elements; the walk reaches element 2,543 at most |
| walked against this host's `RtlUpcaseUnicodeChar` | **0 mismatches over all 65,536 code units** |

So `+0x4b0` is the live coordinate, not a PDB's arithmetic, and the 8-4-4 walk in `Upcase` is the
walk that table wants.

**And the two builds' tables are byte-identical** -- this host's `ntdll` copy on 26200 x64 and the
guest kernel's on 26100 x64 are both 10,240 bytes with sha256
`0721d3e6aea68087e5f59bfd239029c5087f4ed2d2c42cd1c81c1cc661767133`. That is the *premise* of this
item holding again on a second pair, and it is worth reading the right way round: agreement between
nearby builds is cheap, which is why it was never evidence that calling the host's routine was safe.
The fold reads the target's table because two builds agreeing says nothing about two that do not.

**An attribution in this entry is unverified, and is now known to be wrong in one of its two
places.** It recorded `+0x4b0` as "measured on 26100 ARM64". The guest measured above is 26100
**x64**, so that half is wrong, and the ARM64 wording came from notes about the bench rather than
from a reading taken on one.

The same attribution is in the *how it was found* paragraph higher up, where it describes item 70's
verification on 2026-09-14. That is left standing because it is a claim about a session this one
cannot check -- there may well have been an ARM64 target that day -- and rewriting it to match
today's guest would replace an unverified claim with a different unverified claim. Treat it as
**unconfirmed** rather than as a second reading: the only architecture these offsets have actually
been observed on is x64, on both 26100 and 26200.

**What made it verifiable without one.** The trie walk reproduces `RtlUpcaseUnicodeChar` on all
65,536 code units against a table built from real Windows NLS data by an encoder sharing no code
with the walk -- 973 of them move, and the test asserts that count so a fixture where none moved
could not pass vacuously. Six mutations were each caught: the walk site reverted to
`same_object_name`, the leaf substituted rather than added, level two indexed relative to level
one, an index read as a byte offset, the null check removed, and the cache removed.

## 78. [dbgscope] The VS allocator layout moved again, and the pool walker refuses the build — **done** (2026-09-15, dbgscope#167)

**Repo:** `dbgscope` ([#167](https://github.com/glslang/dbgscope/pull/167)) and, through it,
`windbg-mcp` ([#329](https://github.com/glslang/windbg-mcp/pull/329)). Surfaced by `windbg-mcp`'s
live-kernel tier.

Two tests in that tier failed against the CTF guest on
`26100.33438.amd64fre.lt_release_svc_prod1.260904-1524`, both refusing the build:

```text
resolving pool layout failed (unsupported allocator layout fnv1a64:77069ff603c2356c:
no recognized VS structural family is complete); run `.reload /f nt` and retry
```

`_HEAP_VS_AFFINITY_SLOT::VsContext` is spelled **`VsContextOffset`** on that build. Because the old
name sat in a *required* field list, `resolve_type` dropped the whole type — taking `FreeChunkTree`
and `DelayFreeContext` with it — so one renamed field refused the build entirely.

**What the entry got right.** That it is a shape and not a spelling, and that the alias was the
tempting wrong fix: read as an address, a displacement matches no context and every slot is
rejected — a walker that reports the older family's name while walking no VS evidence. Confirmed
live, with the old rule in place: `VS affinity slot 0x1b146000d40 claims context 0xa80, not
0x1b1460002c0; skipped`. It was also right that the semantics had to be measured first.

**What it measured.** `VsContextOffset` is `slot - context`, unscaled bytes.
`ntdll!RtlpHpVsSlotCreate` stores exactly that (`mov rax,rbx; sub rax,rdi; mov [rbx],rax`, `rdi`
being the context the slot was created for), and a live slot held `0xa80`, which was both
`slot - context` and `SlotRef << 6`. `RtlpHpVsContextGetSlotInfo` is **unchanged**, so the slot-map
arithmetic the walker already had needed no edit at all.

**What it got wrong, and it is the useful half.** The item scoped this to the *pool* walker on a
*kernel* target. `src/heap.rs` shares `provenance()` and `vs_roots()` with it, and `heap::list`
resolves the schema *before* it enumerates heaps — so all five user-mode heap tools were down too,
on **any** current Windows. That made the whole thing reproducible on the debugger host itself, with
no VM: `heap_list` against a local process refused with the same message and a different fingerprint
(`fnv1a64:ebf529c63c266d4a`). The measurement that unblocked the item was then taken in user mode
against `ntdll`, not over KD — [[ntdll-mirrors-kernel-rtl-structures]] as a working method rather
than a note.

**And the fingerprint it asked to pin could not be pinned.** The item says to keep
`fnv1a64:77069ff603c2356c` "in the test that pins it". That digest is over every resolved fact, and
the fix resolves one field more — so it identifies the *pre-fix* reading of that build and is a
value the fixed code never produces. The guest now reads `fnv1a64:bbc9a6daae9ff7a2`. What is pinned
instead is the thing actually at risk: the schemas of the two **older** shapes, against digests
recorded before the change, so a future edit that withdraws support for them fails rather than
passes.

**What landed.** A third `VsSemanticFamily` — `AffinitySlotsSelfRelative` (`affinity_slot_vs_offset`)
— beside `Inline` and `AffinitySlots`, because the two affinity shapes are *checked* differently
rather than spelled differently. `AllocatorSchema::vs_shape` is now the one place that judges the
family, consumed by both `provenance()` and `vs_roots()`; they previously reached the same
conclusion independently from two copies of the field list. A PDB carrying both spellings is refused
as ambiguous rather than resolved by precedence. And the refusal names what each family wanted and
what was missing — the old message said only that no family was complete, which reads as a symbol
problem and is why the first diagnosis of this went to `.reload /f nt` before anyone compared a
field name.

**Three builds, not a migration.** Selection stays structural — the fields a target's own PDB
carries, never a build number. The repo's own checked-in dumps turn out to span all three:
`121524-4703-01` has no `_HEAP_VS_AFFINITY_SLOT` at all (inline), `052126-34312-01` and
`081226-2187-01` carry `VsContext` (address), and `082126-7015-01` already carries
`VsContextOffset`. The last is ARM64 and the walker is x64-only, so two of the four are reachable
through the tools; `an_older_builds_allocator_schema_still_resolves` uses that pair to pin the
older shape against **real** type information rather than synthetic offsets.

**Verified.** 299 dbgscope unit tests; both wrong fixes mutation-checked (the alias, and the two
back-reference rules swapped in each direction). Live `ntdll` on 26200: 8,878 chunks where it
previously refused. Live kernel, the guest this item was filed from: 326,098 chunks, and the
tier passes 10/10 including the two tests named above.

## 86. [windbg-mcp] A pool-walk test caps the whole server, including the open it needs first — **done** (2026-09-19)

**Repo:** `windbg-mcp`.

`mcp_smoke::a_pool_walk_takes_this_servers_deadline_not_the_walkers_default` started a server with
`WINDBG_MCP_CALL_TIMEOUT_SECS=60`, because the walk budget it pins is derived as the call timeout
less 15s of headroom and 45s is distinctively not the walker's own 120s default. But that variable
is **server-wide** and is read on every call, so the same 60s also capped the `open_dump` the test
performs to get a session -- against a default of **300s** (`ENGINE_CALL_TIMEOUT`, `src/main.rs`).

Opening the sample dump does symbol work. On a contended runner it exceeded 60s, and the test then
failed with `open_dump` timing out, having measured nothing whatever about the budget it exists to
pin:

```
assertion `left == right` failed: `open_dump` did not succeed: engine call timed out
  left: String("error")
 right: "ok"
```

**Measured twice on 2026-09-19, on code neither change touched**: `main` at `ecfbabb` (the merge of
[#345](https://github.com/glslang/windbg-mcp/pull/345), on the **x64** tier) and
[#347](https://github.com/glslang/windbg-mcp/pull/347) at `08d6f6e` (a Markdown-only diff, on the
**ARM64** tier). So it is neither architecture-specific nor caused by what it lands on -- it is a
budget the test imposed on a step it was not reasoning about. Fifteen CI runs on `main` over the
same period: fourteen green, one red, and the red one is this.

**The remedy was already in that file, twice, and the first draft of this item did not say so.**
Two other tests lower the same variable and both deal with the open it also caps.
`a_running_command_is_interrupted_on_request_and_frees_its_session` hit *this exact failure* --
"36s was measured on a CI runner against a budget of 30, and the test then failed inside the open
rather than in anything it is about" -- and raised its budget to **90s**, sized for the open. And
`a_pool_query_with_no_time_to_walk_is_refused_rather_than_run` runs at 10s and **skips** when the
open does not land, so a slow runner cannot fail it. Raised on review of
[#347](https://github.com/glslang/windbg-mcp/pull/347).

**What landed.** 90s, following the first of those two precedents, with the comment beside it
saying *why* rather than only what: the budget governs the open on the next line as well, and that
open resolves symbols over the network, so how long it takes is the symbol server's to decide
rather than this bench's.

**And 90s did not hold** (2026-09-20). The same failure came back on the ARM64 tier, again on a
Markdown-only diff — [run 35521847427](https://github.com/glslang/windbg-mcp/actions/runs/35521847427),
`open_dump` timing out at the cap. Three occurrences in two days at two different figures is the
answer to which of the two precedents was the right one: the number was never the variable, since
the open's cost is the symbol server's to decide, and this entry picked the remedy that moves it.
The test now **skips** when the open does not land, which is what
`a_pool_query_with_no_time_to_walk_is_refused_rather_than_run` had been doing all along; 90s stays
to make that skip rare rather than to make it unnecessary. What this entry got right is that the
budget governs the open — what it got wrong is that sizing it is a fix.

**What the item got wrong, and it is the half worth keeping.** "90s here derives a 75s walk budget,
still distinctively not the walker's 120s default, so the assertion survives that fix" is true of
the *property* and false of the *code*. The assertion is a literal range -- `(40.0..=46.0)` -- and
its failure message quotes 60s and ~45s beside it, all of which are pinned to the budget being
replaced. Raising the variable alone therefore would not have turned the test green; it would have
turned a timeout into an assertion failure, red for a second wrong reason. Measured on the ARM64
bench by narrowing the range to something impossible: at a 90s budget the worker derives
**74.998947292s**, which the old range misses by 29 seconds. So the range moved to `(70.0..=76.0)`
and the message with it -- a change of four literals, not one, and the item's "small change
following an established precedent" was right about the shape and wrong about the extent.

**Raised rather than skipped, because the two precedents are not interchangeable.** The 10s test
skips when the open does not land because it *cannot* be sized for the open: a budget that is
entirely reply headroom is the thing it exists to pin. This one can be, since it needs a
*distinctive* budget rather than a short one -- and a skip here would buy the same green by
measuring nothing on exactly the contended runners where the arithmetic is under stress.

**Filed rather than fixed where it was found**, because that branch was docs-only and the change
belongs beside the test, with the rerun that proves it -- which is what this entry records.

**Verified** on the ARM64 bench (`aarch64-pc-windows-msvc`), on the tree at `b1c205f` plus this
diff, debugger tier on (`WINDBG_MCP_SMOKE_DUMP=1`): `cargo test --test mcp_smoke pool` passes 2 and
ignores the 2 that need a live KDNET target. The 74.998947292s above is from the same tier with the
range mutated, which is also what says the assertion is reading a real budget rather than passing
vacuously. `cargo fmt --all --check` and `cargo check --target x86_64-pc-windows-msvc --all-targets`
are clean on the Mac. What is **not** measured is the failure itself: the open exceeding 60s needs a
contended runner, so nothing here reproduces it on demand and the evidence for it remains the two
CI runs above.

## 82. [windbg-mcp] A64 puts constants in a literal pool, and the walk cannot read one — **done** (2026-09-19)

**Repo:** `windbg-mcp`.

No single A64 instruction can materialise an arbitrary 32-bit constant. A compiler builds one
either as `movz`/`movk` -- which [#343](https://github.com/glslang/windbg-mcp/pull/343) taught the
walk to fold -- or as a **PC-relative literal load**, `ldr w20,<pool>`, which reads four bytes of
`.text` the walk never looks at. The second is one instruction against two, and MSVC uses it
freely.

Measured on the live ARM64 target, 2026-09-19, over seven drivers and **235** recovered control
codes: **0** carry a proven size, and 15 carry length-check evidence marked `exact: false`. Not one
case anywhere reports `accepted: false`.

The cause is one read. `rdyboost!SmdDispatchDeviceControl+0x1b8` is
`ldr w20,<pool>` / `b <epilogue>`, and the pool holds `0xc000000d`
(`STATUS_INVALID_PARAMETER`). [`error_status`](./src/ioctl.rs) looks for a constant put in the
return register or the IRP's status field and finds a *memory operand* instead, so the block is not
a refusal -- and `exact` requires `Condition::NotEqual` **and** a target that refuses. The
condition half is already right: `cmp w2,#4` / `bne` at `rdyboost+0xf2f4` is exactly the shape the
rule wants. Only the refusal is invisible.

It reaches the codes themselves, not just the evidence. HEVD's dispatch compares against
`ldr w8,HEVD+0x87824`, whose pool entry is `0x0022203b` -- a control code. That map is right only
because HEVD's *cases* come from the `sub`-and-compare chain beside it and the literal is merely
the range bound.

**What is missing there is the cases, not the warning**, and the distinction matters because it
decides what a fix is for. A compare of the traced code register against a value `scalar_of` cannot
resolve still returns a `Compared` carrying an `index` and `code: None`, and the equality arm pushes
it onto **`untracked`** (`src/ioctl.rs`) -- the list built for exactly this, after a map reported
four of HEVD's twenty-eight codes and read as complete. So such a map says it is a lower bound; what
it cannot do is name the code, so a caller gets a site to go and look at instead of a control code.
Raised on review of [#347](https://github.com/glslang/windbg-mcp/pull/347), and it is right: the
work here is recovering the values, not adding a second incompleteness report. Measured on the live
target, `volmgr` answers `code_proved: true` with **5** entries in `untracked` and none in
`unresolved` -- so the mechanism does fire on ARM64. (Those five are `movz`/`movk` compares rather
than pool loads, which is a *separate* question this item does not cover.)

**Why it was deferred, and what the estimate got wrong:** the entry expected "threading a reader
into the fact walk", `map()` having a `read` closure that `update` does not. That turned out not to
be the shape. The walk runs **twice** -- sweeps that settle each block's facts, then a pass that
records from them -- and both must agree about every value, since a literal visible only to the
recording pass would produce a case the sweeps never admitted. So `with_pool_immediates` resolves
each readable literal load into the immediate it stands for **once, before either pass**, and
nothing downstream changed: `source_value` folds an immediate, `scalar_of` resolves a compare
against one and `status_after` reads one as a refusal, each through the arm it already had.

**And the rule for which loads are safe took two goes, in opposite directions.** The entry guessed
"`.rdata`-like data at a PC-relative address with no base or index register". Review found the form
alone insufficient -- a base-less `ldr` can legally name writable module storage -- and the first
remedy over-corrected to the *executable* sections, arguing from the encoding's ±1 MB reach that a
compiler must put the pool among the functions reading it. That confuses distance with permissions:
`.rdata` sits well within a megabyte of `.text`, so legitimate pools were refused unread. The gate
is `worker::constant_ranges` -- readable image storage the driver cannot write, `IMAGE_SCN_MEM_READ`
without `IMAGE_SCN_MEM_WRITE` -- and `spans_one` requires the whole four-byte span inside one such
range, a literal beginning in a section's last bytes otherwise continuing into memory the driver
writes.

**Where it landed:** `ioctl::pool_load` and `ioctl::with_pool_immediates` (`src/ioctl.rs`),
`Layout::literal_pool` as the per-target gate, `worker::constant_ranges` and `worker::spans_one`.
`MAX_POOL_READS` bounds the cost and reports itself through `cap_hit`, so a routine past it answers
a prefix that says it is one. The x64 path is untouched -- there the same constants are immediates --
which is why every existing size test stayed green while the gap was open, and why it took a live
ARM64 measurement to see.

## 83. [windbg-mcp] `reachable_from_dispatch` does not follow the jump tables `ioctl_map` now reads — **done** (2026-09-19)

**Repo:** `windbg-mcp`.

`ioctl_map` resolves A64 switch tables as of
[#345](https://github.com/glslang/windbg-mcp/pull/345) -- 9 tables and 48 codes across `mountmgr`,
`volmgr` and `volsnap` on the live ARM64 target. `reachable_from_dispatch` does not: its walk
follows direct calls and cross-function tail jumps, and its own test says so
(`src/driver.rs`, "the jump table isn't followed"). So the two tools now disagree about the same
driver -- the map names a handler the reachability walk calls NOT REACHABLE, and the tool's advice
is to pass the handler VA by hand to scope past the switch.

Architecture-independent, and newly material rather than newly true: before #345 nothing here could
resolve an A64 table, so there was no asymmetry to notice.

**Why it was deferred, and what replaced the plan:** the entry expected `ioctl::follow_table` to be
extracted out of the `Facts` tracking it is built around. That would leave **two** resolvers having
to agree about a table's base, its bound, its entry width, its byte map and its fold -- five things
this module has each been wrong about once, and a second copy is five more chances. So
`ioctl::jump_targets` runs `map`'s own walk instead and returns what its tables select: a target the
reachability walk admits is a target `ioctl_map` publishes, and the two tools cannot disagree.

**What the review rounds added to that, and none of it was in the estimate.** The resolver answers
per **listing** rather than per site -- asked per site it ran a whole analysis each time, so *n*
indirect jumps cost *n* × every pool and table read -- and its answer carries why it might be short:
a halt it consumed (the interrupt poll behind it is `GetInterrupt`, a consuming read, so no later
poll can find it) and a bound it hit (`cap_hit` or `unsettled`). `driver::JumpTables` is that answer,
merged into the walk's `halted` and `bound_hit`/`tables_bounded` rather than polled for. And the walk
probes **once with no tables first** -- pure graph work -- so a `from` scoped past a switch, or a path
already proven, pays nothing for a resolver it does not need, which is what makes the report's own
advice to scope past the dispatch true.

**And three rules the later rounds drove out, the first two about an address the walk did not
compute itself.** A **discovered** edge is entered at its own address or not at all: a table slot, a
call target or a tail jump that is not an instruction boundary in the listing `uf` returns is
dropped, where it used to widen to the function entry and explore code no path reaches. The entry
fallback is pre-existing and belongs to the *seed* -- a `from` spelled as a symbol is a question
about where to begin -- and the table slots only made it reachable from a second source, so the fix
is wider than the report. And the resolver's module lookup **propagates** a failed enumeration
rather than defaulting to an empty one: `Ok(vec![])` is a target with no modules and degrades
correctly, while an `Err` left every switch in the walk unresolved and the report saying the graph
was fully explored. The round after that one narrowed *which* calls it fails: the enumeration is
consulted past the guards that decide there is nothing to resolve, so a table-free walk never looks
at it, and a `REACHABLE` stands whatever the resolver could not do. Both rounds are right about
different halves -- do not swallow the error, and do not charge it to a walk that never needed
one. And a table slot that goes to the switch's **default** is an edge although it is
not a case: `Map::cases` is a list of *codes*, so `follow_table` drops those slots -- rightly, a
rejected code published as an accepted one being what a reader would go and test -- and exporting
that list unchanged inherited an exclusion that was never about control flow. The bounds check's own
`ja default` is a different edge, carrying an index the switch **refused**, and a walk beginning past
it never traverses one. Added only where a slot actually went there, since with every admitted index
carrying a case nothing in range reaches the default.

**One round was declined, and the reason is in the code because the next one will ask again.** The
resolver propagates from a listing's entry while the walk may begin past a prologue, which reads as
an unsound `REACHABLE` and is not one: `ioctl::Facts::join` is a **meet**, so a jump site's facts
are the ones every entry-to-site path agrees on and a scoped start's paths are a subset of those. A
meet over more paths drops facts rather than inventing them. `a_bound_on_one_path_is_not_a_bound_at_the_join`
is the measurement -- backing the bound out of `join` publishes six fabricated edges.

**Where it landed:** `ioctl::jump_targets` and `ioctl::Tables` (`src/ioctl.rs`),
`driver::JumpTables`, `driver::walk_function`'s `Flow::Jmp` arm and `FnWalk::met_indirect`,
`driver::find_path` (which needed the same edges, its own `Flow::Call` comment recording what
happens when the recipe follows fewer than the walk), and the worker's per-listing resolver.
`docs/limitations.md` and the two prose caveats in `src/driver.rs` say the table is crossed where it
resolves and that the walk still ends at one that does not.

## 90. [windbg-mcp] The resolver reads a whole function, so scoping `from` does not narrow it — **done** (2026-09-19)

**Repo:** `windbg-mcp`.

`driver::reachability` probes with no tables first and asks `ioctl::jump_targets` only where a path
from `start_used` met an indirect jump (item 83). That guard is all-or-nothing: once **any**
indirect jump is reached, the whole listing goes to the resolver, which walks it from the function
entry. So a `from` scoped past a large dispatch switch into a handler holding a switch of its own
still paid for the dispatch's literal pool and tables -- and if those spent `MAX_POOL_READS`,
`MAX_CASES`, `MAX_TABLES` or `MAX_TABLE_ENTRIES`, `jump_targets_within` discarded **every** target
and reported `bounded`, taking the handler's own resolvable switch with it. The visible half was
fixed when the item was filed: `format_report`'s two resolver-cap arms and `docs/limitations.md`
had told the reader to scope `from` past the dispatch, which is exactly that loop.

**What landed is the entry's second option, and the reason is that the first one cannot reach the
cap most likely to fire.** Resolving only the sites the probe reached would need the reachable set
threaded into `jump_targets` and `follow_table` called selectively -- but `with_pool_immediates`
runs over the whole listing *before* the walk, which is where `MAX_POOL_READS` is spent, so site
filtering leaves that cap exactly where it was. And narrowing the fact propagation to `start_used`
is not available at all: it is the meet over every entry-to-site path that makes an entry-derived
table sound for a scoped start (`a_bound_on_one_path_is_not_a_bound_at_the_join`, from item 83's own
declined round). So `jump_targets_within` now hands over the targets a capped pass recovered, with
`bounded` beside them saying the set is short.

**The entry asked for a reading of why each of `halted`, `cap_hit` and `unsettled` discards, and
the three turn out to be three different things.** A **cap** is a bound on work already done
*correctly*: every retained case was recorded from settled facts, and each cap shortens the answer
rather than skewing it -- `MAX_CASES`, `MAX_TABLES` and `MAX_UNRESOLVED` stop a list growing,
`MAX_TABLE_ENTRIES` refuses a whole table rather than shortening one (on `entries` before it is
read, and again on `slots` once a byte map has been), and `MAX_POOL_READS` leaves later literals
unfolded, which makes the facts *weaker* so `follow_table` refuses rather than invents. It is also **deterministic**, which is the half that decides it: the retry that would
recover those edges does not exist, so discarding them cost the caller the only answer that target
will ever give. A **halt** is the caller's rather than the routine's and the same call answers
differently next time -- and the poll that saw an interrupt **consumed** it, so `reachability` walks
on: handing it more edges there means enqueueing more functions and spending more engine round trips
after somebody asked it to stop. And **`unsettled`** has nothing to hand over, which is a fact about
this module rather than a policy: a bound is only ever left on a branch's *outgoing* edge
(`ioctl.rs`'s `bounding` arm), so it reaches a jump in the facts its block was entered with, and the
`unsettled` arm clears every block's entry facts before the recording pass -- leaving `follow_table`
to meet its bounds-check requirement with nothing and refuse every table.
`an_unsettled_resolver_pass_is_bounded` already asserted the empty answer; what was missing was the
reason.

**What did *not* change, deliberately: the report's advice.** `format_report`'s two cap arms say a
handler VA as `from` escapes the resolver only "if that handler holds no switch of its own -- the
resolver reads a whole function". That is still exactly right, and for the reason it was written:
the probe guard decides whether the resolver runs *at all*, and a handler reaching no indirect jump
never resolves anything. A handler that does hold a switch still pays this routine's tables, and
`MAX_POOL_READS` can still be spent before its own literals are read, so the cap can still cost it
edges. What this change removes is the *other* way it lost them -- a cap spent anywhere in the
listing discarding everything the listing had proved.

**Not reachable on any target measured here**, which is unchanged: `MAX_POOL_READS` is far past any
real dispatch routine and `mountmgr`'s two 81-entry tables are the largest seen, so the fixture is
synthetic -- two switches in one listing, differing only in the bound their index is checked
against.

**Where it landed:** `ioctl::jump_targets_within`'s early return and its `Tables` doc comment
(`src/ioctl.rs`), with `a_resolver_cap_keeps_the_targets_it_recovered` as the test, and the third
reachability bullet of `docs/limitations.md`.

## 89. [windbg-mcp] A switch that would not resolve is the one incompleteness the report does not count — **done** (2026-09-20)

**Repo:** `windbg-mcp`.

`reachable_from_dispatch` named four ways a `NOT REACHABLE` could be short of the graph, each with
a remedy the others do not reach: `halted` (the clock or an interrupt), `bound_hit` (raise
`max_functions`/`max_depth`), `blind_stops` (bytes that would not read — get the image), and since
item 83 `tables_bounded` (the resolver's own caps, which those arguments do not reach). A fifth was
computed and thrown away. `driver::walk_function` set `FnWalk::met_indirect` where a
`Flow::Jmp(None)` had no targets and `reachability` read it **once**, to decide whether resolving
was worth the engine round trips; the final walk's copy was discarded. So a walk that ended at a
switch the resolver ran on and could not answer carried no signal at all — `blind` counts only
`Flow::Unreadable` and `Flow::Unknown` — and the report printed **"Bound hit: no — the reachable
call graph was fully explored"** over a graph missing that switch's every case.

**What landed is the entry's proposal, plus one thing it did not see.** `FnWalk::met_indirect` is
now `FnWalk::unresolved_jumps`, the **sites** rather than a flag; `Report` accumulates them into a
`HashSet<u64>`; `format_report` counts them, withholds the "fully explored" claim as `blind`
already does, and prints a `Jumps not followed` paragraph naming a remedy per case; and
`structured::Reachability::unresolved_jumps` carries the count, skipped when zero beside
`tables_bounded`. The two other silent arms the entry named — an instruction set whose operands go
unread, and a listing in no loaded module — need no code of their own: both leave the resolver
answering an empty `JumpTables`, so the walk ends at the jump and the site lands in the same count.

**What the entry did not see is the probe**, and it is the one place the count would have been
worse than the silence. `reachability` walks each function once with no tables to decide whether
resolving is worth a round trip, and a walk that reaches the target on that pass returns straight
away — so its unresolved list is *every* indirect jump on the way, none of which was ever offered
to a resolver. Merged, every `REACHABLE` found inside a dispatch routine would have reported its
own switch as one the walk could not follow: the ordinary success on the ordinary target, carrying
the one signal that says a graph has holes in it. That early return therefore contributes nothing,
and the field's meaning is "what the tables did not answer" rather than "what the walk met".

**And the rendering is outside the verdict branches, unlike `blind`'s.** The entry asked only for
the `NOT REACHABLE` sentence, that being where "fully explored" is printed. But a `REACHABLE` found
in a graph missing a switch's edges is the case #351's review had already ruled on for
`tables_bounded` — the path is real and a *shorter* one may have been omitted with the switch — so
one paragraph is emitted for both verdicts, written to say the thing that is true either way. With
the probe excluded there is no ordinary answer it fires on.

**And "switch" was the wrong word for the rendering, which only a real target said.** Driven
against the ARM64 kernel dump on the build under test (`0.18.0+ga8e42816`), ordinary `nt` routines
come back with counts that are mostly **not** switches — 11 on `nt!ObpLookupObjectName` and on
`nt!KiDispatchException` inside 24 explored functions, 3 on `nt!NtQuerySystemInformation`, 2 on
`nt!NtSetSystemInformation` — because a tail call through a register is an indirect jump too. The
paragraph says *whatever they reach: a switch's case blocks, or a callee a tail jump goes to*; the
first draft called all of them switches and would have described most of them wrongly. The
dispatch switch is the case the item was filed for and is not the only thing the count holds.

**Which made the remedies wrong until both bots said so, in the same round and independently.** A
handler VA and a module refresh reach a table that would not read; they reach nothing at all in a
destination computed at run time, so an unqualified pair promises every reader something that
cannot work for some of them -- the defect `tables_bounded` exists for, one field along. They are
given per case now. What was *not* taken is the alternative both offered, separating the two causes
in the result: `ioctl::Tables` answers per listing, and per site it has targets or nothing, so
deciding that a jump was a switch whose table would not read -- rather than one that was never a
table -- is exactly the analysis that did not answer. A field for it would invent the distinction
rather than report it, and the report says so instead.

**Counted per site, which is what the set is for.** `visited` is keyed by the *start* address, so a
routine entered at two boundaries is walked twice and the two walks overlap; summing what each
ended at reports one switch as two. `one_switch_reached_from_two_starts_is_counted_once` is that
assertion, and `a_switch_the_walk_could_not_follow_is_counted_and_costs_the_clean_sweep` pins the
other two properties of the count — two jumps in one function are two, and a jump the tables
answered is not among them, which is the mutation this fix could have been.

**Where it landed:** `driver::walk_function`'s `Flow::Jmp` arm and `FnWalk::unresolved_jumps`,
`driver::reachability`'s probe guard, early return and merge, `driver::format_report`'s new
paragraph and its `Bound hit: no` arm, `structured::Reachability::unresolved_jumps`, and the third
and fourth reachability bullets of `docs/limitations.md` with the `reachable_from_dispatch` row of
`docs/structured-results.md`.

## 85. [windbg-mcp] The ARM64 second opinion exists and has never been diffed — **done** (2026-09-20)

**Repo:** `windbg-mcp`.

`tools/ghidra_oracle/` runs Ghidra and Driver Buddy over an x64 driver and diffs their control
codes against `ioctl_map`'s. Nothing did that on **ARM64**, although a second implementation --
the Binary Ninja companion [`binja-windbg-mcp`](https://github.com/glslang/binja-windbg-mcp) -- had
already published figures for two ARM64 drivers that agreed with this server's. The agreement had
been read out of two documents by hand, and nothing failed when they diverged.

**`tools/binja_oracle/` is the lane**, in two halves that each run on the machine that can run
them. `oracle.py` replays a companion capture through `binja_windbg_mcp.analysis.ioctl_map`, takes
this server's answer over stdio -- locally on Windows, or through `ssh` from the Mac, which is what
makes it runnable from the bench this repo is edited on -- and diffs them by code and by route,
exiting non-zero when they disagree. `capture.py` makes the captures, because the second half of
this item turned out to need them.

**Three differences are reporting rather than disagreement, and each is subtracted where it can be
seen.** The **build**, compared as `timestamp`+`size`+PDB before anything else; the **case address
convention**, the companion naming *"the first source-mapped statement"* and this walk the block
the branch enters, paired inside a stated forward window rather than a fitted constant; and the
**default-rejection table slots**, which the companion publishes and this walk drops, accounted for
by `entries` minus `followed`, a count this side already gives, so no arm has to be guessed to be
the default. `--selftest` pins all three against the cases where the lane must still fail.

**The first run retired this item's own table.** It claimed the two agreed on ARM64 `mountmgr`
figure for figure. Measured 2026-09-20: the companion's capture pinned `timestamp 2826447139`,
`size 0x21000`, PDB `93E8BD6D...` and the driver the debuggee runs is `timestamp 1169727331`,
`size 0x22000`, PDB `60A98336...`, both calling themselves `10.0.26100.1` with different file
hashes. **The two halves had never been compared on the same binary**, and no RVA in one is an RVA
in the other -- which is why the identity gate is the lane's first act, and why nothing in that
table could have been checked by hand.

**So the second half of this item was making the captures**, and Binary Ninja **Personal has no
headless API**. `capture.py` starts the real GUI in a disposable `BN_USER_DIRECTORY` with a
generated plugin, the mechanism `tools/bn_followup_probe.py` already used for the CLRBHB probes.
What it cost beyond that mechanism was three things the plan did not have:

- **The NT types.** The adapter reads `_DRIVER_OBJECT`, `_IO_STACK_LOCATION` and `_UNICODE_STRING`
  out of the view, and the companion's own fixture got them from a PDB. They are declared in the
  probe instead, and every offset was checked against the live ARM64 kernel with `dt`:
  `Parameters` at 8 and `DeviceObject` at 0x28, `MajorFunction` at 0x70 in a 0x150-wide struct,
  `_IRP` 0xd0 wide with `Tail.Overlay.CurrentStackLocation` at 0xb8. All five agree with the
  layouts the companion's `mountmgr` fixture recorded from the PDB, and the probe refuses if the
  view parses them into anything else.
- **`__security_push_cookie` destroys the parameter binding.** Applying `DriverEntry`'s prototype
  is not enough on ARM64: the helper really does preserve the argument registers and is not
  declared to, so Binary Ninja models it as *returning* `x0` and `x1` and the typed parameter dies
  at the first call. Measured on `rdyboost`: the signature applies and the table fill still reads
  `*(x0 + 0x70) = SmdDispatchGeneric`. The probe types the **entry register** as well, which is
  the same claim the prototype makes, and then checks the recovered `MajorFunction[14]` against
  the live driver object's -- so a mistyped variable is a refusal rather than a published reading.
- **A driver's dispatch is not always registered near its entry.** The prototype is applied
  outward from the entry a call at a time, bounded, and the routine that takes the dispatch
  address is the last resort. `rdyboost` needed all of it.

**Measured 2026-09-20, all three against `windbg-mcp 0.18.0+g30c4af94` and the live ARM64 target:**

| fixture | identity | codes | routes | verdict |
|---|---|---|---:|---|
| ARM64 HEVD | matches | 29 = 29 | 29 of 29, every one `+0x18` | agree |
| ARM64 `mountmgr` 10.0.26100.1 | matches | 24 = 24 | 24 of 24, 48 records | agree |
| ARM64 `rdyboost` | matches | 17 agreed, **2 only the companion** | 17 of 17 | **differ** |

`mountmgr`'s 45 companion-only records are exactly the 45 table slots this side dropped
(`21-5`, `21-5`, `17-4`), landing on the two destinations no route reaches -- so at route level
too the difference is reporting.

**`rdyboost` is the fixture that separates them, and it found a defect on both sides.** The lane
pointed at two codes only the companion has, at `0xf010` and `0xef14` -- which are the two sites
`ioctl_map` reports in `untracked`, so the two implementations agree about *where* they could not
read something. Reading the target settles what is there, and it is an A64 **conditional-compare
chain**: `rdyboost+0xef10` is `cmp w8,w11` / `ccmpne w8,w12,#4` / `ccmpne w8,w10,#4` / `beq` with
`w11 = 0x0056c008` and `w10 = 0x000700a0`, and `rdyboost+0xf00c` is `cmp w8,#0` / `ccmpne w8,w10,#0`
/ `bne` with `w10 = 0x00224194`. **Neither implementation reads one**, and they fail differently:
the companion publishes the chain's *first* operand as a case -- including a meaningless
`0x00000000` -- and misses the `ccmp` operands, while this walk publishes neither and records the
site. So `ioctl_map` **was** missing at least `0x000700a0` and `0x00224194` on this driver, which
is [item 92](#92-windbg-mcp-an-a64-conditional-compare-chain-is-a-compare-chain-the-walk-does-not-read--done-2026-10-02), closed 2026-10-02.
The companion's half is a finding for its own repository and is not filed here.

**What the entry expected and did not get.** It expected the Ghidra lane to grow an ARM64 mode and
a host to be stood up for it. Neither happened: the benches are disjoint -- Ghidra needs a Windows
host with a JDK and PyGhidra, this needs a Python checkout and no disassembler at all -- so the
second lane is a second directory, and the reading discipline is shared by pointing at the x64
README rather than by sharing code. It also expected `rdyboost` to answer whether a decompiler
proves the buffer sizes item 82 was about. It does not: the companion proves **no** size on any of
the three fixtures, and this side proves none either while seeing 13 length checks on `rdyboost` --
so the sizes question is untouched by the second opinion and remains item 91's.

**Where it landed:** `tools/binja_oracle/oracle.py` (the diff and `--selftest`),
`tools/binja_oracle/bn_capture.py` and `capture.py` (the owned-GUI capture), and
`tools/binja_oracle/README.md`, which carries the bench, the three normalisations and the figures
above. The captures themselves are **not** checked in: each is a reading of the build the debuggee
is running at the time, and a stale one would be the exact failure this lane's identity gate
exists to catch.

## 92. [windbg-mcp] An A64 conditional-compare chain is a compare chain the walk does not read — **done** (2026-10-02)

**Repo:** `windbg-mcp`. Filed 2026-09-20 from item 85's ARM64 diff lane; closed by folding the chain
onto the branch that reads it.

A64 has `ccmp`, so a compiler writes `if (code == A || code == B || code == C)` as **one** branch
fed by several compares. `ioctl_map` read the instruction before the branch and filed the rest in
`untracked`, so every other code in such a chain was lost. Measured on `rdyboost` on the live ARM64
target, 2026-09-20, against `windbg-mcp 0.18.0+g30c4af94`:

```
rdyboost+0xef00  mov    w11,#0xC008 / movk w11,#0x56,lsl #0x10   ; w11 = 0x0056c008
rdyboost+0xef08  mov    w10,#0xA0   / movk w10,#7,lsl #0x10      ; w10 = 0x000700a0
rdyboost+0xef10  cmp    w8,w11
rdyboost+0xef14  ccmpne w8,w12,#4
rdyboost+0xef18  ccmpne w8,w10,#4
rdyboost+0xef1c  beq    rdyboost+0xef7c
```

Three codes, one handler, and the map named none of them: `untracked` carried `0xef18`. The second
chain was the same shape with the opposite meaning -- `rdyboost+0xf00c` is `cmp w8,#0` /
`ccmpne w8,w10,#0` / `bne`, with `w10 = 0x00224194`.

### What landed

`ioctl::chained_compare` and `absorb` (`src/ioctl.rs`). **A flag write replaces the set of live
compares; a conditional compare continues it**, and the `nzcv` immediate the encoding carries is
what decides whether it does:

- `ccmpne …,#4` forces `ZF` **set** where the link before it matched, so a match at *any* link
  reaches the `b.eq` and every readable link is a case at its own site. That is the first chain:
  the walk's existing "a case per site" rule is what publishes two of its three codes, and the
  third -- `w12`, whose value the target's registers never showed -- comes back as a reading with
  no code, which the terminator already files in `untracked`.
- `ccmpne …,#0` forces it **clear**, so an earlier match takes the `b.ne` *away* from the case and
  only this compare's own operand can be one. That is the second chain, and reading the first shape
  onto it publishes the arm the routine **rejects**: `0x00000000`, which is exactly what the Binary
  Ninja companion's map carries ([binja-windbg-mcp#14](https://github.com/glslang/binja-windbg-mcp/issues/14)).

**Measured end to end through the tool surface**, against the debugger guest's own
`rdyboost.sys` -- `10.0.26100.1`, SHA-256 `D872CFF761A83D3D508076FA76F90027EDA1C3360CD6BF3DBE3FE5637C87F4AA`,
opened as an image target, dispatch `rdyboost+0xf6a0`, 2026-10-03:

| | codes | `untracked` |
|---|---|---|
| `0.21.0+gdaa11a3d` (without this) | 17 | `rdyboost+0xf800`, `rdyboost+0xf708` |
| `0.21.0+gc02152aa` (with it) | **21** | none |

**Both builds are named and clean, and that is a re-take.** The first pair was `0.20.0+g3b8d6fee`
against a `-dirty` tree, which is a reading nobody can reproduce; and by the time this merged `main`
had moved seventeen commits, item 108's step 1 among them, which touches `ioctl_map`'s own `render`.
Re-taking the baseline *after* that rebase is what makes the four codes attributable to this change
rather than to the release -- it comes back identical, sites included.

The four gained are exactly `0x0056c008`, `0x00070000`, `0x000700a0` and `0x00224194`, and nothing
was lost. **That is not the build this item was filed against** -- its chains are at
`rdyboost+0xef00` and `+0xf00c`, this build's are at `+0xf708` and `+0xf800`, and the file hashes
differ -- which is the same trap item 85 found in the published `mountmgr` agreement, so it is
stated rather than glossed. On *this* build the link the live-target reading could not resolve is
readable, so the fold recovered **four** codes where the entry named three.

### What the entry got wrong, and what it did not see

**The remedy it proposed was a fold into the condition** -- *"reading a chain means folding several
comparisons into one branch's condition"*. That is not what it needed. The walk already carries a
**set** of live compares and already makes a case per site, so what the chain wanted was for that
set to *survive* a flag write; the `nzcv` bit decides survival, and nothing about `Condition`
changed.

**And a kept reading is good for an equality and nothing else**, which the entry did not reach at
all. The forced flags are not the flags that compare would have left: `#4` is `ZF` alone, which on
A64 leaves `C` **clear** -- borrow -- so a `b.lo` after the chain is taken where the comparison it
stands in for would not have been. `equality_survives` answers from an equality's flags, so a
chained reading carried onto an edge would be read against a state the target never reached, and a
case built there is a code the routine sent somewhere else. So `Compared::chained` marks them, the
terminator's equality arms are the only thing that reads them, and they found no table bound and
cross no edge. A chain read by any other branch -- or split across a block boundary -- reports its
site in `untracked` instead of its codes: that **costs a real code** on the `b.lo` shape, which is
the right way round and is pinned as a characterisation rather than implied.

**And the fold needs a predecessor the walk read**, which neither the entry nor the first
implementation asked for. `ccmpne …,#4` defers to the comparison before it, so where that
comparison is not one of the walk's own readings -- `cmp w2,#0` / `ccmpne w9,w10,#4` / `b.eq`, with
`w2` holding something else -- the branch is decided by a condition about another value and the
forced arm sends **every** code to the handler. `w10`'s code is not a false case there, but a list
carrying it with an empty `untracked` reads as the whole set, which is the one thing this module
must not do. So a link with no readable predecessor is dropped and its site becomes the loss: the
answer an unmodelled flag write already gives, and the answer this module gave for that shape
before a chain could be read at all. Raised as a **P1 by Codex** on
[#439](https://github.com/glslang/windbg-mcp/pull/439), which offered keeping the case beside a loss
as the alternative -- declined, because it would publish a code this walk has never published
before on the strength of reasoning about forced flags, where dropping it changes nothing but the
chain the fold was written for. One check covers the class, because `compared` is replaced at every
flag write: it is non-empty at a conditional compare only when the last thing to write the flags was
a comparison of the control code that the walk read.

**And the enumeration is what finished it, rather than three more fixes.** Two further Codex P1s on
the same PR were the same class as the predecessor one -- a forced arm read over flags the walk
cannot evaluate -- so the fold's arms were counted in one pass instead of patched one at a time. The
pair *(does the `nzcv` keep the earlier links, were they read)* plus *(was this link's own
comparison read)* has six cases, and three of them need the site marked: no predecessor (the link
cannot be folded at all, since every code reaches the branch on the forced arm); a **blind** link
mid-chain with `ZF` forced set (the links that were read are still true cases, so the site is a loss
*beside* them rather than instead of them -- `cmp w9,w11` / `ccmpne w2,w3,#4` / `b.eq` is reached by
`w11`'s code *and* by anything satisfying a comparison nothing read); and a blind link with `ZF`
forced **clear** where a predecessor had established the code, which is the arm neither finding
named and only the count found. The other three need nothing: both links read, a readable link that
forces no equality, and a blind link with no predecessor -- where there is nothing about the control
code anywhere and nothing to say.

**A dropped chain is also recorded at the branch that consumes it**, not handed to the edges below.
Leaving the site in `lost` made the answer depend on whether an equality branch happened to come
later: `cmp code,A` / `ccmpne code,B,#4` / `b.lo` with both successors returning reported no case and
no warning at all. A conditional branch that reads those flags commits the site itself now;
`cbz`/`cbnz` deliberately do not, reading a register rather than the flags, so a chain they end is
still live for a branch further on.

**And a class fix closes the class only if it can express the whole rule**, which took one more
round to get right. The commit above recorded the dropped chain by searching the *readings* that
survived it -- and the forced-clear blind arm it had just added clears those readings and leaves the
chain represented by its **loss** alone, so `cmp code,A` / `ccmpne w2,w3,#0` / `b.lo` was still
reported as a complete map with an accepted code in it. Codex filed that against its own fix. What
the check could not express was a chain with no reading left, so the chain is now a fact the block
keeps in its own right -- the site of the conditional compare whose flags are live, answered by
`absorb`, cleared by an ordinary flag write and by a call exactly as the readings are -- and the
terminator asks *that* and takes either the reading or the loss. **The boundary it must not cross is
pinned too**: an ordinary flag write after a chain ends it, and the loss it leaves is carried to the
successor edges and committed only by an equality, as this walk has always done on every target. A
`b.lo` over a code lost to an `and` gains no `untracked` entry it did not have before.

**And the links a forced-clear arm discards are a fact about the case it publishes**, which is the
fourth round and the first finding that was not a P1. `ZF` forced clear means an earlier match
leaves the case, so the code this link compares against reaches it only where none of them matched:
a predecessor that matched the **same** code makes the case unreachable -- `cmp code,A` /
`ccmpne code,A,#0` / `b.ne` rejects every value -- and one whose code could not be read leaves it
unknown whether that is so. The first is dead code rather than anything a compiler emits and is
dropped; the second is `rdyboost`'s own shape with its first constant unread, where the code is
published and the unread site recorded beside it, because this module publishes a case with its
caveat (`proved`, `accepted`) rather than withholding one. **That second half is a marker the fold
had dropped**: before it, the link's own `note_loss` left one, a conditional compare reading a
register that carries the code. A predecessor matching a *different* code needs neither, which is
what the shape is for.

**What the four rounds cost, as a reading rather than a rule.** The answer never moved: `rdyboost`
reported 21 codes with nothing `untracked` on the first commit and reports the same 21 after the
third round, re-measured rather than recalled. The remedies added **820** lines on the **800**
submitted -- counted from the diff rather than by adding the rounds up, which gave a different
number -- and that figure is to be read beside the first one rather than on its own. Six findings
over five rounds, five of them taken: four were silently incomplete maps and the fifth an
unreachable case, which are the two failures this module is arranged against, so the surface bought
the thing the module exists for rather than more of itself. **The sixth is declined on the fact**,
which is the only one of these that was not real: it read the forced-clear arm's replacement of
`lost` as dropping a marker, and the shape it named -- an unread constant compared against the code
-- is marked by that arm's own reading rather than by `lost`. Where its mechanism does bite, a link
blind to the code entirely, the forced-clear link **resolves** what the blind one left open: only
the last link's code reaches the fall-through, so carrying the loss on would mark a complete answer
as a lower bound. Both are tests rather than an argument
(`a_chain_with_an_unread_middle_link_marks_the_case_after_it`,
`a_forced_clear_link_resolves_a_blind_link_before_it`), the second carrying the flag table it rests
on.

**It was then asked a second time, from the other side**, arguing that the case is conditional on the
unread comparison -- which it is. What settles that is the **control**: the same source written
without a conditional compare (`cmp w2,w3` / `b.ne skip` / `cmp code,B` / `b.eq`) publishes the code
and marks nothing, because the guard tests a value that is not the control code and `untracked` is
for a test on the code this walk could not attribute. Marking the `ccmp` form would make the map's
completeness depend on the compiler's instruction selection rather than on the driver, and would
make an `untracked` entry of every input-dependent guard in every driver that happens to be folded.
`a_guard_on_something_else_is_not_a_loss_however_it_is_written` is that control.

**And then a seventh finding on a different line, which was real: a join unions the readings.**
`Facts::join` unions `pending` deliberately -- a comparison is a claim about the path that made it
-- so a non-empty set at a conditional compare proves that **one** incoming path compared the
control code and proves nothing about the rest. With `cmp code,A` on one edge and `cmp w2,#0` on
another, a `ZF`-forcing link admits every code on the second. So the fold asks for flags **this
block wrote**, which is the conservative reading of the single-path rule it already had, and the
fixture was written to fail first and then fixed. What it costs is a chain whose first link is in
another block: it answers with its site instead of its codes, which is what every other cross-block
chain shape answers here, and `rdyboost`'s own chains are contiguous -- re-measured after the change
at 21 codes with nothing `untracked`. **And the same union sharpened the unreachable-case rule.** Finding this link's code on *one*
predecessor does not make the case unreachable on *every* path: with `cmp code,A` on one edge and
`cmp code,B` on another, a link comparing against `A` is dead along the first and **accepted** along
the second, where `B` is forced out and `A` is what the comparison matches. So the case goes only
when every incoming reading named a code and every one of them is this link's -- a sharpening rather
than the per-path provenance the finding offered first, which would be a second kind of fact at
every join for a shape no driver here has. Its sibling guard, *"and there were readings at all"*,
was found **unpinned** by the mutation matrix: vacuous truth over an empty set would have dropped
the case of a forced-clear link with no predecessor, which is a real accepted code, and no test
failed when it was backed out. It has one now.

**Nineteen tests in all, sixteen of them mutation-verified against the mutation they are for.** The
other three are controls, and they are there so a later round does not *fix* something already
right: the non-`ccmp` form of a folded guard, an ordinary flag write after a chain, and the blind
link a forced-clear one resolves.

**And the last thing to land is the one I declined and should not have.** A link that reads the code
and is not modelled leaves a loss, and the forced-clear arm replaced it -- so `cmp code,A` /
`ccmnne code,C,#4` / `ccmpne code,B,#0` / `b.eq` published `B` without saying `B` is rejected where
`B == -C`. That was declined as a fifth distinction for a shape needing a negated compare against a
control code, and pinned as a known limit. **The round after it reached the same gap through
`tst`** -- `tst code,#1` / `ccmpne code,B,#0` / `b.eq` admits only an **odd** code, so an even `B`
is an invented case -- and a bit test before a conditional compare is ordinary codegen. The decline
was wrong on **price**, not on fact, and what closed both is the thing three findings on that line
were really about: *a loss about the control code* and *a forced arm admitting every code* were one
slot, and a `#0` link treats them oppositely -- it resolves the second, as rounds five and six
measured, and resolves nothing about the first. Separated, each is pinned by a mutation in its own
direction: dropping the code-dependent loss fails the `ccmn` and `tst` tests, and not resolving the
forced arm fails the blind-link test the declines rest on.

**That separation then had to be finished, which is the lesson worth keeping.** It was applied to the
arm the finding named and to no other, so a forced-set link with no predecessor still *assigned*
`lost` -- dropping a `tst`'s site, after which the forced-clear arm had nothing to preserve -- and a
**readable** link still overwrote `forced` with `None`, erasing the site a blind link before it had
left. Both published an invented case as definitive, and both came back as P1s in the next round.
The remedy was to enumerate all **four** sites that write either slot and say what each owes: an
ordinary flag write replaces `lost` and clears `forced`, because the flags it replaces are what both
were about; a forced-set link keeps `lost` and keeps a forced arm; a forced-clear link keeps `lost`
and resolves `forced`. When two conflated things are separated, every site that writes either of
them is in scope -- not the one where the defect was seen.

**And `own_flags` belongs to one of those arms and not the other**, which is CodeRabbit's single
finding here and a good one. It is in the predecessor test to stop a forced-**set** arm folding over
a join whose other paths it cannot speak for; a forced-clear arm admits no code by itself, so
requiring it for that arm's blind-link marker bought nothing and cost the marker -- a chain whose
readable link is an edge away reported no case *and* no site, where the comment beside `own_flags`
says it answers with its site. The marker now asks only whether there were readings.

Also filed there and declined: a duplicate-constant forced-set chain emits two cases for one code,
which is `docs/structured-results.md`'s documented **case per site** rather than a defect.

The pair of declines above is a third pass over one line, with the answer unmoved for five rounds, is the
reading the review-round skill says to record rather than escalate. **Two** of the five were against a previous round's own fix, which
is what the class fixes cost: each closed its class and the next round read what the closure could
not express. The rule going on is that a defect in what is here is worth fixing and a request for new
machinery is not.

**The first draft of that substitution keyed on the terminator's condition alone**, and a `ccmp`
carries a condition of its own -- so a block *ending* in one looked like a block whose branch had
just read an equality, and the chain left the answer with no case and no site. The block-boundary
test caught it before review did; the guard asks the flow as well now.

`ccmn`, and a `ccmp` conditioned on `eq`, are deliberately not read. The first compares against a
negation no control code is written as; the second chains a *conjunction*, where two distinct codes
cannot both hold and the earlier reading is a rejection whichever way the branch goes. Both keep
what the module did before -- the flag write loses the compare, `note_loss` records the site -- and
the propagation still applies, so a chain whose middle link is a `ccmn` leaves the links around it
readable.

### What is still open

The companion's half ([binja-windbg-mcp#14](https://github.com/glslang/binja-windbg-mcp/issues/14)),
which is a finding for its own repository. It publishes the chain's first operand and misses the
`ccmp` operands, so item 85's lane now disagrees about `rdyboost` **in the other direction** --
and the lane has **not** been re-run against this fix, which would need a fresh companion capture
of the build the debuggee is running (`tools/binja_oracle/README.md`).

### Where it was

`ioctl::compare` and the `Condition` it derives (`src/ioctl.rs`). Five tests, each
mutation-verified against the rule it is for:
`an_arm64_conditional_compare_chain_recovers_the_codes_it_accepts`,
`a_conditional_compare_that_forces_no_equality_publishes_only_its_own_code`,
`a_chained_reading_founds_no_table_bound`,
`a_chained_reading_is_not_split_across_a_branch_that_reads_the_flags` and
`a_conditional_compare_chain_does_not_cross_a_block_boundary`.

## 93. [windbg-mcp + dbgscope] Multiprocessor hypervisor stops after a temporary breakpoint and detach — **done** (2026-09-21)

Filed on 2026-09-20 after a `run_to_address` hit on the four-processor hypervisor lab was followed
by further processor stops, a detach this server reported as clean, and a guest black at the
console -- twice, each released by a separately authorised native-KD connection, the second only
on a second attempt. Tracked in
[#355](https://github.com/glslang/windbg-mcp/issues/355); the
[investigation record](./docs/hypervisor-demonstration-20260920.md) holds that day's packet traces,
recoveries and evidence hashes, and
[`docs/hypervisor-debugging.md`](./docs/hypervisor-debugging.md) the four-processor section this
entry summarises.

**The mechanism, and the entry's own premise was the thing that was wrong.** The item read the
stops as *per-processor* behaviour of a hypervisor that might resume differently on four
processors, and weighed "a fixed number of continues" and "explicit per-processor resumes" as
possible remedies. Neither is what it is. The breakpoint site is in code **every processor runs**,
so more than one of them reaches the patched instruction before the debugger removes it: measured
2026-09-21 on the rebuilt four-processor guest, a `run_to_address` that returned `verdict: hit`
with an **empty** breakpoint inventory left exactly **three** further stops behind it -- processors
2, 3 and 1 where the hit was reported on 0, each a first-chance `0x80000003` at the breakpoint's
own address, each on that processor's own stack (the four are 2 MiB apart), delivered one per
resume in 1-3 ms, after which the target ran free. Nothing about resuming differs; a stop is owed
per *other* processor, and `qd` has one `DbgKdContinue` to spend. The first queued stop takes it
and the target stops again with no debugger attached.

**It is a race, which is why it took a rebuilt lab to see at all.** 2 of 4 hit-then-detach runs
froze; the other two were clean with the same three stops owing. One processor owes nothing, which
is why every one-vCPU run of the same sequence -- including the 2026-09-20 demonstration that was
offered as a comparison -- was clean, and why "the topology is the cause" stayed unestablished for
a day with the evidence already in hand.

**What landed.** [dbgscope#175](https://github.com/glslang/dbgscope/pull/175), pinned here at
`192e3486`. `spend_pending_break_ins` no longer asks how the session was opened: these stops owe
nothing to the attach, and the `kd_initial_break_attach` gate left the drain unrun on exactly the
`experimental_break_on_connect` path a *running* hypervisor has to be attached with -- the flag had
no other reader and went with the gate. Its attempt count now comes from `GetNumberProcessors` plus
the two free runs rather than a fixed five, which was three stops plus two free runs and so fitted
four processors by coincidence; `DRAIN_BUDGET` bounds the wall clock at four seconds where the
count no longer does. On this side: `examples/hypervisor_detach_regression.ps1`'s one-vCPU refusal
became `-AllowMultiprocessor` and names the recovery route, and
`.claude/skills/live-hypervisor/SKILL.md` was rewritten to the shape the other skills have, with
the stop-per-processor rule as one of its two breakpoint hazards.

**The numbers.** 10 of 10 four-processor hit-then-detach cycles clean against a local build of the
fix, with the backed-out control interleaved between the two batches of five on the same guest and
the same boot (2 of 4 froze), then **10 of 10** against the merged pin `192e3486` — the last five
from a clean tree, answering as `0.19.0+g1ac1abc0`, which is the identity to quote, the earlier
batches having run against trees whose stamp was not read. Every cycle carries an independent WinRM
boot-identity and advancing-uptime check; the guest never rebooted across any of it.

**And recovery turned out to be cheaper than the item assumed.** It recorded a separately
authorised native-KD connection as the remedy. A plain `attach_kernel` -- no
`experimental_break_on_connect` -- finds the target stopped at the breakpoint's own address, and
`end_session`'s drain spends what is owed: done twice, same boot, no reset. That is only true
because something is still executing to answer a debugger, which is what separates this freeze from
the hypercall-page freeze the skill records, where both transports go at once and a reset is the
only route.

**What it does not say.** Four processors is the largest lab measured, so the one-resume-per-
processor rule is what sizes the drain beyond it rather than a second measurement. The mechanism
was read off delivery order and per-processor stack pointers; nothing instrumented the KD stub to
show where the queued exceptions are held. One guest, one engine build, one transport.
## 95. [windbg-mcp] A connection profile carries a name and a string, and nothing about the target — **done** (2026-09-21)

**What it was filed for.** `profiles.json` mapped a name to a connection string, and
`WINDBG_MCP_PROFILE_<NAME>` did the same through the environment. Neither form could say **what**
an endpoint reaches: that this one is a hypervisor rather than an NT kernel, or that two of them
are two endpoints of the *same* guest. That second fact is what debugging a hypervisor alongside
its root partition is built on -- the two sessions interact only through the guest underneath them,
so a pair pointing at different guests is two sessions that never interact, which reads as a bug
for a long time. It lived only in the operator's head, and reading it off the *names* is worse than
not knowing, the wiring being machine-specific and deliberately untracked.

**What landed.** A profile's value may be an object -- `{ "connection": …, "role": …, "guest": …,
"note": … }` -- wherever the string was accepted, which includes the environment: a connection
string never starts with `{`, so the two forms cannot be confused and every variable and file that
predates this keeps its meaning. `role` is `windows`/`nt` or `hypervisor`/`hv`, `guest` is a
name-shaped label shared by every endpoint of one machine, `note` is free text to 200 characters.
They reach the listing `attach_kernel {}` answers with (`ctf-vm; lab-hv (hypervisor, guest "lab");
lab-nt (windows, guest "lab", "root partition")`), the session's own label, and -- as values -- a
`profile` object on the open's result and on every `session_status` row, beside the `kernel_target`
the attach derived for itself.

**The entry's own objection dissolved, and that is the finding.** It warned that *"a role the
server does not verify is a label that can disagree with the target it names, which is the failure
mode this item is about reproduced one level up"*, and proposed deciding between a free-text note
and a typed role on those grounds. The premise was wrong: `worker::kernel_target` already derives
`nt` against `hv` from the engine's primary module on every open, so the role is the one claim here
that **is** checkable. `server::role_disagreement` holds the two together and reports a mismatch in
that profile's own record, in both halves of the result. So the choice was not note-or-role but
both, with the line between them stated: `role` is checked, `guest` and `note` are the operator's
word and nothing can check them -- no debugger question asks two endpoints whether they are the
same machine.

Two things about that check are deliberate and were not obvious. **Absent is not disagreement**: a
freshly attached kernel can have nothing but `nt` in the inventory yet, and reporting one then
would turn *"this server could not tell"* into *"your configuration is wrong"* -- this item's own
failure mode, aimed at the operator instead of the target. And it is **said, never refused**: by
the time there is anything to compare the session is open and the target is whatever it is, so
closing it would cost the attach without fixing the file. The comparison lives in the supervisor
because that is the only side holding both halves -- the worker derives `kernel_target` and has
never heard of a profile, and the profile is resolved before a worker exists.

**What building it changed underneath.** A value of the wrong type used to fail the **whole** file,
so one typo cost every other profile -- and the entry most likely to be malformed is the one being
edited, which landed hardest exactly mid-change. Refusal is now per entry, and per *field* below
that: a `role` that is not one of the four spellings, a `guest` that is not a name, a `note` with a
control character in it, or a member this server does not know each cost that field alone and are
reported in the configuration notes, while the target still opens. The opposite would mean a typo
in a description costs the machine it describes.

**`note` is scrubbed at render rather than at parse**, which is the one ordering that works: it is
the field a pasted connection string would land in, and `KNOWN_SECRETS` is complete only once every
profile on the host has been admitted, so masking by value -- the half of `scrub` that is a
guarantee rather than a net -- needs the later moment. `Entry`, the pre-`Connection` shape holding
the raw string, is deliberately **not** `Debug`; tests destructure it.

**What review found, and it was this feature's own failure mode produced by the server.** Codex,
on [#367](https://github.com/glslang/windbg-mcp/pull/367): two spellings of one name that reach the
**same** target were treated as agreeing however differently they *described* it, so `lab-hv` and
`lab_hv` declaring different guests kept whichever was read first and discarded the other in
silence -- and the order is not arbitrary, the file becoming a `BTreeMap` where `-` sorts before
`_`. A caller would then have been shown a pairing nothing vouches for, which is the one outcome
`guest` exists to prevent. The field they disagree about is now dropped rather than settled, with a
note naming it; the profile stays dialable, because which *target* was meant was never in doubt,
and refusing the attach would cost a machine over a description. One spelling saying less than the
other is not a disagreement -- the union contradicts nothing, so it is taken. The test was
mutation-verified: backing the reconciliation out fails it at the `guest` assertion.

**Then the same fold produced a second finding, and that is the part worth keeping.** The first fix
merged the spellings incrementally over `Option` fields, and Codex came back with `lab`, `other`,
`lab`: the second spelling emptied `guest` and the third **refilled** it, so the asserted pairing
turned on the order the file was read in while the configuration still disagreed. The cause was
structural rather than a missed case -- `Option` cannot tell *never declared* from *dropped because
contradicted*, so every fold over it has to remember the difference somewhere else, which is the
second place to remember that this module's own rules exist to avoid (`is_secret_name`,
`Connection::new`). Patching the fold would have been the third round. What went in instead was a
type: `Claim<T>` of `Unset`/`Agreed`/`Conflicted`, where `Conflicted` is **absorbing**, so
`Claim::absorb` is commutative and associative and there is no transition that brings a
contradicted field back. The test asserts all three orderings settle alike, and that the note is
said once rather than once per later spelling.

**And the rule this item rests on was half-built until the third finding.** "A malformed field
costs that field and not the profile" only holds if the loss is *said* -- and the configuration
notes are rendered by `how_to_configure`, which runs on the refusal paths. A profile that
**resolved** reported nothing at all: an operator's `"role": "windwos"` was simply absent, the
attach looked entirely ordinary, and the role check silently did not run. So a profile keeps its
own refused fields and they travel as `ProfileFacts::ignored`, on the open and on every
`session_status` row. The documentation had already claimed this behaviour before it existed, which
is the more useful half of the finding: the prose described the design rather than the code.

**A third round, and the P1 in it came in through the field added to carry a label.** `guest` is
validated by `is_profile_name`, and that was taken as making it safe to render. It stops the two
things the charset was written for -- a connection string cannot pass, and nothing can forge a line
in a report -- and it does not stop a bare KDNET key, because a key is dotted decimal and
`1.2.3.4` is digits and dots. So a key pasted into `guest` was rendered verbatim into the listing
`attach_kernel {}` answers with, into every session label and into structured output: the exact
disclosure this module exists to prevent, arriving through the least likely field. It is scrubbed
at every render now, like the note beside it, and masking by **value** means a legitimate guest
costs nothing -- a profile named after the target's IP address stays readable.

The same round also caught `ignored` reaching `structuredContent` **only**, so a text-only client
still saw an ordinary attach: `.claude/rules/tool-surface.md`'s rule about annotating both halves,
broken in the commit whose own comments cite it. One renderer now feeds the open's report and
`session_status`'s text.

**A fourth round found the same hole by a second route, and the check outliving its own result.**
A complaint *quotes* the member it is about, and `a_member` quotes one that is name-shaped -- so the
text written to help an operator find their typo was itself the disclosure, in the notes, in
`ignored`, and thus in the listing, the attach result and `session_status`. Every refusal's text is
scrubbed at render now, not just the two fields. And `role_disagreement`'s answer lived only in the
*open's* result: the registered session kept the declared role, so a `session_status` on a later
turn -- or from another client -- went on advertising a role the target had already contradicted,
which is this item's own failure mode surviving the check added to catch it. The contradicted claim
is **withdrawn** from what the session reports (`kdconn::contradicted`), which reuses `ignored`
rather than adding a third state for a claim nobody should read.

**A fifth round found the withdrawal incomplete and the scrub still reachable around.** The
withdrawal removed `role` from the typed facts and left it in the session's **label**, which is
built once at the open and never changes -- so `session_status` and `OpenedSession::target` went on
advertising the rejected role, which is the guarantee the previous round had just written down. The
answer was to stop keeping two copies: the label is back to naming the profile and its redacted
connection, and both halves of a result render the claims from the typed facts through
`server::profile_lines`. And secret registration was coupled to **admission**, so an entry the
environment shadows -- or one whose name or connection is refused -- returned from `admit` before
reaching `Connection::new` and never had its key remembered, while its complaints, which quote the
operator's own text, had already been retained. A connection is remembered when it is **read** now,
in `Entry::of`, whatever later becomes of the entry; that is the correct rule on its own terms,
since being handed a secret in an entry that was then discarded is still being handed one.

**A sixth round found the warning said twice, which is what three homes for one fact buys.** The
disagreement was appended to the report, put in `summary.limitation`, *and* — once the withdrawal
landed — carried in `ignored`, which the text renders: so a mismatched attach returned the same
multi-sentence paragraph twice. Both of the older two went. `limitation` is the wrong field for it
anyway, and that was easier to see with one home than three: it is what a session **cannot do** —
a 32-bit target with no SOS, a hypervisor where NT inspection does not apply — and a mislabelled
profile limits nothing, since the session can do whatever its real target allows. Mixing the two
was worst in exactly the case this check exists for, where the worker's own hypervisor limitation
already occupies that field.

**Seven rounds, six of them on mechanisms the previous round had just added.** Every round that
ended a strand changed a *representation* rather than a behaviour: `Option` to an absorbing
`Claim`, per-field scrubbing to scrubbing at the render boundary, secret registration moved from
admission to the read, and two renderings of a claim collapsed to one. Every round that patched a
case opened the next one. That is `prefer-simplification-over-gap-fixing` measured on a single
feature, and it is the most reusable thing this item produced. The pattern is the
one `prefer-simplification-over-gap-fixing` describes, and the round that broke it was the one that
changed a *type* rather than the fold: `Option` to an absorbing `Claim`.

**What it cost.** Re-derived after review added `ignored` below, rather than left at the figure
first measured. `modelVisible` did not move at all -- 94,879 B before and after -- because the
claims travel in `outputSchema`, which
[`docs/token-budget.md`](./docs/token-budget.md) measured as never reaching the model. Seven tools'
output schemas grew: +352 B on each of the six openers and +417 B on `session_status`, +2,529 B of
wire in total, which is why `tests/golden/tool_budget.json` moved and
`every_documented_surface_figure_matches_the_served_surface` did not. Measured on the ARM64 bench
2026-09-21 against a worktree at `1c749a9`: 1,020 unit tests and 123 `mcp_smoke` with
`WINDBG_MCP_SMOKE_DUMP=1`, 0 failed.

**What it did not do.** `guest` is unverified and will stay so. Nothing was added to the
`attach_kernel` *description* -- the surface is where bytes are expensive, and the refusal text
already routes a caller there -- though the "how do I configure one" advice in that refusal now
names the object form, which is the moment an agent decides what to ask the user for.

**Where it landed:** `src/kdconn.rs` (`Details`, `Entry`, `entry_of`/`configured`, the per-field
refusals and the listing), `src/structured.rs` (`ProfileFacts`, `KernelTarget::label`, the field on
`OpenedSession` and `SessionInfo`), `src/engine.rs` (the facts held on the session),
`src/server.rs` (`opened_as` and `role_disagreement`), and
[`docs/kernel-profiles.md`](./docs/kernel-profiles.md), with the agent-facing half in
`skills/windbg-debugging/`.

**Exercised end to end on the hypervisor lab, 2026-09-22**, against `0.19.0+g1a7f504e` with the
bench's own `lab-nt`/`lab-hypervisor` pair described for the first time. Six of the claims above
were measured rather than read: the listing names the pair
(`ctf-vm; lab-hypervisor (hypervisor, guest "lab"); lab-nt (windows, guest "lab", "root
partition")`, the undescribed profile rendering bare); an open carries the `profile` object and the
`profile says:` line while the label keeps only the name and the redacted connection; a
`session_status` row carries both; a **wrong** `role` is withdrawn -- gone from the facts, its
reason in `ignored`, in the report, the structured half *and* the later status row, with
`kernel_target` untouched and the session still open; two spellings disagreeing about `guest` drop
that field and keep the agreed `role` and the one-sided `note`; and a malformed entry costs itself
alone -- a numeric value skipped the profile, `role: "banana"` and a 201-character note each cost
their field with the profile still listed and dialable. The object form through
`WINDBG_MCP_PROFILE_<NAME>` parses and renders the same. **The one thing that run added** is in
`docs/kernel-profiles.md` under *An older server reading a described file*: the compatibility runs
one way, and a server between **v0.6.0** (where profiles arrived) and **v0.19.0** refuses a
described file **whole**, plain-string entries included. Older than that it does not read the file
at all -- the plugin snapshot on this bench answers `attach_kernel {}` with *missing field
`connection`* -- so that range is the whole exposure, and it closes at the next release.

## 79. [dbgscope] A heap outside the PEB's `ProcessHeaps` is invisible to the heap tools — **done** (2026-09-22, dbgscope#176)

**Repo:** `dbgscope` ([#176](https://github.com/glslang/dbgscope/pull/176)) and, through it,
`windbg-mcp` ([#373](https://github.com/glslang/windbg-mcp/pull/373)). Surfaced by `windbg-mcp`'s heap tools.

As filed:


`walk_user_segment_heaps` enumerates roots from `_PEB.NumberOfHeaps` / `ProcessHeaps`, and on
Windows 26200 that array does not list every heap the debugger can see. Measured on `RuntimeBroker`
(2026-09-15): `NumberOfHeaps` is **1**, `ProcessHeaps[0]` is the segment heap at `0x19a88000000`,
and `!heap -s` reports **four** segment heaps at `0x19a88000000`, `…400000`, `…600000` and
`…800000`. The walk of the listed root is healthy — 8,878 chunks, 3,698 allocated — so this is a
*root discovery* gap rather than a decode one.

**It is not a bad read of the PEB**, which was the first thing checked: `cmd.exe` stopped at its
initial breakpoint reports `NumberOfHeaps` 1 and genuinely has one heap at that point, so the
field and its offset are right.

**How it was found.** Running `dbgscope`'s own `examples/user_heap_smoke` after item 78 (2026-09-15).
It now gets past the layout refusal and fails one step later: its child calls
`HeapCreate(HEAP_CREATE_SEGMENT_HEAP)`, prints the handle, and the walker lists **one** root — the
process default heap, `kind: Nt` — with the created heap absent from `ProcessHeaps` entirely. So the
example cannot reach the Segment Heap it exists to verify, live or over its dump, and the crate's
one end-to-end user-mode heap check is standing down on every current build.
`_NO_DEBUG_HEAP=1` changes nothing, so the debugger's debug heap is not the cause.

- **Why deferred:** the severity is not yet known and the measurement that settles it is the work.
  If the three unlisted heaps are **heap-manager-internal**, `ProcessHeaps` is the correct answer
  for application heaps and what needs fixing is the example's premise plus a sentence in the tool
  descriptions. If any of them is **app-visible** — and a `HeapCreate` return value missing from
  `ProcessHeaps` suggests at least one is — then `heap_list` under-reports on current Windows while
  saying it listed every root, which is the failure mode this repo has already been bitten by once
  (a walk that rejected every segment reporting an empty pool rather than an error).
- **It does not block a release, and the reasoning is worth keeping.** PEB-based enumeration is
  what every release has shipped, and the tools report `coverage` and name the heaps they walked
  rather than claiming completeness. What changed in item 78 is only that the layout now resolves,
  so the tools return a partial answer where they previously returned an error — which is why this
  became visible then rather than being introduced then.
- **What would close it:** establish where `!heap -s` gets its segment-heap table — `ntdll`'s own
  heap-manager globals rather than the PEB — and whether an entry there is app-visible. Then either
  enumerate from that source beside the PEB, or state the boundary in `heap_list`'s description and
  fix `user_heap_smoke` to verify a heap it can actually reach. Either way the answer has to say
  *how many roots it could not see*, not merely how many it walked.

**Where it picks up.** `walk_user_segment_heaps` in `dbgscope`'s `src/pool/snapshot.rs` and the PEB
read feeding it, `examples/user_heap_smoke.rs`, and `heap_list`'s description in
`windbg-mcp`'s `src/server.rs`.


**What it measured (2026-09-22).** The deferral hung on one question: are the unlisted heaps
heap-manager-internal, or app-visible? They are app-visible, and that follows from the code rather
than from a sample. `ntdll!RtlpProcessHeapsInsert` was disassembled on ARM64 26100.1 (live) and on
x64 26200 (from `docs/samples/stale-throw-abort.dmp`). On both builds it does the same things:

- allocates a 0x30-byte entry from the process heap and stores the heap at +0x10;
- links the entry onto a `LIST_ENTRY` in `ntdll`'s data;
- stores the entry's address in the heap's `UserContext` (`_SEGMENT_HEAP` +0x38, `_HEAP` +0x188
  on ARM64);
- writes `NumberOfHeaps = 1; ProcessHeaps[0] = heap`, but **only while the process has no heap
  yet**.

`RtlGetProcessHeaps` calls `RtlpEnumProcessHeaps`, and that walks the list. So on these builds the
PEB array holds one entry and never grows, while `GetProcessHeaps` returns heaps it never names.

The live check used `user_heap_smoke`'s own child on the debugger guest. `NumberOfHeaps` was 1, and
the list held three heaps: the process heap, an NT heap, and the child's `HeapCreate` return value.
The repo's two x64 26200 user dumps carry `ntdll`'s data but no heap pages. In both, the list head
links two different entries while `NumberOfHeaps` is 1.

**What the entry got wrong.**

- It sent the search to "`ntdll`'s own heap-manager globals". The table is not there, and it is not
  a Segment Heap table. It is a process heap list that holds heaps of **both** kinds (the child's
  NT heap is on it). Its head is `ntdll!RtlpProcessHeaps` on 26200, a symbol the public PDB for ARM64
  26100.1 does not carry. What made the list reachable on both builds is the heap's end of the link,
  `UserContext`, which both PDBs type.
- It framed the close as finding where `!heap -s` gets its table. `!heap` was never measured. The
  service's engine bundle ships no `exts.dll`, and the SDK's would not load into it (`0n126`). What
  settled app-visibility is `GetProcessHeaps`'s own code. That is the stronger answer anyway: it
  defines what an application's heaps are, and `!heap` is one more reader of them.
- It named `walk_user_segment_heaps` as the enumerator. Roots were enumerated by `enumerate_roots`
  in `src/heap.rs`. `walk_user_segment_heaps` only walks the roots it is handed.
- It said the answer has to say *how many* roots it could not see. That number does not exist: a
  list has no count until it has been walked, so where the walk breaks, how many entries lie beyond
  the break is unknowable. What the answer carries instead is whether enumeration saw every root. A
  broken list makes the walk `partial`, with a diagnostic naming the entry. `scope_for` also stops
  refusing a heap selector as unsupported when it may simply have been unseen.

**What landed** ([dbgscope#176](https://github.com/glslang/dbgscope/pull/176)). Roots come from that
list, in its order. It is reached through the process heap's typed `UserContext` rather than the
head's symbol, since only one build has the symbol. The entry has no public type, so +0x10 is a
measured offset. What makes reading it safe is the check made on every entry:

- the entry's heap names the entry back;
- the entry's `Blink` is the entry before it, and the ring closes on the first entry;
- exactly one entry, the head, lies inside `ntdll`.

Anything that fails a check ends the walk as unseen. A build whose process heap names no entry
keeps no list, and gets the PEB answer exactly as before. `UserContext` is resolved for the
**user** schema only. The kernel's `_SEGMENT_HEAP` carries it too, and reading it there would move
every pool fingerprint, including the two item 78 pinned. Here, `heap_list`'s description and text
header stop saying "PEB", and the shipped skill tells an agent why `NumberOfHeaps` 1 beside three
listed roots is not a disagreement.

**What it did not do.** The x64 gate stays. The live ARM64 check ran with the gate relaxed in an
uncommitted copy. The root listing was right, and the walk that followed was not: a 0x4000
allocation decoded as VS where x64 decodes it as Segment, and VS free-tree pointers came back as
unreadable addresses. That is ARM64 backend decoding, which is what the gate is for. The entry's
word at +0x18 has a bit 0 that `RtlpEnumProcessHeaps` uses to hide a heap from `GetProcessHeaps`;
such heaps are listed like any other, and none was seen. No build that predates the list is
reachable from this bench, so the fallback is covered by a unit test on the pre-change path and
not by a measurement.

**Verified.** In dbgscope, 46 heap and layout tests passed, 9 of them new. The enumeration tests
run against a byte-level double laid out with the measured process's own addresses. The full lib
suite on the guest passed 414 of 414. Seven mutations were run: skipping the list, dropping the
back-reference, `Blink` or single-head check, dropping the unseen diagnostic from the walk, letting
`saw_every_root` ignore it, and letting the kernel schema read the user field. Each failed the test
written for it. Live on ARM64 with the gate relaxed, `heap::list` returned the process heap, the NT
heap and the created heap `0x149d8400000`, against `NumberOfHeaps` 1.

## 96. [dbgscope + windbg-mcp] The pool walker on ARM64, and an LFH reading that is not `nt`'s — **done** (2026-09-23, dbgscope#179)

**Repo:** `dbgscope`, surfaced by `windbg-mcp`'s heap tools
([dbgscope#177](https://github.com/glslang/dbgscope/pull/177)).

`pool_*` still refuses every ARM64 kernel (`pool::query` accepts `IMAGE_FILE_MACHINE_AMD64` and
nothing else), and they will need to work there — the maintainer's call, 2026-09-23, when the heap
tools were lifted and this was split off.

**Both readings this was filed against are corrected and confirmed against a live pool; the gate
is what is left.** The corrections are on dbgscope's `fix/nt-lfh-bitmap-and-big-page-hash`, read
2026-09-23 from `nt`'s own code on the repository's sample dumps (x64 26100.32995,
`081226-2187-01.dmp`; ARM64 26100, `082126-7015-01.dmp`) and then measured against the live
`ctf-vm` guest, below.

- **`nt`'s LFH block bitmap is one bit per block, 64 to a word**, now
  `LfhBitmap::ContiguousBits`. The bit-level authority is
  `nt!RtlpHpLfhSubsegmentSetWitheldBlocks`, which withholds block `rdx` with `shr rdx,6` /
  `and r8d,3Fh` / `bts rcx,r8` against `BlockBitmap` itself — so the walker's bit `2 * slot` over
  `blocks / 4` bytes was neither the right bit nor the right length.
  `RtlpHpLfhBlockBitmapInitialize`, `RtlpHpLfhSubsegmentCountAllocatedBlocks` and ARM64's
  `RtlpHpLfhBlockBitmapAllocateNonAtomic` agree with it. Note what that routine withholds:
  the block straddling each page boundary, **wherever in the subsegment it falls**, marked busy
  like any allocation — withheld blocks are not a band of high slots a walk can stop before.
- **The big-page hash truncated the page number to ULONG, and `nt` does not.**
  `nt!ExpRemoveTagForBigPages` shifts the whole pointer and multiplies 64 bits wide
  (`shr rax,0Ch` / `imul rcx,rax,9E5Fh` / `shr rdx,20h` / `xor edx,ecx`); ARM64's
  `ExpAddTagForBigPages` is the same (`lsr x9,x21,#0xC` / `mul` / `eor x25,x8,x8,lsr #0x20`).
  Truncating agrees on the low 32 bits of the product and therefore on nothing that survives the
  fold: the two indices differed for every kernel address tried, a kernel page number not fitting
  in 32 bits. `lookup_big_page_target` stops at the first empty entry, so a wrong start index
  loses the tag and size rather than costing probes. Its test had recomputed the same truncating
  formula, so it agreed with the bug instead of catching it; it now pins `nt`'s indices as
  literals. **This half was never ARM64-specific** — it was wrong on x64 too, which is why it is
  worth reading before the gate.
- **Nothing the walker decodes has turned out to be x64-specific.** `_POOL_HEADER` and
  `_HEAP_LFH_SUBSEGMENT` have identical offsets on both, and both routine families above are the
  same algorithm on both. That answers the *investigation* the gate was waiting on; it is not a
  substitute for walking an ARM64 pool.

dbgscope#177 also changed three things the kernel walker shares — a segment list's head compared
exactly rather than masked, a free-page-tree node exempted from the `TreeSignature` check, and tree
links no longer masked to 16 bytes — each measured in user mode only. Those are still unmeasured
against a kernel.

**Both halves are now measured against a live x64 kernel** — the `ctf-vm` guest, Server 26100.33438,
2026-09-23, once it was rebooted:

- **The LFH bitmap, slot for slot.** Subsegment `0xffffac09de402000` carried `BlockCount` 171,
  `WitheldBlockCount` 14 and `FreeCount` **0** — every block allocated — with
  `CommitStateOffset - 8` = 3 bitmap words, all three `0xffffffffffffffff`. `nt`'s own arithmetic
  checks out exactly on it: popcount 192, minus `(-(171 + 14)) & 63` = 7 padding bits, minus 14
  withheld, is 171. The walk reported its *high* slots `reusable_free` against that, because two
  bits per block sizes the read at `ceil(171 / 4)` = 43 bytes where the bitmap is 24 — the extra
  19 bytes being the zeroes after it, so everything above slot ~96 read free. `!pool` calls those
  blocks `(Allocated)`; slot 0 decoded correctly, which is the boundary the arithmetic predicts.
- **The big-page hash.** `nt!PoolBigPageTable` at `0xffff8b836f5c0000`, `PoolBigPageTableSize`
  `0x4000`. The entry for VA `0xffff8b8371402000` sits at index **`0x1640`**, which is what `nt`'s
  hash computes; the truncating one computes `0x1948`, an empty slot.
- **The scale, and the direction.** A forced walk before the fix reported 173,649 allocated chunks
  of 276,511; after it, 252,079 of 292,736. Tens of thousands of live allocated kernel objects
  were being reported as freed — which is the worst direction for these tools to be wrong in, and
  is exactly backwards for the use they were built for.

`a_live_kernel_pool_walk_is_bounded_and_leaves_its_session_usable` now carries that comparison
(`compare_pool_decoding_against_the_engine`), **run both ways against the same guest**: on
`3c1fc7b`, the revision pinned before this landed, it fails naming four of twenty blocks that
`!pool` calls allocated and the walk calls `reusable_free`; on the fix — now
[dbgscope#178](https://github.com/glslang/dbgscope/pull/178), pinned here as `5f33d47` — it
passes, twelve blocks compared and none disagreeing. Twelve is past `POOL_ORACLE_MINIMUM`, which
is what says it compared rather than skipped. The fix was verified through a path dependency and
the merged revision is byte-identical to it (`git diff` over `src/pool/` is empty), so the
reading carries to the pinned build without a second ten-minute run.

**It costs 626s, and that is a finding rather than a footnote.** A `partial` walk's snapshot is
not reused, so each of the helper's `pool_find_tag` and `pool_chunk` calls pays a fresh ~20s walk
— roughly 18 of them here. On a live kernel the walk is *always* partial (uncommitted space
alone emitted 148 diagnostics), so every multi-query test of this shape is quadratic in the
number of questions it asks. Trimming the sample is the cheap half; the four disagreements the
control found were all on **one** page, so the page spread is what must not shrink and the
per-page count is what can.

**The gate is lifted, and what lifted it was a walk rather than the argument above.** The entry
said in as many words that matching structures answered the *investigation* and were "not a
substitute for walking an ARM64 pool", and that held: the bench that measured the x64 half is
x64, so the ARM64 half needed a different machine. It was run on 2026-09-23 against the
Parallels ARM64 debuggee — `Windows 10 Kernel Version 26100 MP (4 procs) Free ARM 64-bit
(AArch64)`, `26100.1.arm64fre.ge_release.240331-1435`, over `com:port=COM1,baud=115200`.

- **The readings, before the gate was touched.** `nt!ExpAddTagForBigPages` on that build computes
  `lsr x9,x21,#0xC` / `mov x8,#0x9E5F` / `mul x8,x9,x8` / `eor x25,x8,x8,lsr #0x20`, then
  `and x8,x8,x25` against `size - 1` and `add x8,x9,x8,lsl #5` — which also confirms the `0x20`
  entry stride. Against the live table (`PoolBigPageTable` `0xffffc386c3260000`, size `0x10000`),
  over the 17 in-use entries in the first 128 slots, `nt`'s hash lands on the entry's own slot
  **15/17** and the truncating one **0/17**; the two others sit one and two slots past their home
  index, whose home slots are now free, which is linear probing. Over 18 live LFH subsegments,
  `ceil(n/64)*8` matched the real bitmap — `(CommitStateOffset - 8)` words — **18/18**; `nt`'s
  count reproduced `BlockCount - FreeCount` **18/18**; and per slot `ContiguousBits` reproduced
  `FreeCount` exactly **18/18** where `AdjacentPairs` was wrong on **271 of 974 slots**, 256 of
  them live blocks reported free.
- **Then the walk, both ways against the same guest.** Blocks sampled from `!pool`'s *allocated*
  rows and the walk asked about each: 59/59 allocated `Cngb` on a 62-block subsegment and 7/7
  `CmFc` on a 49-block one with the fix, against 37/59 and 4/7 on the revision that was then
  pinned. In aggregate, over walks covering near-identical ground (8,165 against 8,168 chunks),
  7,055 allocated chunks against 6,238 — 817 chunks, 10.0% of those walked.
- **What the run also disproved.** The control's 22 misses are slots 33–39, 45–47 and 49–60,
  keeping only 41–44 and 48 above slot 32 — which is exactly the even-numbered bits of the word
  *past* the bitmap, predicted from the bitmap before either binary was built. The entry's own
  guess that the failure is "a band of high slots" is wrong in the same way `SetWitheldBlocks`
  is: the surviving slots are interleaved, not a prefix.

**What did not close, and is the thing to know before pointing the tier at a serial target.** No
walk here ever completed. All four ended `coverage: deadline_truncated`, having spent the 120s
`DEFAULT_WALK_BUDGET` on 8,165–8,288 chunks in ~285s wall each — 285.0, 285.1, 285.2 and 285.4s,
a spread tight enough to be a bound rather than work finishing, and within 15s of the 300s
default `WINDBG_MCP_CALL_TIMEOUT_SECS`. So the ARM64 evidence is a *bounded partial* walk that
decodes correctly, not an exhaustive one, and the 626s comparison above would be about 85 minutes
over that wire.

That turned the live tier's gate inside out rather than deleting it. `target_is_x64` and
`NOT_X64_SKIP` are gone; `pool_walk_is_affordable` reads the transport out of the connection
string instead, and the two pool tests skip a serial link **on cost**, with
`WINDBG_MCP_SMOKE_POOL_SLOW_LINK=1` to run them anyway. A transport nobody has measured counts as
affordable on purpose: the safe default is running a test that may be slow, not skipping one
silently.

**Where it landed:** the machine check in dbgscope's `src/pool/query.rs`, now the same two-machine
list against the same `IMAGE_FILE_MACHINE_*` constants `heap::validate_target` uses;
`test_unsupported_architecture_names_the_machine`, whose fixture moved to i386 because `0xaa64`
became a machine the gate *accepts*; the four `pool_*` descriptions in `windbg-mcp`'s
`src/server.rs`; and `pool_walk_is_affordable` in `tests/mcp_smoke.rs`.

## 99. [dbgscope] A big-page tag the engine resolves and the walker does not — **done** (2026-09-24, dbgscope#180, dbgscope#181)

**Repo:** `dbgscope`, surfaced by `windbg-mcp`'s `pool_*` tools.

**Filed as a question with three candidate answers** — the big-page entry is absent,
present-and-unreached, or present-and-rejected — and the answer was a fourth one the entry did not
list: **present, at exactly the index `big_page_hash` computes, and never consulted at all.**

`ExAllocatePoolWithTag` sends anything that will not fit inside a page to `ExpAllocateBigPool`,
which records the caller's tag and length in `nt!PoolBigPageTable` rather than in a `_POOL_HEADER`.
The walker decoded the page as though a header were there, so it read the caller's own first
sixteen bytes as `PreviousSize`/`BlockSize`/`PoolType`/`PoolTag` and reported the block as starting
0x10 in and 0x10 short. `!pool` calls `ffffac09dd0f5000` a 0x1000-byte `CM25` allocation; the walk
called it a 4080-byte block at `+0x10` tagged `..N.`, out of a registry hive bin's own `hbin`
header. Where those bytes happened to be zero the tag came out `0x00000000`, which is how the item
presented in the first place: as tens of thousands of untagged allocations.

**What the entry got wrong is which question decides it.** It assumed the *allocator* did — that a
big-pool allocation is a plain page range, told apart from the others by its descriptor — and its
third row, a VS chunk disagreeing by 0x10, was filed as probably-unrelated. It is the same defect:
`nt` puts big-pool allocations inside VS subsegments too, where the descriptor says `0x0f`, and a
descriptor cannot tell them apart in either place. What decides it is the **size**, and
structurally rather than by measurement: `_POOL_HEADER.BlockSize` is eight bits of sixteen-byte
units (`dt nt!_POOL_HEADER`, x64 26100.33438), so `0xff * 16` — 4080 bytes of chunk, its own header
included — is the most it can describe. 4080 of payload plus the header is exactly a page, and one
byte more has nowhere to record its own length. That is *why* such an allocation is in the
big-page table, and the table says it back: all 7,639 live entries on that guest recorded
`NumberOfBytes` of `0x1000` or more, and none fewer.

**Two further defects fell out of reading `nt` rather than the structure.** Bit 0 of `Va` is
`POOL_BIG_TABLE_ENTRY_FREE` and the address stays behind it — `ExpRemoveTagForBigPages` frees an
entry with `lock inc qword ptr [rax]` — so matching on `Va & !1` answered for *freed* pool with the
tag it used to have; 2,300 of that kernel's 32,768 slots were in that state, and `nt`'s own
comparison is `cmp rcx,rdi`. And the probe's stop test for `Va == 0` never fired, a never-used slot
reading `1`, so every miss scanned all 32,768 entries.

**Measured** on `ctf-vm` (26100.33438), the same census before and after the first half, minutes
apart: distinct tags **5,665 → 1,501**, the `....` bulk 79,166,848 → 51,216,352 bytes, and `CM25`
(19.0 MB), `CM16`, `EtwB`, `Gpbm`, `Obtb`, `ClfI`, `CM29`, `DxgK` and `Pool` — the big-page table's
own 1 MB allocation — correctly tagged where they had been scattered across bogus tags, one of
which was `0x838bffff`, the top half of a kernel pointer. After the second half, two hours later
against a pool that had itself grown 5%, the `....` bulk fell again to 42,785,104 bytes and
`0xffffac09da29f000` matched `!pool` exactly: `MiRr`, 57,792 bytes, header at the allocation.

**The remedy was built so that it did not have to wait for what is still unexplained.** A chunk
past the limit is matched against the table's entries **by containment and length** rather than by
arithmetic on the chunk header, because the 0x10 between the two is measured and not understood.
That is now item 101, and it is a smaller thing than it was: only chunks *under* the limit carry a
header at all, so only they can have it mislocated.

**A test that agreed four times out of four is the reason this one has an oracle.** `mcp_smoke`'s
`BigPageOracle` puts every `large page allocation` line `!pool` prints back to the walk, sampled
from the engine's side — a walk that loses a tag loses the allocation from every query made under
that tag, so its own output could never have shown this.


## 98. [dbgscope] Uncommitted memory is an unreadable gap, so a live heap walk is not `Complete` — **done** (2026-09-24, dbgscope#183)

**Repo:** `dbgscope`, surfaced by `windbg-mcp`'s `heap_*` and `pool_*` tools.

**The entry's own proposed remedy is not the one that landed, and the reason is the half of it the
entry was least sure about.** It said to tell decommitted from unreadable *using what the
allocator records* — `CommittedPageCount`, `CommitBitmap` — and then, in a bullet added the day
before this was built, warned that those records cannot separate a page that was never committed
from one that was committed and trimmed. Both halves are right, and together they say the
allocator is the wrong witness. The **memory manager** is the right one:
`IDebugDataSpaces2::QueryVirtual` answers `MEM_RESERVE`, `MEM_COMMIT` or `MEM_FREE` about the
target in one call, and about the target rather than about what one allocator believes. It is now
`DebugEngine::virtual_region`, a typed `VirtualRegion`/`VirtualState`.

**Checked rather than assumed, because the allocator route was the specified one.** On 26200 the
records are all there and they do answer: a VS subsegment at `0x245ce144000` covering 0x40000
bytes carried `CommitBitmap = 0x00c01fffffffffff`, and the nine clear bits 45–53 are exactly the
`[0x245ce171000, 0x245ce17a000)` hole the walk reported — bit for bit, no rounding. What the route
also needs is *three* structures rather than two: an LFH page range's descriptor reads
`CommittedPageCount = 1` while two of its 33 pages read, because LFH commits its own pages lazily
and records them at `_HEAP_LFH_SUBSEGMENT.CommitStateOffset` (in eight-byte units, just past the
block bitmap; `CommitUnitShift`/`CommitUnitCount` beside it). Three structures that each move
between builds, against one call — and the one call is also the only one of the four that is
*about the pages* rather than about an allocator's bookkeeping.

**`PoolState::Uncommitted` joins `Unreadable`**, `HeapState` with it, and
`PoolState::is_coverage_gap` is now the single definition of which gap costs a walk its
`complete`. Three properties keep it from being an excuse:

- **Only a positive answer excuses a gap.** A failed query, a run that cannot advance, a state the
  crate does not name (`VirtualState::Unknown`), and a source that cannot be asked are each `None`,
  and `None` keeps the conservative reading. `PoolMemory::committed_run` **defaults** to `None`, so
  every fixture written before this keeps its old meaning and the ones exercising the new state
  have to say so — which is what makes their assertions mean anything.
- **It is asked of the memory manager, never inferred from where the span lies.** That inference is
  what the entry itself did — "read from where they lie, not yet checked" — and item 100 is the
  case it would have got wrong: on a guest trimming paged pool the pages that will not read are
  committed and written.
- **A kernel session is not asked at all**, so the kernel pool walk **classifies** exactly as
  before. `QueryVirtual` is a user-mode question, and a kernel walk files thousands of unreadable
  spans, which would be thousands of failed calls to learn the same thing each time. It is not
  *unchanged* — that word was in this entry until the kernel run below, and it was wrong: the
  silent `walk_vs` site is silent on a kernel too, and now names what it drops.

**The entry named one mechanism and there were two.** With every gap classified, `sihost` was
*still* `Partial`, with no diagnostics, no refusals and no stalls to say why — five free chunks
whose middles the allocator had decommitted, each running past the committed extent it starts in,
for which `walk_vs` emitted no span and cleared `complete` **silently**. A span is geometry and
state, both known there (header read, size out of that header and past the subsegment bound, state
from the free tree); the only thing missing is the chunk's contents, which no span carries. So
where the tail is **confirmed** to hold nothing the chunk is now reported, and where it is not —
memory the process has, or memory nothing could be asked about — it is still refused, with the
walk now naming the chunk it dropped. That silent site was the
standing example in `docs/unknown-not-absent.md` of a walk ending incomplete having said nothing.

**The trap that cost the most time is in the primitive, not the walk.** `QueryVirtual`'s output
buffer must be **16-byte aligned**, and `MEMORY_BASIC_INFORMATION64` is 48 bytes of 8-byte fields,
so Rust aligns it to 8. The engine's *live-target* path copies the answer out with three `movaps`
stores and takes an access violation **inside dbgeng**; the dump path copies field by field and
never complains. The identical call had already answered 22 queries against a full dump before it
was first pointed at a live process, so the dump measurement was evidence of nothing. Found by
running the probe under this server (`dbgeng!Ordinal367+0x14f96`,
`movaps xmmword ptr [rbx],xmm0`, 26200, 2026-09-24) — there is no Rust frame in the fault.

**Measured**, through the new `examples/heap_coverage.rs`, which walks a target and then puts every
gap the walk filed back to the memory manager with an allocated chunk and a free one as controls:

| | before | after |
|---|---|---|
| `sihost` (live, 26200, 4 Segment Heaps) | `Partial`, 45–47 unreadable gaps | `Complete`, 0 unreadable, 33 uncommitted (0x3fd0a0 B) |
| a `.dump /ma` of `RuntimeBroker` | `Partial`, 22 unreadable gaps | `Complete`, 0 unreadable, 22 uncommitted (0x335000 B) |

Every gap `MEM_RESERVE` on both, from a query independent of the one the walk made; both controls
`MEM_COMMIT` on both.

**And the dump case the entry was deferred over was checked from the other end**, since a walk that
swept it up would be the same lie in the other direction. A thin dump (`.dump /mdi`) of that same
`sihost`: address `0x1ec81102040` answers `Committed`, reading it fails `0x8007001E`, and the walk
keeps counting it. A committed page a dump does not carry is not forgiven.

**The live-kernel control, taken the same day once a guest was up**, and it corrected this entry.
The tier ran against `ctf-vm` (live 26100, KDNET) on the new pin: 633,665 chunks walked, 444,836
allocated, `coverage: partial` and the walk returning in 42.3s, inside its budget — so the
conservative path really is the one a kernel takes, and it costs nothing, `committed_run` being
gated on `is_kernel_target` before any engine query. What the run also showed is that "the kernel
pool walk is unchanged" was too strong. The new `walk_vs` diagnostic is the **largest shape on that
target**: `VS chunk at # is # bytes and runs # past the committed extent at #; no span is emitted
for it`, **2,768** occurrences, beside 2,617 of the unchanged `region # is only committed through #`.
Those 2,768 chunks were being dropped before this change as well — the site already cleared
`complete` — with nothing in the answer saying which, or how many. So classification and coverage
are unchanged on a kernel and `diagnostics_emitted` rises, which is the improvement rather than a
regression, and anything thresholding on that count will see it.

**Do not read the other shapes' counts against item 100's table.** That run was a different build
on a differently-loaded guest — 783,042 chunks at 88.1% allocated against 633,665 at 70.2% here —
so the 2,617 here and the 207 there are two readings of two machine states, not a before and an
after. What says the unchanged shape is unchanged is the third arm of
`test_a_gap_with_nothing_behind_it_is_not_worth_a_diagnostic`, which is the kernel case exactly: a
source that cannot be asked still emits it. The conditional added here can only make that
diagnostic fire *less*, never more.

**`examples/user_heap_smoke.rs` could not run, and the reason is not this bench.** This entry
first said `HeapCreate(HEAP_CREATE_SEGMENT_HEAP)` "returns an NT heap **here**", which attributed
to the machine what belongs to the Win32 wrapper: `KERNELBASE!HeapCreate` opens with
`and ecx,40005h` — `HEAP_CREATE_ENABLE_EXECUTE | HEAP_GENERATE_EXCEPTIONS | HEAP_NO_SERIALIZE` —
so 0x100 never reaches `RtlCreateHeap`, and that example built a classic NT heap on **any** host
with this wrapper. It then failed two hundred lines later saying the heap was not among the roots,
which reads as a defect in root enumeration and is not one.

Measured in one process on x64 26200 (2026-09-24), `ntdll!RtlpHpHeapFeatures` 0 throughout: all
three `HeapCreate` shapes that could plausibly matter — growable, with an initial size, with a
fixed maximum — came back NT, and `RtlCreateHeap` with the same flags plus 0x100 came back a
Segment Heap moments later. Fixed in dbgscope#186, which calls `RtlCreateHeap` and reads the
signature back at creation.

The **per-process** switch is a separate thing and is the one to know when picking a target:
`ntdll!RtlpHpHeapFeatures` bit 0 governs the heaps an image gets *without* asking — 1 in `sihost`,
whose four heaps are Segment, 0 in `cmd.exe`. So a process the system enabled it for is what to
point the tools at. And two signatures are easy to swap: `_SEGMENT_HEAP.Signature` and
`_HEAP.SegmentSignature` are both at `+0x10`, while `_HEAP.Signature` (`0xeeffeeff`) is at `+0x98`
— this entry quoted the latter at the former's offset.

## 80. [windbg-mcp] `identity()` re-derives the backend distinction once per field — **done** (2026-09-25)

`local_model_eval.identity()` decided what a record contributed to each identity field by testing
the backend **again, separately, in every place that needed it** — a three-way `if/elif/else`
covering `harness` and `reasoning`, and an unrelated inline ternary choosing `os_build` over
`model_digest` for `weights`. Neither knew about the other, and a field added tomorrow got whatever
its author happened to write. Both existing tests had been added *reactively*, one per review round
on the PR that introduced the third backend, each after a run had already reported something false:
an fm run comparing across a macOS update — which *is* a model update — as though nothing had moved
(`09aa279`), and `think: false` on a backend with no reasoning arm printing `on, off` for a run in
which every backend *with* the knob ran with it on (`faa147a`).

**What landed is the second of the two shapes the entry proposed**, which is the one it called the
complete close: each driver emits the resolved value under one agreed key. `IDENTITY_FIELDS` in
`local_model_eval.py` is the closed list — `weights`, `reasoning`, `harness` — and each of
`local_model_drive.py`, `claude_code_drive.py` and `fm_drive.py` has an `identity_block()` that
answers **all three** on every record it writes, `None` where the row has no answer. `identity()`
reads that one key and tests no backend at all. `tools/test_local_model_eval.py` is the check the
entry asked for: twelve tests, of which
`test_every_backend_answers_every_identity_field` fails when a name is added to `IDENTITY_FIELDS`
that a driver has no opinion about, and
`test_a_field_no_driver_answered_is_unrecorded_rather_than_defaulted` fails when the grader
defaults one instead of saying so. Each was mutation-verified against the mutation it is for, and
the two hold the seam from opposite sides: adding `quantisation` to `IDENTITY_FIELDS` fails the
first on all three backends and leaves the second green, while making `stated()` return
`unavailable` for an absent key fails the second and leaves the first green. Two further
mutations — `fm_drive` dropping `harness` from its block, and the grader inferring the fm arm from
`think` again, which is the `faa147a` bug — fail
`test_each_backend_reports_what_it_claimed` as well.

**What the entry did not see is that the dispatch cannot be deleted, only frozen.** Logs written
before the drivers stated a block still have to grade to what they graded to, or every published
run loses its digests and its harness version. So `legacy_identity()` holds the old per-backend
reading, for records with no `identity` key — and that function is closed by construction rather
than by discipline: a record without the key predates it, so the backends and fields it can have
been written by are fixed at 2026-09-25, a new backend's records always carry the block, and a new
field is absent from every legacy record and correctly reads `unrecorded`. The dispatch is
therefore gone from the path that grows and survives only on the path that cannot.

**And three published identity lines were wrong, which nobody had filed.** Re-grading the six logs
in `eval-out/` moved only the identity block — every cell score, `--matrix` distribution and
`--compare` row is byte-identical — and every line that moved was an overclaim:

- `harness 2.1.270 (Claude Code)` → `2.1.270 (Claude Code), unavailable` on a mixed run. The
  version belonged to the Claude rows; printed alone it read as the whole run's.
- `reasoning unrecorded` → `unavailable, unrecorded` on `2026-09-13` and the three pre-axis logs.
  The Claude rows never *had* an arm; they did not fail to record one.
- `reasoning off` → `off, unavailable` on arm A of the reasoning A/B, and arm B gains
  `harness unavailable` where it previously printed **no harness line at all**. That pair is the
  clearest case: the composition difference between the two arms — arm A had Claude rows and arm B
  did not — was invisible in the field the A/B is about.

The old rendering had two spellings of "no answer" and chose between them per backend: fm stated
`reasoning unavailable` while claude-code, in exactly the same position, contributed nothing. That
was itself an instance of the item — two backend tests, added a round apart, not agreeing in shape.
`docs/eval-runs.json` is regenerated from the same logs, and the footnote now glosses whichever of
the two words the block actually printed rather than keying on `unrecorded` alone.

**Where it picked up.** `identity()` in `tools/local_model_eval.py`, the `stated()` helper beside it
and its `unrecorded`/`unavailable` distinction, and the three drivers' cell dicts
(`local_model_drive.py`, `claude_code_drive.py`, `fm_drive.py`).

## 32. [windbg-mcp] Two ARM64 CI entries, one of which expires — **done** (2026-09-25)

The debugger tier's ARM64 half was a **pair**: `windows-11-arm` and `windows-11-vs2026-arm`. That
was deliberate and temporary. GitHub's Visual Studio 2026 ARM64 image went generally available on
2026-08-20 under the new label, and the `windows-11-arm` label was to be migrated onto it between
21 and 30 September 2026 — so for the duration the two labels were two *OS builds* and therefore
two inbox `dbgeng.dll`s, which is the one thing that job exists to load. Running both is what made
a break during that window attributable to the image rather than to the change under review.

**It converged on 2026-09-23, and the entry was measured rather than taken on announcement.** The
workflow's own runs report `Image: windows-11-arm64` at 2026-09-23T06:22Z and
`windows-11-vs2026-arm64` at 12:57Z the same day — so the flip is pinned to a six-hour window
inside the announced one — and the new image on every run since: eleven sampled across the
following 47 hours, up to and including the merge run of item 80 (`36132889458`, 2026-09-25T12:04Z),
where **both** ARM64 entries reported `windows-11-vs2026-arm64`, `Version: 20260920.164.1`. Same
image, same version, same engine. That is the entry's own convergence condition, and the pair had
stopped buying attribution and started buying a duplicate twenty-minute run on every PR.

**What landed is not quite what the entry said.** It said to drop the `windows-11-arm` entry and
keep the new one, which is right about the *label* and silent about the job *name* — and the name
is the half with the lesson in it. The surviving entry is `windows-11-vs2026-arm` with the suffix
`, arm64`: the label pins the image, the name says which tier it is. Carrying `vs2026` in the job
name would rot exactly as `windows-11-arm` did, one image later. So the convention the pair
established is now written down where the next migration will be read: **the stable entry is
always `, arm64`; a transitional second entry always names the image in its suffix**, both are kept
while they report different images, and the older goes when they do not.

**The required-status-check trap did not bite, and was checked rather than assumed.** `ci.yml`'s
own comment warns that renaming a matrix entry does not rename a required context — it removes the
only job that could satisfy it, and every PR in the repo then blocks on a check that will never
report again. The repository ruleset requires `Build & test`, `Documentation lint` and
`Smoke test (debugger tier)` and **neither ARM64 name**, so both were free to change. Reading the
ruleset took one API call and is the step to repeat rather than the conclusion to reuse.

**And it invalidated a measurement, which is the durable half.** Issue #153's finding — that
`windows-latest`'s System32 carries `symsrv.dll` and `windows-11-arm`'s carries none — is now a
statement about an image that label no longer names, and nobody has probed the new one. It cost
nothing only because the copy step was already written to be independent of the answer, which was
the deliberate choice recorded at the time: *"copying makes the entry not depend on the answer,
which is the property worth having across an image migration"*. That prediction was the one thing
here that was tested by events, and it held. `docs/smoke-test.md` and
`.claude/skills/live-kernel/SKILL.md` both now say which image the probe was taken on rather than
which label.

**Where it picked up.** The `smoke-debugger` matrix in `.github/workflows/ci.yml`, its symbol-half
copy step, the CI section of `docs/smoke-test.md`, and the `symsrv.dll` paragraph in
`.claude/skills/live-kernel/SKILL.md`.


## 81. [windbg-mcp + dbgscope] `changes_debug_target` reads a name, and a wrapper does not say one — **done** (2026-09-25)

**Filed as** `[windbg-mcp]`, and that was the first thing building it disproved. Three shapes were
weighed in the entry and the third — *observe the target instead of predicting it* — was called the
only sound one. It is, and it needed two engine queries neither crate exposed, so this is a pair of
PRs rather than one.

`changes_debug_target` matched the first token of each `;`-separated segment against a list —
`.opendump`, `.attach`, `.detach`, `q` and the rest — and `execute` retired the session's handles
before running a command it matched. `set_breakpoint` refused one. What neither could see was a
wrapper: `.if (1) { .opendump C:\other.dmp }` presents `.if`, and so do `.foreach`, `.block`, `j`,
`z` and an alias defined with `as` — which resolves at *execution* time, so no reading of the text
before it runs can ever be complete. Raised by Codex on
[#341](https://github.com/glslang/windbg-mcp/pull/341) and reached independently by CodeRabbit on
the same PR, both proposing the same remedy: keep the text scan as an early defence and reconcile
the target's identity afterwards.

**What landed.** The worker takes a *fingerprint* of what its engine holds when the target is
opened, and compares it after every op — which is after every command, and therefore after every
breakpoint hit, since a hit happens inside the run whose op has not answered yet. When the two
differ it sends `WorkerMessage::TargetReplaced`, **before** that op's `Done`, and the supervisor
retires the session's handles. One pipe read in order is what makes "before" mean something: the
retirement is applied ahead of the answer reaching the caller and ahead of anything queued behind
it. It is the same move `worker::pump_a_resume` already made for the running state, whose comment
had said for months that "an alias, a `;` list and `.if` all reach execution without saying so, and
a name list that decided this would be wrong in both directions".

The fingerprint is three engine reads, and what each is for is worth keeping:

- **`GetDebuggeeType`'s `(class, qualifier)` pair.** Separates a live kernel from a kernel dump and
  a live process from a user dump. dbgscope read it in two private places and threw the qualifier
  away in both, so nothing outside the crate could ask.
- **`GetNumberDumpFiles` + `GetDumpFileWide`.** Not read anywhere before. It is the only field that
  sees **two dumps of the same process** — same class, same qualifier, same pid, taken five minutes
  apart — which is the ordinary way a `.opendump` swap looks.
- **The current process's OS id, user-mode only.** It catches the replacements that keep the kind
  and have no file to compare: `.attach`, `.create`, `.restart`.

**Five things it turned out not to be.**

- **`dbgscope::DebugEngine::target_identity` reads as though it answers this and does not.** It is a
  generation *that crate* hands out at its own openers and teardowns, used to stop a `Scope` or a
  `ThreadContext` being restored onto a later target. A `.opendump` typed straight at the engine
  never goes through either, so the identity sits exactly where it was — which its own `set_scope`
  doc says, about a borrowed WinDbg client, and which reads as a caveat rather than as the answer
  to this question. Anything that has to notice a swap has to *read the engine*, every time.
- **The pid cannot be in a kernel fingerprint.** On a kernel target "the current process" is
  whatever the machine was running at the last break, so it moves across every `g`; carrying it
  would retire a live handle each time a kernel stopped somewhere else. The rule is its own
  function (`fingerprints_the_process`) so it can be stated against the qualifiers and
  mutation-verified rather than inferred from a call site.
- **A target that has *gone* is not a target that has been *replaced*, and this deliberately says
  nothing about one.** It looks like the same case and is not: there is no second target for a
  handle to wrongly certify, the ending is already carried by `StopReport::target_gone` and refused
  by `worker::refuse_when_the_target_is_gone` with the same recovery a retirement would name — and
  retiring there would break the ordinary ending of a launched program, whose `continue_async`
  would have its session retired between the stop and the `wait_for_stop` that collects it, so the
  run's own result would be refused to the caller who asked for it.
- **The entry's own closing instruction was wrong.** It said the two assertions in
  `server::tests::a_breakpoint_command_that_changes_the_target_is_refused` "should flip to
  `assert!` when it closes". That presumed the *parser* — shape two. Under shape three
  `changes_debug_target` is exactly as incomplete as it was: it still cannot see inside an `.if`,
  and is not supposed to. The assertions stay `!` and now say why, with a pointer to the observer
  that makes the gap survivable. A prescription written beside three options can only be right for
  one of them.
- **Reading the fingerprint is not safe on every engine, and only the tier said so.** The first
  run of the debugger tier killed the engine worker on the two tests where a launched program runs
  to completion — *the engine worker process holding session `sess-…` is gone*. `dump_files`'s
  `GetNumberDumpFiles` on an engine with no debuggee is a `STATUS_ACCESS_VIOLATION` **inside**
  DbgEng, which `catch_unwind` cannot trap, so it takes the process rather than failing the call;
  `debuggee_type` in the same state answers `DEBUG_CLASS_UNINITIALIZED` without complaint. Two
  queries beside each other behaving differently is exactly how they come to be read in one place.
  `has_target` is now asked before either, and dbgscope guards `dump_files` as well, so the
  downstream guard is defence in depth rather than the only thing between a caller and a dead
  process. It is also the reason a probe was committed upstream
  (`examples/held_target_probe.rs`): every claim this entry makes about what a field answers per
  target kind is a line of its output rather than a reading of the API.

- **Retiring the handle afterwards is too late for a call that is already queued**, and the two
  mechanisms differ in exactly that. `Gate::retires` is applied by the supervisor's pump *as it
  forwards the offending job*, so anything behind it meets a session already `Retired`; an
  observation can only be made after the fact, and `engine::pump` writes a job into the worker's
  pipe as soon as it clears that gate without waiting for the job ahead of it to answer. So a
  second call could be sitting in the worker's queue, past every check the supervisor has, when
  the first one replaces the target. The worker therefore asks the same question again **before**
  each op as well as after it — one `Watch` value decides both ends, so an op cannot be refused on
  the way in and never reported. Raised by Codex on the PR, and correct; what no test here stages
  is the race itself, which needs two genuinely concurrent submissions, so what is pinned is the
  shared list and the comparison rule rather than the window.

- **And that refusal must not swallow the handle-less flow**, which was the third finding and the
  one that would have been worst to ship. A retired session goes on serving calls that name *no*
  session, deliberately: the worker is the server's current target, and a caller who asked for no
  guarantee gets whatever it now holds (`On::Default`, `SessionState::accepts_default`, and
  `docs/sessions.md` says so). A refusal keyed on the replacement alone made the new target
  unreachable through the one route documented to reach it, for the life of the worker. The worker
  cannot tell the two kinds of call apart — the supervisor knows, from the gate — so it is now told,
  by `WorkerRequest::handle_bound`. Worth carrying: the useful shape of this mechanism is *which
  promise was made to this caller*, not *what is true of the target*, and the first draft asked only
  the second.

- **Retiring at the stop took away the stop**, which was the fourth finding and the only one that
  was a regression this change *introduced* rather than a gap it failed to close. A
  `continue_async` run whose breakpoint command replaces the target is retired by the very op that
  filed its stop, and `wait_for_stop` resolved through `Sessions::resolve` — so the result the tool
  undertakes to keep collectible became uncollectible at the moment it was most worth reading.
  `SessionState::accepts_execution_read` is the third widened predicate beside `accepts_default`
  and `accepts_teardown`, and the line it draws is **reading a record against operating on a
  target**, not "is an execution handle involved": `break_in` and `interrupt` reach the engine and
  stay refused. Unlike item 55 it needs no matching widening at the front of the queue, because the
  call it admits never gets there — `Sessions::wait_for_stop` reads the execution slot and submits
  no job. Worth checking before adding a fourth: the three agree on `Retired` and part company on
  `KernelUnresolved`, which only a teardown may touch.

- **The baseline was conditioned on the opener having *succeeded*, and an opener can fail with the
  target already open.** `Sessions::open` answers `OpenError::PostCommit { report_only: true }`
  when only the follow-up diagnostic failed, and hands back a usable handle on purpose — so those
  sessions, live and caller-visible, would have had replacement detection disabled for good. Also
  Codex's. It is read off the engine now (`has_target`), which is the same question the guard
  above already had to ask, so the fix removed a parameter rather than adding a case.

- **The current process is the *selection*, not the session**, which is the difference between a
  fingerprint and a trap. DbgEng moves the current process by itself when a child process starts
  and `|Ns` moves it by hand, and neither changes what the session is debugging — so a fingerprint
  built from `current_process_system_id` retires a live handle the first time the debugger points
  somewhere else, permanently, with nobody having asked for anything. It is the process **set**
  now (`DebugEngine::session_processes`, made public for it), sorted, pids only. That still catches
  what the field is for, because the replacements in question change the *composition*: `.attach`
  and `.create` add a process, `.restart` swaps one for a new pid — the same commands the by-name
  list already refuses, so the two agree about what counts. Raised by Codex; it was an edge I had
  reasoned about while designing and then failed to write down, which is worse than not having
  thought of it, since nothing in the code carried the doubt forward.

- **And it was worded in *three* places, of which the first draft fixed one.** `engine::stale_handle`
  is the refusal a caller meets; `server::describe_session` is what `session_status` prints; the
  `SessionState::Retired` variant in `src/structured.rs` is the typed half. Correcting one and
  claiming the wording fixed is how a statement comes to be true in a changelog and false on the
  wire — caught by CodeRabbit, and the lesson is to grep the *claim* rather than the symbol, since
  none of the three shares a function with another.

- **The one finding on this that was declined, and it was declined by measuring.** Review came
  back on the process set arguing the other way: a child process starting or exiting under
  `.childdbg 1` changes the set without the session being replaced, so the first child lifecycle
  event retires the handle. The fact is right; the remedy — tolerate it — is not. The question is
  not whether the set moves but whether a caller's reads still land where they think, and on
  dbgeng 10.0.26100.1 (ARM64, 2026-09-25) they do not: at the child's create event the set goes
  `[2368] -> [1000, 2368]` **and the current process goes `2368 -> 1000`**. Every typed tool here
  reads the current process, so a handle that went on certifying the original would be certifying
  something the next `registers` cannot deliver. dbgscope's `examples/child_process_identity.rs`
  is the record. The line this draws is worth keeping: **a set change is something that happened
  to the session, while the selection moving on `|Ns` is something a caller did** — deliberately,
  through the raw hatch, and without moving the set. The one nobody asked for is the one that
  retires the handle.

- **A break has its own path and needed the rule told to it separately.** `interrupt` and
  `break_in` are answered on the worker's *request reader*, ahead of the engine thread's queue —
  that is the whole point of them — so neither the pre-op nor the post-op check is on their road,
  and `SetInterrupt` acts on whatever the engine is holding. A handle that still looked good would
  have stopped the replacement. `refuse_a_break_for_a_replaced_target` reads the same latch on that
  thread, which it can do **because a `OnceLock` read is not a DbgEng call**: `SetInterrupt` is the
  one entry point documented as safe from another thread, and `AGENTS.md` makes adding a second a
  design change rather than a local one. What none of this closes is the window *inside* the op
  that does the replacing — until it returns nothing has observed anything, here or in the
  supervisor — and that residual is not introduced by this work: before it, a wrapped `.opendump`
  left the handle good for ever, so the window goes from unbounded to one operation. Closing it
  outright would mean reading the engine from the request reader, which is the design change above
  rather than a fix.

- **Every live kernel looks alike, so the fingerprint could not see one swapped for another** —
  same class, same qualifier, no dump files, no process set. Raised by Codex and confirmed by
  attaching to one: the only thing that differs is the connection, which `dbgscope`'s new
  `kernel_connection_options` reads. It is kept as a **hash**, because a KDNET connection string
  carries the target machine's debug `key=` and the fingerprint derives `Debug` and lives for the
  worker's lifetime — one `{:?}` in a log line, now or later, would put a key on the server's
  stderr and into `server_log`. Two other things that run came out of measuring it: the string is
  DbgEng's own canonical form rather than what was dialled (30 characters of `com:port=COM1,…`
  read back as 75 of `KdSrv:…`), so it cannot be matched against a profile; and it answers
  `E_UNEXPECTED` on every non-kernel target, which is a `None` like any other.

  **This was the third round in a row to find a gap by naming one**, which is the signal rather
  than any of the three. The answer was to stop and enumerate: `TargetFingerprint`'s doc now
  carries a row per opener saying which field identifies that kind of target, stated as *what is
  covered* rather than as *what the gaps are* — a row is a claim about one opener and checkable on
  its own, where "these are the only gaps" is a claim about every pair and had been wrong three
  times. An opener added with no row is covered by nothing, and that is readable against
  `EngineOp`.

- **`SessionState::Retired`'s message claimed something that was already untrue.** It told a caller
  "the worker still holds a target, but it is not the one this handle names" — false for `.detach`,
  `q` and `qd`, which are on the by-name list and leave none. It now says only what is true either
  way: the handle does not name the target it was issued for.

**Where it picked up.** `worker::watch_the_target`, `TargetFingerprint` and `replacement` in
`src/worker.rs`; `WorkerMessage::TargetReplaced` in `src/proto.rs`; the `reader` arm and
`stale_handle` in `src/engine.rs`; `changes_debug_target`, `outside_quotes`, `dx_executes_commands`
and `set_breakpoint` in `src/server.rs` — all four of which described the gap and now describe the
division of labour. Upstream: `DebugEngine::debuggee_type`, `DebuggeeType` and
`DebugEngine::dump_files` in dbgscope.

## 102. [windbg-mcp] A `debug_batch` runs its rollback against whatever target it ends up holding — **done** (2026-09-26)

**Filed while closing item 81, and not introduced by it.** That item's fingerprint retires a
session's handles when an op ends holding a different target, which is the *handle* guarantee. What
it does not do is stop a batch that is already running, and that is the sharper half: `batch::run`
watched one thing between steps, `done.target_gone`, so a target that had been **replaced** rather
than released read as an ordinary step. Every remaining step ran against the replacement — and so
did the `always` block, whose whole job is to put a mutation back, writing a restore into a target
that never had the mutation, at an address that means something else there. On a live kernel that
is a write into somebody else's machine.

Nothing upstream stopped it. `batch::validate` refuses unknown fields and bad operands and says
nothing about command text; `batch::retires_handle` and `batch::mutation` both ask
`server::changes_debug_target`, which matches the first token of each `;`-separated segment and so
cannot see a wrapper — and `retires_handle` retires the *handle* in any case, which does not stop a
batch that is already running. **Reached independently by Codex** on
[#389](https://github.com/glslang/windbg-mcp/pull/389) while that PR was in review, with the same
remedy: recheck at step boundaries and abort the remaining steps *including* the cleanup.

**What landed.** `Debuggee::replaced` — one more question the executor asks its host, answered in
the worker by the same fingerprint comparison item 81 built. `batch::run` asks it after **every**
step, and on a `Some` it stops the batch as `BatchOutcome::TargetReplaced { at }`, lists every
remaining step as skipped, and **drops the `always` block**, listing each of its steps as skipped
with the reason. From that moment the batch issues no further engine call at all: it does not
announce the rollback (`rolling_back` exists to protect cleanup commands from a break, and there
are none), and it does not run the state probe (`? @$ip` would answer perfectly well — about the
*replacement*), reporting `SessionAfter::Detached` naming the step instead.

Three things about the shape of it are worth keeping.

- **The baseline is the batch's, not the session's.** `replacement_now` compares against
  `OPENED_AS`, the reading taken when the *session's* target was opened; the batch compares against
  what it found when it started (`worker::batch_baseline`, `held_now`). The two are
  different questions and the difference is a documented route rather than an edge: a call naming
  no `session_id` is deliberately served by whatever the worker now holds, retired handles and all,
  so a batch can legitimately be running against a target that already replaced the session's
  original. Measured against `OPENED_AS`, every such batch would have refused to roll back for the
  life of the worker — the same over-reach `refuse_when_the_target_was_replaced` was narrowed to
  avoid on #389, arrived at from the other direction.
- **The rollback verdict needed a third value, and `rollback_complete` had to stay.** A `false`
  there is now two pieces of news — cleanup that ran and did not finish, and cleanup that was
  deliberately not run — and they send a caller to opposite places. So `BatchReport::rollback`
  answers `NotSupplied`/`Complete`/`Incomplete`/`NotAttempted` and
  `structured::BatchReportInfo` carries both: the flag is what `server::batch_settled` branches on
  to decide `isError`, and removing it would have moved that decision as a side effect of a
  reporting change. `NotAttempted` is asked of the outcome **and** of the step list, so the report
  states what happened rather than what the executor decided.
- **The cleanup block can be where it is first seen, and that is not the same news.** An `always`
  step that replaces the target stops the rest of the cleanup, but the steps themselves ran, so the
  outcome stays `Committed` and the disposition is `Incomplete` — part of the block ran. This was
  not in the item and is the same hazard one block later; it cost four lines, and then a review
  round, because the **last** cleanup step is the case those four lines got wrong: with nothing
  left to skip, every `always` step reads `Ok` and a predicate over the step list alone answers
  "complete" — which `server::batch_settled` turns into "nothing is owed", on a batch whose last
  restore may have landed in whatever the engine now holds. `rollback_complete` asks both halves
  now, and the rendering has a line for a block where nought of the steps failed and the rollback
  is still not complete.
- **One window is closed and one is declined, and the difference is what the critical section
  would have to hold.** Asking the host for a pending break and then sealing the job are two
  transitions, and a break arriving between them is recorded, drained by the seal, and reported
  when the job is released — beside a verdict that was decided before it. `Debuggee::sealing`
  answers both now, read under the lock that already seals and drains, with no DbgEng call added
  to the critical section. The *other* window — between the identity probe and the seal it may
  trigger — is left open on purpose: closing it means holding the worker's interrupt lock across
  four DbgEng queries, so the request reader blocks on the engine thread, which is exactly what
  `AGENTS.md`'s one approved cross-thread exception exists to avoid. And it would buy nothing:
  that reading runs immediately after the call that changed the target, so a break that could land
  in it could have landed a moment earlier **inside** that call, where nothing has observed
  anything yet. The window is strictly contained in one that cannot be closed at all.
- **The promise lived in five places and a `head` hid two of them.** The sweep that was supposed
  to be the enumeration — grep the tree for "every path" — was piped through `head`, which stopped
  at exactly ten matches and cut off `src/server.rs` entirely. Two rounds then arrived one copy at
  a time: the `always` field's own description, served in the *input* schema; the shipped plugin
  skill; and `GROUP_INSTRUCTIONS`, assembled separately from both. The last of those is
  budget-bound — a client truncates the instructions at **2,048 characters** and they were at
  2,003, so the exception had to fit in nineteen of the remaining forty-five ("on every path *it
  can be aimed at*") with the contract left to the tool's own description, which is what
  `discover_opens_a_session_without_initialize` refuses to let fall off the end. The lesson is the
  cheap one: `| head` turns an enumeration back into a sample, and a sample is what this rule
  exists to stop.
- **And the same false claim again, one channel over.** The refusal an `interrupt` racing a
  stopped batch reads said "this session's handle is being retired with it" — true when the target
  was replaced and false for the other two ways of losing it, which retire nothing. Caught in the
  report first and in the request reader a round later, which is the tell that a distinction made
  in one place has to be carried to every sentence that depends on it: one seal reason covers three
  causes, so its message may claim only what all three share, and the batch's own reply is what
  says which it was.
- **Six review rounds asked one question — *how soon does the batch find out* — and the answer
  is where the probe sits, not how many places it is repeated in.** It began after the loop, moved
  to after each step, then to the detection point for the seal, and finally to between a step's
  action and that step's own assertions: `Check::Eval` is engine calls, so a probe after them has
  `? (…)` answered by the replacement and reports the result as this step's verdict, about a target
  the caller never named. `run_step` takes the reading and the seal now and hands the reading back,
  so there is one probe per step rather than two and no gap between them. What is left is inside a
  single engine call, which nothing in this process can observe until it returns — the same
  residual `refuse_a_break_for_a_replaced_target` documents, and the bound rather than the next
  round's finding.
- **And a moved selection is not a replacement, which the first version of that said it was.** A
  report keys the caller's next move off the difference: a replaced target retires this session's
  handle through the post-op fingerprint check, while a moved selection leaves it good — so
  reporting the second as the first told a caller their session was finished when it was not.
  `BatchTarget::moved` answers `Held::Replaced` or `Held::Uncertain` rather than a sentence, the
  outcome and the session state follow it, and `Held::Uncertain` is now *"cannot certify, and the
  session is not going away"* rather than *"the engine would not say"* — two causes under one
  answer, with the sentence saying which. Raised by Codex, along with the seal that was still a
  loop away from the detection that needed it, and two model-facing promises this had missed: the
  `always` field's own description, which is served in the input schema, and the shipped plugin
  skill, both still saying cleanup runs on every path.
- **Two more from the same review, both about what "the same target" means to a *writer*.** The
  identity probe was the one call into the host outside `guarded`, so a panic in any of its four
  engine queries would have unwound past the `always` block and the seal — the rollback loss
  `guarded` exists to prevent, arriving through the check added to prevent a worse one; it answers
  `Held::Uncertain` now, which withholds and reports rather than vanishing. And the *fingerprint* is
  the wrong granularity for this caller: it carries the process **set** and deliberately not the
  selection, which is right for a handle and not for a batch, since `eb <addr>` writes into
  DbgEng's current process — so on a session holding two user-mode processes a step that moves the
  selection would have had its restore applied in the other address space, with the session
  holding exactly the target it always did. `BatchTarget` is the batch's own baseline, and it
  stops at the line worth stating: the current **thread** is not in it, because a thread moves at
  every stop and that is what a `resume` step is for.
- **A batch that stops still has to close itself to breaks, and the first version stopped doing
  it.** Skipping the seal on the replaced path looked free — there is no cleanup left for a break
  to cut short — and the thing it left open is not this job's work but the *engine*: `SetInterrupt`
  acts on whatever it is holding, the worker's own latch is not published until the op **ends**, so
  between the batch seeing the replacement and the worker saying so, `refuse_a_break_for_a_replaced_target`
  lets an interrupt straight through to somebody else's target — a live kernel, in the case that
  matters. Raised by Codex in review. The seal is unconditional now, with the reason as an argument
  (`batch::Sealed`, `worker::Cleanup::TargetLost`), and the refusal a caller reads says which of the
  two it is — a rollback that must finish, or a batch that is sending nothing and whose break would
  land elsewhere. Deleting the `if` is the fix rather than adding a second call: what went wrong was
  that the call was conditional at all.
- **"The engine would not say" is a third answer, and the first version spelled it as the first.**
  Raised by Codex in review, and correct: `has_target` failing came back as `None` from a function
  returning `Option`, which the executor could not tell from *nothing has changed* — so a step that
  swapped the target while the engine went quiet would have had its cleanup run against the
  replacement anyway, and a batch whose *baseline* could not be read checked nothing for its whole
  length. dbgscope says the same thing from the other end, on `has_target` itself: *"an unreadable
  status is not an answer, and this does not collapse one into `true`: what to do when the engine
  cannot be asked differs by caller, and each one below decides."* So `Held` has three values,
  `Held::Uncertain` withholds the cleanup under its own outcome (`BatchOutcome::TargetUncertain`,
  which claims no second target because none was identified), and a batch that cannot read a
  baseline **before its first step is refused outright** — nothing run, nothing changed,
  resubmitting safe, which is the one answer that costs the caller a retry rather than a write.

  **The two halves of the mechanism now decide this reading differently, deliberately.** The
  handle half retires nothing on an engine that will not answer (`worker::replacement_now`), and
  the batch withholds. Same predicate, different price: a wrong retirement costs a caller one
  re-open, a wrong restore costs whatever that address means in somebody else's target. And the
  argument that makes `Uncertain` rare is the same one that makes withholding cheap — an engine that
  cannot answer `GetExecutionStatus`, an engine-local call that never reaches the wire, was
  unlikely to execute the restore either.

**What it rests on, and what it therefore does not close.** The reading is item 81's fingerprint,
which maps every query's error to `None` — the same value a field takes when the question does not
apply to that target kind. So two *failures* of one query compare equal and a swap only that field
would have caught goes unseen, and a query that recovers reads as a replacement that did not
happen. Raised by Codex in review, and half-closed here: a batch will not start against a reading
whose `kind` is missing (`worker::usable_baseline`), that being the field which decides which of
the others are even asked for. The rest is `FOLLOWUPS.md` **item 104**, because the error cannot
be read to tell "does not apply" from "could not be read" — DbgEng answers `E_UNEXPECTED` to both —
so it needs a per-target-kind table of required fields, which is the claim `TargetFingerprint`'s
doc records as having been wrong three review rounds running, and a decision per caller besides.
Filing it was the proportionate move for the same reason this item was not folded into item 81: it
is a change to a type both halves share and deserves its own review.

**But the third round on that seam was about the field *this* item added, and that one is closed
rather than filed.** A batch measures the current process beside the fingerprint
(`worker::BatchTarget`, added two rounds earlier because `eb <addr>` writes into DbgEng's *current*
process), and it was read with the same `.ok()` — so a refused query and a question that does not
apply were again one `None`, two refusals compared equal, and a step that moved the selection
between two held processes while that query was failing read as nothing having happened. The hazard
the field was added for, reintroduced by how the field was read; raised by Codex on the rebased
head. It is `worker::Selection` now — `NotAsked` / `Process` / `Refused` — with `usable_baseline`
refusing a baseline whose selection was refused and `BatchTarget::moved` answering
`Held::Uncertain` on one that arrives mid-batch, worded as *"would not say which process"* rather
than as a selection that moved, which is a claim about the target there is no evidence for.
**Why this one did not have to go to item 104:** both things that make the fingerprint's four
fields undecidable are absent here. Whether the question applies is a **gate in the code**
(`fingerprints_the_process`, on the kind) rather than an inference from an `E_UNEXPECTED` that
spells two things; and the refusal is narrowed to the only shape in which a selection can
misdirect a write — a session holding **more than one** process — since one holding a single
process has nowhere else for a write to land, so the refusal is accepted there and costs nothing.
That narrowing is also what makes the refusal affordable on kinds this bench cannot measure: a TTD
trace holds one process and takes the accepted arm, which matters because replay does not run here
at all (issue #132). Measured with the gate in place: 1,080 unit and 126 smoke tests, dump tier on,
nothing refused that used to run.

**What measuring it disproved — the item's own example.** Every draft of this entry, and the
paragraph in `CLAUDE.md`-adjacent prose that came with item 81, illustrated a replacement with
`.if (1) { .opendump C:\other.dmp }`. Driven live against the dev build over stdio (dbgeng
10.0.26100.1742, ARM64, 2026-09-26) that command does **not** replace anything: `||` afterwards
lists two systems with the original still current, and `? @$ip`, `version` and `lm` all still
answer from it, so the fingerprint reads the current system and correctly says nothing has changed.
`.opendump` *adds* a target; switching to it is what would replace one, and `||1s` through
`ExecuteWide` fails here with `0x80040205`. What does reproduce it, end to end, is a wrapped
`.create` on a launched process — and it is caught at the **`g`**, not at the `.create`, because
the command only arms the creation (*"Create will proceed with next execution"*). The live run
reported `TARGET REPLACED at step 3`, `rollback: NOT ATTEMPTED`, the cleanup listed as skipped with
its reason, **DETACHED/REPLACED by `g`**, and item 81's supervisor retirement firing at the end of
the same op — the two halves agreeing about one event. `end_session` still worked on the retired
handle (item 55) and the launched process did not outlive it.

**Mutation-verified, and the first attempt at stating that was wrong too.** Moving the check to the
top of the loop, beside `abandoned` and `interrupted`, fails **both** replacement tests rather than
the one the comment first claimed, and fails them differently: the two-step batch comes back
`Committed` with its restore written into the new target, having no later step for such a check to
catch it at, while the three-step batch stops at the wrong step and names `lm` as what took the
target. Making the scripted host report a replacement for a target that has *gone* fails exactly
the test that pins that rule and no other.

**What it cost the surface.** The tool description owes two more sentences, so `debug_batch` goes
10,021 → 10,405 model-visible bytes (+384, still under the 11,200 ceiling) and the whole surface
94,971 → 95,355. The output schema grows 3,223 → 3,521 for the `rollback` field and the new outcome
name. Re-recorded in `tests/golden/tool_budget.json`; the group and spec tables in
`src/toolset.rs`, `docs/tool-surface.md` and `docs/token-budget.md` move with it, and three shares
round differently. Worth noting while re-deriving them: the *prose* totals in `README.md`,
`src/toolset.rs` and `docs/remote-listener.md` were already 50 B behind the served surface before
this change (94,921 against 94,971), which is what "prose is not swept" buys and costs.

**Where it picked up.** `batch::run`'s between-steps checks, `batch::Held`,
`batch::Debuggee::replaced`, `BatchOutcome::TargetReplaced`/`TargetUncertain`,
`BatchReport::unverified` and `BatchReport::rollback` in `src/batch.rs`; `BatchEngine`,
`batch_baseline`, `held_now` and `run_batch`'s baseline refusal in `src/worker.rs`;
`BatchOutcomeName` and `RollbackDisposition` in `src/structured.rs`; the batch verdict's rendering
in `src/cast.rs`; `docs/debug-batch.md`, which states the rollback contract.

## 103. [windbg-mcp] H5b — expose the Secure Kernel reads, without forcing them through DbgEng — **done** (2026-10-02)

**Repo:** `windbg-mcp`. **Origin:** the H5 route decision in
[`docs/secure-kernel/secure-kernel-hypercall-feasibility.md`](docs/secure-kernel/secure-kernel-hypercall-feasibility.md),
2026-09-26. H0–H4 passed: a root partition can read a VBS guest's VTL1 and `securekernel.exe`,
`KdDebuggerDataBlock` and `SkLoadedModuleList` were all located and identified. H5a — driving
DbgEng through EXDI — is parked behind a two-part reversal condition, so this is the route.

### Closed 2026-10-02 — and what decided it was the *route*, not the deliverable

**The deliverable never decided this item, and two drafts of its status were wrong about that in
opposite directions** — one closed it on the strength of the four tools, one recast an
already-agreed constraint as a refusal. The status restatement of 2026-10-01 corrected both and left
it **open on named unmade attempts**, which was right. What closes it is that those attempts were
made, and that what they measured settles where the *remaining* ones belong.

**What shipped, and is verified live.** Gates S0–S5x. Secure Kernel modules, symbols and memory off a
Hyper-V checkpoint through four MCP tools, with no driver and no debuggee and DbgEng appearing only
as gate S2's image-symbol server. Since gate S5w the same decode also runs against a **live** guest
through `--sk-live`, over a transport the operator supplies: 11,819 leaf mappings, `securekernel.exe`
identified, six VTL1 modules, 12,375 reads and 50,688,000 bytes with nothing failed (run of
2026-10-01; a re-run the next day reported 11,820 leaves over **4,318** distinct pages, with every
landmark identical — see S5w, where the two readings sit side by side). VTL1 kernel
memory is **fully readable and writable** from the root — read by two routes and written by two, the
second of which this entry had recorded as broken until S5u retracted that.

**What the attempts settled about VTL1 kernel-mode control, which is the question this item kept
running into.** Inspection is complete; **execution control over a real guest's Secure Kernel is
not, and the blocker is the catch rather than the patch.** Planting a breakpoint byte in
`securekernel.exe`'s own `.text` now has two proven routes. Delivering the resulting trap has none on
a VM Hyper-V manages: S5a settled that Secure Kernel has nothing to connect to the hypervisor's live
VTL1 debug port with — no debug hypercall, no `vmcall`, no SynDbg MSR, across ten builds — and S5n/S5o
settled that a managed partition's receive loop cannot be owned from user mode, because the gate
admits the partition's **creator**. S5h's catch and S5t's full replication of the published IUM
capability are both **VTL1 user mode**, which is not VTL1 kernel mode.

**So the realistic route to a controlled stop, step and catch is to own the boot, and that is item
110.** The owner-partition probe already stops, holds, completes and resumes real `securekernel.exe`
image code at **VTL1 CPL0** on a partition of our own, from user mode with no driver; what it does not
have is an *initialized* Secure Kernel runtime, and acquiring one is 110's whole subject. Gate S5v
moved the cost of that materially: 20 of the 24 device-model COM classes activate outside `vmwp.exe`,
at medium integrity, so reusing Hyper-V's device model is plausible for construction rather than a
9.9 MB rewrite.

#### The four attempts that were still open, and where each one went

1. **`sk_symbol`'s qualified-name wart → item 107.** A *qualified* `securekernel!Sym` is resolved by
   a lenient engine and reported as `securekernel!securekernel!Sym` — the right address with a doubled
   rendering. It is the family item 107 is about, a surface accepting what its contract excludes and
   answering `status: ok`, and the judgement it needs (strip a redundant qualifier, or refuse a
   foreign one) is 107's to make across the surface rather than this item's to make for one tool.
2. **The `VidHandleExceptionIntercept` branch decompile → item 110.** It is the one route to *which*
   branch a delivered message took, which sampling cannot supply at any cadence, and 110 arms its own
   intercepts on its own partition — so it is the item that will need the answer.
3. **The `[partition+0x10]` writer census — declined.** Its only remaining purpose was chaining on a
   **managed** VM, which is the route the measurements above rule out: owning that receive loop needs
   kernel mode, which means a driver this repo does not ship, to reach a capability 110 already has
   from user mode on a partition it creates. **Reopens if** a managed-VM retrofit becomes the cheaper
   route — concretely, if item 110's owned-boot route fails on something the device model or the guest
   OS cannot supply.
4. **Separating the partition reset's two causes — declined, with the same condition.** It asks
   whether *be `vmwp` and read* is safe as a standing capability, and it is a question about the
   managed-VM route only: on its **own** partition the probe arms, maps, drains and completes with the
   guest monotonic, so arming is survivable, and the managed-VM reset points at the 64 stolen
   messages. **Reopens with (3)**, and also if anything here ever needs to arm an intercept on a
   partition it did not create — which is the operation that hard-reset both lab guests.

**Both declines are declines of a *route*, not of the item**, and they are recorded here rather than
keeping the item open because nothing about them is waiting on this entry: the capability they would
have served exists on the owned-partition route, and the condition that would reverse them is a
failure of item 110. An earlier draft of this entry relocated all four arms to 110 as "control-axis"
work; that was wrong at the time because closing the remaining gaps was part of this item's goal and
the arms had not been measured. The difference now is that they have — two of them are answered by
being on a route that is not taken, and exactly one is moved to the item that needs it.

**What is deliberately not carried forward.** H5a — driving DbgEng through EXDI — stays parked on
E2's lab condition: it needs a host whose hypervisor slot is free, which is a different type of lab
rather than a redesign, and measuring the stub's three inputs was never its reversal condition. The
*Out of scope* line above stands as written.

### Status 2026-10-01 — the capture route is built and verified; the item stays **open** on attempts not yet made

**What landed.** Gates S0–S4 are run; S1–S3 are built and shipped as four tools —
`open_sk_capture`, `sk_modules`, `sk_symbol`, `sk_read_memory` — behind an opt-in capture tier.
Secure Kernel modules, symbols and memory are readable from a Hyper-V checkpoint with **no driver
and no debuggee**, DbgEng appearing only as gate S2's image-symbol server and never in the path of a
read.

**Why that does not close the item.** Part of what this item is for is closing the *remaining* gaps,
and several of the attempts its own plan names **have not been made**. A shipped deliverable does
not close them and does not make them refusable: each is a run somebody has yet to do, and the
unmade-attempt list at the end of this section is the current state of it. A draft of this section
closed the item on the strength of the four tools and recast the remainder as two refusals — wrongly
on both counts, and the specific errors are recorded there rather than deleted, because the second
one inverted a decision this entry had already taken in favour.

**Re-verified end to end on 2026-10-01 through the registered stdio server**, against three
checkpoints on this bench rather than against this entry's own figures:

- **Positive arm**, the pinned VBS+HVCI checkpoint: VTL1 root `0x107593000` read *from the capture*,
  self-map at [309], 29 present entries, a complete walk over 4,545 distinct pages from 179 table
  reads, 1 of 7 PE headers matching `C:\Windows\System32\securekernel.exe` (10.0.26100.9457,
  1,385,944 bytes), `KdDebuggerDataBlock` at `0xfffff8070eedc5e0` `Size` `0x3a0`,
  `SkLoadedModuleList` at `0xfffff8070eed0770` with 6 entries, the structural cross-check agreeing
  with the block over 1,249 pages, and 18,253 reads of which 0 failed and 0 were refused.
  `sk_modules` named all six VTL1 modules — `securekernel.exe`, `skci.dll`, `symcryptk.dll`,
  `cng.sys`, `vmsvc.dll`, `vmsvcext.sys` — and `sk_read_memory` returned the `MZ` header at the SK
  base with its GPA beside it.
- **Control arm**, the VBS-off twin: partition VTLs `0x1`, `ForceActiveVirtualTrustLevel(vp0, vtl1)`
  refused as `0xC0370509`, and the session reports that limitation instead of answering — so the
  positive arm is *discriminated* rather than merely obtained.
- **Symbols**, on a third checkpoint of the VBS guest: PDB `C2C0D1A62E3269F40C69EA44FDB230C4` age 1
  loaded against the image at preferred base `0x140000000`, with both landmarks agreeing with the
  decode in both directions — `KdDebuggerDataBlock` RVA `0x1335e0` and `SkLoadedModuleList` RVA
  `0x127770`, each also named by the engine. The four type probes still answer 0 of 4, which is
  gate S2's measured finding about a public PDB rather than a regression.
- **Green the same day**: 1,101 unit tests and 130 `mcp_smoke` tests, with
  `cargo clippy --all-targets -- -D warnings` clean, plus both opt-in Secure Kernel gates —
  `sksym` 7/7 with the engine beside the test binary, and
  `a_secure_kernel_capture_opens_as_a_session_and_answers_about_its_vtl1` against a real `.vmrs` in
  16.67s.

**That third checkpoint re-broke the landmark S0 warned about, in a sharper form.** It carries root
`0x1201000` — the same *value* S0's first capture had — with self-map index **434** against S0's
**388**, and `securekernel.exe` at GPA `0x0000000000cd1000` against S0's `0x00cd0000`. A differing
layout means a different boot, so the `CR3` **value** recurs across boots while the address space
behind it does not: matching on that value alone would have read as the same capture. S0 established
that the root is not reboot-stable; this adds that it is not even *distinguishing*, which is why
reading it from the capture every time is the contract rather than a precaution.

#### The operator-supplied transport is a setup step, and the live source behind it is simply unattempted

**This is the item's own first constraint and it is not in question.** The repo distributes **no
driver**; the operator supplies the transport; and once it is in place *the rest is drivable from
it*. That is an install step and a security-posture note to write down, exactly as the live-kernel
tier needs KDNET wiring and a local profile and the engine bundle needs a one-time copy. **A draft of
this section recast that constraint as a refusal — "declined on cost-to-audience", then "declined on
the transport's scope" — and both were wrong**: nobody proposed this repo ship a driver, so no
decision about shipping one was ever open, and the `vmwp.exe` handle-duplication decline dragged in to
support it is S5n's scope call about reaching a partition we do **not** own, which is a different
route from the one this constraint describes.

**The code is already built for it, which is why this is an attempt rather than a design question.**
S1's decode layer takes the byte source as a parameter: [`sk::RawSource`](src/sk.rs) (`src/sk.rs:312`)
is three methods — `shape()` for what the source knows about the processor, `max_read()` for its
transfer width, and `read_chunk()` returning `Result<(), ReadFailure>` — `savedstate` implements it
for a capture, and the trait's own doc says in terms that *"a future driver-backed live source joins
here and changes nothing above it"*. The seam was built knowing the live source's shape: `max_read()`
exists because `HvCallReadGpa` moves at most 16 bytes, and **`ReadFailure::Refused` exists *for* the
live case**, because H4 measured that call answering `HV_STATUS_SUCCESS` with zeros and a per-access
`ReadIntercept`.

**So what is unattempted is an implementation.** No `RawSource` has been written against an
operator-supplied transport, so `ReadFailure::Refused` has never been produced by a real source — it
is fixture-only — and the two consequences S3 named are untested: the session stops being a fixed
snapshot, which is the premise `open_sk_capture`'s decode-on-open rests on, and `sk_read_memory`
acquires a target that can change between two reads.

**And live VTL1 access is not hypothetical — two gates reached it on 2026-09-29**, which is what makes
the remaining work an implementation rather than a question:

- **S5s** — LiveCloudKd's **passive** EXDI CLSID `{53838F70-0936-44A9-AB4E-ABB568401508}` is a working
  live *inspector*. `db 0xFFFFF80629B4A000 L10` reads `4d 5a 90 00 …` (`MZ`) on the VBS guest and all
  zeros on the VBS-off twin at the same address; `.reload /f securekernel.exe=…` gives `securekernel`
  with **PDB symbols** over `0xFFFFF80629B4A000`–`0xFFFFF80629CBF000`; `.writemem` took the whole
  1,527,808-byte image out of live VTL1. No driver and no test-signing. It has **no execution
  control** — `IeXdiControlComponentFunctions` is `0x80004002`.
- **S5r** — a live VTL1 **user-mode stop and resume**. After one byte at `securekernel.exe+0x1434E`
  (`0x75`→`0xEB`, the `jne` guarding `SkpsEnableDebugging` inside `IumInvokeSecureService`),
  `DebugActiveProcess` against the trustlet `LsaIso.exe` (pid 928) returned `True`, delivered
  `CREATE_PROCESS_DEBUG_EVENT`, five module loads and then `EXCEPTION_BREAKPOINT` `0x80000003` at
  `0x7FFE381E3AB0` on tid 4432 — an `int 3` executed in VTL1 user mode, caught in VTL0 and continued
  with `DBG_CONTINUE`; detached cleanly, trustlet alive. **A-B-A**: `ERROR_ACCESS_DENIED (5)` before
  the patch and again after the restore, which is what makes the middle arm a result.

#### EXDI stays out, and the reason is the lab rather than a judgement made here

**A custom EXDI setup is out of the question because it rests on a completely different type of
lab.** That is E2's recorded stop condition rather than a new decision: a host whose hypervisor slot
is already taken leaves no backend that both exposes a gdbstub *and* can host a VBS guest, so the
nested-SLAT assumption never gets tested — *"the answer is a second host rather than a redesign"*.
This bench is that host: Hyper-V owns the box, and a VMware guest under WHP loses its VBS. So the
*Out of scope* line below — *"H5a / EXDI: parked with its two-part reversal condition recorded. Not
re-litigated here"* — stands exactly as written, and this section adds no analysis to it.

**One correction worth keeping, because it is what went wrong.** An ordered EXDI route had
accumulated inside this entry, with a late section restating the item's goal as *"DbgEng inspecting
`securekernel`"* — contradicting this entry's own title and the *Out of scope* line. The cause was
that H5a's three inputs each got measured while H5b was being built (H3 for VTL1 registers, H4 for
VTL1 memory, E1 for how DbgEng locates a kernel over EXDI), and that was read as the parking
decision lapsing. **It is not**: H5a's two-part reversal condition is about the lab, and measuring
the inputs is not it. The design detail stays in
[`docs/secure-kernel/exdi-stub-plan.md`](docs/secure-kernel/exdi-stub-plan.md) as a plan.

#### The attempts the plan names — four were made on 2026-10-01, and four keep this item open

In rough order of cost, and none of them refused. **Still open: attempt 4 and the three arms under attempt 5.**
Two of the four that landed came back as **retractions of this entry's own claims** rather than as
confirmations, which is the more useful outcome and the reason the superseded wording is struck through
rather than deleted.

1. ~~**A `RawSource` against an operator-supplied live transport**, and with it the first real
   `ReadFailure::Refused`, plus whatever the two S3 consequences cost the session model.~~
   **DONE 2026-10-01 as S5w and S5x — all three halves.** `src/livesrc.rs` implements the trait over a
   **child process speaking a line protocol on its stdio**, so what this repository gains is the
   *client* and the operator still supplies the transport; `windbg-mcp --sk-live --transport
   "<command>" --image <path>` drives gate S1's whole decode through it. Against the **running** VBS
   guest it reports what a capture reports — figures from the run of 2026-10-01, which S5w pairs with
   a re-run that moved them: root `0x1201000`, a complete walk of **11,819 leaf
   mappings over 4,229 distinct pages**, `securekernel.exe` identified at `0xFFFFF8024278A000` with 4
   `KDBG` hits and three other PE headers rejected, `KdDebuggerDataBlock` at base `+0x1335E0`,
   `SkLoadedModuleList` at base `+0x127770`, and **six VTL1 modules** — over **12,375 reads and
   50,688,000 bytes with nothing failed**. A second transport mode drives `HvCallReadGpa` instead, at
   its real `max_read` of **16**, and produces **`Refused { detail: "ReadIntercept(2)" }`** — the
   first time that variant has come from a source rather than a fixture — with `refused: 2` in
   `ReadStats` and the decode declining to claim the negative: *"this run identified nothing while 2
   read(s) failed, so its negative has not been earned."* **The two S3 consequences are measured
   rather than assumed**, which is why `--sk-live` is a command-line role and **not** a fifth MCP
   tool: one of the image's 373 pages changed in 20 seconds — 2 bytes, in **`.data`** — while 1,200
   sampled non-image pages and every landmark were byte-identical, so decode-on-open is unsound in
   principle for a live source and `sk_read_memory`'s bytes are not guaranteed between two reads.
   Fifteen unit tests cover the framing against in-memory pipes.
2. ~~**The three operations the IUM write-up claims *on top of* attach.**~~ **DONE 2026-10-01 as S5t,
   and all four pass, single-stepping included.** S5r had replicated only the *access*; what it left
   unexercised were breakpoints at a chosen address, register read and register write. On the same
   gate (`securekernel.exe+0x1434E`, patched in **memory** by guest-physical write and restored),
   against `LsaIso.exe` pid 924 on the VBS guest, under A-B-A control:
   `ReadProcessMemory` walked the **trustlet's own** PE export directory to resolve
   `ntdll!DbgUiRemoteBreakin` = `0x7FF888215B90`; `VirtualProtectEx` reported old protection `0x20`
   and `WriteProcessMemory` planted one `0xCC` there, **read back `0xCC`** — the permission nothing
   had tested; `GetThreadContext` read `RIP` = `0x7FF888203AB1`; `SetThreadContext` redirected it to
   the planted address; and the next event was `EXCEPTION_BREAKPOINT` `0x80000003` at
   **`0x7FF888215B90`** — *our* address — with `RIP` = `0x7FF888215B91`, exactly address + 1. Byte
   and `RIP` restored and verified, detached, trustlet alive, guest uptime monotonic. Arms A and C
   with the gate closed both gave `ERROR_ACCESS_DENIED (5)`. **A second arm the same day added
   single-stepping, so every clause of the published capability is now reproduced**: `EFLAGS.TF`
   armed `0x246`→`0x346`, two `EXCEPTION_SINGLE_STEP` (`0x80000004`) events at `0x7FF888215B94` then
   `0x7FF888215B9D` — advances of 4 and 9 bytes, matching `sub rsp,0x28` and `mov rax,gs:[0x60]` as
   read from this host's `ntdll` — with `TF` self-cleared by each trap. **That arm also crashed the
   trustlet, through a defect in the harness rather than the technique**: it restored `RIP` without
   `RSP` after stepping that `sub rsp,0x28`, so `DbgBreakPoint`'s `ret` popped garbage and WER logged
   `IUMTrustletCrash` for `lsaiso.exe` twice. The guest survived (uptime monotonic, `lsass` alive,
   `Secure System` running) but `LsaIso` did not restart, so that arm had no post-restore control.
   **Re-run on a rebooted guest the same day, with all three harness defects fixed, and it is clean**
   — `LsaIso` pid 908, every address re-derived (SK rebased to `0xFFFFF8024278A000`, the target to
   `0x7FF8EC595B90`), `VirtualProtectEx` reading the correct original `0x20` where the leak had shown
   `0x40`, `RESTORE_FULL_CONTEXT` verified by read-back, protection restored, the trustlet **alive at
   1, 3 and 6 seconds**, Arm C refusing with `ERROR_ACCESS_DENIED (5)` on that **same pid**, and
   **zero `IUMTrustletCrash` events since that boot**. So attempt 2 is **done**, and what it leaves is
   the limit rather than a gap: VTL1 *user* mode only, one build, one trustlet. Full
   figures in the **S5t result** section of
   [`docs/secure-kernel/secure-kernel-hypercall-feasibility.md`](docs/secure-kernel/secure-kernel-hypercall-feasibility.md);
   instruments are **operator-supplied and outside this repository**, like the driver — a host-side
   driver and a guest-side debugger in the `h3probe` bench, which this repo neither ships nor tracks.
3. ~~**The write-path hazard S5r hit, unexplained.**~~ **DONE 2026-10-01 as S5u, and the answer is a
   retraction rather than an explanation.** The claim was that `SdkWriteVirtualMemory` segfaults on a
   VTL1 virtual address because *"the virtual read path handles the Secure Kernel context and the
   virtual write path does not"*. **It does not segfault and it does handle it.** Four arms — {VTL0 NT
   kernel, VTL1 Secure Kernel} × {PE header page, executable `.text` page} — each **mutate** a byte and
   read it back through the *physical* route at a GPA walked from Secure Kernel's own `CR3` (validated
   against the virtual read before anything is written, and restored through that route in a
   `finally`). All four land; three runs, 12 of 12. The VTL0 arms are the control the original lacked,
   and the VTL1 `.text` arm is the gate's own page class, so "an executable VTL1 page is refused" is
   closed rather than assumed. A null or stale partition handle — the other candidate, since S5r ran
   when `s5r_patch.py` still carried `TARGET_PARTITION_ID = 3` — returns `False` cleanly both
   directions with no fault.
   **The fault that was blamed on it is this bench's own**: `hvlib.py`'s `CfgParameters` declares
   **12** fields and 48 bytes where `HvlibEnumPublic.h`'s `VM_OPERATIONS_CONFIG` has **17** and 56, so
   every `SdkGetDefaultConfig` through that binding writes **8 bytes past a Python allocation**, and
   the process dies wherever the garbage collector next walks it — `python -X faulthandler` reports it
   as `Garbage-collecting`, in a different place in every script. Declaring all seventeen fields makes
   it go away: the long-running transport of attempt 1 was dying inside `EnumPartitions` and now
   serves 12,375 reads and exits zero. Three consequences recorded with it: **an exit code of
   `0xC0000005` from any probe here says nothing about what the probe was doing**, which is exactly how
   this claim was arrived at; *"every run ends in an hvlib unload segfault"* is wrong in both
   directions (a single-call probe exits zero 6 of 6, and `s5r_patch.py read` was seen clean once in
   seven); and five flags including **`VSMScan`** have never been settable from this bench. **S5t is
   unaffected** — it patched physically and verified by read-back — and what changes is only the
   *reason* recorded for that choice: the physical route was sound and was never forced.
4. **`sk_symbol`'s qualified-name wart**, below: measured, cheap, and not fixed.
5. **Three arms that are this item's, not item 110's** — a draft moved four of them there as
   "control-axis" and that was wrong, since closing the remaining gaps is part of what this item is
   for. The fourth, the **`CoCreateInstance` probe**, is **DONE 2026-10-01 as S5v**: 20 of the 24
   device-model CLSIDs activate with `CLSCTX_INPROC_SERVER` and `IID_IUnknown` outside `vmwp.exe`, no
   faults, with a positive and a negative control either side; the 4 refusals are
   `CLASS_E_CLASSNOTAVAILABLE` from a module that **does** load first and whose image carries none of
   their GUIDs, so they are a registration naming a module that never implemented them. Each object
   refcounts to zero and dispatches `QueryInterface`. **And it is not admin-gated** — `BiosVdev`
   activates at medium integrity with no `Administrators` membership — so *process context can decide
   it* is answered **no** for construction. It removes the next obstacle and does not establish tier B:
   the private interfaces' IIDs are still unread. The three that remain are written out in the route
   section below: the **`[partition+0x10]` writer census**, the **`VidHandleExceptionIntercept` branch
   decompile**, and **separating the reset's two causes**. Item 110 keeps only what needs an owned
   Windows/VBS boot, plus the VTL1 state write with a message pending.

**One wart found while verifying, recorded rather than fixed.** `sk_symbol`'s `name` is documented
unqualified, the module being applied here — so a *qualified*
`securekernel!SkdInitDebuggerDataBlock` is resolved anyway by a lenient engine and reported as
`securekernel!securekernel!SkdInitDebuggerDataBlock`: the right address with a doubled rendering.
The identifier fields (`address`, `rva`, `engine_address`) are byte-identical to the unqualified
call, so nothing downstream is wrong; what is wrong is the one field a caller would quote back. It
is the family item 107 is about — a surface accepting what its contract excludes and answering
`status: ok` — and the remedy is not simply "strip the qualifier", because a *foreign* one such as
`skci!Foo` should be refused rather than doubled, and which of those two this tool owes is a
judgement nothing here has made.

**One setup constraint, one open question, and two capabilities — an earlier draft of this item
overstated the first two into blockers and got the third wrong.**

- **The driver is a setup cost, not a shipping blocker.** It remains true that no such driver can
  be WHQL-signed and that every alternative makes the operator reconfigure their machine. What does
  **not** follow is that nothing ships: this repo already ships capabilities behind documented
  manual setup — the live-kernel tier needs KDNET wiring and a local profile, and the engine bundle
  needs a one-time copy. So H5b ships as an **opt-in research feature with manual steps**, where the
  repo distributes no driver and the operator supplies the transport. That is an install step and a
  security-posture note to write down, not a reason to build less. **Once it is in place, the rest
  is drivable from it.** And **S0 has since found that most users will not need it at all**: a
  Hyper-V saved state carries VTL1 and its page-table root with no driver in the picture, so the
  operator-supplied transport is what buys a *live* target rather than what buys access.
- **Execution control is an open question, and the hypervisor half of it already works.** What is
  established is narrower than "there is none": post-26100 `securekernel.exe` ships no KD transport
  **of its own**, every `Kd`-prefixed symbol in it being data. The **hypervisor's** VTL1 debug
  machinery is a separate thing and is **initialised**: its activation failure was identified
  (`0x1D`, debug free-page list exhausted), raising `hypervisordebugpages` resolved it, and active
  port `0xC35C` (50012) with both buffers allocated proves the allocations completed. **What is
  unresolved is Secure Kernel-side attachment** — a working port with nothing on the guest side
  connecting to it, which sits uncomfortably beside SK shipping no KD transport and may be the same
  wall. The validation record declines the stronger claim in terms: *"They do not establish that
  this Windows build lacks Secure Kernel debugging support."* So stepping is **an item to settle**
  (S5), starting at attachment rather than at activation.
- **Writes: measured by S4 on 2026-09-26, and the answer differs per route.** An earlier draft of
  this item asserted VTL1 was patchable from the existence of a wrapper; the ABI argued otherwise
  (`HV_ACCESS_GPA_RESULT_CODE` defines `HvAccessGpaWriteIntercept` (3) beside the `ReadIntercept`
  (2) H4 measured), and the ABI was right. **`HvCallWriteGpa` writes VTL0 and is refused on VTL1
  with `WriteIntercept`** — symmetric with the read, and with `HV_STATUS` reading `SUCCESS` on the
  refusal, so a refused write looks like one that landed. **The direct route writes VTL1** —
  differing bytes landed in `securekernel.exe`'s `.text` padding and read back, then restored. So
  VTL1 is fully read/write from the root by that route and refused both directions by the
  hypercall, and the **patch** half of a software breakpoint is solved while the **catch** half
  (S5) is not. **S5h has since measured a catch for VTL1 *user* mode** — a parent-installed exception
  intercept holds a `#BP` raised there and hands it back on removal, and **S5i has since read the
  hypervisor and found that intercept applied at every enabled VTL by design**. **Step 9's arm has
  since measured that the root receives a stop raised in VTL0** — a `#BP` raised there under a
  standing raw intercept arrives at `Vid!VidInterceptPreprocess`, which copies the message, stamps
  the VP and selects `VidHandleExceptionIntercept`. So a receiver exists **for the VTL0 stop**, and
  that is the whole of what is measured: the *catch* half is not closed generally, because the stop
  S5h held was a **VTL1** raise and step 9's arm did not read the markers for one. Whether any of it
  reaches Secure Kernel's own code remains an architectural inference after S5i rather than an open
  mechanism, because VTL1 user mode is not VTL1 kernel mode.
  **A route to VTL1 KERNEL mode is now open at the hypervisor, measured 2026-09-30**: enabling VTL1
  on a VP takes a caller-supplied 224-byte entry context, `Vid.sys` validates only the buffer
  length, and the hypervisor refuses on VTL **state** (`STATUS_HV_VTL_ALREADY_ENABLED` /
  `STATUS_HV_INVALID_VTL_STATE`) rather than on the context, with no policy or measurement gate
  seen. That would run **our** code at VTL1 kernel privilege, not Microsoft's Secure Kernel. Next
  arm: **run, and the answer is no** — `WinHvEnablePartitionVtl` on the non-VBS guest returns
  `STATUS_HV_INVALID_PARAMETER` invariantly across ten flags values and both VTLs, while the same
  call on the VBS guest's partition answers differently, so the refusal is about that partition and
  mirrors VID's own `[partition+0x10] & 0x10` **creation-time capability** check. **VTL cannot be
  retrofitted**, so this needs step 8 — but only **tier A plus a VSM config**, not tier B or C: the
  ~10 MB device-model cliff is the price of booting *Windows*, and running our own code at VTL1
  kernel privilege needs no guest OS at all. See the **VTL1 kernel mode** section of
  [`docs/secure-kernel/secure-kernel-hypercall-feasibility.md`](docs/secure-kernel/secure-kernel-hypercall-feasibility.md).

### S0 — the gate that decides how much setup a user needs — **RUN 2026-09-26, PASS**

**Yes, and it is Microsoft's own.** A Hyper-V **standard checkpoint** carries the guest's VTL1 pages
*and* its VTL1 `CR3`, read through `vmsavedstatedumpprovider.dll` from the Windows SDK — a
user-mode DLL with a documented header (`VmSavedStateDump.h`) and explicit VTL support
(`GetGuestEnabledVirtualTrustLevels`, `ForceActiveVirtualTrustLevel`). No driver, no test-signing,
no hypercall, no HVCI concession; the capture is a **file**, which was copied off Hyper-V's own
directory and read there with no VM named. The probe is
[`tools/sk_savedstate_probe.py`](tools/sk_savedstate_probe.py) and the full record, with both arms
and every number, is the **S0 result** section of
[`docs/secure-kernel/secure-kernel-hypercall-feasibility.md`](docs/secure-kernel/secure-kernel-hypercall-feasibility.md).

- **Same-boot agreement with the live route, landmark for landmark**: VTL1 `CR3` `0x1201000`,
  self-map index 388, 26 present entries, 123 non-zero bytes, first present entry at `0x850`, 11,326
  leaf pages from 166 table reads, `securekernel.exe` at GPA `0x00CD0000` identified against the
  on-disk image, `KdDebuggerDataBlock` at `+0x1335E0` with `Size` `0x3A0`, `SkLoadedModuleList` at
  `+0x127770`, the same six VTL1 modules, and the same four `KDBG` tags of which one is real.
- **Control, on the VBS-off twin**: the partition reports VTL0 only,
  `ForceActiveVirtualTrustLevel(vp0, 1)` is **refused by name** —
  `VM_SAVED_STATE_DUMP_E_VP_VTL_NOT_ENABLED` (`0xC0370509`) — and the same 32768-page physical scan
  finds **more** PE images than the VBS guest — 143 against 101, and 100 against 86 on a second
  capture of the same boot — with **0** `securekernel.exe` and **0** `KDBG` tags either time.
  The header counts move because a running guest's memory does; what is stable is 1-against-0
  matching images and 4-against-0 tags. The positive arm is what makes the negative mean
  anything.
- **A third boot broke a landmark this plan believed.** An older capture of the same guest carries
  VTL1 `CR3` `0x107593000`, self-map index 309, 29 present entries and SK based at
  `0xFFFFF8070EDA9000` — while the image-relative offsets and the GPA are unchanged. So the `CR3` is
  **not** reboot-stable, `docs/secure-kernel/README.md` said it was, and the correction is now
  there. **This is the measured case for the source contract**: an implementation carrying
  `0x1201000` forward would have walked from the wrong root on that capture and not been told.

**What it changes.** Not whether H5b ships — the manual-setup route already decided that — but who
can run it: an operator with no weakened bench can now do S1–S3 against a capture, and the
driver-backed live source is kept for what a snapshot cannot do. S1's source contract is confirmed
and satisfied as written, and it gains a free differential oracle in the provider's own VA→GPA
translator, which agreed with our walk. S3's design question gets a default: the common source is a
fixed snapshot with no debuggee, so the sessionless shape is the case to design for. **S5 is
untouched** — a capture has no execution to control, and if anything that sharpens the
inspector-versus-debugger question rather than answering it. The specification as written follows.

#### S0 as specified

**Is there a driver-free memory source that contains VTL1 pages?** Everything below is the same
code with a different byte source, so this does not decide whether H5b ships — the manual-setup
route does that — but **how far the audience reaches**: a driver-free source means an operator with
no weakened bench, no test-signing and no loaded driver can use S1–S3 against a captured guest,
while a driver-only answer means every user pays the full posture cost. It is a measurement rather
than a design choice, and it is cheap, so it goes first.

The asymmetry to test, and the reason it is not obvious: **a guest kernel crash dump cannot work**,
because the guest's own NT cannot read VTL1 memory and therefore cannot write it into a dump — the
same refusal H4 measured from the outside. A **Hyper-V saved state** is written by the *host*, so
it is the candidate that could contain those pages. Whether it does is unmeasured, and what turns
on it is **the audience and the setup cost**, not whether the item ships — consistent with the
failure branch below and with the first constraint above, where the operator-supplied transport
carries S1–S3 either way.

**Two things have to come out of the source, not one.** Bytes are the obvious half; the other is the
**VTL1 page-table root**, which on the live path came from `HvCallGetVpRegisters` against a running
VP. A saved state has no VP to ask, so S0 is only a pass if the capture also yields VTL1's `CR3` —
from saved register state, or from a structure the walk can start at. Without it there is nothing
to walk *from*, and hard-coding the one measured `0x1201000` is not an answer.

- **Pass:** SK's PML4, `securekernel.exe` and the `KDBG` block are reachable from a saved state of
  the VBS guest, with no driver loaded, matching what the live path found for the same boot —
  **with the page-table root obtained from the capture** rather than carried over from a live run.
- **Control:** the same read against a saved state of the **VBS-off** guest finds no SK — H4's
  Control 1 repeated on the new source, which is what separates "read the guest" from "read
  something".
- **If it fails:** S1–S3 still ship, behind the operator-supplied transport and its documented
  setup. What changes is the install instructions and who can follow them, so write that down
  rather than treating a driver-only answer as a failure of the item.

#### S0 arm 4 — does the encryption knob cover the capture? — **RUN 2026-09-27: it does, and the provider crashes rather than refusing**

**The mitigation holds, so the verdict below stands.** With
`EncryptStateAndVmMigrationTraffic = $true`, **no VTL1 comes out** — and not because the walk found
nothing: `LoadSavedStateFile` never returns. The provider **fast-fails**, and the OS names it:
`windbg-mcp.exe 0.20.0.0`, faulting module **`vmsavedstatedumpprovider.dll 10.0.26100.7705`**,
exception **`0xC0000409`** — the status every `__fastfail` raises, whose legacy name
`STATUS_STACK_BUFFER_OVERRUN` is **not** a diagnosis — WER event name `BEX64`, fault offset
`0xD569`. Measured on **both** guests: the VBS-off control (arm 4a) and the VBS guest (arm 4b),
the second being the one that has a VTL1 to withhold.

**The control is what makes that attributable to the knob**, and it is the arm's whole rigour. A
*fresh plaintext* checkpoint of the same guest, taken minutes later on the next boot and read with
the identical command, **loads normally**: partition VTLs `0x1`, and the VTL1 switch refused with
`0xC0370509` as every plaintext control has been, exit 0. So the failure is not "a fresh capture",
not "this boot" and not the command — the one thing that differs is the setting.

**What this does not establish, and the distinction matters.** The capture is unreadable **by this
provider**; nothing here inspected its bytes, so "encrypted" is Hyper-V's claim about what it wrote
rather than something measured — an entropy reading would have been cheap and was not taken. Nor was
the encrypted checkpoint *applied*: Hyper-V presumably reads what it writes, but that is an
inference, and `Apply-VMSnapshot` is the check that would have made the capture's well-formedness a
measurement rather than an assumption. Shielded VMs are untested.

**And the arm found something it was not looking for, which is the part worth reporting.** A
**documented SDK API fast-fails on an input Microsoft's own hypervisor produced** — not a refusal,
not an `HRESULT`, a crash. **Measured under this server's own debugger**: subcode
**`0x7 FAST_FAIL_FATAL_APP_EXIT`**, the CRT's `abort`, reached from
`gsl::details::terminate` under `PartitionStateParser::GetPartitionStateVirtualProcessors` inside
`LoadSavedStateFile` — a **Guidelines Support Library contract violation** while parsing the
partition state, not a corruption check. So it is a robustness defect with a named cause: a parser
asserted on input it has no key for instead of returning an error. This entry said "the corruption
was *detected*" for one commit, reading `0xC0000409`'s name as its meaning; `src/fault.rs`'s own
`STATUS_STACK_BUFFER_OVERRUN` comment exists to stop exactly that, review caught it by citing it, and
the measurement then settled it. That `vmsavedstatedumpprovider.dll` bug was **reported to Microsoft via Feedback
Hub on 2026-09-27** and needs raising again by nobody; what remains is re-testing a later SDK against
the checked-in repro. It is a different
thing from the VBS-boundary question the arm was run to answer — which came back negative, as the
verdict says.

**It is written up as a sendable report**, in
[`docs/secure-kernel/vmsavedstatedumpprovider-crash.md`](docs/secure-kernel/vmsavedstatedumpprovider-crash.md),
and writing it moved three things the arm itself had left open:

- **The repro is twelve lines and calls one export**
  ([`tools/vmsavedstate_load_probe.py`](tools/vmsavedstate_load_probe.py)), so the defect is no
  longer stated through this server. It crashes at the **same fault offset** `0xD569` from CPython as
  from the Rust binary — two hosts sharing nothing but the DLL, which is what says the fault is the
  provider's and deterministic.
- **The trigger is specific, and a control matrix says so.** The same call **refuses** 4 MiB of
  random bytes, a truncated real capture and one with its first 512 bytes zeroed — all three
  `0x80070570` (`ERROR_FILE_CORRUPT`), no crash. So this is not a parser that dies on anything it
  dislikes; the encrypted path is the unhandled one.
- **"Encrypted" is now measured rather than Hyper-V's claim**, which the arm's own caveat said it was
  not: the two captures share the container magic `14 20 28 01` and the field at `+0x08`, while the
  payload entropy is **8.000** bits/byte against the plaintext capture's **7.246**. A well-formed
  container whose contents the provider has no key for — the case that should have been a clean
  refusal. The `Apply-VMSnapshot` check remains unrun, so Hyper-V reading what it wrote is still an
  inference.

**The bench was left as found**: both knobs back to `False`, the two pinned checkpoints intact and
the three this arm created removed, both guests running, and the pinned VBS capture re-read
afterwards to the same landmarks.

#### S0 arm 4 as specified, before it ran

**Why this arm exists.** S0's result invites the question whether a checkpoint carrying VTL1 is a
defect worth reporting to Microsoft, and the answer recorded in
[`docs/secure-kernel/secure-kernel-hypercall-feasibility.md`](docs/secure-kernel/secure-kernel-hypercall-feasibility.md)
is **no** — the SDK documents the capability, and the host is inside the TCB for a guest that is not
hardware-isolated. Part of that answer is that **Microsoft ships a mitigation for the at-rest half
and it is off on this bench**: `EncryptStateAndVmMigrationTraffic` is `False` on both lab guests. Arm
4 is the one case in that verdict that could overturn it, so it is worth running rather than
asserting: **turn the knob on and see whether VTL1 still comes out.**

**Method.** Record the guest's current `Get-VMSecurity` first — the arm changes VM configuration and
has to put it back. `Set-VMSecurity -EncryptStateAndVmMigrationTraffic $true` is **refused while the
VM runs** (measured: *"The SecuritySettingData property cannot be modified because the virtual
machine is running"*), so the sequence is: graceful shutdown, set the knob, start, take a
`CheckpointType = Standard` checkpoint, run `windbg-mcp --sk-inspect` against it, then **shut down a
second time** to revert the knob, and start again. The revert hits the same running-VM refusal as the
set, which an earlier draft of this method missed — it is **two** stop/start transitions per guest,
not one. A key protector already exists on both guests (5,207 bytes, measured 2026-09-27),
so the knob has one to use and this should need no new key material.

- **Expected pass — the boundary holds:** the provider cannot read the capture at all, and **the
  refusal names a reason at load or read**. That last clause is the whole rigour of this arm: a
  `LocateSavedStateFiles` that found nothing, a path typo or a checkpoint that was never written
  produce the same "no VTL1" as encryption working, and the first three say nothing. So the file's
  existence and plausible size are checked, and the failure has to come from `LoadSavedStateFile` or
  from the reads — not from the file not being there.
- **Finding — worth reporting, and weaker than it looks:** the provider loads it and VTL1 is still
  reachable. **That alone would not have been the finding**, because this arm runs on the owning host
  with the VM's key protector available, where a successful read is authorized decryption and says
  nothing about how the bytes are stored. What would settle *that* is the file: a payload entropy
  reading, or the same capture read on a host lacking the guardian key. Review raised this against
  the run, and the run had in fact taken the entropy reading — 8.000 bits/byte against a plaintext
  capture's 7.246 — so the conclusion stands on the file rather than on the provider.
- **The control has to be a *fresh* capture of the same workflow**, not the pinned one. An older
  checkpoint reading fine leaves "this capture is malformed or capture-specific" confounded with
  "encryption did it", and a named load error does not separate them. The run therefore took a fresh
  **plaintext** checkpoint of the same guest after reverting the knob and read it with the identical
  command; this bullet asked only for the pinned one, which review correctly called insufficient.
- **The arms differ by a boot as well as by the setting**, unavoidably, since the knob needs a power
  cycle. That is why the comparison is *whether it reads at all* rather than a value-for-value one —
  S0 already measured that the `CR3` moves across a boot while the image-relative offsets do not.
- **Cost:** **two** power cycles of a lab guest — one to set the knob, one to revert it — plus a
  checkpoint per arm, each a good fraction of the guest's RAM. The guest must be one whose
  in-guest state is expendable, which is a question for whoever owns the bench rather than an
  implementation detail.

**And one case in that verdict is already true here, which is not about Microsoft.** Reading a
checkpoint needs read access to a *file*, not the Hyper-V role — and this bench's
`D:\Hyper-V\Virtual Machines\Snapshots\<id>.vmrs` grants `BUILTIN\Users: ReadAndExecute` and
`Authenticated Users: Modify`, **inherited from `D:\`** rather than set by Hyper-V. So any
authenticated local user can read a file holding the guest's whole RAM, VTL1 included. It is a
storage-path configuration hazard rather than a product defect, it is not part of arm 4, and it
wants fixing on its own.

### S1 — the decode layer, source-agnostic — **BUILT AND RUN 2026-09-27**

**Built in Rust, in this server, and measured against a real capture.** `src/sk.rs` is the decode
layer over a `RawSource` seam (`root()` beside `read(gpa, len)`, both carrying *why* a read failed),
`src/savedstate.rs` is the Hyper-V saved-state source bound through the SDK's
`vmsavedstatedumpprovider.dll`, and `--sk-inspect` is a fourth non-server role beside
`--render-cast` that drives the two and prints a report. **Not a tool surface** — that is S3, whose
design question is still open, and a CLI role is what lets the decode be exercised without
prejudging it.

**It reproduces S0's probe on the capture it was run against, landmark for landmark**, which is what
makes it measured rather than merely self-consistent. Run against the `Lab Guest Hyper-V` checkpoint
(`H1 pinned 26200.9457 VBS+HVCI`, the **third-boot** capture) with
`--image C:\Windows\System32\securekernel.exe`: VTL1 `CR3` **`0x107593000`** read out of the capture,
root page **29 present entries** with the **self-map at index 309** and 139 non-zero bytes,
`securekernel.exe` at GPA **`0xCD0000`** and base VA **`0xFFFFF8070EDA9000`**,
`KdDebuggerDataBlock` at **`+0x1335E0`** with `Size` **`0x3A0`**, `SkLoadedModuleList` at
**`+0x127770`**, the same **six** VTL1 modules with the same sizes, and **4** `KDBG` tags of which
three are refused on `KernBase` and one accepted. Every one of those figures is S0's for this
capture, including the `215` decodes from `179` table reads. What it adds: **16,437** leaf mappings
over **4,545** distinct pages with **7,803** alias prefixes counted as unexpanded, 0 malformed
entries, 0 unreadable tables, **18,253** reads of which **0** failed, and two checks S0 did not run —
the **structural cross-check** (find the loader entry whose `DllBase` is the base, follow its
`Blink`) found head `0xFFFFF8070EED0770`, **the same address the block names**, and the
**provider's own translator** agreed with the walk on **373 of 373** pages of the image, with zero
pages mapped by one and not the other.

**The control arm refuses by name.** The same command against `Lab Guest Control`
(`H1 control 26200.9457 VBS off`) reports partition VTLs `0x1` against the VBS guest's `0x3` and
`ForceActiveVirtualTrustLevel(vp0, vtl1)` refused with `0xC0370509`
(`VM_SAVED_STATE_DUMP_E_VP_VTL_NOT_ENABLED`) — reported as the **switch** being refused rather than
as a guest with no Secure Kernel, which is the distinction `NotWalkable` exists to keep.

**34 tests, all synthetic** — 26 in `sk`, 4 in `savedstate`, 4 in `skinspect` — inside the default
`cargo test` (1,059 unit tests now, from 1,025). Six guards were **mutation-verified**: the self-map
cut, the list-confirms-the-block rule, the poison fill, whole-or-nothing reads, the large-page frame
mask, and unknown-is-not-wrong in the shape gate. The poison one **failed its mutation** and that is
the finding worth keeping: the assertion compared against the `POISON` constant the code fills with,
so changing the fill to zero moved both sides and the test passed on exactly the bug it exists for.
It asserts the literal `0xAA` now.

**What this does not establish.** The decode has been run against **one** capture, of one build, on
one host — the `0x1201000` capture S0 also used is no longer on this bench, so the reboot-moved root
is pinned by S0's record rather than re-measured here. The `.bin`/`.vsv` pair path is selected by
code and **called by nothing**, this bench never having produced a capture of that form. Nothing
here reads a *live* guest: `ReadFailure::Refused` is constructed by the fixtures alone, because a
capture has nothing to refuse with and the hypercall source that answers
`HV_STATUS_SUCCESS`-with-`ReadIntercept` is not built. And no symbol is resolved — that is S2, which
the base this now produces is the input to.

#### S1 as specified — the bulk of the work, and offline-testable

Everything H4 did, expressed over a source seam so the byte source is a parameter: the guarded
four-level page-table walk, PE identification against an on-disk image, the `KdDebuggerDataBlock`
decode, and the `SkLoadedModuleList` walk.

**The seam is not `read(gpa, len)` alone, and saying it was left a hole.** The decode cannot start
from reads: it starts from the **VTL1 page-table root**, which H4 obtained from
`HvCallGetVpRegisters` at `TargetVtl=1` — a hypercall against a **live VP**. A saved state has no
live VP to issue it on, so a source that is a captured image must either surface the saved register
state or supply the root directly. **The page-table root is therefore part of the source contract**
(`root() -> Gpa` beside `read(gpa, len)`), not something the decode layer derives. The alternative
is hard-coding the one measured `0x1201000`, which is a single build on a single boot and is
exactly what unknown 4 says not to rely on. S0 has to answer this for whatever source it finds.

**S0 answered it, and the hole this paragraph was written to close turned out to be real.** The
saved-state provider supplies the root as a register read — `GetRegisterValue` for `CR3` with the VP
forced to VTL1 — so `root()` is satisfied by the source rather than derived by the decode layer, as
specified. And a second capture of the same guest from an earlier boot carries `0x107593000`, so an
implementation that had hard-coded `0x1201000` would have walked from the wrong root on it. The
contract is measured, not argued.

**It is testable with no bench, no driver and no VM**, which is what makes it worth building even if
S0 fails — but **not with pages recorded off a live Secure Kernel.** Those are machine-specific
memory-dump material and would carry whatever guest and host state happened to be in them, and
`AGENTS.md` requires dumps and credentials to stay out of version control. Fixtures must be
**synthetic** — page tables and a PE header constructed to exercise each rule — or demonstrably
minimized and scrubbed, with what was removed stated. A synthetic fixture is better on the merits
anyway: it can be built to hit the self-map, the 16-byte window and the refusal path deliberately,
which a captured page only does by luck.

Three things must be pinned by tests rather than discovered again:

- **Cycle guards.** SK's PML4 self-maps (index 388 on the measured build), so an unguarded descent
  re-enters the table 512× per level. Unguarded, this took the bench down twice and needed a
  reboot each time. Pin: skip entries whose target PFN is the table they came from, a visited set
  per level, and hard budgets on reads *and* collected leaves that **report** a partial result.
  **And report what the visited set skips**, which S0's run had to add after review asked for it:
  6,773 alias prefixes go unexpanded on a walk whose 11,326 leaf mappings cover 4,189 distinct
  pages, and on the other capture 215 decodes come from 179 reads — 36 tables serving at more than
  one level. Expanding them all is combinatorial on a self-mapped tree — measured by building it,
  which exhausted a 200,000-leaf budget over 509 pages and identified nothing — so the guard stays
  and the omission is counted rather than silent.
- **Identification is per candidate, not per first match, and acceptance is two things agreeing.**
  Section names, timestamp and `SizeOfImage` say the bytes *are* the image; they do not say the VA
  is the base it was loaded at, and a second mapping of one image matches all three (the
  2026-09-25 capture has a duplicate `symcryptk.dll` the module list does not name). `KernBase`
  inside the data block distinguishes them and is **necessary, not sufficient**: the block is
  populated selectively, so a stale or zero `PsLoadedModuleList` still walks into plausible names
  and sizes. Accept a candidate only when the list's first `DllBase` names it back, record the
  reason for each rejection, and move to the next hit and then the next candidate. Which candidate
  the walk reaches first is prefix order and means nothing.
- **A docstring that states an invariant is a claim to check against the code.** `walk_module_list`
  said in prose that the first `DllBase` had to equal the identified base and then only decoded,
  for four rounds. Auditing every docstring in the probe found that one and no other, which is
  the cheap version of waiting for review to find them one at a time.
- **Gate the walk on the paging shape, not just on having a root.** The four-level descent
  hard-codes nine-bit indices and a 48-bit canonical form; a capture in any other mode, or with
  `CR4.LA57` set, would be traversed with the wrong strides and yield missing or invented leaves
  rather than an error — the walk cannot tell it is reading the wrong tables. Refuse and say
  which mode it was. An *unread* paging mode does not block it, for the same reason an unread
  `enabled` does not: unknown is not wrong.
- **A refused VTL switch and a failed register read are different answers.** Collapsing them makes
  a provider that cannot return one register look like a guest with no Secure Kernel — the same
  *refused*-as-*absent* collapse the read seam is guarded against, one level up.
- **Count failed reads at the source, not only at each caller.** Four review rounds on S0's probe
  each found another place where a failure arrived as a result, and a per-caller contract in prose
  did not stop the fifth: two scans wrote `if reason: continue` and reported a clean negative.
  A counter inside the read primitive is the one thing no consumer can bypass, and a run that
  found nothing with a non-zero count is a run whose negative has not been earned. Each scan keeps
  its own count beside it for locality.
- **Read width.** `HvCallReadGpa` moves at most 16 bytes, and judging a 4096-byte page on its first
  sixteen is what made SK's PML4 read as all-zero for most of a session. Any source-side chunking
  must not leak into the decode layer's view of a page.
- **The status/result split.** A refused read can answer `HV_STATUS_SUCCESS` with a per-access
  `ReadIntercept` and zeros. A source that collapses the two produces silent zeros exactly where
  the protected memory is; the seam must carry *why* a read failed, not just bytes-or-not.

### S2 — symbols, which is the one place DbgEng earns its keep — **BUILT AND RUN 2026-09-27**

**Names yes, types no, and no new `dbgscope` primitive.** `src/sksym.rs` opens
`securekernel.exe` as a DbgEng target in its own right, loads `securekernel.pdb` from the public
symbol server, and rebases it onto the base gate S1 found — so a VTL1 address has a name and a name
has a VTL1 address, with no debuggee anywhere. `--sk-inspect --symbols` is the opt-in that drives
it, and it is opt-in because it is the only part of that role that loads an engine.

**The unknown is settled, and the answer was the cheapest of the three it could have been.** DbgEng
accepts a PE image as a target: `OpenDumpFileWide` on `C:\Windows\System32\securekernel.exe`
produces a session with exactly **one** module, at the image's own `ImageBase` `0x140000000`, and
`.reload /f` against it downloads the PDB. Everything the gate needs is `dbgscope` methods that
already existed — `open_dump`, `wait_for_event`, `modules`, `module`, `reload_symbols`,
`module_pdb`, `module_symbol_file`, `symbol_offset`, `symbol_for`, `type_id` — so there is no stacked
`dbgscope` PR, and the `execute` hatch is not used either. The whole of this module's own work is
the **rebase**.

**The measurement, and it is the strongest cross-check this item has produced.** Against the image
on this bench (10.0.26100.9457, PDB key `C2C0D1A62E3269F40C69EA44FDB230C41`, `symbols: pdb`), the
PDB puts `KdDebuggerDataBlock` at RVA **`0x1335E0`** and `SkLoadedModuleList` at **`0x127770`** —
**the same two offsets S0's tag scan and S1's decode found inside the capture**, derived from a file
that has never seen it. Run end to end against the `H1 pinned 26200.9457 VBS+HVCI` checkpoint, both
rebase onto the decode's own addresses (`0xFFFFF8070EEDC5E0` and `0xFFFFF8070EED0770`) and the
engine names each of those addresses with displacement **0**, asked in the other direction. Every S1
figure reproduced unchanged in the same run — root `0x107593000`, 29 present entries, self-map 309,
16,437 leaves over 4,545 pages, 179 table reads, 215 decodes, six modules, the structural
cross-check agreeing with the block, the oracle 373 of 373, 18,253 reads and 0 failed.

**And the report now names the build that produced it**, which it did not under S1: `--sk-inspect`
prints `BUILD_VERSION` as its first line and carries it in the JSON, so a figure quoted out of this
role can be re-derived. The runs above were taken from **this change's own working tree** — a
`0.20.0+g3552d867-dirty.<digest>` build, and the digest is deliberately not written here: it covers
the uncommitted diff, so it moved four times while these paragraphs were being edited. The committed
equivalent is the commit that adds this. **Re-measured after rebasing onto `44428f5`** — every figure
above is identical on both parents, which is the one thing a rebase of a measurement has to be
checked for rather than assumed.

**So the module list is now reachable three ways, and one of them needs no block.** Unknown 4 asked
for a derivation to replace two remembered offsets; the PDB *is* that derivation, per build, and it
reaches `SkLoadedModuleList` directly — which the tag scan cannot, the list being a bare `LIST_ENTRY`
with no signature to search for. The block route stays: it is what works with no symbol server.

**The control arm is the other half of what makes the two halves independent.** Same command against
the VBS-off twin: symbols load and report normally, and the capture refuses the VTL switch by name
(`0xC0370509`). The report and the JSON keep those apart — a run where the engine had symbols and
the capture had no VTL1 must not read like a run where neither half worked.

#### What S2 does **not** deliver, measured rather than assumed

- **The public `securekernel.pdb` carries no type information.** `dt securekernel!_LIST_ENTRY` is
  *not found*, `dt securekernel!*` lists symbols rather than types, every data symbol prints
  `= <no type information>` under `x /t`, and four `GetTypeId` probes in the shipped code answer
  **`E_NOINTERFACE` (`0x80004002`), *no such interface supported*, every one of them** — the engine
  declining to service type queries for this module rather than four names it looked for and missed,
  which is a better corroboration than a sample of four could be. That detail only appeared once the
  probes stopped being booleans (round 5). The plan asked for "symbols **and types**"; the types half
  is not available to ask for, so structure walks over VTL1 stay hand-decoded the way `src/sk.rs`
  already does them. A finite probe cannot prove a PDB has none, which is why the code reports the
  engine's reason per probe rather than a verdict.
- **`SymbolKind::has_type_info` is wrong about this image, and must not be the test.** It reads
  `DEBUG_SYMTYPE_PDB` as private type information; this module is `symbols: pdb` with no types at
  all, because the engine does not distinguish a stripped public PDB from a private one. Asking for
  a type is the only answer. Worth a `dbgscope` doc fix on its own, and not a blocker here.
- **Rebasing inside the engine is a trap, and it was measured being one.** DbgEng will load the
  image a second time at the guest's base — `.reload /i securekernel.exe=fffff8070eda9000,175000`
  with `.exepath` set — and resolves the same PDB there. But it cannot reuse the module name, so the
  second module comes up `securekernel_exe`, and **both answer to `securekernel!`**: with the pair
  loaded, `? securekernel!KdDebuggerDataBlock` answers `0x1401335E0`, the *preferred* base. A
  name-based lookup would silently return an address in the wrong space. One module plus arithmetic
  has no such ambiguity and is testable with no engine.
- **Only two symbols are asked for.** The gate resolves the landmarks S1 already found, in both
  directions; it does not enumerate the PDB, name the other five VTL1 modules (their symbols are in
  *their* images, which nothing here opens), or resolve anything S1 did not locate.
- **It has read one PDB, for one build, on one host.** A module with no symbol **provider** after
  `Symbols::open` has made a resolving query is refused — `Deferred` and `Export` included — with the
  kind and `.reload /f`'s own error named, before any capture is read. Round 1 of the review narrowed
  that to `None` alone, reasoning that `Deferred` means nobody has looked; **that reasoning died the
  moment the forcing probe was added, and rounds 2 and 3 are what it cost** (see below).
  **And the refusal is now measured rather than reasoned about**, which it was not when this bullet
  first said "unmeasured": `--sympath C:\nonexistent-symbol-store` leaves the module reading
  **`Export`** and not `Deferred` — the engine falls back to the image's export table — and the run
  reports *no symbols loaded (the module still reads Export after a resolving query)* while the decode
  proceeds. Refusing `Export` costs the gate nothing, also measured: with symbols failing to load,
  `x securekernel!KdDebuggerDataBlock` and `x securekernel!SkLoadedModuleList` both answer nothing
  against roughly 280 exported names. What is still unmeasured is a build whose PDB is *served but
  wrong* — the `unmatched` arm.
- **Eight tests, seven of them with no engine at all** (1,088 unit tests now, from 1,080 — re-derived
  after rebasing onto `44428f5`, which moved both figures from the 1,071-from-1,065 this said when
  it was branched off `2466abc2`, and again when review round 6 added one). The five pure
  ones pin the rebase: the two landmark offsets against literals, the half-open end of the image,
  an address below the base refused rather than wrapped, both bases checked for overflow, and an
  unresolved symbol reading as *unknown* rather than as a disagreement. All four guards were
  mutation-verified — widen the end to `>`, swap `checked_sub` for `wrapping_sub`, drop the
  preferred base from the overflow loop, make `agrees()` answer `Some(false)` — and each failed the
  one test it belongs to and no other. A sixth is about neither the rebase nor the engine and reads
  the crate's own source: exactly two files may **construct** a `DebugEngine`, which is the review
  finding below turned into a ratchet. Only the seventh needs an engine, a symbol store and a real
  image, and it is gated on the image path so the gate and the input are one thing:
  `WINDBG_MCP_SMOKE_SKSYM=<path to securekernel.exe>`. **It asserts nothing about the type probes**:
  whether a Microsoft public PDB carries type records is Microsoft's to change, and pinning today's
  answer would fail on the build this gate would most want to hear about.
- **The `dbghelp` load order was a hazard and is now a measurement.** The engine bundle beside this
  binary carries its own `dbghelp.dll`, and whichever of DbgEng and the SDK provider loads first is
  the one the other inherits by name. The engine opens first, because it needs its own; the run
  above is what says the provider still reads a capture afterwards.
- **Narrowing that refusal opened a hole, which round 2 of the review found.** Accepting `Deferred`
  left the engine free to load the PDB on the first *landmark* query — after the only `unmatched`
  check had run, so another build's names could have been printed as this build's, and the reported
  provenance would have said `kind Deferred` and "no PDB signature" above addresses a PDB had just
  resolved. That is the `.claude/skills/review-round` rule about what a deleted check was *also*
  load-bearing for, and the whole suite stayed green through it. Fixed by **collapsing** the state
  rather than reporting it: `Symbols::open` now issues one deliberately-failing lookup to make the
  engine look before the provenance is read. Measured, twice: a module reading `symbols: deferred`
  straight after the open moves to `symbols: pdb` with its PDB key on a single failing
  `? securekernel!ThisSymbolDoesNotExistAnywhere`; and with `reload_symbols` not issued at all the
  probe alone still gets `Pdb` and resolves both landmarks, so the two halves are independent and the
  reload stays because it is the one that yields a *named* error. With **neither** issued, the gated
  test fails on exactly the reported state (`symbols Deferred, pdb None, file securekernel.exe`),
  which is what says its two new assertions are not vacuous.
- **Round 3 then found the probe can fail to settle it, and that is when the choice went rather than
  the symptom.** Accepting `Deferred` *after* a resolving query was the thing generating both
  rounds — the probe made the argument for accepting it false, since a module still deferred once the
  engine has looked is one whose symbols did not load. So the refusal is back to requiring a
  provider, now justified by a measurement instead of a guess, and nothing downstream can move the
  kind: that is what makes reading the provenance once and keeping it safe, with the residual
  assumption stated (no further `.reload` is issued) rather than hidden. `Export` goes with it and
  costs nothing this gate wants — neither landmark is an export of `securekernel.exe`. The same round
  found two more, both enumerated rather than patched one at a time: `SymbolFailure::Open`'s message
  said *the engine refused the image as a target* for **four** different engine calls, of which it was
  true for one (review named `--sympath`, where `open_dump` has not run yet), so it is now
  `Engine { step, detail }` and each site names its step; and the symbol file was captured only on the
  success arm, so a refusal that had *read* a PDB left it unprotected — `SymbolFailure::file_read` is
  now the one place that answers what a failure read, and `NoSymbols` was in the same position as the
  `unmatched` case review named.
- **Round 4, two findings, both taken and one remedy declined.** Asking the engine *which* PDB it
  loaded can fail, and `.ok().flatten()` turned that into "there is no signature" — so *could not ask*
  was published as a fact and the mismatch check was skipped with nothing saying so, which is
  `sk::ReadFailure`'s own lesson committed one level up. `PdbUnmatched` is now `PdbUnvouched` carrying
  *why*: both halves are "this PDB is not vouched for", so they are one refusal rather than two cases
  a fifth round can find a third of. And the engine ratchet was bypassable by renaming the type
  (`use … DebugEngine as E; E::new()`); CodeRabbit asked for alias-tracking, which is a parser in a
  test, so instead the **rename** fails the check — a name that cannot be renamed cannot be
  constructed through a rename, and both forms are mutation-verified. What it covers is stated as an
  inclusion: a literal construction and the two rename forms, not a macro-generated call.
- **Round 5 found the third of that class, so the class is now enumerated in the module.** `type_id`'s
  `is_ok_and` collapsed every failure into *absent*, and those negatives are what this gate offers as
  evidence that the PDB has no types — so a DIA that could not answer would have read as a stripped
  PDB. The probes carry the engine's own message now, and counting the rest of the module found a
  third site review had not named: `module_symbol_file`'s `unwrap_or_default`, where an error became
  `""` and an empty path **silently disables** the `--json` guard built on it. That one is a refusal.
  `src/sksym.rs` carries a table of every engine call and what a failure becomes, including the two
  that are answers rather than omissions — the discarded forcing probe, and `symbol_for`, whose `None`
  is `dbgscope`'s own contract.
- **Round 6 found a flag being eaten as a value, and the test that should have caught it was named
  for exactly that.** `--symbols --sympath --cross-check` took `--cross-check` as the symbol path and
  left cross-checking silently off. `a_flag_with_no_value_is_a_usage_error_rather_than_eating_the_next_flag`
  — S1's — puts the flag **last**, so there is no next flag to eat: the name claimed the general
  property and the body covered the trivial half, which is `.claude/skills/review-round`'s "a test can
  pass on a neighbouring rule" from the other side. The helper is shared by all twelve flags that take
  a value, so the fix is central and the assertion is a table over every one of them; `--json` is the
  worst of the twelve, since it would have written the report to a file named `--cross-check`.
  Mutation-verified: backing the guard out fails the new test on `--vm` and leaves the old one green.
- **Round 7 was the fourth on the vouching seam, so the set is now closed rather than extended.** A
  module the engine reports as `Pdb`/`Dia` while having **no** signature for it was still accepted, so
  `symbol_offset` results were trusted with nothing having checked which build they came from. Taken —
  and written as a *requirement on the kind* rather than as a fourth enumerated failure, because the
  three arms of `Unvouched` are the whole set: the identity says the wrong thing, the engine will not
  say, or it has none. Any future shape of "no identity" lands in the third without a new arm.
  `CodeView` and `Sym` keep `None`, those providers genuinely having no signature. Unmeasured like the
  other refusal arms — this bench only produces `Pdb` with an identity, which is what the gated test
  asserts, and that assertion is now a ratchet on the refusal rather than a discovery.
- **Round 8: the same swallow, surviving in the one branch this bench cannot reach.** The text report
  printed a failed probe's reason only when *every* probe failed, so a mixed result — one type
  answered, another query broken — showed the successes and dropped the error. Every probe fails
  against this PDB, so that branch never runs here and round 5's fix looked complete. The loop is
  outside the branch now. Not unit-tested, stated rather than hidden: `report_symbols` takes the
  engine-holding `Symbols`, so splitting a printable provenance out to test a `println!` is more
  structure than the fix is worth. Codex filed nothing at that head, so round 7's closure of the
  vouching set held from its side.
- **The loaded PDB is now an input, and the mutation says the finding's stronger form is wrong.**
  Review also found that `symbol_file()` — a file this run read, discovered only once the engine had
  loaded it — never reached `Inputs`, so `--json` could name it. Taken: it is added where it is first
  known and the alias check re-runs, exactly as the capture paths are. But backing the guard out does
  **not** truncate the PDB on this bench: the write fails with `os error 32`, *being used by another
  process*, because DbgEng still holds it. The guard stays because that protection is incidental —
  it would vanish if symbols were released or `symbol_file` named something the engine had closed —
  and because a sharing violation reported as a failed report-write is the wrong answer to *you named
  an input*. Verified both ways with the cache file hashed before and after.
- **It is a third process in this crate that loads DbgEng, and that was a P1 on the review.** Review
  on [#399](https://github.com/glslang/windbg-mcp/pull/399) asked for image resolution to be routed
  through an engine worker, citing `AGENTS.md`. The fact is right and the remedy is declined: the
  rule's constraint is one debuggee session per process, every call on the thread that made it, and
  no engine in the process that serves MCP — and `--sk-inspect` meets all three, opening **one**
  target which is a *file*, on a single thread, in a role that speaks no MCP and returns from `main`
  before a runtime exists. Routing would mean building a session registry and a `proto` channel
  inside a report writer, and would **pre-decide S3's own open question** for a research CLI. So
  `AGENTS.md` now states the constraint rather than the shape, and
  `sksym::tests::only_the_worker_and_this_module_build_an_engine` fails if a third file constructs an
  engine — mutation-verified both ways: a construction in `engine.rs` fails it, a prose mention of
  the same name does not.

#### S2 as specified

Resolve `securekernel.exe`'s symbols and types against a base supplied by S1. This is the part
worth keeping DbgEng for, and **the only part**: the remaining primitives are reads this server
already has from S1, and routing those through an engine that has no target buys nothing.

**Unknown to settle before committing:** `dbgscope`'s symbol methods (`symbol_offset`,
`symbol_for`, `module_symbol_file`) all assume a session with a target. Image-only resolution —
load `securekernel.exe` at a given base with no debuggee and resolve against it — is not obviously
available, and if it needs an engine call it is a **typed `dbgscope` method**, per this repo's rule
that a new DbgEng primitive belongs there rather than behind the `execute` text hatch. Size that
before promising symbols.

### S3 — the tool surface — **BUILT AND RUN 2026-09-27**

**Four tools, one session per capture, and the whole decode on the open.** `open_sk_capture`,
`sk_modules`, `sk_read_memory` and `sk_symbol` are a `--tools` group of their own
(`securekernel`); `src/sksession.rs` is the session they open, `EngineOp::OpenSecureKernel` and
three siblings carry them to a worker, and `crate::engine::refuse_op_on_kind` is what keeps every
other tool off a capture. The three questions this gate was deferred to answer are answered below,
and two of the three answers are forced rather than chosen.

**1. Where does the engine live? In a worker — and the half of that which is *measured* is the half
about the engine-free code.** The rule (`AGENTS.md`) already keeps DbgEng out of the process serving
MCP, which settles the symbol half and nothing else: the decode needs no engine at all, so nothing
in the rule stopped it living in the supervisor beside the session registry. What stops it is
**S0 arm 4**: `vmsavedstatedumpprovider.dll` `__fastfail`s on a capture it has no key for —
`0xC0000409`, subcode `FAST_FAIL_FATAL_APP_EXIT`, reached from a GSL contract violation inside
`LoadSavedStateFile`, measured from two different hosts and reported to Microsoft
(`docs/secure-kernel/vmsavedstatedumpprovider-crash.md`). A vendor DLL that aborts the process on a
path a *caller* supplies cannot be loaded into the supervisor, where it would take every other
client's session with it; in a worker it costs the one session that named the capture, which is what
process-per-session is for. So the arm that was run to answer a question about the VBS boundary
turned out to decide this one.

**2. One session handle or two? One, with symbols opt-in on it.** The symbols are the capture's only
because the mapping was identified against the same `securekernel.exe` on disk, and the rebase needs
the base the decode found — so a symbol handle without a capture handle can answer nothing in guest
coordinates, and two handles would be two halves of a join nothing checks. `symbols: true` stays
opt-in because it is the only part that needs a debugger bundle and a reachable symbol store, and
the decode stands without it: the control arm below has symbols loaded and no VTL1, which is exactly
the pair a caller must be able to tell from a run where neither worked.

**3. What is a "structure walk" with no types? The decoders `src/sk.rs` already has.** The public
`securekernel.pdb` carries no type information, so there is no `dt` over VTL1 to offer and none is
offered. What the surface exposes is what was hand-decoded — the root page, the walk, the identified
image, the debugger data block and the loader list — plus `sk_read_memory` for anything else, and
the four type probes travel with the session so a caller is **told** why there is no type-driven
walk rather than finding out one failed call at a time.

**And a fourth question nobody asked, which the first answer creates.** A worker holding a capture
has at most one DbgEng target and it is the *image*, at its own preferred base. `read_memory` there
would read a file and answer as though it had read the guest; `registers` would answer about no
thread. Neither *fails*. So the supervisor refuses every op that is not one of this session's own,
in `submit_gated` — the one funnel every non-opener passes — and it is an **allow-list in both
directions**: a tool added to `EngineOp` later is refused on a capture until somebody decides what it
means for one, where a deny-list's cost for forgetting is a wrong answer rather than a refusal. The
refusal names what the engine is actually holding, because "this tool is not available here" sends a
reader looking for a missing feature.

That rule is also what makes the session's answers stable: nothing in a capture session can execute a
command, so the engine's target cannot be replaced under the symbols, and the capture is a file that
does not change. Every figure the open reports is as true at the end of the session as at the
beginning — which is why the **whole decode travels with the opener** rather than being re-read by a
later call, and why a structured-aware client (which drops the text block) gets the read counters
that say whether a negative was earned.

#### What it was run against, and what reproduced

Driven over MCP against the same `H1 pinned 26200.9457 VBS+HVCI` checkpoint gates S0, S1 and S2 were
run on, with `--tools` defaulted, on build `0.20.0+g7606eac3` plus this change's own tree. **Every
S1 and S2 figure came back unchanged through the tool surface**: root `0x107593000` read out of the
capture, root page 29 present entries with the self-map at 309 and 139 non-zero bytes, 16,437 leaf
mappings over 4,545 distinct pages from 179 table reads and 215 decodes with 7,803 alias prefixes
unexpanded, 0 malformed entries and 0 unreadable tables, 16,437 pages scanned with 7 PE headers of
which 1 matches the image, `securekernel.exe` at `0xFFFFF8070EDA9000` (GPA `0xCD0000`),
`KdDebuggerDataBlock` at `+0x1335E0` with `Size` `0x3A0`, `SkLoadedModuleList` at `+0x127770`, the
same six VTL1 modules with the same sizes, three `KDBG` tags rejected on `KernBase` and one accepted,
the structural cross-check reaching head `0xFFFFF8070EED0770` — the address the block names — and
18,253 reads of which **0** failed. Symbols: PDB key `C2C0D1A62E3269F40C69EA44FDB230C41`, both
landmarks agreeing in both directions, and all four type probes answering `E_NOINTERFACE`.

**And one thing the CLI role could not show, which is the point of a read tool.** `sk_read_memory` at
the block's own address returns `C0C5ED0E07F8FFFF C0C5ED0E07F8FFFF 4B444247 A0030000 0090DA0E07F8FFFF`
— a `LIST_ENTRY` pointing at itself, then **`KDBG`** as the owner tag, then `0x3A0` as the `Size`,
then `0xFFFFF8070EDA9000` as `KernBase`. Three of the decode's own conclusions, read back as bytes
through a different code path, and the engine names that address `securekernel!KdDebuggerDataBlock`
beside them. A read across a page boundary (`0xFFFFF8070EDA9FF0`, 64 bytes) comes back whole and
stitched.

**The control arm is the other half.** The same command against the VBS-off twin's capture
(`H1 control 26200.9457 VBS off`) reports partition VTLs `0x1` against the VBS guest's `0x3`, the
provider refusing the VTL switch by name (`0xC0370509`), and the session **opens** carrying that as
its `not_walkable` reason and its `limitation` — after which `sk_modules` and `sk_read_memory` are
refused with the same sentence rather than answering zeroes. Symbols loaded normally on it, which is
the pair that had to stay distinguishable.

The four refusals were exercised in the same run: `read_memory`, `registers`, `modules` and `execute`
against the capture session, each answered with what the engine is holding instead.

#### What it cost, stated because a reader will ask whether it should have been paid

**The surface grew by 7,501 B of model-visible context**, from 95,792 to 103,293 across 63 to 67
tools: `open_sk_capture` 3,918, `sk_symbol` 1,466, `sk_read_memory` 1,277, `sk_modules` 840. That is
paid at the start of **every** conversation, by every caller, because the default surface is every
tool — and the overwhelming majority of callers have no Hyper-V checkpoint, no Windows SDK and no VBS
guest. `--tools` is the lever that exists for it and it is opt-*out*. Whether a group should be able
to be *outside* the default surface is a real question and is left as one (item 106 below), because
it is a change to what `--tools` means rather than something this gate should decide. The four
descriptions were trimmed from 8,340 B first, which took out sentences that explained rather than
told.

**And the wire payload found a multiplication, which is the first time that ceiling has caught one.**
`SecureKernelReport` was first held in `structured::TargetSummary`, whose schema is reached by all
seven openers — so `schemars` inlined the whole report into seven `$defs` closures and `tools/list`
measured **341,057 B**. Moving it into an outcome of its own (`SkOpenOutcome`, declared by one tool)
took **50,844 B** back off the wire for a change no client can observe; the payload settled at
290,213 B, of which the four tools' own output schemas are 14,257 and **378 is `SessionKindName`
gaining a `secure_kernel` variant** — one enum variant paid eight times over, which the per-tool
golden keyed by *name* is what made visible. Both ceilings were raised with the arithmetic recorded
beside them (96,500 → 105,000 and 268,000 → 295,000).

#### Review round 1 on [#401](https://github.com/glslang/windbg-mcp/pull/401): six findings, five taken

Worth recording as a set, because four of the five are the same shape — **a claim nothing compared**:

- **The cross-check reported agreement for any successful search.** `cross_check_within` finds a
  loader entry whose `DllBase` is the identified base and follows its `Blink`; whether that head is
  the one the block names is the *question*, and `decoded` answered `agrees: true` without asking it.
  `--sk-inspect` compared and the tool surface did not, which is why the comparison is now a method
  on `CrossCheck` used by both — a rule with two renderers is a rule one of them gets wrong. The
  field is `Option<bool>` now, for `SkLandmark::agrees`'s reason: a search that found nothing is not
  a disagreement.
- **An interrupt during a capture op marked the job**, so a complete decode was reported cut short
  and its caller was told the operation was stopping. Sealed at the door now, with a `Cleanup`
  variant whose doc says why it belongs in an enum named for cleanup: the other three are sealed to
  protect work that must not stop halfway, and this one because there is nothing there to stop. The
  test that pinned "a teardown is the only op sealed at the door" had a **name claiming a general
  property** over a body that checked one case, which is review round 6 of #399's shape; it now
  states the rule and enumerates both halves.
- **`open_sk_capture`'s three argument refusals answered in the wrong shape.** The tool declares
  `SkOpenOutcome`, whose error branch carries `target`; `typed_error` serialises `Outcome<()>`, which
  does not — so a schema-validating client would reject the message telling it what was wrong.
  `attach_kernel`'s argument refusals have always used `open_failure`, so this was the outlier rather
  than a new rule, and the test now asserts it of **both** openers.
- **The tier's prose claimed four tools and its body reached three.** `sk_symbol` was never called
  against a capture. Rather than narrow the sentence, the test now calls it and asserts the refusal a
  session opened *without* symbols gives — which pins a state that had no test at all, and makes the
  sentence true.
- **`docs/tool-surface.md`'s headline still said 95,792 B** while its own table said 103,293. The
  `.claude/rules/tool-surface.md` trap exactly as written: the tables are checked against a running
  server and a figure in a *sentence* is not.

The sixth is declined with its fact taken, and is the timeout bullet in *What this does not
establish* below.

#### Review round 2: two findings, both taken, both about a claim being wrong for most of its cases

- **`sk_read_memory`'s size bound was the worker's, and arrived as a debugger failure.** A size this
  tool will not serve is the *caller's* argument, and a refusal categorised `debugger` sends them to
  look at the capture for a number they chose. It is checked in the supervisor now — before any
  session is routed to, which is what makes it reachable with nothing open — and the worker keeps its
  own, because a bound only one side holds is one the other side's callers walk past. The bound is
  also **in the schema** now (`minimum: 1`, `maximum: 65536`, the only `schemars(range)` on this
  surface, 28 B): a cap a caller can only discover by exceeding it is a cap they will exceed.
- **The session's `limitation` gave the VBS-off reading for all six `NotWalkable` variants**, and it
  is true of two. A guest whose paging shape this walk does not decode **has** a VTL1, and a register
  the provider would not answer for is the provider's failure rather than a fact about the guest —
  three readings that send a reader to three different places. `what_no_vtl1_means` is the per-cause
  sentence, and the test asserts the VBS-off wording appears for exactly the two variants that
  support it. This is the same class as round 1's four: a sentence asserting more than was
  established, one level up from a value doing it.

#### Review round 3: one finding, and the third time the rule already existed next door

**A read whose last byte is past the top of the address space was not refused.** `Gva::offset` wraps
— deliberately, since a loader record starts `0x30` *before* its `DllBase` and the subtraction is
done the same way — so two bytes at `0xFFFF_FFFF_FFFF_FFFF` continued at zero: the answer stitched
from both ends of the space where something is mapped low, and a refusal naming a page the caller
never asked about where nothing is. Codex.

Refused in **`sk::Space::read_span`**, which is the reader every part of the decode goes through, so
`gather_image` and the module walk are covered rather than the one call site that was in mind — with
its own `VaFailure::Wraps`, because reporting it as the low page it wrapped onto is the reason the
finding was worth filing. The caller's own range is checked in the supervisor too, as an argument and
before any routing, for round 2's reason.

**And `sksym::Rebase` has refused exactly this since gate S2** — `RangeOverflows`, with a test named
`a_range_that_runs_off_the_top_is_refused`. That makes three findings in three rounds where the rule
was already established in a sibling and the new code was the outlier: `attach_kernel`'s
`open_failure`, `--sk-inspect`'s cross-check comparison, and now this. The lesson is cheaper than the
rounds were: when adding a path beside an existing one, read what the existing one *refuses*, not
only what it does.

#### What this does **not** establish

- **One capture, one build, one host.** The same limitation S1 and S2 carry, and the tier is written
  so it does not pretend otherwise: `WINDBG_MCP_SMOKE_SK_CAPTURE` names a `.vmrs` and the test
  asserts the *shape* of the answer — a decode, or the reason there is none, never neither — because
  whether a given capture has VTL1 in it is a property of somebody's guest. Both arms have been run
  here; nothing in the suite pins a figure, deliberately.
- **No live source.** Every tool reads a capture. The operator-supplied transport that reads a
  *running* guest is unbuilt, and so is `ReadFailure::Refused`'s only real producer — a capture has
  nothing to refuse with, so the refusal path is still fixture-only. Two things follow if a live
  source is ever added behind these tools: the session stops being a fixed snapshot, which is the
  premise the decode-on-open rests on, and `sk_read_memory` acquires a target that can change
  between two reads.
- **No writes.** S4 settled that the direct route writes VTL1, and nothing here exposes it. That
  stays out for the reason the plan's *Out of scope* section gives.
- **The capture ops are not interruptible, and they say so.** `interrupt` reaches DbgEng, and a
  page-table walk is this server's own code: a break raised during one has nothing to land on. Round
  1 of review found what that cost before it was said out loud — the interrupt marked the job, so a
  decode that ran to the end came back through `cut_short` labelled as truncated, and the interrupt's
  caller was told an operation was stopping that was not. The ops are sealed at the door now
  (`worker::Cleanup::NotInterruptible`) and the refusal names what it cannot do. What bounds them is
  the walk's own budgets (20,000 table reads, 200,000 leaves) and the read counters that report them,
  not a caller's clock.
- **An open that times out loses its decode, and the recovery is to open again.** The measured open
  is ~16s against a 300s default call timeout, so the window is wide — but the decode travels on the
  opener's reply *only*, and a caller who abandoned that wait cannot get it back: `sk_modules` still
  answers, `session_status` reports state, and the root, the walk, the candidate rejections and the
  read counters are gone until the capture is read again. Raised by Codex on
  [#401](https://github.com/glslang/windbg-mcp/pull/401), **taken as a fact and declined as a
  change**: the remedies are a fifth tool or a field on `session_status`, and both put another copy
  of the report's ten-kilobyte schema on the wire for every caller — which is what item 106 is about,
  arriving in the same review as the item. An earlier draft of this bullet said a timeout costs what
  it costs "exactly as a slow dump open does", and that analogy is the part that was wrong: a dump's
  summary is re-derivable from `modules` and `crash_triage`, and a capture's decode is not. The
  recovery is `end_session` and a second open, which is the 16s again.
- **`sk_read_memory`'s 64 KiB cap is a policy, not a measurement.** A capture is a file and the bytes
  are cheap; what is not cheap is the hex in a result a model pays for.
- **The `.bin`/`.vsv` pair is still called by nothing.** It is selected by code in both roles and
  this bench has never produced a capture of that form.
- **Nothing was measured about a second client.** A capture session is owned like any other and the
  four-session cap is shared with debugger sessions, but no run here had two credentials open one.

#### S3 as specified

Shape it after S0 and S2 answer, not now — **both have answered**, so this is the next gate. What
the plan asked for is SK base and size, structure walks, and symbol resolution against the image.
Note that a reader with no debuggee fits this
server's existing session model awkwardly — the one-worker-per-debuggee reason for the worker
process does not apply — so whether this is a session kind, a sessionless tool group or a separate
surface is a real design question, and **S0 and S5 both move it**: a live driver-backed source is
not a fixed snapshot, and an S5 pass would bring execution state back into a surface shaped on the
assumption that there is none. **S0 has moved it**: the source most users will have is a capture, so
the sessionless shape is the case to design for and the live one is the variant.

**And S2 has moved it in the other direction, which is the part to design around rather than
discover.** The decode is engine-free and the symbols are not: `src/sksym.rs` holds a DbgEng session
on an image file, which is a debuggee-less target and so needs no worker by the
one-session-per-process rule — but it is still an engine in *some* process, and `--sk-inspect` is a
short-lived one. A tool surface is not: it would hold that engine for the life of a session, beside
whatever engine the caller's other sessions hold. **Three things follow, and none of them is
answered.** Whether the symbol half is part of the same session handle as the capture or a separate
thing a caller opens; whether it lives in the supervisor (which has never loaded DbgEng, and where
`dbgeng.dll` in-process would be a new property of that role) or in a worker of its own; and what
`structure walks` means now that types are **not** available, since the plan's wording assumed a PDB
that would format them. Two of the three are about where an engine lives, which is this repo's
oldest architectural line — decide them before writing a tool, not after. And that is now enforced
rather than remembered: `sksym::tests::only_the_worker_and_this_module_build_an_engine` fails on a
third file constructing an engine, so a tool surface that puts one in the supervisor fails
`cargo test` with the reason rather than reaching a review round.

### S4 — settle the write routes — **RUN 2026-09-26, settled; do not repeat as written**

**Repeating it needs a quiesced guest or disposable state, which the run did not have.** Two
defects in the method, both real and neither fatal to the result:

- **"Identical bytes" is only identical at the instant of the first read.** The run reduced that
  window with a stability check — read twice, require agreement — but a running guest can change
  those 16 bytes between the read and the write, and then the write restores *stale* bytes. On a
  page-table or kernel-state page that is corruption, dressed as a no-op.
- **A scratch page was chosen from two all-zero reads and exclusion from known images, and that
  does not establish the page is unowned.** The guest can be using it for anonymous data, or can
  allocate it between the check and the write. The differing-bytes pattern makes this sharper than
  the identical-bytes case it replaced.

Neither invalidates what was measured — the writes landed and were verified restored, and the guest
ran on — but a repeat should **pause the guest**, or use a page the guest explicitly reserved, or
run against a snapshot that is thrown away afterwards. Detecting an intervening write (re-read and
compare immediately before the write) is the cheap partial mitigation and is not a substitute.

**Result in the feasibility record. Settled, both routes.** `HvCallWriteGpa` writes VTL0, honours
the address field, and is **refused on VTL1 with `AccessResult = 3 WriteIntercept`** — per-page,
confirmed on two different pages — so a software breakpoint is unavailable through hypercalls
outright. The **direct route writes VTL1**: differing bytes (`deadbeef…`) were written into
`securekernel.exe`'s `.text` alignment padding and read back, then restored to `0xCC` and verified,
with the guest running on. The mechanism was proven first on an ordinary scratch page, since until
then *neither* route had been shown to write anything — every prior write wrote bytes already
there. **So the patch half of a software breakpoint is solved and the catch half is not**: planting
an `int 3` in Secure Kernel is now a question of S5's transport, not of the write. The original
specification follows.

#### S4 as specified — settle the write routes, with a test that changes nothing

Run this before anything in the repo tells an implementer that patching is available, and note it
is **not** a prerequisite for S0–S3, which need no writes at all. The test is a round-trip that is
a no-op on success: **read 16 bytes, write the identical bytes back, read again.** It exercises
the whole path and returns an `AccessResult` either way, while leaving the guest byte-for-byte as
it was — so a refusal costs nothing and a success corrupts nothing. Run it on a VTL0 page as the
control, then on a VTL1-protected page, on each of the two routes independently, since H4 already
showed the two routes disagree about VTL1 for reads.

- **Pass / fail is per route**, and the interesting outcome is the asymmetry: the direct route
  reading VTL1 where the hypercall will not says nothing about whether it *writes* there.
- **Do not** write different bytes into a running guest to test this.

**And the hazard, stated conditionally because the premise is unproven.** A software breakpoint
*is* a memory patch, so **if** S4 finds VTL1 writable, an `int 3` is one write away — and without a
delivered trap it bugchecks the guest, with SKPG/HyperGuard in the business of noticing exactly
that. So breakpoints are gated on **both** S4 (can we write?) and S5 (can we catch it?), and
neither answer alone is a licence. Until S4 runs, nothing here should be read as saying VTL1 can be
patched.

### S5 — can VTL1 execution be controlled at all? Independent of S0–S3, and worth its own answer

Not required for S1–S3 to be useful, and it decides whether this ends as an inspector or a
debugger.

**An earlier draft of this section started at the wrong boundary and would have cost a reboot to
find out.** It said the hypervisor's root VTL1 debug context "was configured and did not activate"
with "the failure never named", and asked for an early-boot trace of the activation return. All
three are wrong, because they read the validation record's state at one point and missed its
resolution two experiments later:

- the activation return **was** captured directly — `0x1D`, propagated from the debug buffer
  allocator when the **debug free-page list is exhausted**;
- raising the `hypervisordebugpages` reservation from 1000 to 2000 **fixed it**: active port moved
  from `0xFFFF` to `0xC35C` (50012) and both buffers allocated (`0x1000`/2 and `0x1000`/`0xA0`),
  and the activation routine assigns the port only after both allocations succeed;
- the record's own conclusion is **"the allocation failure is resolved, but Secure Kernel
  attachment is not"**, and it names where to go next: *"Secure Kernel-side debugger
  startup/transport beyond the initialized hypervisor port, not another unsupported increase in
  reservation or VM RAM."*

**So the hypervisor side works and the Secure Kernel side does not connect to it.** That is a much
more specific question, and it sits uncomfortably beside a fact this plan already established:
post-26100 `securekernel.exe` ships no KD transport, every `Kd`-prefixed symbol in it being data.
S5 should start by asking whether those are the same wall — a hypervisor port with nothing on the
guest side to speak to it — rather than by re-running a completed experiment.

#### S5a — **RUN 2026-09-27: they are the same wall. Do not repeat; S5 continues below it**

**Secure Kernel has no hypercall or MSR route to that port**, measured offline across ten builds
from 19041.207 to 29667.1000 with `tools/sk_hypercall_scan.py`. The three debug hypercall codes are
never written at any instruction boundary the scan recognises — every occurrence of `0x69`, `0x6A`
or `0x6B` at one is a `cmp` in unrelated code — no sample materialises a synthetic-debugger MSR
number `0x400000F0`–`0x400000FF` at all, and there is no `vmcall`/`vmmcall` instruction in any of
them. The enumerated
hypercall repertoire (19–38 distinct codes per build, `0x0002`–`0x0103`) contains none of them
either; that reading is a heuristic lower bound acting as the negative control, and the verdict
comes from the immediate scan, which covers 100% of each image's executable sections. The positive
control is `kdhvcom.dll`, Windows' own KD-over-hypervisor transport, which is those three hypercalls
behind the five-function KD export contract and which the same scanner reads correctly. Full result,
limits, and the four traps that each produced a wrong reading first — a sample whose *filename*
silently defeats symbol resolution, a control code that is also the rep-count bound, resting the
negative on one approximate evaluator, and bug check codes being read as hypercall codes — are in
[the feasibility record](docs/secure-kernel/secure-kernel-hypercall-feasibility.md).

**What this closes is one route, not the gate.** S5's pass condition is untouched. The remaining
candidate is the one that needs no guest-side code at all: a VTL1 stop driven entirely from the
hypervisor or the root, which Secure Kernel neither cooperates with nor can refuse. **Start there**,
and note that the receiver half was *not* re-derived statically — two attempts on `hvix64.exe` found
the IDT and a page-table walk rather than the hypercall dispatch, so the hypervisor side still rests
on the live trace in the validation record.

**And the mechanism to try is named rather than hypothetical, because Secure Kernel uses it.**
`ShvlInstallExceptionIntercept` (+`0x092C4C` in 26100.9457) issues **`HvCallInstallIntercept`
(`0x004D`)** with intercept type **3** — `HvInterceptTypeException`; 4 is the *access* mask,
`EXECUTE`, and this line had the two adjacent dwords the wrong way round until S5b read the block
against the TLFS — and a 0x18-byte parameter block, and registers the vector in a
bitmask afterwards — so exception interception is a real hypervisor primitive with a VTL1 caller on
this very build. SK aims it at VTL0. **The S5 question is whether a parent partition can aim the
same primitive at a child's VTL1**, which would deliver a `#BP` to the root instead of to SK's own
dispatcher — the missing catch half, on a route that needs nothing from SK. Unmeasured, and the
obvious hazard is that `HvCallInstallIntercept` may be partition-scoped with no VTL parameter to ask
with, which is exactly how `HvCallReadGpa` failed in H4. Test the *install* on its own, against a
VTL0 control, before anything is patched. **Run on 2026-09-28 as S5b, below: the hazard was the
answer.**

- **Do not** re-run S5a, and **do not** go looking for a differently-spelled KD transport in
  `securekernel.exe`. The scan is over the whole image, not over a name.
- **Do not** re-capture the activation return, and **do not** raise the reservation further. Both
  are done, and the record says the second is unsupported.
- **Pass:** a VTL1 execution stop is delivered to a debugger.
- **Necessary but not sufficient for software breakpoints.** A stop arriving by *some* route does
  not show that a VTL1 `int 3` reaches a debugger, and those can differ — the trap has to be routed
  by whatever handles VTL1 exceptions, which is not the same question as whether a debug transport
  exists. So S4 (we can write) plus a generic S5 pass is still **not** a licence to plant one;
  breakpoints stay excluded until **route-specific trap delivery** is demonstrated.
- **Do not** plant an `int 3` in VTL1 to test S5 itself. Without a delivered trap it bugchecks the
  guest and is a plausible SKPG trip; S4 having shown the write lands is not a reason to use it.

#### S5b — **RUN 2026-09-28: the install works on a child, and cannot name a VTL. Do not repeat**

**The hazard the S5a section named is the result.** `HvCallInstallIntercept` is partition-scoped
with no VTL parameter to ask with — the TLFS documents the whole 0x18-byte block
(`PartitionId`, `AccessType`, `InterceptType`, `InterceptParameter`), `HV_INTERCEPT_PARAMETERS`'
exception member is a bare `UINT16 ExceptionVector`, and both known callers write exactly that —
the 26100.9457 SK sample and this host's `winhvr.sys`, neither of them the guests' running SK —
read once with capstone and once with Ghidra. Live, from the root: a parent **can** install an
exception intercept on a child and remove it — `SUCCESS` on both guests, teardown clean — and every
byte put where a VTL might hide (the union's six spare bytes, eight bytes past the block) is
accepted **identically on the child with no VTL1**, while a variable-header declaration is refused
outright, so there is no extended form either. The full record, with the arm table, is the
[S5b result](docs/secure-kernel/secure-kernel-hypercall-feasibility.md) section.

- **The control is what makes it readable, and the first run had none that worked.** Vector `0x1F`
  was picked because no hardware raises it; the hypervisor refuses it as `INVALID_PARAMETER`, every
  arm including the baseline failed the same way, and that reads exactly like a clean negative about
  VTL1. The script now *discovers* an accepted vector on the VTL0-only guest before any VTL arm
  runs — `0x05` (#BR), which the hypervisor takes.
- **"The vector cannot fire" is retracted, and the lesson is about the search rather than the
  vector.** Two rounds each named a way #BR reaches a running x64 guest — MPX's bound-check
  instructions, and the legacy `BOUND` still decoding in **32-bit compatibility mode**, which is
  every WOW64 process — and an `int 5` is a third without looking far. No CPUID reading settles a
  claim about every instruction a guest might execute. What protected the run was the disposable
  guests and the install paired with its removal microseconds later; the vector made a fire
  unlikely, not impossible. **A re-run needing a genuinely inert arm pauses the target or uses one
  it is willing to lose.**
- **Do not** re-run S5b, and **do not** re-test the spare bytes: the same acceptance on a partition
  with no VTL1 is what settles them, and that control has been taken.
- **Aiming is what is closed; scope is not, and the route stays open.** A draft of this block said
  S5b closed the parent-side candidate, and Codex was right that it does not: with no VTL selector
  in the ABI, an intercept is either implicitly VTL0 or implicitly **every VTL**, and the second
  needs no selector because it would already deliver a VTL1 exception to the parent. S5's pass
  condition is untouched, and this run provoked no exception and held no intercept port, so it
  cannot tell the two apart.
- **So S5 has two live candidates, and interception is the first of them.** *Does a parent-installed
  exception intercept fire for a VTL1 exception?* Two ways in: a static read of `hvix64.exe`'s
  intercept dispatch for a check on the active VTL — two attempts have failed on that image, and
  Ghidra is on this bench now where it was not then — or a live test, which needs a port of its own
  to receive on and a VTL1 exception that is **not** a planted `int 3`. Cheaper than the second
  candidate, and it would make it unnecessary. **Half-answered on 2026-09-28 by S5h, below, taking
  the live route**: S5g's enclave supplied the VTL1 exception, and a `#BP` raised there is held and
  handed back without any port — so the *behaviour* was measured while the scope was not: the live
  test cannot separate the hypervisor taking the trap in VTL1 from it taking a VTL0 event that
  dispatching the VTL1 exception produces. **Fully answered on 2026-09-29 by S5i**, which took the
  other way in this bullet names and found the parent's mask seeded into every enabled VTL's
  effective bitmap. Both ways in were needed in the end, and neither made the other unnecessary.
- **The second was measured as S5c on 2026-09-28** — `HvCallSetVpRegisters` (`0x0051`) writing
  `HvRegisterExplicitSuspend` — and it **works, without being the stop S5 asks for**. See below.

#### S5c — **RUN 2026-09-28: the VP stops, VTL1 is readable stopped, and S5 does not pass**

**A parent can halt a running child's virtual processor and read its VTL1 while it is halted** —
`HvCallSetVpRegisters` writing `HvRegisterExplicitSuspend`, with no guest-side code, no exception,
no intercept and no port. VP runtime while suspended was **430** (control, VTL0) and **1,032**
(test, VTL1) per 2000 ms against an idle band of **41,291–84,075**, with a no-suspend null model
beside it. Refused with `0x0015` at VTL1 on the twin with no VTL1, so the `TargetVtl` field is
validated. The full record is the
[S5c result](docs/secure-kernel/secure-kernel-hypercall-feasibility.md) section.

- **It is a VP stop, not a VTL1 stop.** Set by naming VTL1, `ExplicitSuspend` reads `1` at VTL0
  too; the symmetric arm — naming VTL0 on the same VBS guest — reads `1` at VTL1 and stops the VP
  just as hard. One VP-wide suspend behind a VTL parameter that decides who may ask, which is the
  same shape S5b found on the intercept block.
- **S5 still does not pass, and this is the reading rather than modesty.** Its condition wants a
  stop *of VTL1*, at a *chosen point*, *delivered* as an event. This is the whole VP, at an
  arbitrary point, found by polling. `ActiveVtl` read `0` in all 80 read-only samples and in every
  arm, so Secure Kernel was never caught executing.
- **What is genuinely new is the inspector, it must halt *every* VP, and the whole of it has now
  run as one thing.** Stop the guest, read VTL1 registers (H3) and VTL1 memory by **whichever of
  the two routes serves each page** (H4's direct route alone returns a zero page for the very
  address S5e walked to), resume. One halted VP brackets per-VP register reads and does **not** make memory
  consistent — a second VP goes on running Secure Kernel and mutating the page tables a walk reads,
  which is S4's "identical only at the instant of the first read" arriving on the read side.
  `s5d.py` drives `h3probe.sys` and LiveCloudKd's `hvmm.sys` in one process, with the SDK's own
  freeze and pause **off** so the only stop is the measured one: both VPs halted (`SUCCESS`,
  runtimes 11,149 → 379 and 32,119 → 188), **3 of 3** VTL1 GPAs returning content while halted,
  each read twice inside the halt and agreeing 3/3, with two of the three (across two boots,
  so a recurring value rather than one state read twice) byte-identical to H4's
  recorded values. **Not** shown: that the halt was necessary — the same double reads while running
  were stable too, because an idle guest changes nothing and these guests cannot be loaded from
  this host.
- **S5e joined the halves by data flow, and the answer is that the routes are complementary.**
  Those three GPAs were preselected, so they never tested whether the halted *registers* can drive
  the memory path. Taking `CR3` from the halted VP and walking it through the direct route
  **works** — `PML4E[496]` → `PDPTE[24]` → `PDE[76]` → `PTE[400]`, all present with sane flags —
  and the leaf reads too, **through the hypercall rather than the direct route**. Censused whole,
  4,096 bytes each: the `RIP`'s leaf `0x81F000` gives 0 non-zero bytes direct and **4,084** by
  hypercall; `0x3BE1000` gives 200 direct and 0 by hypercall; the page table itself 8 direct and 0
  by hypercall. **Each page readable by exactly one route, and which one differs per page** — so a
  live inspector tries both per page, and neither alone reads VTL1's address space. **One address
  walked, three pages censused** — enough to show the chain completes, not enough to claim an
  arbitrary VTL1 address will: which property decides the serving route is unmeasured and is the
  open question, and H4's `0x3600000` is unretested by either route.
- **A correction to H4 fell out of it**: its "the VTL1 `CR3` page reads as zeros by both routes" is
  a **16-byte prefix** of a page whose first present entry is at offset `0x830`. Read whole, it has
  122 non-zero bytes and **26 present entries**. What proves the row wrong is H4's *own* table for
  that boot — first present entry at offset `0x850`, so a 16-byte read returns zeros whether or not
  the page reads. The S5e census is a **later boot** (the guest restarted 2026-09-27; self-map at
  index 463, not 388) and is not a second opinion on the first: **a VTL1 `CR3` value can repeat
  across boots**, so `CR3` equality is not evidence of the same boot — which is what made two
  correct censuses look contradictory. The same prefix trap caught this gate's own step 3 at 64
  bytes, and its census helper again at the wrong extent. **A prefix is not a page.**
- **Do not** re-run S5c's controls; the suspend bit, the refusal code and the VP-wide scope are
  taken. **Do** read the record before building on the halted context, and note what it does *not*
  say: over eight halt cycles the VTL1 `RIP` equalled its own pre-halt value 8/8 while the
  **VTL0**-labelled `RIP`/`RSP` came back as the VTL1 values 8/8 — but **every** reading in the
  gate was taken with `VsmVpStatus.ActiveVtl = 0`, and a sampler that took 8,000 reads across both
  VPs with no delay caught `ActiveVtl = 1` **zero** times. The halt with Secure Kernel actually
  executing is unmeasured and unreachable from this bench. **And the condition cannot be enforced
  with what this gate has**: reading `ActiveVtl` before the suspend races entry into VTL1, and
  reading it after depends on the suspension preserving it — which is the same unresolved question
  as the VTL0-labelled `RIP` reading as VTL1's. There is no atomic stop-and-observe here, so the
  condition is reportable and not checkable. The record states the observation with its condition
  and gives no consumer rule at all, three attempts at one having been three review findings.
- **S5f, 2026-09-28: the guests were reachable the whole time, over PowerShell Direct.** "Neither
  guest answers ICMP or WinRM, so there is no way to load them" appeared three times in the record
  and equated *no network path* with *no guest access*; `Invoke-Command -VMName` needs no network
  path and no WinRM, wanting a running Windows guest, Hyper-V administration on the host, the VMBus
  and guest credentials. Three things follow, and only the first two are results.
  **The register interface is live for VTL0** (and only VTL0: the spin ran there, every sample is a
  VTL0 `RIP`, and a live VTL0 read is compatible with an inactive VTL1 query returning saved
  context — so the VTL1 readings rest on an instrument validated for the other VTL) — under a
  user-mode spin, 110,638 samples per VP return
  **6,675 / 6,603 distinct** VTL0 `RIP`s, **88%** of them ring-3, so S5c's whole instrument samples
  the running processor rather than a cached exit record, which nothing had checked. **The stop,
  measured on a busy guest, is 23,854×** — 19,512,433 → **818** → 19,447,557 per 2000 ms, before
  and after within 0.3% — against the 40× the idle guest could show. And **the two open questions
  stayed open**: `ActiveVtl = 1` was never observed in **832,560+** samples now spanning idle, a
  two-VP spin and **twelve freshly loaded HVCI-verified kernel images**, and the halt's necessity
  is still unshown (80,399 reads over a matched 3 s window, one distinct value per page — those
  pages are static and a user-mode spin does not mutate SK's memory).
- **Why VTL1 cannot be caught here is now a number, and it names the next experiment.** What holds
  a VP in VTL1 long enough to sample is a **trustlet** (an IUM process, VTL1 *user* mode), not an
  HVCI check. This guest has one, `LsaIso`, and it is inert: **0.3593750 s of CPU in 27.6 hours**,
  unchanged to the tick across a logon burst, because Credential Guard is not configured
  (`LsaCfgFlags` unset, `RequiredSecurityProperties = 0`). At that duty cycle 832,560 samples expect
  about **1.5** hits if that time were spread evenly across two VPs -- 832,560 is the combined
  total, which an earlier draft divided as though it were per-VP and called ~3 -- and under uniform
  sampling zero still has roughly a **22%** probability. So this is *compatibility with rare
  `LsaIso` activity*, *not* validation of the sampler; S5g's known VTL1 workloads later produced
  zero hits too, which points at `ActiveVtl` not reporting rather than at the sampler missing.
- **S5g, 2026-09-28: one route closed, one unresolved, and the enclave route OPEN and measured.**
  Run with the
  operator's authorisation to reconfigure and reboot the VBS guest. **Credential Guard** is **unresolved**, and an earlier
  draft wrongly closed it *by edition* — Microsoft's table says Windows Pro: No, but the operator's
  Pro machine reports Credential Guard protecting it and this bench's own Pro host runs `LsaIso`,
  so Pro does run it; worse, that host reads `SecurityServicesRunning = 0` while its UI says CG is
  on, so the field the guest was judged by is not a sound test. What was seen: `LsaCfgFlags`, the DeviceGuard scenario key and `EnableVirtualizationBasedSecurity`
  all set, **Secure Boot `On` for both reboots** (a documented CG prerequisite, disabled only later
  for the enclave route, so not a confounder), `SecurityServicesRunning` still `2` and no DeviceGuard
  events — because Microsoft's edition table reads *Windows Pro: **No***. `LsaCfgFlags = 1` is
  *enabled with UEFI lock*; `2` is without, and a repeat on an eligible edition should use `2`. **Writing a trustlet** is closed by
  signing policy: IUM needs a Microsoft certificate with the IUM EKU plus membership in SK's
  identity list, and test-signing is deliberately not honoured there. **A VBS enclave WORKS**, once Microsoft's
  `windows-classic-samples/Samples/VbsEnclave` was used as the reference rather than building from
  first principles: `LoadEnclaveImage ok` / `InitializeEnclave ok`, and our own `Spin` running **in
  VTL1 user mode**. The decisive difference was `PolicyFlags = IMAGE_ENCLAVE_POLICY_DEBUGGABLE`
  against the `0` used here while the host passes `ENCLAVE_VBS_FLAG_DEBUG`; beside it non-zero
  Family/Image IDs, a 0x10000000 size the host must match, **no `/ENTRY` override** so the enclave
  CRT starts, `/GUARD:MIXED`, `SubSystem CONSOLE` and a `.def`. Before the reference it was: `CreateEnclave` with the debug flag succeeds every run, and
  `LoadEnclaveImage` refuses with **193 `ERROR_BAD_EXE_FORMAT`** through nine eliminated suspects —
  enclave config, load config, page hashes, a `vertdll` import, the enclave-signing EKU, TLS, the
  enclave CRT, `/INTEGRITYCHECK` (which moved characteristics `0x160` → `0x1E0`), and chain trust
  (in-guest status `UnknownError` → **`Valid`**). Test-signing moved the error 577 → 193 and trust
  left it at 193, so the signature path is satisfied and an unidentified **shape** rule remains.
  **Done — that diff is what opened the route**: Microsoft's sample was used as the reference and
  the differences are listed above, so do not repeat it. Note `veclient.lib` does not exist in SDK 10.0.26100; `vertdll.lib` was used
  instead and whether that substitution is the defect is unmeasured.
- **The condition every halted-register reading was qualified on is now measured, and `ActiveVtl`
  is not the way to it.** With the enclave spinning and the VPs measurably busy (**25.8%** and
  **52.4%** by `HvRegisterVpRuntime`), `ActiveVtl` still read `0` in 274,566 samples — so the parent
  cannot use it to tell whether VTL1 is running. Halting anyway catches VTL1 mid-execution: **6 of 6
  halts** found VP 1's VTL1 `RIP` in **user mode inside the enclave** (`0x21456DE509B`–`…50BC`, five
  distinct addresses across six halts, each stable over 10 reads within its halt), while VP 0 stayed
  parked at Secure Kernel's `0xFFFFF80679FB0035`. So the halted VTL1 context behaves exactly as it
  did parked — readable, frozen by the halt, its own rather than VTL0's — and **#411's scoping of the
  liveness result to VTL0 is superseded: the VTL1 read is live too.**
- **A method error was caught by that same measurement.** An earlier "zero while our code spins in
  VTL1" used `Invoke-Command -AsJob`, and each PowerShell invocation here is its own process, so the
  job and its session died with the call — VP runtime read **0.7%** busy while the spin was
  supposedly running. A guest-side workload only exists when **detached** with `Start-Process`,
  which is why the CPU-load arms were real and the first enclave ones were not.
- **`ActiveVtl` has now read `0` in over 1.15 million samples across four workloads** — idle, a
  user-mode spin, twelve HVCI-verified kernel image loads, and an enclave create/terminate loop.
  **The fourth is weaker than it first looked**: `CreateEnclave` does log a `Secure Trustlet
  started/stopped` pair, but counting them gave **ten in three minutes against 400,000 cycles**, so
  the creates after the first are mostly VTL0 bookkeeping and "a sustained VTL1 workload" was a
  claim from a mechanism rather than a count. Two readings still fit — VTL1 windows shorter than
  the ~55 µs sampling interval, or **the parent-side `ActiveVtl` cannot report a VP executing
  VTL1** — with the second now likelier and neither established.
- **The VBS guest is changed and a later gate must know.** Secure Boot **off**, test-signing **on**
  (VBS/HVCI verified still running after both), a self-signed `CN=VTL1 Enclave Test` cert in
  `LocalMachine\Root`, Credential Guard keys set and inert, `C:\encl\` staged, and **four reboots**
  — so the `CR3`, self-map index and SK base have all moved again from the figures in S5c–S5f.
- **Bench note (historical, S5f only — the S5g reboots cleared them; verified none running).**
  Eleven inbox driver images started in the VBS guest to provoke VTL1 would not stop
  and stay loaded until it reboots. Harmless — drivers for hardware the VM lacks — but a later gate
  reading its module list should know why they are there.
- **S5h, 2026-09-28: a VTL1-raised exception is held and handed back.** S5g's enclave supplies a
  VTL1 exception that is not a planted `int 3`, so S5b's leftover could finally be provoked. What
  came back answered the *behaviour* and not S5b's scope question — **S5i settled that separately
  on 2026-09-29**, by reading the hypervisor; the retraction two bullets down is about what the
  halt evidence could carry, and it stands.
  One binary raises `#BP` in both VTLs and counts what
  its own `__except` catches, so the arms differ in the VTL and nothing else. With the intercept
  standing, **the guest handled 0 of 20,000 in every arm** — 120 consecutive zero samples over 24.4 s
  in VTL0, in VTL1, and on the VTL0-only twin, and 198/218/291 zeroes over 40–60 s in runs without a
  release. **Removing it mid-arm lets all three finish 20,000/20,000**, so the traps are *held and
  handed back*, not discarded — a resumable stop rather than a swallowed exception. Both controls
  hold: an intercept on `#BR` that nothing raises, and a `#DE` raised against a `#BP` intercept, each
  leave both VTLs at their null rates (`0.82–0.96 us` VTL0, `9.36–10.12 us` VTL1). The guest keeps
  serving while an intercept stands — a second PowerShell Direct connection answered during every
  arm — though that says the partition is not wedged and **not** that only the raising thread was
  held, which nothing here arranged a control for: treat a standing `#BP` intercept as freezing
  every thread in the partition that raises that vector. No intercept was left standing and no
  guest needed a reboot. Full record, with the arm tables, in the
  [S5h result](docs/secure-kernel/secure-kernel-hypercall-feasibility.md) section.
- **Two claims in the first write-up of that gate are retracted, both found by review.** *"Six halts
  catch the VTL1 arm inside the enclave, which rules out a VTL0 excursion being what is
  intercepted"* — it does not: a VTL1 exception reflected into VTL0 leaves VTL1 **saved at the
  faulting instruction** while VTL0 sits in kernel code, which is exactly the pair measured, so the
  halt discriminates nothing. The VTL0-labelled read lands in Secure Kernel's own page, which is the
  S5c anomaly's signature rather than a trustworthy VTL0 context, and the 11x cost of a VTL1
  exception over a VTL0 one is if anything a reason to take the excursion seriously. And *"only the
  raising thread is held"* was inferred from a connection that raises no `#BP` at all. **What would
  settle the first** is the route S5b named and this gate skipped: `hvix64.exe`'s intercept dispatch,
  read for a check on the active VTL. **Run as S5i on 2026-09-29, and it found one**: the check is
  at install time rather than in delivery, and it sets the VTL to 0 for any child while seeding that
  slot into every VTL's effective mask — so the intercept does cover VTL1 and the retraction above
  stands as a statement about the halt evidence, not about the conclusion. **And the other route
  S5h named — *delivery metadata from an actual receiver* — was taken by step 9's VTL1 arm on
  2026-09-30 and settles it**: the intercept message's `Rip` is the **enclave's** `int3`, matching
  this halt table's VTL1 value in its low 16 bits on a different boot. An intercept fired on a VTL0
  excursion would name the VTL0 instruction, so the excursion is excluded and the trap is taken at
  the VTL1 raise.
- **The first four runs read the VTL1 arm as *advancing* and that is retracted.** The counts
  reported — 1,902, 6,396, 15,076, 18,486 — were all written by the monitor's final sample, *after*
  teardown removed the intercept and the raiser finished, and one of them became a "405x slower but
  advancing" rate supporting a reading in which the two VTLs were reached differently. The trace says
  the count first moves at sample 121/121 and 219/219. **Read where a count first moved, not what it
  ended at**; the last sample is on the wrong side of the release.
- **S5i, 2026-09-29: the dispatch read is done, and the intercept reaches VTL1 by design.** The
  route S5b named and S5h skipped, run against this host's own `hvix64.exe` `10.0.26100.9444`
  (SHA-256 `CF5AF317…40CE8A`) with [`tools/sk_vmcs_scan.py`](tools/sk_vmcs_scan.py). **It worked
  where two earlier attempts failed because it asked an architectural question instead of a
  structural one**: on Intel VMX an exception intercept *is* the VMCS exception bitmap, field
  `0x4004`, so the anchor is one constant in one instruction rather than a table to recognise. Five
  steps carry it: `HvCallInstallIntercept` at `+0x295800`; the VTL decision at `+0x295879`, which
  compares the target partition against `gs:[0x360]` and sets **VTL := 0 for any child** while the
  self branch takes the caller's own VTL and refuses VTL 0; `InterceptType == 3` landing at
  `+0x2C9430`, which ORs `1 << vector` into `array[VTL].0x1A04` indexed `[partition + VTL*8 +
  0x63C8]`; the recompute at `+0x2BECC8`, which descends the enabled-VTL set **seeded with
  `array[0].0x1A04`** so that a parent's mask lands in *every* VTL's effective mask at `+0x1A0C`;
  and `+0x331AA8`, which programs the bitmap for whichever VTL the VP is running. **So S5b's scope
  question closes in the second direction — implicitly every VTL — and S5h's hold was genuine VTL1
  interception.** #412 was right to withdraw that claim from the halt evidence, which did not carry
  it; the claim is true on different evidence. Full record, with the cross-checks against S5b's live
  arms, in the [S5i result](docs/secure-kernel/secure-kernel-hypercall-feasibility.md) section.
- **The Secure Kernel limit narrows but is still not measured.** A VMCS exception bitmap does not
  distinguish CPL 0 from CPL 3, and step 5 selects it by VTL alone, so nothing in the mechanism
  separates VTL1 *user* mode from VTL1 *kernel* mode. That retires the specific reason to doubt the
  extension to Secure Kernel's own code without making it a measurement, and S5a's prohibition on
  planting an `int 3` there to check is unchanged.
- **S5j, 2026-09-29: the message is already addressed to the parent, and binding to it may displace
  Hyper-V's handler.** The gate's first half, run with the same instrument as S5i
  plus `winhvr.sys` and `Vid.sys` read with symbols. **Routing**: `HvMessageTypeX64ExceptionIntercept`
  (`0x80010003`) appears once in `hvix64.exe`, at `+0x2C9A9E`; the recipient is chosen at `+0x2C95B8`
  by scanning VTLs from the active one upward and then wrapping to the lowest, delivering to the
  first whose **own** `+0x1A04` holds the faulting vector. A `#BP` in VTL1 whose vector the parent
  installed therefore wraps to VTL0, matches, and is delivered as a VTL0 intercept — and `+0x2EB134`
  forks on that byte, sending VTL0 to the parent-directed post at `+0x2EC204` and any higher VTL to
  its own SynIC. **So nothing needs redirecting — the route is not what is missing**, and
  **what happened at the other end is not established** — the read shows where the message is sent,
  and `Vid.sys` has a handler for this very type, so "nothing was bound" and "the existing handler
  received it and retained it" are both live explanations of S5h's hold, wanting different next
  gates. Telling them apart is what comes next. **S5k, below, killed the first and added a third**:
  Vid is bound, and its handler *drops* a message whose vector nothing claimed — which competes with
  the second rather than retiring it, the two being separated by a runtime byte S5k did not read.
  **Build**: the plan's hand-rolled `HvCallCreatePort`/SynIC page is the wrong build. `winhvr.sys`
  exports the lot — `WinHvCreatePort`, `WinHvConnectPort`, `WinHvAllocatePartitionSintIndex`,
  `WinHvGetSintMessage`, `WinHvSetEndOfMessage`, `WinHvSetInterceptRoutine` and
  `WinHvCompleteIntercept`, which is **half** of the resume a debugger needs — for a *software*
  exception Vid first calls `VidInterceptAdvanceInstructionPointer` and only then completes, and
  without that advance the faulting instruction is re-entered rather than resumed — and `Vid.sys`
  already consumes
  them, including a `VidExceptionInterceptReturnCallback` for this very message type.
  **Hazard, and it is why this is a finding rather than a green light**: `WinHvSetInterceptRoutine`
  stores **one** routine and context per table entry, assigned rather than chained, and `Vid.sys`
  imports it. **What follows from that is narrower than an earlier draft said**: the import proves
  `Vid.sys` calls the function, not that its call selects the same entry ours would, so whether a
  registration displaces anything turns on the table's key — which this read did not identify.
  Per-partition means one child; per-message-type or per-SINT means every VM on the host, since the
  displaced handler services IO-port, MSR and CPUID intercepts; an allocated per-client handle means
  no displacement at all. Assume displacement because the cost of being wrong is asymmetric, and
  **do not call `WinHvSetInterceptRoutine` on this bench until the key is known** — read it from `Vid.sys`'s own call sites, which pass it.
  **S5k read them: the key is the partition id, so the blast radius is one child — and the
  prohibition hardens into a permanent one**, because the routine a registration would displace is
  the one that dispatches to Vid's own per-vector table. Do not call it at all. Full record in
  the [S5j result](docs/secure-kernel/secure-kernel-hypercall-feasibility.md) section.
- **S5k, 2026-09-29: an unclaimed vector is dropped inside `Vid.sys`, and the receiver is an IOCTL
  rather than a build.** Both reads S5j called for, against the same two images — `winhvr.sys` `10.0.26100.8972`
  and `Vid.sys` `10.0.26100.9278`, opened as DbgEng image targets with public PDBs. **The table
  key** is the `HV_PARTITION_ID`: `WinHvSetInterceptRoutine` (`+0x8020`) calls
  `WinHvpReferencePartition`, which binary-searches `WinHvpPartitionArray` by 64-bit key and fails
  with `0xC035000D`, *"a partition with the specified partition Id does not exist"*; the routine and
  context land at `+0x10`/`+0x18` of the partition object, and `WinHvpOnInterception` (`+0x4438`)
  looks the same array up by the message header's **Sender** and calls exactly that pair. So the
  blast radius is **one child**, displacement is real, and Vid's only two call sites are an
  activate/deactivate pair on that one field — it relies on assignment replacing. The slot is also
  written at creation (`WinHvpCreatePartitionObject`, `+0x1D42C`), so holding it without displacing
  anyone means creating the partition. **Vid's path**: `VidInterceptIsrCallback` has no filter that
  could lose an exception intercept, `VidInterceptPreprocess` recognises `0x80010003` through a jump
  table at RVA `0x3D137` and selects `VidHandleExceptionIntercept` — which then gates on
  `byte [[partition+0xB68] + vector]`, a `0x100`-byte per-vector table `VidPartitionInitialize`
  fills with `0xFF`. **`0xFF` means no registration, and the handler returns 0 having enqueued
  nothing.** What claims a slot is `VidHandlerpExceptionRegisterEntry` (`+0x63B80`), and it does so
  *before* calling `WinHvInstallIntercept` with the byte-for-byte descriptor S5b read — type 3,
  `AccessType` 4, the same vector field — reached from `VidHandlerIoctlExceptionRegister`
  (`+0x63630`). **So S5b's install was not wrong, it was half of the arming sequence**, and the half
  it skipped is the half that makes anyone listen. Of S5j's two explanations of S5h's hold the first
  is dead — Vid was bound and its routine ran — and the second gains a **competitor rather than a
  refutation**: the drop. **Which of the two S5h met turns on `[partition+0xB68][3]`, a runtime byte
  this gate did not read and nothing already measured stands in for.** An attempt to substitute
  S5h's controls was retracted in review: Vid's register and unregister paths do set and clear the
  slot and the hypervisor intercept together, but `h3probe.sys` writes that mask too — **every probe
  install is paired with a raw `AccessType = 0` removal that touches nothing in `Vid.sys`** — and
  whether that removal clears the shared bit is unread, S5i having read the install as an
  unconditional `OR` and not the removal. An implication needing *no other writer* to be able to
  clear the bit is therefore unestablished, which retracted the argument whichever way the removal
  turned out — **and S5l then read the removal clearing the bit, so it is false rather than merely
  unestablished.** What settles the question itself is reading that byte **inside a replicated
  intercept arm** — it is mutable, so a later read reports the reproduction and says nothing about
  the historical runs beyond an unchanged bench — and it comes before the IOCTL read.
  **Second hazard, mechanism confirmed by S5l**: a VID client holding a vector this probe installs
  *would* have its intercept stripped by the probe's teardown while Vid went on believing it armed,
  silently, on the child under test. Six runs executed that teardown and none read the slot, so
  what is established is the exposure, not a loss. **New hazard**: `VidInterceptPreprocess` ends its switch in `__fastfail(FAST_FAIL_INVALID_ARG)`
  in the **root** — a host bugcheck, not a guest one — for any intercept message type it does not
  handle, including the holes `0x80010005`, `0x80010009`–`0x8001000F` and `0x80010012` inside the
  range it otherwise covers. Full record in the
  [S5k result](docs/secure-kernel/secure-kernel-hypercall-feasibility.md) section.
- **S5l, 2026-09-29: the exception mask is one bit with no owner, so an install/remove pair is not
  free.** The removal read S5k left open, same image and instrument as S5i — `hvix64.exe`
  `10.0.26100.9444`, `--self-test` 20/20, `+0x1A04` still 9 sites / 2 writers and `+0x6124` still
  6 / 3. **Install and remove are the same function and the same bit**: `+0x2C9430` branches on
  `AccessType` alone — `or edx, 1 << vector` for `4`, `not`/`and` for `0` — stores back to
  `array[VTL].0x1A04` and calls the `+0x2BECC8` recompute S5i read. **No refcount, and nowhere for
  one**: two writers in the whole image, this store and a partition-teardown zeroing, and a 32-bit
  bitmask has no room to count. So **two parties holding one vector are one bit**, and since removal
  is a plain `and ~bit` the **first** removal clears it for both, whichever party makes it — so the
  probe's `finally` would strip a VID client's intercept while `[partition+0xB68]` still said armed.
  The hazard's *mechanism* is established; whether a client ever held one is not, no arm having read
  the slot. The controls
  argument S5k retracted is **false on a probed child** rather than merely unestablished. It does
  **not** say which branch S5h met — that is still the replicated arm. **Three bounds read free
  from the same 215 bytes**: `AccessType` must be exactly `0` or `4` (status `5` otherwise, which
  is where S5b's negative control landed); the vector is a `word` at `+8` of the
  `InterceptParameter` and must be `<= 0x1F`; and a per-partition allowed-vector mask at `+0x6124`
  gates installs **except** that target VTL 0 admits vectors `3` (`#BP`) and `4` (`#OF`)
  unconditionally — which, with S5i's "a parent naming a child always installs at VTL 0", is why
  `#BP` on a child never depended on the partition's configuration. **No remediation, and the one
  that suggests itself does not work**: reading a slot before installing is a *diagnostic*, not a
  guard, because the per-partition lock serialises one update and not
  read-then-install-then-remove — a client registering inside that window still loses its bit.
  Making the pair safe needs exclusive coordination with every other installer, which nothing here
  has. The diagnostic itself would be Vid's `[partition+0xB68][vector]`, not the hypervisor mask
  (`array[0].0x1A04` is hypervisor memory the root cannot read, and the ABI has no query beside its
  install and remove). **Even that read is not available on this bench**: local kernel debugging is
  off (`bcdedit /dbgsettings` says
  `debugtype Local`, which is the global store, not the boot entry; `{current}` carries no
  `debug Yes` and `attach_kernel_local` answers `0x80004001`), so it needs a host reboot into debug
  mode or a kernel-read path in `h3probe.sys`. Until then the constraint stands without a remedy:
  an install/remove pair is not free. Full record in the
  [S5l result](docs/secure-kernel/secure-kernel-hypercall-feasibility.md) section.
- **S5m, 2026-09-29: the receiver is a user-mode export, and there is no driver left to write.**
  The IOCTL read S5k named, against `Vid.sys` `10.0.26100.9278`, `vid.dll` `10.0.26100.8457` and
  `WinHvPlatform.dll` `10.0.26100.9278`. **The code is `0x221148`** —
  `CTL_CODE(FILE_DEVICE_UNKNOWN, 0x452, METHOD_BUFFERED, FILE_ANY_ACCESS)`, read from
  `VidIoControlPartition`'s compare chain, with input `{ u8 Vector; u8 pad[3]; u32 Parameter;
  u64 Context; }` and an `8`-byte handle out. `FILE_ANY_ACCESS` is not the access control: the
  dispatcher is reached with a *partition* in `rcx`, so what gates it is holding a partition handle.
  **`vid.dll` exports a wrapper for it** — `VidRegisterExceptionHandler`, one of 215 exports,
  carrying that code and layout into a single `NtDeviceIoControlFile` — **and exports attach,
  receive, complete and unregister beside it**: `VidAttachPartition`, `VidGetHvPartitionId`
  (which translates a VID handle to the `HV_PARTITION_ID` every hypercall gate has been passing),
  `VidMessageSlotMap`, `VidSetupMessageQueue`, `VidMessageSlotHandleAndGetNext`,
  `VidHandleMessageAndGetNextMessage`, `VidUnregisterHandler`. **So no driver, no port, no
  hypercall** — the third downward re-scope in a row, each one deleting the build the previous gate
  specified — **conditional on getting a partition handle**, which every call in the sequence takes
  and which this gate does not test; if a second process cannot obtain one for a running VM, the
  sequence is unavailable and a driver may be back on the table.
  **But it is not a documented call**: `WinHvPlatform.dll` delay-imports 31 `vid.dll`
  functions and this is not one of them — what WHP imports is the *Exo* family, its own partitions'
  mechanism. So S5 is not one supported call from passing; it is one *observed, exported* call from
  passing, which is a different and weaker thing to build on.
  **It covers S5l's hazard for one class of owner, not in general**: the kernel side refuses a
  claimed slot with `STATUS_VID_DUPLICATE_HANDLER` before touching the hypervisor, and unregister
  clears slot and bit together — but that check reads `[partition+0xB68]`, so it sees only parties
  that registered *through Vid*. A raw `WinHvInstallIntercept` owner — this plan's own probe since
  S5b — leaves the slot `0xFF`, a Vid registration succeeds beside it, and unregister later clears
  the shared bit out from under them. The rule that follows is *one installer per vector per
  partition, and let it be the Vid registration*, not "the hazard is solved".
  **And the registration's return value supersedes the replicated arm** S5k and S5l wanted —
  **read as `GetLastError()`, not as the `BOOL`**: the wrapper passes failures through
  `RtlNtStatusToDosError`, and VID-facility statuses have no Win32 mapping, so `0xC0370001` comes
  back verbatim and is unambiguous against invalid-handle (`6`), access-denied (`5`) and
  allocation failure (`1450`) — all measured. Duplicate means the slot was claimed, success means
  it was `0xFF`, anything else classifies nothing. Full record in the
  [S5m result](docs/secure-kernel/secure-kernel-hypercall-feasibility.md) section.
- **S5n, 2026-09-29: a VID partition takes no second *open*, so the receiver has no reachable
  handle.** The first live arm since S5h, and it cost the bench nothing: no VM touched, no
  intercept installed, no reboot. Opening a partition is one `CreateFileW` on
  `\\?\root#vid#0000#{7896e901-fe60-446e-828d-d65920654a23}\<VM Id>` with `OPEN_EXISTING` —
  the path `vid!VidpCreateVidObject` builds, with `GUID_DEVICEINTERFACE_VID` read out of `vid.dll`.
  **Both running guests' VM Ids refuse with `ERROR_BAD_COMMAND` (22)**, while a well-formed unused
  name **opens** and a malformed one gives `0xC0370005` — so the name is recognised and the open
  refused rather than not found. **Two controls reproduce `22` with no VM in them**: a second open
  of the same name fails under either share mask and frees when the handle closes, and — across two
  processes — a name a *child* holds refuses the parent while a **different** unused name opens at
  the same moment. So the rule is global rather than per-process, and per name rather than per
  device; it is not share-mode negotiation.
  **What that does not establish** is that the live VM's `22` has the same cause: `0xC0000184` has
  62 sites in `Vid.sys` and the create dispatcher was not located, so the controls narrow the
  alternatives without eliminating them. The constraint measured is *no second open*, not *one
  handle* — `DuplicateHandle` and inheritance are untested and untried — and the caller was never
  varied, so privilege is an unlikely explanation rather than an excluded one.
  **Also corrected**: `VidAttachPartition` is not "join a partition". IOCTL `0x221014` reaches
  `VidPartitionIoctlAttach`, which loops the VPs calling `VidVpAttach` — the VM worker's *start the
  virtual processors* operation. It was not called.
  **So S5's obstacle has changed shape**: the mechanism exists and is exported, and what blocks it
  is a refused open. A stopped-VM arm
  was proposed and **dropped**: stopping the guest moves both candidate causes at once, and if the
  partition object goes with the VM then its Id is just another unused name, so neither outcome
  discriminates. The order of what was left runs in the numbered plan below rather than here. Full
  record in the
  [S5n result](docs/secure-kernel/secure-kernel-hypercall-feasibility.md) section.
- **S5o, 2026-09-29: the refusal is a partition-state test with no token in it, and the branch
  behind it is an ownership handoff.** A static read of `Vid.sys` — DbgEng opening the image as a
  target, no debuggee, nothing executed — answered the plan's next **two** steps at once.
  `Vid.sys` is KMDF, which is why S5n could find no `IRP_MJ_CREATE` dispatcher — not for want of a
  `MajorFunction` table, which `Wdf01000!FxDriver::Initialize` fills with the framework's own
  dispatch for all 28 entries, but for want of a *VID-owned* one. The callback is
  `VidFileCreate` → `VidFileObjectCreate`, and the refusal is a single site testing
  `[partition+0x3060] == 2` and `[partition+0x3079] == 1`. **It consults no token**, so the
  `SYSTEM` arm cannot change the outcome and was not run — and the one token check on the path,
  `VidSidPartitionCheck`, gates *creating* a partition, admitting any administrator outright and
  otherwise demanding the caller's own `NT VIRTUAL MACHINE` SID match the name. S5n's matched error
  becomes a **common cause**: on the non-Exo arm that site is the only `0xC0000184`.
  **And the branch behind the refusal is not what the plan wanted.** `VidPartitionAttach` makes the
  opener the partition's owning process — storing `PsGetCurrentProcess()` and switching the thread
  pool — and the one route into it this gate located runs through the current owner's detach IOCTL,
  which first calls `VidHandlerUnregister` and detaches every VP. So *on that route*, the step that
  would admit us dismantles the receive path S5m found. **This also corrects S5n on
  `VidPartitionIoctlAttach`**: it is the second half of a handoff, not merely "start the virtual
  processors", and it refuses a partition nobody has detached. **It is not established to be the
  only route in** — the gate enumerates no writers of either gating field, so another path into the
  admitting state would leave registration alongside Hyper-V open, and closing the question needs a
  writer census or live confirmation. It also decodes neither state value, reads one build,
  executed nothing, and leaves Exo partitions and handle duplication untouched. Full record in the
  [S5o result](docs/secure-kernel/secure-kernel-hypercall-feasibility.md) section.
- **S5 still does not pass, and after S5i there is one next gate rather than two.** Its condition wants a
  stop *delivered to a debugger*, and nothing here was delivered to **us** — this probe holds no
  port. That is not the same as nothing receiving it: the root's own stack owns a port for each
  child (S5b found eleven `Vid.sys` sites installing intercepts on children), and an exception
  intercept it never asked for landing there would produce exactly this hold — as would nothing
  being bound at all, which is why the next gate must tell them apart rather than assume one.
  **That first half was run as S5j, above, and it replaced the plan this bullet used to carry.**
  Establishing where the message goes was the right first step and it answered two things: the
  message is already addressed to the parent, so nothing needs redirecting; and the hand-rolled
  `HvCallCreatePort`/`HvCallConnectPort` plus SynIC page named here is **not** the build, because
  `winhvr.sys` exports the whole API and `Vid.sys` already consumes it. What is left is narrower and
  differently shaped, and it is **two reads, not one** — because S5j could not tell whether the hold
  it explains is an absent binding or Hyper-V's own handler keeping the intercept:
  - **The table key** that `WinHvSetInterceptRoutine` searches, from `Vid.sys`'s call sites and from
    whatever creates the entries. It decides whether a registration collides with Hyper-V's at all,
    and if it does, whether that costs one child or every VM on the host.
  - **Vid's own path for `0x80010003`** — preprocess, process, `VidExceptionInterceptReturnCallback`,
    completion. The key alone says nothing about *why the intercept stays outstanding*, which is the
    other live explanation of S5h's hold and the one a receiver would not fix. If Vid receives and
    retains it, building a second receiver is the wrong move whatever the key turns out to be.

  Only after both is there a receiver to build. The dispatch read that used to sit beside this **was
  run as S5i and is done**; nothing in it touches message delivery, so it neither helps nor blocks.

  **Both reads were run as S5k, and there is no receiver to build.** The key is the partition id;
  Vid is bound and recognises the message, and its handler drops one whose vector is not claimed in
  `[partition+0xB68]`, the per-vector table it consults. The receiving path — message,
  completion and instruction-pointer advance — already exists per partition and per vector, and what
  arms it is `VidHandlerIoctlExceptionRegister`, which claims the slot and *then* issues the same
  `WinHvInstallIntercept` S5b read. That pointed at a replicated arm reading `[partition+0xB68][3]`,
  **and S5m supersedes half of it.** The IOCTL has an exported user-mode wrapper, so *"is the slot
  claimed"* is answered by the registration's own return value, read as `GetLastError()`:
  `0xC0370001` means claimed, success means it was `0xFF`. **It does not supersede the other half**,
  because registering *claims* the slot — so a `#BP` raised afterwards exercises the registered
  receive path and cannot reproduce the unregistered drop, and a success says what the slot holds at
  that call rather than what it held during S5h. The other half, and the second candidate —
  **whether the hold is a loop**, since nothing on the drop path injects the exception or advances
  `RIP`, so the faulting instruction is presumably re-entered, an inference S5k did not measure —
  are **both blocked by the standing constraint below**, and the replicated arm additionally needs
  root kernel-memory access this bench does not have. **Both ran on 2026-09-30** once the
  constraint lifted and S5q's IOCTL supplied the kernel read — see step 6 below.

  **Standing constraint, from S5l: no arm may install an exception vector on a child until the
  teardown hazard has a remedy.** The pair is unremediable here — per S5l a pre-read is a
  diagnostic rather than a guard, and safety would need exclusive coordination with every other
  installer, which nothing on this bench has — so the removal can clear a vector another party
  holds. This is a property of *any* arm that arms and disarms a vector, not of a particular one,
  and it is written here rather than against each candidate because blocking them individually is
  how the loop arm stayed runnable after its twin was stopped. **It lifts on exactly two things**:
  an arm redesigned to install nothing, or a way to hold every other installer off for the window.
  Gaining the ability to read Vid's slot is **not** one of them — an earlier version of this
  sentence listed it, contradicting the line above it. A read is a diagnostic: a client can register
  between the read and the teardown, and the removal still clears its bit.

  **A `vid.dll` registration is not an exemption, it is the second lift condition partially met.**
  Vid claims and releases the slot with the bit, so it cannot collide with another *VID* client —
  the duplicate check holds every one of them off. It does not hold off a **raw**
  `WinHvInstallIntercept` installer, which leaves the slot `0xFF`, and against one of those the
  unregister still clears a bit it does not own. So the registration arm is permitted **only while
  no raw installer holds the vector**, and on this bench the only known raw installer is
  `h3probe.sys`, which this plan controls and is retiring for exception vectors. A third-party raw
  installer cannot be excluded, so this is a condition to check rather than a property to rely on.
  **Lifted 2026-09-29 by the operator, for guests the bench owns.** Both lift conditions above are
  about *other parties* — the constraint exists because a removal can clear a vector someone else
  holds. On a guest this bench owns and is willing to lose there is no other party whose loss
  matters, and the operator has authorised exactly that: the lab was built to be spent on this. So
  the constraint stands unchanged for any guest that is shared or that something depends on, and it
  does **not** block S5q below. Two things do not lift with it. The hazard S5q actually carries is
  not the one this paragraph is about — the receiver's callback runs in the **root's** dispatch
  path, where a fault is a host bugcheck rather than a guest one, and no authorisation about guests
  reaches it. And S5a's prohibition on planting an `int 3` in Secure Kernel is untouched: it is a
  different prohibition for a different reason, and S5r below is the route to that question that
  does not need it.

- **A working receiver would still leave Secure Kernel's own code untested**, which is now the only
  gap rather than one of two. Before S5i it was the mechanism question that governed it: an
  excursion-mediated hold would not have reached Secure Kernel at all. S5i retires that — the bitmap
  is selected by VTL and a VMCS bitmap is privilege-blind — so what remains is an architectural
  inference rather than an open mechanism. S5a's prohibition on planting an `int 3` in Secure Kernel
  to check is unchanged.

- **S5q — WRITTEN BEFORE THE RUN, 2026-09-29: chain Vid's intercept routine and receive a VTL1
  `#BP`.** With the standing constraint lifted above for disposable guests, the route S5k
  prohibited becomes the cheapest one to S5's pass condition. `WinHvSetInterceptRoutine` is a
  `winhvr.sys` **kernel** export keyed by `HV_PARTITION_ID` (S5k read the key out of
  `WinHvpReferencePartition`'s binary search), so a root driver reaches it with no VID partition
  handle at all — **S5n's and S5o's refused `CreateFileW` is a fact about the *user-mode* route and
  does not bind this one**, which is the thing the ordered plan below had stopped seeing. What S5k
  called a permanent prohibition was a policy about shared guests, and its stated cost — one
  child's intercepts — is one the operator accepts on a guest the bench owns.

  **Replacing the routine defeats the arm, so chaining is the design rather than a refinement.**
  `WinHvpOnInterception` (`+0x4438`) dispatches IO-port, MSR and CPUID intercepts through the same
  routine it looks up at `+0x10`/`+0x18` of the partition object, so a receiver that merely assigns
  over Vid's stops the child being serviced — and a child that is not serviced runs no enclave and
  raises no `#BP`. The receiver must save the previous routine and context, handle **only**
  `HvMessageTypeX64ExceptionIntercept` (`0x80010003`) carrying the vector it installed, and
  tail-call the saved pair for everything else. That else-branch is also what keeps the arm clear of
  `VidInterceptPreprocess`'s `__fastfail` holes (S5k): nothing is synthesised, only forwarded.

  **The swap is not atomic, and the ABI offers nothing that would make it so.**
  `WinHvSetInterceptRoutine` stores the routine and the context in two separate stores and
  `WinHvpOnInterception` loads them in two separate loads, so an intercept dispatched *during*
  either the install or the restore can pair the new routine with Vid's context, or Vid's routine
  with ours — and either is the host bug check this gate exists to avoid, with both callbacks
  perfectly correct. There is no quiesce: nothing exported pauses or drains intercept dispatch for
  a partition, so this cannot be remedied, only narrowed and declared. **What narrows it** is the
  ordering the arms use, which is deliberate rather than incidental: chain **before** arming any
  vector and remove the vector **before** unchaining, so no exception intercept is ever armed
  across a swap and only an IO-port, MSR or CPUID intercept could land in the window. **What it
  does not do is close it**, and the window is real on any busy partition. Both arms swapped with
  the forward counter at zero throughout, so on this bench it was never exercised — which is an
  absence of dispatch, not evidence that the race is benign.

  **Build**, all in `h3probe.sys`: a kernel-read IOCTL — the capability S5l named as missing, which
  unblocks the replicated `[partition+0xB68][3]` read as a side effect — the chaining receiver, and
  on the resume path **`VidInterceptAdvanceInstructionPointer` and then** `WinHvCompleteIntercept`:
  completing a software exception without advancing `RIP` re-enters the faulting instruction, so a
  receiver that only completes would intercept the same `int 3` for ever and read as a broken chain.

  **Resolution, read 2026-09-29 before anything was built.** The WDK ships **no kernel-mode import
  library for `winhvr.sys`** — the only `WinHv*` libraries in `10.0.26100.0` are user-mode
  `WinHvPlatform.lib` and `WinHvEmulation.lib`, which are the WHP *Exo* family S5m already found to
  be the wrong mechanism. And `MmGetSystemRoutineAddress`, which is how `h3probe.c` resolves
  `nt!HvlInvokeHypercall` today, is documented to cover `ntoskrnl` and `hal` only. **So the receiver
  resolves its imports itself**: find `winhvr.sys`'s base in the loaded-module list and parse its
  export directory by name. The eight exports the gate needs were read out of this host's own
  `winhvr.sys` (201 exports) rather than taken from S5j's record — `WinHvSetInterceptRoutine`,
  `WinHvCompleteIntercept`, `WinHvInstallIntercept`, `WinHvGetSintMessage`, `WinHvSetEndOfMessage`,
  `WinHvCreatePort`, `WinHvConnectPort` and `WinHvAllocatePartitionSintIndex`, all present. That
  export walk is the one piece of this gate with no precedent in the driver, so it is written and
  tested before the intercept goes anywhere near it.

  **Staged, because the dangerous part is the smallest part.** A fault in our callback is a **host**
  bugcheck, and the callback is the only new code executing in the root's dispatch path — so it runs
  first with nothing in it. **Arm 0, the null receiver**: chain in, forward *every* message to the
  saved routine, handle nothing, install no intercept at all. **Pass:** the guest keeps serving —
  a second PowerShell Direct session answers and the enclave completes a full `L<n>` cycle — and
  teardown restores the saved pointer. **That sentence was wrong and the arm 0 result below says
  so**: this exercises registration and restore, not dispatch, because with no intercept installed
  nothing is dispatched. What it does test is real, and it
  is also the only arm that can be run without installing a vector, so the standing constraint does
  not reach it. Only if arm 0 is stable does the exception handling go in. **If arm 0 bugchecks the
  host, the in-kernel receiver is retired** — the same stop condition as below, reached for a
  tenth of the cost. It used to add *and step 8's own-partition build is selected*; step 8 has
  since been costed and the costing **did not settle** the build, so a host bugcheck retires the
  receiver and leaves this line pointed at a route whose cost is still unbounded.

  **Pass:** a `#BP` raised in VTL1 user mode is delivered to **our** callback, its context is
  readable, and `WinHvCompleteIntercept` resumes the raiser. Nothing in S5 has met this; S5h
  measured a hold with no receiver at all.

  **Controls, and the gate is withdrawn rather than caveated without them:**

  - **`BP0` on the same guest.** A VTL0-raised `#BP` must arrive first, or the receiver is unproven
    and nothing VTL1 rests on anything.
  - **The VTL0-only twin.** Same install, same raise, must arrive. If a delivered message cannot
    distinguish a VTL1 arrival from a VTL0 one, **say so** rather than inferring the VTL from the
    arm that produced it — S5i's dispatch read is what carries the VTL claim, and this gate does
    not re-derive it.
  - **`#BR` installed with nothing raising it** — must deliver nothing. S5h's null arm, unchanged.
  - **The chaining control, which is the one a green run would skip.** With the receiver installed
    and no `#BP` raised, the guest keeps serving: a second PowerShell Direct session answers and the
    enclave completes a full `L<n>` cycle. A wedged guest means the chain is wrong, and every
    reading downstream of it is measuring that instead.

  **Stop conditions.** A **host** bugcheck retires the in-kernel receiver — the callback runs in
  the root's dispatch path, so a fault there takes the bench rather than a guest. It no longer
  *selects* step 8's own-partition build: step 8 is costed, and the costing did not settle the
  build either way.
  **That, and not the displacement, is the hazard this gate carries**;
  the displacement is bounded to one child and is what the lift above accepts. A guest that wedges
  only with the chain installed stops the gate until the chain is fixed. **Teardown order is part
  of the gate**: remove the hypervisor intercept bit **first**, then restore the saved routine, and
  pair both in a `finally` — per S5l the removal is an unconditional `and ~bit` with no refcount.
  **An earlier draft of this sentence had the order the other way round**, which contradicted the
  non-atomic-swap paragraph above and the order arm 1 actually used: restoring while the vector is
  still armed leaves an exception able to dispatch through a half-swapped pair, which is the host
  bug check that paragraph is about.

  **What it was expected to settle, and cannot.** A draft here said a delivered message would show
  which branch S5h met. **It would not**: this arm *replaces* Vid's routine, so our receiver is
  reached before Vid's slot check ever runs, and delivery looks identical whether Vid would have
  dropped the message or retained it. Recovering that branch needs Vid's decision instrumented
  while it happens, or S5h reproduced with the slot recorded — neither of which this is. **A draft
  here then said arm 1 made the question moot from the other side, "nothing was delivered at all".
  That is disproven**: step 9's combined arm reads the message arriving at
  `VidInterceptPreprocess` with the chain standing and `forwarded = 0`, so what arm 1 saw nothing
  of was the **chained callback**. The branch question is not moot — it is open, and open for the
  reason this paragraph gives rather than for want of a message.

- **S5r — WRITTEN BEFORE THE RUN, 2026-09-29: reproduce the published IUM-debugging patch from the
  root, with no outer hypervisor.** Quarkslab's
  [*Debugging Windows Isolated User Mode (IUM) processes*](https://blog.quarkslab.com/debugging-windows-isolated-user-mode-ium-processes.html)
  (2023-09-07) debugs VTL1 **user** mode — breakpoints, single-stepping, registers, against
  Microsoft's own shipped trustlets — by patching Secure Kernel's `SkpsIsProcessDebuggingEnabled`
  in physical memory so that the guest's own VTL0 debugger is permitted to attach. Their access to
  that memory is an **outer hypervisor**: VMware Workstation as L1 with its GDB stub enabled,
  Hyper-V nested inside it, the target as L2, IDA driving the patch. **S4's direct route reaches
  the same bytes from the Hyper-V root with no nesting and no second hypervisor**, which is the rig
  [the EXDI stub plan](docs/secure-kernel/exdi-stub-plan.md) went looking for and this plan escaped.
  So the question is not whether the technique works — it is published — but whether this plan's
  primitive is a **strictly cheaper delivery** of it.

  **Pass:** the patch is applied from the root, a debugger attaches to a trustlet in the VBS guest,
  and a breakpoint in VTL1 user mode is hit. **Read that condition strictly when the arm runs**: the
  `int 3` Windows injects into a debuggee on attach is not a breakpoint planted at a chosen address,
  and only the second demonstrates breakpoint *setting*.

  **Controls:** the same attach **before** the patch must fail, or the patch is not what admitted
  it; and the patched bytes are read back and restored against the on-disk image, as S4 did with
  the `.text` cave rather than from memory.

  **What a pass is worth, stated now so it is not overread.** It is a *reproduction with a simpler
  rig*, not a new capability, and the write-up says so in its own first sentence. Its second value
  is evidential and points at a question S4 left open: their patch **persists** for the length of a
  debugging session, which is exactly the persistent-modification experiment S4 declined to run —
  so a pass is evidence that Secure Kernel's own `.text` is not checksummed in a way that catches
  this. That is a reading of one function's page on one build, **not** a property of VBS, and the
  claim goes no further than the bytes touched.

  **Stop:** a bugcheck on applying the patch stops the gate, and it is taken against a throwaway
  checkpoint so that it can. **It would not by itself answer S4's open question**: a stale offset,
  wrong patch bytes or an unrelated fault produce the same outcome, so it counts as integrity
  detection only with evidence attributing it to that mechanism, and is otherwise recorded as
  inconclusive. Verify the details against the original write-up before building on this summary: the
  gate was written from a fetched précis, and the function name, the build it was read on, and
  whether the patch is applied once or re-applied are each load-bearing.

- **S5s — WRITTEN BEFORE THE RUN, 2026-09-29: does LiveCloudKd's active CLSID deliver a VTL1
  breakpoint, or is it inspection of a paused VM?** E2a in
  [the EXDI stub plan](docs/secure-kernel/exdi-stub-plan.md) named this arm and **it was never
  run**, which is why this plan has carried "the active CLSID's breakpoint support is undemonstrated
  by its own write-up" as an observation about someone's documentation rather than a measurement.
  It decides what every novelty claim here is worth. The tool's headline is a *debugger*; its
  published write-up claims you can "(potentially) set breakpoints and walk through code" and
  demonstrates module enumeration and memory reads through `dx` — no breakpoint, no step, no
  exception anywhere in it.

  **Binary, and either outcome is useful.** Register the active CLSID
  (`{67030926-1754-4FDA-9788-7F731CBDAE42}`; the passive one is
  `{53838F70-0936-44A9-AB4E-ABB568401508}`), attach to the VBS guest from its Hyper-V host, and set
  a breakpoint in `securekernel.exe`. **If it is hit**, execution control over VTL1 exists today,
  and what S5 contributes is the route rather than the capability — say that plainly and rewrite
  the claims. **If it is not**, what the tool provides is inspection of a paused VM, which is then
  the accurate description of **what this build of this tool provides** — and of nothing else. It
  says nothing about the other published routes, which rest on their own evidence and which the
  route table keeps separate; the 2025 thesis in particular reaches execution control that this
  sentence once implied nobody had.

  **Controls:** the same breakpoint set in `nt` through the same CLSID must be hit, or a miss
  measures the rig and not VTL1. And the **passive** CLSID must first resolve SK symbols against
  live memory with the VBS-off twin finding no SK data block — E2a's original control, unchanged,
  and the one that says the tool is pointed at a Secure Kernel at all.

  **Cost and hazard, which are on the debugger host rather than a guest.** `hvmm.sys` carries a
  revoked certificate (`CN=Atheros Communications Inc.`, expired 2013) and needs re-signing plus
  test signing on the **Hyper-V host of the target**, and its own `Start-ExdiDebugger.ps1` carries a
  `Stop-ExdiContainingDllHosts` because the surrogate outlives the debugger — the same E0 activation
  stall this plan already hit. Both weakenings outlive the run: record them and reverse them.

- **S5s — RUN 2026-09-29: the active CLSID refuses to start, so the answer is the "if it is not"
  branch.** `kd -kx exdi:CLSID={67030926-…}` against release `v3.3.2.20260720` produces one modal
  dialog carrying a string hardcoded in `ExdiHvSrv.dll` — *"That build of EXDI plugin is not
  supported live Hyper-V debugging"* — and kd's log ends at the version banner with no connection,
  no target and no `bp`. **The gate's `nt` breakpoint control was never reached and did not need to
  be**: it exists to separate a broken rig from a refused VTL1, and the server declined before a
  target existed, which is neither. A breakpoint in `securekernel.exe` cannot be attempted through
  this build at all. **So what LiveCloudKd provides is inspection with Secure Kernel symbols on
  top**, and every novelty claim in this plan may be stated against that — for **this release**,
  the refusal being build-conditional by its own wording.
- **Narrowed 2026-09-30: S5s tested the main release line, not the asset the procedure links.** The
  maintainer's live-debugging page links `LiveCloudKd.EXDI.debugger.v1.0.20251103.zip` (tag
  `v1.0.20251103`, confirmed in the release list) and says to register **`ExdiKdSample.dll`** — a
  separate download post-dating `v2.8.4.20241221`'s *"EXDI plugin renamed to `ExdiHvSrv.dll`"* by
  eleven months, and those notes never name the old spelling, so `exdi-stub-plan.md`'s "the article's
  naming is stale" was an inference from two filenames and is corrected. **Its contents were not
  read**, so whether its DLL is a distinct binary is open — and since the refusal string is
  build-conditional, only that zip answers whether its build carries the same gate. **It is not
  queued, for two reasons that are already on the record**: its procedure
  requires the **Classic** scheduler against this host's **Root** (the 2026-09-19 preflight decision,
  which also declined to change a shared host), and it reaches VTL1 by **duplicating handles from
  `vmwp.exe`** — step 7 below, declined on scope grounds rather than open on technical ones. So this
  is a decision for the maintainer, not a compatibility investigation.
- **And the inspector half passes, with its control.** The passive CLSID connects, finds
  `ntkrnlmp`, resolves NT symbols and walks the process list; `IeXdiControlComponentFunctions` is
  unimplemented (`0x80004002`), so `.exdicmd` is missing beside the execution control.
  `hvlib.dll`'s own classes give the VBS guest `InfoSecureKernelBase` `0xFFFFF80629B4A000`, size
  `0x175000`, `InfoHvddGetCr3Securekernel` `0x1201000` — and the twin **`0x0` on all three**. In the
  debugger, `.reload /f securekernel.exe=<base>` loads `securekernel` **with PDB symbols** and
  `db` at that base reads `4d 5a 90 00`, while the **identical commands at the identical address on
  the VBS-off twin** give all zeros, *Unable to verify timestamp* and one page with no symbols. **No
  `RegCr3` override was needed**, though the value name exists. `SkpsEnableDebugging` (**+0xA4658**)
  and `SkpsSendDebugAttachNotifications` (**+0xA4D50**) resolve, and
  **`SkpsIsProcessDebuggingEnabled` does not exist in this build's public PDB** — which corrects
  S5r, written with that name from a fetched précis rather than from the write-up. The new name is
  a **candidate** for the gate that work patches, not an identification.
- **The partition identity was established three ways before any VTL1 reading was taken**, because
  the host reset below left the twins matched on uptime to under a second and killed the
  discriminator earlier gates used: NT kernel base, the presence of `Secure System` and
  `LsaIso.exe` in VTL0, and hvlib's own `InfoPartitionId`/name — all agreeing with the host's
  `Get-VMSecurity`, and all saying `VmId` 0 is the control and `VmId` 1 the VBS guest. `VmId` is a
  DWORD index over **VMs only**; 2 and 3 fail with `CO_E_SERVER_EXEC_FAILURE`, so the VSM scan adds
  no pseudo-partition to select.
- **The first attempt hung the host, and the cause was the harness rather than the attach.** `kd`
  launched with `Start-Process -NoNewWindow -RedirectStandardOutput` wrote **281 KB of
  `kd: Could not write to pipe, 1450`** while a modal blocked it — the modal being the plugin asking
  for `VmId`, a DWORD in `HKLM\SOFTWARE\LiveCloudKd\Parameters` that did not exist yet. Kernel-Power
  41, unexpected shutdown, **no dump**: a reset of a hung machine, not a bug check, and the same
  signature this bench recorded for `cdb -server`, so the rule is about **any** debugger child and
  `-RedirectStandardOutput` is not the "redirect to a file" it means. Both guests rebooted with the
  host, so the S5g landmarks have moved again. The replacement harness — pre-supplied settings, the
  child in **its own window**, kd's own `-logo`, a **job object** with `KILL_ON_JOB_CLOSE`, a bounded
  wait, an explicit kill on every path and a `dllhost` sweep — then ran six times with no
  recurrence. **No guest was modified, no intercept installed and nothing written to VTL1.** Full
  record in the [S5s result](docs/secure-kernel/secure-kernel-hypercall-feasibility.md) section.

- **S5r — RUN 2026-09-29: PASS, end to end, and the gate had to be found rather than looked up.** A
  `#BP` raised in **VTL1 user mode** was caught by a **VTL0 debugger** and continued, with the guest
  under one hypervisor and no nesting — against the published route's VMware L1 plus nested Hyper-V
  plus IDA. **The claim is a cheaper delivery of a published capability, not a new one**, and the
  write-up says so first.
- **The original work is the gate.** `SkpsIsProcessDebuggingEnabled` does not exist in 26100, so the
  equivalent was located by dumping SK's image out of live VTL1 (`.writemem`, 1,527,808 bytes) and
  **computing `E8`/`E9` displacements over the dump** to find call sites into
  `securekernel!SkpsEnableDebugging`. Two of the three are inside **`IumInvokeSecureService`**, the
  VTL0→VTL1 secure-call dispatcher. `SkpsEnableDebugging` is a **setter**, not a predicate — S5r's own
  gate text treated it as the gate and that was wrong. The guard is at `securekernel.exe+0x1434C`:
  `test bl,bl` / `jne` / `mov ebx,0C0000022h` (`STATUS_ACCESS_DENIED`) / `jmp`, with `bl` from
  `sete bl` on `cmp eax,80430006h`. **One byte opens it** — `0x75` → `0xEB` at **`+0x1434E`** — and
  only the opcode is written, the displacement being identical in both encodings so a torn write
  cannot retarget the branch.
- **The A-B-A is the result, not the middle arm.** `DebugActiveProcess` against `LsaIso.exe`
  (pid 928, a Microsoft-signed trustlet in VTL1 user mode) over PowerShell Direct: **before**
  `False`/`ERROR_ACCESS_DENIED (5)`; **patched** `True`, then `CREATE_PROCESS_DEBUG_EVENT`, five
  `LOAD_DLL_DEBUG_EVENT` and **`EXCEPTION_BREAKPOINT 0x80000003` at `0x7FFE381E3AB0`** on tid 4432,
  continued with `DBG_CONTINUE` and detached cleanly; **after restore** `False`/`5` again. The before
  arm ties the disassembly to the observable — Win32 `5` is the mapping of the `0xC0000022` the guard
  writes — and the after arm makes the middle one a result rather than a trustlet that happened to be
  debuggable.
- **The write goes through S4's physical route** — recorded here as forced by a `SdkWriteVirtualMemory`
  segfault, which **S5u retracts**: that call lands on VTL1, and the fault was an 8-byte struct
  overrun in `hvlib.py` surfacing at the next garbage collection. The route taken was still this: SK base and SK `CR3` read per run
  (`0xFFFFF80629B4A000`, `0x1201000` this boot), a four-level walk to GPA **`0xCE534E`** agreeing with
  an independent `!vtop`, and the page identified by diffing **48 live bytes against the dumped image**
  with the gate byte masked. **The crash printed nothing** — Python's stdout buffer dies with the
  process — so what established the write had not half-landed was a re-read, not the absence of output.
- **Twelve minutes of live Secure Kernel code modification, exercised, with no bugcheck.** Bounded by
  guest uptime `1:03:31` at the patch and `1:17:43` at the post-restore check, across two complete
  debug-attach cycles. S4's write lasted milliseconds between two reads and the record rightly said
  that showed nothing about a periodic check; this one stood while the modified path was *used*.
  **It is one byte on one build and not a property of VBS** — no check was located, so this is not a
  measurement *of* one — but it retires the specific reason this plan gave for not trying, which was
  that a bugcheck is the expected outcome. Bench restored and verified; checkpoint `pre-S5r-patch`
  unused. Full record in the
  [S5r result](docs/secure-kernel/secure-kernel-hypercall-feasibility.md) section.

- **S5q steps 1 and 2 — RUN 2026-09-29, both read-only: the imports resolve and the table is read.**
  Neither installs an intercept, registers a routine nor writes to a partition; **arm 0 has not
  run**, and no code of ours has executed in the root's dispatch path. **Step 1**, `IOCTL_H3_RESOLVE`:
  there is **no kernel-mode import library for `winhvr.sys`** — the WDK's only `WinHv*` libraries are
  the user-mode WHP *Exo* pair — and `MmGetSystemRoutineAddress` covers `ntoskrnl` and `hal` only, so
  the driver finds the module with `AuxKlibQueryModuleInformation` and parses the export directory
  itself, bounding every RVA against `SizeOfImage` and **refusing forwarded exports** rather than
  handing back a `"Dll.Name"` string. **8 of 8 resolved, all inside the image**, and
  `WinHvSetInterceptRoutine` at **`+0x8020`** is the RVA S5k read statically from the same build —
  a static read and a runtime walk agreeing on one offset is what makes the other seven worth
  anything.
- **Step 2, `IOCTL_H3_WHVPART`: the layout was re-derived from this build rather than taken from
  S5k's note**, and `WinHvpReferencePartition` (`+0x2B40`) and `WinHvpOnInterception` (`+0x4438`)
  agree — `WinHvpPartitionArray` (`+0x152D0`) points at `{ULONG Count}` followed by sorted 16-byte
  `{ULONG64 PartitionId; PVOID Object}` entries at `+8`; the object carries a refcount at `+0x00`,
  the **routine at `+0x10`** and the **context at `+0x18`**; and the dispatch is
  **`Routine(Context, Message)`**. Live: **two partitions, `0x2` and `0x3`**, both with
  `0xFFFFF807502E4170` = **`Vid!VidInterceptIsrCallback`** (`Vid.sys+0x4170`, `VidInterceptPreprocess`
  the next symbol) — so **S5k's static claim that Vid is bound is now confirmed at runtime**, for
  both partitions.
- **The constraint step 2 produced, and a static read could not have.** **One routine, two different
  contexts** (`0xFFFF818A46AB3000` against `0xFFFF818A46DF5000`): the routine is Vid's single
  dispatcher and the **context** is what identifies the partition. A chain must therefore save and
  forward **both**, passing the *original* context — one that saved only the routine pointer and
  passed its own looks correct and makes Vid dereference the wrong partition object, a **host** bug
  check on the first non-exception intercept. This is why arm 0 exists and why it came before the
  exception work.
- **Two guards, both load-bearing, and one hazard that is bench-dependent.**
  `WinHvpPartitionArray` is **not exported**, so its RVA is a build-specific constant that would read
  arbitrary kernel memory on another build: the IOCTL refuses unless the **loaded** image's
  `TimeDateStamp` **and** `SizeOfImage` match the build it was read from (`0x31B98FBA` / `0x29000`),
  reporting what it saw either way. And it takes the **same shared push lock**
  `WinHvpReferencePartition` takes, because a concurrently torn-down partition leaves a stale object
  pointer whose dereference at `+0x10` faults in the root. **The hazard**: the dispatch is
  `guard_dispatch_icall`, so a chained routine must be an acceptable **CFG** indirect-call target —
  a real constraint on an HVCI host, and not on this bench — **measured**, not inferred:
  `NtQuerySystemInformation(SystemCodeIntegrityInformation)` gives `CodeIntegrityOptions`
  `0x282203` with **`HVCI_KMCI_ENABLED` (`0x400`) clear** and the scenario key at `Enabled = 0`,
  while **`HVCI_IUM_ENABLED` is set**, so it is *kernel-mode* HVCI that is off. An earlier draft
  inferred it from test-signed drivers loading, which is unsound — they load under HVCI too. Full record in the
  [S5q steps result](docs/secure-kernel/secure-kernel-hypercall-feasibility.md) section.

- **S5q arm 0 — RUN 2026-09-29: the chain installs and restores, and it cannot test what it was
  written to test.** Registration and restore **completed and were verified exactly**, on a partition
  where nothing was dispatched across the swap — which is not the same as safe, the swap being
  non-atomic per the paragraph above; **dispatch is untested**, and the
  gate text above that called arm 0 the step which "exercises the whole hazard with no logic in it"
  is **wrong**. Established: the chain installs on partition `0x3` saving
  `Vid!VidInterceptIsrCallback` and that partition's own context, leaves partition `0x2` untouched
  throughout, the guest keeps serving (two concurrent PowerShell Direct sessions, 0.9 s round trip,
  `LsaIso` alive, the enclave completing 20 VTL1 calls), and the restore is **exact** — routine and
  context back byte for byte — after which the driver unloaded clean. No host reboot, no
  Kernel-Power 41, no dump.
- **The forward counter read `0`, and it is the only reason that is known.** Our routine was never
  called — not during the enclave's VTL1 calls, not during twelve seconds of guest CPU and
  file-system churn. Without the counter every other measure reads as a clean pass and the arm would
  have been written up as *"our code ran in the dispatch path and nothing broke"*, on evidence that
  says nothing of the kind. Zero is **consistent with S5k**: `VidHandlerpExceptionRegisterEntry`
  claims its slot and *then* installs the intercept, so with no intercept installed there are no
  exception-intercept messages to dispatch, and ordinary guest activity produced no IO-port, MSR or
  CPUID intercept routed to VTL0 either.
- **So there are two hazards where the gate assumed one**, and the cheap-arm-first ordering does not
  survive it. **Registration and restore** — replacing a pointer Hyper-V holds and putting it back —
  is what arm 0 tests, and it passes. **Dispatch** — our code running when Hyper-V calls it — cannot
  be reached without an intercept existing, and an intercept means installing a vector. That moves
  the dispatch hazard into **arm 1**, beside the vector-install hazards S5l described, rather than
  ahead of them. Arm 0 is still worth what it measured: a failed restore or a forwarded-wrong context
  would each have been a host bug check, and both were live before this run. Full record in the
  [S5q arm 0 result](docs/secure-kernel/secure-kernel-hypercall-feasibility.md) section.

- **S5q arm 1 — RUN 2026-09-29: the trap is held and the partition's routine is never called —
  which is the chained callback, not delivery.** (This bullet said *"so the message is not
  delivered"*; step 9's arm measured the message arriving at `VidInterceptPreprocess` by a path that
  never reads that slot, so the result stands for the callback and never stood for delivery.)
  Partition `0x3` with our routine chained into its slot,
  `HvCallInstallIntercept` type 3 / access 4 / vector `0x03`, and `spin_host.exe BP0` — S5h's own
  VTL0 raiser — launched detached. The install succeeded, the **raiser was held** at all ten
  2-second samples across 20 s (against **878 µs** to finish all 1000 rounds with no intercept
  standing, measured immediately before), and **`forwarded` stayed 0 throughout**. Teardown removed
  the intercept, released the raiser, restored the chain, left nothing standing; host and both
  guests untouched. **So this is not arm 0's vacuous zero**: the trap fired, the hypervisor took it,
  and our routine still was not called.
- **The alternative had to be excluded before the zero meant anything**, because this instrument has
  never been observed to carry a message — zero in arm 0 across guest churn and 20 VTL1 enclave
  calls, zero here with a trap held. The alternative was *the field we patched is not the field this
  dispatch consults*, and it is a static question.
  [`tools/winhv_partition_readers.py`](tools/winhv_partition_readers.py) answers it: a census of
  `+0x10` alone cannot (365 accesses in `winhvr.sys` by `vid_field_census.py`'s count), so it first
  finds the **28 of 497** functions that can hold a partition object at all — those calling
  `WinHvpReferencePartition` or loading `WinHvpPartitionArray` — and only then reports `+0x10`/`+0x18`
  with capstone's read/write classification and stack traffic dropped. **Two sites trace end to end
  to the same field**: `WinHvSetInterceptRoutine` (`+0x8020`) writes `[rax+0x10]`/`[rax+0x18]` off
  `WinHvpReferencePartition`'s return, and `WinHvpOnInterception` (`+0x4438`) reads the same pair off
  the array-derived object. **So what the zero measures is that *our registered routine was not
  called*.** That is as far as it goes: the census is a lower bound over two anchors, so it cannot
  establish that `WinHvpOnInterception` did not run, and the readings it leaves open — an argument-
  passed holder, a helper this does not follow — are exactly the ones that would let it run and
  consult something else. **That the message was never delivered is an inference from the zero, not
  a measurement of the delivery path**, and the path itself is unresolved. **Step 9's combined arm
  has since disproven that inference by measurement** — same slot chained, same intercept, message
  arriving at `VidInterceptPreprocess` with `forwarded` still `0`. The hedge was right to be one.
- **The limit, stated rather than glossed.** The census is function-scoped, not provenance-scoped.
  Three other functions read the pair — `WinHvpOnMirroringNotification`,
  `WinHvpSendRestartNotificationToAllPartitions`, `WinHvIssueSnpPspGuestRequest` — and their names
  say they serve other message types, but their objects were not identified, so a dispatch consulting
  one of those instead is **narrowed, not eliminated**. **The `.pdata` hole is narrowed, and what
  closed it was giving up on a question the image cannot answer** (re-derived 2026-09-30): `.pdata`
  claims no leaf functions, so the tool decodes the bytes the table leaves out — **9,599 here, 9,569
  of them `0xCC`/`0x00`, five spans holding anything else, 0 distinct bytes refused**. A gap has no
  unwind record, and four attempts to infer where a leaf begins or ends were each wrong differently:
  one stream from the span start loses an island after an odd-length `0x00` run (`00 00` is a two-byte
  `add byte ptr [rax], al`); splitting at *every* `0xCC`/`0x00` byte cuts instructions apart, since **a
  single zero byte is not padding**; one region per span loses provenance, crediting one leaf's field
  access to another leaf's anchor load; and ending an island at padding fixed that only for *padded*
  neighbours, leaving two leaves emitted back to back collapsed. Adding `ret` as a second boundary
  would split a real two-return function instead, then `jmp` and `int 29h` in turn — a predicate per
  round. **So boundaries are not inferred at all.** A `.pdata` entry is a function (exact bounds,
  decoded whole), and **that is where 28 and 42 come from** — and nowhere else by construction, since
  `analyse` iterates the `.pdata` table only and a gap span is never keyed into the reaching set.
  A gap span is a *detector*: the union over its candidate starts, reported in its own section,
  **excluded from both counts**, labelled *boundaries unknown*. Here that section prints **"none: no
  span reaches an anchor or touches `+0x10`, `+0x18`"** — the negative stated as a measurement rather
  than inferred from an empty list. And **`rbp` is no longer assumed to be a
  frame pointer**, being suppressed only where the function's `UNWIND_INFO` names it as the frame
  register — 16 such operands exist image-wide and none is in a reaching function. **The answer did not
  move** through any of the five: 28 and 42 throughout, under every broken reading too, which is why
  the gap scan needed its own test. **The reaching set is still a lower bound**: a function handed the
  partition object as an *argument*, or getting one from a helper other than
  `WinHvpReferencePartition`, calls neither anchor and is absent from the 28 even if it reads the
  pair — and none of the gap work above touches that, because it is a provenance limit rather than a
  coverage one. Closing it needs provenance carried across calls and returns, which the tool does not
  do. **The tool now has `--self-test`, 24/24** — detection under each alignment hazard, no-attribution in both the padded
  and unpadded shapes, a byte refused twice counted once, and a `.pdata`-claimed function as the
  control that attribution still happens where bounds are exact; mutation-verified so the scores share
  a denominator — attributing gap spans as functions scores 20/24, a single start 15/24, a summed
  refusal count 23/24. Every index in it returns empty rather than raising, so a mutation reports the
  assertions it broke instead of aborting. Treat its function set as a reading.
- **What it does to S5j's two explanations, and to the build.** S5k killed *nothing was bound*;
  step 2 confirmed Vid bound at runtime for both partitions. Arm 1 bears against the second, *the
  handler received it and retained it*: the routine chained into `[partition+0x10]` is **not
  called**, so the hold is not something *that routine* retains. **Corrected 2026-09-30 — this entry
  and the doc both said "it happens before the root's intercept dispatch runs", and that does not
  follow.** This host runs the **root** scheduler (Hyper-V-Hypervisor event ID 2 reports `0x4` on each
  of the three most recent boots, latest 2026-09-29 17:58:30, read 2026-09-30) and `Vid.sys`
  `10.0.26100.9278` has **two further paths into `VidInterceptPreprocess` that never read the
  partition callback**: `VidXSchedulerpVpRun` (`+0x2CB80`) calls `[_imp_WinHvRunVpDispatchLoop]` at
  `+0x2CC09` and `VidInterceptPreprocess` **directly** at `+0x2CC2A`, and
  `VidXSchedulerVpThreadStartRoutine` (`+0x2D900`) does the same at `+0x2DAA8` and **`+0x2DAC8`**;
  both test the returned reason and load the message at `[VP+0x8D8]`. So `forwarded = 0` is
  consistent with VID having received the intercept through its dispatch loop, and S5j's second
  explanation is **narrowed to the chained slot, not eliminated**. S5k had flagged this fork
  (`VidDeviceExtension+0x288` bit `0x40`) and scoped its finding to the bit-clear path; S5q did not
  carry that forward. **Three arms now survive, all inferences, and the two paths widen the fork
  rather than picking an arm** — *(3) was later eliminated by step 9's arm, which read the message
  arriving; the fork is kept as written because it is what that arm was built from)*: (1) delivered
  with the per-vector slot unclaimed, so VID took the
  unregistered-vector branch — a raw install neither claims that slot **nor establishes its state**;
  (2) delivered with the slot already claimed by another VID client, so the handler *enqueued* to it,
  which is S5j's received-and-retained reading and stays live because `[partition+0xB68][3]` **was
  never read** and S5l showed a claim survives a probe removal; or (3) not delivered, S5k's "half of
  the arming sequence" being the port and SINT plumbing `winhvr.sys` exports rather than a per-vector
  flag. Both delivery arms travel the same two paths, so the measurement bears on *delivered versus
  not* and not on the branch — an earlier version of this entry called arm 1 "the better supported,
  since its paths are measured", which reads a shared mechanism as evidence for one of the things
  sharing it. Arrivals at the convergence point separate (3) from (1)–(2); only a contemporaneous slot
  read in the same arm separates (1) from (2). **What arm 1 does establish is that the
  receiver is not a routine to chain**: chaining installs and restores cleanly and receives nothing.
  What it does **not** establish is that no delivery path exists, so it leaves the delivery question
  open rather than answered against, and step 8 is where the *chaining* failure points rather than
  where the evidence forces the build. **The successor is step 9 below, not step 8** — and step 9's
  arm has since closed the delivery question **in the affirmative** and eliminated arm (3): the
  message arrives at `VidInterceptPreprocess`, so `forwarded = 0` here was the chained slot being
  bypassed rather than nothing arriving. Full record in the
  [S5q arm 1 result](docs/secure-kernel/secure-kernel-hypercall-feasibility.md) section.

### Out of scope, with the reason rather than as a list

- **Writes as a *tool surface***: the primitive exists and S1's seam should not pretend otherwise,
  but exposing "patch a live guest's VTL1" as a tool needs its own justification and confirmation,
  and nothing in S0–S3 needs it. Note the adjacency hazard when it is built: `HvCallWriteGpa` is
  `0x0054`, one off the read.
- **H5a / EXDI**: parked with its two-part reversal condition recorded. Not re-litigated here.
- **Distributing a driver**: the repo ships none; the operator supplies the transport, per the
  first constraint.

### Unknowns, in the order they change the plan

1. ~~**S0's saved-state source**~~ — **answered 2026-09-26**: a Hyper-V standard checkpoint carries
   VTL1 and its `CR3`, read driver-free through the SDK's `vmsavedstatedumpprovider.dll`. The
   remaining setup is Hyper-V administrator on the host plus the SDK, and the live driver route is
   now what a *running* target costs rather than what access costs.
2. ~~**Image-only symbol resolution**~~ — **answered 2026-09-27**: small, and no `dbgscope` change.
   DbgEng opens a PE image as a target of its own and loads its PDB there, so `symbol_offset` and
   `symbol_for` work against `securekernel.exe` with no debuggee and the rebase onto S1's base is
   arithmetic in `src/sksym.rs`. What the answer *cost* is the half the question did not ask about:
   the public PDB carries **no types**, so "symbols and types" is one of the two.
3. **S5's unresolved Secure Kernel *attachment*** — not its activation, which is done, and since
   2026-09-27 not its *transport* either: **S5a settled why SK does not connect to the port, which
   is that it has nothing to connect with.** No debug hypercall, no `vmcall`, no SynDbg MSR, across
   ten builds. So the remaining unknown is narrower and differently shaped — whether a VTL1 stop can
   be driven from the hypervisor or the root *without* guest-side code. **S5b split the
   named candidate for that in two**: a parent can install an exception intercept on a child and has
   no field to aim one at a VTL, which left *whether it covers VTL1 anyway* unresolved. **S5h then
   measured the behaviour and S5i the scope**: with the intercept standing, a `#BP` raised in VTL1
   user mode never reaches the guest's own dispatch and is handed back intact when it comes down,
   and the hypervisor seeds a parent's installed mask into *every* enabled VTL's effective exception
   bitmap. So the unknown is back to one, and it is the one this gate has never had — whether the
   root can **receive** what the intercept produces. **S5j narrowed even that**: the message is
   already delivered to the parent, `winhvr.sys` exports the receiving API, and the open question is
   the key of the table `WinHvSetInterceptRoutine` searches, which decides whether registering
   displaces the entry Hyper-V holds or takes one of its own. **S5k closed that and moved the
   unknown again**: the key is the partition id, Vid holds the entry, and the receiving path already
   exists — Vid is bound and recognises the message, and drops one whose vector is not claimed in
   its own per-vector table. **S5m then read the IOCTL and found it wrapped by an exported
   `vid.dll` call**, and **S5n and S5o between them settled what that is worth on a VM Hyper-V
   runs: nothing.** The sequence needs a partition handle, a second open is refused, the refusal is
   a partition-state test with no token in it, and the branch it guards hands the partition to a
   new owner only after the old one has torn the receive path down. **So the unknown is no longer
   "can the root receive" but "can the root own", and the ordered plan for it lives here, in one
   place, because keeping a schedule in each gate section produced a run of review findings against
   lists a later gate had invalidated:**

   1. ~~**Open a running child's VID partition.**~~ **Run as S5n: refused.** `CreateFileW` on the VID
      device interface path plus the VM Id, `OPEN_EXISTING`, from an elevated process, gives
      `ERROR_BAD_COMMAND` (22) on both running guests, while a well-formed unused name opens — an
      error matching a single-open rule that S5n could not trace to its check.
   2. ~~**Vary the caller upward.**~~ **Answered by S5n's successor without running it — see
      step 3**, which read the check and found it consults no token. The arm — a run as `SYSTEM`
      carrying the unused-name control — was never performed, and performing it now would add
      nothing: `SeTokenIsAdmin` is true for both that account and the elevated one already
      measured, so it reaches the same instruction with the same two fields. Recorded as *not run*
      rather than as *refused*, because those are different readings and only the second would have
      been a measurement.
   3. ~~**Locate the refusing check.**~~ **Run as S5o: located, statically.** `Vid.sys` is a WDF
      driver, which is why no `IRP_MJ_CREATE` dispatcher was findable by name; the callback is
      `VidFileCreate` → `VidFileObjectCreate`, and the refusal is one site (RVA `0x8f6f`) testing
      `[partition+0x3060] == 2` and `[partition+0x3079] == 1`. **This step's cost estimate here was
      wrong** — it said a host reboot into kernel-debug mode, and the answer came from opening the
      image in DbgEng with no target attached. The error S5n matched is now a common cause: on the
      non-Exo arm there is exactly one such site.
   4. ~~**Register `#BP` through `vid.dll` and receive.**~~ **Not reachable by the route S5o
      located, and not merely gated on a handle.** S5o read the branch the refusal guards: it is
      `VidPartitionAttach`, which makes the opener the partition's owning process, and the way in
      that this gate found runs through the current owner's detach IOCTL — which first calls
      `VidHandlerUnregister` and detaches every VP. So on that route the sequence S5m found cannot
      be run *alongside* Hyper-V; the step that would admit us dismantles what we came for. It
      remains the pass condition for a partition **we** own, which is step 6.
   5. ~~**Census the writers of `[p+0x3060]` and `[p+0x3079]`.**~~ **Run as S5p: done, and it
      confirms step 4.** `[p+0x3079]` has **19 accesses and 4 writers**, with no site taking its
      address in one step or two and nothing touching it in the 52 bytes of code outside `.pdata`;
      three writers clear it and **exactly one sets it**,
      `VidPartitionIoctlDetach+0x43`. Since the create path needs `0x3079 == 1` **and**
      `0x3060 == 2`, and the first has exactly one located producer, **every admission this census
      can account for** was enabled by an owner's detach — a claim about located writes, not a
      proof, since the method sees neither an inter-procedural pointer nor a bulk copy. Built
      [`tools/vid_field_census.py`](tools/vid_field_census.py) for it — decoded operands, a `.pdata`
      function walk plus the executable bytes `.pdata` does not claim, an intra-procedural alias
      table for split addresses, `--self-test` 9/9 — because a byte scan cannot do this: it scans
      aligned, it matches immediates, and it cannot see a write through a taken address, of which
      S5p found a real one (`VsmmPhuPartitionTeardown` doing `and dword ptr [rsi],0` after
      `lea rsi,[rcx+3060h]`). **Review then found two holes in the instrument itself** — leaf
      functions absent from `.pdata`, and addresses formed in two steps — and both are closed or
      measured, with neither changing the result. **Residuals**: an inter-procedural pointer, a
      bulk copy spanning the field, and `[p+0x3060]`'s writers being bounded rather than closed.
   6. ~~**The two blocked arms** — the replicated slot read, and whether the hold is a loop.~~
      **BOTH RUN 2026-09-30, in one window, with a control.** The constraint lifted for guests the
      bench owns on 2026-09-29 and S5q's kernel-read IOCTL supplied the rest.
      **The slot read**: `[P+0xB68]` reads `FF FF FF FF FF FF FF FF` at **all twelve** samples
      at every sample across 24 s of a standing intercept, plus before the install and after the
      removal — not "throughout", since sampling cannot see a claim-and-release inside a gap — the
      contemporaneous, **non-mutating** read S5k has wanted since it was written, and which S5m
      could only half-answer because registering *claims* the slot. It narrows S5j's retained
      explanation without closing it: a claimant would have had to claim and release inside one 2 s
      gap and coincide with the raise. **The loop arm ran without answering its question**, and a
      later arm answered it: `handled = 0` shows only that the guest's `__except` never ran, and
      the 20 fresh stamps are twenty calls to `VidInterceptPreprocess` rather than twenty
      executions — but **the hypervisor's own per-VP `Total Messages/sec` supports re-entry over
      re-preprocessing, under the stated assumption** (see *the loop
      question* below): tens of thousands of deliveries a second armed against **zero** in five
      control phases — one of them the vector armed with the raiser absent, the only arm that
      could have shown an unrelated `#BP` source. The rates are **aggregate** and name no vector
      or `RIP`, so they do not bind an individual delivery to the enclave instruction: S5k's
      re-entry inference is **supported**, not proven. **And a
      third reading came free**: per-VP
      `HvRegisterInterceptSuspend` is **transient**, seen on both VPs at different instants and `0`
      at every sample of a control that raised **1.87 million** `#BP`s with no intercept standing,
      while both VPs keep accumulating `VpRuntime`. **The VPs are being resumed**, which removes the
      necessary-condition objection review round 3 on #428 raised against the ping-pong reading —
      and removing an objection to one explanation is not evidence for it over another, so the
      two-VP question stayed open at this arm. **It was answered by the loop question below**,
      which supplied the missing correlation: `Other Intercepts/sec` is zero on both VPs unarmed
      and nonzero on **both** armed, and that counter moves because an instruction trapped on that
      VP. What performs the resumption is still unmeasured. Full record in the **step 6's two blocked
      arms** section of
      [`docs/secure-kernel/secure-kernel-hypercall-feasibility.md`](docs/secure-kernel/secure-kernel-hypercall-feasibility.md).
   7. ~~**Handle duplication and inheritance, which S5n excluded rather than closed and which this
      plan twice wrote out of existence.**~~ **ATTEMPTED 2026-09-30 — the handle is takeable, and
      the first read through it is refused.** S5n's reason for declining does not hold here:
      `vmwp.exe` is **not** protected (0x00, measured against positive controls with a poisoned
      buffer) and `PROCESS_ALL_ACCESS` succeeds from an elevated admin. Each worker holds **four**
      handles to the VID device, and all four duplicate out with an ordinary `DuplicateHandle`. But
      `VidGetHvPartitionId` through all **eight** (four per worker, both reported) returns
      `ERROR_INVALID_FUNCTION` on six and **`ERROR_ACCESS_DENIED`** on two — the same 3-and-1 split
      in each worker independently — against `ERROR_INVALID_HANDLE` for a non-VID control, so they
      reach `Vid.sys` and are turned away. **Not established**: that the route reaches the exported
      receiver, which *this* arm does not test — the receiver arm below does. A draft inferred
      that read-only duplicated access is
      insufficient; **withdrawn — wrong axis, and S5m already said so**: the receiver is IOCTL
      `0x221148` with `FILE_ANY_ACCESS`, and what gates it is *holding a partition handle*, not an
      access mask. Testing it means invoking `VidRegisterExceptionHandler`, and a draft justified
      skipping that with the wrong hazard — the call **refuses** a claimed slot with
      `STATUS_VID_DUPLICATE_HANDLER` before touching the hypervisor rather than displacing anyone;
      the documented hazard is collision with a **raw** `WinHvInstallIntercept` installer, which
      the duplicate check cannot see. So the test is more available than claimed and still a
      decision: an unclaimed slot would be claimed by us on a running VM. **THAT ARM HAS SINCE RUN
      — see the receiver-arm section — and the route is closed from *user mode* **against a
      partition another process owns** (**it is open from
      kernel mode**, see the gate arm): the IOCTL is issued
      directly for a lossless `NTSTATUS`, and on both workers three handles return
      `STATUS_NOT_IMPLEMENTED` and the fourth `STATUS_ACCESS_DENIED`. Nothing was mutated — the
      poisoned output survived every arm, so no slot was ever claimed. **Why it refuses is now
      read out of `Vid.sys` rather than inferred**: `VidIoControlPreProcess` compares
      `PsGetCurrentProcess()` against the owning process at `[partition+0x3780]` and returns
      `ACCESS_DENIED` before any dispatch, exempting only control codes `0x2210ef` and `0x2211e3`.
      So it is a process-identity gate, no handle could pass it, and the receiver
      (`VidHandlerpExceptionRegisterEntry`) has no access check at all. LiveCloudKd's driver stops
      being a guess: kernel code can make `PsGetCurrentProcess()` match; duplication cannot.**
      **AND THAT IS NOW RUN — the route works.** `h3probe`'s `IOCTL_H3_VIDREG` attaches to the
      owner, reads `[partition+0x3780]` back (it holds the attached `EPROCESS` on both workers) and
      issues the same `0x221148`: **`SUCCESS`**, a registration handle returned, unregister
      `SUCCESS`. Same handle, same code, same buffers as the refused user-mode call — only the
      calling process differs. **It also hard-reset both guests** (`Kernel-Power` 41, no guest bug
      check) seconds after each arm's health check passed, because nothing mapped or drained the
      message slot: **pairing register with unregister is necessary and not sufficient**, the arming
      does the damage. Host untouched, both guests back with `LsaIso` alive.
      **The `VidMessageSlot*` half, same day**: `VidMessageSlotMap` is IOCTL `0x221108` (in 4, out
      8 — a VA in the *calling* process) and `VidMessageSlotHandleAndGetNext` is `0x221107`
      (in 8, out 0). **The map runs and the guest survives** — SUCCESS on the matched handle only,
      slot VA read back with a live `HV_MESSAGE` header, uptime monotonic across a 60 s watch. **The
      completion is deliberately not run**: it is how `Vid.sys` reaches `WinHvCompleteIntercept`,
      and `vmwp` is already the consumer on these VPs, so a second completer races it. That needs a
      partition with one client — **a concrete reason for step 8's rig**. Also: the map is one-way,
      there being no `VidMessageSlotUnmap`.
      **THE CONSUME LOOP RAN TOO, and it makes step 8 the route on evidence rather than cost.**
      `0x221107` is the only `METHOD_NEITHER` code of the four (its input must be USER memory) and
      `Flags` must be **4**; found by a `SkipArm` probe mode that maps and completes without
      arming, so the sweep cost no guest. Armed and consuming: **64 messages, every completion
      `SUCCESS`** — but all of type `0x01000010`, the type already in the slot before anything was
      armed, **not** the `0x80010003` of an exception intercept. So we consumed **the owner's**
      stream, 64 of `vmwp`'s messages, and **the guest reset inside ten seconds**. The gate admits
      one process per partition, on a Hyper-V VM that is `vmwp`, so satisfying it means *being*
      `vmwp` and sharing its slot — **a usable receive loop needs a partition with one client,
      which is step 8**. Not established: that our own intercept was ever delivered (no
      `0x80010003` seen, and the slot was saturated), and the reset is now over-determined between
      arming and stealing rather than pinned.
      **Inheritance of a VID handle a worker still holds is excluded** on object identity —
      no child holds any of the workers' four current VID file objects. **Not excluded**: one
      inherited and since closed in the parent, which a snapshot cannot see. The children's own
      single `File` object is **unidentified** (duplication refused three ways, sole holder, module
      list unavailable), so that case is unfalsifiable here; closing it needs handle lifetimes
      captured across a child creation, which is a new arm. The same comparison shows the four VID handles are **two** file objects,
      three sharing one and one separate, which maps exactly onto the error split.
      **The gate also admits a third caller, and it is the cheap one: whoever created the
      partition.** `PsGetCurrentProcess()` matches `[partition+0x3780]` by construction for the
      process that called `VidCreatePartition`, so on a partition of our own the whole receive path
      runs from **user mode** with no driver — `VidMessageSlotMap`,
      `VidRegisterExceptionHandler`, `VidMessageSlotHandleAndGetNext` and the completion, all
      `SUCCESS` at high integrity, which the 2026-10-01 owner-partition probe runs in both of its modes. So *user
      mode is closed* is about **another owner's** partition, and kernel mode is what a **managed**
      VM costs rather than what the receive path costs. The owned case is **item 110**.
      **LiveCloudKd narrowed only as far as the handles**: they exist and are takeable, so its
      procedure is plausible rather than describing an older Windows — any further inference goes
      with the access-bit one, read off our summary of the tool, not its source. Full record, with
      the controls and the near-miss that a name search caused, in the **Step 7** section of
      [`docs/secure-kernel/secure-kernel-hypercall-feasibility.md`](docs/secure-kernel/secure-kernel-hypercall-feasibility.md).
   8. ~~**The fallback S5q's host-bugcheck stop selects, and a decision rather than an arm.**~~
      **COSTED 2026-09-30 — and the costing did not yield the decision.** What it establishes is a
      negative: the documented partition API cannot reach VTL, so the rig rests entirely on the
      undocumented VID surface and private COM contracts. What it does **not** establish is the
      cost — a first draft decided *do not build* on a buffer size read as a field count and a
      module list read as code to be rewritten, and review rejected both. **Two named probes would
      narrow it and neither settles it**, both unrun: a census of `Vid.sys`'s `0x2211A0` handler for
      the fields it validates — one call of about a dozen — and an activation probe on one of the 24
      device-model CLSIDs, which are registered rather than shown to activate. **No call was made**,
      so *no known obstacle* still rests on S5o, S5p and S5n's control of the first step only.
      Figures, decoded gates, the three tiers and both retractions are in the **Step 8** section of
      [`docs/secure-kernel/secure-kernel-hypercall-feasibility.md`](docs/secure-kernel/secure-kernel-hypercall-feasibility.md).
      **The costing has since split, 2026-10-01.** The VID/VSM half of the rig — create a
      partition, configure VTL1, enter it, register a handler, map the slot, receive and complete —
      is **built and passed** at the tier A this step predicted, as the owner-partition probe. What
      is still unpaid is the guest OS and the device model, and that half is no longer this step:
      it is **item 110**, filed so it carries its own falsification and stop condition rather than
      sitting here as an uncosted fallback.
   9. ~~**Measure delivery at the convergence point, which is what S5q's zero could not.**~~
      **RUN 2026-09-30, and the message IS delivered** — feasibility, the read, and the arm, all
      three; the result is below and the reasoning is kept because the next arm (a VTL1 raise) is
      built from it. Added
      2026-09-30 with the correction above. All three known callers of `VidInterceptPreprocess`
      converge on it, and only one of them reads `[partition+0x10]`, so **arrivals counted at
      `VidInterceptPreprocess` itself answer delivery whichever path carried the message** where a
      counter on the chained slot is blind to two of three. **Closes when** a raise under a standing
      raw install is correlated with an arrival there, *with a positive control* — a raise under a
      Vid-installed intercept, which must arrive — and with the backed-out arm interleaved rather
      than run as a clean batch afterwards. A zero on its own repeats arm 0's uninterpretable
      reading. **And it must carry the `[partition+0xB68][3]` read in the same arm**, because an
      arrival count separates *not delivered* from *delivered* and cannot separate the unclaimed-slot
      branch from an enqueue to a pre-existing claimant — the slot is mutable, so a read taken
      afterwards reports afterwards. That read is the one the
      "was the slot claimed?" section has been asking for since S5k; this step is where it belongs
      rather than as an arm of its own. **Ahead of steps 7 and 8 in the order**,
      because it can move the delivery question without owning a partition or taking a handle out of
      a protected process.

      **Feasibility answered 2026-09-30, and it is the third branch: neither a patch nor a
      breakpoint, but a read.** The step asked how the root's `Vid.sys` can be instrumented at all
      and said to cost that first; the answer is that it does not need to be, because
      `VidInterceptPreprocess` **stores what it received before it branches on anything**. Its
      entry block runs straight to `+0x4f` with no branch: it copies the whole `HV_MESSAGE` to
      `[VP+0x30]` and timestamps `[VP+0x208]`, and the type switch then leaves the chosen handler
      at `[VP+0x158]` and its reason index at `[VP+0x200]` — so a delivered `#BP` is four values
      naming each other (`0x80010003`, vector `3` at `[VP+0x68]`,
      `Vid!VidHandleExceptionIntercept`, `2`). The VP is reached from the context S5q step 2
      already reads live — `[P+0xAB0] + VpIndex*0x980`, validated by `[VP+0] == P`, which
      `VidHandleExceptionIntercept` itself relies on — and `[P+0xB68]` hangs off the **same** `P`,
      so *"in the same arm"* costs nothing extra: one request — **not** one instant, since a
      single IOCTL reading several fields is not an atomic snapshot and the claim table is
      writable by any VID client while it runs. Sound because
      `[VP+0x208]` has one writer with this structure's fingerprint and **0 address-taken** sites
      across `Vid.sys`, and because `VidHandleExceptionIntercept` has **exactly one reference in
      the whole image** — the `lea` inside `VidInterceptPreprocess`. That is what is visible in one
      image and **not** a proof that every invocation goes through preprocess; the positive control
      does not close that gap either, since it is delivered by VID's own registration path and so
      says nothing about a raw-installed one. What the instrument reports is *an arrival was or was
      not observed at the convergence point*, and a raw-arm negative is **inconclusive about
      delivery** — the three limits below say the same thing and this sentence used to contradict
      them. Built
      [`tools/pe_xref.py`](tools/pe_xref.py) for that second reading, `--self-test` 26/26 and
      mutation-verified, because a reachability *negative* over an image is the one
      claim a byte scan cannot make: a branch encodes a displacement, not an address, and the
      address appears in immediates that transfer control nowhere. **Cost**: one bounded kernel-read
      IOCTL in `h3probe.sys` and a client script, against a patch route that fits mechanically
      (5-byte first instruction, 10 bytes of padding, `rel32` in range) but buys a **PatchGuard**
      exposure this gate did not measure, and a host-breakpoint route that needs a reboot this bench
      has not configured (`debug` is off) and is read-only when it arrives. The full record, with
      every offset and both censuses, is the **step 9 feasibility** section of
      [`docs/secure-kernel/secure-kernel-hypercall-feasibility.md`](docs/secure-kernel/secure-kernel-hypercall-feasibility.md).

      **Steps 1 and 2 are RUN, 2026-09-30: the read is built and the walk holds at run time.**
      `IOCTL_H3_VIDVP` (`0x80A`) takes a partition **id**, resolves the context through
      `H3ReadPair` under Hyper-V's own lock, refuses unless the registered routine lands inside the
      loaded `Vid.sys`, and reads everything through a canonical-address + `MmIsAddressValid` +
      SEH helper. On both lab partitions: `[V+0] == P` for all four VPs, `[P+0xAA8]` = 2 against
      Hyper-V's own report of **2 vCPUs** per guest, and `[P+0xB68]` reading `FF FF FF FF FF FF FF
      FF` — so **`[P+0xB68][3]` is `0xFF`, unclaimed**, which S5k asked for and nobody had ever
      read. **The strongest reading is a differential**: the live markers reproduce the type switch
      the feasibility gate read out of `Vid+0x3D137`, on two message types and two partitions —
      `0x80000000` → `VsmmHandleMemoryIntercept` / reason `7`, `0x80010000` →
      `VidHandleIoPortIntercept` / reason `5`, both predicted by the `lea`/`mov esi` pairs beside
      the jump table. Bench untouched: nothing written, no intercept installed, driver stopped
      after, host uptime continuous, no bug check, both guests up throughout. One caveat the output
      made plain: `[V+0x68]` is the exception vector **only** for message type `0x80010003` — on
      the IO-port message it read `0x71`, which is payload.

      **THE ARM IS RUN, 2026-09-30, AND THE MESSAGE IS DELIVERED.** A `#BP` raised in the guest
      under a standing raw `HvCallInstallIntercept` (type 3 / `AccessType` 4 / vector `0x03`)
      arrives at `Vid!VidInterceptPreprocess` on **both** VPs of partition `0x3`: `[V+0x30]` =
      `0x80010003`, `[V+0x68]` = `3`, `[V+0x158]` = `Vid+0x11690` `VidHandleExceptionIntercept`,
      `[V+0x200]` = `2` — every marker as the static read of the jump table predicted — with stamps
      **+27,772,140** and **+32,260,001** past baselines taken immediately before the raise. The
      copied message decodes as itself: `Sender` = partition `3`, `VpIndex` `0` on VP 0 and `1` on
      VP 1 (so the message's own view of which processor raised agrees with the slot it was read
      from), `InstructionLength` `1`, `InterceptAccessType` `2`. The raiser was **held** — S5h's
      signature — and the interleaved backed-out arms on **both** sides show no exception markers
      and a raiser that completes. **So S5q arm 1's third explanation, *not delivered because the
      arming sequence is incomplete*, is eliminated, and `forwarded = 0` there was the chained slot
      being bypassed rather than nothing arriving — and that is now ONE run, not an inference across
      two.** A **combined arm** chains the callback, installs the intercept and reads the markers
      and `forwarded` at the same samples: with the chain standing, `forwarded = 0` while both VPs
      read `0x80010003` / vector `3` / `Vid+0x11690` / reason `2` at stamps ~**1.08 × 10⁹** ticks
      past baselines taken *after* chaining. Review round 3 on #427 asked for exactly that rather
      than accepting the cross-run pairing. **Its own first run was vacuous and the driver's guard
      caught it**: while chained the pair Hyper-V holds is *ours*, so the read was refused with
      `OBJECT_TYPE_MISMATCH` — and the client reported "no arrival observed" from the zeroed buffer
      because it never checked the status. The driver now takes the saved pair from its own chain
      record, the client raises on a refusal, and the arm asserts positively that the saved pair was
      used. What is measured is reception **at preprocess**
      and nothing about retention: "held" is produced by *both* branches of
      `VidHandleExceptionIntercept`, so calling this S5j's received-and-retained reading — as an
      earlier version of this paragraph did — reads a branch out of an observation that does not
      distinguish the branches, and contradicts the next paragraph.

      **What the arm did NOT settle.** Which branch `VidHandleExceptionIntercept` took:
      `[P+0xB68][3]` read `0xFF` before the install and `0xFF` after the removal, consistent with
      arm 1 and corroborated by the trap staying held while nothing completed it, but not decided —
      a claim-and-restore between samples reads as unchanged. And the raise was in **VTL0**, as
      S5q arm 1's was; reading the markers for a **VTL1** raise was the cheap next arm rather than
      something this one covered. The Secure Kernel scope limit stands exactly as S5i left it:
      VTL1 user mode is not VTL1 kernel mode.

      **The VTL1 arm is RUN, 2026-09-30, and it reaches VID too — and it settles S5h's fork.**
      `spin_host.exe BP1` raising inside the VBS enclave, same instrument and partition: both VPs
      read `0x80010003` / vector `3` / reason `2`, with the interleaved backed-out VTL1 arms on
      either side reading nothing and completing 2,000 rounds at **7.63** and **7.49 µs** each.
      **The message's `Rip` is the enclave's `int3`** — `0x00000243071E500D`, `0x123` bytes from the
      routine the raiser named in that same run — and an intercept fired on a VTL0 excursion would
      name the VTL0 instruction instead, so the excursion S5h could not dismiss is excluded and the
      trap is taken at the VTL1 raise. **It agrees with S5h across gates**: both arms' message
      `Rip`s match S5h's halted `RIP`s in their low 16 bits (`500D`, `748D`) on a different boot.
      **`ExecutionState` bits 7-10 track the VTL, measured across two vectors**: `0x0097` in VTL1
      and `0x001F` in VTL0 for **both** `#BP` (vector 3) and `#DE` (vector 0), which separates *the
      active VTL* from *something about `#BP` in an enclave* the way one vector could not. A draft
      said that check was not runnable because the hypervisor takes exception intercepts only for
      vectors 3 and 4 — **false**, and review caught it: S5i read a per-partition allowed-vector
      mask at `+0x6124` with an unconditional *exemption* for 3 and 4, and `#BR` already installed
      through the mask. The vector-0 install was then tried and **succeeded**, which adds a vector
      to what this child's mask is known to admit. **And the freeze is now measured.** Reading the guest's progress counter WHILE the intercept stands — the
      side of the release S5h's retracted "advancing" reading got wrong — gives `handled = 0` at
      ten samples over 30 s, against **2,282** the moment teardown releases it, reproducing S5h's
      artefact one line below the correct reading. Interceptions kept arriving throughout: 20 new
      stamps on both VPs at **one** `Rip`, with nothing retiring — twenty calls to
      `VidInterceptPreprocess`, which is not the same as twenty executions of the instruction.
      **Where the
      second VP's events come from was unresolved for two more arms.** Step 6's arms measured the
      guest VPs' run
      state and found `InterceptSuspend` **transient** with both VPs accumulating runtime, so the
      VPs **are** resumed and round 3's necessary-condition objection to migration is removed — but
      nothing correlates the single raising thread with either VP, so that does not choose between
      migration and one pending intercept being re-preprocessed — **and the loop question then
      supplied that correlation**: `Other Intercepts/sec`, the bucket the exception lands in, is
      zero on both VPs unarmed and nonzero on **both** armed, and that counter moves because an
      instruction trapped on that VP. Migration is the supported reading, on the stated
      assumption that nothing else in the guest raises `#BP`. Two drafts got it wrong in
      turn before that: the first
      called the two VPs "consistent with one held raise", which review refused because the raise
      loop is one thread; the second called it that thread ping-ponging between vCPUs, which review
      refused again because migrating needs the VP resumed and `WinHvCompleteIntercept` — the thing
      that resumes an intercepted VP — is exactly what nothing is *observed* calling. Settling it meant
      measuring the delivery mechanism, which is an arm. Nothing else rests on it: delivery, the
      `Rip`, the `ExecutionState` 2×2 and the freeze are each measured independently. The first
      draft also wrote the unarmed loop's **15.3 ms** as "15 s", three orders out.
      Scope unchanged: VTL1 user mode is not Secure Kernel.

      **One defect worth keeping, because it was this plan's own warning landing in this plan's own
      code.** Run 1 reported the arm CONFOUNDED: the second backed-out arm showed an exception
      marker. It was **stale** — that VP had taken the intercept during the armed arm and gone
      idle, so the marker stood with a stamp byte-identical to the previous phase's read. The hit
      test compared type and vector and ignored the timestamp, which is exactly the defect review
      round 3 filed against this plan. The rule now requires a stamp later than that arm's own
      baseline. The interleaved backed-out arm *after* an armed one is the one case that walks into
      staleness, and interleaving is what the plan asked for — the two requirements interact and
      only running them together showed it.

      Bench: intercept installed once per armed arm and removed in the phase after it, teardown
      reporting **0 standing** every time across three unchained runs and two combined ones, raiser
      killed after every arm, driver stopped between rebuilds, guest responsive with 105 processes,
      both guests up **3h26m** unbroken, host uptime continuous, no bug check since boot. Nothing
      written to a partition object; the **combined** arm chained and unchained the callback — which
      arm 0 had already characterised — and its `unchain` returned `SUCCESS` with the saved pair
      restored. Full record in the
      **step 9, the arm** section of
      [`docs/secure-kernel/secure-kernel-hypercall-feasibility.md`](docs/secure-kernel/secure-kernel-hypercall-feasibility.md).

      (The three checks this paragraph used to name as the arm's first act —
      `[VP+0] == P`, a plausible `[P+0xAA8]`, and `[P+0xB68]` pointing at a table of mostly
      `0xFF` — are the ones steps 1–2 ran, and all three passed.) **The arm's shape, settled across three
      review rounds and cheaper than any of them sounded: one IOCTL called three times per raise —
      before, during the hold, and after.** Delivery is `V+0x208` **moving**, never its value,
      because a previous `#BP` on that VP leaves all four markers already reading as a delivery and
      a post-raise sample cannot tell that from a new arrival; the timestamp works as the version
      stamp precisely because preprocess writes it unconditionally and before the type dispatch.
      The third read is a spoiler *filter* on `[P+0xB68][3]`. **Three limits carry into that design
      rather than being retired by it**, and the doc states them once rather than per paragraph,
      because three review rounds landed on one sentence that kept reclaiming coverage. First, the
      read is **last-arrival state, not a count**, so the positive control has to show the markers
      are still there when sampled. Second, that control shows the *instrument* works and **not**
      that a raw-installed delivery shares VID's own route, so a raw-arm negative means *no arrival
      was observed at the convergence point* and not *not delivered*. Third, nothing durable
      records which branch `VidHandleExceptionIntercept` took, and sampling cannot supply it at any
      cadence — a claim-and-restore between two samples reads as unchanged — so **arms 1 and 2 are
      not separable by this instrument at all**, and the remedies that would separate them are
      stabilising the table or instrumenting the handler, which is the patch route this gate
      declined. Delivery itself rests on the VP markers alone and is unaffected by the third.

   **The list above is the *ownership* route, and S5q goes around it rather than continuing it.**
   Every step in it exists because the exported user-mode receiver needs a partition handle.
   `WinHvSetInterceptRoutine` needs none — it is a `winhvr.sys` kernel export keyed by partition id
   — so with the standing constraint lifted for disposable guests the active work is **S5q**, and
   steps 6 to 8 are what matters only if S5q's stop conditions fire. Step 7 stays open on its own
   terms; step 8 was the fallback the host-bugcheck condition selected, and is now **costed
   without a decision**, so that condition selects a route whose cost is still unbounded. **Step 9 went ahead of both
   and is now RUN** — it was put there because arm 1's conclusion was narrowed from *answered
   against* to *open*, and putting the cheapest thing that could move it before the routes needing
   ownership or a duplicated handle is what got the question answered: the message is delivered.
   **What the answer does to this list: nothing yet, deliberately.** Steps 6–8 exist to get the
   root a *receiver it owns*, and delivery being established does not supply one — it removes the
   possibility that there was nothing to receive. Whether that changes the case for owning a
   partition depends on the next arm (a VTL1 raise) rather than on this one, so the order below is
   left as it stands rather than rewritten on a result it does not turn on. **This is the second time
   this plan has kept walking a route after a cheaper one opened beside it** — S5m already deleted
   the driver S5k specified — and the cause both times was a schedule written against the obstacle
   in front of it rather than against the question. **This correction is a third instance of the same
   cause**, caught by re-reading rather than by an arm: the conclusion was written against the
   instrument in front of it rather than against every path into the receiver.

   **The route to Secure Kernel VTL1 kernel mode, ordered 2026-09-30 — written against the
   question rather than the obstacle, which is what the paragraph above says this plan keeps
   failing to do.** The goal is DbgEng inspecting `securekernel` in VTL1 kernel mode. The plan that
   owns it is [`docs/secure-kernel/exdi-stub-plan.md`](docs/secure-kernel/exdi-stub-plan.md), whose
   premise is that SK ships the metadata a debugger keys off (`KdDebuggerDataBlock`: `KDBG`, size
   `0x3A8`, `SkLoadedModuleList`, `SkeProcessorBlock`, the `Skmm*` bounds, the PTE swizzle bit) and
   **no transport** — and that EXDI closes exactly that split by serving registers and memory from
   outside the target.

   **All three of that stub's inputs are already measured**, which is the thing this item's own
   ordering has been obscuring:

   | what EXDI needs | state |
   |---|---|
   | VTL1 **registers** | **H3, PASS** — the hypervisor grants a parent a child's VTL1 registers, with a VTL0 control that discriminated |
   | VTL1 **memory** | **H4** — `HvCallReadGpa` withholds VTL1 pages as `HV_STATUS_SUCCESS` + zeros + `ReadIntercept`, **but an independent oracle read the same ranges from the root** by direct mapping, and SK's **PML4** was identified from the VTL1 `CR3` |
   | **kernel awareness** | **E1, answered 2026-09-22** — how DbgEng locates the kernel over EXDI |

   **So the critical path is E3 then E4** — **for an EXDI stub, which this item does not build and
   which needs a different lab** (qualified 2026-10-01; the sentence stood here unqualified while this
   entry's own *Out of scope* parked H5a, which is the contradiction the status section at the top
   resolves). E2 is unrunnable on this bench because Hyper-V owns the box and a VMware guest under WHP
   loses its VBS — which is why that stub would have to serve EXDI from the **root** rather than from
   a third-party gdbstub, and why the honest answer is a second host.

   **And steps 6–9 and everything today are a different axis.** The ownership gate, the receiver,
   the consume loop and the VTL1 entry-context arms are about **control** — stopping a VP, arming
   breakpoints. An EXDI stub wants that for breakpoints and stepping; it does not need it to *read*
   Secure Kernel. That work is E3's second half rather than the path to the goal.

   **Three terminal results, and the ordered route that used to sit here reached only the first of
   them** (2026-10-01). A **capture-served inspector** of Secure Kernel — modules, symbols, memory,
   with no debuggee in the path and DbgEng present only as gate S2's image-symbol server — is what
   shipped, and the live source behind the same four tools is the attempt still to be made. A
   **DbgEng-served inspector** over EXDI is **out on the lab**, with H5a's own reversal condition
   unchanged. A **debugger** of an initialized
   Secure Kernel — breakpoints and stepping inside a running `securekernel.exe` — is **item 110**,
   which needs the experiment to own the boot. **The three cheap static arms this list opened with
   stay here, on this item.** A draft moved them to 110 on the grounds that they are control-axis
   questions; that was wrong, because this item's goal includes closing the remaining gaps and these
   are three of them:

   1. **Census the writers of `[partition+0x10]`** with
      [`tools/vid_field_census.py`](tools/vid_field_census.py), the instrument this line built for
      `[p+0x3060]`/`[p+0x3079]`. **Narrowed when the owner-partition probe passed**: it no longer
      bears on whether a receive loop can be owned at all, because that probe owns one. What is left
      is chaining on a **managed** VM — the only case needing `[partition+0x10]` to be
      retrofittable.
   2. **Decompile `VidHandleExceptionIntercept`'s branch.** Parked as "not answerable by sampling",
      which is not the same as unanswerable: Ghidra is on this bench and settled three other
      questions on 2026-09-30 that had been recorded as limits. It is the one route to *which
      branch* a delivered message took, which sampling cannot supply at any cadence.
   3. **Separate the reset's two causes** — a sustained `SkipArm` consume-only run, at most one guest
      reboot — which says whether *be `vmwp` and read* is safe as a standing capability. The
      correction recorded against this one is that H3 reads VTL1 registers with
      `HvCallGetVpRegisters` keyed by **partition id** and H4's oracle reads VTL1 memory by direct
      mapping, so *neither takes a VID handle or the attach* and observation never rested on it; the
      arm is about the **control** half. On its **own** partition the probe arms, maps, drains and
      completes with the guest monotonic, so *arming* is survivable and the managed-VM reset points
      at the 64 stolen messages — still an inference across two different partitions, which is why
      the arm stands.

   **The `CoCreateInstance` probe on one of the 24 device-model CLSIDs is also this item's**, filed
   under step 8 above, where it is recorded as *"registered rather than shown to activate. No call
   was made."* Item 110's arm 3 depends on its answer but does not own it.

   **Restating this item's status retracted no measurement; what it retracted is a goal restated in a
   late section.** So everything that follows is still the record — read the control-axis material
   below as **item 110's** subject, and the EXDI material above as a design held behind E2's lab
   condition rather than as a schedule.

   **The control axis, off this route and not off Secure Kernel.** This paragraph was headed *"a
   separate goal… answers questions about the hypervisor's VTL semantics rather than about
   Microsoft's Secure Kernel"*, written before the results under it and **wrong as of the
   image-backed follow-on**, which stops and resumes real `securekernel.exe` code. What is true is
   narrower: these results are off the **inspection** route this item is about, and they are the
   strongest thing measured on the control axis. Both were cheaper than this item's costing implied
   — tier A plus a VSM config, no guest OS and no device model. **Implemented and passed live on
   2026-10-01 as the guarded owner-partition probe in
   [`tools/vtl1_control_probe.c`](tools/vtl1_control_probe.c).** It builds a one-VP long-mode
   image, targets fixed vector `0x20` at VTL1, and accepts only its marked vector-3 VID message
   while the intercept holds the VP. The decisive memory contract is paired: memory-block flags
   `0x9` make the VA backing VSM-capable, and GPA-range flag `0x8` applies the configured VTL
   protections. With that pair, the high-integrity run stopped at VTL1 GPA `0x10008`, verified the
   VTL1 execution witness, held the owned intercept for 266 ms, completed it with flags 2, stopped
   the VP and deleted the disposable partition, exiting zero. The `/W4 /WX` build and offline
   layout/message self-test also pass. Build, sequence, exact guarded versions and pass condition
   are in
   [`docs/secure-kernel/vtl1-control-probe.md`](docs/secure-kernel/vtl1-control-probe.md).

   **The minimum real-image follow-on also passes.** `--securekernel-breakpoint` guards and maps the
   matching shipping `securekernel.exe`, calls its symbol-derived `DbgBreakPointWithStatus` at
   `0x14001fa70` from the owned VTL1 CPL0 interrupt handler, and accepts the stop only after the
   pending state reports VTL1, CPL0 and the selected `RIP`. Completing the exception advances to
   the stub's `ret`; a second owned `GET_NEXT` resumes dispatch, after which the handler records its
   post-return witness and returns through `iretq`. The 250 ms live hold, completion, return and
   partition deletion all passed. This establishes resumable execution of guarded Secure Kernel
   image code without claiming that the Windows Secure Kernel runtime was initialized; the minimum
   Windows/VBS boot remains the route to that stronger result, and it is **item 110**.

   **Two limits worth stating where the result is, rather than only in item 110.** The guarded image
   is the **host's** `securekernel.exe` — `%SystemRoot%\System32\securekernel.exe` by default — so
   what is pinned is privilege, stop ownership and resumability, and **not** a guest build's
   provenance. And the state primitive is half exercised: the probe reads VTL-selected state
   through `HV_INPUT_VTL_EXPLICIT` at both VTL0 and VTL1
   ([`tools/vtl1_control_probe.c:1073`](tools/vtl1_control_probe.c) and `:1114`) and writes VTL0
   state before the VP starts (`:1331`), so the selector and VTL semantics **are** decoded; what is
   unrun is a **write at VTL1 while a message is pending**, which is item 110's cheapest arm and
   the one that would keep a real Secure Kernel stop from ever patching an instruction.

   The other candidate was **answered by S5c**: the
   suspend register is writable from
   the parent and halts the VP, VTL1 state is readable across the halt, and the halt is VP-wide
   rather than VTL-selective — so it buys a live *inspector* and not the stop S5 asks for. Still
   decides inspector
   versus debugger, and still the one that would change the shape of S3's tool surface rather than
   its contents. **That surface now exists**, so the change is to something built rather than to a
   design: a capture session is a fixed snapshot whose whole decode travels with the open, and
   execution state would make it neither. Independent of the rest, so it can run in parallel or not
   at all.
4. **Build stability of the offsets, and the derivation that replaces them.** **Half-answered
   2026-09-27 by S2**: the PDB derives both offsets per build and agrees with the scan on this one,
   and it reaches `SkLoadedModuleList` directly where the scan cannot. What is *not* answered is the
   no-symbols case, which is the one the recipe below is for — a host with no symbol store, or a
   build whose PDB is not served, still has only the tag scan. So both routes stay, and the scan is
   still the primary rather than the fallback.

   `KdDebuggerDataBlock` at `+0x1335E0` and `SkLoadedModuleList` at `+0x127770` are **one build**,
   and the block's `Size` already disagreed with an earlier static reading (`0x3A0` live against
   `0x3A8` from the image). So the offsets are a fast path to *verify*, never the lookup — but
   "locate them by signature" is not the instruction either, and an earlier draft of this item said
   it: **`SkLoadedModuleList` is a bare `LIST_ENTRY` with nothing to search for.** Only the block
   has a signature. The derivation H4 actually used, and which an implementation should follow:

   1. Find `KdDebuggerDataBlock` by its **`KDBG` owner tag** within SK's address space, and *report*
      the `Size` found rather than matching a remembered constant — matching `0x3A8` exactly is
      what made a first scan report zero occurrences while the tag sat three pages away.
   2. **Validate it**: `KernBase` at `+0x18` must equal the SK base the PE walk established.
   3. **`SkLoadedModuleList` is then read out of it** — the `PsLoadedModuleList` field at `+0x48` —
      rather than located independently.
   4. **Validate that**: walk one entry and check its `DllBase` equals the same SK base.

   Keep the structural route — search for a `KLDR_DATA_TABLE_ENTRY` whose `DllBase` is the SK base
   with `SizeOfImage` sixteen bytes later, then follow its `Blink` — as the **cross-check** rather
   than the primary. It is what found the head independently in H4, and the two agreeing is what
   made either believable.

## 107. [windbg-mcp] A misspelt tool argument is silently ignored, and the call answers `status: ok` — **done** (2026-10-02)

**Repo:** `windbg-mcp`. **Origin:** hit live, 2026-09-29, during item 103's S5o gate. Three
`disassemble` calls passed `target` — which is not a parameter; the parameter is `address` — and
each was served as though it had asked for nothing: `address` deserialised to `None`, the tool
disassembled at the current instruction pointer, and the result came back `"status": "ok"` with a
`start` that was the image entry point. It read as a tool defect for several minutes, and the gate
fell back to `execute` + `uf` to get the disassembly it wanted — which is the text hatch this repo
tries not to reach for.

**The failure shape is the one this repo has already written down, in `src/batch.rs`:** *"Serde
ignores unknown fields by default, which is the wrong default for a step: a misspelt `expect` is a
step that asserts nothing while reading as though it asserts, and it fails open."* A misspelt
`address` is a call that disassembles somewhere else while reading as though it disassembled where
asked, and it fails open the same way. **So this is an unfinished class fix rather than a new
idea** — `#[serde(deny_unknown_fields)]` is already the convention here and reaches **3 of the 52**
`*Args` structs in `src/server.rs` (`BreakpointArgs`, `ClearBreakpointsArgs`, `DebugBatchArgs`).

**The MCP spec neither requires nor forbids rejecting unknown arguments, and that shapes the fix
rather than excusing it.** The 2025-06-18 tools page makes servers responsible — *"Servers MUST:
Validate all tool inputs"* — and lists *"Invalid arguments"* among the protocol errors carrying
JSON-RPC `-32602`. What it does not say is that a property absent from `inputSchema` is invalid,
and **JSON Schema's default is that it is not**: without `additionalProperties: false`, an extra
key conforms. So a client sending `target` is, today, sending something our own published contract
calls valid, and rejecting it while advertising otherwise would be the server breaking its own
schema.

**Which makes the remedy two halves that must land together**, and is the reason this is an item
rather than a one-line patch:

1. `#[serde(deny_unknown_fields)]` on the remaining `*Args` structs, so the argument is refused
   rather than dropped; and
2. the published `inputSchema` carrying `additionalProperties: false` to match, so a client can see
   the constraint before it violates it. `schemars` emits that from the same attribute, so the two
   halves are one change per struct — but **verify it reaches the served schema**, since
   `src/schema.rs` walks and rewrites schemas for per-client surfaces and treats
   `additionalProperties` as a subschema keyword (`SUBSCHEMA`), with a boolean form handled
   specially at `schema.rs:293`.

**Two things to check before doing it wholesale.** `deny_unknown_fields` and `#[serde(flatten)]`
are mutually exclusive, which is exactly why `batch.rs` collects leftovers by hand instead — so any
args struct that flattens needs the `batch.rs` treatment rather than the attribute. And the
per-client surface work means a tool's schema is not always served verbatim; a test that asserts
the refusal should drive it through the served surface, not the struct, or it pins the wrong thing.

**Worth a regression test of the shape this repo prefers**: not "an unknown field is refused" on
one struct, but a test that enumerates the `*Args` types and asserts the property holds for each,
so the next tool added cannot quietly opt out. The three that already carry it would pass today and
the other 49 would not, which is the point.

**A second shape of the same family, inherited from item 103 when it closed on 2026-10-02.**
`sk_symbol`'s `name` is documented **unqualified** — the module is applied by the tool — so a
*qualified* `securekernel!SkdInitDebuggerDataBlock` is outside its contract. A lenient engine resolves
it anyway and the tool reports `securekernel!securekernel!SkdInitDebuggerDataBlock`: the right address
with a doubled rendering, `status: ok`, and the identifier fields (`address`, `rva`,
`engine_address`) byte-identical to the unqualified call. So nothing downstream is wrong; what is
wrong is the one field a caller would quote back — and a lossy display form must never be the
thing anyone keys on.

**It is here rather than on item 103 because the judgement it needs is this item's, not one tool's**:
*strip a redundant qualifier* and *refuse a foreign one* are different answers, and `skci!Foo` passed
to `sk_symbol` should plainly be refused rather than doubled. Deciding that per tool is how a surface
ends up with 52 conventions. The remedy above — `deny_unknown_fields` plus a matching
`additionalProperties: false` — does **not** cover it, because the argument here is well-named and
ill-formed rather than unknown; what it needs is a validator on the *value*, which is the second
shape this item now carries.

### What landed

**Both halves, on all 52 `*Args` structs plus two places the item did not name.** The attribute is
on every one of them — not a `#[serde(flatten)]` among the 52, so the `batch.rs` treatment this
entry warned might be needed was needed nowhere new — and `schemars` emits the matching
`additionalProperties: false` into each served `inputSchema` from the same attribute.
`mcp_smoke::every_tool_refuses_an_unknown_argument` walks the surface and asserts both halves per
tool: 67 schemas that say so, and 67 calls carrying a key no tool has, each refused with that key
named and the tool's own names listed beside it. `src/server.rs`'s tool-parameter section now states
the rule once, where the next struct is written.

**The two places the "remaining `*Args` structs" formulation does not reach**, both found by
enumerating rather than by the item:

- **A nested object a caller fills in.** `walk::FieldArg` and `structured::WatchRequest` are the
  same failure one level down — a misspelt `size` inside a `fields[]` entry is a column read eight
  bytes wide instead of four, silently. (The coordinate types already denied unknown fields, which
  is why only two were left.) The test holds every `$defs` entry of every input schema to the rule,
  with `BatchStep` the one exception and `src/batch.rs`'s hand-rolled `unknown_fields` the reason
  it is an exception rather than a gap.
- **The one tool declared with no `Parameters` at all.** `attach_kernel_local` had no schema of its
  own, so rmcp dropped *every* argument rather than an unknown one — and there the dropped argument
  reads as the caller having reached for `attach_kernel` and getting a local kernel attach reported
  as success. An empty `NoArgs` closes it, and the invariant then has no exception for the test to
  carry. It also decided the order of the test: the schema pass runs over every tool before any tool
  is called, so a regression that took that refusal away fails the assertion rather than attaching to
  the local kernel on the way past.

**Two things this entry had wrong, both about where the fix lands rather than what it is.**

1. **`src/schema.rs` has nothing to do with it.** That module rewrites **output** schemas —
   `constraints_of` is called for `output_schema` and nothing in this crate touches an input schema —
   so its `SUBSCHEMA` handling of `additionalProperties` was never on this path. The input half is
   rmcp's `validate_and_strip`, which removes the root `title` and `description` and nothing else,
   and the per-client narrowing drops whole tools without editing a schema. Verified on the wire
   rather than reasoned about, which is what the item asked for and is the half it got right.
2. **The refusal is not `-32602`.** rmcp's `into_tool_argument_error` converts an argument
   deserialization failure — which *is* `invalid_params` internally — into a tool result with
   `isError: true` and the message as its text, so the code the spec lists never reaches the client
   and the refusal travels the same channel as every other refusal here. One consequence is worth
   naming: that result carries no `structuredContent`, so a client branching on `error.category` sees
   nothing for the commonest caller mistake there is. Left as it stands rather than rewrapped —
   intercepting it means matching rmcp's message prefix, and the message already names the field and
   lists the names the tool does have, which is what a caller acts on. What would make it worth
   doing is a second refusal shape arriving on that path, or a client that branches on the category
   and cannot read text.

**The second shape — a well-named, ill-formed value — is decided as *refuse*.**
`server::reject_module_qualifier` sits beside `reject_command_breakers` as the same kind of rule, and
`sk_symbol` applies it to `name` beside the existing `name`/`address` check, so both refusals happen
before a session is looked for. **Refusing rather than stripping is the decision**, and it is about
the surface rather than about this tool: telling a redundant qualifier from a foreign one needs the
qualifier itself, which is the engine's spelling of the captured image and lives in the worker — so a
lenient reading would move the check away from the caller's terms and buy a second convention, and
`skci!Foo` is plainly the foreign case either way. One rule, stated once, for the next parameter whose
module this server owns. `a_qualified_name_is_refused_where_the_tool_supplies_the_module` drives both
qualifiers and asserts the unqualified form still reaches the ordinary session refusal, which is what
says the rule is about the qualifier rather than about the parameter.

**What it found, which is the half an entry like this is worth reading for.** Turning the default
round immediately failed three tests in the dump tier, all on one call shape: four places in
`tests/mcp_smoke.rs` asked `registers` for `{ "filter": "pc" }`, and `registers` has no `filter` —
that is `modules`' parameter. Every one of those calls had been reading the whole integer register
set and reporting success, which is the item's own failure verbatim, in the suite that exists to
catch it. A static sweep then checked **every** tool-call argument object in the repository against
the served schemas and found three more, all in `tools/`: `attach_kernel { "timeout_ms": … }` in both
the Binary Ninja and Ghidra oracles, and `execute { "timeout_ms": 5000 }` in the Secure Kernel
handoff probe. None of the three is a parameter; all three had been dropped in silence, and all three
would now be refused at runtime — so the class fix's first act was to break three of this project's
own drivers, which is the evidence that the keys were never doing anything. The sweep is the cheap
half to repeat: ask a running server for `tools/list`, then brace-match every `"<tool>", json!({…})`
and `<tool> { … }` in the tree and compare top-level keys against `properties`. It reports four
remaining hits and all four are deliberate — two doc examples *of* the bug, one typo test, and a
comment naming `attach_kernel_local`'s hazard.

**One thing is deliberately still open, and it is in the batch vocabulary rather than in a tool.**
Measured off the wire: of the defs an input schema carries, the ones with no `properties` of their own
are the string enums — and `Check`, which is an internally tagged enum rendered as a `oneOf` of
objects. So a key **added** beside an `expect` entry's own fields is still dropped. It is narrower
than the class this item is about: every field of every `Check` variant is required, so a misspelt one
already fails closed, and what a step carries at its own level *is* collected and named by
`BatchStep::unknown_fields`. Closing it would put the same keyword on three `oneOf` branches that the
test's `$defs` walk does not reach, which makes it `src/batch.rs`'s mechanism to extend rather than a
hole in this one — and the one place in the input surface where "refused" is code rather than a schema
keyword stays one place.

**What it cost, measured rather than estimated** (2026-10-02, and the arithmetic is in
`MODEL_VISIBLE_CEILING`'s doc comment and `docs/token-budget.md`): the model-visible surface goes
103,321 -> **105,276 B** and the payload 290,241 -> **292,196**, the same +1,955 on both, because
`,"additionalProperties":false` is 29 B wherever it lands and nothing else moved. 64 of the 67 tools
gain one at the root, two gain a second for a nested type, and `attach_kernel_local` costs 70 rather
than 29 — it gains the `2020-12` declaration an empty args struct brings and loses the empty
`properties` rmcp served it. 64 x 29 + 58 + 41 = 1,955. The model ceiling moves 105,000 -> 108,000,
leaving 2.6%; the wire and per-tool ceilings are unchanged, `debug_batch` being untouched at 10,842 B
for the `flatten` reason above. **No `outputSchema` moved**, which is the question this repository
asks of any schema change. Both goldens re-recorded; the shape golden's whole diff is one line — the
`(none)` dialect leaving, because every tool now declares one.

Verified on the ARM64 bench: `cargo test` is **1,124 unit tests and 132 `mcp_smoke`**, 0 failed, and
the dump tier green beside it.

## 109. [windbg-mcp] The server can walk a call graph forward and find calls to imports, and cannot answer "who calls this address" — done (2026-10-04)

**`xrefs_to` landed**: every site in one image whose decoded control flow reaches one address, with
module+RVA, the transfer kind, the mnemonic and the section on each. Calls, unconditional jumps and
conditional branches are counted apart, because an address that is only branched to is a label
inside another routine while one that is called is a routine of its own — and the three counts are
exact where the list is capped, so *is it called at all* survives a target reached by four thousand
branches.

**Built on the hazard scan's walk rather than beside it**, which the item asked for and which took
an extraction first: `src/codewalk.rs` now owns the bounded section walk, the window boundaries
that resume after the last *whole* instruction, the clamped overrunning section, the unreadable-window
accounting and the two budgets. `hazards::scan` was moved onto it unchanged — its own 16 tests
cover exactly those behaviours and stayed green, and breaking `codewalk`'s hex-pair instruction
length fails two of them, which is what says the behaviour really moved rather than being copied.
A second copy of that loop would have been a copy of the defects fourteen rounds of review on
[#305](https://github.com/glslang/windbg-mcp/pull/305) and
[#307](https://github.com/glslang/windbg-mcp/pull/307) took out of it.

**Decoded, never pattern-matched**, which was the item's first requirement and is now a test rather
than an intention: the destination is a field on `Flow`, the `Flow` match is exhaustive so an
upstream variant cannot be silently dropped, and the control — an address one byte inside an
instruction — comes back with no sites. The ad-hoc Python this replaces matched `E8`/`E9`
displacements over raw bytes, which is sound enough to generate a lead and not sound enough to be a
tool.

**And the field census the item warned against was not shipped.** "Answering for an address is not
answering for an object" is still true and still unbuilt, deliberately.

**Verified as a round trip, because nothing else tests a search.** A tool answering an empty list
for everything passes every "did it error" check ever written. So
`a_reference_scan_answers_where_the_import_table_cannot_be_read` (dump tier) reads the fact from the
**disassembler** first — a direct call in `nt` and the routine it names — and requires that site
back with its kind, module and RVA. Which call is deliberately not written down: the x64 sample's
`nt!KeBugCheckEx` opens with `RtlCaptureContext`, the ARM64 one reaches `KeBugCheck2` four
instructions in, and a fixture naming either stood down on the other host as a `SKIPPED` line that
read like a missing symbol and was a hard-coded callee. Measured by hand on both samples first: 391
sites for `nt!KeBugCheck2` on the ARM64 dump (383 call, 8 jump), including the site the disassembly
had already shown.

**One claim of this item's own did not survive its verification, and is now item 111.** The entry
said the tool "works with **no debuggee** against an image target, so `securekernel.exe`,
`winhvr.sys`, `Vid.sys` and any driver answer offline". It does not. On `securekernel.exe` opened as
an image the scan reports all four code sections covered with no unreadable range and finds nothing,
while `reachable_from_dispatch` proves a call exists in the same session. The cause is below this
tool — an image target's memory does not read until something else has read it, and the walk counts
what it did not get as scanned — so it is filed as its own item with the measurement, `driver_hazards`
is implicated in it on the same image, and both tools' prose now sends a reader to a dump or a live
target. **That gap was the item's rationale rather than its deliverable**, which is why this closed
and 111 opened rather than this staying half-landed: the thing asked for exists and is tested, and
what is left is a defect in a layer underneath it.

**The surface cost is 2,930 B** — 1,718 of description, 1,163 of input schema — taking the model-visible
surface from 113,516 to 116,520 — 74 B of that `reachable_from_dispatch`'s rewritten `module`
argument, from the review fix below — and its ceiling from 114,000 to 118,000, with the arithmetic and the
reason the description is the larger half recorded above `MODEL_VISIBLE_CEILING`.

## 111. [windbg-mcp + dbgscope] An image target's memory reads only after something else has read it, and a walk counts what it did not get as scanned — **done** (2026-10-04), the second half **withdrawn**

**Filed out of item 109's verification and closed the same day, by running the controls its own
*what closes it* asked for.** Half of what it alleged reproduced on five of the six images
surveyed and half of it reproduced on none — and the half that did not is the one the title ends with, so read this
before citing the title. It is also tagged `[windbg-mcp + dbgscope]` and nothing in `dbgscope`
needed changing: the entry reached for that repo because it had `decode_range` in view, and
`decode_range` turned out not to be in the story.

### What was measured

Bench: the Parallels ARM64 Windows 11 guest, dbgeng 10.0.26100.x, server **`0.21.0+g3f69dde2`** —
read from `initialize`'s `serverInfo` on every arm rather than assumed from the checkout beside it
(`.claude/rules/measurement-provenance.md`). Each arm is a **fresh server process** over ssh
stdio, so a fresh supervisor, a fresh worker and a fresh session, which is what *one read at a
time, in a fresh session* asks for. Two targets, so the reading is not one architecture's:
`C:\Windows\System32\securekernel.exe` (ARM64) and `C:\symbols\ACPI.sys\180E829Ad6000\ACPI.sys`
(x64).

| what the session did first | then `read_memory`, 16 B at `.text` |
|---|---|
| that read itself | `0x8007001E` |
| the same read a second time | `0x8007001E` |
| a 4 KiB read, then a 64 KiB read | `0x8007001E` — the 64 KiB one fails on its **first** 4 KiB chunk |
| 16 B at the image base instead | `0x8007001E`, and the `.text` read after it too |
| nothing at all, for 25 s | `0x8007001E` |
| `modules` | `0x8007001E` |
| `modules { refresh: true }` | **reads** |
| `disassemble` | **reads** |
| `xrefs_to { address }` | **reads** |
| `xrefs_to { target_module, rva }` | **reads** |
| `reachable_from_dispatch` | **reads** |
| `driver_hazards` | **refuses**, and the read after it still fails |

**None of the three candidates the entry named is the mechanism.** Not a chunked read filling
short: the bounded read fails outright on its first page, and says so — the 64 KiB request reports
*reading 4096 bytes … failed*. Not a cached page: a second identical read fails identically. Not
`decode_range`'s own read succeeding where a 16-byte one fails: it is the *same*
`dbgscope::read_memory`, strict in both. And not time. What every tool that worked has in common
is that it resolves an address or a symbol through the debugger's expression evaluator or its
disassembler *before* reading anything, and that resolution is a **module load** — the `.reload`
that `modules { refresh: true }` runs. So the tools that happened to answer on an image target
were the ones that look something up first, and the ones that read memory were the ones that did
not.

### The half that did not reproduce, and it is the damaging half

The entry's own summary was *the walk was fed something that decoded, counted it as read, and
reported a complete scan of code it had not got*. **No walk did that, on either image.**

- A cold `xrefs_to` is byte-for-byte a warm one: two sites on `securekernel` (`0x1400012a8` and
  `0x1400018ac`, both `bl`, against a callee picked by decoding the first 4 KiB by hand) and 242
  on `ACPI`, with identical `scanned` ranges and an empty `unreadable` in all four runs. It reads
  correctly because its own target resolution is the module load.
- A cold `driver_hazards` **fails closed**: *`securekernel`'s PE structures could not be read: 64
  bytes at 0x140000000 could not be read*. It never reaches a walk, so the 1,182 privileged
  instructions the entry put beside the empty reference list are not a figure this bench can
  produce cold at all — warm, the same image answers 559, on ARM64.
- And the accounting underneath is sound by construction, which is why: `decode_range` reads
  through `dbgscope::read_memory`, which is **strict** — a short read is `DbgEngError::ShortRead`,
  the closure's `.ok()` makes it `None`, and `codewalk::walk_code` turns a `None` into an
  `unreadable` range. There is no path from a failed read to a scanned byte.

What the entry's figures were taken on cannot be re-derived: `.text` of 1,002,088 bytes and a
`KVASCODE` section are an **x64** `securekernel.exe`, and the first instruction it quotes
(`cc cc … 48 ba`) is x64 code, while this guest's `System32` is ARM64. So the reading came from
another host and the claim is neither confirmed nor contradicted *there*; it is contradicted on
every target this bench can open, including an x64 one. Re-running the arms above on that host is
what would settle it, and nothing is waiting on the answer — the fix below removes the condition
the claim depended on.

### What landed

`worker::load_an_image_targets_module`, called from `open_dump`'s after-step beside `.load ext`
and before `vertarget`: if the target is an image, `.reload` it, so a session's **first** memory
call reads. Verified against ground truth off the engine — on a fresh session whose first memory
call is at `kernel32!.text`, the server answers `fd7bbea9fd030091300a00d0310a00d0`, which is
`kernel32.dll`'s own bytes at that section's raw offset read from the file on another machine;
without the fix the same call fails.

Three decisions in it, each paid for by a measurement:

- **At the open, not at each reader.** A caller cannot be expected to know that
  `modules { refresh: true }` is the precondition for `read_memory`, and every reader needing the
  same retry is a list of places to forget it.
- **Gated on the target kind**, because `modules { refresh: true }` — this `.reload` plus an
  enumeration, which is as close as a tool call gets to timing it — took **2,159 ms** on the
  checked-in x64 kernel dump against **11 ms** on the image, so doing it unconditionally would put
  something like two seconds on the open of the one kind that does not need it.
- **Gated on `GetDebuggeeType`'s class**, which is a reading rather than a guess: an image target
  answers `DEBUG_CLASS_IMAGE_FILE` / `DEBUG_DUMP_IMAGE_FILE` — **3 / 1027** — with one module, the
  image's own path as its dump file, and a process set holding the engine's `0xf0f0f0f0`
  placeholder. That pair was missing from `TargetFingerprint`'s table, which had two rows for
  `open_dump` and needed three, and it is now there.

The predicate is a pure function (`worker::is_an_image_file`) for `fingerprints_the_process`'s
reason, with a unit test over every target kind this server opens; the behaviour is
`mcp_smoke::an_image_targets_memory_reads_on_the_first_call` in the debugger tier.

**And `xrefs_to`'s description lost the caveat item 109 had just added to it** — *ask it on a dump
or a live target: on an image opened with no debuggee the scan reports ranges it did not really
read, and answers nothing* — because the measurement above says it is false twice over. 146 B
back: the description is 1,572 B where item 109 recorded 1,718, the model-visible surface 116,374
where that entry recorded 116,520, and the wire payload 327,543. The clause was added for the
right reason on a reading that did not survive being re-run, which is the whole of why this entry
is worth reading beside that one.

### The trap this left in its own test, which is the part worth carrying

The smoke test's first fixture was `C:\Windows\System32\ntdll.dll`, chosen on this entry's own
sentence that *the reproduction needs no fixture — any `System32` binary*. It passed. It also
passed with the fix **backed out**, because `ntdll` is the one image surveyed that answers a cold
read anyway: against a build with the fix removed, `kernel32.dll`, `securekernel.exe`,
`notepad.exe`, `ntoskrnl.exe` and `drivers\acpi.sys` all failed `0x8007001E` at their own image
base and `ntdll.dll` returned its `MZ`. Why it is different is not established. The fixture is
`kernel32.dll` now, and the test fails with the fix removed.

One thing that survey turned up and then disposed of: a cold `ntdll` read at base+`0x1000` comes
back **all zeros**, which is exactly the shape this entry feared — bytes returned rather than
refused, and on x64 zeros decode. They are the image's own bytes. RVA `0x1000` in both `ntdll.dll`
and `kernel32.dll` is `.hexpthk`, an executable hot-patch-thunk section that is zero-filled on
disk, confirmed by parsing both files' section tables off the bench. So the one observation that
looked like the withdrawn half was not it either.
