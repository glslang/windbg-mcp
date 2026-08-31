# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **A session handle that a raw `execute` retired can still end its own session.** `qd`, `q`,
  `.detach`, `.kill` and `.opendump` release or replace the target, which *retires* the handle
  naming that session: every later call supplying it is refused, while the worker stays live and
  reachable by a call supplying none. `end_session` was not exempt, and two things did not line
  up. The `execute` that retires the handle appends "`end_session` releases it", and `end_session`
  with that handle was refused one call later — the server contradicting its own instruction. And
  the recovery the refusal named, omitting `session_id`, routes to whichever session is *current*,
  so with anything newer open it reached a different one. The retired session could then not be
  released by its owner at all: it held one of the four sessions and a live engine process with a
  live target until everything newer had gone, or a client disconnect, or a lease expiry.

  A teardown does not touch the target retirement is about — it releases the **session**, which
  the handle still names exactly — so it is now admitted, through a
  `SessionState::accepts_teardown` of its own rather than a second caller of `accepts_default`,
  whose set is the same today but whose question is different. Both places a handle is checked had
  to widen together, the caller-side `Sessions::resolve` and the `Gate` at the front of the
  session's queue; backing either half out alone was tried and fails the same way, because
  widening one only moves the refusal to a place with no caller to explain it to.

  The refusal's own text changed with it: it names `end_session` **with the handle in it** as the
  recovery that always works, and mentions omitting `session_id` second and qualified — "only
  while this is still your current session" — since unqualified it reads as a way back to this
  target and is a way to act on another.

  Found by the session fuzz added below, on the second seed it ran under, and covered by
  `a_handle_a_raw_command_retired_can_still_end_its_own_session`. The second launch in that test
  is the test rather than scenery: with one session open the retired one is still current, so an
  un-handled `end_session` reaches it and the defect is invisible — which is why no
  single-session test had ever seen it.

### Changed

- **Every raw command this server runs is now bounded, except `index_trace`** (`FOLLOWUPS.md`
  item 14). `threads`, `goto_position`, `driver_object`, `device_object`, `irp_stack` and
  `ioctl_trace` moved from `EngineOp::Command` to `EngineOp::BoundedCommand`, so a command that
  runs away — `!drvobj` against a live kernel whose symbols are being fetched one frame at a time,
  a `!tt` seek into a trace with no index — now Ctrl+Breaks itself ahead of the caller's timeout
  and answers with the output it had, instead of holding its session's engine until it finishes.

  The split those six were on the other side of was decided on cost, not on principle: dbgscope's
  watchdog polled a `done` flag on a 200ms sleep, so the join waited out the rest of the nap and
  arming one rounded a command up to `ceil(d / 200ms) * 200ms` — a 30ms `k` became a 200ms `k`, and
  a session issues those by the dozen. That was worth a stated criterion and a list either side of
  it. It is not worth anything now: the `Watchdog` in the pinned revision parks on a `Condvar`, so
  the disarm is immediate and the bound costs nothing until it is reached. Re-measured through the
  tool surface before deciding, twice (x64 bench, sample dump, 20 rounds): a bounded `lm` medians
  3.0ms and 3.3ms against the unbounded `modules` beside it at 4.1ms and 4.2ms, and a ~170ms `.for`
  loop costs ~171ms and ~185ms rather than 200ms. The old second mode — where `lm` raced the
  watchdog's first poll and landed on either ~0.3ms or ~200.7ms run to run — did not appear.

  It arrived through the [#226](https://github.com/glslang/windbg-mcp/issues/226) work rather than
  through anything aimed at this entry: the sleep was what made a *finite* `WaitForEvent` look
  attractive, so fixing that defect retired this trade-off as a side effect and nothing here was
  revisited when it landed.

  `index_trace` stays out, and is now the only op that is. `!ttdext.index -force` deletes an
  unloadable `.idx` before rebuilding it, so a break part-way through can leave a trace with no
  usable index at all — the one case where the abort is worse than the wedge, and one whose long
  run is productive work that frees the session when it finishes. What was the general "raw
  command" op is renamed **`EngineOp::UnboundedCommand`** to say so at the call site, and
  `server::tests::only_index_trace_runs_a_command_unbounded` holds it to its single caller by
  reading the source — because the way a collapsed split comes back is a tool added by copy-paste
  taking the unbounded path with nobody deciding to, and that tool works perfectly until the day
  its command runs away.

- **`set_breakpoint` runs its `bp` on the caller's clock too.** `EngineOp::SetBreakpoint` carries a
  `patience_ms` and the command goes through `execute_command_bounded`. The address is the caller's
  text and `bp` makes the MASM evaluator resolve it, so `bp nt!Foo+0x10` against a deferred module
  with a `srv*` path is a symbol-server fetch with this session's engine held for all of it — the
  wedge the bounded path exists to stop, reached through a **typed** op where nothing in the name
  said there was a command inside. The `bl` reads either side of it stay unbounded, being direct
  engine calls with no `Execute` to break.

  It survived the first draft of the change above, whose rule was stated over ops and whose test
  certified ops, so both missed it. `worker::tests::every_unbounded_execute_in_this_worker_is_accounted_for`
  is the correction: it reads the source for `Execute` calls rather than for enum variants, and
  enumerates the five functions that legitimately run one unbounded — the two openers' fixed
  strings, the resume pump's own `Execute`, and the two that are deferred with items against them.
  Verified by backing the fix out, which names `set_breakpoint`.

  Enumerating rather than reasoning about it turned up a second instance the review did not:
  `worker::resolve`'s `? <expr>`, also caller text, filed as `FOLLOWUPS.md` item 56 rather than
  fixed here because its three callers sit on three different clocks and one of them is item 13.

  **And bounding it added a third state the result had no way to say**, which is
  `structured::BreakpointSet::cut_short`. An interrupted command comes back as an `Ok` run, so a
  `bp` that never finished looked from the caller's side exactly like one that ran and matched
  nothing — the same empty `added`, the same successful result, rendered as "(this call added
  none)". The two have opposite next moves. The listing is a real engine read taken afterwards, so
  `added` settles which happened — non-empty is a breakpoint that landed before the break and must
  **not** be re-requested. Empty settles nothing on its own: without a listing, which of the
  session's breakpoints is new is unknown, and *with* one it is still not evidence the expression
  is unset, because a `bp` at an address that already carries a breakpoint adds no id either. So
  the result says what the diff says and sends the caller to the listing for the rest. Reported in
  both channels — a structured-aware client drops the text — and it stays a success rather than an
  error, because an error is the shape a caller retries.

  That last point turned up a fact this module states as a universal and which is only half true.
  Measured on a live target: `bp ntdll!NtCreateFile` three times leaves **one** breakpoint, and
  `ntdll!NtClose+0x2` twice leaves one, because a resolved breakpoint is keyed by address — while
  `bp nosuchmod!Sym` twice leaves **two**, since a deferred one has no address to key on. `bp`
  duplicates exactly when its expression does not resolve, which is the same condition that makes
  one slow enough to be cut short in the first place. The warnings stay; what changed is that they
  are accurate about why, and no longer claim a retry is safe when the diff cannot know it.

  **One field for both causes**, unlike a stop's `interrupted`/`timed_out` pair: the `interrupt`
  tool reaches this command as readily as the deadline does and leaves the session in the same
  state, so reading only the deadline reported an interrupted `bp` as a completed one — and on the
  branch where the listing had also failed, as a breakpoint positively "set". A stop keeps the two
  apart because the next move differs there; here it does not, and `added` answers what the cause
  would only hint at.

### Added

- **`arming_the_watchdog_does_not_round_a_quick_command_up`**, in the debugger tier, guarding the
  assumption the rule above now rests on. The measurement it was extracted from
  (`measure_what_the_bounded_path_costs_a_quick_command`) is `#[ignore]`d, so it went on passing
  across the very change it exists to catch — the quantization it describes had been gone for six
  days. This one is in the debugger tier — it opens the sample dump, so a plain `cargo test`
  stands it down — and is *not* `#[ignore]`d, which is the difference: CI runs it on all three
  runners. Its oracle is a **ratio between two bounded commands of very different natural cost**,
  an `execute` of `lm` against an `execute` of a ~170ms `.for` loop, failing if they come within
  5x. That is what a fixed quantum destroys — rounding both up to a multiple of the nap makes them
  equal, where without one they stay ~50x apart — and it scales with the host, unlike the first
  version's bounded-against-unbounded margin, which a slow enough baseline grows into. The
  measurement keeps the numbers and its comment now records them.

- **A session fuzz in the debugger tier** — dbgscope's `examples/session_fuzz.rs` brought up to
  this server's surface. That example drives randomised command sequences straight at a
  `DebugEngine` and checks, after every one of them, that the session either still holds a target
  and answers or says it holds none; it exists because the three defects behind
  [#242](https://github.com/glslang/windbg-mcp/issues/242) were each found by hand, one sequence at
  a time, and none of them is about a *command* — they are about the state the previous command
  left behind, and there are more ways to reach a given state than anyone enumerates.

  What the port adds is everything between that engine and a caller. A **third state**, since
  `continue_async` leaves a target moving with nobody waiting and reads are then refused
  `target_running` — the supervisor's state machine
  ([#83](https://github.com/glslang/windbg-mcp/issues/83)), which the example cannot reach. The
  **category** a refusal carries rather than merely that it refused. A **bystander session** on the
  same server, never named by a step and asked after every round, which is the process-per-session
  claim no in-process test can make. And reclamation of whatever the sequence left.

  Its oracle is a **scale rather than an agreement**: a bounded run can stop between one road into
  the session and the next, so what is forbidden is a road moving back down
  `Moving → Holding → Gone` — `stale_session` and then an answer is the half-dead session, while an
  answer and then `stale_session` is a program that finished a millisecond ago. The seed is fixed,
  so CI walks one short deterministic sequence on all three of its `dbgeng.dll`s; the fuzz proper
  is a soak of the same test, and the run prints the states it reached and asserts it reached the
  terminal one, because a walk that never left `Holding` would pass without asking the question.
  `docs/smoke-test.md` has the soak command and what it does and does not assert.

  It found one thing on the second seed it ran under, left standing as `FOLLOWUPS.md` item 55: a
  handle that a raw `execute` has **retired** cannot release its own session, while the `execute`
  that retires it appends "`end_session` releases it" — and the recovery its refusal names, omitting
  the handle, routes to the *newest* session instead. Measured on the release build with two
  launches, the older retired by `qd`.

### Documentation

- **`FOLLOWUPS.md` holds only what is still open; what has landed moved to `DONE.md`.** Thirty-three
  of its fifty-five entries were finished work, so two thirds of a file read for "what is left" was
  answering a different question. The entries move **in full and under the numbers they were filed
  with** — `CLAUDE.md`, `CHANGELOG.md`, `docs/*.md`, `ci.yml` and `build.rs` all cite them as
  "`FOLLOWUPS.md` item N", and those are prose references that renumbering would break without
  failing anything — so `FOLLOWUPS.md`'s numbering is now sparse and its header is what answers
  *which file*, above every entry. Neither file is in the markdownlint globs, so neither is checked
  by CI.

  **Citations are deliberately not retargeted**, and `every_followups_citation_names_an_item_that_exists`
  is what makes that safe: it reads every text file in the repository and fails if a cited number is
  in neither file, if a number is in both, or if `DONE.md`'s index has fallen out of step with its
  entries. Some twenty files carry that string — doc comments in eleven modules and in `tests/`,
  `DECISIONS.md`, every `docs/*.md`, `build.rs`, `ci.yml` and the eval tooling — so a citation whose
  file half followed the entry would make every close a sweep of source comments, unchecked, and one
  that had to be repeated on the next close. The number is the name; which file holds it is the
  landing page's answer. Proved by breaking it three ways: an entry renumbered, an index line
  dropped, and an anchor corrupted.

  Two shapes deliberately stayed: an item **measured and declined** (27, 35), where nothing was
  built and the reopening condition is the content, and one that **half** landed (50), whose entry
  narrows to the half that is left rather than splitting across two files.

- **`DECISIONS.md`'s bounded-command entry (2026-08-02) is superseded by its own revisit trigger**,
  and says so above the criterion rather than only in its Status line. The criterion stays as the
  record of what the tax bought while it stood; `FOLLOWUPS.md` item 14 moves to `DONE.md`. Two
  boundaries the entry now states explicitly, because both have been mistaken for the split before:
  the typed ops carry no `patience_ms` because there is no *command* for a watchdog to break, and
  `reachable_from_dispatch` is a job-level deadline and still item 13.

## [0.14.0] - 2026-08-30

### Added

- **`modules { "refresh": true }` resynchronises the debugger's module inventory before it lists
  it** ([#85](https://github.com/glslang/windbg-mcp/issues/85)). DbgEng's inventory is the
  *debugger's*, not the target's: it is built from the module-load events the debugger saw, so it
  is complete for a dump and for a process the debugger launched, and it is not complete for a
  live kernel — an attach starts from what it can read at connect time, and a driver loaded before
  the debugger dialled in is in the target and missing from the list. On the MessageManager
  regression target that meant `nt` and little else, and a `modules` call straight after the attach
  read as "the challenge driver is not loaded" while the driver was open and serving IOCTLs.
  Measured on that target on 2026-08-30, across one attach: the engine held **1** module, a
  `modules { "filter": "MessageManager" }` matched **0**, and the same call with `refresh: true`
  reported `before: 1` against **158** loaded and matched the driver at `0xfffff80343970000` —
  `deferred`, so it was found without a byte of PDB being fetched.

  The resynchronisation was always available — it is what an unqualified `.reload /f` was doing as
  a side effect of fetching every module's PDB — and nothing said so, so finding a loaded image
  meant guessing that a force symbol reload was the missing step. This is that half on its own, and
  the tool says which half it is: it discovers modules and **fetches no symbols**, so what it finds
  comes back `deferred` with no symbol-server round trip.

  The result carries `refresh` — `synchronized`, the `before` count against `loaded` after it, and
  the engine's own `error` where it failed. Three things worth knowing. **Absent means it was not
  asked for**, which is not the same as one that found nothing, so a default call is unchanged in
  both channels and still cheap. **A failure is reported, not raised**: the listing beside it may
  well be the right one, so the answer stands and the text says so *above* the tables — a caveat
  printed under a listing arrives after the conclusion it was there to prevent — and withdraws the
  only inference the listing supports, that a module absent from it is absent from the target. And
  **on a live target it costs the symbol state**: a reload discards what the engine had loaded
  and reloads it as needed, so most modules come back `deferred` — measured on a launched
  `cmd.exe` either side of a `.reload /f`, where four of its five modules went `pdb` → `deferred`
  and `ntdll` kept its PDB. A **dump** pays none of it: its module list comes from its own header,
  so there is nothing to re-read, and `nt`'s PDB survives a refresh with the other 226 modules
  `deferred` either way. So refresh first and load symbols afterwards on anything live —
  [`docs/structured-results.md`](docs/structured-results.md) has the two reloads side by side and
  both measurements.

- **Asynchronous execution control: `continue_async`, `wait_for_stop` and `break_in`**
  ([#83](https://github.com/glslang/windbg-mcp/issues/83)). `go` waits for the next stop and answers
  with it, which leaves no room for the sequence a live target usually needs — arm a breakpoint,
  resume, *make the thing happen that trips it*, then collect the stop. `continue_async` resumes and
  returns at once with an execution handle; `wait_for_stop` collects the stop whenever it comes; and
  `break_in` ends a run that is not going to reach anything. A guest-side `Sleep` was the only way to
  express the middle step before, and it is not a sound one: a kernel halted in the debugger has a
  halted clock.

  The wait that goes away is the **caller's**, not the debugger's. DbgEng moves a target only from
  inside `WaitForEvent`, so the engine thread stays in the pump for the whole run — what changed is
  that the worker reports the target moving as a milestone, and the reply that follows is the stop,
  filed against the handle by a task that does not care whether the caller is still there. So there
  is no hidden wait anywhere: the run is recorded on the session before the job is queued,
  `session_status` reports it, and `max_run_ms` says when the debugger will end it itself.

  Consequences worth reading before using it. **One run per session**, because a second could not
  start until the first ended. **While the target is moving, every tool that reads it is refused**,
  with a new `target_running` category and the handle to wait on — refused rather than queued, since
  a queued `registers` would be answered whenever the target next stopped and would describe
  wherever it happened to be. **A wait that runs out is a poll**: no stop, nothing cancelled, the
  handle still good. **A stop is read rather than taken**, so a client that disconnected mid-run can
  reconnect and read it. **A break is bound to the run it was asked about**, so one aimed at a run
  that has since stopped is refused rather than landing on whatever the engine started next — and
  one aimed at a run that has not *started*, because something else is still on the engine, bars it
  from ever setting the target going. `requested` then answers the wide question — *is this run
  going to stop* — so a break raised, one already lodged and a barred run are all `true`, as is one
  whose run finished on its way to the engine. `false` means the run had already stopped **when the
  call looked**, which is the ordinary race; a break that could not be *delivered* is an error
  rather than a `false`. **A run's clock starts when the target
  moves**, not when it was asked for, so one waiting its turn reports no elapsed time and its whole
  bound rather than a bound already counted down. And `end_session` reaches the target whether the run is pumping or still
  queued — it breaks the pump in as it arrives, and bars a resume that has not started — rather than
  queueing behind a run that has no reason to end, which is the same path a client disconnect takes.
  [`docs/sessions.md`](docs/sessions.md#running-a-target-asynchronously) has the whole of it.
- **A stop says which thread, and which processor.** `StopReport` — what `go`, the stepping tools
  and `wait_for_stop` all answer with — now carries `thread` (the operating-system thread id the
  position belongs to) and `processor` (which of a kernel target's processors it is on, absent where
  no processor number applies, which every user-mode target is). A position on its own does not
  identify a stop on a multi-threaded target, and the alternative was parsing `~.`, whose text is
  one shape for a thread and another for a processor. Both come from new typed `dbgscope` readers.
- **`pool_find_tag` can answer existence and bounded-cardinality questions without walking the
  entire kernel pool** ([#86](https://github.com/glslang/windbg-mcp/issues/86)). Pass the nonzero
  `stop_after_matches` threshold to stop a newly started walk as soon as that many matching
  allocated chunks are decoded. The result reports `walk.coverage: "match_limit_reached"` and
  echoes the threshold in `walk.stop_after_matches`; its counts and byte total are explicitly
  floors. These deliberately partial snapshots are never cached as exhaustive. A complete cached
  snapshot is still reused and stays complete, while `limit` remains the independent rendering
  cap. The `debug_batch` `pool_find_tag` step accepts the same field.

- **The per-call result budget is charged against every channel a result carries, not only the
  half this client forwards** ([#150](https://github.com/glslang/windbg-mcp/issues/150)).
  `tool_results_stay_within_their_budget` now asserts a tool's model ceiling against
  `content[].text` and against `structuredContent` separately, so a typed tool is checked twice
  and the failure names which channel moved; the `wire` ceiling that landed with #149 still covers
  the result taken together. The printed table gains a `worst` column — the larger of the two
  halves — beside the ceiling it is compared against.

  This closes the half of #150 that was deferred for want of a second client to measure. The
  deferral had the wrong shape: a second client would say what one more implementation happens to
  do, which is a sample and not a rule, and inferring a server's budget from a client's forwarding
  policy is the same step that left the rendering unwatched in the first place. The text-forwarding
  client was also already in this repo's own compatibility matrix — `structuredContent` arrived
  with `2025-06-18`, this server serves `2025-03-26` and `2024-11-05` beneath it, and the channel
  is not gated on the negotiated revision, so for those two the rendering is not the half a client
  happens to forward but the only half it can read.

  No ceiling moved. `session_status` is the one budgeted typed tool whose rendering is larger than
  its typed answer (423 B against 301 B, identical on both CI runners), so it is the only row now
  measured against a number the old assertion never saw; elsewhere the typed half is the larger one
  and the new check restates the old. Which is what a floor under a channel nothing has yet grown
  looks like.

### Fixed

- **Documentation: `!analyze`'s module attribution is a fact about the debugging host, not about
  the dump.** Four documents and a smoke-test fixture said the two checked-in driver crashes
  disagree about it — that `MessageManager` has no PDB so `!analyze` reports `Unknown_Module`,
  while `HEVD` ships one so `!analyze` blames it by name. Measured on one engine against both
  dumps, they behave identically, and what decides it is whether `triage\triage.ini` is beside the
  engine (`skills/windbg-debugging/setup.md` copies it as a step of its own): with it, each crash
  is attributed to its driver; without it, both report `Unknown_Module`; with no `winext\` either,
  `!analyze` does not run at all. A missing PDB costs the *function* — both failure buckets end
  `!unknown_function` whichever way that falls.

  The same correction reaches the `0x9F` walkthrough, where it changes the reading rather than just
  the wording: with `triage\` bundled that dump is attributed to `pci` —
  `0x9F_3_ACPI_IMAGE_pci.sys` — which is the **bus driver** the walkthrough's own device-stack walk
  identifies as *not* the culprit. So the manual walk is required either way, and what a bundled
  engine changes is whether `!analyze` declines to answer or answers with the wrong layer.

  `a_driver_crash_names_the_driver_frame_an_all_kernel_walk_would_miss` now asks the host
  (`triage\triage.ini` beside the server) instead of carrying a per-fixture flag, and asserts on
  both sides of that rather than skipping either. It had never run: `ci.yml` copies no extension
  directory, so `analysis.ran` is false on both runners and every `!analyze` assertion in that tier
  is skipped there.

- **A transcript no longer records an interrupt that reached nothing as one that was delivered.**
  `WINDBG_MCP_TRANSCRIPT`'s `interrupt` event took `delivered` from whether the request succeeded,
  and four of the five things an interrupt can do succeed while raising nothing — there was no
  operation running, a `debug_batch` was sealed for its rollback, or a break was already pending.
  The worker now says which it was, so the transcript records a cause that happened. This matters
  because that event exists precisely to explain a *later* truncated result; one logged against a
  break that was never raised attributes a short answer to a request that did nothing.
- **`record_trace` finds the recorder the engine copy already delivered.** `setup.md`'s one-time
  engine bundle takes the whole `ttd\` directory, and that directory carries `TTD.exe` as well as
  the replay DLLs — but `find_ttd` probed `PATH`, the SDK layout and `WindowsApps` and never its
  own directory, so the one layout this project's own documentation tells people to create was the
  one it did not know. A host bundled exactly as documented could replay a trace and not record
  one, unless the recorder was *also* put on `PATH`. It now probes the bundle beside the
  executable, ranked below `PATH` so that override still wins
  ([#131](https://github.com/glslang/windbg-mcp/issues/131)) and above the machine-wide installs,
  since the payload next to the binary is the pair to the engine the loader actually gives this
  process.
- **A symbol path can now seed later sessions without coupling running workers
  ([#66](https://github.com/glslang/windbg-mcp/issues/66)).** `set_symbol_path` accepts
  `for_new_sessions`: `true` remembers the successful `path`/`append` setting for this client's
  future opens, `false` clears it, and omission keeps the existing session-only behavior. The
  supervisor applies that starting state on the new worker's engine thread before its opener; it
  never broadcasts a reload or path mutation to sessions already running, and listener clients
  cannot inherit one another's host paths.
- **`end_session` stops accepting work when its teardown reaches the front of the session queue
  ([#64](https://github.com/glslang/windbg-mcp/issues/64)).** The pump now marks the session closed
  immediately before forwarding `EndSession`: calls already ahead of it still run, while calls
  submitted behind it are refused as `stale_session` instead of reaching a target that has been
  released or creating a replacement target in a worker that is about to exit. Once teardown
  finishes, the provisional closed reason is refined with whether the target was released, the
  worker was parked, or it was already gone.

### Documentation

- **The WinDbg engine payload has three sources, not one, and the two that need no interactive
  install are now first-class** (issue
  [#132](https://github.com/glslang/windbg-mcp/issues/132)). TTD `.run` replay needs a `ttd\`
  directory beside `windbg-mcp.exe`; System32's `dbgeng.dll` ships none of it, the SDK Debugging
  Tools do not either, and MSIX registration fails from a non-interactive session
  (`Add-AppxPackage` → `0x80070005`, even elevated) — so a host reached over SSH could record
  traces and not replay them. `setup.md` had carried the way through since #133, as an appendix
  headed *when the store package will not install*; it is now source (b) of three named up front,
  because the store package's `InstallLocation\<arch>` and the unpacked `.msixbundle`'s `<arch>\`
  are the **same layout** — so the three sources differ only in how they set `$wd` and the copy
  after them is one block rather than two. What decided it was that this repository's own TTD smoke
  tier already runs against an engine bundled that way, so the route the documentation held at
  arm's length was the one its coverage stood on.
- **That recipe did not work, and had not since the day it was written** (`8bd98a5`, 2026-08-16).
  Its first line read the `.appinstaller` with `(Invoke-WebRequest …).Content` and cast it to
  `[xml]`; under Windows PowerShell 5.1 that property is a `Byte[]` for this content type, so the
  cast threw and nothing was downloaded at all. It now fetches to a file and reads it back with
  `Get-Content -Raw`, which is version-proof. Found by running it end to end for the first time, on
  the ARM64 host the issue was filed from — which also measured what the endorsement rests on: the
  bundle verifies as `Valid` / `Authenticode` / `CN=Microsoft Corporation`, is 1,188,564,441 bytes,
  and **all three** payload trees inside it (`amd64\`, `arm64\`, `x86\`) hold the entire copy
  list, `msdia140.dll` included — plus `ttd\TTD.exe`, so the engine copy already brings the
  *recorder* and not just the replay engine, which `setup.md` and `docs/install.md` now say. The
  recipe gains a publisher check before it unpacks anything, `setup.md` states what that settles
  (provenance) and what it does not (that an unregistered payload is a supported Microsoft
  configuration), and the update advice now says to clear the four wholesale-copied directories
  first — `Expand-Archive -Force` and `Copy-Item -Force` overwrite collisions and delete nothing,
  so re-running merges a new payload into the old one rather than replacing it. That bench was then bundled from the payload and **replays**: a 40 MB trace
  recorded with the bundled `ttd\TTD.exe`, opened by `open_trace` reporting its lifetime rather
  than the missing-`ttd\` diagnostic, and stepped backward with `step_back`. The issue is closed
  on the host it was filed from, and `FOLLOWUPS.md` item 47's blocker — TTD replay being
  unavailable on that bench — goes with it.

## [0.13.2] - 2026-08-28

### Documentation

- **Driving this server with ollama was supported in fact and written down nowhere a reader would
  look.** `skills/windbg-debugging/setup.md` explained at length how to put the server on another
  machine and never said what could drive it from there; its only mention of a local model was a
  half-sentence about `--tools` inside the service bullet, and it linked to none of the three
  documents that carry the subject. It now ends with *What drives the server — there is a choice*:
  the three arrangements, and the four things that decide whether the ollama route works — a
  credential of its own, the `tools` capability being necessary and not sufficient, the lease a
  quiet client loses its sessions to, and the surface being the fixed cost where a single
  `read_memory` is the variable one. The depth stays in `docs/local-model.md` rather than being
  copied, so there is one place for each rule to be wrong.
- **The benchmark's driver was being offered as the way to use a local model, and it is not.**
  `tools/local_model_drive.py` ships in no release — the zip is `windbg-mcp.exe`, the `x86\` worker
  and `LICENSE` — wants a checkout and Python 3, has no interactive mode, and exists to measure a
  model rather than to debug with one. Driving this server with an ollama model is the **client's**
  job: an MCP client that drives one holds the listener exactly as an editor does, ollama ships
  integrations for several of them, and nothing from this repository is involved. `README.md`, the
  skill and `docs/local-model.md` now say so, and name
  [`agent-sandbox-vm`](https://github.com/glslang/agent-sandbox-vm) as the environment the grid is
  actually run in.
- **`README.md` presented driving this with a local model as a benchmark result rather than as
  something a reader can do.** Its single section on the subject was the eval — the grid, the
  axes, the findings — so someone asking whether a local model is supported at all, how the
  listener is configured, or whether a Mac can drive a Windows host over ssh found none of it, and
  the answer to all three is yes. That section is now two. *Driving it* leads with a table of the
  five configurations — an MCP client or ollama, local weights or ollama's cloud, one machine or
  two — then the commands that install **and start** the listener as a service, the ssh forward,
  why the token is not optional, and the one line that points ollama at it. The benchmark follows
  as its own section, backing those claims instead of standing in for them. The service install is
  stated with the prerequisite that makes it work: `--install-service` **refuses** an exe outside
  `%ProgramFiles%`, `%ProgramFiles(x86)%` or `%SystemRoot%`, which a downloaded zip, a Scoop shim
  and a `target\release` build all are, so the whole deployment moves first — engine DLLs and
  `x86\` included — and `--allow-unprotected-path` is named as the development install it is. The
  skill and `docs/mcp-clients.md` both said "elevated" as though elevation were the only
  requirement, and now do not. Its context-window
  finding now carries the qualifier it always needed: it is a fact about that bench's runtime, and
  `ollama ps` is how a reader learns what theirs serves.
- **The tool-surface figures were stale in eight files and disagreed with each other in two.**
  Every current claim now comes from one re-derivation, none of which needs the eval run: the whole
  surface is `tests/golden/tool_budget.json`'s `modelVisible` total, which `cargo test` re-records
  (**68,322** — not the 67,766 five documents carried, and not the 67,873 in `README.md` and
  `CLAUDE.md`); each group's share is that golden summed over `src/toolset.rs`'s membership, which
  reconciles to the total across all 51 tools; and what a `--tools` spec actually *serves* is the
  same sum over a `tools/list` from a listener started with it. So `session,inspect,crash` is
  24,894 rather than 24,445, `crash` 14,587 rather than 14,138, the `session` floor 11,714 rather
  than 11,265, `debug_batch` 9,798 rather than 9,746, and the gap item 41 opened between a group's
  share and what a spec serves is 15,542 against 14,587. `docs/local-model.md` also says how to
  re-derive its own table, because this is the second time these numbers have gone quietly stale.
  The developer-facing copies moved with them — `src/toolset.rs`'s module table and floor,
  `tests/mcp_smoke.rs`'s note on why `--tools` exists, and `CLAUDE.md` — since a figure in a doc
  comment is a current claim like any other.
  The **historical** figures are deliberately untouched: `token-budget.md`'s `67,076 → 67,766`
  before-and-after column, `local-model-eval.md`'s statement of the conditions its grid ran under,
  and this file's earlier entries each record a measured moment and would be falsified by a refresh.
- **That page described one arrangement as though it were the only one — the bench's.** Where the
  weights run and where the listener runs are independent choices, and `docs/local-model.md` opened
  on *the three pieces* with the ssh forward baked in as piece 2, because the bench that produced
  its numbers had the model on a Mac and the engine on a Windows VM. It now opens on the four
  arrangements those two choices make, says that only the listener is pinned and why, labels which
  row each measurement came from, and says outright that on a single machine piece 2 is not a step.
  The driver is also described for what it is — a batch task runner with six tool-calling turns a
  task, no interactive mode, and four environment variables that exist only so the grid can be
  graded — so that a reader stops looking for the conversation it does not have.
- **`docs/local-model.md` is about ollama, not about local weights.** A cloud tag and a local one
  are the same route — the same endpoint, the same script, a different model name — so the page
  says so from its title down, and `ollama launch` is now explicitly not needed rather than merely
  "not a prerequisite". Three facts measured on 2026-08-28 are new, and a local bench could not
  have produced any of them. A pulled cloud tag is a registered *name*: `glm-5.3:cloud` declared
  `capabilities: ['completion', 'thinking', 'tools']`, passed the driver's model gate, and answered
  the first real call with *"currently being rolled out and is not yet available to you"* — so the
  gate is necessary and not sufficient, and one token is the probe. `/api/ps` is empty for a cloud
  model even straight after a successful run, so `served_context` and `model_digest` are recorded
  null and the served-window rule has no instrument at all — the position `claude_code_drive.py`'s
  rows are already in. And the keepalive stays on despite turns of 4 to 10 seconds, because what
  the lease measures is silence, and a queued request is silent the same way a thinking one is.

## [0.13.1] - 2026-08-28

### Documentation

- **The 32-bit .NET worker shipped with a setup page nothing routed to.**
  `skills/windbg-debugging/setup.md` gained its *32-bit .NET targets need a 32-bit server* section
  with the feature in 0.13.0 and is complete — both measured failure codes, the `x86\` copy block,
  the build line, the three ways to get the layout wrong. Nothing that would send a reader there
  moved with it, which is why this is a release and not a merge: the skill reaches an installed
  plugin only when `.claude-plugin/plugin.json`'s version changes, so until this bump the routing
  fix existed on GitHub and on nobody's machine. `skills/windbg-debugging/SKILL.md` said nothing at
  all — a model holding a 32-bit dump had no reason to open `setup.md` from the routing table, and
  nothing told it that a host with no 32-bit worker answers with a summary `limitation` rather than
  an error, so the one signal the fallback exists to send read as a broken SOS. `docs/install.md`'s
  *Wanted / Needs* table — the index of what fails quietly without which files, which is this
  failure's exact shape — had no row for it. `docs/limitations.md` recorded neither the fallback nor
  what such a session gives up. And `README.md` did not mention the second worker image at all; it
  does now, under *How it works*, where the process-per-session model this follows from is stated.
  Two facts that had been stated loosely are also separated wherever they appear: the `heap_*` tools
  refuse on the **target's** processor type, so they are gone whichever worker owns the session,
  while losing the WoW64 process's 64-bit half is the 32-bit worker's **own** trade and does not
  apply to the x64 fallback.

## [0.13.0] - 2026-08-28

### Added

- **The binary carries a PE version resource** — `FileVersion`, `ProductVersion`, `CompanyName`,
  `ProductName`, `FileDescription`, `LegalCopyright`, `OriginalFilename`, `InternalName` and
  `Comments`, where a Rust binary carries none of them by default. Explorer's properties dialog is
  the visible half; the reason is the other one. Windows Defender quarantined a freshly built
  `windbg-mcp.exe` as `Trojan:Win32/Bearfoos.B!ml`, and an absent version resource is one of the two
  causes Microsoft names for that same detection on its own shipped binaries — an `!ml` verdict is a
  machine-learning score rather than a signature match, so a binary with no metadata is scored on
  what little there is. `ProductVersion` carries the git-stamped identity (`0.12.1+g1a2b3c4`) while
  `FileVersion` stays the bare release, so the dialog answers the same question `serverInfo.version`
  does. This does not make the binary signed, and signing is what the reputation systems above
  Defender actually read: [`FOLLOWUPS.md`](./FOLLOWUPS.md) item 50 is what remains.
- **A 32-bit .NET target is opened by an engine that can load its SOS** (issue #234) — a 32-bit
  dump, and a 32-bit (WoW64) process reached with `attach_process`. An extension DLL is loaded into
  the debugger's own process, so its architecture is the *host's*: the 32-bit `sos.dll` will not
  load into this server's x64 engine (`Win32 error 0n193`) and the 64-bit one loads and then fails
  on the target (`Failed to load data access DLL, 0x80004005`), because the CLR data access DLL is
  paired to the target's architecture as well as the host's. Both measured — there is no in-process
  arrangement, and a process's architecture is fixed when its image loads — so the *process* moves.
  The release now ships a 32-bit build of this same server at `x86\windbg-mcp.exe`, and a 32-bit
  user-mode target is opened by that worker rather than by a re-execution of the 64-bit one;
  `!sos.threads`, `!clrstack` and the rest answer. None of it is visible to a client — one server,
  one handle, one tool surface, one session registry — because a worker has never spoken MCP: it
  talks to the supervisor over the same pair of inherited anonymous pipes every other session uses.
  The architecture is settled before anything opens the target, which is what makes the choice
  possible at all — asking the engine would need a session in a process whose architecture is by
  then already fixed — and the two kinds answer differently: a dump carries it in its own header,
  and a live process answers `IsWow64Process2`. `skills/windbg-debugging/setup.md` has the one-time
  copy block for the 32-bit engine payload that worker loads.
- **An opener's summary carries a `limitation`** when the session cannot do something a caller would
  otherwise assume it can. Today that is the case above on a host with no 32-bit worker available:
  rather than failing the open — native analysis of such a target works and always has — it opens
  here and the result says SOS is unreachable and what to copy. Present on both the text and
  the structured halves, so a client that forwards `structuredContent` and drops the text still
  sees it.
- **The smoke test builds its own 32-bit target** rather than waiting to be handed one, so the tier
  covering the above runs unattended and in CI. It compiles a small 32-bit C# program with the
  `csc.exe` every stock Windows ships; one test opens the full-memory dump that program writes of
  itself, and the other attaches to it running. `WINDBG_MCP_X86_DUMP` still overrides the made dump
  with a real capture. The tier stands down where there is no 32-bit engine to run it against.
- **The 32-bit worker's PE version resource is asserted too.** The existing check reads the binary
  built for the host, so `x86\windbg-mcp.exe` — shipped in both the `.zip` and the `.mcpb` — carried
  its resource unchecked on every host and in CI. `build.rs` will not fail a build whose resource it
  could not embed, so a worker that quietly lost one would ship with nothing saying so, and an
  absent version resource is one of the two causes Microsoft names for the `Bearfoos.B!ml` verdict
  that motivated the resource in the first place. Its fields are asserted equal to this build's
  rather than pinned again, because the two binaries are one product from one build.

### Fixed

- **Ending a session no longer kills a process this server only attached to**
  ([`FOLLOWUPS.md`](./FOLLOWUPS.md) item 51). `attach_process` on a running process and then
  `end_session`, and the process was *gone* — not suspended, not detached, terminated. Two defaults
  meeting: the engine ended every non-kernel session passively, which destroys the debug port rather
  than detaching, and a debuggee whose port is destroyed is killed by the kernel, because
  `DebugSetProcessKillOnExit` defaults to true. That is the honest end for a `launch`, which created
  the process, and it still is; it was never right for an attach, and it was worse here than in a
  plain debugger, because the same release runs when a client **disconnects** or its lease expires —
  so a client that simply went away took the service it was looking at with it. A session whose
  target this server attached to is now actively detached and left running, and `end_session`'s
  result says which of the two endings it was. The engine-side half is
  [glslang/dbgscope#121](https://github.com/glslang/dbgscope/pull/121); `end_session`,
  `attach_process` and `launch` now each say in their own description what ending a session will do
  to that kind of target, which is what none of them said before. `end_session`'s structured result
  carries `target_left_running` beside the sentence, because a client that forwards
  `structuredContent` drops the text and this is the one fact about a teardown that cannot be
  recovered afterwards.

## [0.12.1] - 2026-08-26

### Fixed

- **A target that ends during a resume is an ending, not a catastrophe** (issue #242, and
  [`FOLLOWUPS.md`](./FOLLOWUPS.md) item 48, which had held the question open since #226). A `go`, a
  step or a raw `execute 'g'` whose debuggee ran to completion came back
  `Debug command failed: Catastrophic failure (0x8000FFFF)` — the raw `E_UNEXPECTED` DbgEng answers
  once the wait ends with no debuggee left — reported unchanged for a program exiting normally, and
  the output the run had captured was discarded with it. That output is the only copy there will be:
  the command prints its own echo, while the module loads, the breakpoint banner and anything an
  embedded `bp X "…; g"` script printed all arrive during the wait. The ending is now an outcome
  carrying its text, on both halves of the result — `target_gone` on the stop report, a sentence
  beside it, and `run_to_address` gaining a `target_gone` verdict that is deliberately not a
  timeout, since the address was never ruled out.

  The session then said so, where before it half-answered: `.echo` and `.lastevent` kept working
  while `k`, `r` and `registers` failed `0x80040205`, which from a caller's side is
  indistinguishable from #226's wedged session and needs the opposite response. Every tool now
  answers one refusal naming `end_session`, categorised `stale_session` rather than `debugger`
  because no change to what is asked will help. `.detach`, `q` and `qd` take the target away
  themselves and are reported the same way — read from the engine rather than from the command's
  name, since `.kill` is measured *not* to be in that group: it leaves a target that still reads a
  stack and goes away on the next resume.

  A `debug_batch` stops there rather than running on: a resume that ends the target **succeeds**,
  so nothing about the step's result would otherwise halt the batch, and one whose last step ended
  the target would have reported `committed` with its mutations no longer standing in anything and
  its `always` block unable to execute. The outcome is `target_gone` naming the step, the steps
  after it are not attempted, the `always` block is still attempted (the fail-safe direction: a
  misread ending must not drop cleanup that could have run), and `after` is `ended` rather than
  `detached` — a detached process is still running somewhere, and on a live kernel that is the
  difference between a machine that is up and one that is not. A step's `eval` assertions are not
  checked against an engine that has no target either: they are engine calls, and a refused
  `? (...)` used to read back as a *failed assertion* on a step whose action did exactly what it
  was asked.

  The ending reaches the two channels beside the result as well: `run_to_address`'s tool
  description now names the fourth verdict (an output schema never reaches the model, so a
  description that enumerates three when there are four is the only place a model could learn
  otherwise), and a session transcript's `stop` event carries `target_gone` — without it an ending
  is a locationless stop with both other flags false, which is what an ordinary stop looks like,
  followed by every later call being refused with nothing joining the two.

- **Execution control with no debuggee no longer takes the worker down**, which is the same defect's
  other half and was a `STATUS_ACCESS_VIOLATION` inside DbgEng — a structured exception, so no
  `catch_unwind` traps it. `execute 'g'` on a session whose target had exited hit it; so does a raw
  `g` on an engine that never had a target, which is what says the trigger is the missing debuggee
  rather than the departure. dbgscope now refuses every road into `Execute` when the engine holds
  none. It cannot be narrowed to text that looks like execution control — an alias, a `.if` branch
  and `dx …ExecuteCommand("g")` all reach it — so the few engine-level commands that do work without
  a target (`version`, `.echo`, `.sympath`) are refused too.

- **`ttd_calls` and `ttd_memory` return the fields their descriptions promise** (issue #231). Both
  ran `dx` without a recursion depth, and `dx` renders one level unless told otherwise:
  `TTD.Calls` and `TTD.Memory` return *containers of records*, so `-r1` was exactly one level short
  and every result came back as a bare index. The count was right and the payload absent, which
  reads as "three calls, details unavailable" rather than as a defect — and there was no error to
  go on. Not a regression: all three query commands are in the initial commit and only `ttd_events`
  ever carried `-r2`, so two of the three TTD query tools had never returned usable output.
  Measured after the fix against a trace recorded on this host: `ttd_calls` carries `TimeStart`,
  `TimeEnd`, `Function`, `FunctionAddress`, `ReturnAddress`, `ReturnValue` and `Parameters`, and
  `ttd_memory` carries `AccessType`, `IP`, `Address`, `Size` and `Value`. The depth is now one
  constant the three share rather than three literals, and a test asserts that every TTD query asks
  for it — what went wrong was one of them being written differently from its siblings, which no
  test could see while each built its own command line.

- **`record_trace` passes arguments to the target, which its schema always said it could**
  (issue #232). `target` is documented as "Program (with optional arguments)", and the whole string
  went to `TTD.exe` as a **single** argv entry — so the recorder looked for a file named
  `cmd.exe /c dir C:\Windows\System32\ntdll.dll` and answered `0x80004005` with "cannot find the
  file specified", a message pointing at the program rather than at the quoting. TTD's own help
  requires the opposite ("`-launch` … must be the last option in the command-line, followed by the
  program + `<arguments>`"), and `-launch` was already last, so the only thing wrong was that the
  tail was one token instead of several. It is now split by `CommandLineToArgvW`'s rules — the ones
  that will parse the line at the other end — so a quoted path holding spaces stays one argument
  and a backslash run before a quote halves the way Windows says it does. An **unquoted** path that
  exists exactly as written is still one program: that is what handing the whole string over got
  right, `C:\Program Files\…` is where programs live, and splitting it on whitespace would have
  taken the case away from callers relying on it without an error to show for it. That check asks
  the directory the *recorder* will run in — `working_dir` when the caller set one, since the
  recorder resolves a relative program against its own cwd and this process's is a different
  directory. Asking the wrong one is not a refusal: measured on `TTD.exe` 1.01.11, a target of
  `.\a program.exe` under a `working_dir` holding that file split into `.\a` and `program.exe` and
  recorded **`a.exe`** — a different program — into a 29 MB trace reported as a complete recording.
  An empty `target` is refused before the output directory and log are created, beside the existing
  `env` validation.
  Measured: `record_trace { "target": "cmd.exe /c dir C:\\Windows\\System32\\ntdll.dll" }` records
  and the recorder's own echo is now `Launching 'cmd.exe /c dir …'` rather than the quoted single
  token it used to be.

- **`record_trace` reports a recording that already finished as a success, naming the trace**
  (issue #233). The recorder is watched for 2.5s for a fast failure — the un-elevated refusal is
  what that was built to surface — and **any** exit inside the window was treated as one. A target
  that runs to completion faster than that exits inside it, so `hostname.exe` produced a 46 MB
  trace that opened and replayed correctly and was reported as `TTD recording failed to start
  (exit code: 0)`, with the quoted reason being TTD's `Launching '<target>'` banner: a line that
  says nothing was wrong. An early exit means the recorder is no longer running, not why, and "the
  target already finished" is an ordinary reason. The decision is now on the recorder's exit
  *status* and on what it left behind: a successful exit with a finished `.run` is a **complete
  recording**, and the message says so and names the trace — which is the more useful of the two
  success answers, since only one of them has a file ready to open. A successful exit with no trace
  is still an error, and a distinct one. A non-zero exit takes the path it always did, except that
  the reason is now read past the launch banner to the line that reports the failure. The trace is
  identified from the log's own `Full trace dumped to <path>`, falling back to a `.run` in
  `out_dir` written since the recorder was spawned — restricted that way so a trace an earlier
  recording left in the same directory cannot be reported as this one's.

## [0.12.0] - 2026-08-25

### Changed

- **The engine bindings are now `dbgscope`, and `win-kexp` keeps only what its name meant.**
  The dependency had two halves with exactly one reference between them: the debugger side
  (`dbgeng` plus the pool and heap walkers built on it), which is everything this server consumes
  and 117 of the dependency's last 135 commits, and an exploitation side (shellcode, ROP, process
  injection, win32k wrappers) with zero commits in three months. The debugger half keeps the
  repository and its history under the new name; the dormant half was extracted with `git
  filter-repo` and keeps the `win-kexp` name, which now describes all of it. Nothing this server
  used has moved or changed shape — the update is `use win_kexp::` becoming `use dbgscope::` — but
  the crate can now carry a version rather than a git revision, and it sheds `goblin`,
  `byte-strings`, its build script and nine `windows` features on the way. The WinDbg extension
  command it exposes is renamed with it: `!win_kexp.poolmap` is `!dbgscope.poolmap`, since that
  name comes from the cdylib's filename. Both crates are also **relicensed from GPL-3.0 to MIT**,
  which removes a conflict that predates the split and was never deliberate: a GPL library
  linked into this MIT-distributed binary made the combined work GPL. Entries above this one
  name `win-kexp` because that is what the crate was called when they were written.

- **The server reports the git revision it was built from**, as semver build metadata on the
  version it already reported: `0.11.0+g1a2b3c4`, and `-dirty.<digest>` where the build inputs
  differ from that commit — the digest, over the working-tree diff, so that two uncommitted
  iterations on one `HEAD` are not one identity. It reaches both places that carried the crate version alone and are the two a reader
  reaches for when asking *which* build did something — MCP `serverInfo.version`, and a
  transcript's `start` record. A crate version moves only on release, so every build between two of
  them was indistinguishable, including the pairs that matter most: the behaviour a bug report or a
  bench turns on is often a changed *result* rather than a changed API. Absent git, the reported
  version is the bare crate version, and nothing that compares versions is affected — build
  metadata is ignored for precedence.

- **The eval records what a run ran against, so two runs can be compared** (`FOLLOWUPS.md` item 46,
  which closes it). A record identified the question and the surface and neither of the two things
  that change over time: which model weights answered — `qwen3.8:27b-mlx` is a mutable tag that can
  be re-pulled onto different ones — and which server build was asked. Both facts were already on
  the wire and both were thrown away, so every record now carries `server`, `model_digest`, `suite`
  and, for the Claude rows that can have no digest, `harness_version`. A surface is fingerprinted
  by a **digest** of what went over the wire rather than by its byte length, and a field that is
  deliberately null (`unavailable`) is kept apart from one nobody recorded (`unrecorded`). `--compare` reads two logs
  with two rules that are not one rule: a **changed question blocks** a pairing, and a changed
  build, model or window is **named above the table**. `--series` reduces logs to one row per run
  in `docs/eval-runs.json`. The three runs already recorded read `unrecorded` throughout, which is
  the part of this that expires: a run recorded without identity cannot have it added later.

- **The eval's answer key is re-read off the dumps rather than trusted** (`FOLLOWUPS.md` item 45,
  which closes it). Its six tasks are graded against facts read off the checked-in samples with
  this server's own tools, and nothing re-checked them — so a fact that stopped being what the
  server reports would leave the suite grading, every model scoring, and a rotted key looking
  exactly like a model that got worse. Each task now carries a **`verify` binding** of
  `(tool, arguments)` steps to the values expected back, and
  `local_model_eval.py --verify-key` drives the server and checks the lot through the same
  `present()` that grades. It catches a moved fact, a renamed field, a prompt repointed at another
  sample, an `expect` group nothing fetches, an `expect` group edited to something the server does
  not say, an `expect` group widened to also accept something else, a relation whose supporting
  pin was deleted, a gated step ordered before its opener, and a stale text pin — all nine
  verified against deliberately rotted copies of the suite, with the real one green. It is a command rather than a CI
  gate because a Rust test would need a second copy of `present()`, whose three rules were each
  learned from a wrong verdict; run it after a `win-kexp` bump, a symbol-path change or a new
  sample. Nothing was wrong when it landed.

- **The eval's `arm64_pc` task asks a question with one reading** (`FOLLOWUPS.md` item 44, which
  closes it). It asked for "the value of the `pc` register at the point of the crash", which reads
  as the address whose execution faulted — bug check parameter 1 — rather than as the register's
  value: across the 35 runs of it in the three logs on disk, **none** gave the key and **32** gave
  parameter 1. Both are defensible on that dump (`pc` is `nt!KeBugCheck2+0x2e8`, inside the
  bug-check path the machine reached *after* the fault), so the fix is the question and not the
  key — widening `expect` to accept parameter 1 would let the task pass off `open_dump`'s summary,
  where the parameters already are, without the route it exists to check being taken at all. The
  other five prompts were re-read against their keys at the same time and none has the same
  defect; `driver_blame`'s `0x1654` is the nearest thing and is recorded in that task's `note`
  rather than changed, since 33 of its 35 runs give the key. **Scores published before this**
  — `docs/local-model-eval.md`, three tables over — were graded against the old wording and say so
  now.

- **A run's identity includes the question it asked**, so the suite the published runs used is
  frozen as `tools/eval_tasks_v1.json` and both checked-in plans name it; the live
  `tools/eval_tasks.json` is `v2`. `usable()` drops any record whose stored prompt is not the one
  the suite asks now — right for a resume, and it meant rewording `arm64_pc` in place took that
  task out of every historical plan: `after-217.jsonl` graded 15 possible per cell instead of 20,
  with 25 of 150 records `UNCOUNTED`, and a *resumed* plan would have appended new-wording answers
  under the same `(cell, draw, task)` key as the old ones. Pinned, it grades to 20 again and
  resume counts 150 of 150 done. The grader now also names that reason under the table when it
  fires, because it is the one uncounted reason a reader can act on — a served window that was not
  the one requested is unrecoverable, a changed question is only the wrong suite.

- **The eval's `unserved` column is two numbers, because it was two measurements** (`FOLLOWUPS.md`
  item 43, which closes it). A call naming a tool the client is not served is either `taught` — the
  task *was* answerable on this surface, so nothing about the question required a name off it — or
  `wanted`, where it was not and the model reached for the capability that would answer it. Summed,
  they hide each other: re-graded over the two logs on disk, item 41's fix is **4+10 -> 0+6**, an
  elimination of the half it was aimed at rather than a 57% improvement in a total. `taught` prints
  its offenders by name and `--grade --assert-no-taught` exits non-zero on one; `wanted` is not
  assertable, being a property of the task list rather than of this server.

### Fixed

- **Every tool's `outputSchema` is rooted at `type: "object"`, which is what keeps a strict client
  holding any tools at all** (issue #223). The structured results are internally-tagged enums, and
  `schemars` renders one as `{ $schema, oneOf, $defs }` — object-ness stated on each branch of the
  union and nowhere at the root. rmcp passes that through deliberately, because SEP-2106
  (`2026-07-28`) relaxed the requirement for output schemas. But that relaxation says what a server
  *may* emit, not what clients accept: every released `@modelcontextprotocol/sdk` 1.x — 1.30.0
  included — parses `Tool.outputSchema` as `z.object({ type: z.literal("object"), … })` and
  `tools/list` as `z.array(ToolSchema)`, so the array fails on the first non-conforming tool and the
  client registers **none** of them. Measured against 1.30.0 on this server's own captured
  `tools/list`: **0 of 51 tools before, 51 of 51 after**. It reached a real client as zero tools
  registered, a reconnect loop exhausted and the server deregistered.

  Supplying the keyword is not a concession to old clients — it is *true*, since MCP types
  `structuredContent` as a JSON object in every revision — and it changes nothing about what
  validates: each branch of the `oneOf` already carried `"type": "object"`, and `ajv` gives success,
  failure, a payload missing its required fields and an unknown discriminator the same verdict
  either way. Emitting the relaxed shape only to peers that negotiated `2026-07-28` was considered
  and rejected for the same reason: the object-rooted form is legal under both revisions, so the
  version-aware branch would exist only to send a worse schema to half the population. It costs
  16 bytes per tool — 528 across the surface, none of it model-visible.

- **A raw `execute` of `g`/`p`/`t` moves the target instead of wedging the session**
  ([#226](https://github.com/glslang/windbg-mcp/issues/226)). `execute` runs a plain
  `IDebugControl::Execute`, and DbgEng's execution-control commands only *set the run state*
  there — nothing moves until a `WaitForEvent` pumps it. So the call answered with its own echoed
  command, the target had not moved, and from then on every `go`/`step_*` on that session failed
  with `0x80040205` while `bl`, `r` and `.lastevent` kept working, which reads as half alive. There
  was no way back short of `end_session`. The same door was open through `debug_batch`'s
  `{"op": "command"}` step, which reported `committed`, `rollback_complete: true` and
  `after: stopped` on a session it had just wedged.

  The fix asks the **engine** rather than the command text: after any raw `Execute`, win-kexp's new
  `settle` reads the execution status and pumps a target that was left running. That is why no list
  of command names appears anywhere in it — `bp X; g`, an alias, `.if (1) { g }` and the data
  model all reach execution without saying so, and a list would have to enumerate them. The result
  carries what the pump printed plus a line naming where the target ended up, since a step prints
  nothing at all; `debug_batch` now asks the same question before reporting what its session holds.

- **A `go`, step or `resume` that reaches no stop no longer destroys its session**, and says what
  happened. Underneath #226 and reachable with no `execute` at all: win-kexp's `execute_and_wait`
  used a *finite* `WaitForEvent` for every target that was not a live kernel, and on expiry that
  returns `S_FALSE` with the target still running and the engine holding no current process/thread
  — unrecoverable, while the call reported success. Measured: one `go` on a launched process with
  nothing to stop it, and every later `registers`, `bl` and `? @$ip` failed with `0x80040205` for
  the life of the session, with `session_status` still calling it open and live. The wait is now
  the bounded INFINITE one `run_to_address` has always used, so the target is broken in at the
  bound and the session survives, and `go`/`step_*`/`reverse_*` answer with a new
  `timed_out` beside `interrupted` — two different reasons the position is real but is not a stop
  the target reached. Nothing caught this because the only tier that drove execution was the
  live-kernel one, which was already on the bounded wait; the debugger tier now launches a process
  and drives it. A session **transcript** records which of the two reasons a stop was not one the
  target reached, and `--render-cast` says so, rather than showing a forced break as an ordinary
  stop. And where the recovery itself fails, the answer depends on what the engine then says: still
  running is an error carrying the command's output, stopped is the command's answer, and an engine
  that cannot be asked is reported as not known instead of guessed at.

- **And no *result* names one either, which was the channel nobody had scanned** (`FOLLOWUPS.md`
  item 43). Items 40 and 41 below closed the `instructions` string and the descriptions; an
  opener's summary went on ending with "`modules` lists a page of the table and `modules
  { \"filter\": \"<name>\" }` answers for one", because `summary_text` runs in the **worker**,
  which owns one session and has never heard of a client, let alone its surface. `modules` is
  `inspect`, so on an eleven-tool `crash` surface the first result a client ever saw handed it the
  exact name together with its real argument — which is where the local-model bench's "invented"
  `modules` calls were coming from. `crash_triage` rode along the same way, and a post-commit
  failure sent any caller to `execute`. The summary now crosses the pipe as facts and the pointers
  are appended where the surface is (`SUMMARY_NOTES`, `annotated_report`), on both halves of the
  result, since a structured-aware client forwards `structuredContent` and drops the text. Two
  more sentences went the same way: a post-commit failure keeps its advice on every surface and
  drops only the `execute` example, and `crash_triage`'s user-mode refusal — which named
  `backtrace` and `execute` to the one caller that has neither, `crash_triage` being `crash` while
  both of those are `inspect`.

- **A client is told about the tools it is served, and no others** (`FOLLOWUPS.md` item 40, which
  closes it). `--tools` narrowed the router per client — `tools/list` answers with that client's
  set, and anything else is refused by name — while the `instructions` string sent at `initialize`
  stayed one literal naming twenty-one tools, sent to everybody. A `--tools crash` client could
  call eleven tools and was told about twenty-one, so it would ask for `modules`, `execute` or
  `debug_batch` and be refused; driving this server with local models measured every one of those
  wasted calls (`docs/local-model-eval.md`) and read them as models inventing tool names. They were
  reading this server — through this string where the client injects it into its prompt, and
  through the descriptions of tools they *are* served where it does not (`FOLLOWUPS.md` item 41).
  The string is now a base plus a fragment per group, assembled for the client's own surface:
  1,983 characters for the whole surface against the constant's 1,990, 1,220 for
  `session,inspect,crash`, and **927 for `crash`** — a 53% cut, worth ~265 tokens to a client that
  reads it, on the surface that exists to be small.

- **And no served tool's description advertises one the client cannot call** (`FOLLOWUPS.md` item
  41, which closes it). Item 40 fixed one of the two channels above; this is the other and the
  larger. A tool's description cross-references other tools — `open_dump` said the module table is
  "what `modules` lists", `interrupt` and `end_session` both named `debug_batch`, `crash_triage`
  named `backtrace` — and on `--tools crash` those five sentences named four tools the client is
  refused. The eval measured them: with item 40 live, 13 of 61 calls on that surface still asked
  for `modules` or `debug_batch`, three times what the instructions were costing. Re-running those
  five cells afterwards took unserved calls **14 to 6** and `debug_batch` to **zero**; the three
  `modules` calls did not move, so a description naming it is not what a model needs in order to
  ask for it, though one sample per cell cannot say it never contributed. Every such
  sentence now lives in `TOOL_NOTES` beside the tools it names and is appended only to a client
  served all of them, so `--tools crash` reads **14,138 B instead of 15,073** (−6.2%) and names
  nothing it cannot call, `session` alone 11,265 instead of 12,161, and the fifty-one-tool client
  keeps every pointer for 108 bytes more (67,766). Twenty-two (tool, tool-it-names) pairs across
  sixteen descriptions, not the five one surface showed: a spec may name a single tool, and six of
  the pairs — four pointing at `execute`, the three pool tools at each other — are inside one group
  where no group spec reaches them.

- **`--list-listen-clients` sorts both halves of what it prints.** A credential file's entries
  already came back sorted; the environment's arrived in the order the variables were scanned,
  which on Windows is by *variable* name — so `WINDBG_MCP_LISTEN_TOKEN` came before
  `…_TOKEN_BENCH` and `local` led a roster whose other half was alphabetical. The same command
  formatted its two answers differently, and neither could be diffed against the other.

### Added

- **The eval can repeat a cell, which is the only way it can answer "how often"** (`FOLLOWUPS.md`
  item 42, which closes it). The grid runs one draw per (model, context, surface, task) — enough
  for failure *modes* and for whether a surface fits, and not enough for any sentence of the form
  "X caused Y". Three write-ups reached past that anyway and review took two of them back, each
  time because the cell's *composition* had changed too: an aggregate holding across two runs of
  different models is a coincidence, not a rate. A cell group now takes `draws: n` and the draw
  index is part of a record's identity, so repeats **accumulate** — `already_done` resumes per
  draw, the grader counts over draws instead of keeping the last, and `--matrix` prints a
  distribution (`3Y2n` is five draws, three correct) where one draw still prints `Y`. A record
  written before this is draw 1, so the three published runs grade to exactly what they graded to.

  **The seed rides along and does not replay a draw here.** Each draw asks for `seed: <draw index>`
  and records it, which where a seed reproduces a sample makes draws repeatable and pairs the two
  arms of an A/B. It does not here: four identical requests to `qwen3.8:27b-mlx` under
  `seed: 7` returned four different answers (ollama 0.32.15, MLX). Measured after the code comment
  claiming the opposite had been written — the column is what was *asked for*, and the distribution
  over draws is the measurement.

- **The local-model eval: a grid where there were two sightings**
  ([`docs/local-model-eval.md`](./docs/local-model-eval.md), `FOLLOWUPS.md` item 39). Three ~30B
  local models against three tool surfaces and three context windows, with Claude Code as the
  control, scored against an answer key read off the checked-in sample dumps with this server's own
  tools before any model saw them. `tools/local_model_eval.py` runs the grid and grades it,
  `tools/claude_code_drive.py` is the control row, `tools/bench_listener.ps1` stands up the one
  listener that serves all three surfaces — which is 0.11.0's per-client `--tools` doing the
  narrowing, rather than a test double.

  It also found a defect in this server, filed as `FOLLOWUPS.md` item 40: **`--tools` narrows
  `tools/list` and not the `instructions` string**, which is one compile-time constant naming
  twenty-one tools and is sent to every client whatever its surface. A `crash`-surface client is
  served 11 tools and told about 21, of which 17 it cannot call - which is where every "invented"
  tool call in the grid came from, and 59% of a 497-token string that client pays for in full.

  Three findings worth the run. **The window was not the binding constraint**: at a *served*
  8,192-token window a 17,300-token surface answered all six tasks correctly, multi-turn tasks with
  10,000-character results included, so the "will it fit" arithmetic in `docs/local-model.md`
  predicted a failure that does not happen on this runtime. **The surface axis costs fewer answers
  than tools** — 51 tools down to 11 removes 40 tools and 2 of 6 answers, because `open_dump`'s
  summary and `crash_triage`'s frames carry facts that `modules` and `registers` also carry. And
  **a narrowed surface makes every model call tools that are not there**, the control included, so
  the refusal that names the client's own surface is load-bearing rather than cosmetic.

- **The client commands warn when the SCM starts a different copy of this program than the one you
  ran** (`FOLLOWUPS.md` item 38, which closes it). 0.11.0 gave the credential file a shape earlier
  builds refuse — an entry that is an object, carrying a client's `--tools` beside its token — so
  `--add-listen-client <name> --tools …` or `--set-listen-client-tools`, run from a newer copy than
  the one the SCM starts, writes a file the running service cannot read. **Nothing breaks at the
  time, which is the problem**: a reload only ever swaps in a set that would have started this
  listener from cold, so the service goes on serving the clients it had and says so in its log. It
  is the *next start* that fails, a reboot away from the cause. A fresh install cannot reach this
  and neither can an ordinary upgrade, since Windows will not overwrite a running image — a
  development tree with two builds in it is the case that does.

  All five commands print it, with both paths: the four that edit the file, and
  `--list-listen-clients`, which is where an operator goes when a service did not come back after a
  reboot and which was otherwise printing one build's reading of a file another build has to read.
  **A warning and never a refusal** — a path is all there is to compare, since nothing carries a
  version between the two, and running a client command from a second copy of the *same* build is
  legitimate and looks identical from here.

- **`--list-listen-clients`, the one client command that changes nothing** (`FOLLOWUPS.md` item 37,
  which closes it). The four commands that edit a service's credential file each print the whole
  roster afterwards — name, token fingerprint, and the `--tools` spec where one is set — and until
  now that roster could only be had by making a change you may not have wanted. That was survivable
  while every client was served the same surface, because "who may connect" had one other answer in
  the listener's startup line; a client's own spec has no such second answer.

  It reads the same file through the same parser as the edits and prints the same fingerprints,
  and it writes nothing whatever: no token minted, no reload asked for, and not even the credential
  lock the four editors take — that lock is a file this program creates, and creating one is a
  write. **A file it cannot read in full refuses rather than printing a shorter roster** — one entry this server would
  refuse at startup is a file that will not start the service, and a list that quietly dropped the
  client it could not parse would be the most misleading thing this command could print.

  **It says which of the two sources it answered for.** A service's clients are in the credential
  file; a foreground listener's are the environment it was started with, and no command edits
  those — so where no service is installed this answers for the environment instead of refusing,
  and where both are configured it prints both. A `--tools` beside it is refused rather than
  ignored, on the same rule as `--rotate-` and `--remove-listen-client`: it reads exactly like a
  filter over the list it is about to print.

  **And it says it is reading the file rather than the service**, with the state that service is in
  beside it, because the two differ in two unrelated ways. A credential's: a `--remove` or
  `--rotate` whose reload failed leaves a token authenticating that the file no longer names, which
  is the case an operator would run this to check. A surface's: a reload that *succeeded* still
  does not reach a client holding an MCP session, which goes on being served what it had when it
  connected — including when the change was to *clear* the last spec, so the caveat is
  unconditional rather than gated on the file still holding one. The running service
  cannot be asked what it holds: its only channel carries a status code and no data, so what is
  reported beside the roster is the state that service is in, across every state it can reach —
  including **stopping**, which is not stopped: a stop ends the accept loop and then releases every
  target, and the connections already accepted are served until the process exits.

### Documentation

- **`README.md` is now a map rather than the manual.** It had grown to 986 lines carrying twelve
  topics end to end, so a reader looking for one of them scrolled past the other eleven, and every
  topic's prose was in the one file a newcomer opens first. Each topic is now its own document
  under `docs/` — [`architecture.md`](docs/architecture.md), [`install.md`](docs/install.md),
  [`mcp-clients.md`](docs/mcp-clients.md), [`releasing.md`](docs/releasing.md),
  [`tool-surface.md`](docs/tool-surface.md), [`sessions.md`](docs/sessions.md),
  [`kernel-profiles.md`](docs/kernel-profiles.md), [`structured-results.md`](docs/structured-results.md),
  [`debug-batch.md`](docs/debug-batch.md), [`walk-memory.md`](docs/walk-memory.md),
  [`transcripts.md`](docs/transcripts.md), [`limitations.md`](docs/limitations.md) and
  [`walkthroughs.md`](docs/walkthroughs.md) — and the README keeps an index, a quick start, the
  tool table, and a summary of each topic that links to it. **The prose moved verbatim**; what
  changed is where it lives.

  The **`## Tools` table stays in the README**, because `docs/messagemanager-walkthrough.md` and
  two of the new documents link to `README.md#tools`, and because it is the one thing a reader
  wants before deciding to read anything else.

  Three references were wrong before the move and are fixed rather than carried over: the
  *Requirements* section pointed at a *"TTD engine"* section that has never existed (it meant
  *Bundling the WinDbg engine*), the platform badge linked to `#requirements` on a README that no
  longer has that heading, and `crash_triage`'s "no `!analyze`" error told the reader to see "the
  README's engine setup". Source comments in `src/schema.rs`, `src/structured.rs`, `src/worker.rs`
  and `tests/mcp_smoke.rs` that cited a README section now cite the document holding it.

## [0.11.0] - 2026-08-23

### Added

- **A tool surface per client, not just per server** (`FOLLOWUPS.md` item 36, which closes it). A
  `--listen` server names its clients already, and they do not have one budget between them: the
  arrangement this listener exists for is a local model that can hold twenty tools beside a hosted
  client that can hold fifty-one, on the same box and against the same debug sessions. So a client
  may be configured with a `--tools` spec of its own — `WINDBG_MCP_TOOLS_<NAME>` beside its token,
  or a `tools` field in the credential file — and two credentials on one port get two `tools/list`
  answers.

  **The run's `--tools` is the default rather than a ceiling.** A client with no spec of its own is
  served whatever the run serves; a client with one is served that instead, wider or narrower,
  because an intersection would produce a surface neither the operator nor the client ever named.
  `session` is added to a client's spec exactly as it is to a run's.

  The credential file's entries may now be objects — `{"bench": {"token": "…", "tools": "crash"}}` —
  beside the bare tokens they always were, which keep meaning what they meant. A spec naming a
  client nothing configures a token for is **refused at startup**, on the precedent of the two
  collisions that file already refuses: a surface no credential can reach is a setting that would
  never take effect, and the way to write one is the typo that makes the two variables disagree.

  **`--set-listen-client-tools <name> --tools <spec>`** changes a service-hosted listener's client
  surface without a reinstall or a restart, the way item 34's three commands change a token; with
  no `--tools` at all it puts the client back on the service's own surface. It mints no credential
  and revokes none. A `--tools` beside `--rotate-` or `--remove-listen-client` is refused rather
  than ignored, because it reads exactly like a command that had narrowed that client.

  **A surface change reaches a client the next time it is identified**, and nothing announces one.
  The surface is fixed at that moment — `initialize` for a client holding an MCP session, every
  request for one on `2026-07-28`, which therefore picks the change up with nothing done to it —
  and no `notifications/tools/list_changed` is
  sent: this server keeps no handle to notify a session through, and the sessionless revision has
  no session to notify, so it would be a guarantee on one revision and silence on the other. The
  command that changes a surface says so.

  A tool that exists and is not served is still refused by name rather than as an unknown tool, and
  the message now names **which** configuration to widen — the run's flag, or that client's own
  entry — since the caller can see neither.

- **`--tools` serves a named subset of the tool surface** (`FOLLOWUPS.md` item 24's last finding,
  which closes that item). All 51 tools cost a model **67,658 B — about 17k tokens — once per
  conversation, before it has asked anything**. `--tools session,inspect,crash` makes that 20 tools
  and 25,265 B; `--tools crash` is 11 and 15,073 B. Nothing is reworded: the tools that remain are
  the tools they were.

  Fewer tools rather than smaller ones, because measuring settled it: **74% of the model-visible
  surface is prose** - 24,794 B of tool descriptions and 25,333 B inside the input schemas - and
  input-schema prose is most of what tells a model how to drive a tool. `debug_batch` is where
  getting that wrong leaves a patched byte in a running kernel. The structural remainder is
  ~1,744 B, 2.6%, since `$schema` is how a client picks a validator dialect and `minimum`/`format`
  are constraints. There was no strip here worth the risk.

  A spec names groups (`session`, `inspect`, `exec`, `ttd`, `ioctl`, `allocator`, `crash`, `batch`),
  individual tools, or `all`; anything else is refused at startup with the valid names. **`session`
  is always included** - every other tool routes by a `session_id` this server is the only issuer
  of, so a surface with `registers` and no opener is not a smaller surface but a broken one, and
  `--tools crash` is eleven tools rather than one. A tool that exists and is *not* served is refused
  by name ("not on the surface this run advertises") rather than as an unknown tool, because the
  remedy is a flag on a command line the caller cannot see.

  On the stdio command line, on a `--listen` one, or on `--install-service`, where it is written
  into the command line the SCM stores and read back at every start - the only place an install's
  choice survives to. It was server-wide when it landed; the entry above makes it a run's default
  that a named client may replace.

- **A service-hosted listener's clients can be changed without a reinstall**
  (`FOLLOWUPS.md` item 34). `--add-listen-client <name>`, `--remove-listen-client <name>` and
  `--rotate-listen-client <name>`, from an elevated shell, edit the credential file the service
  reads and then tell the running service to re-read it — so a client is added, revoked or rotated
  **without stopping anything**. Before this, `--install-service` was the file's only writer and the
  SCM refuses a second registration, so adding a client meant uninstall, set every credential
  variable again, install, start — which drops every session the service holds, a parked kernel
  attach included.

  Each command **generates the token itself** and never prints one: standard output carries a
  fingerprint (`sha256:701E4CF334890225`) and the token goes to `<name>.token` beside the credential
  file, in the same SYSTEM-and-Administrators directory — not to a path the operator names, because
  writing a live credential into a directory this program does not control the protection of means
  creating, ACL'ing and reopening it by name, which is a window to substitute a file and keep a read
  handle to it. Keeping a working credential out of a shell history and out of an agent's transcript
  is what makes these commands narrow enough to allow-list in a permission rule where "let this
  write `%ProgramData%`" would not be.

  The two properties the installer was hardened for are unchanged: only *this program*, running
  elevated, writes that file, and it still never writes through a file it did not create — the
  content goes to a fresh sibling created with `create_new` in the protected directory, is ACL'd
  there, and is renamed over the old name, which also makes the replacement atomic for a service
  reading it concurrently. `--install-service` now shares that writer, so an install and an
  `--add-listen-client` leave the file to one standard.

  A **rotation keeps the client's name**, and so keeps the debug sessions it has open — only the
  token moves. A **removal releases** what that client still held, down the path a lease expiry
  already uses (an orderly release, not a worker killed and a live kernel left frozen); the command
  could not have refused on their account, since it runs in another process and cannot see them, and
  blocking a revocation on the sessions it is revoking is the wrong way round. Removing the *last*
  client is refused: a listener with no credentials will not start, and `--uninstall-service` is the
  command that means "stop serving".

  The command **waits for the reload**, so the set in force when it returns is the set it wrote — the
  control handler blocks on the reload task's answer and reports a failed re-read as a failed
  control code. A reload that cannot read the file **changes nothing**: the set is only ever
  replaced by one that would have started this listener from cold, so a typo is a loud log line and
  a service still serving, rather than every client locked out of a live kernel target. That failure
  is reported as an **error** for a `--remove` or `--rotate`, whose whole point is that a credential
  stops being accepted, and as a warning for an `--add`.

  Two of these commands cannot run at once (a `token.lock` in the state directory, opened with no
  sharing): both would compute a whole file from their own snapshot and the later write would
  silently discard the earlier.

  A removal also **deletes that client's token copy** if it is still sitting there: the credential
  file is written by then, so the file authenticates nothing from the moment the command returns.

  **A revocation is an expiry that does not wait.** It sets that client's lease clock to now and
  closes an admission gate (`Sessions::revoke`); the sweeper — which already releases an expired
  client's debug sessions, closes the MCP sessions it left resident and clears its state — does the
  teardown on its next pass, and lifts the gate when it is done. So nothing an operator waits on is
  behind a live kernel letting go, and there is no second teardown path to keep in step with the
  first. The gate is what a lease expiry does not need: an expiry fires only after the client has
  been silent for longer than any call can keep it quiet, so nothing of that credential's can still
  be in flight, whereas here an opener that authenticated a moment earlier can be seconds from
  registering — and a session admitted behind the sweep would belong to a client nothing can
  authenticate as and nothing will ever come back for.

  **A name given back is a different client**
  ([#190](https://github.com/glslang/windbg-mcp/issues/190)). A client used to *be* its name, so
  `--remove-listen-client ci` followed by `--add-listen-client ci` produced two credentials that
  nothing keyed on identity could tell apart, and the second reached the debug sessions, MCP session
  ids and lease of the first. Identity is now `(name, incarnation)`: the name is still the whole of
  what is rendered — log lines, refusals and `session_status` say exactly what they did — and the
  incarnation is minted in one place, when a set of credentials is swapped in, which is the only
  code that can tell a name *carrying on* from a name *being given back*. So a
  `--rotate-listen-client` keeps the client and therefore its sessions, which is what it is for, and
  a removal-and-re-add keeps only the name.

  A request already inside the MCP service when the set was swapped still settles against the client
  that is going, and records its MCP session so the sweep closes it — but does not renew the clock,
  since a renewal would push the revocation a whole grace out and the sweep that was to run on its
  next pass would not. A request of that credential's which authenticated a moment before the swap
  and reaches the lease after it is refused, so a revoked client cannot route to its sessions once
  more; one already *inside* the service runs to completion, as it must, because a call against a
  live kernel cannot be abandoned half way.

  The registry gate a revocation closes is **never lifted**, and no longer needs to be. It marks the
  incarnation rather than the name, so a client configured under that name afterwards is simply not
  the one it gates — which deleted the question of *when* to take a gate off, where two separate
  findings had lived. It exists because the release is one pass over the sessions that exist, so an
  opener which authenticated before the revocation and has not registered yet — an `attach_kernel`
  is a worker spawn away — is invisible to it. What it leaves behind is a name and a `u64` per
  revocation.

### Changed

- **An `outputSchema` carries constraints now, not prose** (`FOLLOWUPS.md` item 24's finding 1).
  The whole `tools/list` payload went **394,883 B -> 177,460 B, a 55% cut**, and what a model reads
  did not move by a byte. `schemars` emits each output schema self-contained, so every type
  reachable from a tool's answer is inlined into that tool's `$defs`: `ErrorCategory`'s doc comment
  shipped 33 times, `ModuleInfo`'s seven, the allocator subtree's nine - 222,579 B of duplication.
  That duplication cannot be removed, because MCP gives each tool one schema and no document above
  it for a `$ref` to reach. What could be removed is what was being multiplied: **68% of every
  `outputSchema` byte was a `description`**, and `ErrorCategory` is 2,089 B with its prose and 324 B
  without.

  Nothing read it there. No model is given an output schema - the measurement
  `docs/token-budget.md` opens with - and `description` is an annotation keyword, so every instance
  that validated before validates now. The prose stays where it is read: the rustdoc it is generated
  from, `README.md`'s structured-results table, and each tool's own model-visible `description`.

  The strip is **structural, not textual** (`src/schema.rs`): a field named `description` is a
  property name, so removing every `"description"` key would delete the field rather than its
  documentation. No structured type has such a field, which is precisely why nothing would have
  reported it - there is a unit test for the case, and a smoke assertion reading `tools/list` off
  the wire, because the change comes undone by one import line. `WIRE_CEILING` 460,000 -> 205,000.

- **A default `registers` answer stopped carrying the vector bank** (`FOLLOWUPS.md` item 24's
  finding 7). The `all` argument documents the default as excluding the x87 and vector registers,
  and it did not: DbgEng exposes `xmm0` twice - as 128 bits of `bytes`, and as `xmm0/0` … `xmm0/3`,
  four 32-bit pseudo-registers that carry no subregister flag - so 64 of the x64 sample's 123 rows
  were the vector bank. Excluding them, and skipping `"subregister":false` on the rows that remain,
  takes the answer from **9,804 B to 3,480 B** and its ratio against its own text from 15.9x to
  5.6x; the result ceiling moved 13,500 -> 5,000 with it. `kind` was left alone - it earns its place
  on the `float`, `non_finite` and `unavailable` rows.

  Two things the measurement corrected rather than confirmed. The scaffolding this was filed against
  was 41% of the payload, not the bulk of it. And the text was never "the same thing better": `r`
  prints 17 registers where the values carried 123, so the ratio compared two different sets - it is
  59 against 17 now. The ARM64 half is untouched and filed as item 35: there the same class of row
  is `w0`-`w30`, which DbgEng declines to flag as views either.

- **A `modules` page names the `limit` that would return everything.** Driving the capped tool with
  a local model found the trap the cap had introduced: the obvious value to raise `limit` to is the
  count the note above the rows just gave (`227 module(s) loaded`), and that one is *guaranteed* to
  fall short, because the budget is shared with the unloaded half - the model asked for 227, got 177
  loaded rows and 50 unloaded ones, and had to fetch the table a second time. The note now reads
  ``Showing the first 64 loaded row(s) - `limit: 277` returns all of them, or narrow with `filter`
  to ask about one driver.`` Both halves' match counts are known where the note is built, so the sum
  is too. Above the 2000-row ceiling there is no such value and the note says so rather than naming
  one that would still be short. A re-run halved that task's cost, 146,359 characters to 70,929.

- **`tools/local_model_drive.py` keeps its lease alive while the model thinks.** The same run found
  something that is not about tokens at all: a lease is renewed by requests and its grace is derived
  from how long a *call* may take, so it assumes the server is the slow party. A local model
  inverts that - one turn took 440s against a 390s grace - and the sweep released the client's
  sessions mid-investigation, after which every call returned `404 Session not found`, which reads
  exactly like a broken server. The script now pings after 120s of silence
  (`WINDBG_MCP_KEEPALIVE`, `0` disables). Whether the listener should also be more patient with a
  still-connected client is [`FOLLOWUPS.md`](./FOLLOWUPS.md) item 33.

- **`modules` answers with a page of the table rather than all of it** ([`FOLLOWUPS.md`](./FOLLOWUPS.md)
  item 24). It was the largest single answer this server gives - 53,933 B of model-visible JSON for
  227 modules, a fifth of a whole tool surface for one question, and on a local model a turn of
  prefill measured in minutes as well as the window it fills. A new `limit` (default 64, maximum
  2000) bounds the whole listing, the loaded and unloaded halves sharing it through the same
  `split_row_budget` the heap diagnostics use, so neither can crowd the other out. Measured against
  the same checked-in dump `docs/token-budget.md` records its baseline on: **12,268 B model /
  16,871 B wire for the default page against 53,933 B / 74,052 B for all 227 modules**, for 383 B
  of tool surface paid once a conversation.

  The counts are what keep it honest, and they are values rather than prose: `loaded` is the
  target's inventory as before, and the new `matched` / `unloaded_matched` say how many rows each
  half would have had - so a page is never mistaken for the whole table. The text says the same
  thing and names the argument that undoes it. Every existing cap in this codebase is a worker
  out-of-memory guard; this is the first one whose constraint is the **caller's** context.

- **Driver-frame attribution is now asserted on an ARM64 stack as well**
  ([#154](https://github.com/glslang/windbg-mcp/issues/154)). A `0x139` crash raised inside HEVD by
  its own stack-cookie fail fast is checked in as `docs/samples/082126-7015-01.dmp`, and the smoke
  tier's driver-crash test became a table run over every checked-in driver crash on every host.
  The pair also covers `!analyze` both ways round: it cannot name the PDB-less `MessageManager`,
  and does name `HEVD`.

- **CI runs the debugger tier on the new ARM64 runner image as well.** GitHub's Visual Studio 2026
  ARM64 image went generally available on 2026-08-20 as `windows-11-vs2026-arm`, and the
  `windows-11-arm` label migrates onto it between 21 and 30 September 2026. The tier's ARM64 half
  is now a pair of entries, one per label, because what this job exercises that nothing else does
  is a real inbox `dbgeng.dll` and the two labels are - until the migration completes - two
  different OS builds carrying two different ones. Running both is what makes a break attributable
  to the image rather than to the change under review; the older entry is meant to be dropped once
  the labels converge ([`FOLLOWUPS.md`](./FOLLOWUPS.md) item 32). The cargo cache is now keyed by
  runner label rather than by architecture, or the two ARM64 entries would share one. The x64 entry
  needs no pairing: `windows-latest` has been the Visual Studio 2026 image since its own migration.

- **The ARM64 CI entry resolves symbols, so its target-reading assertions run**
  ([#153](https://github.com/glslang/windbg-mcp/issues/153)). Both runner images carry the
  Debugging Tools; what differs is System32. `windows-latest` ships a `symsrv.dll` there beside
  the `dbghelp.dll` that is always present, so its stock engine reaches the symbol server;
  `windows-11-arm` has none, so a `srv*` path downloaded nothing, `nt` resolved no PDB, and all
  four assertions that read a *target* stood down. That entry now copies the kit's `dbghelp.dll`
  and `symsrv.dll` beside the binary under test - `dbgeng.dll` is deliberately left alone, so it
  goes on loading the image's own engine - and the job fails if either stand-down appears in the
  output, since a skip otherwise reads exactly like a green run.

  This also retires the claim that Windows ships no `symsrv.dll` outside the Debugging Tools. It
  holds on ARM64 and does not hold on the x64 runner image.

### Fixed

- **Two ways a client command could report a revocation that had not happened** (found reviewing
  [#189](https://github.com/glslang/windbg-mcp/pull/189), after it merged). Both ended the same way:
  `--remove-listen-client` or `--rotate-listen-client` printing success while the credential it took
  out of service went on being accepted, which is the worst thing these commands can do.

  A service now reads **the credential file its own commands write**, unconditionally. It used to
  defer to a `WINDBG_MCP_LISTEN_TOKEN_FILE` already in its environment, which left it serving one
  file while the commands edited another — and the reload then succeeded, re-reading the unchanged
  override. `%ProgramData%\windbg-mcp\token` is what the installer writes, the commands edit and
  `--uninstall-service` deletes, so a service reading elsewhere is a configuration whose other three
  halves do not exist. An inherited override is ignored with a warning; the variable is unchanged
  for a foreground listener, which is what it is documented for.

  And a **starting** service is no longer treated as a stopped one. Credentials are read before the
  bind, so a `StartPending` listener is already serving the old set — and a non-loopback bind at boot
  can hold it there for `BIND_PATIENCE`, a minute and a half — while "it will read this at its next
  start" was true only of a start that had not happened. It cannot be told either: the SCM refuses a
  control code to a service in that state (`ERROR_SERVICE_CANNOT_ACCEPT_CTRL`, measured against a
  real service held there by an address not on the host). So the command says the change was not
  handed over, says that whether the start picked it up by itself cannot be told from outside, and
  points at the `clients: …` line the listener logs when it comes up. A `--remove` or `--rotate`
  exits non-zero, because "may still authenticate" is the same thing to act on as "does".

- **`tools/ioctl_harness.ps1` could not run under Windows PowerShell 5.1**, which is the only
  PowerShell a stock debuggee has. Three faults, each fatal before an IOCTL was sent: em dashes in
  a BOM-less UTF-8 file (5.1 decodes such a file in the ANSI code page, so `—` became a string
  terminator and the parse failed tens of lines later), `0x80000000` read as a negative `Int32` so
  the access mask was refused by `CreateFileW`, and the default empty `-InputHex` returning `$null`
  because the pipeline unrolls an empty array - so an IOCTL taking no input buffer could not be
  sent at all.

## [0.10.0] - 2026-08-20

### Added

- **`--listen`: the same tool surface over HTTP, so the client and the model need not be on the
  debugger host** ([#135](https://github.com/glslang/windbg-mcp/pull/135)). DbgEng is Windows-only
  and holds one debuggee per process; nothing about the *client* has to be. `windbg-mcp.exe --listen
  127.0.0.1:8765` serves every tool over streamable HTTP, with the process tree below it unchanged —
  same supervisor, same private pipes to each engine worker, same teardown.

  - **A bearer token is required, and the server refuses to start without one.** The surface
    includes `execute` and `launch`, so a port with no lock on it is arbitrary code on the machine
    holding your kernel debugger. `WINDBG_MCP_LISTEN_TOKEN` names it.
  - **Bind loopback and forward with `ssh -L`.** The listener binds what it is told and *warns* on
    every start when that is not loopback, because the argument for skipping a tunnel — a
    hypervisor network that does not route off the host — is exactly wrong on a debugger host: the
    guest being debugged is on that network, and is a sandbox by design.
  - **A session lease stands in for "stdio closed" — for the clients that can have one.** Under
    stdio the disconnect *is* the teardown signal, and it drives a real `EndSession` through every
    worker rather than killing it, because a live kernel that is merely killed is left frozen. HTTP
    has no such event, so a credential that holds a settled MCP session holds a deadline with it,
    renewed by every admitted request, and a sweep releases what an absent client left. **A
    `2026-07-28` client has no such session and is therefore never given a clock** — SEP-2567
    removed the id a lease is armed by — so what covers an abandoned target there is the per-session
    idle release under **Changed** below, which is a different question deliberately answered
    differently: it is far longer, it is per session rather than per credential, and it spares a
    session with a call still outstanding. A parked `attach_kernel` is exactly that, so it is held
    until somebody ends it rather than until a timer notices.
  - **Silence is not departure and a goodbye is** — both of them session-id behaviours, so both
    belong to the client above that has one. Every request is its own connection, so quiet is the
    resting state; a `DELETE` is the client saying it is done. One that comes back inside the grace
    **adopts what it left**, which is what makes a client restart cost nothing where under stdio it
    costs a KDNET attach — and a KDNET attach costs a reboot of the target.
  - **The grace has a floor and the floor is derived, not chosen**: the longest a single call can
    keep a client quiet is `WORKER_READY_TIMEOUT` plus the call timeout, since an opener spends up
    to 30s bringing a worker up before its budget starts. A shorter grace would release a session
    underneath the request that opened it, so it is refused at startup rather than truncated.
    `WINDBG_MCP_LEASE_GRACE_SECS` overrides it.

  [`docs/remote-listener.md`](./docs/remote-listener.md) is the operator's half.

- **The listener installs as a Windows service** ([#151](https://github.com/glslang/windbg-mcp/pull/151)).
  `--install-service --listen <addr>`, elevated, registers it with the SCM as `windbg-mcp`,
  auto-start, `LocalSystem`; `--uninstall-service` stops and removes it. That is what gives it
  `PATH`, boot start and a life independent of a login shell. Elevation is *not* among the reasons:
  Windows OpenSSH already hands an Administrators member a full token.

  - **The stop is the whole of the difficulty.** A service killed rather than asked leaves a
    detached-but-halted kernel frozen, so `listen::serve` grew a shutdown future for this one case —
    nothing else in this server needs one — and the SCM is told a preshutdown wait sized from what
    releasing every worker can actually take, refreshed at every start rather than left on the
    default.
  - **The token moves out of the environment**, because `launch` under `LocalSystem` would make a
    machine-scope variable a local privilege escalation. `install` writes it to
    `%ProgramData%\windbg-mcp\token`, ACL'd to SYSTEM and Administrators, and refuses to install
    from a user-writable directory unless `--allow-unprotected-path` says the machine is yours.
  - **`LocalSystem` does not read your `profiles.json`** — its `%USERPROFILE%` is the system
    profile — so kernel profiles have to be configured machine-wide or the service sees none.
    Verified rather than assumed, and `install` says so where an operator will read it.
  - A service has no console, so the role also writes to `%ProgramData%\windbg-mcp\service.log`.
    `server_log` is the better channel and is only reachable once the listener is up, which is
    exactly the case that file is for.

- **A long call says how it is going** ([#147](https://github.com/glslang/windbg-mcp/pull/147),
  `src/progress.rs`). A caller that puts a `progressToken` in a call's `_meta` gets
  `notifications/progress` while the call runs. The worker already emitted the milestones; what was
  missing was a route out to the client — and two decisions that are the difference between a
  progress bar and a liveness signal.

  - **Seconds elapsed, with no `total`.** A denominator would have to be a per-tool budget, and in
    an opener's case that budget does not even cover the 30s worker handshake before it starts.
  - **Ten seconds without a word is itself reported.** The milestones alone would have left the two
    longest silences exactly as they were: a parked kernel attach reports once in the first second
    and may never report again, and a pool walk or a `crash_triage` has no milestones at all.
    Incidentally this makes progress something a client can extend its own request timeout on.

  It matters most over `--listen`, where a quiet five-minute call and a dead link look identical
  from the other machine.

- **Per-client session namespaces, so two clients on one listener cannot reach each other's
  targets** ([#162](https://github.com/glslang/windbg-mcp/issues/162), slices 2 and 3). A listener
  may now hold several bearer tokens — `WINDBG_MCP_LISTEN_TOKEN_<NAME>` names a client, the unnamed
  variable names `local` — and a session belongs to whichever client opened it.

  - **Routing** is per client: a handle only routes for its owner, and omitting one finds that
    client's newest session.
  - **Another client's handle is reported unknown**, not "someone else's". The answer must not
    confirm a session the caller may not touch, and there is nothing they could do with the
    distinction.
  - **`session_status` lists only the caller's**, and the four-session **cap is per client**, so a
    busy client cannot deny a quiet one. A session is only ever reclaimed to make room for its own
    client — reclaiming another's is the precise harm a shared registry did.
  - **Closed-session history is per client too**, so a handle still answers after its target is gone
    however busy the rest of the server has been. A shared bound is a shared fate: one client's
    churn would age out another's record of a session that failed, and the answer that client then
    gets for a handle it is still holding is "unknown" — which reads as "never existed".
  - **`server_log`** shows the caller's sessions' records and the supervisor's own — one ring serves
    the whole server, so without this a client could read what another's worker printed. **Its
    counts are the caller's too**: how full the buffer is, where the cursor is now and what the
    oldest record is are all over that client's stream, since numbers about records nobody may read
    still report another client's activity.
  - **A lease expiry releases the sessions of the client whose lease ran out**, not every session.
    Before ownership those were the same set, because the gate served one client at a time.
  - **An `Mcp-Session-Id` another client holds is reported unknown**, and the check runs before the
    caller's own lease is consulted. The MCP service keeps one session table for the server, so on
    a legacy revision the id was the only thing between a client and another's MCP session — and a
    `DELETE` on it closed that session while the lease that minted it still held the id, leaving its
    owner failing every request and refused its own re-`initialize` for a grace period.
  - The rule for identity is **ambient inside a call, by name outside one**. A tool body reads the
    caller from the task-local, which is who is asking; the listener's own diagnostics run after
    that scope has closed and take the client as a parameter, so the one that reports an adoption on
    reconnect counts the reconnecting client's sessions rather than `local`'s.
  - **The tenancy itself became per client** — the gate serialised the server when the registry was
    global and one client could end another's targets, and keeping it shared would have meant one
    client's four-minute pool walk making every other client wait for a boundary the registry now
    provides properly. It has since been retired outright (see **Changed**, below): with sessions
    owned, the contention it had left to arbitrate was one credential racing itself, which inside a
    namespace is not a boundary at all. The `409` it answered with is gone; the one that remains is
    a request arriving while the sweeper releases this credential's own expired sessions.
  - Under **stdio** everything runs as `local`, so one set of registry rules serves both transports
    rather than one rule and an exception.
  - **Every credential variable is stripped from the processes this server creates** — by prefix,
    so a token added later cannot quietly reach a debuggee — and a configured token *file* shuts the
    environment out entirely, which is the precedence a LocalSystem service depends on. That file
    names its own clients (below), because a service reads nothing else.

  **Why authentication is the identity.** `2026-07-28` removed the protocol-level MCP session, so
  there is no session id to key on; requests arrive on whatever socket a client's pool hands them,
  so there is no connection either; `clientInfo` is not retained. The credential is what is left,
  and a name only the holder of a token can present is a boundary — where a name a client picks for
  itself would be a label. Configuring one token for two names is refused at startup rather than
  resolved, because the winner would be a hash-map ordering detail. Both refusals name the
  *variables* to change and never the token: they are printed to stderr, and under the service to a
  log file, so quoting the credential would leave a working one there.

  This separates clients; it does not rank them. Everyone who can authenticate still has the whole
  tool surface.

- **The token file can name more than one client, so a service-hosted listener can hold more than
  one.** A configured `WINDBG_MCP_LISTEN_TOKEN_FILE` is the *only* credential — deliberately, since
  the service installer ACLs it to SYSTEM and Administrators precisely because the machine
  environment is readable by unprivileged processes. The consequence was that the per-client work
  above could not be had in the deployment `docs/remote-listener.md` recommends: a foreground
  listener could hold `local`, `ci` and `laptop`; the service could hold one, so two agents on one
  host shared a namespace, and one of them going over the four-session cap could evict the other's
  target with nothing naming it.

  The file now takes either shape: a **bare token**, which names `local` and is what it has always
  held, or a **JSON object of client name to token** — the shape `WINDBG_MCP_PROFILES` already uses
  for kernel profiles. A leading `{` is what tells them apart, so a bare token may not begin with
  one; a file that does is refused at startup by name rather than read as the other thing. The ACL
  story is unchanged, since it is one file either way.

  `--install-service` copies **every** `WINDBG_MCP_LISTEN_TOKEN*` variable in the installing shell
  rather than the unnamed one alone, and writes the shape that fits — a bare token for a single
  `local`, the object otherwise — so an existing single-client install keeps a file nobody has to
  rewrite. It validates them the way the listener would, because the SCM registers a service once
  and a credential it refuses then fails it at every start.

  **Upgrading with a token that begins with `{`:** an install predating this wrote whatever the
  shell held, so such a file is now read as the JSON shape and the service refuses to start rather
  than authenticating. Write it as `{"local": "<that token>"}` — the refusal in the service log says
  so too — and it works exactly as it did. Any other token is unaffected. The rule is not softened
  to a fallback on purpose: reading a file whose JSON does not parse as one long token would turn a
  hand-written object with a typo in it into a credential that authenticates nobody and explains
  nothing, which is the likelier file by far.

  Its refusals name the file and the key and never a value, for the same reason the environment's
  name the variable: they are printed at startup, and under the service into a log file. A client
  name is now held to one rule wherever it was configured — a variable whose suffix is not a name is
  refused rather than skipped, since an install copies those names into the file — and a name
  written twice in the file is refused rather than collapsed to the last of them. One thing none of
  it can catch is an entry written back to front, since a token is a valid client name, so the
  documentation says which way round it goes.

- **`server_log` — the server's own log, readable from wherever the client is.** The supervisor
  keeps a bounded ring of the most recent records, its own and every engine worker's, and serves a
  caller its own share of them — the supervisor's, which name no session, plus those of the sessions
  that caller opened (under stdio, one client by construction, that is all of them): filterable by session and level, paged with a `since` cursor, answered without
  ever touching a session's engine — so it still answers while the session it is about is wedged,
  like `session_status`.

  This closes a regression the listener introduced. Under stdio the log needs no plumbing: a
  worker's stderr is inherited by the supervisor, the supervisor's is captured by the MCP client,
  and the whole stream lands in a file the operator already has. `--listen` moves the server to
  another machine and the stream stops there.

  - **Records cross the pipe as values.** A worker's `tracing` output is mirrored up the existing
    protocol channel (`WorkerMessage::Log`) and filed by the supervisor **tagged with the session
    id** — the one thing the worker itself cannot stamp them with, and the thing that makes two
    processes' interleaved records readable.
  - **Worker stderr is untouched.** The bridge is a second copy, not a redirection, so the stdio
    behaviour it exists to restore is preserved by not touching it — and the local operator's view
    on the server machine is unchanged.
  - **It cannot block the debugger.** The worker's queue is bounded and dropped when full, never
    blocked on: it is fed from the engine thread, inside DbgEng, where a log line must never wait
    on a pipe. Drops are counted and filed as a record of their own, because a gap in a log that
    reads as a quiet stretch is worse than no log at all.
  - **Not built on MCP's logging capability.** rmcp marks `notifications/message` and its whole
    API `#[deprecated]` for removal (SEP-2577), and this repo asserts that capability is not
    advertised. See [`DECISIONS.md`](./DECISIONS.md) for the trade — pull rather than push — and
    for what a tool reaches that stderr never did: the model holding the session.

  `WINDBG_MCP_LOG_BUFFER` sets how many records are kept (1000 by default). The ring is the same
  stream as stderr, so `RUST_LOG` widens both together.

- **A smoke tier for the listener's lease.** The lease is the only part of this server whose
  failures cost a *target* rather than a call, and it was the only part checked by hand. It is now
  driven over real HTTP against a listener on a loopback port, with a hand-written client — a
  library that normalised a `409` into an exception, or hid the `Mcp-Session-Id` header, would be
  asserting on the server's behalf.

  Four assertions need no debugger, because none of them needs a session to be open: the listener
  refuses to start without a token and says which variable is missing; an unauthenticated request is
  refused, told nothing about what is here, and **costs the server nothing** (the bearer check runs
  before the lease is touched); a credential's second MCP session is served alongside its first,
  while an id this server never issued is not; and going quiet is not leaving while a `DELETE` is. The fifth is in the debugger tier and waits
  out a real grace against a **parked kernel attach** — a session that exists, holds a worker, and
  cannot be interrupted, so releasing it means terminating a process. See
  [`docs/smoke-test.md`](./docs/smoke-test.md).

- **A token budget for the tool surface and for every result.** Two smoke tests measure what this
  server costs the model driving it — a cost nothing here had ever measured, and one a dependency
  bump or a widened schema can move without breaking a single assertion.

  `tool_surface_stays_within_its_token_budget` records a per-tool size table in
  `tests/golden/tool_budget.json` (re-recorded with the same `UPDATE_GOLDEN=1` as the shape golden
  beside it) and enforces three ceilings, because a golden re-recorded on every diff is a rubber
  stamp against slow growth. `tool_results_stay_within_their_budget` runs the debugger tier's dump
  through a fixed set of calls and budgets each answer, plus one rule: a typed answer may not
  exceed the rendering it replaces by more than 20x.

  The baseline it recorded is in [`docs/token-budget.md`](./docs/token-budget.md), along with two
  client behaviours it settled by measurement rather than assumption — `outputSchema` never reaches
  the model (it is ~80% of the `tools/list` payload), and `structuredContent` *replaces* the text
  block rather than accompanying it. The second qualifies `DECISIONS.md`'s "a second channel, not a
  replacement": true for a program reading fields, not for the model. What that costs today is
  itemised as follow-up 24.

- **An ARM64 kernel dump, so the debugger tier reads a *target* on both architectures.**
  [`docs/samples/121524-4703-01.dmp`](docs/samples/121524-4703-01.dmp) is a `0xFC
  ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY` off this project's own ARM64 debuggee — a user-mode
  process jumped into memory that is not executable — captured the way the two x64 samples were, a
  real crash on a real machine, and the smallest of the five that machine had at 440 KB.

  Three of the four tier assertions that read a target now open the sample paired with the
  architecture they are running on, rather than naming one file; the fourth is the driver crash,
  which stays with its own x64 dump on every architecture because what it asserts is a property of
  that crash. What that buys is an ARM64
  `_EPROCESS`, an ARM64 image's headers and an ARM64 stack's frames, read through claims that were
  previously asserted only against x64: the ARM64 CI entry proved the protocol, the session
  machinery and a module list, and nothing at all about reading a target
  ([#143](https://github.com/glslang/windbg-mcp/issues/143)). It also pins the branch of the
  process read nothing else reaches — this dump does not capture the page
  `SeAuditProcessCreationInfo` points at, so the answer comes from the 15-byte
  `_EPROCESS::ImageFileName` and is the truncated `stack_buffer_o`.

- **The gate those assertions used to carry was measuring the wrong thing, and is gone.** Four of
  them were `ignore`d on anything but `x86_64`, on the reading that an engine cannot follow a
  pointer into a dump of another architecture
  ([#142](https://github.com/glslang/windbg-mcp/issues/142)). It can: on an ARM64 host with the
  SDK's `dbghelp.dll` and `symsrv.dll` beside the binary, one engine reads both x64 samples
  completely — the `EPROCESS`, the disassembly, and the driver frame at its literal RVA — and the
  ARM64 sample too, for a 60-of-60 tier. What no engine can do is follow a pointer into a kernel
  dump without `nt`'s **symbols**: strip the symbol path from that same engine and the reads stop.
  System32 ships `dbghelp.dll` and **no** `symsrv.dll`, so a machine with nothing beside the binary
  downloads no PDB — and running *that* configuration by hand reproduces the ARM64 runner's
  reported failure down to the address and the `0x8007001E`, which is the evidence for what state
  it is in.

  So they ask the host instead, each for the premise it has: `walk_memory` and the batch work on
  numeric addresses and need only that `nt`'s base reads, asked with a `dq` through `execute`
  rather than through the tools under test, so that a regression in `walk_memory` cannot silence
  the test that exists to catch it; `crash_triage` and the driver attribution walk `nt`'s *types*,
  so those two also require it to have resolved a PDB. Either way the test prints `SKIPPED` with
  the reason and what still holds.

  The two conditions are separate because they fail apart, which this branch's own CI proved twice
  over. A version that asked only for the read let the driver-crash test through on a runner that
  reads a module base and resolves nothing, where it walked a stack made of the bug check's own
  parameters and failed an attribution assertion for an environmental reason. Asking both of all
  four would stand `walk_memory` and the batch down where they are perfectly testable. And the
  worry that a symbol condition silences assertions passing today is settled rather than assumed:
  the x64 entry reads `mm_exploit_v5.exe` out of `SeAuditProcessCreationInfo`, which is a walk
  through `nt`'s types, and its run shows all four running rather than skipping.

### Fixed

- **The pool's heaviest tag could not be queried, and asking for it answered about a different
  one.** `pool_census` and `pool_chunk` named a tag only by how it *prints*, and that rendering
  maps every unprintable byte to `.` — and a literal `.` to the same thing. So a tag with a
  binary byte came back as `....`, several distinct tags shared that one rendering in the same
  table, and handing it back to `pool_find_tag` was not an error: `....` is four valid ASCII
  bytes, so the query silently asked about a tag nobody had allocated and reported no matches.
  A tag with a byte outside ASCII could not be named at all.

  This is not a corner case. On a live kernel the two heaviest tags by bytes are routinely binary
  — on the bench this was found on, ~66 MB and ~15 MB, both rendering `....` — so the single
  largest pool consumer was the one thing the tool could not be asked about.

  Every census entry and chunk now carries **`raw_tag`** beside the printed form: `0x` and the
  four bytes as hex, in memory order, so it reads in the same direction as the rendering
  (`Tgsm` is `0x5467736d`). `pool_find_tag` accepts either form — the two cannot collide, since
  the raw form is exactly 10 characters and a printed tag is at most 4, so `0x2e` still means the
  four-byte tag it always did. The tables print the raw form wherever the rendering is ambiguous,
  and querying a rendering now says what it really searched for instead of just finding nothing.

  Found by the live-kernel smoke tier, which had been standing down on exactly this — its
  census/`find_tag` cross-check skipped itself whenever the heaviest tag was binary, which on a
  real target was most of the time. It now runs.

- **Two clients on one listener shared a namespace after all**
  ([#162](https://github.com/glslang/windbg-mcp/issues/162), found while closing `FOLLOWUPS.md`
  item 29). Ownership was decided correctly everywhere it is decided — and the identity it was
  decided from never reached a tool call. `listen::gate` scopes the caller around
  `mcp.handle(req)`, which is the HTTP task; rmcp serves a legacy MCP session from a task it spawns
  at `initialize`, and a task-local does not cross a spawn. So every call ran as the default
  `local`: both clients' sessions were owned by `local`, both clients saw both, and either could
  route to or end the other's — the precise harm per-client namespaces were built to stop, in the
  transport they were built for.

  Nothing in the suite could see it. Every rule is unit-tested where it is decided, and those tests
  set the identity themselves; the smoke tier ran one client, for whom `local` is the right answer.
  It took two credentials on one port with a session each.

  The service instance now **carries** its client — captured in the listener's service factory,
  which does run inside the gate's scope, and re-entered in `call_tool`, the one place every tool
  passes. Stdio is unaffected: it has one client and no way to authenticate a second.

- **A listener client on `2026-07-28` can use more than one request at a time**
  ([#168](https://github.com/glslang/windbg-mcp/issues/168)). [SEP-2567] removed the MCP session id
  from the revision current clients negotiate, and the listener's tenancy gate read the absence of
  that id as "a client opening a session" — the one moment it reserves the server. On a revision
  where the id never comes, that made *every* request a reservation: two that overlapped got a
  `409`, and `server_log` while a pool walk ran — the workflow this server documents for a wedged
  session — was exactly that overlap.

  At its sharpest it cost the recovery path: a kernel attach whose target never dials in parks by
  design, and a parked call held its reservation for as long as it parked, so the client could
  reach neither `session_status` nor `end_session`. For that revision, a going-nowhere attach was
  once again a reason to restart the server — the property
  [#61](https://github.com/glslang/windbg-mcp/issues/61) established, quietly lost to a revision
  rather than to a change.

  The fix was for the gate to distinguish the two kinds of nothing: a request on a revision that
  mints no session can never become the holder a reservation arbitrates, so it reserved nothing and
  was served alongside its client's other work. The gate has since been retired altogether (see
  **Changed**), which deletes that classification rather than refining it — a request now presents a
  session id or nothing, and the revision does not enter into it. The one refusal such a client still
  meets is a teardown of its own credential's expired sessions, told to ask again once the release is
  done, which was always the sweep's rule and not the gate's.

  Two lease bugs on the same path came out of review and are fixed here too, both of which end with
  a client losing sessions it was using. A stateless request now **renews** a lease its credential
  already has, since the sweep reads the deadline alone — a credential holding a legacy session and
  since sending stateless requests would otherwise have had those sessions released while it was
  working; that rule outlived the gate, and is now simply what every admitted request does. And a
  reservation that minted no session gave its **deadline** back along with its claim: a `2026-07-28`
  `initialize` may omit the `MCP-Protocol-Version` header, so it was classified as an opener,
  reserved, and took nothing — leaving a clock running against a tenancy that held nothing, which one
  grace later released whatever that client had since opened. With reserving gone, nothing arms a
  deadline before an MCP session exists, so there is no longer a clock to hand back.

  The same issue reported that the listener answered a `2026-07-28` handshake and then `400`d the
  request after it. **It does not** — that was measured with a hand-rolled probe that sent the body
  and none of the transport contract the revision adds, and the `400`s were the server enforcing
  the spec. A request on this revision carries three things: the `MCP-Protocol-Version` header,
  `params._meta` with `io.modelcontextprotocol/protocolVersion` and `…/clientCapabilities`
  ([SEP-2567] moved them there when it removed the session that used to hold them), and SEP-2243's
  `Mcp-Method` header naming the body's method. The smoke tier now drives the revision properly and
  asserts both halves: a handshake and the calls after it are served, and each under-specified
  shape is refused with a body naming the part that is missing.

[SEP-2567]: https://modelcontextprotocol.io/seps/2567-sessionless-mcp

### Changed

- **The listener's single-tenancy gate is retired; the lease is now a clock and nothing else**
  ([#162](https://github.com/glslang/windbg-mcp/issues/162) slice 3b, `FOLLOWUPS.md` item 28). A
  credential may open a second MCP session, and two of its requests never wait on each other. The
  `409` that refused one is gone.

  The gate was the boundary between two clients when the registry was one map for the whole server —
  handles minted from it, the four-session cap shared, `end_session` ending whatever it was handed.
  Ownership took that job over in the slices above, and what the gate had left to arbitrate was one
  credential racing *itself*: a fresh `initialize` while it held one, or a request bearing an id that
  was not the one it held. Inside a namespace neither is a boundary — both MCP sessions reach the
  same debug sessions, because they are the same client — so what the refusal cost was a client's own
  concurrency, and what it bought was nothing.

  - **The clock stays, and it is the whole of what the lease was kept for.** Any request renews it;
    when it runs out, that client's sessions are released exactly as a disconnect would have released
    them, its MCP sessions are closed in the service, and its requests are refused until the release
    is done. Idle release (`WINDBG_MCP_SESSION_IDLE_SECS`) does **not** subsume it: it spares a
    session with a call outstanding, which is precisely the parked `attach_kernel` a vanished client
    leaves behind, and it knows nothing about MCP sessions.
  - **The lease is still armed by an MCP session, so a `2026-07-28` client still has no clock** —
    deliberately, now that it could have one. A lease releases everything that credential holds,
    busy or not, on the reasoning that a client silent for a grace has gone; a stateless client is
    legitimately silent for far longer, and releasing a live kernel from under a caller who is
    thinking is worse than holding an abandoned one for the idle window.
  - **A credential's MCP sessions are recorded as a set**, not as one holder. An id recorded for
    nobody is one any credential may present, so tracking only the newest would have handed a client
    another's older id the moment that client opened a second — the harm the ownership check exists
    to stop, arriving through the removal of the refusal in front of it.
  - **Two refusals remain, and neither was ever tenancy.** An `Mcp-Session-Id` another client holds
    is reported *unknown* (`404`); a request arriving while its own credential's expired sessions are
    still being released is told to ask again (`409`) — the sweep's refusal, and now the only `409`
    this server has.
  - **What went with the gate:** the reservation and its generation counter, the in-flight count and
    its epoch, the handover that waited on `Sessions::busy` (and `Sessions::busy` itself), the
    `Stale` settlement that had to close a session minted by a claim that had expired, and every
    read of `MCP-Protocol-Version`. A request now presents a session id or nothing, and the revision
    does not enter into it — so the classification behind
    [#168](https://github.com/glslang/windbg-mcp/issues/168) is deleted rather than fixed, and the
    trap beside it (a reservation that minted nothing having to hand its deadline back) is
    unreachable rather than handled: only a settled MCP session arms a deadline.
  - **The one lease rule that survives is the one that loses sessions if forgotten.** An *admitted*
    request renews an existing deadline and creates none. A refused one renews nothing, or a stream
    of wrong session ids would hold an abandoned client's live kernel open for ever. What keeps the
    sweep from releasing a session mid-call is the startup floor that was always there: a grace
    longer than the longest a call can keep a client quiet means no request of that credential's can
    still be in flight when its lease expires — which is what the epochs and claim generations were
    protecting one layer above.

- **The last progress milestone is no longer dropped when it races the answer**
  ([#163](https://github.com/glslang/windbg-mcp/issues/163)). A client watching a long call would
  intermittently miss the milestone it most wants — "the target is open", "the rollback finished" —
  because that is the one arriving beside the result.

  `relay` takes a step out of the channel and then sends it. If the send was not ready on its first
  poll, which is ordinary for a write to a peer, and the answer was ready beside it, the loop broke
  and **that message was gone**: the flush at the end re-sends what is still queued, and this one had
  already been taken. It now finishes the send on the same bounded terms the flush uses, so a client
  that has stopped reading still loses the courtesy after a second — it just no longer loses it to a
  scheduling coin toss.

  The result was never affected; it always carried the truth. What was affected is a client that
  watches progress and sees a long unwind stop at "rolling it back (up to 2m03s)" with no closing
  word.

  It surfaced as roughly one debugger-tier run in five failing on one of two tests, which is what
  made it worth chasing: every test in `src/progress.rs` used a notification that completes on its
  first poll, so the losing arm was unreachable and the bug lived entirely in the gap between the
  test double and a real write.

- **A session nobody is using is released, whatever the transport did.** The lease answers "has this
  *client* gone away" by identifying it from `Mcp-Session-Id` — and `2026-07-28` removed the protocol-level
  MCP session (SEP-2567), so on the revision most clients now negotiate no holder is ever installed and
  no lease ever expires. A client that vanished left its targets held until the process exited,
  which for a live kernel is a machine owned by nobody
  ([#162](https://github.com/glslang/windbg-mcp/issues/162)).

  The listener now also releases any session that has gone unused for **30 minutes** (
  `WINDBG_MCP_SESSION_IDLE_SECS`, `0` disables), through the same orderly `EndSession` an explicit
  `end_session` uses. It needs no notion of a client, which is the point: it is the half of the
  lease's job that survives a protocol with no sessions in it.

  - **Far longer than the lease grace, deliberately.** A lease is renewed by any request; this is
    per session, and twenty minutes of reading a stack before the next question is ordinary work.
  - **A session with a call outstanding is never idle**, however old the call — which is exactly an
    `attach_kernel` parked in `WaitForEvent(INFINITE)` waiting for its target to dial in, the one
    session that must never be released. Nor is an opener that has not yet handed back its handle.
  - The floor is the same one the lease refuses to start below: longer than a single call can run,
    or a session is released underneath its own caller.

  This is the first of the slices in #162. It does not make two clients safe from each other — that
  needs a client identity, which a stateless protocol only gets from authentication — but it stops
  the leak that has no workaround today.

- **The server instructions now fit what the client reads.** They were 3,147 characters against a
  measured 2,048-character limit, so 1,099 were paid for on every connection and discarded — and
  what fell off the end was the `debug_batch` paragraph, the one instruction there that stops a
  mutation being left half-applied. Rewritten to 1,990 characters with that guidance inside the
  budget, kept ASCII so the character and byte counts cannot diverge, and asserted in the protocol
  tier so it cannot grow back unnoticed.

- **One wording for `session_id`, on every tool that takes one.** It was documented three different
  ways across 26 tools and not at all on five (`heap_list`, `heap_allocations`, `heap_chunk`,
  `heap_census`, `heap_diagnostics`), where a caller had no way to know what to pass.
  `server_log`'s keeps its own wording, because there the field filters records rather than routing
  a call — a different question that deserves a different sentence.

  The wording also now says what the field *does*. All three originals described only the staleness
  guard — "pass it to refuse the call if the target has been replaced" — which is the consequence,
  not the behaviour: the field is a **router**, and omitting it sends the call to the current
  session, which with several open is not necessarily the one you were last using. That makes this
  half close to byte-neutral, and the instructions are where the surface actually moves: 67,613 B to
  **67,076 B** model-visible, plus 1,167 B of instruction text that was being sent and discarded. That is smaller
  than [`FOLLOWUPS.md`](./FOLLOWUPS.md) item 24 predicted for the `session_id` half, and the reason
  is worth recording: the 9,514 B that bullet claimed had counted the copies inside `outputSchema`,
  which the same document establishes no model reads. The real model-visible figure was 4,695 B.
  Both the item and [`docs/token-budget.md`](./docs/token-budget.md) are corrected, and the doc
  gains the finding that measurement actually supports — five tools carry a third of the surface,
  in their *input* schemas, `debug_batch` alone being 15% of it. The `session_id` wording also gained
  back what an earlier draft of it dropped: a handle is refused when the target was **replaced** by a
  raw command, not only when the session closed, and the README explains the asymmetry that makes
  that guarantee worth having — a retired session refuses its handle while still answering a call
  that names none.

- **`modules` reports which PDB the engine has for a module** — `guid`, `age`, and the `key` those
  two make, which is the middle element of a symbol server's `<pdb>/<key>/<pdb>` path. It completes
  the coordinate work: the image was already identified by `timestamp` + `size`, and its *symbols*
  are identified by a different pair that nothing reported.

  - **`key` is carried already-built** rather than left to the caller, because the age goes in
    **hex** and getting it wrong produces a URL that 404s — a hard failure to read backwards.
  - **Absent for a module whose symbols are `deferred`**, which on a freshly opened dump is nearly
    all of them. This reports the PDB the engine *has*, not one it could find; that is not the same
    as "this module has no PDB", and the `symbols` state beside it says which.
  - **`unmatched`** says the engine loaded a PDB that does not belong to the image, which makes
    every symbol on that module another build's names. Absent when false.
  - It saves a download rather than enabling something otherwise impossible — the same identity is
    in the image's own debug directory, and [`docs/coordinates.md`](./docs/coordinates.md) walks
    the whole chain, including the part where an 11 MB image is selected out of a symbol server by
    two integers.

- **`disassemble` answers with typed instructions carrying `RVA` and encoding, not just `u`'s
  text.** The second half of the same coordinate work, and the last tool that could only answer
  "what is the code here" as a rendering. Each instruction is now
  `{address, module, rva, bytes, text}`, on the same terms a stack frame is: `module` and `rva`
  travel together and are absent when the address is in no loaded module, `attribution_failed`
  marks the different case of a lookup that failed, and `address` and `bytes` are always there.

  - **The addresses are the engine's arithmetic, not a re-parse.** The new
    `win-kexp` primitive (`DebugEngine::disassemble`) walks `IDebugControl::Disassemble`, whose
    every instruction reports where the next one starts; reading an address back out of the
    rendering would make the record depend on the format it exists to replace.
  - **`bytes` is what identifies a build.** Two images that disassemble differently are different
    builds whatever their names say — the "stale image in the analyser" risk, checkable now without
    trusting a file name. It is the engine's spelling (`d503237f` on ARM64 is the instruction word,
    not memory order), so it compares against another disassembly rather than against a file.
  - **`stopped_early` is the code ending, not the call being cut.** Disassembly runs forward into
    whatever follows a function, which may be unmapped or not code; asking again with a larger
    count returns the same instructions. A count the caller set is not that, and does not set it.
  - **The debugger's backtick address form is normalised out of operands** — ``fffff801`3c677ef0``
    becomes `fffff8013c677ef0` — because this server spells an address one way, and that tick is
    also the delimiter of the code span the listing prints in. Only where it is an address: MSVC
    decorates real symbols with backticks (`` `anonymous namespace' ``, `` `vftable' ``) and those
    survive.
  - Default 16 instructions, maximum 128. `execute { "command": "uf module!func" }` still follows a
    whole function, which is the one shape a count cannot ask for, and `execute { "command": "u" }`
    is the engine's listing with its `module!Symbol+0x1c:` labels.

- **`backtrace` answers with typed frames carrying `module` + `RVA`, not just `k`'s text.** The
  tool ran `k` and handed back whatever DbgEng printed, which names a frame as
  `module!Symbol+0x1c` — a form that is unusable the moment the symbol does not resolve, and on a
  driver with no PDB it never does. A frame now carries the offset into its image as well,
  computed from the load base the engine reports, which is the half that survives an unsymbolised
  driver and stays comparable across reboots — and across machines, for **the same image and
  build**, which is what an RVA is relative to. That is what lets a frame be joined to a function
  in a disassembler without either side knowing the other exists.

  Neither half is promised: `module` and `rva` travel together and are absent when the engine
  places the address in no loaded module — a freed pool page, an unloaded driver, a corrupted
  return address, which is what a driver bug tends to leave behind — and `symbol` is absent
  whenever nothing resolves. `address` is the only field always there. A frame whose module
  **lookup failed** now says so (`attribution_failed`), because that is the opposite kind of
  evidence from being in no module and the two were indistinguishable on the wire: the walk has
  always kept the three states apart internally, since picking a faulting frame needs them, and
  the distinction stopped at the serializer. It reaches `crash_triage`'s frames too, they being the
  same records. Confirming the image a
  frame's RVA is against is the *other* half of this phase (`TimeDateStamp`/`SizeOfImage` are on
  `ModuleInfo` already; the PDB GUID and age are not yet), and until it lands the join is on the
  caller to make against a build they know.

  - **The same records as `crash_triage`, from the same walk.** Both tools go through one helper
    (`worker::walk_attributed`) and render through one function (`triage::describe`), so a
    coordinate carried between them names the same place by construction rather than by
    inspection. The debugger tier asserts it from outside: the two stacks are compared field by
    field.
  - **A cap, which `k` did not have** — 32 frames by default, 256 at most, with `frames_truncated`
    saying when the stack went on. The frames are values now, and an uncapped typed answer is an
    uncapped bill for whoever reads it; the flag is what keeps the cap from being read as a short
    stack. `crash_triage`'s own cap comment points here for the deep stack, which is why this one
    is twice as deep.
  - **The listing is rendered from those same values**, as `modules` is
    ([#120](https://github.com/glslang/windbg-mcp/issues/120)), so the text and the records cannot
    disagree. The cost is stated rather than hidden: this is not `k`'s output — it has no
    `Child-SP`/`RetAddr` columns and no `[Inline Frame]` rows, since a stack walk does not return
    them — and `execute { "command": "k" }` is that listing verbatim for anyone who wants it.
  - Under the client behaviour measured in [`docs/token-budget.md`](./docs/token-budget.md),
    `structuredContent` **replaces** the text block rather than accompanying it, so a model driving
    this tool now reads the frames and not the listing. That is the point — the coordinate is in
    the frames — but it is the same trade `FOLLOWUPS.md` item 24 records for every other typed
    tool, and the result budget moved with it.

- The listener no longer claims a reconnecting client **adopted sessions** when there were none to
  adopt. The flag behind that line says a previous tenancy ended inside the grace, which is true
  whether or not that client had opened anything — so an ordinary reconnect logged an adoption that
  had not happened. It now says how many sessions were inherited, or that nothing was open.

- **Opt-in session transcripts, and an asciicast renderer for them**
  ([#87](https://github.com/glslang/windbg-mcp/issues/87)). Point `WINDBG_MCP_TRANSCRIPT` at a path
  and the supervisor records what it was asked and what it did, one JSON object per line: the tool
  call and its result; a session opening, changing state and being released; a wait abandoned, an
  `interrupt`, a worker process dying; and — derived from each result's *typed* half — where
  execution stopped, what a `run_to_address` concluded, every breakpoint or memory mutation, each
  assertion that did not hold, and how a `debug_batch` ended with whether its rollback completed.
  Unset, which is the default, nothing is written.

  What existed before had opposite problems. A client's own log is tens of megabytes of prompts
  with the debugger operations buried inside shell-command source; the curated proof records under
  `examples/` are readable and are written afterwards from memory — one of them says so on its
  face, captioning its own timing as *"illustrative because live recording was not enabled for the
  original run"*. The server is the only party that sees the whole of a session, and it was
  recording none of it.

  - **Written by the supervisor, from values.** One writer, so no locking and no interleaving
    between processes — and a worker's facts still arrive as facts, because they cross the pipe as
    the typed half of its reply and are read back through [`structured`](./src/structured.rs)
    types. Nothing in a transcript is scraped out of a rendering, which is the rule
    [#77](https://github.com/glslang/windbg-mcp/issues/77) was fixed by. A tool this server cannot
    type — an arbitrary `execute` — contributes its call and its result and no derived event, which
    is the honest answer rather than a guess about what the command did.
  - **Redacted, and by the same rule as everywhere else.** `kdconn` grew a scan for arbitrary text
    beside its connection parser, sharing the one list of secret parameter names, so a raw
    `connection` passed to `attach_kernel` is recorded as `key=<redacted>`; an argument member
    *named* like a secret is masked whole, before any tool has one. Profiles still keep the key out
    of the request in the first place — this is the backstop for the caller who passed a raw string
    anyway.
  - **Bounded, and it says so.** Fields are capped (`WINDBG_MCP_TRANSCRIPT_MAX_FIELD`, 16 KiB by
    default) and a record reports how much it dropped. A transcript that quietly truncated would
    read as complete, which is worse than not having one.
  - **Never the transport.** Standard output stays JSON-RPC: the transcript is a file this module
    opens, and a test reads the source to keep it that way.
  - **`windbg-mcp --render-cast <transcript.jsonl>`** renders one as an [asciicast v2] recording —
    each call as a prompt line, its output beneath, and the derived facts marked between them. It
    is derived offline from the same JSONL, so a cast can be made from a transcript recorded weeks
    ago and its timings are the recorded ones, measured on a monotonic clock. `--idle-limit`,
    `--max-lines`, `--title`, `--width`/`--height` shape it.

  Retention is the operator's: nothing but secrets is masked, and debugger output is the contents of
  somebody's memory. The README says what to do with one.

  [asciicast v2]: https://docs.asciinema.org/manual/asciicast/v2/

- **`debug_batch` answers with its report as values**, not only as prose — the last tool whose
  whole answer was a rendering, and the one with the most at stake in being readable by a program.
  `outcome`, the position it stopped `at`, `committed`, `rollback_complete`, what the session holds
  `after`, and every step of both blocks with what it changed and whether an assertion was `unmet`.
  It is built in the worker from the executor's own `BatchReport`, which is what lets a transcript
  record a transaction's verdict as a fact.

  **Visible change for existing clients**: `debug_batch` now declares an `outputSchema` and returns
  `structuredContent`. The text is unchanged and so is `isError` — a batch that did not commit is
  still a tool error carrying the whole report. Note the pairing this tool alone has: a batch that
  *ran* answers `status: "ok"` (the report is the answer) on a result flagged `isError`, while
  `status: "error"` means the batch never ran. Reading only `isError` cannot tell those apart.

## [0.9.0] - 2026-08-14

### Changed

- **`modules` renders its listing from its own values, and no longer runs `lm`**
  ([#120](https://github.com/glslang/windbg-mcp/issues/120)). It was the one tool whose text was
  the *debugger's* rendering rather than a rendering of its own records: the text came from
  `lm` / `lm m <pattern>` inside DbgEng and the values from `IDebugSymbols3` records matched in
  this process, so one answer had two independent implementations of one filter. They disagreed in
  five measured ways — character sets (`lm m nt[fd]*` prints `Ntfs`; matched literally, nothing),
  the `\` escape (`lm m n\t*` prints `nt`, `Ntfs`, `ntosext`), whitespace (`lm m nt v` matches `nt`
  and prints lm's *verbose* listing, a different command rather than a different filter), case
  folding, and the unloaded tail `lm` appends to a filtered listing — and four of them were being
  held shut by **refusing input**, which is a strange thing to have to tell a caller about a
  listing tool.

  The enumeration was already there (win-kexp's `modules()` and `unloaded_modules()`); only the
  command had to go. The listing is now printed from those records, one table for the loaded
  modules and one for the unloaded ones, each with the symbol state as a column of its own
  (`deferred` is still not `none`) and addresses in this server's one representation — so `lm`'s
  backtick form (``fffff803`89200000``) is gone from this tool's output. `execute { "command":
  "lm" }` runs the engine's own listing verbatim for anyone who wants it.

  Consequences worth having:

  - **The filter is matched exactly once**, so its syntax is this server's to define rather than
    something that has to track DbgEng's: a name plus `*` (any run of characters) and `?` (exactly
    one), **every other character literal**. The three refusals that existed only to keep the two
    matchers in step are gone — `nt[fd]*`, `n\t*`, `nt v`, `nté` and `nt; .detach` are now patterns
    that match whatever is actually named that, which on a real target is nothing, answered as an
    empty listing rather than as an error. (The `;` refusal went with them: the filter reaches no
    command any more. The one refusal left is an *empty* filter, which is a caller who meant to
    narrow and sent nothing to narrow by.) Case now folds beyond ASCII too, since there is no
    second fold to stay in step with.
  - **Nothing from outside can add a line to the listing.** The listing is line-oriented and its
    rows begin with an address, so a string carrying a line break prints as two lines — and the
    second can be shaped exactly like a row, putting a module in the text that the values beside it
    do not have, which is the one property this change is for. Both strings that come from outside
    this server are escaped rather than acted on: the caller's `filter`, quoted into the note (until
    now it was command text, and the `;` check refused line breaks along with the separator — the
    command went, and that refusal with it), and the **module and image names**, which are the
    target's to choose. Windows file names exclude the characters below `0x20` and nothing else, so
    a driver may legally be named with a `U+2028`, and a server pointed at malware on purpose is the
    last place to assume none is.

    Escaped, not refused: "nothing matches this" is a good answer to a pattern nothing is named, and
    a module named something hostile still has to be listable — its row is still its row, and the
    name column is measured on what is printed so it still lines up. The guard is Unicode's whole
    line-break set rather than `char::is_control` (`U+2028`/`U+2029` are `Zl`/`Zp`, not `Cc`, break
    a line in a renderer that knows Unicode, and are invisible to `str::lines` — so to a test
    written around it), the other control characters (an ANSI escape is a thing a terminal acts on),
    and the backtick, which is the delimiter the note quotes with: a pattern containing one closes
    the code span, handing what follows to a Markdown-rendering client as markup.
  - **Case-insensitive means both directions.** The filter compares Unicode's simple case mappings
    per character, upward as well as down: `Σ` lowercases to `σ` while final sigma `ς` lowercases
    to itself, so lowercasing alone would have missed a name spelled with `ς` — case-insensitive
    right up until the first name that needed it. It is not full case folding (no dependency for
    that), and where the two differ it errs toward matching, which for a listing filter is the
    right direction: a caller sees a row that names itself rather than missing one.
  - **The unloaded half is rendered the same way**, from `unloaded[]`, under its own heading that
    says what its addresses mean — where an image *was* — instead of a note explaining the
    relationship between the values and a tail `lm` had printed.
  - The smoke tier's claim gets stronger with them: it parses the listing's rows back as records
    and asserts they are **exactly** the values, row for row, rather than "every value appears
    somewhere in the text" — which could never have caught a row the text had and the values did
    not, the direction every one of those five divergences ran in.

  **Visible change for existing clients**: the listing text has a different shape (it is within
  contract — the module docs have always said the text is a rendering that exists to be reworded,
  and `tools_list`'s golden records input schemas only — but it is a change a client reading the
  prose will see). The `symbols` **value** is unchanged. One thing deliberately not carried over:
  `lm`'s symbol-*file* column (the loaded PDB's path), which is not in the typed record;
  `execute { "command": "lmv m <module>" }` and `!lmi` still print it.

- **An opener summarises its target instead of printing the module table**
  ([#105](https://github.com/glslang/windbg-mcp/issues/105)). `open_dump` answered with `lm` —
  the whole inventory, ~230 lines on a kernel dump, unprompted — when what a caller reads off an
  open is three things: which build, where the target's own image is, and (for a crash dump)
  which bug check. Triaging five minidumps in one session meant paying for that table five times
  to answer them.

  Every opener now returns those facts instead, as text and as a typed `summary`:
  `kernel_mode`, `modules_loaded`, the `primary_module` (the kernel on a kernel target, the
  process's own image otherwise — a base to compute `module+RVA` against), and the `bug_check`
  the target stopped on, read from the engine's `ReadBugCheckData` and rendered by the same code
  `crash_triage` uses, so the two spell one value one way. `open_dump`'s own diagnostic is
  `vertarget` rather than `lm`; the kernel openers already ran it.

  The inventory itself is unchanged and one call away — `modules`, which is where it belongs, and
  which the report names. Every summary field is best-effort and independently optional: the
  target is open by the time they are read, and a field that could not be read costs its own
  field rather than a session that exists. That also makes the summary honest about the case in
  [#85](https://github.com/glslang/windbg-mcp/issues/85), where a fresh kernel attach has nothing
  but `nt` in the engine's inventory yet — it says one module, rather than implying a complete
  list.

- **An allocator answer says what decoded it, and sizes what a partial walk missed**
  ([#121](https://github.com/glslang/windbg-mcp/pull/121),
  [#126](https://github.com/glslang/windbg-mcp/pull/126),
  [win-kexp#102](https://github.com/glslang/win-kexp/pull/102),
  [win-kexp#103](https://github.com/glslang/win-kexp/issues/103)). Every `pool_*` answer — and every
  `heap_*` answer added below — now carries `layout`: the image the decoder read, its PDB, a
  fingerprint, and the validated structural family. A walk is only as trustworthy as the types
  behind it, and until now the answer named none of them.

  Beside it, `walk.gaps` turns `coverage: partial` into a quantity. `partial` said a walk did not
  cover the allocator; it could not say by how much, and `pool_diagnostics` could not either — it
  collapses messages by shape, so the count beside a category counts occurrences of that shape, not
  bytes and not chunks. One unreadable page and a third of the pool read identically. The five
  figures are `stalled_pages` (pages a valid-region query could not advance over), `skipped_bytes`
  (what those steps wrote off), `recovered_bytes` (committed memory read *past* them in the same
  regions — the number the walker's stall handling is judged by, and meaningless except next to
  `skipped_bytes`, which is why they travel together rather than as one "how bad was it" score),
  `refused_chunks`, and `unplaced_bytes`.

  The last two are a pair, and both had to be reported for either to be honest. `refused_chunks`
  counts headers a decoder refused and resynchronised past — the first live 26100 walk to report it
  returned 106,516 refusals across 542 extents, which is not a population of 106,516 bad chunks: a
  refusal resynchronises sixteen bytes along and tries again, so one lost sync bills a refusal per
  sixteen bytes until it recovers, about 3 KB of brute-force scanning per affected extent. It sizes
  the disruption, and how far to discount the chunks reported from those extents.
  `unplaced_bytes` is its counterpart: committed bytes of a variable-size subsegment the walk
  declined to decode at all because it could not say where a chunk began in them. A walk that stops
  guessing has to report what stopping cost, or a clean refusal count reads as a walk that saw
  everything.

  `gaps` is **absent** when a walk met none of it, which is the ordinary case — five zeroes on every
  healthy answer are noise on the answers that are fine.

### Added

- **User Segment Heap walking, as five typed tools**: `heap_list`, `heap_allocations`, `heap_chunk`,
  `heap_census` and `heap_diagnostics` ([#122](https://github.com/glslang/windbg-mcp/pull/122),
  [win-kexp#105](https://github.com/glslang/win-kexp/pull/105)). 0.7.0 gave the kernel pool a
  decoder that answers in values; a *user* heap was still `!heap` text to scrape. These are the same
  decoder pointed at the other allocator, and they ride the same worker path the `pool_*` tools do —
  queue budgeting, the caller's deadline, `interrupt`, partial coverage and the per-session snapshot
  all behave as they do there.

  The roots come from the current process's PEB, resolved through `ntdll`'s own PDB types
  (`NumberOfHeaps`, `ProcessHeaps`) rather than an offset table. `heap_list` reports every one of
  them and, more usefully, says which it did *not* walk and why: Segment Heaps walked, classic NT
  heaps listed and skipped, roots whose signature was unrecognised, roots whose signature could not
  be read. Then `heap_allocations` filters chunks by heap, backend (`lfh`, `vs`, `segment`, `large`),
  state and capacity; `heap_chunk` names the allocation containing an address, the offset into it,
  and its contiguous neighbours in the same heap, backend and subsegment; `heap_census` groups the
  heaviest heap/backend/state/size-class combinations; and `heap_diagnostics` filters the walk's own
  diagnostic categories and kept examples, optionally scoped to one heap root.

  What the answers carry beyond the chunks is the point of having them typed:

  - **`layout` says what decoded this** — the exact loaded image, its PDB, a fingerprint, and the
    structurally validated VS family (`inline_vs` or `affinity_slot_vs`). That last field is why
    these are described as version-aware: the variable-size metadata moved *out* of
    `_HEAP_VS_CONTEXT` in current builds, so a decoder keyed to a build number is correct until the
    build it was not tried on, and reports plausible chunks rather than failing. The family is
    chosen by validating the structure the PDB describes, and an ambiguous or unfamiliar one is
    refused rather than guessed at.
  - **`capacity` is allocator-backed; `requested_size` is not always there.** Capacity is what the
    allocation occupies. The size originally asked for is reported only when the selected schema
    validates the exact unused-byte metadata — its absence means *unknown*, and specifically not
    "equal to capacity".
  - **`scope` and `walk`** say which roots were in the answer and how much of them was covered, on
    the same `complete`/`deadline_truncated`/`partial` terms as a pool answer. An address the walk
    never reached is not an address that was freed.
  - **`state` defaults to `allocated`**, so a question about freed memory has to ask for
    `reusable_free` or `cached_free` by name — the alternative is a caller reasoning about
    use-after-free from a listing that quietly omitted the frees.

  V1 covers x64 Segment Heaps in a stopped live target or a dump with the memory to walk. Classic NT
  heaps, WOW64 and ARM64 are out of scope and say so; `execute { "command": "!heap ..." }` remains
  the answer for a classic heap, and is what `heap_list` points at. The agent-facing workflow is
  [`skills/windbg-debugging/heap-walking.md`](skills/windbg-debugging/heap-walking.md).

- **`modules` takes a `filter`**, so "where is that driver loaded?" costs one row rather than the
  whole table ([#105](https://github.com/glslang/windbg-mcp/issues/105)). A plain name matches
  anywhere in a module name — `{"filter": "MessageManager"}` — and `*` (any run of characters) and
  `?` (exactly one) are there for the caller who means to anchor: `nt*` is the names beginning with
  `nt`, `nt` is the names containing it. Every other character is literal. The answer still carries
  `loaded`, the size of the whole inventory, and echoes the `filter` as applied rather than as
  typed.

  A filter that matches nothing is an answer rather than an error, and says so in words — a listing
  with no rows in it otherwise reads as a target with no modules — naming the mistake callers
  actually make: the pattern matches the name symbols are qualified by (`nt`), not the image file
  (`ntkrnlmp.exe`), which is measured, since a dump whose kernel image is `ntkrnlmp.exe` has no
  module of that name. An **empty** filter is the one thing refused: it is a caller who meant to
  narrow and sent nothing to narrow by, and answering with the whole table would look like the
  filter had been applied and matched everything.

  The modules that have **unloaded** come back in their own `unloaded` list, narrowed by the same
  pattern ([win-kexp#101](https://github.com/glslang/win-kexp/pull/101)) — the only thing that can
  name an address in a driver that is no longer there. `{"filter": "nvhda"}` on this repo's sample
  matches no loaded module and twenty-six unloaded `nvhda64v.sys` rows, and is reported as what it
  is: *"no loaded module matches `*nvhda*`, but 26 that have since unloaded do"*. They are matched
  and rendered by **image** name, since an unloaded module has no module name at all (there is
  nothing left to qualify a symbol with), and each row carries the engine's own `unloaded` flag.

  The filter was originally matched twice — once by this server for the values, once by `lm m` for
  the text — which is what the wildcard grammar, whitespace and case-folding refusals in earlier
  builds of this release were for. See the `modules` entry under **Changed** above: one rendering,
  one matcher, and `execute { "command": "lm m <pattern>" }` for WinDbg's own.

- **`walk_memory`: a structure traversal where an unreadable node is a row, not an end**
  ([#103](https://github.com/glslang/windbg-mcp/issues/103)). Walking a kernel list through
  `execute` was all-or-nothing — one unmapped dereference inside a MASM `.for` loop ended the
  whole script with `An unexpected exception was raised (0x80040205)`, leaving no rows, no
  iteration number, and no way to tell which node faulted. Driving the MessageManager
  use-after-free that meant bisecting a 512-entry handle table by hand to find the one bad
  pointer, which was of course the pointer the walk existed to find.

  The new tool names its nodes three ways — an explicit `addresses` list (the bulk read),
  `start` + `stride` (an array), or `start` + `next_offset` (a pointer chain) — and reads named
  `fields` out of each. Offsets may be negative, so a pool header 16 bytes before the address
  the allocator returned is one argument rather than arithmetic per node. A value the debugger
  cannot read comes back as `null` in its own field, a node where nothing read is counted, and
  the walk carries on.

  A **chain** is the one traversal a hole really does stop, because the address of everything
  after it lived in the bytes that would not read — so it stops and says *which node*. It also
  stops on a null link, on a loop (reporting where the list closed: back at the head that is a
  healthy circular `_LIST_ENTRY`, anywhere else it is corruption), and at `count`, where it hands
  back the address to resume from.

  Fields of one structure are fetched in a single read, falling back to per-field reads only
  where there is a hole — one round trip per node in the ordinary case, which is what lets a
  512-node walk finish over KDNET. The walk checks its deadline and the session's interrupt
  between nodes: there is no *command* behind it, so win-kexp's watchdog has nothing to bound,
  and a walk cut short answers with what it really read rather than failing. The one part that
  *is* a command — the `?` resolving a symbolic `start`, which can block on a symbol server —
  takes the watchdog with what is left of the walk's budget.

### Fixed

- **An allocator snapshot is retired when the target could have moved under it**, instead of waiting
  for a caller to remember `refresh: true`. The pool snapshot has been cached per session since
  0.7.0, and the contract was that a caller who let the target run said so on the next query — which
  makes a stale answer the default outcome of forgetting, and a stale pool answer is not obviously
  wrong to the person reading it. Anything that resumes or steps the target now invalidates it
  (`go`, the steps, `reverse_go`, `run_to_address`, and a `debug_batch`'s resume steps), and so does
  any raw command — `execute` and a batch's command steps — because DbgEng offers no reliable way to
  classify what arbitrary debugger text did, and `eb`, `.reload` and `g` are all just text. The
  invalidation happens even when the command *failed*: a command list can change memory before
  reaching the token it fails on. `refresh: true` still exists and is still worth passing at the
  observation an argument rests on, but it is now a statement of intent rather than the only thing
  standing between a caller and a snapshot of a target that has since moved.

## [0.8.1] - 2026-08-13

### Fixed

- A `profiles.json` with a **UTF-8 BOM** is read rather than refused. Windows PowerShell
  5.1's `Set-Content -Encoding utf8` — the obvious way to write the one config file this
  server asks a Windows user to write by hand — puts a BOM in front, and `serde_json`
  rejected the whole file with `expected value at line 1 column 1`: a message that reads as
  "your JSON is malformed" about a file whose JSON is perfect. Found by configuring a real
  KDNET profile and having the first attempt refused.

## [0.8.0] - 2026-08-13

### Changed

- **`crash_triage` is read-only again, and now earns it**
  ([win-kexp#98](https://github.com/glslang/win-kexp/issues/98)). It ran `!analyze -v` for the
  fields no API returns — the pool tag, the failure bucket, the per-parameter notes — and paid for
  them with the session's selected scope, which is why the tool was annotated
  `read_only_hint = false` despite never writing to the debuggee. It now saves the scope and
  restores it (win-kexp's new `ScopeGuard`), on every path out including the interrupt one, so a
  `.frame` or `.cxr` a caller had chosen survives a triage.

  The measurement that made this possible also **corrected the reason**, which had been wrong in
  this repo's comments, its README and its `crash-dump` skill. `!analyze -v` does not select a
  faulting context and leave it selected: it ends with the scope at the target's **default**,
  discarding whatever the caller had chosen — measured on four targets (`0x13A`, `0xD1`, `0x9F`
  and a user-mode access violation). The implicit *thread* it does move — visibly, on the `0x9F`,
  where the thread it blames is not the one the dump opens on — and does put back.

  So the stack `crash_triage` reports is the target's default context (the crash, on a crash dump)
  rather than "the thread the analysis blamed", regardless of where the caller had navigated —
  which is what makes two triages of one session agree. That normalisation is the analysis's own
  side effect, so it holds exactly when the analysis *completed*: with `analyze: false`, when it is
  skipped for want of time or an `ext.dll`, or when the deadline cut it short before the reset it
  does partway through its output, the walk describes the selected context instead — `analysis.ran`
  and `analysis.truncated` are what tell those apart. The
  smoke tier checks the promise from a scope the analysis would otherwise discard — frame 3, since
  a check starting at the default would pass whether the scope was restored or merely reset.

### Documentation

- README documents installing with [Scoop](https://scoop.sh) from the community
  [`gitfool/scoop-dungeon`](https://github.com/gitfool/scoop-dungeon) bucket
  ([#109](https://github.com/glslang/windbg-mcp/issues/109)), whose `post_install` also does the
  engine bundling — copying from the machine's own `Microsoft.WinDbg` store package, when one is
  installed — so `scoop install` covers the manual setup this README otherwise walks through.
  Nothing about that path redistributes Microsoft's engine. Includes the client config to use (the
  version-independent `current` junction), the disconnect-before-`scoop update` caveat (a connected
  client holds the binary open), and how to bundle after the fact if WinDbg arrives later.
  Documented with the trust boundary stated: the bucket is community-maintained and unaudited by
  this project, and a manifest is code — `post_install` is arbitrary PowerShell over a URL and hash
  that autoupdate rewrites — so the skill's `setup.md` tells an agent never to run `scoop install`
  on the user's behalf, and points at the release zip's checksum and build attestation as the paths
  this project can actually vouch for.
- README's engine-bundling section now copies **`winxp\kdexts.dll`**, which it had never listed
  even though `attach_kernel` auto-`.load`s it: without that file `driver_object` /
  `device_object` / `irp_stack` fail with *"No export drvobj found"*. The skill's `setup.md` and
  the driver-IOCTL docs already had it, so the README was the odd one out.

## [0.7.0] - 2026-08-12

### Added

- **Typed results: `structuredContent` and `outputSchema` for the session, execution, register,
  module, breakpoint and pool tools** ([#84](https://github.com/glslang/windbg-mcp/issues/84)).

  Every tool answered in prose, so anything driving this server programmatically had to parse it.
  The MessageManager batch client and its regression test matched on `VERDICT: HIT`, on
  `allocation(s)`, on module-name substrings and on the exact spelling of the `session_id:` line —
  which means a rewording here broke automation there without any debugger behaviour changing at
  all. Twenty-two tools now return the same text **and** a typed result beside it, with a schema in
  `tools/list` describing it. The text is unchanged with one exception, which is an improvement
  rather than a break: a successful `bp` prints nothing at all, so `set_breakpoint` used to answer
  with an empty string and now renders the breakpoints the session holds beneath the command's own
  (usually empty) output.

  What is typed, and why each one earns it: an opener's `session_id` (previously recoverable only
  by finding a line in the report) and, when an open fails, **whether a target was created** — the
  field that decides whether opening again is a recovery or a second attach; `session_status`'s
  per-session `state`, with `waits_indefinitely` and `overdue` for the attach that can park for
  ever; `end_session`'s `released` / `worker_terminated`; `run_to_address`'s verdict; where a
  `go`/step left the target; the register set and the module list as records; the breakpoint a
  `bp` just set, which prints *nothing at all* on success; and the four pool answers.

  **One address representation**, documented once and used everywhere: a `0x`-prefixed, lowercase,
  16-digit zero-padded hex string. A string because a `u64` past 2^53 does not survive a JSON
  parser that reads numbers as doubles, and zero-padded so lexical order matches numeric order.

  **A pool answer now says what its walk covered** — `complete`, `deadline_truncated` or `partial`
  — because those need opposite responses and "incomplete" alone cannot tell them apart: more time
  reaches more of the pool in the first case and changes nothing in the second. A walk that failed
  or was interrupted is not a coverage state but an error, and an *interrupted* one no longer
  reports itself as a debugger failure.

  **Failures carry a category** (`invalid_argument`, `debugger`, `timeout`, `interrupted`,
  `not_run`, `stale_session`, `worker_lost`, `capacity`) in the error branch of the same schema, so
  a caller branches on a value rather than on wording. `not_run` is new information rather than a
  renaming: a pool query refused for want of budget never touched the target, which is the opposite
  of `timeout`, where the work may well still be running.

  Nothing here is parsed out of debugger output. Each value is built from a value — which is why
  `win-kexp` grew typed `register_values`, `modules` and `breakpoints` readers, why its pool walk
  now reports *why* it stopped rather than only that it did, and why its pool queries hand back
  the walk their answer came from (`PoolAnswer`) instead of leaving a caller to ask separately:
  an incomplete walk is deliberately not cached, so the second question could be answered by a
  *different* walk, and the count and the coverage beside it would then describe two things.
  Where the answer is the supervisor's rather than the engine's, it is built from the session
  registry, not from the sentence describing it.

- **`interrupt`: stop the operation a session is running, keeping the session and its target**
  (FOLLOWUPS item 7).

  A runaway call used to have exactly one way out: `end_session`, which ends it by throwing away
  the target it was running against. On a live kernel that is a machine to re-attach, and often a
  guest to reboot. `interrupt` is the graceful one — a Ctrl+Break, exactly as at a WinDbg prompt.
  The interrupted operation ends at the debugger's next poll and returns **whatever it had reached
  to the call that started it**, marked as cut short, and the session takes the next call
  immediately. Partial output is preserved rather than discarded: `SetInterrupt` makes `Execute`
  fail, so an aborted search used to be indistinguishable from a failed one and lost every line it
  had already produced.

  The primitive existed but was only ever *timeout-driven* — win-kexp's watchdog threads
  Ctrl+Break when a deadline passes, and no caller could ask for the same. `SetInterrupt` is now a
  public win-kexp method on a `Send` handle taken from a `&DebugEngine`, which needs no new
  threading model: it is the one DbgEng call documented as safe from another thread, so the engine
  stays confined to its own.

  **Bound to a job, not to a moment.** `SetInterrupt` addresses an *engine*, so raised a moment
  late it stops whatever started next — a caller's `go` aborted by a cancel meant for the search
  before it. The worker tracks which job its engine thread is running, and the request reader reads
  that job and raises the interrupt under one lock, while the engine thread claims and releases the
  job under the same one. So an interrupt reaches the job that was running when it arrived or
  nothing at all, and the job it reached spends it: a pending break left over is drained before the
  next job starts, and only the interrupted caller is told their result was cut short.

  Like the abandon-a-batch signal, the request is **answered by the worker's request reader** rather
  than queued for its engine thread — queued, it could only be read once the operation it means to
  stop had ended. So it does not wait behind the busy session: issue it while the slow call is still
  outstanding. With nothing running it says so and does nothing. Two limits carry over from DbgEng:
  an operation that never polls for the break is not reached, and neither is an `attach_kernel`
  whose target has not connected — `end_session` remains the only end to that one.

  A `debug_batch` interrupted this way stops and runs its `always` block, reporting
  `BATCH: INTERRUPTED` at the step the break reached — a distinct outcome from `ABANDONED`, because
  the session is still open and still holds its target, so the same batch can be resubmitted against
  it. It has to be told rather than left to infer it, and that is not a detail: **an interrupted
  command succeeds**. Preserving the output reached up to the break is the whole point, so a step
  whose assertions still hold is indistinguishable from one that ran, and the batch would carry on
  applying later mutations for a caller who had just asked it to stop.

  So the debugger reports *both* facts. `execute_command_bounded` returns the output **and** whether
  the command finished (`CommandRun { output, cut_short }`), the shape `run_to_address` already had,
  rather than a bare `String` that cannot say "this did not finish" — every place that reads a result
  gets the fact with the value instead of having to remember to ask for it. That is the difference
  between a step that reports itself cut short and a batch that has to guess: the last step of a
  batch, and a step whose assertion stops holding *because* the output was truncated, are both just
  "the step says so" rather than two more special cases.

  **A batch's rollback is not interruptible.** Cleanup runs as part of the same call and is reached
  on every path, so a break landing there hits a restore command — which returns `Ok` with partial
  output like any interrupted command, and would be recorded as a step that worked: `rollback:
  COMPLETE` with the target still changed. The executor announces the block before running it, and
  the worker then refuses breaks for that call and drains any already pending, both under the lock a
  raise has to take. An `interrupt` aimed at a batch that is unwinding says so and sends nothing.
  Two readings that were wrong in the same direction come right for free once the step carries the
  fact. A break landing during the **last** step has no next step to be caught before, so the batch
  reported `COMMITTED` of a transaction whose final step was cut short — directly above the note
  saying it had been. And a step that *fails* because the break truncated its output — a `contains`
  that stops holding, an `eval` that stops parsing, the likeliest shape of an interrupted step —
  reported `FAILED`, sending the caller to debug a step that was fine. Both are now `INTERRUPTED`,
  named at the step the break actually reached.

  Every op now keeps the output an interrupted command reached, not only the bounded ones. The plain
  path (`modules`, `index_trace` and the other typed commands) went through `execute_command`, where
  a break makes `Execute` fail and the captured buffer is discarded with the error — a bare failure
  plus a note promising partial output that was not there. They take `execute_command_bounded` with
  a zero deadline instead, which is the same call plus that recovery: zero spawns no watchdog, so
  they stay unbounded, as `index_trace` in particular must.

### Changed

- **The pool tools take the caller's own deadline instead of win-kexp's default walk budget**
  ([#75](https://github.com/glslang/windbg-mcp/issues/75)).

  A pool walk enforces a wall-clock ceiling of its own, so `pool_find_tag` and friends can no
  longer run for minutes after their caller has given up and leave every later call to that session
  queued behind them. But they took the walker's **default** — 120s — which knows nothing about
  this server's deadline, and was wrong in both directions. A host configured with
  `WINDBG_MCP_CALL_TIMEOUT_SECS=60` got a 120s walk against a 60s budget: the call timed out and
  the engine kept walking, which is precisely the wedge the walk budget was added to fix, arriving
  from this side. And with the 300s default the walk stopped at 120s and handed back a partial
  snapshot with three minutes still to spend.

  `EngineOp::Pool` now carries the caller's remaining patience exactly as a bounded command and a
  batch do — filled in by the supervisor's pump as the request is written, with the worker deriving
  the deadline, because only the worker knows how long the request then sat in *its* queue. The
  arithmetic is the bounded command's, so the invariant is the same: queue wait plus walk budget
  never exceeds the caller's patience. A walk cut short still answers, and every pool result already
  reports how much of the pool it reached.

  Where it parts company with a bounded command is at the bottom of the range: that one *floors* its
  budget, because zero disables its watchdog and an unbounded command is the worse outcome. A walk
  has no such cliff — zero simply stops it at the first check — so there is no floor here, and a
  query that reaches the engine with nothing left to spend is refused rather than run. Flooring it
  would reintroduce the bug at the small end (a 10s call budget yielding a 15s walk) and buy nothing
  for it, since win-kexp caches complete snapshots only: a budget-truncated walk is discarded, so the
  work would be spent for a caller who has gone and the next query would walk from scratch anyway.
  Only a query that *must* walk is refused; one that can be served from the session's cached snapshot
  is still answered, because a cache read costs nothing that even an exhausted caller cannot afford.

  Which slot the pump fills is now named on `EngineOp` itself rather than matched inside the pump,
  because the failure it prevents is silent — that is exactly how `Pool` came to carry no patience
  at all — and is checked against the serialized form, so an op with a `patience_ms` that does not
  hand it out fails a test rather than shipping with an unset deadline.

### Fixed

- **A `2026-07-28` client got a server with no tools at all**
  ([`rmcp` #1114](https://github.com/modelcontextprotocol/rust-sdk/issues/1114)).

  SEP-2549 added `ttlMs` and `cacheScope` to every paginated result, and the `2026-07-28` schema
  makes both **required**. Every `rmcp` before 3.1.1 generated a `list_tools` that hardcoded the
  pair to `None` and then skipped serializing them, so a client that validates responses against
  the spec schema refused the entire reply: the process starts, `initialize` succeeds, the
  capabilities advertise tools — and not one of the 43 is reachable. Neither side reports an
  error, because the response is a well-formed JSON-RPC result; it is only invalid against the
  schema. Clients on the handshake-era revisions were never affected, which is why this reached
  a release: those revisions do not define the fields, and the server is correct without them.

  The dependency now has an `rmcp = "3.1.1"` floor rather than `"3"`, because the fix lives in the
  SDK's macro and a version requirement is the only part of this a downstream resolver reads. The
  smoke test pins the resulting wire shape — the fields present on `2026-07-28`, absent on the
  revisions that predate them, over both the `initialize` handshake and the stateless
  `server/discover` opener — so an older 3.x fails the suite rather than shipping a server that
  looks empty to the newest clients.

## [0.6.0] - 2026-08-10

### Added

- **`debug_batch`: an ordered sequence of debugger steps as one transaction, with assertions and a
  rollback the engine process owns** ([#82](https://github.com/glslang/windbg-mcp/issues/82)).

  A tool call is a request/response, so a client driving a multi-step debugger transaction decides
  what to do next *after* each answer — and the case that matters is the one where no answer
  arrives. A call that times out, or a client that disconnects, leaves whatever the earlier calls
  changed in place: a patched instruction, an armed breakpoint, a target left running. On a kernel
  target that is not an inconvenience. The MessageManager CTF session grew a private JSON-RPC
  client for exactly this (`target/mcp_batch.ps1`, referenced 204 times and revised 18); the shape
  it converged on is what this tool is.

  A batch is submitted as one op and executed inside the session's worker process. Steps are
  `command` (raw), `resume` (a command that moves the target, plus the wait), `run_to` (a
  HIT/STOPPED ELSEWHERE/TIMEOUT verdict), `eval` (a MASM expression's value) and `read_memory`,
  plus `pool_chunk`, `pool_find_tag` and `pool_census`, which ask the kernel pool exactly what the
  tools of those names ask. Those three are here because they are the only typed tools that are
  *not* debugger commands — they are win-kexp walks over the allocator's descriptors, so no
  `command` step can stand in for them, and a transaction that needed one had to be split around
  it. Inside a batch their walk is bounded by the step's share of the budget rather than by the
  walker's own 120s default, so a `refresh` cannot spend the reserve the rollback lives on; a walk
  cut short still reports the coverage it reached.
  Each step may carry assertions — `contains`, `not_contains`, or `eval`, which compares two MASM
  expressions and so covers registers, memory and any relation between them — and an `eval` step
  may `capture` its value under a name later steps interpolate as `{{name}}`.

  **The `always` block is reached on every path**: success, a debugger error, an assertion that did
  not hold, the deadline expiring, a panic out of the debugger (win-kexp methods do panic — several
  use `.expect` — and the worker's own `catch_unwind` is around the whole op, so each engine call a
  step makes is guarded individually). Part of the budget is reserved for it before the first step
  runs, because what is left after a step that ran to its own deadline is nothing, and cleanup
  continues past its own failures. The worker owns that deadline, sized from the caller's remaining patience
  the same way a bounded command's watchdog is, so the rollback has finished and the report has been
  written before the tool call gives up — which is the only reason the report is worth anything.

  A batch whose caller has already given up is **not started at all**: a job stays queued after
  its waiter times out, so the worker checks what patience is left before the first step and
  refuses outright rather than applying mutations nobody is waiting to hear about. That is where a
  batch parts company with a bounded command, which floors its watchdog instead — that one is
  already running and the job left is to free the worker; this one has not started, and not
  starting is what leaves the target as the caller last saw it.

  **A teardown while the batch is running is answered too**, and it is a different problem from a
  timeout: `end_session` and a client disconnect both release the target, and the op that does so
  queues *behind* the batch, so the grace used to expire with the transaction still open and the
  worker was terminated mid-patch. The worker's *request reader* now acts on that release as it
  reads it, rather than only when the engine thread reaches it: the batch stops at its next step,
  runs `always`, and reports `BATCH: ABANDONED`, while the reader answers with **how long that batch
  may still need** — so the teardown's wait covers the step already inside DbgEng as well as the
  rollback behind it. That figure is the batch's own remaining budget plus the overrun its executor
  is allowed, already clamped to the caller's patience, so a teardown never waits longer than the
  batch could have run anyway; it is re-read as the wait goes on, so a batch that finishes early can
  hand the rest back and leave only what the release itself still needs. A session with nothing to
  unwind says nothing and costs exactly what it always did. A batch that
  reaches the engine *after* the release does not start at all, which is the same "nothing ran,
  resubmitting is safe" answer as an unaffordable budget.

  Two edges are reported rather than papered over. The reserve buys the rollback *time*, not a
  guarantee: a step that overruns far enough to consume the reserve as well leaves cleanup with no
  budget, and the result then says `rollback: INCOMPLETE` and names each step that never started.
  And no signal *shortens* a step already inside DbgEng, so a batch built from long steps unwinds
  only once the current step ends — the teardown waits that out rather than cutting it off, but a
  step that ignores its own watchdog is still terminated mid-transaction.

  The result names every step that ran, the exact failing one, what each step changed, whether the
  rollback completed (reported *beside* the original failure, never instead of it), and whether the
  session is left stopped, running, detached or uncertain. A batch that did not commit comes back as
  a tool error carrying that whole report.

  Validation is up front and engine-free: a forward capture reference, a capture on a step that has
  no value, a duplicate name, a `;` in a typed operand, an empty or oversized batch, a deadline too
  short to seat a step and its reserve, and — uniquely among this server's tools — any field the
  schema does not name are all refused before a single step runs. The last is there because those
  typos fail *open*: `"aways"` for `always` is a batch with no rollback that then reports
  `COMMITTED`, and a misspelt `expect` is a step that asserts nothing and commits anyway. A batch containing a target-changing command retires the session handle
  ahead of running, as `execute` does. The executor drives a `Debuggee` trait rather than DbgEng, so
  assertion failure, a command failure after a mutation, deadline expiry and a rollback that itself
  fails are unit-tested without a debugger; the dump tier drives a real engine to both outcomes, and
  to both teardowns — a real disconnect mid-batch, whose rollback has to leave a mark on the machine
  because there is no client left to report to, and an `end_session` mid-batch, where there is.

  The claim itself — *a write that is then restored* — is settled where it can be false, on a live
  KDNET kernel: a byte of the running kernel is patched inside a batch and read back afterwards,
  through a failing assertion, through a call budget shorter than the batch asked for, through a
  disconnect (read back by a **new server process** over a fresh attach) and through an
  `end_session`. A crash dump cannot make that claim at all — a byte patched in a dump is patched in
  a file nobody reads again, so a rollback that silently did nothing passes every assertion the dump
  tier can make. Each of those tests probes the byte before it starts, because a guest with memory
  integrity enabled accepts a debugger write to an image page and drops it, which would otherwise
  leave the whole tier passing for the wrong reason.

  Two limits are documented rather than papered over. DbgEng reports most command failures by
  printing them and returning success, so a raw step that prints an error is a step that
  *succeeded* — assert on its output if that matters. And what a step "changed" is a best-effort
  classification of the command text, biased toward reporting a change: a reporting aid, not what
  makes a mutation recoverable. The `always` block is.

  Validated against the workflow it was filed for, not against a guess at it: the CTF session's own
  transcript records all 18 revisions of the throwaway client and all 188 of its invocations — 1,681
  steps, every one of them a shape the step language covers. The 9 that motivated the pool steps are
  the reason those exist: the client's `@chunkt1` read a pseudo-register with `execute`,
  regex-scraped the value out of the debugger's prose and handed it to `pool_chunk`, and it sat
  *inside* the 32-step transaction, between a code patch and its restore — so a batch without it
  would have had to drop the query or split the transaction. It is now a `capture` and a step.
  Two of the client's revisions exist only to work around gaps this closes — a compound
  assertion rewritten as three pseudo-register assignments and three regexes, and a duplicate of its
  run-to verb whose only difference was restoring a patch "on both hit and timeout". The longest
  single invocation, 32 steps, is transcribed as a regression test.

  `tools/list` gains one tool and its first nested schema, so the recorded wire surface now has
  `$defs` (`usesDefs` flips to `true`); the refs stay internal and single-dialect.

- **`attach_kernel` can name its target by `profile`**, so a KDNET debug key never has to travel in
  an MCP request ([#81](https://github.com/glslang/windbg-mcp/issues/81)).

  A connection string carries the target's key, and a key passed as a tool argument does not stay in
  the tool call: an MCP client keeps a transcript, and the one key handed over during the
  MessageManager CTF session ended up replicated across 524 records of it — through messages, tool
  calls, context snapshots and compaction summaries. That is what a transcript *is*, not a client
  misbehaving, so the server had to offer a way for the secret never to enter the request at all.

  `attach_kernel` now takes **exactly one** of `connection` (unchanged, still supported for a target
  nothing is configured for) or `profile`, a non-secret name this process resolves from
  `WINDBG_MCP_PROFILE_<NAME>` in its environment or from `%USERPROFILE%\.windbg-mcp\profiles.json`
  (`WINDBG_MCP_PROFILES` overrides the path; environment-variable names are matched
  case-insensitively, as Windows matches them). The **file** is re-read on every attach, so adding
  a profile to it takes effect immediately — an environment variable is read from the server's own
  environment at startup, so it belongs in the client's server definition and needs a restart to
  change. Passing both selectors, or neither, is a tool error naming the alternative, and the
  "neither" case lists the profiles this host has — which is what lets an agent find one instead of
  asking the user for a string it would then have to keep.

  The exclusivity is enforced at runtime rather than in the schema: an untagged `oneOf` renders as a
  schema composition clients handle unevenly, the same reason `session_id` is repeated per tool
  struct rather than flattened. Both fields are therefore optional on the wire (`tools/list` golden
  updated).

### Changed

- **Connection strings are redacted everywhere but the one call that dials them.** `key=` and
  `password=` values are masked in session reports, errors and logs, whichever selector opened the
  session: `session_status` now shows
  `kernel target: profile "ctf-vm" (net:port=50000,key=<redacted>)`.

  The guarantee is structural rather than a discipline. The value lives in a `kdconn::Connection`
  whose `Debug` and `Display` are the redacted form, so a log line, a `{:?}` on `EngineOp`, or a
  session label cannot carry the raw string; it is unwrapped at exactly one call site, handing it to
  DbgEng inside the session's own worker process. Redaction masks *values inside connection strings*
  only — debugger output is never rewritten, which on a CTF target would be its own kind of damage.

  Redaction works off a **parse** rather than a scan: the string is split once into the structure
  DbgEng's syntax has (transport prefix, separator-delimited `name=value` items) and rendered from
  that, with a secret parameter's value never emitted. The parse is total — every byte lands in
  exactly one field, so an unredacted render reproduces the input exactly — which is what makes
  the guarantee checkable rather than a matter of having anticipated every delimiter. A repeated
  separator, an empty item or an `=` inside a value changes which field text lands in and cannot
  change which parameter owns it.

  **Whitespace between parameters is refused** rather than interpreted, on both the explicit and
  the configured path: it reads as either a separator (a missing comma) or as filler (a stray
  space), each of those leaks the key under the other reading, and nothing in the string says which
  was meant. A connection carrying any is reported as `<connection redacted>` in full. Whitespace
  *around* the whole string is still trimmed, so a pasted value is fine.

  Errors on the profile path never echo a value either. A connection string typed into `profile` —
  the one mistake that would defeat the whole feature — is refused by naming the shape a profile
  name has, not by quoting back what it was handed. The same applies to a *configured* name: an
  entry whose name is not a name is skipped and located, never quoted, because the way that happens
  is an entry written the wrong way round.

- **Neither process this server creates inherits the profile variables.** An engine worker is told
  the one connection it is opening over its private pipe and resolves nothing itself, and the TTD
  recorder needs no connection at all — so `WINDBG_MCP_PROFILE_*` and `WINDBG_MCP_PROFILES` are
  stripped from both. What each of them then launches is the reason: a `launch`ed debuggee inherits
  its worker's environment, and `TTD.exe` hands its own to the recorded target. Those are precisely
  the untrusted programs that must not receive every configured kernel key.

## [0.5.0] - 2026-08-08

### Added

- **Four tools that read the kernel pool from the allocator's own descriptors** —
  `pool_find_tag`, `pool_chunk`, `pool_census` and `pool_diagnostics`, on a broken-in x64 kernel
  target (38 → 42 tools).

  They go through win-kexp's descriptor walk rather than shelling out to `!pool`/`!poolused` and
  parsing the text back, so the answers are structured and all four read **one** snapshot — they
  cannot disagree with each other. Walking every committed pool page is expensive, so that
  snapshot is cached per session and reused; pass `refresh: true` after letting the target run, or
  you are reading a photograph of a target that has since moved.

  Two distinctions the tools keep deliberately, each of them the difference between an answer and
  a guess:

  - **`pool_find_tag` reports only *allocated* chunks.** A freed chunk's tag is not reliably
    preserved by the allocator, so listing freed ones would be inventing data. To ask whether one
    specific address has been freed, ask `pool_chunk` about it.
  - **`pool_chunk` separates a free hole inside a walked region from an address the snapshot never
    covered.** The first — an explicitly free state, `ReusableFree` or `CachedFree` — is the
    finding that a pointer the target still holds is dangling. The second is not its opposite: a
    region the walk never reached looks exactly like memory that was never pool, so the coverage
    the result prints has to be read before concluding anything from it. A third outcome,
    `Unreadable`, is neither — a Verifier guard page reads exactly that way — and says nothing
    about whether the allocator freed anything. `pool_chunk` also reports the **neighbouring**
    chunks, which is what tells you what a reclaim would land next to.

  `pool_diagnostics` exists because a real walk emits tens of thousands of diagnostics across a
  hundred-plus categories: any per-call summary necessarily truncates, and the one line explaining
  a specific heap is reliably not in the truncated head. A plain substring filter located a
  special-pool misclassification in one call, and disproved a wrong hypothesis in another — which
  is the part that saved the most time.

  What holds the set together is that **a walk states its own coverage**, and every result carries
  the walk's own state — chunks seen, diagnostics grouped by category — whenever it comes back
  empty. An incomplete walk is the ordinary outcome on a live kernel rather than a defect (paged
  pool is partly on disk, so `sparse virtual range` diagnostics are physics), which is exactly why
  "the pool holds no such chunk" and "the walk reached almost none of the pool" must not render
  identically. Letting them hid a real bug for three rounds. The walk is also bounded and gives
  the session back at its ceiling, so a query cannot leave every later call to that session queued
  behind it.

  Measured against Server 26100 over KDNET by the live-kernel smoke tier
  ([`docs/smoke-test.md`](./docs/smoke-test.md)): a forced walk returns in ~52s of its 120s
  budget, indexes 530,680 chunks of which 306,227 are allocated, and reports INCOMPLETE. Those
  figures are what they are because of glslang/win-kexp#92, which corrected the reading of
  `_HEAP_PAGE_RANGE_DESCRIPTOR.RangeFlags`: bit `0x01` is ALLOCATED, set on every unit of every
  allocated range, not "this is an LFH subsegment". Read as LFH it sent VS subsegments, plain
  page-range and large allocations, and Verifier special pool through the LFH decoder, which
  refused them and dropped each range at region creation — so a walk quietly omitted about a fifth
  of the pool. The same fix accounts for the walk now costing twice as long: those regions are
  decoded rather than discarded.

  Known limitation: a pool call takes win-kexp's default 120s walk budget rather than the caller's
  own deadline ([#75](https://github.com/glslang/windbg-mcp/issues/75)). With the default 300s
  call timeout the walk finishes well inside it, but a server run with
  `WINDBG_MCP_CALL_TIMEOUT_SECS` set below the walk's cost will time the call out while the engine
  keeps walking.

- **A walkthrough for those tools on a real bug**: MessageManager, a CTF driver's pool
  use-after-free, driven end to end over a live KDNET kernel with no PDB
  ([`docs/messagemanager-walkthrough.md`](./docs/messagemanager-walkthrough.md)). Unlike the HEVD
  and mountmgr tours it is not about *reaching* an IOCTL but about watching a freed chunk get
  reclaimed — and about the four places a new OS release had moved the furniture under the pool
  walker, because a walker that silently returns "empty" is worse than no walker at all. It claims
  what it demonstrates and no more: a confirmed UAF, freed-chunk control, and two pinned forward
  primitives, with SMEP/SMAP/CET ruling out anything but a data-only payoff and the reclaim left
  as where the work continues. `examples/messagemanager/` holds the client that drives the
  driver's IOCTLs from the target VM, since the server cannot issue `DeviceIoControl` itself.

## [0.4.2] - 2026-08-05

### Fixed

- **The supervisor↔worker protocol has a channel of its own, so nothing a worker prints can cost a
  session** ([#65](https://github.com/glslang/windbg-mcp/issues/65)).

  The protocol used to ride the worker's stdin and stdout — the same stdout any code in that
  process can write to. DbgEng's own output never lands there (it is captured through
  `IDebugOutputCallbacks`), but an extension DLL that prints to the console directly does, and an
  *unterminated* stray line swallowed the message written after it. The supervisor drops what it
  cannot parse, and only a `Done` removes a waiter, so the cost of one stray `printf` was not a
  lost line but a lost session: the call timed out, its waiter stayed, and the session counted as
  busy — and so could never be reclaimed — for the life of the server. 0.4.1 mitigated this by
  opening each message with a newline; the property was still a convention about who prints where.

  Each worker now gets a pair of anonymous pipes, created by the supervisor and inherited across
  the spawn: requests down one, messages up the other. An anonymous pipe has no name to open and
  is reachable only through an inherited handle, so nothing outside that pair of processes can
  write on it — "stray output cannot corrupt a reply" is a property of the plumbing rather than of
  what happens to be loaded. The worker's stdout is now only a log: it is drained into the
  server's stderr with the session it came from, which is also the first time an extension's
  console output has been visible at all. Its stdin is `NUL` — never inherited, since the
  supervisor's stdin is the MCP transport.

  What the channel cannot make impossible is a `Done` that is never written, and that is the half
  that strands a waiter, so it is answered directly: a result that cannot be encoded is replaced
  by one that says so, and a channel that cannot be written to means the supervisor is gone — its
  exit fails every outstanding call out. Teardown is unchanged in substance: EOF on the request
  channel now means what EOF on stdin meant, and a worker still releases its target before it
  exits.

## [0.4.1] - 2026-08-04

### Fixed

- **A worker the server never got round to releasing now lets go by itself, rather than being
  killed with its target still attached** ([#67](https://github.com/glslang/windbg-mcp/issues/67)).

  Workers were spawned with tokio's `kill_on_drop`, so the last act of a supervisor on its way out
  was to `TerminateProcess` every worker handle it still held. For a session shutdown had already
  released that is harmless. For one it *missed* it is the whole failure: the worker is killed
  before it can detach, and a live kernel left attached-but-halted is a target machine stopped
  until someone reboots it. Belt-and-braces that cut the braces.

  A worker has handled this on its own since 0.4.0 — its stdin reaching EOF means "the supervisor
  is gone", and it asks its engine to release the target before exiting, bounded at five seconds —
  so the fix is to stop pre-empting it. `kill_on_drop` is gone; EOF is the teardown on every route
  out, including a Ctrl+C or a crash where there is no supervisor left to do anything. Killing is
  now only ever deliberate: after a release was asked for and refused, or on a worker known to
  hold nothing.

  Workers are also spawned into their **own process group**, without which EOF could not be the
  teardown at all on one route: an interactive Ctrl+C goes to every process sharing the console,
  and a child inherits its parent's group, so a worker took the default console handler and died
  where it stood — no stdin close, no release. It is the route where the server can help least,
  since its own default handler ends it before it can run any shutdown, and it is the one a
  developer driving this from a terminal hits by reflex. Driven rather than argued:
  `examples/ctrl_c_teardown.ps1` fires a real Ctrl+C into a console of its own — Ctrl+C cannot be
  aimed, so a test that sends one from `cargo test` takes the runner with it — and checks the
  worker logged its release before exiting. It fails against a build with that one flag removed.

  The way shutdown could miss a worker is closed too. An open that was admitted before the client
  disconnected, and whose worker finished its handshake after shutdown had walked the registry,
  used to register anyway and be handed its opener — starting an attach nobody was left to end.
  Registration now re-checks, under the same lock that closes the gate, so such an open is refused
  and its (target-less) worker ended. That makes the set of workers to release one that cannot
  grow behind shutdown's snapshot, so the timed drain that used to approximate the same guarantee
  is gone with it.

- **A teardown now says what became of each target, instead of claiming more than it knows.**

  Every release outcome was discarded by whoever was its only witness. At shutdown the client has
  already disconnected, so the log is the only place one can land — and the outcome most worth
  hearing, a worker terminated without ever unwinding, was exactly the silent one. The worker
  discarded as much on its side: its engine's error releasing the target, whether the release
  finished at all, and whether it was even asked.

  All of them are reported now, and read by a single rule: a successful release **anywhere**
  outranks this attempt's failure. Two teardowns can race for one session — a reclamation
  releasing in the background, a disconnect collecting it mid-flight — and only the winner is told
  it worked. The loser sees a timeout, a lost worker, or a debugger error, none of which mean the
  target is still attached. Without that rule the new warning would have fired at the very moment
  another teardown cleanly detached, which is how the next real one gets ignored.

  `end_session` also stops telling a caller "nothing is left attached" when the debugger *refused*
  to release. DbgEng resumes and detaches a live kernel as part of releasing it, and that is the
  step that just failed — so terminating the worker afterwards leaves the guest halted, and the
  one caller who most needed to go and check was told there was nothing to check. Dumps and traces
  are named separately, since for those the old sentence was true.

## [0.4.0] - 2026-08-03

### Changed

- **Each debug session now runs in its own engine process, and a session that cannot be unwound
  can be reclaimed** ([#61](https://github.com/glslang/windbg-mcp/issues/61)).

  A live kernel attach waits for its target with `WaitForEvent(INFINITE)`, and DbgEng cannot
  interrupt a wait that has not yet connected. So a guest that is powered off, not booted with
  debugging enabled, or pointed at the wrong host/port/key parked the attach forever — measured on
  hardware at 300s with no bound and no cancellation path. With one engine thread that park owned
  the server: every later tool call queued behind it, `end_session` included, and the only recovery
  was restarting the process. Since the most common mistake in kernel debugging is exactly "the
  guest is not in debug mode", an agent driving this server hit it routinely.

  The server now runs MCP in a supervisor process and each open target in its own engine worker
  child process. The park costs one worker, and **`end_session` terminates it** — asking the worker
  to let go first, killing it if it will not. That is the in-band recovery that did not exist.

  What this changes for callers:

  - **Sessions are concurrent and no longer replace each other.** Triage a crash dump while a kernel
    attach is live; keep two traces open at once. Up to four; at the limit a new open reclaims the
    oldest *idle* session, and refuses with the list if every session is busy. The opener tools no
    longer say "replaces any session already open", because they do not.
  - **`session_id` routes rather than merely detects.** It names the worker holding your target, so
    another caller's open cannot invalidate your handle — the accident the handle was built to
    report is now largely impossible rather than merely visible.
  - **`session_status` lists every session**, with what state each is in and how long it has been
    there. For an attach that has not landed, that duration is the whole signal: a KDNET link
    still coming up (~25s) and one that will never come up were previously indistinguishable, and
    they need opposite responses. Past the point a healthy attach takes it says so, and names the
    recovery. It still never queues on any worker, so it answers while a session is parked.
  - **Nothing outlives the connection.** A disconnect ends every session the way `end_session`
    does: each is asked to release its target, and terminated only if it will not let go within a
    few seconds. So it cannot leak a debugger process or a debuggee.

    Releasing rather than killing matters most for a live kernel, because DbgEng leaves a
    detached-but-*halted* kernel stopped — a worker killed outright takes the target machine down
    with the connection. A disconnect asks every session to release concurrently, waits five
    seconds, and terminates only those that have not finished; the live-kernel tier checks against
    the target's own uptime that the release is what normally happens. The residual risk is a
    session that cannot let go inside that grace — one busy in a long `go`, say — which is
    terminated, and for a live kernel that does leave the target halted. Ending such a session
    with `end_session` first (it allows considerably longer) is the way to avoid it.
  - Failures scoped to a session (a debugger error, a timeout, a refused handle, a worker that
    died) are all tool errors with their text intact. The only JSON-RPC protocol error left is
    "no engine worker could be started at all".

  Reasoning, and why the two cheaper mitigations were not the fix, in
  [`DECISIONS.md`](./DECISIONS.md). The smoke test's debugger tier covers the reported case end to
  end — an attach parked on a dead port, another session opened alongside it, and `end_session`
  reclaiming it — and a new live-kernel tier drives a real KDNET target through attach, coexistence
  and detach, checking against the target's own uptime that a disconnect leaves it *running*.

- **The bounded-command path now has a stated coverage rule, and tests that prove it works.**
  0.3.0 routed `execute`, `dx` and the `ttd_*` tools through a watchdog that Ctrl+Breaks a
  runaway command before it can pin the engine thread, but nothing exercised that interrupt
  end to end, and "why these five?" had no written answer.

  It gains both. The queue-aware budget arithmetic is a pure function with unit tests that ride
  `cargo test` (`src/worker.rs`, next to the watchdog it arms); three `#[ignore]`d tests drive a
  real engine through the shipped binary, proving a runaway command self-aborts and leaves its
  session usable — including from behind a queued job, which is the half win-kexp's own tests
  cannot cover because the queue belongs to this crate. See
  [`docs/smoke-test.md`](./docs/smoke-test.md).

  The coverage rule, recorded in [`DECISIONS.md`](./DECISIONS.md): bound a command when its
  cost scales with the target's size or with an arbitrary caller-supplied expression; leave
  point queries (`k`, `lm`, `u`, `!irp`, …) unbounded. Arming the watchdog measurably rounds a
  command's duration up to a multiple of 200ms, so bounding a 30ms query would make it a 200ms
  one for a runaway case it does not have. `index_trace` is a deliberate exception and
  now says so: it is O(trace), but `-force` deletes before it rebuilds, so an abort can leave no
  usable index at all — its tool description now tells callers to wait rather than re-issue it.

### Fixed

- **Every opener now commits its session handle, including the four that attach or launch.**
  0.3.0 shipped this guarantee for `open_dump` and `open_trace` only, and documented the gap
  for the rest: win-kexp fused the target-creating call and the wait for the initial break
  into one `Result`, so a failure could mean "nothing happened" or "the process started /
  the attach succeeded, then the wait failed" — indistinguishable from here, and needing
  opposite recovery. Those four tools hedged accordingly, telling callers to check
  `vertarget` before opening again instead of claiming a retry was safe.

  win-kexp split them (glslang/win-kexp#71): each opener is now a `x_begin()` returning a
  `PendingTarget` guard, plus a `wait()` on that guard. The guard cannot exist unless the
  side effect succeeded, so there is finally a seam to commit at. `opened_result` hands its
  `transition` a `commit` callback to invoke at that seam, and every opener reads the same
  way — side effect, `commit()`, wait.

  So a failed break-in wait on `attach_process`, `attach_kernel`, `attach_kernel_local` or
  `launch` now returns the error *with* a usable `session_id`, exactly as a failed load wait
  on a dump already did. The hedge is gone: the server knows which side of the seam a failure
  fell on, and says so — re-open when nothing was created, never re-open when the target is
  already there. For `launch` that is the difference between one process and two.

## [0.3.0] - 2026-08-01

### Added

- **Explicit session handles.** The tools that open a target (`open_dump`, `open_trace`,
  `attach_kernel_local`, `attach_kernel`, `attach_process`, `launch`) now return a
  `session_id`, and every tool that touches the debug target accepts it as an optional
  argument, refusing to run when it no longer matches the session the engine holds. One
  process drives one DbgEng session, but an MCP connection is not a session — a client may
  interleave unrelated requests over the same stdio process — so without a handle a call
  could silently act on a target it never opened. Omitting the argument keeps the previous
  behaviour, so existing callers are unaffected. `decode_ioctl` (pure) and `record_trace`
  (independent of the session) do not take it.

  The check and the session transition both run **on the engine thread**, in the same
  queued job as the debugger call, so they are ordered by the queue that already serialises
  DbgEng access. Validating on the caller side would leave a time-of-check/time-of-use
  window: with session A current, an `open_dump` for B can be in flight while the session
  still reads A, so an `end_session(session_id=A)` would pass, queue behind the open, and
  close B. The guarantee is detection rather than exclusion — the opening tools take no
  handle, so holding one does not prevent a replacement, it makes any later call of yours
  that supplies the handle fail instead of acting on the wrong target.

  The opening tools commit the handle as soon as the target transition succeeds — the
  transition being exactly the one DbgEng call that replaces the target, and nothing else.
  Everything after it (the load wait, and the `lm` / `vertarget` / `r` / TTD lifetime
  diagnostic) runs post-commit, so a failure there reports the error *with* the `session_id`
  rather than swallowing it. The target is genuinely open at that point, and the only other
  way to obtain a handle is to open again, which for `launch` means spawning a second
  process. A `wait_for_event` that times out counts: the dump or trace is loaded either way.
  So does a *panic* in the report — several win-kexp methods use `.expect`, and an unwind
  would otherwise skip straight past the code that attaches the handle.

  One limit is documented rather than fixed: win-kexp bundles the wait for the initial
  break into `launch_process`, `attach_process` and the kernel attaches, so from this server
  a failure there can mean "nothing happened" or "the process started / the attach
  succeeded, then the wait failed", and the two are indistinguishable. Those tools therefore
  say so on failure and point at `vertarget` rather than advising a blind retry, which for
  `launch` would start a second process. Splitting them properly is a win-kexp change.

  `execute` and `dx` are the two paths that can swap the target without going through a
  typed tool. For `execute` the session-control commands (`.opendump`, `.attach`, `.detach`,
  `.kill`, `.restart`, `.abandon`, `.remote`, `q`/`qd`/`qq`) retire the current handle,
  matched per command across every DbgEng command boundary — `;` and line breaks alike,
  since `r\n.opendump other.dmp` is two commands and a scanner that split only on `;` would
  see nothing but `r`. `dx`
  reaches command execution through the data model's
  `Debugger.Utility.Control.ExecuteCommand`, which runs any command string, so an expression
  touching command execution retires the handle too — conservatively, because the command is
  a runtime string this server never sees. Both matches are biased toward retiring —
  over-matching costs a re-open, under-matching would let a stale handle through — and
  neither can be exhaustive, so inside `execute` and `dx` a handle is a strong hint rather
  than a guarantee. Everywhere else it is a guarantee.
- **`session_status`.** Reports the handle of the session the server currently holds, or
  that none is open. It exists to recover a `session_id` a caller never received: the
  per-call timeout can fire while the engine thread is still working, and if that job then
  succeeds it commits a handle no reply ever carried. A live `attach_kernel` is the case
  that matters — it waits indefinitely by design, so the call reporting a timeout while the
  attach completes later is normal, not exceptional. Recovering the handle beats the
  alternative of retrying an attach or launch that would connect or spawn a second time.
  Deliberately does not queue on the engine thread, since the situation it addresses is
  that thread being parked.

  It reports *the current* handle, not *your* handle, so recovery is a two-step check. A
  timed-out open now names the handle it would commit — the id is minted before the job is
  queued, so it can be stated up front — and the caller adopts the session only if
  `session_status` reports that same id. Without that correlation, "ask for the current
  handle" would quietly hand the wrong target to a caller following the documented recovery
  flow, with every later session check passing.

  The current handle alone cannot say *which* of those a mismatch means — "not yours" is
  equally true while an open is still queued and after it has permanently failed — and the
  two need opposite responses: a pending open must not be re-run (that attaches or launches
  a second time), while a failed one must be, since nothing else will produce a target. So
  each opener's outcome is recorded (pending / landed / failed) and `session_status` takes
  an optional `session_id` to ask about one. Outcomes are written from inside the job, under
  `catch_unwind`, so a panicking transition cannot leave an open recorded as pending
  forever; a job that never reaches the engine is recorded as failed on the caller side.

  Only *settled* outcomes are evicted when the history fills. Forgetting a pending open
  would be worse than remembering it indefinitely: `session_status` would report it as
  unknown, which tells the caller to open again — duplicating an attach or a launch, and
  letting the original land afterwards and replace the target underneath them. The history
  can therefore exceed its bound while opens are in flight, which is self-limiting, since
  the engine runs jobs one at a time and every job settles.
- **Tool behaviour annotations.** All 37 tools now declare a title and the
  read-only / destructive / idempotent / open-world hints, so a client can tell
  `read_memory` apart from `execute` before prompting the user. `openWorldHint` is true for
  everything that touches a debug target and false only for `decode_ioctl` and
  `session_status`, which never reach the engine. Two reasons put the rest over the line: a
  symbol server on the path
  means almost any command can pull a PDB (`r` symbolizes the current instruction, `k`
  symbolizes every frame, `bp module!Symbol` resolves a name), and a KDNET session puts the
  target itself across a network link, so even a raw `read_memory` is remote traffic. A
  client may be gating network consent on that hint.
- **End-to-end smoke test** (`tests/mcp_smoke.rs`), for the two events the in-process tests
  cannot see: a dependency moving, and the MCP spec revving. Both change the bytes on the wire
  while the Rust API this crate compiles against stays identical, so the existing tests keep
  passing and clients break. It spawns the built binary and speaks hand-written JSON-RPC to it,
  asserting that stdout carries only JSON-RPC (a dependency logging there corrupts the
  transport), that closing stdin exits the process, that every protocol revision the README
  promises is served — including `2026-07-28`'s handshake-free `server/discover` and its rule
  that *every* request, not just the opener, carries the `_meta` protocol keys — and that no
  capability is advertised that this server does not implement. A golden snapshot
  (`tests/golden/tools_list.json`) records the structural `tools/list` surface (schema dialect,
  hints, parameter types) so a `schemars` or `rmcp` bump lands as a readable diff rather than a
  silent client-visible change; re-record with `UPDATE_GOLDEN=1`. The protocol tier needs no
  debugger, target, or network and runs under plain `cargo test`; a second tier
  (`WINDBG_MCP_SMOKE_DUMP=1`) opens the checked-in sample dump through DbgEng and is the
  automated check for a `win-kexp` regression, available in CI on manual dispatch. Runbook,
  including the manual checklist for the live/TTD paths no runner can host, in
  [`docs/smoke-test.md`](docs/smoke-test.md).

### Changed

- **Upgraded the `rmcp` SDK from 1.x to 3.x**, now that the 3.x line is released rather than beta.
  The practical gain is protocol coverage: 3.x knows the `2026-07-28` revision, so the server now
  answers `server/discover` and the stateless per-request lifecycle in addition to the
  `initialize` handshake, and a client that speaks *only* `2026-07-28` can now talk to it. Both
  come from the SDK's defaults (`supported_protocol_versions` covers every known revision, and
  `serve` dispatches a non-`initialize` opening request through the inline lifecycle), so no
  handler code was needed. The only source change the bump required is the `Content` →
  `ContentBlock` rename in `rmcp::model`; the tool surface, its schemas, and the tool-call wire
  format are unchanged.

- **Debugger failures are now tool-execution errors, not protocol errors.** An unresolvable
  symbol, an unreadable address, a target that never stopped, or a recorder that won't
  start now comes back as a normal tool result with `isError: true` and the debugger's text
  intact, which is what lets the model see the failure and correct itself. Previously every
  such failure became a JSON-RPC `-32603`, which clients surface as a transport-level fault
  and models largely cannot act on. Only a dead engine thread remains a protocol error.
  Semantic input validation (`decode_ioctl`'s code, `ttd_memory`'s address) moved the same
  way — the request satisfies the schema, so the complaint belongs in the result.

  The classification is made by the engine worker, which is the only place that can tell a
  failed operation apart from an engine that never came up: a `DebugEngine::new()` failure
  (missing or unusable `dbgeng.dll`) is permanent and now reports as a protocol error, not
  as a retryable tool error that invites the model to try again forever.

- **`index_trace` is now annotated destructive.** It runs `!ttdext.index -force`, which
  deletes and rebuilds an unloadable `.idx` — replacing an on-disk artifact, whatever the
  intent. `destructiveHint: false` told clients otherwise and could bypass confirmation.
- **Typed tools reject operands that would end the command they build.** They interpolate
  their arguments — `u {address}`, `bp {expression}`, `!drvobj {name} 7` — and DbgEng reads
  `;` as a command separator, so `disassemble { address: "rip; .opendump C:\other.dmp" }`
  ran a target swap from a tool advertising `readOnlyHint: true`, and did it without going
  through the check that retires session handles. Quotes are the same problem deferred:
  `bp <location> "command"` is real WinDbg syntax — `ioctl_trace` builds exactly that form —
  so a quote in a breakpoint location arms a target swap that fires on the next hit, outside
  any tool call. `;`, line breaks, and `"` are now refused with a tool error, the last
  everywhere except `dx`, whose data-model expressions use quoted literals legitimately.
  These parameters were always documented as single operands, so nothing legitimate is
  lost: `execute` remains available for command lists, and is annotated destructive and
  handle-checked accordingly.

### Fixed

- **The server no longer introduces itself as the SDK.** `serverInfo` reported
  `{"name": "rmcp", "version": "<sdk version>"}` to every client, on both the `initialize`
  handshake and the `2026-07-28` `server/discover` response — so anything that names or
  keys off the connected server (client UIs, logs, per-server config) saw "rmcp" rather
  than "windbg-mcp", and saw the SDK's version where it wanted this crate's. The
  `#[tool_handler]` macro defaults to `Implementation::from_build_env()`, whose
  `env!("CARGO_CRATE_NAME")` / `env!("CARGO_PKG_VERSION")` resolve inside `rmcp` rather
  than here; naming the server on the attribute takes both from this crate instead. The
  bug predates the `rmcp` 3.x upgrade — 1.x reported the same — so this is the first
  release in which clients see the right identity.

### Documentation

- README now states which MCP protocol revisions the server speaks — `2026-07-28` and the
  `initialize`-handshake era before it — and what a client gets from each.

## [0.2.1] - 2026-07-23

### Added

- **Discoverable via the official MCP Registry.** Each release now also builds an
  `.mcpb` bundle (`windbg-mcp-vX.Y.Z-windows-x64.mcpb`) next to the existing zip and
  publishes a [`server.json`](server.json) entry (`io.github.glslang/windbg-mcp`) to
  [registry.modelcontextprotocol.io](https://registry.modelcontextprotocol.io) via the
  `mcp-publisher` CLI, authenticated with GitHub OIDC (no secrets). The bundle's
  descriptor is [`packaging/mcpb/manifest.json`](packaging/mcpb/manifest.json); CI stamps
  the release version into both files and the bundle's SHA-256 into `server.json`, so a
  release keeps the same manual bump list as before — Cargo.toml, plugin.json, the README
  badge, and CHANGELOG.

## [0.2.0] - 2026-07-22

### Added

- **Static IOCTL dispatch reachability.** A new `reachable_from_dispatch` tool answers
  whether a code block — given as an absolute address or `module`+`rva` — is reachable from
  a driver's IOCTL dispatch routine, via a bounded breadth-first walk over the call graph
  built from repeated `uf` disassembly. It follows direct calls and cross-function tail
  jumps; it does **not** follow indirect calls through function pointers or unresolved
  compiler jump tables, so a `REACHABLE` verdict is sound (and reports the call path) while
  `NOT REACHABLE` is a best-effort within-bounds result. The `uf`-parsing and graph-walk
  logic is pure and unit-tested (no debugger needed).
- **Driver IOCTL discovery & user-mode reachability.** A new
  [`driver-ioctl.md`](skills/windbg-debugging/driver-ioctl.md) playbook documents a
  static-first, dynamic-confirm workflow for enumerating a driver's IOCTL surface and
  testing whether each code is reachable from user mode (the openable → namespace →
  deliverable → handled gate model), with WinDbg-native (`uf`) static enumeration by
  default and Binary Ninja as an optional escalation. Five supporting tools:
  - `decode_ioctl` — decode a 32-bit control code into its `CTL_CODE` fields and flag
    `METHOD_NEITHER` / `FILE_ANY_ACCESS` (pure; no session needed).
  - `driver_object` — dump a driver's dispatch table + devices (`!drvobj <name> 7`).
  - `device_object` — inspect a device object's type/characteristics/SecurityDescriptor
    (`!devobj`) to answer the *openable* gate.
  - `irp_stack` — dump an IRP's current `IO_STACK_LOCATION` (`!irp`), defaulting the IRP
    to `@rdx` at a dispatch break.
  - `ioctl_trace` — install a conditional logging breakpoint at the IOCTL dispatch
    routine that prints each `IoControlCode` + buffer lengths and continues.
  - An `examples/sweep_ioctls.ps1` harness (host) + `examples/send_ioctls_target.ps1`
    (target-side `DeviceIoControl` sender) driving the dynamic confirm sweep.
  - `attach_kernel` / `attach_kernel_local` now `.load kdexts` automatically so the
    `!drvobj`/`!devobj`/`!irp` commands behind `driver_object`/`device_object`/`irp_stack`
    resolve; `setup.md` bundles `winxp\kdexts.dll`. Verified end-to-end against a live
    KDNET kernel (the tools captured real mountmgr IOCTLs).
  - [`docs/driver-ioctl-walkthrough.md`](docs/driver-ioctl-walkthrough.md): a worked
    `\Driver\mountmgr` enumeration + reachability report against a live kernel. The
    playbook now ends with a "Write the report" step + template.
- **`record_trace` `env` and `working_dir` options** — pass extra `KEY=VALUE` environment
  entries and a working directory to the recorded target, for programs that refuse to run
  without a specific environment (e.g. a Qt app's `QT_QPA_PLATFORM_PLUGIN_PATH`, or an
  anti-analysis "run me from here" guard). Previously the recorder only inherited the
  server's environment.

### Fixed

- **`index_trace` now works.** It invoked `!tt.index`, which fails with `LoadLibrary(tt)` —
  there is no `tt` extension. The bundled engine exposes trace indexing through `TtdExt.dll`,
  so `index_trace` now runs `!ttdext.index` (building a persistent `.idx` next to the `.run`).
- **`open_trace` flags an unindexed trace.** A freshly recorded `.run` has no `.idx`, so the
  first data-model query silently builds an in-memory index and can run long; `open_trace`
  now says so up front (via `!ttdext.index -status`) and points at `index_trace`.
- **`registers` no longer returns a blank result** when there is no thread context (a
  module-load break or a bare `goto_position 0`); it explains why and how to get a context.
- **A runaway debugger command no longer wedges the session.** `execute`, `dx`, and the
  `ttd_*` query tools now run through a bounded path
  ([`win-kexp`](https://github.com/glslang/win-kexp)'s `execute_command_bounded`) that
  `SetInterrupt`s the engine shortly before the per-call timeout. Previously an unbounded
  command — most importantly a broad `s` memory search — could pin the single engine thread
  indefinitely, so every later tool call timed out behind it and the only recovery was to
  kill and reconnect the server. Now such a command self-aborts (with a note) and the engine
  stays usable. (win-kexp pin bumped to include `execute_command_bounded` + its interrupt drain.)

## [0.1.3] - 2026-06-14

### Fixed

- Ending a live-kernel session (`end_session`) no longer leaves the target
  **frozen**. It was a passive detach, which never tells the target to run, so
  detaching while halted at a break left the guest frozen — one CPU halted, the
  rest spinning — with the breakpoint `int3` still patched. `end_session` now
  clears breakpoints, resumes the target, and does an active detach, leaving the
  kernel running. (win-kexp `777b5c2`.)

## [0.1.2] - 2026-06-14

### Fixed

- **Live kernel debugging now works.** `attach_kernel` / `attach_kernel_local`
  connect, request an initial break-in, and wait with the INFINITE timeout a live
  kernel requires — a finite timeout returned `E_NOTIMPL` and never drove the
  connection — so the engine breaks in, breakpoints resolve, and `go` runs to them.
  The wait is bounded by a watchdog (`SetInterrupt`) so the single engine thread
  can't hang on an unresponsive target; a forced timeout is reported as an error.
- A failed kernel attach now returns a clean error instead of panicking the
  debugger worker thread.
- `go`/step with no active debuggee now returns a clear "No active debuggee" error
  instead of crashing the server (a previously uncatchable engine fault).

### Added

- Example stdio JSON-RPC drivers under `examples/` (live-kernel attach, user-mode
  launch, and robustness regression checks).

### Changed

- The live/kernel skill now instructs asking the user for the target's actual KDNET
  connection string (the port and key can't be guessed).
- CI auto-approves and auto-merges Dependabot PRs.

## [0.1.1] - 2026-06-12

### Added

- Prebuilt Windows x64 binary releases: pushing a `vX.Y.Z` tag now builds
  `windbg-mcp.exe` and attaches `windbg-mcp-vX.Y.Z-windows-x64.zip` (plus a SHA256
  checksum) to the GitHub release, and the setup docs gained a no-Rust install path
  that downloads it into `target\release\`.
- Signed build-provenance attestations for release zips, verifiable with
  `gh attestation verify` (see the README's *Releasing* section).

### Security

- GitHub Actions in the CI and release workflows are pinned to immutable
  commit SHAs, with Dependabot configured to keep the pins (and their
  version comments) up to date.

## [0.1.0]

Initial release, packaged as a single-plugin Claude Code marketplace.

### Added

- **`windbg` MCP server** (Rust, stdio) exposing DbgEng-backed debugging tools:
  session management (open dump/trace, attach to process/kernel, launch, end),
  state queries (registers, memory read, backtrace, modules, threads,
  disassemble, `dx`), execution control (go, step over/into, breakpoints), Time
  Travel Debugging navigation (step back, reverse go, goto position) and
  analysis (`ttd_calls`, `ttd_memory`, `ttd_events`, index), TTD trace recording,
  and a raw `execute` command passthrough.
- **`windbg-debugging` skill** with task playbooks: setup, crash-dump triage,
  live/kernel debugging, and TTD recording/replay/analysis.
- Crash-dump `!analyze` support via automatic WinDbg extension DLL loading.
- Windows CI (format, clippy, build, test) and walkthrough docs with sample dumps.

[Unreleased]: https://github.com/glslang/windbg-mcp/compare/v0.14.0...HEAD
[0.14.0]: https://github.com/glslang/windbg-mcp/compare/v0.13.2...v0.14.0
[0.13.2]: https://github.com/glslang/windbg-mcp/compare/v0.13.1...v0.13.2
[0.13.1]: https://github.com/glslang/windbg-mcp/compare/v0.13.0...v0.13.1
[0.13.0]: https://github.com/glslang/windbg-mcp/compare/v0.12.1...v0.13.0
[0.12.1]: https://github.com/glslang/windbg-mcp/compare/v0.12.0...v0.12.1
[0.12.0]: https://github.com/glslang/windbg-mcp/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/glslang/windbg-mcp/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/glslang/windbg-mcp/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/glslang/windbg-mcp/compare/v0.8.1...v0.9.0
[0.8.1]: https://github.com/glslang/windbg-mcp/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/glslang/windbg-mcp/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/glslang/windbg-mcp/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/glslang/windbg-mcp/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/glslang/windbg-mcp/compare/v0.4.2...v0.5.0
[0.4.2]: https://github.com/glslang/windbg-mcp/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/glslang/windbg-mcp/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/glslang/windbg-mcp/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/glslang/windbg-mcp/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/glslang/windbg-mcp/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/glslang/windbg-mcp/compare/v0.1.3...v0.2.0
[0.1.3]: https://github.com/glslang/windbg-mcp/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/glslang/windbg-mcp/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/glslang/windbg-mcp/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/glslang/windbg-mcp/releases/tag/v0.1.0
