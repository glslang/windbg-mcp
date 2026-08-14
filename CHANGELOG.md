# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
  - **A filter cannot add a line to the listing.** It is quoted into the text, and the listing is
    line-oriented, so anything in it that could start a new line is rendered as an escape rather
    than acted on — otherwise a pattern carrying a newline and something shaped like a row would
    put a module in the text that the values beside it do not have, which is the one property this
    change is for. (Until now the filter was command text, and the `;` check refused line breaks
    along with the separator; the command went, and that refusal with it.) Escaped rather than
    refused, because "nothing matches this" is a good answer to a pattern nothing is named — and
    because it covers `\r` and an ANSI escape for the same money. The guard is Unicode's whole
    line-break set, not `char::is_control`: `U+2028`/`U+2029` are `Zl`/`Zp` rather than `Cc`, break
    a line in a renderer that knows Unicode, and are invisible to `str::lines` — so to a test
    written around it.
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

### Added

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

[Unreleased]: https://github.com/glslang/windbg-mcp/compare/v0.8.1...HEAD
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
