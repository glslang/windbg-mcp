# Smoke test

`tests/mcp_smoke.rs` drives the **built binary** over stdio with hand-written JSON-RPC. It exists
for the two moments the in-process unit tests in `src/server.rs` cannot cover: **a dependency
moved**, and **the MCP spec revved**. Both change the bytes on the wire while the Rust API this
crate compiles against stays identical — so the unit tests keep passing and clients break.

## Running it

```pwsh
cargo test --test mcp_smoke              # protocol tier (default)
$env:WINDBG_MCP_SMOKE_DUMP = "1"; cargo test --test mcp_smoke   # + the debugger tier
```

It builds and runs against `target/debug`, so it never touches the `target/release` exe a
connected MCP client holds a lock on (see [`CLAUDE.md`](../CLAUDE.md)). The protocol tier is ~2s;
adding the debugger tier takes it to ~50s, almost all of it two tests waiting out real timers — a
lease grace, and a call staying silent long enough to have to report that it is still running.

### Tiers

| Tier | Gate | Needs | Catches |
| --- | --- | --- | --- |
| **Protocol** | always | no debugger, no target, and no network off this machine — it does bind a loopback port for the listener | transport, revision negotiation, tool-surface drift, and the listener's lease up to the point a session is opened |
| **Debugger** | `WINDBG_MCP_SMOKE_DUMP=1` | `dbgeng.dll`, the checked-in sample dump | `win-kexp` / DbgEng regressions, and a lease expiry releasing a real engine worker |
| **Bounded command** | `--ignored` | `dbgeng.dll`, the sample dump, ~1 minute | the watchdog wiring, which now spans two processes |
| **Live kernel** | `--ignored` + `WINDBG_MCP_SMOKE_KERNEL` | a live kernel target you can freeze — KDNET, or serial | that a kernel attach *lands*, coexists, and is let go — by `end_session` and by a disconnect; and that a `debug_batch` which patches a byte of the running kernel puts it back |
| **MessageManager CTF** | `--ignored` + live-kernel gate + `WINDBG_MCP_SMOKE_CTF=1` | the challenge VM, WinRM, full `nt` symbols | the real driver and retained `Tgsm` pool objects through the shipped MCP transport |
| **Live (other)** | manual | TTD engine, elevation, a test driver | see [Manual checklist](#manual-checklist) |

The protocol tier rides `cargo test`, so CI already runs it. The debugger tier is opt-in
*locally* but runs on every push and PR in CI, as the **Smoke test (debugger tier)** job — it is
the only automated check of the properties process-per-session exists for, and it needs no symbols
and no network. It runs **twice, on x64 and on ARM64** (`windows-11-arm`), because the thing it
exercises that nothing else does is a real `dbgeng.dll`, and there is a different one on each
([#134](https://github.com/glslang/windbg-mcp/issues/134)). The two entries do not share a cargo
cache, and an ARM64 failure does not cancel the x64 run.

**Four of its assertions read the target's memory rather than the dump's structure, and they stand
down on a host whose engine cannot.** A kernel dump's virtual addresses are translated through
structures the engine locates with `nt`'s **symbols**: a host that resolves none still reads the bug
check, the module list and the stack — all of which come out of the dump's own headers — and fails
every read behind them with `0x8007001E`. So `walk_memory`, `disassemble` and the `EPROCESS` read
behind `crash_triage`'s `process_name` have nothing to assert there.

That is what [#142](https://github.com/glslang/windbg-mcp/issues/142) turned out to be. It was read
as an *architecture* limitation — an ARM64 engine unable to follow a pointer into an x64 dump — and
it is not one. Measured on one ARM64 host:

- with the SDK's `dbghelp.dll` and `symsrv.dll` beside the binary, one engine reads **both** x64
  samples and the ARM64 one completely — private symbols, the `EPROCESS`, the driver frame at its
  literal RVA. The whole tier passes there, 60 of 60;
- with nothing beside the binary — System32 ships `dbghelp.dll` and **no** `symsrv.dll`, so a
  `srv*` path downloads nothing — it reproduces the CI failure exactly, down to the address and
  `0x8007001E`;
- and with the full bundle but `_NT_SYMBOL_PATH` pointed at an empty directory it fails again, and
  fails *differently per dump*: the ARM64 sample reads nothing at all, while the x64 sample gives
  up a module base and then walks a stack of the bug check's own parameters. Neither is an answer,
  and only one of them looks like a failure.

Same engine, same dumps: symbols are the variable, and the engine's architecture is not.

So they **ask the host** instead of guessing from `cfg!(target_arch)`, and each asks for the
premise it actually has. `walk_memory` and the batch work on numeric addresses, so they need only
that `nt`'s base reads — asked with a `dq` through `execute` rather than through the tools under
test, since a regression in `walk_memory` must not be able to silence the test that catches it.
`crash_triage` and the driver attribution walk `nt`'s *types* — the `_EPROCESS` behind
`process_name`, and a stack walk that gets past the bug check's own parameters — so those two also
require `nt` to have resolved to a **PDB**. Either way the test prints `SKIPPED` with the reason
and what still holds, which is what an `ignore` keyed to an architecture could never say.

**The two conditions are separate because they fail apart, which the ARM64 CI entry demonstrated
the hour this was written.** A first version asked only for the read. The three tests on the ARM64
sample stood down correctly there — nothing in that dump reads on a runner with no `symsrv.dll` —
while the driver-crash test, which keeps its x64 dump on every architecture, found that dump's
module base perfectly readable, walked a stack made of the bug check's own parameters, and failed
an attribution assertion for a reason that had nothing to do with attribution. Asking *both*
questions of all four would have been the other easy mistake: it stands `walk_memory` and the batch
down on a host where they are perfectly testable.

The worry that a symbol condition silences assertions passing today is settled rather than assumed:
the x64 entry reads `mm_exploit_v5.exe` out of `SeAuditProcessCreationInfo`, a walk through `nt`'s
types that cannot happen without its PDB, and its run shows all four *running* rather than skipping.

**The sample they open follows the host.** Three dumps are checked in (below), and the two crashes
a *memory* read is asserted against are paired with the architecture the tests are running on — so
an ARM64 run reads an ARM64 target, which is coverage this suite has nowhere else
([#143](https://github.com/glslang/windbg-mcp/issues/143)). That pairing is a choice about what to
cover rather than a workaround: with symbols, either engine reads either dump, and the driver-crash
assertion below deliberately opens the x64 dump on every architecture because what it asserts is a
property of *that* crash. The bounded-command and live-kernel tiers are `#[ignore]`d — one is measured in
minutes, the other touches another machine; see below. Neither is automated, and the rest of the
live checklist is not either: no runner has a kernel target, a TTD engine, or elevation.

## What it asserts, and why each one is a dependency tripwire

**Transport.** Every line the server writes to stdout parses as JSON-RPC, and the startup log
appears on **stderr**. A dependency that prints a banner or a warning to stdout desynchronizes
every client, and the client-side symptom is an unreadable parse error. Also: closing stdin exits
the process within 20s (otherwise each client disconnect leaks a process and a DbgEng session),
and a malformed input line does not kill the session. Under process-per-session that last one has
teeth: a disconnect must also take every **engine worker** process with it, which the debugger tier
checks by pid.

**Protocol revisions.** Every revision the README promises — `2026-07-28`, `2025-11-25`,
`2025-06-18`, `2025-03-26`, `2024-11-05` — is offered a handshake, served *that* revision, and can
reach `tools/list` — whose reply carries SEP-2549's `ttlMs`/`cacheScope` on `2026-07-28` and omits
them on the revisions that predate the fields. Those come from the SDK, so the assertion guards the
`rmcp = "3.1.1"` floor: earlier 3.x omitted them everywhere, and a client validating against the
spec schema then rejects the *whole* list, leaving a server that connects and appears to have no
tools. The reply is a valid JSON-RPC result either way, so no error-shaped assertion can see it.
An unknown revision negotiates down to `2025-11-25`. `server/discover` opens a
session with no handshake at all, and — the rule that is easy to get wrong — in that stateless mode
**every** request must carry the `_meta` protocol keys, not just the opener; a request without them
is refused with `-32602`.

**Capability honesty.** `tools` is advertised; `resources`, `prompts`, `completions`, `logging` and
`extensions` are not, because none are implemented. `tasks/get` answers `method_not_found`
(deliberate — [`FOLLOWUPS.md`](../FOLLOWUPS.md) item 8). If an SDK bump starts advertising something
on this server's behalf, this test is where you find out, and the choice is implement it or
suppress it — not ship an advertisement clients will call into a dead end.

**Tool surface golden.** `tests/golden/tools_list.json` records the *structural* `tools/list`
surface as it appears on the wire: JSON Schema dialect, `$defs` usage (`true` since `debug_batch`
introduced the first nested schema), tool count, and per tool its
name, title, four behaviour hints, required arguments, each parameter's type/format/enum, and — for
the tools that declare one — the shape of its `outputSchema`: the dialect, and for each branch of
the result union its `status` const, the payload type it references, and what that branch requires.
It deliberately excludes descriptions, so prose edits do not churn it while a `schemars` dialect
switch, an `rmcp` annotation-casing change, a discriminator that stops being emitted, or an
accidental tool rename all land as a readable line diff.

Re-record after an *intended* change, and read the diff before committing:

```pwsh
$env:UPDATE_GOLDEN = "1"; cargo test --test mcp_smoke tools_list_matches
```

**Schema resolvability.** Every tool's input schema is an object schema whose `$ref`s all resolve
inside the same document. External or dangling refs break strict client-side validators, and a
codegen dependency can introduce them with no change here.

**Kernel connection secrecy.** `attach_kernel` takes exactly one of `connection` and `profile`, and
the schema cannot say so — both are optional there, deliberately (an untagged `oneOf` renders as a
schema composition clients handle unevenly). So the exclusivity is this server's own check, and
these tests are what hold it: both selectors and neither are each refused as a **tool** error naming
the alternative, and neither refusal spawns a worker. A profile that does not exist is answered with
the names that do, and a connection string typed into `profile` — the mistake that would defeat the
whole feature — is refused *without being echoed back*. Every one of these runs a fake profile
(`WINDBG_MCP_PROFILE_SMOKE_KDNET`, pointed at a documentation-range address) and asserts that key
appears on neither the JSON-RPC transport nor the log, checked against every line the server ever
wrote rather than against one result. `WINDBG_MCP_PROFILES` is pointed at a path that does not
exist, so a developer's real profiles can never be read into a failure message.

**Session transcripts.** A server is started with `WINDBG_MCP_TRANSCRIPT` pointed at a temporary
file, driven through a few calls, and shut down; the file is then read back as JSONL and asserted
on — every line a complete object, the calls in the order they were made, a `start` first and a
`shutdown` last, and sequence numbers that only increase. One of those calls passes a raw KDNET
connection (refused for its shape, so nothing dials and no test waits on a network), and the key
must appear nowhere in the file's **bytes** — checked against the whole file rather than a parsed
field, because a key that leaked into a corner nobody thought to look at is still a leak. Every
line the server wrote to stdout is then re-parsed as JSON-RPC, which is the claim that a transcript
being written cannot corrupt a client's connection.

A second test covers the other selector: a server recording, three `attach_kernel` calls that route
through a configured **profile** (an unknown name, the empty listing, and the connection string
typed into `profile`), and the profile's key absent from the file — while its *name* is still
readable, because a transcript has to say which target a session was pointed at. It also counts the
calls it recorded, so the absence assertion cannot pass on an empty file.

A third pins that recording is opt-in, and it uses **the same path twice** — which is the only way
that claim can be tested. A path the server was never told about could not be written whatever the
default was, so asserting it stays absent asserts nothing; here the first run proves the server
does write that exact file when asked, and the second, with the variable unset, proves it does not
when it is not.

The same executable is then run as `--render-cast` over that transcript, and the result is
validated as asciicast v2: a version-2 header with a shape, then events that are `[time, "o", data]`
triples whose times never go backwards. In the **protocol** tier deliberately — every property here
is about the shipped binary reading an environment variable, opening a file beside a live transport,
and reaching its own renderer, and none of that is provable in-process. `src/record.rs` and
`src/cast.rs` cover the shapes. A companion test asserts the opposite case: a server nobody asked to
record writes no file at all.

**Debugger tier.** Opens the checked-in kernel crash dump, confirms it mints a `session_id` that
`session_status` reports, reads it through `modules` / `registers` / `backtrace`, then checks the
session-handle contract on the wire (a stale handle is refused; the handle stops working once
`end_session` runs). It also pins the `isError` contract against a real engine: `threads` is `~`,
which DbgEng implements only in user mode, so on a kernel dump it must come back as a **tool error
carrying the engine's message** — not a JSON-RPC error, and not a dead session. Read-only
throughout, and it needs no symbols, so it runs offline.

It checks what an **open** hands back, which is a summary rather than the module table: the count
and the kernel's base against `modules`, the bug check against `crash_triage`, and the report
itself against the table it replaced — it has to be the shorter of the two. And it checks
`modules { "filter": … }` from both ends at once: the listing's rows are **parsed back as records**
and compared to the values for equality — same rows, same order, no others — filtered and
unfiltered alike. That is a stronger claim than the one this tier used to make ("every module the
values report appears somewhere in the text"), and it is the claim that
[#120](https://github.com/glslang/windbg-mcp/issues/120) made checkable: both halves are rendered
from one set of `IDebugSymbols3` records, where the text used to come from `lm m <pattern>` and the
values from a second implementation of its pattern grammar. It is also what proves no `lm` runs
here — that listing's backtick addresses, `Browse full module list` line and `Unloaded modules:`
tail do not parse as rows. A filter can match only *unloaded* images — `nvhda` on this sample,
twenty-six `nvhda64v.sys` and no loaded module — so those are checked in their own `unloaded` list,
matched by image name (the only name they have), each carrying the engine's `unloaded` flag, and
row-for-row against the text above. What used to be refused is checked as being *matched
literally* now: `nt[fd]*`, `n\t*`, `nt v`, `nté` and `nt; .detach` each come back as an empty
listing in both channels rather than as an error, and the session is still the dump it was
afterwards — there is no command for a `;` to end. The one refusal left is a filter that narrows by
nothing.

It also triages the dump's bug check (`crash_triage`), which is the one place the tier depends on
the sample being a *crash* dump rather than any dump: the `0x9F` code and its four parameters read
through `ReadBugCheckData`, the stack walked and attributed to `nt` by load base, and the crashing
process read out of the current `_EPROCESS` — asserted as `System`, because the engine's own
`GetCurrentProcessExecutableName` answers `ntkrnlmp.exe` there for every process that has ever run
and that regression is invisible in any other check. `!analyze`'s half is checked for coherence
rather than for having run: a host with no `winext\ext.dll` has to say *why* the analysis is
missing rather than silently omit it, and a run that *did* happen is checked for shape — that its
parameter notes stay positional, and that the bucket is derived from the bug check code — rather
than for exact strings, which belong to whichever `ext.dll` the host has and would fail this tier
on a different WinDbg instead of on a change here.

**The coordinate, checked across the three tools that compute one.** `crash_triage`, `backtrace`
and `disassemble` each answer with `module` + `rva` — the offset into an image, which is what
survives a reboot and joins against a disassembler ([`coordinates.md`](./coordinates.md)). Nothing
in the code makes them *disagree*, because they share one walk and one renderer; this is the check
that says so from outside, where a future refactor can see it. `crash_triage` is run with
`analyze: false` and its frames compared field-for-field against `backtrace`'s — `!analyze -v` ends
with the scope at the target's default, so with it off neither call moves anything and the two
stacks are the same stack rather than two that ought to match. Then `disassemble` with no address,
which starts at the program counter, is checked to report the same `address`, `rva` and `module` as
frame 0.

The shape assertions around them hold on a host that resolves nothing: frames are in walk order,
`module` and `rva` are one coordinate and travel together (an `rva` with no `module` is an offset
from nothing), an RVA is unpadded because it is pasted after `module+` rather than sorted, and an
instruction's operands carry no ``fffff801`3c677ef0`` address form — the eight-hex/backtick/eight-hex
pattern specifically, not every backtick, since MSVC decorates real symbols with them and those are
deliberately kept.

**The other half of the coordinate is the identity**, and it has its own premise. `modules` reports
`timestamp` + `size` — the pair a symbol server is keyed by — and, for a module whose symbols the
engine has actually resolved, the `pdb` identity: `guid`, `age`, and the `key` those make. The
assertion checks the GUID's spelling (32 uppercase hex digits, no braces, no dashes) and that `key`
is the GUID with the age **in hex**, which is the composition whose failure mode is a URL that
404s. It is gated on `engine_resolves_kernel_symbols` and on nothing else — not on the target read that
guards the frame assertions, because it needs none: `modules` and the engine's own symbol
bookkeeping answer this without touching a page. The two premises fail apart in both directions, so
nesting it under the read gate would skip a check on a host perfectly able to run it. The hex/decimal confusion itself cannot
be caught here at all: a real `nt` reports age 1, where the two are identical, so that is pinned by
an offline unit test beside `PdbInfo` using age 26.

**A second dump, because the first one could not fail the right way.** The `0x9F` sample is a
watchdog bug check: it fires on an idle CPU's timer DPC, so there is no driver frame on its stack
at all, and it exercises the *absent* `faulting_frame` branch and never the one the tool exists
for. Its process is `System`, short enough to fit the 15-byte `_EPROCESS::ImageFileName` field the
process read originally used — so the truncation that field causes was invisible here too, and
turned up only against a real driver crash whose process was `mm_exploit_v5.exe` (reported as
`mm_exploit_v5.`). Two bugs hiding behind a green tier, both because a convenient fixture is not a
representative one.

So [`docs/samples/081226-2187-01.dmp`](samples/081226-2187-01.dmp) is checked in beside it: a
`0x13A` raised out of `nt!ExFreePoolWithTag` by a **PDB-less** third-party driver. It pins the
claims the other dump structurally cannot — a `faulting_frame` that exists, six frames below the
top and under a stack of allocator internals that a "blame frame 0" rule would name instead; that
frame as `MessageManager+0x1654`, an RVA asserted as a literal because it is a fixed offset into a
fixed image and was identical across five dumps that loaded the driver at five different
addresses; `symbol` absent rather than filled in with the module's own name; a `pool_tag`, which
only `!analyze` produces; and a process name longer than fifteen characters.

**A third dump, because neither of those is an ARM64 target.** The tier runs on ARM64 and, until
[#143](https://github.com/glslang/windbg-mcp/issues/143), read nothing there: the assertions that
touch a target's memory were gated off, so what the ARM64 entry proved was the protocol, the
session machinery and a module list. [`docs/samples/121524-4703-01.dmp`](samples/121524-4703-01.dmp)
is a `0xFC ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY` off this project's own ARM64 debuggee — a
user-mode process jumped into memory that is not executable, and the kernel bug-checked out of
`nt!MiCheckSystemNxFault`. It is 440 KB, the smallest of the five real crashes that machine had,
because every clone carries it for ever.

What it adds is an **ARM64 `_EPROCESS`, an ARM64 image's headers and an ARM64 stack's frames**,
read through the same three claims the x64 samples make. The fourth claim — attributing a frame to
a third-party driver — is still asserted only against an x64 stack, because there is no ARM64
driver crash to assert it on; that is [#154](https://github.com/glslang/windbg-mcp/issues/154), and
it needs a crash produced rather than a sample found. It also pins the one branch of the process
read that nothing else reaches: this dump does not capture the pool page `SeAuditProcessCreationInfo`
points at, so the engine falls back to the 15-byte `_EPROCESS::ImageFileName` and the answer is the
truncated `stack_buffer_o` — the fallback that the driver crash above, with its full
`mm_exploit_v5.exe`, exists to prefer.

Those checks are made against **typed fields** wherever a tool has them (issue #84): the handle is
read from `structuredContent`, not from a `session_id:` line; `nt` and `hal` are matched as module
records rather than as the third token of a rendered row, which is what used to break on a column
shift and name the wrong cause; the stale-handle refusal is checked by its `stale_session` category
rather than by its wording. A field is a contract; the text beside it is a rendering, and rewording
it must not fail a test. The one exception is deliberate: `tool_text` still exists and is still used
where the *rendering* is the thing under test (a batch report, an interrupted call's note).

It also covers process-per-session, which cannot be checked any other way — the claims are about
processes, so they need real ones:

- *Two sessions coexist.* Two dumps open at once, and the first handle still works after the second
  open landed. Under the single-engine design this was impossible by construction.
- *A kernel attach that never connects costs one session.* An `attach_kernel` at a dead port parks
  exactly as a guest that is not in debug mode would; the test then opens a dump **while it is
  parked** (the regression test for [#61](https://github.com/glslang/windbg-mcp/issues/61)) and
  reclaims the parked session with `end_session`, checking by pid that the worker process is gone.
  It skips itself if the attach fails outright instead of parking (a busy UDP port), because there
  is nothing to assert about a park that did not happen.
- *A profile-named attach opens a session and discloses no key.* The same dead-port park, opened by
  `profile` instead of `connection`: `session_status` names the profile and reports the connection
  as `key=<redacted>`, and the key is absent from the transport and the log for the whole life of
  the session. The unit tests prove the resolution and the redaction; only this proves they hold
  over the wire, which is where [#81](https://github.com/glslang/windbg-mcp/issues/81) was.
- *No worker outlives the connection.* Reads the engine pid out of `session_status`, disconnects,
  and checks the process is gone — otherwise every disconnect leaks a debugger process, and for a
  launch or an attach, a debuggee with it.
- *A batch commits or fails, and its rollback runs either way.* `src/batch.rs` proves the executor
  over a scripted debuggee; this proves the wiring — argument schema, the op crossing the pipe, the
  engine seam, the report coming back — by running one batch to `COMMITTED` (with a capture bound
  from one step and interpolated into the next) and one to `FAILED at step 2 of 3`, with the same
  `always` block on both. The claim only a real engine can settle is the second one: the rollback
  ran **inside the worker process**, on the failing path, before the tool call returned. Both
  outcomes are read from the **typed** half as well as the prose — `outcome`, `at`, `committed`,
  `rollback_complete`, each step's `result`, the interpolated `action` — because that half is what
  a transcript records and what a client branches on, and the two agreeing is what keeps the report
  honest. It also pins the pairing only this tool has: a batch that ran answers `status: "ok"` on a
  result flagged `isError`.
- *A transcript records both teardowns and invents neither.* Two sessions, one ended by hand and
  one left to the disconnect, and the file has to account for both — a disconnect has no caller to
  answer, so the transcript is the only record of whether each target was released or a worker was
  killed still holding one. The other half is the absence: an `end_session` terminates its worker
  on purpose, so the pipe reaching EOF is the teardown finishing, and a "lost its engine" record
  after it would report a failure that did not happen.
- *A call that names no session records the one it reached.* Two sessions open and a `modules` call
  with no `session_id`, which routes to the newest. With one session open this proves nothing —
  any answer would be right — which is why there are two.
- *A session reclaimed at the limit records what became of it.* The third way a target is let go,
  after `end_session` and a disconnect: opening past `MAX_SESSIONS` reclaims the oldest idle
  session in a background task, with no caller to answer and nothing in the tool result to say it
  happened. The test opens one past the limit and waits for the record rather than assuming it has
  landed, so a reclamation that never reports is this assertion failing and not a puzzle later.
- *A walk marks what it cannot read and keeps going.* The claim
  [#103](https://github.com/glslang/windbg-mcp/issues/103) is about, and the one that needs a real
  engine: `src/walk.rs` proves the traversal against a fake address space, and this proves the
  holes behave the same when they are DbgEng's. It asserts the **contrast** rather than describing
  it — `execute { "? poi(0x1000)" }` fails outright (the low 64 KB is reserved on every Windows
  target, so it needs no knowledge of this dump), while `walk_memory` returns the same address as a
  row between two module bases whose `MZ` it really read. Then array mode over the `nt` DOS header
  at its own field widths, and a chain from that unmapped address, which must stop with
  `unreadable_link` **naming the node** and carry the engine's reason for reading nothing at all.
- *A pool walk takes this server's deadline, not the walker's default.* Asserted against the
  worker's log (`RUST_LOG=windbg_mcp=debug`) rather than against the answer, because on a dump the
  number has no visible consequence — the pool is local memory, so every budget from 15s to 120s
  produces the identical result. That is exactly why it shipped wrong
  ([#75](https://github.com/glslang/windbg-mcp/issues/75)): the query carried no deadline at all and
  quietly took win-kexp's 120s however long its caller was willing to wait, and nothing that looked
  at results could see it. The test shrinks the call budget to 60s and checks the worker derived
  ~45s — a range, since the milliseconds already spent come off the patience, and one that contains
  neither the 15s floor nor the 120s default. The query itself is allowed to fail: the sample dump
  has no pool-layout symbols on a bare machine (that is the live tier's business), and the budget is
  derived before the first page is read.
- *A running command is interrupted on request.* A `.for` sized to run for hours is stopped by
  `interrupt` while its `execute` call is still outstanding, comes back **as a result** carrying
  what it reached, and the session serves the next call. It belongs in this tier rather than the
  bounded one below because nothing waits out a deadline: the break lands in milliseconds
  (measured: 203ms), and the test bounds the session's call budget to 30s so a *failure* fails fast
  — anything at the watchdog's 15s floor means the deadline did the work and the run proves nothing
  about the request path, which the assertions say. The claim only the shipped binary can settle is
  that the interrupt is answered by the worker's **request reader** rather than queued for its
  engine thread: queued, it would be read only once the command had ended, and every other
  assertion here would still pass. The test retries the interrupt until it reports it reached
  something, because the worker claims the job a moment after the request is written and an
  interrupt landing in that gap correctly binds to nothing — racing it is the test's problem, not
  the server's. Proof it was cut short is the loop counter in `$t0`, as in the bounded tier.
- *A teardown mid-batch rolls it back first.* Two tests, one per teardown, both with a batch parked
  in twenty seconds of `.sleep` steps. `end_session` gets the version with a client still attached:
  it returns in seconds rather than waiting the batch out, and the batch's own call comes back
  `BATCH: ABANDONED` with the rollback complete. The **disconnect** version has nobody left to
  report to — client, supervisor and worker are all gone by the time it is checked — so the rollback
  writes a file (`.logopen`/`.echo`/`.logclose`) and the assertion is made against the filesystem
  afterwards, which is as close as a dump gets to the byte a live target would have restored. Both
  wait for a marker the batch's *first* step writes before tearing anything down: timed with a sleep
  instead, a slow machine would test the refuse-to-start path and pass just as green.
- *Interrupting a batch stops it and rolls it back, keeping the session.* The same twenty-second
  batch, stopped with `interrupt` instead: `BATCH: INTERRUPTED`, rollback complete, and the session
  still usable afterwards — which is the whole difference from the `end_session` version above.
  The assertion that carries it is a **second marker file** written by a step *after* the sleeps: a
  batch that ignored the interrupt reaches it, and the file says so independently of what the report
  claims about itself. That is the bug the interrupt itself created, and it needs a real engine to
  reproduce: an on-request interrupt returns the output the command reached rather than the error the
  break provoked, so the interrupted step comes back `Ok` with its assertions intact and the executor
  saw a step that simply ran. `src/batch.rs` pins the executor's half against a scripted debuggee,
  which answers `Ok` to the interrupted step for exactly this reason.
  It records a transcript too, because this is the only place the *interrupted*-transaction half of
  the [#87](https://github.com/glslang/windbg-mcp/issues/87) contract is real: an `interrupt` that
  genuinely reached a running batch, recorded as its own cause, followed by a verdict whose
  `outcome` is `interrupted` and whose `rollback_complete` is true — as fields, which is what an
  unattended run has to be able to act on rather than a paragraph it would have to match on.
- *Interrupting a batch during its **rollback** is refused.* The severe half of the same problem,
  and it needs no earlier interrupt to set up: cleanup is reached on every path, so a *first* break
  landing there hits a restore command — recorded as a step that worked, reported as `rollback:
  COMPLETE`, with the target still changed. The batch's `always` block writes a marker when it
  starts and another when it finishes, so the interrupt is staged on the first and the second is the
  proof the rollback ran whole; the refusal has to say it is a rollback, or it reads as a bug.

**The listener's lease.** `--listen` gives up the one property stdio has for free: a closed stdin
means the client is definitively gone, and every target is released. Over HTTP a silent client is
indistinguishable from one that is thinking, so a **lease** stands in for that moment — and it is
the only part of this server whose failures cost a *target* rather than a call. Every rule of it has
unit tests in [`listen.rs`](../src/listen.rs) against the state machine directly; what those cannot
reach is the wiring, which is what these assert against a real listener on a loopback port, with a
hand-written HTTP client (a library that normalised a `409` into an exception, or hid the session
header, would be asserting on this server's behalf).

Four of them need no debugger, because tenancy is decided before any session is opened. All four
run a listener holding a **single, unnamed** token, so what they prove they prove for the `local`
client alone; the per-client rules are unit-tested where they are decided, and closing that
end-to-end gap is [`FOLLOWUPS.md`](../FOLLOWUPS.md) item 29:

- *It will not start without a token*, and says which variable is missing. The listener exposes
  every tool here, including the ones that write to a live kernel; a quiet default would be a
  server nobody knows is open.
- *An unauthenticated request is refused, told nothing about what is here, and **costs the server
  nothing***. The last clause is the one worth a test: the bearer check runs before the tenancy
  gate, so a wrong token must not reserve or consume a claim — if it did, anything that could
  reach the port could lock the real client out without ever authenticating.
- *A second connection **from the same client** is refused with `409`*, whether it arrives with a
  fresh `initialize` or with a session id that is not the holder's, and the holder is undisturbed by
  either. Since 2026-08-19 the tenancy is per client, so this is one client racing itself — a
  *different* client is served concurrently and shares nothing with this one.
- *Going quiet is not leaving; saying goodbye is.* Every request is its own connection — which is
  what a client behind a tunnel looks like — so silence is the resting state, and a server that
  read it as departure would hand the registry on between two calls of a working client. A
  `DELETE` does hand it on.

The fifth is in the debugger tier, because it is the sweep meeting a real engine worker: *a lease
that runs out releases what the absent client left*. The target is **a kernel attach nothing will
answer**, deliberately — a parked attach is the worst case in one move, since the session exists,
holds a worker, and cannot be interrupted, so releasing it means terminating a process rather than
asking politely. The test then goes silent for a real grace period (32s, nearly the floor the
listener enforces: the grace must outlast the call budget plus the 30s an engine worker may take to
come up, so the budget is shrunk to a second) and watches **stderr**, not HTTP — every admitted
request renews the lease, so a test that polled would hold open the very thing it is waiting to
expire. It asserts the worker process is gone, the swept session id is no longer served, and the
next client gets a server with nothing left over. Budget ~40s.

**Progress notifications.** The policy — what is reported, when a silence becomes a heartbeat, that
a send never delays the call — has unit tests in [`progress.rs`](../src/progress.rs) against a
collector. What those cannot reach is whether any of it leaves the process, so three assertions do:

- *A call that asked for no progress is sent none*, checked against **stdout as a whole**, since
  that is the transport a stray notification would corrupt. The call is an open that fails, so it
  exercises the path that would report rather than a tool with nothing to say. Protocol tier.
- *An open reports its milestones before it answers.* The debugger tier, because the sequence is the
  point: worker up, target claimed, target open, in that order, one notification each, on the token
  the call supplied, with `progress` increasing and no `total`. They are read out of the queue of
  messages that arrived *while the call was outstanding*, which is what makes "before" an assertion.
- *A remote client is told how a call is going.* The same thing over HTTP, where it is the only
  channel that exists while a call runs: rmcp routes the notification onto the SSE stream the call
  is answered on, keyed by the token, so the milestone and the result come back together. A failing
  open on purpose — one milestone proves the route, and it costs a worker coming up rather than a
  dump load that may go to a symbol server.
- *A call with nothing to report still reports that it is running.* The half of this that is not a
  mapping, and the one that covers a call with **no milestones at all** — a pool walk, a
  `crash_triage`, a batch. A twelve-second batch of `.sleep`s, asserted to produce a beat and
  nothing else. The beat is ten seconds and deliberately not tunable, so this costs wall clock;
  it runs beside the lease grace rather than after it. A parked kernel attach is the other silence
  and would prove the same thing, at the price of a worker holding a UDP port through a
  twenty-second teardown.

The third milestone rides an existing test rather than one of its own: *ending a session stops a
running batch and rolls it back* now watches its own `end_session`, and asserts the teardown said
it had found a transaction to unwind. That is the only milestone with a *number* a caller can act
on, and it is only produced when a teardown really does land mid-transaction — which that test is
already at pains to arrange.

This tier is also the only end-to-end check of the **protocol channel** — the inherited pipe pair a
worker speaks on ([`proto.rs`](../src/proto.rs)). Handles are passed on the worker's command line
and inherited across the spawn, so a mistake there is not a compile error: the worker exits without
a usable channel, or comes up and is never heard from, and either way every test here that opens a
target fails on the open. Run it after touching `engine::spawn_worker` or `worker::run`.

## What it costs the caller

Two tests measure size rather than behaviour: `tool_surface_stays_within_its_token_budget`
(protocol tier) and `tool_results_stay_within_their_budget` (debugger tier). They exist because a
dependency bump or a widened schema can move what this server spends of the *model's* context
without breaking a single assertion — `schemars` inlining one more shared type across 31 output
schemas is tens of kilobytes and no test failure.

Both print their numbers **under `--nocapture`** — libtest shows a passing test's output nowhere,
so without the flag they pass in silence. The debugger tier's CI job passes it and the result table
is in its log; the `build` job does not.

Only the **surface** is goldened, in `tests/golden/tool_budget.json`, re-recorded by the same
`UPDATE_GOLDEN=1` as the shape golden beside it and diffed per tool rather than per line
(`modules: modelVisible 2112 -> 4200`), so a tool added or removed does not blame the tools after
it. Read that diff — it is the only place the price of a reworded description shows up.

**Result budgets are not goldened**, because their sizes move with what symbols a runner resolves.
They are per-tool ceilings in the `budgets` slice of `tool_results_stay_within_their_budget`, so a
result that grows within its ceiling leaves no diff anywhere and is only visible in the printed
table. Adjusting one is an edit to that slice, not a re-record. See
[`token-budget.md`](./token-budget.md) for the baseline, the ceilings and how to raise one.

## When to run it

### A dependency moved

`rmcp`, `schemars`, `tokio`, or a `win-kexp` pin bump (`cargo update -p win-kexp`). Dependabot
watches the cargo ecosystem too, so most of these arrive as a PR — including the `win-kexp` locked
revision — and the run below is what you do on that PR, not only on a bump you made yourself.

1. `cargo test` — the protocol tier plus the existing unit tests.
2. For a `win-kexp` bump, add the debugger tier locally too — CI runs it on the PR, but a local
   run tells you sooner:

   ```pwsh
   $env:WINDBG_MCP_SMOKE_DUMP = "1"; cargo test --test mcp_smoke
   ```

3. If the golden diff fires, read it before re-recording. A changed dialect or nullable encoding is
   a **client-visible** change and belongs in `CHANGELOG.md`, not in a silent re-record.

### The MCP spec revved

1. Add the new revision to the front of `SUPPORTED_REVISIONS` in `tests/mcp_smoke.rs` and run it.
   A failure means the SDK does not speak it yet — that is the answer to "do we need an `rmcp`
   bump", and until then the README's revision list must not claim it.
2. Check `capabilities_advertise_only_what_is_implemented`. New spec revisions add capabilities and
   extensions; this test fails the moment the SDK advertises one this server does not implement.
3. Re-read the stateless assertions in `discover_opens_a_session_without_initialize` against the new
   revision's `_meta` requirements — that is where per-request metadata rules land.
4. Update the revision list in `README.md` and this file's list above to match what actually passes.

## The bounded-command tier

A third tier in the same file, `#[ignore]`d rather than env-gated because it deliberately runs
commands out to a watchdog deadline — minutes, not seconds. It needs the debugger tier's gate too.

```pwsh
$env:WINDBG_MCP_SMOKE_DUMP = "1"
cargo test --test mcp_smoke -- --ignored --nocapture --test-threads=1 bounded
```

`--test-threads=1` is required: each test spawns a server that opens the checked-in sample dump, and
these are timing tests that must not compete for the machine. Total runtime is a bit over a minute,
most of it deliberate waiting. They shrink the per-call budget with
`WINDBG_MCP_CALL_TIMEOUT_SECS`, so the arithmetic under test is the real one rather than a special
case.

- `a_bounded_runaway_command_aborts_and_leaves_its_session_usable` — a `.for` loop sized to run for
  hours is cut short by the watchdog, and the session executes the *next* command normally. This is
  the wedge that used to need a server restart. Proof of interruption is the loop counter left in
  `$t0`, not the clock and not the "interrupted after" note (which the worker renders whenever the
  watchdog *attempted* an interrupt, even one the engine ignored — win-kexp reports the reason as a
  field, and prose for a human is this server's to add).
- `a_bounded_command_queued_behind_another_job_still_beats_its_caller` — the same, from behind a
  `.sleep` that occupies the session for half the call budget. This is the half win-kexp cannot
  cover, because the queue belongs to this crate: budgeting from the patience as sent, instead of
  from what remains after the queue wait, passes every other assertion and fails here. Two details
  the test documents because both silently void it — `.sleep` needs a `0n` prefix (the MASM
  evaluator's default base is hex, so a bare `30000` is 0x30000 ms), and the blocker needs a head
  start, since two tool calls in flight at once reach the session's queue in whichever order wins
  the race.
- `measure_what_the_bounded_path_costs_a_quick_command` — prints what arming the watchdog costs, as
  a distribution. It asserts nothing; it is the evidence behind which tools take the bounded path
  ([`DECISIONS.md`](../DECISIONS.md), 2026-08-02), namely that a bounded command is rounded up to a
  multiple of 200ms. Re-run it after a win-kexp watchdog change — if that cost goes away, so does
  the reason for the split.

These live with the wire tests rather than beside the arithmetic because the wiring they prove now
spans two processes: the supervisor sends the caller's remaining patience, the worker derives the
watchdog deadline from it, and only the shipped binary contains both halves.

Each half is unit-tested where it lives, and both ride `cargo test` everywhere — so a regression in
the common case fails in CI rather than waiting for a manual run. What is sent is
`remaining_patience_ms` in [`src/engine.rs`](../src/engine.rs); what is derived from it is
`watchdog_budget_ms` in [`src/worker.rs`](../src/worker.rs). The tests above are what checks that
the two agree across the pipe, which is the part neither module can prove alone.

## The live-kernel tier

The only tier that touches another machine, and the last thing to run. It needs a live kernel target
you are willing to freeze for the duration, booted with debugging enabled — see the KDNET gotchas in
[`CLAUDE.md`](../CLAUDE.md) before diagnosing a failure.

```pwsh
$env:WINDBG_MCP_SMOKE_KERNEL = "net:port=50000,key=<w.x.y.z>"
cargo test --test mcp_smoke -- --ignored --nocapture --test-threads=1 live_kernel
```

**The transport does not have to be KDNET.** The variable is a DbgEng connection string and is
passed through untouched, so `com:port=COM1,baud=115200` is as valid as a `net:` one — which is the
only option on a hypervisor whose guests have no KDNET-capable NIC (Parallels on Apple Silicon
presents VirtIO, and `1AF4` is not in the Debugging Tools' `VerifiedNICList.xml`). Two assertions
are **transport-specific and skip themselves** rather than failing: the KD endpoint being owned by
the worker process is a UDP claim, and the key-redaction claim needs a key to look for.

**Nor does the target have to be x64** — but two of the eight tests need one. The pool tools
document it (*"Needs a broken-in x64 kernel target"*) because the walker decodes x64 pool
descriptors, so `a_live_kernel_pool_walk_is_bounded_and_leaves_its_session_usable` and
`a_live_kernel_batch_step_can_ask_the_pool_about_a_captured_pointer` stand down against anything
else. The architecture is read from the target's own `vertarget`, not from `cfg!(target_arch)`: what
decides it is the target, and the debugger host is routinely a different machine of a different
shape. Everything skipped here says so in the output rather than passing quietly.

One caveat that is not a gate, because it is a property of a particular wire rather than of the
tests: **a pool walk over a 115200-baud serial link will not finish inside any sane budget** — it
reads every committed pool page. If you point the tier at a serial target, expect those two to time
out rather than to skip, unless the target is also non-x64 and stands down first.

`--test-threads=1` is required, not tidiness: the filter matches **eight** tests, and the KD
transport is single-owner. Run them in parallel and the later attaches fail, which can leave the
target halted.

The connection string is the one from `bcdedit /dbgsettings` on the target (or the `kd -k` command
you would otherwise use). It is **never** guessable, so the tier is gated on it rather than on a
boolean — and gated on `#[ignore]` as well, so a variable left set from an earlier session cannot
freeze a VM during an ordinary `cargo test`.

Everything else about kernel attaches is proved against a *dead* port, which is the failure #61 was
about. This is the other half — an attach that lands:

- **It still lands through a worker process.** The `Committed`/`Opened` milestones cross the pipe
  and leave the session reporting *open*, not stuck mid-attach.
- **The KD transport endpoint belongs to the worker**, checked against `netstat -ano`. That is the
  premise of process-per-session: a thread-based design leaves that endpoint claimed for the life
  of the server, and every retry claims another. If this assertion ever fails, a parked session is
  no longer reclaimable and the fix is undone.
- **A second session works alongside it** — a dump opened and used while the kernel attach is held,
  with the kernel session unaffected. Impossible by construction before.
- **`crash_triage` refuses a kernel that has not crashed, and refuses it correctly.** This is the
  state the debugger-free exploitation loop sits in *between* fires — attached, working, nothing
  bug-checked yet — and a dump can never be in it: a dump either is a crash dump or is not, while a
  live kernel moves between the two. So this is the only place both arms of the refusal are
  reachable, and the only place it can be checked that a kernel target does not take the *user-mode*
  arm. It also checks that the refusal costs the session nothing: the loop attaches once and fires
  many times, so a triage that came too early has to leave the session exactly as usable as it
  found it.
- **`end_session` detaches gracefully rather than killing the worker.** This one has teeth: DbgEng
  leaves a detached-but-halted kernel *frozen*, so win-kexp resumes and actively detaches. A run
  that took the kill path instead would leave the guest halted with a wedged KD stub, needing a
  reboot. For the same reason the test body runs under `catch_unwind` — a failed assertion must
  still detach, or a test failure costs you the VM.
- **A disconnect releases a live kernel session rather than killing its worker.** Same hazard by
  the path nobody watches: closing the connection is an ordinary event, and whatever sessions are
  open at the time are whatever happened to be open. Checked against the **target's own uptime**
  read either side of the disconnect — a halted kernel takes no clock interrupt, so its uptime
  stands still while a released one keeps counting. Re-attaching alone proves nothing here: a
  frozen target still answers its KD stub.
- **A pool walk is bounded and gives the session back.** Needs **full `nt` symbols on this host**,
  which is a real precondition rather than a formality: the walker decodes segment-heap internals
  (`_EX_POOL_HEAP_MANAGER_STATE`, the page-range descriptors, the VS and LFH headers) and none of
  that is in the export table, so without them every pool query fails before reading a byte.
  Symbols are never fetched over the KD wire. The tier sets a path with `set_symbol_path` — the
  typed tool, so `.sympath`'s line-swallowing cannot bite — pointed at a store under
  `target\release\sym` that dev and release builds share, then reloads under `!sym noisy` and
  prints `!lmi nt`, `lm m nt` and `x nt!ExPoolState` when it cannot get them.
  **The trap that actually bit: the harness spawns the *dev* binary, and the engine DLLs live
  beside the release one** — `setup.md` has you copy them there, because that is what the plugin
  runs. `dbgeng.dll` is in System32, so the dev binary opens targets and runs commands perfectly;
  it just has no `symsrv.dll` to read a symbol store and no `msdia140.dll` to parse a PDB, so a
  PDB already sitting in the cache comes back as `file not found` with the error summary blaming
  the store. The tier copies the engine across before starting the server, and says so. It also
  reloads with a bare `.reload /f`, which is slower than `.reload /f nt` but is the form measured
  working end to end here and takes the module name out of the set of things a failure could be.
  Where you already have a symbol path that works for the target, set
  `WINDBG_MCP_SMOKE_SYMBOLS` to it and that is used instead. `pool_find_tag` with `refresh` then
  walks every
  committed pool page, which over KDNET is the query that used to run for minutes past its caller's
  timeout and leave everything behind it queued. Only this tier can show it: against the sample dump
  the same walk is local memory and finishes in well under a second, so the assertions would pass
  for the wrong reason. The claims are that the call **returns** inside its budget, that the very
  next call is served **immediately** rather than waiting out the rest of a walk, and that whatever
  came back **states its own coverage**. A truncated walk is a perfectly good outcome here, and the
  expected one on a busy kernel — so the test never asserts the walk was complete, only that it said
  which it was, and it prints the walk's own diagnostic categories when it fell short, which is the
  part worth reading. **Measured against Server 26100 over KDNET: a forced walk returned in ~52s,
  indexed 530,680 chunks (306,227 allocated), and reported INCOMPLETE.** That was inside the 120s
  the walker used to default to, and is inside the caller-derived budget it takes now
  ([#75](https://github.com/glslang/windbg-mcp/issues/75) — 285s under the default call timeout, and
  the figure to re-read if you shrink `WINDBG_MCP_CALL_TIMEOUT_SECS`), so on that target the
  coverage gap is not the deadline — which is why scoping the
  walk to one side of the pool was closed unbuilt (glslang/win-kexp#89): it would have bought a
  faster query at the cost of a cache that keys on scope, against better than two-fold headroom
  that already exists. That margin is worth re-reading rather than assuming: the same walk cost
  ~24s and reached 437k chunks before glslang/win-kexp#92, so a walk gets *slower* as it gets more
  correct, and the next such fix spends the remaining headroom too.
  Expect INCOMPLETE on any live kernel: paged pool is
  partly on disk, so `sparse virtual range` diagnostics are physics rather than a defect, and the
  coverage caveat is doing its job. The categories that are *not* explained that way are worth
  reading, and this tier is where that paid: a run showing ~5.6k LFH subsegments rejected as
  implausible (glslang/win-kexp#90) was not the walker being careful but the walker misreading
  `_HEAP_PAGE_RANGE_DESCRIPTOR.RangeFlags` bit `0x01` as "LFH subsegment" when it means ALLOCATED,
  which sent VS, large and special-pool ranges through the LFH decoder to be refused and dropped.
  glslang/win-kexp#92 fixed the reading; that category should now be **absent**, and its return
  would mean a regression rather than a busy kernel. Read the per-category counts as the volume:
  the walk keeps only a handful of messages per category verbatim, so the list of examples is a
  sample and its length
  says nothing about how much the walk complained. The header total is the walk's own count
  (#77) — before that fix it was the length of the sample, which understated a real run by two
  orders of magnitude.
  Where the walk *does* complete it also checks the snapshot was cached rather than
  re-walked, and that `pool_census` and `pool_find_tag` agree about the heaviest tag in it. That
  last comparison additionally needs the census to expose a tag that renders unambiguously: pool
  tags are four raw bytes, unprintable ones render as `.` — and so does a literal `.` — so a tag
  containing one cannot be turned back into the bytes it came from. That is a fact about rendering
  and says nothing about the walk, so it skips the comparison with a note rather than failing.

The attach test also records a **transcript** and checks the supplied KD key is nowhere in it. The
protocol tier passes a raw connection too, but its attach is refused for its shape before anything
dials — so it proves the *argument* is scrubbed and nothing about a session that then exists, takes
a label, opens a target and reports on it. Only here is that an attach that landed. Three guards
keep it from passing on nothing: the connection must actually contain a `key=`, the transcript must
contain a mask, and it must contain the kernel `session_open`. The failure message names the file
rather than printing it, since printing it would put the key in the test output.

The first run of this tier found a real bug — shutdown killed workers outright, so a disconnect
froze the target — which no dump-based tier could have found, because killing a worker that holds
a *dump* costs nothing. Both tests therefore collect their evidence and assert only after the
target has been released: an earlier draft asserted as it went, failed at the release check, and
left the target halted. A test for a bug that freezes a machine must not freeze the machine when
it fails.

### A `debug_batch` that really mutates the target

Five of the eight tests are about a batch that **patches a byte of the running kernel and puts it
back**, which is the thing the tool exists for and the thing no dump can test: a byte "patched" in a
crash dump is patched in a file nobody reads again, so a rollback that silently did nothing would
satisfy every assertion the debugger tier can make. Here the byte either reads back as it was or it
does not.

The byte is `nt`'s DOS-header `e_res2` field (`nt+0x28`) — reserved by the PE format, zero in every
image MSVC has linked, read by nothing at runtime, and stable across a detach and re-attach because
the image does not move without a reboot. Each test **probes it first**: read, write a different
value, read it back, restore. That probe decides whether the run can prove anything at all, and it
is the one place a guest with memory integrity (HVCI) enabled announces itself — such a guest
accepts a debugger write to an image page and drops it, which would leave every assertion below
passing for the wrong reason. When the probe cannot write, the test says so loudly and stops rather
than measuring a patch that never landed.

- **A failing batch restores its patch** — the assertion that cannot hold is step 4 of 5, the batch
  stops there, and a **separate later call** finds the original byte. The step after the failure
  writes a third distinct value, so "SKIPPED" is checked against the target and not only against the
  report.
- **A batch reports and rolls back inside its caller's timeout.** The server's per-call budget is
  pinned to 60s, the batch asks for ten minutes and is given nearly a minute of work; the clamp in
  `worker::batch_budget` is what makes the report arrive before the call gives up. The steps are
  many short `.sleep`s rather than a few long ones deliberately: the deadline is then crossed
  *between* steps, so the outcome does not depend on whether DbgEng honours an interrupt inside a
  `.sleep`.
- **A disconnect lets the rollback finish first**, verified from a **new server process** over a
  fresh attach — the byte outlives every process that was involved in patching it. This is the
  substance the debugger tier's version can only approximate with a log file.
- **`end_session` mid-batch does the same with a client still listening**: the batch's own call
  comes back `BATCH: ABANDONED` with the rollback complete, *and* a second attach agrees about the
  byte. Both attaches check `nt`'s base, so a guest that rebooted in between fails loudly instead of
  comparing a byte to a different byte.
- **A batch step queries the pool.** `pool_chunk`, `pool_find_tag` and `pool_census` are the only
  typed tools that are not debugger commands, so a batch that could not call them could not express
  the CTF workflow's `@chunkt1` — which sat inside the transaction, between a patch and its restore.
  The test captures `@$proc` with an `eval` step and asks `pool_chunk` about `{{proc}}`; it needs the
  same full `nt` symbols the pool tier does. Either pool answer is correct (a chunk, or an address
  the walk did not cover) and they are different facts, so both are accepted by name.

## MessageManager CTF regression

[`examples/messagemanager/ctf_regression.ps1`](../examples/messagemanager/ctf_regression.ps1)
turns the MessageManager challenge into a repeatable live regression fixture. It builds a benign
mode of `mm_exploit.c`, copies it to the VM over WinRM, and waits until the process has retained real
`Tgsm` messages. It then runs the ignored Rust test through the shipped stdio MCP transport. The
test attaches over KDNET, checks that `MessageManager.sys` is loaded, finds the retained allocations
with `pool_find_tag`, verifies the session still serves a register request, and always attempts
`end_session` before reporting an assertion failure.

Prerequisites are a disposable VM with the challenge driver installed and running, PowerShell
remoting enabled, a working KDNET connection back to the host, the host MSVC Build Tools path used
by `build.cmd`, and full `nt` symbols. From the repository root:

```pwsh
$credential = Get-Credential
$env:WINDBG_MCP_SMOKE_KERNEL = 'net:port=50000,key=<w.x.y.z>'
$env:WINDBG_MCP_SMOKE_SYMBOLS = 'srv*C:\symbols*https://msdl.microsoft.com/download/symbols'
.\examples\messagemanager\ctf_regression.ps1 `
    -TargetHost ctf-vm -Credential $credential
```

The PowerShell runner owns the extra `WINDBG_MCP_SMOKE_CTF=1` gate and sets it only after the
fixture reports ready. The fixture does not run the race or corrupt pool metadata; it uses the
driver's ordinary Create/SetData/Delete operations to give the pool tools a stable, challenge-
specific population. Its stop file requests orderly deletion after KD detaches, with forced process
termination only as a timeout fallback.

Host artifacts go under ignored `target\ctf-regression\`. The timestamped transcript records
fixture and Cargo output but replaces the complete KDNET connection and any `key=` value; the
`PSCredential` is passed directly to `New-PSSession` and is never serialized. Remote fixture files
are removed by default. If the target is halted or has crashed, cleanup cannot reach it: recover the
VM, remove the named remote directory if necessary, and treat the transcript's detach warning as
the primary failure before rerunning.

## Manual checklist

Not automated: no runner has a kernel target, a TTD-capable engine, or elevation. Run these by hand
before a release, or when a change touches the relevant path. Drivers live in
[`examples/`](../examples/README.md) and need `cargo build --release` first.

- **Live user-mode** — `examples/test_usermode.ps1`: launch `cmd.exe` under the debugger, break in,
  read registers/modules, set a breakpoint.
- **Typed user Segment Heap** — from a sibling `win-kexp` checkout, run
  `cargo run --example user_heap_smoke`. The helper launches an x64 child that retains known
  LFH/VS/backend/large allocations, reloads the exact `ntdll` PDB, verifies each pointer and
  backend, writes a temporary `/ma` full-memory dump, reopens it, and repeats the checks. Set
  `WIN_KEXP_USER_HEAP_SYMBOLS` (or `_NT_SYMBOL_PATH`) when the default Microsoft symbol-store path
  is not appropriate. Missing private types are a failed prerequisite; export symbols must not be
  accepted as a layout. The dump is written to the operating system temporary directory as
  `win-kexp-user-heap-<pid>.dmp`, outside either checkout. The helper removes it after a successful
  run; after a failed run, delete that file from the temporary directory manually and never add it
  to version control.
- **Ctrl+C teardown** — `examples/ctrl_c_teardown.ps1`: a console Ctrl+C must leave a worker time
  to release its target, not kill it where it stands. Unattended, and it needs no target beyond the
  sample dump — but it is here rather than in `cargo test` because Ctrl+C cannot be aimed: the
  script runs the whole scenario in a console of its own, since an event sent to the test runner's
  console would take the runner with it. Self-checking (`PASS`/`FAIL`, exit 0/1/2); what it reads
  is whether the worker logged the release before exiting, because the worker process is gone
  either way. Run it when anything touches worker spawning or the EOF teardown.
- **Failure paths** — `examples/verify_fixes.ps1`: execution control with no debuggee returns a
  clean "No active debuggee" error, and a failed kernel attach is a clean error rather than a panic.
- **Live kernel (KDNET)** — the [live-kernel tier](#the-live-kernel-tier) covers the session
  lifecycle (attach, coexist, detach). For execution control on a real target, additionally run
  `examples/drive_kernel_test.ps1 -Connection "net:port=<n>,key=<w.x.y.z>"`: attach,
  `bp nt!NtCreateFile`, `go` to it, resume, detach. See the KDNET gotchas in `CLAUDE.md` before
  diagnosing a hang.
- **TTD replay** — needs the WinDbg store engine next to the binary (System32's engine rejects
  `.run` traces with `0x80070057`). Open a trace, then exercise `ttd_calls` / `ttd_memory` /
  `ttd_events` and reverse execution. The worked example is
  [`docs/flareauthenticator-ttd-walkthrough.md`](flareauthenticator-ttd-walkthrough.md).
- **TTD recording** — `record_trace` needs elevation and `TTD.exe` on `PATH`.
- **Driver IOCTL sweep** — `examples/sweep_ioctls.ps1` plus the target-side
  `examples/send_ioctls_target.ps1`; needs a benign test driver on a KDNET target.
