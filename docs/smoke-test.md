# Smoke test

`tests/mcp_smoke.rs` drives the **built binary** over stdio with hand-written JSON-RPC. It exists
for the two moments the in-process unit tests in `src/server.rs` cannot cover: **a dependency
moved**, and **the MCP spec revved**. Both change the bytes on the wire while the Rust API this
crate compiles against stays identical — so the unit tests keep passing and clients break.

## Running it

```pwsh
cargo test --test mcp_smoke              # protocol tier (default)
$env:WINDBG_MCP_SMOKE_DUMP = "1"; cargo test --test mcp_smoke   # + the debugger tier
$env:WINDBG_MCP_SMOKE_TTD  = "1"; cargo test --test mcp_smoke   # + the TTD tier (elevated)
```

It builds and runs against `target/debug`, so it never touches the `target/release` exe a
connected MCP client holds a lock on (see [`CLAUDE.md`](../CLAUDE.md)). The protocol tier is ~2s;
adding the debugger tier takes it to ~60s, most of it two tests waiting out real timers — a lease
grace, and a call staying silent long enough to have to report that it is still running.

**The pass count is the same either way**, because each gate is inside its own test: `cargo test
--test mcp_smoke` reports the same number passed with the tier off as with it on — 97 on 2026-08-31,
against ~2s and ~60s respectively, but it moves whenever a test is added, so re-derive it rather
than reading it here. (A plain `cargo test` runs the unit tests beside it and prints a result line
per binary, so it is this harness's own line to read.) The runtime is what tells the two runs apart,
and `--nocapture` is what prints the `SKIPPED` reason — a run that reports every test green having
taken a second covered no debugger claim at all.

### Tiers

| Tier | Gate | Needs | Catches |
| --- | --- | --- | --- |
| **Protocol** | always | no debugger, no target, and no network off this machine — it does bind a loopback port for the listener | transport, revision negotiation, tool-surface drift, and the listener's lease up to the point a session is opened |
| **Debugger** | `WINDBG_MCP_SMOKE_DUMP=1` | `dbgeng.dll`, the checked-in sample dump, and a live user-mode target for the nine that want one — `cmd.exe` for the eight that launch, `ping` for the one that attaches | `dbgscope` / DbgEng regressions, a lease expiry releasing a real engine worker, driving execution on a live user-mode target synchronously and asynchronously, what ending a session does to it, and — over a seeded randomised sequence — that a session is always in one of its three states and never half-answering |
| **Bounded command** | `--ignored` | `dbgeng.dll`, the sample dump, ~1 minute | the watchdog wiring, which now spans two processes |
| **Live kernel** | `--ignored` + `WINDBG_MCP_SMOKE_KERNEL` | a live kernel target you can freeze — KDNET, or serial | that a kernel attach *lands*, coexists, and is let go — by `end_session` and by a disconnect; and that a `debug_batch` which patches a byte of the running kernel puts it back |
| **MessageManager CTF** | `--ignored` + live-kernel gate + `WINDBG_MCP_SMOKE_CTF=1` | the challenge VM, WinRM, full `nt` symbols | the real driver and retained `Tgsm` pool objects through the shipped MCP transport |
| **TTD** | `WINDBG_MCP_SMOKE_TTD=1` | `TTD.exe`, **elevation**, and a WinDbg engine payload beside the binary to replay what it records — both benches' came from `setup.md`'s unpacked `.msixbundle` rather than from an installed package, the ARM64 one as of 2026-08-29 | that `record_trace` records the program it was given and reports a finished recording as one, and that a TTD query returns records rather than bare indices |
| **32-bit managed target** | a 32-bit `dbgeng.dll` in an `x86` directory beside the binary under test | that engine, `x86\windbg-mcp.exe` beside it, and the `csc.exe` every stock Windows ships — it compiles and dumps its own fixture | that a 32-bit dump **and** a 32-bit live process are each opened by a worker of *their* architecture, so 32-bit SOS loads — which this server's own engine cannot do at all |
| **Live (other)** | manual | a test driver on a kernel target | see [Manual checklist](#manual-checklist) |

The protocol tier rides `cargo test`, so CI already runs it. The debugger tier is opt-in
*locally* but runs on every push and PR in CI, as the **Smoke test (debugger tier)** job — it is
the only automated check of the properties process-per-session exists for, and it needs no symbols
and no network. It runs **three times: on x64 and on both ARM64 images**, because the thing it
exercises that nothing else does is a real `dbgeng.dll`, and there is a different one on each
([#134](https://github.com/glslang/windbg-mcp/issues/134)). No two entries share a cargo
cache — the key is the runner label, not the architecture — and no entry's failure cancels
another's.

The two ARM64 entries are `windows-11-arm` and `windows-11-vs2026-arm`, and the pair is temporary.
The Visual Studio 2026 ARM64 image went generally available on 2026-08-20, and GitHub migrates the
`windows-11-arm` label onto it between 21 and 30 September 2026 — so for now the two labels are two
*OS builds*, which for this job means two inbox `dbgeng.dll`s, and running both is what makes a
break attributable to the image rather than to the change under review. Once the migration
completes they are one image and the older entry should go (`FOLLOWUPS.md` item 32). The x64 entry
needs no such pairing: `windows-latest` has been the Visual Studio 2026 Windows Server 2025 image
since its own migration.

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
- with nothing beside the binary — that host's System32 ships `dbghelp.dll` and **no**
  `symsrv.dll`, so a `srv*` path downloads nothing — it reproduces the CI failure exactly, down to
  the address and `0x8007001E`;
- and with the full bundle but `_NT_SYMBOL_PATH` pointed at an empty directory it fails again, and
  fails *differently per dump*: the ARM64 sample reads nothing at all, while the x64 sample gives
  up a module base and then walks a stack of the bug check's own parameters. Neither is an answer,
  and only one of them looks like a failure.

Same engine, same dumps: symbols are the variable, and the engine's architecture is not.

**Whether System32 has a `symsrv.dll` is not a constant, which is what
[#153](https://github.com/glslang/windbg-mcp/issues/153) turned on.** Probing both CI runners
directly: `windows-latest` has one at `C:\Windows\System32\symsrv.dll`, servicing-versioned like
an inbox component, which is why its stock engine resolves symbols with `_NT_SYMBOL_PATH` unset.
`windows-11-arm` has none anywhere in System32, matching this project's own ARM64 bench. Both
images do carry the Debugging Tools, `symsrv.dll` included, so on the ARM64 entry the missing half
was already on disk — the job copies the kit's `dbghelp.dll` and `symsrv.dll` beside the binary
under test and leaves `dbgeng.dll` stock, so what that entry exercises is still the image's own
engine. The copy runs on the `windows-11-vs2026-arm` entry too, without that image's System32
having been probed: copying is what makes the entry independent of the answer, which is worth more
across an image migration than a measurement a migration can invalidate. Read any blanket statement
about what "Windows ships" in this repo with that measurement in mind.

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

**The sample they open follows the host.** Four dumps are checked in (below), and the two crashes
a *memory* read is asserted against are paired with the architecture the tests are running on — so
an ARM64 run reads an ARM64 target, which is coverage this suite has nowhere else
([#143](https://github.com/glslang/windbg-mcp/issues/143)). That pairing is a choice about what to
cover rather than a workaround: with symbols, either engine reads either dump, and the driver-crash
assertion below deliberately opens the x64 dump on every architecture because what it asserts is a
property of *that* crash. The bounded-command and live-kernel tiers are `#[ignore]`d — one is measured in
minutes, the other touches another machine; see below. Neither is automated, and the rest of the
live checklist is not either: no runner has a kernel target, a TTD engine, or elevation.

## What it asserts, and why each one is a dependency tripwire

**The artefact, before it runs.** The exe carries a PE version resource, with `CompanyName`,
`ProductName`, `OriginalFilename`, `InternalName` and `FileVersion` pinned to their values and
`ProductVersion` pinned to the identity `build.rs` stamped — the same string `serverInfo.version`
reports. It is read back through `GetFileVersionInfoW`, the API Explorer and the reputation systems
read it through, rather than by scanning the file for the string, which would pass on a resource
Windows itself refuses to parse. This is a test rather than a hard failure in `build.rs` because the
resource needs `rc.exe` and the `cargo check --target x86_64-pc-windows-msvc` this repo runs from a
Mac has none: the build script warns and carries on, so the only thing standing between a missing
resource and a release is this assertion, on the one host that can build one. To check that it still
catches the case it is for, point `RC_PATH` at nothing, touch `build.rs`, and re-run it.

**And the same claim for the 32-bit worker**, which the assertion above does not reach: it reads the
binary `cargo` built for the *host*, so `x86\windbg-mcp.exe` — shipped in both release artefacts —
went unchecked on every host and in CI until this. Its fields are asserted **equal to this build's**
rather than against literals of their own, because the two are one product from one build; pinning
the strings twice would let the copies drift apart with both tests green. It stands down where there
is no worker beside the server, and gates on that worker rather than on the 32-bit *engine* the rest
of the x86 tier gates on — no engine is needed to read a file's resource, and CI builds the worker on
runners that may carry no x86 engine payload. To check it still catches its case, put any other
signed binary at that path and re-run: it fails on `CompanyName`.

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
the tools that declare one — the shape of its `outputSchema`: the dialect, the root `type`, and for
each branch of the result union its `status` const, the payload type it references, and what that
branch requires.
It deliberately excludes descriptions, so prose edits do not churn it while a `schemars` dialect
switch, an `rmcp` annotation-casing change, a discriminator that stops being emitted, or an
accidental tool rename all land as a readable line diff.

Beside it, `output_schemas_carry_constraints_not_prose` asserts that an output schema carries no
descriptions **at all** — 68% of every `outputSchema` byte used to be rustdoc that no model is given
and no validator reads, which is `FOLLOWUPS.md` item 24's first finding. It reads `tools/list` off
the wire because the way that comes undone is one tool declaring its schema with rmcp's
`schema_for_output` instead of `schema::constraints_of`, and nothing else would report it.

And beside *that*, `output_schemas_are_object_rooted` asserts every declared `outputSchema` is
rooted at `type: "object"` — the keyword whose absence costs a strict client not the one tool that
lacks it but **every tool on the list**. The structured results are internally-tagged enums, which
`schemars` renders as `{ $schema, oneOf, $defs }` with the object-ness on each branch and none at
the root, and rmcp passes that through: `schema_for_input` requires a root `object` and refuses
anything else, while `schema_for_output` deliberately does not, SEP-2106 (`2026-07-28`) having
relaxed the requirement. That relaxation is what a server may emit, not what clients accept — every
released `@modelcontextprotocol/sdk` 1.x through 1.30.0 parses `Tool.outputSchema` as
`z.object({ type: z.literal("object"), … })` and `tools/list` as `z.array(ToolSchema)`, so the array
fails on the first non-conforming tool. Measured against 1.30.0 on this server's own captured
`tools/list`: **0 of 51 tools before the fix, 51 of 51 after**, and all 33 schemas compile under
`ajv`. That is issue #223, which reached a real client as zero tools registered and the server
deregistered after its reconnect loop. `src/schema.rs` supplies the keyword; this is the assertion
that it reaches the wire, since the failure is a tool declaring its schema the other way round.

The reason no tier caught it is worth keeping: this harness is a hand-rolled JSON-RPC client, and
it never validated a tool *definition* — only the results of calling one. The assertion encodes the
SDK's rule rather than adding a Node client to CI.

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

**And it checks that a listing is a *page* of the table** rather than all of it, which is the one
claim about this tool that only a real target with a real module count can support. A call naming
no `limit` comes back with 64 rows counted **across both halves**, with the unloaded rows still
among them — the share that stops two hundred loaded modules crowding out the images that have
gone — while `loaded`, `matched` and `unloaded_matched` go on reporting the target rather than the
page, and the text says which half was cut and names `limit` as the way to see the rest. Then the
same call with `limit: 2000` returns the whole table, so the page is a default and not a ceiling.
The saving is asserted as a ratio, since the bytes belong to the host: the tier prints both
figures under `--nocapture`, which on this sample reads `12268 B model / 16871 B wire for the
default page, against 53933 B / 74052 B for all 227 modules` — the same dump
[`token-budget.md`](./token-budget.md) records its baseline against, so the two can be read
together.

**A refresh is asked for as the first call on a freshly opened session**
(`a_module_listing_can_resynchronise_the_inventory_before_it_lists_it`), which is the ordering
[#85](https://github.com/glslang/windbg-mcp/issues/85) is about: DbgEng's inventory holds the
module loads the debugger *saw*, so on a live kernel attach a driver loaded beforehand is in the
target and absent from the list. A dump cannot reproduce that gap — it carries its own complete
module list — so what this tier claims is the half that would otherwise break silently: the reload
**runs against a real engine, succeeds, and costs the listing nothing**, reported as a
resynchronisation that found the inventory already current (`refresh.before` equal to `loaded`, all
227 of them), with the rows still equal to the values row for row. The default call is asserted in
the same breath, because "cheap and backward compatible" is a claim about an *absent* field: an
answer that carried `refresh` unasked would tell every caller a resynchronisation had happened. The
gap itself is the live tiers' to claim — the generic one checks the reload runs over the KD wire
and loses no modules, and the CTF one asks *before* any symbol work and requires the challenge
driver in the answer.

**`registers` gets the same treatment, and its test runs against this host's own architecture.** A
default answer is documented as the integer registers, excluding the x87 and vector ones — and it
carried 64 of them, because DbgEng exposes `xmm0` twice and leaves the subregister flag clear on the
four 32-bit lanes it calls `xmm0/0` … `xmm0/3`. The tier asserts no default row's name carries the
`/` that names a lane, that no row spends bytes on `"subregister":false`, and that the default is a
**subset of `all`** — the last catching the two answers being computed by rules that have drifted
apart, a row the default has and `all` does not. It does **not** catch a register dropped from
both, which leaves the subset relation intact; that needs an oracle from outside the pair, and it
is a separate assertion that the instruction and stack pointers are still there under whichever
names this architecture gives them.

It opens the crash paired with this host's architecture — *The sample they open follows the host*,
above — rather than the shared x64 dump, on purpose: the rule is a naming
convention, and a convention that held on one architecture and not the other would cost the saving
silently on half the runners. That is not hypothetical — running it that way is what found ARM64
carrying `w0`–`w30` for the same reason and under a different name, which is
[`FOLLOWUPS.md`](../FOLLOWUPS.md) item 35, measured and declined. The test deliberately asserts
nothing about the ARM64 shape: it is a measured cost, not a settled contract.

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
read through the same three claims the x64 samples make. It also pins the one branch of the process
read that nothing else reaches: this dump does not capture the pool page `SeAuditProcessCreationInfo`
points at, so the engine falls back to the 15-byte `_EPROCESS::ImageFileName` and the answer is the
truncated `stack_buffer_o` — the fallback that the driver crash above, with its full
`mm_exploit_v5.exe`, exists to prefer.

**A fourth dump, because the fourth claim had never run on an ARM64 stack.** Attributing a frame
to a third-party driver — turning a captured frame into `module+RVA` off the load base — was
asserted only against x64 frames until
[#154](https://github.com/glslang/windbg-mcp/issues/154). The ARM64 sample above cannot stand in:
its `0xFC` is a fault at the *user-mode* payload, so its faulting frame is in no module at all,
which is the opposite shape. That needed a crash produced rather than a sample found, and the
producing turned out to be the hard part.

[`docs/samples/082126-7015-01.dmp`](samples/082126-7015-01.dmp) is a
`0x139 KERNEL_SECURITY_CHECK_FAILURE` off the same ARM64 debuggee, with HEVD loaded.
**Every obvious trigger fails to crash it**, and the reason is worth recording because it costs an
afternoon otherwise: HEVD wraps its triggers in `__try/__except`, so a kernel-mode access violation
is caught and returned as a status. Its null dereference returns `STATUS_ACCESS_VIOLATION` and the
machine runs on; its non-paged pool overflow returns success; its use-after-free double free
returns success twice and is detected minutes later on a heap-maintenance worker thread, as a
`0x13A` whose stack is `nt`-only — no driver frame anywhere, which is exactly the fixture this one
is not.

What SEH cannot catch is a **fail fast**. `HEVD_IOCTL_BUFFER_OVERFLOW_STACK_GS` compiles its
trigger with `/GS`, so overrunning the stack buffer corrupts the cookie and the driver's own
`__report_gsfailure` runs `mov w0, #2; brk #0xf003` — the ARM64 spelling of
`__fastfail(FAST_FAIL_STACK_COOKIE_CHECK_FAILURE)`. The bug check is raised **inside the driver**,
and the faulting frame is `HEVD+0x10dc`, that instruction's fixed offset in a fixed image.

Reproducing it takes one call, through this repo's own harness, on the debuggee:

```pwsh
$hex = '41' * 1024   # the buffer is far shorter; the cookie is what matters
.\tools\ioctl_harness.ps1 -Device \\.\HackSysExtremeVulnerableDriver -Code 0x222007 -InputHex $hex
```

`0x222007` was read out of the driver's own dispatch rather than taken from HEVD's headers, and
that check earned its keep: this build's IOCTL codes are not the ones the widely-quoted list gives,
and the code that list calls the null dereference is `FREE_UAF_OBJECT` here. `decode_ioctl` and the
dispatch walk in `CLAUDE.md` are how to redo it against another build.

**The two driver crashes are asserted on every host, not paired by architecture** — the one place
this suite deliberately does not pair. An engine that resolves symbols reads either dump either way
round, so pairing them would mean an ARM64 runner stopped reading the x64 crash it reads today:
trading one architecture's coverage for the other's rather than adding it. What the pair covers
that neither does alone is the attribution arithmetic against a second architecture's stack.

**`!analyze`'s own attribution beside it is a fact about the host, not about either dump**, and
this file said otherwise until 2026-08-30 — that `MessageManager` has no PDB so `!analyze` calls
it `Unknown_Module`, and that `HEVD` ships one so `!analyze` blames it by name. Measured on one
engine against both dumps, they behave identically, and what decides it is whether
`triage\triage.ini` is beside the engine:

| beside the server | `analysis.ran` | `analysis.module_name` |
| --- | --- | --- |
| `winext\` and `triage\` | `true` | the driver's name |
| `winext\`, no `triage\` | `true` | `Unknown_Module` |
| neither | `false` | absent |

The last row is **what CI has** — `ci.yml` copies `dbghelp.dll` and `symsrv.dll` and no extension
directory at all — so every `!analyze` assertion in this tier is skipped there, and a green CI run
says nothing about any of them. Run the tier on a host with a bundled engine before believing an
`analysis` claim is covered. The missing PDB does cost something, but not the module: both
buckets end `!unknown_function` whichever way the table above falls.

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
- *A symbol path can seed later sessions without becoming shared worker state.* Two workers are
  open before `set_symbol_path` remembers a unique local directory: the other existing worker must
  stay unchanged, the next open must inherit it, and a session-only override must not replace it.
  Clearing the remembered setting then sends a final open back to its ambient DbgEng path. Empty
  temporary directories prove the routing with no symbol server, matching PDB, or network.
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
  quietly took dbgscope's 120s however long its caller was willing to wait, and nothing that looked
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

- *A raw execution-control command moves the target instead of wedging the session.*
  [#226](https://github.com/glslang/windbg-mcp/issues/226), end to end through the shipped
  transport. `execute` with `t`, `p` and then `g` against a launched `cmd.exe`: each has to say the
  target moved, the `g` has to report the breakpoint it reached, and a `go` afterwards has to work
  — the last being the property the issue is actually about, since before the fix every
  execution-control call on that session failed with `0x80040205` for good while `bl` and `r` kept
  answering. All three commands rather than one, because all three are doors to the same state and
  a fix that closed one would look identical from the outside. What is asserted about `t` and `p`
  is the appended *position* rather than debugger output, and that is measured rather than a
  stylistic choice: the pump captures module loads and a stop banner for a `g` and an **empty
  string** for a step, because DbgEng prints a step's new location from the command's own
  completion and not from the wait.
- *A resume that reaches no stop says so and leaves the session usable.* The bug underneath #226,
  and the more serious of the two — reachable with no `execute` anywhere near it. A `debug_batch`
  `resume` step given three seconds against a target that will not stop in three seconds: the text
  has to say the target was broken in at the bound, `registers` afterwards has to work, and the
  report has to call the session stopped. Before the fix the finite `WaitForEvent` underneath left
  the target running with no current process/thread, so every one of those failed and the call
  still reported success. Driven through a batch rather than `go` for the three-second bound; the
  `timed_out` field `go` itself answers with is asserted false on the test above, and its true case
  belongs to dbgscope's own engine tests, where a two-second bound costs nothing.

- *A run started asynchronously is waited for, broken in, and read twice.*
  [#83](https://github.com/glslang/windbg-mcp/issues/83), the whole lifecycle in one test against a
  launched `cmd.exe /c ping -n 30` — chosen because it runs for half a minute with nothing to stop
  it, so "the target is moving" is a state the test can *be in* rather than a race it has to win.
  Six assertions, each about a different half of the feature: `continue_async` answers
  `running: true` (the claim `go` cannot make, since it answers only once the target has stopped); a
  second `continue_async` is refused as `target_running` **naming the run already there**, since a
  refusal with nothing to wait for leaves a caller stuck; `registers` is refused with the same
  category rather than queued; `session_status` reports the run while everything else is refused, it
  being the one tool that answers there; a 1.5s `wait_for_stop` runs out with no stop and leaves the
  run untouched, which is what makes a short wait a poll; and after `break_in` the stop reports
  `interrupted` — not a place the target chose to stop — with `stopped_at` and `thread` present and
  `processor` **absent**, a user-mode target having no processor number rather than processor 0. Then
  it reads the stop a second time and gets the same answer, and `registers` works again, which are
  the two halves of "a stop is read rather than taken".
- *A session can be ended while its target is running.* The teardown that cannot queue: every other
  operation on a worker's engine thread ends on a clock that process owns, while a run ends when the
  *target* stops — thirty seconds here, potentially an hour on a live kernel — so an `end_session`
  queued behind one would have its grace expire against a worker doing exactly what it was told, and
  the worker would be killed still holding the target. Asserted on `released: true` rather than on
  the call succeeding, because a teardown that killed its worker also "succeeds" and the difference
  between the two is the entire subject. It is the same release a **client disconnect** runs, which
  is why this covers the disconnect policy without staging a disconnect.

- *A target that ends during a resume is an ending, and the session says so.*
  [#242](https://github.com/glslang/windbg-mcp/issues/242) and `FOLLOWUPS.md` item 48, through the
  typed surface: `go` on a `cmd.exe /c exit` has to come back **not** a tool error, with
  `target_gone` on the stop report, no `stopped_at` (a target that is gone has no position, and
  naming one invents a stop), and the ending in the text as well — a structured-aware client
  forwards `structuredContent` and drops the text, so a fact on one half is a fact half the clients
  never see. Then the chain: `backtrace`, `registers` and `execute 'k 3'` each have to be refused
  with the same sentence and the category `stale_session`, and `end_session` has to work, since it
  is what every one of those refusals points at. Both halves are asserted because either alone is
  satisfiable by something wrong — reporting the ending while leaving the half-dead chain in place
  fixes a message, and refusing everything afterwards without reporting it turns a program
  finishing into a call that failed. The category rather than the message, which is what caught
  `engine_error` folding it into `debugger`.
- *A target that ends during the raw hatch's pump reports it with what the pump captured.* The
  minimal repro from the issue, and the corner #226's fix left open: `execute 'g'` sets the run
  state and returns its echo, so it is `settle`'s pump that the exit races. What is asserted about
  the output is only that it **survived** — which lines a `cmd.exe` prints on its way out belongs
  to the host, and the buffer being discarded with the wait's error was the bug. Plus the absence
  of "now stopped", since the sentence the *other* endings get would name a position that does not
  exist.

  These four are the only tests in the suite that drive **execution** on anything but a live
  kernel, which is exactly why both bugs survived: the live-kernel tier was already on the bounded
  wait, and no other tier can `go` at all. The two above use a target that never stops; these two
  use one that is over on the first resume, and that difference is the whole of what they add.

- *Ending a session leaves a process this server only attached to running.* `FOLLOWUPS.md` item 51,
  and the only test here whose live target the debugger did **not** create: a `ping` started by the
  test, attached to with `attach_process`, and still running after `end_session` — where it used to
  be terminated, because the engine ended the session passively and a debuggee whose debug port is
  destroyed is killed by the kernel. What this adds over the dbgscope test that covers the same
  fix is the step the original report blamed and no engine-level test contains: the **supervisor
  terminating the worker** afterwards. The result's own sentence is asserted beside the process,
  because the two endings are opposite, neither is visible from the caller's side, and a wording
  that stopped saying which one happened would leave the caller no way to tell.

  **Asked of the kernel, not of `Child::try_wait`**, and that is the trap rather than a preference:
  a debuggee the kernel kills has its exit status set before the call that killed it returns while
  its process object is not yet signalled, so `try_wait` answers "still running" for a process that
  is already dead. dbgscope's first version of this assertion passed with the fix backed out for
  exactly that reason, and `CheckRemoteDebuggerPresent` is no better — it reads `false` after either
  ending, since the passive end really does tear the debug port down, which is *why* the process
  dies. The exit code is the only probe that separates them, and it separates them completely.

**The listener's lease.** `--listen` gives up the one property stdio has for free: a closed stdin
means the client is definitively gone, and every target is released. Over HTTP a silent client is
indistinguishable from one that is thinking, so a **lease** stands in for that moment — and it is
the only part of this server whose failures cost a *target* rather than a call. Every rule of it has
unit tests in [`listen.rs`](../src/listen.rs) against the state machine directly; what those cannot
reach is the wiring, which is what these assert against a real listener on a loopback port, with a
hand-written HTTP client (a library that normalised a `409` into an exception, or hid the session
header, would be asserting on this server's behalf).

**Ten of them need no debugger**, because none of them needs a session to be open: the six below,
the three after them, and *Two clients are served two surfaces* from the section after that — whose
third test, the token file, is already one of the three. Counting them by grepping for
`Listener::start` gives nine and is wrong: *It will not start without a token* spawns the exe
itself, because a listener that will not start cannot be started by the helper.

Six are the lease's own, and not one of them presents a **second credential** — so what they prove,
they prove for the `local` client alone. That was once the whole listener tier, and the gap it left
was [`FOLLOWUPS.md`](../FOLLOWUPS.md) item 29; the three tests under [Two clients, two of
everything](#two-clients-two-of-everything) below are what closed it:

- *It will not start without a token*, and says which variable is missing. The listener exposes
  every tool here, including the ones that write to a live kernel; a quiet default would be a
  server nobody knows is open.
- *An unauthenticated request is refused, told nothing about what is here, and **costs the server
  nothing***. The last clause is the one worth a test: the bearer check runs before the lease is
  touched, so a wrong token must not renew one or reach the state behind it. It mattered more
  sharply while the gate existed — a request that reserved kept every other request of that
  credential out, so anything that could reach the port could lock the real client out without ever
  authenticating.
- *A credential's second **MCP session** is served alongside its first.* This was a `409` until the
  tenancy gate was retired (2026-08-20, [`FOLLOWUPS.md`](../FOLLOWUPS.md) item 28): with sessions
  owned per client, a credential opening a second MCP session contests nothing — both reach the same
  debug sessions, because they are the same client. Both are exercised, and the assertion underneath
  is that an id **this server never issued** is still not served. An id *another client* holds is
  refused too; that needs two tokens, so it is asserted below rather than here.
- *Going quiet is not leaving; saying goodbye is.* Every request is its own connection — which is
  what a client behind a tunnel looks like — so silence is the resting state, and a server that read
  it as departure would release a working client's targets between two of its calls. Returning with
  the id it left with is served; after a `DELETE` that id is not. The second half used to be read off
  the `409` a second `initialize` got while the first was held, which is exactly what no longer
  happens.
- *`2026-07-28` is served — the handshake **and** everything after it.* The revision current clients
  negotiate has no session id
  ([SEP-2567](https://modelcontextprotocol.io/seps/2567-sessionless-mcp)), so it exercises the
  listener as a client that never presents one: the handshake mints nothing, and a `tools/list` and
  a `tools/call` after it are answered. It exists because
  [#168](https://github.com/glslang/windbg-mcp/issues/168) reported the opposite from a hand-rolled
  probe, so it spells the revision the way it has to be spelled — the `MCP-Protocol-Version`
  header, `params._meta` carrying the protocol version and the client's capabilities, and
  SEP-2243's `Mcp-Method` (plus `Mcp-Name`, which SEP-2243 maps per method: `params.name` for
  `tools/call` and `prompts/get`, `params.uri` for `resources/read`, and nothing for the rest).
- *An under-specified stateless request is told which part it is missing*, rather than merely
  refused. Both shapes the probe sent are pinned here, so the same `400` cannot be read as a broken
  listener a second time.

Three more need no debugger either, and none of them is about the lease:

- *A **token file** names its own clients, and shuts the environment out.* Both halves pull against
  each other, so both are asserted on one listener: a file naming `local` and `ci` serves both, and
  the unnamed `WINDBG_MCP_LISTEN_TOKEN` the harness always sets — which is the environment half,
  needing no arranging — authenticates nobody. The precedence is
  load-bearing — the installer ACLs that file precisely because the machine environment is readable
  by unprivileged processes — while a file that could name only one client made the per-client
  boundary unreachable in the deployment `docs/remote-listener.md` recommends (item 31). The parse
  and precedence rules are unit-tested in [`client.rs`](../src/client.rs); what this reaches is the
  call site, a real listener reading a real file.
- *A `2026-07-28` handshake may **omit** `MCP-Protocol-Version`, and the client is ordinary
  afterwards.* It is the one request of that revision which may — `initialize` *establishes* the
  revision — and it was the likeliest shape a real client sends and the only one nothing drove:
  stdio has no headers to omit, and the harness's own stateless opener sends one. The hazard it
  used to carry is deleted rather than covered (a headerless handshake was classified as an opener
  and armed a deadline that would release the client's own targets one grace later), so what this
  pins is that the shape is served at all (item 30).
- *A run started with `--tools` advertises the narrowed surface **over HTTP**.* stdio builds one
  `WindbgServer` in `main` and the listener builds one per MCP session in its service factory, so
  the narrowing is applied on two different lines and only one of them is the one that has been
  wrong before. `--tools crash` is asserted as the eleven tools it is — `crash_triage` and the
  openers present, `debug_batch` absent — and the startup line as the surface it ended up with,
  which is not the spec that was typed.

Two more of the lease's own assertions are in the debugger tier, because each needs a real engine
worker.

The first is the contention half of #168 at its sharpest: *a stateless client can work while one of
its own calls is parked*. The park is a **kernel attach nothing will answer**, and what
runs alongside it is the recovery path itself — `tools/list`, `session_status`, `end_session`, the
last checked for a tool error as well as an HTTP status, since a refusal inside the call also
arrives on a `200`. It polls the attach to the `attaching` state rather than sleeping towards it: an
attach that failed fast leaves a kernel record a laxer check would accept, and there would be
nothing parked to contend with. The mechanism that made it contend is gone with the gate; the
property is the client's, so the test stays. It lives here rather than above because without `dbgeng.dll` the
attach fails during initialisation instead of parking, which would quietly turn a test about a call
that does not return into one about a call that failed. Budget ~21s, most of it the worker coming
up and the `end_session` that terminates it.

The second is the sweep meeting a real engine worker: *a lease
that runs out releases what the absent client left*. The target is **a kernel attach nothing will
answer**, deliberately — a parked attach is the worst case in one move, since the session exists,
holds a worker, and cannot be interrupted, so releasing it means terminating a process rather than
asking politely. The test then goes silent for a real grace period (32s, nearly the floor the
listener enforces: the grace must outlast the call budget plus the 30s an engine worker may take to
come up, so the budget is shrunk to a second) and watches **stderr**, not HTTP — every admitted
request renews the lease, so a test that polled would hold open the very thing it is waiting to
expire. It asserts the worker process is gone, the swept session id is no longer served, and the
next client gets a server with nothing left over. Budget ~40s.

### Two clients, two of everything

Three tests put **two credentials on one listener**, which is the only way to state a per-client
rule at all: with one credential, "this client's" and "the run's" are the same answer, so every
assertion passes whether or not the identity ever reached the call. That is not hypothetical — the
first of these failed for real when it was written (item 29). `listen::gate` scopes the caller
around the HTTP task, rmcp serves a legacy MCP session from a task it spawns at `initialize`, and a
task-local does not cross a spawn, so **every tool call ran as the default `local`**: both clients'
sessions were owned by `local`, each could see, route to and end the other's, and every unit test
passed, because each supplies the identity itself.

- *Two clients keep their sessions to themselves.* **Debugger tier**, and not by preference: a
  handle another client cannot use has to be a handle, and an adoption counts debug sessions rather
  than the MCP ones the protocol tier can mint on its own. Two clients open a dump each and are
  shown their own and no other's; another client's handle is reported **unknown** rather than
  refused, so the answer cannot confirm a session the caller may not touch. Asserted on the
  session-bearing route *and* the stateless one, because the bug was one of them losing the
  identity, and a fix that held for only one would make the boundary depend on the revision a
  client negotiated.
- *Two clients are served two **surfaces**.* Protocol tier — a tool list needs no target, and
  neither does a refusal for a tool that is off the surface, which is answered before anything is
  routed. The listener runs `--tools session,inspect` with `WINDBG_MCP_TOOLS_BENCH=crash` beside a
  second token, so the two answers are 19 tools and 11 and neither is a subset of the other: the
  run's flag is a **default**, not a ceiling (item 36). It also pins both halves of the refusal —
  `local` is told to widen the run's `--tools`, `bench` is told about its own entry — since naming
  the wrong one sends an operator to a spec that is not in force. Both routes again, for the reason
  above.

  **And the prose narrows with the list**, which is two more claims here because a golden records
  one surface and can see neither. The `instructions` at `initialize` are assembled per client
  (item 40), so `bench` reads 927 characters naming only tools it has where `local` reads its own;
  and no description `bench` is served names `modules`, `debug_batch`, `go` or `backtrace` (item
  41), while `local`'s `open_dump` still says which tool lists the module table. Both directions
  are asserted, because deleting the cross-references outright would satisfy the first and lose the
  pointer the fifty-one-tool client is the one that can use. Backticked names, not bare ones: this
  surface says frames are "attributed to modules" and that a stuck session "does not let go", and
  neither sentence points anywhere.
- *A **token file** naming two clients serves both* — the item-31 test in the list further up,
  counted here as well because it is the third of the three: under a service that file is the whole
  of what is read, so it is the only place a second client can come from at all.

### The commands that install a service and edit its clients

Three tests drive the exe as an **administrative command line** rather than as a server, so none of
them starts a listener. They run in the protocol tier because every claim below is settled before
the SCM is opened or the credential file is touched, which is also what makes them safe on a
developer's own host: none can disturb the clients a service is serving, and each captures whether
`windbg-mcp` is registered either side and asserts it did not move.

- *An install with no address is refused **before anything is registered**.* The SCM stores the
  command line once and nothing re-derives it, so a service registered without `--listen` is one
  that installs cleanly and then fails at every start.
- *A client command says what is missing before it touches anything.* A missing name, a name that
  is not one, and a flag standing where a name belongs — the last because a name may contain `-`,
  so `--add-listen-client --force` would otherwise mint a credential for a client nobody asked for.
  It also asserts the refusal does **not** mention the service, since consulting the SCM first
  would make a usage error depend on whether one happens to be installed.
- *Listing the clients names its source and prints no token.* The one command that only reads
  (item 37), and the only one of the three whose outcome depends on the host — a service host with
  an elevated shell answers with the file's roster, one without answers with the ACL refusal, and a
  host with no service answers for this shell's own credentials. So it asserts what holds in all
  three: it names the source it answered for, and the token handed to it in the environment appears
  nowhere in what it wrote. That second half is the trap the command was built around — a roster may
  carry a fingerprint and nothing else, which is what makes this the one client command that is safe
  to run in an agent's transcript.

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

Each row carries two numbers and the first is charged **per channel**: the model ceiling holds for
`content[].text` and for `structuredContent` separately, not only for the half this client
forwards, so a typed tool is asserted against it twice and the failure names which channel moved.
The `wire` ceiling then covers the result taken together. Raising the model number is therefore a
decision about every client rather than about ours — the tool's own doc comment and
[`token-budget.md`](./token-budget.md) carry why
([#150](https://github.com/glslang/windbg-mcp/issues/150)).

## When to run it

### A dependency moved

`rmcp`, `schemars`, `tokio`, or a `dbgscope` pin bump (`cargo update -p dbgscope`). Dependabot
watches the cargo ecosystem too, so most of these arrive as a PR — including the `dbgscope` locked
revision — and the run below is what you do on that PR, not only on a bump you made yourself.

1. `cargo test` — the protocol tier plus the existing unit tests.
2. For a `dbgscope` bump, add the debugger tier locally too — CI runs it on the PR, but a local
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

## The session fuzz

`a_randomised_command_sequence_leaves_the_session_in_one_state_and_the_server_serving`, inside the
debugger tier rather than beside it — it needs an engine and a live user-mode target, which is that
gate exactly. It is **dbgscope's `examples/session_fuzz.rs` at this server's surface**: that example
drives randomised sequences straight at a `DebugEngine` and checks, after every one, that the
session either still holds a target and answers or says it holds none. It exists because the three
defects behind [#242](https://github.com/glslang/windbg-mcp/issues/242) were each found by hand, one
sequence at a time, and none of them is about a *command* — they are about the state the previous
command left behind, and there are more ways to reach a given state than anyone enumerates.

What the port adds is everything between that engine and a caller:

- **A third state.** `continue_async` leaves a target moving with nobody waiting, and reads are then
  refused `target_running`. That state machine is the supervisor's
  ([#83](https://github.com/glslang/windbg-mcp/issues/83)) and the example cannot reach it.
- **The category a refusal carries**, not merely that it refused — `engine::engine_error`'s `_` arm
  folded "no target left" into `debugger` once, which tells a caller to change what it asked instead
  of to release the session.
- **A bystander session** on the same server, never named by a step and asked after every round:
  one worker driven into any state at all must leave the supervisor serving and the *other* worker
  holding its own target. No in-process test can state that.
- **Reclamation** of whatever the sequence left.

**The oracle is a scale, not an agreement.** The example calls any disagreement between two roads a
violation; here a run bounded at 1.5s can stop *between* one road and the next, and a target can go
away while it does. So the rule is that a probe's roads never move **back** down
`Moving → Holding → Gone`: `stale_session` and then an answer is the half-dead session, while an
answer and then `stale_session` is a program that finished a millisecond ago.

**A tool error is data; a protocol error is a failure.** A step's tool result is discarded on
purpose — `bp` on an unresolvable symbol and a `break_in` for a run that has finished are ordinary,
and what is checked is the state left behind. A top-level JSON-RPC error is not that: it means the
request never reached a debugger, which is a schema or transport regression and is what this
harness exists for. So every call the fuzz makes goes through one `fuzz_call`, which refuses one.
Discarded, it would leave the session readable, every probe passing, the run green, and a whole
corpus entry silently doing nothing — the same vacuity the `Gone` assertion stops, arriving through
the wire rather than through the walk. It matters here more than in the tests above because this is
the widest set of tools the harness drives from one place: nine, with argument shapes nothing else
exercises.

**The seed is fixed, so CI runs one deterministic walk.** Drawing from the clock would fail on a
sequence nobody could reproduce. The default (seed 3, 3 rounds of 6 steps, ~1s) is chosen because
its walk reaches all three states; how long a round lasts depends on whether it draws an unbounded
`g`, which runs the target to its own ending, so anything that reshuffles the walk — a corpus edit,
or a change to `Rng::new` — reshuffles both the coverage and the runtime, and the number is
re-derived by scanning rather than kept. The run prints the states it reached, and **asserts it
reached `Gone` at least once** —
every check is of the form "if the session is in state X it must say so", so a walk that never left
`Holding` would pass without asking the question. `Moving` is reported and not asserted: it needs a
run still going one probe later, which is a race on a loaded runner.

The fuzz proper is the soak, and it is the same test:

```pwsh
$env:WINDBG_MCP_SMOKE_DUMP = "1"
$env:WINDBG_MCP_SMOKE_FUZZ_SEED = "7"
$env:WINDBG_MCP_SMOKE_FUZZ_ROUNDS = "50"; $env:WINDBG_MCP_SMOKE_FUZZ_STEPS = "10"
cargo test --test mcp_smoke -- --nocapture randomised
```

Run it after touching anything in the wait/settle/guard seam, or in the execution slot. A failing
seed replays exactly and the panic names it, with the sequence that got there.

**It has already found one thing**, on the second seed it was run under: a handle the raw hatch had
retired could not release its own session, while the `execute` that retires it says otherwise in the
same breath. Fixed the same day (`FOLLOWUPS.md` item 55), so `fuzz_reclaim` no longer has a
fallback — however a round leaves its session, the handle that opened it ends it, and a round that
cannot is a regression rather than a documented detour.
`a_handle_a_raw_command_retired_can_still_end_its_own_session` is the targeted test that came out
of it, and the second launch in it is the test rather than scenery: with one session open the
retired one is still current, so an un-handled `end_session` reaches it and the defect is
invisible. That is why the fuzz found this on its round teardown and no single-session test did.

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
  watchdog *attempted* an interrupt, even one the engine ignored — dbgscope reports the reason as a
  field, and prose for a human is this server's to add).
- `a_bounded_command_queued_behind_another_job_still_beats_its_caller` — the same, from behind a
  `.sleep` that occupies the session for half the call budget. This is the half dbgscope cannot
  cover, because the queue belongs to this crate: budgeting from the patience as sent, instead of
  from what remains after the queue wait, passes every other assertion and fails here. Two details
  the test documents because both silently void it — `.sleep` needs a `0n` prefix (the MASM
  evaluator's default base is hex, so a bare `30000` is 0x30000 ms), and the blocker needs a head
  start, since two tool calls in flight at once reach the session's queue in whichever order wins
  the race.
- `measure_what_the_bounded_path_costs_a_quick_command` — prints what arming the watchdog costs, as
  a distribution. It asserts nothing; it is the evidence behind which tools take the bounded path
  ([`DECISIONS.md`](../DECISIONS.md), 2026-08-02). **That cost has since gone away, and so has the
  split**: the watchdog used to round a command up to a multiple of 200ms, and now parks on a
  condvar, so every raw command but `index_trace` is bounded. Re-run it after a dbgscope watchdog
  change; its comment carries the 2026-08-31 numbers to compare against.
- `arming_the_watchdog_does_not_round_a_quick_command_up` — the assertion the measurement above is
  not. It exists because that measurement is `#[ignore]`d and so went on passing across exactly
  the change it was written to catch. **It is in the debugger tier, not in a plain `cargo test`**:
  it opens the sample dump through `target_tier()`, so without `WINDBG_MCP_SMOKE_DUMP=1` it stands
  down like everything else here. What it is *not* is `#[ignore]`d, which is the difference from
  the measurement — CI runs it on all three runners.

  The oracle is a **ratio between two bounded commands of very different natural cost** — an
  `execute` of `lm` (milliseconds) against an `execute` of a ~20,000-iteration `.for` loop
  (~170ms) — and it fails if they come within 5x of each other. That is what a fixed quantum does:
  rounding both up to a multiple of the nap makes a 3ms command and a 170ms one *equal*, where
  without one they stay ~50x apart. Deliberately not a bounded command against an unbounded
  baseline plus a margin, which was the first version: the baseline grows into the margin on a
  slow host, so `200 < 120 + 100` passes on precisely the host the guard claimed to survive. A
  ratio scales with the host and the absolute numbers do not matter.

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
- **`modules { "refresh": true }` resynchronises over the KD wire.** This is the only tier where
  that call reaches a target whose module list the debugger did not watch being built. A generic
  KDNET target carries no fixture, so what is claimed here is the mechanism rather than a find: the
  reload runs, reports `synchronized`, and leaves a listing at least as complete as the one before
  it — a refresh that *lost* modules would be worse than no refresh at all. The `before`/`after`
  counts are printed under `--nocapture`, and on the bench this was written against they read
  `1 module(s) before the refresh, 158 after` — which is the size of the gap on a fresh attach,
  measured rather than argued. Finding a *named* module that was missing is the CTF tier's claim,
  below.
- **`crash_triage` refuses a kernel that has not crashed, and refuses it correctly.** This is the
  state the debugger-free exploitation loop sits in *between* fires — attached, working, nothing
  bug-checked yet — and a dump can never be in it: a dump either is a crash dump or is not, while a
  live kernel moves between the two. So this is the only place both arms of the refusal are
  reachable, and the only place it can be checked that a kernel target does not take the *user-mode*
  arm. It also checks that the refusal costs the session nothing: the loop attaches once and fires
  many times, so a triage that came too early has to leave the session exactly as usable as it
  found it.
- **`end_session` detaches gracefully rather than killing the worker.** This one has teeth: DbgEng
  leaves a detached-but-halted kernel *frozen*, so dbgscope resumes and actively detaches. A run
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
  walk to one side of the pool was closed unbuilt (glslang/dbgscope#89): it would have bought a
  faster query at the cost of a cache that keys on scope, against better than two-fold headroom
  that already exists. That margin is worth re-reading rather than assuming: the same walk cost
  ~24s and reached 437k chunks before glslang/dbgscope#92, so a walk gets *slower* as it gets more
  correct, and the next such fix spends the remaining headroom too.
  Expect INCOMPLETE on any live kernel: paged pool is
  partly on disk, so `sparse virtual range` diagnostics are physics rather than a defect, and the
  coverage caveat is doing its job. The categories that are *not* explained that way are worth
  reading, and this tier is where that paid: a run showing ~5.6k LFH subsegments rejected as
  implausible (glslang/dbgscope#90) was not the walker being careful but the walker misreading
  `_HEAP_PAGE_RANGE_DESCRIPTOR.RangeFlags` bit `0x01` as "LFH subsegment" when it means ALLOCATED,
  which sent VS, large and special-pool ranges through the LFH decoder to be refused and dropped.
  glslang/dbgscope#92 fixed the reading; that category should now be **absent**, and its return
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
test attaches over KDNET, checks that `MessageManager.sys` is loaded **before any symbol work**,
asks for one retained
allocation with `pool_find_tag { "stop_after_matches": 1 }`, verifies the result says
`match_limit_reached` with that stop condition, verifies the session still serves a register
request, and always attempts `end_session` before reporting an assertion failure.

That "before any symbol work" is the fixture's own regression, and it is
[#85](https://github.com/glslang/windbg-mcp/issues/85). The driver is loaded before the debugger
dials in, so it is in the target and not in DbgEng's inventory, and a fresh attach lists `nt` and
little else — which is how a running driver came to be reported as "not loaded". It used to be
found only *after* the tier's `load_kernel_symbols`, whose unqualified `.reload /f` resynchronised
the inventory as a side effect of fetching every PDB: the answer was right, and nothing said that a
full symbol load was what made it right. The test now asks with `refresh: true` **first**, so a
pass cannot be borrowed from the reload that follows, and asserts `refresh.synchronized` before it
believes the listing at all. Confirmed by hand against the CTF guest on 2026-08-30, on one
attach: `loaded: 1`, `modules { "filter": "MessageManager" }` matching **0**, and the same call
with `refresh: true` reporting `before: 1` against `loaded: 158` and matching the driver at
`0xfffff80343970000` with `deferred` symbols — found without fetching a PDB.

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

## The TTD tier

```pwsh
$env:WINDBG_MCP_SMOKE_TTD = "1"; cargo test --test mcp_smoke -- --nocapture ttd
```

Four tests, and the tier they belong to exists because **all three of the defects it covers
shipped** — `ttd_calls` and `ttd_memory` had returned blank rows since the initial commit, and
`record_trace` could neither pass an argument nor report a short recording as anything but a
failure. Nothing caught any of it, for a reason that is structural rather than an oversight: a
`.run` is tens of megabytes, none is checked in, and recording one needs elevation and `TTD.exe`.
So this is the only tier that **creates its own target** instead of opening a checked-in one.

Gated on `WINDBG_MCP_SMOKE_TTD=1` and deliberately **not** `#[ignore]`d as well, unlike the two
tiers above it. Those are double-gated because a stale variable costs a wedged VM or a run measured
in minutes; the worst this does is leave a few tens of MB in the temp directory, and against that
the rule that matters is the one `launch_tier` states — a gate nothing sets is a gap that stays
open.

**Elevation and a recorder are the host's business, not the gate's.** Both are read off the
recorder's own refusal — `TTD.exe not found`, `Administrative privileges`, `0x80070005` — and
print `SKIPPED`. Every *other* failure fails the test, which is the distinction that keeps the tier
honest: a helper that treated any error as a skip would pass on a machine where recording is
broken. Replay is a third stand-down, taken separately: a host can record a trace it cannot open, because
replay needs a WinDbg engine payload beside the binary, and by then the recording half has already
been asserted. It is keyed on the **server's own diagnostic** — the sentence
`worker::explain_trace_failure` appends when there is no `ttd\` beside the executable — and not on
`0x80070057`, which is the engine's "the parameter is incorrect" and can equally come from a trace
that failed to load for some other reason. Every other `open_trace` failure fails the test. A
`ttd\` of the *wrong architecture* is deliberately not excused: it gets the engine's error with no
such sentence, and a misconfigured bundle should be loud.

| Test | Claim | How it is read |
| --- | --- | --- |
| `ttd_records_a_target_that_finishes_inside_the_startup_watch_as_complete` | #233 — `hostname.exe` finishes in ~150ms against a 2.5s watch, so it exits *inside* the window, and that is a complete recording rather than a failed start | the message says "recording complete", **and** a non-empty `.run` is in the output directory — two sources for the one fact, because the old bug was a message that contradicted the disk |
| `ttd_records_the_program_a_target_with_arguments_names` | #232 — `cmd.exe /c dir …` records, instead of TTD looking for a file with that whole name | recording at all (the old behaviour could not), plus the trace being named `cmd*`, since TTD names a trace after the program it launched |
| `ttd_resolves_a_relative_target_against_the_recorders_working_directory` | the [#235](https://github.com/glslang/windbg-mcp/pull/235) review finding — a relative target is probed where the *recorder* runs, not where the server does | a fixture copied to `<work_dir>\a program.exe` and recorded as `.\a program.exe`; the trace must be named `a program*`, because the defect recorded **`a.exe`** and reported success |
| `ttd_queries_answer_with_the_fields_they_promise` | #231 — a query returns records, not a column of bare indices | `ttd_events` and `ttd_memory` must render field names (`ModuleLoaded`, `AccessType`, `Value`); the address is a module base, read every time an image is mapped |

**The queries are the two that need no symbols**, on purpose: the fields are then a property of the
query rather than of what the host can resolve, so the tier does not stand down on a machine with
no symbol server. That leaves `ttd_calls` — the tool the issue was reported against — asserted
only by `src/server.rs`'s unit tests on the command it builds, and by hand. It is the deliberate
gap in this tier, and the [manual checklist](#manual-checklist) carries it.

**Each of the four was checked by putting its defect back**, which is the only evidence that a
green tier means anything: `-r1` for the depth (both queries blank, and `ttd_events` is the
assertion that fires), the unconditional early-exit failure, `.arg(target)` for the whole command
line, and the probe against this process's directory — which fails with `` `a01.run` is not a
recording of `a program.exe` ``, the wrong-program recording exactly as it was first measured.

## The 32-bit managed target tier

```pwsh
cargo build --target i686-pc-windows-msvc
Copy-Item target\i686-pc-windows-msvc\debug\windbg-mcp.exe target\debug\x86 -Force
cargo test --test mcp_smoke -- --nocapture a_32_bit_managed
```

Two tests — a 32-bit **dump** and a 32-bit **live process** — and they are the only ones asserting
something **this server's own engine cannot do**. An extension DLL is loaded into the debugger's
process, so a 32-bit `sos.dll` cannot be loaded by the x64 engine (`Win32 error 0n193`) and the
64-bit one refuses a 32-bit CLR — the data access DLL behind it is paired to the target's
architecture too. So `!sos.threads` answering is not a check that SOS works; it is proof that the
engine holding this target is in a 32-bit process
([#234](https://github.com/glslang/windbg-mcp/issues/234)).

**The two differ only in the route**, which is why they are a pair. A dump says what it is in its
own header; a live process has none, so its architecture is `IsWow64Process2` — asked in the
supervisor, before the spawn, because a process's architecture is fixed when its image loads. Both
answers feed one image choice (`engine::worker_images`), so the same fixture program covers both:
captured for one test, running for the other.

**The tier makes its own fixture**, which is what lets it run unattended and is why the gate is no
longer a supplied path. `csc.exe` ships with every stock Windows, so the tier compiles a small
`-platform:x86` C# program that either dumps itself with `MiniDumpWriteDump` or prints a line and
waits. Dumping *itself* is what makes the capture 32-bit with no debugger package on the host: a
32-bit process loads the 32-bit `dbghelp.dll`, where a 64-bit writer pointed at the same target
produces a dump reporting the *host's* architecture. Both were measured on this project's bench —
the 32-bit capture reads as x86 and the 64-bit capture of the same process reads as x64, which is
exactly the discrimination the routing turns on. `WINDBG_MCP_X86_DUMP=<path>` still overrides the
made one, because a real capture off a real application is a better target and there is no reason
to refuse it.

The tier **asserts the dump's size, not its existence**, and that is not belt-and-braces:
`comsvcs.dll MiniDump` was measured writing a near-empty file and reporting nothing wrong, which
passes every check that only asks whether the file is there.

**What the host needs** is `x86\windbg-mcp.exe` and a 32-bit `dbgeng.dll` beside it, in an `x86\`
directory next to the binary under test — so `target\debug\x86\` for a `cargo test` run. Build the
worker with `cargo build --target i686-pc-windows-msvc`; the engine payload is the copy block in
the skill's `setup.md`, and on an x64 host the four DLLs in `SysWOW64` were measured to be enough
for this tier, which loads SOS but resolves no PDB. Both halves are checked before the worker is
spawned, because an image whose engine is missing fails in the *loader*, before any of this
server's code runs.

**The gate is the engine, and the worker is an assertion** — a split worth knowing before changing
either. A host with no 32-bit `dbgeng.dll` has no 32-bit debugger and stands the tier down. A host
with the engine but no 32-bit `windbg-mcp.exe` beside it is a *half-populated* directory, which
`setup.md` warns fails quietly, so it is left to fail loudly on the `limitation` assertion instead.
Gating on the worker would also mean a second copy of `engine::x86_worker_image`'s rule — which has
a fallback in it for a renamed running image — in a file that cannot call it.

Two assertions per test — three on the live one, which also checks its fixture is **still running**
after `end_session` (`FOLLOWUPS.md` item 51). That is duplication of the tier above only in
appearance: the 32-bit worker is a *second image*, and nothing else in the suite would notice if
that one alone went back to taking its target with it. The second of the two is the one that took a
wrong answer to find:

- **No `limitation` on the summary.** The fallback is deliberately loud — a host with no 32-bit
  worker still opens the target, on the x64 build, because native analysis of it works and always
  has, and says in the result that SOS is unreachable. So a run on such a host fails here rather
  than passing quietly, which is the whole point of asserting on it. It is also the only place the
  *fallback* is exercised end to end, since the supervisor's choice of image is otherwise a unit
  test (`engine::tests`). Read it off `summary.limitation`: the opener's payload is an
  `OpenedSession` and the field is on the `TargetSummary` inside it, so indexing the top level
  produced JSON null whatever the session reported and the assertion passed unconditionally.
- **`!sos.threads`, module-qualified.** A bare `!threads` resolves to `ext.dll`'s own native thread
  table, which an open has already loaded and which answers on *any* engine — the first version of
  this test "failed" by printing a perfectly good one. Same trap as `!analyze` versus
  `!ext.analyze -v` elsewhere in this document.

**A source edit invalidates the 32-bit worker, and the failure names the target rather than the
build.** `WorkerMessage::Ready` carries the build identity and the supervisor refuses a mismatch,
so an `x86\windbg-mcp.exe` from before your last edit is turned away and the session falls back to
this build — reported as the `limitation` above, which reads as "this host has no 32-bit worker".
Re-run the two commands at the top of this section after every change, `cargo fmt` included: on a
dirty tree that identity carries a digest over the uncommitted diff of `build.rs`'s `INPUTS`, so a
reformat moves it.

**And check the build actually happened, rather than that you asked for one.** Running
`cargo build --target i686-pc-windows-msvc` in the same breath as a `git checkout` or
`git reset --hard` has been seen answering `Finished in 0.09s` against files git had just
rewritten — Cargo's freshness is mtime-based, and a source and a target stamped within the same
second are not ordered. The failure then names the *target* ("this host could not give the target a
32-bit worker"), so it reads as a missing engine rather than a build that declined to run.
`(Get-Item build.rs).LastWriteTime = Get-Date` before the build forces it.

## Manual checklist

Not automated: no runner has a kernel target, a TTD-capable engine, or elevation. Run these by hand
before a release, or when a change touches the relevant path. Drivers live in
[`examples/`](../examples/README.md) and need `cargo build --release` first. The TTD entry is the
one that shrank — most of it is now [a tier](#the-ttd-tier), and what stays here is what that tier
does not reach.

- **Live user-mode** — `examples/test_usermode.ps1`: launch `cmd.exe` under the debugger, break in,
  read registers/modules, set a breakpoint.
- **Typed user Segment Heap** — from a sibling `dbgscope` checkout, run
  `cargo run --example user_heap_smoke`. The helper launches an x64 child that retains known
  LFH/VS/backend/large allocations, reloads the exact `ntdll` PDB, verifies each pointer and
  backend, writes a temporary `/ma` full-memory dump, reopens it, and repeats the checks. Set
  `WIN_KEXP_USER_HEAP_SYMBOLS` (or `_NT_SYMBOL_PATH`) when the default Microsoft symbol-store path
  is not appropriate. Missing private types are a failed prerequisite; export symbols must not be
  accepted as a layout. The dump is written to the operating system temporary directory as
  `dbgscope-user-heap-<pid>.dmp`, outside either checkout. The helper removes it after a successful
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
- **TTD** — recording and the two queries are the [TTD tier](#the-ttd-tier) now, which is where to
  start; it needs a WinDbg engine payload next to the binary to replay what it records (System32's
  rejects a `.run` with `0x80070057`, and the tier stands that half down rather than failing).
  What is left by hand is what the tier does not reach: **reverse execution** (`reverse_go`,
  `step_back`, `step_over_back`, `goto_position`) on a trace, and `ttd_calls` against **resolved
  symbols** — which the tier avoids deliberately, so that it does not stand down on a host with no
  symbol server. The worked example is
  [`docs/flareauthenticator-ttd-walkthrough.md`](flareauthenticator-ttd-walkthrough.md). **Read a
  row, do not count them**: issue #231 was two of these tools rendering the right number of rows
  with nothing in any of them, which a count cannot tell from a query that matched.
- **Driver IOCTL sweep** — `examples/sweep_ioctls.ps1` plus the target-side
  `examples/send_ioctls_target.ps1`; needs a benign test driver on a KDNET target.
