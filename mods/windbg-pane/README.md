# windbg-pane

A Claude Code mod that draws a WinDbg-style pane from `windbg-mcp` tool calls as they happen:
disassembly with the stop marked, registers, stack, memory, breakpoints, and a command window
showing the WinDbg equivalent of each call. It watches; it never changes a call.

```text
/windbg-pane            open the pane
/windbg-pane close      close it
/windbg-pane clear      forget the session history
/windbg-pane shape      report what the last tool result actually looked like
```

Load it for one session with `claude --plugin-dir mods/windbg-pane`, or copy the directory to
`~/.claude/skills/windbg-pane/`, where Claude Code loads it in every session.

## What it is for

A tool call's typed half says a great deal that prose does not, and a pane is the cheapest way to
see it: that `cr3` changed, that a register read is older than the last step, that a stop is in
VTL1 at CPL 0. The folding logic in `hooks/model.ts` is pure functions over one `View`, so it is
tested without an engine, a target, or a debugger.

## The thing to know before editing it

**Every fixture is a real recording, and that is the point.** `tests/recorded.ts` is a `cmd.exe`
launch breaking on `kernelbase!CreateFileW`; `recorded-kernel.ts` a live KDNET attach;
`recorded-dump.ts` an ARM64 kernel crash dump. They were captured through
`WINDBG_MCP_TRANSCRIPT`, not written by hand, because a hand-made fixture agrees with whatever the
code already does. Three defects found this way would not have been found otherwise:

- a kernel target reports `cr0/cr2/cr3/cr4/cr8`, `xcr0`, `gdtr/idtr/tr` and `kdr*`, and the pane
  drew none of them — so **`cr3`, the page-table root, was silently dropped**;
- `docs/samples/*.dmp` are ARM64, so their registers are `x0`..`x28`, `fp/lr/sp/pc`, `w0`..`w30`
  and `bvr/bcr/wvr/wcr` — **109 of them, not one matching an x64 name** — and the grid came up
  empty;
- a live Secure Kernel stop reports its registers as `registers.values[]` carrying `low`/`high`/
  `status` rather than flat `{ name, value }` rows, and its instruction as a byte *array*, so none
  of the ordinary branches saw any of it.

All three are the same mistake: a fixed list of names quietly drops whatever it does not enumerate.
The pane now picks a register bank per target, and **counts anything it leaves out on screen**
(`+n not shown: …`), so a missing class shows up as a number instead of vanishing. If you add a
target kind, add its bank — and check the count line rather than the grid.

**And a fixture only covers the shapes it happens to contain**, which is the limit of the paragraph
above. Review of this directory found **twenty-eight** more defects in the same class, none of them
reachable from these recordings: an asynchronous run reports `moved`/`running` with no stop and
names its handle in `execution`; `wait_for_stop` nests its stop under `stop`; `run_to_address`
reports an ending or a timeout through `verdict`, with `stopped_at` deliberately absent;
`goto_position` answers with debugger *text* and no payload at all; `clear_breakpoints` answers
with `remaining` and carries no `breakpoints`; `debug_batch` says what the session holds in
`after`; `current_location` carries the authoritative position, which nothing but a register read
or a stop was setting; `session_status` is the one tool that says what the *server* holds, and the
only answer to a session a failed open left provisional — including, in `execution.stopped`,
whether a run is still outstanding, which is what a `continue_async` whose own call timed out
leaves behind; and an opener that fails after creating a target puts the only handle that reaches it
in `error.session_id`, where `TargetCreated::Yes` means the handle is **usable** rather than
abandoned. Every one left stale registers, stack and memory on screen marked current, or hid a
session, or drew cleared breakpoints as armed, or sent a working session to recovery. And
`sk_read_memory` is the only guest-memory read an `open_sk_capture` session has, answering with a
type of its own rather than with the live control's — so a capture's reads were folded nowhere at
all.

Three of those are worth the extra sentence, because they are not missing fields. `remaining` is
**nullable where every other listing is not** — an empty array is the success state after clearing
everything, and `null` means the inventory could not be read — so collapsing them reports an
unreadable session as a clean one. A *read-only* batch also reports `stopped`, so a batch's note
distinguishes an inspection from a run — but **not** its staleness, and reading the final position
as proof that nothing ran was wrong: `SessionAfterInfo::Stopped` carries the instruction pointer and
no execution flag, and a resume that loops back to the same breakpoint stops where it started having
changed every register. And
`breakpoints` means two different things by tool: on the listing it *is* the answer, so empty means
none, while on a `set_breakpoint` it is an inspection taken after the mutation and best-effort, so
empty means it could not be read — and `breakpoint` beside it reports what the call actually did,
authoritatively and always.

**Five rounds in a row landed on this one seam, so the fifth was answered by enumerating instead of
waiting for a sixth.** Every panel here is built from named fields, and every round found another
tool or another field the list did not have — the same mistake as the register banks above, one
layer out. A count of what was left out will not fix it this time: that worked for the banks because
the server hands over a **closed** set to count against, and "every tool whose payload this pane
should fold" is not one. What *is* closed is the other direction — the fields — so
`src/structured.rs` was read for every payload carrying one the panels draw, and there are no more.
Memory bytes at an address are `MemoryRead`, `SecureKernelRead` and `LiveMemoryRead` and nothing
else; `stopped_at` is `StopReport` and `RunToReport`; `location_state` is `CurrentLocation` alone,
`remaining` `BreakpointsCleared` alone; and `frames`, `registers` and `instructions` are matched by
**shape** rather than by tool, so `exception_triage`'s stack folds without ever being named. The
audit found one gap of its own, which is the point of running it: a short `read_memory` carries
`stopped`, saying whether it ran out of time or somebody interrupted it, and that field's own doc
says `read_size` cannot answer the question — the pane drew the shortfall with no reason beside it.
**Most of the tool surface is named nowhere here**, and that is correct rather than a to-do list:
this draws five panels and a command window, not a view per tool.

**And the audit was still half a rule, because it only covered the fold.** The round after it found
that every one of those careful model-side decisions was being undone at the **draw**: a fold that
sees movement with no position deliberately keeps the old `ip` and does not stamp `ipAt`, and the
renderer printed that address as `ip` anyway, marked its row `▶`, and said "ip is elsewhere" about a
position nothing had re-read. The register grid already asked a version of the question and the
other three sites did not — one rule, applied in one of four places, which is what makes a class fix
look finished. `ipIsCurrent` is now the single predicate and the renderer has no opinion of its own.
So: a reading folded carefully is not a reading drawn correctly, and the place to check a staleness
rule is every site that paints the thing.

Three more from that round, each a field read instead of inferred. `Sessions::current` routes an
unaddressed call to the **newest** session that accepts one and no addressed call moves it, so the
pane now applies that rule rather than following whichever session was last named — which had it
pointing at the older of two open sessions while the server routed elsewhere.
`SessionEnded.released` says whether the *worker* let go of the target, not whether the session is
open, so a worker killed holding one left the session marked unresolved for ever;
`recovery_required` is the field that means unconfirmed, and `target_left_running` is the teardown
fact that is not recoverable afterwards.

**The draw-layer audit then closed the rest of it, and the round after found what the audit had
dismissed.** Five reads are drawn: registers, stack, memory, the position, and the breakpoint
inventory. The first four are stamped and gated. The inventory was not, and the audit judged that
harmless because an ordinary breakpoint survives a run — which is true and is not the whole set. A
**one-shot** does not: DbgEng removes it when it is hit, so a `go` after the inventory was read can
have deleted an entry the panel went on drawing as armed. `bpsAt` and `bpsMayBeStale` close it, and
the condition is deliberately the two facts together rather than a plain stale flag, so an inventory
with no one-shot in it is never put in doubt by movement alone. The disassembly is the other
ungated read and `movedAt` is correctly **not** its stamp — code does not change because the target
moved — but a patched byte does change it, and patching a byte is what `debug_batch` is for, so a
batch reporting `BatchStepInfo::changes` now drops the listing rather than redrawing stale bytes as
instructions.

**Then the round after *that* found the one-shot still marked armed in the disassembly, and three
rounds of one defect is a design answer rather than a third patch.** Each fix had been right and
local — the header's `ip`, then the breakpoint panel — and each time the next drawing site was
found by the next review, because **every site computed its own view of freshness from the raw
fields**. Being correct therefore meant remembering the rule once per panel. `drawable(session)`
now answers all of it in one place — the position, the three stale flags, and the breakpoint
addresses split into armed and doubtful — and the renderer reads that and holds no opinion. A new
panel that reaches for `Session` directly is this class of bug returning; put the fact in
`drawable` and draw it from there.

Two reads came with it. A live Secure Kernel stop's `instruction` is the one it **just executed**,
not the one at the stop — `.claude/rules/secure-kernel-live.md` says so, and `sk_live_step` refuses
that record fed back as the next instruction — so drawing it as the current listing labelled the
previous bytes as the stop and reported the ip as elsewhere, RIP being the instruction after it.
And `session_status`'s `execution` block is matched by its **handle** rather than read for its flag:
a finished run's block is kept "until another run replaces it", so presence says nothing, while a
handle the pane has not accounted for is a run it never saw — which is what a `continue_async` whose
own call timed out leaves behind, and `stopped: true` there still means every earlier read is stale.

**And the server's own answer beats a rule the pane cannot finish.** `Sessions::current` routes an
unaddressed call to the newest session whose state `accepts_default` admits — `Opening`,
`Attaching`, `Open`, `Retired` and six of the nine Secure Kernel KD phases. The pane's `state` is a
display string, so any list of the ineligible ones it keeps is a list it has to keep in step, and
`sk kd releasing` is exactly the case such a list misses. So `current` is a **belief** rather than a
value derived per call: an opener moves it, a `session_status` row carrying `current` sets it
authoritatively, and otherwise it stays. Deriving it was the previous round's fix and was wrong for
the reason this paragraph exists — it put the server's eligibility predicate in the pane, where it
cannot be completed.

So when you add a branch here, read the field in `src/structured.rs` rather than inferring it from
a payload in `tests/` — the recordings are evidence of what the server *did* send, never of what it
*can*. The field's doc comment usually states the distinction that matters, and in all three cases
above it did.

**And an absent field is not the absence of the thing it reports**, which is where a decline of mine
was too narrow rather than wrong. Review asked earlier for a `stopped_at` of `null` to be read as a
stop, and that was declined correctly: the field carries `skip_serializing_if`, so it is **absent**
and never `null`. What the decline stopped short of is what *else* produces that absence. Its own
doc says "running, gone, or has **no thread context**", and `target_gone` is a field of its own
precisely because "a target with no thread context also produces" an absent position — so a
module-load break answers a successful `go` with a report that has no position, no `verdict`, no
`running` and no `moved`, and looking for the position alone read a run that happened as no movement
at all. The tell is the report itself: `command` and `output` are the two plain strings every
`StopReport` carries, where `ExecutionStarted` has the first without the second and `RunToReport`
the second without the first. The pane now marks the reads stale and says the target stopped without
saying where.

**One of them is the host's contract rather than the server's, and it is the same mistake one layer
out.** A `tool.call` hook is handed the MCP record, so an MCP server's own `isError`
rides on `ran.result` — the very object `payloadOf` reads the payload out of — while the engine
also sets one on the result `next` resolves to. The hook read the outer flag alone and folded error
payloads as successes. `answered` reads both, and the server's own `status` as well: `Outcome` is
tagged on it, so `status: "error"` is there whichever way the host passed the call through, and it
is the authority the other two are reporting. Types for the host half are under
`.claude-plugin/types/`, written by the engine when it loads the mod.

**And one tool answers with no typed half at all, where the honest reading is a weaker claim rather
than a cleverer one.** The raw `execute` hatch declares no output schema, so a `g` driven through it
moves the target and says so only in debugger text. Review asked for the known state-changing
command forms to be recognised; that is the thing `.claude/rules/execution-waits.md` records as
impossible — `bp X; g`, an alias, `.if (1) { g }` and `dx …ExecuteCommand("g")` all reach execution
without saying so, and the server's own fix was to stop reading the text and ask the engine. The
pane cannot ask the engine, so it says the one thing that is true of any raw command: the reads
taken before it are no longer known to be current. It marks them stale and claims no position.

**A shape read correctly can still be labelled wrongly, which is a different mistake.** The two
Secure Kernel roots were drawn as `trustlet cr3` and `sk`, and neither label is a thing the reading
establishes: `cr3` is the root in force at the stop, `expectedCr3` the session's provider-hello
baseline, and `.claude/rules/secure-kernel-live.md` says plainly that CR3 is discovered and never
asserted — one live sample names no owner, so the labels could have been backwards. They are now
`cr3 at stop` and `baseline`, which is what was measured.

Reading all three brought out the one tool whose **failure carries a payload worth folding**: a
`debug_batch` that did not commit, or whose rollback did not finish, is answered as an MCP error
wrapped around an `Outcome::Ok` report (`server::batch_settled`), so `status` says `ok` while the
call failed — and its `after` is the only statement about what the session was left holding.
`foldBatch` therefore runs off the success branch. Nothing else here does: every other failure is
an `Outcome::Error`, whose payload says only what went wrong.

Some fixtures are deliberately absent. `tests/recorded-sk.ts` and `tests/sk.test.tsx` hold a lab
VM's GUID and live VTL1 addresses from a private run and are gitignored; `windbg.test.tsx` covers
the same code paths with synthetic payloads, so a clone exercises them without the bench.

`claude plugin test mods/windbg-pane` runs it. `claude plugin validate mods/windbg-pane` checks the
manifest and that every `$.state` key the module names is in `types/index.d.ts`.
