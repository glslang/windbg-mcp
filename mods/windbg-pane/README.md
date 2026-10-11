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

Install it for development with `claude --plugin-dir mods/windbg-pane`, or copy the directory into
`~/.claude/mods/`.

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
above. Review of this directory found **sixteen** more defects in the same class, not one of them
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
session, or drew cleared breakpoints as armed, or sent a working session to recovery.

Three of those are worth the extra sentence, because they are not missing fields. `remaining` is
**nullable where every other listing is not** — an empty array is the success state after clearing
everything, and `null` means the inventory could not be read — so collapsing them reports an
unreadable session as a clean one. A *read-only* batch also reports `stopped`, so marking every
batch as movement would make an inspection look like execution; the position is what decides. And
`breakpoints` means two different things by tool: on the listing it *is* the answer, so empty means
none, while on a `set_breakpoint` it is an inspection taken after the mutation and best-effort, so
empty means it could not be read — and `breakpoint` beside it reports what the call actually did,
authoritatively and always.

So when you add a branch here, read the field in `src/structured.rs` rather than inferring it from
a payload in `tests/` — the recordings are evidence of what the server *did* send, never of what it
*can*. The field's doc comment usually states the distinction that matters, and in all three cases
above it did.

**One of the thirteen is the host's contract rather than the server's, and it is the same mistake
one layer out.** A `tool.call` hook is handed the MCP record, so an MCP server's own `isError`
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
