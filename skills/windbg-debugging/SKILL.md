---
name: windbg-debugging
description: Drive WinDbg/DbgEng via the `windbg` MCP server to debug Windows crash dumps, live user-mode and kernel targets, and Time Travel Debugging (.run) traces. Use when analyzing a .dmp, attaching to a process or the kernel, or recording/navigating/analyzing a TTD trace.
---

# WinDbg debugging via the `windbg` MCP server

This skill drives the `windbg` MCP server, which wraps WinDbg/DbgEng for four kinds of
Windows debugging: **crash-dump** analysis, **live user-mode** debugging, **kernel**
debugging, and **Time Travel Debugging (TTD)** of `.run` traces.

**Verify the environment first.** Most failures are setup, not debugging — wrong engine
DLL, missing symbols, or no elevation. Read **[setup.md](setup.md)** before the first
session of a workflow you haven't run yet in this environment.

## Pick a playbook

| Task | Playbook |
|------|----------|
| Build / engine bundling / symbols / elevation | [setup.md](setup.md) |
| Triage a `.dmp` crash dump | [crash-dump.md](crash-dump.md) |
| Launch/attach a process, or debug the kernel | [live-and-kernel.md](live-and-kernel.md) |
| Walk kernel pools or user Segment Heaps | [heap-walking.md](heap-walking.md) |
| Record / open / navigate / analyze a `.run` trace | [ttd.md](ttd.md) |
| Enumerate a driver's IOCTLs & test user-mode reachability | [driver-ioctl.md](driver-ioctl.md) |

## Tool map

Knowing which verb exists keeps you from reaching for raw `execute` when a typed tool
already does the job.

| Group | Tools |
|-------|-------|
| Session | `open_dump`, `open_trace`, `attach_kernel_local`, `attach_kernel`, `attach_process`, `launch`, `end_session`, `session_status` |
| State | `registers`, `read_memory`, `walk_memory`, `backtrace` (typed frames, each `module`+`RVA` as well as its symbol), `modules`, `threads`, `disassemble`, `dx` |
| Control | `go`, `step_over`, `step_into`, `set_breakpoint`, `run_to_address` |
| Transaction | `debug_batch` — an ordered sequence with assertions and a rollback the engine runs, not the client |
| TTD nav | `step_back` (`t-`), `step_over_back` (`p-`), `reverse_go` (`g-`), `goto_position` (`!tt`) |
| TTD analysis | `ttd_calls`, `ttd_memory`, `ttd_events`, `index_trace`, `record_trace` |
| Kernel pool | `pool_find_tag`, `pool_chunk`, `pool_census`, `pool_diagnostics` |
| User Segment Heap | `heap_list`, `heap_allocations`, `heap_chunk`, `heap_census`, `heap_diagnostics` |
| Raw | `execute` — run any debugger command, returns full text output |

The forward control tools (`go`/`step_over`/`step_into`) and the reverse ones
(`reverse_go`/`step_over_back`/`step_back`) mirror a debugger UI's F9/F8/F7 and their
Shift variants. They issue the command **and pump the engine to the next stop** — unlike
a bare `execute`, which only sets the run state and doesn't move the target.

**When a sequence mutates the target, run it as one `debug_batch`, not as separate calls.** A
patched byte, an armed breakpoint or a resumed thread has to be put back, and the call that would
have sent the cleanup is exactly the one that times out. A batch's `always` block is reached inside
the engine process on every path, including a failed assertion and an expired deadline, and part of
the budget is reserved so it has time to run; the report names the exact failing step, what each
step changed, whether the rollback completed, and whether the target is left stopped, running or
gone. Save what you are about to overwrite with an `eval` step's `capture`, and restore it in
`always` as `{{name}}`. A step can also ask the kernel pool what the `pool_*` tools ask —
`pool_chunk`, `pool_find_tag`, `pool_census` — so "capture the pointer, ask the allocator what it
is" stays *inside* the transaction instead of splitting it in two; a `refresh` there is bounded by
the step's share of the batch budget rather than by the walker's own, and says how much of the pool
it reached.

Two edges to keep in mind. If a step overruns far enough to consume the reserve too, cleanup is
skipped and the result says `rollback: INCOMPLETE` — believe it rather than the intent. And a
teardown while the batch runs — `end_session`, or a client disconnect — stops it at its **next**
step and rolls it back first, reported as `BATCH: ABANDONED`; it cannot cut short a step already
inside the debugger, so a batch built from long steps waits out the one it is in before it unwinds
(the teardown waits with it).

## Cross-cutting gotchas (apply to every workflow)

- **One command at a time per session.** Each session is its own engine process, so sessions run
  independently — but within one, work is serial. Issue tool calls for a session **sequentially —
  await each result before the next**: concurrent in-flight requests aren't ordered against each
  other, so a pipelined call can run before `open_dump` establishes a target and fail with
  `0x80040205`, and pipelining stateful debugger commands is unsafe regardless. (Normal MCP
  clients serialize call→result; this only bites custom/batched callers.)
- **Carry the `session_id`.** The tools that open a target return one; pass it on every later
  call — it routes the call to that target's engine. Omitting it means "whatever session is
  current" (the newest one still accepting work), which is fine when you only have one and a
  silent wrong-target read when you have more.
- **Opening a target does not close the ones you have.** Up to four sessions at once, so you can
  triage a dump while a kernel attach is live. `end_session` when you are done with one; at the
  limit a new open reclaims the oldest *idle* session, and refuses if every session is busy.
- **If an open times out, do not retry it** — that connects or spawns a *second* time. The timeout
  abandons the wait, not the job, so the open may still land. Ask `session_status
  { "session_id": "<the id the timeout named>" }`: it says what state the session is in and how
  long it has been there. For a kernel attach that distinction is the whole thing — a link still
  coming up (~25s) looks identical to a guest that will never dial in, and only the elapsed time
  tells them apart. Past that point the report says so, and `end_session` reclaims the session,
  terminating its engine process if the wait will not unwind. It never affects your other sessions.
- **A failed debugger operation comes back as a normal tool result**, flagged as an error and
  carrying the debugger's own text — read it and adjust (wrong symbol, unmapped address, target
  still running). So do a refused handle and a session whose engine died; all of them are things
  you can act on. Only "no engine could be started at all" is a transport-level protocol error.
- **Attach a KDNET kernel target by `profile`, not by connection string.** A connection string
  carries the target's debug key, and once it arrives as a tool argument it is in the transcript
  for good. `attach_kernel { "profile": "<name>" }` has the server resolve it locally instead, and
  `attach_kernel {}` with no arguments lists the profiles this host has — so you never have to
  guess a name. **If none covers the target, ask the user to create a profile rather than asking
  for the connection string** — specifically to add a line to `%USERPROFILE%\.windbg-mcp\profiles.json`,
  which is re-read on every attach, so it works with nothing restarted. (A
  `WINDBG_MCP_PROFILE_<NAME>` variable is read from the server's own environment at startup, so
  setting one in a shell now does nothing until the server restarts — don't offer it as the
  immediate fix.) Only if they decline is `attach_kernel { "connection": "…" }` the answer — and
  say that puts the key in the transcript, so it is their call. Never invent a key.
  [live-and-kernel.md](live-and-kernel.md) has the exact wording to give them.
- **Symbol *names* (`module!func`) need three things together:** (a) `msdia140.dll` and
  `symsrv.dll` bundled next to the binary, (b) a symbol path — set it with the
  **`set_symbol_path`** tool (`srv*C:\ProgramData\Dbg\sym*https://msdl.microsoft.com/download/symbols`,
  `append: true`), which goes through the DbgEng API and so avoids `.sympath` swallowing the
  rest of the command line — and (c) a module-qualified `.reload /f <mod>` at a *stopped*
  position (bare `.reload /f` walks every loaded module, which on a live kernel is slow) (after a
  `go`/breakpoint, **not** straight off a `goto_position`/`!tt`). Without these you silently
  get export symbols only and `module!name` lookups fail. Address-based queries, navigation,
  and memory reads still work without symbols — query by address.
- **`file not found` for a PDB usually means the engine, not the path.** `dbgeng.dll` is in
  System32, so a binary with no DLLs beside it opens targets and runs commands happily — it
  just has no `symsrv.dll` to read a symbol store and no `msdia140.dll` to parse a PDB, and
  the error summary then blames the store (`invalid UNC store`, `pingme.txt`) while the PDB
  sits in it. `!lmi <mod>` settles it: a **CODEVIEW line with a GUID** plus
  `Symbol Type: EXPORT` means the identity was known and the lookup still failed — engine or
  store, not the target. **No CODEVIEW line** is the opposite problem, and a different fix.
  Verify with `lm m <mod>` (`(pdb symbols)` vs `(export symbols)`) — never with
  `x <mod>!<sym>`, which prints *nothing* when unresolved, so its silence proves nothing.
  Details in [setup.md](setup.md).
- **Allocator tools need private PDB types, not exports** — `pool_*` resolves `nt` and `heap_*`
  resolves `ntdll`. Reload only the matching module (`.reload /f nt` or `.reload /f ntdll.dll`) and
  confirm `(pdb symbols)` with `lm m <mod>`. Missing types are a symbol problem on this host;
  symbols never come over the KD wire. See [heap-walking.md](heap-walking.md).
- **`!`-extension commands need the WinDbg `winext\` extensions bundled** next to the engine
  ([setup.md](setup.md)) **and** the module-qualified form: use `!ext.analyze -v`, not bare
  `!analyze` (which this engine resolves to *"No export analyze found"* even after `.load ext`).
  `open_dump` runs `.load ext` for you.
- **`read_memory` takes a numeric/`0x`-hex address only.** For a register/symbol
  expression use `execute` with `db`/`dd` (e.g. `db @rip`).
- **Never walk a list with a MASM `.for` loop — use `walk_memory`.** One unmapped `poi` aborts
  the *whole* script with `0x80040205` and returns nothing, so a table with one freed entry in it
  tells you only that something failed. `walk_memory` marks the hole and keeps going. Name the
  nodes with `addresses` (an explicit list), `start` + `stride` (an array), or `start` +
  `next_offset` (a chain), and `fields` to read out of each; offsets may be negative, so a pool
  header at `-16` is an argument. A chain is the one walk a hole stops — it says which node —
  and it also reports null links, loops (with where the list closed), and the resume address
  when it hits `count`.
- **Single-stepping needs a live thread context** — valid only once the target is stopped
  after a `go`/step or a breakpoint hit. Stepping straight after `goto_position 0` (before
  any thread is live) returns `0x80040205`; `go` to a breakpoint first.
- **`dx` is the escape hatch for the data model** — any LINQ query beyond the
  `ttd_calls`/`ttd_memory`/`ttd_events` wrappers, e.g.
  `@$cursession.TTD.Calls("ntdll!NtCreateFile").Where(c => c.ReturnValue != 0)`. Note it can also
  run debugger commands via `Debugger.Utility.Control.ExecuteCommand`, so like `execute` it is
  annotated destructive and retires your `session_id` when the expression touches command
  execution. Ordinary TTD queries don't trip it.
- **TTD is user-mode only** (a Microsoft limitation) — you cannot time-travel a kernel target.
- **Each tool call is bounded by a per-call timeout** (~60s for load/exec waits); a `go`
  against a long-running live target may hit it.
