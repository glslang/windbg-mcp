---
paths:
  - "src/worker.rs"
  - "src/engine.rs"
---

## Driving execution: the two waits, and the state a raw command can leave

**A plain `Execute` of execution-control text does not move the target.** DbgEng sets the run state
and returns; nothing happens until a `WaitForEvent` pumps it. That is why `go`/`step_*`/`reverse_*`
build `EngineOp::CommandAndWait` (→ `resumed` → `execute_and_wait`) and everything else goes through
`EngineOp::BoundedCommand` (→ `raw_command` → `execute_command_bounded`).

**The hatch used to wedge its session, and the fix is not a list of command names** (issue #226,
2026-08-25). `execute { "command": "g" }` set the run state, answered with its own echo, and left
every later `g`/`p`/`t` failing `0x80040205` while `bl`, `r` and `.lastevent` kept working — half
alive, with no way back but `end_session`. `raw_command` now calls dbgscope's `settle` after every
`Execute`, which asks the **engine** (`GetExecutionStatus`) whether it was left running and pumps it
if so. Ask the engine rather than the text: `bp X; g`, an alias, `.if (1) { g }` and
`dx …ExecuteCommand("g")` all reach execution without saying so, and the list that would catch them
cannot be finished. `debug_batch`'s `{"op": "command"}` step is the same door and is covered by the
same call, because it goes through `raw_command` too.

**Three things about that settle bite.**

- **A step prints nothing.** Measured: the pump captures module loads and a stop banner for a `g`
  and an **empty string** for a `t` or a `p`, because DbgEng prints a step's new position from the
  command's own completion rather than from the wait. So `raw_command` appends a sentence naming
  where the target ended up; without it `execute { "command": "t" }` moves the target and still
  answers with its own echo, which is indistinguishable from the bug.
- **Its budget is capped at `EXEC_WAIT_MS` as well as at what is left of the caller's clock.** The
  cap is not belt-and-braces: without it a raw `g` that reaches no stop blocks for the caller's
  whole patience, which on the default call timeout is nearly four minutes — far longer than `go`
  doing the same thing.
- **The note it appends names no tool.** It is built in the worker, which owns one session and has
  never heard of the client's surface. That is `FOLLOWUPS.md` item 43's rule, and this is exactly
  the shape it was written about.

**And underneath it: `execute_and_wait` used a *finite* `WaitForEvent` for everything that was not
a live kernel.** On expiry that returns `S_FALSE` with the target still running and the engine
holding no current process/thread, and nothing recovers — `SetInterrupt` plus another wait does not,
measured. So **any** `go`/step/`resume` that reached no stop within 60s destroyed its session, with
no `execute` involved, while reporting success. `run_to_address` had documented that hazard since it
was written and used the bounded INFINITE wait for every target type; only this path had not. It now
does, and a forced break at the bound is reported (`Interruption::Deadline` → `StopReport.timed_out`)
rather than passing for a stop.

**The last two finite waits are the openers', and they had the same defect for the same reason.**
`open_dump` and `open_trace` defer the load to the next `WaitForEvent`, so
`wait_for_event(LOAD_WAIT_MS)` *is* the load — and until
[dbgscope#136](https://github.com/glslang/dbgscope/issues/136) that call answered `Result<(), _>`,
flattening `S_FALSE` and `S_OK` into one `Ok`. A dump too large or a symbol path too cold to finish
inside 60s was therefore reported as an open that worked, and whatever the caller did next failed
with nothing connecting it to the open. It could not have been caught here: the fact was thrown away
inside the wait. dbgscope now returns a `WaitOutcome`, `worker::load_completed` reads it, and only
`Stopped` is a load that finished. Three things about it. The failure is deliberately **post-commit**
— `commit()` already sat above the wait, and the two comments there have said "a load wait that times
out still leaves DbgEng holding the dump" since they were written, so the caller is told the session
holds the target and that `end_session` is the recovery rather than another open. `Deadline` is
unreachable there (a finite bound arms no watchdog) and shares the `OnRequest` arm rather than
getting a message nothing can produce. And **the `Expired` arm is unmeasured against a real engine**:
holding a dump load past sixty seconds is not something a test can arrange, so
`a_load_that_did_not_finish_is_not_an_open_that_worked` asserts the mapping and nothing claims how
often it fires.

Two consequences worth carrying:

- **The reason the finite wait looked attractive was a sleep.** Both dbgscope watchdogs polled a
  flag on a fixed 200/300ms nap, so `join` waited out the rest of it and *every* bounded operation
  paid up to one interval — the tax `DECISIONS.md` (2026-08-02) measured at 200ms on a command whose
  unbounded median was 0.22ms, and routed the cheap queries around the bounded path to avoid.
  `Watchdog` now wakes on a condvar, so a disarm is immediate and the bound costs nothing until it
  is reached. That trade-off is retired rather than worked around; the criterion in `DECISIONS.md`
  still stands, but its price has changed.
- **The origin of a break is the watchdog's own flag**, which used to need saying because the
  watchdog reached the engine through `InterruptHandle::interrupt` like any host and so raised the
  same engine-wide flag — reading that flag alone reported the crate's own deadline as "a host
  asked". Since [dbgscope#136](https://github.com/glslang/dbgscope/issues/136) stage 2 the watchdog
  goes through a private `break_in_only` and files nothing, so the two origins are independent
  signals and there is no shared flag to misread. A host's request is instead filed against the
  **operation** it will stop, under the same lock that delivers `SetInterrupt` — which is what
  closed dbgscope#135: an operation clearing the flag as it opened could erase a request whose
  break was still on the way, and the synthetic stop was then reported as the target's own.
  `InterruptHandle::interrupt` answers a `BreakRequest` saying which operation it reached, or
  `NothingRunning`; `worker::interrupt_running` logs that and deliberately does not turn it into a
  different answer for the caller — see the comment there.

**Why nothing caught any of it.** Every tier that drives execution was the live-kernel one, which
was already on the bounded wait; a dump cannot `go`, and no tier launched a process. The debugger
tier now does (`launch_tier`, two tests in `tests/mcp_smoke.rs`). The one target type still
unmeasured on this path is **TTD replay** — `FOLLOWUPS.md` item 47.

**And after touching anything in this seam, run the fuzz** —
`a_randomised_command_sequence_leaves_the_session_in_one_state_and_the_server_serving`, which is
dbgscope's `examples/session_fuzz.rs` brought up to this server's surface. Every defect above was
found by hand, one sequence at a time, and none of them is about a *command*: they are about the
state the previous one left behind, and the number of ways to reach a given state is larger than
anyone enumerates. It rides the debugger tier on a fixed seed, so CI walks one short deterministic
sequence on three real `dbgeng.dll`s; the fuzz proper is a soak of the same test, and
`docs/smoke-test.md` has the command and what the oracle does and does not assert. Two things to
know before editing it. **The oracle is a scale rather than an agreement** — a bounded run can stop
between one road and the next, so what is forbidden is a road moving *back* down
`Moving → Holding → Gone`, not two roads differing. And a walk that never leaves `Holding` asks
nothing, which is why the run prints the states it reached and asserts it reached `Gone`; a corpus
edit reshuffles the walk, so read that line rather than the green tick.

It has already paid for itself: the second seed it ran under found that a handle the raw hatch has
retired could not release its own session, while the `execute` that retires it says `end_session`
will. Fixed the same day (`FOLLOWUPS.md` item 55) — and worth reading before touching handle
routing, because it is the case where the two gates a handle passes have to widen **together**:
`Sessions::resolve` on the caller's side and `Gate::admits` at the front of the session's queue.
Backing either half out alone was tried, and the end-to-end test fails identically both ways, since
widening one only moves the refusal to a place with no caller to explain it to.

**Its blocker moved rather than lifted, and which host it is about is the whole of the distinction.**
Item 47 defers on "replay does not work on this host at all", and the sentence before it names the
**ARM64 bench** — so that is the host, and nothing since has re-checked it. What is new is a
*different* machine: the **x64 bench** has the `ttd\` payload beside `target\debug` and
`target\release` (item 21's unpack recipe), and the TTD tier records a trace, opens it and queries
it there. Item 47's gap is a **target type**, not an architecture, so an x64 measurement would
answer it — but its sibling measurements were all taken on ARM64, and "generalised from one
backend" is the mistake item 47's own text cites. Say which bench, in the item, whenever this
moves. Before writing that test at all, note that a `go` or `reverse_go` on a replay target may
simply stop at the trace boundary, in which case the bound is unreachable rather than untested and
that is itself the answer.

**And a live target has a lifetime, which is what makes a launch test different from every other
one here.** A dump does not go away mid-test; a process does. `go` on `cmd.exe /c ping -n 30` runs
to a breakpoint on ARM64 and to *process exit* on x64 — where `cmd` opens `ping.exe`, hits
`NtCreateFile` once and then waits thirty seconds — so the same test can be about the target's
lifetime on one architecture and not on the other. A test that is not about it asserts with a
**step**, which completes on the next instruction everywhere. (That used to be the workaround for
something worse: an exit during the wait came back as `Catastrophic failure (0x8000FFFF)`, DbgEng's
raw `E_UNEXPECTED`, reported unchanged. Fixed with [#242] — an ending is now
`StopReport::target_gone` carrying what the run captured — so the step is a preference again rather
than a way round a defect.)

**Once a target is gone the session is over, and three places say so rather than one.** dbgscope
refuses every raw command, because text driven into an engine with no debuggee is a
`STATUS_ACCESS_VIOLATION` inside DbgEng that no `catch_unwind` traps — measured on a fresh engine
as well as on one whose debuggee had just left, which is what says the trigger is the missing
debuggee and not the departure. `worker::refuse_when_the_target_is_gone` covers the typed tools,
which reach the engine's own interfaces rather than `Execute` and would otherwise each fail
differently for one fact; it exempts the openers (an engine before its target reads the same),
`end_session` (the answer every refusal gives) and `interrupt` (which never reaches the queue). And
`raw_command` reports the ending from the **run** rather than the command's name, because
`.detach`, `q` and `qd` take the target away as they return while `.kill` measurably does not — it
leaves a target that still reads a stack and goes away on the next resume. A name list would have
to get that right per engine version.

Two traps if you touch this. The refusal's category is `stale_session`, and a worker's category is
only as good as `engine::engine_error`'s match: its `_` arm folded this one into `debugger` — the
exact failure its own doc comment warns about — until the launch-tier test asserted the category
rather than the message. And a session whose target is gone is still reported `open` by
`session_status`, deliberately; `FOLLOWUPS.md` item 48 says what telling the supervisor would cost.

[#242]: https://github.com/glslang/windbg-mcp/issues/242

