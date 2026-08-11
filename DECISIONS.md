# Architecture Decisions

Decision log for windbg-mcp. Newest first. Each entry records the decision, the reasoning, and its
status. Keep entries short; link to code with `file:line` where it helps a future reader.

---

## An interrupt is bound to a job, not to a moment (2026-08-10, FOLLOWUPS item 7)

**Context.** A runaway call had one way out: `end_session`, which ends it by discarding the target.
The primitive for a gentler one existed but was only ever *timeout-driven* — win-kexp's watchdog
threads Ctrl+Break when a deadline passes, and no caller could ask for the same. What stopped it
being a five-line change is that `SetInterrupt` addresses an **engine**, not an operation.

**Decision.** `interrupt` is a per-session tool, and the binding to a job is made **in the worker,
under one lock**. The request reader reads which job the engine thread is claiming and raises the
interrupt while holding `RUNNING`; the engine thread claims and releases that job under the same
lock (`src/worker.rs`). So an interrupt reaches the job that was running when it arrived, or nothing
at all — it can never land on the one after it — and the job it reached *spends* it: any break the
engine did not consume is drained before the next job starts, and only that caller's reply is marked
cut short.

**Why the lock rather than a check.** Read-then-raise without it is a race against an ordinary job
boundary, and losing it means a caller's `go` aborted by a cancel meant for the search before it,
with nothing in the record to say why. That is a rare accident today and the *normal* case under
tasks (FOLLOWUPS item 8), where several calls in flight is the point — which is why this was built
now rather than deferred with it.

**Answered by the reader, never queued**, exactly like the abandon-a-batch signal (2026-08-09
above), and here it is the whole mechanism rather than an ordering detail: queued, the request would
be read only once the operation it means to stop had ended.

**One thing had to change in win-kexp**, and it is not the `SetInterrupt` call. The handle and the
engine share a "raised" flag, so `execute_command_bounded` can tell an aborted `Execute` from a
failed one **without being the thread that asked**. Without it an interrupt on request is a
`CommandFailed` and the output captured up to the break goes with it — most of what an interrupted
search is worth. The watchdog's explanatory note stays the watchdog's: it exists because nobody saw
that deadline pass, whereas this caller is the one who asked.

**A batch has to be told, because an interrupted step succeeds.** Preserving the output a command
reached up to the break is the point of an on-request interrupt, so the debugger returns `Ok` rather
than the error the break provoked — and a `debug_batch` step whose assertions still hold is then
indistinguishable from one that ran to completion. Left to infer it, the executor carried on
applying later mutations for a caller who had just asked it to stop. So `batch::run` checks between
steps, exactly where it checks for a teardown, and stops with its own outcome: `Interrupted` rather
than `Abandoned`, because the session is *staying* — telling a caller to resubmit on a fresh session
when the one they hold is fine is the same class of wrong answer that keeps `Abandoned` apart from a
timeout. The signal it reads is the per-job record ([`Running`]), not the batch abandon flag: that
one is sticky by design, and a sticky flag on a session that survives would refuse every later batch.

**The rollback is not interruptible, and that is the sharper end of the same fact.** Cleanup runs as
part of the same job and is reached on *every* path, so a break landing there — the first one, not
merely a repeat — hits a restore command, which returns `Ok` with partial output like any
interrupted command and is recorded as a step that worked: `rollback: COMPLETE` with the target
still changed. So the executor announces the block before it runs it (`Debuggee::rolling_back`), and
the worker seals the job against further breaks *and* drains any already pending, both under the
lock a raise has to take. Every break is therefore either lodged before the seal and consumed
there, or refused after it. A repeat while a batch is merely *stopping* is refused for the same
reason one step earlier.

**And the same fact distorts the report in two more places, both fixed by attributing rather than
guessing.** An interrupt during the *last* step is invisible between steps — there is no next step
to stop before — so every step had run and the report said `COMMITTED` of a transaction whose final
step was cut short, directly above the note saying it had been; the outcome is re-checked once the
loop ends. And a step that *fails* because the break truncated its output — a `contains` that stops
holding, an `eval` that stops parsing — reported `FAILED`, sending the caller to debug a step that
was fine. Both are attributions this executor can actually make: the between-steps check runs before
every step, so a break outstanding when one fails can only have been raised during that step.

**The root cause was the return type, and it is now fixed rather than worked around.** Four rounds
of review each found a different place that had to be told an interrupt had happened — between
steps, after the last step, when a step fails, and the plain-command path that discarded its output
entirely — and every one was wrong in the same direction, reporting the caller's own interrupt as a
fact about their target. They were all the same defect: `execute_command_bounded` returned
`Result<String, _>`, an interrupt is not an error (the output is worth keeping), so it returned
`Ok(text)` — and a `String` cannot say "this did not finish". The fact then had to travel by side
channel, and a side channel is something each reader must remember to consult.

It now returns `CommandRun { output, cut_short: Option<Interruption> }`, the shape `run_to_address`
had all along — a structured verdict *and* the text, which is what should have been copied in the
first place. Two of the four special cases disappeared rather than being fixed: the last-step case
and the failed-assertion case are both just "the step says it was cut short", read where the step's
result is already interpreted. `Debuggee::interrupted` survives for the one case a step genuinely
cannot carry — a break landing between steps — and the batch outcome now names the step the break
actually *reached* rather than the one that never started. A step is more than its action, so the
flag is collected across its assertions too: an `eval` check is two further engine calls, and a
break landing in one can leave a value that still parses and still matches, so nothing else in the
step would ever say anything was wrong.

The general lesson, since it cost four rounds: **a value that omits how it was produced makes every
reader responsible for finding out**, and readers are added over time. `Ok` for "interrupted" bought
partial output at the price of an invariant nobody could see from the type.

**This is the approved exception to engine-thread confinement** (`AGENTS.md`), and worth being
explicit about, because the rule is otherwise absolute and the code visibly departs from it.
`SetInterrupt` is the one DbgEng entry point Microsoft documents as safe from any thread; it is the
only call this server makes off the engine thread, from exactly one place (`worker::interrupt_running`
on the request reader). The engine is still created on the engine thread, never sent anywhere, and
every other call is made there. The exception is unavoidable rather than convenient: an interrupt
exists to stop an operation that is *running*, so the engine thread is busy by definition, and a
request routed through it would be read only once there was nothing left to interrupt — the
alternative is not a safer interrupt but no interrupt. It is also not new. win-kexp's two watchdogs
have Ctrl+Broken the engine from threads of their own on every bounded command and every go/step
since the bounded path existed; what changed is that a caller can now ask for the same thing.

Validated where it can be: `execute_command_bounded`'s watchdog is the same call from the same
kind of thread and is exercised by the bounded tier; win-kexp's
`test_command_interrupted_on_request_keeps_its_output` drives the new caller against a live engine;
and the dump tier's `a_running_command_is_interrupted_on_request_and_frees_its_session` drives it
through the shipped binary, with the session used again afterwards — which is what would fail if
the cross-thread call had corrupted engine state rather than merely raising a flag. The only other
cross-thread touch is the handle's own refcount, and the handle windbg-mcp holds lives in a
`OnceLock` for the life of the process, so it is never released at all.

**Status.** Adopted. What it deliberately does **not** do: drop a *queued* job (nothing can name one
— a tool call names a session, so that variant belongs with `tasks/cancel`), and reach a live-kernel
wait whose target has not connected (`SetInterrupt` cannot, so the tool says so instead of reporting
a success that does nothing). `end_session` remains the answer to that one.

---

## The rollback belongs to the worker, not the client (2026-08-09, #82)

**Context.** Multi-step debugger work that mutates a target — patch a byte, arm a breakpoint,
resume a thread — has to undo itself. Driven as separate tool calls, the undo is a *later request*,
and the failure mode is structural rather than accidental: the call that would carry the cleanup is
exactly the call that times out, and a client that disconnects sends nothing at all. The
MessageManager session grew a private PowerShell JSON-RPC client to work around this and revised it
eighteen times; every revision added something the server could not express (a verdict check, a
target-object assertion, ordered cleanup, rollback after a wrong object or a failed reclaim).

**Decision.** `debug_batch` submits the whole sequence as one `EngineOp`, and the **worker process**
executes it: steps, assertions, and an `always` block reached on every path, before the reply is
written (`src/batch.rs`). The client's timeout can no longer land between a mutation and its undo,
because there is nothing left for it to land between.

**Three properties follow, and they are the design.** The *deadline is the worker's* — a share of
the budget is reserved for `always` before the first step runs, since what is left after a step that
consumed its own deadline is nothing, and the budget itself is clamped to the caller's remaining
patience (`worker::batch_budget`) so the report lands ahead of the tool call's timeout. The
*rollback is reached unconditionally* — a failure inside it is recorded beside the original, never
in place of it, and cleanup continues past its own failures because a patch that cannot be restored
must not stop a breakpoint from being cleared. Three paths lead to it and all three are handled in
`batch::run`: a debugger error, an expired deadline, and an unwind — every engine call goes through
`batch::guarded`, because `worker::engine_thread` catches panics at *op* granularity and one from a
step would otherwise leave `run` without ever reaching `always`. What the reserve buys is time to run, not a promise:
a step that overruns it too leaves cleanup with no budget, and the report then says the rollback is
incomplete rather than implying it happened. And the *executor never touches DbgEng*: it drives a
`Debuggee` trait with a virtual clock, so assertion failure, a command failure after a mutation,
deadline expiry and a failed rollback are all unit tests rather than things a live target has to be
persuaded to reproduce.

**What is deliberately best-effort, and labelled as such.** Which steps "changed" something is a
first-token classification of the command (`batch::mutation`), biased toward over-reporting for the
same reason `changes_debug_target` is: an over-report costs a line of text, a missed one leaves a
mutation nobody knows to undo. It decides nothing about what runs. Likewise the session-state probe
answers `Stopped` only from a reading it actually got, and never reads a refused probe as
"detached" — that verdict comes from what the batch ran, because a probe cannot tell a released
target from a running one, and turning "could not read" into a verdict is the mistake the pool
tools already learned not to make.

**Validated against the workflow it was filed for.** The CTF session's own transcript
(`~/.codex/sessions/2026/08/08`) records all 18 revisions of the throwaway client and all 188 of its
invocations — 1,681 individual steps. Classified against the step language *as adopted*: 1,672 of
them are `command`, `run_to`, `resume` or `eval` shapes, and **9 were pool-tool calls a batch could
not then reach** (`@chunkt1`, `@census`, `@find`, `@findr`) — the gap that became FOLLOWUPS item 17
and is closed below. Two of the client's revisions exist only to work around
gaps this design closes — its eighth replaced a compound `.if` assertion with three pseudo-register
assignments and three regexes over printed output, and its sixteenth added a duplicate of `@run`
whose only difference was restoring a patch "on both hit and timeout", which is `always` hand-rolled.
`batch::tests::the_messagemanager_sequence_is_a_valid_batch` is the longest single invocation
transcribed, and its sibling drives the wrong-target failure the client wrote that rollback for.

**A timeout is answered by arithmetic; a teardown is answered by a signal** (2026-08-10, item 18).
The budget clamp makes the first guarantee total: the rollback runs and the report is written before
the caller's wait expires. A teardown — `Sessions::shutdown` on a disconnect, or `end_session` — is
different in kind, because it does not wait on the batch's clock at all: the `EndSession` op queues
*behind* the batch and the grace expires while the transaction is still open, so the worker was
terminated mid-patch. Neither obvious fix was worth taking: a longer grace is paid on every
disconnect, including the parked kernel attach it was tuned against, and a supervisor that tracks
what each worker is running is a change to the path every session's teardown depends on.

So the teardown carries the signal itself. The worker's **request reader** acts on
`EngineOp::EndSession` where it reads it — before queueing it for the engine thread, which is by
definition busy inside the batch — setting a flag `batch::run` checks between steps and answering
with **how long that batch may still need** (`WorkerMessage::RollingBack`). The teardown, already
waiting on that op's reply, extends its wait by exactly that figure.

A separate abandon op was the first shape, and review found what is wrong with it: telling a batch
to stop is a sticky, one-way change to worker state, and two independently gated requests can come
apart. A target-changing call landing between them retires the session, the release is then refused
as stale, and the abandon has already aborted somebody's transaction and left a flag no later batch
could get past — on a session that survives. Carried on the release, the property is structural
rather than narrow: a gate refusal stops the request before it reaches the worker, and every request
that reaches it is followed by the supervisor terminating that worker.

Sizing it from the rollback's reserve instead was the first cut, and it was wrong in a way worth
recording: the signal stops a batch at its *next* step, so what a teardown waits out is the step in
flight and then the `always` block. A reserve-sized grace expires inside a long step and terminates
the worker mid-patch — the same failure, arriving a little later, and only on the batches whose
steps are slowest. The batch's own remaining budget is the honest figure, it is bounded by the
caller's patience already, and only the worker can measure it. The reserve then goes back to being
what it always was — how much of the budget is held back for `always` — with nothing shortened to
fit a teardown.

Three properties keep that promise honest, and each of them was a defect first. The figure is
**advertised with the overrun the executor is allowed** (`batch::OVERRUN_ALLOWANCE`): a budget
bounds what a batch may *start*, and anything started just inside it still gets a watchdog floor, so
the bare budget is not a bound the worker can keep. It is stored as an **instant, not an interval**,
so it decays instead of being owed in full whenever it happens to be read. And the teardown
**re-reads it** rather than committing to one extension, because a batch that finishes early
retracts its bound to what the release still needs — a promise revised downwards is invisible to a
wait that already committed to the whole of the old one.

And the release keeps a grace of its own after all that, because it could not start until the
transaction ended — granted by the supervisor, measured from the moment the worker named, and owed
only to a teardown that actually waited on a transaction. The division of labour is the point, and
it took two rounds to find: the **worker** knows when its batch ended and says so; **how long a
release then gets** is the supervisor's own grace, the same one it would have given a session that
never ran a batch. When the worker named a release interval too, the supervisor waited that out and
*then* started its grace, so a teardown spent two of them; when it named nothing, a batch running to
its advertised bound raced the wait's last look and could be killed as the release began.

A session with nothing to unwind says nothing and costs exactly what it always did, so an ordinary
disconnect is untouched. What none of this can do is *shorten* a step already inside DbgEng, so a
batch stops at its next step boundary, not where it stands. The primitive for that now exists —
FOLLOWUPS item 7 landed as `interrupt` (see the entry above) — and a teardown still does not raise
it, because what it would buy is latency rather than safety: the grace already covers the step in
flight, and Ctrl+Breaking it would turn a step that was about to succeed into a failed one.

**Status.** Adopted, and the two things it owed are now paid (2026-08-10). **Pool steps** (FOLLOWUPS
item 17) landed as one `StepAction` variant per question rather than a generic "call a tool" step,
which would have put every tool's arguments in the batch schema twice; the part nobody had
anticipated is that a walk needs a deadline *from the batch*, because win-kexp bounds one at 120s and
an ordinary batch's whole budget is shorter — a refreshed pool step taking that default would spend
the rollback's reserve and overrun the bound advertised to a teardown, which is the failure above
arriving through the one step that is not a command. The pool *tools* went on taking that default
until [#75](https://github.com/glslang/windbg-mcp/issues/75) gave them the call's own patience, on
the same arithmetic as a bounded command. And the **mutating batch** (item 16) is now
exercised on a live kernel, which is the only place the claim can be false: a byte patched in a dump
is patched in a file nobody reads again, so a rollback that silently did nothing satisfies every
assertion the dump tier can make.

---

## Connection strings are parsed, not scanned (2026-08-09, follows #81)

**Context.** Redaction started as a scanner: walk the raw string, and at each `=` work out where
the parameter name began and where its value ended. Review found four holes in it, in four rounds.
A `,\r\n` before a name made the name `"\r\nkey"`, which matched no secret. Whitespace after the
`=` made the value measure zero-length, so nothing was masked and the remainder — key included —
was then emitted whole. Each fix was correct and each was narrow, because the scanner had no
invariant to violate: it was a list of delimiters someone had thought of, and every input was a
chance to think of one fewer.

**Decision.** Parse the string once into the structure DbgEng's syntax already has — a transport
prefix, then separator-delimited items, each a `name`, or a `name` and everything after its first
`=` — and render from that (`src/kdconn.rs`, `Parsed`/`Param`).

**What the parse buys is one property: it is total.** Every byte of the input lands in exactly one
field, so rendering with secrets kept reproduces the input character for character. That is a
claim a test can make over a generated corpus, and it is the claim the safety rests on: a value is
emitted only from a `value` field, and a secret parameter's `value` field is never emitted. Any
decoration — whitespace, line breaks, doubled separators — changes which *field* text lands in and
cannot change which parameter owns it, because the only boundaries are the two structural ones
DbgEng itself uses. The class of bug is gone rather than four instances of it.

**Why not keep hardening the scanner.** It was working, in the sense that each fix was right. But
"is this correct?" was being answered by re-deriving the delimiter rules per input, by whoever
happened to look, and four rounds of that is the evidence: nobody could hold the whole rule set at
once, so the review found what review happens to find. The parse replaces that question with one
anybody can check mechanically.

**Whitespace is refused, not interpreted.** It is the one character class with two readings, and
each leaks under the other: in `net:port=50000 key=1.2.3.4` (a missing comma) the space *separates*
two parameters, and reading it as filler swallows `key=` into `port`'s value unmasked; in
`net:port=1,key= 1.2.3.4` (a stray space) it is *filler*, and reading it as a separator leaves
`key` empty and turns the key into a bare flag. The scanner picked the first reading and leaked the
second; the first cut of this parse picked the second and leaked the first — which is the evidence
that nothing in the string says which was meant. So a connection carrying interior whitespace is
refused by `is_dialable`, and `redact` reports one as `<connection redacted>` in full rather than
guessing. It costs a readable label for a string that is refused anyway; the label exists to tell
two targets apart, and no version of that is worth disclosing a key for. (The outer trim runs
first, so a pasted string with a trailing newline is still fine.)

**Both gates read one predicate**, `is_ambiguous` — whitespace or a control character. They have to
agree: a character only one of them refuses is a character that reaches the parse by whichever route
the other guards, and the first cut of this had exactly that gap. `trim` strips whitespace only, so
a name of `"\u{0}key"` compared equal to nothing and its value was emitted whole — the same failure
the whitespace refusal was added to prevent, one character class over.

**The unredacted render is `cfg(test)`.** `Secrets::Keep` does not exist in a release build — a
build that could produce an unredacted render would be a build with a second way to print a key.
The totality check needs it; nothing else may have it.

**Status.** Implemented. Every redaction test from #81 passes unchanged, including the four
regression cases, alongside the totality tests and the ambiguity ones.

---

## The KDNET key is resolved server-side, and connection strings are a type (2026-08-09, issue #81)

**Context.** `attach_kernel` took a raw DbgEng connection string, and a KDNET one carries the
target's debug key. A tool argument is not a private channel: the client owns the transcript, and
during the MessageManager CTF session the single key supplied was replicated into 524 records of it
— messages, tool calls, context snapshots, compaction summaries. Nothing the client did was wrong;
that is what keeping a conversation *means*. The server's fault was giving the client no way to
avoid handling the secret in the first place.

**Decision.** Two changes, and they answer different halves of the problem.

- **Profiles.** `attach_kernel` takes exactly one of `connection` (unchanged) or `profile`, a name
  resolved inside this process from `WINDBG_MCP_PROFILE_<NAME>` or a machine-local JSON file
  (`src/kdconn.rs`). The name is not a secret, so it can be repeated through a transcript
  indefinitely at no cost. This is the half that keeps the key out of the request.
- **`Connection`, a string that cannot be printed.** Its `Debug` and `Display` render redacted, and
  the raw value is reachable only through `expose()` — called once, in the worker, handing it to
  DbgEng. This is the half that covers the string that *is* still supplied explicitly.

**Why a type rather than "remember to redact".** The leak surfaces are not one place: a session
label shown by `session_status` and by the "no room to open another" list, a tool error, a log line,
and `EngineOp`'s derived `Debug` — which nothing prints today, and which the next person to debug
the pipe protocol will reach for. A redaction helper called at each of those is correct until
someone adds the fifth. Making the *value* unprintable moves the guarantee from a review checklist
to the type system, at the cost of one `expose()` call whose name says what it does.

**Why redaction is scoped to connection strings.** The obvious stronger move — filter every string
leaving the server for `key=` — was rejected. This server's whole job is returning debugger output
verbatim, and on a CTF target a flag can look like anything; a filter that rewrote `!reg` output or
a memory dump would corrupt the answers people came for, silently and in the direction of "the tool
is lying to me". So `redact` masks values in *connection strings*, at the points where a connection
string is rendered, and nothing else.

**Why exclusivity is a runtime check, not a schema `oneOf`.** An untagged enum renders as a schema
composition, and clients handle those unevenly — the same reason each tool's arguments are a plain
self-contained object with `session_id` repeated rather than flattened (`src/server.rs`, "Tool
parameter types"). Both fields are optional on the wire and `kdconn::select` refuses both/neither
with a tool error naming the alternative. The "neither" error lists the profiles the host has, which
is the load-bearing part: an agent that cannot discover a profile name asks the user, the user
answers with a connection string, and the key is in the transcript after all.

**Where the resolved value is allowed to go.** Only into the op sent down one worker's private
pipe. Both processes this server creates are spawned *without* `WINDBG_MCP_PROFILE_*` in their
environment — the engine worker (`engine::spawn_worker`) and the TTD recorder (`ttd::record_launch`)
— and what matters is the process after each of them: `launch` runs an arbitrary binary under the
debugger and `TTD.exe` launches the recorded target, both inheriting the environment they were
given. Those are the least trustworthy processes in any of these workflows, and frequently the
whole reason for the session. Resolution happens in the supervisor for a second reason too — a
selector the caller must fix is refused before any worker is spawned, so a typo costs a message
rather than a session to end.

**Configured names are validated on the way in, not on the way out.** A name is *rendered* — in
the profile list, in a session label, in a collision report — so a name that is not one never
enters the map. The failure that motivates this is not exotic: an entry written the wrong way round
makes the JSON key the connection string, and an unvalidated name would then print a key out of the
error saying the entry is wrong. Rejections are located and counted, never quoted, for the same
reason a mistyped `profile` argument is not echoed.

**Status.** Implemented. Unit tests in `src/kdconn.rs` (fake values throughout); protocol-tier and
debugger-tier smoke tests assert the fake key reaches neither the transport nor the log.

---

## One process per debug session (2026-08-02, issue #61)

**Context.** A live-kernel attach waits for its target with `WaitForEvent(INFINITE)` — a finite
timeout returns `E_NOTIMPL` and never drives the KD link — and `SetInterrupt`, the one DbgEng call
safe from another thread, cannot reach a wait that has not yet connected. So a guest that is powered
off, not booted with debugging enabled, or pointed at the wrong host/port/key parks the attach
**permanently**: measured on hardware at 300s with no bound and no cancellation path. With a single
engine thread that park owned the whole server. Every other tool queued behind it, `end_session`
included, and the only recovery was restarting the process.

**Decision.** Run the MCP protocol in a supervisor process and each open target in its own engine
worker child process (`src/engine.rs`, `src/worker.rs`, `src/proto.rs`). dbgeng.dll holds one
debuggee session per process, so the process *is* the natural unit of a session — this is the shape
the library already imposes, not one invented for the bug.

**Why not the cheaper options.** Three cheaper-looking answers were on the table; none of them is a
fix, though the second fell out of this one for free:

- *Documenting the park in the tool description* leaves the failure in place. It is the most common
  mistake in kernel debugging — a guest not booted in debug mode — so an agent will hit it, and
  "restart the server" is not something an agent can do.
- *Making the pending state age-aware* turns an indistinguishable state into actionable advice, but
  the only action it could name was still a restart. Under process-per-session the same reporting
  names a recovery that works, so `session_status` does it anyway: it distinguishes a KDNET link
  still coming up (~25s) from one that has been waiting far past any healthy attach.
- *A worker **thread** is not a substitute.* Detaching a `JoinHandle` frees nothing: the thread, its
  stack, the `DebugEngine`, its COM objects and the claimed transport endpoint all live on blocked
  for the life of the process, and each retry leaks another set. Only a process can be reclaimed.

**What it cost.** A closure cannot cross a process boundary, so the closures that were marshalled
onto the engine thread became serializable operations (`EngineOp`). They are deliberately
*tool*-shaped rather than DbgEng-shaped: a tool whose work is several engine calls —
`reachable_from_dispatch`'s call-graph walk, `run_to_address`'s resolve-then-run — must stay one
indivisible job, or another call for the same session could interleave between the parts and the
walk would see a target that moved underneath it.

The watchdog budget also split. The supervisor now sends the caller's remaining *patience* and the
worker derives the deadline from it, because the supervisor writes a request the moment it is
submitted and the queueing then happens on the far side of the pipe, where only the worker can
measure it. Computing the deadline on the supervisor's side compiles, passes the unqueued test, and
is wrong: a command that queued for most of the budget would run a full budget *after* its caller
gave up. That is not hypothetical — it is the bug the first cut of this change shipped, caught by
the queue-aware test, and it is why the arithmetic lives next to the thing it arms.

**What it bought beyond the bug.** `session_id` stopped meaning "detect that the target changed
underneath you" and started meaning "route to the worker that owns this target", which retires a
whole class of accident rather than reporting it: an `open_dump` cannot disturb a kernel attach, and
an `end_session` for session A can no longer be ordered against an open of B, because there is
nothing shared to order. Sessions became concurrent (bounded at `MAX_SESSIONS`, 4). And the one
protocol-level error class shrank to "no worker could be started at all" — every other failure is
now scoped to a session and has a next move, so it belongs in the tool result.

**Corroborated upstream.** win-kexp reached the same conclusion from the library side while this was
in review, and now documents it on `attach_kernel` itself: *"Callers that must stay responsive (a
server, an MCP endpoint) need a **separate process they can kill**. Moving the call to a worker
thread and abandoning it is not a recovery"* — the thread, its stack, the `DebugEngine`, its COM
objects and the claimed transport endpoint all live on blocked, and each retry leaks another set.
The same commits settle a detail this server reports on: a guest that is not booted in debug mode
**never dials in at all**, so the wait is stuck in the *connect* phase rather than in a break-in
that failed. That is why `session_status` says a long-parked attach will not end on its own *while
the target stays unreachable*, and equally that fixing the guest still lands it.

**Status:** landed. FOLLOWUPS item 10 records what moved for items 7–9, which were written against
the design this replaced.

---

## Which tools run on the bounded-command path (2026-08-02)

> **Since:** process-per-session (above, same day) moved the pieces this entry names. The bounded
> path is now `EngineOp::BoundedCommand`, the budget arithmetic lives in `src/worker.rs`, and the
> measurement test moved to `tests/mcp_smoke.rs`'s bounded-command tier. The coverage rule below is
> unchanged and still the rule; what changed is that a runaway command now pins one session rather
> than the server.

**Context.** `EngineHandle::run_command` (`src/engine.rs`) runs a raw command under win-kexp's
`execute_command_bounded`, whose watchdog `SetInterrupt`s the engine before the caller's timeout so
a runaway command aborts instead of pinning the single engine thread. It was adopted (#45) for
`execute`, `dx`, `ttd_calls`, `ttd_memory`, `ttd_events`. Every other command-executing tool —
`backtrace`, `modules`, `threads`, `disassemble`, `set_breakpoint`, `goto_position`,
`driver_object`, `device_object`, `irp_stack`, `ioctl_trace`, `index_trace` — still calls
`execute_command` through plain `run`. #46 asked whether that split is principled or accidental.

**The measurement that decides it.** Arming the watchdog is not free, and its cost is not a small
constant. win-kexp spawns a thread that polls a `done` flag on a 200ms sleep and joins it after
`Execute` returns — so the join waits out the rest of that sleep, and a bounded command takes
`ceil(d / 200ms) * 200ms`. Measured against the sample dump
(`measure_what_the_bounded_path_costs_a_quick_command`, `src/engine.rs`):

| command | unbounded (median) | bounded (median) |
| --- | --- | --- |
| `lm` | 0.22ms | ~0.3ms **or** ~200.7ms — it races the watchdog's first poll |
| `.for`, short | 127ms | 200.8ms |
| `.for`, long | 377ms | 401.0ms |

Read as a tax on a point query: **anything taking 1–200ms now takes 200ms** — a 30ms `k` becomes a
200ms `k`. Only sub-millisecond commands can escape, by finishing before the watchdog thread's
first poll, and that is a race rather than a guarantee (the `lm` median flips between the two modes
run to run on one host). An analysis session issues these by the dozen.

**Decision.** Keep the split, on a stated criterion rather than on "these felt slow":

> Bound a command when its cost scales with the **target's size** or with an **arbitrary
> caller-supplied expression**. Leave point queries against current target state unbounded.

- **Bounded.** `execute` and `dx` are open-ended hatches — the caller supplies the command, so
  nothing bounds their runtime. The `ttd_*` wrappers are whole-trace scans, i.e. O(trace), and
  traces are routinely gigabytes. These are where the wedge actually happened.
- **Unbounded.** `k` walks one stack, `u` decodes a screenful, `lm` lists what is loaded, `!irp`
  formats one structure, `bp` sets one breakpoint. Their cost is set by a small fixed feature of
  the target, not by anything the caller says, so the 100ms buys nothing. `!tt` (`goto_position`)
  looks trace-scaled but is not: a seek replays from the nearest keyframe, so it is bounded by
  keyframe spacing rather than trace length.
- **Already bounded elsewhere, so not routed here.** The execution-control tools (`go`, the
  `step_*` family, `reverse_go`) go through `execute_and_wait`, and `run_to_address` through
  win-kexp's `run_to_address`; both carry their own watchdog. The openers are bounded by
  `LOAD_WAIT_MS` on the wait half. A second watchdog would be redundant.
- **`index_trace` is a deliberate exception.** `!ttdext.index -force` *is* O(trace) and can
  legitimately run for many minutes, so the criterion above would bound it — but it is the one
  case where the abort is worse than the wedge. `-force` deletes an unloadable `.idx` and rebuilds
  it, so interrupting mid-rebuild can leave no usable index at all, and the long run is productive
  work rather than a runaway. A wedge here is temporary and self-heals when the build finishes.

**What the criterion does not cover.** `reachable_from_dispatch` issues *many* `uf` commands inside
one job, with `max_functions`/`max_depth` supplied by the caller and uncapped. That is
caller-controlled unbounded runtime, so by the criterion it should be bounded — but `run_command`
bounds a single command string and cannot help a multi-command job. It needs a job-level deadline
instead; see FOLLOWUPS.md item 13.

**Status:** accepted. Revisit if win-kexp's watchdog stops quantizing to 200ms (parking on a condvar
instead of polling a sleep would make it ~free), at which point "bound everything except
`index_trace`" becomes the cheaper and simpler rule — FOLLOWUPS.md item 14.

---

## Dynamic confirmation of static reachability (2026-07-03)

**Context.** `reachable_from_dispatch` (`src/server.rs:1195-1279`) gives a *sound* static verdict
that a target instruction is reachable from an IOCTL dispatch routine, following only
directly-resolvable control-flow edges, and reports the call path (`reconstruct`,
`src/server.rs:442`). It deliberately stops short of the next thing an analyst wants: the *input*
that actually drives the CPU to that block. Two structural reasons — for a conditional branch the
walker keeps **both** directions (`walk_function`, `src/server.rs:285-293`), and it has **no operand
semantics** (it text-parses `uf`; there is no decoder). The decisions below shape a "confirmation
client" that closes that gap for kernel IOCTL drivers.

The data required to execute a reachable block's first instruction is a **solution to the path
condition**: the conjunction of on-path branch predicates over the dispatch inputs — a device
handle (past the security/DACL open-gate), the `IoControlCode` (routes the switch; the one datum the
static walk can't derive), the method bits, the input/output buffer lengths, the input-buffer bytes
each on-path `cmp/test … jcc` tests, and any ordering/device-state preconditions. Offsets are
already known to the codebase (`ioctl_trace`, `src/server.rs:1173-1178`).

### D1 — Confirm reachability live (KDNET/VM), not via TTD
The reachability feature targets **kernel** IOCTL dispatch. TTD is user-mode only, so the otherwise
attractive offline oracle — `ttd_memory(addr,"e")` as an execute-access "did this block run" query,
plus reverse debugging — does not apply. Confirmation happens **live** on a real KDNET/VM target. A
*local* kernel (`attach_kernel_local`) cannot set code breakpoints (`src/server.rs:1167`), so a real
KDNET/VM connection is required.

### D2 — Bridge static→dynamic with a "path recipe," not a solver
Extend the analyzer to emit, for the found path, each on-path branch **with the direction required**
and the **decoded predicate** (e.g. `IoControlCode == 0x22xxxx`; `InputBufferLength >= 0x20`;
`SystemBuffer[0x8] == 1`). That recipe is the concrete "what data" answer and feeds an out-of-band
usermode IOCTL harness (`CreateFile` + `DeviceIoControl`). Full concolic/symbolic synthesis that
*emits* a concrete buffer is **scoped out** (offload to angr/Triton over a memory snapshot if it is
ever needed); kernel state, loops, hashing, and stateful protocols make it brittle and a separate
project.

### D3 — New execution/read/write primitives live in win-kexp, not the `execute` text hatch
`win-kexp` is the typed DbgEng foundation. New primitives (`run_to` with a structured stop reason,
typed register read/write, `write_virtual`) are added there as typed `DebugEngine` methods over the
COM interfaces. `windbg-mcp` stays thin: MCP tool wrappers over those methods, plus the engine-free
analysis (directional path + recipe), which is pure text processing and correctly stays in
`windbg-mcp`. `win-kexp` is a git dependency pinned to `777b5c2`; changes land there first (with its
own tests), then `windbg-mcp`'s `Cargo.toml` moves the pin forward.

### D4 — The state-injection variant is lower priority
An alternative to driving a real client is to break at the dispatch entry, craft an IRP +
IO_STACK_LOCATION + SystemBuffer in memory, set `rcx`/`rdx`, and `go` to the block. It is
**deprioritized**: a wrong or partial IRP mutates live kernel state and can bugcheck the target —
destroying the clean, reproducible state the analysis depends on and making near-misses
non-deterministic. It also still needs the same D2 path data. Keep it as a fallback for targets with
no drivable client, build it only after the drive path, and prefer a snapshot-restorable VM. The
typed **write** primitives it needs (`write_virtual`, register write, `ba` data breakpoints) defer
with it.

### D5 — Build order
1. `win-kexp`: structured breakpoint / `run_to` stop-reason + typed `read_register`.
2. `windbg-mcp`: directional path extraction + `iced-x86` operand-decoded recipe (engine-free,
   unit-tested like the tests at `src/server.rs:1503+`).
3. Usermode IOCTL harness (out-of-band helper).
4. *Deferred with injection:* typed write primitives (`write_virtual`, register write) + the
   injection path itself.

**Status:** accepted; implementation starting at D5 step 1.

### Implementation note (2026-07-03)

Landed as one change across both repos, with two refinements to D5 confirmed during planning:

- **D5.2 recipe decode is `uf`-operand text, not `iced-x86`.** The reachability subsystem is
  deliberately engine-free and text-based (no decoder in `Cargo.toml`), and its unit tests feed
  synthetic `uf` blocks. Decoding the handful of on-path `cmp/test` predicates from the operand
  column `uf` already prints keeps that property (no new dependency, still unit-tested with
  `uf_fn`) at the cost of being heuristic on complex predicates — the boundary where the scoped-out
  symbolic path (D2) would take over. Implemented in `src/server.rs` as `path_recipe`/`format_recipe`
  (types `Direction`/`Predicate`/`IoField`/`BranchStep`/`SegmentRecipe`); the field mapping reuses
  the IO_STACK_LOCATION offsets `ioctl_trace` encodes (`+0x18`/`+0x10`/`+0x08`).
- **D3/D5.1 `run_to` lives in win-kexp.** Added `DebugEngine::run_to_address(addr, timeout_ms)
  -> RunToResult` (a one-shot `g <addr>` + structured `RunToOutcome::{Hit, StoppedElsewhere,
  Timeout}`), reading the instruction pointer typed via `IDebugRegisters::GetInstructionOffset`
  (new `instruction_pointer` helper). `windbg-mcp`'s `run_to_address` tool is a thin wrapper.
  Delivered on win-kexp branch `feature/run-to-address`; `windbg-mcp`'s `Cargo.toml` tracks that
  branch until it merges to win-kexp `main`, then the pin moves back.

Typed **read_register** (beyond the private `instruction_pointer`) and the injection/write
primitives (D4) remain deferred.
