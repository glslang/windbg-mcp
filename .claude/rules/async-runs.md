---
paths:
  - "src/**/*.rs"
  - "tests/**/*.rs"
  - "build.rs"
---

## A run the caller is not waiting for (`continue_async`, #83)

**The wait that went away is the caller's, not DbgEng's, and confusing the two is how this gets
rebuilt wrongly.** A target moves only while the engine thread is inside `WaitForEvent` — `Execute`
sets the run state and returns without the target having moved, which is the same fact
[#226](https://github.com/glslang/windbg-mcp/issues/226) turned on. So there is no arrangement in
which the worker starts a run, goes back to its queue, and the target keeps going: it would sit
still. What `EngineOp::Resume` changes is only *when the reply crosses the pipe*. The engine thread
executes, reports `WorkerMessage::Resumed`, and stays in `settle` for the whole run; the milestone
is what lets `continue_async` return.

**Which makes the supervisor the owner of the whole thing, and there are three places it has to be
right.**

- **The slot is filled before the job is queued**, not when the milestone lands
  (`Sessions::start_execution`). A session whose `execution` slot says nothing is running is one
  where every tool may read the target, so a slot filled *after* the worker answered would leave a
  window in which the target may already be moving and this side would let a `registers` through.
- **The reply is filed by a task, not by the caller.** `continue_async` spawns it before it waits
  for anything, because the case it exists for is the caller not being there — a client that
  disconnects mid-run must still leave a stop somebody can read. A caller that times out therefore
  leaves the run in place rather than abandoning it, which is why that error names the handle.
- **A stop is read rather than taken, and a run is replaced rather than cleared.** Two
  `wait_for_stop` calls on one handle must agree, and a run that finished while nobody was waiting
  has to still be there. The slot is only ever overwritten by the next `continue_async`.
- **`continue_async` waits on the *slot*, and the milestone has to bump it.** The milestone
  arrives on its own `oneshot` (`Waiting::resumed`), read at the top of the loop; the loop then
  waits on `Session::execution_changed`, which is what the filing task moves. Nothing touches that
  watch when a run *starts* unless `reader` says so — so without the bump in its `Resumed` arm the
  call sleeps until the run **ends**, answers `running: true` about a run that is over, and reports
  no bound left. That shipped in this branch's second draft, when a `select!` over both signals
  became "read the milestone, then wait on the slot", and **every ordering test still passed**: the
  one that sends the milestone and the reply together is satisfied whichever wakes it. What caught
  it was CI's debugger tier, as a call that took exactly as long as its target ran. The assertion
  that states the property is `a_run_is_handed_back_while_the_target_is_still_moving` — it sends
  the milestone and **no** reply, so a call that waits on the stop cannot pass it.

**Filing is keyed by *job*, not by handle**, and this is the one that looks like a detail. The
filing task outlives its caller, so by the time a reply arrives the session may be on a later run; a
reply matched by handle alone could land the run-before-last's stop on the one in flight — reported
as a target that had stopped when it is still moving, which is precisely the state that gets
somebody to read a moving target.

**The refusal is a refusal and not a queue** (`Sessions::refuse_while_running`), with its own
`EngineError::TargetRunning` and `ErrorCategory::TargetRunning`. Queued, a `registers` behind a run
would be answered whenever the target next stopped — up to `max_run_ms`, an hour — about wherever it
happened to be, and from the caller's side that is indistinguishable from a hung debugger. Three ops
go through: `Interrupt` (answered ahead of the worker's queue, so it never waits for the engine
thread), `EndSession` (a teardown refused because the target is running is a session nothing can
release), and `Resume` itself, which the slot refuses instead, naming the handle already there.

**And the refusal is only as good as its ordering, which is what `Session::submit_gate` is for.**
Reading the slot and putting the job in the queue are two steps, and between them a submitter holds
nothing — so an ordinary call could pass the check with the slot empty, be descheduled, and enqueue
*behind* a `Resume` that claimed the slot in the meantime. It then waits out the whole run inside
`WaitForEvent` instead of being told the target was running, and if the run outlasts its call
timeout its caller sees a timeout while a command that may **mutate** the target still runs when the
target stops. The gate is a per-session lock held across both steps by both submitters, so a call
either queues ahead of the resume or is refused by it. A lock of its own rather than the slot's,
because the enqueue also takes the registry lock while `Sessions::snapshot` takes the registry lock
and then the slot's — nesting the slot outside the registry would close that loop.

**And `end_session` breaks the pump in rather than waiting for it** (`worker::stop_resuming`,
called beside `announce_teardown` from the request reader; `Running::pumping` is claimed around the
whole of `resume` — the `Execute` included — because a teardown arriving in the window before the
flag was set would find nothing to break and queue behind the whole run). Every other job on that thread ends on a
clock this process owns; a run ends when the *target* does. Queued behind one, a teardown's grace
would expire against a worker that is working perfectly and the worker would be killed still holding
the target — a live kernel left halted, an attached process taken down with the debug port. It is
deliberately narrow: it breaks a job that is **pumping a resumed target** (`Running::pumping`) and
nothing else, so a teardown behind a long `pool_census` still lets it finish, which is what every
release here has always done. A client disconnect runs the same release, so the disconnect policy is
this one and needs no separate mechanism — `a_session_can_be_ended_while_its_target_is_running` is
what covers both.

**Breaking the pump is half of it, and the half that only reaches a run which has already started.**
A resume still in the engine thread's queue — behind a long `pool_census`, or simply not yet
dequeued — has no pump to break, so a teardown finds none, queues behind it, and waits out the whole
run it arrived too early to stop: the same killed worker, reached from the other side of one
instant. So `stop_resuming` also sets `Running::tearing_down`, and `resume` claims the pump through
`Running::claim_pump`, which refuses while that is set. The two are read and written under the one
lock in opposite orders — the reader sets the flag and *then* reads `pumping`, `resume` reads the
flag and *then* claims — so whichever gets there first, the other sees it. A run is either broken in
or never started, and there is no third outcome where the teardown waits.
`a_teardown_either_breaks_a_run_or_stops_it_starting` stages both orderings.

**The same door is closed on EOF**, which is the path with the sharper version of the reason. When
the supervisor dies the worker's reader falls out of its loop and asks the engine to release the
target, waiting `ABRUPT_EXIT_RELEASE` — five seconds, against a run that may have an hour left. So
that path calls `stop_resuming` too, before it queues the release. Without it the wait expires
against a worker that is working perfectly and the process exits with the target never released:
exactly the halted live kernel that release exists to prevent, on the one path where nobody is left
to ask again.

**A break-in names the job it is for, and that is not the same guarantee an `interrupt` has.**
`EngineOp::Interrupt` carries `job: Option<u64>`. `None` is the `interrupt` tool, whose caller named
a *session* and gets whatever that session is running — the binding is made in the worker, under the
lock that claims and releases a job, so it can never land on the one after it. `break_in` is the
other caller and needs more: it holds a handle to **one run**, and between reading the slot and the
request being read the run may have stopped and the engine thread started the next thing. Unbound,
the break would be bound to *that* — a queued command, or the run after this one — and reported to
its caller as an interruption nobody asked for. Named, the worker refuses rather than rebinds.

**Which is also why the two tools carry opposite `idempotentHint`s, and copying one annotation onto
the other is the mistake that has already been made.** `interrupt` is *not* idempotent: its caller
named a session, so a retry after a timeout addresses whichever job is running by then and can stop
an operation nobody aimed at. `break_in` is, for exactly the reason above — the handle pins the
request to one job, so every repeat reaches that run and adds nothing to it: a break already lodged
answers `AlreadyPending` and sends nothing, a bar is an insert into a set that already holds the id,
and a handle whose run has been replaced is `Stale`. It shipped as `false` with `interrupt`'s
comment pasted beneath it, which is a sentence that is true of the tool it was written for and
false of the one it ended up on.

**Naming the job is only half an answer, though, and the other half is `Running::barred`.** A break
for a run that has not *started* — queued behind a `pool_census`, or simply not dequeued — has no
pump to interrupt, and refusing to rebind leaves it to start the moment the queue drains and hold
the target for the bound it named. So the worker bars it, and `claim_pump` refuses it exactly as it
refuses one during a teardown.

**Barred unconditionally, and the version that asked first was wrong in an instructive way.** It
compared ids — they are minted in order, so one above the running job looked like one still queued
— and **a job id is allocated before `Session::submit_gate` is taken**, in `call_within` and in
`start_execution` alike. A task descheduled between the two is overtaken and enqueued behind a
*larger* id, so the run that most needs barring reads as one that has already ended. Ordering the
ids would work and is the wrong fix: it keeps the inference and props it up with an invariant three
call sites must maintain, and the next one to allocate an id elsewhere breaks it silently. Barring
unconditionally needs no invariant — ids are never reused, so barring a job that has already run
matches nothing later. What it costs is that the reply can no longer say *which* case it was, and so
it does not; that precision was invented rather than known.

**And `barred` is a set, where the obvious answer is one slot.** A session holds one run at a time,
so only one queued resume ever *needs* barring — which is the right answer to the wrong question,
because that is about how many bars are wanted at once and not about how many requests can arrive.
A `break_in` for a run that has since finished still reaches the worker (the supervisor sent it
while its slot said the run was going) and can be overtaken on the way, landing *after* a later
`break_in` has barred a genuinely queued run: one slot overwrites that bar with a dead id and the
queued run starts. It is a `BTreeSet` rather than a `HashSet` because `RUNNING` is a `static` with a
const initializer and `HashSet::new` is not `const`. Entries leave only in `claim_pump`, which is
the one place a bar can be used, so a bar for a job that already ran is kept for the worker's life —
one `u64`, against the alternative of tracking which jobs *have* run, which is the same set the
other way up.

**Both of those were mine, one commit apart, and they are the same mistake.** Reasoning about the
sequence a caller intends rather than the states that can actually arrive: ids arrive in allocation
order, and a break arrives while its run is still queued. Neither survived contact with "what if
this task is descheduled here".

**And the outcome is a variant, not a `bool`, because its two readers ask different questions.**
`Output::raised` carries `proto::Interrupted`. `break_in.requested` asks *is this run going to
stop*, for which `Raised`, `AlreadyPending` and `Barred` are all yes; the transcript's `delivered`
asks *did this request raise it*, for which only `Raised` is. One flag made those the same, and
whichever reader lost had a plausible wrong answer — a second `break_in` reading as a run that could
not be stopped, or a transcript crediting a cause that never happened. `false` on `requested` now
has one meaning: the run had already finished. A break that could not be **delivered** is an error
instead, which it previously was not: a lost worker came back as `requested: false` and read exactly
like the benign race.

**Two smaller things that will look like bugs if you do not know them.** The bound is the caller's
`max_run_ms` and **not** the call timeout, deliberately: the point of the tool is that the caller
goes away, so a deadline sized from one tool call's clock would break in on a target the caller was
still happy to leave running — but `wait_for_stop`'s own wait *is* capped below the call timeout
(`STOP_WAIT_MARGIN`), because a wait allowed to run the whole budget would have the call expire
instead of answering, and "the call expired" and "the target never stopped" read identically. And
`Session::finish_execution` restamps `last_used`: everywhere else that stamp is taken on submission,
which is right for a call that answers in seconds and wrong for one that can run for an hour — a run
outlasting the reclamation window would leave its session reclaimable the instant it stopped, and
the stop could be taken before its caller read it.

**Three more edges, each one line of code, and none of which a test would have found by accident.**
`Session::busy` reads the **slot** as well as the waiter map, because `reader` removes the waiter
when the reply lands and the filing task runs after it — so in between, a session with a stale
submission stamp looks idle, and a concurrent open could close it and leave the stop filed where
nothing can resolve it. `Execution::ran_for` is stamped at the stop rather than derived, because a
stop is kept until another run replaces it: derived, a run read an hour later reports an hour, and
two reads of one stop disagree. And `wait_for_stop` takes **one** deadline before its loop, because
the slot is bumped by things that are not stops — the `Resumed` milestone is one — and re-arming
`wait` per wakeup makes `timeout_ms` a per-wakeup allowance, which is `STOP_WAIT_MARGIN` not
holding.

**A run has a phase, and refusing to give it one generated three findings before it got one.**
`Execution::moving_since` is `None` while the run is queued and stamped from the `Resumed`
milestone. The slot is claimed before the job is submitted — that part is right and stays, since a
slot filled when the worker answered would leave a window where the target may be moving and this
side would let a `registers` through — but it makes `started` *when the caller asked*, which behind
a long `pool_census` is minutes before the target went. Everything derived from it was then wrong
the same way: `running_for_ms` counted time the target stood still, and `breaks_in_ms` counted down
a bound the worker had not begun, reporting none left for a run that was about to start a
full-length one. `running()` still does **not** read the phase — a queued run may be moving by the
time a read arrives, and conservative is correct there. This was declined once as "the slot is
deliberately conservative"; that was right about `running()` and wrong about everything else, and
the tell was three findings landing on one seam.

**And the slot stops resolving the moment another run takes it, including under the call that
started this one.** A run that has *stopped* is replaceable — that is what makes a handle age out
rather than accumulate — and it can stop before `continue_async` is scheduled again, so a
concurrent caller watching `session_status` can claim the slot in that window. `start_execution`
therefore reads the slot once per turn and reports `Stale` when its own handle has gone. The two
alternatives are both worse than an error: a record built from the missing handle would tell the
caller the stop is recorded and waiting when `wait_for_stop` can no longer find it, and carrying on
round the loop would wait for a change to a slot this run no longer owns until the whole call
budget ran out.

**And the `Resumed` arm publishes before it wakes.** The phase, then the milestone's channel, then
`execution_moved()`. `start_execution` waits on the *slot* and reads the channel at the top of its
loop, so a bump published first can wake it on another runtime thread while the channel is still
empty — it finds nothing, sees the run still going, consumes the only notification and sleeps until
the run **ends**. That is the same bug this branch shipped once already, arriving the second time
through a two-line ordering rather than a missing wake. `answer_one_resume` mirrors the order for
that reason: a double that publishes differently has stopped standing in for the thing it doubles.

**The stop's typed half rides on `Output::stop`, not `Output::data`.** Same shape and reason as
`Output::summary`: the answer is keyed by a handle the worker has never heard of, so the worker
sends the value and the supervisor folds it in. It travels *instead of* `data` rather than beside
it, unlike `summary`, because the supervisor rebuilds the result either way and a `StopReport`
carries the debugger's whole output — sending both would put a copy of it on the wire for nobody.
It is `Box`ed, and that is the reason `clippy::large_enum_variant` does not fire on
`WorkerMessage::Done`.

