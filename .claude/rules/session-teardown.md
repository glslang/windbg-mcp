---
paths:
  - "src/**/*.rs"
  - "tests/**/*.rs"
  - "build.rs"
---

## What ending a session does to its target (`FOLLOWUPS.md` item 51)

**Remote-kernel uncertainty is now a preservation boundary.** A timed-out attach or unconfirmed
release becomes `KernelUnresolved`; late replies cannot reopen it. Do not kill its worker during
end, idle/capacity reclamation, lease expiry, shutdown, or worker EOF. Only explicit
`end_session { session_id, kernel_handoff_pid }` may terminate it, using the owned child handle and
verifying exit before releasing its endpoint reservation. That result is NOT a detach/resume.
Reservations are supervisor-local; orphan workers require operator recovery before another
server/controller attaches. Non-kernel forced cleanup is unchanged. See `docs/sessions.md`.
A late successful reply to an already-submitted `EndSession` is confirmed release, not unresolved
ownership: the reader records it and cleans up even if the original caller is gone. A returned
pre-commit attach failure claimed no target and must not retain an orphan either.
An orphan's metadata wait observes either completion even if EOF beat the engine's result;
late attach success alone never permits exit.

**The hypervisor-development branch uses a candidate quit path, not the old GO/active-EndSession
sequence.** Checked breakpoint removal, the engine's fixed `qd`, a no-target postcondition, then
passive session cleanup. Explicit teardown and owning-engine drop share it. Local regressions do
not establish live kernel resume; `docs/hypervisor-debugging.md` records the blocked live validation.
Do not equate successful `SetExecutionStatus(GO)` with execution or add an infinite event wait to
teardown. The change belongs in dbgscope's typed `end_session`, never a raw-command workaround in
this server. Repoint the feature-branch dependency to dbgscope main before merging, and re-test.

**Three different things, and which one is decided by the opener rather than by the target type.**
A dump or a trace is closed. A live kernel is resumed and actively detached. A process
`attach_process` attached to is actively detached and **left running**; one `launch` created is
terminated with the session. All of it happens inside dbgscope's `end_session`, from what the
**opener** recorded — DbgEng cannot be asked, since `GetDebuggeeType` answers
`DEBUG_USER_WINDOWS_PROCESS` for a launch and an attach alike.

**And it accepts a handle no other tool will (`FOLLOWUPS.md` item 55).** A raw `execute` that
replaces or releases the target *retires* the handle naming that session, and every other call
supplying it is refused — but a teardown does not touch the target, it releases the **session**,
which the handle still names exactly. That is `SessionState::accepts_teardown`, and it is widened
in *both* the places a handle is checked (`Sessions::resolve_for_teardown` and `On::Teardown` at
the front of the queue) because widening one alone only moves the refusal.

**And it is per process, not per session**, which is where two rounds of review drove it. DbgEng
holds several user-mode targets in one session (`|` lists them, saying `attach` or `create` against
each), while `EndSession` takes one flag for all of them — so no flag can both keep an attached
process and take a launched one. The attached ones are detached individually first, and whatever is
left when the passive end runs is a target the engine created. Nothing here reaches that: a worker
holds one target for its whole life and `EngineOp` has no second opener.

**The attach case was a kill until 2026-08-28, and the two defaults that produced it are each
reasonable.** A passive `EndSession` destroys the debug port rather than detaching, and a debuggee
whose port is destroyed is killed by the kernel, because `DebugSetProcessKillOnExit` defaults to
true. What made it worse here than in a plain debugger is that `end_session` is not the only caller:
a **client disconnect** and a **lease expiry** run the same release, so a client that simply went
away took the process it was looking at with it.

Four things to know before touching this.

- **The kill is synchronous with `end_session`**, not with the worker's later termination — which
  is what the original report assumed, and what makes this testable at all. The exit code is
  `0xC0000354` (`STATUS_DEBUGGER_INACTIVE`) the moment the call returns.
- **`Child::try_wait` is the wrong probe and looks like the right one.** That exit status is set
  while the process object is *not yet signalled*, so `try_wait` answers `Ok(None)` — "still
  running" — for a process that is already dead. dbgscope's first version of this assertion passed
  with the fix backed out. `CheckRemoteDebuggerPresent` is no better: it reads `false` after either
  ending, because the passive end really does tear the port down. `GetExitCodeProcess` is the only
  probe that separates them, and it separates them completely (ten runs each way).
- **The detach falls back to the passive end and still reports the failure.** This teardown is on
  the disconnect path, where a session that will not close is worse than a killed debuggee — but a
  caller told "released" would have no reason to go and look at a target that had just been killed.
  So the fallback is silent about the *session* and loud about the *target*.
- **A worker killed while holding an attached target still takes it down.** `Release::Parked` — a
  worker that never answers — is terminated without ever running `end_session`, so nothing detaches.
  `DEBUG_PROCESS_DETACH_ON_EXIT` at attach time would close that too, and was rejected: it makes a
  killed worker leave the process alive with whatever breakpoints were patched into it, which is a
  target that faults minutes later with nothing connecting it to the debugger. `item 51` records
  the trade.

Keeping a `launch`ed process alive past its session is a real request and is **not** built: it is a
question about the tool surface (an argument on `launch` or on `end_session`), not about a flag, and
nothing has asked for it yet.

