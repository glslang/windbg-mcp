# Sessions and session handles

The six Session tools that open a target (`open_dump`, `open_trace`, `attach_kernel_local`,
`attach_kernel`, `attach_process`, `launch`) each create a **session** — one engine worker process
holding one target — and return a **`session_id`**. Every tool that touches a target accepts that id
as an optional argument, and it is what **routes** the call to the right worker.

Sessions are independent. Opening a second target does not disturb the first, a call against one
does not queue behind work in another, and ending one leaves the rest alone. Up to `4` at once; at
the limit a new open reclaims the oldest **idle** session, and if every session has a call in flight
the open is refused with the list rather than picking a victim. A disconnect attempts the same
release as `end_session`, with a shorter grace. **Unresolved remote kernel controllers are an
exception: their workers and session slots are retained**, including after lease expiry or
supervisor loss. End a healthy live kernel session explicitly and check its release result.

**What ending a session does to its target depends on which tool opened it.** A dump or a trace is
simply closed. A live kernel is resumed and detached, so the machine is left running rather than
frozen at its last break. A process `attach_process` attached to is **detached and left running** —
it was somebody else's process before the session and it is somebody else's afterwards — while one
`launch` started is terminated with the session, which is the honest end for a process the debugger
created. So a target that must survive the debugger is one to attach to, not to launch; and because
a disconnect and a lease expiry run the same release, that holds for a client that simply goes away
as much as for one that calls `end_session`. `end_session`'s own result says which ending it was.

**Stuck non-kernel workers are terminated after the release grace.** Consequently, "attached
processes survive" requires successful native detach; a killed debugger can take its attached
processes with it. Remote kernel workers are instead preserved when release is unconfirmed.
Terminating a kernel debugger does not establish either target resume or detach.

**And a process added through the raw `execute` hatch is not covered by any of this.**
`execute { "command": ".attach 1234" }` reaches DbgEng without going through `attach_process`, so
nothing records that the process was somebody else's, and ending the session takes it. Use
`attach_process`, which opens a session of its own and is the only route that is tracked.

Omit `session_id` and a call goes to the **current** session: the most recently opened one that will
still accept work. That is the pre-handle behaviour and it still holds. What supplying the id buys
is that the call can never land on a target you did not open — it fails loudly instead.

The asymmetry is worth knowing, because it is where the guarantee earns its keep. A raw `execute`
that replaces or releases the target (`.opendump`, `.attach`, `.detach`) leaves the session
**retired**: a call naming its handle is refused, while a call naming nothing is still routed there,
because the worker is genuinely the server's current target and a caller who asked for no guarantee
gets what is in front of them. So omitting the id is not merely "whatever is current" — it is also
"whatever that target has since become".
`decode_ioctl` (pure) and `record_trace` (independent of any debug session) do not take one.

`session_status` lists every session — what it is, what state it is in, how long it has been there,
and which one is current — or reports on one you name. It never queues on any worker, so it answers
even while a session is parked.

**Stopping a call that is taking too long.** `interrupt` Ctrl+Breaks a session's engine, exactly as
Ctrl+Break does at a WinDbg prompt, and leaves the session and its target alone. Call it while the
slow call is still outstanding — it travels on the session's queue but is answered by the worker's
*request reader*, so it does not queue behind the operation it is meant to stop. That operation ends
at the debugger's next poll and returns whatever it had reached **to the call that started it**,
marked as cut short, and the session takes the next call immediately. It is bound to the job that
was running when it arrived, so it can never land on the one after it; with nothing running it says
so and does nothing. Two things it cannot reach, both properties of the debugger: an operation that
never polls for the break, and the parked kernel attach below.

A `debug_batch` is the one call that stops *itself*: it checks between steps and, when interrupted,
runs its `always` block and reports `BATCH: INTERRUPTED` — so no step after the interrupt is applied
and the session keeps its target, unlike `end_session`, which also stops a batch but takes the
session with it. Its **rollback is not interruptible**: cleanup runs as part of the same call, and a
restore cut short would come back `Ok` with partial output and be reported as a rollback that
completed while the target was still changed — so an `interrupt` aimed at a batch that is unwinding
says so and sends nothing, as does one repeated while a batch is still stopping.

## Running a target asynchronously

`go` and the stepping tools wait for the next stop and answer with it, which is what almost every
question wants. What they cannot express is the sequence a live target usually needs: **arm a
breakpoint, resume, make the thing happen that trips it, then collect the stop.** With a blocking
`go` the middle step has nowhere to go — and a guest-side `Sleep` is not a substitute, because a
kernel halted in the debugger has a halted clock.

`continue_async` resumes the target and returns at once with an **execution handle**:

```jsonc
// 1. arm it
set_breakpoint  { "session_id": "sess-…", "expression": "HEVD!IrpDeviceIoCtlHandler" }
// 2. resume — returns as soon as the target is moving
continue_async  { "session_id": "sess-…", "max_run_ms": 300000 }
//    -> { "execution": "exec-…", "running": true, "breaks_in_ms": 300000 }
// 3. …send the IOCTL from the guest, start the process, click the button…
// 4. collect the stop
wait_for_stop   { "session_id": "sess-…", "execution": "exec-…", "timeout_ms": 60000 }
```

Four rules, and each of them is a thing that would otherwise have to be discovered by being caught
by it:

- **One run per session.** A session is one engine process with one engine thread, and DbgEng moves
  a target only while that thread is pumping it, so a second run could not start until the first
  ended. Starting one is refused, naming the run already there.
- **While the target is moving, tools that read it are refused** — with `"category":
  "target_running"` and the handle to wait on. They are refused rather than queued: queued, a
  `registers` would be answered whenever the target next stopped, which could be an hour away, and
  it would describe wherever the target happened to be. `session_status`, `server_log`, `break_in`
  and `end_session` all keep working.
- **A wait that runs out is a poll, not a failure.** `wait_for_stop` answers with no `stop`, the
  target is still running, the handle is still good, and waiting again carries on. Nothing was
  cancelled and nothing was consumed — so a short `timeout_ms` is how you check on a run without
  disturbing it.
- **A stop is read, not taken.** It is filed against the handle when it happens, whether or not
  anybody is waiting, and stays there until another run replaces it. A client that disconnected
  mid-run can reconnect and read what happened; two callers reading it get the same answer.

**Every run is bounded**, and the clock starts when the target *moves* rather than when you asked —
a run waiting its turn behind another call on the same session reports no elapsed time and its whole
bound. `max_run_ms` is how long the debugger lets the target go before breaking it in itself (default 60s, maximum one hour), so a resume that reaches nothing ends rather than
leaving an engine thread waiting for ever with nobody watching. A run that ends that way reports
`timed_out`, and its position is where the target happened to be rather than a stop it reached.
`break_in` ends one early; it returns as soon as the request is lodged, and the stop it produces
arrives on the next `wait_for_stop`. It is bound to the run you name, so it can never land on
whatever the session started next — and a run that had not begun yet, because something else was
still on the engine, is **barred from starting** rather than left to run once the queue drains. It
answers `requested: false` — not an error — only when the run had already stopped by the time the
call looked, which is the ordinary race between reading a handle and acting on it. A break that
could not be *delivered* is a failure rather than that, so the two are never the same answer.

**A stop says where, and whose.** `stopped_at` is the instruction pointer, `thread` the
operating-system thread id it belongs to, and `processor` which of a kernel target's processors it
is on — absent on a user-mode target, which has no processor number rather than processor 0. Three
flags say *why* it stopped: `interrupted` (somebody broke it in), `timed_out` (it reached its
bound), `target_gone` (it ran to completion, which is an ending rather than a failure). None set
means it stopped on its own, at a breakpoint or an exception.

**`end_session` works while a target is running**, and does not wait for it: the worker's request
reader breaks the pump in as the teardown arrives, so the release is reached instead of queueing
behind a run that has no reason to end. A **client disconnect** runs that same release — with the
shorter grace above — so a target left running by a client that goes away is released on the same
path as one ended explicitly, rather than being held until its bound expires.

**Watching a call that is taking a while.** Put a `progressToken` in a call's `_meta` and it reports
on itself with MCP progress notifications while it runs: the engine worker coming up, the target
being claimed, the target being open, a teardown unwinding a transaction — and, when there is
nothing new to say, that it is still running, every ten seconds. `progress` is seconds elapsed and
there is no `total`, since the budget differs per tool and an opener spends up to 30s bringing a
worker up before its own budget starts. Nothing is sent to a call that did not ask. This matters
most over `--listen`, where `session_status` and `server_log` are on the other machine and both are
pull — see [`remote-listener.md`](./remote-listener.md).

## Unresolved remote kernel controllers

A per-call timeout abandons the *wait*, not the native job. A remote kernel timeout, failed release,
or unconfirmed worker loss becomes `kernel_unresolved`, with the reason and `engine_pid` in
`session_status`. This is sticky: a late attach result does not make the session usable again.
The failed opener returns `error.category: "recovery_required"`, its session ID, and
`target: "unknown"`, not advice that an ordinary pending open may still become usable.
Target liveness and detach remain unknown. Pending attaches and unresolved controllers refuse
additional interrupts; an ACTIVE interrupt is not a safe timeout-recovery mechanism.

An already-submitted release is different: a late successful `EndSession` reply confirms release,
closes the session, and permits worker cleanup and endpoint reuse without a recovery handoff.

Ordinary `end_session` reports `released: false`, `worker_terminated: false`, and
`recovery_required: true`. No native teardown is queued for an unresolved controller. Idle/capacity
reclamation, client lease expiry, and server shutdown cannot kill it automatically. On supervisor
loss, the worker retains its engine rather than exiting after an unsuccessful cleanup grace.

Within one supervisor, a KDNET port stays reserved across timeout and worker loss; profile aliases,
different keys, and alternate target addresses do not permit a second owner. Unrecognized
connection forms conservatively conflict with every remote kernel reservation. This is **not a
machine-wide lock**: another server process or native debugger is outside this registry. Do not
restart the server or start another controller as a workaround. An orphan worker cannot be adopted
by a new supervisor; inspect its PID and endpoint out of band before manual recovery.

After inspecting the target console and preparing an out-of-band recovery route, explicitly hand
off ownership using the **same session's exact reported PID**:

```jsonc
end_session { "session_id": "sess-…", "kernel_handoff_pid": 1234 }
```

This is permission to terminate that owned worker, **not** permission to reset a VM and **not** a
successful detach. The reservation is removed only after worker exit is verified using its owned
process handle. Cancelling the request does not cancel the handoff task. The result still reports
`released: false` and `recovery_required: true`, with no claim that the target is running. Verify
that the endpoint is free before starting one recovery controller. If exit cannot be verified,
the reservation remains. A lost supervisor or revoked client requires operator recovery, not a
different client taking over the handle.

These safeguards do not resolve the underlying DbgEng wait behavior; see the
[Microsoft report draft](dbgeng-exit-report.md) for evidence and limitations.

Two caveats, both in the command hatches, and both now confined to a single session. The typed tools
announce their own transitions, but `execute` can replace its session's target directly
(`.opendump`, `.attach`, `.detach`, `.kill`, `.restart`, `.abandon`, `.remote`, `q`/`qd`/`qq`), and
those commands **retire** that session's handle: calls passing it are refused, while calls that pass
no id still reach the worker. `dx` is the second hatch — the data model reaches
`Debugger.Utility.Control.ExecuteCommand`, which runs any command, so an expression that touches
command execution retires the handle too, conservatively, since the command it runs is a runtime
string this server never sees.

Both matches are deliberately biased toward retiring: over-matching costs one re-open,
under-matching would let a stale handle through. Neither can be exhaustive — DbgEng has more ways to
reach the target than a name list can enumerate, and the data model is extensible. They are enforced
at the front of that session's queue, after everything queued ahead of it: checking on the caller's
side would leave a window in which an `execute { ".opendump …" }` already queued ahead retires the
handle between a caller's check and its call.

**What makes a handle mean something even where those matches miss is that the engine is asked
afterwards.** A command can reach `.opendump` without naming it — inside `.if`, `.foreach`,
`.block`, `j` or `z`, or through an alias, which resolves only when it runs — and a breakpoint's
command runs at a **hit**, which is not a moment this server can retire a handle at in advance. So
the engine process takes a reading of what it is holding when the target is opened — what kind of
target DbgEng says it is, which dump or trace files the session is open on, and (user-mode only)
which processes it holds — and compares it after every operation. Note *holds*, not *is pointing
at*: the debugger's current process moves on its own when a child process starts and moves by hand
on `|Ns`, and neither of those is a change of target. A difference retires the session's
handles at that point, before the operation's own answer reaches its caller.

A call that **named the session** and was already queued when the swap happened is refused by the
engine process itself rather than by the handle check, and that is not the same mechanism wearing a
different hat: a job is handed to the engine process as soon as it clears the handle check, without
waiting for the one ahead of it to answer, so retiring the handle afterwards is too late for a call
that is already past every check the server has. The engine process asks again before it runs one.

**Omitting `session_id` still reaches the new target**, which is the same rule as everywhere else
here and is worth stating because the refusal above could be read as cancelling it: a retired
session goes on taking calls that name no session, and they run against whatever the worker now
holds. Only the guarantee a handle buys is withdrawn, because only a handle ever bought one.

**And a stop this server already filed is still collectible with the retired handle.** A
`continue_async` run whose breakpoint command replaced the target retires the session at that very
stop, and `wait_for_stop` hands the result over anyway: it reads a record rather than touching a
target, and the run's own result is the thing a caller most needs at the moment they are told their
handle no longer names what they opened. `break_in` and `interrupt` are on the other side of that
line — they reach the debugger, and would reach whatever it is holding now — so they stay refused.

Two more things follow that are worth knowing at the tool surface. The retirement can arrive on a
call that did nothing wrong — the one that happened to be running when the swap was noticed answers
normally, and the *next* call naming that handle is refused. And a target that has simply **gone**
is not reported this way at all: that is an ending, carried by the stop itself, and the session
refuses further work with a stale-session error rather than a retired handle. Either way
`end_session` still accepts the handle, and opening again is how you get a target.

Note which `.detach` that last sentence is about. `execute { "command": ".detach" }` names a command
on the list above, so it **retires the handle before it runs** — that is the ordinary path and it
ends in a retired handle, not a stale-session error. What ends in a stale-session error is a target
that went without this server being able to see it coming: a launched program running to
completion, or a `.detach` hidden inside a wrapper where the scan cannot read it.
