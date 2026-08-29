# Sessions and session handles

The six Session tools that open a target (`open_dump`, `open_trace`, `attach_kernel_local`,
`attach_kernel`, `attach_process`, `launch`) each create a **session** — one engine worker process
holding one target — and return a **`session_id`**. Every tool that touches a target accepts that id
as an optional argument, and it is what **routes** the call to the right worker.

Sessions are independent. Opening a second target does not disturb the first, a call against one
does not queue behind work in another, and ending one leaves the rest alone. Up to `4` at once; at
the limit a new open reclaims the oldest **idle** session, and if every session has a call in flight
the open is refused with the list rather than picking a victim. Sessions end when you `end_session`
them or when the client disconnects — a disconnect is treated as `end_session` on everything, so no
debugger process is left behind. It gives each session a shorter grace than `end_session` does,
though, so end a live kernel session explicitly if you can: one still busy at disconnect is
terminated, and a terminated kernel session leaves its target halted.

**What ending a session does to its target depends on which tool opened it.** A dump or a trace is
simply closed. A live kernel is resumed and detached, so the machine is left running rather than
frozen at its last break. A process `attach_process` attached to is **detached and left running** —
it was somebody else's process before the session and it is somebody else's afterwards — while one
`launch` started is terminated with the session, which is the honest end for a process the debugger
created. So a target that must survive the debugger is one to attach to, not to launch; and because
a disconnect and a lease expiry run the same release, that holds for a client that simply goes away
as much as for one that calls `end_session`. `end_session`'s own result says which ending it was.

**With one exception, and it is the same exception as everywhere else here: a session that does not
let go is terminated.** Releasing asks the worker to detach and then shuts it down; a worker that
does not answer within the grace is killed while it still owns the debug port, and the kernel takes
its debuggees with it. That is what already happens to a parked kernel attach, and it is the reason
`end_session` exists as a recovery at all — but it means "attached processes survive" is a promise
about a worker that answers, which is every worker that is not wedged. A disconnect and a lease
expiry give a **shorter** grace than `end_session` does, so a session doing something long-running
is the one to end explicitly.

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

**Every run is bounded.** `max_run_ms` is how long the debugger lets the target go before breaking
it in itself (default 60s, maximum one hour), so a resume that reaches nothing ends rather than
leaving an engine thread waiting for ever with nobody watching. A run that ends that way reports
`timed_out`, and its position is where the target happened to be rather than a stop it reached.
`break_in` ends one early; it returns as soon as the request is lodged, and the stop it produces
arrives on the next `wait_for_stop`.

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

**Recovering a session that is stuck.** A per-call timeout abandons the *wait*, not the job, so a
call that reports a timeout may still be running. The case that matters is `attach_kernel`: it waits
for the target to dial in with no timeout, and DbgEng cannot interrupt a wait that has not yet
connected — so a guest that is powered off, not booted with debugging enabled, or pointed at the
wrong host/port/key never arrives, and that wait never ends. `session_status` distinguishes a link
that is still coming up (normal, ~25s for a KDNET resync) from one that has been waiting far longer
than a healthy attach ever takes. For the second, `end_session` is the recovery: it asks the worker
to let go, and terminates the worker process if it will not. Do **not** re-run the open while it is
still waiting — the target was already claimed, so that would attach a second time.

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
reach the target than a name list can enumerate, and the data model is extensible — so inside
`execute` and `dx` a handle is a strong hint rather than a guarantee. Everywhere else it is a
guarantee, and it is enforced at the front of that session's queue, after everything queued ahead of
it: checking on the caller's side would leave a window in which an `execute { ".opendump …" }`
already queued ahead retires the handle between a caller's check and its call.
