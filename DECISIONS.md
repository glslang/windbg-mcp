# Architecture Decisions

Decision log for windbg-mcp. Newest first. Each entry records the decision, the reasoning, and its
status. Keep entries short; link to code with `file:line` where it helps a future reader.

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
pipe. The worker is spawned *without* `WINDBG_MCP_PROFILE_*` in its environment
(`engine::spawn_worker`), which matters for the process after it: `launch` runs an arbitrary binary
under the debugger, that binary inherits its worker's environment, and a debuggee is the least
trustworthy process this server ever creates. Resolution happens in the supervisor for a second
reason too — a selector the caller must fix is refused before any worker is spawned, so a typo
costs a message rather than a session to end.

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
