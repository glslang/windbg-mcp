---
name: live-hypervisor
description: Debug the Microsoft hypervisor (`hvix64.exe`) and the NT kernel it runs, together - two KDNET endpoints as two sessions, the freeze asymmetry between them, enumerating hypercalls from both sides without a hypervisor PDB, breaking on one from either end, what a breakpoint owes on a multiprocessor guest, and the teardown that decides whether the guest comes back. Use when attaching to a hypervisor target, correlating an NT hypercall with its hypervisor-side handler, or diagnosing a guest left black after a detach.
---

# The hypervisor and the kernel it runs

`/live-kernel` is the NT half and still applies in full — KDNET wiring, parked attaches, `.reload`,
where symbols must live. This file is about the **second** target and about holding both at once.

## Two targets, two endpoints, two sessions

A hypervisor target is not a mode of an NT session. It is its own KDNET endpoint with its own port
and key, reached by its own profile, and `attach_kernel` opens it into a session of its own.

Each session gets its own worker process because dbgeng.dll holds one debuggee per process,
`MAX_SESSIONS` is **4** (`engine.rs`), and the reservation that refuses a second controller is
keyed by the endpoint — `Endpoint::Net(port)`, compared with `conflicts`. Two different ports do
not collide, so an NT session and a hypervisor session coexist with no interaction inside this
server at all. **Every interaction between them is in the guest.**

`attach_kernel {}` lists the profiles the host has, **and the listing may say which is which.** A
profile configured as an object carries a `role` and a `guest` (`docs/kernel-profiles.md`), so the
list can read `lab-hv (hypervisor, guest "lab"); lab-nt (windows, guest "lab")` — the pair, named.
Read that before asking anybody anything.

Where it says nothing, which of them is the hypervisor endpoint, which is NT, and whether they
reach the same guest are facts about the machine rather than about this repository, so ask rather
than infer. A pair pointing at *different* guests gives two sessions that never interact, which
reads as a bug for a long time. Then ask the user to **record** the answer as a `guest` on both
profiles, because nothing in this server can recover it later.

**A matching `guest` is an assertion, not a check.** No debugger question asks two endpoints
whether they are the same machine, so what it beats is a guess off the two names — which is worth
a great deal and is still somebody's word. A pair that looks matched can be wrong; it is just wrong
in writing, where you can go and ask about it.

**Check the identity rather than the profile name.** `kernel_mode: true` is true of both. What
separates them is `summary.kernel_target`: `"hypervisor"` when the engine reports kernel mode *and*
the primary module is `hv` (`worker::kernel_target`), with a limitation saying NT process, driver,
object and pool inspection does not apply. An inventory it does not recognise leaves
`kernel_target` **absent** rather than guessing, so absence means ask again, not "this is NT".

**A declared `role` is checked against exactly that**, in the supervisor, which is the only side
holding both halves: `server::role_disagreement` puts the profile's claim beside
`summary.kernel_target`, and a mismatch **withdraws** the declared role: it disappears from the
profile and the reason joins its `ignored`, in both halves of the result. So a disagreement is
the *configuration's* fault — trust the identity, and tell the user which profile to fix. It is
silent where `kernel_target` is absent, and that silence is not agreement: an unrecognised
inventory still means ask again.

**The NT-shaped tools are not merely uninformative here, they fail.** `threads` on a hypervisor
session comes back `An unexpected exception was raised (0x80040205)`: there is no `_ETHREAD` list
to walk. The attach report carries what you actually want — `Microsoft Hypervisor Kernel Version
29671 MP (4 procs) Free x64` names the processor count, and `modules`, `registers`, `read_memory`,
`disassemble`, `set_breakpoint`, `run_to_address` and the execution-control tools all work.

## The asymmetry that orders every step

**Stopping the hypervisor stops everything it runs, the root Windows OS included** — which is why
the debugger lives outside the hypervisor it stops.

So **while the hypervisor session holds a break, the NT session cannot reach its target.** NT's KD
transport runs in NT, and NT is not scheduled.

Measured both ways, with both sessions open at once:

- **An NT break does not stop the hypervisor.** With NT halted at a breakpoint, a hypervisor
  attach *connected and broke in* — so the hypervisor keeps running underneath an NT stop, and the
  hypervisor session stays usable across one.
- **A hypervisor break does stop NT, and the causal link is direct.** With the hypervisor halted, a
  `read_memory` on the NT session for a page DbgEng had not already fetched **hung**, and
  **completed the instant the hypervisor was resumed**. Not an inference from silence: the same
  outstanding call returned as soon as the machine underneath it ran again.

**The refinement is the trap.** A halted hypervisor does **not** make the NT session look dead.
Anything DbgEng already holds still answers instantly — `registers` comes back immediately with the
full context, because it was captured when NT stopped, and a `read_memory` near the stopped RIP
answers from an already-fetched page. The session looks perfectly healthy until you ask it for
something it does not already have, and *then* it hangs for the whole call budget. So a fast,
correct-looking answer out of the NT session is not evidence that the machine is running.

Three consequences, which are most of the procedure:

- **Arm the NT side while the hypervisor is running.** Once the hypervisor is stopped, the NT
  session cannot be reached to arm anything.
- **Resume the hypervisor before expecting anything from NT** — including before `end_session` on
  NT, which has to resume a target that can execute.
- **`break_in` on the NT session does nothing while the hypervisor is halted.** `break_in`'s own
  documentation names a live-kernel target that has never connected as one of the two things
  `SetInterrupt` cannot reach; a halted machine is the same shape.

## Start a session

Order matters and is the reverse of the intuitive one — NT first, while the machine still runs.

1. **NT.** `attach_kernel { "profile": "<nt-profile>" }`. Keep the `session_id`.
2. **Survey and arm**, below, while the machine is live.
3. **Hypervisor.**
   `attach_kernel { "profile": "<hv-profile>", "experimental_break_on_connect": true }`.

`experimental_break_on_connect` exists because **a hypervisor that is already running has nothing
to break into**. It asks for one break on DbgEng's English connection announcement — observed text,
explicitly *not* a documented readiness contract — is refused on anything but a `net:` connection
(`server.rs` checks the first four bytes), scopes its observer to the attach so a duplicate
announcement does not request a second break, and **fails the attach** on a missing announcement,
failed interrupt or unconfirmed stop rather than proceeding. Its watchdog is 60 seconds.

**A failed attach here is not retryable.** The wait is `WaitForEvent(INFINITE)`, has no timeout and
cannot be interrupted, so a reported timeout leaves the worker parked and the session
`kernel_unresolved`. A second `attach_kernel` is a **second controller**, not a retry. Inspect out
of band, then `end_session { session_id, kernel_handoff_pid }`, which verifies process exit and is
**not** a resume or a detach.

Either attach shape lands on the hypervisor's own break routine — `hv+0x404a60`, `int 3` followed
by `ret` on the build below — and every forced break-in measured here landed there too, banner and
all, on whichever processor answered. Read it as this target's `nt!DbgBreakPointWithStatus` rather
than as a breakpoint of yours.

## Survey: enumerating hypercalls

`modules {}` is the image inventory. There is no equivalent tool for hypercalls, so the survey is
built from three enumerations that answer different halves — and none of them needs a hypervisor
PDB.

1. **What NT can call** — the wrappers, from the NT session with symbols loaded:
   ```jsonc
   { "session_id": "<nt>", "command": "x nt!Hvcall*" }   // execute — the call wrappers
   { "session_id": "<nt>", "command": "x nt!Hvl*" }      // execute — the layer above them
   ```
   Names in this area move between builds, so read the build in front of you rather than reciting
   a list. On NT 29671 x64: `HvcallInitiateHypercall`, `HvcallFastExtended`,
   `HvcallpExtendedFastHypercall`, `HvcallpExtendedFastHypercallWithOutput`,
   `HvcallpNoHypervisorPresent`, `HvcallInitInputControl`, and the data global `HvcallCodeVa`.
   Record what you find as a coordinate — `module` + `rva` + the image identity from `modules` —
   because the address is a fact about one boot and the RVA is not (`docs/coordinates.md`).

2. **Where the instruction is.** The `vmcall`/`vmmcall` lives in a page NT maps at boot from the
   hypercall MSR, so it has no fixed RVA in `ntoskrnl` and its address sits in a global:
   ```jsonc
   { "session_id": "<nt>", "command": "dps nt!HvcallCodeVa L1" }   // execute
   ```
   **That page is the enumeration.** Disassemble from the address it gives — on the measured build
   it was a table of five short stubs in `0x36` bytes, then NOPs to the end of the page:

   | Offset | Stub | Call code |
   |---|---|---|
   | `+0x00` | `vmcall; ret` | generic — supplied by the caller in RCX |
   | `+0x04` | `mov ecx,eax; mov eax,11h; vmcall; ret` | `0x11`, 32-bit form |
   | `+0x0f` | `mov rax,rcx; mov rcx,11h; vmcall; ret` | `0x11`, 64-bit form |
   | `+0x1d` | `mov ecx,eax; mov eax,12h; vmcall; ret` | `0x12`, 32-bit form |
   | `+0x28` | `mov rax,rcx; mov rcx,12h; vmcall; ret` | `0x12`, 64-bit form |

   `0f01c1` is `vmcall`, so that target was Intel; an AMD one reads `vmmcall`. Which hypercalls
   `0x11` and `0x12` *are* takes the TLFS — the numbers above are what the target contained, and
   naming them from memory is the kind of claim this repo makes you measure.

   `nt!HvcallInitiateHypercall` ends `mov rax, qword ptr [nt!HvcallCodeVa]` … `call rax`, so it
   reaches stub `+0x00` and nothing else. **A breakpoint on `+0x00` therefore catches only the
   generic path**, which on a merely idle guest may never run: 23 seconds of a resumed target
   produced no hit at all, because the traffic was going through the fast wrappers into the
   dedicated stubs. **And do not arm that page at all** — see the first hazard below.

3. **Which code is being called.** The hypercall input value is in a register at the call site —
   its low 16 bits are the call code, and the rest is fast/rep flags and counts. Reading
   `registers` at the instruction is what turns "a hypercall happened" into "this one did", and it
   is the only one of these that enumerates what the guest *actually uses* rather than what it
   *could*.

**`disassemble` takes `address`; `set_breakpoint` takes `expression`.** Passing `expression` to
`disassemble` is not refused — the field is dropped and the call falls back to the current
instruction pointer, so it answers about wherever the target happens to be stopped and looks like
a successful disassembly of what you asked for. On a target stopped at the KD break-in that is
`nt!DbgBreakPointWithStatus`, whose `int 3; ret` reads plausibly enough to be believed. Two
consecutive calls returning byte-identical output for two different arguments is the tell.

## The hypervisor image's landmarks

**Every RVA below belongs to one build**: hypervisor 29671, `hvix64.exe`, image size `6393856`,
timestamp `3152137373`, checksum `2578329`. `modules` reports `timestamp` and `size` for the
session in front of you; if they differ, the landmarks are a different function and
`run_to_address` will run to it without complaint. The base moves with every boot, so work in
`hv+RVA` and add the base you were given.

| RVA | What it is |
|---|---|
| `hv+0x404a60` | `int 3`, followed at `+0x404a61` by `ret` — where every break lands |
| `hv+0x312024` | inside a recurring deadline-driven callback, `[hv+0x311eec, hv+0x3120de)`; the return site of a debug-break poll, and what the stopped processor's `[rsp]` holds at the initial break |
| `hv+0x20fe71` | the dispatcher's call of that callback; it returns to `hv+0x20fe73` |
| `hv+0x25F460` | the VP loop's exit handler, entered with the exit reason in `edx` |
| `hv+0x25F9D4` | its `cmp r12d,12h` — the VMCALL case, calling `hv+0x21AFF0` |
| `hv+0x21AFF0` | the hypercall entry; `hv+0x247850` gets first refusal, then `hv+0x210520` |
| `hv+0x210520` | the dispatcher: guest register array at `[[r9]+0x10C0]`, input value from guest `RCX` |
| `hv+0x21056D` | **the hypercall site to break on** — input value in `rbx`, register array in `rcx` |
| `hv+0x210669` | where codes `0x5C`/`0x5D` go, and only with bit 31 of the input value set |

**Break at `hv+0x21056D` rather than at either function's entry.** A conditional breakpoint whose
expression dereferences memory can fault, and **a faulting condition stops the hypervisor** — which
freezes the guest and ends the run with nothing learned. It cost two runs, 90 s and 120 s, and
taking the VP from `@rcx` instead of a fixed address did not save it. At `hv+0x21056D` the value is
already in a register, so the condition reads no memory at all.

**A second VP entry/exit pair in the image is not this one.** `hv+0x405860` with handler
`hv+0x375F3C`, whose VMCALL case calls `hv+0x402D9C`, reads exactly like the hypercall path and is
not it — it refuses fast hypercalls and ones with bit 31 set, and its caller routes that refusal
into what reads as a bugcheck path.

**`hv+0x312024` is not a hypercall site**, and it is the wrong fixture to copy for hypercall work.
It is a return address you can read off the stopped stack without any symbols, which is why the
detach regression uses it — and, being code *every processor runs*, it is also the fixture for the
second hazard below.

## Two breakpoint hazards, each of which has cost a guest

### A breakpoint in the hypercall page freezes the guest, and nothing recovers it

On a healthy guest with a clean attach behind it, a breakpoint on the generic `vmcall` at
`HvcallCodeVa+0x00` followed by a `break_in` request ended with the guest **black and frozen at the
console**: the break-in was lodged on the engine and never serviced, and the run stayed outstanding
for nineteen minutes. A hypervisor attach to that guest's *own* hypervisor endpoint, with
hypervisor debugging confirmed enabled for that boot, **also never connected**. Both debug
transports were gone at once.

**It reproduced on the dedicated stubs**, which is what rules out "avoid the generic funnel" as the
remedy: a second run armed the four *dedicated* stubs and left `+0x00` alone, and that guest wedged
inside twenty seconds with **no `break_in` requested at all**. Three placements separate the cause:

| | Generic `+0x00` | Four dedicated stubs | **Nothing armed** | Four `ntoskrnl` wrappers |
|---|---|---|---|---|
| Where | hypercall page | hypercall page | — | inside `nt` |
| Outcome | froze | froze | **stopped cleanly** | **stopped cleanly, then hit** |

The control is what settles it: with nothing armed, a fifteen-second bounded run's own break-in
landed at 15021 ms, processor 0, `timed_out: true`, `target_gone: false`. **This guest stops
perfectly well after an attach** — so the freeze is not a property of the KD link. The surviving
explanation is that the debugger's own path for reporting a trap needs the page it trapped in, so
the stop can never be delivered; the mechanism has not been instrumented.

**So do not patch the hypercall page. Break on the NT wrapper instead** — it is in `ntoskrnl`, it
carries the call code in a register, and it works. Recovery from either freeze was a **reset**:
every other freeze this file records leaves something executing that a debugger can reach, and here
nothing was. The patch costs nothing across the reset, `HvcallCodeVa` being a dynamically mapped
page rather than a file-backed image. Free both endpoints before the guest reboots, or it comes
back to a stale controller on its debug link.

### A breakpoint in code every processor runs owes one stop per *other* processor

**The rule, measured on four processors, 2026-09-21:** a `run_to_address` to `hv+0x312024`
returned `verdict: hit` with an empty breakpoint inventory after it — and the next three resumes
stopped **immediately** (2 ms, 3 ms, 1 ms), on processors 2, 3 and 1, all at that same address,
each a first-chance `0x80000003` with no CTRL+BREAK banner and each on its own processor's stack
(the four are 2 MiB apart, `…0005…`, `…0205…`, `…0405…`, `…0605…`). The fourth resume ran free.
The other processors reached the patched instruction before the debugger removed it, and their
break exceptions are delivered **one per resume**, after the tool that armed the breakpoint has
reported success and taken it off. On one processor there is nothing to deliver, which is why
none of the one-vCPU runs ever saw this.

**What that does to a detach:** `qd` sends one `DbgKdContinue`. A queued stop takes it, and the
target stops again with **no debugger attached** — a guest black at the console while the teardown
reports `released: true`, `target_left_running: true`, `recovery_required: false`. It is a race
between the delivery and the quit, so it is intermittent: **2 of 4** four-processor
hit-then-detach runs froze on 2026-09-21, both leaving the guest stopped at `hv+0x312024` on
another processor's stack.

**The teardown spends them, and that is where the fix lives.** dbgscope's
`quit_and_detach_target` resumes until two consecutive resumes run free, between clearing the
breakpoints and sending `qd`, **sized one resume per processor** — so four processors get six
attempts where the old fixed five was exactly enough by coincidence. It runs on every live-kernel
quit, whatever the attach shape: gating it on an `INITIAL_BREAK` attach, which is what it used to
do, left it unrun on the `experimental_break_on_connect` path that every hypervisor run here uses.
Twenty of twenty four-processor cycles detached cleanly with it, against 2 of 4 freezing without.

**That is dbgscope#175, pinned here at `192e3486` since 2026-09-21** (`DONE.md` item 93). Against
an **older** engine build — a released `windbg-mcp`, or a checkout whose `rev` predates it — a
break-on-connect attach drains nothing at teardown, so either drain by hand before `end_session`
(resume with `continue_async { max_run_ms: 1500 }` and `wait_for_stop` until two runs reach their
bound) or be ready to recover.

**Recovering a guest frozen this way takes one attach and one detach**, and it is recoverable
precisely because something *is* still executing to answer a debugger — unlike the hypercall-page
freeze above:

```jsonc
{ "profile": "<hv-profile>" }            // attach_kernel, plain: no break_on_connect
{ "session_id": "<hv>" }                 // end_session; its drain spends the queued stops
```

Confirmed twice on 2026-09-21, each time on the **same boot** with uptime advancing afterwards and
no reset. The plain attach is deliberate: it finds the pending stop rather than asking for a new
break, and `registers` on it will show `hv+0x312024` — the breakpoint's own address — which is how
you tell this freeze from any other before you do anything.

## Break on a hypercall from both ends

The load-bearing choice is that **the NT side runs asynchronously**. There is no async step: `go`,
`step_over` and `step_into` all wait, and their wait is `EXEC_WAIT_MS` — **60 seconds**
(`server.rs`). A step that hands the machine to the hypervisor debugger will not return inside
that, so a synchronous step reports a timeout that measures the other session rather than the
target. `continue_async` returns a handle the moment the run starts, bounds it with `max_run_ms`
(default `EXEC_WAIT_MS`, clamped to `MAX_ASYNC_RUN_MS` = **one hour**), and `wait_for_stop` reads
the stop rather than taking it — so asking twice gives the same answer, a run that stopped while
nobody waited still has its stop there, and on a kernel target the report names the **processor**.

1. **NT, machine running. Arm the wrappers, not the page.**
   ```jsonc
   { "session_id": "<nt>", "expression": "nt!HvcallInitiateHypercall" }             // set_breakpoint
   { "session_id": "<nt>", "expression": "nt!HvcallFastExtended" }
   { "session_id": "<nt>", "expression": "nt!HvcallpExtendedFastHypercall" }
   { "session_id": "<nt>", "expression": "nt!HvcallpExtendedFastHypercallWithOutput" }
   ```
2. **Resume asynchronously, then make the guest do something.** An idle guest is genuinely idle:
   two separate fifteen-second runs with all four armed reached their bound without a hit. Starting
   a process over WinRM was enough — and the hit came **7 ms** into the run that followed.
   ```jsonc
   { "session_id": "<nt>", "max_run_ms": 90000 }   // continue_async, then trigger from outside
   ```
   While NT moves, this session refuses every read — nothing read from a moving target would mean
   anything. `interrupt`, `end_session` and a further resume still go through.
3. **Collect the stop, read the call code, and choose a value that crosses — here, before the
   hypervisor is armed for it.** `wait_for_stop` reported `Breakpoint 2 hit` at
   `nt!HvcallInitiateHypercall`, `processor: 0`, `timed_out: false`; `registers` then gave
   **`rcx = 0x8001005D`** — by the TLFS input-value layout the low 16 bits are the call code
   (`0x005D`) and bit 16 is the *fast* flag, with the input parameter in `rdx`. Naming the call
   code needs the TLFS; the register is the measurement.

   **A value with bit 31 set does not cross, and that is the class to exclude rather than the
   value.** `0x8001005D` was what both unconditional captures held on 2026-09-21, and it never
   reached the hypervisor's dispatcher in 60 s of free running while the next value out of the same
   wrapper reached it in 714 ms. The first capture on 2026-09-22 was **`0x8000005C`** — a different
   call code, the same bit 31 — so an exclusion written as `@rcx != 0x8001005d` parks on the next
   one of these instead. Mask it:

   ```text
   bc *; bp nt!HvcallInitiateHypercall "j ((@rcx & 0x80000000) == 0) ''; 'gc'"
   ```

   Then **resume NT again**, because `bc`/`bp` only change what is armed and leave NT halted where
   it was. That reached `rcx = 0x00010068` — call code `0x68`, fast bit, `rdx = 0` — in 8.5 s
   (excluding one value by equality took 9.6 s the day before, where the first hit had come in
   7 ms). **That** is the value step 5 arms for, and record `rsp`, `rsi`, `rdi` and `r13` with it:
   they are what identify the instance at the other end.

   Bit 31 marks a hypercall for the parent hypervisor and this lab's guest is itself nested, which
   is a plausible reading of *why* and not a measured one — nothing separates "never delivered
   here" from "answered by `hv+0x247850` before the dispatcher". What is measured is that these do
   not arrive at the dispatcher and that the guest keeps making them.
4. **Attach the hypervisor while NT sits there.** This works — it is how the asymmetry above was
   measured — and the summary comes back `kernel_target: "hypervisor"` with `hv`/`hvix64.exe` and
   `symbols: none`. Both sessions are then open, independently routed, and both targets halted.
5. **Correlate, with a conditional breakpoint on each side.** Arm the hypervisor at `hv+0x21056D`
   for the value step 3 settled on, with a register-only condition, which auto-continues on every
   other hypercall so the guest keeps running:

   ```text
   bp <hv-base>+21056d "j (@rbx == <input-value>) ''; 'gc'"
   ```

   **Both targets are halted at this point, so three calls in this order, and the middle one is
   the one it is easy to leave out:** `continue_async` **NT** — which cannot take effect yet and is
   simply lodged — then `continue_async` the **hypervisor**, which is what puts the guest back on a
   processor and lets NT take that lodged resume, then `wait_for_stop` on the hypervisor. Releasing
   NT alone changes nothing: a halted hypervisor stops NT, so a procedure that resumes the
   hypervisor only at teardown never reaches a stop. **NT first rather than the hypervisor first**
   is deliberate: with NT's resume already lodged, it is taken the instant the guest runs, so the
   first hypercall matching the condition is the released call rather than one another thread
   slipped in during the gap.

   Read the guest register array at that stop — `rcx` points at it. Every register agrees with the
   NT-side capture, transformed as the wrapper's prologue transforms it: `rbp` is NT's `rsp` less
   seven pushes less `0x27`, `rsi` is NT's `rsi` with exactly its low byte cleared, and `rdi`,
   `r13`, `r10` and `r11` arrive untouched. It landed **714 ms** into that hypervisor run. The
   array does not carry `rsp`.

   **Those two transformed values are not *unique*** — the same thread calling the same wrapper
   again at the same stack depth would reproduce them. What makes this one instance is the
   ordering: NT was parked at that call, released, and this was the first hypercall matching it.
6. **Resume both, hypervisor first.** Take any hypervisor breakpoint off first or the next
   hypercall re-enters it immediately, then `continue_async` the hypervisor. Only now does NT
   execute: an outstanding NT call unblocks the moment the hypervisor runs.

**The state both targets are in after each step**, because a step that leaves something halted
where the next step needs it running is invisible in prose and obvious here:

| After step | NT | Hypervisor |
|---|---|---|
| 1 arm the wrappers | halted | not attached |
| 2 resume, trigger from outside | running | not attached |
| 3 capture, re-arm, **resume again**, capture the crossing value | halted at the chosen value | not attached |
| 4 attach | halted | halted at `hv+0x404a60` |
| 5 arm `hv+0x21056D`, lodge NT, **resume the hypervisor** | resumes, then frozen mid-`vmcall` | halted at `hv+0x21056D` |
| 6 clear the hypervisor breakpoint, resume it | resumes, and stops again at once if its conditional is still armed | running |

Three rules fall out of that column pair. **Arming is not resuming** — `bp`, `bc` and
`set_breakpoint` change what is armed and leave the target exactly where it was. **NT's state is
only meaningful while the hypervisor runs**, so any row where the hypervisor is halted is a row
where NT does nothing at all. And **a row that says *running* is a row that accepts three calls and
no others** — `interrupt`, `end_session` and a further resume (`Sessions::refuse_while_running`),
which is as true of the hypervisor as of NT: NT's own conditional cannot be cleared until NT has
stopped, by its next match or by an `interrupt`. Clearing it by hand is optional anyway, since
`end_session`'s teardown clears breakpoints itself before it detaches.

**Three ordering traps, each of which costs a run.**

**An *unconditional* hypervisor breakpoint on a hypercall site deadlocks the NT session.** Every
hypercall stops the world, so the guest executes for microseconds per resume and NT never
accumulates enough time to take its KD resume packet off the NIC — it stays parked at its own
breakpoint however many times the hypervisor is continued. Twelve stop/resume cycles did not
deliver one resume; the conditional form above had NT running again within a second.
`... Retry sending the same data packet for 4160 times.` in the NT session's output is what that
deadlock looks like from the other end.

**NT's breakpoints can only be edited while the hypervisor runs.** `bp` and `bc` write to NT
memory over a transport NT services only when it is executing, so with the hypervisor halted they
block like any other uncached read. Resume the hypervisor, edit NT's breakpoints, then park NT
again.

**NT's transport reports itself lost across a long hypervisor hold, and recovers on its own.**
Measured on four processors: with the hypervisor halted through the crossing, the NT session's
output carried `... Retry sending the same data packet for 64 times.` and then *"The transport
connection between host kernel debugger and target Windows seems lost. please try resync with
target, recycle the host debugger, or reboot the target Windows."* **Do none of those.** The
machine is frozen rather than gone: resume the hypervisor and NT resynchronises by itself — it
answered `vertarget` with a fresh debug session time immediately afterwards and detached cleanly.
The session's own run reported `running_for_ms: 38974` for a run that spent most of that frozen.

**A bounded run that expires can leave a break-in owing**, and the next resume spends it: an
immediate stop at `hv+0x404a60` with the CTRL+BREAK banner and nothing armed. It is harmless, and
it reads like a breakpoint hit if you are not expecting it. Tell it from a queued per-processor
stop by the banner and the address: this one is at the break routine, that one is at your own
breakpoint's address.

**It is not a rule, and the difference matters to any drain that ends on a bounded run.** It was
seen twice on one vCPU; on four processors it did not reproduce — two consecutive expired 1500 ms
runs each ran their whole window, and so did the expired run after the last queued stop, with the
teardown that followed leaving the guest healthy. Which is what lets a drain treat a run that
reached its deadline as a *free* run: dbgscope's does, and twenty of twenty four-processor
teardowns behind it left the guest healthy. Do not add a resume after the second bounded run to be
safe — an extra one is another bounded run to interpret, not a stop consumed.

## Teardown

1. **Resume the hypervisor** and leave it attached — with a bound that outlasts the rest of this
   list. A `continue_async` whose `max_run_ms` expires puts the guest back on the floor, and the
   next step is then asking a frozen kernel to detach itself. Twenty seconds was not enough on
   2026-09-22 and the hypervisor had to be resumed a second time; check `session_status` rather
   than assuming the run is still going.
2. **`end_session` the NT session** — it resumes and actively detaches a live kernel, and needs a
   machine that can execute to do it.
3. **`end_session` the hypervisor session.**
4. **Read guest health from outside the debugger**, twice, for boot identity and advancing uptime.

That order was measured with both sessions open and both targets halted, on one vCPU and again on
four: each answered `released: true`, `target_left_running: true`, `recovery_required: false`,
independent WinRM then gave the same boot with uptime advancing, and both KD ports were free with
no worker left.

**What the teardown does.** dbgscope's `quit_and_detach_target` clears the breakpoints, **spends
the stops the target still owes, and only then sends `qd`**. Two things leave one owing: a
`DEBUG_ENGOPT_INITIAL_BREAK` attach leaves one pending host break-in that the attach's own absorb
step does not cover on this target, and a breakpoint in shared code leaves one per other processor
(above). Either way `qd` has exactly one continue to spend, and a leftover takes it. The drain
**ends on two consecutive free resumes, not one** — a break-in merely slow to arrive reads exactly
like a target running freely, and an intermediate version that drained once went 2 of 3. It sits
inside the quit so both neighbours hold by construction: the clear has succeeded, so no breakpoint
remains for a resume to stop at and be mistaken for the stop it is hunting, and the quit has not
yet spent the continue. Both teardown paths reach it through `end_session`, and
`ABRUPT_EXIT_RELEASE` is 8s so a supervisor-loss release does not expire mid-drain.

**The teardown is sealed against an interrupt on purpose.** A resume cut short reads exactly like
one that found nothing pending, so a client interrupting its own `end_session` could end the drain
early and hand the leftover to `qd`.

**Read the result, and know which question it answers.** `worker_terminated` is **not** the tell —
it is `!matches!(outcome, AlreadyGone | Stale)` and is `true` after an ordinary successful release
too. `target_left_running` separates a resume that failed from one that worked; it does **not**
separate ran-on from resumed-and-stopped-again. Only uptime across the gap does that, which is why
step 4 is not optional: a hypervisor answered all three fields cleanly on 2026-09-20 while the
guest was frozen and black.

**Teardown against a frozen target** — the preservation behaves as designed, and the two calls
answer different questions:

| Call | Answer | Meaning |
|---|---|---|
| `end_session { session_id }` | `released: false`, `recovery_required: true`, `worker_terminated: false` | the release could not be confirmed, so the worker is **kept** |
| `end_session { session_id, kernel_handoff_pid }` | `released: false`, `worker_terminated: true` | that worker exited and its endpoint reservation is released — **not** a resume or detach |

`released: false` on the second is the honest answer rather than a failure: the handoff never
touches the target. Do it only once the target's state is known out of band, and check the
endpoint afterwards — a guest that reboots while this side still holds its port comes back to a
stale controller on its debug link.

## Repeating it

The hypervisor smoke tier is the bounded, repeatable version of the attach/inspect/step/detach
sequence, and `WINDBG_MCP_SMOKE_HYPERVISOR_BREAKPOINT_HIT=1` adds the breakpoint hit. Drive it with
`examples/hypervisor_detach_regression.ps1`, which does the WinRM health checks this file keeps
insisting on, per cycle, and refuses the breakpoint-hit half on a multiprocessor guest unless
`-AllowMultiprocessor` says you know what it owes and can recover it. `/tiers` has how to turn the
tier on; `docs/hypervisor-debugging.md` is the long-form investigation record behind the
measurements quoted here.

**What every number here is:** one lab, one guest, one engine build (server `0.19.0+g023a294a`),
hypervisor and NT both 29671. **The topology differs by section, and it matters.** The hypercall
work — the enumeration, the wrappers, the crossing, the dispatch landmarks, the hypercall-page
freeze — was measured on that guest with **one** vCPU; the stop-per-processor rule, its detach
and its recovery on the **four** it was rebuilt with, 2026-09-21. The asymmetry, the crossing and
the two-session teardown were then **re-run on four** on 2026-09-22 and came out the same, with two
additions: the crossing kept its processor (NT parked on 1, the hypervisor stopping on 1), and it
took 1131 ms where one vCPU took 714 ms. Nothing here generalises to another DbgEng, another
transport, a processor count above four, or a guest with child partitions running.
