---
name: live-hypervisor
description: Debug the Microsoft hypervisor (`hvix64.exe`) and the NT kernel it runs, together - two KDNET endpoints as two sessions, the freeze asymmetry between them, enumerating hypercalls from both sides without a hypervisor PDB, breaking on one from either end, and the teardown that decides whether the guest comes back. Use when attaching to a hypervisor target, correlating an NT hypercall with its hypervisor-side handler, or diagnosing a guest left black after a detach.
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

`attach_kernel {}` lists the profiles the host has; which of them is the hypervisor endpoint, which
is NT, and whether they reach the same guest are facts about the machine rather than about this
repository, so ask rather than infer. A pair pointing at *different* guests gives two sessions that
never interact, which reads as a bug for a long time.

**Check the identity rather than the profile name.** `kernel_mode: true` is true of both. What
separates them is `summary.kernel_target`: `"hypervisor"` when the engine reports kernel mode *and*
the primary module is `hv` (`worker::kernel_target`), with a limitation saying NT process, driver,
object and pool inspection does not apply. An inventory it does not recognise leaves
`kernel_target` **absent** rather than guessing, so absence means ask again, not "this is NT".

## The asymmetry that orders every step

**Stopping the hypervisor stops everything it runs, the root Windows OS included** — this repo's
own words for it are "a break pauses its partitions, including its root Windows OS"
(`docs/hypervisor-debugging.md`), which is why the debugger lives outside the hypervisor it stops.

So **while the hypervisor session holds a break, the NT session cannot reach its target.** NT's KD
transport runs in NT, and NT is not scheduled.

**Measured both ways on 2026-09-21**, with both sessions open at once:

- **An NT break does not stop the hypervisor.** With NT halted at a breakpoint, a hypervisor
  attach *connected and broke in* — so the hypervisor keeps running underneath an NT stop, and the
  hypervisor session stays usable across one.
- **A hypervisor break does stop NT, and the causal link is direct.** With the hypervisor halted, a
  `read_memory` on the NT session for a page DbgEng had not already fetched **hung**, and
  **completed the instant the hypervisor was resumed**. Not an inference from silence: the same
  outstanding call returned as soon as the machine underneath it ran again.

**The refinement is the trap.** A halted hypervisor does **not** make the NT session look dead.
Anything DbgEng already holds still answers instantly — `registers` came back immediately with the
full context, because it was captured when NT stopped, and a `read_memory` near the stopped RIP
answered from an already-fetched page. The session looks perfectly healthy until you ask it for
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
   a list. Measured on NT 29671 x64 (2026-09-21): `HvcallInitiateHypercall`, `HvcallFastExtended`,
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

   `nt!HvcallInitiateHypercall` ends `mov rax, qword ptr [nt!HvcallCodeVa]` … `call rax`
   (`nt+0x2f34ed` on that build), so it reaches stub `+0x00` and nothing else. **A breakpoint on
   `+0x00` therefore catches only the generic path**, which on a merely idle guest may never run:
   23 seconds of a resumed 1-vCPU target produced no hit at all, because the traffic was going
   through the fast wrappers into the dedicated stubs.

3. **Which code is being called.** The hypercall input value is in a register at the call site —
   its low 16 bits are the call code, and the rest is fast/rep flags and counts. Reading
   `registers` at the instruction is what turns "a hypercall happened" into "this one did", and it
   is the only one of these that enumerates what the guest *actually uses* rather than what it
   *could*. **Read the hazard below before arming that breakpoint.**

**`disassemble` takes `address`; `set_breakpoint` takes `expression`.** Passing `expression` to
`disassemble` is not refused — the field is dropped and the call falls back to the current
instruction pointer, so it answers about wherever the target happens to be stopped and looks like
a successful disassembly of what you asked for. On a target stopped at the KD break-in that is
`nt!DbgBreakPointWithStatus`, whose `int 3; ret` reads plausibly enough to be believed. Two
consecutive calls returning byte-identical output for two different arguments is the tell.

4. **What the hypervisor implements** was reversing work and is now done for this build: the VM
   exit reaches a `VMCALL` case that fans out through a switch over call codes, and the chain is
   in the second table below. `docs/hypervisor-demonstration-20260920.md` walks the image the long
   way — PE exception directory to bound functions, RVAs throughout — and the saved artefacts it
   hashes are where to start rather than re-deriving from a fresh copy.

**Every RVA in those documents belongs to one build**: hypervisor 29671, `hvix64.exe`, image size
`6393856`, timestamp `3152137373`, checksum `2578329`. `modules` reports `timestamp` and `size` for
the session in front of you; if they differ, the landmarks are a different function and
`run_to_address` will run to it without complaint. For that build:

| RVA | What the 2026-09-20 analysis established |
|---|---|
| `hv+0x404a60` | `int 3`, followed at `+0x404a61` by `ret` — where the initial break lands |
| `hv+0x312024` | inside a recurring deadline-driven callback, `[hv+0x311eec, hv+0x3120de)` |
| `hv+0x20fe71` | the dispatcher's call of that callback; it returns to `hv+0x20fe73` |
| `hv+0x404c5e` | just after `sti; hlt` in a short conditional halt routine |

**`hv+0x312024` is not a hypercall site and is the wrong fixture to copy.** It is the return site
of a debug-break poll inside a *recurring* callback, reachable on branches where no break was
requested — which is why other processors met a breakpoint there without issuing anything. The
demonstration used it because it was a return address it could read off the stopped stack.

**The hypercall path itself, measured 2026-09-21 on that same build** — the chain one `vmcall`
takes, and the crossing that used it, are in
[`docs/hypervisor-debugging.md`](../../../docs/hypervisor-debugging.md):

| RVA | What it is |
|---|---|
| `hv+0x25F460` | the VP loop's exit handler, entered with the exit reason in `edx` |
| `hv+0x25F9D4` | its `cmp r12d,12h` — the VMCALL case, calling `hv+0x21AFF0` |
| `hv+0x21AFF0` | the hypercall entry; `hv+0x247850` gets first refusal, then `hv+0x210520` |
| `hv+0x210520` | the dispatcher: guest register array at `[[r9]+0x10C0]`, input value from guest `RCX` |
| `hv+0x21056D` | **the site to break on** — input value in `rbx`, register array in `rcx` |
| `hv+0x210669` | where codes `0x5C`/`0x5D` go, and only with bit 31 of the input value set |

**Break at `hv+0x21056D` rather than at either function's entry.** A conditional breakpoint whose
expression dereferences memory can fault, and a faulting condition *stops* the hypervisor — which
freezes the guest and ends the run with nothing learned. It cost two runs, 90 s and 120 s, and
taking the VP from `@rcx` instead of a fixed address did not save it. At `hv+0x21056D` the value is
already in a register, so the condition reads no memory at all.

**A second VP entry/exit pair in the image is not this one.** `hv+0x405860` with handler
`hv+0x375F3C`, whose VMCALL case calls `hv+0x402D9C`, reads exactly like the hypercall path and is
not it — it refuses fast hypercalls and ones with bit 31 set, and its caller routes that refusal
into what reads as a bugcheck path.

## Stopping this guest after the attach froze it, twice

**Measured 2026-09-21**, and it is the reason this file no longer opens with the NT-side
breakpoint as the obvious first move.

On a healthy one-vCPU guest — NT 29671 x64, `nt` symbols resolving, a clean attach and a clean
23-second resumed run behind it — a breakpoint on the generic `vmcall` at `HvcallCodeVa+0x00`
followed by a `break_in` request ended with the guest **black and frozen at the console**. The
break-in was lodged on the engine (`worker: interrupt raised for job 11 … Raised`) and was never
serviced; the run stayed outstanding for nineteen minutes. A hypervisor attach to that guest's
*own* hypervisor endpoint, with hypervisor debugging confirmed enabled for that boot, **also never
connected** and parked into `kernel_unresolved`. Both debug transports were gone at once.

**It reproduced on the dedicated stubs**, which is what rules out the first explanation rather
than confirming it. A second run the same day, after a reset, armed the four *dedicated* stubs and
left `+0x00` alone on the reasoning that the generic funnel was what the debugger's own path used.
That guest wedged inside twenty seconds of a fifteen-second bounded run, with **no `break_in`
requested at all**, and stayed silent for ten consecutive WinRM probes over twenty seconds while
the engine reported no stop at 126 seconds. So "avoid the generic stub" is not a remedy, and the
advice this section originally gave was wrong.

**The control settles it, and it was run.** Third boot, attach, arm **nothing**, `continue_async`
with a fifteen-second bound: the bound's own break-in landed at 15021 ms, processor 0, at
`nt!DbgBreakPointWithStatus`, `timed_out: true` and `target_gone: false`. **This guest stops
perfectly well after the initial attach.** So the freeze is not a property of the KD link, and the
two runs' common factor is what remains:

| | Run 1 | Run 2 | Control | Wrappers |
|---|---|---|---|---|
| Armed | generic `+0x00` | four dedicated stubs | **nothing** | four `ntoskrnl` wrappers |
| Where | hypercall page | hypercall page | — | inside `nt` |
| Outcome | froze | froze | **stopped cleanly** | **stopped cleanly, then hit** |

**A breakpoint patched into the hypercall page is what freezes this guest** — generic stub or
dedicated stub alike — while breakpoints in `ntoskrnl` and break-ins with nothing armed are both
fine. The best available explanation stays what it was: the debugger's own path for reporting a
trap needs the page it trapped in, so the stop can never be delivered. That is now the *surviving*
explanation rather than a guess, but the mechanism itself has still not been instrumented.

**So do not patch the hypercall page.** Break on the NT **wrapper** instead — it is in `ntoskrnl`,
it carries the call code in a register, and it works (below).

**Recovery from either freeze was a reset.** Native KD was not a route: every recovery this repo
records found the hypervisor still executing with a pending stop to release, and here nothing was
executing to answer any debugger — the guest's *own* hypervisor endpoint, with hypervisor
debugging confirmed enabled, would not connect either. The patch costs nothing across the reset,
since `HvcallCodeVa` is a dynamically mapped page rather than a file-backed image. Free both
endpoints before the guest reboots, or it comes back to a stale controller on its debug link.

## Break on a hypercall from both ends

The load-bearing choice is that **the NT side runs asynchronously**. There is no async step: `go`,
`step_over` and `step_into` all wait, and their wait is `EXEC_WAIT_MS` — **60 seconds**
(`server.rs`). A step that hands the machine to the hypervisor debugger will not return inside
that, so a synchronous step reports a timeout that measures the other session rather than the
target. `continue_async` returns a handle the moment the run starts, bounds it with `max_run_ms`
(default `EXEC_WAIT_MS`, clamped to `MAX_ASYNC_RUN_MS` = **one hour**), and `wait_for_stop` reads
the stop rather than taking it — so asking twice gives the same answer, a run that stopped while
nobody waited still has its stop there, and on a kernel target the report names the **processor**.

**This sequence ran end to end on 2026-09-21**, one vCPU, with the guest independently healthy
afterwards — every step of it, including the crossing at step 5. One thing is written in a better
order than it was run: choosing a value that crosses happened *after* the hypervisor was attached
that day, which cost three runs hunting a value that never arrives, so it is step 3 here. What the
sequence does not cover is a second processor.

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
3. **Collect the stop and read the call code.** `wait_for_stop` reported `Breakpoint 2 hit` at
   `nt!HvcallInitiateHypercall`, `processor: 0`, `timed_out: false`. `registers` then gave
   **`rcx = 0x8001005D`** — by the TLFS input-value layout the low 16 bits are the call code
   (`0x005D`) and bit 16 is the *fast* flag, with the input parameter in `rdx` (`0x200B`). Naming
   the call code needs the TLFS; the register is the measurement.

   **That value does not cross, and you will keep landing on it**, so take another one *here*,
   before the hypervisor is armed for it. Both unconditional captures of this wrapper held
   `0x8001005D`, and excluding it cost 9.6 s to get a second value where the first hit had come in
   7 ms — that is what "keep landing on it" rests on, rather than a count of calls. `0x8001005D`
   never reached the hypervisor's dispatcher in 60 s of free running, while the next value out of
   the same wrapper reached it in 714 ms. Bit 31 marks a hypercall for the parent hypervisor and this lab's guest is
   itself nested, which is a plausible reading and not a measured one. Re-arm NT to skip it — and
   then **resume NT again**, because `bc`/`bp` only change what is armed and leave NT halted where
   it was:

   ```text
   bc *; bp nt!HvcallInitiateHypercall "j (@rcx != 0x8001005d) ''; 'gc'"
   ```

   followed by the `continue_async` from step 2. That stopped on `rcx = 0x00010068` — call code
   `0x68`, fast bit, `rdx = 0`. **That** is the value step 5 arms for, and record `rsp`, `rsi`,
   `rdi` and `r13` with it: they are what identify the instance at the other end.
4. **Attach the hypervisor while NT sits there.** This works — it is how the asymmetry above was
   measured — and the summary comes back `kernel_target: "hypervisor"` with `hv`/`hvix64.exe` and
   `symbols: none`. Both sessions are then open, independently routed, and both targets halted.
   Work the hypervisor stop by address and `hv+RVA`: `registers` landed on `hv+0x404a60`, the
   documented `int 3; ret` initial-break site, reproduced on a fresh boot.
5. **Correlate, with a conditional breakpoint on each side.** Measured 2026-09-21. Arm the
   hypervisor at `hv+0x21056D` for the value step 3 settled on, with a register-only condition,
   which auto-continues on every other hypercall so the guest keeps running:

   ```text
   bp <hv-base>+21056d "j (@rbx == <input-value>) ''; 'gc'"
   ```

   **Both targets are halted at this point, so three calls in this order, and the middle one is
   the one it is easy to leave out:** `continue_async` **NT** — which cannot take effect yet and is
   simply lodged — then `continue_async` the **hypervisor**, which is what puts the guest back on a
   processor and lets NT take that lodged resume, then `wait_for_stop` on the hypervisor. Releasing
   NT alone changes nothing: this file's own asymmetry says a halted hypervisor stops NT, and a
   procedure that resumes the hypervisor only at teardown never reaches a stop. **NT first rather
   than the hypervisor first** is deliberate and is the order that was measured: with NT's resume
   already lodged, it is taken the instant the guest runs, so the first hypercall matching the
   condition is the released call rather than one another thread slipped in during the gap.

   Read the guest register array at that stop — `rcx` points at it. Every register agrees with the
   NT-side capture, transformed as the wrapper's prologue transforms it: `rbp` is NT's `rsp` less
   seven pushes less `0x27`, `rsi` is NT's `rsi` with exactly its low byte cleared, and `rdi`,
   `r13`, `r10` and `r11` arrive untouched. It landed **714 ms** into that hypervisor run.

   **Those two transformed values are not *unique*** — the same thread calling the same wrapper
   again at the same stack depth would reproduce them. What makes this one instance is the
   ordering: NT was parked at that call, released, and this was the first hypercall matching it.
6. **Resume both, hypervisor first.** Take any hypervisor breakpoint off first or the next
   hypercall re-enters it immediately, then `continue_async` the hypervisor. Only now does NT
   execute: an outstanding NT call unblocks the moment the hypervisor runs.

**Three review findings on this procedure were all one mistake — a step that changes what is armed
and does not say what to resume — so here is the state both targets are in after each step.** A
step that leaves something halted where the next step needs it running is visible here and is not
visible in the prose:

| After step | NT | Hypervisor |
|---|---|---|
| 1 arm the wrappers | halted | not attached |
| 2 resume, trigger from outside | running | not attached |
| 3 capture, re-arm, **resume again**, capture the crossing value | halted at the chosen value | not attached |
| 4 attach | halted | halted at `hv+0x404a60` |
| 5 arm `hv+0x21056D`, lodge NT, **resume the hypervisor** | resumes, then frozen mid-`vmcall` | halted at `hv+0x21056D` |
| 6 clear the hypervisor breakpoint, resume it | resumes, and stops again at once if its conditional is still armed | running |

Three rules fall out of that column pair, and they are the ones the findings kept landing on.
**Arming is not resuming** — `bp`, `bc` and `set_breakpoint` change what is armed and leave the
target exactly where it was. **NT's state is only meaningful while the hypervisor runs**, so any
row where the hypervisor is halted is a row where NT does nothing at all. And **a row that says
*running* is a row that accepts three calls and no others** — `interrupt`, `end_session` and a
further resume (`Sessions::refuse_while_running`), which step 2 says of NT and is just as true
here: NT's own conditional cannot be cleared until NT has stopped, by its next match or by an
`interrupt`. Clearing it by hand is optional anyway, since `end_session`'s teardown clears
breakpoints itself before it detaches.

**Two ordering traps, both measured 2026-09-21, and each costs a run.**

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

**A bounded hypervisor run that expires leaves a break-in owing**, and the next resume spends it:
an immediate stop at `hv+0x404a60` with the CTRL+BREAK banner and nothing armed. Seen twice. It is
the same leftover the teardown drain exists for, it is harmless, and it reads like a breakpoint
hit if you are not expecting it.

**A breakpoint on hypervisor-side dispatch is shared code every processor runs.** That is the exact
shape `FOLLOWUPS.md` item 93 is open on: on the four-processor lab, a temporary breakpoint hit, its
removal and a reported detach were followed by further per-processor stops and a frozen guest,
twice. `examples/hypervisor_detach_regression.ps1` refuses `-BreakpointHit` on a guest reporting
more than one logical processor, re-checked per cycle because a restart moves it.

**`clear_breakpoints` and `breakpoints` may not be on the surface in front of you.** They landed
2026-09-20 in `9c9dd8a`; a client whose tool list lacks them is either on an older server or a
narrowed surface, and the list alone does not separate those. `execute` with `bl` to list and
`bc *` to clear works either way.

## Teardown

1. **Resume the hypervisor** and leave it attached.
2. **`end_session` the NT session** — it resumes and actively detaches a live kernel, and needs a
   machine that can execute to do it.
3. **`end_session` the hypervisor session.**
4. **Read guest health from outside the debugger**, twice, for boot identity and advancing uptime.
   `released: true` and `target_left_running: true` are the debugger's side of the wire, and on
   2026-09-20 a hypervisor answered exactly that while the guest was frozen and black.

**The clean path is measured, on the dbgscope drain placement.** On 2026-09-21, with an NT session
and a hypervisor session both open and both targets halted, the order above released both:
`released: true`, `target_left_running: true`, `recovery_required: false` on each. Independent
WinRM then answered twice with the **boot identity unchanged** and uptime advancing
(572.21 s → 575.59 s), and both KD ports were free with no worker left. That is the live
hypervisor validation `023a294` recorded as outstanding when it moved the drain into dbgscope —
one run, one vCPU, one engine build, and the four-processor case is still item 93's. The answering
server was `0.19.0+g023a294a`, read off the binary rather than assumed from the checkout, which
`.claude/rules/measurement-provenance.md` exists because those two routinely differ.

**What the teardown does, and where it lives.** dbgscope's `quit_and_detach_target` clears the
breakpoints, **spends the break-ins an `INITIAL_BREAK` KD attach left owing, and only then sends
`qd`** (dbgscope#174, pinned here by `023a294`, 2026-09-21). That drain is the fix for the freeze:
a leftover break-in otherwise takes the target's one continue at `qd` and the guest stops again
with no debugger attached. **It ends on two consecutive free resumes, not one** — a break-in merely
slow to arrive reads exactly like a target running freely, and stopping at the first free run
leaves it pending; an intermediate version that drained once went 2 of 3. Five attempts cap it, so
a target that breaks on every resume cannot make a teardown unbounded, and reaching the cap is not
an error. It sits inside the quit so both neighbours hold by construction — the clear has
succeeded, so no breakpoint remains for a resume to stop at and be mistaken for the break-in it is
hunting, and the quit has not yet spent the continue. Both teardown paths reach it through
`end_session`, and `ABRUPT_EXIT_RELEASE` went 5s to **8s** so a supervisor-loss release does not
expire mid-drain.

**The teardown is sealed against an interrupt on purpose.** A resume cut short reads exactly like
one that found nothing pending, so a client interrupting its own `end_session` could end the drain
early and hand the leftover to `qd`.

**Read the result, and know which question it answers.** `worker_terminated` is **not** the tell —
it is `!matches!(outcome, AlreadyGone | Stale)` and is `true` after an ordinary successful release
too. `target_left_running` separates a resume that failed from one that worked; it does **not**
separate ran-on from resumed-and-stopped-again. Only uptime across the gap does that.

**A frozen guest afterwards** is recovered by one native-KD connection without `-bonc` and without
an explicit-target poke, which finds the pending stop, and one `qd`. Re-attaching with this server
is not that. The 12:00:26 attempt on 2026-09-20 did exactly the right thing and still left the
guest frozen, needing a second connection at 12:03:45.

**That recovery assumes something is still executing to answer**, and it is worth checking before
reaching for it. When the freeze took the hypervisor's transport with it (above), no debugger
could reach the guest at all and the reset was the only route.

**Teardown against a frozen target, measured 2026-09-21** — the preservation behaves as designed,
and the two calls answer different questions:

| Call | Answer | Meaning |
|---|---|---|
| `end_session { session_id }` | `released: false`, `recovery_required: true`, `worker_terminated: false` | the release could not be confirmed, so the worker is **kept** |
| `end_session { session_id, kernel_handoff_pid }` | `released: false`, `worker_terminated: true` | that worker exited and its endpoint reservation is released — **not** a resume or detach |

`released: false` on the second is the honest answer rather than a failure: the handoff never
touches the target. Do it only once the target's state is known out of band, and check the
endpoint afterwards — a guest that reboots while this side still holds its port comes back to a
stale controller on its debug link.

## What has not been measured

Measured on 2026-09-21, one vCPU, one engine build, one guest: the enumeration, the NT-side
hypercall breakpoint and its call code, the hypervisor-side dispatch chain and one hypercall
crossing it, both sessions open at once, the asymmetry in both directions, and a clean two-session
teardown with independent health. What remains:

- **One hypercall has been seen from both ends, once, on one vCPU** — so what is open is the
  multiprocessor case rather than the crossing. A dispatcher breakpoint is hypervisor-side code
  every processor runs, which is the shape `FOLLOWUPS.md` item 93 is filed on; on one processor it
  was uneventful, and that is all it says.
- **Why `0x8001005D` never arrives is unresolved.** The absence is measured at `hv+0x21056D`; it
  does not separate "this hypervisor never receives it" from "`hv+0x247850` answers it before the
  dispatcher is reached", and nothing was instrumented to tell those apart.
- **The hypercall-page freeze has a surviving explanation, not an instrumented one.** Three
  placements separate it cleanly — page freezes, `ntoskrnl` and nothing-armed do not — but nothing
  has shown *where* the reporting path re-enters the page.
- **All of it is one processor.** The four-processor case is open (`FOLLOWUPS.md` item 93); the
  drain consumes up to five break-ins, more than one processor can owe, but whether four
  processors owe one each is unmeasured. The freeze above may also behave differently where a
  second processor exists to service the transport — untested either way.
- **Once each.** The teardown validation, the asymmetry and the breakpoint hit are single runs, on
  the same guest and engine version. None of them generalises to another DbgEng, another
  transport, or a guest with child partitions running.
