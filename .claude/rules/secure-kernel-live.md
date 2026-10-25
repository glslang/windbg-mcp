---
paths:
  - "src/**/*.rs"
  - "tests/**/*.rs"
  - "build.rs"
---

## Driving a live Secure Kernel session, and the orderings that are not guessable

Everything here was learned by running the seven live tools against a real VBS guest and getting it
wrong first. None of it is visible from the signatures, and each one costs a run — a run that
pauses somebody's VM and may leave a target held — so it is written down rather than rediscovered.
The provider and the guest are the operator's (`docs/secure-kernel/live-control-provider.md`); what
follows is this server's half.

**The tool group is `extra`, so the default surface does not serve it.** `securekernel` is the only
group marked that way, which means a client that asks for nothing gets every *ordinary* group and
none of these twelve tools. The refusal is `-32602` naming `--tools`, which reads like a
configuration mistake rather than a missing capability — and an **unset** `WINDBG_MCP_TOOLS`
produces it just as surely as a narrowed one. **On stdio the command line is the only way to widen
it**, and that is a property of where the variable is read rather than of the group: a tools spec in
the environment is a *credential's* surface, resolved in the listener's own factory
(`listen::gate` → `Credentials::surface_for`) and nowhere else, so setting `WINDBG_MCP_TOOLS` for a
stdio server changes nothing. A **listener or service** client is therefore widened without touching
the command line — `WINDBG_MCP_TOOLS_<NAME>` beside that client's token, or a `tools` field in its
credential-file entry, naming `securekernel` like any other group — which is also how one client on
a port gets these tools and another does not.

**Establishing the session needs VTL1 quiescent; the transition is permitted at a stop.** This is
the ordering that looks like a bug from both ends. `allow_transition_cr3` says plainly that "the
initial paused baseline and live-memory source must still match `expected_cr3` exactly" — so while
the session is being opened and armed, the register provider and the live-memory provider must
agree about the VP's page-table root. If anything is executing in VTL1 they sample different
instants and disagree, and the arm fails with `live-memory source CR3 … does not match the bound
CR3 …`. But a *stop* worth catching is usually a transition, which is a different root. Quiet while
establishing, busy while waiting, is the only ordering that satisfies both — and since the
dispatcher pauses the **whole VM** while breakpoint state changes, whatever makes VTL1 busy cannot
be started from outside between the arm and the wait.

**CR3 is discovered, never asserted.** `expected_cr3` is an *optional* assertion about what the
register provider reported, and `control_transport`'s own doc says that without it "the provider
must discover CR3 and report it in its hello". Supplying a value sampled by the caller is strictly
worse than supplying none: it adds a race and promotes the result to a pin the opener accepts.
**One live read of a VP's CR3 is not the Secure Kernel's root** — it is whatever address space was
resident at that instant, and two independent sources agreeing on it proves only that they sampled
together, not whose address space it is. `vmwp_pid`, `dispatcher_vnd` and `partition_id` are
optional assertions for the same reason.

**The root in force at a stop is in the stop's own `registers.values`, not in its `target`.**
`target.expected_cr3` is the session's provider-hello baseline and the `TargetIdentity` is cloned
unchanged into every stop, so under `allow_transition_cr3` it holds exactly the *wrong* root for
the case that flag exists for. Read the `cr3` entry of the register snapshot; the two differing is
what the transition **is**, and comparing them is how a caller detects one.

**A single step is validated against the root it was armed in**, so an instruction that writes CR3
cannot be stepped: `ExpectedStop::SingleStep` carries the CR3 and `RegisterSnapshot::from_values`
refuses a stop whose root differs. That requirement is sound — the memory source reads guest
*physical* memory, so a virtual address is resolved by walking page tables from one root, and every
read at the stop goes through that walk — but it makes a whole instruction class unsteppable rather
than merely careful. `FOLLOWUPS.md` item 123 is the shape of the fix.

**Epochs are consumed exactly once, and a stop's `instruction` is the one just stepped.** A
repeated `sk_live_step` must state `address` and `bytes` for the instruction at the *current* RIP,
and feeding back the stop record's own `instruction` fails with "the step instruction address …
does not match the stopped RIP" — because that field describes what the previous step executed, not
what comes next. Something therefore has to know the next instruction's length; the server can
disassemble, but not against a live session's own image (item 122), so a caller ends up opening a
second session on the pinned image to do it.

**Debug registers are per virtual processor.** A session arms one VP, so a workload that runs on
another one fires nothing, and the symptom is a wait that simply expires. On a guest with more than
one VP, pin whatever is meant to be caught.

**And on one VP they are shared between VTLs: DR0-DR6 are one set, only DR7 is per VTL.** Measured
2026-10-24 on the M7 nested child (`docs/secure-kernel/skcall-debugging-roadmap.md`, M7.1a): a
VTL1 slot-0 arm found the VTL0 kernel session's `ba` address in DR0 and its B0 bit in DR6, and
overwrote both. So a VTL0 `ba` and a VTL1 slot collide, and a VTL1 stop's DR6 can carry bits a
VTL0 debugger left there. The obvious escape, a software breakpoint at
`nt!VslpEnterIumSecureMode`, deadlocks a VBS guest at its first hit (measured 2026-10-25, M7.1a
run `20261025T073515`): the kernel debugger writes HVCI-protected text through
`VslWriteProtectedPage` -> `VslpEnterIumSecureMode`, so the write that services the `int 3`
executes it with `KdDebuggerLock` held and the one processor spins in `KeFreezeExecution` for ever.
Never place a software breakpoint on that write path; `sk_call_trace` stays a processor breakpoint
(a source test pins the kind) and the hypervisor trace stays on software breakpoints. The two
layers share the one VP's slots by **partition**: `open_sk_live_control` takes
`reserved_hardware_slots` (M7 reserves slot 0 for M4's `ba`), and `LiveControl` writes, restores
and compares only the slots it armed and reads DR6 only through them (`owned_slots`,
`owned_cause_mask`, `matches_outside_foreign_slots`); a manifest's sites are armed outside the
reservation through `ServiceManifest::breakpoints_outside` and mapped back by the decoder's
`SlotMap`. The kernel debugger writes its whole cached debug-register block back at every stop, so
the VTL1 controller's slot writes must never overlap a VTL0 debugger stop: the transaction arms M6
before M4 and drains M4 before M6, and per-event writes happen while the VP is held in VTL1.

**A stop wanted while the trace runs is a pump, never a settle.** The trace stays armed until the
VP is quiescent, Hyper-V cannot pause a VM whose `vmwp` is debugger-stopped, and the event-site
breakpoint cannot stay installed across a detach — so `pause_or_hold_running_target` asks for the
pause from a helper thread and pumps `vmwp` under the installed breakpoint until the pause is
reported or an owned event arrives, and that event is the disarm point (`Disarmed::Held`), adopted
by the next wait. Measured 2026-10-24 (M7.1a run `20261024T210251`): the earlier one-second settle
accepted only its own deadline, the next event faulted the session, and recovery then paused a
debugger-held `vmwp` for 60 s. Do not reintroduce a wait that asserts the guest is idle, and never
call a Hyper-V management helper while the dispatcher holds `vmwp` stopped.

**Every event at the site is triaged before it is held, because the intercept is per partition.**
The exception intercept vectors 1 and 3 install for the child is not per VTL: a VTL0 kernel
debugger's `int 3` break-in, its `ba` hit and DbgEng's trap-flag step over its breakpoint all
raise through the VTL1 controller's handler context, and completing them natively discards
them, so the VTL0 kernel never sees its break (measured 2026-10-25, runs `20261025T084354` and
`20261025T113332`: M4's break-in got no stop until M6's teardown unregistered the handler). The
user-side message carries no VTL, so the dispatcher cannot decide alone: `wait_for_stop` and
`begin_disarm` take an `EventTriage`, `LiveControl` answers it through the provider's
`active_vtl` (`HV_INPUT_VTL` with the byte clear reads the executing VTL; read as a target VTL,
`vsm_vp_status` names the VTL asked about, which is why it never discriminated), and a foreign
event is carried through the native completion with the site re-armed instead of being held
and faulting the session. Recovery triages nothing and holds whatever arrives, as before. **That
VTL still loses the exception, and three ways of handing it back were measured not to work**
(runs `20261025T115420` to `20261025T130540`): forcing the completion result (at
`handle_return` the handler's return only picks the flags of the next
`VidMessageSlotHandleAndGetNext`, and a zero leaves the message outstanding with the VP
suspended); `HvRegisterPendingInterruption` from the root, refused with `HV_STATUS 0x0005`
however the input VTL is written; and `HvRegisterPendingEvent0`, accepted and consumed without a
trap whether armed before the completion or under an explicit suspension held across it, which
also blocks VID's completion until something else moves the VM. What re-delivers an exception
nobody claims is `vmwp`'s own handler writing through VID's deferred VP-state path, flushed in
the completion's own hypercall; no root-side path into that batch has been demonstrated. So M4
and M6 cannot share a VP in one window with what exists; the M7 roadmap records the decision:
M7.1's idle gate runs M6 and M4 in alternation (a criterion revision), M7.2 is to be designed
off M4's hardware breakpoints, and the in-`vmwp` redelivery stays a fallback.

**The alternating plan is `--m7-alternate` on the transaction coordinator** (`ALTERNATING_WINDOWS`
in `src/skcorrelate.rs`: M6 alone, then M4 with M5, then M6 again; passed live 2026-10-25, run
`20261025T145507`). Between windows it asks the adapter for a `transition`, and opens the next
window only if every field of the `TransitionAck` reads clean: the VTL1 handler verified
unregistered when a VTL1 window closed, no slot enabled in either VTL's DR7, no pending event or
interruption, the trap flag clear in both VTLs, no engine worker. Two readings a driver gets
wrong first, both measured that day: the dispatcher registers **two** handlers per session
(vectors 1 and 3) and its clean release logs **one** `dispatcher verified handler unregistration
and callback scratch release` line per session, after the last context's deferred cleanup, so
that line is the count and the per-context free line is not written on that path; and a kernel
debugger's `ba` reaches the processor's DR7 **with the continue** that resumes the target (the KD
control set carries DR7), so a reading taken while the target is stopped at the arm shows no slot
(`0x400`), and the slot is measured once the bounded run is under way. After M4's detach VTL0's
DR0 still held its address with the enable clear; a switch reads enabled slots, not values.

**`sk_live_wait` carries its own deadline and takes no timeout argument.** It comes from the
operation's budget, which is of the order of a minute — so anything timed to arrive later than that
cannot be caught by it, and a delay chosen to give the arm headroom can quietly exceed it. Time
such things in **guest** seconds where possible: the dispatcher's pause of the whole VM stops a
guest clock and does not stop a host one.

**A release passes through an unresolved state on its way out.** `live_control_unresolved`, with
"release is in progress; register restoration, handler cleanup and handled detach are unconfirmed",
is a *transient* and is followed by `closed` and `released: true`. Anything reading session states
must treat the end as authoritative in both directions; a sticky "bad" mark renders a successful
run as a failed one.

**What a passing run establishes, and what it does not.** A live read answers with bytes and the GPA
its VTL1 walk resolved to, which shows the Secure Kernel *can* be read. Whether the normal kernel
could **not** make the same read is asserted only when the tier's config names a `vtl0_profile`
(item 124), with `vtl0_guest` naming the expected profile guest claim for the VTL1 VM. The attached
profile must carry that claim before any reads; the pairing is still the operator's assertion.
Then it takes the pair of readings on a VTL0 kernel session opened *after* the VTL1
release — a guest held in the stop cannot answer KDNET — with the server on
`--tools securekernel,inspect`, since `execute` is in `inspect`. Three traps. The axis is
**physical**: VTL0 and VTL1 are separate address spaces and a kernel-looking VA is valid-looking in
both, so a VTL0 read of a Secure Kernel address does not fail — it answers about a different page,
and VTL0's walk of the address is reported, never relied on. The attempt is a physical read of the
GPA VTL1 just read from, and measured 2026-10-11 it fails in **exactly the form of a read with no
RAM behind it** — `Physical memory read at <gpa> failed` — so the attempt alone cannot tell denied
from absent; the control beside it (the NT image base's page reads back its PE header) and the
VTL1 read that just returned bytes from that GPA are what make the failure mean something. And a
page-table comparison settles nothing for a trustlet's pages, which VTL0's tables **do** map. The
attempt and control both use `!db <gpa> L10`; a successful attempt fails the tier and prints the
bytes VTL0 returned.
Each answer must name the requested GPA. The tier does not bind the two sessions to a boot ID;
its paired observations support protection only with an independent audit excluding a reboot
between them. A reboot could make the saved GPA absent, so the tier alone makes no such claim.

**The M7.2 join decides nothing a capture cannot prove, and three of its readings surprise.**
`windbg-mcp --m7-join` (`src/skjoin.rs`) joins the three drained traces offline;
`target/codex-m7/join-m7-run.py` runs it over a run directory. In the nested lab the admission is
`interval_only`, because M6's worker samples K3's counter, so every M5 stage comes back ambiguous
with all round trips as candidates however clean the run, and only the M4 stage can pair, by
rank, when one window certainly contains the other and both traces are complete runs of the same
length. A trace that reached its capacity is not a complete run, so the three K3 qualification
records, all at capacity, pair nothing. And a round trip with no recorded return bounds nothing
when its trace was capped or still armed: the trace stopping says nothing about where the VP was,
and the first draft let a capped hypervisor trace's last open call enclose every later VTL1 phase
(caught by the capped-trace test, 2026-10-25). Zero VTL1 records is `incomplete`, never a vacuous
pass. The roadmap's M7.2 result has the rules and the first-stage field table.
