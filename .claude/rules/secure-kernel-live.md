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
produces it just as surely as a narrowed one. It can only be widened on the **command line**: the
unnamed `WINDBG_MCP_TOOLS` is a *credential's* surface, read on the listener and service paths
alone, with no stdio read site, so setting it in the environment of a stdio server changes nothing.

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
together, not whose space it is. Read the root a session settled on back from a stop's
`target.expected_cr3`. `vmwp_pid`, `dispatcher_vnd` and `partition_id` are optional assertions for
the same reason.

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
its VTL1 walk resolved to, which shows the Secure Kernel *can* be read. Nothing asserts that the
normal kernel could **not** make the same read, and that is the claim the feature exists to
demonstrate (item 124). Two traps when reasoning about it. The axis is **physical**: VTL0 and VTL1
are separate address spaces and a kernel-looking VA is valid-looking in both, so a VTL0 read of a
Secure Kernel address does not fail — it answers about a different page. And a page-table
comparison settles it only for the Secure Kernel's *own* addresses: a trustlet's pages **are**
mapped by VTL0's tables, and the denial is the hypervisor's second-level translation, which no walk
can see. Only attempting the access from VTL0 shows that.
