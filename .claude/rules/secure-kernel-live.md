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
(item 124), and then as a pair of readings on a VTL0 kernel session opened *after* the VTL1
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
attempt itself is a marked gap in the tier (`secure_kernel_page_read_from_vtl0`), and a configured
run fails there until it is written.
