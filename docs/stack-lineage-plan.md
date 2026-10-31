# Stack lineage: judging whether a call stack is what it claims to be

First drafted 2026-10-28; revised and implemented 2026-10-31. This is the design of
`stack_lineage`, a read-only tool that judges a thread's call stack the way a stack-spoofing
detector does, and the record of the measurements that changed the first draft. It is an analysis
capability: it answers a debugger question ("could these frames have been produced by calls?") and
is written for the reason this project writes everything, which is that an answer the reader acts
on must not look like one when it is not.

## 1. Scope

### 1.1 What it is, and what it deliberately is not

"Stack spoofing" is the family of techniques that make a thread's call lineage read as a
legitimate origin to an unwinder-based detector — an EDR stack walker, ETW's stack capture — so
that code the target never meant to run appears to have been called from somewhere ordinary. The
mechanisms differ, and their authors' write-ups are the place to read them; for a detector they
reduce to a short list of observable properties, and those are what this tool reads:

- a return address that **no call pushed** — a synthetic frame planted on the stack;
- a return address whose **preceding instruction is not a call** — a gadget used as a frame;
- a frame **executing in memory no module holds** — injected code, or a JIT;
- on a CPU enforcing CET shadow stacks, a return address **absent from the hardware shadow
  stack**, which records every `call` the thread made and which ordinary code cannot write.

A debugger reads a target; it cannot hide its own execution, and this server's architecture —
one engine per worker process, every call on the engine thread, no engine in the process that
serves MCP — is built for observation. So the coherent integration is the *judge*, not a spoof
engine. That is also the artifact a red-teamer wants ("did my loader's stack pass?"), which is why
the offensive direction is out of scope by construction rather than by refusal (§9).

### 1.2 What it builds on

- `backtrace`'s walk (`worker::walk_attributed`): the engine's frames with each one's `module` +
  `rva` and the three-state module attribution (`triage::Attribution`). `stack_lineage` reuses it,
  so its frames are the same records `backtrace` and `crash_triage` return and join them.
- `dbgscope`, which already has every primitive this needs — **no new dbgscope method**:
  - `DebugEngine::integer_register` reads `ssp` and `cetumsr` by name (§2.1);
  - `DebugEngine::function_extent` asks the engine for a frame's unwind entry
    (`GetFunctionEntryByOffset`), answering `NoEntry` distinctly from a failure;
  - `DebugEngine::read_memory` reads the bytes before a return address and the shadow stack;
  - `dbgscope::dbgeng::decode_instruction` decodes those bytes with no engine at all — iced for
    x86/x64, dbgscope's own A64 decoder for ARM64 — and classifies calls as `Flow::Call`.

## 2. What was measured, and what it overturned

Every claim below was measured on the ARM64 bench on 2026-10-31 against the checked-in samples in
`docs/samples/`, with the SDK's `cdb` (dbgeng 10.0.26100) and by parsing the minidump streams
directly. Four of the first draft's premises did not survive.

| First draft said | Measured |
|---|---|
| The CET fields `ShadowStackPointer…` sit past the 1,232-byte x64 `CONTEXT`, so a CET target reports a larger context | The x64 `CONTEXT` has no shadow-stack fields at all. The shadow-stack pointer lives in the XSAVE **`CET_U`** state component (XSTATE feature 11, `IA32_PL3_SSP` beside `IA32_U_CET`), outside `CONTEXT` |
| `SCOPE_CONTEXT_SIZES` climbs to 65,536, so the bigger context is captured | `GetScope` keeps the **first** size it accepts, which on x64 is 1,232: the ladder stops there whatever the target carries (`dbgscope::DebugEngine::scope`) |
| Parse the CET fields out of the raw context at a header-defined offset | Unnecessary, and the riskiest part of the draft. DbgEng exposes both as registers: `r ssp` and `r cetumsr` answer on an x64 target, and `dx @$curthread.Registers` lists a `CET` group beside `User`, `SIMD` and `FloatingPoint`. On x86 and ARM64 targets `r ssp` is `Bad register error` |
| `GetProcessMitigationPolicy` for `cet_state` | Unnecessary. `cetumsr` is the thread's own `IA32_U_CET`, whose bit 0 is `SH_STK_EN` — a per-thread answer that a dump carries and a process policy query cannot reach |

And three facts the draft did not have, which shaped the rest of the design:

1. **A zero pointer cannot be told from an unrecorded one.** Both x64 user dumps
   (`cppthrow-fastfail.dmp`, `stale-throw-abort.dmp`) carry an extended context —
   `ContextFlags 0x10005f`, 1,663 bytes, a `CONTEXT_EX` at `0x4d0` — whose XSTATE enabled-feature
   mask is **`0x7`** (x87, SSE, AVX): no `CET_U` was recorded at all (they were written by
   emulated x64 processes on the ARM64 bench). DbgEng still answers `ssp=0` and `cetumsr=0`, which
   is exactly what a thread with shadow stacks off reads as. So zero is reported as *no shadow
   stack to compare against*, never as *checked and clean* — the draft's §2.2 rule, which turns
   out to be needed against the register as well as against a context parse. `cdb` prints a
   "This target supports Hardware-enforced Stack Protection … `dps @ssp`" banner on this same dump
   whose pointer is zero, so the banner is no evidence either.
2. **A walk the engine guessed looks exactly like a spoofed one.** On `cppthrow-fastfail.dmp`
   the frames under `cppthrow+0x22989` are a stack address, `0x7ff700000003`, the image base and
   `0x80` — none preceded by a call, most in no module. The cause is the dump, not the target: the
   image is not on this host, so `.fnent` finds **no function entry** and the walker fell back to
   reading `[rsp]` as a return address frame after frame. `081226-2187-01.dmp` degrades the same
   way under `MessageManager+0x1654` (no PDB, no image, no entry, code unreadable), and the
   ARM64 `082126-7015-01.dmp` under `HEVD+0x10dc`. A detector
   that judged every frame would call three ordinary crash dumps spoofed. This is why the verdict
   model has a notion of *where the walk can still vouch for its frames* (§3.2), which the draft
   lacked entirely.
3. **The call-site test works on real stacks.** Every return address on the x64 kernel walk in
   `052126-34312-01.dmp` is preceded by `e8 rel32`, and the ARM64 ones in `082126-7015-01.dmp`
   by a `bl` word (`0x97fffcc4`, `0x940004f9`). The two that are not calls are explained by the
   frame above them: `nt!KiArm64ExceptionVectors`, whose unwind data carries ARM64's custom
   trap-frame code (`E8`), so the address below it is the interrupted PC rather than a return
   address.

## 3. The checks and the verdict

### 3.1 Per frame

Frame 0's address is where the thread is, not a return address, so only the module test applies
to it. Every deeper frame's address is the return address the frame above it was walked to, and
gets four readings:

| Field | Values | How |
|---|---|---|
| `reached_by` | `context`, `unwind_data`, `leaf_rule`, `inferred`, `beyond_walk` | §3.2 |
| `call_site` | `call`, `system_call`, `resumed_context`, `not_a_call`, `unreadable`, `not_decoded` | the up-to-15 bytes ending at the address (4 on ARM64), decoded at every start that would end exactly there; a `Flow::Call` of that length is a call. `syscall`/`sysenter`/`int 2eh`/`vmcall`/`svc` is a system call — asked before the flow, because iced files `SYSCALL` and the hypercalls under `FlowControl::Call` and dbgscope maps that to `Flow::Call`, which a unit test caught. `resumed_context` when the frame above is a kernel or `ntdll` `Ki*` routine — the exception, APC, callback and trap dispatchers, which resume a saved context rather than return |
| `shadow` | `matched` (with `shadow_slot`), `missing`, `not_checked` | §3.3 |
| `frame.module` / `attribution_failed` | as `backtrace` | a frame in no module is `unbacked_code`; a failed lookup is not a finding |

### 3.2 Where the walk can vouch for its frames

A frame was **walked** when the frame above it had unwind data and was itself walked: the
unwinder read this return address from the slot that data says holds it, so a planted value there
is the target's doing and a finding about the target. Frame 1 under a frame 0 with **no** unwind
entry is the one exception, `leaf_rule`: the x64 and ARM64 ABIs require unwind data of every
function that calls, so a frame 0 without it is a leaf whose return address is exactly at `[rsp]`
(in `lr` on ARM64) — a syscall stub, the commonest frame 0 on a live process — and the frame under
it is judged when it checks out. **That argument needs the absence to be real**, and the engine
answers "no entry" just as readily for an image it does not hold, so the rule applies only when
frame 0's image's `.pdata` reads; otherwise frame 1 is inferred.

A frame was **inferred** when the frame above had none — every frame of an x86 walk, which has no unwind tables, and any frame under an image the engine cannot read —
and the walker fell back to a heuristic. An inferred frame that checks out (preceded by a call or a
system call, or resumed from a dispatcher, and in a module) is accepted and the walk goes on; the
first one that does not is `walk_lost_at`, and it and everything under it are `beyond_walk` and
judged by nothing. That is the only reading of the three measured dumps that is not a false alarm,
and it is permanent on purpose: a garbage walk can produce a stale return address that checks out
by chance, and re-anchoring on it would turn the rest of the garbage back into evidence.

The cost is stated rather than hidden. A frame planted directly under one with no unwind data
reads as the walk being lost, so it is `unknown` rather than `suspicious`, and on x86 that is every
frame past the first. On a live x64 or ARM64 process, where every image is mapped and the
unwinder has `.pdata` for every compiled function, that case is a leaf stub at frame 0 and
nothing else.

### 3.3 The shadow stack

Read only on an x64 **user-mode** target, and only when `ssp` is non-zero **and** `cetumsr` has
`SH_STK_EN` set; every other case is `unavailable` with the reason as a value
(`no_register`, `kernel_target`, `pointer_zero`, `not_enabled`, `msr_unreadable`). The entries are
read upward from `ssp`, as many as the walk needs plus a margin, a page at a time; a read that
fails is `read_stopped: unreadable`, and an entry that is a shadow-stack **restore token** (its
value, flags masked, is its own address plus 8) ends the read with `read_stopped: token`, since
past it lies another stack.

Each frame the walk reached is then looked for, inferred ones included — the shadow stack vouches for a frame however the walker found it — from a cursor that only moves forward:

- found at the cursor — `matched`, slot recorded, cursor advances;
- found further on — `matched`, and the entries passed over are calls the CPU recorded that the
  walk does not show: `hidden_calls` on that frame;
- not found — `missing` when the shadow stack demonstrably went past it (a later frame matched, or
  the read reached its margin without stopping), `not_checked` when the read stopped first.

`resumed_context` and `system_call` frames are not looked for: the CPU pushes nothing for them,
which is what makes them not return addresses in the first place.

### 3.4 The verdict

- **`suspicious`** when a frame reached through its context, unwind data or the leaf rule has a
  finding:
  `unbacked_code`, `not_preceded_by_call`, `missing_from_shadow_stack` or `hidden_calls`. A
  positive finding stands on its own, whatever else could not be checked. Each one is listed in
  `findings` with its frame. JIT compilers put code in no module legitimately, and the text says so.
- **`consistent`** only when the shadow stack was compared, the walk was never lost or truncated,
  at least one frame matched, every return address matched or is exempt, and no shadow-stack
  entry was passed over. The hardware record is
  the only evidence strong enough to call a stack clean: a planted frame can be chosen to sit after
  a call, but it cannot be put on the shadow stack.
- **`unknown`** otherwise — which is the **common answer, by design**. Most targets have no shadow
  stack to read (every x86 and ARM64 target, every dump measured here, every x64 thread running
  without enforcement), and a frame the walker guessed is no evidence either way.

## 4. Public interface

One tool, in the `inspect` group, beside `backtrace`:

```text
stack_lineage
  frames     : integer | null   (default 32, maximum 256 — backtrace's cap and default)
  session_id : string | null    (as every routed tool)
```

`read_only_hint`, `open_world_hint`, output schema `constraints_of::<Outcome<structured::StackLineage>>()`.
It walks the session's current thread, exactly as `backtrace` does; thread selection is a
follow-up rather than a second argument shape here.

```text
StackLineage {
  verdict        : consistent | suspicious | unknown
  frames         : [ { frame: FrameInfo, reached_by, call_site, shadow, shadow_slot? } ]
                   reached_by: context | unwind_data | leaf_rule | inferred | beyond_walk
  frames_truncated
  walk_lost_at?  : u32
  shadow_stack   : { status: compared | unavailable | unreadable, unavailable?, pointer?,
                     cet_msr?, entries_read, read_stopped?, skipped_entries }
  findings       : [ { frame: u32, kind: unbacked_code | not_preceded_by_call
                                       | missing_from_shadow_stack | hidden_calls } ]
}
```

**One tool, not a flag on `backtrace` as well.** The draft's §9.4 weighed a `lineage: bool` on
`backtrace` against a tool. A flag would put the verdict model into `StackTrace`, which
`crash_triage` shares through `FrameInfo` and every caller's schema would grow by, and it would
hide the capability behind an argument of a tool whose description is about something else. The
cost of the tool is its description and schema on every surface that serves `inspect`; the figures
are in `docs/tool-surface.md` and `docs/token-budget.md`, re-derived by
`every_documented_surface_figure_matches_the_served_surface` rather than quoted here.

**`stack_lineage`, not `shadow_lineage`.** The shadow stack is one of four checks, and the one
that is unavailable on most targets; naming the tool after it would describe the case it usually
cannot answer.

## 5. Implementation

- **`src/lineage.rs`** — the engine-free core. `judge` takes what the worker observed (frames,
  their attribution, unwind presence and preceding instruction; the shadow stack's entries or why
  there are none) and returns `structured::StackLineage`; `preceding` classifies the bytes before
  an address; `shadow_entries` splits a read into entries and stops at a token; `render` writes the
  listing from the same values. Pure, so every rule in §3 is a unit test on synthetic input.
- **`src/structured.rs`** — the result types beside `StackTrace`.
- **`src/proto.rs`** — `EngineOp::StackLineage { frames }`. Unbounded, for `Backtrace`'s reason:
  direct engine calls with nothing that can stop one, and the reads are a few bytes per frame plus
  at most a few KiB of shadow stack.
- **`src/worker.rs`** — `stack_lineage`: the same `walk_attributed` as `backtrace`, then per frame
  `function_extent` and the preceding bytes, then the two registers and the shadow read, then
  `lineage::judge`. All on the engine thread; no new cross-thread call.
- **`src/server.rs`** / **`src/toolset.rs`** — the tool, in `inspect`.
- **Refusal on Secure Kernel sessions needs no code**: `engine::refuse_op_on_kind` is an
  allow-list, so an op nobody added to a Secure Kernel kind is refused there by construction. A
  unit test pins it.

## 6. Validation

### 6.1 What the bench establishes

- **The pure core** (`cargo test`): every row of §3 on synthetic frames — a matched chain is
  `consistent`; a planted frame with no shadow entry is `missing_from_shadow_stack`; skipped
  entries are `hidden_calls`; a dispatcher's frame is exempt; a zero pointer is `unknown` and never
  `consistent`; a walk lost under a frame with no unwind data judges nothing beneath it; a token
  and an unreadable page stop the read and leave later frames `not_checked`; a lone frame is never
  a vacuous `consistent`.
- **The call-site decoder** on real encodings: the `e8 rel32` and `bl` words measured above, an
  `ff 15` import call, a `syscall`, and bytes that end in no call.
- **Real stacks, end to end** (`WINDBG_MCP_SMOKE_DUMP=1`, the dump tier): every checked-in sample
  answers and none is `consistent` (none has a shadow stack). The clean x64 and ARM64 kernel walks
  are judged frame by frame with every return address a `call` or explained; the three walks that
  degrade under a missing image report `walk_lost_at` there instead of findings. Exactly one sample
  is `suspicious`, and for the right reason: `121524-4703-01.dmp` is a `0xFC` whose trapped PC,
  under `nt!KiArm64ExceptionVectors`, is in user memory no module holds — the CPU really was
  executing there. The x64 user dumps report `pointer_zero`, the x64 kernel ones `kernel_target`,
  the ARM64 and x86 ones `no_register`.

### 6.2 What it cannot

**The positive shadow-stack path has not run against a real CET target**, because no machine on
this bench has one: the debugger guest is ARM64, the x64 dumps here were written under emulation
with `CET_U` absent from their feature mask, and x64 emulation on ARM64 exposes no shadow stacks.
What is unmeasured is therefore specific: that a CET-enforced thread's `ssp` and `cetumsr` read
back non-zero through `integer_register` on a live process and on a dump that recorded `CET_U`;
that its shadow-stack pages read through `read_memory`; and that a real stack matches slot for
slot, including through `KiUserExceptionDispatcher`. The rules are unit-tested; the claim that they
describe Windows is not yet a measurement. `FOLLOWUPS.md` carries it, with the fixture it needs:
a small x64 program with a control arm (ordinary nested calls, expected `consistent`) and a planted
arm (a return address pushed with no call, paused before it returns, expected `suspicious` with
`missing_from_shadow_stack` on that frame), run on an x64 host with hardware-enforced stack
protection on. It is a detector's ground truth — a paused, disposable process the tool observes —
and not an evasion technique.

## 7. Correctness traps

- **Zero is not clean.** `ssp == 0` is `pointer_zero` → `unknown`, for the reason in §2.
- **A guessed frame is not evidence.** §3.2. The regression to watch for is a change that judges
  `beyond_walk` frames, which turns every dump with a missing image into a spoofing report.
- **A positive finding is not cancelled by missing evidence**, and missing evidence does not
  become a finding. `suspicious` and `unknown` are separate verdicts for that reason.
- **The `ssp` register and the walk must describe one context.** Both are read from the session's
  current thread; a raw `.cxr` through `execute` moves the register scope and not the walk
  (`dbgscope::DebugEngine::stack_frames_from`'s measurement), so after one the two can disagree.
- **`resumed_context` is a curated rule** (`Ki*` routines of `nt` and `ntdll`), not a reading of
  unwind codes. A dispatcher it misses makes the frame under it `not_preceded_by_call`, with the
  frame above named in the text. Reading `UWOP_PUSH_MACHFRAME` / ARM64's trap-frame codes would
  replace the rule with a fact and needs a dbgscope primitive for the raw unwind record; that is a
  follow-up.

## 8. Delivery

One change: `src/lineage.rs` with its tests, the result types, the op, the tool, the group entry,
the golden surface and the documented figures, a `mcp_smoke` dump-tier test over every sample, the
runbook entry in `docs/smoke-test.md`, and the `FOLLOWUPS.md` items for §6.2 and §7's last point.

## 9. Decision: analysis, not evasion

The capability is a lineage *judge*, not a spoof *engine*, by the reasoning in §1.1. A debugger
cannot spoof its own execution, and both the architecture (observation) and the project's ethos
(an answer that looks like one must not be one) point the same way. The fixture in §6.2 is a
detection test target and not a bypass. This is recorded so the intent is unambiguous to a
reviewer and so a future contributor does not read the detector's knowledge of the techniques as
a route to building them.
