# Architecture Decisions

Decision log for windbg-mcp. Newest first. Each entry records the decision, the reasoning, and its
status. Keep entries short; link to code with `file:line` where it helps a future reader.

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
