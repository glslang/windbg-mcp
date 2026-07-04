# Follow-ups

Deferred work from the reachability-confirmation effort (path recipe + `run_to_address`, merged
2026-07-04). Each item notes its repo, why it was deferred, and where it picks up. See
[`DECISIONS.md`](./DECISIONS.md) for the design rationale (D1–D5) these extend.

Items are roughly ordered by how soon they're worth doing.

## 1. [win-kexp] Managed breakpoint lifecycle for `run_to_address`

`run_to_address` uses a one-shot `g <addr>` (WinDbg's temporary breakpoint), which DbgEng does **not**
hand back a handle for. On a non-live timeout the target is now broken in (SetInterrupt + WaitForEvent),
but the one-shot breakpoint at `address` can remain armed. Replace `g <addr>` with an explicitly
managed `AddBreakpoint2` + `RemoveBreakpoint` lifecycle so the breakpoint is cleaned up deterministically
in **all** exit paths (hit, stopped-elsewhere, timeout, error).

- **Why deferred:** the interrupt + breakpoint-teardown semantics need a live KDNET/VM kernel target to
  validate; landing it blind risks a worse regression (hang, or clearing the caller's breakpoints).
- **Picks up from:** win-kexp PR #62 review thread on `src/dbgeng.rs` (`run_to_address`, the `Timeout`
  branch). A stale one-shot at `address` is currently harmless to this API's own flow (a later
  `run_to`/`go` arms its own), so it is low-severity until an explicit rewrite is validated on hardware.

## 2. [win-kexp] Typed write primitives

`write_virtual`, a typed register **write**, and `ba` (data) breakpoints. Today only the `execute` raw
text path exists (`eb`/`ed`/`r reg=`).

- **Why deferred:** primarily needed by the state-injection path (item 3); no consumer without it.
- **Note:** win-kexp is the right home for these (DECISIONS.md D3 — typed `DebugEngine` methods, not the
  text hatch), mirroring how `run_to_address`/`instruction_pointer` were added.

## 3. [windbg-mcp + win-kexp] State-injection confirmation path (DECISIONS.md D4)

Alternative to driving a real IOCTL client: break at the dispatch entry, craft an IRP +
IO_STACK_LOCATION + SystemBuffer in memory, set `rcx`/`rdx`, and run to the target block.

- **Why deferred:** a wrong/partial IRP mutates live kernel state and can bugcheck the target,
  destroying the reproducible state the analysis depends on. Deprioritized behind the drive-a-client
  path (`ioctl_harness.ps1` + `run_to_address`).
- **Depends on:** item 2 (typed write primitives) and the item-1 breakpoint work; the same path-recipe
  data the drive path uses. Prefer a snapshot-restorable VM when building it.

## 4. [win-kexp] Typed `read_register`

Generalize the private `instruction_pointer` helper (added for `run_to_address`) into a public typed
register read, per DECISIONS.md D5 step 1. Only the instruction pointer is implemented today.

## 5. [windbg-mcp] Path-recipe decode limits (heuristic boundary)

The operand → IO_STACK_LOCATION field mapping (`+0x18`/`+0x10`/`+0x08`) is heuristic: it holds only
when the compare's memory base is the current stack-location pointer, and complex predicates
(multi-instruction conditions, computed offsets, table lookups) aren't decoded. This is the documented
boundary where item 6 would take over.

## 6. [windbg-mcp] Concolic/symbolic buffer synthesis (DECISIONS.md L3 — scoped out)

Auto-emit a concrete `(code, buffer, lengths)` by SMT-solving the on-path branch predicates, rather
than the human/LLM-readable recipe emitted today.

- **Status:** scoped **out** of the current effort. If ever needed, offload to angr/Triton over a
  debugger memory snapshot rather than building an in-house solver — kernel state modeling, loops,
  hashing, and stateful protocols make it brittle and a separate project.
