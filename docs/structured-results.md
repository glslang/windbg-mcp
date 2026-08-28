# Structured results

Every tool returns the same readable text it always has. The tools below **also** return MCP
[`structuredContent`](https://modelcontextprotocol.io/specification/2025-06-18/server/tools), with a
matching `outputSchema` in `tools/list`, so a program can read a field instead of parsing prose:

| Tool | Typed answer |
|------|--------------|
| `open_dump`, `open_trace`, `attach_kernel`, `attach_kernel_local`, `attach_process`, `launch` | `session_id`, `kind`, `target`, `report`, and a `summary` of the target — `kernel_mode`, `modules_loaded`, the `primary_module` (the kernel, or the process's own image) and, for a crash dump, the `bug_check`. A `limitation` appears only when this session cannot do something a caller would otherwise assume it can — today, a 32-bit user-mode target (a dump, or a WoW64 process reached with `attach_process`) opened where no 32-bit worker was available, so its .NET SOS extension is unreachable. On failure, whether a target was created (`target: no \| yes \| pending`), which is what decides whether opening again is a recovery or a second attach |
| `session_status` | each session's `state` (`opening`/`attaching`/`open`/`failed`/`retired`/`closed`), `engine_pid`, `in_state_for_ms`, and — for an attach — `waits_indefinitely` and `overdue` |
| `server_log` | `records[]` as `{seq, at, level, session_id, target, message}` — `session_id` absent for the supervisor's own — plus `matched`, the buffer's `held`/`capacity`/`oldest_seq`, and a `next_since` cursor that advances even on an empty page |
| `end_session` | `released`, `worker_terminated`, `waited_ms`, `target_left_running` |
| `registers` | `registers[]` as `{name, kind, …}` plus `instruction_pointer` — `kind: int` and `kind: float` carry `value`, `kind: bytes` carries `bytes` (an x87 or vector register, which no number holds), `kind: non_finite` names a NaN or infinity that JSON has no literal for and carries its bits, `kind: unavailable` carries neither, and `subregister` is present only when true; pass `all: true` for the x87/vector registers and subregister views, which the default excludes — including the vector bank's 32-bit lanes (`xmm0/0`), which the engine reports as integers — a value's `kind` is how this server saw it, not the register's architectural width |
| `modules` | `modules[]` with `start`/`end`, `size`, `timestamp` (the `TimeDateStamp`+`size` pair a symbol server is keyed by — see [`coordinates.md`](coordinates.md)), a typed `symbols` state (`deferred` is *not* `none`) and, for a module whose symbols resolved, the `pdb` identity (`guid`, `age`, and the `key` those two make) plus `unmatched` when the engine loaded a PDB that does not belong to the image; `unloaded[]` for the images that have since unloaded (listed by image name, since an unloaded module has none of its own); `loaded` (how many the target has in total), `matched` / `unloaded_matched` (how many each half would have had before `limit` cut it — default 64 rows for the whole listing, maximum 2000, the two halves sharing one budget so neither crowds the other out) and the `filter` a narrowed listing was matched by. The listing text is rendered from these same records rather than pasted from `lm`, so the two halves cannot describe different sets of modules; the filter's grammar is this server's own — a name plus `*` (any run) and `?` (exactly one), **every other character literal** — and `execute { "command": "lm m <pattern>" }` is where WinDbg's fuller wildcard syntax lives |
| `set_breakpoint` | the ids this call `added`, and every breakpoint now set — a successful `bp` prints nothing at all |
| `run_to_address` | `verdict` (`hit`/`stopped_elsewhere`/`timeout`/`target_gone`), `target`, `stopped_at` |
| `go`, `step_over`, `step_into`, `step_back`, `step_over_back`, `reverse_go` | `stopped_at`, plus `interrupted` and `timed_out` — two reasons the position is real and is *not* a stop the target reached: somebody called `interrupt`, or the wait ran out and the debugger broke the target in — and `target_gone`, the ending where there is no position at all because the target ran to completion |
| `pool_find_tag`, `pool_chunk`, `pool_census`, `pool_diagnostics` | the chunks/totals/diagnostics as values, each carrying the `walk` behind them |
| `heap_list`, `heap_allocations`, `heap_chunk`, `heap_census`, `heap_diagnostics` | PEB heap roots and Segment Heap allocations/totals/diagnostics, each carrying exact `ntdll` layout provenance, skipped-heap scope, and walk coverage |
| `walk_memory` | `nodes[]` with each field's `value` — `null` where the debugger could not read it — plus `walked`/`unreadable` counts and a `stopped` reason (`complete`, `cap`, `null_link`, `loop`, `unreadable_link`, `deadline`, `interrupted`), each carrying the address it is about |
| `disassemble` | `instructions[]` in address order, each `{address, module, rva, bytes, text}` — `module`+`rva` travel together and are **absent when the address is in no loaded module**, with `attribution_failed` marking the different case of a lookup that failed; `address` and `bytes` are always there. Plus `start`, the call's `address` after the debugger evaluated it, and `stopped_early`, which means the code ran out before the count rather than the call being truncated. `bytes` is the engine's spelling of the encoding, which is what says whether a disassembler holds the same build |
| `backtrace` | `frames[]` as `{index, address, module, rva, symbol, displacement}`, innermost first, plus `frames_truncated` — whether the stack went on past the call's `frames` cap (32 by default, 256 at most). `address` is always there; `module`+`rva` travel together and are **absent when the engine places the address in no loaded module** (a freed pool page, an unloaded driver), and `symbol`+`displacement` are absent when nothing resolves, which is the ordinary case for a driver with no PDB. A frame whose module *lookup failed* — a different fact from being in no module, and the opposite kind of evidence — carries `attribution_failed: true`. The same records `crash_triage` reports, from the same walk |
| `crash_triage` | `bug_check` (`code`, `name`, four `parameters`), `process_name`, `frames[]` as `{module, rva, symbol}` — see `backtrace` above for when each is absent — the `faulting_frame` picked out of them, and `!analyze`'s own conclusions kept apart under `analysis` |
| `debug_batch` | `outcome` (`committed`/`failed`/`timed_out`/`abandoned`/`interrupted`/`target_gone`), the position it stopped `at`, `committed`, `rollback_complete`, what the session holds `after` (`stopped`/`running`/`detached`/`ended`/`uncertain`), and every step of both blocks with what it `changed`, whether an assertion was `unmet`, and whether it was the step that ended the target |

Two conventions hold across all of them:

- **One address representation.** Every address, and every register-sized value, is a `0x`-prefixed,
  lowercase, 16-digit zero-padded hex **string** — `"0xfffff8031ab10000"`. A string because a `u64`
  past 2^53 does not survive a JSON parser that reads numbers as doubles; zero-padded so lexical
  order matches numeric order. The debugger's backtick form (``fffff803`1ab10000``) appears only in
  the text.
- **An allocator answer says what the walk covered.** `walk.coverage` is `complete`, `deadline_truncated`
  (the call's budget ran out — more time reaches more of the allocator) or `partial` (unreadable regions
  or a traversal cap — more time changes nothing). Counts from anything but `complete` are floors,
  not totals. A walk that failed outright, or was stopped by `interrupt`, is not a coverage state at
  all: it is the error branch below, with category `debugger` or `interrupted`.

One caveat about "also", measured rather than assumed: a client that understands
`structuredContent` generally forwards **it** to the model and drops the text block, rather than
sending both. So for the tools above, the typed answer is what a model reads and the rendering is
what a program-with-a-terminal reads — they are two audiences, not one audience twice.
[`token-budget.md`](token-budget.md) has the measurements, and what they cost.

## Error reporting

Anything scoped to a session comes back as a normal tool result with `isError: true` and the text
intact, so the model can read it and correct itself: a failed *debugger operation* (an unresolvable
symbol, an unreadable address, a target that never stopped), a refused handle, a timeout, a session
whose worker is gone. Each has a next move. The only JSON-RPC protocol error is the one failure that
is the server's rather than a session's — no engine worker could be started at all.

For the tools listed above, a failure also carries structured content — the `error` branch of the
same output schema — so a caller can branch on a stable category instead of on wording:
`invalid_argument`, `debugger`, `timeout`, `interrupted`, `not_run` (the work never started, so
nothing changed — unlike `timeout`, where it may still be running), `stale_session`, `worker_lost`,
`capacity`. Both branches carry a `status` discriminator (`"ok"` / `"error"`), which is what lets one
schema describe a result whichever way it went.
