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
| `modules` | `modules[]` with `start`/`end`, `size`, `timestamp` (the `TimeDateStamp`+`size` pair a symbol server is keyed by — see [`coordinates.md`](coordinates.md)), a typed `symbols` state (`deferred` is *not* `none`) and, for a module whose symbols resolved, the `pdb` identity (`guid`, `age`, and the `key` those two make) plus `unmatched` when the engine loaded a PDB that does not belong to the image; `unloaded[]` for the images that have since unloaded (listed by image name, since an unloaded module has none of its own); `loaded` (how many the target has in total), `matched` / `unloaded_matched` (how many each half would have had before `limit` cut it — default 64 rows for the whole listing, maximum 2000, the two halves sharing one budget so neither crowds the other out) and the `filter` a narrowed listing was matched by. The listing text is rendered from these same records rather than pasted from `lm`, so the two halves cannot describe different sets of modules; the filter's grammar is this server's own — a name plus `*` (any run) and `?` (exactly one), **every other character literal** — and `execute { "command": "lm m <pattern>" }` is where WinDbg's fuller wildcard syntax lives. `refresh: true` resynchronises the debugger's inventory with the target before the listing is taken and reports what that did as `refresh` — `synchronized`, the `before` count against `loaded` after it, and the engine's `error` where it failed, which is reported rather than raised because the stale listing under it may still be the right one. Absent when no refresh was asked for, which is not the same as one that found nothing. **Inventory, not symbols**: see [the two reloads](#inventory-refresh-against-symbol-reload) |
| `set_breakpoint`, `ioctl_trace` | `breakpoint` — the one this call set, **as the engine reports it**: its `id`, where it will fire, whether it is `deferred`, and the `command` it runs on each hit. Plus `replaced`, the ids of breakpoints removed to make room at the same address (what `bp` does, and what was a `breakpoint N redefined` line in debugger text before); `breakpoints`, the session's whole list, a best-effort inspection that is empty if it could not be read; and `cut_short`, meaning resolving the **location** was interrupted — the watchdog broke in while a symbol was being fetched, or somebody called `interrupt`. The breakpoint exists either way, which is why `cut_short` is a success rather than an error: an error is the shape a caller retries, and a retry sets a second breakpoint. Read `deferred` to see whether the location resolved. Before dbgscope#126 this was an `added` list recovered by diffing `bl` either side of a `bp`, with two more fields (`listed`, `listing_error`) whose whole job was to say the diff might be unavailable and an empty `added` therefore unknown; the engine hands back the breakpoint it created, so none of that arises |
| `run_to_address` | `verdict` (`hit`/`stopped_elsewhere`/`timeout`/`target_gone`), `target`, `stopped_at` |
| `go`, `step_over`, `step_into`, `step_back`, `step_over_back`, `reverse_go` | `stopped_at`, and the `thread` it belongs to plus, on a kernel target, the `processor` — absent where no processor number applies (every user-mode target, which is not a failure) or where the engine would not answer, one field because a caller cannot act on the difference. Plus `interrupted` and `timed_out` — two reasons the position is real and is *not* a stop the target reached: somebody called `interrupt`, or the wait ran out and the debugger broke the target in — and `target_gone`, the ending where there is no position at all because the target ran to completion |
| `continue_async` | `execution` (the handle), `command`, `running` (moving *now*), `moved` (it went at all) and `breaks_in_ms`, when the debugger will break the target in itself. Both bools are false where the command completed without ever setting the target going; `moved` alone is true where the run reached its stop before this answered, which a breakpoint one instruction away does routinely. Either way the stop is already recorded against the handle |
| `wait_for_stop` | `running_for_ms`, and `stop` — the same record `go` answers with. **Absent means the target is still running**: this wait ran out, not the run, and nothing was cancelled or consumed. `breaks_in_ms` is then how much of the run's bound is left |
| `break_in` | `requested`, whether that run is not going to keep the target moving — a break raised, one already lodged, a run barred from starting, or one that finished on its way here. `false` means it had already stopped when the call looked, which is the ordinary race and not a failure, while a break that could not be *delivered* is an error rather than a `false`. Plus the debugger's own `detail` |
| `pool_find_tag`, `pool_chunk`, `pool_census`, `pool_diagnostics` | the chunks/totals/diagnostics as values, each carrying the `walk` behind them |
| `heap_list`, `heap_allocations`, `heap_chunk`, `heap_census`, `heap_diagnostics` | PEB heap roots and Segment Heap allocations/totals/diagnostics, each carrying exact `ntdll` layout provenance, skipped-heap scope, and walk coverage |
| `walk_memory` | `nodes[]` with each field's `value` — `null` where the debugger could not read it — plus `walked`/`unreadable` counts and a `stopped` reason (`complete`, `cap`, `null_link`, `loop`, `unreadable_link`, `deadline`, `interrupted`), each carrying the address it is about |
| `disassemble` | `instructions[]` in address order, each `{address, module, rva, bytes, text}` — `module`+`rva` travel together and are **absent when the address is in no loaded module**, with `attribution_failed` marking the different case of a lookup that failed; `address` and `bytes` are always there. Plus `start`, the call's `address` after the debugger evaluated it, and `stopped_early`, which means the code ran out before the count rather than the call being truncated. `bytes` is the engine's spelling of the encoding, which is what says whether a disassembler holds the same build |
| `backtrace` | `frames[]` as `{index, address, module, rva, symbol, displacement}`, innermost first, plus `frames_truncated` — whether the stack went on past the call's `frames` cap (32 by default, 256 at most). `address` is always there; `module`+`rva` travel together and are **absent when the engine places the address in no loaded module** (a freed pool page, an unloaded driver), and `symbol`+`displacement` are absent when nothing resolves, which is the ordinary case for a driver with no PDB. A frame whose module *lookup failed* — a different fact from being in no module, and the opposite kind of evidence — carries `attribution_failed: true`. The same records `crash_triage` reports, from the same walk |
| `crash_triage` | `bug_check` (`code`, `name`, four `parameters`), `process_name`, `frames[]` as `{module, rva, symbol}` — see `backtrace` above for when each is absent — the `faulting_frame` picked out of them, and `!analyze`'s own conclusions kept apart under `analysis` |
| `reachable_from_dispatch` | `verdict` (`reachable`/`not_reachable`), and the walk's own bounds beside it. Every address is a `{address, module, rva}` location -- `module`+`rva` travel together and are absent when the address is in no loaded image, `attribution_failed` marking the different case of a lookup that failed -- and `images[]` carries each named module's `image_name` and `identity` **once**, rather than repeating 150-odd bytes of GUID, timestamp and size on every address of a path. `from`, `target` and, on a `reachable` verdict, `containing_function` and a `path[]` of `{site, kind, callee}` hops. `started_at` appears **only when the walk began somewhere other than the function's entry** -- a `from` naming a handler inside a dispatch routine scopes the walk past the switch, and the verdict depends on that: from one case block a sibling case is not reachable, so an answer re-run from the entry would explore what this one excluded. Its presence is the statement that scoping happened. Plus `recipe[]`, one segment per function on the path with a `steps[]` of `{site, jcc, required, predicate}` -- the branch decisions that keep control on the path, where `predicate` decodes the compare feeding each branch and its `field` is a heuristic read of a displacement rather than a structure. A segment carrying `gates_unknown` is one whose branches could **not** be recovered -- its `steps` is an unknown list rather than a short one, so an empty one there does not mean control reaches the goal unconditionally, and a caller generating input must treat that segment as disqualifying. The verdict is **not** a boolean: `reachable` is sound, and `not_reachable` has three independent reasons it may be incomplete, each with its own remedy -- `bound_hit` (raise `max_functions`/`max_depth`), `stopped` (`deadline`/`interrupted`), and `blind_stops`, instructions whose bytes would not read or whose encoding this build does not decode. `recipe_stopped` is separate from `stopped` because the two passes are bounded separately, and a recipe missing its last segment is a prefix rather than a shorter whole |
| `ioctl_map` | `cases[]` as `{code, device_type, function, method, required_access, dispatch_rva, case_rva, in_size, out_size, recovered, at, evidence[]}` -- the control codes the dispatch routine accepts, each decoded from its own bits, with `at` the `{address, module, rva}` location of the compare or jump that recognises it and `case_rva` the block it routes to. The field names are the **shared IOCTL-case shape** a Binary Ninja or Ghidra companion answers in (`docs/binja-windbg-mcp-plan.md`), so the same driver recovered on either side is the same record. `recovered` says how: `compare` for a compare against the code, `jump_table` for an entry in a switch table that was resolved -- and a table is followed only when its bounds check **and** its base were both recovered, never at a guessed length. A case per **site**: one code compared in two places is two records. `in_size` and `out_size` are proven exact lengths or absent, and never a floor -- a `cmp [sp+10h],20h` / `jb` proves a minimum and proves nothing about the size, so it is in `evidence[]` as a `{field, value, exact, at}` check instead. `tables[]` records each switch table that was followed, where `followed` is how many of its `entries` became cases -- the difference is the slots that go to the switch's default, which a dense table has one of for every index it has no case for. `unresolved[]` lists the indirect transfers that were **not** followed, which is what stops a short list reading as a complete one: with entries there the map is a lower bound on what the driver accepts. Each case carries `accepted`, which is what the compare and the branch do **not** say: `cmp code,N` / `je invalid_request` is the same shape as `je handler`, so a list reporting both as accepted sends a reader to test a code the driver refuses. It is `false` for a landing block that sets an NTSTATUS error and returns -- the ordinary rejection stores that status into the IRP and calls a completion routine on its way out, so a call alone is never read as acceptance -- `true` for a block that reaches a routine with no rejection visible in it, and absent where neither is. `in_size` and `out_size` need the same evidence: an exact size is a check whose *other* edge fails, since `cmp length,20h` / `jne handler` requires nothing. Each case also carries `proved`, which says whether the value it tested was traced from the IRP (`[[Irp+0xb8]+0x18]`) or taken from a bare displacement, and `code_proved` is every case together rather than any one load -- a routine that compares some other structure's `+0x18` field before reading the real control code has one of each, and the guessed one is exactly the case a reader needs warning about. The offsets themselves follow the target's bitness: `+0xb8`/`+0x18` on x64, `+0x60`/`+0x0c` on x86, where both arguments arrive on the stack so nothing is proved. `blind` counts instructions that could not be read or decoded, each a place a compare may be. What an empty `cases` means turns on `code_proved` -- one says the routine compares the code against nothing this could follow, the other that these compares may be about another structure entirely. `stopped` and `cap_hit` say why a list ended early; `case_count` stays exact |
| `driver_hazards` | `sinks[]` as `{library, name, kind, slots[], call_sites[]}` -- the sensitive APIs the driver imports, each with the import-table slot a call goes through (a list, and one in every real image -- more means the table repeats a name, which a crafted one can do) and the `{address, module, rva}` locations that reach it. A call site is matched **by that slot**, never by a name, which is why this answers on a driver with no symbols; a tail `jmp` through the slot counts as one and a `mov` that merely loads it does not. Plus `privileged[]` as `{at, kind, mnemonic}` for `rdmsr`, `out`, `mov cr3` and their families -- membership is the **decoder's** answer rather than a list of mnemonics, so `cli`, `clts` and the virtualisation families are in it too, and `kind` only names the family (`other` for one no family names, with the mnemonic beside it). Which family a `mov` is in is decided by its operands rather than by its rendering. `call_site_count` is exact however many sites are listed, since both lists are bounded and a capped list reported as a count would turn a driver that calls an allocator six hundred times into one that calls it two hundred and fifty-six; `privileged_count` is the same for the instructions. `scanned[]` says which executable ranges were decoded, one entry per contiguous run so a hole is visible, and `unreadable[]` says which were **not** -- bytes that would not read, and any part of a section whose declared span ran past the image. That last one is what qualifies an empty `privileged`: without it a dump missing one page reports a driver with no privileged instructions and nothing says a page was missing. `other_imports` counts the imports that are not on the list, and `unnamed_libraries` names the bound imports whose names live only in the table this never reads. `stopped` and `cap_hit` say why a scan ended early. **Evidence, not a verdict**, and three ways to misread it: an import is not a call, an absent import excludes nothing since a driver can resolve an export at run time, and a call site is not a reachable one. `sink_list_version` is here because what counts as sensitive is a curated judgement -- a result quoted later can be checked against the list that produced it |
| `debug_batch` | `outcome` (`committed`/`failed`/`timed_out`/`abandoned`/`interrupted`/`target_gone`), the position it stopped `at`, `committed`, `rollback_complete`, what the session holds `after` (`stopped`/`running`/`detached`/`ended`/`uncertain`), and every step of both blocks with what it `changed`, whether an assertion was `unmet`, and whether it was the step that ended the target |

Two conventions hold across all of them:

- **One address representation.** Every address, and every register-sized value, is a `0x`-prefixed,
  lowercase, 16-digit zero-padded hex **string** — `"0xfffff8031ab10000"`. A string because a `u64`
  past 2^53 does not survive a JSON parser that reads numbers as doubles; zero-padded so lexical
  order matches numeric order. The debugger's backtick form (``fffff803`1ab10000``) appears only in
  the text.
- **An allocator answer says what the walk covered.** `walk.coverage` is `complete`,
  `deadline_truncated` (the call's budget ran out — more time reaches more of the allocator),
  `partial` (unreadable regions or a traversal cap — more time changes nothing), or
  `match_limit_reached` (`pool_find_tag` deliberately stopped at the nonzero
  `walk.stop_after_matches` threshold). Counts from anything but `complete` are floors, not totals.
  A walk that failed outright, or was stopped by `interrupt`, is not a coverage state at all: it is
  the error branch below, with category `debugger` or `interrupted`.

For `pool_find_tag`, `stop_after_matches` and `limit` answer different questions. The first bounds
a newly started walk and therefore makes its result intentionally partial; the second only caps
the `chunks` rendered after the walk and never changes `matches` or `total_bytes`. If the session
already holds a complete cached snapshot, it is reused and the answer remains exhaustive even when
`stop_after_matches` was supplied.

One caveat about "also", measured rather than assumed: a client that understands
`structuredContent` generally forwards **it** to the model and drops the text block, rather than
sending both. So for the tools above, the typed answer is what a model reads and the rendering is
what a program-with-a-terminal reads — they are two audiences, not one audience twice.
[`token-budget.md`](token-budget.md) has the measurements, and what they cost.

## Inventory refresh against symbol reload

Two different things that have been reached through one command for as long as this server has
existed, and telling them apart is what `modules { "refresh": true }` is for
([#85](https://github.com/glslang/windbg-mcp/issues/85)).

**The inventory** is DbgEng's list of the modules it knows the target has loaded. It is built from
the module-load events the debugger *saw*, so it is complete for a dump (which carries its own
list) and for a process the debugger launched, and it is emphatically not complete for a live
kernel: an attach starts from what it can read at connect time, and a driver loaded before the
debugger dialled in is in the target and missing from the list. A `modules` call there answers
`nt` and little else, and "the driver is not loaded" is the conclusion a caller draws from it.

**A symbol reload** is the separate business of getting a PDB in front of the engine so
`module!Symbol` names resolve. It is what `set_symbol_path` does, and what `.reload /f` does.

They have been confused because `.reload /f` does both: forcing every module's symbols also
resynchronises the inventory, so a caller who ran one got the right module list as a side effect of
a symbol-server download it may not have wanted. `refresh` is the inventory half on its own:

| | `modules { "refresh": true }` | `set_symbol_path`, `.reload /f` |
|---|---|---|
| Finds a module the engine has not heard of | yes | yes, incidentally |
| Fetches PDBs | **no** — what it discovers is `deferred` | yes, one per module |
| Costs a symbol-server round trip | no | yes, per module |
| Effect on symbols already loaded | on a **live** target, discards them | loads them |

The last row is the one to plan around, and it is **live-target only**: on a live target a refresh
throws away the symbol state the engine was holding and reloads it as needed, so **refresh first
and load symbols afterwards** — doing it the other way round undoes the reload you just paid for.
A dump pays none of it. Measured both ways on one host, with the engine's `symsrv.dll` and
`msdia140.dll` bundled and a store configured:

| target | before the refresh | after it |
|---|---|---|
| launched `cmd.exe`, 5 modules, after `.reload /f` | all five `pdb` | `ntdll` still `pdb`, the other four `deferred` |
| the checked-in kernel dump, 227 modules | `nt` `pdb`, 226 `deferred` | unchanged — nothing discarded |

Which fits what the reload is: on a live target it re-reads the module list and the entries are
rebuilt, while a dump's list comes from its own header and there is nothing to re-read. So the note
beside a listing says *on a live target*, and it says *most* modules rather than all of them.

That distinction cost a measurement to find. The first attempt was made on a host whose engine had
no `symsrv.dll` or `msdia140.dll`, where the same five modules could only reach `export` fallback —
so the effect looked like a fallback being reset rather than real PDB state being dropped, and the
dump half was never asked at all.

A refresh that **fails** is reported in the `refresh` field and does not fail the call — the
listing beside it may well be the right one, and a caller can see for itself. What it must not do
is pass unnoticed, so the text says so *above* the tables rather than in the note below them: a
caveat printed under a listing arrives after the conclusion it was there to prevent.

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

## Binary Ninja bridge contracts

`current_location` and `read_memory` use the existing `status: "ok"` / `status: "error"`
outcome and typed error categories. Their text remains available to ordinary MCP hosts.

A successful `current_location` contains `location_state`, nullable `address`, `thread`,
`processor`, and `coordinate`. A missing execution context differs from a valid instruction
pointer outside all loaded images, and both differ from a failed module-attribution call.
Coordinates follow [the shared PE coordinate contract](coordinates.md#guarded-bridge-coordinates).

A successful `read_memory` contains `address`, `requested_size`, `read_size`, and `data`.
`data` is lowercase hexadecimal in memory byte order, two characters per byte actually read.
`read_size < requested_size` explicitly identifies a partial read. The existing allocation
bound still applies; address ranges must not overflow. Batch reads share the same helper
and continue to embed its text in the batch report.
