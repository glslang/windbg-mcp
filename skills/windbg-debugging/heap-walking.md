# Kernel pool and user Segment Heap walking

Use the typed allocator tools when the question is about allocator state, chunk ownership,
neighbours, or aggregate usage. They resolve the exact loaded module's PDB layout and return
structured provenance and coverage; raw `!heap`/`!pool` text is the fallback for an allocator the
v1 decoder does not support.

## Choose the target and symbols

1. Stop the target. The walkers refuse a running target because allocator metadata is not a
   consistent snapshot while it changes.
2. For a broken-in x64 kernel target or suitable kernel dump, load private `nt` types with
   `set_symbol_path`, then `execute { "command": ".reload /f nt" }`. Use `pool_*`.
3. For a stopped x64 user process or sufficiently complete user dump, load private `ntdll` types
   with `set_symbol_path`, then `execute { "command": ".reload /f ntdll.dll" }`. Use `heap_*`.
4. Check `execute { "command": "lm m nt" }` or `lm m ntdll`. The module must report PDB symbols,
   not exports or deferred symbols. If loading fails, follow [setup.md](setup.md)'s engine and
   symbol-store checks before retrying the walk.

Never choose offsets by Windows build number or substitute a nearby build's layout. Each answer's
`layout` names the image and PDB, gives a stable fingerprint, and identifies the structurally
validated VS family. An unfamiliar or ambiguous family is intentionally refused.

## Kernel pool workflow

- Use `pool_census` to establish the population, `pool_find_tag` to narrow allocated chunks,
  `pool_chunk` for one address and its contiguous allocator neighbours, and `pool_diagnostics`
  when expected memory is absent.
- The first query walks the pool. Later queries reuse the same session snapshot. Pass
  `refresh: true` after any execution that could change the target; control tools invalidate the
  cache automatically, but explicit refresh makes the intent clear at the final observation.
- For an existence or bounded-cardinality question, pass nonzero `stop_after_matches` to
  `pool_find_tag`. A newly started walk stops when that many matching allocated chunks have been
  decoded and reports `walk.coverage: match_limit_reached` plus the threshold. Its `matches` and
  `total_bytes` are floors. A complete cached snapshot is reused instead and stays exhaustive.
  `limit` is separate: it caps only the rendered `chunks`, never the walk.
- Read both `layout` and `walk`. `deadline_truncated`, `partial`, and `match_limit_reached` counts
  are floors, and an uncovered address is not evidence that it was never pool.
- Query a tag by its `raw_tag`, not by the `tag` a listing prints. The printed form renders every
  unprintable byte as `.` — and a literal `.` the same way — so a tag containing `.` names no
  particular tag, and `pool_find_tag` will read it as four literal `.` bytes and report no
  matches. This is not a corner case: the heaviest tags on a live kernel are routinely binary, and
  several distinct ones can share a single `....` rendering. Every census entry and chunk carries
  `raw_tag` (`0x` plus the four bytes, in memory order) beside the printed form, and
  `pool_find_tag` accepts either.

## User heap workflow

Start with `heap_list`. It lists every PEB heap root and separates:

- supported Segment Heaps that were walked;
- classic NT heaps, which v1 lists but skips;
- unknown roots; and
- roots whose signatures could not be read.

Then use:

- `heap_allocations` for capped filters by heap, backend (`lfh`, `vs`, `segment`, `large`), state,
  and capacity. It defaults to `state: allocated`; when investigating freed memory, pass
  `state: reusable_free` or `state: cached_free` explicitly;
- `heap_chunk` for the allocation containing an address, its offset, and same-heap neighbours;
- `heap_census` for heaviest heap/backend/state/size-class groups; and
- `heap_diagnostics` for categories and examples, optionally scoped to one heap.

User results report allocation `capacity`. `requested_size` is present only when the selected PDB
schema validates exact unused-byte metadata; absence means unknown, not equal to capacity. Reuse
the cached snapshot while stopped, refresh after execution, and inspect all three result guards:
`layout` (what decoded it), `scope` (which PEB heaps were included or skipped), and `walk` (whether
coverage was complete).

## V1 boundary

V1 supports x64 Segment Heaps in stopped live targets and dumps with sufficient memory. It does
not decode classic NT heaps, WOW64, or ARM64. Microsoft `!heap` supports both Segment and NT heaps,
so direct a classic-heap case to `execute { "command": "!heap ..." }` and state that its output is
outside typed Segment Heap coverage. See Microsoft's [`!heap` documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-heap).
