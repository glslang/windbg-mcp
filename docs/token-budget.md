# Token budget

What this server costs the model driving it, and how that is kept from drifting.

A debugging session shares one context window between the transcript, the reasoning and every
answer this server returns. That makes payload size a correctness-adjacent property: a `modules`
call that spends 13k tokens has not failed, but it has taken the space the investigation needed.
Nothing measured this until [`tests/mcp_smoke.rs`](../tests/mcp_smoke.rs) grew the two tests below,
and the numbers turned out to be larger than anyone had guessed — a careful reading of the source
put the tool surface at 90–130 KB, and the wire is 391 KB.

## Two costs, and they are not the same

**The tool surface** is paid once per conversation, before anything is debugged. **A result** is
paid on every call. They need separate budgets because they grow for different reasons and are
fixed in different places.

There is a second split inside the first, and it is the one that matters most:

| | On the wire | Reaches the model |
|---|---|---|
| `name`, `description`, `inputSchema` | yes | **yes** |
| `outputSchema`, `annotations` | yes | no |
| `content[].text` | yes | only when there is no `structuredContent` |
| `structuredContent` | yes | **yes, and it wins** |

Both rows in the second half were measured against a real client rather than assumed:

- A tool definition reaching the model carries name, description and input schema only. The
  Anthropic tool spec has no field for an output schema, so the 286 KB of `outputSchema` this
  server emits is a client-side parse, validation and memory cost — never a context cost.
- `structuredContent` **replaces** the text block rather than accompanying it. A `session_status`
  call arrives as `{"max_sessions":4,…}` with the human summary dropped; `decode_ioctl`, which
  emits no structured content, arrives as text.

The second point reverses an assumption in [`DECISIONS.md`](../DECISIONS.md) ("A typed result is a
second channel, not a replacement", 2026-08-12, #84). That decision was argued for machine
parseability, against a Python client scraping prose, and it is still right for that reader. What
it did not consider is that a *model* client picks one — so for the 31 tools with an output schema,
the rendering is paid for on the wire and read by nobody, and the half the model does read is the
larger one. `src/structured.rs:1651` already made the other call for `debug_batch`, and states the
reason: carrying both "would make the typed answer the larger of the two channels while adding no
fact this does not already name".

## Why bytes and not tokens

Every figure here is **bytes of minified UTF-8 JSON**. No tokenizer exists in this crate's
dependency tree, and adding one would pull in BPE data to produce a number that varies by model and
would churn the golden on a tokenizer bump rather than on a change to this server. Bytes are
deterministic, diff cleanly, and move with tokens for a fixed content style.

For reporting, **≈4 bytes per token** is the rule of thumb used in this document. It is an
approximation for JSON of this shape, not a measurement.

## The baseline

Recorded in [`tests/golden/tool_budget.json`](../tests/golden/tool_budget.json), which is the
authority — the tables below are a reading of it at the time of writing.

### Tool surface (51 tools)

| Component | Bytes | Reaches the model |
|---|---:|---|
| **Whole `tools/list` payload** | **391,172** | partly |
| — the 51 tools themselves | 391,054 | partly |
| — result-level fields (`resultType`, `ttlMs`, `cacheScope`) | 118 | no |
| `outputSchema` (the 33 tools that have one) | 317,236 | no |
| `inputSchema` (all 51) | 39,667 | yes |
| `description` (all 51) | 24,752 | yes |
| `annotations` | 5,449 | no |
| **Model-visible total** | **67,076** (~16k tokens) | — |
| `initialize` instructions | 1,996 | yes, **all of it** |

Worst single tool: `debug_batch` at 9,757 model-visible bytes, because its `inputSchema` pulls the
whole `StepAction`/`Check` vocabulary out of `src/batch.rs`.

The payload is measured as the **serialized result**, not as the sum of its tools, and the 118-byte
gap between those two is the reason. Result-level fields live in it, and on `2026-07-28` those are
SEP-2549's `ttlMs`/`cacheScope` — the fields the `rmcp = "3.1.1"` floor exists for. Asking the same
server at two revisions shows what a sum would miss:

| Revision | payload | sum of tools | result-level |
|---|---:|---:|---|
| `2026-07-28` | 391,172 | 391,054 | `resultType`, `ttlMs`, `cacheScope` |
| `2025-06-18` | 391,116 | 391,054 | none |

The sum is **identical** across the two; only the payload figure can tell them apart. The golden
records both, so the gap stays visible.

### Results, against `docs/samples/052126-34312-01.dmp`

`model` is whichever half the client forwards; `wire` is the whole result, which every client pays.

| Tool | model | wire | text | structured | ratio |
|---|---:|---:|---:|---:|---:|
| `modules` | 53,897 | 74,016 | 19,732 | 53,897 | 2.7x |
| `execute` (`lm`) | 19,420 | 19,788 | 19,420 | — | — |
| `registers` | 9,804 | 10,534 | 618 | 9,804 | **15.9x** |
| `crash_triage` | 1,855 | 3,133 | 1,159 | 1,855 | 1.6x |
| `open_dump` | 1,347 | 2,277 | 814 | 1,347 | 1.7x |
| `disassemble` | 2,018 | 3,429 | 1,291 | 2,018 | 1.6x |
| `backtrace` | 945 | 1,588 | 532 | 945 | 1.8x |
| `session_status` | 297 | 823 | 420 | 297 | 0.7x |

**Three rows are measured somewhere else** — `backtrace`, `disassemble` and `modules` — against
`docs/samples/121524-4703-01.dmp` on the ARM64 bench, because each changed after this baseline was
recorded and that machine opens the sample matching its own architecture. A stack's size is the
crash's rather than the tool's and a disassembly's is the code's, so the first two are not
comparable to the digit with the rows they replace (572 B of `k` text; `disassemble` had no row at
all, having had no budget). What is comparable is the shape: the model now reads records and not a
listing. `modules` moved by ~100 B for one module's `pdb` object, which is the whole of what that
field costs a caller — against the 15,610 B it costs the wire in schema, which is finding 1 above.

`registers` is the shape of the problem in miniature: the model reads 9,804 bytes of JSON carrying
`"kind":"int"` and `"subregister":false` on every row, and never sees the 618-byte `r` output that
says the same thing better. `modules` is the largest single answer this server gives — roughly
13k tokens, a fifth of a whole tool surface, for one question.

## What the baseline exposes

None of these is a bug. They are recorded because they were invisible, and
[`FOLLOWUPS.md`](../FOLLOWUPS.md) item 24 tracks them.

1. **`$defs` are inlined per tool.** `schemars` emits each output schema self-contained, so
   `ErrorCategory` (2,089 B) ships **31 times**, `WalkGaps` (2,886 B) and the whole
   allocator/pool subtree nine times each. **200,571 bytes — 70% of all `outputSchema`** — is
   duplicated beyond its first copy.
1b. **And finding 1 has a price tag now.** Adding `PdbInfo` — one optional four-field type, on one
   field of `ModuleInfo` — grew the wire by **15,610 B**, because `ModuleInfo` is embedded in the
   openers' `TargetSummary`, in `modules`, and in the allocator shapes, and `schemars` inlines the
   new type into every one of them. Model-visible cost: **zero**, since no model reads an
   `outputSchema`. That ratio — 15 KB of wire for 0 B of context — is the whole of finding 1 in a
   single change, and it is why the ceiling below moved rather than the type being argued about.

2. **Whole schemas repeat.** The six openers carry a byte-identical 11,093 B output schema; the six
   step tools a byte-identical 4,418 B one. 77,555 B of the above.
3. **`session_id` was documented in three different wordings** — **fixed**, and the original figure
   here was wrong in an instructive way. It said 9,514 B across 43 sites; the model-visible total was
   **4,695 B across 32**, because the count had included the copies inside `outputSchema`, which the
   table two sections up says no model reads. Unifying the wording — and documenting the five heap
   tools whose `session_id` had *no* description at all — moved the model-visible surface by
   **−537 B**, not the ~9 KB this bullet implied.

   Most of even that is explained by a second correction, from review. All three original wordings
   described only the staleness guard ("pass it to refuse the call if the target has been replaced"),
   which is the *consequence*. The field is a **router**: omitted, the call goes to the current
   session — the newest still open — and a handle sends it to that one. Unifying on the old phrasing
   would have propagated a description implying omission is safe when several sessions are open,
   which is precisely when it is not. A correct description of two behaviours is not shorter than an
   incomplete description of one, so this half is close to byte-neutral by construction. The
   repetition itself stays deliberate (`src/server.rs`: flattening "renders as a schema composition
   that clients handle unevenly").

   The lesson is the one this whole document exists for: a number that has not been measured in the
   channel it is claimed for is not a finding. The weight is elsewhere — see finding 8.
4. **The instructions overran what the client reads** — **fixed**. 3,147 chars were sent and 2,048
   read, so 1,099 were paid for on every connection and discarded, and what fell off the end was the
   `debug_batch` paragraph: the one instruction there that stops a mutation being left half-applied.
   Rewritten to 1,996 characters with the batch guidance inside the budget, kept ASCII so the
   character and byte counts cannot diverge, and pinned by an assertion in the protocol tier so it
   cannot grow back unnoticed.
5. **`modules` has neither a `limit` nor a cap**, alone among the high-volume tools. 53,875 B here;
   more on a live kernel.
6. **Several tools have no bound at all** — `ttd_calls`, `ttd_memory`, `threads`,
   `execute`, `dx`, `ioctl_trace`, `reachable_from_dispatch` — and `read_memory`
   returns up to ~4 MiB of hex by design (`src/worker.rs:117`). Every existing cap in this codebase
   (`MAX_ROWS`, `MAX_NODES`, `MAX_READ_BYTES`) is justified in its own comment as a **worker
   out-of-memory guard, not a caller-context guard**. That is not wrong; it means nothing here has
   ever had the caller's context window as its constraint.
7. **A typed answer can be much larger than the rendering it replaces.** `registers` is 15.9x its
   own text, because every row carries `"kind":"int"` and `"subregister":false`. This is the one
   finding that is purely model-visible and purely this server's to fix, and it is what the ratio
   rule below exists to stop spreading.
8. **Five tools are a third of the model-visible surface**, and it is their *input* schemas rather
   than their prose. `debug_batch` alone is 9,728 B — 15% of everything a model is given before it
   asks anything — of which 7,962 B is the `StepAction`/`Check` vocabulary its schema pulls out of
   `src/batch.rs`. Then `walk_memory` 4,058, `crash_triage` 2,894, `reachable_from_dispatch` 2,610,
   `server_log` 2,599: **21,889 B, 33%**, against a median tool of 882 B.

   This is where the weight is, and it is a different kind of problem from findings 1–4. Those were
   duplication and waste — the same string paid for repeatedly, or a tail nobody reads. This is one
   tool honestly describing a rich argument, and the levers are real design choices: a smaller step
   vocabulary, a `$ref` the client resolves, or a tool surface that does not offer every tool to
   every caller. Worth measuring before choosing, which is what this table is for.

One interaction worth flagging before acting on any of it: `FOLLOWUPS.md` item 11 proposes *adding*
`structuredContent` to `ttd_calls`, `ttd_memory` and `driver_object` — three of the highest-volume
text-only tools. Under the rule measured above that replaces their text rather than supplementing
it, which may well be an improvement, but it is a size decision and should be taken as one.

## Running it

The surface budget needs no debugger and rides the ordinary test run:

```pwsh
cargo test --test mcp_smoke -- --nocapture tool_surface_stays_within_its_token_budget
```

The result budget needs the debugger tier:

```pwsh
$env:WINDBG_MCP_SMOKE_DUMP = "1"
cargo test --test mcp_smoke -- --nocapture tool_results_stay_within_their_budget
```

**`--nocapture` is not optional if you want to read the numbers.** libtest captures a passing
test's output and prints it only on failure, so without the flag both tests pass in silence — which
is the opposite of the point. It is in both commands above for that reason, and it is why the
debugger tier's CI job passes it (`ci.yml`) while the `build` job, which runs the whole suite, does
not: the surface figures are not in CI's log, they are in `tests/golden/tool_budget.json`.

Which is the more useful record anyway. The printed line tells you where you are; the golden tells
you what changed, and it is the one a reviewer sees.

## Changing the numbers

Two mechanisms guard the surface, because they fail on different things.

The **golden** shows where the bytes are. Any change to any tool's size lands as a readable diff,
so the price of a reworded description is visible in review. Re-record it — along with the shape
golden beside it — with:

```pwsh
$env:UPDATE_GOLDEN = "1"; cargo test --test mcp_smoke
```

Then read the diff before committing it. It is compared **as values, matched by tool name**, not as
lines, so it reports what actually moved:

```text
  + server_log is new: 2599 B to the model, 8858 B on the wire
  ~ modules: modelVisible 2112 -> 4200 (+2088), description 681 -> 2769 (+2088)

totals:
  modelVisible 66078 -> 68166 (+2088)
```

A line diff was tried first and is wrong for this file. Each tool is seven lines, so adding or
removing one shifts every line below it, and a positional differ blames the first tool whose *line
numbers* moved rather than the one that changed — dropping one tool from a 51-tool report made the
failure open with `crash_triage`, which had not changed at all, then truncate before reaching
anything that had. Keying the JSON by name would not have helped: the rows would still be lines,
and an insertion would still shift them.

The **ceilings** (`MODEL_VISIBLE_CEILING`, `WIRE_CEILING`, `WORST_TOOL_CEILING` in
`tests/mcp_smoke.rs`) stop what the golden cannot: a golden re-recorded on every diff is a rubber
stamp, and thirty accepted 2% growths are a doubling nobody voted for. They sit ~15% over today's
figures. Raising one is a normal thing to do — a new tool has to fit somewhere — but do it in its
own commit, with the reason, and update the tables here.

Result budgets are **not** goldened. Their sizes move with what the runner can resolve: a symbol
server that answers turns `deferred` into paths and grows `lm` a column, and the debugger tier runs
on two architectures. Per-tool ceilings with ~35–45% headroom catch a tool that starts returning an
order of magnitude more, without pinning a number the environment owns. `crash_triage` and
`backtrace` are looser still, deliberately: both change *shape* when symbols resolve rather than
merely growing — `!analyze -v` prints a different report, and a stack whose frames resolve carries a
`symbol` on every one where an offline walk carries none — and a ceiling tight enough to be
interesting offline would make the tier flaky about its environment instead of watchful about the
code.

One rule is asserted rather than a number: a tool's `structuredContent` may not exceed its own text
rendering by more than 20x. A typed answer is meant to be the facts behind a rendering, so a large
multiple means it is carrying scaffolding instead. `registers` is at 15.9x and is finding 7 above,
not a failure — the rule is there to catch the next one. Being a ratio, it is only safe to read
alongside the `wire` ceiling below: on its own, a rendering that grows satisfies it *more*.

### Why each call has two ceilings

`model` alone would leave the other channel unwatched. It is `structuredContent` when a tool has
one, and that is a *forwarding policy* rather than protocol — MCP does not require a client to drop
the text block, and this server is advertised for several — so budgeting only the forwarded half
means that for the 31 typed tools the rendering could grow with nothing to notice.

And it would have looked like an improvement. Text is the **denominator** of the ratio rule above,
so a rendering that doubles *lowers* the ratio while `model` does not move at all: the one
assertion that mentioned text was the one that would have waved it through. Measured, not argued —
adding a line of prose per module to `modules` took its text from 19,732 B to 30,385 B, and the
ratio *fell* from 2.7x to 1.8x while `model` stayed at 53,875 B.

So each call also has a **`wire`** ceiling: the whole result as it crosses the pipe, which no
client's policy affects. It is measured rather than derived from `text + structured`, because the
result object also carries content-block scaffolding and JSON escaping — a rendered table's
newlines cost two bytes there and one in `text`.

What is still missing is per-*channel* ceilings, which would say which half moved. That needs a
decision about which forwarding policies this server intends to be good under, and that wants
measurements from a second client rather than a guess about one —
[#150](https://github.com/glslang/windbg-mcp/issues/150).
