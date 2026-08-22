# Token budget

What this server costs the model driving it, and how that is kept from drifting.

A debugging session shares one context window between the transcript, the reasoning and every
answer this server returns. That makes payload size a correctness-adjacent property: a `modules`
call that spends 13k tokens has not failed, but it has taken the space the investigation needed.
Nothing measured this until [`tests/mcp_smoke.rs`](../tests/mcp_smoke.rs) grew the two tests below,
and the numbers turned out to be larger than anyone had guessed — a careful reading of the source
put the tool surface at 90–130 KB, and the wire was 391 KB. It is 177 KB now, and finding 1 below
is where the other 217 KB went.

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
  Anthropic tool spec has no field for an output schema, so the `outputSchema` this server emits is
  a client-side parse, validation and memory cost — never a context cost. It was 286 KB when that
  was measured, and finding 1 is what followed from the measurement: if nothing reads it, the
  documentation inside it is being paid for and never delivered.
- `structuredContent` **replaces** the text block rather than accompanying it. A `session_status`
  call arrives as `{"max_sessions":4,…}` with the human summary dropped; `decode_ioctl`, which
  emits no structured content, arrives as text.

The second point reverses an assumption in [`DECISIONS.md`](../DECISIONS.md) ("A typed result is a
second channel, not a replacement", 2026-08-12, #84). That decision was argued for machine
parseability, against a Python client scraping prose, and it is still right for that reader. What
it did not consider is that a *model* client picks one — so for the 33 tools with an output schema,
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

The first column is the baseline this page was written from; the second is today, and the only
thing between them is finding 1 — the prose taken out of every `outputSchema`.

| Component | Baseline | Today | Reaches the model |
|---|---:|---:|---|
| **Whole `tools/list` payload** | **391,172** | **177,460** | partly |
| — the 51 tools themselves | 391,054 | 177,342 | partly |
| — result-level fields (`resultType`, `ttlMs`, `cacheScope`) | 118 | 118 | no |
| `outputSchema` (the 33 tools that have one) | 317,236 | 102,942 | no |
| `inputSchema` (all 51) | 39,667 | 40,207 | yes |
| `description` (all 51) | 24,752 | 24,794 | yes |
| `annotations` | 5,449 | 5,449 | no |
| **Model-visible total** | **67,076** | **67,658** (~17k tokens) | — |
| `initialize` instructions | 1,996 | 1,990 | yes, **all of it** |

The two halves moved independently, which is the whole argument for measuring them apart: the wire
fell by 55% and the model-visible column did not move at all except for what the tools themselves
have accumulated since.

Worst single tool: `debug_batch` at 9,746 model-visible bytes, because its `inputSchema` pulls the
whole `StepAction`/`Check` vocabulary out of `src/batch.rs`.

The payload is measured as the **serialized result**, not as the sum of its tools, and the 118-byte
gap between those two is the reason. Result-level fields live in it, and on `2026-07-28` those are
SEP-2549's `ttlMs`/`cacheScope` — the fields the `rmcp = "3.1.1"` floor exists for. Asking the same
server at two revisions shows what a sum would miss:

| Revision | payload | sum of tools | result-level |
|---|---:|---:|---|
| `2026-07-28` | 177,460 | 177,342 | `resultType`, `ttlMs`, `cacheScope` |
| `2025-06-18` | 177,404 | 177,342 | none |

The sum is **identical** across the two; only the payload figure can tell them apart. The golden
records both, so the gap stays visible.

### Results, against `docs/samples/052126-34312-01.dmp`

`model` is whichever half the client forwards; `wire` is the whole result, which every client pays.

| Tool | model | wire | text | structured | ratio |
|---|---:|---:|---:|---:|---:|
| `modules` (the whole table, which was the default then) | 53,897 | 74,016 | 19,732 | 53,897 | 2.7x |
| `execute` (`lm`) | 19,420 | 19,788 | 19,420 | — | — |
| `registers` (before finding 7 was fixed; 3,480 / 4,210 / 5.6x now) | 9,804 | 10,534 | 618 | 9,804 | **15.9x** |
| `crash_triage` | 1,855 | 3,133 | 1,159 | 1,855 | 1.6x |
| `open_dump` | 1,347 | 2,277 | 814 | 1,347 | 1.7x |
| `disassemble` | 2,018 | 3,429 | 1,291 | 2,018 | 1.6x |
| `backtrace` | 945 | 1,588 | 532 | 945 | 1.8x |
| `session_status` | 297 | 823 | 420 | 297 | 0.7x |

**`modules` no longer answers with that table**, and the row is kept as the baseline it was: the
default is one page of it (finding 5). The tier re-measures both halves against **this same dump**
and prints them under `--nocapture` — 12,268 B model / 16,871 B wire for the page, against
53,933 B / 74,052 B for all 227 modules — so the row above and the page figure are directly
comparable, and the 36 B between 53,897 and 53,933 is what the rows have accumulated since.

**Three rows are measured somewhere else** — `backtrace`, `disassemble` and `modules` — against
`docs/samples/121524-4703-01.dmp` on the ARM64 bench, because each changed after this baseline was
recorded and that machine opens the sample matching its own architecture. A stack's size is the
crash's rather than the tool's and a disassembly's is the code's, so the first two are not
comparable to the digit with the rows they replace (572 B of `k` text; `disassemble` had no row at
all, having had no budget). What is comparable is the shape: the model now reads records and not a
listing. `modules` moved by ~100 B for one module's `pdb` object, which is the whole of what that
field costs a caller — against the 15,610 B it costs the wire in schema, which is finding 1 above.

`registers` was the shape of the problem in miniature — the model read 9,804 bytes of JSON and never
saw the 618-byte `r` output beside it — though not for the reason written here at the time: see
finding 7, where measuring the payload found most of the weight in rows that should not have been in
a default answer at all, and found this sentence's "says the same thing" to be untrue. `modules` **was** the largest single answer this server gives — roughly
13k tokens, a fifth of a whole tool surface, for one question — which is what finding 5 is, and
what it has since done about it.

## What the baseline exposes

None of these is a bug. They are recorded because they were invisible, and
[`FOLLOWUPS.md`](../FOLLOWUPS.md) item 24 tracks them.

1. **`$defs` are inlined per tool** — **fixed** (2026-08-22), though not by removing the
   duplication, which cannot be done. `schemars` emits each output schema self-contained, so
   `ErrorCategory` (2,089 B) shipped **33 times**, `ModuleInfo` (3,524 B) seven and the
   allocator/pool subtree nine: **222,579 bytes, 69% of all `outputSchema`**, duplicated beyond its
   first copy.

   The lever this finding named — hoisting the shared definitions — is not available. MCP gives
   each tool one `outputSchema` and no document above it, and `#/$defs/…` resolves against the
   schema it appears in, so a client has nowhere to look up a definition another tool declared. The
   multiplier is the protocol's, and it stays.

   What is available is **what gets multiplied**. Measuring the payload found that **68% of every
   `outputSchema` byte was a `description`** — 217,423 B of 320,365 B, and 55% of the whole answer.
   `ErrorCategory` is 2,089 B with its doc comment and **324 B** without. So the schemas now carry
   constraints and nothing else (`src/schema.rs`), and the payload is **394,883 → 177,460 B** with
   the model-visible column unmoved.

   That trade is one-sided because `description` had no reader in this position. No model is given
   an output schema — the measurement at the top of this page. No validator reads one either:
   `description` is an annotation keyword, so every instance that validated before validates now.
   And a human has three better copies — the rustdoc these strings are generated from, the
   structured-results table in `README.md`, and the tool's own model-visible `description`.

   The strip is **structural, not textual**, which is the one place it could have gone wrong
   quietly: a field named `description` renders as `properties: { "description": … }`, and dropping
   every `"description"` key would delete the field rather than its documentation. `src/schema.rs`
   descends only where a JSON Schema keyword says a subschema lives, and has a unit test for
   exactly that case — no structured type has such a field today, and the one that does is the one
   this would have broken.

   **And this finding had a price tag before it was fixed.** Adding `PdbInfo` — one optional
   four-field type, on one field of `ModuleInfo` — grew the wire by **15,610 B**, because
   `ModuleInfo` is embedded in the openers' `TargetSummary`, in `modules`, and in the allocator
   shapes, and `schemars` inlines the new type into every one of them. Model-visible cost:
   **zero**, since no model reads an `outputSchema`. That ratio — 15 KB of wire for 0 B of context
   — was the whole of this finding in a single change, and it is why the ceiling moved
   412,000 → 460,000 rather than the type being argued about. The same type costs roughly a seventh
   of that now, and the ceiling has come back down to 205,000: what changed is not how many times a
   type is copied but how much of it there is to copy.

2. **Whole schemas repeat.** The six openers carried a byte-identical 13,386 B output schema; the
   six step tools a byte-identical 4,433 B one — 89,095 B of the above. This is the same protocol
   fact as finding 1 and has the same answer: there is nowhere to say it once. Those schemas are
   3,838 B and 1,185 B each now.
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
   Rewritten to 1,990 characters with the batch guidance inside the budget, kept ASCII so the
   character and byte counts cannot diverge, and pinned by an assertion in the protocol tier so it
   cannot grow back unnoticed.
5. **`modules` had neither a `limit` nor a cap**, alone among the high-volume tools — **fixed**.
   53,875 B here; more on a live kernel. It now takes a `limit` (default 64 rows, maximum 2000)
   that bounds the **whole** listing, the loaded and unloaded halves sharing it through the same
   `split_row_budget` the heap diagnostics use so that neither crowds the other out. Measured on
   the sample this page's table is measured on, so the numbers are comparable: **12,268 B model /
   16,871 B wire for the default page, against 53,933 B / 74,052 B for all 227 modules**. The tool
   surface
   grew 383 B for the argument, paid once a conversation against ~41 KB saved on every call.

   Two things this settled that the finding did not anticipate. The counts have to be **values**,
   not prose — `loaded` was already the inventory, and `matched` / `unloaded_matched` are new, so a
   page can never be read as the whole table. And the halves need one budget with a share reserved
   rather than one budget each: two halves that each take `limit` in full quietly double the
   ceiling, which is the rule `the_row_limit_bounds_the_whole_listing` already stated for the
   diagnostics listing one tool over.
6. **Several tools have no bound at all** — `ttd_calls`, `ttd_memory`, `threads`,
   `execute`, `dx`, `ioctl_trace`, `reachable_from_dispatch` — and `read_memory`
   returns up to ~4 MiB of hex by design (`src/worker.rs:117`). Every cap in this codebase at the
   time this was written (`MAX_ROWS`, `MAX_NODES`, `MAX_READ_BYTES`) is justified in its own comment
   as a **worker out-of-memory guard, not a caller-context guard**. That is not wrong; it means
   nothing here had ever had the caller's context window as its constraint. `DEFAULT_MODULE_ROWS`
   (finding 5) is the first one that does, and it says so where it is defined — the rest of this
   list is still bounded by what the target happens to hold.
7. **A typed answer can be much larger than the rendering it replaces.** `registers` was 15.9x its
   own text — **fixed** (2026-08-22), and the fix was not the one this finding named. The
   scaffolding it blamed is real: `"kind":"int"` and `"subregister":false` were 1,599 B and 2,460 B
   of the 9,804, 41% between them. But measuring the payload rather than reasoning about it found
   something larger. **64 of the 123 rows were the vector bank**: DbgEng exposes `xmm0` twice, as
   128 bits of `bytes` *and* as `xmm0/0` … `xmm0/3`, four 32-bit pseudo-registers that carry no
   subregister flag — so they passed a filter meaning "integer registers, not subregisters" and sat
   in an answer whose own argument documents it as excluding the vector registers.

   Excluding them and skipping the empty flag takes the default from **9,804 B to 3,480 B** and the
   ratio from 15.9x to **5.6x**; the result ceiling moved 13,500 → 5,000 with it. `kind` was left
   alone: it earns its place on the `float`, `non_finite` and `unavailable` rows, and dropping it
   only for `int` would be an absent field meaning a default — the trap `docs/coordinates.md`
   records paying for.

   **And the sentence under the table was wrong**, which is the more useful correction: the text was
   never "the same thing better". `r` prints 17 registers; the structured half carried 123. They
   described different sets, so the ratio was never a like-for-like comparison of one answer in two
   renderings. It is much closer to one now, at 59 rows against 17.

   The ARM64 half is **measured and declined** (`FOLLOWUPS.md` item 35): there the same class of row
   is `w0`–`w30`, the 32-bit views DbgEng also declines to flag, worth ~1.8 KB of a ~6.3 KB answer —
   and reading every field of the engine's register description on both architectures found nothing
   that identifies them, while the obvious second name rule needs a table of exceptions before it
   even covers `w29`.
8. **Five tools are a third of the model-visible surface**, and it is their *input* schemas rather
   than their prose — **answered** (2026-08-22) by serving fewer tools rather than smaller ones.
   `debug_batch` alone is 9,746 B — 14% of everything a model is given before it asks anything — of
   which 7,980 B is the `StepAction`/`Check` vocabulary its schema pulls out of `src/batch.rs`.
   Then `walk_memory` 4,076, `crash_triage` 2,912, `reachable_from_dispatch` 2,628, `server_log`
   2,599: **21,961 B, 33%**, against a median tool of 900 B.

   This is where the weight is, and it is a different kind of problem from findings 1–4. Those were
   duplication and waste — the same string paid for repeatedly, or a tail nobody reads. This is one
   tool honestly describing a rich argument, and the levers were real design choices: a smaller step
   vocabulary, a `$ref` the client resolves, or a tool surface that does not offer every tool to
   every caller.

   **Finding 1's answer does not transfer here, and that is what settled it.** Prose came out of the
   output schemas because nothing read it. Prose in an *input* schema is the opposite: it is most of
   what tells a model how to drive the tool, and `debug_batch` is the tool where getting that wrong
   leaves a patched byte in a running kernel. Measured across all 51 tools, **74% of the
   model-visible surface is prose** — 24,794 B of tool descriptions and 25,333 B inside the input
   schemas — so a strip here buys context by making the tools harder to drive correctly.

   The structural remainder does not pay for the risk either. Dropping `"default": null`, which
   schemars emits 109 times and which tells a model nothing an absent field does not, is 1,744 B —
   2.6%. The other candidates are not free: `$schema` is 2,850 B but is how a client picks a
   validator dialect (and `tool_schemas_declare_one_dialect_and_are_self_contained` pins it), and
   `minimum`/`format` are constraints. **Roughly 1.7 KB of 67,658 is the whole honest total** for
   trimming the schemas.

   So the third lever is the one taken: `--tools` (`src/toolset.rs`) advertises a named subset. No
   description gets a word shorter; a caller that is reading a crash dump stops paying for nine TTD
   tools and ten allocator ones. Where the bytes sit, and what each profile costs:

   | group | tools | bytes | share |
   |---|---:|---:|---:|
   | `allocator` | 10 | 15,914 | 23.5% |
   | `session` | 10 | 12,161 | 18.0% |
   | `inspect` | 9 | 10,192 | 15.1% |
   | `batch` | 1 | 9,746 | 14.4% |
   | `ttd` | 9 | 6,833 | 10.1% |
   | `ioctl` | 6 | 6,494 | 9.6% |
   | `exec` | 5 | 3,406 | 5.0% |
   | `crash` | 1 | 2,912 | 4.3% |

   | `--tools` | tools | model |
   |---|---:|---:|
   | *(absent)* | 51 | 67,658 |
   | `session,inspect,exec,crash` | 25 | 28,671 |
   | `session,inspect,crash` | 20 | 25,265 |
   | `crash` | 11 | 15,073 |

   `session` is in every surface because every other tool routes by a `session_id` this server is
   the only issuer of — 12,161 B is the floor, and `crash` is eleven tools rather than one. The
   choice is **server-wide**; a per-caller surface on the listener, where clients are already named,
   is item 36.

One interaction worth flagging before acting on any of it: `FOLLOWUPS.md` item 11 proposes *adding*
`structuredContent` to `ttd_calls`, `ttd_memory` and `driver_object` — three of the highest-volume
text-only tools. Under the rule measured above that replaces their text rather than supplementing
it, which may well be an improvement, but it is a size decision and should be taken as one.

## Running it

The surface budget needs no debugger and rides the ordinary test run:

```pwsh
cargo test --test mcp_smoke -- --nocapture tool_surface_stays_within_its_token_budget
```

Two more ride it, both needing no debugger. `every_tool_belongs_to_exactly_one_group` joins
`src/toolset.rs`'s table to the live `tools/list`, because a tool added to `src/server.rs` and not
put in a group would vanish from every narrowed surface without a word — the default surface would
still carry it, so nothing else would notice. And
`a_narrowed_tool_surface_serves_only_what_it_was_asked_for` starts a server with `--tools crash` and
checks the three things that makes true: eleven tools, a refusal by name for a tool that exists and
is not served, and a figure under half the whole surface (it prints 15,073 B).

Beside them, `output_schemas_carry_constraints_not_prose` is the
assertion that finding 1 stays fixed. It reads `tools/list` off the wire, so it catches the way that
change comes undone — one tool declaring its schema with rmcp's `schema_for_output` instead of
`schema::constraints_of` — which is an import line nothing else would report.

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
own commit, with the reason, and update the tables here. **Lowering one is the same act**, and
`WIRE_CEILING` has now been both: 412,000 → 460,000 for `PdbInfo`, then → 205,000 when finding 1
landed. A ceiling left where a fix found it is a ceiling that would have absorbed the next
regression in silence.

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
multiple means it is carrying scaffolding instead. `registers` was at 15.9x — the case the rule was
written around — and is 5.6x since finding 7 was fixed; the rule is there to catch the next one. Being a ratio, it is only safe to read
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
