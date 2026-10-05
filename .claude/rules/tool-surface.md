---
paths:
  - "src/**/*.rs"
  - "tests/**/*.rs"
  - "build.rs"
---

## Adding a tool (`src/toolset.rs`)

Two files, not one. A tool is declared in `src/server.rs` as always, and its name also goes in a
**group** in `src/toolset.rs` — the table behind `--tools`, which advertises a named subset of the
surface because 70% of the 75,547-byte tool surface is prose a model needs and cannot be trimmed
(`docs/token-budget.md` finding 8).

Forgetting the second half fails in the one direction nothing would notice: the *default* surface
is every tool, so the new tool works everywhere you would try it, and it is missing only from a
**narrowed** surface. `mcp_smoke::every_tool_belongs_to_exactly_one_group` is the join that catches
it — it starts a server with all eight group names and asserts that equals the whole `tools/list`.
There is no such thing as a tool in two groups, and a group named after a tool is refused by a unit
test, because `Toolset::parse` resolves group names first and would decide it silently.

Four rules worth knowing before touching it. **`session` is in every surface** whatever the spec
says, because every other tool routes by a `session_id` this server alone issues — so `--tools
crash` is thirteen tools and 11,714 B is the floor. **Output schemas carry no prose at all**
(`src/schema.rs`): declare one with `schema::constraints_of`, never rmcp's `schema_for_output`, or
the tool ships every doc comment in its `$defs` closure and the wire ceiling notices. That call is
also what supplies the root `type: "object"` a discriminated union does not generate and rmcp does
not add — without which every released TypeScript-SDK client rejects the *whole* `tools/list` and
registers no tools at all, not 50 of 51 (issue #223, measured: 0 of 51 against SDK 1.30.0). Both
halves are asserted on the wire in `mcp_smoke`, because both come undone the same way. And **a
surface is per client, not per run** (item 36): `--tools` is the run's *default*, and a listener's
client may be configured with a spec of its own (`WINDBG_MCP_TOOLS_<NAME>`, or a `tools` field in
the credential file) that replaces it. So a change to a group is a change to what several
differently-budgeted callers see, and the assertion that catches a per-client mistake is two
credentials on one port — `two_clients_on_one_listener_are_served_two_surfaces`, not a unit test,
for the reason `.claude/rules/listener-clients.md` gives.

And **a description that names another tool is data, not a doc comment** (item 41). A
cross-reference lives in `TOOL_NOTES` beside the tools it names, and `annotate` appends it in
`router()` only when the surface has every one of them — so the doc comment itself must name no
tool but the always-served ones, and `no_description_names_a_tool_the_client_cannot_call` fails the
build if a new tool's prose points at one its own single-tool spec does not serve. Three
consequences when you add one. The invariant is checked on `--tools <that tool>` and nowhere else,
because that is the tightest surface it can be served on and every wider one is covered by
construction. **Group bytes no longer add up to a surface's**: `crash` is 19,078 B against the
20,244 its two groups sum to in `docs/token-budget.md` (2026-09-07), since narrowing shortens what stays as well
as dropping what goes. Neither of those two figures is worth checking by hand:
`every_documented_surface_figure_matches_the_served_surface` reads the tables in `src/toolset.rs`,
`docs/tool-surface.md` and `docs/token-budget.md` and compares every count, byte total and
percentage in them against a server it starts — so a group that grows fails `cargo test` with the
row and the right number, and the way to update a table is to run it and paste what it says. It
derives group membership from the server rather than from `GROUPS`, so it cannot agree with a table
by sharing its mistake. **Prose is not swept, deliberately** — a text search for anything
surface-shaped was prototyped and measured at 63 lines to triage, most of them neither stale nor
about the surface — so a figure written into a *sentence* is still yours to re-derive, and the
tables are where to re-derive it from. And the check for "names a tool" is deliberately not word containment — this
prose says frames are "attributed to modules" and that a stuck session "does not let go", while a
TTD description quotes `dx @$cursession.TTD.Calls(...)`, which is the debugger command and not the
`dx` tool; the rule is a code span that *is* the name or opens a call with it, bare-if-it-has-an-
underscore, which is what caught `step_back`'s "Reverse of step_into.", and **in double quotes**,
which is the hole the other two leave between them — `Call "execute" instead` matches neither, and
all three invariants could only ever report what the predicate detects. Adding it cost nothing
(measured 2026-10-05: no description, fragment or schema string on the surface quotes a tool name)
and will cost a value spelled like a tool, `{"access": "execute", …}` being a `WatchAccess`, which
is the same trade as the next paragraph's.

**And again for an argument's prose, which is a second channel out of the same file** (item 52).
A doc comment on an argument lands in the tool's **`inputSchema`**, not in its description, so
`no_description_names_a_tool_the_client_cannot_call` walked straight past it — eleven
sentence/tool pairs across seven tools, where the item recorded one. `docs/token-budget.md` counts
that schema inside `modelVisible` and `tool_budget.json` gives it a column, so it is model-visible
on exactly the description's terms. `no_input_schema_names_a_tool_the_client_cannot_call` beside it
is the walk, and it reports every leak rather than the first, because the fix for this channel's
first failure was eleven sentences. **There is no third notes table**: `annotate` rewrites a
description per surface and nothing rewrites a schema, so an argument's prose names no tool but its
own and the always-served openers, and a cross-reference goes in `TOOL_NOTES`. **And no exemption**,
which is the part two review rounds went into. `debug_batch`'s step vocabulary is spelled with four
of the tool table's own words, and `set_breakpoint` declares the *value* `execute`, which is a
`WatchAccess` — so the walk exempted a name the served schema declares, then only the occurrences
written as JSON values, and review escaped both. What the mechanism bought was **one description**,
`debug_batch`'s `steps`, and four names in it: the prose gave them up and the schema kept them, in
each variant's `op` `const`, which is the channel a client validates against. So a step whose name
is also a tool's is documented by its variant and not spelled in prose that ships to a client
without that tool — and nothing has to decide what counts as a value. And what reaches a client is
not the set of doc comments in the file: `schemars` 1.2.2 holds back no summary
line, so an attached comment arrives whole, but a `#[serde(flatten)]`'d type's own comment is not
attached at all — every one of `StepAction`'s *variant* docs ships and not a word of the enum's own
(measured 2026-10-05), which is why the walk reads `input_schema` and not the source.

**And the same rule again for a *result*, which is the channel that took longest to find** (item
43). `SUMMARY_NOTES` beside `TOOL_NOTES`, appended by `annotated_report` rather than `annotate`.
The reason it is a second table and not a wider first one is where the text is built: an opener's
summary is assembled by `summary_text` in the **worker**, which owns one session and has never
heard of a client — so a sentence naming `modules`, with its `filter` argument spelled out, shipped
to an eleven-tool caller for as long as that sentence existed. The summary crosses the pipe as
facts; the pointers are added where `self.surface` is. Three things to know before touching it.
**Annotate above both halves of the result**, because a structured-aware client forwards
`structuredContent` and drops the text — a pointer added to one half is one half the clients never
see, and a pointer *removed* from one half is the leak still open on the other. **A note carries a
predicate**, since a pointer to the bug check on a target that did not bug-check is noise on every
surface. And **the leak was invisible to the eval that was measuring it**: `local_model_drive.py`
records `text[:300]` and the sentence sat at the end of a 2,508-character summary, so two rounds of
"which names is this server teaching" never saw the largest one. What found it was a scan of `src/`
string literals against the tool table — seconds, no bench and no VM, because what a server prints
is a static question and was never an eval's to answer.

