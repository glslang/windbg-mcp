---
paths:
  - "src/**/*.rs"
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
crash` is eleven tools and 11,714 B is the floor. **Output schemas carry no prose at all**
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
construction. **Group bytes no longer add up to a surface's**: `crash` is 14,587 B against the
15,753 its two groups sum to in `docs/token-budget.md`, since narrowing shortens what stays as well
as dropping what goes. And the check for "names a tool" is deliberately not word containment — this
prose says frames are "attributed to modules" and that a stuck session "does not let go", while a
TTD description quotes `dx @$cursession.TTD.Calls(...)`, which is the debugger command and not the
`dx` tool; the rule is a code span that *is* the name or opens a call with it, plus bare-if-it-has-
an-underscore, which is what caught `step_back`'s "Reverse of step_into.".

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

