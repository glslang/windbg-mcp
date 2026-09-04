---
name: eval-bench
description: Run and read the local-model benchmark (`tools/local_model_eval.py`) against this server - the grid's fences, what the grader's matching rules are for, `--verify-key`, `--compare`/`--series`, and how a moved aggregate gets misread as a controlled result. Use when running the eval, adding or re-grading a task, or writing up a benchmark result.
---

# Benchmarking a model against this server

## The grid, and what bites while running it

`docs/local-model-eval.md` is the result; this is what bites while running it again. The grid is
three scripts — the ollama driver, the Claude Code driver, and the matrix runner that spawns either
one per cell and grades the log afterwards.

**Record what the runtime *served*, not what you asked for.** `num_ctx` on a request does not
shrink an instance ollama already holds: with a 32,768 instance loaded, cells asking for 8,192 are
served 32,768 and look perfectly healthy — a 17,300-token prompt "fitting" in 8k, which is the
result the context axis exists to find and would have been fiction. `/api/ps` is the only place
the truth appears. Every record carries `served_context`, the grader marks a cell where the two
disagree with `?`, and the runner evicts the model between windows. The first run of the grid
recorded five such cells; they were dropped and re-run.

**The grader's three matching rules each came from a real wrong verdict**, and all three are in
`present()`:

- A number matches only **between hex boundaries** — `0x22` is the device type `ioctl_decode` asks
  for and `0x22200B` is the code in the question, so plain containment passed for any answer that
  repeated the question. One model scored correct while saying `FILE_DEVICE_KEYBOARD`.
- Leading zeros are formatting — the tool prints `0x802` and a model writing `0x0802` agrees with
  it. That one marked a *correct* control answer wrong.
- A separator between hex digits is formatting too. WinDbg writes ``fffff801`3c65bca8``; Opus
  writes `0xfffff801_3c65bca8`. Both name the address the key holds.

Two of those three were found by reading the **control's** answers, which is the argument for
having a frontier row at all.

**`possible_on` in the task file is a prediction, and predictions about this server are wrong in
one direction: too pessimistic.** Facts here are reachable by more than one route —
`open_dump`'s summary carries the bug check *and* the module count, `crash_triage`'s frame 0 is the
`pc` that `registers` reports — so a task the tool table says needs `inspect` may be answerable
with `crash` alone. Verify against the dump before scoring a model wrong for finding the other
route; the `arm64_pc` entry was corrected mid-run for exactly this.

**Resume is per *cell*, so the log legitimately holds a task twice.** An outstanding task re-runs
its cell's whole list, and the grader keeps the **last** record per (cell, **draw**, task). Do not
"fix" a duplicated task id by deleting rows.

**One draw per cell is what the grid runs, and it cannot answer "X caused Y"** — a rule
`docs/local-model-eval.md` states in as many words and that has not stopped three write-ups (#209
once, #212 twice) from reading a moved aggregate as a controlled result (item 42).
The trap is composition: a total that holds across two runs whose *callers* changed is a
coincidence, not a rate. What answers a rate is `draws: n` on a cell group — the same cell n times,
one thing varied — and the draw index is inside the grader's key, so repeats accumulate instead of
the last one winning. Two consequences when editing that code. **A record with no `draw` is draw
1**, which is the only reason a run recorded before the change still grades to what it graded to,
and it lives in `draw_of` rather than in four `or 1`s. And `--matrix` prints a **distribution** (`3Y2n`)
only when a cell was repeated; a single draw prints the bare mark, so nothing already published is
restated in a new notation.

**And the seed does not replay a draw on this bench, so do not write that it does.** Each draw asks
for `seed: <draw index>` and records it, which is right where a seed reproduces a sample (the
draws become repeatable, and arm A's draw 3 pairs with arm B's). It does not here: four identical
requests to `qwen3.8:27b-mlx` under `seed: 7` returned four different answers (ollama 0.32.15, MLX,
measured 2026-08-24 — after the comment claiming otherwise had already been written). The column is
what was asked for; the distribution over draws is the measurement.

**The Claude Code row needs four fences or it measures something else.** `--strict-mcp-config` (or
it falls back to the editor's registered `windbg-vm`, whose credential is a different client and
gets the whole 51-tool surface — the surface axis then measures nothing); `--disallowedTools` for
the built-ins (or it answers a question about a sample dump by grepping this repository);
`ENABLE_TOOL_SEARCH=false` (or MCP tool schemas are deferred and fetched with `ToolSearch`, so the
surface costs that row almost nothing while every other row pays in full); and a **neutral working
directory**, since Claude Code reads the project it is started in. Its prompt-token column is still
not comparable with the ollama rows — its own system prompt is most of it — and the document says
so rather than quoting it.

**A model "inventing" tools on a narrowed surface is almost always this server advertising them,
and there were two channels; both are narrowed now.** The `instructions` string went per-client
with item 40, and a *tool's description* with item 41 - the descriptions of tools a `crash` client
**is** served used to name `modules` (`open_dump`), `debug_batch` (`interrupt`, `end_session`),
`backtrace` (`crash_triage`) and `go` (`interrupt`), five references on an eleven-tool surface.
Re-running the five `min` cells against item 40's fix (2026-08-24) moved unserved calls 17 -> 14,
and **13 of the remainder named exactly those five**, which is what item 41 then removed. So the
metric is still `unserved` rather than "hallucinated", and it still measures the server before it
measures the model. One call in 61 was a genuine invention, which is the floor.

**It is now two columns, `taught+wanted`** (item 43), split by the task's own `possible_on`: a
reach off the surface on a task this surface *can* answer against one on a task it cannot. Summed
they hide each other, which is the whole argument — re-graded, item 41's fix is `4+10 -> 0+6`, an
elimination of the half it was aimed at rather than a 57% improvement in a total.
`--grade --assert-no-taught` exits non-zero on a taught call and `wanted` is deliberately not
assertable. **The split attributes need, not provenance**: an opener's result taught `modules` on
`unloaded_driver` until #217, and that task is one `min` cannot answer, so those calls are
`wanted`. Lower bound on advertising, upper bound on need.

**Fourth run, five draws of the five `min` cells** (2026-08-25, against #217): `modules` went from
3 of 5 cell-draws to **0 of 25**, and what remains is mostly invented (`execute_command`,
`run_command`). The arms differ by exactly one server behaviour *these tasks reach* - the opener's
summary; the other two paths #217 changed were measured as unexercised (0 user-mode refusals in 95
`crash_triage` calls, 0 post-commit failures) - so this is the cleanest causal read the bench has
produced — with the weakness on the *other* side, which is one draw per cell. Two
things only draws could say: `ioctl_decode` is answered from a frontier model's own knowledge 5/5
and from a local one's 1/5, and **`arm64_pc` is `5n` in every row**, which is what sent someone to
look at the task rather than the models. It went unanswered in all 35 runs in the logs still on
disk, and has been answered right once ever — qwen, in the original grid, reasoning that frame 0
*is* the `pc` (item 44). The key is the literal `pc`, `nt!KeBugCheck2+0x2e8`; almost every model
gives the bug check's parameter 1 instead — the address whose execution faulted. **A task that fails
everywhere is a task to read, not a model to blame.**

**A run records what it ran against, and that is what makes two of them comparable** (item 46).
Every record carries `server` (the build that answered), `model_digest` (the weights behind a
mutable ollama tag), `suite`, and `harness_version` for the Claude rows, which can have no digest -
`opus` and `sonnet` are aliases resolved inside a client this bench does not own. `--compare` reads
two logs with **two rules that are not one rule**: a *changed question* blocks a pairing (via
`stale_prompt`, printed at the row), while a changed build, model or window is *named above the
table* for a reader to weigh - conflating them is how a moved aggregate gets read as a controlled
result. `--series` reduces logs to one row per run in `docs/eval-runs.json`. Six things bite.
**The server's version now carries its git revision** (`0.11.0+g1a2b3c4`), stamped by `build.rs`,
so anything asserting on it is a *prefix* check - and the smoke test additionally asserts the
revision is **there** when built from a checkout, which is the assertion that catches a `build.rs`
that stopped running. **`build.rs`'s watch list and its dirty check are one `INPUTS` const**,
because emitting any `rerun-if-changed` replaces Cargo's default of watching the whole package, and
two lists would disagree about what a clean build is; `-dirty.<digest>` therefore means "the build
inputs differ from that commit", not "the tree is dirty", and the digest is over the diff so two
uncommitted iterations on one `HEAD` are two identities. Git paths go through
`rev-parse --git-path` (and the branch ref through `symbolic-ref`, since `--git-path` takes a path
relative to the git dir and not a revision): a `git worktree` checkout has a `.git` **file**, so a
literal `.git/HEAD` is a watched path that does not exist, which Cargo reads as always-changed and
recompiles the crate on every no-op build. And **the two `/api/ps` facts are one call**
(`runtime_identity`): asking twice could catch different instances and pair one model's window with
another's digest. **The surface and the window are per-cell facts; the weights and the build are
deliberately not** - review asked for both and both were built and then removed, because reaching
the state they guard needs a model re-pulled mid-run or a run spanning a rebuild, and neither
happens here. `tools/` is a developer script and the bar for defending it against states its own
workflow cannot produce is lower than `src/`'s. **A surface is compared by digest, not byte
length** - a same-length reword or an
equal-sized allowlist swap moves neither the count nor the length, though a comparison spanning the
rollout falls back to what both sides recorded and says `unverifiable` rather than `moved` - and **`unrecorded` (nobody
recorded it) is kept apart from `unavailable`** (this row has no such answer), or every run with a
Claude cell reads as a legacy log.

**The key is a snapshot, and `--verify-key` is what re-takes it** (item 45). The six tasks are
graded against facts read off the checked-in dumps with this server's own tools, so a fact that
stops being what the server reports leaves the suite grading and every model scoring against
nothing — a key that has rotted looks exactly like a model that got worse. Each task carries a
`verify` binding of `(tool, args)` steps to the values expected back, and
`WINDBG_MCP_TOKEN=<full surface> python3 tools/local_model_eval.py --verify-key` re-reads the lot.
Five things bite when touching it. **It is a command, not a CI gate**, and that is the decision
rather than an omission: the oracle is `present()`, so a Rust test would need a second copy of
three rules each learned from a wrong verdict — run it after a `dbgscope` bump, a symbol-path
change or a new sample. **The binding grounds `expect`, it does not generate it**: two of
`unloaded_driver`'s three groups are phrasings of a *relation* (`matched: 0` is what "not loaded"
means), so a run reports each group as `value`, `relation` or `skipped`. **Which are relational is
declared (`states`), never inferred** — reading "no pinned value matched" as a relation let a group
edited to a value the tools do not answer pass, which is a broken key reached through the mode
meant to catch one — so a group `grounds` claims but nothing renders is a failure, as is a group
**no** step claims, and a `grounds` group is checked *alternative by alternative* (each must render
or be a **spelling** of one that does), since appending an alternative widens what the grader
accepts without moving anything a whole-group check would see. **The gate is asked per dump**, not once of the host: `docs/smoke-test.md`
records an engine failing differently per dump, so a host-wide gate stands the ARM64 step down over
a missing *x64* PDB — and **a failed probe is a task failure, not a closed gate**, because a closed
gate stands steps down and passes; so are a `modules` answer with no module list and a target with
no `nt`, as is a gated step with no target to probe. **Nothing there reads a structured answer
with a default** - one `probe` helper answers a value or a reason, which is what five review rounds
finding the same shape in six places bought - the last of them a renamed `symbols` on the `nt`
record, which reads as `None` and is not a PDB-backed state, and a `symbols` that is no longer a
string, and a task whose **every** grounding step stands down at a gate is `INCOMPLETE` and
non-zero rather than OK - `driver_blame` has no ungated route where `arm64_pc` does. **Pins compare
types too** (`False == 0` and `227.0 == 227` are true in Python, and one of
those would have hidden a schema change). A `states` group **names the pins its relation
rests on**, so the exemption cannot outlive the fact underneath it. **A pin can be too
tight**: the `pc` fact was first pinned as `registers.32.value`, a position in the ARM64 bank that
an engine may reorder without the key having rotted, so a `read` path enters a list by name
(`registers.name=pc.value`) as well as by index. And **`tools/eval_tasks_v1.json` carries no
binding on purpose** — it is the wording published logs were graded against — so the mode refuses
it by name rather than skipping it.

**Re-run against item 41** (2026-08-24): unserved calls 14 -> 6, with `debug_batch` going 10 -> 0
and every name this server was teaching now gone. What that re-run mostly taught is **how easy it
is to over-read at n=1, in a file that already says so**. Two claims had to be pulled back after
review, and both had passed my own reading first. The three `modules` calls did not move even
though `open_dump` no longer names it - which shows the description is not *necessary*, and not
that it caused none of the earlier three: the callers changed (nemotron/Opus/Sonnet, then
qwen/gemma/Opus), so an aggregate holding at three is a coincidence of composition. And "unserved
on answerable tasks went 4 -> 0" was a **double count** of our own - all four were gemma's
`debug_batch`, so it is the first row again, not independent evidence. What survives is the shape:
every survivor is a direct reach for a module listing on `unloaded_driver`, the one task whose
answer lives in a tool a `crash` client is not served.

**A description reaches every row; the instructions reach two.** `tools/list` is read by all five
rows, so item 41 moved every prompt (-223 tokens on each ollama row, -307 on each Claude one) where
item 40 could not move a local one by a token. Check which channel a prose change travels on before
predicting which columns it can touch.

**And the ollama rows never read the `instructions` at all**, which is what nearly made that fix
look bigger than it is. `tools/local_model_drive.py`'s handshake keeps the negotiated protocol
version and discards the rest of the `initialize` result, so a local row's prompt is the
one-sentence system prompt plus `tools/list`: narrowing that string cannot move those prompt-token
columns by one token, and it did not. Claude Code injects a server's instructions into its own
system prompt, so the two control rows are the only ones any instructions measurement is about.
Check which half of the bench a prose change can reach before predicting what it will do.

**The bench listener is the shipped per-client feature in anger.** `tools/bench_listener.ps1`
serves `full`, `lean` and `min` from one foreground process, tokens arriving on **stdin**; its
startup line naming the three clients and their surfaces is the check that the run is measuring
what it thinks. A cell changes the bearer token and nothing else.

