# The local-model eval

[`local-model.md`](./local-model.md) is the runbook for pointing a local model at this server, and
it records two runs of one model on one surface. This page is the **grid** those two runs argued
for: three local models, three tool surfaces and three context windows, scored against an answer
key, with a frontier model in the same harness as the control.

It exists because the two sightings could not settle the question they raised. One model picking
nine tools correctly says a 51-tool surface is drivable *by that model, at that window*; it says
nothing about which of the three knobs — the model, the surface, the window — was carrying the
result. A grid can, because it moves one at a time.

- The harness is [`tools/local_model_eval.py`](../tools/local_model_eval.py), over
  [`tools/local_model_drive.py`](../tools/local_model_drive.py) and
  [`tools/claude_code_drive.py`](../tools/claude_code_drive.py).
- The tasks and their answer key are [`tools/eval_tasks.json`](../tools/eval_tasks.json).
- The listener the run drives is a foreground one with three clients:
  [`tools/bench_listener.ps1`](../tools/bench_listener.ps1).

## The three axes

**The tool surface**, which is bytes of prose in every turn. Since
[#196](https://github.com/glslang/windbg-mcp/pull/196) a surface is a property of the *client*
rather than of the run, so all three exist on one listener at once and a cell changes nothing but
which bearer token the driver presents:

| Client | `--tools` spec | Tools | Surface bytes | Prompt tokens, by model |
| --- | --- | --- | --- | --- |
| `full` | *(none — the whole surface)* | 51 | 69,552 | 14,540 / 17,270 / 18,501 |
| `lean` | `session,inspect,crash` | 20 | 26,057 | 5,906 / 6,385 / 6,673 |
| `min` | `crash` | 11 | 15,544 | 3,447 / 3,838 / 3,926 |

Bytes are the surface **as handed to the runtime** — minified JSON in ollama's function shape,
which is what the model is actually served. That is not the same measure as
[`token-budget.md`](./token-budget.md)'s, which counts the surface as MCP reports it: 67,658 B for
the same 51 tools, 25,265 for the same 20, 15,073 for the same 11. The function-call wrapper is the
difference and it is a flat ~3% on all three, so either figure supports the arithmetic below —
quote whichever matches what you are measuring, and do not mix them in one sum.

Both columns are **the server this grid ran against**. `FOLLOWUPS.md` item 41 has since taken the
narrowed surfaces down again — `crash` is 14,138 B rather than 15,073, `session,inspect,crash`
24,445 rather than 25,265 — so read the table above as the run's conditions and
[`token-budget.md`](./token-budget.md) for today's.

**The last column is a finding, not a caption.** Identical bytes cost gemma 14,540 tokens, qwen
17,270 and nemotron 18,501 — a 27% spread on the same surface, entirely tokenizer. So "does the
surface fit" has no single answer even at one surface size and one window, and the ≈4 B/token rule
of thumb `local-model.md` records is a per-model constant rather than a shared one.

**The context window**, which is what the runtime will actually hold — not what the model card
says. `OLLAMA_CONTEXT_LENGTH` picks 4k, 32k or 256k from the box's memory, so the eval sets
`num_ctx` per request instead of trusting a default: 262,144 (what this bench serves), 32,768, and
8,192, which is smaller than the 51-tool surface and is in the grid precisely for that reason.

**The model.** Three ~30B-class MLX builds, all declaring the `tools` capability and all with a
262,144 context length on their card, plus Claude through Claude Code as the frontier control.

## What is deliberately not an axis

**The prompt.** One system prompt, one sentence long, identical everywhere:

```text
You are a Windows kernel debugging assistant. Use the provided tools to answer.
Call one tool at a time and use its result. Be concise.
```

Nothing is tuned per model. A model that needs a bespoke prompt to drive this surface is a finding,
not a cell to fix.

**Thinking.** Every local model here can think, and every cell runs with `think: false`. That is a
controlled variable rather than a recommendation — the two runs in `local-model.md` had already
found that a thinking turn can outlive the listener's lease grace, which is a real cost with its
own follow-up (`FOLLOWUPS.md` item 33) and would have confounded every timing here.

**The tools themselves.** The harness executes a read-only allow-list and reports anything else
back to the model as refused, so a wrong pick is *measured* rather than performed. `launch`,
`execute` and `debug_batch` are on the surface and are never run: a debug host is the wrong place
to discover unattended what a model does with them.

## The tasks, and why these six

Six questions with facts behind them, read off the checked-in sample dumps with this server's own
tools **before any model saw them** and recorded in `tools/eval_tasks.json` as the answer key.

| Task | Asks for | Answerable on |
| --- | --- | --- |
| `bugcheck` | the bug check of the x64 `MessageManager` dump | all three surfaces |
| `driver_blame` | which third-party driver crashed, and at what offset | all three surfaces |
| `module_count` | how many modules are loaded in the `0x9F` dump | all three surfaces |
| `unloaded_driver` | whether `nvhda64v.sys` is loaded, and what is left of it | `full`, `lean` |
| `arm64_pc` | the `pc` register in the ARM64 `0xFC` dump | all three surfaces |
| `ioctl_decode` | the four `CTL_CODE` fields of `0x22200B` | `full` |

The third column is the point of the surface axis, and it is why the grader reports **correct out
of possible** rather than a bare score: on `min` two of the six tasks have no tool that can answer
them, and counting those as failures would say a small surface makes a model stupid rather than
that it makes tools absent.

**Four of the six are answerable on every surface, and that is itself the finding.** `open_dump`'s
own summary carries the bug check and the module count, so a model that reads its opener's answer
needs neither `crash_triage` nor `modules`; `crash_triage`'s frame 0 carries the `pc` that
`registers` reports. Cutting the surface from 51 tools to 11 removes far fewer *answers* than it
removes tools, because the facts are reachable by more than one route — which is the opposite of
what the tool table predicts, and is why the third column was written from the tools and then
corrected from the run.

`ioctl_decode` is the deliberate trap. The tool that answers it is on one surface of the three, and
what the other two measure is what a model does when the tool it wants is not there: decline, ask
for it anyway, or compute the answer itself — `CTL_CODE` is arithmetic, and a model that knows the
macro can decode a code with no tool at all.

**One of the six has been reworded since every run on this page** (2026-08-25, `FOLLOWUPS.md`
item 44). `arm64_pc` used to ask for "the value of the `pc` register at the point of the crash",
which reads as the address whose execution faulted — bug check parameter 1 — rather than as the
register's value; it now asks for the register's own value as the debugger reports it, and not for
an address taken from the bug check's parameters. **Every score below was graded against the old
wording**, so none of them is comparable with a run against the current one on that task. The other
five prompts were re-read against their keys at the same time and none has the same defect; what
the check did find is in each task's `note` in `tools/eval_tasks.json`, and the measurement that
prompted it is the fourth run below.

**So a run's identity includes the question it asked**, and the old wording is kept as
[`tools/eval_tasks_v1.json`](../tools/eval_tasks_v1.json) rather than overwritten. The two
checked-in plans name it, which is what keeps this page re-gradable: `usable()` drops every answer
to a question the suite no longer asks — correct for a resume, and the reason a reworded task would
otherwise both shrink these tables' denominators and let a *resumed* plan append new-wording
answers under the same (cell, draw, task) key as the old ones. Grade a published log against the
suite its plan names; grading one against the live suite drops those records and says so under the
table.

## Grading

Mechanical, and stated so it can be argued with:

- **`correct`** — every group in the task's `expect` list appears in the final answer, any
  alternative within a group counting, case-folded. So `0x13A` and `13a` both pass, and an answer
  must carry *both* the code and the name.
- **`possible`** — whether the answer key is reachable on that surface at all.
- **Tool calls** are split five ways, because the ways a call can go wrong are not one finding:
  `useful` (a tool the task needs, and it worked), `wasted` (worked, but nothing to do with the
  question), `off_surface` (the server refused it — on a narrowed surface, the tool is not served),
  `refused` (the harness's read-only fence), and `errored`.
- **`unserved`** — a call naming a tool this client is not served, printed as **`taught+wanted`**
  because it is two measurements that hide each other:
  - **`taught`** — the task *was* answerable on this surface, so nothing about the question
    required a name off it. The model got that name somewhere, and this server is the likeliest
    somewhere. A regression here is a defect in the server, and `--grade --assert-no-taught`
    exits non-zero on one.
  - **`wanted`** — the task is *not* answerable here and the model reached for the capability that
    would answer it. That is the model being right and the surface saying no. It can grow without
    anything being wrong, so nothing asserts on it.

  It was called `hallucinated` until the first run was read properly; see below, because the server
  is where all but one of those names came from. **What the split attributes is need, not
  provenance**: this server taught `modules` through an opener's *result* until
  [#217](https://github.com/glslang/windbg-mcp/pull/217), on a task `min` cannot answer, so those
  calls land in `wanted`. Read `taught` as a lower bound on advertising and `wanted` as an upper
  bound on need; separating them properly is one cell repeated with the sentence varied, which is
  what `draws` is for.

Nothing is graded by a model. A substring check accepts an answer a reader would not in exactly one
direction — a model that lists every bug check code including the right one — and every cell's raw
transcript is kept so a suspicious pass can be read.

### Two corrections the run forced, and why they are not cheating

Grading happens **at the end, over the whole log**, so a key corrected mid-run scores every cell —
the ones already recorded included — by the same final rule. Both corrections came from reading
answers the first key had scored, and both made the key stricter or truer rather than kinder.

**A number must not match inside a longer number.** `0x22` is the device type `ioctl_decode` asks
for and `0x22200B` is the code in the question, so plain containment passed for any answer that
merely repeated the question. One model, with no `decode_ioctl` on its surface, did the bit
arithmetic in prose, miscounted twice in full view, and presented a confident table saying
`FILE_DEVICE_KEYBOARD` and `FILE_READ_DATA` — both wrong — and scored correct. Numeric
expectations now match only between hex boundaries.

**`unloaded_driver` requires the count, and the prompt now asks for it.** On the 11-tool surface a
model with no `modules` answered honestly that it could not check, added that "a kernel-mode dump
does not retain a history of drivers that loaded-then-unloaded" — which is false, and is exactly
what the tool would have told it — and scored correct on the words *not loaded* and *unloaded*. The
26 unload records are the half of the question only the tool can answer, so requiring them
separates reading from guessing. That first went in as a stricter key over an unchanged question,
which review rightly called a key asking for a fact the prompt did not request; the question now
asks *how many* records the dump still carries, and **every cell of that task was re-run under it**
— no score moved, because every model that had the tool had already volunteered the number.

One prediction in the key was simply wrong, and the run found it: **`arm64_pc` is answerable on
every surface**, not only where `registers` is served. `crash_triage`'s frame 0 on that dump is
`0xfffff8013c65bca8`, which is the `pc` the register read reports — the same fact by another
route. Verified against the dump before the key was changed, and it is the kind of thing a grid
finds that a prediction does not: two tools carry one fact, so narrowing a surface removes fewer
answers than the tool table suggests.

### The key is a snapshot, and `--verify-key` is what re-takes it

Every fact above was read off the checked-in dumps with this server's own tools before any model
saw them. That is what makes the bench mechanical, and it is the whole exposure: if one of those
facts stops being what the server reports, the suite goes on grading, every model goes on scoring,
and the number measures nothing. **A key that has rotted is indistinguishable from a model that got
worse.**

So each task carries a **`verify` binding** beside its `expect` — an ordered list of
`(tool, arguments)` steps with the values expected back — and one command re-reads the lot:

```console
WINDBG_MCP_URL=http://127.0.0.1:8766/ WINDBG_MCP_TOKEN=<the full surface's token> \
  python3 tools/local_model_eval.py --verify-key
```

It opens each dump itself, calls the tools a model would call, and checks every pinned value.
Nine things it catches, each of which is a way the key rots without anything looking wrong:

| What moved | How it reads |
| --- | --- |
| a fact — the dump now has 228 modules | `modules loaded: answered 227, pinned 228` |
| a field — the answer's shape changed under it | `crash_triage bug_check.code: no such field in the answer` |
| a question — the prompt was pointed at another sample | `the prompt names …082126-7015-01.dmp, which no step of the binding opens` |
| a key, widened — `expect` grew an alternative nothing fetches | `group 3 (0xfffff8033d680000) is grounded by no step` |
| a key, wrong — a group edited to something the server does not say | `group 1 (access_violation) is in nothing this task pinned - the server answers 0x13a, kernel_mode_heap_corruption` |
| a key, too permissive — a group that also accepts something else | `group 1 also accepts access_violation, which is no spelling of anything this task pinned` |
| a relation whose fact went — the pin a `states` group rests on was deleted | `group 0 (...) is a relation over matched, which this task no longer pins` |
| a binding — a gated step ordered before the step that opens its target | `crash_triage needs the kernel_symbols gate but no step before it opened a target to probe` |
| a tool — `decode_ioctl` stopped saying `METHOD_NEITHER` | `decode_ioctl @text has 'METHOD_NEITHER': not in the answer's text` |

**The binding carries the inputs, which is the half the suite used to lack.** `expect` says what an
answer must *contain*; nothing structured said what to **call** to get it — a task's dump path
lived only in its prose prompt, and `useful_tools` names tools with no arguments and no order. A
task later pointed at a different sample would therefore have left a verifier querying the old one
and matching expectations that never changed: green, and drifted. So the prompt is checked as a
*rendering* of the binding rather than as its only home — every string a step sends must appear in
the question, and every dump the question names must be one a step opens.

**Two verbs, and the difference is the server's own doing.** `is` is exact typed equality against a
named field — `227` the integer is not `"227"` the string, nor `227.0` the float, nor `0` the
boolean `False`, all of which Python's own `==` would have accepted; a renamed field is a failure
rather than a pass. `has` is the grader's own `present()` over the answer's text, for a tool with no
structured half to name a field in — `decode_ioctl`, which is also the one task needing no target
at all.

**A `read` path enters a list two ways, and the second is usually the right one.** `frames.0` is a
position; `registers.name=pc.value` is the register *called* `pc`. The `pc` fact sits at entry 32
of the ARM64 bank, and a pin on 32 would fail on an engine that reordered the bank while still
answering the question the task asks — which would be a false alarm about a key that had not
rotted.

**A step ties a pin to the group models are graded on, and says *how* — declared, not inferred.**

- **`grounds`** — the group is answered by a value the server prints, checked through that same
  `present()`. A claimed group nothing renders is a **failure**, which is the row above: an
  `expect` edited to a value the tools do not answer is a broken key, and every model would be
  graded wrong by it.
- **`states`** — the group is a phrasing of a *relation* over pinned facts rather than a string the
  server prints. `unloaded_driver`'s "not loaded" is what `matched: 0` *means*. That is not a hole —
  the fact behind it is pinned exactly, and only the phrasing is beyond a mechanical check — but it
  is declared **per group** and **names the pins it rests on** (`{"0": ["matched"]}`), so the
  exemption covers the two that earn it, cannot spread, and cannot outlive the fact underneath it:
  deleting the `matched` pin fails rather than leaving the relation reported.
- **`skipped`** — every step claiming it stood down at a gate on this host, which has to be its own
  word: calling it anything else would claim a check this run did not make.

Inferring `relation` from "no pinned value matched" was the first cut, and it was a hole review
found: a group edited to `ACCESS_VIOLATION` for a bug check that is `KERNEL_MODE_HEAP_CORRUPTION`
simply reported `relation` and passed — a broken key reached through the mode meant to catch one.

**And a `grounds` group is checked alternative by alternative, not as a whole**, which closes the
same hole pointed the other way: `expect` *appending* `access_violation` beside a `heap_corruption`
that still matches would widen what the grader accepts while the run stayed green. So every
alternative must render against a pinned value, or be a **spelling** of one that does — letters and
digits only, which is why the suite can list `heap corruption` beside `heap_corruption` (a model
writes prose where a tool writes an identifier) and `` fffff801`3c65bca8 `` beside the plain hex,
while `access_violation` is refused as a second *fact* rather than a second spelling.

A group **no** step claims is a failure too, and that is the ratchet: `expect` cannot grow a fact
the binding does not fetch, and a new task cannot arrive unpinned — nor with **no** `expect` at all,
which is the same hole at the other end and worse than it sounds: `matches()` runs `all()` over the
group list, and `all([])` is true, so a task with no groups grades every answer correct.

**Which corpus is asserted, said rather than implied.** The run names the dumps it re-read and then
names the ones it did not: `answer_key` is prose, nothing reads it — `matches()` grades from
`expect` alone — and it describes the whole sample corpus including `082126-7015-01.dmp`, which no
task references. The two disagree by construction, so the run reports the gap instead of quietly
covering more or less than the suite.

**What stands down where symbols do.** Two steps walk `nt`'s types — `driver_blame`'s stack walk
and `arm64_pc`'s frame 0 — and on a host whose engine resolves no PDB a stack walk gives back
frames made of the bug check's own parameters. Those print `SKIPPED` with the reason, much as
the Rust tier does — but any `expect` **group** whose grounding steps all stand down makes the run `INCOMPLETE` and
non-zero, because "verified nothing about this fact" is not a result a script should read as
success. The unit is the group, not the task: a task can come back mixed, one group grounded by an
ungated step and another only by a gated one, and calling that verified would report a graded fact
as checked having read nothing of it. `driver_blame` loses both of its groups that way, where
`arm64_pc`'s survives — its group is grounded by `registers` *and* by frame 0. The key has not rotted
there; the host cannot say either way; [`smoke-test.md`](./smoke-test.md) has the line and the measurement behind it,
and this mode deliberately keeps no second copy of either. **The gate is asked of each task's own
dump**, not once of the host: that same document records an engine failing *differently per dump*,
so a gate taken off the first opener could stand the ARM64 step down because an x64 PDB was
missing, and report success without checking the route `arm64_pc` depends on. **A probe that fails
is not a closed gate**, either: a gate that closes stands its steps down and *passes*, so a probe
answering an error would turn every gated assertion into a silent no-op — it is a task failure
instead, as is a `modules` answer carrying no module list, one whose module list is no longer a
list, a kernel target with no `nt` in a listing filtered for it, and an `nt` record carrying no
`symbols` field, and a `symbols` that is no longer a string. Only "`nt` resolved, without a PDB"
closes the gate — any *other* string closes it too, since the set of symbol states can legitimately
grow and one this verifier has not heard of is not a rotted key. **Nothing in this mode reads a structured answer with a default** — one helper
returns a value or a reason, which is what stopped five review rounds finding the same shape in
five places. `arm64_pc` is asserted through **both**
routes — `registers`, which needs nothing, and frame 0, which does — because frame 0 is the route
the task's `possible_on: min` depends on and `registers` alone would not be checking it.

**It is a command, not a CI gate, and that was the decision.** The oracle is `present()`, whose
three rules were each learned from a wrong verdict; a Rust test in `tests/mcp_smoke.rs` would need
a second copy of it, and two copies drifting apart is this failure mode reached through its own
fix. The Rust tier goes on pinning what it already pins — the bug checks, `Arg1`, the crashing
process, each driver crash's `module`+`rva` — and this pins what the *tasks* depend on, through the
tools a model would call. Run it after a `win-kexp` bump, a symbol-path change, or a new sample
replacing an old one; nothing else will.

## Running it

Three pieces, and only the first is unusual.

**A listener with three clients**, started in the foreground so nothing is installed and no
credential is written to disk. The tokens go in on **stdin**, never on a command line:

```console
python3 -c "import json,secrets;print(json.dumps({n:secrets.token_urlsafe(32) for n in ('full','lean','min')}))" > bench-tokens.json
chmod 600 bench-tokens.json
scp tools/bench_listener.ps1 <vm>:C:/Users/<you>/bench_listener.ps1
ssh -L 8766:127.0.0.1:8766 <vm> 'powershell -NoProfile -File C:\Users\<you>\bench_listener.ps1' < bench-tokens.json
```

Its startup line is the check that it worked — it names the clients and what each is served:

```text
listening on http://127.0.0.1:8766 (… clients: full, lean, min, serving all 51 tools
 — except lean serves 20 of 51 tools (session, inspect, crash), min serves 11 of 51 tools (session, crash))
```

**Ending the ssh command stops it; *killing* the ssh client does not.** A graceful exit takes the
listener with it (`remote-listener.md` measured that), but a tunnel that is killed from this side
leaves sshd with no reason to tear anything down, and the listener keeps running and keeps the
port — the next run then fails to bind with `Only one usage of each socket address` and looks like
a busy machine rather than a leftover. Stop it **by the PID that owns the port**, never by image
name: the installed service is the same executable, and taking that down drops the sessions
whatever else is connected to this host is holding.

```pwsh
$svc = (Get-CimInstance Win32_Service -Filter "Name='windbg-mcp'").ProcessId
$own = (Get-NetTCPConnection -State Listen -LocalPort 8766 -ErrorAction SilentlyContinue)[0].OwningProcess
if ($own -and $own -ne $svc) { Stop-Process -Id $own -Force }
```

**A plan**, naming the models, the surfaces, the contexts and the per-cell wall-clock budget. The
one this page's run used is checked in as [`tools/eval_plan.json`](../tools/eval_plan.json), so the
grid is re-runnable rather than described:

```json
{
  "run": "2026-08-23",
  "tasks": "tools/eval_tasks_v1.json",
  "url": "http://127.0.0.1:8766/",
  "out": "eval-out/results.jsonl",
  "surfaces": [{ "client": "full" }, { "client": "lean" }, { "client": "min" }],
  "cells": [
    { "backend": "ollama", "models": ["qwen3.8:27b-mlx"],
      "contexts": [262144], "surfaces": ["full", "lean", "min"], "budget_s": 2400 }
  ]
}
```

`surfaces` at the top level names every client the run may present — each entry an object with a
`client`, which is the name the token file uses. Inside a cell group, `surfaces` is a list of those
same names as plain strings. Paths are resolved when the plan is read, so they may be relative to
wherever you run it from.

The tokens are *not* in the plan: a plan is checked in, a credential is not.

```console
EVAL_TOKENS=bench-tokens.json python3 tools/local_model_eval.py tools/eval_plan.json
```

Cells are subprocesses and the log is append-only, so a run that dies in the middle leaves every
finished cell on disk and re-running the same plan resumes rather than repeating. A cell that
overruns its budget is killed and *that* is recorded — a model which cannot finish inside a
generous wall clock has told you something. **Each cell clears its own credential's sessions
before it starts**, rather than the previous one tidying up after itself: however a cell ended —
finished, killed, crashed — the next one begins with nothing of its own attached, and no cleanup
has to have succeeded for that to hold.

And a record whose *served* window is not the one it asked for is not scored at all: the runner
evicts between windows to stop it happening, and the grader refuses to publish it if the eviction
ever fails. Such a record is also not counted as done, so re-running the plan re-runs it.

**Grading, separately**, over the log:

```console
python3 tools/local_model_eval.py --grade results.jsonl tools/eval_tasks_v1.json
```

**The suite argument is the one that log's plan names**, not whichever suite is current — the plan
above writes `results.jsonl` and names `tools/eval_tasks_v1.json`, as does every log this page
reports. It is optional and defaults to `tools/eval_tasks.json`, so a published log graded with the
default silently loses each record whose question has been reworded since; the count and what to do
about it print under the table.

### Repeating a cell, when the question is a rate

The grid runs **one draw per (model, context, surface, task)**, which is what the first three runs
on this page are; the fourth (2026-08-25) repeats each cell five times and is the only one that
does. That is enough for the two things it was built for — failure *modes*, and whether a
surface fits at all — and it is not enough for any sentence of the form "X caused Y". Three
write-ups here reached past that anyway and review took two of them back
(`FOLLOWUPS.md` item 42); the trap each time was a cell whose *composition* also changed, so an
aggregate that held across two runs of different models read as a stable rate rather than as the
coincidence it was.

What answers a rate is the same cell run *n* times with one thing varied. A cell group asks for
that with `draws`, and changes nothing else:

```json
{ "backend": "ollama", "models": ["qwen3.8:27b-mlx"], "contexts": [262144],
  "surfaces": ["min"], "subset": "short", "draws": 5, "budget_s": 2400 }
```

The draw index is part of a record's identity, which is what makes repeats **accumulate** rather
than replace each other:

- Resume works per draw. A plan that ran 3 and now asks for 5 runs draws 4 and 5 and repeats
  nothing.
- The grader counts over draws. Deduplicating on (cell, task) alone — which is what it did — would
  collapse *n* draws to the last one, so a repeated cell would measure exactly as much as a single
  one.
- `--matrix` prints a distribution where it printed a mark: `3Y2n` is five draws, three of them
  correct. One draw still prints `Y`, so every matrix on this page reads as it did.
- A draw that dies is recorded against *that* draw: its row reads `FAILED on 2 draws` when more
  than one of them did, and the draws it never recorded count as `x` in each task's distribution.
  `1Y1x` is a cell that was asked for twice and answered once — a bare `Y` there would be
  indistinguishable from one clean draw, which is the denominator this whole section is about.
  A task **no** draw reached reads `2x` rather than a blank, because a dead draw's note carries
  the ids it was going to run; a blank still means the cell was never asked for that task, which
  is what a group's `subset` does.

A record written before draws existed is draw 1, so the runs already on disk grade to exactly what
they graded to.

**The seed is recorded and does not replay a draw here.** Each draw asks the runtime for a `seed`
of its draw index — free to send, and where a seed reproduces a sample the draws become
repeatable and arm A's draw 3 pairs with arm B's rather than averaging against it. It does not
reproduce one here: measured 2026-08-24, four identical requests to `qwen3.8:27b-mlx` under
`seed: 7` (ollama 0.32.15, MLX) returned four different answers. So the column says what was *asked for*, the
draws vary regardless — which is what a rate needs — and nothing here claims a draw can be
replayed. The Claude Code rows have no seed to ask for at all, and record a null.

**The experiment this exists for is an A/B, and it is two runs rather than a bigger plan**: the
same cell, with and without the prose under test, into two logs, and the two distributions
compared. The variable is a server build, so no single plan can hold both arms. The question that
prompted it — did `open_dump`'s description ever contribute to a `modules` call? — is still not
worth the runtime: that sentence is gone either way, and the fix never depended on which of the two
channels carried it.

### Comparing two runs, which needs a run to say what it ran against

**Re-running a cell is the point, not a hazard.** As models are updated the same question on the
same surface will be asked again, and what will matter is run N against run N-1. The frozen suite
exists so a *reworded question* cannot silently un-grade its own history — a different thing from
discouraging a rerun. What this bench could not do until now was **compare two of them**.

A record identified the question and the surface, and neither of the two things that change over
time. So every record now also carries:

| Field | What it settles | Where it comes from |
| --- | --- | --- |
| `server` | which **build** answered — `windbg-mcp 0.11.0+g1a2b3c4` | the `initialize` result, which the handshake used to discard |
| `model_digest` | which **weights** answered, behind a mutable tag | `/api/ps`, beside the window it already reported |
| `harness_version` | the Claude row's floor: what resolved the alias | `claude --version` |
| `suite` | which task list the questions came from | the file the driver loaded |

**The build is the one that had to be added on the server side.** `surface.bytes` is a real
fingerprint of the tool prose and moved when item 41 landed — and it is a fingerprint of *one
channel*, silent on exactly the one the last three findings were about, since
[#217](https://github.com/glslang/windbg-mcp/pull/217) changed an **opener's result**. And a crate
version is a floor rather than an identity, since it moves only on release: two builds of `0.11.0`
were indistinguishable. So `build.rs` now stamps the git revision into the version this server
reports, and the same string goes into a transcript's `start` record.

**`qwen3.8:27b-mlx` is a name, not a model.** It can be re-pulled onto different weights, so two
runs a month apart can agree on every other recorded field and have been different models — the
axis the whole comparison is about. The digest is a content address and settles it. **The two
control rows cannot have one**: `opus` and `sonnet` are aliases resolved inside a client this bench
does not own, and there is no `/api/ps` to ask, so they record `model_digest: null` beside the
harness version, which is a floor. Naming a real version source for a Claude row is open.

Then:

```console
python3 tools/local_model_eval.py --compare eval-out/after-206.jsonl eval-out/after-210.jsonl \
  tools/eval_tasks_v1.json
```

```text
cell                                 bugcheck  driver_blame  module_count  unloaded_driver  arm64_pc  ioctl_decode
opus   dflt min                      Y -> Y    Y -> Y        Y -> Y        - -> -           n -> n    o -> o
sonnet   dflt min                    Y -> Y    Y -> Y        Y -> Y        - -> -           n -> n    o -> o
gemma4:31b-mlx 262144 min            Y -> Y    Y -> Y        Y -> Y        - -> -           n -> n    o -> -
nemotron-3.5-lightning:3 262144 min  Y -> Y    Y -> Y        Y -> n        - -> -           n -> n    - -> -
qwen3.8:27b-mlx 262144 min           n -> Y    Y -> Y        Y -> Y        - -> -           n -> n    o -> -

old -> new per cell-task; `(old)`/`(new)` is a cell only one run covered.
```

Those two runs were recorded before the identity fields existed, so nothing above the table names a
moved variable — which is exactly what a pair of logs written today would not look like. The two
lines that appear when something did move were checked against a log doctored to move them:

```text
  moved between these runs, besides the question: suite, server, harness, weights
--  not compared for arm64_pc: the question changed between these runs
```

**Two rules, and they are not the same rule.**

- **A changed question blocks a pairing.** It does not annotate one. `arm64_pc` has the same id in
  `eval_tasks_v1.json` and `eval_tasks.json` and a materially different prompt, so pairing on the
  id would put two distributions side by side that the frozen suite established are not comparable
  — and would be *laxer than the grader already is*, since `usable()` refuses such a record
  outright. The predicate is `stale_prompt`, the same one the grader uses, and the refusal is
  printed at the **row** with its reason, which is the principle the `UNCOUNTED` line beside it
  follows. It is a floor: `expect` can move too, and a pairing predicate reading only the prompt
  catches the change the frozen suite was about and not every change there could be.
- **Everything else is named above the table.** The build, the weights, the harness, the suite —
  the uncontrolled variables that are *not* the question. Naming them is not a nicety: this repo
  has three times read a moved aggregate as a controlled result, and every one was a **composition**
  error, where the callers changed and the total held.

**And a series, so history is a query rather than a re-reading.** This page accumulates a prose
section per run, which reads well and cannot be diffed — the tables in it measure different
servers, which the page says in words and no reader can check.
[`eval-runs.json`](./eval-runs.json) is the machine-readable half, one row per run keyed by the
identity above:

```console
python3 tools/local_model_eval.py --series eval-out/*.jsonl tools/eval_tasks_v1.json \
  -o docs/eval-runs.json
```

The three runs already in it read `unrecorded` for every identity field, and that is the point
rather than an omission: **a run recorded without identity cannot have it added later.** Each of
those write-ups names its own server build in prose, which is why nothing published is wrong; what
was missing was any way to *check* it, and to do it for a run nobody has written up yet.

## What one grid showed

Run 2026-08-23, on the ARM64 bench described in `local-model.md`: 33 cells, 144 task runs, about
three hours of wall clock. The raw log, every answer and every tool call are what the tables below
are reduced from. A second, narrow run followed on 2026-08-24 — the five `min` cells against the
server fix this one found — and is reported in its own section rather than folded into these
numbers, because a table that mixed two servers would answer neither question.

### At the window this bench actually serves

Six tasks, 262,144 tokens, **correct out of answerable** — the denominator moves with the surface
because two of the six have no tool to answer them on `min`:

| | `full` (51 tools) | `lean` (20) | `min` (11) | answerable, total |
| --- | --- | --- | --- | --- |
| **Opus** *(control)* | 6/6 | 5/5 **+1** | 3/4 **+1** | **14/15** |
| **Sonnet** *(control)* | 6/6 | 5/5 **+1** | 3/4 **+1** | **14/15** |
| qwen3.8:27b | 6/6 | 5/5 | 4/4 | **15/15** |
| gemma4:31b | 6/6 | 5/5 | 3/4 | **14/15** |
| nemotron-3.5-lightning:30b | 4/6 | 3/5 | 3/4 | **10/15** |

The **+1** is the trap task answered without the tool that answers it, and it is kept outside the
score rather than added to it: both control rows decoded `0x22200B` correctly from the `CTL_CODE`
layout on a surface where `decode_ioctl` is not served. gemma does it too at the reduced windows.
qwen tries and gets it wrong — twice, in prose, in full view.

**The one clean sweep of answerable tasks belongs to the 27B local model**, because both control
rows drop `arm64_pc` on the narrowest surface — the cell two sections down. Read that as the task
set being within reach rather than as a ranking: four of the five models are within one answer of
each other, the fifth is five behind, and the control's own miss is the most useful single result
here, since a question the frontier gets wrong is a question worth re-reading. **And read the sweep
itself as one draw**: re-running the `min` column alone took that cell from 4/4 to 2/4 with nothing
changed that qwen reads (below), which is what a single sample per cell is worth.

That is not a claim that local models are as good. It is a claim about *these questions*, which
are the shape a debugger MCP server is asked most often — open a target, read a field, name a
module, decode a constant.

### The surface axis cost less than the tool table predicts

Cutting 51 tools to 11 removes 40 tools and **two answers**. Two of the six tasks survive the cut
because `open_dump`'s summary carries the bug check and the module count, and a third survives
because `crash_triage`'s frame 0 is the `pc` that `registers` reports. Facts here are reachable by
more than one route, and the narrow surface keeps the routes that matter.

What the cut *does* produce, in every row including the control, is **calls to tools that are not
there** — and most of the reason is this server, not the models. The **after** column is the same
five cells re-run against the fix, two sections down:

| Cell | Unserved calls | After | What it asks for now |
| --- | --- | --- | --- |
| gemma4 `min` | 9 | 9 | `debug_batch`, every one of them — five on one task, four on another |
| Opus `min` | 4 | 3 | `modules`, `debug_batch`, and `list_modules`, which no surface serves |
| Sonnet `min` | 2 | 1 | `modules` |
| nemotron `min` | 2 | 1 | `modules` |
| qwen `min` | 0 | 0 | — |
| every `full` and `lean` cell | 0 | not re-run | — |

**The models were told about those tools by the server**, and the re-run corrected *which part* of
the server told them. `#196` narrows `tools/list` per client; it did not narrow the `instructions`
string sent at `initialize`, which was a compile-time constant naming twenty-one tools — `modules`,
`execute`, `decode_ioctl` and `debug_batch` among them. Measured against this bench: the `min`
client is served **11** tools and told about **21**, of which **17 it cannot call**. Every
off-surface call in the table above is one of those seventeen.

**Only the two control rows ever read that string, though.** `tools/local_model_drive.py`'s
handshake keeps the negotiated protocol version and discards the rest of the `initialize` result,
so an ollama row's prompt is the one-sentence system prompt plus `tools/list` and nothing else.
Claude Code injects an MCP server's instructions into its own system prompt; the bare `/api/chat`
loop does not. So gemma's nine `debug_batch` calls and nemotron's `modules` came from the *other*
place this server names tools a client may not be served — the **descriptions of the tools it is
served**. `open_dump`'s says the module table is "what `modules` lists"; `interrupt`'s and
`end_session`'s both name `debug_batch`; `crash_triage`'s names `backtrace`; `interrupt`'s also
names `go`. Five references on the 11-tool surface, naming four tools it cannot call.

So this is not invention: not one of the seventeen is a name this server does not have, which is
why the column that used to be called `hallucinated` is `unserved`. (The re-run turned up exactly
one that is — Opus asking for `list_modules` — so the floor is not zero.) It
is a real cost — wasted turns, and gemma's whole turn budget
on one task — but it is the cost of the server advertising what it will then refuse. What makes it
recoverable is *a* refusal rather than the server's: `debug_batch` is on the harness's read-only
fence, so gemma's loop never reaches the listener at all and is answered `refused: debug_batch is
not permitted in this harness`. Opus and qwen decline honestly after either wording; gemma re-asks
until it runs out.

The instructions string is also **1,990 characters (~497 tokens) charged identically to every
client that reads it**, of which **59% is sentences naming only tools the `min` client cannot
call** — about 12% of such a client's entire prompt, and 0% of the three ollama prompts here,
which never carried it. A narrowed surface drops 54,000 bytes of schemas and keeps every word of
the prose advertising what was dropped.

### Same surface, same tool output, three different outcomes

The `arm64_pc` task on the 11-tool surface is the cell worth reading in full. All three local
models opened the dump and ran `crash_triage`; all three had exactly the same text in front of
them:

- **qwen** reasoned that frame 0 of the bug-check stack *is* the `pc`, and answered
  `0xfffff8013c65bca8`. Correct, by the route the answer key had not predicted.
- **gemma** called `debug_batch` four times, was refused four times, ran out of turns and returned
  nothing at all.
- **nemotron** answered `0x0000019e7b820000` — bug check parameter 1, the address that was
  executed. Confident, plausible, wrong.

**Opus makes nemotron's mistake here**, reasoning explicitly that the value "matches parameter 1
exactly". On the narrowest surface the 27B local model was the only one to get it right. Failure
modes, not scores, are what separate these rows: only one of those three failures is visible to
whoever asked the question.

**And on the re-run, qwen made it too** — same cell, same surface, same two tool calls, and the
answer was `0x0000019e7b820000` with a paragraph explaining that it matches parameter 1. Nothing
about the cell changed but the instructions string qwen never reads. So the failure modes are the
finding and *the ranking is not*: one sample per cell is enough to say that three models fail this
question in three distinguishable ways, and not enough to say which model gets it right.

### Re-running the narrow cells against the fix

2026-08-24, once `FOLLOWUPS.md` item 40 had landed: the same three-client listener on a rebuilt
server, `min` only, at 262,144, five rows, six tasks — 30 records. `full` and `lean` were not
re-run, because both were already 0 unserved and the fix costs the `full` surface seven characters.

The fix was confirmed live before the time was spent, by reading `initialize` per client:
**1,983** characters for `full`, **1,220** for `lean`, **927** for `min` — and `min`'s naming only
`crash_triage`, `end_session`, `interrupt` and `session_status`, every one of them served.

**Seventeen unserved calls became fourteen**, and the total is the least interesting part of
that — read it by name, because the composition is what moved:

| Name asked for | First run | Re-run | Advertised to a `min` client, then, by |
| --- | --- | --- | --- |
| `debug_batch` | 9 | 10 | the descriptions of `interrupt` and `end_session` |
| `modules` | 4 | 3 | the description of `open_dump` |
| `execute` | 3 | 0 | nothing — it was named only in the instructions |
| `decode_ioctl` | 1 | 0 | nothing — likewise |
| `list_modules` | 0 | 1 | nothing; no surface here serves it |
| **total** | **17** | **14** | |

Both names the fix could reach went to zero, and neither came back. Both were also asked for by
**only the two rows that read the string** — before the fix as much as after — which is consistent
with the injection claim above rather than a test of it. It cannot be a test: these are five cells
of one sample each, nemotron's single dropped call (a `modules`, which `open_dump` still advertises)
is the same size as the effect being claimed, and the variance that took qwen's score from 4/4 to
2/4 two sections down is larger than either. **Thirteen of the fourteen
that remain name a tool the `min` client is still told about by the description of a tool it *is*
served** — one advertising channel narrowed, the other untouched, which is `FOLLOWUPS.md` item 41.
The fourteenth is a name this server does not have anywhere, so the invention rate this page
originally reported as zero is not: it is one call in the re-run's 61.

**Item 41 has since landed** (2026-08-24) and removed all three of those descriptions'
cross-references: on `--tools crash` no served tool's description names a tool the client cannot
call. The next section re-runs these same five cells against it — and the ten `debug_batch` calls
go to zero while the three `modules` do not, which is how the attribution in the row above turned
out to be half wrong.

**The prompt-token columns did not move by a token**, which is the same finding wearing its other
face — an ollama row's prompt never carried the string, so there was nothing in it to save:

| Model | `min` prompt, first run | Re-run |
| --- | --- | --- |
| gemma4:31b | 3,447 | 3,447–3,489 |
| qwen3.8:27b | 3,838 | 3,838–3,878 |
| nemotron-3.5-lightning:30b | 3,926 | 3,926–3,965 |

The cut is real for a client that does read the instructions: the two Claude rows sit at
27,493–27,659 tokens on this surface, where ~265 tokens is about 1% of the prompt. Which is the
honest size of that half of item 40 — the wasted *turns* were always the larger cost.

**One score moved, and not for this reason.** Four of the five cells scored exactly what they
scored before, and this time all five lost `arm64_pc`:

| Cell | First run | Re-run |
| --- | --- | --- |
| Opus `min` | 3/4 **+1** | 3/4 **+1** |
| Sonnet `min` | 3/4 **+1** | 3/4 **+1** |
| qwen3.8 `min` | 4/4 | 2/4 **+1** |
| gemma4 `min` | 3/4 | 3/4 **+1** |
| nemotron `min` | 3/4 | 3/4 |

qwen lost two, with 0 unserved calls in both runs and no exposure to the string that changed. On
`arm64_pc` it made nemotron's mistake (above); on `bugcheck` it opened the dump, called
`end_session`, and answered *"Session closed."* — throwing away a fact its opener had already
handed it. Both are single-sample variance, and so is the **+1** appearing in two cells it had not
appeared in. Read the correctness columns of any one cell here as one draw, not as a rating.

### And again against the second channel, which is where the interesting answer was

2026-08-24, once `FOLLOWUPS.md` item 41 had landed ([#210](https://github.com/glslang/windbg-mcp/pull/210)):
the same five `min` cells, the same six tasks, the same listener on a rebuilt server — 30 records.
Confirmed live before the time was spent, by reading `tools/list` per client: `min`'s eleven
descriptions are **7,732** characters against 8,654, and **no** description any of the three
clients is served names a tool that client cannot call.

**Fourteen unserved calls became six**, and again the total is the least interesting part:

| Name asked for | After #206 | After #210 | What was advertising it |
| --- | --- | --- | --- |
| `debug_batch` | 10 | **0** | the descriptions of `interrupt` and `end_session` |
| `modules` | 3 | **3** | nothing — see below |
| `list_modules` | 1 | 0 | nothing; no surface here serves it |
| `run_command` | 0 | 3 | nothing; likewise |
| **total** | **14** | **6** | |

**Split by whether the task needed the reach** (the `taught`/`wanted` columns, added later and
re-graded over both logs): **4+10 became 0+6**. That is the argument for splitting the column at
all — summed, item 41 reads as a 57% improvement; split, the half it was aimed at is *eliminated*
and the half it was never aimed at is unchanged. All four were gemma's `debug_batch` on
`arm64_pc`, a task `min` can answer, so nothing about the question required a name off the surface.

**Every name this server was teaching is now gone.** Item 40 took `execute` (3) and `decode_ioctl`
(1) to zero and they stayed there; item 41 takes `debug_batch`, which was ten of the fourteen and
was gemma's whole turn budget on one task. Harness refusals fall with it, 9 to 4, because
`debug_batch` is what the read-only fence was catching.

**`modules` did not move, and what that does and does not establish is worth being careful about.**
Item 41's entry named `open_dump`'s description as what was advertising it. `open_dump` no longer
names it — checked on the wire, not inferred — and three calls came anyway. So the description is
**not necessary**: a model will reach for `modules` with nothing on this server naming it.

It does **not** follow that the description caused none of the earlier three, and the callers are
why. Before: nemotron, Opus, Sonnet. After: qwen, gemma, Opus. Only Opus repeated, so an aggregate
that held at three is a coincidence of composition rather than a stable rate — one sample per cell,
and a different set of models each time. The honest reading is that item 41's entry stated a cause
where the evidence supports at most a contributor.

**Every remaining call is on `unloaded_driver`, and each is a direct reach for a module listing** —
three `modules`, and three `run_command` all carrying the same `lm m nvhda64v`. That is the one
task of the six whose answer lives in a tool a `crash` client is not served (`modules`'s `unloaded`
list), and it is what a floor would look like: the surface cannot answer the question, so a model
that spots the missing capability and asks for it is right, and no narrowing of prose can stop it.

**The arithmetic that looks like it proves that does not, and it is our own double count.** Sorted
by task, `arm64_pc` had four unserved before and none now — but all four were gemma's
`debug_batch`, so their disappearance *is* the `debug_batch` row above, counted a second way rather
than independent evidence that answerable tasks are now clean. What supports the floor is the shape
of what remains, not that subtraction.

**The invention rate is higher than the last run could see.** gemma, refused, asked for
`run_command` three times — a name this server does not have anywhere — and the previous run had
one such call in 61. Two runs cannot fix a rate, but they are enough to say the floor is not
measurable by counting names that do not exist: `modules` shows a guess can land on a real tool,
where it is indistinguishable from having been advertised.

**Every row's prompt shrank this time, and that is the difference from item 40.** A tool's
description travels in `tools/list`, which every row reads; the `instructions` string only reaches
a client that injects it, which is why item 40 could not move an ollama prompt by a token.

| Row | `min` prompt after #206 | after #210 | Δ |
| --- | ---: | ---: | ---: |
| gemma4:31b | 3,447–3,489 | 3,224–3,266 | −223 |
| qwen3.8:27b | 3,838–3,878 | 3,615–3,655 | −223 |
| nemotron-3.5-lightning:30b | 3,926–3,965 | 3,700–3,739 | −226 |
| Opus | 27,493–27,543 | 27,186–27,236 | −307 |
| Sonnet | 27,609–27,659 | 27,302–27,352 | −307 |

922 characters off the surface, ~223 tokens off a local prompt (≈4.1 B/token, matching this page's
rule of thumb) and 307 off a Claude one, which encodes a tool definition differently. It is ~6% of
an ollama row's prompt on this surface and ~1% of a Claude row's.

**Scores did not move in aggregate**: 14 of 20 answerable, both runs. Cells moved inside that —
nemotron 3/4 to 2/4, qwen 2/4 to 3/4, gemma losing the false positive it had gained — which is the
same single-sample variance the previous re-run recorded, in the same direction on none of them.
Read them as one draw each, as before.

### The context axis did not bite, and nearly reported that it did

The prediction going in — `local-model.md` says an 8k window is "roughly half" what the 51-tool
surface needs — did not survive contact:

| Window served | `full` (51 tools, ~17k tokens) | `lean` | `min` |
| --- | --- | --- | --- |
| 262,144 | works | works | works |
| 32,768 | works | works | works |
| 8,192 | **works** — 6/6 on the whole task set | works | works |

At a **served** 8,192-token window, a 17,300-token prompt was evaluated in full and answered
correctly, including picking `decode_ioctl` out of 51 tools. No refusal, no visible truncation, no
degradation. On this runtime `num_ctx` is not a hard cap on prompt length for these MLX builds, so
"will the surface fit" is the wrong question to spend the budget on.

**That claim needed one more run before it was safe**, because the reduced-context cells use a
three-task subset and nothing in them was multi-turn with a large result. So qwen ran the *whole*
six-task list on the `full` surface at a served 8,192: **6 of 6 correct**, three of the tasks
taking three turns, and two of them carrying tool results of 9,959 and 10,343 characters — roughly
2,500 tokens of answer landing on top of a 17,300-token prompt, in an 8,192-token window. Whatever
the runtime is doing with `num_ctx` for these builds, it is not the truncation the number implies.

**It nearly went the other way, and the near-miss is the method lesson.** `num_ctx` on a request
does not shrink an instance the runtime already holds: with a 32,768 instance loaded, five cells
asking for 8,192 were served 32,768 and looked entirely healthy. Only `/api/ps` disagreed. Every
record therefore carries `served_context` beside the number it asked for, the grader marks a cell
where the two differ, and the runner evicts the model between windows. Those five records were
dropped and re-run. **Record what was served, not what was requested.**

One genuine context failure did turn up, and it is not about fitting: nemotron at 8k on `lean`
emitted a malformed tool call and the runtime rejected the request outright —
`XML syntax error on line 6: element <parameter> closed by </function>`. The tool-call *syntax*
broke before the window did.

### What it costs, in time and in tool output

| | Wall clock, six tasks | Tool result bytes taken |
| --- | --- | --- |
| Opus / Sonnet (`full`) | 93s / 91s | 20,924 / 22,924 |
| qwen3.8:27b (`full`) | 270s | 31,355 |
| gemma4:31b (`full`) | 348s | 31,365 |
| nemotron (`full`) | **74s** | 25,500 |

**Fast is not a proxy for good, and here it is nearly the opposite.** nemotron is three to five
times faster than the other two local models and gets ten of fifteen; its `module_count` answer —
"134 loaded modules", against a true 227 — was produced with **no tool call at all**. The control
rows are both quicker than every local model *and* take a third less tool output to get there,
which is the clearest single measure of the gap: fewer calls, smaller answers, right the first
time.

Claude's prompt-token column is deliberately absent from these tables. It reads 49k on the `full`
surface, and most of that is Claude Code's own system prompt rather than this server's — see the
last section.

## Fourth run: the first read with every channel closed (2026-08-25)

The five `min` cells again, this time at **five draws each** — 150 records, 25 cell-draws, ~59
minutes of cell time — against a server carrying
[#217](https://github.com/glslang/windbg-mcp/pull/217). That fix closed the **third** advertising
channel: an opener's *result* was ending with "`modules` lists a page of the table and
`modules { "filter": "<name>" }` answers for one", built in the worker, which knows nothing of a
client's surface. So the eleven-tool client's first result had been handing it the exact name and
its real argument the whole time — which is what made the third run's "three `modules` calls came
anyway" reading unsafe.

**`modules` is gone.**

| | after #210 (1 draw/cell) | after #217 (5 draws/cell) |
| --- | --- | --- |
| cell-draws reaching off-surface | 3/5 | 5/25 |
| naming `modules` | **3/5** | **0/25** |
| `taught` | 0 | 0 |

The three models that each named `modules` in their single draw before — gemma, opus and qwen —
named it in **none of their fifteen draws** after. What remains is gemma reaching in four of its
five draws and opus once in five; qwen, nemotron and sonnet never do.

**And the composition flipped from a real name to invented ones.** Before: `modules`, which is the
name that result was handing over. After: `execute_command` (12 calls, gemma, three draws),
`execute` (3, gemma, one draw — a real tool, not served here), `run_command` (1, opus). Thirteen of
the sixteen are names this server does not have.

The two arms differ by **exactly one server behaviour these tasks can reach** — the opener's
summary. Two other paths changed in the same window and neither was exercised, which is measured
rather than assumed: the user-mode refusal that stopped naming `backtrace` and `execute` (0 of the
run's 95 `crash_triage` calls reached it — every task here opens a kernel dump) and the
post-commit failure's `execute` example (no open failed after commit). Everything else merged
between the runs was documentation, the grader or the runner. That is as clean as a single variable gets here — and
the weakness is the other arm, which is one draw per cell. So the claim is not a rate against a
rate; it is the sentence above about fifteen draws. Note also that gemma's twelve calls are a loop
(four per draw, three draws), so **draw-level presence is the unit**, not call count.

### Two things five draws bought that one could not

- **`ioctl_decode` splits by tier as a rate.** Opus and sonnet answer it from their own knowledge
  in all five draws (`5o`); the three local models manage it once in five (`1o4-`). At one draw
  that is a coin toss reported as a fact.
- **`arm64_pc` is `5n` in every row** — twenty-five wrong answers from five models, frontier rows
  included. That is what a *task* defect looks like rather than a model one, and reading it that
  way found one: **across the 35 runs of that task in the three logs still on disk, none gave the
  key's answer and 32 gave the bug check's first parameter.** It has been answered correctly
  exactly once, in the original grid — qwen, above, reasoning that frame 0 of the bug-check stack
  *is* the `pc`. That log is no longer on disk, so one correct answer in fifty is the best this can
  be put; the point survives the arithmetic either way, since a task whose intended reading is
  reached about 2% of the time is measuring its wording. Measured on the dump, both are
  defensible — `registers` reports `pc = 0xfffff8013c65bca8` and `crash_triage` frame 0 is the same
  address, `nt!KeBugCheck2+0x2e8`, so the key is literally right; but that address is inside the
  bug-check path the machine reached *after* the fault, while parameter 1 is the address whose
  execution faulted. A model answering "the pc at the point of the crash" with the faulting address
  is reading the question the way a person would. **The prompt has since been reworded** (item 44,
  2026-08-25): it asks for the register's own value as the debugger reports it, and not for an
  address taken from the bug check's parameters. Widening the key to accept parameter 1 was the
  tempting fix and the wrong one — `open_dump`'s summary already carries the parameters, so the
  task would then pass without the route it exists to check, which is a narrow surface reaching a
  *register* through `crash_triage` frame 0. The scores in this document are as-graded, against
  the old wording. Re-reading the other five prompts against their keys at the same time found no
  second instance: `driver_blame` is the only one with any looseness at all — its `0x1654` is the
  address `nt!ExFreePoolWithTag` returns to rather than one that itself faulted, which is the
  frame `crash_triage` calls `faulting_frame` — and 33 of its 35 recorded runs give the key, the
  other two being an empty answer and a closed session. A wording defect shows up as *agreement
  on a different answer*, and only this task has one.

## What this does not cover

The same list `local-model.md` carries, minus what this closed. Still open: a long investigation
where the transcript outgrows the surface (scenario mode exists and no cell here uses it), anything
behind the read-only allow-list, a box smaller than this one, and any model but these.

And one that this page adds: the Claude row is **Claude Code**, not the Claude API. Its token
columns include a harness this server does not control — its own system prompt, its own
conversation shape and prompt caching — so they are not comparable with the ollama rows and are
marked as such. What is comparable is what the grid is about: which tools get picked out of a given
surface, and whether the answer is right.
