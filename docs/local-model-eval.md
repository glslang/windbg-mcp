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
- **`unserved`** — a call naming a tool this client is not served. It was called `hallucinated`
  until the run was read properly; see below, because the server is where all but one of those
  names came from.

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
  "tasks": "tools/eval_tasks.json",
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
python3 tools/local_model_eval.py --grade results.jsonl tools/eval_tasks.json
```

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

| Name asked for | First run | Re-run | Still advertised to a `min` client by |
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

## What this does not cover

The same list `local-model.md` carries, minus what this closed. Still open: a long investigation
where the transcript outgrows the surface (scenario mode exists and no cell here uses it), anything
behind the read-only allow-list, a box smaller than this one, and any model but these.

And one that this page adds: the Claude row is **Claude Code**, not the Claude API. Its token
columns include a harness this server does not control — its own system prompt, its own
conversation shape and prompt caching — so they are not comparable with the ollama rows and are
marked as such. What is comparable is what the grid is about: which tools get picked out of a given
surface, and whether the answer is right.
