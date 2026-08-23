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

Bytes are the surface as handed to the runtime — minified JSON in ollama's function shape, which
is a little larger than the same surface as MCP reports it in
[`token-budget.md`](./token-budget.md), and is what the model is actually served.

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
- **`hallucinated`** — a call naming a tool the surface never offered. The model was handed a tool
  list; asking for something outside it is invention.

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

**`unloaded_driver` requires the count, which used to be a bonus.** On the 11-tool surface a model
with no `modules` answered honestly that it could not check, added that "a kernel-mode dump does
not retain a history of drivers that loaded-then-unloaded" — which is false, and is exactly what
the tool would have told it — and scored correct on the words *not loaded* and *unloaded*. The 26
unload records are the half of the question only the tool can answer, and every model that had the
tool quoted the number, so requiring it separates reading from guessing.

One prediction in the key was simply wrong, and the run found it: **`arm64_pc` is answerable on
every surface**, not only where `registers` is served. `crash_triage`'s frame 0 on that dump is
`0xfffff8013c65bca8`, which is the `pc` the register read reports — the same fact by another
route. Verified against the dump before the key was changed, and it is the kind of thing a grid
finds that a prediction does not: two tools carry one fact, so narrowing a surface removes fewer
answers than the tool table suggests.

## Running it

Three pieces, and only the first is unusual.

**A listener with three clients**, started in the foreground so it disappears with the ssh channel
and holds no credential a service would keep. The tokens go in on **stdin**, never on a command
line:

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

**A plan**, naming the models, the surfaces, the contexts and the per-cell wall-clock budget. The
tokens are *not* in it: a plan is checked in, a credential is not.

```console
EVAL_TOKENS=bench-tokens.json python3 tools/local_model_eval.py plan.json
```

Cells are subprocesses and the log is append-only, so a run that dies in the middle leaves every
finished cell on disk and re-running the same plan resumes rather than repeating. A cell that
overruns its budget is killed and *that* is recorded — a model which cannot finish inside a
generous wall clock has told you something.

**Grading, separately**, over the log:

```console
python3 tools/local_model_eval.py --grade results.jsonl tools/eval_tasks.json
```

## What one grid showed

Run 2026-08-23, on the ARM64 bench described in `local-model.md`: 33 cells, 144 task runs, about
three hours of wall clock. The raw log, every answer and every tool call are what the tables below
are reduced from.

### At the window this bench actually serves

Six tasks, 262,144 tokens, **correct out of answerable** — the denominator moves with the surface
because two of the six have no tool to answer them on `min`:

| | `full` (51 tools) | `lean` (20) | `min` (11) | answerable, total |
| --- | --- | --- | --- | --- |
| **Opus** *(control)* | 6/6 | 5/5 **+1** | 4/4 | **15/15** |
| **Sonnet** *(control)* | 6/6 | 5/5 **+1** | 4/4 | **15/15** |
| qwen3.8:27b | 6/6 | 5/5 | 4/4 | **15/15** |
| gemma4:31b | 6/6 | 5/5 | 3/4 | **14/15** |
| nemotron-3.5-lightning:30b | 4/6 | 3/5 | 3/4 | **10/15** |

The **+1** is the trap task answered without the tool that answers it: both control rows decoded
`0x22200B` correctly from the `CTL_CODE` layout on a surface where `decode_ioctl` is not served.
gemma does it too at the reduced windows. qwen tries and gets it wrong — twice, in prose, in full
view.

**The headline is the first column against the last.** A 27B local model matched the frontier
control on every answerable task, at every surface size, on this task set. That is not a claim
that local models are as good; it is a claim about *these questions*, which are the shape of
question a debugger MCP server is asked most of the time — open a target, read a field, name a
module, decode a constant.

### The surface axis cost less than the tool table predicts

Cutting 51 tools to 11 removes 40 tools and **two answers**. Two of the six tasks survive the cut
because `open_dump`'s summary carries the bug check and the module count, and a third survives
because `crash_triage`'s frame 0 is the `pc` that `registers` reports. Facts here are reachable by
more than one route, and the narrow surface keeps the routes that matter.

What the cut *does* produce, in every row including the control, is **calls to tools that are not
there**:

| Cell | Off-surface calls |
| --- | --- |
| gemma4 `min` | 8 — `debug_batch` four times on one task, plus `modules` |
| Opus `min` | 4 |
| Sonnet `min` | 2 |
| nemotron `min` | 1 |
| every `full` and `lean` cell | 0 |

Nobody invents a tool when the surface is wide. Everybody does when it is narrow, and the server's
refusal (`#196`, which names the client's own surface) is what turns that into a recoverable
mistake rather than a wrong answer. Opus and qwen recover by declining honestly; gemma spends its
whole turn budget re-asking and returns an **empty answer**.

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
