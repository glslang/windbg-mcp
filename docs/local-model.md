# Driving this server with a local model

The last plane of the split-plane arrangement: the **model** on your own machine, DbgEng where it
has to live. Nothing here is a feature of this server — it is a runbook, because the pieces are a
listener you already have, a tunnel, and a client that happens to be pointed at a local model.

Read [`remote-listener.md`](./remote-listener.md) first for the listener itself; this page is only
what is different when the thing driving it is not a hosted model.

**For the measurements, go to [`local-model-eval.md`](./local-model-eval.md).** The two runs
recorded here are one model on one surface at one window — sightings, and they say so. The eval is
the grid they argued for: three local models against three tool surfaces and three context windows
with a frontier control, scored against an answer key. Where the two disagree, the grid wins; the
clearest case is the arithmetic under *What this server costs a model* below, which predicts that
the 51-tool surface cannot fit an 8k window, and the grid answers all six tasks at a served 8,192
anyway.

## The three pieces

**1 — the engine plane.** The Windows machine runs the listener, bound to loopback, with its token
in the environment rather than on a command line:

```pwsh
setx WINDBG_MCP_LISTEN_TOKEN "<a long random string>"
```

**2 — the link.** For a session you are driving anyway, one ssh channel both forwards the port and
runs the listener, so the server lives exactly as long as the tunnel and nothing is left behind:

```console
ssh -L 8765:127.0.0.1:8765 <vm> 'windbg-mcp.exe --listen 127.0.0.1:8765'
```

Starting it through `ssh` and letting that command *finish* does not work, and the failure looks
like a healthy start — see [Do not start it through ssh and then hang
up](./remote-listener.md#do-not-start-it-through-ssh-and-then-hang-up).

**For anything less throwaway, install it as a service** (`--install-service --listen 127.0.0.1:8765`,
elevated) and the listener survives a logout, a reboot and a dropped tunnel — the forward is then the
only thing you restart. That is the whole reason the service role exists; see [Run it as a Windows
service](./remote-listener.md#run-it-as-a-windows-service), which also covers why the token moves to
an ACL'd file rather than the machine environment.

**3 — the control plane.** Register the server once, against the forwarded port:

```console
claude mcp add windbg-vm --scope local --transport http http://127.0.0.1:8765/ \
  --header "Authorization: Bearer <the same string>"
```

Then drive a local model against it **through ollama's server API**. No second harness is involved
and nothing has to be launched: a session you already have runs the script, which is how every number
further down this page was produced.

[`tools/local_model_drive.py`](../tools/local_model_drive.py) speaks MCP over HTTP to the listener,
hands the whole tool surface to `POST /api/chat`, executes the tool calls that come back and feeds
the results in. It needs a bearer token **of its own** — an environment variable rather than an
argument, the same rule the listener's own token follows:

```console
WINDBG_MCP_TOKEN="<the driver's token>" python3 tools/local_model_drive.py [tasks.json]
```

### Give the run its own listener, not a share of yours

**A credential of its own is the requirement; a listener of its own is how to get one.** The script
refuses to run on the token your editor is registered with, because a shared credential is a shared
namespace: the run would see, route to, and at the four-session cap cause the reclamation of your
targets. A surface of its own is *not* the reason — `WINDBG_MCP_TOOLS_<NAME>` gives one client a
smaller surface on a listener it shares, so the budget alone no longer argues for a second process.

A foreground listener on a second port costs nothing and disappears when you close it, which is
still the right shape for a bench: no privileged write, nothing to clean up, and a build that is
not the installed one. (A service-hosted listener can be given a client without a reinstall these
days — `--add-listen-client` — so that is an option rather than the obstacle it was; see
[`remote-listener.md`](./remote-listener.md#adding-revoking-rotating-and-re-toolling-a-client-without-stopping-anything).)

Generate the token on the machine that will *use* it, and pass it over **stdin** — never on a
command line, where every process on the box can read it:

```pwsh
# on the debug host, from a script run over ssh with the token on stdin:
$token = [Console]::In.ReadToEnd().Trim()
Remove-Item Env:WINDBG_MCP_LISTEN_TOKEN -ErrorAction SilentlyContinue  # no second `local`
$env:WINDBG_MCP_LISTEN_TOKEN_DRIVER = $token
& <path>\windbg-mcp.exe --listen 127.0.0.1:8766
```

```console
# on your machine
python3 -c "import secrets;print(secrets.token_urlsafe(32))" > driver.token   # mode 600
cat driver.token | ssh <vm> 'powershell -NoProfile -File C:\path\start-driver-listener.ps1' &
ssh -N -L 8766:127.0.0.1:8766 <vm> &
WINDBG_MCP_URL=http://127.0.0.1:8766/ WINDBG_MCP_TOKEN="$(cat driver.token)" \
  python3 tools/local_model_drive.py tasks.json
```

The listener's startup line names the clients it holds — `clients: driver` and nothing else is the
check that the recipe worked. Sessions belong to the listener process that opened them, so this run
and your editor's cannot reach each other's even by accident.

It executes only a **read-only allow-list**, and reports anything else back to the model as refused.
That is deliberate: the surface includes `execute` and `launch`, and a debug host is the wrong place
to discover unattended what a model does with them — but a wrong pick is still *measured*, which is
the point.

**Configure that token as a client of its own**, on the Windows machine, beside the one your editor
uses:

```console
setx WINDBG_MCP_LISTEN_TOKEN_DRIVER "<another long random string>"
setx WINDBG_MCP_TOOLS_DRIVER        "session,inspect,crash"
```

The second line is what makes this work on a listener the editor also uses: the driver is served 20
tools and 25,265 B while every other client on that listener keeps all 51. Leave it out and the
driver is served whatever the listener was started with, which is the older behaviour and is the
right one when the listener is the driver's own.

The first line is not a nicety. A shared credential is a shared **namespace**: the driver would see
and route to the editor's sessions, and — the part no fence in a script can prevent — a client over
the four-session cap has its oldest *idle* session reclaimed by the server, so a dump the driver
opens can evict the editor's target without any tool call naming it. The script therefore refuses to
run without a token rather than borrowing one; it cannot tell one token from another, so supplying a
credential that really is its own is yours to get right.

**Under the service, that variable is not where the token goes.** The installer points the service
at an ACL'd token file, and a configured file is the *only* credential this server will read — it
shuts the environment out entirely, named tokens included, because the machine environment is
readable by unprivileged processes and this endpoint has `launch` on it
(`Credentials::from_entries`). So the driver's credential goes **in the file**, which names its own
clients — `%ProgramData%\windbg-mcp\token`, as strict JSON (no comments; a file that does not begin
with `{` is read as a single bare token):

```json
{
  "local":  "<what your editor presents>",
  "driver": "<another long random string>"
}
```

`--install-service` writes that for you from the credential variables in the installing shell, so
setting `WINDBG_MCP_LISTEN_TOKEN_DRIVER` beside the unnamed one before installing is enough. Editing
the file afterwards works too — it is read at startup, so restart the service. Handing the driver
the *editor's* token is still possible and is sharing the namespace knowingly, which is a decision
rather than a default.

Should you share one anyway, the script still fences what it can within that namespace: it ends only
sessions **this run opened**, counting the handles an *opener* returned rather than every handle it
has seen, and leaving alone
whatever the credential already had when it started — a predecessor that died before its cleanup, or
a run going on beside it. What it opened, it releases on the way out.

**Each task gets its own conversation and its own targets.** A task list is a list of separate
questions, so the transcript is fresh and the sessions are released after each one; otherwise a later
task's `session_id`-less call routes to an earlier task's target, and its measurement depends on the
prompts before it.

`WINDBG_MCP_SCENARIO=1` says the list is one continuing investigation instead — **one transcript and
one set of sessions across every task**, so "disassemble the address you just found" means something.
It is also how you would measure the case the run below does not cover: the prompt-token count
printed for each task is the transcript growing, and scenario mode is what makes it grow.

**A different arrangement, not a prerequisite:** `ollama launch claude --model <tag>` (ollama 0.32.12
or newer) makes the local model *the agent* — it drives the harness itself, with these tools as its
tools, rather than being called through the API by something else. That is the end state the
split-plane plan is aimed at, and it is worth knowing about; it is not how anything on this page was
measured, and it is not needed to measure it.

## What this server costs a model, measured

[`token-budget.md`](./token-budget.md) has the method and the golden; these are the numbers that
decide whether a local model can hold this surface at all. Bytes of minified JSON, ≈4 B/token.

| | bytes | ≈tokens |
|---|---|---|
| The tool surface, paid once per conversation | 67,076 (51 tools) | ~17k |
| — the same surface as `--tools session,inspect,crash` | 25,265 (20 tools) | ~6k |
| — as `--tools crash` | 15,073 (11 tools) | ~4k |
| Its worst single tool (`debug_batch`) | 9,746 | ~2.4k |
| The largest answer this server gives (`modules`) | 53,875 | ~13k |
| `read_memory` at its design limit | ~4 MiB of hex | ~1M |

So the surface is a rounding error against a 256k window and roughly twice an 8k one. **The
question is never the model's advertised maximum — it is what the runtime actually serves.**

## The context your runtime serves is not the model's maximum

ollama's own help says it: `OLLAMA_CONTEXT_LENGTH` — *"Context length to use unless otherwise
specified (default: 4k/32k/256k based on VRAM)"*. A model whose card says 262,144 can be served at
4k on a smaller box, and a 51-tool surface does not fit in 4k. Two ways to know rather than assume:

```console
ollama show <model-tag>          # the model's own maximum, under "context length"
ollama ps                        # what the *loaded* instance is serving, under CONTEXT
```

`ollama ps` is the one that answers the question, and it prints nothing until the model is loaded,
so send it one prompt first — `curl -s localhost:11434/api/generate -d
'{"model":"<tag>","prompt":"hi","stream":false,"options":{"num_predict":1}}'` is enough. Pin it with
`OLLAMA_CONTEXT_LENGTH` if two machines have to agree.

Worked example, measured on the bench this page was written on: `ollama show` reports
`context length 262144` for a 27.8B nvfp4 build, and `ollama ps` reports `CONTEXT 262144` with
`100% GPU` once it is loaded — so the default did land on the model's maximum there, and the
17k-token surface is about 6.5% of the window. That is a fact about that machine's memory, not about
the model: the same tag on a smaller box is served at 4k or 32k by the same default.

## What one run showed

Measured 20 August 2026 with `tools/local_model_drive.py`, against a 27.8B nvfp4 build served at
262,144 (see above), on the two checked-in kernel dumps. One model, one bench, six tasks — read it
as a sighting rather than a benchmark.

| | |
| --- | --- |
| Tools offered | 51 (68,970 B in ollama's function shape; the same surface `token-budget.md` measures at 67,076 B as MCP reports it) |
| Prompt tokens, first turn of every task | **17,095–17,127**, by the model's own tokenizer |
| Share of the window | ~6.5% |
| Tool picks | 9 calls across 6 tasks, **all correct first try** |
| Largest answer actually taken | `modules`, **53,772 characters**, passed to the model whole — the run that made the case for capping it, below |

Three things worth carrying:

- **The ≈4 B/token rule of thumb held.** 67,076 B predicted ~16.8k; the tokenizer said ~17.1k. The
  golden's bytes are a usable proxy for what a model is charged.
- **The surface costs context every turn but compute only once.** The first turn after a cold load
  took 86.5s, nearly all of it evaluating those 17k tokens; every later turn started in 0.6–4.7s,
  because the runtime caches the prefix. A surface that fits is therefore paid for once per model
  load, not once per question.
- **Selection was not the problem it was predicted to be.** The plan's section 07 expected a
  30B-class model to struggle with a surface this size; this one picked `open_dump` with the right
  path, `modules` and then *refined its own call* with a `filter`, `decode_ioctl`, and
  `session_status` — and answered the bug check off the opener's summary without needing
  `crash_triage`. It identified `0xFC` on the ARM64 dump, and `0x13A` with `MessageManager` as the
  third-party driver on the other, which is what
  [`messagemanager-walkthrough.md`](./messagemanager-walkthrough.md) says it is.

A fourth thing showed up when the harness stopped truncating results, and it is the one that costs
time rather than context: the turn that *consumed* those 53,772 characters took **169s**, because
~13k new tokens have to be evaluated before the model says anything. Prefix caching pays for the
surface once; it does nothing for a large answer, which is charged in full the moment it arrives. On
a local box the practical cap on `modules` and `read_memory` is patience, not the window.

`read_memory` at address 0 is worth running once for a different reason: it fails, and it fails as a
perfectly good MCP result carrying `isError` rather than as a protocol error. A harness that watches
only for the latter records a failed call as a successful one — which this one did until review
caught it.

What this run does **not** cover: a long investigation where the transcript grows past the surface,
anything behind the allow-list (`execute`, `debug_batch`, `launch`), a smaller box where the served
context is 4k or 32k, and any model but this one.

## What the second run showed, after `modules` was capped

Measured 22 August 2026, same model and bench, six tasks aimed at the row cap rather than at the
surface: three about the module table and three of the first run's questions for comparison. Read
the two runs' figures side by side with care — the first run's 53,772-character `modules` answer was
a **different dump** (the ARM64 one, 177 modules) from this run's x64 sample (227 loaded, 50
unloaded), so the honest like-for-like page-against-table pair is the smoke tier's, in
[`token-budget.md`](./token-budget.md).

| | |
| --- | --- |
| Prompt tokens, first turn of every task | 17,254–17,294 (surface now 69,552 B, the `limit` argument included) |
| Tool picks | **10 calls across 6 tasks, all correct first try**, nothing refused |
| Tool results, whole run | **94,758 characters** (~23.7k tokens), of which one module page is 68,571 |
| "How many modules are loaded?" | answered **227**, from the opener's summary, with **no `modules` call at all** — 2,358 characters, 8.1s |
| "Is `nvhda64v` present, and where?" | `modules { "filter": "nvhda64v" }` — **7,597 characters**, and the right answer: not loaded, 26 unload records |

**The model never mistook a page for the inventory**, which was the risk the cap introduced. Asked
for the whole table it called its own answer "the first page of loaded modules" and reported
`227 loaded / 50 unloaded` from the counts; asked for a total it read the opener's summary and did
not list anything at all.

**But a guessed `limit` is still short, and that is the cap's own doing.** The model asked for
`limit: 240` — a round number above the 227 it had been told — and got 190 loaded rows and 50
unloaded ones, because the budget is shared between the halves. It did not need to ask again here,
having the counts; a caller that did would have paid a third call. That is what the note's
`` `limit: 277` returns all of them `` sentence is for, added the same day: **the number a reader
takes from the line above the rows is guaranteed to fall short, so the note names the one that is
not**.

**The pre-fix run of the same tasks cost 146,359 characters on task 1 alone**, against 70,929 here,
because the model fetched the table twice — once at a guessed limit and once with
`filter: "*", limit: 2000`. A cap the caller has to negotiate is worse than no cap; a cap that says
what to ask for next is not.

### The failure that run found first, which was not about tokens at all

The first attempt never reached task 2. The model spent **440.6s** composing an answer, the
listener's lease grace is **390s**, and a lease is renewed by *requests* — so with nothing in
flight the sweep released the client's sessions, and every later call came back
`404 Session not found`, which reads exactly like a broken server.

The grace is derived from how long a *call* may take: it assumes the **server** is the slow party.
Driving a local model inverts that assumption, and nothing before this had met a client that goes
quiet for seven minutes while still working. `tools/local_model_drive.py` now pings the listener
after 120 seconds of silence (`WINDBG_MCP_KEEPALIVE`, `0` disables) — two pings carried that turn in
the re-run, and every session was released cleanly at the end. Whether the *listener* should also
be more patient with a client whose MCP session is still connected is
[`FOLLOWUPS.md`](../FOLLOWUPS.md) item 33.

## What to measure

The claims worth testing are about the *client's* budget, not this server's correctness, and the
smoke tiers cannot reach them — which is why the driver script exists and why the run above is
written down rather than remembered:

- **Does the surface fit**, at the context the runtime is actually serving. **Measured, and the
  answer was no-question-asked yes** — see the eval: at a *served* 8,192 window a 17,300-token
  surface answered every task. Note *served*: `num_ctx` does not shrink an instance the runtime
  already holds, and asking `/api/ps` is the only way to know which of the two numbers you have.
- **Does the model pick the right tool out of 51**, which is orthogonal to window size and is the
  part a bigger context does not fix. **Measured, and it is the axis that separates models** —
  three ~30B builds scored 15, 14 and 10 of 15 answerable tasks, and the interesting differences
  are in *how* the failures look rather than in the totals.
- **Do individual answers blow the window.** `read_memory` returns up to ~4 MiB by design, and is
  reachable in one careless call. `modules` was the other half of that and is **fixed** since
  2026-08-21: it answers with 64 rows unless a `limit` says otherwise, which on the checked-in
  kernel sample is 12,268 B of model context rather than 53,933 B, with `loaded` / `matched` still
  reporting the whole inventory. What that is worth in practice is the second run above, and it is
  not the flat saving this bullet first predicted: a model asked for one driver pays 7,597
  characters, a model asked for a total pays none at all, and a model asked for the whole table
  still asks for the whole table.

If a model does not cope, the plan named three knobs — a tool-surface profile, a per-call response
budget, a text-or-data content switch. **Two of the three now exist, and neither turned out to be
client-side.**

- **The tool-surface profile is `--tools`** (2026-08-22). Start the listener with
  `--tools session,inspect,crash` and the surface is 20 tools and 25,265 B instead of 51 and
  67,658 — `--tools crash` is 11 and 15,073 B, which is the difference between "roughly twice an 8k
  window" and "half of one". Nothing is reworded: the tools that remain are the tools they were.
  The whole table is in [`token-budget.md`](./token-budget.md) under finding 8, and the README has
  the operator's half. **And it is per client as well as per run** (2026-08-22): a listener's
  clients are named already, so `WINDBG_MCP_TOOLS_<NAME>` beside the token gives one of them its
  own surface — which is what lets the bench below share a listener with a hosted client rather
  than needing one of its own for the budget's sake. The credential is still the reason to run a
  second one; see the next section.
- **The response budget arrived per tool**, not caller-wide: `modules`' `limit`, above.
- **The text-or-data switch is still unbuilt**, and is the one that needs a client rather than a
  server change: which half of a result reaches the model is the client's forwarding policy.

The measurement that decided the first one is worth carrying: **74% of the model-visible surface is
prose**, and it is the prose that tells a model how to drive a tool. There was no strip available
here — only the choice to offer fewer tools.

## Picking this up after a break

Four checks, in the order that fails fastest:

```console
ollama list                                   # is the model still there
claude mcp list                               # windbg-vm: connected, or ConnectionRefused?
ssh <vm> 'powershell -c "(Get-NetTCPConnection -State Listen -LocalPort 8765).Count"'
ssh <vm> 'powershell -c "[bool][Environment]::GetEnvironmentVariable(\"WINDBG_MCP_LISTEN_TOKEN\",\"User\")"'
```

`ConnectionRefused` from `claude mcp list` means piece 2 is down and nothing else is wrong: the
registration, the token and the model all survive a reboot; the tunnel does not.

**Rebuild the listener before drawing conclusions about listener behaviour.** `target\release` on
the Windows machine is whatever was last built there, and this part of the server changes often —
an exe from last week can predate the client-identity and lease work entirely.
