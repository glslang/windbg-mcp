# Driving this server with a local model

The last plane of the split-plane arrangement: the **model** on your own machine, DbgEng where it
has to live. Nothing here is a feature of this server — it is a runbook, because the pieces are a
listener you already have, a tunnel, and a client that happens to be pointed at a local model.

Read [`remote-listener.md`](./remote-listener.md) first for the listener itself; this page is only
what is different when the thing driving it is not a hosted model.

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

It executes only a **read-only allow-list**, and reports anything else back to the model as refused.
That is deliberate: the surface includes `execute` and `launch`, and a debug host is the wrong place
to discover unattended what a model does with them — but a wrong pick is still *measured*, which is
the point.

**Configure that token as a client of its own**, on the Windows machine, beside the one your editor
uses:

```console
setx WINDBG_MCP_LISTEN_TOKEN_DRIVER "<another long random string>"
```

That is not a nicety. A shared credential is a shared **namespace**: the driver would see and route
to the editor's sessions, and — the part no fence in a script can prevent — a client over the
four-session cap has its oldest *idle* session reclaimed by the server, so a dump the driver opens
can evict the editor's target without any tool call naming it. The script therefore refuses to run
without a token rather than borrowing one; it cannot tell one token from another, so supplying a
credential that really is its own is yours to get right.

**Under the service, that variable is not where the token goes.** The installer points the service
at an ACL'd token file, and a configured file is the *only* credential this server will read — it
shuts the environment out entirely, named tokens included, because the machine environment is
readable by unprivileged processes and this endpoint has `launch` on it
(`Credentials::from_entries`). So the driver's credential goes **in the file**, which names its own
clients:

```jsonc
// %ProgramData%\windbg-mcp\token
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
| Largest answer actually taken | `modules`, **53,772 characters**, passed to the model whole |

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

## What to measure

The claims worth testing are about the *client's* budget, not this server's correctness, and the
smoke tiers cannot reach them — which is why the driver script exists and why the run above is
written down rather than remembered:

- **Does the surface fit**, at the context the runtime is actually serving.
- **Does the model pick the right tool out of 51**, which is orthogonal to window size and is the
  part a bigger context does not fix.
- **Do individual answers blow the window.** `modules` has no `limit` and `read_memory` returns up
  to ~4 MiB by design; both are `FOLLOWUPS.md` item 24's last bullets, and both are reachable in one
  careless call.

If a model does not cope, the knobs are all **client-side** today — a tool-surface profile, a
per-call response budget, a text-or-data content switch. This server has none of them: every caller
gets all 51 tools, and there is no way to ask for fewer.

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
