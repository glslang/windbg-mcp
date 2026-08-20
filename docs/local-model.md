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

**2 — the link.** One ssh channel that both forwards the port and runs the listener, so the server
lives exactly as long as the tunnel and nothing is left behind:

```console
ssh -L 8765:127.0.0.1:8765 <vm> 'windbg-mcp.exe --listen 127.0.0.1:8765'
```

Starting it through `ssh` and letting that command *finish* does not work, and the failure looks
like a healthy start — see [Do not start it through ssh and then hang
up](./remote-listener.md#do-not-start-it-through-ssh-and-then-hang-up).

**3 — the control plane.** Register the server once, against the forwarded port:

```console
claude mcp add windbg-vm --scope local --transport http http://127.0.0.1:8765/ \
  --header "Authorization: Bearer <the same string>"
```

Then start the client against a local model. With [ollama](https://ollama.com) 0.32.12 or newer:

```console
ollama launch claude --model <model-tag>
```

`ollama launch` wires a local model into a coding harness — `ollama launch --help` lists the
integrations it knows, of which `claude` is Claude Code. The MCP registration above is unaffected by
which model is driving: the client is the same client.

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

## What to measure

The claims worth testing are about the *client's* budget, not this server's correctness, and the
smoke tiers cannot reach them:

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
