---
paths:
  - "src/record.rs"
  - "src/cast.rs"
---

## Recording a session while debugging this server

`WINDBG_MCP_TRANSCRIPT=<path>` makes the supervisor write a JSONL record of every tool call, every
session transition, every timeout and every worker death (`src/record.rs`; the README has the
format). It is off unless the variable is set, and it is often the fastest way to answer "what
actually happened in that session" — the `tracing` stream on stderr is prose about the *server* and
interleaves both roles, while this is values about the *session*, keyed by session and request.

Two things worth knowing when using it here:

- **It records the supervisor's view.** A worker inherits the variable and ignores it (the role
  check in `main` runs first), so there is exactly one writer and no interleaving. A fact that
  exists only inside a worker reaches the transcript only if it crosses the pipe as a value — which
  is the same rule as everything else in `src/structured.rs`, and the reason `debug_batch` grew a
  typed report.
- **It is also how you measure what an answer is *made of*.** With
  `WINDBG_MCP_TRANSCRIPT_MAX_FIELD=0` the whole structured payload is kept, so one debugger-tier run
  leaves every tool's `data` on disk to be counted field by field — no probe to write, no code to
  add. Do that before optimising a result, because reading the source predicts the wrong half:
  `registers` was blamed in `docs/token-budget.md` for `"kind":"int"` and `"subregister":false`
  scaffolding, which is real and is 41% of it, while the actual bulk was 64 rows of the vector bank
  that the default filter was written to exclude and did not (2026-08-22). One run of the tier
  answered both questions in a form nothing else in this repo can produce.
- **`windbg-mcp --render-cast <transcript.jsonl>`** turns one into an asciicast. That is the
  supported way to produce the recordings under `examples/` and `docs/` — the older ones are
  hand-reconstructed and say so, and a new walkthrough should not add another.

Recording a **live kernel** session is where this needs care, because a transcript of one is as
sensitive as the target: not the connection (attach by `profile` and there is no key in it), but
everything the debugger printed — stack frames, strings, whatever the guest holds. Nothing but
secrets is masked, so treat the file like a crash dump: keep it out of the repo, and delete it when
the investigation is done. It is **appended** to, so a path reused across runs accumulates.

