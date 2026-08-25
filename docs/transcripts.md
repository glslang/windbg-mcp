# Session transcripts (`WINDBG_MCP_TRANSCRIPT`)

Point `WINDBG_MCP_TRANSCRIPT` at a path and the server records what it was asked and what it did,
one JSON object per line. Unset — the default — nothing is written and nothing is spent.

```pwsh
$env:WINDBG_MCP_TRANSCRIPT = "$env:USERPROFILE\.windbg-mcp\session.jsonl"
```

```jsonc
{"v":1,"run":4158027124358305144,"seq":1,"at":"2026-08-16T12:05:20.549Z","mono_ms":1,"event":"tool_request","request":1,"tool":"open_dump","args":{"path":"C:\\dumps\\a.dmp"}}
{"v":1,"run":4158027124358305144,"seq":2,"at":"2026-08-16T12:05:20.672Z","mono_ms":125,"event":"session_open","session":"sess-18cc47a3b2779cc8-1","kind":"crash dump","target":{"text":"C:\\dumps\\a.dmp"},"engine_pid":832}
{"v":1,"run":4158027124358305144,"seq":11,"at":"2026-08-16T12:05:23.129Z","mono_ms":2582,"event":"batch","request":3,"session":"sess-18cc47a3b2779cc8-1","outcome":"failed","at_step":2,"committed":false,"rollback_complete":true,"after":"stopped","elapsed_ms":402}
```

Every record carries the format version, the run that wrote it, a sequence number, a wall clock
and a monotonic offset. A run opens with a `start` record whose own `version` is **the build that
wrote the file** — the crate version with the git revision it was built from appended
(`0.11.0+g1a2b3c4`, and `-dirty` where the build inputs differed from that commit). Two builds of
one release are otherwise indistinguishable, which is what makes a recording hard to place months
later; a build with no git beside it reports the bare crate version.
The events are the tool call and its result; a session opening, changing state and being released;
a wait abandoned, an `interrupt`, a worker process dying; and — derived from each result's *typed*
half, never scraped from the text beside it — where execution stopped, what a `run_to_address`
concluded, every breakpoint or memory mutation, each assertion that did not hold, and how a
`debug_batch` ended with whether its rollback completed. See [`src/record.rs`](../src/record.rs).

A record's `session` is the one the call was **routed** to, not the one it named: omitting
`session_id` accepts the current session rather than none, so the field answers "which target was
this?" even for the calls that did not say.

**It is not the log.** `RUST_LOG` output is prose about the server, on stderr; this is values about
the *session*, in a file of its own. Standard output stays JSON-RPC and nothing else.

Render one as a terminal recording with the same executable:

```pwsh
windbg-mcp --render-cast session.jsonl -o session.cast   # asciicast v2
asciinema play session.cast
```

The rendering is derived, so a cast can be made from a transcript recorded weeks ago and the
timings are the recorded ones. `--idle-limit <s>` tells a player how long to sit in a pause (`0`
plays at the speed it happened), `--max-lines <n>` caps how much of a long result is shown, and
`--title`/`--width`/`--height` shape the recording.

A file holding several runs renders as one recording with the runs laid end to end, separated by
however long the server was actually down — each run's own clock starts at zero, so playing those
offsets as they stand would step backwards at the join and no player would accept it. Two servers
pointed at the same path interleave their lines; they are grouped back into their own runs by the
`run` field every record carries, so neither session is read as part of the other.

**Redaction**, by two mechanisms that are not equally strong. Every secret this server has been
handed — from a profile or from a raw `connection` — is masked **by value**, wherever it appears
and in whatever syntax, so a key that reached this process cannot leave it in a transcript. Under
that sits a scan for `key=`/`password=` in text, which also catches a secret the server has never
seen (one a target printed itself); it has to guess a syntax and is best-effort by nature. An
argument member *named* like a secret is masked whole. Prefer a
[profile](./kernel-profiles.md) regardless: it
keeps the key out of the request in the first place, and all of this is the backstop.

**Retention.** Nothing else is masked, and that is the point to plan around: debugger output is the
contents of somebody's memory — stack frames, strings, registry paths, whatever the target holds —
so a transcript of a live session is as sensitive as the machine it was taken from. Treat one like
a crash dump. Keep it out of version control unless you have read it, put it somewhere with the
same access as the target, and delete it when the investigation is done. The file is **appended**
to, never truncated, so a path reused across runs accumulates until something removes it; each run
starts with a `start` record naming its pid, which is what separates them.

**Size.** Fields are capped at 16 KiB, and a record says how much it dropped rather than being
quietly short. `WINDBG_MCP_TRANSCRIPT_MAX_FIELD` moves the cap; `0` removes it, at the cost of a
file that grows with every module listing and pool census. A whole record is bounded too, well
above what a capped one reaches: a record past that ceiling is replaced by an `oversized` marker
naming its kind and size, which is a bug in the recorder rather than something a session did.
