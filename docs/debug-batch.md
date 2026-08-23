# Transactional batches (`debug_batch`)

A sequence that *mutates* a target — patch a byte, arm a breakpoint, resume a thread — has to put
things back afterwards, and a client cannot be relied on to do it. The call that would have sent the
cleanup is exactly the call that times out, and a disconnect sends nothing at all. On a kernel target
that costs the VM: an un-restored patch, or a target left halted.

`debug_batch` submits the whole sequence as one op. It runs **inside the session's engine process**,
which owns the deadline, so the `always` block is reached on every path — success, a debugger error,
an assertion that did not hold, the deadline expiring, the session being torn down under it — before
the tool call returns. Part of the budget is reserved for it up front, because "what is left" after a
step that ran to its own deadline is nothing.

```jsonc
{
  "steps": [
    { "op": "eval", "expr": "poi(hevd!Guard)", "capture": "orig" },   // save
    { "op": "command", "command": "eq hevd!Guard 0" },                // patch
    { "op": "run_to", "address": "hevd!TriggerUaf",                   // confirm, with a verdict
      "expect": [{ "check": "contains", "text": "VERDICT: HIT" }] },
    { "op": "eval", "expr": "@rcx",
      "expect": [{ "check": "eval", "expr": "(@rcx > 0x1000)", "equals": "1" }] }
  ],
  "always": [
    { "op": "command", "command": "eq hevd!Guard {{orig}}" },         // restore, whatever happened
    { "op": "command", "command": "bc *" }
  ]
}
```

Eight step kinds. Five are the debugger itself: `command` (raw), `resume` (a command that moves the
target, plus the wait), `run_to` (a HIT/STOPPED ELSEWHERE/TIMEOUT verdict), `eval` (a MASM
expression's value), and `read_memory`. Three ask the kernel pool the questions the `pool_*` tools
ask — `pool_chunk`, `pool_find_tag`, `pool_census` — because those are walks over the allocator's own
descriptors rather than debugger commands, so no `command` step can stand in for them:

```jsonc
{ "op": "eval", "expr": "@$t1", "capture": "obj" },                    // what the target handed us
{ "op": "pool_chunk", "address": "{{obj}}", "refresh": true }          // what the allocator says it is
```

Inside a batch a walk is bounded by the *step's* share of the budget rather than by the whole call's,
so a `refresh` cannot spend the reserve the rollback lives on; a walk cut short still reports how
much of the pool it covered. Assertions are `contains`, `not_contains`, and `eval` — the
last compares two MASM expressions, so registers, memory and relations between them are all one
check. An `eval` step may `capture` its value under a name that later steps interpolate as
`{{name}}`; a reference that names no earlier capture is refused before anything runs.

**A field this tool does not know is an error, not something to ignore** — the one place in this
server where that is true. Serde drops unknown fields silently, so `"aways"` for `always` would be a
batch with no rollback block at all: mutations applied, nothing restored, `COMMITTED` reported. The
same goes for a misspelt `expect`, which is a step that asserts nothing and lets the batch commit.
Both fail *open*, so both are refused by name.

The report names every step that ran, the exact one that failed, what each step changed, whether the
rollback completed — reported *beside* the original failure, never instead of it — and whether the
session is left stopped, running, detached, or uncertain. A batch that did not commit comes back as a
tool error carrying that whole report.

It carries the same report as values (see [Structured results](./structured-results.md)), and the
pairing is worth reading once: a batch that **ran** answers `status: "ok"` — the report is the
answer — on a result flagged `isError` when the transaction did not commit or its rollback did not
finish. `status: "error"` is the batch that never ran at all: refused for a malformed step, a stale
handle, too little budget left to start. Reading only `isError` cannot tell those apart, and it is
the difference between "resubmit" and "check what the target is left holding".

Four honest limits, none of them hidden in the report:

- A raw command that prints an error and returns success is a step that *succeeded* with that text
  (DbgEng reports most failures that way), so assert on it if it matters.
- What a step "changed" is a best-effort classification of the command, biased toward reporting a
  change: it is a reporting aid, and the `always` block, not the classifier, is what makes a
  mutation recoverable.
- The reserve buys the rollback *time*, not a guarantee. A step that overruns far enough to consume
  the reserve as well leaves cleanup with no budget; the block is then skipped and the result says
  `rollback: INCOMPLETE`, naming each step that did not run.
- Against a **call timeout** the guarantee is arithmetic: the batch budget is clamped so the
  rollback finishes and the report is written before the caller gives up. Against a **teardown** —
  `end_session`, or a client disconnect, both of which release the target — it is a signal instead.
  The batch is told to stop, does so at its next step, runs `always`, and the teardown waits: the
  worker answers the signal with how long that batch may still need, so the wait covers the step in
  flight as well as the rollback. That figure is the batch's own remaining budget, which was already
  clamped to the caller's patience, so a teardown can never wait longer than the batch could have
  run anyway. What the signal cannot do is *shorten* a step already inside the debugger, so a batch
  of long steps stops at the end of the current one rather than where it stands — and it cannot undo
  what the batch never recorded, since `always` is still the only thing that puts anything back.
