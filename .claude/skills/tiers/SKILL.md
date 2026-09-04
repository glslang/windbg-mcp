---
name: tiers
description: Run and interpret this repo's test tiers - what `cargo test` covers, which gates are off by default, and how to turn on the dump, bounded, live-kernel, TTD and 32-bit tiers. Use before claiming a change is covered by a green run, when a tier needs enabling, or when a pass count or SKIPPED line has to be read correctly.
---

# Running the test tiers

**The pass count does not say which tiers ran.** Each gate is inside its test, so the `mcp_smoke`
harness reports the same **99 passed** with the debugger tier off as with it on — that harness's own
result line, since a plain `cargo test` runs the crate's several hundred unit tests beside it and
prints a result line per binary. What differs between the two runs is the runtime (measured on the
ARM64 bench 2026-08-23: **1.6s against 61s** for `cargo test --test mcp_smoke`) and the `SKIPPED`
lines, which only `--nocapture` prints. Read one of those two before believing a run covered a
debugger claim. The count moves whenever a test is added — it was 69 until #195 and #196, 75
until item 37, 79 until the TTD tier, 84 until item 50's version-resource test, 85 until
item 48's two endings, 87 until item 49's live 32-bit target, 88 until item 51's
attach teardown, 89 until the 32-bit worker's version resource, 90 until #66's symbol-path default,
91 until #83's two asynchronous-execution tests, 93 until #85's module-inventory refresh, 94 until
the session fuzz, 95 until item 55's retired-handle teardown, 96 until item 14's watchdog-cost
guard and 98 until #273's worker-console assertion — and it said 83 while it was 84,
90 while it was 91, 93 while it was 94, and 97 while it was 98, which is the usual state of it, so
re-derive it rather than trusting this sentence.

**And a gate can be a *directory beside the exe*, which prints no `SKIPPED` line at all.** The
debugger tier's `!analyze` assertions are inside `if analysis["ran"] == true`, and `ran` is false
without `winext\ext.dll` — which `ci.yml` does not copy (it takes `dbghelp.dll` and `symsrv.dll`
and no extension directory), so **every `!analyze` claim in that tier is vacuous on both CI
runners** and a green matrix says nothing about any of them. Restoring the extensions on this
bench on 2026-08-30 immediately failed a fixture that had been passing for want of ever running.
Its premise was wrong in the instructive direction: the two driver crashes were described as
disagreeing about `!analyze`'s attribution because `MessageManager` has no PDB and `HEVD` ships
one. Measured on one engine against both dumps, they do not disagree — what decides it is
`triage\triage.ini` (present: each names its driver; absent: both `Unknown_Module`; no `winext\`:
`ran: false`), and the missing PDB costs the *function*, which is not what the test read. So
`analyze_can_attribute_a_module()` asks the **host** and both branches assert, and
`docs/smoke-test.md` carries the table. Two rules fall out. A fixture whose expected value differs
per fixture is worth a second look when the thing being measured is the *engine* — one fixture
would have been enough to notice. And bundling the engine changes what the tier covers, so re-run
it after a `setup.md` copy rather than assuming a green run transfers.

**The dev exe can be locked too, and the failure is quiet.** A worker left running — a driver
script that died mid-session, a debugger tier killed partway — holds `target\debug\windbg-mcp.exe`,
and `cargo build` then fails at the final replace step with `Access is denied (os error 5)` while
everything before it succeeded. If you are driving the binary by hand rather than through
`cargo test`, the next run **silently executes the old code**, which reads as the change not
working. Kill it **by path, not by name**: the registered release server is the same image, and taking it
down with `/IM` drops every session it holds — which for a live kernel leaves the guest frozen (see
the KDNET notes in `.claude/skills/live-kernel/SKILL.md`). Only the processes under `target\debug`:

```pwsh
Get-Process windbg-mcp -ErrorAction SilentlyContinue |
  Where-Object { $_.Path -like '*\target\debug\*' } | Stop-Process -Force
```

Then re-read the build output before believing a behavioural result. Note `cargo clippy` and
`cargo test --bins` do *not* refresh that exe: clippy only checks, and the test harness is a
separate binary.


`cargo test` includes `tests/mcp_smoke.rs`, which spawns the **dev** binary (via
`CARGO_BIN_EXE_windbg-mcp`) and drives it over stdio — so it is also clear of the release lock.
After a dependency bump (`rmcp`, `schemars`, `tokio`, `cargo update -p dbgscope`) or an MCP spec
revision, run it and follow [`docs/smoke-test.md`](./docs/smoke-test.md).

Two of its tests budget **what this server costs the model driving it** — the tool surface, paid
once per conversation, and each result, paid every call. They are guarded differently, and the
difference matters when you change one:

- **The surface** is goldened, in `tests/golden/tool_budget.json`, re-recorded by the same
  `UPDATE_GOLDEN=1 cargo test --test mcp_smoke` as the shape golden beside it. Read that diff
  rather than rubber-stamping it: it is the only place the price of a reworded description or a
  widened schema shows up, and it reports per tool (`modules: modelVisible 2112 -> 4200`).
- **Results are not goldened** — their sizes move with what symbols a runner resolves, so exact
  bytes would be flaky. They are per-tool ceilings in the `budgets` slice of
  `tool_results_stay_within_their_budget`, with a table printed under `--nocapture`. So a result
  that grows *within* its ceiling produces no diff anywhere; if you need to see the movement, run
  the tier and read the table. Changing a ceiling is an edit to that slice, not a re-record.

`--nocapture` is what makes either print anything: libtest shows a passing test's output nowhere.
[`docs/token-budget.md`](./docs/token-budget.md) has the baseline and what it exposed — including
the two client behaviours it settled by measurement: `outputSchema` never reaches the model, and
`structuredContent` *replaces* the text block rather than accompanying it. To include the tier that
opens the sample dump through DbgEng, set the gate first (PowerShell, not `VAR=1 cmd`):

```pwsh
$env:WINDBG_MCP_SMOKE_DUMP = "1"; cargo test --test mcp_smoke
```

That tier now also covers the process-per-session behaviour end to end: two sessions coexisting, a
kernel attach parked on a dead port being reclaimed by `end_session`, and no worker process
outliving the connection. It opens the **dump matching this host's architecture** — an ARM64 one is
checked in beside the two x64 samples, and each architecture also has a **driver** crash — and the
four assertions that read a *target* rather than
the dump's structure check first that this host can: `nt`'s base has to read, plus a resolved PDB
for the two that walk `nt`'s types. Where it cannot they print `SKIPPED` and pass, so a green tier
on a machine without symbols is not the same claim as a green tier here; read the `SKIPPED` lines
(`--nocapture`) before concluding a change is covered. `docs/smoke-test.md` has the measurements
behind that gate. The driver-attribution test is the one that is **not** paired by architecture: it
is a table run over every checked-in driver crash on every host, because an engine with symbols
reads either dump either way round and pairing would have cost an ARM64 runner the x64 crash it
already read. A third tier is `#[ignore]`d because it runs commands out to a watchdog
deadline (minutes, not seconds) — run it by hand after a dbgscope watchdog change:

```pwsh
$env:WINDBG_MCP_SMOKE_DUMP = "1"
cargo test --test mcp_smoke -- --ignored --nocapture --test-threads=1 bounded
```

A fourth tier drives a **real KDNET target** through a full session lifecycle — attach, work
alongside a second session, detach gracefully — separately checks that a client *disconnect*
releases a live kernel session rather than killing its worker, covers the **pool walk**
(`pool_find_tag`/`pool_census`) and the **module-inventory refresh**, both of which only mean
anything over a live link, and runs a **`debug_batch`
that patches a byte of the running kernel** and has to put it back (through a failing assertion, a
clamped call budget, a disconnect and an `end_session`) — the one claim a crash dump cannot test,
because a byte patched in a dump is patched in a file nobody reads again. It is gated on the
connection string (which nobody can guess) *and* `#[ignore]`d, so a stale variable can never freeze
a VM during an ordinary `cargo test`. Run it last, on its own.

**Before deciding a live-kernel claim cannot be checked, read the profiles.** This host normally has
one configured, and a configured profile *is* a live kernel target, so the tier can be run. The
failure this is here to stop is not asking the user for a key; it is concluding "no kernel target on
this host" without looking, shipping the live claim as unverified, and saying so in a PR. Two lines
settle it:

```pwsh
Get-Content "$env:USERPROFILE\.windbg-mcp\profiles.json" -Raw | ConvertFrom-Json | Get-Member -MemberType NoteProperty | Select-Object Name
Get-ChildItem Env: | Where-Object Name -like 'WINDBG_MCP_PROFILE_*' | Select-Object Name
```

Then set the variable **from the profile, in one step**, so the key never lands in a command line, a
tool argument or this transcript:

```pwsh
$env:WINDBG_MCP_SMOKE_KERNEL = (Get-Content "$env:USERPROFILE\.windbg-mcp\profiles.json" -Raw | ConvertFrom-Json).'ctf-vm'
cargo test --test mcp_smoke -- --ignored --nocapture --test-threads=1 live_kernel
```

The tier takes the *raw* string only because it has to exercise the explicit path — not because it
needs a second copy of the key. Print the profile **name** and the port when reporting what you are
attaching to, never the value; `attach_kernel {}` lists the configured names without disclosing any
of them. Only ask the user for a raw connection when no profile is configured at all.

`--test-threads=1` is not optional: the filter matches **eight** tests, and the KD transport is
single-owner, so in parallel the second attach fails and can leave the target halted.

A fifth tier **records its own target** rather than opening a checked-in one, which is what no other
tier does and why the three TTD defects of 2026-08-25 (#231, #232, #233) all shipped: a `.run` is
tens of MB, none is in the repo, and recording needs `TTD.exe` and elevation.

```pwsh
$env:WINDBG_MCP_SMOKE_TTD = "1"; cargo test --test mcp_smoke -- --nocapture ttd
```

Gated on the variable **alone** — no `#[ignore]` beside it, unlike the two tiers above — because a
stale variable here costs a few tens of MB in `%TEMP%` rather than a wedged VM, and against that the
rule that matters is that a gate nothing sets is a gap that stays open. Two things to know before
editing it. The host's reasons to stand down (no recorder, not elevated, a trace it cannot replay)
are read off the **recorder's own refusal** rather than probed for, because probing would put a
second copy of `ttd::find_ttd`'s search in a file that cannot call it; every *other* failure fails
the test, and that split is what stops the tier passing on a machine where recording is broken. And
its assertions read **which program was recorded**, from the trace's file name — TTD names a trace
after the program it launched — because the defect that survived review was a recording that
succeeded against the *wrong* program.

**The transport does not have to be KDNET, and the target does not have to be x64.** The variable is
a DbgEng connection string, passed through untouched, so `com:port=COM1,baud=115200` is as valid as
a `net:` one. Three assertions gate themselves on what the target actually is rather than on the
tier: the KD endpoint being owned by the worker is a UDP claim, the key-redaction claim needs a key
to look for, and the two **pool** tests need an x64 target because the walker decodes x64 pool
descriptors. Each says so when it stands down; none of them passes quietly.

