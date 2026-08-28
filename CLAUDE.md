# CLAUDE.md

Guidance for Claude Code working in this repo. `README.md` is the map — it carries the tool table
and links out to one document per topic under `docs/` (`architecture.md`, `sessions.md`,
`tool-surface.md`, `structured-results.md`, …); this file covers the non-obvious operational
workflows.

## What this is

`windbg-mcp` is a Rust MCP server (stdio, `rmcp`) exposing **WinDbg/DbgEng** for live user-mode,
kernel, crash-dump, and Time Travel Debugging (TTD) work. The low-level DbgEng bindings come from
the sibling crate [`dbgscope`](https://github.com/glslang/dbgscope) (a **path/git dependency we grow
ourselves** — do not add third-party DbgEng crates).

**The binary has two roles.** Started normally it is the **supervisor**: MCP on stdio, no DbgEng.
Re-executed with `--engine-worker` it owns exactly one debug session, because dbgeng.dll holds one
debuggee session per process. Key source: `src/engine.rs` (the supervisor — session registry,
worker supervision, routing), `src/worker.rs` (the child process and the engine thread inside it),
`src/proto.rs` (the wire protocol between them), `src/server.rs` (the MCP tools),
`src/kdconn.rs` (KDNET connection profiles and the redacting `Connection` type), `src/ttd.rs`,
`src/main.rs` (role selection).

Practical consequences when debugging this server: a stack trace or log line can come from either
role (both write to the supervisor's stderr, told apart by `tracing` target — `windbg_mcp::worker`
against `windbg_mcp::engine` and friends), and killing the supervisor leaves no workers behind —
they exit when their request channel closes.

The same records are also readable **through the tool surface**: `server_log` serves a bounded ring
of them (`src/logbridge.rs`), with a worker's tagged by session, which is the only way to see them
when the client is not on this machine (`--listen`). It is a copy of the stderr stream, not a
replacement — worker stderr is untouched — so it holds nothing below the level the server was
started with; `RUST_LOG` widens both together. The ring is bounded, so it holds the run-up to a
failure rather than a session's history — a transcript (below) is what keeps history.

The **supervisor↔worker protocol channel** is a pair of inherited anonymous pipes, *not* the
worker's stdio: anything a worker prints to stdout is drained into the log and cannot reach the
protocol.

## Updating the running windbg MCP after code changes

The MCP server registered for this repo runs `target\release\windbg-mcp.exe`. **While that server is
connected in a Claude Code session, it holds an open handle to the exe**, so a plain
`cargo build --release` fails at the final replace step with `Access is denied (os error 5)` — but
only *after* compilation has already succeeded.

To rebuild and load the new code without stopping the session:

1. **Rename the locked exe out of the way** (Windows allows renaming a running image, just not
   deleting/overwriting it):
   ```
   mv target/release/windbg-mcp.exe target/release/windbg-mcp.exe.stale
   ```
2. **Build** into the now-free path:
   ```
   cargo build --release
   ```
   This builds the `dbgscope` revision pinned in `Cargo.lock` and writes a fresh
   `target\release\windbg-mcp.exe`. If this `windbg-mcp` change depends on a newly pushed
   `dbgscope` commit, move the pin first — edit the `rev` in `Cargo.toml`, then
   `cargo update -p dbgscope` — and commit both with the `windbg-mcp` change (see below: the update
   command alone does **not** move a `rev` pin). The running server keeps executing the *old* code from the
   renamed `.stale` file until its connection is recycled.
3. **Load the new binary** by reconnecting the server: `/mcp` → reconnect `windbg` (or restart
   Claude Code). Only after this reconnect do the windbg tools run the new code.
4. Once reconnected (the old process is gone), delete `target/release/windbg-mcp.exe.stale`. Do
   **not** delete it while the old process is still alive — it demand-pages code from that file.

A worker is spawned by re-executing the supervisor's *own* image, so a supervisor running from the
renamed `.stale` file spawns workers from it too — old code stays consistently old, which is what
you want. It also means `.stale` can be held by more than one process: reconnecting ends the
supervisor, and its workers exit with it, so step 4 is still just "after the reconnect".

## Changing dbgscope (the DbgEng bindings)

`dbgscope` is a **git dependency pinned to an exact `rev`**, not a path dependency — a `windbg-mcp`
build pulls it from GitHub, so **local edits to a dbgscope checkout are invisible to a `windbg-mcp`
build until they are pushed** and the pin is moved. Add new DbgEng primitives as typed `dbgscope`
methods (returning `Result<_, DbgEngError>`, not `panic!`/`.expect`), not via the `execute` text
hatch.

**`cargo update -p dbgscope` does not move the pin.** `Cargo.toml` names a 40-character `rev`, so
the update command only re-resolves *that* revision; the pin is moved by editing the `rev` and then
running `cargo update -p dbgscope` to refresh `Cargo.lock`. Commit both. (This file used to say the
update command alone was enough, which silently leaves you building the old code.)

**Develop against the feature branch, not a `[patch]`.** Push the dbgscope branch and point
`Cargo.toml`'s `rev` at that branch commit while iterating: it needs no local checkout on the build
machine, it works identically on every machine, and it travels through git like everything else.
Repoint before the dependent PR merges — and **"the merge commit" may not exist**, which is how
this was got wrong on 2026-08-27. dbgscope#120 was *rebase*-merged, so its commits landed on `main`
under new SHAs and the branch head this repo pinned was an ancestor of nothing there. It went on
building only because the merged branch had not been deleted yet; deleting it — the ordinary tidy —
would have left `main` unable to resolve its own dependency. So the rule is **repoint at whatever
`dbgscope`'s `main` now is**, and check rather than assume:

```console
git -C ../dbgscope merge-base --is-ancestor <pinned-rev> origin/main   # 0, or the pin is dangling
```

Both PRs merging together is the ordinary case, not a mistake, so the check belongs after the merge
as well as before it. A `[patch]` section still works for a quick local `cargo check` but must never
be committed:

```toml
[patch.'https://github.com/glslang/dbgscope']
dbgscope = { path = "../dbgscope" }
```
`git checkout -- Cargo.toml Cargo.lock` afterwards.

**A green dbgscope PR says nothing about Miri**, since 2026-08-22: it is by far the longest job
there (9 minutes median against `ci.yml`'s 1) and had never failed in a hundred runs, so it runs on
the merge to `main`, weekly for nightly-toolchain drift, and on `workflow_dispatch` — **not** on
pull requests. Dispatch it against the branch when a change touches unsafe code; the alternative is
`main` going red after your merge. A path filter was measured and rejected there, and the workflow's
own header says why, so it is not worth re-proposing.

**Both repos require an approving review**, and a solo maintainer cannot self-approve, so a green
PR still needs `gh pr merge --admin`. In this harness that call is refused by the permission
classifier — so **the human merges**, and an agent's job ends at "green and waiting". Plan the two
PRs around that: dbgscope first, then repoint and re-verify.

## Local verification (no session restart needed)

For a compile/behavior check without touching the locked release exe, use the **dev profile**
(writes `target/debug`, which the registered release server never holds): `cargo test` and
`cargo clippy --all-targets`. The release
build differs only in optimization and is exercised by CI on a fresh runner.

**And the whole crate type-checks from the Mac, which this repo believed it could not.** `cargo
check` does not link, so `rustup target add x86_64-pc-windows-msvc` (and the `aarch64` one) is
enough to run `cargo check --target <msvc> --all-targets` and `cargo clippy` over `src/`,
`tests/` *and* the dependency, on a machine with no Windows anywhere. It takes seconds and needs
no VM. What it does **not** do is run anything: a behavioural claim still wants `cargo test` on
the VM, and the debugger tiers still want a real `dbgeng.dll`. But every mistake that is a *type*
error — a wrong signature, a missing `windows` feature, an API that moved under a dependency bump
— is answerable here, and that is most of what a dependency bump breaks. Doing the `dbgscope`
split this way caught a `windows` feature trimmed by module path (`IMAGE_NT_HEADERS64` is gated
behind `Win32_System_SystemInformation`, not the `Debug` feature its path suggests) that would
otherwise have been a red VM build.

**One warning from that check is expected and is not a break.** `build.rs` compiles the binary's PE
version resource (item 50 — an empty `FileVersion`/`CompanyName`/`ProductName` is half of why
Defender scored this project's own exe as `Bearfoos.B!ml`), and that needs `rc.exe`, which no Mac
has. The script prints `cargo::warning=no PE version resource was embedded: …` and carries on,
because failing there would cost this whole workflow for the sake of metadata. Which means the
warning is the *only* thing between a Windows build that quietly lost its resource and a release, so
the assertion is a test instead — `mcp_smoke::the_binary_carries_a_pe_version_resource`, which reads
the resource back through `GetFileVersionInfoW` on the one host that can build one. To check that
test still catches what it is for, break the compiler rather than the code:
`$env:RC_PATH = "C:\nope\rc.exe"`, touch `build.rs`, re-run it, then unset and touch again. And note
the resource is composed **in `build.rs`** from `CARGO_PKG_*` and literals for a reason: an `.rc`
template or an icon file would be a new build input, and `INPUTS` is one const precisely so the
watch list and the dirty check cannot disagree about what a clean build is.

**A `[patch]` cannot verify against a repo that does not exist yet.** Cargo resolves the original
source *before* applying the patch, so pointing one at a local checkout still fetches the git URL
and fails on a repo not yet created or renamed — which is exactly the middle of a rename. Swap the
dependency itself to `path = "../dbgscope"` for the check and restore it afterwards; the `[patch]`
recipe below works only once the remote is real.

**A dependency's source can be read on the Mac, and the copy there may not be the pinned one.**
`~/.cargo/registry/src/` holds only what this machine has *fetched*, and nothing fetches after a
bump the Mac never built — on 2026-08-24 it had `rmcp-3.1.2` while `Cargo.lock` pinned `3.1.4`
(dependabot #207 bumped it two days earlier). That reads as nothing at all: the API was unchanged,
so a change written against the older source compiled on the VM first try, and it was luck rather
than method.

**So `cargo fetch --locked`, and then let Cargo say where the source is** — do not build the path:

```console
cargo fetch --locked
cargo metadata --locked --format-version 1 |
  jq -r '.packages[] | select(.name=="rmcp")
         | "\(.version) \(.manifest_path | rtrimstr("/Cargo.toml"))"'
```

The fetch resolves and downloads without compiling, so the Windows-only dependencies are no
obstacle, and it takes seconds. `--locked` on both is not decoration: bare `cargo fetch`
re-resolves whenever `Cargo.toml` and `Cargo.lock` are out of step — which is exactly what the
middle of a `dbgscope` `rev` bump is — and would unpack a version nobody reviewed while moving the
pin under you. Neither command touches the lock (measured).

**Reading the path out of `cargo metadata` rather than assembling one is the whole point**, because
a hand-built `registry/src/*/<crate>-<ver>/` is wrong three different ways and this is wrong none:
the `*` matches a copy fetched earlier as readily as the pinned one (`tokio-1.53.0` and `1.53.1`
are both unpacked here); a crate can be in the graph twice, so a name alone does not identify a
version (`syn` is at 2.0.117 and 3.0.3); and a **git** dependency is not under `registry/src` at
all — `dbgscope` is at `~/.cargo/git/checkouts/dbgscope-<hash>/<short-rev>/`, which is both the
dependency most worth reading here and the one a registry path misses silently.

Anything read this way is still a claim about source, not about behaviour; `cargo test` on the VM is
where the pinned version is the one that compiles.

**Two of CI's gates are not Rust and both run on a Mac in seconds**, which matters because this repo
is edited from one and compiled on a VM — so the checks that need no Windows are the cheapest ones
to forget. `cargo fmt --all --check` is the first step of *Build & test*. The other is
**`Documentation lint`**, a markdownlint over `README.md`, `CHANGELOG.md`, `docs/**` and
`skills/**` — note `CLAUDE.md` and `FOLLOWUPS.md` are **not** in its globs, so a clean run says
nothing about them. `.markdownlint.jsonc` — *not* `.markdownlint-cli2.jsonc`, which does not exist
here — turns off three of the defaults and leaves every other one on: no line-length rule (MD013),
no table-pipe spacing (MD060), and duplicate headings flagged only among siblings (MD024), which is
what lets `CHANGELOG.md` repeat `### Added` under every version. **MD051 — a link fragment with no
matching heading — is the one that has actually bitten**, because it is what *renaming a heading*
does to every in-file link pointing at it, and it cost a red round on #196; it is not the only rule
that can fail the job. Same version as CI:

```console
npx markdownlint-cli2@0.23.2 README.md CHANGELOG.md "docs/**/*.md" "skills/**/*.md"
```

It checks *same-file* fragments only, so a cross-file `../README.md#some-heading` is still yours to
verify by hand.

**The pass count does not say which tiers ran.** Each gate is inside its test, so the `mcp_smoke`
harness reports the same **89 passed** with the debugger tier off as with it on — that harness's own
result line, since a plain `cargo test` runs the crate's several hundred unit tests beside it and
prints a result line per binary. What differs between the two runs is the runtime (measured on the
ARM64 bench 2026-08-23: **1.6s against 61s** for `cargo test --test mcp_smoke`) and the `SKIPPED`
lines, which only `--nocapture` prints. Read one of those two before believing a run covered a
debugger claim. The count moves whenever a test is added — it was 69 until #195 and #196, 75
until item 37, 79 until the TTD tier, 84 until item 50's version-resource test, 85 until
item 48's two endings, 87 until item 49's live 32-bit target and 88 until item 51's
attach teardown — and it said 83 while it was 84,
which is the usual state of it, so re-derive it rather than trusting this sentence.

**The dev exe can be locked too, and the failure is quiet.** A worker left running — a driver
script that died mid-session, a debugger tier killed partway — holds `target\debug\windbg-mcp.exe`,
and `cargo build` then fails at the final replace step with `Access is denied (os error 5)` while
everything before it succeeded. If you are driving the binary by hand rather than through
`cargo test`, the next run **silently executes the old code**, which reads as the change not
working. Kill it **by path, not by name**: the registered release server is the same image, and taking it
down with `/IM` drops every session it holds — which for a live kernel leaves the guest frozen (see
the KDNET notes below). Only the processes under `target\debug`:

```pwsh
Get-Process windbg-mcp -ErrorAction SilentlyContinue |
  Where-Object { $_.Path -like '*\target\debug\*' } | Stop-Process -Force
```

Then re-read the build output before believing a behavioural result. Note `cargo clippy` and
`cargo test --bins` do *not* refresh that exe: clippy only checks, and the test harness is a
separate binary.

**A `.ps1` this repo ships has to parse under Windows PowerShell 5.1, and three ways of failing
that are invisible on the machine you write it on.** The scripts in `tools/` and `examples/` run on
*debuggees*, where 5.1 is the only PowerShell there is, and all three faults below abort before the
script does anything — `tools/ioctl_harness.ps1` had all three at once:

- **Non-ASCII in a BOM-less UTF-8 file.** 5.1 decodes such a file in the ANSI code page, so an em
  dash becomes three characters, the last of which is a quotation mark that *ends a string* — and
  the parse error is reported tens of lines later, pointing at a brace. Keep these files ASCII
  (`grep -P '[^\x00-\x7F]'`); PowerShell 7 hides this completely by assuming UTF-8.
- **A hex literal that does not fit `Int32`.** `0x80000000` is a *bit pattern* in 5.1, so it is
  negative and a `uint32` parameter refuses it; 7 widens the same literal to `Int64` and the call
  succeeds. `[Convert]::ToUInt32('80000000', 16)` reads the same on both — the `[uint32]` cast of
  either the literal or a `'0x…'` string fails on 5.1.
- **Returning an empty array.** `return [byte[]] @()` is unrolled by the pipeline into nothing, so
  the caller gets `$null` and every `.Length` on it fails under `Set-StrictMode`. `return , ([byte[]] @())`.

**Driving the server over stdio from a script: do not redirect stderr unless you drain it.** With
`RUST_LOG` widened the server fills the stderr pipe buffer and blocks mid-request, which looks
exactly like a hung debugger. Leave stderr inherited (it lands in your terminal, interleaved) or
read it on a second thread.

**Both review bots comment per commit**, and a round of findings can land *after* a reply to the
previous round. Before calling a review done, re-check with the head SHA:
`gh api --paginate repos/<owner>/<repo>/pulls/<n>/comments --jq '.[] |
select(.original_commit_id=="<sha>")'` — with `--paginate`, since a busy PR's comments span pages
and the first page is exactly where the older rounds are.

**They also circle the same topic, and contradict each other and themselves across rounds.** A bot
reviews *this diff* without the argument that produced it, so the same seam comes back round after
round from a different angle — and a finding framed as "fresh evidence relative to the prior
comment" may be the same claim, or may be genuinely new. Three shapes seen across the four PRs
behind `FOLLOWUPS.md` item 34 (#189 to #192), all from the same reviewer:

- **Against code that no longer exists.** One round argued about a teardown task the *previous*
  commit had deleted. Check which commit a comment is anchored to before acting on it.
- **Round-tripping a decision.** Successive rounds drove a check out of `Lease::admit` and then
  asked for it back. Both were right about different properties, and only reading the code settled
  which — the review text alone could not.
- **Right about the fact, wrong about the remedy.** "The SCM will not deliver a control code to a
  `StartPending` service" was correct (`ERROR_SERVICE_CANNOT_ACCEPT_CTRL` — measured, by holding a
  real service there with an address not on the host). Its proposed fix was a new IPC channel; the
  right fix was a message that stopped claiming otherwise.

So: **verify the fact against the current code, then decide the remedy yourself.** A correct finding
does not make its suggested fix correct, and a confident one is not evidence of anything. Measuring
beats arguing whenever the claim is about behaviour: most of these were settled in one experiment.

**Declining is a normal outcome, and where the reason goes depends on whether the decline shaped a
change.** If you are committing anyway — you took the fact and rejected the remedy — the reason
belongs in *that* commit message, because the next round will raise it again against code that by
then looks deliberate, and nothing else will record why it is the way it is. If nothing changed,
there is nothing to attach a reason to and nothing to protect: repeating the decline next round
costs a sentence, so tell whoever is driving the work and leave it there. Do not manufacture a
commit, and do not argue with the bot in a reply — neither is read by the round that follows.

**A finding about *prose* is acted on only if the prose is wrong, or inconsistent with the code.**
Everything else — rewording, hedging, "consider splitting this rule across the three files that
state it" — is declined, which by the rule above means no commit and no reply: nothing changed.
**Say it to whoever is driving the work**, in one line, so the count of what was waved through
stays visible to them rather than only to you.

The rule exists because the review pressure here is almost entirely on sentences: across #196, #198
and #199, **every** bot finding was about one, and none was about the code those PRs changed. Most
of that pressure pushes toward making correct sentences longer, which is churn and costs a CI round
each time. What the rule still catches, all from those three PRs:

- **Wrong.** A config documented as `.markdownlint-cli2.jsonc`; the file is `.markdownlint.jsonc`.
  And a skill saying `--set-listen-client-tools <name>` changes a client's surface, when with no
  `--tools` beside it that command *clears* the spec — an operator following it removes the
  restriction they meant to change.
- **Inconsistent with the code.** A refusal telling every caller to run a service-only command,
  when a foreground listener's clients come from the environment. And "a change reaches a client
  when it next connects", which describes one MCP revision while the listener's factory identifies
  a sessionless client on *every request*. Neither sentence is false on its face; both produce the
  wrong action.
- **Inconsistent with its own cited source.** A list of the three handoff files, contradicted by
  one of the PRs named as its origin.

When a sentence does have to change, prefer **making the one rule true** over splitting it into two
— that is what the last of those became, and it kept a single summary line that is now correct for
both revisions rather than two rules in three files.

**When findings keep landing on one mechanism, delete the choice generating them rather than fixing
them one at a time.** Each finding is locally real and each fix is locally correct, which is exactly
what makes the pattern hard to see from inside it: the count of mechanisms goes up every round and
nothing looks wrong. The signal is *accumulation on one seam*, not any individual finding. Item 34
produced it twice in one PR ([#189](https://github.com/glslang/windbg-mcp/pull/189)):

- **`--token-out`** let the operator name where a generated token was written. Round one moved the
  ACL before the write; round two found the close-and-reopen race that opened. Every fix was
  another turn of the same screw, and what generated all of them was writing a secret into a
  directory this program does not control the protection of. Deleting the flag — the token goes
  beside the credential file, in the directory already `SYSTEM`-and-`Administrators`-only — ended
  the class outright.
- **Revocation** produced findings in five consecutive rounds, all of them consumers of one
  ambiguity: a `Client` was a *name*, so a name given back was indistinguishable from its
  predecessor to session ownership, routing, lease state and the registry gate. Making identity
  `(name, incarnation)` ([#192](https://github.com/glslang/windbg-mcp/pull/192)) deleted the `409`
  a re-added name waited out, `Sessions::unrevoke`, and the whole question of *when* to lift a
  gate — where two of the five findings had lived.

**And then check what the deleted thing was also load-bearing for**, because this repo has now got
that wrong twice in one PR. A revocation was simplified into "an expiry that does not wait", which
silently gave up the `releasing` flag that had been blocking a re-added name; and the `revoked`
check in `Lease::admit` was removed for a reason that was sound, dropping a *second* property it
also provided (refusing the revoked incarnation's own in-flight request). Both times the full suite
stayed green — a passing test is not evidence that a deleted check was doing nothing, only that
nothing covered it. Before deleting, name every property the code provides; after deleting, assert
the ones you meant to keep.

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
(`pool_find_tag`/`pool_census`), whose cost only exists over a live link, and runs a **`debug_batch`
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

### Two ways a target is reached, and neither is "the" procedure

**KDNET.** Check the target is reachable *before* starting the tier, not by starting it — an attach
that finds nothing parks its worker in `WaitForEvent(INFINITE)` for the whole run and reports a
timeout that measures the environment rather than the code. What settles it is not "can I reach the
guest" but **does the guest's `bcdedit /dbgsettings hostip` equal this debugger host's current IP**,
on the port the profile names; the host IP moves between sessions. Compare the key by *hash* rather
than printing it.

*Finding* the guest is topology-specific. On the machine that paragraph was written for, the
debugger host is itself a Hyper-V guest — `Get-VM` does not exist and there is no local VM to start
— so the target is a *sibling*: it appears in the neighbour table (`Get-NetNeighbor | ?
LinkLayerAddress -like '00-15-5D*'`) and answers **TCP 5985** and nothing else, ICMP and 445 being
closed, so a failed ping proves nothing there. With several neighbours the table will happily
validate the wrong guest, which is what the `hostip` comparison is for.

**Serial, which is what the Parallels bench uses** — and there KDNET is not merely unconfigured but
*impossible*: guests get a `Parallels VirtIO Ethernet Adapter` (`PCI\VEN_1AF4`), and `1AF4` is not
in the Debugging Tools' `VerifiedNICList.xml`. `prlctl set <vm> --device-set net0 --adapter-type
e1000` is accepted and silently ignored on ARM, leaving the guest with no network at all. Do not
spend an afternoon on it. The wiring that works is a TCP socket between two guests:

- target `serial0` → `tcp://localhost:2020`, **client**; `bcdedit /dbgsettings serial debugport:1
  baudrate:115200`
- debugger `serial0` → `tcp://:2020`, **server** — then `prlctl set <vm> --device-connect serial0`,
  or it stays `state=disconnected` and nothing binds the port, and a **VM restart**, or the guest
  never sees a COM port
- `netstat -an | grep 2020` on the Mac: a LISTEN *and* an ESTABLISHED pair means the wire is up
- on the target, `ARM PL011 Serial Port Device (COM1)` in **`Error`** state with no name from
  `GetPortNames()` is correct — that is the kernel debugger owning the port

Three traps on that bench, each of which cost real time:

- **`kd -b` is no longer supported** — the docs say so in those words, and it is silently a no-op,
  so a `kd -k … -b` probe sits at `no_debuggee` against a *running* target and looks like a dead
  link. Use **`-bonc`**. windbg-mcp itself is unaffected; DbgEng issues a proper break-in.
- **Parallels `Pause idle` is on by default**, and a target broken into the debugger burns no CPU,
  so the hypervisor suspends the whole VM mid-run and every later call times out with nothing to
  explain it. `prlctl list` then shows it `paused`, which is *not* a kernel halt.
  `prlctl set "<vm>" --pause-idle off`.
- **A worker killed while holding a broken-in kernel leaves the guest frozen** — `prlctl exec` hangs
  on it. Attaching and detaching properly is the fix:
  `kd -k com:port=COM1,baud=115200 -c ".time;qd"`.
- **Do not hard-reset the debuggee to clear a corrupted kernel pool.** Two `prlctl reset`s in a row
  put it into WinRE ("Your device ran into a problem and couldn't be repaired"), which wants console
  input `prlctl` cannot send and `prlctl exec` cannot see past — a third reset happened to boot
  through it, but nothing guarantees that. Let a bug check reboot the machine itself
  (`AutoReboot=1` is already set there), and expect a file written just before a reset to come back
  whitespace-filled.

**A pool walk will not finish over 115200 baud.** It reads every committed pool page and times out
at 240s, so on a serial bench "x64-only" and "too slow over this wire" cannot be told apart.

## Live kernel + driver IOCTL gotchas (learned driving HEVD over KDNET)

**Loading HEVD on an ARM64 bench takes two things, and the error names neither.**
`StartService FAILED 577` ("cannot verify the digital signature") means both `bcdedit /set
testsigning on` (a reboot) *and* the driver's signing certificate imported into
`Cert:\LocalMachine\Root` — test signing has nothing to chain to otherwise, and an unexpired cert
that is simply untrusted looks identical to an expired one. `TrustedPublisher` refuses with
`E_ACCESSDENIED` and is not needed for `sc start` of a non-PnP driver. Check HVCI
(`(Get-CimInstance Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesRunning`)
before blaming signing; `0` means it is not the cause.

**A crash out of an exploit client is usually not a driver bug.** HEVD's stack-overflow client on
this bench bug-checks `0xFC` with the kernel faulting at the *user-mode payload* — its ROP chain
never disables privileged execution of a user page — so the stack is `nt`-only and carries no
`HEVD` frame at all. A fixture that needs a driver frame wants a path that faults **inside** the
driver, not a failed exploit.

**Getting HEVD to bug-check at all is harder than it looks, because it is written to survive.**
Every trigger is wrapped in `__try/__except`, so a kernel-mode access violation is caught and
returned as a status: the null dereference answers `STATUS_ACCESS_VIOLATION` with the machine still
running, the non-paged pool overflow answers *success* and quietly corrupts the pool, and the UAF
double free answers success twice and surfaces minutes later on a heap-maintenance worker thread as
a `0x13A` whose stack is `nt`-only — the one shape a driver-attribution fixture must not have.
What SEH cannot catch is a **fail fast**. `HEVD_IOCTL_BUFFER_OVERFLOW_STACK_GS` compiles its trigger
with `/GS`, so overrunning the buffer corrupts the cookie and the driver's own `__report_gsfailure`
runs `mov w0, #2; brk #0xf003` — `0x139 KERNEL_SECURITY_CHECK_FAILURE`, raised inside the driver.
That is how `docs/samples/082126-7015-01.dmp` was made (issue #154); `docs/smoke-test.md` has the
one-line recipe.

**Read a driver's IOCTL codes out of its own dispatch — do not take them from a published list.**
This build's are not the ones HEVD's widely-quoted table gives, and the code that table calls the
null dereference is `FREE_UAF_OBJECT` here. Sending the wrong one is not always harmless: several
of them corrupt the kernel silently. The dispatch walk earlier in this section and `decode_ioctl`
are how to read them; on ARM64 the switch is a chain of `sub wN, wM, #0x222, lsl #12` against a
literal, and each case block's `DbgPrintEx` format string names the handler.

**Also: HEVD returns `STATUS_UNSUCCESSFUL` from handlers that succeeded.** `AllocateUaFObject*`
initialises its status to `0xC0000001` and never sets it on the success path, so `sc`-style error 31
out of the harness means nothing. Trust the resulting state, not the status.

**Attach by `profile`, not by connection string — always, for any live target.** `attach_kernel
{ "profile": "<name>" }` resolves the connection inside the server (`src/kdconn.rs`), so the
target's debug key never lands in a tool argument — and therefore never in the *client's*
transcript, where one key previously ended up replicated across hundreds of records.
`attach_kernel {}` lists the profiles this host has. Configure one with
`WINDBG_MCP_PROFILE_<NAME>` or `%USERPROFILE%\.windbg-mcp\profiles.json`; raw `connection` still
works for a target nothing is configured for, and is the last resort rather than the quick option.

A raw `connection` now also reaches a second place: with recording on (below) it is written to the
server's own transcript file, scrubbed to `key=<redacted>`. That backstop is not a reason to pass
one. A profile keeps the key out of the request, so there is nothing for either transcript to
redact, and redaction is a thing that has to keep working while a key never sent cannot leak.

The live smoke tier below is the one sanctioned exception: `WINDBG_MCP_SMOKE_KERNEL` is a raw
connection string, passed straight to `attach_kernel { "connection": … }`, and is deliberately
*not* a profile — the tier has to exercise the explicit path, and it is a variable in a developer's
own shell rather than something a client ever sees.

A worker process does **not** inherit `WINDBG_MCP_PROFILE_*` (`engine::spawn_worker` strips them):
it is told the one connection it is opening over its private pipe, and a `launch`ed debuggee would
otherwise inherit every configured key on the host.

**KDNET attach is a blocking wait, by design.** A live kernel needs `WaitForEvent(INFINITE)` (a finite
timeout returns `E_NOTIMPL` and never drives the link). So if the target isn't reachable, the
`attach_kernel` MCP call reports a *timeout* while its **worker process** stays parked in the wait —
it self-heals and completes the attach the moment the target actually connects. Consequences:
- The park costs **that session only**. Other sessions and every other tool keep working, so an
  attach that is going nowhere is no longer a reason to restart the server. `session_status` says
  how long it has been waiting and whether that is past the point a healthy link takes;
  `end_session` reclaims it, terminating the worker process if the wait will not unwind (it won't —
  `SetInterrupt` cannot reach a wait that has not yet connected).
- **Do not re-run the attach while it is still waiting.** The connection was already claimed, so a
  retry dials a second time. End it first, or fix the target and let the original attach land.
- Diagnosing why nothing dialed in is still out-of-band work (PowerShell): check the debugger is
  listening (`Get-NetUDPEndpoint -LocalPort 50000` → owned by `windbg-mcp.exe`, which will be the
  *worker* process) and whether any VM is running.
- The **target must dial this host**: on the target, `bcdedit /dbgsettings net hostip:<debugger-ip>
  port:50000 key:<key>` — **colons, not `=`**. `hostip` must be the debugger host's current IP.
  Symbols are **not** pulled over the KD wire (see below).
- After a target reboot, the settling KD link shows repeated break-ins in **`kdnic.sys`** (the KD NIC
  transport: `nt!DbgBreakPointWithStatus` ← `kdnic!TXTransmitQueuedSends`). These are not real stops —
  `go` through them until boot proceeds.

**Walking a service-loaded driver's IOCTLs live.** `sxe ld:<drv>.sys` breaks on module load, which is
**before DriverEntry runs** — so the driver object's `MajorFunction` table is *not* populated yet
(`driver_object` shows defaults / "is not a driver object"). To let DriverEntry run and populate it:
1. Compute the PE entry point from the header: `? <base> + dwo(<base> + dwo(<base>+0x3c) + 0x28)`.
2. `bp` it, `go`. At entry, `@rcx` = `DriverObject`, `poi(@rsp)` = return addr (into
   `nt!PnpCallDriverEntry`). `bp` that return, `go` — now the table is populated.
3. `MajorFunction[0x0e]` (IRP_MJ_DEVICE_CONTROL, the IOCTL dispatch) is at **`DriverObject+0xe0`**.
   In the dispatch, the `IoControlCode` is `IO_STACK_LOCATION+0x18`; the current stack location is
   `IRP+0xB8`. `uf` the dispatch to read the (usually binary-search) IOCTL switch, `decode_ioctl`
   each code, and read each case's `DbgPrintEx` string (`da`) for the human name.

**Symbols must be on the debugger host.** PDBs are never fetched from the target over KD. Find the
exact PDB identity the engine wants with `!sym noisy; .reload /f <mod>` (it prints `<pdb>\<GUID>\...`),
then get that PDB onto this host. **Gotcha: `.sympath` / `.sympath+` swallow the *rest of the command
line* — they ignore `;`, so anything chained after them (`; .reload ...`) is parsed as path text.**
Issue `.sympath` alone, or use the **`set_symbol_path`** tool (goes through the DbgEng
`AppendSymbolPath`/`SetSymbolPath` API, immune to the quirk; appends + reloads). When a driver's
`module!Symbol` names don't resolve, **ask the user for the PDB folder** and apply it with that tool.

**Nothing resolves at all without `msdia140.dll` beside the engine** — `symsrv.dll` finds a PDB and
that one *parses* it, so without it every module reports `Symbol Type: EXPORT - PDB not found` even
when the identity was known and the file was downloaded. **`symsrv.dll` is the other half, and
System32 usually does not ship it**: on a machine with neither, a `srv*` path downloads nothing.
*Usually*, because it is not a constant and this repo believed it was — probing both CI runners
(issue #153) found one in `windows-latest`'s System32 and none in `windows-11-arm`'s, so check the host in
front of you (`where.exe symsrv.dll`) rather than assuming either way. Worth
knowing because of how that presents on a *dump* — not as missing symbols but as a **memory read
failing** (`0x8007001E`), since a kernel dump's virtual addresses are translated through structures
the engine locates with `nt`'s symbols. That symptom was read as an ARM64 engine limitation for a
while (issue #142); it is not one, and an engine with symbols reads x64 and ARM64 dumps alike. It is **not** store-package-only, which
this repo believed for a while: Visual Studio Build Tools ships it, including an ARM64 build, at
`…\BuildTools\DIA SDK\bin\arm64\msdia140.dll`. Copy it next to the exe (`target\release`, and
`target\debug` for the smoke tiers — **and `target\debug\deps` if a *unit* test loads the engine**,
which is where libtest's binaries actually run from; this file said `target\debug` alone until a
2026-08-26 test met System32's engine and failed with an error about something else entirely).
**Warm the cache once** afterwards — attach and `.reload /f nt`
— because the first fetch takes minutes and everything around it times out, which reads convincingly
as the parser having made things worse.

## Driving execution: the two waits, and the state a raw command can leave

**A plain `Execute` of execution-control text does not move the target.** DbgEng sets the run state
and returns; nothing happens until a `WaitForEvent` pumps it. That is why `go`/`step_*`/`reverse_*`
build `EngineOp::CommandAndWait` (→ `resumed` → `execute_and_wait`) and everything else goes through
`EngineOp::BoundedCommand` (→ `raw_command` → `execute_command_bounded`).

**The hatch used to wedge its session, and the fix is not a list of command names** (issue #226,
2026-08-25). `execute { "command": "g" }` set the run state, answered with its own echo, and left
every later `g`/`p`/`t` failing `0x80040205` while `bl`, `r` and `.lastevent` kept working — half
alive, with no way back but `end_session`. `raw_command` now calls dbgscope's `settle` after every
`Execute`, which asks the **engine** (`GetExecutionStatus`) whether it was left running and pumps it
if so. Ask the engine rather than the text: `bp X; g`, an alias, `.if (1) { g }` and
`dx …ExecuteCommand("g")` all reach execution without saying so, and the list that would catch them
cannot be finished. `debug_batch`'s `{"op": "command"}` step is the same door and is covered by the
same call, because it goes through `raw_command` too.

**Three things about that settle bite.**

- **A step prints nothing.** Measured: the pump captures module loads and a stop banner for a `g`
  and an **empty string** for a `t` or a `p`, because DbgEng prints a step's new position from the
  command's own completion rather than from the wait. So `raw_command` appends a sentence naming
  where the target ended up; without it `execute { "command": "t" }` moves the target and still
  answers with its own echo, which is indistinguishable from the bug.
- **Its budget is capped at `EXEC_WAIT_MS` as well as at what is left of the caller's clock.** The
  cap is not belt-and-braces: without it a raw `g` that reaches no stop blocks for the caller's
  whole patience, which on the default call timeout is nearly four minutes — far longer than `go`
  doing the same thing.
- **The note it appends names no tool.** It is built in the worker, which owns one session and has
  never heard of the client's surface. That is `FOLLOWUPS.md` item 43's rule, and this is exactly
  the shape it was written about.

**And underneath it: `execute_and_wait` used a *finite* `WaitForEvent` for everything that was not
a live kernel.** On expiry that returns `S_FALSE` with the target still running and the engine
holding no current process/thread, and nothing recovers — `SetInterrupt` plus another wait does not,
measured. So **any** `go`/step/`resume` that reached no stop within 60s destroyed its session, with
no `execute` involved, while reporting success. `run_to_address` had documented that hazard since it
was written and used the bounded INFINITE wait for every target type; only this path had not. It now
does, and a forced break at the bound is reported (`Interruption::Deadline` → `StopReport.timed_out`)
rather than passing for a stop.

Two consequences worth carrying:

- **The reason the finite wait looked attractive was a sleep.** Both dbgscope watchdogs polled a
  flag on a fixed 200/300ms nap, so `join` waited out the rest of it and *every* bounded operation
  paid up to one interval — the tax `DECISIONS.md` (2026-08-02) measured at 200ms on a command whose
  unbounded median was 0.22ms, and routed the cheap queries around the bounded path to avoid.
  `Watchdog` now wakes on a condvar, so a disarm is immediate and the bound costs nothing until it
  is reached. That trade-off is retired rather than worked around; the criterion in `DECISIONS.md`
  still stands, but its price has changed.
- **The origin of a break is the watchdog's own flag, not `interrupt_raised`** — which the watchdog
  sets too, since that is what `InterruptHandle::interrupt` does. Reading the shared flag alone
  reports the crate's own deadline as "a host asked".

**Why nothing caught any of it.** Every tier that drives execution was the live-kernel one, which
was already on the bounded wait; a dump cannot `go`, and no tier launched a process. The debugger
tier now does (`launch_tier`, two tests in `tests/mcp_smoke.rs`). The one target type still
unmeasured on this path is **TTD replay** — `FOLLOWUPS.md` item 47.

**Its blocker moved rather than lifted, and which host it is about is the whole of the distinction.**
Item 47 defers on "replay does not work on this host at all", and the sentence before it names the
**ARM64 bench** — so that is the host, and nothing since has re-checked it. What is new is a
*different* machine: the **x64 bench** has the `ttd\` payload beside `target\debug` and
`target\release` (item 21's unpack recipe), and the TTD tier records a trace, opens it and queries
it there. Item 47's gap is a **target type**, not an architecture, so an x64 measurement would
answer it — but its sibling measurements were all taken on ARM64, and "generalised from one
backend" is the mistake item 47's own text cites. Say which bench, in the item, whenever this
moves. Before writing that test at all, note that a `go` or `reverse_go` on a replay target may
simply stop at the trace boundary, in which case the bound is unreachable rather than untested and
that is itself the answer.

**And a live target has a lifetime, which is what makes a launch test different from every other
one here.** A dump does not go away mid-test; a process does. `go` on `cmd.exe /c ping -n 30` runs
to a breakpoint on ARM64 and to *process exit* on x64 — where `cmd` opens `ping.exe`, hits
`NtCreateFile` once and then waits thirty seconds — so the same test can be about the target's
lifetime on one architecture and not on the other. A test that is not about it asserts with a
**step**, which completes on the next instruction everywhere. (That used to be the workaround for
something worse: an exit during the wait came back as `Catastrophic failure (0x8000FFFF)`, DbgEng's
raw `E_UNEXPECTED`, reported unchanged. Fixed with [#242] — an ending is now
`StopReport::target_gone` carrying what the run captured — so the step is a preference again rather
than a way round a defect.)

**Once a target is gone the session is over, and three places say so rather than one.** dbgscope
refuses every raw command, because text driven into an engine with no debuggee is a
`STATUS_ACCESS_VIOLATION` inside DbgEng that no `catch_unwind` traps — measured on a fresh engine
as well as on one whose debuggee had just left, which is what says the trigger is the missing
debuggee and not the departure. `worker::refuse_when_the_target_is_gone` covers the typed tools,
which reach the engine's own interfaces rather than `Execute` and would otherwise each fail
differently for one fact; it exempts the openers (an engine before its target reads the same),
`end_session` (the answer every refusal gives) and `interrupt` (which never reaches the queue). And
`raw_command` reports the ending from the **run** rather than the command's name, because
`.detach`, `q` and `qd` take the target away as they return while `.kill` measurably does not — it
leaves a target that still reads a stack and goes away on the next resume. A name list would have
to get that right per engine version.

Two traps if you touch this. The refusal's category is `stale_session`, and a worker's category is
only as good as `engine::engine_error`'s match: its `_` arm folded this one into `debugger` — the
exact failure its own doc comment warns about — until the launch-tier test asserted the category
rather than the message. And a session whose target is gone is still reported `open` by
`session_status`, deliberately; `FOLLOWUPS.md` item 48 says what telling the supervisor would cost.

[#242]: https://github.com/glslang/windbg-mcp/issues/242

## What ending a session does to its target (`FOLLOWUPS.md` item 51)

**Three different things, and which one is decided by the opener rather than by the target type.**
A dump or a trace is closed. A live kernel is resumed and actively detached. A process
`attach_process` attached to is actively detached and **left running**; one `launch` created is
terminated with the session. All of it happens inside dbgscope's `end_session`, from a flag
`attach_process_begin` sets — DbgEng cannot be asked, since `GetDebuggeeType` answers
`DEBUG_USER_WINDOWS_PROCESS` for a launch and an attach alike.

**The attach case was a kill until 2026-08-28, and the two defaults that produced it are each
reasonable.** A passive `EndSession` destroys the debug port rather than detaching, and a debuggee
whose port is destroyed is killed by the kernel, because `DebugSetProcessKillOnExit` defaults to
true. What made it worse here than in a plain debugger is that `end_session` is not the only caller:
a **client disconnect** and a **lease expiry** run the same release, so a client that simply went
away took the process it was looking at with it.

Four things to know before touching this.

- **The kill is synchronous with `end_session`**, not with the worker's later termination — which
  is what the original report assumed, and what makes this testable at all. The exit code is
  `0xC0000354` (`STATUS_DEBUGGER_INACTIVE`) the moment the call returns.
- **`Child::try_wait` is the wrong probe and looks like the right one.** That exit status is set
  while the process object is *not yet signalled*, so `try_wait` answers `Ok(None)` — "still
  running" — for a process that is already dead. dbgscope's first version of this assertion passed
  with the fix backed out. `CheckRemoteDebuggerPresent` is no better: it reads `false` after either
  ending, because the passive end really does tear the port down. `GetExitCodeProcess` is the only
  probe that separates them, and it separates them completely (ten runs each way).
- **The detach falls back to the passive end and still reports the failure.** This teardown is on
  the disconnect path, where a session that will not close is worse than a killed debuggee — but a
  caller told "released" would have no reason to go and look at a target that had just been killed.
  So the fallback is silent about the *session* and loud about the *target*.
- **A worker killed while holding an attached target still takes it down.** `Release::Parked` — a
  worker that never answers — is terminated without ever running `end_session`, so nothing detaches.
  `DEBUG_PROCESS_DETACH_ON_EXIT` at attach time would close that too, and was rejected: it makes a
  killed worker leave the process alive with whatever breakpoints were patched into it, which is a
  target that faults minutes later with nothing connecting it to the debugger. `item 51` records
  the trade.

Keeping a `launch`ed process alive past its session is a real request and is **not** built: it is a
question about the tool surface (an argument on `launch` or on `end_session`), not about a flag, and
nothing has asked for it yet.

## A worker of the target's architecture (`src/target.rs`, `engine::worker_images`)

A 32-bit .NET target cannot be read from this server's own process, and the reason is not a missing
DLL. An extension is loaded into the debugger's process, so its architecture is the *host's*: the
32-bit `sos.dll` will not load into an x64 host (`0n193`), and the 64-bit one loads and then fails
on the target (`Failed to load data access DLL, 0x80004005`) because `mscordacwks` is paired to the
**target's** architecture as well as the host's. Measured both ways — there is no in-process
arrangement, which is why the process moves rather than the extension
([#234](https://github.com/glslang/windbg-mcp/issues/234)).

**It is a second worker image, not a second server.** The supervisor normally re-executes itself;
for a 32-bit user-mode target it spawns `x86\windbg-mcp.exe` instead (`engine::worker_images`,
`engine::x86_worker_image`). A worker has never spoken MCP — it speaks `src/proto.rs` down a pair
of inherited anonymous pipes and has never heard of a client — so the client still sees one server,
one `tools/list`, one session registry, one four-session cap and one transcript, and cannot tell
which architecture served a session. **The wire is architecture-neutral because it is JSON**: no
pointer width, no alignment, and nothing in `src/` types a target address as `usize` (DbgEng's are
`ULONG64`). The `usize` fields in `proto.rs` are row limits, clamped. That was not
luck — process-per-session imposed serializability, which is the same property.

**The decision has to precede the engine, not follow it.** `GetEffectiveProcessorType` answers
authoritatively but only once a session exists, in a process whose architecture is by then fixed —
the very thing being chosen. So `src/target.rs` answers without one, **in the supervisor**, which
is the only place a read can still change which process is started. The same constraint rules out
swapping the engine later: `worker.rs` takes `INTERRUPT` from the engine once, into a `OnceLock`,
so an engine replaced mid-session leaves `interrupt` pointing at a dead one.

**Two target kinds can be asked without an engine, and they are asked differently.** A dump carries
its architecture in its own header; a live process answers `IsWow64Process2`. `target::Opening` is
the pair — one value, built from the opener in `EngineOp::opening`, consumed by `worker_images` to
pick the image and by `worker::limitation_for` to report. Three things about the live half. Read
**`ProcessMachine`, falling back to `NativeMachine`**, never the native one alone: the native
machine is the *host's*, so reading it would report an ARM64 box's x86 processes as ARM64 — the
exact case this exists for. The two enumerations are **not one table** (`Arch::of` against
`Arch::of_machine`): 9 is x64 to a minidump and nothing at all as a PE machine type, and 332 is the
other way round, so a shared mapping is how a value gets a plausible wrong answer.
`PROCESS_QUERY_LIMITED_INFORMATION` and not more — asking what a process *is* should need no more
right than naming it, and the attach that follows is where DbgEng asks for debug privilege.

**`IsWow64Process2` lives behind a feature gated by module path, not by subject.** The call is in
`Win32_System_Threading`, its `IMAGE_FILE_MACHINE` out-parameters are in
`Win32_System_SystemInformation`, and without the second feature the import does not resolve —
the same trap this file records for `IMAGE_NT_HEADERS64`.

**The dump half answers for `MDMP` only, and that is the whole format.** Every user-mode capture on
Windows goes through `MiniDumpWriteDump` — procdump, WER, Task Manager, DebugDiag, VS,
`dotnet-dump` — verified against three independent writers. A kernel dump is `PAGEDU64` and reads
as `Other`, which is right: there is no CLR in one, and the x64 engine reads x86 and ARM64 kernel
dumps alike. `MiniDumpReadDumpStream` is the documented API for this and was considered; it needs a
mapping and `unsafe` to read two bytes at a fixed ABI offset, and it still cannot distinguish "not
a minidump" from "no such stream", so the signature check stays hand-written either way. Reach for
it if this ever needs the module list.

**The flag between the two processes is tagged, and that is not decoration.** `--engine-target=`
carries `dump:<path>` or `process:<pid>` (`Opening::flag_value`/`parse`), because a bare value
would have to be told apart by guessing — is `1234` a pid or a file called `1234`? — in the one
process that cannot ask anyone. A value that does not parse is logged and ignored rather than
fatal; what actually catches a supervisor and a worker disagreeing is the build identity on
`WorkerMessage::Ready`.

**Which is also the trap while editing this on a bench.** That check refuses an
`x86\windbg-mcp.exe` built from *any* other state of the tree, and on a dirty tree the identity
carries a digest over the uncommitted diff of `build.rs`'s `INPUTS` — `src`, `tests`, `build.rs`
and the two manifests — so `cargo fmt` moves it as surely as a code change does. A stale 32-bit worker is
therefore turned away, the session falls back to this build, and the smoke tier fails saying *this
host could not give the target a 32-bit worker* — which reads as a missing file rather than a stale
one. After every edit, before running that tier:

```pwsh
cargo build --target i686-pc-windows-msvc
Copy-Item target\i686-pc-windows-msvc\debug\windbg-mcp.exe target\debug\x86 -Force
```

**`x86\` is a subdirectory because the loader makes it one.** An executable's own directory is
searched first, so a 32-bit `dbgeng.dll` dropped beside the 64-bit one would be found by the wrong
process — and putting the 32-bit *worker* inside `x86\` turns that same rule into the mechanism:
it loads the engine sitting next to it, with no code to make it happen. It is also the layout a
debugger package ships (`amd64\`, `x86\`).

**Both halves are probed before spawning**, and this is the one that is easy to leave out: the
engine is an import-table dependency resolved by the loader *before `main`*, so an
`x86\windbg-mcp.exe` with no `dbgeng.dll` beside it does not fail to open a dump — it fails to
start, as a loader error with no Rust in it. `x86_worker_image` returns `None` unless both are
there.

**Falling back is deliberate and the limitation is computed twice on purpose.** An x86 target opens
perfectly well in the x64 build and native analysis of it works; only SOS is lost. So a missing or
unstartable 32-bit worker degrades to this build rather than failing the open, and the *worker*
that ends up with the target asks the same question again and reports the limitation itself
(`worker::limitation_for`). Two reads of one fact rather than a field on the wire — they cannot
disagree, and the worker needs no new protocol to say what it is. Why the 32-bit worker did not
start is a **server** fact and is logged by the supervisor that tried it, not put in the caller's
summary.

**The tier for it makes its own target**, which is why it now covers anything: it was gated on a
supplied dump for as long as it existed, so CI never ran it. `csc.exe` ships with every stock
Windows, so the two tests compile a `-platform:x86` C# program that dumps *itself* — a 32-bit
process loads the 32-bit `dbghelp.dll`, where a 64-bit writer aimed at the same target produces a
dump reporting the host's architecture — and the other test attaches to that same program running.
Two things the tier learned the hard way: assert the dump's **size**, because
`comsvcs.dll MiniDump` was measured writing a near-empty file and reporting nothing wrong; and read
`summary.limitation`, not `limitation`, or the assertion is against JSON null and passes whatever
happened. Its gate is the **engine** (`x86\dbgeng.dll`) and not the worker, so a half-populated
`x86\` fails loudly rather than skipping, and so the gate is not a second copy of
`x86_worker_image`'s renamed-image fallback.

**What this replaced, and why it is worth knowing.** Until 2026-08-27 the engine moved into an
`x86\cdb.exe` run as a debugging server and driven over DbgEng's `npipe:` transport. That worked,
and three things about it did not: `IDebugAdvanced2::GetSymbolInformation` does not cross the remote
transport, so `modules` rows carried no PDB identity; teardown had to be a **kill**, because a
`cdb -server` whose peer has gone spins on the broken pipe without bound (32,089 lines of
`cdb: Could not write to pipe, 1450` in one measured run, which hung the VM and needed a hypervisor
reset); and the pipe `cdb` creates grants **Everyone `FULL ACCESS`** — measured
`D:(D;;WDWO;;;WD)(A;;FA;;;WD)`, with no `SYSTEM` or `Administrators` ACE at all — which made the
transport password the only barrier, and made the name a squat target both ways (pre-create is a
denial of service; adding an instance to a live name hands the *next* client's connection, and the
password, to the squatter). All three are gone with the transport. `FOLLOWUPS.md` item 49 has the
measurements and the options that were weighed.


## Adding a tool (`src/toolset.rs`)

Two files, not one. A tool is declared in `src/server.rs` as always, and its name also goes in a
**group** in `src/toolset.rs` — the table behind `--tools`, which advertises a named subset of the
surface because 74% of the 67,873-byte tool surface is prose a model needs and cannot be trimmed
(`docs/token-budget.md` finding 8).

Forgetting the second half fails in the one direction nothing would notice: the *default* surface
is every tool, so the new tool works everywhere you would try it, and it is missing only from a
**narrowed** surface. `mcp_smoke::every_tool_belongs_to_exactly_one_group` is the join that catches
it — it starts a server with all eight group names and asserts that equals the whole `tools/list`.
There is no such thing as a tool in two groups, and a group named after a tool is refused by a unit
test, because `Toolset::parse` resolves group names first and would decide it silently.

Four rules worth knowing before touching it. **`session` is in every surface** whatever the spec
says, because every other tool routes by a `session_id` this server alone issues — so `--tools
crash` is eleven tools and 11,265 B is the floor. **Output schemas carry no prose at all**
(`src/schema.rs`): declare one with `schema::constraints_of`, never rmcp's `schema_for_output`, or
the tool ships every doc comment in its `$defs` closure and the wire ceiling notices. That call is
also what supplies the root `type: "object"` a discriminated union does not generate and rmcp does
not add — without which every released TypeScript-SDK client rejects the *whole* `tools/list` and
registers no tools at all, not 50 of 51 (issue #223, measured: 0 of 51 against SDK 1.30.0). Both
halves are asserted on the wire in `mcp_smoke`, because both come undone the same way. And **a
surface is per client, not per run** (item 36): `--tools` is the run's *default*, and a listener's
client may be configured with a spec of its own (`WINDBG_MCP_TOOLS_<NAME>`, or a `tools` field in
the credential file) that replaces it. So a change to a group is a change to what several
differently-budgeted callers see, and the assertion that catches a per-client mistake is two
credentials on one port — `two_clients_on_one_listener_are_served_two_surfaces`, not a unit test,
for the reason the next section gives.

And **a description that names another tool is data, not a doc comment** (item 41). A
cross-reference lives in `TOOL_NOTES` beside the tools it names, and `annotate` appends it in
`router()` only when the surface has every one of them — so the doc comment itself must name no
tool but the always-served ones, and `no_description_names_a_tool_the_client_cannot_call` fails the
build if a new tool's prose points at one its own single-tool spec does not serve. Three
consequences when you add one. The invariant is checked on `--tools <that tool>` and nowhere else,
because that is the tightest surface it can be served on and every wider one is covered by
construction. **Group bytes no longer add up to a surface's**: `crash` is 14,138 B against the
15,093 its two groups sum to in `docs/token-budget.md`, since narrowing shortens what stays as well
as dropping what goes. And the check for "names a tool" is deliberately not word containment — this
prose says frames are "attributed to modules" and that a stuck session "does not let go", while a
TTD description quotes `dx @$cursession.TTD.Calls(...)`, which is the debugger command and not the
`dx` tool; the rule is a code span that *is* the name or opens a call with it, plus bare-if-it-has-
an-underscore, which is what caught `step_back`'s "Reverse of step_into.".

**And the same rule again for a *result*, which is the channel that took longest to find** (item
43). `SUMMARY_NOTES` beside `TOOL_NOTES`, appended by `annotated_report` rather than `annotate`.
The reason it is a second table and not a wider first one is where the text is built: an opener's
summary is assembled by `summary_text` in the **worker**, which owns one session and has never
heard of a client — so a sentence naming `modules`, with its `filter` argument spelled out, shipped
to an eleven-tool caller for as long as that sentence existed. The summary crosses the pipe as
facts; the pointers are added where `self.surface` is. Three things to know before touching it.
**Annotate above both halves of the result**, because a structured-aware client forwards
`structuredContent` and drops the text — a pointer added to one half is one half the clients never
see, and a pointer *removed* from one half is the leak still open on the other. **A note carries a
predicate**, since a pointer to the bug check on a target that did not bug-check is noise on every
surface. And **the leak was invisible to the eval that was measuring it**: `local_model_drive.py`
records `text[:300]` and the sentence sat at the end of a 2,508-character summary, so two rounds of
"which names is this server teaching" never saw the largest one. What found it was a scan of `src/`
string literals against the tool table — seconds, no bench and no VM, because what a server prints
is a static question and was never an eval's to answer.

## Several clients on one listener (`src/client.rs`)

A `--listen` server holds **one bearer token per client**: `WINDBG_MCP_LISTEN_TOKEN_<NAME>` names
one, the unnamed variable names `local`, and a configured `WINDBG_MCP_LISTEN_TOKEN_FILE` shuts the
environment out entirely rather than merely outranking it — so that file names its own clients (a
bare token is `local`; a JSON object of name to token is as many as it lists), which is the only way
a service-hosted listener holds more than one, and `--install-service` copies every credential
variable in the shell rather than the unnamed one alone. Under stdio everything runs as `local`,
so there is one set of rules and no transport exception. `docs/remote-listener.md` is the operator's
half; what follows is what bites while editing.

**A credential also carries a tool surface**, since item 36: `WINDBG_MCP_TOOLS_<NAME>` beside the
token, or a `tools` field in a file entry that is then an object rather than a string. That
follows the same precedence — a configured file is the whole configuration, so the variable is not
read on a host that has one — for a reason that is not secrecy but arithmetic: one file answering
who may connect and another answering what they get is two files to keep in step and a precedence
rule to remember.

**Five client commands, and the fifth only reads.** `--list-listen-clients` (item 37) prints the
same `roster` the four editors print, with no write and no reload — and **not under the credential
lock**, which is the trap: `lock_credentials` opens its file with `create(true)` and nothing else
creates it, so a reader that locked would write into `%ProgramData%` on any host where no edit had
yet run, which is exactly the property this command sells. It buys almost nothing either, since
`write_credentials` renames a finished file over the old one. Two more things bite when touching
it. It answers for **both** sources — a service's clients are in the credential
file, a foreground listener's are the environment it was started with — and the environment half
goes through `listen::named_token_file`, *not* `client::env_credentials` alone: a shell naming
`WINDBG_MCP_LISTEN_TOKEN_FILE` has its token variables ignored by the listener, so listing them
would be a roster of credentials nothing accepts. And a file it cannot read in full has to refuse
rather than print a shorter list — a dropped entry is a service that will not start, reported as a
service serving fewer people. And an unelevated caller is turned away by the *credential file's* own ACL rather
than by the lock, which is the object being protected rather than a thing beside it.

**All five warn when the SCM's image is not the one running the command** (item 38), and two things
about that bite. **`Service::query_config()` does not return a path**: the field is called
`executable_path` and `QueryServiceConfigW` fills it from `lpBinaryPathName`, which is the whole
line the SCM starts — exe *and* `--service --listen <addr>`. Compared as it comes it differs from
`current_exe()` on every host, correct ones included, so the warning would be a warning that is
always wrong. `image_in` reads the image back out of the line; a real service on this bench shows
both shapes it has to handle (`WinDefend`'s path is quoted, this service's is not). And the config
is read on a **handle of its own** rather than on the one `edit_client` already holds: adding
`QUERY_CONFIG` there would let a host with a narrowed service descriptor fail
`--remove-listen-client` because a warning wanted a right. It is a warning and never a refusal, for
the reason that is easy to try to "fix" — nothing carries a version between the two, so a second
copy of the *same* build is indistinguishable from a stale one.

**Identity is ambient inside a call, carried by the instance, and by name outside both.**
`crate::client::current()` reads a task-local, which is why no tool signature carries a caller. What
sets it around a tool call is **`call_tool`**, from the client its `WindbgServer` was built with —
*not* `listen::gate`'s `as_client` around `mcp.handle(req)`. The gate's scope covers the HTTP task;
rmcp serves a legacy MCP session from a task it `tokio::spawn`s at `initialize`
(`streamable_http_server::tower::spawn_session_worker`), and a task-local does not cross a spawn. So
the credential is captured where the instance is built — the listener's service factory, which does
run inside the gate's scope — and re-entered per call.

**Getting that wrong is invisible to everything but two real clients.** It was wrong from #162 until
the two-client smoke tier found it (`FOLLOWUPS.md` item 29): every call ran as the default `local`,
so both clients' sessions were owned by `local` and each could see, route to and end the other's,
while every unit test passed — each sets the identity itself, and the tier ran one client, for whom
`local` is the right answer.

**The factory now decides a second thing on that line, with the same failure mode**: which tools
this client is served (item 36). A client may carry a `Toolset` beside its name, so
`credentials.surface_for(&client)` is read there and nowhere later — a surface resolved after the
factory would be resolved for whichever task rmcp happened to serve the call from, which is exactly
the bug above wearing a different hat. It is covered the only way that shape can be:
`two_clients_on_one_listener_are_served_two_surfaces` puts two tokens on one port and asserts two
different `tools/list` answers, on the session-bearing route and the stateless one. One client
cannot state the claim — with one credential, "this client's spec" and "the run's spec" are the same
answer.

Anything running *outside* a call — the listener's own diagnostics, a sweep, a shutdown — gets the
default `local` instead of an error, so it must take the client as a parameter
(`Sessions::live_count_for` against `Sessions::snapshot`). The bug that rule is written from was a
log line reporting `local`'s session count to a named client on reconnect.

**A caller sees only its own sessions**, and that is not a fault to debug: routing, `session_status`,
`server_log`, the four-session cap, closed-session history and lease release are all per client, and
another client's handle is reported *unknown* rather than refused. Two tokens on one host are two
namespaces — if a session "vanished", check which token the request carried.

**There is no tenancy gate any more, and stale memory of it is the likeliest thing to mislead you
here.** Retired 2026-08-20 (`FOLLOWUPS.md` item 28, once #162's ownership had taken the boundary
over). What `Lease` is now: a clock, plus the two answers that were never tenancy. `admit` refuses an
`Mcp-Session-Id` **another client** records (`404`, *unknown* — never "someone else's") and a request
whose own credential is mid-release (`409`, ask again in a moment), and otherwise renews. Gone with
the gate: the reservation and its generation counter, `Occupied`/`409`, the in-flight count and its
epoch, the handover that waited on `Sessions::busy` (and `Sessions::busy` itself), `Arriving`, and
every read of `MCP-Protocol-Version` — the classification behind #168 is deleted rather than fixed,
so a request now presents an id or nothing and the revision does not enter into it. A credential may
hold **several** MCP sessions; they are kept in a set, because an id recorded for nobody is one any
credential may present.

**One lease rule survives, and forgetting it costs a client sessions it was using.** An **admitted**
request renews an existing deadline and creates none:

- *admitted*, because a refusal that renewed would let a stream of wrong session ids hold an
  abandoned client's live kernel target open for ever — the failure the sweep exists to prevent. Both
  refusals return before the renewal, and that ordering is the rule.
- *any* request, not any request of a shape: a credential holding a legacy session can go on to send
  `2026-07-28` ones (a client that upgraded, or restarted inside the grace), and the sweep reads
  `deadline` and nothing else.
- *creates none*, because a clock armed for a credential that holds nothing releases everything it
  opens one grace later. Only a settled MCP session arms one, which is what makes the trap that used
  to sit beside this — a reservation minting nothing and having to hand its deadline back —
  unreachable rather than handled.

The sweep zeroes nothing and waits for nothing, so what keeps it from releasing a session mid-call is
the startup floor in `Lease::new`: a grace longer than the longest a call can keep a client quiet
means **no request of that credential's can still be in flight when its lease expires**. That is the
property the epochs and claim generations were protecting one layer above, and it was already
enforced.

**What rmcp does with session ids, which the ownership answer now leans on.** Two facts, both in
`…/rmcp-3.1.2/src/transport/streamable_http_server/tower.rs`:

- a legacy `initialize` **always** mints one — `create_session()` then `spawn_session_worker`, with no
  check on who is asking — so nothing but this server ever refused a credential a second MCP session,
  and now nothing does. Hence a client's ids are a **set** (an id this server stops recording is one
  any credential may present) and an expiry closes **every** one of them (each abandoned handshake
  otherwise leaves a live service task behind).
- an id the service does not know — never issued, closed by a `DELETE`, or closed by the sweep —
  comes back `404 Not Found: Session not found`. That is deliberately the same status
  `Admission::NotYours` answers with: from the caller's side "not yours" and "not a session here"
  are indistinguishable, and splitting them into a distinguishable pair would confirm a session the
  caller may not touch.

**Driving the listener by hand on `2026-07-28` needs three things, and sending one gets a `400`
that looks like a broken server.** Every request *after the handshake* carries the
`MCP-Protocol-Version` header, `params._meta` with `io.modelcontextprotocol/protocolVersion` *and*
`…/clientCapabilities` (SEP-2567 moved them there when it removed the session that held them), and
SEP-2243's `Mcp-Method` — plus `Mcp-Name`, which is mapped **per method**: `params.name` for
`tools/call` and `prompts/get`, `params.uri` for `resources/read`, nothing for the rest.

`initialize` is the exception and is exempt from all three: it is the request that *establishes*
the revision, so it carries the version in its body, needs no `_meta` and no `Mcp-Method`, and may
omit the header as well. Sending the header anyway is legal and is what `Listener::stateless_opening`
does — which is precisely why the headerless handshake is untested (`FOLLOWUPS.md` item 30). Send
the recipe above on a handshake and you will take the ordinary path rather than the one that
carried the bug. `PowerShell`'s `Invoke-WebRequest` throws
on a 4xx and leaves the body on the exception, so those refusals read as empty when they in fact
name what is missing. Before believing any protocol-level claim about `--listen`, read the validator
that produced it: the rmcp source is on the Mac and needs no Windows build, at
`<rmcp>/src/transport/streamable_http_server/tower.rs`, where `<rmcp>` is the directory
`cargo metadata` reports for the pinned version rather than one assembled by hand — see *Local
verification* for why that distinction has teeth.

**A listener test that needs a real engine worker belongs in the debugger tier**, however cheap it
looks — the protocol tier's contract is "no debugger target". An attach cannot *park* without
`dbgeng.dll`: it fails during initialisation instead, which turns a test about a call that does not
return into one about a call that failed fast. CI's Windows runner happens to have the DLL, so
getting this wrong does not show up as a red build.

**Credentials are built from variables handed in, not read from the environment**
(`Credentials::from_entries`), for the same reason as `kdconn::env_entries`: `set_var` is `unsafe` in
edition 2024 and mutates state the whole test binary shares. And they are **stripped from every
child process by prefix** (`client::strip_credentials`), so a token variable added later cannot
quietly reach an engine worker or a `launch`ed debuggee — but a credential under a *different*
prefix would need its own strip.

Two collisions are refused at startup rather than resolved, because the winner would be a `HashMap`
ordering detail: one token naming two clients, and two tokens naming one (names are folded, so
`…_TOKEN` and `…_TOKEN_LOCAL` collide, as do `…_CI` and `…__CI`). **Neither refusal may quote a
token** — they are printed to stderr and, under the service, to a log file.

**That rule reaches inside an entry too, and getting there took two goes.** A file entry may be an
object (`{"token": …, "tools": …}`), and both ways its fields can be ambiguous were live in #196:
`serde_json::Map` collapsed an exact repeat before this module saw it — the very thing `Entries`
exists to stop one level up — and `entry_of` *folded* the field name, so `{"token": …, "TOKEN": …}`
was two spellings of one field with the later silently winning the credential. The fixes are worth
knowing apart, because only one of them is a check: the value type is now recursive (`Written`,
which takes every JSON type into a variant rather than letting serde raise a type error that would
quote a credential), and **a field name is matched exactly**. A client's *name* is folded because
the operator chose it and configures it in two places that have to agree; `token` is a keyword in a
file format, and being lenient about its case is what created the ambiguity rather than what
tolerated it.

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

## Benchmarking a model against this server (`tools/local_model_eval.py`)

`docs/local-model-eval.md` is the result; this is what bites while running it again. The grid is
three scripts — the ollama driver, the Claude Code driver, and the matrix runner that spawns either
one per cell and grades the log afterwards.

**Record what the runtime *served*, not what you asked for.** `num_ctx` on a request does not
shrink an instance ollama already holds: with a 32,768 instance loaded, cells asking for 8,192 are
served 32,768 and look perfectly healthy — a 17,300-token prompt "fitting" in 8k, which is the
result the context axis exists to find and would have been fiction. `/api/ps` is the only place
the truth appears. Every record carries `served_context`, the grader marks a cell where the two
disagree with `?`, and the runner evicts the model between windows. The first run of the grid
recorded five such cells; they were dropped and re-run.

**The grader's three matching rules each came from a real wrong verdict**, and all three are in
`present()`:

- A number matches only **between hex boundaries** — `0x22` is the device type `ioctl_decode` asks
  for and `0x22200B` is the code in the question, so plain containment passed for any answer that
  repeated the question. One model scored correct while saying `FILE_DEVICE_KEYBOARD`.
- Leading zeros are formatting — the tool prints `0x802` and a model writing `0x0802` agrees with
  it. That one marked a *correct* control answer wrong.
- A separator between hex digits is formatting too. WinDbg writes ``fffff801`3c65bca8``; Opus
  writes `0xfffff801_3c65bca8`. Both name the address the key holds.

Two of those three were found by reading the **control's** answers, which is the argument for
having a frontier row at all.

**`possible_on` in the task file is a prediction, and predictions about this server are wrong in
one direction: too pessimistic.** Facts here are reachable by more than one route —
`open_dump`'s summary carries the bug check *and* the module count, `crash_triage`'s frame 0 is the
`pc` that `registers` reports — so a task the tool table says needs `inspect` may be answerable
with `crash` alone. Verify against the dump before scoring a model wrong for finding the other
route; the `arm64_pc` entry was corrected mid-run for exactly this.

**Resume is per *cell*, so the log legitimately holds a task twice.** An outstanding task re-runs
its cell's whole list, and the grader keeps the **last** record per (cell, **draw**, task). Do not
"fix" a duplicated task id by deleting rows.

**One draw per cell is what the grid runs, and it cannot answer "X caused Y"** — a rule
`docs/local-model-eval.md` states in as many words and that has not stopped three write-ups (#209
once, #212 twice) from reading a moved aggregate as a controlled result (item 42).
The trap is composition: a total that holds across two runs whose *callers* changed is a
coincidence, not a rate. What answers a rate is `draws: n` on a cell group — the same cell n times,
one thing varied — and the draw index is inside the grader's key, so repeats accumulate instead of
the last one winning. Two consequences when editing that code. **A record with no `draw` is draw
1**, which is the only reason a run recorded before the change still grades to what it graded to,
and it lives in `draw_of` rather than in four `or 1`s. And `--matrix` prints a **distribution** (`3Y2n`)
only when a cell was repeated; a single draw prints the bare mark, so nothing already published is
restated in a new notation.

**And the seed does not replay a draw on this bench, so do not write that it does.** Each draw asks
for `seed: <draw index>` and records it, which is right where a seed reproduces a sample (the
draws become repeatable, and arm A's draw 3 pairs with arm B's). It does not here: four identical
requests to `qwen3.8:27b-mlx` under `seed: 7` returned four different answers (ollama 0.32.15, MLX,
measured 2026-08-24 — after the comment claiming otherwise had already been written). The column is
what was asked for; the distribution over draws is the measurement.

**The Claude Code row needs four fences or it measures something else.** `--strict-mcp-config` (or
it falls back to the editor's registered `windbg-vm`, whose credential is a different client and
gets the whole 51-tool surface — the surface axis then measures nothing); `--disallowedTools` for
the built-ins (or it answers a question about a sample dump by grepping this repository);
`ENABLE_TOOL_SEARCH=false` (or MCP tool schemas are deferred and fetched with `ToolSearch`, so the
surface costs that row almost nothing while every other row pays in full); and a **neutral working
directory**, since Claude Code reads the project it is started in. Its prompt-token column is still
not comparable with the ollama rows — its own system prompt is most of it — and the document says
so rather than quoting it.

**A model "inventing" tools on a narrowed surface is almost always this server advertising them,
and there were two channels; both are narrowed now.** The `instructions` string went per-client
with item 40, and a *tool's description* with item 41 - the descriptions of tools a `crash` client
**is** served used to name `modules` (`open_dump`), `debug_batch` (`interrupt`, `end_session`),
`backtrace` (`crash_triage`) and `go` (`interrupt`), five references on an eleven-tool surface.
Re-running the five `min` cells against item 40's fix (2026-08-24) moved unserved calls 17 -> 14,
and **13 of the remainder named exactly those five**, which is what item 41 then removed. So the
metric is still `unserved` rather than "hallucinated", and it still measures the server before it
measures the model. One call in 61 was a genuine invention, which is the floor.

**It is now two columns, `taught+wanted`** (item 43), split by the task's own `possible_on`: a
reach off the surface on a task this surface *can* answer against one on a task it cannot. Summed
they hide each other, which is the whole argument — re-graded, item 41's fix is `4+10 -> 0+6`, an
elimination of the half it was aimed at rather than a 57% improvement in a total.
`--grade --assert-no-taught` exits non-zero on a taught call and `wanted` is deliberately not
assertable. **The split attributes need, not provenance**: an opener's result taught `modules` on
`unloaded_driver` until #217, and that task is one `min` cannot answer, so those calls are
`wanted`. Lower bound on advertising, upper bound on need.

**Fourth run, five draws of the five `min` cells** (2026-08-25, against #217): `modules` went from
3 of 5 cell-draws to **0 of 25**, and what remains is mostly invented (`execute_command`,
`run_command`). The arms differ by exactly one server behaviour *these tasks reach* - the opener's
summary; the other two paths #217 changed were measured as unexercised (0 user-mode refusals in 95
`crash_triage` calls, 0 post-commit failures) - so this is the cleanest causal read the bench has
produced — with the weakness on the *other* side, which is one draw per cell. Two
things only draws could say: `ioctl_decode` is answered from a frontier model's own knowledge 5/5
and from a local one's 1/5, and **`arm64_pc` is `5n` in every row**, which is what sent someone to
look at the task rather than the models. It went unanswered in all 35 runs in the logs still on
disk, and has been answered right once ever — qwen, in the original grid, reasoning that frame 0
*is* the `pc` (item 44). The key is the literal `pc`, `nt!KeBugCheck2+0x2e8`; almost every model
gives the bug check's parameter 1 instead — the address whose execution faulted. **A task that fails
everywhere is a task to read, not a model to blame.**

**A run records what it ran against, and that is what makes two of them comparable** (item 46).
Every record carries `server` (the build that answered), `model_digest` (the weights behind a
mutable ollama tag), `suite`, and `harness_version` for the Claude rows, which can have no digest -
`opus` and `sonnet` are aliases resolved inside a client this bench does not own. `--compare` reads
two logs with **two rules that are not one rule**: a *changed question* blocks a pairing (via
`stale_prompt`, printed at the row), while a changed build, model or window is *named above the
table* for a reader to weigh - conflating them is how a moved aggregate gets read as a controlled
result. `--series` reduces logs to one row per run in `docs/eval-runs.json`. Six things bite.
**The server's version now carries its git revision** (`0.11.0+g1a2b3c4`), stamped by `build.rs`,
so anything asserting on it is a *prefix* check - and the smoke test additionally asserts the
revision is **there** when built from a checkout, which is the assertion that catches a `build.rs`
that stopped running. **`build.rs`'s watch list and its dirty check are one `INPUTS` const**,
because emitting any `rerun-if-changed` replaces Cargo's default of watching the whole package, and
two lists would disagree about what a clean build is; `-dirty.<digest>` therefore means "the build
inputs differ from that commit", not "the tree is dirty", and the digest is over the diff so two
uncommitted iterations on one `HEAD` are two identities. Git paths go through
`rev-parse --git-path` (and the branch ref through `symbolic-ref`, since `--git-path` takes a path
relative to the git dir and not a revision): a `git worktree` checkout has a `.git` **file**, so a
literal `.git/HEAD` is a watched path that does not exist, which Cargo reads as always-changed and
recompiles the crate on every no-op build. And **the two `/api/ps` facts are one call**
(`runtime_identity`): asking twice could catch different instances and pair one model's window with
another's digest. **The surface and the window are per-cell facts; the weights and the build are
deliberately not** - review asked for both and both were built and then removed, because reaching
the state they guard needs a model re-pulled mid-run or a run spanning a rebuild, and neither
happens here. `tools/` is a developer script and the bar for defending it against states its own
workflow cannot produce is lower than `src/`'s. **A surface is compared by digest, not byte
length** - a same-length reword or an
equal-sized allowlist swap moves neither the count nor the length, though a comparison spanning the
rollout falls back to what both sides recorded and says `unverifiable` rather than `moved` - and **`unrecorded` (nobody
recorded it) is kept apart from `unavailable`** (this row has no such answer), or every run with a
Claude cell reads as a legacy log.

**The key is a snapshot, and `--verify-key` is what re-takes it** (item 45). The six tasks are
graded against facts read off the checked-in dumps with this server's own tools, so a fact that
stops being what the server reports leaves the suite grading and every model scoring against
nothing — a key that has rotted looks exactly like a model that got worse. Each task carries a
`verify` binding of `(tool, args)` steps to the values expected back, and
`WINDBG_MCP_TOKEN=<full surface> python3 tools/local_model_eval.py --verify-key` re-reads the lot.
Five things bite when touching it. **It is a command, not a CI gate**, and that is the decision
rather than an omission: the oracle is `present()`, so a Rust test would need a second copy of
three rules each learned from a wrong verdict — run it after a `dbgscope` bump, a symbol-path
change or a new sample. **The binding grounds `expect`, it does not generate it**: two of
`unloaded_driver`'s three groups are phrasings of a *relation* (`matched: 0` is what "not loaded"
means), so a run reports each group as `value`, `relation` or `skipped`. **Which are relational is
declared (`states`), never inferred** — reading "no pinned value matched" as a relation let a group
edited to a value the tools do not answer pass, which is a broken key reached through the mode
meant to catch one — so a group `grounds` claims but nothing renders is a failure, as is a group
**no** step claims, and a `grounds` group is checked *alternative by alternative* (each must render
or be a **spelling** of one that does), since appending an alternative widens what the grader
accepts without moving anything a whole-group check would see. **The gate is asked per dump**, not once of the host: `docs/smoke-test.md`
records an engine failing differently per dump, so a host-wide gate stands the ARM64 step down over
a missing *x64* PDB — and **a failed probe is a task failure, not a closed gate**, because a closed
gate stands steps down and passes; so are a `modules` answer with no module list and a target with
no `nt`, as is a gated step with no target to probe. **Nothing there reads a structured answer
with a default** - one `probe` helper answers a value or a reason, which is what five review rounds
finding the same shape in six places bought - the last of them a renamed `symbols` on the `nt`
record, which reads as `None` and is not a PDB-backed state, and a `symbols` that is no longer a
string, and a task whose **every** grounding step stands down at a gate is `INCOMPLETE` and
non-zero rather than OK - `driver_blame` has no ungated route where `arm64_pc` does. **Pins compare
types too** (`False == 0` and `227.0 == 227` are true in Python, and one of
those would have hidden a schema change). A `states` group **names the pins its relation
rests on**, so the exemption cannot outlive the fact underneath it. **A pin can be too
tight**: the `pc` fact was first pinned as `registers.32.value`, a position in the ARM64 bank that
an engine may reorder without the key having rotted, so a `read` path enters a list by name
(`registers.name=pc.value`) as well as by index. And **`tools/eval_tasks_v1.json` carries no
binding on purpose** — it is the wording published logs were graded against — so the mode refuses
it by name rather than skipping it.

**Re-run against item 41** (2026-08-24): unserved calls 14 -> 6, with `debug_batch` going 10 -> 0
and every name this server was teaching now gone. What that re-run mostly taught is **how easy it
is to over-read at n=1, in a file that already says so**. Two claims had to be pulled back after
review, and both had passed my own reading first. The three `modules` calls did not move even
though `open_dump` no longer names it - which shows the description is not *necessary*, and not
that it caused none of the earlier three: the callers changed (nemotron/Opus/Sonnet, then
qwen/gemma/Opus), so an aggregate holding at three is a coincidence of composition. And "unserved
on answerable tasks went 4 -> 0" was a **double count** of our own - all four were gemma's
`debug_batch`, so it is the first row again, not independent evidence. What survives is the shape:
every survivor is a direct reach for a module listing on `unloaded_driver`, the one task whose
answer lives in a tool a `crash` client is not served.

**A description reaches every row; the instructions reach two.** `tools/list` is read by all five
rows, so item 41 moved every prompt (-223 tokens on each ollama row, -307 on each Claude one) where
item 40 could not move a local one by a token. Check which channel a prose change travels on before
predicting which columns it can touch.

**And the ollama rows never read the `instructions` at all**, which is what nearly made that fix
look bigger than it is. `tools/local_model_drive.py`'s handshake keeps the negotiated protocol
version and discards the rest of the `initialize` result, so a local row's prompt is the
one-sentence system prompt plus `tools/list`: narrowing that string cannot move those prompt-token
columns by one token, and it did not. Claude Code injects a server's instructions into its own
system prompt, so the two control rows are the only ones any instructions measurement is about.
Check which half of the bench a prose change can reach before predicting what it will do.

**The bench listener is the shipped per-client feature in anger.** `tools/bench_listener.ps1`
serves `full`, `lean` and `min` from one foreground process, tokens arriving on **stdin**; its
startup line naming the three clients and their surfaces is the check that the run is measuring
what it thinks. A cell changes the bearer token and nothing else.

## Handing the work over

"Update the handoff docs" means a specific set, discoverable only from what the handoff PRs touched
(#155, #159, #170). They are titled *"Hand the `<X>` work over: …"* — the stem is the convention,
and the clause after the colon says what kind of handoff it is: *"the traps, not just the result"*
on #159 and #170, *"what is covered, what is not"* on #155.

- **`CLAUDE.md`** — what bites while *editing* a subsystem.
- **`FOLLOWUPS.md`** — numbered items, each saying what would close it, why it was deferred, and
  where it picks up. Its header enumerates clusters and needs a line whenever an item is added.
- **[`docs/smoke-test.md`](./docs/smoke-test.md)** — what each tier claims, per test, with budgets.

Plus `CHANGELOG.md` and whichever `docs/*.md` the behaviour moved in.

**Three places to check, not three files to edit.** A handoff touches the ones its change actually
moved: #170 updated two of the three and `README.md`, and was right to — the test its
`docs/smoke-test.md` entry would have described did not exist yet, landing in #176 later the same
day. Going looking for a third edit with no subject is how a section gets written about nothing.
The failure this list prevents is the opposite one, and it is the common one: *not knowing the
third file is there*.

**This prose is reviewed as hard as code, and deserves to be.** A docs-only PR (#170) drew six
findings from the Codex bot, every one a real inaccuracy about the lease — and two of them were
errors introduced while fixing earlier ones. The worst class is a rule stated without its
qualifier: *"a request renews the lease"* where the truth is *"a request the lease **admits**"*,
written on an item that proposed a deletion. Taken at face value it licenses renewal-on-arrival,
which lets a stream of wrong session ids hold an abandoned live kernel target open for ever — the
failure the sweep exists to prevent.

**The drift is continuous, not per-PR.** The 2026-08-23 pass found problems in all three files
accumulated across four merges, none introduced by the change that prompted it: a test count that
said 69 and is 75, an item missing from the `FOLLOWUPS.md` header, and a section describing six
listener tests where there are ten. Assume anything countable has moved, and that the sentence
around it has not.

**So re-derive every number — and distrust the derivation, not just the number.** Four ways this
has gone wrong here, each of which produced a confident wrong edit or came one step from it:

- **A grep is not an enumeration.** Counting `Listener::start` call sites gives nine protocol-tier
  listener tests; there are ten, because `the_listener_will_not_start_without_a_token` spawns the
  exe itself — a listener that will not start cannot be started by the helper. The wrong nine
  reached a PR description before the source was walked properly.
- **`cat A 2>/dev/null || cat B` prints contents without saying whose.** That is how the
  markdownlint config came to be written down as `.markdownlint-cli2.jsonc`, which does not exist
  here; it is `.markdownlint.jsonc`.
- **The `FOLLOWUPS.md` header drifts silently, because nothing reads it.** It has claimed "twelve"
  while enumerating fourteen, and has twice stopped short of items already written. Match its
  `items N–M` spans against the `## N.` headings mechanically rather than counting by eye.
- **A number that looks stale may be right.** "The four assertions that read a *target*" survives
  five tests gating on those conditions, because the four are the ones opening `NATIVE_SAMPLE` and
  the fifth is deliberately separate — counting `skip` call sites would have "fixed" it wrongly.

**And re-read every mechanism, for the same reason.** A number gets re-derived; a claim about *how
something works* gets the file opened. What goes wrong is stating it from the shape of the code
around it, from a field's name, from one backend in front of you, or from what a neighbouring rule
does — and it is cheap to avoid, because every instance below was one `grep` or one `sed` away.
**Six findings across five review rounds** on
[#221](https://github.com/glslang/windbg-mcp/pull/221) were all this, and so was a wrong
verification on [#220](https://github.com/glslang/windbg-mcp/pull/220):

- **From the neighbours.** A proposed test's module counts and `pc` "need a symbol gate", because
  the tier around them gates. `docs/smoke-test.md` already draws that line — target memory against
  the dump's structure — and carries the measurement that settles where a *stack* falls; two rounds
  to land, and what the entry carries now is a pointer to that file rather than a second copy of it.
- **From a name.** A drift test was to pin `answer_key`. **Nothing reads `answer_key`** — `grep -rn`
  finds no consumer in `tools/`, `tests/` or `src/` — because `matches()` grades from each task's
  `expect`. The test would have stayed green while the facts models are scored against rotted.
- **From an identifier.** A compare mode was to pair two runs on `(backend, model, ctx, surface,
  task)` and note any suite difference above the table, while `usable()` in that same file
  *refuses* a record whose prompt differs. The proposal was laxer than the code beside it.
- **From one backend.** "Record the model digest on every record", generalised from the ollama
  driver, which is the only one with an `/api/ps` to ask; `claude_code_drive.py` records a mutable
  alias and has no equivalent to offer.
- **From what a field is for.** `expect` was taken as ground truth for a verifier, but it holds only
  the expected *answers* — a task's dump path lives in its prose `prompt` and `useful_tools` carries
  no arguments, so nothing structured says what to call.
- **From the half that agreed.** "Grades unchanged" after rewording a task, checked by running
  `--grade` and reading the numerators, which did match. The denominators had gone 20 to 15 and
  every row said `UNCOUNTED x5`.

**The tell is that the sentence is about behaviour and the file is not open.** It is the same error
as the eval task that started that work — answering the question the way it reads rather than the
way it is keyed — which is worth knowing because at the time it does not feel like guessing.

**And it survives being noticed, which is the last thing this paragraph is for.** Its first draft
opened "Five review rounds on #221 were all this". Five was neither: it was the *finding* count at
that moment, written as a *round* count, and there were four rounds — by the time either was
counted from the API rather than from my own commit subjects (which had numbered my own edits as
rounds) there were **five rounds and six findings**, the sixth having landed while the paragraph
was being written. The same draft also credited `docs/smoke-test.md` with the three-way symbol
split; that file draws a two-way line — target memory against the dump's structure — and the third
way was mine.

**And this file is not linted.** `CLAUDE.md` and `FOLLOWUPS.md` are absent from CI's markdownlint
globs (see *Local verification* above). Point the linter at them anyway and it reports ten
pre-existing errors — fence and list spacing, nothing that renders wrongly — so neither a clean run
nor a dirty one tells you anything about an edit you just made here.

## Plugin vs. dev build

This project is also installed as a user-scope Claude Code plugin (`windbg-mcp@windbg-mcp`), which is
a snapshot of the last *published* release and does **not** track working-tree edits. In this repo
the plugin is **disabled locally** (`.claude/settings.local.json`) so the dev build above is what
runs. Keep machine-specific server wiring (absolute paths) out of version control.
