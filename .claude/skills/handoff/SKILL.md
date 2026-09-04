---
name: handoff
description: Hand this repo's work over - which files a handoff touches (CLAUDE.md, `.claude/rules/`, FOLLOWUPS.md, DONE.md, docs/smoke-test.md), how closing an item is a move rather than an edit, and why every number and mechanism must be re-derived rather than recalled. Use when updating the handoff docs, closing a FOLLOWUPS item, or writing prose that states a rule about how this code behaves.
---

# Handing the work over

## Handing the work over

"Update the handoff docs" means a specific set, discoverable only from what the handoff PRs touched
(#155, #159, #170). They are titled *"Hand the `<X>` work over: …"* — the stem is the convention,
and the clause after the colon says what kind of handoff it is: *"the traps, not just the result"*
on #159 and #170, *"what is covered, what is not"* on #155.

- **`CLAUDE.md`** — the two roles, the release-exe lock, and the routing table naming every rule
  and skill below. It is loaded into *every* session, so what goes here is what every session
  needs; anything longer belongs in one of the next two.
- **`.claude/rules/*.md`** — what bites while *editing* a subsystem, scoped by a `paths:` glob so
  it loads only when Claude reads a file it covers. A new subsystem note goes in the rule whose
  `paths` already match the file it is about, or in a new rule named after the seam.

  **`paths:` names the files whose *editor* needs the rule, not the files the rule mentions — and
  the ones it will be missing are `engine.rs`, `worker.rs`, `proto.rs` and `server.rs`.** Every
  rule here was first scoped to the files in its own title, which is the natural thing to do and
  was wrong five times: `worker-architecture` bound `worker.rs` and `proto.rs`, `listener-clients`
  bound `server.rs` (`WindbgServer::call_tool` is where a client's identity is re-entered) and
  `engine.rs`, `tool-surface` bound `worker.rs` (`summary_text` builds the prose the rule is
  about), `execution-waits` bound `proto.rs` (`EngineOp`, `StopReport`) and `async-runs` bound
  `server.rs` (the two `idempotentHint`s). Three of those were review findings on
  [#285](https://github.com/glslang/windbg-mcp/pull/285), landing one a round; the other two came
  from finally enumerating instead of grepping. It is always those four because they are the four
  `CLAUDE.md` names as the key source — nearly every behaviour here crosses supervisor, worker and
  MCP, so a rule about any of it binds files its title does not name. **Start from the four and ask
  which ones this rule constrains.**

  **That heuristic is a starting point and not a closure**, which is worth saying because the
  commit that introduced it claimed otherwise and drew a fourth round the same evening.
  `execution-waits` also binds `server.rs` (where six `CommandAndWait` and four `BoundedCommand`
  sites decide which wait a tool gets, and where `EXEC_WAIT_MS` is defined), `batch.rs` (the
  `{"op": "command"}` step goes through `raw_command`) and `structured.rs` (`StopReport` is the
  shape a deadline break is reported in) — and `batch.rs` is not a hub file, so the heuristic
  would never have reached it.

  **A test cannot do this, and two separate reasons matter.** The obvious check — every symbol a
  rule names must resolve to a file in its `paths` — was drafted twice and dropped, because an
  enumeration of every code-span identifier against every definition in `src/` returns mostly
  collisions: `cargo-and-dependencies` "names" `engine.rs` through the word *registry* and
  `worker.rs` through *execute*, `markdown-and-docs` names it through `fmt`, `transcripts` names
  `server.rs` through the `registers` **tool**, and `Arch` and `Expired` are each defined in two
  modules that mean different things by them. Tool names and English words are the same strings as
  this crate's items. The second reason is worse: an index of *definitions* cannot find `batch.rs`
  at all, because that file defines none of the names and is bound by what it **routes**. And the
  one true negative is real as well — `transcripts.md` names `src/structured.rs` only to say the
  transcript obeys the same rule, so declaring it would load a rule that tells a `structured.rs`
  editor nothing.

  **When you do run the enumeration, adjudicate every entry, not every row.** Round three happened
  because the `execution-waits → server.rs` row read `EXEC_WAIT_MS debug_batch dx end_session`, the
  three tool names made it look like noise, and the whole row went in the bin with the one real
  entry inside it. The noise is per entry. The backstop for all of this is the routing table in
  `CLAUDE.md`, which is loaded every session and lists what each rule covers whether or not its
  `paths` would have fired.
- **`.claude/skills/*/SKILL.md`** — the procedures: `tiers`, `review-round`, `live-kernel`,
  `eval-bench`, and this file. A skill's body costs nothing until it is invoked, so length is
  cheap here and expensive in `CLAUDE.md`. Its `description` is the whole of how it gets found —
  that line is in context every session, and the body is not.
- **`FOLLOWUPS.md`** — numbered items still **open**, each saying what would close it, why it was
  deferred, and where it picks up. Its header enumerates clusters and needs a line whenever an item
  is added.
- **`DONE.md`** — the same entries once they land, kept in full and **under the number they were
  filed with**. Closing an item is therefore a *move*: out of `FOLLOWUPS.md`, out of its cluster
  list, and into `DONE.md` **with an index line**, which is the only list of what has closed. An
  item that is **half** landed or **measured and declined** stays put — the first because the entry
  narrows to what is left, the second because nothing was built and the reopening condition is the
  content.

  **A citation is not retargeted, and that is a decision rather than an oversight.** Some twenty
  files say "`FOLLOWUPS.md` item N" — doc comments in eleven modules and in `tests/`,
  `CHANGELOG.md`, `DECISIONS.md`, every `docs/*.md`, the rules and skills under `.claude/`,
  `build.rs`, `ci.yml` and the eval tooling — so
  a citation whose file half followed the entry would make every close a sweep of source comments,
  unchecked, in a form that would have to be swept again next time. The number is the name;
  `FOLLOWUPS.md`'s header answers *which file*, above every entry, for whoever followed one there.
  What keeps that from rotting is a test rather than the rule:
  `engine::every_followups_citation_names_an_item_that_exists` reads every text file in the
  repository and fails if a cited number is in neither file, if one number is in both, or if
  `DONE.md`'s index has fallen out of step with its own entries. It was raised as a review finding
  on the split ([#270](https://github.com/glslang/windbg-mcp/pull/270)) with the sweep as its
  proposed fix; the fact was right and the remedy was the expensive half of it.
- **[`docs/smoke-test.md`](./docs/smoke-test.md)** — what each tier claims, per test, with budgets.

Plus `CHANGELOG.md` and whichever `docs/*.md` the behaviour moved in.

**Six places to check, not six files to edit.** A handoff touches the ones its change actually
moved: #170 updated two of them and `README.md`, and was right to — the test its
`docs/smoke-test.md` entry would have described did not exist yet, landing in #176 later the same
day. Going looking for another edit with no subject is how a section gets written about nothing.
The failure this list prevents is the opposite one, and it is the common one: *not knowing the
next file is there*.

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

**And none of this is linted.** CI's markdownlint globs are `README.md`, `CHANGELOG.md`,
`docs/**/*.md` and `skills/**/*.md` (`.github/workflows/ci.yml`), so `CLAUDE.md`, `FOLLOWUPS.md`,
`DONE.md` and everything under **`.claude/`** are absent from all four — and note `skills/**` is
the *shipped* plugin skill, not `.claude/skills/`, which is this repo's own working guidance and is
unlinted like the rest. Point the linter at them anyway and it reports ten pre-existing errors —
fence and list spacing, nothing that renders wrongly — so neither a clean run nor a dirty one tells
you anything about an edit you just made here.

