---
name: handoff
description: Hand this repo's work over - which files a handoff touches (CLAUDE.md, `.claude/rules/`, FOLLOWUPS.md, DONE.md, docs/smoke-test.md), how closing an item is a move rather than an edit, and why every number and mechanism must be re-derived rather than recalled. Use when updating the handoff docs, closing a FOLLOWUPS item, or writing prose that states a rule about how this code behaves.
---

# Handing the work over

## The files a handoff touches

"Update the handoff docs" means a specific set, discoverable only from what the handoff PRs touched
(#155, #159, #170). They are titled *"Hand the `<X>` work over: …"* — the stem is the convention,
and the clause after the colon says what kind of handoff it is: *"the traps, not just the result"*
on #159 and #170, *"what is covered, what is not"* on #155.

- **`CLAUDE.md`** — the two roles, the release-exe lock, and the routing table naming every rule
  and skill below. It is loaded into *every* session, so what goes here is what every session
  needs; anything longer belongs in one of the next two.
- **`.claude/rules/*.md`** — what bites while *editing* a subsystem, scoped by a `paths:` glob so
  it loads only when Claude reads a file it covers. A new subsystem note goes in the rule whose
  **subject** it belongs to; the scope is not part of that choice, for the reason below.

  **`paths:` is one shared scope for the eight code rules, and that is a decision rather than
  laziness.** Each was first scoped to the files named in its own title, which is the natural thing
  to do and was wrong fourteen times: eight filed as review findings across six rounds on
  [#285](https://github.com/glslang/windbg-mcp/pull/285), six more found by enumerating rather
  than waiting for the next round. `worker-architecture` binds `worker.rs`
  and `proto.rs`, `listener-clients` binds `server.rs` and `engine.rs`, `tool-surface` binds
  `worker.rs`, `execution-waits` binds `server.rs`, `batch.rs` and `structured.rs`, `transcripts`
  binds `main.rs`, `server.rs` and `engine.rs`, and so on. Two heuristics were tried and both
  failed: "start from the four hub files" cannot reach `batch.rs`, which is bound by what it
  *routes*; and a lint over symbols a rule names returns mostly collisions, because tool names and
  English words are the same strings as this crate's items (`cargo-and-dependencies` "names"
  `engine.rs` through *registry*, `transcripts` names `server.rs` through the `registers` **tool**,
  and `Arch` and `Expired` are each defined in two modules meaning different things).

  What settled it was measuring instead of arguing. Against the 72,396 bytes of all eight rules,
  `engine.rs` already loaded 89%, `worker.rs` and `server.rs` 69%, `proto.rs` 62% — because every
  tool call crosses those four. Eleven hand-maintained lists bought 11–38% on the files anyone
  edits and cost a review round per mistake, so they were replaced by `src/**/*.rs` plus
  `tests/**/*.rs` and `build.rs` — `build.rs`'s own `INPUTS` less the manifests — identical in
  all eight. **A new code rule copies that scope; it does not invent
  one.** The laziness that still pays is on the other axis and is untouched: a session touching no
  Rust never loads the 72,211 bytes of code rules at all — it loads `CLAUDE.md` plus whichever
  narrow rules its files match, at most 11,315 B with all three firing.

  **State that as a bound, never as a composition.** Two goes at the exact wording were both review
  findings: "and nothing else" (the narrow rule loads too), then "the one narrow rule its subject
  matches" — which was written one commit *after* the paragraph below documenting that
  `examples/README.md` matches two rules and `build.rs` four. The globs intersect by design, so any
  sentence counting how many fire has to be re-derived against them, and the saving does not need
  the count: what it rests on is the code rules not firing.

  The three rules that are *not* about this server's code keep narrow scopes, and should: their
  **subjects** are disjoint from the code's, so scoping them is one obvious judgement each rather
  than a per-file list, and no round has filed a scope finding against any of the three.

  **Their globs do overlap, and that is fine** — the sentence here used to say they "overlap
  nothing", which is simply false and was a review finding in its own right.
  `cargo-and-dependencies` names `build.rs`, which is also in the code scope; `powershell-scripts`
  names `examples/**`, which catches `examples/README.md` alongside `markdown-and-docs`'s
  `**/*.md`. Both are wanted: `build.rs` is a build input *and* the file the PE version resource
  lives in, and a README beside the scripts it documents is both markdown and script context.
  Overlap costs a few kilobytes on a file that genuinely has two subjects. The failure to care
  about is a rule that does **not** load where it is needed, which is the opposite direction and
  the one all fourteen mistakes were in. Do not narrow a scope to make a Venn diagram tidy.

  One thing to know while reading them: `powershell-scripts` names `tools/**`, so it also loads on
  the eval scripts, which are Python. That is deliberate — its stderr-draining rule is about
  driving this server from *any* script — but the rule's name undersells it.
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
- **[`docs/smoke-test.md`](../../../docs/smoke-test.md)** — what each tier claims, per test, with budgets.

Plus `CHANGELOG.md` and whichever `docs/*.md` the behaviour moved in.

**Six places to check, not six files to edit.** A handoff touches the ones its change actually
moved: #170 updated two of them and `README.md`, and was right to — the test its
`docs/smoke-test.md` entry would have described did not exist yet, landing in #176 later the same
day. Going looking for another edit with no subject is how a section gets written about nothing.
The failure this list prevents is the opposite one, and it is the common one: *not knowing the
next file is there*.

**The closing sentence of an explanation is where the false claim goes.** Rounds six, seven and
eight of #285 were three consecutive findings of exactly this, none of them about the thing being
explained and all of them about the tidy line at the end of it: "a docs session loads `CLAUDE.md`
and nothing else" (it loads the matching narrow rule too), the three narrow rules "overlap nothing"
(`build.rs` is in two scopes, `examples/README.md` in two), and a commit message claiming a change
"closes the class" (the next round reopened it). Each was written *after* the accurate paragraph
above it, as a summary — and summarising is where the qualifier gets dropped, because a crisp line
reads better than a true one. The tell is a sentence with **nothing**, **every**, **always**,
**one**, **closes** or **never** in it that you wrote to finish a paragraph rather than to state a
fact. Re-read those against the thing itself, not against the paragraph they conclude.

**And round ten was the same mistake inside the commit that named it.** The fix for "and nothing
else" replaced it with "the one narrow rule its subject matches", which is false for the same
`examples/README.md` the paragraph above had documented one commit earlier — so the correction, the
rule it contradicted, and the paragraph warning about exactly this shipped together. Naming a habit
does not interrupt it. What worked was changing the *shape* of the claim: state a bound, which
survives a glob change, rather than a composition, which has to be re-derived against every scope
and was wrong both times it was written.

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

