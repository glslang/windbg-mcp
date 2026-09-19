---
name: review-round
description: Work a PR review round in this repo - reading bot findings with the head SHA, deciding what to act on and where the reason for a decline goes, spotting findings that accumulate on one seam, and mutation-verifying a new rule against the mutation it is for. Use when handling review comments on a windbg-mcp or dbgscope PR, or before calling a review done.
---

# Working a review round

**Both review bots comment per commit**, and a round of findings can land *after* a reply to the
previous round. Before calling a review done, re-check with the head SHA:
`gh api --paginate repos/<owner>/<repo>/pulls/<n>/comments --jq '.[] |
select(.original_commit_id=="<sha>")'` — with `--paginate`, since a busy PR's comments span pages
and the first page is exactly where the older rounds are.

**But no findings at the head does not mean the head was reviewed, and neither endpoint above says
which it is.** Comments are findings; `pulls/<n>/reviews` lists only the reviews that *carried* one
— so a clean head and an unreviewed head look identical from both, and on #349 that read as "Codex
never reviewed the final commit" when it had, eight minutes before the merge. **Codex says so
itself, in two places:**

- **Its summary comment**, one per PR and updated in place, marked
  `<!-- codex-pull-request-review-summary -->`. It is an *issue* comment, not a review comment, and
  carries a table whose `Commit` column is the SHA of the latest review and whose `Status` says
  whether it finished:
  ```console
  gh api --paginate repos/<owner>/<repo>/issues/<n>/comments \
    --jq '.[] | select(.body | contains("codex-pull-request-review-summary")) | .body'
  ```
- **A reaction on the PR**: 👀 while a review is running, **👍 once every review has finished with
  no findings** — which is the signal that a round is genuinely closed rather than pending.
  ```console
  gh api repos/<owner>/<repo>/issues/<n>/reactions --jq '.[] | "\(.user.login): \(.content)"'
  ```
  A `+1` from `chatgpt-codex-connector[bot]` is that 👍. Reactions on the *comments* are a different
  thing and are usually empty — the completion signal is on the pull request.

So the order is: findings at the head (act on them), else the summary comment's `Commit` (is the
head even reviewed?), else the 👍 (did it finish clean?). Reviews re-trigger on new commits, and
`@codex review` / `@codex security review` in a comment asks for one.

**Codex is the bot to watch, and CodeRabbit's green is not evidence.** Its check reports `pass` with
*"Review rate limited"* beside it when it has not reviewed at all. Measured on
[#349](https://github.com/glslang/windbg-mcp/pull/349): across the PR's eight commits it filed **no
reviews and no findings** — `pulls/<n>/reviews` has not one CodeRabbit entry — while its check read
`pass` the whole way. All six findings there came from Codex. So read that check's reason text
rather than its bucket, and do not wait on it or offer to re-trigger it.

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

**Your decline rate is a measurement, and zero is a broken instrument.**
[#351](https://github.com/glslang/windbg-mcp/pull/351) ran to **22 findings over eleven rounds with
not one declined**, and that was not 22 correct findings — it was a session that had stopped
evaluating and started complying. Two that should have gone the other way:

- A finding asked the Codex summary lookup to match the bot's login "because a pull-request author
  can add a matching comment with a false `Commit`". The author is the person running the session,
  on their own PR; there is no such threat model. Worse, the skill **already** said to read that
  table's `Commit` against the head, so the change restated an instruction three paragraphs above
  it. Accepted anyway, with a *fresh* rationale invented to justify it — which is the tell: when the
  stated reason does not hold and you find yourself supplying a better one, you have decided to
  accept and are working backwards.
- A finding asked for a new field in a typed payload. Real, and its own text offered a text-only
  alternative as acceptable. Taking the field cost a golden that only a Windows host can re-record,
  turned the branch red for four commits, and none of that was weighed before saying yes.

The asymmetry to hold on to: a bot reads this diff without the argument that produced it, so it is
good at *what the code does* and unreliable about *what it should cost*. Check the premise against
the tree, and price the remedy yourself.

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

**A third shape of it, and the cheapest to act on: the findings are all about what a claim
*excludes*.** [#349](https://github.com/glslang/windbg-mcp/pull/349) drew six findings, **five on one
paragraph** of one `FOLLOWUPS.md` entry, and every one of the five named an operation the paragraph
had left *out* of a set — never one it had put in. The paragraph was an enumeration of which engine
ops can outlive their caller; it was rewritten four times and wrong four times, each round naming
another arm, because `EngineOp` has 34 of them and only `worker.rs` knows which are bounded.

What ended it was not a better list but noticing the **asymmetry**: an inclusion is a claim about one
op and is checkable on its own, while an exclusion is a claim about *every* path through that op —
including a prelude that runs before the clock is armed. So the entry now names ops that are in scope
and certifies **none** as out, and says the audit is unstarted. Generalising: in prose you own,
prefer the claim whose counterexample is a thing you can go and look at. "These are in" survives an
op being added; "these are the only ones" does not.

Two traps that produced three of those five, both worth knowing before starting such an audit.
`patience_slot`-style helpers answer about a **field**, not about the work — an op can carry a
deadline and still have an unbounded tail (`CrashTriage`), or carry none and be bounded
(`CommandAndWait`). And the unbounded work is often in a **shared prelude**: `resolve_coordinate`
runs before the watchdog in three different arms, so reading `fn set_breakpoint` says nothing about
`EngineOp::SetBreakpoint` — which is the "pinned at a site, not a function" rule below, met from the
other direction.

**And then check what the deleted thing was also load-bearing for**, because this repo has now got
that wrong twice in one PR. A revocation was simplified into "an expiry that does not wait", which
silently gave up the `releasing` flag that had been blocking a re-added name; and the `revoked`
check in `Lease::admit` was removed for a reason that was sound, dropping a *second* property it
also provided (refusing the revoked incarnation's own in-flight request). Both times the full suite
stayed green — a passing test is not evidence that a deleted check was doing nothing, only that
nothing covered it. Before deleting, name every property the code provides; after deleting, assert
the ones you meant to keep.

**A test can stage exactly the right scenario, run, and pass because a *neighbouring* rule covers
it.** Not a vacuous assertion — the paragraph above about capability gates is the case that never
runs; this one runs, asserts the right thing, and is green for the wrong reason, so reading it tells
you nothing. The only way to find out is to **break the rule the test claims to pin and confirm that
test fails**. If it stays green it is riding on something else; find what, and pick a construction
that other rule cannot reach.

The evidence is [dbgscope#139](https://github.com/glslang/dbgscope/pull/139) (2026-09-04), **nine
review rounds and fourteen findings** on one 700-line module — counted from
`gh api repos/<owner>/<repo>/pulls/<n>/reviews` and `.../comments`, because the first draft of this
paragraph said eight and eleven from memory and was caught by a reviewer noticing it disagreed with
its own "round nine" two paragraphs down. Four of the fourteen were invisible to a suite that
already covered the mechanism, each needing one specific construction to become visible:

| what was missed | what made it visible |
|---|---|
| a departed claim reopening the open that held it | **two attaches** — with a launch, an unrelated rule protects it either way |
| a claim handed along a chain rather than broadcast | **three** launches — with two, both readings agree |
| an arrived claim believed without re-reading the session | a **second process** keeping the session alive |
| a finished attach blocking a launch on a reused pid | a departed attach **whose guard is still held** |

Two of the four were regressions introduced by that PR and two were pre-existing, which is the point:
the split is invisible from the test results, because *every* one of them was green before and after.
The reviewer found them and the suite could not, and that is a property of the constructions rather
than of the reviewer — so the answer is not "review harder" but **mutation-verify each new rule
against the mutation it is for**, one at a time, and treat "the whole suite still passes" as the
thing to be suspicious of. Two of that PR's own commits shipped a fix whose test passed with the fix
backed out, until exactly that was done.

**And "the rule is pinned" is a claim about a *site*, not about a function**, which is the half of
that discipline it is easiest to leave out. A bug can live in an **argument**:
`e.modules().map(|loaded| loaded.len()).unwrap_or_default()` hands a failed enumeration on as a
count of zero, and zero was the arm reporting a fresh kernel attach — so a debugger call that did
not answer came back as evidence about the target. The fix makes the callee take `Option<usize>`,
and the natural test drives that callee with explicit arguments. It passes, it is a real rule, and
it says nothing whatever about the expression that carried the bug: mutating the **call site** back
to `unwrap_or_default()` came back **MISSED** — correctly. The MISSED *was* the finding. Two ways
out and the second is better: write the test through the caller, or extract the argument into
something with a name (`inventory_size(listed: Result<Vec<T>, E>) -> Option<usize>`) so that site
becomes testable on its own. Either way, **mutate the line the bug was on** — a mutation applied to
the function the bug was *in* is a different experiment, and it is the one that passes.

So read a MISSED as "no test fails when I change this **here**" before reading it as a gap. A rule
can be firmly pinned at one site and unpinned at the one that shipped the defect, and the two are
indistinguishable from the report alone. What settles it is cheap: name the test you expect to
fail, then check it calls the code you mutated.

A corollary for the other direction, which is the one you are in more often: **when you are about to
tell a reviewer their scenario is unreachable, measure it first.** Round nine of that PR said two
live attaches on one pid could starve each other, and the reply forming in my head was that they
cannot. That reply happened to be right — the kernel gives a process one debug port and refuses the
second with `0xD0000048 STATUS_PORT_ALREADY_SET` — but it was worth nothing until a probe said so,
and the probe is what could be put in the code beside the rule for the next round to find. A
dismissal you have not measured is indistinguishable, to you, from one you have.

**And a red is not proof either — read *which* assertion produced it.** The measurement that
retired a P1 on [#351](https://github.com/glslang/windbg-mcp/pull/351) was a fixture where two
paths reach one indirect jump disagreeing about how far the index was bounded, checked by backing
the meet out of `ioctl::Facts::join`. It went red on the first run, which is what a mutation check
is for — and it went red on the **last** assertion, the reader's call count, while the three that
state the rule stayed green. The fixture served only the control's twelve bytes, so the mutated
walk asked for six slots, was refused for want of *bytes*, and left the switch unresolved for a
reason with nothing to do with the bound: every assertion that mattered would have passed with the
rule deleted. Serving whatever length is asked for moved the failure onto the first assertion and
turned the check into six fabricated edges — the finding's own scenario, reproduced. So name the
**assertion** you expect to fail, not only the test, and be most suspicious when the one that went
red is the incidental one you added last.

## A class fix closes the class only if it can express the whole rule

The rule above says to delete the choice generating a run of findings rather than fix them one at a
time. **The failure mode of doing that is centralising the mistake instead of fixing it**, and it is
not visible from inside: every caller now goes through one helper, the commit message says so, and
the next round lands on the helper.

[dbgscope#164](https://github.com/glslang/dbgscope/pull/164) (2026-09-15) produced **17 findings over
11 rounds** on one 1,300-line PE parser, and **three were against the previous round's own fix**:

- Round 3 routed every base-plus-offset through one `va(base, offset)` and said "every addition of an
  offset to a base in this module goes through here". True — and `va` took no length, so it could
  only check where a read *starts*. Round 8 found the header reader handing the reader a span running
  off the end of the address space. The fix was a **signature change**, `va(base, offset, len)`,
  after which the half-version cannot be written. The mutation is what proves the difference: with
  the length inside the helper, one edit fails *both* call sites' tests; before it, each site had its
  own rule and only one test moved.
- Round 9 added `SectionAlignment` rounding with a fallback when the alignment was not a power of
  two. Round 10 pointed out the fallback reproduced the exact under-reporting the rounding was for.

**The tell is a commit message containing "every X now goes through Y".** Ask what Y *cannot*
express. If the rule you just learned does not fit in Y's parameters, Y is the next finding.

## Do the enumeration yourself, at round three

Those eleven rounds were eleven *fields* of an attacker-controlled structure found one at a time —
each locally real, each cheap to fix, and each making the next one look like bad luck rather than a
queue. What ended it was enumerating all 21 field reads in one pass, fixing the two that were left,
and writing the contract into the module doc: what constrains every field, **and the two that are
deliberately unconstrained with why**. A reviewer enumerating a structure's fields is a machine doing
something you can do faster and more completely.

So when a second finding lands on the same *kind* of thing — not the same line — stop answering and
go count. The audit is the deliverable; the remaining fixes fall out of it.

## Their rule can be right and their reproduction wrong

Round 11 asked for ordinal thunks with reserved bits set to be refused. Correct. Its worked example
was a thunk of `0x2110` with the ordinal flag set — which fits the low sixteen bits and is a
perfectly ordinary ordinal import for ordinal 8464. Implementing the example would have refused a
valid thunk: **a new defect, shipped on a true finding.** The test now sets a genuinely reserved bit
*and* pins the reviewer's value as one that must still read.

The first attempt used their example and failed, which is how it was caught — so write the test from
the rule, run it, and read a failure as a question about which of the two is wrong.
