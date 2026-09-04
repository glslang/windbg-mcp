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

A corollary for the other direction, which is the one you are in more often: **when you are about to
tell a reviewer their scenario is unreachable, measure it first.** Round nine of that PR said two
live attaches on one pid could starve each other, and the reply forming in my head was that they
cannot. That reply happened to be right — the kernel gives a process one debug port and refuses the
second with `0xD0000048 STATUS_PORT_ALREADY_SET` — but it was worth nothing until a probe said so,
and the probe is what could be put in the code beside the rule for the next round to find. A
dismissal you have not measured is indistinguishable, to you, from one you have.

