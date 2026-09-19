---
name: merge-dependabot-prs
description: Walk the open Dependabot PR queue oldest-first and merge each one once CI is green. Use when the user asks to "merge dependabot PRs", "clear the dependabot queue", "process bot updates", "ship the dep bumps", or similar. Fixes failing CI when possible (pushing to the bot's branch or opening a follow-up PR), and never blocks the queue on a single failure — skips and continues.
---

# Merge Dependabot PRs

Process the open Dependabot PR queue **oldest first**. For each PR: bring it up to date with the base, wait for CI, merge if green. If CI fails, attempt an automated fix (push to the bot's branch if writable, otherwise open a follow-up PR). **A single failing PR never stops the run** — log the reason and move on.

## 0. Detect GitHub tooling (once, up front)

```bash
if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
  echo "USE: gh"
else
  echo "USE: mcp"
fi
```

- `gh` available → use `gh` everywhere below.
- Otherwise (Claude Code on the web, restricted environments) → use the `mcp__github__*` tools. Each step shows both.

Confirm the target repo (`gh repo view` / current `git remote -v`). If the user wants a different repo than `cwd`, ask.

## 1. List Dependabot PRs, oldest first

**gh:**
```bash
gh pr list \
  --author 'app/dependabot' \
  --state open \
  --json number,title,createdAt,headRefName,baseRefName,mergeable,mergeStateStatus \
  --jq 'sort_by(.createdAt)'
```

**MCP:** call `mcp__github__list_pull_requests` with `state: "open"`. Filter results where `user.login == "dependabot[bot]"`. Sort ascending by `created_at`.

If the list is empty, report so and stop.

Capture the ordered list of PR numbers — process them in that order, one at a time.

## 2. Inner loop: process one PR

For the current PR `#N`:

### 2a. Read state

- **gh:** `gh pr view N --json number,title,headRefName,baseRefName,mergeable,mergeStateStatus,statusCheckRollup,reviewDecision`
- **MCP:** `mcp__github__pull_request_read` (`method: "get"`) + (`method: "status"`) for checks.

### 2b. Rebase if behind / dirty

If `mergeStateStatus` is `BEHIND` or `DIRTY`, ask Dependabot to rebase rather than rebasing yourself — it handles its own lockfile regen:

- **gh:** `gh pr comment N --body "@dependabot rebase"`
- **MCP:** `mcp__github__add_issue_comment` with that body.

Wait ~60–120s, re-read state. If the bot doesn't act after two attempts, fall through to manual rebase (`git fetch && git rebase origin/<base>`) on the branch, or comment `@dependabot recreate`.

### 2c. Wait for CI

Poll `statusCheckRollup` until no check is `IN_PROGRESS` / `PENDING` / `QUEUED`. Cap at ~10 min per PR.

- **gh:** `gh pr checks N --watch` (blocks until done) or loop on `gh pr view N --json statusCheckRollup`.
- **MCP:** loop on `mcp__github__pull_request_read` with `method: "status"`, sleep 15–30s between polls.

If checks never start, comment `@dependabot recreate` and re-poll.

### 2d. If green → merge

Check repo merge settings once at start of run (`gh repo view --json mergeCommitAllowed,squashMergeAllowed,rebaseMergeAllowed`). Prefer **squash** for Dependabot PRs when allowed (clean history: one bump = one commit).

- **gh:** `gh pr merge N --squash --delete-branch`
- **MCP:** `mcp__github__merge_pull_request` with the allowed `merge_method`.

Go back to step 2 for the next PR in the queue.

### 2e. If red → diagnose

1. **Pull failing logs.**
   - gh: `gh pr checks N` → `gh run view <run-id> --log-failed`
   - MCP: read `statusCheckRollup` for each check's `detailsUrl`; `WebFetch` the run page or use `mcp__github__get_commit` for the SHA's checks.

2. **Classify** (in order — stop at first match):

   | Failure type | Action |
   |---|---|
   | Flake / infra hiccup (network, runner crash) | Re-run the failed job, don't push code. `gh run rerun <run-id> --failed` |
   | Lockfile / generated-file drift | Run the project's regen command (e.g. `npm install`, `bundle install`, `cargo update -p X`, `pnpm install --lockfile-only`), commit, push. |
   | Snapshot / fixture mismatch | Regenerate (`jest -u`, `vitest --update`, etc.), eyeball the diff for sanity, commit, push. |
   | Real code change (API rename, removed export, breaking type) | Write the codemod / fix. Run tests locally if possible. Commit, push. |
   | Major-version bump with breaking changes you can't safely fix here | **Skip.** Comment a brief note on the PR explaining what's needed, move on. |
   | Repeated failure after one fix attempt | **Skip.** Don't loop forever. |

### 2f. Push the fix — branch path first, follow-up PR fallback

**Path 1 — push to the Dependabot branch:**

```bash
git fetch origin <headRefName>
git checkout <headRefName>
# apply fix
git add -A
git commit -m "fix: <what>"
git push origin <headRefName>
```

If push is rejected (branch protection, or the actor lacks write to bot branches), fall through to Path 2.

**Path 2 — follow-up PR:**

1. Create a new branch off the Dependabot branch:
   ```bash
   git fetch origin <headRefName>
   git checkout -b followup/<N>-fix origin/<headRefName>
   # apply fix
   git commit -m "fix: <what> (carries #N)"
   git push -u origin followup/<N>-fix
   ```
2. Open a PR targeting the same base as `#N`:
   - **gh:** `gh pr create --base <baseRefName> --title "..." --body "Carries #N forward with required fixes."`
   - **MCP:** `mcp__github__create_pull_request` with the same fields.
3. **Treat the follow-up PR as the new current PR** in the loop. When it merges, the original Dependabot PR will auto-close (because its commits are now in base) — or close it explicitly with a note pointing at the follow-up.

After push, loop back to **step 2c** (wait for CI on the new commit).

### 2g. Never block the queue

If at any point this PR can't be merged and you've attempted one fix cycle, **stop trying, log the reason, move to the next PR**. Don't let one stuck bump strand the rest.

## 3. Final report

When the queue is exhausted, print:

- **Merged:** `#12, #15, #18, …`
- **Skipped:** `#14 — major-version React bump; render snapshots need human review`, `#17 — repeated lint failure after two fix cycles`
- **Open follow-ups:** `#22 (carries #16)`

## Gotchas

- **`@dependabot rebase` is async.** After commenting, the bot takes 30s–2min to push. Don't trust the immediate post-comment state read; poll.
- **Closing a Dependabot PR tells the bot "don't try again."** If you close one that needs to come back, comment `@dependabot recreate` — not just reopen.
- **Branch protection re-checks on every merge.** A PR that was green an hour ago may show `BLOCKED` after an earlier merge in this same run (now behind). Always re-read state at step 2a, even if you already saw it green.
- **Grouped updates** (`dependabot.yml` `groups:`): one PR may contain many bumps. If only one dep in the group breaks tests, consider `@dependabot ignore <name>` + recreate rather than fighting the failing test.
- **Don't use `@dependabot merge`.** It bypasses any fixes you've pushed and gives you no record of which PRs this run touched. Do the merges yourself.
- **Secondary rate limits** on long runs (30+ PRs). Back off 30s on any 403/429 from the API.
- **CI required checks vs. all checks.** Only required checks block merge. An optional check failing is not a reason to skip — verify `mergeable: MERGEABLE` rather than reading "any check red = bad."
- **`needs.*` in workflows can leave a job permanently pending** if a dependency was skipped. If a check is stuck `QUEUED` for >5min with no runner activity, it's probably a `needs` graph issue, not a slow runner — comment `@dependabot recreate` to get fresh check runs.

## Inputs the user might give

- "merge them all" → run the full procedure on every open Dependabot PR.
- "just the patch bumps" → after listing, filter PR titles for `^Bump .* from X.Y.Z to X.Y.(Z+n)` (no major/minor change) before looping.
- "dry run" → run steps 1, 2a, 2c (status only). Don't merge. Print what *would* happen.
- "just #N" → skip step 1, jump into step 2 for that one PR.
