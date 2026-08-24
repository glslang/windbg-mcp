#!/usr/bin/env python3
"""Run the model x tool-surface x context matrix against this server, and grade it.

`local_model_drive.py` answers "can *a* model drive this?" for one model, one surface and
whatever window the runtime happened to serve. This runs that script across a grid and grades
what comes back against the answer key in `tools/eval_tasks.json`, so the question becomes
"which of these knobs actually decides whether a model can drive this?".

    EVAL_TOKENS=<tokens.json> python3 tools/local_model_eval.py <plan.json>
    python3 tools/local_model_eval.py --grade  <results.jsonl> [tasks.json]
    python3 tools/local_model_eval.py --matrix <results.jsonl> [tasks.json]

**Three axes, and they are not independent.** The tool surface is bytes of prose in every
turn; the context is what the runtime will hold; the model is what can pick a tool out of
whatever fits. A surface that does not fit is not a tool-selection result, and a model that
cannot select is not a budget result - which is why every cell records both, and why the
grader reports `possible` beside `correct`: three of the six tasks cannot be answered on the
11-tool surface at all, and counting those as failures would say a small surface makes models
stupid rather than that it makes tools absent.

**The credentials do the narrowing, not a flag.** Each surface is a *client* of one listener
(PR #196): `full` is served every tool, `lean` `session,inspect,crash`, `min` `crash`. So a
cell changes which bearer token the driver presents and nothing else - no restart, no second
process, and the thing under measurement is the shipped feature rather than a test double.
The tokens live in a file of their own, named by `EVAL_TOKENS` and never in the plan, because
a plan is checked in and a credential is not.

**Cells are subprocesses, and the log is append-only.** A matrix run is hours long; a cell that
wedges must not take the grid with it (`budget_s` kills it and records why), and a run that
dies in the middle must leave every finished cell on disk. Re-running the same plan **resumes**:
a (model, context, surface, draw, task) already in the log is not run again.

**One draw per cell answers a different question from n draws of one cell.** The grid moves one
knob at a time across many cells, which is enough for failure *modes* and for whether a surface
fits at all, and is not enough for any statement of the form "X caused Y" - three write-ups
reached past that anyway (`FOLLOWUPS.md` item 42). A cell group may therefore ask for `draws: n`,
which runs the same cell n times asking for seed 1..n, and every reader here keys on the draw so
repeats **accumulate** rather than replace: the grader counts over draws, and `--matrix` prints a
distribution (`3Y2n`) where a single draw prints a mark. A record from before draws existed is
draw 1, so an old log grades exactly as it did.
"""
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DRIVER = os.path.join(HERE, "local_model_drive.py")
CLAUDE_DRIVER = os.path.join(HERE, "claude_code_drive.py")


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def tokens_for(plan):
    """The bearer token per surface, from the file `EVAL_TOKENS` names.

    Separate from the plan on purpose: the plan is the experiment and belongs in the repo,
    the tokens are credentials of the run's own and belong in neither the repo nor a command
    line. Nothing here prints one - a failure names the surface, never the value.
    """
    path = os.environ.get("EVAL_TOKENS", "")
    if not path:
        raise SystemExit("set EVAL_TOKENS to a JSON file of {surface: token} for this run's clients")
    tokens = load(path)
    missing = [s["client"] for s in plan["surfaces"] if s["client"] not in tokens]
    if missing:
        raise SystemExit(f"{path} has no token for: {', '.join(missing)}")
    return tokens


def usable(record, task=None):
    """Whether a record still measures what this run is asking.

    **One predicate, read by the resume set, the grader and the matrix**, because they disagreed
    once and the disagreement was unreachable from either side: grading excluded a record while
    resume counted it as done, so the cell could never be re-run without hand-editing an
    append-only log. Every reason a record has stopped counting belongs here rather than in another
    tuple element somebody has to remember.

    Two reasons so far. A cell asking for an 8,192-token window and served 32,768 - the runtime
    reusing an instance it already holds - is not a measurement of either window. And an answer to
    a question the suite no longer asks is not an answer to the one it asks now: this run changed
    `unloaded_driver`'s prompt mid-flight and had to delete those records **by hand**, because
    resume would otherwise have skipped the task while the grader scored the old answers against
    the new key.
    """
    if task is not None and record.get("prompt") and record["prompt"] != task.get("prompt"):
        return False
    served, asked = record.get("served_context"), record.get("num_ctx")
    if not asked:
        # Nothing was requested - a Claude cell, or a run left at the runtime's default - so
        # there is no claim to check.
        return True
    # `served_context` is null when `/api/ps` was unavailable or did not know the tag. That is not
    # agreement, it is silence: the harness never saw which window this ran at, and scoring it
    # would publish the requested number as though it had been verified.
    return served is not None and served == asked


def draw_of(record):
    """Which draw a record is, for a log that spans the change that introduced them.

    **A record with no `draw` is draw 1**, and that is the whole compatibility story: the runs
    this bench has already recorded grade to exactly what they graded to before, and a re-run of
    the plan that produced them still counts them as done. Everything that keys on a draw goes through here, so
    the default lives in one place rather than in four `or 1`s that could drift apart.
    """
    return record.get("draw") or 1


def already_done(log_path, tasks):
    """Which (backend, model, context, surface, draw, task) the log already holds, so a re-run
    resumes.

    Keyed on the things a cell is identified by rather than on a cell id, because the plan can grow
    a surface or a context between runs and everything already measured is still valid - what must
    not happen is a task being run twice into one log and graded twice.

    **The draw is part of that identity**, which is what lets a plan ask for more draws of a cell
    it has already run: draws 1-3 stay done and 4-5 run. Without it a second draw would be
    indistinguishable from a repeat of the first and would never be run at all.

    `tasks` is the suite as it is *now*, because [`usable`] compares each record against the
    question currently being asked.
    """
    by_id = {t["id"]: t for t in tasks}
    stale = 0
    seen = set()
    if not os.path.exists(log_path):
        return seen
    with open(log_path, encoding="utf-8") as log:
        for line in log:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            if not usable(r, by_id.get(r.get("task"))):
                # Not done: the window it ran at was not the one it asked for, or the question has
                # changed since. It has to run again, and the grader will not score it either.
                stale += 1
                continue
            # **Keyed by backend too.** Two groups can name the same model - an ollama tag
            # aliased `sonnet` beside the Claude Code row - and without this the first one's
            # records make the second's whole cell look finished.
            seen.add((r.get("backend"), r.get("model"), r.get("num_ctx"),
                      (r.get("surface") or {}).get("client"), draw_of(r), r.get("task")))
    if stale:
        print(f"  {stale} record(s) in the log no longer measure what this plan asks "
              f"(a changed prompt, or a window that was not the one requested); they will run again")
    return seen


def cell_tasks(tasks_file, subset):
    tasks = load(tasks_file)["tasks"]
    if subset:
        wanted = load(tasks_file)["subsets"][subset]
        tasks = [t for t in tasks if t["id"] in wanted]
    return tasks


def release_sessions(env, why):
    """End whatever this credential holds, best effort and never fatal.

    Best effort *by construction*, not by neglect: the only caller runs it as a cell's own
    precondition, so a release that fails costs that cell the four-session cap at worst and the
    grid nothing. Nothing downstream reads a result from it, which is why it has none.
    """
    try:
        done = subprocess.run([sys.executable, "-u", DRIVER, "--release"], env=env,
                              capture_output=True, text=True, timeout=120)
        released = [line for line in done.stdout.splitlines() if "released" in line]
        if released or done.returncode:
            print(f"    {why}: {len(released)} session(s) released"
                  + (f", exit {done.returncode}" if done.returncode else ""))
    except (subprocess.TimeoutExpired, OSError) as e:
        print(f"    {why}: could not release ({e})")


def run_cell(plan, tokens, backend, model, context, surface, draw, subset, budget_s, log_path,
             logs_dir):
    """One (backend, model, context, surface, draw) cell: a driver process over the task list."""
    label = (f"{backend}:{model} ctx={context or 'default'} surface={surface}"
             + (f" draw={draw}" if draw != 1 else ""))
    env = dict(os.environ)
    env.update({
        "WINDBG_MCP_URL": plan["url"],
        "WINDBG_MCP_TOKEN": tokens[surface],
        "WINDBG_MCP_EVAL_OUT": log_path,
        "EVAL_RUN": plan["run"],
        "EVAL_SURFACE": surface,
        "EVAL_DRAW": str(draw),
        "MAX_STEPS": str(plan.get("max_steps", 6)),
    })
    if subset:
        env["EVAL_SUBSET"] = subset
    if backend == "ollama":
        env["LOCAL_MODEL"] = model
        env["NUM_CTX"] = str(context or 0)
        # **The seed is the draw index**, which on a runtime that honours it pairs arm A's draw 3
        # with arm B's draw 3 - the experiment draws are for (item 42) is an A/B, and a paired
        # comparison beats averaging two independent samplings. It does not reproduce one here:
        # measured 2026-08-24, four identical requests under one seed gave four different answers
        # (`local_model_drive.SEED`). So it is recorded as what was asked for, the draws vary
        # anyway, and the distribution over them is the measurement.
        env["EVAL_SEED"] = str(draw)
        # Residency for the length of a cell, then eviction: the next cell is either the same
        # model at another surface (keep it) or a different window, which reloads regardless.
        env["OLLAMA_KEEP_ALIVE"] = plan.get("keep_alive", "10m")
        argv = [sys.executable, "-u", DRIVER, plan["tasks"]]
    elif backend == "claude-code":
        env["CLAUDE_MODEL"] = model
        # **Every tool in the prompt, as the local models get them.** Claude Code defers MCP
        # tool schemas by default and fetches them with `ToolSearch`, which is a real feature
        # and the wrong measurement here: it would make the surface axis cost this row almost
        # nothing while charging every other row in full.
        env["ENABLE_TOOL_SEARCH"] = "false"
        argv = [sys.executable, "-u", CLAUDE_DRIVER, plan["tasks"]]
    else:
        raise SystemExit(f"unknown backend `{backend}`")

    # **This cell clears its own namespace before it starts, rather than the last one clearing up
    # after itself.** Cleanup used to be a postcondition: kill the cell, then release what it had
    # open, then check that the release worked, then handle its timeout, then handle its exit
    # code - four rounds of review, each finding a way for the guarantee to be lost, because a
    # postcondition can only be as good as the reporting of it. As a precondition it cannot be
    # lost: however the previous cell died - killed, crashed, cleanly finished - this one begins
    # with nothing of its own attached, and nothing has to notice.
    release_sessions(env, f"before {label}")

    os.makedirs(logs_dir, exist_ok=True)
    # **Claude Code reads the project it is started in, and walks *up* to find it.** `CLAUDE.md`,
    # settings, the checkout itself - and this repository's `CLAUDE.md` now quotes two of the six
    # answers, in the section explaining how the grader was fixed. So a cell started anywhere
    # under the checkout is handed part of the answer key before it calls a tool.
    #
    # `logs_dir` looked neutral and is not: the checked-in plan keeps logs in `eval-out/`, inside
    # the tree. An empty directory of this process's own is the only one that is neutral wherever
    # a plan puts its output.
    cwd = tempfile.mkdtemp(prefix="windbg-eval-cwd-") if backend == "claude-code" else None
    stdout_path = os.path.join(
        logs_dir, f"{backend}_{model.replace(':', '-').replace('/', '-')}_"
                  f"{context or 'default'}_{surface}"
                  # Only a repeated cell carries the suffix, so a plan that never asked for draws
                  # keeps writing the log names it has always written and a resume overwrites the
                  # same file rather than leaving a `_d1` beside it.
                  + (f"_d{draw}" if draw != 1 else "") + ".log")
    print(f"\n=== cell {label} -> {os.path.basename(stdout_path)}")
    started = time.time()
    killed = False
    with open(stdout_path, "w", encoding="utf-8") as out:
        # Its own process group, so the budget below can take the *cell* down rather than only
        # the driver: a Claude cell's driver has `claude` as a child, and killing the parent
        # alone leaves that running against the listener the next cell is about to use.
        proc = subprocess.Popen(argv, env=env, stdout=out, stderr=subprocess.STDOUT, cwd=cwd,
                                start_new_session=True)
        try:
            proc.wait(timeout=budget_s)
        except subprocess.TimeoutExpired:
            # **A budget is part of the measurement.** A model that cannot finish a task list
            # inside a generous wall clock has told us something; a grid that waits for it
            # has not. The kill is recorded as the cell's outcome rather than as an error of
            # the harness.
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                proc.kill()
            proc.wait()
            print(f"    budget of {budget_s}s exceeded; cell killed")
            killed = True
            note = {"run": plan["run"], "backend": backend, "model": model,
                    "num_ctx": context or None, "surface": {"client": surface}, "draw": draw,
                    "task": None, "error": f"cell exceeded its {budget_s}s budget"}
            with open(log_path, "a", encoding="utf-8") as log:
                log.write(json.dumps(note) + "\n")
    if cwd:
        # `rmtree`, not `rmdir`: Claude Code may leave state of its own in the directory it ran
        # in, and a cell must not fail on the way out because its scratch was not empty.
        shutil.rmtree(cwd, ignore_errors=True)
    print(f"    {round(time.time() - started)}s, exit {proc.returncode}")
    # **Not after a kill.** `records()` keeps the last `task: null` note for a cell, so a generic
    # `driver exited -9` written here would bury the budget-exceeded note above - which is the one
    # that says why - and the summary would report the wrong reason for the only outcome it has.
    if proc.returncode and not killed:
        # **A cell that failed is not a cell with fewer tasks.** A driver that dies on a bad
        # credential, an MCP handshake or a missing model writes some records or none, and
        # without this the summary shows a short row or no row at all - an incomplete grid
        # reading as a finished one. The note gives the cell a row that says what happened.
        note = {"run": plan["run"], "backend": backend, "model": model,
                "num_ctx": context or None, "surface": {"client": surface}, "draw": draw,
                "task": None,
                "error": f"driver exited {proc.returncode}; see {os.path.basename(stdout_path)}"}
        with open(log_path, "a", encoding="utf-8") as log:
            log.write(json.dumps(note) + "\n")
    return proc.returncode


NUMERIC = re.compile(r"^(0x)?[0-9a-f]+$")
# A separator *between* hex digits is how a reader is helped, not part of the value: WinDbg
# writes `fffff801`3c65bca8` and the control row wrote `0xfffff801_3c65bca8`. Both name the
# address the key holds, and the second was scored a miss until this existed.
SEPARATOR = re.compile(r"(?<=[0-9a-f])[_`](?=[0-9a-f])")


def normalise(answer):
    return SEPARATOR.sub("", answer.lower())


def present(alt, answer):
    """Whether one alternative appears in an answer, as a *value* rather than as a substring.

    Plain containment for prose, and containment **between hex boundaries** for a number - a
    rule this grader learned the hard way. `0x22` is the device type `ioctl_decode` asks for,
    and `0x22200b` is the code in the question: the first is inside the second, so the check
    passed for every answer that merely repeated the question. One model's hand-decode scored
    correct while saying the device type was `0x2` and the access `FILE_READ_DATA`, both wrong.

    Only digits count as the boundary, not letters, because the leading `x` of `0x13a` would
    otherwise stop the bare `13a` alternative from matching the very answers it is there for.
    """
    alt = alt.lower()
    if not NUMERIC.match(alt):
        return alt in answer
    if alt.startswith("0x"):
        # **Leading zeros are formatting, not value.** The tool prints `0x802` and a model
        # writing the same field as `0x0802` is not wrong - the boundary rule alone marked one
        # such answer incorrect while it agreed with the tool in every field.
        digits = alt[2:].lstrip("0") or "0"
        pattern = rf"(?<![0-9a-f])0x0*{re.escape(digits)}(?![0-9a-f])"
    else:
        pattern = rf"(?<![0-9a-f]){re.escape(alt)}(?![0-9a-f])"
    return re.search(pattern, answer) is not None


def matches(record, task):
    """Whether the answer carries the facts the key requires.

    Every group in `expect` must appear, any alternative within a group counting - so an
    answer may say `0x13A` or `13a`, and must say both the code and the name. Case-folded and
    otherwise literal: a grader that normalised harder would start accepting answers a reader
    would not, and the failures it would then hide are exactly the ones worth reading.
    """
    answer = normalise(record.get("answer") or "")
    if not answer:
        return False
    return all(any(present(alt, answer) for alt in group) for group in task.get("expect", []))


def grade_record(record, task, surface_names):
    """One task's outcome: was it answerable here, was it answered, and how were the tools used."""
    possible = (record.get("surface") or {}).get("client") in task.get("possible_on", [])
    calls = record.get("calls") or []
    useful = set(task.get("useful_tools", []))
    verdicts = {"useful": 0, "wasted": 0, "off_surface": 0, "refused": 0, "errored": 0,
                "unserved": 0, "harness_tool": 0}
    for call in calls:
        name = call.get("name")
        verdict = call.get("verdict")
        if verdict == "harness_tool":
            # The client's own machinery, not a pick out of this server's surface.
            verdicts["harness_tool"] += 1
            continue
        # **A call for a tool this client is not served.** Named `unserved` rather than
        # `hallucinated`, which is what it was called until the run was read properly: the
        # server sends the same `instructions` string to every client, and that string names
        # `modules`, `execute`, `decode_ioctl` and `debug_batch` whether or not the client is
        # served them. A model asking for one of those was told about it by this server. The
        # count is still worth having - it measures a real cost in wasted turns - but it is a
        # measure of the server's advertising, not of the model's imagination.
        if surface_names and name not in surface_names:
            verdicts["unserved"] += 1
        if verdict == "ok":
            verdicts["useful" if name in useful else "wasted"] += 1
        elif verdict == "refused_by_harness":
            verdicts["refused"] += 1
        elif verdict == "error":
            excerpt = (call.get("excerpt") or "").lower()
            if "not on the surface" in excerpt or "tool not found" in excerpt:
                verdicts["off_surface"] += 1
            else:
                verdicts["errored"] += 1
        else:
            verdicts["errored"] += 1
    return {
        "task": record.get("task"),
        "possible": possible,
        "correct": matches(record, task),
        "bonus": all(any(present(alt, normalise(record.get("answer") or "")) for alt in g)
                     for g in task.get("bonus", [])) if task.get("bonus") else None,
        "answered": bool(record.get("answer")),
        "gave_up": bool(record.get("gave_up")),
        "error": record.get("error"),
        "calls": len(calls),
        "result_chars": sum(c.get("chars") or 0 for c in calls),
        "first_prompt_tokens": record.get("first_prompt_tokens"),
        "wall_s": record.get("wall_s"),
        **verdicts,
    }


def records(log_path):
    """Every record in the log, **deduplicated to the last run of each (cell, draw, task)**.

    Resume works at cell granularity - an outstanding task re-runs its cell's whole list - so a
    log legitimately holds a task twice, and the second run is the one that counts. Counting
    both would inflate a cell's task count and average two runs that were never meant to be
    averaged.

    **The draw is inside the key, and that is the difference between a repeat and a re-run**
    (`FOLLOWUPS.md` item 42). Two records of one task under one draw index are the same
    measurement made twice, and the later wins; two records under different indices are two draws
    of it, and both count. Deduplicating on (cell, task) alone - which is what this did - meant n
    draws of a cell collapsed to the last one, so repeating a cell measured nothing.
    """
    latest, seen_at = {}, {}
    for at, line in enumerate(open(log_path, encoding="utf-8")):
        line = line.strip()
        if not line:
            continue
        record = json.loads(line)
        surface = (record.get("surface") or {})
        cell = (record.get("backend"), record.get("model"), record.get("num_ctx"),
                surface.get("client"), draw_of(record))
        latest[(*cell, record.get("task"))] = record
        seen_at[(*cell, record.get("task"))] = at
    # **A cell-level note is superseded by anything that cell recorded afterwards.** The note says
    # "this cell failed"; it is keyed on `task: null`, so a successful resume - which writes only
    # task records - leaves it in place and the summary goes on printing a finished cell as
    # FAILED for ever.
    #
    # *That cell* now means that draw of it, because `cell` above carries the draw index: a draw
    # that was killed is not un-killed by the next draw of the same cell running to completion
    # afterwards, which is what a draw-blind comparison here would have decided.
    for key in list(latest):
        if key[-1] is not None:
            continue
        note_at = seen_at[key]
        if any(other[:-1] == key[:-1] and other[-1] is not None and at > note_at
               for other, at in seen_at.items()):
            del latest[key]
    return list(latest.values())


def summarise(log_path, tasks_file):
    """Grade the whole log and reduce it to one row per cell, **over every draw of it**.

    A cell's row is keyed without the draw index on purpose: n draws of one cell are n samples of
    the same measurement, and a row per draw would be the grid again with a new axis rather than
    the repetition item 42 asks for. So `possible` and `correct` count draw-tasks, `draws` says
    how many draws they came from, and a rate is the two read together. `--matrix` is where the
    per-task distribution lives.
    """
    key = {t["id"]: t for t in load(tasks_file)["tasks"]}
    cells = {}
    for record in records(log_path):
        surface = (record.get("surface") or {})
        cell_id = (record.get("backend"), record.get("model"), record.get("num_ctx"),
                   surface.get("client"))
        cell = cells.setdefault(cell_id, {
            "backend": cell_id[0], "model": cell_id[1], "num_ctx": cell_id[2],
            "surface": cell_id[3], "tools": surface.get("tools"),
            "surface_bytes": surface.get("bytes"), "served_context": record.get("served_context"),
            "tasks": [], "cell_error": None, "failed_draws": 0, "uncounted": 0,
            "draw_ids": set(),
        })
        cell["draw_ids"].add(draw_of(record))
        if record.get("task") is None:
            # A cell-level note - a killed draw of this cell - rather than a task record. Counted
            # as well as kept: on a repeated cell "FAILED" alone cannot say whether one draw of
            # five died or all five did, and those are different findings.
            cell["cell_error"] = record.get("error")
            cell["failed_draws"] += 1
            continue
        if not usable(record, key.get(record.get("task"))):
            # **Not scored, at all** - counting it would publish a result under a window nobody
            # asked for, or against a question the suite no longer asks. `--matrix` marks these
            # `?`; the row says how many were dropped.
            cell["uncounted"] = cell.get("uncounted", 0) + 1
            continue
        task = key.get(record["task"])
        if task is None:
            # A log outlives the suite: a task renamed or dropped since the run should cost its
            # own row, not every row in the file.
            print(f"  skipping unknown task `{record['task']}` in the log")
            continue
        cell["tasks"].append(grade_record(record, task, surface.get("names")))
    for cell in cells.values():
        graded = cell["tasks"]
        cell["draws"] = len(cell.pop("draw_ids"))
        cell["n"] = len(graded)
        cell["possible"] = sum(1 for g in graded if g["possible"])
        cell["correct"] = sum(1 for g in graded if g["correct"])
        cell["correct_of_possible"] = sum(1 for g in graded if g["correct"] and g["possible"])
        cell["false_positive"] = sum(1 for g in graded if g["correct"] and not g["possible"])
        # Task-level: the driver could not complete the task at all.
        cell["errors"] = sum(1 for g in graded if g["error"])
        # Call-level, and kept apart from it: a tool call that failed or was fenced says
        # something about the model's picks, while a task error says the run broke. Folding the
        # two let a cell whose every call failed report no failures at all.
        cell["call_errors"] = sum(g["errored"] for g in graded)
        cell["refused"] = sum(g["refused"] for g in graded)
        cell["off_surface"] = sum(g["off_surface"] for g in graded)
        cell["unserved"] = sum(g["unserved"] for g in graded)
        cell["harness_tool"] = sum(g["harness_tool"] for g in graded)
        cell["wasted"] = sum(g["wasted"] for g in graded)
        cell["useful"] = sum(g["useful"] for g in graded)
        cell["result_chars"] = sum(g["result_chars"] or 0 for g in graded)
        cell["wall_s"] = round(sum(g["wall_s"] or 0 for g in graded))
        prompts = [g["first_prompt_tokens"] for g in graded if g["first_prompt_tokens"]]
        cell["prompt_tokens"] = (min(prompts), max(prompts)) if prompts else None
    return list(cells.values())


def print_table(cells):
    # **The draws column appears only when a cell was repeated.** Every log written before draws
    # existed has exactly one per cell - including the three this bench has published - and a
    # column of `1`s would restate a constant in every table pasted into a write-up.
    repeated = any(c.get("draws", 1) > 1 for c in cells)
    draws_head = f"{'draws':>6} " if repeated else ""
    head = (f"{'backend':<12} {'model':<28} {'ctx':>7} {'surface':<6} {'tools':>5} "
            f"{draws_head}{'ok/possible':>13} {'tokens':>13} {'calls u/w/n/r/e':>16} {'wall':>6}")
    print("\n" + head)
    print("-" * len(head))
    for c in sorted(cells, key=lambda c: (c["backend"], c["model"], -(c["num_ctx"] or 0),
                                          c["surface"] or "")):
        tokens = f"{c['prompt_tokens'][0]}-{c['prompt_tokens'][1]}" if c["prompt_tokens"] else "-"
        # **The numerator is the answerable ones.** A task this surface cannot answer, answered
        # anyway from the model's own knowledge, is counted in `correct` and not in `possible` -
        # so printing one over the other reads `6/5`. The false positives are real and are worth
        # seeing, so they travel beside the score as `+n` rather than inside it.
        extra = c["correct"] - c["correct_of_possible"]
        score = f"{c['correct_of_possible']}/{c['possible']}" + (f"+{extra}" if extra else "")
        # `x n` when more than one draw of the cell died, because on a repeated cell a bare
        # FAILED cannot tell one bad draw from a cell that never completes.
        failed = (" FAILED" + (f" x{c['failed_draws']}" if c.get("failed_draws", 0) > 1 else "")
                  if c.get("cell_error") else "")
        if c.get("uncounted"):
            # One counter for one predicate: a record can stop counting because the window it ran
            # at was not the one it asked for, or because the question has changed since. Naming
            # the row after either reason would be wrong half the time.
            failed += f" UNCOUNTED x{c['uncounted']}"
        print(f"{c['backend']:<12} {(c['model'] or '')[:28]:<28} "
              f"{str(c['num_ctx'] or 'dflt'):>7} {str(c['surface'] or '')[:6]:<6} "
              f"{str(c['tools'] or '-'):>5} "
              + (f"{c['draws']:>6} " if repeated else "")
              + f"{score} of {c['n']:<5} {tokens:>13} "
              f"{c['useful']}/{c['wasted']}/{c['unserved']}/{c['refused']}/"
              f"{c['call_errors']:<8} "
              f"{c['wall_s']:>5}s{failed}")


# The marks a cell-task can carry, in the order a distribution prints them. Fixed rather than
# sorted by count, so `3Y2n` and `2n3Y` cannot be two spellings of one result.
MARK_ORDER = "Yno-!?"


def distribution(marks):
    """One draw's mark, or a count per mark across n of them.

    **A single draw prints the bare mark**, which is what every log written before draws existed
    holds and what the legend has always described - `Y1` everywhere would be a new notation for
    an unchanged result. More than one prints `3Y2n`, which is the thing item 42 says the grid
    could not produce: a rate rather than a sighting, in a column narrow enough to scan.
    """
    if len(marks) == 1:
        return marks[0]
    counts = {}
    for mark in marks:
        counts[mark] = counts.get(mark, 0) + 1
    # Anything not in the alphabet still prints, after it: a mark this function has not been
    # taught is a bug worth seeing rather than a draw worth dropping silently.
    order = ([m for m in MARK_ORDER if m in counts]
             + sorted(m for m in counts if m not in MARK_ORDER))
    return "".join(f"{counts[m]}{m}" for m in order)


def matrix(log_path, tasks_file):
    """One row per cell, one column per task, for reading rather than for arithmetic.

    The summary table answers "how many"; this answers "which", and the two fail differently.
    A cell scoring 4 of 5 is not interesting until you know it is the same task every model
    misses - at which point the finding is about the task, or about the tool it needs, rather
    than about any of the models. It is also what the control is *for*: a task the frontier row
    misses too is a bad question, not a weak local model.

    **And with `draws: n`, it answers "how often".** Every draw of a (cell, task) lands in one
    entry - its mark, its calls and its answer kept per draw, because the interesting thing about
    a `3Y2n` is usually what the two did differently - and the printed mark becomes the
    distribution over them.
    """
    key = {t["id"]: t for t in load(tasks_file)["tasks"]}
    order = [t["id"] for t in load(tasks_file)["tasks"]]
    rows = {}
    for record in records(log_path):
        if record.get("task") is None:
            continue
        surface = record.get("surface") or {}
        row = rows.setdefault((record.get("backend"), record.get("model"), record.get("num_ctx"),
                               surface.get("client")), {})
        task = key.get(record["task"])
        if task is None:
            continue
        graded = grade_record(record, task, surface.get("names"))
        if not usable(record, key.get(record.get("task"))):
            mark = "?"
        elif graded["error"]:
            mark = "!"
        elif not graded["possible"]:
            # Marked apart whether or not the model got there: an answer to a question this
            # surface cannot reach is either knowledge or a lucky guess, and both are worth
            # seeing rather than scoring.
            mark = "o" if graded["correct"] else "-"
        else:
            mark = "Y" if graded["correct"] else "n"
        entry = row.setdefault(record["task"], {"mark": None, "draws": []})
        entry["draws"].append({"draw": draw_of(record), "seed": record.get("seed"), "mark": mark,
                               "calls": [c.get("name") for c in (record.get("calls") or [])],
                               "wall_s": record.get("wall_s"),
                               "answer": (record.get("answer") or "")[:2000],
                               "error": record.get("error")})
    for row in rows.values():
        for entry in row.values():
            entry["draws"].sort(key=lambda d: d["draw"])
            entry["mark"] = distribution([d["mark"] for d in entry["draws"]])
    return order, rows


def print_matrix(order, rows):
    # Wide enough for a distribution as well as a task name: `3Y2n` is four characters and a
    # ten-draw cell is longer still, and a column that clips one would misreport the result
    # rather than merely look untidy.
    marks = [m.get("mark") or "" for row in rows.values() for m in row.values()]
    width = max([len(t) for t in order] + [len(m) for m in marks] or [0]) + 2
    header = f"{'cell':<44}" + "".join(f"{t:<{width}}" for t in order)
    print("\n" + header)
    print("-" * len(header))
    for cell, marks in sorted(rows.items(), key=lambda kv: (kv[0][0], kv[0][1],
                                                            -(kv[0][2] or 0), kv[0][3] or "")):
        backend, model, ctx, surface = cell
        label = f"{model[:24]} {str(ctx or 'dflt'):>6} {surface}"
        print(f"{label:<44}" + "".join(f"{marks.get(t, {}).get('mark', ' '):<{width}}"
                                       for t in order))
    print("\nY correct   n wrong   - not answerable on this surface   "
          "o answered anyway   ! the runtime refused the request   "
          "? served a different window than asked for")
    if any(len(m.get("draws") or []) > 1 for row in rows.values() for m in row.values()):
        print("A repeated cell prints its distribution: `3Y2n` is five draws, three of them "
              "correct.")


def main():
    if sys.argv[1:2] == ["--matrix"]:
        log_path = sys.argv[2]
        tasks_file = sys.argv[3] if len(sys.argv) > 3 else os.path.join(HERE, "eval_tasks.json")
        order, rows = matrix(log_path, tasks_file)
        print_matrix(order, rows)
        out = os.path.splitext(log_path)[0] + ".matrix.json"
        with open(out, "w", encoding="utf-8") as f:
            json.dump({"tasks": order,
                       "rows": [{"backend": c[0], "model": c[1], "num_ctx": c[2],
                                 "surface": c[3], "marks": m} for c, m in rows.items()]},
                      f, indent=2)
        print(f"\nwrote {out}")
        return
    if sys.argv[1:2] == ["--grade"]:
        log_path = sys.argv[2]
        tasks_file = sys.argv[3] if len(sys.argv) > 3 else os.path.join(HERE, "eval_tasks.json")
        cells = summarise(log_path, tasks_file)
        print_table(cells)
        out = os.path.splitext(log_path)[0] + ".graded.json"
        with open(out, "w", encoding="utf-8") as f:
            json.dump(cells, f, indent=2)
        print(f"\nwrote {out}")
        return

    plan = load(sys.argv[1])
    # **Resolved before anything runs, because one backend does not share this cwd.** The Claude
    # cells are started in a neutral directory (see `run_cell`), so a plan naming
    # `tools/eval_tasks.json` relative to where the runner was invoked would have that child
    # looking for it under the log directory - and writing its records to a different
    # `results.jsonl` than the grader later reads. Absolute paths make the two agree whatever
    # directory a cell runs in.
    for field in ("tasks", "out", "logs"):
        if plan.get(field):
            plan[field] = os.path.abspath(plan[field])
    tokens = tokens_for(plan)
    log_path = plan["out"]
    logs_dir = plan.get("logs", os.path.join(os.path.dirname(log_path), "logs"))
    suite = cell_tasks(plan["tasks"], None)
    done = already_done(log_path, suite)
    print(f"plan {plan['run']}: {len(done)} task records already in {log_path}")

    for group in plan["cells"]:
        backend = group["backend"]
        # **`draws` repeats a cell; it does not add an axis.** A group asking for 5 runs the same
        # (model, context, surface) five times, and the grader counts over them - which is the one
        # thing the grid could not do (`FOLLOWUPS.md` item 42). Default 1, so a plan that does not
        # mention it is the grid as it was.
        draws = int(group.get("draws", 1))
        for model in group["models"]:
            for context in group.get("contexts", [None]):
                for surface in group["surfaces"]:
                    subset = group.get("subset")
                    wanted = cell_tasks(plan["tasks"], subset)
                    for draw in range(1, draws + 1):
                        outstanding = [t for t in wanted
                                       if (backend, model, context, surface, draw, t["id"])
                                       not in done]
                        if not outstanding:
                            print(f"  skipping {backend}:{model} ctx={context} {surface}"
                                  + (f" draw {draw}" if draws > 1 else "")
                                  + f": all {len(wanted)} tasks already recorded")
                            continue
                        run_cell(plan, tokens, backend, model, context, surface, draw, subset,
                                 group.get("budget_s", 1800), log_path, logs_dir)
                        done = already_done(log_path, suite)
                if backend == "ollama":
                    # **Evicted between contexts, not only between models** - and this is the
                    # one that had to be learned. `num_ctx` on a request does not shrink an
                    # instance the runtime already holds: asked for 8192 with a 32768 instance
                    # loaded, ollama serves the 32768 one and says so only in `/api/ps`. The
                    # first run of this grid recorded five cells labelled 8192 that ran at
                    # 32768; `served_context` caught it, and eviction is what prevents it.
                    # It also keeps three 30B-class models from having to co-reside.
                    evicted = subprocess.run(["ollama", "stop", model], capture_output=True,
                                             text=True)
                    if evicted.returncode:
                    # Not cosmetic: the next context's cells would be served this instance's
                    # window instead of the one they asked for, which is the 32k-served-as-8k
                    # contamination this eviction exists to prevent. The grader refuses to score a
                    # record whose served window is not the requested one, so the run cannot
                    # publish it either way - this is what says *why* those cells went missing.
                        print(f"    could not evict {model} ({evicted.returncode}): "
                              f"{evicted.stderr.strip()[:200]}\n"
                              f"    cells at the next context may be served this one's window")

    cells = summarise(log_path, plan["tasks"])
    print_table(cells)
    with open(os.path.splitext(log_path)[0] + ".graded.json", "w", encoding="utf-8") as f:
        json.dump(cells, f, indent=2)


if __name__ == "__main__":
    main()
