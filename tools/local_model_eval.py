#!/usr/bin/env python3
"""Run the model x tool-surface x context matrix against this server, and grade it.

`local_model_drive.py` answers "can *a* model drive this?" for one model, one surface and
whatever window the runtime happened to serve. This runs that script across a grid and grades
what comes back against the answer key in `tools/eval_tasks.json`, so the question becomes
"which of these knobs actually decides whether a model can drive this?".

    EVAL_TOKENS=<tokens.json> python3 tools/local_model_eval.py <plan.json>
    python3 tools/local_model_eval.py --grade  <results.jsonl> [tasks.json]
    python3 tools/local_model_eval.py --matrix <results.jsonl> [tasks.json]
    WINDBG_MCP_TOKEN=<token> python3 tools/local_model_eval.py --verify-key [tasks.json]

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

**The key is a snapshot, and `--verify-key` is what re-takes it.** The six tasks are graded
against facts read off the checked-in dumps with this server's own tools, so a fact that stops
being what the server reports leaves the suite grading, every model scoring, and the number
measuring nothing - a key that has rotted looks exactly like a model that got worse. That mode
re-reads every fact through the tools a model would call, against a per-task binding of
`(tool, arguments)` to the values expected back. It needs a credential and a live server, which
is why it is a command rather than a CI gate (`FOLLOWUPS.md` item 45).

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


def stale_prompt(record, task):
    """Whether this record answers a question the suite no longer asks.

    Split out of [`usable`] rather than restated inside it, so the comparison that decides a
    record's fate keeps one home *and* the grader can say which of `usable`'s two reasons dropped
    a record. Rewording a task un-grades every answer to the old wording, which is right for a
    resume and is a footgun when re-grading a log that was published against it - the denominator
    shrinks and the row says only `UNCOUNTED`. `tools/eval_tasks_v1.json` is the suite frozen at
    the wording the logs on disk were run against, and each checked-in plan names the one its own
    log belongs to.
    """
    return bool(task is not None and record.get("prompt")
                and record["prompt"] != task.get("prompt"))


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
    if stale_prompt(record, task):
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


def run_cell(plan, tokens, backend, model, context, surface, draw, subset, planned, budget_s,
             log_path, logs_dir):
    """One (backend, model, context, surface, draw) cell: a driver process over the task list.

    `planned` is the ids this draw was asked to run, and it exists to travel into the cell-level
    note: a draw that dies leaves nothing else behind, and without the list a task **no** draw ever
    reached is indistinguishable in the log from one the cell was never asked (a group's `subset`).
    The grader cannot recover that, so the runner records it.
    """
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
                    "task": None, "planned": planned,
                    "error": f"cell exceeded its {budget_s}s budget"}
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
                "task": None, "planned": planned,
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


# --------------------------------------------------------------------------------------------
# `--verify-key`: whether the server still answers what the suite grades models against.
#
# The suite is mechanical because its facts were read off the checked-in dumps with this server's
# own tools before any model saw them (`FOLLOWUPS.md` item 45). That is also the whole exposure:
# if one of those facts stops being what the server reports, the suite goes on grading, every
# model goes on scoring, and a key that has rotted is indistinguishable from a model that got
# worse. This is the check that tells them apart.
#
# **It lives here rather than in `tests/mcp_smoke.rs`, and that was the decision.** The oracle is
# `present()` a hundred lines up - hex boundaries, leading zeros, separators, each rule learned
# from a wrong verdict - so a Rust gate would need a second copy of it, and two copies drifting
# apart is this item's own failure mode reached through this item's own fix. The Rust tier keeps
# pinning what it already pins (`DRIVER_CRASHES`, `NATIVE_SAMPLE`: the bug checks, `Arg1`, the
# crashing process, each driver crash's `module`+`rva`); this pins what the *tasks* depend on,
# through the tools a model would call. The cost of the choice is that CI cannot run it - CI has
# no listener and no credential - so it is a command to run when a dependency, a symbol path or a
# sample moves, and `--verify-key` says so on every run.
#
# **The binding carries the inputs, not only the expectations.** `expect` says what an answer must
# contain and nothing structured said what to *call* to get it: a task's dump path lived only in
# its prose prompt and `useful_tools` names tools with no arguments and no order. So a task
# pointed at a different sample would have left a verifier querying the old one and matching
# expectations that never changed - green, and drifted. Each task now carries `verify`, an ordered
# list of `(tool, args)` steps with the values expected back, and [`prompt_renders_binding`]
# asserts the prompt is a rendering of it rather than its only home.
# --------------------------------------------------------------------------------------------

# Why a step stands down, keyed by what it asked for. The line this draws is not redrawn here:
# `docs/smoke-test.md` has which reads survive a host whose engine resolves no symbols, which do
# not, and the measurement behind the distinction. Keeping a second copy of it cost three review
# rounds on #221, so this table holds the *reason a step prints*, and that document holds the rule.
GATES = {
    "kernel_symbols": "`nt` resolved no PDB on this host, so a stack walk has no types to read "
                      "and gives back frames made of the bug check's own parameters (issue #142). "
                      "The facts behind this step are asserted through their other route.",
}

# The whole text of a result rather than a field of it, for a tool that has no structured half.
# `decode_ioctl` is the only one the suite calls that answers in prose alone, and it is also the
# one task needing no target at all - so the pure-tool fixture and the untyped answer are the same
# tool, and a `read` that could only name a field would have had nothing to say about it.
WHOLE_TEXT = "@text"


def field(result, path):
    """One `read` path into a result — dotted, with two ways of entering a list.

    An integer segment indexes it, and `name=pc` selects the first element whose `name` is `pc`.
    The second exists because **a position in a list is usually not the fact**: the `pc` register
    is entry 32 of the ARM64 bank, and pinning 32 would fail on an engine that reordered the bank
    while still answering the question the task asks. What the key rests on is that the register
    *called* `pc` holds that value, and this is how a pin says so.

    Raises `KeyError` naming the path that ran out rather than returning a default, because a
    field that has *moved* is exactly the drift this mode exists to catch: a pin that quietly
    read `None` and compared it against `None` would pass on a server that had stopped answering
    at all.
    """
    cursor = result
    for segment in path.split("."):
        if isinstance(cursor, list):
            if "=" in segment:
                key, _, want = segment.partition("=")
                match = next((e for e in cursor
                              if isinstance(e, dict) and str(e.get(key)) == want), None)
                if match is None:
                    raise KeyError(path)
                cursor = match
                continue
            if not segment.isdigit() or int(segment) >= len(cursor):
                raise KeyError(path)
            cursor = cursor[int(segment)]
        elif isinstance(cursor, dict) and segment in cursor:
            cursor = cursor[segment]
        else:
            raise KeyError(path)
    return cursor


def rendered(value):
    """A pinned value as `present()` would have to read it — the grader's own normalisation.

    Shared with the grading path deliberately: a pin is only evidence about the key if the string
    it is checked as is the string a model's answer would be checked as.
    """
    return normalise(value if isinstance(value, str) else json.dumps(value))


def prompt_renders_binding(task):
    """Whether the question still asks for what the binding fetches. Returns the complaints.

    **Both directions, because they rot differently.** Every string this task's steps *send* has
    to appear in the prompt, so a binding repointed at another sample cannot go on being described
    by the old question; and every `.dmp` the prompt names has to be one some step opens, so a
    question repointed at another sample cannot go on being verified against the old one. Numbers
    and booleans are excluded — `frames: 3` is how this asks, not what it asks about — and so is
    the session placeholder, which names nothing outside the run.
    """
    prompt = (task.get("prompt") or "").lower()
    complaints = []
    sent = []
    for step in task.get("verify") or []:
        for name, value in (step.get("args") or {}).items():
            if not isinstance(value, str) or value.startswith("$"):
                continue
            sent.append(value)
            if value.lower() not in prompt:
                complaints.append(f"the binding sends {name}={value!r}, which the prompt "
                                  f"never names")
    for named in re.findall(r"[^\s,;]+\.dmp", prompt, flags=re.IGNORECASE):
        if not any(named.lower() == s.lower() for s in sent):
            complaints.append(f"the prompt names {named}, which no step of the binding opens")
    return complaints


def gates_open(drive, session_id):
    """Which of [`GATES`] this **session's target** satisfies, asked of the engine, not assumed.

    One probe today, and it is the one the suite needs: whether `nt` resolved to a **PDB**, which
    is what a walk through its types needs. `tests/mcp_smoke.rs` asks the same question the same
    way (`engine_resolves_kernel_symbols`), and both PDB-backed states count — `dia` is the same
    PDB read through another API, and the server treats them alike.

    **Per dump, not per host, and this repo has the measurement.** Each sample has its own `nt` with
    its own PDB identity, so a host can resolve one and not another: `docs/smoke-test.md` records an
    engine that "fails *differently per dump*" — the ARM64 sample reading nothing while the x64 one
    gave up a module base. A gate taken once off the first opener and reused would therefore stand
    the ARM64 frame-0 step down because an *x64* PDB was missing, and report success without having
    checked the route `arm64_pc`'s `possible_on: min` rests on. The Rust tier asks per session for
    the same reason; so does this.
    """
    out = drive.mcp("tools/call", {"name": "modules",
                                   "arguments": {"session_id": session_id, "filter": "nt"}})
    modules = ((out.get("result") or {}).get("structuredContent") or {}).get("modules") or []
    nt = next((m for m in modules if m.get("name") == "nt"), None)
    return {"kernel_symbols": bool(nt and nt.get("symbols") in ("pdb", "dia"))}


def run_step(drive, step, session_id):
    """One step of a binding: call the tool, hand back the whole result and what went wrong.

    Returns `(result, text, error)`. A tool that fails is an `error` rather than an exception,
    because the interesting failure here is a *fact* that has moved and the run must reach the rest
    of the task's pins to say which.

    **The result comes back even when the call failed**, which is not tidiness: an opener can
    register a session and *then* fail, and the only handle that can reach that target is in
    `structuredContent.error.session_id`. Discarding it left the caller unable to release a worker
    holding a dump — and repeated runs against the same drift would then meet the four-session cap
    instead of reporting the drift. `local_model_drive.opened_session` already reads both places
    that handle can be, so the caller uses it rather than a second copy of the rule.
    """
    args = {k: (session_id if v == "$session" else v)
            for k, v in (step.get("args") or {}).items()}
    try:
        out = drive.mcp("tools/call", {"name": step["tool"], "arguments": args})
    except Exception as e:  # noqa: BLE001 - a transport failure is this step's result
        return {}, "", f"transport error: {e}"
    if "error" in out:
        return {}, "", f"protocol error: {json.dumps(out['error'])[:200]}"
    result = out.get("result") or {}
    text = "\n".join(block.get("text") or "" for block in (result.get("content") or [])
                     if block.get("type") == "text")
    return result, text, f"the tool refused: {text[:200]}" if result.get("isError") else None


def check_pins(step, structured, text):
    """Every pin of one step, as `(read, ok, detail, rendered_value)` rows.

    **Two verbs, and the difference is the server's own doing.** `is` is exact typed equality
    against a named field — the strong pin, and what a structured answer allows: `227` the integer
    is not `"227"` the string, and a field renamed is a `KeyError` rather than a pass. `has` is
    [`present`] over the rendered text, for a tool with no structured half to name a field in; it
    is weaker on purpose and is used exactly once, which is once more than nothing would be.

    A `has` value is normalised as well as the text, which `matches()` does not do to an `expect`
    alternative — the asymmetry is deliberate and narrow. A pin asks "does the server still print
    this", so both sides being spelled the same way is what makes it answerable; the tie back to
    *grading* is [`grounding`], and that one compares a raw alternative against a normalised value
    exactly as `matches()` does.
    """
    rows = []
    for pin in step.get("pin") or []:
        read = pin.get("read")
        if "has" in pin:
            want = pin["has"]
            haystack = normalise(text) if read == WHOLE_TEXT else None
            if haystack is None:
                rows.append((read, False, f"`has` reads {WHOLE_TEXT} and nothing else", None))
                continue
            ok = present(normalise(want), haystack)
            rows.append((f"{read} has {want!r}", ok,
                         "" if ok else "not in the answer's text", want))
            continue
        try:
            got = field(structured, read)
        except KeyError:
            rows.append((read, False, "no such field in the answer", None))
            continue
        ok = got == pin["is"]
        rows.append((read, ok, "" if ok else f"answered {got!r}, pinned {pin['is']!r}", got))
    return rows


def grounding(task, pinned_by_step, ran):
    """How each `expect` group is tied to the facts this task pinned, and what is missing.

    Two ways a step may claim a group, and **the difference is declared rather than inferred**:

    - **`grounds`** — the group is answered by a value the server prints, checked through
      [`present`], the same oracle that decides pass or fail. A claimed group nothing renders is a
      **failure**. Inferring this instead was a hole: a group edited to a value the server does not
      say (`ACCESS_VIOLATION` for a bug check that is `KERNEL_MODE_HEAP_CORRUPTION`) simply
      reported "relation" and passed, which is a broken key reached through the very mode meant to
      catch one.
    - **`states`** — the group is a phrasing of a *relation* over the pinned facts rather than a
      string the server prints: `unloaded_driver`'s "not loaded" is what `matched: 0` *means*. That
      is not a hole either, because the fact behind it is pinned exactly and only the phrasing is
      beyond a mechanical check — but it has to be **declared per group**, so the exemption covers
      the two groups that earn it and cannot silently spread to the rest.

    A group whose claiming steps all stood down at a gate is `skipped`, which has to be its own
    word: reporting it as anything else would say this host checked something it did not.

    And a group **no** step claims at all is the failure that makes this a ratchet: `expect` cannot
    grow an alternative the binding does not fetch, and a new task cannot arrive unpinned.
    """
    expect = task.get("expect") or []
    claimed = {}
    for index, step in enumerate(task.get("verify") or []):
        for kind in ("grounds", "states"):
            for group in step.get(kind) or []:
                if not isinstance(group, int) or not 0 <= group < len(expect):
                    return None, [f"step {index + 1} {kind} group {group}, "
                                  f"which `expect` has not got"]
                entry = claimed.setdefault(group, {"values": [], "value_ran": False,
                                                   "relation_ran": False})
                if kind == "states":
                    entry["relation_ran"] = entry["relation_ran"] or index in ran
                    continue
                entry["value_ran"] = entry["value_ran"] or index in ran
                if index in ran:
                    entry["values"].extend(pinned_by_step.get(index, []))
    missing = [i for i in range(len(expect)) if i not in claimed]
    if missing:
        return None, [f"`expect` group {i} ({'|'.join(expect[i])}) is grounded by no step"
                      for i in missing]
    how, failures = {}, []
    for group, entry in sorted(claimed.items()):
        if entry["value_ran"]:
            if any(present(alt, value) for alt in expect[group] for value in entry["values"]):
                how[group] = "value"
            else:
                # The key says one thing and the server another. Named as the key's problem, since
                # the pins themselves all held: this is what the group was edited to, against what
                # the tools actually answer.
                failures.append(f"`expect` group {group} ({'|'.join(expect[group])}) is in nothing "
                                f"this task pinned - the server answers "
                                f"{', '.join(sorted(set(entry['values']))) or '(nothing)'}")
        elif entry["relation_ran"]:
            how[group] = "relation"
        else:
            how[group] = "skipped"
    return how, failures


def verify_task(drive, task):
    """One task's binding, against the live server. Returns `(failures, notes)`.

    Opens its own target rather than inheriting a session, which is not tidiness: `crash_triage`'s
    stack is the crash context on a *freshly opened* dump and otherwise whatever the session has
    selected, and the `arm64_pc` fact is read off frame 0.

    The gate is probed on **this task's own session**, once and only if a step needs it — see
    [`gates_open`] for why it cannot be a property of the host.
    """
    failures, notes, session_id = [], [], None
    pinned_by_step, ran, gates = {}, set(), None
    failures.extend(prompt_renders_binding(task))
    try:
        for index, step in enumerate(task.get("verify") or []):
            need = step.get("needs")
            if need:
                if gates is None and session_id:
                    gates = gates_open(drive, session_id)
                    notes.extend(f"    gate {name}: {'open' if open_ else 'closed'}"
                                 for name, open_ in sorted(gates.items()))
                if not (gates or {}).get(need):
                    notes.append(f"    SKIPPED {step['tool']}: {GATES[need]}")
                    continue
            result, text, error = run_step(drive, step, session_id)
            if step.get("session") == "open":
                # **Read before the error is acted on**, through the driver's own helper: an opener
                # that registered a session and then failed reports the only handle that can reach
                # it inside the error, and dropping it leaves a worker holding a dump.
                session_id = drive.opened_session(result) or session_id
            if error:
                failures.append(f"{step['tool']}: {error}")
                continue
            if step.get("session") == "open" and not session_id:
                failures.append(f"{step['tool']}: opened no session to route the rest to")
                break
            ran.add(index)
            pinned = []
            for read, ok, detail, value in check_pins(step, result.get("structuredContent") or {},
                                                      text):
                if ok:
                    pinned.append(rendered(value))
                else:
                    failures.append(f"{step['tool']} {read}: {detail}")
            pinned_by_step[index] = pinned
    finally:
        if session_id:
            drive.end_sessions([session_id])
    how, gaps = grounding(task, pinned_by_step, ran)
    failures.extend(gaps)
    if how:
        by_kind = {}
        for group, kind in sorted(how.items()):
            by_kind.setdefault(kind, []).append(str(group))
        notes.append("    grounds " + ", ".join(f"{kind}: {', '.join(groups)}"
                                                for kind, groups in sorted(by_kind.items())))
    return failures, notes


def verify_key(tasks_file):
    """Re-read the suite's answer key off the dumps, through the tools a model would call.

    **Imported here rather than at the top of the file**, because `local_model_drive` resolves a
    bearer token as it loads and exits if there is none — which is right for a driver and would
    make `--grade` unusable on a machine that is only reading a log.
    """
    sys.path.insert(0, HERE)
    import local_model_drive as drive  # noqa: PLC0415 - see the docstring

    suite = load(tasks_file)
    tasks = suite["tasks"]
    print(f"verifying {suite.get('suite', tasks_file)} against {drive.MCP_URL}")
    print("MCP revision negotiated:", drive.handshake())
    try:
        return verify_against(drive, suite, tasks)
    finally:
        # **The transport session is this run's too.** The revision spoken here mints an
        # `Mcp-Session-Id`, and a run that simply stops leaves it resident until a whole grace
        # passes with no traffic - so repeated verifications on one credential pile them up, each
        # new request renewing the lease that would have swept them. Every path closes it,
        # including the surface refusal below, which happens after the handshake.
        drive.close_transport_session()


def verify_against(drive, suite, tasks):
    """The verification itself, inside the caller's transport cleanup. Returns an exit code."""
    served = {t["name"] for t in drive.mcp("tools/list")["result"]["tools"]}
    wanted = {step["tool"] for t in tasks for step in t.get("verify") or []}
    if wanted - served:
        raise SystemExit(f"this credential is not served {', '.join(sorted(wanted - served))}; "
                         "verifying the key needs the whole surface, not a narrowed one")

    unpinned = [t["id"] for t in tasks if not t.get("verify")]
    if unpinned:
        # **A task with no binding is the hole this mode exists to close**, so it fails rather
        # than being skipped quietly: an unpinned task is one whose facts nothing re-reads, which
        # is the state the whole suite was in before this existed.
        print(f"\nFAILED: {', '.join(unpinned)} carry no `verify` binding, so nothing re-reads "
              f"the facts they are graded against")
        return 1

    failed = {}
    for task in tasks:
        print(f"\n  {task['id']}")
        failures, notes = verify_task(drive, task)
        for note in notes:
            print(note)
        for failure in failures:
            print(f"    FAILED {failure}")
        if failures:
            failed[task["id"]] = failures

    # **Which corpus was asserted, said rather than implied.** `answer_key` is prose and nothing
    # reads it — not this mode, and not `matches()`, which grades from `expect` alone. The two
    # disagree by construction: the key describes the sample corpus and the tasks reference part
    # of it, so a line naming the gap is the honest form of "which corpus is this about".
    opened = {step["args"]["path"].rsplit("\\", 1)[-1]
              for t in tasks for step in t["verify"] if "path" in (step.get("args") or {})}
    documented = set(suite.get("answer_key") or {})
    uncovered = sorted(k for k in documented if k.endswith(".dmp") and k not in opened)
    print(f"\ncorpus: {len(opened)} dump(s) re-read - {', '.join(sorted(opened))}")
    if uncovered:
        print(f"  `answer_key` also documents {', '.join(uncovered)}, which no task references "
              f"and this mode therefore does not assert")
    if failed:
        print(f"\nFAILED: {len(failed)} task(s) are graded against a fact this server no longer "
              f"reports - {', '.join(sorted(failed))}")
        return 1
    print(f"\nOK: every fact {len(tasks)} tasks are graded against still reads off the dumps. "
          f"CI does not run this - re-run it after a win-kexp bump, a symbol-path change or a "
          f"new sample.")
    return 0


def grade_record(record, task, surface_names):
    """One task's outcome: was it answerable here, was it answered, and how were the tools used."""
    possible = (record.get("surface") or {}).get("client") in task.get("possible_on", [])
    calls = record.get("calls") or []
    useful = set(task.get("useful_tools", []))
    verdicts = {"useful": 0, "wasted": 0, "off_surface": 0, "refused": 0, "errored": 0,
                "unserved": 0, "taught": 0, "wanted": 0, "harness_tool": 0}
    taught_tools = []
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
        #
        # **And it is two measurements, split here by whether the task needed the reach**
        # (item 43). `possible` says the answer key is reachable on this surface, so:
        #
        # - `wanted`: the task is *not* answerable here and the model reached for the capability
        #   that would answer it. That is the model being right and the surface saying no; it can
        #   grow without anything being wrong, and a floor of it is a property of the task list.
        # - `taught`: the task *was* answerable here, so nothing about the question required a
        #   name off this surface - the model got it from somewhere, and this server is the
        #   likeliest somewhere. A regression here is a defect in the server.
        #
        # Summed they hide each other, which is what item 43 was written about: the first fix
        # taking `taught` to zero read as a 57% improvement rather than an elimination.
        #
        # **What the split attributes is need, not provenance**, and #217 is why that has to be
        # said. This server taught `modules` through an opener's *result* for as long as the
        # summary named it - on `unloaded_driver`, which is also a task `min` cannot answer, so
        # those calls land in `wanted`. `taught` is therefore a lower bound on advertising and
        # `wanted` an upper bound on need. What separates them properly is one cell repeated with
        # the sentence varied, which is the `draws` machinery beside this and not a column.
        if surface_names and name not in surface_names:
            verdicts["unserved"] += 1
            verdicts["taught" if possible else "wanted"] += 1
            if possible:
                # The names, not just the count: "taught 3" is a number to argue about, while
                # "`modules` on `bugcheck_code`" is a sentence somebody can go and check against
                # the surface that client was served.
                taught_tools.append(name)
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
        "taught_tools": sorted(set(taught_tools)),
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
            "stale_prompt": 0,
            "draw_ids": set(),
        })
        cell["draw_ids"].add(draw_of(record))
        # **Filled in by whichever record first carries it, not by whichever record comes first.**
        # A draw that died writes a note naming only its client, and with `draws` a dead draw 1
        # followed by live ones is ordinary rather than exotic - so a `setdefault` alone froze
        # `tools`, `surface_bytes` and `served_context` at that note's nulls, and the row printed
        # a cell's tool count as `-` while the graded JSON lost the window every later draw ran at.
        for field, value in (("tools", surface.get("tools")),
                             ("surface_bytes", surface.get("bytes")),
                             ("served_context", record.get("served_context"))):
            if cell[field] is None and value is not None:
                cell[field] = value
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
            if stale_prompt(record, key.get(record.get("task"))):
                cell["stale_prompt"] = cell.get("stale_prompt", 0) + 1
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
        cell["taught"] = sum(g["taught"] for g in graded)
        cell["wanted"] = sum(g["wanted"] for g in graded)
        cell["taught_detail"] = sorted({(g["task"], tool) for g in graded
                                        for tool in g["taught_tools"]})
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
            f"{draws_head}{'ok/possible':>13} {'tokens':>13} {'calls u/w/t+n/r/e':>18} "
            f"{'wall':>6}")
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
        # Counted when more than one draw of the cell died, because on a repeated cell a bare
        # FAILED cannot tell one bad draw from a cell that never completes. Spelled out rather
        # than `x2`, since `x` is a *mark* in the matrix beside this and one letter should not be
        # two notations.
        failed = (" FAILED" + (f" on {c['failed_draws']} draws" if c.get("failed_draws", 0) > 1
                               else "") if c.get("cell_error") else "")
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
              # `t+n` in the slot that used to hold one number: the sum is still readable at a
              # glance, and the halves no longer hide each other (item 43).
              f"{c['useful']}/{c['wasted']}/{c['taught']}+{c['wanted']}/{c['refused']}/"
              f"{c['call_errors']:<8} "
              f"{c['wall_s']:>5}s{failed}")
    stale = sum(c.get("stale_prompt", 0) for c in cells)
    if stale:
        # **The one uncounted reason a reader can act on.** A served window that was not the one
        # asked for is a property of the run and nothing recovers it; a changed question is a
        # property of *which suite this log is being graded against*, and grading it against the
        # one it ran on gives every record back.
        print(f"\n  {stale} record(s) answer a question this suite no longer asks and are "
              f"uncounted above.\n  Grade a published log against the suite it ran on - each "
              f"plan in tools/ names its own\n  (tools/eval_tasks_v1.json for the logs this "
              f"bench has published).")
    print_taught(cells)


def print_taught(cells):
    """The `taught` half, named rather than counted - and its absence stated rather than implied.

    A column of zeroes is indistinguishable from a column nobody looked at, which is the failure
    this whole item came out of: the scan that reported a clean result had compared nothing. So
    this line prints either the offenders or the sentence that says there were none.
    """
    offenders = [(cell, task, tool) for cell in cells
                 for task, tool in cell.get("taught_detail", [])]
    if not offenders:
        print("\ntaught: none - every off-surface call was on a task this surface cannot answer")
        return
    print(f"\ntaught: {sum(c['taught'] for c in cells)} call(s) naming a tool off the surface on "
          f"a task that surface *can* answer -")
    for cell, task, tool in offenders:
        print(f"  {(cell['surface'] or '?'):<6} {(cell['model'] or '?')[:28]:<28} "
              f"{task:<18} {tool}")


# The marks a cell-task can carry, in the order a distribution prints them. Fixed rather than
# sorted by count, so `3Y2n` and `2n3Y` cannot be two spellings of one result.
MARK_ORDER = "Yno-!?x"


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

    **A draw that recorded nothing is still one of the draws** (`x`), which is the denominator
    this would otherwise lose: a cell killed on draw 1 writes a note and no task record, so
    building each distribution from the surviving records alone printed a bare `Y` for "one draw
    died, one passed" - indistinguishable from a single clean draw, and understating the sample
    exactly the way item 42 is about.
    """
    key = {t["id"]: t for t in load(tasks_file)["tasks"]}
    order = [t["id"] for t in load(tasks_file)["tasks"]]
    rows = {}
    # **Only a draw that *died* can leave a task unrecorded**, which is what makes the notes the
    # whole story here: a draw that completed wrote every task it was asked, so one it has no
    # record for was never on its list - a cell group's `subset`, not a failure. Reading a
    # missing record as a dead draw put `x` on tasks a successful subset draw had deliberately
    # skipped, which corrupts the very denominator this exists to keep.
    dead = {}
    for record in records(log_path):
        surface = record.get("surface") or {}
        cell_id = (record.get("backend"), record.get("model"), record.get("num_ctx"),
                   surface.get("client"))
        if record.get("task") is None:
            dead.setdefault(cell_id, {})[draw_of(record)] = {
                "planned": record.get("planned"), "error": record.get("error")}
            # **A task that *no* draw reached still belongs in the row**, and the note is the only
            # place its name survives. Seeded from the note's own `planned` list rather than from
            # the suite: a cell group may run a `subset`, and from the log alone "the subset left
            # this task out" and "every draw died before reaching it" look identical - so filling
            # from `order` would invent a denominator instead of restoring one. A note written
            # before this field existed carries nothing, and those cells read as they did.
            for planned in record.get("planned") or []:
                if key.get(planned) is not None:
                    rows.setdefault(cell_id, {}).setdefault(planned, {"mark": None, "draws": []})
            continue

        row = rows.setdefault(cell_id, {})
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
    for cell_id, row in rows.items():
        for task_id, entry in row.items():
            recorded = {d["draw"] for d in entry["draws"]}
            for draw, note in dead.get(cell_id, {}).items():
                if draw in recorded:
                    continue
                if note["planned"] is not None and task_id not in note["planned"]:
                    # That draw was never going to run this task, so its death says nothing about
                    # it. One full-suite draw beside five `subset` ones shares a cell id with
                    # them, and without this every task outside the subset read `1Y5x`.
                    continue
                entry["draws"].append({"draw": draw, "seed": None, "mark": "x", "calls": [],
                                       "wall_s": None, "answer": "", "error": note["error"]})
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
    entries = [m for row in rows.values() for m in row.values()]
    if any(len(m.get("draws") or []) > 1 for m in entries):
        print("A repeated cell prints its distribution: `3Y2n` is five draws, three of them "
              "correct.")
    if any(d["mark"] == "x" for m in entries for d in m.get("draws") or []):
        print("x   the draw recorded nothing for this task - its cell died first, and it counts "
              "in the denominator")


def main():
    if sys.argv[1:2] == ["--verify-key"]:
        # No log to read: this mode asks the *server*, not a run of it. The tasks file is the
        # only positional, and it defaults to the suite in use rather than to a frozen one -
        # `eval_tasks_v1.json` is the wording published logs were graded against and carries no
        # binding, which this refuses by name rather than by skipping it.
        rest = [a for a in sys.argv[2:] if not a.startswith("--")]
        tasks_file = rest[0] if rest else os.path.join(HERE, "eval_tasks.json")
        sys.exit(verify_key(tasks_file))
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
        # **The flag is filtered out before the positionals are read**, since the tasks file is
        # argv[3] and a flag sitting there would be opened as one.
        rest = [a for a in sys.argv[2:] if not a.startswith("--")]
        strict = "--assert-no-taught" in sys.argv[2:]
        log_path = rest[0]
        tasks_file = rest[1] if len(rest) > 1 else os.path.join(HERE, "eval_tasks.json")
        cells = summarise(log_path, tasks_file)
        print_table(cells)
        # The regression item 43 asked for, opt-in so an ordinary grading run still just prints.
        # `wanted` is deliberately not assertable: it is a property of the task list and the
        # surface, and a floor of it is what a narrowed surface *is*.
        if strict and any(c["taught"] for c in cells):
            print("\nFAILED: this server named a tool the client could not call")
            sys.exit(1)
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
                                 [t["id"] for t in wanted], group.get("budget_s", 1800),
                                 log_path, logs_dir)
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
