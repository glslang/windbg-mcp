#!/usr/bin/env python3
"""Drive windbg-mcp from a local model through the ollama server API.

The point of this script is that the local-model plane needs no interactive
harness: it speaks MCP over HTTP to a `--listen` server and hands the whole tool
surface to `POST /api/chat`, so "can a local model drive this?" is a question
with a repeatable answer rather than an impression from a chat session.

    python3 tools/local_model_drive.py [tasks.json]

`tasks.json` is a list of strings, one per task; without it, one default task
runs. See `docs/local-model.md` for what to make of the numbers it prints.

`WINDBG_MCP_TOKEN` is **required, and must be a credential of this run's own** — not
the one your editor is registered with. A shared credential is a shared namespace:
this run would see, route to and (at the four-session cap) cause the reclamation of
the editor's targets, and no fence inside a script can prevent the last of those.
The script cannot tell one token from another, so this is the operator's to get
right; `docs/local-model.md` has the listener side of it.

Configuration:

    WINDBG_MCP_TOKEN    bearer token for a client of this run's own — required
    LOCAL_MODEL         ollama model tag       (default: the first tool-capable one)
    OLLAMA_URL          ollama chat endpoint   (default: http://localhost:11434/api/chat)
    WINDBG_MCP_URL      the listener           (default: http://127.0.0.1:8765/)
    RESULT_LIMIT        truncate tool results to this many characters before the
                        model sees them; `0`, the default, passes them whole
    WINDBG_MCP_SCENARIO treat the task list as one continuing investigation: one
                        transcript and one set of sessions across every task, rather
                        than a conversation and a target apiece
    WINDBG_MCP_KEEPALIVE  seconds of silence after which this run pings the listener to
                        keep its lease alive (default 120; `0` disables) — see below
    NUM_CTX             context window to serve this run at, in tokens; empty means
                        whatever `OLLAMA_CONTEXT_LENGTH` already decides. This is the
                        eval's context axis — see `chat`
    OLLAMA_KEEP_ALIVE   how long the runtime keeps the model resident after a request
                        (default `10m`); `0` evicts it, which is what frees the box
                        between one model's cells and the next
    WINDBG_MCP_EVAL_OUT a file to append one JSON record per task to, for
                        `local_model_eval.py` to grade. Without it this script prints
                        and keeps nothing, which is what it did before the eval existed
    MAX_STEPS           tool-calling turns a task may take before it is given up on
                        (default 6)

**Why the keepalive exists.** The listener releases a client's sessions when its lease
runs out, and the grace is derived from how long a *call* may take, on the assumption
that the server is the slow party. Driving a local model inverts that: a turn is the
model thinking, with no request in flight, and one measured here took **440s against a
390s grace** — so the sweep released the session mid-investigation and every later call
came back `404 Session not found`, which reads exactly like a broken server. A ping
during a long turn costs nothing and removes the whole class.
"""
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request

MCP_URL = os.environ.get("WINDBG_MCP_URL", "http://127.0.0.1:8765/")
OLLAMA = os.environ.get("OLLAMA_URL", "http://localhost:11434/api/chat")
MODEL = os.environ.get("LOCAL_MODEL", "")
NUM_CTX = int(os.environ.get("NUM_CTX", "0") or 0)
KEEP_ALIVE = os.environ.get("OLLAMA_KEEP_ALIVE", "10m")
EVAL_OUT = os.environ.get("WINDBG_MCP_EVAL_OUT", "")
REVISION = "2025-06-18"

# Tool calls this harness will actually execute. Everything else is reported back
# to the model as refused, so a wrong pick is *measured* rather than performed —
# the surface includes `launch` and `execute`, and a debug host is the wrong place
# to find out what a model does with them unattended.
#
# `end_session` is the one destructive member, and it is fenced to sessions this run
# opened: the rest of the namespace belongs to a run that crashed before its cleanup,
# or to one running beside this one.
ALLOWED = {
    "open_dump", "open_trace", "crash_triage", "backtrace", "modules", "registers",
    "threads", "session_status", "end_session", "decode_ioctl", "disassemble",
    "read_memory", "server_log",
}

MAX_STEPS = int(os.environ.get("MAX_STEPS", "6"))

# The debug sessions this run opened, which are the only ones it may end — and the
# ones it ends on the way out, so a run does not leave a worker holding a target for
# the lease grace and the next run does not adopt it.
OPENED = []

# Sessions this credential already had when the run started — a prior run that
# crashed before its cleanup, or another invocation sharing the token. They are not
# this run's to adopt and not its to release, so reconciliation skips them.
PRE_EXISTING = set()

# The tools that can *create* a session, and so the only ones whose answers name a
# handle this run is responsible for.
OPENERS = {"open_dump", "open_trace"}


def opened_session(result):
    """The handle an opener created, from the answer's own field — never from its prose.

    `structuredContent.session_id` on success, `structuredContent.error.session_id`
    on a failure, which is where an opener that created a target and *then* failed
    reports the only handle that can reach it.

    Reading the text instead is wrong twice over, and both ways end with this run
    terminating sessions it does not own: `session_status` and `server_log` name the
    whole client's sessions, and an opener refused at the four-session cap lists every
    live handle in its own error message (`Sessions::take_slot`). The structured field
    is the server's answer to "which session is this about"; the prose is not.
    """
    structured = result.get("structuredContent") or {}
    return structured.get("session_id") or (structured.get("error") or {}).get("session_id")
# Results reach the model **whole** by default. Truncating them would quietly defeat
# one of the things this harness exists to measure — whether a single answer fits a
# local model's window — and would have it reason from JSON cut off mid-structure
# without being told. A cap is available for a deliberately clamped run, and says so
# in the transcript when it bites.
RESULT_LIMIT = int(os.environ.get("RESULT_LIMIT", "0"))


def bearer():
    """The token this run authenticates with, which it does not go looking for.

    Reading it from whatever the editor is registered with was the earlier
    behaviour, and it is what six rounds of review were about: it put this run in
    the editor's namespace, where opening a session can reclaim the editor's idle
    one and no fence in this file can see it happen. Requiring the operator to name
    a credential deletes that class rather than defending against it.
    """
    token = os.environ.get("WINDBG_MCP_TOKEN", "").strip()
    if not token:
        raise SystemExit(
            "set WINDBG_MCP_TOKEN to a bearer token for a client of this run's own — not the one "
            "your editor uses, since a shared credential is a shared namespace. Configure one with "
            "WINDBG_MCP_LISTEN_TOKEN_DRIVER on a foreground listener; see docs/local-model.md."
        )
    return "Bearer " + token


AUTH = bearer()
SCENARIO = bool(os.environ.get("WINDBG_MCP_SCENARIO"))
SESSION = None

# One request at a time on this MCP session: the keepalive below runs on its own thread,
# and two requests sharing `SESSION` would race over the header it may hand back.
WIRE = threading.Lock()
LAST_REQUEST = time.monotonic()
KEEPALIVE_AFTER = float(os.environ.get("WINDBG_MCP_KEEPALIVE", "120"))
# Set before the MCP session is deleted. Read *inside* `WIRE`, which is what makes the
# ping and the `DELETE` a total order rather than two racing requests on one id.
STOP = threading.Event()


def parse(body, ctype):
    if "text/event-stream" in (ctype or ""):
        # The stream opens with an empty `data:` keep-alive before the payload.
        for line in body.splitlines():
            if line.startswith("data:") and line[5:].strip():
                return json.loads(line[5:].strip())
        return None
    return json.loads(body) if body.strip() else None


def mcp(method, params=None, notify=False):
    """One request, with the wire to itself."""
    with WIRE:
        return request(method, params, notify)


def request(method, params=None, notify=False):
    """The request itself. **The caller holds [`WIRE`]** — which the keepalive needs, because
    its decision to ping and the ping itself have to be one atomic thing against teardown."""
    global SESSION, LAST_REQUEST
    payload = {"jsonrpc": "2.0", "method": method}
    if not notify:
        payload["id"] = int(time.time() * 1000) % 100000
    if params is not None:
        payload["params"] = params
    req = urllib.request.Request(MCP_URL, data=json.dumps(payload).encode(), method="POST")
    req.add_header("Authorization", AUTH)
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json, text/event-stream")
    if SESSION:
        req.add_header("Mcp-Session-Id", SESSION)
    with urllib.request.urlopen(req, timeout=600) as response:
        if response.headers.get("Mcp-Session-Id"):
            SESSION = response.headers["Mcp-Session-Id"]
        body = parse(
            response.read().decode("utf-8", "replace"), response.headers.get("Content-Type")
        )
    LAST_REQUEST = time.monotonic()
    return body


def keepalive():
    """Renews this client's lease while the model is thinking.

    An **admitted** request is what renews a lease, and the JSON-RPC body does not enter
    into it — so this pings, and a server that answered the ping with an error would have
    renewed the lease all the same. It reports the first failure and then stays quiet:
    the run's own calls are what matter, and a keepalive that spammed the transcript
    would be worse than one that stopped.

    **It must not outlive the session it is keeping alive.** A ping that is decided while
    `close_transport_session` is deleting the id lands *after* the `DELETE`, and an id the
    server has stopped recording is one any credential may present — so the listener takes
    it back into this client's set and renews the lease around a session that no longer
    exists, which is the pile-up the `DELETE` is there to prevent. Reading [`STOP`] and
    [`SESSION`] inside [`WIRE`], and sending inside the same lock, is what stops that: the
    ping either finished before teardown took the lock, or it never starts. Joining this
    thread would do the same job and block on a request that may take as long as the call
    timeout, for no more safety.

    Reported by chatgpt-codex-connector on #184.
    """
    complained = False
    while KEEPALIVE_AFTER > 0 and not STOP.is_set():
        if STOP.wait(min(30.0, KEEPALIVE_AFTER / 2)):
            return
        try:
            with WIRE:
                idle = time.monotonic() - LAST_REQUEST
                if STOP.is_set() or SESSION is None or idle < KEEPALIVE_AFTER:
                    continue
                request("ping")
            print(f"  keepalive: pinged the listener after {idle:.0f}s of thinking")
        except Exception as e:  # noqa: BLE001 - a keepalive must not end the run
            if not complained:
                complained = True
                print(f"  keepalive: could not ping ({e}); the lease is on its own now")


def handshake():
    out = mcp("initialize", {
        "protocolVersion": REVISION,
        "capabilities": {},
        "clientInfo": {"name": "local-model-drive", "version": "1"},
    })
    mcp("notifications/initialized", notify=True)
    return out["result"]["protocolVersion"]


def ollama(path, body=None):
    url = OLLAMA.replace("/api/chat", path)
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method="POST" if data else "GET")
    if data:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=60) as response:
        return json.load(response)


def pick_model():
    """The configured tag, or the first installed one that can actually call tools.

    Asked rather than assumed: an embedding model, or a chat model without tool
    support, is a perfectly ordinary first entry in `ollama list`, and picking it
    fails at the first `/api/chat` with an error about the wrong thing.
    """
    if MODEL:
        return MODEL
    installed = [m["name"] for m in ollama("/api/tags").get("models", [])]
    if not installed:
        raise SystemExit("no ollama models pulled; `ollama pull <tag>` first")
    for tag in installed:
        if "tools" in (ollama("/api/show", {"model": tag}).get("capabilities") or []):
            return tag
    raise SystemExit(
        "none of the installed models declares the `tools` capability "
        f"({', '.join(installed)}); set LOCAL_MODEL to one that does"
    )


def as_ollama(tools):
    """MCP tool definitions in the function-calling shape ollama takes."""
    return [{"type": "function", "function": {
        "name": tool["name"],
        "description": tool.get("description", ""),
        "parameters": tool.get("inputSchema", {"type": "object", "properties": {}}),
    }} for tool in tools]


class ChatFailed(Exception):
    """The runtime refused the request, which for this harness is a result rather than a crash.

    A surface that does not fit the served window is the whole point of the context axis, and
    the way it presents is an HTTP error carrying a sentence about tokens — so a run that let
    `urlopen` raise would lose the one fact the cell was measuring. The body travels with the
    exception and into the record.
    """


def chat(messages, tools):
    body = {"model": MODEL, "messages": messages, "tools": tools, "stream": False,
            "think": False, "keep_alive": KEEP_ALIVE}
    if NUM_CTX:
        # **The window is a property of the runtime, not of the model.** `ollama show` reports
        # what the weights could take; what a request is actually served is
        # `OLLAMA_CONTEXT_LENGTH` unless a request says otherwise, and this is that override —
        # the eval's context axis is this number moving. Setting it *reloads* the model, so the
        # matrix runs every surface at one context before it moves to the next.
        body["options"] = {"num_ctx": NUM_CTX}
    req = urllib.request.Request(OLLAMA, data=json.dumps(body).encode(), method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=1800) as response:
            return json.load(response)
    except urllib.error.HTTPError as e:
        raise ChatFailed(f"HTTP {e.code}: {e.read().decode('utf-8', 'replace')[:400]}") from e
    except urllib.error.URLError as e:
        # A runtime that died, was restarted, or refused the connection is the same kind of fact
        # as one that returned 500 - the cell records it and the grid goes on. Ordered after
        # `HTTPError`, which is a subclass of this.
        raise ChatFailed(f"no answer from the runtime: {e.reason}") from e


def call_tool(name, args):
    """Run one tool call, and hand back a record of it whose `text` is what the model sees.

    A record rather than a bare answer because the eval grades *how* a call went, and the
    three ways it can fail are not the same finding: `refused_by_harness` is this script's
    read-only fence, `error` is the server saying no — which on a narrowed surface is the
    tool not being served at all — and `transport_error` is the link. Counting them together
    would report a model that invented a tool and a model that asked for a bad address as
    having made the same mistake.
    """
    started = time.time()
    def record(text, ok, chars, verdict):
        return {"name": name, "args": args, "ok": ok, "chars": chars, "verdict": verdict,
                "took_s": round(time.time() - started, 1), "text": text,
                "excerpt": text[:300]}
    if name not in ALLOWED:
        return record(f"refused: `{name}` is not permitted in this harness",
                      None, 0, "refused_by_harness")
    if name == "end_session" and args.get("session_id") not in OPENED:
        # One rule, and it covers the call that names nothing: without a `session_id`
        # the server ends this credential's *current* session, which may be a
        # predecessor's leftover rather than anything this run opened.
        return record(
            f"refused: `{args.get('session_id') or 'the current session'}` was not opened by "
            "this run, so it is not this harness's to end", None, 0, "refused_by_harness")
    try:
        out = mcp("tools/call", {"name": name, "arguments": args})
    except Exception as e:  # a transport failure is a result the model can react to
        if name in OPENERS:
            # **Ambiguous, not failed.** The call may have reached the server and
            # opened a target before the answer went missing, and nothing else will
            # ever name that handle: the model retries and gets a second target, and
            # the cleanup has nothing to release. Ask what exists instead of assuming.
            reconcile_opened()
        return record(f"transport error: {e}", False, 0, "transport_error")
    result = out.get("result", {})
    # **Both kinds of failure.** A protocol error arrives as a top-level `error`; an
    # ordinary tool failure — a bad address, a stale handle — arrives as a perfectly
    # good result carrying `isError`. Counting only the first reports a failed call as
    # a successful one, which is exactly the telemetry this harness is for.
    ok = "error" not in out and not result.get("isError")
    text = json.dumps(result if result else out)
    size = len(text)
    if name in OPENERS:
        # **Whatever the call reported.** An opener can register a session and then
        # fail — a dump that opens and a later step that does not — and the answer
        # carries the handle either way. Tracking only the successes would leave that
        # worker holding its target until the lease grace ran out.
        found = opened_session(result)
        if found and found not in OPENED:
            OPENED.append(found)
    elif name == "end_session" and ok:
        OPENED[:] = [s for s in OPENED if s != args.get("session_id")]
    if RESULT_LIMIT and size > RESULT_LIMIT:
        text = text[:RESULT_LIMIT] + f"\n[truncated by the harness: {size} characters in full]"
    return record(text, ok, size, "ok" if ok else "error")


def run(task, tools, transcript=None):
    """Work one task, and hand back the transcript it leaves behind.

    A task is its own conversation unless `transcript` says otherwise: in scenario
    mode the same one carries across tasks, so "disassemble the address you found"
    means something. Keeping the *session* and dropping the *messages* would be a
    continuing investigation the model cannot remember — target reuse dressed up as
    one, which is what the flag would then be lying about.

    Beside the transcript it hands back a **record** of the task — turns, tokens, every
    tool call and what became of it — which is what `WINDBG_MCP_EVAL_OUT` writes and
    `local_model_eval.py` grades. Nothing here decides whether an answer is right: this
    script drives, and grading against the answer key happens where the key is.
    """
    prompt = task["prompt"] if isinstance(task, dict) else task
    report = {
        "task": task.get("id") if isinstance(task, dict) else None,
        "prompt": prompt, "turns": [], "calls": [], "answer": None,
        "steps": 0, "gave_up": False, "error": None,
    }
    started_task = time.time()
    messages = transcript or [
        {"role": "system", "content":
         "You are a Windows kernel debugging assistant. Use the provided tools to answer. "
         "Call one tool at a time and use its result. Be concise."},
    ]
    messages.append({"role": "user", "content": prompt})
    first_prompt_tokens = None
    for step in range(MAX_STEPS):
        started = time.time()
        try:
            out = chat(messages, tools)
        except ChatFailed as e:
            # The cell's answer, not its accident: a window too small for the surface, a
            # runtime that would not load the model. Recorded and the task ends here.
            report["error"] = str(e)
            report["wall_s"] = round(time.time() - started_task, 1)
            print(f"  chat failed: {e}")
            return messages, report
        took = round(time.time() - started, 1)
        message = out.get("message", {})
        report["steps"] = step + 1
        report["turns"].append({
            "took_s": took,
            "prompt_tokens": out.get("prompt_eval_count"),
            "eval_tokens": out.get("eval_count"),
            "load_ms": round((out.get("load_duration") or 0) / 1e6),
        })
        if first_prompt_tokens is None:
            first_prompt_tokens = out.get("prompt_eval_count")
            report["first_prompt_tokens"] = first_prompt_tokens
            print(f"  prompt tokens: {first_prompt_tokens}")
        messages.append(message)
        calls = message.get("tool_calls") or []
        if not calls:
            answer = message.get("content") or ""
            report["answer"] = answer
            report["wall_s"] = round(time.time() - started_task, 1)
            print(f"  [{took:>6}s] answer: {answer[:400]}")
            return messages, report
        for call in calls:
            name = call["function"]["name"]
            args = call["function"].get("arguments") or {}
            if isinstance(args, str):
                args = json.loads(args or "{}")
            call_record = call_tool(name, args)
            text = call_record.pop("text")
            report["calls"].append(call_record)
            print(f"  [{took:>6}s] -> {name}({json.dumps(args)[:120]}) "
                  f"{call_record['verdict']} result={call_record['chars']} chars")
            print(f"           {text[:200]}")
            messages.append({"role": "tool", "tool_name": name, "content": text})
    report["gave_up"] = True
    report["wall_s"] = round(time.time() - started_task, 1)
    print(f"  gave up after {MAX_STEPS} steps")
    return messages, report


def live_sessions():
    """Every session id this credential can see, from the structured answer."""
    out = mcp("tools/call", {"name": "session_status", "arguments": {}})
    structured = (out.get("result") or {}).get("structuredContent") or {}
    return [s["session_id"] for s in structured.get("sessions") or [] if s.get("session_id")]


def snapshot_existing():
    """Record what was already open, before this run opens anything.

    Without this, the reconciliation below adopts the whole namespace — including a
    session a crashed run left behind or a second invocation sharing the credential —
    and the cleanup then ends somebody else's target. The fence is per *run*, so the
    baseline has to be per run too.
    """
    try:
        PRE_EXISTING.update(live_sessions())
    except Exception as e:
        print(f"  could not read the credential's existing sessions: {e}")
        return
    if PRE_EXISTING:
        print(f"  {len(PRE_EXISTING)} session(s) already open on this credential; "
              "this run will neither adopt nor release them")


def reconcile_opened():
    """Adopt sessions that appeared during this run, after an ambiguous opener.

    Sound because this run authenticates as a client of its own, so the namespace is
    the driver's rather than the editor's. Bounded by the startup snapshot, so what another
    invocation or a crashed predecessor left behind stays theirs. Two runs sharing
    one credential *concurrently* can still overlap here — the answer to that is the
    same as everywhere else on this page: a credential per run.
    """
    try:
        sessions = live_sessions()
    except Exception as e:
        print(f"  could not reconcile after an ambiguous open: {e}")
        return
    for found in sessions:
        if found not in OPENED and found not in PRE_EXISTING:
            OPENED.append(found)
            print(f"  adopted {found} after an ambiguous open")


def close_transport_session():
    """Say goodbye to the MCP session as well as to the debug sessions.

    The revision this speaks mints an `Mcp-Session-Id`, and a run that simply stops
    leaves it resident in the server until a whole grace passes with no traffic at
    all — so repeated runs on one credential pile them up, each new request renewing
    the lease that would have swept them. A `DELETE` is what the protocol provides.
    """
    global SESSION
    # Told before the lock is taken, so a keepalive already waiting for it re-reads this and
    # stands down rather than pinging an id that is about to stop existing.
    STOP.set()
    with WIRE:
        if not SESSION:
            return
        req = urllib.request.Request(MCP_URL, method="DELETE")
        req.add_header("Authorization", AUTH)
        req.add_header("Mcp-Session-Id", SESSION)
        try:
            with urllib.request.urlopen(req, timeout=60) as response:
                print(f"  closed the MCP session ({response.status})")
        except Exception as e:
            print(f"  could not close the MCP session: {e}")
        SESSION = None


def release_what_this_run_opened():
    """End the run's own sessions, so the next one starts from nothing.

    Without this a task that opens a dump and never says goodbye leaves a worker
    holding it for the whole lease grace, the next run adopts it, and a measurement
    that was supposed to start clean starts with somebody's leftovers — or trips the
    four-session cap and reclaims one.
    """
    # **What could not be released stays on the list.** Clearing it regardless would
    # leave the final pass with nothing to retry, and the next task routing its
    # session-less calls to a target this one was supposed to have let go.
    kept = []
    for session in list(OPENED):
        try:
            out = mcp("tools/call", {"name": "end_session", "arguments": {"session_id": session}})
            error = ((out.get("result") or {}).get("structuredContent") or {}).get("error") or {}
            category = error.get("category")
            if not error:
                print(f"  released {session}")
            elif category in ("stale_session", "worker_lost"):
                # Gone either way, so there is nothing left to retry.
                print(f"  {session} was already gone ({category})")
            else:
                kept.append(session)
                print(f"  could not release {session}: {error.get('message', category)}")
        except Exception as e:
            kept.append(session)
            print(f"  could not release {session}: {e}")
    OPENED[:] = kept


def load_tasks(path):
    """A task list, in either shape this harness accepts.

    A bare JSON list of strings is what the first two runs used and still works. The eval
    suite is an object — `{"tasks": [{"id", "prompt", "expect", ...}]}` — because a task
    that is graded needs a name to be graded under and an answer key to be graded against.
    Everything but `prompt` travels through this script untouched, into the record: the
    driver's job is to drive, and nothing here reads `expect`.

    `EVAL_SUBSET` names one of the file's own `subsets`, which is how the reduced-context
    cells run three tasks rather than six without a second file to keep in step.
    """
    with open(path, encoding="utf-8") as f:
        loaded = json.load(f)
    if isinstance(loaded, list):
        return loaded
    tasks = loaded["tasks"]
    subset = os.environ.get("EVAL_SUBSET", "")
    if subset:
        wanted = loaded.get("subsets", {}).get(subset)
        if wanted is None:
            raise SystemExit(f"{path} has no subset `{subset}`")
        tasks = [t for t in tasks if t.get("id") in wanted]
    return tasks


def served_context():
    """What the runtime is actually serving this model, which is not what it could serve.

    Asked rather than assumed for the reason `docs/local-model.md` gives: the default
    `OLLAMA_CONTEXT_LENGTH` picks 4k, 32k or 256k from the box's memory, so a model whose
    card says 262144 is routinely served far less. Best effort — a runtime that does not
    report it leaves the field null rather than failing a run over telemetry.
    """
    try:
        for loaded in ollama("/api/ps").get("models", []):
            if loaded.get("name") == MODEL or loaded.get("model") == MODEL:
                return loaded.get("context_length")
    except Exception:  # noqa: BLE001 - a missing figure must not end a run
        return None
    return None


def write_record(record):
    """Append one task's record to the eval log, if this run is part of an eval.

    **Appended, one JSON object per line, flushed per task.** A matrix run is hours long
    and its cells are separate processes; a run that died in the middle should still leave
    every cell before it on disk, and a reader should be able to grade what is there while
    the rest is still going.
    """
    if not EVAL_OUT:
        return
    with open(EVAL_OUT, "a", encoding="utf-8") as log:
        log.write(json.dumps(record, default=str) + "\n")


def release_everything():
    """End every session this credential holds, and say goodbye to the MCP session.

    For the one case the per-run fence cannot cover: a cell killed at its wall-clock budget, whose
    driver never reached its own cleanup. Whatever it had open then stays attached until the
    listener's lease expires, and the next cell on the same surface either routes a
    `session_id`-less call to a stranger's target or meets the four-session cap.

    **Deliberately everything, not just what a run opened** - there is no run here to have opened
    anything. That is only safe because of the rule the rest of this bench is built on: the
    credential belongs to this run alone (`docs/local-model-eval.md`). Pointed at a shared token it
    would end somebody's sessions, which is the same reason the script refuses to borrow one.
    """
    handshake()
    try:
        sessions = live_sessions()
    except Exception as e:  # noqa: BLE001 - cleanup is best effort by construction
        print(f"  could not list sessions to release: {e}")
        sessions = []
    for session in sessions:
        try:
            mcp("tools/call", {"name": "end_session", "arguments": {"session_id": session}})
            print(f"  released {session}")
        except Exception as e:  # noqa: BLE001
            print(f"  could not release {session}: {e}")
    close_transport_session()


def main():
    global MODEL
    if "--release" in sys.argv[1:]:
        release_everything()
        return
    MODEL = pick_model()
    print(f"model: {MODEL}")
    print("MCP revision negotiated:", handshake())
    threading.Thread(target=keepalive, daemon=True).start()
    tools = mcp("tools/list")["result"]["tools"]
    offered = as_ollama(tools)
    surface = len(json.dumps(offered, separators=(",", ":")))
    print(f"tools offered: {len(tools)} ({surface} B of minified JSON)")
    if NUM_CTX:
        print(f"context requested: {NUM_CTX}")
    if SCENARIO:
        print("scenario: sessions are kept between tasks")
    snapshot_existing()
    tasks = load_tasks(sys.argv[1]) if len(sys.argv) > 1 else [
        "What debug sessions do I currently have open on this server?"
    ]
    cell = {
        "run": os.environ.get("EVAL_RUN", time.strftime("%Y%m%dT%H%M%S")),
        "backend": "ollama",
        "model": MODEL,
        "num_ctx": NUM_CTX or None,
        "surface": {"client": os.environ.get("EVAL_SURFACE", ""),
                    "tools": len(tools), "bytes": surface,
                    "names": sorted(t["name"] for t in tools)},
    }
    transcript = None
    try:
        for i, task in enumerate(tasks, 1):
            prompt = task["prompt"] if isinstance(task, dict) else task
            print(f"\n=== task {i}: {prompt[:110]}")
            transcript, report = run(task, offered, transcript)
            # Read *after* the first turn: nothing is loaded before one, so asking earlier
            # reports the previous model's window or nothing at all.
            record = dict(cell, served_context=served_context(), **report)
            if NUM_CTX and record["served_context"] and record["served_context"] != NUM_CTX:
                # Loudly, because it is invisible otherwise and it invalidates the cell: a
                # request's `num_ctx` does not shrink an instance the runtime already holds.
                print(f"  WARNING: asked for {NUM_CTX} tokens of context and was served "
                      f"{record['served_context']} - evict the model before changing the window")
            write_record(record)
            # Each task is its own conversation, so it gets its own targets: a session
            # left open would be routed to by the next task's `session_id`-less call,
            # which makes that task's measurement depend on the one before it. A task
            # list meant as one continuing investigation says so with WINDBG_MCP_SCENARIO.
            if not SCENARIO:
                transcript = None
                release_what_this_run_opened()
    finally:
        release_what_this_run_opened()
        close_transport_session()


if __name__ == "__main__":
    main()
