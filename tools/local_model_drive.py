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
"""
import json
import os
import sys
import time
import urllib.request

MCP_URL = os.environ.get("WINDBG_MCP_URL", "http://127.0.0.1:8765/")
OLLAMA = os.environ.get("OLLAMA_URL", "http://localhost:11434/api/chat")
MODEL = os.environ.get("LOCAL_MODEL", "")
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

MAX_STEPS = 6

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


def parse(body, ctype):
    if "text/event-stream" in (ctype or ""):
        # The stream opens with an empty `data:` keep-alive before the payload.
        for line in body.splitlines():
            if line.startswith("data:") and line[5:].strip():
                return json.loads(line[5:].strip())
        return None
    return json.loads(body) if body.strip() else None


def mcp(method, params=None, notify=False):
    global SESSION
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
        return parse(response.read().decode("utf-8", "replace"), response.headers.get("Content-Type"))


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


def chat(messages, tools):
    body = {"model": MODEL, "messages": messages, "tools": tools, "stream": False, "think": False}
    req = urllib.request.Request(OLLAMA, data=json.dumps(body).encode(), method="POST")
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=1800) as response:
        return json.load(response)


def call_tool(name, args):
    """Run one tool call. Returns (text for the model, ok, full size in characters)."""
    if name not in ALLOWED:
        return f"refused: `{name}` is not permitted in this harness", None, 0
    if name == "end_session" and args.get("session_id") not in OPENED:
        # One rule, and it covers the call that names nothing: without a `session_id`
        # the server ends this credential's *current* session, which may be a
        # predecessor's leftover rather than anything this run opened.
        return (f"refused: `{args.get('session_id') or 'the current session'}` was not opened by "
                "this run, so it is not this harness's to end"), None, 0
    try:
        out = mcp("tools/call", {"name": name, "arguments": args})
    except Exception as e:  # a transport failure is a result the model can react to
        if name in OPENERS:
            # **Ambiguous, not failed.** The call may have reached the server and
            # opened a target before the answer went missing, and nothing else will
            # ever name that handle: the model retries and gets a second target, and
            # the cleanup has nothing to release. Ask what exists instead of assuming.
            reconcile_opened()
        return f"transport error: {e}", False, 0
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
    return text, ok, size


def run(task, tools, transcript=None):
    """Work one task, and hand back the transcript it leaves behind.

    A task is its own conversation unless `transcript` says otherwise: in scenario
    mode the same one carries across tasks, so "disassemble the address you found"
    means something. Keeping the *session* and dropping the *messages* would be a
    continuing investigation the model cannot remember — target reuse dressed up as
    one, which is what the flag would then be lying about.
    """
    messages = transcript or [
        {"role": "system", "content":
         "You are a Windows kernel debugging assistant. Use the provided tools to answer. "
         "Call one tool at a time and use its result. Be concise."},
    ]
    messages.append({"role": "user", "content": task})
    first_prompt_tokens = None
    for step in range(MAX_STEPS):
        started = time.time()
        out = chat(messages, tools)
        took = round(time.time() - started, 1)
        message = out.get("message", {})
        if first_prompt_tokens is None:
            first_prompt_tokens = out.get("prompt_eval_count")
            print(f"  prompt tokens: {first_prompt_tokens}")
        messages.append(message)
        calls = message.get("tool_calls") or []
        if not calls:
            print(f"  [{took:>6}s] answer: {(message.get('content') or '')[:400]}")
            return messages
        for call in calls:
            name = call["function"]["name"]
            args = call["function"].get("arguments") or {}
            if isinstance(args, str):
                args = json.loads(args or "{}")
            text, ok, size = call_tool(name, args)
            print(f"  [{took:>6}s] -> {name}({json.dumps(args)[:120]}) ok={ok} result={size} chars")
            print(f"           {text[:200]}")
            messages.append({"role": "tool", "tool_name": name, "content": text})
    print(f"  gave up after {MAX_STEPS} steps")
    return messages


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


def main():
    global MODEL
    MODEL = pick_model()
    print(f"model: {MODEL}")
    print("MCP revision negotiated:", handshake())
    tools = mcp("tools/list")["result"]["tools"]
    offered = as_ollama(tools)
    surface = len(json.dumps(offered, separators=(",", ":")))
    print(f"tools offered: {len(tools)} ({surface} B of minified JSON)")
    if SCENARIO:
        print("scenario: sessions are kept between tasks")
    snapshot_existing()
    tasks = json.load(open(sys.argv[1])) if len(sys.argv) > 1 else [
        "What debug sessions do I currently have open on this server?"
    ]
    transcript = None
    try:
        for i, task in enumerate(tasks, 1):
            print(f"\n=== task {i}: {task[:110]}")
            transcript = run(task, offered, transcript)
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
