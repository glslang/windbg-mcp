#!/usr/bin/env python3
"""Drive windbg-mcp from a local model through the ollama server API.

The point of this script is that the local-model plane needs no interactive
harness: it speaks MCP over HTTP to a `--listen` server and hands the whole tool
surface to `POST /api/chat`, so "can a local model drive this?" is a question
with a repeatable answer rather than an impression from a chat session.

    python3 tools/local_model_drive.py [tasks.json]

`tasks.json` is a list of strings, one per task; without it, one default task
runs. See `docs/local-model.md` for what to make of the numbers it prints.

Configuration, all optional:

    LOCAL_MODEL         ollama model tag       (default: the first tool-capable one)
    OLLAMA_URL          ollama chat endpoint   (default: http://localhost:11434/api/chat)
    WINDBG_MCP_URL      the listener           (default: http://127.0.0.1:8765/)
    WINDBG_MCP_TOKEN    bearer token; falls back to the Claude Code registration
                        in ~/.claude.json for WINDBG_MCP_PROJECT, so the token
                        never has to be pasted on a command line
    WINDBG_MCP_PROJECT  which project's registrations to read it from (default: this repo)
    WINDBG_MCP_SERVER   which registration in that project, by name, when the URL
                        does not identify one on its own
    RESULT_LIMIT        truncate tool results to this many characters before the
                        model sees them; `0`, the default, passes them whole
"""
import json
import os
import sys
import time
import urllib.request

MCP_URL = os.environ.get("WINDBG_MCP_URL", "http://127.0.0.1:8765/")
OLLAMA = os.environ.get("OLLAMA_URL", "http://localhost:11434/api/chat")
MODEL = os.environ.get("LOCAL_MODEL", "")
PROJECT = os.environ.get(
    "WINDBG_MCP_PROJECT", os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
REVISION = "2025-06-18"

# Tool calls this harness will actually execute. Everything else is reported back
# to the model as refused, so a wrong pick is *measured* rather than performed —
# the surface includes `launch` and `execute`, and a debug host is the wrong place
# to find out what a model does with them unattended.
#
# `end_session` is in here and is the one destructive member, so it is fenced twice
# over (see `call_tool`): this run may only end sessions it opened itself. Falling
# back to the registered client's token puts the driver in **that client's**
# namespace — which is the ownership model working as designed — so an
# `end_session` with no `session_id` would resolve whatever session that client has
# current and close somebody else's target. Give the driver its own credential
# (`WINDBG_MCP_LISTEN_TOKEN_DRIVER` on the listener, `WINDBG_MCP_TOKEN` here) and it
# gets a namespace of its own instead.
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


def same_endpoint(a, b):
    """Whether two registration URLs name the same listener, modulo a trailing slash."""
    return a.rstrip("/") == b.rstrip("/")


def bearer():
    """The token, from the environment or from this client's registration **for this listener**.

    Matched by URL, or by name when `WINDBG_MCP_SERVER` says which. Never "the first
    registration that has a token": a project can hold several, and handing this
    listener another server's credential would send that secret to a host it does not
    belong to — and then fail the handshake, which is the milder half.
    """
    if os.environ.get("WINDBG_MCP_TOKEN"):
        return "Bearer " + os.environ["WINDBG_MCP_TOKEN"]
    registry = json.load(open(os.path.expanduser("~/.claude.json")))
    servers = registry.get("projects", {}).get(PROJECT, {}).get("mcpServers", {})
    wanted = os.environ.get("WINDBG_MCP_SERVER")
    for name, entry in servers.items():
        if wanted and name != wanted:
            continue
        if not wanted and not same_endpoint(entry.get("url", ""), MCP_URL):
            continue
        auth = (entry.get("headers") or {}).get("Authorization")
        if auth:
            return auth
        raise SystemExit(f"registration `{name}` has no Authorization header")
    raise SystemExit(
        f"no registration for {MCP_URL} in {PROJECT} "
        f"(registered: {', '.join(servers) or 'none'}). "
        "Set WINDBG_MCP_TOKEN, or WINDBG_MCP_SERVER to name one."
    )


AUTH = bearer()
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
    if name == "end_session":
        wanted = args.get("session_id")
        if not wanted:
            return ("refused: name the `session_id` to end. Without one the server ends this "
                    "client's *current* session, which this harness may not have opened."), None, 0
        if wanted not in OPENED:
            return (f"refused: `{wanted}` was not opened by this run, so it is not this "
                    "harness's to end"), None, 0
    try:
        out = mcp("tools/call", {"name": name, "arguments": args})
    except Exception as e:  # a transport failure is a result the model can react to
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


def run(task, tools):
    messages = [
        {"role": "system", "content":
         "You are a Windows kernel debugging assistant. Use the provided tools to answer. "
         "Call one tool at a time and use its result. Be concise."},
        {"role": "user", "content": task},
    ]
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
            return
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
    for session in list(OPENED):
        try:
            mcp("tools/call", {"name": "end_session", "arguments": {"session_id": session}})
            print(f"  released {session}")
        except Exception as e:
            print(f"  could not release {session}: {e}")
    OPENED.clear()


def main():
    global MODEL
    MODEL = pick_model()
    print(f"model: {MODEL}")
    print("MCP revision negotiated:", handshake())
    tools = mcp("tools/list")["result"]["tools"]
    offered = as_ollama(tools)
    surface = len(json.dumps(offered, separators=(",", ":")))
    print(f"tools offered: {len(tools)} ({surface} B of minified JSON)")
    tasks = json.load(open(sys.argv[1])) if len(sys.argv) > 1 else [
        "What debug sessions do I currently have open on this server?"
    ]
    try:
        for i, task in enumerate(tasks, 1):
            print(f"\n=== task {i}: {task[:110]}")
            run(task, offered)
    finally:
        release_what_this_run_opened()
        close_transport_session()


if __name__ == "__main__":
    main()
