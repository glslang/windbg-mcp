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
    WINDBG_MCP_PROJECT  which registration to read it from (default: this repo)
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
ALLOWED = {
    "open_dump", "open_trace", "crash_triage", "backtrace", "modules", "registers",
    "threads", "session_status", "end_session", "decode_ioctl", "disassemble",
    "read_memory", "server_log",
}

MAX_STEPS = 6
RESULT_LIMIT = 6000


def bearer():
    """The token, from the environment or from this client's own registration."""
    if os.environ.get("WINDBG_MCP_TOKEN"):
        return "Bearer " + os.environ["WINDBG_MCP_TOKEN"]
    registry = json.load(open(os.path.expanduser("~/.claude.json")))
    servers = registry["projects"][PROJECT]["mcpServers"]
    for entry in servers.values():
        auth = (entry.get("headers") or {}).get("Authorization")
        if auth:
            return auth
    raise SystemExit("no token: set WINDBG_MCP_TOKEN, or register the server with a bearer header")


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


def pick_model():
    if MODEL:
        return MODEL
    tags = urllib.request.urlopen(OLLAMA.replace("/api/chat", "/api/tags"), timeout=30)
    models = json.load(tags).get("models", [])
    if not models:
        raise SystemExit("no ollama models pulled; `ollama pull <tag>` first")
    return models[0]["name"]


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
    if name not in ALLOWED:
        return f"refused: `{name}` is not permitted in this harness", None
    try:
        out = mcp("tools/call", {"name": name, "arguments": args})
    except Exception as e:  # a transport failure is a result the model can react to
        return f"transport error: {e}", False
    return json.dumps(out.get("result", out))[:RESULT_LIMIT], "error" not in out


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
            text, ok = call_tool(name, args)
            print(f"  [{took:>6}s] -> {name}({json.dumps(args)[:120]}) ok={ok}")
            print(f"           {text[:200]}")
            messages.append({"role": "tool", "tool_name": name, "content": text})
    print(f"  gave up after {MAX_STEPS} steps")


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
    for i, task in enumerate(tasks, 1):
        print(f"\n=== task {i}: {task[:110]}")
        run(task, offered)


if __name__ == "__main__":
    main()
