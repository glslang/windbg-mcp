#!/usr/bin/env python3
"""Drive this server from Claude Code headlessly, into the same eval record as a local model.

The matrix in `local_model_eval.py` needs a frontier row, and the cheapest honest one is the
harness that is already installed: `claude -p` speaks MCP to the same listener, presenting the
same per-client bearer token, so **the surface axis works identically** - `full`, `lean` and
`min` are the same three credentials, narrowed by the server rather than by anything here.

    WINDBG_MCP_TOKEN=<the surface's token> CLAUDE_MODEL=opus \\
      python3 tools/claude_code_drive.py tools/eval_tasks.json

**What this row is not.** A local model here is a bare `POST /api/chat` loop: one system
prompt, the tool list, nothing else. Claude Code brings its own system prompt, its own
conversation shape and prompt caching, so the *token* columns are not comparable with the
ollama rows and the record says so (`harness: claude-code`). What is comparable is what the
matrix is actually about: which tools get picked out of a given surface, whether the answer
is right, and what a task costs in tool results.

Two fences, both deliberate:

- `--strict-mcp-config` so the run cannot fall back on the editor's registered `windbg-vm`
  server. That one carries a *different* credential, which would put these sessions in the
  editor's namespace and silently give every cell the whole 51-tool surface - the surface
  axis would then be measuring nothing.
- `--disallowedTools` for the built-ins. Without it the frontier row can answer a question
  about a dump by reading this repository's own documentation, which is a true answer to the
  wrong question.
"""
import json
import os
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import local_model_drive as drive  # noqa: E402 - the MCP plumbing, one implementation of it

MODEL = os.environ.get("CLAUDE_MODEL", "opus")
MAX_TURNS = int(os.environ.get("MAX_STEPS", "6"))
SERVER = "windbg"

# The same read-only fence the local harness applies, in Claude Code's naming. Anything else -
# `launch`, `execute`, `debug_batch` - is simply not allowed, so a wrong pick is refused rather
# than performed, and the refusal is recorded.
ALLOWED = [f"mcp__{SERVER}__{name}" for name in sorted(drive.ALLOWED)]

# Everything the harness itself brings. A frontier model with `Bash` can answer "what bug check
# is in that dump" by grepping this repo, which measures the repository rather than the server.
DISALLOWED = ["Bash", "Read", "Write", "Edit", "MultiEdit", "NotebookEdit", "Glob", "Grep",
              "WebFetch", "WebSearch", "Task", "Agent", "TodoWrite", "SlashCommand"]

SYSTEM = ("You are a Windows kernel debugging assistant. Use the provided tools to answer. "
          "Call one tool at a time and use its result. Be concise.")


def mcp_config(directory):
    """The one server this run may reach, carrying this cell's credential.

    A file rather than an inline argument because `--mcp-config` also takes JSON on the command
    line, and a token in `argv` is readable by every process on the box - the same rule the rest
    of this bench follows.

    Three things about *how* it is written, all of them the same lesson from
    [#189](https://github.com/glslang/windbg-mcp/pull/189): do not write a secret into a
    directory whose protection this program does not control.

    - The directory is one this process makes (`mkdtemp`, mode 0700), unless `EVAL_SCRATCH`
      names one. It is never the working directory - a fallback to `.` writes a bearer token
      into the checkout the moment somebody runs this script by hand.
    - The file is created **with** mode 0600 rather than chmod'd afterwards. Creating it under
      the process umask and tightening it later leaves a window where the token is on disk and
      world-readable.
    - `O_EXCL`, so this never writes through a symlink somebody left in the directory.

    The caller removes it on the way out.
    """
    path = os.path.join(directory, f"mcp-{os.getpid()}.json")
    config = {"mcpServers": {SERVER: {
        "type": "http",
        "url": drive.MCP_URL,
        "headers": {"Authorization": drive.AUTH},
    }}}
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(config, f)
    return path


def one_task(task, config_path):
    """Run one task in its own `claude -p` conversation, and record what it did."""
    prompt = task["prompt"] if isinstance(task, dict) else task
    report = {"task": task.get("id") if isinstance(task, dict) else None, "prompt": prompt,
              "turns": [], "calls": [], "answer": None, "steps": 0, "gave_up": False,
              "error": None, "harness": "claude-code"}
    argv = [
        "claude", "-p", prompt,
        "--model", MODEL,
        "--mcp-config", config_path, "--strict-mcp-config",
        "--allowedTools", ",".join(ALLOWED),
        "--disallowedTools", ",".join(DISALLOWED),
        "--system-prompt", SYSTEM,
        "--max-turns", str(MAX_TURNS),
        "--output-format", "stream-json", "--verbose",
    ]
    started = time.time()
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=1800)
    report["wall_s"] = round(time.time() - started, 1)
    if proc.returncode != 0:
        report["error"] = f"claude exited {proc.returncode}: {proc.stderr[:400]}"
        return report

    pending = {}
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        kind = event.get("type")
        if kind == "assistant":
            message = event.get("message", {})
            usage = message.get("usage") or {}
            report["turns"].append({
                "prompt_tokens": (usage.get("input_tokens", 0)
                                  + usage.get("cache_creation_input_tokens", 0)
                                  + usage.get("cache_read_input_tokens", 0)),
                "eval_tokens": usage.get("output_tokens"),
            })
            report["steps"] += 1
            for block in message.get("content") or []:
                if block.get("type") == "tool_use":
                    raw = block.get("name") or ""
                    name = raw.replace(f"mcp__{SERVER}__", "")
                    pending[block.get("id")] = {
                        "name": name, "args": block.get("input") or {}, "ok": None, "chars": 0,
                        # A call that is not this server's is the *harness* working - Claude
                        # Code's own `ToolSearch` fetching a deferred schema, say. Recorded, and
                        # kept out of the tool-choice arithmetic: scoring it as a wrong pick
                        # would blame the model for a feature of the client it runs in.
                        "harness_tool": not raw.startswith(f"mcp__{SERVER}__"),
                        "verdict": "unknown", "excerpt": ""}
        elif kind == "user":
            for block in (event.get("message", {}).get("content") or []):
                if block.get("type") != "tool_result":
                    continue
                call = pending.pop(block.get("tool_use_id"), None)
                if call is None:
                    continue
                content = block.get("content")
                text = content if isinstance(content, str) else json.dumps(content)
                call["chars"] = len(text)
                call["excerpt"] = text[:300]
                failed = bool(block.get("is_error"))
                call["ok"] = not failed
                # The same three-way split the local harness records, read off the only
                # signal this route gives: a refusal names the tool, an off-surface call
                # says so in the server's own words, and anything else that failed is an
                # error the model made with a tool it did have.
                lowered = text.lower()
                if call["harness_tool"]:
                    call["verdict"] = "harness_tool"
                elif not failed:
                    call["verdict"] = "ok"
                elif "permission" in lowered or "not allowed" in lowered:
                    call["verdict"] = "refused_by_harness"
                else:
                    call["verdict"] = "error"
                report["calls"].append(call)
        elif kind == "result":
            report["answer"] = event.get("result")
            report["usage"] = event.get("usage")
            report["total_cost_usd"] = event.get("total_cost_usd")
            if event.get("subtype") == "error_max_turns":
                report["gave_up"] = True
    report["first_prompt_tokens"] = (report["turns"][0]["prompt_tokens"]
                                     if report["turns"] else None)
    for call in pending.values():
        # A tool call whose result never came back - the turn cap fell between them.
        call["verdict"] = "unanswered"
        report["calls"].append(call)
    return report


def release_new_sessions(before):
    """End every session this credential gained while the task ran.

    Claude Code has no idea it is being measured and will not tidy up after itself, and a dump
    left open is a worker holding a target for the whole lease grace - which the next cell
    then either adopts or trips the four-session cap against. Bounded by the snapshot for the
    same reason the local harness bounds its own: what was already here is not this run's.
    """
    try:
        now = drive.live_sessions()
    except Exception as e:  # noqa: BLE001 - cleanup must not end the run
        print(f"  could not list sessions to clean up: {e}")
        return
    for session in now:
        if session in before:
            continue
        try:
            drive.mcp("tools/call", {"name": "end_session", "arguments": {"session_id": session}})
            print(f"  released {session}")
        except Exception as e:  # noqa: BLE001
            print(f"  could not release {session}: {e}")


def main():
    print(f"model: claude-code/{MODEL}")
    print("MCP revision negotiated:", drive.handshake())
    tools = drive.mcp("tools/list")["result"]["tools"]
    offered = drive.as_ollama(tools)
    surface_bytes = len(json.dumps(offered, separators=(",", ":")))
    print(f"tools offered: {len(tools)} ({surface_bytes} B, measured as the ollama rows are)")

    scratch = os.environ.get("EVAL_SCRATCH", "")
    owned = not scratch
    if owned:
        scratch = tempfile.mkdtemp(prefix="windbg-eval-")
    config_path = mcp_config(scratch)
    cell = {
        "run": os.environ.get("EVAL_RUN", time.strftime("%Y%m%dT%H%M%S")),
        "backend": "claude-code",
        "model": MODEL,
        "num_ctx": None,
        "surface": {"client": os.environ.get("EVAL_SURFACE", ""), "tools": len(tools),
                    "bytes": surface_bytes, "names": sorted(t["name"] for t in tools)},
    }
    tasks = drive.load_tasks(sys.argv[1]) if len(sys.argv) > 1 else []
    try:
        for i, task in enumerate(tasks, 1):
            prompt = task["prompt"] if isinstance(task, dict) else task
            print(f"\n=== task {i}: {prompt[:110]}")
            before = set(drive.live_sessions())
            report = one_task(task, config_path)
            drive.write_record(dict(cell, **report))
            print(f"  [{report['wall_s']}s] {len(report['calls'])} call(s): "
                  f"{', '.join(c['name'] for c in report['calls']) or 'none'}")
            print(f"  answer: {(report.get('answer') or report.get('error') or '')[:300]}")
            release_new_sessions(before)
    finally:
        os.remove(config_path)
        if owned:
            os.rmdir(scratch)
        drive.close_transport_session()


if __name__ == "__main__":
    main()
