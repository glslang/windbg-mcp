#!/usr/bin/env python3
"""Drive windbg-mcp from Apple's on-device model, into the same eval record as an ollama row.

The grid's third backend. Apple's model cannot be reached through ollama - it is not distributed
as weights and the `FoundationModels` framework is the only way in - so the *model* half is a
Swift one-shot, `tools/fm_chat.swift`. Everything else is `local_model_drive`'s, imported rather
than reimplemented, exactly as `claude_code_drive.py` imports it: the loop, the read-only fence,
`call_tool`'s three failure verdicts, the lease keepalive, session cleanup and the
`WINDBG_MCP_EVAL_OUT` records. **`chat()` is the only thing replaced**, which is why the grader
needs no changes at all.

    WINDBG_MCP_TOKEN=<the surface's token> python3 tools/fm_drive.py tools/eval_tasks.json

`docs/apple-foundation-models.md` is the write-up - what was measured, and the three facts about
Foundation Models that make a drop-in possible at all.

Configuration, beyond what `local_model_drive` already reads:

    FM_CHAT_BIN     the compiled `fm_chat`; built into a temporary directory if unset or missing
    FM_KEEP_BIN     keep a binary this script built, instead of removing it on the way out

**Two axes are refused rather than ignored**, because this model has neither and a silently
dropped axis is how a grid reports an uncontrolled result as a controlled one:

- `OLLAMA_THINK` - the on-device model reports `reasoning: false`. There is no arm to run.
- `NUM_CTX` - the window is fixed at 8,192 tokens and no request can move it.

**What this row may not be compared with.** The surface is measured through `drive.as_ollama()`,
the same helper and the same bytes as the ollama rows, so the `surface` field is comparable. The
*token* columns are not: `prompt_eval_count` here is Apple's tokenizer, which reads this server's
JSON at a different rate to any of the MLX builds - about 3.9 B/token on the surface and 2.2 on
results, against the ~4 the ollama rows are read at. And on a turn that stopped at a tool call
there is no `Response` to ask, so the count is *measured* from the transcript instead and the
record says so (`fm.prompt_tokens_measured`).
"""
import json
import os
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import local_model_drive as drive  # noqa: E402 - the MCP plumbing, one implementation of it

HERE = os.path.dirname(os.path.abspath(__file__))
CHAT_TIMEOUT = int(os.environ.get("FM_CHAT_TIMEOUT", "1800"))

# Set by `ensure_binary()`; a module global so `chat()` can stay a drop-in for the one it replaces.
CHAT_BIN = ""
BUILT_DIR = ""

# **What `fm_chat` reported, per turn, kept where the record can reach it.**
# `drive.run()` copies a fixed set of ollama fields out of each response into `report["turns"]`,
# so the `fm` block - whether a count was measured or came from `Response.usage`, how many tools
# translated, how many were dropped - is dropped on the floor by a loop this backend does not own
# and should not fork. Collected here and folded into the record in `main()`, which means a run
# can no longer claim the full served surface when translation served less than it.
FM_TURNS = []


def ensure_binary():
    """Find or build `fm_chat`, and hand back its path.

    Built rather than required, because there is nothing to install: the toolchain ships with the
    OS this backend only runs on, and a build is under two seconds. `FM_CHAT_BIN` skips it for a
    matrix run that would otherwise pay it per cell.
    """
    global CHAT_BIN, BUILT_DIR
    supplied = os.environ.get("FM_CHAT_BIN", "")
    if supplied and os.path.exists(supplied):
        CHAT_BIN = supplied
        return CHAT_BIN
    BUILT_DIR = tempfile.mkdtemp(prefix="fm-chat-")
    CHAT_BIN = os.path.join(BUILT_DIR, "fm_chat")
    sources = [os.path.join(HERE, "fm_schema.swift"), os.path.join(HERE, "fm_chat.swift")]
    build = subprocess.run(["swiftc", "-swift-version", "6", "-O", *sources, "-o", CHAT_BIN],
                           capture_output=True, text=True, timeout=600)
    if build.returncode != 0:
        raise SystemExit("could not build fm_chat:\n" + (build.stderr or "")[-2000:])
    return CHAT_BIN


def cleanup_binary():
    if BUILT_DIR and not os.environ.get("FM_KEEP_BIN"):
        for name in os.listdir(BUILT_DIR):
            os.remove(os.path.join(BUILT_DIR, name))
        os.rmdir(BUILT_DIR)


def chat(messages, tools):
    """One turn, in the shape `local_model_drive.run()` expects back from ollama.

    Shells out per turn rather than holding a process open, which the daemon's prefix cache makes
    affordable: a cold process answering from a rebuilt transcript reported 408 of 409 input
    tokens cached. Prefill is not re-paid, so a long-lived bridge would buy nothing and would
    have to own history to earn its keep - which is the harness's job, not this function's.

    A refusal comes back as a *result*, not an exception from the subprocess: a window too small
    for the surface is the measurement this backend exists to make. It is translated into the
    same `ChatFailed` the ollama path raises, so `run()` records it and the grid goes on.
    """
    request = json.dumps({"tools": tools, "messages": messages})
    try:
        proc = subprocess.run([CHAT_BIN], input=request, capture_output=True, text=True,
                              timeout=CHAT_TIMEOUT)
    except subprocess.TimeoutExpired as e:
        raise drive.ChatFailed(f"fm_chat did not answer within {CHAT_TIMEOUT}s") from e
    if proc.stderr.strip():
        # Translation notes, one line each. A tool that would not translate at all does not
        # arrive here - it comes back as a `tool_translation_failed` result and ends the turn.
        for line in proc.stderr.strip().splitlines()[:4]:
            print(f"    {line}")
    if proc.returncode != 0 or not proc.stdout.strip():
        raise drive.ChatFailed(
            f"fm_chat exited {proc.returncode}: {(proc.stderr or '(no stderr)').strip()[:400]}")
    try:
        out = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise drive.ChatFailed(f"fm_chat did not answer with JSON: {proc.stdout[:200]}") from e
    if isinstance(out.get("fm"), dict):
        FM_TURNS.append(out["fm"])
    if "error" in out:
        kind = out.get("error_kind", "error")
        if kind == "context_size_exceeded":
            raise drive.ChatFailed(
                f"context size exceeded: {out.get('token_count')} tokens against a window of "
                f"{out.get('context_size')}")
        if kind == "tool_translation_failed":
            raise drive.ChatFailed(
                f"{out['error']} (asked for {out.get('tools_requested')}, "
                f"translated {out.get('tools_translated')})")
        raise drive.ChatFailed(f"{kind}: {out['error']}")
    return out


def refuse_axes_this_model_does_not_have():
    """Refuse a cell that asked for an arm this backend cannot run.

    The same shape as the two refusals `local_model_eval.py` already keys on backend. Ignoring
    either of these would leave two cells differing only in a field neither run honoured, which
    reads in the log as a controlled comparison and is not one.
    """
    if os.environ.get("OLLAMA_THINK", "").strip().lower() in ("1", "true", "yes", "on"):
        raise SystemExit("fm_drive: this model reports `reasoning: false`; there is no think arm "
                         "to run. Unset OLLAMA_THINK for Foundation Models cells.")
    if drive.NUM_CTX:
        raise SystemExit(f"fm_drive: NUM_CTX={drive.NUM_CTX} cannot be honoured; the on-device "
                         "window is fixed at 8192 tokens. Unset NUM_CTX for these cells.")


def runtime_identity():
    """What answered, as far as this backend can say.

    The ollama rows read the loaded instance's digest and served window from `/api/ps`. There is
    no such endpoint here and no address for the weights, so the honest equivalents are the OS
    build the model ships with and the window it enforces - and the fields the ollama rows fill
    are **null rather than absent**, which is the convention `claude_code_drive.py` set: a field
    left out reads as one nobody thought to record.
    """
    build = ""
    try:
        build = subprocess.run(["sw_vers", "-buildVersion"], capture_output=True, text=True,
                               timeout=30).stdout.strip()
    except Exception:  # noqa: BLE001 - identity is a nicety, never a reason to fail a run
        pass
    return {"model_digest": None, "served_context": 8192, "os_build": build or None}


def main():
    refuse_axes_this_model_does_not_have()
    ensure_binary()
    print(f"model: apple-foundation-models (on-device), via {CHAT_BIN}")
    if drive.DRAW != 1:
        print(f"draw {drive.DRAW}")

    # The model half, swapped in. `run()` resolves `chat` out of its own module globals at call
    # time, so this is the whole of the substitution.
    drive.chat = chat

    try:
        print("MCP revision negotiated:", drive.handshake())
        threading.Thread(target=drive.keepalive, daemon=True).start()
        tools = drive.mcp("tools/list")["result"]["tools"]
        drive.adopt_fence(tools)
        # Measured as the ollama rows measure it, through the same helper, so the two backends'
        # surfaces are comparable rather than merely similar. `fm_chat` reads this shape too.
        offered = drive.as_ollama(tools)
        wire = json.dumps(offered, separators=(",", ":"))
        surface = len(wire)
        print(f"tools offered: {len(tools)} ({surface} B, measured as the ollama rows are)")
        if drive.SCENARIO:
            print("scenario: sessions are kept between tasks")
        drive.snapshot_existing()
        tasks = drive.load_tasks(sys.argv[1]) if len(sys.argv) > 1 else [
            "What debug sessions do I currently have open on this server?"
        ]
        cell = {
            "run": os.environ.get("EVAL_RUN", time.strftime("%Y%m%dT%H%M%S")),
            "backend": "fm",
            "model": "apple-foundation-models",
            # Null rather than absent, both of them, and for the reason the docstring gives: this
            # backend *refuses* these axes rather than quietly running without them.
            "num_ctx": None,
            "seed": None,
            "think": False,
            # **Which draw this process is.** `local_model_eval.draw_of()` reads a record with no
            # `draw` as draw 1 - deliberately, so logs recorded before draws existed still grade -
            # which means omitting it does not fail, it silently collapses every draw of a cell
            # onto draw 1 and the grader's `(cell, draw, task)` dedup keeps only the last. A
            # five-draw rate would be recorded, and graded, as one sighting.
            "draw": drive.DRAW,
            "server": dict(drive.SERVER_INFO) or None,
            "suite": dict(drive.SUITE) or None,
            "surface": {"client": os.environ.get("EVAL_SURFACE", ""),
                        "tools": len(tools), "bytes": surface,
                        "names": sorted(t["name"] for t in tools),
                        "digest": drive.surface_digest(wire)},
        }
        transcript = None
        for i, task in enumerate(tasks, 1):
            prompt = task["prompt"] if isinstance(task, dict) else task
            print(f"\n=== task {i}: {prompt[:110]}")
            FM_TURNS.clear()
            transcript, report = drive.run(task, offered, transcript)
            # Per task, beside the turns `run()` recorded, so a reader can tell a measured count
            # from a `Response.usage` one and can see the surface the model was actually built.
            report["fm"] = {"turns": list(FM_TURNS)}
            drive.write_record(dict(cell, **runtime_identity(), **report))
            if not drive.SCENARIO:
                transcript = None
                drive.release_what_this_run_opened()
    finally:
        drive.release_what_this_run_opened()
        drive.close_transport_session()
        cleanup_binary()


if __name__ == "__main__":
    main()
