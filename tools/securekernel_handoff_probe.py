"""Read-only handoff from an existing comparison to a paused Secure Kernel session.

Requires the companion's Python 3.13 / mcp 2.2.0 environment for the CLI.
The capture core and its tests use only the standard library.
"""

import argparse
import asyncio
import copy
import hashlib
import json
from contextlib import AsyncExitStack
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit


class Refused(RuntimeError):
    """A failed acceptance condition, with a credential-free reason."""


def require(condition, message):
    if not condition:
        raise Refused(message)


def validate_connection(config):
    """Require an authenticated HTTPS endpoint before constructing a bearer client."""
    url = urlsplit(config["url"])
    require(
        url.scheme == "https"
        and url.hostname
        and not any((url.username, url.password, url.query, url.fragment)),
        "connection requires HTTPS without URL credentials",
    )
    require(
        isinstance(config.get("token"), str) and config["token"], "missing bearer token"
    )
    return config


def connection(path):
    return validate_connection(json.loads(Path(path).read_text(encoding="utf-8-sig")))


def identity_matches(left, right):
    if any(
        left.get(k) is None or left.get(k) != right.get(k)
        for k in ("timestamp", "size")
    ):
        return False
    a, b = left.get("pdb"), right.get("pdb")
    if (a and a.get("unmatched")) or (b and b.get("unmatched")):
        return False
    return not (a and b) or (
        str(a.get("guid", "")).replace("-", "").casefold()
        == str(b.get("guid", "")).replace("-", "").casefold()
        and a.get("age") == b.get("age")
    )


def basename(value):
    return value.replace("\\", "/").rsplit("/", 1)[-1].casefold()


def paused_location(data):
    require(
        data.get("status") == "ok" and data.get("location_state") == "mapped",
        "paused mapped execution context unavailable",
    )
    require(
        data.get("address") and data.get("coordinate"),
        "instruction pointer unavailable",
    )
    return {k: data.get(k) for k in ("address", "thread", "processor", "coordinate")}


def session_row(data, session_id):
    rows = [s for s in data["sessions"] if s["session_id"] == session_id]
    require(len(rows) == 1, "selected session missing or ambiguous")
    row = rows[0]
    state = row.get("state")
    if isinstance(state, dict):
        state = state.get("state")
    require(state == "open" and row.get("live") is True, "session is not open")
    require(row.get("kind") == "kernel", "session is not a live remote kernel")
    execution = row.get("execution")
    # session_status omits execution before the first continue_async run.
    # current_location below must still prove a readable, mapped stop.
    require(
        execution is None
        or (isinstance(execution, dict) and execution.get("stopped") is True),
        "async execution is running or its state is unavailable",
    )
    return row


class Calls:
    def __init__(self, client, side, report, save):
        self.client, self.side, self.report, self.save = client, side, report, save

    async def discover(self, expected):
        tools, cursor, seen = {}, None, set()
        while True:
            listing = await self.client.list_tools(
                **({"cursor": cursor} if cursor else {})
            )
            tools.update({tool.name: tool for tool in listing.tools})
            cursor = getattr(listing, "next_cursor", None)
            if not cursor:
                break
            require(cursor not in seen, "tool pagination did not advance")
            seen.add(cursor)
        for name, fields in expected.items():
            require(name in tools, f"missing {self.side} tool: {name}")
            schema = tools[name].input_schema
            require(
                set(fields) <= set(schema.get("properties", {})),
                f"unsupported {name} schema",
            )
            require(
                bool(tools[name].output_schema), f"missing structured {name} output"
            )
        self.report.setdefault("schemas", {})[self.side] = {
            name: hashlib.sha256(
                json.dumps(
                    {
                        "input": tools[name].input_schema,
                        "output": tools[name].output_schema,
                    },
                    sort_keys=True,
                ).encode()
            ).hexdigest()
            for name in expected
        }
        self.save()

    async def call(self, name, arguments=None, *, label=None, allow_error=False):
        arguments = arguments or {}
        allowed = {
            "remote": {
                "session_status",
                "current_location",
                "modules",
                "registers",
                "read_memory",
                "execute",
            },
            "companion": {"list_binaries", "similarity_diff", "navigate"},
        }
        require(name in allowed[self.side], "probe attempted a forbidden tool")
        if name == "execute":
            require(
                arguments
                == {
                    "session_id": arguments.get("session_id"),
                    "command": "bl",
                    "timeout_ms": 5000,
                },
                "only the fixed bl command is permitted",
            )
        response = await self.client.call_tool(name, arguments)
        data = response.structured_content
        require(isinstance(data, dict), f"{name} has no structured response")
        # The local report is private: server responses may include target paths.
        self.report["calls"][label or f"{self.side}.{name}"] = {
            "is_error": response.is_error,
            "data": data,
        }
        self.save()
        if not allow_error:
            require(
                not response.is_error
                and data.get("status") not in ("error", "unavailable", "uncertain"),
                f"{name} refused",
            )
        return data


def breakpoint_snapshot(data):
    require(
        not any(data.get(k) for k in ("timed_out", "interrupted", "target_gone")),
        "breakpoint listing was incomplete",
    )
    require(isinstance(data.get("output"), str), "breakpoint listing unavailable")
    return data["output"]


async def capture(
    remote,
    companion,
    *,
    session_id,
    binary_id,
    comparison_id,
    result_id,
    size=32,
    save=lambda report: None,
):
    report = {
        "schema_version": 1,
        "item": 62,
        "status": "failed",
        "calls": {},
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "cleanup_errors": [],
        "session_preserved": False,
    }

    def persist():
        save(report)

    r, c = (
        Calls(remote, "remote", report, persist),
        Calls(companion, "companion", report, persist),
    )
    baseline = None
    try:
        require(type(size) is int and 1 <= size <= 256, "size must be 1–256 bytes")
        require(
            all(
                isinstance(v, str) and v
                for v in (session_id, binary_id, comparison_id, result_id)
            ),
            "explicit IDs required",
        )
        await r.discover(
            {
                "session_status": ["session_id"],
                "current_location": ["session_id"],
                "modules": ["session_id", "filter", "limit"],
                "registers": ["session_id"],
                "read_memory": ["session_id", "coordinate", "size"],
                "execute": ["session_id", "command", "timeout_ms"],
            }
        )
        await c.discover(
            {
                "list_binaries": [],
                "similarity_diff": ["comparison_id", "result_id"],
                "navigate": ["binary_id", "coordinate", "expected_generation"],
            }
        )
        sessions = await r.call("session_status", label="sessions_before")
        selected = session_row(sessions, session_id)
        args = {"session_id": session_id}
        before = paused_location(
            await r.call("current_location", args, label="location_before")
        )
        require(
            basename(before["coordinate"].get("image_name", "")) == "securekernel.exe",
            "stopped instruction does not establish Secure Kernel context",
        )
        bl_args = {**args, "command": "bl", "timeout_ms": 5000}
        breakpoints = breakpoint_snapshot(
            await r.call("execute", bl_args, label="breakpoints_before")
        )
        baseline = (
            sorted(s["session_id"] for s in sessions["sessions"]),
            selected["engine_pid"],
            before,
            breakpoints,
        )
        binaries = (await c.call("list_binaries"))["binaries"]
        matching = [b for b in binaries if b["binary_id"] == binary_id]
        require(len(matching) == 1, "selected companion binary missing or ambiguous")
        binary = matching[0]
        require(
            basename(binary.get("image_name", "")) == "securekernel.exe",
            "wrong static image",
        )
        require(
            binary.get("architecture") in ("aarch64", "x86_64"),
            "unsupported architecture",
        )
        require(not binary.get("modified"), "selected static image is modified")
        diff = await c.call(
            "similarity_diff",
            {
                "comparison_id": comparison_id,
                "result_id": result_id,
                "offset": 0,
                "limit": 1,
            },
        )
        target, reference = diff["result"]["target"], diff["result"]["reference"]
        require(
            target["binary_id"] == binary_id
            and target["generation"] == binary["generation"],
            "selected match is stale or belongs to another binary",
        )
        coordinate = target["coordinate"]
        require(
            identity_matches(binary["identity"], coordinate["identity"]),
            "static identity mismatch",
        )
        require(
            basename(coordinate["image_name"]) == "securekernel.exe"
            and coordinate["module"].casefold() == "securekernel",
            "wrong match image",
        )
        rva = int(coordinate["rva"], 16)
        require(
            0 <= rva and rva + size <= coordinate["identity"]["size"],
            "read outside selected image",
        )
        require(
            not identity_matches(
                coordinate["identity"], reference["coordinate"]["identity"]
            ),
            "comparison does not provide a distinct wrong-build identity",
        )
        modules = await r.call(
            "modules", {**args, "filter": "securekernel", "limit": 2000}
        )
        require(
            modules["matched"] == len(modules["modules"]) == 1,
            "loaded image missing or ambiguous",
        )
        module = modules["modules"][0]
        require(
            basename(module["image_name"]) == "securekernel.exe"
            and identity_matches(coordinate["identity"], module)
            and identity_matches(
                coordinate["identity"], before["coordinate"]["identity"]
            ),
            "loaded Secure Kernel identity mismatch",
        )
        registers = await r.call("registers", args)
        names = {v["name"].casefold() for v in registers["registers"]}
        expected = (
            {"pc", "x0"} if binary["architecture"] == "aarch64" else {"rip", "rax"}
        )
        require(expected <= names, "register set does not match selected architecture")
        report["architecture_evidence"] = {
            "static": binary["architecture"],
            "register_names": sorted(expected),
        }
        await c.call(
            "navigate",
            {
                "binary_id": binary_id,
                "coordinate": coordinate,
                "expected_generation": target["generation"],
            },
        )
        read = await r.call(
            "read_memory",
            {**args, "coordinate": coordinate, "size": size},
            label="guarded_read",
        )
        raw = bytes.fromhex(read["data"])
        require(
            read["requested_size"] == size
            and read["read_size"] == len(raw)
            and 0 < len(raw) <= size,
            "read returned no usable bytes or inconsistent lengths",
        )
        require(
            int(read["address"], 16) == int(module["start"], 16) + rva,
            "read returned an unexpected runtime address",
        )
        report["partial_read"] = len(raw) < size
        wrong = copy.deepcopy(coordinate)
        wrong["identity"] = reference["coordinate"]["identity"]
        refusal = await r.call(
            "read_memory",
            {**args, "coordinate": wrong, "size": size},
            label="wrong_build_read",
            allow_error=True,
        )
        error = refusal.get("error", {})
        require(
            refusal.get("status") == "error"
            and error.get("category") == "debugger"
            and error.get("message")
            in ("coordinate PE identity mismatch", "coordinate PDB identity mismatch")
            and error.get("session_id") == session_id,
            "wrong build was not refused for identity mismatch",
        )
        after_binaries = (await c.call("list_binaries", label="binaries_after"))[
            "binaries"
        ]
        (after_binary,) = [b for b in after_binaries if b["binary_id"] == binary_id]
        require(
            all(
                after_binary.get(k) == binary.get(k)
                for k in ("generation", "identity", "modified", "file_sha256")
            ),
            "static input changed",
        )
        report["status"] = "passed"
    except Exception as error:
        report["error"] = (
            str(error) if isinstance(error, Refused) else type(error).__name__
        )
    finally:
        if baseline is not None:
            # Independent checks still run after any capture failure. No debugger cleanup mutation.
            observed = {}
            for label, name, arguments in (
                ("sessions_after", "session_status", {}),
                ("location_after", "current_location", {"session_id": session_id}),
                (
                    "breakpoints_after",
                    "execute",
                    {"session_id": session_id, "command": "bl", "timeout_ms": 5000},
                ),
            ):
                try:
                    observed[label] = await r.call(name, arguments, label=label)
                except Exception as error:
                    report["cleanup_errors"].append(
                        {"stage": label, "error": type(error).__name__}
                    )
            try:
                ids, pid, location, breakpoints = baseline
                final = observed["sessions_after"]
                require(
                    sorted(s["session_id"] for s in final["sessions"]) == ids,
                    "session inventory changed",
                )
                require(
                    session_row(final, session_id)["engine_pid"] == pid,
                    "worker replaced",
                )
                require(
                    paused_location(observed["location_after"]) == location,
                    "execution context changed",
                )
                require(
                    breakpoint_snapshot(observed["breakpoints_after"]) == breakpoints,
                    "breakpoints changed",
                )
                report["session_preserved"] = True
            except Exception as error:
                report["cleanup_errors"].append(
                    {
                        "stage": "preservation",
                        "error": str(error)
                        if isinstance(error, Refused)
                        else type(error).__name__,
                    }
                )
        if not report["session_preserved"] or report["cleanup_errors"]:
            report["status"] = "failed"
        persist()
    return report


async def connected(stack, config):
    validate_connection(config)
    import httpx2
    from mcp import Client
    from mcp.client.streamable_http import streamable_http_client

    http = await stack.enter_async_context(
        httpx2.AsyncClient(
            headers={"Authorization": "Bearer " + config["token"]},
            verify=True,
            trust_env=False,
            follow_redirects=False,
            timeout=30,
        )
    )
    return await stack.enter_async_context(
        Client(streamable_http_client(config["url"], http_client=http))
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("windbg-connection", "companion-connection", "output"):
        parser.add_argument("--" + option, type=Path, required=True)
    for option in ("session-id", "binary-id", "comparison-id", "result-id"):
        parser.add_argument("--" + option, required=True)
    parser.add_argument("--size", type=int, default=32)
    args = parser.parse_args()
    configs = [
        connection(args.windbg_connection),
        connection(args.companion_connection),
    ]

    def save(report):
        # Keep potentially sensitive target paths in a user-only local report.
        args.output.touch(mode=0o600, exist_ok=True)
        args.output.chmod(0o600)
        args.output.write_text(json.dumps(report, indent=2) + "\n")

    async def run():
        report = None
        try:
            async with AsyncExitStack() as stack:
                remote = await connected(stack, configs[0])
                companion = await connected(stack, configs[1])
                report = await capture(
                    remote,
                    companion,
                    session_id=args.session_id,
                    binary_id=args.binary_id,
                    comparison_id=args.comparison_id,
                    result_id=args.result_id,
                    size=args.size,
                    save=save,
                )
        except Exception as error:
            report = report or {
                "schema_version": 1,
                "item": 62,
                "calls": {},
                "cleanup_errors": [],
            }
            report["status"] = "failed"
            report["cleanup_errors"].append(
                {"stage": "connections", "error": type(error).__name__}
            )
            save(report)
        return report

    report = asyncio.run(run())
    print("Secure Kernel handoff:", report["status"])
    raise SystemExit(0 if report["status"] == "passed" else 1)


if __name__ == "__main__":
    main()
