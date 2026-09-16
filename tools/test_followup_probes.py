"""Offline checks: python3 -m unittest discover -s tools -p test_followup_probes.py."""

import copy
import json
import hashlib
import os
import shutil
import importlib.util
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, call, patch

import bn_followup_gui as gui
import bn_followup_probe as launcher
import clrbhb_decoder_compare as decoder
import securekernel_handoff_probe as handoff

IDENTITY = {"timestamp": 2, "size": 0x200000}
COORDINATE = {
    "module": "securekernel",
    "image_name": "securekernel.exe",
    "identity": IDENTITY,
    "rva": "0x1000",
}
BINARY = {
    "binary_id": "target",
    "generation": ["target", 0x140000000, 5],
    "identity": IDENTITY,
    "image_name": "securekernel.exe",
    "architecture": "aarch64",
    "modified": False,
    "file_sha256": "ab" * 32,
}
SESSION = {
    "session_id": "session",
    "kind": "kernel",
    "state": {"state": "open"},
    "live": True,
    "engine_pid": 10,
    "execution": {"stopped": True},
}
LOCATION = {
    "status": "ok",
    "location_state": "mapped",
    "coordinate": COORDINATE,
    "address": "0xffff800000001000",
    "processor": 0,
    "thread": None,
}


class Client:
    def __init__(self, side):
        self.side, self.calls, self.overrides = side, [], {}

    async def list_tools(self):
        fields = {
            "session_status": ["session_id"],
            "current_location": ["session_id"],
            "modules": ["session_id", "filter", "limit"],
            "registers": ["session_id"],
            "read_memory": ["session_id", "coordinate", "size"],
            "execute": ["session_id", "command", "timeout_ms"],
            "list_binaries": [],
            "similarity_diff": ["comparison_id", "result_id"],
            "navigate": ["binary_id", "coordinate", "expected_generation"],
        }
        return SimpleNamespace(
            tools=[
                SimpleNamespace(
                    name=k,
                    input_schema={"properties": dict.fromkeys(v, {})},
                    output_schema={"type": "object"},
                )
                for k, v in fields.items()
            ],
            next_cursor=None,
        )

    async def call_tool(self, name, args):
        # Enforce the independent recording client's mutation barrier too.
        assert name in (
            "session_status",
            "current_location",
            "modules",
            "registers",
            "read_memory",
            "execute",
            "list_binaries",
            "similarity_diff",
            "navigate",
        )
        if name == "execute":
            assert args == {
                "session_id": "session",
                "command": "bl",
                "timeout_ms": 5000,
            }
        self.calls.append((name, copy.deepcopy(args)))
        count = sum(n == name for n, _ in self.calls)
        if name == "session_status":
            data = {"status": "ok", "sessions": [SESSION]}
        elif name == "current_location":
            data = LOCATION
        elif name == "execute":
            data = {"status": "ok", "output": "bl\n", "timed_out": False}
        elif name == "modules":
            data = {
                "status": "ok",
                "matched": 1,
                "modules": [
                    {
                        "image_name": "securekernel.exe",
                        "start": "0xffff800000000000",
                        **IDENTITY,
                    }
                ],
            }
        elif name == "registers":
            data = {"status": "ok", "registers": [{"name": "pc"}, {"name": "x0"}]}
        elif name == "list_binaries":
            data = {"binaries": [BINARY]}
        elif name == "similarity_diff":
            reference = copy.deepcopy(COORDINATE)
            reference["identity"]["timestamp"] = 1
            data = {
                "result": {
                    "target": {
                        "binary_id": "target",
                        "generation": BINARY["generation"],
                        "coordinate": COORDINATE,
                    },
                    "reference": {"coordinate": reference},
                }
            }
        elif name == "navigate":
            data = {"coordinate": COORDINATE}
        elif args["coordinate"]["identity"]["timestamp"] == 2:
            data = {
                "status": "ok",
                "address": "0xffff800000001000",
                "requested_size": args["size"],
                "read_size": args["size"],
                "data": "df" * args["size"],
            }
        else:
            data = {
                "status": "error",
                "error": {
                    "category": "debugger",
                    "session_id": "session",
                    "message": "coordinate PE identity mismatch",
                },
            }
        data = copy.deepcopy(data)
        override = self.overrides.get((name, count), self.overrides.get(name))
        if override:
            data = override(data)
        return SimpleNamespace(
            structured_content=data, is_error=data.get("status") == "error"
        )


def change(**fields):
    return lambda data: {**data, **fields}


class HandoffTests(unittest.IsolatedAsyncioTestCase):
    async def run_capture(self, remote=None, companion=None, **kwargs):
        return await handoff.capture(
            remote or Client("remote"),
            companion or Client("companion"),
            session_id="session",
            binary_id="target",
            comparison_id="comparison",
            result_id="match",
            **kwargs,
        )

    async def test_read_and_wrong_build_refusal_preserve_session(self):
        remote = Client("remote")
        result = await self.run_capture(remote)
        self.assertEqual(result["status"], "passed", result)
        self.assertTrue(result["session_preserved"])
        self.assertEqual(sum(name == "read_memory" for name, _ in remote.calls), 2)

    async def test_running_target_rejected_before_read(self):
        remote = Client("remote")
        remote.overrides["session_status"] = change(
            sessions=[{**SESSION, "execution": {"stopped": False}}]
        )
        result = await self.run_capture(remote)
        self.assertEqual(result["status"], "failed")
        self.assertFalse(any(n == "read_memory" for n, _ in remote.calls))

    async def test_malformed_execution_state_refused_before_read(self):
        for execution in (
            {},
            {"stopped": None},
            {"stopped": 1},
            {"stopped": "true"},
        ):
            with self.subTest(execution=execution):
                remote = Client("remote")
                remote.overrides["session_status"] = change(
                    sessions=[{**SESSION, "execution": execution}]
                )
                result = await self.run_capture(remote)
                self.assertEqual(result["status"], "failed")
                self.assertFalse(any(n == "read_memory" for n, _ in remote.calls))
        remote = Client("remote")
        remote.overrides["session_status"] = change(
            sessions=[{k: v for k, v in SESSION.items() if k != "execution"}]
        )
        self.assertEqual((await self.run_capture(remote))["status"], "passed")
        self.assertTrue(any(n == "current_location" for n, _ in remote.calls))
        self.assertTrue(any(n == "read_memory" for n, _ in remote.calls))

    async def test_no_async_record_still_requires_successful_paused_location(self):
        for location, expected in (
            (LOCATION, "passed"),
            ({"status": "error", "error": {"category": "target_running"}}, "failed"),
            ({**LOCATION, "location_state": "unmapped"}, "failed"),
        ):
            remote = Client("remote")
            remote.overrides["session_status"] = change(
                sessions=[{**SESSION, "execution": None}]
            )
            remote.overrides["current_location"] = lambda data: location
            result = await self.run_capture(remote)
            self.assertEqual(result["status"], expected)
            self.assertEqual(
                any(n == "read_memory" for n, _ in remote.calls), expected == "passed"
            )

    async def test_connected_revalidates_transport_before_client_creation(self):
        with self.assertRaises(handoff.Refused):
            await handoff.connected(
                None, {"url": "http://localhost/mcp", "token": "secret"}
            )

    async def test_dump_or_non_secure_context_rejected(self):
        for case in ("dump", "nt"):
            with self.subTest(case=case):
                remote = Client("remote")
                if case == "dump":
                    remote.overrides["session_status"] = change(
                        sessions=[{**SESSION, "kind": "dump"}]
                    )
                else:
                    remote.overrides["current_location"] = change(
                        coordinate={**COORDINATE, "image_name": "ntoskrnl.exe"}
                    )
                result = await self.run_capture(remote)
                self.assertEqual(result["status"], "failed")
                self.assertFalse(any(n == "read_memory" for n, _ in remote.calls))

    async def test_identity_architecture_and_truncation_refuse_before_read(self):
        for name, override in (
            (
                "modules",
                change(
                    modules=[
                        {"image_name": "securekernel.exe", **IDENTITY, "timestamp": 3}
                    ]
                ),
            ),
            ("modules", change(matched=2)),
            ("registers", change(registers=[{"name": "rip"}, {"name": "rax"}])),
        ):
            with self.subTest(name=name, override=override):
                remote = Client("remote")
                remote.overrides[name] = override
                result = await self.run_capture(remote)
                self.assertEqual(result["status"], "failed")
                self.assertTrue(result["session_preserved"])
                self.assertFalse(any(n == "read_memory" for n, _ in remote.calls))

    async def test_partial_read_retained_zero_or_invalid_read_fails(self):
        for count, data, expected in (
            (4, "ab" * 4, "passed"),
            (0, "", "failed"),
            (4, "ab", "failed"),
            (4, "xx" * 4, "failed"),
        ):
            remote = Client("remote")
            remote.overrides["read_memory", 1] = change(read_size=count, data=data)
            result = await self.run_capture(remote)
            self.assertEqual(result["status"], expected)
            if expected == "passed":
                self.assertTrue(result["partial_read"])

    async def test_wrong_build_failure_must_be_identity_refusal(self):
        for category, message in (
            ("timeout", "coordinate PE identity mismatch"),
            ("debugger", "target_running"),
            ("debugger", "read failed"),
        ):
            remote = Client("remote")
            remote.overrides["read_memory", 2] = change(
                error={
                    "category": category,
                    "message": message,
                    "session_id": "session",
                }
            )
            result = await self.run_capture(remote)
            self.assertEqual(result["status"], "failed")
            self.assertIn("wrong build", result["error"])

    async def test_cleanup_failures_preserve_original_error_and_continue_checks(self):
        remote = Client("remote")

        def fail(_):
            raise OSError("credential-bearing connection error must not reach report")

        remote.overrides["modules"] = change(matched=0, modules=[])
        remote.overrides["session_status", 2] = fail
        result = await self.run_capture(remote)
        self.assertEqual(result["error"], "loaded image missing or ambiguous")
        self.assertFalse(result["session_preserved"])
        self.assertEqual(remote.calls[-1][0], "execute")
        self.assertNotIn("credential-bearing", json.dumps(result))

    async def test_changed_breakpoints_location_inventory_or_worker_fail(self):
        for name, override in (
            ("execute", change(output="bl\n0 e new breakpoint")),
            ("current_location", change(address="0xffff800000002000")),
            ("session_status", change(sessions=[])),
            ("session_status", change(sessions=[{**SESSION, "engine_pid": 11}])),
        ):
            remote = Client("remote")
            remote.overrides[name, 2] = override
            result = await self.run_capture(remote)
            self.assertEqual(result["status"], "failed")
            self.assertFalse(result["session_preserved"])

    async def test_stale_match_and_modified_binary_refused(self):
        for name, override in (
            ("list_binaries", change(binaries=[{**BINARY, "modified": True}])),
            (
                "similarity_diff",
                change(
                    result={
                        "target": {"binary_id": "target", "generation": [1]},
                        "reference": {},
                    }
                ),
            ),
        ):
            remote, companion = Client("remote"), Client("companion")
            companion.overrides[name] = override
            self.assertEqual(
                (await self.run_capture(remote, companion))["status"], "failed"
            )
            self.assertFalse(any(n == "read_memory" for n, _ in remote.calls))

    async def test_allowlist_rejects_mutations_and_arbitrary_execute(self):
        client = Client("remote")
        calls = handoff.Calls(client, "remote", {"calls": {}}, lambda: None)
        for name, args in (
            ("launch", {}),
            ("go", {}),
            ("end_session", {}),
            ("set_breakpoint", {}),
            ("execute", {"command": "bl; g"}),
            ("execute", {"command": "bl"}),
        ):
            with self.assertRaises(handoff.Refused):
                await calls.call(name, args)
        self.assertEqual(client.calls, [])

    async def test_schema_missing_coordinate_fails_before_tools(self):
        remote = Client("remote")
        listing = await remote.list_tools()
        for tool in listing.tools:
            if tool.name == "read_memory":
                del tool.input_schema["properties"]["coordinate"]

        async def missing():
            return listing

        remote.list_tools = missing
        result = await self.run_capture(remote)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(remote.calls, [])


class HelpersTests(unittest.TestCase):
    def test_connection_rejects_remote_http_and_url_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "connection.json"
            for url in (
                "http://example.org/mcp",
                "http://localhost/mcp",
                "http://127.0.0.1/mcp",
                "http://[::1]/mcp",
                "https://user:secret@example.org/mcp",
                "https://example.org/mcp?token=secret",
                "ftp://localhost/mcp",
            ):
                path.write_text(json.dumps({"url": url, "token": "secret"}))
                with self.assertRaises(handoff.Refused):
                    handoff.connection(path)

    def test_native_decode_requires_text_info_and_fallthrough(self):
        row = {
            "bytes": "df2203d5",
            "length": 4,
            "text_length": 4,
            "branches": [],
            "text": "clrbhb",
        }
        self.assertTrue(gui.decoded_clrbhb(row))
        for field, value in (
            ("text", None),
            ("length", None),
            ("text", "hint #22"),
            ("branches", ["UnconditionalBranch"]),
            ("bytes", "bf2203d5"),
        ):
            self.assertFalse(gui.decoded_clrbhb({**row, field: value}))

    def test_endpoint_analysis_requires_complete_function_and_clrbhb_lift(self):
        good = function_row()
        self.assertTrue(gui.endpoint_analysis_complete(good))
        for field, value in (
            ("llil", ["undefined", "SystemHintOp_ISB()", "jump"]),
            ("llil", None),
            ("instructions", good["function"]["instructions"][:2]),
            ("bounds", [["0x1000", "0x1008"]]),
            ("instructions_truncated", True),
            ("found", False),
        ):
            with self.subTest(field=field, value=value):
                row = copy.deepcopy(good)
                row["function"][field] = value
                self.assertFalse(gui.endpoint_analysis_complete(row))

    def test_synthetic_capture_requires_clrbhb_lift(self):
        # Drive the production call site: complete text with undefined CLRBHB IL.
        synthetic = Mock()
        bn = SimpleNamespace(
            Architecture={"aarch64": Mock()},
            BinaryView=SimpleNamespace(new=Mock(return_value=synthetic)),
        )
        modules = {
            "binaryninja": bn,
            "binaryninjaui": SimpleNamespace(UIContext=Mock()),
            "binja_windbg_mcp": SimpleNamespace(),
            "binja_windbg_mcp.adapter": SimpleNamespace(
                Workspace=Mock(), main_thread=Mock()
            ),
            "binja_windbg_mcp.similarity_adapter": SimpleNamespace(
                NativeSimilarity=Mock()
            ),
        }
        for llil, expected in (
            (["undefined", "add", "ret"], False),
            (["SystemHintOp_CLRBHB()", "add", "ret"], True),
        ):
            function = function_row(0)["function"]
            function["llil"] = llil
            report = {}
            with (
                patch.dict(sys.modules, modules),
                patch.object(gui, "decode_instruction"),
                patch.object(gui, "decoded_clrbhb", return_value=True),
                patch.object(gui, "function_evidence", return_value=function),
            ):
                gui.capture_decode({}, report, lambda: None)
            self.assertEqual(report["synthetic_analysis_passed"], expected)

    def test_exit_alone_does_not_pass_capture(self):
        for rc, forced, capture, crashes in (
            (0, True, {"ok": True}, []),
            (0, False, {}, []),
            (-6, False, {"ok": True}, []),
            (0, False, {"ok": True}, ["crash.ips"]),
        ):
            self.assertEqual(
                launcher.outcome(rc, forced, capture, crashes)["status"], "failed"
            )
        self.assertEqual(
            launcher.outcome(0, False, {"ok": True}, [])["status"], "passed"
        )

    def test_timeout_only_signals_owned_process_group(self):
        process = Mock(pid=123)
        process.poll.return_value = None
        process.wait.return_value = -15
        with patch.object(launcher.os, "killpg") as kill:
            rc, forced = launcher.wait_owned(process, 1, clock=Mock(side_effect=[0, 2]))
        self.assertTrue(forced)
        self.assertEqual(rc, -15)
        self.assertEqual(
            kill.call_args_list,
            [call(123, launcher.signal.SIGTERM), call(123, launcher.signal.SIGKILL)],
        )

    def test_cleanup_signals_group_after_leader_exits(self):
        process = Mock(pid=123)
        process.poll.return_value = 0
        process.wait.return_value = 0
        with patch.object(launcher.os, "killpg") as kill:
            rc, forced = launcher.wait_owned(process, 1)
        self.assertEqual((rc, forced), (0, True))
        self.assertEqual(
            launcher.outcome(rc, forced, {"ok": True}, [])["status"], "failed"
        )
        kill.assert_called_once_with(123, launcher.signal.SIGKILL)

    def test_clean_exit_without_descendants_passes(self):
        process = Mock(pid=123)
        process.poll.return_value = 0
        process.wait.return_value = 0
        with patch.object(launcher.os, "killpg", side_effect=ProcessLookupError):
            rc, forced = launcher.wait_owned(process, 1)
        self.assertEqual((rc, forced), (0, False))
        self.assertEqual(
            launcher.outcome(rc, forced, {"ok": True}, [])["status"], "passed"
        )

    def test_cleanup_runs_on_wait_exception(self):
        process = Mock(pid=123)
        process.poll.side_effect = RuntimeError("poll failed")
        with patch.object(launcher.os, "killpg") as kill:
            with self.assertRaisesRegex(RuntimeError, "poll failed"):
                launcher.wait_owned(process, 1)
        kill.assert_called_once_with(123, launcher.signal.SIGKILL)

    def test_cleanup_tolerates_already_absent_group(self):
        process = Mock(pid=123)
        with patch.object(launcher.os, "killpg", side_effect=ProcessLookupError):
            launcher.cleanup_owned(process)
        process.wait.assert_called_once_with(timeout=5)

    def test_timeout_escalates_when_group_ignores_term(self):
        process = Mock(pid=123)
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired("gui", 5), -9, -9]
        with patch.object(launcher.os, "killpg") as kill:
            self.assertEqual(
                launcher.wait_owned(process, 1, clock=Mock(side_effect=[0, 2])),
                (-9, True),
            )
        self.assertEqual(kill.call_args_list[0], call(123, launcher.signal.SIGTERM))
        self.assertIn(call(123, launcher.signal.SIGKILL), kill.call_args_list)


def function_row(address=0x1000):
    return {
        "address": hex(address),
        "function": {
            "found": True,
            "instructions": [
                {"address": hex(address + offset), "length": 4} for offset in (0, 4, 8)
            ],
            "instructions_truncated": False,
            "bounds": [[hex(address), hex(address + 12)]],
            "llil": ["SystemHintOp_CLRBHB()", "SystemHintOp_ISB()", "jump"],
        },
    }


class DecoderTests(unittest.TestCase):
    def test_cli_requires_baseline_failure_fixed_decode_and_unchanged_controls(self):
        bad = {"decode": -9, "format": None, "text": ""}
        good = {"decode": 0, "format": 0, "text": "clrbhb"}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            before, after, corpus, output = [
                root / n for n in ("before", "after", "corpus", "output")
            ]
            before.write_bytes(b"before")
            after.write_bytes(b"after")
            corpus.write_text("D503201F nop\n")
            args = [
                "compare",
                "--before",
                str(before),
                "--after",
                str(after),
                "--corpus",
                str(corpus),
                "--output",
                str(output),
            ]
            for baseline, fixed, changed, expected in (
                (bad, good, False, 0),
                (good, good, False, 1),
                (bad, bad, False, 1),
                (bad, good, True, 1),
            ):

                def decode(lib, word):
                    if word == 0xD50322DF:
                        return baseline if lib == before else fixed
                    return {
                        "text": "nop" if lib == before or not changed else "changed"
                    }

                with (
                    patch.object(sys, "argv", args),
                    patch.object(decoder, "library", side_effect=lambda p: p),
                    patch.object(decoder, "CORPUS_COUNT", 1),
                    patch.object(
                        decoder,
                        "CORPUS_SHA256",
                        hashlib.sha256(corpus.read_bytes()).hexdigest(),
                    ),
                    patch.object(decoder, "decode", side_effect=decode),
                    patch("builtins.print"),
                    self.assertRaises(SystemExit) as result,
                ):
                    decoder.main()
                self.assertEqual(result.exception.code, expected)

    def test_cli_rejects_unpinned_corpus_before_loading_libraries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            corpus = root / "corpus"
            args = [
                "compare",
                "--before",
                "before",
                "--after",
                "after",
                "--corpus",
                str(corpus),
                "--output",
                str(root / "result"),
            ]
            for content in (
                b"",
                b"D503201F nop\n",
                b"D503201F nop\n" * decoder.CORPUS_COUNT,
            ):
                corpus.write_bytes(content)
                with (
                    patch.object(sys, "argv", args),
                    patch.object(decoder, "library") as library,
                    self.assertRaisesRegex(SystemExit, "corpus SHA-256"),
                ):
                    decoder.main()
                library.assert_not_called()
            # Isolate the count gate from the digest gate, which also rejects
            # truncation; changing either production check must fail a test.
            with (
                patch.object(sys, "argv", args),
                patch.object(decoder, "library") as library,
                patch.object(
                    decoder, "CORPUS_SHA256", hashlib.sha256(content).hexdigest()
                ),
                patch.object(decoder, "CORPUS_COUNT", decoder.CORPUS_COUNT + 1),
                self.assertRaisesRegex(SystemExit, "corpus count"),
            ):
                decoder.main()
            library.assert_not_called()


class ComparisonTests(unittest.TestCase):
    def test_comparison_retains_counts_and_requires_paired_complete_diffs(self):
        matches = [
            {
                "result_id": str(i),
                "reference": {"coordinate": {"rva": hex(0x10FC00 + i * 0x80)}},
                "target": {"coordinate": {"rva": hex(0x11AC00 + i * 0x80)}},
            }
            for i in range(8)
        ]
        for failure in (
            None,
            "wrong_pair",
            "duplicate",
            "short_diff",
            "truncated_text",
            "wrong_clrbhb_reference",
            "wrong_clrbhb_target",
            "wrong_isb",
            "wrong_branch",
            "clrbhb_operand",
            "missing_branch_operand",
            "invalid_branch_operand",
            "wrong_branch_reference",
            "wrong_branch_target",
            "wrong_instruction_address",
        ):
            rows = copy.deepcopy(matches)
            if failure == "wrong_pair":
                rows[0]["reference"] = copy.deepcopy(rows[1]["reference"])
            if failure == "duplicate":
                rows[1] = copy.deepcopy(rows[0])

            def diff_items(result_id):
                match = matches[int(result_id)]
                items = [
                    {
                        side: {
                            "address": hex(
                                0x140000000
                                + int(match[side]["coordinate"]["rva"], 16)
                                + offset
                            ),
                            "rva": hex(
                                int(match[side]["coordinate"]["rva"], 16) + offset
                            ),
                            "text": (
                                "clrbhb",
                                "isb",
                                "b "
                                + hex(
                                    0x140000000
                                    + int(match[side]["coordinate"]["rva"], 16)
                                    + 0x5000
                                ),
                            )[offset // 4],
                            "text_truncated": failure == "truncated_text",
                        }
                        for side in ("reference", "target")
                    }
                    for offset in (0, 4, 8)
                ]
                wrong_text = {
                    "wrong_clrbhb_reference": (0, "reference", "hint #22"),
                    "wrong_clrbhb_target": (0, "target", "undefined"),
                    "wrong_isb": (1, "target", "nop"),
                    "wrong_branch": (
                        2,
                        "reference",
                        items[2]["reference"]["text"].replace("b ", "bl ", 1),
                    ),
                    "clrbhb_operand": (0, "target", "clrbhb x0"),
                    "missing_branch_operand": (2, "target", "b"),
                    "invalid_branch_operand": (2, "reference", "b garbage"),
                    "wrong_branch_reference": (2, "reference", "b 0x140114c04"),
                    "wrong_branch_target": (2, "target", "b 0x14011fc04"),
                }
                if failure == "wrong_instruction_address":
                    items[0]["target"]["address"] = "0x14011ac04"
                if failure in wrong_text:
                    index, side, text = wrong_text[failure]
                    items[index][side]["text"] = text
                return items[:2] if failure == "short_diff" else items

            workspace = Mock()
            workspace.similarity.backend.backends = {"external": Mock()}
            binaries = [{"binary_id": "reference"}, {"binary_id": "target"}]
            workspace.list_binaries.return_value = {"binaries": binaries}
            workspace.acquire.side_effect = lambda key: (
                None,
                SimpleNamespace(file=SimpleNamespace(original_filename="/" + key)),
                None,
                None,
            )
            workspace.similarity.start.return_value = {"comparison_id": "comparison"}
            workspace.similarity.status.return_value = {"active": False}
            workspace.similarity.diff.side_effect = lambda *a, **kw: {
                "instructions_truncated": {"reference": False, "target": False}
            }

            def pages(method, *args, **kwargs):
                if method == workspace.similarity.diff:
                    return diff_items(args[1])
                return rows if not kwargs else [None, None]

            helper = SimpleNamespace(
                state=lambda *a: {}, pages=pages, full_acceptance=lambda *a: True
            )
            report = {}
            with (
                patch.object(gui.importlib.util, "spec_from_file_location") as spec,
                patch.object(
                    gui.importlib.util, "module_from_spec", return_value=helper
                ),
            ):
                spec.return_value.loader.exec_module.return_value = None
                ok = gui.compare_endpoints(
                    workspace,
                    {
                        "bindiff": "/bindiff",
                        "reference": "/reference",
                        "target": "/target",
                    },
                    report,
                    lambda: None,
                )
            self.assertEqual(ok, failure is None, (failure, report))
            evidence = report["comparison"]
            self.assertEqual(
                evidence["retained_results"],
                {"matches": 8, "unmatched": {"reference": 2, "target": 2}},
            )
            self.assertNotIn("matches", evidence)
            self.assertNotIn("unmatched", evidence)
            workspace.similarity.close.assert_called_once_with("comparison")


class CRegressionTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("cc"), "C regression needs a C compiler")
    def test_standalone_rejects_extra_operands_for_all_three_instructions(self):
        source = (
            Path(__file__).resolve().parents[1]
            / "docs/samples/clrbhb-native-regression.c"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "decode.h").write_text("""#pragma once
#include <stdint.h>
enum Operation { ARM64_CLRBHB, ARM64_NOP, ARM64_CSDB };
typedef struct { enum Operation operation; } Instruction;
int aarch64_decompose(uint32_t, Instruction*, uint64_t);
""")
            (root / "format.h").write_text("""#include <stddef.h>
#include "decode.h"
int aarch64_disassemble(Instruction*, char*, size_t);
""")
            stub = root / "decoder.c"
            stub.write_text("""#include <stdio.h>
#include <stdlib.h>
#include "format.h"
int aarch64_decompose(uint32_t word, Instruction* out, uint64_t address) {
    out->operation = word == 0xd50322df ? ARM64_CLRBHB :
        word == 0xd503201f ? ARM64_NOP : ARM64_CSDB;
    return 0;
}
int aarch64_disassemble(Instruction* in, char* out, size_t size) {
    const char* names[] = {"clrbhb", "nop", "csdb"};
    int inject = atoi(getenv("REGRESSION_BAD_INDEX"));
    snprintf(out, size, "%s%s", names[in->operation],
        inject == in->operation ? " unexpected" : "");
    return 0;
}
""")
            executable = root / "regression"
            subprocess.run(
                ["cc", "-I", str(root), str(source), str(stub), "-o", str(executable)],
                check=True,
                capture_output=True,
            )
            for index in (-1, 0, 1, 2):
                result = subprocess.run(
                    [str(executable)],
                    env={**os.environ, "REGRESSION_BAD_INDEX": str(index)},
                    capture_output=True,
                )
                self.assertEqual(
                    result.returncode, 0 if index == -1 else 1, result.stdout
                )


class ObjectAliasTests(unittest.TestCase):
    def test_output_argument_and_intervening_instructions_are_checked(self):
        path = (
            Path(__file__).resolve().parents[1]
            / "docs/samples/cve-2026-83498-stale-pointer-check.py"
        )
        spec = importlib.util.spec_from_file_location("stale_pointer", path)
        checker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(checker)
        for side, call_rva, target in (
            ("reference", 0x9A4A4, 0xC92D8),
            ("target", 0x9A4B4, 0xC93A0),
        ):
            raw = bytearray.fromhex("e3830091020080d200008052")
            raw += struct.pack("<I", 0x94000000 | ((target - call_rva) // 4))
            raw += bytes.fromhex("f31340f9")

            def image(data):
                return {
                    "data": data,
                    "sections": [
                        {
                            "rva": call_rva - 12,
                            "raw_offset": 0,
                            "raw_size": 20,
                            "virtual_size": 20,
                        }
                    ],
                }

            checker.object_alias(image(raw), side, call_rva)
            for offset in (0, 4, 8):
                changed = bytearray(raw)
                changed[offset : offset + 4] = bytes.fromhex("1f2003d5")
                with self.assertRaises(ValueError):
                    checker.object_alias(image(changed), side, call_rva)


if __name__ == "__main__":
    unittest.main()
