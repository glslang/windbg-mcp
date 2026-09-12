"""Offline cleanup regression: python3 -m unittest discover -s docs/samples -p 'test_*.py'."""

import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "handoff_probe", Path(__file__).with_name("similarity-windbg-probe-20260911.py")
)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class CleanupTests(unittest.IsolatedAsyncioTestCase):
    async def test_each_failure_still_attempts_later_cleanup_and_keeps_original_error(
        self,
    ):
        stages = ["unpair_windbg", "similarity_close", "end_session", "session_status"]
        for failure in stages + ["all", "inventory"]:
            with self.subTest(failure=failure):
                calls = []
                report = {"ok": True, "error": "original capture failure"}
                original = RuntimeError("original capture failure")

                async def call(
                    client, name, args=None, *, calls=calls, failure=failure, **kwargs
                ):
                    calls.append((client, name, args))
                    if failure in (name, "all"):
                        raise ValueError("cleanup failure: " + name)
                    return {"sessions": ["other"] if failure == "inventory" else []}

                with self.assertRaises(RuntimeError) as caught:
                    try:
                        raise original
                    finally:
                        await probe.cleanup_debugger(
                            call,
                            "local",
                            "remote",
                            "comparison",
                            "owned-session",
                            {"sessions": []},
                            report,
                        )
                self.assertIs(caught.exception, original)
                self.assertEqual([name for _, name, _ in calls], stages)
                self.assertEqual(
                    calls[2], ("remote", "end_session", {"session_id": "owned-session"})
                )
                self.assertEqual(report["error"], "original capture failure")
                self.assertFalse(report["ok"])
                self.assertEqual(
                    len(report["cleanup_errors"]), 4 if failure == "all" else 1
                )
                self.assertEqual(
                    report["session_inventory_restored"],
                    failure not in ("all", "inventory", "session_status"),
                )

    async def test_no_resource_handles_skip_only_their_cleanup(self):
        calls = []
        report = {"ok": True}

        async def call(client, name, args=None, **kwargs):
            calls.append(name)
            return {"sessions": ["preexisting"]}

        await probe.cleanup_debugger(
            call, "local", "remote", None, None, {"sessions": ["preexisting"]}, report
        )
        self.assertEqual(calls, ["unpair_windbg", "session_status"])
        self.assertTrue(report["ok"])
        self.assertTrue(report["session_inventory_restored"])
        self.assertNotIn("cleanup_errors", report)
