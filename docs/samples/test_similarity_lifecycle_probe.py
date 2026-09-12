"""Offline finalization failures; no Binary Ninja installation or GUI required."""

import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

spec = importlib.util.spec_from_file_location(
    "lifecycle_probe",
    Path(__file__).with_name("similarity-lifecycle-probe-20260911.py"),
)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
handoff_spec = importlib.util.spec_from_file_location(
    "handoff_probe", Path(__file__).with_name("similarity-windbg-probe-20260911.py")
)
handoff_probe = importlib.util.module_from_spec(handoff_spec)
handoff_spec.loader.exec_module(handoff_probe)


class FinalizationTests(unittest.TestCase):
    def finish(self, failure=None, modal=False, handoff=False, listener_alive=False):
        report = {"ok": True, "error": "original capture failure"}
        events = []

        def stage(name):
            events.append(name)
            if name == failure:
                raise RuntimeError(name + " failed")

        def connect(callback):
            stage("quit_hook")
            application.callback = callback

        def execute(action):
            self.assertEqual(action, "Quit")
            stage("quit")
            if hasattr(application, "callback"):
                application.callback()

        def ui_context():
            assert not modal, "modal dialog active"
            return SimpleNamespace(getCurrentActionHandler=lambda: handler)

        view = SimpleNamespace(file=SimpleNamespace(modified=True))
        file_context = SimpleNamespace(
            getOpenFileContexts=lambda: [
                SimpleNamespace(getAllDataViews=lambda: [view])
            ]
        )
        handler = SimpleNamespace(isValidAction=lambda _: True, executeAction=execute)
        application = SimpleNamespace(aboutToQuit=SimpleNamespace(connect=connect))
        plugin = SimpleNamespace(
            shutdown=lambda: stage("plugin_shutdown"),
            listener=SimpleNamespace(
                thread=SimpleNamespace(is_alive=lambda: listener_alive)
            ),
        )
        save = Mock(side_effect=lambda: stage("save"))
        if handoff:
            handoff_probe.finish_gui(
                plugin, file_context, application, ui_context, report, save
            )
            return report, events, view
        probe.finish_gui(
            SimpleNamespace(stop=lambda: stage("timer_stop")),
            object(),
            plugin,
            file_context,
            SimpleNamespace(
                unregisterNotification=lambda _: stage("observer_unregister")
            ),
            application,
            ui_context,
            report,
            save,
        )
        return report, events, view

    def test_live_listener_fails_acceptance_but_still_attempts_quit(self):
        for handoff in (False, True):
            with self.subTest(handoff=handoff):
                report, events, view = self.finish(handoff=handoff, listener_alive=True)
                self.assertTrue(report["listener_thread_alive_after_shutdown"])
                self.assertFalse(report["ok"])
                self.assertEqual(report["cleanup_errors"][0]["stage"], "listener_state")
                self.assertEqual(report["error"], "original capture failure")
                self.assertFalse(view.file.modified)
                self.assertIn("quit", events)
                self.assertTrue(report["application_about_to_quit"])

    def test_handoff_shutdown_errors_still_attempt_guarded_quit(self):
        for failure in (None, "plugin_shutdown", "quit_hook", "save"):
            for modal in (False, True):
                with self.subTest(failure=failure, modal=modal):
                    report, events, view = self.finish(failure, modal, handoff=True)
                    self.assertFalse(view.file.modified)
                    self.assertEqual("quit" in events, not modal)
                    self.assertEqual(report["ok"], failure is None and not modal)
                    self.assertEqual(report["error"], "original capture failure")
                    if failure:
                        self.assertIn(
                            failure, [e["stage"] for e in report["cleanup_errors"]]
                        )

    def test_reproduction_probes_refuse_optimized_python(self):
        for name in ("similarity-lifecycle", "similarity-windbg"):
            for flag in ("-O", "-OO"):
                with self.subTest(name=name, flag=flag):
                    result = subprocess.run(
                        [
                            sys.executable,
                            flag,
                            str(Path(__file__).with_name(name + "-probe-20260911.py")),
                        ],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(
                        "acceptance probes require assertions enabled", result.stderr
                    )
                    self.assertNotIn("ModuleNotFoundError", result.stderr)

    def test_shutdown_failure_still_clears_views_and_requests_guarded_quit(self):
        report, events, view = self.finish(failure="plugin_shutdown")
        self.assertIn("quit", events)
        self.assertFalse(view.file.modified)
        self.assertTrue(report["application_about_to_quit"])
        self.assertFalse(report["ok"])
        self.assertEqual(report["error"], "original capture failure")
        self.assertEqual(report["cleanup_errors"][0]["stage"], "plugin_shutdown")

    def test_other_cleanup_failures_do_not_skip_shutdown_or_quit(self):
        for failure in ("timer_stop", "observer_unregister", "quit_hook", "save"):
            with self.subTest(failure=failure):
                report, events, _ = self.finish(failure=failure)
                self.assertIn("plugin_shutdown", events)
                self.assertIn("quit", events)
                self.assertFalse(report["ok"])

    def test_shutdown_failure_does_not_bypass_modal_guard(self):
        report, events, _ = self.finish(failure="plugin_shutdown", modal=True)
        self.assertNotIn("quit", events)
        self.assertNotIn("application_about_to_quit", report)
        self.assertEqual(
            [error["stage"] for error in report["cleanup_errors"]],
            ["plugin_shutdown", "quit"],
        )

    def test_successful_cleanup_preserves_success(self):
        report, events, view = self.finish()
        self.assertTrue(report["ok"])
        self.assertNotIn("cleanup_errors", report)
        self.assertFalse(view.file.modified)
        self.assertTrue(report["application_about_to_quit"])
        self.assertIn("quit", events)
