"""Offline checks: python3 -m unittest discover -s tools -p 'test_*.py'.

**One record per backend, and every identity field asserted against what that backend claims.**
`local_model_eval.identity()` used to decide what a record contributed to each field by testing
the backend again, separately, in every place that needed it - and both times a field was added,
one backend got an answer its author had thought about and the other two got whatever fell out
(`FOLLOWUPS.md` item 80). The driver knows; the grader reads. These tests are what make the
second sentence true of a field added tomorrow: one fails if a driver does not answer it, and one
fails if the grader defaults it.
"""

import os
import unittest

# **Before the drivers are imported.** `local_model_drive` resolves the run's bearer token at
# import time and exits when there is none, deliberately: a run that goes looking for a credential
# lands in the editor's namespace. Nothing below opens a socket, so a placeholder is the whole of
# what these tests need - and asking the operator for a real one to run an offline test would put
# a listener token on a command line for no reason.
os.environ.setdefault("WINDBG_MCP_TOKEN", "offline-test")

import claude_code_drive  # noqa: E402 - after the token above, which its import chain reads
import fm_drive  # noqa: E402
import local_model_drive  # noqa: E402
import local_model_eval as evaluator  # noqa: E402

# One per backend, keyed as the drivers key themselves. The value is what `identity_block` is
# handed on a healthy run: the reading it resolves into the block.
DRIVERS = {
    "ollama": (local_model_drive, "5642e97495e1a088883805981563dcdc"),
    "claude-code": (claude_code_drive, "2.1.270 (Claude Code)"),
    "fm": (fm_drive, "24G5027"),
}


def record(backend, **extra):
    """A graded record - `task` set, because a note with none carries no identity at all."""
    return {"task": "bugcheck_code", "backend": backend, "model": f"{backend}-model", **extra}


class IdentityContract(unittest.TestCase):
    def test_every_backend_answers_every_identity_field(self):
        """The check that makes a *new* field fail rather than default.

        Adding a name to `IDENTITY_FIELDS` without giving all three drivers an opinion about it
        fails here, which is the whole point: the two bugs this closed were both a field that one
        backend answered and the others inherited.
        """
        for backend, (module, reading) in DRIVERS.items():
            with self.subTest(backend=backend):
                self.assertEqual(set(module.identity_block(reading)),
                                 set(evaluator.IDENTITY_FIELDS))

    def test_a_backend_states_the_arm_it_is_running(self):
        """Only the ollama rows have the knob, and their block carries the arm, not the record."""
        think = local_model_drive.THINK
        try:
            local_model_drive.THINK = True
            self.assertEqual(local_model_drive.identity_block("d")["reasoning"], "on")
            local_model_drive.THINK = False
            self.assertEqual(local_model_drive.identity_block("d")["reasoning"], "off")
        finally:
            local_model_drive.THINK = think
        # Null rather than `off` on both backends that have no arm - an absence, not a setting.
        self.assertIsNone(claude_code_drive.identity_block("2.1.270")["reasoning"])
        self.assertIsNone(fm_drive.identity_block("24G5027")["reasoning"])

    def test_weights_is_whatever_moves_when_the_model_does(self):
        """The fm rows name the OS build; it is the only identity that moves when Apple ships."""
        self.assertEqual(fm_drive.identity_block("24G5027")["weights"], "24G5027")
        self.assertEqual(local_model_drive.identity_block("5642e9")["weights"], "5642e9")
        self.assertIsNone(claude_code_drive.identity_block("2.1.270")["weights"])


class GraderReadsTheBlock(unittest.TestCase):
    def test_each_backend_reports_what_it_claimed(self):
        rows = [record(backend, identity=module.identity_block(reading))
                for backend, (module, reading) in DRIVERS.items()]
        ident = evaluator.identity(rows)
        self.assertEqual(ident["reasoning"], ["off", evaluator.UNAVAILABLE])
        self.assertEqual(ident["harness"], ["2.1.270 (Claude Code)", evaluator.UNAVAILABLE])
        self.assertEqual(ident["weights"], {
            "claude-code-model": [evaluator.UNAVAILABLE],
            "fm-model": ["24G5027"],
            "ollama-model": ["5642e97495e1a088883805981563dcdc"],
        })

    def test_a_field_no_driver_answered_is_unrecorded_rather_than_defaulted(self):
        """The render half of the same guard: a missing answer is loud, never an arm."""
        ident = evaluator.identity([record("ollama", identity={"weights": "d", "harness": None})])
        self.assertEqual(ident["reasoning"], [evaluator.UNRECORDED])

    def test_a_null_is_not_an_absence(self):
        """`unavailable` is a row with no answer; `unrecorded` is a log that never said."""
        stated = evaluator.identity([record("ollama", identity={"weights": None,
                                                               "reasoning": "on",
                                                               "harness": None})])
        self.assertEqual(stated["weights"]["ollama-model"], [evaluator.UNAVAILABLE])
        self.assertEqual(stated["harness"], [evaluator.UNAVAILABLE])

    def test_a_cell_failure_note_carries_no_identity(self):
        """`run_cell` writes it with the cell's coordinates and nothing else."""
        ident = evaluator.identity([{"task": None, "run": "r", "backend": "ollama"}])
        self.assertEqual(ident["run"], ["r"])
        self.assertEqual(ident["reasoning"], [])
        self.assertEqual(ident["weights"], {})


class LogsWrittenBeforeTheBlock(unittest.TestCase):
    """`legacy_identity` is frozen, so what it answers for the shipped logs is pinned here."""

    def test_the_ollama_rows_keep_their_digest_and_their_arm(self):
        block = evaluator.legacy_identity(
            {"backend": "ollama", "model_digest": "5642e9", "think": True})
        self.assertEqual(block, {"weights": "5642e9", "reasoning": "on", "harness": None})

    def test_a_log_from_before_the_axis_reads_unrecorded_not_off(self):
        """No `think` is a log predating the reasoning axis, and asserting `off` would be a
        measurement nobody took."""
        block = evaluator.legacy_identity({"backend": "ollama", "model_digest": "5642e9"})
        self.assertNotIn("reasoning", block)
        self.assertEqual(
            evaluator.identity([record("ollama", model_digest="5642e9")])["reasoning"],
            [evaluator.UNRECORDED])

    def test_the_fm_rows_name_the_os_build(self):
        block = evaluator.legacy_identity(
            {"backend": "fm", "os_build": "24G5027", "model_digest": None, "think": False})
        self.assertEqual(block, {"weights": "24G5027", "reasoning": None, "harness": None})

    def test_the_claude_rows_keep_their_harness_and_gain_no_arm(self):
        block = evaluator.legacy_identity(
            {"backend": "claude-code", "model_digest": None, "harness_version": "2.1.270"})
        self.assertEqual(block, {"weights": None, "reasoning": None, "harness": "2.1.270"})

    def test_a_field_the_old_driver_never_wrote_stays_absent(self):
        """`after-206.jsonl` and friends: nobody recorded these, and nobody can now."""
        block = evaluator.legacy_identity({"backend": "claude-code"})
        self.assertNotIn("weights", block)
        self.assertNotIn("harness", block)


if __name__ == "__main__":
    unittest.main()
