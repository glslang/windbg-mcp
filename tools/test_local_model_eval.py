"""Offline checks: python3 -m unittest discover -s tools -p 'test_*.py'.

**One record per backend, and every identity field asserted against what that backend claims.**
`local_model_eval.identity()` used to decide what a record contributed to each field by testing
the backend again, separately, in every place that needed it - and both times a field was added,
one backend got an answer its author had thought about and the other two got whatever fell out
(`FOLLOWUPS.md` item 80). The driver knows; the grader reads. These tests are what make the
second sentence true of a field added tomorrow: one fails if a driver does not answer it, and one
fails if the grader defaults it.
"""

import json
import os
import shutil
import tempfile
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


def scenario_suite():
    """Three steps, three facts: small enough to read every assertion against by eye."""
    return {
        "suite": "test-scenario",
        "tasks": [
            {"id": "s1", "prompt": "Open the dump. What bug check?", "possible_on": ["full", "min"]},
            {"id": "s2", "prompt": "Which IRP is it about?", "possible_on": ["full", "min"]},
            {"id": "s3", "prompt": "Which driver holds it?", "possible_on": ["full"]},
        ],
        "facts": [
            {"id": "code", "step": "s1", "expect": [["0x9f"]]},
            {"id": "irp", "step": "s2", "expect": [["ffffe2850787bc20"]]},
            {"id": "owner", "step": "s3", "expect": [["nvlddmkm"]]},
        ],
    }


def step_record(suite, step, answer, tokens, conversation="c1", client="full", **extra):
    """One step's record as the driver writes it - a turn per prompt-token figure."""
    prompt = next(t["prompt"] for t in suite["tasks"] if t["id"] == step)
    return {"task": step, "prompt": prompt, "backend": "ollama", "model": "m", "num_ctx": None,
            "draw": 1, "conversation": conversation, "answer": answer, "calls": [],
            "turns": [{"prompt_tokens": t} for t in tokens],
            "surface": {"client": client, "names": []}, **extra}


class Scenario(unittest.TestCase):
    """`--scenario`: the key, the conversation as the unit, and where a run broke (item 39)."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.suite_file = os.path.join(self.dir, "scenario.json")
        with open(self.suite_file, "w", encoding="utf-8") as f:
            json.dump(scenario_suite(), f)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def log(self, *lines):
        path = os.path.join(self.dir, "run.jsonl")
        with open(path, "w", encoding="utf-8") as f:
            f.writelines(json.dumps(line) + "\n" for line in lines)
        return path

    def grade(self, *lines):
        rows, _ = evaluator.grade_scenario(self.log(*lines), self.suite_file)
        self.assertEqual(len(rows), 1)
        return rows[0]

    def test_a_late_fact_is_a_recovery_and_the_first_missing_one_is_the_break(self):
        suite = scenario_suite()
        row = self.grade(
            step_record(suite, "s1", "Bug check 0x9F.", [1000, 1400]),
            step_record(suite, "s2", "I could not tell.", [1900]),
            step_record(suite, "s3", "IRP ffffe285`0787bc20; I cannot name the driver.",
                        [2500, 3100, 3600]))
        self.assertEqual([f["stated_at"] for f in row["facts"]], [1, 3, None])
        self.assertEqual(row["late"], ["irp"])
        # Turns are counted across the conversation, and a fact's turn is the one that answered.
        self.assertEqual([f["turn"] for f in row["facts"]], [2, 6, None])
        self.assertEqual(row["facts"][1]["prompt_tokens"], 3600)
        self.assertEqual((row["held"], row["stated"], row["of"]), (2, 2, 3))
        self.assertEqual(row["broke"]["fact"], "owner")
        self.assertEqual(row["broke"]["cause"], "answer")
        self.assertEqual(row["broke"]["prompt_tokens"], 3600)
        self.assertEqual(row["peak_prompt_tokens"], 3600)

    def test_a_fact_in_an_earlier_answer_does_not_count_before_it_is_asked(self):
        """The failure bucket `0x9F_3_ACPI_IMAGE_pci.sys` carries `acpi` at step 1 of the real one."""
        suite = scenario_suite()
        row = self.grade(
            step_record(suite, "s1", "0x9f, and !analyze guesses nvlddmkm", [100]),
            step_record(suite, "s2", "ffffe2850787bc20", [200]),
            step_record(suite, "s3", "pci", [300]))
        self.assertIsNone(row["facts"][2]["stated_at"])
        self.assertEqual(row["broke"]["fact"], "owner")

    def test_a_break_on_a_step_the_surface_cannot_answer_is_the_surfaces(self):
        suite = scenario_suite()
        row = self.grade(
            step_record(suite, "s1", "0x9f", [100], client="min"),
            step_record(suite, "s2", "ffffe2850787bc20", [200], client="min"),
            step_record(suite, "s3", "pci", [300], client="min"))
        self.assertEqual(row["broke"]["cause"], "surface")

    def test_a_chat_that_failed_is_an_error_whatever_the_surface(self):
        """A window too small for the transcript is this, and it is the reading the mode is for."""
        suite = scenario_suite()
        # On `min`, whose `s3` is not possible - so the cause has to come from the chat failing.
        row = self.grade(
            step_record(suite, "s1", "0x9f", [7900], client="min"),
            step_record(suite, "s2", "ffffe2850787bc20", [8100], client="min"),
            step_record(suite, "s3", None, [], client="min", error="context window exceeded"))
        self.assertEqual(row["broke"]["cause"], "error")
        self.assertEqual(row["broke"]["error"], "context window exceeded")
        self.assertIsNone(row["broke"]["prompt_tokens"])

    def test_a_conversation_that_stopped_early_says_where(self):
        suite = scenario_suite()
        row = self.grade(step_record(suite, "s1", "0x9f", [100]))
        self.assertEqual(row["cut_short"], 2)
        self.assertEqual((row["broke"]["fact"], row["broke"]["cause"]), ("irp", "not reached"))

    def test_the_last_conversation_is_graded_and_its_kill_note_is_its_own(self):
        """The id is what keeps two attempts apart: deduplicating by task would splice them."""
        suite = scenario_suite()
        row = self.grade(
            step_record(suite, "s1", "0x9f", [100], conversation="a"),
            step_record(suite, "s2", "ffffe2850787bc20", [200], conversation="a"),
            {"task": None, "backend": "ollama", "model": "m", "num_ctx": None, "draw": 1,
             "surface": {"client": "full"}, "conversation": "a", "error": "budget"},
            step_record(suite, "s1", "0x9f", [100], conversation="b"),
            {"task": None, "backend": "ollama", "model": "m", "num_ctx": None, "draw": 1,
             "surface": {"client": "full"}, "conversation": "b", "error": "killed again"})
        self.assertEqual((row["conversation"], row["attempts"]), ("b", 2))
        self.assertEqual(row["broke"]["fact"], "irp")
        self.assertEqual(row["broke"]["cause"], "not reached")
        self.assertEqual(row["note"], "killed again")

    def test_a_conversation_killed_before_its_first_record_is_still_the_last(self):
        suite = scenario_suite()
        row = self.grade(
            step_record(suite, "s1", "0x9f", [100], conversation="a"),
            step_record(suite, "s2", "ffffe2850787bc20", [200], conversation="a"),
            {"task": None, "backend": "ollama", "model": "m", "num_ctx": None, "draw": 1,
             "surface": {"client": "full"}, "conversation": "b", "error": "budget"})
        self.assertEqual((row["conversation"], row["held"]), ("b", 0))
        self.assertEqual(row["broke"]["cause"], "not reached")

    def test_a_reworded_step_uncounts_the_whole_conversation(self):
        suite = scenario_suite()
        reworded = step_record(suite, "s2", "ffffe2850787bc20", [200])
        reworded["prompt"] = "an older wording"
        row = self.grade(step_record(suite, "s1", "0x9f", [100]), reworded)
        self.assertEqual(row["uncounted"], ["s2"])

    def test_a_log_holding_a_run_that_was_not_a_scenario_is_refused(self):
        suite = scenario_suite()
        loose = step_record(suite, "s1", "0x9f", [100])
        del loose["conversation"]
        with self.assertRaises(SystemExit):
            self.grade(step_record(suite, "s1", "0x9f", [100]), loose)

    def test_every_per_task_reader_refuses_a_scenario_log(self):
        """One gate in `records()`, which `--grade`, `--matrix`, `--compare` and `--series` share."""
        path = self.log(step_record(scenario_suite(), "s1", "0x9f", [100]))
        with self.assertRaises(SystemExit) as refused:
            evaluator.records(path)
        self.assertIn("--scenario", str(refused.exception))


class ScenarioKey(unittest.TestCase):
    def refused(self, suite):
        with self.assertRaises(SystemExit) as refused:
            evaluator.scenario_key(suite)
        return str(refused.exception)

    def test_facts_out_of_step_order_are_refused(self):
        suite = scenario_suite()
        suite["facts"].reverse()
        self.assertIn("before the fact listed ahead of it", self.refused(suite))

    def test_a_fact_no_step_asks_for_is_refused(self):
        suite = scenario_suite()
        suite["facts"][0]["step"] = "s9"
        self.assertIn("which the suite has not got", self.refused(suite))

    def test_an_empty_group_is_refused_since_it_passes_every_answer(self):
        suite = scenario_suite()
        suite["facts"][1]["expect"] = [["ffffe2850787bc20"], []]
        self.assertIn("empty one", self.refused(suite))

    def test_a_fact_a_prompt_hands_over_is_refused(self):
        suite = scenario_suite()
        suite["tasks"][2]["prompt"] = "Does nvlddmkm hold it?"
        self.assertIn("repeating the question", self.refused(suite))

    def test_the_shipped_scenario_agrees_with_its_own_bindings(self):
        """Offline half of `--verify-key`: every unit's binding sends only what the run knows by
        then, and every `expect` alternative renders from - or is a spelling of - what its own pins
        say the server answers. The live half is the same check against what the server *does*."""
        suite = evaluator.load(os.path.join(os.path.dirname(__file__), "eval_scenario.json"))
        for unit in evaluator.scenario_units(suite):
            with self.subTest(fact=unit["id"]):
                self.assertEqual(evaluator.prompt_renders_binding(unit), [])
                pinned = {i: [evaluator.rendered(pin.get("is", pin.get("has")))
                              for pin in step.get("pin") or []]
                          for i, step in enumerate(unit["verify"])}
                held = {i: {pin["read"] for pin in step.get("pin") or []}
                        for i, step in enumerate(unit["verify"])}
                how, failures = evaluator.grounding(unit, pinned, held, set(pinned))
                self.assertEqual(failures, [])
                self.assertEqual(set(how.values()), {"value"})

    def test_a_scenario_plan_refuses_a_driver_with_no_transcript_and_a_subset(self):
        suite = scenario_suite()
        for group in ({"backend": "claude-code", "models": ["opus"]},
                      {"backend": "ollama", "models": ["m"], "subset": "short"}):
            with self.subTest(group=group), self.assertRaises(SystemExit):
                evaluator.scenario_cells_are_drivable({"cells": [group]}, suite)
        evaluator.scenario_cells_are_drivable({"cells": [{"backend": "ollama"}]}, suite)


if __name__ == "__main__":
    unittest.main()
