"""Offline CLI checks for the reproduction inspector, using empty export graphs."""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class GraphInspectionTests(unittest.TestCase):
    def run_empty_exports(self, flags=(), optimize=None):
        script = Path(__file__).with_name(
            "securekernel-export-graph-inspection-20260911.py"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            # Only parsing is stubbed; the real inspector and JSON writer run.
            (root / "binexport2_pb2.py").write_text(
                "class BinExport2:\n"
                "    instruction = []\n"
                "    flow_graph = []\n"
                "    def ParseFromString(self, data):\n"
                "        assert data == b''\n"
            )
            source = root / "empty.BinExport"
            source.write_bytes(b"")
            output = root / "result.json"
            env = dict(os.environ)
            env.pop("PYTHONOPTIMIZE", None)
            if optimize is not None:
                env["PYTHONOPTIMIZE"] = optimize
            result = subprocess.run(
                [
                    sys.executable,
                    *flags,
                    str(script),
                    "--pb2-dir",
                    str(root),
                    "--reference",
                    str(source),
                    "--target",
                    str(source),
                    "--output",
                    str(output),
                ],
                env=env,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            return result, output.exists()

    def test_missing_graphs_do_not_create_acceptance_output(self):
        result, output_exists = self.run_empty_exports()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("AssertionError", result.stderr)
        self.assertFalse(output_exists)

    def test_optimized_execution_cannot_create_false_acceptance_output(self):
        for flags, optimize in (
            (("-O",), None),
            (("-OO",), None),
            ((), "1"),
            ((), "2"),
        ):
            with self.subTest(flags=flags, optimize=optimize):
                result, output_exists = self.run_empty_exports(flags, optimize)
                self.assertFalse(
                    output_exists, "empty graphs were reported as validated"
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    "graph inspection requires assertions enabled", result.stderr
                )
