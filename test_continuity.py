import json
from pathlib import Path
import subprocess
import sys
import unittest

from continuity import compare, evaluate


ROOT = Path(__file__).resolve().parent
SUITE = json.loads((ROOT / "examples/regressions.json").read_text())
CONTRACT = SUITE["contract"]
LOGIN, GRANT = SUITE["cases"][0]["baseline"]


class ContinuityTests(unittest.TestCase):
    def test_regressions_and_diagnostics(self):
        cases = compare(SUITE)
        self.assertEqual([row["status"] for row in cases], [
            "pass", "pass", "missed_detection", "missed_detection",
            "missed_detection", "new_false_positive",
        ])
        self.assertEqual(cases[0]["candidate"]["evidence"], [["login-1", "grant-1"]])
        self.assertEqual(cases[0]["candidate"]["unique_count"], 2)
        self.assertEqual(cases[2]["candidate"]["issues"], {"missing_identity": ["grant-1"]})
        self.assertEqual(cases[3]["candidate"]["issues"], {"late": ["grant-1"]})
        self.assertEqual(cases[4]["candidate"]["issues"], {"absent_kind": ["iam_grant"]})

    def test_time_boundaries(self):
        self.assertTrue(evaluate(CONTRACT, [LOGIN, dict(GRANT, time=70, arrival=90)])["detected"])
        self.assertFalse(evaluate(CONTRACT, [LOGIN, dict(GRANT, time=71, arrival=90)])["detected"])
        self.assertFalse(evaluate(CONTRACT, [LOGIN, dict(GRANT, time=10)])["detected"])

    def test_conflicting_duplicate_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "Conflicting duplicate"):
            evaluate(CONTRACT, [LOGIN, dict(LOGIN, identity="other")])

    def test_invalid_baseline_cannot_pass(self):
        result = compare({"contract": CONTRACT, "cases": [
            dict(SUITE["cases"][0], baseline=[LOGIN])
        ]})
        self.assertEqual(result[0]["status"], "invalid_baseline")

    def test_cli_rejects_regressions(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "continuity.py"), str(ROOT / "examples/regressions.json")],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(len(json.loads(result.stdout)["suite_sha256"]), 64)
