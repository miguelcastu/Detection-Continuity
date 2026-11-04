import itertools
import json
import random
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from xml.etree import ElementTree

from detcontinuity import report
from detcontinuity.adapters import convert
from detcontinuity.engine import replay
from detcontinuity.inputs import decode, relative_file
from detcontinuity.suite import benchmark, prepare, run

ROOT = Path(__file__).resolve().parent
EXAMPLES = ROOT / "examples"


def event(event_id, kind, time, identity="x", arrival=None):
    return {
        "id": event_id,
        "kind": kind,
        "time": time,
        "arrival": time if arrival is None else arrival,
        "identity": identity,
    }


class EngineTests(unittest.TestCase):
    def test_frontier_agrees_with_brute_force(self):
        rng = random.Random(129)
        for trial in range(240):
            kinds = rng.choices(["a", "b", "c"], k=rng.randrange(1, 5))
            rule = {
                "id": "trial",
                "window": rng.randrange(6),
                "stages": [{"kind": kind, "join": "identity"} for kind in kinds],
            }
            events = [
                event(
                    str(i),
                    rng.choice(["a", "b", "c"]),
                    time,
                    rng.choice(["x", "y"]),
                    time + rng.randrange(4),
                )
                for i, time in enumerate(rng.choices(range(8), k=12))
            ]
            eligible = sorted(
                (e for e in events if e["arrival"] <= 7), key=lambda e: (e["time"], e["id"])
            )
            expected_terminals = set()
            for chain in itertools.combinations(eligible, len(kinds)):
                times = [e["time"] for e in chain]
                if (
                    len(set(times)) == len(times)
                    and len({e["identity"] for e in chain}) == 1
                    and times[-1] - times[0] <= rule["window"]
                    and [e["kind"] for e in chain] == kinds
                ):
                    expected_terminals.add(chain[-1]["id"])
            with self.subTest(trial=trial):
                matches = replay(rule, events, 7)["matches"]
                self.assertEqual({m["terminal"] for m in matches}, expected_terminals)
                for match in matches:
                    chain = [events[int(i)] for i in match["ids"]]
                    self.assertEqual([e["kind"] for e in chain], kinds)
                    self.assertEqual(len({e["time"] for e in chain}), len(chain))
                    self.assertEqual(match["ready"], max(e["arrival"] for e in chain))

    def test_predicates_compare_json_types(self):
        rule = {
            "id": "bool",
            "window": 0,
            "stages": [{"kind": "a", "join": "identity", "where": {"fields.ok": True}}],
        }
        records = [
            dict(event("bad", "a", 1), fields={"ok": 1}),
            dict(event("good", "a", 1), fields={"ok": True}),
        ]
        result = replay(rule, records, 1)
        self.assertEqual([m["terminal"] for m in result["matches"]], ["good"])
        self.assertEqual(result["stages"][0]["predicate_mismatch"], 1)

    def test_duplicate_json_and_conflicting_event_fail_closed(self):
        with self.assertRaises(ValueError):
            decode(b'{"id":"x","id":"y"}')
        rule = {"id": "bool", "window": 0, "stages": [{"kind": "a", "join": "identity"}]}
        a = event("x", "a", 1)
        with self.assertRaises(ValueError):
            replay(rule, [dict(a, fields={"value": True}), dict(a, fields={"value": 1})], 1)


class IntegrationTests(unittest.TestCase):
    def check(self, filename, expected_exit, format_name="json"):
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "detcontinuity",
                "check",
                str(EXAMPLES / filename),
                "--format",
                format_name,
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, expected_exit, result.stderr)
        return result.stdout

    def test_healthy_and_parser_drift_with_real_lab_shapes(self):
        healthy = json.loads(self.check("lab-healthy.json", 0))
        self.assertEqual(healthy["summary"], {"pass": 4})
        failed = json.loads(self.check("lab-regression.json", 1))
        finding = [r for r in failed["assertions"] if r["status"] == "regression"]
        self.assertEqual(len(finding), 1)
        self.assertEqual(finding[0]["candidate_violations"], ["missed_detection"])
        self.assertEqual(
            finding[0]["baseline"]["unique_events"], finding[0]["candidate"]["unique_events"]
        )
        self.assertEqual(finding[0]["candidate"]["stages"][1]["missing_join"], 1)
        rejected = finding[0]["candidate"]["stage_samples"][1]["missing_join"]
        self.assertEqual(rejected, [finding[0]["baseline"]["matches"][0]["terminal"]])
        self.assertEqual(self.check("lab-regression.json", 1), json.dumps(failed, indent=2) + "\n")

    def test_benchmark_distinguishes_faults_from_evidence_degradation(self):
        document = decode((EXAMPLES / "lab-healthy.json").read_bytes())
        rules, cases = prepare(document, EXAMPLES, require_candidate=False)
        results = benchmark(rules, cases, decode((EXAMPLES / "faults.json").read_bytes()))
        self.assertEqual(len(results), 6)
        self.assertTrue(all(row["summary"] == {"pass": 3, "regression": 1} for row in results))
        self.assertEqual(results[-1]["metrics"]["fp"], 1)
        for index, reason in [(1, "lag_budget_exceeded"), (4, "terminal_evidence_changed")]:
            self.assertTrue(
                any(reason in r["candidate_violations"] for r in results[index]["assertions"])
            )
            self.assertEqual(results[index]["metrics"], {"tp": 2, "tn": 2})
        self.assertEqual(run(rules, cases)["summary"], {"pass": 4})

    def test_mapped_jsonl_keeps_independent_event_and_arrival_clocks(self):
        result = self.check("mapped-ecs.json", 0)
        data = json.loads(result)
        matches = data["assertions"][0]["candidate"]["matches"]
        self.assertEqual(matches[0]["ids"], ["ecs-1", "ecs-2"])
        self.assertEqual(matches[0]["lag"], 4)

    def test_outputs_escape_untrusted_names_and_junit_is_parseable(self):
        xml = ElementTree.fromstring(self.check("lab-regression.json", 1, "junit"))
        self.assertEqual(xml.attrib["failures"], "1")
        data = json.loads(self.check("lab-healthy.json", 0))
        data["assertions"][0]["case"] = "<script>alert(1)</script>"
        self.assertIn("&lt;script&gt;", report.html(data))
        self.assertNotIn("<script>", report.html(data))

    def test_rejects_escape_from_suite_and_native_data_in_lab_adapter(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(ValueError, "inside"):
                relative_file(Path(folder), "../secret.json")
        with self.assertRaisesRegex(ValueError, "synthetic"):
            convert("google-secops-lab", b'{"origin":"live"}')

    def test_cli_bad_input_has_safe_diagnostic(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "bad.json"
            path.write_text('{"secret-should-not-leak": Infinity}', encoding="utf-8")
            result = subprocess.run(
                [sys.executable, "-m", "detcontinuity", "check", str(path)],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("secret-should-not-leak", result.stderr)
        self.assertEqual(result.stdout, "")
