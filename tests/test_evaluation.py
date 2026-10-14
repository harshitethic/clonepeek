"""Evaluation schema guardrails and truthful corpus-level confusion reporting."""
from __future__ import annotations

import json
import subprocess
import sys
import unittest

from evaluation.evaluate import _evaluate_cases, _score, _wilson_interval, evaluate


class EvaluationTests(unittest.TestCase):
    def test_all_fixture_labels_are_measured_and_rule_counts_match(self):
        report = evaluate()
        self.assertEqual(report["cases"], 46)
        self.assertEqual((report["tp"], report["fp"], report["fn"], report["tn"]), (15, 3, 2, 26))
        self.assertAlmostEqual(report["precision"], 15 / 18)
        self.assertAlmostEqual(report["recall"], 15 / 17)
        self.assertEqual(len(report["outcomes"]), report["cases"])
        self.assertEqual(
            sum(entry["tp"] for entry in report["by_rule"].values()),
            38,
        )
        self.assertTrue(all(
            entry["fp"] == 0 and entry["fn"] == 0
            for entry in report["by_rule"].values()
        ))
        self.assertIn("NOT", report["disclaimer"])

    def test_missing_or_duplicate_labels_cannot_silently_pass(self):
        a = {
            "id": "case", "path": "package.json",
            "content": '{"scripts":{"postinstall":"echo ok"}}',
            "expected_rules": ["npm-lifecycle"],
            "high_risk": False,
            "why": "A synthetic, harmless install-time diagnostic",
        }
        for corpus in (
            [a, a],
            [{**a, "expected_rules": ["unknown-rule"]}],
            [{**a, "expected_rules": ["npm-lifecycle", "npm-lifecycle"]}],
            [{**a, "why": ""}],
            [{**a, "path": "../package.json"}],
            [{**a, "high_risk": "true"}],
        ):
            with self.subTest(corpus=corpus), self.assertRaises(ValueError):
                _evaluate_cases(corpus)

    def test_empty_denominators_are_unknown_not_perfect(self):
        score = _score([False, False], [False, False])
        self.assertIsNone(score["precision"])
        self.assertIsNone(score["recall"])
        self.assertEqual((score["tp"], score["fp"], score["fn"], score["tn"]), (0, 0, 0, 2))
        self.assertIsNone(_wilson_interval(0, 0))
        low, high = _wilson_interval(7, 7)
        self.assertLess(low, 0.7)
        self.assertEqual(high, 1.0)

    def test_cli_report_is_machine_readable_and_self_consistent(self):
        result = subprocess.run(
            [sys.executable, "-m", "evaluation.evaluate", "--format", "json"],
            capture_output=True, text=True, timeout=30, check=True,
        )
        report = json.loads(result.stdout)
        self.assertEqual(report["cases"], 46)
        self.assertEqual(report["cases"], sum(report[key] for key in ("tp", "fp", "fn", "tn")))
        self.assertEqual(
            set(report["by_rule"]["mcp-server-process"]),
            {"tp", "fp", "fn", "tn", "precision", "recall", "support",
             "precision_wilson_95", "recall_wilson_95"},
        )


if __name__ == "__main__":
    unittest.main()
