"""Test the reusable GitHub Action adapter without a runner or network."""
from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
import tempfile
import unittest

from action_runner import perform
from clonepeek import __version__

EXAMPLES = Path(__file__).resolve().parents[1] / "examples" / "indirect-script"


class CompositeActionTests(unittest.TestCase):
    def run_action(self, extra):
        stdout, stderr = StringIO(), StringIO()
        env = {"CLONEPEEK_INPUT_PATH": str(EXAMPLES), **extra}
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = perform(env)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_default_does_not_fail_and_prints_detection(self):
        code, text, err = self.run_action({})
        self.assertEqual(code, 0, err)
        self.assertIn("scripts/setup.sh:4", text)
        self.assertIn("[CRITICAL]", text)

    def test_configured_threshold_fails_and_emits_outputs(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "github-output"
            summary = Path(folder) / "summary"
            output.touch()
            summary.touch()
            code, _, stderr = self.run_action({
                "CLONEPEEK_INPUT_FAIL_ON": "high",
                "GITHUB_OUTPUT": str(output),
                "GITHUB_STEP_SUMMARY": str(summary),
            })
            self.assertEqual(code, 1)
            self.assertIn("threshold exceeded", stderr)
            fields = dict(x.split("=", 1) for x in output.read_text().splitlines())
            self.assertEqual(fields["findings"], "2")
            self.assertEqual(fields["new-findings"], "2")
            self.assertEqual(fields["critical"], "1")
            self.assertEqual(fields["high"], "0")
            self.assertEqual(fields["scanned"], "1")
            self.assertIn("not** malware detection", summary.read_text())
            self.assertNotIn("curl https://", summary.read_text())

    def test_json_report_written_without_dumping_source_to_log(self):
        with tempfile.TemporaryDirectory() as folder:
            dest = Path(folder) / "sub" / "audit.json"
            code, stdout, _ = self.run_action({
                "CLONEPEEK_INPUT_FORMAT": "json",
                "CLONEPEEK_INPUT_OUTPUT": str(dest),
                "CLONEPEEK_INPUT_FAIL_ON": "none",
            })
            self.assertEqual(code, 0)
            self.assertNotIn("curl https://", stdout)
            report = json.loads(dest.read_text())
            self.assertEqual(report["version"], __version__)
            self.assertEqual(len(report["findings"]), 2)
            self.assertTrue(all(x["status"] == "new" for x in report["findings"]))

    def test_sarif_report_has_current_version(self):
        code, stdout, stderr = self.run_action({"CLONEPEEK_INPUT_FORMAT": "sarif"})
        self.assertEqual(code, 0, stderr)
        report = json.loads(stdout)
        self.assertEqual(report["runs"][0]["tool"]["driver"]["version"], __version__)
        self.assertEqual(len(report["runs"][0]["results"]), 2)

    def test_empty_directory_zero_findings(self):
        with tempfile.TemporaryDirectory() as folder:
            code, stdout, stderr = self.run_action({
                "CLONEPEEK_INPUT_PATH": folder,
                "CLONEPEEK_INPUT_FAIL_ON": "critical",
                "CLONEPEEK_INPUT_FORMAT": "json",
            })
            self.assertEqual(code, 0, stderr)
            self.assertEqual(json.loads(stdout)["findings"], [])

    def test_bad_options_and_missing_directory_fail_closed(self):
        for extra in (
            {"CLONEPEEK_INPUT_FAIL_ON": "supreme"},
            {"CLONEPEEK_INPUT_FORMAT": "xml"},
            {"CLONEPEEK_INPUT_PATH": "/path/that/does/not/exist"},
        ):
            with self.subTest(extra=extra):
                code, _, stderr = self.run_action(extra)
                self.assertEqual(code, 2)
                self.assertIn("clonepeek action:", stderr)

    def test_untrusted_shell_metacharacters_are_not_executed(self):
        with tempfile.TemporaryDirectory() as folder:
            witness = Path(folder) / "NEVER_CREATE"
            path = f"/nonexistent/path; touch {witness}"
            code, _, _ = self.run_action({"CLONEPEEK_INPUT_PATH": path})
            self.assertEqual(code, 2)
            self.assertFalse(witness.exists())

    def test_action_uses_baseline_for_fail_on(self):
        from clonepeek.formats import baseline
        from clonepeek.scanner import scan
        with tempfile.TemporaryDirectory() as folder:
            baseline_file = Path(folder) / "baseline.json"
            findings, _, _ = scan(EXAMPLES)
            baseline_file.write_text(json.dumps(baseline(findings)))
            code, _, err = self.run_action({
                "CLONEPEEK_INPUT_FAIL_ON": "high",
                "CLONEPEEK_INPUT_BASELINE": str(baseline_file),
            })
            self.assertEqual(code, 0, err)

    def test_release_version_is_consistent_with_metadata_and_public_examples(self):
        root = Path(__file__).resolve().parents[1]
        project = (root / "pyproject.toml").read_text(encoding="utf-8")
        sample = json.loads((root / "docs/schema/scan-report-v1.example.json").read_text(encoding="utf-8"))
        landing = (root / "docs/index.html").read_text(encoding="utf-8")
        guide = (root / "docs/GITHUB-ACTION.md").read_text(encoding="utf-8")
        self.assertIn(f'version = "{__version__}"', project)
        self.assertEqual(sample["version"], __version__)
        self.assertIn(f'"softwareVersion":"{__version__}"', landing)
        self.assertIn(f"clonepeek@v{__version__}", landing)
        self.assertIn(f"clonepeek@v{__version__}", guide)

    def test_readme_contains_direct_action_usage(self):
        root = Path(__file__).resolve().parents[1]
        readme = (root / "README.md").read_text(encoding="utf-8")
        self.assertIn(f"uses: harshitethic/clonepeek@v{__version__}", readme)
        self.assertTrue((root / "action.yml").is_file())


if __name__ == "__main__":
    unittest.main()
