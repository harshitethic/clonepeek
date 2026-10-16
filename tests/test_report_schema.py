"""Offline scan-report contract regression with optional full JSON Schema checks."""
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import re
import tempfile
import unittest

from action_runner import perform
from clonepeek.cli import run

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_FILE = ROOT / "docs/schema/scan-report-v1.schema.json"
EXAMPLE_FILE = ROOT / "docs/schema/scan-report-v1.example.json"
FINDING_FIELDS = (
    "rule", "severity", "path", "line", "trigger", "title",
    "evidence", "why", "advice", "fingerprint", "status",
)


def cli_json(path, *args):
    output = io.StringIO()
    with redirect_stdout(output):
        rc = run([str(path), "--format", "json", *args])
    if rc:
        raise AssertionError(f"CLI error: {rc}")
    return json.loads(output.getvalue())


def assert_contract(report, schema):
    """Stdlib subset of this contract, NOT a general JSON Schema validator."""
    assert isinstance(report, dict)
    assert set(schema["required"]) <= set(report)
    assert schema["additionalProperties"] is True
    assert report["tool"] == schema["properties"]["tool"]["const"]
    assert isinstance(report["version"], str) and report["version"]
    for key in ("scanned", "skipped"):
        assert type(report[key]) is int and report[key] >= 0
    assert isinstance(report["findings"], list)
    spec = schema["$defs"]["finding"]
    assert set(spec["required"]) == set(FINDING_FIELDS)
    assert spec["additionalProperties"] is True
    for item in report["findings"]:
        assert isinstance(item, dict) and set(FINDING_FIELDS) <= set(item)
        for name in set(FINDING_FIELDS) - {"line"}:
            assert isinstance(item[name], str)
        assert item["rule"]
        assert type(item["line"]) is int and item["line"] >= 1
        assert item["severity"] in spec["properties"]["severity"]["enum"]
        assert item["status"] in spec["properties"]["status"]["enum"]
        assert re.fullmatch(spec["properties"]["fingerprint"]["pattern"], item["fingerprint"])


class ReportSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))

    def test_real_cli_demo_and_committed_example(self):
        current = cli_json(ROOT / "examples/agent-hooks")
        example = json.loads(EXAMPLE_FILE.read_text(encoding="utf-8"))
        for item in (current, example):
            assert_contract(item, self.schema)
        self.assertEqual(len(current["findings"]), 3)
        self.assertEqual(
            [{k:v for k,v in finding.items() if k != "status"} for finding in current["findings"]],
            [{k:v for k,v in finding.items() if k != "status"} for finding in example["findings"]],
        )

    def test_empty_report_and_baseline_known_status(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            empty = cli_json(root)
            assert_contract(empty, self.schema)
            self.assertEqual(empty["findings"], [])
            self.assertEqual((empty["scanned"], empty["skipped"]), (0, 0))
            (root / "package.json").write_text('{"scripts":{"postinstall":"echo test"}}')
            baseline = root / "baseline.json"
            with redirect_stdout(io.StringIO()):
                self.assertEqual(run([str(root), "--write-baseline", str(baseline)]), 0)
            known = cli_json(root, "--baseline", str(baseline))
            assert_contract(known, self.schema)
            self.assertEqual([x["status"] for x in known["findings"]], ["known"])

    def test_composite_action_output(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "report.json"
            rc = perform({
                "CLONEPEEK_INPUT_PATH": str(ROOT / "examples/agent-hooks"),
                "CLONEPEEK_INPUT_FORMAT": "json",
                "CLONEPEEK_INPUT_OUTPUT": str(output),
                "CLONEPEEK_INPUT_FAIL_ON": "none",
            })
            self.assertEqual(rc, 0)
            report = json.loads(output.read_text(encoding="utf-8"))
            assert_contract(report, self.schema)
            self.assertEqual(len(report["findings"]), 3)

    def test_forward_compatible_schema_contract(self):
        self.assertEqual(self.schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertNotIn("const", self.schema["properties"]["version"])
        self.assertNotIn("enum", self.schema["properties"]["version"])
        self.assertEqual(set(self.schema["properties"]), set(self.schema["required"]))
        self.assertEqual(set(self.schema["$defs"]["finding"]["properties"]), set(FINDING_FIELDS))

    def test_optional_jsonschema_validation(self):
        try:
            from jsonschema import Draft202012Validator
        except ImportError:
            self.skipTest("Optional developer validator not installed")
        Draft202012Validator.check_schema(self.schema)
        validator = Draft202012Validator(self.schema)
        for report in (cli_json(ROOT / "examples/agent-hooks"),
                       json.loads(EXAMPLE_FILE.read_text(encoding="utf-8"))):
            validator.validate(report)
        with tempfile.TemporaryDirectory() as temp:
            validator.validate(cli_json(Path(temp)))
        example = json.loads(EXAMPLE_FILE.read_text(encoding="utf-8"))
        example["findings"][0]["line"] = 0
        self.assertFalse(validator.is_valid(example))
        example["findings"][0]["line"] = 1
        example["findings"][0]["status"] = "safe"
        self.assertFalse(validator.is_valid(example))


if __name__ == "__main__":
    unittest.main()
