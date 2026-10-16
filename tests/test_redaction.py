"""Credential-output safety regressions, using synthetic sentinel values only."""
import json
import unittest

from clonepeek.detectors import inspect
from clonepeek.formats import redact, render_text, sarif


SENTINEL = "SYNTHETIC_TOKEN_DO_NOT_USE_9876"


class RedactionTests(unittest.TestCase):
    def test_unquoted_sensitive_option(self):
        for option in ("--api-key", "--access-token", "--auth_token", "--password", "--client-secret"):
            with self.subTest(option=option):
                shown = redact(f"example-agent {option} {SENTINEL}")
                self.assertIn("[REDACTED]", shown)
                self.assertNotIn(SENTINEL, shown)

    def test_quoted_sensitive_option(self):
        for quote in ("'", '"'):
            with self.subTest(quote=quote):
                shown = redact(f"example-agent --api-key {quote}{SENTINEL} WITH SPACES{quote}")
                self.assertNotIn(SENTINEL, shown)
                self.assertNotIn("WITH SPACES", shown)
                self.assertIn("[REDACTED]", shown)

    def test_bearer_authorization_header(self):
        shown = redact(f'curl -H "Authorization: Bearer {SENTINEL}" https://example.invalid')
        self.assertNotIn(SENTINEL, shown)
        self.assertIn("[REDACTED]", shown)

    def test_all_public_report_formats_omit_option_secret(self):
        cfg = {"mcpServers": {"test": {
            "command": "npx", "args": ["-y", "example-package", "--api-key", SENTINEL]}}}
        findings = inspect(".mcp.json", json.dumps(cfg))
        self.assertEqual(len(findings), 1)
        for report in (render_text(findings, 1, 0),
                       json.dumps([finding.to_dict() for finding in findings]),
                       json.dumps(sarif(findings))):
            self.assertNotIn(SENTINEL, report)
            self.assertIn("[REDACTED]", report)


if __name__ == "__main__":
    unittest.main()
