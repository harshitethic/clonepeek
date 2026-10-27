"""Changed-ref error output should never expose Git's untrusted stderr."""

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from clonepeek.scanner import ScanError, changed_paths


class GitDiffErrorTests(unittest.TestCase):
    def test_failed_git_command_does_not_echo_private_stderr(self):
        secret = "SYNTHETIC_PRIVATE_GIT_CREDENTIAL"
        with tempfile.TemporaryDirectory() as directory:
            fake = subprocess.CompletedProcess([], 128, b"", b"fatal: remote " + secret.encode())
            with patch("clonepeek.scanner.subprocess.run", return_value=fake):
                with self.assertRaises(ScanError) as error:
                    changed_paths(Path(directory), "HEAD")
        self.assertIn("git diff failed", str(error.exception))
        self.assertNotIn(secret, str(error.exception))
        self.assertNotIn("fatal:", str(error.exception))

    def test_successful_diff_keeps_null_separated_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            fake = subprocess.CompletedProcess([], 0, b"package.json\0src/.mcp.json\0", b"")
            with patch("clonepeek.scanner.subprocess.run", return_value=fake):
                self.assertEqual(
                    changed_paths(Path(directory), "HEAD"),
                    {"package.json", "src/.mcp.json"},
                )


if __name__ == "__main__":
    unittest.main()
