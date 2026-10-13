"""Proof: Git metadata in a scanned repository cannot launch fsmonitor helpers."""
from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from clonepeek.scanner import _safe_git_environment, changed_paths, scan


@unittest.skipIf(os.name == "nt", "POSIX executable fixture; covered separately by CI on Windows")
class GitConfigIsolationTests(unittest.TestCase):
    def test_malicious_local_fsmonitor_and_git_env_are_not_executed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            cfg = root / "package.json"
            cfg.write_text('{"scripts": {"postinstall": "echo original"}}', encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(
                ["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                 "commit", "-qm", "baseline"], cwd=root, check=True,
            )
            cfg.write_text('{"scripts": {"postinstall": "echo change"}}', encoding="utf-8")
            marker = root / "unexpected-script-executed.marker"
            monitor = root / "hostile-monitor.sh"
            monitor.write_text(
                "#!/bin/sh\nprintf executed > " + "'" + str(marker) + "'" + "\nexit 0\n",
                encoding="utf-8",
            )
            monitor.chmod(0o755)
            subprocess.run(["git", "config", "core.fsmonitor", str(monitor)], cwd=root, check=True)
            malicious_global = root / "hostile-global-config"
            malicious_global.write_text(
                f"[core]\n    fsmonitor = {monitor}\n", encoding="utf-8"
            )
            with patch.dict(os.environ, {
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "core.fsmonitor",
                "GIT_CONFIG_VALUE_0": str(monitor),
                "GIT_CONFIG_GLOBAL": str(malicious_global),
                "GIT_EXTERNAL_DIFF": str(monitor),
            }):
                changes = changed_paths(root, "HEAD")
                self.assertEqual(changes, {"package.json"})
                findings, count, skipped = scan(root, since="HEAD")
                self.assertEqual(count, 1)
                self.assertEqual(skipped, 0)
                self.assertTrue(any(f.rule == "npm-lifecycle" for f in findings))
            self.assertFalse(marker.exists(), "Scanning ran an executable from untrusted Git config")

    def test_safe_git_environment_drops_git_ssh_and_library_overrides(self):
        with patch.dict(os.environ, {
            "GIT_CONFIG_COUNT": "1",
            "GIT_EXTERNAL_DIFF": "/tmp/hostile",
            "SSH_ASKPASS": "/tmp/hostile",
            "DYLD_INSERT_LIBRARIES": "/tmp/hostile",
            "PATH": os.environ.get("PATH", ""),
        }):
            env = _safe_git_environment()
        for name in ("GIT_CONFIG_COUNT", "GIT_EXTERNAL_DIFF", "SSH_ASKPASS", "DYLD_INSERT_LIBRARIES"):
            self.assertNotIn(name, env)
        self.assertEqual(env["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertEqual(env["GIT_CONFIG_GLOBAL"], os.devnull)
        self.assertEqual(env["GIT_TERMINAL_PROMPT"], "0")


if __name__ == "__main__":
    unittest.main()
