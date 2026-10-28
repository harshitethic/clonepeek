"""Regression coverage for confirmed scan and report edge cases."""

import pytest

def test_reject_unterminated_jsonc_comment():
    from clonepeek.formats import load_json
    with pytest.raises(ValueError, match="Unterminated JSONC"):
        load_json('{"tasks": []} /* never closed', jsonc=True)

