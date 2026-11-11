"""JSONC comment boundary regressions."""

import unittest

from clonepeek.formats import load_json


class JsoncCommentTests(unittest.TestCase):
    def test_unterminated_block_comment_is_parse_error(self):
        with self.assertRaisesRegex(ValueError, "Unterminated JSONC"):
            load_json('{"enabled": true} /* unfinished', jsonc=True)

    def test_terminated_comment_still_parses(self):
        self.assertEqual(
            load_json('{"enabled": true, /* explanation */ "count": 3}', jsonc=True),
            {"enabled": True, "count": 3},
        )

    def test_comment_markers_inside_string_are_preserved(self):
        self.assertEqual(
            load_json('{"url": "https://example.invalid/a/*literal*/"}', jsonc=True),
            {"url": "https://example.invalid/a/*literal*/"},
        )


if __name__ == "__main__":
    unittest.main()
