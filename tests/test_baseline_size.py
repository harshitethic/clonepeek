"""Baseline parsing must limit input size before allocating a JSON object."""

import json
import tempfile
import unittest
from pathlib import Path

from clonepeek.formats import MAX_BASELINE_BYTES, load_baseline


class BaselineSizeTests(unittest.TestCase):
    def test_valid_small_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "baseline.json"
            path.write_text(json.dumps({
                "schema": "clonepeek-baseline-v1",
                "fingerprints": ["synthetic-hash-one", "synthetic-hash-two"],
            }), encoding="utf-8")
            self.assertEqual(load_baseline(path), {"synthetic-hash-one", "synthetic-hash-two"})

    def test_oversized_baseline_rejected_before_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "huge.json"
            with path.open("wb") as stream:
                stream.truncate(MAX_BASELINE_BYTES + 1)
            with self.assertRaisesRegex(ValueError, "16 MiB"):
                load_baseline(path)


if __name__ == "__main__":
    unittest.main()
