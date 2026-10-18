"""Public real-CLI demo is honest, accessible, self-hosted and reproducible."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
MEDIA = DOCS / "media"

class VideoTests(unittest.TestCase):
    def test_video_assets_are_small_and_valid_containers(self):
        video = MEDIA / "clonepeek-real-cli-demo.mp4"
        poster = MEDIA / "clonepeek-real-cli-demo-poster.jpg"
        self.assertTrue(video.is_file())
        self.assertTrue(poster.is_file())
        self.assertLess(video.stat().st_size, 2_000_000, "Too big for a small static GitHub Pages site")
        self.assertLess(poster.stat().st_size, 300_000)
        with video.open("rb") as stream:
            self.assertEqual(stream.read(4), b"\x00\x00\x00\x20")
            self.assertEqual(stream.read(4), b"ftyp")
        with poster.open("rb") as stream:
            self.assertEqual(stream.read(3), b"\xff\xd8\xff")

    def test_transcript_reproduces_harmless_real_scanner_output(self):
        transcript=(MEDIA / "actual-cli-stdout.txt").read_text(encoding="utf-8")
        self.assertIn("PYTHONPATH=src python3 -m clonepeek examples/agent-hooks",transcript)
        self.assertIn("ClonePeek · 2 inspected · 0 skipped · 3 execution surfaces",transcript)
        self.assertIn("1 critical · 1 high · 1 medium",transcript)
        self.assertIn(".cursor/hooks.json:5",transcript)
        self.assertIn(".claude/settings.json:5",transcript)
        self.assertIn("https://example.invalid/bootstrap.sh",transcript)
        self.assertIn("not run",transcript.lower())

    def test_public_page_loads_video_only_on_demand_and_discloses_scope(self):
        home=(DOCS/"index.html").read_text(encoding="utf-8")
        readme=(ROOT/"README.md").read_text(encoding="utf-8")
        self.assertIn('id="video-demo"',home)
        self.assertIn('<video controls playsinline preload="none"',home)
        self.assertNotIn('<video autoplay',home)
        self.assertIn('src="./media/clonepeek-real-cli-demo.mp4"',home)
        self.assertIn('poster="./media/clonepeek-real-cli-demo-poster.jpg"',home)
        self.assertIn('href="./media/actual-cli-stdout.txt"',home)
        self.assertIn("edited replay, not a live scan or proof of security",home)
        self.assertIn("https://harshitethic.github.io/clonepeek/#video-demo",readme)

if __name__=="__main__":
    unittest.main()
