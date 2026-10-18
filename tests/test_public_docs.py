"""Check canonical website pages and evergreen onboarding content offline."""
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
GUIDE = DOCS / "articles/repository-hooks-before-you-trust.html"
BASE = "https://harshitethic.github.io/clonepeek/"


class PageProbe(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.metadata = {}
        self.canonical = []
        self.h1_count = 0

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "h1":
            self.h1_count += 1
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        if tag == "meta":
            self.metadata[a.get("name") or a.get("property")] = a.get("content")
        if tag == "link" and a.get("rel") == "canonical":
            self.canonical.append(a["href"])


class PublicDocsTests(unittest.TestCase):
    def test_standalone_hook_guide_is_accessible_and_indexable(self):
        html = GUIDE.read_text(encoding="utf-8")
        probe = PageProbe()
        probe.feed(html)
        self.assertEqual(probe.h1_count, 1)
        self.assertEqual(probe.canonical, [BASE + "articles/repository-hooks-before-you-trust.html"])
        self.assertEqual(probe.metadata.get("og:url"), probe.canonical[0])
        self.assertIn("npm", probe.metadata.get("description", "").lower())
        self.assertIn("v0.5.1", html)
        self.assertIn("fail-on: none", html)
        self.assertIn("heuristic", html.lower())
        self.assertIn("before", html.lower())
        self.assertIn("./git-fsmonitor-passive-scanning.html", probe.links)
        self.assertIn("https://github.com/harshitethic/clonepeek/issues/14", probe.links)
        for link in probe.links:
            if link.startswith("./") or link.startswith("../"):
                local = (GUIDE.parent / link).resolve()
                self.assertTrue(local.exists(), f"Broken relative link: {link}")
        self.assertNotIn("clonepeek/issues/19", html)

        match = re.search(r'<script type="application/ld\+json">([^<]+)</script>', html)
        self.assertIsNotNone(match)
        structured = json.loads(match.group(1))
        self.assertEqual(structured["@type"], "TechArticle")
        self.assertEqual(structured["mainEntityOfPage"], probe.canonical[0])
        self.assertTrue(structured["isAccessibleForFree"])

    def test_sitemap_home_and_existing_article_links(self):
        root = ET.parse(DOCS / "sitemap.xml").getroot()
        urls = [el.text for el in root.findall("{http://www.sitemaps.org/schemas/sitemap/0.9}url/{http://www.sitemaps.org/schemas/sitemap/0.9}loc")]
        self.assertEqual(len(urls), len(set(urls)))
        self.assertIn(BASE, urls)
        self.assertIn(BASE + "articles/repository-hooks-before-you-trust.html", urls)
        homepage = (DOCS / "index.html").read_text(encoding="utf-8")
        case = (DOCS / "articles/git-fsmonitor-passive-scanning.html").read_text(encoding="utf-8")
        self.assertIn("./articles/repository-hooks-before-you-trust.html", homepage)
        self.assertIn("Cross-platform test suite", homepage)
        discussion = "https://www.producthunt.com/p/clonepeek/which-repo-defined-commands-do-you-check-before-opening-a-project"
        self.assertIn(discussion, homepage)
        self.assertIn(discussion, (ROOT / "README.md").read_text(encoding="utf-8"))
        self.assertIn("https://www.producthunt.com/products/clonepeek", homepage)
        marketplace = "https://github.com/marketplace/actions/clonepeek-passive-repository-execution-audit"
        self.assertIn(marketplace, homepage)
        self.assertIn(marketplace, (ROOT / "README.md").read_text(encoding="utf-8"))
        self.assertNotIn("ask for upvotes", homepage.lower())
        self.assertNotIn("64 automated tests", homepage)
        self.assertNotIn("74 tests. Three OSes.", homepage)
        self.assertIn("ClonePeek v0.5.1", case)
        self.assertIn("clonepeek/issues/14", case)
        self.assertNotIn("clonepeek/issues/19", case.split('<div class="cta">')[-1])


if __name__ == "__main__":
    unittest.main()
