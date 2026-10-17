"""Low-cost RSS discoverability contracts for the public engineering articles."""
from pathlib import Path
import unittest
import xml.etree.ElementTree as ET
from email.utils import parsedate_to_datetime

DOCS=Path(__file__).resolve().parents[1] / "docs"
BASE="https://harshitethic.github.io/clonepeek/"
ATOM="{http://www.w3.org/2005/Atom}"


class FeedTests(unittest.TestCase):
    def test_feed_is_well_formed_and_points_at_existing_original_articles(self):
        root=ET.parse(DOCS/"feed.xml").getroot()
        self.assertEqual(root.tag,"rss")
        self.assertEqual(root.attrib.get("version"),"2.0")
        channel=root.find("channel")
        self.assertEqual(channel.findtext("link"),BASE)
        self.assertEqual(channel.find(ATOM+"link").attrib,
                         {"href":BASE+"feed.xml","rel":"self","type":"application/rss+xml"})
        items=channel.findall("item")
        self.assertEqual(len(items),2)
        links=[item.findtext("link") for item in items]
        self.assertEqual(len(links),len(set(links)))
        for item in items:
            link=item.findtext("link")
            self.assertTrue(link.startswith(BASE+"articles/"),link)
            self.assertTrue((DOCS/link.removeprefix(BASE)).is_file(),link)
            self.assertEqual(item.findtext("guid"),link)
            self.assertEqual(item.find("guid").attrib.get("isPermaLink"),"true")
            self.assertGreater(len(item.findtext("description") or ""),45)
            self.assertIsNotNone(parsedate_to_datetime(item.findtext("pubDate")))

    def test_feed_is_advertised_on_each_published_page(self):
        for file,relative in [
            (DOCS/"index.html","./feed.xml"),
            (DOCS/"articles/git-fsmonitor-passive-scanning.html","../feed.xml"),
            (DOCS/"articles/repository-hooks-before-you-trust.html","../feed.xml"),
        ]:
            text=file.read_text(encoding="utf-8")
            self.assertIn('type="application/rss+xml"',text,file)
            self.assertIn('href="'+relative+'"',text,file)
        self.assertIn('href="./feed.xml">Follow engineering notes by RSS',
                      (DOCS/"index.html").read_text(encoding="utf-8"))

if __name__ == "__main__":
    unittest.main()
