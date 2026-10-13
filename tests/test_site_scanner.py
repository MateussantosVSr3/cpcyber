import unittest
from unittest.mock import patch

from sast.site_scanner import SiteScanError, scan_site, validate_public_url


class SiteScannerTests(unittest.TestCase):
    def test_rejects_private_and_non_web_targets(self):
        for url in ["http://127.0.0.1", "http://10.0.0.1", "file:///etc/passwd", "https://example.com:8443"]:
            with self.assertRaises(SiteScanError, msg=url):
                validate_public_url(url)

    @patch("sast.site_scanner.fetch_site")
    def test_reports_web_findings_and_blocks_high(self, fetch):
        fetch.return_value = (
            "https://example.com/",
            '<html><script>eval(location.hash)</script><img src="http://cdn.example/x.png"></html>',
            {"content-type": "text/html"},
        )
        result = scan_site("https://example.com")
        self.assertEqual(result["gate"], "BLOCKED")
        self.assertEqual(result["scan_type"], "website")
        self.assertIn("W009", {item["rule"] for item in result["findings"]})
        self.assertTrue(all(item["engine"] == "passive-web" for item in result["findings"]))

    @patch("sast.site_scanner.fetch_site")
    def test_secure_headers_pass(self, fetch):
        fetch.return_value = (
            "https://example.com/",
            "<html><body>ok</body></html>",
            {"strict-transport-security": "max-age=31536000", "content-security-policy": "default-src 'self'; frame-ancestors 'none'", "x-content-type-options": "nosniff", "referrer-policy": "no-referrer"},
        )
        self.assertEqual(scan_site("https://example.com")["gate"], "PASSED")


if __name__ == "__main__":
    unittest.main()
