import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from fastapi import BackgroundTasks, HTTPException
from pydantic import ValidationError
from sast import storage
from sast.api import app, Submission, submit, detail, metrics, review
from sast.jobs import process


async def request(method, route, data=None, headers=None):
    """Minimal ASGI client; no extra HTTP dependency required."""
    body = json.dumps(data).encode() if data is not None else b""
    sent = False
    async def receive():
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        await asyncio.sleep(10)
        return {"type": "http.disconnect"}
    events = []
    async def send(message):
        events.append(message)
    scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.4"}, "http_version": "1.1", "method": method,
        "scheme": "http", "path": route, "raw_path": route.encode(), "query_string": b"", "root_path": "",
        "headers": [(b"host", b"testserver"), (b"content-type", b"application/json"), *((k.encode(), v.encode()) for k,v in (headers or {}).items())],
        "client": ("127.0.0.1", 12345), "server": ("testserver", 80)}
    await app(scope, receive, send)
    return next(e["status"] for e in events if e["type"] == "http.response.start"), b"".join(e.get("body", b"") for e in events)


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {"DATABASE_URL": "sqlite:///" + str(Path(self.tmp.name) / "test.db")})
        self.env.start()
        storage.init()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def test_reject_bad_paths(self):
        for path in ["../a.py", "/a.py", "C:/a.py", "a.js"]:
            with self.assertRaises(ValidationError):
                Submission(project="test", files={path: "x=1"})

    def test_reject_large_file(self):
        with self.assertRaises(ValidationError):
            Submission(project="test", files={"a.py": "a" * 100001})

    def test_full_scan_over_http(self):
        status, body = asyncio.run(request("POST", "/api/scans", {"project": "demo", "files": {"a.py": "eval(input())"}}, {"x-sast-client": "dashboard"}))
        self.assertEqual(status, 202, body)
        scan_id = json.loads(body)["id"]
        process(scan_id)
        status, body = asyncio.run(request("GET", "/api/scans/" + scan_id))
        item = json.loads(body)
        self.assertEqual(status, 200)
        self.assertEqual(item["result"]["gate"], "BLOCKED")
        self.assertNotIn("files", item)
        self.assertEqual(storage.get(scan_id, True)["files"], {})

    @patch("sast.jobs.scan_site", return_value={"gate": "PASSED", "findings": [], "errors": [], "files_scanned": 1, "scan_type": "website"})
    @patch("sast.api.validate_public_url", create=True)
    def test_site_scan_over_http(self, _validate, _scan):
        with patch("sast.site_scanner.validate_public_url", return_value="https://example.com/"):
            status, body = asyncio.run(request("POST", "/api/site-scans", {"project": "site", "url": "https://example.com"}, {"x-sast-client": "dashboard"}))
        self.assertEqual(status, 202, body)
        scan_id = json.loads(body)["id"]
        process(scan_id)
        item = detail(scan_id)
        self.assertEqual(item["result"]["gate"], "PASSED")
        self.assertEqual(item["result"]["scan_type"], "website")

    def test_missing_header_blocked(self):
        self.assertEqual(asyncio.run(request("POST", "/api/codex/login", {}))[0], 403)

    def test_cross_origin_blocked(self):
        self.assertEqual(asyncio.run(request("POST", "/api/codex/login", {}, {"x-sast-client": "dashboard", "origin": "https://evil.example"}))[0], 403)

    def test_latest_project_metrics(self):
        first = storage.create("project", {})
        storage.finish(first, {"findings": [{"severity": "HIGH", "file": "a.py"}]})
        second = storage.create("project", {})
        storage.finish(second, {"findings": []})
        self.assertEqual(metrics()["severity"], {})
        self.assertEqual(len(metrics()["trend"]), 2)

    def test_review_preserves_gate(self):
        scan_id = storage.create("demo", {})
        storage.finish(scan_id, {"gate": "BLOCKED", "findings": [{"fingerprint": "test", "severity": "HIGH"}]})
        with patch("sast.api.ai.review", return_value={"severity": "LOW", "provider": "codex"}):
            review(scan_id, "test")
        self.assertEqual(detail(scan_id)["result"]["gate"], "BLOCKED")

    def test_missing_scan(self):
        with self.assertRaises(HTTPException) as error:
            detail("absent")
        self.assertEqual(error.exception.status_code, 404)

    def test_index(self):
        status, body = asyncio.run(request("GET", "/"))
        self.assertEqual(status, 200)
        self.assertIn(b"Conectar conta ao Codex", body)

if __name__ == "__main__":
    unittest.main()
