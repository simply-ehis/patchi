"""Unit tests for patchi.core.hosted.log_parsers"""

import unittest

from patchi.core.hosted.log_parsers import (
    parse_apache,
    parse_cloudflare,
    parse_gunicorn,
    parse_json,
    parse_line,
    parse_nginx,
    parse_uvicorn,
)


class TestParseNginx(unittest.TestCase):
    def test_basic(self):
        line = '127.0.0.1 - frank [10/Oct/2023:13:55:36 +0000] "GET /api/users HTTP/1.1" 200 1234'
        entry = parse_nginx(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.ip, "127.0.0.1")
        self.assertEqual(entry.method, "GET")
        self.assertEqual(entry.path, "/api/users")
        self.assertEqual(entry.status, 200)
        self.assertEqual(entry.source, "nginx")

    def test_404(self):
        line = '10.0.0.1 - - [10/Oct/2023:13:55:36 +0000] "GET /missing HTTP/1.1" 404 0'
        entry = parse_nginx(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.status, 404)
        self.assertEqual(entry.level, "WARNING")

    def test_500(self):
        line = '10.0.0.1 - - [10/Oct/2023:13:55:36 +0000] "POST /api HTTP/1.1" 500 128'
        entry = parse_nginx(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.status, 500)
        self.assertEqual(entry.level, "ERROR")

    def test_no_match(self):
        entry = parse_nginx("not an nginx log line")
        self.assertIsNone(entry)


class TestParseApache(unittest.TestCase):
    def test_basic(self):
        line = '127.0.0.1 - frank [10/Oct/2023:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326'
        entry = parse_apache(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.ip, "127.0.0.1")
        self.assertEqual(entry.status, 200)
        self.assertEqual(entry.source, "apache")


class TestParseUvicorn(unittest.TestCase):
    def test_basic(self):
        line = '127.0.0.1:54321 - "GET /api HTTP/1.1" 200'
        entry = parse_uvicorn(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.ip, "127.0.0.1")
        self.assertEqual(entry.status, 200)
        self.assertEqual(entry.source, "uvicorn")


class TestParseGunicorn(unittest.TestCase):
    def test_basic(self):
        line = '127.0.0.1 - - [10/Oct/2023:13:55:36 +0000] "GET /health HTTP/1.1" 200 5'
        entry = parse_gunicorn(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.ip, "127.0.0.1")
        self.assertEqual(entry.status, 200)
        self.assertEqual(entry.source, "gunicorn")


class TestParseCloudflare(unittest.TestCase):
    def test_basic(self):
        import json

        d = {
            "ClientRequestMethod": "GET",
            "ClientRequestURI": "/api/test",
            "EdgeResponseStatus": 200,
            "ClientIP": "1.2.3.4",
        }
        entry = parse_cloudflare(json.dumps(d))
        self.assertIsNotNone(entry)
        self.assertEqual(entry.ip, "1.2.3.4")
        self.assertEqual(entry.status, 200)
        self.assertEqual(entry.source, "cloudflare")

    def test_no_client_src_port_fallback(self):
        """ClientSrcPort should NOT be used as IP fallback."""
        import json

        d = {
            "ClientRequestMethod": "GET",
            "ClientRequestURI": "/test",
            "EdgeResponseStatus": 200,
            "ClientSrcPort": 54321,
        }
        entry = parse_cloudflare(json.dumps(d))
        self.assertIsNotNone(entry)
        self.assertEqual(entry.ip, "")  # no ClientIP, should be empty


class TestParseJson(unittest.TestCase):
    def test_basic(self):
        import json

        d = {"status": 200, "path": "/api", "ip": "1.2.3.4", "method": "GET"}
        entry = parse_json(json.dumps(d))
        self.assertIsNotNone(entry)
        self.assertEqual(entry.status, 200)
        self.assertEqual(entry.ip, "1.2.3.4")

    def test_timestamp_from_json(self):
        import json

        d = {"status": 200, "path": "/", "timestamp": 1700000000.0}
        entry = parse_json(json.dumps(d))
        self.assertIsNotNone(entry)
        self.assertEqual(entry.timestamp, 1700000000.0)

    def test_no_match(self):
        entry = parse_json("not json at all")
        self.assertIsNone(entry)


class TestParseLine(unittest.TestCase):
    def test_nginx_auto_detected(self):
        line = '127.0.0.1 - - [10/Oct/2023:13:55:36 +0000] "GET /test HTTP/1.1" 200 100'
        entry = parse_line(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.source, "nginx")

    def test_empty_line(self):
        self.assertIsNone(parse_line(""))
        self.assertIsNone(parse_line("   "))

    def test_unrecognised(self):
        self.assertIsNone(parse_line("random garbage line"))


class TestParseLines(unittest.TestCase):
    def test_batch(self):
        from patchi.core.hosted.log_parsers import parse_lines

        lines = [
            '127.0.0.1 - - [10/Oct/2023:13:55:36 +0000] "GET /a HTTP/1.1" 200 100',
            "not a log line",
            '127.0.0.1 - - [10/Oct/2023:13:55:36 +0000] "GET /b HTTP/1.1" 404 0',
        ]
        entries = parse_lines(lines)
        self.assertEqual(len(entries), 2)


if __name__ == "__main__":
    unittest.main()
