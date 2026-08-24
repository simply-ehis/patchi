"""Unit tests for patchi.core.hosted.ip_reputation"""

import tempfile
import unittest
from pathlib import Path

from patchi.core.hosted import ip_reputation


class TestIPReputation(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_lookup_clean(self):
        result = ip_reputation.lookup("1.2.3.4", self.root)
        self.assertFalse(result["known_bad"])
        self.assertEqual(result["threat_level"], "clean")

    def test_record_hit(self):
        ip_reputation.record_hit("1.2.3.4", "test_source", self.root)
        result = ip_reputation.lookup("1.2.3.4", self.root)
        self.assertTrue(result["known_bad"])
        self.assertEqual(result["lists_hit"], 1)

    def test_auto_block(self):
        # Hit from 3 different sources triggers auto-block
        ip_reputation.record_hit("1.2.3.4", "src1", self.root)
        ip_reputation.record_hit("1.2.3.4", "src2", self.root)
        ip_reputation.record_hit("1.2.3.4", "src3", self.root)
        self.assertTrue(ip_reputation.is_blocked("1.2.3.4", self.root))

    def test_manual_block(self):
        ip_reputation.block("1.2.3.4", self.root)
        self.assertTrue(ip_reputation.is_blocked("1.2.3.4", self.root))

    def test_manual_unblock(self):
        ip_reputation.block("1.2.3.4", self.root)
        ok = ip_reputation.unblock("1.2.3.4", self.root)
        self.assertTrue(ok)
        self.assertFalse(ip_reputation.is_blocked("1.2.3.4", self.root))

    def test_unblock_nonexistent(self):
        ok = ip_reputation.unblock("1.2.3.4", self.root)
        self.assertFalse(ok)

    def test_is_not_blocked(self):
        self.assertFalse(ip_reputation.is_blocked("1.2.3.4", self.root))

    def test_get_top_threats(self):
        ip_reputation.record_hit("1.1.1.1", "src1", self.root)
        ip_reputation.record_hit("1.1.1.1", "src2", self.root)
        ip_reputation.record_hit("2.2.2.2", "src1", self.root)
        threats = ip_reputation.get_top_threats(self.root)
        self.assertEqual(len(threats), 2)
        self.assertEqual(threats[0]["ip"], "1.1.1.1")  # more lists_hit

    def test_threat_level(self):
        self.assertEqual(ip_reputation._threat_level(0), "clean")
        self.assertEqual(ip_reputation._threat_level(1), "medium")
        self.assertEqual(ip_reputation._threat_level(3), "high")
        self.assertEqual(ip_reputation._threat_level(5), "critical")

    def test_needs_refresh(self):
        self.assertTrue(ip_reputation.needs_refresh(self.root))

    def test_lookup_returns_sources(self):
        ip_reputation.record_hit("1.2.3.4", "abuse.ch", self.root)
        ip_reputation.record_hit("1.2.3.4", "firehol", self.root)
        result = ip_reputation.lookup("1.2.3.4", self.root)
        self.assertEqual(result["lists_hit"], 2)
        self.assertIn("abuse.ch", result["sources"])
        self.assertIn("firehol", result["sources"])


if __name__ == "__main__":
    unittest.main()
