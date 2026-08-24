"""Unit tests for patchi.core.hosted.watchlist"""

import tempfile
import time
import unittest
from pathlib import Path

from patchi.core.hosted.watchlist import _SCORE_TTL_SECS, WatchlistTracker


class TestWatchlistTracker(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)
        self.escalations = []
        self.tracker = WatchlistTracker(
            self.root,
            escalation_fn=lambda ip, score, sev: self.escalations.append((ip, score, sev)),
        )

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_record_returns_score(self):
        score = self.tracker.record("1.2.3.4", "brute_force", "test")
        self.assertGreater(score, 0)

    def test_empty_ip_ignored(self):
        score = self.tracker.record("", "brute_force")
        self.assertEqual(score, 0.0)

    def test_score_increases_with_hits(self):
        s1 = self.tracker.record("1.2.3.4", "error_spike")
        s2 = self.tracker.record("1.2.3.4", "error_spike")
        self.assertGreater(s2, s1)

    def test_score_decay(self):
        self.tracker.record("1.2.3.4", "brute_force")
        score = self.tracker.score("1.2.3.4")
        self.assertGreater(score, 0)
        # Score for unknown IP should be 0
        self.assertEqual(self.tracker.score("9.9.9.9"), 0.0)

    def test_escalation_high(self):
        # brute_force = 40, need 2 hits to cross 50
        self.tracker.record("1.2.3.4", "brute_force")
        self.tracker.record("1.2.3.4", "brute_force")
        self.assertTrue(any(s == "high" for _, _, s in self.escalations))

    def test_escalation_critical(self):
        # brute_force = 40, injection = 30, scanner = 20, rate = 10
        # Need score >= 100
        self.tracker.record("1.2.3.4", "brute_force")  # 40
        self.tracker.record("1.2.3.4", "brute_force")  # 40+40=80
        self.tracker.record("1.2.3.4", "injection_probe")  # 80+30=110
        self.assertTrue(any(s == "critical" for _, _, s in self.escalations))

    def test_top(self):
        self.tracker.record("1.1.1.1", "brute_force")
        self.tracker.record("2.2.2.2", "injection_probe")
        top = self.tracker.top(10)
        self.assertEqual(len(top), 2)
        # injection_probe (30) < brute_force (40), so 1.1.1.1 should be first
        self.assertEqual(top[0]["ip"], "1.1.1.1")

    def test_clear_ip(self):
        self.tracker.record("1.2.3.4", "brute_force")
        ok = self.tracker.clear_ip("1.2.3.4")
        self.assertTrue(ok)
        self.assertEqual(self.tracker.score("1.2.3.4"), 0.0)

    def test_clear_nonexistent(self):
        ok = self.tracker.clear_ip("9.9.9.9")
        self.assertFalse(ok)

    def test_purge_expired(self):
        self.tracker.record("1.2.3.4", "error_spike")  # low score
        # Manually age the entry
        from patchi.core.hosted.watchlist import _load, _save

        data = _load(self.root)
        data["1.2.3.4"]["last_seen"] = time.time() - _SCORE_TTL_SECS - 100
        _save(self.root, data)
        removed = self.tracker.purge_expired()
        self.assertEqual(removed, 1)

    def test_no_duplicate_escalation(self):
        # Should only escalate once per threshold
        self.tracker.record("1.2.3.4", "brute_force")
        self.tracker.record("1.2.3.4", "brute_force")
        high_escalations = [s for _, _, s in self.escalations if s == "high"]
        self.assertEqual(len(high_escalations), 1)


if __name__ == "__main__":
    unittest.main()
