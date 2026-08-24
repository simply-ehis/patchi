"""Unit tests for patchi.core.hosted.anomaly"""

import time
import unittest

from patchi.core.hosted.anomaly import MLDetector, StatisticalDetector, _RollingWindow
from patchi.core.hosted.log_parsers import LogEntry


def _make_entry(ip="1.2.3.4", path="/test", status=200, method="GET"):
    return LogEntry(
        timestamp=time.time(),
        level="INFO",
        method=method,
        path=path,
        status=status,
        ip=ip,
        message="",
        source="test",
    )


class TestRollingWindow(unittest.TestCase):
    def test_empty_rate(self):
        w = _RollingWindow(60)
        self.assertEqual(w.rate(), 0.0)

    def test_rate_single_event(self):
        w = _RollingWindow(60)
        w.add()
        rate = w.rate()
        self.assertGreater(rate, 0.0)

    def test_count(self):
        w = _RollingWindow(60)
        w.add()
        w.add()
        w.add()
        self.assertEqual(w.count(), 3)


class TestStatisticalDetector(unittest.TestCase):
    def test_normal_traffic_no_findings(self):
        det = StatisticalDetector()
        entry = _make_entry()
        findings = det.feed(entry)
        # Normal single request should not trigger anything
        self.assertEqual(len(findings), 0)

    def test_rate_spike(self):
        det = StatisticalDetector({"hosted": {"rate_spike_rps": 5}})
        for _ in range(20):
            det.feed(_make_entry())
        findings = det.feed(_make_entry())
        # Should detect rate spike
        spike_findings = [f for f in findings if f.detector == "rate_spike"]
        self.assertTrue(len(spike_findings) > 0)

    def test_brute_force(self):
        det = StatisticalDetector({"hosted": {"brute_force_auth": 5}})
        for _ in range(10):
            det.feed(_make_entry(path="/auth/login", method="POST"))
        findings = det.feed(_make_entry(path="/auth/login", method="POST"))
        bf_findings = [f for f in findings if f.detector == "brute_force"]
        self.assertTrue(len(bf_findings) > 0)

    def test_scanner_sweep(self):
        det = StatisticalDetector({"hosted": {"scanner_paths": 5}})
        for i in range(10):
            det.feed(_make_entry(path=f"/path/{i}"))
        findings = det.feed(_make_entry(path="/path/extra"))
        sweep_findings = [f for f in findings if f.detector == "scanner_sweep"]
        self.assertTrue(len(sweep_findings) > 0)

    def test_error_rate(self):
        det = StatisticalDetector({"hosted": {"error_rate_pct": 0.3}})
        # Send some good requests first
        for _ in range(10):
            det.feed(_make_entry(status=200))
        # Then mostly errors — feed enough to fill the rolling window
        for _ in range(100):
            det.feed(_make_entry(status=500))
        # Final feed should produce error_rate findings
        findings = det.feed(_make_entry(status=500))
        error_findings = [f for f in findings if f.detector == "error_spike"]
        self.assertTrue(len(error_findings) > 0)

    def test_injection_probe(self):
        det = StatisticalDetector()
        entry = _make_entry(path="/api?q=../etc/passwd")
        findings = det.feed(entry)
        inj_findings = [f for f in findings if f.detector == "injection_probe"]
        self.assertTrue(len(inj_findings) > 0)

    def test_injection_xss(self):
        det = StatisticalDetector()
        entry = _make_entry(path="/search?q=<script>alert(1)</script>")
        findings = det.feed(entry)
        inj_findings = [f for f in findings if f.detector == "injection_probe"]
        self.assertTrue(len(inj_findings) > 0)

    def test_whitelist_skips(self):
        det = StatisticalDetector({"hosted": {"ip_whitelist": ["1.2.3.4"]}})
        entry = _make_entry(ip="1.2.3.4", path="/api?q=../etc/passwd")
        findings = det.feed(entry)
        self.assertEqual(len(findings), 0)

    def test_lru_eviction(self):
        det = StatisticalDetector()
        det._MAX_IP_TRACKERS = 5
        for i in range(10):
            det.feed(_make_entry(ip=f"10.0.0.{i}"))
        # Should not crash, old IPs evicted
        self.assertLessEqual(len(det._ip_auth_hits), 5)

    def test_configurable_thresholds(self):
        det = StatisticalDetector(
            {
                "hosted": {
                    "rate_spike_rps": 3,
                    "brute_force_auth": 3,
                    "scanner_paths": 3,
                }
            }
        )
        self.assertEqual(det._RATE_SPIKE_RPS, 3)
        self.assertEqual(det._BRUTE_FORCE_AUTH, 3)
        self.assertEqual(det._SCANNER_PATHS, 3)


class TestMLDetector(unittest.TestCase):
    def test_no_sklearn(self):
        """ML detector gracefully returns empty if sklearn missing."""
        det = MLDetector()
        entry = _make_entry()
        # Should not crash even without enough samples
        findings = det.feed(entry)
        self.assertEqual(len(findings), 0)

    def test_sample_cap(self):
        det = MLDetector()
        det._MAX_SAMPLES = 10
        # Use feed() which applies the cap
        for _ in range(20):
            det.feed(_make_entry())
        self.assertLessEqual(len(det._samples), 10)

    def test_vector_conversion(self):
        det = MLDetector()
        entry = _make_entry(path="/api/users?id=123", status=200, method="POST")
        vec = det._to_vector(entry)
        self.assertEqual(len(vec), 7)
        self.assertIsInstance(vec[0], float)


if __name__ == "__main__":
    unittest.main()
