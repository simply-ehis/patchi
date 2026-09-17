"""Unit tests for aggregated flake detection + retention."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from patchi.core.testing import flake_detector_agent as flake


def _root() -> Path:
    t = Path(tempfile.mkdtemp())
    (t / ".patchi").mkdir(exist_ok=True)
    return t


def _record(root: Path, outcomes: dict[str, bool], dur: int = 10) -> None:
    cases = [
        {"name": n, "passed": p, "duration_ms": dur, "file": "t.py", "line": 1}
        for n, p in outcomes.items()
    ]
    total = len(cases)
    passed = sum(1 for c in cases if c["passed"])
    flake._record_test_run(root, "pytest", cases, total, passed, total - passed, 0, dur)


class TestAggregatedDetection(unittest.TestCase):
    def test_flipper_found_stable_excluded(self):
        root = _root()
        _record(root, {"flip": True, "steady": True})
        _record(root, {"flip": False, "steady": True})
        flakes = flake._detect_flaky_tests(root)
        self.assertEqual([f["test_name"] for f in flakes], ["flip"])
        f = flakes[0]
        self.assertEqual((f["run_count"], f["pass_count"], f["fail_count"]), (2, 1, 1))
        self.assertEqual(len(f["history"]), 2)

    def test_min_runs_respected(self):
        root = _root()
        _record(root, {"solo": True})
        self.assertEqual(flake._detect_flaky_tests(root), [])

    def test_quarantine_threshold(self):
        root = _root()
        for passed in (True, False, False, False):
            _record(root, {"bad": passed})
        self.assertIn("bad", flake.get_quarantined_tests(root, flake_threshold=0.5))
        self.assertNotIn("bad", flake.get_quarantined_tests(root, flake_threshold=0.9))

    def test_outlier_detected(self):
        root = _root()
        for _ in range(12):
            _record(root, {"slow": True}, dur=10)
        _record(root, {"slow": True}, dur=1000)
        out = flake._detect_duration_outliers(root)
        self.assertEqual([o["test_name"] for o in out], ["slow"])
        self.assertGreater(out[0]["z_score"], 3.0)

    def test_retention_prunes(self):
        root = _root()
        for _ in range(flake._MAX_KEPT_RUNS + 5):
            _record(root, {"t": True})
        runs = flake._get_all_runs(root)
        self.assertEqual(len(runs), flake._MAX_KEPT_RUNS)


if __name__ == "__main__":
    unittest.main()
