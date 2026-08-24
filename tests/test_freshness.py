"""Unit tests for patchi.core.brain.freshness"""

import tempfile
import time
import unittest
from pathlib import Path

from patchi.core import config as cfg
from patchi.core.brain.freshness import (
    FRESHNESS_FILE,
    check_freshness,
    save_freshness_snapshot,
)


def _setup(tmp: Path) -> Path:
    cfg.init_project(tmp)
    return tmp


def _write(root: Path, rel: str, content: str = "pass") -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


class TestFreshnessSnapshot(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_snapshot_file_created(self):
        _write(self.root, "src/app.py")
        save_freshness_snapshot(self.root, ["src/app.py"])
        self.assertTrue((self.root / FRESHNESS_FILE).exists())

    def test_no_snapshot_means_stale(self):
        result = check_freshness(self.root)
        self.assertTrue(result["is_stale"])
        self.assertIsNone(result["last_recorded"])

    def test_fresh_after_snapshot(self):
        _write(self.root, "src/app.py")
        save_freshness_snapshot(self.root, ["src/app.py"])
        result = check_freshness(self.root)
        self.assertFalse(result["is_stale"])

    def test_stale_after_file_modification(self):
        path = _write(self.root, "src/app.py", "v1")
        save_freshness_snapshot(self.root, ["src/app.py"])
        # Wait a tiny bit and then touch the file
        time.sleep(0.01)
        path.write_text("v2", encoding="utf-8")
        # Force mtime change
        import os

        os.utime(path, None)
        result = check_freshness(self.root)
        self.assertTrue(result["is_stale"])
        self.assertIn("src/app.py", result["changed_files"])

    def test_stale_after_file_deletion(self):
        path = _write(self.root, "src/old.py", "pass")
        save_freshness_snapshot(self.root, ["src/old.py"])
        path.unlink()
        result = check_freshness(self.root)
        self.assertTrue(result["is_stale"])
        self.assertIn("src/old.py", result["deleted_files"])

    def test_last_recorded_timestamp(self):
        _write(self.root, "src/app.py")
        save_freshness_snapshot(self.root, ["src/app.py"])
        result = check_freshness(self.root)
        self.assertIsNotNone(result["last_recorded"])
        # Should be a valid ISO timestamp
        from datetime import datetime

        dt = datetime.fromisoformat(result["last_recorded"])
        self.assertIsNotNone(dt)

    def test_reason_populated_when_stale(self):
        path = _write(self.root, "src/app.py", "v1")
        save_freshness_snapshot(self.root, ["src/app.py"])
        time.sleep(0.01)
        path.write_text("v2", encoding="utf-8")
        import os

        os.utime(path, None)
        result = check_freshness(self.root)
        self.assertIn("modified", result["reason"])

    def test_multiple_files_snapshot(self):
        _write(self.root, "src/a.py")
        _write(self.root, "src/b.py")
        _write(self.root, "src/c.py")
        save_freshness_snapshot(self.root, ["src/a.py", "src/b.py", "src/c.py"])
        result = check_freshness(self.root)
        self.assertFalse(result["is_stale"])


if __name__ == "__main__":
    unittest.main()
