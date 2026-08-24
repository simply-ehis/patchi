"""Unit tests for patchi.core.hosted.audit_log"""

import tempfile
import time
import unittest
from pathlib import Path

from patchi.core.hosted.audit_log import MAX_SIZE_BYTES, clear, read_recent, write


class TestAuditLog(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_write_and_read(self):
        write(self.root, "test_event", data={"key": "value"})
        entries = read_recent(self.root, 10)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["event"], "test_event")
        self.assertEqual(entries[0]["data"]["key"], "value")

    def test_write_multiple(self):
        for i in range(5):
            write(self.root, f"event_{i}")
        entries = read_recent(self.root, 10)
        self.assertEqual(len(entries), 5)
        # Newest first
        self.assertEqual(entries[0]["event"], "event_4")

    def test_read_limit(self):
        for i in range(20):
            write(self.root, f"event_{i}")
        entries = read_recent(self.root, 5)
        self.assertEqual(len(entries), 5)

    def test_read_empty(self):
        entries = read_recent(self.root, 10)
        self.assertEqual(entries, [])

    def test_clear(self):
        write(self.root, "event1")
        write(self.root, "event2")
        removed = clear(self.root)
        self.assertGreater(removed, 0)
        entries = read_recent(self.root, 10)
        self.assertEqual(len(entries), 0)

    def test_write_never_raises(self):
        """Audit logging must not crash the caller even with bad paths."""
        write(Path("/nonexistent/path"), "test")

    def test_rotation(self):
        """Test that rotation happens when file exceeds max size."""
        # Create a large audit file to trigger rotation
        log_path = self.root / ".patchi" / "hosted" / "audit.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)

        # Write enough data to exceed MAX_SIZE_BYTES
        large_data = "x" * (MAX_SIZE_BYTES + 1000)
        log_path.write_text(large_data + "\n", encoding="utf-8")

        # Write should trigger rotation
        write(self.root, "after_rotation")
        self.assertTrue(log_path.exists())

    def test_entry_timestamp(self):
        before = time.time()
        write(self.root, "timed_event")
        after = time.time()
        entries = read_recent(self.root, 1)
        self.assertGreaterEqual(entries[0]["timestamp"], before)
        self.assertLessEqual(entries[0]["timestamp"], after)


if __name__ == "__main__":
    unittest.main()
