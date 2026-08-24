"""Unit tests for patchi.core.queue"""

import tempfile
import unittest
from pathlib import Path

from patchi.core import config as cfg
from patchi.core import queue as q
from patchi.core.constants import QUEUE_MAX_DEPTH, QueueItemState


def _setup(tmp: Path) -> Path:
    cfg.init_project(tmp)
    return tmp


class TestEnqueue(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_enqueue_returns_id(self):
        item_id = q.enqueue("scan", "full", root=self.root)
        self.assertIsNotNone(item_id)
        self.assertEqual(len(item_id), 8)

    def test_enqueued_item_is_waiting(self):
        item_id = q.enqueue("scan", root=self.root)
        item = q.get_item(item_id, self.root)
        self.assertIsNotNone(item)
        self.assertEqual(item["state"], QueueItemState.WAITING.value)

    def test_enqueued_item_has_type_and_target(self):
        item_id = q.enqueue("fix", "src/auth/", root=self.root)
        item = q.get_item(item_id, self.root)
        self.assertEqual(item["type"], "fix")
        self.assertEqual(item["target"], "src/auth/")

    def test_enqueue_multiple(self):
        q.enqueue("scan", root=self.root)
        q.enqueue("fix", root=self.root)
        q.enqueue("test", root=self.root)
        items = q.list_items(QueueItemState.WAITING, self.root)
        self.assertEqual(len(items), 3)

    def test_queue_full_raises(self):
        for _ in range(QUEUE_MAX_DEPTH):
            q.enqueue("scan", root=self.root)
        with self.assertRaises(q.QueueFullError):
            q.enqueue("scan", root=self.root)

    def test_enqueue_with_extra_data(self):
        item_id = q.enqueue("scan", extra={"priority_reason": "user_requested"}, root=self.root)
        item = q.get_item(item_id, self.root)
        self.assertEqual(item.get("priority_reason"), "user_requested")


class TestStateTransitions(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_mark_active(self):
        item_id = q.enqueue("scan", root=self.root)
        ok = q.mark_active(item_id, self.root)
        self.assertTrue(ok)
        item = q.get_item(item_id, self.root)
        self.assertEqual(item["state"], QueueItemState.ACTIVE.value)
        self.assertIsNotNone(item["started"])

    def test_mark_done(self):
        item_id = q.enqueue("scan", root=self.root)
        q.mark_active(item_id, self.root)
        ok = q.mark_done(item_id, result={"files": 10}, root=self.root)
        self.assertTrue(ok)
        item = q.get_item(item_id, self.root)
        self.assertEqual(item["state"], QueueItemState.DONE.value)
        self.assertEqual(item["result"]["files"], 10)
        self.assertIsNotNone(item["completed"])

    def test_mark_failed(self):
        item_id = q.enqueue("fix", root=self.root)
        q.mark_active(item_id, self.root)
        ok = q.mark_failed(item_id, "out of memory", self.root)
        self.assertTrue(ok)
        item = q.get_item(item_id, self.root)
        self.assertEqual(item["state"], QueueItemState.FAILED.value)
        self.assertEqual(item["error"], "out of memory")

    def test_mark_skipped(self):
        item_id = q.enqueue("test", root=self.root)
        ok = q.mark_skipped(item_id, self.root)
        self.assertTrue(ok)
        item = q.get_item(item_id, self.root)
        self.assertEqual(item["state"], QueueItemState.SKIPPED.value)

    def test_update_nonexistent_returns_false(self):
        ok = q.mark_active("ghost_id", self.root)
        self.assertFalse(ok)


class TestPauseResume(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_not_paused_by_default(self):
        self.assertFalse(q.is_paused(self.root))

    def test_pause(self):
        q.pause(self.root)
        self.assertTrue(q.is_paused(self.root))

    def test_resume(self):
        q.pause(self.root)
        q.resume(self.root)
        self.assertFalse(q.is_paused(self.root))

    def test_next_waiting_returns_none_when_paused(self):
        q.enqueue("scan", root=self.root)
        q.pause(self.root)
        self.assertIsNone(q.next_waiting(self.root))


class TestSkip(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_skip_active_item(self):
        item_id = q.enqueue("scan", root=self.root)
        q.mark_active(item_id, self.root)
        skipped_id = q.skip_active(self.root)
        self.assertEqual(skipped_id, item_id)
        item = q.get_item(item_id, self.root)
        self.assertEqual(item["state"], QueueItemState.SKIPPED.value)

    def test_skip_with_nothing_active_returns_none(self):
        q.enqueue("scan", root=self.root)
        skipped_id = q.skip_active(self.root)
        self.assertIsNone(skipped_id)


class TestClear(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_clear_removes_waiting_only(self):
        id1 = q.enqueue("scan", root=self.root)
        id2 = q.enqueue("fix", root=self.root)
        q.mark_active(id1, self.root)
        q.mark_done(id1, root=self.root)

        removed = q.clear(self.root)
        self.assertEqual(removed, 1)  # only id2 (waiting) removed
        self.assertIsNotNone(q.get_item(id1, self.root))  # done item preserved
        self.assertIsNone(q.get_item(id2, self.root))

    def test_clear_all_removes_everything(self):
        q.enqueue("scan", root=self.root)
        id2 = q.enqueue("fix", root=self.root)
        q.mark_active(id2, self.root)
        q.mark_done(id2, root=self.root)

        removed = q.clear_all(self.root)
        self.assertEqual(removed, 2)
        self.assertEqual(q.list_items(root=self.root), [])


class TestNextWaiting(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_returns_none_when_empty(self):
        self.assertIsNone(q.next_waiting(self.root))

    def test_returns_first_waiting(self):
        id1 = q.enqueue("scan", root=self.root)
        q.enqueue("fix", root=self.root)
        nxt = q.next_waiting(self.root)
        self.assertEqual(nxt["id"], id1)

    def test_priority_ordering(self):
        q.enqueue("scan", priority=0, root=self.root)
        id_high = q.enqueue("fix", priority=10, root=self.root)
        nxt = q.next_waiting(self.root)
        self.assertEqual(nxt["id"], id_high)


class TestStats(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_stats_all_zero_initially(self):
        s = q.stats(self.root)
        self.assertEqual(s["waiting"], 0)
        self.assertEqual(s["active"], 0)
        self.assertEqual(s["done"], 0)
        self.assertEqual(s["failed"], 0)

    def test_stats_reflect_state(self):
        id1 = q.enqueue("scan", root=self.root)
        id2 = q.enqueue("fix", root=self.root)
        q.enqueue("test", root=self.root)

        q.mark_active(id1, self.root)
        q.mark_done(id1, root=self.root)
        q.mark_active(id2, self.root)

        s = q.stats(self.root)
        self.assertEqual(s["waiting"], 1)
        self.assertEqual(s["active"], 1)
        self.assertEqual(s["done"], 1)

    def test_depth_counts_waiting_only(self):
        q.enqueue("scan", root=self.root)
        q.enqueue("scan", root=self.root)
        self.assertEqual(q.depth(self.root), 2)


if __name__ == "__main__":
    unittest.main()
