"""Unit tests for patchi.core.snapshot"""

import tempfile
import unittest
from pathlib import Path

from patchi.core import config as cfg
from patchi.core import snapshot


def _setup(tmp: Path) -> Path:
    cfg.init_project(tmp)
    return tmp


def _write_file(root: Path, rel_path: str, content: str) -> Path:
    abs_path = root / rel_path
    abs_path.parent.mkdir(parents=True, exist_ok=True)
    abs_path.write_text(content, encoding="utf-8")
    return abs_path


class TestCreate(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_create_returns_id(self):
        _write_file(self.root, "src/app.py", "print('hello')")
        snap_id = snapshot.create(["src/app.py"], "patch001", self.root)
        self.assertIsNotNone(snap_id)
        self.assertEqual(len(snap_id), 8)

    def test_snapshot_stores_file_content(self):
        _write_file(self.root, "src/app.py", "original content")
        snap_id = snapshot.create(["src/app.py"], "patch001", self.root)
        record = snapshot.load(snap_id, self.root)
        self.assertIsNotNone(record)
        self.assertEqual(record["files"]["src/app.py"], "original content")

    def test_snapshot_stores_multiple_files(self):
        _write_file(self.root, "src/a.py", "content a")
        _write_file(self.root, "src/b.py", "content b")
        snap_id = snapshot.create(["src/a.py", "src/b.py"], "patch002", self.root)
        record = snapshot.load(snap_id, self.root)
        self.assertEqual(len(record["files"]), 2)

    def test_nonexistent_file_stored_as_none(self):
        snap_id = snapshot.create(["src/new_file.py"], "patch003", self.root)
        record = snapshot.load(snap_id, self.root)
        self.assertIsNone(record["files"]["src/new_file.py"])

    def test_snapshot_records_patch_id(self):
        _write_file(self.root, "src/app.py", "content")
        snap_id = snapshot.create(["src/app.py"], "my_patch_id", self.root)
        record = snapshot.load(snap_id, self.root)
        self.assertEqual(record["patch_id"], "my_patch_id")

    def test_snapshot_has_timestamp(self):
        _write_file(self.root, "src/app.py", "content")
        snap_id = snapshot.create(["src/app.py"], "patch001", self.root)
        record = snapshot.load(snap_id, self.root)
        self.assertIn("created", record)


class TestRestore(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_restore_reverts_file_content(self):
        file_path = _write_file(self.root, "src/app.py", "original")
        snap_id = snapshot.create(["src/app.py"], "patch001", self.root)

        # Simulate a fix modifying the file
        file_path.write_text("modified by fix", encoding="utf-8")

        restored = snapshot.restore(snap_id, self.root)
        self.assertIn("src/app.py", restored)
        self.assertEqual(file_path.read_text(encoding="utf-8"), "original")

    def test_restore_multiple_files(self):
        path_a = _write_file(self.root, "src/a.py", "original a")
        path_b = _write_file(self.root, "src/b.py", "original b")
        snap_id = snapshot.create(["src/a.py", "src/b.py"], "patch002", self.root)

        path_a.write_text("modified a", encoding="utf-8")
        path_b.write_text("modified b", encoding="utf-8")

        restored = snapshot.restore(snap_id, self.root)
        self.assertEqual(len(restored), 2)
        self.assertEqual(path_a.read_text(), "original a")
        self.assertEqual(path_b.read_text(), "original b")

    def test_restore_deletes_file_that_didnt_exist(self):
        """If a fix created a new file, restoring should delete it."""
        snap_id = snapshot.create(["src/new_file.py"], "patch003", self.root)

        # Fix created the file
        new_file = _write_file(self.root, "src/new_file.py", "created by fix")

        restored = snapshot.restore(snap_id, self.root)
        self.assertIn("src/new_file.py", restored)
        self.assertFalse(new_file.exists())

    def test_restore_nonexistent_snapshot_raises(self):
        with self.assertRaises(FileNotFoundError):
            snapshot.restore("ghost_snap", self.root)


class TestListAndGet(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_list_empty(self):
        self.assertEqual(snapshot.list_all(self.root), [])

    def test_list_returns_all_snapshots(self):
        _write_file(self.root, "src/a.py", "a")
        _write_file(self.root, "src/b.py", "b")
        snapshot.create(["src/a.py"], "patch001", self.root)
        snapshot.create(["src/b.py"], "patch002", self.root)
        snaps = snapshot.list_all(self.root)
        self.assertEqual(len(snaps), 2)

    def test_list_does_not_include_file_content(self):
        _write_file(self.root, "src/a.py", "sensitive content")
        snapshot.create(["src/a.py"], "patch001", self.root)
        snaps = snapshot.list_all(self.root)
        self.assertNotIn("files", snaps[0])
        self.assertIn("file_paths", snaps[0])

    def test_get_by_patch_id(self):
        _write_file(self.root, "src/a.py", "content")
        snapshot.create(["src/a.py"], "target_patch", self.root)
        record = snapshot.get_by_patch_id("target_patch", self.root)
        self.assertIsNotNone(record)
        self.assertEqual(record["patch_id"], "target_patch")

    def test_get_by_patch_id_missing_returns_none(self):
        result = snapshot.get_by_patch_id("ghost_patch", self.root)
        self.assertIsNone(result)

    def test_load_missing_returns_none(self):
        result = snapshot.load("ghost_id", self.root)
        self.assertIsNone(result)


class TestDelete(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_delete_single(self):
        _write_file(self.root, "src/a.py", "content")
        snap_id = snapshot.create(["src/a.py"], "p1", self.root)
        ok = snapshot.delete(snap_id, self.root)
        self.assertTrue(ok)
        self.assertIsNone(snapshot.load(snap_id, self.root))

    def test_delete_nonexistent_returns_false(self):
        ok = snapshot.delete("ghost_id", self.root)
        self.assertFalse(ok)

    def test_delete_all(self):
        _write_file(self.root, "src/a.py", "a")
        _write_file(self.root, "src/b.py", "b")
        snapshot.create(["src/a.py"], "p1", self.root)
        snapshot.create(["src/b.py"], "p2", self.root)
        count = snapshot.delete_all(self.root)
        self.assertEqual(count, 2)
        self.assertEqual(snapshot.list_all(self.root), [])


class TestDiff(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_diff_shows_changes(self):
        file_path = _write_file(self.root, "src/app.py", "line one\nline two\n")
        snap_id = snapshot.create(["src/app.py"], "patch001", self.root)
        file_path.write_text("line one\nline two modified\n", encoding="utf-8")

        diffs = snapshot.compute_diff(snap_id, self.root)
        self.assertIn("src/app.py", diffs)
        self.assertIn("modified", diffs["src/app.py"])
        self.assertIn("---", diffs["src/app.py"])

    def test_diff_empty_when_no_changes(self):
        _write_file(self.root, "src/app.py", "unchanged content\n")
        snap_id = snapshot.create(["src/app.py"], "patch001", self.root)
        # No modification — diff should be empty string
        diffs = snapshot.compute_diff(snap_id, self.root)
        self.assertEqual(diffs["src/app.py"], "")


if __name__ == "__main__":
    unittest.main()
