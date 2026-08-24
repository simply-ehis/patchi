"""Unit tests for patchi.core.memory"""

import tempfile
import unittest
from pathlib import Path

from patchi.core import config as cfg
from patchi.core import memory as mem
from patchi.core.constants import MemoryCategory


def _setup(tmp: Path) -> Path:
    cfg.init_project(tmp)
    return tmp


class TestBrain(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_get_brain_empty(self):
        brain = mem.get_brain(self.root)
        self.assertIsInstance(brain, dict)
        self.assertEqual(brain, {})

    def test_save_and_get_brain(self):
        brain_data = {"file_count": 42, "route_count": 7, "framework": "FastAPI"}
        mem.save_brain(brain_data, self.root)
        result = mem.get_brain(self.root)
        self.assertEqual(result["file_count"], 42)
        self.assertEqual(result["framework"], "FastAPI")

    def test_mark_brain_stale(self):
        mem.save_brain({"file_count": 10}, self.root)
        mem.mark_brain_stale(["src/app.py", "src/routes.py"], self.root)
        brain = mem.get_brain(self.root)
        self.assertTrue(brain["stale"])
        self.assertIn("2 file(s) changed", brain["stale_reason"])
        self.assertEqual(len(brain["changed_files"]), 2)

    def test_delete_brain(self):
        mem.save_brain({"file_count": 5}, self.root)
        mem.delete(MemoryCategory.BRAIN, self.root)
        brain = mem.get_brain(self.root)
        self.assertEqual(brain, {})


class TestPatches(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_list_patches_empty(self):
        patches = mem.list_patches(self.root)
        self.assertEqual(patches, [])

    def test_save_patch_assigns_id(self):
        patch = {"file": "src/auth.py", "risk_score": 25}
        patch_id = mem.save_patch(patch, self.root)
        self.assertIsNotNone(patch_id)
        self.assertEqual(len(patch_id), 8)

    def test_save_and_list_patches(self):
        mem.save_patch({"file": "a.py", "risk_score": 10}, self.root)
        mem.save_patch({"file": "b.py", "risk_score": 40}, self.root)
        patches = mem.list_patches(self.root)
        self.assertEqual(len(patches), 2)

    def test_get_patch_by_id(self):
        patch_id = mem.save_patch({"file": "auth.py", "risk_score": 20}, self.root)
        result = mem.get_patch(patch_id, self.root)
        self.assertIsNotNone(result)
        self.assertEqual(result["file"], "auth.py")

    def test_get_patch_missing_returns_none(self):
        result = mem.get_patch("nonexistent", self.root)
        self.assertIsNone(result)

    def test_patch_has_timestamp(self):
        patch_id = mem.save_patch({"file": "x.py"}, self.root)
        patch = mem.get_patch(patch_id, self.root)
        self.assertIn("timestamp", patch)

    def test_delete_patches(self):
        mem.save_patch({"file": "a.py"}, self.root)
        mem.delete_patches(self.root)
        self.assertEqual(mem.list_patches(self.root), [])


class TestFailedPatches(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_save_failed(self):
        mem.save_failed("abc12345", "Tests failed: auth_test.py line 42", root=self.root)
        failed = mem.list_failed(self.root)
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0]["id"], "abc12345")
        self.assertIn("Tests failed", failed[0]["reason"])

    def test_delete_failed(self):
        mem.save_failed("abc12345", "reason", root=self.root)
        mem.delete_failed(self.root)
        self.assertEqual(mem.list_failed(self.root), [])


class TestScanResults(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_save_and_get_scan_result(self):
        mem.save_scan_result("CoreScanner", {"files_scanned": 12, "issues": 3}, self.root)
        results = mem.get_scan_results(self.root)
        self.assertIn("CoreScanner", results)
        self.assertEqual(results["CoreScanner"]["files_scanned"], 12)

    def test_scan_result_has_timestamp(self):
        mem.save_scan_result("TestScanner", {"count": 1}, self.root)
        results = mem.get_scan_results(self.root)
        self.assertIn("timestamp", results["TestScanner"])

    def test_overwrite_scan_result(self):
        mem.save_scan_result("CoreScanner", {"files_scanned": 5}, self.root)
        mem.save_scan_result("CoreScanner", {"files_scanned": 10}, self.root)
        results = mem.get_scan_results(self.root)
        self.assertEqual(results["CoreScanner"]["files_scanned"], 10)


class TestKnownIssues(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_save_issue(self):
        mem.save_issue({"type": "security", "severity": "high", "file": "auth.py"}, self.root)
        issues = mem.list_issues(self.root)
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["type"], "security")

    def test_issue_gets_id(self):
        mem.save_issue({"type": "bug"}, self.root)
        issues = mem.list_issues(self.root)
        self.assertIn("id", issues[0])

    def test_resolve_issue(self):
        mem.save_issue({"type": "bug", "id": "fix001"}, self.root)
        ok = mem.resolve_issue("fix001", self.root)
        self.assertTrue(ok)
        self.assertEqual(mem.list_issues(self.root), [])

    def test_resolve_nonexistent_returns_false(self):
        ok = mem.resolve_issue("ghost_id", self.root)
        self.assertFalse(ok)

    def test_delete_issues(self):
        mem.save_issue({"type": "dead_code"}, self.root)
        mem.delete_issues(self.root)
        self.assertEqual(mem.list_issues(self.root), [])


class TestTokens(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_save_token(self):
        mem.save_token("admin", "ADMIN_TOKEN", self.root)
        tokens = mem.list_tokens(self.root)
        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0]["name"], "admin")
        self.assertEqual(tokens[0]["env_var"], "ADMIN_TOKEN")

    def test_no_duplicate_tokens(self):
        mem.save_token("admin", "ADMIN_TOKEN", self.root)
        mem.save_token("admin", "ADMIN_TOKEN", self.root)
        self.assertEqual(len(mem.list_tokens(self.root)), 1)

    def test_remove_token(self):
        mem.save_token("admin", "ADMIN_TOKEN", self.root)
        ok = mem.remove_token("admin", self.root)
        self.assertTrue(ok)
        self.assertEqual(mem.list_tokens(self.root), [])

    def test_remove_nonexistent_returns_false(self):
        ok = mem.remove_token("ghost", self.root)
        self.assertFalse(ok)


class TestSummary(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_summary_all_categories_present(self):
        s = mem.summary(self.root)
        for category in MemoryCategory:
            self.assertIn(category.value, s)

    def test_summary_counts_items(self):
        mem.save_patch({"file": "a.py"}, self.root)
        mem.save_patch({"file": "b.py"}, self.root)
        s = mem.summary(self.root)
        self.assertEqual(s["patches"]["count"], 2)


class TestDeleteAll(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_delete_all_clears_everything(self):
        mem.save_brain({"file_count": 10}, self.root)
        mem.save_patch({"file": "a.py"}, self.root)
        mem.save_issue({"type": "bug"}, self.root)
        mem.save_token("admin", "TOKEN", self.root)

        mem.delete_all(self.root)

        self.assertEqual(mem.get_brain(self.root), {})
        self.assertEqual(mem.list_patches(self.root), [])
        self.assertEqual(mem.list_issues(self.root), [])
        self.assertEqual(mem.list_tokens(self.root), [])


if __name__ == "__main__":
    unittest.main()
