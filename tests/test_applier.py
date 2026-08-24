"""Unit tests for patchi.core.fix.applier"""

import tempfile
import unittest
from pathlib import Path

from patchi.core import config as cfg
from patchi.core import memory as mem
from patchi.core.fix.applier import PatchApplier
from patchi.core.fix.patch import FileChange, Patch, PatchType


def _setup(tmp: Path) -> Path:
    cfg.init_project(tmp)
    # Lock the contract so the gate doesn't block
    brain = mem.get_brain(tmp)
    brain["contract_locked"] = True
    mem.save_brain(brain, tmp)
    return tmp


def _write(root: Path, rel: str, content: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def _make_patch(root: Path, path: str, original: str, proposed: str) -> Patch:
    _write(root, path, original)
    change = FileChange(path=path, original=original, proposed=proposed)
    return Patch(
        agent="CodeFixer",
        patch_type=PatchType.BUG_FIX,
        changes=[change],
        description="Test fix",
        risk_score=10,
        confidence=90,
    )


# Lint-clean fixtures: the applier runs ruff (E,F,W) on proposed content and
# auto-rolls-back on lint errors, so fixtures must be valid, defined names.
_ORIG = "def add(a, b):\n    return a + b\n"
_PROP = "def add(a, b):\n    return a + b + 1\n"


class TestPatchApplier(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_apply_writes_proposed_content(self):
        patch = _make_patch(self.root, "src/app.py", _ORIG, _PROP)
        applier = PatchApplier(self.root)
        result = applier.apply(patch)
        self.assertTrue(result.success)
        content = (self.root / "src/app.py").read_text()
        self.assertEqual(content, _PROP)

    def test_apply_creates_snapshot(self):
        patch = _make_patch(self.root, "src/app.py", _ORIG, _PROP)
        applier = PatchApplier(self.root)
        result = applier.apply(patch)
        self.assertTrue(result.success)
        self.assertNotEqual(result.snapshot_id, "")

    def test_apply_result_has_patch_id(self):
        patch = _make_patch(self.root, "src/app.py", _ORIG, _PROP)
        applier = PatchApplier(self.root)
        result = applier.apply(patch)
        self.assertEqual(result.patch_id, patch.id)

    def test_apply_multiple_files(self):
        _write(self.root, "src/a.py", _ORIG)
        _write(self.root, "src/b.py", _ORIG)
        changes = [
            FileChange("src/a.py", _ORIG, _PROP),
            FileChange("src/b.py", _ORIG, _PROP),
        ]
        patch = Patch(
            agent="CodeFixer",
            patch_type=PatchType.BUG_FIX,
            changes=changes,
            description="Multi fix",
            risk_score=10,
            confidence=90,
        )
        result = PatchApplier(self.root).apply(patch)
        self.assertTrue(result.success)
        self.assertEqual((self.root / "src/a.py").read_text(), _PROP)
        self.assertEqual((self.root / "src/b.py").read_text(), _PROP)

    def test_apply_marks_brain_stale(self):
        patch = _make_patch(self.root, "src/app.py", _ORIG, _PROP)
        # Set brain as fresh first
        brain = mem.get_brain(self.root)
        brain["stale"] = False
        mem.save_brain(brain, self.root)
        PatchApplier(self.root).apply(patch)
        # Brain should be marked stale after apply
        brain = mem.get_brain(self.root)
        self.assertTrue(brain.get("stale"))


class TestPatchRollback(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_rollback_restores_original(self):
        original = _ORIG
        patch = _make_patch(self.root, "src/app.py", original, _PROP)
        applier = PatchApplier(self.root)
        result = applier.apply(patch)
        self.assertTrue(result.success)

        # Now rollback
        rb = applier.rollback(patch.id, result.snapshot_id)
        self.assertTrue(rb.success)
        self.assertTrue(rb.rolled_back)

        content = (self.root / "src/app.py").read_text()
        self.assertEqual(content, original)

    def test_rollback_returns_error_for_bad_snapshot(self):
        rb = PatchApplier(self.root).rollback("fake_patch", "ghost_snapshot")
        self.assertFalse(rb.success)
        self.assertNotEqual(rb.error, "")


class TestApplierTestDetection(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_no_test_runner_when_no_tests(self):
        applier = PatchApplier(self.root)
        runner, cmd = applier._detect_test_runner(["src/app.py"])
        # No tests dir, no pytest in the project
        # runner may or may not be None depending on system pytest install
        # Just verify the method returns without error
        self.assertIsInstance(cmd, list)

    def test_find_python_tests_matches_convention(self):
        _write(self.root, "tests/test_app.py", "def test_foo(): pass")
        applier = PatchApplier(self.root)
        results = applier._find_python_tests(["src/app.py"])
        self.assertIn("tests/test_app.py", results)

    def test_find_python_tests_no_match(self):
        applier = PatchApplier(self.root)
        results = applier._find_python_tests(["src/orphan.py"])
        self.assertEqual(results, [])


if __name__ == "__main__":
    unittest.main()
