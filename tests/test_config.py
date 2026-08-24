"""Unit tests for patchi.core.config"""

import tempfile
import unittest
from pathlib import Path

from patchi.core import config as cfg
from patchi.core.constants import DeviceTier, Mode, QueueMode, RestrictionType


class TestInitProject(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_creates_patchi_dir(self):
        cfg.init_project(self.root)
        self.assertTrue((self.root / ".patchi").is_dir())

    def test_creates_memory_dir(self):
        cfg.init_project(self.root)
        self.assertTrue((self.root / ".patchi" / "memory").is_dir())

    def test_creates_config_file(self):
        cfg.init_project(self.root)
        self.assertTrue((self.root / ".patchi" / "config.json").exists())

    def test_default_mode_is_confirm(self):
        config = cfg.init_project(self.root)
        self.assertEqual(config["mode"], Mode.CONFIRM.value)

    def test_default_queue_mode_is_single(self):
        config = cfg.init_project(self.root)
        self.assertEqual(config["queue_mode"], QueueMode.SINGLE.value)

    def test_device_tier_override(self):
        config = cfg.init_project(self.root, device_tier=DeviceTier.HIGH)
        self.assertEqual(config["device_tier"], DeviceTier.HIGH.value)

    def test_safe_to_reinitialize(self):
        """Calling init_project twice should not overwrite existing values."""
        cfg.init_project(self.root)
        cfg.set_value("mode", Mode.AUTO.value, self.root)
        config = cfg.init_project(self.root)  # second call
        self.assertEqual(config["mode"], Mode.AUTO.value)

    def test_creates_all_memory_files(self):
        cfg.init_project(self.root)
        memory_dir = self.root / ".patchi" / "memory"
        expected_files = [
            "brain.json",
            "patches.json",
            "failed_patches.json",
            "scan_results.json",
            "known_issues.json",
            "restrictions.json",
            "dev_tokens.json",
        ]
        for fname in expected_files:
            self.assertTrue((memory_dir / fname).exists(), f"Missing: {fname}")


class TestLoadAndSave(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)
        cfg.init_project(self.root)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_load_returns_dict(self):
        config = cfg.load(self.root)
        self.assertIsInstance(config, dict)

    def test_set_and_get(self):
        cfg.set_value("mode", Mode.AUTOPILOT.value, self.root)
        self.assertEqual(cfg.get("mode", self.root), Mode.AUTOPILOT.value)

    def test_nested_set_get(self):
        cfg.set_value("ai.local_model_name", "llama3.2", self.root)
        config = cfg.load(self.root)
        self.assertEqual(config["ai"]["local_model_name"], "llama3.2")

    def test_unknown_key_raises_on_read(self):
        """Missing nested key returns None via get, not exception."""
        config = cfg.load(self.root)
        self.assertIsNone(config.get("nonexistent_key"))


class TestModeHelpers(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)
        cfg.init_project(self.root)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_get_mode_default(self):
        self.assertEqual(cfg.get_mode(self.root), Mode.CONFIRM)

    def test_set_mode(self):
        cfg.set_mode(Mode.AUTO, self.root)
        self.assertEqual(cfg.get_mode(self.root), Mode.AUTO)

    def test_get_queue_mode_default(self):
        self.assertEqual(cfg.get_queue_mode(self.root), QueueMode.SINGLE)

    def test_set_queue_mode(self):
        cfg.set_queue_mode(QueueMode.MULTI, self.root)
        self.assertEqual(cfg.get_queue_mode(self.root), QueueMode.MULTI)


class TestRestrictions(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)
        cfg.init_project(self.root)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_add_restriction(self):
        cfg.add_restriction("payments/", RestrictionType.NO_TOUCH, root=self.root)
        restrictions = cfg.get_restrictions(self.root)
        self.assertEqual(len(restrictions), 1)
        self.assertEqual(restrictions[0]["path"], "payments/")
        self.assertEqual(restrictions[0]["type"], RestrictionType.NO_TOUCH.value)

    def test_no_duplicates(self):
        cfg.add_restriction("payments/", RestrictionType.NO_TOUCH, root=self.root)
        cfg.add_restriction("payments/", RestrictionType.NO_TOUCH, root=self.root)
        self.assertEqual(len(cfg.get_restrictions(self.root)), 1)

    def test_remove_restriction(self):
        cfg.add_restriction("payments/", RestrictionType.NO_TOUCH, root=self.root)
        removed = cfg.remove_restriction("payments/", self.root)
        self.assertTrue(removed)
        self.assertEqual(len(cfg.get_restrictions(self.root)), 0)

    def test_remove_nonexistent_returns_false(self):
        removed = cfg.remove_restriction("does_not_exist/", self.root)
        self.assertFalse(removed)

    def test_toggle_restriction(self):
        cfg.add_restriction("src/legacy/", RestrictionType.SCAN_ONLY, root=self.root)
        ok = cfg.toggle_restriction("src/legacy/", enabled=False, root=self.root)
        self.assertTrue(ok)
        r = cfg.get_restrictions(self.root)[0]
        self.assertFalse(r["enabled"])

    def test_multiple_restriction_types(self):
        cfg.add_restriction("payments/", RestrictionType.NO_TOUCH, root=self.root)
        cfg.add_restriction("src/core/", RestrictionType.SCAN_ONLY, root=self.root)
        cfg.add_restriction(".env.production", RestrictionType.SENSITIVE, root=self.root)
        restrictions = cfg.get_restrictions(self.root)
        self.assertEqual(len(restrictions), 3)
        types = {r["type"] for r in restrictions}
        self.assertEqual(
            types,
            {
                RestrictionType.NO_TOUCH.value,
                RestrictionType.SCAN_ONLY.value,
                RestrictionType.SENSITIVE.value,
            },
        )


class TestProjectRootDetection(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_find_project_root_returns_none_when_missing(self):
        # Hermetic: patch the marker dir name so no real .patchi up-tree
        # (e.g. a global config in the user's home) can satisfy the walk.
        import unittest.mock as mock

        with mock.patch.object(cfg, "PATCHI_DIR", ".patchi-no-such-marker"):
            result = cfg.find_project_root(self.root)
        self.assertIsNone(result)

    def test_find_project_root_finds_patchi_dir(self):
        cfg.init_project(self.root)
        result = cfg.find_project_root(self.root)
        self.assertEqual(result, self.root)

    def test_find_project_root_walks_up(self):
        cfg.init_project(self.root)
        subdir = self.root / "src" / "components"
        subdir.mkdir(parents=True)
        result = cfg.find_project_root(subdir)
        self.assertEqual(result, self.root)


if __name__ == "__main__":
    unittest.main()
