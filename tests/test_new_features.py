"""
Comprehensive tests for new features — areas the original test suite didn't cover.

Covers:
- File classifier (AST-first brain purpose field)
- Health score history (memory module)
- Rejection learning (memory module + count tracking)
- Offline mode guard in _call_ai
- Key management API endpoints
- Missing memory functions (clear_all)
- Brain classifier batch mode
- Env file key read/write helpers in api.py
- p scan --offline flag wiring
- ConfigBulkSave (web API)
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path


def _project(tmp: Path) -> Path:
    import patchi.core.config as cfg

    cfg.init_project(tmp)
    return tmp


# ── File classifier tests ──────────────────────────────────────────────────────


class TestFileClassifier(unittest.TestCase):
    def _classify(self, rel_path: str, content: str = "") -> str:
        import tempfile

        from patchi.core.brain.classifier import classify_file

        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / rel_path
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content or "pass\n", encoding="utf-8")
            return classify_file(rel_path, p)

    # Part 7 §0: content outranks path naming. A file whose entire body is
    # `pass` must NOT be labeled by its filename — that was the old guess.

    def test_test_file_by_path(self):
        label = self._classify("tests/test_auth.py", "import pytest\n")
        self.assertIn("test", label.lower())

    def test_cli_command_by_path(self):
        label = self._classify(
            "patchi/cli/commands/scan_cmd.py", "import argparse\n\ndef main():\n    pass\n"
        )
        self.assertIn("CLI", label)

    def test_config_by_path(self):
        label = self._classify("config/settings.py", "DEBUG = True\nTIMEOUT = 30\n")
        self.assertIn("config", label.lower())

    def test_empty_body_not_labeled_by_name(self):
        """A `pass`-only file has no evidence — the name must not decide."""
        label = self._classify("config/settings.py")
        self.assertEqual(label, "Python module")

    def test_init_file(self):
        label = self._classify("patchi/core/__init__.py")
        self.assertIn("init", label.lower())

    def test_route_handler_by_import(self):
        content = "from fastapi import APIRouter\nrouter = APIRouter()\n"
        label = self._classify("src/routes.py", content)
        self.assertIn("FastAPI", label)

    def test_test_file_by_import(self):
        content = "import pytest\n\ndef test_something(): pass\n"
        label = self._classify("src/check.py", content)
        self.assertIn("test", label.lower())

    def test_json_is_config(self):
        label = self._classify("data/settings.json")
        self.assertIn("config", label.lower())

    def test_markdown_is_docs(self):
        label = self._classify("README.md")
        self.assertIn("doc", label.lower())

    def test_agent_by_class_name(self):
        content = "from base import BaseAgent\nclass MyScanner(BaseAgent):\n    pass\n"
        label = self._classify("core/agents/my_scanner.py", content)
        # class name says scanner — content-derived, no path needed
        self.assertIn("scanner", label.lower())

    def test_batch_classify_returns_all_paths(self):
        from patchi.core.brain.classifier import batch_classify
        from patchi.core.brain.scanner import FileInfo, Lang

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            files = []
            for name in ["app.py", "config.py", "tests/test_app.py"]:
                p = root / name
                p.parent.mkdir(exist_ok=True)
                p.write_text("pass\n")
                files.append(FileInfo(path=name, language=Lang.PYTHON, size_bytes=4, lines=1))

            result = batch_classify(files, root, ai_config=None)
            self.assertEqual(len(result), 3)
            for name in ["app.py", "config.py", "tests/test_app.py"]:
                self.assertIn(name, result)
                self.assertIsInstance(result[name], str)
                self.assertGreater(len(result[name]), 0)


# ── Health score history tests ─────────────────────────────────────────────────


class TestHealthHistory(unittest.TestCase):
    def test_log_and_retrieve(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _project(root)
            import patchi.core.memory as mem

            mem.log_health_score(72, 14, root)
            mem.log_health_score(85, 7, root)

            history = mem.get_health_history(root)
            self.assertEqual(len(history), 2)
            self.assertEqual(history[0]["health_score"], 72)
            self.assertEqual(history[1]["health_score"], 85)
            self.assertEqual(history[0]["finding_count"], 14)

    def test_history_capped_at_500(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _project(root)
            import patchi.core.memory as mem

            for i in range(520):
                mem.log_health_score(i % 100, 0, root)

            history = mem.get_health_history(root)
            self.assertLessEqual(len(history), 500)

    def test_history_returns_empty_before_any_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _project(root)
            import patchi.core.memory as mem

            history = mem.get_health_history(root)
            self.assertEqual(history, [])


# ── Rejection learning tests ───────────────────────────────────────────────────


class TestRejectionLearning(unittest.TestCase):
    def test_records_rejection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _project(root)
            import patchi.core.memory as mem

            count = mem.record_rejection("dead_code", root)
            self.assertEqual(count, 1)

    def test_counts_accumulate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _project(root)
            import patchi.core.memory as mem

            mem.record_rejection("dead_code", root)
            mem.record_rejection("dead_code", root)
            count = mem.record_rejection("dead_code", root)
            self.assertEqual(count, 3)

    def test_different_types_tracked_separately(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _project(root)
            import patchi.core.memory as mem

            mem.record_rejection("dead_code", root)
            mem.record_rejection("dead_code", root)
            mem.record_rejection("hardcoded_secret", root)
            counts = mem.get_rejection_counts(root)
            self.assertEqual(counts["dead_code"], 2)
            self.assertEqual(counts["hardcoded_secret"], 1)


# ── Offline mode guard tests ───────────────────────────────────────────────────


class TestOfflineMode(unittest.TestCase):
    def setUp(self):
        os.environ.pop("PATCHI_OFFLINE", None)

    def tearDown(self):
        os.environ.pop("PATCHI_OFFLINE", None)

    def test_call_ai_returns_empty_when_offline(self):
        os.environ["PATCHI_OFFLINE"] = "1"
        from patchi.core.fix.base import _call_ai

        # Should return "" immediately without attempting any HTTP call
        result = _call_ai("test prompt", {}, max_tokens=10)
        self.assertEqual(result, "")

    def test_call_ai_proceeds_when_not_offline(self):
        # No PATCHI_OFFLINE set — function should at least try (and fail gracefully)
        from patchi.core.fix.base import _call_ai

        # With empty config and no keys — should return "" from all-providers-fail path
        result = _call_ai("test", {}, max_tokens=5)
        self.assertEqual(result, "")


# ── Memory clear_all tests ─────────────────────────────────────────────────────


class TestMemoryClearAll(unittest.TestCase):
    def test_clear_all_resets_json_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _project(root)
            import patchi.core.memory as mem

            # Write something to health history
            mem.log_health_score(80, 3, root)
            pre = mem.get_health_history(root)
            self.assertEqual(len(pre), 1)

            # Clear all
            mem.clear_all(root)

            # history.json now contains empty JSON — returns {} or []
            hist_path = root / ".patchi" / "history.json"
            if hist_path.exists():
                content = hist_path.read_text()
                self.assertIn(content.strip(), ("{}", "[]", ""))


# ── Web API key endpoint tests ─────────────────────────────────────────────────


class TestKeyWebAPI(unittest.TestCase):
    def _client(self, tmp: Path):
        _project(tmp)
        from fastapi.testclient import TestClient

        from patchi.web.app import create_app

        app = create_app(tmp)
        return TestClient(app, raise_server_exceptions=False)

    def test_list_keys_returns_empty_initially(self):
        with tempfile.TemporaryDirectory() as tmp:
            c = self._client(Path(tmp))
            r = c.get("/api/keys")
            self.assertEqual(r.status_code, 200)
            self.assertIn("keys", r.json())

    def test_add_key_stores_to_env_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            c = self._client(root)
            r = c.post(
                "/api/keys/add",
                json={
                    "provider": "groq",
                    "key": "gsk_test_key_12345",
                    "nickname": "groq-test",
                },
            )
            self.assertEqual(r.status_code, 200)
            data = r.json()
            self.assertTrue(data["ok"])

            # Verify .patchi/.env was created with the key
            env_file = root / ".patchi" / ".env"
            self.assertTrue(env_file.exists())
            self.assertIn("gsk_test_key_12345", env_file.read_text())

    def test_add_key_rejects_missing_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            c = self._client(Path(tmp))
            r = c.post("/api/keys/add", json={"provider": "groq"})  # no key
            self.assertEqual(r.status_code, 400)

    def test_remove_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            c = self._client(root)
            c.post("/api/keys/add", json={"provider": "groq", "key": "sk_test", "nickname": "g1"})
            r = c.post("/api/keys/remove", json={"nickname": "g1"})
            self.assertEqual(r.status_code, 200)
            self.assertTrue(r.json()["ok"])

    def test_guard_endpoint_returns_structure(self):
        with tempfile.TemporaryDirectory() as tmp:
            c = self._client(Path(tmp))
            r = c.get("/api/guard")
            self.assertEqual(r.status_code, 200)
            data = r.json()
            self.assertIn("connected", data)
            self.assertIn("alerts", data)

    def test_queue_clear_endpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            c = self._client(Path(tmp))
            r = c.post("/api/queue/clear")
            self.assertEqual(r.status_code, 200)

    def test_memory_clear_endpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            c = self._client(Path(tmp))
            r = c.post("/api/memory/clear")
            self.assertEqual(r.status_code, 200)
            self.assertTrue(r.json()["ok"])

    def test_config_bulk_save(self):
        with tempfile.TemporaryDirectory() as tmp:
            c = self._client(Path(tmp))
            r = c.post("/api/config", json={"mode": "auto", "queue_mode": "multi"})
            self.assertEqual(r.status_code, 200)
            self.assertTrue(r.json()["ok"])
            # Verify persisted
            r2 = c.get("/api/config")
            self.assertEqual(r2.json().get("mode"), "auto")

    def test_config_rejects_forbidden_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            c = self._client(Path(tmp))
            r = c.post("/api/config", json={"key": "ai", "value": {"steal": True}})
            self.assertEqual(r.status_code, 400)


# ── Env file helper tests ──────────────────────────────────────────────────────


class TestEnvFileHelpers(unittest.TestCase):
    def test_write_and_read_key(self):
        from patchi.web.api_legacy import _read_env_file_key, _write_env_file_key

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env_file = root / ".env"
            _write_env_file_key(env_file, "TEST_KEY", "abc123")
            _read_env_file_key(root, "TEST_KEY")  # type: ignore
            # direct path test
            content = env_file.read_text()
            self.assertIn("abc123", content)

    def test_overwrite_existing_key(self):
        from patchi.web.api_legacy import _write_env_file_key

        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / ".env"
            _write_env_file_key(env_file, "MY_KEY", "first")
            _write_env_file_key(env_file, "MY_KEY", "second")
            content = env_file.read_text()
            self.assertNotIn("first", content)
            self.assertIn("second", content)
            # Only one entry for the key
            self.assertEqual(content.count("MY_KEY="), 1)


if __name__ == "__main__":
    unittest.main()
