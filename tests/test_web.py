"""
Tests for patchi.web — Phase 8.

Tests: SpawnManager logic, event schema, API endpoints (via TestClient),
WebSocket connection, and spawn rejection reasons.
"""

from __future__ import annotations

import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi.testclient import TestClient

import patchi.core.config as config_mod
from patchi.web.app import create_app
from patchi.web.events import (
    evt_ant_rejected,
    evt_ant_spawned,
    evt_queue_updated,
    evt_status,
)
from patchi.web.spawn import MAX_USER_ANTS, SpawnManager

# ── Event schema ───────────────────────────────────────────────────────────────


class TestEventSchema(unittest.TestCase):
    def test_ant_spawned_shape(self):
        e = evt_ant_spawned("node1", "ant42")
        self.assertEqual(e["event"], "ant.spawned")
        self.assertEqual(e["data"]["ant_id"], "ant42")

    def test_ant_rejected_shape(self):
        e = evt_ant_rejected("node1", "capacity")
        self.assertEqual(e["data"]["reason"], "capacity")

    def test_status_shape(self):
        e = evt_status("confirm", 3, 5, True)
        self.assertEqual(e["event"], "status")
        self.assertEqual(e["data"]["mode"], "confirm")
        self.assertTrue(e["data"]["brain_fresh"])

    def test_queue_updated_shape(self):
        e = evt_queue_updated(4, 1, False)
        self.assertEqual(e["data"]["depth"], 4)
        self.assertFalse(e["data"]["paused"])


# ── Spawn manager ──────────────────────────────────────────────────────────────


class TestSpawnManager(unittest.TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory()
        self._root = Path(self._tmp.name)
        config_mod.init_project(self._root)
        self._sm = SpawnManager(self._root)
        self._sm.set_active(True)

    def tearDown(self):
        self._tmp.cleanup()

    def test_spawn_ok_returns_ant_id(self):
        ant_id, reason = self._sm.try_spawn("src/app.py")
        self.assertIsNotNone(ant_id)
        self.assertEqual(reason, "ok")

    def test_spawn_idle_returns_none(self):
        self._sm.set_active(False)
        ant_id, reason = self._sm.try_spawn("src/app.py")
        self.assertIsNone(ant_id)
        self.assertEqual(reason, "idle")

    def test_cooldown_blocks_second_tap(self):
        self._sm.try_spawn("src/app.py")
        ant_id, reason = self._sm.try_spawn("src/app.py")
        self.assertIsNone(ant_id)
        self.assertEqual(reason, "cooldown")

    def test_capacity_blocks_at_max(self):
        # Spawn MAX_USER_ANTS ants on different nodes
        for i in range(MAX_USER_ANTS):
            self._sm.try_spawn(f"file{i}.py")
        # Next spawn should be blocked
        ant_id, reason = self._sm.try_spawn("file99.py")
        self.assertIsNone(ant_id)
        self.assertEqual(reason, "capacity")

    def test_restricted_node_blocked(self):
        from patchi.core.constants import RestrictionType

        config_mod.add_restriction("secret.py", RestrictionType.NO_TOUCH, root=self._root)
        sm = SpawnManager(self._root)
        sm.set_active(True)
        ant_id, reason = sm.try_spawn("secret.py")
        self.assertIsNone(ant_id)
        self.assertEqual(reason, "restricted")

    def test_mark_done_frees_capacity(self):
        for i in range(MAX_USER_ANTS):
            ant_id, _ = self._sm.try_spawn(f"file{i}.py")
        # Mark one done, capacity should free
        first_ant = list(self._sm._ants.keys())[0]
        self._sm.mark_done(first_ant)
        ant_id, reason = self._sm.try_spawn("newfile.py")
        self.assertEqual(reason, "ok")

    def test_expired_ants_dont_count(self):
        ant_id, _ = self._sm.try_spawn("src/app.py")
        # Backdate the spawn time beyond expiry
        self._sm._ants[ant_id].spawned_at = time.time() - 70
        self._sm._expire_ants()
        self.assertEqual(self._sm.active_count(), 0)

    def test_all_active_returns_list(self):
        self._sm.try_spawn("a.py")
        active = self._sm.all_active()
        self.assertEqual(len(active), 1)
        self.assertIn("ant_id", active[0])
        self.assertIn("node_id", active[0])


# ── API endpoints ─────────────────────────────────────────────────────────────


class TestAPIEndpoints(unittest.TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory()
        self._root = Path(self._tmp.name)
        config_mod.init_project(self._root)
        self._app = create_app(self._root)
        self._client = TestClient(self._app)

    def tearDown(self):
        self._tmp.cleanup()

    def test_index_returns_html(self):
        r = self._client.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("text/html", r.headers["content-type"])

    def test_api_status_returns_json(self):
        r = self._client.get("/api/status")
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertIn("mode", data)
        self.assertIn("queue_depth", data)

    def test_api_config_returns_safe_keys_only(self):
        r = self._client.get("/api/config")
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertIn("mode", data)
        # Sensitive keys must not be present
        self.assertNotIn("ai", data)
        self.assertNotIn("notifications", data)

    def test_api_config_post_valid_key(self):
        r = self._client.post(
            "/api/config",
            json={"key": "theme", "value": "light"},
        )
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()["ok"])
        cfg = config_mod.load(self._root)
        self.assertEqual(cfg["theme"], "light")

    def test_api_config_post_invalid_key_rejected(self):
        r = self._client.post(
            "/api/config",
            json={"key": "ai", "value": {"keys": ["stolen"]}},
        )
        self.assertEqual(r.status_code, 400)

    def test_api_queue_returns_items(self):
        r = self._client.get("/api/queue")
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertIn("items", data)
        self.assertIn("paused", data)

    def test_api_brain_nodes_empty_before_scan(self):
        r = self._client.get("/api/brain/nodes")
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertIn("nodes", data)

    def test_api_ants_empty_initially(self):
        r = self._client.get("/api/ants")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["ants"], [])

    def test_ws_connects_and_receives_status(self):
        with self._client.websocket_connect("/ws") as ws:
            msg = ws.receive_json()
            self.assertEqual(msg["event"], "status.update")
            self.assertIn("mode", msg["data"])


if __name__ == "__main__":
    unittest.main()
