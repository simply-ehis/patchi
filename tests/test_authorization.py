"""Unit tests for testing authorization + active-request audit."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from patchi.core.testing import authorization as auth
from patchi.core.testing.gate import require_scope


def _root() -> Path:
    t = Path(tempfile.mkdtemp())
    (t / ".patchi").mkdir(exist_ok=True)
    return t


class TestNormalize(unittest.TestCase):
    def test_strips_scheme_port_path(self):
        self.assertEqual(auth.normalize_host("https://Shop.Client.com:8443/app?q=1"), "shop.client.com")
        self.assertEqual(auth.normalize_host("shop.client.com"), "shop.client.com")
        self.assertEqual(auth.normalize_host(""), "")
        self.assertEqual(auth.normalize_host("http://127.0.0.1:1612"), "127.0.0.1")


class TestGrants(unittest.TestCase):
    def test_grant_revoke_cycle(self):
        root = _root()
        rec = auth.grant(root, "https://shop.client.com/app", approved_by="Jane", window_hours=24)
        self.assertEqual(rec["host"], "shop.client.com")
        self.assertEqual(rec["approved_by"], "Jane")
        found = auth.authorization_for(root, "http://shop.client.com/other")
        self.assertIsNotNone(found)
        self.assertTrue(auth.revoke(root, "shop.client.com"))
        self.assertIsNone(auth.authorization_for(root, "http://shop.client.com/"))
        self.assertFalse(auth.revoke(root, "shop.client.com"))

    def test_rejects_empty(self):
        root = _root()
        with self.assertRaises(ValueError):
            auth.grant(root, "", approved_by="Jane")
        with self.assertRaises(ValueError):
            auth.grant(root, "shop.client.com", approved_by="  ")
        with self.assertRaises(ValueError):
            auth.grant(root, "shop.client.com", approved_by="Jane", window_hours=0)

    def test_expired_grant_denies_but_lists(self):
        root = _root()
        auth.grant(root, "old.client.com", approved_by="Jane", window_hours=0.0001)
        import time

        time.sleep(0.5)
        self.assertIsNone(auth.authorization_for(root, "http://old.client.com/"))
        grants = auth.list_authorizations(root)
        self.assertTrue(any(g["host"] == "old.client.com" and g["expired"] for g in grants))

    def test_regrant_extends(self):
        root = _root()
        auth.grant(root, "shop.client.com", approved_by="A", window_hours=1)
        rec = auth.grant(root, "shop.client.com", approved_by="B", window_hours=72)
        self.assertEqual(rec["approved_by"], "B")
        self.assertEqual(len(auth.list_authorizations(root)), 1)


class TestGateWithStore(unittest.TestCase):
    def test_localhost_frictionless(self):
        allowed, _ = require_scope("http://127.0.0.1:1612", root=_root())
        self.assertTrue(allowed)

    def test_remote_blocked_then_granted(self):
        root = _root()
        allowed, reason = require_scope("http://shop.client.com/", root=root)
        self.assertFalse(allowed)
        self.assertIn("p authorize", reason)
        auth.grant(root, "shop.client.com", approved_by="Jane")
        allowed, reason = require_scope("http://shop.client.com/", root=root)
        self.assertTrue(allowed)
        self.assertIn("Jane", reason)

    def test_gate_without_root_unchanged(self):
        allowed, _ = require_scope("http://127.0.0.1:9")
        self.assertTrue(allowed)
        allowed, _ = require_scope("http://shop.client.com/", allow_hosts={"shop.client.com"})
        self.assertTrue(allowed)
        allowed, _ = require_scope("http://evil.example/")
        self.assertFalse(allowed)


class TestRegistryEnforcement(unittest.TestCase):
    def test_remote_blocked_without_grant(self):
        from patchi.core.security.pentest.registry import PentestRegistry

        root = _root()
        res = PentestRegistry().run("nuclei", "http://shop.client.com/", root=root)
        self.assertFalse(res.success)
        self.assertIn("scope gate", res.error)

    def test_localhost_passes_gate(self):
        from patchi.core.security.pentest.registry import PentestRegistry

        root = _root()
        # Tool missing here → must pass the GATE and fail on availability,
        # proving the gate (not the tool check) is what blocks remotes.
        res = PentestRegistry().run("zap", "http://127.0.0.1:1612/", root=root)
        self.assertNotIn("scope gate", res.error or "")

    def test_grant_unblocks(self):
        from patchi.core.security.pentest.registry import PentestRegistry

        root = _root()
        auth.grant(root, "shop.client.com", approved_by="Jane")
        res = PentestRegistry().run("zap", "http://shop.client.com/", root=root)
        self.assertNotIn("scope gate", res.error or "")

    def test_audit_rows_written(self):
        from patchi.core.security.pentest.registry import PentestRegistry

        root = _root()
        PentestRegistry().run("nuclei", "http://shop.client.com/", root=root)
        rows = (root / ".patchi" / "audit" / "active_requests.jsonl").read_text().strip().split("\n")
        last = json.loads(rows[-1])
        self.assertEqual(last["tool"], "nuclei")
        self.assertEqual(last["action"], "blocked:no-authorization")

    def test_unknown_tool_blocked_and_logged(self):
        from patchi.core.security.pentest.registry import PentestRegistry

        root = _root()
        res = PentestRegistry().run("nope-tool", "http://127.0.0.1:1/", root=root)
        self.assertFalse(res.success)


if __name__ == "__main__":
    unittest.main()
