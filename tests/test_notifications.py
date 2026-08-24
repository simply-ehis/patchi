"""
Tests for patchi.core.notifications — Phase 7.

All external calls (Apprise.notify, threading) are mocked.
Tests cover: channel parsing, quiet hours, digest, escalation, notifier routing.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

from patchi.core.notifications.channels import (
    ChannelType,
    channel_to_dict,
    from_config,
    load_channels,
)
from patchi.core.notifications.digest import DigestQueue
from patchi.core.notifications.escalation import EscalationTracker
from patchi.core.notifications.notifier import Notifier
from patchi.core.notifications.quiet_hours import is_quiet_now, should_suppress

# ── Channel config parsing ─────────────────────────────────────────────────────


class TestChannelParsing(unittest.TestCase):
    def test_parse_slack_webhook(self):
        raw = {
            "name": "my-slack",
            "type": "slack",
            "min_severity": "high",
            "webhook_url": "https://hooks.slack.com/services/T123/B456/token789",
        }
        ch = from_config(raw)
        self.assertEqual(ch.channel_type, ChannelType.SLACK)
        self.assertEqual(ch.min_severity, "high")
        self.assertIn("slack://", ch.apprise_url)

    def test_parse_discord_webhook(self):
        raw = {
            "name": "my-discord",
            "type": "discord",
            "webhook_url": "https://discord.com/api/webhooks/111/secrettoken",
        }
        ch = from_config(raw)
        self.assertEqual(ch.channel_type, ChannelType.DISCORD)
        self.assertIn("discord://", ch.apprise_url)

    def test_parse_custom_webhook(self):
        raw = {"name": "hook", "type": "webhook", "url": "https://example.com/hook"}
        ch = from_config(raw)
        self.assertIn("json://", ch.apprise_url)

    def test_parse_email(self):
        raw = {
            "name": "email",
            "type": "email",
            "user": "me@example.com",
            "password": "secret",
            "host": "smtp.example.com",
        }
        ch = from_config(raw)
        self.assertIn("mailtos://", ch.apprise_url)

    def test_invalid_type_raises(self):
        with self.assertRaises(ValueError):
            from_config({"name": "x", "type": "fax"})

    def test_missing_name_raises(self):
        with self.assertRaises(ValueError):
            from_config({"type": "webhook", "url": "https://x.com"})

    def test_accepts_severity_filtering(self):
        raw = {
            "name": "high-only",
            "type": "webhook",
            "url": "https://x.com/hook",
            "min_severity": "high",
        }
        ch = from_config(raw)
        self.assertTrue(ch.accepts_severity("critical"))
        self.assertTrue(ch.accepts_severity("high"))
        self.assertFalse(ch.accepts_severity("medium"))
        self.assertFalse(ch.accepts_severity("low"))

    def test_load_channels_skips_invalid(self):
        cfg = {
            "notifications": [
                {"name": "good", "type": "webhook", "url": "https://x.com/hook"},
                {"name": "bad", "type": "fax"},  # invalid — should be skipped
            ]
        }
        channels = load_channels(cfg)
        self.assertEqual(len(channels), 1)
        self.assertEqual(channels[0].name, "good")

    def test_channel_to_dict_hides_url(self):
        raw = {"name": "wh", "type": "webhook", "url": "https://secret.example.com/hook"}
        ch = from_config(raw)
        d = channel_to_dict(ch)
        self.assertNotIn("apprise_url", d)
        self.assertEqual(d["name"], "wh")


# ── Quiet hours ────────────────────────────────────────────────────────────────


class TestQuietHours(unittest.TestCase):
    def _cfg(self, start: str, end: str) -> dict:
        return {"enabled": True, "start": start, "end": end, "timezone": "UTC"}

    def test_disabled_always_false(self):
        self.assertFalse(is_quiet_now({"enabled": False, "start": "22:00", "end": "08:00"}))

    def test_same_day_window_inside(self):
        with patch("patchi.core.notifications.quiet_hours.datetime") as mock_dt:
            mock_dt.now.return_value.time.return_value = __import__("datetime").time(14, 0)
            self.assertTrue(is_quiet_now(self._cfg("09:00", "17:00")))

    def test_same_day_window_outside(self):
        with patch("patchi.core.notifications.quiet_hours.datetime") as mock_dt:
            mock_dt.now.return_value.time.return_value = __import__("datetime").time(20, 0)
            self.assertFalse(is_quiet_now(self._cfg("09:00", "17:00")))

    def test_overnight_window(self):
        with patch("patchi.core.notifications.quiet_hours.datetime") as mock_dt:
            mock_dt.now.return_value.time.return_value = __import__("datetime").time(23, 30)
            self.assertTrue(is_quiet_now(self._cfg("22:00", "08:00")))

    def test_critical_bypasses_quiet_hours(self):
        cfg = self._cfg("00:00", "23:59")  # always quiet
        self.assertFalse(should_suppress("critical", cfg))
        self.assertFalse(should_suppress("high", cfg))

    def test_medium_suppressed_in_quiet_hours(self):
        cfg = {"enabled": True, "start": "00:00", "end": "23:59"}
        with patch("patchi.core.notifications.quiet_hours.datetime") as mock_dt:
            mock_dt.now.return_value.time.return_value = __import__("datetime").time(12, 0)
            self.assertTrue(should_suppress("medium", cfg))


# ── Digest queue ───────────────────────────────────────────────────────────────


class TestDigestQueue(unittest.TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory()
        self._root = Path(self._tmp.name)
        (self._root / ".patchi").mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def test_enqueue_and_peek(self):
        dq = DigestQueue(self._root)
        dq.enqueue("medium", "T", "B")
        items = dq.peek()
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["title"], "T")

    def test_flush_drains_queue(self):
        dq = DigestQueue(self._root)
        dq.enqueue("medium", "T1", "B1")
        dq.enqueue("low", "T2", "B2")
        items = dq.flush()
        self.assertEqual(len(items), 2)
        self.assertEqual(dq.peek(), [])

    def test_flush_empty_returns_empty(self):
        dq = DigestQueue(self._root)
        self.assertEqual(dq.flush(), [])

    def test_should_flush_after_interval(self):
        dq = DigestQueue(self._root)
        dq.enqueue("low", "T", "B")
        # Force last_flushed to be very old
        path = self._root / ".patchi/digest.json"
        data = json.loads(path.read_text())
        data["last_flushed"] = 0.0
        path.write_text(json.dumps(data))
        self.assertTrue(dq.should_flush("hourly"))

    def test_clear_removes_items(self):
        dq = DigestQueue(self._root)
        dq.enqueue("low", "T", "B")
        count = dq.clear()
        self.assertEqual(count, 1)
        self.assertEqual(dq.peek(), [])

    def test_build_digest_body(self):
        items = [
            {"severity": "medium", "title": "A", "body": "issue a"},
            {"severity": "low", "title": "B", "body": "issue b"},
        ]
        body = DigestQueue.build_digest_body(items)
        self.assertIn("2 alert", body)
        self.assertIn("A", body)


# ── Escalation tracker ─────────────────────────────────────────────────────────


class TestEscalationTracker(unittest.TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory()
        self._root = Path(self._tmp.name)
        (self._root / ".patchi").mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def test_register_and_acknowledge(self):
        et = EscalationTracker(self._root, escalation_fn=lambda *a: None)
        et.register("abc123", "critical", "Danger", "sql injection")
        self.assertEqual(len(et.pending()), 1)
        self.assertTrue(et.acknowledge("abc123"))
        self.assertEqual(et.pending(), [])

    def test_acknowledge_unknown_id_returns_false(self):
        et = EscalationTracker(self._root, escalation_fn=lambda *a: None)
        self.assertFalse(et.acknowledge("nope"))

    def test_low_severity_not_registered(self):
        et = EscalationTracker(self._root, escalation_fn=lambda *a: None)
        et.register("x1", "low", "T", "B")
        self.assertEqual(et.pending(), [])

    def test_escalation_fired_when_overdue(self):
        fired = []
        et = EscalationTracker(
            self._root,
            escalation_fn=lambda aid, alert: fired.append(aid),
            escalation_minutes=0,  # escalate immediately
        )
        et.register("z9", "critical", "T", "B")
        et._check_overdue()
        self.assertIn("z9", fired)


# ── Notifier dispatch ──────────────────────────────────────────────────────────


class TestNotifier(unittest.TestCase):
    def _make_notifier(self, tmp_root: Path) -> tuple[Notifier, MagicMock]:
        cfg = {
            "notifications": [
                {"name": "wh", "type": "webhook", "url": "https://example.com/hook"},
            ],
            "quiet_hours": {"enabled": False},
            "digest_frequency": "daily",
            "escalation_minutes": 30,
        }
        (tmp_root / ".patchi").mkdir(exist_ok=True)
        with patch(
            "patchi.core.notifications.notifier._apprise_send", return_value=True
        ) as mock_send:
            notifier = Notifier(tmp_root, cfg)
            return notifier, mock_send

    def test_critical_fires_immediately(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".patchi").mkdir()
            cfg = {
                "notifications": [
                    {"name": "wh", "type": "webhook", "url": "https://x.com/h"},
                ],
                "quiet_hours": {"enabled": False},
                "digest_frequency": "daily",
                "escalation_minutes": 30,
            }
            with patch(
                "patchi.core.notifications.notifier._apprise_send", return_value=True
            ) as mock_fire:
                notifier = Notifier(root, cfg)
                sent = notifier.send("critical", "SQLi", "routes.py:44")
                self.assertEqual(sent, 1)
                mock_fire.assert_called_once()

    def test_medium_goes_to_digest(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".patchi").mkdir()
            cfg = {
                "notifications": [
                    {"name": "wh", "type": "webhook", "url": "https://x.com/h"},
                ],
                "quiet_hours": {"enabled": False},
                "digest_frequency": "daily",
                "escalation_minutes": 30,
            }
            with patch(
                "patchi.core.notifications.notifier._apprise_send", return_value=True
            ) as mock_fire:
                notifier = Notifier(root, cfg)
                sent = notifier.send("medium", "Lint", "too complex")
                self.assertEqual(sent, 0)
                mock_fire.assert_not_called()
                self.assertEqual(len(notifier._digest.peek()), 1)

    def test_no_channels_returns_zero(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".patchi").mkdir()
            cfg = {
                "notifications": [],
                "quiet_hours": {"enabled": False},
                "digest_frequency": "daily",
                "escalation_minutes": 30,
            }
            notifier = Notifier(root, cfg)
            self.assertEqual(notifier.send("critical", "T", "B"), 0)


if __name__ == "__main__":
    unittest.main()
