"""Tests for patchi.core.security.scheduler."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from patchi.core.security.scheduler import ScanScheduler, _parse_interval


class TestParseInterval:
    def test_seconds(self):
        assert _parse_interval("30s") == 30

    def test_minutes(self):
        assert _parse_interval("5m") == 300

    def test_hours(self):
        assert _parse_interval("2h") == 7200

    def test_days(self):
        assert _parse_interval("1d") == 86400

    def test_with_spaces(self):
        assert _parse_interval("  10m  ") == 600

    def test_uppercase(self):
        assert _parse_interval("1H") == 3600

    def test_invalid_defaults_to_one_hour(self):
        assert _parse_interval("forever") == 3600

    def test_empty_string_defaults_to_one_hour(self):
        assert _parse_interval("") == 3600


class TestScanScheduler:
    @patch("patchi.core.security.scheduler.list_agents")
    def test_init_defaults_disabled(self, mock_list):
        mock_list.return_value = []
        s = ScanScheduler(Path("/fake"))
        assert s.enabled is False
        assert s._agents == []
        assert s._thread is None

    @patch("patchi.core.security.scheduler.list_agents")
    @patch("patchi.core.security.scheduler.cfg")
    def test_init_with_config(self, mock_cfg, mock_list):
        mock_cfg.load.return_value = {
            "pipeline": {
                "scheduler": {
                    "enabled": True,
                    "intervals": {"default": "30m", "overrides": {}},
                }
            }
        }
        mock_list.return_value = []
        s = ScanScheduler(Path("/fake"))
        assert s.enabled is True
        assert len(s._agents) == 0

    def test_start_does_nothing_when_disabled(self):
        s = ScanScheduler(Path("/fake"))
        s.start()
        assert s._thread is None

    @patch("patchi.core.security.scheduler.list_agents")
    @patch("patchi.core.security.scheduler.cfg")
    def test_start_creates_thread_when_enabled(self, mock_cfg, mock_list):
        mock_cfg.load.return_value = {
            "pipeline": {
                "scheduler": {
                    "enabled": True,
                    "intervals": {"default": "1h", "overrides": {}},
                }
            }
        }
        mock_list.return_value = []
        s = ScanScheduler(Path("/fake"))
        s.start()
        assert s._thread is not None
        s.stop()

    @patch("patchi.core.security.scheduler.list_agents")
    @patch("patchi.core.security.scheduler.cfg")
    def test_status(self, mock_cfg, mock_list):
        mock_cfg.load.return_value = {
            "pipeline": {"scheduler": {"enabled": False, "intervals": {}}}
        }
        mock_list.return_value = []
        s = ScanScheduler(Path("/fake"))
        st = s.status()
        assert st["enabled"] is False
        assert st["agent_count"] == 0
