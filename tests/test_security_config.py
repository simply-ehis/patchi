"""Tests for patchi.core.security.security_config."""
from __future__ import annotations

from pathlib import Path

from patchi.core.security.security_config import ConfigAuditAgent, _run


class TestRun:
    def test_echo_command(self):
        result = _run(["echo", "hello world"], Path("."))
        assert result["returncode"] == 0
        assert "hello world" in result["stdout"]

    def test_sleep_command(self):
        result = _run(["sleep", "10"], Path("."))
        assert result["returncode"] == -1
        assert result["timed_out"] is True

    def test_unknown_command(self):
        result = _run(["nonexistent_cmd_xyz"], Path("."))
        assert result["returncode"] != 0


class TestConfigAuditAgent:
    def test_agent_metadata(self):
        agent = ConfigAuditAgent()
        assert agent.name == "ConfigAuditAgent"
        assert agent.group.value == "security"
