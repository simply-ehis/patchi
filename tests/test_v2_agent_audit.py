"""
Agent audit — verifies the full agent registry is healthy.

Checks:
1. Every registered agent can be instantiated
2. Security agents module reports no import failures
3. New v2 agents (RedTeamEngineAgent, LiveTestRunnerV2Agent) register
4. Agent names are unique in the registry
5. Every agent declares name/group/timeout

Run: python -m pytest tests/test_v2_agent_audit.py -v -m "not slow"
"""

from __future__ import annotations

# Trigger eager registration exactly like patchi.core.agents.governor does:
# importing the aggregation modules runs every @register decorator.
import patchi.core.agents.scanners  # noqa: F401
import patchi.core.fix.fix_agents  # noqa: F401
import patchi.core.security.security_agents  # noqa: F401
import patchi.core.testing.test_agents  # noqa: F401


def test_registry_loads():
    from patchi.core.agents.base import list_agents

    agents = list_agents()
    assert len(agents) >= 50, f"Expected 50+ registered agents, got {len(agents)}"


def test_agent_names_unique():
    from patchi.core.agents.base import list_agents

    lowered = [cls.name.lower() for cls in list_agents()]
    assert len(lowered) == len(set(lowered)), f"Duplicate agent names: {sorted(lowered)}"


def test_every_agent_instantiable():
    """Each registered agent class instantiates with zero args."""
    from patchi.core.agents.base import list_agents

    broken = []
    for cls in sorted(list_agents(), key=lambda c: c.name):
        try:
            instance = cls()
            assert hasattr(instance, "run"), f"{cls.name} missing run()"
        except Exception as e:
            broken.append((cls.name, str(e)))
    assert not broken, f"Agents failing to instantiate: {broken}"


def test_agents_have_metadata():
    from patchi.core.agents.base import list_agents

    issues = []
    for cls in sorted(list_agents(), key=lambda c: c.name):
        if not getattr(cls, "name", None):
            issues.append(f"{cls.__qualname__}: missing .name")
        if not getattr(cls, "group", None):
            issues.append(f"{cls.name}: missing .group")
        if not getattr(cls, "timeout", None):
            issues.append(f"{cls.name}: missing .timeout")
    assert not issues, f"Metadata gaps: {issues}"


def test_security_agents_no_import_failures(caplog):
    """The eager registration pass should report zero failures."""
    import logging

    with caplog.at_level(logging.WARNING, logger="patchi.security.agents"):
        import importlib

        import patchi.core.security.security_agents as sa

        importlib.reload(sa)

    failure_msgs = [r.message for r in caplog.records if "registered" in r.getMessage() and "failed" in r.getMessage()]
    for msg in failure_msgs:
        # e.g. "security_agents: registered 54/54 agents (0 failed)"
        parts = msg.split()
        failed = int(parts[-2]) if len(parts) >= 2 else -1
        assert failed == 0, f"Security agents with import failures: {msg}"


def test_red_team_engine_agent_registered():
    from patchi.core.agents.base import get_agent

    assert get_agent("RedTeamEngineAgent") is not None, "RedTeamEngineAgent not registered"
    assert get_agent("RedTeamAgent") is not None, "Legacy RedTeamAgent lost"


def test_live_runner_v2_agent_registered():
    from patchi.core.agents.base import get_agent

    assert get_agent("LiveTestRunnerV2Agent") is not None, "LiveTestRunnerV2Agent not registered"


def test_tool_realize_wired():
    """The realize layer provides real implementations for tool handlers."""
    from patchi.core.ai.tools.realize import (
        attack_simulate,
        red_team,
        run_tests,
        scan_vulnerabilities,
    )

    assert callable(scan_vulnerabilities)
    assert callable(attack_simulate)
    assert callable(red_team)
    assert callable(run_tests)


def test_hosted_webhooks_roundtrip(tmp_path):
    from patchi.core.hosted.webhooks import add_webhook, list_webhooks, remove_webhook

    rec = add_webhook(tmp_path, url="https://example.com/hook", events=["finding"], name="test")
    assert rec["id"]
    hooks = list_webhooks(tmp_path)
    assert len(hooks) == 1
    assert "secret" not in hooks[0]  # redacted
    assert hooks[0]["has_secret"] is False
    assert remove_webhook(tmp_path, rec["id"]) is True
    assert list_webhooks(tmp_path) == []


def test_compliance_report_structure(tmp_path):
    from patchi.core.hosted.compliance_report import generate_report

    report = generate_report(tmp_path, standard="pci-dss")
    assert report["standard"] == "pci-dss"
    assert "sections" in report
    assert "summary" in report
    # Missing scans → pending controls, never crash
    assert report["summary"]["controls_total"] > 0

    err = generate_report(tmp_path, standard="bogus")
    assert "error" in err
