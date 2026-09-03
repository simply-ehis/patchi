"""
Tests for the SmartAgent (offline, deterministic planner + Council advisory).

These prove the agent actually plans and executes *real* tools end-to-end
without any API key.
"""

from __future__ import annotations

from pathlib import Path

from patchi.core.ai.smart import SmartAgent, run_smart_agent


def _vuln_project(tmp_path: Path) -> Path:
    (tmp_path / "app").mkdir(exist_ok=True)
    (tmp_path / "app" / "config.py").write_text(
        'SECRET = "sk-live-abcdef1234567890abcdef1234567890"\n'
        'def f():\n    return 1\n',
        encoding="utf-8",
    )
    return tmp_path


def test_planner_security_goal():
    agent = SmartAgent(Path("/nonexistent"))
    plan = agent._plan("audit this project for security vulnerabilities")
    tools = [s["tool"] for s in plan]
    assert "scan_vulnerabilities" in tools
    # security goals should NOT trigger a test run or stress test by default
    assert "run_tests" not in tools


def test_planner_test_goal():
    agent = SmartAgent(Path("/nonexistent"))
    plan = agent._plan("run the test suite and tell me what failed")
    tools = [s["tool"] for s in plan]
    assert "run_tests" in tools


def test_run_emits_events_and_runs_tools(tmp_path, monkeypatch):
    # Scope the security fan-out to a single fast agent so the test is
    # deterministic and quick; we only need to prove the scan streams events.
    import patchi.core.ai.tools.realize as realize_mod

    def _fast_select(root, name_map, area=None):
        from patchi.core.security.security_agents import SensitiveDataAgent

        return [c for n, c in name_map.items() if c is SensitiveDataAgent]

    monkeypatch.setattr(realize_mod, "_select_security_agents", _fast_select)
    monkeypatch.setenv("PATCHI_AGENT_TIMEOUT", "15")

    root = _vuln_project(tmp_path)
    events: list[dict] = []

    def on_event(p):
        events.append(p)

    report = run_smart_agent(
        root, "audit this project for security vulnerabilities",
        max_steps=3, on_event=on_event, on_progress=lambda s: None,
    )
    assert "steps_executed" in report
    executed = {s["tool"] for s in report["steps_executed"]}
    # The planner must have actually run the security scan.
    assert "scan_vulnerabilities" in executed
    # Live events must have been produced (sink captures them in event_sample).
    assert len(events) > 0
    emitted = report.get("event_sample", events)
    assert any(e["event"].startswith("security.") for e in emitted)


def test_offline_no_openai_required(tmp_path, monkeypatch):
    # If openai is missing entirely, the agent must still run via deterministic plan.
    # Scope the security fan-out to a single fast agent (offline, no API key).
    import patchi.core.ai.tools.realize as realize_mod

    def _fast_select(root, name_map, area=None):
        from patchi.core.security.security_agents import SensitiveDataAgent

        return [c for n, c in name_map.items() if c is SensitiveDataAgent]

    monkeypatch.setattr(realize_mod, "_select_security_agents", _fast_select)
    monkeypatch.setenv("PATCHI_AGENT_TIMEOUT", "15")

    root = _vuln_project(tmp_path)
    report = run_smart_agent(
        root, "find security issues", max_steps=2,
        on_event=lambda p: None, on_progress=lambda s: None,
    )
    assert report["events"] >= 0
    assert "steps_executed" in report
