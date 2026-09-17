"""Tests for the testing-layer upgrades (spec Parts 1–8 execution):

- `p test live` maps to LiveTestRunnerV2Agent (recordings + screenshots
  finally reachable from the CLI, per the CLI ↔ web parity rule).
- Evidence artifacts (screenshots/recordings) surface in test results.
- Harness-backed AI test generation: schema enforcement, anti-placeholder
  semantic gate, honest degradation without AI.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

import pytest
from pydantic import ValidationError

from patchi.core.ai.test_harness_gen import (
    GeneratedCase,
    TestPlan,
    _validate_plan,
    generate_tests_via_harness,
)

# ── `p test live` wiring ───────────────────────────────────────────────────


def test_live_type_maps_to_live_v2_agent():
    m = json.loads(Path("patchi/cli/commands/agent_maps.json").read_text(encoding="utf-8"))
    assert m["test"]["test_types"]["live"] == ["LiveTestRunnerV2Agent"]


def test_live_agent_is_registered():
    from patchi.core.agents.base import AgentGroup, list_agents
    from patchi.core.testing import test_agents  # noqa: F401  (registration side effect)

    names = {a.name for a in list_agents(AgentGroup.TEST)}
    assert "LiveTestRunnerV2Agent" in names


def test_live_agent_carries_record_config():
    """The CLI hands LiveTestRunnerV2Agent its config contract with video on."""

    src = Path("patchi/cli/commands/test_cmd.py").read_text(encoding="utf-8")
    assert '"record_video": True' in src  # config contract includes recording
    assert "live_test_config" in src


def test_live_agent_passthrough_honors_record_video():
    """The agent must forward record_video into LiveTestConfigV2 — dropping
    the flag used to silently disable recordings (a pure honesty bug)."""
    src = Path("patchi/core/testing/live_v2/runner.py").read_text(encoding="utf-8")
    assert 'record_video=bool(config_data.get("record_video", False))' in src


# ── evidence surfacing ────────────────────────────────────────────────────


def test_evidence_sweep_lists_screenshots(tmp_path: Path, capsys):
    """Failure screenshots on disk are named in the results, not buried."""
    from patchi.cli.commands.test_cmd import _show_evidence

    shots = tmp_path / ".patchi" / "artifacts" / "browser"
    shots.mkdir(parents=True)
    (shots / "home-fail-0.png").write_bytes(b"png")

    class _R:  # minimal result stand-in
        agent_name = "BrowserTest"
        data: dict = {}

    _show_evidence([_R()], tmp_path)
    out = capsys.readouterr().out
    assert "Evidence:" in out
    assert "home-fail-0.png" in out


def test_evidence_silent_when_nothing_exists(tmp_path: Path, capsys):
    from patchi.cli.commands.test_cmd import _show_evidence

    _show_evidence([], tmp_path)
    assert "Evidence:" not in capsys.readouterr().out


# ── harness generation: schema + anti-placeholder ─────────────────────────


def _case(name="test_div_by_zero_raises", body=None, symbol="divide"):
    return GeneratedCase(
        name=name,
        target_symbol=symbol,
        rationale="zero divisor must raise ValueError, not return inf",
        test_code=body
        or (
            "def test_div_by_zero_raises():\n"
            "    from calc import divide\n"
            "    with pytest.raises(ValueError):\n"
            "        divide(1, 0)\n"
        ),
    )


def test_case_without_assert_is_rejected():
    with pytest.raises(ValidationError):
        GeneratedCase(
            name="test_nothing",
            target_symbol="divide",
            rationale="none",
            test_code="def test_nothing():\n    pass\n",
        )


def test_pytest_raises_counts_as_assertion():
    """pytest.raises asserts behavior — the gate must accept it."""
    case = GeneratedCase(
        name="test_div_by_zero_raises",
        target_symbol="divide",
        rationale="zero divisor must raise, not return inf",
        test_code=(
            "def test_div_by_zero_raises():\n"
            "    from calc import divide\n"
            "    with pytest.raises(ValueError):\n"
            "        divide(1, 0)\n"
        ),
    )
    assert case.test_code  # validation passed — construction succeeded


def test_case_with_bad_name_is_rejected():
    with pytest.raises(ValidationError):
        GeneratedCase(
            name="check_thing",
            target_symbol="divide",
            rationale="names matter for pytest discovery",
            test_code="def check_thing():\n    assert True\n",
        )


def test_plan_rejects_symbol_not_in_module():
    plan = TestPlan(module="calc", cases=[_case(symbol="nonexistent")])
    ok, reason = _validate_plan(plan, allowed={"divide"}, module="calc")
    assert not ok
    assert "not a top-level symbol" in reason


def test_plan_rejects_test_that_never_imports_module():
    body = "def test_x():\n    assert divide(2, 1) == 2\n"
    plan = TestPlan(module="calc", cases=[_case(body=body)])
    ok, reason = _validate_plan(plan, allowed={"divide"}, module="calc")
    assert not ok
    assert "never imports" in reason


def test_plan_accepts_real_case():
    plan = TestPlan(module="calc", cases=[_case()])
    ok, _ = _validate_plan(plan, allowed={"divide"}, module="calc")
    assert ok


# ── honest degradation ────────────────────────────────────────────────────


def test_no_ai_returns_reason_not_crash(tmp_path: Path):
    """No AI configured → explicit reason; caller falls back to skeletons."""
    with mock.patch("patchi.core.ai.client.call_ai", return_value=None):
        res = generate_tests_via_harness(tmp_path, ["calc.py"], config={})
    assert res["success"] is False
    assert res["reason"] == "no-ai"


def test_schema_failure_escalates_and_writes_nothing(tmp_path: Path):
    """A model that can't satisfy the schema escalates — no placeholder file."""
    (tmp_path / "calc.py").write_text("def divide(a, b):\n    return a / b\n", encoding="utf-8")

    with mock.patch("patchi.core.ai.client.call_ai", return_value="not json at all"):
        res = generate_tests_via_harness(tmp_path, ["calc.py"], config={})


    assert res["success"] is False
    assert res.get("escalated")
    assert not list((tmp_path / ".patchi" / "generated_tests").glob("*.py"))


def test_valid_plan_writes_real_tests(tmp_path: Path):
    (tmp_path / "calc.py").write_text("def divide(a, b):\n    return a / b\n", encoding="utf-8")
    good = TestPlan(
        module="calc",
        cases=[
            GeneratedCase(
                name="test_div_returns_quotient",
                target_symbol="divide",
                rationale="6/3 must be 2.0",
                test_code=(
                    "def test_div_returns_quotient():\n"
                    "    from calc import divide\n"
                    "    assert divide(6, 3) == 2.0\n"
                ),
            )
        ],
    )
    import patchi.core.ai.client as ai_mod
    import patchi.core.ai.test_harness_gen as gen_mod

    with mock.patch.object(ai_mod, "call_ai", return_value="OK"), mock.patch.object(
        gen_mod, "harness_call", return_value=(good, "ok")
    ):
        res = generate_tests_via_harness(tmp_path, ["calc.py"], config={})

    assert res["success"] is True
    written = (tmp_path / ".patchi" / "generated_tests" / "test_calc.py").read_text(encoding="utf-8")
    assert "test_div_returns_quotient" in written
    assert "from calc import" in written
    assert res["created"][0]["evidence"][0]["symbol"] == "divide"
