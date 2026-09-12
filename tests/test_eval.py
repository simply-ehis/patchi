"""Tests for the standing eval set (spec §5) — including proof the set bites."""

from pathlib import Path

from patchi.core.evals.runner import eval_all, eval_gate, eval_generation, eval_noise

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_gate_suite_passes_with_defaults():
    r = eval_gate(REPO_ROOT)
    assert r["cases"] == 16, r
    assert r["ok"] is True, r["failures"]
    assert r["vuln_recall"] == 1.0
    assert r["clean_defend_escapes"] == 0


def test_noise_suite_passes_with_defaults():
    r = eval_noise(REPO_ROOT)
    assert r["cases"] == 10, r
    assert r["ok"] is True, r["failures"]


def test_eval_all_reports_generation_skipped_not_passing():
    r = eval_all(REPO_ROOT)
    assert r["ok"] is True
    gen = r["suites"]["generation"]
    assert gen["skipped"] is True
    assert gen["ok"] is None  # never a passing number without a model


def test_sabotaged_thresholds_fail():
    """Negative control: a mis-tuned gate MUST fail the eval set."""
    r = eval_gate(REPO_ROOT, {"confidence_gate": {"min_agents_to_keep": 5}})
    assert r["ok"] is False
    assert r["passed"] < r["cases"]
    assert any(f["id"] == "g01" for f in r["failures"])


def test_generation_without_model_skips_never_passes(monkeypatch):
    """No model → SKIPPED with reason. A skip must never read as a pass."""
    import patchi.core.evals.runner as runner

    monkeypatch.setattr(runner, "_model_available", lambda _c: (False, "no model here"))
    r = eval_generation(REPO_ROOT, {})
    assert r["skipped"] is True
    assert r["ok"] is None
    assert "reason" in r


def test_generation_harness_scores_grounding(monkeypatch):
    """A stubbed model that ignores the target counts as hallucinated."""
    import patchi.core.evals.runner as runner

    monkeypatch.setattr(runner, "_model_available", lambda _c: (True, "stub"))
    monkeypatch.setattr(runner, "_model_id", lambda _c: "stub/1")
    monkeypatch.setattr(
        "patchi.core.ai.client.call_ai",
        lambda *a, **k: "def test_x():\n    assert True\n",
    )
    r = eval_generation(REPO_ROOT, {})
    assert r.get("skipped") is not True
    assert r["cases"] == 3
    assert r["grounded"] == 0
    assert r["hallucination_rate"] == 1.0
    assert r["ok"] is False


def test_case_ids_unique_and_labeled():
    import json

    for name in ("gate_cases.json", "noise_cases.json"):
        data = json.loads((REPO_ROOT / "evals" / "cases" / name).read_text(encoding="utf-8"))
        ids = [c["id"] for c in data]
        assert len(ids) == len(set(ids)), f"duplicate ids in {name}"
    gate = json.loads((REPO_ROOT / "evals" / "cases" / "gate_cases.json").read_text(encoding="utf-8"))
    assert all(c["kind"] in ("vuln", "clean", "config") for c in gate)
    assert all(c["expect_routing"] in ("defend", "ai_analyze", "human_review", "discard") for c in gate)
    config_cases = [c for c in gate if c["kind"] == "config"]
    assert config_cases, "expected knob-pinning config cases"
