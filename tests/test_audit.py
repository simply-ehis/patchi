"""Tests for the Drift Detector / Plan-vs-Built Report Card (p audit)."""

import json
from pathlib import Path

from patchi.core.brain.audit import (
    _diff_scope,
    _snapshot_scope,
    compute_drift,
    load_plan,
    report_card,
    save_plan,
)

_PLAN = Path(".patchi/plan.json")


def _write_plan(root: Path, total: int, charter_v: int, layers: dict | None = None):
    plan = {
        "saved_at": "2026-01-01T00:00:00+00:00",
        "intent": "build the foo",
        "layers": layers or {},
        "charter": {},
        "scan_summary": {"MyScanner": {"finding_count": total, "timestamp": None}},
        "charter_violations": charter_v,
        "total_findings": total,
    }
    p = root / _PLAN
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(plan), encoding="utf-8")
    return plan


def _scans(total: int, charter_v: int) -> dict:
    scans = {
        "MyScanner": {"findings": [{"x": i} for i in range(total)]},
        "CharterGuard": {"findings": [{"v": i} for i in range(charter_v)]},
    }
    return scans


def test_save_and_load_plan(tmp_path):
    # save_plan reads live memory; just exercise load on a hand-written plan.
    _write_plan(tmp_path, total=2, charter_v=0)
    loaded = load_plan(tmp_path)
    assert loaded["total_findings"] == 2
    assert loaded["intent"] == "build the foo"


def test_save_plan_writes_state(tmp_path):
    plan = save_plan(tmp_path, intent="snapshot intent")
    assert plan["intent"] == "snapshot intent"
    assert load_plan(tmp_path) is not None


def test_compute_drift_clean(tmp_path):
    _write_plan(tmp_path, total=2, charter_v=0, layers={})
    drift = compute_drift(tmp_path, scans=_scans(2, 0))
    assert drift["has_plan"] is True
    assert drift["clean"] is True
    assert drift["new_findings"] == 0
    assert drift["new_charter_violations"] == 0


def test_compute_drift_detected(tmp_path):
    _write_plan(tmp_path, total=1, charter_v=0, layers={})
    drift = compute_drift(tmp_path, scans=_scans(3, 1))
    assert drift["clean"] is False
    assert drift["new_findings"] == 3
    assert drift["new_charter_violations"] == 1
    # per-scanner row reflects the +2 delta
    row = next(r for r in drift["per_scanner"] if r["scanner"] == "MyScanner")
    assert row["delta"] == 2


def test_compute_drift_no_plan(tmp_path):
    drift = compute_drift(tmp_path, scans=_scans(1, 0))
    assert drift["has_plan"] is False


def test_report_card_no_plan(tmp_path):
    card = report_card(tmp_path, run_scan=False)
    assert card["has_plan"] is False


def test_report_card_with_plan(tmp_path):
    _write_plan(tmp_path, total=1, charter_v=0, layers={})
    card = report_card(tmp_path, run_scan=False)  # uses stored scans (empty) -> drift vs plan
    assert card["has_plan"] is True
    assert "Plan-vs-Built" in card["summary"]


def test_snapshot_scope_captures_symbols_and_hash(tmp_path):
    (tmp_path / "mod.py").write_text("def alpha():\n    pass\n\nclass Beta:\n    pass\n")
    scope = _snapshot_scope(tmp_path)
    assert "mod.py" in scope
    info = scope["mod.py"]
    assert info["lang"] == "python"
    assert "alpha" in info["symbols"] and "Beta" in info["symbols"]
    assert info["hash"] and len(info["hash"]) == 16  # sha256[:16] content hash


def test_save_plan_stores_scope(tmp_path):
    (tmp_path / "mod.py").write_text("def keep():\n    pass\n")
    plan = save_plan(tmp_path, intent="scope snapshot")
    assert "scope" in plan
    assert "mod.py" in plan["scope"]


def test_diff_scope_detects_added_removed_modified():
    plan_scope = {
        "a.py": {"lang": "python", "symbols": ["foo", "bar"], "hash": "h1"},
        "b.py": {"lang": "python", "symbols": ["baz"], "hash": "h2"},
    }
    cur_scope = {
        "a.py": {"lang": "python", "symbols": ["foo", "bar", "qux"], "hash": "h1b"},
        "c.py": {"lang": "python", "symbols": ["new"], "hash": "h3"},
    }
    sd = _diff_scope(plan_scope, cur_scope)
    assert sd["added_files"] == ["c.py"]
    assert sd["removed_files"] == ["b.py"]
    assert sd["added_count"] == 1 and sd["removed_count"] == 1
    modified = sd["modified_files"]
    assert len(modified) == 1 and modified[0]["file"] == "a.py"
    assert modified[0]["symbols_added"] == ["qux"]
    assert modified[0]["symbols_removed"] == []
    assert modified[0]["symbols_unchanged"] == ["bar", "foo"]


def test_diff_scope_clean_when_identical():
    scope = {"a.py": {"lang": "python", "symbols": ["foo"], "hash": "h"}}
    sd = _diff_scope(scope, dict(scope))
    assert sd["added_count"] == 0
    assert sd["removed_count"] == 0
    assert sd["modified_count"] == 0


def test_compute_drift_includes_scope_diff(tmp_path, monkeypatch):
    plan = _write_plan(tmp_path, total=1, charter_v=0, layers={})
    plan["scope"] = {
        "a.py": {"lang": "python", "symbols": ["foo"], "hash": "h1"},
        "b.py": {"lang": "python", "symbols": ["baz"], "hash": "h2"},
    }
    (tmp_path / _PLAN).write_text(json.dumps(plan), encoding="utf-8")

    # current scope: removed b.py, added c.py, modified a.py
    cur = {
        "a.py": {"lang": "python", "symbols": ["foo", "qux"], "hash": "h1b"},
        "c.py": {"lang": "python", "symbols": ["new"], "hash": "h3"},
    }
    monkeypatch.setattr("patchi.core.brain.audit._snapshot_scope", lambda root: cur)

    drift = compute_drift(tmp_path, scans=_scans(1, 0))
    sd = drift["scope_diff"]
    assert sd["removed_files"] == ["b.py"]
    assert sd["added_files"] == ["c.py"]
    assert sd["modified_files"][0]["file"] == "a.py"
    # scope drift makes the build "not clean" even if finding counts match
    assert drift["clean"] is False

