"""Tests for Phase 4b (watch-mode wiring) and Phase 5 (Learning Brain)."""

from pathlib import Path

from patchi.core import memory as mem
from patchi.core.brain import learning
from patchi.core.brain.charter import parse_charter, save_charter
from patchi.core.brain.proactive import escalate_to_governor, run_proactive


def _write(root: Path, rel: str, text: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def _proj(tmp_path: Path) -> Path:
    (tmp_path / ".patchi").mkdir()
    return tmp_path


def test_run_proactive_proposes_and_reports(tmp_path):
    r = _proj(tmp_path)
    _write(r, "pkg/utils.py", "def helper():\n    return 1\n")
    _write(r, "pkg/main.py", "def run():\n    return helper()\n")
    result = run_proactive(r, ["pkg/main.py"])
    types = {f.fix_type for f in result["fixes"]}
    assert "missing_import" in types
    assert result["applied"] == []
    assert result["skipped"]  # safe fix reported but not applied


def test_run_proactive_applies_safe_fixes(tmp_path):
    r = _proj(tmp_path)
    _write(r, "pkg/utils.py", "def helper():\n    return 1\n")
    _write(r, "pkg/main.py", "def run():\n    return helper()\n")
    result = run_proactive(r, ["pkg/main.py"], apply=True)
    applied_types = {f.fix_type for f in result["applied"]}
    assert "missing_import" in applied_types
    assert "from pkg.utils import helper" in (r / "pkg/main.py").read_text()


def test_learning_suppresses_rejected_fix_type(tmp_path):
    r = _proj(tmp_path)
    _write(r, "pkg/main.py", "def used():\n    return 1\n\nx = used()\n\ndef junk():\n    pass\n")
    for _ in range(3):
        learning.record_rejection("dead_code", "ProactiveAgent", r)
    assert not learning.should_suggest("dead_code", r)
    result = run_proactive(r, ["pkg/main.py"])
    active_types = {f.fix_type for f in result["fixes"]}
    suppressed_types = {f.fix_type for f in result["suppressed"]}
    assert "dead_code" not in active_types
    assert "dead_code" in suppressed_types


def test_escalate_charter_violation_to_governor(tmp_path):
    r = _proj(tmp_path)
    _write(r, "data/store.py", "def db():\n    return 1\n")
    _write(r, "ui/app.py", "from data.store import db\n\ndef render():\n    return db()\n")
    save_charter(parse_charter("ui must not import data"), r)

    result = run_proactive(r, ["ui/app.py"])
    escalated_types = {f.fix_type for f in result["escalated"]}
    assert "charter_violation" in escalated_types

    for fix in result["escalated"]:
        escalate_to_governor(r, fix)
    issues = mem.list_issues(r)
    assert any(i.get("fix_type") == "charter_violation" for i in issues)


def test_learn_reset_clears_learning(tmp_path):
    r = _proj(tmp_path)
    learning.record_rejection("dead_code", "ProactiveAgent", r)
    assert learning.get_summary(r)["rejections"].get("dead_code") == 1
    # Simulate `p learn --reset` by deleting learning.json.
    (r / ".patchi" / "learning.json").unlink()
    assert learning.get_summary(r)["rejections"] == {}
