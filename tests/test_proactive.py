"""Tests for the Proactive Agent (Phase 4)."""

from pathlib import Path

from patchi.core.brain.charter import parse_charter
from patchi.core.brain.import_graph import build_import_graph
from patchi.core.brain.proactive import (
    ProactiveAgent,
    ProposedFix,
    build_fix_list,
    rank_fixes,
)
from patchi.core.brain.scanner import FileScanner


def _scan(root: Path):
    fis = FileScanner(root).scan()
    return fis, build_import_graph(root)


def _write(root: Path, rel: str, text: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def test_missing_import_proposed_and_applied(tmp_path):
    _write(tmp_path, "pkg/utils.py", "def helper():\n    return 1\n")
    _write(tmp_path, "pkg/main.py", "def run():\n    return helper()\n")
    fis, graph = _scan(tmp_path)
    agent = ProactiveAgent(tmp_path)
    fixes = agent.analyze_change(["pkg/main.py"], fis, graph, include_format=False)
    mi = [f for f in fixes if f.fix_type == "missing_import"]
    assert mi, "expected a missing-import fix"
    assert mi[0].name == "helper"
    assert mi[0].suggested == "from pkg.utils import helper"
    assert ProactiveAgent.apply(mi[0], tmp_path, apply_unsafe=True)
    assert "from pkg.utils import helper" in (tmp_path / "pkg/main.py").read_text()


def test_unused_import_proposed_and_applied(tmp_path):
    _write(tmp_path, "pkg/main.py", "import os\n\ndef run():\n    return 1\n")
    fis, graph = _scan(tmp_path)
    agent = ProactiveAgent(tmp_path)
    fixes = agent.analyze_change(["pkg/main.py"], fis, graph, include_format=False)
    ui = [f for f in fixes if f.fix_type == "unused_import"]
    assert ui, "expected an unused-import fix"
    assert ui[0].name == "os"
    assert ProactiveAgent.apply(ui[0], tmp_path, apply_unsafe=True)
    assert "import os" not in (tmp_path / "pkg/main.py").read_text()


def test_dead_code_proposed_and_removed(tmp_path):
    _write(tmp_path, "pkg/main.py",
           "def used():\n    return 1\n\ndef unused_thing(): pass\n\nx = used()\n")
    fis, graph = _scan(tmp_path)
    agent = ProactiveAgent(tmp_path)
    fixes = agent.analyze_change(["pkg/main.py"], fis, graph, include_format=False)
    dc = [f for f in fixes if f.fix_type == "dead_code"]
    assert dc, "expected a dead-code fix"
    assert dc[0].name == "unused_thing"
    assert ProactiveAgent.apply(dc[0], tmp_path, apply_unsafe=True)
    assert "unused_thing" not in (tmp_path / "pkg/main.py").read_text()
    # used() must survive
    assert "def used" in (tmp_path / "pkg/main.py").read_text()


def test_signature_callers_detected(tmp_path):
    _write(tmp_path, "pkg/main.py", "def foo(a):\n    return a\n")
    _write(tmp_path, "pkg/caller.py",
           "from pkg.main import foo\n\ndef go():\n    return foo(1)\n")
    fis, graph = _scan(tmp_path)
    agent = ProactiveAgent(tmp_path)
    # First run stores the baseline (no fixes yet).
    agent.analyze_change(["pkg/main.py"], fis, graph, include_format=False)
    # Change the signature.
    _write(tmp_path, "pkg/main.py", "def foo(a, b):\n    return a + b\n")
    fis2, graph2 = _scan(tmp_path)
    fixes = agent.analyze_change(["pkg/main.py"], fis2, graph2, include_format=False)
    sc = [f for f in fixes if f.fix_type == "signature_callers"]
    assert sc, "expected a signature-change caller fix"
    assert "pkg/caller.py" in sc[0].callers


def test_charter_violation_on_forbidden_import(tmp_path):
    _write(tmp_path, "data/store.py", "def db():\n    return 1\n")
    _write(tmp_path, "ui/app.py",
           "from data.store import db\n\ndef render():\n    return db()\n")
    fis, graph = _scan(tmp_path)
    charter = parse_charter("ui must not import data")
    agent = ProactiveAgent(tmp_path)
    fixes = agent.analyze_change(["ui/app.py"], fis, graph, charter, include_format=False)
    cv = [f for f in fixes if f.fix_type == "charter_violation"]
    assert cv, "expected a charter-violation fix"
    assert cv[0].name == "ui→data"


def test_no_fixes_for_clean_file(tmp_path):
    _write(tmp_path, "pkg/main.py", "def run():\n    return 1\n\nx = run()\n")
    fis, graph = _scan(tmp_path)
    agent = ProactiveAgent(tmp_path)
    fixes = agent.analyze_change(["pkg/main.py"], fis, graph, include_format=False)
    assert fixes == []


def test_format_not_proposed_when_disabled(tmp_path):
    _write(tmp_path, "pkg/main.py", "def run():\n    return 1\n")
    fis, graph = _scan(tmp_path)
    agent = ProactiveAgent(tmp_path)
    fixes = agent.analyze_change(["pkg/main.py"], fis, graph, include_format=False)
    assert not any(f.fix_type == "format" for f in fixes)


def test_dead_code_never_wipes_only_definition(tmp_path):
    """Regression: safe --apply must never empty a file by deleting its only def."""
    _write(tmp_path, "pkg/main.py", "def only_fn():\n    return 1\n")
    fis, graph = _scan(tmp_path)
    agent = ProactiveAgent(tmp_path)
    fixes = agent.analyze_change(["pkg/main.py"], fis, graph, include_format=False)
    dc = [f for f in fixes if f.fix_type == "dead_code"]
    if dc:
        # Proposed, but safe-apply must refuse (would wipe the file).
        assert ProactiveAgent.apply(dc[0], tmp_path, apply_unsafe=False) is False
    # File content must be preserved regardless.
    assert (tmp_path / "pkg/main.py").read_text().strip() == "def only_fn():\n    return 1"


def test_rank_fixes_orders_by_priority():
    fixes = [
        ProposedFix("format", "f.py", "fmt", safe=True),
        ProposedFix("charter_violation", "f.py", "cv", safe=False),
        ProposedFix("dead_code", "f.py", "dc", safe=True),
    ]
    ordered = [f.fix_type for f in rank_fixes(fixes)]
    assert ordered == ["charter_violation", "dead_code", "format"]


def test_build_fix_list_excludes_missing_import_by_default(tmp_path):
    _write(tmp_path, "pkg/utils.py", "def helper():\n    return 1\n")
    _write(tmp_path, "pkg/main.py", "def run():\n    return helper()\n")

    fl = build_fix_list(tmp_path, include_format=False)
    assert not any(f.fix_type == "missing_import" for f in fl)

    # With the opt-in flag, cross-module missing-imports appear.
    fl2 = build_fix_list(tmp_path, include_format=False, include_missing_import=True)
    assert any(f.fix_type == "missing_import" for f in fl2)

