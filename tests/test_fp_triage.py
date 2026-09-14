"""FP triage: debt severity caps, fixture skips, IDOR guard-awareness, scope."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from patchi.core.agents.base import AgentInput, Severity, scope_allows
from patchi.core.agents.comment_scanner import CommentScanner
from patchi.core.agents.env_scanner import EnvScanner


def _inp(root: Path, scope: list[str] | None = None) -> AgentInput:
    return AgentInput(root=root, scope=scope or [], brain={}, config={})


def test_debt_markers_capped_at_medium():
    sevs = {name: sev for _, name, sev in CommentScanner.TECH_DEBT_PATTERNS}
    assert sevs["BUG"] == Severity.MEDIUM
    assert sevs["XXX"] == Severity.MEDIUM
    assert all(s != Severity.CRITICAL and s != Severity.HIGH for s in sevs.values())


def test_scope_allows_empty_means_all(tmp_path: Path):
    assert scope_allows(_inp(tmp_path), "any/deep/file.py")


def test_scope_allows_files_and_dirs(tmp_path: Path):
    inp = _inp(tmp_path, scope=["a.py", "pkg/"])
    assert scope_allows(inp, "a.py")
    assert scope_allows(inp, "pkg/b.py")
    assert not scope_allows(inp, "other.py")
    assert not scope_allows(inp, "pkg2/b.py")


def test_env_scanner_skips_fixtures(tmp_path: Path):
    agent = EnvScanner()
    inp = _inp(tmp_path)
    assert agent._should_skip_file("patchi/core/security/attack_scenarios/auth.yaml", inp)
    assert agent._should_skip_file("tests/fixtures/keys.env", inp)
    assert not agent._should_skip_file("src/app.py", inp)


def test_env_scanner_scope_narrows(tmp_path: Path):
    # Part 7: "abc123" is not a verifiable secret — use a realistic value.
    (tmp_path / "a.py").write_text('token = "Q7ZmK2vX9pL4wN8cR3tY6uI1oP5aS0"\n', encoding="utf-8")
    (tmp_path / "b.py").write_text('token = "Q7ZmK2vX9pL4wN8cR3tY6uI1oP5aS0"\n', encoding="utf-8")
    full = EnvScanner().run(_inp(tmp_path))
    scoped = EnvScanner().run(_inp(tmp_path, scope=["a.py"]))
    full_files = {f.file for f in full.findings}
    scoped_files = {f.file for f in scoped.findings}
    assert "b.py" in full_files
    assert scoped_files <= {"a.py"}


def test_comment_scanner_scope_narrows(tmp_path: Path):
    (tmp_path / "a.py").write_text("# BUG: broken\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("# BUG: broken\n", encoding="utf-8")
    scoped = CommentScanner().run(_inp(tmp_path, scope=["a.py"]))
    assert {f.file for f in scoped.findings if f.file != "__summary__"} == {"a.py"}


def test_idor_guard_awareness():
    from patchi.core.security.business_logic_agent import _OWNERSHIP_RE

    assert _OWNERSHIP_RE.search("with tenant_context(root):")
    assert _OWNERSHIP_RE.search("patch_project != str(root)")
    assert _OWNERSHIP_RE.search("current_user.id")
    assert not _OWNERSHIP_RE.search("patch = mem.read('patches', root)")


def test_idor_fixed_endpoint_clean():
    from patchi.core.security.business_logic_agent import BusinessLogicAgent

    root = Path(__file__).resolve().parent.parent
    inp = AgentInput(root=root, scope=[], brain={}, config={})
    result = BusinessLogicAgent().run(inp)
    idors = [f for f in result.findings if f.type == "idor_missing_ownership_check"]
    assert all("web/api" not in f.file or "fix.py" not in f.file for f in idors), [
        (f.file, f.line) for f in idors if "fix.py" in f.file
    ]
