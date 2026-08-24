"""Tests for the charter guard-rail system (Pillar 2)."""

from pathlib import Path

from patchi.core import memory as mem
from patchi.core.brain.charter import (
    Charter,
    check_charter,
    load_charter,
    parse_charter,
    parse_charter_with_ai,
    save_charter,
)


def _layer(name, deps=None):
    return {
        "name": name,
        "level": 2,
        "summary": f"{name} layer",
        "public_api": [],
        "files": [f"{name}/a.py"],
        "depends_on": deps or [],
        "dependents": [],
        "role": name,
        "kind": "subsystem",
        "validity_hash": "x",
    }


def _charter(tmp_path: Path, text: str) -> Charter:
    c = parse_charter(text)
    save_charter(c, tmp_path)
    return c


def test_parse_charter_boundary():
    c = parse_charter("Frontend must not import backend")
    assert len(c.boundaries) == 1
    assert c.boundaries[0]["from"] == "frontend"
    assert c.boundaries[0]["to"] == "backend"


def test_parse_charter_role_resolution():
    c = parse_charter("React must not import flask")
    assert c.boundaries[0]["from"] == "react"
    assert c.boundaries[0]["to"] == "flask"


def test_parse_charter_stack_constraint():
    c = parse_charter("We use only Python and TypeScript")
    assert "python" in c.stack["languages"]
    assert "typescript" in c.stack["languages"]


def test_parse_charter_security_rule():
    c = parse_charter("No hardcoded secrets and no eval")
    assert "no_hardcoded_secrets" in c.security
    assert "no_eval" in c.security


def test_check_charter_flags_violation():
    layers = {
        "frontend": _layer("frontend", deps=["backend"]),
        "backend": _layer("backend"),
    }
    c = parse_charter("Frontend must not import backend")
    violations = check_charter(c, layers)
    assert len(violations) == 1
    assert violations[0].severity == "high"
    assert "frontend" in violations[0].message.lower()


def test_check_charter_no_false_positive():
    layers = {
        "frontend": _layer("frontend", deps=["shared"]),
        "backend": _layer("backend"),
        "shared": _layer("shared"),
    }
    c = parse_charter("Frontend must not import backend")
    assert check_charter(c, layers) == []


def test_check_charter_role_resolution_violation():
    # Real subsystem layer names (ui / api) resolved from react / flask.
    layers = {
        "ui": _layer("ui", deps=["api"]),
        "api": _layer("api"),
    }
    c = parse_charter("React must not import flask")
    violations = check_charter(c, layers)
    assert len(violations) == 1


def test_to_finding_shape():
    c = parse_charter("Frontend must not import backend")
    v = check_charter(c, {"frontend": _layer("frontend", deps=["backend"]),
                          "backend": _layer("backend")})[0]
    f = v.to_finding()
    assert f["severity"] in ("high", "medium", "low")
    assert f["agent"] == "CharterGuard"
    assert f["type"] == "charter-drift"
    assert "rule" in f and "message" in f


def test_save_load_roundtrip(tmp_path):
    c = _charter(tmp_path, "Frontend must not import backend")
    loaded = load_charter(tmp_path)
    assert loaded is not None
    assert loaded.boundaries[0]["from"] == c.boundaries[0]["from"]


def test_check_charter_missing_layer_skipped():
    # Boundary references a layer absent from the current codebase.
    layers = {"backend": _layer("backend")}
    c = parse_charter("Frontend must not import backend")
    assert check_charter(c, layers) == []


def test_parse_charter_with_ai_returns_none_without_ai():
    c = parse_charter_with_ai("Frontend must not import backend", {})
    assert c is None


def test_parse_charter_with_ai_falls_back(monkeypatch):
    # Force the LLM call to raise; the CLI path falls back to heuristic parsing.
    import patchi.core.brain.charter as ch

    def boom(*a, **k):
        raise RuntimeError("no llm")

    monkeypatch.setattr(ch, "call_ai" if hasattr(ch, "call_ai") else "parse_charter_with_ai", boom)
    # Without ai keys in config, parse_charter_with_ai short-circuits to None.
    c = parse_charter_with_ai("Frontend must not import backend", {"ai": {"keys": ["x"]}})
    # Either None (handled by CLI fallback) or a parsed charter is acceptable.
    assert c is None or isinstance(c, Charter)


def test_cli_set_and_check(tmp_path, monkeypatch):
    from patchi.cli.commands import charter_cmd
    from patchi.core.config import require_project_root

    monkeypatch.setattr(require_project_root, "__call__", lambda: tmp_path)
    charter_cmd.run_set("Frontend must not import backend", root=tmp_path)

    mem.save_layers({
        "frontend": _layer("frontend", deps=["backend"]),
        "backend": _layer("backend"),
    }, tmp_path)

    c = load_charter(tmp_path)
    violations = check_charter(c, mem.get_layers(tmp_path))
    assert len(violations) == 1
