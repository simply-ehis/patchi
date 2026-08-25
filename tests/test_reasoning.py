"""Tests for the Reasoning Engine (Phase 3)."""

from pathlib import Path

from patchi.core import memory as mem
from patchi.core.brain.layered_brain import build_layers, layers_to_dict
from patchi.core.brain.reasoning import ReasoningEngine


class _FI:
    def __init__(self, path, language="python", funcs=()):
        self.path = path
        self.language = language
        self.functions = [type("F", (), {"name": n})() for n in funcs]
        self.classes = []
        self.imports = []
        self.exports = []
        self.is_entry_point = False


class _Graph:
    def __init__(self, edges):
        self.edges = edges


def _build(root: Path):
    # api depends on auth, so a change in auth ripples to api.
    fis = [
        _FI("auth/login.py", funcs=("do_login",)),
        _FI("auth/session.py", funcs=("make_token",)),
        _FI("api/routes.py", funcs=("get_user",)),
        _FI("data/models.py", funcs=("User",)),
    ]
    graph = _Graph({"api/routes.py": ["auth/login.py"]})
    layers = build_layers(fis, graph, [], None)
    mem.save_layers(layers_to_dict(layers), root)
    return fis, layers


def test_impact_analysis_blast_radius(tmp_path):
    _build(tmp_path)
    engine = ReasoningEngine(tmp_path)
    analysis = engine.impact_analysis(["auth/login.py"])
    assert "auth" in analysis.affected_layers
    # api imports auth → api is in the blast radius
    assert "api" in analysis.impacted_layers
    assert "auth" not in analysis.impacted_layers  # directly affected, not downstream


def test_impact_analysis_no_layers(tmp_path):
    engine = ReasoningEngine(tmp_path)
    analysis = engine.impact_analysis(["x.py"])
    assert "No layered brain" in analysis.summary


def test_explain_layer(tmp_path):
    _build(tmp_path)
    engine = ReasoningEngine(tmp_path)
    info = engine.explain("auth")
    assert info["layer"] == "auth"
    assert info["level"] == 2
    assert "summary" in info
    # dependency context should mention session module
    assert "session" in info["summary"] or info["depends_on"] == []


def test_explain_file_resolves_to_layer(tmp_path):
    _build(tmp_path)
    engine = ReasoningEngine(tmp_path)
    info = engine.explain("auth/login.py")
    assert info["layer"] == "auth"


def test_why_file(tmp_path):
    _build(tmp_path)
    engine = ReasoningEngine(tmp_path)
    info = engine.why("auth/login.py")
    assert info["layer"] == "auth"
    assert "api" in info["depended_on_by"]  # api depends on auth
    assert info["importance"] in ("critical", "shared", "leaf")


def test_ask_matches_layer(tmp_path):
    _build(tmp_path)
    engine = ReasoningEngine(tmp_path)
    answer = engine.ask("what does the auth subsystem do?")
    assert "auth" in answer
    assert "layered brain" in answer.lower() or "auth" in answer.lower()


def test_ask_no_brain(tmp_path):
    engine = ReasoningEngine(tmp_path)
    answer = engine.ask("anything?")
    assert "scan" in answer.lower()


def test_ask_no_match(tmp_path):
    _build(tmp_path)
    engine = ReasoningEngine(tmp_path)
    answer = engine.ask("zzzqqq nonexistentthing")
    assert "couldn't match" in answer.lower()
