"""Web file-explain view: the /why page and its /api/why endpoint.

The endpoint must serve the *same* two explanation-path diagrams the CLI's
`p why --mermaid` renders — computed through the shared ``_why_diagrams``
helper, verified here by direct comparison. Errors are data (404 + JSON),
never an HTML page, per the machine-pure convention.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from patchi.web.app import create_app

GRAPH = {
    "import_graph": {
        "nodes": ["caller_a.py", "caller_b.py", "core.py", "helper.py", "other.py"],
        "edges": {
            "caller_a.py": ["core.py"],
            "caller_b.py": ["core.py"],
            "core.py": ["helper.py", "other.py"],
        },
    }
}


@pytest.fixture()
def seeded(tmp_path, monkeypatch):
    """App with a cached import graph (as if `p scan` had run)."""
    import patchi.core.memory as mem

    monkeypatch.setattr(mem, "get_brain", lambda root=None, *a, **k: GRAPH)
    return tmp_path


@pytest.fixture()
def bare(tmp_path):
    """App with no scan data at all."""
    return tmp_path


def _client(root) -> TestClient:
    return TestClient(create_app(root))


# ── page ─────────────────────────────────────────────────────────────────────


def test_why_page_renders(seeded):
    r = _client(seeded).get("/why")
    assert r.status_code == 200
    assert 'id="why-path"' in r.text
    assert 'id="why-go"' in r.text
    assert "/static/mermaid.min.js" in r.text  # vendored renderer referenced


def test_why_page_in_nav(seeded):
    r = _client(seeded).get("/why")
    assert 'href="/why"' in r.text  # reachable from the main tabs


def test_why_page_accepts_initial_path(seeded):
    r = _client(seeded).get("/why", params={"path": "core.py"})
    assert r.status_code == 200
    assert "core.py" in r.text


# ── API ──────────────────────────────────────────────────────────────────────


def test_api_why_returns_two_diagrams(seeded):
    r = _client(seeded).get("/api/why", params={"path": "core.py"})
    assert r.status_code == 200
    doc = r.json()
    assert doc["ok"] is True
    assert doc["path"] == "core.py"
    titles = [d["title"] for d in doc["diagrams"]]
    assert titles == ["Dependents — who calls this file", "Call flow — what this file leans on"]
    for d in doc["diagrams"]:
        assert "sequenceDiagram" in d["mermaid"]


def test_api_why_diagrams_match_cli_helper(seeded):
    from patchi.cli.commands.reason_cmd import _why_diagrams

    doc = _client(seeded).get("/api/why", params={"path": "core.py"}).json()
    expected = _why_diagrams(seeded, "core.py")
    assert [(d["title"], d["mermaid"]) for d in doc["diagrams"]] == expected


def test_api_why_dependents_walk_names_importers(seeded):
    doc = _client(seeded).get("/api/why", params={"path": "core.py"}).json()
    dependents_mermaid = doc["diagrams"][0]["mermaid"]
    assert "caller_a" in dependents_mermaid or "caller_b" in dependents_mermaid


def test_api_why_layer_facts_when_layers_exist(seeded, monkeypatch):
    """With a layered brain present, the document carries the p why facts."""
    # A stub engine keeps this test about the *wiring*, not the layer format.
    # Patch the source module — the endpoint imports the name at call time.
    class _FakeEngine:
        def __init__(self, root):
            pass

        def why(self, path):
            return {
                "file": path,
                "layer": "core-layer",
                "purpose": "Shared core helpers.",
                "depended_on_by": ["caller_a.py", "caller_b.py"],
                "importance": "critical",
                "files_in_layer": 3,
            }

    import patchi.core.brain.reasoning as reasoning_mod

    monkeypatch.setattr(reasoning_mod, "ReasoningEngine", _FakeEngine)
    doc = _client(seeded).get("/api/why", params={"path": "core.py"}).json()
    assert doc["layer"] == "core-layer"
    assert doc["importance"] == "critical"
    assert doc["depended_on_by"] == ["caller_a.py", "caller_b.py"]
    assert doc["files_in_layer"] == 3


def test_api_why_without_path_is_a_json_404(bare):
    r = _client(bare).get("/api/why")
    assert r.status_code == 404
    assert r.headers["content-type"].startswith("application/json")
    assert r.json()["ok"] is False
    assert "provide" in r.json()["error"]


def test_api_why_without_scan_data_is_a_json_404(bare):
    r = _client(bare).get("/api/why", params={"path": "core.py"})
    assert r.status_code == 404
    doc = r.json()
    assert doc["ok"] is False
    assert "p scan" in doc["error"]
