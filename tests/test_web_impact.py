"""Web impact view: the /impact page and its /api/impact endpoint.

The endpoint must serve the *same* affected-neighborhood flowchart the
CLI renders (`p impact --mermaid`, `p fix`'s summary/PR file) — computed
by the shared ``neighborhood_diagram`` over the same cached import graph,
verified here by direct comparison. Errors are data (404 + JSON), never
an HTML page, per the machine-pure convention.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from patchi.web.app import create_app

GRAPH = {
    "import_graph": {
        "nodes": ["caller_a.py", "caller_b.py", "core.py", "helper.py", "island.py"],
        "edges": {
            "caller_a.py": ["core.py"],
            "caller_b.py": ["core.py"],
            "core.py": ["helper.py"],
            "island.py": ["helper.py"],  # island.py imports helper.py but is NOT a dependent of core.py
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


def test_impact_page_renders(seeded):
    r = _client(seeded).get("/impact")
    assert r.status_code == 200
    assert 'id="impact-files"' in r.text
    assert 'id="impact-go"' in r.text
    assert "/static/mermaid.min.js" in r.text  # vendored renderer referenced


def test_impact_page_in_nav(seeded):
    r = _client(seeded).get("/impact")
    assert 'href="/impact"' in r.text  # reachable from the main tabs


def test_impact_page_accepts_initial_files(seeded):
    r = _client(seeded).get("/impact", params={"files": "core.py"})
    assert r.status_code == 200
    assert "core.py" in r.text


# ── API ──────────────────────────────────────────────────────────────────────


def test_api_impact_returns_diagram_and_stats(seeded):
    r = _client(seeded).get("/api/impact", params={"files": "core.py"})
    assert r.status_code == 200
    doc = r.json()
    assert doc["ok"] is True
    assert doc["files"] == ["core.py"]
    assert doc["source"] == "explicit"
    assert "flowchart TD" in doc["mermaid"]
    assert doc["stats"]["changed"] == 1
    assert doc["stats"]["total_affected"] >= 1
    assert "risk" in doc["stats"]


def test_api_impact_diagram_matches_cli_helper(seeded):
    """Verbatim sharing: byte-identical to the CLI renderer's output."""
    from patchi.cli.commands.reason_cmd import _cached_graph
    from patchi.core.brain.mermaid import neighborhood_diagram

    doc = _client(seeded).get("/api/impact", params={"files": "core.py,helper.py"}).json()
    graph = _cached_graph(seeded)
    expected_mermaid, expected_stats = neighborhood_diagram(graph, ["core.py", "helper.py"])
    assert doc["mermaid"] == expected_mermaid
    assert doc["stats"] == expected_stats


def test_api_impact_neighborhood_is_scoped(seeded):
    """Only dependents appear — island.py is not a dependent of core.py."""
    doc = _client(seeded).get("/api/impact", params={"files": "core.py"}).json()
    assert "island_py" not in doc["mermaid"]
    assert "caller_a" in doc["mermaid"] or "caller_b" in doc["mermaid"]


def test_api_impact_accepts_comma_separated_files(seeded):
    doc = _client(seeded).get("/api/impact", params={"files": "core.py,island.py"}).json()
    assert doc["ok"] is True
    assert doc["files"] == ["core.py", "island.py"]
    assert "island_py" in doc["mermaid"]


def test_api_impact_infers_recent_fix_files(seeded, monkeypatch):
    """No ?files= -> fall back to the last fix run's touched files."""
    import patchi.core.memory as mem

    monkeypatch.setattr(
        mem,
        "list_patches",
        lambda root=None, *a, **k: [
            {"id": "old", "affected_paths": ["ancient.py"]},
            {"id": "newest", "affected_paths": ["core.py", "helper.py"]},
        ],
    )
    doc = _client(seeded).get("/api/impact").json()
    assert doc["ok"] is True
    assert doc["source"] == "recent_fix"
    assert doc["files"] == ["core.py", "helper.py"]


def test_api_impact_without_files_or_patches_is_a_json_404(seeded):
    r = _client(seeded).get("/api/impact")
    assert r.status_code == 404
    assert r.headers["content-type"].startswith("application/json")
    doc = r.json()
    assert doc["ok"] is False
    assert "?files=" in doc["error"]


def test_api_impact_without_scan_data_is_a_json_404(bare):
    r = _client(bare).get("/api/impact", params={"files": "core.py"})
    assert r.status_code == 404
    doc = r.json()
    assert doc["ok"] is False
    assert "p scan" in doc["error"]


def test_api_impact_unknown_files_still_render(seeded):
    """Unknown changed files get nodes (no neighborhood) — same as the CLI."""
    doc = _client(seeded).get("/api/impact", params={"files": "brand_new.py"}).json()
    assert doc["ok"] is True
    assert "brand_new_py" in doc["mermaid"]
    assert doc["stats"]["changed"] == 1
