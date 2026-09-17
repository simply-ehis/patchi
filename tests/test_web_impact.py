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


def test_api_impact_max_nodes_caps_like_cli(seeded):
    """The web view honors the same cap as `p impact --mermaid --max-nodes`
    — one renderer, one contract."""
    from patchi.cli.commands.reason_cmd import _cached_graph
    from patchi.core.brain.mermaid import neighborhood_diagram

    doc = _client(seeded).get("/api/impact", params={"files": "core.py", "max_nodes": 2}).json()
    assert doc["ok"] is True
    assert doc["stats"]["rendered"] == 2
    assert doc["stats"]["truncated"] is True

    # Byte-identical to the CLI renderer at the same budget, modulo the HTTP
    # boundary's documented int->str key coercion on omitted_by_distance.
    graph = _cached_graph(seeded)
    expected_mermaid, expected_stats = neighborhood_diagram(graph, ["core.py"], max_nodes=2)
    assert doc["mermaid"] == expected_mermaid
    expected = {
        **expected_stats,
        "omitted_by_distance": {
            str(k): v for k, v in expected_stats["omitted_by_distance"].items()
        },
    }
    assert doc["stats"] == expected


def test_api_impact_invalid_max_nodes_falls_back_to_default(seeded):
    """A display control, not a data request: < 1 falls back to 60 rather
    than erroring the panel."""
    doc = _client(seeded).get("/api/impact", params={"files": "core.py", "max_nodes": 0}).json()
    assert doc["ok"] is True
    assert doc["stats"]["truncated"] is False  # 5-node graph fits under 60


# ── mode=map: whole-graph blast-radius map ─────────────────────────────────


def test_api_impact_map_mode_shape(seeded):
    """The map is the whole-graph dependency_diagram with highlights + the
    CLI's _blast_radii ranking, not the scoped neighborhood."""
    doc = _client(seeded).get("/api/impact", params={"files": "core.py", "mode": "map"}).json()
    assert doc["ok"] is True
    assert doc["mode"] == "map"
    assert "flowchart LR" in doc["mermaid"]  # dependency_diagram renders LR; neighborhood is TD
    assert doc["stats"]["nodes"] == 5
    assert doc["stats"]["highlighted"] == 1
    assert doc["stats"]["unknown"] == 0
    assert isinstance(doc["stats"]["risk"], dict)


def test_api_impact_map_diagram_matches_cli_helper(seeded):
    """Verbatim sharing: the map is byte-identical to dependency_diagram with
    the same highlight set."""
    from patchi.cli.commands.reason_cmd import _blast_radii, _cached_graph
    from patchi.core.brain.mermaid import dependency_diagram

    doc = _client(seeded).get(
        "/api/impact", params={"files": "core.py,island.py", "mode": "map"}
    ).json()
    graph = _cached_graph(seeded)
    expected = dependency_diagram(
        graph, max_nodes=60, title="Blast-radius map", highlight=["core.py", "island.py"]
    )
    assert doc["mermaid"] == expected
    # and the risk histogram slices the same radii the CLI --all table shows
    radii = _blast_radii(graph)
    assert len(radii) == doc["stats"]["nodes"]


def test_api_impact_map_highlights_changed_nodes(seeded):
    """Changed files carry the :::changed class; untouched nodes don't."""
    doc = _client(seeded).get("/api/impact", params={"files": "core.py", "mode": "map"}).json()
    assert "core_py[" in doc["mermaid"] and ":::changed" in doc["mermaid"]
    assert "classDef changed" in doc["mermaid"]


def test_api_impact_map_unknown_files_counted_not_rendered(seeded):
    """A requested file the graph doesn't know is reported in stats, not
    silently dropped or invented into the map."""
    doc = _client(seeded).get(
        "/api/impact", params={"files": "core.py,brand_new.py", "mode": "map"}
    ).json()
    assert doc["stats"]["highlighted"] == 1
    assert doc["stats"]["unknown"] == 1
    assert "brand_new" not in doc["mermaid"]


def test_api_impact_map_respects_max_nodes(seeded):
    """max_nodes caps the map the same way it caps the neighborhood."""
    doc = _client(seeded).get(
        "/api/impact", params={"files": "core.py", "mode": "map", "max_nodes": 3}
    ).json()
    assert doc["stats"]["rendered"] == 3


def test_api_impact_map_works_without_files(seeded):
    """The map is whole-graph: it renders even with no changed-file set (the
    neighborhood mode requires files or a recent fix run; the map doesn't)."""
    doc = _client(seeded).get("/api/impact", params={"mode": "map"}).json()
    assert doc["ok"] is True
    assert doc["stats"]["highlighted"] == 0


def test_api_impact_unknown_mode_is_a_json_404(seeded):
    r = _client(seeded).get("/api/impact", params={"files": "core.py", "mode": "nope"})
    assert r.status_code == 404
    doc = r.json()
    assert doc["ok"] is False
    assert "neighborhood" in doc["error"] and "map" in doc["error"]


def test_impact_page_offers_map_toggle(seeded):
    """The page exposes the map view and its fetch wiring."""
    r = _client(seeded).get("/impact")
    assert r.status_code == 200
    assert 'id="impact-mode-map"' in r.text
    assert 'id="impact-mode-neighborhood"' in r.text
    assert "mode=map" in r.text  # fetch layer sends the mode
