"""`p impact --mermaid` — affected-neighborhood flowcharts for changed files.

Contract under test (Part 5 "smarter diagrams" revision):
  - Scoped by construction: only the changed files and their transitive
    dependents appear — never the whole graph.
  - Blast direction: importer --> imported ("who breaks me").
  - Risk styling computed from real transitive-dependent counts.
  - Adaptive truncation: closest BFS shells kept first; the omitted tail is
    reported in stats, never silently dropped.
  - --all + --mermaid is refused (no neighborhood exists for --all).
"""

from __future__ import annotations

import pytest

from patchi.core.brain.import_graph import ImportGraph
from patchi.core.brain.mermaid import neighborhood_diagram, risk_class, sequence_diagram


def _chain(depth: int) -> ImportGraph:
    """changed.py <- d1.py <- d2.py ... (each di imports d(i-1))."""
    g = ImportGraph()
    prev = "changed.py"
    for i in range(1, depth + 1):
        cur = f"d{i}.py"
        g.add_edge(cur, prev)
        prev = cur
    return g


@pytest.fixture()
def graph():
    g = ImportGraph()
    g.add_edge("mid.py", "leaf.py")
    g.add_edge("top_a.py", "mid.py")
    g.add_edge("top_b.py", "mid.py")
    g.add_edge("unrelated.py", "other.py")  # a separate component
    return g


# ── risk_class: the shared bands ─────────────────────────────────────────────


def test_risk_class_bands():
    """Bands match the CLI table's preserved semantics: 0 = low, 1-3 = med,
    4-10 = high, 11+ = critical."""
    assert risk_class(0) == "low"
    assert risk_class(1) == "med"
    assert risk_class(3) == "med"
    assert risk_class(4) == "high"
    assert risk_class(10) == "high"
    assert risk_class(11) == "critical"
    assert risk_class(400) == "critical"


# ── scoping and direction ────────────────────────────────────────────────────


def test_neighborhood_excludes_unaffected_files(graph):
    src, stats = neighborhood_diagram(graph, ["leaf.py"])
    assert "unrelated" not in src and "other" not in src
    for name in ("leaf", "mid", "top_a", "top_b"):
        assert name in src
    assert stats["changed"] == 1
    assert stats["total_affected"] == 3
    assert stats["rendered"] == 4 and stats["omitted"] == 0


def test_neighborhood_edges_point_in_blast_direction(graph):
    """importer --> imported: the flow reads 'top_a breaks mid breaks leaf'."""
    src, _ = neighborhood_diagram(graph, ["leaf.py"])
    assert "top_a_py --> mid_py" in src
    assert "mid_py --> leaf_py" in src


def test_neighborhood_highlights_only_changed(graph):
    src, _ = neighborhood_diagram(graph, ["leaf.py"])
    assert ':::changed' in src
    # exactly one changed-class node (leaf)
    assert src.count(":::changed") == 1


def test_neighborhood_risk_from_transitive_counts(graph):
    """mid has 2 transitive dependents (med band); top_a has 1 (low)."""
    _, stats = neighborhood_diagram(graph, ["leaf.py"])
    assert stats["risk"] == {"low": 2, "med": 2}


def test_neighborhood_dynamic_title_when_not_given(graph):
    src, _ = neighborhood_diagram(graph, ["leaf.py"])
    assert "title: Impact neighborhood — 1 changed, 3 affected" in src


def test_neighborhood_unknown_changed_file_still_gets_a_node(graph):
    src, stats = neighborhood_diagram(graph, ["brand_new.py"])
    assert "brand_new" in src
    assert stats["changed"] == 1
    assert stats["total_affected"] == 0


def test_neighborhood_through_unknown_changed_file(graph):
    """A brand-new file's importers still form the neighborhood — BFS starts
    from unknown changed files too."""
    g = ImportGraph()
    g.add_edge("importer.py", "brand_new.py")
    src, stats = neighborhood_diagram(g, ["brand_new.py"])
    assert "importer" in src
    assert stats["total_affected"] == 1


# ── adaptive truncation ──────────────────────────────────────────────────────


def test_neighborhood_keeps_closest_shells_first():
    g = _chain(5)
    src, stats = neighborhood_diagram(g, ["changed.py"], max_nodes=3)
    assert stats["rendered"] == 3
    assert stats["truncated"] is True
    # changed (d0) + d1 (distance 1) + d2 (distance 2) rendered; the rest
    # omitted, reported by distance.
    assert "d1" in src and "d2" in src and "d3" not in src
    assert stats["omitted_by_distance"] == {3: 1, 4: 1, 5: 1}
    assert stats["max_distance"] == 2  # furthest RENDERED node


def test_neighborhood_changed_files_always_kept():
    g = _chain(5)
    src, stats = neighborhood_diagram(g, ["changed.py"], max_nodes=1)
    # even a budget of 1 keeps the changed file itself
    assert "changed_py[" in src
    assert stats["omitted_by_distance"] == {1: 1, 2: 1, 3: 1, 4: 1, 5: 1}


# ── CLI wiring: p impact --mermaid modes ────────────────────────────────────


@pytest.fixture()
def graph_root(tmp_path, monkeypatch):
    """Project root with a cached import graph (as if `p scan` had run)."""
    import patchi.core.memory as mem

    data = {
        "import_graph": {
            "nodes": ["leaf.py", "mid.py", "top_a.py", "top_b.py"],
            "edges": {
                "mid.py": ["leaf.py"],
                "top_a.py": ["mid.py"],
                "top_b.py": ["mid.py"],
            },
        }
    }
    monkeypatch.setattr(mem, "get_brain", lambda root=None, *a, **k: data)
    return tmp_path


def test_cli_mermaid_human_mode_fences(graph_root, capsys):
    from patchi.cli.commands.reason_cmd import run_impact

    run_impact(["leaf.py"], root=graph_root, mermaid=True)
    out = capsys.readouterr().out
    assert out.count("```mermaid") == 1
    assert "top_a" in out  # dependents included
    assert "shown" in out and "affected" in out  # stats line


def test_cli_mermaid_json_mode(graph_root, capsys):
    import json as jsonlib

    from patchi.cli.commands.reason_cmd import run_impact

    run_impact(["leaf.py"], root=graph_root, mermaid=True, json_output=True)
    out = capsys.readouterr().out
    doc = jsonlib.loads(out)  # byte-pure: the whole stdout is the document
    assert doc["files"] == ["leaf.py"]
    assert "flowchart TD" in doc["mermaid"]
    assert doc["stats"]["total_affected"] == 3


def test_cli_mermaid_out_mode_writes_markdown(graph_root, capsys):
    from patchi.cli.commands.reason_cmd import run_impact

    out = graph_root / "impact.md"
    run_impact(["leaf.py"], root=graph_root, mermaid=True, out=out)
    text = out.read_text(encoding="utf-8")
    assert text.count("```mermaid") == 1
    assert "```json" in text  # stats block for machines
    assert "Impact neighborhood" in text
    stdout = capsys.readouterr().out
    assert "```mermaid" not in stdout  # file only, pointer on stdout


def test_cli_mermaid_without_graph_is_honest(tmp_path, monkeypatch, capsys):
    import patchi.core.memory as mem
    from patchi.cli.commands.reason_cmd import run_impact

    monkeypatch.setattr(mem, "get_brain", lambda root=None, *a, **k: {})
    with pytest.raises(SystemExit) as exc:
        run_impact(["leaf.py"], root=tmp_path, mermaid=True, out=tmp_path / "x.md")
    assert exc.value.code == 1
    assert not (tmp_path / "x.md").exists()


def test_cli_mermaid_with_all_is_refused(graph_root, capsys):
    from patchi.cli.commands.reason_cmd import run_impact

    with pytest.raises(SystemExit) as exc:
        run_impact(None, root=graph_root, mermaid=True, show_all=True, out=graph_root / "x.md")
    assert exc.value.code == 2
    assert not (graph_root / "x.md").exists()


def test_cli_mermaid_without_files_fails_honestly(graph_root):
    from patchi.cli.commands.reason_cmd import run_impact

    with pytest.raises(SystemExit) as exc:
        run_impact([], root=graph_root, mermaid=True)
    assert exc.value.code == 1


def test_sequence_diagram_walks_to_natural_end():
    """max_hops=0 (new default) walks the call chain until it ends, not 8
    hops. (The walk follows the imports direction: handler -> what it uses.)"""
    g = ImportGraph()
    prev = "changed.py"
    for i in range(1, 13):
        cur = f"d{i}.py"
        g.add_edge(prev, cur)  # changed.py imports d1 imports d2 ...
        prev = cur
    from patchi.core.brain.route_mapper import RouteInfo

    route = RouteInfo(method="USE", path="changed.py", handler="changed", file="changed.py", line=1)
    src = sequence_diagram([route], g, entry="changed.py")
    assert "d12" in src  # full chain walked, no cap
