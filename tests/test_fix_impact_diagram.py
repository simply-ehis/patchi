"""`p fix` embeds the impact-neighborhood diagram of the patched files.

Contract (PR-comment embedding):
  - The diagram covers the union of applied + queued + blocked patch files —
    the run's full touched set, not just the applied ones.
  - It renders through the SAME cached-graph path and renderer as
    `p impact --mermaid`, so the two commands can never disagree.
  - Scoped by construction: only the touched files and their transitive
    dependents appear, never the whole graph.
  - Degradation is honest: no patches or no cached graph -> "impact": null
    in JSON and a summary without the section — never a fake empty diagram.
  - --out writes a self-contained PR-comment markdown: headline stats, risk
    table, and the mermaid block ready to paste.
  - --out and --json are mutually exclusive (one channel per consumer).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from patchi.cli.commands.fix_cmd import (
    ImpactDiagram,
    _impact_json,
    _impact_neighborhood,
    _write_pr_markdown,
)
from patchi.core.brain.import_graph import ImportGraph


@pytest.fixture()
def fix_project(tmp_path: Path) -> Path:
    """A minimal inited project whose brain carries a small import graph.

    Shape: auth.py <- service.py <- api.py, plus an unrelated component.
    """
    (tmp_path / ".patchi" / "memory").mkdir(parents=True)
    (tmp_path / "patchi.project.toml").write_text("", encoding="utf-8")
    brain = {
        "contract_locked": True,
        "import_graph": {
            "nodes": ["auth.py", "service.py", "api.py", "other.py"],
            "edges": {
                "service.py": ["auth.py"],
                "api.py": ["service.py"],
                "other.py": ["api.py"],  # separate importer of api.py
            },
        },
    }
    (tmp_path / ".patchi" / "memory" / "brain.json").write_text(
        json.dumps(brain), encoding="utf-8"
    )
    return tmp_path


def _patch(paths: list[str]):
    """A minimal Patch stand-in (the dataclass needs no AI to construct)."""
    from patchi.core.fix.patch import FileChange, Patch

    return Patch(changes=[FileChange(path=p, original="a\n", proposed="b\n") for p in paths])


def _diag(changed: list[str], graph: ImportGraph) -> ImpactDiagram:
    from patchi.core.brain.mermaid import neighborhood_diagram

    mermaid, stats = neighborhood_diagram(graph, changed)
    return ImpactDiagram(mermaid, stats)


# ── payload builder ───────────────────────────────────────────────────────


def test_diagram_covers_union_of_applied_queued_blocked(fix_project: Path):
    """Queued and blocked files are part of 'what this run takes down' too."""
    applied = [_patch(["auth.py"])]
    queued = [_patch(["service.py"])]
    blocked = [(_patch(["other.py"]), "risk gate")]
    diagram = _impact_neighborhood(applied, queued, blocked, fix_project)
    assert diagram is not None
    assert "auth_py" in diagram.mermaid and "service_py" in diagram.mermaid
    assert "other_py" in diagram.mermaid
    # api.py imports service.py -> in the neighborhood; stats agree
    assert diagram.stats["changed"] == 3
    assert diagram.stats["total_affected"] >= 1  # at least api.py


def test_scoped_neighborhood_excludes_unrelated_files():
    """A patch to auth.py must not drag unrelated components into the chart.

    Unrelated means: not the changed file and not a transitive dependent.
    (The fixture's other.py imports api.py, which transitively depends on
    auth.py — so other.py IS affected and must appear; a truly unrelated
    file with no path to auth.py must not.)
    """
    g = ImportGraph()
    g.add_edge("service.py", "auth.py")
    g.add_edge("unrelated.py", "island.py")  # separate component
    diagram = _diag(["auth.py"], g)
    assert "unrelated_py" not in diagram.mermaid
    assert "island_py" not in diagram.mermaid
    assert "service_py" in diagram.mermaid


def test_no_patches_returns_none(fix_project: Path):
    assert _impact_neighborhood([], [], [], fix_project) is None


def test_no_cached_graph_returns_none(tmp_path: Path):
    """No scan data -> honest None, not an empty diagram."""
    (tmp_path / ".patchi" / "memory").mkdir(parents=True)
    (tmp_path / "patchi.project.toml").write_text("", encoding="utf-8")
    assert _impact_neighborhood([_patch(["auth.py"])], [], [], tmp_path) is None


def test_never_raises_on_renderer_failure(fix_project: Path, monkeypatch):
    """A diagram must never fail a successful fix run."""

    def boom(*a, **k):
        raise RuntimeError("renderer exploded")

    monkeypatch.setattr("patchi.core.brain.mermaid.neighborhood_diagram", boom)
    assert _impact_neighborhood([_patch(["auth.py"])], [], [], fix_project) is None


# ── JSON contract ─────────────────────────────────────────────────────────


def test_impact_json_none_stays_none():
    assert _impact_json(None) is None


def test_impact_json_carries_mermaid_and_stats(fix_project: Path):
    diagram = _impact_neighborhood([_patch(["auth.py"])], [], [], fix_project)
    payload = _impact_json(diagram)
    assert payload is not None
    assert "```mermaid" not in payload["mermaid"]  # raw source, not fenced
    assert payload["changed"] == 1
    assert "risk" in payload


# ── PR markdown ───────────────────────────────────────────────────────────


def test_pr_markdown_is_self_contained(fix_project: Path, tmp_path: Path):
    diagram = _impact_neighborhood([_patch(["auth.py"])], [], [], fix_project)
    assert diagram is not None
    out = tmp_path / "pr" / "impact.md"
    _write_pr_markdown(diagram, out)
    text = out.read_text(encoding="utf-8")
    assert text.startswith("## Patchi fix — impact summary")
    assert "```mermaid" in text and diagram.mermaid in text
    assert "1 file(s) changed" in text
    assert "importer" in text  # direction legend for reviewers


def test_pr_markdown_omits_empty_risk_table(fix_project: Path, tmp_path: Path):
    diagram = _diag(["auth.py"], ImportGraph())
    out = tmp_path / "impact.md"
    _write_pr_markdown(diagram, out)
    assert "| Risk |" not in out.read_text(encoding="utf-8")


# ── CLI wiring ────────────────────────────────────────────────────────────


def test_summary_prints_impact_line(fix_project: Path, capsys):
    """The human summary names the neighborhood size when a diagram exists."""
    from patchi.cli.commands.fix_cmd import _show_summary

    diagram = _impact_neighborhood([_patch(["auth.py"])], [], [], fix_project)
    assert diagram is not None
    _show_summary([_patch(["auth.py"])], [], [], diagram)
    assert "Impact: 1 changed file(s)" in capsys.readouterr().out


def test_show_impact_section_writes_pr_file(fix_project: Path, tmp_path: Path, capsys):
    """--out wires the diagram into a PR-comment file and says where."""
    from patchi.cli.commands.fix_cmd import _show_impact_section

    diagram = _impact_neighborhood([_patch(["auth.py"])], [], [], fix_project)
    assert diagram is not None
    out_file = tmp_path / "IMPACT_PR.md"
    _show_impact_section(diagram, out_file)
    assert "IMPACT_PR.md" in capsys.readouterr().out
    assert "```mermaid" in out_file.read_text(encoding="utf-8")


def test_out_and_json_are_mutually_exclusive(fix_project: Path):
    """One output channel per consumer — same contract as p why/p impact."""
    from patchi.cli.commands.fix_cmd import run

    with pytest.raises(SystemExit) as exc:
        run(dry_run=True, root=fix_project, json_output=True, out="impact.md")
    assert exc.value.code == 2
