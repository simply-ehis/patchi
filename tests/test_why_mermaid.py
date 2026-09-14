"""`p why --mermaid` — explanation path as Mermaid sequence diagrams."""

import pytest

from patchi.cli.commands.reason_cmd import _cached_graph, run_why


@pytest.fixture()
def graph_root(tmp_path, monkeypatch):
    """A project root whose cached brain memory holds a small import graph:

        caller_a.py  -> core.py
        caller_b.py  -> core.py
        core.py      -> helper.py, other.py
    """
    import patchi.core.memory as mem

    data = {
        "import_graph": {
            "nodes": ["caller_a.py", "caller_b.py", "core.py", "helper.py", "other.py"],
            "edges": {
                "caller_a.py": ["core.py"],
                "caller_b.py": ["core.py"],
                "core.py": ["helper.py", "other.py"],
            },
        }
    }
    monkeypatch.setattr(mem, "get_brain", lambda root=None, *a, **k: data)
    return tmp_path


def test_cached_graph_round_trips_dict(graph_root):
    g = _cached_graph(graph_root)
    assert g is not None
    assert g.nodes == {"caller_a.py", "caller_b.py", "core.py", "helper.py", "other.py"}
    assert g.edges["core.py"] == {"helper.py", "other.py"}
    assert g.reverse["core.py"] == {"caller_a.py", "caller_b.py"}


def test_cached_graph_none_without_scan_data(tmp_path, monkeypatch):
    import patchi.core.memory as mem

    monkeypatch.setattr(mem, "get_brain", lambda root=None, *a, **k: {})
    assert _cached_graph(tmp_path) is None


def test_mermaid_emits_both_walks(graph_root, capsys):
    run_why("core.py", root=graph_root, mermaid=True)
    out = capsys.readouterr().out
    assert out.count("```mermaid") == 2  # dependents walk + call-flow walk
    # Dependents walk must name an importer; call-flow walk must name an import.
    assert "caller_a" in out or "caller_b" in out
    assert "helper" in out or "other" in out


def test_mermaid_without_scan_data_is_honest(tmp_path, monkeypatch, capsys):
    import patchi.core.memory as mem

    monkeypatch.setattr(mem, "get_brain", lambda root=None, *a, **k: {})
    run_why("core.py", root=tmp_path, mermaid=True)
    out = capsys.readouterr().out
    assert "Run `p scan` first" in out
    assert "```mermaid" not in out


def test_mermaid_unknown_file_still_diagrams(graph_root, capsys):
    """--mermaid works from the import graph even when layers don't know the
    file (the layered-brain path would return an error here)."""
    run_why("helper.py", root=graph_root, mermaid=True)
    out = capsys.readouterr().out
    assert "```mermaid" in out
