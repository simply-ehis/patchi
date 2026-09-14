"""Mermaid generation from Brain graph data (Part 4 §2 / Item 31)."""

from patchi.core.brain.import_graph import ImportGraph
from patchi.core.brain.mermaid import dependency_diagram


def test_truncation_keeps_highest_fan_in_not_first_alphabetical():
    """30 modules import zzz_hub.py, which sorts LAST alphabetically.

    Old behavior truncated to the first max_nodes alphabetically and dropped
    the hub entirely. Ranking must precede truncation: the hub survives and
    its incoming edges are visible.
    """
    g = ImportGraph()
    for i in range(30):
        g.add_edge(f"mod_{i:02d}.py", "zzz_hub.py")
    diagram = dependency_diagram(g, max_nodes=10)
    assert "zzz_hub" in diagram, "highest fan-in node dropped by alphabetical truncation"
    # 9 of the 10 kept nodes are importers of the hub -> 9 visible edges.
    assert diagram.count("--> zzz_hub_py") == 9
    # Zero-fan-in nodes truncate alphabetically: early mods stay, late ones go.
    assert "mod_00_py" in diagram
    assert "mod_20_py" not in diagram


def test_low_fan_in_leaves_are_truncated_first():
    """Leaves (fan-in 1) outrank pure importers (fan-in 0); exactly the
    alphabetically-last 6 leaves fall outside the top-25."""
    g = ImportGraph()
    for i in range(30):
        g.add_edge(f"mod_{i:02d}.py", "zzz_hub.py")
        g.add_edge(f"mod_{i:02d}.py", f"leaf_{i:02d}.py")
    diagram = dependency_diagram(g, max_nodes=25)
    # Kept: zzz_hub (fan-in 30) + 24 leaves. Dropped: leaf_24..leaf_29 + all mods.
    for i in range(24):
        assert f"leaf_{i:02d}_py" in diagram
    for i in range(24, 30):
        assert f"leaf_{i:02d}_py" not in diagram
    assert "mod_00_py" not in diagram


def test_colliding_stems_get_disambiguated_labels():
    """Three different base.py files must not render as three identical boxes."""
    g = ImportGraph()
    g.add_edge("a/base.py", "a/core.py")
    g.add_edge("b/base.py", "b/core.py")
    g.add_edge("c/base.py", "c/core.py")
    diagram = dependency_diagram(g, max_nodes=10)
    assert '["a/base"]' in diagram
    assert '["b/base"]' in diagram
    assert '["c/base"]' in diagram
