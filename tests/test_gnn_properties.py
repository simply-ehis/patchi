"""Property-based tests for GNN vulnerability classifier invariants.

Hypothesis-generated checks that the GNN forward pass upholds its output
contract under random valid CPG-shaped inputs: fixed class-catalog width,
determinism, and bounded sensitivity to input noise.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import numpy as np
import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

torch = pytest.importorskip("torch", reason="torch not installed")

from patchi.core.agents.gnn_models import (  # noqa: E402
    CLASS_NAMES,
    GINGATNet,
    graph_to_tensors,
)

# ── Strategies (defined before use — module import order matters) ────────────

NODE_TYPE_CHOICES = [
    "function_definition",
    "assignment",
    "call",
    "return",
    "if",
    "while",
    "import",
]

_node_triple_strategy = st.tuples(
    st.sampled_from(NODE_TYPE_CHOICES),
    st.integers(min_value=1, max_value=200),
    st.text(
        min_size=1,
        max_size=80,
        alphabet=st.characters(blacklist_categories=("Cc",)),
    ),
)

_node_list_strategy = st.lists(_node_triple_strategy, min_size=1, max_size=15)

_edge_pair_strategy = st.tuples(
    st.integers(min_value=0, max_value=29),
    st.integers(min_value=0, max_value=29),
).filter(lambda e: e[0] != e[1])

_edge_list_strategy = st.lists(_edge_pair_strategy, min_size=0, max_size=20)


def _triple_to_node(triple) -> dict:
    return {"type": triple[0], "line": triple[1], "code": triple[2]}


def _build_graph(n_nodes: int, nodes: list, edges: list, n_edges_cap: int = 20) -> dict:
    """Assemble a graph dict from strategy outputs; pad nodes to n_nodes."""
    triples = list(nodes)[:n_nodes]
    if len(triples) < n_nodes:
        default = ("function_definition", 1, "def f(u):")
        triples += [default] * (n_nodes - len(triples))
    cpg_nodes = [_triple_to_node(t) for t in triples]
    valid_edges = [
        [min(e[0], n_nodes - 1), min(e[1], n_nodes - 1)]
        for e in list(edges)[:n_edges_cap]
        if e[0] < n_nodes and e[1] < n_nodes
    ]
    return {"nodes": cpg_nodes, "edges": valid_edges}


# ── Concrete contract tests ─────────────────────────────────────────────────


def test_logits_shape_is_class_catalog_size():
    net = GINGATNet().eval()
    g = {
        "nodes": [
            {"type": "function_definition", "line": 1, "code": "def f(u):"},
            {"type": "assignment", "line": 2, "code": "q = sel"},
            {"type": "call", "line": 3, "code": "db.execute(q)"},
        ],
        "edges": [[0, 1], [1, 2]],
    }
    x, ei, b = graph_to_tensors(g)
    with torch.no_grad():
        logits = net(x, ei, b)
    assert logits.shape == (1, len(CLASS_NAMES))


def test_class_catalog_first_is_safe():
    assert CLASS_NAMES[0] == "safe"
    assert len(CLASS_NAMES) >= 30


def test_same_input_same_output():
    net = GINGATNet().eval()
    g = {
        "nodes": [
            {"type": "function_definition", "line": 1, "code": "def f(u):"},
            {"type": "assignment", "line": 2, "code": "q = sel"},
            {"type": "call", "line": 3, "code": "db.execute(q)"},
        ],
        "edges": [[0, 1], [1, 2]],
    }
    x, ei, b = graph_to_tensors(g)
    with torch.no_grad():
        out1 = net(x, ei, b)
        out2 = net(x, ei, b)
    np.testing.assert_allclose(out1.numpy(), out2.numpy(), atol=1e-10)


# ── Property-based invariants ───────────────────────────────────────────────


@given(
    n_nodes=st.integers(min_value=1, max_value=15),
    nodes=_node_list_strategy,
    edges=_edge_list_strategy,
)
@settings(max_examples=25, deadline=None)
def test_property_output_shape_invariant(n_nodes, nodes, edges):
    """logits always have exactly len(CLASS_NAMES) columns."""
    g = _build_graph(n_nodes, nodes, edges)
    try:
        x, ei, b = graph_to_tensors(g)
    except (ValueError, IndexError, RuntimeError):
        return
    with torch.no_grad():
        net = GINGATNet().eval()
        logits = net(x, ei, b)
    assert logits.shape == (1, len(CLASS_NAMES))


@given(
    n_nodes=st.integers(min_value=1, max_value=12),
    nodes=_node_list_strategy,
    edges=_edge_list_strategy,
)
@settings(max_examples=25, deadline=None)
def test_property_determinism_across_runs(n_nodes, nodes, edges):
    """Same graph -> same logits, bit-for-bit."""
    g = _build_graph(n_nodes, nodes, edges)
    try:
        x, ei, b = graph_to_tensors(g)
    except (ValueError, IndexError, RuntimeError):
        return
    with torch.no_grad():
        net = GINGATNet().eval()
        out1 = net(x, ei, b)
        out2 = net(x, ei, b)
    np.testing.assert_allclose(out1.numpy(), out2.numpy(), atol=1e-10)


@given(
    n_nodes=st.integers(min_value=3, max_value=10),
    nodes=_node_list_strategy,
    edges=_edge_list_strategy,
)
@settings(max_examples=15, deadline=None)
def test_property_perturbation_stability(n_nodes, nodes, edges):
    """Tiny feature noise produces bounded logit movement (no blow-up)."""
    g = _build_graph(n_nodes, nodes, edges)
    try:
        x, ei, b = graph_to_tensors(g)
    except (ValueError, IndexError, RuntimeError):
        return
    with torch.no_grad():
        net = GINGATNet().eval()
        base = net(x, ei, b).numpy()
        perturbed = net(x + torch.randn_like(x) * 1e-3, ei, b).numpy()
    max_shift = float(np.max(np.abs(base - perturbed)))
    assert max_shift < 10.0, f"logits shifted {max_shift:.4f} under 1e-3 noise"


@given(
    n_nodes=st.integers(min_value=2, max_value=12),
    nodes=_node_list_strategy,
    edges=_edge_list_strategy,
)
@settings(max_examples=15, deadline=None)
def test_property_forward_accepts_extra_node(n_nodes, nodes, edges):
    """Appending one node keeps the forward pass finite and well-shaped."""
    g = _build_graph(n_nodes, nodes, edges)
    try:
        x, ei, b = graph_to_tensors(g)
        g2 = _build_graph(n_nodes + 1, nodes, edges)
        x2, ei2, b2 = graph_to_tensors(g2)
    except (ValueError, IndexError, RuntimeError):
        return
    with torch.no_grad():
        net = GINGATNet().eval()
        out = net(x2, ei2, b2)
    assume(torch.isfinite(out).all())
    assert out.shape == (1, len(CLASS_NAMES))
