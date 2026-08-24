"""Tests for the trust-gated GNN vulnerability classifier (E-3 Slice 2).

The honesty contract is the point of these tests:
  - missing model / bad checksum / untrained weights => ZERO findings,
    never fabricated output, and a skip reason a human can act on.
  - a properly marked + checksummed model loads and produces shaped
    findings (with random weights we assert SHAPE, not vulnerability
    truth — the weights carry no knowledge).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from patchi.core.agents.gnn_models import (
    CLASS_NAMES,
    MODEL_NAME,
    GNNVulnerabilityClassifier,
    encode_node,
    export_onnx,
    graph_to_tensors,
    verify_checksum,
    write_checksum,
)

torch_gnn = pytest.importorskip("torch", reason="torch not installed")
pytest.importorskip("torch_geometric", reason="torch_geometric not installed")
onnxruntime = pytest.importorskip("onnxruntime", reason="onnxruntime not installed")
ort = onnxruntime



def _feed(sess, x, ei, b):
    """Feed only the input names the exported session declares."""

    declared = {i.name for i in sess.get_inputs()}
    feed = {"x": x.numpy(), "edge_index": ei.numpy()}
    if "batch" in declared:
        feed["batch"] = b.numpy()
    return feed


def _tiny_graph():
    return {
        "nodes": [
            {"type": "function_definition", "line": 1, "code": "def f(u):", "function": "f"},
            {"type": "assignment", "line": 2, "code": "q = 'SELECT' + u"},
            {"type": "call", "line": 3, "code": "db.execute(q)"},
        ],
        "edges": [[0, 1], [1, 2]],
    }


@pytest.fixture()
def exported_model(tmp_path: Path) -> Path:
    """Export an UNTRAINED model into tmp; returns the model path."""
    net = __import__("patchi.core.agents.gnn_models", fromlist=["GINGATNet"]).GINGATNet()
    net.eval()
    p = tmp_path / MODEL_NAME
    export_onnx(net, p)
    write_checksum(p)
    return p


class TestGraphEncoding:
    def test_encode_node_width(self):
        assert len(encode_node({"type": "call", "line": 3})) == 128

    def test_graph_to_tensors_shapes(self):
        x, ei, batch = graph_to_tensors(_tiny_graph())
        assert x is not None and x.shape == (3, 128)
        assert ei.shape[0] == 2 and ei.shape[1] == 2
        assert batch.shape[0] == 3

    def test_edge_string_ids_skipped_not_crash(self):
        g = {"nodes": [{"type": "a"}] * 3, "edges": [["zero", "one"]]}
        _, ei, _ = graph_to_tensors(g)
        assert ei.shape[1] == 0  # non-int edge dropped

    def test_out_of_range_edges_dropped(self):
        g = {"nodes": [{"type": "a"}] * 2, "edges": [[0, 99]]}
        _, ei, _ = graph_to_tensors(g)
        assert ei.shape[1] == 0


class TestTrustGate:
    def test_missing_model_never_available(self, tmp_path: Path):
        clf = GNNVulnerabilityClassifier(model_path=tmp_path / "nope.onnx")
        assert not clf.available
        assert "not found" in clf.skip_reason()
        assert clf.detect_vulnerabilities(_tiny_graph()) == []

    def test_untrained_model_refuses_findings(self, tmp_path: Path, exported_model: Path):
        """THE honesty test: random weights must not fabricate vulnerabilities."""
        clf = GNNVulnerabilityClassifier(model_path=exported_model)
        assert not clf.available
        assert "UNTRAINED" in clf.skip_reason()
        # Even direct calls return nothing.
        assert clf.detect_vulnerabilities(_tiny_graph()) == []

    def test_allow_untrained_smoke_tags_low_confidence(self, tmp_path: Path, exported_model: Path):
        clf = GNNVulnerabilityClassifier(model_path=exported_model, allow_untrained=True)
        assert clf.available
        results = clf.detect_vulnerabilities(_tiny_graph())
        for r in results:
            assert r["severity"] in ("info", "low")  # capped, never critical
            assert r["confidence"] <= 1.0

    def test_checksum_mismatch_blocks(self, tmp_path: Path, exported_model: Path):
        # Tamper with the model after checksumming
        data = bytearray(exported_model.read_bytes())
        data[-1] ^= 0xFF
        exported_model.write_bytes(bytes(data))
        ok, msg = verify_checksum(exported_model)
        assert not ok
        clf = GNNVulnerabilityClassifier(model_path=exported_model)
        assert not clf.available
        assert "integrity" in clf.skip_reason().lower()

    def test_trained_marker_enables_trust(self, tmp_path: Path, exported_model: Path):
        marker = exported_model.with_suffix(".trained")
        marker.write_text("", encoding="utf-8")
        clf = GNNVulnerabilityClassifier(model_path=exported_model)
        assert clf.available
        assert clf.trusted


class TestOnnxRoundtrip:
    def test_export_produces_valid_session(self, tmp_path: Path, exported_model: Path):
        sess = ort.InferenceSession(str(exported_model))
        input_names = {i.name for i in sess.get_inputs()}
        assert {"x", "edge_index"} <= input_names
        # batch is optional: constant folding prunes it when the forward only
        # uses it for a single-graph branch (documented limitation).

    def test_onnx_matches_torch_forward(self, tmp_path: Path, exported_model: Path):
        """ONNX output must numerically match the PyTorch forward pass."""
        import numpy as np
        import torch

        from patchi.core.agents.gnn_models import GINGATNet

        net = GINGATNet().eval()
        # Re-export from THIS net so weights match
        p = tmp_path / "same_weights.onnx"
        export_onnx(net, p)

        x, ei, b = graph_to_tensors(_tiny_graph())
        with torch.no_grad():
            expected = net(x, ei, b).numpy()

        sess = ort.InferenceSession(str(p))
        got = sess.run(["logits"], _feed(sess, x, ei, b))[0]
        assert np.allclose(expected, got, atol=1e-3), (
            "ONNX graph must reproduce PyTorch forward exactly"
        )

    def test_dynamic_node_count(self, tmp_path: Path, exported_model: Path):
        """A model exported at N=10 must accept a different node count."""
        import onnxruntime as ort

        from patchi.core.agents.gnn_models import graph_to_tensors

        big = {
            "nodes": [{"type": f"t{i}", "line": i, "code": f"x{i}"} for i in range(25)],
            "edges": [[i, i + 1] for i in range(24)],
        }
        x, ei, b = graph_to_tensors(big)
        sess = ort.InferenceSession(str(exported_model))
        got = sess.run(["logits"], _feed(sess, x, ei, b))
        assert got[0].shape[1] >= 30

    def test_class_catalog_shape(self):
        assert len(CLASS_NAMES) >= 30
        assert CLASS_NAMES[0] == "safe"
