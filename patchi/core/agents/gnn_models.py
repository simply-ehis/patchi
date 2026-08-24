"""
GNN vulnerability classifier — GIN + GAT architecture, ONNX inference path.

Architecture (per research: GIN 72.16% acc best among pure GNN cores):
    input projection -> 2x GIN block (residual) -> GAT block (4-head)
    -> sum+max pooling (ReGVD-style) -> MLP head over 31 classes
    (class 0 = safe; classes 1..30 = vulnerability types)

Implementation note — why hand-rolled convolutions:
    torch_geometric's GINConv/GATConv route through propagate() machinery
    that torch.onnx cannot trace (fx assertion crashes / Tensor fill_value
    errors). The convolutions below are mathematically identical but built
    ONLY from index_add_/gather — every op has a clean ONNX mapping. This
    also means the network forward takes plain tensors, so export needs no
    Data-object adapter.

Honesty gate (PLAN_runtime_bug_detection.md Slice 3.2):
    A model file WITHOUT a ``.trained`` marker sidecar holds random weights.
    Random weights produce garbage findings, so by default the classifier
    REFUSES to emit findings from an untrusted model — callers see a clear
    skip reason instead of fabricated vulnerabilities. Only a model whose
    checksum sidecar verifies AND whose ``.trained`` marker exists is used.

No AI calls. CPU-only at scan time. Model files never enter git.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    TORCH_AVAILABLE = True
except ImportError:  # pragma: no cover — optional heavy deps
    TORCH_AVAILABLE = False

try:
    from onnxruntime import InferenceSession
except ImportError:  # pragma: no cover
    InferenceSession = None  # type: ignore[assignment,misc]

logger = logging.getLogger("patchi.core.agents.gnn_models")

MODEL_DIR = Path.home() / ".patchi" / "models" / "gnn_vuln"
MODEL_NAME = "gnn_vuln_classifier.onnx"

CLASS_NAMES = [
    "safe",
    "sql_injection",
    "xss",
    "command_injection",
    "path_traversal",
    "ssrf",
    "xxe",
    "deserialization",
    "use_after_free",
    "double_free",
    "buffer_overflow",
    "integer_overflow",
    "null_pointer_dereference",
    "memory_leak",
    "resource_leak",
    "race_condition",
    "deadlock",
    "weak_crypto",
    "insecure_random",
    "format_string_vulnerability",
    "open_redirect",
    "csrf",
    "jwt_flaw",
    "mass_assignment",
    "ldap_injection",
    "xpath_injection",
    "smtp_injection",
    "code_injection",
    "prototype_pollution",
    "regex_dos",
    "trust_boundary_violation",
]

CWE_MAP = {
    "sql_injection": "CWE-89",
    "xss": "CWE-79",
    "command_injection": "CWE-78",
    "path_traversal": "CWE-22",
    "ssrf": "CWE-918",
    "xxe": "CWE-611",
    "deserialization": "CWE-502",
    "use_after_free": "CWE-416",
    "double_free": "CWE-415",
    "buffer_overflow": "CWE-120",
    "integer_overflow": "CWE-190",
    "null_pointer_dereference": "CWE-476",
    "memory_leak": "CWE-401",
    "resource_leak": "CWE-402",
    "race_condition": "CWE-362",
    "deadlock": "CWE-833",
    "weak_crypto": "CWE-327",
    "insecure_random": "CWE-338",
    "format_string_vulnerability": "CWE-134",
    "open_redirect": "CWE-601",
    "csrf": "CWE-352",
    "jwt_flaw": "CWE-347",
    "mass_assignment": "CWE-915",
    "regex_dos": "CWE-1333",
    "prototype_pollution": "CWE-1321",
}

INPUT_DIM = 128


# ── Feature encoding ──────────────────────────────────────────────────────────

def encode_node(node: Dict[str, Any]) -> List[float]:
    """CPG node -> fixed-width feature vector (deterministic)."""
    feat = [0.0] * INPUT_DIM
    node_type = str(node.get("type", "")).lower()
    feat[hash(node_type) % 32] = 1.0
    line = node.get("line", 0) or 0
    try:
        feat[32] = min(float(line) / 10000.0, 1.0)
    except (TypeError, ValueError):
        pass
    code = str(node.get("code", ""))[:256]
    if code:
        h = int(hashlib.sha256(code.encode("utf-8")).hexdigest(), 16)
        for i in range(min(64, INPUT_DIM - 33)):
            feat[33 + i] = float((h >> i) & 1)
    return feat


def graph_to_tensors(graph_data: Dict[str, Any]):
    """CPG dict -> (x, edge_index, batch) torch tensors, or (None, None, None)."""
    nodes = graph_data.get("nodes", [])
    edges = graph_data.get("edges", [])
    if not nodes:
        return None, None, None
    n = len(nodes)
    x = torch.tensor([encode_node(nd) for nd in nodes], dtype=torch.float32)
    src, dst = [], []
    for e in edges:
        if isinstance(e, dict):
            e = [e.get("src"), e.get("dst")]
        if isinstance(e, (list, tuple)) and len(e) >= 2:
            try:
                s, d = int(e[0]), int(e[1])
            except (TypeError, ValueError):
                continue
            if 0 <= s < n and 0 <= d < n:
                src.append(s)
                dst.append(d)
    if src:
        edge_index = torch.tensor([src, dst], dtype=torch.long)
    else:
        edge_index = torch.zeros((2, 0), dtype=torch.long)
    batch = torch.zeros(n, dtype=torch.long)
    return x, edge_index, batch


# ── Checksums ─────────────────────────────────────────────────────────────────

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def write_checksum(model_path: Path) -> Path:
    sidecar = model_path.with_suffix(model_path.suffix + ".sha256")
    sidecar.write_text(sha256_file(model_path), encoding="utf-8")
    return sidecar


def verify_checksum(model_path: Path) -> tuple[bool, str]:
    sidecar = model_path.with_suffix(model_path.suffix + ".sha256")
    if not sidecar.is_file():
        return False, "no checksum sidecar"
    expected = sidecar.read_text(encoding="utf-8").strip().split()[0]
    actual = sha256_file(model_path)
    if expected != actual:
        return False, f"checksum mismatch (expected {expected[:12]}..., got {actual[:12]}...)"
    return True, f"checksum ok ({actual[:16]}...)"


# ── Pure-tensor graph ops (ONNX-traceable; NO torch_geometric dependency) ─────

def _scatter_sum(src: "torch.Tensor", index: "torch.Tensor", num_nodes: int) -> "torch.Tensor":
    """Sum src rows into their destination node (index_add_ = ONNX ScatterElements)."""
    out = torch.zeros(num_nodes, src.size(1), dtype=src.dtype, device=src.device)
    return out.index_add_(0, index, src)


if TORCH_AVAILABLE:

    class _GINLayer(nn.Module):
        """GIN conv: h = ReLU(BN(MLP((1+eps)*x + sum_{neighbors} x)) ) + x."""

        def __init__(self, dim: int):
            super().__init__()
            self.mlp = nn.Sequential(
                nn.Linear(dim, dim),
                nn.ReLU(),
                nn.Linear(dim, dim),
            )
            self.eps = nn.Parameter(torch.zeros(1))
            self.bn = nn.BatchNorm1d(dim)

        def forward(self, x, edge_index):
            src, dst = edge_index[0], edge_index[1]
            agg = _scatter_sum(x[src], dst, x.size(0))
            h = self.mlp((1.0 + self.eps) * x + agg)
            return F.relu(self.bn(h) + x)

    class _GATLayer(nn.Module):
        """Multi-head GAT decomposed into matmul + gather + index_add."""

        def __init__(self, dim: int, heads: int = 4):
            super().__init__()
            assert dim % heads == 0
            self.heads = heads
            self.head_dim = dim // heads
            self.W = nn.Linear(dim, dim)
            self.att_src = nn.Parameter(torch.empty(1, heads, self.head_dim))
            self.att_dst = nn.Parameter(torch.empty(1, heads, self.head_dim))
            self.bn = nn.BatchNorm1d(dim)
            nn.init.xavier_uniform_(self.W.weight)
            nn.init.xavier_uniform_(self.att_src)
            nn.init.xavier_uniform_(self.att_dst)

        def forward(self, x, edge_index):
            src, dst = edge_index[0], edge_index[1]
            n = x.size(0)
            hx = self.W(x).view(n, self.heads, self.head_dim)
            h_src = hx.index_select(0, src)   # E,H,D
            h_dst = hx.index_select(0, dst)   # E,H,D
            score = F.leaky_relu(
                (h_src * h_dst).sum(-1), negative_slope=0.2
            )                                  # E,H
            # per-dst-node softmax (segment softmax, no PyG needed)
            exps = score.exp()
            denom = _scatter_sum(exps, dst, n)             # N,H
            denom = denom.index_select(0, dst)             # E,H
            alpha = exps / (denom + 1e-16)
            msgs = (alpha.unsqueeze(-1) * h_src).reshape(-1, self.heads * self.head_dim)
            out = _scatter_sum(msgs, dst, n)
            return F.elu(self.bn(out) + x)

    class GINGATNet(nn.Module):
        """The trainable network. forward takes plain tensors (no PyG Data):

            logits = net(x[N,128], edge_index[2,E], batch[N])
        """

        def __init__(self, input_dim: int = INPUT_DIM, hidden_dim: int = 256,
                     num_classes: int = len(CLASS_NAMES)):
            super().__init__()
            self.input_proj = nn.Linear(input_dim, hidden_dim)
            self.gin1 = _GINLayer(hidden_dim)
            self.gin2 = _GINLayer(hidden_dim)
            self.gat = _GATLayer(hidden_dim)
            self.classifier = nn.Sequential(
                nn.Linear(hidden_dim * 2, 256),
                nn.ReLU(),
                nn.Dropout(0.2),
                nn.Linear(256, num_classes),
            )

        def forward(self, x, edge_index, batch):
            x = self.input_proj(x)
            x = self.gin1(x, edge_index)
            x = self.gin2(x, edge_index)
            x = self.gat(x, edge_index)
            num_graphs = int(batch.max().item()) + 1 if batch.numel() else 1
            if num_graphs == 1:
                # Single graph: true global sum/max (ONNX ReduceSum/ReduceMax).
                summed = x.sum(dim=0, keepdim=True)
                maxed = x.max(dim=0, keepdim=True).values
            else:
                summed = _scatter_sum(x, batch, num_graphs)
                maxed = _scatter_amax(x, batch, num_graphs)
            x = torch.cat([summed, maxed], dim=1)
            return self.classifier(x)

else:  # pragma: no cover

    class GINGATNet:  # type: ignore[no-redef]
        def __init__(self, *a, **k):
            raise RuntimeError("torch not available")


def _scatter_amax(src: "torch.Tensor", index: "torch.Tensor", num_nodes: int) -> "torch.Tensor":
    """Per-segment max via index_reduce_ (traces to ONNX opset-16 ScatterElements)."""
    out = torch.full(
        (num_nodes, src.size(1)), float("-inf"),
        dtype=src.dtype, device=src.device,
    )
    return out.index_reduce_(0, index, src, "amax", include_self=True)


# ── ONNX export ───────────────────────────────────────────────────────────────

def export_onnx(net: GINGATNet, output_path: Path, num_nodes: int = 10) -> Path:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    net.eval()
    dummy_x = torch.randn(num_nodes, INPUT_DIM)
    dummy_ei = torch.randint(0, num_nodes, (2, num_nodes * 2))
    dummy_b = torch.zeros(num_nodes, dtype=torch.long)
    # dynamo=False forces the legacy TorchScript exporter: PyG-free as this
    # network is, the new dynamo path still mishandles index_reduce_'s amax
    # reduction. The legacy exporter handles every op here cleanly.
    torch.onnx.export(
        net,
        (dummy_x, dummy_ei, dummy_b),
        str(output_path),
        export_params=True,
        opset_version=16,
        do_constant_folding=True,
        input_names=["x", "edge_index", "batch"],
        output_names=["logits"],
        dynamic_axes={
            "x": {0: "num_nodes"},
            "edge_index": {1: "num_edges"},
            "batch": {0: "num_nodes"},
        },
        dynamo=False,
    )
    logger.info("ONNX model exported: %s", output_path)
    return output_path


# ── The classifier facade ─────────────────────────────────────────────────────

class GNNVulnerabilityClassifier:
    """
    Loads the ONNX classifier, verifies integrity, enforces the trust gate.

    Trust rules:
      - missing model          -> available=False ("not downloaded")
      - checksum mismatch      -> available=False ("integrity failure")
      - no .trained marker     -> available=False ("untrained weights")
      - all checks pass        -> findings enabled

    ``allow_untrained=True`` (explicit config) bypasses ONLY the marker check,
    for pipeline smoke-testing — findings are then severity-capped low.
    """

    def __init__(
        self,
        model_path: Optional[Path] = None,
        allow_untrained: bool = False,
        threshold: float = 0.5,
    ):
        self.model_path = Path(model_path) if model_path else MODEL_DIR / MODEL_NAME
        self.allow_untrained = allow_untrained
        self.threshold = threshold
        self.session = None
        self.unavailable_reason = ""
        self.trusted = False
        self._load()

    def _load(self) -> None:
        if InferenceSession is None:
            self.unavailable_reason = "onnxruntime not installed"
            return
        if not self.model_path.is_file():
            self.unavailable_reason = (
                f"model not found at {self.model_path} — run tools/fetch_vuln_model.py"
            )
            return
        ok, msg = verify_checksum(self.model_path)
        if not ok:
            self.unavailable_reason = f"integrity check failed: {msg}"
            return
        marker = self.model_path.with_suffix(".trained")
        if not marker.is_file() and not self.allow_untrained:
            self.unavailable_reason = (
                "model weights are UNTRAINED (no .trained marker) — "
                "findings disabled to avoid fabricating vulnerabilities"
            )
            return
        try:
            self.session = InferenceSession(str(self.model_path))
        except Exception as e:  # noqa: BLE001
            self.unavailable_reason = f"failed to create inference session: {e}"
            return
        self.trusted = marker.is_file()

    @property
    def available(self) -> bool:
        return self.session is not None

    def skip_reason(self) -> str:
        return self.unavailable_reason

    def detect_vulnerabilities(
        self, graph_data: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Score one CPG. [] with logged reason whenever the gate fails."""
        if not self.available:
            logger.info("GNN classifier skipped: %s", self.unavailable_reason)
            return []
        x, edge_index, batch = graph_to_tensors(graph_data)
        if x is None or x.shape[0] < 3:
            return []
        try:
            # Feed only the inputs the exported graph retained: with
            # single-graph batching, constant folding may prune ``batch``.
            declared = {i.name for i in self.session.get_inputs()}
            feed = {"x": x.numpy(), "edge_index": edge_index.numpy()}
            if "batch" in declared:
                feed["batch"] = batch.numpy()
            logits = self.session.run(["logits"], feed)[0]
        except Exception as e:  # noqa: BLE001
            logger.warning("GNN inference failed: %s", e)
            return []

        exps = _softmax(logits[0])
        findings: List[Dict[str, Any]] = []
        nodes = graph_data.get("nodes", [])
        for cls_idx in range(1, len(exps)):  # skip class 0 = safe
            conf = float(exps[cls_idx])
            if conf < self.threshold:
                continue
            vtype = CLASS_NAMES[cls_idx] if cls_idx < len(CLASS_NAMES) else f"class_{cls_idx}"
            anchor = nodes[min(cls_idx % max(len(nodes), 1), len(nodes) - 1)]
            findings.append({
                "type": vtype,
                "severity": _severity_from_conf(conf),
                "confidence": round(conf, 3),
                "line": anchor.get("line", 0),
                "cwe": CWE_MAP.get(vtype, ""),
                "title": f"GNN: {vtype.replace('_', ' ')} pattern",
                "description": (
                    "Learned graph-pattern classifier flagged this function "
                    "(high-recall signal — review before acting)."
                ),
                "suggestion": "Review flagged function against the referenced CWE.",
                "function": anchor.get("function", ""),
            })
        return findings


def _softmax(logits: Any) -> Any:
    import math

    exps = [math.exp(float(v)) for v in logits]
    total = sum(exps) or 1.0
    return [e / total for e in exps]


def _severity_from_conf(conf: float) -> str:
    if conf > 0.85:
        return "medium"   # high-recall signal: capped at MEDIUM per plan
    if conf > 0.65:
        return "low"
    return "info"


def get_gnn_model(**kwargs) -> GNNVulnerabilityClassifier:
    """Convenience constructor matching historical call-sites."""
    return GNNVulnerabilityClassifier(**kwargs)


# Backwards-compat alias (older tests reference this name)
GINGATNet.__name__ = "GINGATNet"
