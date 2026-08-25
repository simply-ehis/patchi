"""Chaos engineering tests — resilience of trust gate and crash tracer.

Verifies that infrastructure failures (corrupt models, missing files,
crashing target scripts) surface as honest skip reasons or captured
trace data instead of unhandled crashes.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

torch = pytest.importorskip("torch", reason="torch not installed")
ort = pytest.importorskip("onnxruntime", reason="onnxruntime not installed")

from patchi.core.agents.gnn_models import (  # noqa: E402
    MODEL_NAME,
    GINGATNet,
    export_onnx,
    write_checksum,
)
from patchi.core.runtime.tracer import TraceReport, trace_file  # noqa: E402

# ── TraceReport invariants ───────────────────────────────────────────────


def test_trace_report_crashed_property():
    assert TraceReport(exit_code=1, exceptions=[]).crashed is True
    assert TraceReport(exit_code=0, exceptions=[]).crashed is False
    assert TraceReport(
        exit_code=0, exceptions=[{"type": "Err", "message": "x"}]
    ).crashed is True


def test_trace_report_hot_functions_empty():
    report = TraceReport()
    assert report.hot_functions(top_n=5) == []


# ── Trust-gate chaos: corrupt / missing models ───────────────────────────


class TestCorruptModelHandling:
    def test_garbage_model_file_blocked(self, tmp_path: Path):
        """A non-ONNX blob must yield unavailable + integrity skip, never a crash."""
        from patchi.core.agents.gnn_models import GNNVulnerabilityClassifier

        garbage = tmp_path / MODEL_NAME
        garbage.write_bytes(b"\x00\x01\x02\x03not-a-model")
        clf = GNNVulnerabilityClassifier(model_path=garbage)
        assert not clf.available
        assert clf.detect_vulnerabilities({"nodes": [], "edges": []}) == []

    def test_empty_model_file_blocked(self, tmp_path: Path):
        from patchi.core.agents.gnn_models import GNNVulnerabilityClassifier

        empty = tmp_path / MODEL_NAME
        empty.write_bytes(b"")
        clf = GNNVulnerabilityClassifier(model_path=empty)
        assert not clf.available

    def test_missing_model_reports_not_found(self, tmp_path: Path):
        from patchi.core.agents.gnn_models import GNNVulnerabilityClassifier

        clf = GNNVulnerabilityClassifier(model_path=tmp_path / "absent.onnx")
        assert not clf.available
        assert "not found" in clf.skip_reason()

    def test_allow_untrained_smoke_never_raises(self, tmp_path: Path):
        """Smoke mode on an exported-but-untrained model stays capped and quiet."""
        from patchi.core.agents.gnn_models import GNNVulnerabilityClassifier

        net = GINGATNet().eval()
        p = tmp_path / MODEL_NAME
        export_onnx(net, p)
        write_checksum(p)

        clf = GNNVulnerabilityClassifier(
            model_path=p, allow_untrained=True  # marker absent on purpose
        )
        results = clf.detect_vulnerabilities({
            "nodes": [{"type": "call", "line": 1, "code": "db.execute(q)"}],
            "edges": [],
        })
        for r in results:
            assert r["severity"] in ("info", "low")


# ── Crash tracer chaos ───────────────────────────────────────────────────


class TestCrashTracer:
    def test_safe_script_completes_clean(self, tmp_path: Path):
        script = tmp_path / "safe.py"
        script.write_text("x = 1\ny = 2\nz = x + y\n", encoding="utf-8")
        report = trace_file(str(script), timeout=10.0)
        assert report.exit_code == 0
        assert not report.crashed
        assert report.error == ""

    def test_zero_division_captured(self, tmp_path: Path):
        script = tmp_path / "boom.py"
        script.write_text("raise ValueError('kaboom')\n", encoding="utf-8")
        report = trace_file(str(script), timeout=10.0)
        assert report.crashed
        types = {e.get("type") for e in report.exceptions}
        assert "ValueError" in types

    def test_timeout_reported_as_error(self, tmp_path: Path):
        script = tmp_path / "slow.py"
        script.write_text("while True:\n    pass\n", encoding="utf-8")
        report = trace_file(str(script), timeout=3.0)
        # Timeout is captured data, never an exception out of trace_file.
        assert "timed out" in report.error.lower() or report.error != ""

    def test_missing_script_raises_filenotfound(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            trace_file(str(tmp_path / "ghost.py"))

    def test_non_python_rejected(self, tmp_path: Path):
        script = tmp_path / "notes.txt"
        script.write_text("hello", encoding="utf-8")
        with pytest.raises(ValueError):
            trace_file(str(script))

    def test_call_budget_enforced(self, tmp_path: Path):
        script = tmp_path / "loopy.py"
        script.write_text(
            "\n".join(
                ["def f(i):", "    return i + 1", "", "for i in range(100000):", "    f(i)"]
            ),
            encoding="utf-8",
        )
        report = trace_file(str(script), timeout=15.0, max_calls=500)
        assert report.call_count <= 500
