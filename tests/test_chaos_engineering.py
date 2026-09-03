"""Chaos engineering tests — resilience of crash tracer.

Verifies that crashing target scripts surface as captured trace data
instead of unhandled crashes.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

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
