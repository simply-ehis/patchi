"""Tests for CI bundle: stable ids, baseline delta, renderer registry."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from patchi.core import ci_bundle


def _f(file="a.py", type="x", line=10, severity="high", message="m"):
    return {"file": file, "type": type, "line": line, "severity": severity, "message": message}


def test_stable_id_ignores_small_line_moves():
    assert ci_bundle.stable_id(_f(line=10)) == ci_bundle.stable_id(_f(line=12))
    assert ci_bundle.stable_id(_f(line=10)) != ci_bundle.stable_id(_f(line=20))
    assert ci_bundle.stable_id(_f(file="b.py")) != ci_bundle.stable_id(_f(file="a.py"))


def test_baseline_delta_added_and_fixed():
    base = [_f(file="a.py"), _f(file="gone.py")]
    cur = [_f(file="a.py"), _f(file="new.py")]
    d = ci_bundle.baseline_delta(base, cur)
    assert [f["file"] for f in d["added"]] == ["new.py"]
    assert [f["file"] for f in d["fixed"]] == ["gone.py"]
    assert (d["added_count"], d["fixed_count"]) == (1, 1)


def test_renderers_all_formats():
    findings = [_f(severity="critical"), _f(file="b.py", severity="low")]
    md = ci_bundle.render_findings(findings, "markdown")
    assert "a.py:10" in md and "critical" in md
    assert json.loads(ci_bundle.render_findings(findings, "json"))[0]["file"] == "a.py"
    sarif = json.loads(ci_bundle.render_findings(findings, "sarif"))
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == 2


def test_render_unknown_format_raises():
    with pytest.raises(ValueError, match="unknown findings format"):
        ci_bundle.render_findings([], "xml")


def test_register_renderer_override():
    ci_bundle.register_renderer("shout", lambda fs: "!")
    assert ci_bundle.render_findings([], "shout") == "!"
    assert ci_bundle.render_findings([], "SHOUT") == "!"  # case-insensitive
    del ci_bundle.RENDERERS["shout"]


def test_filter_since_fail_open(tmp_path: Path):
    findings = [_f()]
    # Not a git repo ref — must return input unchanged, never crash
    assert ci_bundle.filter_since(findings, "refs/nonexistent", tmp_path) == findings
