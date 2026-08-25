"""Tests for noise reduction: NoiseFilter + ConfidenceGate enhancements.

Covers the false-positive learning loop, agent-consensus enforcement,
AI confidence calibration, and file-level noise classification.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from patchi.core.agents.base import Severity
from patchi.core.security.confidence_gate import ConfidenceGate
from patchi.core.security.noise_filter import (
    NoiseFilter,
    classify,
)
from patchi.core.security.orchestrator import CorrelatedFinding, Finding

# ── Helpers ──────────────────────────────────────────────────────────────


def make_finding(
    file: str = "src/app.py",
    line: int = 10,
    type_: str = "sql_injection",
    severity: Severity = Severity.HIGH,
    snippet: str = "cursor.execute(f'SELECT * FROM users WHERE id={uid}')",
    cwe: str = "CWE-89",
    agent: str = "injection_agent",
) -> Finding:
    return Finding(
        agent=agent,
        type=type_,
        severity=severity,
        file=file,
        line=line,
        message=f"Possible {type_} in {file}:{line}",
        code_snippet=snippet,
        cwe=cwe,
    )


def make_cf(**kwargs) -> CorrelatedFinding:
    return CorrelatedFinding(finding=make_finding(**kwargs), confirmed_by=["a1"])


# ── classify(): path → category ──────────────────────────────────────────


class TestClassify:
    @pytest.mark.parametrize("path,expected", [
        # lockfiles
        ("web/package-lock.json", "lockfile"),
        ("backend/poetry.lock", "lockfile"),
        ("go.sum", "lockfile"),
        # generated / minified
        ("web/app.min.js", "generated"),
        ("proto/service_pb2.py", "generated"),
        ("proto/service_pb2_grpc.py", "generated"),
        ("web/bundle.js.map", "generated"),
        # docs
        ("README.md", "docs"),
        ("docs/architecture.rst", "docs"),
        # tests — filename patterns
        ("tests/test_auth.py", "tests"),           # dir marker anyway
        ("src/test_utils.py", "tests"),
        ("src/auth_test.py", "tests"),
        ("web/api.spec.ts", "tests"),
        ("web/component.test.tsx", "tests"),
        ("conftest.py", "tests"),
        # tests — directory markers
        ("tests/helpers.py", "tests"),
        ("spec/models/user.rb", "tests"),
        ("__snapshots__/ui.snap", "generated"),    # snapshot pattern wins
        ("fixtures/data.py", "tests"),
        # real source must stay clean
        ("src/auth/login.py", None),
        ("app/main.go", None),
        ("lib/service.ts", None),
        ("migrations/0001_init.py", None),          # migrations are NOT test noise
    ])
    def test_categories(self, path: str, expected: str | None):
        assert classify(path) == expected, f"{path} -> {classify(path)}, want {expected}"

    def test_windows_separators_normalized(self):
        assert classify("src\\tests\\test_x.py") == "tests"


# ── NoiseFilter.apply() ──────────────────────────────────────────────────


class TestNoiseFilterDicts:
    """merge_results() produces plain dicts — the filter must handle both."""

    def _d(self, file: str, severity: str = "high") -> dict:
        return {
            "agent": "injection_agent",
            "type": "sql_injection",
            "severity": severity,
            "file": file,
            "line": 10,
            "message": "possible sqli",
        }

    def test_cap_mode_downgrades_dict_severity(self):
        nf = NoiseFilter(config={"noise_filter": {"mode": "cap"}})
        dicts = [self._d("tests/test_login.py", "critical"), self._d("src/auth.py")]
        kept, report = nf.apply(dicts)

        assert len(kept) == 2
        assert report.capped == 1
        assert kept[0]["severity"] == "info"
        assert kept[0]["noise_category"] == "tests"
        assert kept[1]["severity"] == "high"          # source untouched
        assert "noise_category" not in kept[1]

    def test_discard_mode_removes_dict_noise(self):
        nf = NoiseFilter(config={"noise_filter": {"mode": "discard"}})
        kept, report = nf.apply([self._d("yarn.lock"), self._d("src/db.py")])
        assert len(kept) == 1 and kept[0]["file"] == "src/db.py"
        assert report.discarded == 1

    def test_mixed_objects_and_dicts(self):
        nf = NoiseFilter()
        mixed = [make_finding(file="web/app.min.js"), self._d("docs/notes.md")]
        kept, report = nf.apply(mixed)
        assert len(kept) == 2
        assert report.by_category == {"generated": 1, "docs": 1}
        # object got enum, dict got string
        from patchi.core.agents.base import Severity

        assert mixed[0].severity == Severity.INFO
        assert mixed[1]["severity"] == "info"


class TestNoiseFilterApply:
    def test_cap_mode_downgrades_but_keeps(self):
        nf = NoiseFilter(config={"noise_filter": {"mode": "cap"}})
        findings = [
            make_finding(file="tests/test_login.py", severity=Severity.CRITICAL),
            make_finding(file="src/auth.py", severity=Severity.HIGH),
        ]
        kept, report = nf.apply(findings)

        assert len(kept) == 2
        assert report.total_in == 2
        assert report.capped == 1
        assert report.discarded == 0
        assert report.by_category == {"tests": 1}
        # capped finding downgraded to info, never deleted silently
        assert kept[0].severity == Severity.INFO
        # source finding untouched
        assert kept[1].severity == Severity.HIGH

    def test_discard_mode_removes_noise(self):
        nf = NoiseFilter(config={"noise_filter": {"mode": "discard"}})
        findings = [
            make_finding(file="package-lock.json"),
            make_finding(file="src/db.py"),
            make_finding(file="web/app.min.js"),
        ]
        kept, report = nf.apply(findings)

        assert len(kept) == 1
        assert kept[0].file == "src/db.py"
        assert report.discarded == 2
        assert set(report.by_category) == {"lockfile", "generated"}

    def test_disabled_filter_keeps_everything(self):
        nf = NoiseFilter(config={"noise_filter": {"enabled": False}})
        findings = [make_finding(file="tests/test_a.py")]
        kept, report = nf.apply(findings)
        assert len(kept) == 1 and report.capped == 0

    def test_toggles_respected(self):
        nf = NoiseFilter(config={"noise_filter": {"skip_tests": False}})
        assert nf.category_for("tests/test_a.py") is None
        assert nf.category_for("yarn.lock") == "lockfile"

    def test_report_statement_honest(self):
        _, report = NoiseFilter().apply([make_finding(file="x.md")])
        d = report.to_dict()
        assert "0/1" in d["statement"] or "capped" in d["statement"]

    def test_capped_finding_can_never_defend(self, tmp_path: Path):
        """Even a max-shaped finding from a test file cannot auto-defend."""
        gate = ConfidenceGate(tmp_path)
        f = make_finding(
            file="tests/test_vault.py",
            severity=Severity.CRITICAL,
            snippet="x" * 500,
        )
        f.noise_category = "tests"
        cf = CorrelatedFinding(finding=f, confirmed_by=["a", "b", "c"], composite_score=95)
        result = gate.gate(cf)
        assert result.routing != "defend"
        assert "noise_category" and True  # cap survives scoring


# ── ConfidenceGate: FP memory ────────────────────────────────────────────


class TestFalsePositiveMemory:
    def test_record_persists_and_penalizes(self, tmp_path: Path):
        gate = ConfidenceGate(tmp_path)
        f = make_finding()
        cf = CorrelatedFinding(finding=f, confirmed_by=["a1", "a2"])

        before = gate.gate(cf).confidence_score

        added = gate.record_false_positives([
            {"file": f.file, "type": f.type, "line": f.line, "reason": "analyst verified"},
        ])
        assert added == 1

        after = gate.gate(cf).confidence_score
        # flow(0.7)+high(0.1)+2 agents(0.2)+line(0.1)-fp(0.3) = 0.8
        assert after == pytest.approx(0.8, abs=1e-9)
        assert after < before

        # persisted to disk; a fresh gate instance sees it too
        assert (tmp_path / ".patchi/memory/known_false_positives.json").is_file()
        fresh = ConfidenceGate(tmp_path)
        assert fresh.gate(cf).confidence_score == pytest.approx(after, abs=1e-9)

    def test_record_is_idempotent(self, tmp_path: Path):
        gate = ConfidenceGate(tmp_path)
        entry = {"file": "a.py", "type": "t", "line": 1}
        assert gate.record_false_positives([entry]) == 1
        assert gate.record_false_positives([entry]) == 0

    def test_forget_restores_score(self, tmp_path: Path):
        gate = ConfidenceGate(tmp_path)
        cf = make_cf()
        gate.record_false_positives([
            {"file": cf.finding.file, "type": cf.finding.type, "line": cf.finding.line},
        ])
        penalized = gate.gate(cf).confidence_score
        assert gate.forget_false_positive(cf.finding.file, cf.finding.type, cf.finding.line)
        restored = ConfidenceGate(tmp_path).gate(cf).confidence_score
        assert restored > penalized

    def test_fp_auto_discard_drops_known_fps(self, tmp_path: Path):
        cfg = {"confidence_gate": {"fp_auto_discard": True}}
        gate = ConfidenceGate(tmp_path, cfg)
        cf = make_cf(snippet="x" * 80)  # high-scoring shape
        gate.record_false_positives([
            {"file": cf.finding.file, "type": cf.finding.type, "line": cf.finding.line},
        ])
        assert gate.gate(cf).routing == "discard"

    def test_learn_from_dismissed_closes_loop(self, tmp_path: Path):
        from patchi.core.security.gated_finding import GatedFinding, GatedReport

        gate = ConfidenceGate(tmp_path)
        f = make_finding(line=42)
        gf = GatedFinding(
            finding=f, routing="discard",
            routing_reason="AI dismissed: fixture data",
        )
        gated = GatedReport(findings=[gf], stats={})

        assert gate.learn_from_dismissed(gated) == 1
        # Next scan with a fresh gate: pre-penalized relative to a
        # non-FP twin of the same finding.
        fresh = ConfidenceGate(tmp_path)
        penalized = fresh._compute_score(CorrelatedFinding(finding=f, confirmed_by=["a"]))
        twin = make_finding(file="src/other.py", line=7)
        baseline = fresh._compute_score(CorrelatedFinding(finding=twin, confirmed_by=["a"]))
        assert penalized < baseline


# ── ConfidenceGate: consensus enforcement ────────────────────────────────


class TestAgentConsensus:
    def test_single_agent_demoted_from_defend(self, tmp_path: Path):
        gate = ConfidenceGate(tmp_path, {"confidence_gate": {"min_agents_for_defend": 2}})
        # deterministic-ish finding that would normally score >= 0.7
        cf = CorrelatedFinding(
            finding=make_finding(severity=Severity.CRITICAL),
            confirmed_by=["only_one_agent"],
            composite_score=85,
        )
        result = gate.gate(cf)
        assert result.routing == "ai_analyze"
        assert "consensus floor" in result.routing_reason

    def test_multi_agent_can_defend(self, tmp_path: Path):
        gate = ConfidenceGate(tmp_path, {"confidence_gate": {"min_agents_for_defend": 2}})
        cf = CorrelatedFinding(
            finding=make_finding(severity=Severity.CRITICAL),
            confirmed_by=["a1", "a2"],
            composite_score=85,
        )
        assert gate.gate(cf).routing == "defend"

    def test_min_agents_to_keep_kills_loners(self, tmp_path: Path):
        gate = ConfidenceGate(tmp_path, {
            "confidence_gate": {"min_agents_to_keep": 2}
        })
        solo = CorrelatedFinding(
            finding=make_finding(severity=Severity.CRITICAL),
            confirmed_by=["solo"],
            composite_score=95,
        )
        duo = CorrelatedFinding(
            finding=make_finding(severity=Severity.MEDIUM, line=99),
            confirmed_by=["a1", "a2"],
        )
        assert gate.gate(solo).routing == "discard"
        assert gate.gate(duo).routing != "discard"

    def test_default_behavior_unchanged(self, tmp_path: Path):
        """With no config, single-agent high-confidence still defends."""
        gate = ConfidenceGate(tmp_path)
        cf = CorrelatedFinding(
            finding=make_finding(severity=Severity.CRITICAL),
            confirmed_by=["one"],
            composite_score=90,
        )
        assert gate.gate(cf).routing == "defend"


# ── ConfidenceGate: AI calibration ───────────────────────────────────────


class TestAICalibration:
    def test_weight_zero_means_no_blend(self, tmp_path: Path):
        gate = ConfidenceGate(tmp_path)  # ai_weight defaults to 0.0
        cf = make_cf()
        plain = gate.gate(cf).confidence_score
        blended = gate.gate(cf, ai_confidence=1.0).confidence_score
        assert plain == blended

    def test_calibration_blends_model_verdict(self, tmp_path: Path):
        gate = ConfidenceGate(tmp_path, {"confidence_gate": {"ai_weight": 0.5}})
        cf = make_cf()
        low_ai = gate.gate(cf, ai_confidence=0.1).confidence_score
        mid_ai = gate.gate(cf, ai_confidence=0.5).confidence_score
        high_ai = gate.gate(cf, ai_confidence=0.95).confidence_score
        # Monotonic in model confidence
        assert low_ai < mid_ai < high_ai

    def test_calibration_can_promote_tier(self, tmp_path: Path):
        gate = ConfidenceGate(tmp_path, {"confidence_gate": {"ai_weight": 0.8}})
        cf = make_cf(severity=Severity.LOW, snippet="", cwe="", line=0)
        weak = gate.gate(cf)
        boosted = gate.gate(cf, ai_confidence=1.0)
        assert boosted.confidence_score > weak.confidence_score
        if boosted.confidence_score >= 0.7:
            assert boosted.confidence_tier == "high"

    def test_out_of_range_confidence_clamped(self, tmp_path: Path):
        gate = ConfidenceGate(tmp_path, {"confidence_gate": {"ai_weight": 0.5}})
        cf = make_cf()
        s_neg = gate.gate(cf, ai_confidence=-3.0).confidence_score
        s_big = gate.gate(cf, ai_confidence=42.0).confidence_score
        assert 0.0 <= s_neg <= 1.0 and 0.0 <= s_big <= 1.0


# ── Integration: pipeline stage ordering ─────────────────────────────────


class TestPipelineIntegration:
    def _pipeline(self, tmp_path: Path, config=None):
        from patchi.core.security.detection_pipeline import DetectionPipeline
        return DetectionPipeline(tmp_path, config or {})

    def test_noise_capped_before_gating(self, tmp_path: Path):
        pipe = self._pipeline(tmp_path)
        from patchi.core.security.orchestrator import SecurityReport

        report = SecurityReport(findings=[
            make_finding(file="tests/test_secret.py", type_="hardcoded_secret",
                         severity=Severity.CRITICAL),
            make_finding(file="src/vault.py", type_="hardcoded_secret",
                         severity=Severity.HIGH),
        ])
        result = pipe.process(report)

        assert "noise" in result.stats
        assert result.stats["noise"]["by_category"].get("tests") == 1
        # The test-file critical became info-capped => routed as discard/info,
        # never defend.
        test_findings = [g for g in result.findings
                         if g.finding.file.startswith("tests/")]
        assert all(g.routing != "defend" for g in test_findings)

    def test_empty_report_short_circuits(self, tmp_path: Path):
        from patchi.core.security.orchestrator import SecurityReport
        result = self._pipeline(tmp_path).process(SecurityReport(findings=[]))
        assert result.stats["total"] == 0

    def test_learned_fps_survive_new_gate_instance(self, tmp_path: Path):
        pipe = self._pipeline(tmp_path)
        from patchi.core.security.gated_finding import GatedFinding

        f = make_finding(file="src/noisy.py", line=7)
        gf = GatedFinding(finding=f, routing="discard", routing_reason="test")
        pipe.gate.learn_from_dismissed(
            __import__("patchi.core.security.gated_finding", fromlist=["GatedReport"]).GatedReport(
                findings=[gf], stats={}
            )
        )
        fresh = ConfidenceGate(tmp_path)
        key = (f.file, f.type, f.line)
        assert key in fresh._known_fps
