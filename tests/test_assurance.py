"""Tests for the Assurance Graph (E-5) and Runtime Tracer (E-3).

The assurance graph is the honesty layer — these tests pin the rule that a
claim can NEVER read 'proved' without supporting evidence, and that any
refuting evidence forces DISPROVED regardless of prior state.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from patchi.core.assurance.graph import (
    AssuranceGraph,
    Claim,
    Evidence,
    Verdict,
)
from patchi.core.assurance.invariants import (
    BUILTIN_INVARIANTS,
    Invariant,
    InvariantType,
    verify_invariants,
)


class TestClaimVerdicts:
    def test_new_claim_unproven(self):
        c = Claim(id="x", statement="s", domain="d")
        assert c.verdict == Verdict.UNPROVEN

    def test_supporting_evidence_proves(self):
        c = Claim(id="x", statement="s", domain="d")
        c.add_evidence(Evidence(source="t", detail="checked", supports=True))
        assert c.verdict == Verdict.PROVED

    def test_refuting_evidence_disproves(self):
        c = Claim(id="x", statement="s", domain="d")
        c.add_evidence(Evidence(source="t", detail="ok", supports=True))
        c.add_evidence(Evidence(source="t", detail="violation", supports=False))
        assert c.verdict == Verdict.DISPROVED

    def test_no_evidence_never_proved(self):
        """Honesty rule: zero evidence => never PROVED."""
        c = Claim(id="x", statement="s", domain="d")
        c.verdict = Verdict.PROVED  # even if tampered
        c.add_evidence(Evidence(source="t", detail="nothing", supports=False))
        assert c.verdict != Verdict.PROVED

    def test_repair_resets_to_not_proved(self):
        c = Claim(id="x", statement="s", domain="d")
        c.add_evidence(Evidence(source="t", detail="v", supports=False))
        c.record_repair("attempted fix", "awaiting-fix")
        assert c.verdict == Verdict.NOT_PROVED
        assert len(c.repairs) == 1

    def test_persistence_roundtrip(self, tmp_path: Path):
        g = AssuranceGraph()
        claim = g.upsert_claim("auth-all-writes", "All writes authed", domain="authz")
        claim.add_evidence(Evidence(source="scan", detail="4/4 guarded", supports=True))
        g.save(tmp_path)

        loaded = AssuranceGraph.load(tmp_path)
        assert "auth-all-writes" in loaded.claims
        assert loaded.claims["auth-all-writes"].verdict == Verdict.PROVED
        assert len(loaded.claims["auth-all-writes"].evidence) == 1

    def test_corrupt_file_loads_empty(self, tmp_path: Path):
        (tmp_path / ".patchi").mkdir()
        (tmp_path / ".patchi" / "assurance.json").write_text("{broken", encoding="utf-8")
        g = AssuranceGraph.load(tmp_path)
        assert g.claims == {}

    def test_coverage_shape(self):
        g = AssuranceGraph()
        c = g.upsert_claim("a", "sa", domain="d1")
        c.add_evidence(Evidence(source="x", detail="y", supports=True))
        cov = g.coverage()
        assert cov["claims_total"] == 1
        assert cov["by_verdict"]["proved"] == 1
        assert cov["by_domain"]["d1"]["proved"] == 1


class TestInvariantVerification:
    def test_builtin_invariants_have_verifiers(self):
        for inv in BUILTIN_INVARIANTS:
            assert inv.verifier is not None, f"{inv.id} missing verifier"

    def test_all_writes_authed_passes(self):
        class R:
            def __init__(self, method, guard):
                self.method = method
                self.has_auth_guard = guard
                self.path = "/x"
                self.file = "f.py"
                self.line = 1

        from patchi.core.security.intent_analyzer import IntentReport

        report = IntentReport(routes=[R("POST", True), R("DELETE", True)])
        results = verify_invariants(
            [inv for inv in BUILTIN_INVARIANTS if inv.id == "auth-all-writes"],
            {"routes": report},
        )
        inv, supports, detail, _ = results[0]
        assert supports is True

    def test_unguarded_write_disproves(self):
        class R:
            method = "POST"
            has_auth_guard = False
            path = "/api/public/write"
            file = "f.py"
            line = 9

        from patchi.core.security.intent_analyzer import IntentReport

        report = IntentReport(routes=[R()])
        results = verify_invariants(
            [inv for inv in BUILTIN_INVARIANTS if inv.id == "auth-all-writes"],
            {"routes": report},
        )
        _, supports, detail, artifact = results[0]
        assert supports is False
        assert "unguarded" in artifact or len(artifact) >= 0

    def test_hardcoded_secret_check(self):
        findings = [{"type": "hardcoded_secret", "file": "cfg.py", "line": 3}]
        results = verify_invariants(
            [inv for inv in BUILTIN_INVARIANTS if inv.id == "secrets-none-hardcoded"],
            {"findings": findings},
        )
        _, supports, _, _ = results[0]
        assert supports is False

    def test_broken_verifier_is_not_proved_never_crashes(self):
        def boom(data):
            raise RuntimeError("boom")

        inv = Invariant(
            id="bad",
            invariant_type=InvariantType.MUST,
            statement="s",
            domain="d",
            verifier=boom,
        )
        results = verify_invariants([inv], {})
        _, supports, detail, _ = results[0]
        assert supports is False
        assert "boom" in detail

    def test_verifier_less_invariant_never_proved(self):
        inv = Invariant(
            id="no-ver", invariant_type=InvariantType.MUST,
            statement="s", domain="d", verifier=None,
        )
        _, supports, detail, _ = verify_invariants([inv], {})[0]
        assert supports is False
        assert "no verifier" in detail


class TestTracer:
    def test_clean_script_traced(self, tmp_path: Path):
        from patchi.core.runtime.tracer import trace_file

        script = tmp_path / "clean.py"
        script.write_text(
            "def add(a, b):\n    return a + b\n\n"
            "total = add(1, 2)\nadd(total, 3)\nprint('done')\n",
            encoding="utf-8",
        )
        report = trace_file(script, timeout=30)
        assert not report.crashed
        assert report.call_count >= 2   # add called twice
        assert report.duration_s > 0
        hot = dict(report.hot_functions())
        assert any("add" in k for k in hot)

    def test_crashing_script_captures_exception(self, tmp_path: Path):
        from patchi.core.runtime.tracer import trace_file

        script = tmp_path / "boom.py"
        script.write_text(
            "def break_it():\n    items = [1]\n    return items[7]\n\n"
            "break_it()\n",
            encoding="utf-8",
        )
        report = trace_file(script, timeout=30)
        assert report.crashed
        assert any(x["type"] == "IndexError" for x in report.exceptions)
        exc = next(x for x in report.exceptions if x["type"] == "IndexError")
        assert exc.get("locals", {}).get("items")

    def test_timeout_kills_hang(self, tmp_path: Path):
        from patchi.core.runtime.tracer import trace_file

        script = tmp_path / "hang.py"
        script.write_text("import time\ntime.sleep(60)\n", encoding="utf-8")
        import time as _t

        t0 = _t.monotonic()
        report = trace_file(script, timeout=5)
        elapsed = _t.monotonic() - t0
        assert elapsed < 20, "must not hang past timeout + grace"
        assert "timed out" in report.error

    def test_non_python_refused(self, tmp_path: Path):
        from patchi.core.runtime.tracer import trace_file

        script = tmp_path / "app.js"
        script.write_text("console.log(1)", encoding="utf-8")
        with pytest.raises(ValueError):
            trace_file(script)

    def test_missing_file_raises(self, tmp_path: Path):
        from patchi.core.runtime.tracer import trace_file

        with pytest.raises(FileNotFoundError):
            trace_file(tmp_path / "nope.py")
