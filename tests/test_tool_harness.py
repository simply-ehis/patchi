"""Tests for tool adapters + upgraded Layer2 AI arbiter."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from patchi.core.agents.base import Severity
from patchi.core.security.tool_adapters import (
    make_tool_finding,
    normalize_severity,
    tool_confidence,
)

# ── Severity normalization ───────────────────────────────────────────────


class TestNormalizeSeverity:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            # bandit uppercase
            ("HIGH", "high"),
            ("MEDIUM", "medium"),
            ("LOW", "low"),
            # lowercase passthrough
            ("high", "high"),
            ("critical", "critical"),
            ("info", "info"),
            # compiler-style
            ("ERROR", "high"),
            ("WARNING", "medium"),
            ("NOTE", "info"),
            # SARIF numeric security-severity
            (9.5, "critical"),
            (7.2, "high"),
            (8.8, "high"),
            (4.0, "medium"),
            (1.1, "low"),
            # garbage -> default medium
            ("", "medium"),
            (None, "medium"),
            ("weird", "medium"),
        ],
    )
    def test_matrix(self, raw, expected):
        assert normalize_severity(raw).value == expected


class TestToolConfidence:
    def test_tiers(self):
        assert tool_confidence("HIGH") == 0.9
        assert tool_confidence("MEDIUM") == 0.6
        assert tool_confidence("LOW") == 0.3

    def test_passthrough_and_clamp(self):
        assert tool_confidence(0.75) == 0.75
        assert tool_confidence(42) == 1.0


class TestMakeToolFinding:
    def test_valid_finding_with_all_fields(self):
        f = make_tool_finding(
            agent="BanditAgent",
            ftype="B608",
            raw_severity="HIGH",
            file="src/db.py",
            line=10,
            message="sqli",
            cwe="CWE-89",
            snippet="cursor.execute(q + uid)",
            confidence_raw="HIGH",
        )
        assert f.severity == Severity.HIGH
        assert f.cwe == "CWE-89"
        assert f.extra["tool"] == "BanditAgent"
        assert f.extra["tool_confidence"] == 0.9
        assert "execute" in f.code_snippet

    def test_numeric_cwe_prefixed(self):
        f = make_tool_finding("X", "t", "LOW", "a.py", 1, "m", cwe=89)
        assert f.cwe == "CWE-89"

    def test_never_crashes_on_garbage(self):
        f = make_tool_finding("X", "", None, None, None, None)
        assert f.type == "x_finding"
        assert f.file == ""
        assert f.line == 0


# ── Layer2 structured parsing ────────────────────────────────────────────


class TestExtractJson:
    def _orchestrator(self, tmp_path: Path):
        from patchi.core.security.layer2_orchestrator import Layer2Orchestrator

        return Layer2Orchestrator(tmp_path)

    def test_bare_json(self, tmp_path: Path):
        o = self._orchestrator(tmp_path)
        assert o._extract_json('{"confirmed": true}')["confirmed"] is True

    def test_markdown_fenced(self, tmp_path: Path):
        o = self._orchestrator(tmp_path)
        text = '```json\n{"findings": [{"index": 0}]}\n```'
        parsed = o._extract_json(text)
        assert parsed["findings"][0]["index"] == 0

    def test_embedded_in_prose(self, tmp_path: Path):
        o = self._orchestrator(tmp_path)
        text = 'Here is my analysis:\n{"findings": [{"confirmed": false}]}\nDone.'
        assert o._extract_json(text)["findings"][0]["confirmed"] is False

    def test_garbage_returns_none(self, tmp_path: Path):
        o = self._orchestrator(tmp_path)
        assert o._extract_json("I think it's probably fine.") is None
        assert o._extract_json("") is None


class TestPerFindingBatch:
    """The old code smeared ONE verdict across a whole batch."""

    def _make_gated(self, tmp_path: Path, file: str, line: int):
        from patchi.core.agents.base import Severity
        from patchi.core.security.orchestrator import Finding

        f = Finding(
            agent="BanditAgent",
            type="B608",
            severity=Severity.HIGH,
            file=file,
            line=line,
            message="sqli",
            code_snippet="cursor.execute(q + uid)",
            cwe="CWE-89",
        )
        f.extra = {"tool_confidence": 0.9}
        from patchi.core.security.gated_finding import GatedFinding

        return GatedFinding(
            finding=f, confidence_score=0.5, confirmed_by=["BanditAgent", "TaintAnalyzer"]
        )

    def test_per_finding_verdicts(self, tmp_path: Path, monkeypatch):
        import patchi.core.security.layer2_orchestrator as l2

        o = l2.Layer2Orchestrator(tmp_path)
        batch = [
            self._make_gated(tmp_path, "src/a.py", 10),
            self._make_gated(tmp_path, "src/b.py", 20),
        ]

        fake_response = {
            "findings": [
                {
                    "confirmed": True,
                    "confidence_adjustment": 0.7,
                    "summary": "real sqli",
                    "evidence_quote": "cursor.execute(q + uid)",
                },
                {
                    "confirmed": False,
                    "confidence_adjustment": -0.8,
                    "summary": "fixture data",
                    "evidence_quote": "",
                },
            ]
        }

        monkeypatch.setattr(
            "patchi.core.ai.client.call_ai_structured",
            lambda **kw: fake_response,
        )
        results = o._analyze_batch(batch)

        assert len(results) == 2
        assert results[0].confirmed is True
        assert results[0].confidence_adjustment == pytest.approx(0.7)
        assert results[1].confirmed is False

    def test_legacy_single_verdict_replicates(self, tmp_path: Path, monkeypatch):
        import patchi.core.security.layer2_orchestrator as l2

        o = l2.Layer2Orchestrator(tmp_path)
        batch = [self._make_gated(tmp_path, "src/c.py", 30)]
        monkeypatch.setattr(
            "patchi.core.ai.client.call_ai_structured",
            lambda **kw: {"confirmed": True, "summary": "ok", "confidence_adjustment": 0.4},
        )
        results = o._analyze_batch(batch)
        assert len(results) == 1 and results[0].confirmed

    def test_ai_unavailable_offline_honest(self, tmp_path: Path, monkeypatch):
        import builtins

        import patchi.core.security.layer2_orchestrator as l2

        real_import = builtins.__import__

        def no_client(name, *a, **k):
            if name.startswith("patchi.core.ai"):
                raise ImportError("offline")
            return real_import(name, *a, **k)

        monkeypatch.setattr(builtins, "__import__", no_client)
        o = l2.Layer2Orchestrator(tmp_path)
        batch = [self._make_gated(tmp_path, "src/d.py", 40)]
        results = o._analyze_batch(batch)
        assert results[0].need_human_review is True
        assert "unavailable" in results[0].summary.lower()


# ── End-to-end consensus on the vulnerable sample ────────────────────────


@pytest.mark.skipif(
    not shutil.which("bandit") and not shutil.which("semgrep"),
    reason="bandit and semgrep not installed",
)
class TestConsensusE2E:
    # Semgrep's cold start (rule-cache warm-up on a fresh runner) can exceed
    # the global 60s pytest-timeout; the suite hung on exactly that once.
    @pytest.mark.timeout(300)
    def test_bandit_and_semgrep_correlate(self, tmp_path: Path):
        """Both tools flag the same sink -> CorrelatedFinding with 2 confirmers."""
        import tempfile

        import patchi.core.security.security_agents  # noqa: F401
        from patchi.core.agents.base import AgentGroup, AgentInput, list_agents
        from patchi.core.security.orchestrator import SecurityOrchestrator

        td = Path(tempfile.mkdtemp())
        (td / "vuln.py").write_text(
            "import sqlite3\n"
            "def f(uid):\n"
            "    conn = sqlite3.connect('x.db')\n"
            "    cur = conn.cursor()\n"
            "    cur.execute('SELECT * FROM u WHERE id=' + uid)\n",
            encoding="utf-8",
        )

        agents = {a.name: a for a in list_agents(AgentGroup.SECURITY)}
        agent_results = []
        for name in ("BanditAgent", "SemgrepAgent"):
            cls = agents.get(name)
            if cls is None:
                continue
            res = cls().run(AgentInput(root=td, scope=[], brain={}, config={}))
            assert res.status.value == "done", f"{name} failed: {res.errors[:1]}"
            agent_results.append(res)

        report = SecurityOrchestrator().correlate(agent_results)
        multi = [cf for cf in report.findings if len(cf.confirmed_by) >= 2]
        # Bandit B608 (line 5) and semgrep sql-injection (line 5) should merge
        assert multi, (
            f"expected cross-tool correlation; got "
            f"{[(c.finding.type, c.confirmed_by) for c in report.findings]}"
        )


@pytest.mark.skipif(
    not shutil.which("bandit") and not shutil.which("semgrep"),
    reason="bandit and semgrep not installed",
)
class TestToolVerify:
    """The fix loop re-runs the same tools to prove the vuln is gone."""

    def _vuln_file(self, tmp_path: Path, vulnerable: bool) -> Path:
        f = tmp_path / "vuln.py"
        if vulnerable:
            f.write_text(
                "import sqlite3\n"
                "def f(uid):\n"
                "    conn = sqlite3.connect('x.db')\n"
                "    cur = conn.cursor()\n"
                "    cur.execute('SELECT * FROM u WHERE id=' + uid)\n",
                encoding="utf-8",
            )
        else:
            f.write_text(
                "import sqlite3\n"
                "def f(uid):\n"
                "    conn = sqlite3.connect('x.db')\n"
                "    cur = conn.cursor()\n"
                "    cur.execute('SELECT * FROM u WHERE id=?', (uid,))\n",
                encoding="utf-8",
            )
        return f

    def test_vuln_still_present(self, tmp_path: Path):
        import patchi.core.security.tool_verify as tv

        f = self._vuln_file(tmp_path, True)
        original = type("F", (), {"cwe": "CWE-89", "type": "sql_injection"})()
        assert tv.finding_resolved("bandit", f, original) is False
        assert tv.finding_resolved("semgrep", f, original) is False

    def test_fixed_is_resolved(self, tmp_path: Path):
        import patchi.core.security.tool_verify as tv

        f = self._vuln_file(tmp_path, False)
        original = type("F", (), {"cwe": "CWE-89", "type": "sql_injection"})()
        assert tv.finding_resolved("bandit", f, original) is True
        assert tv.finding_resolved("semgrep", f, original) is True


class TestHighFindingsOnFile:
    """Watch-mode SAST verification of applied proactive fixes.

    Mocks the slow tool layer (Bandit/Semgrep) — the real-tool path is
    exercised by TestToolVerify. Here we test the HIGH/CRITICAL filter and
    the real-path rewrite that high_findings_on_file adds.
    """

    def _fake(self, severity_name: str, cwe: str = "CWE-89") -> object:
        from patchi.core.agents.base import Severity

        return type(
            "F",
            (),
            {
                "agent": "x",
                "type": "sql_injection",
                "severity": getattr(Severity, severity_name.upper()),
                "file": "temp_copy.py",
                "line": 3,
                "cwe": cwe,
                "message": "",
                "detail": "",
                "suggestion": "",
            },
        )()

    def test_keeps_only_high_and_critical(self, tmp_path: Path, monkeypatch):
        import patchi.core.security.tool_verify as tv

        f = tmp_path / "v.py"
        f.write_text("x = 1\n", encoding="utf-8")

        def fake_run(tool, fp):
            return [
                self._fake("low"),
                self._fake("medium"),
                self._fake("high"),
                self._fake("critical"),
            ]

        monkeypatch.setattr(tv, "run_tool_on_file", fake_run)
        highs = tv.high_findings_on_file(f)
        # 2 (high+critical) per tool call, called for bandit then semgrep
        assert len(highs) == 4
        assert {h.severity.value for h in highs} == {"high", "critical"}
        assert all(h.file == str(f) for h in highs)

    def test_clean_file_has_no_high(self, tmp_path: Path, monkeypatch):
        import patchi.core.security.tool_verify as tv

        f = tmp_path / "v.py"
        f.write_text("x = 1\n", encoding="utf-8")

        monkeypatch.setattr(
            tv, "run_tool_on_file", lambda tool, fp: [self._fake("low"), self._fake("medium")]
        )
        assert tv.high_findings_on_file(f) == []

    def test_tool_failure_is_fail_open(self, tmp_path: Path, monkeypatch):
        import patchi.core.security.tool_verify as tv

        f = tmp_path / "v.py"
        f.write_text("x = 1\n", encoding="utf-8")

        def boom(tool, fp):
            raise RuntimeError("semgrep exploded")

        monkeypatch.setattr(tv, "run_tool_on_file", boom)
        assert tv.high_findings_on_file(f) == []


class TestVerifyProactiveFixes:
    """Diff-based regression check for watch-mode applied fixes.

    verify_proactive_fixes() returns only findings that are NEW compared to
    a pre-fix snapshot — so pre-existing findings are never re-reported on
    every save. All cases are fail‑open.
    """

    def _fake(self, type_: str, cwe: str = "", line: int = 1) -> object:
        return type("F", (), {"type": type_, "cwe": cwe, "line": line})()

    def test_flags_only_new_findings(self, tmp_path: Path, monkeypatch):
        import patchi.core.security.tool_verify as tv

        # create the file so vpath.exists() passes
        (tmp_path / "x.py").write_text("x = 1\n", encoding="utf-8")
        # post state has one pre-existing + one new high-severity finding
        monkeypatch.setattr(
            tv, "high_findings_on_file",
            lambda fp: [self._fake("B606"), self._fake("B307", "CWE-78", 5)],
        )
        pre = {"x.py": {("B606", "")}}
        issues = tv.verify_proactive_fixes(tmp_path, ["x.py"], pre)
        assert len(issues) == 1
        assert issues[0]["name"] == "CWE-78"
        assert issues[0]["line"] == 5
        assert issues[0]["file"] == "x.py"

    def test_no_new_findings_means_no_issues(self, tmp_path: Path, monkeypatch):
        import patchi.core.security.tool_verify as tv

        monkeypatch.setattr(
            tv, "high_findings_on_file", lambda fp: [self._fake("B606")],
        )
        pre = {"x.py": {("B606", "")}}
        assert tv.verify_proactive_fixes(tmp_path, ["x.py"], pre) == []

    def test_skips_non_py_and_missing(self, tmp_path: Path, monkeypatch):
        import patchi.core.security.tool_verify as tv

        monkeypatch.setattr(
            tv, "high_findings_on_file", lambda fp: [self._fake("B607")],
        )
        # "x.txt" has no .py suffix → skip; "missing.py" doesn't exist → skip
        assert tv.verify_proactive_fixes(tmp_path, ["x.txt", "missing.py"], {}) == []

    def test_tool_failure_is_fail_open(self, tmp_path: Path, monkeypatch):
        import patchi.core.security.tool_verify as tv

        def boom(fp):
            raise RuntimeError("semgrep exploded")

        monkeypatch.setattr(tv, "high_findings_on_file", boom)
        assert tv.verify_proactive_fixes(tmp_path, ["x.py"], {}) == []


@pytest.mark.skipif(
    not shutil.which("bandit") and not shutil.which("semgrep"),
    reason="bandit and semgrep not installed",
)
class TestSastGate:
    """Pre-commit fast gate: exit 1 on high/critical, 0 when clean."""

    def test_flags_high_finding(self, tmp_path: Path):
        import patchi.core.security.sast_gate as gate

        f = tmp_path / "vuln.py"
        f.write_text(
            "import sqlite3\n"
            "def f(uid):\n"
            "    conn = sqlite3.connect('x.db')\n"
            "    cur = conn.cursor()\n"
            "    cur.execute('SELECT * FROM u WHERE id=' + uid)\n",
            encoding="utf-8",
        )
        assert gate.main(["sast_gate", str(f)]) == 1

    def test_clean_file_passes(self, tmp_path: Path):
        import patchi.core.security.sast_gate as gate

        f = tmp_path / "clean.py"
        f.write_text(
            "import sqlite3\n"
            "def f(uid):\n"
            "    conn = sqlite3.connect('x.db')\n"
            "    cur = conn.cursor()\n"
            "    cur.execute('SELECT * FROM u WHERE id=?', (uid,))\n",
            encoding="utf-8",
        )
        assert gate.main(["sast_gate", str(f)]) == 0

    def test_no_python_files_is_zero(self, tmp_path: Path):
        import patchi.core.security.sast_gate as gate

        assert gate.main(["sast_gate"]) == 0
