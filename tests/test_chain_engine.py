"""Tests for the Exploit Chain Engine (E-1) and Business Logic Analyzer (E-2).

The chain engine is the substrate everything else reasons over — these tests
pin the linking rules, severity escalation, and dedup behavior so a refactor
can't silently weaken chain detection.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from patchi.core.agents.base import Finding, Severity
from patchi.core.security.attack_tree import build_attack_trees
from patchi.core.security.chain_analyzer import (
    ChainAnalyzer,
    NodeRole,
    classify,
)


def F(type_: str, file_: str = "app.py", line: int = 1, sev: str = "medium", agent: str = "TestAgent") -> Finding:
    return Finding(
        agent=agent,
        type=type_,
        severity=Severity(sev),
        file=file_,
        line=line,
        message=f"{type_} in {file_}",
    )


class TestClassification:
    def test_injection_is_exploit(self):
        assert classify("sql_injection") == NodeRole.EXPLOIT

    def test_missing_auth_is_entry(self):
        assert classify("missing_auth") == NodeRole.ENTRY

    def test_hardcoded_secret_is_impact(self):
        assert classify("hardcoded_secret") == NodeRole.IMPACT

    def test_unknown_type_standalone(self):
        assert classify("todo_comment") == NodeRole.STANDALONE


class TestChainDetection:
    def test_auth_to_sqli_chain_found(self):
        findings = [
            F("missing_auth", "routes/api.py", 10),
            F("sql_injection", "services/users.py", 42, "high"),
            F("hardcoded_secret", "config.py", 5),
        ]
        # routes -> services -> config: cross-module link chain
        analyzer = ChainAnalyzer(
            findings,
            import_edges={
                "routes/api.py": {"services/users.py"},
                "services/users.py": {"config.py"},
            },
        )
        chains = analyzer.find_chains()
        assert chains, "auth + sqli + secret must form a chain"
        top = chains[0]
        assert top.length >= 2
        assert top.nodes[0].role == NodeRole.ENTRY
        assert top.nodes[-1].role == NodeRole.IMPACT

    def test_severity_escalates_with_depth(self):
        # Co-located medium findings chained -> at least high
        findings = [
            F("cors_misconfig", "app.py", 1, "medium"),
            F("xss_reflected", "app.py", 9, "medium"),
            F("session_token_logged", "app.py", 3, "medium"),
        ]
        analyzer = ChainAnalyzer(findings)
        chains = analyzer.find_chains()
        assert any(c.severity in ("high", "critical") for c in chains), (
            "multi-step chain must escalate above its medium components"
        )

    def test_disconnected_findings_no_chain(self):
        findings = [
            F("missing_auth", "a.py", 1),
            F("sql_injection", "b.py", 1),  # no import edge a->b
        ]
        analyzer = ChainAnalyzer(findings)
        chains = analyzer.find_chains()
        assert not any(
            c.nodes[0].finding.file == "a.py" and c.nodes[1].finding.file == "b.py"
            for c in chains
        ), "findings in unconnected modules must not link"

    def test_same_file_findings_link(self):
        findings = [
            F("ssrf", "handler.py", 5, "high"),
            F("aws_secret", "handler.py", 90),
        ]
        analyzer = ChainAnalyzer(findings)
        chains = analyzer.find_chains()
        assert chains, "co-located ssrf + secret must chain"

    def test_impact_does_not_start_chain(self):
        # secret first, injection second: direction must stay entry->impact
        findings = [
            F("hardcoded_secret", "cfg.py", 1),
            F("command_injection", "cli.py", 2, "high"),
        ]
        analyzer = ChainAnalyzer(findings)
        for c in analyzer.find_chains():
            assert c.nodes[-1].role in (NodeRole.IMPACT, NodeRole.EXPLOIT)
            assert c.nodes[0].role != NodeRole.IMPACT or len(c.nodes) == 1

    def test_no_cycles_infinite_loop(self):
        # Mutually-linked types must terminate
        findings = [
            F("jwt_weakness", "a.py", 1),
            F("missing_auth", "b.py", 2),
            F("sql_injection", "c.py", 3),
            F("sensitive_data_exposure", "d.py", 4),
        ]
        analyzer = ChainAnalyzer(findings)
        chains = analyzer.find_chains(max_depth=5)  # must return, not hang
        assert isinstance(chains, list)

    def test_dedup_identical_steps(self):
        findings = [F("missing_auth"), F("xss"), F("session_cookie")]
        analyzer = ChainAnalyzer(findings)
        chains = analyzer.find_chains()
        sigs = [tuple(n.key for n in c.nodes) for c in chains]
        assert len(sigs) == len(set(sigs)), "duplicate chains must be deduped"

    def test_summary_shape(self):
        analyzer = ChainAnalyzer([F("missing_auth"), F("sql_injection"), F("secret")])
        s = analyzer.summary()
        assert {"findings_analyzed", "chains_found", "by_severity", "worst"} <= set(s)

    def test_empty_input(self):
        analyzer = ChainAnalyzer([])
        assert analyzer.find_chains() == []
        assert analyzer.summary()["chains_found"] == 0


class TestAttackTrees:
    def test_tree_built_from_secret_chain(self):
        findings = [
            F("missing_auth"),
            F("sql_injection", "svc.py", 7),
            F("exposed_secret", "svc.py", 88),
        ]
        analyzer = ChainAnalyzer(findings)
        trees = build_attack_trees(analyzer.find_chains())
        assert trees, "secret-terminating chain must build a tree"
        assert any("Credential" in t.goal or "Secret" in t.goal for t in trees)

    def test_tree_render_contains_goal(self):
        from patchi.core.security.attack_tree import AttackTree, TreeNode

        tree = AttackTree(goal="Test Goal", root=TreeNode(label="root"))
        text = tree.render()
        assert "Test Goal" in text

    def test_trees_sorted_worst_first(self):
        findings_hi = [F("missing_auth"), F("rce_gadget", "x.py", 1, "critical")]
        an = ChainAnalyzer(findings_hi)
        trees = build_attack_trees(an.find_chains())
        if len(trees) > 1:
            order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
            sevs = [order.get(t.worst_severity, 0) for t in trees]
            assert sevs == sorted(sevs, reverse=True)


class TestIntentAnalyzer:
    @pytest.fixture()
    def project(self, tmp_path: Path) -> Path:
        (tmp_path / "routes.py").write_text(
            """
from flask import Flask
app = Flask(__name__)

@app.route("/api/public/ping", methods=["GET"])
def ping():
    return "ok"

@app.route("/api/public/feedback", methods=["POST"])
def feedback():
    return "thanks"

@app.route("/api/admin/users", methods=["GET"])
@login_required
@admin_required
def admin_users():
    return "users"

@app.route("/api/user/profile", methods=["POST"])
@login_required
def update_profile():
    return "updated"
""",
            encoding="utf-8",
        )
        return tmp_path

    def test_routes_extracted(self, project: Path):
        from patchi.core.security.intent_analyzer import IntentAnalyzer

        report = IntentAnalyzer().analyze_root(project)
        assert len(report.routes) >= 4

    def test_unauthenticated_state_change_flagged(self, project: Path):
        from patchi.core.security.intent_analyzer import IntentAnalyzer

        report = IntentAnalyzer().analyze_root(project)
        flagged = {r.path for r in report.unauthenticated_state_changing}
        assert "/api/public/feedback" in flagged

    def test_guarded_routes_not_flagged(self, project: Path):
        from patchi.core.security.intent_analyzer import IntentAnalyzer

        report = IntentAnalyzer().analyze_root(project)
        flagged = {r.path for r in report.unauthenticated_state_changing}
        assert "/api/user/profile" not in flagged

    def test_admin_surface_detected(self, project: Path):
        from patchi.core.security.intent_analyzer import IntentAnalyzer

        report = IntentAnalyzer().analyze_root(project)
        admin_paths = {r.path for r in report.admin_without_strict_guard}
        assert "/api/admin/users" in admin_paths

    def test_findings_feed_chain_engine(self, project: Path):
        from patchi.core.security.intent_analyzer import (
            IntentAnalyzer,
            findings_from_report,
        )

        report = IntentAnalyzer().analyze_root(project)
        findings = findings_from_report(report, project)
        assert findings, "gaps must produce chain-ready findings"
        # They must be usable by the chain engine (duck-typed contract)
        analyzer = ChainAnalyzer(findings)
        assert isinstance(analyzer.summary(), dict)

    def test_syntax_error_file_tolerated(self, tmp_path: Path):
        from patchi.core.security.intent_analyzer import IntentAnalyzer

        (tmp_path / "broken.py").write_text("def broken(:\n", encoding="utf-8")
        report = IntentAnalyzer().analyze_root(tmp_path)
        assert report.routes == []
